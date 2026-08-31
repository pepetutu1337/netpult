//! Сторож: сам замечает, что обход перестал работать, и чинит.
//!
//! Лестница ремонта — от дешёвого к дорогому:
//!   1. упал прокси Telegram — поднять;
//!   2. zapret выключен, хотя должен работать — включить;
//!   3. zapret работает, но сайты не открываются — перезапустить движок;
//!   4. не помогло — подобрать другую стратегию.
//!
//! Каждый шаг пишется в журнал, чтобы потом было видно, что происходило ночью.

use crate::config::{state_dir, Config};
use crate::probe;
use crate::profile;
use crate::split;
use crate::telegram::Telegram;
use crate::tune;
use crate::zapret::{State, Zapret};
use std::io::Write;
use std::time::{Duration, SystemTime};

/// Проверочные адреса: лёгкие ответы, разные владельцы.
const TARGETS: [&str; 2] = [
    "https://www.youtube.com/generate_204",
    "https://discord.com/api/v9/gateway",
];

/// Пробивается ли путь до видео.
///
/// Имена краевых узлов тут раньше были вписаны списком (`rr1---sn-...`). Это
/// та же ошибка, от которой предостерегает `probe::video`: имя выдаётся под
/// сеть и под сессию, соседний узел из той же группы резолвится и молчит. На
/// чужой машине такой список даёт вечное «видео перекрыто» на исправном
/// обходе — и сторож раз за разом перебирает стратегии впустую. Поэтому узел
/// берём тот, который ютуб выдал этой машине, а не угаданный.
fn video_reachable() -> bool {
    let v = probe::video(Duration::from_secs(8));
    // Узел не нашёлся — судить не о чем, врать про поломку незачем.
    if !v.checked {
        return true;
    }
    v.plain
}

pub fn log_path() -> std::path::PathBuf {
    state_dir().join("watch.log")
}

fn stamp() -> String {
    // Локальное время читаем у системы: тащить ради этого библиотеку часовых
    // поясов не стоит, а UTC в журнале путает.
    #[cfg(unix)]
    if let Ok(out) = std::process::Command::new("date")
        .arg("+%Y-%m-%d %H:%M:%S")
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !text.is_empty() {
            return text;
        }
    }

    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Без внешних библиотек: сутки и время по UTC из секунд эпохи.
    let days = secs / 86_400;
    let time = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

/// Григорианская дата из числа суток с 1970-01-01 (алгоритм Говарда Хиннанта).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn note(text: &str) {
    let line = format!("[{}] {text}\n", stamp());
    print!("{line}");
    std::io::stdout().flush().ok();
    if std::fs::create_dir_all(state_dir()).is_ok()
        && let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path())
        {
            file.write_all(line.as_bytes()).ok();
        }
}

/// Показывает всплывающее уведомление на рабочем столе, если есть чем.
/// Тихо ничего не делает там, где `notify-send` недоступен (сервер, Windows).
pub fn notify(text: &str) {
    if cfg!(target_os = "linux") {
        std::process::Command::new("notify-send")
            .args(["-a", "Обход блокировок", "netpult", text])
            .status()
            .ok();
    }
}

/// Запись в журнал + уведомление: для событий, о которых стоит знать сразу.
fn alert(text: &str) {
    note(text);
    notify(text);
}

/// Открываются ли сайты вообще.
///
/// Именно «хоть один», а не «все»: адреса разных владельцев, и у любого бывает
/// своя авария. Требование «все разом» превращало получасовой сбой дискорда в
/// перезапуск движка и получасовой перебор стратегий на ровном месте.
fn everything_reachable() -> bool {
    TARGETS
        .iter()
        .any(|url| probe::reachable(url, Duration::from_secs(8)))
}

/// Один проход сторожа. Возвращает `true`, если пришлось вмешаться.
fn last_network_path() -> std::path::PathBuf {
    state_dir().join("last-network")
}

/// Сменилась сеть — применяем её профиль, если он сохранён.
fn follow_network(cfg: &Config) -> bool {
    let Some(now) = profile::current_network() else {
        return false;
    };
    let before = std::fs::read_to_string(last_network_path()).unwrap_or_default();
    if before.trim() == now {
        return false;
    }
    std::fs::create_dir_all(state_dir()).ok();
    std::fs::write(last_network_path(), &now).ok();

    if before.trim().is_empty() {
        return false; // Первый запуск: просто запомнили, где мы.
    }
    match profile::apply(cfg) {
        Ok(done) if done.is_empty() => {
            note(&format!("сеть сменилась: {} → {now}", before.trim()));
            false
        }
        Ok(done) => {
            alert(&format!("сеть «{now}»: {}", done.join(", ")));
            true
        }
        Err(e) => {
            note(&format!("сеть «{now}», профиль не применён: {e}"));
            false
        }
    }
}

/// Свой туннель поднят.
///
/// Раньше сторож на этом просто выходил: zapret тут и правда трогать нельзя.
/// Но и делать вид, что всё хорошо, нельзя тоже — нода умирает молча, и о том,
/// что «ничего не работает», человек узнаёт сам, когда полезет проверять. При
/// поднятом туннеле трафик идёт через ноду, значит обычная проверка адреса —
/// это и есть проверка ноды: то, что не прошло у сторожа, не пройдёт и у
/// человека.
fn tunnel_tick() -> bool {
    if everything_reachable() {
        return false;
    }
    let было = crate::singbox::active_node()
        .map(|(n, _)| n)
        .unwrap_or_else(|| "?".into());
    note(&format!("через ноду «{было}» сайты не открываются — ищу живую"));

    // Пусть движок сам перемерит группу и переставит автоподбор на живую.
    crate::singbox::measure_group(crate::singbox::AUTO, 5000);
    if crate::singbox::select(crate::singbox::AUTO).is_err() {
        note("не удалось переключиться на автоподбор");
        return true;
    }
    std::thread::sleep(Duration::from_secs(3));
    if everything_reachable() {
        let стало = crate::singbox::active_node()
            .map(|(n, _)| n)
            .unwrap_or_else(|| "?".into());
        alert(&format!("нода «{было}» перестала пропускать трафик — перешёл на «{стало}»"));
    } else {
        alert("ни одна нода не пропускает трафик — проверь подписку: net vpn nodes");
    }
    true
}

/// Как часто позволено перебирать стратегии.
///
/// Подбор идёт минутами и на это время рвёт связь. Без выдержки сторож,
/// упершийся в поломку, которую стратегией не лечат (лёг провайдер, кончился
/// трафик), гонял бы перебор каждые десять минут круглосуточно.
const TUNE_COOLDOWN: Duration = Duration::from_secs(6 * 60 * 60);

fn tune_stamp() -> std::path::PathBuf {
    state_dir().join("tune.last")
}

fn tune_allowed() -> bool {
    match std::fs::metadata(tune_stamp()).and_then(|m| m.modified()) {
        Ok(t) => t.elapsed().map(|e| e > TUNE_COOLDOWN).unwrap_or(true),
        Err(_) => true,
    }
}

pub fn tick(cfg: &Config) -> bool {
    maybe_update_geoblock();
    let mut acted = follow_network(cfg);
    let z = Zapret::new(cfg);
    let tg = Telegram::new(cfg);

    // 1. Прокси Telegram.
    if cfg.watch_telegram && tg.binary().is_some() && !tg.running() {
        match tg.start() {
            Ok(()) => {
                note("прокси Telegram лежал — поднял");
                acted = true;
            }
            Err(e) => note(&format!("прокси Telegram не поднимается: {e}")),
        }
    }

    // 2. Сам движок обхода.
    //
    // При поднятом своём туннеле трогать zapret нельзя: весь трафик идёт через
    // ноду, проверки сайтов ничего не говорят о DPI, и сторож начинает лечить
    // здорового — перезапускает движок по кругу, пока systemd не упрётся в
    // предел запусков и не пометит службу упавшей.
    if crate::singbox::Core::state_now() == crate::singbox::State::Up {
        return tunnel_tick() || acted;
    }
    if z.state() == State::Missing {
        return acted;
    }
    if cfg.watch_zapret && z.state() == State::Off {
        match z.start() {
            Ok(()) => {
                note("zapret был выключен — включил");
                acted = true;
            }
            Err(e) => note(&format!("zapret не включается: {e}")),
        }
    }

    if !cfg.watch_zapret || z.state() != State::On {
        return acted;
    }

    // 3. Работает, но пропускает ли?
    //
    // Сайты и видео проверяются порознь: страница ютуба может открываться, а
    // видео с неё — уже нет. Раньше лечение в этом случае не запускалось
    // вовсе, потому что проверка видела только страницу.
    let сайты = everything_reachable();
    let видео = video_reachable();
    if сайты && видео {
        return acted;
    }
    if сайты {
        note("сайты открываются, а путь до видео перекрыт");
    } else {
        note("сайты не открываются");
    }

    note("перезапускаю движок");
    if let Err(e) = z.restart() {
        note(&format!("перезапуск не удался: {e}"));
        return true;
    }
    std::thread::sleep(Duration::from_secs(2));
    if everything_reachable() && video_reachable() {
        note("после перезапуска всё открывается");
        return true;
    }

    // 4. Дело в стратегии.
    if !tune_allowed() {
        note("не помогло, но стратегию уже подбирали недавно — жду");
        return true;
    }
    note("не помогло — подбираю стратегию");
    std::fs::create_dir_all(state_dir()).ok();
    std::fs::write(tune_stamp(), "").ok();
    match tune::run(cfg, &tune::Options { full: false, verbose: false }) {
        Ok(best) => alert(&format!(
            "стратегия сменена на {} ({}, {:.0} КБ/с)",
            best.strategy,
            if best.reachable { "открывается" } else { "всё ещё нет" },
            best.speed
        )),
        Err(e) => alert(&format!("обход упал, подбор не удался: {e}")),
    }
    true
}

/// Раз в сутки обновляет автосписок геоблока (если сплит вообще используется).
fn maybe_update_geoblock() {
    let marker = state_dir().join("geoblock.updated");
    let day = 24 * 60 * 60;
    let fresh = std::fs::metadata(&marker)
        .and_then(|m| m.modified())
        .map(|t| t.elapsed().map(|e| e.as_secs() < day).unwrap_or(false))
        .unwrap_or(false);
    if fresh {
        return;
    }
    match split::update_geoblock() {
        Ok(n) => {
            note(&format!("автосписок геоблока обновлён: {n} доменов"));
            std::fs::write(&marker, "").ok();
        }
        Err(e) => note(&format!("автосписок геоблока не обновился: {e}")),
    }
}

/// Бесконечный цикл проверок.
pub fn run(cfg: &Config) -> Result<(), String> {
    note(&format!(
        "сторож запущен, проверка раз в {} мин",
        cfg.watch_interval_min
    ));
    loop {
        tick(cfg);
        std::thread::sleep(Duration::from_secs(cfg.watch_interval_min as u64 * 60));
    }
}

/// Ставит сторожа в автозапуск.
pub fn install(cfg: &Config) -> Result<String, String> {
    if !cfg!(target_os = "linux") {
        return Err(format!(
            "автозапуск сторожа на {} ещё не подведён — пока запускай «netpult watch» вручную",
            std::env::consts::OS
        ));
    }

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let unit_dir = crate::config::home().join(".config/systemd/user");
    std::fs::create_dir_all(&unit_dir).map_err(|e| e.to_string())?;
    let unit = unit_dir.join("netpult-watch.service");

    let body = format!(
        "[Unit]\n\
         Description=netpult — сторож обхода блокировок\n\
         After=network-online.target\n\n\
         [Service]\n\
         Type=simple\n\
         ExecStart={} watch\n\
         Restart=on-failure\n\
         RestartSec=30\n\n\
         [Install]\n\
         WantedBy=default.target\n",
        exe.display()
    );
    std::fs::write(&unit, body).map_err(|e| e.to_string())?;

    let _ = cfg;
    run_systemctl(&["--user", "daemon-reload"])?;
    run_systemctl(&["--user", "enable", "--now", "netpult-watch.service"])?;
    Ok(unit.display().to_string())
}

pub fn uninstall() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("автозапуск сторожа ставится только на Linux".into());
    }
    run_systemctl(&["--user", "disable", "--now", "netpult-watch.service"])?;
    let unit = crate::config::home().join(".config/systemd/user/netpult-watch.service");
    std::fs::remove_file(unit).ok();
    run_systemctl(&["--user", "daemon-reload"])
}

pub fn status() -> String {
    if !cfg!(target_os = "linux") {
        return "сторож: автозапуск доступен пока только на Linux".into();
    }
    let out = std::process::Command::new("systemctl")
        .args(["--user", "is-active", "netpult-watch.service"])
        .output();
    match out {
        Ok(o) if String::from_utf8_lossy(&o.stdout).trim() == "active" => {
            "сторож: работает".into()
        }
        _ => "сторож: не запущен".into(),
    }
}

fn run_systemctl(args: &[&str]) -> Result<(), String> {
    let status = std::process::Command::new("systemctl")
        .args(args)
        .status()
        .map_err(|e| format!("не запустился systemctl: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl {} завершился с ошибкой", args.join(" ")))
    }
}
