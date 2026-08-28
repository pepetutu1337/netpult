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
    if std::fs::create_dir_all(state_dir()).is_ok() {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path())
        {
            file.write_all(line.as_bytes()).ok();
        }
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

fn everything_reachable() -> bool {
    TARGETS
        .iter()
        .all(|url| probe::reachable(url, Duration::from_secs(8)))
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
    if everything_reachable() {
        return acted;
    }

    note("сайты не открываются — перезапускаю движок");
    if let Err(e) = z.restart() {
        note(&format!("перезапуск не удался: {e}"));
        return true;
    }
    std::thread::sleep(Duration::from_secs(2));
    if everything_reachable() {
        note("после перезапуска всё открывается");
        return true;
    }

    // 4. Дело в стратегии.
    note("не помогло — подбираю стратегию");
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
