//! netpult — один пульт для обхода блокировок: zapret, VPN и прокси Telegram.

mod config;
mod probe;
mod profile;
mod split;
mod qr;
mod share;
mod socks;
mod telegram;
mod tune;
mod tui;
mod vpn;
mod watch;
mod zapret;

use config::Config;
use std::time::Duration;
use telegram::Telegram;
use vpn::Vpn;
use zapret::Zapret;

pub const GREEN: &str = "\x1b[32m";
pub const RED: &str = "\x1b[31m";
pub const YELLOW: &str = "\x1b[33m";
pub const DIM: &str = "\x1b[2m";
pub const BOLD: &str = "\x1b[1m";
pub const RESET: &str = "\x1b[0m";

fn main() {
    quiet_broken_pipe();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = Config::load();

    let command = args.first().map(String::as_str).unwrap_or("tui");
    let rest: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();

    let result = match command {
        "tui" | "menu" | "" => tui::run(&cfg),
        "status" => {
            print_status(&cfg);
            Ok(())
        }
        "on" => Zapret::new(&cfg).start().map(|_| print_status(&cfg)),
        "off" => Zapret::new(&cfg).stop().map(|_| print_status(&cfg)),
        "restart" => Zapret::new(&cfg).restart().map(|_| print_status(&cfg)),
        "toggle" => toggle_zapret(&cfg),
        "strat" | "strategy" => strategy(&cfg, rest.first().copied()),
        "vpn" => match rest.first().copied() {
            None | Some("on") | Some("open") => Vpn::new(&cfg).open(),
            Some("off") => Vpn::new(&cfg).close(),
            Some(other) => Err(format!("net vpn on|off, а не «{other}»")),
        },
        "tg" | "telegram" => telegram_command(&cfg, &rest),
        "test" => {
            run_test_public(&cfg);
            Ok(())
        }
        "tune" => tune_command(&cfg, &rest),
        "profile" | "prof" => profile_command(&cfg, &rest),
        "share" => share_command(&cfg, &rest),
        "split" => split_command(&cfg, &rest),
        "watch" => watch_command(&cfg, &rest),
        "qr" => show_qr_maybe_png(&cfg, &rest),
        "--raw" => raw_qr(rest.first().copied()),
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other => Err(format!("неизвестная команда: {other}")),
    };

    if let Err(message) = result {
        eprintln!("{RED}{message}{RESET}");
        std::process::exit(1);
    }
}

/// `net strat | head` обрывает трубу, и стандартный вывод начинает ругаться
/// паникой. Для утилиты это нормальный конец работы, а не сбой.
fn quiet_broken_pipe() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let text = info.to_string();
        if text.contains("Broken pipe") || text.contains("os error 32") {
            std::process::exit(0);
        }
        previous(info);
    }));
}

fn toggle_zapret(cfg: &Config) -> Result<(), String> {
    let z = Zapret::new(cfg);
    if z.state() == zapret::State::On {
        z.stop()?;
    } else {
        z.start()?;
    }
    print_status(cfg);
    Ok(())
}

fn strategy(cfg: &Config, want: Option<&str>) -> Result<(), String> {
    let z = Zapret::new(cfg);
    match want {
        Some(value) => {
            let name = z.set_strategy(value)?;
            println!("{GREEN}Стратегия: {name}{RESET}");
            Ok(())
        }
        None => {
            let current = z.strategy().unwrap_or_default();
            let list = z.strategies();
            if list.is_empty() {
                return Err("стратегий не нашлось — где стоит zapret?".into());
            }
            println!("Стратегии (текущая помечена ●):");
            for (i, name) in list.iter().enumerate() {
                if *name == current {
                    println!("{GREEN}{:>3} ● {name}{RESET}", i + 1);
                } else {
                    println!("{:>3}   {name}", i + 1);
                }
            }
            println!("\nПоставить: net strat <номер|имя>");
            Ok(())
        }
    }
}

fn telegram_command(cfg: &Config, rest: &[&str]) -> Result<(), String> {
    let action = rest.first().copied();
    let extra = rest.get(1..).unwrap_or(&[]);
    let tg = Telegram::new(cfg);
    match action {
        None | Some("show") | Some("link") => {
            if let Some(link) = tg.local_link() {
                println!("На этом компьютере:\n  {link}");
            }
            if let Some(link) = tg.lan_link() {
                println!("Для телефона (та же сеть Wi-Fi):\n  {link}");
                println!("{DIM}QR для телефона: net tg qr{RESET}");
            }
            if tg.local_link().is_none() {
                return Err("секрет ещё не создан — запусти: net tg on".into());
            }
            Ok(())
        }
        Some("on") | Some("start") => {
            tg.start()?;
            println!("{GREEN}Прокси Telegram включён{RESET}");
            show_qr(cfg)
        }
        Some("off") | Some("stop") => {
            tg.stop()?;
            println!("{RED}Прокси Telegram выключен{RESET}");
            Ok(())
        }
        Some("qr") => show_qr_maybe_png(cfg, extra),
        Some("newsecret") => {
            // Сменить секрет прокси — только по этой команде. Секрет постоянный:
            // сам не крутится при перезапусках, чтобы настроенный Telegram не
            // отваливался. После смены на телефоне надо пересканировать QR.
            let tg = Telegram::new(cfg);
            let was_running = tg.running();
            if was_running {
                tg.stop().ok();
            }
            std::fs::remove_file(cfg.tg_secret_path()).ok();
            std::fs::remove_file(config::state_dir().join("tglock.secret")).ok();
            std::fs::remove_file(config::home().join(".config/tglock/secret")).ok();
            println!("{GREEN}Секрет сброшен — новый создастся при запуске.{RESET}");
            if was_running {
                tg.start()?;
                println!("{DIM}Прокси перезапущен. Пересканируй QR на телефоне: net tg qr{RESET}");
            } else {
                println!("{DIM}Включи прокси: net tg on{RESET}");
            }
            Ok(())
        }
        Some(other) => Err(format!("net tg on|off|qr|link|newsecret, а не «{other}»")),
    }
}

fn tune_command(cfg: &Config, rest: &[&str]) -> Result<(), String> {
    let full = rest.contains(&"--all");
    println!("Подбираю стратегию. Интернет будет прыгать.");
    if !full {
        println!("{DIM}Останавливаюсь на первой рабочей и быстрой. Полный перебор: net tune --all{RESET}");
    }
    let best = tune::run(cfg, &tune::Options { full, verbose: true })?;
    println!(
        "\n{GREEN}Выбрана {}{RESET} — {}, {:.0} КБ/с",
        best.strategy,
        if best.reachable { "YouTube открывается" } else { "YouTube так и не открылся" },
        best.speed
    );
    Ok(())
}

fn watch_command(cfg: &Config, rest: &[&str]) -> Result<(), String> {
    match rest.first().copied() {
        None => watch::run(cfg),
        Some("--once") => {
            if !watch::tick(cfg) {
                watch::note("всё на месте, вмешиваться не пришлось");
            }
            Ok(())
        }
        Some("install") => {
            let unit = watch::install(cfg)?;
            println!("{GREEN}Сторож в автозапуске{RESET}: {unit}");
            println!("{DIM}Проверяет связь раз в {} мин, журнал: {}{RESET}",
                cfg.watch_interval_min, watch::log_path().display());
            Ok(())
        }
        Some("uninstall") => {
            watch::uninstall()?;
            println!("Сторож убран из автозапуска");
            Ok(())
        }
        Some("log") => {
            let text = std::fs::read_to_string(watch::log_path())
                .map_err(|_| "журнала пока нет".to_string())?;
            let tail: Vec<&str> = text.lines().rev().take(30).collect();
            for line in tail.into_iter().rev() {
                println!("{line}");
            }
            Ok(())
        }
        Some(other) => Err(format!("net watch [--once|install|uninstall|log], а не «{other}»")),
    }
}

fn profile_command(cfg: &Config, rest: &[&str]) -> Result<(), String> {
    match rest.first().copied() {
        None | Some("show") => {
            let network = profile::current_network().unwrap_or_else(|| "не видно".into());
            println!("Сеть: {BOLD}{network}{RESET}");
            let all = profile::load();
            match all.get(&network) {
                Some(p) => println!(
                    "Профиль: zapret {}, Telegram {}{}",
                    if p.zapret { "вкл" } else { "выкл" },
                    if p.telegram { "вкл" } else { "выкл" },
                    p.strategy.as_ref().map(|s| format!(", стратегия {s}")).unwrap_or_default()
                ),
                None => println!("{DIM}Профиля для этой сети нет. Настрой как надо и сохрани: net profile save{RESET}"),
            }
            Ok(())
        }
        Some("save") => {
            let (network, p) = profile::save_current(cfg)?;
            println!(
                "{GREEN}Запомнил для сети «{network}»{RESET}: zapret {}, Telegram {}{}",
                if p.zapret { "вкл" } else { "выкл" },
                if p.telegram { "вкл" } else { "выкл" },
                p.strategy.as_ref().map(|s| format!(", стратегия {s}")).unwrap_or_default()
            );
            Ok(())
        }
        Some("apply") => {
            let done = profile::apply(cfg)?;
            if done.is_empty() {
                println!("Всё уже как в профиле");
            } else {
                for line in done {
                    println!("{GREEN}{line}{RESET}");
                }
            }
            Ok(())
        }
        Some("list") => {
            let all = profile::load();
            if all.is_empty() {
                println!("{DIM}Профилей пока нет{RESET}");
            }
            let here = profile::current_network();
            for (network, p) in all {
                let mark = if Some(&network) == here.as_ref() { "●" } else { " " };
                println!(
                    "{mark} {network}: zapret {}, Telegram {}{}",
                    if p.zapret { "вкл" } else { "выкл" },
                    if p.telegram { "вкл" } else { "выкл" },
                    p.strategy.as_ref().map(|s| format!(", {s}")).unwrap_or_default()
                );
            }
            Ok(())
        }
        Some("forget") => {
            let network = rest.get(1).copied()
                .map(str::to_string)
                .or_else(profile::current_network)
                .ok_or("какую сеть забыть?")?;
            profile::forget(&network)?;
            println!("Забыл «{network}»");
            Ok(())
        }
        Some(other) => Err(format!("net profile [show|save|apply|list|forget], а не «{other}»")),
    }
}

fn share_command(cfg: &Config, rest: &[&str]) -> Result<(), String> {
    let port = cfg.share_port;
    match rest.first().copied() {
        Some("serve") => share::serve(port, share_password(cfg).as_deref()),
        Some("on") => {
            // Прокси на всю сеть без пароля пускал бы любого соседа. Раздача
            // «для всех» — не то, что нужно: если пароль не задан, создаём свой.
            let password = share_password(cfg);
            share_service_public("on", port)?;
            print_share_hint(port, password.as_deref());
            Ok(())
        }
        Some("off") => {
            share_service_public("off", port)?;
            println!("Раздача выключена");
            Ok(())
        }
        Some("open") => {
            // Осознанно открыть без пароля — по явной команде, не по умолчанию.
            std::fs::remove_file(config::state_dir().join("share.pass")).ok();
            let mut c = cfg.clone();
            c.share_password = None;
            println!("{YELLOW}Раздача будет БЕЗ пароля — доступна любому в этой сети.{RESET}");
            share_service_public("on", port)?;
            print_share_hint(port, None);
            Ok(())
        }
        Some("password") | Some("pass") => {
            // Просто показать — ничего не меняя.
            match share_password(cfg) {
                Some(p) => println!("Логин {BOLD}netpult{RESET}, пароль {BOLD}{p}{RESET}"),
                None => println!("{DIM}Пароль не задан (раздача открыта).{RESET}"),
            }
            Ok(())
        }
        Some("newpass") => {
            // Сменить пароль — только по этой явной команде. Старый QR/логин на
            // телефоне после этого перестанут пускать, придётся ввести новый.
            if cfg.share_password.is_some() {
                return Err(
                    "пароль задан вручную в настройках (share_password) — смени там".into(),
                );
            }
            let fresh = random_password();
            config::state_dir_ensure().map_err(|e| e.to_string())?;
            std::fs::write(config::state_dir().join("share.pass"), &fresh)
                .map_err(|e| e.to_string())?;
            println!("{GREEN}Новый пароль раздачи: {BOLD}{fresh}{RESET}");
            println!("{DIM}Старый больше не пускает. На телефоне впиши новый.{RESET}");
            if probe::port_open(port, std::time::Duration::from_millis(400)) {
                share_service_public("on", port).ok(); // перезапустить с новым паролем
            }
            Ok(())
        }
        None | Some("status") => {
            if probe::port_open(port, std::time::Duration::from_millis(400)) {
                println!("{GREEN}Раздача работает{RESET}");
                print_share_hint(port, share_password(cfg).as_deref());
                print_share_clients(port);
            } else {
                println!("{RED}Раздача выключена{RESET}  ({DIM}включить: net share on{RESET})");
            }
            Ok(())
        }
        Some(other) => Err(format!("net share [on|off|status|password|newpass|open], а не «{other}»")),
    }
}

/// Пароль раздачи: заданный в настройках или свой, сохранённый в state-каталоге.
/// Без пароля прокси не поднимаем — раздавать интернет всей сети незачем.
fn share_password(cfg: &Config) -> Option<String> {
    if let Some(p) = &cfg.share_password {
        return Some(p.clone());
    }
    let path = config::state_dir().join("share.pass");
    if let Ok(saved) = std::fs::read_to_string(&path) {
        let saved = saved.trim().to_string();
        if !saved.is_empty() {
            return Some(saved);
        }
    }
    let generated = random_password();
    config::state_dir_ensure().ok();
    std::fs::write(&path, &generated).ok();
    Some(generated)
}

fn random_password() -> String {
    // Короткий, читаемый: набрать на телефоне легко, подобрать перебором — нет.
    const ABC: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut x = (seed as u64) ^ (&seed as *const _ as u64) | 1;
    (0..10)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ABC[(x as usize) % ABC.len()] as char
        })
        .collect()
}

fn split_command(cfg: &Config, rest: &[&str]) -> Result<(), String> {
    match rest.first().copied() {
        Some("serve") => split::serve(cfg),
        Some("on") => {
            split::ensure_default_list().map_err(|e| e.to_string())?;
            split_service("on", cfg.split_port)?;
            print_split_hint(cfg);
            Ok(())
        }
        Some("off") => {
            split_service("off", cfg.split_port)?;
            println!("Сплит выключен");
            Ok(())
        }
        Some("list") => {
            split::ensure_default_list().map_err(|e| e.to_string())?;
            let mut count = 0;
            for path in split::all_list_paths() {
                let Ok(text) = std::fs::read_to_string(&path) else { continue };
                let domains: Vec<&str> = text
                    .lines()
                    .filter(|l| { let t = l.trim(); !t.is_empty() && !t.starts_with('#') })
                    .collect();
                if domains.is_empty() {
                    continue;
                }
                let label = if path == split::geoblock_path() {
                    "автосписок геоблока"
                } else {
                    "свой список"
                };
                println!("{DIM}— {label} ({}) —{RESET}", domains.len());
                for d in &domains {
                    println!("  {d}");
                }
                count += domains.len();
            }
            if count == 0 {
                println!("{DIM}Список пуст.{RESET}");
            }
            Ok(())
        }
        Some("log") => {
            let text = std::fs::read_to_string(split::log_path())
                .map_err(|_| "лог сплита пуст — пока ничего не проходило".to_string())?;
            let lines: Vec<&str> = text.lines().collect();
            let show = lines.len().saturating_sub(40);
            for line in &lines[show..] {
                if line.contains("нода") {
                    println!("{GREEN}{line}{RESET}");
                } else {
                    println!("{DIM}{line}{RESET}");
                }
            }
            let via = lines.iter().filter(|l| l.contains("нода")).count();
            println!(
                "{DIM}всего записей {}, из них через ноду {via}{RESET}",
                lines.len()
            );
            Ok(())
        }
        Some("update") => {
            println!("Тяну автосписок геоблока…");
            let n = split::update_geoblock()?;
            println!("{GREEN}Геоблок обновлён: {n} доменов{RESET}");
            if probe::port_open(cfg.split_port, std::time::Duration::from_millis(400)) {
                split_service("on", cfg.split_port).ok(); // перечитать список
                println!("{DIM}Сплит перезапущен с новым списком.{RESET}");
            }
            Ok(())
        }
        Some("add") => {
            let domain = rest.get(1).ok_or("какой домен добавить? net split add openai.com")?;
            let path = split::ensure_default_list().map_err(|e| e.to_string())?;
            let mut text = std::fs::read_to_string(&path).unwrap_or_default();
            if text.lines().any(|l| l.trim() == *domain) {
                println!("{DIM}{domain} уже в списке{RESET}");
            } else {
                if !text.ends_with('\n') { text.push('\n'); }
                text.push_str(domain);
                text.push('\n');
                std::fs::write(&path, text).map_err(|e| e.to_string())?;
                println!("{GREEN}Добавил {domain}{RESET} — перезапусти сплит: net split off && net split on");
            }
            Ok(())
        }
        None | Some("status") => {
            let up = &cfg.split_upstream;
            let node_ok = socks::reachable(up, std::time::Duration::from_secs(2));
            if probe::port_open(cfg.split_port, std::time::Duration::from_millis(400)) {
                println!("{GREEN}Сплит работает{RESET} на 127.0.0.1:{}", cfg.split_port);
            } else {
                println!("{RED}Сплит выключен{RESET}  ({DIM}включить: net split on{RESET})");
            }
            if node_ok {
                println!("{GREEN}Нода-SOCKS {up} отвечает{RESET}");
            } else {
                println!("{YELLOW}Нода-SOCKS {up} молчит — включи VPN-клиент в режиме прокси{RESET}");
            }
            Ok(())
        }
        Some(other) => Err(format!("net split [on|off|status|list|add|update], а не «{other}»")),
    }
}

fn print_split_hint(cfg: &Config) {
    println!("Сплит-прокси: {BOLD}127.0.0.1:{}{RESET}", cfg.split_port);
    println!("{DIM}Домены из списка идут через ноду {}, остальное напрямую.{RESET}", cfg.split_upstream);
    println!("{DIM}Список: net split list.  Прописать прокси в системе — тогда весь браузер разделится сам.{RESET}");
    if !socks::reachable(&cfg.split_upstream, std::time::Duration::from_secs(2)) {
        println!("{YELLOW}Сейчас нода-SOCKS не отвечает: подними Happ в режиме прокси (не TUN).{RESET}");
    }
}

fn split_service(action: &str, port: u16) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err(format!(
            "служба сплита на {} ещё не подведена — запусти «netpult split serve» вручную",
            std::env::consts::OS
        ));
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = config::home().join(".config/systemd/user");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let unit = dir.join("netpult-split.service");
    if action == "on" {
        let body = format!(
            "[Unit]\nDescription=netpult — сплит-прокси (порт {port})\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={} split serve\nRestart=on-failure\nRestartSec=10\n\n[Install]\nWantedBy=default.target\n",
            exe.display()
        );
        std::fs::write(&unit, body).map_err(|e| e.to_string())?;
    }
    let systemctl = |args: &[&str]| -> Result<(), String> {
        let status = std::process::Command::new("systemctl").args(args).status()
            .map_err(|e| format!("не запустился systemctl: {e}"))?;
        if status.success() { Ok(()) } else { Err(format!("systemctl {} не сработал", args.join(" "))) }
    };
    systemctl(&["--user", "daemon-reload"])?;
    if action == "on" {
        systemctl(&["--user", "enable", "--now", "netpult-split.service"])
    } else {
        systemctl(&["--user", "disable", "--now", "netpult-split.service"])
    }
}

fn print_share_clients(port: u16) {
    let peers = probe::connected_peers(port);
    if peers.is_empty() {
        println!("{DIM}Подключённых устройств нет.{RESET}");
    } else {
        println!("{GREEN}Подключено устройств: {}{RESET}", peers.len());
        for peer in peers {
            println!("  {peer}");
        }
    }
}

fn print_share_hint(port: u16, password: Option<&str>) {
    let ip = probe::lan_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "адрес не виден".into());
    println!("Прокси для телефона: {BOLD}{ip}:{port}{RESET}");
    match password {
        Some(pass) => {
            println!("Логин {BOLD}netpult{RESET}, пароль {BOLD}{pass}{RESET}");
            println!("{DIM}Телефон: настройки Wi-Fi → эта сеть → прокси вручную → узел {ip}, порт {port},{RESET}");
            println!("{DIM}проверка подлинности вкл, имя netpult, пароль выше.{RESET}");
        }
        None => {
            println!("{DIM}Телефон: настройки Wi-Fi → эта сеть → прокси вручную → узел {ip}, порт {port}.{RESET}");
        }
    }
    println!("{DIM}Трафик телефона пойдёт через этот компьютер и через zapret. Выключить: net share off.{RESET}");
}

pub fn share_service_public(action: &str, port: u16) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err(format!(
            "служба раздачи на {} ещё не подведена — запусти «netpult share serve» вручную",
            std::env::consts::OS
        ));
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = config::home().join(".config/systemd/user");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let unit = dir.join("netpult-share.service");

    if action == "on" {
        let body = format!(
            "[Unit]\nDescription=netpult — раздача обхода на телефон (порт {port})\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={} share serve\nRestart=on-failure\nRestartSec=10\n\n[Install]\nWantedBy=default.target\n",
            exe.display()
        );
        std::fs::write(&unit, body).map_err(|e| e.to_string())?;
    }

    let systemctl = |args: &[&str]| -> Result<(), String> {
        let status = std::process::Command::new("systemctl")
            .args(args)
            .status()
            .map_err(|e| format!("не запустился systemctl: {e}"))?;
        if status.success() { Ok(()) } else { Err(format!("systemctl {} не сработал", args.join(" "))) }
    };
    systemctl(&["--user", "daemon-reload"])?;
    if action == "on" {
        systemctl(&["--user", "enable", "--now", "netpult-share.service"])
    } else {
        systemctl(&["--user", "disable", "--now", "netpult-share.service"])
    }
}

fn show_qr(cfg: &Config) -> Result<(), String> {
    show_qr_maybe_png(cfg, &[])
}

/// QR прокси Telegram: в терминал, а с `--png [путь]` — ещё и картинкой в файл.
fn show_qr_maybe_png(cfg: &Config, extra: &[&str]) -> Result<(), String> {
    let tg = Telegram::new(cfg);
    let link = tg
        .lan_link()
        .ok_or("нет ссылки: прокси ещё не запускался или не видно локальной сети")?;
    let grid = qr::encode(&link)?;

    if let Some(pos) = extra.iter().position(|a| *a == "--png") {
        let path = extra
            .get(pos + 1)
            .map(|p| p.to_string())
            .unwrap_or_else(|| {
                config::home()
                    .join("telegram-proxy-qr.png")
                    .display()
                    .to_string()
            });
        let png = qr::to_png(&grid, 8, 4);
        std::fs::write(&path, png).map_err(|e| format!("не записать {path}: {e}"))?;
        println!("{GREEN}QR сохранён: {path}{RESET}");
        println!("  {link}");
        return Ok(());
    }

    println!();
    print!("{}", qr::render(&grid, 2));
    println!("  {link}\n");
    println!("{DIM}Телефон: камера на QR, откроется Telegram, подтвердить прокси.{RESET}");
    println!("{DIM}Нужна одна сеть Wi-Fi с этим компьютером, и он должен не спать.{RESET}");
    println!("{DIM}Сохранить картинкой: net tg qr --png{RESET}");
    Ok(())
}

fn raw_qr(text: Option<&str>) -> Result<(), String> {
    let grid = qr::encode(text.unwrap_or("test"))?;
    for row in grid {
        let line: String = row.iter().map(|&b| if b { '#' } else { '.' }).collect();
        println!("{line}");
    }
    Ok(())
}

pub fn status_lines(cfg: &Config) -> Vec<(bool, String)> {
    let z = Zapret::new(cfg);
    let mut lines = Vec::new();

    lines.push(match z.state() {
        zapret::State::On => (
            true,
            format!("zapret    ВКЛ    {}", z.strategy().unwrap_or_default()),
        ),
        zapret::State::Off => (false, "zapret    ВЫКЛ".to_string()),
        zapret::State::Missing => (false, "zapret    не установлен".to_string()),
    });

    lines.push(match Vpn::new(cfg).state() {
        vpn::State::Tunnel => (true, "VPN       ВКЛ    туннель поднят".to_string()),
        vpn::State::AppOnly => (false, "VPN       окно открыто, туннеля нет".to_string()),
        vpn::State::Off => (false, "VPN       ВЫКЛ".to_string()),
    });

    if probe::port_open(cfg.split_port, Duration::from_millis(300)) {
        let node = socks::reachable(&cfg.split_upstream, Duration::from_secs(1));
        lines.push((node, format!(
            "Сплит     ВКЛ    {}",
            if node { "нода отвечает" } else { "нода молчит" }
        )));
    }
    let share_on = probe::port_open(cfg.share_port, Duration::from_millis(300));
    if share_on {
        let ip = probe::lan_ip().map(|i| i.to_string()).unwrap_or_default();
        let clients = probe::connected_peers(cfg.share_port).len();
        let tail = match clients {
            0 => "устройств нет".to_string(),
            n => format!("устройств: {n}"),
        };
        lines.push((true, format!("Раздача   ВКЛ    {ip}:{}  {tail}", cfg.share_port)));
    }

    let tg = Telegram::new(cfg);
    lines.push(if tg.running() {
        let where_ = probe::lan_ip()
            .map(|ip| format!("{ip}:{}", cfg.tg_port))
            .unwrap_or_else(|| format!("порт {}", cfg.tg_port));
        (true, format!("Telegram  ВКЛ    {where_}"))
    } else {
        (false, "Telegram  ВЫКЛ".to_string())
    });

    lines
}

fn print_status(cfg: &Config) {
    for (ok, line) in status_lines(cfg) {
        let color = if ok { GREEN } else { RED };
        println!("{color}{line}{RESET}");
    }
    println!("{DIM}{}{RESET}", watch::status());
    match probe::external_addr(Duration::from_secs(5)) {
        Some(a) => println!("внешний адрес: {} · {} · {}", a.ip, a.country, a.org),
        None => println!("{RED}внешний адрес: не отвечает{RESET}"),
    }
}

pub fn run_test_public(cfg: &Config) {
    let z = Zapret::new(cfg);
    println!(
        "Стратегия: {}   zapret: {}",
        z.strategy().unwrap_or_else(|| "?".into()),
        if z.state() == zapret::State::On { "включён" } else { "выключен" }
    );
    if !probe::curl_available() {
        println!("{YELLOW}curl не найден — проверить доступность нечем{RESET}");
        return;
    }
    println!("Доступность:");
    for (label, url) in [
        ("youtube.com ", "https://www.youtube.com/generate_204"),
        ("ytimg (CDN) ", "https://i.ytimg.com/generate_204"),
        ("discord.com ", "https://discord.com/api/v9/gateway"),
        ("telegram.org", "https://web.telegram.org/"),
    ] {
        let ok = probe::reachable(url, Duration::from_secs(10));
        let (color, verdict) = if ok {
            (GREEN, "открывается")
        } else {
            (RED, "НЕ открывается")
        };
        println!("{color}  {label} — {verdict}{RESET}");
    }

    if Telegram::new(cfg).running() {
        println!("{GREEN}  прокси TGLock — слушает порт {}{RESET}", cfg.tg_port);
    }

    match probe::google_speed(Duration::from_secs(20)) {
        Some(kbs) => println!("Скорость с серверов Google: {kbs:.0} КБ/с"),
        None => println!("Скорость с серверов Google: не измерилась"),
    }
    println!(
        "{DIM}Точный вердикт по YouTube — открыть видео в 1080p. Тормозит после первых секунд = стратегия не та.{RESET}"
    );
}

fn print_help() {
    println!(
        "{BOLD}netpult — пульт обхода блокировок{RESET}

  net                  интерактивный экран (по умолчанию)
  net status           состояние всего сразу и внешний адрес
  net test             проверить YouTube / Discord / Telegram и скорость

{BOLD}zapret{RESET} — обход DPI на прямом трафике
  net on | off | toggle | restart
  net strat            список стратегий
  net strat <номер|имя>  поставить стратегию
  net tune             подобрать рабочую стратегию перебором
  net tune --all       перебрать все, не останавливаясь на первой хорошей

{BOLD}сторож{RESET} — сам чинит, когда обход отвалился
  net watch --once     один проход проверки прямо сейчас
  net watch install    поставить в автозапуск
  net watch uninstall  убрать из автозапуска
  net watch log        что чинилось

{BOLD}профили{RESET} — своё поведение в каждой сети
  net profile          какая сеть и что для неё сохранено
  net profile save     запомнить текущее состояние для этой сети
  net profile apply    привести всё к профилю сети
  net profile list     все профили

{BOLD}раздача{RESET} — телефон ходит в интернет через этот компьютер
  net share on|off     включить / выключить прокси для телефона (пароль обязателен)
  net share status     адрес, порт, пароль и подключённые устройства
  net share password   показать текущий пароль
  net share newpass    сменить пароль (по твоей команде, сам не меняется)

{BOLD}сплит{RESET} — через ноду только нужные домены, остальное напрямую
  net split on|off     включить / выключить сплит-прокси
  net split list       какие домены идут через ноду (свой список + автосписок)
  net split add <дом>  добавить домен в свой список
  net split update     обновить автосписок геоблока (itdoginfo, ~466 доменов)
  net split log        что шло через ноду, а что напрямую

{BOLD}VPN{RESET} — для геоблока, когда сервис режет по стране
  net vpn              открыть окно клиента
  net vpn off          закрыть

{BOLD}Telegram{RESET} — локальный прокси, без чужих серверов
  net tg on | off      включить / выключить
  net tg qr            QR для телефона (net tg qr --png [файл] — сохранить картинкой)
  net tg link          ссылки для компьютера и телефона
  net tg newsecret     сменить секрет прокси (QR на телефоне придётся пересканировать)"
    );
}
