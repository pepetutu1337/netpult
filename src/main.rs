//! netpult — один пульт для обхода блокировок: zapret, VPN и прокси Telegram.

mod config;
mod json;
mod picker;
mod probe;
mod profile;
mod split;
mod sudoer;
mod qr;
mod route;
mod share;
mod singbox;
mod socks;
mod sub;
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

    let result = dispatch(&cfg, command, &rest);

    if let Err(message) = result {
        eprintln!("{RED}{message}{RESET}");
        std::process::exit(1);
    }
}

/// Разбор команды. Вынесен из main, чтобы палитра могла запускать выбранное
/// тем же путём, каким его набирают руками.
pub fn dispatch(cfg: &Config, command: &str, rest: &[&str]) -> Result<(), String> {
    dispatch_with(cfg, command, rest, true)
}

/// `palette` — можно ли на незнакомую команду открыть выбор. Из экрана нельзя:
/// там подсказки и так под строкой ввода, второй список поверх собьёт с толку.
pub fn dispatch_with(
    cfg: &Config,
    command: &str,
    rest: &[&str],
    palette: bool,
) -> Result<(), String> {
    let rest = rest.to_vec();
    match command {
        "tui" | "menu" | "" => tui::run(cfg),
        "status" => {
            print_status(cfg);
            Ok(())
        }
        "on" => zapret_action(cfg, "Включаю обход", |z| z.start()),
        "off" => zapret_action(cfg, "Выключаю обход", |z| z.stop()),
        "restart" => zapret_action(cfg, "Перезапускаю обход", |z| z.restart()),
        "toggle" => toggle_zapret(cfg),
        "strat" | "strategy" => strategy(cfg, rest.first().copied()),
        "vpn" => vpn_command(cfg, &rest),
        "tg" | "telegram" => telegram_command(cfg, &rest),
        "path" | "route" | "how" => route::report(cfg, rest.contains(&"--deep")),
        "test" => {
            run_test_public(cfg);
            Ok(())
        }
        "tune" => tune_command(cfg, &rest),
        "profile" | "prof" => profile_command(cfg, &rest),
        "share" => share_command(cfg, &rest),
        "split" => split_command(cfg, &rest),
        "watch" => watch_command(cfg, &rest),
        "qr" => show_qr_maybe_png(cfg, &rest),
        "--raw" => raw_qr(rest.first().copied()),
        "version" | "-V" | "--version" => {
            println!("netpult {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other if palette => unknown_command(cfg, other, &rest),
        other => Err(format!(
            "нет такой команды: {other}{}",
            match picker::closest(&commands(), other, 2).first() {
                Some(close) => format!(". Похоже на «{close}»"),
                None => String::new(),
            }
        )),
    }
}

/// Ошибка на незнакомое подслово: подсказываем ближайшее из тех, что есть у
/// этой команды, — «nods» почти всегда означает «nodes».
fn unknown_sub(prefix: &str, typed: &str) -> String {
    let all = commands();
    let family: Vec<(&str, &str)> = all
        .iter()
        .filter(|(name, _)| name.starts_with(&format!("{prefix} ")))
        .copied()
        .collect();
    match picker::closest(&family, typed, 1).first() {
        Some(close) => format!("нет такого: {prefix} {typed}. Похоже на «net {close}»"),
        None => format!("нет такого: {prefix} {typed}"),
    }
}

/// Команды пульта для палитры: что набрать и что оно делает.
pub fn commands() -> Vec<(&'static str, &'static str)> {
    vec![
        ("status", "состояние всего и внешний адрес"),
        ("test", "проверить YouTube, Discord, Telegram и скорость"),
        ("path", "через что идёт интернет и что чему мешает"),
        ("on", "включить zapret"),
        ("off", "выключить zapret"),
        ("restart", "перезапустить zapret"),
        ("strat", "список стратегий обхода"),
        ("tune", "подобрать рабочую стратегию перебором"),
        ("vpn on", "поднять туннель"),
        ("vpn off", "снять туннель"),
        ("vpn nodes", "ноды с задержками"),
        ("vpn use", "выбрать ноду стрелками"),
        ("vpn auto", "выбирать самую быструю самому"),
        ("vpn update", "перечитать подписку"),
        ("vpn sub", "загрузить подписку по ссылке"),
        ("vpn core install", "поставить ядро sing-box"),
        ("vpn info", "подписка: трафик, срок, страница устройств"),
        ("vpn hwid", "идентификатор этого устройства для панели"),
        ("vpn log", "журнал ядра"),
        ("tg on", "включить прокси Telegram"),
        ("tg off", "выключить прокси Telegram"),
        ("tg qr", "QR прокси для телефона"),
        ("tg link", "ссылки на прокси"),
        ("split on", "сплит: нужные домены через ноду"),
        ("split off", "выключить сплит"),
        ("split list", "какие домены идут через ноду"),
        ("split update", "обновить автосписок геоблока"),
        ("split log", "что шло через ноду"),
        ("share on", "раздать интернет телефону"),
        ("share off", "выключить раздачу"),
        ("share status", "адрес, порт, пароль, устройства"),
        ("profile", "профиль этой сети"),
        ("profile save", "запомнить состояние для этой сети"),
        ("profile apply", "привести всё к профилю сети"),
        ("watch --once", "один проход проверки"),
        ("watch install", "сторож в автозапуск"),
        ("watch log", "что чинилось"),
        ("help", "справка"),
    ]
}

/// Незнакомая команда — не приговор: почти всегда это опечатка или половина
/// нужного слова. Показываем палитру, отфильтрованную набранным, и запускаем
/// выбранное. Если ввод не с терминала — просто советуем похожее.
fn unknown_command(cfg: &Config, typed: &str, rest: &[&str]) -> Result<(), String> {
    let typed_full = if rest.is_empty() {
        typed.to_string()
    } else {
        format!("{typed} {}", rest.join(" "))
    };
    let all = commands();
    let items: Vec<picker::Item> = all
        .iter()
        .map(|(name, about)| picker::Item::new(*name).hint(*about))
        .collect();

    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let close = picker::closest(&all, &typed_full, 3);
        if close.is_empty() {
            return Err(format!("неизвестная команда: {typed_full}"));
        }
        return Err(format!(
            "неизвестная команда: {typed_full}. Похоже на: {}",
            close.join(", ")
        ));
    }

    match picker::choose_prefilled("КОМАНДЫ", &items, &typed_full)? {
        Some(index) => {
            let parts: Vec<&str> = all[index].0.split(' ').collect();
            dispatch(cfg, parts[0], &parts[1..])
        }
        None => Ok(()),
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

/// `net vpn` — управление туннелем: клиент Happ там, где он есть, и своё ядро
/// sing-box там, где Happ не встаёт (macOS 11, например).
fn vpn_command(cfg: &Config, rest: &[&str]) -> Result<(), String> {
    let core = singbox::Core::new(cfg);
    // Своё ядро главнее клиента: если подписка разобрана, туннель поднимает
    // netpult сам. Happ остаётся запасным путём, пока подписки нет.
    let own_core = sub::config_path().exists() && cfg.core_bin.is_some();
    match rest.first().copied() {
        None | Some("on") | Some("open") => {
            if own_core {
                core.start()?;
                print_core_status();
                Ok(())
            } else {
                Vpn::new(cfg).open()
            }
        }
        Some("off") => {
            if own_core && core.state() == singbox::State::Up {
                core.stop()
            } else {
                Vpn::new(cfg).close()
            }
        }
        Some("sub") | Some("subscription") => {
            let url = rest
                .get(1)
                .copied()
                .ok_or("нужна ссылка: net vpn sub <ссылка на подписку>")?;
            vpn_subscribe(url)
        }
        Some("update") => {
            let url = sub::saved_url()?;
            vpn_subscribe(&url)
        }
        Some("core") => match rest.get(1).copied() {
            Some("install") | None => {
                println!("Качаю ядро...");
                let path = singbox::install_core()?;
                println!("{GREEN}Ядро: {}{RESET}", path.display());
                Ok(())
            }
            Some(other) => Err(format!("net vpn core install, а не «{other}»")),
        },
        Some("info") => vpn_info(),
        Some("hwid") => vpn_hwid(rest.get(1).copied()),
        Some("nodes") | Some("list") => vpn_nodes(cfg),
        Some("use") | Some("select") => {
            let want = rest[1..].join(" ");
            if want.trim().is_empty() {
                vpn_pick(cfg)
            } else {
                vpn_use(&want)
            }
        }
        Some("auto") => {
            singbox::select(singbox::AUTO)?;
            println!("{GREEN}Нода выбирается автоматически по задержке{RESET}");
            Ok(())
        }
        Some("log") => {
            let path = config::state_dir().join("core.log");
            let text = std::fs::read_to_string(&path)
                .map_err(|_| format!("журнала ещё нет: {}", path.display()))?;
            for line in text.lines().rev().take(30).collect::<Vec<_>>().iter().rev() {
                println!("{line}");
            }
            Ok(())
        }
        Some(other) => Err(unknown_sub("vpn", other)),
    }
}

/// Список нод с задержками. Пока ядро не поднято, задержку взять неоткуда —
/// показываем хотя бы имена, чтобы было видно, что подписка на месте.
fn vpn_nodes(cfg: &Config) -> Result<(), String> {
    let names: Vec<String> = sub::load_nodes()?.into_iter().map(|n| n.name).collect();
    if singbox::Core::new(cfg).state() != singbox::State::Up {
        for (i, name) in names.iter().enumerate() {
            println!("{:>3}. {name}", i + 1);
        }
        println!("\nвсего нод: {}. Задержки появятся, когда туннель поднят.", names.len());
        return Ok(());
    }
    let current = singbox::current_node();
    println!("Меряю задержки...");
    for (i, name) in names.iter().enumerate() {
        let mark = if current.as_deref() == Some(name.as_str()) {
            "●"
        } else {
            " "
        };
        match singbox::delay(name, 3000) {
            Some(ms) => {
                let color = if ms < 300 {
                    GREEN
                } else if ms < 800 {
                    YELLOW
                } else {
                    RED
                };
                println!("{:>3}. {mark} {name} — {color}{ms} мс{RESET}", i + 1);
            }
            None => println!("{:>3}. {mark} {name} — {RED}не отвечает{RESET}", i + 1),
        }
    }
    if let Some(now) = current {
        println!("\nсейчас: {now}");
    }
    Ok(())
}

/// Выбор ноды стрелками с поиском по мере набора. Задержки подставляются, если
/// туннель поднят: выбирать вслепую из двух десятков стран бессмысленно.
fn vpn_pick(cfg: &Config) -> Result<(), String> {
    let names: Vec<String> = sub::load_nodes()?.into_iter().map(|n| n.name).collect();
    let up = singbox::Core::new(cfg).state() == singbox::State::Up;
    let current = if up { singbox::current_node() } else { None };
    if up {
        println!("Меряю задержки...");
    }
    let items: Vec<picker::Item> = names
        .iter()
        .map(|name| {
            let mut item = picker::Item::new(name.clone())
                .current(current.as_deref() == Some(name.as_str()));
            if up {
                item = item.hint(match singbox::delay(name, 3000) {
                    Some(ms) => format!("{ms} мс"),
                    None => "не отвечает".to_string(),
                });
            }
            item
        })
        .collect();
    match picker::choose("НОДЫ", &items)? {
        Some(index) => vpn_use(&names[index]),
        None => Ok(()),
    }
}

/// Выбор ноды номером из списка или частью имени — набирать флаги стран руками
/// невозможно.
fn vpn_use(want: &str) -> Result<(), String> {
    let names: Vec<String> = sub::load_nodes()?.into_iter().map(|n| n.name).collect();
    let found = match want.trim().parse::<usize>() {
        Ok(n) if n >= 1 && n <= names.len() => names[n - 1].clone(),
        Ok(n) => return Err(format!("ноды №{n} нет, всего {}", names.len())),
        Err(_) => {
            let needle = want.to_lowercase();
            names
                .iter()
                .find(|n| n.to_lowercase().contains(&needle))
                .cloned()
                .ok_or_else(|| format!("ноды с «{want}» в имени нет"))?
        }
    };
    singbox::select(&found)?;
    println!("{GREEN}Нода: {found}{RESET}");
    Ok(())
}

/// Что подписка говорит о себе: сколько осталось, до какого числа, где её
/// страница. Там же список устройств — панель ведёт его у себя, и попасть в
/// него можно только этой ссылкой.
fn vpn_info() -> Result<(), String> {
    let url = sub::saved_url()?;
    let info = sub::info(&url, Duration::from_secs(20))?;
    if let Some(title) = &info.title {
        println!("{BOLD}{title}{RESET}");
    }
    let gb = |bytes: u64| bytes as f64 / 1024.0 / 1024.0 / 1024.0;
    if info.total_bytes > 0 {
        println!(
            "Трафик: {:.2} ГБ из {:.0} ГБ",
            gb(info.used_bytes),
            gb(info.total_bytes)
        );
    } else {
        println!("Трафик: {:.2} ГБ (без ограничения)", gb(info.used_bytes));
    }
    match info.expires {
        Some(stamp) => {
            let left = stamp - now_seconds();
            let days = left / 86400;
            if left > 0 {
                println!("Осталось дней: {days}");
            } else {
                println!("{RED}Срок вышел{RESET}");
            }
        }
        None => println!("Срок: не указан"),
    }
    println!("\nЭто устройство: hwid {}", sub::hwid());
    if let Some(page) = &info.page {
        println!("Устройства и их удаление — на странице подписки:\n  {page}");
    }
    if let Some(support) = &info.support {
        println!("Поддержка: {support}");
    }
    println!(
        "{DIM}Панель считает каждое приложение отдельным устройством. Чтобы пульт занял\nместо соседа, а не своё: net vpn hwid <его идентификатор>.{RESET}"
    );
    Ok(())
}

/// Показать или сменить идентификатор устройства.
fn vpn_hwid(value: Option<&str>) -> Result<(), String> {
    match value {
        None => {
            println!("{}", sub::hwid());
            println!("{DIM}Хранится в {}{RESET}", sub::hwid_path().display());
            println!(
                "{DIM}Сменить: net vpn hwid <значение>. Новый случайный: net vpn hwid --reset{RESET}"
            );
            Ok(())
        }
        Some("--reset") | Some("reset") => {
            let fresh = sub::reset_hwid()?;
            println!("{GREEN}Новый идентификатор: {fresh}{RESET}");
            println!(
                "{YELLOW}Панель посчитает пульт новым устройством и займёт ещё одно место.{RESET}"
            );
            Ok(())
        }
        Some(other) => {
            let set = sub::set_hwid(other)?;
            println!("{GREEN}Идентификатор устройства: {set}{RESET}");
            println!("{DIM}Перечитай подписку, чтобы панель это увидела: net vpn update{RESET}");
            Ok(())
        }
    }
}

/// Секунды с начала эпохи — для срока подписки.
fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn print_core_status() {
    match singbox::current_node() {
        Some(now) => println!("{GREEN}Туннель поднят{RESET} — нода: {now}"),
        None => println!("{GREEN}Туннель поднят{RESET}"),
    }
}

fn vpn_subscribe(url: &str) -> Result<(), String> {
    println!("Забираю подписку...");
    let mut nodes = sub::fetch(url, Duration::from_secs(30))?;
    sub::dedupe_names(&mut nodes);
    let config = singbox::build_config(&nodes)?;
    let path = sub::save(url, &nodes, &config)?;
    println!(
        "{GREEN}Разобрано нод: {}{RESET}\nКонфиг: {}",
        nodes.len(),
        path.display()
    );
    println!("Список нод — net vpn nodes");
    Ok(())
}

/// Общая обвязка для «включи/выключи/перезапусти»: сказать, что делаем, до
/// того как делать, и показать итог. Молчание в этом месте выглядит зависанием
/// даже когда всё занимает полсекунды.
fn zapret_action(
    cfg: &Config,
    what: &str,
    action: impl Fn(&Zapret) -> Result<(), String>,
) -> Result<(), String> {
    println!("{what}...");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    action(&Zapret::new(cfg))?;
    for (ok, line) in status_lines(cfg) {
        let color = if ok { GREEN } else { RED };
        println!("{color}{line}{RESET}");
    }
    Ok(())
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
    // Сплит писался под времена, когда ноду держал Happ в режиме прокси. Своё
    // ядро делит трафик само, по правилам маршрутизации, и второй делитель
    // поверх него — лишний слой.
    if singbox::Core::new(cfg).state() == singbox::State::Up {
        println!("{YELLOW}Свой туннель уже поднят и делит трафик сам — сплит поверх него не нужен.{RESET}");
    } else if !socks::reachable(&cfg.split_upstream, std::time::Duration::from_secs(2)) {
        println!("{YELLOW}Сейчас нода-SOCKS не отвечает: подними Happ в режиме прокси (не TUN) или свой туннель — net vpn on.{RESET}");
    }
}

/// Своя служба пользователя: сплит и раздача устроены одинаково — файл юнита,
/// перезагрузка, включение с запуском. Отличаются только именем и командой.
///
/// Systemd на включении печатает про созданный симлинк, а на выключении — про
/// удалённый; человеку это ничего не говорит, поэтому его вывод забираем себе.
/// И главное: `enable --now` возвращается раньше, чем служба успевает занять
/// порт, поэтому дожидаемся порта — иначе следующая же команда честно скажет
/// «выключено» о том, что секунду назад включили.
fn user_service(action: &str, name: &str, description: &str, command: &str, port: u16) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err(format!(
            "служба на {} ещё не подведена — запусти «netpult {command}» вручную",
            std::env::consts::OS
        ));
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = config::home().join(".config/systemd/user");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let unit = dir.join(format!("{name}.service"));
    if action == "on" {
        let body = format!(
            "[Unit]\nDescription={description} (порт {port})\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={} {command}\nRestart=on-failure\nRestartSec=10\n\n[Install]\nWantedBy=default.target\n",
            exe.display()
        );
        std::fs::write(&unit, body).map_err(|e| e.to_string())?;
    }

    let run = |args: &[&str]| -> Result<(), String> {
        let out = std::process::Command::new("systemctl")
            .args(args)
            .output()
            .map_err(|e| format!("не запустился systemctl: {e}"))?;
        if out.status.success() {
            return Ok(());
        }
        let trouble = String::from_utf8_lossy(&out.stderr);
        Err(format!(
            "systemctl {}: {}",
            args.join(" "),
            trouble.trim().lines().next().unwrap_or("не сработало")
        ))
    };
    run(&["--user", "daemon-reload"])?;
    let service = format!("{name}.service");
    if action != "on" {
        return run(&["--user", "disable", "--now", &service]);
    }
    run(&["--user", "enable", "--now", &service])?;

    let waiting = std::time::Instant::now();
    while waiting.elapsed() < Duration::from_secs(5) {
        if probe::port_open(port, Duration::from_millis(200)) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    Err(format!(
        "служба запущена, но порт {port} так и не занят — смотри: journalctl --user -u {service} -n 20"
    ))
}

fn split_service(action: &str, port: u16) -> Result<(), String> {
    user_service(
        action,
        "netpult-split",
        "netpult — сплит-прокси",
        "split serve",
        port,
    )
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
    user_service(
        action,
        "netpult-share",
        "netpult — раздача обхода на телефон",
        "share serve",
        port,
    )
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
        // На маке и в Windows свой движок zapret ставится отдельно и пультом
        // пока не управляется — пугать этим красной строкой незачем.
        zapret::State::Missing if !cfg!(target_os = "linux") => {
            (false, "zapret    управляется отдельно (не Linux)".to_string())
        }
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
        ("ytimg (превью)", "https://i.ytimg.com/generate_204"),
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

    // Отдельно и последним — то, ради чего всё затевается. Страница и превью
    // открываются даже со сломанным обходом, а видео при этом не идёт.
    let video = probe::video(Duration::from_secs(10));
    if !video.checked {
        println!("{DIM}  видео-CDN   — сервер для проверки не нашёлся{RESET}");
    } else {
        let (color, verdict) = if video.plain {
            (GREEN, "идёт")
        } else {
            (RED, "МОЛЧИТ")
        };
        println!("{color}  видео-CDN   — {verdict}{RESET}");
        match video.browser {
            Some(true) => println!("{GREEN}  то же браузерным приветствием TLS — идёт{RESET}"),
            Some(false) => {
                println!("{YELLOW}  то же браузерным приветствием TLS — МОЛЧИТ{RESET}");
                println!(
                    "{DIM}  Вот так и выглядит «в консоли всё есть, а в браузере ютуб не грузится»:\n  браузер шлёт приветствие на два килобайта, DPI его собирает и режет.{RESET}"
                );
            }
            None => {}
        }
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
        "{BOLD}netpult{RESET} — обход блокировок: zapret, VPN, прокси Telegram, раздача, сплит.

{BOLD}экран{RESET}
  net                  открыть экран: состояние, ноды, строка команд
  {DIM}в строке набирается любая команда отсюда — покажет похожие;
  пока строка пуста: ↑↓ и колесо мыши — нода, Enter — включить её,
  p — замерить задержки, r — обновить, q — выход;
  ссылку на подписку можно просто вставить в строку{RESET}

{BOLD}zapret{RESET} — обход DPI: YouTube, Discord
  net on               включить
  net off              выключить
  net restart          перезапустить
  net toggle           переключить
  net strat            список стратегий
  net strat <номер>    поставить стратегию номером или именем
  net tune             подобрать рабочую перебором
  net tune --all       перебрать все, не останавливаясь на первой хорошей

{BOLD}VPN{RESET} — своё ядро sing-box вместо Happ
  net vpn core install поставить ядро под свою систему
  net vpn sub <ссылка> разобрать подписку и собрать конфиг
  net vpn update       перечитать подписку по сохранённой ссылке
  net vpn on           поднять туннель (спросит пароль: TUN нужен root)
  net vpn off          снять туннель
  net vpn nodes        ноды с задержками
  net vpn use          выбрать ноду стрелками
  net vpn use <номер|имя>  выбрать сразу: «net vpn use Турция»
  net vpn auto         выбирать самую быструю самому
  net vpn info         подписка: трафик, срок, ссылка на устройства
  net vpn hwid         идентификатор этого устройства
  net vpn hwid <знач>  занять место другого приложения (тот же hwid)
  net vpn hwid --reset новый идентификатор — панель сочтёт новым устройством
  net vpn log          журнал ядра

{BOLD}Telegram{RESET} — локальный прокси, без чужих серверов
  net tg on            включить
  net tg off           выключить
  net tg qr            QR для телефона
  net tg qr --png [файл]   сохранить QR картинкой
  net tg link          ссылки для компьютера и телефона
  net tg newsecret     сменить секрет прокси

{BOLD}сплит{RESET} — через ноду только нужные домены, остальное напрямую
  net split on         включить
  net split off        выключить
  net split list       какие домены идут через ноду
  net split add <дом>  добавить домен в свой список
  net split update     обновить автосписок геоблока
  net split log        что шло через ноду, а что напрямую

{BOLD}раздача{RESET} — телефон в интернет через этот компьютер
  net share on         включить (пароль обязателен)
  net share off        выключить
  net share open       включить без пароля, если очень надо
  net share status     адрес, порт, пароль, подключённые устройства
  net share password   показать пароль
  net share newpass    сменить пароль

{BOLD}профили сетей{RESET} — своё поведение в каждой сети
  net profile          какая сеть и что для неё сохранено
  net profile save     запомнить состояние для этой сети
  net profile apply    привести всё к профилю сети
  net profile list     все профили
  net profile forget   забыть профиль этой сети

{BOLD}сторож{RESET} — чинит упавшее без тебя
  net watch --once     один проход проверки прямо сейчас
  net watch install    поставить в автозапуск
  net watch uninstall  убрать из автозапуска
  net watch log        что чинилось

{BOLD}прочее{RESET}
  net status           состояние всего и внешний адрес
  net path             через что идёт интернет: свой обход, чужой VPN,
                       обход на роутере, и что чему мешает
  net path --deep      то же, но с проверкой: снимет свой обход на пару
                       секунд и посмотрит, открывается ли без него
  net test             проверить YouTube, Discord, Telegram и скорость
  net version          версия
  net help             эта справка"
    );
}
