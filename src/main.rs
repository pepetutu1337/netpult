//! netpult — один пульт для обхода блокировок: zapret, VPN и прокси Telegram.

mod calls;
mod config;
mod deps;
mod dns;
mod doctor;
mod json;
mod network;
mod picker;
mod probe;
mod progress;
mod profile;
mod split;
mod sudoer;
mod qr;
mod route;
mod share;
mod singbox;
mod socks;
mod sub;
mod subs;
mod sync;
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
    // Пульт красит вывод и стирает строку прогресса управляющими
    // последовательностями. Windows-консоль по умолчанию их не разбирает и
    // печатает как текст; этот вызов включает их разбор, если консоль умеет.
    // На Linux и macOS он ничего не делает.
    #[cfg(windows)]
    let _ = crossterm::ansi_support::supports_ansi();
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
        "dns" => dns_command(cfg, &rest),
        "deps" | "install" => deps_command(cfg, &rest),
        "calls" | "звонки" => calls_command(cfg, &rest),
        "doctor" | "fix" | "осмотр" => doctor::run(cfg, rest.contains(&"--fix") || command == "fix"),
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
        ("toggle", "переключить zapret"),
        ("strat", "список стратегий обхода"),
        ("tune", "подобрать рабочую стратегию перебором"),
        ("dns on", "шифрованный DNS для всей системы"),
        ("dns off", "вернуть DNS своей сети"),
        ("dns status", "шифруется ли DNS сейчас"),
        ("dns test", "проверить: куда уходят запросы имён"),
        ("vpn on", "поднять туннель"),
        ("vpn off", "снять туннель"),
        ("vpn nodes", "ноды с задержками"),
        ("vpn use", "выбрать ноду стрелками"),
        ("vpn auto", "выбирать самую быструю самому"),
        ("vpn update", "перечитать подписку"),
        ("vpn sync", "обновить ноды в конфиге ядра на месте"),
        ("vpn add", "добавить свои ноды из json-файла"),
        ("vpn bank", "запас нод: что лежит и когда отвечало"),
        ("vpn bank rm", "убрать ноду из запаса"),
        ("vpn sub", "загрузить подписку по ссылке"),
        ("vpn core install", "поставить ядро sing-box"),
        ("vpn info", "подписка: трафик, срок, страница устройств"),
        ("vpn hwid", "идентификатор этого устройства для панели"),
        ("vpn log", "журнал ядра"),
        ("calls", "чем прикрыты звонки Telegram"),
        ("calls on", "починить звонки: через ноду только Telegram"),
        ("calls on --dpi", "починить звонки дурением DPI, без ноды"),
        ("calls on --here", "туннель отсюда, даже за своим роутером"),
        ("calls off", "вернуть звонки как было"),
        ("calls update", "обновить адреса Telegram"),
        ("deps", "что нужно пульту и что нашлось"),
        ("deps install", "поставить недостающее"),
        ("doctor", "осмотр: что сломано и чем чинится"),
        ("doctor --fix", "осмотр и починка безопасного"),
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
        ("version", "версия пульта"),
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
            if sub::config_path().exists() {
                ensure_dep(cfg, deps::Kind::Core)?;
            }
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
        // Обновление нод в чужом конфиге sing-box: на роутере ядро подняли
        // отдельно от пульта, и трогать там можно только список нод.
        Some("sync") => {
            let mut plan = sync::Plan::default();
            let mut args = rest[1..].iter().copied();
            while let Some(arg) = args.next() {
                match arg {
                    "--config" => match args.next() {
                        Some(path) => plan.config = path.into(),
                        None => return Err("--config ждёт путь к конфигу".into()),
                    },
                    "--binary" => match args.next() {
                        Some(path) => plan.binary = path.into(),
                        None => return Err("--binary ждёт путь к sing-box".into()),
                    },
                    "--proxy" => match args.next() {
                        Some(addr) => plan.probe_proxy = addr.to_string(),
                        None => return Err("--proxy ждёт адрес вида socks5h://127.0.0.1:1180".into()),
                    },
                    "--restart" => {
                        let tail: Vec<String> = args.by_ref().map(str::to_string).collect();
                        if tail.is_empty() {
                            return Err("--restart ждёт команду перезапуска ядра".into());
                        }
                        plan.restart = tail;
                    }
                    "--dry-run" => plan.dry_run = true,
                    "--fresh-only" => plan.keep_alive = false,
                    other => return Err(format!("непонятный ключ: {other}")),
                }
            }
            // Шесть отрезков: подписка, сборка, проверка, бэкап с заменой,
            // перезапуск, проба наружу. Седьмой (откат) считается запасным.
            let mut ход = progress::Progress::new("обновляю", 6).logged();
            let report = {
                let ход = &mut ход;
                sync::run(&plan, &mut |что| {
                    ход.step(что);
                    ход.tick();
                })
            };
            ход.clear();
            let report = report?;
            if report.rolled_back {
                println!("{YELLOW}{}{RESET}", report.note);
                println!("{DIM}прежний конфиг лежит в {}{RESET}", report.backup.display());
                return Err("обновление откачено".into());
            }
            let kept = if report.kept > 0 {
                format!(" (из них перенесено прежних: {})", report.kept)
            } else {
                String::new()
            };
            println!("{GREEN}{}: {}{kept}{RESET}", report.note, report.nodes);
            let what = if plan.dry_run { "собранный конфиг" } else { "прежний конфиг" };
            println!("{DIM}{what}: {}{RESET}", report.backup.display());
            Ok(())
        }
        Some("sub") | Some("subscription") => {
            let url = rest
                .get(1)
                .copied()
                .ok_or("нужна ссылка: net vpn sub <ссылка на подписку>")?;
            vpn_subscribe(cfg, url)
        }
        Some("update") => vpn_refresh(cfg),
        Some("subs") => vpn_subs(cfg, &rest[1..]),
        Some("core") => match rest.get(1).copied() {
            Some("install") | None => {
                println!("Качаю ядро...");
                let path = singbox::install_core()?;
                println!("{GREEN}Ядро: {}{RESET}", path.display());
                Ok(())
            }
            Some(other) => Err(format!("net vpn core install, а не «{other}»")),
        },
        // Свои ноды из файла: тот же разбор, что и у подписки, поэтому годится
        // и выгрузка sing-box, и xray, и просто список ссылок.
        Some("add") => match rest.get(1).copied() {
            Some(path) => vpn_add(path),
            None => Err("нужен файл: net vpn add <файл.json>".into()),
        },
        Some("bank") => match rest.get(1).copied() {
            None | Some("list") => vpn_bank_list(),
            Some("rm") | Some("del") => {
                let what = rest[2..].join(" ");
                if what.trim().is_empty() {
                    return Err("что убрать: net vpn bank rm <имя|адрес:порт>".into());
                }
                vpn_bank_rm(&what)
            }
            Some(other) => Err(format!("net vpn bank [list|rm], а не «{other}»")),
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
            let path = match rest.get(1).copied() {
                Some("sub") | Some("subs") => sub::refresh_log_path(),
                _ => config::state_dir().join("core.log"),
            };
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
    let mut ход = progress::Progress::new("меряю", names.len());
    let mut живых = 0;
    let mut сумма = 0u32;
    for (i, name) in names.iter().enumerate() {
        ход.step(name);
        let mark = if current.as_deref() == Some(name.as_str()) {
            "●"
        } else {
            " "
        };
        let строка = match singbox::delay(name, 3000) {
            Some(ms) => {
                живых += 1;
                сумма += ms;
                let color = if ms < 300 {
                    GREEN
                } else if ms < 800 {
                    YELLOW
                } else {
                    RED
                };
                format!("{:>3}. {mark} {name} — {color}{ms} мс{RESET}", i + 1)
            }
            None => format!("{:>3}. {mark} {name} — {RED}не отвечает{RESET}", i + 1),
        };
        ход.line(&строка);
        ход.tick();
    }
    let заняло = ход.длительность();
    ход.finish();
    println!();
    if let Some(среднее) = сумма.checked_div(живых) {
        println!(
            "{DIM}отвечает {живых} из {}, в среднем {среднее} мс · прогон занял {заняло}{RESET}",
            names.len()
        );
    } else {
        println!("{RED}не ответила ни одна нода{RESET}");
    }
    if let Some(now) = current {
        println!("сейчас: {now}");
    }
    Ok(())
}

/// Выбор ноды стрелками с поиском по мере набора. Задержки подставляются, если
/// туннель поднят: выбирать вслепую из двух десятков стран бессмысленно.
fn vpn_pick(cfg: &Config) -> Result<(), String> {
    let names: Vec<String> = sub::load_nodes()?.into_iter().map(|n| n.name).collect();
    let up = singbox::Core::new(cfg).state() == singbox::State::Up;
    let current = if up { singbox::current_node() } else { None };
    let mut ход = progress::Progress::new("меряю", if up { names.len() } else { 0 });
    let items: Vec<picker::Item> = names
        .iter()
        .map(|name| {
            let mut item = picker::Item::new(name.clone())
                .current(current.as_deref() == Some(name.as_str()));
            if up {
                ход.step(name);
                item = item.hint(match singbox::delay(name, 3000) {
                    Some(ms) => format!("{ms} мс"),
                    None => "не отвечает".to_string(),
                });
                ход.tick();
            }
            item
        })
        .collect();
    ход.clear();
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

/// Добавить ноды из файла. Разбор тот же, что у подписки, поэтому подойдёт и
/// выгрузка sing-box, и конфиг xray, и просто список ссылок построчно.
fn vpn_add(path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("не прочитать {path}: {e}"))?;
    let found = sub::parse(&text)?;
    if found.is_empty() {
        return Err("в файле не нашлось ни одной ноды".into());
    }
    let mut bank = sub::load_bank();
    let added = sub::add_missing(&mut bank, &found);
    sub::save_bank(&bank)?;
    if added == 0 {
        println!("{YELLOW}Все {} нод уже в запасе{RESET}", found.len());
        return Ok(());
    }
    println!("{GREEN}Добавлено в запас: {added}{RESET}");
    println!("{DIM}В работу попадут при следующем net vpn update{RESET}");
    Ok(())
}

/// Сколько прошло с отклика — словами, потому что «1788063000» никому ничего
/// не говорит.
pub(crate) fn когда(last_ok: Option<u64>) -> String {
    let Some(then) = last_ok else {
        return "ни разу".to_string();
    };
    let прошло = sub::now_secs().saturating_sub(then);
    match прошло {
        0..=300 => "только что".to_string(),
        301..=5400 => format!("{} мин назад", прошло / 60),
        5401..=172_800 => format!("{} ч назад", прошло / 3600),
        _ => format!("{} дн назад", прошло / 86_400),
    }
}

fn vpn_bank_list() -> Result<(), String> {
    let bank = sub::load_bank();
    if bank.is_empty() {
        println!("{DIM}Запас пуст — он наполняется при net vpn update{RESET}");
        return Ok(());
    }
    let живые = sub::load_nodes().unwrap_or_default();
    let ширина = bank
        .iter()
        .map(|k| k.node.name.chars().count())
        .max()
        .unwrap_or(0)
        .clamp(8, 32);
    println!("{BOLD}ЗАПАС НОД{RESET}  {DIM}всего {}{RESET}\n", bank.len());
    for kept in &bank {
        let в_работе = живые.iter().any(|n| n.name == kept.node.name);
        let метка = if в_работе {
            format!("{GREEN}●{RESET}")
        } else {
            format!("{DIM}○{RESET}")
        };
        println!(
            "  {метка} {}  {DIM}{}{RESET}  {DIM}отвечала: {}{RESET}",
            picker::fit(&kept.node.name, ширина),
            picker::fit(&sub::place(&kept.node), 24),
            когда(kept.last_ok)
        );
    }
    println!("\n{DIM}● в работе · ○ лежит в запасе{RESET}");
    println!("{DIM}Убрать: net vpn bank rm <имя|адрес:порт>{RESET}");
    Ok(())
}

fn vpn_bank_rm(what: &str) -> Result<(), String> {
    let mut bank = sub::load_bank();
    let gone = sub::drop_from_bank(&mut bank, what);
    if gone.is_empty() {
        return Err(format!("в запасе нет «{what}» — смотри net vpn bank"));
    }
    sub::save_bank(&bank)?;
    println!("{GREEN}Убрано из запаса: {}{RESET}", gone.join(", "));
    println!("{DIM}Из работы уйдёт при следующем net vpn update{RESET}");
    Ok(())
}

/// `net vpn sub <url>` — завести ссылку и сразу обновиться, не дожидаясь крона.
fn vpn_subscribe(cfg: &Config, url: &str) -> Result<(), String> {
    let mut store = subs::Store::load();
    let свежая = store.add(url);
    store.save()?;
    println!(
        "{}",
        if свежая {
            format!("{GREEN}Ссылка добавлена{RESET}")
        } else {
            format!("{DIM}Ссылка уже в списке{RESET}")
        }
    );
    vpn_refresh(cfg)
}

/// Перечитать все активные подписки и пересобрать конфиг движка.
fn vpn_refresh(cfg: &Config) -> Result<(), String> {
    println!("Забираю подписки...");
    let r = subs::refresh(Duration::from_secs(3))?;
    let rec = &r.rec;

    for f in &r.fetched {
        match &f.result {
            Ok(n) => println!("  {GREEN}✓{RESET} {}  {DIM}{n} нод{RESET}", subs::short(&f.url)),
            Err(e) => println!("  {YELLOW}✗{RESET} {}  {DIM}{e}{RESET}", subs::short(&f.url)),
        }
        if f.retired {
            println!(
                "    {YELLOW}→ в отставку: {} провалов подряд{RESET}",
                subs::RETIRE_AFTER
            );
        }
    }

    println!(
        "{GREEN}Актив: {}{RESET}  {DIM}+{} новых · ~{} перенесено · ↺{} из запаса · ⚰{} в запас · ✂{} вычищено{RESET}",
        rec.active.len(),
        rec.added.len(),
        rec.carried.len(),
        rec.revived.len(),
        rec.parked.len(),
        rec.pruned.len(),
    );
    if !rec.revived.is_empty() {
        println!("{DIM}вернулись из запаса: {}{RESET}", rec.revived.join(", "));
    }
    if !rec.parked.is_empty() {
        println!("{DIM}ушли в запас: {}{RESET}", rec.parked.join(", "));
    }
    println!(
        "{DIM}Конфиг: {}  ·  журнал: net vpn log sub{RESET}",
        r.config.display()
    );

    // Ядро держит конфиг в памяти с момента запуска. Без перезапуска новые
    // ноды лежат на диске, а туннель продолжает ходить через старые — и
    // команда выглядит выполненной, хотя ничего не изменилось.
    подхватить_ноды(cfg);
    Ok(())
}

/// `net vpn subs …` — список ссылок и работа с ним.
fn vpn_subs(cfg: &Config, args: &[&str]) -> Result<(), String> {
    match args.first().copied() {
        None | Some("list") => vpn_subs_list(),
        Some("add") => {
            let url = args
                .get(1)
                .copied()
                .ok_or("нужна ссылка: net vpn subs add <url>")?;
            vpn_subscribe(cfg, url)
        }
        Some("rm") | Some("del") | Some("forget") => {
            let url = args
                .get(1)
                .copied()
                .ok_or("нужна ссылка: net vpn subs rm <url>")?;
            let mut store = subs::Store::load();
            if store.forget(url) {
                store.save()?;
                println!("{GREEN}Ссылка убрана{RESET}");
                Ok(())
            } else {
                Err("нет такой ссылки — смотри net vpn subs list".into())
            }
        }
        Some("revive") => {
            let url = args
                .get(1)
                .copied()
                .ok_or("нужна ссылка: net vpn subs revive <url>")?;
            let mut store = subs::Store::load();
            if store.revive(url) {
                store.save()?;
                println!("{GREEN}Ссылка поднята из отставки{RESET}");
                vpn_refresh(cfg)
            } else {
                Err("нет такой отставленной ссылки — смотри net vpn subs list".into())
            }
        }
        Some(other) => Err(format!(
            "net vpn subs [list|add|rm|revive], а не «{other}»"
        )),
    }
}

fn vpn_subs_list() -> Result<(), String> {
    let store = subs::Store::load();
    if store.subs.is_empty() {
        println!("{DIM}Подписок нет — net vpn subs add <ссылка>{RESET}");
        return Ok(());
    }
    println!("{BOLD}ПОДПИСКИ{RESET}\n");
    for s in &store.subs {
        let (метка, состояние) = match s.state {
            subs::State::Active => (format!("{GREEN}●{RESET}"), String::new()),
            subs::State::Retired => (
                format!("{DIM}○{RESET}"),
                format!("  {YELLOW}в отставке{RESET}"),
            ),
        };
        let провалы = if s.fail_streak > 0 {
            format!("  {DIM}провалов подряд: {}{RESET}", s.fail_streak)
        } else {
            String::new()
        };
        println!(
            "  {метка} {}  {DIM}нод в прошлый раз: {} · отдавала: {}{RESET}{провалы}{состояние}",
            subs::short(&s.url),
            s.last_count,
            когда(s.last_live),
        );
    }
    println!("\n{DIM}● активна · ○ в отставке (не опрашивается){RESET}");
    println!("{DIM}Вернуть: net vpn subs revive <url> · забыть: net vpn subs rm <url>{RESET}");
    Ok(())
}

/// Перезапустить туннель, если он поднят, чтобы обновлённые ноды заработали.
/// Молча этого не делаем: перезапуск роняет связь на пару секунд, и человек
/// должен понимать, почему у него моргнул интернет.
fn подхватить_ноды(cfg: &Config) {
    let core = singbox::Core::new(cfg);
    if core.state() != singbox::State::Up {
        return;
    }
    // Ядро на том же API может быть чужим. На роутере оно именно чужое:
    // sing-box там поднят мимо пульта, и его конфиг обновляется отдельной
    // командой `vpn sync` — с проверкой и откатом. Тронуть его отсюда значит
    // уронить интернет всей квартире, причём в момент, когда хозяин далеко.
    if !core.наш() {
        println!("\n{DIM}Рядом работает чужое ядро — не трогаю его.{RESET}");
        println!("{DIM}Применить новые ноды к нему: net vpn sync{RESET}");
        return;
    }
    println!("\n{DIM}Туннель поднят на прежнем конфиге — перезапускаю, чтобы новые ноды{RESET}");
    println!("{DIM}заработали. Связь моргнёт на пару секунд.{RESET}");
    if let Err(e) = core.stop() {
        println!("{YELLOW}Не вышло снять туннель: {e}{RESET}");
        println!("{DIM}Новые ноды уже на диске — примени вручную: net vpn off && net vpn on{RESET}");
        return;
    }
    match core.start() {
        Ok(()) => println!("{GREEN}Туннель поднят на новых нодах{RESET}"),
        Err(e) => {
            println!("{RED}Туннель не поднялся обратно: {e}{RESET}");
            println!("{DIM}Конфиг сохранён, подними вручную: net vpn on{RESET}");
        }
    }
}

/// Общая обвязка для «включи/выключи/перезапусти»: сказать, что делаем, до
/// того как делать, и показать итог. Молчание в этом месте выглядит зависанием
/// даже когда всё занимает полсекунды.
fn zapret_action(
    cfg: &Config,
    what: &str,
    action: impl Fn(&Zapret) -> Result<(), String>,
) -> Result<(), String> {
    ensure_dep(cfg, deps::Kind::Zapret)?;
    println!("{what}...");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    action(&Zapret::new(cfg))?;
    print_status_lines(cfg);
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
            ensure_dep(cfg, deps::Kind::Tglock)?;
            tg.start()?;
            println!("{GREEN}Прокси Telegram включён{RESET}");
            show_qr(cfg)
        }
        Some("off") | Some("stop") => {
            tg.stop()?;
            println!("{RED}Прокси Telegram выключен{RESET}");
            Ok(())
        }
        Some("calls") | Some("звонки") => calls_command(cfg, extra),
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
        Some(other) => Err(format!(
            "net tg on|off|qr|link|calls|newsecret, а не «{other}»"
        )),
    }
}

fn tune_command(cfg: &Config, rest: &[&str]) -> Result<(), String> {
    ensure_dep(cfg, deps::Kind::Zapret)?;
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

/// Шифрованный DNS на всю систему. Отдельно от туннеля: туннель поднят не
/// всегда, а DNS утекает всегда.
fn dns_command(cfg: &Config, rest: &[&str]) -> Result<(), String> {
    match rest.first().copied() {
        None | Some("status") => {
            dns_status();
            Ok(())
        }
        Some("on") => {
            let за_роутером = dns::шлюз_кита();
            // За роутером кита свой резолвер не нужен: DNS отдаётся роутеру,
            // и ядро для этого не требуется.
            if за_роутером.is_none() {
                ensure_dep(cfg, deps::Kind::Core)?;
            }
            if за_роутером.is_some() {
                println!("Отдаю DNS роутеру...");
            } else {
                println!("Поднимаю свой резолвер...");
            }
            for шаг in dns::on(cfg)? {
                println!("  {GREEN}✓{RESET} {шаг}");
            }
            if let Some(gw) = за_роутером {
                println!("{GREEN}Шифрованный DNS работает через роутер {gw}{RESET}");
                println!("{DIM}Свой резолвер тут только мешал бы: роутер решает, какой сайт{RESET}");
                println!("{DIM}пустить через ноду, по тем самым запросам, которые мы бы у него{RESET}");
                println!("{DIM}забрали — и такие сайты уходили бы напрямую.{RESET}");
                return Ok(());
            }
            println!(
                "{GREEN}Шифрованный DNS включён{RESET} — теперь его получают все программы, 
а не только браузер со своей галочкой."
            );
            println!("{DIM}Российские зоны идут российским резолвером напрямую: иначе банки,{RESET}");
            println!("{DIM}прячущие записи от иностранных, перестают открываться.{RESET}");
            println!("{DIM}Выключить: net dns off{RESET}");
            Ok(())
        }
        Some("off") => {
            if !dns::поддержано() {
                return Err(format!(
                    "на {} свой резолвер не подводился — и снимать нечего",
                    std::env::consts::OS
                ));
            }
            for шаг in dns::off()? {
                println!("  {шаг}");
            }
            println!("{GREEN}Система вернулась к DNS своей сети{RESET}");
            Ok(())
        }
        Some("test") => {
            dns_test();
            Ok(())
        }
        Some(other) => Err(format!("net dns [on|off|status|test], а не «{other}»")),
    }
}

fn dns_status() {
    if !dns::поддержано() {
        println!(
            "{BOLD}ШИФРОВАННЫЙ DNS{RESET}  {DIM}на {} ещё не подведён{RESET}",
            std::env::consts::OS
        );
        println!("{DIM}Сам резолвер пошёл бы и тут, не хватает способа сказать системе{RESET}");
        println!("{DIM}«спрашивай его»: на Linux это systemd-resolved, тут нужен свой путь.{RESET}");
        println!("{DIM}Пока DNS шифруется под поднятым туннелем: net vpn on{RESET}");
        return;
    }
    // Роутер кита сам шифрует DNS и по этим же запросам решает, какой сайт
    // пустить через ноду. Свой резолвер поверх него не добавляет ничего, зато
    // ломает раскладку: роутер не видит адресов, которые получила машина, и
    // сайт уходит напрямую мимо ноды.
    if let Some(gw) = dns::шлюз_кита() {
        if dns::state() == dns::State::Off {
            println!("{BOLD}ШИФРОВАННЫЙ DNS{RESET}  {GREEN}его шифрует роутер {gw}{RESET}");
            println!("{DIM}свой резолвер тут не нужен: роутер и шифрует, и раскладывает домены{RESET}");
        } else {
            println!("{BOLD}ШИФРОВАННЫЙ DNS{RESET}  {YELLOW}свой резолвер поверх роутера кита{RESET}");
            println!("{DIM}Шифруется, но роутер {gw} перестаёт видеть, какие адреса{RESET}");
            println!("{DIM}запрашивает машина, и сайты из его списка уходят мимо ноды.{RESET}");
            println!("{DIM}Отдать DNS роутеру: net dns on{RESET}");
        }
        return;
    }
    let state = dns::state();
    let hooked = dns::подключён();
    let (color, text) = match (&state, hooked) {
        (dns::State::Up, true) => (GREEN, "включён — весь DNS машины шифруется"),
        (dns::State::Up, false) => (YELLOW, "резолвер работает, но система его не спрашивает"),
        (dns::State::Broken, _) => (RED, "служба поднята, а резолвер молчит"),
        (dns::State::Off, true) => (RED, "система направлена на резолвер, а его нет"),
        (dns::State::Off, false) => (DIM, "выключен"),
    };
    println!("{BOLD}ШИФРОВАННЫЙ DNS{RESET}  {color}{text}{RESET}");
    println!("{DIM}резолвер 127.0.0.1:{} · наружу DoH к 1.1.1.1 · российские зоны — DoH к 77.88.8.8{RESET}",
        dns::port());
    if state == dns::State::Off && !hooked {
        println!("{DIM}включить: net dns on{RESET}");
    }
}

/// Проверка вживую: спрашивает ли система нас, отвечаем ли мы и куда после
/// этого ушёл запрос.
///
/// Меряться временем тут бесполезно — первая же попытка это показала: кэш
/// отвечает за ноль миллисекунд, а несуществующее имя в российской зоне
/// отвечает дольше заграничного. Зато видно соединение на 443 к DoH-серверу
/// и запрос к российскому резолверу — вот это и есть развилка.
fn dns_test() {
    if !dns::поддержано() {
        dns_status();
        return;
    }
    println!("{BOLD}ШИФРОВАННЫЙ DNS — ПРОВЕРКА{RESET}\n");

    let подключена = dns::подключён();
    отметить(подключена, &format!(
        "система спрашивает   {}",
        if подключена {
            format!("127.0.0.1:{} — это мы", dns::port())
        } else {
            "DNS своей сети — резолвер не подключён".to_string()
        }
    ));

    // Имена со случайной меткой: старое ушло бы в кэш, и запрос наружу не
    // случился бы вовсе — а нам нужно посмотреть именно на него.
    //
    // Оба канала теперь на 443: российский резолвер спрашивается по DoH с тех
    // пор, как открытый 53 стал перехватываться. Если вернуть его на 53,
    // сюда же надо вернуть и проверку в dns::каналы — иначе она будет искать
    // соединение, которого нет, и рапортовать о поломке на ровном месте.
    let метка = format!("np{}", sub::now_secs() % 100_000);
    let заграничное = format!("{метка}.example.com");
    let российское = format!("{метка}.vtb.ru");
    let живой = dns::ask("127.0.0.1", dns::port(), "example.com", Duration::from_secs(6));
    отметить(живой.is_some(), &match &живой {
        Some(ответ) if !ответ.адреса.is_empty() => format!(
            "резолвер отвечает    example.com → {} за {} мс",
            ответ.адреса[0],
            ответ.заняло.as_millis()
        ),
        Some(_) => "резолвер отвечает    но без адресов".to_string(),
        None => format!("резолвер молчит      на 127.0.0.1:{}", dns::port()),
    });

    let _ = dns::ask("127.0.0.1", dns::port(), &заграничное, Duration::from_secs(6));
    let _ = dns::ask("127.0.0.1", dns::port(), &российское, Duration::from_secs(6));
    let (doh, ru) = dns::каналы();
    отметить(doh, "канал наружу         1.1.1.1:443 — шифрованный DoH");
    отметить(ru, "российские зоны      77.88.8.8:443 — тоже DoH, чтоб банки жили");

    if doh && ru && подключена {
        println!("\n{GREEN}Всё на месте: весь DNS машины шифруется, российское ходит своим путём.{RESET}");
    } else if !подключена {
        println!("\n{DIM}Включить: net dns on{RESET}");
    } else {
        println!("\n{YELLOW}Соединение видно не всё — повтори через секунду,{RESET}");
        println!("{DIM}сокеты живут недолго и могли уже закрыться.{RESET}");
    }
}

fn отметить(ok: bool, text: &str) {
    let (color, dot) = if ok { (GREEN, "✓") } else { (RED, "✗") };
    println!("  {color}{dot}{RESET} {text}");
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

/// Строка состояния одной службы, разобранная на колонки.
///
/// Колонки нарочно не склеены пробелами внутри строки: выравнивание — дело
/// того, кто рисует. Экран и вывод в консоль ставят их по-разному, а ширина
/// имени зависит от того, какие службы вообще подняты.
pub struct Status {
    pub ok: bool,
    /// Имя службы: `zapret`, `VPN`, `Telegram`.
    pub name: &'static str,
    /// Короткое положение дел: `ВКЛ`, `ВЫКЛ`, `не установлен`.
    pub state: String,
    /// Подробность, если она есть: стратегия, адрес, число устройств.
    pub detail: String,
}

impl Status {
    fn new(ok: bool, name: &'static str, state: &str, detail: &str) -> Status {
        Status {
            ok,
            name,
            state: state.to_string(),
            detail: detail.to_string(),
        }
    }
}

pub fn status_lines(cfg: &Config) -> Vec<Status> {
    let z = Zapret::new(cfg);
    let mut lines = Vec::new();

    lines.push(match z.state() {
        zapret::State::On => Status::new(
            true,
            "zapret",
            "ВКЛ",
            &z.strategy().unwrap_or_default(),
        ),
        zapret::State::Off => Status::new(false, "zapret", "ВЫКЛ", ""),
        // На маке и в Windows свой движок zapret ставится отдельно и пультом
        // пока не управляется — пугать этим красной строкой незачем.
        zapret::State::Missing if !cfg!(target_os = "linux") => {
            Status::new(false, "zapret", "—", "управляется отдельно (не Linux)")
        }
        zapret::State::Missing => Status::new(false, "zapret", "нет", "не установлен"),
    });

    lines.push(match Vpn::new(cfg).state() {
        vpn::State::Tunnel => Status::new(true, "VPN", "ВКЛ", "туннель поднят"),
        vpn::State::AppOnly => Status::new(false, "VPN", "—", "окно открыто, туннеля нет"),
        vpn::State::Off => Status::new(false, "VPN", "ВЫКЛ", ""),
    });

    // Молчащая подписка ничем себя не проявляет: ноды в конфиге работают, пока
    // провайдер не сменит им ключи при очередной ротации, и тогда ложатся все
    // разом. Показываем только когда пора беспокоиться — постоянная строка
    // «последнее обновление такого-то числа» превращается в шум, который
    // перестают читать раньше, чем он станет важным.
    if let Some(days) = sync::days_since_sync()
        && days >= 14
    {
        lines.push(Status::new(
            false,
            "Подписка",
            &format!("{days} сут"),
            "ноды не обновлялись — доживут до ближайшей ротации ключей",
        ));
    }

    if probe::port_open(cfg.split_port, Duration::from_millis(300)) {
        let node = socks::reachable(&cfg.split_upstream, Duration::from_secs(1));
        lines.push(Status::new(
            node,
            "Сплит",
            "ВКЛ",
            if node { "нода отвечает" } else { "нода молчит" },
        ));
    }
    if probe::port_open(cfg.share_port, Duration::from_millis(300)) {
        let ip = probe::lan_ip().map(|i| i.to_string()).unwrap_or_default();
        let clients = probe::connected_peers(cfg.share_port).len();
        let tail = match clients {
            0 => "устройств нет".to_string(),
            n => format!("устройств: {n}"),
        };
        lines.push(Status::new(
            true,
            "Раздача",
            "ВКЛ",
            &format!("{ip}:{}  {tail}", cfg.share_port),
        ));
    }

    let tg = Telegram::new(cfg);
    lines.push(if tg.running() {
        let where_ = probe::lan_ip()
            .map(|ip| format!("{ip}:{}", cfg.tg_port))
            .unwrap_or_else(|| format!("порт {}", cfg.tg_port));
        Status::new(true, "Telegram", "ВКЛ", &where_)
    } else {
        Status::new(false, "Telegram", "ВЫКЛ", "")
    });

    lines
}

/// Ширина колонки имени по самому длинному из показываемых.
pub fn status_name_width(lines: &[Status]) -> usize {
    lines
        .iter()
        .map(|s| s.name.chars().count())
        .max()
        .unwrap_or(0)
}

/// Состояние служб столбиком: имя, положение, подробность.
fn print_status_lines(cfg: &Config) {
    let lines = status_lines(cfg);
    let width = status_name_width(&lines);
    for s in &lines {
        let color = if s.ok { GREEN } else { RED };
        let name = format!("{:<width$}", s.name, width = width);
        let state = format!("{:<4}", s.state);
        if s.detail.is_empty() {
            println!("{color}{name}  {state}{RESET}");
        } else {
            println!("{color}{name}  {state}{RESET}  {DIM}{}{RESET}", s.detail);
        }
    }
}

/// Пульт ещё не настроен: ни одной зависимости и ни одной подписки.
///
/// Пустой пульт выглядит как сломанный — везде нули и «выключено». Вместо
/// этого показываем три шага: что поставить, чем прикрыть, куда идти дальше.
pub fn первый_запуск(cfg: &Config) -> bool {
    deps::Kind::ALL
        .into_iter()
        .all(|kind| deps::find(kind, cfg).is_none())
        && !sub::config_path().exists()
}

pub fn print_first_run() {
    println!("{BOLD}netpult{RESET} — пульт обхода блокировок. Пока пусто, начнём.\n");
    println!("  1. {BOLD}net deps install{RESET}   поставить то, чем обходят:");
    println!("     {DIM}zapret (YouTube, Discord), tglock (Telegram), ядро sing-box (туннель){RESET}");
    println!("  2. {BOLD}net on{RESET}             включить обход DPI");
    println!("     {DIM}не помогло — net tune подберёт стратегию перебором{RESET}");
    println!("  3. {BOLD}net vpn sub <ссылка>{RESET}  подписка, если она есть:");
    println!("     {DIM}с ней работают туннель, звонки в Telegram и сплит{RESET}");
    println!("\n{DIM}Что сломано и чем чинится — net doctor. Все команды — net help.{RESET}");
}

fn print_status(cfg: &Config) {
    if первый_запуск(cfg) {
        print_first_run();
        return;
    }
    // Первым — ответ на вопрос, ради которого команду и набирают.
    let (ok, carrier) = route::carrier(cfg);
    let color = if ok { GREEN } else { YELLOW };
    println!("{BOLD}Трафик{RESET}  {color}{carrier}{RESET}\n");
    print_status_lines(cfg);
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
    // Шесть отрезков: четыре адреса, видео-CDN и скорость. Каждый — до
    // десятка секунд, так что без бегущей строки проверка выглядит зависшей.
    let mut ход = progress::Progress::new("проверяю", 6);
    for (label, url) in [
        ("youtube.com ", "https://www.youtube.com/generate_204"),
        ("ytimg (превью)", "https://i.ytimg.com/generate_204"),
        ("discord.com ", "https://discord.com/api/v9/gateway"),
        ("telegram.org", "https://web.telegram.org/"),
    ] {
        ход.step(label.trim());
        let ok = probe::reachable(url, Duration::from_secs(10));
        let (color, verdict) = if ok {
            (GREEN, "открывается")
        } else {
            (RED, "НЕ открывается")
        };
        ход.line(&format!("{color}  {label} — {verdict}{RESET}"));
        ход.tick();
    }

    // Отдельно и последним — то, ради чего всё затевается. Страница и превью
    // открываются даже со сломанным обходом, а видео при этом не идёт.
    ход.step("видео-CDN");
    let video = probe::video(Duration::from_secs(10));
    ход.tick();
    ход.clear();
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

    ход.step("скорость");
    let скорость = probe::google_speed(Duration::from_secs(20));
    ход.tick();
    ход.finish();
    match скорость {
        Some(kbs) => println!("Скорость с серверов Google: {kbs:.0} КБ/с"),
        None => println!("Скорость с серверов Google: не измерилась"),
    }
    println!(
        "{DIM}Точный вердикт по YouTube — открыть видео в 1080p. Тормозит после первых секунд = стратегия не та.{RESET}"
    );
}

fn print_help() {
    println!("{}", help_text());
}

/// Текст справки отдельно от печати: так его можно проверить тестом на то,
/// что ни одна команда не потерялась.
fn help_text() -> String {
    format!(
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

{BOLD}звонки{RESET} — прокси ведёт переписку, но не голос
  net calls            чем прикрыты звонки сейчас
  net calls on         починить: через ноду идёт только Telegram
  net calls on --dpi   починить дурением DPI, без ноды (помогает не всем)
  net calls on --here  поднять туннель отсюда, даже если стоишь за своим роутером
  net calls off        вернуть как было
  net calls update     обновить адреса Telegram

{BOLD}DNS{RESET} — шифрование запросов имён для всей системы
  net dns on           поднять свой резолвер и перевести систему на него
  net dns off          вернуть DNS своей сети
  net dns status       шифруется ли сейчас
  net dns test         куда уходят запросы имён

{BOLD}хозяйство{RESET}
  net deps             что нужно пульту: что нашлось, чего нет
  net deps install     поставить недостающее (zapret, tglock, ядро)
  net deps use <что> <путь>  запомнить свою установку
  net doctor           осмотр: что сломано и чем чинится
  net doctor --fix     осмотр и починка безопасного

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
    )
}

// ── зависимости ─────────────────────────────────────────────────────────────

/// Спрашивает «да/нет» в терминале. Не терминал — считаем, что ответа нет:
/// в скрипте и в сторожe вопросы задавать некому.
fn ask_yes(question: &str) -> bool {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return false;
    }
    print!("{question} [Y/n] ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    let answer = answer.trim().to_lowercase();
    answer.is_empty() || answer == "y" || answer == "д" || answer == "да" || answer == "yes"
}

/// Проверяет зависимость перед командой, которая без неё не работает.
///
/// Смысл в том, чтобы не отвечать «не найдено» и не бросать человека: если
/// можно поставить — предлагаем прямо здесь, если нельзя — говорим, какой
/// командой это чинится.
fn ensure_dep(cfg: &Config, kind: deps::Kind) -> Result<(), String> {
    if deps::find(kind, cfg).is_some() {
        return Ok(());
    }
    println!(
        "{YELLOW}Нет {}{RESET} — {}",
        kind.title(),
        kind.about()
    );
    if !ask_yes("Поставить сейчас?") {
        return Err(format!(
            "без {} эта команда не работает. Поставить позже: net deps install {}",
            kind.title(),
            kind.key()
        ));
    }
    let path = deps::install(kind, None)?;
    deps::remember(kind, &path)?;
    println!("{GREEN}Готово:{RESET} {}", path.display());
    println!("{DIM}Пульт запомнил путь. Повтори команду.{RESET}");
    Err(format!("{} поставлен, повтори команду", kind.title()))
}

fn deps_command(cfg: &Config, rest: &[&str]) -> Result<(), String> {
    match rest.first().copied() {
        None | Some("status") | Some("list") => {
            print_deps(cfg);
            Ok(())
        }
        Some("install") | Some("add") => {
            let what = rest.get(1).copied();
            let file = rest.get(2).map(std::path::PathBuf::from);
            let kinds: Vec<deps::Kind> = match what {
                None | Some("all") | Some("всё") => deps::Kind::ALL
                    .into_iter()
                    .filter(|k| deps::find(*k, cfg).is_none())
                    .collect(),
                Some(word) => vec![deps::Kind::parse(word)
                    .ok_or_else(|| format!("не знаю такой зависимости: {word}. Есть zapret, tglock, core"))?],
            };
            if kinds.is_empty() {
                println!("{GREEN}Всё на месте.{RESET} Что где лежит: net deps");
                return Ok(());
            }
            let mut trouble = Vec::new();
            for kind in kinds {
                println!("Ставлю {}...", kind.title());
                match deps::install(kind, file.as_deref()) {
                    Ok(path) => {
                        deps::remember(kind, &path)?;
                        println!("{GREEN}  готово:{RESET} {}", path.display());
                    }
                    Err(message) => {
                        println!("{RED}  не вышло:{RESET} {message}");
                        trouble.push(kind.title());
                    }
                }
            }
            if trouble.is_empty() {
                Ok(())
            } else {
                Err(format!("не поставилось: {}", trouble.join(", ")))
            }
        }
        Some("use") | Some("path") => {
            let word = rest.get(1).copied().ok_or("net deps use <zapret|tglock|core> <путь>")?;
            let kind = deps::Kind::parse(word)
                .ok_or_else(|| format!("не знаю такой зависимости: {word}"))?;
            let path = rest.get(2).ok_or("не сказано, какой путь запомнить")?;
            let path = std::path::PathBuf::from(path);
            if !path.exists() {
                return Err(format!("нет такого пути: {}", path.display()));
            }
            deps::remember(kind, &path)?;
            println!("{GREEN}Запомнил:{RESET} {} → {}", kind.title(), path.display());
            Ok(())
        }
        Some(other) => Err(unknown_sub("deps", other)),
    }
}

fn print_deps(cfg: &Config) {
    println!("{BOLD}ЗАВИСИМОСТИ{RESET}");
    let mut missing = Vec::new();
    for kind in deps::Kind::ALL {
        match deps::find(kind, cfg) {
            Some(found) => {
                let version = deps::version_of(kind, &found.path)
                    .map(|v| format!(" · {v}"))
                    .unwrap_or_default();
                println!(
                    "  {GREEN}✓{RESET} {:<14} {}{}",
                    kind.title(),
                    short_path(&found.path),
                    version
                );
                println!("     {DIM}{}{RESET}", found.source);
            }
            None => {
                missing.push(kind);
                println!("  {RED}✗{RESET} {:<14} {DIM}нет — {}{RESET}", kind.title(), kind.about());
                println!("     {DIM}без него не работает: {}{RESET}", kind.needed_for());
            }
        }
    }
    if missing.is_empty() {
        println!("\n{GREEN}Всё на месте.{RESET}");
    } else {
        println!(
            "\nПоставить: {}",
            missing
                .iter()
                .map(|k| format!("net deps install {}", k.key()))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("{DIM}Уже стоит своё? Скажи путь: net deps use <что> <путь>{RESET}");
    }
}

/// Домашняя папка в пути — это шум: сокращаем до `~`.
pub fn short_path(path: &std::path::Path) -> String {
    let home = config::home();
    match path.strip_prefix(&home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

fn calls_command(cfg: &Config, rest: &[&str]) -> Result<(), String> {
    match rest.first().copied() {
        None | Some("status") => {
            match calls::состояние(cfg) {
                calls::Способ::Нода => {
                    println!("{GREEN}Звонки идут через ноду{RESET}");
                    println!("{DIM}Остальной интернет — напрямую. Снять: net calls off{RESET}");
                }
                calls::Способ::ПолныйТуннель => {
                    println!("{GREEN}Звонки внутри полного туннеля{RESET}");
                    println!("{DIM}Через ноду идёт весь интернет. Только Telegram: net calls on{RESET}");
                }
                calls::Способ::Dpi => {
                    println!("{YELLOW}Звонки прикрыты дурением DPI{RESET}");
                    println!("{DIM}Помогает не у всех провайдеров. Надёжнее: net calls on{RESET}");
                }
                calls::Способ::Роутер(gw) => {
                    println!("{YELLOW}Эта машина за своим роутером {gw}{RESET}");
                    println!("Голос всех домашних устройств решается на нём, а не здесь.");
                    println!("{DIM}Туннель именно отсюда, поверх роутера: net calls on --here{RESET}");
                }
                calls::Способ::Никак => {
                    println!("{RED}Звонки ничем не прикрыты{RESET}");
                    println!("Прокси Telegram ведёт переписку, но не голос — это разные потоки.");
                    println!("{DIM}Включить: net calls on{RESET}");
                }
            }
            Ok(())
        }
        Some("on") => {
            let dpi = rest.contains(&"--dpi");
            let here = rest.contains(&"--here");
            for шаг in calls::on(cfg, dpi, here)? {
                println!("  {GREEN}✓{RESET} {шаг}");
            }
            Ok(())
        }
        Some("off") => {
            for шаг in calls::off(cfg)? {
                println!("  {шаг}");
            }
            Ok(())
        }
        Some("update") => {
            let сколько = singbox::update_telegram_cidr()?;
            println!("{GREEN}Адреса Telegram обновлены: {сколько} сетей{RESET}");
            if calls::состояние(cfg) == calls::Способ::Нода {
                singbox::rewrite_scope(singbox::Scope::TelegramOnly)?;
                singbox::Core::new(cfg).stop().ok();
                singbox::Core::new(cfg).start()?;
                println!("{DIM}Туннель перезапущен с новым списком{RESET}");
            }
            Ok(())
        }
        Some(other) => Err(unknown_sub("calls", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Команда, которой нет в справке, для человека не существует: `net dns`
    /// однажды уже так и потерялся — жил в подсказках строки, а в справке нет.
    #[test]
    fn каждая_команда_есть_в_справке() {
        let help = help_text();
        let потеряны: Vec<&str> = commands()
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| {
                let первое_слово = name.split_whitespace().next().unwrap_or(name);
                !help.contains(&format!("net {name}")) && !help.contains(&format!("net {первое_слово} "))
            })
            .collect();
        assert!(потеряны.is_empty(), "нет в справке: {потеряны:?}");
    }

    /// Обратная сторона: справка не должна звать в команду, которой нет.
    #[test]
    fn справка_не_врёт_про_команды() {
        let known: Vec<&str> = commands()
            .iter()
            .map(|(name, _)| name.split_whitespace().next().unwrap_or(name))
            .collect();
        let mut чужие = Vec::new();
        for line in help_text().lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("net ") else { continue };
            let слово = rest.split_whitespace().next().unwrap_or("");
            // Пояснения к строке «net» без команды написаны по-русски; сами
            // команды — латиницей, по ним и судим.
            if слово.is_empty() || !слово.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                continue;
            }
            if !known.contains(&слово) {
                чужие.push(слово.to_string());
            }
        }
        чужие.sort();
        чужие.dedup();
        assert!(чужие.is_empty(), "справка зовёт в несуществующее: {чужие:?}");
    }
}
