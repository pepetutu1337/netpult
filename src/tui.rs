//! Интерактивный экран: состояние сверху, строка ввода снизу.
//!
//! Строка ввода есть всегда: набираешь часть команды — под ней появляются
//! похожие, стрелки выбирают, Enter выполняет. Пока строка пустая, цифры
//! работают как быстрые клавиши, чтобы привычные действия остались в одно
//! нажатие.

use crate::config::Config;
use crate::probe;
use crate::profile;
use crate::telegram::Telegram;
use crate::tune;
use crate::vpn::Vpn;
use crate::zapret::{self, Zapret};
use crate::{qr, status_lines, BOLD, DIM, GREEN, RED, RESET, YELLOW};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal;
use std::io::Write;
use std::time::Duration;

pub fn run(cfg: &Config) -> Result<(), String> {
    let mut message: Option<(bool, String)> = None;
    let mut input = String::new();
    let mut cursor = 0usize;
    // Состояние опрашивает систему (службы, процессы, интерфейсы) — делать это
    // на каждую нажатую букву значит превратить набор в рывки. Держим снимок и
    // обновляем его по времени и после действий.
    let mut status = status_lines(cfg);
    let mut status_taken = std::time::Instant::now();

    let all = crate::commands();
    let items: Vec<crate::picker::Item> = all
        .iter()
        .map(|(name, about)| crate::picker::Item::new(*name).hint(*about))
        .collect();

    terminal::enable_raw_mode().map_err(|e| e.to_string())?;
    let _ = crossterm::execute!(std::io::stdout(), event::EnableBracketedPaste);
    print!("\x1b[2J");

    let result = loop {
        if status_taken.elapsed() > Duration::from_secs(5) {
            status = status_lines(cfg);
            status_taken = std::time::Instant::now();
        }

        let matches = suggest(&items, &input);
        if cursor >= matches.len() {
            cursor = 0;
        }
        draw(&status, message.as_ref(), &input, &matches, cursor);

        let event = match event::read() {
            Ok(e) => e,
            Err(e) => break Err(e.to_string()),
        };
        // Вставка ссылки приходит одним событием, а не потоком клавиш: без
        // этой ветки вставленное просто пропадало.
        if let Event::Paste(text) = &event {
            input.push_str(text.trim());
            cursor = 0;
            continue;
        }
        let Event::Key(key) = event else { continue };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        if input.is_empty() {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    let outcome = paused(|| hotkey(cfg, c));
                    match outcome {
                        Ok(value) => message = value,
                        Err(e) => message = Some((false, e)),
                    }
                    status = status_lines(cfg);
                    status_taken = std::time::Instant::now();
                    continue;
                }
                KeyCode::Char('/') => continue,
                _ => {}
            }
        }

        match key.code {
            KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => break Ok(()),
            KeyCode::Esc => {
                input.clear();
                cursor = 0;
            }
            KeyCode::Backspace => {
                input.pop();
                cursor = 0;
            }
            KeyCode::Down | KeyCode::Tab => {
                if !matches.is_empty() {
                    cursor = (cursor + 1) % matches.len();
                }
            }
            KeyCode::Up | KeyCode::BackTab => {
                if !matches.is_empty() {
                    cursor = (cursor + matches.len() - 1) % matches.len();
                }
            }
            KeyCode::Enter => {
                let line = match matches.get(cursor) {
                    Some(suggestion) => suggestion.line.clone(),
                    None => input.trim().to_string(),
                };
                input.clear();
                cursor = 0;
                if line.is_empty() {
                    continue;
                }
                message = Some(paused(|| Ok(run_line(cfg, &line)))?);
                status = status_lines(cfg);
                status_taken = std::time::Instant::now();
            }
            KeyCode::Char(c) => {
                input.push(c);
                cursor = 0;
            }
            _ => {}
        }
    };

    let _ = crossterm::execute!(std::io::stdout(), event::DisableBracketedPaste);
    terminal::disable_raw_mode().map_err(|e| e.to_string())?;
    println!();
    result
}

/// Подсказка: что показать и что выполнить.
pub struct Suggestion {
    /// Команда целиком, как её выполнять.
    pub line: String,
    /// Что показать слева.
    pub label: String,
    /// Пояснение справа.
    pub about: String,
}

/// Похожие команды под набранным.
///
/// Две особые ситуации, без которых экран врал «похожих команд нет» на вполне
/// осмысленный ввод: вставленная ссылка (человек вставляет подписку и ждёт
/// действия, а не поиска команды с такими буквами) и команда с аргументами —
/// «vpn use Турция» ни на что не похоже по буквам, но выполнить его надо.
fn suggest(items: &[crate::picker::Item], input: &str) -> Vec<Suggestion> {
    let typed = input.trim();
    if typed.is_empty() {
        return Vec::new();
    }
    if let Some(url) = find_url(typed) {
        return vec![Suggestion {
            line: format!("vpn sub {url}"),
            label: "vpn sub <ссылка>".to_string(),
            about: "загрузить подписку по вставленной ссылке".to_string(),
        }];
    }

    let mut found: Vec<Suggestion> = crate::picker::filter(items, typed)
        .into_iter()
        .map(|index| Suggestion {
            line: items[index].label.clone(),
            label: items[index].label.clone(),
            about: items[index].hint.clone().unwrap_or_default(),
        })
        .collect();

    // Набранное с аргументами ставим первым: раз человек дописал аргумент,
    // именно это он и хочет запустить, а не голую команду из списка.
    if with_arguments(typed) {
        found.insert(
            0,
            Suggestion {
                line: typed.to_string(),
                label: typed.to_string(),
                about: "выполнить как набрано".to_string(),
            },
        );
    }
    found
}

/// Ссылка в набранном — где бы она ни стояла.
fn find_url(text: &str) -> Option<String> {
    let at = text.find("https://").or_else(|| text.find("http://"))?;
    Some(text[at..].split_whitespace().next()?.to_string())
}

/// Первое слово — известная команда, а дальше что-то ещё.
fn with_arguments(typed: &str) -> bool {
    let mut words = typed.split_whitespace();
    let Some(first) = words.next() else {
        return false;
    };
    if words.next().is_none() {
        return false;
    }
    crate::commands()
        .iter()
        .any(|(name, _)| name.split_whitespace().next() == Some(first))
}

/// Выйти из сырого режима на время действия: команды печатают обычным
/// образом, а в сыром режиме перевод строки не возвращает каретку.
fn paused<T>(action: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    terminal::disable_raw_mode().ok();
    let result = action();
    terminal::enable_raw_mode().ok();
    print!("\x1b[2J");
    result
}

/// Выполнить набранную строку так же, как если бы её набрали в терминале.
fn run_line(cfg: &Config, line: &str) -> (bool, String) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    clear();
    println!("{DIM}  net {line}{RESET}\n");
    let outcome = match crate::dispatch_with(cfg, parts[0], &parts[1..], false) {
        Ok(()) => (true, format!("выполнено: {line}")),
        Err(e) => (false, e),
    };
    pause();
    outcome
}

/// Быстрые клавиши старого меню.
fn hotkey(cfg: &Config, key: char) -> Result<Option<(bool, String)>, String> {
    Ok(match key {
        '1' => Some(toggle_zapret(cfg)),
        '2' => {
            pick_strategy(cfg)?;
            None
        }
        '3' => {
            println!();
            crate::run_test_public(cfg);
            pause();
            None
        }
        '4' => Some(match Vpn::new(cfg).state() {
            crate::vpn::State::Off => act(Vpn::new(cfg).open(), "Окно Happ открыто"),
            _ => act(Vpn::new(cfg).close(), "Happ закрыт"),
        }),
        '5' => Some(toggle_telegram(cfg)),
        '6' => {
            show_qr(cfg);
            None
        }
        '7' => {
            clear();
            println!("  Подбираю стратегию. Интернет будет прыгать.\n");
            let outcome = match tune::run(cfg, &tune::Options { full: false, verbose: true }) {
                Ok(best) => (true, format!("выбрана {}", best.strategy)),
                Err(e) => (false, e),
            };
            pause();
            Some(outcome)
        }
        '8' => Some(toggle_share(cfg)),
        '9' => {
            clear();
            let network = profile::current_network().unwrap_or_else(|| "не видно".into());
            println!("  Сеть: {BOLD}{network}{RESET}\n");
            println!("  {DIM}[s]{RESET} запомнить состояние для этой сети");
            println!("  {DIM}[a]{RESET} привести всё к профилю сети");
            println!("  {DIM}[любая другая]{RESET} назад");
            match read_key()? {
                Some(KeyCode::Char('s')) => Some(match profile::save_current(cfg) {
                    Ok((net, _)) => (true, format!("профиль сети «{net}» сохранён")),
                    Err(e) => (false, e),
                }),
                Some(KeyCode::Char('a')) => Some(match profile::apply(cfg) {
                    Ok(done) if done.is_empty() => (true, "всё уже как в профиле".to_string()),
                    Ok(done) => (true, done.join(", ")),
                    Err(e) => (false, e),
                }),
                _ => None,
            }
        }
        _ => None,
    })
}

fn read_key() -> Result<Option<KeyCode>, String> {
    terminal::enable_raw_mode().map_err(|e| e.to_string())?;
    let key = loop {
        match event::read() {
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => break Some(k.code),
            Ok(Event::Resize(_, _)) => break None,
            Ok(_) => continue,
            Err(e) => {
                terminal::disable_raw_mode().ok();
                return Err(e.to_string());
            }
        }
    };
    terminal::disable_raw_mode().map_err(|e| e.to_string())?;
    Ok(key)
}

fn clear() {
    print!("\x1b[2J\x1b[H");
    std::io::stdout().flush().ok();
}

fn draw(
    status: &[(bool, String)],
    message: Option<&(bool, String)>,
    input: &str,
    matches: &[Suggestion],
    cursor: usize,
) {
    // Кадр собирается целиком и печатается одним куском поверх старого: экран
    // не чистится, поэтому не мигает. Каждая строка затирает хвост прежней.
    let mut rows: Vec<String> = Vec::new();
    rows.push(format!("{BOLD}  ОБХОД БЛОКИРОВОК{RESET}"));
    rows.push(String::new());
    for (ok, text) in status {
        let (color, dot) = if *ok { (GREEN, "●") } else { (RED, "○") };
        rows.push(format!("  {color}{dot} {text}{RESET}"));
    }
    rows.push(String::new());

    // Быстрые клавиши видны всегда — иначе они «пропадают» при наборе.
    rows.push(format!(
        "  {DIM}[1]{RESET} zapret вкл/выкл   {DIM}[2]{RESET} стратегия   {DIM}[3]{RESET} проверить"
    ));
    rows.push(format!(
        "  {DIM}[4]{RESET} VPN               {DIM}[5]{RESET} Telegram    {DIM}[6]{RESET} QR на телефон"
    ));
    rows.push(format!(
        "  {DIM}[7]{RESET} автоподбор        {DIM}[8]{RESET} раздача     {DIM}[9]{RESET} профиль сети"
    ));
    rows.push(format!("  {DIM}[q]{RESET} выход"));
    rows.push(String::new());

    // Место под подсказки — всегда одной высоты, иначе строка ввода прыгает.
    const ROWS: usize = 6;
    let mut hints: Vec<String> = Vec::new();
    if matches.is_empty() && !input.trim().is_empty() {
        hints.push(format!("  {YELLOW}похожих команд нет{RESET}"));
    } else {
        let shown = matches.len().min(ROWS);
        let first = cursor
            .saturating_sub(ROWS - 1)
            .min(matches.len().saturating_sub(shown));
        for item in matches.iter().skip(first).take(ROWS) {
            let selected = matches
                .get(cursor)
                .map(|c| std::ptr::eq(c, item))
                .unwrap_or(false);
            if selected {
                hints.push(format!(
                    "  {GREEN}▸ {}{RESET}  {DIM}{}{RESET}",
                    item.label, item.about
                ));
            } else {
                hints.push(format!("    {}  {DIM}{}{RESET}", item.label, item.about));
            }
        }
    }
    while hints.len() < ROWS {
        hints.push(String::new());
    }
    rows.extend(hints);

    rows.push(match message {
        Some((ok, text)) => {
            let color = if *ok { GREEN } else { YELLOW };
            format!("  {color}{text}{RESET}")
        }
        None => String::new(),
    });
    rows.push(String::new());

    let mut frame = String::from("\x1b[H");
    for row in rows {
        frame.push_str(&row);
        frame.push_str("\x1b[K\r\n");
    }
    frame.push_str(&format!("  {BOLD}›{RESET} {input}▏\x1b[K\x1b[J"));

    print!("{frame}");
    std::io::stdout().flush().ok();
}

fn act(result: Result<(), String>, done: &str) -> (bool, String) {
    match result {
        Ok(()) => (true, done.to_string()),
        Err(e) => (false, e),
    }
}

fn toggle_zapret(cfg: &Config) -> (bool, String) {
    let z = Zapret::new(cfg);
    if z.state() == zapret::State::On {
        act(z.stop(), "zapret выключен")
    } else {
        act(z.start(), "zapret включён")
    }
}

fn toggle_telegram(cfg: &Config) -> (bool, String) {
    let tg = Telegram::new(cfg);
    if tg.running() {
        act(tg.stop(), "прокси Telegram выключен")
    } else {
        act(tg.start(), "прокси Telegram включён")
    }
}

fn toggle_share(cfg: &Config) -> (bool, String) {
    let on = probe::port_open(cfg.share_port, Duration::from_millis(300));
    let action = if on { "off" } else { "on" };
    match crate::share_service_public(action, cfg.share_port) {
        Ok(()) if on => (true, "раздача выключена".into()),
        Ok(()) => (
            true,
            format!(
                "раздача включена: {}:{}",
                probe::lan_ip().map(|i| i.to_string()).unwrap_or_default(),
                cfg.share_port
            ),
        ),
        Err(e) => (false, e),
    }
}

fn pick_strategy(cfg: &Config) -> Result<(), String> {
    let z = Zapret::new(cfg);
    let list = z.strategies();
    if list.is_empty() {
        return Ok(());
    }
    let current = z.strategy().unwrap_or_default();

    clear();
    println!("{BOLD}  СТРАТЕГИИ{RESET}  {DIM}(текущая помечена ●){RESET}\n");
    for (i, name) in list.iter().enumerate() {
        if *name == current {
            println!("  {GREEN}{:>3} ● {name}{RESET}", i + 1);
        } else {
            println!("  {:>3}   {name}", i + 1);
        }
    }
    print!("\n  Номер (пусто — оставить как есть): ");
    std::io::stdout().flush().ok();

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer).map_err(|e| e.to_string())?;
    let answer = answer.trim();
    if answer.is_empty() {
        return Ok(());
    }
    match z.set_strategy(answer) {
        Ok(name) => println!("  {GREEN}Поставлена: {name}{RESET}"),
        Err(e) => println!("  {RED}{e}{RESET}"),
    }
    pause();
    Ok(())
}

fn show_qr(cfg: &Config) {
    clear();
    match Telegram::new(cfg).lan_link() {
        Some(link) => match qr::encode(&link) {
            Ok(grid) => {
                print!("{}", qr::render(&grid, 2));
                println!("  {link}");
                println!("\n  {DIM}Камера телефона на QR — Telegram подхватит прокси.{RESET}");
            }
            Err(e) => println!("  {RED}{e}{RESET}"),
        },
        None => println!("  {YELLOW}Прокси ещё не запускался — включи его клавишей 5.{RESET}"),
    }
    pause();
}

fn pause() {
    println!("\n  {DIM}Любая клавиша — назад{RESET}");
    std::io::stdout().flush().ok();
    if terminal::enable_raw_mode().is_ok() {
        loop {
            match event::read() {
                Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        terminal::disable_raw_mode().ok();
    } else {
        std::thread::sleep(Duration::from_secs(2));
    }
}
