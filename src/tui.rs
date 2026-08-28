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
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal;
use std::io::Write;
use std::time::Duration;

pub fn run(cfg: &Config) -> Result<(), String> {
    let mut message: Option<(bool, String)> = None;
    let mut input = String::new();
    let mut cursor = 0usize;

    loop {
        let all = crate::commands();
        let items: Vec<crate::picker::Item> = all
            .iter()
            .map(|(name, about)| crate::picker::Item::new(*name).hint(*about))
            .collect();
        let matches = if input.trim().is_empty() {
            Vec::new()
        } else {
            crate::picker::filter(&items, input.trim())
        };
        if cursor >= matches.len() {
            cursor = 0;
        }

        draw(cfg, message.as_ref(), &input, &all, &matches, cursor);
        let Some(key) = read_key()? else { continue };

        // Пока строка пуста, клавиши работают по-старому: цифра — действие.
        if input.is_empty() {
            match key {
                KeyCode::Char('q') | KeyCode::Esc => {
                    println!();
                    return Ok(());
                }
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    message = hotkey(cfg, c)?;
                    continue;
                }
                // Косая черта привычна как «открыть команды», но строка тут и
                // так всегда открыта — просто не считаем её вводом.
                KeyCode::Char('/') => continue,
                _ => {}
            }
        }

        match key {
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
                // Выбранная подсказка главнее набранного: обычно набирают
                // половину, а хотят целое.
                let line = match matches.get(cursor) {
                    Some(index) => all[*index].0.to_string(),
                    None => input.trim().to_string(),
                };
                input.clear();
                cursor = 0;
                if line.is_empty() {
                    continue;
                }
                message = Some(run_line(cfg, &line));
            }
            KeyCode::Char(c) => {
                input.push(c);
                cursor = 0;
            }
            _ => {}
        }
    }
}

/// Выполнить набранную строку так же, как если бы её набрали в терминале.
fn run_line(cfg: &Config, line: &str) -> (bool, String) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    clear();
    println!("{DIM}  net {line}{RESET}\n");
    let outcome = match crate::dispatch(cfg, parts[0], &parts[1..]) {
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
    cfg: &Config,
    message: Option<&(bool, String)>,
    input: &str,
    all: &[(&str, &str)],
    matches: &[usize],
    cursor: usize,
) {
    clear();
    println!("{BOLD}  ОБХОД БЛОКИРОВОК{RESET}\n");

    for (ok, line) in status_lines(cfg) {
        let (color, dot) = if ok { (GREEN, "●") } else { (RED, "○") };
        println!("  {color}{dot} {line}{RESET}");
    }
    println!();

    if input.trim().is_empty() {
        println!(
            "  {DIM}[1]{RESET} zapret вкл/выкл   {DIM}[2]{RESET} стратегия   {DIM}[3]{RESET} проверить"
        );
        println!(
            "  {DIM}[4]{RESET} VPN               {DIM}[5]{RESET} Telegram    {DIM}[6]{RESET} QR на телефон"
        );
        println!(
            "  {DIM}[7]{RESET} автоподбор        {DIM}[8]{RESET} раздача     {DIM}[9]{RESET} профиль сети"
        );
        println!("  {DIM}[q]{RESET} выход");
    } else if matches.is_empty() {
        println!("  {YELLOW}похожих команд нет{RESET}");
    } else {
        // Больше восьми строк подсказок читать уже некогда.
        for (row, index) in matches.iter().take(8).enumerate() {
            let (name, about) = all[*index];
            if row == cursor {
                println!("  {GREEN}▸ {name}{RESET}  {DIM}{about}{RESET}");
            } else {
                println!("    {name}  {DIM}{about}{RESET}");
            }
        }
        if matches.len() > 8 {
            println!("  {DIM}…ещё {}{RESET}", matches.len() - 8);
        }
    }

    if let Some((ok, text)) = message {
        let color = if *ok { GREEN } else { YELLOW };
        println!("\n  {color}{text}{RESET}");
    }

    // Строка ввода всегда последняя: глаз ищет её внизу, как в оболочке.
    println!();
    print!("  {BOLD}›{RESET} {input}▏");
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
