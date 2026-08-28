//! Интерактивный экран: состояние сверху, действия по одной клавише.

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

    loop {
        draw(cfg, message.as_ref());
        let Some(key) = read_key()? else { continue };

        message = match key {
            // Палитра команд: то же, что набрать команду в строке, только с
            // поиском и стрелками — команд стало больше, чем цифр в меню.
            KeyCode::Char('/') => {
                match palette(cfg) {
                    Ok(Some(outcome)) => Some(outcome),
                    Ok(None) => None,
                    Err(e) => Some((false, e)),
                }
            }
            KeyCode::Char('1') => Some(toggle_zapret(cfg)),
            KeyCode::Char('2') => {
                pick_strategy(cfg)?;
                None
            }
            KeyCode::Char('3') => {
                println!();
                crate::run_test_public(cfg);
                pause();
                None
            }
            KeyCode::Char('4') => Some(match Vpn::new(cfg).state() {
                crate::vpn::State::Off => act(Vpn::new(cfg).open(), "Окно Happ открыто"),
                _ => act(Vpn::new(cfg).close(), "Happ закрыт"),
            }),
            KeyCode::Char('5') => Some(toggle_telegram(cfg)),
            KeyCode::Char('6') => {
                show_qr(cfg);
                None
            }
            KeyCode::Char('7') => {
                clear();
                println!("  Подбираю стратегию. Интернет будет прыгать.\n");
                let outcome = match tune::run(cfg, &tune::Options { full: false, verbose: true }) {
                    Ok(best) => (true, format!("выбрана {}", best.strategy)),
                    Err(e) => (false, e),
                };
                pause();
                Some(outcome)
            }
            KeyCode::Char('8') => Some(toggle_share(cfg)),
            KeyCode::Char('9') => {
                clear();
                let network = profile::current_network().unwrap_or_else(|| "не видно".into());
                println!("  Сеть: {BOLD}{network}{RESET}\n");
                println!("  {DIM}[s]{RESET} запомнить состояние для этой сети");
                println!("  {DIM}[a]{RESET} привести всё к профилю сети");
                println!("  {DIM}[любая другая]{RESET} назад");
                let choice = read_key()?;
                let outcome = match choice {
                    Some(KeyCode::Char('s')) => match profile::save_current(cfg) {
                        Ok((net, _)) => (true, format!("профиль сети «{net}» сохранён")),
                        Err(e) => (false, e),
                    },
                    Some(KeyCode::Char('a')) => match profile::apply(cfg) {
                        Ok(done) if done.is_empty() => (true, "всё уже как в профиле".to_string()),
                        Ok(done) => (true, done.join(", ")),
                        Err(e) => (false, e),
                    },
                    _ => return Ok(()),
                };
                Some(outcome)
            }
            KeyCode::Char('q') | KeyCode::Esc => {
                println!();
                return Ok(());
            }
            _ => None,
        };
    }
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

fn draw(cfg: &Config, message: Option<&(bool, String)>) {
    clear();
    println!("{BOLD}  ОБХОД БЛОКИРОВОК{RESET}\n");

    for (ok, line) in status_lines(cfg) {
        let (color, dot) = if ok { (GREEN, "●") } else { (RED, "○") };
        println!("  {color}{dot} {line}{RESET}");
    }

    println!(
        "\n  {DIM}[1]{RESET} zapret вкл/выкл   {DIM}[2]{RESET} стратегия   {DIM}[3]{RESET} проверить"
    );
    println!(
        "  {DIM}[4]{RESET} VPN               {DIM}[5]{RESET} Telegram    {DIM}[6]{RESET} QR на телефон"
    );
    println!(
        "  {DIM}[7]{RESET} автоподбор        {DIM}[8]{RESET} раздача     {DIM}[9]{RESET} профиль сети"
    );
    println!("  {DIM}[/]{RESET} команды поиском   {DIM}[q]{RESET} выход");

    if let Some((ok, text)) = message {
        let color = if *ok { GREEN } else { YELLOW };
        println!("\n  {color}{text}{RESET}");
    }
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

/// Палитра: выбрал команду — она тут же выполняется, вывод остаётся на экране
/// до нажатия клавиши, иначе результат мелькнул бы и пропал.
fn palette(cfg: &Config) -> Result<Option<(bool, String)>, String> {
    let all = crate::commands();
    let items: Vec<crate::picker::Item> = all
        .iter()
        .map(|(name, about)| crate::picker::Item::new(*name).hint(*about))
        .collect();
    let Some(index) = crate::picker::choose("КОМАНДЫ", &items)? else {
        return Ok(None);
    };
    let parts: Vec<&str> = all[index].0.split(' ').collect();
    clear();
    println!("{DIM}  net {}{RESET}\n", all[index].0);
    let outcome = match crate::dispatch(cfg, parts[0], &parts[1..]) {
        Ok(()) => (true, format!("выполнено: {}", all[index].0)),
        Err(e) => (false, e),
    };
    pause();
    Ok(Some(outcome))
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
