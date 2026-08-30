//! Экран пульта: состояние сверху, ноды посередине, строка ввода снизу.
//!
//! Устроен как одно окно, из которого никуда не уходишь. Команды набираются
//! в строке — под ней тут же появляются похожие. Вывод команды печатается на
//! том же экране, поэтому «нажмите клавишу, чтобы вернуться» не нужно: экран
//! и есть то место, куда возвращаться.
//!
//! Долгие дела (замер задержек, подбор стратегии) идут в отдельном потоке и
//! досылают строки по мере готовности — экран при этом живой, а не замерший.

use crate::config::Config;
use crate::singbox;
use crate::picker::{clip, fit, pad};
use crate::sub;
use crate::{status_lines, Status, BOLD, DIM, GREEN, RED, RESET, YELLOW};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseEventKind};
use crossterm::terminal;
use std::io::{BufRead, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

/// Сколько строк вывода команды показывать.
const OUTPUT_ROWS: usize = 8;

/// Сколько строк отдаём похожим командам. Раньше их было ровно четыре, и это
/// молча обрезало список: набранное имя пульта показывает все команды разом,
/// а из них было видно четыре штуки без всякого признака, что есть ещё.
const SUGGEST_ROWS_MAX: usize = 9;
const SUGGEST_ROWS_MIN: usize = 4;

/// Наименьшее место под ноды, если окно совсем низкое.
const NODE_ROWS_MIN: usize = 5;

/// Сколько колонок занимает всё, что стоит правее имени в строке ноды:
/// отступ 2, маркеры «выбрано» и «текущая» с пробелами 4, полоска задержки 8,
/// число «1234 мс» 7, плюс два пробела-разделителя. Считается по строке, а не
/// прикидывается на глаз — раньше тут стояло 26 без объяснения, и колонка
/// имени была на три знака уже, чем могла быть.
const NODE_TAIL: usize = 2 + 4 + 8 + 7 + 2;

/// Сколько нод оставляем на виду, пока набирают команду: список команд в этот
/// момент главнее, и отдавать ему нижние две строки экрана — значит прятать
/// то, на что человек прямо сейчас смотрит.
const NODE_ROWS_BUSY: usize = 8;

/// Весточка из рабочего потока.
enum Work {
    /// Команда пошла: её номер процесса, чтобы было чем оборвать.
    Started(u32),
    /// Строка вывода запущенной команды.
    Line(String),
    /// Задержка ноды: номер и результат замера.
    Delay(usize, Option<u32>),
    /// Дело кончилось: чем именно.
    Done(bool, String),
}

struct Node {
    name: String,
    /// `None` — ещё не мерили, `Some(None)` — не ответила.
    delay: Option<Option<u32>>,
}

struct Screen {
    status: Vec<Status>,
    /// Чем сейчас держится связь: готовый ответ для первой строки экрана.
    carrier: (bool, String),
    status_taken: Instant,
    current_taken: Instant,
    nodes: Vec<Node>,
    node_at: usize,
    /// Нода, через которую идёт трафик, и выбрана ли она автоподбором.
    current: Option<(String, bool)>,
    input: String,
    suggestion_at: usize,
    output: Vec<String>,
    message: Option<(bool, String)>,
    busy: Option<String>,
    busy_since: Instant,
    /// Последняя запущенная команда — чтобы повторить её после пароля.
    last: Option<String>,
    /// Процесс идущей команды: по нему её и обрываем.
    running: Option<u32>,
}

pub fn run(cfg: &Config) -> Result<(), String> {
    let mut screen = Screen {
        status: status_lines(cfg),
        carrier: crate::route::carrier(cfg),
        status_taken: Instant::now(),
        current_taken: Instant::now(),
        nodes: load_nodes(),
        node_at: 0,
        current: None,
        input: String::new(),
        suggestion_at: 0,
        output: Vec::new(),
        message: None,
        busy: None,
        busy_since: Instant::now(),
        last: None,
        running: None,
    };
    let commands = crate::commands();
    let items: Vec<crate::picker::Item> = commands
        .iter()
        .map(|(name, about)| crate::picker::Item::new(*name).hint(*about))
        .collect();
    let (sender, receiver): (Sender<Work>, Receiver<Work>) = mpsc::channel();

    terminal::enable_raw_mode().map_err(|e| e.to_string())?;
    // Свой буфер экрана: кадр рисуется поверх себя, а история терминала
    // остаётся нетронутой. Без этого длинный вывод прокручивал экран, и
    // заголовок печатался снова и снова.
    //
    // Колесо мыши терминал шлёт как управляющую последовательность. Пока её
    // никто не разбирает, она долетает до строки ввода россыпью знаков — на
    // экране будто сам собой набирается мусор. Забираем мышь себе и толкуем
    // колесо как движение по списку нод.
    let _ = crossterm::execute!(
        std::io::stdout(),
        terminal::EnterAlternateScreen,
        event::EnableBracketedPaste,
        event::EnableMouseCapture
    );
    print!("\x1b[2J");

    let result = loop {
        // Сначала забираем всё, что успели прислать рабочие потоки.
        while let Ok(work) = receiver.try_recv() {
            match work {
                Work::Started(pid) => screen.running = Some(pid),
                Work::Line(line) => screen.output.push(line),
                Work::Delay(index, ms) => {
                    if let Some(node) = screen.nodes.get_mut(index) {
                        node.delay = Some(ms);
                    }
                }
                Work::Done(ok, text) => {
                    screen.busy = None;
                    screen.running = None;
                    // Пароль спрашиваем не заранее, а по надобности: там, где
                    // хватает polkit, лишний запрос только раздражает.
                    if !ok && text.contains(crate::sudoer::NEED_PASSWORD)
                        && let Some(again) = screen.last.clone() {
                            match ask_password(&again) {
                                Ok(()) => {
                                    start_command(&mut screen, sender.clone(), &again);
                                    continue;
                                }
                                Err(e) => {
                                    screen.message = Some((false, e));
                                    continue;
                                }
                            }
                        }
                    screen.message = Some((ok, text));
                    screen.status = status_lines(cfg);
                    screen.carrier = crate::route::carrier(cfg);
                    screen.status_taken = Instant::now();
                    screen.nodes = merge_nodes(screen.nodes);
                    screen.current = singbox::active_node();
                }
            }
        }
        if screen.status_taken.elapsed() > Duration::from_secs(10) && screen.busy.is_none() {
            screen.status = status_lines(cfg);
            screen.carrier = crate::route::carrier(cfg);
            screen.status_taken = Instant::now();
        }
        // Автоподбор переставляет ноду сам, без нашего ведома: спрашиваем, кто
        // сейчас в деле, иначе в заголовке висит давно смененная страна.
        if screen.current_taken.elapsed() > Duration::from_secs(3) && screen.busy.is_none() {
            screen.current = singbox::active_node();
            screen.current_taken = Instant::now();
        }

        let suggestions = suggest(&items, &screen.input);
        if screen.suggestion_at >= suggestions.len() {
            screen.suggestion_at = 0;
        }
        draw(&screen, &suggestions);

        // Ждём нажатия недолго: пока его нет, забираем вести от потоков и
        // перерисовываем — так виден ход замера.
        if !event::poll(Duration::from_millis(120)).map_err(|e| e.to_string())? {
            continue;
        }
        let event = match event::read() {
            Ok(e) => e,
            Err(e) => break Err(e.to_string()),
        };
        if let Event::Mouse(mouse) = &event {
            match mouse.kind {
                MouseEventKind::ScrollUp => move_node(&mut screen, -1),
                MouseEventKind::ScrollDown => move_node(&mut screen, 1),
                _ => {}
            }
            continue;
        }
        if let Event::Paste(text) = &event {
            screen.input.push_str(text.trim());
            screen.suggestion_at = 0;
            continue;
        }
        let Event::Key(key) = event else { continue };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
            // Пока команда идёт, Ctrl+C обрывает её, а не пульт: выйти,
            // оставив за собой недоделанное дело, — не то, чего ждут.
            if screen.busy.is_some() {
                stop_running(&mut screen);
                continue;
            }
            break Ok(());
        }

        if screen.input.is_empty() {
            // Пустая строка — экран слушается стрелок и коротких клавиш.
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                KeyCode::Up => {
                    move_node(&mut screen, -1);
                    continue;
                }
                KeyCode::Down => {
                    move_node(&mut screen, 1);
                    continue;
                }
                KeyCode::Enter => {
                    choose_node(&mut screen);
                    continue;
                }
                KeyCode::Char('p') | KeyCode::Char('з') => {
                    start_ping(&mut screen, sender.clone());
                    continue;
                }
                KeyCode::Char('r') | KeyCode::Char('к') => {
                    screen.status = status_lines(cfg);
                    screen.carrier = crate::route::carrier(cfg);
                    screen.status_taken = Instant::now();
                    screen.nodes = load_nodes();
                    screen.current = singbox::active_node();
                    continue;
                }
                _ => {}
            }
        }

        match key.code {
            KeyCode::Esc => {
                screen.input.clear();
                screen.suggestion_at = 0;
            }
            KeyCode::Backspace => {
                screen.input.pop();
                screen.suggestion_at = 0;
            }
            KeyCode::Down | KeyCode::Tab => {
                if !suggestions.is_empty() {
                    screen.suggestion_at = (screen.suggestion_at + 1) % suggestions.len();
                }
            }
            KeyCode::Up | KeyCode::BackTab => {
                if !suggestions.is_empty() {
                    screen.suggestion_at =
                        (screen.suggestion_at + suggestions.len() - 1) % suggestions.len();
                }
            }
            KeyCode::Enter => {
                let line = match suggestions.get(screen.suggestion_at) {
                    Some(found) => found.line.clone(),
                    None => strip_own_name(&screen.input),
                };
                screen.input.clear();
                screen.suggestion_at = 0;
                match line.as_str() {
                    "" => {}
                    // Выбор ноды живёт на этом же экране — незачем звать
                    // отдельный список поверх него.
                    "vpn use" | "vpn nodes" => {
                        screen.message =
                            Some((true, "ноды выше: стрелки — выбор, Enter — включить, p — замерить".into()))
                    }
                    _ => start_command(&mut screen, sender.clone(), &line),
                }
            }
            KeyCode::Char(c) => {
                screen.input.push(c);
                screen.suggestion_at = 0;
            }
            _ => {}
        }
    };

    let _ = crossterm::execute!(
        std::io::stdout(),
        event::DisableMouseCapture,
        event::DisableBracketedPaste,
        terminal::LeaveAlternateScreen
    );
    terminal::disable_raw_mode().map_err(|e| e.to_string())?;
    println!();
    result
}

fn load_nodes() -> Vec<Node> {
    sub::load_nodes()
        .unwrap_or_default()
        .into_iter()
        .map(|n| Node {
            name: n.name,
            delay: None,
        })
        .collect()
}

/// Перечитать список нод, сохранив уже измеренное: после команды `vpn update`
/// список может смениться, а мерить всё заново из-за этого не хочется.
fn merge_nodes(previous: Vec<Node>) -> Vec<Node> {
    let fresh = load_nodes();
    fresh
        .into_iter()
        .map(|mut node| {
            if let Some(old) = previous.iter().find(|p| p.name == node.name) {
                node.delay = old.delay;
            }
            node
        })
        .collect()
}

fn move_node(screen: &mut Screen, step: isize) {
    if screen.nodes.is_empty() {
        return;
    }
    let count = screen.nodes.len() as isize;
    screen.node_at = ((screen.node_at as isize + step + count) % count) as usize;
}

fn choose_node(screen: &mut Screen) {
    let Some(node) = screen.nodes.get(screen.node_at) else {
        return;
    };
    screen.message = Some(match singbox::select(&node.name) {
        Ok(()) => {
            screen.current = Some((node.name.clone(), false));
            (true, format!("нода: {}", node.name))
        }
        Err(e) => (false, e),
    });
}

/// Замер задержек всех нод. Идёт в отдельном потоке и досылает результаты по
/// одному: список заполняется на глазах, а не появляется через минуту.
fn start_ping(screen: &mut Screen, sender: Sender<Work>) {
    if screen.busy.is_some() {
        return;
    }
    if singbox::Core::state_now() != singbox::State::Up {
        screen.message = Some((false, "туннель не поднят — задержки мерить нечем".into()));
        return;
    }
    let names: Vec<String> = screen.nodes.iter().map(|n| n.name.clone()).collect();
    if names.is_empty() {
        screen.message = Some((false, "подписка ещё не загружена".into()));
        return;
    }
    for node in screen.nodes.iter_mut() {
        node.delay = None;
    }
    screen.busy = Some("меряю задержки".into());
    screen.busy_since = Instant::now();
    screen.message = None;
    std::thread::spawn(move || {
        let total = names.len();
        for (index, name) in names.iter().enumerate() {
            let ms = singbox::delay(name, 3000);
            let _ = sender.send(Work::Delay(index, ms));
            let _ = sender.send(Work::Line(format!("замерено {}/{total}", index + 1)));
        }
        let _ = sender.send(Work::Done(true, format!("задержки: {total} нод")));
    });
}

/// Запустить команду и показывать её вывод по мере появления.
///
/// Команда выполняется отдельным процессом того же пульта: так её вывод
/// перехватывается построчно, экран остаётся живым, а печать команд не нужно
/// переписывать ради интерактивности.
fn start_command(screen: &mut Screen, sender: Sender<Work>, line: &str) {
    // Службы из экрана не запускают: они не заканчиваются, и пульт остался бы
    // «занят» навсегда.
    if is_daemon(line) {
        screen.message = Some((
            false,
            "это служба, она работает без конца — ставится отдельно: net watch install".into(),
        ));
        return;
    }
    // Вывод, который не лезет в панель на восемь строк, показываем во весь
    // терминал: калечить QR-код рамкой незачем.
    if needs_terminal(line) {
        screen.message = Some(hand_over(line));
        return;
    }
    if screen.busy.is_some() {
        screen.message = Some((false, "подожди, предыдущее ещё идёт".into()));
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        screen.message = Some((false, "не найти самого себя на диске".into()));
        return;
    };
    let args: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    screen.output.clear();
    screen.busy = Some(line.to_string());
    screen.busy_since = Instant::now();
    screen.message = None;
    screen.last = Some(line.to_string());
    let shown = line.to_string();
    std::thread::spawn(move || {
        let child = std::process::Command::new(exe)
            .args(&args)
            // Внутри экрана списки рисует сам экран: подпроцессу интерактив
            // запрещён, иначе его управляющие коды лезут в панель вывода.
            .env("NETPULT_PLAIN", "1")
            // Пароля тут не спросишь: пусть sudo сразу скажет, что его нет,
            // вместо того чтобы ждать ответа в пустоту.
            .env(crate::sudoer::NOASK, "1")
            // Клавиатура принадлежит экрану: без этого подпроцесс перехватывал
            // бы нажатия у себя.
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                let _ = sender.send(Work::Done(false, format!("не запустилось: {e}")));
                return;
            }
        };
        let _ = sender.send(Work::Started(child.id()));
        if let Some(out) = child.stdout.take() {
            for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                let clean = strip_colors(&line);
                if !clean.trim().is_empty() {
                    let _ = sender.send(Work::Line(clean));
                }
            }
        }
        let mut trouble = String::new();
        if let Some(err) = child.stderr.take() {
            for line in std::io::BufReader::new(err).lines().map_while(Result::ok) {
                let clean = strip_colors(&line);
                trouble.push_str(clean.trim());
                if !clean.trim().is_empty() {
                    let _ = sender.send(Work::Line(clean));
                }
            }
        }
        let ok = child.wait().map(|s| s.success()).unwrap_or(false);
        let _ = sender.send(Work::Done(
            ok,
            if ok {
                format!("готово: {shown}")
            } else if trouble.is_empty() {
                format!("не вышло: {shown}")
            } else {
                strip_colors(&trouble)
            },
        ));
    });
}

/// Команда, которая не заканчивается сама.
fn is_daemon(line: &str) -> bool {
    matches!(line.trim(), "watch" | "split serve" | "share serve")
}

/// Оборвать идущую команду.
fn stop_running(screen: &mut Screen) {
    if let Some(pid) = screen.running.take() {
        #[cfg(unix)]
        {
            let _ = std::process::Command::new("kill")
                .arg(pid.to_string())
                .status();
        }
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .status();
        }
    }
    screen.busy = None;
    screen.message = Some((false, "оборвано".into()));
}

/// Нужен ли команде весь экран: её вывод не лезет в панель на восемь строк.
/// QR-код, справка, длинные списки — панель такой вывод не показывает, а
/// калечит. Пароль сюда больше не относится: его спрашивают отдельно.
fn needs_terminal(line: &str) -> bool {
    const BIG: [&str; 13] = [
        "tg qr", "tg link", "help", "test", "tune", "status", "path", "strat", "split list",
        "split log", "share status", "vpn log", "watch log",
    ];
    BIG.iter()
        .any(|name| line == *name || line.starts_with(&format!("{name} ")))
}

/// Спросить пароль, отдав терминал на эти несколько секунд. Возвращаемся сразу
/// после ввода — клавишу «чтобы вернуться» тут жать не за чем.
fn ask_password(line: &str) -> Result<(), String> {
    terminal::disable_raw_mode().ok();
    let _ = crossterm::execute!(
        std::io::stdout(),
        event::DisableMouseCapture,
        terminal::LeaveAlternateScreen
    );
    print!("\x1b[2J\x1b[H");
    println!("{DIM}  net {line} — нужны права администратора{RESET}\n");
    std::io::stdout().flush().ok();

    let asked = crate::sudoer::ask();

    terminal::enable_raw_mode().ok();
    let _ = crossterm::execute!(
        std::io::stdout(),
        terminal::EnterAlternateScreen,
        event::EnableMouseCapture
    );
    print!("\x1b[2J");
    asked
}

/// Отдать терминал команде: выйти из сырого режима, дать ей напечатать своё и
/// спросить пароль, дождаться и вернуть экран.
fn hand_over(line: &str) -> (bool, String) {
    let Ok(exe) = std::env::current_exe() else {
        return (false, "не найти самого себя на диске".into());
    };
    let args: Vec<&str> = line.split_whitespace().collect();
    terminal::disable_raw_mode().ok();
    let _ = crossterm::execute!(
        std::io::stdout(),
        event::DisableMouseCapture,
        terminal::LeaveAlternateScreen
    );
    print!("\x1b[2J\x1b[H");
    println!("{DIM}  net {line}{RESET}\n");
    std::io::stdout().flush().ok();

    let status = std::process::Command::new(exe).args(&args).status();

    println!("\n{DIM}  нажми любую клавишу{RESET}");
    std::io::stdout().flush().ok();
    terminal::enable_raw_mode().ok();
    let _ = event::read();
    let _ = crossterm::execute!(
        std::io::stdout(),
        terminal::EnterAlternateScreen,
        event::EnableMouseCapture
    );
    print!("\x1b[2J");

    match status {
        Ok(status) if status.success() => (true, format!("готово: {line}")),
        Ok(_) => (false, format!("не вышло: {line} — смотри net vpn log")),
        Err(e) => (false, format!("не запустилось: {e}")),
    }
}

/// Дополнить до ширины по видимым знакам. Обычное форматирование считает
/// байты, а флаги стран занимают их по четыре штуки — столбец разъезжается.

fn strip_colors(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for skip in chars.by_ref() {
                if skip.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Подсказка: что показать и что выполнить.
pub struct Suggestion {
    pub line: String,
    pub label: String,
    pub about: String,
}

/// Похожие команды под набранным.
///
/// Две особые ситуации, без которых экран врал «похожих команд нет» на вполне
/// осмысленный ввод: вставленная ссылка (человек вставляет подписку и ждёт
/// действия, а не поиска команды с такими буквами) и команда с аргументами —
/// «vpn use Турция» ни на что не похоже по буквам, но выполнить его надо.
fn suggest(items: &[crate::picker::Item], input: &str) -> Vec<Suggestion> {
    let typed = strip_own_name(input);
    let typed = typed.as_str();
    if typed.is_empty() {
        // Пустая строка — чистый экран. Но если набрано имя пульта и от него
        // ничего не осталось, человек ждёт список команд, а не пустоту.
        if input.trim().is_empty() {
            return Vec::new();
        }
        return items
            .iter()
            .map(|item| Suggestion {
                line: item.label.clone(),
                label: item.label.clone(),
                about: item.hint.clone().unwrap_or_default(),
            })
            .collect();
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

/// Внутри пульта имя пульта писать незачем, но рука набирает его по привычке —
/// молча срезаем, иначе «net vpn nodes» не совпадёт ни с чем.
///
/// Одно голое имя тоже срезаем, в пустую строку. Раньше «net» уходил в поиск
/// как обычное слово и совпадал по буквам n→e→t ровно с одной командой,
/// `vpn core install`: человек набирал «net», ждал список, получал бессмыслицу
/// и вынужден был дописывать «net o», чтобы увидеть `off`.
pub fn strip_own_name(input: &str) -> String {
    let typed = input.trim();
    for name in ["netpult", "net"] {
        if typed == name {
            return String::new();
        }
        if let Some(rest) = typed.strip_prefix(&format!("{name} ")) {
            return rest.trim().to_string();
        }
    }
    typed.to_string()
}

fn find_url(text: &str) -> Option<String> {
    let at = text.find("https://").or_else(|| text.find("http://"))?;
    Some(text[at..].split_whitespace().next()?.to_string())
}

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

/// Тонкая черта во всю ширину. Блоки на экране разделены пустыми строками, и
/// на прозрачном терминале, где сквозь текст просвечивает картинка, границы
/// блоков теряются совсем. Черта их держит и стоит одну строку.
fn rule(width: usize) -> String {
    format!("  {DIM}{}{RESET}", "─".repeat(width.saturating_sub(4)))
}

/// Короткая сводка по нодам в шапку: сколько замерено, сколько живо, какая
/// самая быстрая. Пока ничего не мерено — молчим, пустые цифры не нужны.
fn node_summary(screen: &Screen) -> String {
    let measured: Vec<Option<u32>> = screen.nodes.iter().filter_map(|n| n.delay).collect();
    if measured.is_empty() {
        return String::new();
    }
    let alive = measured.iter().filter(|d| d.is_some()).count();
    let best = measured.iter().flatten().min();
    let tail = match best {
        Some(ms) => format!(" · лучшая {ms} мс"),
        None => String::new(),
    };
    format!(
        "  {DIM}живых {alive}/{}{tail}{RESET}",
        screen.nodes.len()
    )
}

/// Полоска качества связи: чем короче задержка, тем длиннее. Восемь знаков —
/// достаточно, чтобы разница читалась боковым зрением, и не настолько широко,
/// чтобы теснить имена.
fn delay_bar(ms: u32) -> String {
    const WIDTH: usize = 8;
    let filled = match ms {
        0..=99 => 8,
        100..=199 => 7,
        200..=299 => 6,
        300..=449 => 5,
        450..=649 => 4,
        650..=899 => 3,
        900..=1399 => 2,
        _ => 1,
    };
    let color = if ms < 300 {
        GREEN
    } else if ms < 800 {
        YELLOW
    } else {
        RED
    };
    format!(
        "{color}{}{RESET}{DIM}{}{RESET}",
        "█".repeat(filled),
        "·".repeat(WIDTH - filled)
    )
}

fn draw(screen: &Screen, suggestions: &[Suggestion]) {
    // Кадр печатается поверх прежнего, строка затирает строку: без очистки
    // экрана нет мигания.
    let width = terminal::size().map(|(w, _)| w as usize).unwrap_or(80).max(48);

    let mut rows: Vec<String> = Vec::new();
    rows.push(format!("{BOLD}  ОБХОД БЛОКИРОВОК{RESET}{}", node_summary(screen)));
    rows.push(rule(width));
    // Ответ на главный вопрос экрана — первой строкой и не тусклым. Раньше его
    // приходилось складывать в голове из трёх равноправных строк состояния.
    let (carrier_ok, carrier) = &screen.carrier;
    let carrier_color = if *carrier_ok { GREEN } else { YELLOW };
    rows.push(format!("  {DIM}Трафик{RESET}  {carrier_color}{carrier}{RESET}"));
    rows.push(String::new());

    // Колонки состояния выравниваются здесь, а не пробелами внутри строк:
    // ширина зависит от того, какие службы вообще подняты.
    let name_width = crate::status_name_width(&screen.status);
    for s in &screen.status {
        let (color, dot) = if s.ok { (GREEN, "●") } else { (RED, "○") };
        let name = pad(s.name, name_width);
        let state = pad(&s.state, 4);
        if s.detail.is_empty() {
            rows.push(format!("  {color}{dot}{RESET} {name}  {color}{state}{RESET}"));
        } else {
            rows.push(format!(
                "  {color}{dot}{RESET} {name}  {color}{state}{RESET}  {}",
                s.detail
            ));
        }
    }
    rows.push(String::new());

    // Список нод занимает всё, что осталось от окна: показывать семь строк из
    // двадцати двух — значит прятать половину подписки без причины.
    let height = terminal::size().map(|(_, h)| h as usize).unwrap_or(24);
    // Пустая панель вывода занимала восемь строк ни за чем, и на невысоком
    // окне из-за неё было видно пять нод из двадцати двух. Пока выводить
    // нечего, эти строки отдаём списку.
    let output_rows = if screen.output.is_empty() {
        0
    } else {
        OUTPUT_ROWS.min(screen.output.len())
    };
    // Пустая строка ввода — показывать нечего, и держать под это четыре
    // строки незачем: они складывались с пустотой под списком нод в широкую
    // мёртвую полосу над строкой ввода.
    let suggest_rows = if suggestions.is_empty() && screen.input.trim().is_empty() {
        1
    } else {
        suggestions.len().clamp(SUGGEST_ROWS_MIN, SUGGEST_ROWS_MAX)
    };
    let fixed = rows.len() + output_rows + suggest_rows + 5;
    // Место забирает то, чем сейчас заняты. Пока строка пуста, экран про ноды
    // — список во всю высоту. Как только набирают команду, главное на экране
    // это список команд, и ноды ужимаются до нескольких строк, чтобы он не
    // жался к нижнему краю.
    let room = if screen.input.trim().is_empty() {
        height.saturating_sub(fixed).max(NODE_ROWS_MIN)
    } else {
        height
            .saturating_sub(fixed)
            .clamp(NODE_ROWS_MIN, NODE_ROWS_BUSY)
    };

    if screen.nodes.is_empty() {
        rows.push(format!(
            "  {DIM}НОДЫ{RESET}  {DIM}подписки нет: набери vpn sub и вставь ссылку{RESET}"
        ));
        for _ in 0..room {
            rows.push(String::new());
        }
    } else {
        let here = match &screen.current {
            Some((name, true)) => format!("{name}  {DIM}(автоподбор){RESET}"),
            Some((name, false)) => name.clone(),
            None => "не выбрана".to_string(),
        };
        // Пока задержки не мерены, «p — замерить» и есть то, что тут надо
        // сделать: говорим это словами, а не прочерками в каждой строке.
        let unmeasured = screen.nodes.iter().all(|n| n.delay.is_none());
        let hint = if unmeasured {
            format!("{YELLOW}p — замерить задержки{RESET}")
        } else {
            format!("{DIM}↑↓ выбор · Enter включить · p замерить{RESET}")
        };
        rows.push(format!(
            "  {DIM}НОДЫ{RESET} {GREEN}{here}{RESET}  {}/{}  {hint}",
            screen.node_at + 1,
            screen.nodes.len()
        ));

        // Окно прокрутки держится вокруг выбранной строки, а не стоит на месте.
        let shown = room.min(screen.nodes.len());
        let first = screen
            .node_at
            .saturating_sub(shown / 2)
            .min(screen.nodes.len() - shown);
        for (offset, node) in screen.nodes.iter().skip(first).take(shown).enumerate() {
            let index = first + offset;
            let selected = index == screen.node_at;
            let current = screen
                .current
                .as_ref()
                .is_some_and(|(name, _)| *name == node.name);
            let mark = if current {
                format!("{GREEN}●{RESET}")
            } else {
                " ".to_string()
            };
            let delay = match node.delay {
                // Незамеренное молчит и на экране. Двадцать два прочерка
                // столбиком не сообщают ничего, а занимают половину окна и
                // читаются как список поломок.
                None => String::new(),
                Some(None) => format!("{RED}молчит{RESET}"),
                Some(Some(ms)) => {
                    let color = if ms < 300 {
                        GREEN
                    } else if ms < 800 {
                        YELLOW
                    } else {
                        RED
                    };
                    // Полоска слева от числа: глазу хватает её одной, число
                    // нужно, только когда ноды близки.
                    format!("{} {color}{}{RESET}", delay_bar(ms), pad(&format!("{ms} мс"), 7))
                }
            };
            // Имена занимают всю ширину, какая есть: на широком окне «Нидерланды
            // 2 (Амстердам)» больше не обрезается до неузнаваемости, на узком
            // колонка ужимается сама.
            let name_width = width.saturating_sub(NODE_TAIL).clamp(16, 42);
            let name = if delay.is_empty() {
                clip(&node.name, name_width)
            } else {
                fit(&node.name, name_width)
            };
            if selected {
                rows.push(format!("  {GREEN}▸{RESET} {mark} {GREEN}{name}{RESET} {delay}"));
            } else {
                // Двадцать строк в полную яркость перебивали шапку состояния,
                // хотя список — второй шаг, а не первый.
                rows.push(format!("    {mark} {DIM}{name}{RESET} {delay}"));
            }
        }
        // Список не растягиваем пустыми строками до отведённой высоты: три
        // пустые строки под последней нодой читаются как обрыв, а не как
        // пауза. Недобранное место просто уходит нижним блокам.
        for _ in shown..room.min(screen.nodes.len()) {
            rows.push(String::new());
        }
    }
    rows.push(String::new());

    // Показываем последние строки вывода: панель растёт до предела и дальше
    // прокручивается сама.
    let tail = screen.output.len().saturating_sub(output_rows);
    for row in 0..output_rows {
        match screen.output.get(tail + row) {
            Some(line) => rows.push(format!("  {DIM}│{RESET} {line}")),
            None => rows.push(String::new()),
        }
    }
    if output_rows > 0 {
        rows.push(String::new());
    }

    // Черта отделяет то, что набирают, от того, что показывают: строка ввода
    // и её подсказки — единственная часть экрана, которая отвечает на нажатия.
    rows.push(rule(width));

    if !suggestions.is_empty() {
        // Шапка блока — как у списка нод: счётчик и клавиши сверху, а не под
        // списком. Один и тот же смысл в двух местах экрана сбивал с толку.
        let shown = suggest_rows.saturating_sub(1).min(suggestions.len());
        rows.push(format!(
            "  {DIM}КОМАНДЫ{RESET}  {}/{}  {DIM}↑↓ или Tab листать · Enter выполнить{RESET}",
            screen.suggestion_at + 1,
            suggestions.len()
        ));
        // Окно листается вместе с выбором, иначе до нижних команд не дойти.
        let first = screen
            .suggestion_at
            .saturating_sub(shown / 2)
            .min(suggestions.len() - shown);
        // Ширина колонки считается так же, как у нод: от ширины окна, а не от
        // самой длинной видимой строки. Иначе колонка прыгала при листании.
        let name_width = width.saturating_sub(NODE_TAIL).clamp(16, 42);
        for (offset, item) in suggestions.iter().skip(first).take(shown).enumerate() {
            let index = first + offset;
            let label = fit(&item.label, name_width.min(24));
            // Описание тоже режем по ширине: без этого длинная строка
            // переносится, и высота блока перестаёт сходиться с расчётной.
            let about = clip(&item.about, width.saturating_sub(name_width.min(24) + 8));
            if index == screen.suggestion_at {
                rows.push(format!("  {GREEN}▸ {label}{RESET}  {about}"));
            } else {
                rows.push(format!("    {label}  {DIM}{about}{RESET}"));
            }
        }
        for _ in shown + 1..suggest_rows {
            rows.push(String::new());
        }
    } else if !screen.input.trim().is_empty() {
        rows.push(format!("  {YELLOW}похожих команд нет{RESET}"));
        for _ in 1..suggest_rows {
            rows.push(String::new());
        }
    } else {
        rows.push(format!(
            "  {DIM}набирай команду — покажу похожие · q — выход · r — обновить{RESET}"
        ));
    }

    rows.push(match (&screen.busy, &screen.message) {
        (Some(what), _) => {
            // Крутилка и секунды: видно, что дело идёт, а не встало.
            const FRAMES: [&str; 4] = ["|", "/", "-", "\\"];
            let elapsed = screen.busy_since.elapsed();
            let frame = FRAMES[(elapsed.as_millis() / 120) as usize % FRAMES.len()];
            format!(
                "  {YELLOW}{frame} {what}… {:.0} с{RESET}",
                elapsed.as_secs_f32()
            )
        }
        (None, Some((ok, text))) => {
            // Красный тут и значит «не вышло». Жёлтый остаётся за
            // предупреждением и подсказкой — двум смыслам один цвет не дают.
            let color = if *ok { GREEN } else { RED };
            format!("  {color}{text}{RESET}")
        }
        _ => String::new(),
    });
    rows.push(String::new());

    let mut frame = String::from("\x1b[H");
    for row in rows {
        frame.push_str(&row);
        frame.push_str("\x1b[K\r\n");
    }
    frame.push_str(&format!("  {BOLD}›{RESET} {}▏\x1b[K\x1b[J", screen.input));
    print!("{frame}");
    std::io::stdout().flush().ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::picker::Item;

    fn команды() -> Vec<Item> {
        crate::commands()
            .iter()
            .map(|(name, about)| Item::new(*name).hint(*about))
            .collect()
    }

    #[test]
    fn имя_пульта_целиком_срезается() {
        assert_eq!(strip_own_name("net"), "");
        assert_eq!(strip_own_name("netpult"), "");
        assert_eq!(strip_own_name("  net  "), "");
        assert_eq!(strip_own_name("net off"), "off");
        assert_eq!(strip_own_name("net vpn nodes"), "vpn nodes");
    }

    #[test]
    fn набранное_имя_пульта_показывает_все_команды() {
        // Раньше «net» уходил в поиск обычным словом и совпадал по буквам
        // n→e→t ровно с одной командой, `vpn core install`.
        let items = команды();
        let found = suggest(&items, "net");
        assert_eq!(found.len(), items.len(), "показаны не все команды");
        assert!(
            found.iter().any(|s| s.line == "off"),
            "«off» должна быть в списке сразу после «net»"
        );
    }

    #[test]
    fn пустая_строка_ничего_не_предлагает() {
        assert!(suggest(&команды(), "").is_empty());
        assert!(suggest(&команды(), "   ").is_empty());
    }

    #[test]
    fn имя_пульта_с_командой_ищет_команду() {
        let found = suggest(&команды(), "net off");
        assert_eq!(found[0].line, "off");
    }

    #[test]
    fn длинное_имя_подрезается_под_ширину() {
        assert_eq!(fit("Нидерланды 2", 6).chars().count(), 6);
        assert_eq!(fit("США", 8).chars().count(), 8);
    }

    #[test]
    fn последняя_колонка_не_добивается_пробелами() {
        // clip режет длинное, но короткое оставляет как есть — за ним ничего
        // нет, и хвост из пробелов там ни к чему.
        assert_eq!(clip("США", 8), "США");
        assert_eq!(clip("Нидерланды 2", 6).chars().count(), 6);
    }
}
