//! Выбор из списка: стрелки, поиск по мере набора, Enter.
//!
//! Нод у подписки два десятка, а имена — с флагами: набирать их руками
//! невозможно, номерами неудобно. Поэтому список фильтруется по мере набора,
//! как палитра команд в редакторах: буквы ищутся подпоследовательностью, то
//! есть «трц» находит «Турция», а «нидр» — «Нидерланды».

use crate::{BOLD, DIM, GREEN, RESET, YELLOW};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal;
use std::io::Write;

pub struct Item {
    /// Что выбирают.
    pub label: String,
    /// Приписка справа: задержка, описание команды.
    pub hint: Option<String>,
    /// Помечается точкой — текущая нода, действующая стратегия.
    pub current: bool,
}

impl Item {
    pub fn new(label: impl Into<String>) -> Item {
        Item {
            label: label.into(),
            hint: None,
            current: false,
        }
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Item {
        self.hint = Some(hint.into());
        self
    }

    pub fn current(mut self, current: bool) -> Item {
        self.current = current;
        self
    }
}

/// Показать список и вернуть выбранный номер (в исходном порядке) либо None,
/// если человек передумал.
pub fn choose(title: &str, items: &[Item]) -> Result<Option<usize>, String> {
    choose_prefilled(title, items, "")
}

/// То же, но поиск уже заполнен — когда человек начал набирать команду в
/// строке, а закончить хочет стрелками.
pub fn choose_prefilled(title: &str, items: &[Item], query: &str) -> Result<Option<usize>, String> {
    if items.is_empty() {
        return Ok(None);
    }
    // Без терминала стрелок не бывает: в трубе или в скрипте лучше честно
    // сказать, чем ждать нажатия, которого не будет.
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err("выбор стрелками работает только в терминале — укажи имя или номер".into());
    }
    let mut query = query.to_string();
    let mut cursor = 0usize;
    // Первой показываем текущую строку, если она есть: обычно от неё и пляшут.
    if let Some(pos) = items.iter().position(|i| i.current) {
        cursor = pos;
    }

    terminal::enable_raw_mode().map_err(|e| e.to_string())?;
    let result = loop {
        let matches = filter(items, &query);
        if matches.is_empty() {
            cursor = 0;
        } else if !matches.contains(&cursor) {
            cursor = matches[0];
        }
        draw(title, items, &matches, cursor, &query);

        let key = match event::read() {
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => k,
            Ok(_) => continue,
            Err(e) => break Err(e.to_string()),
        };
        let step = |cursor: usize, forward: bool| -> usize {
            if matches.is_empty() {
                return cursor;
            }
            let at = matches.iter().position(|m| *m == cursor).unwrap_or(0);
            let next = if forward {
                (at + 1) % matches.len()
            } else {
                (at + matches.len() - 1) % matches.len()
            };
            matches[next]
        };
        match (key.code, key.modifiers) {
            (KeyCode::Esc, _) => break Ok(None),
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => break Ok(None),
            (KeyCode::Enter, _) => {
                break Ok(if matches.is_empty() { None } else { Some(cursor) });
            }
            (KeyCode::Down, _) | (KeyCode::Tab, _) | (KeyCode::Char('n'), KeyModifiers::CONTROL) => {
                cursor = step(cursor, true)
            }
            (KeyCode::Up, _) | (KeyCode::BackTab, _) | (KeyCode::Char('p'), KeyModifiers::CONTROL) => {
                cursor = step(cursor, false)
            }
            (KeyCode::Backspace, _) => {
                query.pop();
            }
            (KeyCode::Char(c), _) => query.push(c),
            _ => {}
        }
    };
    terminal::disable_raw_mode().map_err(|e| e.to_string())?;
    println!();
    result
}

/// Ближайшие совпадения текстом — для подсказки, когда терминала нет.
pub fn closest(commands: &[(&str, &str)], query: &str, limit: usize) -> Vec<String> {
    let items: Vec<Item> = commands.iter().map(|(name, _)| Item::new(*name)).collect();
    filter(&items, query)
        .into_iter()
        .take(limit)
        .map(|i| items[i].label.clone())
        .collect()
}

/// Строки, подходящие под запрос, в порядке «чем точнее, тем выше».
pub fn filter(items: &[Item], query: &str) -> Vec<usize> {
    if query.is_empty() {
        return (0..items.len()).collect();
    }
    let mut scored: Vec<(i32, usize)> = items
        .iter()
        .enumerate()
        .filter_map(|(i, item)| score(&item.label, query).map(|s| (s, i)))
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, i)| i).collect()
}

/// Оценка совпадения: буквы запроса должны встретиться в имени по порядку.
/// Подряд идущие и стоящие в начале слова ценятся выше — так «гер» уверенно
/// поднимает «Германию» над случайным совпадением букв.
fn score(label: &str, query: &str) -> Option<i32> {
    let haystack: Vec<char> = label.to_lowercase().chars().collect();
    let needle: Vec<char> = query.to_lowercase().chars().filter(|c| !c.is_whitespace()).collect();
    if needle.is_empty() {
        return Some(0);
    }
    let mut score = 0;
    let mut at = 0usize;
    let mut previous: Option<usize> = None;
    for want in needle {
        let found = haystack[at..].iter().position(|c| *c == want)? + at;
        score += 1;
        if previous == Some(found.saturating_sub(1)) {
            score += 4;
        }
        if found == 0 || !haystack[found - 1].is_alphanumeric() {
            score += 3;
        }
        previous = Some(found);
        at = found + 1;
    }
    Some(score)
}

fn draw(title: &str, items: &[Item], matches: &[usize], cursor: usize, query: &str) {
    let height = terminal::size().map(|(_, h)| h as usize).unwrap_or(24);
    // Строки под заголовок, поле поиска и подсказку внизу.
    let room = height.saturating_sub(6).max(3);

    let mut out = String::from("\x1b[2J\x1b[H");
    out.push_str(&format!("{BOLD}  {title}{RESET}\r\n\r\n"));
    out.push_str(&format!("  {DIM}поиск:{RESET} {query}▏\r\n\r\n"));

    if matches.is_empty() {
        out.push_str(&format!("  {YELLOW}ничего не нашлось{RESET}\r\n"));
    }

    // Окно прокрутки держим вокруг выбранной строки.
    let at = matches.iter().position(|m| *m == cursor).unwrap_or(0);
    let start = at.saturating_sub(room / 2).min(matches.len().saturating_sub(room));
    for index in matches.iter().skip(start).take(room) {
        let item = &items[*index];
        let selected = *index == cursor;
        let dot = if item.current { "●" } else { " " };
        let hint = item
            .hint
            .as_ref()
            .map(|h| format!("  {DIM}{h}{RESET}"))
            .unwrap_or_default();
        if selected {
            out.push_str(&format!("  {GREEN}▸ {dot} {}{RESET}{hint}\r\n", item.label));
        } else {
            out.push_str(&format!("    {dot} {}{hint}\r\n", item.label));
        }
    }
    if matches.len() > room {
        out.push_str(&format!(
            "  {DIM}…ещё {}{RESET}\r\n",
            matches.len() - room
        ));
    }
    out.push_str(&format!(
        "\r\n  {DIM}↑↓ — выбор, Enter — принять, Esc — отмена{RESET}\r\n"
    ));

    print!("{out}");
    std::io::stdout().flush().ok();
}


#[cfg(test)]
mod tests {
    use super::*;

    fn items(labels: &[&str]) -> Vec<Item> {
        labels.iter().map(|l| Item::new(*l)).collect()
    }

    #[test]
    fn ищет_подпоследовательностью() {
        let list = items(&["🇹🇷 Турция", "🇩🇪 Германия", "🇯🇵 Япония"]);
        let found = filter(&list, "трц");
        assert_eq!(list[found[0]].label, "🇹🇷 Турция");
    }

    #[test]
    fn подряд_идущие_буквы_важнее() {
        let list = items(&["🇦🇱 Албания GRPC", "🇩🇪 Германия"]);
        let found = filter(&list, "гер");
        assert_eq!(list[found[0]].label, "🇩🇪 Германия");
    }

    #[test]
    fn начало_слова_важнее_середины() {
        let list = items(&["vpn update", "vpn use"]);
        let found = filter(&list, "use");
        assert_eq!(list[found[0]].label, "vpn use");
    }

    #[test]
    fn чужие_строки_отсеиваются() {
        let list = items(&["vpn nodes", "share on"]);
        assert_eq!(filter(&list, "zzz").len(), 0);
    }

    #[test]
    fn пустой_запрос_оставляет_всё() {
        let list = items(&["a", "b", "c"]);
        assert_eq!(filter(&list, "").len(), 3);
    }

    #[test]
    fn подсказка_ближайших_команд() {
        let commands = [("vpn nodes", ""), ("vpn use", ""), ("share on", "")];
        let close = closest(&commands, "vpn nods", 2);
        assert_eq!(close[0], "vpn nodes");
    }
}
