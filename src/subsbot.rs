//! Telegram-бот для подписок: написал в чат — роутер на следующем опросе
//! подхватил.
//!
//! Опрос идёт long-poll'ом (`getUpdates` с таймаутом): роутер сам ходит к
//! api.telegram.org, входящих портов не нужно, CGNAT не мешает. Команды
//! принимаются только из одного заранее заданного чата — `bot_chat` в
//! конфиге; чужие сообщения игнорируются молча.
//!
//! Telegram у провайдера может быть заблокирован — тогда `getUpdates`
//! просто не ответит, и это не ошибка: на такой случай есть запасной канал
//! через манифест (см. [`crate::manifest`]).
//!
//! Команды (текст сообщения):
//!   add <url>       — завести ссылку
//!   rm <url>        — забыть ссылку
//!   revive <url>    — вернуть из отставки
//!   list            — показать список
//!   status          — коротко: активные/в отставке, последний прогон

use crate::json::Json;
use crate::subs::{self, Store};
use std::process::Command;

const API: &str = "https://api.telegram.org";

fn offset_path() -> std::path::PathBuf {
    crate::config::state_dir().join("subsbot.offset")
}

fn load_offset() -> i64 {
    std::fs::read_to_string(offset_path())
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn save_offset(v: i64) {
    let _ = crate::config::state_dir_ensure();
    let _ = std::fs::write(offset_path(), v.to_string());
}

/// Итог одного цикла опроса.
pub struct Polled {
    /// Команды поменяли список подписок — вызывающему стоит пересобрать конфиг.
    pub store_changed: bool,
    /// Сколько команд обработали.
    pub handled: usize,
}

fn api_call(token: &str, method: &str, args: &[(&str, &str)]) -> Result<Json, String> {
    let url = format!("{API}/bot{token}/{method}");
    let mut cmd = Command::new("curl");
    cmd.args(["-fsS", "--connect-timeout", "10", "--max-time", "60"]);
    for (k, v) in args {
        cmd.arg("-d").arg(format!("{k}={v}"));
    }
    cmd.arg(url);
    let out = cmd
        .output()
        .map_err(|e| format!("curl не запустился: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{method}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Json::parse(&String::from_utf8_lossy(&out.stdout))
        .map_err(|e| format!("{method}: ответ не JSON: {e}"))
}

fn send(token: &str, chat: i64, text: &str) {
    let _ = api_call(
        token,
        "sendMessage",
        &[
            ("chat_id", &chat.to_string()),
            ("text", text),
            ("disable_web_page_preview", "true"),
        ],
    );
}

/// Один цикл: забрать новые сообщения, выполнить команды из своего чата,
/// ответить. `chat` — единственный чат, чьи команды слушаем.
pub fn poll_once(token: &str, chat: i64) -> Result<Polled, String> {
    let offset = load_offset();
    let resp = api_call(
        token,
        "getUpdates",
        &[
            ("offset", &offset.to_string()),
            ("timeout", "0"),
            ("allowed_updates", "[\"message\"]"),
        ],
    )?;
    let updates = resp
        .get("result")
        .map(|r| r.arr().to_vec())
        .unwrap_or_default();

    let mut store_changed = false;
    let mut handled = 0usize;
    let mut max_id = offset - 1;

    for upd in &updates {
        if let Some(Json::Num(id)) = upd.get("update_id") {
            max_id = max_id.max(*id as i64);
        }
        let Some(msg) = upd.get("message") else {
            continue;
        };
        let from_chat = match msg.get("chat").and_then(|c| c.get("id")) {
            Some(Json::Num(n)) => *n as i64,
            _ => continue,
        };
        let Some(text) = msg.get("text").and_then(|t| t.as_str()) else {
            continue;
        };
        if from_chat != chat {
            // Чужой чат — не отвечаем даже отказом, чтобы бот не отсвечивал.
            continue;
        }
        handled += 1;
        let (reply, changed) = handle(text.trim());
        store_changed |= changed;
        send(token, chat, &reply);
    }

    if max_id >= offset {
        save_offset(max_id + 1);
    }
    Ok(Polled {
        store_changed,
        handled,
    })
}

/// Разобрать команду. Возвращает ответ и признак «список подписок изменился».
fn handle(text: &str) -> (String, bool) {
    let mut parts = text.splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("").trim_start_matches('/');
    let arg = parts.next().unwrap_or("").trim();

    match cmd {
        "add" if !arg.is_empty() => {
            let mut store = Store::load();
            let added = store.add(arg);
            if store.save().is_err() {
                return ("не смог записать список подписок".into(), false);
            }
            if added {
                (
                    format!("добавил: {}\nсобираю ноды…", subs::short(arg)),
                    true,
                )
            } else {
                ("эта ссылка уже в списке".into(), false)
            }
        }
        "rm" | "del" | "forget" if !arg.is_empty() => {
            let mut store = Store::load();
            if store.forget(arg) {
                let _ = store.save();
                (format!("забыл: {}", subs::short(arg)), true)
            } else {
                ("такой ссылки нет — пришли list".into(), false)
            }
        }
        "revive" if !arg.is_empty() => {
            let mut store = Store::load();
            if store.revive(arg) {
                let _ = store.save();
                (
                    format!("вернул из отставки: {}\nсобираю ноды…", subs::short(arg)),
                    true,
                )
            } else {
                ("нет такой отставленной ссылки".into(), false)
            }
        }
        "list" => (list_text(), false),
        "status" => (status_text(), false),
        _ => (
            "команды: add <url> · rm <url> · revive <url> · list · status".into(),
            false,
        ),
    }
}

fn list_text() -> String {
    let store = Store::load();
    if store.subs.is_empty() {
        return "подписок нет".into();
    }
    let mut out = String::new();
    for s in &store.subs {
        let mark = match s.state {
            subs::State::Active => "●",
            subs::State::Retired => "○ (в отставке)",
        };
        out.push_str(&format!(
            "{mark} {} — нод: {}, провалов подряд: {}\n",
            subs::short(&s.url),
            s.last_count,
            s.fail_streak
        ));
    }
    out
}

fn status_text() -> String {
    let store = Store::load();
    let active = store
        .subs
        .iter()
        .filter(|s| s.state == subs::State::Active)
        .count();
    let retired = store.subs.len() - active;
    let bank = crate::sub::load_bank().len();
    let last = crate::sync::days_since_sync()
        .map(|d| format!("{d} дн назад"))
        .unwrap_or_else(|| "ни разу".into());
    format!(
        "подписок активных: {active}, в отставке: {retired}\nв запасе нод: {bank}\nпоследний удачный sync: {last}"
    )
}

/// Токен и chat_id из конфига netpult (`bot_token`, `bot_chat`) или из
/// переменных окружения `NETPULT_BOT_TOKEN` / `NETPULT_BOT_CHAT`.
pub fn creds() -> Option<(String, i64)> {
    let mut token = std::env::var("NETPULT_BOT_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    let mut chat = std::env::var("NETPULT_BOT_CHAT")
        .ok()
        .and_then(|s| s.trim().parse().ok());
    if let Ok(text) = std::fs::read_to_string(crate::config::config_path()) {
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            match k.trim() {
                "bot_token" if token.is_none() && !v.trim().is_empty() => {
                    token = Some(v.trim().to_string())
                }
                "bot_chat" if chat.is_none() => chat = v.trim().parse().ok(),
                _ => {}
            }
        }
    }
    Some((token?, chat?))
}

/// Разослать в чат готовый текст — итог применения новых ссылок.
pub fn notify(token: &str, chat: i64, text: &str) {
    send(token, chat, text);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn незнакомая_команда_подсказывает() {
        let (reply, changed) = handle("привет");
        assert!(reply.contains("add <url>"));
        assert!(!changed);
    }

    #[test]
    fn add_без_аргумента_не_меняет_список() {
        let (_, changed) = handle("add");
        assert!(!changed);
    }
}
