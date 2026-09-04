//! Запасной канал управления подписками: запечатанный манифест на публичном
//! хосте.
//!
//! Основной путь — бот (см. [`crate::subsbot`]): написал в чат, роутер на
//! следующем опросе подхватил. Но у провайдера родителей Telegram может быть
//! под блокировкой, и когда вдобавок легли все ноды, до бота не достучаться
//! ничем. Тогда работает это: роутер раз в несколько минут тянет один и тот
//! же URL (гист, pastebin, свой VPS), где лежит запечатанный [`crate::seal`]
//! блоб. Хозяин правит этот блоб с телефона командой `net vpn subs seal`.
//!
//! Формат распечатанного payload — рукописный JSON:
//! `{"seq": <число>, "add": [ссылки], "remove": [ссылки]}`.
//! `seq` строго возрастает (берём время эпохи): манифест со `seq` не больше
//! уже виденного игнорируется — это защита от повторного применения старого.

use crate::json::Json;
use crate::seal;
use crate::subs::Store;

/// Что манифест поменял в списке подписок.
#[derive(Debug, Default)]
pub struct Applied {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// Манифест был не новее виденного — ничего не делали.
    pub stale: bool,
}

impl Applied {
    pub fn changed(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty()
    }
}

/// Собрать payload и запечатать. `add`/`remove` — списки ссылок; `seq` обычно
/// время эпохи на момент сборки.
pub fn pack(secret: &[u8], seq: u64, add: &[String], remove: &[String]) -> String {
    let list = |items: &[String]| {
        items
            .iter()
            .map(|s| crate::json::escape(s))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let payload = format!(
        "{{\"seq\": {seq}, \"add\": [{}], \"remove\": [{}]}}",
        list(add),
        list(remove)
    );
    seal::seal(secret, payload.as_bytes())
}

/// Распечатать и разобрать. Возвращает `(seq, add, remove)`.
pub fn unpack(secret: &[u8], blob: &str) -> Result<(u64, Vec<String>, Vec<String>), String> {
    let plain = seal::open(secret, blob)?;
    let text = String::from_utf8(plain).map_err(|_| "манифест: payload не UTF-8")?;
    let root = Json::parse(&text).map_err(|e| format!("манифест: payload не JSON: {e}"))?;
    let seq = match root.get("seq") {
        Some(Json::Num(n)) => *n as u64,
        _ => return Err("манифест: нет поля seq".into()),
    };
    let urls = |key: &str| -> Vec<String> {
        root.get(key)
            .map(|v| {
                v.arr()
                    .iter()
                    .filter_map(|e| e.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok((seq, urls("add"), urls("remove")))
}

/// Скачать манифест по URL, распечатать, применить к списку подписок.
///
/// Ничего не пересобирает — если [`Applied::changed`], вызывающий сам зовёт
/// [`crate::subs::refresh`], чтобы новые ссылки сразу дали ноды.
pub fn poll(url: &str, secret: &[u8]) -> Result<Applied, String> {
    let out = std::process::Command::new("curl")
        .args([
            "-fsSL",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            "-A",
            "netpult",
            url,
        ])
        .output()
        .map_err(|e| format!("curl не запустился: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "манифест не скачался: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let blob = String::from_utf8_lossy(&out.stdout).to_string();
    apply(&blob, secret)
}

/// Применить уже скачанный блоб (отдельно от сети — так проверяется тестами).
pub fn apply(blob: &str, secret: &[u8]) -> Result<Applied, String> {
    let (seq, add, remove) = unpack(secret, blob)?;
    let mut store = Store::load();
    if seq <= store.manifest_seq {
        return Ok(Applied {
            stale: true,
            ..Default::default()
        });
    }

    let mut applied = Applied::default();
    for url in &add {
        if store.add(url) {
            applied.added.push(url.clone());
        }
    }
    for url in &remove {
        if store.forget(url) {
            applied.removed.push(url.clone());
        }
    }
    store.manifest_seq = seq;
    store.save()?;
    Ok(applied)
}

/// Секрет для печати/распечатывания: сначала `--key`, потом переменная
/// окружения `NETPULT_SUB_KEY`, потом `sub_hmac_key` из конфига netpult.
/// Строка берётся как есть (в байтах UTF-8) — так же, как её задаёт kit.conf.
pub fn secret(explicit: Option<&str>) -> Result<Vec<u8>, String> {
    if let Some(k) = explicit.filter(|s| !s.is_empty()) {
        return Ok(k.as_bytes().to_vec());
    }
    if let Ok(k) = std::env::var("NETPULT_SUB_KEY")
        && !k.is_empty()
    {
        return Ok(k.into_bytes());
    }
    if let Ok(text) = std::fs::read_to_string(crate::config::config_path()) {
        for line in text.lines() {
            if let Some((k, v)) = line.split_once('=')
                && k.trim() == "sub_hmac_key"
                && !v.trim().is_empty()
            {
                return Ok(v.trim().as_bytes().to_vec());
            }
        }
    }
    Err("нет ключа: задай --key, переменную NETPULT_SUB_KEY или sub_hmac_key в конфиге".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_кругооборот() {
        let key = b"secret";
        let add = vec!["https://a.example/x".to_string(), "vless://b".to_string()];
        let remove = vec!["https://old.example".to_string()];
        let blob = pack(key, 100, &add, &remove);
        let (seq, a, r) = unpack(key, &blob).unwrap();
        assert_eq!(seq, 100);
        assert_eq!(a, add);
        assert_eq!(r, remove);
    }

    #[test]
    fn чужой_ключ_манифест_не_вскроет() {
        let blob = pack(b"one", 1, &["https://a".to_string()], &[]);
        assert!(unpack(b"two", &blob).is_err());
    }

    #[test]
    fn пустые_списки_разбираются() {
        let blob = pack(b"k", 5, &[], &[]);
        let (seq, a, r) = unpack(b"k", &blob).unwrap();
        assert_eq!(seq, 5);
        assert!(a.is_empty() && r.is_empty());
    }
}
