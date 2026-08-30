//! Что пульт знает про сети, в которых бывал.
//!
//! Одна вещь про сеть важнее прочих: чинит ли что-то блокировки **выше**
//! пульта — роутер, провайдер, чужой VPN. Дома чинит роутер, и свой zapret
//! не нужен; в кафе не чинит никто, и без своего обхода сидеть не на чем.
//!
//! Беда в том, что при включённом своём обходе это не проверить: он чинит всё
//! сам, и снаружи обе сети выглядят одинаково. Поэтому вердикт записывается
//! тогда, когда его удалось получить честно, и потом показывается вместе с
//! датой — устаревшему верить нельзя, роутер мог сломаться со вчера.

use crate::config::state_dir;
use std::collections::BTreeMap;

/// Что видели в этой сети и когда.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Seen {
    /// Открывалось ли заблокированное без всякого пульта.
    pub upstream: bool,
    /// Время проверки, unix-секунды.
    pub checked: u64,
}

/// После какого срока вердикт считается устаревшим. Неделя: роутер за неделю
/// успевает и сломаться, и починиться, а провайдер — сменить фильтрацию.
pub const УСТАРЕЛ: u64 = 7 * 86_400;

impl Seen {
    pub fn устарел(&self) -> bool {
        crate::sub::now_secs().saturating_sub(self.checked) > УСТАРЕЛ
    }
}

fn path() -> std::path::PathBuf {
    state_dir().join("networks")
}

pub fn load() -> BTreeMap<String, Seen> {
    let mut out = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(path()) else {
        return out;
    };
    let mut name: Option<String> = None;
    let mut seen = Seen { upstream: false, checked: 0 };
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("сеть ") {
            if let Some(previous) = name.take() {
                out.insert(previous, seen);
            }
            name = Some(rest.trim().to_string());
            seen = Seen { upstream: false, checked: 0 };
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "upstream" => seen.upstream = value.trim() == "on",
            "checked" => seen.checked = value.trim().parse().unwrap_or(0),
            _ => {}
        }
    }
    if let Some(previous) = name {
        out.insert(previous, seen);
    }
    out
}

fn save_all(all: &BTreeMap<String, Seen>) -> Result<(), String> {
    std::fs::create_dir_all(state_dir()).map_err(|e| e.to_string())?;
    let mut text =
        String::from("# Что пульт видел в этих сетях: чинит ли блокировки что-то выше него.\n\n");
    for (name, seen) in all {
        text.push_str(&format!("сеть {name}\n"));
        text.push_str(&format!("upstream = {}\n", if seen.upstream { "on" } else { "off" }));
        text.push_str(&format!("checked = {}\n\n", seen.checked));
    }
    std::fs::write(path(), text).map_err(|e| e.to_string())
}

/// Записать вердикт про текущую сеть. Молча ничего не делает, если сеть не
/// опознана: писать вердикт непонятно про что — хуже, чем не писать.
pub fn remember(network: Option<&str>, upstream: bool) {
    let Some(network) = network else { return };
    let mut all = load();
    all.insert(
        network.to_string(),
        Seen { upstream, checked: crate::sub::now_secs() },
    );
    let _ = save_all(&all);
}

pub fn known(network: Option<&str>) -> Option<Seen> {
    load().get(network?).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn разбор_записи() {
        let text = "# заметка\n\nсеть kv_52\nupstream = on\nchecked = 1788000000\n\nсеть шлюз 10.0.0.1\nupstream = off\nchecked = 1788000100\n";
        // Разбор проверяем на той же логике, что и чтение файла.
        let mut out = BTreeMap::new();
        let mut name: Option<String> = None;
        let mut seen = Seen { upstream: false, checked: 0 };
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("сеть ") {
                if let Some(p) = name.take() {
                    out.insert(p, seen);
                }
                name = Some(rest.trim().to_string());
                seen = Seen { upstream: false, checked: 0 };
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                match k.trim() {
                    "upstream" => seen.upstream = v.trim() == "on",
                    "checked" => seen.checked = v.trim().parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        if let Some(p) = name {
            out.insert(p, seen);
        }
        assert_eq!(out.len(), 2);
        assert!(out["kv_52"].upstream);
        assert!(!out["шлюз 10.0.0.1"].upstream);
        assert_eq!(out["kv_52"].checked, 1_788_000_000);
    }

    #[test]
    fn безымянная_сеть_не_запоминается() {
        // Вызов с None не должен ни падать, ни писать файл.
        remember(None, true);
        assert_eq!(known(None), None);
    }
}
