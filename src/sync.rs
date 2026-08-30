//! Обновление нод в чужом конфиге sing-box.
//!
//! На роутере ядро подняли до пульта и вокруг него выросла своя обвязка:
//! редирект из локальной сети, правила маршрутизации, clash API для выбора
//! ноды, сплит по доменам. Класть туда конфиг, собранный пультом с нуля,
//! нельзя — вместе с нодами уедет вся эта обвязка, и роутер останется без
//! интернета. Поэтому подписка сюда приезжает точечно: разобрать чужой
//! конфиг, подменить только ноды и списки выбора, остальное вернуть как было.
//!
//! Порядок действий выбран так, чтобы связь не проседала дольше перезапуска
//! ядра: сначала новый конфиг проверяется `sing-box check` рядом, и только
//! проверенный встаёт на место. Если после перезапуска наружу не достучаться,
//! возвращается прежний конфиг.

use crate::json::Json;
use crate::sub::{self, Node};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Типы outbound, которые считаются нодами и подлежат замене. Всё прочее —
/// `direct`, `block`, `dns`, селекторы — это обвязка, её не трогаем.
const NODE_TYPES: [&str; 8] = [
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "hysteria",
    "hysteria2",
    "tuic",
    "wireguard",
];

fn is_node(outbound: &Json) -> bool {
    outbound
        .get("type")
        .and_then(|t| t.as_str())
        .is_some_and(|t| NODE_TYPES.contains(&t.as_str()))
}

fn tag_of(outbound: &Json) -> Option<String> {
    outbound.get("tag").and_then(|t| t.as_str())
}

/// Адрес и порт ноды — по ним узнаём одну и ту же ноду под разными именами.
fn place_of(outbound: &Json) -> Option<(String, i64)> {
    let server = outbound.get("server")?.as_str()?;
    let port = match outbound.get("server_port")? {
        Json::Num(n) => *n as i64,
        _ => return None,
    };
    Some((server, port))
}

/// Собрать новый конфиг: чужая обвязка + свежие ноды.
///
/// Возвращает текст конфига и число нод. Ничего не пишет и никуда не ходит —
/// чистое преобразование, потому и проверяется тестами.
/// Возвращает текст конфига, сколько всего нод вышло и сколько из них
/// перенесено из прежнего.
///
/// `keep` — теги нод прежнего конфига, которые надо сохранить.
pub fn merge(
    existing: &str,
    nodes: &[Node],
    keep: &[String],
) -> Result<(String, usize, usize), String> {
    if nodes.is_empty() {
        return Err("подписка не дала ни одной ноды — обновлять нечем".into());
    }
    let mut config = Json::parse(existing).map_err(|e| format!("конфиг не разобрать: {e}"))?;
    let old = match config.get("outbounds") {
        Some(Json::Arr(items)) => items.clone(),
        _ => return Err("в конфиге нет списка outbounds".into()),
    };

    // Свежие ноды — на место прежних, обвязка остаётся на своих местах и в
    // прежнем порядке.
    let mut fresh: Vec<Json> = Vec::new();
    for node in nodes {
        let parsed = Json::parse(&node.to_outbound())
            .map_err(|e| format!("нода «{}» не собралась: {e}", node.name))?;
        fresh.push(parsed);
    }
    let new_tags: Vec<String> = fresh.iter().filter_map(tag_of).collect();

    // Прежние ноды — следом за свежими. Отсеиваем только те, что подписка и
    // так вернула: сравниваем по адресу с портом, потому что имя у одной и
    // той же ноды может смениться, а повторять её в списке дважды ни к чему.
    //
    // Отпавшие не выбрасываем намеренно. Нода молчит сегодня и отвечает
    // завтра — провайдеры их поднимают обратно, а `urltest` мёртвую всё равно
    // не выберет, так что висеть она никому не мешает.
    let fresh_places: Vec<(String, i64)> = fresh.iter().filter_map(place_of).collect();
    let kept: Vec<Json> = old
        .iter()
        .filter(|o| is_node(o))
        .filter(|o| tag_of(o).is_some_and(|t| keep.contains(&t)))
        .filter(|o| tag_of(o).is_some_and(|t| !new_tags.contains(&t)))
        .filter(|o| place_of(o).is_none_or(|p| !fresh_places.contains(&p)))
        .cloned()
        .collect();
    let kept_tags: Vec<String> = kept.iter().filter_map(tag_of).collect();

    let mut out: Vec<Json> = Vec::new();
    let mut put_nodes = false;
    for item in &old {
        if is_node(item) {
            // Ноды кладём одной пачкой на место первой прежней.
            if !put_nodes {
                out.extend(fresh.iter().cloned());
                out.extend(kept.iter().cloned());
                put_nodes = true;
            }
            continue;
        }
        out.push(item.clone());
    }
    if !put_nodes {
        out.extend(fresh.iter().cloned());
        out.extend(kept.iter().cloned());
    }

    // Списки выбора: подставляем новые имена, а всё, что не было нодой
    // (`direct`, вложенный `auto`), оставляем на месте.
    let old_tags: Vec<String> = old.iter().filter(|o| is_node(o)).filter_map(tag_of).collect();
    for item in out.iter_mut() {
        let kind = item.get("type").and_then(|t| t.as_str()).unwrap_or_default();
        if kind != "selector" && kind != "urltest" {
            continue;
        }
        let Some(Json::Arr(list)) = item.get("outbounds") else {
            continue;
        };
        let survivors: Vec<Json> = list
            .iter()
            .filter(|entry| {
                entry
                    .as_str()
                    .is_some_and(|name| !old_tags.contains(&name))
            })
            .cloned()
            .collect();
        let mut updated: Vec<Json> = new_tags
            .iter()
            .chain(kept_tags.iter())
            .map(|t| Json::Str(t.clone()))
            .collect();
        updated.extend(survivors);
        item.set("outbounds", Json::Arr(updated));

        // Умолчание могло указывать на ноду, которой больше нет.
        if let Some(default) = item.get("default").and_then(|d| d.as_str())
            && !new_tags.contains(&default)
            && !kept_tags.contains(&default)
            && !matches!(item.get("outbounds"), Some(Json::Arr(l)) if l.iter().any(|e| e.as_str().as_deref() == Some(default.as_str())))
        {
            item.set("default", Json::Str(new_tags[0].clone()));
        }
    }

    config.set("outbounds", Json::Arr(out));
    Ok((config.to_text(), nodes.len() + kept.len(), kept.len()))
}

/// Куда и чем обновлять.
pub struct Plan {
    /// Конфиг ядра, который правим.
    pub config: PathBuf,
    /// Бинарь sing-box — им же и проверяем конфиг перед заменой.
    pub binary: PathBuf,
    /// Чем перезапустить ядро после замены.
    pub restart: Vec<String>,
    /// Через что проверить, что связь жива: адрес прокси ядра.
    pub probe_proxy: String,
    /// Оставлять ли в конфиге прежние ноды. Молчащие тоже остаются: они
    /// оживают, а `urltest` мёртвую не выберет.
    pub keep_alive: bool,
    /// Только собрать и проверить рядом, ничего не заменяя. Нужен, чтобы
    /// убедиться в правке до того, как она коснётся живого роутера.
    pub dry_run: bool,
}

impl Default for Plan {
    fn default() -> Self {
        Plan {
            config: PathBuf::from("/etc/sing-box/config.json"),
            binary: PathBuf::from("/usr/bin/sing-box"),
            restart: vec!["/etc/init.d/sing-box".into(), "restart".into()],
            probe_proxy: "socks5h://127.0.0.1:1180".into(),
            keep_alive: true,
            dry_run: false,
        }
    }
}

/// Итог обновления — то, что уходит в журнал и на экран.
pub struct Report {
    /// Всего нод в новом конфиге: свежие плюс перенесённые живые.
    pub nodes: usize,
    /// Сколько прежних нод пережило обновление.
    pub kept: usize,
    pub backup: PathBuf,
    pub rolled_back: bool,
    pub note: String,
}

/// Забрать подписку и обновить ноды на месте.
pub fn run(plan: &Plan) -> Result<Report, String> {
    let url = sub::saved_url()?;
    let nodes = sub::fetch(&url, Duration::from_secs(45))?;
    let existing = std::fs::read_to_string(&plan.config)
        .map_err(|e| format!("не прочитать {}: {e}", plan.config.display()))?;
    let previous = if plan.keep_alive { previous_tags(&existing) } else { Vec::new() };
    let (merged, count, kept) = merge(&existing, &nodes, &previous)?;

    // Проверяем рядом, а не на месте: битый конфиг не должен даже на секунду
    // оказаться тем, с чем ядро попробует подняться.
    let candidate = plan.config.with_extension("json.new");
    std::fs::write(&candidate, &merged).map_err(|e| format!("не записать проверяемый конфиг: {e}"))?;
    if let Err(e) = check(&plan.binary, &candidate) {
        let _ = std::fs::remove_file(&candidate);
        return Err(e);
    }
    if plan.dry_run {
        return Ok(Report {
            nodes: count,
            kept,
            backup: candidate,
            rolled_back: false,
            note: "холостой прогон: конфиг собран и проверен, ничего не заменено".into(),
        });
    }

    let backup = backup_path(&plan.config);
    std::fs::copy(&plan.config, &backup).map_err(|e| format!("не сделать бэкап: {e}"))?;
    std::fs::rename(&candidate, &plan.config).map_err(|e| format!("не заменить конфиг: {e}"))?;

    restart(&plan.restart)?;
    if alive(&plan.probe_proxy) {
        return Ok(Report {
            nodes: count,
            kept,
            backup,
            rolled_back: false,
            note: "ноды обновлены".into(),
        });
    }

    // Наружу не достучались — возвращаем прежний конфиг и поднимаем ядро
    // обратно. Лучше вчерашние ноды, чем никаких.
    std::fs::copy(&backup, &plan.config).map_err(|e| format!("откат не удался: {e}"))?;
    restart(&plan.restart)?;
    Ok(Report {
        nodes: count,
        kept,
        backup,
        rolled_back: true,
        note: "после обновления связи не было — вернул прежний конфиг".into(),
    })
}

/// Теги всех нод, которые уже есть в конфиге.
///
/// Живость нарочно не проверяется. Раньше тут был прозвон через clash API, и
/// молчащие ноды отбрасывались — но нода, молчащая сегодня, назавтра обычно
/// оживает, а прозвон двух десятков нод занимал больше минуты на каждом
/// запуске.
fn previous_tags(existing: &str) -> Vec<String> {
    let Ok(config) = Json::parse(existing) else {
        return Vec::new();
    };
    let Some(Json::Arr(items)) = config.get("outbounds") else {
        return Vec::new();
    };
    items
        .iter()
        .filter(|o| is_node(o))
        .filter_map(tag_of)
        .collect()
}

fn check(binary: &Path, config: &Path) -> Result<(), String> {
    let out = Command::new(binary)
        .arg("check")
        .arg("-c")
        .arg(config)
        .output()
        .map_err(|e| format!("не запустить {}: {e}", binary.display()))?;
    if out.status.success() {
        return Ok(());
    }
    let why = String::from_utf8_lossy(&out.stderr);
    Err(format!(
        "sing-box забраковал новый конфиг, ничего не меняю: {}",
        why.trim()
    ))
}

fn restart(command: &[String]) -> Result<(), String> {
    let Some((program, args)) = command.split_first() else {
        return Err("нечем перезапускать ядро".into());
    };
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| format!("не запустить {program}: {e}"))?;
    if !status.success() {
        return Err(format!("{program} вернул {status}"));
    }
    // Ядру нужно мгновение, чтобы поднять слушателей и соединиться с нодой.
    std::thread::sleep(Duration::from_secs(3));
    Ok(())
}

/// Жива ли связь через ядро. Адрес лёгкий и отвечает пустым телом.
fn alive(proxy: &str) -> bool {
    for _ in 0..3 {
        let out = Command::new("curl")
            .args(["-s", "-o", "/dev/null", "-x", proxy, "--max-time", "10", "-w", "%{http_code}"])
            .arg("https://www.gstatic.com/generate_204")
            .output();
        if let Ok(out) = out
            && out.status.success()
            && String::from_utf8_lossy(&out.stdout).trim().starts_with('2')
        {
            return true;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    false
}

fn backup_path(config: &Path) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    config.with_extension(format!("json.bak-{stamp}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub::{Kind, Transport};

    fn нода(name: &str, server: &str) -> Node {
        Node {
            name: name.to_string(),
            kind: Kind::Vless,
            server: server.to_string(),
            port: 443,
            secret: "11111111-2222-3333-4444-555555555555".into(),
            method: None,
            flow: None,
            tls: true,
            sni: Some(server.to_string()),
            alpn: Vec::new(),
            fingerprint: None,
            insecure: false,
            reality_key: None,
            reality_short_id: None,
            transport: Transport::Tcp,
        }
    }

    const РОУТЕР: &str = r#"{
      "log": {"level": "warn"},
      "inbounds": [{"type": "redirect", "tag": "redir", "listen": "::", "listen_port": 1179}],
      "route": {"rules": [{"inbound": "redir", "outbound": "proxy"}], "final": "proxy"},
      "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
      "outbounds": [
        {"type": "vless", "tag": "Старая-1", "server": "a.example", "server_port": 443, "uuid": "u"},
        {"type": "vless", "tag": "Старая-2", "server": "b.example", "server_port": 443, "uuid": "u"},
        {"type": "selector", "tag": "proxy", "outbounds": ["auto", "Старая-1", "Старая-2"], "default": "auto"},
        {"type": "urltest", "tag": "auto", "outbounds": ["Старая-1", "Старая-2"]},
        {"type": "direct", "tag": "direct"}
      ]
    }"#;

    #[test]
    fn обвязка_роутера_переживает_обновление() {
        let (text, count, _) = merge(РОУТЕР, &[нода("Новая-1", "c.example")], &[]).unwrap();
        assert_eq!(count, 1);
        let c = Json::parse(&text).unwrap();
        // Всё, что не ноды, осталось на месте — иначе роутер потеряет интернет.
        assert!(c.get("route").is_some(), "маршрутизация потерялась");
        assert!(c.get("inbounds").is_some(), "входы потерялись");
        assert!(c.get("experimental").is_some(), "clash API потерялся");
        assert_eq!(
            c.get("log").and_then(|l| l.get("level")).and_then(|v| v.as_str()),
            Some("warn".to_string())
        );
    }

    #[test]
    fn старые_ноды_уходят_новые_приходят() {
        let (text, _, _) = merge(РОУТЕР, &[нода("Новая-1", "c.example"), нода("Новая-2", "d.example")], &[]).unwrap();
        let c = Json::parse(&text).unwrap();
        let tags: Vec<String> = c
            .get("outbounds")
            .map(|o| o.arr().iter().filter_map(tag_of).collect())
            .unwrap_or_default();
        assert!(tags.contains(&"Новая-1".to_string()));
        assert!(!tags.iter().any(|t| t.starts_with("Старая")), "старые ноды остались: {tags:?}");
        assert!(tags.contains(&"direct".to_string()), "direct не должен пропадать");
    }

    #[test]
    fn списки_выбора_показывают_новые_ноды_и_хранят_прочее() {
        let (text, _, _) = merge(РОУТЕР, &[нода("Новая-1", "c.example")], &[]).unwrap();
        let c = Json::parse(&text).unwrap();
        let selector = c
            .get("outbounds")
            .unwrap()
            .arr()
            .iter()
            .find(|o| tag_of(o).as_deref() == Some("proxy"))
            .cloned()
            .unwrap();
        let list: Vec<String> = selector
            .get("outbounds")
            .map(|o| o.arr().iter().filter_map(|e| e.as_str()).collect())
            .unwrap_or_default();
        assert!(list.contains(&"Новая-1".to_string()));
        assert!(list.contains(&"auto".to_string()), "вложенный auto потерялся");
        assert!(!list.iter().any(|t| t.starts_with("Старая")));
    }

    #[test]
    fn умолчание_не_остаётся_на_исчезнувшей_ноде() {
        // Тут умолчание указывает прямо на ноду, а не на auto.
        let config = РОУТЕР.replace("\"default\": \"auto\"", "\"default\": \"Старая-1\"");
        let (text, _, _) = merge(&config, &[нода("Новая-1", "c.example")], &[]).unwrap();
        let c = Json::parse(&text).unwrap();
        let selector = c
            .get("outbounds")
            .unwrap()
            .arr()
            .iter()
            .find(|o| tag_of(o).as_deref() == Some("proxy"))
            .cloned()
            .unwrap();
        assert_eq!(
            selector.get("default").and_then(|d| d.as_str()),
            Some("Новая-1".to_string())
        );
    }


    #[test]
    fn прежняя_нода_остаётся_рядом_со_свежими() {
        let keep = vec!["Старая-2".to_string()];
        let (text, count, kept_count) = merge(РОУТЕР, &[нода("Новая-1", "c.example")], &keep).unwrap();
        assert_eq!(count, 2, "считаем и свежие, и перенесённые");
        assert_eq!(kept_count, 1, "перенесённой числится ровно одна");
        let c = Json::parse(&text).unwrap();
        let tags: Vec<String> = c
            .get("outbounds")
            .map(|o| o.arr().iter().filter_map(tag_of).collect())
            .unwrap_or_default();
        assert!(tags.contains(&"Новая-1".to_string()));
        assert!(tags.contains(&"Старая-2".to_string()), "живую не перенесли: {tags:?}");
        assert!(!tags.contains(&"Старая-1".to_string()), "мёртвую тащить не надо");
        // И в списке выбора она тоже должна быть, иначе толку от неё нет.
        let selector = c
            .get("outbounds")
            .unwrap()
            .arr()
            .iter()
            .find(|o| tag_of(o).as_deref() == Some("proxy"))
            .cloned()
            .unwrap();
        let list: Vec<String> = selector
            .get("outbounds")
            .map(|o| o.arr().iter().filter_map(|e| e.as_str()).collect())
            .unwrap_or_default();
        assert!(list.contains(&"Старая-2".to_string()));
    }


    #[test]
    fn отпавшие_ноды_не_выбрасываются() {
        // Живость не проверяем намеренно: молчащая нода назавтра оживает, а
        // urltest мёртвую всё равно не выберет.
        let keep = vec!["Старая-1".to_string(), "Старая-2".to_string()];
        let (text, count, kept_count) =
            merge(РОУТЕР, &[нода("Новая-1", "c.example")], &keep).unwrap();
        assert_eq!(count, 3);
        assert_eq!(kept_count, 2);
        let c = Json::parse(&text).unwrap();
        let tags: Vec<String> = c
            .get("outbounds")
            .map(|o| o.arr().iter().filter_map(tag_of).collect())
            .unwrap_or_default();
        for t in ["Новая-1", "Старая-1", "Старая-2"] {
            assert!(tags.contains(&t.to_string()), "потеряли {t}: {tags:?}");
        }
    }

    #[test]
    fn та_же_нода_под_новым_именем_не_двоится() {
        // Подписка вернула ту же машину, но назвала иначе. Старую переносить
        // не надо — иначе в списке две записи на один сервер.
        let keep = vec!["Старая-1".to_string()];
        let (text, count, kept_count) = merge(РОУТЕР, &[нода("Новое имя", "a.example")], &keep).unwrap();
        assert_eq!(count, 1);
        assert_eq!(kept_count, 0, "дубль по адресу переносить не надо");
        let c = Json::parse(&text).unwrap();
        let tags: Vec<String> = c
            .get("outbounds")
            .map(|o| o.arr().iter().filter_map(tag_of).collect())
            .unwrap_or_default();
        assert!(tags.contains(&"Новое имя".to_string()));
        assert!(!tags.contains(&"Старая-1".to_string()), "дубль по адресу: {tags:?}");
    }

    #[test]
    fn пустая_подписка_ничего_не_ломает() {
        assert!(merge(РОУТЕР, &[], &[]).is_err());
    }
}
