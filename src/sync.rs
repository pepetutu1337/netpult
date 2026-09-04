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

/// Один ли и тот же набор нод (порядок неважен, все поля важны).
fn same_nodes(a: &[Node], b: &[Node]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut a: Vec<&Node> = a.iter().collect();
    let mut b: Vec<&Node> = b.iter().collect();
    let key = |n: &&Node| (n.server.clone(), n.port);
    a.sort_by_key(key);
    b.sort_by_key(key);
    a == b
}

/// Собрать новый конфиг: чужая обвязка + готовый список нод.
///
/// `nodes` — уже сведённый активный список (см. [`sub::reconcile`]): что
/// подписка отдала, что перенесли живым, что подняли из запаса. Здесь только
/// подстановка: все прежние ноды-outbound'ы заменяются на `nodes`, обвязка
/// (`direct`, `route`, `inbounds`, селекторы) остаётся на своих местах,
/// списки выбора и `default` переписываются на новые имена.
///
/// Возвращает текст конфига и число нод. Ничего не пишет и никуда не ходит.
pub fn merge(existing: &str, nodes: &[Node]) -> Result<(String, usize), String> {
    if nodes.is_empty() {
        return Err("список нод пуст — обновлять нечем".into());
    }
    let mut config = Json::parse(existing).map_err(|e| format!("конфиг не разобрать: {e}"))?;
    let old = match config.get("outbounds") {
        Some(Json::Arr(items)) => items.clone(),
        _ => return Err("в конфиге нет списка outbounds".into()),
    };

    let mut fresh: Vec<Json> = Vec::new();
    for node in nodes {
        let parsed = Json::parse(&node.to_outbound())
            .map_err(|e| format!("нода «{}» не собралась: {e}", node.name))?;
        fresh.push(parsed);
    }
    let new_tags: Vec<String> = fresh.iter().filter_map(tag_of).collect();

    // Ноды кладём одной пачкой на место первой прежней, обвязку — как была.
    let mut out: Vec<Json> = Vec::new();
    let mut put_nodes = false;
    for item in &old {
        if is_node(item) {
            if !put_nodes {
                out.extend(fresh.iter().cloned());
                put_nodes = true;
            }
            continue;
        }
        out.push(item.clone());
    }
    if !put_nodes {
        out.extend(fresh.iter().cloned());
    }

    // Списки выбора: подставляем новые имена, а всё, что не было нодой
    // (`direct`, вложенный `auto`), оставляем на месте.
    let old_tags: Vec<String> = old
        .iter()
        .filter(|o| is_node(o))
        .filter_map(tag_of)
        .collect();
    for item in out.iter_mut() {
        let kind = item
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or_default();
        if kind != "selector" && kind != "urltest" {
            continue;
        }
        let Some(Json::Arr(list)) = item.get("outbounds") else {
            continue;
        };
        let survivors: Vec<Json> = list
            .iter()
            .filter(|entry| entry.as_str().is_some_and(|name| !old_tags.contains(&name)))
            .cloned()
            .collect();
        let mut updated: Vec<Json> = new_tags.iter().map(|t| Json::Str(t.clone())).collect();
        updated.extend(survivors);
        item.set("outbounds", Json::Arr(updated));

        // Умолчание могло указывать на ноду, которой больше нет.
        if let Some(default) = item.get("default").and_then(|d| d.as_str())
            && !new_tags.contains(&default)
            && !matches!(item.get("outbounds"), Some(Json::Arr(l)) if l.iter().any(|e| e.as_str().as_deref() == Some(default.as_str())))
        {
            item.set("default", Json::Str(new_tags[0].clone()));
        }
    }

    config.set("outbounds", Json::Arr(out));
    Ok((config.to_text(), nodes.len()))
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
    /// Сводить ли свежие ноды с прежними и запасом (см. [`sub::reconcile`]):
    /// выпавшие из подписки пробуются, живые остаются, молчащие уходят в
    /// запас, из запаса живые поднимаются. `false` — только то, что отдала
    /// подписка сейчас.
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
    /// Всего нод в новом конфиге.
    pub nodes: usize,
    /// Из них перенесено живыми, хотя подписка их больше не отдаёт.
    pub carried: usize,
    /// Из них поднято обратно из запаса.
    pub revived: usize,
    /// Ушло в запас как молчащие.
    pub parked: usize,
    pub backup: PathBuf,
    pub rolled_back: bool,
    pub note: String,
}

/// Забрать подписку и обновить ноды на месте.
/// `phase` вызывается перед каждым отрезком работы. Обновление идёт под
/// минуту — скачивание подписки, проверка конфига, перезапуск ядра, проба
/// наружу, — и без отметок непонятно, на чём оно стоит: на медленной сети
/// или на упавшем ядре.
pub fn run(plan: &Plan, phase: &mut dyn FnMut(&str)) -> Result<Report, String> {
    phase("забираю подписки");
    let (fresh, fetched, store) = crate::subs::fetch_all();
    if fetched.is_empty() {
        return Err("нет активных подписок — net vpn subs add <ссылка>".into());
    }

    phase("собираю конфиг");
    let existing = std::fs::read_to_string(&plan.config)
        .map_err(|e| format!("не прочитать {}: {e}", plan.config.display()))?;

    // «Что было в работе» берём из самого чужого конфига: его ноды-outbound'ы
    // тем же разбором, что и подписку.
    let prev_active = if plan.keep_alive {
        sub::parse(&existing).unwrap_or_default()
    } else {
        Vec::new()
    };
    let bank = if plan.keep_alive {
        sub::load_bank()
    } else {
        Vec::new()
    };
    let rec = sub::reconcile(&fresh, &prev_active, bank, Duration::from_secs(3));
    if rec.active.is_empty() {
        // Ни свежих, ни живых прежних, ни поднятых из запаса. Чужой конфиг не
        // трогаем — вчерашние ноды лучше пустого, — но счётчики подписок уже
        // посчитаны, сохраняем их и пишем в журнал.
        let _ = store.save();
        let _ = crate::subs::write_log(&rec, &fetched, true);
        return Err(
            "ни одной живой ноды: ни в подписках, ни в запасе — конфиг оставлен прежним".into(),
        );
    }
    // Набор нод не изменился — конфиг не трогаем и ядро не перезапускаем
    // (иначе суточный крон роняет связь каждый день на ровном месте).
    // Сравниваем сами ноды со всеми полями: сменил провайдер ключи на том же
    // адресе — это изменение, перетряхнуть надо. Обвязку не сравниваем: её
    // sync и так не меняет. Состояние подписок и запаса закрепляем всегда.
    if same_nodes(&prev_active, &rec.active) {
        persist(&rec, &store, &fetched);
        return Ok(Report {
            nodes: rec.active.len(),
            carried: rec.carried.len(),
            revived: rec.revived.len(),
            parked: rec.parked.len(),
            backup: plan.config.clone(),
            rolled_back: false,
            note: "ноды не менялись".into(),
        });
    }

    let (merged, count) = merge(&existing, &rec.active)?;
    let carried = rec.carried.len();
    let revived = rec.revived.len();
    let parked = rec.parked.len();

    // Проверяем рядом, а не на месте: битый конфиг не должен даже на секунду
    // оказаться тем, с чем ядро попробует подняться.
    let candidate = plan.config.with_extension("json.new");
    std::fs::write(&candidate, &merged)
        .map_err(|e| format!("не записать проверяемый конфиг: {e}"))?;
    phase("проверяю конфиг ядром");
    if let Err(e) = check(&plan.binary, &candidate) {
        let _ = std::fs::remove_file(&candidate);
        return Err(e);
    }
    if plan.dry_run {
        return Ok(Report {
            nodes: count,
            carried,
            revived,
            parked,
            backup: candidate,
            rolled_back: false,
            note: "холостой прогон: конфиг собран и проверен, ничего не заменено".into(),
        });
    }

    // Проверка прошла — состояние подписок и запаса можно закреплять: свежий
    // конфиг ниже либо встанет, либо откатится, но счётчики провалов, отставка
    // и живость нод от этого не меняются.
    persist(&rec, &store, &fetched);

    let backup = backup_path(&plan.config);
    std::fs::copy(&plan.config, &backup).map_err(|e| format!("не сделать бэкап: {e}"))?;
    std::fs::rename(&candidate, &plan.config).map_err(|e| format!("не заменить конфиг: {e}"))?;

    phase("перезапускаю ядро");
    restart(&plan.restart)?;
    phase("проверяю связь наружу");
    if alive(&plan.probe_proxy) {
        stamp_success();
        return Ok(Report {
            nodes: count,
            carried,
            revived,
            parked,
            backup,
            rolled_back: false,
            note: "ноды обновлены".into(),
        });
    }

    // Наружу не достучались — возвращаем прежний конфиг и поднимаем ядро
    // обратно. Лучше вчерашние ноды, чем никаких.
    phase("связи нет — откатываюсь");
    std::fs::copy(&backup, &plan.config).map_err(|e| format!("откат не удался: {e}"))?;
    restart(&plan.restart)?;
    Ok(Report {
        nodes: count,
        carried,
        revived,
        parked,
        backup,
        rolled_back: true,
        note: "после обновления связи не было — вернул прежний конфиг".into(),
    })
}

/// Записать на диск то, что насчитал [`sub::reconcile`]: запас с обновлёнными
/// отметками отклика и состояние подписок; строку в журнал обновлений.
fn persist(rec: &sub::Reconciled, store: &crate::subs::Store, fetched: &[crate::subs::Fetched]) {
    let mut bank = rec.bank.clone();
    sub::add_missing(&mut bank, &rec.active);
    let live: Vec<String> = rec.active.iter().map(sub::place).collect();
    let now = sub::now_secs();
    for kept in bank.iter_mut() {
        if live.contains(&sub::place(&kept.node)) {
            kept.last_ok = Some(now);
        }
    }
    let _ = sub::save_bank(&bank);
    let _ = store.save();
    let _ = crate::subs::write_log(rec, fetched, false);
}

/// Отметка последнего удачного обновления нод.
///
/// Молчащая подписка — самый тихий способ однажды остаться без интернета.
/// Ноды в конфиге живут дальше и работают, пока провайдер не сменит им ключи
/// при очередной ротации, и тогда умирают все разом. Между «подписка перестала
/// отвечать» и «ничего не работает» проходят недели, и всё это время ошибка
/// видна только в выводе команды, которую в это время никто не запускает.
pub fn stamp_path() -> PathBuf {
    crate::config::state_dir().join("sync.stamp")
}

fn stamp_success() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = std::fs::create_dir_all(crate::config::state_dir());
    let _ = std::fs::write(stamp_path(), now.to_string());
}

/// Сколько суток назад ноды обновлялись удачно. `None` — ни разу.
pub fn days_since_sync() -> Option<u64> {
    let text = std::fs::read_to_string(stamp_path()).ok()?;
    let then: u64 = text.trim().parse().ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(now.saturating_sub(then) / 86_400)
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
            .args([
                "-s",
                "-o",
                "/dev/null",
                "-x",
                proxy,
                "--max-time",
                "10",
                "-w",
                "%{http_code}",
            ])
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
        let (text, count) = merge(РОУТЕР, &[нода("Новая-1", "c.example")]).unwrap();
        assert_eq!(count, 1);
        let c = Json::parse(&text).unwrap();
        // Всё, что не ноды, осталось на месте — иначе роутер потеряет интернет.
        assert!(c.get("route").is_some(), "маршрутизация потерялась");
        assert!(c.get("inbounds").is_some(), "входы потерялись");
        assert!(c.get("experimental").is_some(), "clash API потерялся");
        assert_eq!(
            c.get("log")
                .and_then(|l| l.get("level"))
                .and_then(|v| v.as_str()),
            Some("warn".to_string())
        );
    }

    #[test]
    fn старые_ноды_уходят_новые_приходят() {
        let (text, _) = merge(
            РОУТЕР,
            &[нода("Новая-1", "c.example"), нода("Новая-2", "d.example")],
        )
        .unwrap();
        let c = Json::parse(&text).unwrap();
        let tags: Vec<String> = c
            .get("outbounds")
            .map(|o| o.arr().iter().filter_map(tag_of).collect())
            .unwrap_or_default();
        assert!(tags.contains(&"Новая-1".to_string()));
        assert!(
            !tags.iter().any(|t| t.starts_with("Старая")),
            "старые ноды остались: {tags:?}"
        );
        assert!(
            tags.contains(&"direct".to_string()),
            "direct не должен пропадать"
        );
    }

    #[test]
    fn списки_выбора_показывают_новые_ноды_и_хранят_прочее() {
        let (text, _) = merge(РОУТЕР, &[нода("Новая-1", "c.example")]).unwrap();
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
        assert!(
            list.contains(&"auto".to_string()),
            "вложенный auto потерялся"
        );
        assert!(!list.iter().any(|t| t.starts_with("Старая")));
    }

    #[test]
    fn умолчание_не_остаётся_на_исчезнувшей_ноде() {
        // Тут умолчание указывает прямо на ноду, а не на auto.
        let config = РОУТЕР.replace("\"default\": \"auto\"", "\"default\": \"Старая-1\"");
        let (text, _) = merge(&config, &[нода("Новая-1", "c.example")]).unwrap();
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
    fn merge_кладёт_ровно_переданный_список() {
        // Что оставить живым, а что убрать, решает sub::reconcile до merge;
        // merge лишь подставляет готовый список. Передали свежую и одну
        // прежнюю — обе в конфиге и в списке выбора, остальные прежние ушли.
        let (text, count) = merge(
            РОУТЕР,
            &[нода("Новая-1", "c.example"), нода("Старая-2", "b.example")],
        )
        .unwrap();
        assert_eq!(count, 2);
        let c = Json::parse(&text).unwrap();
        let tags: Vec<String> = c
            .get("outbounds")
            .map(|o| o.arr().iter().filter_map(tag_of).collect())
            .unwrap_or_default();
        assert!(tags.contains(&"Новая-1".to_string()));
        assert!(tags.contains(&"Старая-2".to_string()));
        assert!(
            !tags.contains(&"Старая-1".to_string()),
            "лишнюю не переносим: {tags:?}"
        );

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
        assert!(list.contains(&"Старая-2".to_string()));
        assert!(
            list.contains(&"auto".to_string()),
            "вложенный auto потерялся"
        );
    }

    #[test]
    fn пустой_список_ничего_не_ломает() {
        assert!(merge(РОУТЕР, &[]).is_err());
    }

    #[test]
    fn same_nodes_не_зависит_от_порядка_но_ловит_смену_ключа() {
        let a = нода("N1", "a.example");
        let b = нода("N2", "b.example");
        assert!(same_nodes(&[a.clone(), b.clone()], &[b.clone(), a.clone()]));

        let mut b2 = b.clone();
        b2.secret = "99999999-9999-9999-9999-999999999999".into();
        assert!(!same_nodes(&[a.clone(), b], &[a, b2]));
    }
}
