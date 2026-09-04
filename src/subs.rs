//! Список подписок: несколько ссылок, у каждой своё состояние.
//!
//! Раньше ссылка была одна, в файле `subscription`. Теперь их несколько:
//! часть добавляешь руками, часть прилетает через бота или подписанный
//! манифест (см. [`crate::manifest`]). Каждую забираем и проверяем отдельно;
//! та, что [`RETIRE_AFTER`] обновлений подряд не отдала ни одной ноды, уходит
//! в `retired` — опрашивать перестаём, но ссылку держим: вернуть можно одной
//! командой, а забыть — только явно.
//!
//! Формат файла — тот же рукописный JSON, что у запаса нод: пар ключ-значение
//! мало, тащить ради них serde незачем.

use crate::json::{self, Json};
use crate::sub::{self, Node};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

/// Сколько обновлений подряд подписка может не отдать ни одной ноды, прежде
/// чем мы перестаём её опрашивать. При суточном кроне — неделя: переживает
/// долгую ротацию у провайдера, но не держит мёртвую ссылку вечно.
pub const RETIRE_AFTER: u32 = 7;

pub fn store_path() -> PathBuf {
    crate::config::state_dir().join("subscriptions.json")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Active,
    Retired,
}

impl State {
    fn tag(self) -> &'static str {
        match self {
            State::Active => "active",
            State::Retired => "retired",
        }
    }
    fn parse(s: &str) -> State {
        if s == "retired" {
            State::Retired
        } else {
            State::Active
        }
    }
}

#[derive(Debug, Clone)]
pub struct Subscription {
    pub url: String,
    /// Когда ссылку завели, секунды эпохи.
    pub added: u64,
    pub state: State,
    /// Обновлений подряд без единой ноды. Ноды пришли — сбрасывается в ноль.
    pub fail_streak: u32,
    /// Последний раз, когда ссылка отдала хоть одну ноду.
    pub last_live: Option<u64>,
    /// Сколько нод пришло в тот раз.
    pub last_count: usize,
}

impl Subscription {
    fn new(url: &str) -> Subscription {
        Subscription {
            url: url.trim().to_string(),
            added: crate::sub::now_secs(),
            state: State::Active,
            fail_streak: 0,
            last_live: None,
            last_count: 0,
        }
    }

    /// Обновление вернуло `count` нод (0 — провал или пусто). Возвращает
    /// `true`, если подписка только что ушла в отставку.
    pub fn record(&mut self, count: usize) -> bool {
        if count > 0 {
            self.fail_streak = 0;
            self.last_live = Some(crate::sub::now_secs());
            self.last_count = count;
            return false;
        }
        self.fail_streak += 1;
        if self.state == State::Active && self.fail_streak >= RETIRE_AFTER {
            self.state = State::Retired;
            return true;
        }
        false
    }

    fn to_json(&self) -> String {
        let last_live = match self.last_live {
            Some(t) => t.to_string(),
            None => "null".to_string(),
        };
        // json::escape уже возвращает строку в кавычках.
        format!(
            "{{\"url\": {}, \"added\": {}, \"state\": \"{}\", \"fail_streak\": {}, \"last_live\": {}, \"last_count\": {}}}",
            json::escape(&self.url),
            self.added,
            self.state.tag(),
            self.fail_streak,
            last_live,
            self.last_count
        )
    }

    fn from_json(item: &Json) -> Option<Subscription> {
        let url = item.get("url")?.as_str()?;
        if url.trim().is_empty() {
            return None;
        }
        let num = |k: &str| match item.get(k) {
            Some(Json::Num(n)) => Some(*n as u64),
            _ => None,
        };
        Some(Subscription {
            url: url.trim().to_string(),
            added: num("added").unwrap_or_else(crate::sub::now_secs),
            state: item
                .get("state")
                .and_then(|v| v.as_str())
                .map(|s| State::parse(&s))
                .unwrap_or(State::Active),
            fail_streak: num("fail_streak").unwrap_or(0) as u32,
            last_live: num("last_live"),
            last_count: num("last_count").unwrap_or(0) as usize,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Store {
    pub subs: Vec<Subscription>,
    /// Наибольший `seq` виденного манифеста — чтобы не принять старый повторно.
    pub manifest_seq: u64,
}

impl Store {
    /// Подписки с диска. Нет файла — пробуем перенести единственную ссылку из
    /// старого формата (`subscription`), чтобы обновление с прежней версии не
    /// потеряло её.
    pub fn load() -> Store {
        if let Ok(text) = std::fs::read_to_string(store_path())
            && let Ok(root) = Json::parse(&text)
        {
            let subs = root
                .get("subs")
                .map(|s| s.arr().iter().filter_map(Subscription::from_json).collect())
                .unwrap_or_default();
            let manifest_seq = match root.get("manifest_seq") {
                Some(Json::Num(n)) => *n as u64,
                _ => 0,
            };
            return Store { subs, manifest_seq };
        }

        let mut store = Store::default();
        if let Ok(old) = std::fs::read_to_string(crate::sub::subscription_path()) {
            let url = old.trim();
            if !url.is_empty() {
                store.subs.push(Subscription::new(url));
            }
        }
        store
    }

    pub fn save(&self) -> Result<(), String> {
        crate::config::state_dir_ensure()
            .map_err(|e| format!("не создать каталог состояния: {e}"))?;
        let body: Vec<String> = self.subs.iter().map(Subscription::to_json).collect();
        let text = format!(
            "{{\"subs\": [{}], \"manifest_seq\": {}}}",
            body.join(", "),
            self.manifest_seq
        );
        std::fs::write(store_path(), text)
            .map_err(|e| format!("не записать список подписок: {e}"))?;
        // Для совместимости со старым кодом и глазами: первая живая ссылка
        // остаётся и в отдельном файле, его читает `sub::saved_url`.
        if let Some(first) = self.subs.iter().find(|s| s.state == State::Active) {
            let _ = std::fs::write(crate::sub::subscription_path(), &first.url);
        }
        Ok(())
    }

    /// Добавить ссылку. Уже была активной — `false`; была в отставке —
    /// поднимаем обратно и `true`; новой не было — заводим и `true`.
    pub fn add(&mut self, url: &str) -> bool {
        let want = url.trim().to_string();
        if want.is_empty() {
            return false;
        }
        if let Some(existing) = self.subs.iter_mut().find(|s| s.url == want) {
            if existing.state == State::Retired {
                existing.state = State::Active;
                existing.fail_streak = 0;
                return true;
            }
            return false;
        }
        self.subs.push(Subscription::new(&want));
        true
    }

    pub fn revive(&mut self, url: &str) -> bool {
        let want = url.trim();
        match self.subs.iter_mut().find(|s| s.url == want) {
            Some(s) if s.state == State::Retired => {
                s.state = State::Active;
                s.fail_streak = 0;
                true
            }
            _ => false,
        }
    }

    /// Убрать ссылку совсем. Возвращает `true`, если что-то убрали.
    pub fn forget(&mut self, url: &str) -> bool {
        let want = url.trim();
        let before = self.subs.len();
        self.subs.retain(|s| s.url != want);
        self.subs.len() != before
    }

    pub fn active(&self) -> impl Iterator<Item = &Subscription> {
        self.subs.iter().filter(|s| s.state == State::Active)
    }
}

/// Что дала одна подписка на этом прогоне.
pub struct Fetched {
    pub url: String,
    /// Сколько нод пришло, либо текст ошибки.
    pub result: Result<usize, String>,
    /// Подписка только что ушла в отставку.
    pub retired: bool,
}

/// Итог обновления всех подписок.
pub struct Refresh {
    pub rec: sub::Reconciled,
    pub fetched: Vec<Fetched>,
    /// Путь пересобранного конфига движка.
    pub config: PathBuf,
}

/// Забрать все активные подписки, свести свежие ноды с прежним активным
/// списком и запасом, переписать конфиг движка. Ничего не перезапускает —
/// это на вызывающем.
///
/// Забрать все активные подписки: вернуть объединённый список свежих нод,
/// отчёт по каждой ссылке и store с уже посчитанными счётчиками провалов
/// (несохранённый — записать на диск должен вызывающий).
pub fn fetch_all() -> (Vec<Node>, Vec<Fetched>, Store) {
    let mut store = Store::load();
    let urls: Vec<String> = store.active().map(|s| s.url.clone()).collect();
    let mut fresh: Vec<Node> = Vec::new();
    let mut fetched: Vec<Fetched> = Vec::new();
    for url in &urls {
        let result = sub::fetch(url, Duration::from_secs(30));
        let count = result.as_ref().map(|n| n.len()).unwrap_or(0);
        let retired = store
            .subs
            .iter_mut()
            .find(|s| &s.url == url)
            .map(|s| s.record(count))
            .unwrap_or(false);
        match result {
            Ok(nodes) => {
                fresh.extend(nodes);
                fetched.push(Fetched {
                    url: url.clone(),
                    result: Ok(count),
                    retired,
                });
            }
            Err(e) => fetched.push(Fetched {
                url: url.clone(),
                result: Err(e),
                retired,
            }),
        }
    }
    sub::dedupe_names(&mut fresh);
    (fresh, fetched, store)
}

/// `probe` — таймаут проверки отклика для нод, выпавших из подписки.
pub fn refresh(probe: Duration) -> Result<Refresh, String> {
    let (fresh, fetched, store) = fetch_all();
    if fetched.is_empty() {
        return Err("нет активных подписок — net vpn subs add <ссылка>".into());
    }

    let prev_active = sub::current_nodes();
    let bank = sub::load_bank();
    let rec = sub::reconcile(&fresh, &prev_active, bank, probe);

    let mut active = rec.active.clone();
    sub::dedupe_names(&mut active);
    if active.is_empty() {
        // Ни свежих, ни переживших, ни поднятых из запаса. Прежний конфиг не
        // трогаем — вчерашние ноды лучше пустого файла, — но состояние
        // подписок сохраняем: счётчики провалов и отставка уже посчитаны.
        store.save()?;
        let _ = write_log(&rec, &fetched, true);
        return Err(
            "ни одной живой ноды: ни в подписках, ни в запасе — конфиг оставлен прежним".into(),
        );
    }

    let config = crate::singbox::build_config(&active)?;
    // sub::save пишет и «первую ссылку» в отдельный файл для sub::saved_url;
    // берём первую активную из store.
    let first = store
        .active()
        .next()
        .map(|s| s.url.clone())
        .unwrap_or_default();
    let path = sub::save(&first, &active, &config)?;

    // Отметки отклика: всё, что в работе, отвечало только что.
    let mut bank = rec.bank.clone();
    let live: Vec<String> = active.iter().map(sub::place).collect();
    let now = sub::now_secs();
    sub::add_missing(&mut bank, &active);
    for kept in bank.iter_mut() {
        if live.contains(&sub::place(&kept.node)) {
            kept.last_ok = Some(now);
        }
    }
    sub::save_bank(&bank)?;
    store.save()?;

    let _ = write_log(&rec, &fetched, false);
    Ok(Refresh {
        rec,
        fetched,
        config: path,
    })
}

pub fn write_log(
    rec: &sub::Reconciled,
    fetched: &[Fetched],
    pool_empty: bool,
) -> std::io::Result<()> {
    crate::config::state_dir_ensure()?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(sub::refresh_log_path())?;

    let list = |names: &[String]| {
        if names.is_empty() {
            "—".to_string()
        } else {
            names.join(", ")
        }
    };
    let ok_subs = fetched.iter().filter(|f| f.result.is_ok()).count();
    let bad: Vec<String> = fetched
        .iter()
        .filter_map(|f| {
            f.result
                .as_ref()
                .err()
                .map(|e| format!("{}: {e}", short(&f.url)))
        })
        .collect();
    let retired: Vec<String> = fetched
        .iter()
        .filter(|f| f.retired)
        .map(|f| short(&f.url))
        .collect();

    writeln!(
        f,
        "{ts}  подписок ок: {ok}/{total}  |  +{na} новых: {new}  |  ~{ca} перенесено: {carried}  |  ↺{ra} из запаса: {revived}  |  ⚰{pa} в запас: {parked}  |  ✂{pra} вычищено: {pruned}  |  актив: {act}",
        ts = stamp(),
        ok = ok_subs,
        total = fetched.len(),
        na = rec.added.len(),
        new = list(&rec.added),
        ca = rec.carried.len(),
        carried = list(&rec.carried),
        ra = rec.revived.len(),
        revived = list(&rec.revived),
        pa = rec.parked.len(),
        parked = list(&rec.parked),
        pra = rec.pruned.len(),
        pruned = list(&rec.pruned),
        act = rec.active.len(),
    )?;
    if !bad.is_empty() {
        writeln!(f, "{}  подписки не ответили: {}", stamp(), bad.join(" · "))?;
    }
    if !retired.is_empty() {
        writeln!(
            f,
            "{}  в отставку ({} провалов подряд): {}",
            stamp(),
            RETIRE_AFTER,
            retired.join(", ")
        )?;
    }
    if pool_empty {
        writeln!(
            f,
            "{}  ВНИМАНИЕ: во всём пуле нет ни одной живой ноды",
            stamp()
        )?;
    }
    Ok(())
}

/// Ссылка коротко: хост и хвост, чтобы в журнале и на экране не мелькал
/// токен целиком.
pub fn short(url: &str) -> String {
    let no_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = no_scheme.split(['/', '?']).next().unwrap_or(no_scheme);
    let tail: String = url
        .chars()
        .rev()
        .take(6)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{host}…{tail}")
}

fn stamp() -> String {
    #[cfg(unix)]
    if let Ok(out) = std::process::Command::new("date")
        .arg("+%Y-%m-%d %H:%M:%S")
        .output()
    {
        let t = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !t.is_empty() {
            return t;
        }
    }
    sub::now_secs().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn семь_пустых_обновлений_отправляют_в_отставку() {
        let mut s = Subscription::new("https://sub.example/x");
        for _ in 0..RETIRE_AFTER - 1 {
            assert!(!s.record(0));
            assert_eq!(s.state, State::Active);
        }
        assert!(s.record(0));
        assert_eq!(s.state, State::Retired);
    }

    #[test]
    fn ноды_обнуляют_счётчик_провалов() {
        let mut s = Subscription::new("https://sub.example/x");
        s.record(0);
        s.record(0);
        s.record(12);
        assert_eq!(s.fail_streak, 0);
        assert_eq!(s.last_count, 12);
        assert!(s.last_live.is_some());
    }

    #[test]
    fn повторная_ссылка_поднимает_из_отставки() {
        let mut store = Store::default();
        assert!(store.add("https://sub.example/x"));
        assert!(!store.add("https://sub.example/x")); // уже активна
        store.subs[0].state = State::Retired;
        assert!(store.add("https://sub.example/x")); // подняли обратно
        assert_eq!(store.subs[0].state, State::Active);
        assert_eq!(store.subs.len(), 1);
    }

    #[test]
    fn забыть_убирает_совсем_а_отставка_нет() {
        let mut store = Store::default();
        store.add("https://a.example");
        store.add("https://b.example");
        store.subs[0].record(0);
        for _ in 0..RETIRE_AFTER {
            store.subs[0].record(0);
        }
        assert_eq!(store.active().count(), 1);
        assert_eq!(store.subs.len(), 2);
        assert!(store.forget("https://a.example"));
        assert_eq!(store.subs.len(), 1);
    }

    #[test]
    fn запись_читается_обратно() {
        let mut s = Subscription::new("https://sub.example/x?token=abc");
        s.record(9);
        let json = format!("[{}]", s.to_json());
        let parsed = crate::json::Json::parse(&json).unwrap();
        let back = Subscription::from_json(&parsed.arr()[0]).unwrap();
        assert_eq!(back.url, s.url);
        assert_eq!(back.last_count, 9);
        assert_eq!(back.state, State::Active);
    }
}
