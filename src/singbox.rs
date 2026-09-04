//! Конфиг для движка sing-box: TUN-туннель, ноды из подписки, выбор ноды на
//! ходу через clash API.
//!
//! Конфиг собирается строкой, а не структурами: схема движка меняется от версии
//! к версии, и держать её зеркало в типах — работа ради работы. Проверяется
//! конфиг тем же движком (`sing-box check`), а не нашей верой в него.

use crate::json;
use crate::sub::Node;

/// Адрес встроенного API движка: через него меняется нода без перезапуска.
pub const CLASH_API: &str = "127.0.0.1:9090";

/// Тег селектора, который выбирает текущую ноду.
pub const SELECTOR: &str = "proxy";

/// Тег автоподбора по задержке.
pub const AUTO: &str = "auto";

/// Что именно уходит в туннель.
///
/// Полный туннель — обычный VPN: наружу через ноду идёт всё, кроме российского.
/// Точечный нужен для звонков: их душат по IP, дурить DPI нечего, но и гнать
/// через ноду весь интернет ради разговора незачем — цена этому лишние
/// задержки везде и мёртвые сервисы, которые не любят адреса датацентров.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Всё через ноду, российское — напрямую.
    All,
    /// Через ноду только Telegram, остальное напрямую.
    TelegramOnly,
}

pub fn scope_path() -> PathBuf {
    crate::config::state_dir().join("scope")
}

pub fn scope() -> Scope {
    match std::fs::read_to_string(scope_path()) {
        Ok(text) if text.trim() == "telegram" => Scope::TelegramOnly,
        _ => Scope::All,
    }
}

pub fn set_scope(scope: Scope) -> Result<(), String> {
    crate::config::state_dir_ensure().map_err(|e| e.to_string())?;
    let word = match scope {
        Scope::All => "all",
        Scope::TelegramOnly => "telegram",
    };
    std::fs::write(scope_path(), word).map_err(|e| format!("не записать охват: {e}"))
}

/// Наборы правил, которые ядро качает само. Берём с jsDelivr: он на Fastly, а
/// не на закрытых по IP адресах GitHub.
fn rule_sets(scope: Scope) -> String {
    let mut sets = vec![
        set_entry("geosite-ru", "sing-geosite@rule-set/geosite-category-ru"),
        set_entry("geoip-ru", "sing-geoip@rule-set/geoip-ru"),
    ];
    if scope == Scope::TelegramOnly {
        // Готового набора адресов Telegram у SagerNet нет — только домены.
        // Адреса берём официальным списком, он лежит рядом (см. telegram_cidr).
        sets.push(set_entry(
            "geosite-telegram",
            "sing-geosite@rule-set/geosite-telegram",
        ));
    }
    sets.join(",\n      ")
}

fn set_entry(tag: &str, path: &str) -> String {
    format!(
        r#"{{"type": "remote", "tag": "{tag}", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/SagerNet/{path}.srs", "download_detour": "direct"}}"#
    )
}

fn route_rules(scope: Scope) -> String {
    let mut rules = vec![
        r#"{"action": "sniff"}"#.to_string(),
        r#"{"protocol": "dns", "action": "hijack-dns"}"#.to_string(),
        r#"{"ip_is_private": true, "outbound": "direct"}"#.to_string(),
    ];
    match scope {
        Scope::All => {
            rules.push(r#"{"rule_set": "geosite-ru", "outbound": "direct"}"#.to_string());
            rules.push(r#"{"rule_set": "geoip-ru", "outbound": "direct"}"#.to_string());
        }
        Scope::TelegramOnly => {
            // Telegram ловим и по именам, и по адресам: голос идёт по IP,
            // минуя DNS вовсе, и одного списка доменов тут мало.
            rules.push(format!(
                r#"{{"rule_set": "geosite-telegram", "outbound": "{SELECTOR}"}}"#
            ));
            rules.push(format!(
                r#"{{"ip_cidr": [{}], "outbound": "{SELECTOR}"}}"#,
                telegram_cidr()
                    .iter()
                    .map(|net| format!("\"{net}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    rules.join(",\n      ")
}

/// Адреса Telegram: официальный список core.telegram.org/resources/cidr.txt.
///
/// Он лежит в файле состояния и обновляется командой; пока файла нет, берётся
/// вшитый снимок. Держать только вшитый нельзя — диапазоны меняются, и тогда
/// часть разговоров пойдёт мимо ноды и умрёт.
pub fn telegram_cidr() -> Vec<String> {
    let свежий = std::fs::read_to_string(cidr_path()).unwrap_or_default();
    let список: Vec<String> = свежий
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        // IPv6 у Telegram есть, но туннель поднимается на ipv4_only: адреса
        // шестой версии в правило не пойдут и только раздуют конфиг.
        .filter(|l| !l.contains(':'))
        .map(str::to_string)
        .collect();
    if список.is_empty() {
        ВШИТЫЕ_СЕТИ.iter().map(|s| s.to_string()).collect()
    } else {
        список
    }
}

pub fn cidr_path() -> PathBuf {
    crate::config::state_dir().join("telegram-cidr.txt")
}

/// Снимок официального списка на 09.2026.
const ВШИТЫЕ_СЕТИ: [&str; 8] = [
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
    "91.105.192.0/23",
    "149.154.160.0/20",
];

/// Обновить список адресов Telegram с сайта самого Telegram.
pub fn update_telegram_cidr() -> Result<usize, String> {
    let out = Command::new("curl")
        .args([
            "-fsL",
            "--connect-timeout",
            "8",
            "--max-time",
            "30",
            "https://core.telegram.org/resources/cidr.txt",
        ])
        .output()
        .map_err(|e| format!("не запустился curl: {e}"))?;
    let текст = String::from_utf8_lossy(&out.stdout);
    let сети: Vec<&str> = текст
        .lines()
        .map(str::trim)
        .filter(|l| l.contains('/') && !l.starts_with('#'))
        .collect();
    if сети.len() < 4 {
        return Err("список адресов Telegram не пришёл — сайт закрыт или пуст".into());
    }
    crate::config::state_dir_ensure().map_err(|e| e.to_string())?;
    std::fs::write(cidr_path(), сети.join("\n") + "\n")
        .map_err(|e| format!("не записать список: {e}"))?;
    Ok(сети.iter().filter(|l| !l.contains(':')).count())
}

fn route_final(scope: Scope) -> &'static str {
    match scope {
        Scope::All => SELECTOR,
        Scope::TelegramOnly => "direct",
    }
}

/// Куда уходят запросы имён. В точечном туннеле — своему провайдеру: гнать
/// весь DNS за границу ради Telegram незачем, а российские сайты от этого
/// ломаются.
fn dns_block(scope: Scope) -> String {
    let (rules, last) = match scope {
        Scope::All => (
            r#"{"rule_set": "geosite-ru", "server": "dns-direct"}"#.to_string(),
            "dns-remote",
        ),
        Scope::TelegramOnly => (
            r#"{"rule_set": "geosite-telegram", "server": "dns-remote"}"#.to_string(),
            "dns-direct",
        ),
    };
    format!(
        r#"{{
    "servers": [
      {{"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "detour": "{SELECTOR}"}},
      {{"type": "https", "tag": "dns-direct", "server": "77.88.8.8"}}
    ],
    "rules": [
      {rules}
    ],
    "final": "{last}",
    "strategy": "ipv4_only"
  }}"#
    )
}

pub fn build_config(nodes: &[Node]) -> Result<String, String> {
    build_config_scoped(nodes, scope())
}

pub fn build_config_scoped(nodes: &[Node], scope: Scope) -> Result<String, String> {
    if nodes.is_empty() {
        return Err("нет ни одной ноды".into());
    }
    let tags: Vec<String> = nodes.iter().map(|n| n.name.clone()).collect();
    let quoted: Vec<String> = tags.iter().map(|t| json::escape(t)).collect();
    let outbounds: Vec<String> = nodes
        .iter()
        .zip(&tags)
        .map(|(node, tag)| {
            let mut node = node.clone();
            node.name = tag.clone();
            node.to_outbound()
        })
        .collect();

    let selector = format!(
        "{{\"type\": \"selector\", \"tag\": {}, \"outbounds\": [{}, {}], \"default\": {}}}",
        json::escape(SELECTOR),
        json::escape(AUTO),
        quoted.join(", "),
        json::escape(AUTO)
    );
    let urltest = format!(
        "{{\"type\": \"urltest\", \"tag\": {}, \"outbounds\": [{}], \"url\": \"https://www.gstatic.com/generate_204\", \"interval\": \"5m\", \"tolerance\": 50}}",
        json::escape(AUTO),
        quoted.join(", ")
    );

    let mut all = vec![selector, urltest];
    all.extend(outbounds);
    all.push("{\"type\": \"direct\", \"tag\": \"direct\"}".to_string());

    Ok(format!(
        r#"{{
  "log": {{"level": "warn"}},
  "dns": {dns},
  "inbounds": [
    {{
      "type": "tun",
      "tag": "tun-in",
      "address": ["172.19.0.1/30"],
      "auto_route": true,
      "strict_route": false,
      "stack": "gvisor"
    }}
  ],
  "outbounds": [{outbounds}],
  "route": {{
    "rules": [
      {rules}
    ],
    "rule_set": [
      {sets}
    ],
    "auto_detect_interface": true,
    "default_domain_resolver": {{"server": "dns-direct"}},
    "final": "{final}"
  }},
  "experimental": {{
    "clash_api": {{"external_controller": "{api}"}},
    "cache_file": {{"enabled": true, "path": "{cache}"}}
  }}
}}
"#,
        dns = dns_block(scope),
        rules = route_rules(scope),
        sets = rule_sets(scope),
        final = route_final(scope),
        outbounds = all.join(",\n    "),
        api = CLASH_API,
        // Без явного пути ядро кладёт кэш в тот каталог, откуда его запустили,
        // и файл появляется где попало — вплоть до корня репозитория.
        cache = crate::json::escape(
            &crate::config::state_dir().join("cache.db").to_string_lossy()
        )
        .trim_matches('"')
    ))
}

/// Переписывает охват в уже собранном конфиге: ноды остаются те же, меняются
/// только маршруты и DNS. Нужно, чтобы переключение не требовало заново
/// разбирать подписку.
pub fn rewrite_scope(scope: Scope) -> Result<(), String> {
    let path = crate::config::state_dir().join("singbox.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|_| "конфиг ядра ещё не собран: net vpn sub <ссылка>".to_string())?;
    let mut config = crate::json::Json::parse(&text)?;
    let route = crate::json::Json::parse(&format!(
        r#"{{"rules": [{}], "rule_set": [{}], "auto_detect_interface": true, "default_domain_resolver": {{"server": "dns-direct"}}, "final": "{}"}}"#,
        route_rules(scope),
        rule_sets(scope),
        route_final(scope)
    ))?;
    let dns = crate::json::Json::parse(&dns_block(scope))?;
    config.set("route", route);
    config.set("dns", dns);
    std::fs::write(&path, config.to_text()).map_err(|e| format!("не записать конфиг: {e}"))?;
    set_scope(scope)
}

use crate::config::Config;
use std::path::PathBuf;
use std::process::Command;

/// Своё ядро вместо клиента: тот же туннель, что поднимает Happ, только
/// управляемый отсюда.
pub struct Core<'a> {
    cfg: &'a Config,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum State {
    /// Ядро работает, туннель поднят.
    Up,
    Down,
}

impl<'a> Core<'a> {
    pub fn new(cfg: &'a Config) -> Self {
        Core { cfg }
    }

    pub fn bin(&self) -> Result<PathBuf, String> {
        self.cfg
            .core_bin
            .clone()
            .ok_or_else(|| "ядро sing-box не найдено — net vpn core install".to_string())
    }

    /// Состояние ядра, когда настроек под рукой нет: живость определяется по
    /// API, а он не зависит ни от чего в конфиге.
    pub fn state_now() -> State {
        if api_get("/version").is_some() {
            State::Up
        } else {
            State::Down
        }
    }

    pub fn state(&self) -> State {
        // Живость проверяется по API, а не по процессу: ядро может остаться в
        // памяти, но не отвечать, и тогда пульт врал бы, что всё хорошо.
        if api_get("/version").is_some() {
            State::Up
        } else {
            State::Down
        }
    }

    /// Поднять туннель. TUN требует прав администратора на всех трёх системах:
    /// Linux и macOS спрашивают пароль через sudo, Windows — своим окном
    /// «разрешить внести изменения».
    pub fn start(&self) -> Result<(), String> {
        if self.state() == State::Up {
            return Ok(());
        }
        let bin = self.bin()?;
        let config = crate::sub::config_path();
        if !config.exists() {
            return Err("подписка ещё не загружена — net vpn sub <ссылка>".into());
        }
        let log = crate::config::state_dir().join("core.log");
        let pid = self.pid_path();
        if !cfg!(windows) {
            // TUN без root не поднять никак: проверяем возможность спросить
            // пароль до запуска, иначе sudo молча упрётся в невидимый запрос.
            crate::sudoer::ready()?;
            println!("Нужны права root — TUN без них не поднять.");
        } else {
            println!("Windows спросит разрешение администратора — TUN без него не поднять.");
        }
        let command = format!(
            "nohup {bin} run -c {config} > {log} 2>&1 & echo $! > {pid}",
            bin = shell_quote(&bin.to_string_lossy()),
            config = shell_quote(&config.to_string_lossy()),
            log = shell_quote(&log.to_string_lossy()),
            pid = shell_quote(&pid.to_string_lossy()),
        );
        let status = if cfg!(windows) {
            // Обычный spawn поднял бы ядро без прав, и оно молча упало бы на
            // создании адаптера. `-Verb RunAs` показывает то самое окно UAC.
            let script = format!(
                "$p = Start-Process -FilePath '{bin}' -ArgumentList 'run','-c','{config}' \
                 -Verb RunAs -WindowStyle Hidden -PassThru; \
                 $p.Id | Out-File -Encoding ascii '{pid}'",
                bin = bin.display(),
                config = config.display(),
                pid = pid.display(),
            );
            Command::new("powershell")
                .args(["-NoProfile", "-Command", &script])
                .status()
                .map_err(|e| format!("powershell не запустился: {e}"))?
                .success()
        } else {
            crate::sudoer::command()
                .args(["sh", "-c", &command])
                .status()
                .map_err(|e| format!("sudo не запустился: {e}"))?
                .success()
        };
        if !status {
            return Err("ядро не запустилось — смотри net vpn log".into());
        }

        // Первый запуск дольше остальных: ядро тянет списки правил для
        // российского сплита. Дальше они лежат в кэше и старт мгновенный.
        // Молчать эти секунды нельзя — со стороны это выглядит как зависание.
        println!("Ядро запущено, поднимаю туннель...");
        let started = std::time::Instant::now();
        let limit = std::time::Duration::from_secs(60);
        let mut said = 0;
        while started.elapsed() < limit {
            if self.state() == State::Up {
                crate::progress::дождались();
                println!("Туннель поднят за {:.0} с", started.elapsed().as_secs_f32());
                // Автоподбор до первого замера держит первую ноду списка —
                // живая она или мёртвая, ему пока неоткуда знать. Гоним замер
                // сразу, иначе первые минуты трафик идёт наугад.
                println!("Проверяю ноды, чтобы автоподбор выбрал живую...");
                crate::progress::ждём("прозваниваю ноды", 0);
                measure_group(AUTO, 5000);
                crate::progress::дождались();
                if let Some((name, _)) = active_node() {
                    println!("Нода: {name}");
                }
                return Ok(());
            }
            let seconds = started.elapsed().as_secs();
            if seconds > said {
                said = seconds;
                if seconds == 3 {
                    crate::progress::дождались();
                    println!("  списки правил тянутся при первом запуске, это разово");
                }
                crate::progress::ждём("поднимаю туннель", seconds);
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        crate::progress::дождались();
        Err("ядро не открыло API за минуту — смотри net vpn log".into())
    }

    pub fn stop(&self) -> Result<(), String> {
        if !cfg!(windows) {
            crate::sudoer::ready()?;
        }
        let pid_path = self.pid_path();
        let pid = std::fs::read_to_string(&pid_path)
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok());
        let ok = match pid {
            Some(pid) if !cfg!(windows) => crate::sudoer::command()
                .args(["kill", &pid.to_string()])
                .status()
                .map(|s| s.success())
                .unwrap_or(false),
            // Ядро на Windows запущено от администратора, и снять его можно
            // только тем же правом — снова через окно разрешения.
            _ if cfg!(windows) => Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "Start-Process taskkill -ArgumentList '/IM','sing-box.exe','/F' \
                     -Verb RunAs -WindowStyle Hidden -Wait",
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false),
            _ => Command::new("pkill")
                .args(["-f", "sing-box run"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false),
        };
        let _ = std::fs::remove_file(&pid_path);
        if ok {
            Ok(())
        } else {
            Err("не удалось остановить ядро".into())
        }
    }

    fn pid_path(&self) -> PathBuf {
        crate::config::state_dir().join("core.pid")
    }

    /// Наше ли это ядро, а не чужое, отвечающее на том же API.
    ///
    /// `state()` смотрит только на clash API 127.0.0.1:9090 — и этого хватает,
    /// чтобы ответить «туннель есть». Но на роутере рядом живёт свой sing-box,
    /// поднятый мимо пульта, и API там отвечает он. Автоматике трогать его
    /// нельзя: снятие «туннеля» уронило бы интернет всей квартире.
    ///
    /// Признак владения — наш файл с номером процесса, и чтобы под этим
    /// номером действительно жило ядро: номера переиспользуются, и убить по
    /// протухшему файлу постороннего — ровно то, чего мы избегаем.
    pub fn наш(&self) -> bool {
        let Some(pid) = std::fs::read_to_string(self.pid_path())
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok())
        else {
            return false;
        };
        if cfg!(target_os = "linux") {
            std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|comm| comm.trim() == "sing-box")
                .unwrap_or(false)
        } else {
            // На маке и Windows /proc нет; там пульт — единственный, кто
            // поднимает ядро, и файла с номером достаточно.
            true
        }
    }
}

/// Кто сейчас выбран в селекторе.
pub fn current_node() -> Option<String> {
    let body = api_get(&format!("/proxies/{SELECTOR}"))?;
    field(&body, "now")
}

/// Нода, через которую на самом деле идёт трафик.
///
/// Селектор может стоять на автоподборе, и тогда его «now» — это слово «auto»,
/// а не страна. Настоящую ноду знает сам автоподбор, у него и спрашиваем.
pub fn active_node() -> Option<(String, bool)> {
    let chosen = current_node()?;
    if chosen != AUTO {
        return Some((chosen, false));
    }
    let body = api_get(&format!("/proxies/{AUTO}"))?;
    field(&body, "now").map(|name| (name, true))
}

/// Переключить ноду. Без перезапуска ядра — соединения переедут сами.
pub fn select(name: &str) -> Result<(), String> {
    // Без поднятого ядра выбирать нечего, и «ядро её не знает» тут врало бы:
    // ядра нет вовсе.
    if Core::state_now() != State::Up {
        return Err("туннель не поднят — сначала net vpn on".into());
    }
    let body = format!("{{\"name\": {}}}", crate::json::escape(name));
    let out = Command::new("curl")
        .args([
            "-fsS",
            "-X",
            "PUT",
            "-H",
            "Content-Type: application/json",
            "-d",
            &body,
            &format!("http://{CLASH_API}/proxies/{SELECTOR}"),
        ])
        .output()
        .map_err(|e| format!("curl не запустился: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("нода «{name}» не выбралась — ядро её не знает?"))
    }
}

/// Заставить движок перемерить всю группу разом: он сам разошлёт пробы по
/// нодам и переставит автоподбор на живую.
pub fn measure_group(group: &str, timeout_ms: u32) {
    // Именно `/proxies/<группа>/delay`: путь `/group/.../delay` движок знает,
    // но отвечает пустотой и проб не рассылает.
    let _ = delay(group, timeout_ms);
}

/// Замерить задержку одной ноды глазами самого движка.
pub fn delay(name: &str, timeout_ms: u32) -> Option<u32> {
    let encoded = url_encode(name);
    let body = api_get(&format!(
        "/proxies/{encoded}/delay?timeout={timeout_ms}&url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204"
    ))?;
    field(&body, "delay")?.parse().ok()
}

/// Запрос к API движка. Свой HTTP-клиент тут не нужен: curl уже используется
/// для проверок, и он же обрабатывает таймауты.
fn api_get(path: &str) -> Option<String> {
    let out = Command::new("curl")
        .args([
            "-fsS",
            "--max-time",
            "12",
            &format!("http://{CLASH_API}{path}"),
        ])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).to_string())
}

/// Значение поля верхнего уровня. Ответы API маленькие и плоские, полный
/// разбор JSON тут был бы из пушки по воробьям.
fn field(body: &str, key: &str) -> Option<String> {
    let value = crate::json::Json::parse(body).ok()?;
    value.get(key)?.as_str()
}

fn url_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Имя файла ядра в релизе netpult под текущую систему.
/// Релиз, в котором лежат сборки ядра.
pub const CORE_TAG: &str = "core-1.13.19";

fn core_asset() -> &'static str {
    if cfg!(target_os = "macos") {
        "sing-box-macos-universal"
    } else if cfg!(windows) {
        "sing-box-windows-x86_64.exe"
    } else {
        "sing-box-linux-x86_64"
    }
}

/// Поставить ядро рядом с состоянием.
///
/// Ядро качается из релизов netpult, а не с сайта sing-box: официальные
/// маковские сборки требуют macOS 12 и на Big Sur не запускаются, наши собраны
/// компилятором постарше. Ссылка пробуется напрямую и через зеркала — GitHub
/// из России закрыт, а ядро нужно как раз для того, чтобы это чинить.
pub fn install_core() -> Result<PathBuf, String> {
    let target = crate::config::state_dir().join(if cfg!(windows) {
        "sing-box.exe"
    } else {
        "sing-box"
    });
    crate::config::state_dir_ensure().map_err(|e| format!("не создать каталог состояния: {e}"))?;
    // Ядро лежит отдельным релизом и живёт своей жизнью: оно меняется раз в
    // несколько месяцев, а пульт — часто, и таскать 180 МБ в каждый выпуск
    // незачем.
    let url = format!(
        "https://github.com/pepetutu1337/netpult/releases/download/{CORE_TAG}/{}",
        core_asset()
    );
    let mirrors = ["", "https://gh-proxy.com/", "https://ghfast.top/"];
    for mirror in mirrors {
        let ok = Command::new("curl")
            .args([
                "-fsSL",
                "--connect-timeout",
                "8",
                "--max-time",
                "600",
                // Встал и молчит — не ждём десять минут, идём к зеркалу.
                "--speed-time",
                "20",
                "--speed-limit",
                "2048",
                "-o",
                &target.to_string_lossy(),
                &format!("{mirror}{url}"),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755));
            }
            // Скачанному файлу macOS ставит карантин и отказывается запускать.
            if cfg!(target_os = "macos") {
                let _ = Command::new("xattr")
                    .args(["-d", "com.apple.quarantine", &target.to_string_lossy()])
                    .status();
            }
            return Ok(target);
        }
    }
    Err(format!(
        "ядро не скачалось. Собери своё: tools/build-core.sh, и положи как {}",
        target.display()
    ))
}
