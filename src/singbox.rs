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

pub fn build_config(nodes: &[Node]) -> Result<String, String> {
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
  "dns": {{
    "servers": [
      {{"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "detour": "{selector}"}},
      {{"type": "udp", "tag": "dns-direct", "server": "77.88.8.8"}}
    ],
    "rules": [
      {{"rule_set": "geosite-ru", "server": "dns-direct"}}
    ],
    "final": "dns-remote",
    "strategy": "ipv4_only"
  }},
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
      {{"action": "sniff"}},
      {{"protocol": "dns", "action": "hijack-dns"}},
      {{"ip_is_private": true, "outbound": "direct"}},
      {{"rule_set": "geosite-ru", "outbound": "direct"}},
      {{"rule_set": "geoip-ru", "outbound": "direct"}}
    ],
    "rule_set": [
      {{
        "type": "remote",
        "tag": "geosite-ru",
        "format": "binary",
        "url": "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ru.srs",
        "download_detour": "direct"
      }},
      {{
        "type": "remote",
        "tag": "geoip-ru",
        "format": "binary",
        "url": "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-ru.srs",
        "download_detour": "direct"
      }}
    ],
    "auto_detect_interface": true,
    "default_domain_resolver": {{"server": "dns-direct"}},
    "final": "{selector}"
  }},
  "experimental": {{
    "clash_api": {{"external_controller": "{api}"}},
    "cache_file": {{"enabled": true}}
  }}
}}
"#,
        selector = SELECTOR,
        outbounds = all.join(",\n    "),
        api = CLASH_API
    ))
}

use crate::config::Config;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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

    pub fn state(&self) -> State {
        // Живость проверяется по API, а не по процессу: ядро может остаться в
        // памяти, но не отвечать, и тогда пульт врал бы, что всё хорошо.
        if api_get("/version").is_some() {
            State::Up
        } else {
            State::Down
        }
    }

    /// Поднять туннель. TUN требует прав root — sudo запросит пароль в том же
    /// окне, поэтому потоки не перехватываются.
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
        let command = format!(
            "nohup {bin} run -c {config} > {log} 2>&1 & echo $! > {pid}",
            bin = shell_quote(&bin.to_string_lossy()),
            config = shell_quote(&config.to_string_lossy()),
            log = shell_quote(&log.to_string_lossy()),
            pid = shell_quote(&pid.to_string_lossy()),
        );
        let status = if cfg!(windows) {
            Command::new(&bin)
                .args(["run", "-c", &config.to_string_lossy()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map(|_| true)
                .map_err(|e| format!("ядро не запустилось: {e}"))?
        } else {
            Command::new("sudo")
                .args(["sh", "-c", &command])
                .status()
                .map_err(|e| format!("sudo не запустился: {e}"))?
                .success()
        };
        if !status {
            return Err("ядро не запустилось — смотри net vpn log".into());
        }
        // Движку нужно время поднять интерфейс и открыть API.
        for _ in 0..20 {
            if self.state() == State::Up {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        Err("ядро запущено, но API молчит — смотри net vpn log".into())
    }

    pub fn stop(&self) -> Result<(), String> {
        let pid_path = self.pid_path();
        let pid = std::fs::read_to_string(&pid_path)
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok());
        let ok = match pid {
            Some(pid) if !cfg!(windows) => Command::new("sudo")
                .args(["kill", &pid.to_string()])
                .status()
                .map(|s| s.success())
                .unwrap_or(false),
            _ => Command::new(if cfg!(windows) { "taskkill" } else { "pkill" })
                .args(if cfg!(windows) {
                    vec!["/IM", "sing-box.exe", "/F"]
                } else {
                    vec!["-f", "sing-box run"]
                })
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
}

/// Кто сейчас выбран в селекторе.
pub fn current_node() -> Option<String> {
    let body = api_get(&format!("/proxies/{SELECTOR}"))?;
    field(&body, "now")
}

/// Переключить ноду. Без перезапуска ядра — соединения переедут сами.
pub fn select(name: &str) -> Result<(), String> {
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
    let url = format!(
        "https://github.com/pepetutu1337/netpult/releases/latest/download/{}",
        core_asset()
    );
    let mirrors = ["", "https://gh-proxy.com/", "https://ghfast.top/"];
    for mirror in mirrors {
        let ok = Command::new("curl")
            .args([
                "-fsSL",
                "--connect-timeout",
                "10",
                "--max-time",
                "600",
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
