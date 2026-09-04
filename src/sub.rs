//! Подписки: скачать, распознать формат, разобрать в список нод.
//!
//! Панель отдаёт разное в зависимости от того, кем представился клиент:
//! `clash-verge` получит YAML, `v2rayNG` — base64 со ссылками, `sing-box` —
//! готовый JSON. Поэтому запрос повторяется с разными User-Agent, пока не
//! придёт то, что мы умеем разобрать. Это и есть «понимает любую подписку»:
//! не угадать формат, а перебрать личины и разобрать всё, что прислали.
//!
//! Отдельная история — панели с учётом устройств (Remnawave и подобные). Они
//! отдают настоящие ноды только клиенту, который присылает идентификатор
//! устройства в заголовке `x-hwid`; всем остальным приходит заглушка вида
//! «Приложение не поддерживается». Поэтому идентификатор у нас есть свой,
//! постоянный, и уходит с каждым запросом — как это делает Happ.

use crate::json::{self, Json};
use std::process::Command;
use std::time::Duration;

/// Личины по убыванию удобства ответа: чем раньше в списке, тем меньше
/// догадок при разборе.
const AGENTS: &[&str] = &[
    "sing-box/1.13.0",
    "Happ/2.0.0",
    "v2rayNG/1.9.0",
    "clash-verge/2.0.0",
    "Shadowrocket/2.2.0",
    "curl/8.0.0",
];

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
}

impl Kind {
    fn tag(&self) -> &'static str {
        match self {
            Kind::Vless => "vless",
            Kind::Vmess => "vmess",
            Kind::Trojan => "trojan",
            Kind::Shadowsocks => "shadowsocks",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Transport {
    Tcp,
    Ws { path: String, host: Option<String> },
    Grpc { service: String },
    HttpUpgrade { path: String, host: Option<String> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub name: String,
    pub kind: Kind,
    pub server: String,
    pub port: u16,
    /// uuid для vless/vmess, пароль для trojan/shadowsocks.
    pub secret: String,
    /// Метод шифрования shadowsocks.
    pub method: Option<String>,
    pub flow: Option<String>,
    pub tls: bool,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub fingerprint: Option<String>,
    pub insecure: bool,
    pub reality_key: Option<String>,
    pub reality_short_id: Option<String>,
    pub transport: Transport,
}

impl Node {
    fn blank(kind: Kind) -> Node {
        Node {
            name: String::new(),
            kind,
            server: String::new(),
            port: 443,
            secret: String::new(),
            method: None,
            flow: None,
            tls: false,
            sni: None,
            alpn: Vec::new(),
            fingerprint: None,
            insecure: false,
            reality_key: None,
            reality_short_id: None,
            transport: Transport::Tcp,
        }
    }

    fn valid(&self) -> bool {
        !self.server.is_empty() && !self.secret.is_empty() && self.port > 0
    }

    /// Outbound для конфига sing-box.
    pub fn to_outbound(&self) -> String {
        let mut fields = vec![
            format!("\"type\": {}", json::escape(self.kind.tag())),
            format!("\"tag\": {}", json::escape(&self.name)),
            format!("\"server\": {}", json::escape(&self.server)),
            format!("\"server_port\": {}", self.port),
        ];
        match self.kind {
            Kind::Vless => {
                fields.push(format!("\"uuid\": {}", json::escape(&self.secret)));
                if let Some(flow) = &self.flow {
                    fields.push(format!("\"flow\": {}", json::escape(flow)));
                }
                fields.push("\"packet_encoding\": \"xudp\"".into());
            }
            Kind::Vmess => {
                fields.push(format!("\"uuid\": {}", json::escape(&self.secret)));
                fields.push("\"security\": \"auto\"".into());
            }
            Kind::Trojan => fields.push(format!("\"password\": {}", json::escape(&self.secret))),
            Kind::Shadowsocks => {
                fields.push(format!(
                    "\"method\": {}",
                    json::escape(self.method.as_deref().unwrap_or("aes-128-gcm"))
                ));
                fields.push(format!("\"password\": {}", json::escape(&self.secret)));
            }
        }
        if self.tls {
            fields.push(format!("\"tls\": {}", self.tls_block()));
        }
        if let Some(transport) = self.transport_block() {
            fields.push(format!("\"transport\": {transport}"));
        }
        format!("{{{}}}", fields.join(", "))
    }

    fn tls_block(&self) -> String {
        let mut parts = vec!["\"enabled\": true".to_string()];
        let sni = self.sni.clone().unwrap_or_else(|| self.server.clone());
        parts.push(format!("\"server_name\": {}", json::escape(&sni)));
        if self.insecure {
            parts.push("\"insecure\": true".into());
        }
        if !self.alpn.is_empty() {
            let list: Vec<String> = self.alpn.iter().map(|a| json::escape(a)).collect();
            parts.push(format!("\"alpn\": [{}]", list.join(", ")));
        }
        if let Some(fp) = &self.fingerprint {
            parts.push(format!(
                "\"utls\": {{\"enabled\": true, \"fingerprint\": {}}}",
                json::escape(fp)
            ));
        }
        if let Some(key) = &self.reality_key {
            let mut reality = vec![
                "\"enabled\": true".to_string(),
                format!("\"public_key\": {}", json::escape(key)),
            ];
            if let Some(sid) = &self.reality_short_id {
                reality.push(format!("\"short_id\": {}", json::escape(sid)));
            }
            parts.push(format!("\"reality\": {{{}}}", reality.join(", ")));
        }
        format!("{{{}}}", parts.join(", "))
    }

    fn transport_block(&self) -> Option<String> {
        match &self.transport {
            Transport::Tcp => None,
            Transport::Ws { path, host } => {
                let mut parts = vec![
                    "\"type\": \"ws\"".to_string(),
                    format!("\"path\": {}", json::escape(path)),
                ];
                if let Some(h) = host {
                    parts.push(format!("\"headers\": {{\"Host\": {}}}", json::escape(h)));
                }
                Some(format!("{{{}}}", parts.join(", ")))
            }
            Transport::Grpc { service } => Some(format!(
                "{{\"type\": \"grpc\", \"service_name\": {}}}",
                json::escape(service)
            )),
            Transport::HttpUpgrade { path, host } => {
                let mut parts = vec![
                    "\"type\": \"httpupgrade\"".to_string(),
                    format!("\"path\": {}", json::escape(path)),
                ];
                if let Some(h) = host {
                    parts.push(format!("\"host\": {}", json::escape(h)));
                }
                Some(format!("{{{}}}", parts.join(", ")))
            }
        }
    }
}

/// Скачать подписку, перебирая личины, пока не разберётся хоть одна нода.
/// Что подписка рассказывает о себе: имя, трафик, срок, страница с
/// устройствами. Всё это лежит в заголовках ответа — их и читаем, тела не надо.
pub struct Info {
    pub title: Option<String>,
    pub used_bytes: u64,
    pub total_bytes: u64,
    pub expires: Option<i64>,
    pub page: Option<String>,
    pub support: Option<String>,
}

pub fn info(url: &str, timeout: Duration) -> Result<Info, String> {
    let hwid = hwid();
    let out = Command::new("curl")
        .args([
            "-sSL",
            "-o",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
            "-D",
            "-",
            "--connect-timeout",
            "10",
            "--max-time",
            &timeout.as_secs().to_string(),
            "-A",
            AGENTS[0],
            "-H",
            &format!("x-hwid: {hwid}"),
            "-H",
            &format!("x-device-os: {}", device_os()),
            "-H",
            &format!("x-ver-os: {}", os_version()),
            "-H",
            "x-device-model: netpult",
            url,
        ])
        .output()
        .map_err(|e| format!("curl не запустился: {e}"))?;
    if !out.status.success() {
        return Err("подписка не ответила".into());
    }
    Ok(parse_info(&String::from_utf8_lossy(&out.stdout)))
}

/// Разбор заголовков подписки. Вынесено отдельно ради проверок: формат
/// `subscription-userinfo` описан в договорённостях клиентов, а не в стандарте,
/// и лишнего доверия не заслуживает.
pub fn parse_info(headers: &str) -> Info {
    let mut info = Info {
        title: None,
        used_bytes: 0,
        total_bytes: 0,
        expires: None,
        page: None,
        support: None,
    };
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "profile-title" => {
                info.title = Some(match value.strip_prefix("base64:") {
                    Some(encoded) => base64_decode(encoded)
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                        .unwrap_or_else(|| value.to_string()),
                    None => value.to_string(),
                })
            }
            "profile-web-page-url" => info.page = Some(value.to_string()),
            "support-url" => info.support = Some(value.to_string()),
            "subscription-userinfo" => {
                for part in value.split(';') {
                    let Some((key, number)) = part.split_once('=') else {
                        continue;
                    };
                    let number = number.trim();
                    match key.trim() {
                        "upload" => info.used_bytes += number.parse().unwrap_or(0),
                        "download" => info.used_bytes += number.parse().unwrap_or(0),
                        "total" => info.total_bytes = number.parse().unwrap_or(0),
                        "expire" => info.expires = number.parse().ok().filter(|v| *v > 0),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    info
}

pub fn fetch(url: &str, timeout: Duration) -> Result<Vec<Node>, String> {
    let hwid = hwid();
    let mut last_error = String::from("подписка не ответила");
    for agent in AGENTS {
        let output = Command::new("curl")
            .args([
                "-fsSL",
                "--connect-timeout",
                "10",
                "--max-time",
                &timeout.as_secs().to_string(),
                "-A",
                agent,
                "-H",
                &format!("x-hwid: {hwid}"),
                "-H",
                &format!("x-device-os: {}", device_os()),
                "-H",
                &format!("x-ver-os: {}", os_version()),
                "-H",
                "x-device-model: netpult",
                url,
            ])
            .output()
            .map_err(|e| format!("curl не запустился: {e}"))?;
        if !output.status.success() {
            last_error = format!("подписка не отдалась (личина {agent})");
            continue;
        }
        let body = String::from_utf8_lossy(&output.stdout).to_string();
        match parse(&body) {
            Ok(nodes) if !nodes.is_empty() => {
                if let Some(message) = panel_message(&nodes) {
                    // Дальше перебирать личины смысла нет: панель ответила
                    // осмысленно, просто отказом.
                    return Err(format!("панель вместо нод прислала сообщение: {message}"));
                }
                return Ok(nodes);
            }
            Ok(_) => last_error = format!("под личиной {agent} пришёл пустой список"),
            Err(e) => last_error = format!("под личиной {agent}: {e}"),
        }
    }
    Err(last_error)
}

/// Панели с учётом устройств вместо отказа присылают «ноды»-заглушки на
/// несуществующем адресе, а текст кладут в имя: «Лимит устройств!», «Скачайте
/// Happ». Молча собрать из этого конфиг — худшее, что можно сделать: туннель
/// поднимется в никуда.
fn panel_message(nodes: &[Node]) -> Option<String> {
    let stub = |n: &Node| n.server == "0.0.0.0" || n.server == "127.0.0.1" || n.port <= 1;
    if !nodes.iter().all(stub) {
        return None;
    }
    let names: Vec<String> = nodes
        .iter()
        .map(|n| n.name.trim().to_string())
        .filter(|n| !n.is_empty())
        .collect();
    Some(if names.is_empty() {
        "ноды без адреса".to_string()
    } else {
        names.join(" / ")
    })
}

/// Постоянный идентификатор устройства. Панель считает по нему слоты, поэтому
/// он обязан переживать перезапуски: заводится один раз и лежит рядом с
/// остальным состоянием.
/// Файл с идентификатором устройства.
pub fn hwid_path() -> std::path::PathBuf {
    crate::config::state_dir().join("hwid")
}

/// Задать свой идентификатор устройства.
///
/// Нужно, когда панель считает один компьютер за два: у каждого приложения свой
/// hwid, и подписка видит Happ и пульт как разные устройства. Поставив пульту
/// тот же идентификатор, что и у соседа, занимаешь одно место вместо двух.
pub fn set_hwid(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.len() < 8 || !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("идентификатор — от восьми знаков, буквы, цифры и дефис".into());
    }
    crate::config::state_dir_ensure().map_err(|e| e.to_string())?;
    std::fs::write(hwid_path(), value).map_err(|e| e.to_string())?;
    Ok(value.to_string())
}

/// Забыть идентификатор: следующий запрос создаст новый. Панель посчитает это
/// новым устройством и займёт ещё одно место — поэтому только по просьбе.
pub fn reset_hwid() -> Result<String, String> {
    let _ = std::fs::remove_file(hwid_path());
    Ok(hwid())
}

pub fn hwid() -> String {
    let path = crate::config::state_dir().join("hwid");
    if let Ok(saved) = std::fs::read_to_string(&path) {
        let saved = saved.trim().to_string();
        if !saved.is_empty() {
            return saved;
        }
    }
    let generated = generate_hwid();
    let _ = crate::config::state_dir_ensure();
    let _ = std::fs::write(&path, &generated);
    generated
}

/// Идентификатор берётся из machine-id, если система его даёт, иначе из имени
/// узла и времени. Вид — как у Happ, шестнадцатеричная строка.
fn generate_hwid() -> String {
    let seed = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if seed.len() >= 32 {
        return seed[..32].to_string();
    }
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "netpult".into());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut hash: u128 = 0xcbf29ce484222325;
    for byte in host.bytes().chain(now.to_le_bytes()) {
        hash ^= byte as u128;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:032x}")
}

fn device_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(windows) {
        "windows"
    } else {
        "linux"
    }
}

fn os_version() -> String {
    let output = if cfg!(windows) {
        Command::new("cmd").args(["/C", "ver"]).output()
    } else {
        Command::new("uname").arg("-r").output()
    };
    output
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

/// Разобрать тело подписки в любом из ходовых форматов.
pub fn parse(body: &str) -> Result<Vec<Node>, String> {
    let text = body.trim();
    if text.is_empty() {
        return Err("пустой ответ".into());
    }
    if text.starts_with('{') || text.starts_with('[') {
        return parse_json(text);
    }
    if text.contains("proxies:") {
        return Ok(parse_clash(text));
    }
    if text.contains("://") {
        return Ok(parse_links(text));
    }
    // Остаётся base64-блоб — самый частый вид подписки.
    let decoded = base64_decode(text).ok_or("не base64 и не знакомый формат")?;
    let decoded = String::from_utf8_lossy(&decoded).to_string();
    if decoded.trim().starts_with('{') || decoded.trim().starts_with('[') {
        return parse_json(decoded.trim());
    }
    if decoded.contains("proxies:") {
        return Ok(parse_clash(&decoded));
    }
    Ok(parse_links(&decoded))
}

fn parse_links(text: &str) -> Vec<Node> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(parse_link)
        .filter(Node::valid)
        .collect()
}

/// Одна ссылка `vless://`, `vmess://`, `trojan://` или `ss://`.
pub fn parse_link(link: &str) -> Option<Node> {
    let (scheme, rest) = link.split_once("://")?;
    match scheme.to_ascii_lowercase().as_str() {
        "vless" => parse_userinfo_link(rest, Kind::Vless),
        "trojan" => parse_userinfo_link(rest, Kind::Trojan),
        "vmess" => parse_vmess(rest),
        "ss" => parse_ss(rest),
        _ => None,
    }
}

/// `vless://uuid@host:port?params#имя` — та же форма и у trojan.
fn parse_userinfo_link(rest: &str, kind: Kind) -> Option<Node> {
    let mut node = Node::blank(kind);
    let (main, fragment) = match rest.split_once('#') {
        Some((m, f)) => (m, Some(f)),
        None => (rest, None),
    };
    let (address, query) = match main.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (main, None),
    };
    let (secret, hostport) = address.split_once('@')?;
    node.secret = percent_decode(secret);
    let (host, port) = split_hostport(hostport)?;
    node.server = host;
    node.port = port;
    node.name = fragment
        .map(percent_decode)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("{}:{}", node.server, node.port));
    if let Some(query) = query {
        apply_query(&mut node, query);
    }
    // trojan почти всегда поверх TLS, даже когда параметр не указан.
    if node.kind == Kind::Trojan && !node.tls {
        node.tls = true;
    }
    Some(node)
}

fn apply_query(node: &mut Node, query: &str) {
    let mut ws_path = String::from("/");
    let mut ws_host = None;
    let mut grpc_service = String::new();
    let mut network = String::from("tcp");
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value);
        match key.to_ascii_lowercase().as_str() {
            "security" => match value.as_str() {
                "tls" => node.tls = true,
                "reality" => {
                    node.tls = true;
                    node.reality_key.get_or_insert_with(String::new);
                }
                _ => {}
            },
            "sni" | "peer" | "servername" => node.sni = Some(value),
            "alpn" => node.alpn = value.split(',').map(|a| a.trim().to_string()).collect(),
            "fp" => node.fingerprint = Some(value),
            "pbk" | "publickey" => {
                node.tls = true;
                node.reality_key = Some(value);
            }
            "sid" | "shortid" => node.reality_short_id = Some(value),
            "flow" => {
                if !value.is_empty() {
                    node.flow = Some(value)
                }
            }
            "allowinsecure" | "insecure" | "skip-cert-verify" => {
                node.insecure = value == "1" || value == "true"
            }
            "type" | "net" | "network" | "obfs" => network = value,
            "path" => ws_path = value,
            "host" => ws_host = Some(value),
            "servicename" | "service_name" => grpc_service = value,
            _ => {}
        }
    }
    node.transport = match network.as_str() {
        "ws" | "websocket" => Transport::Ws {
            path: ws_path,
            host: ws_host,
        },
        "grpc" => Transport::Grpc {
            service: grpc_service,
        },
        "httpupgrade" => Transport::HttpUpgrade {
            path: ws_path,
            host: ws_host,
        },
        _ => Transport::Tcp,
    };
    // Пустой ключ Reality означал бы «включено, но нечем» — такую ноду
    // sing-box не примет, лучше считать это обычным TLS.
    if node.reality_key.as_deref() == Some("") {
        node.reality_key = None;
    }
}

/// `vmess://` — base64 с JSON внутри (формат v2rayN).
fn parse_vmess(rest: &str) -> Option<Node> {
    let raw = base64_decode(rest.trim())?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let value = Json::parse(&text).ok()?;
    let mut node = Node::blank(Kind::Vmess);
    node.server = value.get("add")?.as_str()?;
    node.port = value.get("port")?.as_u16()?;
    node.secret = value.get("id")?.as_str()?;
    node.name = value
        .get("ps")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{}:{}", node.server, node.port));
    node.tls = matches!(
        value.get("tls").and_then(|v| v.as_str()).as_deref(),
        Some("tls")
    );
    node.sni = value
        .get("sni")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let host = value
        .get("host")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let path = value
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| "/".into());
    node.transport = match value.get("net").and_then(|v| v.as_str()).as_deref() {
        Some("ws") => Transport::Ws { path, host },
        Some("grpc") => Transport::Grpc { service: path },
        Some("httpupgrade") => Transport::HttpUpgrade { path, host },
        _ => Transport::Tcp,
    };
    Some(node)
}

/// `ss://` в обеих формах: целиком base64 и «base64-метод@хост:порт».
fn parse_ss(rest: &str) -> Option<Node> {
    let (main, fragment) = match rest.split_once('#') {
        Some((m, f)) => (m, Some(percent_decode(f))),
        None => (rest, None),
    };
    let main = main.split('?').next()?;
    let mut node = Node::blank(Kind::Shadowsocks);
    let (userinfo, hostport) = match main.split_once('@') {
        Some((u, h)) => (
            String::from_utf8(base64_decode(u).unwrap_or_else(|| u.as_bytes().to_vec())).ok()?,
            h.to_string(),
        ),
        None => {
            let decoded = String::from_utf8(base64_decode(main)?).ok()?;
            let (u, h) = decoded.split_once('@')?;
            (u.to_string(), h.to_string())
        }
    };
    let (method, password) = userinfo.split_once(':')?;
    node.method = Some(method.to_string());
    node.secret = password.to_string();
    let (host, port) = split_hostport(&hostport)?;
    node.server = host;
    node.port = port;
    node.name = fragment
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("{}:{}", node.server, node.port));
    Some(node)
}

/// JSON-подписки: выгрузка sing-box (`outbounds`), xray (`outbounds` со своей
/// схемой) и SIP008 (`servers`).
fn parse_json(text: &str) -> Result<Vec<Node>, String> {
    let value = Json::parse(text)?;
    let mut nodes = Vec::new();
    if let Some(servers) = value.get("servers") {
        for item in servers.arr() {
            let mut node = Node::blank(Kind::Shadowsocks);
            node.server = item
                .get("server")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            node.port = item
                .get("server_port")
                .and_then(|v| v.as_u16())
                .unwrap_or(0);
            node.secret = item
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            node.method = item.get("method").and_then(|v| v.as_str());
            node.name = item
                .get("remarks")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| format!("{}:{}", node.server, node.port));
            if node.valid() {
                nodes.push(node);
            }
        }
    }
    let outbounds = value
        .get("outbounds")
        .map(|v| v.arr().to_vec())
        .unwrap_or_else(|| value.arr().to_vec());
    for item in &outbounds {
        if let Some(node) = node_from_outbound(item) {
            nodes.push(node);
        }
    }
    if nodes.is_empty() {
        return Err("в JSON не нашлось ни одной ноды".into());
    }
    Ok(nodes)
}

fn node_from_outbound(item: &Json) -> Option<Node> {
    let kind = match item
        .get("type")
        .or_else(|| item.get("protocol"))?
        .as_str()?
        .as_str()
    {
        "vless" => Kind::Vless,
        "vmess" => Kind::Vmess,
        "trojan" => Kind::Trojan,
        "shadowsocks" => Kind::Shadowsocks,
        _ => return None,
    };
    let mut node = Node::blank(kind);
    node.name = item
        .get("tag")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| "нода".into());
    // Схема sing-box: поля прямо в объекте. Схема xray: внутри settings.vnext.
    if let (Some(server), Some(port)) = (
        item.get("server").and_then(|v| v.as_str()),
        item.get("server_port").and_then(|v| v.as_u16()),
    ) {
        node.server = server;
        node.port = port;
        node.secret = item
            .get("uuid")
            .or_else(|| item.get("password"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        node.method = item.get("method").and_then(|v| v.as_str());
        node.flow = item
            .get("flow")
            .and_then(|v| v.as_str())
            .filter(|f| !f.is_empty());
        if let Some(tls) = item.get("tls") {
            node.tls = tls
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            node.sni = tls.get("server_name").and_then(|v| v.as_str());
            node.insecure = tls
                .get("insecure")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            node.alpn = tls
                .get("alpn")
                .map(|a| a.arr().iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            node.fingerprint = tls
                .get("utls")
                .and_then(|u| u.get("fingerprint"))
                .and_then(|v| v.as_str());
            if let Some(reality) = tls.get("reality") {
                node.reality_key = reality.get("public_key").and_then(|v| v.as_str());
                node.reality_short_id = reality.get("short_id").and_then(|v| v.as_str());
            }
        }
        if let Some(transport) = item.get("transport") {
            let path = transport
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| "/".into());
            let host = transport
                .get("headers")
                .and_then(|h| h.get("Host"))
                .and_then(|v| v.as_str())
                .or_else(|| transport.get("host").and_then(|v| v.as_str()));
            node.transport = match transport.get("type").and_then(|v| v.as_str()).as_deref() {
                Some("ws") => Transport::Ws { path, host },
                Some("grpc") => Transport::Grpc {
                    service: transport
                        .get("service_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default(),
                },
                Some("httpupgrade") => Transport::HttpUpgrade { path, host },
                _ => Transport::Tcp,
            };
        }
    } else {
        let settings = item.get("settings")?;
        let peer = settings
            .get("vnext")
            .or_else(|| settings.get("servers"))?
            .arr()
            .first()?
            .clone();
        node.server = peer.get("address").and_then(|v| v.as_str())?;
        node.port = peer.get("port").and_then(|v| v.as_u16())?;
        if let Some(user) = peer.get("users").and_then(|u| u.arr().first().cloned()) {
            node.secret = user
                .get("id")
                .or_else(|| user.get("password"))
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            node.flow = user
                .get("flow")
                .and_then(|v| v.as_str())
                .filter(|f| !f.is_empty());
        } else {
            node.secret = peer
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            node.method = peer.get("method").and_then(|v| v.as_str());
        }
        if let Some(stream) = item.get("streamSettings") {
            let security = stream
                .get("security")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            node.tls = security == "tls" || security == "reality";
            let tls_settings = stream
                .get("tlsSettings")
                .or_else(|| stream.get("realitySettings"));
            if let Some(t) = tls_settings {
                node.sni = t.get("serverName").and_then(|v| v.as_str());
                node.fingerprint = t.get("fingerprint").and_then(|v| v.as_str());
                node.reality_key = t.get("publicKey").and_then(|v| v.as_str());
                node.reality_short_id = t.get("shortId").and_then(|v| v.as_str());
                node.insecure = t
                    .get("allowInsecure")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
            }
            let network = stream
                .get("network")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            node.transport = match network.as_str() {
                "ws" => Transport::Ws {
                    path: stream
                        .get("wsSettings")
                        .and_then(|w| w.get("path"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_else(|| "/".into()),
                    host: stream
                        .get("wsSettings")
                        .and_then(|w| w.get("headers"))
                        .and_then(|h| h.get("Host"))
                        .and_then(|v| v.as_str()),
                },
                "grpc" => Transport::Grpc {
                    service: stream
                        .get("grpcSettings")
                        .and_then(|g| g.get("serviceName"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default(),
                },
                _ => Transport::Tcp,
            };
        }
    }
    node.valid().then_some(node)
}

/// Clash / Clash.Meta YAML: нужен только блок `proxies:`, и притом в двух
/// начертаниях — поток `{a: 1, b: 2}` и обычные вложенные строки. Полный YAML
/// тут не нужен, а его разбор — отдельная библиотека.
fn parse_clash(text: &str) -> Vec<Node> {
    let mut nodes = Vec::new();
    let mut inside = false;
    let mut current: Vec<(String, String)> = Vec::new();
    let flush = |fields: &mut Vec<(String, String)>, nodes: &mut Vec<Node>| {
        if let Some(node) = clash_node(fields) {
            nodes.push(node);
        }
        fields.clear();
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("proxies:") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        // Следующий корневой ключ (без отступа и не элемент списка) закрывает блок.
        if !line.starts_with([' ', '\t', '-']) && !trimmed.is_empty() {
            break;
        }
        if trimmed.starts_with('-') {
            flush(&mut current, &mut nodes);
            let body = trimmed.trim_start_matches('-').trim();
            let body = body.trim_start_matches('{').trim_end_matches('}');
            for pair in split_flow(body) {
                if let Some((k, v)) = pair.split_once(':') {
                    current.push((k.trim().to_string(), clean_yaml(v)));
                }
            }
        } else if let Some((k, v)) = trimmed.split_once(':') {
            current.push((k.trim().to_string(), clean_yaml(v)));
        }
    }
    flush(&mut current, &mut nodes);
    nodes
}

/// Разделить `a: 1, b: 2` по запятым верхнего уровня.
fn split_flow(body: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut current = String::new();
    for c in body.chars() {
        match c {
            '{' | '[' => {
                depth += 1;
                current.push(c);
            }
            '}' | ']' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                parts.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    parts
}

fn clean_yaml(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(&[',', '}'][..])
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn clash_node(fields: &[(String, String)]) -> Option<Node> {
    let get = |key: &str| {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
    };
    let kind = match get("type")?.as_str() {
        "vless" => Kind::Vless,
        "vmess" => Kind::Vmess,
        "trojan" => Kind::Trojan,
        "ss" | "shadowsocks" => Kind::Shadowsocks,
        _ => return None,
    };
    let mut node = Node::blank(kind);
    node.server = get("server")?;
    node.port = get("port")?.parse().ok()?;
    node.secret = get("uuid").or_else(|| get("password"))?;
    node.method = get("cipher");
    node.flow = get("flow");
    node.name = get("name").unwrap_or_else(|| format!("{}:{}", node.server, node.port));
    node.tls = get("tls")
        .map(|v| v == "true")
        .unwrap_or(node.kind == Kind::Trojan);
    node.sni = get("servername").or_else(|| get("sni"));
    node.fingerprint = get("client-fingerprint");
    node.insecure = get("skip-cert-verify")
        .map(|v| v == "true")
        .unwrap_or(false);
    if let Some(key) = get("public-key") {
        node.tls = true;
        node.reality_key = Some(key);
        node.reality_short_id = get("short-id");
    }
    node.transport = match get("network").as_deref() {
        Some("ws") => Transport::Ws {
            path: get("path").unwrap_or_else(|| "/".into()),
            host: get("host"),
        },
        Some("grpc") => Transport::Grpc {
            service: get("grpc-service-name").unwrap_or_default(),
        },
        _ => Transport::Tcp,
    };
    node.valid().then_some(node)
}

fn split_hostport(text: &str) -> Option<(String, u16)> {
    // IPv6 записывается в скобках: [::1]:443
    if let Some(rest) = text.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.trim_start_matches(':').parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port) = text.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// base64 в обеих азбуках (обычной и URL-безопасной), с необязательным
/// выравниванием: подписки приходят и так, и так.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for c in text.chars() {
        if c.is_whitespace() || c == '=' {
            continue;
        }
        let value = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Имена нод у панелей повторяются, а тег в конфиге движка должен быть
/// уникальным — иначе он не стартует. Разводим сразу после разбора, чтобы
/// список для человека и конфиг для движка звали ноды одинаково.
pub fn dedupe_names(nodes: &mut [Node]) {
    let mut seen: Vec<String> = Vec::with_capacity(nodes.len());
    for node in nodes.iter_mut() {
        let base = if node.name.trim().is_empty() {
            format!("{}:{}", node.server, node.port)
        } else {
            node.name.trim().to_string()
        };
        let mut tag = base.clone();
        let mut n = 2;
        while seen.contains(&tag) {
            tag = format!("{base} {n}");
            n += 1;
        }
        seen.push(tag.clone());
        node.name = tag;
    }
}

/// Куда ложится разобранная подписка: сам конфиг движка и список нод для меню.
pub fn config_path() -> std::path::PathBuf {
    crate::config::state_dir().join("singbox.json")
}

pub fn nodes_path() -> std::path::PathBuf {
    crate::config::state_dir().join("nodes.list")
}

pub fn subscription_path() -> std::path::PathBuf {
    crate::config::state_dir().join("subscription")
}

/// Сохранить конфиг движка, список имён нод и саму ссылку — по ней подписка
/// обновляется потом одной командой.
/// Свой запас нод: всё, что когда-либо приходило в подписке или добавлялось
/// руками из файла.
///
/// Провайдер время от времени выводит рабочие ноды из подписки. Раз они ещё
/// отвечают, терять их незачем — запас живёт отдельно от подписки и переживает
/// её обновление. Хранится в том же виде, в каком sing-box читает outbounds:
/// пишем `to_outbound`, читаем своим же разбором подписки, без отдельного
/// формата и отдельных ошибок.
pub fn bank_path() -> std::path::PathBuf {
    crate::config::state_dir().join("nodes.json")
}

/// Через сколько молчания нода выпадает из запаса. Отвечавшая в этот срок
/// ещё может ожить; та, что молчит месяц, — уже вряд ли, а место занимает.
pub const PRUNE_AFTER_SECS: u64 = 30 * 24 * 60 * 60;

/// Нода в запасе и когда она последний раз отвечала.
#[derive(Debug, Clone)]
pub struct Kept {
    pub node: Node,
    /// Отметка времени последнего успешного отклика, секунды эпохи.
    pub last_ok: Option<u64>,
    /// Когда ноду впервые занесли в запас. Нужен, чтобы вычищать по сроку
    /// даже те, что не отвечали ни разу.
    pub first_seen: u64,
}

impl Kept {
    /// Сколько нода молчит: от последнего отклика, а если его не было — от
    /// момента, когда её впервые увидели.
    fn silent_for(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_ok.unwrap_or(self.first_seen))
    }
}

/// Ключ ноды: адрес с портом. Имя для этого не годится — провайдер
/// переименовывает ноды между выгрузками.
pub fn place(node: &Node) -> String {
    format!("{}:{}", node.server, node.port)
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Записать запас: сами ноды в виде outbounds плюс отметки откликов.
///
/// Формат нарочно совпадает с выгрузкой sing-box — читаем его тем же разбором
/// подписки, что и всё остальное, без отдельного парсера и отдельных ошибок.
/// Отметки лежат рядом отдельным полем, движку они не мешают.
pub fn save_bank(entries: &[Kept]) -> Result<(), String> {
    crate::config::state_dir_ensure().map_err(|e| format!("не создать каталог состояния: {e}"))?;
    let body: Vec<String> = entries.iter().map(|k| k.node.to_outbound()).collect();
    let seen: Vec<String> = entries
        .iter()
        .filter_map(|k| {
            k.last_ok
                .map(|t| format!("{}: {t}", json::escape(&place(&k.node))))
        })
        .collect();
    let first: Vec<String> = entries
        .iter()
        .map(|k| format!("{}: {}", json::escape(&place(&k.node)), k.first_seen))
        .collect();
    let text = format!(
        "{{\"outbounds\": [{}], \"seen\": {{{}}}, \"first\": {{{}}}}}",
        body.join(", "),
        seen.join(", "),
        first.join(", ")
    );
    std::fs::write(bank_path(), text).map_err(|e| format!("не записать запас нод: {e}"))
}

/// Запас с диска. Нет файла или он битый — считаем, что запаса нет: это не
/// повод рушить обновление подписки.
pub fn load_bank() -> Vec<Kept> {
    let Ok(text) = std::fs::read_to_string(bank_path()) else {
        return Vec::new();
    };
    let Ok(nodes) = parse(&text) else {
        return Vec::new();
    };
    let root = Json::parse(&text).ok();
    let seen = root.as_ref().and_then(|j| j.get("seen").cloned());
    let first = root.as_ref().and_then(|j| j.get("first").cloned());
    let now = now_secs();
    let stamp = |map: &Option<Json>, node: &Node| {
        map.as_ref()
            .and_then(|s| s.get(&place(node)))
            .and_then(|v| match v {
                crate::json::Json::Num(n) => Some(*n as u64),
                _ => None,
            })
    };
    nodes
        .into_iter()
        .map(|node| {
            let last_ok = stamp(&seen, &node);
            // Файл со старой версии поля «first» не имел — берём отметку
            // отклика, а её нет — считаем, что нода только что попала в запас.
            let first_seen = stamp(&first, &node).or(last_ok).unwrap_or(now);
            Kept {
                node,
                last_ok,
                first_seen,
            }
        })
        .collect()
}

/// Дописать в запас ноды, которых там ещё нет.
pub fn add_missing(bank: &mut Vec<Kept>, extra: &[Node]) -> usize {
    let now = now_secs();
    let mut added = 0;
    for node in extra {
        if bank.iter().any(|k| place(&k.node) == place(node)) {
            continue;
        }
        bank.push(Kept {
            node: node.clone(),
            last_ok: None,
            first_seen: now,
        });
        added += 1;
    }
    added
}

/// Итог сведе́ния свежих нод из подписок с прежним активным списком и запасом.
#[derive(Debug, Default)]
pub struct Reconciled {
    /// Что кладём в конфиг движка: свежие + пережившие проверку + поднятые
    /// из запаса.
    pub active: Vec<Node>,
    /// Обновлённый запас: всё виденное, минус вычищенное по сроку молчания.
    pub bank: Vec<Kept>,
    /// Ноды, которых в прошлом активном списке не было.
    pub added: Vec<String>,
    /// Поднятые из запаса обратно в работу.
    pub revived: Vec<String>,
    /// Подписка перестала их отдавать, но они ещё отвечают — оставлены в работе.
    pub carried: Vec<String>,
    /// Подписка перестала их отдавать и они молчат — ушли в запас.
    pub parked: Vec<String>,
    /// Вычищены из запаса по сроку молчания.
    pub pruned: Vec<String>,
}

/// Свести свежий список нод из подписок с тем, что было в работе, и с запасом.
///
///   * свежая нода из подписки — всегда в работе;
///   * нода, которую подписка больше не отдаёт: отвечает — остаётся в работе,
///     молчит — уходит в запас;
///   * нода из запаса, которой нет в подписке, но она снова отвечает и в
///     работе её нет, — поднимается обратно;
///   * из запаса вычищается всё, что молчит дольше [`PRUNE_AFTER_SECS`].
///
/// Отклик проверяется через [`responds`] с таймаутом `probe`. Функция сама
/// никуда не пишет — только считает; запись остаётся на вызывающем.
pub fn reconcile(
    fresh: &[Node],
    prev_active: &[Node],
    mut bank: Vec<Kept>,
    probe: std::time::Duration,
) -> Reconciled {
    let now = now_secs();
    let fresh_places: Vec<String> = fresh.iter().map(place).collect();
    let prev_places: Vec<String> = prev_active.iter().map(place).collect();

    let mut active: Vec<Node> = fresh.to_vec();
    let mut active_places: Vec<String> = fresh_places.clone();
    let mut carried = Vec::new();
    let mut parked = Vec::new();

    // Ноды прежнего списка, которых подписка больше не отдаёт.
    for node in prev_active {
        let p = place(node);
        if fresh_places.contains(&p) {
            continue;
        }
        if responds(node, probe) {
            carried.push(node.name.clone());
            active.push(node.clone());
            active_places.push(p);
        } else {
            parked.push(node.name.clone());
        }
    }

    // В запас дописываем всё виденное: и свежее, и то, что было в работе.
    add_missing(&mut bank, fresh);
    add_missing(&mut bank, prev_active);

    // Поднять из запаса живых, которых сейчас нет в работе.
    let mut revived = Vec::new();
    for kept in bank.iter_mut() {
        let p = place(&kept.node);
        if active_places.contains(&p) {
            kept.last_ok = Some(now);
            continue;
        }
        if responds(&kept.node, probe) {
            kept.last_ok = Some(now);
            revived.push(kept.node.name.clone());
            active.push(kept.node.clone());
            active_places.push(p);
        }
    }

    // Вычистка запаса по сроку молчания. То, что сейчас в работе, не трогаем.
    let mut pruned = Vec::new();
    bank.retain(|kept| {
        if active_places.contains(&place(&kept.node)) {
            return true;
        }
        if kept.silent_for(now) > PRUNE_AFTER_SECS {
            pruned.push(kept.node.name.clone());
            return false;
        }
        true
    });

    // Что нового относительно прошлого активного списка.
    let added: Vec<String> = active
        .iter()
        .filter(|n| !prev_places.contains(&place(n)))
        .map(|n| n.name.clone())
        .collect();

    Reconciled {
        active,
        bank,
        added,
        revived,
        carried,
        parked,
        pruned,
    }
}

/// Выкинуть из запаса по имени или по адресу с портом. Возвращает выкинутые.
pub fn drop_from_bank(bank: &mut Vec<Kept>, what: &str) -> Vec<String> {
    let want = what.trim();
    let mut gone = Vec::new();
    bank.retain(|k| {
        let hit = k.node.name == want || place(&k.node) == want;
        if hit {
            gone.push(k.node.name.clone());
        }
        !hit
    });
    gone
}

/// Отвечает ли нода.
///
/// Сначала спрашиваем ядро: если оно поднято и знает эту ноду, clash API даст
/// честную задержку через сам туннель. Ядра нет — стучимся в адрес с портом
/// напрямую. Это слабее полноценной проверки (сервер может быть жив, а доступ
/// по нему уже отозван), но отсекает главное: ноды, чей сервер исчез или
/// закрыл порт.
pub fn responds(node: &Node, timeout: std::time::Duration) -> bool {
    if crate::singbox::delay(&node.name, timeout.as_millis() as u32).is_some() {
        return true;
    }
    let target = format!("{}:{}", node.server, node.port);
    let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&target) else {
        return false;
    };
    for addr in addrs {
        if std::net::TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return true;
        }
    }
    false
}

pub fn save(url: &str, nodes: &[Node], config: &str) -> Result<std::path::PathBuf, String> {
    crate::config::state_dir_ensure().map_err(|e| format!("не создать каталог состояния: {e}"))?;
    let path = config_path();
    std::fs::write(&path, config).map_err(|e| format!("не записать конфиг: {e}"))?;
    let names: Vec<&str> = nodes.iter().map(|n| n.name.as_str()).collect();
    std::fs::write(nodes_path(), names.join("\n"))
        .map_err(|e| format!("не записать список нод: {e}"))?;
    std::fs::write(subscription_path(), url)
        .map_err(|e| format!("не записать ссылку подписки: {e}"))?;
    Ok(path)
}

/// Ссылка подписки, сохранённая при разборе: по ней подписка обновляется.
pub fn saved_url() -> Result<String, String> {
    std::fs::read_to_string(subscription_path())
        .map(|s| s.trim().to_string())
        .map_err(|_| "подписка ещё не загружена — net vpn sub <ссылка>".to_string())
}

/// Ноды из уже собранного конфига движка. Нужны как «что было в работе» для
/// [`reconcile`]. Конфига нет или он битый — считаем, что в работе пусто.
pub fn current_nodes() -> Vec<Node> {
    std::fs::read_to_string(config_path())
        .ok()
        .and_then(|text| parse(&text).ok())
        .unwrap_or_default()
}

/// Путь журнала обновлений подписок.
pub fn refresh_log_path() -> std::path::PathBuf {
    crate::config::state_dir().join("sub.log")
}

/// Ноды из сохранённого списка. Полный разбор конфига для меню не нужен —
/// движку он нужен целиком, а человеку только имена.
pub fn load_nodes() -> Result<Vec<SavedNode>, String> {
    let text = std::fs::read_to_string(nodes_path())
        .map_err(|_| "подписка ещё не загружена — net vpn sub <ссылка>")?;
    Ok(text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| SavedNode {
            name: l.to_string(),
        })
        .collect())
}

pub struct SavedNode {
    pub name: String,
}

#[cfg(test)]
mod bank_tests {
    use super::*;

    fn нода(name: &str, server: &str, port: u16) -> Node {
        let mut n = parse_link(&format!("vless://uuid@{server}:{port}#{name}")).unwrap();
        n.name = name.to_string();
        n
    }

    fn запись(node: Node) -> Kept {
        Kept {
            node,
            last_ok: None,
            first_seen: now_secs(),
        }
    }

    #[test]
    fn запас_узнаёт_ноду_по_адресу_а_не_по_имени() {
        let mut bank = vec![запись(нода("Старое имя", "a.example", 443))];
        // Та же машина под новым именем — дубля быть не должно.
        let added = add_missing(&mut bank, &[нода("Новое имя", "a.example", 443)]);
        assert_eq!(added, 0);
        assert_eq!(bank.len(), 1);
        // Другой порт — уже другая нода.
        let added = add_missing(&mut bank, &[нода("Другая", "a.example", 8443)]);
        assert_eq!(added, 1);
    }

    #[test]
    fn из_запаса_убирают_и_по_имени_и_по_адресу() {
        let mut bank = vec![
            запись(нода("Первая", "a.example", 443)),
            запись(нода("Вторая", "b.example", 443)),
        ];
        assert_eq!(drop_from_bank(&mut bank, "Первая"), vec!["Первая"]);
        assert_eq!(drop_from_bank(&mut bank, "b.example:443"), vec!["Вторая"]);
        assert!(bank.is_empty());
        assert!(drop_from_bank(&mut bank, "чего нет").is_empty());
    }

    // Адреса вида *.example не резолвятся, поэтому в тестах любая нода
    // считается молчащей — это и проверяем на путях parked/pruned/added.
    const МИГ: std::time::Duration = std::time::Duration::from_millis(1);

    #[test]
    fn свежие_ноды_попадают_в_актив_и_в_новые() {
        let fresh = vec![нода("A", "a.example", 443), нода("B", "b.example", 443)];
        let r = reconcile(&fresh, &[], Vec::new(), МИГ);
        assert_eq!(r.active.len(), 2);
        assert_eq!(r.added.len(), 2);
        assert_eq!(r.bank.len(), 2);
    }

    #[test]
    fn выпавшая_из_подписки_молчащая_уходит_в_запас() {
        let prev = vec![нода("Старая", "old.example", 443)];
        let fresh = vec![нода("Новая", "new.example", 443)];
        let r = reconcile(&fresh, &prev, Vec::new(), МИГ);
        assert!(r.active.iter().all(|n| n.name != "Старая"));
        assert_eq!(r.parked, vec!["Старая"]);
        assert!(r.carried.is_empty());
    }

    #[test]
    fn давно_молчащая_нода_вычищается_из_запаса() {
        let труп = Kept {
            node: нода("Труп", "dead.example", 443),
            last_ok: Some(now_secs().saturating_sub(PRUNE_AFTER_SECS + 100)),
            first_seen: now_secs().saturating_sub(PRUNE_AFTER_SECS + 200),
        };
        let свежая = Kept {
            node: нода("Свежий", "fresh.example", 443),
            last_ok: Some(now_secs()),
            first_seen: now_secs(),
        };
        let r = reconcile(&[], &[], vec![труп, свежая], МИГ);
        assert_eq!(r.pruned, vec!["Труп"]);
        assert!(r.bank.iter().any(|k| k.node.name == "Свежий"));
        assert_eq!(r.bank.len(), 1);
    }

    #[test]
    fn нода_в_подписке_защищена_от_вычистки() {
        let древняя = Kept {
            node: нода("Древний", "x.example", 443),
            last_ok: Some(0),
            first_seen: 0,
        };
        let fresh = vec![нода("Древний", "x.example", 443)];
        let r = reconcile(&fresh, &[], vec![древняя], МИГ);
        assert!(r.pruned.is_empty());
        assert!(r.bank.iter().any(|k| k.node.name == "Древний"));
    }
}

#[cfg(test)]
mod info_tests {
    use super::*;

    const HEADERS: &str = "HTTP/2 200\r\n\
profile-title: base64:0J/QvtC00L/QuNGB0LrQsA==\r\n\
subscription-userinfo: upload=100; download=900; total=0; expire=1792021685\r\n\
profile-web-page-url: https://panel.example/sub/abc\r\n\
support-url: https://t.me/example\r\n";

    #[test]
    fn заголовки_подписки_разбираются() {
        let info = parse_info(HEADERS);
        assert_eq!(info.title.as_deref(), Some("Подписка"));
        assert_eq!(info.used_bytes, 1000);
        assert_eq!(info.total_bytes, 0);
        assert_eq!(info.expires, Some(1792021685));
        assert_eq!(info.page.as_deref(), Some("https://panel.example/sub/abc"));
        assert_eq!(info.support.as_deref(), Some("https://t.me/example"));
    }

    #[test]
    fn пустой_срок_не_считается_сроком() {
        let info = parse_info("subscription-userinfo: expire=0\r\n");
        assert_eq!(info.expires, None);
    }

    #[test]
    fn чужие_заголовки_не_мешают() {
        let info = parse_info("server: nginx\r\ncontent-type: text/plain\r\n");
        assert!(info.title.is_none() && info.used_bytes == 0);
    }

    #[test]
    fn короткий_идентификатор_не_принимается() {
        assert!(set_hwid("abc").is_err());
        assert!(set_hwid("плохой id").is_err());
    }
}
