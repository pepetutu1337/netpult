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
                    parts.push(format!(
                        "\"headers\": {{\"Host\": {}}}",
                        json::escape(h)
                    ));
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
    node.tls = matches!(value.get("tls").and_then(|v| v.as_str()).as_deref(), Some("tls"));
    node.sni = value.get("sni").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let host = value.get("host").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
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
            node.server = item.get("server").and_then(|v| v.as_str()).unwrap_or_default();
            node.port = item.get("server_port").and_then(|v| v.as_u16()).unwrap_or(0);
            node.secret = item.get("password").and_then(|v| v.as_str()).unwrap_or_default();
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
    let kind = match item.get("type").or_else(|| item.get("protocol"))?.as_str()?.as_str() {
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
        node.flow = item.get("flow").and_then(|v| v.as_str()).filter(|f| !f.is_empty());
        if let Some(tls) = item.get("tls") {
            node.tls = tls.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            node.sni = tls.get("server_name").and_then(|v| v.as_str());
            node.insecure = tls.get("insecure").and_then(|v| v.as_bool()).unwrap_or(false);
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
            node.flow = user.get("flow").and_then(|v| v.as_str()).filter(|f| !f.is_empty());
        } else {
            node.secret = peer.get("password").and_then(|v| v.as_str()).unwrap_or_default();
            node.method = peer.get("method").and_then(|v| v.as_str());
        }
        if let Some(stream) = item.get("streamSettings") {
            let security = stream.get("security").and_then(|v| v.as_str()).unwrap_or_default();
            node.tls = security == "tls" || security == "reality";
            let tls_settings = stream
                .get("tlsSettings")
                .or_else(|| stream.get("realitySettings"));
            if let Some(t) = tls_settings {
                node.sni = t.get("serverName").and_then(|v| v.as_str());
                node.fingerprint = t.get("fingerprint").and_then(|v| v.as_str());
                node.reality_key = t.get("publicKey").and_then(|v| v.as_str());
                node.reality_short_id = t.get("shortId").and_then(|v| v.as_str());
                node.insecure = t.get("allowInsecure").and_then(|v| v.as_bool()).unwrap_or(false);
            }
            let network = stream.get("network").and_then(|v| v.as_str()).unwrap_or_default();
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
    node.tls = get("tls").map(|v| v == "true").unwrap_or(node.kind == Kind::Trojan);
    node.sni = get("servername").or_else(|| get("sni"));
    node.fingerprint = get("client-fingerprint");
    node.insecure = get("skip-cert-verify").map(|v| v == "true").unwrap_or(false);
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
