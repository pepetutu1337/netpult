//! Сплит-прокси: через ноду только нужные домены, остальное напрямую.
//!
//! Ровно то, что делает домашний роутер. netpult поднимает локальный
//! HTTP-прокси; для каждого соединения смотрит на имя хоста и решает:
//!   в списке — отправить в заграничный SOCKS (его держит VPN-клиент);
//!   нет — соединиться напрямую, быстро, без крюка за границу.
//!
//! Заграничный SOCKS не поднимаем сами: у Happ он уже слушает
//! `127.0.0.1:10808`, когда выбрана нода. Так HWID-замок Happ не трогается и
//! ротация нод работает сама.

use crate::config::{Config, state_dir};
use crate::socks;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

pub const DEFAULT_PORT: u16 = 8898;
pub const DEFAULT_UPSTREAM: &str = "127.0.0.1:10808";

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Список доменов, идущих через ноду. Подстрочное совпадение по суффиксу:
/// `openai.com` ловит и `api.openai.com`, и `chat.openai.com`.
pub struct DomainList {
    suffixes: Vec<String>,
}

impl DomainList {
    /// Грузит несколько файлов в один список (ручной + автосписок геоблока).
    pub fn load_all(paths: &[std::path::PathBuf]) -> DomainList {
        let text = paths
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .collect::<Vec<_>>()
            .join("\n");
        DomainList::parse(&text)
    }

    pub fn parse(text: &str) -> DomainList {
        let suffixes = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.trim_start_matches("*.").to_ascii_lowercase())
            .collect();
        DomainList { suffixes }
    }

    /// Идёт ли хост через ноду.
    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.suffixes
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
    }
}

/// Ручной список — правит человек, автообновление его не трогает.
pub fn list_path() -> std::path::PathBuf {
    state_dir().join("split-domains.list")
}

pub fn log_path() -> std::path::PathBuf {
    state_dir().join("split.log")
}

/// Пишет решение маршрутизации в лог, чтобы потом видеть, что шло через ноду,
/// а что напрямую. Лог сам себя подрезает, чтобы не разрастаться без предела.
fn log_decision(host: &str, via_node: bool) {
    use std::io::Write;
    let mark = if via_node {
        "нода  "
    } else {
        "прямо "
    };
    let stamp = std::process::Command::new("date")
        .arg("+%H:%M:%S")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let path = log_path();

    // Раз в сотню запросов подрезаем хвост, оставляя последние ~500 строк.
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() > 200_000
        && let Ok(text) = std::fs::read_to_string(&path)
    {
        let tail: Vec<&str> = text.lines().rev().take(500).collect();
        let trimmed: String = tail.into_iter().rev().collect::<Vec<_>>().join("\n") + "\n";
        std::fs::write(&path, trimmed).ok();
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        writeln!(f, "{stamp}  {mark}  {host}").ok();
    }
}

/// Автосписок геоблока — перезаписывается `net split update`.
pub fn geoblock_path() -> std::path::PathBuf {
    state_dir().join("split-geoblock.list")
}

/// Оба списка, которые читает прокси.
pub fn all_list_paths() -> Vec<std::path::PathBuf> {
    vec![list_path(), geoblock_path()]
}

/// Источники автосписка ушедших из РФ сервисов (itdoginfo/allow-domains).
///
/// Первым — сам GitHub: из РФ он доступен, это проверено запросом с
/// российского адреса (301 от raw.githubusercontent.com). Раньше первым стояло
/// зеркало jsDelivr «потому что GitHub недоступен» — неправда, и она стоила
/// лишней зависимости от чужого CDN на ровном месте.
///
/// Зеркала следом: список — единственное, откуда берутся новые уехавшие
/// сервисы, и его молчание ничем не проявляется. Всё продолжает работать,
/// просто перестаёт узнавать новое.
pub const GEOBLOCK_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Categories/geoblock.lst",
    "https://cdn.jsdelivr.net/gh/itdoginfo/allow-domains@main/Categories/geoblock.lst",
    "https://fastly.jsdelivr.net/gh/itdoginfo/allow-domains@main/Categories/geoblock.lst",
    "https://gh-proxy.com/https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Categories/geoblock.lst",
];

/// Тянет автосписок геоблока и сохраняет его. Возвращает число доменов.
pub fn update_geoblock() -> Result<usize, String> {
    let mut body = String::new();
    for url in GEOBLOCK_URLS {
        if let Ok(out) = std::process::Command::new("curl")
            .args(["-fsSL", "--max-time", "30", url])
            .output()
            && out.status.success()
            && out.stdout.len() > 1000
        {
            body = String::from_utf8_lossy(&out.stdout).into_owned();
            break;
        }
    }
    if body.is_empty() {
        return Err("не скачался список геоблока (все зеркала молчат)".into());
    }
    let domains: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && l.contains('.'))
        .collect();

    // Защита от битой загрузки: пустой/куцый ответ не затирает рабочий список.
    if domains.len() < 100 {
        return Err(format!(
            "подозрительно короткий список ({}), не сохраняю",
            domains.len()
        ));
    }

    std::fs::create_dir_all(state_dir()).map_err(|e| e.to_string())?;
    let header = "# Автосписок геоблока (itdoginfo/allow-domains). Не править руками —\n\
                  # перезаписывается командой net split update. Свои домены — в\n\
                  # split-domains.list.\n";
    let text = format!("{header}{}\n", domains.join("\n"));
    std::fs::write(geoblock_path(), text).map_err(|e| e.to_string())?;
    Ok(domains.len())
}

/// Домены по умолчанию: то, что режут по стране, а не по DPI.
pub const DEFAULT_DOMAINS: &str = "\
# Домены, которые ходят через заграничную ноду (сплит-прокси).
# Остальное идёт напрямую. Строка на домен; поддомены попадают сами.
openai.com
chatgpt.com
oaistatic.com
oaiusercontent.com
anthropic.com
claude.ai
gemini.google.com
aistudio.google.com
googleapis.com
";

pub fn ensure_default_list() -> std::io::Result<std::path::PathBuf> {
    let path = list_path();
    if !path.exists() {
        std::fs::create_dir_all(state_dir())?;
        std::fs::write(&path, DEFAULT_DOMAINS)?;
    }
    Ok(path)
}

/// Запускает сплит-прокси, пока процесс жив.
pub fn serve(cfg: &Config) -> Result<(), String> {
    let port = cfg.split_port;
    let upstream = cfg.split_upstream.clone();
    let list = std::sync::Arc::new(DomainList::load_all(&all_list_paths()));

    if !socks::reachable(&upstream, Duration::from_secs(2)) {
        eprintln!(
            "внимание: SOCKS ноды {upstream} не отвечает — проверяемые домены не откроются, \
             пока не подключишь VPN-клиент в режиме прокси"
        );
    }

    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("не занять порт {port}: {e}"))?;

    for incoming in listener.incoming() {
        let Ok(client) = incoming else { continue };
        let upstream = upstream.clone();
        let list = std::sync::Arc::clone(&list);
        std::thread::spawn(move || {
            if let Err(e) = handle(client, &upstream, &list)
                && std::env::var_os("NETPULT_DEBUG").is_some()
            {
                eprintln!("сплит: соединение оборвалось: {e}");
            }
        });
    }
    Ok(())
}

fn handle(mut client: TcpStream, upstream: &str, list: &DomainList) -> std::io::Result<()> {
    client.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    client.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;

    let mut reader = BufReader::new(client.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        headers.push(line);
    }

    let is_connect = method.eq_ignore_ascii_case("CONNECT");
    let (host, port) = if is_connect {
        parse_authority(&target, 443)
    } else {
        let (h, _) = split_absolute_url(&target);
        parse_authority(&h, 80)
    };

    let via_node = list.matches(&host);
    log_decision(&host, via_node);
    let upstream_stream = if via_node {
        socks::connect(upstream, &host, port, UPSTREAM_TIMEOUT).map_err(|e| {
            std::io::Error::other(format!("нода {upstream} не соединила с {host}: {e}"))
        })
    } else {
        TcpStream::connect((host.as_str(), port))
    };

    let upstream_stream = match upstream_stream {
        Ok(s) => s,
        Err(e) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return Err(e);
        }
    };
    upstream_stream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    upstream_stream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;

    if is_connect {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    } else {
        let (_, path) = split_absolute_url(&target);
        let mut head = format!("{method} {path} {version}\r\n");
        for line in &headers {
            if line.to_ascii_lowercase().starts_with("proxy-connection") {
                continue;
            }
            head.push_str(line);
        }
        head.push_str("\r\n");
        (&upstream_stream).write_all(head.as_bytes())?;
    }

    let leftover = reader.buffer().to_vec();
    if !leftover.is_empty() {
        (&upstream_stream).write_all(&leftover)?;
    }
    pump(client, upstream_stream)
}

fn pump(client: TcpStream, upstream: TcpStream) -> std::io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    let forward = std::thread::spawn(move || {
        copy(&mut client_read, &mut upstream_write);
        upstream_write.shutdown(Shutdown::Write).ok();
    });
    let mut upstream_read = upstream;
    let mut client_write = client;
    copy(&mut upstream_read, &mut client_write);
    client_write.shutdown(Shutdown::Write).ok();
    forward.join().ok();
    Ok(())
}

fn copy(from: &mut TcpStream, to: &mut TcpStream) {
    let mut buffer = [0u8; 32 * 1024];
    loop {
        match from.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buffer[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

fn parse_authority(authority: &str, default_port: u16) -> (String, u16) {
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            (host.to_string(), port.parse().unwrap_or(default_port))
        }
        _ => (authority.to_string(), default_port),
    }
}

fn split_absolute_url(target: &str) -> (String, String) {
    let without_scheme = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);
    match without_scheme.split_once('/') {
        Some((host, rest)) => (host.to_string(), format!("/{rest}")),
        None => (without_scheme.to_string(), "/".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_domains_and_subdomains() {
        let list = DomainList::parse("openai.com\n*.claude.ai\n# коммент\n");
        assert!(list.matches("openai.com"));
        assert!(list.matches("api.openai.com"));
        assert!(list.matches("chat.openai.com."));
        assert!(list.matches("claude.ai"));
        assert!(list.matches("www.claude.ai"));
        assert!(!list.matches("notopenai.com"));
        assert!(!list.matches("openai.com.evil.ru"));
        assert!(!list.matches("example.org"));
    }

    #[test]
    fn parses_authority() {
        assert_eq!(
            parse_authority("example.com:443", 80),
            ("example.com".into(), 443)
        );
        assert_eq!(
            parse_authority("example.com", 80),
            ("example.com".into(), 80)
        );
    }
}
