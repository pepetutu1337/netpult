//! Раздача обхода на телефон.
//!
//! Поднимает на этой машине прокси, доступный из локальной сети. Телефон
//! указывает его в настройках Wi-Fi — и весь его трафик выходит в интернет с
//! этого компьютера, а значит, проходит через zapret и получает те же
//! стратегии обхода. Никакого VPN на телефоне не нужно.
//!
//! Протокол — HTTP: и `CONNECT` для HTTPS, и обычные запросы. Его понимают
//! настройки Wi-Fi и на Android, и на iOS. Реализация своя, без библиотек:
//! задача сводится к «соединить два сокета и перекладывать байты».

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_PORT: u16 = 8899;

/// Сколько ждать ответа от сайта, прежде чем считать соединение мёртвым.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Пароль для доступа к прокси, если он задан в настройках.
///
/// Без пароля прокси открыт всем, кто сидит в той же сети Wi-Fi. Дома это
/// обычно не страшно, в кафе или гостинице — страшно, поэтому пароль стоит
/// задать: `share_password = ...` в настройках.
pub struct Auth {
    expected: Option<String>,
}

impl Auth {
    pub fn new(password: Option<&str>) -> Self {
        Auth {
            expected: password
                .filter(|p| !p.is_empty())
                .map(|p| base64(format!("netpult:{p}").as_bytes())),
        }
    }

    fn allows(&self, headers: &[String]) -> bool {
        let Some(expected) = &self.expected else {
            return true;
        };
        headers.iter().any(|line| {
            line.to_ascii_lowercase().starts_with("proxy-authorization:")
                && line.split_whitespace().next_back() == Some(expected.as_str())
        })
    }
}

fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub struct Stats {
    pub connections: AtomicUsize,
}

/// Запускает прокси и обслуживает подключения, пока процесс жив.
pub fn serve(port: u16, password: Option<&str>) -> Result<(), String> {
    let auth = Arc::new(Auth::new(password));
    let listener = TcpListener::bind(("0.0.0.0", port))
        .map_err(|e| format!("не занять порт {port}: {e}"))?;
    let stats = Arc::new(Stats { connections: AtomicUsize::new(0) });

    for incoming in listener.incoming() {
        let Ok(client) = incoming else { continue };
        let stats = Arc::clone(&stats);
        let auth = Arc::clone(&auth);
        std::thread::spawn(move || {
            stats.connections.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = handle(client, &auth)
                && std::env::var_os("NETPULT_DEBUG").is_some() {
                    eprintln!("соединение оборвалось: {e}");
                }
        });
    }
    Ok(())
}

fn handle(mut client: TcpStream, auth: &Auth) -> std::io::Result<()> {
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

    // Заголовки читаем целиком: для обычных запросов их надо передать дальше.
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

    if !auth.allows(&headers) {
        client.write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"netpult\"\r\nContent-Length: 0\r\n\r\n",
        )?;
        return Ok(());
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        connect_tunnel(client, reader, &target)
    } else {
        plain_http(client, reader, &method, &target, &version, &headers)
    }
}

/// HTTPS: клиент просит трубу до сайта, дальше мы только переливаем байты.
fn connect_tunnel(
    mut client: TcpStream,
    reader: BufReader<TcpStream>,
    target: &str,
) -> std::io::Result<()> {
    let upstream = match TcpStream::connect(with_default_port(target, 443)) {
        Ok(s) => s,
        Err(e) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return Err(e);
        }
    };
    upstream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    upstream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;

    // В буфере читателя могли осесть первые байты рукопожатия — отдать их первыми.
    let leftover = reader.buffer().to_vec();
    if !leftover.is_empty() {
        (&upstream).write_all(&leftover)?;
    }
    pump(client, upstream)
}

/// Обычный HTTP: пересобираем запрос и отправляем сайту.
fn plain_http(
    client: TcpStream,
    reader: BufReader<TcpStream>,
    method: &str,
    target: &str,
    version: &str,
    headers: &[String],
) -> std::io::Result<()> {
    let (host, path) = split_absolute_url(target);
    let upstream = TcpStream::connect(with_default_port(&host, 80))?;
    upstream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    upstream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;

    let mut head = format!("{method} {path} {version}\r\n");
    for line in headers {
        // Заголовок для прокси дальше не нужен.
        if line.to_ascii_lowercase().starts_with("proxy-connection") {
            continue;
        }
        head.push_str(line);
    }
    head.push_str("\r\n");
    (&upstream).write_all(head.as_bytes())?;

    let leftover = reader.buffer().to_vec();
    if !leftover.is_empty() {
        (&upstream).write_all(&leftover)?;
    }
    pump(client, upstream)
}

/// Переливает байты в обе стороны, пока кто-нибудь не закроется.
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

fn with_default_port(target: &str, default: u16) -> String {
    if target.contains(':') && !target.ends_with(']') {
        target.to_string()
    } else {
        format!("{target}:{default}")
    }
}

/// `http://example.com/a?b` → (`example.com`, `/a?b`)
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
    fn splits_absolute_urls() {
        assert_eq!(
            split_absolute_url("http://example.com/a?b=1"),
            ("example.com".to_string(), "/a?b=1".to_string())
        );
        assert_eq!(
            split_absolute_url("http://example.com"),
            ("example.com".to_string(), "/".to_string())
        );
    }

    #[test]
    fn checks_proxy_password() {
        let open = Auth::new(None);
        assert!(open.allows(&[]));

        let closed = Auth::new(Some("хорошийпароль"));
        assert!(!closed.allows(&[]));
        let header = format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64("netpult:хорошийпароль".as_bytes())
        );
        assert!(closed.allows(&[header]));
        assert!(!closed.allows(&["Proxy-Authorization: Basic bm90aGluZw==\r\n".to_string()]));
    }

    #[test]
    fn encodes_base64_like_the_standard() {
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
        assert_eq!(base64(b"netpult:1234"), "bmV0cHVsdDoxMjM0");
    }

    #[test]
    fn adds_default_port() {
        assert_eq!(with_default_port("example.com", 443), "example.com:443");
        assert_eq!(with_default_port("example.com:8443", 443), "example.com:8443");
    }
}
