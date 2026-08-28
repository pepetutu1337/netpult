//! Проверки сети: адрес в локальной сети, внешний адрес, доступность сайтов.
//!
//! Запросы делает системный `curl`, а не своя криптобиблиотека, и это
//! осознанно. Стратегии zapret ломают часть TLS-клиентов: на `general_alt10`
//! соединение rustls с `www.youtube.com` намертво зависает, тогда как curl,
//! openssl и браузер проходят. Проверка на rustls показывала бы «не
//! открывается» там, где у человека всё работает. curl есть на всех трёх
//! системах (в Windows начиная с 10-й), и ведёт себя как настоящий клиент.

use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::process::Command;
use std::time::{Duration, Instant};

/// Адрес этой машины в локальной сети.
///
/// Никуда не отправляет ни байта: UDP-сокет без соединения только выбирает
/// маршрут, а нам нужен его локальный конец. Работает одинаково на всех системах.
pub fn lan_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    socket.local_addr().ok().map(|a| a.ip())
}

pub fn curl_available() -> bool {
    Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn curl(args: &[&str], timeout: Duration) -> Option<String> {
    let secs = timeout.as_secs().max(1).to_string();
    let out = Command::new("curl")
        .args(["-s", "--max-time", &secs])
        .args(args)
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        None
    }
}

/// Открывается ли адрес.
///
/// Адрес лучше брать лёгкий (`/generate_204` и подобные): тяжёлая страница
/// упирается в таймаут и даёт ложную тревогу.
pub fn reachable(url: &str, timeout: Duration) -> bool {
    let code = curl(&["-o", NULL_DEVICE, "-w", "%{http_code}", url], timeout);
    match code {
        // Любой ответ сервера значит, что соединение дошло и DPI его не убил.
        Some(text) => text.trim().parse::<u32>().map(|c| c > 0).unwrap_or(false),
        None => false,
    }
}

#[cfg(windows)]
const NULL_DEVICE: &str = "NUL";
#[cfg(not(windows))]
const NULL_DEVICE: &str = "/dev/null";

/// Слушает ли кто-то этот порт на этой машине.
pub fn port_open(port: u16, timeout: Duration) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, timeout).is_ok()
}

pub struct ExternalAddr {
    pub ip: String,
    pub country: String,
    pub org: String,
}

pub fn external_addr(timeout: Duration) -> Option<ExternalAddr> {
    let body = curl(&["https://ipinfo.io/json"], timeout)?;
    let field = |key: &str| -> String {
        body.split(&format!("\"{key}\""))
            .nth(1)
            .and_then(|rest| rest.split(':').nth(1))
            .and_then(|rest| rest.split('"').nth(1))
            .unwrap_or("?")
            .to_string()
    };
    Some(ExternalAddr {
        ip: field("ip"),
        country: field("country"),
        org: field("org"),
    })
}

/// Скорость скачивания с серверов Google, килобайты в секунду.
pub fn google_speed(timeout: Duration) -> Option<f64> {
    let start = Instant::now();
    let out = curl(
        &[
            "-o",
            NULL_DEVICE,
            "-w",
            "%{size_download}",
            "https://i.ytimg.com/vi/dQw4w9WgXcQ/maxresdefault.jpg",
        ],
        timeout,
    )?;
    let bytes: f64 = out.trim().parse().ok()?;
    let secs = start.elapsed().as_secs_f64();
    if bytes <= 0.0 || secs <= 0.0 {
        return None;
    }
    Some(bytes / 1024.0 / secs)
}
