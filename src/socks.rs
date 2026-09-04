//! Клиент SOCKS5: соединиться с узлом через прокси (без аутентификации).
//!
//! Нужен, чтобы отдавать выбранные домены в заграничный SOCKS, который держит
//! VPN-клиент (у Happ это `127.0.0.1:10808`). Реализуем только команду CONNECT —
//! ровно это и требуется для сплита.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Открывает через SOCKS5-прокси соединение до `host:port`.
///
/// Хост передаётся прокси именем, а не адресом (тип 0x03): резолвит его сам
/// прокси на своей стороне — так к домену применяется маршрутизация ноды, а не
/// локальный DNS.
pub fn connect(
    proxy: &str,
    host: &str,
    port: u16,
    timeout: Duration,
) -> std::io::Result<TcpStream> {
    let proxy_addr = proxy
        .to_socket_addrs_first()
        .ok_or_else(|| std::io::Error::other(format!("плохой адрес прокси: {proxy}")))?;
    let mut stream = TcpStream::connect_timeout(&proxy_addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    // Приветствие: версия 5, один метод — без аутентификации.
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply)?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(std::io::Error::other("прокси не принял метод без пароля"));
    }

    // CONNECT к домену.
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(std::io::Error::other("слишком длинное имя хоста"));
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request)?;

    // Ответ: VER REP RSV ATYP BND.ADDR BND.PORT. Нас интересует REP.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "прокси отказал, код {}",
            head[1]
        )));
    }
    // Дочитываем связанный адрес, чтобы поток встал на начало данных.
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            len[0] as usize
        }
        other => {
            return Err(std::io::Error::other(format!(
                "неизвестный тип адреса {other}"
            )));
        }
    };
    let mut rest = vec![0u8; addr_len + 2];
    stream.read_exact(&mut rest)?;

    Ok(stream)
}

/// Мелкий помощник: первый разобранный адрес прокси.
trait FirstAddr {
    fn to_socket_addrs_first(&self) -> Option<std::net::SocketAddr>;
}

impl FirstAddr for str {
    fn to_socket_addrs_first(&self) -> Option<std::net::SocketAddr> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs().ok()?.next()
    }
}

/// Проверяет, что прокси на этом адресе отвечает по SOCKS5.
pub fn reachable(proxy: &str, timeout: Duration) -> bool {
    let Some(addr) = proxy.to_socket_addrs_first() else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, timeout) else {
        return false;
    };
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    if stream.write_all(&[0x05, 0x01, 0x00]).is_err() {
        return false;
    }
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).is_ok() && reply[0] == 0x05
}
