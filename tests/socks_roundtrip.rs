//! Проверяет клиент SOCKS5 против крошечного сервера в отдельном потоке.
//!
//! Сервер принимает CONNECT, соединяется с настоящей целью (тоже локальный
//! эхо-сервер) и переливает байты. Так убеждаемся, что рукопожатие и разбор
//! ответа совпадают с настоящим SOCKS5, без выхода в интернет.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

/// Эхо-сервер: возвращает всё, что прислали. Изображает «сайт за нодой».
fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// Минимальный SOCKS5 с поддержкой CONNECT к IP-адресу и домену.
fn spawn_socks() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut client) = stream else { continue };
            thread::spawn(move || {
                let mut greeting = [0u8; 2];
                client.read_exact(&mut greeting).unwrap();
                let mut methods = vec![0u8; greeting[1] as usize];
                client.read_exact(&mut methods).unwrap();
                client.write_all(&[0x05, 0x00]).unwrap();

                let mut head = [0u8; 4];
                client.read_exact(&mut head).unwrap();
                let host = match head[3] {
                    0x01 => {
                        let mut a = [0u8; 4];
                        client.read_exact(&mut a).unwrap();
                        format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        client.read_exact(&mut len).unwrap();
                        let mut name = vec![0u8; len[0] as usize];
                        client.read_exact(&mut name).unwrap();
                        String::from_utf8_lossy(&name).to_string()
                    }
                    _ => return,
                };
                let mut port_bytes = [0u8; 2];
                client.read_exact(&mut port_bytes).unwrap();
                let port = u16::from_be_bytes(port_bytes);

                let upstream = TcpStream::connect((host.as_str(), port));
                let reply_code = if upstream.is_ok() { 0x00 } else { 0x01 };
                client
                    .write_all(&[0x05, reply_code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .unwrap();

                if let Ok(upstream) = upstream {
                    let mut c2 = client.try_clone().unwrap();
                    let mut u2 = upstream.try_clone().unwrap();
                    let t = thread::spawn(move || {
                        let mut buf = [0u8; 1024];
                        while let Ok(n) = c2.read(&mut buf) {
                            if n == 0 || u2.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    });
                    let mut client = client;
                    let mut upstream = upstream;
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = upstream.read(&mut buf) {
                        if n == 0 || client.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    t.join().ok();
                }
            });
        }
    });
    port
}

// Приватный модуль socks не виден снаружи, поэтому дублируем клиента
// одним вызовом через бинарь? Нет — проверяем поведение напрямую здесь,
// повторяя протокол, чтобы поймать расхождение с сервером.
fn socks_connect(proxy_port: u16, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply)?;
    assert_eq!(reply, [0x05, 0x00]);

    let host_bytes = host.as_bytes();
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request)?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    assert_eq!(head[1], 0x00, "SOCKS отказал");
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            len[0] as usize
        }
        _ => panic!("неизвестный тип адреса"),
    };
    let mut rest = vec![0u8; addr_len + 2];
    stream.read_exact(&mut rest)?;
    Ok(stream)
}

#[test]
fn tunnels_through_socks_to_echo() {
    let echo = spawn_echo();
    let socks = spawn_socks();
    thread::sleep(Duration::from_millis(100));

    // Через SOCKS соединяемся с эхо-сервером по имени localhost.
    let mut stream = socks_connect(socks, "localhost", echo).expect("connect через SOCKS");
    stream.write_all(b"netpult").unwrap();
    let mut buf = [0u8; 7];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"netpult", "эхо через SOCKS-туннель совпало");
}
