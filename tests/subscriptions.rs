//! Разбор подписок во всех ходовых форматах.
//!
//! Подписка скачивается системным curl, а он умеет `file://` — значит образцы
//! форматов лежат файлами рядом и проверяются тем же путём, каким пойдёт живая
//! ссылка, без выхода в сеть.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::process::Command;

/// Прогнать образец через `net vpn sub` в отдельном HOME и вернуть имена нод
/// вместе с конфигом движка.
fn parse(sample: &str) -> (Vec<String>, String) {
    // Тесты идут в потоках одного процесса, поэтому каталог у каждого свой:
    // иначе они затирают друг другу разобранную подписку.
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("netpult-test-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sample_path = dir.join("sample");
    std::fs::write(&sample_path, sample).unwrap();

    // curl понимает только косые черты вперёд, а на Windows путь приходит с
    // обратными. И форма ровно с тремя косыми: в `file://C:/…` кусок до первой
    // косой — это имя хоста, а не диск.
    let путь = sample_path.display().to_string().replace('\\', "/");
    let url = format!("file://{}{путь}", if путь.starts_with('/') { "" } else { "/" });

    let out = Command::new(env!("CARGO_BIN_EXE_netpult"))
        .args(["vpn", "sub", &url])
        .env("HOME", &dir)
        .env("USERPROFILE", &dir)
        .env("XDG_DATA_HOME", dir.join("data"))
        .env("LOCALAPPDATA", dir.join("data"))
        .output()
        .expect("бинарь не запустился");
    assert!(
        out.status.success(),
        "разбор не удался: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let state: PathBuf = состояние(&dir);
    let names = std::fs::read_to_string(state.join("nodes.list"))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let config = std::fs::read_to_string(state.join("singbox.json")).unwrap();
    (names, config)
}

/// Куда пульт кладёт своё состояние на этой системе. Дублирует `config::state_dir`
/// нарочно: тест на то и тест, чтобы поймать, если та разъедется с
/// договорённостью. Каталоги у систем разные, и подставить один общий нельзя —
/// именно на этом проверка и падала под macOS и Windows, пока гонялась только
/// под Linux.
fn состояние(dir: &std::path::Path) -> PathBuf {
    if cfg!(windows) {
        dir.join("data/netpult")
    } else if cfg!(target_os = "macos") {
        dir.join("Library/Application Support/netpult")
    } else {
        dir.join("data/netpult")
    }
}

fn base64(text: &str) -> String {
    const ABC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = text.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ABC[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[test]
fn ссылки_списком() {
    let sample = "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&pbk=KEY123&sid=ab&fp=chrome&sni=www.microsoft.com&flow=xtls-rprx-vision#Нода%20Финляндия\n\
                  trojan://пароль@trojan.example.com:8443?sni=t.example.com#Trojan";
    let (names, config) = parse(sample);
    assert_eq!(names, vec!["Нода Финляндия", "Trojan"]);
    assert!(config.contains("\"public_key\": \"KEY123\""), "reality не пробросился");
    assert!(config.contains("\"flow\": \"xtls-rprx-vision\""));
    assert!(config.contains("\"type\": \"trojan\""));
}

#[test]
fn блоб_base64() {
    let inner = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@a.example.com:443?security=tls&type=ws&path=%2Fws&host=cdn.example.com#WS";
    let (names, config) = parse(&base64(inner));
    assert_eq!(names, vec!["WS"]);
    assert!(config.contains("\"type\": \"ws\""));
    assert!(config.contains("\"path\": \"/ws\""));
    assert!(config.contains("\"Host\": \"cdn.example.com\""));
}

#[test]
fn vmess_с_json_внутри() {
    let inner = r#"{"v":"2","ps":"Япония","add":"jp.example.com","port":"443","id":"99999999-8888-7777-6666-555555555555","aid":"0","net":"ws","path":"/x","host":"jp.example.com","tls":"tls"}"#;
    let (names, config) = parse(&format!("vmess://{}", base64(inner)));
    assert_eq!(names, vec!["Япония"]);
    assert!(config.contains("\"type\": \"vmess\""));
    assert!(config.contains("\"path\": \"/x\""));
}

#[test]
fn shadowsocks_обеих_форм() {
    let userinfo = base64("aes-256-gcm:секрет");
    let sample = format!(
        "ss://{userinfo}@ss.example.com:8388#SS-короткая\n\
         ss://{}#SS-длинная",
        base64("chacha20-ietf-poly1305:пароль@ss2.example.com:9000")
    );
    let (names, config) = parse(&sample);
    assert_eq!(names, vec!["SS-короткая", "SS-длинная"]);
    assert!(config.contains("\"method\": \"aes-256-gcm\""));
    assert!(config.contains("\"method\": \"chacha20-ietf-poly1305\""));
}

#[test]
fn clash_yaml() {
    let sample = "port: 7890\nproxies:\n  - name: \"Германия\"\n    type: vless\n    server: de.example.com\n    port: 443\n    uuid: 12345678-1234-1234-1234-123456789abc\n    tls: true\n    servername: de.example.com\n    client-fingerprint: chrome\n    network: ws\n    ws-opts:\n      path: /path\n  - {name: Инлайн, type: trojan, server: it.example.com, port: 443, password: pw}\nproxy-groups:\n  - name: авто\n";
    let (names, config) = parse(sample);
    assert_eq!(names, vec!["Германия", "Инлайн"]);
    assert!(config.contains("\"fingerprint\": \"chrome\""));
    assert!(config.contains("\"type\": \"trojan\""));
}

#[test]
fn выгрузка_sing_box() {
    let sample = r#"{"outbounds":[{"type":"vless","tag":"Нода","server":"s.example.com","server_port":443,"uuid":"aaaa-bbbb","tls":{"enabled":true,"server_name":"s.example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"PK","short_id":"01"}}},{"type":"direct","tag":"direct"}]}"#;
    let (names, config) = parse(sample);
    assert_eq!(names, vec!["Нода"]);
    assert!(config.contains("\"short_id\": \"01\""));
}

#[test]
fn выгрузка_xray() {
    let sample = r#"{"outbounds":[{"protocol":"vless","tag":"Xray","settings":{"vnext":[{"address":"x.example.com","port":443,"users":[{"id":"uuid-1","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.apple.com","publicKey":"PK2","shortId":"ff","fingerprint":"chrome"}}}]}"#;
    let (names, config) = parse(sample);
    assert_eq!(names, vec!["Xray"]);
    assert!(config.contains("\"public_key\": \"PK2\""));
    assert!(config.contains("\"server_name\": \"www.apple.com\""));
}

#[test]
fn одинаковые_имена_разводятся() {
    let sample = "vless://a@1.example.com:443#Нода\nvless://b@2.example.com:443#Нода";
    let (names, _) = parse(sample);
    assert_eq!(names, vec!["Нода", "Нода 2"]);
}
