//! Свой резолвер: шифрованный DNS для всей машины, а не для одного браузера.
//!
//! Зачем отдельно от туннеля. Под туннелем DNS и так защищён — ядро
//! перехватывает запросы и уводит их в DoH через ноду. Но туннель поднят не
//! всегда, а DNS утекает всегда. Штатный путь Linux (`systemd-resolved` с
//! DNS-over-TLS) тут не годится: порт 853 у провайдера закрыт наглухо
//! (проверено — соединение отбивается), а DoH по 443 работает; resolved же
//! умеет только DoT.
//!
//! Поэтому пульт поднимает тем же ядром sing-box крошечный резолвер на
//! localhost и переводит на него systemd-resolved. Дальше шифрование получают
//! все программы разом: любой браузер, Steam, что угодно без своих настроек.
//!
//! Российские зоны нарочно резолвятся российским DNS напрямую. Иначе банки,
//! прячущие записи от иностранных резолверов, просто перестают открываться —
//! на роутере этот же сплит стоит по той же причине.

use crate::config::{state_dir, Config};
use std::net::{Ipv4Addr, UdpSocket};
use std::process::Command;
use std::time::{Duration, Instant};

/// Порт резолвера. 53 занят заглушкой systemd-resolved, 5353 — mDNS
/// (kdeconnect и avahi держат его на любой десктопной системе), поэтому 5335.
pub const PORT: u16 = 5335;

const UNIT: &str = "netpult-dns.service";
const UNIT_PATH: &str = "/etc/systemd/system/netpult-dns.service";
const DROPIN_DIR: &str = "/etc/systemd/resolved.conf.d";
const DROPIN: &str = "/etc/systemd/resolved.conf.d/netpult.conf";

/// Куда уходит всё, кроме российских зон.
const DOH: &str = "1.1.1.1";
/// Кто резолвит российские зоны. Тот же, что на роутере.
const RU: &str = "77.88.8.8";

/// Подведён ли свой резолвер к этой системе.
///
/// Сам резолвер — обычное ядро sing-box и пойдёт где угодно. Не хватает
/// второй половины: способа сказать системе «спрашивай его». На Linux это
/// systemd-resolved, на маке `networksetup`, на Windows `netsh` — и обе
/// последние умеют только порт 53, то есть резолвер там придётся поднимать
/// на привилегированном порту и держать службой их средствами. Не сделано.
pub fn поддержано() -> bool {
    cfg!(target_os = "linux")
}

pub fn config_path() -> std::path::PathBuf {
    state_dir().join("dns.json")
}

/// Конфиг резолвера. Отдельный от конфига туннеля: тот держит ноды и
/// маршруты, а этот — только DNS, и живёт своей жизнью.
pub fn build_config(port: u16) -> String {
    let cache = state_dir().join("dns-cache.db");
    format!(
        r#"{{
  "log": {{"level": "warn"}},
  "dns": {{
    "servers": [
      {{"type": "https", "tag": "doh", "server": "{DOH}"}},
      {{"type": "udp", "tag": "ru", "server": "{RU}"}}
    ],
    "rules": [
      {{"rule_set": "geosite-ru", "server": "ru"}}
    ],
    "final": "doh",
    "strategy": "ipv4_only"
  }},
  "inbounds": [
    {{
      "type": "direct",
      "tag": "dns-in",
      "listen": "127.0.0.1",
      "listen_port": {port},
      "network": "udp"
    }}
  ],
  "outbounds": [{{"type": "direct", "tag": "direct"}}],
  "route": {{
    "default_domain_resolver": {{"server": "ru"}},
    "rules": [
      {{"action": "sniff"}},
      {{"protocol": "dns", "action": "hijack-dns"}}
    ],
    "rule_set": [
      {{
        "type": "remote",
        "tag": "geosite-ru",
        "format": "binary",
        "url": "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ru.srs",
        "download_detour": "direct"
      }}
    ]
  }},
  "experimental": {{
    "cache_file": {{"enabled": true, "path": {cache}}}
  }}
}}
"#,
        cache = crate::json::escape(&cache.to_string_lossy())
    )
}

/// Ответ резолвера: адреса и сколько заняло.
pub struct Ответ {
    pub адреса: Vec<Ipv4Addr>,
    pub заняло: Duration,
}

/// Спросить у резолвера адрес имени. Свой запрос, а не `dig`: утилит для DNS
/// на голой системе может не быть вовсе, а нужен ровно один тип записи.
pub fn ask(server: &str, port: u16, name: &str, timeout: Duration) -> Option<Ответ> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    let id: u16 = (crate::sub::now_secs() % 65536) as u16;
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]); // обычный рекурсивный запрос
    query.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // один вопрос
    for part in name.split('.') {
        if part.is_empty() || part.len() > 63 {
            return None;
        }
        query.push(part.len() as u8);
        query.extend_from_slice(part.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&[0, 1, 0, 1]); // A, IN

    let начало = Instant::now();
    socket.send_to(&query, (server, port)).ok()?;
    let mut buf = [0u8; 2048];
    let (len, _) = socket.recv_from(&mut buf).ok()?;
    let заняло = начало.elapsed();
    let адреса = parse_answer(&buf[..len], id)?;
    Some(Ответ { адреса, заняло })
}

/// Разбор ответа: пропускаем вопрос, идём по записям, берём A.
fn parse_answer(data: &[u8], id: u16) -> Option<Vec<Ipv4Addr>> {
    if data.len() < 12 || u16::from_be_bytes([data[0], data[1]]) != id {
        return None;
    }
    let answers = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut i = 12;
    // вопрос: имя, потом тип и класс
    i = skip_name(data, i)?;
    i = i.checked_add(4)?;

    let mut out = Vec::new();
    for _ in 0..answers {
        i = skip_name(data, i)?;
        if i + 10 > data.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([data[i], data[i + 1]]);
        let rdlen = u16::from_be_bytes([data[i + 8], data[i + 9]]) as usize;
        i += 10;
        if i + rdlen > data.len() {
            return None;
        }
        if rtype == 1 && rdlen == 4 {
            out.push(Ipv4Addr::new(data[i], data[i + 1], data[i + 2], data[i + 3]));
        }
        i += rdlen;
    }
    Some(out)
}

/// Имя в ответе бывает сжатым указателем на прежнее — тогда оно занимает
/// ровно два байта и разворачивать его незачем, нам нужна только длина.
fn skip_name(data: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *data.get(i)? as usize;
        if len == 0 {
            return Some(i + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(i + 2);
        }
        i = i.checked_add(len + 1)?;
    }
}

/// Куда резолвер только что ходил: есть ли шифрованное соединение с DoH и
/// уходил ли запрос российскому резолверу напрямую.
///
/// Это единственная честная проверка «шифруется ли»: по времени ответа не
/// видно ничего (кэш отвечает за ноль, а несуществующее имя в российской зоне
/// отвечает дольше заграничного), а соединение на 443 к DoH-серверу видно
/// прямо в таблице сокетов.
pub fn каналы() -> (bool, bool) {
    let tcp = таблица(&["-tn"]);
    let udp = таблица(&["-un"]);
    (
        tcp.contains(&format!("{DOH}:443")),
        udp.contains(&format!("{RU}:53")),
    )
}

fn таблица(args: &[&str]) -> String {
    Command::new("ss")
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// Отвечает ли наш резолвер прямо сейчас.
pub fn отвечает(timeout: Duration) -> bool {
    ask("127.0.0.1", PORT, "example.com", timeout)
        .map(|o| !o.адреса.is_empty())
        .unwrap_or(false)
}

#[derive(Debug, PartialEq)]
pub enum State {
    /// Служба поднята и резолвер отвечает.
    Up,
    /// Служба есть, но резолвер молчит.
    Broken,
    Off,
}

pub fn state() -> State {
    let running = Command::new("systemctl")
        .args(["is-active", "--quiet", UNIT])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !running {
        return State::Off;
    }
    if отвечает(Duration::from_secs(3)) {
        State::Up
    } else {
        State::Broken
    }
}

/// Переведён ли systemd-resolved на нас.
pub fn подключён() -> bool {
    std::fs::read_to_string(DROPIN)
        .map(|t| t.contains(&format!("127.0.0.1:{PORT}")))
        .unwrap_or(false)
}

fn sudo_write(path: &str, body: &str) -> Result<(), String> {
    let mut child = crate::sudoer::command()
        .args(["tee", path])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("не запустился tee: {e}"))?;
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().ok_or("некуда писать")?;
        stdin
            .write_all(body.as_bytes())
            .map_err(|e| format!("не записалось: {e}"))?;
    }
    let ok = child.wait().map(|s| s.success()).unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(format!("не записать {path} — нужны права root"))
    }
}

fn sudo(args: &[&str]) -> Result<(), String> {
    let out = crate::sudoer::command()
        .args(args)
        .output()
        .map_err(|e| format!("не запустилось: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&out.stderr);
    Err(format!(
        "{}: {}",
        args.join(" "),
        text.trim().lines().next().unwrap_or("не сработало")
    ))
}

/// Текст юнита. Служба системная, а не пользовательская: пользовательская
/// поднимается только после входа в сеанс, и до входа имя не резолвилось бы
/// вовсе — а systemd-resolved к этому времени уже направлен на нас.
fn unit_text(bin: &str, config: &str) -> String {
    format!(
        "[Unit]\n\
         Description=netpult — шифрованный DNS (DoH) для всей системы\n\
         After=network.target\n\
         Before=systemd-resolved.service\n\n\
         [Service]\n\
         Type=simple\n\
         ExecStart={bin} run -c {config}\n\
         Restart=always\n\
         RestartSec=3\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Настройка для systemd-resolved. `Domains=~.` обязателен: без него resolved
/// продолжит спрашивать DNS роутера для всего, что тот объявил своим.
fn dropin_text() -> String {
    format!(
        "# Поставлено netpult (net dns on). Убрать: net dns off\n\
         [Resolve]\n\
         DNS=127.0.0.1:{PORT}\n\
         Domains=~.\n\
         DNSOverTLS=no\n\
         DNSStubListener=yes\n"
    )
}

pub fn on(cfg: &Config) -> Result<Vec<String>, String> {
    if !cfg!(target_os = "linux") {
        return Err(format!(
            "на {} свой резолвер ещё не подведён",
            std::env::consts::OS
        ));
    }
    let bin = crate::singbox::Core::new(cfg).bin()?;
    crate::sudoer::ready()?;

    let mut шаги = Vec::new();
    let config = config_path();
    std::fs::create_dir_all(state_dir()).map_err(|e| e.to_string())?;
    std::fs::write(&config, build_config(PORT)).map_err(|e| format!("не записать конфиг: {e}"))?;

    // Проверяем конфиг тем же ядром, что будет его исполнять: битый конфиг не
    // должен уронить DNS всей машины.
    let проверка = Command::new(&bin)
        .args(["check", "-c", &config.to_string_lossy()])
        .output()
        .map_err(|e| format!("ядро не запустилось: {e}"))?;
    if !проверка.status.success() {
        return Err(format!(
            "ядро не приняло конфиг резолвера: {}",
            String::from_utf8_lossy(&проверка.stderr).trim()
        ));
    }

    sudo_write(
        UNIT_PATH,
        &unit_text(&bin.to_string_lossy(), &config.to_string_lossy()),
    )?;
    sudo(&["systemctl", "daemon-reload"])?;
    sudo(&["systemctl", "enable", "--now", UNIT])?;
    шаги.push("резолвер поднят".into());

    // Ждём, пока резолвер реально ответит. Переводить систему на молчащий
    // сервер — это выключить ей DNS.
    let срок = Instant::now();
    while срок.elapsed() < Duration::from_secs(15) {
        if отвечает(Duration::from_secs(2)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    if !отвечает(Duration::from_secs(3)) {
        let _ = sudo(&["systemctl", "disable", "--now", UNIT]);
        return Err(format!(
            "резолвер не отвечает на 127.0.0.1:{PORT} — систему не трогаю, смотри: journalctl -u {UNIT} -n 30"
        ));
    }
    шаги.push("резолвер отвечает".into());

    sudo(&["mkdir", "-p", DROPIN_DIR])?;
    sudo_write(DROPIN, &dropin_text())?;
    sudo(&["systemctl", "restart", "systemd-resolved"])?;
    шаги.push("systemd-resolved переведён".into());

    // Последняя проверка — уже глазами системы, через её заглушку.
    std::thread::sleep(Duration::from_millis(700));
    if ask("127.0.0.53", 53, "example.com", Duration::from_secs(5))
        .map(|o| o.адреса.is_empty())
        .unwrap_or(true)
    {
        off_dropin()?;
        return Err(
            "после перевода система перестала резолвить — вернул как было".into(),
        );
    }
    шаги.push("система резолвит через нас".into());
    Ok(шаги)
}

fn off_dropin() -> Result<(), String> {
    sudo(&["rm", "-f", DROPIN])?;
    sudo(&["systemctl", "restart", "systemd-resolved"])
}

pub fn off() -> Result<Vec<String>, String> {
    crate::sudoer::ready()?;
    let mut шаги = Vec::new();
    if подключён() {
        off_dropin()?;
        шаги.push("systemd-resolved вернулся к DNS сети".into());
    }
    if Command::new("systemctl")
        .args(["is-enabled", "--quiet", UNIT])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        sudo(&["systemctl", "disable", "--now", UNIT])?;
        sudo(&["rm", "-f", UNIT_PATH])?;
        sudo(&["systemctl", "daemon-reload"])?;
        шаги.push("резолвер снят".into());
    }
    if шаги.is_empty() {
        шаги.push("и так было выключено".into());
    }
    Ok(шаги)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn запрос_разбирается() {
        // Ответ на example.com с одной записью A 93.184.216.34, имя в ответе
        // сжато указателем — так его пишут все настоящие резолверы.
        let mut data = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        data.extend_from_slice(b"\x07example\x03com\x00");
        data.extend_from_slice(&[0, 1, 0, 1]);
        data.extend_from_slice(&[0xC0, 0x0C]); // указатель на имя
        data.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        data.extend_from_slice(&[93, 184, 216, 34]);
        let got = parse_answer(&data, 0x1234).unwrap();
        assert_eq!(got, vec![Ipv4Addr::new(93, 184, 216, 34)]);
    }

    #[test]
    fn чужой_ответ_отбрасывается() {
        let data = vec![0x99, 0x99, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        assert!(parse_answer(&data, 0x1234).is_none());
    }

    #[test]
    fn обрезанный_ответ_не_валит() {
        let mut data = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        data.extend_from_slice(b"\x07example\x03com\x00");
        data.extend_from_slice(&[0, 1, 0, 1]);
        data.extend_from_slice(&[0xC0, 0x0C, 0, 1]); // запись обрывается
        assert!(parse_answer(&data, 0x1234).is_none());
    }

    #[test]
    fn в_конфиге_есть_и_доh_и_российский_резолвер() {
        let text = build_config(5335);
        assert!(text.contains("\"server\": \"1.1.1.1\""));
        assert!(text.contains("\"server\": \"77.88.8.8\""));
        assert!(text.contains("\"listen_port\": 5335"));
        // Без sniff запросы до обработчика DNS не доходят — проверено вживую.
        assert!(text.contains("\"action\": \"sniff\""));
    }

    #[test]
    fn настройка_resolved_перехватывает_всё() {
        // Без `Domains=~.` resolved продолжит спрашивать DNS роутера.
        assert!(dropin_text().contains("Domains=~."));
        assert!(dropin_text().contains(&format!("DNS=127.0.0.1:{PORT}")));
    }
}
