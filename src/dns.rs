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
/// Порт резолвера.
///
/// На Linux `systemd-resolved` принимает адрес с портом, поэтому берём
/// непривилегированный: 53 занят его же заглушкой, 5353 — mDNS (kdeconnect и
/// avahi держат его на любой десктопной системе), отсюда 5335.
///
/// На маке и Windows системе адрес назначается через `networksetup` и `netsh`,
/// а они порт задать не умеют — только адрес. Значит слушать надо 53, и
/// служба там поднимается от администратора.
pub fn port() -> u16 {
    if cfg!(target_os = "linux") { 5335 } else { 53 }
}

const UNIT: &str = "netpult-dns.service";
const UNIT_PATH: &str = "/etc/systemd/system/netpult-dns.service";
const DROPIN_DIR: &str = "/etc/systemd/resolved.conf.d";
const DROPIN: &str = "/etc/systemd/resolved.conf.d/netpult.conf";

/// launchd на маке: демон системный, потому что 53 — привилегированный порт.
const PLIST: &str = "/Library/LaunchDaemons/com.netpult.dns.plist";
const LABEL: &str = "com.netpult.dns";

/// Служба Windows.
const WINSVC: &str = "netpult-dns";

/// Куда уходит всё, кроме российских зон.
const DOH: &str = "1.1.1.1";
/// Кто резолвит российские зоны. Тот же, что на роутере.
const RU: &str = "77.88.8.8";

/// Подведён ли свой резолвер к этой системе. Резолвер — обычное ядро sing-box
/// и идёт везде; вопрос всегда во второй половине, в способе сказать системе
/// «спрашивай его».
pub fn поддержано() -> bool {
    cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(windows)
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
    ask("127.0.0.1", port(), "example.com", timeout)
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
    if !служба_поднята() {
        return State::Off;
    }
    if отвечает(Duration::from_secs(3)) {
        State::Up
    } else {
        State::Broken
    }
}

fn служба_поднята() -> bool {
    if cfg!(target_os = "linux") {
        успех("systemctl", &["is-active", "--quiet", UNIT])
    } else if cfg!(target_os = "macos") {
        // `launchctl print` возвращает ноль, только если демон загружен.
        успех("launchctl", &["print", &format!("system/{LABEL}")])
    } else {
        Command::new("sc")
            .args(["query", WINSVC])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
            .unwrap_or(false)
    }
}

fn успех(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Сетевые службы мака, у которых есть смысл трогать DNS. `networksetup`
/// перечисляет и отключённые — они помечены звёздочкой, их пропускаем.
fn маковские_службы() -> Vec<String> {
    let out = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    разобрать_службы(&out)
}

fn разобрать_службы(text: &str) -> Vec<String> {
    text.lines()
        .skip(1) // первая строка — пояснение про звёздочку
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(str::to_string)
        .collect()
}

/// Сетевые адаптеры Windows, которым назначается DNS.
fn виндовые_адаптеры() -> Vec<String> {
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected | ForEach-Object { $_.InterfaceAlias }",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && *l != "Loopback Pseudo-Interface 1")
        .map(str::to_string)
        .collect()
}

/// Спрашивает ли система именно нас.
pub fn подключён() -> bool {
    if cfg!(target_os = "linux") {
        std::fs::read_to_string(DROPIN)
            .map(|t| t.contains(&format!("127.0.0.1:{}", port())))
            .unwrap_or(false)
    } else if cfg!(target_os = "macos") {
        маковские_службы().iter().any(|служба| {
            Command::new("networksetup")
                .args(["-getdnsservers", служба])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("127.0.0.1"))
                .unwrap_or(false)
        })
    } else {
        Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses",
            ])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("127.0.0.1"))
            .unwrap_or(false)
    }
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
         DNS=127.0.0.1:{}\n\
         Domains=~.\n\
         DNSOverTLS=no\n\
         DNSStubListener=yes\n",
        port()
    )
}

/// Текст plist для launchd. Демон системный: 53 — привилегированный порт, и
/// он должен подниматься до входа в сеанс, иначе имена не резолвятся с
/// загрузки.
fn plist_text(bin: &str, config: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\n\
         <key>Label</key><string>{LABEL}</string>\n\
         <key>ProgramArguments</key><array>\n\
         <string>{bin}</string><string>run</string><string>-c</string><string>{config}</string>\n\
         </array>\n\
         <key>RunAtLoad</key><true/>\n\
         <key>KeepAlive</key><true/>\n\
         </dict></plist>\n"
    )
}

/// Поднять службу резолвера средствами этой системы.
fn поднять_службу(bin: &str, config: &str) -> Result<(), String> {
    if cfg!(target_os = "linux") {
        sudo_write(UNIT_PATH, &unit_text(bin, config))?;
        sudo(&["systemctl", "daemon-reload"])?;
        sudo(&["systemctl", "enable", "--now", UNIT])
    } else if cfg!(target_os = "macos") {
        sudo_write(PLIST, &plist_text(bin, config))?;
        sudo(&["chown", "root:wheel", PLIST])?;
        // bootout на всякий случай: повторное bootstrap поверх загруженного
        // демона отвечает отказом, а не перезагружает его.
        let _ = sudo(&["launchctl", "bootout", &format!("system/{LABEL}")]);
        sudo(&["launchctl", "bootstrap", "system", PLIST])
    } else {
        // sc принимает binPath одной строкой; кавычки нужны из-за пробелов в
        // пути к профилю пользователя.
        let path = format!("\"{bin}\" run -c \"{config}\"");
        let _ = sudo(&["sc", "delete", WINSVC]);
        sudo(&[
            "sc",
            "create",
            WINSVC,
            &format!("binPath= {path}"),
            "start= auto",
            "DisplayName= netpult DNS",
        ])?;
        sudo(&["sc", "start", WINSVC])
    }
}

fn снять_службу() -> Result<(), String> {
    if cfg!(target_os = "linux") {
        sudo(&["systemctl", "disable", "--now", UNIT])?;
        sudo(&["rm", "-f", UNIT_PATH])?;
        sudo(&["systemctl", "daemon-reload"])
    } else if cfg!(target_os = "macos") {
        let _ = sudo(&["launchctl", "bootout", &format!("system/{LABEL}")]);
        sudo(&["rm", "-f", PLIST])
    } else {
        let _ = sudo(&["sc", "stop", WINSVC]);
        sudo(&["sc", "delete", WINSVC])
    }
}

/// Сказать системе спрашивать нас.
fn привязать_систему() -> Result<(), String> {
    if cfg!(target_os = "linux") {
        sudo(&["mkdir", "-p", DROPIN_DIR])?;
        sudo_write(DROPIN, &dropin_text())?;
        sudo(&["systemctl", "restart", "systemd-resolved"])
    } else if cfg!(target_os = "macos") {
        let службы = маковские_службы();
        if службы.is_empty() {
            return Err("не нашёл ни одной сетевой службы — networksetup молчит".into());
        }
        for служба in &службы {
            sudo(&["networksetup", "-setdnsservers", служба, "127.0.0.1"])?;
        }
        // Кэш мака держит прежние ответы; без сброса переключение заметно не сразу.
        let _ = sudo(&["dscacheutil", "-flushcache"]);
        let _ = sudo(&["killall", "-HUP", "mDNSResponder"]);
        Ok(())
    } else {
        let адаптеры = виндовые_адаптеры();
        if адаптеры.is_empty() {
            return Err("не нашёл подключённых адаптеров".into());
        }
        for адаптер in &адаптеры {
            sudo(&[
                "netsh",
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                &format!("name={адаптер}"),
                "static",
                "127.0.0.1",
                "primary",
            ])?;
        }
        let _ = sudo(&["ipconfig", "/flushdns"]);
        Ok(())
    }
}

fn отвязать_систему() -> Result<(), String> {
    if cfg!(target_os = "linux") {
        sudo(&["rm", "-f", DROPIN])?;
        sudo(&["systemctl", "restart", "systemd-resolved"])
    } else if cfg!(target_os = "macos") {
        for служба in маковские_службы() {
            // «Empty» — то самое слово, которым networksetup возвращает
            // раздачу DNS обратно роутеру.
            let _ = sudo(&["networksetup", "-setdnsservers", &служба, "Empty"]);
        }
        let _ = sudo(&["dscacheutil", "-flushcache"]);
        let _ = sudo(&["killall", "-HUP", "mDNSResponder"]);
        Ok(())
    } else {
        for адаптер in виндовые_адаптеры() {
            let _ = sudo(&[
                "netsh",
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                &format!("name={адаптер}"),
                "dhcp",
            ]);
        }
        let _ = sudo(&["ipconfig", "/flushdns"]);
        Ok(())
    }
}

/// Через что система резолвит имена. На Linux — заглушка resolved, на маке и
/// Windows система спрашивает наш адрес напрямую, отдельной заглушки нет.
fn системный_резолвер() -> (&'static str, u16) {
    if cfg!(target_os = "linux") {
        ("127.0.0.53", 53)
    } else {
        ("127.0.0.1", port())
    }
}

pub fn on(cfg: &Config) -> Result<Vec<String>, String> {
    if !поддержано() {
        return Err(format!(
            "на {} свой резолвер ещё не подведён",
            std::env::consts::OS
        ));
    }
    let bin = crate::singbox::Core::new(cfg).bin()?;
    if !cfg!(windows) {
        crate::sudoer::ready()?;
    }

    let mut шаги = Vec::new();
    let config = config_path();
    std::fs::create_dir_all(state_dir()).map_err(|e| e.to_string())?;
    std::fs::write(&config, build_config(port())).map_err(|e| format!("не записать конфиг: {e}"))?;

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

    поднять_службу(&bin.to_string_lossy(), &config.to_string_lossy())?;
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
        let _ = снять_службу();
        return Err(format!(
            "резолвер не отвечает на 127.0.0.1:{} — систему не трогаю, смотри {}",
            port(),
            где_журнал()
        ));
    }
    шаги.push("резолвер отвечает".into());

    привязать_систему()?;
    шаги.push("система переведена на него".into());

    // Последняя проверка — уже глазами системы.
    std::thread::sleep(Duration::from_millis(900));
    let (server, порт) = системный_резолвер();
    if ask(server, порт, "example.com", Duration::from_secs(5))
        .map(|ответ| ответ.адреса.is_empty())
        .unwrap_or(true)
    {
        let _ = отвязать_систему();
        return Err("после перевода система перестала резолвить — вернул как было".into());
    }
    шаги.push("система резолвит через нас".into());
    Ok(шаги)
}

fn где_журнал() -> String {
    if cfg!(target_os = "linux") {
        format!("journalctl -u {UNIT} -n 30")
    } else if cfg!(target_os = "macos") {
        "log show --predicate 'process == \"sing-box\"' --last 5m".to_string()
    } else {
        format!("Просмотр событий → Журналы Windows → Система, служба {WINSVC}")
    }
}

pub fn off() -> Result<Vec<String>, String> {
    if !поддержано() {
        return Err(format!(
            "на {} свой резолвер не подводился — и снимать нечего",
            std::env::consts::OS
        ));
    }
    if !cfg!(windows) {
        crate::sudoer::ready()?;
    }
    let mut шаги = Vec::new();
    if подключён() {
        отвязать_систему()?;
        шаги.push("система вернулась к DNS своей сети".into());
    }
    if служба_поднята() {
        снять_службу()?;
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
    fn службы_мака_разбираются() {
        // Настоящий вывод `networksetup -listallnetworkservices`: первая
        // строка — пояснение, звёздочкой помечены отключённые службы.
        let text = "An asterisk (*) denotes that a network service is disabled.\n\
                    Wi-Fi\n\
                    *Thunderbolt Bridge\n\
                    iPhone USB\n";
        assert_eq!(разобрать_службы(text), vec!["Wi-Fi", "iPhone USB"]);
    }

    #[test]
    fn пустой_вывод_networksetup_не_валит() {
        assert!(разобрать_службы("").is_empty());
        assert!(разобрать_службы("An asterisk (*) denotes...").is_empty());
    }

    #[test]
    fn plist_называет_демона_и_бинарь() {
        let text = plist_text("/usr/local/bin/sing-box", "/tmp/dns.json");
        assert!(text.contains("<key>Label</key><string>com.netpult.dns</string>"));
        assert!(text.contains("/usr/local/bin/sing-box"));
        assert!(text.contains("/tmp/dns.json"));
        assert!(text.contains("<key>RunAtLoad</key><true/>"));
    }

    #[test]
    fn порт_под_систему() {
        // На Linux resolved принимает порт, поэтому непривилегированный.
        // На маке и Windows адрес назначается без порта — значит только 53.
        if cfg!(target_os = "linux") {
            assert_eq!(port(), 5335);
        } else {
            assert_eq!(port(), 53);
        }
    }

    #[test]
    fn настройка_resolved_перехватывает_всё() {
        // Без `Domains=~.` resolved продолжит спрашивать DNS роутера.
        assert!(dropin_text().contains("Domains=~."));
        assert!(dropin_text().contains(&format!("DNS=127.0.0.1:{}", port())));
    }
}
