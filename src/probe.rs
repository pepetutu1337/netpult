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

/// Адрес этой машины в локальной сети — тот, по которому до неё достучится
/// телефон.
///
/// Спрашивать маршрут наружу тут нельзя: при поднятом туннеле он приводит к
/// адресу самого туннеля (172.19.0.1), и пульт выдавал телефону адрес, которого
/// в его Wi-Fi не существует. Поэтому сначала перебираем адреса интерфейсов и
/// берём домашний, а трюк с UDP оставлен запасным путём.
pub fn lan_ip() -> Option<IpAddr> {
    if let Some(found) = interface_addresses()
        .into_iter()
        .filter(is_home_address)
        .min_by_key(home_rank)
    {
        return Some(found);
    }
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    let ip = socket.local_addr().ok().map(|a| a.ip())?;
    is_home_address(&ip).then_some(ip)
}

/// Адрес туннеля пульта: он есть в конфиге ядра и домашним не является.
const OWN_TUNNEL: [u8; 4] = [172, 19, 0, 1];

fn is_home_address(ip: &IpAddr) -> bool {
    let IpAddr::V4(v4) = ip else { return false };
    let o = v4.octets();
    if v4.is_loopback() || v4.is_link_local() || o == OWN_TUNNEL {
        return false;
    }
    v4.is_private()
}

/// Чем меньше число, тем охотнее берём адрес. Домашние сети почти всегда
/// 192.168.x, поэтому он первый; 172.16–31 — чаще всего чужие туннели и
/// контейнеры, поэтому он последний.
fn home_rank(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(v4) => match v4.octets()[0] {
            192 => 0,
            10 => 1,
            _ => 2,
        },
        IpAddr::V6(_) => 3,
    }
}

/// Адреса всех интерфейсов. Разбираем вывод системной утилиты — ради одного
/// списка тащить libc и getifaddrs незачем.
fn interface_addresses() -> Vec<IpAddr> {
    let output = if cfg!(target_os = "linux") {
        Command::new("ip").args(["-4", "-o", "addr", "show"]).output()
    } else if cfg!(target_os = "macos") {
        Command::new("ifconfig").arg("-a").output()
    } else {
        Command::new("ipconfig").output()
    };
    let Ok(out) = output else { return Vec::new() };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut found = Vec::new();
    for word in text.split(|c: char| c.is_whitespace() || c == ':') {
        let candidate = word.split('/').next().unwrap_or(word);
        if let Ok(ip) = candidate.parse::<IpAddr>() {
            found.push(ip);
        }
    }
    found
}

pub fn curl_available() -> bool {
    Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn curl(args: &[&str], timeout: Duration) -> Option<String> {
    curl_full(args, timeout).ok()
}

/// Код выхода curl нужен отдельно: «не умею такую группу шифров» (59) — это не
/// то же самое, что «сайт не ответил», и вести себя надо по-разному.
fn curl_full(args: &[&str], timeout: Duration) -> Result<String, i32> {
    let secs = timeout.as_secs().max(1).to_string();
    let out = Command::new("curl")
        .args(["-s", "--max-time", &secs])
        .args(args)
        .output()
        .map_err(|_| -1)?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(out.status.code().unwrap_or(-1))
    }
}

/// Страница видео, из которой добывается имя краевого сервера видео-CDN.
///
/// Именно этот CDN душат, и именно он молчит, когда «ютуб не грузится» — сама
/// страница и превью при этом открываются как ни в чём не бывало. Проверять
/// обход по `youtube.com` или `i.ytimg.com` бессмысленно: они отвечают и со
/// сломанной стратегией. На том же и держится этот способ добычи имени —
/// страница доедет даже тогда, когда видео наглухо задушено.
const WATCH_URL: &str = "https://www.youtube.com/watch?v=aqz-KE-bpKQ";

/// Группы ключей «как у браузера»: постквантовая X25519MLKEM768 плюс обычные
/// про запас. Ключ ML-KEM весит 1216 байт и раздувает приветствие TLS до двух
/// килобайт, а оно уже не влезает в один сегмент TCP.
///
/// Разница не косметическая. Маленькое приветствие DPI пересобирать не станет,
/// и нарезки хватает; большое он пересобирает обязательно, читает имя сайта и
/// режет. Стратегия, прошедшая проверку обычным curl, может при этом оставить
/// браузер без ютуба — так и случилось 30.08.2026, когда Firefox молчал, а
/// консольные проверки рапортовали, что всё хорошо.
const BROWSER_CURVES: &str = "X25519MLKEM768:X25519:P-256";

/// Имя краевого сервера, добытое со страницы видео.
///
/// Гадать тут нельзя. Имена вида `rr5---sn-5go7ynlk` выдаются под сеть и под
/// сессию: соседний `rr1` из той же группы резолвится и при этом молчит, и
/// проверка врала бы «видео не идёт» на исправном обходе. Постоянный
/// `redirector.googlevideo.com` тоже не годится, хотя и живёт всегда: он
/// отвечает даже тогда, когда всё видео задушено, — душат именно краевые.
///
/// Имя ищется один раз за запуск: страница весит больше мегабайта, а перебору
/// стратегий она нужна на каждом шаге.
/// Насколько долго держим найденный узел CDN.
///
/// Раньше он запоминался навсегда (OnceLock). В разовом запуске это незаметно,
/// а сторож живёт неделями одним процессом — и всю неделю спрашивал один и тот
/// же узел, выбранный при старте. Узлов за именем сотни, перекрыты они
/// вразнобой: попался живой — проверка вечно зелёная, попался мёртвый — вечно
/// красная. И то и другое к делу отношения не имеет.
const HOST_TTL: Duration = Duration::from_secs(30 * 60);

fn video_host() -> Option<String> {
    static HOST: std::sync::Mutex<Option<(String, Instant)>> = std::sync::Mutex::new(None);
    let mut держим = HOST.lock().ok()?;
    if let Some((host, взят)) = держим.as_ref()
        && взят.elapsed() < HOST_TTL
    {
        return Some(host.clone());
    }
    let page = curl(&[WATCH_URL], Duration::from_secs(20))?;
    let host = find_video_host(&page)?;
    *держим = Some((host.clone(), Instant::now()));
    Some(host)
}

/// Первое имя краевого сервера в тексте страницы.
fn find_video_host(page: &str) -> Option<String> {
    let at = page.find("---sn-")?;
    // Влево до начала имени, вправо до конца домена.
    let head = page[..at].rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))? + 1;
    let tail = page[at..].find(".googlevideo.com")? + at + ".googlevideo.com".len();
    let host = &page[head..tail];
    if host.len() > 200 { None } else { Some(host.to_string()) }
}

/// Ответ видео-CDN на два приветствия TLS: обычное и браузерное.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Video {
    /// Нашёлся ли краевой сервер, к которому вообще можно стучаться. Пока
    /// не нашёлся, судить не о чем — и врать про поломку тоже незачем.
    pub checked: bool,
    /// Отвечает при обычном, коротком приветствии.
    pub plain: bool,
    /// Отвечает при большом, браузерном. `None` — проверить нечем: у этого
    /// curl нет постквантовых групп (старая система, свой TLS-движок).
    pub browser: Option<bool>,
}

impl Video {
    /// Годится ли обход целиком: и для консоли, и для браузера. Непроверенное
    /// за поломку не считаем, иначе пульт будет паниковать на пустом месте.
    pub fn ok(&self) -> bool {
        !self.checked || (self.plain && self.browser.unwrap_or(true))
    }

    /// Тот самый перекос: консоль живёт, браузер нет.
    pub fn console_only(&self) -> bool {
        self.checked && self.plain && self.browser == Some(false)
    }
}

/// Доходит ли до видео-CDN — обычным приветствием и браузерным.
pub fn video(timeout: Duration) -> Video {
    let Some(host) = video_host() else {
        return Video::default();
    };
    let url = format!("https://{host}/");
    Video {
        checked: true,
        plain: reachable(&url, timeout),
        browser: video_browser_hello(&url, timeout),
    }
}

fn video_browser_hello(url: &str, timeout: Duration) -> Option<bool> {
    match curl_full(
        &["-o", NULL_DEVICE, "-w", "%{http_code}", "--curves", BROWSER_CURVES, url],
        timeout,
    ) {
        Ok(text) => Some(text.trim().parse::<u32>().map(|c| c > 0).unwrap_or(false)),
        // 59 — curl собран без постквантовых групп. Не поломка обхода, просто
        // проверить нечем: молчим, а не пугаем красным.
        Err(59) => None,
        Err(_) => Some(false),
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

/// Адреса устройств, подключённых сейчас к нашему порту из локальной сети.
///
/// Читаем реальные соединения у системы (`ss`), а не свой счётчик: пульт и
/// прокси — разные процессы, и общий счётчик потребовал бы канала между ними.
/// Локальные подключения (127.0.0.1, ::1) не считаем — это мы сами, не телефон.
pub fn connected_peers(port: u16) -> Vec<String> {
    if !cfg!(target_os = "linux") {
        return Vec::new();
    }
    let out = match Command::new("ss")
        .args(["-Htn", "state", "established", &format!("sport = :{port}")])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    // С `-H` и фильтром по состоянию колонки: Recv-Q Send-Q Local Peer.
    // Peer — четвёртое поле (индекс 3).
    let mut peers: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().nth(3)) // Peer Address:Port
        .filter_map(|peer| peer.rsplit_once(':').map(|(addr, _)| addr))
        .map(|addr| addr.trim_start_matches('[').trim_end_matches(']').to_string())
        .filter(|addr| addr != "127.0.0.1" && addr != "::1" && !addr.is_empty())
        .collect();
    peers.sort();
    peers.dedup();
    peers
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn краевой_сервер_вынимается_из_страницы() {
        let page = r#"{"url":"https://rr5---sn-5go7ynlk.googlevideo.com/videoplayback?expire=1"}"#;
        assert_eq!(
            find_video_host(page).as_deref(),
            Some("rr5---sn-5go7ynlk.googlevideo.com")
        );
    }

    #[test]
    fn без_краевого_сервера_ничего_не_выдумывается() {
        assert!(find_video_host("обычная страница без плеера").is_none());
        assert!(find_video_host("").is_none());
    }

    #[test]
    fn непроверенное_за_поломку_не_считается() {
        let пусто = Video::default();
        assert!(пусто.ok(), "нечего было проверить — не повод бить тревогу");
        assert!(!пусто.console_only());
    }

    #[test]
    fn перекос_в_сторону_консоли_виден() {
        let v = Video { checked: true, plain: true, browser: Some(false) };
        assert!(!v.ok());
        assert!(v.console_only());
    }

    #[test]
    fn адрес_туннеля_за_домашний_не_считается() {
        assert!(!is_home_address(&ip(172, 19, 0, 1)));
        assert!(!is_home_address(&ip(127, 0, 0, 1)));
        assert!(!is_home_address(&ip(169, 254, 3, 7)));
        assert!(!is_home_address(&ip(8, 8, 8, 8)));
    }

    #[test]
    fn домашние_адреса_узнаются() {
        assert!(is_home_address(&ip(192, 168, 1, 213)));
        assert!(is_home_address(&ip(10, 0, 0, 5)));
        assert!(is_home_address(&ip(172, 20, 1, 1)));
    }

    #[test]
    fn домашний_wifi_важнее_подсети_контейнеров() {
        let mut all = [ip(172, 20, 0, 3), ip(192, 168, 1, 213), ip(10, 1, 2, 3)];
        all.sort_by_key(home_rank);
        assert_eq!(all[0], ip(192, 168, 1, 213));
    }
}
