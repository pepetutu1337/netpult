//! Через что на самом деле идёт интернет.
//!
//! Пульт не единственный, кто лезет в сеть: обход может стоять на роутере,
//! рядом может работать чужой VPN, в переменных среды — прокси. Всё это
//! перекрывает друг друга, и «включил zapret, а не помогло» чаще всего значит
//! именно это. Команда показывает картину целиком и называет конфликты.

use crate::config::Config;
use crate::probe;
use crate::profile;
use crate::singbox;
use crate::zapret::{self, Zapret};
use crate::{BOLD, DIM, GREEN, RED, RESET, YELLOW};
use std::process::Command;
use std::time::Duration;

/// Куда уходит трафик по умолчанию.
pub struct Exit {
    pub interface: String,
    pub gateway: Option<String>,
}

/// Похоже ли имя на интерфейс туннеля.
fn is_tunnel(name: &str) -> bool {
    ["tun", "utun", "wg", "tailscale", "ppp", "proton", "nordlynx", "amnezia"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

pub fn default_exit() -> Option<Exit> {
    // И там и там спрашиваем у системы именно тот маршрут, которым пойдёт
    // пакет, а не пересказ таблицы: при поднятом туннеле разница
    // принципиальна.
    let (program, args, dev_key, gw_key) = if cfg!(target_os = "macos") {
        ("route", vec!["-n", "get", "1.1.1.1"], "interface:", "gateway:")
    } else if cfg!(target_os = "linux") {
        ("ip", vec!["route", "get", "1.1.1.1"], "dev", "via")
    } else {
        // На Windows нет ни того, ни другого, а `route print` разбирать ради
        // одной строки не стоит: остальное в отчёте и без него на месте.
        return None;
    };
    let out = Command::new(program).args(&args).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let word_after = |key: &str| -> Option<String> {
        let mut words = text.split_whitespace();
        while let Some(word) = words.next() {
            if word == key {
                return words.next().map(str::to_string);
            }
        }
        None
    };
    Some(Exit {
        interface: word_after(dev_key)?,
        gateway: word_after(gw_key),
    })
}

/// Чужие туннели, поднятые прямо сейчас: имя и чем поднят.
fn foreign_tunnels(cfg: &Config) -> Vec<String> {
    let mut found = Vec::new();
    // Своё ядро видно по управляющему API, а не по имени процесса: чужой
    // sing-box (тот же Happ внутри) выглядит точно так же.
    let ours = singbox::Core::new(cfg).state() == singbox::State::Up;

    for (process, label) in [
        ("openvpn", "OpenVPN"),
        ("wireguard-go", "WireGuard"),
        ("tailscaled", "Tailscale"),
        ("warp-svc", "Cloudflare WARP"),
        ("xray", "Xray"),
        ("v2ray", "V2Ray"),
        ("hysteria", "Hysteria"),
        ("tun2socks", "tun2socks"),
    ] {
        if zapret::process_running(process) {
            found.push(label.to_string());
        }
    }
    if zapret::process_running("Happ") || zapret::process_running("happ") {
        found.push("Happ".to_string());
    }
    if zapret::process_running("sing-box") && !ours {
        found.push("чужой sing-box".to_string());
    }
    // WireGuard живёт в ядре, процесса у него может не быть вовсе.
    if let Ok(out) = Command::new("wg").arg("show").arg("interfaces").output() {
        let names = String::from_utf8_lossy(&out.stdout);
        for name in names.split_whitespace() {
            found.push(format!("WireGuard {name}"));
        }
    }
    found.sort();
    found.dedup();
    found
}

fn system_proxy() -> Option<String> {
    for key in ["all_proxy", "https_proxy", "http_proxy", "ALL_PROXY", "HTTPS_PROXY"] {
        if let Ok(value) = std::env::var(key)
            && !value.trim().is_empty() {
                return Some(format!("{key}={value}"));
            }
    }
    None
}

fn nameservers() -> Vec<String> {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    let listed: Vec<String> = text
        .lines()
        .filter_map(|line| line.strip_prefix("nameserver "))
        .map(|value| value.trim().to_string())
        .collect();
    // 127.0.0.53 — это заглушка systemd-resolved, а не настоящий сервер: за
    // ней стоит либо роутер, либо DoH, и разница тут как раз важна.
    if listed.iter().all(|ip| ip.starts_with("127."))
        && let Some(real) = resolved_upstream() {
            return real;
        }
    listed
}

fn resolved_upstream() -> Option<Vec<String>> {
    let out = Command::new("resolvectl").arg("status").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut found = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        for key in ["Current DNS Server:", "DNS Servers:"] {
            if let Some(rest) = line.strip_prefix(key) {
                for server in rest.split_whitespace() {
                    found.push(server.to_string());
                }
            }
        }
    }
    found.sort();
    found.dedup();
    if found.is_empty() { None } else { Some(found) }
}

/// Сайты, по которым видно работу ТСПУ: если открываются без всякого обхода —
/// значит обход делает кто-то выше нас.
const BLOCKED: [(&str, &str); 3] = [
    ("youtube.com", "https://www.youtube.com/generate_204"),
    ("ytimg (CDN)", "https://i.ytimg.com/generate_204"),
    ("discord.com", "https://discord.com/api/v9/gateway"),
];

/// Одной строкой: чем именно сейчас держится связь.
///
/// Экран открывают ради этого ответа, а раньше его приходилось складывать
/// в голове из трёх равноправных строк состояния. Проверки тут дешёвые —
/// маршрут у системы и состояние своих служб, без единого запроса в сеть,
/// поэтому строку не жалко пересчитывать при каждой перерисовке.
pub fn carrier(cfg: &Config) -> (bool, String) {
    let zapret_on = Zapret::new(cfg).state() == zapret::State::On;
    let tunnel_on = singbox::Core::new(cfg).state() == singbox::State::Up;
    let exit = default_exit();
    let through_tunnel = exit.as_ref().is_some_and(|e| is_tunnel(&e.interface));

    // Порядок проверок — по силе: туннель забирает маршрут целиком и делает
    // остальное неважным, дальше идёт zapret, и только потом «никак».
    match (through_tunnel, tunnel_on, zapret_on) {
        (true, _, _) => {
            let name = exit.map(|e| e.interface).unwrap_or_default();
            (true, format!("через туннель {name}"))
        }
        // Ядро поднято, а маршрут мимо него: так бывает при сплите, когда в
        // туннель уходят только выбранные домены.
        (false, true, _) => (true, "туннель поднят, маршрут мимо — сплит".to_string()),
        (false, false, true) => (true, "напрямую, обход zapret".to_string()),
        (false, false, false) => (false, "напрямую, без обхода".to_string()),
    }
}

pub fn report(cfg: &Config, deep: bool) -> Result<(), String> {
    let z = Zapret::new(cfg);
    let zapret_on = z.state() == zapret::State::On;
    let tunnel_on = singbox::Core::new(cfg).state() == singbox::State::Up;
    let exit = default_exit();
    let foreign = foreign_tunnels(cfg);
    let proxy = system_proxy();

    println!("{BOLD}ЧЕРЕЗ ЧТО ИДЁТ ИНТЕРНЕТ{RESET}\n");

    match &exit {
        Some(exit) => {
            let kind = if is_tunnel(&exit.interface) {
                format!(" {GREEN}(туннель){RESET}")
            } else {
                String::new()
            };
            let via = exit
                .gateway
                .as_ref()
                .map(|g| format!("  шлюз {g}"))
                .unwrap_or_default();
            println!("  Выход       {}{kind}{via}", exit.interface);
        }
        None => println!("  Выход       {DIM}не видно{RESET}"),
    }
    match probe::external_addr(Duration::from_secs(5)) {
        Some(a) => println!("  Внешний IP  {} · {} · {}", a.ip, a.country, a.org),
        None => println!("  Внешний IP  {RED}не отвечает{RESET}"),
    }
    let dns = nameservers();
    if !dns.is_empty() {
        // Адрес резолвера человеку ничего не говорит: 127.0.0.1:5335 выглядит
        // как «что-то местное». Важно другое — шифруется запрос или уходит
        // открытым в резолвер сети.
        let свой = crate::dns::подключён() && crate::dns::state() == crate::dns::State::Up;
        let пометка = if свой {
            format!("  {GREEN}(шифруется){RESET}")
        } else {
            format!("  {DIM}(открытым текстом){RESET}")
        };
        println!("  DNS         {}{пометка}", dns.join(", "));
    }
    // Без имени сети весь отчёт одинаков дома и в кафе: там и там выход через
    // шлюз, там и там российский адрес. Разница только в том, что делает
    // роутер, — а это к сети и привязано.
    let сеть = profile::current_network();
    match &сеть {
        Some(name) => {
            let знакомая = if crate::network::known(Some(name)).is_some() {
                String::new()
            } else {
                format!("  {DIM}(в первый раз){RESET}")
            };
            println!("  Сеть        {name}{знакомая}");
        }
        None => println!("  Сеть        {DIM}не опознана{RESET}"),
    }

    println!("\n{BOLD}  На этом компьютере{RESET}");
    mark(zapret_on, &format!(
        "zapret        {}",
        if zapret_on {
            z.strategy().unwrap_or_else(|| "включён".into())
        } else {
            "выключен".into()
        }
    ));
    mark(tunnel_on, &format!(
        "свой туннель  {}",
        match (tunnel_on, singbox::active_node()) {
            (true, Some((name, auto))) =>
                format!("{name}{}", if auto { " (автоподбор)" } else { "" }),
            (true, None) => "поднят".to_string(),
            _ => "выключен".to_string(),
        }
    ));
    if foreign.is_empty() {
        mark(false, "чужой VPN     не вижу");
    } else {
        mark(true, &format!("чужой VPN     {}", foreign.join(", ")));
    }
    if let Some(proxy) = &proxy {
        mark(true, &format!("прокси        {proxy}"));
    }

    println!("\n{BOLD}  Со стороны сети{RESET}");
    if zapret_on || tunnel_on || !foreign.is_empty() {
        if deep {
            deep_check(cfg, zapret_on, tunnel_on, сеть.as_deref())?;
        } else {
            // Прямо сейчас не разглядеть, зато можно сказать, чем эта сеть
            // оказалась в прошлый раз. Без этого отчёт дома и в чужой сети
            // выглядит одинаково, а значит не отвечает на главный вопрос.
            вспомнить(сеть.as_deref());
            println!("  {DIM}проверить сейчас: net path --deep (ненадолго выключит свой обход){RESET}");
        }
    } else {
        let upstream = probe_blocked();
        crate::network::remember(сеть.as_deref(), upstream);
        if upstream {
            println!("  {GREEN}● обход стоит выше — заблокированное открывается без всякого пульта{RESET}");
            println!("  {DIM}обычно это роутер или сам провайдер. Свой zapret тут не нужен.{RESET}");
        } else {
            println!("  {RED}○ обхода выше нет — заблокированное не открывается{RESET}");
            println!("  {DIM}включить свой: net on{RESET}");
        }
    }

    let troubles = conflicts(zapret_on, tunnel_on, &foreign, proxy.is_some(), exit.as_ref());
    if !troubles.is_empty() {
        println!("\n{BOLD}  Мешает друг другу{RESET}");
        for line in troubles {
            println!("  {YELLOW}! {line}{RESET}");
        }
    }
    Ok(())
}

/// Что известно про эту сеть с прошлого раза. Вердикт всегда идёт с датой:
/// роутер мог сломаться со вчера, и старому «обход выше есть» верить нельзя.
fn вспомнить(сеть: Option<&str>) {
    let Some(name) = сеть else {
        println!("  {DIM}сеть не опознана — сказать про неё нечего{RESET}");
        return;
    };
    let Some(seen) = crate::network::known(Some(name)) else {
        println!(
            "  {YELLOW}в этой сети пульт ещё не проверялся — про обход выше ничего не известно{RESET}"
        );
        return;
    };
    let давность = crate::когда(Some(seen.checked));
    if seen.upstream {
        println!("  {GREEN}● в прошлый раз обход был выше — проверено {давность}{RESET}");
        if seen.устарел() {
            println!("  {DIM}давно; свой zapret можно выключить, но лучше сперва --deep{RESET}");
        } else {
            println!("  {DIM}свой zapret тут, скорее всего, лишний: net off{RESET}");
        }
    } else {
        println!("  {RED}○ в прошлый раз обхода выше не было — проверено {давность}{RESET}");
        println!("  {DIM}свой обход в этой сети нужен{RESET}");
    }
}

fn mark(on: bool, text: &str) {
    let (color, dot) = if on { (GREEN, "●") } else { (DIM, "○") };
    println!("    {color}{dot} {text}{RESET}");
}

/// Открывается ли заблокированное прямо сейчас. Хватает половины списка:
/// один сайт может лежать сам по себе.
fn probe_blocked() -> bool {
    let open = BLOCKED
        .iter()
        .filter(|(_, url)| probe::reachable(url, Duration::from_secs(8)))
        .count();
    open * 2 > BLOCKED.len()
}

/// Проверка с временно снятым своим обходом: иначе не отличить, кто именно
/// чинит трафик — пульт или роутер.
fn deep_check(
    cfg: &Config,
    zapret_on: bool,
    tunnel_on: bool,
    сеть: Option<&str>,
) -> Result<(), String> {
    if tunnel_on {
        return Err("сначала сними туннель: net vpn off — из-под него сети не видно".into());
    }
    let z = Zapret::new(cfg);
    println!("  {DIM}выключаю свой zapret на несколько секунд...{RESET}");
    if zapret_on {
        z.stop()?;
        std::thread::sleep(Duration::from_millis(700));
    }
    let upstream = probe_blocked();
    crate::network::remember(сеть, upstream);
    if zapret_on {
        println!("  {DIM}возвращаю как было...{RESET}");
        z.start()?;
    }
    if upstream {
        println!("  {GREEN}● обход стоит выше — без своего zapret всё равно открывается{RESET}");
        println!("  {DIM}свой можно держать выключенным: net off{RESET}");
    } else {
        println!("  {RED}○ выше обхода нет — без своего zapret заблокированное закрыто{RESET}");
    }
    Ok(())
}

fn conflicts(
    zapret_on: bool,
    tunnel_on: bool,
    foreign: &[String],
    proxy: bool,
    exit: Option<&Exit>,
) -> Vec<String> {
    let mut out = Vec::new();
    if tunnel_on && zapret_on {
        out.push(
            "zapret при поднятом туннеле не делает ничего: трафик уходит внутри туннеля, DPI видит только его. Выключи: net off".to_string(),
        );
    }
    if tunnel_on && !foreign.is_empty() {
        out.push(format!(
            "рядом со своим туннелем работает {} — оба поднимают свой маршрут по умолчанию, победит кто угодно. Оставь один",
            foreign.join(", ")
        ));
    }
    if foreign.len() > 1 {
        out.push(format!("сразу несколько чужих туннелей: {}", foreign.join(", ")));
    }
    if proxy && tunnel_on {
        out.push(
            "в переменных среды прописан прокси: часть программ пойдёт через него мимо туннеля"
                .to_string(),
        );
    }
    if let Some(exit) = exit
        && tunnel_on && !is_tunnel(&exit.interface) {
            out.push(format!(
                "туннель поднят, но трафик уходит через {} — маршрут он на себя не забрал",
                exit.interface
            ));
        }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn туннели_узнаются_по_имени() {
        for name in ["tun0", "utun3", "wg0", "tailscale0", "nordlynx"] {
            assert!(is_tunnel(name), "{name} — туннель");
        }
        for name in ["wlan0", "eth0", "enp3s0", "lo"] {
            assert!(!is_tunnel(name), "{name} — обычный интерфейс");
        }
    }

    #[test]
    fn туннель_и_zapret_вместе_названы_конфликтом() {
        let out = conflicts(true, true, &[], false, None);
        assert!(out.iter().any(|line| line.contains("zapret")), "{out:?}");
    }

    #[test]
    fn один_включённый_обход_никому_не_мешает() {
        assert!(conflicts(true, false, &[], false, None).is_empty());
        assert!(conflicts(false, true, &[], false, None).is_empty());
    }

    #[test]
    fn чужой_туннель_рядом_со_своим_замечен() {
        let foreign = vec!["Happ".to_string()];
        let out = conflicts(false, true, &foreign, false, None);
        assert!(out.iter().any(|line| line.contains("Happ")), "{out:?}");
    }

    #[test]
    fn туннель_не_забравший_маршрут_виден() {
        let exit = Exit {
            interface: "wlan0".to_string(),
            gateway: Some("192.168.1.1".to_string()),
        };
        let out = conflicts(false, true, &[], false, Some(&exit));
        assert!(out.iter().any(|line| line.contains("маршрут")), "{out:?}");
    }
}
