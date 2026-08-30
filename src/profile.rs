//! Профили под сеть: дома нужен один набор, в гостях другой.
//!
//! Профиль привязывается к имени сети Wi-Fi, а если его не видно — к шлюзу.
//! Пульт узнаёт сеть и включает то, что в ней было включено в прошлый раз.

use crate::config::{home, state_dir, Config};
use crate::telegram::Telegram;
use crate::zapret::{State, Zapret};
use std::collections::BTreeMap;
use std::process::Command;

/// Как выглядит текущая сеть: имя Wi-Fi или адрес шлюза.
pub fn current_network() -> Option<String> {
    if let Some(ssid) = wifi_ssid() {
        return Some(ssid);
    }
    gateway().map(|g| format!("шлюз {g}"))
}

fn output(command: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(command).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn wifi_ssid() -> Option<String> {
    if cfg!(target_os = "linux") {
        if let Some(name) = output("iwgetid", &["-r"]) {
            return Some(name);
        }
        let list = output("nmcli", &["-t", "-f", "active,ssid", "dev", "wifi"])?;
        list.lines()
            .find(|l| l.starts_with("да:") || l.starts_with("yes:"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, ssid)| ssid.to_string())
    } else if cfg!(target_os = "macos") {
        let text = output(
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
            &["-I"],
        )?;
        text.lines()
            .find(|l| l.trim_start().starts_with("SSID:"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
    } else {
        let text = output("netsh", &["wlan", "show", "interfaces"])?;
        text.lines()
            .find(|l| l.trim_start().starts_with("SSID") && !l.contains("BSSID"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
    }
}

fn gateway() -> Option<String> {
    if cfg!(target_os = "linux") {
        let text = output("ip", &["route", "show", "default"])?;
        text.split_whitespace().nth(2).map(str::to_string)
    } else if cfg!(target_os = "macos") {
        let text = output("route", &["-n", "get", "default"])?;
        text.lines()
            .find(|l| l.trim_start().starts_with("gateway:"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
    } else {
        let text = output("powershell", &["-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"])?;
        Some(text)
    }
}

/// Что должно быть включено в этой сети.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Profile {
    pub zapret: bool,
    pub telegram: bool,
    pub strategy: Option<String>,
}

fn profiles_path() -> std::path::PathBuf {
    let _ = home();
    state_dir().join("profiles")
}

/// Читает все профили: имя сети → что включать.
pub fn load() -> BTreeMap<String, Profile> {
    let mut out = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(profiles_path()) else {
        return out;
    };

    let mut name: Option<String> = None;
    let mut profile = Profile::default();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("сеть ").or_else(|| line.strip_prefix("network ")) {
            if let Some(previous) = name.take() {
                out.insert(previous, std::mem::take(&mut profile));
            }
            name = Some(rest.trim().to_string());
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        let on = value == "on" || value == "да" || value == "true";
        match key {
            "zapret" => profile.zapret = on,
            "telegram" => profile.telegram = on,
            "strategy" => profile.strategy = Some(value.to_string()),
            _ => {}
        }
    }
    if let Some(previous) = name {
        out.insert(previous, profile);
    }
    out
}

fn save_all(profiles: &BTreeMap<String, Profile>) -> Result<(), String> {
    std::fs::create_dir_all(state_dir()).map_err(|e| e.to_string())?;
    let mut text = String::from("# Профили netpult: что включать в какой сети.\n\n");
    for (name, p) in profiles {
        text.push_str(&format!("сеть {name}\n"));
        text.push_str(&format!("zapret = {}\n", if p.zapret { "on" } else { "off" }));
        text.push_str(&format!("telegram = {}\n", if p.telegram { "on" } else { "off" }));
        if let Some(s) = &p.strategy {
            text.push_str(&format!("strategy = {s}\n"));
        }
        text.push('\n');
    }
    std::fs::write(profiles_path(), text).map_err(|e| e.to_string())
}

/// Снимает профиль с того, что включено прямо сейчас.
pub fn snapshot(cfg: &Config) -> Profile {
    let z = Zapret::new(cfg);
    Profile {
        zapret: z.state() == State::On,
        telegram: Telegram::new(cfg).running(),
        strategy: z.strategy(),
    }
}

pub fn save_current(cfg: &Config) -> Result<(String, Profile), String> {
    let network = current_network().ok_or("не вижу, в какой я сети")?;
    let profile = snapshot(cfg);
    let mut all = load();
    all.insert(network.clone(), profile.clone());
    save_all(&all)?;
    Ok((network, profile))
}

pub fn forget(network: &str) -> Result<(), String> {
    let mut all = load();
    if all.remove(network).is_none() {
        return Err(format!("профиля для «{network}» нет"));
    }
    save_all(&all)
}

/// Приводит состояние к профилю текущей сети. Возвращает, что сделал.
pub fn apply(cfg: &Config) -> Result<Vec<String>, String> {
    let network = current_network().ok_or("не вижу, в какой я сети")?;
    let profile = load()
        .get(&network)
        .cloned()
        .ok_or_else(|| format!("для сети «{network}» профиля нет"))?;

    let mut done = Vec::new();
    let z = Zapret::new(cfg);

    if let Some(strategy) = &profile.strategy
        && z.strategy().as_deref() != Some(strategy.as_str()) {
            z.set_strategy(strategy)?;
            done.push(format!("стратегия {strategy}"));
        }

    match (profile.zapret, z.state()) {
        (true, State::Off) => {
            z.start()?;
            done.push("zapret включён".into());
        }
        (false, State::On) => {
            z.stop()?;
            done.push("zapret выключен".into());
        }
        _ => {}
    }

    let tg = Telegram::new(cfg);
    match (profile.telegram, tg.running()) {
        (true, false) => {
            tg.start()?;
            done.push("прокси Telegram включён".into());
        }
        (false, true) => {
            tg.stop()?;
            done.push("прокси Telegram выключен".into());
        }
        _ => {}
    }

    Ok(done)
}
