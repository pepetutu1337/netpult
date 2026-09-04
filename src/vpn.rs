//! VPN: определение поднятого туннеля и запуск клиента Happ.
//!
//! Само подключение включается в окне Happ — управлять им из командной строки
//! нечем, у клиента нет такого интерфейса. Здесь только «поднят ли туннель»
//! и «открыть окно».

use crate::config::Config;
use crate::zapret::process_running;
use std::process::{Command, Stdio};

pub struct Vpn<'a> {
    cfg: &'a Config,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum State {
    /// Туннель поднят, трафик идёт через ноду.
    Tunnel,
    /// Клиент открыт, но туннеля нет.
    AppOnly,
    Off,
}

impl<'a> Vpn<'a> {
    pub fn new(cfg: &'a Config) -> Self {
        Vpn { cfg }
    }

    pub fn state(&self) -> State {
        if tunnel_up() {
            State::Tunnel
        } else if process_running(app_process_name()) {
            State::AppOnly
        } else {
            State::Off
        }
    }

    pub fn open(&self) -> Result<(), String> {
        let bin = self
            .cfg
            .happ_bin
            .as_ref()
            .ok_or("клиент Happ не найден — укажи happ_bin в настройках")?;
        Command::new(bin)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("не запустился: {e}"))?;
        Ok(())
    }

    pub fn close(&self) -> Result<(), String> {
        let name = app_process_name();
        let ok = if cfg!(windows) {
            Command::new("taskkill")
                .args(["/IM", name, "/F"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        } else {
            Command::new("pkill")
                .args(["-x", name])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };
        if ok {
            Ok(())
        } else {
            Err("клиент не запущен".into())
        }
    }
}

/// Есть ли среди интерфейсов `utun*` хоть один с выданным адресом.
///
/// `ifconfig` на маке пишет интерфейсы подряд, без пустых строк между ними:
/// имя начинается с начала строки, подробности — с отступа. Поэтому идём по
/// строкам и запоминаем, к какому интерфейсу относится текущая, — разбиение
/// по пустой строке склеивало бы весь вывод в один кусок, и туннель не
/// находился бы никогда.
fn utun_with_address(text: &str) -> bool {
    let mut внутри_utun = false;
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) {
            внутри_utun = line.starts_with("utun");
            continue;
        }
        if внутри_utun && line.trim_start().starts_with("inet ") {
            return true;
        }
    }
    false
}

fn app_process_name() -> &'static str {
    if cfg!(windows) { "Happ.exe" } else { "Happ" }
}

/// Есть ли поднятый туннельный интерфейс.
fn tunnel_up() -> bool {
    if cfg!(windows) {
        // У туннеля Happ на Windows отдельный адаптер; ищем его в списке.
        Command::new("ipconfig")
            .output()
            .map(|o| {
                let text = String::from_utf8_lossy(&o.stdout).to_lowercase();
                text.contains("happ") || text.contains("wintun")
            })
            .unwrap_or(false)
    } else if cfg!(target_os = "macos") {
        Command::new("ifconfig")
            .output()
            .map(|o| utun_with_address(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or(false)
    } else {
        Command::new("ip")
            .args(["-br", "link"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout).lines().any(|line| {
                    let name = line.split_whitespace().next().unwrap_or("");
                    let up = line.contains(" UP ") || line.contains(" UNKNOWN ");
                    up && (name.starts_with("tun") || name.starts_with("happ"))
                })
            })
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::utun_with_address;

    /// Настоящий вывод `ifconfig` на macOS: пустых строк между интерфейсами
    /// нет, подробности идут с табуляции.
    const IFCONFIG: &str = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether a4:83:e7:00:00:00
\tinet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet6 fe80::1234%utun0 prefixlen 64 scopeid 0x10
";

    #[test]
    fn туннель_без_адреса_не_считается() {
        // utun0 есть, но с одним лишь локальным IPv6 — это служебный
        // интерфейс маковских VPN-заготовок, а не поднятый туннель.
        assert!(!utun_with_address(IFCONFIG));
    }

    #[test]
    fn туннель_с_адресом_находится() {
        let text = format!(
            "{IFCONFIG}utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n\tinet 10.7.0.2 --> 10.7.0.2 netmask 0xffffffff\n"
        );
        assert!(utun_with_address(&text));
    }

    #[test]
    fn чужой_интерфейс_с_адресом_не_путается_с_туннелем() {
        // en0 с адресом идёт раньше utun — признак не должен протечь на него.
        assert!(!utun_with_address(
            "en0: flags=8863<UP> mtu 1500\n\tinet 192.168.1.42 netmask 0xffffff00\nutun0: flags=8051<UP> mtu 1380\n"
        ));
    }
}
