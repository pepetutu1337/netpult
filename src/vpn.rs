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
        if ok { Ok(()) } else { Err("клиент не запущен".into()) }
    }
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
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split("\n\n")
                    .any(|block| block.starts_with("utun") && block.contains("inet "))
            })
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
