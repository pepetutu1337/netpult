//! Управление обходом DPI.
//!
//! Движок у каждой системы свой, стратегии — общие:
//!   Linux   — nfqws через NFQUEUE, обычно уже обёрнут в systemd-юнит;
//!   Windows — winws через WinDivert (тот же проект, другой драйвер);
//!   macOS   — tpws через PF: только TCP, UDP этот бэкенд не умеет.

use crate::config::{read_env_value, Config};
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum State {
    On,
    Off,
    /// Не нашли установленный zapret.
    Missing,
}

pub struct Zapret<'a> {
    cfg: &'a Config,
}

impl<'a> Zapret<'a> {
    pub fn new(cfg: &'a Config) -> Self {
        Zapret { cfg }
    }

    pub fn dir(&self) -> Option<&PathBuf> {
        self.cfg.zapret_dir.as_ref()
    }

    pub fn state(&self) -> State {
        if self.dir().is_none() {
            return State::Missing;
        }
        if cfg!(target_os = "linux") {
            let out = Command::new("systemctl")
                .args(["is-active", &self.cfg.zapret_service])
                .output();
            match out {
                Ok(o) if String::from_utf8_lossy(&o.stdout).trim() == "active" => State::On,
                _ => State::Off,
            }
        } else {
            // На Windows и macOS процесс запускается напрямую, не через службу.
            if process_running(engine_process_name()) { State::On } else { State::Off }
        }
    }

    pub fn strategy(&self) -> Option<String> {
        let dir = self.dir()?;
        read_env_value(&dir.join("conf.env"), "strategy")
    }

    /// Доступные стратегии: сначала свои, потом штатные.
    pub fn strategies(&self) -> Vec<String> {
        let Some(dir) = self.dir() else {
            return Vec::new();
        };
        let mut custom = list_bat(&dir.join("custom-strategies"), |_| true);
        custom.sort();
        let mut stock = list_bat(&dir.join("zapret-latest"), |name| {
            name.starts_with("general") || name.starts_with("discord")
        });
        stock.sort();
        custom.extend(stock);
        custom
    }

    /// Ставит стратегию по имени или по номеру из списка и перезапускает движок.
    pub fn set_strategy(&self, want: &str) -> Result<String, String> {
        let dir = self.dir().ok_or("zapret не найден")?;
        let list = self.strategies();

        let name = if let Ok(index) = want.parse::<usize>() {
            list.get(index.wrapping_sub(1))
                .cloned()
                .ok_or_else(|| format!("нет стратегии под номером {index}"))?
        } else {
            let with_ext = if want.ends_with(".bat") {
                want.to_string()
            } else {
                format!("{want}.bat")
            };
            list.iter()
                .find(|s| *s == &with_ext)
                .cloned()
                .ok_or_else(|| format!("стратегия «{with_ext}» не найдена"))?
        };

        let conf = dir.join("conf.env");
        let text = std::fs::read_to_string(&conf).map_err(|e| e.to_string())?;
        let updated: String = text
            .lines()
            .map(|line| {
                if line.trim_start().starts_with("strategy=") {
                    format!("strategy={name}")
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&conf, updated + "\n").map_err(|e| e.to_string())?;

        if self.state() == State::On {
            self.restart()?;
        }
        Ok(name)
    }

    pub fn start(&self) -> Result<(), String> {
        self.service("start")
    }

    pub fn stop(&self) -> Result<(), String> {
        self.service("stop")
    }

    pub fn restart(&self) -> Result<(), String> {
        self.service("restart")
    }

    fn service(&self, action: &str) -> Result<(), String> {
        if self.dir().is_none() {
            return Err("zapret не установлен".into());
        }
        if cfg!(target_os = "linux") {
            let status = Command::new("sudo")
                .args(["systemctl", action, &self.cfg.zapret_service])
                .status()
                .map_err(|e| format!("не запустился systemctl: {e}"))?;
            if status.success() {
                Ok(())
            } else {
                Err(format!("systemctl {action} завершился с ошибкой"))
            }
        } else {
            Err(format!(
                "движок для {} ещё не подключён — пока управляй им родными средствами",
                std::env::consts::OS
            ))
        }
    }
}

fn list_bat(dir: &PathBuf, keep: impl Fn(&str) -> bool) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.path().is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| name.ends_with(".bat") && keep(name))
        .collect()
}

fn engine_process_name() -> &'static str {
    if cfg!(windows) {
        "winws.exe"
    } else if cfg!(target_os = "macos") {
        "tpws"
    } else {
        "nfqws"
    }
}

pub fn process_running(name: &str) -> bool {
    if cfg!(windows) {
        Command::new("tasklist")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(name))
            .unwrap_or(false)
    } else {
        Command::new("pgrep")
            .args(["-x", name])
            .output()
            .map(|o| !o.stdout.is_empty())
            .unwrap_or(false)
    }
}
