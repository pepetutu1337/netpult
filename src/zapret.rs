//! Управление обходом DPI.
//!
//! Движок у каждой системы свой, стратегии — общие:
//!   Linux   — nfqws через NFQUEUE, обычно уже обёрнут в systemd-юнит;
//!   Windows — winws через WinDivert (тот же проект, другой драйвер);
//!   macOS   — tpws через PF: только TCP, UDP этот бэкенд не умеет.

use crate::config::{Config, read_env_value};
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
            if process_running(engine_process_name()) {
                State::On
            } else {
                State::Off
            }
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
        self.service("start")?;
        clear_manual_off();
        Ok(())
    }

    pub fn stop(&self) -> Result<(), String> {
        self.service("stop")?;
        mark_manual_off();
        Ok(())
    }

    pub fn restart(&self) -> Result<(), String> {
        self.service("restart")
    }

    /// Выключали ли zapret явной командой (`net zapret off`/`toggle`), а не
    /// он сам упал. Сторож лечит только то, что сломалось само — ручное
    /// выключение не чинит, пока не попросят обратно (`start`/`toggle`).
    pub fn is_manual_off(&self) -> bool {
        manual_off_marker().exists()
    }

    fn service(&self, action: &str) -> Result<(), String> {
        if self.dir().is_none() {
            return Err("zapret не установлен".into());
        }
        if cfg!(target_os = "linux") {
            // Служба, перезапущенная слишком часто, попадает в start-limit-hit
            // и дальше не стартует вовсе, пока счётчик не сброшен. Сбрасываем
            // молча: для «включи обход» это внутренняя кухня systemd.
            if action != "stop" {
                let _ = systemctl("reset-failed", &self.cfg.zapret_service);
            }
            match systemctl(action, &self.cfg.zapret_service) {
                Ok(()) => Ok(()),
                Err(trouble) => Err(format!("systemctl {action}: {trouble}")),
            }
        } else {
            Err(format!(
                "движок для {} ещё не подключён — пока управляй им родными средствами",
                std::env::consts::OS
            ))
        }
    }
}

/// Выполнить действие над службой.
///
/// Сперва без sudo: во многих сборках polkit разрешает управлять службой
/// хозяину активного сеанса, и тогда пароль спрашивать не за что. Пароль
/// просим только если без него правда не вышло.
fn systemctl(action: &str, service: &str) -> Result<(), String> {
    let plain = Command::new("systemctl")
        .args([action, service])
        .output()
        .map_err(|e| format!("не запустился systemctl: {e}"))?;
    if plain.status.success() {
        return Ok(());
    }
    crate::sudoer::ready()?;
    let out = crate::sudoer::command()
        .args(["systemctl", action, service])
        .output()
        .map_err(|e| format!("не запустился sudo: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let trouble = String::from_utf8_lossy(&out.stderr);
    if trouble.contains("password is required") || trouble.contains("пароль") {
        return Err(crate::sudoer::NEED_PASSWORD.to_string());
    }
    Err(trouble
        .trim()
        .lines()
        .next()
        .unwrap_or("не вышло")
        .to_string())
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

fn manual_off_marker() -> PathBuf {
    crate::config::state_dir().join("zapret.manual-off")
}

fn mark_manual_off() {
    let _ = std::fs::create_dir_all(crate::config::state_dir());
    let _ = std::fs::write(manual_off_marker(), "");
}

fn clear_manual_off() {
    let _ = std::fs::remove_file(manual_off_marker());
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
