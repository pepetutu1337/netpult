//! Локальный прокси для Telegram (TGLock) и ссылка с QR для телефона.

use crate::config::Config;
use crate::probe;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

pub struct Telegram<'a> {
    cfg: &'a Config,
}

impl<'a> Telegram<'a> {
    pub fn new(cfg: &'a Config) -> Self {
        Telegram { cfg }
    }

    pub fn binary(&self) -> Option<&PathBuf> {
        self.cfg.tglock_bin.as_ref()
    }

    pub fn running(&self) -> bool {
        probe::port_open(self.cfg.tg_port, Duration::from_millis(300))
    }

    pub fn start(&self) -> Result<(), String> {
        if self.running() {
            return Ok(());
        }
        let bin = self.binary().ok_or(
            "бинарь tglock-cli не найден — положи его рядом с настройками или укажи tglock_bin",
        )?;
        self.cfg.ensure_state_dir().map_err(|e| e.to_string())?;

        let log = std::fs::File::create(self.cfg.tg_log_path()).map_err(|e| e.to_string())?;
        let errlog = log.try_clone().map_err(|e| e.to_string())?;

        let mut command = Command::new(bin);
        command
            .arg("--quiet")
            .args(["--port", &self.cfg.tg_port.to_string()])
            .arg("--secret-file")
            .arg(self.cfg.tg_secret_path())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(errlog));
        if self.cfg.tg_lan {
            command.arg("--lan");
        }

        let child = command.spawn().map_err(|e| format!("не запустился: {e}"))?;
        std::fs::write(self.cfg.tg_pid_path(), child.id().to_string()).ok();

        for _ in 0..20 {
            if self.running() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        Err(format!(
            "прокси не поднялся, смотри {}",
            self.cfg.tg_log_path().display()
        ))
    }

    pub fn stop(&self) -> Result<(), String> {
        let pid = std::fs::read_to_string(self.cfg.tg_pid_path())
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        let Some(pid) = pid else {
            return Err("не знаю, какой процесс гасить: pid-файла нет".into());
        };

        let ok = if cfg!(windows) {
            Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        } else {
            Command::new("kill")
                .arg(pid.to_string())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };

        std::fs::remove_file(self.cfg.tg_pid_path()).ok();
        if ok {
            Ok(())
        } else {
            Err("процесс не отозвался".into())
        }
    }

    fn secret(&self) -> Option<String> {
        std::fs::read_to_string(self.cfg.tg_secret_path())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Ссылка для клиента Telegram. Префикс `dd` перед секретом обязателен:
    /// он включает режим маскировки трафика.
    pub fn link(&self, host: &str) -> Option<String> {
        let secret = self.secret()?;
        Some(format!(
            "tg://proxy?server={host}&port={}&secret=dd{secret}",
            self.cfg.tg_port
        ))
    }

    pub fn local_link(&self) -> Option<String> {
        self.link("127.0.0.1")
    }

    pub fn lan_link(&self) -> Option<String> {
        let ip = probe::lan_ip()?;
        self.link(&ip.to_string())
    }
}
