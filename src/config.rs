//! Настройки и пути.
//!
//! Формат конфига — простые строки `ключ = значение`, чтобы не тащить парсер
//! TOML ради десятка полей. Всё, что не задано, определяется автоматически.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Config {
    /// Папка установки zapret (та, где лежат conf.env и стратегии).
    pub zapret_dir: Option<PathBuf>,
    /// Имя systemd-юнита zapret, если управление идёт через него.
    pub zapret_service: String,
    /// Бинарь tglock-cli.
    pub tglock_bin: Option<PathBuf>,
    /// Порт локального прокси Telegram.
    pub tg_port: u16,
    /// Слушать ли прокси Telegram на всю локальную сеть (для телефона).
    pub tg_lan: bool,
    /// Приложение Happ.
    pub happ_bin: Option<PathBuf>,
    /// Ядро sing-box: своё, вместо Happ. Ищется рядом с состоянием и в PATH.
    pub core_bin: Option<PathBuf>,
    /// Как часто сторож проверяет связь, минуты.
    pub watch_interval_min: u32,
    /// Следить ли за zapret.
    pub watch_zapret: bool,
    /// Следить ли за прокси Telegram.
    pub watch_telegram: bool,
    /// Порт прокси для раздачи на телефон.
    pub share_port: u16,
    /// Пароль прокси раздачи. Пусто — прокси открыт всей локальной сети.
    pub share_password: Option<String>,
    /// Порт локального сплит-прокси.
    pub split_port: u16,
    /// Заграничный SOCKS, куда сплит гонит домены из списка (Happ: 127.0.0.1:10808).
    pub split_upstream: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            zapret_dir: None,
            zapret_service: "zapret_discord_youtube.service".to_string(),
            tglock_bin: None,
            tg_port: 1080,
            tg_lan: true,
            happ_bin: None,
            core_bin: None,
            watch_interval_min: 10,
            watch_zapret: true,
            watch_telegram: true,
            share_port: crate::share::DEFAULT_PORT,
            share_password: None,
            split_port: crate::split::DEFAULT_PORT,
            split_upstream: crate::split::DEFAULT_UPSTREAM.to_string(),
        }
    }
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Папка состояния: конфиг, pid-файлы, секрет прокси, скачанные бинари.
pub fn state_dir() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(home)
            .join("netpult")
    } else if cfg!(target_os = "macos") {
        home().join("Library/Application Support/netpult")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".local/share"))
            .join("netpult")
    }
}

pub fn config_path() -> PathBuf {
    state_dir().join("config")
}

pub fn state_dir_ensure() -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir())
}

fn first_existing(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|p| p.exists()).cloned()
}

/// Ищет уже установленный zapret и tglock. Сам поиск живёт в `deps`: он
/// смотрит и в папках программ, и в склонированных репозиториях, и в PATH.
fn detect_zapret_dir() -> Option<PathBuf> {
    crate::deps::find_zapret().map(|f| f.path)
}

fn detect_tglock() -> Option<PathBuf> {
    crate::deps::find_tglock().map(|f| f.path)
}

fn detect_happ() -> Option<PathBuf> {
    let h = home();
    let candidates = if cfg!(target_os = "macos") {
        vec![PathBuf::from("/Applications/Happ.app/Contents/MacOS/Happ")]
    } else if cfg!(windows) {
        vec![h.join("AppData/Local/Programs/Happ/Happ.exe")]
    } else {
        vec![
            h.join("Apps/Happ.linux.x64.pkg/opt/happ/bin/Happ"),
            PathBuf::from("/opt/happ/bin/Happ"),
        ]
    };
    first_existing(&candidates)
}

/// Ядро sing-box: сначала своё, положенное рядом с состоянием, потом системное.
fn detect_core() -> Option<PathBuf> {
    let name = if cfg!(windows) {
        "sing-box.exe"
    } else {
        "sing-box"
    };
    let mut candidates = vec![state_dir().join(name), home().join(".local/bin").join(name)];
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|p| p.join(name)));
    }
    first_existing(&candidates)
}

fn parse(text: &str) -> HashMap<String, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

impl Config {
    pub fn load() -> Config {
        let mut cfg = Config::default();

        if let Ok(text) = std::fs::read_to_string(config_path()) {
            let map = parse(&text);
            if let Some(v) = map.get("zapret_dir") {
                cfg.zapret_dir = Some(PathBuf::from(v));
            }
            if let Some(v) = map.get("zapret_service") {
                cfg.zapret_service = v.clone();
            }
            if let Some(v) = map.get("tglock_bin") {
                cfg.tglock_bin = Some(PathBuf::from(v));
            }
            if let Some(v) = map.get("tg_port").and_then(|v| v.parse().ok()) {
                cfg.tg_port = v;
            }
            if let Some(v) = map.get("tg_lan") {
                cfg.tg_lan = v != "false" && v != "0";
            }
            if let Some(v) = map.get("happ_bin") {
                cfg.happ_bin = Some(PathBuf::from(v));
            }
            if let Some(v) = map.get("core_bin") {
                cfg.core_bin = Some(PathBuf::from(v));
            }
            if let Some(v) = map.get("watch_interval_min").and_then(|v| v.parse().ok()) {
                cfg.watch_interval_min = v;
            }
            if let Some(v) = map.get("watch_zapret") {
                cfg.watch_zapret = v != "false" && v != "0";
            }
            if let Some(v) = map.get("watch_telegram") {
                cfg.watch_telegram = v != "false" && v != "0";
            }
            if let Some(v) = map.get("share_port").and_then(|v| v.parse().ok()) {
                cfg.share_port = v;
            }
            if let Some(v) = map.get("share_password") {
                cfg.share_password = Some(v.clone()).filter(|s| !s.is_empty());
            }
            if let Some(v) = map.get("split_port").and_then(|v| v.parse().ok()) {
                cfg.split_port = v;
            }
            if let Some(v) = map.get("split_upstream") {
                cfg.split_upstream = v.clone();
            }
        }

        if cfg.zapret_dir.is_none() {
            cfg.zapret_dir = detect_zapret_dir();
        }
        if cfg.tglock_bin.is_none() {
            cfg.tglock_bin = detect_tglock();
        }
        if cfg.happ_bin.is_none() {
            cfg.happ_bin = detect_happ();
        }
        if cfg.core_bin.is_none() {
            cfg.core_bin = detect_core();
        }
        cfg
    }

    /// Файл секрета прокси. Если прокси уже поднимали другим способом,
    /// секрет берётся оттуда: иначе ссылка окажется от другого прокси.
    pub fn tg_secret_path(&self) -> PathBuf {
        let own = state_dir().join("tglock.secret");
        if own.exists() {
            return own;
        }
        let h = home();
        let known = [
            h.join(".config/tglock/secret"),
            h.join(".local/share/tgqr/secret"),
        ];
        known.into_iter().find(|p| p.exists()).unwrap_or(own)
    }

    pub fn tg_pid_path(&self) -> PathBuf {
        state_dir().join("tglock.pid")
    }

    pub fn tg_log_path(&self) -> PathBuf {
        state_dir().join("tglock.log")
    }

    pub fn ensure_state_dir(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(state_dir())
    }
}

/// Читает `ключ=значение` из conf.env самого zapret.
pub fn read_env_value(path: &Path, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines()
        .map(str::trim)
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| k.trim() == key)
        .map(|(_, v)| v.trim().to_string())
}
