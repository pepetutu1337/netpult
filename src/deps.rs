//! Зависимости пульта: где они лежат и как их поставить.
//!
//! Пульт сам ничего не обходит: DPI дурит `nfqws` из zapret, туннель поднимает
//! `sing-box`, Telegram прикрывает `tglock-cli`. Без них команды упираются в
//! «не найдено», и человек остаётся один на один с чужими репозиториями.
//! Здесь собрано всё про них: поиск по всем разумным местам (включая папки
//! склонированных репозиториев), установка в одно предсказуемое место и
//! честный рассказ, что именно не вышло.
//!
//! Про скачивание: файлы релизов GitHub лежат на `objects.githubusercontent.com`,
//! а его диапазон 185.199.108–111.x закрыт в России **по IP** — TCP-соединение
//! не встаёт вообще, дурить DPI нечего. Поэтому источник не один:
//! сначала наш склад через jsDelivr (Fastly, тот диапазон не трогает),
//! потом обычная ссылка релиза, потом медленные зеркала, а если и это мимо —
//! пульт принимает принесённый руками файл.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{self, Config};

/// Что пульту нужно снаружи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Zapret,
    Tglock,
    Core,
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Zapret, Kind::Tglock, Kind::Core];

    /// Короткое имя — им же зовут в командах: `net deps install zapret`.
    pub fn key(self) -> &'static str {
        match self {
            Kind::Zapret => "zapret",
            Kind::Tglock => "tglock",
            Kind::Core => "core",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Kind::Zapret => "zapret",
            Kind::Tglock => "tglock",
            Kind::Core => "ядро sing-box",
        }
    }

    pub fn about(self) -> &'static str {
        match self {
            Kind::Zapret => "обход DPI: YouTube, Discord, звонки",
            Kind::Tglock => "прокси Telegram без чужих серверов",
            Kind::Core => "туннель, сплит и шифрованный DNS",
        }
    }

    /// Команды пульта, которые без этого не работают.
    pub fn needed_for(self) -> &'static str {
        match self {
            Kind::Zapret => "net on, net tune, net strat",
            Kind::Tglock => "net tg on, net tg qr",
            Kind::Core => "net vpn, net split, net dns",
        }
    }

    pub fn parse(word: &str) -> Option<Kind> {
        match word {
            "zapret" | "запрет" | "dpi" => Some(Kind::Zapret),
            "tglock" | "tg" | "telegram" => Some(Kind::Tglock),
            "core" | "sing-box" | "singbox" | "ядро" => Some(Kind::Core),
            _ => None,
        }
    }
}

/// Найденная зависимость: где лежит и откуда её взяли.
#[derive(Debug, Clone)]
pub struct Found {
    pub path: PathBuf,
    /// Человеческое «откуда»: своя папка, чужая установка, PATH, конфиг.
    pub source: &'static str,
}

/// Куда пульт кладёт то, что скачал сам.
pub fn install_dir() -> PathBuf {
    config::state_dir().join("deps")
}

fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

/// Папки, в которых люди держат программы и склонированные репозитории.
///
/// Список нарочно щедрый: цель — чтобы у человека, который уже поставил zapret
/// руками или собрал tglock из исходников, пульт увидел готовое, а не заставлял
/// ставить второй раз.
fn search_roots() -> Vec<PathBuf> {
    let h = config::home();
    let mut roots = vec![
        install_dir(),
        config::state_dir(),
        h.clone(),
        h.join("Apps"),
        h.join("apps"),
        h.join("Dev"),
        h.join("dev"),
        h.join("Projects"),
        h.join("projects"),
        h.join("Downloads"),
        h.join("Загрузки"),
        h.join("git"),
        h.join("src"),
        h.join("code"),
        h.join(".local/share"),
        h.join(".local/bin"),
        h.join("opt"),
    ];
    if !cfg!(windows) {
        roots.extend([
            PathBuf::from("/opt"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/usr/local/share"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/share"),
        ]);
    }
    roots
}

/// Ищет исполняемый файл: сначала прямо в известных папках, потом на уровень
/// глубже (папка репозитория), потом в PATH.
fn find_exe(names: &[String], deeper: &[&str]) -> Option<Found> {
    let own = install_dir();
    for name in names {
        let mine = own.join(name);
        if mine.is_file() {
            return Some(Found {
                path: mine,
                source: "поставлен пультом",
            });
        }
    }

    for root in search_roots() {
        for name in names {
            let direct = root.join(name);
            if direct.is_file() {
                return Some(Found {
                    path: direct,
                    source: "уже был в системе",
                });
            }
        }
        // Папка репозитория: ~/Dev/tglock/tglock-cli, ~/Dev/tglock/target/release/…
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten().take(400) {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            for name in names {
                for sub in deeper {
                    let candidate = if sub.is_empty() {
                        dir.join(name)
                    } else {
                        dir.join(sub).join(name)
                    };
                    if candidate.is_file() {
                        return Some(Found {
                            path: candidate,
                            source: "найден в папке репозитория",
                        });
                    }
                }
            }
        }
    }

    let bare = names.first()?.clone();
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(&bare);
            if candidate.is_file() {
                return Some(Found {
                    path: candidate,
                    source: "из PATH",
                });
            }
        }
    }
    None
}

/// Похожа ли папка на установленный zapret.
fn looks_like_zapret(dir: &Path) -> bool {
    dir.join("conf.env").is_file() && (dir.join("nfqws").is_file() || dir.join("service.sh").is_file())
}

/// Ищет установленный zapret где угодно, а не только там, куда его кладёт
/// официальный установщик.
///
/// Папок-кандидатов у живого человека обычно несколько: рабочая, резервная
/// копия перед обновлением, распакованный архив в Загрузках. Берём не первую
/// попавшуюся, а ту, на которую показывает служба; если службы нет — самую
/// похожую на рабочую.
pub fn find_zapret() -> Option<Found> {
    let mut best: Option<(i32, Found)> = None;
    let mut consider = |dir: PathBuf, source: &'static str| {
        if !looks_like_zapret(&dir) {
            return;
        }
        let score = zapret_score(&dir);
        if best.as_ref().is_none_or(|(top, _)| score > *top) {
            best = Some((score, Found { path: dir, source }));
        }
    };

    for root in search_roots() {
        consider(root.clone(), "уже был в системе");
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten().take(400) {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if !name.contains("zapret") {
                continue;
            }
            let source = if dir.starts_with(install_dir()) {
                "поставлен пультом"
            } else {
                "уже был в системе"
            };
            consider(dir.clone(), source);
            // Архив распакован «папка в папке».
            let Ok(inner) = std::fs::read_dir(&dir) else {
                continue;
            };
            for sub in inner.flatten().take(50) {
                consider(sub.path(), source);
            }
        }
    }
    best.map(|(_, found)| found)
}

/// Насколько папка похожа на ту, которой пользуются на самом деле.
fn zapret_score(dir: &Path) -> i32 {
    let mut score = 0;
    if service_dir().is_some_and(|used| used == dir) {
        score += 100;
    }
    if dir.starts_with(install_dir()) {
        score += 30;
    }
    if dir.join("nfqws").is_file() {
        score += 40;
    }
    if dir.join("custom-strategies").is_dir() {
        score += 10;
    }
    let name = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    // Копии перед обновлением лежат рядом и выглядят как рабочая папка.
    for mark in ["backup", "bak", "old", "copy", "копия", "резерв"] {
        if name.contains(mark) {
            score -= 60;
        }
    }
    score
}

/// Папка, из которой запускается служба zapret: она и есть рабочая.
fn service_dir() -> Option<PathBuf> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let out = Command::new("systemctl")
        .args(["cat", "zapret_discord_youtube.service"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.trim_start().starts_with("ExecStart="))?;
    let path = line.split('=').nth(1)?.split_whitespace().next()?;
    Path::new(path).parent().map(Path::to_path_buf)
}

pub fn find_tglock() -> Option<Found> {
    let names = vec![exe("tglock-cli"), exe("tglock")];
    find_exe(&names, &["", "target/release", "bin"])
}

pub fn find_core() -> Option<Found> {
    find_exe(&[exe("sing-box")], &["", "bin"])
}

/// Спрашивает версию у самого файла. Не вышло — не беда, просто не покажем.
fn ask_version(bin: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new(bin).args(args).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| !l.trim().is_empty())?;
    Some(line.trim().to_string())
}

/// Путь задан руками в файле настроек, а не найден поиском.
fn set_by_hand(kind: Kind) -> bool {
    let key = match kind {
        Kind::Zapret => "zapret_dir",
        Kind::Tglock => "tglock_bin",
        Kind::Core => "core_bin",
    };
    std::fs::read_to_string(config::config_path())
        .map(|text| {
            text.lines()
                .any(|l| l.trim_start().starts_with(key) && l.contains('='))
        })
        .unwrap_or(false)
}

/// Спрашивает версию у найденного файла. Отдельно от поиска: поиск идёт при
/// каждом запуске пульта, а запускать ради версии чужой бинарь — только по делу.
pub fn version_of(kind: Kind, path: &Path) -> Option<String> {
    match kind {
        Kind::Tglock => ask_version(path, &["--version"]),
        Kind::Core => ask_version(path, &["version"])
            .map(|v| v.replace("sing-box version ", "").trim().to_string())
            // Своя сборка ядра не проставляет версию — писать «unknown» незачем.
            .filter(|v| v != "unknown"),
        Kind::Zapret => crate::config::read_env_value(&path.join("conf.env"), "strategy")
            .map(|s| format!("стратегия {s}")),
    }
}

/// Что найдено сейчас — с учётом того, что в конфиге путь могли задать руками.
pub fn find(kind: Kind, cfg: &Config) -> Option<Found> {
    let configured = match kind {
        Kind::Zapret => cfg.zapret_dir.clone(),
        Kind::Tglock => cfg.tglock_bin.clone(),
        Kind::Core => cfg.core_bin.clone(),
    };
    if let Some(path) = configured.filter(|p| p.exists()) {
        let source = if path.starts_with(install_dir()) {
            "поставлен пультом"
        } else if set_by_hand(kind) {
            "указан в настройках"
        } else {
            "уже был в системе"
        };
        return Some(Found {
            path,
            source,
        });
    }
    match kind {
        Kind::Zapret => find_zapret(),
        Kind::Tglock => find_tglock(),
        Kind::Core => find_core(),
    }
}

// ── скачивание ──────────────────────────────────────────────────────────────

/// Наш склад бинарей: отдельный репозиторий, чтобы пульт не таскал чужие
/// сборки в своей истории. Раздаётся через jsDelivr — он живёт на Fastly, а не
/// на закрытых по IP адресах GitHub.
pub const DEPS_REPO: &str = "pepetutu1337/netpult-deps";
pub const DEPS_TAG: &str = "v1";

/// Ссылки на файл склада: сначала CDN, потом сам GitHub (github.com не закрыт,
/// закрыт только хост файлов релизов).
fn depot_urls(file: &str) -> Vec<String> {
    vec![
        format!("https://cdn.jsdelivr.net/gh/{DEPS_REPO}@{DEPS_TAG}/{file}"),
        format!("https://raw.githubusercontent.com/{DEPS_REPO}/{DEPS_TAG}/{file}"),
    ]
}

/// Ссылки на файл релиза чужого проекта: прямая и через зеркала.
///
/// Зеркала отдают файлы релизов по 400–700 Б/с — на трёхмегабайтный бинарь это
/// полтора часа. Держим их последними и только чтобы не остаться совсем ни с
/// чем: с включённым обходом или из-за границы прямая ссылка обычно работает.
fn release_urls(url: &str) -> Vec<String> {
    vec![
        url.to_string(),
        format!("https://gh-proxy.com/{url}"),
        format!("https://ghfast.top/{url}"),
    ]
}

/// Качает первый отозвавшийся источник. Возвращает ссылку, которая сработала.
pub fn download(urls: &[String], target: &Path, min_bytes: u64) -> Result<String, String> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("не создать {}: {e}", parent.display()))?;
    }
    let temp = target.with_extension("part");
    let mut trouble = String::new();
    for url in urls {
        let _ = std::fs::remove_file(&temp);
        let ok = Command::new("curl")
            .args([
                // Без -S: 404 на складе — это не ошибка, а «идём к следующему
                // источнику», и ругань curl в такой момент только пугает.
                "-fsL",
                "--connect-timeout",
                "8",
                "--max-time",
                "900",
                // Встал и молчит — не ждём четверть часа, идём к следующему.
                "--speed-time",
                "20",
                "--speed-limit",
                "2048",
                "-o",
                &temp.to_string_lossy(),
                url,
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let size = std::fs::metadata(&temp).map(|m| m.len()).unwrap_or(0);
        if ok && size >= min_bytes {
            std::fs::rename(&temp, target).map_err(|e| format!("не переложить файл: {e}"))?;
            make_runnable(target);
            return Ok(url.clone());
        }
        trouble = if size > 0 && size < min_bytes {
            format!("{url}: пришёл огрызок в {size} Б")
        } else {
            format!("{url}: не отозвался")
        };
    }
    let _ = std::fs::remove_file(&temp);
    Err(trouble)
}

/// Права на запуск и снятие карантина macOS — иначе скачанное не запустится.
fn make_runnable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
    }
    if cfg!(target_os = "macos") {
        let _ = Command::new("xattr")
            .args(["-d", "com.apple.quarantine", &path.to_string_lossy()])
            .status();
    }
}

/// Переменная окружения, которой можно подсунуть принесённый руками файл.
fn env_override(kind: Kind) -> Option<PathBuf> {
    let key = match kind {
        Kind::Zapret => "NETPULT_ZAPRET",
        Kind::Tglock => "NETPULT_TGLOCK",
        Kind::Core => "NETPULT_CORE",
    };
    std::env::var_os(key).map(PathBuf::from).filter(|p| p.exists())
}

// ── установка ───────────────────────────────────────────────────────────────

/// Ставит зависимость. `local` — принесённый руками файл или папка.
pub fn install(kind: Kind, local: Option<&Path>) -> Result<PathBuf, String> {
    std::fs::create_dir_all(install_dir())
        .map_err(|e| format!("не создать {}: {e}", install_dir().display()))?;
    let brought = local.map(PathBuf::from).or_else(|| env_override(kind));
    match kind {
        Kind::Tglock => install_tglock(brought.as_deref()),
        Kind::Core => install_core(brought.as_deref()),
        Kind::Zapret => install_zapret(brought.as_deref()),
    }
}

const TGLOCK_TAG: &str = "v2.0.0-beta.14";

fn tglock_asset() -> &'static str {
    if cfg!(target_os = "macos") {
        "tglock-cli-universal-apple-darwin"
    } else if cfg!(windows) {
        "tglock-cli-x86_64-pc-windows-msvc.exe"
    } else {
        "tglock-cli-x86_64-unknown-linux-gnu"
    }
}

fn tglock_depot_file() -> &'static str {
    if cfg!(target_os = "macos") {
        "tglock/macos-universal/tglock-cli"
    } else if cfg!(windows) {
        "tglock/windows-x86_64/tglock-cli.exe"
    } else {
        "tglock/linux-x86_64/tglock-cli"
    }
}

fn install_tglock(local: Option<&Path>) -> Result<PathBuf, String> {
    let target = install_dir().join(exe("tglock-cli"));
    if let Some(file) = local {
        std::fs::copy(file, &target).map_err(|e| format!("не скопировать {}: {e}", file.display()))?;
        make_runnable(&target);
        return Ok(target);
    }
    let mut urls = depot_urls(tglock_depot_file());
    urls.extend(release_urls(&format!(
        "https://github.com/by-sonic/tglock/releases/download/{TGLOCK_TAG}/{}",
        tglock_asset()
    )));
    let source = download(&urls, &target, 500_000).map_err(|trouble| {
        format!(
            "tglock не скачался ({trouble}).\n\
             Принеси файл с любой машины с интернетом и поставь из него:\n\
             \x20 net deps install tglock <файл>\n\
             Файл: https://github.com/by-sonic/tglock/releases → {}",
            tglock_asset()
        )
    })?;
    // Скачаться мог и мусор: обрезанный файл, страница ошибки, сборка под
    // чужую архитектуру. Пусть скажет свою версию — тогда он точно рабочий.
    if ask_version(&target, &["--version"]).is_none() {
        let _ = std::fs::remove_file(&target);
        return Err(format!(
            "скачанный tglock не запускается (источник {source}). Попробуй ещё раз или принеси файл: net deps install tglock <файл>"
        ));
    }
    Ok(target)
}

fn install_core(local: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(file) = local {
        let target = config::state_dir().join(exe("sing-box"));
        std::fs::copy(file, &target).map_err(|e| format!("не скопировать {}: {e}", file.display()))?;
        make_runnable(&target);
        return Ok(target);
    }
    crate::singbox::install_core()
}

/// Порт zapret под Linux: он приносит и nfqws, и стратегии, и systemd-юнит.
const ZAPRET_PORT: &str = "Sergeydigl3/zapret-discord-youtube-linux";

fn install_zapret(local: Option<&Path>) -> Result<PathBuf, String> {
    if !cfg!(target_os = "linux") {
        return Err(format!(
            "автоустановки zapret под {} нет: там другой движок.\n\
             Поставь родным способом и скажи пульту, где он:\n\
             \x20 net deps use zapret <папка>",
            std::env::consts::OS
        ));
    }
    let dir = install_dir().join("zapret");
    let archive = install_dir().join("zapret-port.tar.gz");

    if let Some(brought) = local {
        if brought.is_dir() {
            if !looks_like_zapret(brought) {
                return Err(format!(
                    "в {} нет conf.env — это не папка zapret",
                    brought.display()
                ));
            }
            return Ok(brought.to_path_buf());
        }
        std::fs::copy(brought, &archive)
            .map_err(|e| format!("не скопировать {}: {e}", brought.display()))?;
    } else {
        // codeload живёт на адресах github.com, а они не закрыты — в отличие от
        // хоста файлов релизов.
        let urls = vec![format!(
            "https://codeload.github.com/{ZAPRET_PORT}/tar.gz/refs/heads/master"
        )];
        download(&urls, &archive, 20_000).map_err(|trouble| {
            format!("не скачался порт zapret ({trouble}). Проверь интернет: net doctor")
        })?;
    }

    let unpack = install_dir().join("zapret-unpack");
    let _ = std::fs::remove_dir_all(&unpack);
    std::fs::create_dir_all(&unpack).map_err(|e| e.to_string())?;
    let ok = Command::new("tar")
        .args(["-xzf", &archive.to_string_lossy(), "-C", &unpack.to_string_lossy()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        return Err("архив zapret не распаковался".into());
    }
    // В архиве одна папка с версией в имени — переносим её на постоянное место.
    let inner = std::fs::read_dir(&unpack)
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.path())
        .find(|p| p.is_dir())
        .ok_or("в архиве zapret пусто")?;
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::rename(&inner, &dir).map_err(|e| format!("не переложить папку zapret: {e}"))?;
    let _ = std::fs::remove_dir_all(&unpack);
    let _ = std::fs::remove_file(&archive);

    for name in ["service.sh", "auto_tune.sh"] {
        make_runnable(&dir.join(name));
    }

    // Дальше порт сам качает nfqws и стратегии. Это файлы релизов, и как раз
    // они закрыты по IP — поэтому неудачу разбираем отдельным текстом.
    let out = Command::new("bash")
        .arg(dir.join("service.sh"))
        .arg("download-deps")
        .current_dir(&dir)
        .output()
        .map_err(|e| format!("не запустился service.sh: {e}"))?;
    if !dir.join("nfqws").is_file() {
        let tail = String::from_utf8_lossy(&out.stderr);
        let last = tail.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("");
        return Err(format!(
            "порт zapret скачан в {}, но nfqws не пришёл: {last}\n\
             Так и должно быть, если сеть закрывает файлы релизов GitHub по IP.\n\
             Обходные пути:\n\
             \x20 · включить туннель и повторить: net vpn on && net deps install zapret\n\
             \x20 · принести zapret-vXX.X.tar.gz с другой машины: NETPULT_ZAPRET=<файл> не нужен,\n\
             \x20   положи распакованный nfqws как {}",
            dir.display(),
            dir.join("nfqws").display()
        ));
    }
    Ok(dir)
}

/// Запоминает путь в конфиге пульта, чтобы поиск больше не гадал.
pub fn remember(kind: Kind, path: &Path) -> Result<(), String> {
    let key = match kind {
        Kind::Zapret => "zapret_dir",
        Kind::Tglock => "tglock_bin",
        Kind::Core => "core_bin",
    };
    config::state_dir_ensure().map_err(|e| e.to_string())?;
    let file = config::config_path();
    let text = std::fs::read_to_string(&file).unwrap_or_default();
    let mut lines: Vec<String> = text
        .lines()
        .filter(|l| !l.trim_start().starts_with(&format!("{key} ")) && !l.trim_start().starts_with(&format!("{key}=")))
        .map(str::to_string)
        .collect();
    lines.push(format!("{key} = {}", path.display()));
    std::fs::write(&file, lines.join("\n") + "\n").map_err(|e| format!("не записать настройки: {e}"))
}
