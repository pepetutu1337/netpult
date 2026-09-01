//! Осмотр: что сломано и какой командой это чинится.
//!
//! Остальные команды показывают состояние — включено или выключено, отвечает
//! или нет. Осмотр отвечает на другой вопрос: «почему не работает и что мне
//! сделать». Поэтому у каждой строки есть не только вердикт, но и причина
//! (что именно измеряли) и готовая команда. С `--fix` пульт выполняет те
//! починки, которые безопасны и не требуют выбора.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::config::Config;
use crate::{deps, dns, probe, singbox, sub, watch, zapret};
use crate::{BOLD, DIM, GREEN, RED, RESET, YELLOW};
use crate::{telegram::Telegram, zapret::Zapret};

#[derive(PartialEq, Clone, Copy)]
pub enum Verdict {
    Ok,
    Warn,
    Fail,
    /// Проверить не удалось — не то же самое, что «сломано».
    Skip,
}

impl Verdict {
    fn mark(self) -> String {
        match self {
            Verdict::Ok => format!("{GREEN}✓{RESET}"),
            Verdict::Warn => format!("{YELLOW}!{RESET}"),
            Verdict::Fail => format!("{RED}✗{RESET}"),
            Verdict::Skip => format!("{DIM}·{RESET}"),
        }
    }
}

/// Что чинит найденную беду.
pub struct Fix {
    /// Команда, которую человек может набрать сам.
    pub command: String,
    /// Можно ли выполнить её по `net doctor --fix` без вопросов.
    pub safe: bool,
}

pub struct Check {
    pub name: String,
    pub verdict: Verdict,
    /// Что именно измерили — чтобы вердикт не приходилось принимать на веру.
    pub detail: String,
    pub fix: Option<Fix>,
}

impl Check {
    fn ok(name: &str, detail: impl Into<String>) -> Check {
        Check {
            name: name.into(),
            verdict: Verdict::Ok,
            detail: detail.into(),
            fix: None,
        }
    }

    fn skip(name: &str, detail: impl Into<String>) -> Check {
        Check {
            name: name.into(),
            verdict: Verdict::Skip,
            detail: detail.into(),
            fix: None,
        }
    }

    fn bad(verdict: Verdict, name: &str, detail: impl Into<String>, command: &str, safe: bool) -> Check {
        Check {
            name: name.into(),
            verdict,
            detail: detail.into(),
            fix: Some(Fix {
                command: command.to_string(),
                safe,
            }),
        }
    }
}

const QUICK: Duration = Duration::from_secs(6);

/// Достучаться до чужого адреса по TCP. Именно соединение, а не HTTP: когда
/// диапазон закрыт по IP, сессия не встаёт вовсе, и это видно только так.
fn tcp_reachable(addr: &str, timeout: Duration) -> bool {
    let Ok(mut candidates) = addr.to_socket_addrs() else {
        return false;
    };
    candidates.any(|target| TcpStream::connect_timeout(&target, timeout).is_ok())
}

/// Весь осмотр. `fix` — чинить ли найденное.
pub fn run(cfg: &Config, fix: bool) -> Result<(), String> {
    println!("{BOLD}ОСМОТР{RESET}\n");
    let mut checks = Vec::new();
    checks.extend(basics());
    checks.extend(dependencies(cfg));
    checks.extend(conflicts(cfg));
    checks.extend(bypass(cfg));
    checks.extend(telegram(cfg));
    checks.extend(tunnel(cfg));
    checks.extend(extras());

    for check in &checks {
        println!("{} {}", check.verdict.mark(), check.name);
        if !check.detail.is_empty() {
            println!("   {DIM}{}{RESET}", check.detail);
        }
        if let Some(fix) = &check.fix {
            println!("   чинится: {BOLD}{}{RESET}", fix.command);
        }
    }

    let broken: Vec<&Check> = checks
        .iter()
        .filter(|c| matches!(c.verdict, Verdict::Fail | Verdict::Warn))
        .collect();

    println!();
    if broken.is_empty() {
        println!("{GREEN}Всё в порядке.{RESET}");
        return Ok(());
    }

    if !fix {
        println!(
            "Нашлось {}: {}",
            beda(broken.len()),
            broken
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("{DIM}Починить самому: net doctor --fix{RESET}");
        return Ok(());
    }

    println!("{BOLD}ЧИНЮ{RESET}");
    let mut left = Vec::new();
    for check in broken {
        let Some(fix) = &check.fix else { continue };
        if !fix.safe {
            println!("  {DIM}{} — руками: {}{RESET}", check.name, fix.command);
            left.push(check.name.clone());
            continue;
        }
        println!("  {} → {}", check.name, fix.command);
        let words: Vec<&str> = fix.command.split_whitespace().skip(1).collect();
        let Some((command, rest)) = words.split_first() else {
            continue;
        };
        match crate::dispatch_with(cfg, command, rest, false) {
            Ok(()) => println!("    {GREEN}готово{RESET}"),
            Err(trouble) => {
                println!("    {RED}{trouble}{RESET}");
                left.push(check.name.clone());
            }
        }
    }
    println!();
    if left.is_empty() {
        println!("{GREEN}Починил. Проверить ещё раз: net doctor{RESET}");
    } else {
        println!("Осталось руками: {}", left.join(", "));
    }
    Ok(())
}

fn beda(count: usize) -> String {
    let tail = match (count % 10, count % 100) {
        (_, 11..=14) => "проблем",
        (1, _) => "проблема",
        (2..=4, _) => "проблемы",
        _ => "проблем",
    };
    format!("{count} {tail}")
}

fn basics() -> Vec<Check> {
    let mut checks = Vec::new();

    if probe::curl_available() {
        checks.push(Check::ok("curl на месте", "им пульт проверяет связь"));
    } else {
        checks.push(Check::bad(
            Verdict::Fail,
            "нет curl",
            "без него пульт не может ничего проверить и ничего скачать",
            "поставь curl средствами системы",
            false,
        ));
        return checks;
    }

    // Сначала голый IP: если и он молчит, дело не в блокировках, а в сети.
    let net = tcp_reachable("1.1.1.1:443", QUICK);
    if !net {
        checks.push(Check::bad(
            Verdict::Fail,
            "нет интернета",
            "не встаёт даже соединение с 1.1.1.1:443 — дело не в блокировках",
            "проверь Wi-Fi и кабель",
            false,
        ));
        return checks;
    }
    checks.push(Check::ok("интернет есть", "1.1.1.1:443 отвечает"));

    // Имена. Резолвинг ломается отдельно от связи, и симптом у него чужой:
    // «всё висит», хотя сеть цела.
    if probe::reachable("https://1.1.1.1/", QUICK) && !probe::reachable("https://cloudflare.com/", QUICK) {
        checks.push(Check::bad(
            Verdict::Fail,
            "имена не разрешаются",
            "по адресу открывается, по имени — нет: сломан DNS",
            "net dns on",
            false,
        ));
    } else {
        checks.push(Check::ok("имена разрешаются", "cloudflare.com открывается"));
    }
    checks
}

fn dependencies(cfg: &Config) -> Vec<Check> {
    deps::Kind::ALL
        .into_iter()
        .map(|kind| match deps::find(kind, cfg) {
            Some(found) => Check::ok(
                &format!("{} на месте", kind.title()),
                crate::short_path(&found.path),
            ),
            None => Check::bad(
                Verdict::Warn,
                &format!("нет {}", kind.title()),
                format!("без него не работает: {}", kind.needed_for()),
                &format!("net deps install {}", kind.key()),
                false,
            ),
        })
        .collect()
}

/// Взаимные помехи: обход поверх обхода мешает сам себе.
fn conflicts(cfg: &Config) -> Vec<Check> {
    let mut checks = Vec::new();
    let zapret_on = Zapret::new(cfg).state() == zapret::State::On;
    let tunnel_on = singbox::Core::new(cfg).state() == singbox::State::Up;

    if zapret_on && tunnel_on {
        checks.push(Check::bad(
            Verdict::Warn,
            "zapret и туннель включены разом",
            "в туннеле дурить DPI нечего: zapret только тратит силы и путает проверки",
            "net off",
            true,
        ));
    }
    let (_, how) = crate::route::carrier(cfg);
    checks.push(Check::ok("маршрут", how));
    checks
}

fn bypass(cfg: &Config) -> Vec<Check> {
    let mut checks = Vec::new();
    let z = Zapret::new(cfg);
    match z.state() {
        zapret::State::Missing => return checks,
        zapret::State::Off => {
            // Выключенный обход — беда только если без него не работает.
            let video = probe::video(QUICK);
            if video.ok() {
                checks.push(Check::skip(
                    "zapret выключен",
                    "видео и так открывается: обход в этой сети не нужен",
                ));
            } else {
                checks.push(Check::bad(
                    Verdict::Fail,
                    "видео не открывается, обход выключен",
                    "краевой сервер googlevideo молчит",
                    "net on",
                    true,
                ));
            }
            return checks;
        }
        zapret::State::On => {}
    }

    let strategy = z.strategy().unwrap_or_else(|| "не задана".into());
    let video = probe::video(QUICK);
    if !video.checked {
        checks.push(Check::skip(
            "стратегию проверить нечем",
            "не нашёлся краевой сервер googlevideo — YouTube не открылся совсем",
        ));
    } else if video.console_only() {
        checks.push(Check::bad(
            Verdict::Warn,
            "стратегия годится только для консоли",
            format!("{strategy}: обычное приветствие TLS проходит, браузерное — нет"),
            "net tune",
            false,
        ));
    } else if !video.ok() {
        checks.push(Check::bad(
            Verdict::Fail,
            "стратегия не работает",
            format!("{strategy}: краевой сервер googlevideo не отвечает"),
            "net tune",
            false,
        ));
    } else {
        checks.push(Check::ok("обход работает", format!("{strategy}, видео открывается")));
    }
    checks
}

fn telegram(cfg: &Config) -> Vec<Check> {
    let mut checks = Vec::new();
    let tg = Telegram::new(cfg);
    if tg.binary().is_none() {
        return checks;
    }

    // Сам Telegram: доходит ли до его серверов напрямую. Их диапазон закрывают
    // по IP, и тогда никакое дурение DPI уже не поможет — нужен прокси.
    let dc = tcp_reachable("149.154.167.51:443", QUICK);
    if tg.running() {
        checks.push(Check::ok(
            "прокси Telegram работает",
            format!("слушает порт {}", cfg.tg_port),
        ));
    } else if dc {
        checks.push(Check::skip(
            "прокси Telegram выключен",
            "серверы Telegram отвечают напрямую — прокси пока не нужен",
        ));
    } else {
        checks.push(Check::bad(
            Verdict::Fail,
            "Telegram закрыт, прокси выключен",
            "149.154.167.51:443 не отвечает: соединение не встаёт",
            "net tg on",
            true,
        ));
    }
    checks
}

fn tunnel(cfg: &Config) -> Vec<Check> {
    let mut checks = Vec::new();
    if !sub::config_path().exists() {
        checks.push(Check::skip(
            "подписки нет",
            "туннель, сплит и звонки через ноду без неё не поднять: net vpn sub <ссылка>",
        ));
        return checks;
    }
    let core = singbox::Core::new(cfg);
    if core.state() != singbox::State::Up {
        checks.push(Check::skip("туннель выключен", "включается: net vpn on"));
        return checks;
    }
    match singbox::active_node() {
        Some((name, true)) => checks.push(Check::ok("нода отвечает", name)),
        Some((name, false)) => checks.push(Check::bad(
            Verdict::Warn,
            "выбранная нода молчит",
            format!("{name} не отвечает на замер"),
            "net vpn auto",
            true,
        )),
        None => checks.push(Check::bad(
            Verdict::Warn,
            "ядро поднято, ноды не видно",
            "не отвечает служебный интерфейс ядра",
            "net vpn off && net vpn on",
            false,
        )),
    }
    checks
}

fn extras() -> Vec<Check> {
    let mut checks = Vec::new();

    // Служба поднята, а резолвер молчит — самая злая из тихих поломок: имена
    // перестают разрешаться на всей машине, а внешне «DNS включён».
    match dns::state() {
        dns::State::Up => checks.push(Check::ok(
            "DNS шифруется",
            if dns::подключён() { "система направлена на свой резолвер" } else { "резолвер поднят, но система его не спрашивает" },
        )),
        dns::State::Broken => checks.push(Check::bad(
            Verdict::Fail,
            "резолвер DNS не отвечает",
            "служба поднята, но ответов нет — имена не разрешаются",
            "net dns off",
            true,
        )),
        dns::State::Off => {
            if let Some(gw) = dns::шлюз_кита() {
                checks.push(Check::ok("DNS отдан роутеру", format!("шифрует {gw}")));
            } else {
                checks.push(Check::skip("DNS не шифруется", "включается: net dns on"));
            }
        }
    }

    if watch::status().starts_with("не") {
        checks.push(Check::skip(
            "сторож не поставлен",
            "он чинит упавшее без тебя: net watch install",
        ));
    } else {
        checks.push(Check::ok("сторож на месте", "проверяет связь и чинит сам"));
    }
    checks
}
