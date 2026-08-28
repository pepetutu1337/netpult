//! Автоподбор стратегии обхода.
//!
//! Перебирает стратегии, после каждой перезапускает движок и смотрит, что
//! реально изменилось: открывается ли YouTube и с какой скоростью отдаёт CDN.
//! Текущая стратегия проверяется первой — если она в порядке, ничего трогать
//! не надо.

use crate::config::Config;
use crate::probe;
use crate::zapret::{State, Zapret};
use crate::{DIM, GREEN, RED, RESET, YELLOW};
use std::time::Duration;

/// Оценка стратегии: главное — доступность, скорость решает споры равных.
#[derive(Debug, Clone)]
pub struct Score {
    pub strategy: String,
    pub reachable: bool,
    pub speed: f64,
}

impl Score {
    fn value(&self) -> f64 {
        if self.reachable { 1000.0 + self.speed } else { self.speed / 10.0 }
    }
}

/// Скорость, после которой перебор можно не продолжать.
const GOOD_ENOUGH_KBS: f64 = 200.0;

pub struct Options {
    /// Проверить все стратегии, не останавливаясь на первой хорошей.
    pub full: bool,
    /// Печатать ход перебора.
    pub verbose: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options { full: false, verbose: true }
    }
}

/// Насколько кандидат должен обгонять текущую стратегию, чтобы её менять.
///
/// Замер скорости шумный: первое соединение бывает вдвое медленнее следующего.
/// Без запаса пульт дёргал бы рабочую стратегию из-за случайной просадки.
const SWITCH_MARGIN: f64 = 1.5;

/// Проверяет одну стратегию: ставит, перезапускает движок, замеряет.
fn measure(z: &Zapret, name: &str) -> Result<Score, String> {
    z.set_strategy(name)?;
    if z.state() != State::On {
        z.start()?;
    } else {
        z.restart()?;
    }
    // Движку нужно мгновение, чтобы поднять правила фаервола.
    std::thread::sleep(Duration::from_millis(1500));

    let reachable = probe::reachable(
        "https://www.youtube.com/generate_204",
        Duration::from_secs(8),
    );

    // Два замера, берём лучший: холодный старт соединения занижает первый.
    let speed = (0..2)
        .filter_map(|_| probe::google_speed(Duration::from_secs(15)))
        .fold(0.0_f64, f64::max);

    Ok(Score { strategy: name.to_string(), reachable, speed })
}

/// Подбирает рабочую стратегию и оставляет лучшую из проверенных.
pub fn run(cfg: &Config, options: &Options) -> Result<Score, String> {
    let z = Zapret::new(cfg);
    let all = z.strategies();
    if all.is_empty() {
        return Err("стратегий не нашлось — где стоит zapret?".into());
    }
    if !probe::curl_available() {
        return Err("нет curl — подбирать не по чему".into());
    }

    let current: Option<String> = z.strategy();

    // Текущая идёт первой: чаще всего менять ничего и не нужно.
    let mut order: Vec<String> = Vec::new();
    if let Some(now) = &current {
        if all.contains(now) {
            order.push(now.clone());
        }
    }
    order.extend(all.into_iter().filter(|s| Some(s) != current.as_ref()));

    let mut results: Vec<Score> = Vec::new();
    for name in &order {
        if options.verbose {
            print!("  {name} … ");
            use std::io::Write;
            std::io::stdout().flush().ok();
        }

        let score = measure(&z, name)?;
        if options.verbose {
            let mark = if score.reachable {
                format!("{GREEN}открывается{RESET}")
            } else {
                format!("{RED}нет{RESET}")
            };
            println!("{mark}  {:.0} КБ/с", score.speed);
        }

        let good = score.reachable && score.speed >= GOOD_ENOUGH_KBS;
        results.push(score);
        if good && !options.full {
            if options.verbose {
                println!("{DIM}  хватит: стратегия рабочая и быстрая{RESET}");
            }
            break;
        }
    }

    let best = results
        .iter()
        .max_by(|a, b| a.value().partial_cmp(&b.value()).unwrap())
        .cloned()
        .ok_or("нечего выбирать")?;

    // Рабочую стратегию меняем, только если новая заметно лучше.
    let chosen = match results.first() {
        Some(now)
            if now.strategy == *current.as_deref().unwrap_or("")
                && now.reachable
                && best.speed < now.speed * SWITCH_MARGIN =>
        {
            if options.verbose && best.strategy != now.strategy {
                println!(
                    "{DIM}  {} не обгоняет текущую заметно — оставляю как было{RESET}",
                    best.strategy
                );
            }
            now.clone()
        }
        _ => best,
    };

    if !chosen.reachable && options.verbose {
        println!(
            "{YELLOW}  Ни одна стратегия не открыла YouTube. Оставляю лучшую по скорости.{RESET}"
        );
    }

    z.set_strategy(&chosen.strategy)?;
    if z.state() != State::On {
        z.start()?;
    }
    Ok(chosen)
}
