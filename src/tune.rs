//! Автоподбор стратегии обхода.
//!
//! Перебирает стратегии, после каждой перезапускает движок и смотрит, что
//! реально изменилось: открывается ли YouTube и с какой скоростью отдаёт CDN.
//! Текущая стратегия проверяется первой — если она в порядке, ничего трогать
//! не надо.

use crate::config::Config;
use crate::probe;
use crate::progress::Progress;
use crate::zapret::{State, Zapret};
use crate::{DIM, GREEN, RED, RESET, YELLOW};
use std::time::Duration;

/// Оценка стратегии: главное — доступность, скорость решает споры равных.
#[derive(Debug, Clone)]
pub struct Score {
    pub strategy: String,
    pub reachable: bool,
    /// Что ответил видео-CDN на обычное и на браузерное приветствие TLS.
    pub video: probe::Video,
    pub speed: f64,
}

impl Score {
    fn value(&self) -> f64 {
        // Три ступени, и порядок между ними важнее любой скорости.
        //
        // Стратегия, которую держит только консоль, — ловушка: все проверки
        // зелёные, а браузер у человека молчит. Такая обязана проигрывать
        // любой полноценной, даже заметно более медленной.
        let tier = match (self.reachable, self.video.ok(), self.video.console_only()) {
            (true, true, _) => 3000.0,
            (true, false, true) => 1500.0,
            (true, false, false) => 1000.0,
            _ => 0.0,
        };
        if tier > 0.0 {
            tier + self.speed
        } else {
            self.speed / 10.0
        }
    }

    /// Годится без оговорок: и страница, и видео, и браузерное приветствие.
    pub fn full(&self) -> bool {
        self.reachable && self.video.ok()
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
        Options {
            full: false,
            verbose: true,
        }
    }
}

/// Насколько кандидат должен обгонять текущую стратегию, чтобы её менять.
///
/// Замер скорости шумный: первое соединение бывает вдвое медленнее следующего.
/// Без запаса пульт дёргал бы рабочую стратегию из-за случайной просадки.
const SWITCH_MARGIN: f64 = 1.5;

/// Проверяет одну стратегию: ставит, перезапускает движок, замеряет.
///
/// Одна стратегия проверяется под минуту: перезапуск, две сетевые пробы и два
/// замера скорости. `phase` вызывается перед каждым отрезком, чтобы наверху
/// было видно, на чём именно пульт стоит, — иначе минута тишины на каждую из
/// десятка стратегий читается как зависший перебор.
fn measure(z: &Zapret, name: &str, phase: &mut dyn FnMut(&str)) -> Result<Score, String> {
    phase("перезапускаю обход");
    z.set_strategy(name)?;
    if z.state() != State::On {
        z.start()?;
    } else {
        z.restart()?;
    }
    // Движку нужно мгновение, чтобы поднять правила фаервола.
    std::thread::sleep(Duration::from_millis(1500));

    phase("открываю страницу");
    let reachable = probe::reachable(
        "https://www.youtube.com/generate_204",
        Duration::from_secs(8),
    );
    // Страница ютуба открывается и со сломанным обходом — решает видео-CDN.
    phase("стучусь в видео-CDN");
    let video = probe::video(Duration::from_secs(8));

    // Два замера, берём лучший: холодный старт соединения занижает первый.
    let mut speed = 0.0_f64;
    for попытка in 1..=2 {
        phase(&format!("меряю скорость ({попытка} из 2)"));
        if let Some(v) = probe::google_speed(Duration::from_secs(15)) {
            speed = speed.max(v);
        }
    }

    Ok(Score {
        strategy: name.to_string(),
        reachable,
        video,
        speed,
    })
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
    if let Some(now) = &current
        && all.contains(now)
    {
        order.push(now.clone());
    }
    order.extend(all.into_iter().filter(|s| Some(s) != current.as_ref()));

    let mut results: Vec<Score> = Vec::new();
    let всего = order.len();
    let mut ход = Progress::new("перебираю", if options.verbose { всего } else { 0 }).logged();
    for name in &order {
        let подпись = name.clone();
        let score = {
            let ход = &mut ход;
            measure(&z, name, &mut |что| {
                ход.step(&format!("{подпись} — {что}"));
            })?
        };
        if options.verbose {
            let mark = match (score.reachable, score.video.plain) {
                (true, true) => format!("{GREEN}видео идёт{RESET}"),
                (true, false) => format!("{RED}видео молчит{RESET}"),
                _ => format!("{RED}нет{RESET}"),
            };
            let browser = match score.video.browser {
                Some(true) => format!("  {GREEN}браузер ок{RESET}"),
                Some(false) => format!("  {YELLOW}только консоль{RESET}"),
                None => String::new(),
            };
            ход.line(&format!(
                "  {name} … {mark}{browser}  {:.0} КБ/с",
                score.speed
            ));
        }
        ход.tick();

        let good = score.full() && score.speed >= GOOD_ENOUGH_KBS;
        results.push(score);
        if good && !options.full {
            if options.verbose {
                ход.line(&format!(
                    "{DIM}  хватит: стратегия рабочая и быстрая{RESET}"
                ));
            }
            break;
        }
    }
    ход.finish();

    let best = results
        .iter()
        .max_by(|a, b| a.value().partial_cmp(&b.value()).unwrap())
        .cloned()
        .ok_or("нечего выбирать")?;

    // Рабочую стратегию меняем, только если новая заметно лучше.
    // Оговорка про запас скорости действует, только пока текущая стратегия
    // хороша целиком. Если браузер на ней молчит, держаться за неё из-за
    // лишних килобайт в секунду незачем — меняем на полноценную.
    let chosen = match results.first() {
        Some(now)
            if now.strategy == *current.as_deref().unwrap_or("")
                && now.full()
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

    if options.verbose {
        if !chosen.reachable {
            println!(
                "{YELLOW}  Ни одна стратегия не открыла YouTube. Оставляю лучшую по скорости.{RESET}"
            );
        } else if chosen.video.console_only() {
            println!("{YELLOW}  Ни одна стратегия не прошла браузерным приветствием TLS.{RESET}");
            println!(
                "{DIM}  Консоль и качалки работать будут, браузер — нет. Лечится не тут, а\n  на стороне обхода: нужна стратегия, переживающая приветствие в два\n  килобайта (помогает fooling=badseq).{RESET}"
            );
        } else if !chosen.video.plain {
            println!("{YELLOW}  Страница ютуба открылась, а видео-CDN молчит.{RESET}");
        }
    }

    z.set_strategy(&chosen.strategy)?;
    if z.state() != State::On {
        z.start()?;
    }
    Ok(chosen)
}
