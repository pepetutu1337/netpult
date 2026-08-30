//! Полоса выполнения для долгих прогонов.
//!
//! Замер двух десятков нод занимает под минуту, подбор стратегии — минуты.
//! Молчание в это время читается как зависание, и человек жмёт Ctrl+C ровно
//! перед тем, как всё бы закончилось. Поэтому под выводом всегда висит одна
//! живая строка: что сейчас проверяется, сколько сделано и сколько осталось.
//!
//! Строка живая только в терминале. В журнале (`net vpn sync` из cron,
//! вывод в конвейер) возврат каретки превратился бы в кашу, поэтому там
//! прогресс молчит и говорят только итоговые строки.

use crate::{DIM, RESET};
use crossterm::tty::IsTty;
use std::io::Write;
use std::time::Instant;

/// Вывод идёт в терминал, а не в файл/конвейер/журнал.
pub fn терминал() -> bool {
    std::io::stdout().is_tty()
}

/// Строка ожидания: в терминале она одна и обновляется на месте, в журнале —
/// редкие отметки, чтобы шестьдесят секунд не превратились в шестьдесят строк.
pub fn ждём(что: &str, прошло: u64) {
    if терминал() {
        print!("\r\x1b[2K{DIM}  {что} … {прошло} с{RESET}");
        let _ = std::io::stdout().flush();
    } else if matches!(прошло, 5 | 15 | 30 | 45) {
        println!("  {что} … {прошло} с");
    }
}

/// Убрать строку ожидания перед постоянным выводом.
pub fn дождались() {
    if терминал() {
        print!("\r\x1b[2K");
        let _ = std::io::stdout().flush();
    }
}

pub struct Progress {
    label: &'static str,
    total: usize,
    done: usize,
    live: bool,
    /// Печатать ли шаги обычными строками там, где бегущей строки быть не
    /// может (журнал cron, конвейер).
    quiet_log: bool,
    started: Instant,
    width: usize,
}

/// Ширина полосы в знаках. Восемь — короткая, но по ней уже видно движение,
/// и на узком терминале имя ноды остаётся целым.
const BAR: usize = 8;

impl Progress {
    /// `total` — сколько шагов всего. Ноль допустим: полоса просто не рисуется.
    pub fn new(label: &'static str, total: usize) -> Self {
        Progress {
            label,
            total,
            done: 0,
            live: std::io::stdout().is_tty(),
            quiet_log: false,
            started: Instant::now(),
            // Ширина нужна только чтобы обрезать хвост. Псевдотерминал без
            // размера (запуск через script, часть CI) отдаёт ноль — на нём
            // строка схлопнулась бы до одной полосы без подписи.
            width: match crossterm::terminal::size() {
                Ok((w, _)) if w >= 40 => w as usize,
                _ => 80,
            },
        }
    }

    /// Для коротких прогонов из нескольких этапов: в журнале каждый этап
    /// остаётся отдельной строкой. Для перебора двух десятков нод так делать
    /// нельзя — журнал заплывёт, поэтому по умолчанию выключено.
    pub fn logged(mut self) -> Self {
        self.quiet_log = true;
        self
    }

    /// Отметить начало очередного шага: `what` — что именно сейчас делается.
    /// Вызывается ДО работы, чтобы на экране висело настоящее «чем занят».
    pub fn step(&mut self, what: &str) {
        if self.total == 0 {
            return;
        }
        if self.live {
            self.draw(what);
        } else if self.quiet_log {
            println!("  {}/{} {what}", self.done + 1, self.total);
        }
    }

    /// Шаг закончен. Считается отдельно от `step`, чтобы счётчик показывал
    /// сделанное, а не начатое.
    pub fn tick(&mut self) {
        self.done += 1;
    }

    /// Напечатать постоянную строку, не потеряв полосу: сначала стираем её,
    /// потом печатаем, полоса вернётся на следующем шаге.
    pub fn line(&mut self, text: &str) {
        self.clear();
        println!("{text}");
    }

    /// Убрать полосу с экрана. Вызывается в конце и перед каждой постоянной
    /// строкой — иначе хвост старой полосы остаётся торчать справа.
    pub fn clear(&mut self) {
        if self.live && self.total > 0 {
            print!("\r\x1b[2K");
            let _ = std::io::stdout().flush();
        }
    }

    /// Закончили: полоса уходит с экрана. Итог печатает вызывающий — ему
    /// виднее, что в этом прогоне было главным.
    pub fn finish(mut self) {
        self.clear();
    }

    /// Сколько шло, словами. Для итоговой строки: «21 нода за 1 мин 4 с».
    pub fn длительность(&self) -> String {
        длительность(self.started.elapsed().as_secs())
    }

    fn draw(&self, what: &str) {
        let filled = (self.done * BAR).checked_div(self.total).unwrap_or(0);
        let bar: String = (0..BAR)
            .map(|i| if i < filled { '▓' } else { '░' })
            .collect();
        let head = format!(
            "{DIM}{} {}/{} {bar}{RESET} ",
            self.label,
            self.done + 1,
            self.total
        );
        // Видимая длина без управляющих последовательностей: по ней режется
        // хвост, иначе длинное имя ноды переносится и полоса размножается.
        let visible = self.label.chars().count()
            + 1
            + digits(self.done + 1)
            + 1
            + digits(self.total)
            + 1
            + BAR
            + 1;
        let room = self.width.saturating_sub(visible + 1);
        print!("\r\x1b[2K{head}{}", clip(what, room));
        let _ = std::io::stdout().flush();
    }
}

fn digits(n: usize) -> usize {
    n.to_string().chars().count()
}

/// Обрезка по знакам, а не по байтам: имена нод — кириллица и флаги-эмодзи,
/// срез по байтам развалил бы их в середине.
fn clip(text: &str, room: usize) -> String {
    if room == 0 {
        return String::new();
    }
    if text.chars().count() <= room {
        return text.to_string();
    }
    text.chars().take(room.saturating_sub(1)).collect::<String>() + "…"
}

fn длительность(secs: u64) -> String {
    if secs < 60 {
        format!("{secs} с")
    } else {
        format!("{} мин {} с", secs / 60, secs % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn хвост_режется_по_знакам() {
        assert_eq!(clip("Германия", 20), "Германия");
        assert_eq!(clip("Германия", 4), "Гер…");
        assert_eq!(clip("Германия", 0), "");
    }

    #[test]
    fn длительность_словами() {
        assert_eq!(длительность(5), "5 с");
        assert_eq!(длительность(59), "59 с");
        assert_eq!(длительность(60), "1 мин 0 с");
        assert_eq!(длительность(125), "2 мин 5 с");
    }

    #[test]
    fn молчит_без_терминала() {
        // В тестах stdout не терминал — полоса не должна ничего печатать.
        let mut p = Progress::new("проверяю", 5);
        assert!(!p.live);
        p.step("нода");
        p.tick();
    }
}
