//! Звонки в Telegram: почему не работают и чем их чинить.
//!
//! Переписку выручает прокси MTProto (`net tg on`) — он ведёт к серверам
//! Telegram один поток и маскирует его под обычный веб. Голос через этот поток
//! не идёт: разговор — отдельные UDP-пакеты к голосовым серверам, и прокси их
//! не касается. Отсюда знакомая картина: сообщения ходят, звонок не встаёт.
//!
//! Чинить можно двумя способами, и они разной надёжности.
//!
//! **Через ноду (точечный туннель).** Голос уходит в туннель, но туннель
//! забирает только Telegram: остальной интернет идёт напрямую, без лишних
//! задержек и без адресов датацентра там, где их не любят. Работает всегда,
//! пока жива нода.
//!
//! **Через zapret.** Отдельный блок стратегии дурит DPI на UDP-портах голоса
//! (`--filter-l7=stun --dpi-desync=fake`). Помогает, только если провайдер
//! режет звонки разбором пакетов. Если же диапазоны Telegram закрыты по IP —
//! а автор zapret говорит именно об этом, — дурить нечего, и путь не поможет.
//! Второе «но»: при разговоре напрямую между собеседниками обход нужен обоим.

use std::path::PathBuf;

use crate::config::Config;
use crate::singbox::{self, Scope};
use crate::sub;
use crate::zapret::{self, Zapret};

/// Чем сейчас прикрыты звонки.
#[derive(Debug, PartialEq)]
pub enum Способ {
    /// Машина стоит за своим роутером с обходом. Голос всех домашних устройств
    /// решается там: поднимать поверх ещё один туннель — только мешать.
    /// Проверить и включить надо на роутере, отсюда этого не видно.
    Роутер(String),
    /// Точечный туннель: через ноду уходит только Telegram.
    Нода,
    /// Стратегия zapret с блоком для голосовых портов.
    Dpi,
    /// Полный туннель — звонки и так внутри него.
    ПолныйТуннель,
    Никак,
}

pub fn состояние(cfg: &Config) -> Способ {
    let туннель = singbox::Core::new(cfg).state() == singbox::State::Up;
    if туннель {
        return match singbox::scope() {
            Scope::TelegramOnly => Способ::Нода,
            Scope::All => Способ::ПолныйТуннель,
        };
    }
    if стратегия_со_звонками(cfg) {
        return Способ::Dpi;
    }
    // Дома за своим роутером голос заворачивает он сам, и поднимать поверх
    // ещё один туннель незачем — станет только хуже.
    if let Some(gw) = crate::dns::шлюз_кита() {
        return Способ::Роутер(gw);
    }
    Способ::Никак
}

/// Имя стратегии, которую пульт собирает сам под звонки.
const СТРАТЕГИЯ: &str = "netpult-telegram-calls.bat";

fn стратегия_со_звонками(cfg: &Config) -> bool {
    Zapret::new(cfg).state() == zapret::State::On
        && Zapret::new(cfg)
            .strategy()
            .is_some_and(|s| s == СТРАТЕГИЯ)
}

/// Включить звонки. `dpi` — не трогать ноду, чинить дурением DPI.
pub fn on(cfg: &Config, dpi: bool, here: bool) -> Result<Vec<String>, String> {
    if dpi {
        return через_zapret(cfg);
    }
    if let (false, Способ::Роутер(gw)) = (here, состояние(cfg)) {
        return Ok(vec![
            format!("эта машина за своим роутером {gw} — голос решается на нём"),
            "включить там: netctl calls on (кит) или rctl calls".into(),
            "нужен туннель именно отсюда — net calls on --here".into(),
        ]);
    }
    if sub::config_path().exists() && cfg.core_bin.is_some() {
        через_ноду(cfg)
    } else {
        let мы = через_zapret(cfg);
        match мы {
            Ok(mut шаги) => {
                шаги.push(
                    "подписки нет, поэтому чиню дурением DPI: помогает не у всех провайдеров"
                        .into(),
                );
                шаги.push("надёжный путь — нода: net vpn sub <ссылка>, потом net calls on".into());
                Ok(шаги)
            }
            Err(беда) => Err(format!(
                "{беда}\nНадёжный путь — через ноду: net vpn sub <ссылка>, потом net calls on"
            )),
        }
    }
}

fn через_ноду(cfg: &Config) -> Result<Vec<String>, String> {
    let mut шаги = Vec::new();
    let core = singbox::Core::new(cfg);
    let прежний = singbox::scope();

    // Диапазоны Telegram меняются, а голос идёт по адресам, минуя имена:
    // устаревший список — это часть разговоров мимо ноды.
    match singbox::update_telegram_cidr() {
        Ok(сколько) => шаги.push(format!("список адресов Telegram обновлён: {сколько} сетей")),
        Err(_) => шаги.push("список адресов Telegram не обновился, беру прежний".into()),
    }

    singbox::rewrite_scope(Scope::TelegramOnly)?;

    // Порядок важен: сперва поднимаем туннель и только потом снимаем zapret.
    // Обратный порядок оставлял машину вообще без обхода, если ядро не
    // взлетело, — и виноватым выглядел бы zapret, который никто не просил
    // выключать.
    if core.state() == singbox::State::Up {
        core.stop()?;
    }
    if let Err(беда) = core.start() {
        singbox::rewrite_scope(прежний).ok();
        return Err(format!("{беда}\nОхват туннеля вернул как был"));
    }
    шаги.push("через ноду идёт только Telegram, остальное — напрямую".into());
    шаги.push("туннель поднят".into());

    let z = Zapret::new(cfg);
    if z.state() == zapret::State::On {
        z.stop().ok();
        шаги.push("zapret выключен: в туннеле он только мешает проверкам".into());
    }
    Ok(шаги)
}

fn через_zapret(cfg: &Config) -> Result<Vec<String>, String> {
    let z = Zapret::new(cfg);
    let dir = z.dir().ok_or("zapret не найден: net deps install zapret")?.clone();
    let база = z
        .strategy()
        .filter(|s| s != СТРАТЕГИЯ)
        .ok_or("не понять, от какой стратегии отталкиваться: net strat")?;

    let исходник = найти_стратегию(&dir, &база)
        .ok_or_else(|| format!("не нашёлся файл стратегии {база}"))?;
    let текст = std::fs::read_to_string(&исходник).map_err(|e| e.to_string())?;
    let собрано = добавить_голос(&текст);

    let своя = dir.join("custom-strategies").join(СТРАТЕГИЯ);
    std::fs::create_dir_all(своя.parent().unwrap_or(&dir)).map_err(|e| e.to_string())?;
    std::fs::write(&своя, собрано).map_err(|e| format!("не записать стратегию: {e}"))?;
    std::fs::write(запомненная_база(), &база).ok();

    z.set_strategy(СТРАТЕГИЯ)?;
    if z.state() != zapret::State::On {
        z.start()?;
    } else {
        z.restart()?;
    }
    Ok(vec![
        format!("стратегия собрана из {база} и включена"),
        "добавлен блок для голосовых портов: UDP 590-1400, 3478, фильтр stun".into(),
        "проверь звонком: если тишина, значит режут по IP — тогда только нода".into(),
    ])
}

fn запомненная_база() -> PathBuf {
    crate::config::state_dir().join("calls.base")
}

fn найти_стратегию(dir: &std::path::Path, name: &str) -> Option<PathBuf> {
    let свои = dir.join("custom-strategies").join(name);
    if свои.is_file() {
        return Some(свои);
    }
    let штатные = dir.join("zapret-latest").join(name);
    штатные.is_file().then_some(штатные)
}

/// Дописывает в стратегию блок для голоса.
///
/// Порты голоса добавляются и в `--wf-udp`: по нему порт zapret строит правила
/// файрвола, и без этого пакеты разговора до nfqws просто не дойдут — фильтр
/// будет стоять, а трогать ему будет нечего.
pub fn добавить_голос(текст: &str) -> String {
    const ПОРТЫ: &str = "590-1400,3478,3479";
    const БЛОК: &str = "--filter-udp=590-1400,3478 --filter-l7=stun --dpi-desync=fake --dpi-desync-repeats=6";

    // Второй проход по уже собранной стратегии не должен плодить блоки.
    if текст.contains(БЛОК) {
        return текст.to_string();
    }

    let mut строки: Vec<String> = Vec::new();
    let mut вписан = false;
    for строка in текст.lines() {
        let mut строка = строка.to_string();
        if let Some(at) = строка.find("--wf-udp=")
            && !строка.contains(ПОРТЫ)
        {
            let конец = строка[at..]
                .find(char::is_whitespace)
                .map(|i| at + i)
                .unwrap_or(строка.len());
            строка.insert_str(конец, &format!(",{ПОРТЫ}"));
            вписан = true;
        }
        строки.push(строка);
    }
    if !вписан {
        // Стратегия без явного списка UDP-портов: без него правило файрвола
        // построить не из чего, и чинить нечего.
        строки.push(format!(":: netpult: --wf-udp={ПОРТЫ}"));
    }

    // Блок голоса ставим первым среди нагрузок: он самый узкий по фильтру и не
    // перехватывает чужие пакеты.
    let голос = format!("{БЛОК} --new ^");
    if let Some(место) = строки.iter().position(|s| s.contains("--filter-")) {
        строки.insert(место, голос);
    } else {
        строки.push(голос);
    }
    строки.join("\n") + "\n"
}

/// Снять починку звонков и вернуть, как было.
pub fn off(cfg: &Config) -> Result<Vec<String>, String> {
    let mut шаги = Vec::new();
    let core = singbox::Core::new(cfg);
    if singbox::scope() == Scope::TelegramOnly {
        if core.state() == singbox::State::Up {
            core.stop()?;
            шаги.push("точечный туннель снят".into());
        }
        singbox::rewrite_scope(Scope::All).ok();
        шаги.push("охват туннеля вернулся к полному".into());
    }
    if стратегия_со_звонками(cfg) {
        let база = std::fs::read_to_string(запомненная_база())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        match база {
            Some(база) => {
                Zapret::new(cfg).set_strategy(&база)?;
                шаги.push(format!("стратегия вернулась к {база}"));
            }
            None => шаги.push("стратегия со звонками осталась: не помню, какая была до неё".into()),
        }
    }
    if шаги.is_empty() {
        шаги.push("нечего снимать: звонки ничем не прикрыты".into());
    }
    Ok(шаги)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn голосовые_порты_попадают_в_правила_файрвола() {
        let текст = "start \"zapret\" winws.exe --wf-tcp=80,443 --wf-udp=443,50000-50100 ^\n--filter-udp=443 --dpi-desync=fake --new ^\n";
        let вышло = добавить_голос(текст);
        assert!(вышло.contains("--wf-udp=443,50000-50100,590-1400,3478,3479"));
        assert!(вышло.contains("--filter-l7=stun"));
        // Порты дописываются к списку, а не затирают его.
        assert!(вышло.contains("--wf-tcp=80,443"));
    }

    #[test]
    fn блок_голоса_идёт_раньше_широких_фильтров() {
        let текст = "--wf-udp=443 ^\n--filter-udp=443 --dpi-desync=fake --new ^\n";
        let вышло = добавить_голос(текст);
        let голос = вышло.find("--filter-l7=stun").expect("блок голоса на месте");
        let широкий = вышло.find("--filter-udp=443 ").expect("прежний блок на месте");
        assert!(голос < широкий);
    }

    #[test]
    fn второй_проход_не_плодит_порты() {
        let текст = "--wf-udp=443 ^\n--filter-udp=443 --dpi-desync=fake --new ^\n";
        let раз = добавить_голос(текст);
        let два = добавить_голос(&раз);
        assert_eq!(два.matches("590-1400,3478,3479").count(), 1);
    }
}
