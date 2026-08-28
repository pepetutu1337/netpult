//! Минимальный разбор и сборка JSON.
//!
//! Подписки приходят в JSON (vmess-ссылки, выгрузка sing-box, xray, SIP008), и
//! конфиг движка тоже JSON. Тащить ради этого serde в бинарь, где сейчас одна
//! зависимость, не хочется — нужен разбор без схемы и вывод с экранированием,
//! это две сотни строк.

use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn parse(text: &str) -> Result<Json, String> {
        let bytes: Vec<char> = text.chars().collect();
        let mut p = Parser { s: &bytes, i: 0 };
        p.skip_ws();
        let value = p.value()?;
        p.skip_ws();
        if p.i < p.s.len() {
            return Err(format!("лишние данные после JSON на позиции {}", p.i));
        }
        Ok(value)
    }

    /// Поле объекта. Отсутствующее поле и `null` неразличимы — так удобнее:
    /// панели кладут `null` там, где другие просто не пишут ключ.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(pairs) => pairs
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .filter(|v| **v != Json::Null),
            _ => None,
        }
    }

    pub fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(items) => items,
            _ => &[],
        }
    }

    /// Строка. Числа и булевы приводятся к строке: в подписках порт, `aid` и
    /// `tls` кочуют между строкой и числом от панели к панели.
    pub fn as_str(&self) -> Option<String> {
        match self {
            Json::Str(s) => Some(s.clone()),
            Json::Num(n) => Some(if n.fract() == 0.0 {
                format!("{}", *n as i64)
            } else {
                format!("{n}")
            }),
            Json::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    pub fn as_u16(&self) -> Option<u16> {
        self.as_str()?.trim().parse().ok()
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            Json::Str(s) => match s.as_str() {
                "true" | "1" => Some(true),
                "false" | "0" | "" => Some(false),
                _ => None,
            },
            Json::Num(n) => Some(*n != 0.0),
            _ => None,
        }
    }
}

struct Parser<'a> {
    s: &'a [char],
    i: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_whitespace() {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: char) -> Result<(), String> {
        if self.i < self.s.len() && self.s[self.i] == c {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("ожидался «{c}» на позиции {}", self.i))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.s.get(self.i) {
            None => Err("JSON оборвался".into()),
            Some('{') => self.object(),
            Some('[') => self.array(),
            Some('"') => Ok(Json::Str(self.string()?)),
            Some('t') => self.literal("true", Json::Bool(true)),
            Some('f') => self.literal("false", Json::Bool(false)),
            Some('n') => self.literal("null", Json::Null),
            _ => self.number(),
        }
    }

    fn literal(&mut self, word: &str, value: Json) -> Result<Json, String> {
        for c in word.chars() {
            self.eat(c)?;
        }
        Ok(value)
    }

    fn object(&mut self) -> Result<Json, String> {
        self.eat('{')?;
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.s.get(self.i) == Some(&'}') {
            self.i += 1;
            return Ok(Json::Obj(pairs));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.eat(':')?;
            let value = self.value()?;
            pairs.push((key, value));
            self.skip_ws();
            match self.s.get(self.i) {
                Some(',') => self.i += 1,
                Some('}') => {
                    self.i += 1;
                    return Ok(Json::Obj(pairs));
                }
                _ => return Err(format!("ожидались «,» или «}}» на позиции {}", self.i)),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.eat('[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.s.get(self.i) == Some(&']') {
            self.i += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_ws();
            match self.s.get(self.i) {
                Some(',') => self.i += 1,
                Some(']') => {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(format!("ожидались «,» или «]» на позиции {}", self.i)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.eat('"')?;
        let mut out = String::new();
        loop {
            let c = *self.s.get(self.i).ok_or("строка не закрыта")?;
            self.i += 1;
            match c {
                '"' => return Ok(out),
                '\\' => {
                    let e = *self.s.get(self.i).ok_or("экранирование оборвалось")?;
                    self.i += 1;
                    match e {
                        '"' | '\\' | '/' => out.push(e),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => out.push(self.unicode_escape()?),
                        other => return Err(format!("неизвестное экранирование \\{other}")),
                    }
                }
                other => out.push(other),
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, String> {
        let first = self.hex4()?;
        // Суррогатная пара: имена нод у панелей бывают с эмодзи флагов.
        if (0xd800..0xdc00).contains(&first) {
            if self.s.get(self.i) == Some(&'\\') && self.s.get(self.i + 1) == Some(&'u') {
                self.i += 2;
                let second = self.hex4()?;
                let combined =
                    0x10000 + ((first - 0xd800) << 10) + (second.wrapping_sub(0xdc00) & 0x3ff);
                return char::from_u32(combined).ok_or_else(|| "битая суррогатная пара".into());
            }
            return Ok('\u{fffd}');
        }
        char::from_u32(first).ok_or_else(|| format!("недопустимый символ U+{first:04X}"))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let mut value = 0u32;
        for _ in 0..4 {
            let c = *self.s.get(self.i).ok_or("оборвался \\u")?;
            self.i += 1;
            let digit = c.to_digit(16).ok_or_else(|| format!("не шестнадцатеричная цифра: {c}"))?;
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.s.get(self.i) == Some(&'-') {
            self.i += 1;
        }
        while let Some(c) = self.s.get(self.i) {
            if c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-') {
                self.i += 1;
            } else {
                break;
            }
        }
        let text: String = self.s[start..self.i].iter().collect();
        text.parse()
            .map(Json::Num)
            .map_err(|_| format!("не число: «{text}»"))
    }
}

/// Экранирование строки для вывода JSON.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
