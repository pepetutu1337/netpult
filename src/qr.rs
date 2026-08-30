//! Кодировщик QR без внешних зависимостей.
//!
//! Байтовый режим, уровень коррекции L, версии 1–10 (до 271 байта). Этого с
//! запасом хватает на ссылки `tg://proxy` и на конфиги прокси.
//!
//! Сверен с libqrencode: при одной и той же маске матрица совпадает модуль в
//! модуль (см. `tests/qr_vectors.rs`).

/// Вместимость в байтах для версий 1..=10 на уровне L.
const CAPACITY: [usize; 10] = [17, 32, 53, 78, 106, 134, 154, 192, 230, 271];

/// (всего кодовых слов, слов коррекции на блок, размеры блоков данных)
const BLOCKS: [(usize, usize, &[usize]); 10] = [
    (26, 7, &[19]),
    (44, 10, &[34]),
    (70, 15, &[55]),
    (100, 20, &[80]),
    (134, 26, &[108]),
    (172, 18, &[68, 68]),
    (196, 20, &[78, 78]),
    (242, 24, &[97, 97]),
    (292, 30, &[116, 116]),
    (346, 18, &[68, 68, 69, 69]),
];

const ALIGN: [&[usize]; 10] = [
    &[],
    &[6, 18],
    &[6, 22],
    &[6, 26],
    &[6, 30],
    &[6, 34],
    &[6, 22, 38],
    &[6, 24, 42],
    &[6, 26, 46],
    &[6, 28, 50],
];

// ── Арифметика поля Галуа для Рида — Соломона ────────────────────────────

struct Gf {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf {
    fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11D;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Gf { exp, log }
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }

    fn generator(&self, n: usize) -> Vec<u8> {
        let mut g = vec![1u8];
        for i in 0..n {
            g = self.poly_mul(&g, &[1, self.exp[i]]);
        }
        g
    }

    fn poly_mul(&self, a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; a.len() + b.len() - 1];
        for (i, &av) in a.iter().enumerate() {
            for (j, &bv) in b.iter().enumerate() {
                out[i + j] ^= self.mul(av, bv);
            }
        }
        out
    }

    fn encode(&self, data: &[u8], n: usize) -> Vec<u8> {
        let gen_poly = self.generator(n);
        let mut rem = vec![0u8; n];
        for &byte in data {
            let factor = byte ^ rem[0];
            rem.remove(0);
            rem.push(0);
            for (i, &g) in gen_poly[1..].iter().enumerate() {
                rem[i] ^= self.mul(g, factor);
            }
        }
        rem
    }
}

// ── Поток данных ─────────────────────────────────────────────────────────

fn build_codewords(payload: &[u8], version: usize, gf: &Gf) -> Vec<u8> {
    let (_, ec_per_block, block_sizes) = BLOCKS[version - 1];
    let data_capacity: usize = block_sizes.iter().sum();

    let mut bits: Vec<u8> = Vec::new();
    let put = |bits: &mut Vec<u8>, value: usize, length: usize| {
        for i in (0..length).rev() {
            bits.push(((value >> i) & 1) as u8);
        }
    };

    put(&mut bits, 0b0100, 4); // байтовый режим
    put(&mut bits, payload.len(), if version < 10 { 8 } else { 16 });
    for &byte in payload {
        put(&mut bits, byte as usize, 8);
    }

    let terminator = std::cmp::min(4, data_capacity * 8 - bits.len());
    put(&mut bits, 0, terminator);
    while !bits.len().is_multiple_of(8) {
        bits.push(0);
    }

    let mut data: Vec<u8> = bits
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | b))
        .collect();
    let pad = [0xECu8, 0x11];
    let mut pad_index = 0;
    while data.len() < data_capacity {
        data.push(pad[pad_index % 2]);
        pad_index += 1;
    }

    let mut blocks: Vec<&[u8]> = Vec::new();
    let mut ec_blocks: Vec<Vec<u8>> = Vec::new();
    let mut pos = 0;
    for &size in block_sizes {
        let chunk = &data[pos..pos + size];
        pos += size;
        ec_blocks.push(gf.encode(chunk, ec_per_block));
        blocks.push(chunk);
    }

    let mut out = Vec::new();
    let longest = *block_sizes.iter().max().unwrap();
    for i in 0..longest {
        for block in &blocks {
            if i < block.len() {
                out.push(block[i]);
            }
        }
    }
    for i in 0..ec_per_block {
        for block in &ec_blocks {
            out.push(block[i]);
        }
    }
    out
}

// ── Матрица ──────────────────────────────────────────────────────────────

fn bch(value: u32, generator: u32, gen_len: u32) -> u32 {
    let mut v = value;
    for i in (0..gen_len).rev() {
        if v & (1 << (i + gen_len)) != 0 {
            v ^= generator << i;
        }
    }
    v
}

fn place_function_patterns(m: &mut Vec<Vec<Option<u8>>>, size: usize, version: usize) {
    let finder = |m: &mut Vec<Vec<Option<u8>>>, row: i32, col: i32| {
        for r in -1..8 {
            for c in -1..8 {
                let (rr, cc) = (row + r, col + c);
                if rr < 0 || cc < 0 || rr >= size as i32 || cc >= size as i32 {
                    continue;
                }
                let edge = r == -1 || r == 7 || c == -1 || c == 7;
                let ring = r == 0 || r == 6 || c == 0 || c == 6;
                let core = (2..=4).contains(&r) && (2..=4).contains(&c);
                m[rr as usize][cc as usize] = Some(if edge {
                    0
                } else if ring || core {
                    1
                } else {
                    0
                });
            }
        }
    };
    finder(m, 0, 0);
    finder(m, 0, size as i32 - 7);
    finder(m, size as i32 - 7, 0);

    for &pos in ALIGN[version - 1] {
        for &pos2 in ALIGN[version - 1] {
            let skip = (pos == 6 && pos2 == 6)
                || (pos == 6 && pos2 == size - 7)
                || (pos == size - 7 && pos2 == 6);
            if skip {
                continue;
            }
            for r in -2i32..3 {
                for c in -2i32..3 {
                    let value = if r.abs().max(c.abs()) != 1 { 1 } else { 0 };
                    m[(pos as i32 + r) as usize][(pos2 as i32 + c) as usize] = Some(value);
                }
            }
        }
    }

    for i in 8..size - 8 {
        let bit = if i % 2 == 0 { 1 } else { 0 };
        m[6][i] = Some(bit);
        m[i][6] = Some(bit);
    }

    m[size - 8][8] = Some(1); // тёмный модуль

    for i in 0..9 {
        if m[8][i].is_none() {
            m[8][i] = Some(0);
        }
        if m[i][8].is_none() {
            m[i][8] = Some(0);
        }
    }
    for i in size - 8..size {
        m[8][i] = Some(0);
    }
    for i in size - 7..size {
        m[i][8] = Some(0);
    }

    if version >= 7 {
        let v = version as u32;
        let bits = (v << 12) | bch(v << 12, 0x1F25, 12);
        for i in 0..18usize {
            let bit = ((bits >> i) & 1) as u8;
            m[i / 3][size - 11 + i % 3] = Some(bit);
            m[size - 11 + i % 3][i / 3] = Some(bit);
        }
    }
}

fn place_data(m: &mut Vec<Vec<Option<u8>>>, size: usize, codewords: &[u8]) {
    let mut bits: Vec<u8> = Vec::with_capacity(codewords.len() * 8);
    for &cw in codewords {
        for i in (0..8).rev() {
            bits.push((cw >> i) & 1);
        }
    }

    let mut idx = 0usize;
    let mut upward = true;
    let mut col = size as i32 - 1;
    while col > 0 {
        if col == 6 {
            col -= 1;
        }
        let rows: Vec<usize> = if upward {
            (0..size).rev().collect()
        } else {
            (0..size).collect()
        };
        for row in rows {
            for c in [col, col - 1] {
                if m[row][c as usize].is_none() {
                    m[row][c as usize] = Some(if idx < bits.len() { bits[idx] } else { 0 });
                    idx += 1;
                }
            }
        }
        upward = !upward;
        col -= 2;
    }
}

fn mask_bit(mask: usize, r: usize, c: usize) -> bool {
    match mask {
        0 => (r + c).is_multiple_of(2),
        1 => r.is_multiple_of(2),
        2 => c.is_multiple_of(3),
        3 => (r + c).is_multiple_of(3),
        4 => (r / 2 + c / 3).is_multiple_of(2),
        5 => (r * c) % 2 + (r * c) % 3 == 0,
        6 => ((r * c) % 2 + (r * c) % 3).is_multiple_of(2),
        _ => ((r + c) % 2 + (r * c) % 3).is_multiple_of(2),
    }
}

fn is_function(size: usize, version: usize, row: usize, col: usize) -> bool {
    if row < 9 && col < 9 {
        return true;
    }
    if row < 9 && col >= size - 8 {
        return true;
    }
    if row >= size - 8 && col < 9 {
        return true;
    }
    if row == 6 || col == 6 {
        return true;
    }
    for &pos in ALIGN[version - 1] {
        for &pos2 in ALIGN[version - 1] {
            let skip = (pos == 6 && pos2 == 6)
                || (pos == 6 && pos2 == size - 7)
                || (pos == size - 7 && pos2 == 6);
            if skip {
                continue;
            }
            if row.abs_diff(pos) <= 2 && col.abs_diff(pos2) <= 2 {
                return true;
            }
        }
    }
    if version >= 7 && ((row < 6 && col >= size - 11) || (col < 6 && row >= size - 11)) {
        return true;
    }
    false
}

fn count_overlapping(haystack: &str, needle: &str) -> usize {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    if n.len() > h.len() {
        return 0;
    }
    (0..=h.len() - n.len()).filter(|&i| &h[i..i + n.len()] == n).count()
}

fn penalty(grid: &[Vec<u8>], size: usize) -> usize {
    let mut score = 0usize;

    let mut lines: Vec<Vec<u8>> = grid.to_vec();
    for c in 0..size {
        lines.push((0..size).map(|r| grid[r][c]).collect());
    }

    for line in &lines {
        // Правило 1: серии из пяти и более одинаковых модулей.
        let mut run = 1usize;
        for i in 1..line.len() {
            if line[i] == line[i - 1] {
                run += 1;
            } else {
                if run >= 5 {
                    score += 3 + run - 5;
                }
                run = 1;
            }
        }
        if run >= 5 {
            score += 3 + run - 5;
        }

        // Правило 3: узор, похожий на поисковый.
        let pattern: String = line.iter().map(|&b| if b == 1 { '1' } else { '0' }).collect();
        score += 40 * count_overlapping(&pattern, "10111010000");
        score += 40 * count_overlapping(&pattern, "00001011101");
    }

    // Правило 2: одноцветные квадраты 2×2.
    for r in 0..size - 1 {
        for c in 0..size - 1 {
            let sum = grid[r][c] + grid[r][c + 1] + grid[r + 1][c] + grid[r + 1][c + 1];
            if sum == 0 || sum == 4 {
                score += 3;
            }
        }
    }

    // Правило 4: перекос баланса тёмного и светлого.
    let dark: usize = grid.iter().flatten().map(|&b| b as usize).sum();
    let percent = dark as f64 * 100.0 / (size * size) as f64;
    score += 10 * ((percent - 50.0).abs() / 5.0) as usize;

    score
}

fn apply_format(grid: &mut Vec<Vec<u8>>, size: usize, mask_id: usize) {
    let fmt = (0b01u32 << 3) | mask_id as u32; // 0b01 — уровень коррекции L
    let bits = ((fmt << 10) | bch(fmt << 10, 0x537, 10)) ^ 0x5412;

    // Первая копия — вокруг верхнего левого поискового узора, старшим битом вперёд.
    for i in 0..15usize {
        let bit = ((bits >> (14 - i)) & 1) as u8;
        match i {
            0..=5 => grid[8][i] = bit,
            6 => grid[8][7] = bit,
            7 => grid[8][8] = bit,
            8 => grid[7][8] = bit,
            _ => grid[14 - i][8] = bit,
        }
    }
    // Вторая копия — тот же порядок бит: вверх по столбцу 8, затем вправо по строке 8.
    for j in 0..15usize {
        let bit = ((bits >> (14 - j)) & 1) as u8;
        if j < 7 {
            grid[size - 1 - j][8] = bit;
        } else {
            grid[8][size - 15 + j] = bit;
        }
    }
    grid[size - 8][8] = 1;
}

/// Строит матрицу QR: `true` — тёмный модуль.
pub fn encode(text: &str) -> Result<Vec<Vec<bool>>, String> {
    let payload = text.as_bytes();
    let version = (1..=10)
        .find(|&v| CAPACITY[v - 1] >= payload.len())
        .ok_or_else(|| format!("текст длиннее 271 байта: {}", payload.len()))?;

    let gf = Gf::new();
    let codewords = build_codewords(payload, version, &gf);
    let size = version * 4 + 17;

    let mut m: Vec<Vec<Option<u8>>> = vec![vec![None; size]; size];
    place_function_patterns(&mut m, size, version);
    place_data(&mut m, size, &codewords);

    let mut best: Option<(usize, Vec<Vec<u8>>)> = None;
    for mask_id in 0..8 {
        let mut grid: Vec<Vec<u8>> = (0..size)
            .map(|r| {
                (0..size)
                    .map(|c| {
                        let cell = m[r][c].unwrap_or(0);
                        if !is_function(size, version, r, c) && mask_bit(mask_id, r, c) {
                            cell ^ 1
                        } else {
                            cell
                        }
                    })
                    .collect()
            })
            .collect();
        apply_format(&mut grid, size, mask_id);

        let score = penalty(&grid, size);
        if best.as_ref().is_none_or(|(bs, _)| score < *bs) {
            best = Some((score, grid));
        }
    }

    let grid = best.unwrap().1;
    Ok(grid
        .into_iter()
        .map(|row| row.into_iter().map(|b| b == 1).collect())
        .collect())
}

/// Рисует матрицу полублоками: две строки модулей на одну строку текста.
pub fn render(grid: &[Vec<bool>], quiet: usize) -> String {
    let size = grid.len();
    let width = size + quiet * 2;
    let blank = vec![false; width];

    let mut rows: Vec<Vec<bool>> = vec![blank.clone(); quiet];
    for row in grid {
        let mut line = vec![false; quiet];
        line.extend(row.iter().copied());
        line.extend(std::iter::repeat_n(false, quiet));
        rows.push(line);
    }
    rows.extend(std::iter::repeat_n(blank, quiet));

    let mut out = String::new();
    let mut i = 0;
    while i < rows.len() {
        let top = &rows[i];
        let empty = vec![false; width];
        let bottom = if i + 1 < rows.len() { &rows[i + 1] } else { &empty };
        for (t, b) in top.iter().zip(bottom.iter()) {
            // Тёмный модуль должен печататься тёмной клеткой: терминал обычно
            // светлый на тёмном, а сканеру нужно наоборот.
            out.push(match (t, b) {
                (true, true) => ' ',
                (true, false) => '▄',
                (false, true) => '▀',
                (false, false) => '█',
            });
        }
        out.push('\n');
        i += 2;
    }
    out
}

// ── PNG без внешних библиотек ────────────────────────────────────────────
//
// Пишем чёрно-белый PNG вручную: сам формат простой, а тянуть ради него крейт
// с деком-прессией незачем. Данные упаковываем в zlib «как есть» (несжатые
// блоки) — QR маленький, размер файла всё равно копеечный.

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(kind);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc_input);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

/// Кодирует матрицу QR в PNG: тёмный модуль — чёрный, светлый — белый.
/// `scale` — сколько пикселей на модуль, `quiet` — поля в модулях.
pub fn to_png(grid: &[Vec<bool>], scale: usize, quiet: usize) -> Vec<u8> {
    let modules = grid.len() + quiet * 2;
    let side = modules * scale;

    // Сырьё: по строке на пиксель, каждая начинается с байта фильтра 0.
    let mut raw = Vec::with_capacity((side + 1) * side);
    for py in 0..side {
        raw.push(0);
        let my = py / scale;
        for px in 0..side {
            let mx = px / scale;
            let dark = my >= quiet
                && my < quiet + grid.len()
                && mx >= quiet
                && mx < quiet + grid.len()
                && grid[my - quiet][mx - quiet];
            raw.push(if dark { 0x00 } else { 0xFF });
        }
    }

    // zlib: заголовок + несжатые блоки (тип 00) + adler32.
    let mut zlib = vec![0x78, 0x01];
    let mut offset = 0;
    while offset < raw.len() {
        let block = std::cmp::min(65535, raw.len() - offset);
        let last = if offset + block >= raw.len() { 1 } else { 0 };
        zlib.push(last);
        zlib.extend_from_slice(&(block as u16).to_le_bytes());
        zlib.extend_from_slice(&(!(block as u16)).to_le_bytes());
        zlib.extend_from_slice(&raw[offset..offset + block]);
        offset += block;
    }
    zlib.extend_from_slice(&adler32(&raw).to_be_bytes());

    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&(side as u32).to_be_bytes());
    ihdr.extend_from_slice(&(side as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]); // 8 бит, greyscale
    png_chunk(&mut png, b"IHDR", &ihdr);
    png_chunk(&mut png, b"IDAT", &zlib);
    png_chunk(&mut png, b"IEND", &[]);
    png
}

#[cfg(test)]
mod png_tests {
    use super::*;

    #[test]
    fn png_has_valid_signature_and_size() {
        let grid = encode("test").unwrap();
        let png = to_png(&grid, 4, 4);
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        // IHDR ширина = (модули + поля*2) * scale
        let side = ((grid.len() + 8) * 4) as u32;
        let w = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
        assert_eq!(w, side);
    }
}
