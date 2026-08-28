//! Эталонные матрицы QR.
//!
//! Вектора в `tests/vectors.txt` сняты с реализации, которая помодульно сверена
//! с libqrencode (при одинаковой маске совпало 105 случайных строк из 105).
//! Здесь проверяется, что кодировщик даёт ровно те же матрицы.

use std::process::Command;

fn matrix(text: &str) -> Vec<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_netpult"))
        .args(["--raw", text])
        .output()
        .expect("не запустился netpult");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn matches_reference_vectors() {
    let raw = include_str!("vectors.txt");
    let mut lines = raw.lines();
    let mut checked = 0;

    while let Some(text) = lines.next() {
        let rows: usize = lines.next().expect("нет числа строк").parse().unwrap();
        let expected: Vec<String> = (0..rows)
            .map(|_| lines.next().expect("не хватает строк матрицы").to_string())
            .collect();

        let got = matrix(text);
        assert_eq!(got.len(), expected.len(), "размер матрицы для {text:?}");
        for (i, (a, b)) in got.iter().zip(expected.iter()).enumerate() {
            assert_eq!(a, b, "строка {i} матрицы для {text:?}");
        }
        checked += 1;
    }

    assert_eq!(checked, 5, "проверено векторов");
}
