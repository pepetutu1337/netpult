//! Разбор набранного в строке ввода: ссылка и команда с аргументами.
//!
//! Проверяется через сам бинарь: «vpn sub <ссылка>» и «vpn use <имя>» должны
//! доходить до дела, а не отвечать «нужна ссылка» или «нет такой команды».

use std::process::Command;

fn run(args: &[&str]) -> (bool, String) {
    let dir = std::env::temp_dir().join(format!("netpult-input-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let out = Command::new(env!("CARGO_BIN_EXE_netpult"))
        .args(args)
        .env("HOME", &dir)
        .env("XDG_DATA_HOME", dir.join("data"))
        .output()
        .expect("бинарь не запустился");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[test]
fn подписка_из_файла_разбирается_командой_с_аргументом() {
    let dir = std::env::temp_dir().join(format!("netpult-input-src-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sample = dir.join("sample");
    std::fs::write(&sample, "vless://uuid@example.com:443?security=tls#Нода").unwrap();
    let (ok, text) = run(&["vpn", "sub", &format!("file://{}", sample.display())]);
    assert!(ok, "разбор не удался: {text}");
    assert!(text.contains("Актив: 1"), "{text}");
}

#[test]
fn команда_без_обязательного_аргумента_объясняет_чего_ждёт() {
    let (ok, text) = run(&["vpn", "sub"]);
    assert!(!ok);
    assert!(text.contains("нужна ссылка"), "{text}");
}

#[test]
fn незнакомая_команда_подсказывает_похожую() {
    let (ok, text) = run(&["vpn", "nods"]);
    assert!(!ok);
    assert!(text.contains("vpn nodes"), "{text}");
}
