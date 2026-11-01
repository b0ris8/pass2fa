//! Несекретное состояние интерфейса: ~/.config/pass2fa/state.json (последняя папка выбора файла,
//! размер окна). Свой файл — не зависим от кэшей/настроек окружения рабочего стола.
use serde_json::{Map, Value};
use std::path::PathBuf;

fn file() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("pass2fa").join("state.json"))
}

fn load() -> Map<String, Value> {
    file()
        .and_then(|f| std::fs::read_to_string(f).ok())
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

/// Чтение-изменение-запись одного ключа (остальные сохраняются).
pub fn set(key: &str, val: Value) {
    let Some(f) = file() else { return };
    let mut m = load();
    if m.get(key) == Some(&val) {
        return;
    }
    m.insert(key.into(), val);
    if let Some(d) = f.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(&f, serde_json::to_string_pretty(&Value::Object(m)).unwrap_or_default());
}

pub fn get(key: &str) -> Option<Value> {
    load().get(key).cloned()
}

/// Размер окна в логических пикселях [ширина, высота].
pub fn window_size() -> Option<[f32; 2]> {
    let a = get("window")?;
    let (w, h) = (a.get(0)?.as_f64()? as f32, a.get(1)?.as_f64()? as f32);
    (w >= 400.0 && h >= 300.0 && w < 10000.0 && h < 10000.0).then_some([w, h])
}

pub fn set_window_size(s: [f32; 2]) {
    set("window", serde_json::json!([s[0].round(), s[1].round()]));
}
