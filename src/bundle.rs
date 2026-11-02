//! Браузерное расширение, встроенное в бинарник: `install-browser` раскладывает его рядом с манифестом хоста,
//! так что программа и расширение всегда одной версии и не нужны bash/zip для сборки.
//! Firefox/LibreWolf — .xpi (zip без сжатия), Chromium — распакованная папка.
use std::path::{Path, PathBuf};

const FILES: &[(&str, &[u8])] = &[
    ("background.js", include_bytes!("../extension/src/background.js")),
    ("common.js", include_bytes!("../extension/src/common.js")),
    ("popup.css", include_bytes!("../extension/src/popup.css")),
    ("popup.html", include_bytes!("../extension/src/popup.html")),
    ("popup.js", include_bytes!("../extension/src/popup.js")),
    ("icons/icon-16.png", include_bytes!("../extension/src/icons/icon-16.png")),
    ("icons/icon-32.png", include_bytes!("../extension/src/icons/icon-32.png")),
    ("icons/icon-48.png", include_bytes!("../extension/src/icons/icon-48.png")),
    ("icons/icon-128.png", include_bytes!("../extension/src/icons/icon-128.png")),
];
const MANIFEST_FIREFOX: &[u8] = include_bytes!("../extension/manifest.firefox.json");
const MANIFEST_CHROMIUM: &[u8] = include_bytes!("../extension/manifest.chromium.json");

/// Куда раскладывать: Linux ~/.local/share/pass2fa/extension, Windows %LOCALAPPDATA%\pass2fa\extension.
pub fn dir() -> PathBuf {
    dirs::data_local_dir().unwrap_or_else(|| PathBuf::from(".")).join("pass2fa").join("extension")
}

/// Записать pass2fa-firefox.xpi и chromium/; вернуть (xpi, папка chromium).
pub fn write(base: &Path) -> Result<(PathBuf, PathBuf), String> {
    let ch = base.join("chromium");
    std::fs::create_dir_all(ch.join("icons")).map_err(|e| format!("{}: {e}", ch.display()))?;
    for (name, data) in FILES.iter().copied().chain([("manifest.json", MANIFEST_CHROMIUM)]) {
        let p = ch.join(name);
        std::fs::write(&p, data).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    let xpi = base.join("pass2fa-firefox.xpi");
    let entries: Vec<(&str, &[u8])> = std::iter::once(("manifest.json", MANIFEST_FIREFOX)).chain(FILES.iter().copied()).collect();
    std::fs::write(&xpi, zip_stored(&entries)).map_err(|e| format!("{}: {e}", xpi.display()))?;
    Ok((xpi, ch))
}

pub fn remove(base: &Path) -> Option<PathBuf> {
    std::fs::remove_dir_all(base).ok().map(|_| base.to_path_buf())
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

/// Минимальный zip (метод 0 — без сжатия), дата 1980-01-01: этого достаточно для .xpi.
fn zip_stored(files: &[(&str, &[u8])]) -> Vec<u8> {
    const DATE: u16 = 0x0021; // 1980-01-01
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let (crc, size, off) = (crc32(data), data.len() as u32, out.len() as u32);
        let n = name.as_bytes();
        // локальный заголовок
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // версия для распаковки
        out.extend_from_slice(&0u16.to_le_bytes()); // флаги
        out.extend_from_slice(&0u16.to_le_bytes()); // метод: store
        out.extend_from_slice(&0u16.to_le_bytes()); // время
        out.extend_from_slice(&DATE.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(n.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(n);
        out.extend_from_slice(data);
        // запись центрального каталога
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // создано версией
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&DATE.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(n.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // комментарий
        central.extend_from_slice(&0u16.to_le_bytes()); // диск
        central.extend_from_slice(&0u16.to_le_bytes()); // внутр. атрибуты
        central.extend_from_slice(&0u32.to_le_bytes()); // внешн. атрибуты
        central.extend_from_slice(&off.to_le_bytes());
        central.extend_from_slice(n);
    }
    let (cd_off, cd_len, cnt) = (out.len() as u32, central.len() as u32, files.len() as u16);
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&cnt.to_le_bytes());
    out.extend_from_slice(&cnt.to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_known() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn manifests_have_ids() {
        let ff: serde_json::Value = serde_json::from_slice(MANIFEST_FIREFOX).unwrap();
        assert_eq!(ff["browser_specific_settings"]["gecko"]["id"], crate::native::FIREFOX_EXT_ID);
        let _: serde_json::Value = serde_json::from_slice(MANIFEST_CHROMIUM).unwrap();
    }
}
