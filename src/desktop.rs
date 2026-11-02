//! Иконка приложения. На Wayland окно не может само выставить иконку (winit 0.30 это игнорирует),
//! поэтому — стандарт freedesktop: app_id "pass2fa" + ~/.local/share/applications/pass2fa.desktop
//! + иконка в hicolor. Так её находит любая панель/док (waybar, sfwbar, …) — без привязки к DE.
//! На Windows/X11 дополнительно ставится иконка окна (with_icon); на Windows — ещё ярлык в «Пуске» и иконка exe (build.rs).
#[allow(unused_imports)]
use std::path::{Path, PathBuf};

pub const APP_ID: &str = "pass2fa";
pub static ICON_SVG: &[u8] = include_bytes!("../assets/pass2fa.svg");

/// RGBA px×px из встроенной SVG.
pub fn icon_rgba(px: u32) -> Option<Vec<u8>> {
    let tree = resvg::usvg::Tree::from_data(ICON_SVG, &resvg::usvg::Options::default()).ok()?;
    let mut pm = resvg::tiny_skia::Pixmap::new(px, px)?;
    let s = px as f32 / tree.size().width();
    resvg::render(&tree, resvg::tiny_skia::Transform::from_scale(s, s), &mut pm.as_mut());
    // tiny-skia хранит premultiplied — для PNG и IconData нужен straight alpha
    let mut out = pm.data().to_vec();
    for p in out.chunks_exact_mut(4) {
        let a = p[3] as u32;
        if a > 0 && a < 255 {
            for c in &mut p[..3] {
                *c = ((*c as u32 * 255 + a / 2) / a).min(255) as u8;
            }
        }
    }
    Some(out)
}

#[cfg(unix)]
fn paths() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let data = dirs::data_dir()?; // ~/.local/share
    Some((
        data.join("applications").join(format!("{APP_ID}.desktop")),
        data.join("icons/hicolor/scalable/apps").join(format!("{APP_ID}.svg")),
        data.join("icons/hicolor/256x256/apps").join(format!("{APP_ID}.png")),
    ))
}

#[cfg(unix)]
fn desktop_entry() -> String {
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| APP_ID.into());
    format!(
        "[Desktop Entry]\nType=Application\nName=2FA Codes and Passwords\nGenericName=Password Manager\n\
         Comment=Локальные пароли и 2FA (age)\nExec=\"{exe}\"\nIcon={APP_ID}\nTerminal=false\n\
         Categories=Utility;Security;\nStartupWMClass={APP_ID}\nStartupNotify=false\n"
    )
}

/// Пишет/обновляет только если содержимое отличается. Возвращает список записанных файлов.
#[cfg(unix)]
pub fn ensure_installed() -> Result<Vec<PathBuf>, String> {
    let (desk, svg, png) = paths().ok_or("нет XDG data dir")?;
    let mut written = Vec::new();
    let mut put = |p: &PathBuf, data: &[u8]| -> Result<(), String> {
        if std::fs::read(p).ok().as_deref() == Some(data) {
            return Ok(());
        }
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        std::fs::write(p, data).map_err(|e| format!("{}: {e}", p.display()))?;
        written.push(p.clone());
        Ok(())
    };
    put(&desk, desktop_entry().as_bytes())?;
    put(&svg, ICON_SVG)?;
    if let Some(rgba) = icon_rgba(256) {
        let mut buf = Vec::new();
        image::write_buffer_with_format(
            &mut std::io::Cursor::new(&mut buf),
            &rgba,
            256,
            256,
            image::ExtendedColorType::Rgba8,
            image::ImageFormat::Png,
        )
        .map_err(|e| e.to_string())?;
        put(&png, &buf)?;
    }
    if !written.is_empty() {
        refresh_icon_cache();
    }
    Ok(written)
}

/// Если в ~/.local/share/icons/hicolor лежит icon-theme.cache, Qt/GTK верят ему, пока не изменилась
/// дата папки темы, — и новую иконку не видят (панель показывает заглушку). Пересобираем кэш
/// gtk-update-icon-cache, если он есть; иначе просто обновляем дату папки — кэш считается устаревшим.
#[cfg(unix)]
fn refresh_icon_cache() {
    let Some(theme) = dirs::data_dir().map(|d| d.join("icons/hicolor")) else { return };
    if !theme.join("icon-theme.cache").exists() {
        return;
    }
    let rebuilt = ["gtk-update-icon-cache", "gtk4-update-icon-cache"].iter().any(|bin| {
        std::process::Command::new(bin)
            .args(["-f", "-q"])
            .arg(&theme)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    });
    if !rebuilt {
        if let Ok(f) = std::fs::File::open(&theme) {
            let _ = f.set_modified(std::time::SystemTime::now());
        }
    }
}

#[cfg(unix)]
pub fn uninstall() -> Vec<PathBuf> {
    let mut removed = Vec::new();
    if let Some((a, b, c)) = paths() {
        for p in [a, b, c] {
            if std::fs::remove_file(&p).is_ok() {
                removed.push(p);
            }
        }
    }
    removed
}

// Windows: ярлык «pass2fa» в меню «Пуск» (%APPDATA%\Microsoft\Windows\Start Menu\Programs) на pass2faw.exe —
// GUI без консоли; иконка — из ресурса exe. Создаётся только из установленной копии (%LOCALAPPDATA%\pass2fa),
// чтобы ярлык не вёл в папку сборки; пересоздаётся, если exe новее ярлыка (после обновления).
#[cfg(windows)]
fn shortcut() -> Option<PathBuf> {
    Some(dirs::data_dir()?.join(r"Microsoft\Windows\Start Menu\Programs").join(format!("{APP_ID}.lnk")))
}

#[cfg(windows)]
pub fn ensure_installed() -> Result<Vec<PathBuf>, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let home = dirs::data_local_dir().map(|d| d.join("pass2fa"));
    let dir = exe.parent().map(Path::to_path_buf);
    let canon = |p: &Option<PathBuf>| p.as_ref().and_then(|p| std::fs::canonicalize(p).ok());
    if canon(&home).is_none() || canon(&home) != canon(&dir) {
        return Ok(vec![]); // запуск не из установленной копии — ярлык не трогаем
    }
    let gui = exe.with_file_name("pass2faw.exe");
    let target = if gui.is_file() { gui } else { exe.clone() };
    let lnk = shortcut().ok_or("нет %APPDATA%")?;
    let mtime = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    if lnk.is_file() && mtime(&lnk) >= mtime(&target) {
        return Ok(vec![]);
    }
    if let Some(d) = lnk.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    // пути — через переменные окружения: без проблем с кавычками и кириллицей в профиле
    let ps = "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:P2F_LNK);\
              $s.TargetPath=$env:P2F_EXE;$s.WorkingDirectory=$env:P2F_DIR;\
              $s.IconLocation=$env:P2F_EXE+',0';$s.Description='2FA Codes and Passwords';$s.Save()";
    let st = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps])
        .env("P2F_LNK", &lnk)
        .env("P2F_EXE", &target)
        .env("P2F_DIR", target.parent().unwrap_or(Path::new(".")))
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("powershell: {e}"))?;
    if !st.success() {
        return Err(format!("не удалось создать ярлык {}", lnk.display()));
    }
    Ok(vec![lnk])
}

#[cfg(windows)]
pub fn uninstall() -> Vec<PathBuf> {
    shortcut().into_iter().filter(|p| std::fs::remove_file(p).is_ok()).collect()
}

#[cfg(not(any(unix, windows)))]
pub fn ensure_installed() -> Result<Vec<PathBuf>, String> {
    Ok(vec![])
}
#[cfg(not(any(unix, windows)))]
pub fn uninstall() -> Vec<PathBuf> {
    vec![]
}

#[cfg(test)]
mod tests {
    #[test]
    fn icon_renders() {
        let px = super::icon_rgba(64).unwrap();
        assert_eq!(px.len(), 64 * 64 * 4);
        assert!(px.chunks(4).any(|p| p[3] == 255));
    }
}
