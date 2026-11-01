//! Иконка приложения. На Wayland окно не может само выставить иконку (winit 0.30 это игнорирует),
//! поэтому — стандарт freedesktop: app_id "pass2fa" + ~/.local/share/applications/pass2fa.desktop
//! + иконка в hicolor. Так её находит любая панель/док (waybar, sfwbar, …) — без привязки к DE.
//! На Windows/X11 дополнительно ставится иконка окна (with_icon).
use std::path::PathBuf;

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
    Ok(written)
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

#[cfg(not(unix))]
pub fn ensure_installed() -> Result<Vec<PathBuf>, String> {
    Ok(vec![])
}
#[cfg(not(unix))]
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
