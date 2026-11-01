//! Иконки сервисов офлайн: встроенный набор Simple Icons (CC0, ~3500 брендов),
//! автоподбор по issuer / имени / домену URL. Своя иконка (файл или "si:<slug>") имеет приоритет.
//! Нет совпадения — плашка с первой буквой.
use eframe::egui::{self, Color32};
use std::collections::HashMap;
use std::sync::OnceLock;

static BLOB: &[u8] = include_bytes!("../assets/simple-icons.tsv.z");

pub struct Si {
    pub slug: String,
    pub hex: Color32,
    pub path: String,
}

struct Db {
    icons: Vec<Si>,
    by_key: HashMap<String, usize>,
}

fn db() -> &'static Db {
    static DB: OnceLock<Db> = OnceLock::new();
    DB.get_or_init(|| {
        let raw = miniz_oxide::inflate::decompress_to_vec_zlib(BLOB).unwrap_or_default();
        let text = String::from_utf8_lossy(&raw);
        let mut icons = Vec::new();
        let mut by_key = HashMap::new();
        for line in text.lines() {
            let mut it = line.splitn(4, '\t');
            let (Some(slug), Some(hex), Some(keys), Some(path)) = (it.next(), it.next(), it.next(), it.next()) else { continue };
            let c = u32::from_str_radix(hex, 16).unwrap_or(0x5E81AC);
            let idx = icons.len();
            icons.push(Si {
                slug: slug.to_string(),
                hex: Color32::from_rgb((c >> 16) as u8, (c >> 8) as u8, c as u8),
                path: path.to_string(),
            });
            by_key.entry(slug.to_string()).or_insert(idx);
            for k in keys.split(' ') {
                by_key.entry(k.to_string()).or_insert(idx);
            }
        }
        Db { icons, by_key }
    })
}

pub fn norm(s: &str) -> String {
    s.to_lowercase().chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}

pub fn by_slug(slug: &str) -> Option<&'static Si> {
    let d = db();
    d.by_key.get(&norm(slug)).map(|&i| &d.icons[i])
}

/// Хост из URL без схемы/порта/пути и без www.
pub fn host(url: &str) -> Option<String> {
    let u = url.trim();
    let u = u.split("://").nth(1).unwrap_or(u);
    let h = u.split(['/', '?', '#', ':']).next()?.trim_start_matches("www.").to_lowercase();
    if h.contains('.') { Some(h) } else { None }
}

/// Ищем по кандидатам: само слово, слово+com/dotcom; для домена — метки слева направо.
pub fn find(cands: &[&str]) -> Option<&'static Si> {
    let d = db();
    let mut keys: Vec<String> = Vec::new();
    for c in cands {
        let c = c.trim();
        if c.is_empty() { continue; }
        if let Some(h) = host(c) {
            // mail.google.com -> mailgooglecom, google ; booking.com -> bookingcom, booking
            let labels: Vec<&str> = h.split('.').collect();
            keys.push(norm(&h));
            if labels.len() >= 2 {
                keys.push(norm(&labels[labels.len() - 2..].join(".")));
                keys.push(norm(labels[labels.len() - 2]));
            }
            keys.extend(labels.iter().take(labels.len().saturating_sub(1)).map(|l| norm(l)));
        } else {
            // «Google (me@x)» -> «Google»; «Atlassian Jira» -> целиком и по словам
            let head = c.split(['(', ':', '|', '—', '-']).next().unwrap_or(c).trim();
            for v in [head, c] {
                let n = norm(v);
                keys.push(n.clone());
                keys.push(format!("{n}com"));
                keys.push(format!("{n}dotcom"));
            }
            keys.extend(head.split_whitespace().map(norm));
        }
    }
    keys.into_iter()
        .filter(|k| k.len() >= 2)
        .find_map(|k| d.by_key.get(&k).map(|&i| &d.icons[i]))
}

/// Растеризация SVG-пути 24x24 в белый (или тёмный для светлых брендов) значок.
pub fn rasterize(si: &Si, px: u32) -> Option<egui::ColorImage> {
    let [r, g, b, _] = si.hex.to_array();
    let lum = 0.2126 * r as f32 + 0.7152 * g as f32 + 0.0722 * b as f32;
    let fg = if lum > 190.0 { "#2E3440" } else { "#FFFFFF" };
    let svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="{fg}" d="{}"/></svg>"#,
        si.path
    );
    let tree = resvg::usvg::Tree::from_str(&svg, &resvg::usvg::Options::default()).ok()?;
    let mut pm = resvg::tiny_skia::Pixmap::new(px, px)?;
    let s = px as f32 / 24.0;
    resvg::render(&tree, resvg::tiny_skia::Transform::from_scale(s, s), &mut pm.as_mut());
    Some(egui::ColorImage::from_rgba_premultiplied([px as usize, px as usize], pm.data()))
}

pub const FILE_EXTS: &[&str] = &["svg", "svgz", "png", "jpg", "jpeg", "ico", "webp"];

/// Своя иконка из файла: SVG/SVGZ через resvg (векторно, в нужном размере), остальное через image.
/// Результат — квадрат px×px, картинка вписана с сохранением пропорций.
pub fn load_file(path: &std::path::Path, px: u32) -> Option<egui::ColorImage> {
    let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    if ext == "svg" || ext == "svgz" {
        let data = std::fs::read(path).ok()?;
        let mut opt = resvg::usvg::Options::default();
        opt.resources_dir = path.parent().map(|p| p.to_path_buf());
        let tree = resvg::usvg::Tree::from_data(&data, &opt).ok()?; // svgz распаковывается сам
        let sz = tree.size();
        let s = (px as f32 / sz.width()).min(px as f32 / sz.height());
        let (dx, dy) = ((px as f32 - sz.width() * s) / 2.0, (px as f32 - sz.height() * s) / 2.0);
        let mut pm = resvg::tiny_skia::Pixmap::new(px, px)?;
        resvg::render(&tree, resvg::tiny_skia::Transform::from_row(s, 0.0, 0.0, s, dx, dy), &mut pm.as_mut());
        return Some(egui::ColorImage::from_rgba_premultiplied([px as usize, px as usize], pm.data()));
    }
    let img = image::open(path).ok()?.thumbnail(px, px).to_rgba8();
    Some(egui::ColorImage::from_rgba_unmultiplied([img.width() as usize, img.height() as usize], img.as_raw()))
}

/// Цвет плашки-буквы — стабильный по имени, из палитры Nord.
pub fn letter_color(name: &str) -> Color32 {
    const P: [Color32; 6] = [
        Color32::from_rgb(191, 97, 106),
        Color32::from_rgb(208, 135, 112),
        Color32::from_rgb(163, 190, 140),
        Color32::from_rgb(180, 142, 173),
        Color32::from_rgb(94, 129, 172),
        Color32::from_rgb(143, 188, 187),
    ];
    let h = name.bytes().fold(5381u32, |a, b| a.wrapping_mul(33) ^ b as u32);
    P[(h % P.len() as u32) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matching() {
        assert_eq!(find(&["GitHub (b0ris8)"]).unwrap().slug, "github");
        assert_eq!(find(&["Booking"]).unwrap().slug, "bookingdotcom");
        assert_eq!(find(&["", "https://www.paypal.com/signin"]).unwrap().slug, "paypal");
        assert_eq!(find(&["Atlassian Jira (me@x)"]).unwrap().slug, "atlassian");
        assert!(rasterize(by_slug("github").unwrap(), 32).is_some());
        // своя SVG (неквадратная, с группой и трансформацией) — вписывается в квадрат
        let p = std::env::temp_dir().join(format!("pass2fa-icon-{}.svg", std::process::id()));
        std::fs::write(&p, r##"<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100" viewBox="0 0 200 100"><g transform="translate(10,10)"><rect width="180" height="80" rx="12" fill="#0a84ff"/><circle cx="90" cy="40" r="30" fill="#fff"/></g></svg>"##).unwrap();
        let img = load_file(&p, 64).unwrap();
        assert_eq!(img.size, [64, 64]);
        let _ = std::fs::remove_file(&p);
    }
}
