//! GUI на egui/eframe (wgpu + Wayland), без GTK, порталов и DBus.
use crate::filepick::{Outcome, Picker, Purpose};
use crate::gen::{self, GenOpts};
use crate::model::{Algo, LoginEntry, TotpEntry, Vault};
use crate::{export, icons, import, totp, vault};
use age::secrecy::{ExposeSecret, SecretString};
use eframe::egui::{self, Align, Color32, Layout, RichText, TextureHandle, TextureOptions, Vec2};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// Иконки Phosphor (MIT), вшитое подмножество assets/phosphor-subset.ttf.
#[allow(dead_code)]
pub mod icon {
    pub const COPY: &str = "\u{e1ca}";
    pub const EDIT: &str = "\u{e3b4}";
    pub const TRASH: &str = "\u{e4a6}";
    pub const EYE: &str = "\u{e220}";
    pub const EYE_OFF: &str = "\u{e224}";
    pub const LOCK: &str = "\u{e2fa}";
    pub const LOCK_KEY: &str = "\u{e2fe}";
    pub const PLUS: &str = "\u{e3d4}";
    pub const KEY: &str = "\u{e2d6}";
    pub const SHIELD: &str = "\u{e40c}";
    pub const GEAR: &str = "\u{e270}";
    pub const IMPORT: &str = "\u{e20c}";
    pub const EXPORT: &str = "\u{e4c0}";
    pub const DICE: &str = "\u{e1ee}";
    pub const SEARCH: &str = "\u{e30c}";
    pub const X: &str = "\u{e4f6}";
    pub const CHECK: &str = "\u{e182}";
    pub const WARN: &str = "\u{e4e0}";
    pub const USER: &str = "\u{e4c2}";
    pub const SPIN: &str = "\u{e094}";
    pub const ARROW_RIGHT: &str = "\u{e06c}";
    pub const ARROW_UP: &str = "\u{e08e}";
    pub const FOLDER: &str = "\u{e24a}";
    pub const FOLDER_OPEN: &str = "\u{e256}";
    pub const FILE: &str = "\u{e230}";
    pub const HOUSE: &str = "\u{e2c2}";
    pub const IMAGE: &str = "\u{e2ca}";
    pub const GLOBE: &str = "\u{e288}";
    pub const RESET: &str = "\u{e038}";
    pub const MINUS: &str = "\u{e32a}";
    pub const RECENT: &str = "\u{e1a0}";
}
use icon::*;

const AUTOLOCK: Duration = Duration::from_secs(5 * 60);
const CLIP_CLEAR: Duration = Duration::from_secs(20);

// ширина контентной колонки и колонок строк
const CODES_W: f32 = 820.0;
const LOGINS_W: f32 = 1040.0;
const ROW_H: f32 = 44.0;
const ICON: f32 = 30.0;

// Nord
const N0: Color32 = Color32::from_rgb(46, 52, 64);
const N1: Color32 = Color32::from_rgb(59, 66, 82);
const N2: Color32 = Color32::from_rgb(67, 76, 94);
const N3: Color32 = Color32::from_rgb(76, 86, 106);
const N4: Color32 = Color32::from_rgb(216, 222, 233);
const SUB: Color32 = Color32::from_rgb(150, 162, 184);
const N6: Color32 = Color32::from_rgb(236, 239, 244);
const N8: Color32 = Color32::from_rgb(136, 192, 208);
const N10: Color32 = Color32::from_rgb(94, 129, 172);
const RED: Color32 = Color32::from_rgb(191, 97, 106);
const YEL: Color32 = Color32::from_rgb(235, 203, 139);
const GRN: Color32 = Color32::from_rgb(163, 190, 140);

pub fn run(path: PathBuf) -> eframe::Result<()> {
    // Wayland: иконку панель берёт из .desktop по app_id — держим их актуальными (пишет только при изменении)
    let _ = crate::desktop::ensure_installed();
    let mut vp = egui::ViewportBuilder::default()
        .with_title("2FA Codes and Passwords")
        .with_app_id(crate::desktop::APP_ID);
    if let Some(rgba) = crate::desktop::icon_rgba(128) {
        vp = vp.with_icon(std::sync::Arc::new(egui::IconData { rgba, width: 128, height: 128 }));
    }
    #[cfg(feature = "devshot")]
    if let Some(w) = std::env::var("PASS2FA_DEV_W").ok().and_then(|w| w.parse::<f32>().ok()) {
        vp = vp.with_min_inner_size([300.0, 300.0]).with_inner_size([w, 720.0]);
    }
    let opts = eframe::NativeOptions {
        viewport: vp
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([520.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native("pass2fa", opts, Box::new(move |cc| Ok(Box::new(App::new(cc, path)))))
}

// ---------- фоновое сохранение (scrypt ~1 c, UI не замирает) ----------
struct Saver {
    tx: Option<Sender<(Vault, SecretString)>>,
    rx: Receiver<Result<(), String>>,
    pending: usize,
    handle: Option<JoinHandle<()>>,
}

impl Saver {
    fn new(path: PathBuf) -> Self {
        let (tx, wrx) = mpsc::channel::<(Vault, SecretString)>();
        let (wtx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            while let Ok(mut job) = wrx.recv() {
                let mut skipped = 0;
                while let Ok(newer) = wrx.try_recv() {
                    job = newer; // пишем только самую свежую версию
                    skipped += 1;
                }
                let r = vault::save(&path, &job.1, &job.0);
                for _ in 0..skipped {
                    let _ = wtx.send(Ok(()));
                }
                let _ = wtx.send(r);
            }
        });
        Self { tx: Some(tx), rx, pending: 0, handle: Some(handle) }
    }
    fn submit(&mut self, v: &Vault, p: &SecretString) {
        if let Some(tx) = &self.tx {
            self.pending += 1;
            let _ = tx.send((v.clone(), p.clone()));
        }
    }
    fn poll(&mut self) -> Option<String> {
        let mut err = None;
        while let Ok(r) = self.rx.try_recv() {
            self.pending = self.pending.saturating_sub(1);
            if let Err(e) = r { err = Some(e); }
        }
        err
    }
    fn finish(&mut self) {
        self.tx.take();
        if let Some(h) = self.handle.take() { let _ = h.join(); }
    }
}

// ---------- иконки сервисов ----------
struct IconCache {
    base: PathBuf,
    tex: HashMap<String, Option<TextureHandle>>,
}

enum Ico {
    Brand(TextureHandle, Color32),
    Image(TextureHandle),
    Letter(String, Color32),
}

impl IconCache {
    fn si_tex(&mut self, ctx: &egui::Context, si: &icons::Si) -> Option<TextureHandle> {
        let key = format!("si:{}", si.slug);
        self.tex
            .entry(key.clone())
            .or_insert_with(|| icons::rasterize(si, 64).map(|img| ctx.load_texture(key, img, TextureOptions::LINEAR)))
            .clone()
    }

    fn file_tex(&mut self, ctx: &egui::Context, p: &str) -> Option<TextureHandle> {
        let key = format!("file:{p}");
        if !self.tex.contains_key(&key) {
            let pb = Path::new(p);
            let full = if pb.is_relative() { self.base.join(pb) } else { pb.to_path_buf() };
            let t = icons::load_file(&full, 64).map(|ci| ctx.load_texture(key.clone(), ci, TextureOptions::LINEAR));
            self.tex.insert(key.clone(), t);
        }
        self.tex.get(&key).cloned().flatten()
    }

    /// Своя иконка (si:slug / файл) → автоподбор Simple Icons → буква.
    fn resolve(&mut self, ctx: &egui::Context, custom: Option<&str>, cands: &[&str], name: &str) -> Ico {
        if let Some(c) = custom.map(str::trim).filter(|c| !c.is_empty()) {
            if let Some(slug) = c.strip_prefix("si:") {
                if let Some(si) = icons::by_slug(slug) {
                    if let Some(t) = self.si_tex(ctx, si) { return Ico::Brand(t, si.hex); }
                }
            } else if let Some(t) = self.file_tex(ctx, c) {
                return Ico::Image(t);
            }
        }
        if let Some(si) = icons::find(cands) {
            if let Some(t) = self.si_tex(ctx, si) { return Ico::Brand(t, si.hex); }
        }
        let l = name.trim().chars().find(|c| c.is_alphanumeric()).map(|c| c.to_uppercase().to_string()).unwrap_or("?".into());
        Ico::Letter(l, icons::letter_color(name))
    }

    fn paint(&mut self, ui: &mut egui::Ui, custom: Option<&str>, cands: &[&str], name: &str, size: f32) {
        let ico = self.resolve(ui.ctx(), custom, cands, name);
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
        let p = ui.painter();
        let r = size * 0.22;
        let uv = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
        match ico {
            Ico::Brand(t, bg) => {
                p.rect_filled(rect, r, bg);
                p.image(t.id(), rect.shrink(size * 0.2), uv, Color32::WHITE);
            }
            Ico::Image(t) => {
                p.rect_filled(rect, r, N2);
                p.image(t.id(), rect.shrink(size * 0.06), uv, Color32::WHITE);
            }
            Ico::Letter(l, bg) => {
                p.rect_filled(rect, r, bg);
                p.text(rect.center(), egui::Align2::CENTER_CENTER, l, egui::FontId::proportional(size * 0.55), Color32::WHITE);
            }
        }
    }
}

fn code_cands(c: &TotpEntry) -> [&str; 2] {
    [c.issuer.as_str(), c.name.as_str()]
}
fn login_cands(l: &LoginEntry) -> [&str; 2] {
    [l.url.as_str(), l.name.as_str()]
}

// ---------- состояние ----------
enum Screen {
    Locked { pass: String, err: Option<String>, show: bool },
    Create { p1: String, p2: String, err: Option<String>, show: bool },
    Unlocking(Receiver<Result<(Vault, SecretString), String>>),
    Open(Box<Session>),
}

#[derive(PartialEq, Clone, Copy)]
enum Tab { Codes, Logins, Settings }

enum Edit {
    Code { idx: Option<usize>, e: TotpEntry, uri: String, err: Option<String>, show: bool },
    Login { idx: Option<usize>, e: LoginEntry, show: bool },
}

struct Session {
    v: Vault,
    pass: SecretString,
    tab: Tab,
    filter: String,
    shown: HashSet<usize>,
    edit: Option<Edit>,
    confirm_del: Option<(Tab, usize)>,
    gen: GenOpts,
    import_path: String,
    export_path: String,
    export_pv_path: String,
    picker: Option<Picker>,
    np0: String,
    np1: String,
    np2: String,
    show_np: bool,
}

struct App {
    path: PathBuf,
    screen: Screen,
    saver: Saver,
    status: Option<(String, Color32, Instant)>,
    last_input: Instant,
    clip_at: Option<Instant>,
    ic: IconCache,
    #[cfg(feature = "devshot")]
    frames: u32,
}

/// Число с кнопками «−» / «+» (значение можно и тянуть мышью, и ввести).
fn stepper(ui: &mut egui::Ui, v: &mut i64, min: i64, max: i64, step: i64, suffix: &str) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 3.0;
        let b = Vec2::new(28.0, 26.0);
        if ui.add_enabled(*v > min, egui::Button::new(MINUS).min_size(b)).clicked() {
            // к ближайшему кратному шагу вниз (30 → 15, 29 → 15)
            *v = (((*v - 1).div_euclid(step)) * step).max(min);
        }
        ui.add(egui::DragValue::new(v).range(min..=max).suffix(suffix).speed(0.2));
        if ui.add_enabled(*v < max, egui::Button::new(PLUS).min_size(b)).clicked() {
            *v = (((*v).div_euclid(step) + 1) * step).min(max);
        }
    });
}

/// Поле секрета с кнопкой «глаз». Возвращает ответ TextEdit.
fn secret_field(ui: &mut egui::Ui, text: &mut String, show: &mut bool, hint: &str, width: f32) -> egui::Response {
    ui.horizontal(|ui| {
        let r = ui.add(
            egui::TextEdit::singleline(text)
                .password(!*show)
                .hint_text(hint)
                .desired_width(width)
                .font(egui::TextStyle::Monospace),
        );
        if ui
            .add(egui::Button::new(if *show { EYE_OFF } else { EYE }).min_size(Vec2::new(34.0, 28.0)))
            .on_hover_text(if *show { "скрыть" } else { "показать" })
            .clicked()
        {
            *show = !*show;
        }
        r
    })
    .inner
}

fn enter(r: &egui::Response) -> bool {
    r.lost_focus() && r.ctx.input(|i| i.key_pressed(egui::Key::Enter))
}

fn arrow(ui: &mut egui::Ui, tip: &str) -> bool {
    ui.add(egui::Button::new(RichText::new(ARROW_RIGHT).size(16.0)).fill(N10).min_size(Vec2::new(40.0, 28.0)))
        .on_hover_text(tip)
        .clicked()
}

fn has_cyr(s: &str) -> bool {
    s.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c))
}

fn layout_warn(ui: &mut egui::Ui, s: &[&str]) {
    if s.iter().any(|x| has_cyr(x)) {
        ui.colored_label(YEL, format!("{WARN} в пароле кириллица — раскладка RU"));
    }
}

/// Центрированная колонка фиксированной ширины (или по окну, если оно уже).
fn column<R>(ui: &mut egui::Ui, max_w: f32, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let w = ui.available_width().min(max_w);
    let pad = ((ui.available_width() - w) / 2.0).max(0.0);
    ui.horizontal_top(|ui| {
        ui.add_space(pad);
        ui.vertical(|ui| {
            ui.set_width(w);
            add(ui)
        })
        .inner
    })
    .inner
}

fn row_frame(i: usize) -> egui::Frame {
    egui::Frame::new()
        .fill(if i % 2 == 0 { N1 } else { N0 })
        .corner_radius(6.0)
        .inner_margin(egui::Margin::symmetric(10, 0))
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, path: PathBuf) -> Self {
        nord(&cc.egui_ctx);
        cc.egui_ctx.set_zoom_factor(1.25);
        #[cfg(feature = "devshot")]
        if let Some(z) = std::env::var("PASS2FA_DEV_ZOOM").ok().and_then(|z| z.parse::<f32>().ok()) {
            cc.egui_ctx.set_zoom_factor(z);
        }
        let screen = if vault::exists(&path) {
            Screen::Locked { pass: String::new(), err: None, show: false }
        } else {
            Screen::Create { p1: String::new(), p2: String::new(), err: None, show: false }
        };
        Self {
            saver: Saver::new(path.clone()),
            ic: IconCache { base: path.parent().unwrap_or(Path::new(".")).to_path_buf(), tex: HashMap::new() },
            path,
            screen,
            status: None,
            last_input: Instant::now(),
            clip_at: None,
            #[cfg(feature = "devshot")]
            frames: 0,
        }
    }

    fn msg(&mut self, s: impl Into<String>, c: Color32) {
        self.status = Some((s.into(), c, Instant::now()));
    }

    fn copy(&mut self, ctx: &egui::Context, text: &str, what: &str) {
        ctx.copy_text(text.to_string());
        self.clip_at = Some(Instant::now() + CLIP_CLEAR);
        self.msg(format!("{what} скопирован, буфер очистится через {} с", CLIP_CLEAR.as_secs()), GRN);
    }

    fn lock(&mut self) {
        if let Screen::Open(s) = &mut self.screen {
            s.np0.zeroize();
            s.np1.zeroize();
            s.np2.zeroize();
            if let Some(Edit::Login { e, .. }) = &mut s.edit { e.zeroize(); }
        }
        // Session -> drop: Vault и записи затираются (ZeroizeOnDrop)
        self.screen = Screen::Locked { pass: String::new(), err: None, show: false };
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &ui.ctx().clone();
        #[cfg(feature = "devshot")]
        self.devshot(ctx);
        let active = ctx.input(|i| !i.events.is_empty() || i.pointer.is_moving());
        if active { self.last_input = Instant::now(); }
        if matches!(self.screen, Screen::Open(_)) {
            if self.last_input.elapsed() > AUTOLOCK || ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::L)) {
                self.lock();
                self.msg("Заблокировано", N8);
            }
            ctx.request_repaint_after(Duration::from_millis(500));
        }
        if let Some(t) = self.clip_at {
            if Instant::now() >= t {
                ctx.copy_text(String::new());
                self.clip_at = None;
            } else {
                ctx.request_repaint_after(t - Instant::now());
            }
        }
        if let Some(e) = self.saver.poll() { self.msg(format!("ОШИБКА СОХРАНЕНИЯ: {e}"), RED); }
        if self.saver.pending > 0 { ctx.request_repaint_after(Duration::from_millis(200)); }

        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).filter(|p| !p.as_os_str().is_empty()).collect()
        });
        for p in dropped { self.do_import(&p); }

        if let Screen::Unlocking(rx) = &mut self.screen {
            match rx.try_recv() {
                Ok(Ok((mut v, pass))) => {
                    v.sort();
                    self.screen = Screen::Open(Box::new(Session::new(v, pass)));
                }
                Ok(Err(e)) => self.screen = Screen::Locked { pass: String::new(), err: Some(e), show: false },
                Err(_) => ctx.request_repaint_after(Duration::from_millis(100)),
            }
        }

        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal(|ui| {
                if self.saver.pending > 0 {
                    ui.spinner();
                    ui.label(format!("{SPIN} сохранение…"));
                }
                if let Some((s, c, t)) = &self.status {
                    if t.elapsed() < Duration::from_secs(8) || *c == RED {
                        ui.add(egui::Label::new(RichText::new(s).color(*c)).truncate());
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.small(RichText::new(self.path.display().to_string()).color(N3));
                });
            });
        });

        match &self.screen {
            Screen::Locked { .. } => self.ui_locked(ui),
            Screen::Create { .. } => self.ui_create(ui),
            Screen::Unlocking(_) => {
                egui::CentralPanel::default_margins().show(ui, |ui| {
                    ui.centered_and_justified(|ui| { ui.spinner(); });
                });
            }
            Screen::Open(_) => self.ui_open(ui),
        }
    }

    fn on_exit(&mut self) {
        self.saver.finish(); // дождаться последней записи
    }
}

#[cfg(feature = "devshot")]
impl App {
    fn devshot(&mut self, ctx: &egui::Context) {
        self.frames += 1;
        ctx.request_repaint();
        if self.frames == 2 && std::env::var("PASS2FA_DEV_TAB").as_deref() == Ok("lock") {
            if let Screen::Locked { pass, show, .. } = &mut self.screen { *pass = "мой-пароль".into(); *show = true; }
        }
        if self.frames == 2 && std::env::var("PASS2FA_DEV_TAB").as_deref() != Ok("lock") {
            if let (Screen::Locked { pass, .. }, Ok(p)) = (&mut self.screen, std::env::var("PASS2FA_DEV_PASS")) {
                *pass = p;
                let p = SecretString::from(std::mem::take(pass));
                let path = self.path.clone();
                let (tx, rx) = mpsc::channel();
                std::thread::spawn(move || { let _ = tx.send(vault::load(&path, &p).map(|v| (v, p))); });
                self.screen = Screen::Unlocking(rx);
            }
        }
        if let Screen::Open(s) = &mut self.screen {
            match std::env::var("PASS2FA_DEV_TAB").as_deref() {
                Ok("logins") => s.tab = Tab::Logins,
                Ok("settings") => s.tab = Tab::Settings,
                Ok("edit") if s.edit.is_none() => s.edit = Some(Edit::Login { idx: Some(0), e: s.v.passwords[0].clone(), show: false }),
                Ok("picker") if s.picker.is_none() => s.picker = Some(Picker::open(Purpose::Import, &["csv", "json", "txt"], None)),
                Ok("editcode") if s.edit.is_none() => s.edit = Some(Edit::Code { idx: Some(0), e: s.v.codes[0].clone(), uri: String::new(), err: None, show: false }),
                _ => {}
            }
        }
        let waiting = std::env::var("PASS2FA_DEV_PASS").is_ok() && !matches!(self.screen, Screen::Open(_));
        if waiting && self.frames > 3 { self.frames = 3; }
        if self.frames == 40 {
            let out = std::env::var("PASS2FA_DEV_SHOT").unwrap_or("/tmp/pass2fa.png".into());
            let c2 = ctx.clone();
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::ScreenshotCallback::new(move |img| {
                let raw: Vec<u8> = img.pixels.iter().flat_map(|c| c.to_array()).collect();
                let _ = image::save_buffer(&out, &raw, img.size[0] as u32, img.size[1] as u32, image::ExtendedColorType::Rgba8);
                c2.send_viewport_cmd(egui::ViewportCommand::Close);
            })));
        }
    }
}

impl Session {
    fn new(v: Vault, pass: SecretString) -> Self {
        Self {
            v,
            pass,
            tab: Tab::Codes,
            filter: String::new(),
            shown: HashSet::new(),
            edit: None,
            confirm_del: None,
            gen: GenOpts::default(),
            import_path: String::new(),
            export_path: String::new(),
            export_pv_path: String::new(),
            picker: None,
            np0: String::new(),
            np1: String::new(),
            np2: String::new(),
            show_np: false,
        }
    }
    fn matches(&self, hay: &[&str]) -> bool {
        if self.filter.is_empty() { return true; }
        let f = self.filter.to_lowercase();
        hay.iter().any(|h| h.to_lowercase().contains(&f))
    }
}

// ---------- экраны ----------
impl App {
    fn ui_locked(&mut self, ui: &mut egui::Ui) {
        let mut submit = false;
        egui::CentralPanel::default_margins().show(ui, |ui| {
            let Screen::Locked { pass, err, show } = &mut self.screen else { return };
            ui.add_space(ui.available_height() * 0.3);
            ui.vertical_centered(|ui| {
                ui.heading(format!("{LOCK_KEY} Хранилище заблокировано"));
                ui.add_space(12.0);
                ui.allocate_ui_with_layout(Vec2::new(420.0, 32.0), Layout::left_to_right(Align::Center), |ui| {
                    let r = secret_field(ui, pass, show, "пароль", 300.0);
                    if !r.has_focus() && !ui.ctx().memory(|m| m.focused().is_some()) { r.request_focus(); }
                    if enter(&r) { submit = true; }
                    if arrow(ui, "Открыть (Enter)") { submit = true; }
                });
                layout_warn(ui, &[pass]);
                if let Some(e) = err { ui.colored_label(RED, e.as_str()); }
            });
        });
        if submit {
            if let Screen::Locked { pass, .. } = &mut self.screen {
                let p = SecretString::from(std::mem::take(pass));
                let path = self.path.clone();
                let (tx, rx) = mpsc::channel();
                std::thread::spawn(move || {
                    let r = vault::load(&path, &p).map(|v| (v, p));
                    let _ = tx.send(r);
                });
                self.screen = Screen::Unlocking(rx);
            }
        }
    }

    fn ui_create(&mut self, ui: &mut egui::Ui) {
        let mut create = false;
        egui::CentralPanel::default_margins().show(ui, |ui| {
            let Screen::Create { p1, p2, err, show } = &mut self.screen else { return };
            ui.add_space(ui.available_height() * 0.25);
            ui.vertical_centered(|ui| {
                ui.heading("Новое хранилище");
                ui.label(RichText::new(self.path.display().to_string()).color(N4));
                ui.add_space(12.0);
                ui.allocate_ui_with_layout(Vec2::new(420.0, 32.0), Layout::left_to_right(Align::Center), |ui| {
                    secret_field(ui, p1, show, "пароль (от 10 символов)", 300.0);
                });
                ui.allocate_ui_with_layout(Vec2::new(420.0, 32.0), Layout::left_to_right(Align::Center), |ui| {
                    let r = ui.add(egui::TextEdit::singleline(p2).password(!*show).hint_text("повтор").desired_width(300.0).font(egui::TextStyle::Monospace));
                    if enter(&r) { create = true; }
                    if arrow(ui, "Создать (Enter)") { create = true; }
                });
                layout_warn(ui, &[p1, p2]);
                ui.small("Забытый пароль не восстанавливается. Расшифровка без программы: age -d vault.age");
                if let Some(e) = err { ui.colored_label(RED, e.as_str()); }
            });
        });
        if create {
            if let Screen::Create { p1, p2, err, .. } = &mut self.screen {
                if p1 != p2 {
                    *err = Some("пароли не совпали".into());
                } else if p1.chars().count() < 10 {
                    *err = Some("короче 10 символов".into());
                } else {
                    let pass = SecretString::from(std::mem::take(p1));
                    p2.zeroize();
                    let v = Vault::default();
                    self.saver.submit(&v, &pass);
                    self.screen = Screen::Open(Box::new(Session::new(v, pass)));
                }
            }
        }
    }

    fn do_import(&mut self, p: &Path) {
        let Screen::Open(s) = &mut self.screen else {
            self.msg("Сначала открой хранилище", YEL);
            return;
        };
        match import::from_file(p) {
            Ok(v) => {
                let st = s.v.merge(v);
                self.saver.submit(&s.v, &s.pass);
                self.msg(format!("{}: {st}. Исходный файл удали сам (shred -u).", p.display()), GRN);
            }
            Err(e) => self.msg(format!("Импорт: {e}"), RED),
        }
    }

    fn ui_open(&mut self, ui: &mut egui::Ui) {
        let ctx = &ui.ctx().clone();
        let mut want_lock = false;
        let mut to_copy: Option<(String, &'static str)> = None;
        let mut dirty = false;
        let mut import_req: Option<PathBuf> = None;
        let mut message: Option<(String, Color32)> = None;
        let mut del_now: Option<(Tab, usize)> = None;

        let App { screen, ic, path: vault_path, .. } = self;
        let Screen::Open(s) = screen else { return };

        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                // узкое окно: вкладки и кнопки — только значки (подписи во всплывающих подсказках)
                let compact = ui.available_width() < 720.0;
                let (nc, np) = (s.v.codes.len(), s.v.passwords.len());
                let t1 = if compact { format!("{SHIELD} {nc}") } else { format!("{SHIELD} 2FA ({nc})") };
                let t2 = if compact { format!("{KEY} {np}") } else { format!("{KEY} Пароли ({np})") };
                let t3 = if compact { GEAR.to_string() } else { format!("{GEAR} Импорт и настройки") };
                ui.selectable_value(&mut s.tab, Tab::Codes, t1).on_hover_text("2FA");
                ui.selectable_value(&mut s.tab, Tab::Logins, t2).on_hover_text("Пароли");
                ui.selectable_value(&mut s.tab, Tab::Settings, t3).on_hover_text("Импорт и настройки");
                ui.separator();
                let right_w = if compact { 84.0 } else { 196.0 };
                let clear_w = if s.filter.is_empty() { 0.0 } else { 28.0 };
                let w = (ui.available_width() - right_w - clear_w - 12.0).clamp(60.0, 260.0);
                let r = ui.add(egui::TextEdit::singleline(&mut s.filter).hint_text(format!("{SEARCH} поиск (Ctrl+F)")).desired_width(w));
                if ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::F)) { r.request_focus(); }
                if !s.filter.is_empty() && ui.small_button(X).on_hover_text("очистить (Esc)").clicked() { s.filter.clear(); }
                if ui.input(|i| i.key_pressed(egui::Key::Escape)) && s.edit.is_none() && s.picker.is_none() { s.filter.clear(); }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let lock = if compact { LOCK.to_string() } else { format!("{LOCK} Блок") };
                    if ui.button(lock).on_hover_text("Заблокировать (Ctrl+L)").clicked() { want_lock = true; }
                    match s.tab {
                        Tab::Codes => {
                            let t = if compact { PLUS.to_string() } else { format!("{PLUS} 2FA") };
                            if ui.button(t).on_hover_text("Добавить 2FA").clicked() {
                                s.edit = Some(Edit::Code { idx: None, e: TotpEntry::new("", ""), uri: String::new(), err: None, show: true });
                            }
                        }
                        Tab::Logins => {
                            let t = if compact { PLUS.to_string() } else { format!("{PLUS} Пароль") };
                            if ui.button(t).on_hover_text("Добавить пароль").clicked() {
                                s.edit = Some(Edit::Login { idx: None, e: LoginEntry::default(), show: true });
                            }
                        }
                        Tab::Settings => {}
                    }
                });
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default_margins().frame(egui::Frame::new().fill(N0).inner_margin(10.0)).show(ui, |ui| {
            match s.tab {
                Tab::Codes => {
                    let now = totp::now();
                    let rows: Vec<usize> = (0..s.v.codes.len())
                        .filter(|&i| { let c = &s.v.codes[i]; s.matches(&[&c.name, &c.issuer]) })
                        .collect();
                    if s.v.codes.is_empty() { ui.label(format!("Пусто. «{PLUS} 2FA» или вкладка импорта.")); }
                    egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, ROW_H, rows.len(), |ui, range| {
                        column(ui, CODES_W, |ui| {
                            for k in range {
                                let i = rows[k];
                                row_frame(k).show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    ui.set_height(ROW_H - 4.0);
                                    ui.horizontal_centered(|ui| {
                                        let c = &s.v.codes[i];
                                        ic.paint(ui, c.icon_path.as_deref(), &code_cands(c), &c.name, ICON);
                                        ui.add_space(6.0);
                                        // справа фиксированно: код + шкала + 3 кнопки; в узком окне шкалы нет, код уже
                                        let narrow = ui.available_width() < 520.0;
                                        let code_w = if narrow { 116.0 } else { 130.0 };
                                        let right = code_w + if narrow { 0.0 } else { 56.0 } + 3.0 * 34.0 + 24.0;
                                        let name_w = (ui.available_width() - right).max(60.0);
                                        ui.allocate_ui_with_layout(Vec2::new(name_w, ROW_H - 8.0), Layout::left_to_right(Align::Center), |ui| {
                                            ui.set_min_width(name_w);
                                            ui.set_max_width(name_w);
                                            ui.add(egui::Label::new(RichText::new(&c.name).size(16.0)).truncate());
                                        });
                                        match totp::code_at(c, now) {
                                            Some((code, left)) => {
                                                let col = if left <= 5 { RED } else if left <= 10 { YEL } else { N8 };
                                                let r = ui
                                                    .allocate_ui_with_layout(Vec2::new(code_w, ROW_H - 8.0), Layout::left_to_right(Align::Center), |ui| {
                                            ui.set_min_width(code_w);
                                            ui.set_max_width(code_w);
                                                        ui.add(egui::Label::new(RichText::new(group(&code)).monospace().size(22.0).color(col)).sense(egui::Sense::click()))
                                                    })
                                                    .inner
                                                    .on_hover_text("клик — копировать");
                                                if !narrow {
                                                    ui.add(egui::ProgressBar::new(left as f32 / c.period.max(1) as f32).desired_width(48.0).desired_height(5.0).fill(col));
                                                    ui.add_space(8.0);
                                                }
                                                if r.clicked() || ui.button(COPY).on_hover_text("копировать код").clicked() {
                                                    to_copy = Some((code, "Код"));
                                                }
                                            }
                                            None => {
                                                ui.colored_label(RED, format!("{WARN} битый секрет"));
                                            }
                                        }
                                        if ui.button(EDIT).on_hover_text("изменить").clicked() {
                                            s.edit = Some(Edit::Code { idx: Some(i), e: s.v.codes[i].clone(), uri: String::new(), err: None, show: false });
                                        }
                                        del_button(ui, &mut s.confirm_del, &mut del_now, Tab::Codes, i);
                                    });
                                });
                            }
                        });
                    });
                }
                Tab::Logins => {
                    let rows: Vec<usize> = (0..s.v.passwords.len())
                        .filter(|&i| { let l = &s.v.passwords[i]; s.matches(&[&l.name, &l.url, &l.username, &l.note]) })
                        .collect();
                    if s.v.passwords.is_empty() { ui.label("Пусто."); }
                    egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, ROW_H, rows.len(), |ui, range| {
                        column(ui, LOGINS_W, |ui| {
                            for k in range {
                                let i = rows[k];
                                row_frame(k).show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    ui.set_height(ROW_H - 4.0);
                                    ui.horizontal_centered(|ui| {
                                        let l = &s.v.passwords[i];
                                        ic.paint(ui, l.icon.as_deref(), &login_cands(l), &l.name, ICON);
                                        ui.add_space(6.0);
                                        // справа: логин+кн, пароль+2кн, 2 кн; колонки логина/пароля сжимаются в узком окне,
                                        // в совсем узком — остаются только кнопки (текст логина/пароля скрыт)
                                        let aw = ui.available_width();
                                        let (user_w, pass_w) = if aw > 900.0 { (230.0, 150.0) } else if aw > 680.0 { (150.0, 100.0) } else { (0.0, 0.0) };
                                        let right = user_w + 34.0 + pass_w + if pass_w > 0.0 { 2.0 } else { 1.0 } * 34.0 + 2.0 * 34.0 + 40.0;
                                        let name_w = (aw - right).max(80.0);
                                        let sub = icons::host(&l.url).unwrap_or_else(|| l.url.clone());
                                        let sub = (!sub.is_empty() && sub != l.name.trim_start_matches("www.")).then_some(sub);
                                        let lay = if sub.is_some() {
                                            Layout::top_down(Align::Min).with_main_align(Align::Center)
                                        } else {
                                            Layout::left_to_right(Align::Center)
                                        };
                                        ui.allocate_ui_with_layout(Vec2::new(name_w, ROW_H - 8.0), lay, |ui| {
                                            ui.set_min_width(name_w);
                                            ui.set_max_width(name_w);
                                            ui.spacing_mut().item_spacing.y = 0.0;
                                            let r = ui.add(egui::Label::new(RichText::new(&l.name).strong().size(15.0)).truncate());
                                            if let Some(sub) = sub {
                                                ui.add(egui::Label::new(RichText::new(sub).small().color(SUB)).truncate());
                                            }
                                            if !l.note.is_empty() { r.on_hover_text(&l.note); }
                                        });
                                        if user_w > 0.0 {
                                            ui.allocate_ui_with_layout(Vec2::new(user_w, ROW_H - 8.0), Layout::left_to_right(Align::Center), |ui| {
                                                ui.set_min_width(user_w);
                                                ui.set_max_width(user_w);
                                                ui.add(egui::Label::new(RichText::new(&l.username).color(N4)).truncate());
                                            });
                                        }
                                        if ui.add_enabled(!l.username.is_empty(), egui::Button::new(format!("{USER}"))).on_hover_text(format!("копировать логин: {}", l.username)).clicked() {
                                            to_copy = Some((l.username.clone(), "Логин"));
                                        }
                                        let vis = s.shown.contains(&i);
                                        if pass_w > 0.0 {
                                            ui.allocate_ui_with_layout(Vec2::new(pass_w, ROW_H - 8.0), Layout::left_to_right(Align::Center), |ui| {
                                                ui.set_min_width(pass_w);
                                                ui.set_max_width(pass_w);
                                                let t = if vis { l.password.clone() } else { "••••••••••".into() };
                                                ui.add(egui::Label::new(RichText::new(t).monospace()).truncate());
                                            });
                                        }
                                        if pass_w > 0.0 && ui.button(if vis { EYE_OFF } else { EYE }).on_hover_text(if vis { "скрыть" } else { "показать" }).clicked() {
                                            if vis { s.shown.remove(&i); } else { s.shown.insert(i); }
                                        }
                                        if ui.button(KEY).on_hover_text("копировать пароль").clicked() {
                                            to_copy = Some((l.password.clone(), "Пароль"));
                                        }
                                        ui.add_space(8.0);
                                        if ui.button(EDIT).on_hover_text("изменить").clicked() {
                                            s.edit = Some(Edit::Login { idx: Some(i), e: s.v.passwords[i].clone(), show: false });
                                        }
                                        del_button(ui, &mut s.confirm_del, &mut del_now, Tab::Logins, i);
                                    });
                                });
                            }
                        });
                    });
                }
                Tab::Settings => {
                    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| column(ui, 860.0, |ui| {
                        ui.heading(format!("{IMPORT} Импорт"));
                        ui.label("JSON: свой старый, PassVault, Proton Authenticator, Aegis (без шифрования), 2FAS и др. CSV: Proton Pass, Chrome/Firefox, Bitwarden (CSV PassVault без заголовков — бери его JSON). Текст со строками otpauth://. Можно перетащить файл в окно.");
                        ui.horizontal(|ui| {
                            if ui.button(format!("{FOLDER_OPEN} Выбрать файл…")).clicked() {
                                s.picker = Some(Picker::open(Purpose::Import, &["csv", "json", "txt"], None));
                            }
                            ui.add(egui::TextEdit::singleline(&mut s.import_path).hint_text("или путь вручную").desired_width(420.0));
                            if ui.button(format!("{IMPORT} Импорт")).clicked() && !s.import_path.trim().is_empty() {
                                import_req = Some(PathBuf::from(expand_tilde(s.import_path.trim())));
                            }
                        });
                        ui.add_space(16.0);
                        ui.separator();
                        ui.heading(format!("{EXPORT} Экспорт 2FA для Aegis"));
                        ui.label("Открытый JSON с секретами — только для разового переноса. Сразу после импорта в Aegis удалить файл (shred -u) и на ПК, и на устройстве.");
                        ui.horizontal(|ui| {
                            if ui.button(format!("{FOLDER_OPEN} Куда сохранить…")).clicked() {
                                s.picker = Some(Picker::open(Purpose::ExportAegis, &["json"], Some("aegis-export.json")));
                            }
                            ui.add(egui::TextEdit::singleline(&mut s.export_path).hint_text("или путь вручную").desired_width(420.0));
                            if ui.button(format!("{EXPORT} Экспорт")).clicked() && !s.export_path.trim().is_empty() {
                                message = Some(export_msg(&s.v, &PathBuf::from(expand_tilde(s.export_path.trim()))));
                            }
                        });
                        ui.add_space(16.0);
                        ui.separator();
                        ui.heading(format!("{EXPORT} Экспорт паролей для PassVault"));
                        ui.label("Открытый JSON (формат PassVault). В PassVault: Импорт → PassVault JSON, пароль файла пустой. После переноса удалить файл и на ПК, и на устройстве.");
                        ui.horizontal(|ui| {
                            if ui.button(format!("{FOLDER_OPEN} Куда сохранить…")).clicked() {
                                s.picker = Some(Picker::open(Purpose::ExportPassVault, &["json"], Some("passvault-export.json")));
                            }
                            ui.add(egui::TextEdit::singleline(&mut s.export_pv_path).hint_text("или путь вручную").desired_width(420.0));
                            if ui.button(format!("{EXPORT} Экспорт")).clicked() && !s.export_pv_path.trim().is_empty() {
                                message = Some(export_pv_msg(&s.v, &PathBuf::from(expand_tilde(s.export_pv_path.trim()))));
                            }
                        });
                        ui.add_space(16.0);
                        ui.separator();
                        ui.heading(format!("{KEY} Сменить пароль хранилища"));
                        secret_field(ui, &mut s.np0, &mut s.show_np, "текущий пароль", 300.0);
                        ui.add(egui::TextEdit::singleline(&mut s.np1).password(!s.show_np).hint_text("новый пароль").desired_width(300.0).font(egui::TextStyle::Monospace));
                        let mut go = false;
                        ui.horizontal(|ui| {
                            let r = ui.add(egui::TextEdit::singleline(&mut s.np2).password(!s.show_np).hint_text("повтор").desired_width(300.0).font(egui::TextStyle::Monospace));
                            if enter(&r) { go = true; }
                            if arrow(ui, "Сменить (Enter)") { go = true; }
                        });
                        layout_warn(ui, &[&s.np1, &s.np2]);
                        if go {
                            if s.np0.as_str() != s.pass.expose_secret() {
                                message = Some(("текущий пароль неверный".into(), RED));
                            } else if s.np1 != s.np2 {
                                message = Some(("новые пароли не совпали".into(), RED));
                            } else if s.np1.chars().count() < 10 {
                                message = Some(("короче 10 символов".into(), RED));
                            } else {
                                // копия под старым паролем — обычные сохранения её не трогают
                                let keep = vault_path.with_extension(format!("age.before-passwd-{}", totp::now()));
                                let _ = std::fs::copy(&*vault_path, &keep);
                                s.pass = SecretString::from(std::mem::take(&mut s.np1));
                                s.np0.zeroize();
                                s.np2.zeroize();
                                dirty = true;
                                message = Some((format!("Пароль сменён. Копия под старым паролем: {}", keep.display()), GRN));
                            }
                        }
                        ui.add_space(16.0);
                        ui.separator();
                        ui.heading("Файлы");
                        ui.label(format!("Хранилище: {}", vault_path.display()));
                        ui.label("Рядом: vault.age.bak — предыдущая версия (после каждого сохранения).");
                        ui.label("Восстановление без программы: age -d vault.age > vault.json");
                        ui.label(format!("Автоблокировка: {} мин без действий; буфер обмена чистится через {} с.", AUTOLOCK.as_secs() / 60, CLIP_CLEAR.as_secs()));
                        ui.label("Иконки: Simple Icons (CC0), офлайн, подбираются по имени/issuer/домену. Своя — в карточке записи.");
                    }));
                }
            }
        });

        // удаление
        if let Some((tab, i)) = del_now {
            match tab {
                Tab::Codes if i < s.v.codes.len() => { s.v.codes.remove(i); }
                Tab::Logins if i < s.v.passwords.len() => { s.v.passwords.remove(i); s.shown.clear(); }
                _ => {}
            }
            s.confirm_del = None;
            dirty = true;
        }

        // окно редактирования
        if let Some(ed) = &mut s.edit {
            let mut close = false;
            let mut commit = false;
            let mut pick_icon = false;
            egui::Modal::new(egui::Id::unique("pass2fa-edit")).show(ctx, |ui| {
                ui.set_width(580.0);
                match ed {
                    Edit::Code { idx, e, uri, err, show } => {
                        ui.heading(if idx.is_some() { "Изменить 2FA" } else { "Новый 2FA" });
                        ui.label("otpauth:// (из QR) — заполнит поля ниже:");
                        if ui.add(egui::TextEdit::singleline(uri).desired_width(f32::INFINITY)).changed() {
                            if let Some(p) = totp::parse_otpauth(uri) {
                                let ip = e.icon_path.take();
                                *e = p;
                                e.icon_path = ip;
                                *err = None;
                            }
                        }
                        egui::Grid::new("ec").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                            ui.label("Имя"); ui.add(egui::TextEdit::singleline(&mut e.name).desired_width(380.0)); ui.end_row();
                            ui.label("Issuer"); ui.add(egui::TextEdit::singleline(&mut e.issuer).desired_width(380.0)); ui.end_row();
                            ui.label("Секрет (base32)"); secret_field(ui, &mut e.secret, show, "", 340.0); ui.end_row();
                            ui.label("Цифр");
                            let mut d = e.digits as i64;
                            stepper(ui, &mut d, 6, 9, 1, "");
                            e.digits = d as u32;
                            ui.end_row();
                            ui.label("Период, с");
                            let mut p = e.period as i64;
                            stepper(ui, &mut p, 10, 120, 15, " с");
                            e.period = p as u64;
                            ui.end_row();
                            ui.label("Алгоритм");
                            egui::ComboBox::from_id_salt("algo").selected_text(format!("{:?}", e.algorithm)).show_ui(ui, |ui| {
                                for a in [Algo::SHA1, Algo::SHA256, Algo::SHA512] {
                                    ui.selectable_value(&mut e.algorithm, a, format!("{a:?}"));
                                }
                            });
                            ui.end_row();
                            ui.label("Иконка");
                            pick_icon |= icon_row(ui, ic, &mut e.icon_path, &[e.issuer.as_str(), e.name.as_str()], &e.name);
                            ui.end_row();
                        });
                        if let Some(er) = err { ui.colored_label(RED, er.as_str()); }
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button(format!("{CHECK} Сохранить")).clicked() {
                                e.secret = e.secret.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
                                if e.name.trim().is_empty() { *err = Some("нужно имя".into()); }
                                else if totp::base32_decode(&e.secret).is_none() { *err = Some("секрет не base32".into()); }
                                else { commit = true; }
                            }
                            if ui.button(format!("{X} Отмена")).clicked() { close = true; }
                        });
                    }
                    Edit::Login { idx, e, show } => {
                        ui.heading(if idx.is_some() { "Изменить пароль" } else { "Новый пароль" });
                        egui::Grid::new("el").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                            ui.label("Имя"); ui.add(egui::TextEdit::singleline(&mut e.name).desired_width(380.0)); ui.end_row();
                            ui.label("URL"); ui.add(egui::TextEdit::singleline(&mut e.url).desired_width(380.0)); ui.end_row();
                            ui.label("Логин"); ui.add(egui::TextEdit::singleline(&mut e.username).desired_width(380.0)); ui.end_row();
                            ui.label("Пароль"); secret_field(ui, &mut e.password, show, "", 340.0); ui.end_row();
                            ui.label("");
                            ui.horizontal(|ui| {
                                let mut n = s.gen.len as i64;
                                stepper(ui, &mut n, 8, 128, 1, " симв.");
                                s.gen.len = n as usize;
                                ui.checkbox(&mut s.gen.upper, "A-Z");
                                ui.checkbox(&mut s.gen.digits, "0-9");
                                ui.checkbox(&mut s.gen.symbols, "!#$");
                                if ui.button(format!("{DICE} сгенерировать")).clicked() {
                                    e.password.zeroize();
                                    e.password = gen::generate(&s.gen);
                                    *show = true;
                                }
                            });
                            ui.end_row();
                            ui.label("Заметка"); ui.add(egui::TextEdit::multiline(&mut e.note).desired_rows(2).desired_width(380.0)); ui.end_row();
                            ui.label("Иконка");
                            pick_icon |= icon_row(ui, ic, &mut e.icon, &[e.url.as_str(), e.name.as_str()], &e.name);
                            ui.end_row();
                        });
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button(format!("{CHECK} Сохранить")).clicked() && !e.name.trim().is_empty() { commit = true; }
                            if ui.button(format!("{X} Отмена")).clicked() { close = true; }
                        });
                    }
                }
            });
            if pick_icon {
                s.picker = Some(Picker::open(Purpose::Icon, icons::FILE_EXTS, None));
            }
            if commit {
                match s.edit.take() {
                    Some(Edit::Code { idx, e, .. }) => match idx {
                        Some(i) if i < s.v.codes.len() => s.v.codes[i] = e.clone(),
                        _ => s.v.codes.push(e.clone()),
                    },
                    Some(Edit::Login { idx, e, .. }) => match idx {
                        Some(i) if i < s.v.passwords.len() => s.v.passwords[i] = e.clone(),
                        _ => s.v.passwords.push(e.clone()),
                    },
                    None => {}
                }
                s.v.sort();
                s.shown.clear();
                dirty = true;
            } else if close {
                s.edit = None;
            }
        }

        // выбор файла (поверх всего)
        if let Some(pk) = &mut s.picker {
            match pk.ui(ctx) {
                Outcome::None => {}
                Outcome::Cancel => s.picker = None,
                Outcome::Picked(p) => {
                    match pk.purpose {
                        Purpose::Import => {
                            s.import_path = p.display().to_string();
                            import_req = Some(p);
                        }
                        Purpose::ExportAegis => {
                            s.export_path = p.display().to_string();
                            message = Some(export_msg(&s.v, &p));
                        }
                        Purpose::ExportPassVault => {
                            s.export_pv_path = p.display().to_string();
                            message = Some(export_pv_msg(&s.v, &p));
                        }
                        Purpose::Icon => match &mut s.edit {
                            Some(Edit::Code { e, .. }) => e.icon_path = Some(p.display().to_string()),
                            Some(Edit::Login { e, .. }) => e.icon = Some(p.display().to_string()),
                            None => {}
                        },
                    }
                    s.picker = None;
                }
            }
        }

        if dirty { self.saver.submit(&s.v, &s.pass); }
        if let Some((m, c)) = message { self.msg(m, c); }
        if let Some((t, w)) = to_copy { self.copy(ctx, &t, w); }
        if let Some(p) = import_req { self.do_import(&p); }
        if want_lock { self.lock(); }
    }
}

/// Строка «Иконка» в карточке: превью, поле (пусто = авто, si:slug, путь), выбор файла, сброс.
/// Возвращает true, если нажали «выбрать файл».
fn icon_row(ui: &mut egui::Ui, ic: &mut IconCache, field: &mut Option<String>, cands: &[&str], name: &str) -> bool {
    let mut pick = false;
    ui.horizontal(|ui| {
        ic.paint(ui, field.as_deref(), cands, name, 26.0);
        let mut t = field.clone().unwrap_or_default();
        let auto = icons::find(cands).map(|s| format!("авто: si:{}", s.slug)).unwrap_or("авто: буква".into());
        if ui.add(egui::TextEdit::singleline(&mut t).hint_text(auto).desired_width(230.0)).changed() {
            *field = if t.trim().is_empty() { None } else { Some(t) };
        }
        if ui.button(format!("{IMAGE}")).on_hover_text("выбрать SVG/PNG/JPEG/ICO/WebP").clicked() { pick = true; }
        if ui.button(RESET).on_hover_text("сбросить на авто").clicked() { *field = None; }
    })
    .response
    .on_hover_text("пусто — автоподбор; si:github — из набора Simple Icons; или путь к SVG/PNG/JPEG/ICO/WebP");
    pick
}

fn export_msg(v: &Vault, p: &Path) -> (String, Color32) {
    match export::aegis_to_file(v, p) {
        Ok(n) => (format!("{n} записей 2FA → {} (открытый текст — удали после переноса)", p.display()), YEL),
        Err(e) => (format!("Экспорт: {e}"), RED),
    }
}

fn export_pv_msg(v: &Vault, p: &Path) -> (String, Color32) {
    match export::passvault_to_file(v, p) {
        Ok(n) => (format!("{n} паролей → {} (открытый текст — удали после переноса)", p.display()), YEL),
        Err(e) => (format!("Экспорт: {e}"), RED),
    }
}

/// корзина → «удалить?» — удаление в два клика.
fn del_button(ui: &mut egui::Ui, confirm: &mut Option<(Tab, usize)>, now: &mut Option<(Tab, usize)>, tab: Tab, i: usize) {
    if *confirm == Some((tab, i)) {
        if ui.button(RichText::new(CHECK).color(RED)).on_hover_text("точно удалить").clicked() { *now = Some((tab, i)); }
        if ui.button(X).on_hover_text("отмена").clicked() { *confirm = None; }
    } else if ui.button(TRASH).on_hover_text("удалить").clicked() {
        *confirm = Some((tab, i));
    }
}

fn group(code: &str) -> String {
    let mid = code.len() / 2;
    format!("{} {}", &code[..mid], &code[mid..])
}

fn expand_tilde(p: &str) -> String {
    match (p.strip_prefix("~/"), dirs::home_dir()) {
        (Some(rest), Some(h)) => h.join(rest).to_string_lossy().into_owned(),
        _ => p.to_string(),
    }
}

fn icon_font(ctx: &egui::Context) {
    let mut f = egui::FontDefinitions::default();
    f.font_data.insert(
        "phosphor".into(),
        std::sync::Arc::new(egui::FontData::from_static(include_bytes!("../assets/phosphor-subset.ttf"))),
    );
    for fam in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        f.families.entry(fam).or_default().push("phosphor".into());
    }
    ctx.set_fonts(f);
}

fn nord(ctx: &egui::Context) {
    icon_font(ctx);
    let mut v = egui::Visuals::dark();
    v.override_text_color = Some(N6);
    v.window_fill = N0;
    v.panel_fill = N1;
    v.extreme_bg_color = Color32::from_rgb(37, 42, 52); // поля ввода темнее фона
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, N2);
    v.faint_bg_color = Color32::from_rgb(52, 59, 73);
    v.widgets.inactive.bg_fill = N3;
    v.widgets.inactive.weak_bg_fill = N2;
    v.widgets.hovered.bg_fill = N10;
    v.widgets.hovered.weak_bg_fill = N10;
    v.widgets.active.bg_fill = Color32::from_rgb(129, 161, 193);
    v.selection.bg_fill = N10;
    v.hyperlink_color = N8;
    ctx.set_theme(egui::Theme::Dark);
    ctx.set_visuals_of(egui::Theme::Dark, v);
    ctx.all_styles_mut(|s| {
        s.spacing.item_spacing = egui::vec2(6.0, 4.0);
        s.spacing.button_padding = egui::vec2(8.0, 4.0);
    });
}
