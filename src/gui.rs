//! GUI на egui/eframe (wgpu + Wayland), без GTK, порталов и DBus.
use crate::filepick::{Outcome, Picker, Purpose};
use crate::gen::{self, GenOpts};
use crate::model::{Algo, LoginEntry, TotpEntry, Vault};
use crate::{export, icons, import, session, totp, vault};
use age::secrecy::SecretString;
use age::x25519::Identity;
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
    pub const OPEN_OUT: &str = "\u{e5de}";
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
            .with_inner_size(crate::state::window_size().unwrap_or([1120.0, 720.0]))
            .with_min_inner_size([520.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native("pass2fa", opts, Box::new(move |cc| Ok(Box::new(App::new(cc, path)))))
}

// ---------- фоновое сохранение (scrypt ~1 c, UI не замирает) ----------
struct Saver {
    tx: Option<Sender<(Vault, Identity)>>,
    rx: Receiver<Result<(), String>>,
    pending: usize,
    handle: Option<JoinHandle<()>>,
}

impl Saver {
    fn new(path: PathBuf) -> Self {
        let (tx, wrx) = mpsc::channel::<(Vault, Identity)>();
        let (wtx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            while let Ok(mut job) = wrx.recv() {
                let mut skipped = 0;
                while let Ok(newer) = wrx.try_recv() {
                    job = newer; // пишем только самую свежую версию
                    skipped += 1;
                }
                let r = vault::save(&path, &job.1, &job.0); // по ключу — миллисекунды
                for _ in 0..skipped {
                    let _ = wtx.send(Ok(()));
                }
                let _ = wtx.send(r);
            }
        });
        Self { tx: Some(tx), rx, pending: 0, handle: Some(handle) }
    }
    fn submit(&mut self, v: &Vault, p: &Identity) {
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
    Unlocking(Receiver<Result<(Vault, Identity), String>>),
    Open(Box<Session>),
}

#[derive(PartialEq, Clone, Copy)]
enum Tab { Codes, Logins, Settings }

enum Edit {
    Code { idx: Option<usize>, e: TotpEntry, uri: String, err: Option<String>, show: bool, sites: String },
    Login { idx: Option<usize>, e: LoginEntry, show: bool, sites: String },
}

impl Edit {
    fn code(idx: Option<usize>, e: TotpEntry, show: bool) -> Self {
        let sites = e.sites.join("\n");
        Edit::Code { idx, e, uri: String::new(), err: None, show, sites }
    }
    fn login(idx: Option<usize>, e: LoginEntry, show: bool) -> Self {
        let sites = e.extra_sites.join("\n");
        Edit::Login { idx, e, show, sites }
    }
}

/// Группы равнозначных доменов → текст для редактора (строка = группа).
fn equiv_text(v: &Vault) -> String {
    v.equiv.iter().map(|g| g.join(" ")).collect::<Vec<_>>().join("\n")
}

struct Session {
    v: Vault,
    /// ключ хранилища (мастер-пароль в памяти не держим)
    id: Identity,
    /// смена пароля идёт в фоне (scrypt ~2–3 с)
    pw_job: Option<Receiver<Result<PathBuf, String>>>,
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
    /// None — «Все группы»; Some("") — «Без группы»; Some(имя) — группа
    group_filter: Option<String>,
    /// поле «новая группа» в боковой панели
    new_group: Option<String>,
    /// переименование: (старое имя, новое)
    rename_group: Option<(String, String)>,
    /// удаление группы: ждём подтверждения
    confirm_group_del: Option<String>,
    gen_last: String,
    gen_show: bool,
    /// редактор групп равнозначных доменов (настройки)
    equiv_buf: String,
}

struct App {
    path: PathBuf,
    screen: Screen,
    saver: Saver,
    status: Option<(String, Color32, Instant)>,
    last_input: Instant,
    clip_at: Option<Instant>,
    ic: IconCache,
    /// текущий размер окна (логические пиксели) — пишется в state.json при выходе
    win_size: Option<[f32; 2]>,
    #[cfg(feature = "devshot")]
    frames: u32,
}

/// Перетаскиваемая запись пароля (индекс в vault.passwords).
struct DragLogin(usize);

enum GroupAct {
    Add(String),
    Rename(String, String),
    Remove(String),
}

/// Боковая панель групп: фильтр + цель для перетаскивания записей.
fn groups_panel(ui: &mut egui::Ui, s: &mut Session, act: &mut Option<GroupAct>, move_to: &mut Option<(usize, String)>) {
    let total = s.v.passwords.len();
    let none_cnt = s.v.passwords.iter().filter(|l| l.group.is_empty()).count();
    let groups = s.v.all_groups();
    ui.horizontal(|ui| {
        ui.label(RichText::new("Группы").strong());
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.small_button(PLUS).on_hover_text("новая группа").clicked() && s.new_group.is_none() {
                s.new_group = Some(String::new());
            }
        });
    });
    ui.add_space(4.0);
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        // элемент списка: выбор фильтра + приём перетаскивания
        let mut item = |ui: &mut egui::Ui, filter: Option<String>, label: String, count: usize, target: Option<String>| -> egui::Response {
            let selected = s.group_filter == filter;
            let hovered_drop = target.is_some() && egui::DragAndDrop::has_payload_of_type::<DragLogin>(ui.ctx());
            let atoms = (
                RichText::new(label).color(N6),
                egui::Atom::grow(),
                RichText::new(count.to_string()).small().color(SUB),
            );
            let r = ui.add(
                egui::Button::selectable(selected, atoms)
                    .frame_when_inactive(selected)
                    .min_size(Vec2::new(ui.available_width(), 26.0)),
            );
            if let (Some(t), true) = (&target, hovered_drop) {
                if r.dnd_hover_payload::<DragLogin>().is_some() {
                    ui.painter().rect_stroke(r.rect, 5.0, egui::Stroke::new(2.0, GRN), egui::StrokeKind::Inside);
                }
                if let Some(p) = r.dnd_release_payload::<DragLogin>() {
                    *move_to = Some((p.0, t.clone()));
                }
            }
            if r.clicked() { s.group_filter = filter; }
            r
        };
        item(ui, None, format!("{FOLDER_OPEN} Все группы"), total, None);
        ui.separator();
        for g in &groups {
            let cnt = s.v.passwords.iter().filter(|l| &l.group == g).count();
            let r = item(ui, Some(g.clone()), format!("{FOLDER} {g}"), cnt, Some(g.clone()));
            r.context_menu(|ui| {
                if ui.button(format!("{EDIT} Переименовать")).clicked() {
                    s.rename_group = Some((g.clone(), g.clone()));
                    ui.close();
                }
                if ui.button(format!("{TRASH} Удалить группу")).on_hover_text("записи не удаляются — уходят в «Без группы»").clicked() {
                    s.confirm_group_del = Some(g.clone());
                    ui.close();
                }
            });
        }
        item(ui, Some(String::new()), format!("{FOLDER} Без группы"), none_cnt, Some(String::new()));
        ui.add_space(8.0);
        if let Some(ng) = &mut s.new_group {
            let r = ui.add(egui::TextEdit::singleline(ng).id(egui::Id::unique("pass2fa-new-group")).hint_text("имя группы + Enter").desired_width(f32::INFINITY));
            focus_if_free(&r);
            if enter(&r) {
                if !ng.trim().is_empty() { *act = Some(GroupAct::Add(ng.trim().to_string())); }
                s.new_group = None;
            } else if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                s.new_group = None;
            }
        }
        if let Some((old, new)) = &mut s.rename_group {
            ui.label(RichText::new(format!("Переименовать «{old}»")).small().color(SUB));
            let r = ui.add(egui::TextEdit::singleline(new).id(egui::Id::unique("pass2fa-rename-group")).desired_width(f32::INFINITY));
            focus_if_free(&r);
            if enter(&r) {
                if !new.trim().is_empty() && new.trim() != old { *act = Some(GroupAct::Rename(old.clone(), new.trim().to_string())); }
                s.rename_group = None;
            } else if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                s.rename_group = None;
            }
        }
        if let Some(g) = s.confirm_group_del.clone() {
            ui.colored_label(YEL, format!("Удалить группу «{g}»? Записи останутся."));
            ui.horizontal(|ui| {
                if ui.button(RichText::new(format!("{CHECK} удалить")).color(RED)).clicked() {
                    *act = Some(GroupAct::Remove(g.clone()));
                    s.confirm_group_del = None;
                }
                if ui.button(X).clicked() { s.confirm_group_del = None; }
            });
        }
        ui.add_space(10.0);
        ui.label(RichText::new(format!("Перетащи запись за иконку/имя на группу или ПКМ {ARROW_RIGHT} «Переместить в группу».")).small().color(SUB));
    });
}

const FORM_LABEL_W: f32 = 120.0;

/// Строка формы: в широком окне подпись слева фиксированной ширины, в узком — над полем.
fn form_row(ui: &mut egui::Ui, narrow: bool, label: &str, add: impl FnOnce(&mut egui::Ui)) {
    if narrow {
        if !label.is_empty() {
            ui.label(RichText::new(label).small().color(SUB));
        }
        add(ui);
        ui.add_space(6.0);
    } else {
        ui.horizontal(|ui| {
            ui.allocate_ui_with_layout(Vec2::new(FORM_LABEL_W, 26.0), Layout::left_to_right(Align::Center), |ui| {
                ui.set_min_width(FORM_LABEL_W);
                ui.label(label);
            });
            add(ui);
        });
        ui.add_space(4.0);
    }
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
/// Адрес для открытия: URL записи, иначе имя, если похоже на домен; без схемы — https://.
fn site_url(url: &str, name: &str) -> Option<String> {
    let u = url.trim();
    let n = name.trim();
    let raw = if !u.is_empty() { u } else if n.contains('.') && !n.contains(' ') && !n.contains('@') { n } else { return None };
    crate::native::endpoint(raw)?;
    Some(if raw.contains("://") { raw.to_string() } else { format!("https://{raw}") })
}

/// Открыть адрес в браузере по умолчанию: $BROWSER, затем xdg-open, затем librewolf/firefox. Только http(s).
fn open_in_browser(url: &str) -> Result<(), String> {
    let low = url.to_lowercase();
    if !(low.starts_with("https://") || low.starts_with("http://")) {
        return Err(format!("не http(s): {url}"));
    }
    let mut cands: Vec<String> = std::env::var("BROWSER").map(|b| b.split(':').filter(|x| !x.is_empty()).map(String::from).collect()).unwrap_or_default();
    cands.extend(["xdg-open", "librewolf", "firefox"].map(String::from));
    for c in cands {
        if let Ok(mut ch) = std::process::Command::new(&c)
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            std::thread::spawn(move || { let _ = ch.wait(); }); // без зомби
            return Ok(());
        }
    }
    Err("не нашёл браузер ($BROWSER, xdg-open, librewolf, firefox)".into())
}

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

/// Enter в однострочном поле: поле в фокусе (или только что его отдало) и в этом кадре нажат Enter.
fn enter(r: &egui::Response) -> bool {
    (r.has_focus() || r.lost_focus()) && r.ctx.input(|i| i.key_pressed(egui::Key::Enter))
}

/// Фокус в поле — только если сейчас ничего не в фокусе (иначе поле каждый кадр перехватывает фокус
/// и Enter теряется).
fn focus_if_free(r: &egui::Response) {
    if !r.has_focus() && r.ctx.memory(|m| m.focused().is_none()) {
        r.request_focus();
    }
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
            // сессия уже открыта (браузер/другое окно) — не спрашиваем пароль повторно
            match session::identity() {
                Some(id) => {
                    let (tx, rx) = mpsc::channel();
                    let path2 = path.clone();
                    std::thread::spawn(move || {
                        let _ = tx.send(vault::load_with(&path2, &id).map(|v| (v, id)));
                    });
                    Screen::Unlocking(rx)
                }
                None => Screen::Locked { pass: String::new(), err: None, show: false },
            }
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
            win_size: None,
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

    /// full = true: закрыть и общую сессию (браузер, CLI); false — только окно (автоблокировка по простою).
    fn lock(&mut self, full: bool) {
        if full {
            session::clear();
        }
        if let Screen::Open(s) = &mut self.screen {
            s.np0.zeroize();
            s.np1.zeroize();
            s.np2.zeroize();
            s.gen_last.zeroize();
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
        // размер окна: точки egui × zoom = логические пиксели (в них же его задаёт with_inner_size)
        // (inner_rect на Wayland пустой — позиция окна неизвестна; viewport_rect позиции не требует)
        let r = ctx.viewport_rect();
        if r.width() > 1.0 {
            let z = ctx.zoom_factor();
            self.win_size = Some([r.width() * z, r.height() * z]);
        }
        let active = ctx.input(|i| !i.events.is_empty() || i.pointer.is_moving());
        if active { self.last_input = Instant::now(); }
        if matches!(self.screen, Screen::Open(_)) {
            let hotkey = ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::L));
            if hotkey {
                self.lock(true);
                self.msg("Заблокировано (окно и браузер)", N8);
            } else if self.last_input.elapsed() > AUTOLOCK {
                self.lock(false);
                self.msg(format!("Окно заблокировано по простою; браузер — по своему таймауту {} мин", session::TTL_SECS / 60), N8);
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
                Ok(Ok((mut v, id))) => {
                    v.sort();
                    self.screen = Screen::Open(Box::new(Session::new(v, id)));
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
        if let Some(sz) = self.win_size {
            crate::state::set_window_size(sz);
        }
    }

    /// devshot: имитация клавиатуры (для проверки ввода групп и т.п.)
    #[cfg(feature = "devshot")]
    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw: &mut egui::RawInput) {
        if std::env::var("PASS2FA_DEV_TAB").as_deref() != Ok("newgroup") || !matches!(self.screen, Screen::Open(_)) {
            return;
        }
        raw.focused = true; // в headless-композиторе окно не получает фокус ОС
        let key = |k, pressed| egui::Event::Key { key: k, physical_key: None, pressed, repeat: false, modifiers: Default::default() };
        match self.frames {
            15 => raw.events.push(egui::Event::Text("Новая группа".into())),
            20 => raw.events.push(key(egui::Key::Enter, true)),
            21 => raw.events.push(key(egui::Key::Enter, false)),
            _ => {}
        }
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
                std::thread::spawn(move || { let _ = tx.send(vault::unlock(&path, &p)); });
                self.screen = Screen::Unlocking(rx);
            }
        }
        if let Screen::Open(s) = &mut self.screen {
            match std::env::var("PASS2FA_DEV_TAB").as_deref() {
                Ok("logins") => s.tab = Tab::Logins,
                Ok("settings") => s.tab = Tab::Settings,
                Ok("edit" | "editnarrow") if s.edit.is_none() => s.edit = Some(Edit::login(Some(0), s.v.passwords[0].clone(), false)),
                Ok("picker") if s.picker.is_none() => s.picker = Some(Picker::open(Purpose::Import, &["csv", "json", "txt"], None)),
                Ok("gen") if self.frames == 8 => {
                    s.tab = Tab::Logins;
                    s.gen_last = gen::generate(&s.gen);
                }
                Ok("newgroup") if self.frames == 8 => {
                    s.tab = Tab::Logins;
                    s.new_group = Some(String::new());
                }
                Ok("editcode") if s.edit.is_none() => s.edit = Some(Edit::code(Some(0), s.v.codes[0].clone(), false)),
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
    fn new(v: Vault, id: Identity) -> Self {
        Self {
            v,
            id,
            pw_job: None,
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
            group_filter: None,
            new_group: None,
            rename_group: None,
            confirm_group_del: None,
            gen_last: String::new(),
            gen_show: false,
            equiv_buf: String::new(),
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
                    let r = vault::unlock(&path, &p).map(|(v, id)| {
                        let _ = session::publish(&id); // общая разблокировка для браузера/CLI
                        (v, id)
                    });
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
                    let path = self.path.clone();
                    let (tx, rx) = mpsc::channel();
                    std::thread::spawn(move || {
                        let v = Vault::default();
                        let r = vault::create(&path, &pass, &v).map(|id| {
                            let _ = session::publish(&id);
                            (v, id)
                        });
                        let _ = tx.send(r);
                    });
                    self.screen = Screen::Unlocking(rx);
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
                self.saver.submit(&s.v, &s.id);
                self.msg(format!("{}: {st}. Исходный файл удали сам (shred -u).", p.display()), GRN);
            }
            Err(e) => self.msg(format!("Импорт: {e}"), RED),
        }
    }

    fn ui_open(&mut self, ui: &mut egui::Ui) {
        let ctx = &ui.ctx().clone();
        let mut want_lock = false;
        let mut to_copy: Option<(String, &'static str)> = None;
        let mut open_url: Option<String> = None;
        let mut dirty = false;
        let mut import_req: Option<PathBuf> = None;
        let mut message: Option<(String, Color32)> = None;
        let mut del_now: Option<(Tab, usize)> = None;

        let App { screen, ic, path: vault_path, .. } = self;
        let Screen::Open(s) = screen else { return };
        if let Some(rx) = &s.pw_job {
            match rx.try_recv() {
                Ok(Ok(keep)) => {
                    s.pw_job = None;
                    message = Some((format!("Пароль сменён. Ключ под старым паролем сохранён: {}", keep.display()), GRN));
                }
                Ok(Err(e)) => {
                    s.pw_job = None;
                    message = Some((format!("Пароль не сменён: {e}"), RED));
                }
                Err(_) => ctx.request_repaint_after(Duration::from_millis(150)),
            }
        }

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
                    if ui.button(lock).on_hover_text("Заблокировать окно и браузер (Ctrl+L)").clicked() { want_lock = true; }
                    match s.tab {
                        Tab::Codes => {
                            let t = if compact { PLUS.to_string() } else { format!("{PLUS} 2FA") };
                            if ui.button(t).on_hover_text("Добавить 2FA").clicked() {
                                s.edit = Some(Edit::code(None, TotpEntry::new("", ""), true));
                            }
                        }
                        Tab::Logins => {
                            let t = if compact { PLUS.to_string() } else { format!("{PLUS} Пароль") };
                            if ui.button(t).on_hover_text("Добавить пароль").clicked() {
                                let mut e = LoginEntry::default();
                                e.group = s.group_filter.clone().unwrap_or_default();
                                s.edit = Some(Edit::login(None, e, true));
                            }
                        }
                        Tab::Settings => {}
                    }
                });
            });
            ui.add_space(4.0);
        });

        // --- группы слева (только на вкладке паролей и если окно не узкое)
        let mut group_act: Option<GroupAct> = None;
        let mut move_to: Option<(usize, String)> = None;
        let narrow_groups = ui.available_width() < 640.0;
        if s.tab == Tab::Logins && !narrow_groups {
            egui::Panel::left("groups")
                .resizable(true)
                .default_size(210.0)
                .size_range(150.0..=360.0)
                .frame(egui::Frame::new().fill(N1).inner_margin(egui::Margin::symmetric(8, 10)))
                .show(ui, |ui| {
                    groups_panel(ui, s, &mut group_act, &mut move_to);
                });
        }

        egui::CentralPanel::default_margins().frame(egui::Frame::new().fill(N0).inner_margin(10.0)).show(ui, |ui| {
            match s.tab {
                Tab::Codes => {
                    let now = totp::now();
                    let rows: Vec<usize> = (0..s.v.codes.len())
                        .filter(|&i| { let c = &s.v.codes[i]; s.matches(&[&c.name, &c.issuer, &c.sites.join(" ")]) })
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
                                            s.edit = Some(Edit::code(Some(i), s.v.codes[i].clone(), false));
                                        }
                                        del_button(ui, &mut s.confirm_del, &mut del_now, Tab::Codes, i);
                                    });
                                });
                            }
                        });
                    });
                }
                Tab::Logins => {
                    // --- генератор: одна кнопка — новый пароль сразу в буфер
                    column(ui, LOGINS_W, |ui| {
                        ui.horizontal(|ui| {
                            if ui.add(egui::Button::new(RichText::new(format!("{DICE} Сгенерировать в буфер")).strong()).fill(N10))
                                .on_hover_text("новый пароль сразу копируется (Ctrl+G)").clicked()
                                || ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::G))
                            {
                                s.gen_last.zeroize();
                                s.gen_last = gen::generate(&s.gen);
                                to_copy = Some((s.gen_last.clone(), "Новый пароль"));
                            }
                            let mut n = s.gen.len as i64;
                            stepper(ui, &mut n, 8, 128, 1, " симв.");
                            s.gen.len = n as usize;
                            ui.checkbox(&mut s.gen.upper, "A-Z");
                            ui.checkbox(&mut s.gen.digits, "0-9");
                            ui.checkbox(&mut s.gen.symbols, "!#$");
                        });
                        // результат — отдельной строкой под кнопками, чтобы не обрезался в узком окне
                        ui.horizontal(|ui| {
                            if !s.gen_last.is_empty() {
                                ui.label(RichText::new("последний:").small().color(SUB));
                                let t = if s.gen_show { s.gen_last.clone() } else { "•".repeat(s.gen_last.chars().count().min(24)) };
                                ui.add(egui::Label::new(RichText::new(t).monospace().color(N8)).truncate());
                                if ui.small_button(if s.gen_show { EYE_OFF } else { EYE }).clicked() { s.gen_show = !s.gen_show; }
                                if ui.small_button(COPY).on_hover_text("скопировать ещё раз").clicked() {
                                    to_copy = Some((s.gen_last.clone(), "Пароль"));
                                }
                                if ui.small_button(PLUS).on_hover_text("создать запись с этим паролем").clicked() {
                                    let mut e = LoginEntry::default();
                                    e.password = s.gen_last.clone();
                                    e.group = s.group_filter.clone().unwrap_or_default();
                                    s.edit = Some(Edit::login(None, e, true));
                                }
                            }
                        });
                        if narrow_groups {
                            // узкое окно: группы — выпадающим списком вместо боковой панели
                            ui.horizontal(|ui| {
                                ui.label(format!("{FOLDER}"));
                                let cur = match &s.group_filter { None => "Все группы".to_string(), Some(g) if g.is_empty() => "Без группы".into(), Some(g) => g.clone() };
                                egui::ComboBox::from_id_salt("grp_combo").selected_text(cur).show_ui(ui, |ui| {
                                    ui.selectable_value(&mut s.group_filter, None, "Все группы");
                                    for g in s.v.all_groups() {
                                        ui.selectable_value(&mut s.group_filter, Some(g.clone()), g);
                                    }
                                    ui.selectable_value(&mut s.group_filter, Some(String::new()), "Без группы");
                                });
                            });
                        }
                        ui.add_space(4.0);
                    });
                    let rows: Vec<usize> = (0..s.v.passwords.len())
                        .filter(|&i| {
                            let l = &s.v.passwords[i];
                            s.group_filter.as_ref().is_none_or(|g| &l.group == g)
                                && s.matches(&[&l.name, &l.url, &l.username, &l.note, &l.group, &l.extra_sites.join(" ")])
                        })
                        .collect();
                    if rows.is_empty() {
                        ui.label(if s.v.passwords.is_empty() { "Пусто." } else { "В этой группе ничего нет — перетащи сюда записи или выбери «Все группы»." });
                    }
                    let groups = s.v.all_groups();
                    egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, ROW_H, rows.len(), |ui, range| {
                        column(ui, LOGINS_W, |ui| {
                            for k in range {
                                let i = rows[k];
                                row_frame(k).show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    ui.set_height(ROW_H - 4.0);
                                    ui.horizontal_centered(|ui| {
                                        let l = &s.v.passwords[i];
                                        let icon_rect = ui.cursor();
                                        ic.paint(ui, l.icon.as_deref(), &login_cands(l), &l.name, ICON);
                                        ui.add_space(6.0);
                                        // справа: логин+кн, пароль+2кн, 2 кн; колонки логина/пароля сжимаются в узком окне,
                                        // в совсем узком — остаются только кнопки (текст логина/пароля скрыт)
                                        let aw = ui.available_width();
                                        let (user_w, pass_w) = if aw > 900.0 { (230.0, 150.0) } else if aw > 680.0 { (150.0, 100.0) } else { (0.0, 0.0) };
                                        let right = 34.0 + user_w + 34.0 + pass_w + if pass_w > 0.0 { 2.0 } else { 1.0 } * 34.0 + 2.0 * 34.0 + 40.0;
                                        let name_w = (aw - right).max(80.0);
                                        let sub = icons::host(&l.url).unwrap_or_else(|| l.url.clone());
                                        let sub = (!sub.is_empty() && sub != l.name.trim_start_matches("www.")).then_some(sub);
                                        // в «Все группы» подписываем группу записи
                                        let sub = match (&s.group_filter, l.group.is_empty(), sub) {
                                            (None, false, Some(h)) => Some(format!("{h} · {FOLDER} {}", l.group)),
                                            (None, false, None) => Some(format!("{FOLDER} {}", l.group)),
                                            (_, _, x) => x,
                                        };
                                        let lay = if sub.is_some() {
                                            Layout::top_down(Align::Min).with_main_align(Align::Center)
                                        } else {
                                            Layout::left_to_right(Align::Center)
                                        };
                                        let name_resp = ui.allocate_ui_with_layout(Vec2::new(name_w, ROW_H - 8.0), lay, |ui| {
                                            ui.set_min_width(name_w);
                                            ui.set_max_width(name_w);
                                            ui.spacing_mut().item_spacing.y = 0.0;
                                            ui.add(egui::Label::new(RichText::new(&l.name).strong().size(15.0)).truncate());
                                            if let Some(sub) = sub {
                                                ui.add(egui::Label::new(RichText::new(sub).small().color(SUB)).truncate());
                                            }
                                        }).response;
                                        // за иконку и имя запись можно тащить на группу; ПКМ — меню; двойной клик — изменить
                                        let grab = icon_rect.min.x;
                                        let handle = egui::Rect::from_min_max(egui::pos2(grab, name_resp.rect.min.y), name_resp.rect.max);
                                        let h = ui.interact(handle, egui::Id::unique(("pass2fa-row", i)), egui::Sense::click_and_drag());
                                        let h = if l.note.is_empty() { h } else { h.on_hover_text(&l.note) };
                                        h.dnd_set_drag_payload(DragLogin(i));
                                        if h.hovered() { ui.ctx().set_cursor_icon(egui::CursorIcon::Grab); }
                                        if h.double_clicked() {
                                            s.edit = Some(Edit::login(Some(i), s.v.passwords[i].clone(), false));
                                        }
                                        let cur_group = l.group.clone();
                                        h.context_menu(|ui| {
                                            ui.label(RichText::new("Переместить в группу").small().color(SUB));
                                            for g in &groups {
                                                if ui.add_enabled(g != &cur_group, egui::Button::new(format!("{FOLDER} {g}"))).clicked() {
                                                    move_to = Some((i, g.clone()));
                                                    ui.close();
                                                }
                                            }
                                            if ui.add_enabled(!cur_group.is_empty(), egui::Button::new("Без группы")).clicked() {
                                                move_to = Some((i, String::new()));
                                                ui.close();
                                            }
                                            ui.separator();
                                            if ui.button(format!("{PLUS} Новая группа…")).clicked() {
                                                s.new_group = Some(String::new());
                                                ui.close();
                                            }
                                        });
                                        let l = &s.v.passwords[i];
                                        let site = site_url(&l.url, &l.name);
                                        let r = ui.add_enabled(site.is_some(), egui::Button::new(OPEN_OUT));
                                        if let Some(u) = &site {
                                            if r.on_hover_text(format!("открыть в браузере: {u}")).clicked() {
                                                open_url = Some(u.clone());
                                            }
                                        }
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
                                            s.edit = Some(Edit::login(Some(i), s.v.passwords[i].clone(), false));
                                        }
                                        del_button(ui, &mut s.confirm_del, &mut del_now, Tab::Logins, i);
                                    });
                                });
                            }
                        });
                    });
                    // что тащим — подпись у курсора
                    if let (Some(p), Some(pos)) = (egui::DragAndDrop::payload::<DragLogin>(ui.ctx()), ui.ctx().pointer_latest_pos()) {
                        if let Some(l) = s.v.passwords.get(p.0) {
                            egui::Area::new(egui::Id::unique("pass2fa-drag-preview"))
                                .order(egui::Order::Tooltip)
                                .fixed_pos(pos + Vec2::new(14.0, 10.0))
                                .interactable(false)
                                .show(ui.ctx(), |ui| {
                                    egui::Frame::popup(ui.style()).show(ui, |ui| {
                                        ui.label(format!("{KEY} {}  {ARROW_RIGHT}  {FOLDER} группа", l.name));
                                    });
                                });
                        }
                    }
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
                        ui.label(format!("Открытый JSON (формат PassVault). В PassVault: Импорт {ARROW_RIGHT} PassVault JSON, пароль файла пустой. После переноса удалить файл и на ПК, и на устройстве."));
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
                            if s.pw_job.is_some() {
                                message = Some(("смена пароля уже идёт…".into(), YEL));
                            } else if s.np1 != s.np2 {
                                message = Some(("новые пароли не совпали".into(), RED));
                            } else if s.np1.chars().count() < 10 {
                                message = Some(("короче 10 символов".into(), RED));
                            } else {
                                // перешифровывается только ключ-файл (данные не трогаем); scrypt — в фоне
                                let old = SecretString::from(std::mem::take(&mut s.np0));
                                let new = SecretString::from(std::mem::take(&mut s.np1));
                                s.np2.zeroize();
                                let path = vault_path.clone();
                                let (tx, rx) = mpsc::channel();
                                std::thread::spawn(move || { let _ = tx.send(vault::change_password(&path, &old, &new)); });
                                s.pw_job = Some(rx);
                                message = Some(("меняю пароль…".into(), YEL));
                            }
                        }
                        ui.add_space(16.0);
                        ui.separator();
                        ui.heading(format!("{GLOBE} Равнозначные домены"));
                        ui.label("Один сервис на разных доменах. Строка — группа, домены через пробел. Пароль с адресом proton.me подставится и на protonmail.com; 2FA с Issuer «Proton» — на обоих.");
                        if s.equiv_buf.is_empty() { s.equiv_buf = equiv_text(&s.v); }
                        ui.add(egui::TextEdit::multiline(&mut s.equiv_buf).desired_rows(4).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace));
                        ui.horizontal(|ui| {
                            if ui.button(format!("{CHECK} Применить")).clicked() {
                                s.v.equiv = crate::native::parse_equiv(&s.equiv_buf);
                                s.equiv_buf = equiv_text(&s.v);
                                dirty = true;
                                message = Some((format!("групп доменов: {}", s.v.equiv.len()), GRN));
                            }
                            if ui.button("По умолчанию").clicked() {
                                s.v.equiv = crate::model::default_equiv();
                                s.equiv_buf = equiv_text(&s.v);
                                dirty = true;
                            }
                        });
                        ui.add_space(16.0);
                        ui.separator();
                        ui.heading("Файлы");
                        ui.label(format!("Хранилище: {}", vault_path.display()));
                        ui.label("Рядом: vault.age.bak — предыдущая версия (после каждого сохранения).");
                        ui.label(format!("Ключ: {} — зашифрован паролем. В бэкап — ОБА файла.", vault::key_path(vault_path).display()));
                        ui.label("Восстановление без программы: age -d -i vault.key.age vault.age > vault.json");
                        ui.label(format!("Автоблокировка: {} мин без действий; буфер обмена чистится через {} с.", AUTOLOCK.as_secs() / 60, CLIP_CLEAR.as_secs()));
                        ui.label("Иконки: Simple Icons (CC0), офлайн, подбираются по имени/issuer/домену. Своя — в карточке записи.");
                        ui.add_space(16.0);
                        ui.separator();
                        ui.heading(format!("{GLOBE} Браузер"));
                        ui.label(format!(
                            "Разблокировка общая: окно, браузерное расширение и CLI. Держится {} мин без обращений (kernel keyring, на диск не пишется). «Блок»/Ctrl+L закрывают всё; автоблокировка по простою — только окно.",
                            session::TTL_SECS / 60
                        ));
                        ui.label(format!("Установка хоста: pass2fa install-browser · id расширения: Firefox/LibreWolf {}, Chromium {}", crate::native::FIREFOX_EXT_ID, crate::native::CHROMIUM_EXT_ID));
                    }));
                }
            }
        });

        // группы: перенос записи и действия над группами
        if let Some((i, g)) = move_to {
            let name = s.v.passwords.get_mut(i).filter(|l| l.group != g).map(|l| {
                l.group = g.clone();
                l.name.clone()
            });
            if let Some(name) = name {
                s.v.add_group(&g);
                dirty = true;
                message = Some((format!("{name} {ARROW_RIGHT} {}", if g.is_empty() { "Без группы".into() } else { g }), GRN));
            }
        }
        match group_act {
            Some(GroupAct::Add(g)) => { s.v.add_group(&g); dirty = true; }
            Some(GroupAct::Rename(o, n)) => {
                s.v.rename_group(&o, &n);
                if s.group_filter.as_deref() == Some(o.as_str()) { s.group_filter = Some(n.trim().to_string()); }
                dirty = true;
            }
            Some(GroupAct::Remove(g)) => {
                s.v.remove_group(&g);
                if s.group_filter.as_deref() == Some(g.as_str()) { s.group_filter = None; }
                dirty = true;
                message = Some((format!("Группа «{g}» удалена, записи — в «Без группы»"), YEL));
            }
            None => {}
        }

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
            let mut save_btn = false;
            // ширина формы — по окну: в узком окне подписи над полями, поля на всю ширину
            let mw = (ctx.content_rect().width() - 40.0).clamp(280.0, 580.0);
            let narrow = mw < 500.0;
            let fw = if narrow { mw } else { mw - FORM_LABEL_W - 8.0 };
            egui::Modal::new(egui::Id::unique("pass2fa-edit")).show(ctx, |ui| {
                ui.set_width(mw);
                egui::ScrollArea::vertical().max_height((ctx.content_rect().height() - 110.0).max(120.0)).show(ui, |ui| {
                match ed {
                    Edit::Code { idx, e, uri, err, show, sites } => {
                        ui.heading(if idx.is_some() { "Изменить 2FA" } else { "Новый 2FA" });
                        ui.label("otpauth:// (из QR) — заполнит поля ниже:");
                        if ui.add(egui::TextEdit::singleline(uri).desired_width(mw)).changed() {
                            if let Some(p) = totp::parse_otpauth(uri) {
                                let ip = e.icon_path.take();
                                *e = p;
                                e.icon_path = ip;
                                *err = None;
                            }
                        }
                        ui.add_space(4.0);
                        form_row(ui, narrow, "Имя", |ui| { ui.add(egui::TextEdit::singleline(&mut e.name).desired_width(fw)); });
                        form_row(ui, narrow, "Issuer", |ui| { ui.add(egui::TextEdit::singleline(&mut e.issuer).desired_width(fw)); });
                        form_row(ui, narrow, "Сайты", |ui| {
                            ui.add(egui::TextEdit::multiline(sites).desired_rows(2).hint_text("по одному на строку: https://account.proton.me\nпусто — по Issuer").desired_width(fw));
                        });
                        form_row(ui, narrow, "Секрет (base32)", |ui| { secret_field(ui, &mut e.secret, show, "", fw - 44.0); });
                        form_row(ui, narrow, "Цифр", |ui| {
                            let mut d = e.digits as i64;
                            stepper(ui, &mut d, 6, 9, 1, "");
                            e.digits = d as u32;
                        });
                        form_row(ui, narrow, "Период, с", |ui| {
                            let mut p = e.period as i64;
                            stepper(ui, &mut p, 10, 120, 15, " с");
                            e.period = p as u64;
                        });
                        form_row(ui, narrow, "Алгоритм", |ui| {
                            egui::ComboBox::from_id_salt("algo").selected_text(format!("{:?}", e.algorithm)).show_ui(ui, |ui| {
                                for a in [Algo::SHA1, Algo::SHA256, Algo::SHA512] {
                                    ui.selectable_value(&mut e.algorithm, a, format!("{a:?}"));
                                }
                            });
                        });
                        form_row(ui, narrow, "Иконка", |ui| {
                            pick_icon |= icon_row(ui, ic, &mut e.icon_path, &[e.issuer.as_str(), e.name.as_str()], &e.name, fw);
                        });
                        if let Some(er) = err { ui.colored_label(RED, er.as_str()); }
                    }
                    Edit::Login { idx, e, show, sites } => {
                        ui.heading(if idx.is_some() { "Изменить пароль" } else { "Новый пароль" });
                        ui.add_space(4.0);
                        form_row(ui, narrow, "Имя", |ui| { ui.add(egui::TextEdit::singleline(&mut e.name).desired_width(fw)); });
                        form_row(ui, narrow, "URL", |ui| {
                            ui.horizontal(|ui| {
                                ui.add(egui::TextEdit::singleline(&mut e.url).hint_text("https://…").desired_width(fw - 80.0));
                                let site = site_url(&e.url, "");
                                if ui.add_enabled(!e.url.trim().is_empty(), egui::Button::new(COPY)).on_hover_text("копировать адрес").clicked() {
                                    to_copy = Some((e.url.trim().to_string(), "Адрес"));
                                }
                                if ui.add_enabled(site.is_some(), egui::Button::new(OPEN_OUT)).on_hover_text("открыть в браузере").clicked() {
                                    open_url = site;
                                }
                            });
                        });
                        form_row(ui, narrow, "Доп. сайты", |ui| {
                            ui.add(egui::TextEdit::multiline(sites).desired_rows(1).hint_text("ещё адреса, по одному на строку").desired_width(fw));
                        });
                        form_row(ui, narrow, "Логин", |ui| { ui.add(egui::TextEdit::singleline(&mut e.username).desired_width(fw)); });
                        form_row(ui, narrow, "Пароль", |ui| { secret_field(ui, &mut e.password, show, "", fw - 44.0); });
                        form_row(ui, narrow, "", |ui| {
                            // генератор переносится на новую строку, если не влезает
                            ui.horizontal_wrapped(|ui| {
                                ui.set_max_width(fw);
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
                        });
                        form_row(ui, narrow, "Группа", |ui| {
                            ui.horizontal(|ui| {
                                ui.add(egui::TextEdit::singleline(&mut e.group).hint_text("без группы").desired_width(fw - 64.0));
                                egui::ComboBox::from_id_salt("edit_grp").selected_text(FOLDER).width(40.0).show_ui(ui, |ui| {
                                    if ui.selectable_label(e.group.is_empty(), "Без группы").clicked() { e.group.clear(); }
                                    for g in s.v.all_groups() {
                                        let sel = e.group == g;
                                        if ui.selectable_label(sel, &g).clicked() { e.group = g; }
                                    }
                                });
                            });
                        });
                        form_row(ui, narrow, "Заметка", |ui| { ui.add(egui::TextEdit::multiline(&mut e.note).desired_rows(2).desired_width(fw)); });
                        form_row(ui, narrow, "Иконка", |ui| {
                            pick_icon |= icon_row(ui, ic, &mut e.icon, &[e.url.as_str(), e.name.as_str()], &e.name, fw);
                        });
                    }
                }
                });
                // кнопки — вне прокрутки, всегда видны
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button(format!("{CHECK} Сохранить")).clicked() { save_btn = true; }
                    if ui.button(format!("{X} Отмена")).clicked() { close = true; }
                });
            });
            if save_btn {
                match ed {
                    Edit::Code { e, err, sites, .. } => {
                        e.sites = crate::native::parse_sites(sites);
                        e.secret = e.secret.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
                        if e.name.trim().is_empty() { *err = Some("нужно имя".into()); }
                        else if totp::base32_decode(&e.secret).is_none() { *err = Some("секрет не base32".into()); }
                        else { commit = true; }
                    }
                    Edit::Login { e, sites, .. } => {
                        e.extra_sites = crate::native::parse_sites(sites);
                        if !e.name.trim().is_empty() { commit = true; }
                    }
                }
            }
            if pick_icon {
                s.picker = Some(Picker::open(Purpose::Icon, icons::FILE_EXTS, None));
            }
            if commit {
                match s.edit.take() {
                    Some(Edit::Code { idx, e, .. }) => match idx {
                        Some(i) if i < s.v.codes.len() => s.v.codes[i] = e.clone(),
                        _ => s.v.codes.push(e.clone()),
                    },
                    Some(Edit::Login { idx, e, .. }) => {
                        s.v.add_group(&e.group);
                        match idx {
                            Some(i) if i < s.v.passwords.len() => s.v.passwords[i] = e.clone(),
                            _ => s.v.passwords.push(e.clone()),
                        }
                    }
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

        if dirty { self.saver.submit(&s.v, &s.id); }
        if let Some((m, c)) = message { self.msg(m, c); }
        if let Some((t, w)) = to_copy { self.copy(ctx, &t, w); }
        if let Some(u) = open_url {
            match open_in_browser(&u) {
                Ok(()) => self.msg(format!("{OPEN_OUT} {u}"), GRN),
                Err(e) => self.msg(e, RED),
            }
        }
        if let Some(p) = import_req { self.do_import(&p); }
        if want_lock { self.lock(true); }
    }
}

/// Строка «Иконка» в карточке: превью, поле (пусто = авто, si:slug, путь), выбор файла, сброс.
/// Возвращает true, если нажали «выбрать файл».
fn icon_row(ui: &mut egui::Ui, ic: &mut IconCache, field: &mut Option<String>, cands: &[&str], name: &str, width: f32) -> bool {
    let mut pick = false;
    ui.horizontal(|ui| {
        ic.paint(ui, field.as_deref(), cands, name, 26.0);
        let mut t = field.clone().unwrap_or_default();
        let auto = icons::find(cands).map(|s| format!("авто: si:{}", s.slug)).unwrap_or("авто: буква".into());
        if ui.add(egui::TextEdit::singleline(&mut t).hint_text(auto).desired_width((width - 26.0 - 2.0 * 36.0 - 20.0).max(80.0))).changed() {
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
        Ok(n) => (format!("{n} записей 2FA {ARROW_RIGHT} {} (открытый текст — удали после переноса)", p.display()), YEL),
        Err(e) => (format!("Экспорт: {e}"), RED),
    }
}

fn export_pv_msg(v: &Vault, p: &Path) -> (String, Color32) {
    match export::passvault_to_file(v, p) {
        Ok(n) => (format!("{n} паролей {ARROW_RIGHT} {} (открытый текст — удали после переноса)", p.display()), YEL),
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
