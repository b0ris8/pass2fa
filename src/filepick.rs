//! Встроенный выбор файла на egui: без GTK, порталов и DBus.
//! (xdg-open открывает файловый менеджер, но не возвращает выбранный путь — поэтому свой.)
//! Поле сверху: обычный текст — фильтр по имени; «/…» или «~/…» + Enter — переход/выбор по пути.
//! Последняя папка запоминается между запусками в ~/.config/pass2fa/state.json (только путь, без секретов).
use eframe::egui::{self, RichText};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq)]
pub enum Purpose {
    Import,
    ExportAegis,
    ExportPassVault,
    Icon,
}

pub struct Picker {
    pub purpose: Purpose,
    dir: PathBuf,
    exts: &'static [&'static str],
    save_name: Option<String>,
    show_hidden: bool,
    list: Vec<(String, bool)>,
    err: Option<String>,
    query: String,
    focus: bool,
    last: Option<PathBuf>,
}

pub enum Outcome {
    None,
    Cancel,
    Picked(PathBuf),
}

fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

fn state_file() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("pass2fa").join("state.json"))
}

fn load_last_dir() -> Option<PathBuf> {
    let raw = std::fs::read_to_string(state_file()?).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let p = PathBuf::from(v.get("last_dir")?.as_str()?);
    p.is_dir().then_some(p)
}

fn save_last_dir(d: &Path) {
    let Some(f) = state_file() else { return };
    if let Some(parent) = f.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&f, serde_json::json!({ "last_dir": d.display().to_string() }).to_string());
}

fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/").or_else(|| (p == "~").then_some("")) {
        Some(rest) => home().join(rest),
        None => PathBuf::from(p),
    }
}

impl Picker {
    pub fn open(purpose: Purpose, exts: &'static [&'static str], save_name: Option<&str>) -> Self {
        let last = load_last_dir();
        let start = last
            .clone()
            .or_else(|| dirs::download_dir().filter(|d| d.is_dir()))
            .unwrap_or_else(home);
        let mut p = Self {
            purpose,
            dir: start,
            exts,
            save_name: save_name.map(str::to_string),
            show_hidden: false,
            list: vec![],
            err: None,
            query: String::new(),
            focus: true,
            last,
        };
        p.refresh();
        p
    }

    fn refresh(&mut self) {
        self.list.clear();
        self.err = None;
        match std::fs::read_dir(&self.dir) {
            Ok(rd) => {
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if !self.show_hidden && name.starts_with('.') {
                        continue;
                    }
                    let is_dir = e.path().is_dir();
                    if !is_dir && !self.exts.is_empty() {
                        let ext = Path::new(&name).extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
                        if !self.exts.contains(&ext.as_str()) {
                            continue;
                        }
                    }
                    self.list.push((name, is_dir));
                }
                self.list.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.to_lowercase().cmp(&b.0.to_lowercase())));
            }
            Err(e) => self.err = Some(e.to_string()),
        }
    }

    fn go(&mut self, d: PathBuf) {
        self.dir = d;
        self.query.clear();
        self.focus = true;
        self.refresh();
    }

    fn pick(&self, p: PathBuf) -> Outcome {
        if let Some(d) = if p.is_dir() { Some(p.as_path()) } else { p.parent() } {
            save_last_dir(d);
        }
        Outcome::Picked(p)
    }

    fn visible(&self) -> Vec<(String, bool)> {
        let q = self.query.trim().to_lowercase();
        if q.is_empty() || q.starts_with('/') || q.starts_with('~') {
            return self.list.clone();
        }
        self.list.iter().filter(|(n, _)| n.to_lowercase().contains(&q)).cloned().collect()
    }

    pub fn ui(&mut self, ctx: &egui::Context) -> Outcome {
        use crate::gui::icon::*;
        let mut out = Outcome::None;
        let title = match self.purpose {
            Purpose::Import => "Импорт — выбери файл",
            Purpose::ExportAegis => "Экспорт для Aegis — папка и имя файла",
            Purpose::ExportPassVault => "Экспорт для PassVault — папка и имя файла",
            Purpose::Icon => "Иконка — SVG/PNG/JPEG/ICO/WebP",
        };
        let vis = self.visible();
        egui::Modal::new(egui::Id::unique("pass2fa-picker")).show(ctx, |ui| {
            ui.set_width(660.0);
            ui.heading(title);
            let mut nav: Option<PathBuf> = None;
            ui.horizontal(|ui| {
                if ui.button(HOUSE).on_hover_text("домашняя папка").clicked() {
                    nav = Some(home());
                }
                if let Some(d) = dirs::download_dir() {
                    if ui.button(format!("{IMPORT} Загрузки")).clicked() {
                        nav = Some(d);
                    }
                }
                if let Some(l) = self.last.clone() {
                    if ui.button(RECENT).on_hover_text(format!("последняя папка: {}", l.display())).clicked() {
                        nav = Some(l);
                    }
                }
                if ui.button(ARROW_UP).on_hover_text("вверх").clicked() {
                    if let Some(p) = self.dir.parent() {
                        nav = Some(p.to_path_buf());
                    }
                }
                if ui.checkbox(&mut self.show_hidden, "скрытые").changed() {
                    self.refresh();
                }
            });
            ui.label(RichText::new(self.dir.display().to_string()).monospace().small());
            let r = ui.add(
                egui::TextEdit::singleline(&mut self.query)
                    .hint_text(format!("{SEARCH} фильтр по имени · или путь /… ~/… + Enter"))
                    .desired_width(f32::INFINITY),
            );
            if self.focus {
                r.request_focus();
                self.focus = false;
            }
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                let q = self.query.trim();
                if q.starts_with('/') || q.starts_with('~') {
                    let p = expand(q);
                    if p.is_dir() {
                        nav = Some(p);
                    } else if p.is_file() && self.save_name.is_none() {
                        out = self.pick(p);
                    } else if self.save_name.is_some() && p.parent().is_some_and(Path::is_dir) {
                        out = self.pick(p);
                    } else {
                        self.err = Some(format!("нет такого пути: {}", p.display()));
                        self.focus = true;
                    }
                } else {
                    // Enter при фильтре: единственное совпадение — открыть/выбрать
                    let files: Vec<_> = vis.iter().filter(|(_, d)| !*d).collect();
                    let dirs_: Vec<_> = vis.iter().filter(|(_, d)| *d).collect();
                    if files.len() == 1 && self.save_name.is_none() {
                        out = self.pick(self.dir.join(&files[0].0));
                    } else if files.is_empty() && dirs_.len() == 1 {
                        nav = Some(self.dir.join(&dirs_[0].0));
                    } else {
                        self.focus = true;
                    }
                }
            }
            ui.separator();
            egui::ScrollArea::vertical().max_height(340.0).auto_shrink([false, false]).show(ui, |ui| {
                if let Some(e) = &self.err {
                    ui.colored_label(egui::Color32::from_rgb(191, 97, 106), e);
                }
                for (name, is_dir) in &vis {
                    let label = if *is_dir { format!("{FOLDER}  {name}") } else { format!("{FILE}  {name}") };
                    let r = ui.add(egui::Button::new(label).frame_when_inactive(false));
                    if r.clicked() {
                        let p = self.dir.join(name);
                        if *is_dir {
                            nav = Some(p);
                        } else if self.save_name.is_none() {
                            out = self.pick(p);
                        } else {
                            self.save_name = Some(name.clone());
                        }
                    }
                }
                if vis.is_empty() && self.err.is_none() {
                    ui.weak(if self.query.is_empty() { "подходящих файлов нет" } else { "ничего не найдено" });
                }
            });
            if let Some(p) = nav {
                self.go(p);
            }
            ui.separator();
            ui.horizontal(|ui| {
                if let Some(n) = &mut self.save_name {
                    ui.label("Имя файла:");
                    ui.add(egui::TextEdit::singleline(n).desired_width(260.0));
                    let name = n.trim().to_string();
                    if ui.button(format!("{CHECK} Сохранить сюда")).clicked() && !name.is_empty() {
                        out = self.pick(self.dir.join(name));
                    }
                }
                if ui.button(format!("{X} Отмена")).clicked() {
                    out = Outcome::Cancel;
                }
            });
        });
        if matches!(out, Outcome::None) && ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            out = Outcome::Cancel;
        }
        out
    }
}
