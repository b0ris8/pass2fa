//! Встроенный выбор файла на egui: без GTK, порталов и DBus.
//! (xdg-open открывает файловый менеджер, но не возвращает выбранный путь — поэтому свой.)
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
}

pub enum Outcome {
    None,
    Cancel,
    Picked(PathBuf),
}

fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

impl Picker {
    pub fn open(purpose: Purpose, exts: &'static [&'static str], save_name: Option<&str>) -> Self {
        let start = dirs::download_dir().filter(|d| d.is_dir()).unwrap_or_else(home);
        let mut p = Self {
            purpose,
            dir: start,
            exts,
            save_name: save_name.map(str::to_string),
            show_hidden: false,
            list: vec![],
            err: None,
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
                    if !self.show_hidden && name.starts_with('.') { continue; }
                    let is_dir = e.path().is_dir();
                    if !is_dir && !self.exts.is_empty() {
                        let ext = Path::new(&name).extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
                        if !self.exts.contains(&ext.as_str()) { continue; }
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
        self.refresh();
    }

    pub fn ui(&mut self, ctx: &egui::Context) -> Outcome {
        use crate::gui::icon::*;
        let mut out = Outcome::None;
        let title = match self.purpose {
            Purpose::Import => "Импорт — выбери файл",
            Purpose::ExportAegis => "Экспорт для Aegis — папка и имя файла",
            Purpose::ExportPassVault => "Экспорт для PassVault — папка и имя файла",
            _ => "Иконка — SVG/PNG/JPEG/ICO/WebP",
        };
        egui::Modal::new(egui::Id::unique("pass2fa-picker")).show(ctx, |ui| {
            ui.set_width(640.0);
            ui.heading(title);
            ui.horizontal(|ui| {
                if ui.button(format!("{HOUSE}")).on_hover_text("домашняя папка").clicked() { self.go(home()); }
                if let Some(d) = dirs::download_dir() {
                    if ui.button(format!("{IMPORT} Загрузки")).clicked() { self.go(d); }
                }
                if ui.button(format!("{ARROW_UP}")).on_hover_text("вверх").clicked() {
                    if let Some(p) = self.dir.parent() { self.go(p.to_path_buf()); }
                }
                if ui.checkbox(&mut self.show_hidden, "скрытые").changed() { self.refresh(); }
            });
            ui.label(RichText::new(self.dir.display().to_string()).monospace().small());
            ui.separator();
            let mut nav: Option<PathBuf> = None;
            egui::ScrollArea::vertical().max_height(360.0).auto_shrink([false, false]).show(ui, |ui| {
                if let Some(e) = &self.err { ui.colored_label(egui::Color32::from_rgb(191, 97, 106), e); }
                for (name, is_dir) in &self.list {
                    let label = if *is_dir { format!("{FOLDER}  {name}") } else { format!("{FILE}  {name}") };
                    let r = ui.add(egui::Button::new(label).frame_when_inactive(false));
                    if r.clicked() {
                        let p = self.dir.join(name);
                        if *is_dir { nav = Some(p); }
                        else if self.save_name.is_none() { out = Outcome::Picked(p); }
                        else { self.save_name = Some(name.clone()); }
                    }
                }
                if self.list.is_empty() && self.err.is_none() { ui.weak("подходящих файлов нет"); }
            });
            if let Some(p) = nav { self.go(p); }
            ui.separator();
            ui.horizontal(|ui| {
                if let Some(n) = &mut self.save_name {
                    ui.label("Имя файла:");
                    ui.add(egui::TextEdit::singleline(n).desired_width(260.0));
                    if ui.button(format!("{CHECK} Сохранить сюда")).clicked() && !n.trim().is_empty() {
                        out = Outcome::Picked(self.dir.join(n.trim()));
                    }
                }
                if ui.button(format!("{X} Отмена")).clicked() { out = Outcome::Cancel; }
            });
        });
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) { out = Outcome::Cancel; }
        out
    }
}
