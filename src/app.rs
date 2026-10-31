//! Fenêtre de l'application.

use crate::checksums;
use crate::export::{self, Row};
use crate::gpg::{self, GpgOk};
use crate::hash::{self, Algo, Hashes};
use crate::shell;
use crate::signature::SigStatus;
use crate::store::{self, HistoryEntry, Settings, ThemeChoice};
use crate::virustotal::VtReport;
use crate::worker::{Event, NewItem, Worker};
use eframe::egui::{self, Color32, CornerRadius, Margin, RichText, Stroke, Theme};
use notify::Watcher;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant, SystemTime};

const MAX_VISIBLE: usize = 300;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Verify,
    Gpg,
    Watch,
    History,
    Settings,
}

#[derive(Clone, PartialEq)]
enum State {
    Queued,
    Running(u64),
    Done,
    Missing,
    Failed(String),
    Cancelled,
}

#[derive(Clone, PartialEq)]
enum Vt {
    Idle,
    Loading,
    Done(Result<VtReport, String>),
}

struct Item {
    id: u64,
    path: PathBuf,
    size: u64,
    state: State,
    expected: Option<(Algo, String)>,
    hashes: Option<Hashes>,
    signature: Option<SigStatus>,
    vt: Vt,
    expanded: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tone {
    Good,
    Warn,
    Bad,
    Neutral,
}

#[derive(Clone)]
struct Verdict {
    tone: Tone,
    title: String,
    detail: String,
}

fn verdict_of(item: &Item, global: &Option<(Algo, String)>) -> Verdict {
    let make = |tone, title: &str, detail: &str| Verdict {
        tone,
        title: title.to_string(),
        detail: detail.to_string(),
    };
    match &item.state {
        State::Queued => make(Tone::Neutral, "En attente", ""),
        State::Running(_) => make(Tone::Neutral, "Calcul en cours", ""),
        State::Missing => make(Tone::Bad, "Fichier introuvable", "Il figure dans le fichier de contrôle mais pas dans le dossier."),
        State::Failed(error) => make(Tone::Bad, "Lecture impossible", error),
        State::Cancelled => make(Tone::Neutral, "Annulé", ""),
        State::Done => {
            let tampered = item.signature == Some(SigStatus::Tampered);
            let Some(hashes) = &item.hashes else {
                return make(Tone::Neutral, "Terminé", "");
            };
            let expected = item.expected.as_ref().or(global.as_ref());
            match expected {
                Some((algo, value)) if hashes.get(*algo) != value => make(
                    Tone::Bad,
                    "Empreinte différente",
                    &format!("Le {} ne correspond pas : fichier abîmé, modifié ou mauvaise version.", algo.name()),
                ),
                _ if tampered => make(Tone::Bad, "Signature rompue", "Le fichier a été modifié après sa signature."),
                Some((algo, _)) if algo.is_weak() => make(
                    Tone::Warn,
                    "Identique, contrôle limité",
                    &format!("Le {} détecte un fichier abîmé, mais pas une modification volontaire.", algo.name()),
                ),
                Some((algo, _)) => make(
                    Tone::Good,
                    "Empreinte identique",
                    &format!("Le {} correspond à l'empreinte attendue.", algo.name()),
                ),
                None => match &item.signature {
                    Some(SigStatus::Valid { .. }) => make(Tone::Good, "Signature valide", "Vérifie que le nom de l'éditeur est bien celui que tu attends."),
                    Some(SigStatus::Untrusted(_)) => make(Tone::Warn, "Signature non fiable", "Windows ne peut pas confirmer l'identité de l'éditeur."),
                    _ => make(Tone::Neutral, "Empreintes calculées", "Colle l'empreinte publiée pour comparer."),
                },
            }
        }
    }
}

fn signature_text(status: &SigStatus) -> String {
    match status {
        SigStatus::Valid { signer } => format!("Signé par {signer}"),
        SigStatus::Unsigned => "Aucune signature intégrée".to_string(),
        SigStatus::Tampered => "Signature rompue : fichier modifié".to_string(),
        SigStatus::Untrusted(why) => format!("Signature non fiable : {why}"),
    }
}

fn format_size(size: u64) -> String {
    const UNITS: [&str; 5] = ["octets", "Ko", "Mo", "Go", "To"];
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{size} octets")
    } else {
        format!("{value:.1} {}", UNITS[unit]).replace('.', ",")
    }
}

struct Palette {
    bg: Color32,
    panel: Color32,
    card: Color32,
    line: Color32,
    text: Color32,
    muted: Color32,
    accent: Color32,
    accent_soft: Color32,
    good: Color32,
    warn: Color32,
    bad: Color32,
}

const LIGHT: Palette = Palette {
    bg: Color32::from_rgb(245, 246, 250),
    panel: Color32::from_rgb(255, 255, 255),
    card: Color32::from_rgb(255, 255, 255),
    line: Color32::from_rgb(226, 229, 238),
    text: Color32::from_rgb(28, 31, 46),
    muted: Color32::from_rgb(98, 104, 125),
    accent: Color32::from_rgb(79, 70, 229),
    accent_soft: Color32::from_rgb(234, 233, 253),
    good: Color32::from_rgb(4, 130, 88),
    warn: Color32::from_rgb(180, 105, 0),
    bad: Color32::from_rgb(204, 38, 38),
};

const DARK: Palette = Palette {
    bg: Color32::from_rgb(17, 19, 28),
    panel: Color32::from_rgb(23, 26, 37),
    card: Color32::from_rgb(29, 32, 45),
    line: Color32::from_rgb(47, 51, 69),
    text: Color32::from_rgb(235, 237, 245),
    muted: Color32::from_rgb(158, 164, 186),
    accent: Color32::from_rgb(129, 120, 247),
    accent_soft: Color32::from_rgb(45, 43, 82),
    good: Color32::from_rgb(52, 211, 153),
    warn: Color32::from_rgb(251, 191, 36),
    bad: Color32::from_rgb(248, 113, 113),
};

fn palette(ui: &egui::Ui) -> &'static Palette {
    if ui.visuals().dark_mode {
        &DARK
    } else {
        &LIGHT
    }
}

fn tone_color(tone: Tone, p: &Palette) -> Color32 {
    match tone {
        Tone::Good => p.good,
        Tone::Warn => p.warn,
        Tone::Bad => p.bad,
        Tone::Neutral => p.muted,
    }
}

fn tone_icon(tone: Tone) -> &'static str {
    match tone {
        Tone::Good => "✔",
        Tone::Warn => "⚠",
        Tone::Bad => "✖",
        Tone::Neutral => "•",
    }
}

fn apply_theme(ctx: &egui::Context) {
    for (theme, p) in [(Theme::Light, &LIGHT), (Theme::Dark, &DARK)] {
        ctx.style_mut_of(theme, |style| {
            style.spacing.item_spacing = egui::vec2(8.0, 8.0);
            style.spacing.button_padding = egui::vec2(12.0, 6.0);
            style.spacing.interact_size.y = 30.0;
            let v = &mut style.visuals;
            v.panel_fill = p.bg;
            v.window_fill = p.card;
            v.extreme_bg_color = if theme == Theme::Dark { p.bg } else { Color32::from_rgb(248, 249, 252) };
            v.override_text_color = Some(p.text);
            v.hyperlink_color = p.accent;
            v.selection.bg_fill = p.accent_soft;
            v.selection.stroke = Stroke::new(1.0_f32, p.accent);
            for w in [&mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active, &mut v.widgets.open] {
                w.corner_radius = CornerRadius::same(5);
            }
            v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, p.line);
            v.widgets.inactive.weak_bg_fill = p.accent_soft;
            v.widgets.inactive.bg_fill = p.line;
            v.widgets.inactive.bg_stroke = Stroke::NONE;
            v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, p.text);
            v.widgets.hovered.weak_bg_fill = p.line;
            v.widgets.hovered.bg_fill = p.line;
            v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, p.accent);
            v.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, p.text);
            v.widgets.active.weak_bg_fill = p.accent_soft;
            v.widgets.active.fg_stroke = Stroke::new(1.0_f32, p.text);
        });
    }
}

/// Segoe UI est plus lisible et couvre plus d'alphabets que la police intégrée.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\segoeui.ttf") {
        fonts.font_data.insert("segoe".to_string(), egui::FontData::from_owned(bytes).into());
        if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
            family.insert(0, "segoe".to_string());
        }
    }
    ctx.set_fonts(fonts);
    ctx.all_styles_mut(|style| {
        style.text_styles.insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
        style.text_styles.insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
        style.text_styles.insert(egui::TextStyle::Small, egui::FontId::proportional(12.0));
        style.text_styles.insert(egui::TextStyle::Heading, egui::FontId::proportional(24.0));
        style.text_styles.insert(egui::TextStyle::Monospace, egui::FontId::monospace(12.5));
    });
}

fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let p = palette(ui);
    egui::Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0_f32, p.line))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

fn primary(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let p = palette(ui);
    let label = RichText::new(text).color(if ui.visuals().dark_mode { Color32::from_rgb(20, 18, 50) } else { Color32::WHITE });
    ui.add(egui::Button::new(label).fill(p.accent).stroke(Stroke::NONE))
}

fn header(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.heading(RichText::new(title).strong());
    ui.label(RichText::new(subtitle).color(palette(ui).muted));
    ui.add_space(6.0);
}

enum Action {
    Remove(u64),
    Copy(String),
    Toggle(u64),
    Vt(u64, String),
    OpenFolder(PathBuf),
}

pub struct App {
    settings: Settings,
    settings_dirty: bool,
    worker: Worker,
    events: Receiver<Event>,
    page: Page,
    items: Vec<Item>,
    next_id: u64,
    expected_text: String,
    only_problems: bool,
    checksum_algo: Algo,
    clipboard_hash: Option<String>,
    was_focused: bool,
    notice: Option<(String, Tone)>,
    history: Vec<HistoryEntry>,
    history_filter: String,
    context_menu: bool,
    vt_key_input: String,
    gpg_file: Option<PathBuf>,
    gpg_signature: Option<PathBuf>,
    gpg_key: Option<PathBuf>,
    gpg_result: Option<Result<GpgOk, String>>,
    gpg_running: bool,
    watcher: Option<notify::RecommendedWatcher>,
    watch_error: Option<String>,
    watch_pending: HashMap<PathBuf, (u64, Instant)>,
    watch_seen: HashSet<(PathBuf, u64, Option<SystemTime>)>,
    watch_count: usize,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, paths: Vec<PathBuf>) -> Self {
        Self::build(&cc.egui_ctx, paths)
    }

    fn build(ctx: &egui::Context, paths: Vec<PathBuf>) -> Self {
        install_fonts(ctx);
        apply_theme(ctx);
        let settings = store::load_settings();
        set_theme(ctx, settings.theme);
        let (worker, events) = Worker::start(ctx.clone());
        let mut app = App {
            history: store::load_history(),
            settings,
            settings_dirty: false,
            worker,
            events,
            page: Page::Verify,
            items: Vec::new(),
            next_id: 1,
            expected_text: String::new(),
            only_problems: false,
            checksum_algo: Algo::Sha256,
            clipboard_hash: None,
            was_focused: false,
            notice: None,
            history_filter: String::new(),
            context_menu: shell::is_installed(),
            vt_key_input: String::new(),
            gpg_file: None,
            gpg_signature: None,
            gpg_key: None,
            gpg_result: None,
            gpg_running: false,
            watcher: None,
            watch_error: None,
            watch_pending: HashMap::new(),
            watch_seen: HashSet::new(),
            watch_count: 0,
        };
        app.restart_watcher();
        if !paths.is_empty() {
            app.worker.collect(paths, true);
        }
        app
    }

    fn global_expected(&self) -> Option<(Algo, String)> {
        hash::parse_expected(&self.expected_text)
    }

    fn add_items(&mut self, new: Vec<NewItem>) {
        let expand = self.items.len() + new.len() <= 3;
        for item in new {
            let id = self.next_id;
            self.next_id += 1;
            let state = if item.missing { State::Missing } else { State::Queued };
            if !item.missing {
                self.worker.enqueue(id, item.path.clone());
            }
            self.items.push(Item {
                id,
                path: item.path,
                size: item.size,
                state,
                expected: item.expected,
                hashes: None,
                signature: None,
                vt: Vt::Idle,
                expanded: expand,
            });
        }
    }

    fn drain_events(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::NewItems(items) => self.add_items(items),
                Event::Notice(text) => self.notice = Some((text, Tone::Warn)),
                Event::Progress { id, done } => {
                    if let Some(item) = self.item_mut(id) {
                        if item.state == State::Queued || matches!(item.state, State::Running(_)) {
                            item.state = State::Running(done);
                        }
                    }
                }
                Event::Finished { id, hashes, signature } => {
                    if let Some(item) = self.item_mut(id) {
                        item.state = State::Done;
                        item.hashes = Some(hashes);
                        item.signature = signature;
                    }
                    self.remember(id);
                }
                Event::Cancelled { id } => {
                    if let Some(item) = self.item_mut(id) {
                        item.state = State::Cancelled;
                    }
                }
                Event::Failed { id, error } => {
                    if let Some(item) = self.item_mut(id) {
                        item.state = State::Failed(error);
                    }
                }
                Event::Vt { id, result } => {
                    if let Some(item) = self.item_mut(id) {
                        item.vt = Vt::Done(result);
                    }
                }
                Event::Gpg(result) => {
                    self.gpg_running = false;
                    self.gpg_result = Some(result);
                }
                Event::Watched(paths) => {
                    for path in paths {
                        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                        self.watch_pending.insert(path, (size, Instant::now()));
                    }
                }
            }
        }
    }

    fn item_mut(&mut self, id: u64) -> Option<&mut Item> {
        self.items.iter_mut().find(|i| i.id == id)
    }

    fn remember(&mut self, id: u64) {
        if !self.settings.keep_history {
            return;
        }
        let global = self.global_expected();
        let Some(item) = self.items.iter().find(|i| i.id == id) else { return };
        self.history.push(HistoryEntry {
            date: chrono::Local::now().format("%d/%m/%Y %H:%M").to_string(),
            path: item.path.display().to_string(),
            size: item.size,
            sha256: item.hashes.as_ref().map(|h| h.sha256.clone()).unwrap_or_default(),
            verdict: verdict_of(item, &global).title,
        });
        if let Err(e) = store::save_history(&mut self.history) {
            self.notice = Some((format!("Historique non enregistré : {e}"), Tone::Warn));
        }
    }

    fn restart_watcher(&mut self) {
        self.watcher = None;
        self.watch_error = None;
        self.watch_pending.clear();
        let (true, Some(folder)) = (self.settings.watch_enabled, self.settings.watch_folder.clone()) else {
            return;
        };
        let worker = self.worker.clone();
        let created = notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
            if let Ok(event) = result {
                if event.kind.is_create() || event.kind.is_modify() {
                    worker.send(Event::Watched(event.paths));
                }
            }
        });
        match created {
            Ok(mut watcher) => match watcher.watch(&folder, notify::RecursiveMode::NonRecursive) {
                Ok(()) => self.watcher = Some(watcher),
                Err(e) => self.watch_error = Some(format!("Surveillance impossible : {e}")),
            },
            Err(e) => self.watch_error = Some(format!("Surveillance impossible : {e}")),
        }
    }

    /// Un fichier n'est traité que lorsque sa taille n'a plus bougé depuis 2 secondes :
    /// un téléchargement encore en cours donnerait une empreinte fausse.
    fn tick_watcher(&mut self, ctx: &egui::Context) {
        if self.watch_pending.is_empty() {
            return;
        }
        ctx.request_repaint_after(Duration::from_secs(1));
        let mut ready = Vec::new();
        self.watch_pending.retain(|path, (size, since)| {
            let Ok(meta) = std::fs::metadata(path) else { return false };
            if !meta.is_file() || is_partial_download(path) {
                return false;
            }
            if meta.len() != *size {
                *size = meta.len();
                *since = Instant::now();
                return true;
            }
            if since.elapsed() < Duration::from_secs(2) {
                return true;
            }
            ready.push((path.clone(), meta.len(), meta.modified().ok()));
            false
        });
        let mut paths = Vec::new();
        for (path, size, modified) in ready {
            if self.watch_seen.insert((path.clone(), size, modified)) {
                self.watch_count += 1;
                paths.push(path);
            }
        }
        if !paths.is_empty() {
            self.worker.collect(paths, false);
        }
    }

    fn check_clipboard(&mut self, ctx: &egui::Context) {
        // Les tests d'interface tournent en parallèle, et l'accès simultané au presse-papiers
        // depuis plusieurs fils fait planter arboard. L'application n'y accède que depuis ce fil.
        let focused = ctx.input(|i| i.focused);
        let gained = focused && !self.was_focused;
        self.was_focused = focused;
        if !gained || !self.settings.watch_clipboard || cfg!(test) {
            return;
        }
        let text = arboard::Clipboard::new().and_then(|mut c| c.get_text()).unwrap_or_default();
        if text.len() > 300 {
            return;
        }
        let Some((_, value)) = hash::parse_expected(&text) else { return };
        if self.global_expected().map(|(_, v)| v) != Some(value.clone()) {
            self.clipboard_hash = Some(value);
        }
    }

    fn handle_drops(&mut self, ctx: &egui::Context) {
        let paths: Vec<PathBuf> =
            ctx.input(|i| i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect());
        if paths.is_empty() {
            return;
        }
        if self.page == Page::Gpg {
            for path in paths {
                self.assign_gpg(path);
            }
        } else {
            self.page = Page::Verify;
            self.worker.collect(paths, true);
        }
    }

    fn assign_gpg(&mut self, path: PathBuf) {
        let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
        self.gpg_result = None;
        if matches!(ext.as_str(), "asc" | "sig" | "gpg" | "pgp" | "key") {
            if gpg::looks_like_public_key(&path) || ext == "key" {
                self.gpg_key = Some(path);
            } else {
                self.gpg_signature = Some(path);
            }
        } else {
            self.gpg_file = Some(path);
        }
    }

    fn visible_algos(&self) -> Vec<Algo> {
        let s = &self.settings;
        Algo::ALL
            .into_iter()
            .filter(|a| match a {
                Algo::Sha256 => s.show_sha256,
                Algo::Sha512 => s.show_sha512,
                Algo::Sha1 => s.show_sha1,
                Algo::Md5 => s.show_md5,
                Algo::Crc32 => s.show_crc32,
            })
            .collect()
    }

    fn rows(&self) -> Vec<Row> {
        let global = self.global_expected();
        self.items
            .iter()
            .map(|item| {
                let mut row = Row {
                    path: item.path.display().to_string(),
                    size: item.size,
                    verdict: verdict_of(item, &global).title,
                    signature: item.signature.as_ref().map(signature_text).unwrap_or_default(),
                    ..Row::default()
                };
                if let Some(h) = &item.hashes {
                    row.sha256 = h.sha256.clone();
                    row.sha512 = h.sha512.clone();
                    row.sha1 = h.sha1.clone();
                    row.md5 = h.md5.clone();
                    row.crc32 = h.crc32.clone();
                }
                row
            })
            .collect()
    }

    fn export(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name("rapport-empreinte.csv")
            .add_filter("Tableur CSV", &["csv"])
            .add_filter("Texte", &["txt"])
            .save_file()
        else {
            return;
        };
        self.write_export(&path);
    }

    fn write_export(&mut self, path: &Path) {
        let rows = self.rows();
        let is_txt = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("txt"));
        let content = if is_txt { export::to_txt(&rows) } else { export::to_csv(&rows) };
        self.notice = Some(match std::fs::write(path, content) {
            Ok(()) => (format!("Rapport enregistré : {}", path.display()), Tone::Good),
            Err(e) => (format!("Enregistrement impossible : {e}"), Tone::Bad),
        });
    }

    fn create_checksum_file(&mut self) {
        let algo = self.checksum_algo;
        let default = match algo {
            Algo::Sha256 => "SHA256SUMS",
            Algo::Sha512 => "SHA512SUMS",
            Algo::Sha1 => "SHA1SUMS",
            Algo::Md5 => "MD5SUMS",
            Algo::Crc32 => "CRC32SUMS",
        };
        let Some(dest) = rfd::FileDialog::new().set_file_name(default).save_file() else { return };
        self.write_checksum_file(&dest, algo);
    }

    fn write_checksum_file(&mut self, dest: &Path, algo: Algo) {
        let base = dest.parent().unwrap_or(Path::new("."));
        let mut lines = Vec::new();
        let mut outside = 0;
        for item in &self.items {
            let Some(hashes) = &item.hashes else { continue };
            match item.path.strip_prefix(base) {
                Ok(relative) if item.path != dest => {
                    lines.push((hashes.get(algo).to_string(), relative.display().to_string()));
                }
                _ => outside += 1,
            }
        }
        if lines.is_empty() {
            self.notice = Some((
                "Rien à enregistrer : enregistre le fichier de contrôle dans le dossier des fichiers.".to_string(),
                Tone::Warn,
            ));
            return;
        }
        self.notice = Some(match std::fs::write(dest, checksums::generate(&lines)) {
            Ok(()) if outside > 0 => (
                format!("{} ligne(s) écrites. {outside} fichier(s) ignoré(s), car hors de ce dossier.", lines.len()),
                Tone::Warn,
            ),
            Ok(()) => (format!("Fichier de contrôle créé : {}", dest.display()), Tone::Good),
            Err(e) => (format!("Enregistrement impossible : {e}"), Tone::Bad),
        });
    }

    fn vt_key(&self) -> Option<String> {
        self.settings.vt_key.as_deref().and_then(store::unprotect)
    }

    fn sidebar(&mut self, ctx: &egui::Context) {
        let p = if ctx.style().visuals.dark_mode { &DARK } else { &LIGHT };
        egui::SidePanel::left("nav")
            .exact_width(190.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(egui::Frame::new().fill(p.panel).inner_margin(Margin::same(14)))
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.label(RichText::new("Empreinte").size(20.0).strong().color(p.accent));
                ui.label(RichText::new("Vérification de fichiers").small().color(p.muted));
                ui.add_space(14.0);
                for (page, label) in [
                    (Page::Verify, "Vérifier"),
                    (Page::Gpg, "Signature GPG"),
                    (Page::Watch, "Surveillance"),
                    (Page::History, "Historique"),
                    (Page::Settings, "Réglages"),
                ] {
                    let active = self.page == page;
                    let text = RichText::new(label).color(if active { p.accent } else { p.text });
                    let text = if active { text.strong() } else { text };
                    let button = egui::Button::new(text)
                        .fill(if active { p.accent_soft } else { Color32::TRANSPARENT })
                        .stroke(Stroke::NONE)
                        .wrap_mode(egui::TextWrapMode::Extend);
                    if ui.add_sized([ui.available_width(), 36.0], button).clicked() {
                        self.page = page;
                    }
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    ui.label(RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION"))).small().color(p.muted));
                    if self.watcher.is_some() {
                        ui.label(RichText::new("● Surveillance active").small().color(p.good));
                    }
                });
            });
    }

    fn page_verify(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        let hovering = ui.ctx().input(|i| !i.raw.hovered_files.is_empty());
        header(ui, "Vérifier un fichier", "Calcule les empreintes, compare-les à celle publiée et contrôle la signature de l'éditeur.");

        let zone = egui::Frame::new()
            .fill(if hovering { p.accent_soft } else { p.card })
            .stroke(Stroke::new(if hovering { 2.0_f32 } else { 1.0_f32 }, if hovering { p.accent } else { p.line }))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::symmetric(16, 14));
        zone.show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new(if hovering { "Relâche pour vérifier" } else { "Dépose ici des fichiers ou des dossiers" }).size(16.0).strong());
                    ui.label(RichText::new("Un fichier .sha256, .md5 ou SHA256SUMS est lu et vérifié automatiquement.").small().color(p.muted));
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Dossier").clicked() {
                        if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                            self.worker.collect(vec![folder], true);
                        }
                    }
                    if primary(ui, "Choisir des fichiers").clicked() {
                        if let Some(files) = rfd::FileDialog::new().pick_files() {
                            self.worker.collect(files, true);
                        }
                    }
                });
            });
        });
        ui.add_space(4.0);

        card(ui, |ui| {
            ui.label(RichText::new("Empreinte attendue").strong());
            ui.add(
                egui::TextEdit::singleline(&mut self.expected_text)
                    .hint_text(RichText::new("Colle ici l'empreinte publiée par l'éditeur (facultatif)").color(p.muted))
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .margin(Margin::symmetric(8, 7)),
            );
            let text = self.expected_text.trim();
            if !text.is_empty() {
                match hash::parse_expected(text) {
                    Some((algo, _)) if algo.is_weak() => {
                        ui.colored_label(p.warn, format!("⚠ {} reconnu : il détecte un fichier abîmé, pas une modification volontaire.", algo.name()));
                    }
                    Some((algo, _)) => {
                        ui.colored_label(p.good, format!("✔ {} reconnu", algo.name()));
                    }
                    None => {
                        ui.colored_label(p.bad, "✖ Ce texte n'est pas une empreinte MD5, SHA-1, SHA-256, SHA-512 ou CRC32.");
                    }
                }
            }
            if let Some(value) = self.clipboard_hash.clone() {
                ui.horizontal(|ui| {
                    let short: String = value.chars().take(16).collect();
                    ui.label(RichText::new(format!("Empreinte trouvée dans le presse-papiers : {short}…")).color(p.muted));
                    if ui.button("Utiliser").clicked() {
                        self.expected_text = value.clone();
                        self.clipboard_hash = None;
                    }
                    if ui.button("Ignorer").clicked() {
                        self.clipboard_hash = None;
                    }
                });
            }
        });

        if let Some((text, tone)) = self.notice.clone() {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.colored_label(tone_color(tone, p), format!("{} {text}", tone_icon(tone)));
                if ui.small_button("Fermer").clicked() {
                    self.notice = None;
                }
            });
        }

        if self.items.is_empty() {
            return;
        }
        ui.add_space(4.0);
        self.toolbar(ui);
        self.item_list(ui);
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        let global = self.global_expected();
        let total = self.items.len();
        let busy = self.items.iter().filter(|i| matches!(i.state, State::Queued | State::Running(_))).count();
        let bad = self.items.iter().filter(|i| verdict_of(i, &global).tone == Tone::Bad).count();
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(format!("{total} fichier(s)")).strong());
            if busy > 0 {
                ui.add(egui::Spinner::new().size(14.0));
                ui.label(RichText::new(format!("{busy} en cours")).color(p.muted));
                if ui.button("Annuler").clicked() {
                    self.worker.cancel_all();
                }
            }
            if bad > 0 {
                ui.colored_label(p.bad, format!("{bad} problème(s)"));
            }
            ui.checkbox(&mut self.only_problems, "Problèmes seulement");
            if busy == 0 {
                if ui.button("Tout effacer").clicked() {
                    self.items.clear();
                }
                if ui.button("Exporter").clicked() {
                    self.export();
                }
                egui::ComboBox::from_id_salt("checksum_algo")
                    .selected_text(self.checksum_algo.name())
                    .width(90.0)
                    .show_ui(ui, |ui| {
                        for algo in Algo::ALL {
                            ui.selectable_value(&mut self.checksum_algo, algo, algo.name());
                        }
                    });
                if ui.button("Créer un fichier de contrôle").clicked() {
                    self.create_checksum_file();
                }
            }
        });
    }

    fn item_list(&mut self, ui: &mut egui::Ui) {
        let global = self.global_expected();
        let algos = self.visible_algos();
        let can_vt = self.settings.vt_key.is_some();
        let mut actions = Vec::new();
        let only_problems = self.only_problems;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let mut shown = 0;
            let mut hidden = 0;
            for item in &self.items {
                let verdict = verdict_of(item, &global);
                if only_problems && verdict.tone != Tone::Bad {
                    continue;
                }
                if shown >= MAX_VISIBLE {
                    hidden += 1;
                    continue;
                }
                shown += 1;
                draw_item(ui, item, &verdict, &algos, can_vt, &mut actions);
                ui.add_space(2.0);
            }
            if shown == 0 && only_problems {
                ui.label(RichText::new("Aucun problème à afficher.").color(palette(ui).muted));
            }
            if hidden > 0 {
                ui.label(RichText::new(format!("{hidden} autre(s) non affiché(s). Le rapport exporté les contient tous.")).color(palette(ui).muted));
            }
        });
        for action in actions {
            match action {
                Action::Remove(id) => self.items.retain(|i| i.id != id),
                Action::Copy(text) => ui.ctx().copy_text(text),
                Action::Toggle(id) => {
                    if let Some(item) = self.item_mut(id) {
                        item.expanded = !item.expanded;
                    }
                }
                Action::Vt(id, sha256) => {
                    if let Some(key) = self.vt_key() {
                        if let Some(item) = self.item_mut(id) {
                            item.vt = Vt::Loading;
                        }
                        self.worker.virustotal(id, sha256, key);
                    } else {
                        self.notice = Some(("Clé VirusTotal illisible : enregistre-la à nouveau dans les réglages.".to_string(), Tone::Bad));
                    }
                }
                Action::OpenFolder(path) => {
                    let _ = std::process::Command::new("explorer").arg("/select,").arg(path).spawn();
                }
            }
        }
    }

    fn page_gpg(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        header(ui, "Signature GPG", "Prouve qu'un fichier a été signé avec une clé précise. Souvent proposé par les logiciels open source.");
        card(ui, |ui| {
            ui.label(RichText::new("Dépose les trois fichiers ici, ou choisis-les un par un.").color(p.muted));
            ui.add_space(4.0);
            for (slot, label, filters) in [
                (0, "Fichier à vérifier", None),
                (1, "Signature (.sig, .asc)", Some(["sig", "asc", "gpg", "pgp"])),
                (2, "Clé publique de l'éditeur (.asc)", Some(["asc", "gpg", "pgp", "key"])),
            ] {
                let current = match slot {
                    0 => &self.gpg_file,
                    1 => &self.gpg_signature,
                    _ => &self.gpg_key,
                };
                let text = current.as_ref().map(|c| c.display().to_string());
                ui.horizontal(|ui| {
                    ui.add_sized([230.0, 24.0], egui::Label::new(label));
                    if ui.button("Choisir").clicked() {
                        let mut dialog = rfd::FileDialog::new();
                        if let Some(filters) = filters {
                            dialog = dialog.add_filter(label, &filters);
                        }
                        if let Some(path) = dialog.pick_file() {
                            self.gpg_result = None;
                            match slot {
                                0 => self.gpg_file = Some(path),
                                1 => self.gpg_signature = Some(path),
                                _ => self.gpg_key = Some(path),
                            }
                        }
                    }
                    match text {
                        Some(text) => ui.add(egui::Label::new(text).truncate()),
                        None => ui.label(RichText::new("Non choisi").color(p.muted)),
                    };
                });
            }
            ui.add_space(4.0);
            let ready = self.gpg_file.is_some() && self.gpg_signature.is_some() && self.gpg_key.is_some();
            ui.horizontal(|ui| {
                ui.add_enabled_ui(ready && !self.gpg_running, |ui| {
                    if primary(ui, "Vérifier la signature").clicked() {
                        if let (Some(f), Some(s), Some(k)) = (self.gpg_file.clone(), self.gpg_signature.clone(), self.gpg_key.clone()) {
                            self.gpg_running = true;
                            self.gpg_result = None;
                            self.worker.gpg(f, s, k);
                        }
                    }
                });
                if self.gpg_running {
                    ui.add(egui::Spinner::new().size(16.0));
                }
            });
        });
        match self.gpg_result.clone() {
            Some(Ok(ok)) => {
                card(ui, |ui| {
                    ui.label(RichText::new("✔ Signature valide pour cette clé").size(16.0).strong().color(p.good));
                    for identity in &ok.identities {
                        ui.label(identity);
                    }
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(group_fingerprint(&ok.fingerprint)).monospace());
                        if ui.small_button("Copier").clicked() {
                            ui.ctx().copy_text(ok.fingerprint.clone());
                        }
                    });
                    ui.colored_label(p.warn, "⚠ Compare cette empreinte de clé avec celle publiée par l'éditeur : n'importe qui peut créer une clé portant son nom. La date d'expiration et la révocation de la clé ne sont pas contrôlées.");
                });
            }
            Some(Err(error)) => {
                card(ui, |ui| {
                    ui.colored_label(p.bad, RichText::new(format!("✖ {error}")).strong());
                });
            }
            None => {}
        }
    }

    fn page_watch(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        header(ui, "Surveillance d'un dossier", "Vérifie automatiquement chaque nouveau fichier, par exemple dans Téléchargements, tant que l'application est ouverte.");
        let mut changed = false;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Choisir le dossier").clicked() {
                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                        self.settings.watch_folder = Some(folder);
                        changed = true;
                    }
                }
                if ui.button("Téléchargements").clicked() {
                    if let Some(home) = std::env::var_os("USERPROFILE") {
                        self.settings.watch_folder = Some(PathBuf::from(home).join("Downloads"));
                        changed = true;
                    }
                }
            });
            match &self.settings.watch_folder {
                Some(folder) => ui.label(folder.display().to_string()),
                None => ui.label(RichText::new("Aucun dossier choisi").color(p.muted)),
            };
            ui.add_enabled_ui(self.settings.watch_folder.is_some(), |ui| {
                changed |= ui.checkbox(&mut self.settings.watch_enabled, "Activer la surveillance").changed();
            });
            if let Some(error) = &self.watch_error {
                ui.colored_label(p.bad, error);
            } else if self.watcher.is_some() {
                ui.colored_label(p.good, format!("● Active. {} fichier(s) vérifié(s) depuis l'ouverture.", self.watch_count));
            }
            ui.label(RichText::new("Les résultats arrivent dans la page Vérifier. Les téléchargements encore en cours sont ignorés jusqu'à ce qu'ils soient terminés.").small().color(p.muted));
        });
        if changed {
            self.settings_dirty = true;
            self.restart_watcher();
        }
    }

    fn page_history(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        header(ui, "Historique", "Les vérifications passées. Il reste sur ce PC.");
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.history_filter).hint_text(RichText::new("Rechercher un nom ou une empreinte").color(p.muted)).desired_width(320.0));
            if !self.history.is_empty() && ui.button("Tout effacer").clicked() {
                self.history.clear();
                if let Err(e) = store::save_history(&mut self.history) {
                    self.notice = Some((format!("Historique non effacé : {e}"), Tone::Bad));
                }
            }
        });
        if self.history.is_empty() {
            ui.label(RichText::new("Aucune vérification pour l'instant.").color(p.muted));
            return;
        }
        let filter = self.history_filter.to_lowercase();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for entry in self.history.iter().rev().take(MAX_VISIBLE).filter(|e| {
                filter.is_empty() || e.path.to_lowercase().contains(&filter) || e.sha256.contains(&filter)
            }) {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        let name = Path::new(&entry.path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                        ui.add(egui::Label::new(RichText::new(name).strong()).truncate());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(RichText::new(&entry.date).small().color(p.muted));
                        });
                    });
                    ui.label(RichText::new(format!("{} · {}", entry.verdict, format_size(entry.size))).color(p.muted));
                    ui.add(egui::Label::new(RichText::new(&entry.sha256).monospace().small()).truncate());
                });
                ui.add_space(2.0);
            }
        });
    }

    fn page_settings(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        header(ui, "Réglages", "Tout reste enregistré sur ce PC.");
        let mut changed = false;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            card(ui, |ui| {
                ui.label(RichText::new("Apparence").strong());
                ui.horizontal(|ui| {
                    for (choice, label) in [(ThemeChoice::System, "Comme Windows"), (ThemeChoice::Light, "Clair"), (ThemeChoice::Dark, "Sombre")] {
                        if ui.selectable_value(&mut self.settings.theme, choice, label).changed() {
                            set_theme(ui.ctx(), choice);
                            changed = true;
                        }
                    }
                });
            });
            card(ui, |ui| {
                ui.label(RichText::new("Empreintes affichées").strong());
                ui.label(RichText::new("Toutes sont calculées : la comparaison fonctionne même si l'algorithme est masqué.").small().color(p.muted));
                ui.horizontal_wrapped(|ui| {
                    let s = &mut self.settings;
                    changed |= ui.checkbox(&mut s.show_sha256, "SHA-256").changed();
                    changed |= ui.checkbox(&mut s.show_sha512, "SHA-512").changed();
                    changed |= ui.checkbox(&mut s.show_sha1, "SHA-1").changed();
                    changed |= ui.checkbox(&mut s.show_md5, "MD5").changed();
                    changed |= ui.checkbox(&mut s.show_crc32, "CRC32").changed();
                });
            });
            card(ui, |ui| {
                ui.label(RichText::new("Windows").strong());
                let mut wanted = self.context_menu;
                if ui.checkbox(&mut wanted, "Ajouter « Vérifier avec Empreinte » au clic droit").changed() {
                    let result = if wanted { shell::install() } else { shell::uninstall() };
                    match result {
                        Ok(()) => self.context_menu = wanted,
                        Err(e) => self.notice = Some((format!("Clic droit non modifié : {e}"), Tone::Bad)),
                    }
                }
                ui.label(RichText::new("Sous Windows 11, l'entrée se trouve dans « Afficher d'autres options ». Si tu déplaces l'application, décoche puis recoche cette case.").small().color(p.muted));
                changed |= ui.checkbox(&mut self.settings.watch_clipboard, "Proposer l'empreinte trouvée dans le presse-papiers").changed();
                changed |= ui.checkbox(&mut self.settings.keep_history, "Conserver l'historique").changed();
            });
            card(ui, |ui| {
                ui.label(RichText::new("VirusTotal (facultatif)").strong());
                ui.label(RichText::new("Seule l'empreinte SHA-256 est envoyée, et seulement lorsque tu cliques sur le bouton d'un fichier. Le fichier n'est jamais envoyé. La clé gratuite s'obtient sur virustotal.com.").small().color(p.muted));
                if self.settings.vt_key.is_some() {
                    ui.horizontal(|ui| {
                        ui.colored_label(p.good, "✔ Clé enregistrée, chiffrée pour ton compte Windows");
                        if ui.button("Supprimer la clé").clicked() {
                            self.settings.vt_key = None;
                            changed = true;
                        }
                    });
                } else {
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut self.vt_key_input).password(true).hint_text(RichText::new("Clé API").color(p.muted)).desired_width(340.0));
                        if ui.button("Enregistrer").clicked() && !self.vt_key_input.trim().is_empty() {
                            self.settings.vt_key = store::protect(self.vt_key_input.trim());
                            self.vt_key_input.clear();
                            changed = true;
                        }
                    });
                }
            });
            if let Some((text, tone)) = &self.notice {
                ui.colored_label(tone_color(*tone, p), text);
            }
        });
        self.settings_dirty |= changed;
    }
}

fn group_fingerprint(fingerprint: &str) -> String {
    fingerprint.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" ")
}

fn is_partial_download(path: &Path) -> bool {
    let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase());
    matches!(ext.as_deref(), Some("crdownload" | "part" | "partial" | "tmp" | "download" | "opdownload"))
}

fn set_theme(ctx: &egui::Context, choice: ThemeChoice) {
    ctx.set_theme(match choice {
        ThemeChoice::System => egui::ThemePreference::System,
        ThemeChoice::Light => egui::ThemePreference::Light,
        ThemeChoice::Dark => egui::ThemePreference::Dark,
    });
}

fn draw_item(ui: &mut egui::Ui, item: &Item, verdict: &Verdict, algos: &[Algo], can_vt: bool, actions: &mut Vec<Action>) {
    let p = palette(ui);
    let color = tone_color(verdict.tone, p);
    card(ui, |ui| {
        ui.horizontal(|ui| {
            match item.state {
                State::Queued | State::Running(_) => {
                    ui.add(egui::Spinner::new().size(16.0));
                }
                _ => {
                    ui.label(RichText::new(tone_icon(verdict.tone)).size(18.0).strong().color(color));
                }
            }
            let name = item.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| item.path.display().to_string());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Retirer").clicked() {
                    actions.push(Action::Remove(item.id));
                }
                if ui.small_button(if item.expanded { "Réduire" } else { "Détails" }).clicked() {
                    actions.push(Action::Toggle(item.id));
                }
                ui.label(RichText::new(&verdict.title).strong().color(color));
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.add(egui::Label::new(RichText::new(name).strong()).truncate()).on_hover_text(item.path.display().to_string());
                });
            });
        });
        if let State::Running(done) = item.state {
            let fraction = if item.size == 0 { 0.0 } else { done as f32 / item.size as f32 };
            ui.add(egui::ProgressBar::new(fraction).desired_height(6.0).fill(p.accent));
            ui.label(RichText::new(format!("{} sur {}", format_size(done), format_size(item.size))).small().color(p.muted));
        }
        if !item.expanded {
            return;
        }
        ui.horizontal(|ui| {
            ui.label(RichText::new(format_size(item.size)).small().color(p.muted));
            ui.add(egui::Label::new(RichText::new(item.path.display().to_string()).small().color(p.muted)).truncate());
        });
        if !verdict.detail.is_empty() {
            ui.label(RichText::new(&verdict.detail).color(color));
        }
        if let Some(status) = &item.signature {
            let tone = match status {
                SigStatus::Valid { .. } => Tone::Good,
                SigStatus::Unsigned => Tone::Warn,
                SigStatus::Tampered | SigStatus::Untrusted(_) => Tone::Bad,
            };
            ui.colored_label(tone_color(tone, p), format!("{} {}", tone_icon(tone), signature_text(status)));
        }
        if let Some(hashes) = &item.hashes {
            ui.add_space(2.0);
            for algo in algos {
                let value = hashes.get(*algo);
                ui.horizontal(|ui| {
                    ui.add_sized([62.0, 20.0], egui::Label::new(RichText::new(algo.name()).small().strong().color(p.muted)));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("Copier").clicked() {
                            actions.push(Action::Copy(value.to_string()));
                        }
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.add(egui::Label::new(RichText::new(value).monospace()).truncate()).on_hover_text(value);
                        });
                    });
                });
            }
            ui.horizontal(|ui| {
                if ui.small_button("Ouvrir le dossier").clicked() {
                    actions.push(Action::OpenFolder(item.path.clone()));
                }
                match &item.vt {
                    Vt::Idle => {
                        let button = ui.add_enabled(can_vt, egui::Button::new("Chercher sur VirusTotal").small());
                        let button = if can_vt { button } else { button.on_disabled_hover_text("Ajoute d'abord une clé dans les réglages.") };
                        if button.clicked() {
                            actions.push(Action::Vt(item.id, hashes.sha256.clone()));
                        }
                    }
                    Vt::Loading => {
                        ui.add(egui::Spinner::new().size(14.0));
                    }
                    Vt::Done(Ok(VtReport::Unknown)) => {
                        ui.label(RichText::new("VirusTotal ne connaît pas ce fichier : cela ne prouve rien.").color(p.muted));
                    }
                    Vt::Done(Ok(VtReport::Known { malicious, suspicious, clean })) => {
                        let tone = if *malicious > 0 { Tone::Bad } else if *suspicious > 0 { Tone::Warn } else { Tone::Good };
                        ui.colored_label(tone_color(tone, p), format!("VirusTotal : {malicious} malveillant(s), {suspicious} suspect(s), {clean} sans détection"));
                    }
                    Vt::Done(Err(error)) => {
                        ui.colored_label(p.bad, error);
                    }
                }
            });
        }
    });
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.render(ctx);
    }
}

impl App {
    fn render(&mut self, ctx: &egui::Context) {
        self.drain_events();
        self.tick_watcher(ctx);
        self.check_clipboard(ctx);
        self.handle_drops(ctx);
        self.sidebar(ctx);
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(if ctx.style().visuals.dark_mode { DARK.bg } else { LIGHT.bg }).inner_margin(Margin::same(20)))
            .show(ctx, |ui| match self.page {
                Page::Verify => self.page_verify(ui),
                Page::Gpg => self.page_gpg(ui),
                Page::Watch => self.page_watch(ui),
                Page::History => self.page_history(ui),
                Page::Settings => self.page_settings(ui),
            });
        if self.settings_dirty {
            self.settings_dirty = false;
            if let Err(e) = store::save_settings(&self.settings) {
                self.notice = Some((format!("Réglages non enregistrés : {e}"), Tone::Bad));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done_item(expected: Option<(Algo, String)>, signature: Option<SigStatus>) -> Item {
        Item {
            id: 1,
            path: PathBuf::from("a"),
            size: 3,
            state: State::Done,
            expected,
            hashes: Some(hash::hash_reader(&b"abc"[..], |_| true).unwrap().unwrap()),
            signature,
            vt: Vt::Idle,
            expanded: true,
        }
    }

    const SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const MD5: &str = "900150983cd24fb0d6963f7d28e17f72";

    #[test]
    fn sha256_identique_est_vert() {
        let item = done_item(Some((Algo::Sha256, SHA256.into())), None);
        assert!(verdict_of(&item, &None).tone == Tone::Good);
    }

    #[test]
    fn md5_identique_reste_un_avertissement() {
        let item = done_item(Some((Algo::Md5, MD5.into())), None);
        assert!(verdict_of(&item, &None).tone == Tone::Warn);
    }

    #[test]
    fn empreinte_differente_est_rouge() {
        let item = done_item(Some((Algo::Sha256, "0".repeat(64))), None);
        assert!(verdict_of(&item, &None).tone == Tone::Bad);
    }

    #[test]
    fn signature_rompue_l_emporte_sur_une_empreinte_identique() {
        let item = done_item(Some((Algo::Sha256, SHA256.into())), Some(SigStatus::Tampered));
        assert!(verdict_of(&item, &None).tone == Tone::Bad);
    }

    #[test]
    fn l_empreinte_du_fichier_de_controle_passe_avant_celle_saisie() {
        let item = done_item(Some((Algo::Sha256, SHA256.into())), None);
        let global = Some((Algo::Sha256, "0".repeat(64)));
        assert!(verdict_of(&item, &global).tone == Tone::Good);
    }

    mod interface {
        use super::*;
        use egui_kittest::kittest::Queryable;
        use egui_kittest::Harness;

        fn folder(name: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!("empreinte-ui-{}-{name}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        fn harness(paths: Vec<PathBuf>) -> Harness<'static, App> {
            let ctx = egui::Context::default();
            let app = App::build(&ctx, paths);
            let mut h = Harness::builder()
                .with_size(egui::vec2(1000.0, 720.0))
                .build_state(|ctx, app: &mut App| app.render(ctx), app);
            h.step();
            h
        }

        fn wait(h: &mut Harness<'static, App>, done: impl Fn(&App) -> bool) {
            for _ in 0..600 {
                h.step();
                if done(h.state()) {
                    h.step();
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("délai dépassé");
        }

        fn finished(app: &App, count: usize) -> bool {
            app.items.len() == count && app.items.iter().all(|i| !matches!(i.state, State::Queued | State::Running(_)))
        }

        #[test]
        fn navigation_entre_toutes_les_pages() {
            folder("nav");
            let mut h = harness(vec![]);
            for (button, title) in [
                ("Signature GPG", "Signature GPG"),
                ("Surveillance", "Surveillance d'un dossier"),
                ("Historique", "Historique"),
                ("Réglages", "Réglages"),
                ("Vérifier", "Vérifier un fichier"),
            ] {
                h.get_all_by_label(button).next().unwrap().click();
                h.step();
                h.step();
                assert!(h.query_all_by_label(title).next().is_some(), "{title}");
            }
        }

        #[test]
        fn comparaison_saisie_apres_le_calcul() {
            let dir = folder("compare");
            let file = dir.join("a.txt");
            std::fs::write(&file, b"abc").unwrap();
            let mut h = harness(vec![file]);
            wait(&mut h, |app| finished(app, 1));
            h.get_by_label("Empreintes calculées");

            h.state_mut().expected_text = SHA256.to_string();
            h.step();
            h.step();
            h.get_by_label("Empreinte identique");

            h.state_mut().expected_text = "0".repeat(64);
            h.step();
            h.step();
            h.get_by_label("Empreinte différente");
        }

        #[test]
        fn annulation_d_un_tres_gros_fichier() {
            let dir = folder("annule");
            let file = dir.join("gros.bin");
            std::fs::File::create(&file).unwrap().set_len(1024 * 1024 * 1024).unwrap();
            let mut h = harness(vec![file.clone()]);
            wait(&mut h, |app| matches!(app.items.first().map(|i| &i.state), Some(State::Running(_))));
            h.get_by_label("Annuler").click();
            h.step();
            wait(&mut h, |app| app.items[0].state == State::Cancelled);
            h.get_by_label("Annulé");
            std::fs::remove_file(file).unwrap();
        }

        #[test]
        fn fichier_de_controle_cree_puis_relu() {
            let dir = folder("controle");
            std::fs::write(dir.join("a b.txt"), b"abc").unwrap();
            std::fs::create_dir_all(dir.join("sous")).unwrap();
            std::fs::write(dir.join("sous").join("c.txt"), b"xyz").unwrap();
            let mut h = harness(vec![dir.clone()]);
            wait(&mut h, |app| finished(app, 2));
            let sums = dir.join("SHA256SUMS");
            h.state_mut().write_checksum_file(&sums, Algo::Sha256);
            h.state_mut().write_export(&dir.join("rapport.csv"));
            let csv = std::fs::read_to_string(dir.join("rapport.csv")).unwrap();
            assert!(csv.contains(SHA256), "{csv}");

            let mut h = harness(vec![sums.clone()]);
            wait(&mut h, |app| finished(app, 2));
            let global = None;
            assert!(h.state().items.iter().all(|i| verdict_of(i, &global).tone == Tone::Good));

            std::fs::write(dir.join("a b.txt"), b"abd").unwrap();
            let mut h = harness(vec![sums]);
            wait(&mut h, |app| finished(app, 2));
            let bad = h.state().items.iter().filter(|i| verdict_of(i, &global).tone == Tone::Bad).count();
            assert_eq!(bad, 1);
        }
    }

    #[test]
    fn tailles_lisibles() {
        assert_eq!(format_size(12), "12 octets");
        assert_eq!(format_size(1536), "1,5 Ko");
    }

    #[test]
    fn telechargements_partiels() {
        assert!(is_partial_download(Path::new("a.zip.crdownload")));
        assert!(!is_partial_download(Path::new("a.zip")));
    }
}
