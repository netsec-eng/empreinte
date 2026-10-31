//! Travail en arrière-plan : la fenêtre ne se fige jamais, même sur un très gros fichier.

use crate::checksums;
use crate::gpg::{self, GpgOk};
use crate::hash::{self, Algo, Hashes};
use crate::signature::{self, SigStatus};
use crate::virustotal::{self, VtReport};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct NewItem {
    pub path: PathBuf,
    pub size: u64,
    pub expected: Option<(Algo, String)>,
    pub missing: bool,
}

pub enum Event {
    NewItems(Vec<NewItem>),
    Notice(String),
    Progress { id: u64, done: u64 },
    Finished { id: u64, hashes: Hashes, signature: Option<SigStatus> },
    Cancelled { id: u64 },
    Failed { id: u64, error: String },
    Vt { id: u64, result: Result<VtReport, String> },
    Gpg(Result<GpgOk, String>),
    Watched(Vec<PathBuf>),
}

struct Job {
    id: u64,
    path: PathBuf,
    generation: u64,
}

#[derive(Clone)]
pub struct Worker {
    jobs: Sender<Job>,
    pub events: Sender<Event>,
    generation: Arc<AtomicU64>,
    wake: eframe::egui::Context,
}

impl Worker {
    pub fn start(wake: eframe::egui::Context) -> (Worker, Receiver<Event>) {
        let (jobs, job_rx) = channel::<Job>();
        let (events, event_rx) = channel();
        let generation = Arc::new(AtomicU64::new(0));
        let worker = Worker { jobs, events, generation, wake };
        let runner = worker.clone();
        std::thread::spawn(move || {
            for job in job_rx {
                runner.run(job);
            }
        });
        (worker, event_rx)
    }

    pub fn send(&self, event: Event) {
        let _ = self.events.send(event);
        self.wake.request_repaint();
    }

    pub fn enqueue(&self, id: u64, path: PathBuf) {
        let generation = self.generation.load(Ordering::SeqCst);
        let _ = self.jobs.send(Job { id, path, generation });
    }

    /// Annule le calcul en cours et tout ce qui attend.
    pub fn cancel_all(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    fn run(&self, job: Job) {
        let still_wanted = || self.generation.load(Ordering::SeqCst) == job.generation;
        if !still_wanted() {
            self.send(Event::Cancelled { id: job.id });
            return;
        }
        let file = match File::open(&job.path) {
            Ok(file) => file,
            Err(e) => {
                self.send(Event::Failed { id: job.id, error: format!("Lecture impossible : {e}") });
                return;
            }
        };
        let mut last = Instant::now();
        let result = hash::hash_reader(file, |done| {
            if last.elapsed() >= Duration::from_millis(80) {
                last = Instant::now();
                self.send(Event::Progress { id: job.id, done });
            }
            still_wanted()
        });
        match result {
            Ok(Some(hashes)) => {
                let signature = signature::is_signable(&job.path).then(|| signature::check(&job.path));
                self.send(Event::Finished { id: job.id, hashes, signature });
            }
            Ok(None) => self.send(Event::Cancelled { id: job.id }),
            Err(e) => self.send(Event::Failed { id: job.id, error: format!("Lecture impossible : {e}") }),
        }
    }

    /// Transforme des chemins déposés en fichiers à traiter, sans bloquer la fenêtre.
    pub fn collect(&self, paths: Vec<PathBuf>, read_checksums: bool) {
        let this = self.clone();
        std::thread::spawn(move || {
            let mut items = Vec::new();
            for path in paths {
                if path.is_dir() {
                    collect_dir(&path, &mut items);
                } else if read_checksums && checksums::is_checksum_file(&path) {
                    match read_checksum_file(&path) {
                        Ok((found, skipped)) => {
                            if skipped > 0 {
                                this.send(Event::Notice(format!(
                                    "{skipped} ligne(s) ignorée(s) : elles désignaient un fichier hors du dossier."
                                )));
                            }
                            if found.is_empty() {
                                this.send(Event::Notice(format!(
                                    "Aucune empreinte trouvée dans {}.",
                                    path.display()
                                )));
                            }
                            items.extend(found);
                        }
                        Err(e) => this.send(Event::Notice(e)),
                    }
                } else {
                    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    items.push(NewItem { path, size, expected: None, missing: false });
                }
            }
            this.send(Event::NewItems(items));
        });
    }

    pub fn virustotal(&self, id: u64, sha256: String, key: String) {
        let this = self.clone();
        std::thread::spawn(move || {
            this.send(Event::Vt { id, result: virustotal::lookup(&sha256, &key) });
        });
    }

    pub fn gpg(&self, file: PathBuf, signature: PathBuf, key: PathBuf) {
        let this = self.clone();
        std::thread::spawn(move || {
            this.send(Event::Gpg(gpg::verify(&file, &signature, &key)));
        });
    }
}

fn collect_dir(dir: &Path, items: &mut Vec<NewItem>) {
    for entry in walkdir::WalkDir::new(dir).follow_links(false).into_iter().flatten() {
        if entry.file_type().is_file() {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            items.push(NewItem { path: entry.into_path(), size, expected: None, missing: false });
        }
    }
}

fn read_checksum_file(path: &Path) -> Result<(Vec<NewItem>, usize), String> {
    const MAX_SIZE: u64 = 32 * 1024 * 1024;
    let meta = std::fs::metadata(path).map_err(|e| format!("Lecture impossible : {e}"))?;
    if meta.len() > MAX_SIZE {
        return Err("Ce fichier de contrôle est trop volumineux.".to_string());
    }
    let bytes = std::fs::read(path).map_err(|e| format!("Lecture impossible : {e}"))?;
    let text = String::from_utf8_lossy(&bytes);
    let base = path.parent().unwrap_or(Path::new("."));
    let mut items = Vec::new();
    let mut skipped = 0;
    for entry in checksums::parse(&text) {
        if !checksums::is_safe_relative(&entry.file) {
            skipped += 1;
            continue;
        }
        let target = base.join(&entry.file);
        let meta = std::fs::metadata(&target).ok().filter(|m| m.is_file());
        items.push(NewItem {
            path: target,
            size: meta.as_ref().map_or(0, |m| m.len()),
            missing: meta.is_none(),
            expected: Some((entry.algo, entry.hash)),
        });
    }
    Ok((items, skipped))
}
