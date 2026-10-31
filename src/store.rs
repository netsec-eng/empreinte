//! Réglages et historique, enregistrés uniquement sur ce PC.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};

const HISTORY_LIMIT: usize = 1000;

pub fn data_dir() -> PathBuf {
    if cfg!(test) {
        return std::env::temp_dir().join(format!("empreinte-tests-{}", std::process::id()));
    }
    if let Some(dir) = std::env::var_os("EMPREINTE_DATA_DIR") {
        return PathBuf::from(dir);
    }
    std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir).join("Empreinte")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ThemeChoice {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: ThemeChoice,
    pub show_sha256: bool,
    pub show_sha512: bool,
    pub show_sha1: bool,
    pub show_md5: bool,
    pub show_crc32: bool,
    pub watch_clipboard: bool,
    pub keep_history: bool,
    pub watch_folder: Option<PathBuf>,
    pub watch_enabled: bool,
    /// Clé VirusTotal chiffrée par Windows pour ce compte (DPAPI), en hexadécimal.
    pub vt_key: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            theme: ThemeChoice::System,
            show_sha256: true,
            show_sha512: false,
            show_sha1: false,
            show_md5: true,
            show_crc32: false,
            watch_clipboard: true,
            keep_history: true,
            watch_folder: None,
            watch_enabled: false,
            vt_key: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryEntry {
    pub date: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub verdict: String,
}

fn read_json<T: for<'a> Deserialize<'a>>(name: &str) -> Option<T> {
    let bytes = std::fs::read(data_dir().join(name)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Écrit dans un fichier voisin puis remplace : une coupure ne laisse pas de fichier à moitié écrit.
fn write_json<T: Serialize>(name: &str, value: &T) -> std::io::Result<()> {
    let dir = data_dir();
    std::fs::create_dir_all(&dir)?;
    let temp = dir.join(format!("{name}.tmp"));
    std::fs::write(&temp, serde_json::to_vec_pretty(value)?)?;
    std::fs::rename(temp, dir.join(name))
}

pub fn load_settings() -> Settings {
    read_json("settings.json").unwrap_or_default()
}

pub fn save_settings(settings: &Settings) -> std::io::Result<()> {
    write_json("settings.json", settings)
}

pub fn load_history() -> Vec<HistoryEntry> {
    read_json("history.json").unwrap_or_default()
}

pub fn save_history(history: &mut Vec<HistoryEntry>) -> std::io::Result<()> {
    if history.len() > HISTORY_LIMIT {
        let excess = history.len() - HISTORY_LIMIT;
        history.drain(..excess);
    }
    write_json("history.json", history)
}

fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: bytes.len() as u32, pbData: bytes.as_ptr() as *mut u8 }
}

pub fn protect(secret: &str) -> Option<String> {
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    unsafe {
        let input = blob(secret.as_bytes());
        let ok = CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut out,
        );
        if ok == 0 {
            return None;
        }
        let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize);
        let hex = bytes.iter().map(|b| format!("{b:02x}")).collect();
        LocalFree(out.pbData as _);
        Some(hex)
    }
}

pub fn unprotect(hex: &str) -> Option<String> {
    if hex.len() % 2 != 0 || !hex.is_ascii() {
        return None;
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    unsafe {
        let input = blob(&bytes);
        let ok = CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut out,
        );
        if ok == 0 {
            return None;
        }
        let plain = std::slice::from_raw_parts(out.pbData, out.cbData as usize);
        let text = String::from_utf8(plain.to_vec()).ok();
        LocalFree(out.pbData as _);
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_cle_est_chiffree_et_relisible() {
        let hidden = protect("ma-cle-secrete").unwrap();
        assert!(!hidden.contains("ma-cle-secrete"));
        assert_eq!(unprotect(&hidden).as_deref(), Some("ma-cle-secrete"));
        assert_eq!(unprotect("zz"), None);
    }
}
