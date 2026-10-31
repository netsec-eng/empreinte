//! Lecture et création des fichiers de contrôle (`.sha256`, `SHA256SUMS`, `.md5`…).

use crate::hash::Algo;
use std::path::{Component, Path};

#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub algo: Algo,
    pub hash: String,
    pub file: String,
}

pub fn is_checksum_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let by_ext = [".md5", ".sha1", ".sha256", ".sha512", ".md5sum", ".sha1sum", ".sha256sum", ".sha512sum"]
        .iter()
        .any(|e| name.ends_with(e));
    let by_name = ["sums", "sums.txt", "checksums", "checksums.txt"]
        .iter()
        .any(|e| name.ends_with(e));
    by_ext || by_name
}

/// Un fichier de contrôle vient d'Internet : il ne doit pas pouvoir désigner
/// un fichier situé hors de son propre dossier.
pub fn is_safe_relative(file: &str) -> bool {
    let path = Path::new(file);
    !file.is_empty()
        && path.components().all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// Comprend le format GNU (`empreinte  fichier`) et le format BSD (`SHA256 (fichier) = empreinte`).
pub fn parse(text: &str) -> Vec<Entry> {
    text.trim_start_matches('\u{feff}').lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<Entry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    if let Some((left, hash)) = line.rsplit_once(") = ") {
        let (_, file) = left.split_once(" (")?;
        return entry(hash, file);
    }
    let (hash, file) = line.split_once(char::is_whitespace)?;
    let file = file.trim_start();
    entry(hash, file.strip_prefix('*').unwrap_or(file))
}

fn entry(hash: &str, file: &str) -> Option<Entry> {
    let hash = hash.trim().to_ascii_lowercase();
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let algo = Algo::from_hex_len(hash.len())?;
    Some(Entry { algo, hash, file: file.trim_end().to_string() })
}

/// Crée le contenu au format GNU, lisible par `sha256sum -c` et par cette application.
pub fn generate(lines: &[(String, String)]) -> String {
    lines.iter().map(|(hash, file)| format!("{hash} *{}\n", file.replace('\\', "/"))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn format_gnu_et_bsd() {
        let text = format!(
            "\u{feff}# commentaire\r\n{HASH}  a.zip\r\n{HASH} *dossier/b c.zip\nSHA256 (d.iso) = {}\n\nnimporte quoi\n",
            HASH.to_uppercase()
        );
        let entries = parse(&text);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].file, "a.zip");
        assert_eq!(entries[1].file, "dossier/b c.zip");
        assert_eq!(entries[2].file, "d.iso");
        assert_eq!(entries[2].hash, HASH);
        assert_eq!(entries[2].algo, Algo::Sha256);
    }

    #[test]
    fn creation_puis_relecture() {
        let text = generate(&[(HASH.into(), "sous\\dossier\\a b.zip".into())]);
        let entries = parse(&text);
        assert_eq!(entries[0].file, "sous/dossier/a b.zip");
        assert_eq!(entries[0].hash, HASH);
    }

    #[test]
    fn refuse_de_sortir_du_dossier() {
        assert!(is_safe_relative("a.zip"));
        assert!(is_safe_relative("./sous/a.zip"));
        assert!(!is_safe_relative("../a.zip"));
        assert!(!is_safe_relative("sous/../../a.zip"));
        assert!(!is_safe_relative("C:\\Windows\\a.exe"));
        assert!(!is_safe_relative("\\\\serveur\\partage\\a"));
        assert!(!is_safe_relative("/etc/passwd"));
        assert!(!is_safe_relative(""));
    }

    #[test]
    fn reconnait_les_noms() {
        for name in ["a.sha256", "SHA256SUMS", "sha512sums.txt", "A.MD5", "checksums.txt"] {
            assert!(is_checksum_file(Path::new(name)), "{name}");
        }
        for name in ["setup.exe", "notes.txt", "sums.zip"] {
            assert!(!is_checksum_file(Path::new(name)), "{name}");
        }
    }
}
