//! Calcul des empreintes et lecture des empreintes saisies par l'utilisateur.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::io::{self, Read};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algo {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Crc32,
}

impl Algo {
    pub const ALL: [Algo; 5] = [Algo::Sha256, Algo::Sha512, Algo::Sha1, Algo::Md5, Algo::Crc32];

    pub fn name(self) -> &'static str {
        match self {
            Algo::Md5 => "MD5",
            Algo::Sha1 => "SHA-1",
            Algo::Sha256 => "SHA-256",
            Algo::Sha512 => "SHA-512",
            Algo::Crc32 => "CRC32",
        }
    }

    /// Algorithme qui ne protège pas contre une modification volontaire.
    pub fn is_weak(self) -> bool {
        !matches!(self, Algo::Sha256 | Algo::Sha512)
    }

    /// Les longueurs sont toutes différentes : elles suffisent à reconnaître l'algorithme.
    pub fn from_hex_len(len: usize) -> Option<Algo> {
        match len {
            8 => Some(Algo::Crc32),
            32 => Some(Algo::Md5),
            40 => Some(Algo::Sha1),
            64 => Some(Algo::Sha256),
            128 => Some(Algo::Sha512),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub crc32: String,
}

impl Hashes {
    pub fn get(&self, algo: Algo) -> &str {
        match algo {
            Algo::Md5 => &self.md5,
            Algo::Sha1 => &self.sha1,
            Algo::Sha256 => &self.sha256,
            Algo::Sha512 => &self.sha512,
            Algo::Crc32 => &self.crc32,
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lit `reader` jusqu'au bout. Renvoie `None` si `keep_going` demande l'arrêt.
pub fn hash_reader(
    mut reader: impl Read,
    mut keep_going: impl FnMut(u64) -> bool,
) -> io::Result<Option<Hashes>> {
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut crc = crc32fast::Hasher::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut done = 0u64;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let chunk = &buffer[..read];
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
        sha512.update(chunk);
        crc.update(chunk);
        done += read as u64;
        if !keep_going(done) {
            return Ok(None);
        }
    }
    Ok(Some(Hashes {
        md5: to_hex(&md5.finalize()),
        sha1: to_hex(&sha1.finalize()),
        sha256: to_hex(&sha256.finalize()),
        sha512: to_hex(&sha512.finalize()),
        crc32: format!("{:08x}", crc.finalize()),
    }))
}

/// Reconnaît une empreinte dans un texte collé : `ABC…`, `sha256:abc…`, `ab:cd…`,
/// ou une ligne `empreinte  fichier`.
pub fn parse_expected(text: &str) -> Option<(Algo, String)> {
    let text = text.trim();
    if let Some(found) = parse_token(text) {
        return Some(found);
    }
    text.split_whitespace().find_map(parse_token)
}

fn parse_token(token: &str) -> Option<(Algo, String)> {
    let lower = token.trim().to_ascii_lowercase();
    let body = lower.rsplit_once(['=', '/']).map_or(lower.as_str(), |(_, b)| b);
    let body = ["sha256:", "sha512:", "sha1:", "md5:", "crc32:"]
        .iter()
        .find_map(|p| body.strip_prefix(p))
        .unwrap_or(body);
    let clean: String = body.chars().filter(|c| !matches!(c, ':' | ' ' | '-')).collect();
    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Algo::from_hex_len(clean.len()).map(|algo| (algo, clean))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hashes(data: &[u8]) -> Hashes {
        hash_reader(data, |_| true).unwrap().unwrap()
    }

    #[test]
    fn valeurs_de_reference_pour_abc() {
        let h = hashes(b"abc");
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(h.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            h.sha512,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(h.crc32, "352441c2");
    }

    #[test]
    fn fichier_vide() {
        let h = hashes(b"");
        assert_eq!(h.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(h.crc32, "00000000");
    }

    #[test]
    fn annulation() {
        let result = hash_reader(&b"abc"[..], |_| false).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn reconnait_les_formats_colles() {
        let md5 = "900150983cd24fb0d6963f7d28e17f72";
        assert_eq!(parse_expected(md5), Some((Algo::Md5, md5.into())));
        assert_eq!(parse_expected(&md5.to_uppercase()), Some((Algo::Md5, md5.into())));
        assert_eq!(parse_expected(&format!("  md5:{md5} \n")), Some((Algo::Md5, md5.into())));
        assert_eq!(parse_expected(&format!("{md5}  setup.exe")), Some((Algo::Md5, md5.into())));
        assert_eq!(parse_expected("35:24:41:c2"), Some((Algo::Crc32, "352441c2".into())));
        assert_eq!(
            parse_expected(&format!("SHA256 (a.zip) = {}", "a".repeat(64))),
            Some((Algo::Sha256, "a".repeat(64)))
        );
    }

    #[test]
    fn refuse_ce_qui_n_est_pas_une_empreinte() {
        assert_eq!(parse_expected(""), None);
        assert_eq!(parse_expected("bonjour tout le monde"), None);
        assert_eq!(parse_expected(&"z".repeat(32)), None);
        assert_eq!(parse_expected(&"a".repeat(33)), None);
    }
}
