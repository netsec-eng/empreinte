//! Export des résultats en TXT ou CSV.

#[derive(Clone, Debug, Default)]
pub struct Row {
    pub path: String,
    pub size: u64,
    pub verdict: String,
    pub signature: String,
    pub sha256: String,
    pub sha512: String,
    pub sha1: String,
    pub md5: String,
    pub crc32: String,
}

/// Une cellule commençant par `=`, `+`, `-` ou `@` serait exécutée comme une formule par Excel.
/// Un nom de fichier venu d'Internet ne doit pas pouvoir le faire.
fn cell(value: &str) -> String {
    let safe = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    format!("\"{}\"", safe.replace('"', "\"\""))
}

/// Le séparateur `;` et le BOM permettent à Excel en français d'ouvrir le fichier directement.
pub fn to_csv(rows: &[Row]) -> String {
    let mut out = String::from("\u{feff}Fichier;Taille;Résultat;Signature;SHA-256;SHA-512;SHA-1;MD5;CRC32\r\n");
    for r in rows {
        let cells = [
            cell(&r.path),
            r.size.to_string(),
            cell(&r.verdict),
            cell(&r.signature),
            cell(&r.sha256),
            cell(&r.sha512),
            cell(&r.sha1),
            cell(&r.md5),
            cell(&r.crc32),
        ];
        out.push_str(&cells.join(";"));
        out.push_str("\r\n");
    }
    out
}

pub fn to_txt(rows: &[Row]) -> String {
    let mut out = format!(
        "Rapport Empreinte — {}\r\n\r\n",
        chrono::Local::now().format("%d/%m/%Y %H:%M")
    );
    for r in rows {
        out.push_str(&format!("{}\r\n  Taille    : {} octets\r\n  Résultat  : {}\r\n", r.path, r.size, r.verdict));
        if !r.signature.is_empty() {
            out.push_str(&format!("  Signature : {}\r\n", r.signature));
        }
        for (name, value) in [
            ("SHA-256", &r.sha256),
            ("SHA-512", &r.sha512),
            ("SHA-1", &r.sha1),
            ("MD5", &r.md5),
            ("CRC32", &r.crc32),
        ] {
            if !value.is_empty() {
                out.push_str(&format!("  {name:<9} : {value}\r\n"));
            }
        }
        out.push_str("\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutralise_les_formules_et_les_guillemets() {
        let rows = [Row { path: "=cmd|calc\".exe".into(), ..Row::default() }];
        let csv = to_csv(&rows);
        assert!(csv.contains("\"'=cmd|calc\"\".exe\""), "{csv}");
    }

    #[test]
    fn txt_omet_ce_qui_est_vide() {
        let rows = [Row { path: "a".into(), sha256: "abc".into(), ..Row::default() }];
        let txt = to_txt(&rows);
        assert!(txt.contains("SHA-256"));
        assert!(!txt.contains("MD5"));
    }
}
