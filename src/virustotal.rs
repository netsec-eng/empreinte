//! Recherche d'une empreinte sur VirusTotal. Le fichier lui-même n'est jamais envoyé.

use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VtReport {
    Known { malicious: u64, suspicious: u64, clean: u64 },
    Unknown,
}

pub fn lookup(sha256: &str, api_key: &str) -> Result<VtReport, String> {
    let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
    let response = ureq::get(&url)
        .set("x-apikey", api_key)
        .timeout(Duration::from_secs(20))
        .call();
    match response {
        Ok(ok) => {
            let body: serde_json::Value =
                ok.into_json().map_err(|e| format!("Réponse illisible : {e}"))?;
            parse_report(&body).ok_or_else(|| "Réponse inattendue de VirusTotal.".to_string())
        }
        Err(ureq::Error::Status(404, _)) => Ok(VtReport::Unknown),
        Err(ureq::Error::Status(401, _)) => Err("Clé API refusée par VirusTotal.".to_string()),
        Err(ureq::Error::Status(429, _)) => {
            Err("Quota VirusTotal atteint. Réessaie plus tard.".to_string())
        }
        Err(ureq::Error::Status(code, _)) => Err(format!("VirusTotal a répondu l'erreur {code}.")),
        Err(e) => Err(format!("Connexion impossible : {e}")),
    }
}

fn parse_report(body: &serde_json::Value) -> Option<VtReport> {
    let stats = body.pointer("/data/attributes/last_analysis_stats")?;
    let count = |name: &str| stats.get(name).and_then(|v| v.as_u64()).unwrap_or(0);
    Some(VtReport::Known {
        malicious: count("malicious"),
        suspicious: count("suspicious"),
        clean: count("harmless") + count("undetected"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lit_les_statistiques() {
        let body = json!({"data": {"attributes": {"last_analysis_stats": {
            "malicious": 2, "suspicious": 1, "harmless": 10, "undetected": 50
        }}}});
        assert_eq!(
            parse_report(&body),
            Some(VtReport::Known { malicious: 2, suspicious: 1, clean: 60 })
        );
    }

    #[test]
    fn reponse_inattendue() {
        assert_eq!(parse_report(&json!({"error": "x"})), None);
    }
}
