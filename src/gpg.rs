//! Vérification des signatures GPG détachées (`.sig`, `.asc`) avec une clé publique fournie.

use pgp::types::PublicKeyTrait;
use pgp::{Deserializable, SignedPublicKey, StandaloneSignature};
use std::fs::File;
use std::io::{BufReader, Cursor};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpgOk {
    pub fingerprint: String,
    pub identities: Vec<String>,
}

fn is_armored(bytes: &[u8]) -> bool {
    let start = bytes.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(0);
    bytes[start..].starts_with(b"-----BEGIN")
}

fn parse<T: Deserializable>(bytes: &[u8]) -> Result<T, String> {
    if is_armored(bytes) {
        T::from_armor_single(Cursor::new(bytes)).map(|(v, _)| v).map_err(|e| e.to_string())
    } else {
        T::from_bytes(Cursor::new(bytes)).map_err(|e| e.to_string())
    }
}

/// Indique si un fichier `.asc` contient une clé publique et non une signature.
pub fn looks_like_public_key(path: &Path) -> bool {
    std::fs::read(path)
        .map(|bytes| bytes.windows(10).take(4096).any(|w| w == b"PUBLIC KEY"))
        .unwrap_or(false)
}

pub fn verify(file: &Path, signature: &Path, key: &Path) -> Result<GpgOk, String> {
    let key_bytes = std::fs::read(key).map_err(|e| format!("Clé illisible : {e}"))?;
    let key: SignedPublicKey =
        parse(&key_bytes).map_err(|e| format!("Ce fichier n'est pas une clé publique valable : {e}"))?;
    key.verify().map_err(|e| format!("La clé publique est invalide : {e}"))?;

    let sig_bytes = std::fs::read(signature).map_err(|e| format!("Signature illisible : {e}"))?;
    let sig: StandaloneSignature =
        parse(&sig_bytes).map_err(|e| format!("Ce fichier n'est pas une signature valable : {e}"))?;

    let open = || {
        File::open(file).map(BufReader::new).map_err(|e| format!("Fichier illisible : {e}"))
    };
    let mut valid = sig.signature.verify(&key, open()?).is_ok();
    if !valid {
        for subkey in &key.public_subkeys {
            if sig.signature.verify(subkey, open()?).is_ok() {
                valid = true;
                break;
            }
        }
    }
    if !valid {
        return Err(
            "Signature INVALIDE : le fichier a été modifié, ou il a été signé avec une autre clé."
                .to_string(),
        );
    }
    Ok(GpgOk {
        fingerprint: key
            .fingerprint()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect(),
        identities: key
            .details
            .users
            .iter()
            .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
            .collect(),
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
    use pgp::types::SecretKeyTrait;
    use pgp::{ArmorOptions, KeyType, SecretKeyParamsBuilder, SignedSecretKey};
    use std::path::PathBuf;

    fn new_key(user: &str) -> (SignedSecretKey, SignedPublicKey) {
        let mut rng = rand::thread_rng();
        let secret = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id(user.to_string())
            .build()
            .unwrap()
            .generate(&mut rng)
            .unwrap()
            .sign(&mut rng, String::new)
            .unwrap();
        let public = secret.public_key().sign(&mut rng, &secret, String::new).unwrap();
        (secret, public)
    }

    fn sign(secret: &SignedSecretKey, data: &[u8]) -> StandaloneSignature {
        let mut config = SignatureConfig::v4(SignatureType::Binary, secret.algorithm(), HashAlgorithm::SHA2_256);
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(chrono::Utc::now())),
            Subpacket::regular(SubpacketData::Issuer(secret.key_id())),
        ];
        StandaloneSignature::new(config.sign(secret, String::new, data).unwrap())
    }

    struct Fixture {
        dir: PathBuf,
        file: PathBuf,
        signature: PathBuf,
        key: PathBuf,
    }

    fn fixture(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("empreinte-gpg-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (secret, public) = new_key("Éditeur <editeur@example.com>");
        let file = dir.join("logiciel.zip");
        std::fs::write(&file, b"contenu authentique").unwrap();
        let signature = dir.join("logiciel.zip.asc");
        let armored = sign(&secret, b"contenu authentique").to_armored_string(ArmorOptions::default()).unwrap();
        std::fs::write(&signature, armored).unwrap();
        let key = dir.join("cle.asc");
        std::fs::write(&key, public.to_armored_string(ArmorOptions::default()).unwrap()).unwrap();
        Fixture { dir, file, signature, key }
    }

    #[test]
    fn signature_valide() {
        let f = fixture("ok");
        let ok = verify(&f.file, &f.signature, &f.key).unwrap();
        assert_eq!(ok.identities, ["Éditeur <editeur@example.com>"]);
        assert_eq!(ok.fingerprint.len(), 40);
        assert!(looks_like_public_key(&f.key));
        assert!(!looks_like_public_key(&f.signature));
        std::fs::remove_dir_all(&f.dir).unwrap();
    }

    #[test]
    fn fichier_falsifie() {
        let f = fixture("falsifie");
        std::fs::write(&f.file, b"contenu remplace").unwrap();
        assert!(verify(&f.file, &f.signature, &f.key).unwrap_err().contains("INVALIDE"));
        std::fs::remove_dir_all(&f.dir).unwrap();
    }

    #[test]
    fn signe_avec_une_autre_cle() {
        let f = fixture("autre");
        let (_, other) = new_key("Pirate <pirate@example.com>");
        std::fs::write(&f.key, other.to_armored_string(ArmorOptions::default()).unwrap()).unwrap();
        assert!(verify(&f.file, &f.signature, &f.key).unwrap_err().contains("INVALIDE"));
        std::fs::remove_dir_all(&f.dir).unwrap();
    }

    #[test]
    fn fichiers_inverses() {
        let f = fixture("inverse");
        assert!(verify(&f.file, &f.key, &f.signature).is_err());
        std::fs::remove_dir_all(&f.dir).unwrap();
    }
}