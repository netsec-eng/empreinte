//! Entrée « Vérifier avec Empreinte » du clic droit, pour le compte courant uniquement.

use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
use winreg::RegKey;

const KEYS: [&str; 2] = [
    r"Software\Classes\*\shell\Empreinte",
    r"Software\Classes\Directory\shell\Empreinte",
];

pub fn is_installed() -> bool {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    KEYS.iter().all(|key| hkcu.open_subkey_with_flags(key, KEY_READ).is_ok())
}

pub fn install() -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let exe = exe.to_string_lossy();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    for key in KEYS {
        let (entry, _) = hkcu.create_subkey(key)?;
        entry.set_value("", &"Vérifier avec Empreinte")?;
        entry.set_value("Icon", &exe.to_string())?;
        let (command, _) = entry.create_subkey("command")?;
        command.set_value("", &format!("\"{exe}\" \"%1\""))?;
    }
    Ok(())
}

pub fn uninstall() -> std::io::Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    for key in KEYS {
        match hkcu.delete_subkey_all(key) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Modifie le vrai registre du compte : à lancer à la main avec `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn installation_puis_retrait() {
        assert!(!is_installed(), "l'entrée existe déjà : test annulé pour ne pas la supprimer");
        install().unwrap();
        assert!(is_installed());
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let command: String =
            hkcu.open_subkey(format!(r"{}\command", KEYS[0])).unwrap().get_value("").unwrap();
        assert!(command.ends_with("\" \"%1\""), "{command}");
        uninstall().unwrap();
        assert!(!is_installed());
    }
}
