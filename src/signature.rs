//! Signature numérique Windows (Authenticode) des fichiers exécutables.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigStatus {
    Valid { signer: String },
    Unsigned,
    /// Le fichier a été modifié après sa signature.
    Tampered,
    Untrusted(String),
}

pub fn is_signable(path: &Path) -> bool {
    let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase());
    matches!(ext.as_deref(), Some("exe" | "msi" | "dll" | "sys" | "cab" | "msix" | "appx"))
}

const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B_0001;
const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B_0003;
const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
const CERT_E_EXPIRED: u32 = 0x800B_0101;
const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B_0111;
const TRUST_E_BAD_DIGEST: u32 = 0x8009_6010;

/// La révocation n'est pas contrôlée : elle exigerait un accès réseau à chaque fichier.
pub fn check(path: &Path) -> SigStatus {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        let mut file: WINTRUST_FILE_INFO = std::mem::zeroed();
        file.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        file.pcwszFilePath = wide.as_ptr();

        let mut data: WINTRUST_DATA = std::mem::zeroed();
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &mut file;
        data.dwStateAction = WTD_STATEACTION_VERIFY;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let code = WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut _,
        ) as u32;

        let status = match code {
            0 => SigStatus::Valid {
                signer: signer_name(&data).unwrap_or_else(|| "éditeur inconnu".to_string()),
            },
            TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => {
                SigStatus::Unsigned
            }
            TRUST_E_BAD_DIGEST => SigStatus::Tampered,
            CERT_E_EXPIRED => SigStatus::Untrusted("certificat expiré".to_string()),
            CERT_E_UNTRUSTEDROOT => {
                SigStatus::Untrusted("certificat d'une autorité non reconnue".to_string())
            }
            TRUST_E_EXPLICIT_DISTRUST => {
                SigStatus::Untrusted("certificat explicitement rejeté".to_string())
            }
            other => SigStatus::Untrusted(format!("signature refusée par Windows (0x{other:08X})")),
        };

        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut _,
        );
        status
    }
}

unsafe fn signer_name(data: &WINTRUST_DATA) -> Option<String> {
    let provider = WTHelperProvDataFromStateData(data.hWVTStateData);
    if provider.is_null() {
        return None;
    }
    let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
    if signer.is_null() {
        return None;
    }
    let cert = WTHelperGetProvCertFromChain(signer, 0);
    if cert.is_null() {
        return None;
    }
    let context = (*cert).pCert;
    let mut buffer = [0u16; 256];
    let len = CertGetNameStringW(
        context,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        std::ptr::null(),
        buffer.as_mut_ptr(),
        buffer.len() as u32,
    );
    (len > 1).then(|| String::from_utf16_lossy(&buffer[..len as usize - 1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fichier_texte_non_signe() {
        let dir = std::env::temp_dir().join(format!("empreinte-sig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("texte.exe");
        std::fs::write(&path, b"pas un programme").unwrap();
        assert_eq!(check(&path), SigStatus::Unsigned);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn composant_signe_de_windows() {
        let path = Path::new(r"C:\Windows\explorer.exe");
        match check(path) {
            SigStatus::Valid { signer } => assert!(signer.contains("Microsoft"), "{signer}"),
            // Sur certaines versions, explorer.exe n'est signé que par catalogue.
            SigStatus::Unsigned => {}
            other => panic!("{other:?}"),
        }
    }
}
