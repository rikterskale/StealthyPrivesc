//! Native Authenticode / PE metadata inspection.
//!
//! Windows builds use WinVerifyTrust, CryptQueryObject, and version resources
//! instead of spawning a PowerShell child. Linux builds only expose status
//! mapping for tests.

#![cfg_attr(not(windows), allow(dead_code))]

/// Map a WinVerifyTrust HRESULT-style code to Authenticode status labels.
pub fn status_from_trust_result(code: i32) -> &'static str {
    match code as u32 {
        0 => "valid",
        0x800B_0100 => "notsigned", // TRUST_E_NOSIGNATURE
        0x8009_6010 | 0x8009_601C => "hashmismatch", // TRUST_E_BAD_DIGEST / MALFORMED
        0x800B_0109 | 0x800B_010A | 0x800B_0004 | 0x800B_0111 => "nottrusted",
        _ => "unknownerror",
    }
}

/// PascalCase labels matching the Windows Authenticode status enum.
pub fn status_pascal_case(status: &str) -> &'static str {
    match status {
        "valid" => "Valid",
        "notsigned" => "NotSigned",
        "hashmismatch" => "HashMismatch",
        "nottrusted" => "NotTrusted",
        _ => "UnknownError",
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthenticodeInfo {
    pub status: String,
    pub signer: String,
    pub publisher: String,
    pub product: String,
    pub file_version: String,
    pub original_filename: String,
    pub origin: String,
    pub timestamp: String,
    pub chain: String,
    pub issuer: String,
}

impl AuthenticodeInfo {
    pub fn missing() -> Self {
        Self {
            status: "not_collected".into(),
            origin: "unknown".into(),
            chain: "unknown".into(),
            ..Self::default()
        }
    }

    pub fn into_tuple(
        self,
    ) -> (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    ) {
        (
            self.status,
            self.signer,
            self.publisher,
            self.product,
            self.file_version,
            self.original_filename,
            self.origin,
            self.timestamp,
            self.chain,
        )
    }

    pub fn driver_signature_json(&self) -> String {
        serde_json::json!({
            "Status": status_pascal_case(&self.status),
            "Signer": self.signer,
            "Publisher": self.issuer,
        })
        .to_string()
    }
}

#[cfg(windows)]
pub fn inspect(path: &std::path::Path) -> AuthenticodeInfo {
    windows_impl::inspect(path)
}

#[cfg(not(windows))]
pub fn inspect(_path: &std::path::Path) -> AuthenticodeInfo {
    AuthenticodeInfo::missing()
}

#[cfg(windows)]
mod windows_impl {
    use super::{status_from_trust_result, AuthenticodeInfo};
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;
    use windows_sys::Win32::Foundation::{HANDLE, HWND, TRUE};
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW,
        CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_CONTEXT, CERT_FIND_SUBJECT_CERT,
        CERT_NAME_ISSUER_FLAG, CERT_NAME_RDN_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CERT_X500_NAME_STR,
        CMSG_SIGNER_CERT_INFO_PARAM, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
        WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2,
        WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
        WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
    };

    struct TrustNames {
        status: &'static str,
        chain: String,
        signer: String,
        issuer: String,
        timestamp: String,
    }

    pub fn inspect(path: &Path) -> AuthenticodeInfo {
        if !path.is_file() {
            return AuthenticodeInfo::missing();
        }
        let wide = to_wide(path);
        let trust = verify_trust(&wide);
        let mut signer = trust.signer;
        let mut issuer = trust.issuer;
        if signer.is_empty() {
            let embedded = signer_from_embedded(&wide);
            signer = embedded.0;
            issuer = embedded.1;
        }
        let (publisher, product, file_version, original_filename) = version_info(&wide);
        AuthenticodeInfo {
            status: trust.status.into(),
            signer,
            publisher,
            product,
            file_version,
            original_filename,
            origin: zone_origin(path),
            timestamp: trust.timestamp,
            chain: trust.chain,
            issuer,
        }
    }

    fn verify_trust(path: &[u16]) -> TrustNames {
        unsafe {
            let mut file = WINTRUST_FILE_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
                pcwszFilePath: path.as_ptr(),
                hFile: ptr::null_mut::<c_void>() as HANDLE,
                pgKnownSubject: ptr::null_mut(),
            };
            let mut data = WINTRUST_DATA {
                cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                pPolicyCallbackData: ptr::null_mut(),
                pSIPClientData: ptr::null_mut(),
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_FILE,
                Anonymous: WINTRUST_DATA_0 {
                    pFile: ptr::null_mut(),
                },
                dwStateAction: WTD_STATEACTION_VERIFY,
                hWVTStateData: ptr::null_mut::<c_void>() as HANDLE,
                pwszURLReference: ptr::null_mut(),
                dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
                dwUIContext: 0,
                pSignatureSettings: ptr::null_mut(),
            };
            data.Anonymous.pFile = &mut file;
            let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            let code = WinVerifyTrust(INVALID_HWND, &mut action, &mut data as *mut _ as *mut _);
            let (signer, issuer, timestamp) = signer_from_state(data.hWVTStateData);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(INVALID_HWND, &mut action, &mut data as *mut _ as *mut _);
            let status = status_from_trust_result(code);
            let chain = if code == 0 {
                "true".into()
            } else {
                format!("0x{:08x}", code as u32)
            };
            TrustNames {
                status,
                chain,
                signer,
                issuer,
                timestamp,
            }
        }
    }

    fn signer_from_state(state: HANDLE) -> (String, String, String) {
        unsafe {
            if state.is_null() {
                return Default::default();
            }
            let prov = WTHelperProvDataFromStateData(state);
            if prov.is_null() {
                return Default::default();
            }
            let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
            let (signer, issuer) = names_from_provider_signer(sgnr);
            let ts = WTHelperGetProvSignerFromChain(prov, 0, TRUE, 0);
            let (timestamp, _) = names_from_provider_signer(ts);
            (signer, issuer, timestamp)
        }
    }

    fn names_from_provider_signer(
        sgnr: *mut windows_sys::Win32::Security::WinTrust::CRYPT_PROVIDER_SGNR,
    ) -> (String, String) {
        unsafe {
            if sgnr.is_null() {
                return Default::default();
            }
            let cert = WTHelperGetProvCertFromChain(sgnr, 0);
            if cert.is_null() {
                return Default::default();
            }
            let ctx = (*cert).pCert;
            if ctx.is_null() {
                return Default::default();
            }
            (cert_name(ctx, 0), cert_name(ctx, CERT_NAME_ISSUER_FLAG))
        }
    }

    fn signer_from_embedded(path: &[u16]) -> (String, String) {
        unsafe {
            let mut store: HCERTSTORE = ptr::null_mut();
            let mut msg = ptr::null_mut();
            let ok = CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                path.as_ptr() as *const _,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut store,
                &mut msg,
                ptr::null_mut(),
            );
            if ok == 0 {
                return Default::default();
            }
            let mut size = 0u32;
            let queried = CryptMsgGetParam(
                msg,
                CMSG_SIGNER_CERT_INFO_PARAM,
                0,
                ptr::null_mut(),
                &mut size,
            );
            let names = if queried == 0 || size == 0 {
                Default::default()
            } else {
                let mut info = vec![0u8; size as usize];
                if CryptMsgGetParam(
                    msg,
                    CMSG_SIGNER_CERT_INFO_PARAM,
                    0,
                    info.as_mut_ptr() as *mut _,
                    &mut size,
                ) == 0
                {
                    Default::default()
                } else {
                    let cert = CertFindCertificateInStore(
                        store,
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        info.as_ptr() as *const _,
                        ptr::null(),
                    );
                    if cert.is_null() {
                        Default::default()
                    } else {
                        let pair = (cert_name(cert, 0), cert_name(cert, CERT_NAME_ISSUER_FLAG));
                        let _ = CertFreeCertificateContext(cert);
                        pair
                    }
                }
            };
            if !msg.is_null() {
                let _ = CryptMsgClose(msg);
            }
            if !store.is_null() {
                let _ = CertCloseStore(store, 0);
            }
            names
        }
    }

    fn cert_name(cert: *const CERT_CONTEXT, flags: u32) -> String {
        unsafe {
            let mut type_para = CERT_X500_NAME_STR;
            let needed = CertGetNameStringW(
                cert,
                CERT_NAME_RDN_TYPE,
                flags,
                &mut type_para as *mut _ as *const _,
                ptr::null_mut(),
                0,
            );
            if needed <= 1 {
                return String::new();
            }
            let mut buf = vec![0u16; needed as usize];
            let written = CertGetNameStringW(
                cert,
                CERT_NAME_RDN_TYPE,
                flags,
                &mut type_para as *mut _ as *const _,
                buf.as_mut_ptr(),
                needed,
            );
            if written <= 1 {
                return String::new();
            }
            String::from_utf16_lossy(&buf[..written as usize - 1])
        }
    }

    fn version_info(path: &[u16]) -> (String, String, String, String) {
        unsafe {
            let mut handle = 0u32;
            let size = GetFileVersionInfoSizeW(path.as_ptr(), &mut handle);
            if size == 0 {
                return Default::default();
            }
            let mut block = vec![0u8; size as usize];
            if GetFileVersionInfoW(path.as_ptr(), 0, size, block.as_mut_ptr() as *mut _) == 0 {
                return Default::default();
            }
            let translation = version_bytes(&block, &to_wide_str("\\VarFileInfo\\Translation"));
            let lang = if translation.len() >= 4 {
                format!(
                    "{:02x}{:02x}{:02x}{:02x}",
                    translation[1], translation[0], translation[3], translation[2]
                )
            } else {
                "040904b0".into()
            };
            let query = |name: &str| {
                let sub = format!("\\StringFileInfo\\{lang}\\{name}");
                wide_to_string(&version_wide(&block, &to_wide_str(&sub)))
            };
            (
                query("CompanyName"),
                query("ProductName"),
                query("FileVersion"),
                query("OriginalFilename"),
            )
        }
    }

    fn version_bytes(block: &[u8], key: &[u16]) -> Vec<u8> {
        unsafe {
            let mut value_ptr: *mut c_void = ptr::null_mut();
            let mut len = 0u32;
            if VerQueryValueW(
                block.as_ptr() as *const _,
                key.as_ptr(),
                &mut value_ptr,
                &mut len,
            ) == 0
                || value_ptr.is_null()
                || len == 0
            {
                return Vec::new();
            }
            std::slice::from_raw_parts(value_ptr as *const u8, len as usize).to_vec()
        }
    }

    fn version_wide(block: &[u8], key: &[u16]) -> Vec<u16> {
        unsafe {
            let mut value_ptr: *mut c_void = ptr::null_mut();
            let mut len = 0u32;
            if VerQueryValueW(
                block.as_ptr() as *const _,
                key.as_ptr(),
                &mut value_ptr,
                &mut len,
            ) == 0
                || value_ptr.is_null()
                || len == 0
            {
                return Vec::new();
            }
            std::slice::from_raw_parts(value_ptr as *const u16, (len as usize) / 2)
                .iter()
                .copied()
                .take_while(|c| *c != 0)
                .collect()
        }
    }

    fn zone_origin(path: &Path) -> String {
        let mut ads = path.as_os_str().to_os_string();
        ads.push(":Zone.Identifier");
        if std::fs::read(&ads).is_ok() {
            "downloaded-zone-identifier".into()
        } else {
            "local-or-unknown".into()
        }
    }

    fn to_wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn to_wide_str(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn wide_to_string(value: &[u16]) -> String {
        String::from_utf16_lossy(value)
    }

    const INVALID_HWND: HWND = -1isize as HWND;
}

#[cfg(test)]
mod tests {
    use super::{status_from_trust_result, status_pascal_case, AuthenticodeInfo};

    #[test]
    fn maps_winverifytrust_codes() {
        assert_eq!(status_from_trust_result(0), "valid");
        assert_eq!(status_from_trust_result(0x800B_0100u32 as i32), "notsigned");
        assert_eq!(
            status_from_trust_result(0x8009_6010u32 as i32),
            "hashmismatch"
        );
        assert_eq!(
            status_from_trust_result(0x800B_0109u32 as i32),
            "nottrusted"
        );
        assert_eq!(status_from_trust_result(1), "unknownerror");
        assert_eq!(status_pascal_case("valid"), "Valid");
        assert_eq!(status_pascal_case("notsigned"), "NotSigned");
        assert_eq!(status_pascal_case("mystery"), "UnknownError");
    }

    #[test]
    fn missing_tuple_has_not_collected_status() {
        let (status, _, _, _, _, _, origin, _, chain) = AuthenticodeInfo::missing().into_tuple();
        assert_eq!(status, "not_collected");
        assert_eq!(origin, "unknown");
        assert_eq!(chain, "unknown");
    }

    #[test]
    fn authenticode_module_does_not_spawn_helper() {
        let src = include_str!("authenticode.rs");
        assert!(!src.contains(concat!("powershell", ".exe")));
        assert!(!src.contains(concat!("Get-Authenticode", "Signature")));
    }

    #[test]
    fn driver_json_uses_issuer_as_publisher() {
        let info = AuthenticodeInfo {
            status: "valid".into(),
            signer: "CN=Example".into(),
            issuer: "CN=Issuer".into(),
            publisher: "Contoso".into(),
            ..AuthenticodeInfo::default()
        };
        let json = info.driver_signature_json();
        assert!(json.contains("\"Status\":\"Valid\""));
        assert!(json.contains("\"Signer\":\"CN=Example\""));
        assert!(json.contains("\"Publisher\":\"CN=Issuer\""));
        assert!(!json.contains("Contoso"));
    }

    #[cfg(not(windows))]
    #[test]
    fn inspect_is_unavailable_off_windows() {
        let info = super::inspect(std::path::Path::new("/bin/true"));
        assert_eq!(info.status, "not_collected");
        assert_eq!(info.origin, "unknown");
    }

    #[cfg(windows)]
    #[test]
    fn unsigned_file_is_not_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsigned.bin");
        std::fs::write(&path, b"MZ").unwrap();
        let info = super::inspect(&path);
        assert_ne!(info.status, "valid");
        assert_eq!(info.origin, "local-or-unknown");
    }
}
