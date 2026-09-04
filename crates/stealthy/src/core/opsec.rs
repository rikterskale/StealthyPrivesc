//! Compile-time string policy for the `opsec-string-strip` flavor.
//!
//! The constrained flavor keeps authorization, plugin IDs, and audit fields.
//! It omits product brand, GTFOBins/LOLBAS URLs, repository URLs, and
//! third-party vendor catalog text so those literals are not in the binary.

#[cfg(not(feature = "opsec-string-strip"))]
pub const BRAND: &str = "StealthyPrivesc";
#[cfg(feature = "opsec-string-strip")]
pub const BRAND: &str = "host-inventory";

#[cfg(not(feature = "opsec-string-strip"))]
pub const REPO_URL: &str = "https://github.com/rikterskale/StealthyPrivesc";
#[cfg(feature = "opsec-string-strip")]
pub const REPO_URL: &str = "urn:local:inventory";

#[cfg(not(feature = "opsec-string-strip"))]
#[cfg_attr(windows, allow(dead_code))]
pub const GTFO_TECHNIQUE: &str = "gtfobins";
#[cfg(feature = "opsec-string-strip")]
#[cfg_attr(windows, allow(dead_code))]
pub const GTFO_TECHNIQUE: &str = "set-id";

#[cfg_attr(not(windows), allow(dead_code))]
#[cfg(not(feature = "opsec-string-strip"))]
pub const LOLBAS_TECHNIQUE: &str = "lolbas";
#[cfg_attr(not(windows), allow(dead_code))]
#[cfg(feature = "opsec-string-strip")]
pub const LOLBAS_TECHNIQUE: &str = "binary-path";

#[cfg(not(feature = "opsec-string-strip"))]
#[cfg_attr(windows, allow(dead_code))]
pub fn gtfobins_detail(binary: &str, functions: &str) -> Option<String> {
    Some(format!(
        "gtfobins.binary={binary} gtfobins.functions={functions} gtfobins.url=https://gtfobins.github.io/gtfobins/{binary}/ recommend_only=true"
    ))
}

#[cfg(feature = "opsec-string-strip")]
#[cfg_attr(windows, allow(dead_code))]
pub fn gtfobins_detail(_binary: &str, _functions: &str) -> Option<String> {
    None
}

#[cfg_attr(not(windows), allow(dead_code))]
#[cfg(not(feature = "opsec-string-strip"))]
pub fn lolbas_detail(binary: &str, page: &str, functions: &str) -> Option<String> {
    Some(format!(
        "lolbas.binary={binary} lolbas.functions={functions} lolbas.url=https://lolbas-project.github.io/lolbas/Binaries/{page}/ recommend_only=true"
    ))
}

#[cfg_attr(not(windows), allow(dead_code))]
#[cfg(feature = "opsec-string-strip")]
pub fn lolbas_detail(_binary: &str, _page: &str, _functions: &str) -> Option<String> {
    None
}

/// Third-party AV/EDR name fragments used for read-only product hints.
/// Empty in the OPSEC flavor so vendor brands are not in the binary.
#[cfg_attr(not(windows), allow(dead_code))]
#[cfg(not(feature = "opsec-string-strip"))]
pub const THIRD_PARTY_SENSOR_NEEDLES: &[&str] = &[
    "crowdstrike",
    "falcon",
    "sentinel",
    "carbon black",
    "cylance",
    "symantec",
    "norton",
    "mcafee",
    "trellix",
    "kaspersky",
    "eset",
    "trend micro",
    "sophos",
    "bitdefender",
    "cortex",
    "tanium",
];

#[cfg(feature = "opsec-string-strip")]
pub const THIRD_PARTY_SENSOR_NEEDLES: &[&str] = &[];

#[cfg_attr(not(windows), allow(dead_code))]
pub fn third_party_sensor_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    THIRD_PARTY_SENSOR_NEEDLES
        .iter()
        .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::{gtfobins_detail, lolbas_detail, BRAND, REPO_URL};

    #[cfg(not(feature = "opsec-string-strip"))]
    #[test]
    fn default_flavor_keeps_brand_and_catalog_urls() {
        assert_eq!(BRAND, "StealthyPrivesc");
        assert!(REPO_URL.contains("github.com"));
        let gtfo = gtfobins_detail("find", "shell,sudo").unwrap();
        assert!(gtfo.contains("gtfobins.github.io"));
        let lolbas = lolbas_detail("certutil.exe", "Certutil", "download").unwrap();
        assert!(lolbas.contains("lolbas-project.github.io"));
    }

    #[cfg(feature = "opsec-string-strip")]
    #[test]
    fn opsec_flavor_omits_brand_and_catalog_urls() {
        assert_ne!(BRAND, "StealthyPrivesc");
        assert!(!BRAND.contains("Stealthy"));
        assert!(!REPO_URL.contains("github.com"));
        assert!(!REPO_URL.contains("StealthyPrivesc"));
        assert!(gtfobins_detail("find", "shell,sudo").is_none());
        assert!(lolbas_detail("certutil.exe", "Certutil", "download").is_none());
    }
}
