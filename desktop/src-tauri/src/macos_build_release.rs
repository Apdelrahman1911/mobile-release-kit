//! Fixed source-selected build DATA, shared by the actual Cargo build and its
//! regression tests. No runtime selector, package/signing authority or IO.
#![forbid(unsafe_code)]

use serde::Deserialize;
#[path = "macos_build_profile.rs"]
mod profiles;
pub use profiles::{MacBuildProfiles, MacBuildTarget};

pub const INPUT_LIMIT: usize = 4096;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BuildReleaseInput {
    schema_version: u32,
    package_version: String,
    release: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BuildRelease {
    pub package_version: String,
    pub release: String,
    target: MacBuildTarget,
}

impl BuildRelease {
    /// Keep the existing ARM-only parser contract for legacy fixed consumers.
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        Self::parse_for(MacBuildTarget::Arm64, bytes)
    }

    pub fn parse_for(target: MacBuildTarget, bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > INPUT_LIMIT { return Err("build-release-size"); }
        // Derived structs also accept sequences; the wire contract is an object.
        if bytes.iter().copied().find(|b| !b" \t\r\n".contains(b)) != Some(b'{') {
            return Err("build-release-shape");
        }
        // Deserialize directly: duplicate fields must not be collapsed through
        // an intermediate serde_json::Value before the closed struct sees them.
        let value: BuildReleaseInput = serde_json::from_slice(bytes).map_err(|_| "build-release-shape")?;
        let parts: Vec<_> = value.package_version.split('.').collect();
        let version = value.package_version.len() <= 32 && parts.len() == 3
            && parts.iter().all(|part| !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0')) && part.parse::<u32>().is_ok());
        let prefix = target.release_prefix();
        let release = value.release.len() <= 128 && value.release.starts_with(prefix)
            && value.release.len() > prefix.len()
            && value.release.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
            && value.release.as_bytes().last().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        if value.schema_version != 1 || !version || !release { return Err("build-release-binding"); }
        Ok(Self { package_version: value.package_version, release: value.release, target })
    }

    /// Compile-time SOURCE DATA selection only. The Intel application/native
    /// execution gates remain closed until their independent port is qualified.
    pub fn from_source(cargo_target: &str, cargo_os: &str) -> Result<Self, &'static str> {
        let profiles = MacBuildProfiles::parse(include_bytes!("../../macos-installed-inputs/platforms-v1.json"))?;
        let target = profiles.select(cargo_target, cargo_os)?;
        match target {
            MacBuildTarget::Arm64 => Self::parse(include_bytes!("../../macos-installed-inputs/build-release.json")),
            MacBuildTarget::Intel => Self::parse_for(target, include_bytes!("../../macos-installed-inputs/build-release-intel.json")),
        }
    }

    pub fn check_projections(&self, cargo_version: &str, tauri_bytes: &[u8]) -> Result<(), &'static str> {
        // Tauri has its own complete config parser. This fixed source projection
        // reads only its version, while still refusing duplicate version keys.
        #[derive(Deserialize)]
        struct TauriVersion { version: String }
        if tauri_bytes.is_empty() || tauri_bytes.len() > 64 * 1024 { return Err("build-release-tauri-size"); }
        if tauri_bytes.iter().copied().find(|b| !b" \t\r\n".contains(b)) != Some(b'{') {
            return Err("build-release-tauri-shape");
        }
        let tauri: TauriVersion = serde_json::from_slice(tauri_bytes).map_err(|_| "build-release-tauri-shape")?;
        if cargo_version != self.package_version || tauri.version != self.package_version {
            return Err("build-release-version-projection");
        }
        Ok(())
    }

    pub fn declarations(&self) -> String {
        format!("// Generated from the fixed source {}; no runtime override.\n\
            pub const PACKAGE_VERSION: &str = {:?};\n\
            pub const RELEASE: &str = {:?};\n", self.target.release_input(), self.package_version, self.release)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fixed_source_matches_actual_compiled_constants_and_version_projections() {
        let value = BuildRelease::from_source(env!("MRK_COMPILED_TARGET"), std::env::consts::OS).unwrap();
        value.check_projections(env!("CARGO_PKG_VERSION"), include_bytes!("../tauri.conf.json")).unwrap();
        assert_eq!(value.package_version, crate::macos_install_paths::PACKAGE_VERSION);
        assert_eq!(value.release, crate::macos_install_paths::RELEASE);
        let arm = BuildRelease::parse(include_bytes!("../../macos-installed-inputs/build-release.json")).unwrap();
        assert_eq!(arm.package_version, "0.1.0");
        assert_eq!(arm.release, "macos26-arm64-entry-m2a-01"); // Engineering entry only, not a v2 publisher release.
        assert_eq!(arm.declarations(), concat!(
            "// Generated from the fixed source build-release.json; no runtime override.\n",
            "pub const PACKAGE_VERSION: &str = \"0.1.0\";\n",
            "pub const RELEASE: &str = \"macos26-arm64-entry-m2a-01\";\n"));
    }

    #[test]
    fn intel_source_input_and_cross_target_release_bindings_are_closed() {
        let arm_bytes = include_bytes!("../../macos-installed-inputs/build-release.json");
        let intel_bytes = include_bytes!("../../macos-installed-inputs/build-release-intel.json");
        let arm = BuildRelease::parse(arm_bytes).unwrap();
        let intel = BuildRelease::parse_for(MacBuildTarget::Intel, intel_bytes).unwrap();
        intel.check_projections(env!("CARGO_PKG_VERSION"), include_bytes!("../tauri.conf.json")).unwrap();
        assert_eq!(intel.release, "macos26-x86_64-entry-m2a-01");
        assert_eq!(BuildRelease::from_source("aarch64-apple-darwin", "macos").unwrap(), arm);
        assert_eq!(BuildRelease::from_source("x86_64-apple-darwin", "macos").unwrap(), intel);
        assert_eq!(BuildRelease::from_source("x86_64-unknown-linux-gnu", "linux").unwrap(), arm);
        assert_eq!(BuildRelease::from_source("x86_64-pc-windows-msvc", "windows").unwrap(), arm);
        assert!(BuildRelease::parse(intel_bytes).is_err());
        assert!(BuildRelease::parse_for(MacBuildTarget::Intel, arm_bytes).is_err());
        assert!(BuildRelease::parse_for(MacBuildTarget::Arm64, intel_bytes).is_err());
        assert!(BuildRelease::from_source("i686-apple-darwin", "macos").is_err());
        assert!(BuildRelease::from_source("x86_64-apple-darwin", "linux").is_err());
        assert_eq!(intel.declarations(), concat!(
            "// Generated from the fixed source build-release-intel.json; no runtime override.\n",
            "pub const PACKAGE_VERSION: &str = \"0.1.0\";\n",
            "pub const RELEASE: &str = \"macos26-x86_64-entry-m2a-01\";\n"));
    }

    #[test]
    fn closed_build_identity_and_projection_mutations_refuse() {
        let valid = json!({"schemaVersion":1,"packageVersion":"1.2.3","release":"macos26-arm64-example-02"});
        let value = BuildRelease::parse(&serde_json::to_vec(&valid).unwrap()).unwrap();
        value.check_projections("1.2.3", br#"{"version":"1.2.3","bundle":{"active":false}}"#).unwrap();
        let mut spaced = b" \t\r\n".to_vec();
        spaced.extend(serde_json::to_vec(&valid).unwrap());
        assert_eq!(BuildRelease::parse(&spaced).unwrap(), value);
        value.check_projections("1.2.3", b" \t\r\n{\"version\":\"1.2.3\"}").unwrap();
        for (field, replacement) in [
            ("schemaVersion", json!(2)), ("schemaVersion", json!(true)), ("schemaVersion", json!(1.0)),
            ("packageVersion", json!(null)), ("packageVersion", json!("01.2.3")),
            ("packageVersion", json!("1.2.3.4")), ("packageVersion", json!("1.2.-3")),
            ("packageVersion", json!("4294967296.2.3")), ("packageVersion", json!("1.2.3-beta")),
            ("release", json!("macos26-arm64-")), ("release", json!("macos26-arm64-example/02")),
            ("release", json!("macos26-arm64-example.")), ("release", json!("macos26-arm64-UPPER")),
            ("release", json!("macos26-arm64-".to_owned() + &"a".repeat(128))),
            ("extra", json!(false)),
        ] {
            let mut changed = valid.clone(); changed[field] = replacement;
            assert!(BuildRelease::parse(&serde_json::to_vec(&changed).unwrap()).is_err(), "{field}");
        }
        for raw in [b"".as_slice(), b"[]", b"{}", b"null",
            br#"[1,"1.2.3","macos26-arm64-example-02"]"#,
            b" \t\r\n[1,\"1.2.3\",\"macos26-arm64-example-02\"]",
            br#"{"schemaVersion":1,"packageVersion":"1.2.3","release":"macos26-arm64-example-02","release":"macos26-arm64-example-02"}"#,
            br#"{"schemaVersion":1,"packageVersion":"1.2.3","release":"macos26-arm64-example-02"} {}"#] {
            assert!(BuildRelease::parse(raw).is_err());
        }
        assert!(BuildRelease::parse(&vec![b' '; INPUT_LIMIT + 1]).is_err());
        assert!(value.check_projections("1.2.4", br#"{"version":"1.2.3"}"#).is_err());
        for raw in [b"".as_slice(), br#"{}"#, br#"{"version":123}"#, br#"{"version":"1.2.4"}"#,
            br#"["1.2.3"]"#, b" \t\r\n[\"1.2.3\"]",
            br#"{"version":"1.2.3","version":"1.2.3"}"#] {
            assert!(value.check_projections("1.2.3", raw).is_err());
        }
    }
}
