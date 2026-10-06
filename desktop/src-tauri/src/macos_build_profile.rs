//! Closed SOURCE build identity only. This cannot admit a runtime, native ABI,
//! helper, installation, signing identity or qualification result.
#![forbid(unsafe_code)]

use serde::{de::{value::MapAccessDeserializer, MapAccess, Visitor}, Deserialize, Deserializer};

pub const PROFILE_INPUT_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacBuildTarget { Arm64, Intel }

impl MacBuildTarget {
    /// Actual Rust target shape only, never supplier or native qualification.
    /// Do not use the build-script HOST or the non-Mac declaration fallback.
    pub fn compiled() -> Option<Self> {
        if cfg!(all(target_os = "macos", target_arch = "aarch64", target_pointer_width = "64")) {
            Some(Self::Arm64)
        } else if cfg!(all(target_os = "macos", target_arch = "x86_64", target_pointer_width = "64")) {
            Some(Self::Intel)
        } else { None }
    }
    pub fn matches_compiled(target: &str) -> bool {
        Self::compiled().is_some_and(|selected| selected.target() == target)
    }
    pub fn target(self) -> &'static str {
        match self { Self::Arm64 => "aarch64-apple-darwin", Self::Intel => "x86_64-apple-darwin" }
    }
    pub fn release_input(self) -> &'static str {
        match self { Self::Arm64 => "build-release.json", Self::Intel => "build-release-intel.json" }
    }
    pub fn release_prefix(self) -> &'static str {
        match self { Self::Arm64 => "macos26-arm64-", Self::Intel => "macos26-x86_64-" }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Profile {
    machine: String,
    macho_cpu: u32,
    macho_subtype: u32,
    runner_arch: String,
    runner_label: String,
    release_input: String,
    release_prefix: String,
}

impl Profile {
    fn matches(&self, target: MacBuildTarget) -> bool {
        let (machine, cpu, subtype, arch, runner) = match target {
            MacBuildTarget::Arm64 => ("arm64", 0x0100000c, 0, "ARM64", "macos-26"),
            MacBuildTarget::Intel => ("x86_64", 0x01000007, 3, "X64", "macos-26-intel"),
        };
        self.machine == machine && self.macho_cpu == cpu && self.macho_subtype == subtype
            && self.runner_arch == arch && self.runner_label == runner
            && self.release_input == target.release_input()
            && self.release_prefix == target.release_prefix()
    }
}

// Serde's derived struct visitor also accepts a sequence. Every profile must
// instead be an object, and direct MapAccess preserves duplicate field errors.
fn profile_object<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Profile, D::Error> {
    struct Object;
    impl<'de> Visitor<'de> for Object {
        type Value = Profile;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a closed Mac build profile object")
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Profile, A::Error> {
            Profile::deserialize(MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileTable {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "aarch64-apple-darwin", deserialize_with = "profile_object")]
    arm64: Profile,
    #[serde(rename = "x86_64-apple-darwin", deserialize_with = "profile_object")]
    intel: Profile,
}

/// Proof only that the two fixed SOURCE entries matched their closed contract.
/// The private field prevents constructing this proof without parsing.
#[derive(Debug)]
pub struct MacBuildProfiles { _private: () }

impl MacBuildProfiles {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > PROFILE_INPUT_LIMIT { return Err("macos-profile-size"); }
        if bytes.iter().copied().find(|b| !b" \t\r\n".contains(b)) != Some(b'{') {
            return Err("macos-profile-shape");
        }
        let table: ProfileTable = serde_json::from_slice(bytes).map_err(|_| "macos-profile-shape")?;
        if table.schema_version != 1 || !table.arm64.matches(MacBuildTarget::Arm64)
            || !table.intel.matches(MacBuildTarget::Intel) {
            return Err("macos-profile-binding");
        }
        Ok(Self { _private: () })
    }

    /// Select build DATA from Cargo's actual target and target OS, never the
    /// build-script host. Non-Mac builds retain the old ARM declaration facade;
    /// that compatibility output is not a Mac execution/native profile.
    pub fn select(&self, cargo_target: &str, cargo_os: &str) -> Result<MacBuildTarget, &'static str> {
        if cargo_os == "macos" {
            return [MacBuildTarget::Arm64, MacBuildTarget::Intel].into_iter()
                .find(|target| cargo_target == target.target()).ok_or("macos-build-target");
        }
        if cargo_target.is_empty() || cargo_os.is_empty() || cargo_target.ends_with("-apple-darwin") {
            return Err("macos-build-target");
        }
        Ok(MacBuildTarget::Arm64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    const SOURCE: &[u8] = include_bytes!("../../macos-installed-inputs/platforms-v1.json");

    #[test]
    fn exact_source_profiles_select_cargo_target_not_host_or_native_permission() {
        let profiles = MacBuildProfiles::parse(SOURCE).unwrap();
        for target in [MacBuildTarget::Arm64, MacBuildTarget::Intel] {
            assert_eq!(profiles.select(target.target(), "macos"), Ok(target));
        }
        for (target, os) in [("x86_64-unknown-linux-gnu", "linux"), ("aarch64-unknown-linux-gnu", "linux"),
            ("x86_64-pc-windows-msvc", "windows"), ("aarch64-apple-ios", "ios")] {
            assert_eq!(profiles.select(target, os), Ok(MacBuildTarget::Arm64));
        }
        for (target, os) in [("", "linux"), ("x86_64-unknown-linux-gnu", ""), ("i686-apple-darwin", "macos"),
            ("aarch64-apple-darwin", "linux"), ("x86_64-apple-darwin", "windows"),
            ("i686-apple-darwin", "linux"), ("x86_64-unknown-linux-gnu", "macos"),
            ("x86_64h-apple-darwin", "macos")] {
            assert_eq!(profiles.select(target, os), Err("macos-build-target"));
        }
        // Membership alone must not admit a manifest for the other architecture.
        let compiled = MacBuildTarget::compiled();
        for target in ["aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64h-apple-darwin", "", "x86_64-unknown-linux-gnu"] {
            assert_eq!(MacBuildTarget::matches_compiled(target),
                compiled.is_some_and(|current| current.target() == target));
        }
        assert_eq!(compiled.is_some(), cfg!(all(target_os = "macos", target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64"))));
        let mut spaced = b" \t\r\n".to_vec(); spaced.extend_from_slice(SOURCE);
        assert!(MacBuildProfiles::parse(&spaced).is_ok());
    }

    #[test]
    fn closed_profile_shape_exact_types_and_cross_target_values_refuse() {
        let valid: Value = serde_json::from_slice(SOURCE).unwrap();
        let encoded = |value: &Value| serde_json::to_vec(value).unwrap();
        for replacement in [json!(true), json!(1.0), json!("1"), json!(null), json!(2)] {
            let mut changed = valid.clone(); changed["schemaVersion"] = replacement;
            assert!(MacBuildProfiles::parse(&encoded(&changed)).is_err());
        }
        for target in ["aarch64-apple-darwin", "x86_64-apple-darwin"] {
            let other = if target.starts_with("aarch64") { "x86_64-apple-darwin" } else { "aarch64-apple-darwin" };
            for (field, _) in valid[target].as_object().unwrap() {
                let mut missing = valid.clone(); missing[target].as_object_mut().unwrap().remove(field);
                assert!(MacBuildProfiles::parse(&encoded(&missing)).is_err(), "{target}/{field}");
                let mut wrong_type = valid.clone(); wrong_type[target][field] = json!(null);
                assert!(MacBuildProfiles::parse(&encoded(&wrong_type)).is_err(), "{target}/{field}");
                let mut crossed = valid.clone(); crossed[target][field] = valid[other][field].clone();
                assert_eq!(MacBuildProfiles::parse(&encoded(&crossed)).err(), Some("macos-profile-binding"), "{target}/{field}");
            }
            for field in ["machoCpu", "machoSubtype"] {
                let number = valid[target][field].as_u64().unwrap();
                for replacement in [json!(true), json!(number as f64), json!(number.to_string()), json!(-1)] {
                    let mut changed = valid.clone(); changed[target][field] = replacement;
                    assert!(MacBuildProfiles::parse(&encoded(&changed)).is_err(), "{target}/{field}");
                }
            }
            let mut array = valid.clone();
            array[target] = match target {
                "aarch64-apple-darwin" => json!(["arm64",16777228,0,"ARM64","macos-26","build-release.json","macos26-arm64-"]),
                _ => json!(["x86_64",16777223,3,"X64","macos-26-intel","build-release-intel.json","macos26-x86_64-"]),
            };
            assert!(MacBuildProfiles::parse(&encoded(&array)).is_err());
            let mut swapped = valid.clone(); swapped[target] = valid[other].clone();
            assert_eq!(MacBuildProfiles::parse(&encoded(&swapped)).err(), Some("macos-profile-binding"));
            let mut extra = valid.clone(); extra[target]["extra"] = json!(false);
            assert!(MacBuildProfiles::parse(&encoded(&extra)).is_err());
        }
        for key in ["schemaVersion", "aarch64-apple-darwin", "x86_64-apple-darwin"] {
            let mut missing = valid.clone(); missing.as_object_mut().unwrap().remove(key);
            assert!(MacBuildProfiles::parse(&encoded(&missing)).is_err());
        }
        let mut extra = valid.clone(); extra["i686-apple-darwin"] = valid["x86_64-apple-darwin"].clone();
        assert!(MacBuildProfiles::parse(&encoded(&extra)).is_err());
        for raw in [b"".as_slice(), b"[]", b"{}", b"null", b"{} {}", b"[1,{},{}]"] {
            assert!(MacBuildProfiles::parse(raw).is_err());
        }
        assert!(MacBuildProfiles::parse(&vec![b' '; PROFILE_INPUT_LIMIT + 1]).is_err());
        let mut trailing = SOURCE.to_vec(); trailing.extend_from_slice(b" {}");
        assert!(MacBuildProfiles::parse(&trailing).is_err());
    }

    #[test]
    fn repeated_profile_keys_are_not_collapsed_even_when_values_match() {
        let valid: Value = serde_json::from_slice(SOURCE).unwrap();
        let canonical = serde_json::to_string(&valid).unwrap();
        for key in ["schemaVersion", "aarch64-apple-darwin", "x86_64-apple-darwin"] {
            let mut duplicate = canonical.clone();
            duplicate.insert_str(1, &format!("{key:?}:{},", valid[key]));
            assert_eq!(MacBuildProfiles::parse(duplicate.as_bytes()).err(), Some("macos-profile-shape"));
        }
        for target in ["aarch64-apple-darwin", "x86_64-apple-darwin"] {
            let profile = serde_json::to_string(&valid[target]).unwrap();
            for (key, value) in valid[target].as_object().unwrap() {
                let mut duplicate = profile.clone(); duplicate.insert_str(1, &format!("{key:?}:{value},"));
                let changed = canonical.replacen(&profile, &duplicate, 1);
                assert_ne!(changed, canonical);
                assert_eq!(MacBuildProfiles::parse(changed.as_bytes()).err(), Some("macos-profile-shape"));
            }
        }
        // The JSON spelling differs, but it denotes the same key.
        let mut escaped = canonical.clone();
        escaped.insert_str(1, "\"schemaVersio\\u006e\":1,");
        assert_eq!(MacBuildProfiles::parse(escaped.as_bytes()).err(), Some("macos-profile-shape"));
    }
}
