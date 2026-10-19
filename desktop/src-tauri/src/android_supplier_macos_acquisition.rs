//! Public acquisition projection of the SAME checked compiled supplier.
//!
//! No URL/hash/path/mode is accepted from a caller. No IO, missing-tool proof,
//! network, source-picker authority, privileged copy or readiness is provided.
//! Call outside short Registry/source/control locks on the admitted owner's
//! preparation path. Cold/unsupported caches stay unavailable, never initialize.
use super::*;
use std::io::{self, Write};

pub(crate) const MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const _: () = assert!(policy::ENTRY_LIMIT <= 32_768);

/// Private bootstrap DATA; not renderer input or a borrow of a native tool role.
/// Deliberately no Deserialize/Clone or registration/source conversion.
pub(crate) struct Projection {
    pub(crate) profile: Profile,
    pub(crate) reference_sha256: [u8; 32],
    pub(crate) projection_sha256: [u8; 32],
    pub(crate) bytes: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u8,
    profile: &'static str,
    reference_sha256: String,
    archives: Vec<Archive>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Archive {
    component: &'static str,
    url: &'static str,
    bytes: u64,
    sha256: &'static str,
    expanded_bytes: u64,
    members: Vec<Member>,
    parents: Vec<Parent>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Member {
    name: &'static str,
    kind: &'static str,
    archive_mode: u32,
    bytes: u64,
    sha256: Option<&'static str>,
    source_relative: Option<&'static str>,
    source_mode: Option<u32>,
}
#[derive(Serialize)]
struct Parent { relative: &'static str, mode: u32 }

fn group(component: Component) -> Option<SourceGroup> {
    match component {
        Component::Jdk => Some(SourceGroup::Jdk),
        Component::SdkPlatform | Component::SdkBuildTools => Some(SourceGroup::Sdk),
        Component::Gradle => Some(SourceGroup::Gradle),
        Component::Aapt2 | Component::Bundletool => None,
    }
}
fn component_name(component: Component) -> Option<&'static str> {
    match component {
        Component::Jdk => Some("jdk"), Component::SdkPlatform => Some("sdk-platform"),
        Component::SdkBuildTools => Some("sdk-build-tools"), Component::Gradle => Some("gradle"),
        Component::Aapt2 | Component::Bundletool => None,
    }
}
fn source_mode(source: &SourceMemberSpec) -> Option<u32> {
    // Do not loosen source policy or carry archived JDK setgid onto new paths.
    // Current public profiles specify one exact 0644/0755 source mode.
    match source.kind {
        SourceKindSpec::Directory { modes: [0o755] } => Some(0o755),
        SourceKindSpec::File { modes: [mode], .. } if *mode == 0o644 || *mode == 0o755 => Some(*mode),
        _ => None, // Including aliases and any future ambiguous mode policy.
    }
}
fn member(reference: &Reference, archive: &OfficialArchive, item: &OfficialMember) -> Option<Member> {
    let (kind, archive_mode, bytes, sha256) = match item.kind {
        ArchiveKind::Directory { mode } => ("directory", mode, 0, None),
        ArchiveKind::File { mode, bytes, sha256 } => ("file", mode, bytes, Some(sha256)),
        ArchiveKind::Alias { .. } => return None,
    };
    let (source_relative, source_mode) = match item.disposition {
        ArchiveDisposition::Picked { source_index } => {
            let source = reference.source_members.get(source_index as usize)?;
            if source.group != group(archive.component)? { return None; }
            let same = match (item.kind, source.kind) {
                (ArchiveKind::Directory { .. }, SourceKindSpec::Directory { .. }) => true,
                (ArchiveKind::File { bytes, sha256, .. }, SourceKindSpec::File { bytes: size, sha256: hash, .. }) =>
                    bytes == size && sha256 == hash,
                _ => false,
            };
            if !same { return None; }
            (Some(source.relative), Some(source_mode(source)?))
        },
        ArchiveDisposition::WrapperDirectory if kind == "directory" => (None, None),
        _ => return None, // Never acquire/replace app-signed fixed support.
    };
    Some(Member { name: item.name, kind, archive_mode, bytes, sha256, source_relative, source_mode })
}

struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, value: &[u8]) -> io::Result<usize> {
        if self.0.len().checked_add(value.len()).is_none_or(|size| size > MANIFEST_BYTES) {
            return Err(io::Error::other("public supplier projection exceeds its fixed bound"));
        }
        self.0.extend_from_slice(value);
        Ok(value.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
fn projection(checked: &CheckedReference) -> Option<Projection> {
    let profile = match checked.profile {
        Profile::MacArm64 => "macos-arm64", Profile::MacX64 => "macos-x86_64", Profile::LinuxX64 => return None,
    };
    let reference = checked.reference;
    if reference.archives.len() != COMPONENTS.len() || reference.source_members.len() != reference.source_bindings.len() {
        return None;
    }
    let mut archives = Vec::with_capacity(4);
    let (mut entries, mut expanded) = (0usize, 0u64);
    for (index, original) in reference.archives.iter().take(4).enumerate() {
        if original.component != COMPONENTS[index] || original.members.len() != original.member_count as usize
            || original.archive.bytes == 0 || original.archive.bytes > ARCHIVE_BYTES
            || original.expanded_bytes > original.archive.bytes.checked_mul(8)? { return None; }
        entries = entries.checked_add(original.members.len())?;
        expanded = expanded.checked_add(original.expanded_bytes)?;
        if entries > policy::ENTRY_LIMIT || expanded > 1024 * 1024 * 1024 { return None; }
        let members: Vec<Member> = original.members.iter().map(|item| member(reference, original, item)).collect::<Option<_>>()?;
        let mut parents = Vec::new();
        for (source, binding) in reference.source_members.iter().zip(reference.source_bindings) {
            if let SourceProvenance::ArchiveParent { archive, .. } = binding.provenance {
                if usize::from(archive) == index {
                    if source.group != group(original.component)? || !matches!(source.kind, SourceKindSpec::Directory { .. })
                        || !matches!(binding.disposition, SourceDisposition::Directory) { return None; }
                    entries = entries.checked_add(1)?;
                    if entries > policy::ENTRY_LIMIT { return None; }
                    parents.push(Parent { relative: source.relative, mode: source_mode(source)? });
                }
            }
        }
        archives.push(Archive { component: component_name(original.component)?, url: original.official_source,
            bytes: original.archive.bytes, sha256: original.archive.sha256,
            expanded_bytes: original.expanded_bytes, members, parents });
    }
    let manifest = Manifest { schema_version: 1, profile, reference_sha256: hex(&checked.digest), archives };
    // Reserve the fixed maximum once, before serialization; no unbounded growth
    // hidden behind serde. The original NEW acquisition profile charges this
    // 8MiB buffer + bounded member vectors; existing registration pools unchanged.
    let mut writer = Bounded(Vec::new());
    writer.0.try_reserve_exact(MANIFEST_BYTES).ok()?;
    serde_json::to_writer(&mut writer, &manifest).ok()?;
    let projection_sha256 = Sha256::digest(&writer.0).into();
    Some(Projection { profile: checked.profile, reference_sha256: checked.digest,
        projection_sha256, bytes: writer.0 })
}
fn hex(value: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        output.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
    }
    output
}

pub(crate) fn for_profile(profile: Profile) -> Option<Projection> {
    if !available_for(profile) { return None; }
    let catalogue = match profile {
        Profile::MacArm64 => COMPILED_CATALOGUE.get()?,
        Profile::MacX64 => INTEL_COMPILED_CATALOGUE.get()?,
        Profile::LinuxX64 => return None,
    };
    if catalogue.len() != 1 { return None; }
    let checked = catalogue.first()?.as_ref()?;
    if checked.profile != profile { return None; }
    projection(checked)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_current_public_archives_and_source_modes_only() {
        for (profile, reference) in [(Profile::MacArm64, &REFERENCES[0]),
            (Profile::MacX64, &intel_catalogue::REFERENCES[0])] {
            let checked = CheckedReference::new_for(profile, reference).unwrap();
            let output = projection(&checked).unwrap();
            assert_eq!(output.profile, profile);
            assert_eq!(output.reference_sha256, checked.digest);
            assert_eq!(output.projection_sha256, <[u8; 32]>::from(Sha256::digest(&output.bytes)));
            assert!(output.bytes.len() < MANIFEST_BYTES);
            let data: serde_json::Value = serde_json::from_slice(&output.bytes).unwrap();
            let archives = data["archives"].as_array().unwrap();
            assert_eq!(archives.len(), 4);
            for (item, original) in archives.iter().zip(reference.archives) {
                assert_eq!(item["url"], original.official_source);
                assert_eq!(item["sha256"], original.archive.sha256);
                assert_eq!(item["bytes"], original.archive.bytes);
                assert_eq!(item["members"].as_array().unwrap().len(), original.member_count as usize);
                for member in item["members"].as_array().unwrap() {
                    assert!(member["kind"] == "file" || member["kind"] == "directory");
                    assert!(member["sourceMode"].is_null() || member["sourceMode"] == 0o644 || member["sourceMode"] == 0o755);
                    assert_eq!(member["sourceRelative"].is_null(), member["sourceMode"].is_null());
                }
            }
            assert!(data.get("ready").is_none() && data.get("registered").is_none());
        }
    }
    #[test]
    fn unsupported_getter_does_not_initialize_either_cache() {
        let arm = COMPILED_CATALOGUE.get().map(|value| value as *const CheckedCatalogue);
        let intel = INTEL_COMPILED_CATALOGUE.get().map(|value| value as *const CheckedCatalogue);
        assert!(for_profile(Profile::LinuxX64).is_none());
        assert_eq!(COMPILED_CATALOGUE.get().map(|value| value as *const CheckedCatalogue), arm);
        assert_eq!(INTEL_COMPILED_CATALOGUE.get().map(|value| value as *const CheckedCatalogue), intel);
    }
    #[test]
    fn closed_source_modes_and_projection_bytes_stay_bounded() {
        let unsupported = SourceMemberSpec { group: SourceGroup::Jdk, relative: "Contents",
            kind: SourceKindSpec::Directory { modes: &[0o2755] } };
        assert!(source_mode(&unsupported).is_none());
        let mut writer = Bounded(Vec::new());
        writer.0.resize(MANIFEST_BYTES, 0);
        assert!(writer.write(b"x").is_err());
        assert_eq!(writer.0.len(), MANIFEST_BYTES);
        assert!(component_name(Component::Aapt2).is_none());
        assert!(component_name(Component::Bundletool).is_none());
    }
}
