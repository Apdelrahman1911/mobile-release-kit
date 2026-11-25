//! Fixed Android SDK metadata, not an SDK-manager receipt or licence consent.
//!
//! Both selected vendor ZIPs lack package.xml. Protected documents are compiled
//! official-definition projections; optional picked package.xml files are genuine
//! observations only and never become those payload bytes.
use crate::android_supplier_macos_source::{
    ArchivePin, CanonicalFile, OptionalSdkMetadataSpec, PickedSdkMetadataData,
    SdkMetadataKind,
};
use crate::android_toolchain_macos_policy;
use quick_xml::{events::{BytesStart, Event}, Reader, XmlVersion};
use serde::Serialize;

pub(crate) const INPUT_LIMIT: usize = 32 * 1024;
// Sequential parser high-water reservation, not RSS/allocator metadata. Bounds:
// <=64 nodes, <=64 non-namespace attributes (<=256B values), <=64 namespace
// declarations (prefix<=64B, URI<=256B) and depth<=8; at most two namespace
// string sets; total retained text<=32KiB. Geometric vector/string capacities,
// expanded QName copies, two licence-normalization buffers and reader scratch
// fit within512KiB. Source-book retained/reproof original buffers are separate.
pub(crate) const PARSER_WORK_BYTES: usize = 512 * 1024;
const COMMON: &str = "http://schemas.android.com/repository/android/common/02";
const SDK: &str = "http://schemas.android.com/sdk/android/repo/repository2/03";
const GENERIC: &str = "http://schemas.android.com/repository/android/generic/02";
const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
const XML: &str = "http://www.w3.org/XML/1998/namespace";
const LICENSE_SHA256: &str = "aaf80cd0aee7e569ffa8a4be1b61189c0fefccf23068e38dfafe336289b8c723";
const GENERATOR: &[u8] = include_bytes!("../../tools/macos_android_sdk_metadata.py");
const GENERATOR_SHA256: &str = "aa0c8da938b2f2fd82624bebdba6fd3de060798b309b0a13364449a67bbbc545";
const REPOSITORY: ArchivePin<'static> = ArchivePin {
    bytes: 419185, sha256: "c9e2f9e8b118dcc9c5584904ea27cbcefb217a5807029cedadfaa0b2f842fa8d",
};
pub(crate) static OPTIONAL: [OptionalSdkMetadataSpec; 2] = [
    OptionalSdkMetadataSpec {
        kind: SdkMetadataKind::Platform35Revision2,
        relative: "platforms/android-35/package.xml", max_bytes: INPUT_LIMIT,
        modes: &[0o444, 0o644],
    },
    OptionalSdkMetadataSpec {
        kind: SdkMetadataKind::BuildTools35,
        relative: "build-tools/35.0.0/package.xml", max_bytes: INPUT_LIMIT,
        modes: &[0o444, 0o644],
    },
];

#[derive(Serialize)]
pub(crate) struct CompiledSdkMetadata {
    pub(crate) kind: SdkMetadataKind,
    pub(crate) file: CanonicalFile,
    // File identity above binds these exact bytes; source-book copies this
    // immutable slice without inventing or opening a picked source.
    #[serde(skip)]
    pub(crate) bytes: &'static [u8],
    pub(crate) input_archive: ArchivePin<'static>,
    pub(crate) repository_xml: ArchivePin<'static>,
    pub(crate) repository_source: &'static str,
    pub(crate) generator_sha256: &'static str,
    pub(crate) source_properties_relative: &'static str,
    pub(crate) source_properties_member: &'static str,
    pub(crate) source_properties_mode: u32,
    pub(crate) source_properties_bytes: u64,
    pub(crate) source_properties_sha256: &'static str,
}
static PLATFORM: CompiledSdkMetadata = CompiledSdkMetadata {
    kind: SdkMetadataKind::Platform35Revision2,
    file: CanonicalFile {
        path: "sdk/platforms/android-35/package.xml", size: 17832,
        sha256: "385364dad6ba50838ec90abc8e4593976e0e0c54c87cf703857ba0a1aad63fe2", mode: 0o444,
    },
    bytes: include_bytes!("../../macos-installed-inputs/android-sdk/platform-35-package.xml"),
    input_archive: ArchivePin { bytes: 64273788,
        sha256: "0988cacad01b38a18a47bac14a0695f246bc76c1b06c0eeb8eb0dc825ab0c8e0" },
    repository_xml: REPOSITORY,
    repository_source: "https://dl.google.com/android/repository/repository2-3.xml",
    generator_sha256: GENERATOR_SHA256,
    source_properties_relative: "platforms/android-35/source.properties",
    source_properties_member: "android-35/source.properties", source_properties_mode: 0o644,
    source_properties_bytes: 257,
    source_properties_sha256: "2c3764446f335ad2cc44383a0360fe247620b7c774ec100d5087771ac8ed3b28",
};
static BUILD_TOOLS: CompiledSdkMetadata = CompiledSdkMetadata {
    kind: SdkMetadataKind::BuildTools35,
    file: CanonicalFile {
        path: "sdk/build-tools/35.0.0/package.xml", size: 17719,
        sha256: "6f7a9969f1bb25e39ae22fa5690b878e6806217453acf3b534712fb3a76ad1d4", mode: 0o444,
    },
    bytes: include_bytes!("../../macos-installed-inputs/android-sdk/build-tools-35-package.xml"),
    input_archive: ArchivePin { bytes: 76857898,
        sha256: "530cdbd1ec315e1477624d7ed2f0f2962108d69f36eddba5894cef9ea2cedb48" },
    repository_xml: REPOSITORY,
    repository_source: "https://dl.google.com/android/repository/repository2-3.xml",
    generator_sha256: GENERATOR_SHA256,
    source_properties_relative: "build-tools/35.0.0/source.properties",
    source_properties_member: "android-15/source.properties", source_properties_mode: 0o644,
    source_properties_bytes: 63,
    source_properties_sha256: "084847d70abc41284feee7ea717e7c92eab0d1be05f048c27445a359cfe109d8",
};

pub(crate) fn compiled_sdk_metadata(kind: SdkMetadataKind) -> &'static CompiledSdkMetadata {
    match kind {
        SdkMetadataKind::Platform35Revision2 => &PLATFORM,
        SdkMetadataKind::BuildTools35 => &BUILD_TOOLS,
    }
}
pub(crate) fn compiled_valid(kind: SdkMetadataKind) -> bool {
    let document = compiled_sdk_metadata(kind);
    document.kind == kind && document.bytes.len() as u64 == document.file.size
        && document.file.mode == 0o444
        && android_toolchain_macos_policy::digest_matches(GENERATOR, document.generator_sha256)
        && android_toolchain_macos_policy::digest_matches(document.bytes, document.file.sha256)
        // Exact compiled-source identity needs no parser workspace or String; coverage uses
        // the same predicate as optional original observations in the data tests.
}
pub(crate) fn observation_valid(spec: &OptionalSdkMetadataSpec, value: &PickedSdkMetadataData<'_>) -> bool {
    let expected = &OPTIONAL[spec.kind.index()];
    spec.kind == expected.kind && spec.relative == expected.relative
        && spec.max_bytes == INPUT_LIMIT && spec.modes == expected.modes
        && value.file.path == spec.relative && value.file.size == value.contents.len() as u64
        && !value.contents.is_empty() && value.contents.len() <= INPUT_LIMIT
        && spec.modes.contains(&value.file.mode)
        && android_toolchain_macos_policy::digest(value.contents) == value.file.sha256
        && valid_package(spec.kind, value.contents)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tag {
    Repository, License, LocalPackage, TypeDetails, Revision, DisplayName,
    UsesLicense, ApiLevel, ExtensionLevel, BaseExtension, Layoutlib,
    Major, Minor, Micro, Preview,
}
impl Tag {
    fn parse(namespace: &str, local: &str) -> Option<Self> {
        Some(match (namespace, local) {
            (COMMON, "repository") => Self::Repository,
            ("", "license") => Self::License,
            ("", "localPackage") => Self::LocalPackage,
            ("", "type-details") => Self::TypeDetails,
            ("", "revision") => Self::Revision,
            ("", "display-name") => Self::DisplayName,
            ("", "uses-license") => Self::UsesLicense,
            ("", "api-level") => Self::ApiLevel,
            ("", "extension-level") => Self::ExtensionLevel,
            ("", "base-extension") => Self::BaseExtension,
            ("", "layoutlib") => Self::Layoutlib,
            ("", "major") => Self::Major,
            ("", "minor") => Self::Minor,
            ("", "micro") => Self::Micro,
            ("", "preview") => Self::Preview,
            _ => return None,
        })
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Attr { Id, Type, Path, Obsolete, Api, Ref, XsiType }
struct Node {
    tag: Tag,
    attrs: Vec<(Attr, String)>,
    text: String,
    children: Vec<usize>,
}
impl Node {
    fn attr(&self, key: Attr) -> Option<&str> {
        self.attrs.iter().find(|(kind, _)| *kind == key).map(|(_, value)| value.as_str())
    }
    fn exact_attrs(&self, wanted: &[(Attr, &str)]) -> bool {
        self.attrs.len() == wanted.len()
            && wanted.iter().all(|(key, value)| self.attr(*key) == Some(*value))
    }
    fn allowed_attrs(&self, wanted: &[Attr]) -> bool {
        self.attrs.iter().all(|(key, _)| wanted.contains(key))
    }
    fn whitespace(&self) -> bool { self.text.trim().is_empty() }
    fn scalar(&self, wanted: &str) -> bool {
        self.attrs.is_empty() && self.children.is_empty() && self.text.trim() == wanted
    }
    fn children_as(&self, nodes: &[Node], tags: &[Tag]) -> Option<Vec<usize>> {
        if !self.whitespace() || self.children.len() != tags.len() { return None; }
        let mut result = Vec::with_capacity(tags.len());
        for tag in tags {
            let mut matches = self.children.iter().copied().filter(|index| nodes[*index].tag == *tag);
            let index = matches.next()?;
            if matches.next().is_some() { return None; }
            result.push(index);
        }
        Some(result)
    }
}
struct Namespace { prefix: String, uri: String, depth: usize }
fn part(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64
        && value.bytes().enumerate().all(|(i, b)| b.is_ascii_alphabetic() || b == b'_'
            || i != 0 && (b.is_ascii_digit() || matches!(b, b'-' | b'.')))
}
fn qname<'a>(raw: &'a str, scope: &'a [Namespace], default: bool) -> Option<(&'a str, &'a str)> {
    if let Some((prefix, local)) = raw.split_once(':') {
        if !part(prefix) || !part(local) { return None; }
        if prefix == "xml" { return Some((XML, local)); }
        let binding = scope.iter().rev().find(|n| n.prefix == prefix)?;
        if binding.uri.is_empty() { return None; }
        Some((&binding.uri, local))
    } else {
        if !part(raw) { return None; }
        let uri = if default { scope.iter().rev().find(|n| n.prefix.is_empty()).map_or("", |n| n.uri.as_str()) } else { "" };
        Some((uri, raw))
    }
}
fn xml_char(ch: char) -> bool {
    matches!(ch, '\t' | '\n' | '\r') || (ch >= ' ' && !matches!(ch, '\u{fffe}' | '\u{ffff}'))
}
fn start_node(
    event: &BytesStart<'_>, depth: usize, scope: &mut Vec<Namespace>,
    declared: &mut Vec<(String, String)>, declarations: &mut usize, attributes: &mut usize,
) -> Option<Node> {
    let mut pending = Vec::new();
    for item in event.attributes().with_checks(true) {
        let item = item.ok()?;
        let name = item.key.as_ref();
        let value = item.normalized_value(XmlVersion::Implicit1_0).ok()?;
        if name.len() > 128 || value.len() > 256 || !value.chars().all(xml_char) { return None; }
        let namespace = if name == "xmlns" { Some("") }
            else if let Some(prefix) = name.strip_prefix("xmlns:") {
                // Only the exact unprefixed name declares a default namespace.
                // quick-xml does not validate namespace-attribute QName syntax.
                if !part(prefix) { return None; }
                Some(prefix)
            } else { None };
        if let Some(prefix) = namespace {
            *declarations += 1;
            if *declarations > 64
                || !prefix.is_empty() && value.is_empty()
                || prefix == "xmlns" || value == "http://www.w3.org/2000/xmlns/"
                || (prefix == "xml") != (value == XML) { return None; }
            if declared.iter().any(|(old, uri)| old == prefix && uri != value.as_ref()) { return None; }
            if !declared.iter().any(|(old, _)| old == prefix) {
                declared.push((prefix.to_owned(), value.to_string()));
            }
            scope.push(Namespace { prefix: prefix.to_owned(), uri: value.into_owned(), depth });
        } else {
            *attributes += 1;
            if *attributes > 64 { return None; }
            pending.push((name.to_owned(), value.into_owned()));
        }
    }
    let name = event.name();
    let (namespace, local) = qname(name.as_ref(), scope, true)?;
    let tag = Tag::parse(namespace, local)?;
    let mut attrs = Vec::with_capacity(pending.len());
    for (raw, value) in pending {
        let (namespace, local) = qname(&raw, scope, false)?;
        let kind = match (namespace, local) {
            ("", "id") => Attr::Id, ("", "type") => Attr::Type,
            ("", "path") => Attr::Path, ("", "obsolete") => Attr::Obsolete,
            ("", "api") => Attr::Api, ("", "ref") => Attr::Ref,
            (XSI, "type") => Attr::XsiType,
            _ => return None,
        };
        if attrs.iter().any(|(key, _)| *key == kind) { return None; }
        let value = if kind == Attr::XsiType {
            // This QName is resolved against THIS element's active namespace
            // scope, never an unrelated declaration elsewhere in the file.
            if value.matches(':').count() != 1 { return None; }
            let (namespace, local) = qname(&value, scope, false)?;
            format!("{{{namespace}}}{local}")
        } else { value };
        attrs.push((kind, value));
    }
    Some(Node { tag, attrs, text: String::new(), children: Vec::new() })
}
fn text(nodes: &mut [Node], stack: &[usize], value: &str, total: &mut usize) -> Option<()> {
    *total = total.checked_add(value.len())?;
    if *total > INPUT_LIMIT || !value.chars().all(xml_char) { return None; }
    if let Some(index) = stack.last() { nodes[*index].text.push_str(value); }
    else if !value.chars().all(|c| matches!(c, ' ' | '\t' | '\n' | '\r')) { return None; }
    Some(())
}
fn declaration(raw: &str) -> Option<()> {
    if raw.len() > 256 || !raw.strip_prefix("xml").is_some_and(|s| s.chars().next().is_some_and(|c| matches!(c, ' ' | '\t' | '\r' | '\n'))) { return None; }
    let start = BytesStart::from_content(raw, 3);
    let mut last = None;
    for item in start.attributes().with_checks(true) {
        let item = item.ok()?;
        let (rank, valid) = match item.key.as_ref() {
            "version" => (0, item.value == "1.0"),
            "encoding" => (1, item.value.eq_ignore_ascii_case("UTF-8")),
            "standalone" => (2, item.value == "yes" || item.value == "no"),
            _ => return None,
        };
        if !valid || last.is_none() && rank != 0 || last.is_some_and(|old| rank <= old) { return None; }
        last = Some(rank);
    }
    last.map(|_| ())
}
fn parse(raw: &[u8]) -> Option<Vec<Node>> {
    if raw.is_empty() || raw.len() > INPUT_LIMIT { return None; }
    let source = std::str::from_utf8(raw).ok()?;
    if !source.chars().all(xml_char)
        || raw.windows(9).any(|w| w.eq_ignore_ascii_case(b"<!DOCTYPE"))
        || raw.windows(8).any(|w| w.eq_ignore_ascii_case(b"<!ENTITY")) { return None; }
    let mut reader = Reader::from_str(source);
    reader.config_mut().check_end_names = true;
    reader.config_mut().check_comments = true;
    let mut nodes: Vec<Node> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut scope = Vec::new();
    let mut declared = Vec::new();
    let (mut declarations, mut attributes, mut characters) = (0usize, 0usize, 0usize);
    let (mut closed, mut declaration_allowed) = (false, true);
    for _ in 0..4096 {
        let event = reader.read_event().ok()?;
        match event {
            value @ (Event::Start(_) | Event::Empty(_)) => {
                let empty = matches!(&value, Event::Empty(_));
                let header = match value { Event::Start(h) | Event::Empty(h) => h, _ => unreachable!() };
                declaration_allowed = false;
                if closed || stack.len() >= 8 || nodes.len() >= 64 { return None; }
                let depth = stack.len() + 1;
                let node = start_node(&header, depth, &mut scope, &mut declared,
                    &mut declarations, &mut attributes)?;
                let index = nodes.len();
                if let Some(parent) = stack.last().copied() { nodes[parent].children.push(index); }
                else if !nodes.is_empty() { return None; }
                nodes.push(node);
                if empty {
                    scope.retain(|item| item.depth < depth);
                    if stack.is_empty() { closed = true; }
                } else { stack.push(index); }
            }
            Event::End(_) => {
                let depth = stack.len();
                stack.pop()?;
                scope.retain(|item| item.depth < depth);
                if stack.is_empty() { closed = true; }
            }
            Event::Text(value) => {
                let value = value.xml10_content();
                text(&mut nodes, &stack, &value, &mut characters)?;
                if !value.is_empty() { declaration_allowed = false; }
            }
            Event::CData(value) => {
                if stack.is_empty() { return None; }
                text(&mut nodes, &stack, &value.xml10_content(), &mut characters)?;
            }
            Event::GeneralRef(value) => {
                if stack.is_empty() { return None; }
                let character = match value.resolve_char_ref().ok()? {
                    Some(ch) => ch,
                    None => match value.as_ref() {
                        "amp" => '&', "lt" => '<', "gt" => '>', "apos" => '\'', "quot" => '"',
                        _ => return None,
                    },
                };
                let mut encoded = [0u8; 4];
                text(&mut nodes, &stack, character.encode_utf8(&mut encoded), &mut characters)?;
            }
            Event::Decl(value) => {
                if !declaration_allowed || !nodes.is_empty() { return None; }
                declaration(value.as_ref())?;
                declaration_allowed = false;
            }
            Event::Comment(_) => declaration_allowed = false,
            Event::Eof => return (closed && stack.is_empty() && !nodes.is_empty()).then_some(nodes),
            Event::DocType(_) | Event::PI(_) => return None,
        }
    }
    None
}
fn normalized_license(value: &str) -> String {
    // Java Repository31.9.2 TrimStringAdapter: remove horizontal whitespace only
    // when preceded by ASCII whitespace; replace isolated LF, collapse spaces,
    // finally trim codepoints0..32. Not generic Unicode whitespace folding.
    let mut first = String::with_capacity(value.len());
    let mut previous = None;
    for ch in value.chars() {
        let after_space = previous.is_some_and(|p| matches!(p, ' ' | '\t' | '\n' | '\r' | '\u{0b}' | '\u{0c}'));
        if !matches!(ch, ' ' | '\t') || !after_space { first.push(ch); }
        previous = Some(ch);
    }
    let mut second = String::with_capacity(first.len());
    let mut chars = first.chars().peekable();
    let mut previous = None;
    while let Some(ch) = chars.next() {
        let projected = if ch == '\n' && previous != Some('\n') && chars.peek() != Some(&'\n') { ' ' } else { ch };
        if projected != ' ' || !second.ends_with(' ') { second.push(projected); }
        previous = Some(ch);
    }
    second.trim_matches(|ch| ch <= '\u{20}').to_owned()
}
fn package(kind: SdkMetadataKind, raw: &[u8]) -> Option<()> {
    let nodes = parse(raw)?;
    let root = nodes.first()?;
    if root.tag != Tag::Repository || !root.attrs.is_empty() { return None; }
    let roots = root.children_as(&nodes, &[Tag::License, Tag::LocalPackage])?;
    let licence = &nodes[roots[0]];
    if !licence.allowed_attrs(&[Attr::Id, Attr::Type]) || licence.attr(Attr::Id) != Some("android-sdk-license")
        || licence.attr(Attr::Type).unwrap_or("text") != "text" || !licence.children.is_empty() { return None; }
    let normalized = normalized_license(&licence.text);
    if normalized.len() != 16960 || android_toolchain_macos_policy::digest(normalized.as_bytes()) != LICENSE_SHA256 { return None; }
    let platform = kind == SdkMetadataKind::Platform35Revision2;
    let path = if platform { "platforms;android-35" } else { "build-tools;35.0.0" };
    let local = &nodes[roots[1]];
    if !local.allowed_attrs(&[Attr::Path, Attr::Obsolete]) || local.attr(Attr::Path) != Some(path)
        || local.attr(Attr::Obsolete).unwrap_or("false") != "false" { return None; }
    let fields = local.children_as(&nodes, &[Tag::TypeDetails, Tag::Revision, Tag::DisplayName, Tag::UsesLicense])?;
    let details = &nodes[fields[0]];
    let expected = if platform { format!("{{{SDK}}}platformDetailsType") } else { format!("{{{GENERIC}}}genericDetailsType") };
    if !details.exact_attrs(&[(Attr::XsiType, &expected)]) { return None; }
    if platform {
        let values = details.children_as(&nodes, &[Tag::ApiLevel, Tag::ExtensionLevel, Tag::BaseExtension, Tag::Layoutlib])?;
        if !nodes[values[0]].scalar("35") || !nodes[values[1]].scalar("13") || !nodes[values[2]].scalar("true") { return None; }
        let layout = &nodes[values[3]];
        if !layout.exact_attrs(&[(Attr::Api, "15")]) || !layout.children.is_empty() || !layout.whitespace() { return None; }
    } else { details.children_as(&nodes, &[])?; }
    let revision = &nodes[fields[1]];
    if !revision.attrs.is_empty() || !revision.whitespace() || revision.children.is_empty() || revision.children.len() > 4 { return None; }
    let mut seen = Vec::new();
    for index in &revision.children {
        let part = &nodes[*index];
        if !matches!(part.tag, Tag::Major | Tag::Minor | Tag::Micro | Tag::Preview) || seen.contains(&part.tag) { return None; }
        let expected = if part.tag == Tag::Major { if platform { "2" } else { "35" } } else { "0" };
        if !part.scalar(expected) { return None; }
        seen.push(part.tag);
    }
    if !seen.contains(&Tag::Major) { return None; }
    if !nodes[fields[2]].scalar(if platform { "Android SDK Platform 35" } else { "Android SDK Build-Tools 35" }) { return None; }
    let licence_ref = &nodes[fields[3]];
    if !licence_ref.exact_attrs(&[(Attr::Ref, "android-sdk-license")])
        || !licence_ref.children.is_empty() || !licence_ref.whitespace() { return None; }
    Some(())
}
pub(crate) fn valid_package(kind: SdkMetadataKind, raw: &[u8]) -> bool { package(kind, raw).is_some() }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android_toolchain_macos_policy::{digest, FileSpec};

    pub(super) fn compiled_projection_and_genuine_optional_observations_are_distinct_data() {
        for kind in [SdkMetadataKind::Platform35Revision2, SdkMetadataKind::BuildTools35] {
            let document = compiled_sdk_metadata(kind);
            assert!(compiled_valid(kind));
            assert!(valid_package(kind, document.bytes));
            let spec = &OPTIONAL[kind.index()];
            let file = FileSpec { path: spec.relative.into(), size: document.bytes.len() as u64,
                sha256: digest(document.bytes), mode: 0o644 };
            assert!(observation_valid(spec, &PickedSdkMetadataData { file: &file, contents: document.bytes }));
            for changed in [
                FileSpec { path: document.file.path.into(), ..file.clone() },
                FileSpec { size: file.size + 1, ..file.clone() },
                FileSpec { sha256: "f".repeat(64), ..file.clone() },
                FileSpec { mode: 0o755, ..file.clone() },
            ] {
                assert!(!observation_valid(spec, &PickedSdkMetadataData { file: &changed, contents: document.bytes }));
            }
            // A genuine selected XML can use normal SDK-manager presentation;
            // that new hash remains an observation, not generated payload bytes.
            let presentation = std::str::from_utf8(document.bytes).unwrap()
                .replace("encoding=\"UTF-8\"", "encoding=\"UTF-8\" standalone=\"yes\"")
                .replace("<common:repository", "<r:repository")
                .replace("</common:repository>", "</r:repository>")
                .replace("xmlns:common=", "xmlns:r=");
            assert!(valid_package(kind, presentation.as_bytes()));
            assert_ne!(digest(presentation.as_bytes()), document.file.sha256);
            let default_namespace = std::str::from_utf8(document.bytes).unwrap()
                .replace("<common:repository", "<common:repository xmlns=\"\"");
            assert!(valid_package(kind, default_namespace.as_bytes()));
            assert_eq!(compiled_sdk_metadata(kind).bytes, document.bytes);
        }
        assert_eq!(normalized_license("  One \n    line\n\n Next  block  "), "One line\n\nNext block");
    }

    pub(super) fn optional_metadata_requires_exact_semantics_not_prefix_or_hash_search_data() {
        let kind = SdkMetadataKind::Platform35Revision2;
        let raw = std::str::from_utf8(compiled_sdk_metadata(kind).bytes).unwrap();
        for changed in [
            raw.replace("sdk:platformDetailsType", "absent:platformDetailsType"),
            raw.replace(SDK, "https://example.invalid/untrusted-type"),
            raw.replace("<major>2</major>", "<major>3</major>"),
            raw.replace("<major>2</major>", "<major>2</major><major>2</major>"),
            raw.replace("<api-level>35</api-level>", "<api-level>34</api-level>"),
            raw.replace("obsolete=\"false\"", "obsolete=\"true\""),
            raw.replace("<uses-license ", "<uses-license extra=\"value\" "),
            raw.replace("xmlns:sdk=", "xmlns:other="),
            raw.replace("<common:repository", "<common:repository xmlns:=\"\""),
            raw.replace("<revision>", "<revision><unknown></unknown>"),
            raw.replace("</localPackage>", "</localPackage><localPackage path=\"extra\"></localPackage>"),
            raw.replace("<license ", "<license id=\"duplicate\" "),
            raw.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "<!DOCTYPE repository SYSTEM \"file:///unread\">"),
            raw.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "<?xml version=\"1.0\" encoding=\"UTF-16\"?>"),
            raw.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "<?xml version=\"1.0\" version=\"1.0\"?>"),
            raw.replace("</common:repository>", "</common:repository>&unknown;"),
            raw.replace("<layoutlib ", "<layoutlib xmlns:sdk=\"https://example.invalid/rebound\" "),
        ] {
            assert!(!valid_package(kind, changed.as_bytes()));
        }
        let mut different_licence = raw.to_owned();
        let at = different_licence.find("<license ").unwrap();
        let at = at + different_licence[at..].find('>').unwrap() + 1;
        different_licence.insert_str(at, "Different terms. ");
        assert!(!valid_package(kind, different_licence.as_bytes()));
        assert!(!valid_package(kind, &vec![b' '; INPUT_LIMIT + 1]));
        assert!(!valid_package(SdkMetadataKind::BuildTools35, raw.as_bytes()));
    }
    #[test]
    fn compiled_projection_and_genuine_optional_observations_are_distinct() {
        compiled_projection_and_genuine_optional_observations_are_distinct_data();
    }
    #[test]
    fn optional_metadata_requires_exact_semantics_not_prefix_or_hash_search() {
        optional_metadata_requires_exact_semantics_not_prefix_or_hash_search_data();
    }
}
#[cfg(test)]
pub(crate) fn assert_sdk_metadata_data_contract() {
    tests::compiled_projection_and_genuine_optional_observations_are_distinct_data();
    tests::optional_metadata_requires_exact_semantics_not_prefix_or_hash_search_data();
}
