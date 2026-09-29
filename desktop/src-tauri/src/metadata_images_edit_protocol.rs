//! Closed public-image DATA. Original picker/root/edit owners retain authority.
//! Raw images enter only the private native child pipe, never a renderer DTO.
use std::{collections::BTreeSet, io, sync::OnceLock};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use crate::{edit_protocol::{self as edit, token, Capability, ChildFrame, CoreEditOutcome, CoreReason,
    Effect, Journal, NativeEditReason, NativeFinality, Phase, ResourceState}, error::BridgeError,
    github_workflow_edit_protocol::{value_bounds, RegisteredIdentity},
    metadata_text_edit_protocol::{locale_bounded, Platform}, protocol::{check_value, strict_json}};

pub const PROTOCOL: &str = "mrk-metadata-images/1";
pub const DOMAIN: &str = "metadata_images";
pub const EVENT: &str = "mrk://metadata-images-edit";
pub const SELECTION_EVENT: &str = "mrk://metadata-images-selection";
pub const REQUEST_LIMIT: usize = 33 * 1024 * 1024;
pub const SMALL_REQUEST_LIMIT: usize = 64 * 1024;
pub const RESPONSE_LIMIT: usize = 512 * 1024;
pub const VIEW_LIMIT: usize = 384 * 1024;
pub const STATUS_LIMIT: usize = 2 * 1024 * 1024;
pub const FILE_LIMIT: usize = 10 * 1024 * 1024;
pub const BATCH_LIMIT: usize = 24 * 1024 * 1024;
pub const MAX_FILES: usize = 10;
pub const TRANSACTION_LIMIT: usize = 64 * 1024 * 1024;

fn keys(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|v| v.len() == names.len() && names.iter().all(|name| v.contains_key(*name)))
}
pub(crate) fn safe_text(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
}
fn hex(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn digest(raw: &[u8]) -> String { format!("{:x}", Sha256::digest(raw)) }
fn basename(value: &str) -> bool { safe_text(value, 255) && !value.contains(['/', '\\']) }
fn relative(value: &str) -> bool {
    safe_text(value, 512) && !value.contains(['\\', ':']) && value.split('/').count() <= 12
        && value.split('/').all(|part| !part.is_empty() && !part.starts_with('.') && part.len() <= 255
            && !part.ends_with(['.', ' ']) && !part.chars().any(|c| "<>\"|?*".contains(c)))
}
fn protected_source(value: &str) -> bool {
    safe_text(value, 4096) && !value.starts_with('/') && !value.contains('\\')
        && value.split('/').all(|part| !matches!(part, "" | "." | ".."))
}
fn number(value: &Value, limit: usize) -> bool { value.as_u64().is_some_and(|v| v <= limit as u64) }
fn policy() -> Option<&'static Value> {
    static DATA: OnceLock<Option<Value>> = OnceLock::new();
    DATA.get_or_init(|| strict_json(include_bytes!("../../../src/mobile_release/api/data/metadata-images-v1.json")).ok()).as_ref()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context { pub platform: Platform, pub locale: String, pub asset_type: String }
impl Context {
    pub(crate) fn valid(&self) -> bool {
        locale_bounded(&self.locale) && !self.locale.contains(['/', '\\'])
            && !self.asset_type.is_empty() && self.asset_type.len() <= 64
            && self.asset_type.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && self.type_row().is_some()
    }
    fn type_row(&self) -> Option<&'static Value> {
        policy()?["types"].as_array()?.iter().find(|row| row["platform"] == json!(self.platform) && row["id"] == self.asset_type)
    }
    fn folder(&self, root: &str) -> Option<String> {
        let row = self.type_row()?;
        Some(match self.platform {
            Platform::Android if row["singleton"] == true => format!("{root}/android/{}/images", self.locale),
            Platform::Android => format!("{root}/android/{}/images/{}", self.locale, self.asset_type),
            Platform::Ios => format!("{root}/ios/screenshots/{}/{}", self.locale, self.asset_type),
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedItem { pub item_id: String, pub display_name: String, pub byte_length: u32, pub sha256: String }
impl SelectedItem {
    pub(crate) fn valid(&self) -> bool { token(&self.item_id) && basename(&self.display_name)
        && (1..=FILE_LIMIT).contains(&(self.byte_length as usize)) && hex(&self.sha256) }
}
// Not Serialize/Deserialize/Clone: neither renderer DATA nor a second byte owner.
pub(crate) struct SelectedImageData { pub item_id: String, pub display_name: String, pub bytes: Vec<u8>, pub sha256: String }
impl SelectedImageData {
    fn item(&self) -> SelectedItem { SelectedItem { item_id: self.item_id.clone(), display_name: self.display_name.clone(),
        byte_length: self.bytes.len() as u32, sha256: self.sha256.clone() } }
}
// Private native→core exclusion DATA only. Never a renderer projection or
// destination/cleanup authority, and never persisted in an image journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImageIdentityFamily { Posix, Windows }

fn canonical_u64(value: &str) -> bool {
    !value.is_empty() && value.len() <= 20 && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" || !value.starts_with('0')) && value.parse::<u64>().is_ok()
}
fn file_id_hex(bytes: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(32);
    for byte in bytes { result.push(HEX[(byte >> 4) as usize] as char); result.push(HEX[(byte & 15) as usize] as char); }
    result
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WindowsImageIdentity { volume_serial: String, file_id: String }
impl WindowsImageIdentity {
    fn native(volume: u64, file_id: [u8; 16]) -> Self { Self { volume_serial: volume.to_string(), file_id: file_id_hex(file_id) } }
    fn valid(&self) -> bool {
        canonical_u64(&self.volume_serial) && self.file_id.len() == 32
            && self.file_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct PosixSourceObject { pub device: String, pub inode: String }
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub(crate) enum SourceObject { Posix(PosixSourceObject), Windows(WindowsImageIdentity) }
impl SourceObject {
    fn family(&self) -> ImageIdentityFamily {
        match self { Self::Posix(_) => ImageIdentityFamily::Posix, Self::Windows(_) => ImageIdentityFamily::Windows }
    }
    fn valid(&self) -> bool {
        match self {
            Self::Posix(value) => canonical_u64(&value.device) && canonical_u64(&value.inode),
            Self::Windows(value) => value.valid(),
        }
    }
}
impl From<crate::asset_source::ImageSourceObject> for SourceObject {
    fn from(value: crate::asset_source::ImageSourceObject) -> Self {
        use crate::asset_source::ImageSourceObject;
        match value {
            ImageSourceObject::Posix { device, inode } => Self::Posix(PosixSourceObject { device: device.to_string(), inode: inode.to_string() }),
            ImageSourceObject::Windows { volume_serial, file_id } => Self::Windows(WindowsImageIdentity::native(volume_serial, file_id)),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum ImageRegisteredIdentity { Posix(RegisteredIdentity), Windows(WindowsImageIdentity) }
impl ImageRegisteredIdentity {
    pub(crate) fn from_project(value: crate::asset_source::ProjectIdentity) -> Self {
        use crate::asset_source::ProjectIdentity;
        match value {
            ProjectIdentity::Posix(identity) => Self::Posix(identity.workflow_identity()),
            ProjectIdentity::Windows { volume, file_id } => Self::Windows(WindowsImageIdentity::native(volume, file_id)),
        }
    }
    fn family(&self) -> ImageIdentityFamily {
        match self { Self::Posix(_) => ImageIdentityFamily::Posix, Self::Windows(_) => ImageIdentityFamily::Windows }
    }
    fn valid(&self) -> bool {
        match self { Self::Posix(identity) => identity.valid(), Self::Windows(identity) => identity.valid() }
    }
    fn valid_root(&self, root: &str) -> bool {
        self.valid() && safe_text(root, 4096) && match self {
            Self::Posix(_) => root.starts_with('/'),
            Self::Windows(_) => windows_image_root(root),
        }
    }
}
fn windows_image_component(value: &str) -> bool {
    // Kept in lockstep with original native decode::component, on every target.
    if value.is_empty() || matches!(value, "." | "..") || value.len() > 255
        || value.encode_utf16().count() > 255 || value.ends_with(['.', ' '])
        || value.chars().any(|c| c < ' ' || c == '\u{7f}' || "<>:\"/\\|?*".contains(c)) { return false; }
    let stem = value.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$") { return false; }
    !["COM", "LPT"].iter().any(|prefix| stem.strip_prefix(*prefix).is_some_and(|tail|
        ["1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"].contains(&tail)))
}
fn windows_image_root(value: &str) -> bool {
    if !safe_text(value, 4096) { return false; }
    let ordinary = value.strip_prefix(r"\\?\").unwrap_or(value);
    let bytes = ordinary.as_bytes();
    if bytes.len() <= 3 || !bytes[0].is_ascii_alphabetic() || bytes[1..3] != *b":\\" { return false; }
    let mut count = 0usize;
    ordinary[3..].split('\\').all(|part| { count += 1; count <= 44 && windows_image_component(part) })
}
pub(crate) struct ImportData {
    pub context: Context, pub images: Vec<SelectedImageData>, pub protected_sources: Vec<String>,
    pub protected_objects: Vec<SourceObject>,
}
impl ImportData {
    pub(crate) fn valid(&self) -> bool {
        let mut ids = BTreeSet::new();
        self.context.valid() && (1..=MAX_FILES).contains(&self.images.len())
            && self.images.iter().try_fold(0usize, |sum, image| sum.checked_add(image.bytes.len())).is_some_and(|sum| sum <= BATCH_LIMIT)
            && self.images.iter().all(|image| image.item().valid() && ids.insert(&image.item_id) && digest(&image.bytes) == image.sha256)
            && self.protected_sources.len() <= MAX_FILES && self.protected_sources.iter().all(|path| protected_source(path))
            && self.protected_sources.iter().collect::<BTreeSet<_>>().len() == self.protected_sources.len()
            && self.protected_objects.len() == self.images.len() && self.protected_objects.iter().all(SourceObject::valid)
            && self.protected_objects.iter().collect::<BTreeSet<_>>().len() == self.images.len()
            && self.protected_objects.first().is_some_and(|first| self.protected_objects.iter().all(|row| row.family() == first.family()))
    }
    pub(crate) fn details(&self) -> Details {
        Details { intent: Intent::Import, checkout: None, prepared: None,
            context: Some(self.context.clone()), selected: self.images.iter().map(SelectedImageData::item).collect(), submission: None }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Intent { Import, Recover }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SelectionPhase { Selecting, Capturing, Selected, Cancelled, Failed, Unknown }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SelectionReason { None, Cancelled, DialogFailed, UnsupportedPlatform, RuntimeUnqualified,
    InvalidSelection, SourceChanged, SourceUnavailable, SelectionLimit, Busy, CallerLost, WindowLost, Shutdown, ActiveTimeout, CleanupUnknown }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SelectionSettlement { Pending, Known, Unknown, LateKnown }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Selection {
    pub operation_id: String, pub project_id: String, pub platform: Platform, pub locale: String, pub asset_type: String,
    pub phase: SelectionPhase, pub reason: SelectionReason, pub settlement: SelectionSettlement,
    pub selection_token: Option<String>, pub items: Vec<SelectedItem>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SelectionStatus {
    pub schema_version: u32, pub domain: &'static str, pub window_generation: String, pub status_revision: u32,
    pub capability: Capability, pub active: Option<Selection>, pub last_terminal: Option<Selection>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ContentDigest { pub byte_length: u32, pub sha256: String }
impl ContentDigest { fn valid(&self, limit: usize) -> bool { self.byte_length as usize <= limit && hex(&self.sha256) } }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Baseline { pub config: ContentDigest, pub ignore: ContentDigest, pub inventory_sha256: String }
impl Baseline { pub(crate) fn valid(&self) -> bool { self.config.valid(512 * 1024) && self.ignore.valid(1024 * 1024) && hex(&self.inventory_sha256) } }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Choice { pub item_id: String, pub replace_existing: bool }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrepareMetadataImagesEdit {
    pub session_id: String, pub revision: String, pub draft_revision: u32, pub baseline_generation: u32,
    pub expected_baseline: Baseline, pub choices: Vec<Choice>,
}
#[derive(Clone)]
pub(crate) struct Submission { pub expected_baseline: Baseline, pub choices: Vec<Choice> }
impl Submission {
    pub(crate) fn valid_for(&self, detail: &Details) -> bool {
        if !self.expected_baseline.valid() || detail.submission.is_some()
            || !detail.checkout.as_ref().is_some_and(|old| old.baseline == self.expected_baseline) { return false; }
        if detail.intent == Intent::Recover { return self.choices.is_empty(); }
        self.choices.len() == detail.selected.len() && self.choices.iter().zip(&detail.selected)
            .all(|(choice, selected)| token(&choice.item_id) && choice.item_id == selected.item_id)
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Checkout { pub revision: String, pub baseline: Baseline, pub view: Value }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Prepared {
    pub revision: String, pub plan_token: String, pub draft_revision: u32, pub baseline_generation: u32, pub view: Value,
}
#[derive(Clone, Serialize)]
pub(crate) struct Details {
    pub intent: Intent, pub checkout: Option<Checkout>, pub prepared: Option<Prepared>,
    #[serde(skip)] pub context: Option<Context>,
    #[serde(skip)] pub selected: Vec<SelectedItem>,
    #[serde(skip)] pub submission: Option<Submission>,
}
impl Details {
    pub(crate) fn recovery() -> Self { Self { intent: Intent::Recover, checkout: None, prepared: None,
        context: None, selected: Vec::new(), submission: None } }
    pub(crate) fn opened_matches(&self, opened: &Opened) -> bool {
        if self.intent != opened.intent || !view_valid(&opened.view, false) { return false; }
        if self.intent == Intent::Recover { return opened.view["kind"] == "recover" && self.context.is_none() && self.selected.is_empty(); }
        let Some(context) = &self.context else { return false; };
        let Some(files) = opened.view["files"].as_array() else { return false; };
        opened.view["kind"] == "import" && opened.view["platform"] == json!(context.platform)
            && opened.view["locale"] == context.locale && opened.view["assetType"] == context.asset_type
            && files.len() == self.selected.len() && files.iter().zip(&self.selected).all(|(file, selected)|
                file["itemId"] == selected.item_id && file["displayName"] == selected.display_name
                && file["selected"]["byteLength"] == selected.byte_length && file["selected"]["sha256"] == selected.sha256
                && file["action"] == if file["before"].is_null() { "create" } else { "preserve" })
    }
    pub(crate) fn prepared_matches(&self, prepared: &PreparedReply) -> bool {
        let (Some(checkout), Some(submission)) = (&self.checkout, &self.submission) else { return false; };
        if !view_valid(&prepared.view, true) || submission.expected_baseline != checkout.baseline { return false; }
        if self.intent == Intent::Recover { return submission.choices.is_empty() && prepared.view == checkout.view; }
        for key in ["kind", "policy", "platform", "locale", "assetType", "metadataRoot", "folder", "existing", "assurance"] {
            if prepared.view[key] != checkout.view[key] { return false; }
        }
        let (Some(old), Some(new)) = (checkout.view["files"].as_array(), prepared.view["files"].as_array()) else { return false; };
        old.len() == new.len() && old.len() == submission.choices.len()
            && old.iter().zip(new).zip(&submission.choices).all(|((old, new), choice)| {
                if ["itemId", "displayName", "path", "before", "selected", "canReplace", "issues"].iter().any(|key| old[*key] != new[*key])
                    || new["itemId"] != choice.item_id { return false; }
                let same = !old["before"].is_null() && old["before"]["sha256"] == old["selected"]["sha256"]
                    && old["before"]["byteLength"] == old["selected"]["byteLength"];
                if choice.replace_existing && (old["before"].is_null() || !same && old["canReplace"] != true) { return false; }
                let action = if old["before"].is_null() { "create" } else if choice.replace_existing && !same { "replace" } else { "preserve" };
                new["action"] == action && new["after"] == if action == "preserve" { old["before"].clone() } else { old["selected"].clone() }
            })
    }
    pub(crate) fn terminal_admissible(&self, submitted: bool, core: &CoreEditOutcome) -> bool {
        if !core.valid() { return false; }
        if self.intent == Intent::Import {
            if !submitted { return matches!(core.effect, Effect::NotStarted | Effect::Unknown)
                && matches!(core.journal, Journal::NotCreated | Journal::Unknown); }
            let Some(expected) = self.prepared.as_ref().and_then(|p| expected_success(&p.view)) else { return false; };
            if core.reason == CoreReason::None { return (core.effect.clone(), core.journal.clone()) == expected; }
            return match core.effect {
                Effect::Unchanged => expected.0 == Effect::Unchanged,
                Effect::Committed | Effect::RolledBack => expected.0 == Effect::Committed,
                Effect::NotStarted | Effect::Unknown => true,
            };
        }
        let Some(checkout) = &self.checkout else {
            // Refused inspection may know a journal exists, but has no proof of
            // an old commit/rollback. Retain it without inventing an import.
            return !submitted && matches!(core.effect, Effect::NotStarted | Effect::Unknown)
                && matches!(core.journal, Journal::NotCreated | Journal::RecoveryRequired | Journal::Unknown);
        };
        if checkout.view["state"] != "recoverable" {
            return !submitted && matches!(core.effect, Effect::NotStarted | Effect::Unknown)
                && matches!(core.journal, Journal::NotCreated | Journal::RecoveryRequired | Journal::Unknown);
        }
        let Some(expected) = expected_success(&checkout.view) else { return false; };
        if core.reason == CoreReason::None {
            return submitted && self.prepared.as_ref().is_some_and(|p| p.view == checkout.view)
                && (core.effect.clone(), core.journal.clone()) == expected;
        }
        if !submitted && !matches!(core.journal, Journal::RecoveryRequired | Journal::Unknown) { return false; }
        let allowed_effect = match checkout.view["action"].as_str() {
            Some("committed_cleanup") => matches!(core.effect, Effect::Committed | Effect::Unknown),
            Some("rolled_back_cleanup") => matches!(core.effect, Effect::RolledBack | Effect::Unknown),
            Some("preparing_cleanup") => matches!(core.effect, Effect::NotStarted | Effect::Unknown),
            Some("rollback") => matches!(core.effect, Effect::NotStarted | Effect::Unknown)
                || submitted && core.effect == Effect::RolledBack,
            _ => false,
        };
        allowed_effect && matches!(core.journal, Journal::Clean | Journal::RecoveryRequired | Journal::Unknown)
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Projection {
    pub domain: &'static str, pub project_id: String, pub session_id: String, pub owner_generation: String,
    pub phase: Phase, pub review_remaining_ms: u32, pub apply_submitted: bool, pub core_outcome: Option<CoreEditOutcome>,
    pub native_reason: NativeEditReason, pub native_finality: NativeFinality, pub late_settled: bool, pub details: Option<Details>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MetadataImagesEditStatus {
    pub schema_version: u32, pub domain: &'static str, pub window_generation: String, pub status_revision: u32,
    pub capability: Capability, pub active: Option<Projection>, pub last_terminal: Option<Projection>,
}

fn content(value: &Value) -> bool {
    keys(value, &["byteLength", "sha256"]) && number(&value["byteLength"], FILE_LIMIT) && value["sha256"].as_str().is_some_and(hex)
}
fn summary(value: &Value) -> bool {
    if !keys(value, &["byteLength", "sha256", "format", "width", "height", "headerChecked"])
        || !number(&value["byteLength"], FILE_LIMIT) || !value["sha256"].as_str().is_some_and(hex) || !value["headerChecked"].is_boolean() { return false; }
    if value["format"].is_null() { return value["width"].is_null() && value["height"].is_null() && value["headerChecked"] == false; }
    matches!(value["format"].as_str(), Some("png" | "jpeg")) && number(&value["width"], u32::MAX as usize)
        && number(&value["height"], u32::MAX as usize) && (value["headerChecked"] != true
            || value["width"].as_u64().is_some_and(|w| w > 0 && w <= 16384)
                && value["height"].as_u64().is_some_and(|h| h > 0 && h <= 16384)
                && value["width"].as_u64().and_then(|w| value["height"].as_u64().and_then(|h| w.checked_mul(h))).is_some_and(|p| p <= 67108864))
}
const IMAGE_ISSUES: &[(&str, &str)] = &[
    ("image.empty", "The selected image is empty."),
    ("image.limit", "The selected image exceeds the 10 MiB file limit."),
    ("image.format", "Select a PNG or JPEG image; this file's contents have another format."),
    ("image.header", "The image's dimension-bearing header is incomplete or invalid."),
    ("image.extension", "The filename extension does not match the PNG or JPEG contents."),
    ("image.dimensions", "The image dimensions exceed the bounded local inspection limits."),
    ("image.device", "These dimensions do not match the selected Apple display type in the pinned Store tool."),
    ("image.singleton", "Another format already occupies this single-image slot; choose the existing image format."),
    ("image.portable-collision", "Two image names would collide on a supported filesystem; no file was changed."),
    ("image.duplicate", "The resulting image set contains duplicate image contents."),
    ("image.count", "The resulting image set exceeds the selected type's supported count."),
    ("image.sibling", "An existing image in this selected set is unsupported or invalid; preserve it and review the conflict."),
    ("image.total", "The selected and existing image data exceed this transaction's bounded size; use a smaller set."),
    ("image.source-target", "This destination is one of your selected original files. Keep that original unchanged or select another source file."),
];
fn issues(value: &Value, recovery: bool) -> bool {
    let Some(rows) = value.as_array() else { return false; };
    let mut codes = BTreeSet::new();
    rows.len() <= 16 && rows.iter().all(|row| keys(row, &["code", "severity", "message"]) && row["severity"] == "error"
        && row["code"].as_str().is_some_and(|code| codes.insert(code) && if recovery {
            code == "image.recovery-conflict" && row["message"] == "The complete image recovery state could not be verified. Nothing was changed; preserve the journal and review the conflict."
        } else { IMAGE_ISSUES.iter().any(|(allowed, message)| code == *allowed && row["message"] == *message) }))
}
fn import_view(value: &Value, prepared: bool) -> bool {
    if !keys(value, &["kind", "policy", "platform", "locale", "assetType", "metadataRoot", "folder", "files", "existing", "finalOrder", "valid", "issues", "assurance"])
        || value["kind"] != "import" || value["policy"] != "metadata-images-v1" || !value["valid"].is_boolean()
        || !issues(&value["issues"], false) || value["valid"] != value["issues"].as_array().is_some_and(Vec::is_empty)
        || prepared && value["valid"] != true { return false; }
    let Ok(context) = Context::deserialize(json!({"platform":value["platform"],"locale":value["locale"],"assetType":value["assetType"]})) else { return false; };
    let (Some(root), Some(folder)) = (value["metadataRoot"].as_str(), value["folder"].as_str()) else { return false; };
    if !context.valid() || !crate::metadata_text_edit_protocol::target_context(root, context.platform, &context.locale)
        || !relative(folder) || context.folder(root).as_deref() != Some(folder) { return false; }
    let assurance = &value["assurance"];
    if !keys(assurance, &["localCopyOnly", "sourceFilesUnchanged", "storeContacted", "fullDecode", "contentApproved", "storeAccepted"])
        || assurance["localCopyOnly"] != true || assurance["sourceFilesUnchanged"] != true
        || ["storeContacted", "fullDecode", "contentApproved", "storeAccepted"].iter().any(|key| assurance[*key] != false) { return false; }
    let (Some(files), Some(existing), Some(order)) = (value["files"].as_array(), value["existing"].as_array(), value["finalOrder"].as_array()) else { return false; };
    if !(1..=MAX_FILES).contains(&files.len()) || existing.len() > 256 || order.len() > 266 { return false; }
    let in_folder = |value: &Value| value.as_str().is_some_and(|path| relative(path)
        && path.strip_prefix(&format!("{folder}/")).is_some_and(|leaf| !leaf.is_empty() && !leaf.contains('/')));
    let mut ids = BTreeSet::new(); let mut targets = BTreeSet::new(); let mut resulting = BTreeSet::new();
    for row in existing {
        if !keys(row, &["path", "summary"]) || !in_folder(&row["path"]) || !summary(&row["summary"])
            || !resulting.insert(row["path"].as_str().unwrap_or_default()) { return false; }
    }
    for row in files {
        if !keys(row, &["itemId", "displayName", "path", "action", "before", "selected", "after", "canReplace", "issues"])
            || !row["itemId"].as_str().is_some_and(|s| token(s) && ids.insert(s))
            || !row["displayName"].as_str().is_some_and(basename) || !in_folder(&row["path"])
            || !targets.insert(row["path"].as_str().unwrap_or_default()) || !summary(&row["selected"]) || !summary(&row["after"])
            || !row["before"].is_null() && !summary(&row["before"]) || !row["canReplace"].is_boolean()
            || !issues(&row["issues"], false) || prepared && (row["selected"]["headerChecked"] != true || row["after"]["headerChecked"] != true) { return false; }
        match existing.iter().find(|old| old["path"] == row["path"]) {
            Some(old) if old["summary"] == row["before"] => {},
            None if row["before"].is_null() => {},
            _ => return false,
        }
        match row["action"].as_str() {
            Some("create") if row["before"].is_null() && row["after"] == row["selected"] && row["canReplace"] == false => {},
            Some("preserve") if !row["before"].is_null() && row["after"] == row["before"] => {},
            Some("replace") if !row["before"].is_null() && row["after"] == row["selected"] && row["canReplace"] == true => {},
            _ => return false,
        }
        resulting.insert(row["path"].as_str().unwrap_or_default());
    }
    order.len() == resulting.len() && order.iter().zip(resulting).all(|(path, expected)| path == expected)
}
fn recovery_view(value: &Value, prepared: bool) -> bool {
    if !keys(value, &["kind", "state", "action", "transactionId", "platform", "locale", "assetType", "files", "privateCleanup", "valid", "issues", "assurance"])
        || value["kind"] != "recover" || !value["valid"].is_boolean() || !issues(&value["issues"], true) { return false; }
    let assurance = &value["assurance"];
    if !keys(assurance, &["newRestorationAttempt", "sourceFilesUnchanged", "storeContacted", "importRetried"])
        || assurance["newRestorationAttempt"] != true || assurance["sourceFilesUnchanged"] != true
        || assurance["storeContacted"] != false || assurance["importRetried"] != false { return false; }
    let cleanup = &value["privateCleanup"];
    if !keys(cleanup, &["fileCount", "directoryCount", "scope"]) || cleanup["scope"] != "original-image-journal-only"
        || !number(&cleanup["fileCount"], 520) || !number(&cleanup["directoryCount"], 256) { return false; }
    let Some(files) = value["files"].as_array() else { return false; };
    let mut paths = BTreeSet::new();
    if files.len() > MAX_FILES || !files.iter().all(|file| keys(file, &["path", "effect", "original", "new"])
        && file["path"].as_str().is_some_and(|path| relative(path) && paths.insert(path))
        && matches!(file["effect"].as_str(), Some("restore_original" | "keep_committed" | "preserve"))
        && ["original", "new"].iter().all(|key| file[*key].is_null() || content(&file[*key]))) { return false; }
    let action = matches!(value["action"].as_str(), Some("rollback" | "committed_cleanup" | "rolled_back_cleanup" | "preparing_cleanup"));
    match value["state"].as_str() {
        Some("idle") => !prepared && value["valid"] == false && value["action"].is_null() && value["transactionId"].is_null()
            && ["platform", "locale", "assetType"].iter().all(|key| value[*key].is_null()) && files.is_empty()
            && cleanup["fileCount"] == 0 && cleanup["directoryCount"] == 0 && value["issues"].as_array().is_some_and(Vec::is_empty),
        Some("conflict") => !prepared && value["valid"] == false && value["action"].is_null()
            && value["issues"].as_array().is_some_and(|issues| !issues.is_empty())
            && value["transactionId"].is_null() && files.is_empty()
            && ["platform", "locale", "assetType"].iter().all(|key| value[*key].is_null())
            && cleanup["fileCount"] == 0 && cleanup["directoryCount"] == 0,
        Some("recoverable") => {
            let Ok(context) = Context::deserialize(json!({"platform":value["platform"],"locale":value["locale"],"assetType":value["assetType"]})) else { return false; };
            let Some(suffix) = context.folder("") else { return false; };
            let Some((folder, _)) = files.first().and_then(|file| file["path"].as_str()).and_then(|path| path.rsplit_once('/')) else { return false; };
            let Some(root) = folder.strip_suffix(&suffix) else { return false; };
            if !context.valid() || !crate::metadata_text_edit_protocol::target_context(root, context.platform, &context.locale)
                || value["valid"] != true || !action || !value["transactionId"].as_str().is_some_and(token)
                || !value["issues"].as_array().is_some_and(Vec::is_empty) || cleanup["fileCount"].as_u64().unwrap_or(0) < 4
                || cleanup["directoryCount"].as_u64().unwrap_or(u64::MAX) > folder.split('/').count() as u64 { return false; }
            let Some(kind) = context.type_row() else { return false; };
            let singleton = kind["singleton"] == true;
            let mut changed = 0usize; let mut new_bytes = 0usize; let mut total_bytes = 0usize;
            for file in files {
                let Some((parent, name)) = file["path"].as_str().and_then(|path| path.rsplit_once('/')) else { return false; };
                let Some((stem, extension)) = name.rsplit_once('.') else { return false; };
                if parent != folder || !matches!(extension.to_ascii_lowercase().as_str(), "png" | "jpg" | "jpeg")
                    || singleton && !stem.eq_ignore_ascii_case(&context.asset_type) { return false; }
                if file["new"].is_null() {
                    if file["original"].is_null() || file["effect"] != "preserve" { return false; }
                } else {
                    let size = file["new"]["byteLength"].as_u64().unwrap_or(0) as usize;
                    if size == 0 || file["effect"] != if value["action"] == "committed_cleanup" { "keep_committed" } else { "restore_original" } { return false; }
                    changed += 1; new_bytes += size;
                }
                total_bytes += file["original"]["byteLength"].as_u64().unwrap_or(0) as usize
                    + file["new"]["byteLength"].as_u64().unwrap_or(0) as usize;
            }
            changed > 0 && (!singleton || files.len() == 1) && files.len() as u64 <= kind["maxCount"].as_u64().unwrap_or(0)
                && new_bytes <= BATCH_LIMIT && total_bytes <= TRANSACTION_LIMIT
                && if value["action"] == "rollback" { cleanup["fileCount"] == 4 + changed }
                    else { cleanup["fileCount"].as_u64().is_some_and(|count| count <= (4 + 2 * files.len()) as u64) }
        },
        _ => false,
    }
}
pub(crate) fn view_valid(value: &Value, prepared: bool) -> bool {
    value_bounds(value, 16, VIEW_LIMIT).is_ok() && match value["kind"].as_str() {
        Some("import") => import_view(value, prepared), Some("recover") => recovery_view(value, prepared), _ => false,
    }
}
pub(crate) fn expected_success(view: &Value) -> Option<(Effect, Journal)> {
    if !view_valid(view, true) { return None; }
    match view["kind"].as_str() {
        Some("import") => Some(if view["files"].as_array()?.iter().all(|row| row["action"] == "preserve") {
            (Effect::Unchanged, Journal::NotCreated)
        } else { (Effect::Committed, Journal::Clean) }),
        Some("recover") => Some((match view["action"].as_str()? {
            "rollback" | "rolled_back_cleanup" => Effect::RolledBack, "committed_cleanup" => Effect::Committed,
            "preparing_cleanup" => Effect::NotStarted, _ => return None,
        }, Journal::Clean)),
        _ => None,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Opened { pub intent: Intent, pub revision: String, pub baseline: Baseline, pub view: Value, pub scope_resources: ResourceState }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PreparedReply { pub revision: String, pub plan_token: String, pub view: Value, pub scope_resources: ResourceState }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TerminalReply {
    pub kind: String, pub plan_token: Option<String>, pub effect: Effect, pub journal: Journal, pub resources: ResourceState, pub reason: CoreReason,
}
impl TerminalReply { pub(crate) fn outcome(&self) -> CoreEditOutcome {
    CoreEditOutcome { effect: self.effect.clone(), journal: self.journal.clone(), resources: self.resources.clone(), reason: self.reason.clone() }
} }

pub(crate) fn decode(bytes: &[u8], session: &str) -> Result<ChildFrame, BridgeError> {
    if !token(session) || bytes.len() > RESPONSE_LIMIT || !bytes.ends_with(b"\n") { return Err(BridgeError::protocol()); }
    let body = &bytes[..bytes.len() - 1];
    if body.first() != Some(&b'{') || body.last() != Some(&b'}') || body.iter().any(|b| matches!(*b, b'\r' | b'\n')) { return Err(BridgeError::protocol()); }
    let value = strict_json(body)?;
    if !keys(&value, &["protocol", "session", "seq", "kind", "result"]) || value["protocol"] != PROTOCOL || value["session"] != session { return Err(BridgeError::protocol()); }
    let seq = value["seq"].as_u64().filter(|seq| *seq <= 2).ok_or_else(BridgeError::protocol)? as u32;
    let raw = &value["result"];
    match value["kind"].as_str() {
        Some("opened") if seq == 0 && keys(raw, &["intent", "revision", "baseline", "view", "scopeResources"]) => {
            let result = Opened::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || !result.baseline.valid() || !view_valid(&result.view, false)
                || result.scope_resources != ResourceState::Settled || result.view["kind"] != json!(result.intent) { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::MetadataImagesOpened(result))
        },
        Some("prepared") if seq == 1 && keys(raw, &["revision", "planToken", "view", "scopeResources"]) => {
            let result = PreparedReply::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || !token(&result.plan_token) || result.revision == result.plan_token
                || result.scope_resources != ResourceState::Settled || !view_valid(&result.view, true) { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::MetadataImagesPrepared(result))
        },
        Some("terminal") if bytes.len() <= edit::TERMINAL_LIMIT && keys(raw, &["kind", "planToken", "effect", "journal", "resources", "reason"]) => {
            let result = TerminalReply::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if result.kind != "outcome" || !result.outcome().valid() || result.plan_token.as_deref().is_some_and(|s| !token(s)) { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::MetadataImagesTerminal(seq, result))
        },
        _ => Err(BridgeError::protocol()),
    }
}

fn base64(raw: &[u8]) -> Result<String, BridgeError> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let size = raw.len().checked_add(2).and_then(|n| (n / 3).checked_mul(4)).ok_or_else(BridgeError::invalid)?;
    let mut output = String::new(); output.try_reserve_exact(size).map_err(|_| BridgeError::invalid())?;
    for bytes in raw.chunks(3) {
        let a = bytes[0]; let b = *bytes.get(1).unwrap_or(&0); let c = *bytes.get(2).unwrap_or(&0);
        output.push(ALPHABET[(a >> 2) as usize] as char);
        output.push(ALPHABET[((a & 3) << 4 | b >> 4) as usize] as char);
        output.push(if bytes.len() > 1 { ALPHABET[((b & 15) << 2 | c >> 6) as usize] as char } else { '=' });
        output.push(if bytes.len() > 2 { ALPHABET[(c & 63) as usize] as char } else { '=' });
    }
    Ok(output)
}
fn canonical_base64(encoded: &str, size: usize) -> bool {
    if size == 0 || size > FILE_LIMIT || encoded.len() != (size + 2) / 3 * 4 { return false; }
    let bytes = encoded.as_bytes();
    let padding = (3 - size % 3) % 3;
    let value = |b: u8| -> Option<u8> { match b {
        b'A'..=b'Z' => Some(b - b'A'), b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52), b'+' => Some(62), b'/' => Some(63), _ => None,
    } };
    let end = bytes.len() - padding;
    bytes[..end].iter().all(|byte| value(*byte).is_some()) && bytes[end..].iter().all(|byte| *byte == b'=')
        && (padding == 0 || value(bytes[end - 1]).is_some_and(|v| (v & (if padding == 2 { 15 } else { 3 })) == 0))
}
fn import_wire_valid(params: &Value, family: ImageIdentityFamily) -> bool {
    let Ok(context) = Context::deserialize(json!({"platform":params["platform"],"locale":params["locale"],"assetType":params["assetType"]})) else { return false; };
    let (Some(images), Some(paths), Some(objects)) = (params["images"].as_array(), params["protectedSources"].as_array(),
        params["protectedObjects"].as_array()) else { return false; };
    if !context.valid() || !(1..=MAX_FILES).contains(&images.len()) || paths.len() > MAX_FILES || objects.len() != images.len() { return false; }
    let mut ids = BTreeSet::new(); let mut total = 0usize; let mut original_paths = BTreeSet::new(); let mut original_objects = BTreeSet::new();
    paths.iter().all(|path| path.as_str().is_some_and(|path| protected_source(path) && original_paths.insert(path)))
        && objects.iter().all(|row| SourceObject::deserialize(row).is_ok_and(|object| object.valid()
            && object.family() == family && original_objects.insert(object)))
        && images.iter().all(|row| {
            if !keys(row, &["itemId", "displayName", "byteLength", "sha256", "base64"])
                || !row["itemId"].as_str().is_some_and(|id| token(id) && ids.insert(id))
                || !row["displayName"].as_str().is_some_and(basename)
                || !row["sha256"].as_str().is_some_and(hex) { return false; }
            let Some(size) = row["byteLength"].as_u64().filter(|size| (1..=FILE_LIMIT as u64).contains(size)) else { return false; };
            total += size as usize; // At most ten already bounded rows.
            total <= BATCH_LIMIT && row["base64"].as_str().is_some_and(|encoded| canonical_base64(encoded, size as usize))
        })
}

// Two serialization passes avoid Vec's geometric capacity growth for the one
// large frame. The requested backing is <=32MiB(+padding) encoded DATA plus a
// <=33MiB frame, not a 64MiB process-RSS promise. Raw bodies are consumed first;
// the owned Value insertions below avoid serializing/cloning the big strings.
struct Count { length: usize, limit: usize }
impl io::Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.length) { return Err(io::Error::new(io::ErrorKind::InvalidData, "bounded image request")); }
        self.length += bytes.len(); Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
fn frame_exact(value: &Value, limit: usize) -> Result<Vec<u8>, BridgeError> {
    let mut count = Count { length: 0, limit: limit.saturating_sub(1) };
    serde_json::to_writer(&mut count, value).map_err(|_| BridgeError::invalid())?;
    let mut bytes = Vec::new(); bytes.try_reserve_exact(count.length + 1).map_err(|_| BridgeError::invalid())?;
    serde_json::to_writer(&mut bytes, value).map_err(|_| BridgeError::invalid())?;
    if bytes.len() != count.length { return Err(BridgeError::invalid()); }
    bytes.push(b'\n'); Ok(bytes)
}
pub(crate) fn import_params(root: &str, registered: ImageRegisteredIdentity, data: ImportData) -> Result<Value, BridgeError> {
    if !registered.valid_root(root) || !data.valid()
        || data.protected_objects.iter().any(|object| object.family() != registered.family()) { return Err(BridgeError::invalid()); }
    let mut images = Vec::new(); images.try_reserve_exact(data.images.len()).map_err(|_| BridgeError::invalid())?;
    for image in data.images {
        let encoded = base64(&image.bytes)?;
        let mut row = json!({"itemId":image.item_id,"displayName":image.display_name,"byteLength":image.bytes.len(),"sha256":image.sha256});
        row["base64"] = Value::String(encoded);
        images.push(row);
        // Consume raw backing as each item is encoded. No byte copy survives in
        // a renderer projection or original selection after the atomic handoff.
    }
    let mut params = json!({"root":root,"registeredIdentity":registered,"intent":"import","platform":data.context.platform,
        "locale":data.context.locale,"assetType":data.context.asset_type,"protectedSources":data.protected_sources,
        "protectedObjects":data.protected_objects});
    params["images"] = Value::Array(images);
    Ok(params)
}
pub(crate) fn request(session: &str, seq: u32, op: &str, params: Value) -> Result<Vec<u8>, BridgeError> {
    if !token(session) || seq > 2 { return Err(BridgeError::invalid()); }
    let legal = match (seq, op) {
        (0, "open") => {
            let import = params["intent"] == "import";
            let roster = if import { &["root", "registeredIdentity", "intent", "platform", "locale", "assetType", "images", "protectedSources", "protectedObjects"][..] }
                else { &["root", "registeredIdentity", "intent"][..] };
            keys(&params, roster) && (import || params["intent"] == "recover")
                && ImageRegisteredIdentity::deserialize(&params["registeredIdentity"]).is_ok_and(|identity|
                    params["root"].as_str().is_some_and(|root| identity.valid_root(root))
                        && (!import || import_wire_valid(&params, identity.family())))
        },
        (1, "prepare") => keys(&params, &["revision", "expectedBaseline", "choices"])
            && params["revision"].as_str().is_some_and(token)
            && Baseline::deserialize(&params["expectedBaseline"]).is_ok_and(|baseline| baseline.valid())
            && Vec::<Choice>::deserialize(&params["choices"]).is_ok_and(|choices| {
                let mut ids = BTreeSet::new();
                choices.len() <= MAX_FILES && choices.iter().all(|choice| token(&choice.item_id) && ids.insert(&choice.item_id))
            }),
        (2, "apply") => keys(&params, &["planToken"]) && params["planToken"].as_str().is_some_and(token),
        (1 | 2, "discard") => keys(&params, &[]),
        _ => false,
    };
    if !legal { return Err(BridgeError::invalid()); }
    let limit = if seq == 0 && params["intent"] == "import" { REQUEST_LIMIT } else { SMALL_REQUEST_LIMIT };
    let mut value = json!({"protocol":PROTOCOL,"session":session,"seq":seq,"op":op});
    value["params"] = params;
    check_value(&value)?;
    frame_exact(&value, limit)
}

pub(crate) fn catalog() -> Result<Value, BridgeError> {
    // Compile-time core-owned DATA; no file lookup, child or selected project.
    let source = strict_json(include_bytes!("../../../src/mobile_release/api/data/metadata-images-v1.json"))?;
    let help = strict_json(include_bytes!("../../../src/mobile_release/api/data/metadata-image-help-v1.json"))?;
    let value = json!({"schemaVersion":1,"policy":"metadata-images-v1",
        "platforms":[{"id":"android","label":"Android / Google Play"},{"id":"ios","label":"iOS / App Store"}],
        "types":source["types"],"limits":{"maxFiles":MAX_FILES,"maxFileBytes":FILE_LIMIT,"maxBatchBytes":BATCH_LIMIT,
        "maxTransactionBytes":TRANSACTION_LIMIT,"maxDimension":16384,"maxPixels":67108864,"formats":["png","jpeg"]},"help":help["fields"]});
    value_bounds(&value, 16, 128 * 1024)?; Ok(value)
}

#[cfg(test)]
#[path = "metadata_images_edit_protocol_tests.rs"]
pub(crate) mod tests;
