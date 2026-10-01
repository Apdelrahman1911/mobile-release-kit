//! Closed required-note transport. Private text/baselines are direct responses,
//! never routine status or evidence. The original core owns policy and paths.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use crate::{edit_protocol::{self as edit, bounded, token, ChildFrame, CoreEditOutcome,
    CoreReason, Effect, Journal, NativeEditReason, NativeFinality, Phase, ResourceState},
    error::BridgeError, github_workflow_edit_protocol::{value_bounds, RegisteredIdentity},
    protocol::{check_value, strict_json}};

pub(crate) const PROTOCOL: &str = "mrk-required-notes/1";
pub(crate) const DOMAIN: &str = "required_notes";
pub(crate) const EVENT: &str = "mrk-required-notes-status";
pub(crate) const IMPORT_EVENT: &str = "mrk-required-notes-import-status";
pub(crate) const REQUEST_LIMIT: usize = 512 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 1024 * 1024;
pub(crate) const OPENED_LIMIT: usize = 16 * 1024;
pub(crate) const VIEW_LIMIT: usize = 896 * 1024;
pub(crate) const STATUS_LIMIT: usize = 16 * 1024;
pub(crate) const VALIDATE_CHARACTERS: usize = 65537;
pub(crate) const VALIDATE_BYTES: usize = 4 * VALIDATE_CHARACTERS;

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Kind { AndroidBuild, AndroidDefault, IosBetaReview, IosAppReview, TestflightWhatToTest }
impl Kind {
    pub(crate) fn android(self) -> bool { matches!(self, Self::AndroidBuild | Self::AndroidDefault) }
    pub(crate) fn byte_limit(self) -> usize {
        match self { Self::AndroidBuild | Self::AndroidDefault => 2000, Self::TestflightWhatToTest => 65536, _ => 32768 }
    }
    fn character_limit(self) -> Option<u32> {
        match self { Self::AndroidBuild | Self::AndroidDefault => Some(500), Self::TestflightWhatToTest => Some(4000), _ => None }
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Context {
    #[serde(rename = "android-build")] AndroidBuild { locale: String },
    #[serde(rename = "android-default")] AndroidDefault { locale: String },
    #[serde(rename = "ios-beta-review")] IosBetaReview {},
    #[serde(rename = "ios-app-review")] IosAppReview {},
    #[serde(rename = "testflight-what-to-test")] TestflightWhatToTest {},
}
impl Context {
    pub(crate) fn retained_bytes(&self) -> usize { match self { Self::AndroidBuild { locale } | Self::AndroidDefault { locale } => locale.capacity(), _ => 0 } }
    pub(crate) fn kind(&self) -> Kind {
        match self { Self::AndroidBuild { .. } => Kind::AndroidBuild, Self::AndroidDefault { .. } => Kind::AndroidDefault,
            Self::IosBetaReview {} => Kind::IosBetaReview, Self::IosAppReview {} => Kind::IosAppReview,
            Self::TestflightWhatToTest {} => Kind::TestflightWhatToTest }
    }
    pub(crate) fn valid(&self) -> bool {
        match self { Self::AndroidBuild { locale } | Self::AndroidDefault { locale } =>
            crate::metadata_text_edit_protocol::locale_bounded(locale) && !locale.contains(['/', '\\']), _ => true }
    }
    fn destination(&self, root: &str, build: Option<u32>) -> Option<String> {
        Some(match self {
            Self::AndroidBuild { locale } => format!("{root}/android/{locale}/changelogs/{}.txt", build?),
            Self::AndroidDefault { locale } => { let _ = build?; format!("{root}/android/{locale}/changelogs/default.txt") },
            Self::IosBetaReview {} => format!("{root}/review/ios-beta-notes.txt"),
            Self::IosAppReview {} => format!("{root}/review/ios-notes.txt"),
            Self::TestflightWhatToTest {} => format!("{root}/testflight/what-to-test.txt"),
        })
    }
}
fn keys(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|v| v.len() == names.len() && names.iter().all(|name| v.contains_key(*name)))
}
fn hex(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
// Nullable fields remain required in the closed wire; missing is not null.
fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where D: serde::Deserializer<'de>, T: Deserialize<'de> { Option::<T>::deserialize(deserializer) }
fn relative(path: &str) -> bool {
    !path.is_empty() && path.len() <= 512 && path.split('/').count() <= 12 && path.split('/').all(|part|
        !part.is_empty() && part.len() <= 255 && !part.starts_with('.') && !part.ends_with(['.', ' '])
        && !part.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}' || "\\:<>\"|?*".contains(c)))
}
pub(crate) fn validate_text_bounded(text: &str) -> bool { text.len() <= VALIDATE_BYTES && text.chars().count() <= VALIDATE_CHARACTERS }

// These private DATA types intentionally have no Debug implementation.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ContentDigest { pub(crate) byte_length: u32, pub(crate) sha256: String }
impl ContentDigest { fn valid(&self, max: usize, nonempty: bool) -> bool {
    self.byte_length as usize <= max && (!nonempty || self.byte_length != 0) && hex(&self.sha256)
} }
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Assertion {
    Absent {}, Present { #[serde(rename = "byteLength")] byte_length: u32, sha256: String },
}
impl Assertion {
    fn present(&self) -> bool { matches!(self, Self::Present { .. }) }
    fn valid(&self, max: usize) -> bool {
        match self { Self::Absent {} => true, Self::Present { byte_length, sha256 } => *byte_length as usize <= max && hex(sha256) }
    }
    fn matches(&self, original: &Original, max: usize) -> bool {
        match (self, original) {
            (Self::Absent {}, Original::Absent {}) => true,
            (Self::Present { byte_length, sha256 }, Original::Present { text }) =>
                text.len() <= max && text.len() == *byte_length as usize && digest(text.as_bytes()) == *sha256,
            _ => false,
        }
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Baseline {
    pub(crate) config: ContentDigest,
    #[serde(deserialize_with = "required_option")]
    pub(crate) version: Option<ContentDigest>,
    pub(crate) note: Assertion,
    #[serde(deserialize_with = "required_option")]
    pub(crate) counterpart: Option<Assertion>,
}
impl Baseline {
    pub(crate) fn valid_for(&self, context: &Context) -> bool {
        context.valid() && self.config.valid(512 * 1024, true) && self.note.valid(context.kind().byte_limit())
            && if context.kind().android() {
                self.version.as_ref().is_some_and(|d| d.valid(65536, true)) && self.counterpart.as_ref().is_some_and(|d| d.valid(2000))
            } else { self.version.is_none() && self.counterpart.is_none() }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Original { Absent {}, Present { text: String } }
impl Original { fn text(&self) -> Option<&str> { match self { Self::Absent {} => None, Self::Present { text } => Some(text) } } }
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum EffectiveSource { Exact, Default, Missing }
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Effective { source: EffectiveSource, valid: bool }
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Selection {
    pub(crate) context: Context, pub(crate) metadata_root: String, pub(crate) destination: String,
    #[serde(deserialize_with = "required_option")]
    pub(crate) saved_build: Option<u32>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) effective: Option<Effective>,
}
impl Selection {
    fn valid(&self, baseline: &Baseline) -> bool {
        if !baseline.valid_for(&self.context) || !relative(&self.metadata_root) || !relative(&self.destination)
            || self.context.destination(&self.metadata_root, self.saved_build).as_deref() != Some(self.destination.as_str()) { return false; }
        if self.context.kind().android() {
            if !self.saved_build.is_some_and(|build| (1..=2_100_000_000).contains(&build)) { return false; }
            let (exact, default) = if self.context.kind() == Kind::AndroidBuild {
                (baseline.note.present(), baseline.counterpart.as_ref().is_some_and(Assertion::present))
            } else { (baseline.counterpart.as_ref().is_some_and(Assertion::present), baseline.note.present()) };
            let source = if exact { EffectiveSource::Exact } else if default { EffectiveSource::Default } else { EffectiveSource::Missing };
            self.effective.as_ref().is_some_and(|value| value.source == source && (source != EffectiveSource::Missing || !value.valid))
        } else { self.saved_build.is_none() && self.effective.is_none() }
    }
}

const ISSUES: [(&str, &str); 13] = [
    ("notes.missing", "This selected note file has not been saved yet."),
    ("notes.utf8", "Use a UTF-8 text file. The selected contents were not decoded or changed."),
    ("notes.editor-byte-limit", "This note exceeds its disclosed local text-editor byte limit. It was not truncated."),
    ("notes.android-content", "Google Play notes need non-whitespace text without NUL characters."),
    ("notes.android-length", "Google Play notes allow 500 Unicode characters, including all whitespace and line endings."),
    ("notes.android-policy", "Google Play notes failed the shared core release-note policy."),
    ("notes.apple-empty", "Apple receives an empty value after its whitespace trimming. Add useful instructions."),
    ("notes.testflight-length", "TestFlight what-to-test allows at most 4000 characters after Apple-bound whitespace trimming."),
    ("metadata.empty-text", "Add non-whitespace instructions instead of an empty note."),
    ("metadata.nul", "Text notes must not contain NUL characters."),
    ("metadata.placeholder", "Replace unresolved placeholders with reviewed release or testing instructions."),
    ("metadata.secret-pattern", "Remove possible credentials from this note. Use the separate credential fields; rotate any exposed credential."),
    ("metadata.length", "The note exceeds the existing core preflight character limit."),
];
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Issue { code: String, message: String }
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ValidationState { FormatValid, Invalid }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Validation {
    schema_version: u32, pub(crate) kind: Kind, pub(crate) valid: bool, state: ValidationState,
    #[serde(deserialize_with = "required_option")]
    raw_byte_count: Option<u32>,
    #[serde(deserialize_with = "required_option")]
    character_count: Option<u32>,
    #[serde(deserialize_with = "required_option")]
    character_limit: Option<u32>,
    #[serde(deserialize_with = "required_option")]
    outbound_character_count: Option<u32>, editor_byte_limit: u32, issues: Vec<Issue>,
}
impl Validation {
    fn valid_for(&self, kind: Kind) -> bool {
        if self.schema_version != 1 || self.kind != kind || self.character_limit != kind.character_limit()
            || self.editor_byte_limit as usize != kind.byte_limit() || self.issues.len() > ISSUES.len()
            || self.raw_byte_count.is_some_and(|n| n as usize > VALIDATE_BYTES)
            || self.character_count.is_some_and(|n| n as usize > VALIDATE_CHARACTERS)
            || self.outbound_character_count.is_some_and(|n| n as usize > VALIDATE_CHARACTERS)
            || self.valid != self.issues.is_empty() || (self.state == ValidationState::FormatValid) != self.valid { return false; }
        let mut seen = std::collections::BTreeSet::new();
        if !self.issues.iter().all(|row| seen.insert(row.code.as_str()) && ISSUES.iter().any(|(code, message)| row.code == *code && row.message == *message)) { return false; }
        !self.valid || self.raw_byte_count.is_some_and(|n| n as usize <= kind.byte_limit())
            && self.character_count.is_some() && if kind.android() { self.outbound_character_count.is_none() } else { self.outbound_character_count.is_some() }
    }
    fn has(&self, code: &str) -> bool { self.issues.iter().any(|row| row.code == code) }
    fn matches_text(&self, text: Option<&str>) -> bool {
        let Some(text) = text else {
            return !self.valid && self.has("notes.missing") && self.raw_byte_count.is_none()
                && self.character_count.is_none() && self.outbound_character_count.is_none();
        };
        if self.raw_byte_count != Some(text.len() as u32) { return false; }
        if text.len() > self.kind.byte_limit() {
            return !self.valid && self.has("notes.editor-byte-limit") && self.character_count.is_none() && self.outbound_character_count.is_none();
        }
        // Transport correlation only; never a provider policy decision. The raw
        // submitted bytes are not replaced by either counting view.
        if self.kind.android() { self.character_count == Some(text.chars().count() as u32) && self.outbound_character_count.is_none() }
        else {
            self.character_count == Some(text.replace("\r\n", "\n").replace('\r', "\n").trim_end_matches('\n').chars().count() as u32)
                && self.outbound_character_count == Some(text.trim_matches(['\0', '\t', '\n', '\u{b}', '\u{c}', '\r', ' ']).chars().count() as u32)
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Observation {
    schema_version: u32, pub(crate) selection: Selection, pub(crate) baseline: Baseline,
    pub(crate) original: Original, pub(crate) validation: Validation,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Loaded {
    schema_version: u32, #[serde(rename = "type")] type_name: &'static str,
    project_id: String, window_generation: String, selection: Selection, baseline: Baseline, original: Original, validation: Validation,
}
impl Observation {
    pub(crate) fn loaded(self, project_id: String, window_generation: String) -> Loaded {
        Loaded { schema_version: 1, type_name: "required-notes-loaded", project_id, window_generation,
            selection: self.selection, baseline: self.baseline, original: self.original, validation: self.validation }
    }
}
pub(crate) fn observation_result(value: Value, context: &Context) -> Result<Observation, BridgeError> {
    value_bounds(&value, 16, REQUEST_LIMIT).map_err(|_| BridgeError::protocol())?;
    if !keys(&value, &["schemaVersion", "selection", "baseline", "original", "validation"]) { return Err(BridgeError::protocol()); }
    let result = Observation::deserialize(&value).map_err(|_| BridgeError::protocol())?;
    if result.schema_version != 1 || result.selection.context != *context || !result.selection.valid(&result.baseline)
        || !result.baseline.note.matches(&result.original, context.kind().byte_limit())
        || !result.validation.valid_for(context.kind()) || !result.validation.matches_text(result.original.text())
        || result.validation.has("notes.utf8") || result.validation.has("metadata.secret-pattern") { return Err(BridgeError::protocol()); }
    Ok(result)
}
pub(crate) fn validation_result(value: Value, context: &Context, text: &str) -> Result<Validation, BridgeError> {
    value_bounds(&value, 8, STATUS_LIMIT).map_err(|_| BridgeError::protocol())?;
    let result = Validation::deserialize(&value).map_err(|_| BridgeError::protocol())?;
    if !context.valid() || !validate_text_bounded(text) || !result.valid_for(context.kind()) || !result.matches_text(Some(text)) { return Err(BridgeError::protocol()); }
    Ok(result)
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Action { Create, Replace, Preserve }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PreparedView {
    schema_version: u32, pub(crate) selection: Selection, pub(crate) baseline: Baseline,
    pub(crate) before: Original, pub(crate) after: String, pub(crate) action: Action,
    create_directories: Vec<String>, validation: Validation,
}
impl PreparedView {
    fn valid(&self) -> bool {
        let kind = self.selection.context.kind();
        if self.schema_version != 1 || !self.selection.valid(&self.baseline)
            || !self.baseline.note.matches(&self.before, kind.byte_limit()) || self.after.len() > kind.byte_limit()
            || !self.validation.valid || !self.validation.valid_for(kind) || !self.validation.matches_text(Some(&self.after))
            || self.create_directories.len() > 11 || bounded(self, VIEW_LIMIT).is_err() { return false; }
        let action = match self.before.text() { None => Action::Create, Some(text) if text == self.after => Action::Preserve, _ => Action::Replace };
        if action != self.action { return false; }
        let Some((parent, _)) = self.selection.destination.rsplit_once('/') else { return false; };
        let mut ancestors = Vec::new(); let mut current = String::new();
        for part in parent.split('/') { if !current.is_empty() { current.push('/'); } current.push_str(part); ancestors.push(current.clone()); }
        self.create_directories.len() <= ancestors.len()
            && self.create_directories.as_slice() == &ancestors[ancestors.len().saturating_sub(self.create_directories.len())..]
            && (self.create_directories.is_empty() || action == Action::Create)
    }
    pub(crate) fn matches_checkout(&self, checkout: &Checkout, context: &Context) -> bool {
        self.selection.context == *context && self.selection == checkout.selection && self.baseline == checkout.baseline
    }
}
#[derive(Clone)]
pub(crate) struct Checkout { pub(crate) revision: String, pub(crate) selection: Selection, pub(crate) baseline: Baseline }
#[derive(Clone)]
pub(crate) struct Submission { pub(crate) context: Context, pub(crate) expected_baseline: Baseline, pub(crate) text: String }
impl Submission {
    pub(crate) fn valid_for(&self, context: &Context) -> bool {
        self.context == *context && self.expected_baseline.valid_for(context) && self.text.len() <= context.kind().byte_limit()
    }
    pub(crate) fn matches(&self, checkout: &Checkout, view: &PreparedView) -> bool {
        self.valid_for(&view.selection.context) && self.expected_baseline == checkout.baseline && self.text == view.after
    }
}
#[derive(Clone)]
pub(crate) struct PrivatePrepared { pub(crate) revision: String, pub(crate) plan_token: String, pub(crate) view: PreparedView }
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Binding {
    pub(crate) request_id: u32, pub(crate) window_generation: String, pub(crate) context: Context, pub(crate) draft_revision: u32,
}
impl Binding { pub(crate) fn valid(&self) -> bool {
    self.request_id < u32::MAX && self.draft_revision < u32::MAX && token(&self.window_generation) && self.context.valid()
} }
#[derive(Clone)]
pub(crate) struct Details {
    pub(crate) binding: Binding, pub(crate) revision: Option<String>, pub(crate) plan_token: Option<String>,
    pub(crate) action: Option<Action>,
    pub(crate) checkout: Option<Checkout>, pub(crate) prepared: Option<PrivatePrepared>, pub(crate) submission: Option<Submission>,
}
impl Details {
    pub(crate) fn new(binding: Binding) -> Self { Self { binding, revision: None, plan_token: None, action: None, checkout: None, prepared: None, submission: None } }
    pub(crate) fn drop_private(&mut self) { self.checkout = None; self.prepared = None; self.submission = None; }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PreparedDirect {
    schema_version: u32, #[serde(rename = "type")] type_name: &'static str,
    project_id: String, window_generation: String, owner_generation: String, session_id: String,
    revision: String, plan_token: String, draft_revision: u32,
    selection: Selection, baseline: Baseline, before: Original, after: String, action: Action,
    create_directories: Vec<String>, validation: Validation,
}
impl PrivatePrepared {
    pub(crate) fn direct(&self, project: &str, owner_generation: &str, session: &str, binding: &Binding) -> PreparedDirect {
        let view = self.view.clone();
        PreparedDirect { schema_version: 1, type_name: "required-notes-prepared", project_id: project.into(),
            window_generation: binding.window_generation.clone(), owner_generation: owner_generation.into(), session_id: session.into(),
            revision: self.revision.clone(), plan_token: self.plan_token.clone(), draft_revision: binding.draft_revision,
            selection: view.selection, baseline: view.baseline, before: view.before, after: view.after, action: view.action,
            create_directories: view.create_directories, validation: view.validation }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PreparedEnvelope { pub(crate) request_id: u32, pub(crate) prepared: PreparedDirect }
// Construct explicitly BEFORE emission. Never flatten/serialize private Details.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RoutineStatus {
    pub(crate) schema_version: u32, pub(crate) domain: &'static str, pub(crate) project_id: String,
    pub(crate) window_generation: String, pub(crate) owner_generation: String, pub(crate) session_id: String,
    pub(crate) plan_token: Option<String>, pub(crate) revision: Option<String>, pub(crate) context: Context,
    pub(crate) draft_revision: u32, pub(crate) status_revision: u32, pub(crate) phase: Phase, pub(crate) apply_submitted: bool,
    pub(crate) core_outcome: Option<CoreEditOutcome>, pub(crate) native_reason: NativeEditReason,
    pub(crate) native_finality: NativeFinality, pub(crate) late_settled: bool,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StatusEnvelope { pub(crate) request_id: u32, pub(crate) status: Option<RoutineStatus> }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Opened { pub(crate) revision: String, pub(crate) selection: Selection, pub(crate) baseline: Baseline, scope_resources: ResourceState }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedReply { pub(crate) revision: String, pub(crate) plan_token: String, pub(crate) view: PreparedView, scope_resources: ResourceState }
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum OutcomeKind { Outcome }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalReply {
    #[serde(rename = "kind")] _kind: OutcomeKind,
    #[serde(deserialize_with = "required_option")]
    pub(crate) plan_token: Option<String>,
    effect: Effect, journal: Journal, resources: ResourceState, reason: CoreReason,
}
impl TerminalReply { pub(crate) fn outcome(&self) -> CoreEditOutcome {
    CoreEditOutcome { effect: self.effect.clone(), journal: self.journal.clone(), resources: self.resources.clone(), reason: self.reason.clone() }
} }
// One lossless projection from the app's completed native project selection.
// This Notes-only DATA codec neither aliases Images' decimal wire nor selects
// a profile/acquires a lease. The original edit owner supplies the identity.
pub(crate) fn registered_identity_from_project(identity: crate::asset_source::ProjectIdentity) -> Value {
    use crate::asset_source::ProjectIdentity;
    match identity {
        ProjectIdentity::Posix(identity) => json!(identity.workflow_identity()),
        ProjectIdentity::Windows { volume, file_id } => {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut encoded = String::with_capacity(32);
            for byte in file_id {
                encoded.push(HEX[(byte >> 4) as usize] as char);
                encoded.push(HEX[(byte & 15) as usize] as char);
            }
            json!({"platform":"windows-ntfs-v1","volumeSerial":format!("{volume:016x}"),"fileId":encoded})
        },
    }
}
// Closed Notes-only root DATA. This never selects a native platform or grants
// authority, and deliberately leaves every other edit protocol unchanged.
fn notes_registered_identity(value: &Value) -> bool {
    if value.get("platform").and_then(Value::as_str) == Some("windows-ntfs-v1") {
        keys(value, &["platform", "volumeSerial", "fileId"])
            && value["volumeSerial"].as_str().is_some_and(|s| s.len() == 16
                && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            && value["fileId"].as_str().is_some_and(|s| s.len() == 32
                && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    } else {
        RegisteredIdentity::deserialize(value).is_ok_and(|identity| identity.valid())
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivateOpen { root: String, registered_identity: Value, context: Context }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivatePrepare { revision: String, context: Context, expected_baseline: Baseline, text: String }
pub(crate) fn request(session: &str, seq: u32, op: &str, params: Value) -> Result<Vec<u8>, BridgeError> {
    if !token(session) || seq > 2 { return Err(BridgeError::invalid()); }
    value_bounds(&params, 16, REQUEST_LIMIT)?;
    let legal = match (seq, op) {
        (0, "open") => PrivateOpen::deserialize(&params).is_ok_and(|p| p.root.len() > 1 && p.root.len() <= 4096
            && !p.root.contains('\0') && notes_registered_identity(&p.registered_identity) && p.context.valid()),
        (1, "prepare") => keys(&params, &["revision", "context", "expectedBaseline", "text"])
            && PrivatePrepare::deserialize(&params).is_ok_and(|p| token(&p.revision) && p.context.valid()
                && p.expected_baseline.valid_for(&p.context) && p.text.len() <= p.context.kind().byte_limit()),
        (2, "apply") => keys(&params, &["planToken"]) && params["planToken"].as_str().is_some_and(token),
        (1 | 2, "discard") => keys(&params, &[]),
        _ => false,
    };
    if !legal { return Err(BridgeError::invalid()); }
    let value = json!({"protocol":PROTOCOL,"session":session,"seq":seq,"op":op,"params":params});
    check_value(&value)?;
    let mut bytes = bounded(&value, REQUEST_LIMIT - 1)?; bytes.push(b'\n'); Ok(bytes)
}
pub(crate) fn decode(bytes: &[u8], session: &str) -> Result<ChildFrame, BridgeError> {
    if !token(session) || bytes.len() > RESPONSE_LIMIT || !bytes.ends_with(b"\n") { return Err(BridgeError::protocol()); }
    let body = &bytes[..bytes.len() - 1];
    if body.first() != Some(&b'{') || body.last() != Some(&b'}') || body.iter().any(|b| matches!(*b, b'\r' | b'\n')) { return Err(BridgeError::protocol()); }
    let value = strict_json(body)?;
    if !keys(&value, &["protocol", "session", "seq", "kind", "result"]) || value["protocol"] != PROTOCOL || value["session"] != session { return Err(BridgeError::protocol()); }
    let seq = value["seq"].as_u64().filter(|seq| *seq <= 2).ok_or_else(BridgeError::protocol)? as u32;
    let raw = &value["result"];
    value_bounds(raw, 16, RESPONSE_LIMIT).map_err(|_| BridgeError::protocol())?;
    match value["kind"].as_str() {
        Some("opened") if seq == 0 && bytes.len() <= OPENED_LIMIT => {
            if !keys(raw, &["revision", "selection", "baseline", "scopeResources"]) { return Err(BridgeError::protocol()); }
            let result = Opened::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || !result.selection.valid(&result.baseline) || result.scope_resources != ResourceState::Settled { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::RequiredNotesOpened(result))
        },
        Some("prepared") if seq == 1 => {
            if !keys(raw, &["revision", "planToken", "view", "scopeResources"]) { return Err(BridgeError::protocol()); }
            let result = PreparedReply::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || !token(&result.plan_token) || result.revision == result.plan_token
                || result.scope_resources != ResourceState::Settled || !result.view.valid() { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::RequiredNotesPrepared(result))
        },
        Some("terminal") if bytes.len() <= edit::TERMINAL_LIMIT => {
            if !keys(raw, &["kind", "planToken", "effect", "journal", "resources", "reason"]) { return Err(BridgeError::protocol()); }
            let result = TerminalReply::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if !result.outcome().valid() || result.plan_token.as_deref().is_some_and(|s| !token(s)) { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::RequiredNotesTerminal(seq, result))
        },
        _ => Err(BridgeError::protocol()),
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AvailabilityReason {
    None, UnsupportedPlatform, RuntimeUnavailable,
    #[serde(rename = "unqualified")]
    NotQualified,
    DocumentUnavailable,
}
#[derive(Serialize)]
pub(crate) struct Availability { pub(crate) available: bool, pub(crate) reason: AvailabilityReason }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Capabilities {
    pub(crate) schema_version: u32, pub(crate) window_generation: String,
    pub(crate) read: Availability, pub(crate) edit: Availability, pub(crate) import: Availability,
}
#[derive(Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ImportPhase { Pending, Settled, Unknown }
#[derive(Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ImportOutcome { Selected, Cancelled, Refused }
#[derive(Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ImportReason { None, Cancelled, InvalidFile, ChangedFile, InvalidText, Unavailable, IoError, ContextChanged, CleanupUnknown }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportStatus {
    pub(crate) schema_version: u32, pub(crate) request_id: u32, pub(crate) window_generation: String, pub(crate) project_id: String,
    pub(crate) context: Context, pub(crate) phase: ImportPhase, pub(crate) outcome: Option<ImportOutcome>, pub(crate) reason: ImportReason,
}
#[derive(Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub(crate) enum Imported {
    Cancelled { #[serde(rename = "schemaVersion")] schema_version: u32, #[serde(rename = "type")] type_name: &'static str },
    Selected { #[serde(rename = "schemaVersion")] schema_version: u32, #[serde(rename = "type")] type_name: &'static str,
        kind: Kind, text: String, validation: Validation },
}
impl Imported {
    // A refusal returns the ORIGINAL private allocation to its caller for
    // original-owner retirement. It is not an error/status/log payload.
    pub(crate) fn selected(kind: Kind, text: String, validation: Validation) -> Result<Self, (String, Validation)> {
        if text.len() > kind.byte_limit() || !validation.valid || !validation.valid_for(kind) || !validation.matches_text(Some(&text)) {
            return Err((text, validation));
        }
        Ok(Self::Selected { schema_version: 1, type_name: "required-notes-import", kind, text, validation })
    }
    pub(crate) fn cancelled() -> Self { Self::Cancelled { schema_version: 1, type_name: "required-notes-import" } }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportEnvelope { pub(crate) request_id: u32, pub(crate) result: Option<Imported>, pub(crate) status: ImportStatus }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportStatusEnvelope { pub(crate) request_id: u32, pub(crate) status: Option<ImportStatus> }

pub(crate) fn private_error() -> BridgeError {
    BridgeError::new("required_notes_unavailable", "The original notes operation could not complete. Check its status before trying again.")
}
const PASSIVE_ERRORS: [(&str, &str); 14] = [
    ("required_notes_invalid_params", "Required-note input has an unsupported shape or size."),
    ("required_notes_unavailable", "Saved required-note observation is unavailable on this platform."),
    ("required_notes_config_missing", "Save the project configuration before loading release or review notes."),
    ("required_notes_config_invalid", "Correct the saved project configuration before loading these notes."),
    ("required_notes_not_configured", "Enable the selected platform and choose a locale declared in the saved configuration."),
    ("required_notes_version_missing", "Save the configured release-version file before loading Android notes."),
    ("required_notes_version_invalid", "Correct the saved release version before loading Android notes."),
    ("required_notes_unsafe", "A selected configuration, version or note path cannot be read safely."),
    ("required_notes_changed", "A selected configuration, version, note or original absence changed during observation."),
    ("required_notes_unreadable", "A selected configuration, version or note could not be read."),
    ("required_notes_limit", "The required-note observation exceeded its disclosed editor or observation limit."),
    ("required_notes_encoding", "A selected configuration, version or note file is not valid UTF-8."),
    ("required_notes_sensitive", "A selected file may contain secret material; no contents were returned."),
    ("required_notes_cleanup_unknown", "Original required-note observation cleanup could not be confirmed."),
];
pub(crate) fn public_error(error: BridgeError) -> BridgeError {
    if !error.retryable && PASSIVE_ERRORS.iter().any(|(code, message)| error.code == *code && error.message == *message) { error }
    else { private_error() }
}
pub(crate) fn decode_passive_envelope(bytes: &[u8], id: &str) -> Result<Value, BridgeError> {
    if bytes.len() > RESPONSE_LIMIT { return Err(BridgeError::protocol()); }
    crate::protocol::decode_response(bytes, id).map_err(public_error)
}

#[cfg(test)]
pub(crate) mod tests {
    // Transport-only in-memory fixtures, not provider-policy or native-runtime
    // receipts. No project read, process, tool, dialog or runtime is created.
    use super::*;
    pub(crate) const WINDOW: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REVISION: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const PLAN: &str = "cccccccccccccccccccccccccccccccc";
    pub(crate) const SESSION: &str = "dddddddddddddddddddddddddddddddd";
    pub(crate) fn validation_value(context: &Context, text: &str) -> Value {
        let kind = context.kind();
        json!({"schemaVersion":1,"kind":kind,"valid":true,"state":"format-valid",
            "rawByteCount":text.len(),"characterCount":if kind.android() { text.chars().count() }
                else { text.replace("\r\n","\n").replace('\r',"\n").trim_end_matches('\n').chars().count() },
            "characterLimit":kind.character_limit(),
            "outboundCharacterCount":if kind.android() { None } else { Some(text.trim_matches(['\0','\t','\n','\u{b}','\u{c}','\r',' ']).chars().count()) },
            "editorByteLimit":kind.byte_limit(),"issues":[]})
    }
    fn assertion(text: &str) -> Value { json!({"state":"present","byteLength":text.len(),"sha256":digest(text.as_bytes())}) }
    fn observation_value(context: &Context, text: &str) -> Value {
        let android = context.kind().android(); let build = android.then_some(17);
        json!({"schemaVersion":1,"selection":{"context":context,"metadataRoot":"metadata",
            "destination":context.destination("metadata",build).unwrap(),"savedBuild":build,
            "effective":if android { Some(json!({"source":if context.kind()==Kind::AndroidBuild {"exact"}else{"default"},"valid":true})) }else{None}},
            "baseline":{"config":{"byteLength":2,"sha256":digest(b"{}")},
                "version":if android {Some(json!({"byteLength":2,"sha256":digest(b"17")}))}else{None},
                "note":assertion(text),"counterpart":if android {Some(json!({"state":"absent"}))}else{None}},
            "original":{"state":"present","text":text},"validation":validation_value(context,text)})
    }
    fn prepared_value(context: &Value, after: &str) -> Value {
        let selected: Context = serde_json::from_value(context["selection"]["context"].clone()).unwrap();
        json!({"schemaVersion":1,"selection":context["selection"],"baseline":context["baseline"],
            "before":context["original"],"after":after,"action":"replace","createDirectories":[],"validation":validation_value(&selected,after)})
    }
    fn frame(seq: u32, kind: &str, result: Value) -> Vec<u8> {
        let mut bytes=serde_json::to_vec(&json!({"protocol":PROTOCOL,"session":SESSION,"seq":seq,"kind":kind,"result":result})).unwrap();
        bytes.push(b'\n'); bytes
    }
    pub(crate) fn projection() -> edit::EditProjection {
        let context=Context::IosAppReview {};
        let original=observation_value(&context,"PRIVATE_BEFORE_SENTINEL\r\n");
        let observed=observation_result(original.clone(),&context).ok().unwrap();
        let view:PreparedView=serde_json::from_value(prepared_value(&original,"PRIVATE_AFTER_SENTINEL\r\n")).unwrap();
        let mut detail=Details::new(Binding { request_id:7,window_generation:WINDOW.into(),context:context.clone(),draft_revision:3 });
        detail.revision=Some(REVISION.into()); detail.plan_token=Some(PLAN.into()); detail.action=Some(Action::Replace);
        detail.checkout=Some(Checkout {revision:REVISION.into(),selection:observed.selection,baseline:observed.baseline.clone()});
        detail.prepared=Some(PrivatePrepared {revision:REVISION.into(),plan_token:PLAN.into(),view});
        detail.submission=Some(Submission {context,expected_baseline:observed.baseline,text:"PRIVATE_AFTER_SENTINEL\r\n".into()});
        edit::EditProjection {domain:edit::EditDomain::RequiredNotes,workflow:None,metadata_text:None,required_notes:Some(detail),
            release_version:None,metadata_images:None,project_id:"project-1".into(),session_id:SESSION.into(),owner_generation:WINDOW.into(),
            phase:Phase::Reviewing,review_remaining_ms:1000,checkout:None,prepared:None,apply_submitted:false,core_outcome:None,
            native_reason:NativeEditReason::None,native_finality:NativeFinality::Pending,late_settled:false}
    }

    #[test]
    fn observation_correlates_raw_utf8_and_requires_nullable_fields_and_exact_destination() {
        for context in [Context::AndroidBuild {locale:"en-US".into()},Context::AndroidDefault {locale:"fr-FR".into()},
            Context::IosBetaReview {},Context::IosAppReview {},Context::TestflightWhatToTest {}] {
            let source=observation_value(&context,"Public \u{1f642}\r\nreview\r\n");
            assert!(observation_result(source.clone(),&context).is_ok());
            let mut changed=source.clone(); changed["original"]["text"]=json!("Public \u{1f642}\nreview\n");
            assert!(observation_result(changed,&context).is_err()); // no normalized baseline
            for (object,key) in [("baseline","version"),("baseline","counterpart"),("selection","savedBuild"),("selection","effective")] {
                let mut changed=source.clone(); changed[object].as_object_mut().unwrap().remove(key);
                assert!(observation_result(changed,&context).is_err());
            }
            let mut changed=source.clone(); changed["selection"]["destination"]=json!("metadata/review/arbitrary.txt");
            assert!(observation_result(changed,&context).is_err());
            let mut changed=source.clone(); changed["baseline"]["config"]["byteLength"]=json!(2.0);
            assert!(observation_result(changed,&context).is_err());
        }
    }
    #[test]
    fn invalid_exact_android_file_never_falls_back_to_default_in_transport() {
        let context=Context::AndroidBuild {locale:"en-US".into()}; let mut source=observation_value(&context," ");
        source["baseline"]["counterpart"]=assertion("Usable default"); source["selection"]["effective"]["valid"]=json!(false);
        source["validation"]["valid"]=json!(false); source["validation"]["state"]=json!("invalid");
        source["validation"]["issues"]=json!([{"code":ISSUES[3].0,"message":ISSUES[3].1}]);
        assert!(observation_result(source.clone(),&context).is_ok());
        source["selection"]["effective"]["source"]=json!("default");
        assert!(observation_result(source,&context).is_err());
    }
    #[test]
    fn validation_keeps_oversize_feedback_but_rejects_forged_counts_and_missing_nulls() {
        let context=Context::TestflightWhatToTest {}; let text="x".repeat(65537);
        let mut value=validation_value(&context,&text); value["valid"]=json!(false); value["state"]=json!("invalid");
        value["characterCount"]=Value::Null; value["outboundCharacterCount"]=Value::Null;
        value["issues"]=json!([{"code":ISSUES[2].0,"message":ISSUES[2].1}]);
        assert!(validation_result(value.clone(),&context,&text).is_ok());
        value["rawByteCount"]=json!(65536); assert!(validation_result(value,&context,&text).is_err());
        let android=Context::AndroidBuild {locale:"en-US".into()}; let mut value=validation_value(&android,"public");
        value.as_object_mut().unwrap().remove("outboundCharacterCount");
        assert!(validation_result(value,&android,"public").is_err());
    }
    #[test]
    fn prepared_wire_is_closed_and_submission_matches_exact_checkout_and_raw_after() {
        let context=Context::IosAppReview {}; let original=observation_value(&context,"before\r\n");
        let view=prepared_value(&original,"after\r\n");
        let bytes=frame(1, "prepared", json!({"revision":REVISION,"planToken":PLAN,"scopeResources":"settled","view":view}));
        assert!(matches!(decode(&bytes,SESSION),Ok(ChildFrame::RequiredNotesPrepared(_))));
        assert!(decode(&bytes,WINDOW).is_err());
        let duplicate=String::from_utf8(bytes.clone()).unwrap().replacen("\"seq\":1","\"seq\":1,\"seq\":1",1);
        assert!(decode(duplicate.as_bytes(),SESSION).is_err());
        let scalar=String::from_utf8(bytes).unwrap().replacen("\"seq\":1","\"seq\":1.0",1);
        assert!(decode(scalar.as_bytes(),SESSION).is_err());
        let observed=observation_result(original,&context).ok().unwrap();
        let checkout=Checkout {revision:REVISION.into(),selection:observed.selection,baseline:observed.baseline};
        let mut parsed:PreparedView=serde_json::from_value(view).unwrap(); assert!(parsed.valid());
        let mut submission=Submission {context:context.clone(),expected_baseline:checkout.baseline.clone(),text:"after\r\n".into()};
        assert!(parsed.matches_checkout(&checkout,&context) && submission.matches(&checkout,&parsed));
        submission.text="after\n".into(); assert!(!submission.matches(&checkout,&parsed));
        parsed.action=Action::Preserve; assert!(!parsed.valid());
        assert!(request(SESSION,1,"prepare",json!({"revision":REVISION,"context":context,"expectedBaseline":checkout.baseline,"text":"public","path":"elsewhere"})).is_err());
    }
    #[test]
    fn status_projection_and_private_retirement_never_serialize_content_or_baseline() {
        let mut original=projection();
        let encoded=serde_json::to_string(&original.required_notes_projection(4).ok().unwrap()).unwrap();
        for private in ["PRIVATE_BEFORE_SENTINEL","PRIVATE_AFTER_SENTINEL","baseline","sha256","metadataRoot","destination","byteLength","createDirectories"] {
            assert!(!encoded.contains(private));
        }
        assert!(original.workflow_projection().is_err() && original.metadata_text_projection().is_err()
            && original.release_version_projection().is_err() && original.metadata_images_projection().is_err());
        original.required_notes.as_mut().unwrap().drop_private();
        let detail=original.required_notes.as_ref().unwrap();
        assert!(detail.checkout.is_none() && detail.prepared.is_none() && detail.submission.is_none());
        assert!(detail.revision.as_deref()==Some(REVISION) && detail.plan_token.as_deref()==Some(PLAN) && detail.action==Some(Action::Replace));
        assert_eq!(serde_json::to_string(&original.required_notes_projection(4).ok().unwrap()).unwrap(),encoded);
    }
    #[test]
    fn invalid_shared_validation_cannot_produce_selected_private_import() {
        for context in [Context::AndroidBuild {locale:"en-US".into()},Context::AndroidDefault {locale:"en-US".into()},
            Context::IosBetaReview {},Context::IosAppReview {},Context::TestflightWhatToTest {}] {
            let text="{\"client_secret\":\"abc\r\ndef\"}".to_owned(); let mut value=validation_value(&context,&text);
            value["valid"]=json!(false); value["state"]=json!("invalid");
            value["issues"]=json!([{"code":ISSUES[11].0,"message":ISSUES[11].1}]);
            let validation=validation_result(value,&context,&text).ok().unwrap();
            let refused=Imported::selected(context.kind(),text.clone(),validation).err().unwrap();
            assert_eq!(refused.0,text); // same raw allocation is returned, not selected
        }
    }
    #[test]
    fn required_note_root_union_is_lossless_closed_and_domain_private() {
        let identity = json!({"platform":"windows-ntfs-v1","volumeSerial":"ffffffffffffffff",
                              "fileId":"1234567890abcdef1234567890abcdef"});
        let params = json!({"root":r"C:\projects\mobile","registeredIdentity":identity,
                            "context":{"kind":"ios-beta-review"}});
        let wire = request(SESSION, 0, "open", params.clone()).unwrap();
        let parsed: Value = serde_json::from_slice(&wire).unwrap();
        assert_eq!(parsed["params"]["registeredIdentity"], identity);
        assert!(RegisteredIdentity::deserialize(&identity).is_err());
        for (name, value) in [
            ("volumeSerial", json!(u64::MAX)),
            ("volumeSerial", json!("FFFFFFFFFFFFFFFF")),
            ("volumeSerial", json!("fffffffffffffff")),
            ("fileId", json!("g".repeat(32))),
            ("uid", json!(1000)),
            ("platform", json!("posix")),
        ] {
            let mut invalid = params.clone();
            invalid["registeredIdentity"][name] = value;
            assert!(request(SESSION, 0, "open", invalid).is_err());
        }
        let mut missing = params;
        missing["registeredIdentity"].as_object_mut().unwrap().remove("fileId");
        assert!(request(SESSION, 0, "open", missing).is_err());
        let posix = json!({"device":"9007199254740993","inode":"18446744073709551615",
                           "mode":0o040700,"uid":1000,"gid":1000});
        assert!(notes_registered_identity(&posix));
        assert!(RegisteredIdentity::deserialize(&posix).is_ok_and(|value| value.valid()));
    }
    #[test]
    fn notes_project_identity_codec_preserves_native_width_and_file_id_order() {
        use crate::asset_source::{DirectoryIdentity, ProjectIdentity};
        let windows = registered_identity_from_project(ProjectIdentity::Windows {
            volume: u64::MAX, file_id: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        });
        assert_eq!(windows, json!({"platform":"windows-ntfs-v1","volumeSerial":"ffffffffffffffff",
                                  "fileId":"000102030405060708090a0b0c0d0e0f"}));
        assert!(notes_registered_identity(&windows));
        let posix = DirectoryIdentity::synthetic_evidence_identity();
        assert_eq!(registered_identity_from_project(ProjectIdentity::Posix(posix)),
                   json!(posix.workflow_identity()));
    }
}
