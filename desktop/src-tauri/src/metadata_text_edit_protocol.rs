//! Bounded public-text DATA and the dedicated original-owner wire. Policy,
//! filesystem observation and write authority remain in the core; these DTOs
//! cannot choose a root, retarget a checkout or confer native qualification.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use crate::{edit_protocol::{self as edit, bounded, token, Capability, ChildFrame,
    CoreEditOutcome, CoreReason, Effect, Journal, NativeEditReason, NativeFinality, Phase, ResourceState},
    error::BridgeError, github_workflow_edit_protocol::{value_bounds, RegisteredIdentity},
    protocol::{check_value, strict_json}};

pub const PROTOCOL: &str = "mrk-metadata-text/1";
pub const DOMAIN: &str = "metadata_text";
pub const EVENT: &str = "metadata-text-edit-status";
pub const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
pub const STATUS_LIMIT: usize = 2 * 1024 * 1024;
pub const VIEW_LIMIT: usize = 768 * 1024;
pub const TEXT_LIMIT: usize = 32 * 1024;
const CONFIG_LIMIT: u32 = 512 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Platform { Android, Ios }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FieldId {
    #[serde(rename = "title.txt")] Title,
    #[serde(rename = "short_description.txt")] ShortDescription,
    #[serde(rename = "full_description.txt")] FullDescription,
    #[serde(rename = "description.txt")] Description,
    #[serde(rename = "keywords.txt")] Keywords,
    #[serde(rename = "privacy_url.txt")] PrivacyUrl,
    #[serde(rename = "support_url.txt")] SupportUrl,
    #[serde(rename = "release_notes.txt")] ReleaseNotes,
}
const ANDROID: [FieldId; 3] = [FieldId::Title, FieldId::ShortDescription, FieldId::FullDescription];
const IOS: [FieldId; 5] = [FieldId::Description, FieldId::Keywords, FieldId::PrivacyUrl, FieldId::SupportUrl, FieldId::ReleaseNotes];
impl Platform {
    pub(crate) fn ids(self) -> &'static [FieldId] { match self { Self::Android => &ANDROID, Self::Ios => &IOS } }
    fn name(self) -> &'static str { match self { Self::Android => "android", Self::Ios => "ios" } }
}
impl FieldId {
    fn name(self) -> &'static str {
        match self {
            Self::Title => "title.txt", Self::ShortDescription => "short_description.txt", Self::FullDescription => "full_description.txt",
            Self::Description => "description.txt", Self::Keywords => "keywords.txt", Self::PrivacyUrl => "privacy_url.txt",
            Self::SupportUrl => "support_url.txt", Self::ReleaseNotes => "release_notes.txt",
        }
    }
}
pub(crate) fn locale_bounded(locale: &str) -> bool {
    // Membership and LOCALE_RE remain core policy, not a second Rust policy.
    (2..=12).contains(&locale.len()) && locale.bytes().all(|b| b.is_ascii() && !b.is_ascii_control())
}
#[derive(Clone)]
pub(crate) struct Context { pub(crate) platform: Platform, pub(crate) locale: String }
impl Context { pub(crate) fn valid(&self) -> bool { locale_bounded(&self.locale) } }
fn keys(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|v| v.len() == names.len() && names.iter().all(|name| v.contains_key(*name)))
}
fn hex(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn relative(path: &str) -> bool {
    if path.is_empty() || path.len() > 512 { return false; }
    let mut count = 0;
    for part in path.split('/') {
        count += 1;
        if count > 12 || part.is_empty() || part.len() > 255 || part.starts_with('.') || part.ends_with(['.', ' '])
            || part.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}' || "\\:<>\"|?*".contains(c)) { return false; }
        let lower = part.to_lowercase();
        if ["private", "secrets", "credentials", "review", "testflight", "build", "deriveddata", "pods", "node_modules", "venv", "dist", "target", "__pycache__"].contains(&lower.as_str()) { return false; }
        let stem = lower.split('.').next().unwrap_or("");
        if ["con", "prn", "aux", "nul"].contains(&stem)
            || stem.len() == 4 && (stem.starts_with("com") || stem.starts_with("lpt")) && stem.as_bytes()[3].is_ascii_digit() { return false; }
    }
    true
}
fn field_path(root: &str, platform: Platform, locale: &str, id: FieldId) -> String {
    format!("{}/{}/{}/{}", root, platform.name(), locale, id.name())
}
pub(crate) fn target_context(root: &str, platform: Platform, locale: &str) -> bool {
    relative(root) && locale_bounded(locale) && !locale.contains(['/', '\\'])
        && platform.ids().iter().all(|id| relative(&field_path(root, platform, locale, *id)))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentDigest { pub byte_length: u32, pub sha256: String }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
pub enum BaselineField {
    Absent { id: FieldId },
    Present { id: FieldId, #[serde(rename = "byteLength")] byte_length: u32, sha256: String },
}
impl BaselineField {
    fn id(&self) -> FieldId { match self { Self::Absent { id } | Self::Present { id, .. } => *id } }
    fn valid(&self) -> bool {
        match self { Self::Absent { .. } => true, Self::Present { byte_length, sha256, .. } => *byte_length as usize <= TEXT_LIMIT && hex(sha256) }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Baseline { pub config: ContentDigest, pub fields: Vec<BaselineField> }
impl Baseline {
    pub(crate) fn valid_for(&self, platform: Platform) -> bool {
        (1..=CONFIG_LIMIT).contains(&self.config.byte_length) && hex(&self.config.sha256)
            && self.fields.len() == platform.ids().len()
            && self.fields.iter().zip(platform.ids()).all(|(field, id)| field.id() == *id && field.valid())
    }
    pub(crate) fn platform(&self) -> Option<Platform> {
        [Platform::Android, Platform::Ios].into_iter().find(|platform| self.valid_for(*platform))
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextField { pub id: FieldId, pub text: String }
pub(crate) fn fields_valid(fields: &[TextField], platform: Platform) -> bool {
    fields.len() == platform.ids().len()
        && fields.iter().zip(platform.ids()).all(|(field, id)| field.id == *id && field.text.len() <= TEXT_LIMIT)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TextContent { pub text: String, pub byte_length: u32, pub sha256: String }
impl TextContent {
    fn valid(&self) -> bool { self.text.len() <= TEXT_LIMIT && self.text.len() == self.byte_length as usize && hex(&self.sha256) && digest(self.text.as_bytes()) == self.sha256 }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
pub enum Before {
    Absent {},
    Present { text: String, #[serde(rename = "byteLength")] byte_length: u32, sha256: String },
}
impl Before {
    fn text(&self) -> &str { match self { Self::Absent {} => "", Self::Present { text, .. } => text } }
    fn valid(&self) -> bool {
        match self { Self::Absent {} => true, Self::Present { text, byte_length, sha256 } =>
            text.len() <= TEXT_LIMIT && text.len() == *byte_length as usize && hex(sha256) && digest(text.as_bytes()) == *sha256 }
    }
    fn baseline(&self, id: FieldId) -> BaselineField {
        match self { Self::Absent {} => BaselineField::Absent { id }, Self::Present { byte_length, sha256, .. } =>
            BaselineField::Present { id, byte_length: *byte_length, sha256: sha256.clone() } }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action { Create, Replace, Preserve }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileView { pub id: FieldId, pub path: String, pub action: Action, pub before: Before, pub after: TextContent, pub line_endings_changed: bool }

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assurance {
    pub basis: String, pub project_code_executed: bool, pub tools_probed: bool, pub credentials_read: bool,
    pub git_observed: bool, pub store_contacted: bool, pub writes_performed: bool, pub release_readiness: String,
}
impl Assurance {
    fn valid(&self, basis: &str) -> bool {
        self.basis == basis && !self.project_code_executed && !self.tools_probed && !self.credentials_read
            && !self.git_observed && !self.store_contacted && !self.writes_performed && self.release_readiness == "unknown"
    }
}
// Fixed core-owned issue labels, not input/exception echoes or a Rust policy.
const ISSUES: [(&str, &str, &str); 6] = [
    ("metadata.empty-text", "INVALID", "Public Store text must contain non-whitespace content."),
    ("metadata.nul", "INVALID", "Public Store text must not contain NUL."),
    ("metadata.placeholder", "FAIL", "Public Store text contains an unresolved placeholder."),
    ("metadata.secret-pattern", "FAIL", "Public Store text may contain secret material. Remove it and rotate exposed credentials."),
    ("metadata.url", "INVALID", "Use an absolute credential-free HTTPS URL without a query or fragment."),
    ("metadata.length", "FAIL", "Public Store text exceeds the shared core character limit."),
];
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextIssue { pub code: String, pub status: String, pub message: String }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidatedField { pub id: FieldId, pub valid: bool, pub character_count: u32, pub limit: u32, pub issues: Vec<TextIssue> }
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationState { FormatValid, Invalid }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidationResult {
    pub schema_version: u32, pub platform: Platform, pub valid: bool, pub state: ValidationState,
    pub fields: Vec<ValidatedField>, pub assurance: Assurance,
}
impl ValidationResult {
    fn valid_for(&self, platform: Platform) -> bool {
        self.schema_version == 1 && self.platform == platform && self.fields.len() == platform.ids().len()
            && self.assurance.valid("schema-policy") && self.valid == self.fields.iter().all(|field| field.valid)
            && (self.state == ValidationState::FormatValid) == self.valid
            && self.fields.iter().zip(platform.ids()).all(|(field, id)| {
                if field.id != *id || field.character_count as usize > TEXT_LIMIT || field.limit == 0 || field.limit as usize > TEXT_LIMIT
                    || field.valid && field.character_count > field.limit
                    || field.valid != field.issues.is_empty() || field.issues.len() > ISSUES.len() { return false; }
                let mut previous = None;
                field.issues.iter().all(|issue| {
                    let index = ISSUES.iter().position(|(code, status, message)| issue.code == *code && issue.status == *status && issue.message == *message);
                    let ordered = index.is_some_and(|index| previous.is_none_or(|old| index > old));
                    previous = index; ordered
                })
            })
    }
    fn matches_texts<'a>(&self, fields: impl Iterator<Item = (FieldId, &'a str)>) -> bool {
        // A wire correlation only: scalar counting/newline view does not make
        // any Store policy decision or alter the submitted bytes.
        self.fields.iter().zip(fields).all(|(row, (id, text))| row.id == id && row.character_count == character_count(text))
    }
}
fn character_count(text: &str) -> u32 {
    text.replace("\r\n", "\n").replace('\r', "\n").trim_end_matches('\n').chars().count() as u32
}
fn line_styles(text: &str) -> u8 {
    let mut bytes = text.as_bytes().iter().peekable();
    let mut styles = 0;
    while let Some(byte) = bytes.next() {
        match *byte {
            b'\r' if bytes.peek() == Some(&&b'\n') => { styles |= 1; let _ = bytes.next(); },
            b'\r' => styles |= 2, b'\n' => styles |= 4, _ => {},
        }
    }
    styles
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedView {
    pub schema_version: u32, pub platform: Platform, pub locale: String, pub metadata_root: String,
    pub files: Vec<FileView>, pub create_directories: Vec<String>, pub validation: ValidationResult,
}
impl PreparedView {
    fn valid(&self) -> bool {
        if self.schema_version != 1 || !target_context(&self.metadata_root, self.platform, &self.locale)
            || self.files.len() != self.platform.ids().len() || self.create_directories.len() > 11
            || bounded(self, VIEW_LIMIT).is_err() || !self.validation.valid_for(self.platform) || !self.validation.valid { return false; }
        for (file, id) in self.files.iter().zip(self.platform.ids()) {
            if file.id != *id || file.path != field_path(&self.metadata_root, self.platform, &self.locale, *id)
                || !file.before.valid() || !file.after.valid()
                || file.line_endings_changed != (line_styles(file.before.text()) != line_styles(&file.after.text)) { return false; }
            let action = match &file.before {
                Before::Absent {} => Action::Create,
                Before::Present { text, .. } if *text == file.after.text => Action::Preserve,
                Before::Present { .. } => Action::Replace,
            };
            if file.action != action { return false; }
        }
        if !self.validation.matches_texts(self.files.iter().map(|file| (file.id, file.after.text.as_str()))) { return false; }
        // All fixed fields share one locale directory. Observed-absent target
        // ancestors therefore form one complete suffix of its ancestor chain.
        // Dependency-only parents can never appear in this creation roster.
        let parent = format!("{}/{}/{}", self.metadata_root, self.platform.name(), self.locale);
        let mut ancestors = Vec::new(); let mut current = String::new();
        for part in parent.split('/') {
            if !current.is_empty() { current.push('/'); } current.push_str(part); ancestors.push(current.clone());
        }
        self.create_directories.len() <= ancestors.len()
            && self.create_directories.as_slice() == &ancestors[ancestors.len().saturating_sub(self.create_directories.len())..]
            && (self.create_directories.is_empty() || self.files.iter().all(|file| file.action == Action::Create))
    }
    pub(crate) fn matches_checkout(&self, checkout: &Checkout, platform: Platform, locale: &str) -> bool {
        self.platform == platform && self.locale == locale && self.metadata_root == checkout.metadata_root
            && checkout.baseline.valid_for(platform) && self.files.len() == checkout.baseline.fields.len()
            && self.files.iter().zip(&checkout.baseline.fields).all(|(file, old)| file.before.baseline(file.id) == *old)
    }
}
#[derive(Clone)]
pub(crate) struct Submission { pub(crate) expected_baseline: Baseline, pub(crate) fields: Vec<TextField> }
impl Submission {
    pub(crate) fn valid_for(&self, platform: Platform) -> bool { self.expected_baseline.valid_for(platform) && fields_valid(&self.fields, platform) }
    pub(crate) fn matches(&self, checkout: &Checkout, view: &PreparedView) -> bool {
        self.expected_baseline == checkout.baseline && self.fields.len() == view.files.len()
            && self.fields.iter().zip(&view.files).all(|(field, file)| field.id == file.id && field.text == file.after.text)
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkout { pub revision: String, pub metadata_root: String, pub baseline: Baseline }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Prepared { pub revision: String, pub plan_token: String, pub draft_revision: u32, pub baseline_generation: u32, pub view: PreparedView }
#[derive(Clone)]
pub(crate) struct Details {
    pub(crate) platform: Platform, pub(crate) locale: String, pub(crate) checkout: Option<Checkout>, pub(crate) prepared: Option<Prepared>,
    pub(crate) submission: Option<Submission>,
}
impl Details {
    pub(crate) fn new(context: Context) -> Self { Self { platform: context.platform, locale: context.locale, checkout: None, prepared: None, submission: None } }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Projection {
    pub domain: &'static str, pub project_id: String, pub session_id: String, pub owner_generation: String,
    pub platform: Platform, pub locale: String, pub phase: Phase, pub review_remaining_ms: u32,
    pub checkout: Option<Checkout>, pub prepared: Option<Prepared>, pub apply_submitted: bool, pub core_outcome: Option<CoreEditOutcome>,
    pub native_reason: NativeEditReason, pub native_finality: NativeFinality, pub late_settled: bool,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataTextEditStatus {
    pub schema_version: u32, pub domain: &'static str, pub window_generation: String, pub status_revision: u32,
    pub capability: Capability, pub active: Option<Projection>, pub last_terminal: Option<Projection>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareMetadataTextEdit {
    pub session_id: String, pub revision: String, pub expected_baseline: Baseline, pub fields: Vec<TextField>,
    pub draft_revision: u32, pub baseline_generation: u32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Opened { pub revision: String, pub metadata_root: String, pub baseline: Baseline, pub scope_resources: ResourceState }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedReply { pub revision: String, pub plan_token: String, pub view: PreparedView, pub scope_resources: ResourceState }
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum OutcomeKind { Outcome }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalReply {
    #[serde(rename = "kind")] _kind: OutcomeKind,
    pub plan_token: Option<String>, pub effect: Effect, pub journal: Journal, pub resources: ResourceState, pub reason: CoreReason,
}
impl TerminalReply {
    pub(crate) fn outcome(&self) -> CoreEditOutcome { CoreEditOutcome { effect: self.effect.clone(), journal: self.journal.clone(), resources: self.resources.clone(), reason: self.reason.clone() } }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivateOpen { root: String, registered_identity: RegisteredIdentity, platform: Platform, locale: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivatePrepare { revision: String, expected_baseline: Baseline, fields: Vec<TextField> }
pub(crate) fn request(session: &str, seq: u32, op: &str, params: Value) -> Result<Vec<u8>, BridgeError> {
    if !token(session) || seq > 2 { return Err(BridgeError::invalid()); }
    value_bounds(&params, 16, edit::REQUEST_LIMIT)?;
    let legal = match (seq, op) {
        (0, "open") => PrivateOpen::deserialize(&params).is_ok_and(|p| p.root.len() > 1 && p.root.len() <= 4096
            && !p.root.contains('\0') && p.registered_identity.valid() && (Context { platform: p.platform, locale: p.locale }).valid()),
        (1, "prepare") => PrivatePrepare::deserialize(&params).is_ok_and(|p| token(&p.revision)
            && p.expected_baseline.platform().is_some_and(|platform| fields_valid(&p.fields, platform))),
        (2, "apply") => keys(&params, &["planToken"]) && params["planToken"].as_str().is_some_and(token),
        (1 | 2, "discard") => keys(&params, &[]),
        _ => false,
    };
    if !legal { return Err(BridgeError::invalid()); }
    let value = json!({"protocol":PROTOCOL,"session":session,"seq":seq,"op":op,"params":params});
    check_value(&value)?;
    let mut bytes = bounded(&value, edit::REQUEST_LIMIT - 1)?; bytes.push(b'\n'); Ok(bytes)
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
        Some("opened") if seq == 0 => {
            let result = Opened::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || !relative(&result.metadata_root) || result.baseline.platform().is_none()
                || result.scope_resources != ResourceState::Settled { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::MetadataTextOpened(result))
        },
        Some("prepared") if seq == 1 => {
            let result = PreparedReply::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || !token(&result.plan_token) || result.revision == result.plan_token
                || result.scope_resources != ResourceState::Settled || !result.view.valid() { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::MetadataTextPrepared(result))
        },
        Some("terminal") if bytes.len() <= edit::TERMINAL_LIMIT => {
            if !keys(raw, &["kind", "planToken", "effect", "journal", "resources", "reason"]) { return Err(BridgeError::protocol()); }
            let result = TerminalReply::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if !result.outcome().valid() || result.plan_token.as_deref().is_some_and(|s| !token(s)) { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::MetadataTextTerminal(seq, result))
        },
        _ => Err(BridgeError::protocol()),
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
pub enum ObservedField {
    Absent { id: FieldId, path: String },
    Present { id: FieldId, path: String, text: String, #[serde(rename = "byteLength")] byte_length: u32, sha256: String },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub schema_version: u32, pub platform: Platform, pub locale: String, pub metadata_root: String,
    pub observation_scope: String, pub baseline: Baseline, pub fields: Vec<ObservedField>, pub assurance: Assurance,
}
pub(crate) fn observation_result(value: Value, platform: Platform, locale: &str) -> Result<Observation, BridgeError> {
    value_bounds(&value, 16, RESPONSE_LIMIT).map_err(|_| BridgeError::protocol())?;
    let result = Observation::deserialize(&value).map_err(|_| BridgeError::protocol())?;
    if result.schema_version != 1 || result.platform != platform || result.locale != locale
        || !target_context(&result.metadata_root, platform, locale) || !result.baseline.valid_for(platform)
        || result.observation_scope != "single-request-non-atomic" || !result.assurance.valid("static-text")
        || result.fields.len() != platform.ids().len() { return Err(BridgeError::protocol()); }
    for ((field, id), baseline) in result.fields.iter().zip(platform.ids()).zip(&result.baseline.fields) {
        let expected_path = field_path(&result.metadata_root, platform, locale, *id);
        let valid = match (field, baseline) {
            (ObservedField::Absent { id: seen, path }, BaselineField::Absent { id: base }) => seen == id && seen == base && *path == expected_path,
            (ObservedField::Present { id: seen, path, text, byte_length, sha256 }, BaselineField::Present { id: base, byte_length: base_length, sha256: base_sha }) =>
                seen == id && seen == base && *path == expected_path && byte_length == base_length && sha256 == base_sha
                    && text.len() == *byte_length as usize && digest(text.as_bytes()) == *sha256,
            _ => false,
        };
        if !valid { return Err(BridgeError::protocol()); }
    }
    Ok(result)
}
pub(crate) fn validation_result(value: Value, platform: Platform, fields: &[TextField]) -> Result<ValidationResult, BridgeError> {
    value_bounds(&value, 16, RESPONSE_LIMIT).map_err(|_| BridgeError::protocol())?;
    let result = ValidationResult::deserialize(&value).map_err(|_| BridgeError::protocol())?;
    if !fields_valid(fields, platform) || !result.valid_for(platform)
        || !result.matches_texts(fields.iter().map(|field| (field.id, field.text.as_str()))) { return Err(BridgeError::protocol()); }
    Ok(result)
}
const PASSIVE_ERRORS: [(&str, &str); 13] = [
    ("metadata_text_invalid_params", "Metadata text input has an unsupported shape or size."),
    ("metadata_text_unavailable", "Selected public text observation is unavailable on this platform."),
    ("metadata_text_config_missing", "Save the project configuration before loading locale text."),
    ("metadata_text_config_invalid", "The saved configuration is invalid; correct it before loading locale text."),
    ("metadata_text_not_configured", "Select an enabled platform and a locale declared in the saved configuration."),
    ("metadata_text_unsafe", "A selected public text path cannot be read safely."),
    ("metadata_text_changed", "The selected configuration or public text changed during observation."),
    ("metadata_text_unreadable", "The selected configuration or public text could not be read."),
    ("metadata_text_limit", "The selected public text exceeds the bounded editor observation limit."),
    ("metadata_text_encoding", "A selected public text file is not valid UTF-8."),
    ("metadata_text_sensitive", "A selected public text file may contain secret material; no contents were returned."),
    ("metadata_text_cleanup_unknown", "Original observation resource cleanup could not be confirmed."),
    // Protocol failures generated by the shared strict decoder stay generic.
    ("protocol_error", "The core returned an invalid or incomplete response."),
];
pub(crate) fn decode_passive_envelope(bytes: &[u8], id: &str) -> Result<Value, BridgeError> {
    if bytes.len() > RESPONSE_LIMIT { return Err(BridgeError::protocol()); }
    crate::protocol::decode_response(bytes, id).map_err(|error| {
        if !error.retryable && PASSIVE_ERRORS.iter().any(|(code, message)| error.code == *code && error.message == *message) { error }
        else { BridgeError::protocol() }
    })
}

#[cfg(test)]
mod tests {
    // In-memory DTO/grammar/correlation only. No filesystem, child, runtime,
    // native registration, credentials or policy qualification is exercised.
    use super::*;
    const SESSION: &str = "0123456789abcdef0123456789abcdef";
    const REVISION: &str = "fedcba9876543210fedcba9876543210";
    const PLAN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fn assurance(basis: &str) -> Value {
        json!({"basis":basis,"projectCodeExecuted":false,"toolsProbed":false,"credentialsRead":false,
            "gitObserved":false,"storeContacted":false,"writesPerformed":false,"releaseReadiness":"unknown"})
    }
    fn validation(platform: Platform, text: &str) -> Value {
        json!({"schemaVersion":1,"platform":platform,"valid":true,"state":"format-valid",
            "fields":platform.ids().iter().map(|id| json!({"id":id,"valid":true,"characterCount":character_count(text),
                "limit":TEXT_LIMIT,"issues":[]})).collect::<Vec<_>>(),"assurance":assurance("schema-policy")})
    }
    fn view(platform: Platform, before: Option<&str>, after: &str) -> Value {
        let files = platform.ids().iter().map(|id| json!({"id":id,"path":field_path("release/metadata",platform,"en-US",*id),
            "action": match before { None => "create",Some(old) if old == after => "preserve",_ => "replace" },
            "before":before.map_or_else(|| json!({"state":"absent"}), |old| json!({"state":"present","text":old,"byteLength":old.len(),"sha256":digest(old.as_bytes())})),
            "after":{"text":after,"byteLength":after.len(),"sha256":digest(after.as_bytes())},
            "lineEndingsChanged":line_styles(before.unwrap_or("")) != line_styles(after)})).collect::<Vec<_>>();
        json!({"schemaVersion":1,"platform":platform,"locale":"en-US","metadataRoot":"release/metadata","files":files,
            "createDirectories":[],"validation":validation(platform,after)})
    }
    fn checkout(view: &PreparedView) -> Checkout {
        Checkout { revision:REVISION.into(),metadata_root:view.metadata_root.clone(),baseline:Baseline {
            config:ContentDigest { byte_length:2,sha256:"c".repeat(64) },fields:view.files.iter().map(|file| file.before.baseline(file.id)).collect() } }
    }
    fn frame(seq: u32, kind: &str, result: Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&json!({"protocol":PROTOCOL,"session":SESSION,"seq":seq,"kind":kind,"result":result})).unwrap();
        bytes.push(b'\n'); bytes
    }
    fn prepared(view: Value) -> Vec<u8> { frame(1,"prepared",json!({"revision":REVISION,"planToken":PLAN,"view":view,"scopeResources":"settled"})) }
    #[test]
    fn private_wire_is_closed_sequenced_and_domain_isolated() {
        let open = json!({"root":"/inert/project","registeredIdentity":{"device":"0","inode":"42","mode":0o40755,"uid":1000,"gid":1000},"platform":"android","locale":"en-US"});
        assert!(request(SESSION,0,"open",open.clone()).is_ok());
        assert!(edit::request(SESSION,0,"open",open.clone()).is_err());
        assert!(crate::github_workflow_edit_protocol::request(SESSION,0,"open",open.clone()).is_err());
        for key in ["metadataRoot","configPath","path","fields","token"] {
            let mut bad = open.clone(); bad[key] = Value::Null; assert!(request(SESSION,0,"open",bad).is_err());
        }
        let mut bad = open; bad["registeredIdentity"]["inode"] = json!(42); assert!(request(SESSION,0,"open",bad).is_err());
        let terminal = json!({"kind":"outcome","planToken":null,"effect":"not_started","journal":"not_created","resources":"settled","reason":"ignore_conflict"});
        assert!(matches!(decode(&frame(0,"terminal",terminal.clone()),SESSION),Ok(ChildFrame::MetadataTextTerminal(0,_))));
        assert!(edit::decode(&frame(0,"terminal",terminal.clone()),SESSION).is_err());
        assert!(crate::github_workflow_edit_protocol::decode(&frame(0,"terminal",terminal.clone()),SESSION).is_err());
        let mut bad = terminal.clone(); bad["kind"] = json!("conflict"); assert!(decode(&frame(1,"terminal",bad),SESSION).is_err());
        let mut bad = terminal; bad.as_object_mut().unwrap().remove("planToken"); assert!(decode(&frame(0,"terminal",bad),SESSION).is_err());
        assert!(request(SESSION,0,"discard",json!({})).is_err());
        assert!(request(SESSION,1,"discard",json!({})).is_ok());
        assert!(request(SESSION,2,"discard",json!({})).is_ok());
        assert!(request(SESSION,1,"apply",json!({"planToken":PLAN})).is_err());
        assert!(request(SESSION,2,"apply",json!({"planToken":PLAN})).is_ok());
    }
    #[test]
    fn prepared_requires_canonical_files_exact_bytes_actions_and_raw_line_styles() {
        for platform in [Platform::Android,Platform::Ios] { for before in [None,Some("Public\r\n"),Some("Prior\n")] {
            let original = view(platform,before,"Public\r\n");
            assert!(matches!(decode(&prepared(original.clone()),SESSION),Ok(ChildFrame::MetadataTextPrepared(_))));
            for (key,value) in [("id",json!("changelog.txt")),("path",json!("../other.txt")),("before",json!({"state":"absent","byteLength":0})),
                ("after",json!({"text":"different","byteLength":8,"sha256":"b".repeat(64)})),("lineEndingsChanged",json!(line_styles(before.unwrap_or("")) == line_styles("Public\r\n")))] {
                let mut bad = original.clone(); bad["files"][0][key] = value; assert!(decode(&prepared(bad),SESSION).is_err());
            }
            let mut bad = original.clone(); bad["files"].as_array_mut().unwrap().swap(0,1); assert!(decode(&prepared(bad),SESSION).is_err());
            let mut bad = original; bad["files"][0]["action"] = json!(if before.is_none() { "preserve" } else { "create" });
            assert!(decode(&prepared(bad),SESSION).is_err());
        } }
        let original = view(Platform::Android,None,"Public");
        for dirs in [json!(["release/metadata/android/en-US"]),json!(["release/metadata/android","release/metadata/android/en-US"])] {
            let mut valid = original.clone(); valid["createDirectories"] = dirs; assert!(decode(&prepared(valid),SESSION).is_ok());
        }
        for dirs in [json!(["release"]),json!(["release/mobile-release.json"]),json!([".gitignore"]),json!(["release/metadata/android/en-US","release/metadata/android"])] {
            let mut bad = original.clone(); bad["createDirectories"] = dirs; assert!(decode(&prepared(bad),SESSION).is_err());
        }
    }
    #[test]
    fn prepared_cannot_replace_original_context_baseline_or_submitted_text() {
        let original: PreparedView = serde_json::from_value(view(Platform::Android,Some("Prior"),"Public")).unwrap();
        let checkout = checkout(&original);
        let submission = Submission { expected_baseline:checkout.baseline.clone(),fields:original.files.iter().map(|file| TextField { id:file.id,text:file.after.text.clone() }).collect() };
        assert!(original.matches_checkout(&checkout,Platform::Android,"en-US"));
        assert!(submission.matches(&checkout,&original));
        assert!(!original.matches_checkout(&checkout,Platform::Ios,"en-US"));
        assert!(!original.matches_checkout(&checkout,Platform::Android,"fr-FR"));
        let mut changed = original.clone(); changed.metadata_root = "release/other".into(); assert!(!changed.matches_checkout(&checkout,Platform::Android,"en-US"));
        let mut changed = checkout.clone(); changed.baseline.config.sha256 = "d".repeat(64); assert!(!submission.matches(&changed,&original));
        let other: PreparedView = serde_json::from_value(view(Platform::Android,Some("Prior"),"Other")).unwrap();
        assert!(other.valid() && other.matches_checkout(&checkout,Platform::Android,"en-US"));
        assert!(!submission.matches(&checkout,&other)); // Shape/checkout alone cannot authorize replacement text.
        for root in ["/private", "release/private", "release/.hidden", "release/metadata.", "release/CON", "release/../metadata"] {
            assert!(!target_context(root,Platform::Android,"en-US"));
        }
        assert!(!target_context("release/metadata",Platform::Android,"a/b"));
        assert!(!target_context("a/b/c/d/e/f/g/h/i/j",Platform::Android,"en-US"));
    }
    #[test]
    fn passive_observation_is_complete_non_atomic_and_digest_bound() {
        for before in [None,Some("Public\r\n")] {
            let source: PreparedView = serde_json::from_value(view(Platform::Android,before,"Public\r\n")).unwrap();
            let fields = source.files.iter().map(|file| match &file.before {
                Before::Absent {} => json!({"id":file.id,"path":file.path,"state":"absent"}),
                Before::Present { text,byte_length,sha256 } => json!({"id":file.id,"path":file.path,"state":"present","text":text,"byteLength":byte_length,"sha256":sha256}),
            }).collect::<Vec<_>>();
            let original = json!({"schemaVersion":1,"platform":"android","locale":"en-US","metadataRoot":"release/metadata",
                "observationScope":"single-request-non-atomic","baseline":checkout(&source).baseline,"fields":fields,"assurance":assurance("static-text")});
            assert!(observation_result(original.clone(),Platform::Android,"en-US").is_ok());
            assert!(observation_result(original.clone(),Platform::Android,"fr-FR").is_err());
            let mut bad = original.clone(); bad["observationScope"] = json!("atomic"); assert!(observation_result(bad,Platform::Android,"en-US").is_err());
            let mut bad = original.clone(); bad["fields"][0]["text"] = json!("wrong"); assert!(observation_result(bad,Platform::Android,"en-US").is_err());
            let mut bad = original.clone(); bad["fields"].as_array_mut().unwrap().pop(); assert!(observation_result(bad,Platform::Android,"en-US").is_err());
            let mut bad = original; bad["assurance"]["writesPerformed"] = json!(true); assert!(observation_result(bad,Platform::Android,"en-US").is_err());
        }
    }
    #[test]
    fn validation_correlates_scalar_counts_without_rewriting_text_or_duplicating_policy() {
        let text = "😀\r\nx\r\n\n";
        let fields = Platform::Android.ids().iter().map(|id| TextField { id:*id,text:text.into() }).collect::<Vec<_>>();
        let original = validation(Platform::Android,text);
        assert_eq!(character_count(text),3);
        assert!(validation_result(original.clone(),Platform::Android,&fields).is_ok());
        let mut bad = original.clone(); bad["fields"][0]["characterCount"] = json!(text.encode_utf16().count());
        assert!(validation_result(bad,Platform::Android,&fields).is_err());
        let mut invalid = original; invalid["valid"] = json!(false); invalid["state"] = json!("invalid"); invalid["fields"][0]["valid"] = json!(false);
        invalid["fields"][0]["issues"] = json!([{"code":ISSUES[3].0,"status":ISSUES[3].1,"message":ISSUES[3].2}]);
        assert!(validation_result(invalid.clone(),Platform::Android,&fields).is_ok()); // Core-only policy result, not a Rust scan.
        let mut bad = invalid.clone(); bad["fields"][0]["issues"][0]["message"] = json!(text); assert!(validation_result(bad,Platform::Android,&fields).is_err());
        let mut bad = invalid; let duplicate = bad["fields"][0]["issues"][0].clone(); bad["fields"][0]["issues"].as_array_mut().unwrap().push(duplicate);
        assert!(validation_result(bad,Platform::Android,&fields).is_err());
        assert_eq!(fields[0].text,text);
    }
    #[test]
    fn passive_errors_and_complete_view_budgets_never_echo_or_truncate() {
        let envelope = |code: &str,message: &str| {
            let mut bytes = serde_json::to_vec(&json!({"protocol":1,"id":"query-1","ok":false,"error":{"code":code,"message":message,"retryable":false}})).unwrap();
            bytes.push(b'\n'); bytes
        };
        assert_eq!(decode_passive_envelope(&envelope(PASSIVE_ERRORS[10].0,PASSIVE_ERRORS[10].1),"query-1").unwrap_err().code,"metadata_text_sensitive");
        assert_eq!(decode_passive_envelope(&envelope("metadata_text_sensitive","unapproved input echo"),"query-1").unwrap_err().code,"protocol_error");
        assert_eq!(decode_passive_envelope(&envelope("other_error","unapproved input echo"),"query-1").unwrap_err().code,"protocol_error");
        let text = "\u{1}".repeat(TEXT_LIMIT);
        let large = view(Platform::Android,Some(&text),&text);
        let bytes = prepared(large.clone());
        assert!(bytes.len() < RESPONSE_LIMIT && serde_json::to_vec(&large).unwrap().len() > VIEW_LIMIT);
        assert!(decode(&bytes,SESSION).is_err()); // Whole review refuses, never a partial/truncated success.
    }
    #[test]
    fn two_large_reviews_fit_status_without_duplicate_original_text_in_checkout() {
        let text = "\u{1}".repeat(20_000);
        let view: PreparedView = serde_json::from_value(view(Platform::Android,Some(&text),&text)).unwrap();
        let size = bounded(&view,VIEW_LIMIT).unwrap().len(); assert!(size > VIEW_LIMIT - 128 * 1024);
        let checkout = checkout(&view);
        let encoded = serde_json::to_value(&checkout).unwrap();
        assert!(encoded.get("fields").is_none() && encoded["baseline"]["fields"][0].get("text").is_none());
        let projection = Projection { domain:DOMAIN,project_id:"project-1".into(),session_id:SESSION.into(),owner_generation:REVISION.into(),
            platform:Platform::Android,locale:"en-US".into(),phase:Phase::Reviewing,review_remaining_ms:900_000,
            checkout:Some(checkout),prepared:Some(Prepared { revision:REVISION.into(),plan_token:PLAN.into(),draft_revision:1,baseline_generation:0,view }),
            apply_submitted:false,core_outcome:None,native_reason:NativeEditReason::None,native_finality:NativeFinality::Pending,late_settled:false };
        let status = MetadataTextEditStatus { schema_version:1,domain:DOMAIN,window_generation:REVISION.into(),status_revision:1,
            capability:Capability { available:false,reason:edit::EditAvailability::RuntimeUnqualified },active:Some(projection.clone()),last_terminal:Some(projection) };
        assert!(bounded(&status,STATUS_LIMIT).is_ok());
    }
}
