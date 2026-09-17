//! Closed, borrowed-value admission for the session-only native credential lane.
//! Tauri has already materialized Json bodies. These are admitted-payload limits,
//! not a pre-IPC allocation/RSS guarantee. No parser observation or path enters.
use std::{io, sync::Arc};
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use crate::protocol;

pub(crate) const POLICY: &str = "credential-policy-v1";
pub(crate) const DRAFT_LIMIT: usize = 512 * 1024;
const SMALL_LIMIT: usize = 1024;
const PREPARE_LIMIT: usize = 128 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Kind {
    AndroidKeystore, AndroidFirebase, AppleP12, AppleProfile, AscP8,
    IosFirebase, GoogleWif, ProjectReadToken,
}
impl Kind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::AndroidKeystore => "android-keystore", Self::AndroidFirebase => "android-firebase",
            Self::AppleP12 => "apple-p12", Self::AppleProfile => "apple-profile", Self::AscP8 => "asc-p8",
            Self::IosFirebase => "ios-firebase", Self::GoogleWif => "google-wif", Self::ProjectReadToken => "project-read-token",
        }
    }
    pub(crate) fn enabled(self) -> bool {
        matches!(self, Self::AndroidKeystore | Self::AndroidFirebase | Self::GoogleWif | Self::ProjectReadToken)
    }
    pub(crate) fn file(self) -> Option<crate::credential_format::FileKind> {
        use crate::credential_format::FileKind;
        match self { Self::AndroidKeystore => Some(FileKind::AndroidKeystore), Self::AndroidFirebase => Some(FileKind::AndroidFirebase), _ => None }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform { Android, Ios, Project }
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Stage { Candidate, ExternalTesting, Production }
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Purpose { Full, Signing, Store }

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None, Closed, Unqualified, UnsupportedPlatform, UnsupportedFilesystem,
    UnsupportedFormat, InvalidRequest, Busy, SourceRefused, SourceChanged,
    MaterialLimit, ParserLimit, ProjectOverlap, ExclusionUnconfirmed, Capacity,
    ContextStale, UserCancelled, ReviewExpired, Deadline, DocumentLost, Shutdown,
    CleanupUnknown,
}
#[derive(Clone, Copy, Serialize)]
pub(crate) struct AssetError {
    pub(crate) code: &'static str, pub(crate) message: &'static str, pub(crate) retryable: bool,
    #[serde(skip)] pub(crate) reason: Reason,
}
impl AssetError {
    pub(crate) fn new(reason: Reason) -> Self {
        let code = match reason {
            Reason::None | Reason::InvalidRequest => "asset_invalid_request",
            Reason::Closed => "asset_closed", Reason::Unqualified => "asset_unqualified",
            Reason::UnsupportedPlatform => "asset_unsupported_platform", Reason::UnsupportedFilesystem => "asset_unsupported_filesystem",
            Reason::UnsupportedFormat => "asset_unsupported_format", Reason::Busy => "asset_busy",
            Reason::SourceRefused => "asset_source_refused", Reason::SourceChanged => "asset_source_changed",
            Reason::MaterialLimit => "asset_material_limit", Reason::ParserLimit => "asset_parser_limit",
            Reason::ProjectOverlap => "asset_project_overlap", Reason::ExclusionUnconfirmed => "asset_exclusion_unconfirmed",
            Reason::Capacity => "asset_capacity", Reason::ContextStale => "assessment_context_stale",
            Reason::UserCancelled => "asset_user_cancelled", Reason::ReviewExpired => "asset_review_expired",
            Reason::Deadline => "asset_deadline", Reason::DocumentLost => "asset_document_lost",
            Reason::Shutdown => "asset_shutdown", Reason::CleanupUnknown => "asset_cleanup_unknown",
        };
        Self { code, message: if reason == Reason::ContextStale { "Assessment context changed; prepare again." }
            else { "This session action was not completed. See its status reason." }, retryable: false, reason }
    }
    pub(crate) fn invalid() -> Self { Self::new(Reason::InvalidRequest) }
}
#[derive(Serialize)]
#[serde(untagged)]
enum Failure { Native(AssetError), Assessment(crate::credential_assessment::AssessmentError) }
// A non-owning invoke waiter can copy the safe error receipt without removing
// an original owner/result. No serde `rc` feature or R1 DTO change is needed.
#[derive(Clone)]
pub(crate) struct CommandError(Arc<Failure>);
impl Serialize for CommandError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> { self.0.serialize(serializer) }
}
impl From<AssetError> for CommandError { fn from(error: AssetError) -> Self { Self(Arc::new(Failure::Native(error))) } }
impl From<crate::credential_assessment::AssessmentError> for CommandError {
    fn from(error: crate::credential_assessment::AssessmentError) -> Self { Self(Arc::new(Failure::Assessment(error))) }
}

pub(crate) struct RecordRef<'a> { pub(crate) record_id: &'a str, pub(crate) expected_revision: u32 }
pub(crate) struct Context<'a> {
    pub(crate) project_id: &'a str, pub(crate) draft: &'a Value,
    pub(crate) platform: Platform, pub(crate) stage: Stage, pub(crate) purpose: Purpose,
}
pub(crate) struct Choose<'a> { pub(crate) context_revision: u32, pub(crate) kind: Kind, pub(crate) replacement: Option<RecordRef<'a>> }
pub(crate) enum Source<'a> {
    Selection(&'a str), Record(RecordRef<'a>), Scalar { kind: Kind, replacement: Option<RecordRef<'a>> },
}
pub(crate) struct Prepare<'a> { pub(crate) context_revision: u32, pub(crate) source: Source<'a>, pub(crate) fields: Option<&'a Value> }

// No Debug/Deserialize or renderer readback. Immutable record backing is shared
// by Arc in the owner, rather than cloning these write-only strings for leases.
pub(crate) struct Fields { kind: Kind, values: Vec<Option<String>> }
impl Fields {
    pub(crate) fn empty_firebase() -> Self { Self { kind: Kind::AndroidFirebase, values: Vec::new() } }
    pub(crate) fn byte_count(&self) -> usize { self.values.iter().flatten().map(String::capacity).sum() }
    pub(crate) fn into_value(&self) -> Value {
        let mut object = Map::new();
        for (name, value) in field_names(self.kind).iter().zip(&self.values) {
            object.insert((*name).into(), value.as_ref().map_or(Value::Null, |value| Value::String(value.clone())));
        }
        Value::Object(object)
    }
}

struct Counter { used: usize, limit: usize }
impl io::Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.used) { return Err(io::Error::new(io::ErrorKind::InvalidData, "session input bound")); }
        self.used += bytes.len(); Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
fn within(value: &Value, limit: usize) -> bool { serde_json::to_writer(Counter { used: 0, limit }, value).is_ok() }
fn bounded(body: &Value, limit: usize) -> Result<(), AssetError> {
    protocol::check_value(body).map_err(|_| AssetError::invalid())?;
    if !within(body, limit) { return Err(AssetError::invalid()); }
    Ok(())
}
fn exact<'a>(body: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>, AssetError> {
    let object = body.as_object().ok_or_else(AssetError::invalid)?;
    if object.len() != keys.len() || !keys.iter().all(|key| object.contains_key(*key)) { return Err(AssetError::invalid()); }
    Ok(object)
}
fn text(value: &Value) -> Result<&str, AssetError> { value.as_str().ok_or_else(AssetError::invalid) }
fn number(value: &Value) -> Result<u32, AssetError> {
    let value = value.as_u64().ok_or_else(AssetError::invalid)?;
    u32::try_from(value).map_err(|_| AssetError::invalid())
}
fn token(value: &Value) -> Result<&str, AssetError> {
    let value = text(value)?;
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) { return Err(AssetError::invalid()); }
    Ok(value)
}
fn kind(value: &Value) -> Result<Kind, AssetError> {
    match text(value)? {
        "android-keystore" => Ok(Kind::AndroidKeystore), "android-firebase" => Ok(Kind::AndroidFirebase),
        "apple-p12" => Ok(Kind::AppleP12), "apple-profile" => Ok(Kind::AppleProfile), "asc-p8" => Ok(Kind::AscP8),
        "ios-firebase" => Ok(Kind::IosFirebase), "google-wif" => Ok(Kind::GoogleWif), "project-read-token" => Ok(Kind::ProjectReadToken),
        _ => Err(AssetError::invalid()),
    }
}
fn record(value: &Value) -> Result<RecordRef<'_>, AssetError> {
    let object = exact(value, &["recordId", "expectedRevision"])?;
    Ok(RecordRef { record_id: token(&object["recordId"])?, expected_revision: number(&object["expectedRevision"])? })
}
fn replacement(value: &Value) -> Result<Option<RecordRef<'_>>, AssetError> {
    if value.is_null() { Ok(None) } else { record(value).map(Some) }
}
fn field_names(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::AndroidKeystore => &["storePassword", "keyAlias", "keyPassword"],
        Kind::AndroidFirebase => &[], Kind::GoogleWif => &["provider", "serviceAccount"], Kind::ProjectReadToken => &["token"],
        _ => &[],
    }
}
pub(crate) fn validate_fields(kind: Kind, value: &Value) -> Result<(), AssetError> {
    if !kind.enabled() { return Err(AssetError::new(Reason::UnsupportedFormat)); }
    let object = exact(value, field_names(kind))?;
    let mut total = 0usize;
    for name in field_names(kind) {
        let value = &object[*name];
        if value.is_null() { continue; }
        let value = text(value)?;
        if value.len() > 4096 || value.len() > 65_536usize.saturating_sub(total) { return Err(AssetError::invalid()); }
        total += value.len();
    }
    Ok(())
}
pub(crate) fn own_fields(kind: Kind, value: &Value) -> Result<Fields, AssetError> {
    validate_fields(kind, value)?;
    let object = value.as_object().ok_or_else(AssetError::invalid)?;
    let mut values = Vec::new();
    values.try_reserve_exact(field_names(kind).len()).map_err(|_| AssetError::new(Reason::Capacity))?;
    for name in field_names(kind) {
        let source = &object[*name];
        if source.is_null() { values.push(None); }
        else { values.push(Some(copy_text(text(source)?)?)); }
    }
    Ok(Fields { kind, values })
}
pub(crate) fn copy_text(text: &str) -> Result<String, AssetError> {
    let mut copy = String::new(); copy.try_reserve_exact(text.len()).map_err(|_| AssetError::new(Reason::Capacity))?;
    copy.push_str(text); Ok(copy)
}
pub(crate) fn draft_bytes(value: &Value) -> Result<Vec<u8>, AssetError> {
    struct Writer(Vec<u8>);
    impl io::Write for Writer {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if data.len() > DRAFT_LIMIT.saturating_sub(self.0.len()) { return Err(io::Error::new(io::ErrorKind::InvalidData, "session draft bound")); }
            self.0.extend_from_slice(data); Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    let mut bytes = Vec::new(); bytes.try_reserve_exact(DRAFT_LIMIT).map_err(|_| AssetError::new(Reason::Capacity))?;
    let mut writer = Writer(bytes);
    serde_json::to_writer(&mut writer, value).map_err(|_| AssetError::invalid())?;
    Ok(writer.0)
}

pub(crate) fn status(body: &Value) -> Result<(), AssetError> { bounded(body, SMALL_LIMIT)?; exact(body, &[])?; Ok(()) }
pub(crate) fn open(body: &Value) -> Result<(), AssetError> {
    bounded(body, SMALL_LIMIT)?; let object = exact(body, &["mode"])?;
    if text(&object["mode"])? != "session" { return Err(AssetError::invalid()); } Ok(())
}
pub(crate) fn context(body: &Value) -> Result<Context<'_>, AssetError> {
    bounded(body, protocol::REQUEST_LIMIT)?;
    let object = exact(body, &["projectId", "draft", "platform", "stage", "purpose"])?;
    let project_id = text(&object["projectId"])?;
    if !protocol::valid_id(project_id) || !object["draft"].is_object() || !within(&object["draft"], DRAFT_LIMIT) { return Err(AssetError::invalid()); }
    let platform = match text(&object["platform"])? { "android" => Platform::Android, "ios" => Platform::Ios, "project" => Platform::Project, _ => return Err(AssetError::invalid()) };
    let stage = match text(&object["stage"])? { "candidate" => Stage::Candidate, "external-testing" => Stage::ExternalTesting, "production" => Stage::Production, _ => return Err(AssetError::invalid()) };
    let purpose = match text(&object["purpose"])? { "full" => Purpose::Full, "signing" => Purpose::Signing, "store" => Purpose::Store, _ => return Err(AssetError::invalid()) };
    Ok(Context { project_id, draft: &object["draft"], platform, stage, purpose })
}
pub(crate) fn choose(body: &Value) -> Result<Choose<'_>, AssetError> {
    bounded(body, SMALL_LIMIT)?;
    let object = exact(body, &["contextRevision", "kind", "replacement"])?;
    Ok(Choose { context_revision: number(&object["contextRevision"])?, kind: kind(&object["kind"])?, replacement: replacement(&object["replacement"])? })
}
pub(crate) fn prepare(body: &Value) -> Result<Prepare<'_>, AssetError> {
    bounded(body, PREPARE_LIMIT)?;
    let root = body.as_object().ok_or_else(AssetError::invalid)?;
    let source = root.get("source").and_then(Value::as_object).ok_or_else(AssetError::invalid)?;
    let tag = source.get("type").ok_or_else(AssetError::invalid)?;
    let (source, fields) = match text(tag)? {
        "selection" => {
            exact(body, &["contextRevision", "source", "fields"])?;
            let object = exact(&root["source"], &["type", "selectionToken"])?;
            (Source::Selection(token(&object["selectionToken"])?), Some(&root["fields"]))
        }
        "record" => {
            exact(body, &["contextRevision", "source"])?;
            let object = exact(&root["source"], &["type", "recordId", "expectedRevision"])?;
            (Source::Record(RecordRef { record_id: token(&object["recordId"])?, expected_revision: number(&object["expectedRevision"])? }), None)
        }
        "scalar" => {
            exact(body, &["contextRevision", "source", "fields"])?;
            let object = exact(&root["source"], &["type", "kind", "replacement"])?;
            let kind = kind(&object["kind"])?;
            if !matches!(kind, Kind::GoogleWif | Kind::ProjectReadToken) { return Err(AssetError::invalid()); }
            validate_fields(kind, &root["fields"])?;
            (Source::Scalar { kind, replacement: replacement(&object["replacement"])? }, Some(&root["fields"]))
        }
        _ => return Err(AssetError::invalid()),
    };
    Ok(Prepare { context_revision: number(root.get("contextRevision").ok_or_else(AssetError::invalid)?)?, source, fields })
}
pub(crate) fn delete(body: &Value) -> Result<RecordRef<'_>, AssetError> { bounded(body, SMALL_LIMIT)?; record(body) }
pub(crate) fn preview_token(body: &Value) -> Result<&str, AssetError> {
    bounded(body, SMALL_LIMIT)?; let object = exact(body, &["previewToken"])?; token(&object["previewToken"])
}
pub(crate) fn discard(body: &Value) -> Result<u32, AssetError> {
    bounded(body, SMALL_LIMIT)?; let object = exact(body, &["operationId"])?; number(&object["operationId"])
}
pub(crate) fn lock(body: &Value) -> Result<(), AssetError> {
    bounded(body, SMALL_LIMIT)?; let object = exact(body, &["discardSession"])?;
    if object["discardSession"] != Value::Bool(true) { return Err(AssetError::invalid()); } Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn commands_are_closed_and_never_admit_paths_or_observations() {
        assert!(status(&json!({})).is_ok());
        assert!(status(&json!({"path":"fictional"})).is_err());
        assert!(open(&json!({"mode":"persistent"})).is_err());
        assert!(choose(&json!({"contextRevision":1,"kind":"android-keystore","replacement":null,"observation":{}})).is_err());
        assert!(prepare(&json!({"contextRevision":1,"source":{"type":"record","recordId":"a".repeat(32),"expectedRevision":1},"fields":{}})).is_err());
        assert!(lock(&json!({"discardSession":false})).is_err());
    }
    #[test]
    fn token_and_counter_grammar_is_exact() {
        for bad in [json!(1.0), json!(-1), json!(u64::from(u32::MAX)+1), json!(true)] { assert!(number(&bad).is_err()); }
        assert!(number(&json!(0)).is_ok());
        assert!(token(&json!("a".repeat(32))).is_ok());
        for bad in ["A".repeat(32), "a".repeat(31), "g".repeat(32)] { assert!(token(&json!(bad)).is_err()); }
    }
    #[test]
    fn fields_preserve_missing_whitespace_and_nul_for_core_not_native_policy() {
        let value = json!({"provider":" \0 ","serviceAccount":null});
        let fields = own_fields(Kind::GoogleWif, &value);
        assert!(fields.is_ok());
        if let Ok(fields) = fields { assert_eq!(fields.into_value(), value); }
        assert!(validate_fields(Kind::GoogleWif, &json!({"provider":"x".repeat(4097),"serviceAccount":null})).is_err());
        assert!(validate_fields(Kind::GoogleWif, &json!({"provider":null})).is_err());
        assert!(validate_fields(Kind::AndroidFirebase, &json!({})).is_ok());
    }
    #[test]
    fn stale_and_native_refusals_have_only_fixed_public_text() {
        let stale = AssetError::new(Reason::ContextStale);
        assert_eq!(stale.code, "assessment_context_stale");
        assert_eq!(stale.message, "Assessment context changed; prepare again.");
        let refused = AssetError::new(Reason::SourceRefused);
        assert_eq!(refused.code, "asset_source_refused"); assert!(!refused.retryable);
    }
}
