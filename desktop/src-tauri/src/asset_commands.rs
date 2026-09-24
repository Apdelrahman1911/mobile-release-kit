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
#[cfg_attr(test, derive(Debug))]
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
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl CommandError {
    pub(crate) fn installed_assessment_failure(&self) -> crate::credential_assessment::InstalledAssessmentFailure {
        match self.0.as_ref() {
            Failure::Assessment(error) => error.installed_failure(),
            Failure::Native(_) => crate::credential_assessment::InstalledAssessmentFailure::none(),
        }
    }
}
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

// A separate DATA-only purpose in the existing native owner. These four field
// names grant neither credential capture nor arbitrary pathname authority.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) enum ProjectPathField {
    #[serde(rename = "version.source")] VersionSource,
    #[serde(rename = "ios.project")] IosProject,
    #[serde(rename = "ios.workspace")] IosWorkspace,
    #[serde(rename = "metadata.root")] MetadataRoot,
}
impl ProjectPathField {
    pub(crate) fn directory(self) -> bool { self != Self::VersionSource }
    pub(crate) fn accepts_basename(self, name: &str) -> bool {
        match self {
            Self::IosProject => name.ends_with(".xcodeproj"),
            Self::IosWorkspace => name.ends_with(".xcworkspace"),
            Self::VersionSource | Self::MetadataRoot => true,
        }
    }
}
pub(crate) struct ChooseProjectPath<'a> { pub(crate) project_id: &'a str, pub(crate) field: ProjectPathField }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProjectPathResult {
    project_id: String, field: ProjectPathField, relative_path: String,
}

pub(crate) fn choose_project_path(body: &Value) -> Result<ChooseProjectPath<'_>, AssetError> {
    bounded(body, SMALL_LIMIT)?;
    let object = exact(body, &["projectId", "field"])?;
    let project_id = text(&object["projectId"])?;
    if !protocol::valid_id(project_id) { return Err(AssetError::invalid()); }
    let field = match text(&object["field"])? {
        "version.source" => ProjectPathField::VersionSource, "ios.project" => ProjectPathField::IosProject,
        "ios.workspace" => ProjectPathField::IosWorkspace, "metadata.root" => ProjectPathField::MetadataRoot,
        _ => return Err(AssetError::invalid()),
    };
    Ok(ChooseProjectPath { project_id, field })
}
pub(crate) fn project_path_result(project_id: &str, field: ProjectPathField, relative_path: String) -> Result<ProjectPathResult, AssetError> {
    if !protocol::valid_id(project_id) || !crate::release_version_protocol::relative_display_path(&relative_path)
        || !field.accepts_basename(relative_path.rsplit('/').next().unwrap_or("")) { return Err(AssetError::invalid()); }
    let result = ProjectPathResult { project_id: copy_text(project_id)?, field, relative_path };
    serde_json::to_writer(Counter { used: 0, limit: SMALL_LIMIT }, &result).map_err(|_| AssetError::new(Reason::Capacity))?;
    Ok(result)
}
/// All path-picker exits use this closed safe vocabulary, never a native path,
/// errno or another lane's message. Only settled genuine Cancel returns null.
pub(crate) fn project_path_error(reason: Reason) -> crate::error::BridgeError {
    let (code, message) = match reason {
        Reason::None | Reason::InvalidRequest => ("project_path_invalid", "The project-path request has an unsupported shape or size."),
        Reason::Closed | Reason::Unqualified | Reason::UnsupportedPlatform | Reason::UnsupportedFilesystem =>
            ("project_path_unavailable", "Browsing existing project paths is unavailable in this desktop runtime profile."),
        Reason::Busy => ("project_path_busy", "Finish the original native operation before browsing a project path."),
        Reason::ContextStale | Reason::DocumentLost | Reason::Shutdown | Reason::UserCancelled =>
            ("project_path_stale", "The project or document context changed; no field was updated."),
        Reason::SourceRefused | Reason::ProjectOverlap | Reason::ExclusionUnconfirmed | Reason::UnsupportedFormat =>
            ("project_path_unsafe", "Choose an existing supported file or folder strictly inside the selected project."),
        Reason::SourceChanged => ("project_path_changed", "The selected path or project changed during selection; no field was updated."),
        Reason::MaterialLimit | Reason::ParserLimit | Reason::Capacity =>
            ("project_path_limit", "The project-path selection exceeded a supported limit."),
        Reason::Deadline | Reason::ReviewExpired => ("project_path_deadline", "The project-path selection exceeded its operation deadline."),
        Reason::CleanupUnknown => ("project_path_cleanup_unknown", "Original project-path cleanup is unconfirmed. New native work is disabled; keep this window open."),
    };
    crate::error::BridgeError::new(code, message)
}

// No Debug/Deserialize or renderer readback. Immutable record backing is shared
// by Arc in the owner, rather than cloning these write-only strings for leases.
pub(crate) struct Fields { kind: Kind, values: Vec<Option<String>> }
impl Fields {
    pub(crate) fn empty_firebase() -> Self { Self { kind: Kind::AndroidFirebase, values: Vec::new() } }
    pub(crate) fn byte_count(&self) -> usize { self.values.iter().flatten().map(String::capacity).sum() }
    // Lookup admission counts retained allocation capacity, including empty
    // value cells. Keep the independent committed-record charge unchanged.
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let cells = self.values.capacity().checked_mul(std::mem::size_of::<Option<String>>())?;
        self.values.iter().flatten().try_fold(cells, |bytes, value| bytes.checked_add(value.capacity()))
    }
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
pub(crate) fn assert_project_path_command_contracts() {
    // Explicit-call, DATA-only contracts for a future harness=false observer.
    // They neither dispatch GTK nor manufacture a native selection proof.
    use serde_json::json;
    let fields = [
        ("version.source", ProjectPathField::VersionSource, false, "release/VERSION"),
        ("ios.project", ProjectPathField::IosProject, true, "ios/Example.xcodeproj"),
        ("ios.workspace", ProjectPathField::IosWorkspace, true, "ios/Example.xcworkspace"),
        ("metadata.root", ProjectPathField::MetadataRoot, true, "metadata/en-US"),
    ];
    for (name, expected, directory, relative) in fields {
        let body = json!({"projectId":"Project_1-a", "field":name});
        let args = choose_project_path(&body).ok().expect("fixed field refused");
        assert_eq!(args.project_id, "Project_1-a"); assert_eq!(args.field, expected);
        assert_eq!(expected.directory(), directory);
        let result = project_path_result(args.project_id, args.field, relative.to_owned()).ok().expect("relative DATA refused");
        let value = serde_json::to_value(&result).expect("bounded DTO serialization");
        assert_eq!(value, json!({"projectId":"Project_1-a", "field":name, "relativePath":relative}));
        assert!(serde_json::to_vec(&result).expect("DTO bytes").len() <= SMALL_LIMIT);
        for key in ["path", "relativePath", "initialFolder", "filters", "title", "draft", "expectedIdentity", "operationId"] {
            let mut extra = body.clone(); extra[key] = json!("not authority");
            assert!(choose_project_path(&extra).is_err());
        }
    }
    for field in ["", "Version.source", "ios", "ios.project ", "metadata.root.extra", "android.keystore", "candidate.root"] {
        assert!(choose_project_path(&json!({"projectId":"project-1", "field":field})).is_err());
    }
    for body in [Value::Null, json!([]), json!({}), json!({"projectId":"project-1"}),
        json!({"field":"version.source"}), json!({"projectId":1,"field":"version.source"}),
        json!({"projectId":"project-1","field":null}), json!({"projectId":"project-1","field":"x".repeat(SMALL_LIMIT)})] {
        assert!(choose_project_path(&body).is_err());
    }
    for id in ["".to_owned(), "a".repeat(65), "a/b".to_owned(), " x".to_owned(), "a\0b".to_owned(), "prøject".to_owned()] {
        assert!(choose_project_path(&json!({"projectId":id, "field":"version.source"})).is_err());
    }
    assert!(choose_project_path(&json!({"projectId":"A".repeat(64), "field":"version.source"})).is_ok());
    // The transport rule is the existing conservative relative-display subset,
    // not an extension whitelist, normalization, trimming or truncation rule.
    for relative in ["", "/absolute", "../VERSION", "dir/./VERSION", "dir//VERSION", ".hidden", "private/VERSION",
        "dir/name ", "dir/name.", "dir/name\\file", "C:VERSION", "dir/a\nb", "dir/CON.txt", "build/VERSION"] {
        assert!(project_path_result("project-1", ProjectPathField::VersionSource, relative.into()).is_err());
    }
    assert!(project_path_result("project-1", ProjectPathField::VersionSource, "package.json".into()).is_ok());
    assert!(project_path_result("project-1", ProjectPathField::VersionSource, "no-extension".into()).is_ok());
    for (field, wrong) in [(ProjectPathField::IosProject, "Example.XCODEPROJ"), (ProjectPathField::IosWorkspace, "Example.xcodeproj")] {
        assert!(project_path_result("project-1", field, wrong.into()).is_err());
    }
    let exactly_512 = format!("{}/{}/c", "a".repeat(255), "b".repeat(254));
    assert_eq!(exactly_512.len(), 512);
    assert!(project_path_result("project-1", ProjectPathField::VersionSource, exactly_512.clone()).is_ok());
    assert!(project_path_result("project-1", ProjectPathField::VersionSource, format!("{exactly_512}d")).is_err());
    assert!(project_path_result("project-1", ProjectPathField::MetadataRoot, vec!["a"; 12].join("/")).is_ok());
    assert!(project_path_result("project-1", ProjectPathField::MetadataRoot, vec!["a"; 13].join("/")).is_err());
    let cancellation: Option<ProjectPathResult> = None;
    assert_eq!(serde_json::to_value(cancellation).expect("null DTO"), Value::Null);
    let errors = [
        (Reason::InvalidRequest, "project_path_invalid"), (Reason::Unqualified, "project_path_unavailable"),
        (Reason::Busy, "project_path_busy"), (Reason::ContextStale, "project_path_stale"),
        (Reason::UserCancelled, "project_path_stale"), (Reason::SourceRefused, "project_path_unsafe"),
        (Reason::SourceChanged, "project_path_changed"), (Reason::Capacity, "project_path_limit"),
        (Reason::Deadline, "project_path_deadline"), (Reason::CleanupUnknown, "project_path_cleanup_unknown"),
    ];
    for (reason, code) in errors {
        let error = project_path_error(reason);
        assert_eq!(error.code, code); assert!(!error.retryable && !error.message.is_empty());
        assert!(serde_json::to_vec(&error).expect("safe fixed error").len() <= SMALL_LIMIT);
    }
}

#[cfg(test)]
pub(crate) fn assert_project_path_wiring_contract() {
    // Fixed source DATA only. Handler registration alone does not grant Tauri
    // command permission: AppManifest and the main/local ACL must agree too.
    fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        source.split_once(start).expect("source start").1.split_once(end).expect("source end").0
    }
    let commands = section(include_str!("../build.rs"), "const COMMANDS: &[&str] = &[", "];");
    let handlers = section(include_str!("shell.rs"), ".invoke_handler(tauri::generate_handler![", "])");
    let capability: Value = serde_json::from_str(include_str!("../capabilities/main.json")).expect("fixed main capability DATA");
    assert_eq!(commands.matches("\"choose_project_path\"").count(), 1);
    assert_eq!(handlers.split(',').filter(|name| name.trim() == "choose_project_path").count(), 1);
    assert_eq!(capability["local"], true);
    assert_eq!(capability["windows"], serde_json::json!(["main"]));
    assert!(capability.get("remote").is_none());
    let permissions = capability["permissions"].as_array().expect("closed permissions");
    assert_eq!(permissions.iter().filter(|permission| permission.as_str() == Some("allow-choose-project-path")).count(), 1);
    for permission in permissions {
        let permission = permission.as_str().expect("named permission");
        assert!(permission.starts_with("allow-") || ["core:event:allow-listen", "core:event:allow-unlisten"].contains(&permission));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn lookup_fields_charge_keeps_empty_cells_and_string_capacity() {
        let mut value = String::with_capacity(79); value.push_str("data"); value.truncate(1);
        let mut values = Vec::with_capacity(7); values.push(Some(value)); values.push(None);
        let fields = Fields { kind: Kind::GoogleWif, values };
        let cells = fields.values.capacity() * std::mem::size_of::<Option<String>>();
        assert_eq!(fields.retained_bytes(), Some(cells + fields.byte_count()));
        assert!(cells > 0 && fields.byte_count() > 1);
        assert_eq!(Fields::empty_firebase().retained_bytes(), Some(0));
    }
    #[test]
    fn project_path_command_is_registered_once_for_the_fixed_main_local_capability() { assert_project_path_wiring_contract(); }
    #[test]
    fn project_path_commands_are_closed_bounded_relative_data_only() { assert_project_path_command_contracts(); }
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
