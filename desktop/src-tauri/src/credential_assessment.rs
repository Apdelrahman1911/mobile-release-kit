//! Private supplied-input assessment adapter, not a renderer command or vault.
//!
//! The core owns requirement selection and scalar/Firebase policy. This module
//! admits the finite wire union and rebuilds a secret-free response; it never
//! forwards protocol::decode_response's arbitrary Value or error message.
//! No selected file, parser, document owner, storage or native gate is added.
//! A future prepare route still needs retained original-document/selection
//! custody and an exact-tuple recheck (R5); this result cannot grant assignment.
//! Request/serializer/owner buffers can retain secret copies, especially after
//! unknown cleanup. There is no zeroization, cancellation or erasure promise.
use std::io;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{Map, Value};
use crate::{error::BridgeError, protocol::{self, Method}, supervisor::Supervisor};

const POLICY: &str = "credential-policy-v1";
const DRAFT_LIMIT: usize = 512 * 1024;
const SCALAR_LIMIT: usize = 4096;
const SCALARS_LIMIT: usize = 65536;
const OBSERVATION_LIMIT: usize = 64 * 1024;
const OBSERVATION_NODES: usize = 4096;
const OBSERVATION_DEPTH: usize = 8;
const CLIENT_LIMIT: usize = 256;
const PROJECTED_STRING_LIMIT: usize = 1024;
const RESULT_LIMIT: usize = 16 * 1024;

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Platform { Android, Ios, Project }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Stage { Candidate, ExternalTesting, Production }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Purpose { Full, Signing, Store }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
enum PolicyVersion { #[serde(rename = "credential-policy-v1")] V1 }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Kind { AndroidKeystore, AndroidFirebase, AppleP12, AppleProfile, AscP8, IosFirebase, GoogleWif, ProjectReadToken }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum FieldId { File, StorePassword, KeyAlias, KeyPassword, Password, KeyId, IssuerId, Provider, ServiceAccount, Token }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
enum Requirement {
    #[serde(rename = "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64")] AndroidKeystore,
    #[serde(rename = "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD")] AndroidStorePassword,
    #[serde(rename = "MOBILE_RELEASE_ANDROID_KEY_ALIAS")] AndroidKeyAlias,
    #[serde(rename = "MOBILE_RELEASE_ANDROID_KEY_PASSWORD")] AndroidKeyPassword,
    #[serde(rename = "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64")] AndroidFirebase,
    #[serde(rename = "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64")] AppleP12,
    #[serde(rename = "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD")] ApplePassword,
    #[serde(rename = "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64")] AppleProfile,
    #[serde(rename = "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64")] AscP8,
    #[serde(rename = "MOBILE_RELEASE_ASC_KEY_ID")] AscKeyId,
    #[serde(rename = "MOBILE_RELEASE_ASC_ISSUER_ID")] AscIssuerId,
    #[serde(rename = "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64")] IosFirebase,
    #[serde(rename = "MOBILE_RELEASE_GOOGLE_WIF_PROVIDER")] GoogleProvider,
    #[serde(rename = "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT")] GoogleServiceAccount,
    #[serde(rename = "MOBILE_RELEASE_PROJECT_READ_TOKEN")] ProjectToken,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role { File, Secret, Identifier }
struct LayoutField { id: FieldId, requirement: Requirement, role: Role }

impl Kind {
    fn platform(self) -> Platform {
        match self {
            Self::AndroidKeystore | Self::AndroidFirebase | Self::GoogleWif => Platform::Android,
            Self::AppleP12 | Self::AppleProfile | Self::AscP8 | Self::IosFirebase => Platform::Ios,
            Self::ProjectReadToken => Platform::Project,
        }
    }
    fn firebase(self) -> bool { matches!(self, Self::AndroidFirebase | Self::IosFirebase) }
    fn has_file(self) -> bool { !matches!(self, Self::GoogleWif | Self::ProjectReadToken) }
    fn material_limit(self) -> u64 {
        // Fixed version-one wire bounds, not a reader, size claim or selector.
        // Canonical material_size_limit and all requiredness remain in Python.
        if matches!(self, Self::AndroidKeystore | Self::AppleP12) { 32 * 1024 * 1024 } else { 4 * 1024 * 1024 }
    }
    fn permits_format(self, format: Format) -> bool {
        matches!((self, format),
            (Self::AndroidKeystore, Format::Jks | Format::Pkcs12) | (Self::AppleP12, Format::Pkcs12)
            | (Self::AppleProfile, Format::CmsSignedData) | (Self::AscP8, Format::Pkcs8)
            | (Self::AndroidFirebase, Format::FirebaseJson) | (Self::IosFirebase, Format::FirebasePlist))
    }
    fn layout(self) -> &'static [LayoutField] {
        // Redaction allowlist: exact guide field order and server constants.
        // No stages, purposes, service flags, help or requiredness live here.
        use FieldId as F;
        use Requirement as R;
        use Role as T;
        match self {
            Self::AndroidKeystore => &[
                LayoutField { id: F::File, requirement: R::AndroidKeystore, role: T::File },
                LayoutField { id: F::StorePassword, requirement: R::AndroidStorePassword, role: T::Secret },
                LayoutField { id: F::KeyAlias, requirement: R::AndroidKeyAlias, role: T::Identifier },
                LayoutField { id: F::KeyPassword, requirement: R::AndroidKeyPassword, role: T::Secret },
            ],
            Self::AndroidFirebase => &[LayoutField { id: F::File, requirement: R::AndroidFirebase, role: T::File }],
            Self::AppleP12 => &[
                LayoutField { id: F::File, requirement: R::AppleP12, role: T::File },
                LayoutField { id: F::Password, requirement: R::ApplePassword, role: T::Secret },
            ],
            Self::AppleProfile => &[LayoutField { id: F::File, requirement: R::AppleProfile, role: T::File }],
            Self::AscP8 => &[
                LayoutField { id: F::File, requirement: R::AscP8, role: T::File },
                LayoutField { id: F::KeyId, requirement: R::AscKeyId, role: T::Identifier },
                LayoutField { id: F::IssuerId, requirement: R::AscIssuerId, role: T::Identifier },
            ],
            Self::IosFirebase => &[LayoutField { id: F::File, requirement: R::IosFirebase, role: T::File }],
            Self::GoogleWif => &[
                LayoutField { id: F::Provider, requirement: R::GoogleProvider, role: T::Identifier },
                LayoutField { id: F::ServiceAccount, requirement: R::GoogleServiceAccount, role: T::Identifier },
            ],
            Self::ProjectReadToken => &[LayoutField { id: F::Token, requirement: R::ProjectToken, role: T::Secret }],
        }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum UnavailableReason { NotRun, Incomplete, UnsupportedFormat, UnsupportedVariant, MaterialLimit, ParserLimit }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum RejectedReason { EmptyFile, SuffixConflict, MalformedContainer }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
enum Format {
    #[serde(rename = "jks")] Jks,
    #[serde(rename = "pkcs12")] Pkcs12,
    #[serde(rename = "cms-signed-data")] CmsSignedData,
    #[serde(rename = "pkcs8")] Pkcs8,
    #[serde(rename = "firebase-json")] FirebaseJson,
    #[serde(rename = "firebase-plist")] FirebasePlist,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AuthSafe { Data, SignedData }
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum DerEncoding { Der }
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum P8Encoding { Pem, Der }
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum PlistEncoding { Xml, Binary }
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Algorithm { Ec, Rsa, Other }
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Curve { P256, Other }
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum AndroidRoot { Object, Other }
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum IosRoot { Dictionary, Other }

// No secret-bearing DTO derives Debug. Option members are required on the wire:
// admission checks exact keys before converting an explicit null to None.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AndroidClientInfo { package_name: Option<String> }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientInfo { android_client_info: Option<AndroidClientInfo> }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AndroidClient { client_info: Option<ClientInfo> }
#[derive(Serialize)]
struct AndroidProjection { root: AndroidRoot, clients: Option<Vec<Option<AndroidClient>>> }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IosProjection { root: IosRoot, bundle_id: Option<String> }

#[derive(Serialize)]
#[serde(tag = "format")]
enum Observed {
    #[serde(rename = "jks")]
    Jks { #[serde(rename = "byteCount")] byte_count: u64, version: u8 },
    #[serde(rename = "pkcs12")]
    Pkcs12 { #[serde(rename = "byteCount")] byte_count: u64, version: u8, #[serde(rename = "authSafe")] auth_safe: AuthSafe },
    #[serde(rename = "cms-signed-data")]
    CmsSignedData { #[serde(rename = "byteCount")] byte_count: u64, encoding: DerEncoding },
    #[serde(rename = "pkcs8")]
    Pkcs8 { #[serde(rename = "byteCount")] byte_count: u64, encoding: P8Encoding, algorithm: Algorithm, curve: Option<Curve> },
    #[serde(rename = "firebase-json")]
    FirebaseJson { #[serde(rename = "byteCount")] byte_count: u64, document: AndroidProjection },
    #[serde(rename = "firebase-plist")]
    FirebasePlist { #[serde(rename = "byteCount")] byte_count: u64, encoding: PlistEncoding, document: IosProjection },
}
impl Observed {
    fn format(&self) -> Format {
        match self {
            Self::Jks { .. } => Format::Jks, Self::Pkcs12 { .. } => Format::Pkcs12,
            Self::CmsSignedData { .. } => Format::CmsSignedData, Self::Pkcs8 { .. } => Format::Pkcs8,
            Self::FirebaseJson { .. } => Format::FirebaseJson, Self::FirebasePlist { .. } => Format::FirebasePlist,
        }
    }
}
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum FileObservation {
    Unavailable { reason: UnavailableReason },
    Rejected { reason: RejectedReason },
    Observed { #[serde(flatten)] data: Observed },
}
#[derive(Serialize)]
struct EmptyFields {}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeystoreFields { store_password: Option<String>, key_alias: Option<String>, key_password: Option<String> }
#[derive(Serialize)]
struct P12Fields { password: Option<String> }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct P8Fields { key_id: Option<String>, issuer_id: Option<String> }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WifFields { provider: Option<String>, service_account: Option<String> }
#[derive(Serialize)]
struct TokenFields { token: Option<String> }
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Input {
    AndroidKeystore { fields: KeystoreFields, observation: Option<FileObservation> },
    AndroidFirebase { fields: EmptyFields, observation: Option<FileObservation> },
    AppleP12 { fields: P12Fields, observation: Option<FileObservation> },
    AppleProfile { fields: EmptyFields, observation: Option<FileObservation> },
    AscP8 { fields: P8Fields, observation: Option<FileObservation> },
    IosFirebase { fields: EmptyFields, observation: Option<FileObservation> },
    GoogleWif { fields: WifFields, observation: () },
    ProjectReadToken { fields: TokenFields, observation: () },
}
#[derive(Serialize)]
struct RequestContext { draft: Value, platform: Platform, stage: Stage, purpose: Purpose }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AssessmentRequest {
    schema_version: u8, policy_version: PolicyVersion, context: RequestContext, input: Input,
}

#[derive(Clone, Copy)]
enum ErrorKind { InvalidRequest, Limit, Version, PolicyStale, ContextInvalid, Unavailable, Busy, ShuttingDown, QueryTimeout, CleanupUnknown, ContextStale }
#[derive(Serialize)]
pub(crate) struct AssessmentError { code: &'static str, message: &'static str, retryable: bool }
impl AssessmentError {
    fn new(kind: ErrorKind) -> Self {
        let (code, message) = match kind {
            ErrorKind::InvalidRequest => ("assessment_invalid_request", "The assessment request has an unsupported shape or value type."),
            ErrorKind::Limit => ("assessment_limit", "The assessment request exceeds a supported interface bound."),
            ErrorKind::Version => ("assessment_version", "This assessment schema version is unavailable."),
            ErrorKind::PolicyStale => ("assessment_policy_stale", "Credential policy changed; prepare the context again."),
            ErrorKind::ContextInvalid => ("assessment_context_invalid", "The submitted draft is not valid for assessment."),
            ErrorKind::Unavailable => ("assessment_unavailable", "Credential assessment is unavailable; no credential was verified."),
            ErrorKind::Busy => ("busy", "Two read-only queries already own the available slots."),
            ErrorKind::ShuttingDown => ("shutting_down", "The application is stopping its owned queries."),
            ErrorKind::QueryTimeout => ("query_timeout", "The read-only query exceeded its operation deadline."),
            ErrorKind::CleanupUnknown => ("cleanup_unknown", "Original query cleanup is unconfirmed. Further queries are disabled; the owner is retained."),
            ErrorKind::ContextStale => ("assessment_context_stale", "Assessment context changed; prepare again."),
        };
        Self { code, message, retryable: false }
    }
    fn invalid() -> Self { Self::new(ErrorKind::InvalidRequest) }
    fn limit() -> Self { Self::new(ErrorKind::Limit) }
    fn unavailable() -> Self { Self::new(ErrorKind::Unavailable) }
    // Reserved for a real native tuple mismatch, not a core error or caller flag.
    // No document/selection binding is implemented or asserted by this helper.
    pub(crate) fn context_stale() -> Self { Self::new(ErrorKind::ContextStale) }
}

fn sanitized_error(error: BridgeError) -> AssessmentError {
    // Discard message and never render Debug/Display for the raw BridgeError.
    if error.retryable { return AssessmentError::unavailable(); }
    let kind = match error.code.as_str() {
        "assessment_invalid_request" => ErrorKind::InvalidRequest, "assessment_limit" => ErrorKind::Limit,
        "assessment_version" => ErrorKind::Version, "assessment_policy_stale" => ErrorKind::PolicyStale,
        "assessment_context_invalid" => ErrorKind::ContextInvalid, "assessment_unavailable" => ErrorKind::Unavailable,
        "busy" => ErrorKind::Busy, "shutting_down" => ErrorKind::ShuttingDown,
        "query_timeout" => ErrorKind::QueryTimeout, "cleanup_unknown" => ErrorKind::CleanupUnknown,
        _ => ErrorKind::Unavailable,
    };
    AssessmentError::new(kind)
}

struct SizeBudget { used: usize, limit: usize }
impl io::Write for SizeBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.used) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "assessment JSON bound"));
        }
        self.used += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
fn size_within(value: &Value, limit: usize) -> bool {
    serde_json::to_writer(SizeBudget { used: 0, limit }, value).is_ok()
}
fn json_bounds(value: &Value, max_nodes: usize, max_depth: usize) -> bool {
    let mut pending = vec![(value, 0usize)];
    let mut nodes = 0usize;
    while let Some((current, depth)) = pending.pop() {
        nodes += 1;
        if nodes > max_nodes || depth > max_depth { return false; }
        match current {
            Value::Object(items) => {
                if depth >= max_depth || items.len() > max_nodes.saturating_sub(nodes + pending.len()) / 2 { return false; }
                nodes += items.len(); // Keys are nodes at depth + 1, as in Python.
                pending.extend(items.values().map(|value| (value, depth + 1)));
            }
            Value::Array(items) => {
                if depth >= max_depth || items.len() > max_nodes.saturating_sub(nodes + pending.len()) { return false; }
                pending.extend(items.iter().map(|value| (value, depth + 1)));
            }
            _ => {}
        }
    }
    true
}
fn exact<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>, AssessmentError> {
    let object = value.as_object().ok_or_else(AssessmentError::invalid)?;
    if object.len() != keys.len() || !keys.iter().all(|key| object.contains_key(*key)) { return Err(AssessmentError::invalid()); }
    Ok(object)
}
fn finite<T: DeserializeOwned>(value: &Value) -> Result<T, AssessmentError> {
    // Serde's externally tagged unit enums can also accept object syntax.
    // The assessment wire permits exact JSON strings only, never that syntax.
    if !value.is_string() { return Err(AssessmentError::invalid()); }
    T::deserialize(value).map_err(|_| AssessmentError::invalid())
}
fn scalar(value: &Value, total: &mut usize) -> Result<Option<String>, AssessmentError> {
    if value.is_null() { return Ok(None); }
    let value = value.as_str().ok_or_else(AssessmentError::invalid)?;
    if value.len() > SCALAR_LIMIT || value.len() > SCALARS_LIMIT.saturating_sub(*total) { return Err(AssessmentError::limit()); }
    *total += value.len();
    Ok(Some(value.to_owned())) // NUL and empty strings remain field facts for the core.
}
fn projected_string(value: &Value) -> Result<Option<String>, AssessmentError> {
    if value.is_null() { return Ok(None); }
    let value = value.as_str().ok_or_else(AssessmentError::invalid)?;
    if value.len() > PROJECTED_STRING_LIMIT { return Err(AssessmentError::limit()); }
    Ok(Some(value.to_owned()))
}
fn android_projection(value: &Value) -> Result<AndroidProjection, AssessmentError> {
    let object = exact(value, &["root", "clients"])?;
    let root: AndroidRoot = finite(&object["root"])?;
    if root == AndroidRoot::Other && !object["clients"].is_null() { return Err(AssessmentError::invalid()); }
    let clients = if object["clients"].is_null() { None } else {
        let raw_clients = object["clients"].as_array().ok_or_else(AssessmentError::invalid)?;
        if raw_clients.len() > CLIENT_LIMIT { return Err(AssessmentError::limit()); }
        let mut clients = Vec::with_capacity(raw_clients.len());
        for client in raw_clients {
            if client.is_null() { clients.push(None); continue; }
            let client = exact(client, &["clientInfo"])?;
            let client_info = if client["clientInfo"].is_null() { None } else {
                let info = exact(&client["clientInfo"], &["androidClientInfo"])?;
                let android_client_info = if info["androidClientInfo"].is_null() { None } else {
                    let android = exact(&info["androidClientInfo"], &["packageName"])?;
                    Some(AndroidClientInfo { package_name: projected_string(&android["packageName"])? })
                };
                Some(ClientInfo { android_client_info })
            };
            clients.push(Some(AndroidClient { client_info }));
        }
        Some(clients)
    };
    Ok(AndroidProjection { root, clients })
}
fn ios_projection(value: &Value) -> Result<IosProjection, AssessmentError> {
    let object = exact(value, &["root", "bundleId"])?;
    let root: IosRoot = finite(&object["root"])?;
    if root == IosRoot::Other && !object["bundleId"].is_null() { return Err(AssessmentError::invalid()); }
    Ok(IosProjection { root, bundle_id: projected_string(&object["bundleId"])? })
}
fn observation(value: &Value, kind: Kind) -> Result<Option<FileObservation>, AssessmentError> {
    if value.is_null() { return Ok(None); }
    if !kind.has_file() { return Err(AssessmentError::invalid()); }
    let object = value.as_object().ok_or_else(AssessmentError::invalid)?;
    let status = object.get("status").and_then(Value::as_str).ok_or_else(AssessmentError::invalid)?;
    let observation = match status {
        "unavailable" => {
            let object = exact(value, &["status", "reason"])?;
            FileObservation::Unavailable { reason: finite(&object["reason"])? }
        }
        "rejected" => {
            let object = exact(value, &["status", "reason"])?;
            FileObservation::Rejected { reason: finite(&object["reason"])? }
        }
        "observed" => {
            let format: Format = finite(object.get("format").ok_or_else(AssessmentError::invalid)?)?;
            if !kind.permits_format(format) { return Err(AssessmentError::invalid()); }
            let keys: &[&str] = match format {
                Format::Jks => &["status", "byteCount", "format", "version"],
                Format::Pkcs12 => &["status", "byteCount", "format", "version", "authSafe"],
                Format::CmsSignedData => &["status", "byteCount", "format", "encoding"],
                Format::Pkcs8 => &["status", "byteCount", "format", "encoding", "algorithm", "curve"],
                Format::FirebaseJson => &["status", "byteCount", "format", "document"],
                Format::FirebasePlist => &["status", "byteCount", "format", "encoding", "document"],
            };
            let object = exact(value, keys)?;
            let byte_count = object["byteCount"].as_u64().filter(|value| *value > 0).ok_or_else(AssessmentError::invalid)?;
            if byte_count > kind.material_limit() { return Err(AssessmentError::limit()); }
            let data = match format {
                Format::Jks => {
                    let version = object["version"].as_u64().filter(|value| matches!(*value, 1 | 2)).ok_or_else(AssessmentError::invalid)?;
                    Observed::Jks { byte_count, version: version as u8 }
                }
                Format::Pkcs12 => {
                    if object["version"].as_u64() != Some(3) { return Err(AssessmentError::invalid()); }
                    Observed::Pkcs12 { byte_count, version: 3, auth_safe: finite(&object["authSafe"])? }
                }
                Format::CmsSignedData => Observed::CmsSignedData { byte_count, encoding: finite(&object["encoding"])? },
                Format::Pkcs8 => {
                    let algorithm: Algorithm = finite(&object["algorithm"])?;
                    let curve = if object["curve"].is_null() { None } else { Some(finite(&object["curve"])?) };
                    if algorithm != Algorithm::Ec && curve.is_some() { return Err(AssessmentError::invalid()); }
                    Observed::Pkcs8 { byte_count, encoding: finite(&object["encoding"])?, algorithm, curve }
                }
                Format::FirebaseJson => Observed::FirebaseJson { byte_count, document: android_projection(&object["document"])? },
                Format::FirebasePlist => Observed::FirebasePlist {
                    byte_count, encoding: finite(&object["encoding"])?, document: ios_projection(&object["document"])?,
                },
            };
            FileObservation::Observed { data }
        }
        _ => return Err(AssessmentError::invalid()),
    };
    if !json_bounds(value, OBSERVATION_NODES, OBSERVATION_DEPTH) || !size_within(value, OBSERVATION_LIMIT) {
        return Err(AssessmentError::limit());
    }
    Ok(Some(observation))
}

fn input(value: &Value) -> Result<Input, AssessmentError> {
    let object = exact(value, &["kind", "fields", "observation"])?;
    let kind: Kind = finite(&object["kind"])?;
    let keys: &[&str] = match kind {
        Kind::AndroidKeystore => &["storePassword", "keyAlias", "keyPassword"],
        Kind::AppleP12 => &["password"], Kind::AscP8 => &["keyId", "issuerId"],
        Kind::GoogleWif => &["provider", "serviceAccount"], Kind::ProjectReadToken => &["token"],
        _ => &[],
    };
    let fields = exact(&object["fields"], keys)?;
    let mut total = 0usize;
    let observation = observation(&object["observation"], kind)?;
    Ok(match kind {
        Kind::AndroidKeystore => Input::AndroidKeystore { fields: KeystoreFields {
            store_password: scalar(&fields["storePassword"], &mut total)?, key_alias: scalar(&fields["keyAlias"], &mut total)?,
            key_password: scalar(&fields["keyPassword"], &mut total)?,
        }, observation },
        Kind::AndroidFirebase => Input::AndroidFirebase { fields: EmptyFields {}, observation },
        Kind::AppleP12 => Input::AppleP12 { fields: P12Fields { password: scalar(&fields["password"], &mut total)? }, observation },
        Kind::AppleProfile => Input::AppleProfile { fields: EmptyFields {}, observation },
        Kind::AscP8 => Input::AscP8 { fields: P8Fields {
            key_id: scalar(&fields["keyId"], &mut total)?, issuer_id: scalar(&fields["issuerId"], &mut total)?,
        }, observation },
        Kind::IosFirebase => Input::IosFirebase { fields: EmptyFields {}, observation },
        Kind::GoogleWif => Input::GoogleWif { fields: WifFields {
            provider: scalar(&fields["provider"], &mut total)?, service_account: scalar(&fields["serviceAccount"], &mut total)?,
        }, observation: () },
        Kind::ProjectReadToken => Input::ProjectReadToken { fields: TokenFields { token: scalar(&fields["token"], &mut total)? }, observation: () },
    })
}

impl AssessmentRequest {
    pub(crate) fn admit(body: &Value) -> Result<Self, AssessmentError> {
        let object = exact(body, &["schemaVersion", "policyVersion", "context", "input"])?;
        let policy = object["policyVersion"].as_str().ok_or_else(AssessmentError::invalid)?;
        if policy.is_empty() || policy.len() > 64 || !policy.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)) {
            return Err(AssessmentError::invalid());
        }
        if policy != POLICY { return Err(AssessmentError::new(ErrorKind::PolicyStale)); }
        match &object["schemaVersion"] {
            Value::Number(number) if number.is_i64() || number.is_u64() => {
                if number.as_u64() != Some(1) { return Err(AssessmentError::new(ErrorKind::Version)); }
            }
            _ => return Err(AssessmentError::invalid()),
        }
        let context = exact(&object["context"], &["draft", "platform", "stage", "purpose"])?;
        let platform: Platform = finite(&context["platform"])?;
        let stage: Stage = finite(&context["stage"])?;
        let purpose: Purpose = finite(&context["purpose"])?;
        let draft = &context["draft"];
        if !draft.is_object() { return Err(AssessmentError::invalid()); }
        let input = input(&object["input"])?;
        protocol::check_value(body).map_err(|_| AssessmentError::limit())?;
        if !size_within(body, protocol::REQUEST_LIMIT - 1) || !size_within(draft, DRAFT_LIMIT) { return Err(AssessmentError::limit()); }
        // No duplicate config/schema validator here: core independently parses
        // this bounded draft. The real transport still bounds its actual frame.
        Ok(Self { schema_version: 1, policy_version: PolicyVersion::V1,
            context: RequestContext { draft: draft.clone(), platform, stage, purpose }, input })
    }
    fn into_params(self) -> Result<Value, AssessmentError> {
        serde_json::to_value(self).map_err(|_| AssessmentError::unavailable())
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum State { NotApplicable, Missing, Unknown, Invalid, Configured, FormatValid }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Identity { NotApplicable, NotAssessed, Match, Mismatch }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Presence { Missing, Supplied }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ApplicabilityState { Required, NotApplicable }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ApplicabilityReason { Selected, WrongPlatform, PlatformDisabled, NotRequired }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum IssueCode {
    NotRun, Incomplete, UnsupportedFormat, UnsupportedVariant, MaterialLimit, ParserLimit,
    EmptyFile, SuffixConflict, MalformedContainer, RequiredMissing, ValueNul, ScalarFormat,
    #[serde(rename = "pkcs8-algorithm")] Pkcs8Algorithm,
    FirebaseShape, IdentityMismatch,
}
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Scope {
    ValueAdmission, IdentifierFormat, FileNonempty, SuffixConsistency, ContainerParse,
    JksHeader, PfxEnvelope, CmsSignedDataEnvelope,
    #[serde(rename = "pkcs8-envelope")] Pkcs8Envelope,
    JsonDocument, PlistDocument, EcP256Identifiers, FirebaseShape, ApplicationIdentity,
}
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Outcome { Passed, Failed, AssertedPass, AssertedFail }
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Check { scope: Scope, outcome: Outcome }
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FieldResult { id: FieldId, requirement: Requirement, presence: Presence, state: State, issues: Vec<IssueCode>, checks: Vec<Check> }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ResultContext { platform: Platform, stage: Stage, purpose: Purpose }
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Applicability { state: ApplicabilityState, reason: ApplicabilityReason }
#[derive(Deserialize, Serialize)]
enum Basis { #[serde(rename = "supplied-input-only")] SuppliedInputOnly }
#[derive(Deserialize, Serialize)]
enum SourceCustody { #[serde(rename = "not-established")] NotEstablished }
#[derive(Deserialize, Serialize)]
enum Validation { #[serde(rename = "not-run")] NotRun }
#[derive(Deserialize, Serialize)]
enum Readiness { #[serde(rename = "unknown")] Unknown }
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AssessmentAssurance {
    basis: Basis, scalar_values_processed: bool, file_observations_processed: bool,
    selected_files_read: bool, keyring_accessed: bool, storage_writes_performed: bool, project_code_executed: bool,
    source_custody: SourceCustody, native_validation: Validation, service_validation: Validation, release_readiness: Readiness,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AssessmentResult {
    schema_version: u8, policy_version: PolicyVersion, kind: Kind, context: ResultContext,
    applicability: Applicability, state: State, fields: Vec<FieldResult>, identity: Identity, assurance: AssessmentAssurance,
}

#[derive(Clone, Copy)]
enum FileFact { Missing, Unavailable(UnavailableReason), Rejected(RejectedReason), Observed(Format) }
enum FieldExpectation { File(FileFact), Scalar { presence: Presence, nul: bool, processed: bool } }
impl FieldExpectation {
    fn file(observation: &Option<FileObservation>) -> Self {
        Self::File(match observation {
            None => FileFact::Missing,
            Some(FileObservation::Unavailable { reason }) => FileFact::Unavailable(*reason),
            Some(FileObservation::Rejected { reason }) => FileFact::Rejected(*reason),
            Some(FileObservation::Observed { data }) => FileFact::Observed(data.format()),
        })
    }
    fn scalar(value: &Option<String>) -> Self {
        Self::Scalar {
            presence: if value.as_ref().is_none_or(|value| value.is_empty()) { Presence::Missing } else { Presence::Supplied },
            nul: value.as_ref().is_some_and(|value| value.contains('\0')), processed: value.is_some(),
        }
    }
    fn presence(&self) -> Presence {
        match self {
            Self::File(FileFact::Missing) => Presence::Missing,
            Self::File(_) => Presence::Supplied,
            Self::Scalar { presence, .. } => *presence,
        }
    }
}
struct Expected {
    kind: Kind, context: ResultContext, fields: Vec<FieldExpectation>,
    scalar_values_processed: bool, file_observations_processed: bool,
}
impl AssessmentRequest {
    fn expected(&self) -> Expected {
        use FieldExpectation as E;
        let (kind, fields) = match &self.input {
            Input::AndroidKeystore { fields, observation } => (Kind::AndroidKeystore, vec![
                E::file(observation), E::scalar(&fields.store_password), E::scalar(&fields.key_alias), E::scalar(&fields.key_password),
            ]),
            Input::AndroidFirebase { observation, .. } => (Kind::AndroidFirebase, vec![E::file(observation)]),
            Input::AppleP12 { fields, observation } => (Kind::AppleP12, vec![E::file(observation), E::scalar(&fields.password)]),
            Input::AppleProfile { observation, .. } => (Kind::AppleProfile, vec![E::file(observation)]),
            Input::AscP8 { fields, observation } => (Kind::AscP8, vec![E::file(observation), E::scalar(&fields.key_id), E::scalar(&fields.issuer_id)]),
            Input::IosFirebase { observation, .. } => (Kind::IosFirebase, vec![E::file(observation)]),
            Input::GoogleWif { fields, .. } => (Kind::GoogleWif, vec![E::scalar(&fields.provider), E::scalar(&fields.service_account)]),
            Input::ProjectReadToken { fields, .. } => (Kind::ProjectReadToken, vec![E::scalar(&fields.token)]),
        };
        let scalar_values_processed = fields.iter().any(|field| matches!(field, E::Scalar { processed: true, .. }));
        let file_observations_processed = fields.iter().any(|field| matches!(field, E::File(fact) if !matches!(fact, FileFact::Missing)));
        Expected { kind, context: ResultContext { platform: self.context.platform, stage: self.context.stage, purpose: self.context.purpose },
            fields, scalar_values_processed, file_observations_processed }
    }
}

fn field_is(field: &FieldResult, state: State, issues: &[IssueCode], checks: &[(Scope, Outcome)]) -> bool {
    field.state == state && field.issues.as_slice() == issues && field.checks.len() == checks.len()
        && field.checks.iter().zip(checks).all(|(actual, (scope, outcome))| actual.scope == *scope && actual.outcome == *outcome)
}
fn scalar_result(field: &FieldResult, role: Role, presence: Presence, nul: bool) -> bool {
    use Outcome::{Failed, Passed};
    use Scope::{IdentifierFormat, ValueAdmission};
    if presence == Presence::Missing { return field_is(field, State::Missing, &[IssueCode::RequiredMissing], &[]); }
    if nul { return field_is(field, State::Invalid, &[IssueCode::ValueNul], &[(ValueAdmission, Failed)]); }
    match role {
        Role::Secret => field_is(field, State::Configured, &[], &[(ValueAdmission, Passed)]),
        Role::Identifier => field_is(field, State::Configured, &[], &[(ValueAdmission, Passed), (IdentifierFormat, Passed)])
            || field_is(field, State::Invalid, &[IssueCode::ScalarFormat], &[(ValueAdmission, Passed), (IdentifierFormat, Failed)]),
        Role::File => false,
    }
}
fn unavailable_issue(reason: UnavailableReason) -> IssueCode {
    match reason {
        UnavailableReason::NotRun => IssueCode::NotRun, UnavailableReason::Incomplete => IssueCode::Incomplete,
        UnavailableReason::UnsupportedFormat => IssueCode::UnsupportedFormat, UnavailableReason::UnsupportedVariant => IssueCode::UnsupportedVariant,
        UnavailableReason::MaterialLimit => IssueCode::MaterialLimit, UnavailableReason::ParserLimit => IssueCode::ParserLimit,
    }
}
fn rejected_check(reason: RejectedReason) -> (IssueCode, Scope) {
    match reason {
        RejectedReason::EmptyFile => (IssueCode::EmptyFile, Scope::FileNonempty),
        RejectedReason::SuffixConflict => (IssueCode::SuffixConflict, Scope::SuffixConsistency),
        RejectedReason::MalformedContainer => (IssueCode::MalformedContainer, Scope::ContainerParse),
    }
}
fn format_scope(format: Format) -> Scope {
    match format {
        Format::Jks => Scope::JksHeader, Format::Pkcs12 => Scope::PfxEnvelope,
        Format::CmsSignedData => Scope::CmsSignedDataEnvelope, Format::Pkcs8 => Scope::Pkcs8Envelope,
        Format::FirebaseJson => Scope::JsonDocument, Format::FirebasePlist => Scope::PlistDocument,
    }
}
fn file_result(field: &FieldResult, fact: FileFact, kind: Kind) -> Option<Identity> {
    use Outcome::{AssertedFail, AssertedPass, Failed, Passed};
    let not_assessed = if kind.firebase() { Identity::NotAssessed } else { Identity::NotApplicable };
    match fact {
        FileFact::Missing => field_is(field, State::Missing, &[IssueCode::RequiredMissing], &[]).then_some(not_assessed),
        FileFact::Unavailable(reason) => field_is(field, State::Unknown, &[unavailable_issue(reason)], &[]).then_some(not_assessed),
        FileFact::Rejected(reason) => {
            let (issue, scope) = rejected_check(reason);
            field_is(field, State::Invalid, &[issue], &[(scope, AssertedFail)]).then_some(not_assessed)
        }
        FileFact::Observed(format) => {
            let envelope = (format_scope(format), AssertedPass);
            match format {
                Format::Jks | Format::Pkcs12 | Format::CmsSignedData => field_is(field, State::Configured, &[], &[envelope]).then_some(not_assessed),
                Format::Pkcs8 => {
                    let valid = field_is(field, State::Configured, &[], &[envelope, (Scope::EcP256Identifiers, Passed)])
                        || field_is(field, State::Invalid, &[IssueCode::Pkcs8Algorithm], &[envelope, (Scope::EcP256Identifiers, Failed)]);
                    valid.then_some(not_assessed)
                }
                Format::FirebaseJson | Format::FirebasePlist => {
                    if field_is(field, State::Invalid, &[IssueCode::FirebaseShape], &[envelope, (Scope::FirebaseShape, Failed)]) {
                        Some(Identity::NotAssessed)
                    } else if field_is(field, State::Invalid, &[IssueCode::IdentityMismatch], &[
                        envelope, (Scope::FirebaseShape, Passed), (Scope::ApplicationIdentity, Failed),
                    ]) { Some(Identity::Mismatch) }
                    else if field_is(field, State::FormatValid, &[], &[
                        envelope, (Scope::FirebaseShape, Passed), (Scope::ApplicationIdentity, Passed),
                    ]) { Some(Identity::Match) } else { None }
                }
            }
        }
    }
}
impl AssessmentResult {
    /// Only the core's already-sanitized disposition. This is not another
    /// requirements selector or a native/service-validation assertion.
    pub(crate) fn permits_session_preview(&self) -> bool {
        self.applicability.state == ApplicabilityState::Required
            && matches!(self.state, State::Configured | State::FormatValid)
    }
}

fn result_valid(result: &AssessmentResult, expected: &Expected) -> bool {
    if result.schema_version != 1 || result.policy_version != PolicyVersion::V1 || result.kind != expected.kind
        || result.context != expected.context || result.fields.len() != expected.kind.layout().len()
        || result.fields.len() != expected.fields.len() { return false; }
    let assurance = &result.assurance;
    if assurance.scalar_values_processed != expected.scalar_values_processed || assurance.file_observations_processed != expected.file_observations_processed
        || assurance.selected_files_read || assurance.keyring_accessed || assurance.storage_writes_performed || assurance.project_code_executed { return false; }
    let applicable = result.applicability.state == ApplicabilityState::Required;
    if applicable != (result.applicability.reason == ApplicabilityReason::Selected) { return false; }
    if expected.kind.platform() != expected.context.platform {
        if applicable || result.applicability.reason != ApplicabilityReason::WrongPlatform { return false; }
    } else if result.applicability.reason == ApplicabilityReason::WrongPlatform { return false; }
    if expected.context.platform == Platform::Project && result.applicability.reason == ApplicabilityReason::PlatformDisabled { return false; }
    let mut identity = if expected.kind.firebase() { Identity::NotAssessed } else { Identity::NotApplicable };
    for ((field, layout), fact) in result.fields.iter().zip(expected.kind.layout()).zip(&expected.fields) {
        if field.id != layout.id || field.requirement != layout.requirement || field.presence != fact.presence()
            || field.issues.len() > 1 || field.checks.len() > 3 { return false; }
        if !applicable {
            if !field_is(field, State::NotApplicable, &[], &[]) { return false; }
            continue;
        }
        match fact {
            FieldExpectation::File(fact) => {
                if layout.role != Role::File { return false; }
                let Some(file_identity) = file_result(field, *fact, expected.kind) else { return false; };
                identity = file_identity;
            }
            FieldExpectation::Scalar { presence, nul, .. } => {
                if !scalar_result(field, layout.role, *presence, *nul) { return false; }
            }
        }
    }
    let aggregate = if !applicable { State::NotApplicable } else {
        [State::Invalid, State::Missing, State::Unknown].into_iter()
            .find(|state| result.fields.iter().any(|field| field.state == *state))
            .unwrap_or(if expected.kind.firebase() { State::FormatValid } else { State::Configured })
    };
    result.state == aggregate && result.identity == identity
}
fn string_members(object: &Map<String, Value>, keys: &[&str]) -> bool {
    keys.iter().all(|key| object.get(*key).is_some_and(Value::is_string))
}
fn result_shape(raw: &Value) -> bool {
    let Ok(object) = exact(raw, &["schemaVersion", "policyVersion", "kind", "context", "applicability", "state", "fields", "identity", "assurance"]) else { return false; };
    if object["schemaVersion"].as_u64() != Some(1) || !string_members(object, &["policyVersion", "kind", "state", "identity"]) { return false; }
    let Ok(context) = exact(&object["context"], &["platform", "stage", "purpose"]) else { return false; };
    let Ok(applicability) = exact(&object["applicability"], &["state", "reason"]) else { return false; };
    if !string_members(context, &["platform", "stage", "purpose"]) || !string_members(applicability, &["state", "reason"]) { return false; }
    let Some(fields) = object["fields"].as_array() else { return false; };
    if fields.is_empty() || fields.len() > 4 { return false; }
    for field in fields {
        let Ok(field) = exact(field, &["id", "requirement", "presence", "state", "issues", "checks"]) else { return false; };
        if !string_members(field, &["id", "requirement", "presence", "state"]) { return false; }
        let Some(issues) = field["issues"].as_array() else { return false; };
        let Some(checks) = field["checks"].as_array() else { return false; };
        if issues.len() > 1 || !issues.iter().all(Value::is_string) || checks.len() > 3 { return false; }
        for check in checks {
            let Ok(check) = exact(check, &["scope", "outcome"]) else { return false; };
            if !string_members(check, &["scope", "outcome"]) { return false; }
        }
    }
    let Ok(assurance) = exact(&object["assurance"], &[
        "basis", "scalarValuesProcessed", "fileObservationsProcessed", "selectedFilesRead", "keyringAccessed",
        "storageWritesPerformed", "projectCodeExecuted", "sourceCustody", "nativeValidation", "serviceValidation", "releaseReadiness",
    ]) else { return false; };
    string_members(assurance, &["basis", "sourceCustody", "nativeValidation", "serviceValidation", "releaseReadiness"])
        && ["scalarValuesProcessed", "fileObservationsProcessed", "selectedFilesRead", "keyringAccessed", "storageWritesPerformed", "projectCodeExecuted"]
            .iter().all(|key| assurance[*key].is_boolean())
}
fn sanitized_result(raw: Value, expected: &Expected) -> Result<AssessmentResult, AssessmentError> {
    // Bound before allocating DTO strings/vectors. The only strings that can
    // survive deserialization are closed enums; all unknown members refuse.
    protocol::check_value(&raw).map_err(|_| AssessmentError::unavailable())?;
    if !size_within(&raw, RESULT_LIMIT) || !result_shape(&raw) { return Err(AssessmentError::unavailable()); }
    let result: AssessmentResult = serde_json::from_value(raw).map_err(|_| AssessmentError::unavailable())?;
    if !result_valid(&result, expected) { return Err(AssessmentError::unavailable()); }
    Ok(result)
}

pub(crate) async fn assess_supplied(supervisor: &Supervisor, request: AssessmentRequest) -> Result<AssessmentResult, AssessmentError> {
    let expected = request.expected();
    let params = request.into_params()?;
    // Existing original-child owner, 10s + 2s endpoints, two slots/no queue and
    // retained unknown remain untouched. No retry or alternate runtime exists.
    match supervisor.query(Method::AssessCredentials, params).await {
        Ok(raw) => sanitized_result(raw, &expected),
        Err(error) => Err(sanitized_error(error)),
    }
}

#[cfg(test)]
mod tests {
    // Only fictional in-memory DTOs and fixed errors. Never construct/call a
    // Supervisor, runtime, child, file reader, native parser, keyring or service.
    use super::*;
    use serde_json::json;

    const KINDS: [Kind; 8] = [Kind::AndroidKeystore, Kind::AndroidFirebase, Kind::AppleP12, Kind::AppleProfile,
        Kind::AscP8, Kind::IosFirebase, Kind::GoogleWif, Kind::ProjectReadToken];

    fn client(package: Value) -> Value {
        json!({"clientInfo": {"androidClientInfo": {"packageName": package}}})
    }
    fn request(kind: Kind) -> Value {
        let fields = match kind {
            Kind::AndroidKeystore => json!({"storePassword":"fictional-store-password", "keyAlias":"fixture_alias", "keyPassword":"fictional-key-password"}),
            Kind::AppleP12 => json!({"password":"fictional-p12-password"}),
            Kind::AscP8 => json!({"keyId":"FIXTURE123", "issuerId":"12345678-1234-1234-1234-123456789abc"}),
            Kind::GoogleWif => json!({"provider":"projects/123/locations/global/workloadIdentityPools/fixture/providers/fixture", "serviceAccount":"fixture@fixture-project.iam.gserviceaccount.com"}),
            Kind::ProjectReadToken => json!({"token":"fictional-read-token"}),
            _ => json!({}),
        };
        let observation = match kind {
            Kind::AndroidKeystore => json!({"status":"observed", "byteCount":128, "format":"jks", "version":2}),
            Kind::AppleP12 => json!({"status":"observed", "byteCount":128, "format":"pkcs12", "version":3, "authSafe":"data"}),
            Kind::AppleProfile => json!({"status":"observed", "byteCount":128, "format":"cms-signed-data", "encoding":"der"}),
            Kind::AscP8 => json!({"status":"observed", "byteCount":128, "format":"pkcs8", "encoding":"pem", "algorithm":"ec", "curve":"p256"}),
            Kind::AndroidFirebase => json!({"status":"observed", "byteCount":128, "format":"firebase-json", "document":{"root":"object", "clients":[client(json!("org.assessment.fixture"))]}}),
            Kind::IosFirebase => json!({"status":"observed", "byteCount":128, "format":"firebase-plist", "encoding":"xml", "document":{"root":"dictionary", "bundleId":"org.assessment.fixture"}}),
            _ => Value::Null,
        };
        // Deliberately not a valid core config: this adapter must not add a
        // second config/requirement validator. Only the core can accept draft.
        json!({"schemaVersion":1, "policyVersion":POLICY,
            "context":{"draft":{}, "platform":kind.platform(), "stage":"candidate", "purpose":"full"},
            "input":{"kind":kind, "fields":fields, "observation":observation}})
    }
    fn admitted(body: &Value) -> AssessmentRequest {
        match AssessmentRequest::admit(body) { Ok(request) => request, Err(_) => panic!("fictional request should admit") }
    }
    fn roundtrip(body: &Value) -> Value {
        match admitted(body).into_params() { Ok(value) => value, Err(_) => panic!("fictional request should serialize") }
    }
    fn request_error(body: &Value, code: &str) {
        match AssessmentRequest::admit(body) {
            Err(error) => { assert_eq!(error.code, code); assert!(!error.retryable); }
            Ok(_) => panic!("unsupported fictional request admitted"),
        }
    }
    fn set(value: &mut Value, pointer: &str, replacement: Value) {
        match value.pointer_mut(pointer) { Some(slot) => *slot = replacement, None => panic!("fictional JSON pointer is missing") }
    }
    fn remove(value: &mut Value, pointer: &str, key: &str) {
        match value.pointer_mut(pointer).and_then(Value::as_object_mut) {
            Some(object) => { object.remove(key); }
            None => panic!("fictional object is missing"),
        }
    }
    fn check(scope: Scope, outcome: Outcome) -> Value { json!({"scope":scope, "outcome":outcome}) }
    fn response(kind: Kind) -> Value {
        let expected = admitted(&request(kind)).expected();
        let mut fields = Vec::new();
        for (layout, fact) in kind.layout().iter().zip(&expected.fields) {
            let mut state = State::Configured;
            let mut checks = Vec::new();
            match fact {
                FieldExpectation::File(FileFact::Observed(format)) => {
                    checks.push(check(format_scope(*format), Outcome::AssertedPass));
                    if *format == Format::Pkcs8 { checks.push(check(Scope::EcP256Identifiers, Outcome::Passed)); }
                    if kind.firebase() {
                        checks.push(check(Scope::FirebaseShape, Outcome::Passed));
                        checks.push(check(Scope::ApplicationIdentity, Outcome::Passed));
                        state = State::FormatValid;
                    }
                }
                FieldExpectation::Scalar { .. } => {
                    checks.push(check(Scope::ValueAdmission, Outcome::Passed));
                    if layout.role == Role::Identifier { checks.push(check(Scope::IdentifierFormat, Outcome::Passed)); }
                }
                _ => panic!("fictional baseline must be supplied"),
            }
            fields.push(json!({"id":layout.id, "requirement":layout.requirement, "presence":"supplied", "state":state, "issues":[], "checks":checks}));
        }
        json!({"schemaVersion":1, "policyVersion":POLICY, "kind":kind, "context":expected.context,
            "applicability":{"state":"required", "reason":"selected"},
            "state":if kind.firebase() { State::FormatValid } else { State::Configured }, "fields":fields,
            "identity":if kind.firebase() { Identity::Match } else { Identity::NotApplicable },
            "assurance":{"basis":"supplied-input-only", "scalarValuesProcessed":expected.scalar_values_processed,
                "fileObservationsProcessed":expected.file_observations_processed, "selectedFilesRead":false, "keyringAccessed":false,
                "storageWritesPerformed":false, "projectCodeExecuted":false, "sourceCustody":"not-established",
                "nativeValidation":"not-run", "serviceValidation":"not-run", "releaseReadiness":"unknown"}})
    }
    fn accepts(body: &Value, raw: Value) {
        let expected = admitted(body).expected();
        let original = raw.clone();
        match sanitized_result(raw, &expected) {
            Ok(result) => assert_eq!(serde_json::to_value(result).ok(), Some(original)),
            Err(_) => panic!("finite fictional response should admit"),
        }
    }
    fn refuses(body: &Value, raw: Value) {
        let expected = admitted(body).expected();
        match sanitized_result(raw, &expected) {
            Err(error) => {
                assert_eq!(error.code, "assessment_unavailable");
                assert_eq!(error.message, "Credential assessment is unavailable; no credential was verified.");
                assert!(!error.retryable);
            }
            Ok(_) => panic!("unsupported fictional response admitted"),
        }
    }

    #[test]
    fn all_eight_request_unions_roundtrip_without_native_authority() {
        for kind in KINDS {
            let body = request(kind);
            assert_eq!(roundtrip(&body), body);
            accepts(&body, response(kind));
        }
    }

    #[test]
    fn mandatory_nullable_fields_and_unknown_members_refuse() {
        for kind in KINDS {
            let body = request(kind);
            for pointer in ["", "/context", "/input", "/input/fields"] {
                let keys: Vec<String> = match body.pointer(pointer).and_then(Value::as_object) {
                    Some(object) => object.keys().cloned().collect(), None => panic!("fictional object missing"),
                };
                for key in keys {
                    let mut incomplete = body.clone(); remove(&mut incomplete, pointer, &key);
                    request_error(&incomplete, "assessment_invalid_request");
                }
                let mut extra = body.clone();
                match extra.pointer_mut(pointer).and_then(Value::as_object_mut) {
                    Some(object) => { object.insert("fictional-private-extra".into(), json!("fictional-private-value")); }
                    None => panic!("fictional object missing"),
                }
                request_error(&extra, "assessment_invalid_request");
            }
            let mut missing = body.clone();
            if let Some(fields) = missing["input"]["fields"].as_object_mut() {
                for value in fields.values_mut() { *value = Value::Null; }
            }
            missing["input"]["observation"] = Value::Null;
            assert_eq!(roundtrip(&missing), missing);
        }
    }

    #[test]
    fn schema_policy_and_context_types_are_exact() {
        for bad in [Value::Null, json!(true), json!(1), json!(""), json!("é"), json!("bad token"), json!("a\0b"), json!("x".repeat(65))] {
            let mut body = request(Kind::AppleP12); body["policyVersion"] = bad;
            request_error(&body, "assessment_invalid_request");
        }
        for stale in ["credential-policy-v2".to_owned(), "x".repeat(64)] {
            let mut body = request(Kind::AppleP12); body["policyVersion"] = json!(stale);
            request_error(&body, "assessment_policy_stale");
        }
        for version in [json!(-1), json!(0), json!(2)] {
            let mut body = request(Kind::AppleP12); body["schemaVersion"] = version;
            request_error(&body, "assessment_version");
        }
        for bad in [json!(true), json!(1.0), json!("1"), Value::Null] {
            let mut body = request(Kind::AppleP12); body["schemaVersion"] = bad;
            request_error(&body, "assessment_invalid_request");
        }
        for (pointer, bad) in [("/context/platform", json!({"ios":null})), ("/context/stage", json!("all")),
            ("/context/purpose", json!([])), ("/context/draft", json!([])), ("/input/kind", json!({"apple-p12":null}))] {
            let mut body = request(Kind::AppleP12); set(&mut body, pointer, bad);
            request_error(&body, "assessment_invalid_request");
        }
    }

    #[test]
    fn observations_preserve_null_slots_order_and_complete_projection() {
        let mut body = request(Kind::AndroidFirebase);
        body["input"]["observation"]["document"]["clients"] = json!([
            client(json!("org.assessment.fixture")), null, {"clientInfo":null},
            {"clientInfo":{"androidClientInfo":null}}, client(Value::Null), client(json!("")), client(json!("org.assessment.fixture")),
        ]);
        assert_eq!(roundtrip(&body), body); // No filtering, sorting, deduplication or policy decision.
        for projection in [json!({"root":"object", "clients":null}), json!({"root":"object", "clients":[]}), json!({"root":"other", "clients":null})] {
            body["input"]["observation"]["document"] = projection;
            assert_eq!(roundtrip(&body), body);
        }
        for encoding in ["xml", "binary"] {
            let mut body = request(Kind::IosFirebase);
            body["input"]["observation"]["encoding"] = json!(encoding);
            for name in [Value::Null, json!(""), json!("org.assessment.fixture")] {
                body["input"]["observation"]["document"]["bundleId"] = name;
                assert_eq!(roundtrip(&body), body);
            }
        }
    }

    #[test]
    fn observed_unions_disallow_cross_kind_or_contradictory_tags() {
        let mut body = request(Kind::AppleP12);
        body["input"]["observation"] = request(Kind::AndroidKeystore)["input"]["observation"].clone();
        request_error(&body, "assessment_invalid_request");
        for kind in [Kind::GoogleWif, Kind::ProjectReadToken] {
            let mut body = request(kind); body["input"]["observation"] = json!({"status":"unavailable", "reason":"not-run"});
            request_error(&body, "assessment_invalid_request");
        }
        for bad in [json!(true), json!(1.0), json!(0), json!(3)] {
            let mut body = request(Kind::AndroidKeystore); body["input"]["observation"]["version"] = bad;
            request_error(&body, "assessment_invalid_request");
        }
        for algorithm in ["rsa", "other"] {
            let mut body = request(Kind::AscP8); body["input"]["observation"]["algorithm"] = json!(algorithm);
            request_error(&body, "assessment_invalid_request");
            body["input"]["observation"]["curve"] = Value::Null;
            assert_eq!(roundtrip(&body), body);
        }
        for bad in [json!({"root":"other", "clients":[]}), json!({"root":"object", "clients":[{"clientInfo":{}}]}),
            json!({"root":"object", "clients":[client(json!(true))]}), json!({"root":"object", "clients":[], "allClientsValid":true})] {
            let mut body = request(Kind::AndroidFirebase); body["input"]["observation"]["document"] = bad;
            request_error(&body, "assessment_invalid_request");
        }
        for bad in [json!({"status":"unavailable", "reason":"empty-file"}), json!({"status":"rejected", "reason":"incomplete"}),
            json!({"status":"unavailable", "reason":"not-run", "filename":"fictional-private-name"})] {
            let mut body = request(Kind::AppleProfile); body["input"]["observation"] = bad;
            request_error(&body, "assessment_invalid_request");
        }
    }

    #[test]
    fn scalar_utf8_and_wire_material_bounds_are_enforced() {
        for value in ["x".repeat(SCALAR_LIMIT), "é".repeat(SCALAR_LIMIT / 2), "  ".into(), "fictional\0value".into(), String::new()] {
            let mut body = request(Kind::ProjectReadToken); body["input"]["fields"]["token"] = json!(value);
            assert_eq!(roundtrip(&body), body);
        }
        for value in ["x".repeat(SCALAR_LIMIT + 1), "é".repeat(SCALAR_LIMIT / 2 + 1)] {
            let mut body = request(Kind::ProjectReadToken); body["input"]["fields"]["token"] = json!(value);
            request_error(&body, "assessment_limit");
        }
        let mut total = SCALARS_LIMIT;
        assert!(scalar(&json!("x"), &mut total).is_err());
        for kind in KINDS.into_iter().filter(|kind| kind.has_file()) {
            let mut body = request(kind);
            for count in [1, kind.material_limit()] {
                body["input"]["observation"]["byteCount"] = json!(count);
                assert_eq!(roundtrip(&body), body);
            }
            body["input"]["observation"]["byteCount"] = json!(kind.material_limit() + 1);
            request_error(&body, "assessment_limit");
            for bad in [json!(true), json!(1.0), json!(0), json!(-1), json!("128")] {
                body["input"]["observation"]["byteCount"] = bad;
                request_error(&body, "assessment_invalid_request");
            }
        }
    }

    #[test]
    fn observation_serialized_bounds_include_escaping() {
        let mut body = request(Kind::AndroidFirebase);
        body["input"]["observation"]["document"]["clients"] = json!(vec![client(json!("org.assessment.fixture")); CLIENT_LIMIT]);
        assert_eq!(roundtrip(&body), body);
        body["input"]["observation"]["document"]["clients"] = json!(vec![client(json!("org.assessment.fixture")); CLIENT_LIMIT + 1]);
        request_error(&body, "assessment_limit");
        body["input"]["observation"]["document"]["clients"] = json!([client(json!("é".repeat(512)))]);
        assert_eq!(roundtrip(&body), body);
        body["input"]["observation"]["document"]["clients"] = json!([client(json!("é".repeat(513)))]);
        request_error(&body, "assessment_limit");
        body["input"]["observation"]["document"]["clients"] = json!(vec![client(json!("\0".repeat(1024))); 12]);
        assert!(!size_within(&body["input"]["observation"], OBSERVATION_LIMIT));
        request_error(&body, "assessment_limit");
    }

    #[test]
    fn draft_and_envelope_depth_nodes_remain_bounded() {
        let mut body = request(Kind::ProjectReadToken);
        body["context"]["draft"] = json!({"oversized":"x".repeat(DRAFT_LIMIT)});
        request_error(&body, "assessment_limit");
        let mut deep = Value::Null;
        for _ in 0..protocol::DEPTH_LIMIT { deep = Value::Array(vec![deep]); }
        body["context"]["draft"] = json!({"deep":deep});
        request_error(&body, "assessment_limit");
        body["context"]["draft"] = json!({"many":vec![Value::Null; protocol::NODE_LIMIT]});
        request_error(&body, "assessment_limit");
        let mut value = Value::Null;
        for _ in 0..OBSERVATION_DEPTH { value = Value::Array(vec![value]); }
        assert!(json_bounds(&value, OBSERVATION_NODES, OBSERVATION_DEPTH));
        value = Value::Array(vec![value]);
        assert!(!json_bounds(&value, OBSERVATION_NODES, OBSERVATION_DEPTH));
        assert!(json_bounds(&json!({"a":null}), 3, 1));
        assert!(!json_bounds(&json!({"a":null}), 2, 1));
    }

    #[test]
    fn result_is_rebuilt_as_only_closed_secret_free_data() {
        for kind in KINDS {
            let body = request(kind);
            let raw = response(kind);
            accepts(&body, raw.clone());
            let serialized = serde_json::to_string(&raw).unwrap_or_default();
            for private in ["fictional-store-password", "fictional-read-token", "FIXTURE123", "org.assessment.fixture", "byteCount", "draft"] {
                assert!(!serialized.contains(private));
            }
            assert!(serialized.len() <= RESULT_LIMIT);
        }
    }

    #[test]
    fn result_unknown_keys_wrong_types_and_unit_enum_objects_refuse() {
        let body = request(Kind::AndroidKeystore);
        for pointer in ["", "/context", "/applicability", "/fields/0", "/fields/0/checks/0", "/assurance"] {
            let mut raw = response(Kind::AndroidKeystore);
            match raw.pointer_mut(pointer).and_then(Value::as_object_mut) {
                Some(object) => { object.insert("fictional-private-extra".into(), json!("fictional-private-value")); }
                None => panic!("fictional object missing"),
            }
            refuses(&body, raw);
        }
        for (pointer, value) in [
            ("/schemaVersion", json!(true)), ("/schemaVersion", json!(1.0)), ("/kind", json!({"android-keystore":null})),
            ("/context/platform", json!({"android":null})), ("/fields/0/id", json!({"file":null})),
            ("/fields/0/issues", json!([{"required-missing":null}])), ("/fields/0/checks/0/outcome", json!({"asserted-pass":null})),
            ("/assurance/basis", json!({"supplied-input-only":null})), ("/assurance/selectedFilesRead", json!(0)),
        ] {
            let mut raw = response(Kind::AndroidKeystore); set(&mut raw, pointer, value); refuses(&body, raw);
        }
        for key in ["schemaVersion", "policyVersion", "kind", "context", "applicability", "state", "fields", "identity", "assurance"] {
            let mut raw = response(Kind::AndroidKeystore); remove(&mut raw, "", key); refuses(&body, raw);
        }
    }

    #[test]
    fn result_kind_context_version_and_fixed_field_order_must_match() {
        let body = request(Kind::AndroidKeystore);
        for (pointer, value) in [("/schemaVersion", json!(2)), ("/policyVersion", json!("credential-policy-v2")),
            ("/kind", json!("apple-p12")), ("/context/platform", json!("ios")), ("/context/stage", json!("production")),
            ("/context/purpose", json!("store")), ("/fields/0/id", json!("password")),
            ("/fields/0/requirement", json!("MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64"))] {
            let mut raw = response(Kind::AndroidKeystore); set(&mut raw, pointer, value); refuses(&body, raw);
        }
        let mut raw = response(Kind::AndroidKeystore);
        if let Some(fields) = raw["fields"].as_array_mut() { fields.swap(1, 2); }
        refuses(&body, raw);
        let mut raw = response(Kind::AndroidKeystore);
        if let Some(fields) = raw["fields"].as_array_mut() { fields.pop(); }
        refuses(&body, raw);
    }

    #[test]
    fn result_presence_assurance_and_no_native_claims_must_match() {
        let body = request(Kind::AndroidKeystore);
        for (pointer, value) in [("/fields/0/presence", json!("missing")), ("/assurance/scalarValuesProcessed", json!(false)),
            ("/assurance/fileObservationsProcessed", json!(false)), ("/assurance/selectedFilesRead", json!(true)),
            ("/assurance/keyringAccessed", json!(true)), ("/assurance/storageWritesPerformed", json!(true)),
            ("/assurance/projectCodeExecuted", json!(true)), ("/assurance/sourceCustody", json!("established")),
            ("/assurance/nativeValidation", json!("passed")), ("/assurance/serviceValidation", json!("passed")),
            ("/assurance/releaseReadiness", json!("ready"))] {
            let mut raw = response(Kind::AndroidKeystore); set(&mut raw, pointer, value); refuses(&body, raw);
        }
        let mut body = request(Kind::ProjectReadToken); body["input"]["fields"]["token"] = json!("");
        let expected = admitted(&body).expected();
        assert!(expected.scalar_values_processed);
        assert!(expected.fields[0].presence() == Presence::Missing);
    }

    #[test]
    fn missing_invalid_companions_do_not_invalidate_recognized_files() {
        let mut body = request(Kind::AppleP12); body["input"]["fields"]["password"] = Value::Null;
        let mut raw = response(Kind::AppleP12);
        raw["state"] = json!("missing"); raw["assurance"]["scalarValuesProcessed"] = json!(false);
        raw["fields"][1]["presence"] = json!("missing"); raw["fields"][1]["state"] = json!("missing");
        raw["fields"][1]["issues"] = json!(["required-missing"]); raw["fields"][1]["checks"] = json!([]);
        accepts(&body, raw.clone());
        let mut file_failure = raw.clone(); file_failure["fields"][0]["state"] = json!("invalid");
        refuses(&body, file_failure);
        body["input"]["fields"]["password"] = json!("fictional\0password");
        raw["state"] = json!("invalid"); raw["assurance"]["scalarValuesProcessed"] = json!(true);
        raw["fields"][1]["presence"] = json!("supplied"); raw["fields"][1]["state"] = json!("invalid");
        raw["fields"][1]["issues"] = json!(["value-nul"]);
        raw["fields"][1]["checks"] = json!([check(Scope::ValueAdmission, Outcome::Failed)]);
        accepts(&body, raw.clone());
        raw["fields"][1]["issues"] = json!(["scalar-format"]);
        refuses(&body, raw); // A password is never an identifier or failed password-verification claim.
    }

    #[test]
    fn unknown_and_missing_remain_distinct_under_aggregate_precedence() {
        let mut body = request(Kind::AndroidKeystore);
        body["input"]["observation"] = json!({"status":"unavailable", "reason":"incomplete"});
        body["input"]["fields"]["storePassword"] = Value::Null;
        let mut raw = response(Kind::AndroidKeystore);
        raw["state"] = json!("missing");
        raw["fields"][0]["state"] = json!("unknown"); raw["fields"][0]["issues"] = json!(["incomplete"]); raw["fields"][0]["checks"] = json!([]);
        raw["fields"][1]["presence"] = json!("missing"); raw["fields"][1]["state"] = json!("missing");
        raw["fields"][1]["issues"] = json!(["required-missing"]); raw["fields"][1]["checks"] = json!([]);
        accepts(&body, raw.clone());
        let mut wrong = raw.clone(); wrong["state"] = json!("invalid"); refuses(&body, wrong);
        body["input"]["fields"]["keyAlias"] = json!("fictional invalid alias");
        raw["state"] = json!("invalid"); raw["fields"][2]["state"] = json!("invalid");
        raw["fields"][2]["issues"] = json!(["scalar-format"]);
        raw["fields"][2]["checks"] = json!([check(Scope::ValueAdmission, Outcome::Passed), check(Scope::IdentifierFormat, Outcome::Failed)]);
        accepts(&body, raw.clone());
        raw["fields"][0]["state"] = json!("invalid"); refuses(&body, raw);
    }

    #[test]
    fn asserted_scopes_cannot_be_upgraded_to_actual_native_checks() {
        for kind in KINDS.into_iter().filter(|kind| kind.has_file()) {
            let body = request(kind);
            let mut raw = response(kind); raw["fields"][0]["checks"][0]["outcome"] = json!("passed");
            refuses(&body, raw);
            let mut raw = response(kind);
            let first = raw["fields"][0]["checks"][0].clone();
            if let Some(checks) = raw["fields"][0]["checks"].as_array_mut() { checks.push(first); }
            refuses(&body, raw);
            let mut body = request(kind); body["input"]["observation"] = json!({"status":"rejected", "reason":"empty-file"});
            let mut raw = response(kind); raw["state"] = json!("invalid"); raw["fields"][0]["state"] = json!("invalid");
            raw["fields"][0]["issues"] = json!(["empty-file"]); raw["fields"][0]["checks"] = json!([check(Scope::FileNonempty, Outcome::AssertedFail)]);
            raw["identity"] = json!(if kind.firebase() { Identity::NotAssessed } else { Identity::NotApplicable });
            accepts(&body, raw.clone());
            raw["fields"][0]["checks"][0]["outcome"] = json!("failed"); refuses(&body, raw);
        }
    }

    #[test]
    fn firebase_shape_identity_and_aggregate_are_consistent() {
        for kind in [Kind::AndroidFirebase, Kind::IosFirebase] {
            let body = request(kind);
            let mut mismatch = response(kind);
            mismatch["state"] = json!("invalid"); mismatch["fields"][0]["state"] = json!("invalid");
            mismatch["fields"][0]["issues"] = json!(["identity-mismatch"]); mismatch["identity"] = json!("mismatch");
            mismatch["fields"][0]["checks"][2]["outcome"] = json!("failed");
            accepts(&body, mismatch.clone()); // Rust validates scope coherence, not a second Firebase policy.
            mismatch["identity"] = json!("match"); refuses(&body, mismatch);
            let mut malformed = response(kind);
            malformed["state"] = json!("invalid"); malformed["fields"][0]["state"] = json!("invalid");
            malformed["fields"][0]["issues"] = json!(["firebase-shape"]); malformed["identity"] = json!("not-assessed");
            if let Some(checks) = malformed["fields"][0]["checks"].as_array_mut() { checks.pop(); }
            malformed["fields"][0]["checks"][1]["outcome"] = json!("failed");
            accepts(&body, malformed.clone());
            malformed["identity"] = json!("mismatch"); refuses(&body, malformed);
            let mut wrong_order = response(kind);
            if let Some(checks) = wrong_order["fields"][0]["checks"].as_array_mut() { checks.swap(1, 2); }
            refuses(&body, wrong_order);
        }
    }

    #[test]
    fn nonfirebase_cannot_claim_format_valid_or_application_identity() {
        for kind in [Kind::AndroidKeystore, Kind::AppleP12, Kind::AppleProfile, Kind::AscP8, Kind::GoogleWif, Kind::ProjectReadToken] {
            let body = request(kind);
            let mut raw = response(kind); raw["state"] = json!("format-valid"); refuses(&body, raw);
            let mut raw = response(kind); raw["identity"] = json!("match"); refuses(&body, raw);
            let mut raw = response(kind); raw["fields"][0]["state"] = json!("format-valid"); refuses(&body, raw);
        }
    }

    #[test]
    fn pkcs8_policy_scopes_and_companion_outcomes_are_independent() {
        let mut body = request(Kind::AscP8); body["input"]["fields"]["keyId"] = Value::Null;
        let mut raw = response(Kind::AscP8); raw["state"] = json!("missing");
        raw["fields"][1]["presence"] = json!("missing"); raw["fields"][1]["state"] = json!("missing");
        raw["fields"][1]["issues"] = json!(["required-missing"]); raw["fields"][1]["checks"] = json!([]);
        accepts(&body, raw.clone());
        body["input"]["observation"]["curve"] = json!("other");
        raw["state"] = json!("invalid"); raw["fields"][0]["state"] = json!("invalid");
        raw["fields"][0]["issues"] = json!(["pkcs8-algorithm"]); raw["fields"][0]["checks"][1]["outcome"] = json!("failed");
        accepts(&body, raw.clone());
        raw["fields"][0]["checks"][1]["outcome"] = json!("asserted-fail"); refuses(&body, raw);
    }

    #[test]
    fn not_applicable_has_no_completed_checks_and_correct_context_reason() {
        let mut body = request(Kind::AndroidKeystore); body["context"]["platform"] = json!("ios");
        let mut raw = response(Kind::AndroidKeystore); raw["context"]["platform"] = json!("ios");
        raw["applicability"] = json!({"state":"not-applicable", "reason":"wrong-platform"}); raw["state"] = json!("not-applicable");
        if let Some(fields) = raw["fields"].as_array_mut() {
            for field in fields { field["state"] = json!("not-applicable"); field["issues"] = json!([]); field["checks"] = json!([]); }
        }
        accepts(&body, raw.clone());
        raw["applicability"]["reason"] = json!("platform-disabled"); refuses(&body, raw);
        let body = request(Kind::ProjectReadToken);
        let mut raw = response(Kind::ProjectReadToken);
        raw["applicability"] = json!({"state":"not-applicable", "reason":"not-required"}); raw["state"] = json!("not-applicable");
        raw["fields"][0]["state"] = json!("not-applicable"); raw["fields"][0]["checks"] = json!([]);
        accepts(&body, raw.clone());
        raw["applicability"]["reason"] = json!("platform-disabled"); refuses(&body, raw);
    }

    #[test]
    fn refusal_mapping_discards_every_engine_message_and_unknown_code() {
        for kind in [ErrorKind::InvalidRequest, ErrorKind::Limit, ErrorKind::Version, ErrorKind::PolicyStale, ErrorKind::ContextInvalid,
            ErrorKind::Unavailable, ErrorKind::Busy, ErrorKind::ShuttingDown, ErrorKind::QueryTimeout, ErrorKind::CleanupUnknown] {
            let expected = AssessmentError::new(kind);
            let actual = sanitized_error(BridgeError::new(expected.code, "fictional-private-message"));
            assert_eq!(actual.code, expected.code); assert_eq!(actual.message, expected.message); assert!(!actual.retryable);
            assert!(!serde_json::to_string(&actual).unwrap_or_default().contains("fictional-private"));
        }
        for code in ["invalid_request", "protocol_error", "runtime_unavailable", "fictional-private-code", "assessment_context_stale"] {
            let error = sanitized_error(BridgeError::new(code, "fictional-private-message"));
            assert_eq!(error.code, "assessment_unavailable");
            assert_eq!(error.message, "Credential assessment is unavailable; no credential was verified.");
        }
        let error = sanitized_error(BridgeError { code: "assessment_limit".into(), message: "fictional-private-message".into(), retryable: true });
        assert_eq!(error.code, "assessment_unavailable");
    }

    #[test]
    fn native_stale_is_fixed_and_not_accepted_from_core() {
        let stale = AssessmentError::context_stale();
        assert_eq!(stale.code, "assessment_context_stale");
        assert_eq!(stale.message, "Assessment context changed; prepare again.");
        assert!(!stale.retryable);
        assert_eq!(sanitized_error(BridgeError::new(stale.code, stale.message)).code, "assessment_unavailable");
        let body = request(Kind::ProjectReadToken);
        let mut raw = response(Kind::ProjectReadToken); raw["state"] = json!("stale"); refuses(&body, raw);
    }

    #[test]
    fn result_dedicated_limit_never_forwards_partial_or_raw_values() {
        let body = request(Kind::ProjectReadToken);
        let mut raw = response(Kind::ProjectReadToken); raw["fictional-private"] = json!("x".repeat(RESULT_LIMIT));
        assert!(!size_within(&raw, RESULT_LIMIT)); refuses(&body, raw);
        refuses(&body, json!({"value":"fictional-private-password"}));
        refuses(&body, json!("fictional-private-password"));
        let mut raw = response(Kind::ProjectReadToken); raw["fields"][0]["issues"] = json!(["required-missing", "value-nul"]);
        refuses(&body, raw);
    }
}
