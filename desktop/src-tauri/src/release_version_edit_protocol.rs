//! Fourth fixed edit DATA profile. The shared core owns grammar/policy and
//! original filesystem custody; these bounded DTOs grant neither.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use crate::{edit_protocol::{self as edit, bounded, token, Capability, ChildFrame,
    CoreEditOutcome, CoreReason, Effect, Journal, NativeEditReason, NativeFinality, Phase, ResourceState},
    error::BridgeError, github_workflow_edit_protocol::{value_bounds, RegisteredIdentity},
    protocol::{check_value, strict_json}, release_version_protocol::relative_display_path};

pub const PROTOCOL: &str = "mrk-release-version/1";
pub const DOMAIN: &str = "release_version";
pub const EVENT: &str = "release-version-edit-status";
pub const REQUEST_LIMIT: usize = 16 * 1024;
pub const OPENED_LIMIT: usize = 512 * 1024;
pub const VIEW_LIMIT: usize = 1024 * 1024;
pub const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
pub const STATUS_LIMIT: usize = 2 * 1024 * 1024;
pub const TEXT_LIMIT: usize = 64 * 1024;

fn keys(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|v| v.len() == names.len() && names.iter().all(|name| v.contains_key(*name)))
}
fn hex(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn key(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.as_bytes()[0].is_ascii_uppercase()
        && value.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}
fn selection(source: &str, name_key: &str, build_key: &str) -> bool {
    relative_display_path(source) && !source.eq_ignore_ascii_case("release/mobile-release.json")
        && key(name_key) && key(build_key) && name_key != build_key
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Values { pub name: String, pub build: String }
impl Values {
    pub(crate) fn proposed(&self) -> bool {
        !self.name.is_empty() && self.name.len() <= 64 && self.name.is_ascii()
            && !self.build.is_empty() && self.build.len() <= 10 && self.build.bytes().all(|b| b.is_ascii_digit())
    }
    fn original(&self) -> bool {
        [&self.name, &self.build].into_iter().all(|s| !s.is_empty() && s.len() <= TEXT_LIMIT
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.+-".contains(&b)))
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Intent { Edit, Create }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContentDigest { pub bytes: u32, pub sha256: String }
impl ContentDigest {
    fn valid(&self, maximum: usize) -> bool { self.bytes > 0 && self.bytes as usize <= maximum && hex(&self.sha256) }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
pub enum BaselineFile { Absent {}, Present { bytes: u32, sha256: String } }
impl BaselineFile {
    fn valid(&self) -> bool { match self {
        Self::Absent {} => true,
        Self::Present { bytes, sha256 } => *bytes > 0 && *bytes as usize <= TEXT_LIMIT && hex(sha256),
    } }
    pub(crate) fn intent(&self) -> Intent { if matches!(self, Self::Absent {}) { Intent::Create } else { Intent::Edit } }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Baseline { pub saved_config: ContentDigest, pub saved_version: BaselineFile }
impl Baseline {
    pub(crate) fn valid(&self) -> bool { self.saved_config.valid(512 * 1024) && self.saved_version.valid() }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextContent { pub text: String, pub bytes: u32, pub sha256: String }
impl TextContent {
    fn valid(&self) -> bool { !self.text.is_empty() && self.text.len() <= TEXT_LIMIT && self.text.len() == self.bytes as usize
        && hex(&self.sha256) && digest(self.text.as_bytes()) == self.sha256 }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
pub enum Before { Absent {}, Present { text: String, bytes: u32, sha256: String } }
impl Before {
    fn text(&self) -> &str { match self { Self::Absent {} => "", Self::Present { text, .. } => text } }
    fn valid(&self) -> bool { match self {
        Self::Absent {} => true,
        Self::Present { text, bytes, sha256 } => !text.is_empty() && text.len() <= TEXT_LIMIT && text.len() == *bytes as usize
            && hex(sha256) && digest(text.as_bytes()) == *sha256,
    } }
    fn baseline(&self) -> BaselineFile { match self {
        Self::Absent {} => BaselineFile::Absent {},
        Self::Present { bytes, sha256, .. } => BaselineFile::Present { bytes: *bytes, sha256: sha256.clone() },
    } }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action { Create, Replace, Preserve }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileView {
    pub path: String, pub action: Action, pub before: Before, pub after: TextContent,
    pub requested_mode: u32, pub preserve_mode: bool,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LineStyle { Crlf, Lf, Cr, Vt, Ff, Fs, Gs, Rs, Nel, Ls, Ps }
fn line_styles(text: &str) -> Vec<LineStyle> {
    let mut rest = text.to_owned();
    let mut styles = Vec::new();
    for (separator, style) in [("\r\n", LineStyle::Crlf), ("\n", LineStyle::Lf), ("\r", LineStyle::Cr),
        ("\u{b}", LineStyle::Vt), ("\u{c}", LineStyle::Ff), ("\u{1c}", LineStyle::Fs),
        ("\u{1d}", LineStyle::Gs), ("\u{1e}", LineStyle::Rs), ("\u{85}", LineStyle::Nel),
        ("\u{2028}", LineStyle::Ls), ("\u{2029}", LineStyle::Ps)] {
        if rest.contains(separator) { styles.push(style); rest = rest.replace(separator, ""); }
    }
    styles
}
fn final_newline(text: &str) -> bool {
    text.ends_with(['\r', '\n', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}', '\u{2029}'])
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LineEndings {
    pub before: Vec<LineStyle>, pub after: Vec<LineStyle>, pub final_newline_before: bool,
    pub final_newline_after: bool, pub preserved: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validation { pub valid: bool, pub state: String, pub issues: Vec<Value> }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedView {
    pub schema_version: u32, pub source: String, pub name_key: String, pub build_key: String, pub ios_enabled: bool,
    pub intent: Intent, pub values: Values, pub file: FileView, pub create_directories: Vec<String>,
    pub line_endings: LineEndings, pub validation: Validation,
}
impl PreparedView {
    fn valid(&self) -> bool {
        if self.schema_version != 1 || !selection(&self.source, &self.name_key, &self.build_key)
            || !self.values.proposed() || self.file.path != self.source || !self.file.before.valid() || !self.file.after.valid()
            || bounded(self, VIEW_LIMIT).is_err() || !self.validation.valid || self.validation.state != "format-valid"
            || !self.validation.issues.is_empty() || self.file.requested_mode > 0o777
            || self.line_endings.before != line_styles(self.file.before.text()) || self.line_endings.after != line_styles(&self.file.after.text)
            || self.line_endings.final_newline_before != final_newline(self.file.before.text())
            || self.line_endings.final_newline_after != final_newline(&self.file.after.text) { return false; }
        match &self.file.before {
            Before::Absent {} => {
                if self.intent != Intent::Create || self.file.action != Action::Create || self.file.preserve_mode
                    || self.file.requested_mode != 0o644 || self.line_endings.preserved
                    || self.file.after.text != format!("{}={}\n{}={}\n", self.name_key, self.values.name, self.build_key, self.values.build) { return false; }
            },
            Before::Present { text, .. } => {
                let action = if *text == self.file.after.text { Action::Preserve } else { Action::Replace };
                if self.intent != Intent::Edit || self.file.action != action || !self.file.preserve_mode || !self.line_endings.preserved
                    || self.line_endings.before != self.line_endings.after
                    || self.line_endings.final_newline_before != self.line_endings.final_newline_after
                    || !self.create_directories.is_empty() { return false; }
            },
        }
        let mut ancestors = Vec::new();
        if let Some((parent, _)) = self.source.rsplit_once('/') {
            let mut current = String::new();
            for part in parent.split('/') {
                if !current.is_empty() { current.push('/'); }
                current.push_str(part); ancestors.push(current.clone());
            }
        }
        self.create_directories.len() <= ancestors.len()
            && self.create_directories.as_slice() == &ancestors[ancestors.len().saturating_sub(self.create_directories.len())..]
    }
    pub(crate) fn matches_checkout(&self, checkout: &Checkout) -> bool {
        self.source == checkout.source && self.name_key == checkout.name_key && self.build_key == checkout.build_key
            && self.ios_enabled == checkout.ios_enabled && self.file.before.baseline() == checkout.baseline.saved_version
            && self.intent == checkout.baseline.saved_version.intent()
    }
}
#[derive(Clone)]
pub(crate) struct Submission { pub(crate) expected_baseline: Baseline, pub(crate) intent: Intent, pub(crate) values: Values }
impl Submission {
    pub(crate) fn valid(&self) -> bool { self.expected_baseline.valid() && self.values.proposed() && self.intent == self.expected_baseline.saved_version.intent() }
    pub(crate) fn matches(&self, checkout: &Checkout, view: &PreparedView) -> bool {
        self.expected_baseline == checkout.baseline && self.intent == view.intent && self.values == view.values
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkout {
    pub revision: String, pub source: String, pub name_key: String, pub build_key: String, pub ios_enabled: bool,
    pub values: Option<Values>, pub baseline: Baseline,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Prepared { pub revision: String, pub plan_token: String, pub draft_revision: u32, pub baseline_generation: u32, pub view: PreparedView }
#[derive(Clone, Default)]
pub(crate) struct Details { pub(crate) checkout: Option<Checkout>, pub(crate) prepared: Option<Prepared>, pub(crate) submission: Option<Submission> }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Projection {
    pub domain: &'static str, pub project_id: String, pub session_id: String, pub owner_generation: String,
    pub phase: Phase, pub review_remaining_ms: u32, pub checkout: Option<Checkout>, pub prepared: Option<Prepared>,
    pub apply_submitted: bool, pub core_outcome: Option<CoreEditOutcome>, pub native_reason: NativeEditReason,
    pub native_finality: NativeFinality, pub late_settled: bool,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseVersionEditStatus {
    pub schema_version: u32, pub domain: &'static str, pub window_generation: String, pub status_revision: u32,
    pub capability: Capability, pub active: Option<Projection>, pub last_terminal: Option<Projection>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareReleaseVersionEdit {
    pub session_id: String, pub revision: String, pub expected_baseline: Baseline, pub intent: Intent, pub values: Values,
    pub draft_revision: u32, pub baseline_generation: u32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Opened {
    pub revision: String, pub source: String, pub name_key: String, pub build_key: String, pub ios_enabled: bool,
    pub values: Option<Values>, pub baseline: Baseline, pub scope_resources: ResourceState,
}
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
struct PrivateOpen { root: String, registered_identity: RegisteredIdentity }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivatePrepare { revision: String, expected_baseline: Baseline, intent: Intent, values: Values }
pub(crate) fn request(session: &str, seq: u32, op: &str, params: Value) -> Result<Vec<u8>, BridgeError> {
    if !token(session) || seq > 2 { return Err(BridgeError::invalid()); }
    value_bounds(&params, 16, REQUEST_LIMIT)?;
    let legal = match (seq, op) {
        (0, "open") => PrivateOpen::deserialize(&params).is_ok_and(|p| p.root.len() > 1 && p.root.len() <= 4096
            && !p.root.contains('\0') && p.registered_identity.valid()),
        (1, "prepare") => PrivatePrepare::deserialize(&params).is_ok_and(|p| token(&p.revision)
            && p.expected_baseline.valid() && p.intent == p.expected_baseline.saved_version.intent() && p.values.proposed()),
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
        Some("opened") if seq == 0 => {
            // Option fields must be explicitly present, including null absence.
            if !keys(raw, &["revision","source","nameKey","buildKey","iosEnabled","values","baseline","scopeResources"]) { return Err(BridgeError::protocol()); }
            let result = Opened::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || !selection(&result.source, &result.name_key, &result.build_key) || !result.baseline.valid()
                || bounded(raw, OPENED_LIMIT).is_err() || result.scope_resources != ResourceState::Settled
                || !match (&result.values, &result.baseline.saved_version) {
                    (None, BaselineFile::Absent {}) => true,
                    (Some(values), BaselineFile::Present { bytes, .. }) => values.original() && values.name.len() + values.build.len() < *bytes as usize,
                    _ => false,
                } { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::ReleaseVersionOpened(result))
        },
        Some("prepared") if seq == 1 => {
            let result = PreparedReply::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || !token(&result.plan_token) || result.revision == result.plan_token
                || result.scope_resources != ResourceState::Settled || !result.view.valid() { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::ReleaseVersionPrepared(result))
        },
        Some("terminal") if bytes.len() <= edit::TERMINAL_LIMIT => {
            if !keys(raw, &["kind","planToken","effect","journal","resources","reason"]) { return Err(BridgeError::protocol()); }
            let result = TerminalReply::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if !result.outcome().valid() || result.plan_token.as_deref().is_some_and(|s| !token(s)) { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::ReleaseVersionTerminal(seq, result))
        },
        _ => Err(BridgeError::protocol()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REVISION: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const PLAN: &str = "cccccccccccccccccccccccccccccccc";
    const ORIGINAL: &str = "VERSION_NAME='1.2'\r\nBUILD_NUMBER=\"7\"\n# Keep café";
    fn frame(seq: u32, kind: &str, result: Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&json!({"protocol":PROTOCOL,"session":SESSION,"seq":seq,"kind":kind,"result":result})).unwrap();
        bytes.push(b'\n'); bytes
    }
    fn baseline(present: bool) -> Value {
        json!({"savedConfig":{"bytes":2,"sha256":digest(b"{}")},"savedVersion":if present {
            json!({"state":"present","bytes":ORIGINAL.len(),"sha256":digest(ORIGINAL.as_bytes())})
        } else { json!({"state":"absent"}) }})
    }
    fn opened(present: bool) -> Value {
        json!({"revision":REVISION,"source":"public/nested/version.properties","nameKey":"VERSION_NAME","buildKey":"BUILD_NUMBER","iosEnabled":true,
            "values":if present { json!({"name":"1.2","build":"7"}) } else { Value::Null },
            "baseline":baseline(present),"scopeResources":"settled"})
    }
    fn view(action: &str) -> Value {
        let create = action == "create";
        let (after, name, build) = if create { ("VERSION_NAME=1.3\nBUILD_NUMBER=8\n", "1.3", "8") }
            else if action == "preserve" { (ORIGINAL, "1.2", "7") }
            else { ("VERSION_NAME='1.3'\r\nBUILD_NUMBER=\"8\"\n# Keep café", "1.3", "8") };
        json!({"schemaVersion":1,"source":"public/nested/version.properties","nameKey":"VERSION_NAME","buildKey":"BUILD_NUMBER","iosEnabled":true,
            "intent":if create { "create" } else { "edit" },"values":{"name":name,"build":build},
            "file":{"path":"public/nested/version.properties","action":action,
                "before":if create { json!({"state":"absent"}) } else { json!({"state":"present","text":ORIGINAL,"bytes":ORIGINAL.len(),"sha256":digest(ORIGINAL.as_bytes())}) },
                "after":{"text":after,"bytes":after.len(),"sha256":digest(after.as_bytes())},"requestedMode":420,"preserveMode":!create},
            "createDirectories":if create { vec!["public/nested"] } else { vec![] },
            "lineEndings":{"before":if create { vec![] } else { vec!["crlf","lf"] },"after":if create { vec!["lf"] } else { vec!["crlf","lf"] },
                "finalNewlineBefore":false,"finalNewlineAfter":create,"preserved":!create},
            "validation":{"valid":true,"state":"format-valid","issues":[]}})
    }
    fn prepared(view: Value) -> Vec<u8> {
        frame(1,"prepared",json!({"revision":REVISION,"planToken":PLAN,"view":view,"scopeResources":"settled"}))
    }
    #[test]
    fn original_policy_invalid_atoms_are_correctable_and_absence_requires_explicit_null() {
        let mut invalid = opened(true);
        invalid["values"] = json!({"name":"bad","build":"0"});
        assert!(matches!(decode(&frame(0,"opened",invalid), SESSION), Ok(ChildFrame::ReleaseVersionOpened(_))));
        let mut long = opened(true);
        long["values"] = json!({"name":"x".repeat(200),"build":"0"});
        long["baseline"]["savedVersion"]["bytes"] = json!(256);
        assert!(decode(&frame(0,"opened",long),SESSION).is_ok());
        assert!(decode(&frame(0,"opened",opened(false)),SESSION).is_ok());
        let mut missing = opened(false); missing.as_object_mut().unwrap().remove("values");
        assert!(decode(&frame(0,"opened",missing),SESSION).is_err());
        for (pointer, value) in [
            ("/values",json!({"name":"","build":""})), ("/baseline/savedVersion",json!({"state":"absent","text":""})),
            ("/baseline/savedVersion",json!({"state":"unreadable"})), ("/scopeResources",json!("unknown")),
        ] {
            let mut bad = opened(false); *bad.pointer_mut(pointer).unwrap() = value;
            assert!(decode(&frame(0,"opened",bad),SESSION).is_err());
        }
        for (pointer, value) in [
            ("/values",Value::Null), ("/values/build",json!(7)), ("/values/name",json!("1.2\n")),
            ("/baseline/savedVersion/bytes",json!(0)), ("/source",json!("RELEASE/MOBILE-RELEASE.JSON")),
            ("/nameKey",json!("VERSION_NAME\n")), ("/buildKey",json!("VERSION_NAME")),
        ] {
            let mut bad = opened(true); *bad.pointer_mut(pointer).unwrap() = value;
            assert!(decode(&frame(0,"opened",bad),SESSION).is_err());
        }
    }
    #[test]
    fn one_file_review_checks_real_text_hashes_mode_action_separator_and_missing_ancestor_suffix() {
        for action in ["create","replace","preserve"] {
            assert!(matches!(decode(&prepared(view(action)),SESSION),Ok(ChildFrame::ReleaseVersionPrepared(_))));
        }
        for (pointer, value) in [
            ("/file/path",json!("different/version")), ("/file/after/bytes",json!(1)),
            ("/file/after/sha256",json!("0".repeat(64))), ("/file/before/sha256",json!("0".repeat(64))),
            ("/file/action",json!("preserve")), ("/file/preserveMode",json!(false)),
            ("/file/requestedMode",json!(512)), ("/lineEndings/after",json!(["lf"])),
            ("/lineEndings/finalNewlineAfter",json!(true)), ("/createDirectories",json!(["public"])),
        ] {
            let mut bad = view("replace"); *bad.pointer_mut(pointer).unwrap() = value;
            assert!(decode(&prepared(bad),SESSION).is_err());
        }
        for (pointer, value) in [
            ("/createDirectories",json!(["public"])), ("/createDirectories",json!(["public/nested","public"])),
            ("/file/requestedMode",json!(384)), ("/file/preserveMode",json!(true)), ("/intent",json!("edit")),
            ("/file/before",json!({"state":"absent","bytes":0})),
        ] {
            let mut bad = view("create"); *bad.pointer_mut(pointer).unwrap() = value;
            assert!(decode(&prepared(bad),SESSION).is_err());
        }
        assert_eq!(line_styles("\r\n\n\r\u{b}\u{c}\u{1c}\u{1d}\u{1e}\u{85}\u{2028}\u{2029}"),
            vec![LineStyle::Crlf,LineStyle::Lf,LineStyle::Cr,LineStyle::Vt,LineStyle::Ff,LineStyle::Fs,LineStyle::Gs,LineStyle::Rs,LineStyle::Nel,LineStyle::Ls,LineStyle::Ps]);
    }
    #[test]
    fn private_domain_frames_are_closed_bounded_and_never_accept_foreign_authority() {
        let valid = frame(0,"opened",opened(true));
        let mut foreign: Value = serde_json::from_slice(&valid).unwrap();
        foreign["protocol"] = json!("mrk-metadata-text/1");
        let mut bytes = serde_json::to_vec(&foreign).unwrap(); bytes.push(b'\n');
        assert!(decode(&bytes,SESSION).is_err());
        assert!(crate::edit_protocol::decode(&valid,SESSION).is_err());
        assert!(crate::metadata_text_edit_protocol::decode(&valid,SESSION).is_err());
        assert!(decode(&valid[..valid.len()-1],SESSION).is_err());
        assert!(decode(&valid,REVISION).is_err());
        let mut extra = opened(true); extra["root"] = json!("/not-authority");
        assert!(decode(&frame(0,"opened",extra),SESSION).is_err());
        let mut oversized = view("replace"); oversized["file"]["after"]["text"] = json!("x".repeat(TEXT_LIMIT + 1));
        assert!(decode(&prepared(oversized),SESSION).is_err());
        let terminal = json!({"kind":"outcome","planToken":Value::Null,"effect":"not_started","journal":"not_created","resources":"settled","reason":"invalid_params"});
        assert!(matches!(decode(&frame(1,"terminal",terminal.clone()),SESSION),Ok(ChildFrame::ReleaseVersionTerminal(1,_))));
        let mut missing = terminal; missing.as_object_mut().unwrap().remove("planToken");
        assert!(decode(&frame(1,"terminal",missing),SESSION).is_err());
        let duplicate = String::from_utf8(valid).unwrap().replacen("\"protocol\":", "\"protocol\":\"wrong\",\"protocol\":",1);
        assert!(decode(duplicate.as_bytes(),SESSION).is_err());
    }
    #[test]
    fn fixed_private_requests_require_original_identity_sequence_intent_and_string_values() {
        let private = json!({"root":"/inert-never-opened","registeredIdentity":{"device":"1","inode":"2","mode":16832,"uid":1000,"gid":1000}});
        assert!(request(SESSION,0,"open",private.clone()).is_ok());
        assert!(request(SESSION,0,"open",json!({"root":"/inert-never-opened"})).is_err());
        assert!(request(SESSION,1,"open",private).is_err());
        let params = json!({"revision":REVISION,"expectedBaseline":baseline(true),"intent":"edit","values":{"name":"1.3","build":"8"}});
        assert!(request(SESSION,1,"prepare",params.clone()).is_ok());
        for (pointer, value) in [("/intent",json!("create")), ("/values/build",json!(8)), ("/values/build",json!("8\n")),
            ("/values/name",json!("x".repeat(65))), ("/revision",json!(PLAN.to_owned()+"\n"))] {
            let mut bad = params.clone(); *bad.pointer_mut(pointer).unwrap() = value;
            assert!(request(SESSION,1,"prepare",bad).is_err());
        }
        assert!(request(SESSION,1,"apply",json!({"planToken":PLAN})).is_err());
        assert!(request(SESSION,2,"apply",json!({"planToken":PLAN})).is_ok());
        assert!(request(SESSION,3,"apply",json!({"planToken":PLAN})).is_err());
        assert!(request(SESSION,1,"discard",json!({})).is_ok());
        assert!(request(SESSION,2,"discard",json!({})).is_ok());
        assert!(request(SESSION,2,"discard",json!({"source":"override"})).is_err());
    }
}
