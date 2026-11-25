//! Closed app-ID DATA. Only the existing registered EditOwner owns execution.
//! Public requests cannot supply continuity, paths, root facts or a new owner.
use crate::{
    edit_protocol::{
        self as edit, bounded, token, Capability, ChildFrame, CoreEditOutcome, CoreReason, Effect,
        Journal, NativeEditReason, NativeFinality, Phase, ResourceState,
    },
    error::BridgeError,
    github_workflow_edit_protocol::RegisteredIdentity,
    protocol::{check_value, strict_json},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const DOMAIN: &str = "project_identity";
pub const PROTOCOL: &str = "mrk-project-identity/1";
pub const EVENT: &str = "project-identity-state-changed";
pub const REQUEST_LIMIT: usize = 16 * 1024;
pub const RESPONSE_LIMIT: usize = 128 * 1024;
pub const STATUS_LIMIT: usize = edit::STATUS_LIMIT;
const CONFIG: &str = "release/mobile-release.json";
const MAX_FILE: u64 = 2 * 1024 * 1024;
const NEW_WARNING: &str = "A different identity is a different app. This cannot update your existing app. Availability in the stores has not been checked.";
const INVALIDATIONS: [&str; 3] = [
    "credential-assessments-and-assignments",
    "prepared-release-plans",
    "candidate-identity-revision",
];
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
fn keys(v: &Value, names: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == names.len() && names.iter().all(|k| o.contains_key(*k)))
}
fn text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
}
fn string(v: &Value, max: usize) -> bool {
    v.as_str().is_some_and(|s| text(s, max))
}
fn integer(v: &Value, min: u64, max: u64) -> bool {
    v.as_u64().is_some_and(|n| (min..=max).contains(&n))
}
fn one(v: &Value, names: &[&str]) -> bool {
    v.as_str().is_some_and(|s| names.contains(&s))
}
fn path(s: &str) -> bool {
    text(s, 512)
        && s.split('/').count() <= 16
        && s.split('/').all(|p| {
            let lower = p.to_ascii_lowercase();
            !p.is_empty()
                && p != "."
                && p != ".."
                && p.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.+ @()-".contains(&c))
                && ![
                    ".git",
                    ".gradle",
                    ".idea",
                    ".mobile-release",
                    "build",
                    "deriveddata",
                    "pods",
                    "node_modules",
                    "private",
                    "secrets",
                    "credentials",
                    "xcuserdata",
                ]
                .contains(&lower.as_str())
                && ![".mobile-release-", ".private-", ".codex-private-"]
                    .iter()
                    .any(|prefix| lower.starts_with(prefix))
        })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Android,
    Ios,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Intent {
    Edit,
    Recover,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityIntent {
    Preserve,
    NewApplication,
}
/// Native-only selection input. UNKNOWN is not proof of Store absence. Root
/// must supply Existing for every retained known-published fact; core also
/// independently vetoes changes to approved/configured Store identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum NativeContinuity {
    Existing,
    Unknown,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetSelection {
    pub platform: Platform,
    pub target: String,
    #[serde(deserialize_with = "required_option")]
    pub project: Option<String>,
}
impl TargetSelection {
    fn valid(&self) -> bool {
        text(&self.target, 255)
            && self
                .target
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_. :()-".contains(&c))
            && match self.platform {
                Platform::Android => {
                    self.project.is_none()
                        && (self.target == ":"
                            || self.target.starts_with(':')
                                && self.target[1..].split(':').all(|p| {
                                    !p.is_empty()
                                        && p.bytes().all(|c| {
                                            c.is_ascii_alphanumeric() || b"_.-".contains(&c)
                                        })
                                })
                                && path(&format!(
                                    "{}/build.gradle.kts",
                                    self.target[1..].replace(':', "/")
                                )))
                }
                Platform::Ios => self
                    .project
                    .as_deref()
                    .is_some_and(|p| path(p) && p.ends_with(".xcodeproj")),
            }
    }
    fn selected(&self, continuity: NativeContinuity) -> Selection {
        Selection {
            platform: self.platform,
            target: self.target.clone(),
            project: self.project.clone(),
            continuity,
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    platform: Platform,
    target: String,
    #[serde(deserialize_with = "required_option")]
    project: Option<String>,
    continuity: NativeContinuity,
}
impl Selection {
    fn valid(&self) -> bool {
        TargetSelection {
            platform: self.platform,
            target: self.target.clone(),
            project: self.project.clone(),
        }
        .valid()
    }
}
fn selection(v: &Value) -> Option<Selection> {
    Selection::deserialize(v).ok().filter(Selection::valid)
}
fn identity(s: &str, platform: Platform) -> bool {
    s.len() <= 255
        && s.split('.').count() >= 2
        && s.split('.').all(|p| {
            p.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && p.bytes().all(|c| {
                    c.is_ascii_alphanumeric()
                        || c == (if platform == Platform::Android {
                            b'_'
                        } else {
                            b'-'
                        })
                })
        })
}
fn identity_value(v: &Value, platform: Platform) -> bool {
    v.as_str().is_some_and(|s| identity(s, platform))
}

#[derive(Deserialize)]
#[serde(tag = "intent", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Open {
    Edit {
        #[serde(rename = "projectId")]
        project_id: String,
        selection: TargetSelection,
    },
    Recover {
        #[serde(rename = "projectId")]
        project_id: String,
    },
}
impl Open {
    pub(crate) fn project_id(&self) -> &str {
        match self {
            Self::Edit { project_id, .. } | Self::Recover { project_id } => project_id,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        crate::protocol::valid_id(self.project_id())
            && match self {
                Self::Edit { selection, .. } => selection.valid(),
                Self::Recover { .. } => true,
            }
    }
    pub(crate) fn platform(&self) -> Option<Platform> {
        match self {
            Self::Edit { selection, .. } => Some(selection.platform),
            Self::Recover { .. } => None,
        }
    }
    pub(crate) fn bind(self, continuity: NativeContinuity) -> BoundOpen {
        BoundOpen {
            open: self,
            continuity,
        }
    }
}
pub(crate) struct BoundOpen {
    open: Open,
    continuity: NativeContinuity,
}
impl BoundOpen {
    pub(crate) fn project_id(&self) -> &str {
        self.open.project_id()
    }
    pub(crate) fn valid(&self) -> bool {
        self.open.valid()
    }
    pub(crate) fn details(&self) -> Details {
        let (intent, expected) = match &self.open {
            Open::Edit { selection, .. } => {
                (Intent::Edit, Some(selection.selected(self.continuity)))
            }
            Open::Recover { .. } => (Intent::Recover, None),
        };
        Details {
            intent,
            expected,
            requested: None,
            checkout: None,
            prepared: None,
            diagnostic: None,
        }
    }
    pub(crate) fn params(self, root: &std::path::Path, registered: RegisteredIdentity) -> Value {
        match self.open {
            Open::Edit { selection, .. } => {
                json!({"root":root,"registeredIdentity":registered,"intent":"edit","selection":selection.selected(self.continuity)})
            }
            Open::Recover { .. } => {
                json!({"root":root,"registeredIdentity":registered,"intent":"recover"})
            }
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "intent", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Prepare {
    Edit {
        #[serde(rename = "sessionId")]
        session_id: String,
        revision: String,
        #[serde(rename = "desiredIdentity")]
        desired_identity: String,
        #[serde(rename = "identityIntent")]
        identity_intent: IdentityIntent,
    },
    Recover {
        #[serde(rename = "sessionId")]
        session_id: String,
        revision: String,
    },
}
impl Prepare {
    pub(crate) fn session_id(&self) -> &str {
        match self {
            Self::Edit { session_id, .. } | Self::Recover { session_id, .. } => session_id,
        }
    }
    pub(crate) fn revision(&self) -> &str {
        match self {
            Self::Edit { revision, .. } | Self::Recover { revision, .. } => revision,
        }
    }
    pub(crate) fn submission(&self) -> Submission {
        match self {
            Self::Edit {
                desired_identity,
                identity_intent,
                ..
            } => Submission::Edit {
                desired_identity: desired_identity.clone(),
                identity_intent: *identity_intent,
            },
            Self::Recover { .. } => Submission::Recover,
        }
    }
    pub(crate) fn params(&self) -> Value {
        match self {
            Self::Edit {
                revision,
                desired_identity,
                identity_intent,
                ..
            } => {
                json!({"revision":revision,"intent":"edit","desiredIdentity":desired_identity,"identityIntent":identity_intent})
            }
            Self::Recover { revision, .. } => json!({"revision":revision,"intent":"recover"}),
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Apply {
    pub session_id: String,
    pub revision: String,
    pub plan_token: String,
    pub intent: Intent,
}
#[derive(Clone)]
pub(crate) enum Submission {
    Edit {
        desired_identity: String,
        identity_intent: IdentityIntent,
    },
    Recover,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub code: String,
    pub path: String,
    pub line: u32,
    pub column: u32,
    pub help: String,
}
impl Diagnostic {
    fn valid(&self) -> bool {
        path(&self.path)
            && (1..=MAX_FILE).contains(&u64::from(self.line))
            && (1..=MAX_FILE).contains(&u64::from(self.column))
            && text(&self.help, 1024)
            && [
                "invalid-input",
                "unsafe-path",
                "missing-control",
                "invalid-config",
                "identity-mismatch",
                "target-mismatch",
                "ambiguous-target",
                "unsupported-syntax",
                "dynamic-identity",
                "unsupported-plugin",
                "imported-control",
                "generated-project",
                "variant-identity",
                "ambiguous-identity",
                "conditional-config",
                "include-cycle",
                "shared-control",
                "unsupported-plist",
                "plist-override",
                "scheme-selection",
                "scheme-required",
                "existing-application",
                "new-intent-required",
                "dependent-service",
                "stale-revision",
            ]
            .contains(&self.code.as_str())
    }
}
fn locations(rows: &Value, platform: Platform, change: bool) -> bool {
    let Some(rows) = rows.as_array().filter(|r| r.len() <= 65) else {
        return false;
    };
    let mut seen = BTreeSet::new();
    rows.iter().all(|r| {
        let names: &[&str] = if change {
            &["path", "line", "column", "role", "beforeId", "afterId"]
        } else {
            &["path", "line", "column", "role"]
        };
        keys(r, names)
            && r["path"].as_str().is_some_and(path)
            && integer(&r["line"], 1, MAX_FILE)
            && integer(&r["column"], 1, MAX_FILE)
            && r["role"]
                == (if r["path"] == CONFIG {
                    "saved-identity"
                } else if platform == Platform::Android {
                    "android-application-id"
                } else {
                    "ios-bundle-id"
                })
            && seen.insert((
                r["path"].as_str(),
                r["line"].as_u64(),
                r["column"].as_u64(),
                r["role"].as_str(),
            ))
            && (!change
                || identity_value(&r["beforeId"], platform)
                    && identity_value(&r["afterId"], platform)
                    && r["beforeId"] != r["afterId"])
    })
}
fn analysis(v: &Value) -> bool {
    if !keys(
        v,
        &[
            "schemaVersion",
            "kind",
            "revision",
            "selection",
            "state",
            "identity",
            "configuredIdentity",
            "identityStatus",
            "configurations",
            "locations",
            "diagnostics",
            "nextStep",
            "scope",
            "buildVerificationRequired",
        ],
    ) || v["schemaVersion"] != 1
        || v["kind"] != "project-identity"
        || !v["revision"].as_str().is_some_and(token)
        || !one(&v["state"], &["supported", "unsupported"])
        || v["scope"] != "recognized-literal-source-only"
        || v["buildVerificationRequired"] != true
        || !string(&v["nextStep"], 1024)
    {
        return false;
    }
    let Some(s) = selection(&v["selection"]) else {
        return false;
    };
    let Some(configs) = v["configurations"].as_array().filter(|a| a.len() <= 32) else {
        return false;
    };
    let Some(diagnostics) = v["diagnostics"].as_array().filter(|a| a.len() <= 1) else {
        return false;
    };
    let mut names = BTreeSet::new();
    if !["identity", "configuredIdentity"]
        .iter()
        .all(|k| v[*k].is_null() || identity_value(&v[*k], s.platform))
        || !(v["identityStatus"].is_null()
            || one(&v["identityStatus"], &["unverified", "approved", "blocked"]))
        || !configs
            .iter()
            .all(|c| string(c, 80) && names.insert(c.as_str()))
        || !locations(&v["locations"], s.platform, false)
        || !diagnostics
            .iter()
            .all(|d| Diagnostic::deserialize(d).is_ok_and(|d| d.valid()))
    {
        return false;
    }
    if v["state"] == "unsupported" {
        return diagnostics.len() == 1;
    }
    let rows = v["locations"].as_array().unwrap();
    diagnostics.is_empty()
        && !v["identity"].is_null()
        && v["identity"] == v["configuredIdentity"]
        && !v["identityStatus"].is_null()
        && !configs.is_empty()
        && rows.len() >= 2
        && rows
            .iter()
            .filter(|r| r["role"] == "saved-identity")
            .count()
            == 1
}
fn preview(v: &Value) -> bool {
    if !keys(
        v,
        &[
            "schemaVersion",
            "kind",
            "revision",
            "selection",
            "intent",
            "state",
            "changes",
            "warnings",
            "invalidations",
            "retainVersionReservations",
            "buildVerificationRequired",
        ],
    ) || v["schemaVersion"] != 1
        || v["kind"] != "project-identity-preview"
        || !v["revision"].as_str().is_some_and(token)
        || !one(&v["intent"], &["preserve", "new-application"])
        || !one(&v["state"], &["change", "unchanged"])
        || v["retainVersionReservations"] != true
        || v["buildVerificationRequired"] != true
    {
        return false;
    }
    let Some(s) = selection(&v["selection"]) else {
        return false;
    };
    if !locations(&v["changes"], s.platform, true) {
        return false;
    }
    if v["state"] == "unchanged" {
        return v["changes"] == json!([])
            && v["warnings"] == json!([])
            && v["invalidations"] == json!([]);
    }
    let rows = v["changes"].as_array().unwrap();
    s.continuity == NativeContinuity::Unknown
        && v["intent"] == "new-application"
        && rows.len() >= 2
        && rows
            .iter()
            .filter(|r| r["role"] == "saved-identity")
            .count()
            == 1
        && rows
            .iter()
            .all(|r| r["beforeId"] == rows[0]["beforeId"] && r["afterId"] == rows[0]["afterId"])
        && v["warnings"] == json!([NEW_WARNING])
        && v["invalidations"] == json!(INVALIDATIONS)
}
fn recovery(v: &Value) -> bool {
    if !keys(
        v,
        &[
            "schemaVersion",
            "kind",
            "state",
            "reason",
            "action",
            "transactionId",
            "desiredIdentity",
            "files",
            "help",
            "privateCleanup",
            "retainVersionReservations",
        ],
    ) || v["schemaVersion"] != 1
        || v["kind"] != "project-identity-recovery"
        || !one(&v["state"], &["idle", "recoverable", "conflict"])
        || !one(
            &v["reason"],
            &[
                "none",
                "incomplete_journal",
                "foreign_journal",
                "legacy_journal",
                "invalid_journal",
                "unsupported_descriptor",
                "target_changed",
                "control_changed",
                "namespace_changed",
                "inventory_changed",
            ],
        )
        || v["retainVersionReservations"] != true
        || !string(&v["help"], 1024)
    {
        return false;
    }
    let c = &v["privateCleanup"];
    let Some(rows) = v["files"].as_array().filter(|r| r.len() <= 64) else {
        return false;
    };
    if !keys(c, &["fileCount", "directoryCount", "scope"])
        || c["scope"] != "inspected-owned-journal-only"
        || !integer(&c["fileCount"], 0, 1024)
        || !integer(&c["directoryCount"], 0, 1025)
    {
        return false;
    }
    if v["state"] != "recoverable" {
        return v["action"].is_null()
            && v["transactionId"].is_null()
            && v["desiredIdentity"].is_null()
            && rows.is_empty()
            && c["fileCount"] == 0
            && c["directoryCount"] == 0
            && (v["state"] == "idle") == (v["reason"] == "none");
    }
    let mut seen = BTreeSet::new();
    v["reason"] == "none"
        && v["transactionId"].as_str().is_some_and(token)
        && one(
            &v["action"],
            &[
                "rollback",
                "preparing_cleanup",
                "committed_cleanup",
                "rolled_back_cleanup",
            ],
        )
        && integer(&c["directoryCount"], 1, 1025)
        && (identity_value(&v["desiredIdentity"], Platform::Android)
            || identity_value(&v["desiredIdentity"], Platform::Ios))
        && rows.iter().all(|r| {
            keys(r, &["path", "action", "beforeBytes", "afterBytes"])
                && r["path"].as_str().is_some_and(path)
                && seen.insert(r["path"].as_str())
                && integer(&r["beforeBytes"], 0, MAX_FILE)
                && (r["afterBytes"].is_null() || integer(&r["afterBytes"], 0, MAX_FILE))
                && r["action"]
                    == if v["action"] == "rollback" && !r["afterBytes"].is_null() {
                        "restore_original"
                    } else {
                        "preserve"
                    }
        })
}
fn preview_matches(v: &Value, observed: &Value, submission: &Submission) -> bool {
    let Submission::Edit {
        desired_identity,
        identity_intent,
    } = submission
    else {
        return false;
    };
    if !analysis(observed)
        || observed["state"] != "supported"
        || !preview(v)
        || v["selection"] != observed["selection"]
        || v["revision"] != observed["revision"]
        || v["intent"] != json!(identity_intent)
    {
        return false;
    }
    let s = selection(&observed["selection"]).unwrap();
    if !identity(desired_identity, s.platform) {
        return false;
    }
    if observed["identity"] == desired_identity.as_str() {
        return v["state"] == "unchanged";
    }
    let rows = v["changes"].as_array().unwrap();
    let original = observed["locations"].as_array().unwrap();
    *identity_intent == IdentityIntent::NewApplication
        && s.continuity == NativeContinuity::Unknown
        && observed["identityStatus"] == "unverified"
        && v["state"] == "change"
        && rows.len() == original.len()
        && rows.iter().zip(original).all(|(r, old)| {
            ["path", "line", "column", "role"]
                .iter()
                .all(|k| r[*k] == old[*k])
                && r["beforeId"] == observed["identity"]
                && r["afterId"] == desired_identity.as_str()
        })
}

#[derive(Clone, Serialize)]
pub struct Checkout {
    pub revision: String,
    pub view: Value,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Prepared {
    pub revision: String,
    pub plan_token: String,
    pub view: Value,
}
#[derive(Clone)]
pub(crate) struct Details {
    pub intent: Intent,
    expected: Option<Selection>,
    requested: Option<Submission>,
    pub checkout: Option<Checkout>,
    pub prepared: Option<Prepared>,
    pub diagnostic: Option<Diagnostic>,
}
impl Details {
    /// Private original selection, not a public Status/renderer authority.
    /// None is meaningful only for the separately tagged descriptor recovery.
    pub(crate) fn platform(&self) -> Option<Platform> {
        self.expected.as_ref().map(|selected| selected.platform)
    }
    pub(crate) fn accepts_current_continuity(&self, current: NativeContinuity) -> bool {
        self.valid()
            && match self.intent {
                // Recovery can only finish/roll back its original descriptor. It
                // cannot submit a new ID and must not be stranded by later history.
                Intent::Recover => true,
                Intent::Edit => self.expected.as_ref().is_some_and(|selected| {
                    current != NativeContinuity::Existing
                        || selected.continuity == NativeContinuity::Existing
                }),
            }
    }
    pub(crate) fn revision(&self) -> Option<&str> {
        self.checkout.as_ref().map(|c| c.revision.as_str())
    }
    pub(crate) fn plan_token(&self) -> Option<&str> {
        self.prepared.as_ref().map(|p| p.plan_token.as_str())
    }
    pub(crate) fn valid(&self) -> bool {
        if (self.intent == Intent::Edit) != self.expected.is_some()
            || self.expected.as_ref().is_some_and(|s| !s.valid())
        {
            return false;
        }
        if let Some(c) = &self.checkout {
            if !token(&c.revision)
                || match self.intent {
                    Intent::Edit => {
                        !analysis(&c.view)
                            || c.view["revision"] != c.revision
                            || selection(&c.view["selection"]).as_ref() != self.expected.as_ref()
                    }
                    Intent::Recover => !recovery(&c.view),
                }
            {
                return false;
            }
        }
        if let Some(submission) = &self.requested {
            if self.checkout.is_none() || !self.submission_fits(submission) {
                return false;
            }
        }
        if let Some(p) = &self.prepared {
            if !token(&p.plan_token)
                || self.revision() != Some(p.revision.as_str())
                || p.plan_token == p.revision
            {
                return false;
            }
            let (Some(c), Some(s)) = (&self.checkout, &self.requested) else {
                return false;
            };
            if match self.intent {
                Intent::Edit => !preview_matches(&p.view, &c.view, s),
                Intent::Recover => {
                    !recovery(&p.view) || p.view["state"] != "recoverable" || p.view != c.view
                }
            } {
                return false;
            }
        }
        self.diagnostic
            .as_ref()
            .is_none_or(|d| self.intent == Intent::Edit && self.prepared.is_none() && d.valid())
    }
    fn submission_fits(&self, submission: &Submission) -> bool {
        let Some(c) = &self.checkout else {
            return false;
        };
        match (self.intent, submission) {
            (
                Intent::Edit,
                Submission::Edit {
                    desired_identity,
                    identity_intent,
                },
            ) => {
                let Some(s) = self.expected.as_ref() else {
                    return false;
                };
                c.view["state"] == "supported"
                    && identity(desired_identity, s.platform)
                    && (c.view["identity"] == desired_identity.as_str()
                        || *identity_intent == IdentityIntent::NewApplication
                            && s.continuity == NativeContinuity::Unknown
                            && c.view["identityStatus"] == "unverified")
            }
            (Intent::Recover, Submission::Recover) => c.view["state"] == "recoverable",
            _ => false,
        }
    }
    pub(crate) fn admit_submission(&mut self, submission: Submission) -> bool {
        if !self.valid()
            || self.requested.is_some()
            || self.prepared.is_some()
            || self.diagnostic.is_some()
            || !self.submission_fits(&submission)
        {
            return false;
        }
        self.requested = Some(submission);
        true
    }
    pub(crate) fn accept_opened(&mut self, opened: Opened) -> bool {
        if self.checkout.is_some()
            || self.requested.is_some()
            || self.intent != opened.intent
            || !opened.valid()
            || self.intent == Intent::Edit
                && selection(&opened.view["selection"]).as_ref() != self.expected.as_ref()
        {
            return false;
        }
        self.checkout = Some(Checkout {
            revision: opened.revision,
            view: opened.view,
        });
        true
    }
    pub(crate) fn accept_prepared(&mut self, reply: PreparedReply) -> bool {
        if !self.valid()
            || self.prepared.is_some()
            || self.intent != reply.intent
            || !reply.valid()
            || self.revision() != Some(reply.revision.as_str())
        {
            return false;
        }
        let (Some(c), Some(s)) = (&self.checkout, &self.requested) else {
            return false;
        };
        if match self.intent {
            Intent::Edit => !preview_matches(&reply.view, &c.view, s),
            Intent::Recover => reply.view != c.view,
        } {
            return false;
        }
        self.prepared = Some(Prepared {
            revision: reply.revision,
            plan_token: reply.plan_token,
            view: reply.view,
        });
        true
    }
    pub(crate) fn terminal_admissible(&self, applied: bool, core: &CoreEditOutcome) -> bool {
        if !self.valid() || !core.valid() || applied && self.prepared.is_none() {
            return false;
        }
        if self.intent == Intent::Recover {
            if core.effect == Effect::Unchanged || !applied && core.journal == Journal::Clean {
                return false;
            }
            if let Some(c) = &self.checkout {
                let valid = match c.view["action"].as_str() {
                    Some("committed_cleanup") => core.effect == Effect::Committed,
                    Some("rolled_back_cleanup") => core.effect == Effect::RolledBack,
                    Some("preparing_cleanup") => core.effect == Effect::NotStarted,
                    Some("rollback") => {
                        core.effect == Effect::NotStarted
                            || applied
                                && matches!(core.effect, Effect::RolledBack | Effect::Unknown)
                    }
                    _ => core.effect == Effect::NotStarted,
                };
                if !valid || c.view["state"] == "recoverable" && core.journal == Journal::NotCreated
                {
                    return false;
                }
            } else if !matches!(core.effect, Effect::NotStarted | Effect::Unknown)
                || !matches!(core.journal, Journal::NotCreated | Journal::Unknown)
            {
                return false;
            }
            if applied && core.reason == CoreReason::None {
                return self
                    .prepared
                    .as_ref()
                    .is_some_and(|p| expected_recovery(&p.view) == Some(core.effect.clone()))
                    && core.journal == Journal::Clean
                    && core.resources == ResourceState::Settled;
            }
            return true;
        }
        if !applied {
            return matches!(core.effect, Effect::NotStarted | Effect::Unknown)
                && matches!(core.journal, Journal::NotCreated | Journal::Unknown);
        }
        let Some(p) = &self.prepared else {
            return false;
        };
        let change = p.view["state"] == "change";
        if matches!(
            core.effect,
            Effect::Unchanged | Effect::Committed | Effect::RolledBack
        ) && (core.effect == Effect::Unchanged) == change
        {
            return false;
        }
        core.reason != CoreReason::None
            || core.effect
                == (if change {
                    Effect::Committed
                } else {
                    Effect::Unchanged
                })
                && core.journal
                    == (if change {
                        Journal::Clean
                    } else {
                        Journal::NotCreated
                    })
                && core.resources == ResourceState::Settled
    }
}
pub(crate) fn expected_recovery(v: &Value) -> Option<Effect> {
    if !recovery(v) || v["state"] != "recoverable" {
        return None;
    }
    match v["action"].as_str() {
        Some("committed_cleanup") => Some(Effect::Committed),
        Some("preparing_cleanup") => Some(Effect::NotStarted),
        Some("rollback" | "rolled_back_cleanup") => Some(Effect::RolledBack),
        _ => None,
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Projection {
    pub domain: &'static str,
    pub intent: Intent,
    pub project_id: String,
    pub session_id: String,
    pub owner_generation: String,
    pub phase: Phase,
    pub review_remaining_ms: u32,
    pub checkout: Option<Checkout>,
    pub prepared: Option<Prepared>,
    pub diagnostic: Option<Diagnostic>,
    pub apply_submitted: bool,
    pub core_outcome: Option<CoreEditOutcome>,
    pub native_reason: NativeEditReason,
    pub native_finality: NativeFinality,
    pub late_settled: bool,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityStatus {
    pub schema_version: u32,
    pub domain: &'static str,
    pub window_generation: String,
    pub status_revision: u32,
    pub capability: Capability,
    pub active: Option<Projection>,
    pub last_terminal: Option<Projection>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Opened {
    intent: Intent,
    revision: String,
    view: Value,
    scope_resources: ResourceState,
}
impl Opened {
    fn valid(&self) -> bool {
        token(&self.revision)
            && self.scope_resources == ResourceState::Settled
            && match self.intent {
                Intent::Edit => analysis(&self.view) && self.view["revision"] == self.revision,
                Intent::Recover => recovery(&self.view),
            }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedReply {
    intent: Intent,
    revision: String,
    plan_token: String,
    view: Value,
    scope_resources: ResourceState,
}
impl PreparedReply {
    fn valid(&self) -> bool {
        token(&self.revision)
            && token(&self.plan_token)
            && self.revision != self.plan_token
            && self.scope_resources == ResourceState::Settled
            && match self.intent {
                Intent::Edit => preview(&self.view) && self.view["revision"] == self.revision,
                Intent::Recover => recovery(&self.view) && self.view["state"] == "recoverable",
            }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalReply {
    pub intent: Intent,
    #[serde(deserialize_with = "required_option")]
    pub plan_token: Option<String>,
    effect: Effect,
    journal: Journal,
    resources: ResourceState,
    reason: CoreReason,
    #[serde(deserialize_with = "required_option")]
    pub diagnostic: Option<Diagnostic>,
}
impl TerminalReply {
    pub(crate) fn outcome(&self) -> CoreEditOutcome {
        CoreEditOutcome {
            effect: self.effect.clone(),
            journal: self.journal.clone(),
            resources: self.resources.clone(),
            reason: self.reason.clone(),
        }
    }
    fn valid(&self) -> bool {
        self.outcome().valid()
            && self.plan_token.as_deref().is_none_or(token)
            && self.diagnostic.as_ref().is_none_or(|d| {
                d.valid()
                    && self.intent == Intent::Edit
                    && self.plan_token.is_none()
                    && self.reason != CoreReason::None
            })
    }
}
pub(crate) fn request(
    session: &str,
    seq: u32,
    op: &str,
    params: Value,
) -> Result<Vec<u8>, BridgeError> {
    let mode = one(&params["intent"], &["edit", "recover"]);
    let recover = params["intent"] == "recover";
    let valid = token(session)
        && match (seq, op) {
            (0, "open") => {
                mode && string(&params["root"], 4096)
                    && RegisteredIdentity::deserialize(&params["registeredIdentity"])
                        .is_ok_and(|id| id.valid())
                    && if recover {
                        keys(&params, &["root", "registeredIdentity", "intent"])
                    } else {
                        keys(
                            &params,
                            &["root", "registeredIdentity", "intent", "selection"],
                        ) && selection(&params["selection"]).is_some()
                    }
            }
            (1, "prepare") => {
                mode && params["revision"].as_str().is_some_and(token)
                    && if recover {
                        keys(&params, &["revision", "intent"])
                    } else {
                        keys(
                            &params,
                            &["revision", "intent", "desiredIdentity", "identityIntent"],
                        ) && one(&params["identityIntent"], &["preserve", "new-application"])
                            && (identity_value(&params["desiredIdentity"], Platform::Android)
                                || identity_value(&params["desiredIdentity"], Platform::Ios))
                    }
            }
            (2, "apply") => {
                mode && keys(&params, &["planToken", "intent"])
                    && params["planToken"].as_str().is_some_and(token)
            }
            (1 | 2, "discard") => keys(&params, &[]),
            _ => false,
        };
    if !valid {
        return Err(BridgeError::invalid());
    }
    let v = json!({"protocol":PROTOCOL,"session":session,"seq":seq,"op":op,"params":params});
    check_value(&v)?;
    let mut bytes = bounded(&v, REQUEST_LIMIT - 1)?;
    bytes.push(b'\n');
    Ok(bytes)
}
pub(crate) fn decode(bytes: &[u8], session: &str) -> Result<ChildFrame, BridgeError> {
    if !token(session) || bytes.len() > RESPONSE_LIMIT || !bytes.ends_with(b"\n") {
        return Err(BridgeError::protocol());
    }
    let body = &bytes[..bytes.len() - 1];
    if body.first() != Some(&b'{')
        || body.last() != Some(&b'}')
        || body.iter().any(|b| matches!(*b, b'\r' | b'\n'))
    {
        return Err(BridgeError::protocol());
    }
    let v = strict_json(body)?;
    if !keys(&v, &["protocol", "session", "seq", "kind", "result"])
        || v["protocol"] != PROTOCOL
        || v["session"] != session
    {
        return Err(BridgeError::protocol());
    }
    let raw = &v["result"];
    check_value(raw).map_err(|_| BridgeError::protocol())?;
    match (v["seq"].as_u64(), v["kind"].as_str()) {
        (Some(0), Some("opened")) => {
            let r = Opened::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if !r.valid() {
                return Err(BridgeError::protocol());
            }
            Ok(ChildFrame::IdentityOpened(r))
        }
        (Some(1), Some("prepared")) => {
            let r = PreparedReply::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if !r.valid() {
                return Err(BridgeError::protocol());
            }
            Ok(ChildFrame::IdentityPrepared(r))
        }
        (Some(n @ 0..=2), Some("terminal")) => {
            bounded(&v, edit::TERMINAL_LIMIT - 1).map_err(|_| BridgeError::protocol())?;
            let r = TerminalReply::deserialize(raw).map_err(|_| BridgeError::protocol())?;
            if !r.valid() {
                return Err(BridgeError::protocol());
            }
            Ok(ChildFrame::IdentityTerminal(n as u32, r))
        }
        _ => Err(BridgeError::protocol()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) const REVISION: &str = "22222222222222222222222222222222";
    pub(crate) const PLAN: &str = "33333333333333333333333333333333";
    const SESSION: &str = "11111111111111111111111111111111";
    const OLD: &str = "com.example.original";
    const NEW: &str = "com.example.another";

    fn public_open() -> Value {
        json!({"intent":"edit","projectId":"a".repeat(32),"selection":{"platform":"android","target":":app","project":null}})
    }
    fn analysis_data(continuity: NativeContinuity) -> Value {
        json!({"schemaVersion":1,"kind":"project-identity","revision":REVISION,
            "selection":{"platform":"android","target":":app","project":null,"continuity":continuity},
            "state":"supported","identity":OLD,"configuredIdentity":OLD,"identityStatus":"unverified","configurations":["release"],
            "locations":[{"path":"app/build.gradle.kts","line":4,"column":20,"role":"android-application-id"},
                {"path":CONFIG,"line":10,"column":20,"role":"saved-identity"}],"diagnostics":[],
            "nextStep":"Review the app identity.","scope":"recognized-literal-source-only","buildVerificationRequired":true})
    }
    fn preview_data(continuity: NativeContinuity, noop: bool) -> Value {
        let observed = analysis_data(continuity);
        let changes: Vec<Value> = if noop {
            Vec::new()
        } else {
            observed["locations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    let mut row = row.clone();
                    row["beforeId"] = json!(OLD);
                    row["afterId"] = json!(NEW);
                    row
                })
                .collect()
        };
        json!({"schemaVersion":1,"kind":"project-identity-preview","revision":REVISION,"selection":observed["selection"],
            "intent":if noop {"preserve"} else {"new-application"},"state":if noop {"unchanged"} else {"change"},"changes":changes,
            "warnings":if noop {json!([])} else {json!([NEW_WARNING])},"invalidations":if noop {json!([])} else {json!(INVALIDATIONS)},
            "retainVersionReservations":true,"buildVerificationRequired":true})
    }
    fn opened(continuity: NativeContinuity) -> Opened {
        Opened {
            intent: Intent::Edit,
            revision: REVISION.to_owned(),
            view: analysis_data(continuity),
            scope_resources: ResourceState::Settled,
        }
    }
    fn reply(continuity: NativeContinuity, noop: bool) -> PreparedReply {
        PreparedReply {
            intent: Intent::Edit,
            revision: REVISION.to_owned(),
            plan_token: PLAN.to_owned(),
            view: preview_data(continuity, noop),
            scope_resources: ResourceState::Settled,
        }
    }
    pub(crate) fn edit_details(prepared: bool, noop: bool) -> Details {
        let mut d = Open::deserialize(&public_open())
            .unwrap()
            .bind(NativeContinuity::Unknown)
            .details();
        assert!(d.accept_opened(opened(NativeContinuity::Unknown)));
        if prepared {
            assert!(d.admit_submission(Submission::Edit {
                desired_identity: if noop { OLD } else { NEW }.to_owned(),
                identity_intent: if noop {
                    IdentityIntent::Preserve
                } else {
                    IdentityIntent::NewApplication
                }
            }));
            assert!(d.accept_prepared(reply(NativeContinuity::Unknown, noop)));
        }
        assert!(d.valid());
        d
    }
    fn recovery_data(action: &str) -> Value {
        json!({"schemaVersion":1,"kind":"project-identity-recovery","state":"recoverable","reason":"none","action":action,
            "transactionId":"4".repeat(32),"desiredIdentity":NEW,"files":[{"path":"app/build.gradle.kts",
                "action":if action=="rollback" {"restore_original"} else {"preserve"},"beforeBytes":100,"afterBytes":101}],
            "help":"Review the interrupted identity change.","privateCleanup":{"fileCount":8,"directoryCount":2,"scope":"inspected-owned-journal-only"},
            "retainVersionReservations":true})
    }
    pub(crate) fn recovery_details(action: &str, prepared: bool) -> Details {
        let mut d = Open::Recover {
            project_id: "a".repeat(32),
        }
        .bind(NativeContinuity::Unknown)
        .details();
        assert!(d.accept_opened(Opened {
            intent: Intent::Recover,
            revision: REVISION.to_owned(),
            view: recovery_data(action),
            scope_resources: ResourceState::Settled
        }));
        if prepared {
            assert!(d.admit_submission(Submission::Recover));
            assert!(d.accept_prepared(PreparedReply {
                intent: Intent::Recover,
                revision: REVISION.to_owned(),
                plan_token: PLAN.to_owned(),
                view: recovery_data(action),
                scope_resources: ResourceState::Settled
            }));
        }
        assert!(d.valid());
        d
    }
    fn outcome(effect: Effect, journal: Journal, reason: CoreReason) -> CoreEditOutcome {
        CoreEditOutcome {
            effect,
            journal,
            resources: ResourceState::Settled,
            reason,
        }
    }

    #[test]
    fn renderer_cannot_choose_continuity_registered_root_force_or_recovery_paths() {
        assert!(Open::deserialize(&public_open()).unwrap().valid());
        for (key, value) in [
            ("continuity", json!("unknown")),
            ("root", json!("/inert-root")),
            ("registeredIdentity", json!({})),
            ("force", json!(true)),
        ] {
            let mut raw = public_open();
            raw[key] = value;
            assert!(Open::deserialize(&raw).is_err());
        }
        for value in [json!("existing"), json!("unknown"), Value::Null] {
            let mut raw = public_open();
            raw["selection"]["continuity"] = value;
            assert!(Open::deserialize(&raw).is_err());
        }
        let mut no_project = public_open();
        no_project["selection"]
            .as_object_mut()
            .unwrap()
            .remove("project");
        assert!(Open::deserialize(&no_project).is_err());
        for value in [
            json!("app"),
            json!(":../app"),
            json!(":build"),
            json!(":app/other"),
        ] {
            let mut raw = public_open();
            raw["selection"]["target"] = value;
            assert!(!Open::deserialize(&raw).unwrap().valid());
        }
    }
    #[test]
    fn only_native_binding_supplies_complete_private_selection_and_registered_facts() {
        let bound = Open::deserialize(&public_open())
            .unwrap()
            .bind(NativeContinuity::Existing);
        let registered = RegisteredIdentity {
            device: "1".into(),
            inode: "2".into(),
            mode: 0o40755,
            uid: 1000,
            gid: 1001,
        };
        let params = bound.params(std::path::Path::new("/inert-root-never-opened"), registered);
        assert_eq!(params["selection"]["continuity"], "existing");
        let raw = request(SESSION, 0, "open", params.clone()).unwrap();
        assert_eq!(
            strict_json(&raw[..raw.len() - 1]).unwrap()["params"],
            params
        );
        for field in ["device", "inode", "mode", "uid", "gid"] {
            let mut bad = params.clone();
            bad["registeredIdentity"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(request(SESSION, 0, "open", bad).is_err());
        }
    }
    #[test]
    fn observed_revision_target_and_continuity_must_equal_original_native_selection() {
        for field in ["target", "project", "continuity"] {
            let mut d = Open::deserialize(&public_open())
                .unwrap()
                .bind(NativeContinuity::Unknown)
                .details();
            let mut r = opened(NativeContinuity::Unknown);
            r.view["selection"][field] = match field {
                "target" => json!(":other"),
                "project" => json!("Other.xcodeproj"),
                _ => json!("existing"),
            };
            assert!(!d.accept_opened(r));
            assert!(d.checkout.is_none());
        }
        let mut d = Open::deserialize(&public_open())
            .unwrap()
            .bind(NativeContinuity::Unknown)
            .details();
        let mut r = opened(NativeContinuity::Unknown);
        r.revision = "9".repeat(32);
        assert!(!d.accept_opened(r));
    }
    #[test]
    fn prepare_is_single_use_and_requires_exact_complete_original_locations_ids_and_warning() {
        for corrupt in 0..7 {
            let mut d = edit_details(false, false);
            assert!(d.admit_submission(Submission::Edit {
                desired_identity: NEW.into(),
                identity_intent: IdentityIntent::NewApplication
            }));
            assert!(!d.admit_submission(Submission::Edit {
                desired_identity: OLD.into(),
                identity_intent: IdentityIntent::Preserve
            }));
            let mut r = reply(NativeContinuity::Unknown, false);
            match corrupt {
                0 => r.view["changes"][0]["line"] = json!(5),
                1 => r.view["changes"][0]["path"] = json!("other/build.gradle.kts"),
                2 => r.view["changes"][0]["beforeId"] = json!("com.example.other"),
                3 => r.view["changes"][0]["afterId"] = json!("com.example.other"),
                4 => r.view["warnings"] = json!([]),
                5 => r.view["changes"].as_array_mut().unwrap().reverse(),
                _ => r.plan_token = REVISION.into(),
            }
            assert!(!d.accept_prepared(r));
            assert!(d.prepared.is_none());
        }
        let mut d = edit_details(true, false);
        assert!(!d.accept_prepared(reply(NativeContinuity::Unknown, false)));
    }
    #[test]
    fn known_existing_or_approved_cannot_change_but_may_preserve_identity() {
        for existing in [false, true] {
            let continuity = if existing {
                NativeContinuity::Existing
            } else {
                NativeContinuity::Unknown
            };
            let mut d = Open::deserialize(&public_open())
                .unwrap()
                .bind(continuity)
                .details();
            let mut r = opened(continuity);
            if !existing {
                r.view["identityStatus"] = json!("approved");
            }
            assert!(d.accept_opened(r));
            assert!(!d.admit_submission(Submission::Edit {
                desired_identity: NEW.into(),
                identity_intent: IdentityIntent::NewApplication
            }));
            assert!(d.admit_submission(Submission::Edit {
                desired_identity: OLD.into(),
                identity_intent: IdentityIntent::Preserve
            }));
            assert!(d.accept_prepared(reply(continuity, true)));
        }
        let mut d = edit_details(false, false);
        assert!(!d.admit_submission(Submission::Edit {
            desired_identity: NEW.into(),
            identity_intent: IdentityIntent::Preserve
        }));
    }
    #[test]
    fn retained_native_selection_rechecks_new_existing_history_before_prepare_and_apply() {
        for prepared in [false, true] {
            let detail = edit_details(prepared, false);
            assert_eq!(detail.platform(), Some(Platform::Android));
            assert!(detail.accepts_current_continuity(NativeContinuity::Unknown));
            assert!(!detail.accepts_current_continuity(NativeContinuity::Existing));
        }
        let mut existing = Open::deserialize(&public_open())
            .unwrap()
            .bind(NativeContinuity::Existing)
            .details();
        assert!(existing.accept_opened(opened(NativeContinuity::Existing)));
        // No later lack of a lookup result can declassify the captured veto.
        assert!(existing.accepts_current_continuity(NativeContinuity::Unknown));
        assert!(existing.accepts_current_continuity(NativeContinuity::Existing));
        assert!(!existing.admit_submission(Submission::Edit {
            desired_identity: NEW.into(),
            identity_intent: IdentityIntent::NewApplication,
        }));
        for action in [
            "rollback",
            "preparing_cleanup",
            "committed_cleanup",
            "rolled_back_cleanup",
        ] {
            for prepared in [false, true] {
                let recovery = recovery_details(action, prepared);
                assert_eq!(recovery.platform(), None);
                assert!(recovery.accepts_current_continuity(NativeContinuity::Existing));
                assert!(recovery.accepts_current_continuity(NativeContinuity::Unknown));
            }
        }
    }
    #[test]
    fn terminal_cannot_claim_unapplied_commit_or_hide_known_commit_pending_cleanup() {
        let d = edit_details(true, false);
        let success = outcome(Effect::Committed, Journal::Clean, CoreReason::None);
        assert!(!d.terminal_admissible(false, &success));
        assert!(d.terminal_admissible(true, &success));
        assert!(!d.terminal_admissible(
            true,
            &outcome(Effect::Unchanged, Journal::NotCreated, CoreReason::None)
        ));
        assert!(d.terminal_admissible(
            true,
            &outcome(
                Effect::Committed,
                Journal::RecoveryRequired,
                CoreReason::FilesystemError
            )
        ));
        let noop = edit_details(true, true);
        assert!(noop.terminal_admissible(
            true,
            &outcome(Effect::Unchanged, Journal::NotCreated, CoreReason::None)
        ));
        assert!(!noop.terminal_admissible(true, &success));
        let recovery = recovery_details("committed_cleanup", false);
        assert!(recovery.terminal_admissible(
            false,
            &outcome(
                Effect::Committed,
                Journal::RecoveryRequired,
                CoreReason::PendingState
            )
        ));
        assert!(!recovery.terminal_admissible(
            false,
            &outcome(
                Effect::NotStarted,
                Journal::RecoveryRequired,
                CoreReason::PendingState
            )
        ));
        assert!(!recovery.terminal_admissible(false, &success));
        assert!(recovery_details("committed_cleanup", true).terminal_admissible(true, &success));
    }
    #[test]
    fn recovery_actions_and_inventory_must_equal_the_original_review_not_renderer_paths() {
        let mut d = recovery_details("committed_cleanup", false);
        assert!(!d.admit_submission(Submission::Edit {
            desired_identity: NEW.into(),
            identity_intent: IdentityIntent::NewApplication
        }));
        assert!(d.admit_submission(Submission::Recover));
        let mut r = PreparedReply {
            intent: Intent::Recover,
            revision: REVISION.into(),
            plan_token: PLAN.into(),
            view: recovery_data("rollback"),
            scope_resources: ResourceState::Settled,
        };
        assert!(!d.accept_prepared(r));
        r = PreparedReply {
            intent: Intent::Recover,
            revision: REVISION.into(),
            plan_token: PLAN.into(),
            view: recovery_data("committed_cleanup"),
            scope_resources: ResourceState::Settled,
        };
        r.view["files"][0]["path"] = json!("other/build.gradle.kts");
        assert!(!d.accept_prepared(r));
    }
    #[test]
    fn private_codec_is_finite_and_cannot_cross_session_domain_or_expand_terminal() {
        let value = json!({"protocol":PROTOCOL,"session":SESSION,"seq":0,"kind":"opened","result":{
            "intent":"edit","revision":REVISION,"view":analysis_data(NativeContinuity::Unknown),"scopeResources":"settled"}});
        let encode = |value: &Value| {
            let mut raw = serde_json::to_vec(value).unwrap();
            raw.push(b'\n');
            raw
        };
        assert!(matches!(
            decode(&encode(&value), SESSION).unwrap(),
            ChildFrame::IdentityOpened(_)
        ));
        for (key, value) in [
            ("protocol", json!(edit::PROTOCOL)),
            ("session", json!("9".repeat(32))),
            ("seq", json!(3)),
            ("kind", json!("prepared")),
        ] {
            let mut bad = json!({"protocol":PROTOCOL,"session":SESSION,"seq":0,"kind":"opened","result":{
                "intent":"edit","revision":REVISION,"view":analysis_data(NativeContinuity::Unknown),"scopeResources":"settled"}});
            bad[key] = value;
            assert!(decode(&encode(&bad), SESSION).is_err());
        }
        let duplicate = String::from_utf8(encode(&value)).unwrap().replacen(
            "\"seq\":0",
            "\"seq\":0,\"seq\":0",
            1,
        );
        assert!(decode(duplicate.as_bytes(), SESSION).is_err());
        assert!(request(
            SESSION,
            3,
            "apply",
            json!({"planToken":PLAN,"intent":"edit"})
        )
        .is_err());
        assert!(request(
            SESSION,
            1,
            "prepare",
            json!({"revision":REVISION,"intent":"recover","desiredIdentity":NEW})
        )
        .is_err());
    }
}
