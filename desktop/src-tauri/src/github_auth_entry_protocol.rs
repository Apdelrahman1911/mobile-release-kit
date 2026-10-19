//! Closed public DATA for the selected-account GitHub CLI entry.
//! No path, token, environment, provider nomination, process or native proof can
//! be supplied through this protocol. Authentication remains the existing
//! GitHub connection protocol's /user result, never an auth-progress phase.
use crate::{
    error::BridgeError,
    github_connection_protocol::{self as connection, Reason},
    protocol::{strict_json, valid_id},
};
use serde::Serialize;
use serde_json::Value;

pub(crate) const REQUEST_LIMIT: usize = 1024;
pub(crate) const PATH_LIMIT: usize = 4096;
// Includes the one retained historical ConnectionStatus and its serialization
// overlap, status/path/input cells and fixed native panel/control backing. The
// actual original admission adds this to its existing working reservation.
pub(crate) const ENTRY_BACKING: usize = 256 * 1024;

pub(crate) struct Connect {
    pub(crate) project_id: String,
    pub(crate) repository: String,
    pub(crate) selected_login: String,
    pub(crate) expected_document_revision: u32,
    pub(crate) expected_connection_revision: u32,
}
impl Connect {
    pub(crate) fn bounded(&self) -> bool {
        valid_id(&self.project_id)
            && connection::coordinate(&self.repository)
            && login(&self.selected_login)
            && revision(self.expected_document_revision)
            && revision(self.expected_connection_revision)
            && self
                .project_id
                .capacity()
                .checked_add(self.repository.capacity())
                .and_then(|bytes| bytes.checked_add(self.selected_login.capacity()))
                .is_some_and(|bytes| bytes <= REQUEST_LIMIT)
    }
}
pub(crate) enum Command {
    Status,
    Connect(Connect),
    Cancel { operation_id: String },
}
pub(crate) fn login(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 39
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}
fn revision(value: u32) -> bool {
    value != 0 && value != u32::MAX
}
fn decode_command_value(name: &str, value: &Value) -> Result<Command, BridgeError> {
    let fields = value.as_object().ok_or_else(BridgeError::invalid)?;
    let exact = |names: &[&str]| {
        fields.len() == names.len() && names.iter().all(|name| fields.contains_key(*name))
    };
    let text = |key: &str| {
        fields
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(BridgeError::invalid)
    };
    let count = |key: &str| {
        fields
            .get(key)
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| revision(*value))
            .ok_or_else(BridgeError::invalid)
    };
    match name {
        "github_auth_status" if exact(&[]) => Ok(Command::Status),
        "github_auth_connect"
            if exact(&[
                "projectId",
                "repository",
                "selectedLogin",
                "expectedDocumentRevision",
                "expectedConnectionRevision",
            ]) =>
        {
            // Check each borrowed scalar before copying. No generic recursive
            // serialization or permissive serde Value clone of caller input.
            let (project, repository, selected) = (
                text("projectId")?,
                text("repository")?,
                text("selectedLogin")?,
            );
            if !valid_id(project) || !connection::coordinate(repository) || !login(selected) {
                return Err(BridgeError::invalid());
            }
            let input = Connect {
                project_id: project.into(),
                repository: repository.into(),
                selected_login: selected.into(),
                expected_document_revision: count("expectedDocumentRevision")?,
                expected_connection_revision: count("expectedConnectionRevision")?,
            };
            if !input.bounded() {
                return Err(BridgeError::invalid());
            }
            Ok(Command::Connect(input))
        }
        "github_auth_cancel" if exact(&["operationId"]) => {
            let operation = text("operationId")?;
            if !valid_id(operation) {
                return Err(BridgeError::invalid());
            }
            Ok(Command::Cancel {
                operation_id: operation.into(),
            })
        }
        _ => Err(BridgeError::invalid()),
    }
}
/// The three native handlers admit RAW bytes only through this exact decoder.
/// Size and duplicate-key rejection therefore precede any command allocation,
/// not merely a synthetic test or an already-collapsed JSON Value.
pub(crate) fn decode_command(name: &str, bytes: &[u8]) -> Result<Command, BridgeError> {
    if bytes.len().saturating_add(name.len()).saturating_add(32) > REQUEST_LIMIT {
        return Err(BridgeError::invalid());
    }
    let value = strict_json(bytes).map_err(|_| BridgeError::invalid())?;
    decode_command_value(name, &value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Idle,
    Picking,
    Running,
    CheckingIdentity,
    Stopping,
    Settled,
    Failed,
    CleanupUnknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpHandoff {
    pub(crate) session_id: String,
    pub(crate) operation_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32,
    pub(crate) document_revision: u32,
    pub(crate) connection_revision: u32,
    pub(crate) available: bool,
    pub(crate) operation_id: Option<String>,
    pub(crate) project_id: Option<String>,
    pub(crate) repository: Option<String>,
    // This is an explicitly requested but unverified selection until /user.
    pub(crate) selected_login: Option<String>,
    pub(crate) phase: Phase,
    pub(crate) reason: Reason,
    pub(crate) http: Option<HttpHandoff>,
}
impl Status {
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>();
        for text in [
            &self.operation_id,
            &self.project_id,
            &self.repository,
            &self.selected_login,
        ] {
            bytes = bytes.checked_add(text.as_ref().map_or(0, String::capacity))?;
        }
        if let Some(http) = &self.http {
            bytes = bytes
                .checked_add(http.session_id.capacity())?
                .checked_add(http.operation_id.capacity())?;
        }
        Some(bytes)
    }
}
// One-use response DATA, deliberately not Clone. In particular, returning this
// cannot confer the original native owner or reproduce a token handoff.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectResult {
    pub(crate) schema_version: u32,
    pub(crate) operation_id: String,
    #[serde(flatten)]
    pub(crate) outcome: Outcome,
}
#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub(crate) enum Outcome {
    HttpHandoff { connection: connection::Status },
    NoHttp { auth: Status },
    Unknown { auth: Status },
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> Value {
        serde_json::json!({"projectId":"fixture-project","repository":"fixture-owner/fixture-repo",
            "selectedLogin":"fixture-login","expectedDocumentRevision":1,"expectedConnectionRevision":2})
    }
    #[test]
    fn exact_three_commands_never_accept_paths_tokens_roles_or_environment() {
        assert!(matches!(
            decode_command("github_auth_status", b"{}"),
            Ok(Command::Status)
        ));
        assert!(matches!(
            decode_command_value("github_auth_connect", &input()),
            Ok(Command::Connect(_))
        ));
        assert!(matches!(
            decode_command(
                "github_auth_cancel",
                br#"{"operationId":"fixture-operation"}"#
            ),
            Ok(Command::Cancel { .. })
        ));
        for field in [
            "path",
            "physicalExecutable",
            "token",
            "environment",
            "provider",
            "role",
            "argv",
        ] {
            let mut value = input();
            value[field] = Value::String("not-authority".into());
            assert!(decode_command_value("github_auth_connect", &value).is_err());
        }
        for name in [
            "github_auth_list",
            "github_auth_status_online",
            "github_auth_refresh",
            "exec",
        ] {
            assert!(decode_command(name, b"{}").is_err());
        }
    }
    #[test]
    fn identities_login_and_expected_revisions_are_bounded_before_admission() {
        for bad in [
            "",
            "-flag",
            "space name",
            "user@host",
            "a/b",
            "a\n",
            "é",
            "tail-",
            &"a".repeat(40),
        ] {
            let mut value = input();
            value["selectedLogin"] = Value::String(bad.into());
            assert!(decode_command_value("github_auth_connect", &value).is_err());
        }
        for bad in [
            Value::Null,
            Value::Bool(true),
            Value::from(0),
            Value::from(-1),
            Value::from(1.5),
            Value::from(u32::MAX),
            Value::from(u64::MAX),
        ] {
            for field in ["expectedDocumentRevision", "expectedConnectionRevision"] {
                let mut value = input();
                value[field] = bad.clone();
                assert!(decode_command_value("github_auth_connect", &value).is_err());
            }
        }
        let mut value = input();
        value["repository"] = Value::String("https://github.com/owner/repo".into());
        assert!(decode_command_value("github_auth_connect", &value).is_err());
        value = input();
        value["projectId"] = Value::String("../elsewhere".into());
        assert!(decode_command_value("github_auth_connect", &value).is_err());
    }
    #[test]
    fn strict_raw_decoder_refuses_duplicates_and_bounded_unknown_bodies() {
        assert!(decode_command(
            "github_auth_cancel",
            br#"{"operationId":"first","operationId":"second"}"#
        )
        .is_err());
        assert!(decode_command("github_auth_status", &vec![b' '; REQUEST_LIMIT]).is_err());
        assert!(decode_command("github_auth_status", b"null").is_err());
        assert!(decode_command("github_auth_status", br#"{"x":{}}"#).is_err());
    }
    #[test]
    fn cancellation_has_no_stale_revision_gate_to_block_stop() {
        assert!(decode_command(
            "github_auth_cancel",
            br#"{"operationId":"fixture-operation"}"#
        )
        .is_ok());
        assert!(decode_command(
            "github_auth_cancel",
            br#"{"operationId":"fixture-operation","expectedDocumentRevision":1}"#
        )
        .is_err());
    }
}
