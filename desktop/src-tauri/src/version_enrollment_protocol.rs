//! Fixed current-counter review DATA. No account, Store floor or native grant
//! can be obtained by deserializing these values. No caller branch/path/SHA.
use crate::{
    error::BridgeError,
    github_connection_protocol::{bounds, coordinate, nullable, numeric_id, GitHubReadControl},
    github_preflight_protocol::hex,
    protocol::{strict_json, valid_id},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub(crate) const PROTOCOL: &str = "mrk-version-enrollment/1";
pub(crate) const INITIAL_LIMIT: usize = 8192;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const GO_LIMIT: usize = 8192;
pub(crate) const RESPONSE_LIMIT: usize = 8192;
pub(crate) const LEDGER_BRANCH: &str = "mrk-version-allocations";
pub(crate) const LEDGER_PATH: &str = "release/.mrk-version-allocations-v1.json";
// Existing code128MiB partition is separate. This quote is finite owned
// request/reply/state/control backing, NOT a CPython heap/RSS limit.
pub(crate) const RETAINED_LIMIT: usize = 8 * 1024 * 1024;

pub(crate) fn refused(reason: Reason) -> BridgeError {
    let code = serde_json::to_value(reason)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "invalid-input".into());
    BridgeError::new(&format!("version_enrollment_{}", code.replace('-', "_")),
        match reason {
            Reason::CounterMissing => "This repository has no supported shared version counter. Keep using manual versions.",
            Reason::ProtectionUnavailable | Reason::ProtectionUnsupported => "The counter branch needs supported, readable protection against deletion and force pushes.",
            Reason::CleanupUnknown => "Keep the original counter connection operation; its cleanup is unconfirmed.",
            Reason::ReviewChanged | Reason::TargetChanged => "The saved project, account or counter changed. Review it again after the original operation settles.",
            Reason::StateUnavailable => "The original private application state is unavailable; it was not reset.",
            Reason::StateTooLarge => "Saved counter state exceeds this connection path's size or complexity limit (256 KiB / 4,096 nodes). All records were kept. Continue with manual versions; do not delete or reset state.",
            _ => "The shared version counter could not be connected. Manual version editing is unchanged.",
        })
}
pub(crate) fn need(value: bool) -> Result<(), BridgeError> {
    if value {
        Ok(())
    } else {
        Err(BridgeError::protocol())
    }
}
/// Only the public action's BEFORE-installation error arm calls this. It is
/// not a mapping for arbitrary framework errors or post-admission failures.
pub(crate) fn not_started(error: BridgeError) -> BridgeError {
    let reason = match error.code.as_str() {
        "busy" | "version_enrollment_busy" => Some(Reason::Busy),
        "version_enrollment_not_connected" => Some(Reason::NotConnected),
        "version_enrollment_runtime_unavailable" => Some(Reason::RuntimeUnavailable),
        "version_enrollment_target_changed" => Some(Reason::TargetChanged),
        "version_enrollment_review_changed" => Some(Reason::ReviewChanged),
        "version_enrollment_rate_limited" => Some(Reason::RateLimited),
        _ => None,
    };
    match reason {
        Some(reason) => {
            let original = refused(reason);
            BridgeError::new(
                &original.code.replacen(
                    "version_enrollment_",
                    "version_enrollment_not_started_",
                    1,
                ),
                &original.message,
            )
        }
        None => error,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None,
    CounterMissing,
    ProtectionUnavailable,
    ProtectionUnsupported,
    AuthorityChanged,
    AuthorityRewound,
    LedgerInvalid,
    ReviewChanged,
    InvalidInput,
    Unauthorized,
    Forbidden,
    NotFoundOrInaccessible,
    TargetChanged,
    RateLimited,
    NetworkUnavailable,
    TlsFailed,
    ResponseInvalid,
    ResponseLimit,
    Expired,
    Cancelled,
    Busy,
    NotConnected,
    RuntimeUnavailable,
    CleanupUnknown,
    StateUnavailable,
    StateTooLarge,
    Connected,
}
impl Reason {
    fn wire(self) -> bool {
        !matches!(
            self,
            Self::Busy
                | Self::NotConnected
                | Self::RuntimeUnavailable
                | Self::CleanupUnknown
                | Self::StateUnavailable
                | Self::StateTooLarge
                | Self::Connected
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind {
    Review,
    Confirm,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Target {
    pub(crate) project_binding: String,
    pub(crate) repository: String,
    pub(crate) account_id: String,
    pub(crate) repository_id: String,
}
impl Target {
    pub(crate) fn valid(&self) -> bool {
        hex(&self.project_binding, 64)
            && coordinate(&self.repository)
            && numeric_id(&self.account_id)
            && numeric_id(&self.repository_id)
    }
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|i| value.as_bytes()[i] == b'-')
        && value.as_bytes()[14] == b'4'
        && b"89ab".contains(&value.as_bytes()[19])
        && value.bytes().enumerate().all(|(i, b)| {
            [8, 13, 18, 23].contains(&i) || b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
        })
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Authority {
    pub(crate) project_id: String,
    pub(crate) repository: String,
    pub(crate) repository_id: String,
    pub(crate) ledger_id: String,
    pub(crate) genesis_sha256: String,
    pub(crate) protected_branch: bool,
}
impl Authority {
    fn valid(&self) -> bool {
        (crate::service_protocol::Id::parse(&self.project_id).is_ok() || uuid(&self.project_id))
            && coordinate(&self.repository)
            && numeric_id(&self.repository_id)
            && uuid(&self.ledger_id)
            && hex(&self.genesis_sha256, 64)
            && self.protected_branch
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Checkpoint {
    pub(crate) sequence: u32,
    pub(crate) head_sha256: String,
    pub(crate) commit: String,
}
impl Checkpoint {
    fn valid(&self) -> bool {
        self.sequence <= 64 && hex(&self.head_sha256, 64) && hex(&self.commit, 40)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Version {
    pub(crate) name: String,
    pub(crate) build: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Offer {
    pub(crate) authority: Authority,
    pub(crate) checkpoint: Checkpoint,
    pub(crate) blob: String,
    pub(crate) version: Version,
}
impl Offer {
    pub(crate) fn valid(&self) -> bool {
        self.authority.valid()
            && self.checkpoint.valid()
            && hex(&self.blob, 40)
            && (self.checkpoint.sequence != 0
                || self.checkpoint.head_sha256 == self.authority.genesis_sha256)
            && (1..=2_100_000_000).contains(&self.version.build)
            && !self.version.name.is_empty()
            && self.version.name.len() <= 64
            && self
                .version
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
        // Shape only. Python validates exact Genesis + every reservation and
        // version policy; neither this parser nor an Offer is that execution.
    }
    pub(crate) fn matches(&self, target: &Target) -> bool {
        self.valid()
            && self.authority.repository == target.repository
            && self.authority.repository_id == target.repository_id
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) kind: Kind,
    pub(crate) target: Target,
    #[serde(deserialize_with = "nullable")]
    pub(crate) review: Option<Offer>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) previous: Option<Checkpoint>,
}
impl Request {
    pub(crate) fn valid(&self) -> bool {
        self.target.valid()
            && (self.kind == Kind::Confirm) == self.review.is_some()
            && self.review.as_ref().is_none_or(|o| o.matches(&self.target))
            && self
                .previous
                .as_ref()
                .is_none_or(|c| self.review.is_some() && c.valid())
    }
}
pub(crate) fn encode_initial(id: &str, request: &Request) -> Result<Vec<u8>, BridgeError> {
    need(valid_id(id) && request.valid())?;
    encode(
        &json!({"protocol":PROTOCOL,"id":id,"action":request}),
        INITIAL_LIMIT,
    )
}
fn encode(value: &Value, limit: usize) -> Result<Vec<u8>, BridgeError> {
    let mut raw = serde_json::to_vec(value).map_err(|_| BridgeError::protocol())?;
    raw.push(b'\n');
    need(raw.len() <= limit)?;
    Ok(raw)
}
fn frame(bytes: &[u8], maximum: usize, nodes: usize) -> Result<Value, BridgeError> {
    need((3..=maximum).contains(&bytes.len()) && bytes.last() == Some(&b'\n'))?;
    let body = &bytes[..bytes.len() - 1];
    need(
        body.first() == Some(&b'{')
            && body.last() == Some(&b'}')
            && !body.iter().any(|b| b"\r\n".contains(b)),
    )?;
    let value = strict_json(body)?;
    // No arrays in this profile, including Serde positional struct arrays.
    fn objects(v: &Value) -> bool {
        match v {
            Value::Array(_) => false,
            Value::Object(o) => o.values().all(objects),
            _ => true,
        }
    }
    need(bounds(&value, maximum, nodes, 8) && objects(&value))?;
    Ok(value)
}
pub(crate) fn decode_ready(bytes: &[u8], id: &str, digest: &str) -> Result<(), BridgeError> {
    need(
        frame(bytes, READY_LIMIT, 32)?
            == json!({"protocol":PROTOCOL,"id":id,"ready":{"requestSha256":digest}}),
    )
}
pub(crate) fn encode_go(id: &str, digest: &str, token: &str) -> Result<Vec<u8>, BridgeError> {
    need(
        valid_id(id)
            && hex(digest, 64)
            && !token.is_empty()
            && token.len() <= 4096
            && token.bytes().all(|b| (0x21..=0x7e).contains(&b)),
    )?;
    // Borrow the SAME connection token into one private writer buffer; never
    // make a token-bearing Value/DTO or a second retained String.
    let mut raw = Vec::with_capacity(GO_LIMIT);
    raw.extend_from_slice(b"{\"protocol\":\"mrk-version-enrollment/1\",\"id\":");
    serde_json::to_writer(&mut raw, id).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b",\"go\":{\"requestSha256\":");
    serde_json::to_writer(&mut raw, digest).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b",\"token\":");
    let escaped = token.bytes().filter(|b| matches!(b, b'"' | b'\\')).count();
    need(raw.len() + token.len() + escaped + 5 <= GO_LIMIT)?; // quotes + }} + LF
    serde_json::to_writer(&mut raw, token).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b"}}\n");
    Ok(raw)
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResultValue {
    schema_version: u32,
    pub(crate) reason: Reason,
    #[serde(deserialize_with = "nullable")]
    pub(crate) offer: Option<Offer>,
    pub(crate) control: GitHubReadControl,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reply {
    protocol: String,
    id: String,
    pub(crate) result: ResultValue,
}
pub(crate) fn decode_reply(
    id: &str,
    bytes: &[u8],
    request: &Request,
) -> Result<Reply, BridgeError> {
    let value: Reply = serde_json::from_value(frame(bytes, RESPONSE_LIMIT, 256)?)
        .map_err(|_| BridgeError::protocol())?;
    let r = &value.result;
    need(
        value.protocol == PROTOCOL
            && value.id == id
            && request.valid()
            && r.schema_version == 1
            && r.reason.wire()
            && r.control.valid()
            && (r.reason == Reason::None) == r.offer.is_some()
            && r.offer.as_ref().is_none_or(|o| {
                o.matches(&request.target)
                    && request.review.as_ref().is_none_or(|review| review == o)
                    && r.control.reason == crate::github_connection_protocol::Reason::None
            }),
    )?;
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Idle,
    Reading,
    Connecting,
    Reviewed,
    Connected,
    Refused,
    Stopping,
    CleanupUnknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewView {
    pub(crate) id: String,
    pub(crate) repository: String,
    pub(crate) version: Version,
    pub(crate) reservations: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32,
    pub(crate) revision: u32,
    pub(crate) project_id: Option<String>,
    pub(crate) operation_id: Option<String>,
    pub(crate) phase: Phase,
    pub(crate) reason: Reason,
    pub(crate) review: Option<ReviewView>,
}
impl Status {
    pub(crate) fn idle() -> Self {
        Self {
            schema_version: 1,
            revision: 1,
            project_id: None,
            operation_id: None,
            phase: Phase::Idle,
            reason: Reason::None,
            review: None,
        }
    }
}

/// Renderer requests have no paths, authority/account IDs, hashes, floors or
/// state bytes. The original Document derives every such private input.
pub(crate) enum Command {
    Status,
    Review(String),
    Confirm {
        project_id: String,
        review_id: String,
    },
    Cancel(String),
}
pub(crate) fn decode_command(name: &str, raw: &[u8]) -> Result<Command, BridgeError> {
    need(!raw.is_empty() && raw.len() <= INITIAL_LIMIT)?;
    let value = strict_json(raw)?;
    let object = value.as_object().ok_or_else(BridgeError::invalid)?;
    let field = |key: &str| -> Result<String, BridgeError> {
        object
            .get(key)
            .and_then(Value::as_str)
            .filter(|id| valid_id(id))
            .map(str::to_owned)
            .ok_or_else(BridgeError::invalid)
    };
    match name {
        "version_enrollment_status" if object.is_empty() => Ok(Command::Status),
        "version_enrollment_review" if object.len() == 1 => {
            Ok(Command::Review(field("projectId")?))
        }
        "version_enrollment_confirm" if object.len() == 2 => {
            let project_id = field("projectId")?;
            let review_id = field("reviewId")?;
            need(crate::service_protocol::Id::parse(&review_id).is_ok())?;
            Ok(Command::Confirm {
                project_id,
                review_id,
            })
        }
        "version_enrollment_cancel" if object.len() == 1 => {
            let id = field("operationId")?;
            need(crate::service_protocol::Id::parse(&id).is_ok())?;
            Ok(Command::Cancel(id))
        }
        _ => Err(BridgeError::invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn offer() -> Offer {
        Offer {
            authority: Authority {
                project_id: "a".repeat(32),
                repository: "fixture/app".into(),
                repository_id: "123".into(),
                ledger_id: "00000000-0000-4000-8000-000000000003".into(),
                genesis_sha256: "b".repeat(64),
                protected_branch: true,
            },
            checkpoint: Checkpoint {
                sequence: 1,
                head_sha256: "c".repeat(64),
                commit: "d".repeat(40),
            },
            blob: "e".repeat(40),
            version: Version {
                name: "1.2.3".into(),
                build: 7,
            },
        }
    }
    fn request() -> Request {
        Request {
            kind: Kind::Review,
            target: Target {
                project_binding: "f".repeat(64),
                repository: "fixture/app".into(),
                account_id: "456".into(),
                repository_id: "123".into(),
            },
            review: None,
            previous: None,
        }
    }
    #[test]
    fn exact_ready_go_and_offer_control_coherence() {
        let request = request();
        let initial = encode_initial("fixture-read", &request).unwrap();
        let digest = crate::github_preflight_protocol::request_digest(&initial);
        let ready = encode(
            &json!({"protocol":PROTOCOL,"id":"fixture-read","ready":{"requestSha256":digest}}),
            READY_LIMIT,
        )
        .unwrap();
        decode_ready(&ready, "fixture-read", &digest).unwrap();
        assert!(decode_ready(&ready, "other", &digest).is_err());
        let go = encode_go("fixture-read", &digest, "fixture-token").unwrap();
        assert!(go.len() <= GO_LIMIT);
        let control = json!({"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false});
        let mut value = json!({"protocol":PROTOCOL,"id":"fixture-read","result":{"schemaVersion":1,"reason":"none","offer":offer(),"control":control}});
        decode_reply(
            "fixture-read",
            &encode(&value, RESPONSE_LIMIT).unwrap(),
            &request,
        )
        .unwrap();
        value["result"]["control"]["reason"] = json!("cancelled");
        assert!(decode_reply(
            "fixture-read",
            &encode(&value, RESPONSE_LIMIT).unwrap(),
            &request
        )
        .is_err());
        value["result"]["offer"] = Value::Null;
        value["result"]["reason"] = json!("cancelled");
        decode_reply(
            "fixture-read",
            &encode(&value, RESPONSE_LIMIT).unwrap(),
            &request,
        )
        .unwrap();
    }
    #[test]
    fn native_frame_rejects_positional_or_foreign_offer_and_previous_without_review() {
        let mut request = request();
        request.previous = Some(offer().checkpoint);
        assert!(encode_initial("fixture-read", &request).is_err());
        request.previous = None;
        assert!(frame(b"{\"result\":[]}\n", RESPONSE_LIMIT, 256).is_err());
        assert!(frame(b"{\"id\":1,\"id\":2}\n", RESPONSE_LIMIT, 256).is_err());
        let mut wrong = offer();
        wrong.authority.repository = "elsewhere/app".into();
        assert!(!wrong.matches(&request.target));
        let mut genesis = offer();
        genesis.checkpoint.sequence = 0;
        assert!(!genesis.valid());
    }
    #[test]
    fn renderer_commands_are_closed_and_do_not_accept_authority_or_state() {
        assert!(matches!(
            decode_command("version_enrollment_status", b"{}"),
            Ok(Command::Status)
        ));
        assert!(matches!(
            decode_command("version_enrollment_review", br#"{"projectId":"project-1"}"#),
            Ok(Command::Review(_))
        ));
        let confirm = json!({"projectId":"project-1","reviewId":"a".repeat(32)});
        assert!(matches!(
            decode_command(
                "version_enrollment_confirm",
                &serde_json::to_vec(&confirm).unwrap()
            ),
            Ok(Command::Confirm { .. })
        ));
        for bytes in [
            br#"{"projectId":"project-1","authority":{}}"#.as_slice(),
            br#"{"projectId":"project-1","projectId":"project-2"}"#,
            br#"["project-1"]"#,
            br#"{"projectId":null}"#,
        ] {
            assert!(decode_command("version_enrollment_review", bytes).is_err());
        }
        assert!(decode_command(
            "version_enrollment_cancel",
            br#"{"operationId":"project-1"}"#
        )
        .is_err());
        assert!(decode_command("arbitrary_call", b"{}").is_err());
        assert!(
            decode_command("version_enrollment_status", &vec![b' '; INITIAL_LIMIT + 1]).is_err()
        );
    }
    #[test]
    fn go_escapes_into_one_private_buffer_and_refuses_expansion_before_token_write() {
        let token = "inert\\\"value";
        let raw = encode_go("op", &"f".repeat(64), token).unwrap();
        let value: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["go"]["token"], token);
        assert!(encode_go("op", &"f".repeat(64), &"\\".repeat(4096)).is_err());
    }
}
