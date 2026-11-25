//! Public device DATA and the distinct PRIVATE worker framing. The private
//! request/terminal/token types deliberately implement no Debug/Serialize.
use crate::{
    error::BridgeError,
    github_connection_protocol as connection,
    protocol::{strict_json, valid_id},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(crate) const CLIENT_ID: Option<&str> = None; // Owner's device-enabled OAuth App; never gh's identity.
pub(crate) const CONSENT: &str = "github-device-session-repo-v1";
pub(crate) const VERIFY: &str = "https://github.com/login/device";
pub(crate) const PROTOCOL: &str = "mrk-github-device/1";
pub(crate) const REQUEST_LIMIT: usize = 16384;
pub(crate) const RESPONSE_LIMIT: usize = 16384;
pub(crate) const WORK_SECONDS: u64 = 10;
pub(crate) const HARD_SECONDS: u64 = 12;
pub(crate) const ENTRY_BACKING: usize = 256 * 1024;
pub(crate) fn client(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
pub(crate) fn configured() -> Option<&'static str> {
    CLIENT_ID.filter(|id| client(id))
}
fn revision(value: u32) -> bool {
    value != 0 && value != u32::MAX
}
fn printable(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
fn user_code(value: &str) -> bool {
    value.len() == 9
        && value.as_bytes()[4] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 4 || b.is_ascii_uppercase() || b.is_ascii_digit())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Idle,
    Starting,
    Pending,
    Checking,
    Connecting,
    Stopping,
    Settled,
    Failed,
    CleanupUnknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None,
    PublisherUnconfigured,
    RuntimeUnavailable,
    Busy,
    TargetChanged,
    Waiting,
    SlowDown,
    Denied,
    Expired,
    ClientRefused,
    ResponseInvalid,
    Cancelled,
    CleanupUnknown,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Code {
    pub(crate) user_code: String,
    pub(crate) verification_uri: &'static str,
    pub(crate) remaining_seconds: u32,
    pub(crate) check_after_seconds: u32,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Http {
    pub(crate) session_id: String,
    pub(crate) operation_id: String,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32,
    pub(crate) document_revision: u32,
    pub(crate) connection_revision: u32,
    pub(crate) available: bool,
    pub(crate) operation_id: Option<String>,
    pub(crate) project_id: Option<String>,
    pub(crate) repository: Option<String>,
    pub(crate) revision: u32,
    pub(crate) phase: Phase,
    pub(crate) reason: Reason,
    pub(crate) code: Option<Code>,
    pub(crate) http: Option<Http>,
}
impl Status {
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let mut n = std::mem::size_of::<Self>();
        for text in [&self.operation_id, &self.project_id, &self.repository] {
            n = n.checked_add(text.as_ref().map_or(0, String::capacity))?;
        }
        if let Some(code) = &self.code {
            n = n.checked_add(code.user_code.capacity())?;
        }
        if let Some(http) = &self.http {
            n = n
                .checked_add(http.session_id.capacity())?
                .checked_add(http.operation_id.capacity())?;
        }
        (n <= 8192).then_some(n)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start {
    pub(crate) project_id: String,
    pub(crate) repository: String,
    pub(crate) expected_document_revision: u32,
    pub(crate) expected_connection_revision: u32,
    pub(crate) consent_version: String,
}
impl Start {
    pub(crate) fn valid(&self) -> bool {
        valid_id(&self.project_id)
            && connection::coordinate(&self.repository)
            && revision(self.expected_document_revision)
            && revision(self.expected_connection_revision)
            && self.consent_version == CONSENT
            && self.project_id.capacity()
                + self.repository.capacity()
                + self.consent_version.capacity()
                <= 1024
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Selected {
    pub(crate) operation_id: String,
    pub(crate) revision: u32,
}
pub(crate) enum Command {
    Status,
    Start(Start),
    Check(Selected),
    Open(Selected),
    Cancel(String),
}
pub(crate) fn command(name: &str, raw: &[u8]) -> Result<Command, BridgeError> {
    if raw.len() + name.len() + 32 > 1024 {
        return Err(BridgeError::invalid());
    }
    let value = strict_json(raw).map_err(|_| BridgeError::invalid())?;
    match name {
        "github_device_status" if value.as_object().is_some_and(|o| o.is_empty()) => {
            Ok(Command::Status)
        }
        "github_device_start" => {
            let v: Start = serde_json::from_value(value).map_err(|_| BridgeError::invalid())?;
            if !v.valid() {
                return Err(BridgeError::invalid());
            }
            Ok(Command::Start(v))
        }
        "github_device_check" | "github_device_open" => {
            let v: Selected = serde_json::from_value(value).map_err(|_| BridgeError::invalid())?;
            if !valid_id(&v.operation_id) || !revision(v.revision) {
                return Err(BridgeError::invalid());
            }
            Ok(if name == "github_device_check" {
                Command::Check(v)
            } else {
                Command::Open(v)
            })
        }
        "github_device_cancel" => {
            let o = value.as_object().ok_or_else(BridgeError::invalid)?;
            let id = o
                .get("operationId")
                .and_then(|v| v.as_str())
                .filter(|id| valid_id(id))
                .ok_or_else(BridgeError::invalid)?;
            if o.len() != 1 {
                return Err(BridgeError::invalid());
            }
            Ok(Command::Cancel(id.into()))
        }
        _ => Err(BridgeError::invalid()),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Role {
    Start,
    Poll,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Context {
    pub(crate) operation_id: String,
    pub(crate) project_id: String,
    pub(crate) repository: String,
    pub(crate) generation: u32,
    pub(crate) sequence: u32,
}
impl Context {
    pub(crate) fn valid(&self) -> bool {
        valid_id(&self.operation_id)
            && valid_id(&self.project_id)
            && connection::coordinate(&self.repository)
            && self.generation != 0
            && self.sequence <= 120
    }
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Clock {
    pub(crate) work_end_ns: u64,
    pub(crate) hard_end_ns: u64,
}
impl Clock {
    pub(crate) fn valid(self) -> bool {
        self.work_end_ns > 0
            && self.hard_end_ns <= i64::MAX as u64
            && self
                .hard_end_ns
                .checked_sub(self.work_end_ns)
                .is_some_and(|n| n > 0 && n <= 2_000_000_000)
    }
}
pub(crate) struct Request {
    raw: Zeroizing<Vec<u8>>,
    digest: String,
    id: String,
    role: Role,
}
impl Request {
    pub(crate) fn new(
        id: &str,
        role: Role,
        context: &Context,
        client_id: &str,
        device_code: Option<&str>,
        clock: Clock,
    ) -> Result<Self, BridgeError> {
        if !valid_id(id)
            || !context.valid()
            || !client(client_id)
            || !clock.valid()
            || match role {
                Role::Start => context.sequence != 0 || device_code.is_some(),
                Role::Poll => {
                    context.sequence == 0 || !device_code.is_some_and(|c| printable(c, 1024))
                }
            }
        {
            return Err(BridgeError::invalid());
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Initial<'a> {
            protocol: &'static str,
            id: &'a str,
            role: Role,
            context: &'a Context,
            client_id: &'a str,
            device_code: Option<&'a str>,
            clock: Clock,
        }
        let mut raw = Zeroizing::new(
            serde_json::to_vec(&Initial {
                protocol: PROTOCOL,
                id,
                role,
                context,
                client_id,
                device_code,
                clock,
            })
            .map_err(|_| BridgeError::invalid())?,
        );
        if raw.len() >= REQUEST_LIMIT || raw.contains(&b'\n') {
            return Err(BridgeError::invalid());
        }
        raw.push(b'\n');
        Ok(Self {
            digest: Sha256::digest(&*raw)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            raw,
            id: id.into(),
            role,
        })
    }
    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub(crate) fn digest(&self) -> String {
        self.digest.clone()
    }
    pub(crate) fn role(&self) -> Role {
        self.role
    }
    fn control(&self, kind: &str) -> Vec<u8> {
        format!("{{\"protocol\":\"{}\",\"id\":\"{}\",\"role\":\"{}\",\"requestSha256\":\"{}\",\"kind\":\"{}\"}}\n",PROTOCOL,self.id,if self.role==Role::Start{"start"}else{"poll"},self.digest,kind).into_bytes()
    }
    pub(crate) fn ready(&self) -> Vec<u8> {
        self.control("ready")
    }
    pub(crate) fn go(&self) -> Vec<u8> {
        self.control("go")
    }
    pub(crate) fn terminal(&self, raw: Zeroizing<Vec<u8>>) -> Result<Terminal, BridgeError> {
        let parsed = parse_terminal(&raw)?;
        if parsed.protocol != PROTOCOL
            || parsed.id != self.id
            || parsed.role
                != if self.role == Role::Start {
                    "start"
                } else {
                    "poll"
                }
            || parsed.request_sha256 != self.digest
        {
            return Err(BridgeError::protocol());
        }
        validate_terminal(&parsed, self.role)?;
        Ok(Terminal {
            raw,
            role: self.role,
        })
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ParsedTerminal<'a> {
    #[serde(borrow)]
    protocol: &'a str,
    id: &'a str,
    role: &'a str,
    request_sha256: &'a str,
    status: &'a str,
    #[serde(deserialize_with = "present")]
    first_failure_ns: Option<u64>,
    #[serde(borrow, deserialize_with = "present")]
    reply: Option<ParsedReply<'a>>,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ParsedReply<'a> {
    Code {
        #[serde(borrow, rename = "deviceCode")]
        device_code: &'a str,
        #[serde(rename = "userCode")]
        user_code: &'a str,
        #[serde(rename = "expiresIn")]
        expires_in: u32,
        interval: u32,
    },
    Token {
        #[serde(borrow)]
        token: &'a str,
        scopes: Vec<&'a str>,
        #[serde(rename = "expiresIn", deserialize_with = "present")]
        expires_in: Option<u32>,
    },
    // Empty structs, not unit variants: Serde's internally tagged unit
    // visitor ignores extra fields even with deny_unknown_fields.
    Pending {},
    SlowDown {},
    Expired {},
    Denied {},
    ClientRefused {},
    Invalid {},
}
fn present<'de, D, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(d)
}
fn parse_terminal(raw: &[u8]) -> Result<ParsedTerminal<'_>, BridgeError> {
    if raw.len() > RESPONSE_LIMIT
        || raw.last() != Some(&b'\n')
        || raw.iter().filter(|b| **b == b'\n').count() != 1
    {
        return Err(BridgeError::protocol());
    }
    // Borrowed typed decoding rejects duplicate/unknown fields before any
    // secret String allocation. No generic Value (non-zeroizing token copy).
    serde_json::from_slice(raw).map_err(|_| BridgeError::protocol())
}
fn validate_terminal(value: &ParsedTerminal<'_>, role: Role) -> Result<(), BridgeError> {
    if value
        .first_failure_ns
        .is_some_and(|at| at == 0 || at > i64::MAX as u64)
        || (value.status == "ok" && value.first_failure_ns.is_some())
    {
        return Err(BridgeError::protocol());
    }
    if value.status == "cleanup-unknown" {
        return Err(BridgeError::cleanup_unknown());
    }
    if value.status != "ok" {
        return if ["refused", "cancelled", "timed-out"].contains(&value.status)
            && value.reply.is_none()
        {
            Ok(())
        } else {
            Err(BridgeError::protocol())
        };
    }
    let valid = match value.reply.as_ref() {
        Some(ParsedReply::Code {
            device_code,
            user_code: code,
            expires_in,
            interval,
        }) => {
            role == Role::Start
                && printable(device_code, 1024)
                && user_code(code)
                && (1..=900).contains(expires_in)
                && (5..=900).contains(interval)
        }
        Some(ParsedReply::Token {
            token,
            scopes,
            expires_in,
        }) => {
            role == Role::Poll
                && printable(token, 4096)
                && scopes.len() <= 32
                && expires_in.is_none_or(|v| v > 0)
                && scopes.iter().enumerate().all(|(i, s)| {
                    !s.is_empty()
                        && s.len() <= 64
                        && s.as_bytes()[0].is_ascii_lowercase()
                        && s.bytes().all(|b| {
                            b.is_ascii_lowercase() || b.is_ascii_digit() || b"_:.-".contains(&b)
                        })
                        && !scopes[..i].contains(s)
                })
        }
        Some(
            ParsedReply::Pending {}
            | ParsedReply::SlowDown {}
            | ParsedReply::Expired {}
            | ParsedReply::Denied {},
        ) => role == Role::Poll,
        Some(ParsedReply::ClientRefused {} | ParsedReply::Invalid {}) => true,
        None => false,
    };
    if valid {
        Ok(())
    } else {
        Err(BridgeError::protocol())
    }
}
pub(crate) enum Reply {
    Code {
        device: Zeroizing<String>,
        user: String,
        expires: u32,
        interval: u32,
    },
    Token {
        token: Zeroizing<String>,
        expires: Option<u32>,
    },
    Pending,
    SlowDown,
    Refused(Reason),
}
pub(crate) struct Terminal {
    raw: Zeroizing<Vec<u8>>,
    role: Role,
}
impl Terminal {
    pub(crate) fn first_failure_ns(&self) -> Result<Option<u64>, BridgeError> {
        Ok(parse_terminal(&self.raw)?.first_failure_ns)
    }
    pub(crate) fn result(self) -> Result<Reply, BridgeError> {
        let value = parse_terminal(&self.raw)?;
        validate_terminal(&value, self.role)?;
        match value.status {
            "cancelled" => {
                return Err(BridgeError::new(
                    "cancelled",
                    "The device connection was stopped.",
                ))
            }
            "timed-out" => return Err(BridgeError::timeout()),
            "refused" => {
                return Err(BridgeError::new(
                    "device_refused",
                    "The device connection was refused.",
                ))
            }
            "ok" => {}
            _ => return Err(BridgeError::protocol()),
        }
        Ok(match value.reply.ok_or_else(BridgeError::protocol)? {
            ParsedReply::Code {
                device_code,
                user_code,
                expires_in,
                interval,
            } => Reply::Code {
                device: Zeroizing::new(device_code.into()),
                user: user_code.into(),
                expires: expires_in,
                interval,
            },
            ParsedReply::Token {
                token, expires_in, ..
            } => Reply::Token {
                token: Zeroizing::new(token.into()),
                expires: expires_in,
            },
            ParsedReply::Pending {} => Reply::Pending,
            ParsedReply::SlowDown {} => Reply::SlowDown,
            ParsedReply::Expired {} => Reply::Refused(Reason::Expired),
            ParsedReply::Denied {} => Reply::Refused(Reason::Denied),
            ParsedReply::ClientRefused {} => Reply::Refused(Reason::ClientRefused),
            ParsedReply::Invalid {} => Reply::Refused(Reason::ResponseInvalid),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_publisher_is_not_a_borrowed_gh_application() {
        assert!(configured().is_none());
        assert!(!client(""));
        assert!(!client("client?secret"));
    }
    #[test]
    fn exact_public_request_cannot_supply_token_code_or_provider() {
        let raw=br#"{"projectId":"project","repository":"owner/repo","expectedDocumentRevision":1,"expectedConnectionRevision":1,"consentVersion":"github-device-session-repo-v1"}"#;
        assert!(matches!(
            command("github_device_start", raw),
            Ok(Command::Start(_))
        ));
        for extra in ["token", "clientId", "deviceCode", "endpoint"] {
            let s = String::from_utf8(raw.to_vec())
                .unwrap()
                .replace("{", &format!("{{\"{extra}\":\"private\","));
            assert!(command("github_device_start", s.as_bytes()).is_err());
        }
        assert!(command("github_device_status", br#"{"x":1,"x":2}"#).is_err());
    }
    #[test]
    fn private_terminal_correlation_and_mixed_reply_refuse_before_consumption() {
        let context = Context {
            operation_id: "device-1".into(),
            project_id: "project".into(),
            repository: "owner/repo".into(),
            generation: 1,
            sequence: 1,
        };
        let request = Request::new(
            "child-1",
            Role::Poll,
            &context,
            "inert-client",
            Some("inert-code"),
            Clock {
                work_end_ns: 1,
                hard_end_ns: 2,
            },
        )
        .unwrap();
        let raw=format!("{{\"protocol\":\"{PROTOCOL}\",\"id\":\"child-1\",\"role\":\"poll\",\"requestSha256\":\"{}\",\"status\":\"ok\",\"firstFailureNs\":null,\"reply\":{{\"kind\":\"pending\"}}}}\n",request.digest());
        assert!(matches!(
            request
                .terminal(Zeroizing::new(raw.as_bytes().to_vec()))
                .unwrap()
                .result(),
            Ok(Reply::Pending)
        ));
        for bad in [
            raw.replace("child-1", "child-2"),
            raw.replace("\"pending\"", "\"pending\",\"token\":\"private\""),
            raw.clone() + "\n",
        ] {
            assert!(request.terminal(Zeroizing::new(bad.into_bytes())).is_err());
        }
        for kind in [
            "pending",
            "slow-down",
            "expired",
            "denied",
            "client-refused",
            "invalid",
        ] {
            let tag = format!("\"{kind}\"");
            let frame = raw.replace("\"pending\"", &tag);
            let reply = request
                .terminal(Zeroizing::new(frame.as_bytes().to_vec()))
                .unwrap()
                .result()
                .unwrap();
            assert!(matches!(
                (kind, reply),
                ("pending", Reply::Pending)
                    | ("slow-down", Reply::SlowDown)
                    | ("expired", Reply::Refused(Reason::Expired))
                    | ("denied", Reply::Refused(Reason::Denied))
                    | ("client-refused", Reply::Refused(Reason::ClientRefused))
                    | ("invalid", Reply::Refused(Reason::ResponseInvalid))
            ));
            for extra in ["token", "deviceCode", "unexpected"] {
                let bad = frame.replace(&tag, &format!("{tag},\"{extra}\":\"private\""));
                assert!(request.terminal(Zeroizing::new(bad.into_bytes())).is_err());
            }
        }
    }
}
