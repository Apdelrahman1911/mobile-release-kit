//! Fixed PRIVATE worker framing, never an IPC/public command or token DTO.
//! Native snapshots are DATA. Only the original registered source/Document
//! owners may construct a request, and only Supervisor retirement can consume
//! its terminal. A valid terminal is not child/descendant/native finality.
use crate::{error::BridgeError, github_connection_session::auth_provider::Command};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

#[path = "github_auth_config.rs"]
mod config;
pub(crate) use config::schema_one as config_schema_one;

pub(crate) const PROTOCOL: &str = "mrk-gh-auth/1";
pub(crate) const REQUEST_LIMIT: usize = 32768;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const RESPONSE_LIMIT: usize = 8192;
pub(crate) const WORK_SECONDS: u64 = 20;
pub(crate) const HARD_SECONDS: u64 = 30;
pub(crate) const TOOL_LIMIT: u64 = 128 * 1024 * 1024;
pub(crate) const CONFIG_LIMIT: u64 = 64 * 1024;
const MAGIC: &[u8] = b"MRK-GH-AUTH/1\0";

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Role {
    Version,
    Token,
}
impl Role {
    pub(crate) fn output_limit(self) -> usize {
        if self == Self::Version {
            1024
        } else {
            4098
        }
    }
}

// Lossless JSON integers on the PRIVATE Python pipe, not renderer numbers.
pub(crate) type Identity = (u64, u64, u32, u32, u32, u64, u64, i64, i64);
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Snapshot {
    pub(crate) identity: Identity,
    pub(crate) sha256: String,
}
impl Snapshot {
    fn valid(&self, uid: u32, executable: bool) -> bool {
        let (dev, ino, mode, owner, _, links, size, _, _) = self.identity;
        dev > 0
            && ino > 0
            && mode & 0o170000 == 0o100000
            && links == 1
            && mode & 0o7022 == 0
            && size > 0
            && size <= if executable { TOOL_LIMIT } else { CONFIG_LIMIT }
            && if executable {
                (owner == 0 || owner == uid) && mode & 0o111 != 0
            } else {
                owner == uid && mode & 0o777 == 0o600
            }
            && hex(&self.sha256)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Files {
    #[serde(rename = "config.yml")]
    pub(crate) config: Snapshot,
    #[serde(rename = "hosts.yml")]
    pub(crate) hosts: Snapshot,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Native {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) home: String,
    pub(crate) config: String,
    pub(crate) executable: String,
    pub(crate) tool: Snapshot,
    pub(crate) files: Files,
}
impl Native {
    pub(crate) fn valid(&self) -> bool {
        self.uid != 0
            && path(&self.home)
            && path(&self.config)
            && path(&self.executable)
            && Path::new(&self.home).join(".config/gh") == Path::new(&self.config)
            && Path::new(&self.executable)
                .file_name()
                .is_some_and(|name| name == "gh")
            && !Path::new(&self.executable).starts_with(&self.config)
            && self.tool.valid(self.uid, true)
            && self.files.config.valid(self.uid, false)
            && self.files.hosts.valid(self.uid, false)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        self.home
            .capacity()
            .checked_add(self.config.capacity())?
            .checked_add(self.executable.capacity())?
            .checked_add(self.tool.sha256.capacity())?
            .checked_add(self.files.config.sha256.capacity())?
            .checked_add(self.files.hosts.sha256.capacity())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Context {
    pub(crate) login: String,
    pub(crate) project_id: String,
    pub(crate) repository: String,
    pub(crate) generation: u32,
    pub(crate) revision: String,
}
impl Context {
    pub(crate) fn valid(&self) -> bool {
        Command::Token {
            login: self.login.clone(),
        }
        .arguments()
        .is_ok()
            && crate::protocol::valid_id(&self.project_id)
            && crate::protocol::valid_id(&self.revision)
            && crate::github_connection_protocol::coordinate(&self.repository)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        self.login
            .capacity()
            .checked_add(self.project_id.capacity())?
            .checked_add(self.repository.capacity())?
            .checked_add(self.revision.capacity())
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
        self.work_end_ns != 0
            && self.hard_end_ns <= i64::MAX as u64
            && self.hard_end_ns.checked_sub(self.work_end_ns) == Some(10_000_000_000)
    }
}

#[derive(Serialize)]
struct Initial<'a> {
    protocol: &'static str,
    id: &'a str,
    role: Role,
    #[serde(flatten)]
    context: &'a Context,
    native: &'a Native,
    clock: Clock,
}
// No raw config/token bytes, but still kept on the private native path.
pub(crate) struct Request {
    raw: Vec<u8>,
    digest: [u8; 32],
    id: String,
    role: Role,
}
impl Request {
    pub(crate) fn from_original_snapshot(
        id: &str,
        role: Role,
        context: &Context,
        native: &Native,
        clock: Clock,
    ) -> Result<Self, BridgeError> {
        if !crate::protocol::valid_id(id) || !context.valid() || !native.valid() || !clock.valid() {
            return Err(BridgeError::invalid());
        }
        let mut raw = serde_json::to_vec(&Initial {
            protocol: PROTOCOL,
            id,
            role,
            context,
            native,
            clock,
        })
        .map_err(|_| BridgeError::invalid())?;
        if raw.len() >= REQUEST_LIMIT || raw.contains(&b'\n') {
            return Err(BridgeError::invalid());
        }
        raw.push(b'\n');
        Ok(Self {
            digest: Sha256::digest(&raw).into(),
            raw,
            id: id.into(),
            role,
        })
    }
    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub(crate) fn role(&self) -> Role {
        self.role
    }
    pub(crate) fn digest(&self) -> String {
        self.digest.iter().map(|b| format!("{b:02x}")).collect()
    }
    pub(crate) fn ready(&self) -> Vec<u8> {
        // The fixed Python encoder sorts precisely these three ASCII keys.
        format!(
            "{{\"digest\":\"{}\",\"id\":\"{}\",\"protocol\":\"{}\"}}\n",
            self.digest(),
            self.id,
            PROTOCOL
        )
        .into_bytes()
    }
    pub(crate) fn go(&self) -> Vec<u8> {
        format!("MRK-GH-AUTH-GO/1 {}\n", self.digest()).into_bytes()
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.raw.capacity())?
            .checked_add(self.id.capacity())
    }
    pub(crate) fn terminal(&self, raw: Zeroizing<Vec<u8>>) -> Result<Terminal, BridgeError> {
        let start = MAGIC.len() + 32;
        if raw.len() < start + 3
            || raw.len() > RESPONSE_LIMIT
            || !raw.starts_with(MAGIC)
            || raw[MAGIC.len()..start] != self.digest
            || raw[start] > 4
        {
            return Err(BridgeError::protocol());
        }
        let status = raw[start];
        let length = usize::from(u16::from_be_bytes([raw[start + 1], raw[start + 2]]));
        if raw.len() != start + 3 + length
            || (status == 0 && !(1..=self.role.output_limit()).contains(&length))
            || (status != 0 && length != 0)
        {
            return Err(BridgeError::protocol());
        }
        // Original resources MUST remain held on cleanup-unknown. No terminal
        // marker can discharge nested C/A/W debt, including after gh wait/EOF.
        if status == 4 {
            return Err(BridgeError::cleanup_unknown());
        }
        Ok(Terminal {
            raw,
            body: start + 3,
            status,
        })
    }
}

/// Owns raw output from its FIRST pipe read. No Debug/Clone/Serialize.
/// Even a valid result remains provisional until actual Supervisor retirement.
pub(crate) struct Terminal {
    raw: Zeroizing<Vec<u8>>,
    body: usize,
    status: u8,
}
impl Terminal {
    pub(crate) fn result(self) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        match self.status {
            0 => {
                let mut output = Zeroizing::new(Vec::new());
                output
                    .try_reserve_exact(self.raw.len() - self.body)
                    .map_err(|_| BridgeError::cleanup_unknown())?;
                output.extend_from_slice(&self.raw[self.body..]);
                Ok(output)
            }
            1 => Err(BridgeError::new(
                "gh_auth_refused",
                "The selected GitHub CLI account could not be read.",
            )),
            2 => Err(BridgeError::new(
                "cancelled",
                "The selected GitHub CLI account read was stopped.",
            )),
            3 => Err(BridgeError::timeout()),
            _ => Err(BridgeError::cleanup_unknown()),
        }
    }
}
pub(crate) fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn path(value: &str) -> bool {
    (2..=4096).contains(&value.len())
        && value.starts_with('/')
        && !value.bytes().any(|b| b < 32 || b == 127 || b == b'\\')
        && value[1..]
            .split('/')
            .all(|v| !v.is_empty() && v.len() <= 255 && v != "." && v != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(role: Role) -> Request {
        let snapshot = |mode| Snapshot {
            identity: (1, 2, 0o100000 | mode, 1001, 1001, 1, 12, 123, 456),
            sha256: "a".repeat(64),
        };
        Request::from_original_snapshot(
            "gh-auth-fixture",
            role,
            &Context {
                login: "fixture-login".into(),
                project_id: "fixture-project".into(),
                repository: "fixture-owner/fixture-repo".into(),
                generation: 1,
                revision: "fixture-revision".into(),
            },
            &Native {
                uid: 1001,
                gid: 1001,
                home: "/fixture/home".into(),
                config: "/fixture/home/.config/gh".into(),
                executable: "/fixture/official/gh".into(),
                tool: snapshot(0o755),
                files: Files {
                    config: snapshot(0o600),
                    hosts: snapshot(0o600),
                },
            },
            Clock {
                work_end_ns: 40_000_000_000,
                hard_end_ns: 50_000_000_000,
            },
        )
        .unwrap()
    }
    fn terminal(request: &Request, status: u8, output: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut raw = Zeroizing::new(MAGIC.to_vec());
        raw.extend_from_slice(&request.digest);
        raw.push(status);
        raw.extend_from_slice(&(output.len() as u16).to_be_bytes());
        raw.extend_from_slice(output);
        raw
    }
    #[test]
    fn fixed_private_framing_has_no_public_account_inventory() {
        let request = request(Role::Token);
        let value: serde_json::Value = serde_json::from_slice(request.raw()).unwrap();
        assert_eq!(value["role"], "token");
        assert_eq!(value["login"], "fixture-login");
        // Exact Python fixture parity, including newline and private request
        // digest. This is codec evidence only, never native admission.
        assert_eq!(request.raw().len(), 808);
        assert_eq!(
            request.digest(),
            "a4a83b521da35bcb0178bf1b0ec9f34e161d65f87a96c9e0172e0bb984931a7e"
        );
        assert_eq!(value.as_object().unwrap().len(), 10);
        assert!(request.raw().len() < REQUEST_LIMIT && request.ready().len() < READY_LIMIT);
        assert_eq!(
            request.go(),
            format!("MRK-GH-AUTH-GO/1 {}\n", request.digest()).as_bytes()
        );
        assert!(!value.as_object().unwrap().contains_key("argv"));
    }
    #[test]
    fn raw_private_output_has_one_consuming_terminal_and_no_stderr_path() {
        let request = request(Role::Token);
        let output = b"synthetic-private-output-not-a-credential\n";
        let value = request
            .terminal(terminal(&request, 0, output))
            .unwrap()
            .result()
            .unwrap();
        assert_eq!(value.as_slice(), output);
        for status in 1..=3 {
            assert!(request
                .terminal(terminal(&request, status, b""))
                .unwrap()
                .result()
                .is_err());
            assert!(request
                .terminal(terminal(&request, status, output))
                .is_err());
        }
        assert!(request.terminal(terminal(&request, 4, b"")).is_err());
    }
    #[test]
    fn malformed_missing_foreign_or_oversize_never_discharges_originals() {
        for role in [Role::Version, Role::Token] {
            let request = request(role);
            assert!(request.terminal(Zeroizing::new(Vec::new())).is_err());
            assert!(request.terminal(terminal(&request, 0, b"")).is_err());
            assert!(request
                .terminal(terminal(&request, 0, &vec![b'x'; role.output_limit() + 1]))
                .is_err());
            let mut foreign = terminal(&request, 0, b"synthetic");
            foreign[MAGIC.len()] ^= 1;
            assert!(request.terminal(foreign).is_err());
            let mut coalesced = terminal(&request, 0, b"synthetic");
            coalesced.push(b'x');
            assert!(request.terminal(coalesced).is_err());
        }
    }
    #[test]
    fn source_shape_and_clock_are_not_permission_or_fallback() {
        for value in ["relative", "/", "/a/../b", "/a//b", "/a\\b", "/a\nb"] {
            assert!(!path(value));
        }
        assert!(path("/fixture/physical/gh"));
        assert!(!Clock {
            work_end_ns: 1,
            hard_end_ns: 10_000_000_000
        }
        .valid());
        assert!(!Clock {
            work_end_ns: 1,
            hard_end_ns: u64::MAX
        }
        .valid());
        assert!(Clock {
            work_end_ns: 1,
            hard_end_ns: 10_000_000_001
        }
        .valid());
    }
}
