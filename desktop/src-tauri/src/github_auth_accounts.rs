//! Local names only, from the same held PRIVATE gh configuration. No YAML
//! value, token, active-account claim, path or authentication result is public.
//! Stock 2.88.1 UsersForHost reads exactly hosts/github.com/users keys. Complex
//! YAML is refused rather than interpreted differently from go-gh v2.13.0.
use crate::{
    error::BridgeError,
    github_auth_capture_wire as capture, github_auth_entry_protocol as entry,
    github_connection_protocol::{self as connection, Reason},
    protocol::{strict_json, valid_id},
};
use serde::Serialize;

pub(crate) const MAX_NAMES: usize = 16;
const MAX_HOSTS: usize = 16;
const MAX_LINES: usize = 512;
const HOST_FIELDS: [&[u8]; 14] = [
    b"user",
    b"users",
    b"oauth_token",
    b"git_protocol",
    b"editor",
    b"prompt",
    b"prefer_editor_prompt",
    b"pager",
    b"http_unix_socket",
    b"browser",
    b"color_labels",
    b"accessible_colors",
    b"accessible_prompter",
    b"spinner",
];

fn trim(raw: &[u8]) -> &[u8] {
    raw.trim_ascii_start().trim_ascii_end()
}
// Borrowed slices only. Secret scalars are checked and discarded, never copied
// into a node tree, diagnostic, public result or error string.
fn scalar(raw: &[u8]) -> Option<&[u8]> {
    let raw = trim(raw);
    if raw.is_empty() || raw.starts_with(b"#") {
        return Some(b"");
    }
    if matches!(raw[0], b'\'' | b'"') {
        let end = raw[1..].iter().position(|b| *b == raw[0])? + 1;
        let tail = &raw[end + 1..];
        if !tail.is_empty() && (!tail.starts_with(b" ") || !trim(tail).starts_with(b"#")) {
            return None;
        }
        let value = &raw[1..end];
        return (!value.iter().any(|b| matches!(*b, b'\\' | b'\'' | b'"'))).then_some(value);
    }
    let end = raw.windows(2).position(|b| b == b" #").unwrap_or(raw.len());
    let value = trim(&raw[..end]);
    (!value.is_empty()
        && !matches!(
            value[0],
            b'-' | b'+' | b'!' | b'&' | b'*' | b'|' | b'>' | b'[' | b'{' | b'?' | b'%'
        )
        && value
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b" _./=+@-".contains(b)))
    .then_some(value)
}
fn empty(raw: &[u8]) -> bool {
    let raw = trim(raw);
    raw.is_empty() || raw.starts_with(b"#") || raw == b"{}"
}
fn login(raw: &[u8]) -> bool {
    std::str::from_utf8(raw).is_ok_and(|v| entry::login(v) && !v.contains("--"))
}
fn hostname(raw: &[u8]) -> bool {
    !raw.is_empty()
        && raw.len() <= 253
        && raw.split(|b| *b == b'.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part[0].is_ascii_alphanumeric()
                && part[part.len() - 1].is_ascii_alphanumeric()
                && part.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        })
}

/// Complete finite ordinary block-mapping subset. `None` means unsupported or
/// malformed, NEVER a partial/empty list. The caller has already checked the
/// independent config.yml schema-one guard on its actual original bytes.
pub(crate) fn names(raw: &[u8]) -> Option<Vec<String>> {
    if raw.is_empty()
        || raw.len() > capture::CONFIG_LIMIT as usize
        || raw
            .iter()
            .any(|b| !matches!(*b, b'\n' | b'\r') && !(32..=126).contains(b))
    {
        return None;
    }
    let mut hosts: [Option<&[u8]>; MAX_HOSTS] = [None; MAX_HOSTS];
    let mut users: [Option<&[u8]>; MAX_NAMES] = [None; MAX_NAMES];
    let (mut host_count, mut user_count, mut fields) = (0usize, 0usize, 0u16);
    let (mut host_indent, mut user_indent, mut token_indent) = (None, None, None);
    let (mut in_users, mut have_user, mut token_seen, mut github, mut github_seen) =
        (false, false, false, false, false);
    let mut found: Vec<&[u8]> = Vec::new();
    for (number, row) in raw.split(|b| *b == b'\n').enumerate() {
        if number >= MAX_LINES {
            return None;
        }
        let row = row.strip_suffix(b"\r").unwrap_or(row);
        if row.contains(&b'\r') {
            return None;
        }
        let indent = row.iter().position(|b| *b != b' ').unwrap_or(row.len());
        let text = &row[indent..];
        if text.is_empty() || text.starts_with(b"#") {
            continue;
        }
        let colon = text.iter().position(|b| *b == b':')?;
        let (key, rest) = (&text[..colon], &text[colon + 1..]);
        if !rest.is_empty() && !rest.starts_with(b" ") {
            return None;
        }
        if indent == 0 {
            if !hostname(key)
                || !empty(rest)
                || trim(rest) == b"{}"
                || host_count == MAX_HOSTS
                || hosts[..host_count]
                    .iter()
                    .flatten()
                    .any(|old| old.eq_ignore_ascii_case(key))
            {
                return None;
            }
            hosts[host_count] = Some(key);
            host_count += 1;
            github = key == b"github.com";
            if key.eq_ignore_ascii_case(b"github.com") && !github {
                return None;
            }
            github_seen |= github;
            fields = 0;
            user_count = 0;
            users.fill(None);
            host_indent = None;
            user_indent = None;
            token_indent = None;
            in_users = false;
            have_user = false;
            token_seen = false;
        } else if host_count == 0 {
            return None;
        } else if host_indent.is_none() || Some(indent) == host_indent {
            if !matches!(indent, 2 | 4) {
                return None;
            }
            host_indent = Some(indent);
            let field = HOST_FIELDS.iter().position(|known| *known == key)?;
            if fields & (1 << field) != 0 {
                return None;
            }
            fields |= 1 << field;
            in_users = key == b"users" && trim(rest) != b"{}";
            have_user = false;
            if key == b"users" {
                if !empty(rest) {
                    return None;
                }
            } else {
                let value = scalar(rest)?;
                if key == b"user" && !login(value) {
                    return None;
                }
            }
        } else if in_users && (user_indent.is_none() || Some(indent) == user_indent) {
            let parent = host_indent?;
            if !matches!(indent.checked_sub(parent), Some(2 | 4))
                || !login(key)
                || !empty(rest)
                || user_count == MAX_NAMES
                || users[..user_count]
                    .iter()
                    .flatten()
                    .any(|old| old.eq_ignore_ascii_case(key))
            {
                return None;
            }
            user_indent = Some(indent);
            users[user_count] = Some(key);
            user_count += 1;
            have_user = trim(rest) != b"{}";
            token_seen = false;
            if github {
                found.push(key);
            }
        } else {
            if !in_users
                || !have_user
                || token_seen
                || key != b"oauth_token"
                || !matches!(indent.checked_sub(user_indent?), Some(2 | 4))
                || token_indent.is_some_and(|old| old != indent)
            {
                return None;
            }
            scalar(rest)?;
            token_indent = Some(indent);
            token_seen = true;
        }
    }
    // No inferred host/token or active-user fallback. An absent users map means
    // no listed names, NOT proof that the user has no credentials elsewhere.
    if !github_seen {
        return Some(Vec::new());
    }
    found.sort_unstable_by_key(|name| name.to_ascii_lowercase());
    Some(
        found
            .into_iter()
            .map(|v| std::str::from_utf8(v).unwrap().to_owned())
            .collect(),
    )
}

pub(crate) struct Request {
    pub(crate) project_id: String,
    pub(crate) repository: String,
    pub(crate) expected_document_revision: u32,
    pub(crate) expected_connection_revision: u32,
}
impl Request {
    pub(crate) fn bounded(&self) -> bool {
        valid_id(&self.project_id)
            && connection::coordinate(&self.repository)
            && self.expected_document_revision != 0
            && self.expected_document_revision != u32::MAX
            && self.expected_connection_revision != 0
            && self.expected_connection_revision != u32::MAX
            && self
                .project_id
                .capacity()
                .checked_add(self.repository.capacity())
                .is_some_and(|n| n <= entry::REQUEST_LIMIT)
    }
}
pub(crate) fn decode(raw: &[u8]) -> Result<Request, BridgeError> {
    const COMMAND: &str = "github_auth_accounts";
    if raw.len().saturating_add(COMMAND.len()).saturating_add(32) > entry::REQUEST_LIMIT {
        return Err(BridgeError::invalid());
    }
    let value = strict_json(raw).map_err(|_| BridgeError::invalid())?;
    let fields = value.as_object().ok_or_else(BridgeError::invalid)?;
    if fields.len() != 4
        || ![
            "projectId",
            "repository",
            "expectedDocumentRevision",
            "expectedConnectionRevision",
        ]
        .iter()
        .all(|key| fields.contains_key(*key))
    {
        return Err(BridgeError::invalid());
    }
    let project = fields["projectId"]
        .as_str()
        .filter(|v| valid_id(v))
        .ok_or_else(BridgeError::invalid)?;
    let repository = fields["repository"]
        .as_str()
        .filter(|v| connection::coordinate(v))
        .ok_or_else(BridgeError::invalid)?;
    let revision = |key: &str| {
        fields[key]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| *v != 0 && *v != u32::MAX)
            .ok_or_else(BridgeError::invalid)
    };
    Ok(Request {
        project_id: project.into(),
        repository: repository.into(),
        expected_document_revision: revision("expectedDocumentRevision")?,
        expected_connection_revision: revision("expectedConnectionRevision")?,
    })
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Reading,
    Stopping,
    Settled,
    Failed,
    CleanupUnknown,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct List {
    pub(crate) observation_id: String,
    pub(crate) logins: Vec<String>,
    pub(crate) current: bool,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32,
    pub(crate) kind: &'static str,
    pub(crate) document_revision: u32,
    pub(crate) connection_revision: u32,
    pub(crate) available: bool,
    pub(crate) operation_id: String,
    pub(crate) project_id: String,
    pub(crate) repository: String,
    pub(crate) phase: Phase,
    pub(crate) reason: Reason,
    pub(crate) accounts: Option<List>,
}
impl Status {
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let mut size = std::mem::size_of::<Self>()
            .checked_add(self.operation_id.capacity())?
            .checked_add(self.project_id.capacity())?
            .checked_add(self.repository.capacity())?;
        if let Some(list) = &self.accounts {
            size = size
                .checked_add(list.observation_id.capacity())?
                .checked_add(
                    list.logins
                        .capacity()
                        .checked_mul(std::mem::size_of::<String>())?,
                )?;
            for name in &list.logins {
                size = size.checked_add(name.capacity())?;
            }
        }
        Some(size)
    }
}
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum PublicStatus {
    Connect(entry::Status),
    Accounts(Status),
}

/// Native-only comparison DATA, constructed from actual held SourceBook bytes.
/// No serde/Debug, public fingerprint, claim of token presence or reusable loan.
#[derive(Clone)]
pub(crate) struct Witness {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) home: String,
    pub(crate) config: String,
    pub(crate) files: capture::Files,
    pub(crate) logins: Vec<String>,
}
impl Witness {
    pub(crate) fn valid(&self) -> bool {
        let file = |s: &capture::Snapshot| {
            let (dev, ino, mode, uid, _, links, size, _, _) = s.identity;
            dev > 0
                && ino > 0
                && mode & 0o170000 == 0o100000
                && links == 1
                && mode & 0o7022 == 0
                && mode & 0o777 == 0o600
                && uid == self.uid
                && size > 0
                && size <= capture::CONFIG_LIMIT
                && capture::hex(&s.sha256)
        };
        self.uid != 0
            && capture::path(&self.home)
            && capture::path(&self.config)
            && std::path::Path::new(&self.home).join(".config/gh")
                == std::path::Path::new(&self.config)
            && file(&self.files.config)
            && file(&self.files.hosts)
            && self.logins.len() <= MAX_NAMES
            && self.logins.iter().all(|n| login(n.as_bytes()))
            && self
                .logins
                .windows(2)
                .all(|pair| pair[0].to_ascii_lowercase() < pair[1].to_ascii_lowercase())
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let mut size = std::mem::size_of::<Self>()
            .checked_add(self.home.capacity())?
            .checked_add(self.config.capacity())?
            .checked_add(self.files.config.sha256.capacity())?
            .checked_add(self.files.hosts.sha256.capacity())?
            .checked_add(
                self.logins
                    .capacity()
                    .checked_mul(std::mem::size_of::<String>())?,
            )?;
        for name in &self.logins {
            size = size.checked_add(name.capacity())?;
        }
        Some(size)
    }
    pub(crate) fn matches(&self, native: &capture::Native, login: &str) -> bool {
        self.uid == native.uid
            && self.gid == native.gid
            && self.home == native.home
            && self.config == native.config
            && self.files == native.files
            && self.logins.iter().any(|name| name == login)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_complete_names_not_tokens_or_active_account() {
        let raw = b"github.com:\n    user: Fixture-B\n    oauth_token: PRIVATE_SENTINEL\n    git_protocol: https\n    users:\n        Fixture-B:\n            oauth_token: PRIVATE_SENTINEL\n        Fixture-A:\nghe.example:\n    users:\n        Other:\n";
        assert_eq!(
            names(raw),
            Some(vec!["Fixture-A".into(), "Fixture-B".into()])
        );
        assert_eq!(names(b"github.com:\n  users: {}\n"), Some(vec![]));
        assert_eq!(names(b"ghe.example:\n  users:\n    Other:\n"), Some(vec![]));
    }
    #[test]
    fn malformed_ambiguous_or_partial_mapping_never_returns_a_subset() {
        for raw in [
            "github.com:\n  users:\n    Fixture:\n    fixture:\n",
            "github.com:\n  users:\n    First:\n    unsafe/name:\n",
            "github.com:\n  users: {First: null}\n",
            "github.com:\n  users:\n    First: &alias\n",
            "github.com:\n  users:\n    First:\n      oauth_token: |\n        PRIVATE\n",
            "github.com:\n  users:\n    First:\n---\nother: value\n",
            "github.com:\n  users:\n    First:\ngithub.com:\n  user: Other\n",
            "github.com:\n  users:\n    First:\n  users:\n    Second:\n",
            "github.com:\n  users:\n    First:\n      unknown: PRIVATE\n",
        ] {
            assert!(names(raw.as_bytes()).is_none());
        }
        let mut many = "github.com:\n  users:\n".to_string();
        for n in 0..17 {
            many.push_str(&format!("    Fixture{n}:\n"));
        }
        assert!(names(many.as_bytes()).is_none());
        assert!(names(&[b'#'; 65537]).is_none());
    }
    #[test]
    fn raw_request_has_no_paths_tokens_account_choice_or_duplicate_keys() {
        let input = br#"{"projectId":"p","repository":"Fixture/App","expectedDocumentRevision":1,"expectedConnectionRevision":2}"#;
        assert!(decode(input).is_ok());
        for raw in [br#"{"projectId":"p","projectId":"p","repository":"Fixture/App","expectedDocumentRevision":1,"expectedConnectionRevision":2}"#.as_slice(), br#"{"path":"private"}"#, br#"{"token":"private"}"#] { assert!(decode(raw).is_err()); }
    }
    #[test]
    fn complete_native_witness_and_exact_membership_must_all_match() {
        let snap = capture::Snapshot {
            identity: (1, 2, 0o100600, 1001, 1001, 1, 9, 1, 1),
            sha256: "a".repeat(64),
        };
        let mut native = capture::Native {
            uid: 1001,
            gid: 1001,
            home: "/inert/home".into(),
            config: "/inert/home/.config/gh".into(),
            executable: "/inert/gh".into(),
            tool: snap.clone(),
            files: capture::Files {
                config: snap.clone(),
                hosts: snap,
            },
        };
        let witness = Witness {
            uid: native.uid,
            gid: native.gid,
            home: native.home.clone(),
            config: native.config.clone(),
            files: native.files.clone(),
            logins: vec!["Fixture".into()],
        };
        assert!(witness.matches(&native, "Fixture"));
        assert!(!witness.matches(&native, "Other"));
        native.files.hosts.sha256 = "b".repeat(64);
        assert!(!witness.matches(&native, "Fixture"));
        native.files = witness.files.clone();
        native.uid += 1;
        assert!(!witness.matches(&native, "Fixture"));
    }
}
