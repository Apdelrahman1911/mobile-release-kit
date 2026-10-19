//! Local-only selected-account gh acquisition and PRIVATE connection handoff.
//!
//! No auth-status enumeration: gh status tests configured accounts over HTTP,
//! and its pinned 2.80.0 source has no JSON output. The user instead explicitly
//! selects a login (or an existing native account registration supplies it).
//! `auth token --hostname github.com --user LOGIN` is a local config/keyring
//! read in the public gh 2.40.0 source. Authentication/immutable ID binding stays
//! with the EXISTING HTTP owner, not gh or this unverified selection DTO.
//!
//! No process owner, generic command IPC, HTTP client or native qualification
//! is introduced. Missing original CaptureOwner means unavailable, never a
//! std::process fallback. Only genuine original wait/EOF/close/join receipts
//! permit its private output to be consumed.
use serde::Serialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const TOKEN_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Unavailable,
    Refused,
    Changed,
    InvalidOutput,
    OutputLimit,
    TimedOut,
    Unknown,
}

/// Closed native calls, not a shell/extension/API/status/login/switch endpoint.
pub(crate) enum Command {
    Version,
    Token { login: String },
}
impl Command {
    pub(crate) fn arguments(&self) -> Result<Vec<String>, Failure> {
        match self {
            Self::Version => Ok(vec!["--version".into()]),
            Self::Token { login: selected } if login(selected) => Ok(vec![
                "auth".into(),
                "token".into(),
                "--hostname".into(),
                "github.com".into(),
                "--user".into(),
                selected.clone(),
            ]),
            _ => Err(Failure::Refused),
        }
    }
    pub(crate) fn stdout_limit(&self) -> usize {
        match self {
            Self::Version => 1024,
            Self::Token { .. } => TOKEN_BYTES + 2,
        }
    }
    pub(crate) fn stderr_limit(&self) -> usize {
        8192
    }
    pub(crate) fn timeout_seconds(&self) -> u64 {
        15
    }
}

/// Original native-selected current-user/tool context; never deserialized.
/// CaptureOwner admits the absolute regular gh executable, its held tool lease
/// and exact current config/keyring context. No PATH search, project executable,
/// installation, permission change or account switch is performed here.
pub(crate) struct NativeEnvironment {
    pub(crate) home: PathBuf,
    pub(crate) config: PathBuf,
    pub(crate) session_bus: Option<String>,
    pub(crate) runtime_directory: Option<PathBuf>,
}
impl NativeEnvironment {
    pub(crate) fn values(&self) -> Result<BTreeMap<String, String>, Failure> {
        fn directory(value: &Path) -> Result<String, Failure> {
            if !value.is_absolute() {
                return Err(Failure::Refused);
            }
            let text = value.to_str().ok_or(Failure::Refused)?;
            if text.len() > 4096 || text.chars().any(char::is_control) {
                return Err(Failure::Refused);
            }
            Ok(text.to_owned())
        }
        let mut environment: BTreeMap<String, String> = [
            ("PATH", "/usr/bin:/bin"),
            ("LANG", "C"),
            ("LC_ALL", "C"),
            ("GH_HOST", "github.com"),
            ("GH_PROMPT_DISABLED", "1"),
            ("GH_PAGER", "cat"),
            ("GH_NO_UPDATE_NOTIFIER", "1"),
            ("GH_NO_EXTENSION_UPDATE_NOTIFIER", "1"),
            ("NO_COLOR", "1"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect();
        environment.insert("HOME".into(), directory(&self.home)?);
        environment.insert("GH_CONFIG_DIR".into(), directory(&self.config)?);
        if let Some(bus) = &self.session_bus {
            if bus.is_empty() || bus.len() > 4096 || bus.chars().any(char::is_control) {
                return Err(Failure::Refused);
            }
            environment.insert("DBUS_SESSION_BUS_ADDRESS".into(), bus.clone());
        }
        if let Some(directory_path) = &self.runtime_directory {
            environment.insert("XDG_RUNTIME_DIR".into(), directory(directory_path)?);
        }
        // Constructed rather than filtered from ambient state: no GH_TOKEN,
        // GITHUB_TOKEN, enterprise tokens, GH_DEBUG, proxy, GIT/SSH/loader vars.
        Ok(environment)
    }
}

/// Private bytes, not a settlement capability. No Debug/Clone/Serialize.
pub(crate) struct PrivateOutput {
    exit_code: i32,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
}
impl PrivateOutput {
    /// Only the original native owner calls this AFTER its associated original
    /// capture has genuinely settled; a result-shaped message cannot do so.
    pub(crate) fn from_original_capture(exit_code: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> Self {
        Self {
            exit_code,
            stdout: Zeroizing::new(stdout),
            stderr: Zeroizing::new(stderr),
        }
    }
    fn successful(self, limit: usize) -> Result<Zeroizing<Vec<u8>>, Failure> {
        if self.stdout.len() > limit || self.stderr.len() > 8192 {
            return Err(Failure::OutputLimit);
        }
        if self.exit_code != 0 {
            return Err(Failure::Refused);
        }
        if !self.stderr.is_empty() {
            return Err(Failure::InvalidOutput);
        }
        Ok(self.stdout)
    }
}

/// Root's original in-process tool/account owner, not serialized booleans.
/// check_current binds the selected login, project/client/session/action/consent,
/// original tool/config/keyring leases, deadline and cancellation. Retain these
/// through the existing HTTP connection handoff. OriginalCapture retains child,
/// pipes, watchdog and leases on Unknown; no Drop-based cleanup or guessed PID.
pub(crate) trait CaptureOwner {
    type OriginalCapture;
    fn current_revision(&mut self) -> Result<String, Failure>;
    fn check_current(
        &mut self,
        expected_revision: &str,
        selected_login: &str,
    ) -> Result<(), Failure>;
    /// Compare every connection target field to THIS original admitted project
    /// and account invocation. Syntactically valid caller targets are not enough.
    fn check_for_connection(
        &mut self,
        expected_revision: &str,
        selected_login: &str,
        project_id: &str,
        repository: &str,
        generation: u32,
    ) -> Result<(), Failure>;
    fn capture(&mut self, command: Command) -> Result<Self::OriginalCapture, Failure>;
    fn consume_settled(
        &mut self,
        original: Self::OriginalCapture,
    ) -> Result<PrivateOutput, Failure>;
}

#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Selection {
    pub(crate) revision: String,
    pub(crate) login: String,
    pub(crate) verified: bool,
}

fn login(value: &str) -> bool {
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
        && !value.contains("--")
}
fn revision(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_:".contains(&byte))
}
fn version(output: PrivateOutput) -> Result<(), Failure> {
    let bytes = output.successful(1024)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Failure::InvalidOutput)?;
    let first = text.lines().next().ok_or(Failure::InvalidOutput)?;
    let number = first
        .strip_prefix("gh version ")
        .and_then(|value| value.split(' ').next())
        .ok_or(Failure::InvalidOutput)?;
    let parts: Vec<_> = number.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty() || part.len() > 3 || !part.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(Failure::InvalidOutput);
    }
    let minor = parts[1]
        .parse::<u32>()
        .map_err(|_| Failure::InvalidOutput)?;
    // Source compatibility only; actual executable/runtime admission remains
    // with the original tool owner. No unsolicited upgrade or native pass.
    if parts[0] != "2" || minor < 40 {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

pub(super) struct SelectedAccount {
    pub(super) login: String,
    pub(super) account_revision: String,
}

/// Single-consumer native-memory token. Only the parent ConnectionState can
/// take its private parts. Never an event/result/draft/vault/project payload.
pub(crate) struct NativeCredential {
    selected: SelectedAccount,
    token: Zeroizing<String>,
}
impl NativeCredential {
    pub(super) fn into_connection_parts<O: CaptureOwner>(
        self,
        owner: &mut O,
        project_id: &str,
        repository: &str,
        generation: u32,
    ) -> Result<(SelectedAccount, Zeroizing<String>), Failure> {
        if !crate::protocol::valid_id(project_id)
            || !crate::github_connection_protocol::coordinate(repository)
        {
            return Err(Failure::Refused);
        }
        owner.check_current(&self.selected.account_revision, &self.selected.login)?;
        owner.check_for_connection(
            &self.selected.account_revision,
            &self.selected.login,
            project_id,
            repository,
            generation,
        )?;
        Ok((self.selected, self.token))
    }
}

/// One native selection/acquisition attempt. A failed/unknown token capture
/// cannot be re-armed here; a new original authorization belongs to Root.
pub(crate) struct Provider {
    selected: Option<Selection>,
    attempted: bool,
}
impl Provider {
    pub(crate) fn new() -> Self {
        Self {
            selected: None,
            attempted: false,
        }
    }
    pub(crate) fn invalidate(&mut self) {
        self.selected = None;
    }
    fn invoke<O: CaptureOwner>(owner: &mut O, command: Command) -> Result<PrivateOutput, Failure> {
        let original = owner.capture(command)?;
        owner.consume_settled(original)
    }
    pub(crate) fn select<O: CaptureOwner>(
        &mut self,
        owner: &mut O,
        selected_login: &str,
    ) -> Result<Selection, Failure> {
        if self.attempted {
            return Err(Failure::Refused);
        }
        self.selected = None;
        if !login(selected_login) {
            return Err(Failure::Refused);
        }
        let original_revision = owner.current_revision()?;
        if !revision(&original_revision) {
            return Err(Failure::Changed);
        }
        owner.check_current(&original_revision, selected_login)?;
        let output = match Self::invoke(owner, Command::Version) {
            Ok(output) => output,
            Err(error) => {
                if error == Failure::Unknown {
                    self.attempted = true;
                }
                return Err(error);
            }
        };
        version(output)?;
        owner.check_current(&original_revision, selected_login)?;
        let selection = Selection {
            revision: original_revision,
            login: selected_login.into(),
            verified: false,
        };
        self.selected = Some(selection.clone());
        Ok(selection)
    }
    pub(crate) fn acquire_selected<O: CaptureOwner>(
        &mut self,
        owner: &mut O,
        selected_login: &str,
        expected_revision: &str,
    ) -> Result<NativeCredential, Failure> {
        if self.attempted {
            return Err(Failure::Refused);
        }
        let original = self.selected.as_ref().ok_or(Failure::Changed)?;
        if original.revision != expected_revision
            || original.login != selected_login
            || !login(selected_login)
        {
            return Err(Failure::Changed);
        }
        owner.check_current(expected_revision, selected_login)?;
        self.attempted = true; // Before capture: Unknown is not permission to retry.
        self.selected = None;
        let output = Self::invoke(
            owner,
            Command::Token {
                login: selected_login.into(),
            },
        )?;
        let mut bytes = output.successful(TOKEN_BYTES + 2)?;
        owner.check_current(expected_revision, selected_login)?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        if bytes.is_empty()
            || bytes.len() > TOKEN_BYTES
            || bytes.iter().any(|byte| !(0x21..=0x7e).contains(byte))
        {
            return Err(Failure::InvalidOutput);
        }
        let token =
            String::from_utf8(std::mem::take(&mut *bytes)).map_err(|_| Failure::InvalidOutput)?;
        Ok(NativeCredential {
            selected: SelectedAccount {
                login: selected_login.into(),
                account_revision: expected_revision.into(),
            },
            token: Zeroizing::new(token),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct FakeOwner {
        values: VecDeque<PrivateOutput>,
        calls: Vec<Vec<String>>,
        changed: bool,
        unknown: bool,
        handoffs: usize,
    }
    impl FakeOwner {
        fn new() -> Self {
            Self {
                values: [
                    "gh version 2.80.0 (synthetic fixture)\n",
                    "INERT_NOT_A_CREDENTIAL\n",
                ]
                .into_iter()
                .map(|value| {
                    PrivateOutput::from_original_capture(0, value.as_bytes().to_vec(), vec![])
                })
                .collect(),
                calls: vec![],
                changed: false,
                unknown: false,
                handoffs: 0,
            }
        }
    }
    impl CaptureOwner for FakeOwner {
        type OriginalCapture = PrivateOutput;
        fn current_revision(&mut self) -> Result<String, Failure> {
            Ok("synthetic-account-revision".into())
        }
        fn check_current(&mut self, _: &str, _: &str) -> Result<(), Failure> {
            if self.changed {
                Err(Failure::Changed)
            } else {
                Ok(())
            }
        }
        fn check_for_connection(
            &mut self,
            revision: &str,
            login: &str,
            project_id: &str,
            repository: &str,
            generation: u32,
        ) -> Result<(), Failure> {
            self.check_current(revision, login)?;
            if project_id != "synthetic-project"
                || repository != "synthetic-owner/synthetic-repository"
                || generation != 3
            {
                return Err(Failure::Changed);
            }
            self.handoffs += 1;
            Ok(())
        }
        fn capture(&mut self, command: Command) -> Result<PrivateOutput, Failure> {
            self.calls.push(command.arguments()?);
            if self.unknown {
                return Err(Failure::Unknown);
            }
            self.values.pop_front().ok_or(Failure::Unavailable)
        }
        fn consume_settled(&mut self, original: PrivateOutput) -> Result<PrivateOutput, Failure> {
            Ok(original)
        }
    }

    #[test]
    fn explicit_unverified_selection_uses_only_local_token_command_then_consumes_once() {
        let mut owner = FakeOwner::new();
        let mut provider = Provider::new();
        let selected = provider.select(&mut owner, "selected-fixture").unwrap();
        assert!(!selected.verified);
        assert!(!serde_json::to_string(&selected)
            .unwrap()
            .contains("INERT_NOT_A_CREDENTIAL"));
        let credential = provider
            .acquire_selected(&mut owner, "selected-fixture", &selected.revision)
            .unwrap();
        let (account, token) = credential
            .into_connection_parts(
                &mut owner,
                "synthetic-project",
                "synthetic-owner/synthetic-repository",
                3,
            )
            .unwrap();
        assert_eq!(account.login, "selected-fixture");
        assert_eq!(account.account_revision, selected.revision);
        assert_eq!(&*token, "INERT_NOT_A_CREDENTIAL");
        assert_eq!(
            owner.calls,
            vec![
                vec!["--version"],
                vec![
                    "auth",
                    "token",
                    "--hostname",
                    "github.com",
                    "--user",
                    "selected-fixture"
                ]
            ]
        );
        assert!(matches!(
            provider.acquire_selected(&mut owner, "selected-fixture", &selected.revision),
            Err(Failure::Refused)
        ));
        assert!(matches!(
            provider.select(&mut owner, "another-fixture"),
            Err(Failure::Refused)
        ));
        assert_eq!(owner.calls.len(), 2);
    }
    #[test]
    fn account_change_or_another_login_never_falls_back_to_active_account() {
        let mut owner = FakeOwner::new();
        let mut provider = Provider::new();
        let selected = provider.select(&mut owner, "selected-fixture").unwrap();
        assert!(matches!(
            provider.acquire_selected(&mut owner, "another-fixture", &selected.revision),
            Err(Failure::Changed)
        ));
        owner.changed = true;
        assert!(matches!(
            provider.acquire_selected(&mut owner, "selected-fixture", &selected.revision),
            Err(Failure::Changed)
        ));
        assert_eq!(owner.calls.len(), 1);
    }
    #[test]
    fn token_failure_or_unknown_is_bounded_private_and_never_rearmed() {
        for raw in [
            b"two lines\nprivate\n".to_vec(),
            vec![b'x'; TOKEN_BYTES + 3],
            b" token\n".to_vec(),
            vec![],
        ] {
            let mut owner = FakeOwner::new();
            let mut provider = Provider::new();
            let selected = provider.select(&mut owner, "selected-fixture").unwrap();
            owner.values.clear();
            owner
                .values
                .push_back(PrivateOutput::from_original_capture(0, raw, vec![]));
            assert!(matches!(
                provider.acquire_selected(&mut owner, "selected-fixture", &selected.revision),
                Err(Failure::InvalidOutput | Failure::OutputLimit)
            ));
            provider.invalidate();
            assert!(matches!(
                provider.select(&mut owner, "selected-fixture"),
                Err(Failure::Refused)
            ));
        }
        let mut owner = FakeOwner::new();
        let mut provider = Provider::new();
        let selected = provider.select(&mut owner, "selected-fixture").unwrap();
        owner.unknown = true;
        assert!(matches!(
            provider.acquire_selected(&mut owner, "selected-fixture", &selected.revision),
            Err(Failure::Unknown)
        ));
        assert!(matches!(
            provider.acquire_selected(&mut owner, "selected-fixture", &selected.revision),
            Err(Failure::Refused)
        ));
        assert_eq!(owner.calls.len(), 2);
    }
    #[test]
    fn consume_handoff_rechecks_original_account_revision() {
        let mut owner = FakeOwner::new();
        let mut provider = Provider::new();
        let selected = provider.select(&mut owner, "selected-fixture").unwrap();
        let credential = provider
            .acquire_selected(&mut owner, "selected-fixture", &selected.revision)
            .unwrap();
        owner.changed = true;
        assert!(matches!(
            credential.into_connection_parts(
                &mut owner,
                "synthetic-project",
                "synthetic-owner/synthetic-repository",
                3
            ),
            Err(Failure::Changed)
        ));
    }
    #[test]
    fn altered_project_repository_or_generation_cannot_handoff_a_captured_token() {
        for (project, repository, generation) in [
            ("another-project", "synthetic-owner/synthetic-repository", 3),
            ("synthetic-project", "another-owner/synthetic-repository", 3),
            (
                "synthetic-project",
                "synthetic-owner/synthetic-repository",
                4,
            ),
            ("invalid project", "synthetic-owner/synthetic-repository", 3),
            (
                "synthetic-project",
                "https://github.com/synthetic-owner/synthetic-repository",
                3,
            ),
        ] {
            let mut owner = FakeOwner::new();
            let mut provider = Provider::new();
            let selected = provider.select(&mut owner, "selected-fixture").unwrap();
            let credential = provider
                .acquire_selected(&mut owner, "selected-fixture", &selected.revision)
                .unwrap();
            assert!(credential
                .into_connection_parts(&mut owner, project, repository, generation)
                .is_err());
            assert_eq!(owner.handoffs, 0);
            assert_eq!(owner.calls.len(), 2); // Version/local token only, no HTTP admission.
        }
    }
    #[test]
    fn unknown_version_capture_also_blocks_further_native_commands() {
        let mut owner = FakeOwner::new();
        let mut provider = Provider::new();
        owner.unknown = true;
        assert!(matches!(
            provider.select(&mut owner, "selected-fixture"),
            Err(Failure::Unknown)
        ));
        owner.unknown = false;
        assert!(matches!(
            provider.select(&mut owner, "selected-fixture"),
            Err(Failure::Refused)
        ));
        assert_eq!(owner.calls.len(), 1);
    }
    #[test]
    fn invalid_login_cannot_add_cli_options_or_invoke_status() {
        for name in [
            "",
            "--user",
            "has space",
            "with/slash",
            "two--hyphens",
            "user\nname",
        ] {
            assert!(matches!(
                Command::Token { login: name.into() }.arguments(),
                Err(Failure::Refused)
            ));
        }
    }
    #[test]
    fn environment_excludes_ambient_token_precedence_and_routing() {
        let environment = NativeEnvironment {
            home: "/synthetic/home".into(),
            config: "/synthetic/gh".into(),
            session_bus: None,
            runtime_directory: None,
        }
        .values()
        .unwrap();
        for key in [
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GH_ENTERPRISE_TOKEN",
            "GITHUB_ENTERPRISE_TOKEN",
            "GH_DEBUG",
            "GIT_CONFIG_COUNT",
            "GIT_ASKPASS",
            "HTTP_PROXY",
            "DYLD_INSERT_LIBRARIES",
        ] {
            assert!(!environment.contains_key(key));
        }
        assert_eq!(environment.get("GH_HOST").unwrap(), "github.com");
    }
}
