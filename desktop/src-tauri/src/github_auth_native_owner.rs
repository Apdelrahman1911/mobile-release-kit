//! Concrete adapter of the EXISTING Supervisor's private original tickets to
//! the selected-account Provider. No block_on, process fallback or user/token
//! transport is added. The actual Document owner arms a role before admission,
//! stores the original ticket here, drops its mutex, then awaits only a wait
//! handle. Native source POSTs/current consent remain the original gate's work.
use crate::{
    asset_session::GitHubAuthGoGate,
    error::BridgeError,
    github_auth_capture_wire::{Context, Role},
    github_connection_session::auth_provider::{
        CaptureOwner, Command, Failure, NativeCredential, PreparedGhConnection, PrivateOutput,
        Provider, Selection,
    },
    supervisor::{GitHubAuthReceipt, GitHubAuthTicket, GitHubAuthWait},
};

fn gate_failure(error: BridgeError) -> Failure {
    match error.code.as_str() {
        "target_changed" | "github_connection_refused_target_changed" => Failure::Changed,
        "query_timeout" | "github_connection_refused_expired" => Failure::TimedOut,
        "runtime_unavailable"
        | "github_connection_refused_runtime_unavailable"
        | "github_connection_refused_unqualified" => Failure::Unavailable,
        "invalid_request"
        | "busy"
        | "cancelled"
        | "shutting_down"
        | "github_connection_refused_invalid_input"
        | "github_connection_refused_busy"
        | "github_connection_refused_cancelled" => Failure::Refused,
        // This includes both original cleanup_unknown and the connection's
        // prefixed form. An unexpected gate failure is not a known refusal.
        _ => Failure::Unknown,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    VersionArmed,
    VersionWaiting,
    VersionPresented,
    Ready,
    TokenArmed,
    TokenWaiting,
    TokenPresented,
    Used,
    HandedOff,
    Failed,
}

/// Never a renderer/IPC object; the constructor requires the actual original
/// document gate. No supplied booleans/paths/JSON can substitute for that gate.
pub(crate) struct NativeGhProvider {
    provider: Provider,
    original: NativeCapture,
    selection: Option<Selection>,
}
struct NativeCapture {
    gate: GitHubAuthGoGate,
    context: Context,
    phase: Phase,
    ticket: Option<GitHubAuthTicket>,
    capture_id: Option<String>,
}
impl NativeGhProvider {
    pub(crate) fn registered(gate: GitHubAuthGoGate, context: Context) -> Result<Self, Failure> {
        if !context.valid() {
            return Err(Failure::Refused);
        }
        gate.check_current(&context).map_err(gate_failure)?;
        Ok(Self {
            provider: Provider::new(),
            original: NativeCapture {
                gate,
                context,
                phase: Phase::New,
                ticket: None,
                capture_id: None,
            },
            selection: None,
        })
    }
    pub(crate) fn context(&self) -> &Context {
        &self.original.context
    }
    pub(crate) fn arm_version(&mut self) -> Result<Role, Failure> {
        if self.original.phase != Phase::New {
            return Err(Failure::Refused);
        }
        self.original.current()?;
        // Spend BEFORE the original Supervisor admission can lose its return.
        self.original.phase = Phase::VersionArmed;
        Ok(Role::Version)
    }
    pub(crate) fn arm_token(&mut self, selected: &Selection) -> Result<Role, Failure> {
        if self.original.phase != Phase::Ready
            || self.selection.as_ref() != Some(selected)
            || selected.verified
        {
            return Err(Failure::Refused);
        }
        self.original.current()?;
        self.original.phase = Phase::TokenArmed;
        Ok(Role::Token)
    }
    pub(crate) fn retain_original(
        &mut self,
        ticket: GitHubAuthTicket,
    ) -> Result<GitHubAuthWait, Failure> {
        if self.original.ticket.is_some() {
            self.original.phase = Phase::Failed;
            return Err(Failure::Unknown);
        }
        let expected = match self.original.phase {
            Phase::VersionArmed => Role::Version,
            Phase::TokenArmed => Role::Token,
            _ => {
                self.original.phase = Phase::Failed;
                return Err(Failure::Refused);
            }
        };
        // Original ticket is retained before currentness/role checks. An
        // unknown/different context never becomes another capture or retry.
        self.original.ticket = Some(ticket);
        self.original.phase = Phase::Failed;
        let ticket = self.original.ticket.as_ref().ok_or(Failure::Unknown)?;
        if ticket.role() != expected || ticket.context() != &self.original.context {
            return Err(Failure::Changed);
        }
        self.original.current()?;
        let ticket = self.original.ticket.as_ref().ok_or(Failure::Unknown)?;
        self.original.capture_id = Some(ticket.operation_id().to_owned());
        self.original.phase = if expected == Role::Version {
            Phase::VersionWaiting
        } else {
            Phase::TokenWaiting
        };
        Ok(ticket.wait_handle())
    }
    pub(crate) fn finish_selection(&mut self) -> Result<Selection, Failure> {
        if self.original.phase != Phase::VersionWaiting {
            return Err(Failure::Refused);
        }
        self.original.require_settled()?;
        let login = self.original.context.login.clone();
        let result = self.provider.select(&mut self.original, &login);
        match result {
            Ok(selection) if self.original.phase == Phase::VersionPresented => {
                self.original.phase = Phase::Ready;
                self.selection = Some(selection.clone());
                Ok(selection)
            }
            Err(error) => {
                self.original.phase = Phase::Failed;
                Err(error)
            }
            _ => {
                self.original.phase = Phase::Failed;
                Err(Failure::Unknown)
            }
        }
    }
    fn finish_token(&mut self) -> Result<NativeCredential, Failure> {
        if self.original.phase != Phase::TokenWaiting {
            return Err(Failure::Refused);
        }
        self.original.require_settled()?;
        let selection = self.selection.as_ref().ok_or(Failure::Changed)?;
        let result = self.provider.acquire_selected(
            &mut self.original,
            &selection.login,
            &selection.revision,
        );
        self.original.phase = if result.is_ok() {
            Phase::Used
        } else {
            Phase::Failed
        };
        result
    }
    /// Run outside the actual Document mutex, just like finish_selection:
    /// all original gate callbacks are complete before returning this private
    /// token-bearing handoff. Under that SAME Document, Root must still rematch
    /// the retained original registration/consent/source work before calling
    /// ConnectionState::connect_prepared_gh. Matching DATA alone is not enough.
    pub(crate) fn finish_prepared_connection(&mut self) -> Result<PreparedGhConnection, Failure> {
        let credential = self.finish_token()?;
        let context = self.original.context.clone();
        let result = credential.prepare_connection(
            &mut self.original,
            context.project_id,
            context.repository,
            context.generation,
        );
        self.original.phase = if result.is_ok() {
            Phase::HandedOff
        } else {
            Phase::Failed
        };
        result
    }
    pub(crate) fn stop(&mut self) {
        self.original.phase = Phase::Failed;
        self.provider.invalidate();
        self.selection = None;
        if let Some(ticket) = &self.original.ticket {
            ticket.stop();
        }
    }
}
impl NativeCapture {
    fn current(&mut self) -> Result<(), Failure> {
        match self.gate.check_current(&self.context) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.phase = Phase::Failed;
                if let Some(ticket) = &self.ticket {
                    ticket.stop();
                }
                Err(gate_failure(error))
            }
        }
    }
    fn require_settled(&mut self) -> Result<(), Failure> {
        self.current()?;
        match self.ticket.as_ref().ok_or(Failure::Unknown)?.receipt() {
            GitHubAuthReceipt::Settled => Ok(()),
            GitHubAuthReceipt::Pending => Err(Failure::Unavailable), // Await SAME ticket; not another capture.
            _ => {
                self.phase = Phase::Failed;
                Err(Failure::Unknown)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_unknown_is_not_downgraded_to_changed_or_retryable_refusal() {
        assert_eq!(
            gate_failure(BridgeError::cleanup_unknown()),
            Failure::Unknown
        );
        assert_eq!(
            gate_failure(BridgeError::new(
                "github_connection_refused_cleanup_unknown",
                "inert"
            )),
            Failure::Unknown
        );
        assert_eq!(
            gate_failure(BridgeError::new("unexpected-original-failure", "inert")),
            Failure::Unknown
        );
        assert_eq!(
            gate_failure(BridgeError::new(
                "github_connection_refused_target_changed",
                "inert"
            )),
            Failure::Changed
        );
        assert_eq!(gate_failure(BridgeError::timeout()), Failure::TimedOut);
        assert_eq!(gate_failure(BridgeError::shutdown()), Failure::Refused);
        assert_eq!(
            gate_failure(BridgeError::unavailable("inert")),
            Failure::Unavailable
        );
    }
}
impl CaptureOwner for NativeCapture {
    type OriginalCapture = GitHubAuthTicket;
    fn current_revision(&mut self) -> Result<String, Failure> {
        self.current()?;
        Ok(self.context.revision.clone())
    }
    fn check_current(&mut self, revision: &str, login: &str) -> Result<(), Failure> {
        if revision != self.context.revision
            || login != self.context.login
            || self.phase == Phase::Failed
        {
            return Err(Failure::Changed);
        }
        self.current()
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
        if self.phase != Phase::Used
            || project_id != self.context.project_id
            || repository != self.context.repository
            || generation != self.context.generation
        {
            return Err(Failure::Changed);
        }
        Ok(())
    }
    fn capture(&mut self, command: Command) -> Result<Self::OriginalCapture, Failure> {
        self.require_settled()?;
        let role = match (&command, self.phase) {
            (Command::Version, Phase::VersionWaiting) => Role::Version,
            (Command::Token { login }, Phase::TokenWaiting) if login == &self.context.login => {
                Role::Token
            }
            _ => {
                self.phase = Phase::Failed;
                return Err(Failure::Refused);
            }
        };
        self.phase = if role == Role::Version {
            Phase::VersionPresented
        } else {
            Phase::TokenPresented
        };
        self.ticket.take().ok_or(Failure::Unknown)
    }
    fn consume_settled(
        &mut self,
        original: Self::OriginalCapture,
    ) -> Result<PrivateOutput, Failure> {
        self.current()?;
        if self.capture_id.as_deref() != Some(original.operation_id())
            || original.context() != &self.context
            || !matches!(
                (self.phase, original.role()),
                (Phase::VersionPresented, Role::Version) | (Phase::TokenPresented, Role::Token)
            )
        {
            self.phase = Phase::Failed;
            return Err(Failure::Changed);
        }
        // No arbitrary raw output constructor is used by this concrete owner.
        // Ticket's original Owner.retire is necessary, not merely a frame/EOF.
        let result = original.consume();
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result.map(PrivateOutput::from_private_capture)
    }
}
