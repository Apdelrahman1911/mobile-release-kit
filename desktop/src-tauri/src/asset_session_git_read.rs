//! Local Git reads under the SAME native Document and Supervisor. The only
//! retained execution object is its original typed Supervisor ticket. No
//! renderer path, token, native snapshot, alternate owner or source authority.
use super::*;
use crate::{
    git_read_protocol as wire,
    supervisor::{GitReadAdmission, GitReadReceipt, GitReadTicket},
};

pub(super) enum Entry {
    Original { ticket: GitReadTicket, gate: GitReadGate },
    Finished(wire::Projection),
}
struct Selection {
    document: Weak<Inner>,
    root: asset_source::RegisteredRoot,
    context: wire::Context,
    document_revision: u32,
    connection: crate::github_connection_session::LocalGitReadSession,
    action: wire::Action,
    #[cfg(any(target_os="linux",target_os="macos"))]
    agent_observation: Option<Arc<agent_git_index::Observation>>,
}
#[derive(Clone)]
pub(crate) struct GitReadGate(Arc<Selection>);
impl GitReadGate {
    pub(crate) fn context(&self) -> wire::Context {
        self.0.context.clone()
    }
    fn matches(&self, document: &Arc<Inner>, state: &DocumentState, id: &str) -> bool {
        self.0.document.upgrade().is_some_and(|old| Arc::ptr_eq(&old, document))
            && state.lifetime.original_bound()
            && !state.lost_observed
            && !state.unknown
            && !state.exhausted
            && !state.stopping
            && !state.quit_pending
            && !state.retiring
            && !state.lock_pending
            && !state.maintenance.closed()
            && !version_allocation::pending(state)
            && !version_enrollment::pending(state)
            && state.github.local_git_read_session(&self.0.context.project_id, self.0.context.generation, Instant::now())
                == Some(self.0.connection)
            && state.revision == self.0.document_revision
            && matches!(&state.git_read, Some(Entry::Original { ticket, gate })
                if ticket.operation_id() == id && Arc::ptr_eq(&gate.0, &self.0))
            && document.bridge.registry_generation() == self.0.context.generation
            && document
                .bridge
                .native_project(&self.0.context.project_id)
                .is_ok_and(|(generation, root)| generation == self.0.context.generation && root == self.0.root)
    }
    pub(crate) fn check_current(&self, id: &str) -> Result<asset_source::RegisteredRoot, BridgeError> {
        self.claim(id, || Ok(self.0.root.clone()))
    }
    pub(crate) fn claim<T>(&self, id: &str, claim: impl FnOnce() -> Result<T, BridgeError>) -> Result<T, BridgeError> {
        let document = self.0.document.upgrade().ok_or_else(BridgeError::cleanup_unknown)?;
        let state = document.state.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if !self.matches(&document, &state, id) {
            return Err(BridgeError::new(
                "git_stale_observation",
                "The original local Git read context changed.",
            ));
        }
        // Document -> Supervisor registry -> owner. No IO or await here.
        claim()
    }
}
pub(super) fn pending(state: &DocumentState) -> bool {
    matches!(&state.git_read, Some(Entry::Original { ticket, .. }) if !ticket.settled())
}
pub(super) fn stop(state: &DocumentState) {
    if let Some(Entry::Original { ticket, .. }) = &state.git_read {
        if !ticket.settled() {
            ticket.stop();
        }
    }
}
fn error_reason(error: &BridgeError) -> (&'static str, wire::Outcome) {
    use wire::Outcome;
    match error.code.as_str() {
        "cancelled" | "shutting_down" => ("authorization", Outcome::Cancelled),
        "query_timeout" => ("deadline", Outcome::TimedOut),
        "git_stale_observation" => ("stale-observation", Outcome::Refused),
        "runtime_unavailable" => ("unsupported-repository", Outcome::Refused),
        "protocol_error" | "output_limit" => ("response-invalid", Outcome::Refused),
        "invalid_request" => ("invalid-input", Outcome::Refused),
        _ => ("command-failed", Outcome::Refused),
    }
}
fn projection(entry: &Entry) -> wire::Projection {
    let Entry::Original { ticket, gate } = entry else {
        let Entry::Finished(value) = entry else { unreachable!() };
        return value.clone();
    };
    let mut result = wire::Projection {
        operation_id: ticket.operation_id().into(),
        context: gate.context(),
        action: gate.0.action.clone(),
        phase: ticket.pending_phase(),
        outcome: None,
        reason: None,
        result: serde_json::Value::Null,
    };
    match ticket.receipt() {
        GitReadReceipt::Pending => {}
        GitReadReceipt::RetainedUnknown | GitReadReceipt::Settled { was_unknown: true, .. } => {
            result.phase = wire::Phase::CleanupUnknown;
            result.outcome = Some(wire::Outcome::CleanupUnknown);
            result.reason = Some("unknown".into());
        }
        GitReadReceipt::Settled {
            outcome,
            was_unknown: false,
        } => {
            result.phase = wire::Phase::Settled;
            match outcome {
                Ok(value) => {
                    result.outcome = Some(value.status);
                    result.reason = value.reason;
                    result.result = value.result;
                }
                Err(error) => {
                    let (reason, outcome) = error_reason(&error);
                    result.reason = Some(reason.into());
                    result.outcome = Some(outcome);
                }
            }
        }
    }
    result
}
pub(super) fn reconcile(state: &mut DocumentState) {
    if matches!(&state.git_read, Some(Entry::Original { ticket, .. }) if ticket.settled()) {
        // This is only bounded history after all actual original/native and
        // management joins. Never demote Unknown or detach a pending ticket.
        let result = projection(state.git_read.as_ref().expect("original checked"));
        #[cfg(any(target_os="linux",target_os="macos"))]
        if let Some(Entry::Original {gate,..})=&state.git_read {
            if let Some(document)=gate.0.document.upgrade() {
                agent_git_index::observe_returned(&document,gate.0.agent_observation.as_ref(),&result);
            }
        }
        state.git_read = Some(Entry::Finished(result));
    }
}
pub(super) fn retained_bytes(state: &DocumentState) -> Option<usize> {
    match &state.git_read {
        None => Some(0),
        Some(Entry::Original { .. }) => None, // Do not guess a live worker census.
        Some(Entry::Finished(_)) => Some(wire::RESULT_BACKING),
    }
}
impl DocumentBinding {
    fn git_read_new_gate(&self, state: &DocumentState) -> Result<(), BridgeError> {
        if !state.lifetime.original_bound() || state.lost_observed {
            return Err(BridgeError::unavailable("The original application document is unavailable."));
        }
        self.passive_query_gate_locked(state, self.inner.bridge.as_ref())?;
        if !self.inner.bridge.supervisor.can_exit()
            || !self.inner.bridge.edits.can_exit()
            || self.inner.bridge.edits.preflight_attention()
            || state
                .slot
                .as_ref()
                .is_some_and(|slot| slot.phase != Phase::Idle || !slot.owner.resources_settled())
            || state.github.native_work_pending()
        {
            return Err(BridgeError::new(
                "busy",
                "Finish the original task before reading local Git changes.",
            ));
        }
        if !self.inner.bridge.supervisor.git_read_profile_available() {
            return Err(BridgeError::unavailable("The fixed local Git read runtime is unavailable."));
        }
        Ok(())
    }
    fn git_read_snapshot(&self, state: &DocumentState) -> wire::Status {
        wire::Status {
            schema_version: 1,
            document_revision: state.revision,
            available: self.inner.bridge.supervisor.git_read_profile_available() && state.lifetime.original_bound() && !state.lost_observed,
            operation: state.git_read.as_ref().map(projection),
        }
    }
    pub(crate) fn git_read_status(&self) -> wire::Status {
        let mut state = self.lock();
        reconcile(&mut state);
        self.git_read_snapshot(&state) // Memory only; never starts/replays a read.
    }
    pub(crate) fn git_read_cancel(&self, operation_id: &str) -> Result<wire::Status, BridgeError> {
        let mut state = self.lock();
        match &state.git_read {
            Some(Entry::Original { ticket, .. }) if ticket.operation_id() == operation_id => ticket.stop(),
            Some(Entry::Finished(value)) if value.operation_id == operation_id => {}
            _ => return Err(BridgeError::invalid()),
        }
        reconcile(&mut state);
        Ok(self.git_read_snapshot(&state))
    }
    pub(crate) fn git_read_start(&self, args: wire::Start) -> Result<wire::StartResult, BridgeError> {
        let admitted = Instant::now();
        let mut state = self.lock();
        reconcile(&mut state);
        // All normal Err paths in Supervisor::admit precede insertion. Panic,
        // lost IPC and cleanup_unknown are NOT converted to a clean refusal.
        // After Ok(ticket), storing the same original is the only step below.
        let outcome = (|| -> Result<(GitReadTicket, GitReadGate), BridgeError> {
            self.git_read_new_gate(&state)?;
            if state.revision != args.expected_document_revision {
                return Err(BridgeError::new(
                    "git_stale_observation",
                    "Check the current project before starting this read.",
                ));
            }
            if !args.action.valid() {
                return Err(BridgeError::invalid());
            }
            let (generation, root) = self
                .registry_result(&mut state, self.inner.bridge.native_project(&args.project_id), None)
                .map_err(|_| BridgeError::unavailable("Choose an original registered project before reading Git changes."))?;
            let connection = state.github.local_git_read_session(&args.project_id, generation, Instant::now())
                .ok_or_else(|| BridgeError::new("busy", "Finish the original connection work or select its current project before reading local Git."))?;
            let future = GitReadAdmission::reservation_bytes().ok_or_else(BridgeError::invalid)?;
            #[cfg(any(
                all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
                all(
                    target_os = "macos",
                    target_pointer_width = "64",
                    any(target_arch = "aarch64", target_arch = "x86_64")
                )
            ))]
            lookup_memory::git_read_admission_bytes(&self.inner, &state, future)
                .map_err(|_| BridgeError::new("busy", "The current native tasks leave insufficient bounded read storage."))?;
            let context = wire::Context {
                project_id: args.project_id.clone(),
                generation,
                revision: format!("document-{}", state.revision),
            };
            #[cfg(any(target_os="linux",target_os="macos"))]
            let agent_observation=agent_git_index::observe_admission(&self.inner,&state,&args.project_id,generation,&root,&args.action);
            let gate = GitReadGate(Arc::new(Selection {
                document: Arc::downgrade(&self.inner),
                root,
                context,
                document_revision: state.revision,
                connection,
                action: args.action.clone(),
                #[cfg(any(target_os="linux",target_os="macos"))]
                agent_observation,
            }));
            let reservation = GitReadAdmission::reserve(gate.clone(), args.action.clone(), admitted)?;
            let ticket = self.inner.bridge.supervisor.start_git_read(reservation)?;
            Ok((ticket, gate))
        })();
        let (admission, reason) = match outcome {
            Ok((ticket, gate)) => {
                // First worker check cannot pass the still-held Document mutex
                // before this ticket is stored. No fallible check/bump follows.
                state.git_read = Some(Entry::Original { ticket, gate });
                (wire::Admission::Started, None)
            }
            Err(error) if error.code == "cleanup_unknown" => return Err(error),
            Err(error) => (
                wire::Admission::Refused,
                Some(match error.code.as_str() {
                    "git_stale_observation" => wire::StartRefusal::StaleObservation,
                    "invalid_request" => wire::StartRefusal::InvalidInput,
                    "busy" => wire::StartRefusal::Busy,
                    _ => wire::StartRefusal::Unavailable,
                }),
            ),
        };
        Ok(wire::StartResult {
            schema_version: 1,
            admission,
            request: args,
            status: self.git_read_snapshot(&state),
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn comparison_data_alone_never_grants_git_source_or_go() {
        let root = asset_source::RegisteredRoot {
            path: "/inert/git-read".into(),
            identity: asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity()),
        };
        let gate = GitReadGate(Arc::new(Selection {
            document: Weak::new(),
            #[cfg(any(target_os="linux",target_os="macos"))]
            agent_observation: None,
            root,
            context: wire::Context {
                project_id: "project-1".into(),
                generation: 1,
                revision: "document-1".into(),
            },
            document_revision: 1,
            connection: crate::github_connection_session::ConnectionState::new()
                .local_git_read_session("project-1", 1, Instant::now()).unwrap(),
            action: wire::Action {
                kind: wire::Kind::Observe,
                expected_revision: None,
                paths: vec![],
                staged: false,
            },
        }));
        assert!(gate.check_current("git-read-1").is_err());
        let mut called = false;
        assert!(gate
            .claim("git-read-1", || {
                called = true;
                Ok(())
            })
            .is_err());
        assert!(!called);
    }
}
