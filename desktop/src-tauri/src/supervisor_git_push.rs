//! Closed Push additions to the SAME GitLocal Supervisor arm. The connection
//! hold uses a Weak original Owner plus its real mailbox, so retiring the Doc
//! entry cannot leave an uncharged runtime held by historical connection DATA.
use super::*;
use crate::github_connection_protocol::GitHubReadControl;
use std::sync::OnceLock;

pub(super) struct JoinedControl {
    // Minted only at the original Invocation retirement after all actual jobs
    // and NativeUse/source/runtime/management returns. A helper frame is DATA.
    at: Instant,
    control: GitHubReadControl,
}
pub(super) fn joined_control(at: Instant, control: GitHubReadControl) -> JoinedControl {
    JoinedControl { at, control }
}

pub(crate) struct GitLocalPushHold {
    owner: std::sync::Weak<Owner>,
    receipt: Arc<Mutex<GitLocalReceipt>>,
    joined: Arc<OnceLock<JoinedControl>>,
    work_end: Instant,
}
impl GitLocalTicket {
    pub(crate) fn push_stop_unknown(&self) {
        self.owner.fail(BridgeError::cleanup_unknown());
    }
    pub(crate) fn push_hold(&self) -> Result<Arc<GitLocalPushHold>, BridgeError> {
        let invocation = self
            .owner
            .git_local
            .as_ref()
            .filter(|i| i.action.kind().is_push())
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let ends = self
            .owner
            .git_local_endpoints
            .ok_or_else(BridgeError::cleanup_unknown)?;
        Ok(Arc::new(GitLocalPushHold {
            owner: Arc::downgrade(&self.owner),
            receipt: self.receipt.clone(),
            joined: invocation.push_joined.clone(),
            work_end: ends.work,
        }))
    }
}
impl GitLocalPushHold {
    pub(crate) fn matches(&self, gate: &crate::asset_session::GitLocalGate, id: &str) -> bool {
        self.owner.upgrade().is_some_and(|o| {
            o.id == id
                && o.git_local.as_ref().is_some_and(|v| {
                    v.action.kind().is_push()
                        && v.gate.same_original(gate)
                        && Arc::ptr_eq(&v.receipt, &self.receipt)
                        && Arc::ptr_eq(&v.push_joined, &self.joined)
                })
        })
    }
    pub(crate) fn work_end(&self) -> Instant {
        self.work_end
    }
    pub(crate) fn receipt(&self) -> GitLocalReceipt {
        lock(&self.receipt).clone()
    }
    pub(crate) fn joined_control(&self) -> Option<(Instant, GitHubReadControl)> {
        if !matches!(
            *lock(&self.receipt),
            GitLocalReceipt::Settled {
                was_unknown: false,
                ..
            }
        ) {
            return None;
        }
        self.joined.get().map(|v| (v.at, v.control.clone()))
    }
    pub(crate) fn stop(&self, unknown: bool) {
        if let Some(owner) = self.owner.upgrade() {
            owner.fail(if unknown {
                BridgeError::cleanup_unknown()
            } else {
                BridgeError::new(
                    "cancelled",
                    "The original selected-account Git Push was stopped.",
                )
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wire::push_worker::tests as data;

    #[test]
    fn returned_push_only_compares_exact_original_request_and_never_local_publication() {
        // Private correlation fixture only, not an actual joined invocation.
        let request = Arc::new(data::request(true));
        let candidate = Arc::new(data::candidate(&request));
        let native = request.native.as_ref().unwrap().clone();
        let review = request.binding.as_ref().unwrap().review.clone();
        let mut p = GitLocalPublication {
            request,
            candidate,
            publication: wire::Publication::PushReturned,
            fetch_keep: None,
            fetch_returned: None,
            push_returned: Some(data::returned()),
        };
        assert!(p.push_for(&p.request.id, &native, &review).is_ok());
        assert!(p.intent_for(&p.request.id, &native, &review).is_err());
        assert!(p.push_for("foreign", &native, &review).is_err());
        let mut changed = native.clone();
        changed.files.head.identity.1 += 1;
        assert!(p.push_for(&p.request.id, &changed, &review).is_err());
        let mut foreign = crate::git_push_protocol::tests::review();
        foreign.account_id = "99".into();
        assert!(p
            .push_for(&p.request.id, &native, &wire::Review::Push(foreign))
            .is_err());
        for marker in [
            wire::Publication::NotReported,
            wire::Publication::RefReturned,
            wire::Publication::FetchReturned,
        ] {
            p.publication = marker;
            assert!(p.push_for(&p.request.id, &native, &review).is_err());
        }
        p.publication = wire::Publication::PushReturned;
        p.push_returned = None;
        assert!(p.push_for(&p.request.id, &native, &review).is_err());
    }

    #[test]
    fn original_known_receipt_and_joined_control_are_both_required_without_retaining_owner() {
        let at = Instant::now();
        let receipt = Arc::new(Mutex::new(GitLocalReceipt::Pending));
        let joined = Arc::new(OnceLock::new());
        let hold = GitLocalPushHold {
            owner: std::sync::Weak::new(),
            receipt: receipt.clone(),
            joined: joined.clone(),
            work_end: at,
        };
        let control = GitHubReadControl {
            reason: crate::github_connection_protocol::Reason::RateLimited,
            credential_expires_at: None,
            cooldown_seconds: Some(60),
            cooldown_blocked: false,
        };
        assert!(joined.set(joined_control(at, control.clone())).is_ok());
        assert!(hold.joined_control().is_none());
        *lock(&receipt) = GitLocalReceipt::RetainedUnknown;
        assert!(hold.joined_control().is_none());
        *lock(&receipt) = GitLocalReceipt::Settled {
            outcome: Err(BridgeError::protocol()),
            was_unknown: true,
        };
        assert!(hold.joined_control().is_none());
        *lock(&receipt) = GitLocalReceipt::Settled {
            outcome: Err(BridgeError::protocol()),
            was_unknown: false,
        };
        let (observed, value) = hold.joined_control().unwrap();
        assert_eq!(observed, at);
        assert_eq!(value.cooldown_seconds, Some(60));
        assert!(joined
            .set(joined_control(at + Duration::from_secs(1), control))
            .is_err());
        assert_eq!(hold.joined_control().unwrap().0, at);
        assert_eq!(hold.owner.strong_count(), 0);
        assert!(hold.owner.upgrade().is_none());
    }
}
