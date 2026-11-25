//! Closed Fetch additions to the SAME GitLocal Supervisor arm. The connection
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

pub(crate) struct GitLocalFetchHold {
    owner: std::sync::Weak<Owner>,
    receipt: Arc<Mutex<GitLocalReceipt>>,
    joined: Arc<OnceLock<JoinedControl>>,
    work_end: Instant,
}
impl GitLocalTicket {
    pub(crate) fn fetch_stop_unknown(&self) {
        self.owner.fail(BridgeError::cleanup_unknown());
    }
    pub(crate) fn fetch_hold(&self) -> Result<Arc<GitLocalFetchHold>, BridgeError> {
        let invocation = self
            .owner
            .git_local
            .as_ref()
            .filter(|i| i.action.kind() == wire::Kind::Fetch)
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let ends = self
            .owner
            .git_local_endpoints
            .ok_or_else(BridgeError::cleanup_unknown)?;
        Ok(Arc::new(GitLocalFetchHold {
            owner: Arc::downgrade(&self.owner),
            receipt: self.receipt.clone(),
            joined: invocation.fetch_joined.clone(),
            work_end: ends.work,
        }))
    }
}
impl GitLocalFetchHold {
    pub(crate) fn matches(&self, gate: &crate::asset_session::GitLocalGate, id: &str) -> bool {
        self.owner.upgrade().is_some_and(|o| {
            o.id == id
                && o.git_local.as_ref().is_some_and(|v| {
                    v.action.kind() == wire::Kind::Fetch
                        && v.gate.same_original(gate)
                        && Arc::ptr_eq(&v.receipt, &self.receipt)
                        && Arc::ptr_eq(&v.fetch_joined, &self.joined)
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
                    "The original selected-account Git Fetch was stopped.",
                )
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_fetch_protocol::tests as data;

    // Correlation DATA only. This cfg(test) construction does not run an
    // original candidate job, acquire a source, or prove process settlement.
    fn publication() -> GitLocalPublication {
        let request = Arc::new(data::request(wire::Phase::Apply));
        let candidate = Arc::new(data::candidate(&request));
        GitLocalPublication {
            request,
            candidate,
            publication: wire::Publication::FetchReturned,
            upstream_returned: None,
            fetch_keep: Some(data::keep()),
            fetch_returned: Some(serde_json::from_value(data::returned()).unwrap()),
            push_returned: None,
        }
    }

    #[test]
    fn source_exception_requires_exact_original_keep_native_review_and_returned_phase() {
        let mut p = publication();
        let native = data::native();
        let review = wire::Review::Fetch(data::review());
        let keep = data::keep();
        assert!(p.fetch_for(&p.request.id, &native, &review, &keep).is_ok());
        assert!(p.intent_for(&p.request.id, &native, &review).is_err());
        assert!(p.fetch_for("foreign", &native, &review, &keep).is_err());
        let mut other = keep.clone();
        other.identity[1] += 1;
        assert!(p
            .fetch_for(&p.request.id, &native, &review, &other)
            .is_err());
        let mut changed_native = native.clone();
        changed_native.files.head.identity.1 += 1;
        assert!(p
            .fetch_for(&p.request.id, &changed_native, &review, &keep)
            .is_err());
        let mut changed_review = data::review();
        changed_review.account_id = "99".into();
        assert!(p
            .fetch_for(
                &p.request.id,
                &native,
                &wire::Review::Fetch(changed_review),
                &keep
            )
            .is_err());
        for marker in [
            wire::Publication::NotReported,
            wire::Publication::RefReturned,
            wire::Publication::BranchRefReturned,
        ] {
            p.publication = marker;
            assert!(p.fetch_for(&p.request.id, &native, &review, &keep).is_err());
        }
        p.publication = wire::Publication::FetchReturned;
        p.fetch_keep = None;
        assert!(p.fetch_for(&p.request.id, &native, &review, &keep).is_err());
        p.fetch_keep = Some(keep.clone());
        p.fetch_returned.as_mut().unwrap().phase =
            crate::git_fetch_protocol::Effect::PackLinkEntered;
        assert!(p.fetch_for(&p.request.id, &native, &review, &keep).is_err());
    }

    #[test]
    fn private_control_waits_for_same_known_receipt_and_cannot_be_replaced() {
        let at = Instant::now();
        let receipt = Arc::new(Mutex::new(GitLocalReceipt::Pending));
        let joined = Arc::new(OnceLock::new());
        let hold = GitLocalFetchHold {
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
        assert!(hold.joined_control().is_none()); // A return frame/slot is not a receipt.
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
        let (observed_at, observed) = hold.joined_control().unwrap();
        assert_eq!(observed_at, at);
        assert_eq!(observed.cooldown_seconds, Some(60));
        assert!(joined
            .set(joined_control(at + Duration::from_secs(1), control))
            .is_err());
        assert_eq!(hold.joined_control().unwrap().0, at);
        // The historical mailbox/control carry no strong Owner/runtime root.
        assert_eq!(hold.owner.strong_count(), 0);
        assert!(hold.owner.upgrade().is_none());
    }
}
