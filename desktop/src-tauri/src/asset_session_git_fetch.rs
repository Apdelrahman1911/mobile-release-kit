//! Narrow Fetch branches of the existing GitLocal Document gate. All helpers
//! below are memory-only under the SAME Doc; source/Store/network IO remains in
//! the original retained jobs. Pins cannot reconstruct a Connection or grant.
use super::*;
use crate::github_connection_session::fetch::Pins;
use zeroize::Zeroizing;

pub(super) fn select(
    state: &DocumentState,
    project: &str,
    generation: u32,
    action: &wire::Action,
    at: Instant,
) -> Result<Option<Pins>, BridgeError> {
    let wire::Action::Fetch(action) = action else {
        return Ok(None);
    };
    let work = at
        .checked_add(Duration::from_secs(wire::WORK_SECONDS))
        .ok_or_else(BridgeError::timeout)?;
    state
        .github
        .select_git_fetch(project, generation, action, at, work)
        .map(Some)
}
pub(super) fn selected_review(
    state: &DocumentState,
    review: &ReadyReview,
    at: Instant,
) -> Result<Option<Pins>, BridgeError> {
    match (&review.action, &review.public.review, &review.fetch) {
        (wire::Action::Fetch(action), wire::Review::Fetch(details), Some(pins)) => {
            let work = at
                .checked_add(Duration::from_secs(wire::WORK_SECONDS))
                .ok_or_else(BridgeError::timeout)?;
            state
                .github
                .git_fetch_review_current(pins, action, details, Instant::now(), work)?;
            Ok(Some(pins.clone()))
        }
        (_, _, None) if review.action.kind() != wire::Kind::Fetch => Ok(None),
        _ => Err(changed()),
    }
}
pub(super) fn review_current(state: &DocumentState, review: &ReadyReview) -> bool {
    match (&review.public.review, &review.fetch) {
        (wire::Review::Fetch(details), Some(pins)) => {
            state
                .github
                .git_fetch_prepared_current(pins, details, Instant::now())
        }
        (_, None) => review.action.kind() != wire::Kind::Fetch,
        _ => false,
    }
}
/// Called only after retaining Entry::Original. Every error from this point is
/// original-retention/Unknown, never a no-admission refusal or automatic retry.
pub(super) fn retain(state: &mut DocumentState) -> Result<(), BridgeError> {
    let Some(Entry::Original { ticket, gate }) = &state.git_local else {
        return Err(BridgeError::cleanup_unknown());
    };
    let Some(pins) = &gate.0.fetch else {
        return Ok(());
    };
    let result = ticket.fetch_hold().and_then(|original| {
        state
            .github
            .retain_git_fetch(pins.clone(), original, gate, ticket.operation_id())
    });
    if result.is_err() {
        ticket.fetch_stop_unknown();
    }
    result
}
pub(super) fn finish(state: &mut DocumentState) -> Result<(), BridgeError> {
    let Some(Entry::Original { ticket, gate }) = &state.git_local else {
        return Err(BridgeError::cleanup_unknown());
    };
    if gate.0.fetch.is_none() {
        return Ok(());
    }
    state.github.finish_git_fetch(gate, ticket.operation_id())
}
pub(super) fn extra_retained(review: Option<&ReadyReview>) -> Option<usize> {
    review.and_then(|r| r.fetch.as_ref()).map_or(Some(0), |p| {
        p.heap()?.checked_add(std::mem::size_of::<Pins>())
    })
}
impl GitLocalGate {
    pub(crate) fn fetch_target(&self, id: &str) -> Result<wire::fetch_worker::Target, BridgeError> {
        self.claim(id, || {
            self.0
                .fetch
                .as_ref()
                .ok_or_else(BridgeError::cleanup_unknown)?
                .target(self.0.review.as_ref().and_then(wire::Review::fetch_details))
        })
    }
    pub(crate) fn fetch_go(
        &self,
        id: &str,
        request: &wire::Request,
        claim: impl FnOnce() -> bool,
    ) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        let document = self
            .0
            .document
            .upgrade()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let state = document
            .state
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        let edit = document
            .bridge
            .edits
            .saved_registration_guard(&document.session_identity)?;
        self.current_with_edit_locked(&document, &state, id, &edit)?;
        state.github.git_fetch_go(
            self.0
                .fetch
                .as_ref()
                .ok_or_else(BridgeError::cleanup_unknown)?,
            self,
            id,
            request,
            Instant::now(),
            claim,
        )
    }
    pub(super) fn fetch_current_locked(
        &self,
        state: &DocumentState,
        id: &str,
    ) -> Result<(), BridgeError> {
        match (&self.0.action, &self.0.fetch) {
            (wire::Action::Fetch(_), Some(pins)) => {
                state
                    .github
                    .git_fetch_current(pins, self, id, Instant::now())
            }
            (_, None) => Ok(()),
            _ => Err(BridgeError::cleanup_unknown()),
        }
    }
}
