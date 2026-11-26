//! An optional origin on the ORIGINAL enrollment Lane, not a second driver,
//! Review, credential owner or state writer.
use super::*;
use crate::{
    github_connection_session::action_delegation as native,
    service_github_action_protocol::{self as wire, enrollment as data},
    service_github_action_requests as rows,
};
use sha2::{Digest, Sha256};
use std::{future::Future, mem::size_of};

#[derive(Clone)]
pub(crate) struct Capture {
    input: data::Input,
    root: asset_source::RegisteredRoot,
    pins: Pins,
    input_epoch: u64,
    stamp: Arc<SavedEditStamp>,
    // The private Review's Original is retained by State, not by another owner.
    reviewed: Option<Weak<Original>>,
}
impl PartialEq for Capture {
    fn eq(&self, other: &Self) -> bool {
        self.input == other.input
            && self.root == other.root
            && self.pins == other.pins
            && self.input_epoch == other.input_epoch
            && match (&self.reviewed, &other.reviewed) {
                (None, None) => true,
                (Some(a), Some(b)) => Weak::ptr_eq(a, b),
                _ => false,
            }
    }
}
impl Eq for Capture {}
impl Capture {
    fn heap(&self) -> Option<usize> {
        [
            self.root.path.capacity(),
            self.input.heap()?,
            self.pins.session_id.capacity(),
            self.pins.project_id.capacity(),
            self.pins.target.project_binding.capacity(),
            self.pins.target.repository.capacity(),
            self.pins.target.account_id.capacity(),
            self.pins.target.repository_id.capacity(),
        ]
        .into_iter()
        .try_fold(0usize, |n, v| n.checked_add(v))
    }
    fn retained_fits(&self) -> bool {
        self.input.valid()
            && self.root.path.capacity() <= 4096
            && self.heap().is_some_and(|n| n <= CAPTURE_HEAP)
    }
}
pub(super) struct Permission {
    capture: Capture,
    scope: Weak<rows::NativeScope>,
}
pub(in crate::asset_session) fn permission_retained(state: &DocumentState) -> bool {
    state.version_enrollment.permission.is_some()
}
const CAPTURE_HEAP: usize = 4096 + 1024;

/// This is in addition to every old Enrollment DATA8MiB/CODE128MiB term and
/// the unchanged GitHub32 row/MAIN envelopes. Real types, not wire lengths.
pub(in crate::asset_session) fn native_backing() -> Option<usize> {
    let [allow, active] = native_phases()?;
    (allow.max(active) <= data::NATIVE_BACKING).then_some(data::NATIVE_BACKING)
}
fn native_phases() -> Option<[usize; 2]> {
    let sum = |values: &[usize]| values.iter().try_fold(0usize, |n, v| n.checked_add(*v));
    // These control cells can coexist with the first off-Doc Allow capture:
    // an ordinary GUI action may win before the second checked Doc cut. Keep
    // them in BOTH phases rather than assuming Allow excludes that original.
    let control = sum(&[
        size_of::<Lane>(),
        size_of::<VersionEnrollmentControl>(),
        size_of::<WaitGuard>(),
        size_of::<rows::Claim>(),
        1024, // fixed hash/hex, Arc/Weak headers, select/timer and return controls
    ])?;
    let allow = sum(&[
        control,
        // First and second native Review plus a construction frontier. Their
        // retained private context never exists on all32 service rows.
        3 * (size_of::<Capture>()
            + CAPTURE_HEAP
            + size_of::<SavedEditStamp>()
            + 2 * size_of::<usize>()),
        2 * size_of::<native::Review>(),
        2 * wire::RAW_LIMIT,
        2 * size_of::<data::Input>(),
    ])?;
    let active = sum(&[
        control,
        // Installation MOVES the surviving Capture out of the native Review;
        // the second Review/NativeProject was explicitly dropped before then.
        // Pending/retained permission rejects another capture before cloning.
        size_of::<Permission>()
            + CAPTURE_HEAP
            + size_of::<SavedEditStamp>()
            + 2 * size_of::<usize>(),
        2 * (size_of::<p::Status>() + data::SNAPSHOT_BACKING),
        2 * wire::RAW_LIMIT,
        2 * size_of::<data::Input>(),
    ])?;
    Some([allow, active])
}

struct Hash(Sha256);
impl std::io::Write for Hash {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn digest<T: serde::Serialize>(value: &T) -> Result<String, BridgeError> {
    let mut hash = Hash(Sha256::new());
    hash.0.update(b"MRK-counter-enrollment-delegation/1\0");
    serde_json::to_writer(&mut hash, value).map_err(|_| BridgeError::protocol())?;
    Ok(format!("{:x}", hash.0.finalize()))
}

pub(super) fn producer_ready(review: &Review) -> bool {
    review.producer.as_ref().is_none_or(|producer| {
        producer
            .upgrade()
            .is_some_and(|entry| entry.positively_returned(&review.id))
    })
}

impl DocumentBinding {
    pub(in crate::asset_session) fn enrollment_agent_review(
        &self,
        state: &DocumentState,
        input: data::Input,
        generation: u32,
        root: &asset_source::RegisteredRoot,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
        now: Instant,
    ) -> Result<native::Review, BridgeError> {
        let enrollment = &state.version_enrollment;
        if !input.valid()
            || native_backing().is_none()
            || pending(state)
            || enrollment.permission.is_some()
            || enrollment.view.revision != input.revision()
        {
            return Err(busy());
        }
        let (project, selected_generation) = state.github.registration().ok_or_else(changed)?;
        if selected_generation != generation {
            return Err(changed());
        }
        let pins = state.github.capture_version_enrollment_pins(
            project,
            generation,
            &github_setup_project_binding(root)?,
            input.session(),
            input.connection_revision(),
            now,
        )?;
        let input_epoch = self.inner.android_registration_control.epoch()?;
        let mut end = now
            .checked_add(Duration::from_millis(wire::INTENT_MS))
            .ok_or_else(BridgeError::invalid)?
            .min(pins.credential_end);
        let (identity, reviewed, data) = match &input {
            data::Input::CounterEnrollmentReview(value) => {
                let hash = digest(&(&input, project, generation, input_epoch, &pins.target))?;
                (
                    self.inner.session_identity.clone(),
                    None,
                    wire::Review::CounterEnrollmentReview(data::ReviewReference {
                        session_id: value.session_id.clone(),
                        expected_revision: value.expected_revision,
                        expected_connection_revision: value.expected_connection_revision,
                        request_sha256: hash,
                    }),
                )
            }
            data::Input::CounterEnrollmentConnect(value) => {
                let review = enrollment
                    .review
                    .as_ref()
                    .filter(|review| {
                        review.id == value.review_id
                            && now < review.end
                            && review.original.root == *root
                            && review.original.pins == pins
                            && review.original.input_epoch == input_epoch
                            && edit.matches(&review.original.stamp)
                            && producer_ready(review)
                    })
                    .ok_or_else(|| p::refused(p::Reason::ReviewChanged))?;
                end = end.min(review.end);
                (
                    review.identity.clone(),
                    Some(Arc::downgrade(&review.original)),
                    wire::Review::CounterEnrollmentConnect(data::ConnectReference {
                        session_id: value.session_id.clone(),
                        expected_revision: value.expected_revision,
                        expected_connection_revision: value.expected_connection_revision,
                        review_id: value.review_id.clone(),
                        review_sha256: digest(&(&input, input_epoch, &pins.target, &review.offer))?,
                    }),
                )
            }
        };
        let capture = Capture {
            input,
            root: root.clone(),
            pins,
            input_epoch,
            stamp: Arc::new(edit.stamp()?),
            reviewed,
        };
        if !capture.retained_fits() || !data.valid() || !data.retained_fits() || end <= now {
            return Err(BridgeError::invalid());
        }
        Ok(native::Review {
            identity,
            stamp: edit.stamp()?,
            end,
            data,
            activity: None,
            dispatch: None,
            enrollment: Some(capture), operation: None,
        })
    }

    pub(in crate::asset_session) fn enrollment_agent_allow(
        &self,
        state: &mut DocumentState,
        review: native::Review,
        scope: &Arc<rows::NativeScope>,
    ) -> Result<(), BridgeError> {
        if pending(state)
            || state.version_enrollment.permission.is_some()
            || !scope.review.kind().enrollment_family()
            || scope.review != review.data
            || !Arc::ptr_eq(&scope.identity, &review.identity)
            || scope.current(false).is_err()
        {
            return Err(changed());
        }
        let capture = review.enrollment.ok_or_else(BridgeError::invalid)?;
        if !capture.retained_fits() {
            return Err(BridgeError::invalid());
        }
        state.version_enrollment.permission = Some(Permission {
            capture,
            scope: Arc::downgrade(scope),
        });
        Ok(())
    }

    // The first cut precedes status/expiry, lane removal and every destructive
    // tail. A foreign GUI/caller cannot steal a retained linked original.
    pub(super) fn enrollment_origin_allowed(
        &self,
        state: &DocumentState,
        project: &str,
        review_id: Option<&str>,
        entry: Option<&Arc<rows::Entry>>,
    ) -> Result<(), BridgeError> {
        match (&state.version_enrollment.permission, entry) {
            (None, None) => Ok(()),
            (Some(permission), Some(entry))
                if permission.scope.upgrade().is_some_and(|scope| {
                    Arc::ptr_eq(&scope, entry.scope())
                        && scope.runtime_id == project
                        && permission.capture.input.review_id() == review_id
                        && entry.current(false).is_ok()
                }) =>
            {
                Ok(())
            }
            _ => Err(changed()),
        }
    }

    pub(super) fn enrollment_origin_current(
        &self,
        state: &DocumentState,
        project: &str,
        review_id: Option<&str>,
        entry: Option<&Arc<rows::Entry>>,
        generation: u32,
        root: &asset_source::RegisteredRoot,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
        now: Instant,
    ) -> Result<(), BridgeError> {
        self.enrollment_origin_allowed(state, project, review_id, entry)?;
        let Some(entry) = entry else { return Ok(()) };
        let capture = &state
            .version_enrollment
            .permission
            .as_ref()
            .ok_or_else(changed)?
            .capture;
        if capture.input.kind() != entry.scope().review.kind()
            || capture.root != *root
            || capture.pins.generation != generation
            || state.version_enrollment.view.revision != capture.input.revision()
            || !self
                .inner
                .android_registration_control
                .matches_epoch(capture.input_epoch)
            || !edit.matches(&capture.stamp)
            || state.github.capture_version_enrollment_pins(
                project,
                generation,
                &github_setup_project_binding(root)?,
                capture.input.session(),
                capture.input.connection_revision(),
                now,
            )? != capture.pins
        {
            return Err(changed());
        }
        if let Some(original) = &capture.reviewed {
            let review = state
                .version_enrollment
                .review
                .as_ref()
                .ok_or_else(changed)?;
            if !original
                .upgrade()
                .is_some_and(|o| Arc::ptr_eq(&o, &review.original))
                || !Arc::ptr_eq(&review.identity, &entry.scope().identity)
                || !producer_ready(review)
                || now >= review.end
                || !edit.matches(&review.original.stamp)
            {
                return Err(p::refused(p::Reason::ReviewChanged));
            }
        }
        Ok(())
    }

    pub(in crate::asset_session) fn enrollment_agent_revoke(
        &self,
        state: &mut DocumentState,
        scope: &Arc<rows::NativeScope>,
        at: Instant,
    ) {
        let enrollment = &mut state.version_enrollment;
        if !enrollment.permission.as_ref().is_some_and(|permission| {
            permission
                .scope
                .upgrade()
                .is_some_and(|old| Arc::ptr_eq(&old, scope))
        }) {
            return;
        }
        let original = enrollment.lane.as_ref().filter(|lane| {
            lane.agent
                .as_ref()
                .is_some_and(|entry| Arc::ptr_eq(entry.scope(), scope))
        });
        match original {
            Some(lane) => {
                let entry = lane.agent.as_ref().expect("matched original Entry");
                if entry.enrollment_retired(&lane.id) && !lane.control.pending() {
                    // Most importantly: the completed Review producer's actual
                    // Scope/Entry + all3 returns. Keep its private Review/Offer.
                    // Never call State::stop, which would destroy that Review.
                    enrollment.permission = None;
                } else {
                    // Retain active/Unknown original. Driver forwards exact F
                    // OFF Doc; this currentness latch cannot lock OwnerState.
                    lane.control.agent_stop_requested(at);
                }
            }
            None => {
                // An unused exact grant has no admitted native original.
                scope.unused_closed();
                enrollment.permission = None;
            }
        }
    }

    pub(in crate::asset_session) fn enrollment_entry_attached(
        &self,
        entry: &Arc<rows::Entry>,
    ) -> bool {
        self.lock()
            .version_enrollment
            .lane
            .as_ref()
            .is_some_and(|lane| {
                lane.agent
                    .as_ref()
                    .is_some_and(|original| Arc::ptr_eq(original, entry))
            })
    }
}

pub(super) fn unknown(lane: &Lane) {
    if let Some(entry) = &lane.agent {
        entry.unknown(wire::Reason::CleanupUnknown);
    }
}

fn sample(document: &DocumentBinding, lane: &Lane) {
    let Some(entry) = &lane.agent else { return };
    // Actual native retirement already closed this control. Later withdrawal
    // of that old permission must not revoke its producing success/Review.
    if !lane.control.pending() {
        return;
    }
    match entry.first_stop() {
        Some((true, _)) => {
            lane.control.unknown();
            unknown(lane);
        }
        Some((false, at)) => lane.control.stop_at(at),
        None => {}
    }
    if Instant::now() >= lane.end {
        lane.control.stop_at(lane.end);
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if !lane.control.current() {
        // The SAME original Host prepare can still be awaited before HTTP is
        // armed. Retire only its exact ticket OFF Doc; never drop its future
        // or finish its caller. Host's try-only Busy gets another bounded
        // control wake, not a new operation or a renewed cleanup endpoint.
        if let Err(error) = document.enrollment_cancel_host(lane) {
            if error.code != "version_enrollment_busy" {
                lane.control.unknown();
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = document;
    // Publish uncertainty at the SAME F+2 even when an original Host/native
    // future has not returned. Keep polling/holding that exact future; this
    // grants no join or release credit.
    if lane.control.check_cleanup(lane.end).is_err() {
        unknown(lane);
    }
    if lane.control.uncertain() {
        unknown(lane);
    }
}

/// A select around ONE pinned original action, not a replacement task/future.
/// No Doc/Owner/Host/job-book lock survives an original .await into this loop.
pub(super) async fn drive<F: Future>(
    document: &DocumentBinding,
    lane: &Arc<Lane>,
    action: F,
) -> F::Output {
    if lane.agent.is_none() {
        return action.await;
    }
    tokio::pin!(action);
    loop {
        sample(document, lane);
        let now = Instant::now();
        let mut wake = now + Duration::from_millis(100);
        for end in [
            Some(lane.end),
            lane.control.cleanup_end(lane.end),
            lane.agent.as_ref().map(|e| e.scope().read.end()),
        ]
        .into_iter()
        .flatten()
        {
            // A passed endpoint cannot become a hot loop or a renewed cutoff.
            if end > now {
                wake = wake.min(end);
            }
        }
        tokio::select! {
            result = &mut action => { sample(document, lane); return result; },
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {},
        }
    }
}

/// Only the original finish after HTTP observer + jobs/NativeUse + Connection
/// retirement calls this. Status is merely the small DATA being projected.
pub(super) fn returned(lane: &Lane, status: &p::Status, connect: bool) {
    let Some(entry) = &lane.agent else { return };
    let operation = if connect {
        data::Operation::Connect
    } else {
        data::Operation::Review
    };
    let phase = match status.phase {
        p::Phase::Reviewed if !connect => data::Phase::Reviewed,
        p::Phase::Connected if connect => data::Phase::Connected,
        p::Phase::Refused => data::Phase::Refused,
        _ => {
            unknown(lane);
            return;
        }
    };
    let reason: data::OutcomeReason = match serde_json::to_value(status.reason)
        .ok()
        .and_then(|value| serde_json::from_value(value).ok())
    {
        Some(reason) => reason,
        None => {
            unknown(lane);
            return;
        }
    };
    let review = status.review.as_ref().map(|r| data::ReviewView {
        id: r.id.clone(),
        repository: r.repository.clone(),
        version: data::Version {
            name: r.version.name.clone(),
            build: r.version.build,
        },
        reservations: r.reservations,
    });
    let result = data::Snapshot {
        operation,
        phase,
        reason,
        review,
    };
    if !result.valid_for(operation.kind()) {
        unknown(lane);
        return;
    }
    let why = match status.reason {
        p::Reason::None | p::Reason::Connected => wire::Reason::None,
        p::Reason::Cancelled => entry.first_reason().unwrap_or(wire::Reason::UserCancelled),
        p::Reason::Expired => entry.first_reason().unwrap_or(wire::Reason::Expired),
        p::Reason::TargetChanged | p::Reason::ReviewChanged => wire::Reason::ContextChanged,
        p::Reason::Busy => wire::Reason::Busy,
        p::Reason::RuntimeUnavailable => wire::Reason::Unavailable,
        _ => wire::Reason::NativeRefused,
    };
    let effect = if !connect {
        wire::Effect::None
    } else if phase == data::Phase::Connected {
        wire::Effect::LocalMappingObserved
    } else {
        wire::Effect::NotSent
    }; // Entry preserves any genuine earlier GO.
    entry.enrollment_returned(&lane.id, why, effect, Some(result));
}

#[cfg(test)]
#[path = "asset_session_version_enrollment_agent_tests.rs"]
mod tests;
