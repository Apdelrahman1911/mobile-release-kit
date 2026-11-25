//! Fixed native return facet on the SAME passive Supervisor Owner. No runner,
//! task, new deadline, result-shaped join, or renderer-provided source exists.
use super::*;
use crate::{service_metadata_text_protocol as p, service_metadata_text_requests::Entry};
use std::sync::atomic::AtomicBool;
pub(super) struct Completion {
    entry: Arc<Entry>,
    armed: AtomicBool,
    returned: bool,
}
impl Completion {
    fn new(entry: Arc<Entry>) -> Self {
        Self {
            entry,
            armed: AtomicBool::new(false),
            returned: false,
        }
    }
    pub(super) fn arm(&self) -> Result<(), BridgeError> {
        if self.armed.load(Ordering::SeqCst) {
            return Err(BridgeError::invalid());
        }
        self.entry
            .read_claim()
            .map_err(|_| BridgeError::invalid())?;
        self.armed.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub(super) fn unknown(&self) {
        self.entry.unknown()
    }
    pub(super) fn complete(
        mut self,
        result: Result<Value, BridgeError>,
        unknown: bool,
    ) -> Result<Value, BridgeError> {
        let parsed = result.and_then(|v| {
            let platform = match self.entry.input().platform {
                p::Platform::Android => crate::metadata_text_edit_protocol::Platform::Android,
                p::Platform::Ios => crate::metadata_text_edit_protocol::Platform::Ios,
            };
            let original = crate::metadata_text_edit_protocol::observation_result(
                v,
                platform,
                &self.entry.input().locale,
            )?;
            let bytes =
                p::encoded(&original, p::READ_BYTES - 4096).map_err(|_| BridgeError::protocol())?;
            let data: p::Observation =
                serde_json::from_slice(&bytes).map_err(|_| BridgeError::protocol())?;
            data.validate().map_err(|_| BridgeError::protocol())?;
            Ok((data, original))
        });
        let retained = match &parsed {
            Ok((o, _)) => Ok(o.clone()),
            Err(_) => Err(crate::service_protocol::Error::Conflict),
        };
        let joined = self.entry.read_retired(retained, unknown);
        self.returned = true;
        if joined.is_err() {
            self.entry.unknown();
            return Err(BridgeError::cleanup_unknown());
        }
        // Only public already-validated text. Its encoding is independently
        // bounded, not a generic native response or second source observation.
        let (_, original) = parsed?;
        serde_json::to_value(original).map_err(|_| BridgeError::protocol())
    }
}
impl Drop for Completion {
    fn drop(&mut self) {
        if self.armed.load(Ordering::SeqCst) && !self.returned {
            self.entry.unknown()
        }
    }
}
impl Supervisor {
    pub(crate) fn start_agent_metadata_text(
        &self,
        params: Value,
        entry: Arc<Entry>,
    ) -> Result<PassiveQuery, BridgeError> {
        let (sender, receiver) = oneshot::channel();
        let owner = self.admit(
            AdmissionRequest::Passive {
                method: Method::MetadataTextObserve,
                params: &params,
            },
            CompletionTarget::MetadataText {
                sender,
                completion: Completion::new(entry),
            },
        )?;
        Ok(PassiveQuery {
            inner: self.inner.clone(),
            owner,
            receiver,
        })
    }
}
fn entry(owner: &Owner) -> Option<Arc<Entry>> {
    let state = lock(&owner.state);
    match &state.reply {
        Some(PassiveReply::MetadataText { completion, .. }) => Some(completion.entry.clone()),
        _ => None,
    }
}
pub(super) fn limit(owner: &Owner) -> usize {
    if entry(owner).is_some() {
        p::READ_BYTES
    } else {
        owner.profile.stdout_limit()
    }
}
pub(super) fn observe(owner: &Owner, now: Instant) {
    let Some(entry) = entry(owner) else { return };
    let failure = match entry.stop_at(now) {
        Ok(Some(at)) => Some((
            BridgeError::new("cancelled", "The original public-text request was stopped."),
            at,
        )),
        Err(_) => Some((BridgeError::cleanup_unknown(), now)),
        Ok(None) => None,
    };
    if let Some((error, at)) = failure {
        let mut state = lock(&owner.state);
        if state.terminal {
            return;
        }
        state.fail_at(error, at);
        drop(state);
        owner.stop.send_replace(true);
        owner.changed.notify_waiters();
    }
}
pub(super) fn deadline(owner: &Owner, now: Instant, end: Instant) -> Instant {
    if entry(owner).is_some() {
        end.min(now + Duration::from_millis(100))
    } else {
        end
    }
}
pub(super) fn decode(owner: &Owner, bytes: &[u8]) -> Option<Result<ReadOutcome, BridgeError>> {
    entry(owner)?;
    // Preparse node/byte admission on this linked-only read. The original
    // metadata envelope decoder still validates its exact success/error grammar.
    Some((|| {
        if bytes.len() > p::READ_BYTES {
            return Err(BridgeError::protocol());
        }
        crate::protocol::strict_metadata_agent_frame_json(bytes)?;
        crate::metadata_text_edit_protocol::decode_passive_envelope(bytes, &owner.id)
            .map(ReadOutcome::Passive)
    })())
}
