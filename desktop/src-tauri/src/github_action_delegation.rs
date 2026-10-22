//! Private three-kind Consent bridge. No public status creates this identity.
use super::*;
use crate::{
    edit_owner::SavedEditStamp, service_github_action_protocol as p,
    service_github_action_requests as r,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Weak};
pub(crate) struct Review {
    pub(crate) identity: Arc<()>,
    pub(crate) stamp: SavedEditStamp,
    pub(crate) end: Instant,
    pub(crate) data: p::Review,
    pub(crate) activity: Option<super::activity::delegation::Capture>,
    pub(crate) dispatch: Option<dispatch::Capture>,
}
struct Hash {
    sha: Sha256,
}
impl std::io::Write for Hash {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.sha.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(super) fn review<T: Serialize>(
    kind: p::Kind,
    session: &str,
    id: &str,
    revision: u32,
    prepared: &T,
    identity: Arc<()>,
    stamp: SavedEditStamp,
    end: Instant,
) -> Result<Review, BridgeError> {
    let mut hash = Hash { sha: Sha256::new() };
    serde_json::to_writer(&mut hash, prepared).map_err(|_| BridgeError::protocol())?;
    let data = p::Review::from_prepared(kind, p::PreparedReference {
        session_id: session.into(),
        consent_id: id.into(),
        expected_revision: revision,
        prepared_sha256: format!("{:x}", hash.sha.finalize()),
    }).ok_or_else(BridgeError::protocol)?;
    if !data.valid() {
        return Err(BridgeError::protocol());
    }
    Ok(Review {
        identity,
        stamp,
        end,
        data,
        activity: None,
        dispatch: None,
    })
}
pub(super) fn origin(scope: &Option<Weak<r::NativeScope>>, entry: Option<&Arc<r::Entry>>) -> bool {
    match (scope, entry) {
        (None, None) => true,
        (Some(scope), Some(entry)) => scope
            .upgrade()
            .is_some_and(|s| Arc::ptr_eq(&s, entry.scope()) && entry.current(false).is_ok()),
        _ => false,
    }
}
pub(super) fn revoke(scope: &Option<Weak<r::NativeScope>>) {
    if let Some(scope) = scope.as_ref().and_then(Weak::upgrade) {
        scope.unused_closed()
    }
}
pub(super) fn unknown(entry: &Option<Arc<r::Entry>>) {
    if let Some(e) = entry {
        e.unknown(p::Reason::CleanupUnknown)
    }
}
pub(super) fn reason(s: &str) -> p::Reason {
    match s {
        "none" => p::Reason::None,
        "cancelled" => p::Reason::UserCancelled,
        "expired" | "consent-expired" => p::Reason::Expired,
        "target-changed" => p::Reason::ContextChanged,
        "busy" => p::Reason::Busy,
        "runtime-unavailable" | "unqualified" => p::Reason::Unavailable,
        "cleanup-unknown" => p::Reason::CleanupUnknown,
        _ => p::Reason::NativeRefused,
    }
}
pub(super) fn accepted<R: Serialize, E: Serialize>(
    entry: &Option<Arc<r::Entry>>,
    id: &str,
    r: R,
    e: E,
) {
    let Some(entry) = entry else { return };
    let Some(reason_value) = serde_json::to_value(r)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
    else {
        entry.unknown(p::Reason::CleanupUnknown);
        return;
    };
    let effect = serde_json::to_value(e)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok());
    match effect {
        Some(effect) => entry.returned_native(id, reason(&reason_value), effect),
        None => entry.unknown(p::Reason::CleanupUnknown),
    }
}

pub(crate) use p::Selection;

#[cfg(test)]
#[path = "github_action_delegation_tests.rs"]
mod tests;

#[path="github_dispatch_delegation.rs"]
pub(crate) mod dispatch;
