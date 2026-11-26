//! MAIN-only revision DATA on the EXISTING shared Store counter. This is not
//! a grant/queue/clock. All production counter cuts run under the same Doc lock.
use crate::service_protocol::Error;
use serde::Serialize;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainAccess<T> {
    #[serde(flatten)]
    pub(crate) access: T,
    pub(crate) permission_revision: String,
}
impl<T> MainAccess<T> {
    pub(crate) fn new(access: T, revision: u64) -> Self {
        Self {
            access,
            permission_revision: revision.to_string(),
        }
    }
}
pub(crate) fn parse(value: &str) -> Result<u64, Error> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|c| c.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err(Error::InvalidRequest);
    }
    value.parse().map_err(|_| Error::InvalidRequest)
}
/// Compare the original user-captured value; never rebase at either native cut.
/// Overflow is detected before any link/lease can become installed.
pub(crate) fn next(counter: &AtomicU64, expected: u64) -> Result<u64, Error> {
    if counter.load(Ordering::Acquire) != expected {
        return Err(Error::AccessDenied);
    }
    expected.checked_add(1).ok_or(Error::StateUnknown)
}
/// Consume BEFORE attaching a native link or publishing any usable grant. A
/// later installation/return error cannot replay the same permission revision.
pub(crate) fn consume(counter: &AtomicU64, expected: u64) -> Result<u64, Error> {
    let next = next(counter, expected)?;
    counter
        .compare_exchange(expected, next, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| Error::AccessDenied)?;
    Ok(next)
}
/// Revoke linearizes on this same counter even before a first Allow arrives.
/// The original invocation timestamp and every STOP survive overflow/error.
pub(crate) fn revoke(
    counter: &AtomicU64,
    at: Instant,
    stop: impl FnOnce(Instant),
) -> Result<u64, Error> {
    let advanced = counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
        .map(|old| old + 1)
        .map_err(|_| Error::StateUnknown);
    stop(at);
    advanced
}
/// A lost original relay cannot accept future grants. Reuse the existing
/// exhausted counter sentinel, not another permission flag or tombstone pool.
pub(crate) fn relay_lost(counter: &AtomicU64, at: Instant, stop: impl FnOnce(Instant)) {
    counter.store(u64::MAX, Ordering::Release);
    stop(at);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn store_permission_revision_is_canonical_u64_string_and_main_only() {
        for n in [0, 1, (1u64 << 53) + 1, u64::MAX] {
            assert_eq!(parse(&n.to_string()), Ok(n));
        }
        for s in [
            "",
            "00",
            "01",
            "+1",
            "-1",
            "1.0",
            "1e3",
            "1\n",
            " 1",
            "18446744073709551616",
        ] {
            assert_eq!(parse(s), Err(Error::InvalidRequest));
        }
        let old = crate::service_store_protocol::Access::empty();
        let cli = serde_json::to_value(&old).unwrap();
        assert!(cli.get("permissionRevision").is_none());
        let main = serde_json::to_value(MainAccess::new(old, (1u64 << 53) + 1)).unwrap();
        assert_eq!(main["permissionRevision"], "9007199254740993");
        let mut unchanged = main;
        unchanged
            .as_object_mut()
            .unwrap()
            .remove("permissionRevision");
        assert_eq!(unchanged, cli);
        // Existing MAIN Allow decoders require the original revision too;
        // neither the old prepared statusRevision nor a missing field substitutes.
        let store = serde_json::json!({"kind":"access-check","operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"expectedStatusRevision":1,"expectedPermissionRevision":"0","consentVersion":"agent-android-store-access-once-v1"});
        assert!(
            super::super::decode::<super::super::Allow>(&serde_json::to_vec(&store).unwrap())
                .is_ok()
        );
        let start = serde_json::json!({"origin":{"projectId":"a".repeat(32),"serviceInstance":"b".repeat(32),"requestId":"c".repeat(32)},"review":{"reviewId":"d".repeat(32),"operation":{"operationId":"e".repeat(32),"ownerGeneration":"f".repeat(32),"statusRevision":1}},"expectedPermissionRevision":"0","consentVersion":"agent-android-store-access-once-v1"});
        assert!(
            super::super::preparation::decode::<super::super::preparation::AllowStart>(
                &serde_json::to_vec(&start).unwrap()
            )
            .is_ok()
        );
        for value in [
            None,
            Some(serde_json::json!(0)),
            Some(serde_json::Value::Null),
        ] {
            let mut bad = store.clone();
            let mut bad_start = start.clone();
            match value {
                Some(v) => {
                    bad["expectedPermissionRevision"] = v.clone();
                    bad_start["expectedPermissionRevision"] = v;
                }
                None => {
                    bad.as_object_mut()
                        .unwrap()
                        .remove("expectedPermissionRevision");
                    bad_start
                        .as_object_mut()
                        .unwrap()
                        .remove("expectedPermissionRevision");
                }
            }
            assert!(super::super::decode::<super::super::Allow>(
                &serde_json::to_vec(&bad).unwrap()
            )
            .is_err());
            assert!(
                super::super::preparation::decode::<super::super::preparation::AllowStart>(
                    &serde_json::to_vec(&bad_start).unwrap()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn store_permission_revoke_before_first_cut_and_between_cuts_refuses_old_user_revision() {
        let counter = AtomicU64::new(7);
        let returned = parse("7").unwrap();
        let at = Instant::now();
        assert_eq!(revoke(&counter, at, |seen| assert_eq!(seen, at)), Ok(8));
        assert_eq!(next(&counter, returned), Err(Error::AccessDenied));
        let next_returned = counter.load(Ordering::Acquire);
        assert_eq!(next(&counter, next_returned), Ok(9));
        revoke(&counter, at, |_| {}).unwrap();
        assert_eq!(consume(&counter, next_returned), Err(Error::AccessDenied));
    }
    #[test]
    fn store_permission_all_family_commit_consumes_before_fallible_install_and_cannot_replay() {
        let counter = AtomicU64::new(0);
        let user = 0;
        assert_eq!(next(&counter, user), Ok(1));
        assert_eq!(next(&counter, user), Ok(1));
        assert_eq!(consume(&counter, user), Ok(1));
        // A subsequent fallible binding/lease call has not returned. Neither
        // another family nor a delayed retry may reuse this original revision.
        assert_eq!(next(&counter, user), Err(Error::AccessDenied));
        assert_eq!(consume(&counter, user), Err(Error::AccessDenied));
        assert_eq!(consume(&counter, 1), Ok(2));
    }
    #[test]
    fn store_permission_overflow_and_relay_loss_still_stop_at_original_invocation() {
        let counter = AtomicU64::new(u64::MAX - 1);
        let at = Instant::now();
        let mut stopped = 0;
        assert_eq!(consume(&counter, u64::MAX - 1), Ok(u64::MAX));
        assert_eq!(next(&counter, u64::MAX), Err(Error::StateUnknown));
        assert_eq!(
            revoke(&counter, at, |seen| {
                assert_eq!(seen, at);
                stopped += 1;
            }),
            Err(Error::StateUnknown)
        );
        assert_eq!(stopped, 1);
        assert_eq!(counter.load(Ordering::Acquire), u64::MAX);
        let counter = AtomicU64::new(4);
        relay_lost(&counter, at, |seen| {
            assert_eq!(seen, at);
            stopped += 1;
        });
        assert_eq!(stopped, 2);
        assert_eq!(next(&counter, 4), Err(Error::AccessDenied));
        assert_eq!(next(&counter, u64::MAX), Err(Error::StateUnknown));
    }
}
