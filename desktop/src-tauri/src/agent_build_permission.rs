//! MAIN-only permission revision DATA for the two fixed build families.
//! The original per-family Document counter, not this parser, grants anything.
use super::Access;
use crate::service_protocol::{Error, Id};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainAccess {
    pub(crate) enabled: bool,
    pub(crate) remaining_ms: u64,
    pub(crate) project_id: Option<Id>,
    pub(crate) observation_revision: Option<u64>,
    pub(crate) consumed: bool,
    pub(crate) permission_revision: String,
}
impl MainAccess {
    pub(crate) fn new(access: Access, revision: u64) -> Self {
        Self {
            enabled: access.enabled,
            remaining_ms: access.remaining_ms,
            project_id: access.project_id,
            observation_revision: access.observation_revision,
            consumed: access.consumed,
            permission_revision: revision.to_string(),
        }
    }
}

pub(crate) fn permission_revision(value: &str) -> Result<u64, Error> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|c| c.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err(Error::InvalidRequest);
    }
    value.parse().map_err(|_| Error::InvalidRequest)
}

/// Compare the ACTUALLY returned, user-captured revision at both Doc cuts.
/// Compute overflow BEFORE any Inbox/Doc installation; never refresh expected.
pub(crate) fn permission_next(expected: u64, current: u64) -> Result<u64, Error> {
    if expected != current {
        return Err(Error::AccessDenied);
    }
    current.checked_add(1).ok_or(Error::StateUnknown)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn revisions_are_canonical_full_u64_not_javascript_numbers() {
        for n in [0, 1, (1u64 << 53) + 1, u64::MAX] {
            assert_eq!(permission_revision(&n.to_string()), Ok(n));
        }
        for value in ["", "00", "01", "+1", "-0", " 1", "1.0", "1e3", "18446744073709551616"] {
            assert_eq!(permission_revision(value), Err(Error::InvalidRequest));
        }
        assert_eq!(permission_next(u64::MAX, u64::MAX), Err(Error::StateUnknown));
    }
    #[test]
    fn returned_revision_cannot_survive_pre_first_cut_revoke_or_another_allow() {
        // The production two-cut predicate consumes the ORIGINAL returned
        // revision, including when Revoke completed before the first cut.
        let returned = permission_revision("7").unwrap();
        assert_eq!(permission_next(returned, 8), Err(Error::AccessDenied));
        assert_eq!(permission_next(returned, 7), Ok(8));
        // A successful competing install and a between-cuts Revoke both
        // advance the same counter; neither can rebase this pending Allow.
        assert_eq!(permission_next(returned, 8), Err(Error::AccessDenied));
    }
}
