//! Closed historical Activity DATA. This is not a source, account or read permit.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::mem::size_of;

pub(crate) const SNAPSHOT_BACKING: usize = 4096;
pub(crate) const RESPONSE_LIMIT: usize = 8192;
pub(crate) const ROWS: usize = 30;

/// MAIN comparison only: all counter values, including zero, stay exact in JS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PermissionRevision(pub(crate) u64);
pub(crate) fn decimal(s: &str, zero: bool) -> Option<u64> {
    if s.is_empty()
        || s.len() > 20
        || !s.bytes().all(|c| c.is_ascii_digit())
        || s.len() > 1 && s.starts_with('0')
        || !zero && s == "0"
    {
        return None;
    }
    s.parse().ok()
}
// Exact existing Connection UTC grammar, kept as a closed service DATA
// predicate so the installed CLI does not import a native owner graph.
fn utc(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() != 20
        || !value.is_ascii()
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
        || b.iter()
            .enumerate()
            .any(|(i, c)| ![4, 7, 10, 13, 16, 19].contains(&i) && !c.is_ascii_digit())
    {
        return false;
    }
    let n = |start, end| value[start..end].parse::<u32>().unwrap_or(0);
    let (year, month, day) = (n(0, 4), n(5, 7), n(8, 10));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum = match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    year > 0 && day > 0 && day <= maximum && n(11, 13) < 24 && n(14, 16) < 60 && n(17, 19) < 60
}
impl Serialize for PermissionRevision {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for PermissionRevision {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        decimal(&s, true)
            .map(Self)
            .ok_or_else(|| serde::de::Error::custom("permission revision"))
    }
}
impl PermissionRevision {
    pub(crate) fn successor(self, current: u64) -> Option<u64> {
        (self.0 == current).then_some(())?;
        current.checked_add(1)
    }
}

/// MAIN metadata only. The six existing CLI Access/Status shapes stay unchanged.
/// A typed Tauri result avoids a second, map-heavy Value representation.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainAccess {
    #[serde(flatten)]
    pub(crate) access: super::Access,
    pub(crate) permission_revision: PermissionRevision,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Selection {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32,
}
impl Selection {
    pub(crate) fn valid(&self) -> bool {
        super::original(&self.session_id, self.expected_revision)
            && (1..u32::MAX - 8).contains(&self.expected_revision)
            && (1..u32::MAX - 1).contains(&self.expected_connection_revision)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Reference {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32,
    pub(crate) account_id: String,
    pub(crate) repository_id: String,
}
impl Reference {
    pub(crate) fn selection(&self) -> Selection {
        Selection {
            session_id: self.session_id.clone(),
            expected_revision: self.expected_revision,
            expected_connection_revision: self.expected_connection_revision,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        self.selection().valid()
            && decimal(&self.account_id, false).is_some()
            && decimal(&self.repository_id, false).is_some()
    }
    pub(crate) fn retained_fits(&self) -> bool {
        self.session_id.capacity() <= 128
            && self.account_id.capacity() <= 64
            && self.repository_id.capacity() <= 128
    }
}

// Store numeric IDs without separately allocated text. Their public encoding is
// still the original positive canonical decimal STRING, never a lossy JS number.
mod id {
    use super::*;
    pub(super) fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(v)
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        decimal(&s, false).ok_or_else(|| serde::de::Error::custom("numeric id"))
    }
}
macro_rules! enumeration {
    ($name:ident, $($variant:ident => $value:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub(crate) enum $name { $(#[serde(rename = $value)] $variant),+ }
        impl $name { pub(crate) fn from_str(s: &str) -> Option<Self> { match s { $($value => Some(Self::$variant),)+ _ => None } } }
    };
}
enumeration!(SectionState, Read => "read", Unavailable => "unavailable");
enumeration!(SectionReason, None => "none", Forbidden => "forbidden", Inaccessible => "not-found-or-inaccessible");
enumeration!(Coverage, Complete => "complete", Windowed => "windowed", Unknown => "unknown");
enumeration!(PullState, Open => "open", Closed => "closed");
enumeration!(RunState, Queued => "queued", InProgress => "in_progress", Completed => "completed", Waiting => "waiting", Pending => "pending", Requested => "requested");
enumeration!(Conclusion, Success => "success", Failure => "failure", Neutral => "neutral", Cancelled => "cancelled", Skipped => "skipped", TimedOut => "timed_out", ActionRequired => "action_required", Stale => "stale", StartupFailure => "startup_failure");
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pull {
    #[serde(with = "id")]
    pub(crate) number: u64,
    pub(crate) state: PullState,
    pub(crate) draft: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Run {
    #[serde(with = "id")]
    pub(crate) id: u64,
    pub(crate) attempt: u16,
    pub(crate) status: RunState,
    #[serde(deserialize_with = "super::nullable")]
    pub(crate) conclusion: Option<Conclusion>,
}
// Even malformed service input cannot allocate an unbounded row vector before
// validation. No dynamic Value tree or provider strings are decoded here.
fn rows<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    struct Rows<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Rows<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most thirty rows")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Vec<T>, A::Error> {
            let mut v = Vec::with_capacity(ROWS);
            while let Some(row) = a.next_element()? {
                if v.len() == ROWS {
                    return Err(serde::de::Error::custom("rows limit"));
                }
                v.push(row);
            }
            Ok(v)
        }
    }
    d.deserialize_seq(Rows(std::marker::PhantomData))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "T: Deserialize<'de>"))]
pub(crate) struct Section<T> {
    pub(crate) state: SectionState,
    pub(crate) reason: SectionReason,
    pub(crate) coverage: Coverage,
    #[serde(deserialize_with = "super::nullable")]
    pub(crate) total: Option<u32>,
    #[serde(deserialize_with = "rows")]
    pub(crate) rows: Vec<T>,
}
impl<T> Section<T> {
    fn valid(&self) -> bool {
        self.rows.len() <= ROWS
            && match self.state {
                SectionState::Unavailable => {
                    self.rows.is_empty()
                        && self.total.is_none()
                        && self.coverage == Coverage::Unknown
                        && self.reason != SectionReason::None
                }
                SectionState::Read => {
                    self.reason == SectionReason::None
                        && self
                            .total
                            .is_none_or(|n| n <= i32::MAX as u32 && n as usize >= self.rows.len())
                        && self.coverage
                            == if self.total == Some(self.rows.len() as u32) {
                                Coverage::Complete
                            } else {
                                Coverage::Windowed
                            }
                }
            }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Snapshot {
    #[serde(with = "id")]
    pub(crate) account_id: u64,
    #[serde(with = "id")]
    pub(crate) repository_id: u64,
    pub(crate) observed_at: String,
    pub(crate) pull_requests: Section<Pull>,
    pub(crate) workflow_runs: Section<Run>,
}
// Absence preserves every old CLI row. An explicitly present null must not
// silently widen the six older closed decoders to accept a new unused field.
pub(super) fn optional_snapshot<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<Snapshot>, D::Error> {
    Snapshot::deserialize(d).map(Some)
}
impl Snapshot {
    pub(crate) fn allocated(&self) -> Option<usize> {
        size_of::<Self>()
            .checked_add(2 * size_of::<usize>())?
            .checked_add(self.observed_at.capacity())?
            .checked_add(
                self.pull_requests
                    .rows
                    .capacity()
                    .checked_mul(size_of::<Pull>())?,
            )?
            .checked_add(
                self.workflow_runs
                    .rows
                    .capacity()
                    .checked_mul(size_of::<Run>())?,
            )
    }
    pub(crate) fn valid(&self) -> bool {
        self.account_id != 0
            && self.repository_id != 0
            && utc(&self.observed_at)
            && self.allocated().is_some_and(|n| n <= SNAPSHOT_BACKING)
            && self.pull_requests.valid()
            && self.workflow_runs.valid()
            && self.pull_requests.rows.iter().enumerate().all(|(i, row)| {
                row.number != 0
                    && !self.pull_requests.rows[..i]
                        .iter()
                        .any(|r| r.number == row.number)
            })
            && self.workflow_runs.rows.iter().enumerate().all(|(i, row)| {
                row.id != 0
                    && (1..=1000).contains(&row.attempt)
                    && (row.status == RunState::Completed || row.conclusion.is_none())
                    && !self.workflow_runs.rows[..i].iter().any(|r| r.id == row.id)
            })
    }
    pub(crate) fn matches(&self, reference: &Reference) -> bool {
        decimal(&reference.account_id, false) == Some(self.account_id)
            && decimal(&reference.repository_id, false) == Some(self.repository_id)
    }
}

#[cfg(test)]
#[path = "service_github_activity_protocol_tests.rs"]
mod tests;
