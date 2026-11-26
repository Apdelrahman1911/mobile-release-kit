//! Codes-only DATA from the original repository/PR/retry owners. Neither a
//! marker nor this complete journal projection is a native review or permission.
use super::{dispatch::Hex, Effect, Kind, Reason, State};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::mem::size_of;
pub(crate) const ROWS: usize = 32;

/// The original positive u64 IDs keep their STRING wire representation (JS
/// numbers would silently lose large GitHub IDs). The retained backing is fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Number(pub(crate) u64);
impl Number {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        (!s.is_empty() && s.len() <= 20 && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok()).flatten().filter(|n| *n > 0).map(Self)
    }
}
impl Serialize for Number {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok,S::Error> { s.collect_str(&self.0) }
}
impl<'de> Deserialize<'de> for Number {
    fn deserialize<D: Deserializer<'de>>(d:D)->Result<Self,D::Error> {
        struct N;
        impl<'de> serde::de::Visitor<'de> for N {
            type Value=Number;
            fn expecting(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str("positive canonical numeric ID string")}
            fn visit_str<E:serde::de::Error>(self,s:&str)->Result<Number,E> {Number::parse(s).ok_or_else(||E::custom("ID"))}
        }
        d.deserialize_str(N)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag="target",rename_all="kebab-case",deny_unknown_fields)]
pub(crate) enum Observation {
    Repository { id:Number },
    Pr { id:Number, number:Number },
    #[serde(rename_all="camelCase")]
    FailedJobs { run_id:Number, attempt:u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Record {
    pub(crate) marker: Hex<16>,
    pub(crate) record_sha256: Hex<32>,
    pub(crate) claimed: bool,
    pub(crate) acknowledged: bool,
    pub(crate) closed: bool,
}
fn rows<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Record>, D::Error> {
    struct Rows;
    impl<'de> serde::de::Visitor<'de> for Rows {
        type Value = Vec<Record>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most32 original journal records")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
            let mut result = Vec::with_capacity(ROWS);
            while let Some(value) = a.next_element()? {
                if result.len() == ROWS { return Err(serde::de::Error::custom("record limit")); }
                result.push(value);
            }
            Ok(result)
        }
    }
    d.deserialize_seq(Rows)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Snapshot {
    #[serde(rename_all = "camelCase")]
    Prepared {
        consent_id: Hex<16>,
        prepared_sha256: Hex<32>,
        next: Kind,
    },
    Pending { #[serde(deserialize_with = "rows")] rows: Vec<Record> },
    Reconciled { marker: Hex<16>, effect: Effect, #[serde(deserialize_with="super::nullable")] observed:Option<Observation> },
}
impl Snapshot {
    pub(crate) fn heap(&self) -> Option<usize> {
        match self { Self::Pending { rows } => rows.capacity().checked_mul(size_of::<Record>()), _ => Some(0) }
    }
    pub(crate) fn valid_for(&self, kind: Kind) -> bool {
        use Kind as K;
        match self {
            Self::Prepared { next, .. } => match kind {
                K::RepositoryPrepare => *next == K::RepositoryCreate,
                K::PrPrepare => matches!(next, K::DraftPrCreate | K::PrCreate),
                K::FailedJobsPrepare => *next == K::FailedJobsRetry,
                _ => false,
            },
            Self::Pending { rows } => matches!(kind, K::RepositoryPending | K::PrPending | K::FailedJobsPending)
                && rows.len() <= ROWS && rows.capacity() <= ROWS
                && rows.iter().enumerate().all(|(i, r)| {
                    !rows[..i].iter().any(|old| old.marker == r.marker)
                        && (!r.acknowledged || r.claimed)
                        && (!r.closed || kind == K::PrPending && r.claimed && r.acknowledged)
                }),
            Self::Reconciled { effect, observed, .. } => kind.operation_reconcile() && effect.valid_for(kind)
                && match observed {
                    None => *effect == Effect::Unresolved,
                    Some(Observation::Repository{id}) => kind == K::RepositoryReconcile && id.0 > 0
                        && matches!(effect, Effect::CreatedObserved | Effect::FoundUnattributed),
                    Some(Observation::Pr{id,number}) => kind == K::PrReconcile && id.0 > 0 && number.0 > 0
                        && matches!(effect, Effect::CreatedObserved | Effect::ClosedConfirmed | Effect::FoundUnattributed),
                    Some(Observation::FailedJobs{run_id,attempt}) => kind == K::FailedJobsReconcile && run_id.0 > 0 && (1..=1000).contains(attempt)
                        && matches!(effect, Effect::Accepted | Effect::AdvancedUnattributed),
                },
        }
    }
    pub(crate) fn valid_reason(&self, kind: Kind, reason: Reason) -> bool {
        self.valid_for(kind) && match self {
            Self::Prepared { .. } | Self::Pending { .. } => reason == Reason::None,
            Self::Reconciled { effect, .. } => match effect {
                Effect::CreatedObserved | Effect::ClosedConfirmed | Effect::Accepted => reason == Reason::None,
                Effect::Unresolved | Effect::FoundUnattributed | Effect::AdvancedUnattributed =>
                    matches!(reason, Reason::None | Reason::NativeRefused),
                _ => false, // stopped/invalid readbacks are not inventory/diagnostic receipts
            },
        }
    }
    pub(crate) fn valid_row(&self, kind: Kind, state: State, reason: Reason, effect: Effect) -> bool {
        self.valid_reason(kind, reason)
            && match self {
                Self::Prepared { .. } | Self::Pending { .. } => state == State::Complete && effect == Effect::None,
                Self::Reconciled { effect: e, .. } => *e == effect
                    && (state == State::Complete && reason == Reason::None
                        || state == State::Refused && reason == Reason::NativeRefused),
            }
    }
}

#[cfg(test)]
#[path="service_github_operation_protocol_tests.rs"]
mod tests;
