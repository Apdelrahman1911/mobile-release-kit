//! Compact historical DATA for the existing workflow/counter owners. No input,
//! private Consent, provider token, native source or execution authority lives here.
use super::{hex, nullable, original, Kind};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::mem::size_of;
pub(crate) const RESPONSE_LIMIT: usize = 8192;
pub(crate) const SNAPSHOT_BACKING: usize = 4096;
pub(crate) const ROWS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RequestReference {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) request_sha256: String,
}
impl RequestReference {
    pub(crate) fn valid(&self) -> bool {
        original(&self.session_id, self.expected_revision) && hex(&self.request_sha256, 64)
    }
    pub(crate) fn retained_fits(&self) -> bool {
        self.session_id.capacity() <= 128 && self.request_sha256.capacity() <= 128
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Observe {
    Track,
    Reconcile,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RecordReference {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) marker: String,
    pub(crate) record_sha256: String,
    pub(crate) observe: Observe,
    #[serde(deserialize_with = "nullable")]
    pub(crate) run_id: Option<String>,
}
impl RecordReference {
    pub(crate) fn valid(&self) -> bool {
        original(&self.session_id, self.expected_revision)
            && hex(&self.marker, 32)
            && hex(&self.record_sha256, 64)
            && (self.observe == Observe::Track) == self.run_id.is_some()
            && self.run_id.as_ref().is_none_or(|v| decimal(v).is_some())
    }
    pub(crate) fn retained_fits(&self) -> bool {
        self.session_id.capacity() <= 128
            && self.marker.capacity() <= 64
            && self.record_sha256.capacity() <= 128
            && self.run_id.as_ref().is_none_or(|s| s.capacity() <= 32)
    }
}
fn decimal(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 20 || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    s.parse::<u64>().ok().filter(|n| *n > 0)
}
/// Fixed binary backing; serialization still uses canonical lowercase hex.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Hex<const N: usize>(pub(crate) [u8; N]);
impl<const N: usize> Hex<N> {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        if !hex(s, 2 * N) {
            return None;
        }
        let mut out = [0u8; N];
        for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
            fn digit(v: u8) -> u8 {
                if v <= b'9' {
                    v - b'0'
                } else {
                    v - b'a' + 10
                }
            }
            out[i] = digit(pair[0]) * 16 + digit(pair[1]);
        }
        Some(Self(out))
    }
}
impl<const N: usize> Serialize for Hex<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Fixed scratch, no growable serializer/hex String retained in a row.
        let mut bytes = [0u8; 64];
        if N > 32 {
            return Err(serde::ser::Error::custom("hex length"));
        }
        for (i, n) in self.0.iter().enumerate() {
            bytes[2 * i] = b"0123456789abcdef"[(n >> 4) as usize];
            bytes[2 * i + 1] = b"0123456789abcdef"[(n & 15) as usize];
        }
        s.serialize_str(std::str::from_utf8(&bytes[..2 * N]).map_err(serde::ser::Error::custom)?)
    }
}
impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<const N: usize>;
        impl<'de, const N: usize> serde::de::Visitor<'de> for V<N> {
            type Value = Hex<N>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("fixed lowercase hex")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Hex::parse(s).ok_or_else(|| E::custom("hex"))
            }
        }
        d.deserialize_str(V::<N>)
    }
}
/// Canonical existing ledger UUID, fixed binary backing (no format change).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LedgerId(pub(crate) Hex<16>);
impl LedgerId {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        if s.len() != 36 || [8, 13, 18, 23].iter().any(|i| s.as_bytes()[*i] != b'-') {
            return None;
        }
        let mut b = [0u8; 32];
        let mut n = 0;
        for (i, v) in s.bytes().enumerate() {
            if [8, 13, 18, 23].contains(&i) {
                continue;
            }
            if n == 32 {
                return None;
            }
            b[n] = v;
            n += 1;
        }
        let h = Hex::parse(std::str::from_utf8(&b).ok()?)?;
        // Original counter protocol requires UUIDv4 with the RFC4122 variant.
        if h.0[6] >> 4 != 4 || h.0[8] >> 6 != 2 {
            return None;
        }
        Some(Self(h))
    }
}
impl Serialize for LedgerId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut b = [0u8; 36];
        let mut j = 0;
        for n in self.0 .0 {
            while [8, 13, 18, 23].contains(&j) {
                b[j] = b'-';
                j += 1;
            }
            b[j] = b"0123456789abcdef"[(n >> 4) as usize];
            b[j + 1] = b"0123456789abcdef"[(n & 15) as usize];
            j += 2;
        }
        s.serialize_str(std::str::from_utf8(&b).map_err(serde::ser::Error::custom)?)
    }
}
impl<'de> Deserialize<'de> for LedgerId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = LedgerId;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("canonical ledger UUID")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<LedgerId, E> {
                LedgerId::parse(s).ok_or_else(|| E::custom("ledger UUID"))
            }
        }
        d.deserialize_str(V)
    }
}
mod optional_id {
    use super::*;
    pub(super) fn serialize<S: Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(n) => s.serialize_some(&n.to_string()),
            None => s.serialize_none(),
        }
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
        let v = Option::<String>::deserialize(d)?;
        v.map(|s| decimal(&s).ok_or_else(|| serde::de::Error::custom("run id")))
            .transpose()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Purpose {
    Preflight,
    Release,
    Setup,
    Counter,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Pending {
    pub(crate) marker: Hex<16>,
    #[serde(with = "optional_id")]
    pub(crate) run_id: Option<u64>,
    pub(crate) purpose: Purpose,
}
fn rows<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Pending>, D::Error> {
    struct Rows;
    impl<'de> serde::de::Visitor<'de> for Rows {
        type Value = Vec<Pending>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most64 original records")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut a: A,
        ) -> Result<Self::Value, A::Error> {
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
    d.deserialize_seq(Rows)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Platform {
    Android,
    Ios,
    Both,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Stage {
    Candidate,
    ExternalTesting,
    ProductionSubmit,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Snapshot {
    #[serde(rename_all = "camelCase")]
    Prepared {
        marker: Hex<16>,
        prepared_sha256: Hex<32>,
        source_sha: Hex<20>,
        #[serde(deserialize_with = "nullable")]
        platform: Option<Platform>,
        #[serde(deserialize_with = "nullable")]
        stage: Option<Stage>,
    },
    Pending {
        #[serde(deserialize_with = "rows")]
        rows: Vec<Pending>,
    },
    #[serde(rename_all = "camelCase")]
    Observed {
        marker: Hex<16>,
        #[serde(with = "optional_id")]
        run_id: Option<u64>,
        attempt: u16,
        status: super::activity::RunState,
        #[serde(deserialize_with = "nullable")]
        conclusion: Option<super::activity::Conclusion>,
    },
    #[serde(rename_all = "camelCase")]
    Counter {
        marker: Hex<16>,
        commit_sha: Hex<20>,
        ledger_id: LedgerId,
        genesis_sha256: Hex<32>,
    },
}
impl Snapshot {
    pub(crate) fn allocated(&self) -> Option<usize> {
        size_of::<Self>()
            .checked_add(2 * size_of::<usize>())?
            .checked_add(match self {
                Self::Pending { rows } => rows.capacity().checked_mul(size_of::<Pending>())?,
                _ => 0,
            })
    }
    pub(crate) fn valid_for(&self, kind: Kind) -> bool {
        if self.allocated().is_none_or(|n| n > SNAPSHOT_BACKING) {
            return false;
        }
        match self {
            Self::Prepared {
                platform, stage, ..
            } => match kind {
                Kind::PreflightPrepare => platform.is_some() && stage.is_none(),
                Kind::ReleasePrepare => {
                    matches!(platform, Some(Platform::Android | Platform::Ios)) && stage.is_some()
                }
                Kind::SetupPrepare | Kind::CounterPrepare => platform.is_none() && stage.is_none(),
                _ => false,
            },
            Self::Pending { rows } => {
                rows.len() <= ROWS
                    && rows.iter().enumerate().all(|(i, r)| {
                        !rows[..i].iter().any(|old| old.marker == r.marker)
                            && r.run_id != Some(0)
                            && match kind {
                                Kind::PreflightPending => r.purpose == Purpose::Preflight,
                                Kind::ReleasePending => r.purpose == Purpose::Release,
                                Kind::PublicationPending => {
                                    matches!(r.purpose, Purpose::Setup | Purpose::Counter)
                                        && r.run_id.is_none()
                                }
                                _ => false,
                            }
                    })
                    && matches!(
                        kind,
                        Kind::PreflightPending | Kind::ReleasePending | Kind::PublicationPending
                    )
            }
            Self::Observed {
                run_id,
                attempt,
                status,
                conclusion,
                ..
            } => {
                matches!(kind, Kind::PreflightObserve | Kind::ReleaseObserve)
                    && run_id.is_some_and(|n| n > 0)
                    && *attempt == 1
                    && (*status == super::activity::RunState::Completed) == conclusion.is_some()
            }
            Self::Counter { .. } => matches!(kind, Kind::CounterCreate | Kind::CounterReconcile),
        }
    }
}
pub(super) fn optional_snapshot<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<Snapshot>, D::Error> {
    Snapshot::deserialize(d).map(Some)
}
pub(crate) fn requires_result(kind: Kind) -> bool {
    kind.dispatch_family() && !matches!(kind, Kind::PreflightDispatch | Kind::ReleaseDispatch)
}

#[cfg(test)]
#[path = "service_github_dispatch_protocol_tests.rs"]
mod tests;
