//! Finite private-vault namespace and original mutation bookkeeping.
//!
//! This is subordinate DATA owned by the existing document operation, not a new
//! task/timeout/recovery owner. Native calls must record their actual returns;
//! none of these projections authenticates ciphertext, retries an operation or
//! adopts/removes debris. Unknown and cancellation never become success merely
//! because a later status request observes plausible current files.
use crate::vault_format::{self as format, Id, Mutation};
use serde::Serialize;
use std::collections::BTreeSet;

pub(crate) use crate::vault_format::{DESCRIPTOR_COUNT, WORKING_BYTES};
pub(crate) const ENTRY_COUNT: usize = 256;
pub(crate) const DISK_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const RESIDENT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Problem {
    State, Bounds, Identity, UnsupportedFilesystem, UnsupportedEntry, Busy,
    Native, Interrupted, Corrupt, DurabilityUnknown, CleanupUnknown, Stopped,
}
type Result<T> = std::result::Result<T, Problem>;

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[path = "vault_store_linux.rs"]
mod linux;
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) use linux::{Location, Observation, ReadOriginal, ReadWitness, RootWitness, StoreBook};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "vault_store_macos.rs"]
mod macos;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use macos::{Location, Observation, ReadOriginal, ReadWitness, RootWitness, StoreBook};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Effect { NotStarted, KnownNone, KnownApplied, Unknown }
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Durability { NotRun, Confirmed, Unknown }
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Cleanup { Pending, Known, Unknown }
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StorageOutcome { pub(crate) effect: Effect, pub(crate) durability: Durability, pub(crate) cleanup: Cleanup }

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fence { Absent, Possible, Durable, Clearing, Cleared, Unknown }

/// A record mutation has only one intent and one possible effect call. This
/// fixed record stays in the original StoreBook through stop/cleanup/join.
struct MutationProgress {
    operation: Mutation, fence: Fence, effect_entered: bool, effect_sync_returned: bool, stopped: bool,
    first: Option<Problem>, outcome: StorageOutcome,
}
impl MutationProgress {
    fn new(operation: Mutation) -> Self {
        Self { operation, fence: Fence::Absent, effect_entered: false, effect_sync_returned: false, stopped: false, first: None,
            outcome: StorageOutcome { effect: Effect::NotStarted, durability: Durability::NotRun, cleanup: Cleanup::Pending } }
    }
    fn fail(&mut self, problem: Problem) {
        if self.first.is_none() { self.first = Some(problem); }
    }
    fn stop(&mut self) { self.stopped = true; self.fail(Problem::Stopped); }
    fn working(&self) -> Result<()> {
        if self.stopped { Err(Problem::Stopped) } else if self.first.is_some() { Err(Problem::State) } else { Ok(()) }
    }
    fn begin_intent(&mut self) -> Result<()> {
        self.working()?;
        if self.fence != Fence::Absent || self.effect_entered || self.outcome.effect != Effect::NotStarted { return Err(Problem::State); }
        self.fence = Fence::Possible; Ok(())
    }
    fn intent_durable_returned(&mut self) -> Result<()> {
        // Record the actual already-entered file+directory sync return even if
        // STOP arrived meanwhile. It is not permission to enter the effect.
        if self.fence != Fence::Possible || self.effect_entered { return Err(Problem::State); }
        self.fence = Fence::Durable; Ok(())
    }
    fn enter_effect(&mut self) -> Result<()> {
        self.working()?;
        if self.fence != Fence::Durable || self.effect_entered { return Err(Problem::State); }
        self.effect_entered = true; self.outcome.effect = Effect::Unknown; Ok(())
    }
    fn applied_returned(&mut self) -> Result<()> {
        if !self.effect_entered || self.outcome.effect != Effect::Unknown { return Err(Problem::State); }
        self.outcome.effect = Effect::KnownApplied; Ok(())
    }
    fn no_effect_proved(&mut self, proof: &NoEffectProof) -> Result<()> {
        // Errno, cancellation, candidate existence or a currently absent path
        // alone is not this proof. The native owner must freshly compare the
        // original expected slot/absence and positively clean its own candidate.
        if !proof.target_original_unchanged || !proof.candidate_cleanup_known
            || self.outcome.effect == Effect::KnownApplied || self.outcome.durability != Durability::NotRun
            || matches!(self.fence, Fence::Clearing | Fence::Cleared | Fence::Unknown) { return Err(Problem::State); }
        self.outcome.effect = Effect::KnownNone; Ok(())
    }
    fn absent_intent_proved(&mut self, proof: &AbsentIntentProof) -> Result<()> {
        // An exclusive intent open which never yielded an original must not be
        // reported as an unlink. Only actual fresh absence plus directory sync
        // under the ORIGINAL cleanup endpoint can settle this no-fence case.
        // This cannot excuse an owned/pending intent or an entered record effect.
        if self.effect_entered || self.outcome.effect != Effect::KnownNone
            || !matches!(self.fence, Fence::Absent | Fence::Possible)
            || !proof.no_intent_original || !proof.current_absence_confirmed || !proof.directory_sync_confirmed {
            return Err(Problem::State);
        }
        self.fence = Fence::Cleared; Ok(())
    }
    fn enter_effect_sync(&mut self) -> Result<()> {
        if self.outcome.effect != Effect::KnownApplied || self.outcome.durability != Durability::NotRun { return Err(Problem::State); }
        self.outcome.durability = Durability::Unknown; Ok(())
    }
    fn effect_sync_returned(&mut self, success: bool) -> Result<()> {
        if self.outcome.effect != Effect::KnownApplied || self.outcome.durability != Durability::Unknown || self.effect_sync_returned { return Err(Problem::State); }
        self.effect_sync_returned = true;
        if success { self.outcome.durability = Durability::Confirmed; }
        else { self.fail(Problem::DurabilityUnknown); }
        Ok(())
    }
    fn enter_clear(&mut self, original_intent_matched: bool) -> Result<()> {
        let permissible = self.outcome.effect == Effect::KnownNone
            || self.outcome.effect == Effect::KnownApplied && self.outcome.durability == Durability::Confirmed;
        if !original_intent_matched || !permissible || !matches!(self.fence, Fence::Possible | Fence::Durable) {
            return Err(Problem::State);
        }
        // Work STOP may be set. The caller still needs the ORIGINAL cleanup
        // endpoint before this cleanup call, never a fresh phase timeout.
        self.fence = Fence::Clearing; Ok(())
    }
    fn clear_sync_returned(&mut self, success: bool) -> Result<()> {
        if self.fence != Fence::Clearing { return Err(Problem::State); }
        if success { self.fence = Fence::Cleared; }
        else { self.fence = Fence::Unknown; self.fail(Problem::DurabilityUnknown); }
        Ok(())
    }
    fn cleanup_returned(&mut self, all_originals_known: bool) {
        if !all_originals_known {
            self.outcome.cleanup = Cleanup::Unknown; self.fail(Problem::CleanupUnknown);
        } else if self.outcome.cleanup == Cleanup::Pending { self.outcome.cleanup = Cleanup::Known; }
        // A later positive close cannot overwrite a previously unknown cleanup
        // operation or grant an old API call a manufactured success receipt.
    }
    fn success(&self) -> bool {
        !self.stopped && self.first.is_none() && self.effect_entered && self.fence == Fence::Cleared
            && self.outcome == StorageOutcome { effect: Effect::KnownApplied, durability: Durability::Confirmed, cleanup: Cleanup::Known }
    }
    fn mutation_paused(&self) -> bool {
        matches!(self.fence, Fence::Possible | Fence::Durable | Fence::Clearing | Fence::Unknown)
            || self.outcome.effect == Effect::Unknown || self.outcome.durability == Durability::Unknown
            || self.outcome.cleanup != Cleanup::Known
    }
}

// Constructed only inside this storage module from actual native rechecks, not
// accepted from an IPC caller or an Error-to-bool convenience conversion.
struct NoEffectProof { target_original_unchanged: bool, candidate_cleanup_known: bool }
struct AbsentIntentProof { no_intent_original: bool, current_absence_confirmed: bool, directory_sync_confirmed: bool }

#[derive(Clone, Copy, PartialEq, Eq)]
enum Name { Reservation, Header, Lock, Intent, Record(Id), Candidate(Id), Other }
impl Name {
    fn parse(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > 255 || name.contains(&0) || name.contains(&b'/') || name == b"." || name == b".." {
            return Err(Problem::UnsupportedEntry);
        }
        let text = std::str::from_utf8(name).map_err(|_| Problem::UnsupportedEntry)?;
        Ok(match text {
            format::RESERVATION_NAME => Self::Reservation,
            format::HEADER_NAME => Self::Header,
            format::LOCK_NAME => Self::Lock,
            format::INTENT_NAME => Self::Intent,
            _ => if let Some(token) = text.strip_prefix("record-") {
                Self::Record(Id::from_token(token).map_err(|_| Problem::UnsupportedEntry)?)
            } else if let Some(token) = text.strip_prefix(".candidate-") {
                Self::Candidate(Id::from_token(token).map_err(|_| Problem::UnsupportedEntry)?)
            } else { Self::Other },
        })
    }
}

/// Only a bounded namespace/byte census; a plausible header length is not an
/// authenticated vault. The current original header and reserved identity must
/// still be checked before a key lease or descriptor can be published.
struct Inventory {
    names: BTreeSet<Vec<u8>>, records: Vec<Id>, bytes: u64,
    reservation: bool, header: bool, lock: bool, intent: bool, debris: bool, malformed: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Inspection { Uninitialized, Locked, Interrupted, Corrupt }
impl Inventory {
    fn new() -> Self {
        Self { names: BTreeSet::new(), records: Vec::new(), bytes: 0,
            reservation: false, header: false, lock: false, intent: false, debris: false, malformed: false }
    }
    fn add(&mut self, name: &[u8], bytes: u64, ordinary_private_single_link: bool) -> Result<()> {
        if !ordinary_private_single_link { return Err(Problem::Identity); }
        if self.names.len() >= ENTRY_COUNT || self.names.contains(name) { return Err(Problem::Bounds); }
        let total = self.bytes.checked_add(bytes).filter(|value| *value <= DISK_BYTES).ok_or(Problem::Bounds)?;
        let kind = Name::parse(name)?;
        if matches!(kind, Name::Record(_)) && self.records.len() >= DESCRIPTOR_COUNT { return Err(Problem::Bounds); }
        self.names.insert(name.to_vec()); self.bytes = total;
        match kind {
            Name::Reservation => { self.reservation = true; self.malformed |= bytes != format::RESERVATION_BYTES as u64; },
            Name::Header => { self.header = true; self.malformed |= bytes != format::HEADER_BYTES as u64; },
            Name::Lock => { self.lock = true; self.malformed |= bytes != 0; },
            Name::Intent => { self.intent = true; }, // Bad/unauthenticated intent still fences mutation.
            Name::Record(id) => {
                self.records.push(id);
                self.malformed |= !(format::RECORD_OVERHEAD as u64 + 9..=format::RECORD_LIMIT as u64).contains(&bytes);
            },
            Name::Candidate(_) | Name::Other => { self.debris = true; },
        }
        Ok(())
    }
    fn inspection(&self) -> Inspection {
        if self.malformed || self.header && !self.reservation || !self.lock && !self.names.is_empty() {
            return Inspection::Corrupt;
        }
        if self.intent || self.debris || self.reservation && !self.header || !self.header && !self.records.is_empty() {
            return Inspection::Interrupted;
        }
        if self.header { Inspection::Locked } else { Inspection::Uninitialized }
    }
    fn candidate_budget(&self, candidate: usize) -> Result<()> {
        if self.inspection() != Inspection::Locked || candidate > format::RECORD_LIMIT || self.names.len() + 2 > ENTRY_COUNT {
            return Err(Problem::State);
        }
        // Current records, old revision, new candidate, controls and intent all
        // count simultaneously; eventual replacement is not advance credit.
        self.bytes.checked_add(candidate as u64).and_then(|value| value.checked_add(format::INTENT_BYTES as u64))
            .filter(|value| *value <= DISK_BYTES).ok_or(Problem::Bounds).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn progress() -> MutationProgress {
        let mut value = MutationProgress::new(Mutation::Replace);
        value.begin_intent().unwrap(); value.intent_durable_returned().unwrap(); value
    }
    fn inventory() -> Inventory {
        let mut value = Inventory::new();
        for (name, size) in [(format::LOCK_NAME, 0), (format::RESERVATION_NAME, 48), (format::HEADER_NAME, 104)] {
            value.add(name.as_bytes(), size, true).unwrap();
        }
        value
    }

    #[test]
    fn never_created_intent_requires_actual_absence_and_cleanup_directory_sync() {
        let mut value = MutationProgress::new(Mutation::New);
        value.begin_intent().unwrap(); value.stop();
        value.no_effect_proved(&NoEffectProof { target_original_unchanged: true, candidate_cleanup_known: true }).unwrap();
        for (no_intent_original, current_absence_confirmed, directory_sync_confirmed) in
            [(false, true, true), (true, false, true), (true, true, false)] {
            assert!(value.absent_intent_proved(&AbsentIntentProof { no_intent_original, current_absence_confirmed, directory_sync_confirmed }).is_err());
        }
        value.absent_intent_proved(&AbsentIntentProof { no_intent_original: true, current_absence_confirmed: true, directory_sync_confirmed: true }).unwrap();
        value.cleanup_returned(true);
        assert!(!value.mutation_paused()); assert!(!value.success()); assert!(value.stopped);
        assert_eq!(value.outcome.effect, Effect::KnownNone);
        assert!(value.begin_intent().is_err());
        let mut entered = progress(); entered.enter_effect().unwrap();
        assert!(entered.absent_intent_proved(&AbsentIntentProof { no_intent_original: true, current_absence_confirmed: true, directory_sync_confirmed: true }).is_err());
    }

    #[test]
    fn durable_effect_clear_and_cleanup_are_separate_nonrenewable_facts() {
        for operation in [Mutation::New, Mutation::Replace, Mutation::Delete] {
            let mut value = MutationProgress::new(operation);
            assert!(value.enter_effect().is_err()); assert!(!value.success());
            value.begin_intent().unwrap(); assert!(value.enter_effect().is_err());
            value.intent_durable_returned().unwrap(); value.enter_effect().unwrap();
            assert_eq!(value.outcome.effect, Effect::Unknown); assert!(value.enter_effect().is_err());
            value.applied_returned().unwrap(); assert!(value.enter_clear(true).is_err());
            value.enter_effect_sync().unwrap(); value.effect_sync_returned(true).unwrap();
            assert!(!value.success()); assert!(value.enter_clear(false).is_err());
            value.enter_clear(true).unwrap(); value.clear_sync_returned(true).unwrap();
            assert!(!value.success()); value.cleanup_returned(true); assert!(value.success());
            assert!(!value.mutation_paused());
            assert!(value.begin_intent().is_err()); assert!(value.enter_effect().is_err());
        }
    }

    #[test]
    fn stop_and_first_failure_survive_late_applied_sync_and_cleanup_returns() {
        for at in 0..5 {
            let mut value = progress();
            if at == 0 {
                value.stop(); assert!(value.enter_effect().is_err());
                let proof = NoEffectProof { target_original_unchanged: true, candidate_cleanup_known: true };
                value.no_effect_proved(&proof).unwrap();
            } else {
                value.enter_effect().unwrap(); if at == 1 { value.stop(); }
                value.applied_returned().unwrap(); value.enter_effect_sync().unwrap();
                if at == 2 { value.stop(); } value.effect_sync_returned(true).unwrap();
            }
            value.enter_clear(true).unwrap(); if at == 3 { value.stop(); }
            value.clear_sync_returned(true).unwrap(); if at == 4 { value.stop(); }
            value.cleanup_returned(true); value.fail(Problem::Native);
            assert_eq!(value.first, Some(Problem::Stopped)); assert!(!value.success());
            assert_eq!(value.outcome.effect, if at == 0 { Effect::KnownNone } else { Effect::KnownApplied });
        }
        let mut value = progress(); value.fail(Problem::Native); value.stop();
        assert_eq!(value.first, Some(Problem::Native)); assert!(value.enter_effect().is_err());
    }

    #[test]
    fn no_effect_requires_fresh_original_and_candidate_cleanup_not_an_errno() {
        for entered in [false, true] {
            let mut value = progress(); if entered { value.enter_effect().unwrap(); }
            value.fail(Problem::Native);
            for (target, candidate) in [(false, false), (true, false), (false, true)] {
                assert!(value.no_effect_proved(&NoEffectProof { target_original_unchanged: target, candidate_cleanup_known: candidate }).is_err());
            }
            assert!(value.enter_clear(true).is_err());
            value.no_effect_proved(&NoEffectProof { target_original_unchanged: true, candidate_cleanup_known: true }).unwrap();
            value.enter_clear(true).unwrap(); value.clear_sync_returned(true).unwrap(); value.cleanup_returned(true);
            assert_eq!(value.outcome.effect, Effect::KnownNone); assert!(!value.success());
        }
        let mut applied = progress(); applied.enter_effect().unwrap(); applied.applied_returned().unwrap();
        assert!(applied.no_effect_proved(&NoEffectProof { target_original_unchanged: true, candidate_cleanup_known: true }).is_err());
    }

    #[test]
    fn failed_record_sync_fence_clear_or_late_close_never_publish_success() {
        let mut sync = progress(); sync.enter_effect().unwrap(); sync.applied_returned().unwrap();
        sync.enter_effect_sync().unwrap(); sync.effect_sync_returned(false).unwrap(); sync.cleanup_returned(true);
        assert!(sync.effect_sync_returned(true).is_err());
        assert!(sync.enter_clear(true).is_err()); assert!(sync.mutation_paused()); assert!(!sync.success());
        assert_eq!(sync.outcome, StorageOutcome { effect: Effect::KnownApplied, durability: Durability::Unknown, cleanup: Cleanup::Known });
        let mut clear = progress(); clear.enter_effect().unwrap(); clear.applied_returned().unwrap();
        clear.enter_effect_sync().unwrap(); clear.effect_sync_returned(true).unwrap();
        clear.enter_clear(true).unwrap(); clear.clear_sync_returned(false).unwrap(); clear.cleanup_returned(true);
        assert!(clear.mutation_paused()); assert!(!clear.success()); assert!(clear.enter_clear(true).is_err());
        let mut close = progress(); close.enter_effect().unwrap(); close.applied_returned().unwrap();
        close.enter_effect_sync().unwrap(); close.effect_sync_returned(true).unwrap();
        close.enter_clear(true).unwrap(); close.clear_sync_returned(true).unwrap();
        close.cleanup_returned(false); close.cleanup_returned(true);
        assert_eq!(close.outcome.cleanup, Cleanup::Unknown); assert!(!close.success()); assert!(close.mutation_paused());
        // Fresh authenticated restart observation is outside this record: it
        // can never modify the old API outcome merely because no fence remains.
    }

    #[test]
    fn restart_inventory_counts_every_entry_and_never_adopts_debris() {
        assert!(Inventory::new().inspection() == Inspection::Uninitialized);
        let mut clean = inventory(); assert!(clean.inspection() == Inspection::Locked);
        clean.add(b"record-03030303030303030303030303030303", 360, true).unwrap();
        assert!(clean.inspection() == Inspection::Locked); assert_eq!(clean.records.len(), 1);
        assert_eq!(clean.bytes, 512); assert!(clean.candidate_budget(360).is_ok());
        for (name, length) in [(format::INTENT_NAME, 0), (format::INTENT_NAME, 200),
            (".candidate-04040404040404040404040404040404", 8), ("unexpected", 12)] {
            let mut interrupted = inventory(); interrupted.add(name.as_bytes(), length, true).unwrap();
            assert!(interrupted.inspection() == Inspection::Interrupted);
            assert!(interrupted.candidate_budget(360).is_err());
            assert_eq!(interrupted.bytes, 152 + length);
        }
        let mut reserved = Inventory::new(); reserved.add(format::LOCK_NAME.as_bytes(), 0, true).unwrap();
        reserved.add(format::RESERVATION_NAME.as_bytes(), 48, true).unwrap();
        assert!(reserved.inspection() == Inspection::Interrupted);
        let mut header_only = Inventory::new(); header_only.add(format::LOCK_NAME.as_bytes(), 0, true).unwrap();
        header_only.add(format::HEADER_NAME.as_bytes(), 104, true).unwrap(); assert!(header_only.inspection() == Inspection::Corrupt);
    }

    #[test]
    fn inventory_rejects_aliases_unknown_permissions_duplicate_names_and_quota_credit() {
        for name in [b".".as_slice(), b"..", b"a/b", b"a\0b", b"record-0", b"record-00000000000000000000000000000000",
            b".candidate-ABCDEFABCDEFABCDEFABCDEFABCDEFABCD"] { assert!(inventory().add(name, 1, true).is_err()); }
        assert!(inventory().add(b"other", 1, false).is_err());
        assert!(inventory().add(format::LOCK_NAME.as_bytes(), 0, true).is_err());
        let mut names = inventory();
        for number in 1..=DESCRIPTOR_COUNT {
            let mut bytes = [0; 16]; bytes[..8].copy_from_slice(&(number as u64).to_le_bytes());
            names.add(Id::from_bytes(bytes).unwrap().record_name().as_bytes(), 360, true).unwrap();
        }
        assert!(names.add(b"record-ffffffffffffffffffffffffffffffff", 360, true).is_err());
        let mut full = inventory(); full.bytes = DISK_BYTES - 100;
        assert!(full.candidate_budget(360).is_err()); assert!(full.add(b"unknown", 101, true).is_err());
        let mut exact = inventory(); exact.bytes = DISK_BYTES - 360 - 200;
        assert!(exact.candidate_budget(360).is_ok()); exact.bytes += 1; assert!(exact.candidate_budget(360).is_err());
        let mut overflow = inventory(); overflow.bytes = u64::MAX; assert!(overflow.candidate_budget(360).is_err());
    }
}
