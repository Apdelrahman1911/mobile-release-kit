//! Closed DATA ledger for the fixed Mac Android registration transfer.
//!
//! This is not peer authentication, source/supplier admission, filesystem custody
//! or completion evidence. The original owner supplies those and its one clock.
//! The native adapter must reject oversized NSData/frames BEFORE copying them.
//! No path, UID, process, command, environment or destination is accepted here.
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(crate) const MAX_FILES: usize = 32_768;
pub(crate) const MAX_BYTES: u64 = 1 << 30;
// The fixed NSXPC outer envelope occupies32 of the total65,536-byte frame.
pub(crate) const MAX_FRAME: usize = 64 * 1024 - 32;
// Fixed wire header: magic/version, transaction, inventory, sequence, kind,
// file ordinal, byte offset, payload length. The bound includes the envelope.
const MAGIC: &[u8; 8] = b"MRKAR01\0";
const HEADER: usize = 8 + 16 + 32 + 4 + 1 + 4 + 8 + 4;
pub(crate) const MAX_PAYLOAD: usize = MAX_FRAME - HEADER;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) transaction: [u8; 16],
    pub(crate) inventory: [u8; 32],
}
impl Identity {
    fn valid(self) -> bool {
        self.transaction != [0; 16] && self.inventory != [0; 32]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct File {
    pub(crate) bytes: u64,
    pub(crate) sha256: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind { Begin, Data, End, Finish }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Frame {
    pub(crate) identity: Identity,
    pub(crate) sequence: u32,
    pub(crate) kind: Kind,
    pub(crate) file: u32,
    pub(crate) offset: u64,
}
impl Frame {
    /// Native NSData length must already have been bounded before copying.
    /// This parser allocates nothing and accepts no trailing/noncanonical bytes.
    pub(crate) fn decode(wire: &[u8]) -> Result<(Self, &[u8]), Failure> {
        if wire.len() < HEADER || wire.len() > MAX_FRAME || &wire[..8] != MAGIC {
            return Err(Failure::Bounds);
        }
        let identity = Identity {
            transaction: wire[8..24].try_into().map_err(|_| Failure::Bounds)?,
            inventory: wire[24..56].try_into().map_err(|_| Failure::Bounds)?,
        };
        if !identity.valid() { return Err(Failure::Identity); }
        let sequence = u32::from_be_bytes(wire[56..60].try_into().map_err(|_| Failure::Bounds)?);
        let kind = match wire[60] {
            0 => Kind::Begin, 1 => Kind::Data, 2 => Kind::End, 3 => Kind::Finish,
            _ => return Err(Failure::Phase),
        };
        let file = u32::from_be_bytes(wire[61..65].try_into().map_err(|_| Failure::Bounds)?);
        let offset = u64::from_be_bytes(wire[65..73].try_into().map_err(|_| Failure::Bounds)?);
        let length = u32::from_be_bytes(wire[73..77].try_into().map_err(|_| Failure::Bounds)?) as usize;
        if length != wire.len() - HEADER { return Err(Failure::Bounds); }
        if (kind == Kind::Data) == (length == 0) { return Err(Failure::Phase); }
        Ok((Self { identity, sequence, kind, file, offset }, &wire[HEADER..]))
    }

    /// Serialize one bounded control/payload DATA frame, never a native receipt.
    pub(crate) fn encode(self, bytes: &[u8]) -> Result<Vec<u8>, Failure> {
        if bytes.len() > MAX_PAYLOAD { return Err(Failure::Bounds); }
        if !self.identity.valid() { return Err(Failure::Identity); }
        if (self.kind == Kind::Data) == bytes.is_empty() { return Err(Failure::Phase); }
        let mut wire = Vec::with_capacity(HEADER + bytes.len());
        wire.extend_from_slice(MAGIC);
        wire.extend_from_slice(&self.identity.transaction);
        wire.extend_from_slice(&self.identity.inventory);
        wire.extend_from_slice(&self.sequence.to_be_bytes());
        wire.push(match self.kind { Kind::Begin => 0, Kind::Data => 1, Kind::End => 2, Kind::Finish => 3 });
        wire.extend_from_slice(&self.file.to_be_bytes());
        wire.extend_from_slice(&self.offset.to_be_bytes());
        wire.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        wire.extend_from_slice(bytes);
        Ok(wire)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure { Identity, Bounds, Sequence, Phase, Digest, Effect, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase { BetweenFiles, FileOpen, Transferred, Failed }

/// A one-use local permit, NOT a serialized receipt or native-effect proof.
/// Losing it leaves the original pending slot occupied; no later frame proceeds.
pub(crate) struct Permit { frame: Frame, instance: Arc<()> }
impl Permit { pub(crate) fn frame(&self) -> Frame { self.frame } }
struct OpenFile { bytes: u64, hash: Sha256 }
struct Pending { frame: Frame, length: u64, hash: Option<Sha256> }

pub(crate) struct Transfer {
    identity: Identity,
    instance: Arc<()>,
    files: Vec<File>,
    total: u64,
    next_file: usize,
    next_sequence: u32,
    written: u64,
    open: Option<OpenFile>,
    pending: Option<Pending>,
    transferred: bool,
    first_failure: Option<Failure>,
}
impl Transfer {
    /// Caller supplies the actual already parsed/admitted inventory file roster.
    /// Exactly one instance owns the whole original transaction lifetime. It must
    /// never be reconstructed for retry; the native owner permanently rejects
    /// nonce reuse. The private Arc also forbids a stale permit from a distinct
    /// accidental same-identity ledger (including after the old ledger is dropped).
    /// The shared inventory parser remains authoritative for names, aliases,
    /// executable roles, supplier provenance and total selected entry count.
    pub(crate) fn new(identity: Identity, files: Vec<File>, selected_entries: usize) -> Result<Self, Failure> {
        if !identity.valid() { return Err(Failure::Identity); }
        if files.is_empty() || files.len() > MAX_FILES || selected_entries < files.len()
            || selected_entries > MAX_FILES { return Err(Failure::Bounds); }
        let total = files.iter().try_fold(0u64, |sum, file| {
            sum.checked_add(file.bytes).filter(|sum| *sum <= MAX_BYTES)
        }).ok_or(Failure::Bounds)?;
        Ok(Self { identity, instance: Arc::new(()), files, total, next_file: 0, next_sequence: 0, written: 0,
            open: None, pending: None, transferred: false, first_failure: None })
    }
    pub(crate) fn phase(&self) -> Phase {
        if self.first_failure.is_some() { Phase::Failed }
        else if self.transferred { Phase::Transferred }
        else if self.open.is_some() { Phase::FileOpen }
        else { Phase::BetweenFiles }
    }
    pub(crate) fn failure(&self) -> Option<Failure> { self.first_failure }
    pub(crate) fn written(&self) -> u64 { self.written }
    pub(crate) fn expected_bytes(&self) -> u64 { self.total }
    pub(crate) fn fail(&mut self, failure: Failure) {
        // Pending/native-effect ambiguity is retained, never cleared for retry.
        if self.first_failure.is_none() { self.first_failure = Some(failure); }
    }
    fn check(&self, frame: Frame, bytes: &[u8]) -> Result<Pending, Failure> {
        if self.first_failure.is_some() || self.transferred || self.pending.is_some() {
            return Err(Failure::Phase);
        }
        if frame.identity != self.identity { return Err(Failure::Identity); }
        if frame.sequence != self.next_sequence || self.next_sequence.checked_add(1)
            .is_none_or(|next| next == u32::MAX) { return Err(Failure::Sequence); }
        if bytes.len() > MAX_PAYLOAD { return Err(Failure::Bounds); }
        if frame.file as usize != self.next_file { return Err(Failure::Sequence); }
        let length = u64::try_from(bytes.len()).map_err(|_| Failure::Bounds)?;
        let mut pending = Pending { frame, length, hash: None };
        match frame.kind {
            Kind::Begin => {
                if self.open.is_some() || self.next_file >= self.files.len()
                    || frame.offset != 0 || !bytes.is_empty() { return Err(Failure::Phase); }
            }
            Kind::Data => {
                let open = self.open.as_ref().ok_or(Failure::Phase)?;
                let file = self.files.get(self.next_file).ok_or(Failure::Phase)?;
                if bytes.is_empty() || frame.offset != open.bytes
                    || open.bytes.checked_add(length).is_none_or(|end| end > file.bytes)
                    || self.written.checked_add(length).is_none_or(|end| end > self.total) {
                    return Err(Failure::Bounds);
                }
                let mut hash = open.hash.clone();
                hash.update(bytes);
                pending.hash = Some(hash);
            }
            Kind::End => {
                let open = self.open.as_ref().ok_or(Failure::Phase)?;
                let file = self.files.get(self.next_file).ok_or(Failure::Phase)?;
                if !bytes.is_empty() || frame.offset != open.bytes || open.bytes != file.bytes {
                    return Err(Failure::Bounds);
                }
                let actual: [u8; 32] = open.hash.clone().finalize().into();
                if actual != file.sha256 { return Err(Failure::Digest); }
            }
            Kind::Finish => {
                if self.open.is_some() || self.next_file != self.files.len()
                    || self.written != self.total || frame.offset != self.total
                    || !bytes.is_empty() { return Err(Failure::Phase); }
            }
        }
        Ok(pending)
    }
    /// Reserve BEFORE the corresponding native effect. At most one frame may
    /// be in flight. Any invalid frame irreversibly latches failure.
    pub(crate) fn admit(&mut self, frame: Frame, bytes: &[u8]) -> Result<Permit, Failure> {
        match self.check(frame, bytes) {
            Ok(pending) => { self.pending = Some(pending); Ok(Permit { frame, instance: Arc::clone(&self.instance) }) }
            Err(failure) => { self.fail(failure); Err(failure) }
        }
    }
    /// Called only after the real original effect returned positively:
    /// Begin=create recorded original; Data=all bytes written; End=original file
    /// writer fsynced/closed; Finish=source transfer/queue originals settled.
    /// Failure/lost return uses fail(), never this method or a replacement file.
    pub(crate) fn acknowledge(&mut self, permit: Permit) -> Result<(), Failure> {
        if self.first_failure.is_some() || !Arc::ptr_eq(&self.instance, &permit.instance)
            || self.pending.as_ref().is_none_or(|p| p.frame != permit.frame) {
            self.fail(Failure::Unknown); return Err(Failure::Unknown);
        }
        let pending = match self.pending.take() {
            Some(pending) => pending,
            None => { self.fail(Failure::Unknown); return Err(Failure::Unknown); }
        };
        match pending.frame.kind {
            Kind::Begin => self.open = Some(OpenFile { bytes: 0, hash: Sha256::new() }),
            Kind::Data => {
                let Some(open) = self.open.as_mut() else {
                    self.fail(Failure::Unknown); return Err(Failure::Unknown);
                };
                let Some(hash) = pending.hash else {
                    self.fail(Failure::Unknown); return Err(Failure::Unknown);
                };
                // check() proved both sums before any native effect.
                open.bytes += pending.length;
                open.hash = hash;
                self.written += pending.length;
            }
            Kind::End => { self.open = None; self.next_file += 1; }
            Kind::Finish => self.transferred = true,
        }
        self.next_sequence += 1;
        Ok(())
    }
    /// Byte/sequence completion ONLY. Publication/Ready/original finality still
    /// requires the original owner, immutable readback and the retained lease.
    pub(crate) fn transfer_complete(&self) -> bool {
        self.transferred && self.first_failure.is_none() && self.pending.is_none()
            && self.open.is_none() && self.next_file == self.files.len() && self.written == self.total
    }
}


/// Closed persistent DATA for M2's permanent lease and pre-writer intent.
/// Parsing these records NEVER acquires a lease, authenticates a principal,
/// proves source/supplier provenance or admits catalog/Start/recovery. Native
/// original ownership and complete readback are separate mandatory predicates.
pub(crate) mod records {
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use super::{Identity, MAX_BYTES, MAX_FILES};

    const LEASE_MAGIC: &[u8; 8] = b"MRKAL01\0";
    pub(crate) const LEASE_HEADER_BYTES: usize = 8 + 4 + 16 + 16 + 16;
    pub(crate) const INTENT_BYTES: usize = 8 * 1024;
    pub(crate) const ACCOUNT_ATTEMPT_LIMIT: usize = 32;
    const CONTENT_RECORDS: u32 = 3; // inventory, OS provider, registration
    const LEASE_MODE: u32 = 0o100400; // native regular-file type + fixed0400

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum RecordFailure { Bounds, Format, Binding, Totals }

    /// Values must come from the mutually authenticated native peer and native
    /// UID/principal round-trip. A deserialized value is only comparison DATA.
    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct LeaseBinding {
        account: u32,
        principal: [u8; 16],
        instance: [u8; 16],
        transaction: [u8; 16],
    }
    impl LeaseBinding {
        pub(crate) fn new(account: u32, principal: [u8; 16], instance: [u8; 16], transaction: [u8; 16])
            -> Result<Self, RecordFailure>
        {
            let value = Self { account, principal, instance, transaction };
            if !value.valid() { return Err(RecordFailure::Binding); }
            Ok(value)
        }
        fn valid(&self) -> bool {
            self.account != 0 && self.account != u32::MAX && self.principal != [0; 16]
                && self.instance != [0; 16] && self.transaction != [0; 16]
        }
        pub(crate) fn account(&self) -> u32 { self.account }
        pub(crate) fn principal(&self) -> [u8; 16] { self.principal }
        pub(crate) fn instance(&self) -> [u8; 16] { self.instance }
        pub(crate) fn transaction(&self) -> [u8; 16] { self.transaction }
        pub(crate) fn encode(&self) -> Result<[u8; LEASE_HEADER_BYTES], RecordFailure> {
            if !self.valid() { return Err(RecordFailure::Binding); }
            let mut raw = [0; LEASE_HEADER_BYTES];
            raw[..8].copy_from_slice(LEASE_MAGIC);
            raw[8..12].copy_from_slice(&self.account.to_be_bytes());
            raw[12..28].copy_from_slice(&self.principal);
            raw[28..44].copy_from_slice(&self.instance);
            raw[44..60].copy_from_slice(&self.transaction);
            Ok(raw)
        }
        pub(crate) fn decode(raw: &[u8]) -> Result<Self, RecordFailure> {
            if raw.len() != LEASE_HEADER_BYTES { return Err(RecordFailure::Bounds); }
            if &raw[..8] != LEASE_MAGIC { return Err(RecordFailure::Format); }
            // Exact width checks precede every fixed-width conversion.
            Self::new(
                u32::from_be_bytes(raw[8..12].try_into().map_err(|_| RecordFailure::Format)?),
                raw[12..28].try_into().map_err(|_| RecordFailure::Format)?,
                raw[28..44].try_into().map_err(|_| RecordFailure::Format)?,
                raw[44..60].try_into().map_err(|_| RecordFailure::Format)?)
        }
        pub(crate) fn header_sha256(&self) -> Result<[u8; 32], RecordFailure> {
            Ok(Sha256::digest(self.encode()?).into())
        }
    }

    /// Immutable finalized lease fstat/header DATA. The user-only ACL, local
    /// APFS, flags, no-follow ancestry and named-original checks are native
    /// responsibilities; these fields cannot stand in for those observations.
    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct LeaseIdentityData {
        pub(crate) device: u64,
        pub(crate) inode: u64,
        pub(crate) mode: u32,
        pub(crate) uid: u32,
        pub(crate) gid: u32,
        pub(crate) links: u64,
        pub(crate) bytes: u64,
        pub(crate) modified_seconds: i64,
        pub(crate) modified_nanoseconds: u32,
        pub(crate) changed_seconds: i64,
        pub(crate) changed_nanoseconds: u32,
        pub(crate) flags: u32,
        pub(crate) header_sha256: [u8; 32],
    }
    impl LeaseIdentityData {
        fn valid(&self, binding: &LeaseBinding) -> bool {
            self.device != 0 && self.inode != 0 && self.mode == LEASE_MODE && self.uid == 0
                && self.gid == 0 && self.links == 1 && self.bytes == LEASE_HEADER_BYTES as u64
                && self.modified_nanoseconds < 1_000_000_000 && self.changed_nanoseconds < 1_000_000_000
                && self.flags == 0 && binding.header_sha256().is_ok_and(|hash| hash == self.header_sha256)
        }
    }

    /// Complete selected content, including the three immutable content records.
    /// File bytes are an upper-bound commitment before any writer starts, not a
    /// claim that the bytes were written or that filesystem blocks were freed.
    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct ContentTotals {
        pub(crate) files: u32,
        pub(crate) directories: u32,
        pub(crate) aliases: u32,
        pub(crate) payload_bytes: u64,
        pub(crate) metadata_bytes: u64,
    }
    impl ContentTotals {
        pub(crate) fn entries(&self) -> Option<u32> {
            self.files.checked_add(self.directories)?.checked_add(self.aliases)?.checked_add(CONTENT_RECORDS)
        }
        pub(crate) fn content_bytes(&self) -> Option<u64> {
            self.payload_bytes.checked_add(self.metadata_bytes)
        }
        fn valid(&self) -> bool {
            self.files != 0 && self.payload_bytes != 0 && self.metadata_bytes != 0
                && self.entries().is_some_and(|count| (count as u64) <= MAX_FILES as u64)
                && self.content_bytes().is_some_and(|bytes| bytes <= MAX_BYTES)
        }
    }

    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    enum IntentProfile {
        #[serde(rename = "macos-arm64-android-original-lease-v1")]
        OriginalLeaseV1,
    }
    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    enum IntentState {
        #[serde(rename = "incomplete")]
        Incomplete,
    }

    /// Comparison-only commitments of copied payload and exactly three content
    /// records. Sealed-system provider bytes are a separate read budget.
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub(crate) struct ContentCommitments {
        pub(crate) supplier_record:[u8;32],
        pub(crate) payload_inventory:[u8;32],
        pub(crate) os_provider:[u8;32],
        pub(crate) totals:ContentTotals,
    }

    /// An intent never contains a terminal-success/finality bit. Its permanent
    /// binding survives both successful and interrupted publication. On restart,
    /// even Ready content requires explicit fresh SH acquisition/readback.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct Intent {
        schema_version: u32,
        profile: IntentProfile,
        state: IntentState,
        binding: LeaseBinding,
        lease_original: LeaseIdentityData,
        source_consent_sha256: [u8; 32],
        supplier_inventory_sha256: [u8; 32],
        payload_inventory_sha256: [u8; 32],
        os_provider_sha256: [u8; 32],
        totals: ContentTotals,
    }
    impl Intent {
        pub(crate) fn new(
            binding: LeaseBinding,
            lease_original: LeaseIdentityData,
            source_consent_sha256: [u8; 32],
            supplier_inventory_sha256: [u8; 32],
            payload_inventory_sha256: [u8; 32],
            os_provider_sha256: [u8; 32],
            totals: ContentTotals,
        ) -> Result<Self, RecordFailure> {
            let value = Self { schema_version: 1, profile: IntentProfile::OriginalLeaseV1,
                state: IntentState::Incomplete, binding, lease_original, source_consent_sha256,
                supplier_inventory_sha256, payload_inventory_sha256, os_provider_sha256, totals };
            value.check()?;
            Ok(value)
        }
        fn check(&self) -> Result<(), RecordFailure> {
            if self.schema_version != 1 { return Err(RecordFailure::Format); }
            if !self.binding.valid() || !self.lease_original.valid(&self.binding)
                || [self.source_consent_sha256, self.supplier_inventory_sha256,
                    self.payload_inventory_sha256, self.os_provider_sha256].contains(&[0; 32])
            {
                return Err(RecordFailure::Binding);
            }
            if !self.totals.valid() { return Err(RecordFailure::Totals); }
            Ok(())
        }
        pub(crate) fn encode(&self) -> Result<Vec<u8>, RecordFailure> {
            self.check()?;
            let raw = serde_json::to_vec(self).map_err(|_| RecordFailure::Format)?;
            if raw.is_empty() || raw.len() > INTENT_BYTES { return Err(RecordFailure::Bounds); }
            Ok(raw)
        }
        pub(crate) fn decode(raw: &[u8]) -> Result<Self, RecordFailure> {
            if raw.is_empty() || raw.len() > INTENT_BYTES { return Err(RecordFailure::Bounds); }
            // Deserialize directly to the closed typed structs. A Value/map
            // round-trip would erase duplicate-field evidence before validation.
            let value: Self = serde_json::from_slice(raw).map_err(|_| RecordFailure::Format)?;
            value.check()?;
            Ok(value)
        }
        /// Both supplied arguments must be from the fresh ORIGINAL native lease,
        /// not copied out of this same intent or a prior serialized receipt.
        pub(crate) fn matches_original_data(&self, binding: &LeaseBinding, original: &LeaseIdentityData) -> bool {
            self.check().is_ok() && &self.binding == binding && &self.lease_original == original
        }
        pub(crate) fn transfer_identity(&self) -> Identity {
            Identity { transaction: self.binding.transaction, inventory: self.payload_inventory_sha256 }
        }
        pub(crate) fn totals(&self) -> ContentTotals { self.totals }
        pub(crate) fn content_data(&self)->ContentCommitments {
            ContentCommitments{supplier_record:self.supplier_inventory_sha256,
                payload_inventory:self.payload_inventory_sha256,os_provider:self.os_provider_sha256,totals:self.totals}
        }
        /// Counts planned immutable file bytes including the permanent lease and
        /// this exact serialized intent. The owner separately charges directory/
        /// alias storage, native buffers, actual disk allocation and every effect.
        /// Not an output-persistence or cleanup receipt.
        pub(crate) fn planned_file_bytes(&self) -> Result<u64, RecordFailure> {
            self.totals.content_bytes().and_then(|bytes| bytes.checked_add(LEASE_HEADER_BYTES as u64))
                .and_then(|bytes| bytes.checked_add(self.encode().ok()?.len() as u64))
                .ok_or(RecordFailure::Bounds)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn binding() -> LeaseBinding { LeaseBinding::new(501, [1; 16], [2; 16], [3; 16]).unwrap() }
        fn original(binding: &LeaseBinding) -> LeaseIdentityData {
            LeaseIdentityData { device: 7, inode: 42, mode: LEASE_MODE, uid: 0, gid: 0, links: 1,
                bytes: LEASE_HEADER_BYTES as u64, modified_seconds: 1, modified_nanoseconds: 2,
                changed_seconds: 3, changed_nanoseconds: 4, flags: 0, header_sha256: binding.header_sha256().unwrap() }
        }
        fn totals() -> ContentTotals {
            ContentTotals { files: 3, directories: 2, aliases: 1, payload_bytes: 100, metadata_bytes: 32 }
        }
        fn intent() -> Intent {
            let binding = binding();
            Intent::new(binding, original(&binding), [4; 32], [5; 32], [6; 32], [7; 32], totals()).unwrap()
        }
        #[test]
        fn lease_header_is_fixed_and_rejects_account_reuse_or_noncanonical_bytes() {
            let value = binding();
            let raw = value.encode().unwrap();
            assert_eq!(raw.len(), LEASE_HEADER_BYTES);
            assert_eq!(LeaseBinding::decode(&raw).unwrap(), value);
            assert_eq!((value.account(), value.principal(), value.instance(), value.transaction()),
                (501, [1; 16], [2; 16], [3; 16]));
            assert!(LeaseBinding::decode(&raw[..raw.len() - 1]).is_err());
            let mut extra = raw.to_vec(); extra.push(0);
            assert!(LeaseBinding::decode(&extra).is_err());
            let mut foreign_magic = raw; foreign_magic[6] = b'2';
            assert!(LeaseBinding::decode(&foreign_magic).is_err());
            for account in [0, u32::MAX] { assert!(LeaseBinding::new(account, [1; 16], [2; 16], [3; 16]).is_err()); }
            for (principal, instance, transaction) in [([0; 16], [2; 16], [3; 16]),
                ([1; 16], [0; 16], [3; 16]), ([1; 16], [2; 16], [0; 16])] {
                assert!(LeaseBinding::new(501, principal, instance, transaction).is_err());
            }
            let reused_account = LeaseBinding::new(501, [9; 16], [2; 16], [3; 16]).unwrap();
            assert_ne!(value.header_sha256().unwrap(), reused_account.header_sha256().unwrap());
            assert!(!intent().matches_original_data(&reused_account, &original(&value)));
        }
        #[test]
        fn incomplete_intent_roundtrip_binds_exact_lease_and_only_transfer_data() {
            let value = intent();
            let raw = value.encode().unwrap();
            let parsed = Intent::decode(&raw).unwrap();
            assert_eq!(parsed, value);
            assert!(parsed.matches_original_data(&binding(), &original(&binding())));
            assert_eq!(parsed.transfer_identity(), Identity { transaction: [3; 16], inventory: [6; 32] });
            assert_eq!(parsed.totals().entries(), Some(9));
            assert_eq!(parsed.planned_file_bytes().unwrap(), 132 + LEASE_HEADER_BYTES as u64 + raw.len() as u64);
            let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(json["state"], "incomplete");
            assert!(json.get("ready").is_none() && json.get("success").is_none() && json.get("finality").is_none());
            assert!(json.get("destination").is_none() && json.get("sourcePath").is_none());
        }
        #[test]
        fn original_identity_mode_owner_links_size_flags_and_header_cannot_be_replaced() {
            let expected = original(&binding());
            for which in 0..13 {
                let mut changed = expected;
                match which {
                    0 => changed.device += 1,
                    1 => changed.inode += 1,
                    2 => changed.mode = 0o100600,
                    3 => changed.uid = 501,
                    4 => changed.gid = 80,
                    5 => changed.links = 2,
                    6 => changed.bytes += 1,
                    7 => changed.modified_seconds += 1,
                    8 => changed.modified_nanoseconds += 1,
                    9 => changed.changed_seconds += 1,
                    10 => changed.changed_nanoseconds += 1,
                    11 => changed.flags = 1,
                    _ => changed.header_sha256[0] ^= 1,
                }
                assert!(!intent().matches_original_data(&binding(), &changed), "identity field {which}");
            }
            for which in 0..9 {
                let mut changed = expected;
                match which {
                    0 => changed.device = 0,
                    1 => changed.inode = 0,
                    2 => changed.mode = 0o100600,
                    3 => changed.uid = 501,
                    4 => changed.links = 2,
                    5 => changed.bytes = 0,
                    6 => changed.modified_nanoseconds = 1_000_000_000,
                    7 => changed.changed_nanoseconds = 1_000_000_000,
                    _ => changed.flags = 1,
                }
                assert!(Intent::new(binding(), changed, [4; 32], [5; 32], [6; 32], [7; 32], totals()).is_err());
            }
        }
        #[test]
        fn closed_json_refuses_duplicate_fields_terminal_claims_paths_and_oversized_input() {
            let raw = intent().encode().unwrap();
            assert!(Intent::decode(&[]).is_err());
            assert!(Intent::decode(&vec![b' '; INTENT_BYTES + 1]).is_err());
            let text = std::str::from_utf8(&raw).unwrap();
            for bad in [
                text.replacen("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1", 1),
                text.replacen("\"account\":501", "\"account\":501,\"account\":501", 1),
                text.replacen("\"state\":\"incomplete\"", "\"state\":\"ready\"", 1),
                text.replacen("\"state\":\"incomplete\"", "\"state\":\"complete\"", 1),
                text.replacen("\"schemaVersion\":1", "\"schemaVersion\":2", 1),
                text.replacen("macos-arm64-android-original-lease-v1", "android-registered-macos-arm64-v1", 1),
                text.replacen("\"schemaVersion\":1", "\"schemaVersion\":1,\"success\":true", 1),
                text.replacen("\"schemaVersion\":1", "\"schemaVersion\":1,\"destination\":\"/tmp/foreign\"", 1),
                text.replacen("\"account\":501", "\"account\":501.0", 1),
                format!("{text}{{}}"),
            ] { assert!(Intent::decode(bad.as_bytes()).is_err()); }
        }
        #[test]
        fn content_bound_includes_metadata_entries_and_all_arithmetic_is_checked() {
            for changed in [
                ContentTotals { files: 0, ..totals() },
                ContentTotals { files: u32::MAX, ..totals() },
                ContentTotals { directories: MAX_FILES as u32, ..totals() },
                ContentTotals { aliases: u32::MAX, ..totals() },
                ContentTotals { payload_bytes: 0, ..totals() },
                ContentTotals { metadata_bytes: 0, ..totals() },
                ContentTotals { payload_bytes: MAX_BYTES, ..totals() },
                ContentTotals { payload_bytes: u64::MAX, metadata_bytes: 1, ..totals() },
            ] { assert!(Intent::new(binding(), original(&binding()), [4; 32], [5; 32], [6; 32], [7; 32], changed).is_err()); }
            let maximum = ContentTotals { files: MAX_FILES as u32 - CONTENT_RECORDS, directories: 0,
                aliases: 0, payload_bytes: MAX_BYTES - 1, metadata_bytes: 1 };
            assert!(Intent::new(binding(), original(&binding()), [4; 32], [5; 32], [6; 32], [7; 32], maximum).is_ok());
            for which in 0..4 {
                let mut value = intent();
                match which {
                    0 => value.source_consent_sha256 = [0; 32],
                    1 => value.supplier_inventory_sha256 = [0; 32],
                    2 => value.payload_inventory_sha256 = [0; 32],
                    _ => value.os_provider_sha256 = [0; 32],
                }
                assert!(value.encode().is_err());
                assert!(Intent::decode(&serde_json::to_vec(&value).unwrap()).is_err());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> Identity { Identity { transaction: [1; 16], inventory: [2; 32] } }
    fn file(bytes: &[u8]) -> File { File { bytes: bytes.len() as u64, sha256: Sha256::digest(bytes).into() } }
    fn frame(transfer: &Transfer, kind: Kind, offset: u64) -> Frame {
        Frame { identity: identity(), sequence: transfer.next_sequence, kind,
            file: transfer.next_file as u32, offset }
    }
    fn step(transfer: &mut Transfer, kind: Kind, offset: u64, bytes: &[u8]) {
        let permit = transfer.admit(frame(transfer, kind, offset), bytes).unwrap();
        transfer.acknowledge(permit).unwrap();
    }
    #[test]
    fn ordered_nonempty_and_empty_files_only_complete_transfer_not_publication() {
        let mut transfer = Transfer::new(identity(), vec![file(b"abc"), file(b"")], 3).unwrap();
        step(&mut transfer, Kind::Begin, 0, b"");
        step(&mut transfer, Kind::Data, 0, b"a");
        step(&mut transfer, Kind::Data, 1, b"bc");
        step(&mut transfer, Kind::End, 3, b"");
        step(&mut transfer, Kind::Begin, 0, b"");
        step(&mut transfer, Kind::End, 0, b"");
        assert!(!transfer.transfer_complete());
        step(&mut transfer, Kind::Finish, 3, b"");
        assert!(transfer.transfer_complete());
        assert_eq!(transfer.phase(), Phase::Transferred);
        assert_eq!(transfer.written(), transfer.expected_bytes());
        assert!(transfer.admit(frame(&transfer, Kind::Finish, 3), b"").is_err());
        assert!(!transfer.transfer_complete()); // Duplicate terminal input is not a retry.
    }
    #[test]
    fn overlapping_frame_or_lost_permit_cannot_start_another_native_effect() {
        let mut transfer = Transfer::new(identity(), vec![file(b"x")], 1).unwrap();
        let permit = transfer.admit(frame(&transfer, Kind::Begin, 0), b"").unwrap();
        assert_eq!(permit.frame().kind, Kind::Begin);
        assert!(transfer.admit(frame(&transfer, Kind::Begin, 0), b"").is_err());
        assert!(transfer.acknowledge(permit).is_err());
        assert_eq!(transfer.phase(), Phase::Failed);
        assert!(transfer.pending.is_some());
    }
    #[test]
    fn native_effect_failure_retains_pending_and_first_failure_without_accounting_success() {
        let mut transfer = Transfer::new(identity(), vec![file(b"x")], 1).unwrap();
        step(&mut transfer, Kind::Begin, 0, b"");
        let permit = transfer.admit(frame(&transfer, Kind::Data, 0), b"x").unwrap();
        transfer.fail(Failure::Effect);
        transfer.fail(Failure::Unknown);
        assert_eq!(transfer.failure(), Some(Failure::Effect));
        assert!(transfer.acknowledge(permit).is_err());
        assert_eq!(transfer.written(), 0);
        assert!(transfer.pending.is_some());
        assert!(!transfer.transfer_complete());
    }
    #[test]
    fn wrong_identity_stale_sequence_and_counter_exhaustion_latch() {
        for case in 0..3 {
            let mut transfer = Transfer::new(identity(), vec![file(b"")], 1).unwrap();
            let mut input = frame(&transfer, Kind::Begin, 0);
            if case == 0 { input.identity.transaction = [3; 16]; }
            if case == 1 { input.sequence = 1; }
            if case == 2 { transfer.next_sequence = u32::MAX - 1; input.sequence = u32::MAX - 1; }
            assert!(transfer.admit(input, b"").is_err());
            assert_eq!(transfer.phase(), Phase::Failed);
            assert!(transfer.admit(frame(&transfer, Kind::Begin, 0), b"").is_err());
        }
    }
    #[test]
    fn bad_digest_incomplete_file_and_oversized_frame_never_reach_finish() {
        for case in 0..3 {
            let mut transfer = Transfer::new(identity(), vec![file(b"ab")], 1).unwrap();
            step(&mut transfer, Kind::Begin, 0, b"");
            match case {
                0 => { step(&mut transfer, Kind::Data, 0, b"ac");
                    assert!(transfer.admit(frame(&transfer, Kind::End, 2), b"").is_err()); }
                1 => { step(&mut transfer, Kind::Data, 0, b"a");
                    assert!(transfer.admit(frame(&transfer, Kind::End, 1), b"").is_err()); }
                _ => { assert!(transfer.admit(frame(&transfer, Kind::Data, 0), &vec![0; MAX_PAYLOAD + 1]).is_err()); }
            }
            assert!(!transfer.transfer_complete());
            assert_eq!(transfer.phase(), Phase::Failed);
        }
    }
    #[test]
    fn byte_offsets_empty_data_and_foreign_ack_are_closed() {
        for case in 0..3 {
            let mut transfer = Transfer::new(identity(), vec![file(b"x")], 1).unwrap();
            step(&mut transfer, Kind::Begin, 0, b"");
            if case == 0 { assert!(transfer.admit(frame(&transfer, Kind::Data, 1), b"x").is_err()); }
            if case == 1 { assert!(transfer.admit(frame(&transfer, Kind::Data, 0), b"").is_err()); }
            if case == 2 {
                let permit = transfer.admit(frame(&transfer, Kind::Data, 0), b"x").unwrap();
                let mut foreign = permit.frame(); foreign.identity.inventory = [9; 32];
                assert!(transfer.acknowledge(Permit { frame: foreign, instance: Arc::clone(&transfer.instance) }).is_err());
            }
            assert_eq!(transfer.written(), 0);
            assert!(!transfer.transfer_complete());
        }
    }
    #[test]
    fn permit_from_a_distinct_same_identity_ledger_cannot_acknowledge_an_effect() {
        for retire_original in [false, true] {
            let mut original = Transfer::new(identity(), vec![file(b"x")], 1).unwrap();
            let mut other = Transfer::new(identity(), vec![file(b"x")], 1).unwrap();
            step(&mut original, Kind::Begin, 0, b"");
            step(&mut other, Kind::Begin, 0, b"");
            let stale = original.admit(frame(&original, Kind::Data, 0), b"x").unwrap();
            if retire_original { drop(original); }
            let own = other.admit(frame(&other, Kind::Data, 0), b"x").unwrap();
            assert_eq!(stale.frame(), own.frame());
            assert_eq!(other.acknowledge(stale), Err(Failure::Unknown));
            assert_eq!(other.failure(), Some(Failure::Unknown));
            assert_eq!(other.written(), 0);
            assert!(other.pending.is_some());
            assert!(other.acknowledge(own).is_err());
            assert!(!other.transfer_complete());
        }
    }
    #[test]
    fn wire_frame_bound_includes_header_and_rejects_truncation_extra_bytes_or_untyped_payload() {
        let data = Frame { identity: identity(), sequence: 12, kind: Kind::Data, file: 3, offset: 4096 };
        let payload = vec![7; MAX_PAYLOAD];
        let wire = data.encode(&payload).unwrap();
        assert_eq!(wire.len(), MAX_FRAME);
        let (decoded, content) = Frame::decode(&wire).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(content, payload.as_slice());
        assert!(data.encode(&vec![0; MAX_PAYLOAD + 1]).is_err());
        assert!(Frame::decode(&wire[..wire.len() - 1]).is_err());
        let mut extra = wire.clone(); extra.push(0);
        assert!(Frame::decode(&extra).is_err());
        let mut malformed = wire.clone(); malformed[60] = 9;
        assert!(Frame::decode(&malformed).is_err());
        let mut control = data; control.kind = Kind::Finish;
        assert!(control.encode(b"x").is_err());
        assert!(data.encode(b"").is_err());
        let control_wire = control.encode(b"").unwrap();
        assert_eq!(Frame::decode(&control_wire).unwrap(), (control, &b""[..]));
    }
    #[test]
    fn constructor_rejects_unbounded_or_inconsistent_admitted_rosters() {
        assert!(Transfer::new(identity(), vec![], 0).is_err());
        assert!(Transfer::new(identity(), vec![file(b"")], 0).is_err());
        assert!(Transfer::new(identity(), vec![file(b"")], MAX_FILES + 1).is_err());
        assert!(Transfer::new(identity(), vec![File { bytes: MAX_BYTES + 1, sha256: [0; 32] }], 1).is_err());
        assert!(Transfer::new(identity(), vec![File { bytes: u64::MAX, sha256: [0; 32] }, file(b"x")], 2).is_err());
    }
}


/// The authenticated connection carries these closed DATA messages before the
/// transfer. No path/account/destination or command string is accepted. Peers
/// still owe original source consent, supplier authority and native custody.
pub(crate) mod preparation {
    use super::Failure;
    use sha2::{Digest, Sha256};
    pub(crate) const HELLO_BYTES: usize = 256;
    pub(crate) const METADATA_HEADER: usize = 20;
    pub(crate) const METADATA_LIMITS: [usize; 3] = [4 * 1024 * 1024, 4096, 64 * 1024];
    const HELLO_MAGIC: &[u8; 8] = b"MRKAH01\0";
    const META_MAGIC: &[u8; 8] = b"MRKAM01\0";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Hello {
        pub(crate) transaction: [u8; 16],
        pub(crate) instance: [u8; 16],
        pub(crate) origin: u64,
        pub(crate) work: u64,
        pub(crate) hard: u64,
        // inventory, registration, OS provider; exact order and bytes.
        pub(crate) lengths: [u32; 3],
        pub(crate) hashes: [[u8; 32]; 3],
        pub(crate) source_consent: [u8; 32],
        pub(crate) supplier_record: [u8; 32],
        pub(crate) source_generation: u32,
        pub(crate) project_registration: u32,
    }
    impl Hello {
        fn valid(&self) -> bool {
            self.transaction != [0; 16] && self.instance != [0; 16] && self.origin != 0
                && self.work.checked_sub(self.origin) == Some(300_000_000_000)
                && self.hard.checked_sub(self.origin) == Some(310_000_000_000)
                && self.hard < (1_u64 << 61)
                && self.lengths.iter().zip(METADATA_LIMITS).all(|(length, maximum)| *length != 0 && (*length as usize) <= maximum)
                && self.hashes.iter().all(|hash| *hash != [0; 32])
                && self.source_consent != [0; 32] && self.supplier_record != [0; 32]
                && self.source_generation != 0 && self.source_generation != u32::MAX
                && self.project_registration != 0 && self.project_registration != u32::MAX
        }
        pub(crate) fn encode(&self) -> Result<[u8; HELLO_BYTES], Failure> {
            if !self.valid() { return Err(Failure::Bounds); }
            let mut out = [0; HELLO_BYTES]; out[..8].copy_from_slice(HELLO_MAGIC);
            out[8..24].copy_from_slice(&self.transaction); out[24..40].copy_from_slice(&self.instance);
            for (index, value) in [self.origin, self.work, self.hard].into_iter().enumerate() {
                let at = 40 + index * 8; out[at..at+8].copy_from_slice(&value.to_be_bytes());
            }
            for index in 0..3 {
                let at = 64 + index * 4; out[at..at+4].copy_from_slice(&self.lengths[index].to_be_bytes());
                let at = 76 + index * 32; out[at..at+32].copy_from_slice(&self.hashes[index]);
            }
            out[172..204].copy_from_slice(&self.source_consent);
            out[204..236].copy_from_slice(&self.supplier_record);
            out[236..240].copy_from_slice(&self.source_generation.to_be_bytes());
            out[240..244].copy_from_slice(&self.project_registration.to_be_bytes());
            Ok(out)
        }
        pub(crate) fn decode(raw: &[u8]) -> Result<Self, Failure> {
            if raw.len() != HELLO_BYTES || &raw[..8] != HELLO_MAGIC || raw[244..] != [0; 12] { return Err(Failure::Bounds); }
            let u32at = |at| raw.get(at..at+4).and_then(|bytes| bytes.try_into().ok()).map(u32::from_be_bytes).ok_or(Failure::Bounds);
            let u64at = |at| raw.get(at..at+8).and_then(|bytes| bytes.try_into().ok()).map(u64::from_be_bytes).ok_or(Failure::Bounds);
            let value = Self {
                transaction: raw[8..24].try_into().map_err(|_| Failure::Bounds)?,
                instance: raw[24..40].try_into().map_err(|_| Failure::Bounds)?,
                origin: u64at(40)?, work: u64at(48)?, hard: u64at(56)?,
                lengths: [u32at(64)?, u32at(68)?, u32at(72)?],
                hashes: [raw[76..108].try_into().map_err(|_| Failure::Bounds)?,
                    raw[108..140].try_into().map_err(|_| Failure::Bounds)?,
                    raw[140..172].try_into().map_err(|_| Failure::Bounds)?],
                source_consent: raw[172..204].try_into().map_err(|_| Failure::Bounds)?,
                supplier_record: raw[204..236].try_into().map_err(|_| Failure::Bounds)?,
                source_generation: u32at(236)?, project_registration: u32at(240)?,
            };
            if value.valid() { Ok(value) } else { Err(Failure::Bounds) }
        }
    }
    pub(crate) struct MetadataChunk<'a> { pub(crate) field: u8, pub(crate) offset: u32, pub(crate) bytes: &'a [u8] }
    impl<'a> MetadataChunk<'a> {
        pub(crate) fn decode(raw: &'a [u8]) -> Result<Self, Failure> {
            if raw.len() <= METADATA_HEADER || raw.len() > super::MAX_FRAME || &raw[..8] != META_MAGIC
                || raw[8] >= 3 || raw[9..12] != [0; 3] { return Err(Failure::Bounds); }
            let offset = u32::from_be_bytes(raw[12..16].try_into().map_err(|_| Failure::Bounds)?);
            let count = u32::from_be_bytes(raw[16..20].try_into().map_err(|_| Failure::Bounds)?) as usize;
            if count != raw.len() - METADATA_HEADER { return Err(Failure::Bounds); }
            Ok(Self { field: raw[8], offset, bytes: &raw[METADATA_HEADER..] })
        }
        pub(crate) fn encode(field: u8, offset: u32, bytes: &[u8]) -> Result<Vec<u8>, Failure> {
            if field >= 3 || bytes.is_empty() || bytes.len() > super::MAX_FRAME - METADATA_HEADER { return Err(Failure::Bounds); }
            let mut out = vec![0; METADATA_HEADER]; out[..8].copy_from_slice(META_MAGIC);
            out[8] = field; out[12..16].copy_from_slice(&offset.to_be_bytes());
            out[16..20].copy_from_slice(&(bytes.len() as u32).to_be_bytes()); out.extend_from_slice(bytes);
            Ok(out)
        }
    }
    /// Bounded metadata only, retained by the sole original helper transaction.
    /// First field failure is terminal. No per-chunk replacement or late append.
    pub(crate) struct Metadata {
        hello: Hello, raw: [Vec<u8>; 3], next: usize, failed: bool,
    }
    impl Metadata {
        pub(crate) fn new(hello: Hello) -> Result<Self, Failure> {
            if !hello.valid() { return Err(Failure::Bounds); }
            let mut raw = [Vec::new(), Vec::new(), Vec::new()];
            for (target, length) in raw.iter_mut().zip(hello.lengths) {
                target.try_reserve_exact(length as usize).map_err(|_| Failure::Bounds)?;
                if target.capacity() > length as usize { return Err(Failure::Bounds); }
            }
            Ok(Self { hello, raw, next: 0, failed: false })
        }
        pub(crate) fn push(&mut self, chunk: MetadataChunk<'_>) -> Result<(), Failure> {
            let result = self.push_once(chunk);
            if result.is_err() { self.failed = true; }
            result
        }
        fn push_once(&mut self, chunk: MetadataChunk<'_>) -> Result<(), Failure> {
            if self.failed || self.next >= 3 || chunk.field as usize != self.next { return Err(Failure::Phase); }
            let raw = &mut self.raw[self.next];
            if chunk.offset as usize != raw.len() || raw.len().checked_add(chunk.bytes.len())
                .is_none_or(|end| end > self.hello.lengths[self.next] as usize) { return Err(Failure::Bounds); }
            raw.extend_from_slice(chunk.bytes);
            if raw.len() == self.hello.lengths[self.next] as usize {
                let actual: [u8; 32] = Sha256::digest(raw).into();
                if actual != self.hello.hashes[self.next] { return Err(Failure::Digest); }
                self.next += 1;
            }
            Ok(())
        }
        pub(crate) fn complete(&self) -> bool { self.next == 3 && !self.failed }
        pub(crate) fn hello(&self) -> Hello { self.hello }
        pub(crate) fn raw(&self) -> Result<[&[u8]; 3], Failure> {
            if !self.complete() { return Err(Failure::Phase); }
            Ok([&self.raw[0], &self.raw[1], &self.raw[2]])
        }
        pub(crate) fn retained_bytes(&self) -> usize { self.raw.iter().map(Vec::capacity).sum() }
        pub(crate) fn into_complete(self) -> Result<(Hello, [Vec<u8>; 3]), Failure> {
            if !self.complete() { return Err(Failure::Phase); }
            Ok((self.hello, self.raw))
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        fn hello() -> Hello {
            let hash: [u8; 32] = Sha256::digest(b"x").into();
            Hello { transaction: [1; 16], instance: [2; 16], origin: 10, work: 300_000_000_010,
                hard: 310_000_000_010, lengths: [1, 1, 1], hashes: [hash; 3],
                source_consent: [3; 32], supplier_record: [4; 32], source_generation: 1, project_registration: 1 }
        }
        #[test]
        fn preparation_bounds_bind_exact_clock_and_preserve_metadata_order() {
            let value = hello(); assert_eq!(Hello::decode(&value.encode().unwrap()).unwrap(), value);
            let mut wrong = value.encode().unwrap(); wrong[244] = 1; assert!(Hello::decode(&wrong).is_err());
            let mut wrong = value; wrong.work += 1; assert!(wrong.encode().is_err());
            let mut meta = Metadata::new(value).unwrap();
            for field in 0..3 {
                let raw = MetadataChunk::encode(field, 0, b"x").unwrap();
                meta.push(MetadataChunk::decode(&raw).unwrap()).unwrap();
            }
            assert!(meta.complete());
            assert!(meta.push(MetadataChunk { field: 0, offset: 0, bytes: b"x" }).is_err());
            assert!(!meta.complete());
        }
        #[test]
        fn metadata_digest_failure_never_accepts_a_later_replacement() {
            let mut meta = Metadata::new(hello()).unwrap();
            assert!(meta.push(MetadataChunk { field: 0, offset: 0, bytes: b"z" }).is_err());
            assert!(meta.push(MetadataChunk { field: 0, offset: 0, bytes: b"x" }).is_err());
        }
    }
}

/// Registration terminal candidate DATA. This is computed before the original
/// final lease consume and is NOT H, original finality, a lease or Start permit.
pub(crate) mod terminal {
    pub(crate) const BYTES: usize = 176;
    pub(crate) const ERROR_PREFIX: usize = 20;
    pub(crate) const RECORDED_ERRORS: usize = 64;
    const MAGIC: &[u8; 8] = b"MRKART01";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u32)]
    pub(crate) enum Problem {
        Binding = 1, Bounds, SupplierUnavailable, Inventory, Ownership, Collision,
        Native, Stopped, Unknown, Transfer, Persist, Admission, Unavailable,
    }
    impl Problem {
        fn decode(value: u32) -> Option<Self> {
            Some(match value {
                1 => Self::Binding, 2 => Self::Bounds, 3 => Self::SupplierUnavailable,
                4 => Self::Inventory, 5 => Self::Ownership, 6 => Self::Collision,
                7 => Self::Native, 8 => Self::Stopped, 9 => Self::Unknown,
                10 => Self::Transfer, 11 => Self::Persist, 12 => Self::Admission,
                13 => Self::Unavailable, _ => return None,
            })
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u32)]
    pub(crate) enum CandidateDisposition {
        PreparedComplete = 1, Refused = 2, Unknown = 3,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct OutputAccountingData {
        /// Observed sums only. They are NOT complete totals when complete=false.
        pub(crate) observed_logical_bytes: u64,
        pub(crate) observed_allocated_bytes: u64,
        pub(crate) complete: bool,
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct TerminalCandidate {
        pub(crate) disposition: CandidateDisposition,
        pub(crate) first_problem: Option<Problem>,
        pub(crate) transaction: [u8; 16],
        pub(crate) instance: [u8; 16],
        pub(crate) written_bytes: u64,
        pub(crate) accounting: OutputAccountingData,
        pub(crate) publication_applied: bool,
        pub(crate) content_files: u32,
        pub(crate) content_aliases: u32,
        /// Recorded count, not an uncapped census of every possible error.
        pub(crate) recorded_error_count: u32,
        /// Exactly min(recorded_error_count,20) codes. Never a complete list
        /// merely because the enclosing fixed-size message was received.
        pub(crate) error_prefix: Vec<Problem>,
        /// PRE-lease-close dependencies only; deliberately not named "final".
        pub(crate) pre_lease_dependencies_known: bool,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Invalid { Format, Bounds, Binding }

    impl TerminalCandidate {
        pub(crate) fn unknown() -> Self {
            Self { disposition: CandidateDisposition::Unknown, first_problem: None,
                transaction: [0; 16], instance: [0; 16], written_bytes: 0,
                accounting: OutputAccountingData { observed_logical_bytes: 0,
                    observed_allocated_bytes: 0, complete: false },
                publication_applied: false, content_files: 0, content_aliases: 0,
                recorded_error_count: 0, error_prefix: Vec::new(),
                pre_lease_dependencies_known: false }
        }
        fn check(&self) -> Result<(), Invalid> {
            if self.recorded_error_count as usize > RECORDED_ERRORS
                || self.error_prefix.len() != (self.recorded_error_count as usize).min(ERROR_PREFIX)
                || self.content_files as usize > super::MAX_FILES
                || self.content_aliases as usize > super::MAX_FILES
            { return Err(Invalid::Bounds); }
            if (self.transaction == [0; 16]) != (self.instance == [0; 16])
                || self.error_prefix.first().copied() != self.first_problem
            { return Err(Invalid::Binding); }
            match self.disposition {
                CandidateDisposition::PreparedComplete if !self.pre_lease_dependencies_known
                    || !self.publication_applied || !self.accounting.complete
                    || self.first_problem.is_some() || self.recorded_error_count != 0
                    || self.transaction == [0; 16] => return Err(Invalid::Binding),
                CandidateDisposition::Refused if !self.pre_lease_dependencies_known =>
                    return Err(Invalid::Binding),
                CandidateDisposition::Unknown if self.pre_lease_dependencies_known =>
                    return Err(Invalid::Binding),
                _ => {}
            }
            Ok(())
        }
        pub(crate) fn encode(&self) -> Result<[u8; BYTES], Invalid> {
            self.check()?;
            let mut raw = [0; BYTES];
            raw[..8].copy_from_slice(MAGIC);
            for (at, value) in [
                (8, self.disposition as u32), (12, self.first_problem.map_or(0, |p| p as u32)),
                (72, u32::from(self.accounting.complete)), (76, u32::from(self.publication_applied)),
                (80, self.content_files), (84, self.content_aliases),
                (88, self.recorded_error_count), (92, u32::from(self.pre_lease_dependencies_known)),
            ] { raw[at..at + 4].copy_from_slice(&value.to_be_bytes()); }
            raw[16..32].copy_from_slice(&self.transaction);
            raw[32..48].copy_from_slice(&self.instance);
            for (at, value) in [(48, self.written_bytes), (56, self.accounting.observed_logical_bytes),
                (64, self.accounting.observed_allocated_bytes)]
            { raw[at..at + 8].copy_from_slice(&value.to_be_bytes()); }
            for (index, value) in self.error_prefix.iter().enumerate() {
                let at = 96 + index * 4;
                raw[at..at + 4].copy_from_slice(&(*value as u32).to_be_bytes());
            }
            Ok(raw)
        }
        /// The one fixed Unknown encoding; callers do not duplicate wire offsets.
        pub(crate) fn unknown_bytes() -> [u8; BYTES] {
            let mut raw = [0; BYTES]; raw[..8].copy_from_slice(MAGIC);
            raw[8..12].copy_from_slice(&(CandidateDisposition::Unknown as u32).to_be_bytes());
            raw
        }
        pub(crate) fn decode(raw: &[u8]) -> Result<Self, Invalid> {
            if raw.len() != BYTES || &raw[..8] != MAGIC { return Err(Invalid::Format); }
            let word = |at| u32::from_be_bytes(raw[at..at + 4].try_into().expect("fixed bounded word"));
            let wide = |at| u64::from_be_bytes(raw[at..at + 8].try_into().expect("fixed bounded wide"));
            let flag = |at| match word(at) { 0 => Ok(false), 1 => Ok(true), _ => Err(Invalid::Format) };
            let disposition = match word(8) {
                1 => CandidateDisposition::PreparedComplete, 2 => CandidateDisposition::Refused,
                3 => CandidateDisposition::Unknown, _ => return Err(Invalid::Format),
            };
            let first_problem = match word(12) { 0 => None,
                value => Some(Problem::decode(value).ok_or(Invalid::Format)?) };
            let recorded_error_count = word(88);
            if recorded_error_count as usize > RECORDED_ERRORS { return Err(Invalid::Bounds); }
            let prefix_count = (recorded_error_count as usize).min(ERROR_PREFIX);
            let mut error_prefix = Vec::with_capacity(prefix_count);
            for index in 0..ERROR_PREFIX {
                let value = word(96 + index * 4);
                if index < prefix_count {
                    error_prefix.push(Problem::decode(value).ok_or(Invalid::Format)?);
                } else if value != 0 { return Err(Invalid::Format); }
            }
            let value = Self { disposition, first_problem,
                transaction: raw[16..32].try_into().expect("fixed transaction"),
                instance: raw[32..48].try_into().expect("fixed instance"),
                written_bytes: wide(48),
                accounting: OutputAccountingData { observed_logical_bytes: wide(56),
                    observed_allocated_bytes: wide(64), complete: flag(72)? },
                publication_applied: flag(76)?, content_files: word(80),
                content_aliases: word(84), recorded_error_count, error_prefix,
                pre_lease_dependencies_known: flag(92)? };
            value.check()?; Ok(value)
        }
        pub(crate) fn omitted_recorded_errors(&self) -> u32 {
            self.recorded_error_count - self.error_prefix.len() as u32
        }
        /// Candidate shape only, NOT non-entry/finality evidence. The caller
        /// separately proves positive original Hello-never-entered and the same
        /// prepared native peer's actually joined Refused terminal. No source,
        /// artifact, or success authority follows from this zero-pair shape.
        pub(crate) fn prehello_refusal_candidate(&self) -> bool {
            self.check().is_ok() && self.disposition == CandidateDisposition::Refused
                && self.transaction == [0; 16] && self.instance == [0; 16]
                && self.written_bytes == 0 && self.content_files == 0 && self.content_aliases == 0
                && !self.publication_applied && self.accounting.complete
                && self.accounting.observed_logical_bytes == 0 && self.accounting.observed_allocated_bytes == 0
                && self.pre_lease_dependencies_known
        }
        pub(crate) fn matches_source_data(&self, transaction: &[u8; 16], instance: &[u8; 16]) -> bool {
            transaction != &[0; 16] && instance != &[0; 16]
                && &self.transaction == transaction && &self.instance == instance
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn fixed_unknown_and_pre_g_candidate_remain_data_not_finality() {
            let unknown = TerminalCandidate::unknown();
            assert_eq!(unknown.encode().unwrap(), TerminalCandidate::unknown_bytes());
            assert_eq!(TerminalCandidate::decode(&TerminalCandidate::unknown_bytes()), Ok(unknown.clone()));
            let mut ready = unknown;
            ready.disposition = CandidateDisposition::PreparedComplete;
            ready.transaction = [1; 16]; ready.instance = [2; 16];
            ready.pre_lease_dependencies_known = true; ready.publication_applied = true;
            ready.accounting.complete = true;
            let raw = ready.encode().unwrap();
            assert_eq!(&raw[..8], b"MRKART01");
            assert_eq!(&raw[8..12], &1_u32.to_be_bytes());
            assert_eq!(&raw[92..96], &1_u32.to_be_bytes());
            assert_eq!(TerminalCandidate::decode(&raw), Ok(ready.clone()));
            assert!(ready.matches_source_data(&[1; 16], &[2; 16]));
            assert!(!ready.matches_source_data(&[3; 16], &[2; 16]));
            // No finality/lease/H method or bit exists in this DATA type.
            ready.pre_lease_dependencies_known = false;
            assert_eq!(ready.encode(), Err(Invalid::Binding));
        }
        #[test]
        fn prehello_zero_pair_refusal_is_never_source_or_success_authority() {
            let mut refused=TerminalCandidate::unknown();
            refused.disposition=CandidateDisposition::Refused;
            refused.pre_lease_dependencies_known=true;refused.accounting.complete=true;
            assert!(refused.prehello_refusal_candidate());
            assert!(!refused.matches_source_data(&[0;16],&[0;16]));
            assert!(!refused.matches_source_data(&[1;16],&[2;16]));
            let mut changed=refused.clone();changed.written_bytes=1;
            assert!(!changed.prehello_refusal_candidate());
            changed=refused.clone();changed.publication_applied=true;
            assert!(!changed.prehello_refusal_candidate());
            changed=refused.clone();changed.instance=[1;16];
            assert!(!changed.prehello_refusal_candidate());
            changed=refused.clone();changed.accounting.complete=false;
            assert!(!changed.prehello_refusal_candidate());
            changed=refused;changed.disposition=CandidateDisposition::PreparedComplete;
            assert!(!changed.prehello_refusal_candidate());
        }
        #[test]
        fn counted_error_prefix_never_claims_all_errors_or_complete_accounting() {
            let mut data = TerminalCandidate::unknown();
            data.first_problem = Some(Problem::Native);
            data.recorded_error_count = 64;
            data.error_prefix = vec![Problem::Native; 20];
            data.accounting.observed_logical_bytes = 17;
            data.accounting.observed_allocated_bytes = 4096;
            let raw = data.encode().unwrap();
            let got = TerminalCandidate::decode(&raw).unwrap();
            assert_eq!(got, data);
            assert_eq!(got.omitted_recorded_errors(), 44);
            assert!(!got.accounting.complete);
            data.error_prefix.pop();
            assert_eq!(data.encode(), Err(Invalid::Bounds));
            data.recorded_error_count = 65;
            assert_eq!(data.encode(), Err(Invalid::Bounds));
        }
        #[test]
        fn terminal_refuses_noncanonical_flags_tail_unknown_codes_and_identity() {
            let raw = TerminalCandidate::unknown_bytes();
            for (at, value) in [(8, 0_u32), (8, 4), (12, 99), (72, 2), (76, 2),
                (88, 65), (92, 2), (96, 1)] {
                let mut bad = raw; bad[at..at + 4].copy_from_slice(&value.to_be_bytes());
                assert!(TerminalCandidate::decode(&bad).is_err(), "offset {at}");
            }
            let mut bad = raw; bad[16] = 1;
            assert_eq!(TerminalCandidate::decode(&bad), Err(Invalid::Binding));
            assert!(TerminalCandidate::decode(&raw[..BYTES - 1]).is_err());
            let mut extra = raw.to_vec(); extra.push(0);
            assert!(TerminalCandidate::decode(&extra).is_err());
        }
    }
}
