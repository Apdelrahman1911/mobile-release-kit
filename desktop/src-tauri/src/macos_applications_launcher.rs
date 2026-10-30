//! Bounded Applications-launcher inventory and lifecycle decisions.
//!
//! This is DATA, not a signature check or filesystem authority. The native
//! installer must supply authenticated inventories and original observations,
//! retain its maintenance ownership, and verify every moved original before any
//! deletion. No publication is enabled by introducing these helpers.
use crate::macos_install_maintenance::ActionData;
use crate::macos_install_record::{Entry, InventoryIndex};

type Result<T> = std::result::Result<T, &'static str>;

pub const APPLICATIONS_PARENT: &str = "/Applications";
pub const APPLICATIONS_NAME: &str = "Mobile Release Kit.app";
pub const APPLICATIONS_PATH: &str = "/Applications/Mobile Release Kit.app";
pub const BUNDLE: &str = "app/Contents/Helpers/MobileReleaseKitLauncher.app";
pub const EXECUTABLE: &str = "app/Contents/Helpers/MobileReleaseKitLauncher.app/Contents/MacOS/mrk-macos-launcher";
pub const INFO: &str = "app/Contents/Helpers/MobileReleaseKitLauncher.app/Contents/Info.plist";
pub const ICON: &str = "app/Contents/Helpers/MobileReleaseKitLauncher.app/Contents/Resources/icon.png";
pub const SIGNATURE: &str = "app/Contents/Helpers/MobileReleaseKitLauncher.app/Contents/_CodeSignature/CodeResources";
pub const TICKET: &str = "app/Contents/Helpers/MobileReleaseKitLauncher.app/Contents/CodeResources";
pub const TICKET_LIMIT: u64 = 1024 * 1024;
pub const FILES: [&str; 4] = [EXECUTABLE, INFO, ICON, SIGNATURE];
pub const LIMITS: [u64; 4] = [8 * 1024 * 1024, 16 * 1024, 1024 * 1024, 256 * 1024];

#[derive(Clone, Copy)]
pub struct LauncherInventory<'a> {
    // Private fields prevent a caller from accidentally omitting a signed leaf.
    entries: [&'a Entry; 4],
    ticket: Option<&'a Entry>,
    total_bytes: u64,
}
impl<'a> LauncherInventory<'a> {
    /// Old inventories may have no launcher. Any partial/extra launcher subtree
    /// refuses; a parent/root entry cannot masquerade as a required leaf.
    pub fn from_index(index: &InventoryIndex<'a>) -> Result<Option<Self>> {
        let prefix = format!("{BUNDLE}/");
        let selected = index.files.keys().filter(|name|
            name.as_str() == BUNDLE || name.starts_with(&prefix)).take(FILES.len() + 2).count();
        if selected == 0 { return Ok(None); }
        if !(FILES.len()..=FILES.len()+1).contains(&selected) { return Err("launcher-inventory-roster"); }
        let mut rows = Vec::with_capacity(FILES.len());
        let mut total_bytes = 0u64;
        for (slot, path) in FILES.iter().enumerate() {
            let entry = *index.files.get(*path).ok_or("launcher-inventory-roster")?;
            if entry.path != *path || entry.size == 0 || entry.size > LIMITS[slot]
                || entry.executable != (slot == 0) || entry.sha256.len() != 64
                || !entry.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return Err("launcher-inventory-entry");
            }
            total_bytes = total_bytes.checked_add(entry.size).ok_or("launcher-inventory-size")?;
            rows.push(entry);
        }
        let ticket = index.files.get(TICKET).copied();
        if selected != FILES.len() + usize::from(ticket.is_some()) {
            return Err("launcher-inventory-roster");
        }
        if let Some(entry) = ticket {
            if entry.path != TICKET || entry.executable || entry.size == 0 || entry.size > TICKET_LIMIT
                || entry.sha256.len() != 64
                || !entry.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return Err("launcher-ticket-entry");
            }
            total_bytes = total_bytes.checked_add(entry.size).ok_or("launcher-inventory-size")?;
        }
        let entries = rows.try_into().map_err(|_| "launcher-inventory-roster")?;
        Ok(Some(Self { entries, ticket, total_bytes }))
    }

    pub fn entries(&self) -> &[&'a Entry; 4] { &self.entries }
    pub fn ticket(&self) -> Option<&'a Entry> { self.ticket }
    pub fn total_bytes(&self) -> u64 { self.total_bytes }

    /// Correspondence only; the caller independently reads/retains the actual
    /// signed bundle and derives its observed records under native ownership.
    pub fn same_content(&self, other: &Self) -> bool {
        self.entries.iter().zip(other.entries).all(|(left, right)|
            left.path == right.path && left.sha256 == right.sha256
            && left.size == right.size && left.executable == right.executable)
            && match (self.ticket, other.ticket) {
                (None, None) => true,
                (Some(left), Some(right)) => left.path == right.path && left.sha256 == right.sha256
                    && left.size == right.size && left.executable == right.executable,
                _ => false,
            }
    }
}

/// In-memory observation, never deserialized permission to change a path.
pub enum Presence<'a> { Absent, Observed(LauncherInventory<'a>), Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    LegacyNotEnrolled,
    KeepCurrent,
    PublishAbsent,
    ReplaceEnrolled,
    RemoveEnrolled,
    AlreadyAbsent,
    Refuse,
}

/// A source-selected operation and its authenticated current/predecessor
/// inventories select the next operation; matching bytes alone cannot authorize
/// update/removal. No generic "overwrite" or "force" decision exists.
pub fn decide(action: ActionData, current: Option<&LauncherInventory<'_>>,
    predecessor: Option<&LauncherInventory<'_>>, observed: &Presence<'_>) -> Decision {
    let Some(current) = current else {
        // Never silently discard a launcher enrolled by a predecessor.
        return if predecessor.is_none() { Decision::LegacyNotEnrolled } else { Decision::Refuse };
    };
    match observed {
        Presence::Unknown => Decision::Refuse,
        // A signed byte-for-byte copy is still not prior enrollment. Fresh
        // install must not adopt it and later authorize its removal as ours.
        Presence::Observed(_) if action == ActionData::FreshInstall => Decision::Refuse,
        Presence::Absent => if action == ActionData::Uninstall { Decision::AlreadyAbsent } else { Decision::PublishAbsent },
        Presence::Observed(actual) if current.same_content(actual) => {
            if action == ActionData::Uninstall { Decision::RemoveEnrolled } else { Decision::KeepCurrent }
        }
        Presence::Observed(actual) if action == ActionData::Update
            && predecessor.is_some_and(|previous| previous.same_content(actual)) => Decision::ReplaceEnrolled,
        Presence::Observed(_) => Decision::Refuse,
    }
}

/// Closed observational DATA, not authority to publish or a worker's claim
/// about its future join. Parent independently binds it to the signed inventory
/// and actual current Applications original before recording success.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutcomeData { VerifiedExisting, Published, Restored, InverseRestored, Refused, Unknown }

// Persistent enrollment identifies the original, not merely matching signed
// bytes. Birth time supplements device/inode against later inode reuse; ctime
// is deliberately excluded because our exclusive rename legitimately changes it.
#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OriginalIdentityData {
    pub device: i64, pub inode: u64, pub birth_seconds: i64, pub birth_nanoseconds: i64,
    #[serde(default, skip_serializing_if="Option::is_none", deserialize_with="crate::macos_persistent_identity::present_uuid")]
    pub volume_uuid: Option<crate::macos_persistent_identity::VolumeUuid>,
}
impl PartialEq for OriginalIdentityData {
    fn eq(&self, other: &Self) -> bool {
        crate::macos_persistent_identity::same_volume_data((self.device,self.volume_uuid),(other.device,other.volume_uuid))
            && (self.inode,self.birth_seconds,self.birth_nanoseconds)==(other.inode,other.birth_seconds,other.birth_nanoseconds)
    }
}
impl Eq for OriginalIdentityData {}
impl OriginalIdentityData {
    pub fn same_volume_data(self, other: Self) -> bool {
        crate::macos_persistent_identity::same_volume_data((self.device,self.volume_uuid),(other.device,other.volume_uuid))
    }
    pub fn matches_legacy_binding_data(self, observed: Self,
        binding: crate::macos_persistent_identity::LegacyVolumeBindingData) -> bool {
        self.valid_data() && observed.valid_data()
            && (self.inode,self.birth_seconds,self.birth_nanoseconds)==(observed.inode,observed.birth_seconds,observed.birth_nanoseconds)
            && binding.matches_data((self.device,self.volume_uuid),(observed.device,observed.volume_uuid))
    }
    pub fn valid_data(self) -> bool {
        self.device >= 0 && self.inode != 0 && self.birth_seconds > 0
            && (0..1_000_000_000).contains(&self.birth_nanoseconds)
    }
}

/// Comparison DATA for an immutable historical publication-stage identity.
/// Native callers must first authenticate the selected generation and enroll
/// its existing root-volume witness. This neither changes persisted equality
/// nor grants a witness, file ownership, publication or cleanup authority.
pub fn recorded_stage_identity_matches_data(recorded: OriginalIdentityData,
    observed: OriginalIdentityData,
    bindings: &[Option<crate::macos_persistent_identity::LegacyVolumeBindingData>]) -> bool {
    recorded.valid_data() && observed.valid_data()
        && (recorded == observed || bindings.iter().flatten()
            .any(|binding| recorded.matches_legacy_binding_data(observed, *binding)))
}

#[cfg(test)]
pub(crate) fn assert_recorded_stage_identity_data_contract() {
    use crate::{macos_install_record::DirectoryIdentity,
        macos_persistent_identity::{LegacyVolumeBindingData, VolumeUuid}};
    let first = VolumeUuid::from_bytes_data([1; 16]).unwrap();
    let other = VolumeUuid::from_bytes_data([2; 16]).unwrap();
    let root = DirectoryIdentity {device: 16777229, inode: 10, mode: 0o040755,
        uid: 0, gid: 0, flags: 0, volume_uuid: None};
    let live_root = DirectoryIdentity {device: 16777232, volume_uuid: Some(first), ..root};
    let binding = LegacyVolumeBindingData::root_data(root, live_root).unwrap();
    let old = OriginalIdentityData {device: root.device, inode: 20,
        birth_seconds: 17, birth_nanoseconds: 3, volume_uuid: None};
    let live = OriginalIdentityData {device: live_root.device, volume_uuid: Some(first), ..old};
    // Authentic old records still fail ordinary missing/present UUID equality.
    assert_ne!(old, live);
    assert!(!recorded_stage_identity_matches_data(old, live, &[]));
    assert!(!recorded_stage_identity_matches_data(old, live, &[None]));
    assert!(recorded_stage_identity_matches_data(old, live, &[Some(binding)]));
    assert_ne!(old, live);
    assert!(recorded_stage_identity_matches_data(old, old, &[]));
    assert!(recorded_stage_identity_matches_data(live, live, &[]));
    assert!(recorded_stage_identity_matches_data(live,
        OriginalIdentityData {device: 123, ..live}, &[]));
    for changed in [OriginalIdentityData {inode: live.inode + 1, ..live},
        OriginalIdentityData {birth_seconds: live.birth_seconds + 1, ..live},
        OriginalIdentityData {birth_nanoseconds: live.birth_nanoseconds + 1, ..live},
        OriginalIdentityData {volume_uuid: Some(other), ..live},
        OriginalIdentityData {device: live.device + 1, ..live},
        OriginalIdentityData {volume_uuid: None, ..live}] {
        assert!(!recorded_stage_identity_matches_data(old, changed, &[Some(binding)]));
    }
    assert!(!recorded_stage_identity_matches_data(
        OriginalIdentityData {device: old.device + 1, ..old}, live, &[Some(binding)]));
    assert!(!recorded_stage_identity_matches_data(
        OriginalIdentityData {volume_uuid: Some(other), ..old}, live, &[Some(binding)]));
    for invalid in [OriginalIdentityData {inode: 0, ..old},
        OriginalIdentityData {birth_seconds: 0, ..old},
        OriginalIdentityData {birth_nanoseconds: -1, ..old},
        OriginalIdentityData {birth_nanoseconds: 1_000_000_000, ..old}] {
        assert!(!recorded_stage_identity_matches_data(invalid, invalid, &[Some(binding)]));
    }
    assert!(LegacyVolumeBindingData::root_data(root,
        DirectoryIdentity {inode: root.inode + 1, ..live_root}).is_none());
    assert!(LegacyVolumeBindingData::root_data(root, root).is_none());
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct PhaseReferenceData {pub stage_instance:String,pub sha256:String}
impl PhaseReferenceData {
    pub fn valid_data(&self)->bool {
        let hex=|value:&str,n|value.len()==n && value.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        hex(&self.stage_instance,32) && self.stage_instance.bytes().any(|b|b!=b'0') && hex(&self.sha256,64)
    }
}
fn required_phase<'de,D:serde::Deserializer<'de>>(deserializer:D)
    ->std::result::Result<Option<PhaseReferenceData>,D::Error> {serde::Deserialize::deserialize(deserializer)}
fn required_identity<'de, D: serde::Deserializer<'de>>(deserializer: D)
    -> std::result::Result<Option<OriginalIdentityData>, D::Error> {
    serde::Deserialize::deserialize(deserializer)
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationData {
    pub outcome: OutcomeData,
    #[serde(deserialize_with = "required_identity")]
    pub published_identity: Option<OriginalIdentityData>,
    #[serde(deserialize_with="required_phase")]
    pub publication_phase:Option<PhaseReferenceData>,
    pub write_count: u64,
    pub write_bytes: u64,
    pub originals_closed: bool,
    pub within_original_deadline: bool,
    pub readback_verified: bool,
    pub workspace_cleared: bool,
}
impl ObservationData {
    pub fn valid_data(&self) -> bool {
        // One new copied launcher; inverse uses the retained old original,
        // never a second arbitrary copy or widened payload quota.
        let limit = LIMITS.iter().copied().sum::<u64>() + TICKET_LIMIT;
        self.publication_phase.as_ref().is_none_or(PhaseReferenceData::valid_data)
            && match self.outcome {OutcomeData::Published|OutcomeData::Restored=>self.publication_phase.is_some(),
                OutcomeData::VerifiedExisting=>self.publication_phase.is_none(),_=>true}
            && self.published_identity.is_none_or(OriginalIdentityData::valid_data)
            && (!matches!(self.outcome, OutcomeData::VerifiedExisting | OutcomeData::Published | OutcomeData::Restored)
                || self.published_identity.is_some())
            && (self.write_count == 0) == (self.write_bytes == 0)
            && self.write_count <= self.write_bytes && self.write_bytes <= limit
            && match self.outcome {
                OutcomeData::VerifiedExisting => self.write_count == 0,
                OutcomeData::Published | OutcomeData::Restored => self.write_count > 0,
                _ => true,
            }
    }
    pub fn complete_data(&self, inverse: bool) -> bool {
        self.valid_data() && self.originals_closed && self.within_original_deadline
            && self.readback_verified && self.workspace_cleared
            && if inverse { self.outcome == OutcomeData::InverseRestored }
                else { matches!(self.outcome, OutcomeData::VerifiedExisting | OutcomeData::Published | OutcomeData::Restored) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn entries(digest: char) -> Vec<Entry> {
        FILES.iter().enumerate().map(|(slot, path)| Entry { path: (*path).into(),
            sha256: digest.to_string().repeat(64), size: 100 + slot as u64, executable: slot == 0 }).collect()
    }
    fn index(rows: &[Entry]) -> InventoryIndex<'_> {
        InventoryIndex { files: rows.iter().map(|entry| (entry.path.clone(), entry)).collect::<BTreeMap<_, _>>(),
            directories: BTreeSet::new(), payload_bytes: rows.iter().map(|entry| entry.size).sum() }
    }
    #[test]
    fn complete_inventory_only_and_all_signed_fields_match() {
        let rows = entries('a');
        let value = LauncherInventory::from_index(&index(&rows)).unwrap().unwrap();
        assert_eq!(value.entries().len(), 4);
        assert_eq!(value.total_bytes(), 406);
        assert!(LauncherInventory::from_index(&index(&[])).unwrap().is_none());
        for slot in 0..4 {
            let mut missing = entries('a'); missing.remove(slot);
            assert!(LauncherInventory::from_index(&index(&missing)).is_err());
            for mutation in 0..5 {
                let mut changed = entries('a');
                match mutation {
                    0 => changed[slot].size = 0,
                    1 => changed[slot].size = LIMITS[slot] + 1,
                    2 => changed[slot].executable = !changed[slot].executable,
                    3 => changed[slot].sha256 = "A".repeat(64),
                    _ => changed[slot].path.push_str(".unexpected"),
                }
                assert!(LauncherInventory::from_index(&index(&changed)).is_err());
            }
            let mut changed = entries('a'); changed[slot].sha256 = "b".repeat(64);
            let other = LauncherInventory::from_index(&index(&changed)).unwrap().unwrap();
            assert!(!value.same_content(&other));
        }
        let mut extra = entries('a');
        extra.push(Entry { path: format!("{BUNDLE}/Contents/extra"), sha256: "b".repeat(64), size: 1, executable: false });
        assert!(LauncherInventory::from_index(&index(&extra)).is_err());
        extra[4].path = BUNDLE.into();
        assert!(LauncherInventory::from_index(&index(&extra)).is_err());
    }

    #[test]
    fn stapled_ticket_is_optional_exact_and_part_of_content_identity() {
        let bare = entries('a');
        let bare_value = LauncherInventory::from_index(&index(&bare)).unwrap().unwrap();
        let mut rows = entries('a');
        rows.push(Entry { path: TICKET.into(), sha256: "b".repeat(64), size: 200, executable: false });
        let value = LauncherInventory::from_index(&index(&rows)).unwrap().unwrap();
        assert_eq!(value.total_bytes(), 606);
        assert!(value.ticket().is_some());
        assert!(!value.same_content(&bare_value));
        assert!(!bare_value.same_content(&value));
        for mutation in 0..6 {
            let mut changed = entries('a');
            changed.push(Entry { path: TICKET.into(), sha256: "b".repeat(64), size: 200, executable: false });
            match mutation {
                0 => changed[4].size = 0,
                1 => changed[4].size = TICKET_LIMIT + 1,
                2 => changed[4].executable = true,
                3 => changed[4].sha256 = "B".repeat(64),
                4 => changed[4].path.push_str(".unexpected"),
                _ => { changed.remove(0); },
            }
            assert!(LauncherInventory::from_index(&index(&changed)).is_err());
        }
        rows[4].sha256 = "c".repeat(64);
        let changed = LauncherInventory::from_index(&index(&rows)).unwrap().unwrap();
        let mut original = entries('a');
        original.push(Entry { path: TICKET.into(), sha256: "b".repeat(64), size: 200, executable: false });
        let original = LauncherInventory::from_index(&index(&original)).unwrap().unwrap();
        assert!(!changed.same_content(&original));
    }

    #[test]
    fn lifecycle_never_overwrites_unknown_or_unapproved_predecessor() {
        let old_rows = entries('a'); let new_rows = entries('b'); let unknown_rows = entries('c');
        let old = LauncherInventory::from_index(&index(&old_rows)).unwrap().unwrap();
        let new = LauncherInventory::from_index(&index(&new_rows)).unwrap().unwrap();
        let unknown = LauncherInventory::from_index(&index(&unknown_rows)).unwrap().unwrap();
        for action in [ActionData::FreshInstall, ActionData::SamePackageNoop,
            ActionData::RestoreFixedApp, ActionData::Update, ActionData::Uninstall] {
            assert_eq!(decide(action, None, None, &Presence::Unknown), Decision::LegacyNotEnrolled);
            assert_eq!(decide(action, None, Some(&old), &Presence::Absent), Decision::Refuse);
            assert_eq!(decide(action, Some(&new), Some(&old), &Presence::Unknown), Decision::Refuse);
            assert_eq!(decide(action, Some(&new), Some(&old), &Presence::Observed(unknown)), Decision::Refuse);
            assert_eq!(decide(action, Some(&new), None, &Presence::Observed(old)), Decision::Refuse);
            assert_eq!(decide(action, Some(&new), Some(&old), &Presence::Absent),
                if action == ActionData::Uninstall { Decision::AlreadyAbsent } else { Decision::PublishAbsent });
            assert_eq!(decide(action, Some(&new), Some(&old), &Presence::Observed(new)),
                if action == ActionData::FreshInstall { Decision::Refuse }
                else if action == ActionData::Uninstall { Decision::RemoveEnrolled } else { Decision::KeepCurrent });
            assert_eq!(decide(action, Some(&new), Some(&old), &Presence::Observed(old)),
                if action == ActionData::Update { Decision::ReplaceEnrolled } else { Decision::Refuse });
        }
    }
    #[test]
    fn launcher_observation_preserves_zero_core_noop_and_requires_actual_finality() {
        use OutcomeData::*;
        for outcome in [VerifiedExisting, Published, Restored, InverseRestored, Refused, Unknown] {
            let writes = u64::from(matches!(outcome, Published | Restored));
            let base = ObservationData { outcome, published_identity:Some(OriginalIdentityData {device:1,inode:42,birth_seconds:1,birth_nanoseconds:0, volume_uuid: None }),
                publication_phase:matches!(outcome,Published|Restored).then(||PhaseReferenceData {stage_instance:"1".repeat(32),sha256:"2".repeat(64)}), write_count: writes, write_bytes: writes,
                originals_closed: true, within_original_deadline: true, readback_verified: true, workspace_cleared: true };
            assert!(base.valid_data());
            assert_eq!(base.complete_data(false), matches!(outcome, VerifiedExisting | Published | Restored));
            assert_eq!(base.complete_data(true), outcome == InverseRestored);
            for cut in 0..4 {
                let mut failed = base.clone();
                match cut { 0 => failed.originals_closed = false, 1 => failed.within_original_deadline = false,
                    2 => failed.readback_verified = false, _ => failed.workspace_cleared = false };
                assert!(!failed.complete_data(false)); assert!(!failed.complete_data(true));
            }
            for (count, bytes) in [(0, 1), (1, 0), (2, 1), (u64::MAX, u64::MAX)] {
                let mut bad = base.clone(); bad.write_count = count; bad.write_bytes = bytes;
                assert!(!bad.valid_data());
            }
        }
        let value = serde_json::json!({"outcome":"restored","writeCount":1,"writeBytes":4,
            "publishedIdentity":{"device":1,"inode":42,"birthSeconds":1,"birthNanoseconds":0},
            "publicationPhase":{"stageInstance":"1".repeat(32),"sha256":"2".repeat(64)},
            "originalsClosed":true,"withinOriginalDeadline":true,"readbackVerified":true,"workspaceCleared":true});
        assert!(serde_json::from_value::<ObservationData>(value.clone()).unwrap().complete_data(false));
        for key in ["publicationPhase", "publishedIdentity", "writeCount", "writeBytes", "originalsClosed", "withinOriginalDeadline", "readbackVerified", "workspaceCleared"] {
            let mut missing = value.clone(); missing.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<ObservationData>(missing).is_err());
        }
        for identity in [serde_json::Value::Null,
            serde_json::json!({"device":1,"inode":0,"birthSeconds":1,"birthNanoseconds":0}),
            serde_json::json!({"device":1,"inode":42,"birthSeconds":0,"birthNanoseconds":0}),
            serde_json::json!({"device":1,"inode":42,"birthSeconds":1,"birthNanoseconds":1_000_000_000})] {
            let mut bad=value.clone();bad["publishedIdentity"]=identity;
            assert!(!serde_json::from_value::<ObservationData>(bad).unwrap().complete_data(false));
        }
        let mut absent_inverse=value.clone();absent_inverse["outcome"]=serde_json::json!("inverse-restored");
        absent_inverse["publishedIdentity"]=serde_json::Value::Null;
        assert!(serde_json::from_value::<ObservationData>(absent_inverse).unwrap().complete_data(true));
        let mut extra = value; extra["trusted"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ObservationData>(extra).is_err());
    }

}
