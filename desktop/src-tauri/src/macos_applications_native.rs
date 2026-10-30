// Native convenience-bundle operations using the Installer's existing original
// descriptor book, clock, copier and exclusive rename. This module is private
// to macos_install; there is no new process owner or caller-selected target.
//
// Enrollment in current-state, recovery and removal census is deliberately a
// prerequisite for calling these operations. Merely compiling this adapter
// does not publish /Applications or report a fully installed application.
use super::*;
use mobile_release_desktop::macos_applications_launcher as launcher;
use installation_record::InventoryIndex;

pub(super) const WORK_NAME: &str = ".applications-launcher-v1";
pub(super) const SOURCE_NAME: &str = "MobileReleaseKitLauncher.app";
const RETAINED_NAME: &str = "previous.app";

// Returned copy writes are accounted separately so restoring a missing
// convenience launcher cannot turn a core same-package no-op into a rewrite.
// A bound failure is absorbing and retained AFTER the actual returned write.
#[derive(Default)]
pub(super) struct WriteCounts {
    pub(super) calls: u64, pub(super) bytes: u64, pub(super) failed: bool,
}
impl WriteCounts {
    pub(super) fn record_returned(&mut self, count: u64, core_bytes: u64) -> Result<()> {
        let calls = self.calls.checked_add(1);
        let bytes = self.bytes.checked_add(count);
        self.calls = calls.unwrap_or(u64::MAX);
        self.bytes = bytes.unwrap_or(u64::MAX);
        self.failed |= count == 0 || calls.is_none() || bytes.is_none()
            || self.calls > self.bytes
            || self.bytes > launcher::LIMITS.iter().copied().sum::<u64>() + launcher::TICKET_LIMIT
            || core_bytes.checked_add(self.bytes).is_none_or(|n| n > installation_record::PAYLOAD_LIMIT);
        check(!self.failed, "launcher-write-bound")
    }
}
fn selected_copy_bytes(indexed: &InventoryIndex<'_>) -> Result<u64> {
    Ok(launcher::LauncherInventory::from_index(indexed)?.ok_or("launcher-inventory-missing")?.total_bytes())
}

// Retain only the five selected signed entries, not another complete parsed
// runtime inventory. The enclosing observer reserves this bounded work inside
// its existing control/original budget before invoking capture.
pub(super) const PHASE_LIMIT: usize = 4096;
// Explicit additional peak for one immutable receipt: serialized DATA, strict
// parse/owned strings, retained raw bytes and readback buffer. The original
// book separately charges actual Original/name capacities. Five originals
// cover worker stage alias + writer + reader and parent stage + reader. The
// writer is closed before the readback reader opens, so the extra live peak
// is two, not five. KeepCurrent creates no phase or these originals.
pub(super) const PHASE_CONTROL_QUOTE: u64 = 16 * PHASE_LIMIT as u64
    + std::mem::size_of::<PublicationPhaseData>() as u64;
pub(super) const PHASE_ORIGINAL_QUOTE: u64 = 5;
pub(super) const PHASE_LIVE_QUOTE: u64 = 2;
pub(super) const OBSERVATION_CONTROL_QUOTE: u64 = 3 * installation_record::INVENTORY_LIMIT as u64 + 64 * 1024
    + PHASE_CONTROL_QUOTE;
pub(super) struct Material { entries: Vec<Entry>, bytes: u64 }
impl Material {
    fn from_index(index: &InventoryIndex<'_>) -> Result<Option<Self>> {
        let Some(selected) = launcher::LauncherInventory::from_index(index)? else { return Ok(None); };
        let entries = selected.entries().iter().copied().chain(selected.ticket()).map(|entry|
            Entry { path:entry.path.clone(),sha256:entry.sha256.clone(),size:entry.size,executable:entry.executable }).collect();
        Ok(Some(Self { entries,bytes:selected.total_bytes() }))
    }
    fn index(&self) -> InventoryIndex<'_> {
        InventoryIndex { files:self.entries.iter().map(|entry| (entry.path.clone(),entry)).collect(),
            directories:["", "/Contents", "/Contents/MacOS", "/Contents/Resources", "/Contents/_CodeSignature"]
                .into_iter().map(|suffix| format!("{}{suffix}",launcher::BUNDLE)).collect(),payload_bytes:self.bytes }
    }
    fn binding(&self) -> serde_json::Value {
        // Five fixed selected leaves, not an independently authoritative manifest.
        serde_json::json!(self.entries.iter().map(|entry|serde_json::json!({
            "path":entry.path,"sha256":entry.sha256,"bytes":entry.size,"executable":entry.executable
        })).collect::<Vec<_>>())
    }
    fn same(&self, other: &Self) -> Result<bool> {
        Ok(launcher::LauncherInventory::from_index(&self.index())?.ok_or("launcher-inventory-missing")?
            .same_content(&launcher::LauncherInventory::from_index(&other.index())?.ok_or("launcher-inventory-missing")?))
    }
}

// Read both the held original and its current name, including Darwin birth
// time. A later byte-identical replacement is not an enrolled original.
fn original_identity(book: &Install, original: usize) -> Result<launcher::OriginalIdentityData> {
    book.check_name(original,true)?;
    let held=stat::fstat(book.fd(original)?).map_err(|_|"launcher-identity-stat")?;
    let row=&book.originals[original];
    let named=book.named(row.parent,&row.name).map_err(|_|"launcher-identity-name")?;
    let data=launcher::OriginalIdentityData {device:i64::from(held.st_dev),inode:held.st_ino,
        birth_seconds:held.st_birthtime,birth_nanoseconds:held.st_birthtime_nsec,
        volume_uuid:Some(mobile_release_desktop::macos_persistent_identity::observe_volume(book.fd(original)?.as_fd())
            .map_err(|_|"launcher-volume-uuid")?) };
    check(data.valid_data() && Identity::of(&held)==Identity::of(&named)
        && held.st_birthtime==named.st_birthtime && held.st_birthtime_nsec==named.st_birthtime_nsec
        && held.st_flags==0 && named.st_flags==0,"launcher-original-identity")?;
    book.check_name(original,true)?;
    Ok(data)
}
fn require_enrolled(book:&Install,original:usize,expected:Option<launcher::OriginalIdentityData>)->Result<()> {
    let observed=original_identity(book,original)?;
    check(expected.is_some_and(|value|value.valid_data() && (value==observed
        || book.legacy_volumes.iter().flatten().any(|binding|value.matches_legacy_binding_data(observed,*binding)))),
        "launcher-enrolled-original")
}

fn occupied_decision(action: mobile_release_desktop::macos_install_maintenance::ActionData,
    enrolled: bool, same: bool) -> Result<launcher::Decision> {
    use mobile_release_desktop::macos_install_maintenance::ActionData;
    check(enrolled && !matches!(action,ActionData::FreshInstall|ActionData::Uninstall),
        "launcher-unenrolled-collision")?;
    if same { Ok(launcher::Decision::KeepCurrent) }
    else {
        check(action == ActionData::Update,"launcher-generation-content")?;
        Ok(launcher::Decision::ReplaceEnrolled)
    }
}

pub(super) struct Observation {
    pub(super) current: Material, pub(super) previous: Option<Material>,
    pub(super) operation: Operation, pub(super) decision: launcher::Decision,
    absent: bool,
    prior_capsule: Option<String>,
}
impl Observation {
    pub(super) fn capture(book: &mut Install, prepared: &PreparedFresh,
        history: Option<&maintenance::History>, old_release: Option<usize>,
        action: mobile_release_desktop::macos_install_maintenance::ActionData,
        control_bytes: u64) -> Result<Option<Self>> {
        check(action != mobile_release_desktop::macos_install_maintenance::ActionData::Uninstall,
            "launcher-install-observation-action")?;
        // The enclosing observer has already charged its own full live work;
        // this additional peak must fit BEFORE inventory metadata is read.
        check(control_bytes.checked_add(OBSERVATION_CONTROL_QUOTE)
            .is_some_and(|n|n<=(installation_record::CONTROL_LIMIT as u64)),"launcher-observation-memory")?;
        let current = Material::from_index(&prepared.inventory.index()?)?;
        let previous = if let Some(history) = history {
            let generation = history.current.state.current_data();
            let binding = generation.release_data().binding_data();
            let release = old_release.ok_or("launcher-generation-missing")?;
            check(book.matches_recorded_directory(release,generation.release_directory_data())?, "launcher-generation-original")?;
            let (reader, bytes) = maintenance::metadata_original(book,release,
                installation_record::INVENTORY_NAME,installation_record::INVENTORY_LIMIT)?;
            check(format!("{:x}",Sha256::digest(&bytes)) == binding.inventory_sha256, "launcher-generation-inventory")?;
            let inventory = Inventory::parse_for_release(&bytes,binding.runtime_manifest_sha256,binding.release)?;
            let material = Material::from_index(&inventory.index()?)?;
            book.check_name(reader,true)?;
            book.forward_close(reader,"launcher-generation-inventory-close")?;
            book.check_name(release,false)?;
            material
        } else {
            check(old_release.is_none(),"launcher-generation-context")?;
            None
        };
        let Some(current) = current else {
            check(previous.is_none(),"launcher-enrollment-downgrade")?;
            return Ok(None); // Legacy unrelated Applications namespace untouched.
        };
        let mut operation = Operation::open(book)?;
        let absent = operation.absent(book)?;
        let prior_capsule = history.filter(|h|h.current.capsule.launcher_data()
            .is_some_and(|entry|entry.complete_data(false) || entry.complete_data(true))).map(|h|h.current.capsule.digest_data().to_owned());
        let decision = if absent { launcher::Decision::PublishAbsent } else {
            // Neither fresh matching bytes nor a legacy generation without
            // enrollment can authorize adopting a pre-existing copy.
            check(action != mobile_release_desktop::macos_install_maintenance::ActionData::FreshInstall,
                "launcher-unowned-collision")?;
            check(prior_capsule.is_some(),"launcher-unenrolled-collision")?;
            let old = previous.as_ref().ok_or("launcher-unowned-collision")?;
            operation.hold_matching(book,&old.index(),history.and_then(|h|h.current.capsule.launcher_data()).and_then(|row|row.published_identity))?;
            occupied_decision(action,prior_capsule.is_some(),current.same(old)?)?
        };
        Ok(Some(Self { current,previous,operation,decision,absent,prior_capsule }))
    }
    pub(super) fn close_for_reobservation(self, book: &mut Install) -> Result<()> {
        self.post(book)?;
        if let Some(bundle) = self.operation.bundle {
            book.forward_close(bundle,"launcher-observation-bundle-close")?;
        }
        self.operation.parent_post(book)?;
        book.forward_close(self.operation.applications,"launcher-observation-parent-close")?;
        book.forward_close(self.operation.system_root,"launcher-observation-root-close")?;
        book.clock()
    }
    pub(super) fn planned_cost(&self) -> Result<(u64,u64,u64)> {
        let new_files = if self.decision == launcher::Decision::KeepCurrent {0} else {self.current.entries.len() as u64};
        let (old_files,old_bytes) = if self.absent {(0,0)} else {
            let old = self.previous.as_ref().ok_or("launcher-generation-missing")?;
            (old.entries.len() as u64,old.bytes)
        };
        let bytes = old_bytes.checked_add(if new_files==0 {0} else {self.current.bytes})
            .ok_or("launcher-storage-bound")?;
        // The new receipt is persisted in the generation stage, not in the
        // copied bundle. Charge it once with the physical file/storage total;
        // historical receipt bytes are already counted by the history census.
        let phase = u64::from(self.creates_phase());
        Ok((old_files+new_files+phase,bytes.checked_add(phase * PHASE_LIMIT as u64)
            .ok_or("launcher-storage-bound")?,new_files))
    }
    pub(super) fn creates_phase(&self) -> bool {self.decision != launcher::Decision::KeepCurrent}
    pub(super) fn post(&self, book: &mut Install) -> Result<()> {
        if self.absent { check(self.operation.absent(book)?,"launcher-original-absence")?; }
        else {
            self.operation.parent_post(book)?;
            let old = self.previous.as_ref().ok_or("launcher-unowned-collision")?;
            let bundle = self.operation.bundle.ok_or("launcher-original-missing")?;
            check(book.originals[bundle].parent == Some(self.operation.applications)
                && book.originals[bundle].name == launcher::APPLICATIONS_NAME,"launcher-original-binding")?;
            maintenance::audit_launcher_tree(book,bundle,&old.index())?;
            book.check_name(bundle,true)?;
            self.operation.parent_post(book)?;
        }
        book.clock()
    }
    // The parent has already joined the original worker and validated the
    // recorded core state. A child's closed DATA cannot substitute for this
    // separate readback through our pre-GO parent originals.
    pub(super) fn after_join(&self, book: &mut Install,
        action: mobile_release_desktop::macos_install_maintenance::ActionData,
        history: Option<&maintenance::History>, invocation: &str, inverse: bool,
        row: &launcher::ObservationData,intent:&transaction::IntentData) -> Result<()> {
        use mobile_release_desktop::macos_install_maintenance::ActionData;
        check(row.complete_data(inverse) && row.write_bytes <= self.current.bytes,
            "launcher-parent-result")?;
        if matches!(row.outcome,launcher::OutcomeData::Published|launcher::OutcomeData::Restored) {
            check(row.write_bytes == self.current.bytes,"launcher-parent-copy-bytes")?;
        }
        if inverse {
            check(action == ActionData::Update,"launcher-parent-inverse-action")?;
            if let Some(original) = self.operation.bundle {
                // A known rename may change ctime, never inode, ownership,
                // content or the retained original. Do not adopt a same-byte
                // replacement at the old name.
                maintenance::rebind_renamed(book,original,self.operation.applications,
                    launcher::APPLICATIONS_NAME)?;
            }
            check(row.published_identity==self.operation.bundle.map(|n|original_identity(book,n)).transpose()?,
                "launcher-parent-inverse-identity")?;
            self.post(book)?;
        } else if self.decision == launcher::Decision::KeepCurrent {
            check(row.outcome == launcher::OutcomeData::VerifiedExisting,
                "launcher-parent-existing-result")?;
            require_enrolled(book,self.operation.bundle.ok_or("launcher-original-missing")?,row.published_identity)?;
            self.post(book)?;
        } else {
            check(matches!(row.outcome,launcher::OutcomeData::Published|launcher::OutcomeData::Restored),
                "launcher-parent-publication-result")?;
            let mut current = Operation { applications:self.operation.applications,
                system_root:self.operation.system_root,bundle:None,
                returned:Returned::NotAttempted,verified:false };
            current.hold_matching(book,&self.current.index(),row.published_identity)?;
            book.forward_close(current.bundle.ok_or("launcher-original-missing")?,
                "launcher-parent-bundle-close")?;
            current.parent_post(book)?;
        }
        // Use the exact generation whose staging area the worker was allowed
        // to use, including the new invocation on an update that was inversed.
        let instance = match action {
            ActionData::FreshInstall|ActionData::Update => invocation.to_owned(),
            ActionData::SamePackageNoop|ActionData::RestoreFixedApp => history
                .ok_or("launcher-parent-history")?.current.state.current_data().instance_data().to_owned(),
            ActionData::Uninstall => return Err("launcher-parent-install-action"),
        };
        check(worker::invocation_valid(&instance),"launcher-generation-instance")?;
        let root = book.gate.parent.ok_or("launcher-maintenance-required")?;
        let stage = book.open(Some(root),&format!(".install-{instance}"),true)?;
        book.protected(stage,true,Some(0o700))?;
        native::no_xattrs(book.fd(stage)?.as_fd()).map_err(|_|"launcher-stage-attributes")?;
        book.absent(stage,WORK_NAME)?;
        if let Some(reference)=&row.publication_phase {
            check(reference.valid_data() && reference.stage_instance==instance,"launcher-parent-phase-stage")?;
            let (reader,raw)=maintenance::metadata_original(book,stage,
                &PublicationPhaseData::name(intent.invocation_data())?,PHASE_LIMIT)?;
            check(format!("{:x}",Sha256::digest(&raw))==reference.sha256,"launcher-parent-phase-digest")?;
            let phase=PublicationPhaseData::parse_raw(&raw)?;phase.check(intent,&instance)?;
            check(phase.stage==container_identity(book,stage)?
                && if inverse {phase.previous==row.published_identity} else {Some(phase.staged)==row.published_identity},
                "launcher-parent-phase-original")?;
            book.check_name(reader,true)?;book.forward_close(reader,"launcher-parent-phase-close")?;
        } else {check(self.decision==launcher::Decision::KeepCurrent || inverse,"launcher-parent-phase-required")?;}
        book.check_name(stage,false)?;
        book.forward_close(stage,"launcher-parent-stage-close")?;
        self.operation.parent_post(book)?;
        book.clock()
    }
    pub(super) fn binding(&self, book: &Install) -> Result<serde_json::Value> {
        self.operation.parent_post(book)?;
        Ok(serde_json::json!({"absent":self.absent,
            "applications":worker::identity_data(book.identity(self.operation.applications)?),
            "original":self.operation.bundle.map(|n|book.identity(n).map(worker::identity_data)).transpose()?,
            "current":self.current.binding(),"previous":self.previous.as_ref().map(Material::binding),
            "priorCapsuleSha256":self.prior_capsule}))
    }
}


// A convenience-only retirement completes before the core remover captures its
// first deletion snapshot. The already authenticated installation remains
// intact on failure; a later operation can recognize only this exact enrolled
// generation's retained signed subset, never an arbitrary Applications copy.
pub(super) struct RemovalPreparation {
    material: Material, operation: Operation, generation: transaction::GenerationData,
    workspace: Option<Workspace>, retirement: Retirement,
    absent: bool, entered: bool, completed: bool, first_failure: Option<&'static str>,
}
impl RemovalPreparation {
    pub(super) fn observe(book: &mut Install, prepared: &PreparedFresh,
        generation: &transaction::GenerationData, capsule: &transaction::CapsuleData) -> Result<Option<Self>> {
        let Some(material) = Material::from_index(&prepared.inventory.index()?)? else {
            check(capsule.launcher_data().is_none(),"launcher-removal-enrollment-mismatch")?;
            return Ok(None);
        };
        check(capsule.launcher_data().is_some_and(|row|row.complete_data(false) || row.complete_data(true)),
            "launcher-removal-enrollment-required")?;
        let binding = generation.release_data().binding_data();
        check(format!("{:x}",Sha256::digest(&prepared.inventory_bytes)) == binding.inventory_sha256,
            "launcher-removal-source")?;
        check(book.removal_control_reserved.checked_add(OBSERVATION_CONTROL_QUOTE)
            .is_some_and(|n|n<=(installation_record::CONTROL_LIMIT as u64)),"launcher-removal-control-bound")?;
        book.removal_control_reserved += OBSERVATION_CONTROL_QUOTE;
        let mut operation = Operation::open(book)?;
        let absent = operation.absent(book)?;
        let workspace = Workspace::admit(book,generation,&prepared.inventory_bytes)?;
        if book.removal_snapshot_capture.is_some() {
            check(absent && workspace.is_none(),"launcher-removal-snapshot-absence")?;
        }
        let mut result = Self {material,operation,generation:generation.clone(),workspace,
            retirement:Retirement::new(),absent,entered:false,completed:false,first_failure:None};
        if let Some(workspace) = result.workspace.as_ref() {
            // An interrupted retirement cannot authorize deleting a newer or
            // unrelated occupant, even one with identical bytes.
            check(absent,"launcher-removal-live-and-retained")?;
            result.retirement.inspect_resumed(book,workspace,&result.material.index(),capsule.launcher_data().and_then(|row|row.published_identity))?;
        } else if !absent {
            result.operation.hold_matching(book,&result.material.index(),capsule.launcher_data().and_then(|row|row.published_identity))?;
        }
        result.post_before(book)?;
        Ok(Some(result))
    }
    pub(super) fn allowed_stage(&self, book: &Install, stage: usize) -> Result<bool> {
        let Some(workspace) = self.workspace.as_ref() else {return Ok(false);};
        workspace.post(book)?;
        if book.identity(stage)?.same_object(book.identity(workspace.stage)?) {
            check(book.originals[stage].parent == book.gate.parent
                && book.originals[stage].name == format!(".install-{}",self.generation.instance_data()),
                "launcher-removal-stage-binding")?;
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn observed_post(&self,book:&Install)->Result<()> {
        self.operation.parent_post(book)?;
        if self.completed || self.absent {
            check(self.operation.absent(book)?,"launcher-removal-original-absence")?;
        } else {
            book.check_name(self.operation.bundle.ok_or("launcher-original-missing")?,true)?;
        }
        if !self.completed {if let Some(workspace)=self.workspace.as_ref() {workspace.post(book)?;}}
        book.clock()
    }
    fn post_before(&self, book: &mut Install) -> Result<()> {
        self.operation.parent_post(book)?;
        if self.absent {check(self.operation.absent(book)?,"launcher-removal-original-absence")?;}
        else {
            let bundle = self.operation.bundle.ok_or("launcher-original-missing")?;
            maintenance::audit_launcher_tree(book,bundle,&self.material.index())?;
            book.check_name(bundle,true)?;
        }
        if let Some(workspace) = self.workspace.as_ref() {
            workspace.post(book)?;
            for node in &self.retirement.nodes {book.check_name(node.original,true)?;}
        }
        book.clock()
    }
    pub(super) fn retire_before_snapshot(&mut self, book: &mut Install, prepared: &PreparedFresh) -> Result<()> {
        check(!self.entered && !self.completed,"launcher-removal-once")?;
        self.entered = true;
        let result = (|| {
            Operation::mutation_ready(book)?;
            check(book.removal_snapshot_capture.is_none() && book.removal_payload_plan.is_none(),
                "launcher-removal-before-snapshot")?;
            self.post_before(book)?;
            if self.workspace.is_none() && !self.absent {
                self.workspace = Some(Workspace::create(book,prepared,&self.generation)?);
                let workspace = self.workspace.as_ref().ok_or("launcher-workspace-missing")?;
                self.operation.quarantine(book,workspace,&self.material.index())?;
                self.retirement.prepare(book,&self.operation,workspace,&self.material.index())?;
            }
            if let Some(workspace) = self.workspace.as_mut() {
                self.retirement.run(book,workspace)?;
                workspace.retire_empty(book)?;
            }
            check(self.operation.absent(book)?,"launcher-removal-final-absence")?;
            self.operation.parent_post(book)?;
            self.completed = true;
            Ok(())
        })();
        if let Err(error) = result {self.first_failure.get_or_insert(error);}
        result
    }
    pub(super) fn close_before_second_census(self, book: &mut Install) -> Result<()> {
        check(self.completed && self.first_failure.is_none()
            && self.workspace.as_ref().is_none_or(|w|w.retirement_settled),"launcher-removal-finality")?;
        check(self.operation.absent(book)?,"launcher-removal-final-absence")?;
        // The deletion ledger already closed the quarantined original; only
        // our shared-namespace parent readers remain, still the same originals.
        book.forward_close(self.operation.applications,"launcher-removal-parent-close")?;
        book.forward_close(self.operation.system_root,"launcher-removal-root-close")?;
        book.clock()
    }
    pub(super) fn physical_cost(&self) -> (u64,u64) {
        if self.absent && self.workspace.is_none() {(0,0)}
        else {(self.material.entries.len() as u64,self.material.bytes)}
    }
}

// Same-worker, same-book lifecycle state. Callers retain this value through
// original settlement even when a method returns an error after an effect.
pub(super) struct Effects {
    observation: Observation,
    workspace: Option<Workspace>,
    phase:Option<PublicationPhase>,phase_started:bool,
    next: Operation,
    old_retirement: Retirement,
    new_retirement: Retirement,
    inverse: Inverse,
    entered: bool,
    committed: bool,
    inverse_verified: bool,
    inverse_entered: bool,
    readback_verified: bool,
    final_identity: Option<launcher::OriginalIdentityData>,
    first_failure: Option<&'static str>,
}
impl Effects {
    pub(super) fn new(observation: Observation) -> Self {
        // Borrow the exact original parent slots, not duplicate descriptors.
        let next = Operation { applications:observation.operation.applications,
            system_root:observation.operation.system_root,bundle:None,
            returned:Returned::NotAttempted,verified:false };
        Self { observation,workspace:None,phase:None,phase_started:false,next,old_retirement:Retirement::new(),
            new_retirement:Retirement::new(),inverse:Inverse::new(),entered:false,
            committed:false,inverse_verified:false,inverse_entered:false,readback_verified:false,final_identity:None,first_failure:None }
    }
    fn retain(&mut self, result: Result<()>) -> Result<()> {
        if let Err(error) = result { self.first_failure.get_or_insert(error); }
        result
    }
    pub(super) fn publish_before_state(&mut self, book: &mut Install, prepared: &PreparedFresh,
        generation: &transaction::GenerationData,intent:&transaction::IntentData) -> Result<()> {
        check(!self.entered && self.first_failure.is_none(),"launcher-lifecycle-once")?;
        self.entered = true;
        let result = (|| {
            Operation::mutation_ready(book)?;
            check(book.maintenance.as_ref().is_some_and(|e|!e.state_published),"launcher-before-state")?;
            self.observation.post(book)?;
            if self.observation.decision == launcher::Decision::KeepCurrent {
                self.readback_verified = true;
                return Ok(());
            }
            check(matches!(self.observation.decision,launcher::Decision::PublishAbsent
                | launcher::Decision::ReplaceEnrolled),"launcher-lifecycle-decision")?;
            self.workspace = Some(Workspace::create(book,prepared,generation)?);
            let workspace = self.workspace.as_ref().ok_or("launcher-workspace-missing")?;
            let staged = Operation::stage(book,prepared,workspace)?;
            self.observation.post(book)?;
            self.phase_started=true;
            self.phase=Some(PublicationPhase::record(book,workspace,intent,staged,self.observation.operation.bundle)?);
            self.phase.as_ref().ok_or("launcher-phase-required")?.post(book)?;
            if self.observation.decision == launcher::Decision::ReplaceEnrolled {
                let old = self.observation.previous.as_ref().ok_or("launcher-generation-missing")?;
                self.observation.operation.quarantine(book,workspace,&old.index())?;
            }
            self.next.publish(book,workspace,staged,&self.observation.current.index())?;
            self.readback_verified = true;
            Ok(())
        })();
        self.retain(result)
    }
    pub(super) fn finish_after_state(&mut self, book: &mut Install) -> Result<()> {
        check(self.entered && !self.committed && self.first_failure.is_none(),"launcher-finalize-once")?;
        let result = (|| {
            Operation::mutation_ready(book)?;
            check(book.maintenance.as_ref().is_some_and(|e|e.state_published && !e.inverse
                && e.state.is_some()),"launcher-finalize-state")?;
            self.live_post(book,false)?;
            if let Some(workspace) = self.workspace.as_mut() {
                if self.observation.decision == launcher::Decision::ReplaceEnrolled {
                    let old = self.observation.previous.as_ref().ok_or("launcher-generation-missing")?;
                    self.old_retirement.prepare(book,&self.observation.operation,workspace,&old.index())?;
                    self.old_retirement.run(book,workspace)?;
                }
                workspace.retire_empty(book)?;
            }
            self.live_post(book,false)?;
            check(!book.launcher_writes.failed,"launcher-write-bound")?;
            if let Some(phase)=&self.phase {phase.close(book)?;}
            self.final_identity=Some(original_identity(book,if self.observation.decision==launcher::Decision::KeepCurrent {
                self.observation.operation.bundle
            } else {self.next.bundle}.ok_or("launcher-original-missing")?)?);
            self.committed = true;
            Ok(())
        })();
        self.retain(result)
    }
    fn live_post(&self, book: &mut Install, inverse: bool) -> Result<()> {
        if inverse || self.observation.decision == launcher::Decision::KeepCurrent {
            self.observation.post(book)
        } else {
            self.next.parent_post(book)?;
            check(self.next.returned == Returned::Published && self.next.verified,"launcher-final-publication")?;
            let bundle = self.next.bundle.ok_or("launcher-original-missing")?;
            check(book.originals[bundle].parent == Some(self.next.applications)
                && book.originals[bundle].name == launcher::APPLICATIONS_NAME,"launcher-final-original")?;
            maintenance::audit_launcher_tree(book,bundle,&self.observation.current.index())?;
            book.check_name(bundle,true)?;
            self.next.parent_post(book)
        }
    }
    pub(super) fn restore_before_inverse_state(&mut self, book: &mut Install,
        prepared: &PreparedFresh) -> Result<()> {
        check(!self.inverse_entered && !self.committed,"launcher-inverse-once")?;
        self.inverse_entered = true;
        let result = (|| {
            Operation::mutation_ready(book)?;
            check(!book.unknown && book.maintenance.as_ref().is_some_and(|e|
                e.action == mobile_release_desktop::macos_install_maintenance::ActionData::Update
                && !e.state_published),"launcher-inverse-before-state")?;
            // A failed receipt write must retain its staged original so later
            // recovery can validate the exact metadata prefix before cleanup.
            check(!self.phase_started || self.phase.is_some(),"launcher-phase-unsettled")?;
            if let Some(phase)=&self.phase {phase.post(book)?;}
            if let Some(workspace) = self.workspace.as_mut() {
                match self.observation.operation.returned {
                    Returned::Quarantined => {
                        let old = self.observation.previous.as_ref().ok_or("launcher-generation-missing")?;
                        let current_index = self.observation.current.index();
                        let next = if self.next.returned == Returned::Published { Some((&self.next,&current_index)) }
                            else { check(self.next.returned == Returned::NotAttempted
                                || self.next.returned == Returned::Refused,"launcher-inverse-publication")?;None };
                        self.inverse.restore(book,workspace,&self.observation.operation,&old.index(),next)?;
                    },
                    Returned::NotAttempted => {
                        if self.next.returned == Returned::Published {
                            check(self.observation.absent,"launcher-inverse-previous-absence")?;
                            self.inverse.restore_absence(book,workspace,&self.next,&self.observation.current.index())?;
                        } else {
                            check(matches!(self.next.returned,Returned::NotAttempted|Returned::Refused),
                                "launcher-inverse-publication")?;
                        }
                    },
                    _ => return Err("launcher-inverse-original-refused"),
                }
                self.new_retirement.prepare_staged_copy(book,workspace,prepared)?;
                self.new_retirement.run(book,workspace)?;
                workspace.retire_empty(book)?;
            }
            // This is the original previous presence/absence, not the incoming
            // bundle's existence and never permission to publish inverse state.
            self.live_post(book,true)?;
            check(!book.launcher_writes.failed,"launcher-write-bound")?;
            if let Some(phase)=&self.phase {phase.close(book)?;}
            self.final_identity=self.observation.operation.bundle.map(|n|original_identity(book,n)).transpose()?;
            self.inverse_verified = true;
            Ok(())
        })();
        self.retain(result)
    }
    pub(super) fn result_data(&self, book: &Install, originals_closed: bool,
        within_original_deadline: bool) -> launcher::ObservationData {
        let workspace_cleared = self.workspace.as_ref().is_none_or(|w|w.retirement_settled);
        let accepted = (self.committed || self.inverse_verified) && !book.launcher_writes.failed;
        launcher::ObservationData {
            outcome:if book.unknown { launcher::OutcomeData::Unknown }
                else if self.inverse_verified { launcher::OutcomeData::InverseRestored }
                else if self.committed { match self.observation.decision {
                    launcher::Decision::KeepCurrent => launcher::OutcomeData::VerifiedExisting,
                    launcher::Decision::PublishAbsent if self.observation.previous.is_some() => launcher::OutcomeData::Restored,
                    _ => launcher::OutcomeData::Published,
                }} else {launcher::OutcomeData::Refused},
            published_identity:self.final_identity,
            publication_phase:self.phase.as_ref().map(PublicationPhase::reference),
            write_count:book.launcher_writes.calls,write_bytes:book.launcher_writes.bytes,
            originals_closed,within_original_deadline,
            readback_verified:accepted && (self.readback_verified || self.inverse_verified),workspace_cleared,
        }
    }
}

// A temporary Rust borrow, not a second owner or operation. The SAME state
// returns to the Install book even when a native operation returned an error.
pub(super) fn with_effects(book: &mut Install,
    action: impl FnOnce(&mut Effects,&mut Install)->Result<()>) -> Result<()> {
    let Some(mut effects) = book.launcher_effects.take() else {return Ok(());};
    let result = action(&mut effects,book);
    book.launcher_effects = Some(effects);
    result
}

// One immutable recovery record per actual intent, inside the existing
// generation stage. It is evidence, not authority inferred from its filename.
#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct PublicationPhaseData {
    schema_version:u8, phase:String, invocation:String, intent_sha256:String,
    instance:String, inventory_sha256:String, source_commit:String, runtime_manifest_sha256:String,
    stage:launcher::OriginalIdentityData, workspace:launcher::OriginalIdentityData,
    staged:launcher::OriginalIdentityData, previous:Option<launcher::OriginalIdentityData>,
}
impl PublicationPhaseData {
    fn name(invocation:&str)->Result<String> {
        check(worker::invocation_valid(invocation),"launcher-phase-invocation")?;
        Ok(format!("launcher-{invocation}.json"))
    }
    fn valid_data(&self)->bool {
        self.schema_version==1 && self.phase=="launcher-prepublication"
            && worker::invocation_valid(&self.invocation) && worker::invocation_valid(&self.instance)
            && sha(&self.intent_sha256) && sha(&self.inventory_sha256) && sha(&self.runtime_manifest_sha256)
            && self.source_commit.len()==40 && self.source_commit.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && self.stage.valid_data() && self.workspace.valid_data() && self.staged.valid_data()
            && self.stage.same_volume_data(self.workspace) && self.workspace.same_volume_data(self.staged)
            && self.stage.inode!=self.workspace.inode && self.stage.inode!=self.staged.inode && self.workspace.inode!=self.staged.inode
            && self.previous.is_none_or(|row|row.valid_data() && row.same_volume_data(self.stage)
                && row.inode!=self.stage.inode && row.inode!=self.workspace.inode && row.inode!=self.staged.inode)
    }
    fn check(&self,intent:&transaction::IntentData,instance:&str)->Result<()> {
        let binding=intent.next_data().binding_data();
        check(self.valid_data() && self.invocation==intent.invocation_data() && self.intent_sha256==intent.digest_data()
            && self.instance==instance && self.inventory_sha256==binding.inventory_sha256
            && self.source_commit==binding.source_commit && self.runtime_manifest_sha256==binding.runtime_manifest_sha256,
            "launcher-phase-binding")
    }
    fn parse_raw(raw:&[u8])->Result<Self> {
        check(!raw.is_empty() && raw.len()<=PHASE_LIMIT,"launcher-phase-bound")?;
        let value=mobile_release_desktop::protocol::strict_json(raw).map_err(|_|"launcher-phase-json")?;
        // Serde's optional-field convenience must not accept an omitted prior
        // presence. Null is explicit and parent-checked against original absence.
        check(value.is_object() && value.get("previous").is_some(),"launcher-phase-shape")?;
        let phase:Self=serde_json::from_value(value).map_err(|_|"launcher-phase-shape")?;
        check(phase.valid_data(),"launcher-phase-shape")?;
        Ok(phase)
    }
}
fn phase_location_data(phase:&PublicationPhaseData,staged:Option<launcher::OriginalIdentityData>,
    live:Option<launcher::OriginalIdentityData>)->Result<bool> {
    check(phase.valid_data(),"launcher-phase-shape")?;
    // This boolean classifies only the recorded NEW original's placement.
    // Previous enrollment/quarantine, core State and actual exclusive lock
    // remain independent required caller checks. No action is authorized here.
    match (staged,live) {
        (Some(staged),live) if staged==phase.staged && (live.is_none() || live==phase.previous)=>Ok(false),
        (None,Some(live)) if live==phase.staged=>Ok(true),
        _=>Err("launcher-phase-placement-refused"),
    }
}

// Names come only from complete already-parsed history/capsule bindings. A
// matching prefix found on disk never enrolls a phase or authorizes cleanup.
pub(super) fn recorded_phases<'a>(history:&'a maintenance::History,instance:&str)
    ->Result<Vec<&'a maintenance::Recorded>> {
    use mobile_release_desktop::macos_install_maintenance::ActionData;
    check(history.originals.len()<transaction::INVOCATION_LIMIT,"launcher-phase-history-bound")?;
    let mut rows=Vec::new();
    for record in history.originals.values().chain(std::iter::once(&history.current)) {
        let Some(reference)=record.capsule.launcher_data().and_then(|row|row.publication_phase.as_ref()) else {continue;};
        let expected=match record.intent.action_data() {
            ActionData::FreshInstall|ActionData::Update=>record.intent.invocation_data().to_owned(),
            ActionData::SamePackageNoop|ActionData::RestoreFixedApp=>record.state.current_data().instance_data().to_owned(),
            ActionData::Uninstall=>return Err("launcher-phase-history-action"),
        };
        check(reference.valid_data() && reference.stage_instance==expected,"launcher-phase-history-stage")?;
        if reference.stage_instance==instance {rows.push(record);}
    }
    Ok(rows)
}
pub(super) fn phase_name(invocation:&str)->Result<String> {PublicationPhaseData::name(invocation)}
pub(super) fn archive_phase_reference(capsule:&transaction::CapsuleData,intent:&transaction::IntentData,
    raw:&[u8])->Result<launcher::PhaseReferenceData> {
    let row=capsule.launcher_data().ok_or("launcher-phase-history-required")?;
    let reference=row.publication_phase.as_ref().ok_or("launcher-phase-history-required")?;
    check(reference.valid_data() && capsule.invocation_data()==intent.invocation_data()
        && capsule.intent_digest_data()==intent.digest_data()
        && format!("{:x}",Sha256::digest(raw))==reference.sha256,"launcher-phase-history-binding")?;
    let phase=PublicationPhaseData::parse_raw(raw)?;phase.check(intent,&reference.stage_instance)?;
    check(row.published_identity==if row.outcome==launcher::OutcomeData::InverseRestored {phase.previous}else{Some(phase.staged)},
        "launcher-phase-history-original")?;
    Ok(reference.clone())
}

pub(super) fn recorded_phase_post(book:&mut Install,stage:usize,record:&maintenance::Recorded)->Result<u64> {
    let observation=record.capsule.launcher_data().ok_or("launcher-phase-history-required")?;
    let reference=observation.publication_phase.as_ref().ok_or("launcher-phase-history-required")?;
    check(book.originals[stage].parent==book.gate.parent
        && book.originals[stage].name==format!(".install-{}",reference.stage_instance),"launcher-phase-history-stage")?;
    let (reader,raw)=maintenance::metadata_original(book,stage,
        &PublicationPhaseData::name(record.intent.invocation_data())?,PHASE_LIMIT)?;
    check(format!("{:x}",Sha256::digest(&raw))==reference.sha256,"launcher-phase-history-hash")?;
    let phase=PublicationPhaseData::parse_raw(&raw)?;phase.check(&record.intent,&reference.stage_instance)?;
    let expected=if observation.outcome==launcher::OutcomeData::InverseRestored {phase.previous}else{Some(phase.staged)};
    // audit_selected_generation already authenticated the complete original
    // generation before enrolling its bounded legacy root-volume witness.
    // Keep all stage FD/name/hash/identity and stored capsule checks strict.
    check(launcher::recorded_stage_identity_matches_data(phase.stage,
        container_identity(book,stage)?,&book.legacy_volumes)
        && observation.published_identity==expected,
        "launcher-phase-history-original")?;
    book.check_name(reader,true)?;book.forward_close(reader,"launcher-phase-history-close")?;
    book.check_name(stage,false)?;Ok(raw.len() as u64)
}

struct PublicationPhase {
    reader:usize, stage:usize, raw:Vec<u8>, data:PublicationPhaseData,
}
fn container_identity(book:&Install,original:usize)->Result<launcher::OriginalIdentityData> {
    book.check_name(original,false)?;
    let held=stat::fstat(book.fd(original)?).map_err(|_|"launcher-phase-original-stat")?;
    let row=&book.originals[original];
    let named=book.named(row.parent,&row.name).map_err(|_|"launcher-phase-original-name")?;
    let result=launcher::OriginalIdentityData {device:i64::from(held.st_dev),inode:held.st_ino,
        birth_seconds:held.st_birthtime,birth_nanoseconds:held.st_birthtime_nsec,
        volume_uuid:Some(mobile_release_desktop::macos_persistent_identity::observe_volume(book.fd(original)?.as_fd())
            .map_err(|_|"launcher-volume-uuid")?) };
    check(result.valid_data() && Identity::of(&held)==Identity::of(&named)
        && held.st_birthtime==named.st_birthtime && held.st_birthtime_nsec==named.st_birthtime_nsec
        && held.st_flags==0 && named.st_flags==0,"launcher-phase-original-identity")?;
    book.check_name(original,false)?;
    Ok(result)
}
fn phase_admission_data(originals:usize,live:usize)->Result<()> {
    check(originals.checked_add(PHASE_ORIGINAL_QUOTE as usize)
        .is_some_and(|n|n<=installation_record::ORIGINAL_LIMIT)
        && live.checked_add(PHASE_LIVE_QUOTE as usize).is_some_and(|n|n<=96),
        "launcher-phase-budget")
}
impl PublicationPhase {
    fn record(book:&mut Install,workspace:&Workspace,intent:&transaction::IntentData,
        staged:usize,previous:Option<usize>)->Result<Self> {
        Operation::mutation_ready(book)?;workspace.post(book)?;
        let external=book.removal_live_reserved
            + if book.worker_deadline.is_some() {worker::EXTRA_LIVE} else {0};
        phase_admission_data(book.originals.len(),book.originals.iter().filter(|row|row.fd.is_some()).count()
            .checked_add(external).ok_or("launcher-phase-budget")?)?;
        check(book.originals[staged].parent==Some(workspace.original)
            && book.originals[staged].name==SOURCE_NAME,"launcher-phase-staged-original")?;
        let binding=intent.next_data().binding_data();
        let data=PublicationPhaseData {schema_version:1,phase:"launcher-prepublication".into(),
            invocation:intent.invocation_data().into(),intent_sha256:intent.digest_data().into(),
            instance:workspace.instance.clone(),inventory_sha256:binding.inventory_sha256.into(),
            source_commit:binding.source_commit.into(),runtime_manifest_sha256:binding.runtime_manifest_sha256.into(),
            stage:container_identity(book,workspace.stage)?,workspace:container_identity(book,workspace.original)?,
            staged:original_identity(book,staged)?,previous:previous.map(|n|original_identity(book,n)).transpose()?};
        data.check(intent,&workspace.instance)?;
        let raw=serde_json::to_vec(&data).map_err(|_|"launcher-phase-shape")?;
        check(raw.len()<=PHASE_LIMIT,"launcher-phase-bound")?;
        let name=PublicationPhaseData::name(intent.invocation_data())?;
        book.absent(workspace.stage,&name)?;
        // The ordinary workspace cleanup consumes its own stage reader.
        // Retain this one additional original for immutable evidence POST;
        // do not keep a deleted workspace FD or silently reopen by path later.
        let stage=book.open(book.originals[workspace.stage].parent,
            &book.originals[workspace.stage].name.clone(),true)?;
        check(container_identity(book,stage)?==data.stage,"launcher-phase-stage-original")?;
        let reader=book.record_file(stage,&name,&raw,Role::ReceiptWriter)?;
        // Both data and containing directory durable before the first rename.
        book.persist(stage,false)?;
        let phase=Self {reader,stage,raw,data};
        phase.post(book)?;workspace.post(book)?;
        check(container_identity(book,workspace.original)?==phase.data.workspace
            && original_identity(book,staged)?==phase.data.staged
            && previous.map(|n|original_identity(book,n)).transpose()?==phase.data.previous,
            "launcher-phase-original-post")?;
        Ok(phase)
    }
    fn reference(&self)->launcher::PhaseReferenceData {
        launcher::PhaseReferenceData {stage_instance:self.data.instance.clone(),sha256:format!("{:x}",Sha256::digest(&self.raw))}
    }
    fn close(&self,book:&mut Install)->Result<()> {
        self.post(book)?;book.forward_close(self.reader,"launcher-phase-reader-close")?;
        book.check_name(self.stage,false)?;book.forward_close(self.stage,"launcher-phase-stage-close")
    }
    fn post(&self,book:&Install)->Result<()> {
        let stage=self.stage;
        check(book.originals[self.reader].parent==Some(stage)
            && book.originals[self.reader].name==PublicationPhaseData::name(&self.data.invocation)?
            && container_identity(book,stage)?==self.data.stage,"launcher-phase-original")?;
        book.check_name(self.reader,true)?;
        book.protected(self.reader,false,Some(0o444))?;
        let stat=stat::fstat(book.fd(self.reader)?).map_err(|_|"launcher-phase-stat")?;
        check(stat.st_size==self.raw.len() as i64 && stat.st_flags==0,"launcher-phase-original")?;
        let mut bytes=[0u8;PHASE_LIMIT];let mut at=0usize;
        while at<self.raw.len() {
            book.clock()?;
            let n=nix::sys::uio::pread(book.fd(self.reader)?,&mut bytes[at..self.raw.len()],at as i64)
                .map_err(|_|"launcher-phase-read")?;
            check(n>0 && n<=self.raw.len()-at,"launcher-phase-read")?;at+=n;
        }
        check(bytes[..at]==self.raw,"launcher-phase-original-bytes")?;
        book.check_name(self.reader,true)?;book.clock()
    }
}

// The existing authenticated Fresh/rehome Parent may preserve a torn new
// convenience copy with the rest of that attempt. This is not Update recovery
// or an alternative registration owner. Only its original source/R/M view can
// invoke the one exclusive withdrawal; all returned effects stay in this value.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum FreshPlacement { Workspace, Stage, Applications }
fn fresh_placement_data(phase:&PublicationPhaseData,workspace:Option<launcher::OriginalIdentityData>,
    stage:Option<launcher::OriginalIdentityData>,live:Option<launcher::OriginalIdentityData>)->Result<FreshPlacement> {
    check(phase.previous.is_none() && !(workspace.is_some() && stage.is_some()),"launcher-fresh-placement")?;
    let published=phase_location_data(phase,workspace.or(stage),live)?;
    Ok(if published {FreshPlacement::Applications}else if workspace.is_some(){FreshPlacement::Workspace}else{FreshPlacement::Stage})
}
pub(super) struct FreshRecovery {
    phase:PublicationPhase,operation:Operation,material:Material,workspace:Option<usize>,
    bundle:usize,location:FreshPlacement,returned:Returned,first:Option<&'static str>,settled:bool,
}
impl FreshRecovery {
    pub(super) fn observe(book:&mut Install,view:&worker::ReinstallOldControlsObserved<'_>,
        invocation:&str,expected:Option<[u8;32]>)->Result<Option<Self>> {
        view.post(book)?;
        let (_,inventory,_)=view.incoming(book)?;
        let (_,_,index_peak)=view.incoming_index_peak(book)?;
        check(maintenance::removal_effective_control_bytes(book)?.checked_add(index_peak as u64)
            .and_then(|n|n.checked_add(PHASE_CONTROL_QUOTE+128*1024))
            .is_some_and(|n|n<=installation_record::CONTROL_LIMIT as u64),"launcher-recovery-memory")?;
        let index=inventory.index()?;
        let Some(material)=Material::from_index(&index)? else{return Ok(None);};drop(index);
        let end=book.originals.len().checked_add(256).filter(|n|*n<=installation_record::ORIGINAL_LIMIT)
            .ok_or("launcher-recovery-budget")?;
        check(book.originals.iter().filter(|row|row.fd.is_some()).count()+book.removal_live_reserved+16<=96,
            "launcher-recovery-budget")?;
        maintenance::reserve_removal_original_storage(book,end)?;
        check(maintenance::removal_effective_control_bytes(book)?.checked_add(PHASE_CONTROL_QUOTE)
            .is_some_and(|n|n<=installation_record::CONTROL_LIMIT as u64),"launcher-recovery-memory")?;
        book.removal_control_reserved=book.removal_control_reserved.checked_add(PHASE_CONTROL_QUOTE)
            .ok_or("launcher-recovery-memory")?;
        let root=view.root_original();let name=format!(".install-{invocation}");
        check(worker::invocation_valid(invocation),"launcher-recovery-invocation")?;
        let mut operation=Operation::open(book)?;
        let stage=match book.named(Some(root),&name) {
            Err(Errno::ENOENT)=>{
                check(operation.absent(book)?,"launcher-recovery-unowned-live")?;
                book.forward_close(operation.applications,"launcher-recovery-applications-close")?;
                book.forward_close(operation.system_root,"launcher-recovery-root-close")?;return Ok(None);
            },Err(_)=>return Err("launcher-recovery-stage"),Ok(_)=>book.open(Some(root),&name,true)?,
        };
        book.protected(stage,true,Some(0o700))?;
        native::no_xattrs(book.fd(stage)?.as_fd()).map_err(|_|"launcher-recovery-stage-attributes")?;
        let phase_name=PublicationPhaseData::name(invocation)?;
        let sealed=match book.named(Some(stage),&phase_name) {
            Err(Errno::ENOENT)=>false,
            Err(_)=>return Err("launcher-recovery-phase"),
            Ok(value)=>value.st_mode & 0o7777==0o444,
        };
        if !sealed {
            // A missing or unfinished receipt never grants authority over a
            // live Applications entry. The subsequent ordinary partial-prefix
            // audit validates/preserves its original bytes, if any.
            check(operation.absent(book)?,"launcher-recovery-unowned-live")?;
            book.check_name(stage,true)?;book.forward_close(stage,"launcher-recovery-stage-close")?;
            book.forward_close(operation.applications,"launcher-recovery-applications-close")?;
            book.forward_close(operation.system_root,"launcher-recovery-root-close")?;view.post(book)?;return Ok(None);
        }
        let (intent_reader,intent_raw)=maintenance::metadata_original(book,root,
            &transaction::intent_name_data(invocation).map_err(|_|"launcher-recovery-intent-name")?,transaction::INTENT_LIMIT)?;
        let intent=transaction::IntentData::parse_data(&intent_raw,view.new_selection(book)?).map_err(|_|"launcher-recovery-intent")?;
        check(intent.invocation_data()==invocation
            && intent.action_data()==mobile_release_desktop::macos_install_maintenance::ActionData::FreshInstall
            && intent.previous_data().is_none() && intent.previous_state_data().is_none()
            && expected.is_none_or(|hash|<[u8;32]>::from(Sha256::digest(&intent_raw))==hash),
            "launcher-recovery-fresh-intent")?;
        let (reader,raw)=maintenance::metadata_original(book,stage,&phase_name,PHASE_LIMIT)?;
        let data=PublicationPhaseData::parse_raw(&raw)?;data.check(&intent,invocation)?;
        check(data.previous.is_none() && data.stage==container_identity(book,stage)?,"launcher-recovery-stage-original")?;
        let phase=PublicationPhase{reader,stage,raw,data};phase.post(book)?;
        book.check_name(intent_reader,true)?;book.forward_close(intent_reader,"launcher-recovery-intent-close")?;
        let workspace=match book.named(Some(stage),WORK_NAME) {
            Err(Errno::ENOENT)=>None,Err(_)=>return Err("launcher-recovery-workspace"),Ok(_)=>{
                let original=book.open(Some(stage),WORK_NAME,true)?;
                book.protected(original,true,Some(0o700))?;
                native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_|"launcher-recovery-workspace-attributes")?;
                check(container_identity(book,original)?==phase.data.workspace,"launcher-recovery-workspace-original")?;
                let roster=maintenance::roster_now(book,original)?;
                check(roster.len()<=1 && roster.keys().all(|name|name==SOURCE_NAME),"launcher-recovery-workspace-roster")?;
                Some(original)
            },
        };
        let mut held=[None,None,None];
        for (at,parent,name) in [(0,workspace,SOURCE_NAME),(1,Some(stage),SOURCE_NAME),
            (2,Some(operation.applications),launcher::APPLICATIONS_NAME)] {
            let Some(parent)=parent else{continue;};
            match book.named(Some(parent),name) {
                Err(Errno::ENOENT)=>(),Err(_)=>return Err("launcher-recovery-placement"),Ok(_)=>{
                    let original=book.open(Some(parent),name,true)?;
                    require_enrolled(book,original,Some(phase.data.staged))?;
                    maintenance::audit_launcher_tree(book,original,&material.index())?;
                    held[at]=Some(original);
                },
            }
        }
        let facts=held.map(|row|row.map(|n|original_identity(book,n)).transpose()).into_iter().collect::<Result<Vec<_>>>()?;
        let location=fresh_placement_data(&phase.data,facts[0],facts[1],facts[2])?;
        let bundle=held.into_iter().flatten().next().ok_or("launcher-recovery-placement")?;
        operation.bundle=Some(bundle);
        phase.post(book)?;view.post(book)?;
        Ok(Some(Self{phase,operation,material,workspace,bundle,location,returned:Returned::NotAttempted,first:None,settled:false}))
    }
    pub(super) fn preserve(&mut self,book:&mut Install,view:&worker::ReinstallOldControlsObserved<'_>)->Result<()> {
        check(self.first.is_none() && !self.settled && self.returned==Returned::NotAttempted,"launcher-recovery-once")?;
        let result=(|| {
            // view.post proves the genuine current producer and SAME held R/M
            // originals. It does not masquerade as the worker's closed-R grant.
            view.post(book)?;self.phase.post(book)?;self.operation.parent_post(book)?;
            require_enrolled(book,self.bundle,Some(self.phase.data.staged))?;
            maintenance::audit_launcher_tree(book,self.bundle,&self.material.index())?;
            if self.location==FreshPlacement::Applications {
                book.absent(self.phase.stage,SOURCE_NAME)?;
                check(book.originals[self.bundle].parent==Some(self.operation.applications)
                    && book.originals[self.bundle].name==launcher::APPLICATIONS_NAME,"launcher-recovery-live-original")?;
                // The receipt already binds this still-original stage. No
                // recreated workspace or inferred replacement identity needed.
                check(container_identity(book,self.phase.stage)?==self.phase.data.stage,"launcher-recovery-stage-original")?;
                book.clock()?;self.returned=Returned::Attempting;
                match native::publish_directory(book.fd(self.operation.applications)?.as_fd(),launcher::APPLICATIONS_NAME,
                    book.fd(self.phase.stage)?.as_fd(),SOURCE_NAME) {
                    Ok(())=>self.returned=Returned::Withdrawn,
                    Err(error)=>{
                        self.returned=if error.raw_os_error()==Some(Errno::EEXIST as i32){Returned::Refused}
                            else{book.unknown=true;Returned::Unknown};return Err("launcher-recovery-withdrawal");
                    },
                }
                maintenance::rebind_renamed(book,self.bundle,self.phase.stage,SOURCE_NAME)?;
                self.location=FreshPlacement::Stage;
                book.persist(self.operation.applications,false)?;book.persist(self.phase.stage,false)?;
            }
            check(self.operation.absent(book)?,"launcher-recovery-foreign-live")?;
            require_enrolled(book,self.bundle,Some(self.phase.data.staged))?;
            maintenance::audit_launcher_tree(book,self.bundle,&self.material.index())?;
            self.phase.post(book)?;view.post(book)?;
            book.forward_close(self.bundle,"launcher-recovery-bundle-close")?;
            if let Some(workspace)=self.workspace {book.check_name(workspace,true)?;
                book.forward_close(workspace,"launcher-recovery-workspace-close")?;}
            self.phase.close(book)?;
            self.operation.parent_post(book)?;
            book.forward_close(self.operation.applications,"launcher-recovery-applications-close")?;
            book.forward_close(self.operation.system_root,"launcher-recovery-root-close")?;
            view.post(book)?;self.settled=true;Ok(())
        })();
        if let Err(error)=result {self.first.get_or_insert(error);}result
    }
}

// Read-only preservation contract. An unfinished writer can be preserved only
// as an exact prefix of the receipt this SOURCE would have written for the
// still-present staged original. It cannot authorize an Applications move.
pub(super) fn partial_phase_record(raw:&[u8],intent:&transaction::IntentData,
    stage:launcher::OriginalIdentityData,workspace:Option<launcher::OriginalIdentityData>,
    staged:Option<launcher::OriginalIdentityData>,recovered:Option<launcher::OriginalIdentityData>,
    sealed:bool)->Result<()> {
    check(intent.action_data()==mobile_release_desktop::macos_install_maintenance::ActionData::FreshInstall
        && intent.previous_data().is_none() && intent.previous_state_data().is_none()
        && raw.len()<=PHASE_LIMIT,"launcher-partial-phase-context")?;
    if let Ok(phase)=PublicationPhaseData::parse_raw(raw) {
        phase.check(intent,intent.invocation_data())?;
        check(phase.stage==stage && phase.previous.is_none()
            && workspace.is_none_or(|original|original==phase.workspace),"launcher-partial-phase-original")?;
        fresh_placement_data(&phase,staged,recovered,None)?;
        check(serde_json::to_vec(&phase).map_err(|_|"launcher-partial-phase-json")?==raw,
            "launcher-partial-phase-canonical")?;
        return Ok(());
    }
    check(!sealed && recovered.is_none(),"launcher-partial-phase-unfinished")?;
    let binding=intent.next_data().binding_data();
    let phase=PublicationPhaseData {schema_version:1,phase:"launcher-prepublication".into(),
        invocation:intent.invocation_data().into(),intent_sha256:intent.digest_data().into(),
        instance:intent.invocation_data().into(),inventory_sha256:binding.inventory_sha256.into(),
        source_commit:binding.source_commit.into(),runtime_manifest_sha256:binding.runtime_manifest_sha256.into(),
        stage,workspace:workspace.ok_or("launcher-partial-phase-workspace")?,
        staged:staged.ok_or("launcher-partial-phase-copy")?,previous:None};
    phase.check(intent,intent.invocation_data())?;
    let expected=serde_json::to_vec(&phase).map_err(|_|"launcher-partial-phase-json")?;
    check(expected.len()<=PHASE_LIMIT && expected.starts_with(raw),"launcher-partial-phase-prefix")
}
pub(super) fn preservation_identity(book:&Install,original:usize)->Result<launcher::OriginalIdentityData> {
    container_identity(book,original)
}

// A workspace belongs to the installed generation's original creation stage.
// The instance survives no-op and restore operations; no new root-level name
// or directory selected by scanning is introduced.
pub(super) struct Workspace {
    original: usize, stage: usize, instance: String,
    pub(super) retirement_attempted: bool, pub(super) retired: bool,
    pub(super) retirement_settled: bool,
}
impl Workspace {
    pub(super) fn create(book: &mut Install, prepared: &PreparedFresh,
        generation: &transaction::GenerationData) -> Result<Self> {
        Operation::mutation_ready(book)?;
        let root = book.gate.parent.ok_or("launcher-maintenance-required")?;
        let binding = generation.release_data().binding_data();
        check(root == prepared.destination && binding.release == paths::RELEASE
            && Some(binding.inventory_sha256) == option_env!("MRK_MACOS_INSTALL_INVENTORY_SHA256")
            && Some(binding.source_commit) == option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT")
            && Some(binding.runtime_manifest_sha256) == option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256")
            && format!("{:x}", Sha256::digest(&prepared.inventory_bytes)) == binding.inventory_sha256,
            "launcher-generation-binding")?;
        launcher::LauncherInventory::from_index(&prepared.inventory.index()?)?.ok_or("launcher-inventory-missing")?;
        let instance = generation.instance_data();
        check(worker::invocation_valid(instance), "launcher-generation-instance")?;
        let stage = book.open(Some(root), &format!(".install-{instance}"), true)?;
        book.protected(stage, true, Some(0o700))?;
        native::no_xattrs(book.fd(stage)?.as_fd()).map_err(|_| "launcher-stage-attributes")?;
        // Existing leftovers are a recovery case, never adopted or overwritten
        // by ordinary create. The full census must authorize a resume first.
        let original = book.directory(stage, WORK_NAME, true, 0o700)?;
        let out = Self { original, stage, instance: instance.to_owned(),
            retirement_attempted: false, retired: false, retirement_settled: false };
        out.post(book)?;
        Ok(out)
    }
    // Only an already authenticated generation/inventory selects this stage.
    // No directory scanning, previous filename, or persisted success bit grants
    // authority. The caller must retain its original completed-package/history
    // admission; this method adds exact filesystem correspondence to that input.
    pub(super) fn admit(book: &mut Install, generation: &transaction::GenerationData,
        inventory_bytes: &[u8]) -> Result<Option<Self>> {
        check(book.gate.verified, "launcher-maintenance-required")?;
        let root = book.gate.parent.ok_or("launcher-maintenance-required")?;
        let binding = generation.release_data().binding_data();
        check(format!("{:x}", Sha256::digest(inventory_bytes)) == binding.inventory_sha256,
            "launcher-generation-binding")?;
        let inventory = Inventory::parse_for_release(inventory_bytes, binding.runtime_manifest_sha256, binding.release)?;
        launcher::LauncherInventory::from_index(&inventory.index()?)?.ok_or("launcher-inventory-missing")?;
        let instance = generation.instance_data();
        check(worker::invocation_valid(instance), "launcher-generation-instance")?;
        let stage = book.open(Some(root), &format!(".install-{instance}"), true)?;
        book.protected(stage, true, Some(0o700))?;
        native::no_xattrs(book.fd(stage)?.as_fd()).map_err(|_| "launcher-stage-attributes")?;
        if let Err(Errno::ENOENT) = book.named(Some(stage), WORK_NAME) {
            book.check_name(stage, true)?;
            book.forward_close(stage, "launcher-stage-close")?;
            return Ok(None);
        }
        let original = book.open(Some(stage), WORK_NAME, true)?;
        let out = Self { original, stage, instance: instance.to_owned(),
            retirement_attempted: false, retired: false, retirement_settled: false };
        out.post(book)?;
        out.roster(book)?;
        Ok(Some(out))
    }

    fn roster(&self, book: &mut Install) -> Result<BTreeMap<String, u64>> {
        self.post(book)?;
        let before = Identity::of(&stat::fstat(book.fd(self.original)?).map_err(|_| "launcher-workspace-stat")?);
        let actual = maintenance::roster_now(book, self.original)?;
        check(actual.len() <= 2 && actual.keys().all(|name| name == SOURCE_NAME || name == RETAINED_NAME),
            "launcher-workspace-roster")?;
        self.post(book)?;
        check(Identity::of(&stat::fstat(book.fd(self.original)?).map_err(|_| "launcher-workspace-stat")?) == before,
            "launcher-workspace-changed")?;
        // This private directory is mutable by our recorded copy/move effects.
        // Its fresh, stable observation is not authority for any child bytes.
        book.originals[self.original].identity = Some(before);
        Ok(actual)
    }

    // Successful operations leave the old exact phase-directory census intact.
    // Only this held EMPTY workspace is removed. Preserve returned effects even
    // if a following check/close fails; there is no name-based cleanup retry.
    pub(super) fn retire_empty(&mut self, book: &mut Install) -> Result<()> {
        check(!self.retirement_attempted && !self.retired, "launcher-workspace-retirement-once")?;
        Operation::mutation_ready(book)?;
        check(self.roster(book)?.is_empty(), "launcher-workspace-not-empty")?;
        let before = stat::fstat(book.fd(self.stage)?).map_err(|_| "launcher-stage-stat")?;
        let mut remaining = maintenance::roster_now(book, self.stage)?;
        check(remaining.remove(WORK_NAME) == Some(book.identity(self.original)?.ino),
            "launcher-workspace-name")?;
        book.persist(self.original, false)?;
        book.check_name(self.original, true)?;
        let expected = book.identity(self.original)?;
        self.retirement_attempted = true;
        match unistd::unlinkat(book.fd(self.stage)?, WORK_NAME, unistd::UnlinkatFlags::RemoveDir) {
            Ok(()) => self.retired = true,
            Err(_) => { book.unknown = true; return Err("launcher-workspace-unlink-unknown"); }
        }
        book.clock()?;
        book.absent(self.stage, WORK_NAME)?;
        let actual = stat::fstat(book.fd(self.original)?).map_err(|_| "launcher-workspace-unlinked-stat")?;
        check(expected.same_object(Identity::of(&actual)) && expected.mode == u32::from(actual.st_mode)
            && actual.st_flags == 0, "launcher-workspace-unlinked-original")?;
        refresh_removed_parent(book, self.stage, before, &remaining)?;
        book.forward_close(self.original, "launcher-workspace-close")?;
        book.persist(self.stage, false)?;
        book.check_name(self.stage, true)?;
        book.forward_close(self.stage, "launcher-stage-close")?;
        self.retirement_settled = true;
        Ok(())
    }

    fn post(&self, book: &Install) -> Result<()> {
        check(!self.retirement_attempted && !self.retired, "launcher-workspace-retired")?;
        let root = book.gate.parent.ok_or("launcher-maintenance-required")?;
        check(book.originals[self.stage].parent == Some(root)
            && book.originals[self.stage].name == format!(".install-{}", self.instance)
            && book.originals[self.original].parent == Some(self.stage)
            && book.originals[self.original].name == WORK_NAME, "launcher-workspace-binding")?;
        book.check_name(root, false)?;
        book.protected(root, true, Some(0o755))?;
        for original in [self.stage, self.original] {
            book.check_name(original, false)?;
            book.protected(original, true, Some(0o700))?;
            check(stat::fstat(book.fd(original)?).map_err(|_| "launcher-workspace-stat")?.st_flags == 0,
                "launcher-workspace-flags")?;
            native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_| "launcher-workspace-attributes")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Returned { NotAttempted, Attempting, Refused, Published, Quarantined, Withdrawn, Restored, Unknown }

// Returned effects live in the caller's original book-owned operation. An
// error after rename does not erase the syscall effect or allow another try.
pub(super) struct Operation {
    applications: usize,
    system_root: usize,
    bundle: Option<usize>,
    pub(super) returned: Returned,
    pub(super) verified: bool,
}
impl Operation {
    pub(super) fn open(book: &mut Install) -> Result<Self> {
        book.clock()?;
        check(book.gate.verified && book.gate.parent.is_some(), "launcher-maintenance-required")?;
        let system_root = book.open(None, "/", true)?;
        book.protected_as(system_root, true, None, AclRole::SystemRoot)?;
        let applications = book.open(Some(system_root), "Applications", true)?;
        let out = Self { applications, system_root, bundle: None, returned: Returned::NotAttempted, verified: false };
        out.parent_post(book)?;
        Ok(out)
    }

    fn parent_post(&self, book: &Install) -> Result<()> {
        book.clock()?;
        book.check_name(self.system_root, false)?;
        book.protected_as(self.system_root, true, None, AclRole::SystemRoot)?;
        book.check_name(self.applications, false)?;
        let value = stat::fstat(book.fd(self.applications)?).map_err(|_| "launcher-parent-stat")?;
        // /Applications is an ordinary shared convenience namespace. Unlike
        // the runtime root it may be admin-group writable and have an Apple
        // ACL. Do not chmod it, pretend its roster authenticates a source, or
        // relax the existing protection policy for any protected payload.
        check(value.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFDIR.bits()
            && value.st_uid == 0 && value.st_mode & 0o002 == 0,
            "launcher-parent-policy")?;
        let fs = statfs::fstatfs(book.fd(self.applications)?).map_err(|_| "launcher-parent-mount")?;
        check(fs.filesystem_type_name() == "apfs" && fs.flags().contains(MntFlags::MNT_LOCAL)
            && !fs.flags().intersects(MntFlags::MNT_UNION | MntFlags::MNT_AUTOMOUNTED | MntFlags::MNT_IGNORE_OWNERSHIP),
            "launcher-parent-mount")?;
        book.clock()
    }

    fn mutation_ready(book: &Install) -> Result<()> {
        book.clock()?;
        check(book.gate.verified && (book.gate.exclusive_acquired
            || book.worker_stderr_is_gate && book.worker_go_eof
                && book.worker_deadline.is_some() && !book.gate.lock_attempted),
            "launcher-exclusive-maintenance-required")?;
        book.registration_ready()
    }

    pub(super) fn absent(&self, book: &Install) -> Result<bool> {
        self.parent_post(book)?;
        let result = match book.named(Some(self.applications), launcher::APPLICATIONS_NAME) {
            Err(Errno::ENOENT) => Ok(true),
            Ok(_) => Ok(false),
            Err(_) => Err("launcher-observation-refused"),
        };
        self.parent_post(book)?;
        result
    }

    /// Exact authenticated inventory only. Unknown or modified bundles refuse;
    /// no signature-only approximation or name-based replacement is allowed.
    pub(super) fn hold_matching(&mut self, book: &mut Install, expected: &InventoryIndex<'_>,
        enrolled:Option<launcher::OriginalIdentityData>) -> Result<()> {
        check(self.bundle.is_none() && self.returned == Returned::NotAttempted,
            "launcher-operation-once")?;
        launcher::LauncherInventory::from_index(expected)?.ok_or("launcher-inventory-missing")?;
        self.parent_post(book)?;
        let bundle = book.open(Some(self.applications), launcher::APPLICATIONS_NAME, true)?;
        // Store the exact original before any fallible read can return.
        self.bundle = Some(bundle);
        require_enrolled(book,bundle,enrolled)?;
        maintenance::audit_launcher_tree(book,bundle,expected)?;
        self.parent_post(book)?;
        book.check_name(bundle, true)
    }

    /// Copy from the completed package into a source-selected protected
    /// workspace. Never write a build/staging tree beneath /Applications.
    pub(super) fn stage(book: &mut Install, prepared: &PreparedFresh, workspace: &Workspace) -> Result<usize> {
        Self::mutation_ready(book)?;
        workspace.post(book)?;
        let indexed = prepared.inventory.index()?;
        launcher::LauncherInventory::from_index(&indexed)?.ok_or("launcher-inventory-missing")?;
        check(book.gate.parent == Some(prepared.destination), "launcher-source-destination")?;
        let mut current = prepared.input;
        let mut opened = Vec::with_capacity(3);
        for name in ["app", "Contents", "Helpers"] {
            let child = book.open(Some(current), name, true)?;
            opened.push(child);
            book.protected(child, true, Some(0o555))?;
            native::no_xattrs(book.fd(child)?.as_fd()).map_err(|_| "launcher-source-attributes")?;
            current = child;
        }
        book.absent(workspace.original, SOURCE_NAME)?;
        check(!book.launcher_writes.failed && book.launcher_writes.calls == 0, "launcher-copy-once")?;
        check(book.payload_written.checked_add(selected_copy_bytes(&indexed)?)
            .is_some_and(|n| n <= installation_record::PAYLOAD_LIMIT), "launcher-copy-budget")?;
        let bundle = book.copy_tree_with_role(launcher::BUNDLE, current, workspace.original,
            &indexed.files, &indexed.directories, 0, Role::LauncherWriter)?;
        for original in opened.into_iter().rev() {
            book.check_name(original, true)?;
            book.forward_close(original, "launcher-source-close")?;
        }
        book.check_name(prepared.input, true)?;
        workspace.post(book)?;
        Ok(bundle)
    }

    pub(super) fn publish(&mut self, book: &mut Install, workspace: &Workspace, staged: usize,
        expected: &InventoryIndex<'_>) -> Result<()> {
        check(self.returned == Returned::NotAttempted && self.bundle.is_none(), "launcher-operation-once")?;
        Self::mutation_ready(book)?;
        workspace.post(book)?;
        self.parent_post(book)?;
        check(book.originals[staged].parent == Some(workspace.original)
            && book.originals[staged].name == SOURCE_NAME, "launcher-staged-original")?;
        launcher::LauncherInventory::from_index(expected)?.ok_or("launcher-inventory-missing")?;
        maintenance::audit_launcher_tree(book,staged,expected)?;
        book.absent(self.applications, launcher::APPLICATIONS_NAME)?;
        check(book.identity(workspace.original)?.dev == book.identity(self.applications)?.dev, "launcher-filesystem")?;
        book.clock()?;
        // No overwrite-capable primitive, filesystem fallback or path retry.
        self.returned = Returned::Attempting;
        let result = native::publish_directory(book.fd(workspace.original)?.as_fd(), SOURCE_NAME,
            book.fd(self.applications)?.as_fd(), launcher::APPLICATIONS_NAME);
        match result {
            Ok(()) => self.returned = Returned::Published,
            Err(error) => {
                self.returned = if error.raw_os_error() == Some(Errno::EEXIST as i32) { Returned::Refused }
                    else { book.unknown = true; Returned::Unknown };
                return Err("launcher-publication-refused-or-unknown");
            }
        }
        self.bundle = Some(staged);
        maintenance::rebind_renamed(book, staged, self.applications, launcher::APPLICATIONS_NAME)?;
        book.absent(workspace.original, SOURCE_NAME)?;
        maintenance::audit_launcher_tree(book,staged,expected)?;
        book.persist(workspace.original, false)?;
        book.persist(self.applications, false)?;
        self.parent_post(book)?;
        book.check_name(staged, true)?;
        self.verified = true;
        Ok(())
    }

    /// Withdraw only the held matching bundle, retaining it under protection.
    /// A shared-parent race is rechecked AFTER the exclusive move. On mismatch
    /// retain the moved entry untouched: never delete it or overwrite a new
    /// Applications occupant in a guessed rollback.
    pub(super) fn quarantine(&mut self, book: &mut Install, workspace: &Workspace,
        expected: &InventoryIndex<'_>) -> Result<usize> {
        check(self.returned == Returned::NotAttempted, "launcher-operation-once")?;
        let bundle = self.bundle.ok_or("launcher-original-missing")?;
        Self::mutation_ready(book)?;
        workspace.post(book)?;
        self.parent_post(book)?;
        check(book.originals[bundle].parent == Some(self.applications)
            && book.originals[bundle].name == launcher::APPLICATIONS_NAME, "launcher-original-binding")?;
        maintenance::audit_launcher_tree(book,bundle,expected)?;
        book.check_name(bundle, true)?;
        book.absent(workspace.original, RETAINED_NAME)?;
        check(book.identity(workspace.original)?.dev == book.identity(self.applications)?.dev, "launcher-filesystem")?;
        book.clock()?;
        self.returned = Returned::Attempting;
        let result = native::publish_directory(book.fd(self.applications)?.as_fd(), launcher::APPLICATIONS_NAME,
            book.fd(workspace.original)?.as_fd(), RETAINED_NAME);
        match result {
            Ok(()) => self.returned = Returned::Quarantined,
            Err(error) => {
                self.returned = if error.raw_os_error() == Some(Errno::EEXIST as i32) { Returned::Refused }
                    else { book.unknown = true; Returned::Unknown };
                return Err("launcher-withdrawal-refused-or-unknown");
            }
        }
        maintenance::rebind_renamed(book, bundle, workspace.original, RETAINED_NAME)?;
        maintenance::audit_launcher_tree(book,bundle,expected)?;
        // If another user placed an entry after the move, absence refuses and
        // the caller cannot publish over it. Our retained bundle stays intact.
        book.absent(self.applications, launcher::APPLICATIONS_NAME)?;
        book.persist(self.applications, false)?;
        book.persist(workspace.original, false)?;
        self.parent_post(book)?;
        self.verified = true;
        Ok(bundle)
    }
}

// One pre-state inverse using the exact original quarantine, not a new copy.
// It never retries a rename or treats restored convenience UI as core recovery.
// The enclosing maintenance failure remains first even if this inverse works.
pub(super) struct Inverse {
    entered: bool,
    pub(super) withdrawn: Returned,
    pub(super) restored: Returned,
    pub(super) first_failure: Option<&'static str>,
    pub(super) verified: bool,
}
impl Inverse {
    pub(super) fn new() -> Self {
        Self { entered:false,withdrawn:Returned::NotAttempted,restored:Returned::NotAttempted,
            first_failure:None,verified:false }
    }
    pub(super) fn restore(&mut self, book: &mut Install, workspace: &Workspace,
        previous: &Operation, previous_inventory: &InventoryIndex<'_>,
        next: Option<(&Operation, &InventoryIndex<'_>)>) -> Result<()> {
        check(!self.entered, "launcher-inverse-once")?;
        self.entered = true;
        let result = self.restore_inner(book, workspace, previous, previous_inventory, next);
        if let Err(error) = result { self.first_failure = Some(error); }
        result
    }
    // Update may begin with an honestly missing prior launcher. Inverse must
    // restore that absence, not leave a newly published convenience bundle.
    pub(super) fn restore_absence(&mut self, book: &mut Install, workspace: &Workspace,
        published: &Operation, expected: &InventoryIndex<'_>) -> Result<()> {
        check(!self.entered,"launcher-inverse-once")?;
        self.entered = true;
        let result = (|| {
            Operation::mutation_ready(book)?;
            check(!book.unknown && book.maintenance.as_ref().is_some_and(|e|
                e.action == mobile_release_desktop::macos_install_maintenance::ActionData::Update
                && !e.state_published),"launcher-inverse-before-state")?;
            workspace.post(book)?;
            published.parent_post(book)?;
            check(published.returned == Returned::Published && published.verified,"launcher-inverse-publication")?;
            let new = published.bundle.ok_or("launcher-original-missing")?;
            check(book.originals[new].parent == Some(published.applications)
                && book.originals[new].name == launcher::APPLICATIONS_NAME,"launcher-inverse-new-original")?;
            launcher::LauncherInventory::from_index(expected)?.ok_or("launcher-inventory-missing")?;
            maintenance::audit_launcher_tree(book,new,expected)?;
            book.check_name(new,true)?;
            book.absent(workspace.original,SOURCE_NAME)?;
            check(book.identity(workspace.original)?.dev == book.identity(published.applications)?.dev,
                "launcher-filesystem")?;
            book.clock()?;
            self.withdrawn = Returned::Attempting;
            match native::publish_directory(book.fd(published.applications)?.as_fd(),launcher::APPLICATIONS_NAME,
                book.fd(workspace.original)?.as_fd(),SOURCE_NAME) {
                Ok(()) => self.withdrawn = Returned::Withdrawn,
                Err(error) => {
                    self.withdrawn = if error.raw_os_error() == Some(Errno::EEXIST as i32) {Returned::Refused}
                        else {book.unknown = true;Returned::Unknown};
                    return Err("launcher-inverse-withdrawal-refused-or-unknown");
                },
            }
            maintenance::rebind_renamed(book,new,workspace.original,SOURCE_NAME)?;
            maintenance::audit_launcher_tree(book,new,expected)?;
            book.check_name(new,true)?;
            book.absent(published.applications,launcher::APPLICATIONS_NAME)?;
            book.persist(published.applications,false)?;
            book.persist(workspace.original,false)?;
            published.parent_post(book)?;
            self.verified = true;
            Ok(())
        })();
        if let Err(error) = result { self.first_failure = Some(error); }
        result
    }
    fn restore_inner(&mut self, book: &mut Install, workspace: &Workspace,
        previous: &Operation, previous_inventory: &InventoryIndex<'_>,
        next: Option<(&Operation, &InventoryIndex<'_>)>) -> Result<()> {
        Operation::mutation_ready(book)?;
        check(!book.unknown && book.maintenance.as_ref().is_some_and(|effects|
            effects.action == mobile_release_desktop::macos_install_maintenance::ActionData::Update
            && !effects.state_published), "launcher-inverse-before-state")?;
        workspace.post(book)?;
        previous.parent_post(book)?;
        check(previous.returned == Returned::Quarantined && previous.verified,
            "launcher-inverse-quarantine")?;
        let old = previous.bundle.ok_or("launcher-original-missing")?;
        check(book.originals[old].parent == Some(workspace.original)
            && book.originals[old].name == RETAINED_NAME, "launcher-inverse-original")?;
        launcher::LauncherInventory::from_index(previous_inventory)?.ok_or("launcher-inventory-missing")?;
        maintenance::audit_launcher_tree(book,old,previous_inventory)?;
        book.check_name(old, true)?;
        if let Some((published, expected)) = next {
            published.parent_post(book)?;
            check(published.returned == Returned::Published && published.verified
                && book.identity(published.applications)?.same_object(book.identity(previous.applications)?),
                "launcher-inverse-publication")?;
            let new = published.bundle.ok_or("launcher-original-missing")?;
            check(book.originals[new].parent == Some(published.applications)
                && book.originals[new].name == launcher::APPLICATIONS_NAME, "launcher-inverse-new-original")?;
            launcher::LauncherInventory::from_index(expected)?.ok_or("launcher-inventory-missing")?;
            maintenance::audit_launcher_tree(book,new,expected)?;
            book.check_name(new, true)?;
            book.absent(workspace.original, SOURCE_NAME)?;
            check(book.identity(workspace.original)?.dev == book.identity(published.applications)?.dev,
                "launcher-filesystem")?;
            book.clock()?;
            self.withdrawn = Returned::Attempting;
            match native::publish_directory(book.fd(published.applications)?.as_fd(), launcher::APPLICATIONS_NAME,
                book.fd(workspace.original)?.as_fd(), SOURCE_NAME) {
                Ok(()) => self.withdrawn = Returned::Withdrawn,
                Err(error) => {
                    self.withdrawn = if error.raw_os_error() == Some(Errno::EEXIST as i32) { Returned::Refused }
                        else { book.unknown = true; Returned::Unknown };
                    return Err("launcher-inverse-withdrawal-refused-or-unknown");
                },
            }
            maintenance::rebind_renamed(book, new, workspace.original, SOURCE_NAME)?;
            // A shared-parent substitution is retained, never deleted as ours.
            maintenance::audit_launcher_tree(book,new,expected)?;
            book.check_name(new, true)?;
            book.absent(published.applications, launcher::APPLICATIONS_NAME)?;
            book.persist(published.applications, false)?;
            book.persist(workspace.original, false)?;
            published.parent_post(book)?;
        }
        // In particular do not overwrite another user's entry placed between
        // withdrawal and restoration. Both proven originals remain retained.
        previous.parent_post(book)?;
        workspace.post(book)?;
        book.absent(previous.applications, launcher::APPLICATIONS_NAME)?;
        maintenance::audit_launcher_tree(book,old,previous_inventory)?;
        book.check_name(old, true)?;
        check(book.identity(workspace.original)?.dev == book.identity(previous.applications)?.dev,
            "launcher-filesystem")?;
        book.clock()?;
        self.restored = Returned::Attempting;
        match native::publish_directory(book.fd(workspace.original)?.as_fd(), RETAINED_NAME,
            book.fd(previous.applications)?.as_fd(), launcher::APPLICATIONS_NAME) {
            Ok(()) => self.restored = Returned::Restored,
            Err(error) => {
                self.restored = if error.raw_os_error() == Some(Errno::EEXIST as i32) { Returned::Refused }
                    else { book.unknown = true; Returned::Unknown };
                return Err("launcher-inverse-restoration-refused-or-unknown");
            },
        }
        maintenance::rebind_renamed(book, old, previous.applications, launcher::APPLICATIONS_NAME)?;
        book.absent(workspace.original, RETAINED_NAME)?;
        maintenance::audit_launcher_tree(book,old,previous_inventory)?;
        book.persist(workspace.original, false)?;
        book.persist(previous.applications, false)?;
        previous.parent_post(book)?;
        book.check_name(old, true)?;
        self.verified = true;
        Ok(())
    }
}

// At most five signed leaves and five directories, never a general recursive
// deletion API. Each original is retained before an unlink can be entered.
struct RetiredNode {
    original: usize, parent: usize, name: String, directory: bool,
    size: u64, digest: String, attempted: bool, removed: bool,
}
pub(super) struct Retirement {
    nodes: Vec<RetiredNode>, prepared: bool, entered: bool, root_name: &'static str,
    pub(super) first_failure: Option<&'static str>,
    pub(super) completed: bool,
}
impl Retirement {
    pub(super) fn new() -> Self {
        Self { nodes: Vec::with_capacity(10), prepared: false, entered: false, root_name: RETAINED_NAME,
            first_failure: None, completed: false }
    }

    // The caller stores `self` before calling prepare, so failure never loses
    // the exact attempted operation. Only a verified quarantined bundle enters.
    pub(super) fn prepare(&mut self, book: &mut Install, operation: &Operation,
        workspace: &Workspace, expected: &InventoryIndex<'_>) -> Result<()> {
        check(!self.entered && !self.prepared && self.nodes.is_empty(), "launcher-retirement-once")?;
        self.entered = true;
        let result = self.prepare_inner(book, operation, workspace, expected);
        if let Err(error) = result { self.first_failure = Some(error); }
        result
    }
    fn prepare_inner(&mut self, book: &mut Install, operation: &Operation,
        workspace: &Workspace, expected: &InventoryIndex<'_>) -> Result<()> {
        Operation::mutation_ready(book)?;
        workspace.post(book)?;
        check(operation.returned == Returned::Quarantined && operation.verified,
            "launcher-retirement-quarantine")?;
        let bundle = operation.bundle.ok_or("launcher-original-missing")?;
        check(book.originals[bundle].parent == Some(workspace.original)
            && book.originals[bundle].name == RETAINED_NAME, "launcher-retirement-original")?;
        let selected = launcher::LauncherInventory::from_index(expected)?.ok_or("launcher-inventory-missing")?;
        // Ten held originals + bounded fresh roster readers; no new quota or
        // credit for a merely planned future close is introduced.
        let external = book.removal_live_reserved + if book.worker_deadline.is_some() { worker::EXTRA_LIVE } else { 0 };
        check(book.originals.iter().filter(|r| r.fd.is_some()).count() + external + 12 <= 96
            && book.originals.len().checked_add(60).is_some_and(|n| n <= installation_record::ORIGINAL_LIMIT), "launcher-retirement-budget")?;
        maintenance::audit_launcher_tree(book,bundle,expected)?;
        let mut directories = BTreeMap::new();
        directories.insert(String::new(), bundle);
        self.nodes.push(RetiredNode { original: bundle, parent: workspace.original,
            name: RETAINED_NAME.into(), directory: true, size: 0, digest: String::new(), attempted: false, removed: false });
        for path in ["Contents", "Contents/MacOS", "Contents/Resources", "Contents/_CodeSignature"] {
            let (parent_path, name) = path.rsplit_once('/').unwrap_or(("", path));
            let parent = *directories.get(parent_path).ok_or("launcher-retirement-parent")?;
            let original = book.open(Some(parent), name, true)?;
            self.nodes.push(RetiredNode { original, parent, name: name.into(), directory: true,
                size: 0, digest: String::new(), attempted: false, removed: false });
            book.protected(original, true, Some(0o555))?;
            native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_| "launcher-retirement-attributes")?;
            directories.insert(path.into(), original);
        }
        for entry in selected.entries().iter().copied().chain(selected.ticket()) {
            let relative = entry.path.strip_prefix(launcher::BUNDLE).and_then(|p| p.strip_prefix('/'))
                .ok_or("launcher-retirement-file")?;
            let (parent_path, name) = relative.rsplit_once('/').ok_or("launcher-retirement-file")?;
            let parent = *directories.get(parent_path).ok_or("launcher-retirement-parent")?;
            let original = book.open(Some(parent), name, false)?;
            self.nodes.push(RetiredNode { original, parent, name: name.into(), directory: false,
                size: entry.size, digest: entry.sha256.clone(), attempted: false, removed: false });
            book.protected(original, false, Some(if entry.executable { 0o555 } else { 0o444 }))?;
            native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_| "launcher-retirement-attributes")?;
        }
        check(self.nodes.len() <= 10, "launcher-retirement-bound")?;
        workspace.post(book)?;
        self.prepared = true;
        Ok(())
    }

    // Resume an interrupted retirement from a protected generation workspace.
    // Only absent subsets of the EXACT authenticated signed bundle are allowed:
    // surviving files still require full original bytes/hash and sealed mode.
    // Caller stores this ledger first and independently selects the authorized
    // current/predecessor inventory; no persisted success claim is imported.
    pub(super) fn prepare_resumed(&mut self, book: &mut Install, workspace: &Workspace,
        expected: &InventoryIndex<'_>) -> Result<()> {
        check(!self.entered && !self.prepared && self.nodes.is_empty(), "launcher-retirement-once")?;
        self.entered = true;
        let result = Operation::mutation_ready(book).and_then(|()|
            self.capture_remaining(book, workspace, expected, None, None));
        if let Err(error) = result { self.first_failure = Some(error); }
        result
    }

    // Remove only an interrupted copy of the authenticated NEW source. A 0600
    // unsealed file must be an exact bounded prefix of the original signed file;
    // sealed survivors must be complete. Nothing is accepted just for its name.
    pub(super) fn prepare_staged_copy(&mut self, book: &mut Install, workspace: &Workspace,
        prepared: &PreparedFresh) -> Result<()> {
        check(!self.entered && !self.prepared && self.nodes.is_empty(), "launcher-retirement-once")?;
        self.entered = true;
        self.root_name = SOURCE_NAME;
        let result = (|| {
            Operation::mutation_ready(book)?;
            check(book.gate.parent == Some(prepared.destination), "launcher-source-destination")?;
            let index = prepared.inventory.index()?;
            launcher::LauncherInventory::from_index(&index)?.ok_or("launcher-inventory-missing")?;
            let mut source = prepared.input;
            let mut opened = Vec::with_capacity(4);
            for name in ["app", "Contents", "Helpers", SOURCE_NAME] {
                let next = book.open(Some(source), name, true)?;
                opened.push(next);
                book.protected(next, true, Some(0o555))?;
                native::no_xattrs(book.fd(next)?.as_fd()).map_err(|_| "launcher-source-attributes")?;
                source = next;
            }
            self.capture_remaining(book, workspace, &index, Some(source), None)?;
            for original in opened.into_iter().rev() {
                book.check_name(original, true)?;
                book.forward_close(original, "launcher-source-close")?;
            }
            book.check_name(prepared.input, true)
        })();
        // Do not leave prepared=true if source POST or original close refused.
        if let Err(error) = result { self.prepared = false; self.first_failure = Some(error); }
        result
    }

    // Inspection is read-only. Running the retained ledger still requires the
    // actual original exclusive maintenance and registration ownership.
    fn inspect_resumed(&mut self, book: &mut Install, workspace: &Workspace,
        expected: &InventoryIndex<'_>,enrolled:Option<launcher::OriginalIdentityData>) -> Result<()> {
        check(!self.entered && !self.prepared && self.nodes.is_empty(),"launcher-retirement-once")?;
        self.entered = true;
        let result = self.capture_remaining(book,workspace,expected,None,Some(enrolled));
        if let Err(error) = result {self.first_failure = Some(error);}
        result
    }
    fn capture_remaining(&mut self, book: &mut Install, workspace: &Workspace,
        expected: &InventoryIndex<'_>, source: Option<usize>,
        enrolled:Option<Option<launcher::OriginalIdentityData>>) -> Result<()> {
        check(book.gate.verified,"launcher-maintenance-required")?;
        let selected = launcher::LauncherInventory::from_index(expected)?.ok_or("launcher-inventory-missing")?;
        let top = workspace.roster(book)?;
        // A simultaneous staged new bundle requires publication/recovery
        // selection first; do not erase a retained predecessor preemptively.
        let other_name = if source.is_some() { RETAINED_NAME } else { SOURCE_NAME };
        check(!top.contains_key(other_name), "launcher-recovery-other-bundle-present")?;
        let Some(inode) = top.get(self.root_name).copied() else {
            self.prepared = true;
            return Ok(());
        };
        let external = book.removal_live_reserved + if book.worker_deadline.is_some() { worker::EXTRA_LIVE } else { 0 };
        check(book.originals.iter().filter(|r| r.fd.is_some()).count() + external + 16 <= 96
            && book.originals.len().checked_add(100).is_some_and(|n| n <= installation_record::ORIGINAL_LIMIT), "launcher-retirement-budget")?;
        let children = signed_children(&selected)?;
        let bundle = book.open(Some(workspace.original), self.root_name, true)?;
        self.nodes.push(RetiredNode { original: bundle, parent: workspace.original, name: self.root_name.into(),
            directory: true, size: 0, digest: String::new(), attempted: false, removed: false });
        check(book.identity(bundle)?.ino == inode, "launcher-recovery-original")?;
        if let Some(enrolled)=enrolled {require_enrolled(book,bundle,enrolled)?;}
        let mut directories = BTreeMap::new();
        directories.insert(String::new(), bundle);
        let mut rosters = BTreeMap::new();
        for path in ["", "Contents", "Contents/MacOS", "Contents/Resources", "Contents/_CodeSignature"] {
            let directory = if path.is_empty() { bundle } else {
                let (parent_path, name) = path.rsplit_once('/').unwrap_or(("", path));
                let Some(parent) = directories.get(parent_path).copied() else { continue; };
                let roster: &BTreeMap<String, u64> = rosters.get(parent_path).ok_or("launcher-recovery-parent")?;
                let Some(inode) = roster.get(name).copied() else { continue; };
                let original = book.open(Some(parent), name, true)?;
                self.nodes.push(RetiredNode { original, parent, name: name.into(), directory: true,
                    size: 0, digest: String::new(), attempted: false, removed: false });
                check(book.identity(original)?.ino == inode, "launcher-recovery-original")?;
                directories.insert(path.to_owned(), original);
                original
            };
            let mode = book.identity(directory)?.mode & 0o7777;
            check(mode == 0o555 || source.is_some() && mode == 0o700, "launcher-recovery-directory-mode")?;
            book.protected(directory, true, Some(mode))?;
            native::no_xattrs(book.fd(directory)?.as_fd()).map_err(|_| "launcher-retirement-attributes")?;
            check(stat::fstat(book.fd(directory)?).map_err(|_| "launcher-recovery-stat")?.st_flags == 0,
                "launcher-recovery-flags")?;
            let actual = maintenance::roster_now(book, directory)?;
            check(actual.keys().all(|name| children.get(path).is_some_and(|names| names.contains(name))),
                "launcher-recovery-unknown-child")?;
            rosters.insert(path.to_owned(), actual);
        }
        for entry in selected.entries().iter().copied().chain(selected.ticket()) {
            let relative = entry.path.strip_prefix(launcher::BUNDLE).and_then(|p| p.strip_prefix('/'))
                .ok_or("launcher-retirement-file")?;
            let (parent_path, name) = relative.rsplit_once('/').ok_or("launcher-retirement-file")?;
            let Some(parent) = directories.get(parent_path).copied() else { continue; };
            let Some(inode) = rosters.get(parent_path).and_then(|row| row.get(name)).copied() else { continue; };
            let original = book.open(Some(parent), name, false)?;
            self.nodes.push(RetiredNode { original, parent, name: name.into(), directory: false,
                size: entry.size, digest: entry.sha256.clone(), attempted: false, removed: false });
            check(book.identity(original)?.ino == inode, "launcher-recovery-original")?;
            let actual = book.identity(original)?;
            let mode = actual.mode & 0o7777;
            let partial = source.is_some() && mode == 0o600;
            check(partial || mode == if entry.executable { 0o555 } else { 0o444 }, "launcher-recovery-file-mode")?;
            check(actual.size >= 0 && actual.size as u64 <= entry.size
                && (partial || actual.size as u64 == entry.size), "launcher-recovery-file-size")?;
            book.protected(original, false, Some(mode))?;
            native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_| "launcher-retirement-attributes")?;
            check(stat::fstat(book.fd(original)?).map_err(|_| "launcher-recovery-stat")?.st_flags == 0,
                "launcher-recovery-flags")?;
            let digest = if let Some(source) = source {
                source_prefix(book, source, relative, original, actual.size as u64, entry)?
            } else {
                let digest = hash_at(book, original, entry.size)?;
                check(digest == entry.sha256, "launcher-recovery-file-hash")?;
                digest
            };
            let node = self.nodes.last_mut().ok_or("launcher-recovery-node")?;
            node.size = actual.size as u64;
            node.digest = digest;
        }
        // Exact first/second snapshots and retained originals, not a caller's
        // reconstructed namespace. Pread above leaves every file at offset zero
        // so run() genuinely rechecks its bytes immediately before unlink.
        for (path, directory) in &directories {
            check(maintenance::roster_now(book, *directory)? == rosters[path], "launcher-recovery-roster-changed")?;
            book.check_name(*directory, true)?;
        }
        for node in &self.nodes { book.check_name(node.original, true)?; }
        check(self.nodes.len() <= 10 && workspace.roster(book)? == top, "launcher-recovery-roster-changed")?;
        self.prepared = true;
        Ok(())
    }

    pub(super) fn run(&mut self, book: &mut Install, workspace: &Workspace) -> Result<()> {
        check(self.prepared && self.first_failure.is_none() && !self.completed,
            "launcher-retirement-not-ready")?;
        let result = (|| {
            // Leaves were appended after directories. Reverse order deletes
            // every leaf, then deepest known directories, then the bundle root.
            for slot in (0..self.nodes.len()).rev() { self.unlink(book, workspace, slot)?; }
            check(self.nodes.iter().all(|node| node.removed && node.attempted
                && book.originals[node.original].state == State::Closed
                && book.originals[node.original].fd.is_none()), "launcher-retirement-finality")?;
            book.absent(workspace.original, self.root_name)?;
            workspace.post(book)?;
            book.persist(workspace.original, false)?;
            book.clock()?;
            self.completed = true;
            Ok(())
        })();
        if let Err(error) = result { self.first_failure = Some(error); }
        result
    }

    fn unlink(&mut self, book: &mut Install, workspace: &Workspace, slot: usize) -> Result<()> {
        Operation::mutation_ready(book)?;
        workspace.post(book)?;
        let node = &self.nodes[slot];
        check(!node.attempted && !node.removed, "launcher-retirement-node-once")?;
        let (original, parent, name, directory) = (node.original, node.parent, node.name.clone(), node.directory);
        check(book.originals[original].parent == Some(parent) && book.originals[original].name == name,
            "launcher-retirement-node-original")?;
        book.check_name(original, true)?;
        let before = stat::fstat(book.fd(parent)?).map_err(|_| "launcher-retirement-parent-stat")?;
        let mut remaining = maintenance::roster_now(book, parent)?;
        check(remaining.remove(&name) == Some(book.identity(original)?.ino), "launcher-retirement-name")?;
        if directory {
            check(self.nodes.iter().filter(|child| child.parent == original).all(|child| child.removed),
                "launcher-retirement-children")?;
            check(maintenance::roster_now(book, original)?.is_empty(), "launcher-retirement-not-empty")?;
            book.persist(original, false)?;
        } else {
            check(book.read(original, node.size, false)?.0 == node.digest, "launcher-retirement-file-hash")?;
        }
        let expected = book.identity(original)?;
        check(stat::fstat(book.fd(original)?).map_err(|_| "launcher-retirement-node-stat")?.st_flags == 0
            && before.st_flags == 0, "launcher-retirement-node-flags")?;
        native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_| "launcher-retirement-attributes")?;
        book.check_name(original, true)?;
        book.clock()?;
        self.nodes[slot].attempted = true;
        let result = unistd::unlinkat(book.fd(parent)?, name.as_str(),
            if directory { unistd::UnlinkatFlags::RemoveDir } else { unistd::UnlinkatFlags::NoRemoveDir });
        match result {
            Ok(()) => self.nodes[slot].removed = true,
            Err(_) => { book.unknown = true; return Err("launcher-retirement-unlink-unknown"); }
        }
        book.clock()?;
        book.absent(parent, &name)?;
        let actual = stat::fstat(book.fd(original)?).map_err(|_| "launcher-retirement-unlinked-stat")?;
        check(expected.dev == i64::from(actual.st_dev) && expected.ino == actual.st_ino
            && expected.mode == u32::from(actual.st_mode) && expected.uid == actual.st_uid
            && expected.gid == actual.st_gid && actual.st_flags == 0, "launcher-retirement-unlinked-original")?;
        refresh_removed_parent(book, parent, before, &remaining)?;
        book.forward_close(original, "launcher-retirement-close")?;
        book.persist(parent, false)?;
        workspace.post(book)
    }
}

// Shared by bundle-leaf and empty-workspace retirement. Only the exact parent
// of an actually successful single-name unlink may refresh its original aliases.
fn refresh_removed_parent(book: &mut Install, parent: usize, before: FileStat,
    remaining: &BTreeMap<String, u64>) -> Result<()> {
        let changed = stat::fstat(book.fd(parent)?).map_err(|_| "launcher-retirement-parent-stat")?;
        let named = book.named(book.originals[parent].parent, &book.originals[parent].name)
            .map_err(|_| "launcher-retirement-parent-name")?;
        check(worker::removal_payload_parent_change_data(Identity::of(&before), before.st_flags,
            Identity::of(&changed), changed.st_flags, Identity::of(&named), named.st_flags),
            "launcher-retirement-parent-changed")?;
        check(maintenance::roster_now(book, parent)? == *remaining, "launcher-retirement-remaining-roster")?;
        // Refresh only aliases of this exact parent after its independently
        // checked own single-name removal. Other original baselines stay exact.
        for index in 0..book.originals.len() {
            if book.originals[index].fd.is_none() { continue; }
            let identity = book.identity(index)?;
            if identity.dev == i64::from(before.st_dev) && identity.ino == before.st_ino {
                let held = stat::fstat(book.fd(index)?).map_err(|_| "launcher-retirement-parent-stat")?;
                let alias_name = book.named(book.originals[index].parent, &book.originals[index].name)
                    .map_err(|_| "launcher-retirement-alias-name")?;
                check(worker::removal_payload_parent_change_data(identity, 0, Identity::of(&held), held.st_flags,
                    Identity::of(&alias_name), alias_name.st_flags)
                    && Identity::of(&held) == Identity::of(&changed), "launcher-retirement-alias")?;
                book.originals[index].identity = Some(Identity::of(&changed));
            }
        }
    Ok(())
}

// A fixed signed layout, not a generic filesystem deletion grammar. Optional
// stapled ticket is nominated by the same authenticated inventory as the four
// mandatory leaves; unknown additions never become removable.
fn signed_children(selected: &launcher::LauncherInventory<'_>) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut children: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for path in ["", "Contents", "Contents/MacOS", "Contents/Resources", "Contents/_CodeSignature"] {
        children.entry(path.into()).or_default();
        if !path.is_empty() {
            let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
            children.entry(parent.into()).or_default().insert(name.into());
        }
    }
    for entry in selected.entries().iter().copied().chain(selected.ticket()) {
        let relative = entry.path.strip_prefix(launcher::BUNDLE).and_then(|p| p.strip_prefix('/'))
            .ok_or("launcher-retirement-file")?;
        let (parent, name) = relative.rsplit_once('/').ok_or("launcher-retirement-file")?;
        check(children.get_mut(parent).ok_or("launcher-retirement-parent")?.insert(name.into()),
            "launcher-retirement-duplicate")?;
    }
    Ok(children)
}

fn hash_at(book: &Install, original: usize, size: u64) -> Result<String> {
    check(size <= launcher::LIMITS[0] && book.identity(original)?.size >= 0
        && book.identity(original)?.size as u64 == size, "launcher-recovery-size")?;
    book.check_name(original, true)?;
    let mut buffer = [0u8; 65536];
    let mut digest = Sha256::new();
    let mut offset = 0u64;
    while offset < size {
        book.clock()?;
        let take = usize::try_from((size-offset).min(buffer.len() as u64)).map_err(|_| "launcher-recovery-size")?;
        let count = nix::sys::uio::pread(book.fd(original)?, &mut buffer[..take], offset as i64)
            .map_err(|_| "launcher-recovery-read")?;
        check(count > 0 && count <= take, "launcher-recovery-read")?;
        offset += count as u64;
        digest.update(&buffer[..count]);
    }
    book.clock()?;
    check(nix::sys::uio::pread(book.fd(original)?, &mut buffer[..1], offset as i64)
        .map_err(|_| "launcher-recovery-read")? == 0, "launcher-recovery-eof")?;
    book.check_name(original, true)?;
    Ok(format!("{:x}", digest.finalize()))
}

// Full source hash precedes byte-prefix comparison. Positional reads retain
// original offsets and identity; cleanup never relies on a hash of an unknown
// partial file or treats zero-length/unsealed data as a complete signed asset.
fn source_prefix(book: &mut Install, source_root: usize, relative: &str,
    target: usize, size: u64, entry: &Entry) -> Result<String> {
    let parts: Vec<&str> = relative.split('/').collect();
    check((2..=3).contains(&parts.len()) && size <= entry.size, "launcher-source-prefix-path")?;
    let mut opened = Vec::with_capacity(3);
    let mut parent = source_root;
    for part in &parts[..parts.len()-1] {
        let next = book.open(Some(parent), part, true)?;
        opened.push(next);
        book.protected(next, true, Some(0o555))?;
        native::no_xattrs(book.fd(next)?.as_fd()).map_err(|_| "launcher-source-attributes")?;
        parent = next;
    }
    let source = book.open(Some(parent), parts[parts.len()-1], false)?;
    opened.push(source);
    book.protected(source, false, Some(if entry.executable { 0o555 } else { 0o444 }))?;
    native::no_xattrs(book.fd(source)?.as_fd()).map_err(|_| "launcher-source-attributes")?;
    check(hash_at(book, source, entry.size)? == entry.sha256, "launcher-source-file-hash")?;
    let digest = prefix_hash(size,
        |at, buffer| nix::sys::uio::pread(book.fd(source)?, buffer, at as i64).map_err(|_| "launcher-prefix-read"),
        |at, buffer| nix::sys::uio::pread(book.fd(target)?, buffer, at as i64).map_err(|_| "launcher-prefix-read"),
        || book.clock())?;
    book.check_name(target, true)?;
    for original in opened.into_iter().rev() {
        book.check_name(original, true)?;
        book.forward_close(original, "launcher-source-close")?;
    }
    book.check_name(source_root, true)?;
    Ok(digest)
}

// Shared actual byte-comparison loop; reader ports make short/error/late reads
// testable without privileged filesystem actions or a second deletion engine.
fn prefix_hash(size: u64,
    mut read_source: impl FnMut(u64, &mut [u8]) -> Result<usize>,
    mut read_target: impl FnMut(u64, &mut [u8]) -> Result<usize>,
    mut tick: impl FnMut() -> Result<()>) -> Result<String> {
    check(size <= launcher::LIMITS[0], "launcher-prefix-size")?;
    let mut source_buffer = [0u8; 65536];
    let mut target_buffer = [0u8; 65536];
    let mut offset = 0u64;
    let mut digest = Sha256::new();
    while offset < size {
        tick()?;
        let take = usize::try_from((size-offset).min(source_buffer.len() as u64)).map_err(|_| "launcher-prefix-size")?;
        // Short reads are allowed only with equal positive progress. Both
        // regular-file originals are bounded and checked again below.
        let target_count = read_target(offset, &mut target_buffer[..take])?;
        check(target_count > 0 && target_count <= take, "launcher-prefix-read")?;
        let mut source_count = 0usize;
        while source_count < target_count {
            tick()?;
            let count = read_source(offset + source_count as u64, &mut source_buffer[source_count..target_count])?;
            check(count > 0 && count <= target_count-source_count, "launcher-prefix-read")?;
            source_count += count;
        }
        check(source_buffer[..target_count] == target_buffer[..target_count], "launcher-prefix-mismatch")?;
        digest.update(&target_buffer[..target_count]);
        offset += target_count as u64;
    }
    tick()?;
    check(read_target(offset, &mut target_buffer[..1])? == 0, "launcher-prefix-eof")?;
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launcher_phase_is_closed_and_original_placement_never_accepts_identical_replacements() {
        let records=installation_record::ORIGINAL_LIMIT-PHASE_ORIGINAL_QUOTE as usize;
        let live=96-PHASE_LIVE_QUOTE as usize;
        assert!(phase_admission_data(records,live).is_ok());
        assert!(phase_admission_data(records+1,live).is_err());
        assert!(phase_admission_data(records,live+1).is_err());
        assert!(phase_admission_data(usize::MAX,live).is_err());
        assert!(phase_admission_data(records,usize::MAX).is_err());
        assert!(PHASE_CONTROL_QUOTE>=16*PHASE_LIMIT as u64);

        let identity=|inode|launcher::OriginalIdentityData {device:1,inode,birth_seconds:17,birth_nanoseconds:3, volume_uuid: None };
        let phase=PublicationPhaseData {schema_version:1,phase:"launcher-prepublication".into(),
            invocation:"1".repeat(32),intent_sha256:"2".repeat(64),instance:"3".repeat(32),
            inventory_sha256:"4".repeat(64),source_commit:"5".repeat(40),runtime_manifest_sha256:"6".repeat(64),
            stage:identity(1),workspace:identity(2),staged:identity(3),previous:Some(identity(4))};
        let raw=serde_json::to_vec(&phase).unwrap();
        assert!(PublicationPhaseData::parse_raw(&raw).is_ok());
        let value:serde_json::Value=serde_json::from_slice(&raw).unwrap();
        for key in value.as_object().unwrap().keys() {
            let mut missing=value.clone();missing.as_object_mut().unwrap().remove(key);
            assert!(PublicationPhaseData::parse_raw(&serde_json::to_vec(&missing).unwrap()).is_err(),"{key}");
        }
        for (key,bad) in [("schemaVersion",serde_json::json!(2)),("phase",serde_json::json!("complete")),
            ("invocation",serde_json::json!("../extra")),("sourceCommit",serde_json::json!("5".repeat(39))),
            ("staged",value["workspace"].clone()),("previous",value["staged"].clone()),
            ("unrelated",serde_json::json!(true))] {
            let mut changed=value.clone();changed[key]=bad;
            assert!(PublicationPhaseData::parse_raw(&serde_json::to_vec(&changed).unwrap()).is_err(),"{key}");
        }
        let duplicate=format!("{{\"schemaVersion\":1,{}",String::from_utf8(raw.clone()).unwrap().trim_start_matches('{'));
        assert!(PublicationPhaseData::parse_raw(duplicate.as_bytes()).is_err());
        assert!(PublicationPhaseData::parse_raw(&vec![b' ';PHASE_LIMIT+1]).is_err());
        assert_eq!(phase_location_data(&phase,Some(phase.staged),None),Ok(false));
        assert_eq!(phase_location_data(&phase,Some(phase.staged),phase.previous),Ok(false));
        assert_eq!(phase_location_data(&phase,None,Some(phase.staged)),Ok(true));
        for (staged,live) in [(None,None),(Some(phase.staged),Some(phase.staged)),
            (Some(identity(10)),None),(None,Some(identity(10))),
            (Some(phase.staged),Some(identity(10))),(None,phase.previous)] {
            assert!(phase_location_data(&phase,staged,live).is_err());
        }
        // Crash immediately after live publication/workspace retirement and
        // a second crash after withdrawal use the original phase-stage slot.
        // No recreated workspace and no signed-byte-only replacement qualify.
        let fresh=PublicationPhaseData {previous:None,..phase.clone()};
        for (workspace,stage,live,want) in [
            (Some(fresh.staged),None,None,FreshPlacement::Workspace),
            (None,None,Some(fresh.staged),FreshPlacement::Applications),
            (None,Some(fresh.staged),None,FreshPlacement::Stage),
        ] {assert_eq!(fresh_placement_data(&fresh,workspace,stage,live),Ok(want));}
        for (workspace,stage,live) in [
            (None,None,None),(Some(fresh.staged),Some(fresh.staged),None),
            (Some(fresh.staged),None,Some(fresh.staged)),(None,Some(fresh.staged),Some(fresh.staged)),
            (Some(identity(99)),None,None),(None,Some(identity(99)),None),(None,None,Some(identity(99))),
        ] {assert!(fresh_placement_data(&fresh,workspace,stage,live).is_err());}
        assert!(fresh_placement_data(&phase,None,None,Some(phase.staged)).is_err());
        for mutate in 0..3 {
            let mut replacement=phase.staged;
            match mutate {0=>replacement.inode+=1,1=>replacement.birth_seconds+=1,_=>replacement.birth_nanoseconds+=1}
            assert!(phase_location_data(&phase,None,Some(replacement)).is_err());
            assert!(fresh_placement_data(&fresh,None,Some(replacement),None).is_err());
        }
    }

    #[test]
    fn occupied_launcher_requires_recorded_enrollment_not_identical_signed_bytes() {
        use mobile_release_desktop::macos_install_maintenance::ActionData::*;
        for action in [FreshInstall,SamePackageNoop,RestoreFixedApp,Update,Uninstall] {
            for same in [false,true] { assert!(occupied_decision(action,false,same).is_err()); }
        }
        for action in [FreshInstall,Uninstall] { assert!(occupied_decision(action,true,true).is_err()); }
        for action in [SamePackageNoop,RestoreFixedApp,Update] {
            assert_eq!(occupied_decision(action,true,true),Ok(launcher::Decision::KeepCurrent));
        }
        assert_eq!(occupied_decision(Update,true,false),Ok(launcher::Decision::ReplaceEnrolled));
        for action in [SamePackageNoop,RestoreFixedApp] { assert!(occupied_decision(action,true,false).is_err()); }
    }

    #[test]
    fn launcher_returned_writes_remain_separate_and_absorb_bounds_after_recording() {
        let mut count = WriteCounts::default();
        count.record_returned(3, 0).unwrap();
        count.record_returned(2, 0).unwrap();
        assert_eq!((count.calls, count.bytes, count.failed), (2, 5, false));
        assert!(count.record_returned(1, installation_record::PAYLOAD_LIMIT - 5).is_err());
        assert_eq!((count.calls, count.bytes, count.failed), (3, 6, true));
        // A later apparently in-budget observation cannot erase the failure.
        assert!(count.record_returned(1, 0).is_err());
        assert_eq!((count.calls, count.bytes), (4, 7));
        let limit = launcher::LIMITS.iter().sum::<u64>() + launcher::TICKET_LIMIT;
        let mut full = WriteCounts::default();
        full.record_returned(limit, 0).unwrap();
        assert!(full.record_returned(1, 0).is_err());
        assert_eq!((full.calls, full.bytes, full.failed), (2, limit+1, true));
        let mut zero = WriteCounts::default();
        assert!(zero.record_returned(0, 0).is_err());
        assert!(zero.failed);
        let mut overflow = WriteCounts { calls:u64::MAX,bytes:u64::MAX,failed:false };
        assert!(overflow.record_returned(1, 0).is_err());
        assert_eq!((overflow.calls, overflow.bytes, overflow.failed), (u64::MAX, u64::MAX, true));
    }

    fn read_bytes(bytes: &[u8], at: u64, output: &mut [u8], limit: usize) -> Result<usize> {
        let at = usize::try_from(at).map_err(|_| "test-offset")?;
        if at >= bytes.len() { return Ok(0); }
        let count = output.len().min(limit).min(bytes.len()-at);
        output[..count].copy_from_slice(&bytes[at..at+count]);
        Ok(count)
    }

    #[test]
    fn signed_prefix_comparison_handles_short_reads_and_rejects_foreign_or_extra_bytes() {
        let source: Vec<u8> = (0..65539).map(|n| (n % 251) as u8).collect();
        for length in [0, 3, 65535, 65536, 65539] {
            let target = &source[..length];
            let hash = prefix_hash(length as u64,
                |at, out| read_bytes(&source, at, out, 997),
                |at, out| read_bytes(target, at, out, 4001), || Ok(())).unwrap();
            assert_eq!(hash, format!("{:x}", Sha256::digest(target)));
        }
        let mut changed = source.clone(); changed[65536] ^= 1;
        assert_eq!(prefix_hash(source.len() as u64,
            |at, out| read_bytes(&source, at, out, 997),
            |at, out| read_bytes(&changed, at, out, 4001), || Ok(())), Err("launcher-prefix-mismatch"));
        assert_eq!(prefix_hash(3, |at, out| read_bytes(&source, at, out, 1),
            |at, out| read_bytes(&source[..4], at, out, 1), || Ok(())), Err("launcher-prefix-eof"));
        assert_eq!(prefix_hash(4, |at, out| read_bytes(&source, at, out, 1),
            |at, out| read_bytes(&source[..3], at, out, 1), || Ok(())), Err("launcher-prefix-read"));
        assert_eq!(prefix_hash(4, |at, out| read_bytes(&source[..3], at, out, 1),
            |at, out| read_bytes(&source[..4], at, out, 1), || Ok(())), Err("launcher-prefix-read"));
    }

    #[test]
    fn signed_prefix_read_or_deadline_failure_never_produces_a_cleanup_digest() {
        assert_eq!(prefix_hash(launcher::LIMITS[0]+1, |_, _| panic!("source entered"),
            |_, _| panic!("target entered"), || panic!("clock entered")), Err("launcher-prefix-size"));
        for failure in 0..3 {
            let source = b"abcdef";
            let mut ticks = 0;
            let result = prefix_hash(3,
                |at, out| if failure == 0 { Err("source-refused") } else { read_bytes(source, at, out, 1) },
                |at, out| if failure == 1 { Err("target-refused") } else { read_bytes(&source[..3], at, out, 1) },
                || { ticks += 1; if failure == 2 && ticks == 3 { Err("deadline") } else { Ok(()) } });
            assert_eq!(result, Err(["source-refused", "target-refused", "deadline"][failure]));
        }
        assert_eq!(prefix_hash(3, |_, out| Ok(out.len()+1),
            |at, out| read_bytes(b"abc", at, out, 3), || Ok(())), Err("launcher-prefix-read"));
        assert_eq!(prefix_hash(3, |at, out| read_bytes(b"abc", at, out, 3),
            |_, out| Ok(out.len()+1), || Ok(())), Err("launcher-prefix-read"));
    }
}
