// Restore-specific native recovery. Detached implementation-in-progress: this
// reader is not wired as an action capability. Full reference/census/effects
// integration is required before a caller may activate it.
use super::*;
use mobile_release_desktop::macos_applications_launcher::OriginalIdentityData;
use transaction::RestorePrepublicationData;

const RECEIPT_LIMIT: usize = 64*1024;
const RECEIPT_KIND: &str = "mrk-restore-app-prepublication-preservation-v1";
// This reservation is charged by capture before bounded strict JSON parsing;
// it is transient, not multiplied as though every parsed Value stayed live.
const RECEIPT_PARSE_QUOTE: usize = RECEIPT_LIMIT*64;
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct OwnAttempt {
    invocation: String, request_id: String, identity: OriginalIdentityData,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct AttemptBinding {
    invocation: String, request_id: String, intent_sha256: String, identity: OriginalIdentityData,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct ReceiptWire {
    schema_version: u32, kind: String, target: String, torn_invocation: String,
    previous_state_sha256: String, previous_capsule_sha256: String,
    root: OriginalIdentityData, stage: OriginalIdentityData, old_state: OriginalIdentityData,
    stage_sha256: String, own_attempt: OwnAttempt, attempts: Vec<AttemptBinding>,
}
struct ReceiptData { wire: ReceiptWire, raw: Vec<u8> }
fn id_data(value: &str) -> bool {
    worker::invocation_valid(value) && value.bytes().any(|b|b!=b'0')
}
impl ReceiptData {
    fn parse(raw: &[u8], reference: &transaction::RestoreReferenceData,
        base: &IntentData, previous:(&StateData,&CapsuleData), selected: &ReleaseSetData) -> Result<Self> {
        check(!raw.is_empty() && raw.len()<=RECEIPT_LIMIT && hash(raw)==reference.receipt_sha256_data(),
            "restore-recovery-receipt-bound")?;
        let value=mobile_release_desktop::protocol::strict_json(raw).map_err(|_|"restore-recovery-receipt-shape")?;
        check(value.is_object() && ["root","stage","oldState","ownAttempt"].iter().all(|key|value[*key].is_object())
            && value["ownAttempt"]["identity"].is_object()
            && value["attempts"].as_array().is_some_and(|rows|!rows.is_empty()
                && rows.len()<transaction::INVOCATION_LIMIT
                && rows.iter().all(|row|row.is_object() && row["identity"].is_object())),
            "restore-recovery-receipt-shape")?;
        let wire:ReceiptWire=serde_json::from_value(value).map_err(|_|"restore-recovery-receipt-shape")?;
        // Historical namespace uses real recorded source membership, never a
        // producer set with a predecessor relabelled as current. This parser
        // is not active recovery admission (which separately remains strict).
        check(base.action_data()==ActionData::RestoreFixedApp && base.recovery_data().is_none()
            && selected.contains_data(base.next_data())
            && transaction::correspondence_data(base,Some(previous),None,None)==transaction::CorrespondenceData::Pending,
            "restore-recovery-recorded-base")?;
        let (torn,torn_request,torn_sha)=(base.invocation_data(),base.request_id_data(),base.digest_data());
        let (old_state,old_capsule)=(previous.0.digest_data(),previous.1.digest_data());
        check(wire.schema_version==1 && wire.kind==RECEIPT_KIND && wire.target==selected.target_data().target()
            && wire.torn_invocation==torn && reference.torn_invocation_data()==torn
            && wire.previous_state_sha256==old_state && wire.previous_capsule_sha256==old_capsule
            && sha(&wire.stage_sha256) && wire.own_attempt.invocation==reference.receipt_invocation_data()
            && id_data(&wire.own_attempt.invocation) && id_data(&wire.own_attempt.request_id),
            "restore-recovery-receipt-binding")?;
        // Include the creating intent ORIGINAL, but never its body hash: that
        // body contains this receipt's digest and is written only afterwards.
        let mut identities=BTreeSet::new();
        for identity in [wire.root,wire.stage,wire.old_state,wire.own_attempt.identity] {
            check(identity.valid_data() && identity.same_volume_data(wire.root) && identity.device>0
                && identities.insert(identity.inode),"restore-recovery-original-alias")?;
        }
        let mut invocations=BTreeSet::new();let mut requests=BTreeSet::new();
        invocations.insert(wire.own_attempt.invocation.as_str());requests.insert(wire.own_attempt.request_id.as_str());
        let mut previous:Option<&str>=None;
        for row in &wire.attempts {
            check(id_data(&row.invocation) && id_data(&row.request_id) && sha(&row.intent_sha256)
                && previous.is_none_or(|old|old<row.invocation.as_str())
                && invocations.insert(&row.invocation) && requests.insert(&row.request_id)
                && row.identity.valid_data() && row.identity.same_volume_data(wire.root)
                && identities.insert(row.identity.inode),"restore-recovery-attempt-binding")?;
            previous=Some(&row.invocation);
        }
        check(wire.attempts.iter().any(|row|row.invocation==torn && row.request_id==torn_request
            && row.intent_sha256==torn_sha),"restore-recovery-base-required")?;
        let mut canonical=serde_json::to_vec(&wire).map_err(|_|"restore-recovery-receipt-shape")?;
        canonical.push(b'\n');check(canonical==raw,"restore-recovery-receipt-canonical")?;
        Ok(Self{wire,raw:canonical})
    }
    // This comparison is used before any expected-body-prefix admission. A
    // later receipt cannot create missing durable custody of an earlier intent.
    fn own_original(&self, invocation:&str, request:&str, observed:OriginalIdentityData) -> Result<()> {
        check(self.wire.own_attempt.invocation==invocation && self.wire.own_attempt.request_id==request
            && observed==self.wire.own_attempt.identity && observed.valid_data(),"restore-recovery-own-original")
    }
    fn canonical_intent(&self, base:&IntentData, previous:(&StateData,&CapsuleData),selected:&ReleaseSetData)
        -> Result<(IntentData,Vec<u8>)> {
        let reference=data(transaction::RestoreReferenceData::new_data(&self.wire.torn_invocation,
            &self.wire.own_attempt.invocation,&hash(&self.raw)))?;
        let bytes=data(IntentData::restore_retry_body_recorded_data(base,&self.wire.own_attempt.invocation,
            &self.wire.own_attempt.request_id,previous,&reference,selected))?;
        let intent=data(IntentData::parse_recorded_data(&bytes,selected))?;Ok((intent,bytes))
    }
}

// Immutable receipt history is a single bounded prefix chain. A newly read
// receipt cannot authenticate an earlier intent unless that earlier receipt
// already bound its own original. These rows contain canonical expected body
// hashes, not a claim that an interrupted writer completed.
#[derive(Clone)]
struct ExpectedAttempt {
    invocation:String,request:String,body:Vec<u8>,identity:OriginalIdentityData,
    receipt:Option<String>,
}
fn chain_data(receipts:&[ReceiptData],base:&IntentData,base_raw:&[u8],
    previous:(&StateData,&CapsuleData),selected:&ReleaseSetData)->Result<Vec<ExpectedAttempt>> {
    check(!receipts.is_empty() && receipts.len()<transaction::INVOCATION_LIMIT
        && base_raw.len()<=transaction::INTENT_LIMIT && hash(base_raw)==base.digest_data(),
        "restore-recovery-chain-bound")?;
    let refs:Vec<&ReceiptData>=receipts.iter().collect();
    chain_refs_data(&refs,base,base_raw,previous,selected)
}
fn chain_refs_data(receipts:&[&ReceiptData],base:&IntentData,base_raw:&[u8],
    previous:(&StateData,&CapsuleData),selected:&ReleaseSetData)->Result<Vec<ExpectedAttempt>> {
    check(!receipts.is_empty()&&receipts.len()<transaction::INVOCATION_LIMIT
        &&!base_raw.is_empty()&&base_raw.len()<=transaction::INTENT_LIMIT&&hash(base_raw)==base.digest_data(),
        "restore-recovery-chain-bound")?;
    let mut ordered=receipts.to_vec();
    ordered.sort_by_key(|r|r.wire.attempts.len());
    let first=ordered[0];
    let base_row=first.wire.attempts.first().ok_or("restore-recovery-chain-base")?;
    check(base_row.invocation==base.invocation_data() && base_row.request_id==base.request_id_data()
        && base_row.intent_sha256==base.digest_data(),"restore-recovery-chain-base")?;
    let mut expected=vec![ExpectedAttempt{invocation:base.invocation_data().into(),request:base.request_id_data().into(),
        body:base_raw.to_vec(),identity:base_row.identity,receipt:None}];
    let mut own_ids=BTreeSet::new();
    for receipt in ordered {
        check(receipt.wire.root==first.wire.root && receipt.wire.stage==first.wire.stage
            && receipt.wire.old_state==first.wire.old_state && receipt.wire.stage_sha256==first.wire.stage_sha256
            && receipt.wire.torn_invocation==base.invocation_data()
            && receipt.wire.attempts.len()==expected.len()
            && own_ids.insert(receipt.wire.own_attempt.invocation.as_str()),"restore-recovery-chain-prefix")?;
        for row in &receipt.wire.attempts {
            let old=expected.iter().find(|old|old.invocation==row.invocation).ok_or("restore-recovery-chain-attempt")?;
            check(row.request_id==old.request && row.intent_sha256==hash(&old.body) && row.identity==old.identity,
                "restore-recovery-chain-attempt")?;
        }
        let (intent,body)=receipt.canonical_intent(base,previous,selected)?;
        check(expected.iter().all(|old|old.invocation!=intent.invocation_data() && old.request!=intent.request_id_data()
            && old.identity.inode!=receipt.wire.own_attempt.identity.inode),
            "restore-recovery-chain-identity")?;
        expected.push(ExpectedAttempt{invocation:intent.invocation_data().into(),request:intent.request_id_data().into(),
            body,identity:receipt.wire.own_attempt.identity,
            receipt:Some(intent.restore_recovery_data().ok_or("restore-recovery-chain-reference")?.receipt_name_data())});
    }
    Ok(expected)
}
fn attempt_prefix_data(expected:&[u8],actual:&[u8],mode:u32,own_receipt:bool)->Result<()> {
    check(!expected.is_empty() && expected.len()<=transaction::INTENT_LIMIT && actual.len()<=expected.len()
        && matches!(mode,0o444|0o600) && expected.starts_with(actual)
        && (mode!=0o444 || expected==actual) && (own_receipt || mode==0o444 && expected==actual),
        "restore-recovery-intent-prefix")
}
struct AttemptObserved {
    expected:ExpectedAttempt,raw_sha:String,raw_size:usize,mode:u32,placement:transaction::RestoreOriginalPlacementData,
}
fn optional_identity(book:&mut Install,root:usize,name:&str)->Result<Option<OriginalIdentityData>> {
    match book.named(Some(root),name) {Err(Errno::ENOENT)=>return Ok(None),Err(_)=>return Err("restore-recovery-original-name"),Ok(_)=>{}}
    removal_archive_scope(book,|book| {
        let original=book.open(Some(root),name,false)?;
        let identity=applications::preservation_identity(book,original)?;
        let facts=book.identity(original)?;
        check(matches!(facts.mode,0o100444|0o100600),"restore-recovery-intent-mode")?;
        book.protected(original,false,Some(facts.mode&0o7777))?;
        native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_|"restore-recovery-intent-attributes")?;
        book.check_name(original,true)?;Ok(Some(identity))
    })
}
fn observe_attempt(book:&mut Install,root:usize,base:&str,expected:ExpectedAttempt)->Result<AttemptObserved> {
    let original=data(transaction::intent_name_data(&expected.invocation))?;
    let preserved=format!(".restore-recovery-{base}-{}.intent.json",expected.invocation);
    let placement=data(transaction::RestoreOriginalPlacementData::compare_data(expected.identity,
        optional_identity(book,root,&original)?,optional_identity(book,root,&preserved)?))?;
    let name=match placement {transaction::RestoreOriginalPlacementData::Original=>&original,
        transaction::RestoreOriginalPlacementData::Preserved=>&preserved};
    let (raw_sha,raw_size,mode)=removal_archive_scope(book,|book| {
        let (reader,raw,file)=partial_fresh_writer_bytes(book,root,name,transaction::INTENT_LIMIT)?;
        check(applications::preservation_identity(book,reader)?==expected.identity,"restore-recovery-intent-original")?;
        let mode=file.identity.mode&0o7777;
        attempt_prefix_data(&expected.body,&raw,mode,expected.receipt.is_some())?;
        if placement==transaction::RestoreOriginalPlacementData::Preserved {removal_snapshot_metadata_kind(book,reader,&raw,6)?;}
        book.check_name(reader,true)?;Ok((hash(&raw),raw.len(),mode))
    })?;
    // The name that was absent may not acquire a second alias during reading.
    book.absent(root,if name==&original{&preserved}else{&original})?;
    Ok(AttemptObserved{expected,raw_sha,raw_size,mode,placement})
}

const RESTORE_PHASES: [&str; 2] = ["staging-created", "prepared"];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparedReceipt { Absent, WriterPrefix, Complete }
struct StageObservation {
    original: usize,
    identity: Identity,
    commitment: [u8; 32],
    app: Option<PartialFreshTreeObserved>,
    prepared: PreparedReceipt,
    control_bytes: u64, control_files:u64,
}
fn summary_matches(value: &serde_json::Value, identity: Option<(i64,u64)>) -> bool {
    match identity {
        None => value.is_null(),
        Some((device,inode)) => value.as_object().is_some_and(|v| v.len()==2
            && v.get("device").and_then(|v|v.as_i64())==Some(device)
            && v.get("inode").and_then(|v|v.as_u64())==Some(inode)),
    }
}
fn receipt_data(raw: &[u8], phase: usize, intent: &IntentData, stage: Identity,
    app: Option<Identity>) -> Result<bool> {
    check(phase<RESTORE_PHASES.len() && intent.action_data()==ActionData::RestoreFixedApp,
        "restore-recovery-receipt-action")?;
    // Shared predicate validates exact source fields, selected release and
    // inventory, bounded/strict JSON, phase0/1 order and pending final closes.
    // These two phase names coincide; no Fresh action/authority is reused.
    if !partial_fresh_receipt_data(raw,phase,intent)? { return Ok(false); }
    let value=mobile_release_desktop::protocol::strict_json(raw).map_err(|_|"restore-recovery-receipt-shape")?;
    check(summary_matches(&value["stage"],Some((stage.dev,stage.ino)))
        && summary_matches(&value["runtime"],None)
        && summary_matches(&value["app"],if phase==0 {None}else{app.map(|id|(id.dev,id.ino))})
        && (phase==0 || app.is_some()) && value["payloadWritersSettled"]==true
        && value["runtimePublication"]=="not-attempted"
        && value["appPublication"]=="not-attempted", "restore-recovery-receipt-originals")?;
    Ok(true)
}
fn prepared_data(present: bool, parsed: bool, sealed: bool, app_complete: bool)
    -> Result<PreparedReceipt> {
    if !present {
        check(!parsed && !sealed,"restore-recovery-receipt-observation")?;
        return Ok(PreparedReceipt::Absent);
    }
    check(app_complete && (!sealed || parsed),"restore-recovery-prepared-before-app")?;
    Ok(if parsed && sealed {PreparedReceipt::Complete}else{PreparedReceipt::WriterPrefix})
}
// The caller retains and budgets this stage original in its SAME Book. It
// supplies only a fixed source-selected inventory and actual input root; no
// filename/selector/authority comes from a UI or receipt. source=None is only
// for existing authenticated conserved-prefix census, never installation.
fn stage_observation(book: &mut Install, stage: usize, intent: &IntentData,
    index: &installation_record::InventoryIndex<'_>, source: Option<usize>,
    work: &mut PartialFreshTreeWork) -> Result<StageObservation> {
    check(intent.action_data()==ActionData::RestoreFixedApp,"restore-recovery-action")?;
    let identity=partial_fresh_directory(book,stage)?;
    check(identity.mode==0o040700,"restore-recovery-stage-mode")?;
    let before=roster_now(book,stage)?;
    check(before.contains_key("staging-created.json") && before.len()<=3
        && before.keys().all(|name|matches!(name.as_str(),"staging-created.json"|"prepared.json"|"app")),
        "restore-recovery-stage-roster")?;
    let app=if before.contains_key("app") {
        let mode=if source.is_some(){PartialFreshPayloadRead::Paired}else{PartialFreshPayloadRead::Conserved};
        let app=partial_fresh_payload_tree(book,source,"app",stage,"app","app",index,0,false,mode,None,work)?;
        check(app.identity.ino==before["app"],"restore-recovery-app-original")?;Some(app)
    }else{book.absent(stage,"app")?;None};
    let mut hash=Sha256::new(); hash.update(b"MRK-RESTORE-APP-PREFIX-V1\0");
    let mut control_bytes=0u64;
    let mut prepared=PreparedReceipt::Absent;
    for (phase,label) in RESTORE_PHASES.iter().enumerate() {
        let name=format!("{label}.json");
        if !before.contains_key(&name) {check(phase==1,"restore-recovery-created-required")?;hash.update([0]);continue;}
        // Existing scope closes every newly adopted reader on all paths. No
        // old writer is resumed, sealed, truncated or assigned future finality.
        let observation=removal_archive_scope(book,|book|{
            work.check(transaction::STATE_LIMIT+2*PARTIAL_FRESH_BLOCK)?;
            let (_,raw,file)=partial_fresh_writer_bytes(book,stage,&name,transaction::STATE_LIMIT)?;
            check(file.identity.ino==before[&name],"restore-recovery-phase-original")?;
            let complete=receipt_data(&raw,phase,intent,identity,app.map(|a|a.identity))?;
            if phase==0 {
                check(complete && file.state==PartialFreshFileState::Complete,"restore-recovery-created-required")?;
            }else{
                prepared=prepared_data(true,complete,file.state==PartialFreshFileState::Complete,
                    app.is_some_and(|a|a.state==PartialFreshFileState::Complete))?;
            }
            hash.update([1]);partial_fresh_identity_digest(&mut hash,file.identity);hash.update(file.digest);
            control_bytes=control_bytes.checked_add(raw.len() as u64).ok_or("restore-recovery-control-bound")?;
            Ok(())
        });
        observation?;
    }
    if let Some(app)=app {hash.update([1]);hash.update(app.digest);}else{hash.update([0]);}
    check(roster_now(book,stage)?==before && partial_fresh_directory(book,stage)?==identity,
        "restore-recovery-stage-post")?;
    Ok(StageObservation {original:stage,identity,commitment:hash.finalize().into(),app,prepared,control_bytes,control_files:before.len() as u64-u64::from(app.is_some())})
}

// One operation raises this reservation as the strict receipt reveals its
// actual attempt count. Repeated phase/index checks do not re-debit workspace.
#[derive(Default)]
struct CaptureBudget { attempts:usize,index:usize,inventory:usize,charged:usize }
impl CaptureBudget {
    fn reserve(&mut self,book:&mut Install,attempts:usize,index:usize,inventory:usize)->Result<()> {
        self.attempts=self.attempts.max(attempts);self.index=self.index.max(index);
        self.inventory=self.inventory.max(inventory);
        let wanted=self.attempts.checked_mul(RECEIPT_LIMIT*4+transaction::INTENT_LIMIT*4)
            .and_then(|n|n.checked_add(RECEIPT_PARSE_QUOTE+PARTIAL_FRESH_WORK+64*1024))
            .and_then(|n|n.checked_add(self.index)).and_then(|n|n.checked_add(self.inventory))
            .ok_or("restore-recovery-memory")?;
        let extra=wanted.checked_sub(self.charged).ok_or("restore-recovery-memory")?;
        check(removal_effective_control_bytes(book)?.checked_add(extra as u64)
            .is_some_and(|n|n<=installation_record::CONTROL_LIMIT as u64),"restore-recovery-memory")?;
        book.removal_control_reserved=book.removal_control_reserved.checked_add(extra as u64)
            .ok_or("restore-recovery-memory")?;
        self.charged=wanted;Ok(())
    }
    // Call only AFTER owned parse/index/workspace allocations have dropped and
    // all native scopes succeeded. Neither original records nor their backing
    // are refunded. Retained result data keeps its own conservative debit.
    fn retain(self,book:&mut Install,retained:usize)->Result<usize> {
        check(retained<=self.charged,"restore-recovery-retained-memory")?;
        retire_control(book,self.charged-retained)?;Ok(retained)
    }
}
fn retire_control(book:&mut Install,charged:usize)->Result<()> {
    check(!book.unknown,"restore-recovery-unsettled-memory")?;
    let next=book.removal_control_reserved.checked_sub(charged as u64).ok_or("restore-recovery-memory")?;
    check(book.removal_observation_control.is_none()||next>=book.removal_observation_reserved,
        "restore-recovery-reservation-overlap")?;
    book.removal_control_reserved=next;Ok(())
}
fn reserve_capture(book:&mut Install,budget:&mut CaptureBudget,attempts:usize,index:(usize,usize,usize))->Result<()> {
    check((1..=transaction::INVOCATION_LIMIT).contains(&attempts),"restore-recovery-attempt-bound")?;
    budget.reserve(book,attempts,index.2,0)?;
    let count=partial_fresh_retry_original_quote_data(index.0,index.1)?
        .checked_add(attempts.checked_mul(40).ok_or("restore-recovery-original-bound")?)
        .ok_or("restore-recovery-original-bound")?;
    let end=book.originals.len().checked_add(count).filter(|n|*n<=installation_record::ORIGINAL_LIMIT)
        .ok_or("restore-recovery-original-bound")?;
    transport_live(book,0)?;
    reserve_removal_original_storage(book,end)
}
fn stage_original_quote(stage:&StageObservation,attempts:usize,receipts:usize)->Result<usize> {
    let files=usize::try_from(stage.app.map_or(0,|a|a.files)).map_err(|_|"restore-recovery-original-bound")?;
    let dirs=usize::try_from(stage.app.map_or(0,|a|a.directories)).map_err(|_|"restore-recovery-original-bound")?;
    partial_fresh_retry_original_quote_data(files,dirs)?
        .checked_add(attempts.checked_mul(8).ok_or("restore-recovery-original-bound")?)
        .and_then(|n|n.checked_add(receipts.checked_mul(4)?))
        .ok_or("restore-recovery-original-bound")
}
fn fixed_intent_id(name:&str)->Option<&str> {
    let id=name.strip_prefix(".maintenance-")?.strip_suffix(".intent.json")?;
    id_data(id).then_some(id)
}
fn fixed_receipt_id(name:&str)->Option<&str> {
    let id=name.strip_prefix(".restore-recovery-")?.strip_suffix(".json")?;
    id_data(id).then_some(id)
}
fn historical(history:&History,id:&str)->bool {history.current.intent.invocation_data()==id||history.originals.contains_key(id)}
fn stage_at(book:&mut Install,root:usize,name:&str)->Result<Option<usize>> {
    match book.named(Some(root),name) {Err(Errno::ENOENT)=>return Ok(None),Err(_)=>return Err("restore-recovery-stage-name"),Ok(_)=>{}}
    let stage=book.open(Some(root),name,true)?;book.protected(stage,true,Some(0o700))?;
    native::no_xattrs(book.fd(stage)?.as_fd()).map_err(|_|"restore-recovery-stage-attributes")?;
    Ok(Some(stage))
}
struct ReceiptObserved {data:ReceiptData,identity:OriginalIdentityData}
pub(super) struct Observation {
    root:usize,base:IntentData,base_raw:Vec<u8>,admission:RestorePrepublicationData,
    root_identity:OriginalIdentityData,old_state:OriginalIdentityData,stage_identity:OriginalIdentityData,
    stage:StageObservation,stage_placement:transaction::RestoreOriginalPlacementData,
    attempts:Vec<AttemptObserved>,receipts:Vec<ReceiptObserved>,
    current:Option<transaction::RestoreReferenceData>,preservation:Preservation,
}
impl Observation {
    // Caller supplies completed namespace names only after its independent
    // genuine State/capsule audit. They are not a permissive filename filter.
    pub(super) fn capture(book:&mut Install,prepared:&PreparedFresh,selected:&ReleaseSetData,
        history:&History,prior_groups:&Namespace,pending:Option<&str>)->Result<Option<Self>> {
        let completed_names=&prior_groups.names;
        let root=prepared.destination;let names=roster_now(book,root)?;
        let receipt_names:Vec<String>=names.keys().filter(|name|!completed_names.contains(*name)
            && fixed_receipt_id(name).is_some()).cloned().collect();
        let candidates:Vec<String>=names.keys().filter_map(|name|fixed_intent_id(name))
            .filter(|id|!historical(history,id)&&Some(*id)!=pending).map(str::to_owned).collect();
        if candidates.is_empty()&&receipt_names.is_empty(){return Ok(None);}
        check(receipt_names.len()<transaction::INVOCATION_LIMIT && candidates.len()<=transaction::INVOCATION_LIMIT,
            "restore-recovery-attempt-bound")?;
        book.absent(root,paths::APP_NAME)?;
        let index_quote=worker::reinstall_index_quote_data(&prepared.inventory)?;
        let mut budget=CaptureBudget::default();
        reserve_capture(book,&mut budget,receipt_names.len().saturating_add(candidates.len()).min(transaction::INVOCATION_LIMIT).max(1),index_quote)?;
        let index=prepared.inventory.index()?;
        check((index.files.len(),index.directories.len())==(index_quote.0,index_quote.1),"restore-recovery-index-quote")?;
        let root_identity=applications::preservation_identity(book,root)?;
        let old_state=applications::preservation_identity(book,history.state_original)?;
        held_bytes(book,history.state_original,&history.state_bytes)?;
        let prior=(&history.current.state,&history.current.capsule);
        let mut receipt_raws=Vec::new();let mut nominated:Option<String>=None;
        for name in receipt_names {
            let (raw,identity)=removal_archive_scope(book,|book|{
                let (reader,raw)=metadata_original(book,root,&name,RECEIPT_LIMIT)?;
                let identity=applications::preservation_identity(book,reader)?;
                held_bytes(book,reader,&raw)?;Ok((raw,identity))
            })?;
            let value=mobile_release_desktop::protocol::strict_json(&raw).map_err(|_|"restore-recovery-receipt-shape")?;
            let base=value.get("tornInvocation").and_then(|v|v.as_str()).filter(|id|id_data(id))
                .ok_or("restore-recovery-receipt-binding")?;
            check(nominated.as_deref().is_none_or(|old|old==base),"restore-recovery-distinct-base")?;
            nominated=Some(base.into());receipt_raws.push((name,raw,identity));
        }
        let base_id=if let Some(base)=nominated {base}else {
            check(candidates.len()==1,"restore-recovery-base-required")?;candidates[0].clone()
        };
        check(!historical(history,&base_id)&&Some(base_id.as_str())!=pending,"restore-recovery-base-reused")?;
        let base_source=data(transaction::intent_name_data(&base_id))?;
        let base_saved=format!(".restore-recovery-{base_id}-{base_id}.intent.json");
        let source=optional_identity(book,root,&base_source)?;let saved=optional_identity(book,root,&base_saved)?;
        let base_identity=match (source,saved) {(Some(id),None)|(None,Some(id))=>id,_=>return Err("restore-recovery-base-placement")};
        let (base_raw,base)=removal_archive_scope(book,|book|{
            let (reader,raw)=metadata_original(book,root,if source.is_some(){&base_source}else{&base_saved},transaction::INTENT_LIMIT)?;
            check(applications::preservation_identity(book,reader)?==base_identity,"restore-recovery-base-original")?;
            let base=data(IntentData::parse_data(&raw,selected))?;
            check(base.invocation_data()==base_id,"restore-recovery-base-binding")?;
            held_bytes(book,reader,&raw)?;Ok((raw,base))
        })?;
        let admission=prior_groups.admission(&base,history,selected)?;
        if let Some(reference)=base.restore_recovery_data() {
            check(prior_groups.group_for(reference)?.holder_identity==base_identity,
                "restore-recovery-prior-holder-original")?;
        }
        data(admission.unchanged_state_data(&history.state_bytes,None,None))?;
        for name in [data(transaction::archived_state_name_data(history.current.state.invocation_data()))?,
            data(transaction::archived_state_name_data(&base_id))?,data(transaction::capsule_name_data(&base_id))?] {book.absent(root,&name)?;}
        let mut receipts=Vec::new();
        for (name,raw,identity) in receipt_raws {
            let reference=data(transaction::RestoreReferenceData::new_data(&base_id,fixed_receipt_id(&name)
                .ok_or("restore-recovery-receipt-name")?,&hash(&raw)))?;
            let data=ReceiptData::parse(&raw,&reference,&base,prior,selected)?;
            check(data.wire.root==root_identity&&data.wire.old_state==old_state,"restore-recovery-receipt-originals")?;
            receipts.push(ReceiptObserved{data,identity});
        }
        receipts.sort_by_key(|r|r.data.wire.attempts.len());
        let expected=if receipts.is_empty(){
            check(source.is_some()&&saved.is_none(),"restore-recovery-base-receipt-required")?;
            vec![ExpectedAttempt{invocation:base_id.clone(),request:base.request_id_data().into(),body:base_raw.clone(),identity:base_identity,receipt:None}]
        }else{
            let refs:Vec<&ReceiptData>=receipts.iter().map(|r|&r.data).collect();
            chain_refs_data(&refs,&base,&base_raw,prior,selected)?
        };
        let mut ids:BTreeSet<&str>=history.originals.keys().map(String::as_str).collect();ids.insert(history.current.intent.invocation_data());
        let mut requests:BTreeSet<&str>=history.originals.values().chain(std::iter::once(&history.current))
            .map(|r|r.intent.request_id_data()).collect();
        for row in &expected {check(ids.insert(&row.invocation)&&requests.insert(&row.request),"restore-recovery-cross-history-attempt")?;}
        check(ids.len()+(if pending.is_none(){1}else{0})<=transaction::INVOCATION_LIMIT,"restore-recovery-aggregate-invocations")?;
        check(candidates.iter().all(|id|expected.iter().any(|row|&row.invocation==id)),"restore-recovery-unbound-intent")?;
        let stage_source=format!(".install-{base_id}");let stage_saved=format!(".restore-recovery-{base_id}.stage");
        let a=stage_at(book,root,&stage_source)?;let b=stage_at(book,root,&stage_saved)?;
        let stage_identity=if let Some(receipt)=receipts.last(){receipt.data.wire.stage}else {
            check(a.is_some()&&b.is_none(),"restore-recovery-stage-receipt-required")?;
            applications::preservation_identity(book,a.ok_or("restore-recovery-stage-required")?)?
        };
        let stage_placement=data(transaction::RestoreOriginalPlacementData::compare_data(stage_identity,
            a.map(|i|applications::preservation_identity(book,i)).transpose()?,b.map(|i|applications::preservation_identity(book,i)).transpose()?))?;
        let stage_original=a.or(b).ok_or("restore-recovery-stage-required")?;
        let mut work=PartialFreshTreeWork::new(0)?;
        let stage=stage_observation(book,stage_original,&base,&index,Some(prepared.input),&mut work)?;
        if let Some(receipt)=receipts.last(){check(archive_hex_text_data(&stage.commitment)==receipt.data.wire.stage_sha256,"restore-recovery-stage-commitment")?;}
        check(pending.is_none_or(|id|receipts.last().is_some_and(|r|r.data.wire.own_attempt.invocation==id)),
            "restore-recovery-current-latest")?;
        let mut attempts=Vec::new();let mut current=None;
        for row in expected {
            book.absent(root,&data(transaction::capsule_name_data(&row.invocation))?)?;
            book.absent(root,&data(transaction::archived_state_name_data(&row.invocation))?)?;
            if row.invocation!=base_id {book.absent(root,&format!(".install-{}",row.invocation))?;}
            let observed=observe_attempt(book,root,&base_id,row)?;
            if Some(observed.expected.invocation.as_str())==pending {
                check(observed.placement==transaction::RestoreOriginalPlacementData::Original&&observed.mode==0o444
                    && observed.raw_sha==hash(&observed.expected.body),"restore-recovery-current-intent")?;
                let intent=data(IntentData::parse_data(&observed.expected.body,selected))?;
                current=intent.restore_recovery_data().cloned();check(current.is_some(),"restore-recovery-current-reference")?;
            }else{attempts.push(observed);}
        }
        check(pending.is_none()||current.is_some(),"restore-recovery-current-required")?;
        check(roster_now(book,root)?==names,"restore-recovery-root-post")?;
        held_bytes(book,history.state_original,&history.state_bytes)?;
        Ok(Some(Self{root,base,base_raw,admission,root_identity,old_state,stage_identity,stage,stage_placement,
            attempts,receipts,current,preservation:Preservation::fresh()}))
    }
}

impl Observation {
    fn post(&self,book:&mut Install,prepared:&PreparedFresh,history:&History,selected:&ReleaseSetData)->Result<()> {
        check(self.root==prepared.destination && self.base.next_data()==selected.current_data()
            && applications::preservation_identity(book,self.root)?==self.root_identity
            && applications::preservation_identity(book,history.state_original)?==self.old_state,
            "restore-recovery-originals-post")?;
        held_bytes(book,history.state_original,&history.state_bytes)?;
        data(self.admission.unchanged_state_data(&history.state_bytes,None,None))?;
        book.absent(self.root,paths::APP_NAME)?;
        book.absent(self.root,&data(transaction::archived_state_name_data(history.current.state.invocation_data()))?)?;
        let source=format!(".install-{}",self.base.invocation_data());
        let saved=format!(".restore-recovery-{}.stage",self.base.invocation_data());
        check(applications::preservation_identity(book,self.stage.original)?==self.stage_identity,
            "restore-recovery-stage-original")?;
        let expected_name=match self.stage_placement {transaction::RestoreOriginalPlacementData::Original=>&source,
            transaction::RestoreOriginalPlacementData::Preserved=>&saved};
        check(book.originals[self.stage.original].parent==Some(self.root)
            && book.originals[self.stage.original].name==*expected_name,"restore-recovery-stage-placement")?;
        book.absent(self.root,if expected_name==&source{&saved}else{&source})?;
        let index=prepared.inventory.index()?;let mut work=PartialFreshTreeWork::new(0)?;
        let actual=stage_observation(book,self.stage.original,&self.base,&index,Some(prepared.input),&mut work)?;
        check(actual.commitment==self.stage.commitment&&actual.app==self.stage.app
            && actual.prepared==self.stage.prepared,"restore-recovery-stage-post")?;
        for receipt in &self.receipts {
            removal_archive_scope(book,|book| {
                let reference=data(transaction::RestoreReferenceData::new_data(self.base.invocation_data(),
                    &receipt.data.wire.own_attempt.invocation,&hash(&receipt.data.raw)))?;
                let (reader,raw)=metadata_original(book,self.root,&reference.receipt_name_data(),RECEIPT_LIMIT)?;
                check(applications::preservation_identity(book,reader)?==receipt.identity&&raw==receipt.data.raw,
                    "restore-recovery-receipt-post")?;
                held_bytes(book,reader,&raw)
            })?;
        }
        for attempt in &self.attempts {
            let actual=observe_attempt(book,self.root,self.base.invocation_data(),attempt.expected.clone())?;
            check(actual.raw_sha==attempt.raw_sha&&actual.raw_size==attempt.raw_size&&actual.mode==attempt.mode
                && actual.placement==attempt.placement,"restore-recovery-attempt-post")?;
        }
        book.clock()
    }
    // Empty current intent ORIGINAL precedes its immutable ownAttempt receipt.
    // Failures leave known owned files retained; neither caller nor retry may
    // fabricate finality for an incomplete receipt or complete an old writer.
    pub(super) fn prepare_intent(&mut self,book:&mut Install,prepared:&PreparedFresh,history:&History,
        selected:&ReleaseSetData,invocation:&str,request:&str)->Result<(usize,IntentData,Vec<u8>)> {
        check(self.current.is_none()&&!self.preservation.entered&&id_data(invocation)&&id_data(request)
            && self.attempts.iter().all(|a|a.expected.invocation!=invocation&&a.expected.request!=request)
            && !historical(history,invocation)&&history.originals.values().chain(std::iter::once(&history.current))
                .all(|r|r.intent.request_id_data()!=request),"restore-recovery-new-attempt")?;
        self.post(book,prepared,history,selected)?;
        let name=data(transaction::intent_name_data(invocation))?;
        book.absent(self.root,&name)?;
        let receipt_name=format!(".restore-recovery-{invocation}.json");book.absent(self.root,&receipt_name)?;
        let writer=book.create_file(self.root,&name,Role::ReceiptWriter)?;
        let own_identity=applications::preservation_identity(book,writer)?;
        check(book.identity(writer)?.size==0&&book.identity(writer)?.mode==0o100600,"restore-recovery-empty-own-original")?;
        let mut attempts:Vec<AttemptBinding>=self.attempts.iter().map(|a|AttemptBinding{invocation:a.expected.invocation.clone(),
            request_id:a.expected.request.clone(),intent_sha256:hash(&a.expected.body),identity:a.expected.identity}).collect();
        attempts.sort_by(|a,b|a.invocation.cmp(&b.invocation));
        let wire=ReceiptWire{schema_version:1,kind:RECEIPT_KIND.into(),target:selected.target_data().target().into(),
            torn_invocation:self.base.invocation_data().into(),previous_state_sha256:history.current.state.digest_data().into(),
            previous_capsule_sha256:history.current.capsule.digest_data().into(),root:self.root_identity,stage:self.stage_identity,
            old_state:self.old_state,stage_sha256:archive_hex_text_data(&self.stage.commitment),
            own_attempt:OwnAttempt{invocation:invocation.into(),request_id:request.into(),identity:own_identity},attempts};
        let mut raw=serde_json::to_vec(&wire).map_err(|_|"restore-recovery-receipt-encode")?;raw.push(b'\n');
        let reference=data(transaction::RestoreReferenceData::new_data(self.base.invocation_data(),invocation,&hash(&raw)))?;
        let receipt=ReceiptData::parse(&raw,&reference,&self.base,(&history.current.state,&history.current.capsule),selected)?;
        // Adopt complete receipt before beginning its own linked intent body.
        let reader=book.record_file(self.root,&receipt_name,&raw,Role::ReceiptWriter)?;
        let receipt_identity=applications::preservation_identity(book,reader)?;held_bytes(book,reader,&raw)?;
        book.persist(self.root,false)?;book.forward_close(reader,"restore-recovery-new-receipt-close")?;
        #[cfg(feature="macos-installed-restore-own-attempt-fixture")]
        {
            // Parent's SAME reserved writer, after durable ownAttempt and
            // before canonical intent body/current assignment or worker spawn.
            check(!book.worker_stderr_is_gate && !book.worker_go_eof && book.maintenance.is_none()
                && !book.unknown && self.current.is_none() && !self.preservation.entered
                && book.payload_write_calls==0 && book.payload_written==0 && book.stage.is_none()
                && self.base.action_data()==ActionData::RestoreFixedApp
                && book.originals[reader].state==State::Closed && book.originals[reader].fd.is_none()
                && book.originals[writer].state==State::Owned && book.originals[writer].role==Role::ReceiptWriter
                && book.identity(writer)?.size==0 && book.identity(writer)?.mode==0o100600
                && applications::preservation_identity(book,writer)?==own_identity,
                "restore-fixture-own-attempt-boundary")?;
            book.registration_ready()?;held_bytes(book,history.state_original,&history.state_bytes)?;
            book.absent(self.root,paths::APP_NAME)?;book.check_name(writer,true)?;
            book.protected(writer,false,Some(0o600))?;book.clock()?;
            native::restore_fixture_abrupt_exit()
        }
        let (intent,body)=receipt.canonical_intent(&self.base,(&history.current.state,&history.current.capsule),selected)?;
        data(self.admission.retry_data(&intent,(&history.current.state,&history.current.capsule),selected))?;
        self.current=Some(reference);self.receipts.push(ReceiptObserved{data:receipt,identity:receipt_identity});
        let original=book.record_reserved_file(writer,&body)?;
        check(applications::preservation_identity(book,original)?==own_identity,"restore-recovery-own-intent-post")?;
        book.persist(self.root,false)?;held_bytes(book,original,&body)?;
        Ok((original,intent,body))
    }
    pub(super) fn reference(&self)->Option<&transaction::RestoreReferenceData>{self.current.as_ref()}
    pub(super) fn ready(&self,book:&mut Install,prepared:&PreparedFresh,history:&History,
        selected:&ReleaseSetData,intent:&IntentData)->Result<()> {
        let reference=self.current.as_ref().ok_or("restore-recovery-reference-required")?;
        check(intent.restore_recovery_data()==Some(reference),"restore-recovery-current-binding")?;
        data(self.admission.retry_data(intent,(&history.current.state,&history.current.capsule),selected))?;
        let receipt=self.receipts.last().ok_or("restore-recovery-receipt-required")?;
        removal_archive_scope(book,|book|{
            let (original,raw)=metadata_original(book,self.root,&data(transaction::intent_name_data(intent.invocation_data()))?,transaction::INTENT_LIMIT)?;
            let identity=applications::preservation_identity(book,original)?;
            receipt.data.own_original(intent.invocation_data(),intent.request_id_data(),identity)?;
            let (_,expected)=receipt.data.canonical_intent(&self.base,(&history.current.state,&history.current.capsule),selected)?;
            check(raw==expected&&hash(&raw)==intent.digest_data(),"restore-recovery-current-bytes")?;
            held_bytes(book,original,&raw)
        })?;
        self.post(book,prepared,history,selected)
    }
    pub(super) fn preserve(&mut self,book:&mut Install,prepared:&PreparedFresh,history:&History,
        selected:&ReleaseSetData,intent:&IntentData)->Result<()> {
        self.preservation.enter(book)?;
        let result=(||{
            self.ready(book,prepared,history,selected,intent)?;
            if self.stage_placement==transaction::RestoreOriginalPlacementData::Original {
                self.preservation.move_original(book,self.root,self.stage.original,self.stage_identity,
                    &format!(".install-{}",self.base.invocation_data()),
                    &format!(".restore-recovery-{}.stage",self.base.invocation_data()),true)?;
                self.stage_placement=transaction::RestoreOriginalPlacementData::Preserved;
                #[cfg(feature="macos-installed-restore-stage-move-fixture")]
                {
                    // The existing move owner has recorded/rebound the actual
                    // returned rename. No older intent has moved in this call.
                    check(book.worker_stderr_is_gate && book.worker_go_eof && !book.unknown
                        && intent.action_data()==ActionData::RestoreFixedApp && self.current.as_ref()==intent.restore_recovery_data()
                        && self.stage_placement==transaction::RestoreOriginalPlacementData::Preserved
                        && self.attempts.iter().all(|a|a.placement==transaction::RestoreOriginalPlacementData::Original)
                        && !self.attempts.is_empty() && book.payload_write_calls==0 && book.payload_written==0
                        && book.stage.is_none() && book.app.is_none() && book.runtime.is_none()
                        && book.runtime_publication=="not-attempted" && book.app_publication=="not-attempted",
                        "restore-fixture-stage-move-boundary")?;
                    book.registration_ready()?;held_bytes(book,history.state_original,&history.state_bytes)?;
                    book.absent(self.root,paths::APP_NAME)?;
                    book.absent(self.root,&format!(".install-{}",self.base.invocation_data()))?;
                    check(applications::preservation_identity(book,self.stage.original)?==self.stage_identity,
                        "restore-fixture-stage-original")?;
                    book.check_name(self.stage.original,true)?;book.protected(self.stage.original,true,Some(0o700))?;
                    book.clock()?;native::restore_fixture_abrupt_exit()
                }
            }
            for index in 0..self.attempts.len() {
                if self.attempts[index].placement==transaction::RestoreOriginalPlacementData::Preserved{continue;}
                let attempt=&self.attempts[index];
                let source=data(transaction::intent_name_data(&attempt.expected.invocation))?;
                let saved=format!(".restore-recovery-{}-{}.intent.json",self.base.invocation_data(),attempt.expected.invocation);
                removal_archive_scope(book,|book|{
                    let (reader,raw,file)=partial_fresh_writer_bytes(book,self.root,&source,transaction::INTENT_LIMIT)?;
                    check(applications::preservation_identity(book,reader)?==attempt.expected.identity&&hash(&raw)==attempt.raw_sha
                        &&raw.len()==attempt.raw_size&&file.identity.mode&0o7777==attempt.mode,"restore-recovery-attempt-before-move")?;
                    self.preservation.move_original(book,self.root,reader,attempt.expected.identity,&source,&saved,false)
                })?;
                self.attempts[index].placement=transaction::RestoreOriginalPlacementData::Preserved;
            }
            self.post(book,prepared,history,selected)?;
            check(self.attempts.iter().all(|a|a.placement==transaction::RestoreOriginalPlacementData::Preserved)
                && self.stage_placement==transaction::RestoreOriginalPlacementData::Preserved,"restore-recovery-preserved-required")?;
            book.persist(self.root,false)?;book.clock()?;self.preservation.settled=true;Ok(())
        })();result.map_err(|why|self.preservation.fail(why))
    }
    pub(super) fn complete(&self)->bool{self.preservation.complete()}
    pub(super) fn planned_receipt_bytes(&self)->u64{RECEIPT_LIMIT as u64}
}

struct GroupObserved {
    base:IntentData,base_raw:Vec<u8>,holder:IntentData,holder_identity:OriginalIdentityData,
    stage_identity:OriginalIdentityData,names:BTreeSet<String>,attempts:Vec<ExpectedAttempt>,
    files:u64,bytes:u64,payload_bytes:u64,original_quote:usize,control_reserved:usize,transport:RestoreStageSpanData,
}
// This borrowed witness exists ONLY during the original parent's post-join
// readback, before that exact new-State reader is closed. It is not restart
// admission for any post-publication or State-swap crash window.
struct CommittedRestore<'a> {
    root:usize,reader:usize,raw:&'a [u8],state:&'a StateData,
    intent:&'a IntentData,history:&'a History,
}
fn committed_restore_data(raw:&[u8],state:&StateData,intent:&IntentData,
    previous:(&StateData,&CapsuleData),selected:&ReleaseSetData)->Result<()> {
    check(intent.action_data()==ActionData::RestoreFixedApp && intent.restore_recovery_data().is_some()
        && intent.next_data()==selected.current_data() && state.invocation_data()==intent.invocation_data()
        && state.restore_recovery_data()==intent.restore_recovery_data(),"restore-recovery-committed-binding")?;
    let old=previous.0.current_data();let new=state.current_data();
    check(new.release_data()==old.release_data() && new.instance_data()==old.instance_data()
        && new.release_directory_data()==old.release_directory_data(),"restore-recovery-committed-runtime")?;
    let reproduced=data(StateData::encode_applied_data(intent,Some(previous),&new,selected))?;
    check(reproduced==raw && hash(raw)==state.digest_data(),"restore-recovery-committed-state")
}
impl<'a> CommittedRestore<'a> {
    fn new(book:&Install,root:usize,reader:usize,raw:&'a [u8],state:&'a StateData,
        intent:&'a IntentData,history:&'a History,selected:&ReleaseSetData)->Result<Self> {
        committed_restore_data(raw,state,intent,(&history.current.state,&history.current.capsule),selected)?;
        let witness=Self{root,reader,raw,state,intent,history};witness.post(book)?;Ok(witness)
    }
    fn post(&self,book:&Install)->Result<()> {
        check(self.reader!=self.history.state_original
            && book.originals[self.reader].parent==Some(self.root)
            && book.originals[self.reader].name==transaction::STATE_NAME
            && self.state.invocation_data()==self.intent.invocation_data(),"restore-recovery-committed-original")?;
        held_bytes(book,self.reader,self.raw)?;
        let archive=data(transaction::archived_state_name_data(self.history.current.state.invocation_data()))?;
        check(book.originals[self.history.state_original].parent==Some(self.root)
            && book.originals[self.history.state_original].name==archive,"restore-recovery-committed-old-placement")?;
        held_bytes(book,self.history.state_original,&self.history.state_bytes)?;book.clock()
    }
    fn archived_previous(&self,book:&Install,root:usize,previous:&Recorded)->Result<bool> {
        self.post(book)?;
        check(root==self.root,"restore-recovery-committed-root")?;
        Ok(previous.state.invocation_data()==self.history.current.state.invocation_data()
            && previous.state.digest_data()==self.history.current.state.digest_data()
            && previous.capsule.digest_data()==self.history.current.capsule.digest_data())
    }
}
fn previous_record<'a>(history:&'a History,intent:&IntentData)->Result<&'a Recorded> {
    let (id,sha)=intent.previous_state_data().ok_or("restore-recovery-prior-required")?;
    let record=if history.current.state.invocation_data()==id{&history.current}
        else{history.originals.get(id).ok_or("restore-recovery-prior-history")?};
    check(record.state.digest_data()==sha&&transaction::correspondence_data(intent,
        Some((&record.state,&record.capsule)),None,None)==transaction::CorrespondenceData::Pending,
        "restore-recovery-prior-correspondence")?;Ok(record)
}
fn with_recorded_index<T>(book:&mut Install,budget:&mut CaptureBudget,root:usize,base:&IntentData,previous:&Recorded,
    f:impl FnOnce(&mut Install,&installation_record::InventoryIndex<'_>)->Result<T>)->Result<T> {
    removal_archive_scope(book,|book| {
        let generation=previous.state.current_data();let binding=base.next_data().binding_data();
        check(generation.release_data()==base.next_data(),"restore-recovery-inventory-generation")?;
        let versions=book.open(Some(root),"versions",true)?;book.protected(versions,true,Some(0o755))?;
        let release=book.open(Some(versions),binding.release,true)?;
        check(book.matches_recorded_directory(release,generation.release_directory_data())?,"restore-recovery-release-original")?;
        book.protected(release,true,Some(0o755))?;
        let stat=book.named(Some(release),installation_record::INVENTORY_NAME).map_err(|_|"restore-recovery-inventory-name")?;
        let len=usize::try_from(stat.st_size).map_err(|_|"restore-recovery-inventory-size")?;
        check(len>0&&len<=installation_record::INVENTORY_LIMIT,"restore-recovery-inventory-size")?;
        let quote=len.checked_mul(8).and_then(|n|n.checked_add(installation_record::RECORD_LIMIT*4))
            .ok_or("restore-recovery-inventory-memory")?;
        budget.reserve(book,1,0,quote)?;
        let (reader,raw)=metadata_original(book,release,installation_record::INVENTORY_NAME,len)?;
        check(book.identity(reader)?==Identity::of(&stat)&&hash(&raw)==binding.inventory_sha256,"restore-recovery-signed-inventory")?;
        let descriptor=metadata_bytes(book,release,installation_record::RECORD_NAME,installation_record::RECORD_LIMIT)?;
        let expected=installation_record::Expected{kind:installation_record::Kind::Ordinary,source_commit:binding.source_commit,
            runtime_manifest:binding.runtime_manifest_sha256,install_root:book.recorded_directory(root)?,
            release_directory:book.recorded_directory(release)?};
        let record=installation_record::Record::parse_observed_for_release_data(&descriptor,&raw,&expected,base.next_data())?;
        check(record.instance()==generation.instance_data(),"restore-recovery-runtime-instance")?;
        let inventory=Inventory::parse_for_release(&raw,binding.runtime_manifest_sha256,binding.release)?;
        let quote=worker::reinstall_index_quote_data(&inventory)?;
        reserve_capture(book,budget,1,quote)?;
        let index=inventory.index()?;check((index.files.len(),index.directories.len())==(quote.0,quote.1),"restore-recovery-index-quote")?;
        let result=f(book,&index);held_bytes(book,reader,&raw)?;book.check_name(release,true)?;result
    })
}
// Pure transport/namespace result until the outer flat chain has resolved all
// prior-group dependencies and unified all invocation and original identities.
// A complete latest receipt alone does not construct an active PriorGroup.
fn read_preserved_group(book:&mut Install,root:usize,history:&History,selected:&ReleaseSetData,
    holder:&IntentData,committed:Option<&CommittedRestore<'_>>)->Result<GroupObserved> {
    let mut budget=CaptureBudget::default();
    let mut group=read_preserved_group_reserved(book,root,history,selected,holder,committed,&mut budget)?;
    // GroupObserved retains expected bodies and bounded names, not the parsed
    // receipt forest or inventory. A simultaneous old/new namespace is charged
    // once for EACH live result; the just-dropped parse workspace is reusable.
    let retained=group.attempts.len().checked_mul(transaction::INTENT_LIMIT*4+2048)
        .and_then(|n|n.checked_add(transaction::INTENT_LIMIT*4+64*1024))
        .and_then(|n|n.checked_add(group.names.iter().map(|s|s.len()+128).sum::<usize>()))
        .ok_or("restore-recovery-retained-memory")?;
    group.control_reserved=budget.retain(book,retained)?;Ok(group)
}
fn read_preserved_group_reserved(book:&mut Install,root:usize,history:&History,selected:&ReleaseSetData,
    holder:&IntentData,committed:Option<&CommittedRestore<'_>>,budget:&mut CaptureBudget)->Result<GroupObserved> {
    let reference=holder.restore_recovery_data().ok_or("restore-recovery-group-reference")?;
    let previous=previous_record(history,holder)?;
    // Transport later reparses the bounded whole receipt forest. Use its
    // same maximum temporary quote now, so the pre-effect namespace POST
    // proves that workspace beside the actual containing-owner reservations.
    reserve_capture(book,budget,transaction::INVOCATION_LIMIT,(0,0,0))?;
    let latest=metadata_bytes(book,root,&reference.receipt_name_data(),RECEIPT_LIMIT)?;
    check(hash(&latest)==reference.receipt_sha256_data(),"restore-recovery-group-receipt")?;
    let base_name=data(reference.preserved_intent_name_data(reference.torn_invocation_data()))?;
    let base_raw=metadata_bytes(book,root,&base_name,transaction::INTENT_LIMIT)?;
    let base=data(IntentData::parse_recorded_data(&base_raw,selected))?;
    check(base.invocation_data()==reference.torn_invocation_data(),"restore-recovery-group-base")?;
    let prior=(&previous.state,&previous.capsule);
    let last=ReceiptData::parse(&latest,reference,&base,prior,selected)?;
    reserve_capture(book,budget,last.wire.attempts.len()+1,(0,0,0))?;
    let mut raw_receipts=Vec::new();
    let mut names=BTreeSet::new();names.insert(reference.receipt_name_data());
    for row in &last.wire.attempts {
        if row.invocation==base.invocation_data(){continue;}
        let name=format!(".restore-recovery-{}.json",row.invocation);
        let raw=metadata_bytes(book,root,&name,RECEIPT_LIMIT)?;
        let ref_data=data(transaction::RestoreReferenceData::new_data(base.invocation_data(),&row.invocation,&hash(&raw)))?;
        raw_receipts.push(ReceiptData::parse(&raw,&ref_data,&base,prior,selected)?);
        check(names.insert(name),"restore-recovery-group-duplicate")?;
    }
    raw_receipts.push(last);
    let expected=chain_data(&raw_receipts,&base,&base_raw,prior,selected)?;
    let latest=raw_receipts.last().ok_or("restore-recovery-group-receipt")?;
    let own=expected.last().ok_or("restore-recovery-group-own")?;
    check(own.invocation==holder.invocation_data()&&hash(&own.body)==holder.digest_data(),"restore-recovery-group-holder")?;
    let own_identity=own.identity;
    let own_original=data(transaction::intent_name_data(holder.invocation_data()))?;
    // The holder may become exactly the next group's preserved BASE. Its
    // identity/body stay bound by this older immutable ownAttempt receipt.
    let own_preserved=format!(".restore-recovery-{}-{}.intent.json",holder.invocation_data(),holder.invocation_data());
    let a=optional_identity(book,root,&own_original)?;let b=optional_identity(book,root,&own_preserved)?;
    let place=data(transaction::RestoreOriginalPlacementData::compare_data(own_identity,a,b))?;
    let actual_name=match place {transaction::RestoreOriginalPlacementData::Original=>&own_original,
        transaction::RestoreOriginalPlacementData::Preserved=>&own_preserved};
    removal_archive_scope(book,|book| {
        let (reader,raw)=metadata_original(book,root,actual_name,transaction::INTENT_LIMIT)?;
        check(applications::preservation_identity(book,reader)?==own_identity&&raw==own.body,"restore-recovery-group-own-original")?;
        held_bytes(book,reader,&raw)
    })?;
    check(applications::preservation_identity(book,root)?==latest.wire.root,"restore-recovery-group-root")?;
    let archived=committed.map(|w|w.archived_previous(book,root,previous)).transpose()?.unwrap_or(false);
    let previous_name=if previous.state.invocation_data()==history.current.state.invocation_data()&&!archived{transaction::STATE_NAME.into()}
        else{data(transaction::archived_state_name_data(previous.state.invocation_data()))?};
    removal_archive_scope(book,|book| {
        let (reader,raw)=metadata_original(book,root,&previous_name,transaction::STATE_LIMIT)?;
        check(applications::preservation_identity(book,reader)?==latest.wire.old_state&&hash(&raw)==previous.state.digest_data(),
            "restore-recovery-group-old-state")?;held_bytes(book,reader,&raw)
    })?;
    let stage_name=reference.preserved_stage_name_data();
    book.absent(root,&format!(".install-{}",base.invocation_data()))?;
    let (stage,stage_identity)=with_recorded_index(book,budget,root,&base,previous,|book,index| {
        removal_archive_scope(book,|book| {
            let original=stage_at(book,root,&stage_name)?.ok_or("restore-recovery-group-stage")?;
            let identity=applications::preservation_identity(book,original)?;
            check(identity==latest.wire.stage,"restore-recovery-group-stage-original")?;
            let mut work=PartialFreshTreeWork::new(0)?;
            let stage=stage_observation(book,original,&base,index,None,&mut work)?;
            check(archive_hex_text_data(&stage.commitment)==latest.wire.stage_sha256,"restore-recovery-group-stage-content")?;
            Ok((stage,identity))
        })
    })?;
    names.insert(stage_name);
    let mut bytes=stage.control_bytes;let payload_bytes=stage.app.map_or(0,|a|a.bytes);
    let mut files=stage.control_files+stage.app.map_or(0,|a|a.files);
    for row in expected.iter().take(expected.len()-1) {
        let attempt=observe_attempt(book,root,base.invocation_data(),row.clone())?;
        check(attempt.placement==transaction::RestoreOriginalPlacementData::Preserved,"restore-recovery-group-not-preserved")?;
        check(names.insert(data(reference.preserved_intent_name_data(&row.invocation))?),"restore-recovery-group-name")?;
        bytes=bytes.checked_add(attempt.raw_size as u64).ok_or("restore-recovery-group-storage")?;files+=1;
    }
    for receipt in &raw_receipts {bytes=bytes.checked_add(receipt.raw.len() as u64).ok_or("restore-recovery-group-storage")?;files+=1;}
    check(bytes.checked_add(payload_bytes).is_some_and(|n|n<=installation_record::PAYLOAD_LIMIT),"restore-recovery-group-storage")?;
    let holder=data(IntentData::parse_recorded_data(&own.body,selected))?;
    let original_quote=stage_original_quote(&stage,expected.len(),raw_receipts.len())?;
    let transport=RestoreStageSpanData::observed(reference,latest.wire.root,stage_identity,&stage)?;
    Ok(GroupObserved{base,base_raw,holder,holder_identity:own_identity,stage_identity,names,attempts:expected,files,bytes,payload_bytes,original_quote,control_reserved:0,transport})
}

// Flat, bounded group closure. No receipt grants recursive authority. Every
// group is fully audited before a holder->next-base overlap can be recognized.
pub(super) struct Namespace {
    pub(super) names:BTreeSet<String>,pub(super) files:u64,pub(super) bytes:u64,pub(super) payload_bytes:u64,
    pub(super) attempts:usize,groups:Vec<GroupObserved>,facts:InstallInvocationSetData,
}
impl Namespace {
    pub(super) fn merge_facts(&self,facts:&mut InstallInvocationSetData)->Result<()> {facts.merge(&self.facts)}
    pub(super) fn future_originals(&self)->Result<usize> {
        // Parent prepare POST + postjoin group census; the worker uses no
        // more scans. Existing earlier reads are already in book.originals.
        self.groups.iter().try_fold(0usize,|n,g|n.checked_add(g.original_quote.checked_mul(2)?))
            .ok_or("restore-recovery-future-originals")
    }
    fn group_for(&self,reference:&transaction::RestoreReferenceData)->Result<&GroupObserved> {
        self.groups.iter().find(|g|g.holder.restore_recovery_data()==Some(reference))
            .ok_or("restore-recovery-prior-group-required")
    }
    fn admission(&self,base:&IntentData,history:&History,selected:&ReleaseSetData)->Result<RestorePrepublicationData> {
        let prior=(&history.current.state,&history.current.capsule);
        match base.restore_recovery_data() {
            None=>data(RestorePrepublicationData::from_recorded_data(base,prior,selected)),
            Some(reference)=>{
                let group=self.group_for(reference)?;
                check(group.holder.digest_data()==base.digest_data()&&group.holder.invocation_data()==base.invocation_data(),
                    "restore-recovery-prior-group-holder")?;
                data(RestorePrepublicationData::from_preserved_retry_data(base,&group.base,prior,selected))
            },
        }
    }
    fn close_groups(mut groups:Vec<GroupObserved>,history:&History,selected:&ReleaseSetData)->Result<Self> {
        check(groups.len()<transaction::INVOCATION_LIMIT,"restore-recovery-group-count")?;
        let mut facts=InstallInvocationSetData::empty();
        for record in history.originals.values().chain(std::iter::once(&history.current)) {
            check(facts.insert(InstallInvocationFactData::intent(&record.intent)?)?,"restore-recovery-history-duplicate")?;
        }
        let completed=facts.len;
        let mut holders=BTreeMap::new();
        for (index,group) in groups.iter().enumerate() {
            check(holders.insert(group.holder.invocation_data().to_owned(),index).is_none(),"restore-recovery-group-holder-duplicate")?;
        }
        let mut linked=BTreeSet::new();
        for group in &groups {
            let mut current=group;let mut seen=BTreeSet::new();
            for _ in 0..=groups.len() {
                check(seen.insert(current.holder.invocation_data()),"restore-recovery-group-cycle")?;
                let Some(reference)=current.base.restore_recovery_data()else{break;};
                let prior=&groups[*holders.get(reference.receipt_invocation_data()).ok_or("restore-recovery-group-parent")?];
                check(prior.holder.restore_recovery_data()==Some(reference)
                    && prior.holder.digest_data()==current.base.digest_data()
                    && prior.holder_identity==current.attempts.first().ok_or("restore-recovery-group-base")?.identity
                    && prior.base.previous_state_data()==current.base.previous_state_data()
                    && prior.base.next_data()==current.base.next_data(),"restore-recovery-group-link")?;
                current=prior;
            }
            check(current.base.restore_recovery_data().is_none(),"restore-recovery-group-cycle")?;
            if let Some(reference)=group.base.restore_recovery_data() {
                check(linked.insert(reference.receipt_invocation_data().to_owned()),"restore-recovery-group-fork")?;
            }
        }
        let mut names=BTreeSet::new();let mut files=0u64;let mut bytes=0u64;let mut payload_bytes=0u64;
        // Each historical completed holder, or the one exact parent-holder /
        // child-base edge, is counted once. Other duplicate IDs/originals are
        // refused even when signed content happens to be byte-identical.
        let mut seen:BTreeMap<String,(OriginalIdentityData,Option<String>)>=BTreeMap::new();
        let mut original_owner:BTreeMap<u64,String>=BTreeMap::new();
        for group in &groups {
            check(original_owner.insert(group.stage_identity.inode,
                format!("stage:{}",group.base.invocation_data())).is_none(),"restore-recovery-group-original-alias")?;
            for row in &group.attempts {
                let parsed=data(IntentData::parse_recorded_data(&row.body,selected))?;
                let fact=InstallInvocationFactData::intent(&parsed)?;
                let edge=if row.invocation==group.base.invocation_data(){group.base.restore_recovery_data().map(|r|r.receipt_invocation_data().to_owned())}
                    else{None};
                if let Some((identity,old_edge))=seen.get(&row.invocation) {
                    let is_holder=row.invocation==group.holder.invocation_data();
                    check(*identity==row.identity&&((edge.as_deref()==Some(row.invocation.as_str())&&holders.contains_key(&row.invocation))
                        ||is_holder&&old_edge.as_deref()==Some(row.invocation.as_str())),"restore-recovery-cross-group-duplicate")?;
                }else {
                    check(original_owner.insert(row.identity.inode,row.invocation.clone()).is_none(),
                        "restore-recovery-group-original-alias")?;
                    seen.insert(row.invocation.clone(),(row.identity,edge));
                }
                let inserted=facts.insert(fact)?;
                check(inserted||holders.contains_key(&row.invocation),"restore-recovery-group-history-reuse")?;
            }
            for name in &group.names {check(names.insert(name.clone()),"restore-recovery-group-name-overlap")?;}
            files=files.checked_add(group.files).ok_or("restore-recovery-group-storage")?;
            payload_bytes=payload_bytes.checked_add(group.payload_bytes).ok_or("restore-recovery-group-storage")?;
            bytes=bytes.checked_add(group.bytes).filter(|n|*n<=installation_record::PAYLOAD_LIMIT).ok_or("restore-recovery-group-storage")?;
        }
        groups.sort_by(|a,b|a.holder.invocation_data().cmp(b.holder.invocation_data()));
        Ok(Self{names,files,bytes,payload_bytes,attempts:facts.len.checked_sub(completed).ok_or("restore-recovery-group-count")?,groups,facts})
    }
}
// `pending` is ONLY an actually read source-bound next torn base, never an IPC
// selector. Every completed root comes from already genuine history; every
// additional edge comes from exact receipt/body/original audit of its child.
pub(super) fn namespace(book:&mut Install,root:usize,history:&History,selected:&ReleaseSetData,
    pending:Option<&IntentData>)->Result<Namespace> {
    namespace_at(book,root,history,selected,pending,None)
}
fn namespace_at(book:&mut Install,root:usize,history:&History,selected:&ReleaseSetData,
    pending:Option<&IntentData>,committed:Option<&CommittedRestore<'_>>)->Result<Namespace> {
    if let Some(witness)=committed {witness.post(book)?;}
    let mut queue=Vec::new();
    for record in history.originals.values().chain(std::iter::once(&history.current)) {
        if record.intent.restore_recovery_data().is_none(){continue;}
        let raw=metadata_bytes(book,root,&data(transaction::intent_name_data(record.intent.invocation_data()))?,transaction::INTENT_LIMIT)?;
        check(hash(&raw)==record.intent.digest_data(),"restore-recovery-completed-holder")?;
        queue.push(data(IntentData::parse_recorded_data(&raw,selected))?);
    }
    if let Some(pending)=pending {
        if pending.restore_recovery_data().is_some() {
            let raw=metadata_bytes(book,root,&data(transaction::intent_name_data(pending.invocation_data()))?,transaction::INTENT_LIMIT)?;
            check(hash(&raw)==pending.digest_data(),"restore-recovery-pending-holder")?;
            queue.push(data(IntentData::parse_data(&raw,selected))?);
        }
    }
    let mut groups:Vec<GroupObserved>=Vec::new();
    while let Some(holder)=queue.pop() {
        if let Some(old)=groups.iter().find(|g|g.holder.invocation_data()==holder.invocation_data()) {
            check(old.holder.digest_data()==holder.digest_data()&&old.holder.restore_recovery_data()==holder.restore_recovery_data(),
                "restore-recovery-group-holder-conflict")?;continue;
        }
        check(groups.len()<transaction::INVOCATION_LIMIT,"restore-recovery-group-count")?;
        let group=read_preserved_group(book,root,history,selected,&holder,committed)?;
        if group.base.restore_recovery_data().is_some(){queue.push(data(IntentData::parse_recorded_data(&group.base_raw,selected))?);}
        groups.push(group);
    }
    let result=Namespace::close_groups(groups,history,selected)?;
    if let Some(capture)=book.removal_snapshot_capture.as_mut() {for group in &result.groups {capture.restore_stage(group.transport)?;}}
    if let Some(witness)=committed {witness.post(book)?;}
    Ok(result)
}

impl Namespace {
    fn commitment(&self)->[u8;32] {
        let mut hash=Sha256::new();hash.update(b"MRK-RESTORE-NAMESPACE-v1\0");
        hash.update(names_commitment(&self.names));hash.update(self.facts.commitment());
        for number in [self.files,self.bytes,self.payload_bytes,self.groups.len() as u64] {hash.update(number.to_le_bytes());}
        // close_groups sorts by holder invocation. Full body digests bind each
        // reference; original birth identities bind custody. No names travel
        // over INIT and this summary never replaces the local full audit.
        for group in &self.groups {
            hash.update(group.base.digest_data().as_bytes());hash.update(group.holder.digest_data().as_bytes());
            for identity in [group.holder_identity,group.stage_identity] {
                hash.update(identity.device.to_le_bytes());hash.update(identity.inode.to_le_bytes());
                hash.update(identity.birth_seconds.to_le_bytes());hash.update(identity.birth_nanoseconds.to_le_bytes());
            }
        }hash.finalize().into()
    }
    pub(super) fn binding(&self)->serde_json::Value {
        serde_json::json!({"commitment":archive_hex_text_data(&self.commitment()),"groups":self.groups.len(),
            "names":self.names.len(),"files":self.files,"controlBytes":self.bytes,"payloadBytes":self.payload_bytes})
    }
    pub(super) fn fresh_ids(&self,invocation:&str,request:&str)->Result<()> {
        let invocation=archive_hex_data(invocation)?;let request=archive_hex_data(request)?;
        check(invocation!=request&&self.facts.len<transaction::INVOCATION_LIMIT
            && self.facts.rows[..self.facts.len].iter().flatten().all(|f|f.disjoint(invocation,Some(request))),
            "restore-recovery-namespace-replay")
    }
    pub(super) fn post(&self,book:&mut Install,root:usize,history:&History,selected:&ReleaseSetData)->Result<()> {
        let mut groups=Vec::new();
        for group in &self.groups {groups.push(read_preserved_group(book,root,history,selected,&group.holder,None)?);}
        let actual=Self::close_groups(groups,history,selected)?;
        check(actual.binding()==self.binding(),"restore-recovery-namespace-post")?;
        let charged=actual.groups.iter().try_fold(0usize,|n,g|n.checked_add(g.control_reserved))
            .ok_or("restore-recovery-retained-memory")?;
        drop(actual);retire_control(book,charged)
    }
}
// Called only after state_after_join reproduced the current State and rebound
// the held old State to its exact archive. Do NOT call active Observation.post:
// it intentionally requires an absent App and unchanged canonical old State.
pub(in crate::installer) struct JoinedNamespace {namespace:Namespace,names:BTreeSet<String>,before:[u8;32],intent:[u8;32]}
fn names_commitment(names:&BTreeSet<String>)->[u8;32] {
    let mut hash=Sha256::new();hash.update(b"MRK-RESTORE-ROOT-CENSUS-v1\0");
    for name in names {hash.update((name.len() as u64).to_le_bytes());hash.update(name.as_bytes());}
    hash.finalize().into()
}
impl JoinedNamespace {
    pub(super) fn update_original_names(&self,names:&mut BTreeSet<String>,intent:&IntentData)->Result<()> {
        check(intent.action_data()==ActionData::RestoreFixedApp&&archive_hex_data::<32>(intent.digest_data())?==self.intent
            && names_commitment(names)==self.before,"restore-recovery-archive-original-census")?;
        names.retain(|name|self.names.contains(name));
        for name in &self.names {names.insert(name.clone());}
        check(self.namespace.names.is_subset(names),"restore-recovery-archive-preserved-census")
    }
}
pub(super) fn after_join(book:&mut Install,prepared:&PreparedFresh,history:&History,selected:&ReleaseSetData,
    intent:&IntentData,reader:usize,raw:&[u8],state:&StateData,prior:&Namespace,
    active:&Observation,original_names:&BTreeSet<String>)->Result<JoinedNamespace> {
    let witness=CommittedRestore::new(book,prepared.destination,reader,raw,state,intent,history,selected)?;
    check(active.current.as_ref()==intent.restore_recovery_data()
        && active.root==prepared.destination,"restore-recovery-after-join-reference")?;
    // Rebind the parent's SAME held stage after authenticating the exact
    // preserved group. Descendant/index summaries never substitute for its FD.
    let actual=namespace_at(book,prepared.destination,history,selected,Some(intent),Some(&witness))?;
    let group=actual.group_for(intent.restore_recovery_data().ok_or("restore-recovery-reference-required")?)?;
    check(group.base.digest_data()==active.base.digest_data() && group.stage_identity==active.stage_identity,
        "restore-recovery-after-join-stage")?;
    for old in &prior.groups {
        let next=actual.group_for(old.holder.restore_recovery_data().ok_or("restore-recovery-prior-reference")?)?;
        check(next.base.digest_data()==old.base.digest_data() && next.holder.digest_data()==old.holder.digest_data()
            && next.holder_identity==old.holder_identity && next.stage_identity==old.stage_identity
            && next.names==old.names,"restore-recovery-after-join-prior")?;
    }
    rebind_preserved(book,active.stage.original,prepared.destination,
        &intent.restore_recovery_data().ok_or("restore-recovery-reference-required")?.preserved_stage_name_data())?;
    check(applications::preservation_identity(book,active.stage.original)?==active.stage_identity,
        "restore-recovery-after-join-stage-original")?;
    let quote=original_names.iter().try_fold(0usize,|n,name|n.checked_add(name.len()+128))
        .and_then(|n|n.checked_add(actual.names.iter().map(|name|name.len()+128).sum::<usize>()))
        .ok_or("restore-recovery-final-census-memory")?;
    check(removal_effective_control_bytes(book)?.checked_add(quote as u64)
        .is_some_and(|n|n<=installation_record::CONTROL_LIMIT as u64),"restore-recovery-final-census-memory")?;
    book.removal_control_reserved=book.removal_control_reserved.checked_add(quote as u64)
        .ok_or("restore-recovery-final-census-memory")?;
    let mut wanted=original_names.clone();let mut before=BTreeSet::new();let mut ignored_bytes=0;
    active.root_names(&mut before,&mut ignored_bytes)?;
    for name in before.iter().chain(prior.names.iter()) {wanted.remove(name);}
    for name in &actual.names {check(wanted.insert(name.clone()),"restore-recovery-final-census-overlap")?;}
    wanted.insert(data(transaction::intent_name_data(intent.invocation_data()))?);
    wanted.insert(format!(".install-{}",intent.invocation_data()));
    wanted.insert(data(transaction::archived_state_name_data(history.current.state.invocation_data()))?);
    wanted.insert(paths::APP_NAME.into());wanted.insert(paths::REGISTRATION_GATE_NAME.into());
    book.absent(prepared.destination,&data(transaction::capsule_name_data(intent.invocation_data()))?)?;
    exact_roster(book,prepared.destination,&wanted)?;
    witness.post(book)?;Ok(JoinedNamespace{namespace:actual,names:wanted,before:names_commitment(original_names),
        intent:archive_hex_data(intent.digest_data())?})
}

// Nomination only: neither a matching filename nor a complete receipt makes
// this an admitted action. Full capture and closed root census follow it.
pub(super) fn nominate_base(book:&mut Install,root:usize,history:&History,selected:&ReleaseSetData,
    completed:&Namespace,pending:Option<&str>)->Result<Option<IntentData>> {
    let mut budget=CaptureBudget::default();
    let result=nominate_base_reserved(book,root,history,selected,completed,pending,&mut budget)?;
    if budget.charged!=0 {budget.retain(book,if result.is_some(){transaction::INTENT_LIMIT*4+64*1024}else{0})?;}
    Ok(result)
}
fn nominate_base_reserved(book:&mut Install,root:usize,history:&History,selected:&ReleaseSetData,
    completed:&Namespace,pending:Option<&str>,budget:&mut CaptureBudget)->Result<Option<IntentData>> {
    let names=roster_now(book,root)?;
    let candidates:Vec<String>=names.keys().filter_map(|name|fixed_intent_id(name))
        .filter(|id|!historical(history,id)&&Some(*id)!=pending).map(str::to_owned).collect();
    check(candidates.len()<=transaction::INVOCATION_LIMIT,"restore-recovery-nomination-bound")?;
    if !candidates.is_empty()||names.keys().any(|name|!completed.names.contains(name)&&fixed_receipt_id(name).is_some()) {
        reserve_capture(book,budget,1,(0,0,0))?;
    }
    let mut staged=None;
    for id in &candidates {
        match book.named(Some(root),&format!(".install-{id}")) {
            Err(Errno::ENOENT)=>{},Err(_)=>return Err("restore-recovery-nomination-stage"),
            Ok(_)=>{check(staged.is_none(),"restore-recovery-multiple-current-stages")?;staged=Some(id.clone());},
        }
    }
    let mut bases=BTreeSet::new();
    if let Some(id)=staged{bases.insert(id);}else{
        for name in names.keys().filter(|name|!completed.names.contains(*name)&&fixed_receipt_id(name).is_some()) {
            let raw=metadata_bytes(book,root,name,RECEIPT_LIMIT)?;
            let value=mobile_release_desktop::protocol::strict_json(&raw).map_err(|_|"restore-recovery-nomination-receipt")?;
            let id=value.get("tornInvocation").and_then(|v|v.as_str()).filter(|v|id_data(v))
                .ok_or("restore-recovery-nomination-base")?;bases.insert(id.to_owned());
            check(bases.len()<transaction::INVOCATION_LIMIT,"restore-recovery-nomination-bound")?;
        }
        if bases.is_empty(){
            if candidates.is_empty(){return Ok(None);}
            // No durable complete phase means no preservation effect may be
            // attempted. Capturing a fresh identity would fabricate authority.
            return Err("restore-recovery-created-receipt-required");
        }
    }
    let mut parsed=Vec::new();let mut referenced=BTreeSet::new();
    for id in bases {
        check(!historical(history,&id)&&Some(id.as_str())!=pending,"restore-recovery-nomination-history")?;
        let original=data(transaction::intent_name_data(&id))?;
        let saved=format!(".restore-recovery-{id}-{id}.intent.json");
        let a=optional_identity(book,root,&original)?;let b=optional_identity(book,root,&saved)?;
        check(a.is_some()!=b.is_some(),"restore-recovery-nomination-placement")?;
        let raw=metadata_bytes(book,root,if a.is_some(){&original}else{&saved},transaction::INTENT_LIMIT)?;
        let intent=data(IntentData::parse_data(&raw,selected))?;
        check(intent.invocation_data()==id&&intent.action_data()==ActionData::RestoreFixedApp,"restore-recovery-nomination-action")?;
        if let Some(reference)=intent.restore_recovery_data(){referenced.insert(reference.torn_invocation_data().to_owned());}
        parsed.push(intent);
    }
    parsed.retain(|base|!referenced.contains(base.invocation_data()));
    check(parsed.len()==1,"restore-recovery-nomination-chain")?;
    Ok(parsed.pop())
}
impl Observation {
    pub(super) fn root_names(&self,names:&mut BTreeSet<String>,bytes:&mut u64)->Result<()> {
        let stage_name=match self.stage_placement {transaction::RestoreOriginalPlacementData::Original=>format!(".install-{}",self.base.invocation_data()),
            transaction::RestoreOriginalPlacementData::Preserved=>format!(".restore-recovery-{}.stage",self.base.invocation_data())};
        check(names.insert(stage_name),"restore-recovery-root-role-overlap")?;
        *bytes=bytes.checked_add(self.stage.control_bytes).ok_or("restore-recovery-evidence-storage")?;
        for attempt in &self.attempts {
            let name=match attempt.placement {transaction::RestoreOriginalPlacementData::Original=>data(transaction::intent_name_data(&attempt.expected.invocation))?,
                transaction::RestoreOriginalPlacementData::Preserved=>format!(".restore-recovery-{}-{}.intent.json",self.base.invocation_data(),attempt.expected.invocation)};
            check(names.insert(name),"restore-recovery-root-role-overlap")?;
            *bytes=bytes.checked_add(attempt.raw_size as u64).ok_or("restore-recovery-evidence-storage")?;
        }
        for receipt in &self.receipts {
            check(names.insert(format!(".restore-recovery-{}.json",receipt.data.wire.own_attempt.invocation)),"restore-recovery-root-role-overlap")?;
            *bytes=bytes.checked_add(receipt.data.raw.len() as u64).ok_or("restore-recovery-evidence-storage")?;
        }
        check(*bytes<=installation_record::PAYLOAD_LIMIT,"restore-recovery-evidence-storage")
    }
    pub(super) fn payload_cost(&self)->GenerationCostData {
        // Metadata bytes are separately charged by root_names; count physical
        // metadata leaves here without charging those bytes a second time.
        GenerationCostData{files:self.stage.app.map_or(0,|a|a.files)+self.stage.control_files
            +self.attempts.len() as u64+self.receipts.len() as u64,
            bytes:self.stage.app.map_or(0,|a|a.bytes)}
    }
    pub(super) fn attempt_count(&self)->usize{self.attempts.len()}
    pub(super) fn future_originals(&self)->Result<usize> {
        // Worker read-intent POST, preserve READY and preserve POST. Parent
        // creation/postjoin is bounded by the same quote. Include the one
        // next immutable receipt/current intent and every actual prior move.
        stage_original_quote(&self.stage,self.attempts.len()+1,self.receipts.len()+1)?
            .checked_mul(3).and_then(|n|n.checked_add(self.attempts.len().checked_mul(4)?))
            .ok_or("restore-recovery-future-originals")
    }
    pub(super) fn merge_facts(&self,facts:&mut InstallInvocationSetData)->Result<()> {
        for attempt in &self.attempts {
            facts.insert(InstallInvocationFactData::new(archive_hex_data(&attempt.expected.invocation)?,
                archive_hex_data(&attempt.expected.request)?,archive_hex_data(&hash(&attempt.expected.body))?)?)?;
        }Ok(())
    }
    pub(super) fn binding(&self)->Result<serde_json::Value> {
        let reference=self.current.as_ref().ok_or("restore-recovery-reference-required")?;
        Ok(serde_json::json!({"reference":reference,"root":self.root_identity,"oldState":self.old_state,
            "stage":self.stage_identity,"stageSha256":archive_hex_text_data(&self.stage.commitment),
            "baseIntentSha256":self.base.digest_data(),"priorAttempts":self.attempts.len()}))
    }
    pub(super) fn fresh_ids(&self,invocation:&str,request:&str)->Result<()> {
        let invocation=archive_hex_data(invocation)?;let request=archive_hex_data(request)?;
        check(invocation!=request,"restore-recovery-fresh-identity")?;
        for attempt in &self.attempts {
            let fact=InstallInvocationFactData::new(archive_hex_data(&attempt.expected.invocation)?,
                archive_hex_data(&attempt.expected.request)?,archive_hex_data(&hash(&attempt.expected.body))?)?;
            check(fact.disjoint(invocation,Some(request)),"restore-recovery-invocation-replay")?;
        }
        Ok(())
    }
}

// Actual returned effects are absorbing and remain in the SAME worker Book.
// Constructors/caller wiring below must retain this state on every Result path.
fn rebind_preserved(book:&mut Install,original:usize,root:usize,name:&str)->Result<()> {
    // The ordinary App/State rebind deliberately requires 0555/0444. A
    // preserved unfinished stage/intent must instead KEEP its exact 0700 or
    // 0600 mode; sealing it here would complete an earlier writer's object.
    let before=book.identity(original)?;let mode=before.mode&0o7777;
    let directory=before.mode&0o170000==0o040000;
    check(if directory {mode==0o700}else{before.mode&0o170000==0o100000&&matches!(mode,0o600|0o444)},
        "restore-recovery-rebind-mode")?;
    let actual=stat::fstat(book.fd(original)?).map_err(|_|"restore-recovery-rebind-stat")?;
    let named=book.named(Some(root),name).map_err(|_|"restore-recovery-rebind-name")?;
    check(actual.st_flags==0&&named.st_flags==0&&Identity::of(&actual)==Identity::of(&named)
        && same_renamed(before,Identity::of(&actual)),"restore-recovery-rebind-original")?;
    book.originals[original].parent=Some(root);book.originals[original].name=name.into();
    book.originals[original].identity=Some(Identity::of(&actual));
    book.protected(original,directory,Some(mode))?;
    native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_|"restore-recovery-rebind-attributes")?;
    book.check_name(original,true)
}
struct Preservation {
    entered: bool, settled: bool, returned: ReturnedData, first: Option<&'static str>,
}
impl Preservation {
    fn fresh() -> Self {Self {entered:false,settled:false,returned:ReturnedData::KnownRefusal,first:None}}
    fn fail(&mut self,why:&'static str) -> &'static str {*self.first.get_or_insert(why)}
    fn returned(&mut self,value:ReturnedData) {
        if self.returned==ReturnedData::Unknown || value==ReturnedData::Unknown {self.returned=ReturnedData::Unknown;}
        else if value==ReturnedData::KnownSuccess {self.returned=value;}
    }
    fn enter(&mut self,book:&Install) -> Result<()> {
        check(!self.entered && !self.settled && self.first.is_none(),"restore-recovery-preservation-once")?;
        self.entered=true;
        let result=(||{
            check(book.worker_stderr_is_gate && book.worker_go_eof && book.registration.verified
                && book.gate.verified,"restore-recovery-original-go-required")?;
            book.clock()
        })();result.map_err(|why|self.fail(why))
    }
    fn move_original(&mut self,book:&mut Install,root:usize,original:usize,
        expected:OriginalIdentityData,source:&str,destination:&str,directory:bool) -> Result<()> {
        let result=(||{
            check(self.entered && !self.settled && self.first.is_none(),"restore-recovery-preservation-state")?;
            book.clock()?;book.check_name(root,false)?;
            let before=book.identity(original)?;let mode=before.mode&0o7777;
            check(book.originals[original].parent==Some(root) && book.originals[original].name==source
                && before.dev==book.identity(root)?.dev
                && if directory {mode==0o700}else{matches!(mode,0o444|0o600)},"restore-recovery-move-original")?;
            book.check_name(original,true)?;book.protected(original,directory,Some(mode))?;
            native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_|"restore-recovery-move-attributes")?;
            check(applications::preservation_identity(book,original)?==expected,"restore-recovery-move-original")?;
            book.absent(root,destination)?;book.clock()?;
            match native::publish_directory(book.fd(root)?.as_fd(),source,book.fd(root)?.as_fd(),destination) {
                Ok(())=>self.returned(ReturnedData::KnownSuccess),
                Err(error)=>{
                    let observed=if error.raw_os_error()==Some(Errno::EEXIST as i32) {ReturnedData::KnownRefusal}
                        else{book.unknown=true;ReturnedData::Unknown};
                    self.returned(observed);return Err("restore-recovery-exclusive-move");
                },
            }
            // Native return is latched before rebind, flush or any POST can
            // fail. Only this known own rename permits the ctime rebind.
            rebind_preserved(book,original,root,destination)?;
            check(same_renamed(before,book.identity(original)?)
                && applications::preservation_identity(book,original)?==expected,"restore-recovery-move-post")?;
            book.protected(original,directory,Some(mode))?;
            native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_|"restore-recovery-move-attributes")?;
            book.absent(root,source)?;book.persist(root,false)?;book.check_name(original,true)?;book.clock()
        })();result.map_err(|why|self.fail(why))
    }
    fn complete(&self) -> bool {self.entered && self.settled && self.first.is_none() && self.returned!=ReturnedData::Unknown}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restore_receipt_chain_binds_own_original_and_rejects_forks_cycles_or_replaced_prior_rows() {
        for intel in [false,true] {
            let (snapshot,_)=removal_archive_test_snapshot(intel,0);
            let (_,header,_)=removal_archive_test_parse(&snapshot,true).unwrap();let header=header.unwrap();
            let spans=parse_removal_genesis_data(snapshot.len() as u64,&"2".repeat(32),|at,out|{
                let at=at as usize;let n=out.len().min(snapshot.len().saturating_sub(at));
                out[..n].copy_from_slice(&snapshot[at..at+n]);Ok(n)
            }).unwrap();
            let selected=ReleaseSetData::parse_for_target_data(spans.selected_bytes_data(),header.target).unwrap();
            let id=|n:u32|format!("{n:032x}");
            let identity=|n:u64|OriginalIdentityData{device:1,inode:n,birth_seconds:10,birth_nanoseconds:1, volume_uuid: None };
            let initial=data(IntentData::parse_data(&IntentData::encode_data(&id(1),&id(101),ActionData::FreshInstall,None,&selected).unwrap(),&selected)).unwrap();
            let generation=transaction::GenerationData::from_original_fields_data(&selected,selected.current_data(),&id(1),
                installation_record::DirectoryIdentity{device:1,inode:10,mode:0o040755,uid:0,gid:0,flags:0, volume_uuid: None },
                transaction::AppIdentityData::from_original_fields_data(1,11,0o040555,0,0,0).unwrap()).unwrap();
            let state=StateData::parse_data(&StateData::encode_applied_data(&initial,None,&generation,&selected).unwrap(),&selected).unwrap();
            let capsule=CapsuleData::parse_data(&CapsuleData::encode_data(&initial,None,Some(&state),Some(selected.current_data()),
                transaction::RecordedOutcomeData::Applied,transaction::WriterObservationData{returned:true,exit_code:Some(0),
                    original_joined:true,result_eof:true,original_closes_known:true,within_original_deadline:true,
                    payload_write_count:1,payload_write_bytes:1},&selected).unwrap(),&selected).unwrap();
            let previous=(&state,&capsule);
            let base_raw=IntentData::encode_data(&id(2),&id(102),ActionData::RestoreFixedApp,Some(previous),&selected).unwrap();
            let base=IntentData::parse_data(&base_raw,&selected).unwrap();
            let first=ReceiptWire{schema_version:1,kind:RECEIPT_KIND.into(),target:selected.target_data().target().into(),
                torn_invocation:id(2),previous_state_sha256:state.digest_data().into(),previous_capsule_sha256:capsule.digest_data().into(),
                root:identity(20),stage:identity(21),old_state:identity(22),stage_sha256:"a".repeat(64),
                own_attempt:OwnAttempt{invocation:id(3),request_id:id(103),identity:identity(24)},
                attempts:vec![AttemptBinding{invocation:id(2),request_id:id(102),intent_sha256:base.digest_data().into(),identity:identity(23)}]};
            let parse=|wire:&ReceiptWire| {
                let mut raw=serde_json::to_vec(wire).unwrap();raw.push(b'\n');
                let reference=transaction::RestoreReferenceData::new_data(&id(2),&wire.own_attempt.invocation,&hash(&raw)).unwrap();
                ReceiptData::parse(&raw,&reference,&base,previous,&selected)
            };
            let first_data=parse(&first).unwrap();
            assert!(first_data.own_original(&id(3),&id(103),identity(24)).is_ok());
            assert!(first_data.own_original(&id(3),&id(103),identity(25)).is_err());
            let expected=chain_data(&[first_data],&base,&base_raw,previous,&selected).unwrap();
            assert_eq!(expected.len(),2);assert_eq!(expected[1].invocation,id(3));
            // Exact Applied Restore bytes are necessary comparison DATA, not
            // a held-new-State witness or proof of an original worker join.
            let current=IntentData::parse_data(&expected[1].body,&selected).unwrap();
            let restored=transaction::GenerationData::from_original_fields_data(&selected,selected.current_data(),&id(1),
                generation.release_directory_data(),
                transaction::AppIdentityData::from_original_fields_data(1,31,0o040555,0,0,0).unwrap()).unwrap();
            let applied_raw=StateData::encode_applied_data(&current,Some(previous),&restored,&selected).unwrap();
            let applied=StateData::parse_data(&applied_raw,&selected).unwrap();
            assert!(committed_restore_data(&applied_raw,&applied,&current,previous,&selected).is_ok());
            assert!(committed_restore_data(&applied_raw,&applied,&base,previous,&selected).is_err());
            assert!(committed_restore_data(&applied_raw,&state,&current,previous,&selected).is_err());
            let mut changed=applied_raw.clone();changed.push(b' ');
            assert!(committed_restore_data(&changed,&applied,&current,previous,&selected).is_err());
            let mut next=first.clone();next.own_attempt=OwnAttempt{invocation:id(4),request_id:id(104),identity:identity(25)};
            next.attempts.push(AttemptBinding{invocation:id(3),request_id:id(103),intent_sha256:hash(&expected[1].body),identity:identity(24)});
            assert_eq!(chain_data(&[parse(&first).unwrap(),parse(&next).unwrap()],&base,&base_raw,previous,&selected).unwrap().len(),3);
            // A missing predecessor, same-length fork or circular self row
            // never gains authority by the current receipt's own hash.
            assert!(chain_data(&[parse(&next).unwrap()],&base,&base_raw,previous,&selected).is_err());
            let mut fork=first.clone();fork.own_attempt=next.own_attempt.clone();
            assert!(chain_data(&[parse(&first).unwrap(),parse(&fork).unwrap()],&base,&base_raw,previous,&selected).is_err());
            for change in 0..4 {
                let mut wrong=next.clone();
                match change {0=>wrong.attempts[1].intent_sha256="b".repeat(64),1=>wrong.attempts[1].identity=identity(26),
                    2=>wrong.stage_sha256="c".repeat(64),_=>wrong.attempts[1].request_id=id(105)};
                assert!(chain_data(&[parse(&first).unwrap(),parse(&wrong).unwrap()],&base,&base_raw,previous,&selected).is_err());
            }
            let mut cycle=next.clone();cycle.attempts[1].invocation=id(4);assert!(parse(&cycle).is_err());
            let mut alias=next.clone();alias.own_attempt.identity=first.root;assert!(parse(&alias).is_err());
            let mut duplicate=next.clone();duplicate.attempts.push(duplicate.attempts[0].clone());assert!(parse(&duplicate).is_err());
            // A genuine recorded chain can span boot device renumbering. UUID,
            // inode and birth time still bind every old and newly created row.
            let volume=mobile_release_desktop::macos_persistent_identity::VolumeUuid::from_bytes_data([1;16]).unwrap();
            let mut stable=first.clone();
            for original in [&mut stable.root,&mut stable.stage,&mut stable.old_state,&mut stable.own_attempt.identity,
                &mut stable.attempts[0].identity] {original.volume_uuid=Some(volume);}
            let stable_expected=chain_data(&[parse(&stable).unwrap()],&base,&base_raw,previous,&selected).unwrap();
            let mut rebooted=stable.clone();
            for original in [&mut rebooted.root,&mut rebooted.stage,&mut rebooted.old_state] {original.device=2;}
            rebooted.own_attempt=OwnAttempt{invocation:id(4),request_id:id(104),
                identity:OriginalIdentityData{device:2,volume_uuid:Some(volume),..identity(25)}};
            rebooted.attempts.push(AttemptBinding{invocation:id(3),request_id:id(103),
                intent_sha256:hash(&stable_expected[1].body),identity:stable.own_attempt.identity});
            assert_eq!(chain_data(&[parse(&stable).unwrap(),parse(&rebooted).unwrap()],&base,&base_raw,previous,&selected).unwrap().len(),3);
            let mut wrong=rebooted.clone();wrong.own_attempt.identity.volume_uuid=
                mobile_release_desktop::macos_persistent_identity::VolumeUuid::from_bytes_data([2;16]);
            assert!(parse(&wrong).is_err());
            wrong=rebooted.clone();wrong.own_attempt.identity.inode=stable.root.inode;wrong.own_attempt.identity.device=3;
            assert!(parse(&wrong).is_err());
            wrong=rebooted.clone();wrong.own_attempt.identity.volume_uuid=None;assert!(parse(&wrong).is_err());
        }
    }
    #[test]
    fn restore_intent_prefix_requires_prior_durable_own_binding_and_exact_original_bytes() {
        let full=b"{\"fixed\":true}\n";
        assert!(attempt_prefix_data(full,full,0o444,false).is_ok());
        assert!(attempt_prefix_data(full,full,0o600,false).is_err());
        for length in 0..=full.len() {
            assert!(attempt_prefix_data(full,&full[..length],0o600,true).is_ok());
            assert_eq!(attempt_prefix_data(full,&full[..length],0o444,true).is_ok(),length==full.len());
        }
        for wrong in [b"other".as_slice(),b"{\"wrong\":true}",b"{\"fixed\":true}\nextra"] {
            assert!(attempt_prefix_data(full,wrong,0o600,true).is_err());
        }
        assert!(attempt_prefix_data(full,full,0o644,true).is_err());
        assert!(attempt_prefix_data(b"",b"",0o600,true).is_err());
        assert!(attempt_prefix_data(&vec![b'a';transaction::INTENT_LIMIT+1],b"",0o600,true).is_err());
    }
    #[test]
    fn restore_preservation_keeps_first_error_and_actual_unknown_return_absorbing() {
        let mut state=Preservation::fresh();
        assert!(!state.complete());state.entered=true;
        state.returned(ReturnedData::KnownSuccess);state.returned(ReturnedData::KnownRefusal);
        assert!(state.returned==ReturnedData::KnownSuccess);
        state.settled=true;assert!(state.complete());
        assert_eq!(state.fail("actual-post-failure"),"actual-post-failure");
        assert_eq!(state.fail("later-close-failure"),"actual-post-failure");assert!(!state.complete());
        state.returned(ReturnedData::Unknown);state.returned(ReturnedData::KnownSuccess);
        assert!(state.returned==ReturnedData::Unknown);assert!(!state.complete());
    }
    #[test]
    fn restore_receipt_checks_real_source_phase_and_selected_original_summaries() {
        let stage=Identity {dev:1,ino:42,mode:0o040700,uid:0,gid:0,links:2,size:0,
            mtime:1,mtime_ns:0,ctime:1,ctime_ns:0};
        let app=Identity {ino:43,mode:0o040555,..stage};
        for intel in [false,true] {
            let (snapshot,_)=removal_archive_test_snapshot(intel,0);
            let (_,header,_)=removal_archive_test_parse(&snapshot,true).unwrap();
            let header=header.unwrap();
            let spans=parse_removal_genesis_data(snapshot.len() as u64,&"2".repeat(32),|at,out|{
                let at=at as usize;let n=out.len().min(snapshot.len().saturating_sub(at));
                out[..n].copy_from_slice(&snapshot[at..at+n]);Ok(n)
            }).unwrap();
            let selected=ReleaseSetData::parse_for_target_data(spans.selected_bytes_data(),header.target).unwrap();
            let fresh=IntentData::encode_data(&"4".repeat(32),&"5".repeat(32),ActionData::FreshInstall,None,&selected).unwrap();
            let mut wire:serde_json::Value=serde_json::from_slice(&fresh).unwrap();
            wire["action"]=serde_json::json!("restore-fixed-app");wire["previous"]=wire["next"].clone();
            wire["previousState"]=serde_json::json!({"invocation":"6".repeat(32),"sha256":"7".repeat(64)});
            // Parsed receipt-shape fixture only. It does not pass recovery's
            // separate genuine previous-State/capsule admission.
            let intent=IntentData::parse_data(&serde_json::to_vec(&wire).unwrap(),&selected).unwrap();
            let value=serde_json::json!({"schemaVersion":1,"release":intent.next_data().binding_data().release,
                "phase":"staging-created","runtimePublication":"not-attempted","appPublication":"not-attempted",
                "payloadVerified":false,"payloadWritersSettled":true,"installationMetadata":{},"maintenanceGate":{},
                "registrationReservation":{},"originalSettlement":"pending-final-closes","stage":{"device":1,"inode":42},
                "runtime":null,"app":null,"createdAncestors":[],"inventorySha256":intent.next_data().binding_data().inventory_sha256});
            let raw=serde_json::to_vec(&value).unwrap();
            assert_eq!(receipt_data(&raw,0,&intent,stage,Some(app)),Ok(true));
            assert_eq!(receipt_data(b"{",0,&intent,stage,None),Ok(false));
            let fresh=IntentData::parse_data(&fresh,&selected).unwrap();
            assert!(receipt_data(&raw,0,&fresh,stage,None).is_err());
            for (key,bad) in [("stage",serde_json::json!({"device":1,"inode":44})),
                ("runtime",serde_json::json!({"device":1,"inode":44})),("app",serde_json::json!({"device":1,"inode":43})),
                ("payloadWritersSettled",serde_json::json!(false)),("phase",serde_json::json!("app-publication-confirmed")),
                ("inventorySha256",serde_json::json!("8".repeat(64)))] {
                let mut changed=value.clone();changed[key]=bad;
                assert!(receipt_data(&serde_json::to_vec(&changed).unwrap(),0,&intent,stage,Some(app)).is_err(),"{key}");
            }
            let mut prepared=value;prepared["phase"]=serde_json::json!("prepared");
            prepared["payloadVerified"]=serde_json::json!(true);
            prepared["app"]=serde_json::json!({"device":1,"inode":43});
            let raw=serde_json::to_vec(&prepared).unwrap();
            assert_eq!(receipt_data(&raw,1,&intent,stage,Some(app)),Ok(true));
            assert!(receipt_data(&raw,1,&intent,stage,None).is_err());
            assert!(receipt_data(&raw,2,&intent,stage,Some(app)).is_err());
            let duplicate=String::from_utf8(raw).unwrap().replacen("\"phase\":", "\"phase\":null,\"phase\":",1);
            assert!(receipt_data(duplicate.as_bytes(),1,&intent,stage,Some(app)).is_err());
        }
    }
    #[test]
    fn restore_prepared_receipt_never_promotes_unsealed_or_unfinished_app() {
        assert_eq!(prepared_data(false,false,false,false),Ok(PreparedReceipt::Absent));
        assert_eq!(prepared_data(false,false,false,true),Ok(PreparedReceipt::Absent));
        assert_eq!(prepared_data(true,false,false,true),Ok(PreparedReceipt::WriterPrefix));
        assert_eq!(prepared_data(true,true,false,true),Ok(PreparedReceipt::WriterPrefix));
        assert_eq!(prepared_data(true,true,true,true),Ok(PreparedReceipt::Complete));
        for (present,parsed,sealed,complete) in [(false,true,false,true),(false,false,true,true),
            (true,false,true,true),(true,false,false,false),(true,true,false,false),(true,true,true,false)] {
            assert!(prepared_data(present,parsed,sealed,complete).is_err());
        }
        let exact=serde_json::json!({"device":1,"inode":42});
        assert!(summary_matches(&exact,Some((1,42))));
        assert!(summary_matches(&serde_json::Value::Null,None));
        for bad in [serde_json::json!({"device":1,"inode":43}),serde_json::json!([1,42]),
            serde_json::json!({"device":1,"inode":42,"trusted":true}),serde_json::json!({"device":true,"inode":42})] {
            assert!(!summary_matches(&bad,Some((1,42))));
        }
        assert!(!summary_matches(&exact,None));
        assert!(!summary_matches(&serde_json::Value::Null,Some((1,42))));
    }
}

// Closed V3 transport descriptor. These fixed DATA rows describe an indivisible
// preserved stage; neither a row nor its matching path admits a partial tree.
// Every consumer must reproduce the receipt/history census and conserved tree.
#[derive(Clone,Copy,PartialEq,Eq)]
pub(super) struct RestoreStageSpanData {
    torn:[u8;16],holder:[u8;16],receipt:[u8;32],root:OriginalIdentityData,
    stage:OriginalIdentityData,top:Identity,commitment:[u8;32],
    app_files:u32,app_directories:u32,app_bytes:u64,phase_files:u8,phase_bytes:u64,
}
impl RestoreStageSpanData {
    fn observed(reference:&transaction::RestoreReferenceData,root:OriginalIdentityData,
        stage:OriginalIdentityData,observed:&StageObservation)->Result<Self> {
        let value=Self {torn:archive_hex_data(reference.torn_invocation_data())?,
            holder:archive_hex_data(reference.receipt_invocation_data())?,receipt:archive_hex_data(reference.receipt_sha256_data())?,
            root,stage,top:observed.identity,commitment:observed.commitment,
            app_files:u32::try_from(observed.app.map_or(0,|a|a.files)).map_err(|_|"restore-transport-count")?,
            app_directories:u32::try_from(observed.app.map_or(0,|a|a.directories)).map_err(|_|"restore-transport-count")?,
            app_bytes:observed.app.map_or(0,|a|a.bytes),phase_files:u8::try_from(observed.control_files).map_err(|_|"restore-transport-count")?,
            phase_bytes:observed.control_bytes};value.validate()?;Ok(value)
    }
    fn validate(&self)->Result<()> {
        check(self.torn.iter().any(|b|*b!=0)&&self.holder.iter().any(|b|*b!=0)&&self.torn!=self.holder
            && self.receipt.iter().any(|b|*b!=0)&&self.commitment.iter().any(|b|*b!=0)
            && self.root.valid_data()&&self.stage.valid_data()&&self.root.device>0
            && self.stage.same_volume_data(self.root)&&self.stage.inode!=self.root.inode
            && self.top.dev==self.stage.device&&self.top.ino==self.stage.inode
            && archive_directory_data(self.top,0,true)
            && self.app_files as usize<=installation_record::FILE_LIMIT
            && self.app_directories as usize<=installation_record::FILE_LIMIT
            && (self.app_directories!=0||self.app_files==0&&self.app_bytes==0)
            && (1..=2).contains(&self.phase_files)&&self.phase_bytes>0&&self.phase_bytes<=8192
            && self.app_bytes.checked_add(self.phase_bytes).is_some_and(|n|n<=installation_record::PAYLOAD_LIMIT),
            "restore-transport-shape")
    }
    pub(super) fn reference(&self)->Result<transaction::RestoreReferenceData> {
        data(transaction::RestoreReferenceData::new_data(&archive_hex_text_data(&self.torn),
            &archive_hex_text_data(&self.holder),&archive_hex_text_data(&self.receipt)))
    }
    pub(super) fn name(&self)->String {format!(".restore-recovery-{}.stage",archive_hex_text_data(&self.torn))}
    pub(super) fn storage_bytes(&self)->u64 {self.app_bytes+self.phase_bytes}
    pub(super) fn original_quote(&self)->Result<usize> {
        // The conserved app reader's existing quote is separate from the
        // stage original, its two exact rosters, and each phase-file reader.
        partial_fresh_retry_original_quote_data(self.app_files as usize,self.app_directories as usize)?
            .checked_add(3+self.phase_files as usize).filter(|n|*n<=installation_record::ORIGINAL_LIMIT)
            .ok_or("restore-transport-original-budget")
    }
    pub(super) fn encode(&self,out:&mut SnapshotBytes)->Result<()> {
        self.validate()?;
        for bytes in [self.torn.as_slice(),self.holder.as_slice(),self.receipt.as_slice()] {out.put(bytes)?;}
        for id in [self.root,self.stage] {out.put(&id.device.to_be_bytes())?;out.put(&id.inode.to_be_bytes())?;
            out.put(&id.birth_seconds.to_be_bytes())?;out.put(&id.birth_nanoseconds.to_be_bytes())?;}
        out.identity(self.top,0)?;out.put(&self.commitment)?;
        out.u32(self.app_files as usize)?;out.u32(self.app_directories as usize)?;
        out.put(&self.app_bytes.to_be_bytes())?;out.put(&[self.phase_files])?;out.put(&self.phase_bytes.to_be_bytes())
    }
    pub(super) fn parse<F:FnMut(u64,&mut[u8])->Result<usize>>(cursor:&mut ArchiveCursor<F>)->ArchiveParse<Self> {
        let torn=cursor.array()?;let holder=cursor.array()?;let receipt=cursor.array()?;
        fn original<F:FnMut(u64,&mut[u8])->Result<usize>>(cursor:&mut ArchiveCursor<F>)->ArchiveParse<OriginalIdentityData> {
            Ok(OriginalIdentityData{device:cursor.i64()?,inode:cursor.u64()?,birth_seconds:cursor.i64()?,birth_nanoseconds:cursor.i64()?, volume_uuid: None })
        }
        let root=original(cursor)?;let stage=original(cursor)?;let (top,_flags)=cursor.identity(&[0o040700])?;
        let value=Self{torn,holder,receipt,root,stage,top,commitment:cursor.array()?,app_files:cursor.u32()?,
            app_directories:cursor.u32()?,app_bytes:cursor.u64()?,phase_files:cursor.byte()?,phase_bytes:cursor.u64()?};
        value.validate()?;Ok(value)
    }
}
pub(super) fn stage_rows(rows:&[RestoreStageSpanData])->Result<()> {
    check(rows.len()<=transaction::INVOCATION_LIMIT&&rows.windows(2).all(|w|w[0].torn<w[1].torn),"restore-transport-order")?;
    let mut bytes=0u64;
    for (i,row) in rows.iter().enumerate() {row.validate()?;
        check(rows[..i].iter().all(|old|old.holder!=row.holder&&old.stage.inode!=row.stage.inode&&old.root==row.root),
            "restore-transport-alias")?;
        bytes=removal_archive_storage_sum_data(bytes,row.storage_bytes())?;
    }Ok(())
}
pub(super) fn stage_heap(count:usize)->Result<usize> {
    check(count<=transaction::INVOCATION_LIMIT,"restore-transport-count")?;
    count.checked_mul(std::mem::size_of::<RestoreStageSpanData>()).ok_or("restore-transport-memory")
}
// Grammar only: expected prefix and ownAttempt identity are separately checked
// by the authenticated group census. No Noop kind5 predicate is broadened.
pub(crate) fn snapshot_prefix_path(path:&str)->Option<(&str,&str)> {
    let tail=path.strip_prefix(".restore-recovery-")?.strip_suffix(".intent.json")?;
    let (base,attempt)=tail.split_once('-')?;
    (id_data(base)&&id_data(attempt)).then_some((base,attempt))
}
pub(crate) fn snapshot_prefix_shape(path:&str,id:Identity,flags:u32,size:u64)->bool {
    snapshot_prefix_path(path).is_some()&&id.uid==0&&id.gid==0&&id.links==1&&flags==0
        && id.size>=0&&id.size as u64==size&&size<=transaction::INTENT_LIMIT as u64
        && (id.mode==0o100600||id.mode==0o100444&&size>0)
}

fn snapshot_span<'a>(genesis:&'a RemovalGenesisData,path:&str)->Result<(usize,&'a RemovalControlSpanData)> {
    genesis.controls_data().iter().enumerate().find(|(_,row)|row.path_data()==path&&matches!(row.kind_data(),0|6))
        .ok_or("restore-transport-control-required")
}
fn snapshot_bytes<F:FnMut(u64,&mut[u8])->Result<usize>>(genesis:&RemovalGenesisData,path:&str,limit:usize,
    read:&mut F)->Result<Vec<u8>> {
    let (_,row)=snapshot_span(genesis,path)?;
    check(limit<=installation_record::INVENTORY_LIMIT&&row.len_data()<=limit as u64
        && if row.kind_data()==0 {row.identity_data().mode==0o100444&&row.flags_data()==0&&row.len_data()>0}
            else{snapshot_prefix_shape(path,row.identity_data(),row.flags_data(),row.len_data())},
        "restore-transport-prefix-shape")?;
    let size=row.len_data() as usize;let mut raw=Vec::new();
    raw.try_reserve_exact(size).map_err(|_|"restore-transport-allocation")?;
    check(raw.capacity()<=limit,"restore-transport-allocation")?;raw.resize(size,0);
    let mut at=0usize;while at<size {
        let n=read(row.offset_data().checked_add(at as u64).ok_or("restore-transport-offset")?,&mut raw[at..])?;
        check(n>0&&n<=size-at,"restore-transport-short-read")?;at+=n;
    }
    check(<[u8;32]>::from(Sha256::digest(&raw))==*row.digest_data(),"restore-transport-control-hash")?;Ok(raw)
}
// Temporary one-group DATA. No Original index is fabricated: identity/body
// comparisons below are snapshot facts and live custody is checked separately.
struct SnapshotGroupData {
    base:IntentData,previous:StateData,holder:IntentData,expected:Vec<ExpectedAttempt>,indices:Vec<usize>,
}
fn snapshot_group<F:FnMut(u64,&mut[u8])->Result<usize>>(genesis:&RemovalGenesisData,
    descriptor:&RestoreStageSpanData,selected:&ReleaseSetData,state:&StateData,read:&mut F)->Result<SnapshotGroupData> {
    let reference=descriptor.reference()?;
    let base_path=data(reference.preserved_intent_name_data(reference.torn_invocation_data()))?;
    let base_raw=snapshot_bytes(genesis,&base_path,transaction::INTENT_LIMIT,read)?;
    let base=data(IntentData::parse_recorded_data(&base_raw,selected))?;
    check(base.invocation_data()==reference.torn_invocation_data(),"restore-transport-base")?;
    let (previous,sha)=base.previous_state_data().ok_or("restore-transport-previous")?;
    let evidence=state.evidence_data().find(|e|e.invocation==previous).ok_or("restore-transport-previous")?;
    check(evidence.state_sha256==sha,"restore-transport-previous-sha")?;
    let old_path=data(transaction::archived_state_name_data(previous))?;
    let (_,old_span)=snapshot_span(genesis,&old_path)?;
    let old_raw=snapshot_bytes(genesis,&old_path,transaction::STATE_LIMIT,read)?;
    let old=data(StateData::parse_data(&old_raw,selected))?;
    check(old.digest_data()==evidence.state_sha256,"restore-transport-previous-sha")?;drop(old_raw);
    let cap_raw=snapshot_bytes(genesis,&data(transaction::capsule_name_data(previous))?,transaction::CAPSULE_LIMIT,read)?;
    let cap=data(CapsuleData::parse_recorded_data(&cap_raw,selected))?;
    check(cap.digest_data()==evidence.capsule_sha256,"restore-transport-previous-capsule")?;drop(cap_raw);
    let raw=snapshot_bytes(genesis,&reference.receipt_name_data(),RECEIPT_LIMIT,read)?;
    let last=ReceiptData::parse(&raw,&reference,&base,(&old,&cap),selected)?;drop(raw);
    let root=genesis.directories_data().iter().find(|d|d.path_data().is_empty())
        .ok_or("restore-transport-root")?.identity_data();
    check(last.wire.root==descriptor.root&&last.wire.stage==descriptor.stage
        && archive_hex_data::<32>(&last.wire.stage_sha256)?==descriptor.commitment
        && (root.dev,root.ino)==(descriptor.root.device,descriptor.root.inode)
        && (old_span.identity_data().dev,old_span.identity_data().ino)==(last.wire.old_state.device,last.wire.old_state.inode),
        "restore-transport-descriptor-binding")?;
    let mut receipts=Vec::new();let mut indices=Vec::new();
    receipts.try_reserve_exact(last.wire.attempts.len()).map_err(|_|"restore-transport-allocation")?;
    indices.try_reserve_exact(2*transaction::INVOCATION_LIMIT).map_err(|_|"restore-transport-allocation")?;
    check(receipts.capacity()<=transaction::INVOCATION_LIMIT&&indices.capacity()<=2*transaction::INVOCATION_LIMIT,
        "restore-transport-allocation")?;
    for attempt in &last.wire.attempts {
        if attempt.invocation==base.invocation_data(){continue;}
        let name=format!(".restore-recovery-{}.json",attempt.invocation);
        let raw=snapshot_bytes(genesis,&name,RECEIPT_LIMIT,read)?;
        let reference=data(transaction::RestoreReferenceData::new_data(base.invocation_data(),&attempt.invocation,&hash(&raw)))?;
        receipts.push(ReceiptData::parse(&raw,&reference,&base,(&old,&cap),selected)?);
        indices.push(snapshot_span(genesis,&name)?.0);
    }
    receipts.push(last);indices.push(snapshot_span(genesis,&reference.receipt_name_data())?.0);
    let expected=chain_data(&receipts,&base,&base_raw,(&old,&cap),selected)?;
    let own=expected.last().ok_or("restore-transport-own-required")?;
    let holder=data(IntentData::parse_recorded_data(&own.body,selected))?;
    check(holder.restore_recovery_data()==Some(&reference),"restore-transport-holder")?;
    // A holder is either a genuine completed history intent or the exact next
    // group's base. The flat closure below proves that edge, not this path.
    let holder_path=if holder.invocation_data()==state.invocation_data()||state.evidence_data().any(|e|e.invocation==holder.invocation_data()) {
        data(transaction::intent_name_data(holder.invocation_data()))?
    }else{format!(".restore-recovery-{}-{}.intent.json",holder.invocation_data(),holder.invocation_data())};
    let (_,holder_span)=snapshot_span(genesis,&holder_path)?;
    let holder_raw=snapshot_bytes(genesis,&holder_path,transaction::INTENT_LIMIT,read)?;
    check(holder_raw==own.body&&(holder_span.identity_data().dev,holder_span.identity_data().ino)==(own.identity.device,own.identity.inode),
        "restore-transport-holder-original")?;
    for row in expected.iter().take(expected.len()-1) {
        let path=data(reference.preserved_intent_name_data(&row.invocation))?;
        let (index,span)=snapshot_span(genesis,&path)?;
        check(span.kind_data()==6&&(span.identity_data().dev,span.identity_data().ino)==(row.identity.device,row.identity.inode),
            "restore-transport-attempt-original")?;
        let raw=snapshot_bytes(genesis,&path,transaction::INTENT_LIMIT,read)?;
        attempt_prefix_data(&row.body,&raw,span.identity_data().mode&0o7777,row.receipt.is_some())?;
        indices.push(index);
    }
    check(indices.len()<=2*transaction::INVOCATION_LIMIT,"restore-transport-control-count")?;
    Ok(SnapshotGroupData{base,previous:old,holder,expected,indices})
}

fn completed_reference_coverage(completed:&[transaction::RestoreReferenceData],observed:&[transaction::RestoreReferenceData])->Result<()> {
    check(completed.len()<=transaction::INVOCATION_LIMIT&&observed.len()<=transaction::INVOCATION_LIMIT
        && completed.iter().enumerate().all(|(i,reference)|!completed[..i].contains(reference)
            && observed.iter().filter(|candidate|*candidate==reference).count()==1),"restore-transport-completed-coverage")
}
pub(super) struct SnapshotCensus {pub(super) indices:Vec<usize>,pub(super) facts:InstallInvocationSetData}
pub(super) fn snapshot_census<F:FnMut(u64,&mut[u8])->Result<usize>>(genesis:&RemovalGenesisData,
    selected:&ReleaseSetData,state:&StateData,completed:&[transaction::RestoreReferenceData],read:&mut F)->Result<SnapshotCensus> {
    let descriptors=genesis.restore_stages_data();stage_rows(descriptors)?;
    check(completed.len()<=descriptors.len()&&descriptors.len()<=transaction::INVOCATION_LIMIT,"restore-transport-group-count")?;
    let observed=descriptors.iter().map(RestoreStageSpanData::reference).collect::<Result<Vec<_>>>()?;
    completed_reference_coverage(completed,&observed)?;drop(observed);
    let mut indices=Vec::new();indices.try_reserve_exact(2*transaction::INVOCATION_LIMIT).map_err(|_|"restore-transport-allocation")?;
    check(indices.capacity()<=2*transaction::INVOCATION_LIMIT,"restore-transport-allocation")?;
    let mut facts=InstallInvocationSetData::empty();
    let mut links:Vec<(Option<usize>,bool)>=Vec::new();links.try_reserve_exact(descriptors.len()).map_err(|_|"restore-transport-allocation")?;
    let mut originals:BTreeMap<(i64,u64),([u8;16],OriginalIdentityData,bool,bool)>=BTreeMap::new();
    for descriptor in descriptors {
        let group=snapshot_group(genesis,descriptor,selected,state,read)?;
        let reference=descriptor.reference()?;
        let is_complete=completed.iter().any(|r|r==&reference);
        if is_complete {
            let expected=if group.holder.invocation_data()==state.invocation_data(){
                check(state.restore_recovery_data()==Some(&reference),"restore-transport-current-reference")?;
                let raw=rehome_span_bytes_data(genesis,&data(transaction::intent_name_data(state.invocation_data()))?,transaction::INTENT_LIMIT,read)?;
                hash(&raw)
            }else{state.evidence_data().find(|e|e.invocation==group.holder.invocation_data())
                .ok_or("restore-transport-holder-history")?.intent_sha256.to_owned()};
            check(expected==group.holder.digest_data(),"restore-transport-holder-history")?;
        }
        let parent=group.base.restore_recovery_data().map(|reference|->Result<usize>{
            descriptors.iter().position(|old|old.reference().is_ok_and(|r|&r==reference))
                .ok_or("restore-transport-parent-required")
        }).transpose()?;
        links.push((parent,is_complete));
        for row in &group.expected {
            let parsed=data(IntentData::parse_recorded_data(&row.body,selected))?;
            let fact=InstallInvocationFactData::intent(&parsed)?;
            let inserted=facts.insert(fact)?;
            if !inserted {check(originals.values().any(|(id,identity,_,_)|*id==fact.invocation&&*identity==row.identity),
                "restore-transport-original-replacement")?;}
            let holder=row.invocation==group.holder.invocation_data();
            let base=row.invocation==group.base.invocation_data()&&parent.is_some();
            if row.invocation==state.invocation_data()||state.evidence_data().any(|e|e.invocation==row.invocation) {
                check(holder&&is_complete,"restore-transport-history-reuse")?;
            }
            check(descriptors.iter().all(|d|d.stage.inode!=row.identity.inode
                && d.root.inode!=row.identity.inode),"restore-transport-original-alias")?;
            let key=(row.identity.device,row.identity.inode);
            if let Some((id,identity,old_base,old_holder))=originals.get_mut(&key) {
                check(*id==fact.invocation&&*identity==row.identity&&((holder&&*old_base&&! *old_holder)
                    ||base&&*old_holder&&! *old_base),"restore-transport-original-overlap")?;
                *old_base|=base;*old_holder|=holder;
            }else {check(originals.len()<transaction::INVOCATION_LIMIT,"restore-transport-original-count")?;
                originals.insert(key,(fact.invocation,row.identity,base,holder));}
        }
        for index in group.indices {
            check(indices.len()<2*transaction::INVOCATION_LIMIT&&!indices.contains(&index),"restore-transport-control-overlap")?;
            indices.push(index);
        }
    }
    check(links.len()==descriptors.len(),"restore-transport-group-count")?;
    let mut children=[0u8;transaction::INVOCATION_LIMIT];
    for (parent,_) in &links {if let Some(parent)=parent {
        children[*parent]=children[*parent].checked_add(1).ok_or("restore-transport-fork")?;
        check(children[*parent]==1,"restore-transport-fork")?;
    }}
    for (index,(_,complete)) in links.iter().enumerate() {
        check(*complete==(children[index]==0),"restore-transport-detached-group")?;
        let mut at=index;let mut seen=0u64;
        loop {check(at<links.len()&&seen&(1u64<<at)==0,"restore-transport-cycle")?;seen|=1u64<<at;
            match links[at].0 {Some(parent)=>at=parent,None=>break,}}
    }
    Ok(SnapshotCensus{indices,facts})
}

// The ordinary snapshot cap remains2MiB and the retained plan remains256KiB.
// Restore's bounded receipt forest uses separate transient128MiB Book budget;
// refund occurs only after the callback dropped all temporary parse backing.
pub(super) fn snapshot_plan_work<T>(book:&mut Install,genesis:&RemovalGenesisData,
    call:impl FnOnce(&mut Install)->Result<T>)->Result<T> {
    if genesis.restore_stages_data().is_empty(){return call(book);}
    let mut budget=CaptureBudget::default();budget.reserve(book,transaction::INVOCATION_LIMIT,0,0)?;
    let result=call(book)?;budget.retain(book,0)?;Ok(result)
}

// The stage is always read whole. It never enters RemovalRemainingPlan and no
// partially deleted stage can satisfy its original receipt commitment/counts.
fn with_transport_index<T>(book:&mut Install,descriptor:&RestoreStageSpanData,snapshot:&SnapshotRead<'_>,
    inspect:impl FnOnce(&mut Install,&SnapshotGroupData,&installation_record::InventoryIndex<'_>)->Result<T>)->Result<T> {
    snapshot.post(book)?;
    let installed_root=book.gate.parent.ok_or("restore-transport-root")?;
    check(applications::preservation_identity(book,installed_root)?==descriptor.root,"restore-transport-installed-root-original")?;
    let mut budget=CaptureBudget::default();budget.reserve(book,transaction::INVOCATION_LIMIT,0,0)?;
    let result=(|| {
        let genesis=snapshot.genesis;
        let selected=ReleaseSetData::parse_for_target_data(genesis.selected_bytes_data(),genesis.header.target)
            .map_err(|_|"restore-transport-selection")?;
        let raw=rehome_span_bytes_data(genesis,transaction::STATE_NAME,transaction::STATE_LIMIT,
            &mut |at,out|snapshot.read_at(book,at,out))?;
        let state=data(StateData::parse_data(&raw,&selected))?;drop(raw);
        let group=snapshot_group(genesis,descriptor,&selected,&state,&mut |at,out|snapshot.read_at(book,at,out))?;
        let release=group.previous.current_data();let binding=group.base.next_data().binding_data();
        check(release.release_data()==group.base.next_data(),"restore-transport-inventory-release")?;
        let inventory_path=rehome_path_data(&["versions",binding.release,installation_record::INVENTORY_NAME])?;
        let (_,inventory_span)=snapshot_span(genesis,&inventory_path)?;
        let size=usize::try_from(inventory_span.len_data()).map_err(|_|"restore-transport-inventory-size")?;
        let inventory_quote=size.checked_mul(8).and_then(|n|n.checked_add(installation_record::RECORD_LIMIT*4))
            .ok_or("restore-transport-inventory-memory")?;
        budget.reserve(book,1,0,inventory_quote)?;
        let raw=snapshot_bytes(genesis,&inventory_path,installation_record::INVENTORY_LIMIT,&mut |at,out|snapshot.read_at(book,at,out))?;
        check(hash(&raw)==binding.inventory_sha256,"restore-transport-inventory-digest")?;
        let record_path=rehome_path_data(&["versions",binding.release,installation_record::RECORD_NAME])?;
        let record_raw=snapshot_bytes(genesis,&record_path,installation_record::RECORD_LIMIT,&mut |at,out|snapshot.read_at(book,at,out))?;
        let expected=installation_record::Expected {kind:installation_record::Kind::Ordinary,source_commit:binding.source_commit,
            runtime_manifest:binding.runtime_manifest_sha256,install_root:installation_record::DirectoryIdentity {
                device:descriptor.root.device,inode:descriptor.root.inode,mode:0o040755,uid:0,gid:0,flags:0, volume_uuid: None },
            release_directory:release.release_directory_data()};
        let record=installation_record::Record::parse_observed_for_release_data(&record_raw,&raw,&expected,group.base.next_data())?;
        check(record.instance()==release.instance_data(),"restore-transport-runtime-instance")?;
        let inventory=Inventory::parse_for_release(&raw,binding.runtime_manifest_sha256,binding.release)?;
        let quote=worker::reinstall_index_quote_data(&inventory)?;budget.reserve(book,1,quote.2,inventory_quote)?;
        let index=inventory.index()?;check((index.files.len(),index.directories.len())==(quote.0,quote.1),"restore-transport-inventory-index")?;
        inspect(book,&group,&index)
    })()?;
    snapshot.post(book)?;budget.retain(book,0)?;Ok(result)
}
// Same signed metadata/index and actual maximum temporary Book debit, without
// acquiring any stage originals. A containing writer runs this AFTER its
// lifetime/storage reservations and BEFORE its first physical effect.
// The SAME peak applies at admission and each actual tree read. Containing
// lifecycles add their future held-reader envelope rather than assuming those
// readers will close before the Restore cut; no future close supplies credit.
pub(in crate::installer) fn transport_live_data(live:usize,external:usize,held:usize)->bool {
    live.checked_add(external).and_then(|n|n.checked_add(held))
        .and_then(|n|n.checked_add(40)).is_some_and(|n|n<=96)
}
fn transport_live(book:&Install,held:usize)->Result<()> {
    let external=book.removal_live_reserved.checked_add(if book.worker_deadline.is_some(){worker::EXTRA_LIVE}else{0})
        .ok_or("restore-transport-live-budget")?;
    check(transport_live_data(book.originals.iter().filter(|row|row.fd.is_some()).count(),external,held),
        "restore-transport-live-budget")
}
pub(super) fn preflight_transport_work(book:&mut Install,descriptor:&RestoreStageSpanData,snapshot:&SnapshotRead<'_>)->Result<()> {
    transport_live(book,0)?;
    with_transport_index(book,descriptor,snapshot,|_,_,_|Ok(()))
}
pub(super) fn audit_transport_stage(book:&mut Install,parent:usize,descriptor:&RestoreStageSpanData,
    snapshot:&SnapshotRead<'_>)->Result<Identity> {
    transport_live(book,0)?;
    with_transport_index(book,descriptor,snapshot,|book,group,index| {
        removal_archive_scope(book,|book| {
            let stage=stage_at(book,parent,&descriptor.name())?.ok_or("restore-transport-stage-missing")?;
            let identity=applications::preservation_identity(book,stage)?;
            let before=partial_fresh_directory(book,stage)?;
            let original_root=applications::preservation_identity(book,parent)?==descriptor.root;
            check(identity==descriptor.stage&&if original_root {before==descriptor.top}
                else {same_renamed(descriptor.top,before)},"restore-transport-stage-original")?;
            let mut work=PartialFreshTreeWork::new(0)?;
            let actual=stage_observation(book,stage,&group.base,&index,None,&mut work)?;
            let mut projection=RestoreStageSpanData::observed(&descriptor.reference()?,descriptor.root,identity,&actual)?;
            // Only this exact top's known rename may change ctime. All app/
            // phase descendants are inside the unchanged commitment.
            projection.top=descriptor.top;
            check(projection==*descriptor&&partial_fresh_directory(book,stage)?==before,"restore-transport-stage-changed")?;
            Ok(before)
        })
    })
}

#[cfg(test)]
#[test]
fn snapshot_completed_reference_coverage_refuses_omitted_group() {
    let reference=|base:u8,holder:u8|transaction::RestoreReferenceData::new_data(
        &format!("{base:032x}"),&format!("{holder:032x}"),&"a".repeat(64)).unwrap();
    let c1=reference(1,2);let c2=reference(3,4);let p1=reference(5,1);
    assert!(completed_reference_coverage(&[c1.clone(),c2.clone()],&[c1.clone(),c2.clone(),p1.clone()]).is_ok());
    // Equal row counts are NOT coverage: an ancestor of C1 cannot replace C2.
    assert!(completed_reference_coverage(&[c1.clone(),c2],&[c1.clone(),p1]).is_err());
    assert!(completed_reference_coverage(&[c1.clone(),c1.clone()],&[c1.clone()]).is_err());
    assert!(completed_reference_coverage(&[c1.clone()],&[c1.clone(),c1]).is_err());
}

#[cfg(test)]
#[test]
fn snapshot_v3_descriptor_wire_and_completed_prefix_data() {
    let root=OriginalIdentityData{device:1,inode:2,birth_seconds:1,birth_nanoseconds:2, volume_uuid: None };
    let descriptor=RestoreStageSpanData{torn:[1;16],holder:[2;16],receipt:[3;32],root,
        stage:OriginalIdentityData{inode:91,..root},
        top:Identity{dev:1,ino:91,mode:0o040700,uid:0,gid:0,links:2,size:64,
            mtime:1,mtime_ns:2,ctime:3,ctime_ns:4},commitment:[4;32],
        app_files:3,app_directories:2,app_bytes:17,phase_files:2,phase_bytes:100};
    descriptor.validate().unwrap();
    assert_eq!(descriptor.storage_bytes(),117);
    assert_eq!(descriptor.original_quote().unwrap(),4*2+2*3+192+3+2);
    let mut encoded=SnapshotBytes::new(512).unwrap();descriptor.encode(&mut encoded).unwrap();
    let bytes=encoded.0;
    let mut cursor=ArchiveCursor::new(bytes.len() as u64,|at,out:&mut[u8]|{
        let at=at as usize;let n=out.len().min(bytes.len()-at).min(7);
        out[..n].copy_from_slice(&bytes[at..at+n]);Ok(n)
    });
    assert!(RestoreStageSpanData::parse(&mut cursor).unwrap()==descriptor);cursor.eof().unwrap();
    for bad in [RestoreStageSpanData{phase_files:0,..descriptor},RestoreStageSpanData{phase_bytes:8193,..descriptor},
        RestoreStageSpanData{holder:descriptor.torn,..descriptor},RestoreStageSpanData{app_directories:0,..descriptor},
        RestoreStageSpanData{top:Identity{mode:0o040555,..descriptor.top},..descriptor}] {
        assert!(bad.validate().is_err());
    }
    assert!(stage_rows(&[descriptor,descriptor]).is_err());
    // Real legacy encoder and sole streaming parser, both targets. These are
    // wire/DATA checks only; a descriptor is not a receipt or native witness.
    for intel in [false,true] {
        let table=RemovalArchiveCensus::empty(0).unwrap();
        let (legacy,header)=removal_archive_test_snapshot_with_table(intel,table);
        assert!(legacy.starts_with(REMOVAL_SNAPSHOT_MAGIC));
        let (v3,_) = removal_archive_test_snapshot_with_restores(intel,RemovalArchiveCensus::empty(0).unwrap(),vec![descriptor]);
        assert!(v3.starts_with(REMOVAL_SNAPSHOT_RESTORE_MAGIC));
        let decoded=parse_removal_genesis_data(v3.len() as u64,&"2".repeat(32),|at,out|{
            let at=at as usize;let n=out.len().min(v3.len()-at).min(11);
            out[..n].copy_from_slice(&v3[at..at+n]);Ok(n)
        }).unwrap();
        assert!(decoded.restore_stages_data()==&[descriptor]);
        let mut wrong_version=v3.clone();wrong_version[..REMOVAL_SNAPSHOT_MAGIC.len()].copy_from_slice(REMOVAL_SNAPSHOT_MAGIC);
        assert!(removal_archive_test_parse(&wrong_version,true).is_err());
        let mut empty=legacy.clone();empty[..REMOVAL_SNAPSHOT_MAGIC.len()].copy_from_slice(REMOVAL_SNAPSHOT_RESTORE_MAGIC);
        // The legacy header ends with control-count. Insert the V3 count at
        // its real field boundary, not an alternate parser/schema fixture.
        empty.splice(header-2..header-2,[0,0]);
        assert!(removal_archive_test_parse(&empty,true).is_err());
        let mut bad_kind=legacy.clone();bad_kind[header]=6;
        assert!(removal_archive_test_parse(&bad_kind,true).is_err());
        for version in [&legacy,&v3] {for cut in 0..REMOVAL_SNAPSHOT_MAGIC.len() {
            assert!(!removal_archive_test_parse(&version[..cut],false).unwrap().0);
            if cut!=0 {let mut corrupt=version[..cut].to_vec();corrupt[0]^=1;
                assert!(removal_archive_test_parse(&corrupt,false).is_err());}
        }}
    }
    // Reuse existing genuine State/Intent DATA fixture for the ordinary move
    // set, adding ONLY one typed inert transport row. No physical authority
    // is fabricated; native consumers require the private held SnapshotRead.
    let (mut genesis,selected,state,intent)=rehome_test_fixture();
    genesis.spans.restore_stages.push(descriptor);
    let mut plan=RehomeMoveSetData::begin_genesis(&genesis,&selected,&state).unwrap();
    plan.add_intent(&selected,&state,&intent).unwrap();
    plan.add(descriptor.name(),RehomeKindData::RestorePreservedStage).unwrap();
    let plan=plan.finish_genesis().unwrap();
    let stage_position=plan.moves.iter().position(|spec|spec.kind==RehomeKindData::RestorePreservedStage).unwrap();
    let child=Identity{ino:900,mode:0o040700,..descriptor.top};
    for prefix in 0..=plan.moves.len() {
        let (directories,files,bytes)=plan.prefix_counts(prefix).unwrap();
        let reference=RehomeReferenceData::observed_data(&plan,child,0,prefix,directories,files,bytes,[5;32]).unwrap();
        let present=prefix>stage_position;
        assert!(reference.restores.as_slice()==if present{std::slice::from_ref(&descriptor)}else{&[]});
        assert_eq!(reference.storage_bytes_data(),bytes+if present{descriptor.storage_bytes()}else{0});
        assert_eq!(reference.audit_originals_data().unwrap(),2*directories+files
            +if present{descriptor.original_quote().unwrap()-2}else{0});
        assert_eq!(plan.restore_originals_data(0,prefix).unwrap(),if present{descriptor.original_quote().unwrap()-2}else{0});
        assert_eq!(plan.restore_storage_data(prefix,plan.moves.len()).unwrap(),if present{0}else{descriptor.storage_bytes()});
        let mut sides=vec![RehomeSideData::OldOnly;plan.moves.len()];
        sides[..prefix].fill(RehomeSideData::NewOnly);assert_eq!(plan.prefix_data(&sides).unwrap(),prefix);
        for bad in [RehomeSideData::Both,RehomeSideData::Neither] {
            sides[stage_position]=bad;assert!(plan.prefix_data(&sides).is_err());
        }
    }
}

// Nonshipping, readonly projections of ALREADY authenticated original groups.
// They are private fixture records, never INIT/RESULT, selectors or admission.
#[cfg(feature="macos-installed-restore-chain-observer")]
fn fixture_attempt(attempt:&AttemptObserved)->serde_json::Value {
    serde_json::json!({"invocation":attempt.expected.invocation,"requestId":attempt.expected.request,
        "identity":attempt.expected.identity,"expectedSha256":hash(&attempt.expected.body),
        "rawSha256":attempt.raw_sha,"bytes":attempt.raw_size,"mode":attempt.mode})
}
#[cfg(feature="macos-installed-restore-chain-observer")]
impl Observation {
    pub(super) fn fixture_post(&self,book:&mut Install,prepared:&PreparedFresh,history:&History,selected:&ReleaseSetData)->Result<()> {
        self.post(book,prepared,history,selected)
    }
    pub(super) fn fixture_pending(&self)->Result<serde_json::Value> {
        check(self.current.is_none()&&!self.preservation.entered&&(1..=3).contains(&self.attempts.len())
            &&self.receipts.len()+1==self.attempts.len()&&self.stage.prepared==PreparedReceipt::Absent,
            "restore-chain-fixed-pending")?;
        let app=self.stage.app.ok_or("restore-chain-positive-app")?;
        check(app.bytes>0&&app.bytes<=65536&&app.state==PartialFreshFileState::Unfinished
            &&self.stage.control_files==1
            &&self.attempts.iter().all(|a|a.placement==transaction::RestoreOriginalPlacementData::Original),
            "restore-chain-fixed-app-prefix")?;
        Ok(serde_json::json!({"base":self.base.invocation_data(),"stage":self.stage_identity,
            "stageSha256":archive_hex_text_data(&self.stage.commitment),"appBytes":app.bytes,
            "phaseFiles":self.stage.control_files,"stagePreserved":self.stage_placement==transaction::RestoreOriginalPlacementData::Preserved,
            "attempts":self.attempts.iter().map(fixture_attempt).collect::<Vec<_>>(),
            "receipts":self.receipts.iter().map(|r|hash(&r.data.raw)).collect::<Vec<_>>()}))
    }
}
#[cfg(feature="macos-installed-restore-chain-observer")]
impl Namespace {
    pub(super) fn fixture_preserved(&self,book:&mut Install,root:usize)->Result<serde_json::Value> {
        check(self.groups.len()==1,"restore-chain-one-group")?;
        let group=&self.groups[0];
        check(group.attempts.len()==4&&group.transport.app_bytes>0&&group.transport.app_bytes<=65536
            &&group.transport.phase_files==1,"restore-chain-fixed-complete")?;
        // Only three readonly additional attempt views, sequential scoped FDs;
        // no native borrowing or future-close credit and no increased cap.
        check(book.originals.len().checked_add(12).is_some_and(|n|n<=installation_record::ORIGINAL_LIMIT)
            &&book.originals.iter().filter(|r|r.fd.is_some()).count().checked_add(4).is_some_and(|n|n<=96),
            "restore-chain-observer-original-bound")?;
        let mut attempts=Vec::with_capacity(3);
        for expected in group.attempts.iter().take(3) {
            let attempt=observe_attempt(book,root,group.base.invocation_data(),expected.clone())?;
            check(attempt.placement==transaction::RestoreOriginalPlacementData::Preserved,"restore-chain-preserved-attempt")?;
            attempts.push(fixture_attempt(&attempt));
        }
        Ok(serde_json::json!({"base":group.base.invocation_data(),"stage":group.stage_identity,
            "stageSha256":archive_hex_text_data(&group.transport.commitment),"appBytes":group.transport.app_bytes,
            "phaseFiles":group.transport.phase_files,"stagePreserved":true,"attempts":attempts,
            "holder":group.holder.invocation_data(),"reference":group.holder.restore_recovery_data()}))
    }
}
