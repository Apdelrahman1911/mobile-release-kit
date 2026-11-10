// Private native Fresh conservation. A current source/R/M view is required;
// parsed DATA cannot construct these original owners or a Fresh Ready value.
use super::*;
use fresh_data::{OutputEnrollmentIndexData,OutputEnrollmentData,OutputRoleData};

// Native-only first snapshot, retained across scoped readers. The expected
// persistent birth came from the real origin/enrollment reader under current
// source/R/M custody; no DATA constructor exposes this witness.
pub(in crate::installer) struct AppMetadata {
    birth:transaction::FreshBirthIdentityData,
    snapshot:mobile_release_desktop::macos_existing_app_metadata::SnapshotData,
}
fn birth_before_attributes(book:&Install,n:usize)->Result<transaction::FreshBirthIdentityData> {
    book.check_name(n,true)?;book.protected(n,true,Some(0o555))?;
    let held=stat::fstat(book.fd(n)?).map_err(|_|"fresh-app-birth-stat")?;
    let row=&book.originals[n];let named=book.named(row.parent,&row.name).map_err(|_|"fresh-app-birth-name")?;
    check(Identity::of(&held)==Identity::of(&named) && held.st_flags==0 && named.st_flags==0
        && held.st_birthtime==named.st_birthtime && held.st_birthtime_nsec==named.st_birthtime_nsec,
        "fresh-app-birth-original")?;
    let uuid=mobile_release_desktop::macos_persistent_identity::observe_volume(book.fd(n)?.as_fd())
        .map_err(|_|"fresh-app-birth-volume")?;
    transaction::FreshBirthIdentityData::from_original_fields_data(i64::from(held.st_dev),held.st_ino,
        held.st_birthtime,held.st_birthtime_nsec,uuid).map_err(|_|"fresh-app-birth-original")
}
impl AppMetadata {
    pub(in crate::installer) fn alias(&self,book:&Install,n:usize)
        ->Result<Option<mobile_release_desktop::macos_existing_app_metadata::SnapshotData>> {
        let id=book.identity(n)?;let (_,inode,seconds,nanos,_)=self.birth.fields_data();
        if id.ino!=inode || id.mode!=0o040555{return Ok(None);}
        let held=stat::fstat(book.fd(n)?).map_err(|_|"fresh-app-alias-stat")?;
        if held.st_birthtime!=seconds || held.st_birthtime_nsec!=nanos{return Ok(None);}
        if !birth_before_attributes(book,n)?.same_object_data(&self.birth){return Ok(None);}
        check(book.read_existing_app_metadata(n,"fresh-app-alias-metadata")?==self.snapshot,
            "fresh-app-alias-metadata")?;Ok(Some(self.snapshot))
    }
}
fn bind_app_metadata(book:&mut Install,source:&worker::FreshRecoveryInput<'_>,index:&OutputEnrollmentIndexData,
    stage:usize,intent:&IntentData)->Result<()> {
    source.post(book)?;let root=source.root_original();
    match book.named(Some(root),paths::APP_NAME) {Err(Errno::ENOENT)=>return Ok(()),Err(_)=>return Err("fresh-app-name"),Ok(_)=>()};
    let row=index.find_data("app").ok_or("fresh-app-unenrolled")?;
    check(row.role_data()==OutputRoleData::PayloadDirectory,"fresh-app-enrollment-role")?;
    check(index.find_data("stage/both-publications-confirmed.json").is_some_and(|v|v.role_data()==OutputRoleData::StageReceipt)
        && partial_fresh_receipt(book,stage,3,intent)?.state==PartialFreshFileState::Complete,
        "fresh-app-publication-receipt")?;
    let original=book.open(Some(root),paths::APP_NAME,true)?;
    let birth=birth_before_attributes(book,original)?;
    check(birth.same_object_data(&row.identity_data()),"fresh-app-enrolled-birth")?;
    if let Some(first)=book.fresh_census_metadata.iter().find(|row|row.birth.same_object_data(&birth)) {
        check(first.alias(book,original)?.is_some(),"fresh-app-first-snapshot")?;
    }else{
        // Only this authenticated, complete published app original may capture
        // the canonical bounded MACL snapshot. Source trees/children stay strict.
        book.capture_existing_app_metadata(original,true,"fresh-app-first-snapshot")?;
        let snapshot=book.originals[original].existing_app_metadata.ok_or("fresh-app-first-snapshot")?;
        retain_metadata(book,original,birth,snapshot)?;
    }
    book.check_name(original,true)?;book.forward_close(original,"fresh-app-anchor-close")?;source.post(book)
}
pub(in crate::installer) struct EnrolledAttemptObserved<'a> {
    source:&'a worker::FreshRecoveryInput<'a>,audit:PartialFreshAttemptAudit,
    origin:[u8;32],journal:[u8;32],head:[u8;32],entries:usize,
}
impl EnrolledAttemptObserved<'_> {
    pub(in crate::installer) fn before_launcher(self,book:&mut Install,input:&worker::FreshRecoveryInput<'_>,
        launcher:&applications::FreshRecovery)->Result<()> {
        check(std::ptr::eq(self.source,input),"fresh-census-owning-source")?;
        let current=observe(book,input,Some(launcher))?;
        check(self.audit.facts==current.audit.facts && self.audit.intent.digest_data()==current.audit.intent.digest_data()
            && self.origin==current.origin && self.journal==current.journal && self.head==current.head
            && self.entries==current.entries,"fresh-census-launcher-pre-effect")?;
        input.post(book)
    }
}
// The consuming launcher check reobserves the same full native census. This
// token still has no preservation/Ready conversion; conservation must retain
// its own actual created child, receipts and fresh baseline after withdrawal.

fn control_limit(role:OutputRoleData,path:&str)->Result<usize> {
    Ok(match role {
        OutputRoleData::MetadataFile if path=="release/install-inventory.json"=>installation_record::INVENTORY_LIMIT,
        OutputRoleData::MetadataFile=>installation_record::RECORD_LIMIT,
        OutputRoleData::StageReceipt=>transaction::STATE_LIMIT.max(applications::PHASE_LIMIT),
        OutputRoleData::RootControl=>transaction::CAPSULE_LIMIT.max(transaction::STATE_LIMIT)
            .max(mobile_release_desktop::macos_install_producer::DESCRIPTOR_LIMIT)
            .max(mobile_release_desktop::macos_install_producer::SIGNATURE_LIMIT),
        _=>return Err("fresh-census-control-role"),
    })
}
fn same_birth(book:&Install,original:usize,expected:transaction::FreshBirthIdentityData)->Result<()> {
    // fresh_output_identity performs live held/name device+birth+UUID checks.
    // Persistent correspondence alone may tolerate a reboot's device renumber.
    check(book.fresh_output_identity(original)?.same_object_data(&expected),"fresh-census-enrolled-original")
}
fn control_hash(book:&Install,original:usize,maximum:usize)->Result<[u8;32]> {
    let before=book.identity(original)?;
    check(before.mode==0o100444 && before.size>0 && before.size as u64<=maximum as u64,
        "fresh-census-unsealed-control")?;
    partial_fresh_raw_post(book,original,before,0)?;
    let mut block=[0u8;PARTIAL_FRESH_BLOCK];let mut digest=Sha256::new();let mut at=0i64;
    while at<before.size {
        book.clock()?;let wanted=usize::try_from((before.size-at).min(block.len() as i64))
            .map_err(|_|"fresh-census-control-bound")?;
        let used=nix::sys::uio::pread(book.fd(original)?,&mut block[..wanted],at)
            .map_err(|_|"fresh-census-control-read")?;
        check(used>0 && used<=wanted,"fresh-census-control-short")?;
        at=at.checked_add(used as i64).ok_or("fresh-census-control-bound")?;
        digest.update(&block[..used]);book.clock()?;
    }
    check(nix::sys::uio::pread(book.fd(original)?,&mut block[..1],at)
        .map_err(|_|"fresh-census-control-read")?==0,"fresh-census-control-extra")?;
    partial_fresh_raw_post(book,original,before,0)?;Ok(digest.finalize().into())
}
struct Census<'a> {
    enrollment:&'a OutputEnrollmentIndexData,inventory:&'a installation_record::InventoryIndex<'a>,
    seen:BTreeSet<&'a str>,root:usize,stage:usize,release:Option<usize>,conserved_root:Option<usize>,control_parents:Option<&'a BTreeMap<String,usize>>,
}
impl<'a> Census<'a> {
    fn row(&self,path:&str,role:OutputRoleData)->Result<&'a OutputEnrollmentData> {
        let row=self.enrollment.find_data(path).ok_or("fresh-census-unenrolled-output")?;
        check(row.role_data()==role,"fresh-census-enrollment-role")?;Ok(row)
    }
    fn mark(&mut self,book:&Install,row:&'a OutputEnrollmentData,original:usize,parent:usize,
        published_parent:Option<usize>)->Result<()> {
        same_birth(book,original,row.identity_data())?;
        let actual=book.fresh_output_identity(parent)?;
        if let Some(published)=published_parent {
            check(parent==published && matches!(row.path_data(),"app"|"runtime"),"fresh-census-publication-parent")?;
            same_birth(book,self.stage,row.parent_data())?;
            check(actual.fields_data().4==row.parent_data().fields_data().4,"fresh-census-publication-volume")?;
        }else if row.role_data()==OutputRoleData::RootControl && self.control_parents.is_some() && self.conserved_root.is_some() {
            // Only the enclosing authenticated eight-slot receipt can provide
            // this old root for an explicitly moved top-level control.
            same_birth(book,self.conserved_root.ok_or("fresh-census-conserved-root")?,row.parent_data())?;
        }else{check(actual.same_object_data(&row.parent_data()),"fresh-census-enrollment-parent")?;}
        check(self.seen.insert(row.path_data()),"fresh-census-duplicate-output")
    }
    fn payload(&mut self,book:&mut Install,parent:usize,leaf:&str,path:&str,depth:usize,
        published_parent:Option<usize>,work:&mut PartialFreshTreeWork)->Result<()> {
        check(payload_depth_data(path,depth,true),"fresh-census-payload-depth")?;
        let inventory=self.inventory;
        let row=self.row(path,OutputRoleData::PayloadDirectory)?;
        let original=book.open(Some(parent),leaf,true)?;
        self.mark(book,row,original,parent,published_parent)?;
        let before=partial_fresh_directory(book,original)?;
        let retained=work.retained;
        let result=(|| {
            let names=partial_fresh_children(path,inventory,work)?;
            let actual=partial_fresh_roster(book,original,&names,inventory,work)?;
            for (child,inode) in names.iter().zip(&actual) {
                if *inode==0 {continue;}
                let name=child.rsplit('/').next().ok_or("fresh-census-payload-leaf")?;
                if let Some(item)=inventory.files.get(*child) {
                    let row=self.row(child,OutputRoleData::PayloadFile)?;
                    check(row.expected_file_data()==Some((item.size,item.sha256.as_str())),"fresh-census-source-file")?;
                    let file=book.open(Some(original),name,false)?;
                    check(book.identity(file)?.ino==*inode,"fresh-census-roster-original")?;
                    self.mark(book,row,file,original,None)?;
                    let id=book.identity(file)?;
                    partial_fresh_file_shape_data(id,0,item.size,item.executable)?;
                    partial_fresh_raw_post(book,file,id,0)?;
                    book.forward_close(file,"fresh-census-payload-close")?;
                }else{
                    check(inventory.directories.contains(*child),"fresh-census-source-directory")?;
                    let named=book.named(Some(original),name).map_err(|_|"fresh-census-payload-name")?;
                    check(named.st_ino==*inode,"fresh-census-roster-original")?;
                    self.payload(book,original,name,child,depth+1,None,work)?;
                }
            }
            check(partial_fresh_directory(book,original)?==before,"fresh-census-payload-post")?;
            Ok(())
        })();
        // Memory accounting follows actual scope drops; errors retain the Book's
        // monotone original and control reservations for final owner closure.
        if result.is_ok(){work.retained=retained;}
        result?;book.forward_close(original,"fresh-census-directory-close")
    }
    fn control(&mut self,book:&mut Install,row:&'a OutputEnrollmentData)->Result<()> {
        let (parent,name)=match row.role_data() {
            OutputRoleData::MetadataFile=>(self.release.ok_or("fresh-census-release-required")?,
                row.path_data().strip_prefix("release/").ok_or("fresh-census-control-path")?),
            OutputRoleData::StageReceipt=>(self.stage,row.path_data().strip_prefix("stage/").ok_or("fresh-census-control-path")?),
            OutputRoleData::RootControl=>{
                let name=row.path_data().strip_prefix("control/").ok_or("fresh-census-control-path")?;
                (self.control_parents.and_then(|rows|rows.get(name)).copied().unwrap_or(self.root),name)
            },
            _=>return Err("fresh-census-control-role"),
        };
        let original=book.open(Some(parent),name,false)?;self.mark(book,row,original,parent,None)?;
        let (bytes,sha)=row.expected_file_data().ok_or("fresh-census-control-expected")?;
        check(book.identity(original)?.size as u64==bytes && control_hash(book,original,control_limit(row.role_data(),row.path_data())?)?
            ==archive_hex_data::<32>(sha)?,"fresh-census-control-content")?;
        book.forward_close(original,"fresh-census-control-close")
    }
    fn publication(&self,book:&mut Install,intent:&IntentData,phase:usize)->Result<()> {
        let name=fresh_data::PHASE_NAMES[phase];
        self.row(&format!("stage/{name}"),OutputRoleData::StageReceipt)?;
        check(partial_fresh_receipt(book,self.stage,phase,intent)?.state==PartialFreshFileState::Complete,
            "fresh-census-publication-receipt")
    }
}
fn inner<'a>(book:&mut Install,source:&'a worker::FreshRecoveryInput<'a>,launcher:Option<&applications::FreshRecovery>,stage:usize,journal_size:usize)
    ->Result<EnrolledAttemptObserved<'a>> {
    source.post(book)?;let selected=source.new_selection(book)?;let root=source.root_original();
    let (intent_original,intent_raw)=metadata_original(book,root,&data(transaction::intent_name_data(source.invocation()))?,transaction::INTENT_LIMIT)?;
    let intent=data(IntentData::parse_fresh_birth_data(&intent_raw,selected))?;
    check(intent.invocation_data()==source.invocation(),"fresh-census-current-intent")?;
    book.forward_close(intent_original,"fresh-census-intent-close")?;
    let (index,origin_original,journal_original,journal)=book.fresh_output_read(root,stage,&intent,selected,journal_size)?;
    bind_app_metadata(book,source,&index,stage,&intent)?;
    // Existing paired SOURCE audit proves the complete finite physical census,
    // source copy frontier and every generated control's own closed grammar.
    let first=partial_fresh_attempt(book,match launcher{Some(v)=>PartialFreshSource::FreshLauncher(source,v),None=>PartialFreshSource::Fresh(source)},source.invocation(),None)?;
    check(first.facts.cut!=PartialFreshCut::Recorded && first.intent.digest_data()==intent.digest_data()
        && first.intent.action_data()==ActionData::FreshInstall && *first.intent.next_data()==*selected.current_data(),
        "fresh-census-current-strict-fresh")?;
    let origin=archive_hex_data::<32>(index.origin_data().digest_data())?;
    let head=archive_hex_data::<32>(index.head_data())?;let entries=index.len_data();
    let versions=book.open(Some(root),"versions",true)?;
    let r=book.registration.participant.ok_or("fresh-census-current-r")?;
    let m=book.gate.participant.ok_or("fresh-census-current-m")?;
    for (original,expected) in [root,versions,r,m].into_iter().zip(index.origin_data().birth_data().identities_data()) {
        same_birth(book,original,expected)?;
    }
    // The authentic launcher owner audits every separately phase-enrolled
    // descendant, even when its live bundle is still in Applications. No DATA
    // count or pathname can substitute for this retained native owner.
    let launcher_counts=if let Some(launcher)=launcher {launcher.fresh_census_stage_counts(book,source)?}
        else{stage_launcher_counts(book,source,stage)?};
    let (_,inventory,_)=source.incoming(book)?;let payload_index=inventory.index()?;
    let release=match book.named(Some(versions),selected.current_data().binding_data().release) {
        Ok(_)=>Some(book.open(Some(versions),selected.current_data().binding_data().release,true)?),
        Err(Errno::ENOENT)=>None,Err(_)=>return Err("fresh-census-release-name"),
    };
    let mut census=Census{enrollment:&index,inventory:&payload_index,seen:BTreeSet::new(),root,stage,release,conserved_root:None,control_parents:None};
    if let Some(release)=release {
        let row=census.row("release",OutputRoleData::ReleaseDirectory)?;census.mark(book,row,release,versions,None)?;
    }
    for (path,published_parent,published_leaf,phase) in [("app",Some(root),paths::APP_NAME,3usize),
        ("runtime",release,"runtime",2usize)] {
        let staged=match book.named(Some(stage),path){Ok(_)=>true,Err(Errno::ENOENT)=>false,Err(_)=>return Err("fresh-census-payload-name")};
        let published=if let Some(parent)=published_parent {match book.named(Some(parent),published_leaf){
            Ok(_)=>true,Err(Errno::ENOENT)=>false,Err(_)=>return Err("fresh-census-payload-name")}}else{false};
        check(!(staged&&published),"fresh-census-payload-duplicate")?;
        if !staged&&!published{continue;}
        let (parent,leaf,rebound)=if staged{(stage,path,None)}else{
            census.publication(book,&first.intent,phase)?;
            let parent=published_parent.ok_or("fresh-census-publication-parent")?;(parent,published_leaf,Some(parent))};
        let mut work=PartialFreshTreeWork::new(8192)?;
        census.payload(book,parent,leaf,path,0,rebound,&mut work)?;
    }
    for row in index.rows_data() {
        if matches!(row.role_data(),OutputRoleData::MetadataFile|OutputRoleData::StageReceipt|OutputRoleData::RootControl) {
            census.control(book,row)?;
        }
    }
    check(census.seen.len()==entries && index.rows_data().all(|row|census.seen.contains(row.path_data())),
        "fresh-census-enrollment-missing")?;
    // The existing physical audit counts every file/directory exactly once.
    // Five separately bound originals are outside enrollment: Intent, origin,
    // journal, stage and versions. Root and R/M are not in the eight-slot audit.
    check(first.facts.files.checked_add(first.facts.directories)==(entries as u64).checked_add(5).and_then(|n|n.checked_add(launcher_counts.0)).and_then(|n|n.checked_add(launcher_counts.1)),
        "fresh-census-physical-membership")?;
    drop(census);drop(payload_index);drop(index);
    for original in [release,Some(versions),Some(journal_original),Some(origin_original)].into_iter().flatten() {
        book.check_name(original,true)?;book.forward_close(original,"fresh-census-anchor-close")?;
    }
    source.post(book)?;
    let after=partial_fresh_attempt(book,match launcher{Some(v)=>PartialFreshSource::FreshLauncher(source,v),None=>PartialFreshSource::Fresh(source)},source.invocation(),None)?;
    check(first.facts==after.facts && first.intent.digest_data()==after.intent.digest_data()
        && first.request==after.request && after.retry.is_none(),"fresh-census-whole-post")?;
    source.post(book)?;Ok(EnrolledAttemptObserved{source,audit:after,origin,journal,head,entries})
}
pub(in crate::installer) fn observe<'a>(book:&mut Install,source:&'a worker::FreshRecoveryInput<'a>,launcher:Option<&applications::FreshRecovery>)
    ->Result<EnrolledAttemptObserved<'a>> {
    source.post(book)?;let root=source.root_original();let stage_name=format!(".install-{}",source.invocation());
    let (files,directories,index_peak)=source.incoming_index_peak(book)?;
    let (_,inventory,_)=source.incoming(book)?;
    let audit_quote=partial_fresh_inventory_quote_data(files,directories,inventory)?;
    let records=book.originals.len().checked_add(audit_quote.checked_mul(2).ok_or("fresh-census-original-bound")?)
        .and_then(|n|n.checked_add(files)).and_then(|n|n.checked_add(directories.checked_mul(2)?))
        .and_then(|n|n.checked_add(256)).filter(|n|*n<=installation_record::ORIGINAL_LIMIT)
        .ok_or("fresh-census-original-bound")?;
    reserve_removal_original_storage(book,records)?;
    check(book.originals.iter().filter(|r|r.fd.is_some()).count().checked_add(72).is_some_and(|n|n<=96),
        "fresh-census-live-bound")?;
    let result=removal_archive_scope(book,|book| {
        let stage=book.open(Some(root),&stage_name,true)?;removal_archive_stat(book,stage,true,0o700)?;
        let journal=book.named(Some(stage),fresh_data::JOURNAL_NAME).map_err(|_|"fresh-census-journal-required")?;
        let size=usize::try_from(journal.st_size).map_err(|_|"fresh-census-journal-bound")?;
        check(size<=fresh_data::JOURNAL_LIMIT,"fresh-census-journal-bound")?;
        let entries=(size/(fresh_data::ENTRY_MIN+4)).min(fresh_data::ENROLLMENT_LIMIT);
        let quote=(size as u64).checked_mul(4).and_then(|n|n.checked_add((entries as u64).checked_mul(1152)?))
            .and_then(|n|n.checked_add(index_peak as u64)).and_then(|n|n.checked_add(4*fresh_data::ORIGIN_LIMIT as u64))
            .and_then(|n|n.checked_add(PARTIAL_FRESH_WORK as u64+131072)).ok_or("fresh-census-control-bound")?;
        check(removal_effective_control_bytes(book)?.checked_add(quote)
            .is_some_and(|n|n<=installation_record::CONTROL_LIMIT as u64),"fresh-census-control-bound")?;
        book.removal_control_reserved=book.removal_control_reserved.checked_add(quote).ok_or("fresh-census-control-bound")?;
        let observed=inner(book,source,launcher,stage,size)?;
        check(book.originals.len()<=records,"fresh-census-original-quote")?;
        // Retain8KiB for the private native observation. No new writer or move
        // may spend that reservation or infer completed old syscall returns.
        book.removal_control_reserved=book.removal_control_reserved.checked_sub(quote-8192)
            .ok_or("fresh-census-control-bound")?;Ok(observed)
    });
    result.and_then(|observed|{source.post(book)?;Ok(observed)})
}

// All names below are a closed namespace. New directories and receipt writers
// use the existing Book's exclusive creation/known-close ledger. No lookup may
// replace a missing actual creation result in the same call.
pub(in crate::installer) const ROOT_NAME:&str=".fresh-conservation-v1";
const ORIGIN_NAME:&str="origin.json";
const ATTEMPT_NAME:&str="attempt.json";
const BLANK_NAME:&str="blank-versions.json";
const RECEIPT_LIMIT:usize=16*1024;
const RECEIPT_COUNT:usize=12;
const RECEIPT_QUOTE:usize=RECEIPT_LIMIT*RECEIPT_COUNT;
fn hex(raw:&[u8])->String{raw.iter().map(|b|format!("{b:02x}")).collect()}
fn directory(book:&mut Install,parent:usize,name:&str,mode:u32)->Result<usize> {
    let before=worker::fresh_conservation_parent_before(book,parent)?;
    let original=book.directory(parent,name,true,mode)?;
    worker::reinstall_parent_returned(book,parent,before)?;Ok(original)
}
fn copy_control(book:&mut Install,parent:usize,name:&str,body:&[u8])->Result<()> {
    let before=worker::fresh_conservation_parent_before(book,parent)?;
    let writer=book.create_file(parent,name,Role::ReceiptWriter)?;
    worker::reinstall_parent_returned(book,parent,before)?;
    let original=book.record_reserved_file(writer,body)?;book.persist(parent,false)?;
    if name=="inventory.json"{held_inventory(book,original,body)?;}else{held_bytes(book,original,body)?;}
    book.forward_close(original,"fresh-conservation-source-copy-close")
}
fn bytes(value:&serde_json::Value)->Result<Vec<u8>> {
    let mut raw=serde_json::to_vec(value).map_err(|_|"fresh-conservation-json")?;raw.push(b'\n');
    check(raw.len()<=RECEIPT_LIMIT,"fresh-conservation-receipt-bound")?;Ok(raw)
}
fn birth_value(book:&Install,original:usize)->Result<serde_json::Value> {
    serde_json::to_value(book.fresh_output_identity(original)?.fields_data()).map_err(|_|"fresh-conservation-birth")
}
fn birth_data(value:&serde_json::Value)->Result<transaction::FreshBirthIdentityData> {
    let (dev,ino,sec,nsec,uuid)=serde_json::from_value(value.clone()).map_err(|_|"fresh-conservation-birth")?;
    data(transaction::FreshBirthIdentityData::from_original_fields_data(dev,ino,sec,nsec,uuid))
}
fn receipt_write(book:&mut Install,parent:usize,name:&str,mut value:serde_json::Value)->Result<(usize,[u8;32])> {
    book.absent(parent,name)?;
    // This exact reserved writer is included without hashing its own body.
    let before=worker::fresh_conservation_parent_before(book,parent)?;
    let writer=book.create_file(parent,name,Role::ReceiptWriter)?;
    worker::reinstall_parent_returned(book,parent,before)?;
    value["writer"]=birth_value(book,writer)?;
    let raw=bytes(&value)?;
    let reader=book.record_reserved_file(writer,&raw)?;
    book.persist(parent,false)?;held_bytes(book,reader,&raw)?;
    let digest=Sha256::digest(&raw).into();
    // A caller never observes a receipt returned before both original closes.
    book.forward_close(reader,"fresh-conservation-receipt-close")?;
    Ok((writer,digest))
}
fn facts_value(value:&PartialFreshAttemptAudit)->serde_json::Value {
    serde_json::json!({"digest":hex(&value.facts.digest),
        "payloadBytes":value.facts.payload_bytes,"controlBytes":value.facts.control_bytes,
        "files":value.facts.files,"directories":value.facts.directories})
}
fn slots_value(book:&mut Install,source:&worker::FreshRecoveryInput<'_>,value:&PartialFreshAttemptAudit)->Result<serde_json::Value> {
    let mut out=Vec::with_capacity(8);
    for slot in &value.slots {
        let name=partial_fresh_name_data(slot.slot,&value.invocation,source.new_selection(book)?)?;
        let parent=if slot.side==PartialFreshSide::Current{source.root_original()}else{value.retry.ok_or("fresh-conservation-preserved")?};
        let original=book.open(Some(parent),&name,slot.identity.mode&0o170000==0o040000)?;
        check(book.identity(original)?==slot.identity,"fresh-conservation-top-original")?;
        out.push(serde_json::json!({"name":name,"birth":birth_value(book,original)?,
            "identity":worker::identity_data(slot.identity),"preserved":slot.side==PartialFreshSide::Preserved,
            "bytes":slot.counts.bytes,"files":slot.counts.files,"directories":slot.counts.directories,"controls":slot.counts.controls}));
        book.forward_close(original,"fresh-conservation-top-close")?;
    }Ok(serde_json::Value::Array(out))
}
// Repeated preservation audits traverse the authenticated interrupted output,
// not every member of the incoming package. A paired audit opens at most two
// originals per present file and four per present directory (source/output
// handles and separate roster readers). The fixed allowance also covers the
// control readers, roots, retry roster, and optional launcher ancestors.
// Moving slots cannot grow these counts: every before/after/receipt audit is
// checked against the SAME retained initial facts by partial_fresh_equivalent.
// Keep four full-source POST allowances and the full Fresh allowance; no
// credit is taken for closed originals or already executed phases.
fn preservation_original_quote_data(used:usize,files:u64,directories:u64,slots:usize,incoming:usize)->Result<usize> {
    let reason="fresh-conservation-original-quote";
    check((1..=8).contains(&slots),reason)?;
    let files=usize::try_from(files).map_err(|_|reason)?;
    let directories=usize::try_from(directories).map_err(|_|reason)?;
    let audit=partial_fresh_retry_original_quote_data(files,directories)?
        .checked_add(PARTIAL_FRESH_LAUNCHER_ORIGINALS).ok_or(reason)?;
    // Initial audit, retry-creation receipt, three audits per move, blank audit,
    // and five additional whole-observation/transport margins. Prefixes use the
    // entire slot count, so resumption never refunds consumed original records.
    let audits=slots.checked_mul(3).and_then(|n|n.checked_add(8)).ok_or(reason)?;
    used.checked_add(audit.checked_mul(audits).ok_or(reason)?)
        .and_then(|n|n.checked_add(incoming.checked_mul(5)?))
        .and_then(|n|n.checked_add(64+256)).filter(|n|*n<=installation_record::ORIGINAL_LIMIT)
        .ok_or(reason)
}

struct ConservationRootOriginal { root:usize,namespace:usize,birth:transaction::FreshBirthIdentityData }
// A paired audit retains two directories per inventory depth (0..=16),
// with at most two leaf-file readers OR a separate roster reader. Its fixed
// top-level readers fit18: intent, stage, enrollment pair, four phase receipts,
// versions/release, inventory/record, published app and four root controls.
// Launcher ancestors run in a nested scope before versions/release and root
// controls, and fit the same18. Tree recursion closes each child before its
// sibling; payload files do not accumulate across the inventory.
// Charge five more owners (namespace, attempt, retry, moved top, blank versions),
// four worker handles and one extra roster reader even when already held or
// mutually exclusive. This is64 future handles, not72 new handles on top of
// the newly retained conservation owners. The actual Book96 cap is unchanged.
fn preservation_live_quote_data(live:usize)->Result<usize> {
    let future=2*(PAYLOAD_DIRECTORY_DEPTH_LIMIT+1)+2+18+5+worker::EXTRA_LIVE+1;
    live.checked_add(future).filter(|n|*n<=96).ok_or("fresh-conservation-live-quote")
}
// Current-process native owner. The immutable receipts describe only completed
// observations. Historical reobservation is a separate constructor; it cannot
// fill this owner's syscall-return ledger or manufacture settle_return_data.
pub(in crate::installer) struct ConservationAttemptOriginal {
    container:ConservationRootOriginal,child:usize,child_birth:transaction::FreshBirthIdentityData,
    ledger:PartialFreshPreservation,attempt:[u8;32],head:[u8;32],receipts:usize,
    source:[String;3],first:Option<&'static str>,blank:Option<usize>,blank_receipt:Option<[u8;32]>,
}
impl ConservationAttemptOriginal {
    pub(in crate::installer) fn create(book:&mut Install,observed:EnrolledAttemptObserved<'_>)->Result<Self> {
        let source=observed.source;source.post(book)?;
        let fresh=observe(book,source,None)?;
        check(observed.audit.facts==fresh.audit.facts && observed.origin==fresh.origin
            && observed.journal==fresh.journal && observed.head==fresh.head && observed.entries==fresh.entries,
            "fresh-conservation-precreate-census")?;
        let value=fresh.audit;
        check(value.retry.is_none() && value.collision.is_none() && (1..=8).contains(&value.slots.len())
            && value.slots.last().is_some_and(|slot|slot.slot==PartialFreshTop::Versions)
            && value.slots.iter().all(|slot|slot.side==PartialFreshSide::Current),"fresh-conservation-initial-slots")?;
        let root=source.root_original();
        if let Some(prior)=source.prior_namespace(){prior.post(book)?;
            let current=namespace(book,root,source.new_selection(book)?,Some(&prior.reference))?.ok_or("fresh-conservation-prior")?;
            check(current.matches(prior),"fresh-conservation-prior-changed")?;
            let mut union=current.facts;union.insert(InstallInvocationFactData::intent(&value.intent)?)?;
        }else{book.absent(root,ROOT_NAME)?;}
        let (producer,signature)=source.incoming_controls(book)?;let (_,inventory,raw)=source.incoming(book)?;
        let controls=producer.len().checked_add(signature.len()).and_then(|n|n.checked_add(raw.len()))
            .and_then(|n|n.checked_add(RECEIPT_QUOTE)).ok_or("fresh-conservation-control-quote")?;
        let (files,dirs,index_peak)=source.incoming_index_peak(book)?;
        let retry=partial_fresh_inventory_quote_data(files,dirs,inventory)?;
        let before=preservation_original_quote_data(book.originals.len(),value.facts.files,
            value.facts.directories,value.slots.len(),retry)?;
        reserve_removal_original_storage(book,before)?;
        check(removal_effective_control_bytes(book)?.checked_add(controls as u64).and_then(|n|n.checked_add(index_peak as u64))
            .and_then(|n|n.checked_add(PARTIAL_FRESH_WORK as u64)).is_some_and(|n|n<=installation_record::CONTROL_LIMIT as u64),
            "fresh-conservation-control-quote")?;
        let payload=inventory.index()?.payload_bytes;
        let prior_bytes=source.prior_namespace().map_or(0,|v|v.bytes);
        partial_fresh_storage_data(prior_bytes.checked_add(controls as u64).ok_or("fresh-conservation-storage-quote")?,
            value.facts.payload_bytes+value.facts.control_bytes,payload,raw.len(),producer.len(),signature.len())?;
        preservation_live_quote_data(book.originals.iter().filter(|r|r.fd.is_some()).count())?;
        book.removal_control_reserved=book.removal_control_reserved.checked_add(controls as u64).ok_or("fresh-conservation-control-quote")?;
        let commitments=[hash(producer),hash(signature),hash(raw)];
        let (namespace,namespace_birth,origin)=if let Some(prior)=source.prior_namespace() {
            let namespace=book.open(Some(root),ROOT_NAME,true)?;removal_archive_stat(book,namespace,true,0o700)?;
            receipt_birth(book,namespace,&serde_json::to_value(prior.birth.fields_data()).map_err(|_|"fresh-conservation-birth")?)?;
            (namespace,prior.birth,prior.origin)
        }else{
            let namespace=directory(book,root,ROOT_NAME,0o700)?;
            let namespace_birth=book.fresh_output_identity(namespace)?;
            let (_,origin)=receipt_write(book,namespace,ORIGIN_NAME,serde_json::json!({
            "schemaVersion":1,"kind":"mrk-fresh-conservation-origin-v1","root":birth_value(book,root)?,
            "namespace":birth_value(book,namespace)?,"invocation":value.invocation,
            "intentSha256":value.intent.digest_data(),"outputOriginSha256":hex(&observed.origin),
            "outputJournalSha256":hex(&observed.journal),"outputHead":hex(&observed.head),
            "outputEntries":observed.entries,"source":commitments}))?;
            (namespace,namespace_birth,origin)
        };
        let child=directory(book,namespace,&format!("attempt-{}",value.invocation),0o700)?;
        let child_birth=book.fresh_output_identity(child)?;
        // Keep complete authenticated source controls for later conserved
        // history/removal readers, even when this output stopped before metadata.
        for (name,body) in [("producer.json",producer),("producer.sig",signature),("inventory.json",raw)] {
            copy_control(book,child,name,body)?;
        }
        let slots=slots_value(book,source,&value)?;
        let (_,attempt)=receipt_write(book,child,ATTEMPT_NAME,serde_json::json!({
            "schemaVersion":1,"kind":"mrk-fresh-conservation-attempt-v1","originSha256":hex(&origin),
            "attempt":birth_value(book,child)?,"invocation":value.invocation,"requestId":value.request,
            "intentSha256":value.intent.digest_data(),"source":commitments,
            "output":{"outputOriginSha256":hex(&observed.origin),"outputJournalSha256":hex(&observed.journal),
                "outputHead":hex(&observed.head),"outputEntries":observed.entries},
            "previous":value.intent.fresh_conservation_data(),"facts":facts_value(&value),"slots":slots}))?;
        let ledger=PartialFreshPreservation{invocation:value.invocation,request:value.request,intent:value.intent,
            initial:value.facts,root,child,retry:None,collision:None,retry_quote:value.retry_quote,
            slots:value.slots,prefix:0,pending:None,unknown:false,first:None,returned_settled:false};
        let owner=Self{container:ConservationRootOriginal{root,namespace,birth:namespace_birth},child,child_birth,
            ledger,attempt,head:attempt,receipts:0,source:commitments,first:None,blank:None,blank_receipt:None};
        owner.post(book,source)?;Ok(owner)
    }
    pub(in crate::installer) fn child_original(&self)->Result<usize>{Ok(self.child)}
    pub(in crate::installer) fn namespace_inode(&self,book:&Install)->Result<u64>{Ok(book.identity(self.container.namespace)?.ino)}
    pub(in crate::installer) fn preservation(&self)->&PartialFreshPreservation{&self.ledger}
    pub(in crate::installer) fn preservation_mut(&mut self)->&mut PartialFreshPreservation{&mut self.ledger}
    pub(in crate::installer) fn post(&self,book:&Install,source:&worker::FreshRecoveryInput<'_>)->Result<()> {
        source.post(book)?;check(self.first.is_none() && !book.unknown && source.root_original()==self.container.root
            && source.invocation()==self.ledger.invocation,"fresh-conservation-owning-source")?;
        for (original,birth,parent,name) in [(self.container.namespace,self.container.birth,self.container.root,ROOT_NAME.to_owned()),
            (self.child,self.child_birth,self.container.namespace,format!("attempt-{}",self.ledger.invocation))] {
            check(book.originals[original].parent==Some(parent) && book.originals[original].name==name,"fresh-conservation-original-parent")?;
            removal_archive_stat(book,original,true,0o700)?;
            check(book.fresh_output_identity(original)?==birth,"fresh-conservation-original-birth")?;
        }
        let (producer,signature)=source.incoming_controls(book)?;let (_,_,inventory)=source.incoming(book)?;
        check([hash(producer),hash(signature),hash(inventory)]==self.source,"fresh-conservation-source-changed")
    }
    pub(in crate::installer) fn own_parent(&self,book:&Install,source:&worker::FreshRecoveryInput<'_>,n:usize)->Result<()> {
        check(source.root_original()==self.container.root && source.invocation()==self.ledger.invocation
            && self.first.is_none() && !book.unknown,"fresh-conservation-owning-source")?;
        let allowed=n==self.container.root || n==self.child && book.originals[n].parent==Some(self.container.namespace)
            && book.originals[n].name==format!("attempt-{}",self.ledger.invocation)
            || self.ledger.retry==Some(n) && book.originals[n].parent==Some(self.child)
                && book.originals[n].name==partial_fresh_retry_name_data(&self.ledger.invocation)?;
        check(allowed,"fresh-conservation-effect-parent")
    }
    pub(in crate::installer) fn quote(&self,book:&mut Install,context:&worker::ReinstallPreservationContext<'_>)->Result<()> {
        context.post_source(book)?;
        let future=preservation_original_quote_data(book.originals.len(),self.ledger.initial.files,
            self.ledger.initial.directories,self.ledger.slots.len(),self.ledger.retry_quote)?;
        reserve_removal_original_storage(book,future)?;
        preservation_live_quote_data(book.originals.iter().filter(|r|r.fd.is_some()).count())?;
        context.post_source(book)
    }
    pub(in crate::installer) fn record_prefix(&mut self,book:&mut Install,source:&worker::FreshRecoveryInput<'_>)->Result<()> {
        let result=(|| {
            self.post(book,source)?;
            check(self.receipts==self.ledger.prefix && self.receipts<=self.ledger.slots.len()
                && self.ledger.pending.is_none() && !self.ledger.failed_data(),"fresh-conservation-prefix-order")?;
            let actual={let context=worker::ReinstallPreservationContext::Fresh{source,owner:&mut *self};
                partial_fresh_attempt(book,PartialFreshSource::Effect(&context),source.invocation(),context.preservation().retry)?};
            partial_fresh_equivalent(&self.ledger,&actual,self.ledger.prefix)?;
            let retry=self.ledger.retry.ok_or("fresh-conservation-preserved-original")?;
            let slots=slots_value(book,source,&actual)?;
            let (_,sha)=receipt_write(book,self.child,&format!("prefix-{}.json",self.ledger.prefix),serde_json::json!({
                "schemaVersion":1,"kind":"mrk-fresh-conservation-prefix-v1","invocation":self.ledger.invocation,
                "attemptSha256":hex(&self.attempt),"previousSha256":hex(&self.head),
                "prefix":self.ledger.prefix,"preserved":birth_value(book,retry)?,"facts":facts_value(&actual),"slots":slots}))?;
            self.head=sha;self.receipts+=1;self.post(book,source)
        })();
        if let Err(why)=result{self.first.get_or_insert(why);}result
    }
}

// Actual blank cut only. This type cannot expose worker Ready and has no DATA
// constructor. A separate ordinary observation must consume it before Intent.
pub(in crate::installer) struct FreshBlankReady {
    root:usize,versions:usize,versions_birth:transaction::FreshBirthIdentityData,
    reference:transaction::FreshConservationReferenceData,
}
// A native preparation boundary, never a serialized or caller-selected list.
// Failure leaves every remaining capability in the same Book for finality.
// The completed preservation owner is no longer used after its blank cut;
// the following ordinary observation independently reads the full namespace.
pub(in crate::installer) struct PreparationOriginals { first: usize }
impl PreparationOriginals {
    pub(in crate::installer) fn begin(book: &Install) -> Self {
        Self { first: book.originals.len() }
    }
    pub(in crate::installer) fn finish(self, book: &mut Install, ready: &FreshBlankReady) -> Result<()> {
        check(ready.root < self.first && book.gate.parent == Some(ready.root)
            && book.gate.verified && book.gate.exclusive_acquired && !book.worker_stderr_is_gate
            && book.originals.get(ready.versions).is_some_and(|row|
                row.parent == Some(ready.root) && row.name == "versions"),
            "fresh-preparation-blank")?;
        check(book.fresh_output_identity(ready.versions)? == ready.versions_birth,
            "fresh-preparation-blank")?;
        book.close_preparation_originals(self.first, ready.versions)
    }
}
impl ConservationAttemptOriginal {
    pub(in crate::installer) fn blank(&mut self,book:&mut Install,source:&worker::FreshRecoveryInput<'_>)->Result<FreshBlankReady> {
        let result=(|| {
            self.post(book,source)?;
            check(self.ledger.returned_settled_data() && self.receipts==self.ledger.slots.len()+1
                && self.blank.is_none() && self.blank_receipt.is_none(),"fresh-conservation-blank-once")?;
            let audit={let context=worker::ReinstallPreservationContext::Fresh{source,owner:&mut *self};
                partial_fresh_attempt(book,PartialFreshSource::Effect(&context),source.invocation(),context.preservation().retry)?};
            partial_fresh_equivalent(&self.ledger,&audit,self.ledger.slots.len())?;
            let root=self.container.root;
            let wanted:BTreeSet<String>=[ROOT_NAME,paths::REGISTRATION_GATE_NAME,paths::MAINTENANCE_GATE_NAME]
                .into_iter().map(str::to_owned).collect();
            exact_roster(book,root,&wanted)?;book.absent(root,"versions")?;
            let versions=directory(book,root,"versions",0o755)?;self.blank=Some(versions);
            check(roster_now(book,versions)?.is_empty(),"fresh-conservation-blank-versions")?;
            let versions_birth=book.fresh_output_identity(versions)?;
            let (_,sha)=receipt_write(book,self.child,BLANK_NAME,serde_json::json!({
                "schemaVersion":1,"kind":"mrk-fresh-conservation-blank-v1","invocation":self.ledger.invocation,
                "attemptSha256":hex(&self.attempt),"prefixSha256":hex(&self.head),"prefix":self.ledger.prefix,
                "root":birth_value(book,root)?,"versions":birth_value(book,versions)?,"facts":facts_value(&audit)}))?;
            self.blank_receipt=Some(sha);
            let mut wanted=wanted;wanted.insert("versions".into());exact_roster(book,root,&wanted)?;
            check(roster_now(book,versions)?.is_empty() && book.fresh_output_identity(versions)?==versions_birth,
                "fresh-conservation-blank-post")?;self.post(book,source)?;
            Ok(FreshBlankReady{root,versions,versions_birth,
                reference:data(transaction::FreshConservationReferenceData::new_data(&self.ledger.invocation,&hex(&sha)))?})
        })();
        if let Err(why)=result{self.first.get_or_insert(why);}result
    }
}
impl FreshBlankReady {
    pub(in crate::installer) fn versions_original(&self)->usize{self.versions}
    pub(in crate::installer) fn consume(self,book:&Install,observed:&mut Observed)->Result<()> {
        check(observed.action==ActionData::FreshInstall && observed.history.is_none() && observed.intent.is_none()
            && observed.prepared.destination==self.root && observed.prepared.versions==self.versions
            && observed.fresh_conservation.as_ref()==Some(&self.reference)
            && book.fresh_output_identity(self.versions)?==self.versions_birth,"fresh-conservation-independent-fresh")?;
        observed.controls_post(book)
    }
}

// This read-only expected source is formed only from the actual conservation
// controls. It permits the existing conserved payload reader, never a copy.
// A retained read snapshots CURRENT root metadata without rebinding its
// historical Original. Ordinary publication may have changed timestamps;
// the held object/name, protection and the read's exact POST still govern.
pub(super) fn retained_root_identity(book:&Install,root:usize)->Result<Identity> {
    check(book.gate.parent==Some(root) && book.gate.verified
        && (book.gate.exclusive_acquired || book.worker_stderr_is_gate),"fresh-conservation-current-exclusion")?;
    book.check_name(root,false)?;book.protected(root,true,Some(0o755))?;
    native::no_xattrs(book.fd(root)?.as_fd()).map_err(|_|"fresh-conservation-root-attributes")?;
    let held=stat::fstat(book.fd(root)?).map_err(|_|"fresh-conservation-root-stat")?;
    let row=&book.originals[root];let named=book.named(row.parent,&row.name).map_err(|_|"fresh-conservation-root-name")?;
    check(Identity::of(&held)==Identity::of(&named) && archive_directory_data(Identity::of(&held),held.st_flags,false) && named.st_flags==0
        && book.identity(root)?.same_object(Identity::of(&held)),"fresh-conservation-root-original")?;
    book.clock()?;Ok(Identity::of(&held))
}
pub(super) struct RetainedInput {
    pub(super) root:usize,pub(super) child:usize,originals:[usize;3],raw:[Vec<u8>;3],
    descriptor:mobile_release_desktop::macos_install_producer::ProducerData,inventory:Inventory,
}
impl RetainedInput {
    pub(super) fn post(&self,book:&Install)->Result<()> {
        check(book.gate.parent==Some(self.root) && book.gate.verified
            && (book.gate.exclusive_acquired || book.worker_stderr_is_gate),"fresh-conservation-current-exclusion")?;
        retained_root_identity(book,self.root)?;book.check_name(self.child,true)?;
        for n in 0..2 {held_bytes(book,self.originals[n],&self.raw[n])?;}
        held_inventory(book,self.originals[2],&self.raw[2])
    }
    pub(super) fn new_selection(&self,book:&Install)->Result<&ReleaseSetData>{self.post(book)?;Ok(self.descriptor.release_set_data())}
    pub(super) fn incoming(&self,book:&Install)->Result<(usize,&Inventory,&[u8])>{self.post(book)?;Ok((self.child,&self.inventory,&self.raw[2]))}
    pub(super) fn incoming_controls(&self,book:&Install)->Result<(&[u8],&[u8])>{self.post(book)?;Ok((&self.raw[0],&self.raw[1]))}
    pub(super) fn incoming_index_peak(&self,book:&Install)->Result<(usize,usize,usize)>{self.post(book)?;worker::reinstall_index_quote_data(&self.inventory)}
}
fn shape(value:&serde_json::Value,keys:&[&str])->Result<()> {
    let map=value.as_object().ok_or("fresh-conservation-receipt-shape")?;
    check(map.len()==keys.len() && keys.iter().all(|key|map.contains_key(*key)),"fresh-conservation-receipt-shape")
}
fn receipt_read(book:&mut Install,parent:usize,name:&str,kind:&str,keys:&[&str])->Result<(serde_json::Value,[u8;32],usize)> {
    let (original,raw)=metadata_original(book,parent,name,RECEIPT_LIMIT)?;
    let value=mobile_release_desktop::protocol::strict_json(&raw).map_err(|_|"fresh-conservation-receipt-json")?;
    shape(&value,keys)?;
    check(value["schemaVersion"].as_u64()==Some(1) && value["kind"].as_str()==Some(kind)
        && bytes(&value)?==raw && book.fresh_output_identity(original)?.same_object_data(&birth_data(&value["writer"])?),
        "fresh-conservation-receipt-original")?;
    let sha=Sha256::digest(&raw).into();book.forward_close(original,"fresh-conservation-read-close")?;
    Ok((value,sha,raw.len()))
}
fn receipt_birth(book:&Install,original:usize,value:&serde_json::Value)->Result<()> {
    check(book.fresh_output_identity(original)?.same_object_data(&birth_data(value)?),"fresh-conservation-receipt-birth")
}
fn slot_births(book:&mut Install,retry:usize,slots:&serde_json::Value)->Result<()> {
    let rows=slots.as_array().ok_or("fresh-conservation-slots")?;
    check((1..=8).contains(&rows.len()),"fresh-conservation-slots")?;
    for row in rows {
        shape(row,&["name","birth","identity","preserved","bytes","files","directories","controls"])?;
        let name=row["name"].as_str().ok_or("fresh-conservation-slot-name")?;
        check(component(name)||name==paths::APP_NAME,"fresh-conservation-slot-name")?;
        let named=book.named(Some(retry),name).map_err(|_|"fresh-conservation-slot-name")?;
        let dir=named.st_mode&nix::libc::S_IFMT==nix::libc::S_IFDIR;
        let original=book.open(Some(retry),name,dir)?;
        // The receipt binds this exact persistent app original before the
        // canonical first snapshot. A subsequent alias must conserve it.
        if name==paths::APP_NAME {
            check(birth_before_attributes(book,original)?.same_object_data(&birth_data(&row["birth"])?),
                "fresh-conservation-app-birth")?;
            book.capture_existing_app_metadata(original,true,"fresh-conservation-app-metadata")?;
            let snapshot=book.originals[original].existing_app_metadata.ok_or("fresh-conservation-app-metadata")?;
            retain_metadata(book,original,birth_data(&row["birth"])?,snapshot)?;
        }
        receipt_birth(book,original,&row["birth"])?;
        book.forward_close(original,"fresh-conservation-slot-close")?;
    }Ok(())
}
// At most one extra live versions probe per retained attempt after rehome,
// plus16 fixed aliases/candidates. These are charged rows, never close credit.
const TRANSPORT_ORIGINAL_MARGIN:usize=16+transaction::INVOCATION_LIMIT;
pub(in crate::installer) struct Namespace {
    pub(super) reference:transaction::FreshConservationReferenceData,
    pub(super) bytes:u64,pub(super) files:u64,pub(super) directories:u64,pub(super) controls:u64,
    pub(super) facts:InstallInvocationSetData,
    root:usize,parent:usize,identity:Identity,birth:transaction::FreshBirthIdentityData,origin:[u8;32],projection:[u8;32],names:BTreeSet<String>,originals:usize,
}
// Complete retained observation. The source copies and every receipt are
// counted in addition to all physically preserved payload/control bytes.
struct AttemptRead {
    reference:transaction::FreshConservationReferenceData,previous:Option<transaction::FreshConservationReferenceData>,
    bytes:u64,files:u64,directories:u64,controls:u64,facts:InstallInvocationSetData,
    before_versions:transaction::FreshBirthIdentityData,blank_versions:transaction::FreshBirthIdentityData,
}
fn read_attempt(book:&mut Install,root:usize,parent:usize,container:usize,selected:&ReleaseSetData,
    origin:&serde_json::Value,origin_sha:[u8;32],invocation:&str)->Result<AttemptRead> {
    let child_name=format!("attempt-{invocation}");
        let child=book.open(Some(container),&child_name,true)?;removal_archive_stat(book,child,true,0o700)?;
        let (attempt,attempt_sha,attempt_bytes)=receipt_read(book,child,ATTEMPT_NAME,"mrk-fresh-conservation-attempt-v1",
            &["schemaVersion","kind","originSha256","attempt","invocation","requestId","intentSha256","source","output","previous","facts","slots","writer"])?;
        check(attempt["originSha256"]==hex(&origin_sha) && attempt["invocation"]==invocation,"fresh-conservation-attempt-link")?;
        shape(&attempt["output"],&["outputOriginSha256","outputJournalSha256","outputHead","outputEntries"])?;
        let previous:Option<transaction::FreshConservationReferenceData>=serde_json::from_value(attempt["previous"].clone())
            .map_err(|_|"fresh-conservation-previous")?;
        if let Some(previous)=&previous {
            data(transaction::FreshConservationReferenceData::new_data(previous.invocation_data(),previous.receipt_sha256_data()))?;
            check(previous.invocation_data()!=invocation && previous.invocation_data()!=attempt["requestId"].as_str().ok_or("fresh-conservation-request")?,
                "fresh-conservation-previous")?;
        }else{
            check(attempt["invocation"]==origin["invocation"] && attempt["intentSha256"]==origin["intentSha256"]
                && attempt["source"]==origin["source"] && ["outputOriginSha256","outputJournalSha256","outputHead","outputEntries"]
                    .iter().all(|key|attempt["output"][*key]==origin[*key]),"fresh-conservation-origin-attempt")?;
        }
        receipt_birth(book,child,&attempt["attempt"])?;
        let mut originals=[0usize;3];let mut raw:[Vec<u8>;3]=std::array::from_fn(|_|Vec::new());
        for (n,name,limit) in [(0,"producer.json",mobile_release_desktop::macos_install_producer::DESCRIPTOR_LIMIT),
            (1,"producer.sig",mobile_release_desktop::macos_install_producer::SIGNATURE_LIMIT),
            (2,"inventory.json",installation_record::INVENTORY_LIMIT)] {
            let value=if n==2 {metadata_inventory_original(book,child,name,limit)?}
                else {metadata_original(book,child,name,limit)?};originals[n]=value.0;raw[n]=value.1;
            check(attempt["source"][n]==hash(&raw[n]),"fresh-conservation-source-copy")?;
        }
        let descriptor=mobile_release_desktop::macos_install_producer::ProducerData::parse_data(&raw[0],selected.target_data())
            .map_err(|_|"fresh-conservation-producer")?;
        check(selected.contains_data(descriptor.release_set_data().current_data()),"fresh-conservation-source-selection")?;
        let inventory=Inventory::parse_for_selected_release(&raw[2],descriptor.release_set_data().current_data())?;
        let read=RetainedInput{root,child,originals,raw,descriptor,inventory};read.post(book)?;
        let (files,dirs,_)=read.incoming_index_peak(book)?;
        let quote=partial_fresh_inventory_quote_data(files,dirs,&read.inventory)?;
        reserve_removal_original_storage(book,book.originals.len().checked_add(quote.checked_mul(2)
            .ok_or("fresh-conservation-originals")?).and_then(|n|n.checked_add(128)).ok_or("fresh-conservation-originals")?)?;
        let retry_name=partial_fresh_retry_name_data(invocation)?;
        let retry=book.open(Some(child),&retry_name,true)?;removal_archive_stat(book,retry,true,0o700)?;
        slot_births(book,retry,&attempt["slots"])?;
        removal_archive_scope(book,|book|{
            let (_,raw)=metadata_original(book,retry,&data(transaction::intent_name_data(invocation))?,transaction::INTENT_LIMIT)?;
            let intent=data(IntentData::parse_fresh_birth_data(&raw,read.new_selection(book)?))?;
            check(intent.digest_data()==attempt["intentSha256"].as_str().ok_or("fresh-conservation-intent")?,"fresh-conservation-intent")?;
            let stage=book.open(Some(retry),&format!(".install-{invocation}"),true)?;
            applications::retained_fresh_metadata(book,stage,&intent)
        })?;
        let audit=partial_fresh_attempt(book,PartialFreshSource::Retained(&read),invocation,Some(retry))?;
        retained_enrollment(book,&read,&audit,&attempt["output"])?;
        check(attempt["intentSha256"]==audit.intent.digest_data() && attempt["requestId"]==audit.request
            && attempt["facts"]==facts_value(&audit) && audit.slots.iter().all(|slot|slot.side==PartialFreshSide::Preserved),
            "fresh-conservation-current-content")?;
        let initial=attempt["slots"].as_array().ok_or("fresh-conservation-slots")?;
        check(initial.len()==audit.slots.len(),"fresh-conservation-slots")?;
        let mut head=attempt_sha;let mut control=attempt_bytes;
        let mut wanted:BTreeSet<String>=[ATTEMPT_NAME,BLANK_NAME,"producer.json","producer.sig","inventory.json"]
            .into_iter().map(str::to_owned).collect();wanted.insert(retry_name);
        for prefix in 0..=audit.slots.len() {
            let name=format!("prefix-{prefix}.json");wanted.insert(name.clone());
            let (receipt,sha,count)=receipt_read(book,child,&name,"mrk-fresh-conservation-prefix-v1",
                &["schemaVersion","kind","invocation","attemptSha256","previousSha256","prefix","preserved","facts","slots","writer"])?;
            check(receipt["invocation"]==invocation && receipt["attemptSha256"]==hex(&attempt_sha)
                && receipt["previousSha256"]==hex(&head) && receipt["prefix"].as_u64()==Some(prefix as u64)
                && receipt["facts"]==attempt["facts"],"fresh-conservation-prefix-chain")?;
            receipt_birth(book,retry,&receipt["preserved"])?;
            let slots=receipt["slots"].as_array().ok_or("fresh-conservation-slots")?;
            check(slots.len()==initial.len(),"fresh-conservation-slots")?;
            for (at,((row,before),actual)) in slots.iter().zip(initial).zip(&audit.slots).enumerate() {
                shape(row,&["name","birth","identity","preserved","bytes","files","directories","controls"])?;
                shape(&row["identity"],&["device","inode","mode","uid","gid","links","bytes","mtime","mtimeNanos","ctime","ctimeNanos"])?;
                let live=worker::identity_data(actual.identity);
                check(["inode","mode","uid","gid","links","bytes","mtime","mtimeNanos"].iter().all(|key|row["identity"][*key]==live[*key]),
                    "fresh-conservation-slot-identity")?;
                check(["name","birth","bytes","files","directories","controls"].iter().all(|k|row[*k]==before[*k])
                    && row["name"]==partial_fresh_name_data(actual.slot,invocation,read.new_selection(book)?)?
                    && row["preserved"].as_bool()==Some(at<prefix)
                    && row["bytes"].as_u64()==Some(actual.counts.bytes) && row["files"].as_u64()==Some(actual.counts.files)
                    && row["directories"].as_u64()==Some(actual.counts.directories)
                    && row["controls"].as_u64()==Some(actual.counts.controls),"fresh-conservation-slot-chain")?;
            }
            head=sha;control=control.checked_add(count).ok_or("fresh-conservation-control-count")?;
        }
        let (blank,blank_sha,count)=receipt_read(book,child,BLANK_NAME,"mrk-fresh-conservation-blank-v1",
            &["schemaVersion","kind","invocation","attemptSha256","prefixSha256","prefix","root","versions","facts","writer"])?;
        check(blank["invocation"]==invocation && blank["attemptSha256"]==hex(&attempt_sha) && blank["prefixSha256"]==hex(&head)
            && blank["prefix"].as_u64()==Some(audit.slots.len() as u64) && blank["facts"]==attempt["facts"],"fresh-conservation-blank-link")?;
        receipt_birth(book,root,&blank["root"])?;
        // The ordinary versions may now contain the independently installed
        // successful generation, but must still be the recorded actual object.
        let blank_versions=birth_data(&blank["versions"])?;
        locate_blank_versions(book,root,parent,container,blank_versions)?;exact_roster(book,child,&wanted)?;
        let reference=data(transaction::FreshConservationReferenceData::new_data(invocation,&hex(&blank_sha)))?;

        let control=(control+count+read.raw.iter().map(Vec::len).sum::<usize>()) as u64;
        let mut facts=InstallInvocationSetData::empty();facts.insert(InstallInvocationFactData::intent(&audit.intent)?)?;
        read.post(book)?;
        let before_versions=audit.intent.fresh_birth_data().ok_or("fresh-conservation-birth")?.identities_data()[1];
        Ok(AttemptRead{reference,previous,before_versions,blank_versions,bytes:audit.facts.payload_bytes+audit.facts.control_bytes+control,
            files:audit.facts.files+audit.slots.len() as u64+6,directories:audit.facts.directories+2,
            controls:audit.facts.control_bytes+control,facts})
}
pub(in crate::installer) fn namespace(book:&mut Install,root:usize,selected:&ReleaseSetData,
    expected:Option<&transaction::FreshConservationReferenceData>)->Result<Option<Namespace>> {
    namespace_except(book,root,selected,expected,None)
}
pub(in crate::installer) fn namespace_except(book:&mut Install,root:usize,selected:&ReleaseSetData,
    expected:Option<&transaction::FreshConservationReferenceData>,pending:Option<&PendingOriginal>)->Result<Option<Namespace>> {
    namespace_at(book,root,root,selected,expected,pending)
}
fn namespace_at(book:&mut Install,root:usize,parent:usize,selected:&ReleaseSetData,
    expected:Option<&transaction::FreshConservationReferenceData>,pending:Option<&PendingOriginal>)->Result<Option<Namespace>> {
    check(book.fresh_conservation_projection.is_none(),"fresh-transport-projection-once")?;
    match book.named(Some(parent),ROOT_NAME) {
        Err(Errno::ENOENT)=>{check(expected.is_none(),"fresh-conservation-missing")?;return Ok(None);},
        Err(_)=>return Err("fresh-conservation-name"),Ok(_)=>(),
    }
    retained_live(book)?;
    let start=book.originals.len();
    let reserve=RECEIPT_QUOTE.checked_mul(4).and_then(|n|n.checked_add(2*installation_record::INVENTORY_LIMIT))
        .and_then(|n|n.checked_add(PARTIAL_FRESH_WORK+131072)).ok_or("fresh-conservation-memory")?;
    check(removal_effective_control_bytes(book)?.checked_add(reserve as u64)
        .is_some_and(|n|n<=installation_record::CONTROL_LIMIT as u64),"fresh-conservation-memory")?;
    book.removal_control_reserved=book.removal_control_reserved.checked_add(reserve as u64).ok_or("fresh-conservation-memory")?;
    let result=removal_archive_scope(book,|book|{
        let container=book.open(Some(parent),ROOT_NAME,true)?;let identity=removal_archive_stat(book,container,true,0o700)?.0;
        book.fresh_conservation_projection=Some(Projection::new(container));
        let birth=book.fresh_output_identity(container)?;
        let (origin,origin_sha,origin_bytes)=receipt_read(book,container,ORIGIN_NAME,"mrk-fresh-conservation-origin-v1",
            &["schemaVersion","kind","root","namespace","invocation","intentSha256","outputOriginSha256",
                "outputJournalSha256","outputHead","outputEntries","source","writer"])?;
        receipt_birth(book,root,&origin["root"])?;receipt_birth(book,container,&origin["namespace"])?;
        let names=roster_now(book,container)?;
        if let Some(pending)=pending {pending.post(book)?;
            check(pending.root==root && book.identity(container)?.same_object(book.identity(pending.namespace)?),"fresh-conservation-pending-container")?;}
        check((2..=transaction::INVOCATION_LIMIT+1).contains(&names.len()) && names.contains_key(ORIGIN_NAME),"fresh-conservation-attempt-count")?;
        let mut attempts=Vec::with_capacity(transaction::INVOCATION_LIMIT);
        let mut facts=InstallInvocationSetData::empty();
        let (mut bytes,mut files,mut directories,mut controls)=(origin_bytes as u64,1u64,1u64,origin_bytes as u64);
        for name in names.keys().filter(|name|name.as_str()!=ORIGIN_NAME) {
            if pending.is_some_and(|pending|*name==format!("attempt-{}",pending.invocation)){continue;}
            let invocation=name.strip_prefix("attempt-").filter(|v|worker::invocation_valid(v)).ok_or("fresh-conservation-attempt-name")?;
            let row=removal_archive_scope(book,|book|read_attempt(book,root,parent,container,selected,&origin,origin_sha,invocation))?;
            facts.merge(&row.facts)?;
            bytes=bytes.checked_add(row.bytes).filter(|n|*n<=transaction::MAINTENANCE_STORAGE_LIMIT).ok_or("fresh-conservation-storage")?;
            files=files.checked_add(row.files).ok_or("fresh-conservation-files")?;
            directories=directories.checked_add(row.directories).ok_or("fresh-conservation-directories")?;
            controls=controls.checked_add(row.controls).filter(|n|*n<=installation_record::CONTROL_LIMIT as u64).ok_or("fresh-conservation-controls")?;
            attempts.push((row.reference,row.previous,row.before_versions,row.blank_versions));
        }
        if attempts.is_empty(){
            check(expected.is_none() && pending.is_some_and(|pending|origin["invocation"]==pending.invocation)
                && names.len()==2,"fresh-conservation-pending-first")?;return Ok(None);
        }
        check(attempts.iter().filter(|row|row.1.is_none()).count()==1,"fresh-conservation-chain-root")?;
        for (at,row) in attempts.iter().enumerate(){
            if let Some(previous)=&row.1 {
                let parents=attempts.iter().enumerate().filter(|(other,value)|*other!=at && value.0==*previous).collect::<Vec<_>>();
                check(parents.len()==1 && row.2.same_object_data(&parents[0].1.3),"fresh-conservation-chain-parent")?;
            }
            check(attempts.iter().filter(|value|value.1.as_ref()==Some(&row.0)).count()<=1,"fresh-conservation-chain-fork")?;
        }
        let tips=attempts.iter().filter(|row|!attempts.iter().any(|child|child.1.as_ref()==Some(&row.0))).collect::<Vec<_>>();
        check(tips.len()==1,"fresh-conservation-chain-tip")?;let tip=tips[0];
        let mut count=0usize;let mut cursor=Some(tip);
        while let Some(row)=cursor {
            count+=1;check(count<=attempts.len(),"fresh-conservation-chain-cycle")?;
            cursor=row.1.as_ref().and_then(|previous|attempts.iter().find(|old|old.0==*previous));
        }
        check(count==attempts.len() && expected.is_none_or(|value|*value==tip.0),"fresh-conservation-complete-chain")?;
        check(roster_now(book,container)?==names && removal_archive_stat(book,container,true,0o700)?.0==identity,
            "fresh-conservation-namespace-post")?;
        Ok(Some(Namespace{reference:tip.0.clone(),bytes,files,directories,controls,facts,root,parent,identity,birth,origin:origin_sha,projection:[0;32],
            names:names.keys().cloned().collect(),originals:book.originals.len().checked_sub(start)
                .and_then(|n|n.checked_add(TRANSPORT_ORIGINAL_MARGIN)).ok_or("fresh-conservation-original-quote")?}))
    });
    let projection=book.fresh_conservation_projection.take();
    let mut result=result?;
    if let Some(value)=result.as_mut(){
        let projection=projection.ok_or("fresh-transport-projection-required")?;
        check(projection.rows>0,"fresh-transport-projection-empty")?;value.projection=projection.digest.finalize().into();
        if parent==root && book.removal_snapshot_capture.is_some(){
            let row=ConservationSpanData::observed(book,value)?;
            let capture=book.removal_snapshot_capture.as_mut().ok_or("fresh-transport-capture")?;
            check(!capture.failed && capture.conservation.as_ref().is_none_or(|old|*old==row)
                && (!capture.complete || capture.conservation.is_some()),"fresh-transport-capture-changed")?;
            if !capture.complete {capture.memory(row.memory()?)?;capture.conservation=Some(row);capture.memory(0)?;}
        }
    }
    // Retain32KiB for at most65 names, BTree nodes and the fixed invocation
    // array, even for temporary observations; no allocator/drop credit.
    book.removal_control_reserved=book.removal_control_reserved.checked_sub(reserve as u64-32768).ok_or("fresh-conservation-memory")?;
    Ok(result)
}

fn retained_enrollment(book:&mut Install,read:&RetainedInput,audit:&PartialFreshAttemptAudit,origin:&serde_json::Value)->Result<()> {
    read.post(book)?;let retry=audit.retry.ok_or("fresh-conservation-preserved")?;
    let parent=|slot:PartialFreshTop|->Result<usize>{
        let row=audit.slots.iter().find(|row|row.slot==slot).ok_or("fresh-conservation-top-required")?;
        Ok(if row.side==PartialFreshSide::Current{read.root}else{retry})
    };
    let stage=book.open(Some(parent(PartialFreshTop::Stage)?),&format!(".install-{}",audit.invocation),true)?;
    let size=usize::try_from(book.named(Some(stage),fresh_data::JOURNAL_NAME).map_err(|_|"fresh-conservation-journal")?.st_size)
        .map_err(|_|"fresh-conservation-journal")?;
    check(size<=fresh_data::JOURNAL_LIMIT,"fresh-conservation-journal")?;
    let entries=(size/(fresh_data::ENTRY_MIN+4)).min(fresh_data::ENROLLMENT_LIMIT);
    let quote=size.checked_mul(4).and_then(|n|n.checked_add(entries.checked_mul(1152)?))
        .and_then(|n|n.checked_add(131072)).ok_or("fresh-conservation-enrollment-memory")?;
    check(removal_effective_control_bytes(book)?.checked_add(quote as u64)
        .is_some_and(|n|n<=installation_record::CONTROL_LIMIT as u64),"fresh-conservation-enrollment-memory")?;
    book.removal_control_reserved=book.removal_control_reserved.checked_add(quote as u64).ok_or("fresh-conservation-enrollment-memory")?;
    let result=(|| {
        let selected=read.new_selection(book)?;
        let (index,origin_original,journal_original,journal)=book.fresh_output_read(parent(PartialFreshTop::Intent)?,stage,&audit.intent,selected,size)?;
        check(origin["outputOriginSha256"]==index.origin_data().digest_data() && origin["outputJournalSha256"]==hex(&journal)
            && origin["outputHead"]==index.head_data() && origin["outputEntries"].as_u64()==Some(index.len_data() as u64),
            "fresh-conservation-enrollment-chain")?;
        let versions=book.open(Some(parent(PartialFreshTop::Versions)?),"versions",true)?;
        let births=index.origin_data().birth_data().identities_data();
        same_birth(book,read.root,births[0])?;same_birth(book,versions,births[1])?;
        for (name,birth) in [(paths::REGISTRATION_GATE_NAME,births[2]),(paths::MAINTENANCE_GATE_NAME,births[3])] {
            let original=book.open(Some(read.root),name,false)?;same_birth(book,original,birth)?;
            book.forward_close(original,"fresh-conservation-gate-close")?;
        }
        let release=match book.named(Some(versions),selected.current_data().binding_data().release) {
            Ok(_)=>Some(book.open(Some(versions),selected.current_data().binding_data().release,true)?),
            Err(Errno::ENOENT)=>None,Err(_)=>return Err("fresh-conservation-release"),
        };
        let inventory=read.inventory.index()?;
        let mut control_parents=BTreeMap::new();
        for row in &audit.slots {
            if !matches!(row.slot,PartialFreshTop::App|PartialFreshTop::Versions|PartialFreshTop::Stage|PartialFreshTop::Intent) {
                control_parents.insert(partial_fresh_name_data(row.slot,&audit.invocation,selected)?,parent(row.slot)?);
            }
        }
        let mut census=Census{enrollment:&index,inventory:&inventory,seen:BTreeSet::new(),root:read.root,stage,release,
            conserved_root:Some(read.root),control_parents:Some(&control_parents)};
        if let Some(release)=release {let row=census.row("release",OutputRoleData::ReleaseDirectory)?;
            census.mark(book,row,release,versions,None)?;}
        for (path,parent,leaf,phase) in [("app",audit.slots.iter().any(|row|row.slot==PartialFreshTop::App).then(||parent(PartialFreshTop::App)).transpose()?,paths::APP_NAME,3usize),
            ("runtime",release,"runtime",2usize)] {
            let staged=match book.named(Some(stage),path){Ok(_)=>true,Err(Errno::ENOENT)=>false,Err(_)=>return Err("fresh-conservation-payload")};
            let published=if let Some(parent)=parent {match book.named(Some(parent),leaf){Ok(_)=>true,Err(Errno::ENOENT)=>false,Err(_)=>return Err("fresh-conservation-payload")}}else{false};
            check(!(staged&&published),"fresh-conservation-payload-duplicate")?;
            if !staged&&!published {continue;}
            let (parent,leaf,rebound)=if staged{(stage,path,None)}else{
                census.publication(book,&audit.intent,phase)?;let parent=parent.ok_or("fresh-conservation-publication")?;(parent,leaf,Some(parent))};
            census.payload(book,parent,leaf,path,0,rebound,&mut PartialFreshTreeWork::new(8192)?)?;
        }
        for row in index.rows_data(){if matches!(row.role_data(),OutputRoleData::MetadataFile|OutputRoleData::StageReceipt|OutputRoleData::RootControl){census.control(book,row)?;}}
        check(census.seen.len()==index.len_data() && index.rows_data().all(|row|census.seen.contains(row.path_data())),
            "fresh-conservation-enrollment-missing")?;
        drop(census);drop(inventory);drop(index);
        for original in [release,Some(versions),Some(origin_original),Some(journal_original),Some(stage)].into_iter().flatten(){
            book.forward_close(original,"fresh-conservation-enrollment-close")?;
        }
        read.post(book)
    })();
    if result.is_ok(){book.removal_control_reserved=book.removal_control_reserved.checked_sub(quote as u64)
        .ok_or("fresh-conservation-enrollment-memory")?;}
    result
}

// A stage-only launcher may be read without a live Applications owner. The
// caller's full paired audit still checks its closed phase/placement grammar.
// A live Applications copy requires FreshRecovery and never reaches this path.
fn stage_launcher_counts(book:&mut Install,source:&worker::FreshRecoveryInput<'_>,stage:usize)->Result<(u64,u64)> {
    source.post(book)?;
    removal_archive_scope(book,|book|{
        let workspace=match book.named(Some(stage),applications::WORK_NAME) {
            Ok(_)=>Some(book.open(Some(stage),applications::WORK_NAME,true)?),Err(Errno::ENOENT)=>None,
            Err(_)=>return Err("fresh-census-launcher-workspace"),
        };
        let mut copies=Vec::with_capacity(2);
        for parent in [Some(stage),workspace].into_iter().flatten(){
            match book.named(Some(parent),applications::SOURCE_NAME) {
                Ok(_)=>copies.push(parent),Err(Errno::ENOENT)=>(),Err(_)=>return Err("fresh-census-launcher-copy"),
            }
        }
        check(copies.len()<=1,"fresh-census-launcher-duplicate")?;
        let mut counts=(0,u64::from(workspace.is_some()));
        if let Some(parent)=copies.first().copied(){
            let (mut incoming,inventory,_)=source.incoming(book)?;let index=inventory.index()?;
            for name in ["app","Contents","Helpers"]{incoming=book.open(Some(incoming),name,true)?;
                check(partial_fresh_directory(book,incoming)?.mode==0o040555,"fresh-census-launcher-source")?;}
            let tree=partial_fresh_payload_tree(book,Some(incoming),applications::SOURCE_NAME,parent,applications::SOURCE_NAME,
                mobile_release_desktop::macos_applications_launcher::BUNDLE,&index,launcher_inventory_depth_data(),false,
                PartialFreshPayloadRead::Paired,None,&mut PartialFreshTreeWork::new(8192)?)?;
            counts.0=tree.files;counts.1+=tree.directories;
        }
        source.post(book)?;Ok(counts)
    })
}

pub(in crate::installer) fn retain_launcher_metadata(book:&mut Install,original:usize)->Result<()> {
    let snapshot=book.originals[original].existing_app_metadata.ok_or("fresh-launcher-native-snapshot")?;
    let birth=birth_before_attributes(book,original)?;
    retain_metadata(book,original,birth,snapshot)
}
fn retain_metadata(book:&mut Install,original:usize,birth:transaction::FreshBirthIdentityData,
    snapshot:mobile_release_desktop::macos_existing_app_metadata::SnapshotData)->Result<()> {
    if let Some(first)=book.fresh_census_metadata.iter().find(|row|row.birth.same_object_data(&birth)) {
        check(first.alias(book,original)?.is_some() && first.snapshot==snapshot,"fresh-conservation-first-snapshot")?;
    }else{
        let cap=2*transaction::INVOCATION_LIMIT;
        check(book.fresh_census_metadata.len()<cap,"fresh-conservation-metadata-count")?;
        if book.fresh_census_metadata.capacity()==0 {
            let cost=cap.checked_mul(std::mem::size_of::<AppMetadata>()).ok_or("fresh-conservation-metadata-memory")?;
            check(removal_effective_control_bytes(book)?.checked_add(cost as u64)
                .is_some_and(|n|n<=installation_record::CONTROL_LIMIT as u64),"fresh-conservation-metadata-memory")?;
            book.removal_control_reserved=book.removal_control_reserved.checked_add(cost as u64).ok_or("fresh-conservation-metadata-memory")?;
            book.fresh_census_metadata.try_reserve_exact(cap).map_err(|_|"fresh-conservation-metadata-memory")?;
            check(book.fresh_census_metadata.capacity()<=cap,"fresh-conservation-metadata-memory")?;
        }
        book.fresh_census_metadata.push(AppMetadata{birth,snapshot});
    }
    book.check_name(original,true)
}

fn locate_blank_versions(book:&mut Install,root:usize,parent:usize,container:usize,birth:transaction::FreshBirthIdentityData)->Result<()> {
    let mut count=0usize;
    let mut inspect=|book:&mut Install,parent:usize|->Result<()> {
        match book.named(Some(parent),"versions") {
            Err(Errno::ENOENT)=>Ok(()),Err(_)=>Err("fresh-conservation-versions-name"),Ok(_)=>{
                let n=book.open(Some(parent),"versions",true)?;removal_archive_stat(book,n,true,0o755)?;
                count+=usize::from(book.fresh_output_identity(n)?.same_object_data(&birth));
                book.forward_close(n,"fresh-conservation-versions-close")
            }
        }
    };
    inspect(book,root)?;if parent!=root{inspect(book,parent)?;}
    let names=roster_now(book,container)?;
    check(names.len()<=transaction::INVOCATION_LIMIT+1,"fresh-conservation-attempt-count")?;
    for name in names.keys().filter(|name|name.as_str()!=ORIGIN_NAME) {
        let invocation=name.strip_prefix("attempt-").filter(|v|worker::invocation_valid(v)).ok_or("fresh-conservation-attempt-name")?;
        removal_archive_scope(book,|book|{
            let child=book.open(Some(container),name,true)?;removal_archive_stat(book,child,true,0o700)?;
            let retry_name=partial_fresh_retry_name_data(invocation)?;
            match book.named(Some(child),&retry_name){Err(Errno::ENOENT)=>Ok(()),Err(_)=>Err("fresh-conservation-preserved-name"),Ok(_)=>{
                let retry=book.open(Some(child),&retry_name,true)?;removal_archive_stat(book,retry,true,0o700)?;inspect(book,retry)
            }}
        })?;
    }
    check(count==1,"fresh-conservation-versions-original")
}

impl Namespace {
    // Read-only collector body. Only a later admitted owner may export this
    // after its genuine wait/EOF/close envelope; DATA grants no native custody.
    pub(in crate::installer) fn audit_data(&self,book:&mut Install,selected:&ReleaseSetData)->Result<Vec<u8>> {
        let end=book.originals.len().checked_add(self.originals.checked_mul(2).ok_or("fresh-audit-original-bound")?)
            .filter(|n|*n<=installation_record::ORIGINAL_LIMIT).ok_or("fresh-audit-original-bound")?;
        reserve_removal_original_storage(book,end)?;
        self.reobserve(book,selected)?;
        let reserve=(RECEIPT_LIMIT*8) as u64;
        check(removal_effective_control_bytes(book)?.checked_add(reserve).is_some_and(|n|n<=installation_record::CONTROL_LIMIT as u64),
            "fresh-audit-control-bound")?;
        book.removal_control_reserved=book.removal_control_reserved.checked_add(reserve).ok_or("fresh-audit-control-bound")?;
        let attempts=self.facts.rows[..self.facts.len].iter().flatten().map(|row|serde_json::json!({
            "invocation":hex(&row.invocation),"requestId":hex(&row.request),"intentSha256":hex(&row.intent)})).collect::<Vec<_>>();
        let value=bytes(&serde_json::json!({"schemaVersion":1,"kind":"mrk-fresh-conservation-observed-v1",
            "selectionSha256":hash(&selected.encode_data().map_err(|_|"fresh-audit-selection")?),"reference":self.reference,
            "originSha256":hex(&self.origin),"root":birth_value(book,self.root)?,"namespace":self.birth.fields_data(),
            "bytes":self.bytes,"files":self.files,"directories":self.directories,"controlBytes":self.controls,"attempts":attempts}))?;
        self.reobserve(book,selected)?;
        book.removal_control_reserved=book.removal_control_reserved.checked_sub(reserve).ok_or("fresh-audit-control-bound")?;Ok(value)
    }
    pub(in crate::installer) fn inode(&self)->u64{self.identity.ino}
    pub(in crate::installer) fn future_originals(&self)->usize{self.originals}
    pub(in crate::installer) fn reobserve(&self,book:&mut Install,selected:&ReleaseSetData)->Result<()> {
        let observed=namespace_at(book,self.root,self.parent,selected,Some(&self.reference),None)?.ok_or("fresh-conservation-missing")?;
        check(self.matches(&observed),"fresh-conservation-whole-post")
    }
    pub(in crate::installer) fn post(&self,book:&Install)->Result<()> {
        book.check_name(self.root,false)?;book.protected(self.root,true,Some(0o755))?;
        let named=book.named(Some(self.parent),ROOT_NAME).map_err(|_|"fresh-conservation-namespace-name")?;
        let (dev,ino,sec,nsec,uuid)=self.birth.fields_data();
        check(self.identity.same_object(Identity::of(&named)) && i64::from(named.st_dev)==dev && named.st_ino==ino
            && named.st_birthtime==sec && named.st_birthtime_nsec==nsec && named.st_flags==0 && named.st_mode==0o040700
            && book.fresh_output_identity(self.root)?.fields_data().4==uuid,"fresh-conservation-namespace-original")
    }
    fn matches(&self,other:&Self)->bool {
        self.reference==other.reference && self.bytes==other.bytes && self.files==other.files && self.directories==other.directories
            && self.controls==other.controls && self.root==other.root && self.identity==other.identity && self.birth==other.birth
            && self.origin==other.origin && self.names==other.names && self.parent==other.parent && self.projection==other.projection
    }
}

pub(in crate::installer) enum Entry { Ordinary, Current(String), Retained }
pub(in crate::installer) fn nominate(book:&mut Install,root:usize,selected:&ReleaseSetData)->Result<Entry> {
    check(book.gate.parent==Some(root) && book.gate.verified && book.gate.exclusive_acquired
        && !book.worker_stderr_is_gate,"fresh-conservation-entry-exclusion")?;
    let rows=removal_root_roster(book,root)?;
    let intents=rows.iter().filter_map(|(name,_)|completed_entry_intent_leaf_data(name).transpose()).collect::<Result<Vec<_>>>()?;
    if intents.len()!=1 {
        return Ok(if !rows.iter().any(|row|row.0==transaction::STATE_NAME)
            && rows.iter().any(|row|row.0==ROOT_NAME){Entry::Retained}else{Entry::Ordinary});
    }
    let invocation=intents[0];
    if rows.iter().any(|row|row.0==ROOT_NAME) {
        let exists=removal_archive_scope(book,|book|{
            let namespace=book.open(Some(root),ROOT_NAME,true)?;removal_archive_stat(book,namespace,true,0o700)?;
            match book.named(Some(namespace),&format!("attempt-{invocation}")) {
                Ok(_)=>Ok(true),Err(Errno::ENOENT)=>Ok(false),Err(_)=>Err("fresh-conservation-attempt-name")
            }
        })?;
        if exists{return Ok(Entry::Retained);}
    }
    let raw=metadata_bytes(book,root,&data(transaction::intent_name_data(invocation))?,transaction::INTENT_LIMIT)?;
    let parsed=match IntentData::parse_fresh_birth_data(&raw,selected) {Ok(value)=>value,Err(_)=>return Ok(Entry::Ordinary)};
    let pair=control_names(selected,parsed.next_data().binding_data().release)?;
    let complete=completed_entry_sealed_all_data([
        completed_entry_sealed_stat(book,root,transaction::STATE_NAME,transaction::STATE_LIMIT)?,
        completed_entry_sealed_stat(book,root,&data(transaction::capsule_name_data(invocation))?,transaction::CAPSULE_LIMIT)?,
        completed_entry_sealed_stat(book,root,&pair.0,mobile_release_desktop::macos_install_producer::DESCRIPTOR_LIMIT)?,
        completed_entry_sealed_stat(book,root,&pair.1,mobile_release_desktop::macos_install_producer::SIGNATURE_LIMIT)?]);
    Ok(if complete{Entry::Ordinary}else{Entry::Current(invocation.to_owned())})
}
impl EnrolledAttemptObserved<'_> {
    pub(in crate::installer) fn fresh_ids(&self,invocation:&str,request:&str)->Result<()> {
        let mut facts=InstallInvocationSetData::empty();
        if let Some(prior)=self.source.prior_namespace(){facts.merge(&prior.facts)?;}
        facts.insert(InstallInvocationFactData::intent(&self.audit.intent)?)?;
        let id=archive_hex_data(invocation)?;let req=archive_hex_data(request)?;
        check(id!=req && id!=[0;16] && req!=[0;16] && facts.len<transaction::INVOCATION_LIMIT
            && facts.rows[..facts.len].iter().flatten().all(|row|row.disjoint(id,Some(req))),"fresh-conservation-new-ids")
    }
}
impl FreshBlankReady {
    pub(in crate::installer) fn reobserve(book:&mut Install,input:&worker::ReinstallInputRead<'_>)->Result<Self> {
        input.post_source(book)?;
        check(input.prefix_read_role(book)?==worker::PrefixReadRole::ParentSignature && !book.worker_stderr_is_gate,
            "fresh-conservation-blank-parent")?;
        let root=input.root_original();
        let namespace=namespace(book,root,input.new_selection(book)?,None)?.ok_or("fresh-conservation-namespace")?;
        let wanted=[ROOT_NAME,"versions",paths::REGISTRATION_GATE_NAME,paths::MAINTENANCE_GATE_NAME].into_iter().map(str::to_owned).collect();
        exact_roster(book,root,&wanted)?;
        let versions=book.open(Some(root),"versions",true)?;removal_archive_stat(book,versions,true,0o755)?;
        check(roster_now(book,versions)?.is_empty(),"fresh-conservation-current-blank")?;
        let versions_birth=book.fresh_output_identity(versions)?;input.post_source(book)?;
        // Current observed emptiness under new R/M; no earlier returned mkdir,
        // write, fsync or close is claimed by this separate constructor.
        Ok(Self{root,versions,versions_birth,reference:namespace.reference})
    }
}

// Read-only native custody of the sole unfinished attempt. Opening it does not
// permit any move; resume() still owes the full chain and both-sided census.
pub(in crate::installer) struct PendingOriginal {
    root:usize,namespace:usize,child:usize,retry:usize,invocation:String,intent_parent:usize,
    namespace_birth:transaction::FreshBirthIdentityData,child_birth:transaction::FreshBirthIdentityData,
    retry_birth:transaction::FreshBirthIdentityData,
}
impl PendingOriginal {
    pub(in crate::installer) fn invocation(&self)->&str{&self.invocation}
    pub(in crate::installer) fn intent_parent(&self)->usize{self.intent_parent}
    pub(in crate::installer) fn child(&self)->usize{self.child}
    pub(in crate::installer) fn retry(&self)->usize{self.retry}
    pub(in crate::installer) fn inode(&self,book:&Install)->Result<u64>{Ok(book.identity(self.namespace)?.ino)}
    pub(in crate::installer) fn post(&self,book:&Install)->Result<()> {
        check(book.gate.parent==Some(self.root) && book.gate.verified && book.gate.exclusive_acquired
            && !book.worker_stderr_is_gate,"fresh-conservation-pending-exclusion")?;
        for (n,birth) in [(self.namespace,self.namespace_birth),(self.child,self.child_birth),(self.retry,self.retry_birth)] {
            removal_archive_stat(book,n,true,0o700)?;check(book.fresh_output_identity(n)?==birth,"fresh-conservation-pending-original")?;
        }
        check(book.originals[self.namespace].parent==Some(self.root) && book.originals[self.namespace].name==ROOT_NAME
            && book.originals[self.child].parent==Some(self.namespace) && book.originals[self.child].name==format!("attempt-{}",self.invocation)
            && book.originals[self.retry].parent==Some(self.child) && book.originals[self.retry].name==partial_fresh_retry_name_data(&self.invocation)?,
            "fresh-conservation-pending-parent")
    }
}
pub(in crate::installer) fn pending(book:&mut Install,root:usize)->Result<Option<PendingOriginal>> {
    check(book.gate.parent==Some(root) && book.gate.verified && book.gate.exclusive_acquired,"fresh-conservation-pending-exclusion")?;
    let namespace=book.open(Some(root),ROOT_NAME,true)?;removal_archive_stat(book,namespace,true,0o700)?;
    let names=roster_now(book,namespace)?;check(names.len()<=transaction::INVOCATION_LIMIT+1,"fresh-conservation-attempt-count")?;
    let mut selected=None;
    for name in names.keys().filter(|name|name.as_str()!=ORIGIN_NAME) {
        let invocation=name.strip_prefix("attempt-").filter(|v|worker::invocation_valid(v)).ok_or("fresh-conservation-attempt-name")?;
        let child=book.open(Some(namespace),name,true)?;removal_archive_stat(book,child,true,0o700)?;
        match book.named(Some(child),BLANK_NAME) {
            Ok(_)=>book.forward_close(child,"fresh-conservation-pending-probe-close")?,
            Err(Errno::ENOENT)=>{
                check(selected.is_none(),"fresh-conservation-pending-ambiguous")?;
                let retry=book.open(Some(child),&partial_fresh_retry_name_data(invocation)?,true)?;
                removal_archive_stat(book,retry,true,0o700)?;
                let name=data(transaction::intent_name_data(invocation))?;
                let current=match book.named(Some(root),&name){Ok(_)=>true,Err(Errno::ENOENT)=>false,Err(_)=>return Err("fresh-conservation-pending-intent")};
                let preserved=match book.named(Some(retry),&name){Ok(_)=>true,Err(Errno::ENOENT)=>false,Err(_)=>return Err("fresh-conservation-pending-intent")};
                check(current!=preserved,"fresh-conservation-pending-intent-placement")?;
                selected=Some(PendingOriginal{root,namespace,child,retry,invocation:invocation.to_owned(),intent_parent:if current{root}else{retry},
                    namespace_birth:book.fresh_output_identity(namespace)?,child_birth:book.fresh_output_identity(child)?,retry_birth:book.fresh_output_identity(retry)?});
            },
            Err(_)=>return Err("fresh-conservation-pending-blank"),
        }
    }
    if let Some(value)=&selected{value.post(book)?;}else{book.forward_close(namespace,"fresh-conservation-pending-container-close")?;}
    Ok(selected)
}

impl ConservationAttemptOriginal {
    pub(in crate::installer) fn resume(book:&mut Install,source:&worker::FreshRecoveryInput<'_>,new_id:&str,new_request:&str)->Result<Self> {
        source.post(book)?;let pending=source.pending_original().ok_or("fresh-conservation-pending-required")?;
        let reserve=(RECEIPT_QUOTE*4+2*installation_record::INVENTORY_LIMIT+PARTIAL_FRESH_WORK) as u64;
        check(removal_effective_control_bytes(book)?.checked_add(reserve).is_some_and(|n|n<=installation_record::CONTROL_LIMIT as u64),"fresh-conservation-resume-memory")?;
        book.removal_control_reserved=book.removal_control_reserved.checked_add(reserve).ok_or("fresh-conservation-resume-memory")?;
        let (origin,origin_sha,_)=receipt_read(book,pending.namespace,ORIGIN_NAME,"mrk-fresh-conservation-origin-v1",
            &["schemaVersion","kind","root","namespace","invocation","intentSha256","outputOriginSha256","outputJournalSha256","outputHead","outputEntries","source","writer"])?;
        receipt_birth(book,pending.root,&origin["root"])?;receipt_birth(book,pending.namespace,&origin["namespace"])?;
        let (attempt,attempt_sha,_)=receipt_read(book,pending.child,ATTEMPT_NAME,"mrk-fresh-conservation-attempt-v1",
            &["schemaVersion","kind","originSha256","attempt","invocation","requestId","intentSha256","source","output","previous","facts","slots","writer"])?;
        check(attempt["invocation"]==source.invocation() && attempt["originSha256"]==hex(&origin_sha),"fresh-conservation-resume-attempt")?;
        receipt_birth(book,pending.child,&attempt["attempt"])?;
        let (producer,signature)=source.incoming_controls(book)?;let (_,_,inventory_bytes)=source.incoming(book)?;
        let source_hashes=[hash(producer),hash(signature),hash(inventory_bytes)];
        check(attempt["source"]==serde_json::to_value(&source_hashes).map_err(|_|"fresh-conservation-source")?,"fresh-conservation-resume-source")?;
        let (value,head,receipts)=removal_archive_scope(book,|book|{
            let mut originals=[0usize;3];let mut raw:[Vec<u8>;3]=std::array::from_fn(|_|Vec::new());
            for (at,name,body) in [(0,"producer.json",producer),(1,"producer.sig",signature),(2,"inventory.json",inventory_bytes)] {
                let observed=if at==2 {metadata_inventory_original(book,pending.child,name,body.len())?}
                    else {metadata_original(book,pending.child,name,body.len())?};
                check(observed.1==body,"fresh-conservation-resume-source-copy")?;originals[at]=observed.0;raw[at]=observed.1;
            }
            let descriptor=mobile_release_desktop::macos_install_producer::ProducerData::parse_data(&raw[0],source.new_selection(book)?.target_data())
                .map_err(|_|"fresh-conservation-resume-producer")?;
            let inventory=Inventory::parse_for_selected_release(&raw[2],descriptor.release_set_data().current_data())?;
            let read=RetainedInput{root:pending.root,child:pending.child,originals,raw,descriptor,inventory};read.post(book)?;
            let intent_raw=metadata_bytes(book,pending.intent_parent,&data(transaction::intent_name_data(source.invocation()))?,transaction::INTENT_LIMIT)?;
            let intent=data(IntentData::parse_fresh_birth_data(&intent_raw,source.new_selection(book)?))?;
            check(attempt["intentSha256"]==intent.digest_data() && attempt["requestId"]==intent.request_id_data()
                && attempt["previous"]==serde_json::to_value(intent.fresh_conservation_data()).map_err(|_|"fresh-conservation-reference")?,"fresh-conservation-resume-intent")?;
            if intent.fresh_conservation_data().is_none(){
                check(origin["invocation"]==source.invocation() && origin["source"]==attempt["source"]
                    && origin["intentSha256"]==attempt["intentSha256"] && ["outputOriginSha256","outputJournalSha256","outputHead","outputEntries"]
                        .iter().all(|key|origin[*key]==attempt["output"][*key]),"fresh-conservation-resume-origin")?;
            }
            let rows=attempt["slots"].as_array().filter(|v|(1..=8).contains(&v.len())).ok_or("fresh-conservation-resume-slots")?;
            for row in rows {
                shape(row,&["name","birth","identity","preserved","bytes","files","directories","controls"])?;
                let name=row["name"].as_str().filter(|v|component(v)||*v==paths::APP_NAME).ok_or("fresh-conservation-resume-slot")?;
                let current=match book.named(Some(pending.root),name){Ok(_)=>true,Err(Errno::ENOENT)=>false,Err(_)=>return Err("fresh-conservation-resume-slot")};
                let preserved=match book.named(Some(pending.retry),name){Ok(_)=>true,Err(Errno::ENOENT)=>false,Err(_)=>return Err("fresh-conservation-resume-slot")};
                check(current!=preserved,"fresh-conservation-resume-placement")?;
                let parent=if current{pending.root}else{pending.retry};
                slot_births(book,parent,&serde_json::Value::Array(vec![row.clone()]))?;
            }
            let stage_name=format!(".install-{}",source.invocation());
            let stage_parent=if book.named(Some(pending.root),&stage_name).is_ok(){pending.root}else{pending.retry};
            let stage=book.open(Some(stage_parent),&stage_name,true)?;
            applications::retained_fresh_metadata(book,stage,&intent)?;
            book.forward_close(stage,"fresh-conservation-resume-stage-close")?;
            let audit=partial_fresh_attempt(book,PartialFreshSource::Fresh(source),source.invocation(),Some(pending.retry))?;
            let prefix=partial_fresh_prefix_data(&audit.slots.iter().map(|row|row.side).collect::<Vec<_>>())?;
            check(rows.len()==audit.slots.len() && audit.slots.last().is_some_and(|v|v.slot==PartialFreshTop::Versions)
                && attempt["facts"]==facts_value(&audit),"fresh-conservation-resume-content")?;
            retained_enrollment(book,&read,&audit,&attempt["output"])?;
            let mut head=attempt_sha;let mut wanted:BTreeSet<String>=[ATTEMPT_NAME,"producer.json","producer.sig","inventory.json"]
                .into_iter().map(str::to_owned).collect();wanted.insert(partial_fresh_retry_name_data(source.invocation())?);
            for at in 0..=prefix {
                let name=format!("prefix-{at}.json");wanted.insert(name.clone());
                let (receipt,digest,_)=receipt_read(book,pending.child,&name,"mrk-fresh-conservation-prefix-v1",
                    &["schemaVersion","kind","invocation","attemptSha256","previousSha256","prefix","preserved","facts","slots","writer"])?;
                check(receipt["invocation"]==source.invocation() && receipt["attemptSha256"]==hex(&attempt_sha)
                    && receipt["previousSha256"]==hex(&head) && receipt["prefix"].as_u64()==Some(at as u64)
                    && receipt["facts"]==attempt["facts"],"fresh-conservation-resume-chain")?;
                receipt_birth(book,pending.retry,&receipt["preserved"])?;
                let states=receipt["slots"].as_array().filter(|v|v.len()==rows.len()).ok_or("fresh-conservation-resume-slots")?;
                for (index,((state,before),actual)) in states.iter().zip(rows).zip(&audit.slots).enumerate(){
                    shape(state,&["name","birth","identity","preserved","bytes","files","directories","controls"])?;
                    check(["name","birth","bytes","files","directories","controls"].iter().all(|key|state[*key]==before[*key])
                        && state["name"]==partial_fresh_name_data(actual.slot,source.invocation(),source.new_selection(book)?)?
                        && state["preserved"].as_bool()==Some(index<at),"fresh-conservation-resume-slot-chain")?;
                    if at==prefix {
                        let actual=worker::identity_data(actual.identity);
                        shape(&state["identity"],&["device","inode","mode","uid","gid","links","bytes","mtime","mtimeNanos","ctime","ctimeNanos"])?;
                        check(["inode","mode","uid","gid","links","bytes","mtime","mtimeNanos","ctime","ctimeNanos"].iter()
                            .all(|key|state["identity"][*key]==actual[*key]),"fresh-conservation-resume-unrecorded-move")?;
                    }
                }
                head=digest;
            }
            // Includes exact prefix range and refuses a torn/missing next
            // receipt, unrecorded preserved directory, or blank creation.
            exact_roster(book,pending.child,&wanted)?;
            let mut facts=InstallInvocationSetData::empty();if let Some(prior)=source.prior_namespace(){facts.merge(&prior.facts)?;}
            facts.insert(InstallInvocationFactData::intent(&audit.intent)?)?;
            let id=archive_hex_data(new_id)?;let request=archive_hex_data(new_request)?;
            check(id!=request && id!=[0;16] && request!=[0;16] && facts.len<transaction::INVOCATION_LIMIT
                && facts.rows[..facts.len].iter().flatten().all(|row|row.disjoint(id,Some(request))),"fresh-conservation-new-ids")?;
            Ok((audit,head,prefix+1))
        })?;
        let prefix=receipts-1;
        let ledger=PartialFreshPreservation{invocation:value.invocation,request:value.request,intent:value.intent,
            initial:value.facts,root:pending.root,child:pending.child,retry:Some(pending.retry),collision:None,retry_quote:value.retry_quote,
            slots:value.slots,prefix,pending:None,unknown:false,first:None,returned_settled:false};
        let owner=Self{container:ConservationRootOriginal{root:pending.root,namespace:pending.namespace,birth:pending.namespace_birth},
            child:pending.child,child_birth:pending.child_birth,ledger,attempt:attempt_sha,head,receipts,source:source_hashes,
            first:None,blank:None,blank_receipt:None};
        source.post(book)?;owner.post(book,source)?;
        book.removal_control_reserved=book.removal_control_reserved.checked_sub(reserve-RECEIPT_QUOTE as u64)
            .ok_or("fresh-conservation-resume-memory")?;Ok(owner)
    }
}

// Explicit compact snapshot projection. The complete namespace reader owns
// this scope; descendant controls/rosters feed this typed commitment rather
// than the ordinary shallow control grammar. No missing descendant is ignored.
pub(in crate::installer) struct Projection {namespace:usize,digest:Sha256,rows:u64}
impl Projection {
    fn new(namespace:usize)->Self {let mut digest=Sha256::new();digest.update(b"MRK-FRESH-SNAPSHOT-V1\0");Self{namespace,digest,rows:0}}
    fn path(&self,book:&Install,mut n:usize)->Result<Option<String>> {
        let mut names=Vec::new();
        for _ in 0..24 {
            if n==self.namespace || book.identity(n)?.same_object(book.identity(self.namespace)?) {
                names.reverse();return Ok(Some(names.join("/")));}
            let row=book.originals.get(n).ok_or("fresh-transport-capture-original")?;
            names.push(row.name.as_str());let Some(parent)=row.parent else{return Ok(None);};n=parent;
        }Err("fresh-transport-capture-depth")
    }
    fn add(&mut self,path:&str,id:Identity,tag:u8,body:&[u8])->Result<()> {
        check(path.len()<=2048 && self.rows<installation_record::ORIGINAL_LIMIT as u64,"fresh-transport-capture-count")?;
        self.digest.update([tag]);self.digest.update((path.len() as u16).to_be_bytes());self.digest.update(path.as_bytes());
        rehome_hash_identity(&mut self.digest,Identity{dev:0,ctime:0,ctime_ns:0,..id},0);
        self.digest.update((body.len() as u64).to_be_bytes());self.digest.update(body);self.rows+=1;Ok(())
    }
}
pub(super) fn capture_metadata(book:&mut Install,n:usize,raw:&[u8])->Result<bool> {
    let Some(projection)=book.fresh_conservation_projection.as_ref()else{return Ok(false);};
    let Some(path)=projection.path(book,n)?else{return Ok(false);};
    let (id,flags)=snapshot_stat(book,n)?;check(flags==0,"fresh-transport-capture-flags")?;
    book.fresh_conservation_projection.as_mut().ok_or("fresh-transport-capture")?.add(&path,id,1,&Sha256::digest(raw))?;Ok(true)
}
pub(super) fn capture_roster(book:&mut Install,n:usize,rows:&BTreeMap<String,u64>)->Result<bool> {
    let Some(projection)=book.fresh_conservation_projection.as_ref()else{return Ok(false);};
    let Some(path)=projection.path(book,n)?else{return Ok(false);};
    let (id,flags)=snapshot_stat(book,n)?;check(flags==0,"fresh-transport-capture-flags")?;
    let mut digest=Sha256::new();digest.update((rows.len() as u64).to_be_bytes());
    for (name,ino) in rows{digest.update((name.len() as u16).to_be_bytes());digest.update(name.as_bytes());digest.update(ino.to_be_bytes());}
    book.fresh_conservation_projection.as_mut().ok_or("fresh-transport-capture")?.add(&path,id,2,&digest.finalize())?;Ok(true)
}
#[derive(Clone,PartialEq,Eq)]
pub(super) struct ConservationSpanData {
    root:transaction::FreshBirthIdentityData,namespace:transaction::FreshBirthIdentityData,top:Identity,
    invocation:[u8;16],receipt:[u8;32],origin:[u8;32],projection:[u8;32],
    bytes:u64,files:u64,directories:u64,controls:u64,originals:usize,facts:Vec<InstallInvocationFactData>,
}
impl ConservationSpanData {
    fn observed(book:&Install,value:&Namespace)->Result<Self> {
        let mut facts=Vec::new();facts.try_reserve_exact(value.facts.len).map_err(|_|"fresh-transport-allocation")?;
        check(facts.capacity()<=value.facts.len,"fresh-transport-memory")?;
        facts.extend(value.facts.rows[..value.facts.len].iter().flatten().copied());
        let row=Self{root:book.fresh_output_identity(value.root)?,namespace:value.birth,top:value.identity,
            invocation:archive_hex_data(value.reference.invocation_data())?,receipt:archive_hex_data(value.reference.receipt_sha256_data())?,
            origin:value.origin,projection:value.projection,bytes:value.bytes,files:value.files,directories:value.directories,
            controls:value.controls,originals:value.originals,facts};row.validate()?;Ok(row)
    }
    fn validate(&self)->Result<()> {
        let root=self.root.fields_data();let ns=self.namespace.fields_data();
        check(root.4==ns.4 && root.0==ns.0 && i64::from(self.top.dev)==ns.0
            && root.1!=ns.1 && self.top.ino==ns.1 && archive_directory_data(self.top,0,true)
            && self.invocation!=[0;16] && self.receipt!=[0;32] && self.origin!=[0;32] && self.projection!=[0;32]
            && self.controls>0 && self.controls<=self.bytes && self.bytes<=transaction::MAINTENANCE_STORAGE_LIMIT
            && self.files>0 && self.files<=installation_record::FILE_LIMIT as u64 && self.directories>0
            && self.directories<=installation_record::FILE_LIMIT as u64 && self.originals>=2
            && self.originals<=installation_record::ORIGINAL_LIMIT && (1..=transaction::INVOCATION_LIMIT).contains(&self.facts.len()),
            "fresh-transport-shape")?;
        let mut ids=InstallInvocationSetData::empty();
        for row in &self.facts {check(ids.insert(InstallInvocationFactData::new(row.invocation,row.request,row.intent)?)?,"fresh-transport-ids")?;}
        check(self.facts.windows(2).all(|w|w[0].invocation<w[1].invocation)
            && self.facts.iter().any(|row|row.invocation==self.invocation),"fresh-transport-order")
    }
    fn reference(&self)->Result<transaction::FreshConservationReferenceData>{
        data(transaction::FreshConservationReferenceData::new_data(&hex(&self.invocation),&hex(&self.receipt)))
    }
    pub(super) fn memory(&self)->Result<usize>{
        check(self.facts.capacity()<=transaction::INVOCATION_LIMIT,"fresh-transport-memory")?;
        Ok(std::mem::size_of::<Self>()+self.facts.capacity()*std::mem::size_of::<InstallInvocationFactData>())
    }
    pub(super) fn originals(&self)->usize{self.originals}
    pub(super) fn storage(&self)->u64{self.bytes}
    pub(super) fn merge(&self,ids:&mut InstallInvocationSetData)->Result<()>{for row in &self.facts {ids.insert(*row)?;}Ok(())}
    pub(super) fn bind(&self,state:&StateData)->Result<()> {check(state.fresh_conservation_data()==Some(&self.reference()?),"fresh-transport-state-reference")}
    pub(super) fn encode(&self,out:&mut SnapshotBytes)->Result<()> {
        self.validate()?;
        for id in [self.root,self.namespace] {out.string(&serde_json::to_string(&id.fields_data()).map_err(|_|"fresh-transport-birth")?)?;}
        out.identity(self.top,0)?;out.put(&self.invocation)?;
        for value in [self.receipt,self.origin,self.projection]{out.put(&value)?;}
        for n in [self.bytes,self.files,self.directories,self.controls,self.originals as u64]{out.put(&n.to_be_bytes())?;}
        out.u16(self.facts.len())?;for row in &self.facts {out.put(&row.invocation)?;out.put(&row.request)?;out.put(&row.intent)?;}Ok(())
    }
    pub(super) fn parse<F:FnMut(u64,&mut[u8])->Result<usize>>(cursor:&mut ArchiveCursor<F>)->ArchiveParse<Self> {
        fn identity<F:FnMut(u64,&mut[u8])->Result<usize>>(cursor:&mut ArchiveCursor<F>)->ArchiveParse<transaction::FreshBirthIdentityData>{
            let raw=cursor.string(256,false,false)?;let value=serde_json::from_str(&raw).map_err(|_|"fresh-transport-birth")?;
            let id=birth_data(&value)?;archive_require(serde_json::to_string(&id.fields_data()).map_err(|_|"fresh-transport-birth")?==raw,"fresh-transport-birth")?;Ok(id)
        }
        let root=identity(cursor)?;let namespace=identity(cursor)?;let(top,_)=cursor.identity(&[0o040700])?;
        let invocation=cursor.array()?;let receipt=cursor.array()?;let origin=cursor.array()?;let projection=cursor.array()?;
        let bytes=cursor.u64()?;let files=cursor.u64()?;let directories=cursor.u64()?;let controls=cursor.u64()?;
        let originals=usize::try_from(cursor.u64()?).map_err(|_|"fresh-transport-originals")?;
        let count=cursor.u16()?;archive_require((1..=transaction::INVOCATION_LIMIT).contains(&count),"fresh-transport-count")?;
        let mut facts=Vec::new();facts.try_reserve_exact(count).map_err(|_|"fresh-transport-allocation")?;
        archive_require(facts.capacity()<=count,"fresh-transport-memory")?;
        for _ in 0..count{facts.push(InstallInvocationFactData::new(cursor.array()?,cursor.array()?,cursor.array()?)?);}
        let value=Self{root,namespace,top,invocation,receipt,origin,projection,bytes,files,directories,controls,originals,facts};value.validate()?;Ok(value)
    }
}

pub(super) fn audit_transport(book:&mut Install,parent:usize,row:&ConservationSpanData,snapshot:&SnapshotRead<'_>)->Result<Identity>{
    snapshot.post(book)?;row.validate()?;retained_live(book)?;
    let start=book.originals.len();
    reserve_removal_original_storage(book,start.checked_add(row.originals()).filter(|n|*n<=installation_record::ORIGINAL_LIMIT)
        .ok_or("fresh-transport-original-budget")?)?;
    let root=book.gate.parent.ok_or("fresh-transport-root")?;
    check(book.fresh_output_identity(root)?.same_object_data(&row.root),"fresh-transport-root")?;
    if parent!=root {
        check(book.originals[parent].name==REHOME_CHILD,"fresh-transport-parent")?;
        let actual=book.originals[parent].parent.ok_or("fresh-transport-parent")?;
        let expected=book.originals[snapshot.snapshot].parent.ok_or("fresh-transport-archive")?;
        book.check_name(actual,false)?;book.check_name(expected,false)?;
        check(book.identity(actual)?.same_object(book.identity(expected)?)
            && book.fresh_output_identity(actual)?.same_object_data(&book.fresh_output_identity(expected)?),
            "fresh-transport-archive-original")?;
    }
    let selected=ReleaseSetData::parse_for_target_data(snapshot.genesis.selected_bytes_data(),snapshot.genesis.header.target)
        .map_err(|_|"fresh-transport-selection")?;
    let value=namespace_at(book,root,parent,&selected,Some(&row.reference()?),None)?.ok_or("fresh-transport-missing")?;
    let expected=Identity{dev:value.identity.dev,..row.top};
    check(value.birth.same_object_data(&row.namespace) && value.identity==if parent==root{expected}else{
        Identity{ctime:value.identity.ctime,ctime_ns:value.identity.ctime_ns,..expected}},"fresh-transport-top")?;
    let actual=value.identity;let mut projected=ConservationSpanData::observed(book,&value)?;
    projected.root=row.root;projected.namespace=row.namespace;projected.top=row.top;projected.originals=row.originals;
    check(projected==*row && value.originals.checked_sub(TRANSPORT_ORIGINAL_MARGIN).is_some_and(|n|n<=row.originals),"fresh-transport-content")?;
    check(book.originals.len().checked_sub(start).is_some_and(|n|n<=row.originals()),"fresh-transport-original-budget")?;
    snapshot.post(book)?;Ok(actual)
}

// Retained-only readers: six namespace/source anchors, five enrollment
// anchors, at most eighteen payload directories plus one leaf/roster, and
// ten fixed phase/launcher/control margins. Paired source/launcher admission
// keeps its separate72 quote; this40 never admits that different path.
fn retained_live(book:&Install)->Result<()> {
    let external=book.removal_live_reserved.checked_add(if book.worker_deadline.is_some(){worker::EXTRA_LIVE}else{0})
        .ok_or("fresh-transport-live-budget")?;
    check(book.originals.iter().filter(|r|r.fd.is_some()).count().checked_add(external)
        .and_then(|n|n.checked_add(40)).is_some_and(|n|n<=96),"fresh-transport-live-budget")
}

pub(super) fn preflight_transport_work(book:&mut Install,row:&ConservationSpanData,snapshot:&SnapshotRead<'_>)->Result<()> {
    row.validate()?;snapshot.post(book)?;retained_live(book)?;
    let root=book.gate.parent.ok_or("fresh-transport-root")?;
    let bound=book.originals.len().checked_add(row.originals()).and_then(|n|n.checked_add(2))
        .filter(|n|*n<=installation_record::ORIGINAL_LIMIT).ok_or("fresh-transport-original-budget")?;
    reserve_removal_original_storage(book,bound)?;
    removal_archive_scope(book,|book|{
        // The only candidates are the actual original root and the actual
        // rehome child belonging to this same held snapshot's archive.
        let matches=|book:&Install,parent:usize|->Result<bool>{match book.named(Some(parent),ROOT_NAME){
            Err(Errno::ENOENT)=>Ok(false),Err(_)=>Err("fresh-transport-name"),Ok(st)=>{
                let (_,ino,sec,nsec,_)=row.namespace.fields_data();
                Ok(st.st_ino==ino && st.st_birthtime==sec && st.st_birthtime_nsec==nsec)
            }
        }};
        let archive=book.originals[snapshot.snapshot].parent.ok_or("fresh-transport-archive")?;
        let child=match book.named(Some(archive),REHOME_CHILD){
            Err(Errno::ENOENT)=>None,Err(_)=>return Err("fresh-transport-child"),Ok(_)=>{
                let n=book.open(Some(archive),REHOME_CHILD,true)?;removal_archive_stat(book,n,true,0o700)?;Some(n)
            }
        };
        let current=matches(book,root)?;let moved=child.map(|n|matches(book,n)).transpose()?.unwrap_or(false);
        check(current!=moved,"fresh-transport-placement")?;
        audit_transport(book,if current{root}else{child.ok_or("fresh-transport-child")?},row,snapshot)?;
        check(book.originals.len()<=bound,"fresh-transport-original-budget")?;snapshot.post(book)
    })
}

#[cfg(test)]
mod original_quote_tests {
    use super::*;
    #[test]
    fn live_quote_covers_retained_conservation_owners_and_deepest_paired_read() {
        // Initial census permits up to24 held originals. Retaining namespace,
        // attempt, retry and blank versions must not make that same source
        // impossible before the next bounded audit.
        for retained in 0..=4 {
            assert!(preservation_live_quote_data(24+retained).is_ok());
        }
        // The existing contextual Store-path regression covers the real
        // deepest accepted path. The quote uses that same depth constant.
        assert_eq!(PAYLOAD_DIRECTORY_DEPTH_LIMIT,16);
        // Exact process-wide boundary, one above, and arithmetic overflow.
        assert_eq!(preservation_live_quote_data(32).unwrap(),96);
        assert!(preservation_live_quote_data(33).is_err());
        assert!(preservation_live_quote_data(usize::MAX).is_err());
    }
    #[test]
    fn interrupted_output_and_incoming_install_have_separate_quotes() {
        // Exact retained failing package shape and real copying frontier.
        let incoming=partial_fresh_retry_original_quote_data(7230,1279).unwrap()
            +PARTIAL_FRESH_LAUNCHER_ORIGINALS;
        assert_eq!(incoming,19864);
        assert!(incoming*24+256>installation_record::ORIGINAL_LIMIT);
        let expected=5*incoming+(2*5+4*4+192+96)*(3*3+8)+320;
        assert_eq!(preservation_original_quote_data(0,5,4,3,incoming).unwrap(),expected);
        assert!(preservation_original_quote_data(0,6,4,3,incoming).unwrap()>expected);
        assert!(preservation_original_quote_data(0,5,5,3,incoming).unwrap()>expected);
        for slots in 1..=8 {
            let cost=preservation_original_quote_data(0,5,4,slots,incoming).unwrap();
            assert_eq!(preservation_original_quote_data(installation_record::ORIGINAL_LIMIT-cost,5,4,slots,incoming).unwrap(),installation_record::ORIGINAL_LIMIT);
            assert!(preservation_original_quote_data(installation_record::ORIGINAL_LIMIT-cost+1,5,4,slots,incoming).is_err());
        }
        // Keep refusal for large output, overflow, and invalid slot shape.
        for (used,files,dirs,slots,source) in [
            (0,7230,1279,8,incoming),(usize::MAX,5,4,3,incoming),
            (0,u64::MAX,4,3,incoming),(0,5,u64::MAX,3,incoming),
            (0,5,4,0,incoming),(0,5,4,9,incoming),(0,5,4,3,usize::MAX),
        ] {assert!(preservation_original_quote_data(used,files,dirs,slots,source).is_err());}
        let future=preservation_original_quote_data(4000,5,4,3,incoming).unwrap();
        // Check old/new vector overlap and255-byte future names using the
        // actual production Original layout and128MiB containing budget.
        let storage=removal_original_storage_quote_data(4000,incoming*3,4000*255,future).unwrap();
        assert!(storage+20*1024*1024<=installation_record::CONTROL_LIMIT as u64);
        println!("FRESH_PRESERVATION_QUOTE incoming={} files=5 dirs=4 slots=3 future={} originalBytes={} storageBytes={}",incoming,future,std::mem::size_of::<Original>(),storage);
    }
}

// Private actual-observation projection, absent from every shipping graph.
#[cfg(feature="macos-installed-fresh-census-control")]
include!("macos_fresh_census_projection.rs");
