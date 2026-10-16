// Nonshipping, fixed three-phase missing-app fixture. No ordinary writer dispatch.
use super::*;

const EXECUTABLE: &str = "mrk-macos-app-absence-fixture";
const RECORD_LIMIT: usize = 64 * 1024;
const OUTPUT_MARKER:&[u8]=b"MRK_MACOS_APP_ABSENCE_RESULT=";
const FIXTURE_PACKAGE_LIMIT: u64 = 640 * 1024 * 1024;
const FIXTURE_IMAGE_LIMIT: u64 = 2560 * 1024 * 1024;
const PHASE_NAMES: [&str; 3] = ["MRK-AppAbsence-Baseline.pkg", "MRK-AppAbsence-Withdraw.pkg", "MRK-AppAbsence-Verify.pkg"];
const CARRIER_NAMES: [&str; 6] = ["Install.pkg", "producer.json", "producer.sig",
    "MRK-AppAbsence-Baseline.pkg", "MRK-AppAbsence-Withdraw.pkg", "MRK-AppAbsence-Verify.pkg"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PhaseData { Baseline, Withdraw, Verify }
impl PhaseData {
    fn from_name(name: &str) -> Result<Self> {
        match name {
            "MRK-AppAbsence-Baseline.pkg" => Ok(Self::Baseline),
            "MRK-AppAbsence-Withdraw.pkg" => Ok(Self::Withdraw),
            "MRK-AppAbsence-Verify.pkg" => Ok(Self::Verify),
            _ => Err("app-absence-fixed-phase"),
        }
    }
}
struct TransportData<'a> { phase: PhaseData, parent: &'a str, product: String }
fn path_component_data(value: &str) -> bool {
    !value.is_empty() && value.len() <= 255 && value.is_ascii()
        && value != "." && value != ".." && !value.starts_with(' ') && !value.ends_with(' ')
        && !value.contains("  ") && value.bytes().all(|b| b.is_ascii_alphanumeric() || b" ._-".contains(&b))
}
fn transport_data(path: &str) -> Result<TransportData<'_>> {
    check(path.starts_with('/') && path.len() <= 4096 && path[1..].split('/').count() <= 32,
        "app-absence-transport-path")?;
    check(path[1..].split('/').all(path_component_data), "app-absence-transport-path")?;
    let (parent, name) = path.rsplit_once('/').ok_or("app-absence-transport-path")?;
    check(!parent.is_empty(), "app-absence-transport-parent")?;
    let phase = PhaseData::from_name(name)?;
    Ok(TransportData { phase, parent, product: format!("{parent}/Install.pkg") })
}
fn carrier_names_data<'a>(names: impl IntoIterator<Item=&'a str>) -> bool {
    let mut seen = BTreeSet::new();
    for name in names {
        if seen.len() >= CARRIER_NAMES.len() || !CARRIER_NAMES.contains(&name) || !seen.insert(name) { return false; }
    }
    seen.len() == CARRIER_NAMES.len()
}
fn nonzero_hex_data(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn decimal_data(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.starts_with('0') && value.bytes().all(|b| b.is_ascii_digit())
}
struct BindingData<'a> { source: &'a str, run: &'a str, attempt: &'a str, target: &'a str }
impl<'a> BindingData<'a> {
    fn new(source: &'a str, product_source: &str, run: &'a str, attempt: &'a str, target: &'a str) -> Result<Self> {
        check(nonzero_hex_data(source,40) && source == product_source && decimal_data(run,20)
            && decimal_data(attempt,10) && matches!(target,"aarch64-apple-darwin"|"x86_64-apple-darwin"),
            "app-absence-source-run-binding")?;
        Ok(Self { source, run, attempt, target })
    }
    fn baseline_name(&self) -> String {
        let target = if self.target == "aarch64-apple-darwin" { "arm64" } else { "intel" };
        format!("MobileReleaseKit-AppAbsence-{}-{}-{}-{target}-baseline.json", &self.source[..12], self.run, self.attempt)
    }
    fn private_name(&self, nonce: &str) -> Result<String> {
        check(nonzero_hex_data(nonce,32),"app-absence-root-nonce")?;
        Ok(format!("MobileReleaseKit-AppAbsenceFixture-{}-{nonce}",&self.source[..12]))
    }
}
fn compiled_binding_data() -> Result<BindingData<'static>> {
    BindingData::new(option_env!("MRK_APP_ABSENCE_FIXTURE_SOURCE_COMMIT").ok_or("app-absence-compile-binding")?,
        option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT").ok_or("app-absence-compile-binding")?,
        option_env!("MRK_APP_ABSENCE_FIXTURE_RUN_ID").ok_or("app-absence-compile-binding")?,
        option_env!("MRK_APP_ABSENCE_FIXTURE_RUN_ATTEMPT").ok_or("app-absence-compile-binding")?,target())
}
// DATA predicate only: only the later actual joined initial Installer and
// protected baseline/current-history readers may supply these observations.
fn fresh_install_matches_data(action: ActionData, actual_created_root: bool, original_joined: bool,
    original_status: Option<i32>, instance: &str, expected_instance: &str) -> bool {
    action == ActionData::FreshInstall && actual_created_root && original_joined && original_status == Some(0)
        && nonzero_hex_data(instance,32) && instance == expected_instance
}
fn same_gate_data(before: Identity, acquired: Identity, before_flags: u32, acquired_flags: u32) -> bool {
    before == acquired && before_flags == 0 && acquired_flags == 0
}
// Quote only these future transport outputs; NOT total live stage/image/input
// accounting. The shared owner must admit their complete coexistence separately.
fn transport_output_bytes_data(product: u64, fixture: u64, image: u64) -> Option<u64> {
    if product < 28 || product > installation_record::PAYLOAD_LIMIT || fixture < 28
        || fixture > FIXTURE_PACKAGE_LIMIT || image == 0 || image > FIXTURE_IMAGE_LIMIT { return None; }
    product.checked_add(fixture.checked_mul(3)?)?.checked_add(image)?
        .checked_add(16 * 1024 + 512)
}
fn outer_phase_credit_data(verified_before_export: bool, record_readback: bool,
    original_joined: bool, actual_exit: Option<i32>, all_originals_closed: bool,
    deadline_met: bool, unknown: bool) -> bool {
    verified_before_export && record_readback && original_joined && actual_exit == Some(0)
        && all_originals_closed && deadline_met && !unknown
}

impl Install {
    // Same native Source invariants as ordinary worker_source; only the fixed
    // executable name differs. Never rename this binary to impersonate Install.
    fn app_absence_source(&mut self, source: &str, input: usize) -> Result<Source> {
        self.clock()?;
        let script = self.originals.get(input).and_then(|r| r.parent).ok_or("worker-script-parent")?;
        check(self.originals[input].name == "input", "worker-script-input")?;
        self.protected(script, true, Some(0o755))?;
        native::no_xattrs(self.fd(script)?.as_fd()).map_err(|_| "worker-script-attributes")?;
        let directory = source.strip_suffix("/input").filter(|s| !s.is_empty()).ok_or("worker-script-input")?;
        let executable = format!("{directory}/{EXECUTABLE}");
        let actual = std::env::current_exe().map_err(|_| "worker-self-image")?;
        check(actual.as_os_str() == std::ffi::OsStr::new(&executable), "worker-self-image")?;
        let image = self.open(Some(script), EXECUTABLE, false)?;
        self.protected(image, false, Some(0o555))?;
        native::no_xattrs(self.fd(image)?.as_fd()).map_err(|_| "worker-self-attributes")?;
        let size = u64::try_from(self.identity(image)?.size).map_err(|_| "worker-self-bound")?;
        check(size > 0 && size <= SELF_LIMIT, "worker-self-bound")?;
        let image_sha = self.read(image, size, false)?.0;
        Ok(Source { script,image,input,image_sha,executable,directory:directory.into(),source:source.into() })
    }
    // Unlike ordinary maintenance_gate(), this fixture-only acquisition has
    // NO create-on-ENOENT branch. A gate removed between preadmission and open
    // refuses without even attempting a GateWriter or repairing a name.
    fn app_absence_existing_maintenance_gate(&mut self, gates: &ExistingGates) -> Result<()> {
        self.clock()?;gates.post(self)?;
        let registration=self.registration.participant.ok_or("app-absence-registration-missing")?;
        check(self.registration.entered && self.registration.parent==Some(gates.root)
            && self.registration.creation=="existing-not-modified" && self.registration.writer.is_none()
            && self.registration.verified && self.registration.lock_attempted && self.registration.exclusive_acquired
            && !self.registration.closed_under_maintenance
            && self.originals[registration].state==State::Owned,"app-absence-original-r-before-m")?;
        self.registration_protected(registration)?;
        gates.match_acquired(self,gates.registration,registration)?;
        check(!self.gate.entered && !self.worker_stderr_is_gate,"gate-already-entered")?;
        self.gate.entered=true;self.gate.parent=Some(gates.root);
        let reader=self.open_role(Some(gates.root),paths::MAINTENANCE_GATE_NAME,false,Role::GateParticipant)?;
        // Full original identity (not just name/inode) BEFORE acquiring M.
        gates.match_acquired(self,gates.maintenance,reader)?;
        self.gate.creation="existing-not-modified";
        self.gate_protected(reader)?;
        let (_,body)=self.read(reader,paths::MAINTENANCE_GATE_BYTES.len() as u64,true)?;
        check(body==paths::MAINTENANCE_GATE_BYTES,"gate-content")?;
        self.gate.verified=true;self.clock()?;
        self.gate.lock_attempted=true;
        #[allow(deprecated)] // Same original borrowed descriptor as production.
        let locked=fcntl::flock(self.fd(reader)?.as_raw_fd(),fcntl::FlockArg::LockExclusiveNonblock);
        locked.map_err(|_|"gate-busy-or-refused")?;
        self.gate.exclusive_acquired=true;
        self.clock()?;self.gate_protected(reader)?;
        gates.match_acquired(self,gates.maintenance,reader)?;gates.post(self)
    }
}

// Native preparation does not inspect signature verifiers. Store this object
// in the actual owner BEFORE inspect() can enter any native cell. Even a failed
// inspect remains owned here for settle() inside the SAME original deadline.
struct Admission {
    phase: PhaseData, source: Source, inventory: Option<Inventory>, inventory_bytes: Option<Vec<u8>>,
    producer: ProducerAdmission, selected: Option<ReleaseSetData>, carrier: usize,
}
impl Admission {
    fn prepare(book: &mut Install, input_path: &str, fixture_package: &str) -> Result<Self> {
        book.clock()?;
        check(book.worker_deadline.is_some() && !book.worker_stderr_is_gate
            && !book.gate.entered && !book.registration.entered,"app-absence-original-parent")?;
        let binding=compiled_binding_data()?;
        check(binding.target==target(),"app-absence-native-target")?;
        let transport=transport_data(fixture_package)?;
        let (input,inventory,inventory_bytes)=book.input(input_path)?;
        let source=book.app_absence_source(input_path,input)?;
        let producer=ProducerAdmission::new(book,&source,&transport.product)?;
        let carrier=producer.input.app_absence_readonly_parent(book)?;
        check(carrier_names_data(maintenance::roster_now(book,carrier)?.keys().map(String::as_str)),"app-absence-carrier-roster")?;
        // Input::open authenticated the actual readonly parent and original P
        // names. Parsed same-parent spelling alone is never its authority.
        check(producer.input.private_path_data(book)?==transport.product,"app-absence-product-parent")?;
        Ok(Self { phase:transport.phase,source,inventory:Some(inventory),inventory_bytes:Some(inventory_bytes),
            producer,selected:None,carrier })
    }
    fn inspect(&mut self, book: &mut Install) -> Result<()> {
        check(self.selected.is_none(),"app-absence-admission-once")?;
        let selected=self.producer.inspect(book,&self.source)?;
        maintenance::selected_compile(&selected)?;
        self.selected=Some(selected);
        self.post(book,true)
    }
    fn post(&self, book: &mut Install, content: bool) -> Result<()> {
        check(self.selected.is_some(),"app-absence-native-admission-required")?;
        self.producer.authenticated_post(book,&self.source,content)?;
        check(self.producer.input.app_absence_readonly_parent(book)?==self.carrier
            && carrier_names_data(maintenance::roster_now(book,self.carrier)?.keys().map(String::as_str)),"app-absence-carrier-post")?;
        book.clock()
    }
    fn settle(&mut self, book: &Install) -> bool { self.producer.settle(book) }
}

// Both existing originals are pinned BEFORE any helper acquisition. Retained
// readers stay in the same Install book; they neither lock nor repair a gate.
struct ExistingGates { root: usize, registration: usize, maintenance: usize }
impl ExistingGates {
    fn preadmit(book: &mut Install, root: usize) -> Result<Self> {
        book.clock()?;
        check(!book.registration.entered && !book.gate.entered,"app-absence-gates-once")?;
        book.protected(root,true,Some(0o755))?;book.check_name(root,true)?;
        let mut admit=|name:&str,bytes:&[u8]| -> Result<usize> {
            let original=book.open(Some(root),name,false)?;
            book.protected(original,false,Some(0o444))?;
            native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_|"app-absence-gate-attributes")?;
            let info=stat::fstat(book.fd(original)?).map_err(|_|"app-absence-gate-stat")?;
            check(info.st_flags==0 && info.st_size==bytes.len() as i64,"app-absence-gate-shape")?;
            let (_,body)=book.read(original,bytes.len() as u64,true)?;
            check(body==bytes,"app-absence-gate-content")?;
            book.check_name(original,true)?;Ok(original)
        };
        let registration=admit(paths::REGISTRATION_GATE_NAME,paths::REGISTRATION_GATE_BYTES)?;
        let maintenance=admit(paths::MAINTENANCE_GATE_NAME,paths::MAINTENANCE_GATE_BYTES)?;
        let value=Self { root,registration,maintenance };value.post(book)?;Ok(value)
    }
    fn post(&self, book: &Install) -> Result<()> {
        book.protected(self.root,true,Some(0o755))?;book.check_name(self.root,false)?;
        for original in [self.registration,self.maintenance] {
            book.check_name(original,true)?;book.protected(original,false,Some(0o444))?;
            let actual=stat::fstat(book.fd(original)?).map_err(|_|"app-absence-gate-stat")?;
            check(actual.st_flags==0,"app-absence-gate-flags")?;
            native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_|"app-absence-gate-attributes")?;
        }
        book.clock()
    }
    fn match_acquired(&self, book: &Install, original: usize, acquired: usize) -> Result<()> {
        book.check_name(original,true)?;book.check_name(acquired,true)?;
        let a=stat::fstat(book.fd(original)?).map_err(|_|"app-absence-gate-stat")?;
        let b=stat::fstat(book.fd(acquired)?).map_err(|_|"app-absence-gate-stat")?;
        check(same_gate_data(book.identity(original)?,book.identity(acquired)?,a.st_flags,b.st_flags),
            "app-absence-same-gate-original")
    }
    // The fixture owner retains this admission and closes every non-M
    // original while the original M still excludes ordinary maintenance.
    fn acquire_registration(&self, book: &mut Install) -> Result<()> {
        self.post(book)?;book.registration_before_maintenance(self.root)?;
        let acquired=book.registration.participant.ok_or("app-absence-registration-missing")?;
        check(book.registration.creation=="existing-not-modified" && book.registration.exclusive_acquired
            && book.registration.writer.is_none(),"app-absence-registration-no-repair")?;
        self.match_acquired(book,self.registration,acquired)?;self.post(book)
    }
}

const BINDING_FIELDS:[&str;12]=["fixtureSource","productSource","runId","runAttempt","target",
    "packageSha256","producerDescriptorSha256","producerSignatureSha256","fixtureExecutableSha256",
    "inventorySha256","runtimeManifestSha256","protocolSha256"];
const BASELINE_FIELDS:[&str;10]=["schemaVersion","kind","binding","rootNonce","parentIdentity",
    "privateIdentity","siblingCensusSha256","siblingCount","rootAbsent","transportState"];
const PRIVATE_FIELDS:[&str;9]=["schemaVersion","kind","binding","baselineSha256","snapshot",
    "withdrawnAppIdentity","renameReturned","proof","transportState"];
fn digest_data(bytes:&[u8])->String {format!("{:x}",Sha256::digest(bytes))}
fn json_bytes_data(value:&Value,limit:usize)->Result<Vec<u8>> {
    let bytes=serde_json::to_vec(value).map_err(|_|"app-absence-record-json")?;
    check(!bytes.is_empty() && bytes.len()<limit,"app-absence-record-bound")?;Ok(bytes)
}
fn stable_identity_data(id:Identity)->Value {
    json!({"device":id.dev,"inode":id.ino,"mode":id.mode,"uid":id.uid,"gid":id.gid})
}
fn stable_identity_shape(value:&Value)->Result<()> {
    object(value,&["device","inode","mode","uid","gid"])?;
    check(value["device"].as_i64().is_some() && value["inode"].as_u64().is_some_and(|v|v>0)
        && value["mode"].as_u64().is_some_and(|v|v<=u32::MAX as u64)
        && value["uid"]==0 && value["gid"].as_u64().is_some_and(|v|v<=u32::MAX as u64),
        "app-absence-identity-shape")
}
fn binding_value(admission:&Admission)->Result<Value> {
    let b=compiled_binding_data()?;
    let value=json!({"fixtureSource":b.source,"productSource":b.source,"runId":b.run,"runAttempt":b.attempt,
        "target":b.target,"packageSha256":admission.producer.input.package_sha256_data(),
        "producerDescriptorSha256":digest_data(admission.producer.input.descriptor_data()),
        "producerSignatureSha256":digest_data(admission.producer.input.signature_data()),
        "fixtureExecutableSha256":admission.source.image_sha,
        "inventorySha256":option_env!("MRK_MACOS_INSTALL_INVENTORY_SHA256"),
        "runtimeManifestSha256":option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"),"protocolSha256":paths::PROTOCOL_SHA});
    for key in &BINDING_FIELDS[5..] {check(value[*key].as_str().is_some_and(sha),"app-absence-binding-hash")?;}
    Ok(value)
}
fn phase_name(phase:PhaseData)->&'static str {match phase {PhaseData::Baseline=>"baseline",PhaseData::Withdraw=>"withdraw",PhaseData::Verify=>"verify"}}
fn proof_data(phase:PhaseData)->Value {match phase {
    PhaseData::Baseline=>json!({"rootAbsent":true,"privateDirectoryCreated":true,"parentCensusMatched":true,"recordReadback":true}),
    PhaseData::Withdraw=>json!({"initialFreshInstallRecorded":true,"createdRootMatchedPriorAbsence":true,"sameInstance":true,
        "reservationClosedUnderMaintenance":true,"renameKnownSuccess":true,"appAbsent":true,"runtimeUnchanged":true,
        "historyUnchanged":true,"withdrawnAppVerified":true,"recordReadback":true}),
    PhaseData::Verify=>json!({"restoreFixedAppRecorded":true,"initialHistoryPreserved":true,"sameInstance":true,
        "runtimeUnchanged":true,"newAppOriginal":true,"currentAppVerified":true,"withdrawnAppVerified":true,
        "reservationClosedUnderMaintenance":true,"recordReadback":true,"retainedPrivateEvidence":true}),
}}
fn observation_data(binding:&Value,phase:PhaseData,baseline:&str,record:&str)->Result<Value> {
    object(binding,&BINDING_FIELDS)?;check(sha(baseline)&&sha(record),"app-absence-record-hash")?;
    let mut value=binding.clone();let out=value.as_object_mut().ok_or("app-absence-binding-shape")?;
    out.insert("schemaVersion".into(),json!(1));out.insert("kind".into(),json!("app-absence-phase-observation"));
    out.insert("phase".into(),json!(phase_name(phase)));out.insert("baselineSha256".into(),json!(baseline));
    out.insert("recordSha256".into(),json!(record));out.insert("proof".into(),proof_data(phase));
    out.insert("originalOuterExitRequired".into(),json!(true));out.insert("systemServiceExitClaimed".into(),json!(false));
    out.insert("productReady".into(),json!(false));json_bytes_data(&value,4096)?;Ok(value)
}
struct HeldRecord {original:usize,bytes:Vec<u8>,value:Value,digest:String}
impl HeldRecord {
    fn read(book:&mut Install,parent:usize,name:&str)->Result<Self> {
        let original=book.open(Some(parent),name,false)?;
        book.protected(original,false,Some(0o444))?;
        native::no_xattrs(book.fd(original)?.as_fd()).map_err(|_|"app-absence-record-attributes")?;
        check(stat::fstat(book.fd(original)?).map_err(|_|"app-absence-record-stat")?.st_flags==0,"app-absence-record-flags")?;
        let size=usize::try_from(book.identity(original)?.size).map_err(|_|"app-absence-record-bound")?;
        check(size>0 && size<=RECORD_LIMIT,"app-absence-record-bound")?;
        let (digest,bytes)=book.read(original,size as u64,true)?;
        let value=packet(&bytes,RECORD_LIMIT)?;
        let held=Self{original,bytes,value,digest};held.post(book)?;Ok(held)
    }
    fn write(book:&mut Install,parent:usize,name:&str,value:Value)->Result<Self> {
        let bytes=json_bytes_data(&value,RECORD_LIMIT)?;
        book.absent(parent,name)?;
        let original=book.record_file(parent,name,&bytes,Role::ReceiptWriter)?;
        book.persist(parent,false)?;
        let held=Self{original,digest:digest_data(&bytes),bytes,value};held.post(book)?;Ok(held)
    }
    fn write_baseline(book:&mut Install,parent:usize,name:&str,value:Value)->Result<Self> {
        let bytes=json_bytes_data(&value,RECORD_LIMIT)?;
        book.absent(parent,name)?;
        let writer=book.create_public_receipt_file(parent,name)?;
        // Rejoin the unchanged strict wheel-owned record writer/readback path.
        let original=book.record_reserved_file(writer,&bytes)?;
        book.persist(parent,false)?;
        let held=Self{original,digest:digest_data(&bytes),bytes,value};held.post(book)?;Ok(held)
    }
    fn post(&self,book:&Install)->Result<()> {maintenance::held_bytes(book,self.original,&self.bytes)}
}
// Immediate names only; no sibling contents or symlink traversal. Every scan
// uses a fresh book-tracked OFD and compares its full PRE/POST metadata. The
// cross-phase parent identity excludes timestamps changed by our own children.
fn sibling_census(book:&mut Install,support:usize,exclude:&[&str])->Result<(String,usize)> {
    book.check_name(support,false)?;
    let parent=book.originals[support].parent;let name=book.originals[support].name.clone();
    let reader=book.open(parent,&name,true)?;
    check(book.identity(support)?.same_object(book.identity(reader)?),"app-absence-census-parent")?;
    let mut rows=BTreeMap::<String,Value>::new();let mut block=[0u8;65536];let mut total=0usize;let mut seen=BTreeSet::new();
    loop {
        book.clock()?;let used=native::directory_block(book.fd(reader)?.as_fd(),&mut block).map_err(|_|"app-absence-census-read")?;
        if used==0 {break;}check(used<=block.len(),"app-absence-census-bound")?;let mut offset=0;
        while offset<used {
            check(used-offset>=11,"app-absence-census-entry")?;
            let inode=u64::from_ne_bytes(block[offset..offset+8].try_into().map_err(|_|"app-absence-census-entry")?);
            let length=usize::from(u16::from_ne_bytes([block[offset+9],block[offset+10]]));
            let next=offset.checked_add(11+length).filter(|n|*n<=used).ok_or("app-absence-census-entry")?;
            let raw=&block[offset+11..next];offset=next;
            if raw==b"." || raw==b".." {continue;}
            check(!raw.is_empty() && raw.len()<=255 && !raw.contains(&0) && !raw.contains(&b'/') && inode!=0
                && seen.len()<512 && seen.insert(raw.to_vec()),"app-absence-census-bound")?;
            let c=std::ffi::CString::new(raw).map_err(|_|"app-absence-census-name")?;
            let info=stat::fstatat(book.fd(reader)?,c.as_c_str(),AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_|"app-absence-census-stat")?;
            check(info.st_ino==inode,"app-absence-census-original")?;
            if exclude.iter().any(|v|v.as_bytes()==raw) {continue;}
            let key=raw.iter().map(|b|format!("{b:02x}")).collect::<String>();
            let value=json!({"identity":identity_data(Identity::of(&info)),"flags":info.st_flags});
            total=total.checked_add(key.len()+json_bytes_data(&value,1024)?.len()).filter(|n|*n<=256*1024)
                .ok_or("app-absence-census-bound")?;
            rows.insert(key,value);
        }
    }
    book.check_name(reader,true)?;book.forward_close(reader,"app-absence-census-close")?;
    book.check_name(support,false)?;
    Ok((digest_data(&json_bytes_data(&json!(rows),256*1024)?),rows.len()))
}
fn support_post(book:&Install,support:usize)->Result<()> {
    let mut current=Some(support);let mut count=0;
    while let Some(n)=current {
        check(count<3,"app-absence-support-chain")?;
        let role=match count {0=>AclRole::SystemSupport,1=>AclRole::SystemLibrary,_=>AclRole::SystemRoot};
        book.check_name(n,false)?;book.protected_as(n,true,None,role)?;
        let actual=stat::fstat(book.fd(n)?).map_err(|_|"app-absence-support-stat")?;
        check(stable_identity_data(Identity::of(&actual))==stable_identity_data(book.identity(n)?),"app-absence-support-original")?;
        current=book.originals[n].parent;count+=1;
    }
    check(count==3,"app-absence-support-chain")
}
fn protected_private(book:&Install,private:usize)->Result<()> {
    book.protected(private,true,Some(0o700))?;book.check_name(private,false)?;
    let st=stat::fstat(book.fd(private)?).map_err(|_|"app-absence-private-stat")?;
    check(st.st_flags==0,"app-absence-private-flags")?;
    native::no_xattrs(book.fd(private)?.as_fd()).map_err(|_|"app-absence-private-attributes")
}
fn private_roster(book:&mut Install,private:usize,expected:&[&str])->Result<()> {
    protected_private(book,private)?;
    let names=maintenance::roster_now(book,private)?;
    check(names.keys().map(String::as_str).collect::<BTreeSet<_>>()==expected.iter().copied().collect(),"app-absence-private-roster")
}
fn protected_storage(book:&Install,root:usize,app_bytes:u64)->Result<()> {
    check(app_bytes>0 && app_bytes<=installation_record::PAYLOAD_LIMIT,"app-absence-app-bound")?;
    book.clock()?;let fs=statfs::fstatfs(book.fd(root)?).map_err(|_|"app-absence-storage")?;
    let free=fs.blocks_available().checked_mul(u64::from(fs.block_size())).ok_or("app-absence-storage")?;
    // Existing app remains live after rename; another complete app plus fixed
    // records and the approved free floor/reserve must fit this actual volume.
    let needed=app_bytes.checked_add(3*RECORD_LIMIT as u64).and_then(|n|n.checked_add(5*1024*1024*1024))
        .ok_or("app-absence-storage")?;
    check(free>=needed,"app-absence-storage")?;book.clock()
}
// The existing three-phase fixture qualifies ordinary Restore only. A
// recovered final State must not silently inherit that proof; its nonempty
// conserved namespace needs the separate interrupted-worker/transport gate.
fn ordinary_restore_namespace_data(value:&Value)->Result<()> {
    check(value["restoreRecovery"].is_null(),"app-absence-ordinary-restore-required")?;
    let namespace=&value["restoreNamespace"];
    object(namespace,&["commitment","groups","names","files","controlBytes","payloadBytes"])?;
    check(namespace["commitment"].as_str().is_some_and(sha)
        && ["groups","names","files","controlBytes","payloadBytes"].iter()
            .all(|key|namespace[*key].as_u64()==Some(0)),"app-absence-ordinary-restore-required")
}
fn initial_snapshot_data(value:&Value)->Result<()> {
    ordinary_restore_namespace_data(value)?;
    object(value,&["root","versions","release","runtime","app","instance","invocation","requestId","action",
        "stateSha256","intentSha256","capsuleSha256","previous","history","restoreRecovery","restoreNamespace"])?;
    for key in ["stateSha256","intentSha256","capsuleSha256"] {check(value[key].as_str().is_some_and(sha),"app-absence-snapshot-hash")?;}
    for key in ["invocation","requestId"] {check(value[key].as_str().is_some_and(invocation_valid),"app-absence-snapshot-invocation")?;}
    let history=value["history"].as_array().ok_or("app-absence-snapshot-history")?;
    check(value["action"]=="fresh-install" && value["previous"].is_null() && history.len()==1
        && value["instance"].as_str().is_some_and(|s|nonzero_hex_data(s,32))
        && history[0]["invocation"]==value["invocation"] && history[0]["stateSha256"]==value["stateSha256"],
        "app-absence-initial-snapshot")
}
fn restore_snapshot_data(before:&Value,after:&Value)->Result<()> {
    initial_snapshot_data(before)?;
    ordinary_restore_namespace_data(after)?;
    object(after,&["root","versions","release","runtime","app","instance","invocation","requestId","action",
        "stateSha256","intentSha256","capsuleSha256","previous","history","restoreRecovery","restoreNamespace"])?;
    for key in ["stateSha256","intentSha256","capsuleSha256"] {check(after[key].as_str().is_some_and(sha),"app-absence-snapshot-hash")?;}
    for key in ["invocation","requestId"] {check(after[key].as_str().is_some_and(invocation_valid),"app-absence-snapshot-invocation")?;}
    check(after["action"]=="restore-fixed-app" && after["invocation"]!=before["invocation"]
        && after["requestId"]!=before["requestId"]
        && after["previous"]==json!([before["invocation"],before["stateSha256"]]),"app-absence-restore-predecessor")?;
    for key in ["root","versions","release","runtime","instance"] {check(before[key]==after[key],"app-absence-runtime-history-changed")?;}
    let a=before["history"].as_array().ok_or("app-absence-snapshot-history")?;
    let b=after["history"].as_array().ok_or("app-absence-snapshot-history")?;
    check(b.len()==2 && b.iter().filter(|row|*row==&a[0]).count()==1
        && before["app"]["device"]==after["app"]["device"] && before["app"]["inode"]!=after["app"]["inode"],
        "app-absence-restore-new-original")
}
fn rename_return_data(returned:transaction::ReturnedData,result:Result<()>)->Result<()> {
    result?; // First returned syscall/POST refusal remains the original failure.
    check(returned==transaction::ReturnedData::KnownSuccess,"app-absence-rename-return")
}
fn same_renamed_data(before:&Value,after:&Value)->bool {
    ["device","inode","mode","uid","gid","links","bytes","mtime","mtimeNanos"]
        .iter().all(|key|!before[*key].is_null() && before[*key]==after[*key])
}
struct Baseline {support:usize,private:usize,record:HeldRecord}
impl Baseline {
    fn create(book:&mut Install,binding:&Value)->Result<Self> {
        let b=compiled_binding_data()?;let support=book.support_root()?;
        book.absent(support,"MobileReleaseKit")?;book.absent(support,&b.baseline_name())?;
        let (census,count)=sibling_census(book,support,&[])?;
        book.clock()?;let mut raw=[0u8;16];getrandom::fill(&mut raw).map_err(|_|"app-absence-root-nonce")?;book.clock()?;
        let nonce=raw.iter().map(|b|format!("{b:02x}")).collect::<String>();let name=b.private_name(&nonce)?;
        let private=book.directory(support,&name,true,0o700)?;protected_private(book,private)?;
        check(book.identity(support)?.dev==book.identity(private)?.dev,"app-absence-private-filesystem")?;
        private_roster(book,private,&[])?;book.absent(support,"MobileReleaseKit")?;
        check(sibling_census(book,support,&[&name])?==(census.clone(),count),"app-absence-census-changed")?;
        let value=json!({"schemaVersion":1,"kind":"app-absence-baseline","binding":binding,"rootNonce":nonce,
            "parentIdentity":stable_identity_data(book.identity(support)?),"privateIdentity":stable_identity_data(book.identity(private)?),
            "siblingCensusSha256":census,"siblingCount":count,"rootAbsent":true,"transportState":"pending-original-exit"});
        let record=HeldRecord::write_baseline(book,support,&b.baseline_name(),value)?;
        let baseline=Self{support,private,record};baseline.post(book,false)?;Ok(baseline)
    }
    fn read(book:&mut Install,binding:&Value)->Result<Self> {
        let b=compiled_binding_data()?;let support=book.support_root()?;
        let record=HeldRecord::read(book,support,&b.baseline_name())?;let value=&record.value;
        object(value,&BASELINE_FIELDS)?;object(&value["binding"],&BINDING_FIELDS)?;
        check(value["schemaVersion"]==1 && value["kind"]=="app-absence-baseline" && value["binding"]==*binding
            && value["rootAbsent"]==true && value["transportState"]=="pending-original-exit"
            && value["siblingCensusSha256"].as_str().is_some_and(sha)
            && value["siblingCount"].as_u64().is_some_and(|n|n<=512),"app-absence-baseline-binding")?;
        stable_identity_shape(&value["parentIdentity"])?;stable_identity_shape(&value["privateIdentity"])?;
        let nonce=value["rootNonce"].as_str().ok_or("app-absence-root-nonce")?;let name=b.private_name(nonce)?;
        let private=book.open(Some(support),&name,true)?;protected_private(book,private)?;
        check(stable_identity_data(book.identity(support)?)==value["parentIdentity"]
            && stable_identity_data(book.identity(private)?)==value["privateIdentity"]
            && book.identity(support)?.dev==book.identity(private)?.dev,"app-absence-baseline-originals")?;
        let baseline=Self{support,private,record};baseline.post(book,true)?;Ok(baseline)
    }
    fn post(&self,book:&mut Install,root_present:bool)->Result<()> {
        self.record.post(book)?;protected_private(book,self.private)?;support_post(book,self.support)?;
        check(stable_identity_data(book.identity(self.support)?)==self.record.value["parentIdentity"]
            && stable_identity_data(book.identity(self.private)?)==self.record.value["privateIdentity"],"app-absence-baseline-originals")?;
        let b=compiled_binding_data()?;let name=b.private_name(self.record.value["rootNonce"].as_str().ok_or("app-absence-root-nonce")?)?;
        let public=b.baseline_name();let exclusions=if root_present {vec![name.as_str(),public.as_str(),"MobileReleaseKit"]}
            else {book.absent(self.support,"MobileReleaseKit")?;vec![name.as_str(),public.as_str()]};
        let (digest,count)=sibling_census(book,self.support,&exclusions)?;
        check(self.record.value["siblingCensusSha256"]==digest && self.record.value["siblingCount"]==count,"app-absence-census-changed")
    }
}
fn observe_current(book:&mut Install,admission:&mut Admission,baseline:&Baseline)->Result<maintenance::Observed> {
    let inventory=admission.inventory.take().ok_or("app-absence-input-once")?;
    let inventory_bytes=admission.inventory_bytes.take().ok_or("app-absence-input-once")?;
    let root=book.open(Some(baseline.support),"MobileReleaseKit",true)?;
    book.protected(root,true,Some(0o755))?;book.check_name(root,true)?;
    check(book.identity(root)?.dev==book.identity(baseline.private)?.dev,"app-absence-private-filesystem")?;
    Install::maintenance_input_bound(&inventory,&inventory_bytes)?;
    let gates=ExistingGates::preadmit(book,root)?;
    gates.acquire_registration(book)?;book.app_absence_existing_maintenance_gate(&gates)?;
    let versions=book.open(Some(root),"versions",true)?;book.protected(versions,true,Some(0o755))?;
    let selected=admission.selected.as_ref().ok_or("app-absence-native-admission-required")?.clone();
    let prepared=PreparedFresh{input:admission.source.input,inventory,inventory_bytes,destination:root,versions};
    let observed=maintenance::observe(book,prepared,selected,None)?;
    check(observed.action==ActionData::SamePackageNoop,"app-absence-current-required")?;
    observed.incoming_controls(book,admission.producer.input.descriptor_data(),admission.producer.input.signature_data())?;
    book.registration_complete_admitted(root,observed.action)?;
    gates.post(book)?;book.registration_ready()?;Ok(observed)
}
fn pending_record_proof_data(phase:PhaseData)->Value {
    let mut proof=proof_data(phase);
    // This document is serialized BEFORE its own original write/readback.
    // Only the later stdout observation may report returned recordReadback.
    if let Some(map)=proof.as_object_mut() {map.remove("recordReadback");}
    proof
}
fn private_record_data(binding:&Value,baseline:&str,snapshot:&Value,app:&Value,phase:PhaseData)->Result<Value> {
    check(matches!(phase,PhaseData::Withdraw|PhaseData::Verify) && sha(baseline),"app-absence-private-phase")?;
    Ok(json!({"schemaVersion":1,"kind":if phase==PhaseData::Withdraw {"app-absence-withdrawn"}else{"app-absence-verification"},
        "binding":binding,"baselineSha256":baseline,"snapshot":snapshot,"withdrawnAppIdentity":app,
        "renameReturned":"known-success","proof":pending_record_proof_data(phase),"transportState":"pending-original-exit"}))
}
fn withdraw(book:&mut Install,admission:&mut Admission,binding:&Value,baseline:&Baseline)->Result<Value> {
    private_roster(book,baseline.private,&[])?;
    let observed=observe_current(book,admission,baseline)?;
    // The ordinary export does not expose its parent's mkdir syscall token.
    // This is observed absent -> protected current root + genuine single
    // FreshInstall history/instance, NOT creator-actor/syscall attribution.
    // The independent parent additionally requires the initial Installer0.
    maintenance::app_absence_initial_history(&observed)?;
    let snapshot=maintenance::app_absence_snapshot(book,&observed)?;initial_snapshot_data(&snapshot)?;
    let index=observed.prepared.inventory.index()?;
    let app_bytes=index.files.iter().filter(|(path,_)|path.starts_with("app/")).try_fold(0u64,|n,(_,entry)|
        n.checked_add(entry.size).ok_or("app-absence-app-bound"))?;
    protected_storage(book,observed.prepared.destination,app_bytes)?;
    baseline.post(book,true)?;admission.post(book,true)?;
    // One original, never retry/rollback. Actual KnownSuccess remains retained
    // even if the following POST refuses; no later mutation then starts.
    let (returned,result)=maintenance::app_absence_withdraw(book,&observed,baseline.private);
    rename_return_data(returned,result)?;
    book.absent(observed.prepared.destination,paths::APP_NAME)?;
    let retained=maintenance::app_absence_retained_audit(book,&observed,baseline.private)?;
    let app=identity_data(book.identity(retained)?);
    check(same_renamed_data(&snapshot["app"],&app),"app-absence-withdrawn-original")?;
    maintenance::app_absence_state_post(book,&observed)?;
    let after=maintenance::app_absence_snapshot(book,&observed)?;
    for key in ["root","versions","release","runtime","instance","stateSha256","intentSha256","capsuleSha256","history"] {
        check(snapshot[key]==after[key],"app-absence-runtime-history-changed")?;
    }
    private_roster(book,baseline.private,&["app"])?;
    let record=HeldRecord::write(book,baseline.private,"withdrawn.json",
        private_record_data(binding,&baseline.record.digest,&snapshot,&app,PhaseData::Withdraw)?)?;
    private_roster(book,baseline.private,&["app","withdrawn.json"])?;
    baseline.post(book,true)?;record.post(book)?;admission.post(book,true)?;
    maintenance::app_absence_state_post(book,&observed)?;
    observation_data(binding,PhaseData::Withdraw,&baseline.record.digest,&record.digest)
}
fn verify(book:&mut Install,admission:&mut Admission,binding:&Value,baseline:&Baseline)->Result<Value> {
    private_roster(book,baseline.private,&["app","withdrawn.json"])?;
    let previous=HeldRecord::read(book,baseline.private,"withdrawn.json")?;
    object(&previous.value,&PRIVATE_FIELDS)?;
    check(previous.value["schemaVersion"]==1 && previous.value["kind"]=="app-absence-withdrawn"
        && previous.value["binding"]==*binding && previous.value["baselineSha256"]==baseline.record.digest
        && previous.value["renameReturned"]=="known-success" && previous.value["proof"]==pending_record_proof_data(PhaseData::Withdraw)
        && previous.value["transportState"]=="pending-original-exit","app-absence-withdrawal-record")?;
    let observed=observe_current(book,admission,baseline)?;
    let snapshot=maintenance::app_absence_snapshot(book,&observed)?;
    restore_snapshot_data(&previous.value["snapshot"],&snapshot)?;
    let retained=maintenance::app_absence_retained_audit(book,&observed,baseline.private)?;
    let app=identity_data(book.identity(retained)?);
    check(app==previous.value["withdrawnAppIdentity"] && same_renamed_data(&previous.value["snapshot"]["app"],&app),
        "app-absence-withdrawn-original")?;
    let record=HeldRecord::write(book,baseline.private,"verification.json",
        private_record_data(binding,&baseline.record.digest,&snapshot,&app,PhaseData::Verify)?)?;
    private_roster(book,baseline.private,&["app","withdrawn.json","verification.json"])?;
    baseline.post(book,true)?;previous.post(book)?;record.post(book)?;admission.post(book,true)?;
    maintenance::app_absence_state_post(book,&observed)?;book.check_name(retained,true)?;
    observation_data(binding,PhaseData::Verify,&baseline.record.digest,&record.digest)
}
// Exactly one bounded JSON line, not an authority-bearing frame. Use the same
// original absolute work clock and existing nonblocking-pipe helpers. Restore
// inherited flags before releasing any fixture originals; no new export clock.
fn emit_observation(book:&Install,value:&Value)->Result<()> {
    let raw=json_bytes_data(value,4096-OUTPUT_MARKER.len())?;
    let mut bytes=Vec::with_capacity(OUTPUT_MARKER.len()+raw.len()+1);
    bytes.extend_from_slice(OUTPUT_MARKER);bytes.extend_from_slice(&raw);bytes.push(b'\n');
    check(bytes.len()<=4096,"app-absence-output-bound")?;
    let output=std::io::stdout();let fd=output.as_fd();let deadline=book.shared_deadline()?;
    pipe_data(fd,true,deadline)?;
    let old=fcntl::fcntl(fd,fcntl::FcntlArg::F_GETFL).map_err(|_|"app-absence-output-flags")?;
    let sent=(|| {
        nonblocking(fd,deadline)?;let mut at=0;
        while at<bytes.len() {
            deadline.check_work()?;
            match unistd::write(fd,&bytes[at..]) {
                Ok(n) if n>0 && n<=bytes.len()-at=>at+=n,
                Ok(_)=>return Err("app-absence-output-write"),
                Err(Errno::EINTR)=>(),Err(Errno::EAGAIN)=>wait_ready(fd,true,deadline,true)?,
                Err(_)=>return Err("app-absence-output-write"),
            }
        }
        deadline.check_work()
    })();
    let restore=fcntl::fcntl(fd,fcntl::FcntlArg::F_SETFL(OFlag::from_bits_truncate(old)))
        .map_err(|_|"app-absence-output-restore").and_then(|_|{
            check(fcntl::fcntl(fd,fcntl::FcntlArg::F_GETFL).map_err(|_|"app-absence-output-flags")?==old,"app-absence-output-restore")});
    sent.and(restore)
}
pub(in crate::installer) fn entry()->i32 {
    let started=match monotonic(){Ok(v)=>v,Err(_)=>return 1};
    let deadline=match Deadline::from_entry(started){Ok(v)=>v,Err(_)=>return 1};
    let mut book=Install::with_worker_deadline(deadline,false);let mut admission=None;
    let result=(|| {
        let args=entry_arguments_data(std::env::args_os())?;
        check(args.len()==3,"app-absence-fixed-arguments")?;
        admission=Some(Admission::prepare(&mut book,&args[1],&args[2])?);
        let admitted=admission.as_mut().ok_or("app-absence-admission-missing")?;
        admitted.inspect(&mut book)?;let binding=binding_value(admitted)?;
        let output=match admitted.phase {
            PhaseData::Baseline=>{
                let baseline=Baseline::create(&mut book,&binding)?;
                admitted.post(&mut book,true)?;baseline.post(&mut book,false)?;
                observation_data(&binding,PhaseData::Baseline,&baseline.record.digest,&baseline.record.digest)?
            },
            PhaseData::Withdraw=>{let baseline=Baseline::read(&mut book,&binding)?;withdraw(&mut book,admitted,&binding,&baseline)?},
            PhaseData::Verify=>{let baseline=Baseline::read(&mut book,&binding)?;verify(&mut book,admitted,&binding,&baseline)?},
        };
        // This line says only pre-exit facts. Parent MUST require our actual0.
        emit_observation(&book,&output)
    })();
    let native=admission.as_mut().is_none_or(|a|a.settle(&book));
    if !native {
        // Never free borrowed originals while native custody is unresolved.
        // Process exit, not a fabricated close receipt, retires retained state.
        std::mem::forget(admission);std::mem::forget(book);return 1;
    }
    let closed=book.settle_originals();
    let timely=book.shared_deadline().and_then(Deadline::check_total).is_ok();
    if result.is_ok() && closed && timely && !book.unknown {0}else{1}
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_transport_and_same_source_bindings() {
        let source="1".repeat(40);
        for target in ["aarch64-apple-darwin","x86_64-apple-darwin"] {
            let binding=BindingData::new(&source,&source,"123","1",target).unwrap();
            assert!(binding.baseline_name().len()<255);
            assert!(binding.private_name(&"2".repeat(32)).unwrap().len()<255);
            for bad in ["0".repeat(32),"A".repeat(32),"../other".into()] {assert!(binding.private_name(&bad).is_err());}
        }
        for (product,run,attempt,target) in [(&"2".repeat(40)[..],"123","1","aarch64-apple-darwin"),
            (&source[..],"0123","1","aarch64-apple-darwin"),(&source[..],"123","0","aarch64-apple-darwin"),
            (&source[..],"123","1","x86_64-unknown-linux-gnu")] {
            assert!(BindingData::new(&source,product,run,attempt,target).is_err());
        }
        assert!(carrier_names_data(CARRIER_NAMES));
        assert!(!carrier_names_data(CARRIER_NAMES[..5].iter().copied()));
        assert!(!carrier_names_data(CARRIER_NAMES.into_iter().chain(["Install.pkg"])));
        for (index,name) in PHASE_NAMES.into_iter().enumerate() {
            let path=format!("/Volumes/Fixture {index}/{name}");let parsed=transport_data(&path).unwrap();
            assert_eq!(parsed.parent,format!("/Volumes/Fixture {index}"));
            assert_eq!(parsed.product,format!("/Volumes/Fixture {index}/Install.pkg"));
        }
        for path in ["MRK-AppAbsence-Baseline.pkg","/MRK-AppAbsence-Baseline.pkg",
            "/Volumes/P/Install.pkg","/Volumes/../P/MRK-AppAbsence-Baseline.pkg",
            "/Volumes//P/MRK-AppAbsence-Withdraw.pkg","/Volumes/P/MRK-AppAbsence-Verify.pkg/"] {
            assert!(transport_data(path).is_err());
        }
    }
    #[test]
    fn initial_fresh_install_and_same_gate_not_name_only() {
        let instance="3".repeat(32);
        assert!(fresh_install_matches_data(ActionData::FreshInstall,true,true,Some(0),&instance,&instance));
        for action in [ActionData::SamePackageNoop,ActionData::RestoreFixedApp,ActionData::Update] {
            assert!(!fresh_install_matches_data(action,true,true,Some(0),&instance,&instance));
        }
        for (created,joined,status) in [(false,true,Some(0)),(true,false,Some(0)),(true,true,None),(true,true,Some(1))] {
            assert!(!fresh_install_matches_data(ActionData::FreshInstall,created,joined,status,&instance,&instance));
        }
        assert!(!fresh_install_matches_data(ActionData::FreshInstall,true,true,Some(0),&instance,&"4".repeat(32)));
        let original=Identity { dev:1,ino:2,mode:0o100444,uid:0,gid:0,links:1,size:30,mtime:3,mtime_ns:4,ctime:5,ctime_ns:6 };
        assert!(same_gate_data(original,original,0,0));
        for changed in [Identity{ino:3,..original},Identity{mode:0o100644,..original},Identity{ctime:6,..original}] {
            assert!(!same_gate_data(original,changed,0,0));
        }
        assert!(!same_gate_data(original,original,1,0));assert!(!same_gate_data(original,original,0,1));
    }
    #[test]
    fn output_quote_and_original_exit_finality_are_separate() {
        assert_eq!(RECORD_LIMIT,64*1024);
        let max=transport_output_bytes_data(installation_record::PAYLOAD_LIMIT,FIXTURE_PACKAGE_LIMIT,FIXTURE_IMAGE_LIMIT).unwrap();
        assert!(max>FIXTURE_IMAGE_LIMIT);
        for (p,f,i) in [(27,28,1),(28,27,1),(28,28,0),(installation_record::PAYLOAD_LIMIT+1,28,1),
            (28,FIXTURE_PACKAGE_LIMIT+1,1),(28,28,FIXTURE_IMAGE_LIMIT+1),(u64::MAX,u64::MAX,u64::MAX)] {
            assert!(transport_output_bytes_data(p,f,i).is_none());
        }
        assert!(outer_phase_credit_data(true,true,true,Some(0),true,true,false));
        for missing in 0..5 {let mut facts=[true;5];facts[missing]=false;
            assert!(!outer_phase_credit_data(facts[0],facts[1],facts[2],Some(0),facts[3],facts[4],false));}
        for status in [None,Some(1),Some(20)] {assert!(!outer_phase_credit_data(true,true,true,status,true,true,false));}
        assert!(!outer_phase_credit_data(true,true,true,Some(0),true,true,true));
    }    fn snapshot_fixture() -> Value {
        let id=json!({"device":1,"inode":2,"mode":0o40555,"uid":0,"gid":0,"links":3,"bytes":96,
            "mtime":4,"mtimeNanos":0,"ctime":5,"ctimeNanos":0});
        let invocation="a".repeat(32);let request="b".repeat(32);let state="c".repeat(64);
        json!({"root":{"device":1,"inode":7},"versions":{"device":1,"inode":8},"release":id,"runtime":id,
            "app":id,"instance":"d".repeat(32),"invocation":invocation,"requestId":request,"action":"fresh-install",
            "stateSha256":state,"intentSha256":"e".repeat(64),"capsuleSha256":"f".repeat(64),"previous":null,
            "history":[{"invocation":invocation,"requestId":request,"stateSha256":state,"intentSha256":"e".repeat(64),"capsuleSha256":"f".repeat(64)}],
            "restoreRecovery":null,"restoreNamespace":{"commitment":"6".repeat(64),"groups":0,"names":0,
                "files":0,"controlBytes":0,"payloadBytes":0}})
    }
    #[test]
    fn actual_restore_requires_new_app_and_exact_initial_history() {
        let before=snapshot_fixture();assert!(initial_snapshot_data(&before).is_ok());
        let mut after=before.clone();after["action"]=json!("restore-fixed-app");after["invocation"]=json!("1".repeat(32));
        after["requestId"]=json!("2".repeat(32));after["previous"]=json!([before["invocation"],before["stateSha256"]]);
        after["app"]["inode"]=json!(3);
        after["history"].as_array_mut().unwrap().push(json!({"invocation":"1".repeat(32),"requestId":"2".repeat(32),
            "intentSha256":"3".repeat(64),"stateSha256":"4".repeat(64),"capsuleSha256":"5".repeat(64)}));
        assert!(restore_snapshot_data(&before,&after).is_ok());
        // A genuine recovered State/reference still is NOT ordinary Restore
        // evidence. Missing/null/extra rows and typed count substitutions also
        // refuse; the private commitment never replaces an actual native audit.
        for baseline in [&before,&after] {
            let validate=|value:&Value|if baseline["action"]=="fresh-install" {initial_snapshot_data(value)}
                else {restore_snapshot_data(&before,value)};
            let mut changed=baseline.clone();
            changed["restoreRecovery"]=json!({"tornInvocation":"7".repeat(32),
                "receiptInvocation":"8".repeat(32),"receiptSha256":"9".repeat(64)});
            assert!(validate(&changed).is_err());
            for key in ["restoreRecovery","restoreNamespace"] {
                let mut changed=baseline.clone();changed.as_object_mut().unwrap().remove(key);
                assert!(validate(&changed).is_err(),"{key}");
            }
            for key in ["groups","names","files","controlBytes","payloadBytes"] {
                for bad in [json!(1),json!(true),Value::Null,json!(-1)] {
                    let mut changed=baseline.clone();changed["restoreNamespace"][key]=bad;
                    assert!(validate(&changed).is_err(),"{key}");
                }
            }
            let mut changed=baseline.clone();changed["restoreNamespace"]["commitment"]=json!("unknown");
            assert!(validate(&changed).is_err());
            changed=baseline.clone();changed["restoreNamespace"]["admitted"]=json!(true);
            assert!(validate(&changed).is_err());
        }
        for key in ["root","versions","release","runtime","instance","previous","action","history"] {
            let mut changed=after.clone();changed[key]=Value::Null;assert!(restore_snapshot_data(&before,&changed).is_err(),"{key}");
        }
        for key in ["invocation","requestId"] {let mut changed=after.clone();changed[key]=before[key].clone();
            assert!(restore_snapshot_data(&before,&changed).is_err(),"{key}");}
        for key in ["inode","device"] {let mut changed=after.clone();changed["app"][key]=if key=="inode" {json!(2)}else{json!(9)};
            assert!(restore_snapshot_data(&before,&changed).is_err(),"{key}");}
        let mut changed=after.clone();changed["history"][0]["capsuleSha256"]=json!("0".repeat(64));
        assert!(restore_snapshot_data(&before,&changed).is_err());
        let mut changed=before.clone();changed["action"]=json!("same-package-noop");assert!(initial_snapshot_data(&changed).is_err());
        changed=before.clone();changed["previous"]=json!(["1".repeat(32),"2".repeat(64)]);assert!(initial_snapshot_data(&changed).is_err());
    }
    #[test]
    fn exclusive_rename_metadata_and_record_bounds_are_not_identity_reset() {
        use transaction::ReturnedData as R;
        assert!(rename_return_data(R::KnownSuccess,Ok(())).is_ok());
        for returned in [R::KnownSuccess,R::KnownRefusal,R::Unknown] {
            assert_eq!(rename_return_data(returned,Err("original-post-failed")),Err("original-post-failed"));
        }
        assert!(rename_return_data(R::Unknown,Ok(())).is_err());
        assert!(rename_return_data(R::KnownRefusal,Ok(())).is_err());
        let before=snapshot_fixture()["app"].clone();let mut after=before.clone();after["ctime"]=json!(6);
        assert!(same_renamed_data(&before,&after));
        for key in ["device","inode","mode","uid","gid","links","bytes","mtime","mtimeNanos"] {
            let mut bad=after.clone();bad[key]=json!(999);assert!(!same_renamed_data(&before,&bad),"{key}");
            bad[key]=Value::Null;assert!(!same_renamed_data(&before,&bad),"{key}");
        }
        let id=Identity{dev:1,ino:2,mode:0o40700,uid:0,gid:0,links:2,size:64,mtime:1,mtime_ns:0,ctime:1,ctime_ns:0};
        assert!(stable_identity_shape(&stable_identity_data(id)).is_ok());
        for key in ["device","inode","mode","uid","gid"] {let mut bad=stable_identity_data(id);bad[key]=Value::Null;
            assert!(stable_identity_shape(&bad).is_err());}
        let fresh=Identity{dev:1,ino:7,mode:0o100600,uid:0,gid:80,links:1,size:0,mtime:1,mtime_ns:0,ctime:1,ctime_ns:0};
        let normalized=Identity{gid:0,ctime:2,..fresh};
        for gid in [0,80,501] {
            let inherited=Identity{gid,..fresh};assert!(public_receipt_writer_private_data(inherited));
            assert!(public_receipt_writer_normalized_data(inherited,normalized,normalized,Ok(())).is_ok());
        }
        for bad in [Identity{ino:8,..normalized},Identity{dev:2,..normalized},Identity{uid:501,..normalized},
            Identity{gid:80,..normalized},Identity{links:2,..normalized},Identity{mode:0o100640,..normalized},
            Identity{mode:0o40600,..normalized},Identity{size:1,..normalized},Identity{mtime:2,..normalized}] {
            assert!(public_receipt_writer_normalized_data(fresh,bad,bad,Ok(())).is_err());
        }
        assert!(public_receipt_writer_normalized_data(fresh,normalized,fresh,Ok(())).is_err());
        assert!(public_receipt_writer_normalized_data(Identity{links:2,..fresh},normalized,normalized,Ok(())).is_err());
        assert_eq!(public_receipt_writer_normalized_data(fresh,normalized,normalized,Err("original-owner-refused")),Err("original-owner-refused"));
        assert!(json_bytes_data(&json!("a".repeat(RECORD_LIMIT)),RECORD_LIMIT).is_err());
        assert!(json_bytes_data(&json!("a".repeat(RECORD_LIMIT-3)),RECORD_LIMIT).is_ok());
    }
    #[test]
    fn phase_observations_are_pending_outer_exit_and_keep_private_fields_private() {
        let mut binding=Map::new();for key in BINDING_FIELDS {binding.insert(key.into(),json!("1".repeat(if key.ends_with("Source"){40}else{64})));}
        binding.insert("runId".into(),json!("123"));binding.insert("runAttempt".into(),json!("1"));
        binding.insert("target".into(),json!("aarch64-apple-darwin"));let binding=Value::Object(binding);
        for phase in [PhaseData::Baseline,PhaseData::Withdraw,PhaseData::Verify] {
            let value=observation_data(&binding,phase,&"2".repeat(64),&"3".repeat(64)).unwrap();
            assert_eq!(value.as_object().unwrap().len(),21);assert_eq!(value["originalOuterExitRequired"],true);
            assert_eq!(value["systemServiceExitClaimed"],false);assert_eq!(value["productReady"],false);
            let raw=json_bytes_data(&value,4096).unwrap();assert!(raw.len()<4096);
            for forbidden in ["rootNonce","privateIdentity","invocation","requestId","originalsClosed","deadlineMet","cleanupSucceeded"] {
                assert!(!value.as_object().unwrap().contains_key(forbidden));
            }
            assert_eq!(value["proof"],proof_data(phase));
        }
        let record=private_record_data(&binding,&"2".repeat(64),&snapshot_fixture(),&snapshot_fixture()["app"],PhaseData::Withdraw).unwrap();
        assert!(!record["proof"].as_object().unwrap().contains_key("recordReadback"));
        assert_eq!(record["transportState"],"pending-original-exit");assert_eq!(record["renameReturned"],"known-success");
        assert!(object(&record,&PRIVATE_FIELDS).is_ok());
        assert!(private_record_data(&binding,&"2".repeat(64),&Value::Null,&Value::Null,PhaseData::Baseline).is_err());
    }

}
