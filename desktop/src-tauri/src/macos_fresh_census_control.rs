// NONSHIPPING control, included only inside installer::worker. The public
// process entry is separately bound. These collectors read genuine native
// originals; they do not construct Fresh Ready/conservation capabilities.
use super::*;

const PRODUCT_SOURCE: &str = "8097137e9204c2e1dfa5d3bf5d3785e662ee64ef";
const OUTPUT_LIMIT: usize = 16 * 1024;
const OUTPUT_RESERVE: u64 = 128 * 1024;

#[cfg(feature="macos-installed-fresh-census-control")]
pub(super) enum CensusRequest<'a> {
    // A bounded nomination only. FreshRecoveryInput authenticates the actual
    // held intent; this string is not an old-attempt or ownership capability.
    Frontier { invocation: &'a str },
    CompletedConservation,
}

// Four bounded args: exact protected input/package plus completed scope or
// a nomination. No private writer, generic root or arbitrary operation role.
#[cfg(feature="macos-installed-fresh-census-control")]
pub(in crate::installer) fn entry() -> i32 {
    let started = match monotonic() { Ok(value)=>value, Err(_)=>return 1 };
    let args = match entry_arguments_data(std::env::args_os()) { Ok(value)=>value, Err(_)=>return 1 };
    let result = (|| {
        check(args.len()==4 && args[1].starts_with('/') && args[2].starts_with('/'),"fresh-census-arguments")?;
        let request = if args[3]=="completed-conservation" { CensusRequest::CompletedConservation }
            else { check(invocation_valid(&args[3]),"fresh-census-invocation")?;
                CensusRequest::Frontier{invocation:&args[3]} };
        collect(Deadline::from_entry(started)?,&args[1],&args[2],request)
    })();
    match result {
        Ok(body) => if std::io::Write::write(&mut std::io::stdout().lock(),&body).ok()==Some(body.len()) {0}else{1},
        Err(reason) => {
            // Closed static reasons only. One bounded write, no retry. Refusal
            // is not an observation or reconstruction of the old child exit.
            let line=format!("fresh-census-refused:{reason}\n");
            if line.len()<=256 {let _=std::io::Write::write(&mut std::io::stderr().lock(),line.as_bytes());}
            1
        }
    }
}

pub(super) fn control_binding() -> Result<(&'static str, &'static str)> {
    check(option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT") == Some(PRODUCT_SOURCE),
        "fresh-census-product-source")?;
    let control = option_env!("MRK_FRESH_CONTROL_SOURCE_SHA256")
        .ok_or("fresh-census-control-unbound")?;
    let manifest = option_env!("MRK_FRESH_CONTROL_MANIFEST_SHA256")
        .ok_or("fresh-census-control-unbound")?;
    let valid = |s: &str, len: usize| s.len() == len
        && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && s.bytes().any(|b| b != b'0');
    check(valid(control,64) && valid(manifest,64),
        "fresh-census-control-binding")?;
    Ok((control,manifest))
}

#[cfg(feature="macos-installed-fresh-census-control")]
fn read_only_gate_post(book: &Install, root: usize) -> Result<()> {
    reinstall_exclusion(book,root)?;
    check(book.registration.creation == "existing-not-modified"
        && book.registration.writer.is_none() && !book.registration.closed_under_maintenance
        && book.gate.creation == "existing-not-modified" && book.gate.writer.is_none(),
        "fresh-census-existing-gates")?;
    let r = book.registration.participant.ok_or("fresh-census-r-original")?;
    let m = book.gate.participant.ok_or("fresh-census-m-original")?;
    for n in [r,m] {
        check(fcntl::fcntl(book.fd(n)?,fcntl::FcntlArg::F_GETFL)
            .map_err(|_|"fresh-census-gate-flags")? & OFlag::O_ACCMODE.bits()
            == OFlag::O_RDONLY.bits(), "fresh-census-gate-readonly")?;
    }
    book.registration_protected(r)?;
    book.gate_protected(m)?;
    maintenance::held_bytes(book,r,paths::REGISTRATION_GATE_BYTES)?;
    maintenance::held_bytes(book,m,paths::MAINTENANCE_GATE_BYTES)?;
    book.clock()
}

// Existing R may be opened/locked but never created by its current helper.
// The M sequence deliberately omits maintenance_gate's absent/create branch.
// The actual Book owns each opened participant before any fallible check.
#[cfg(feature="macos-installed-fresh-census-control")]
fn acquire_existing_gates(book: &mut Install, root: usize) -> Result<()> {
    check(!book.registration.entered && !book.gate.entered
        && book.registration.participant.is_none() && book.gate.participant.is_none(),
        "fresh-census-gates-once")?;
    book.registration_before_maintenance(root)?;
    check(book.registration.creation == "existing-not-modified"
        && book.registration.verified && book.registration.exclusive_acquired
        && book.registration.writer.is_none(), "fresh-census-existing-r")?;
    book.registration_protected(book.registration.participant.ok_or("fresh-census-r-original")?)?;
    book.gate.entered = true;
    book.gate.parent = Some(root);
    book.gate.creation = "existing-not-modified";
    let reader = book.open_role(Some(root),paths::MAINTENANCE_GATE_NAME,false,Role::GateParticipant)?;
    book.gate_protected(reader)?;
    maintenance::held_bytes(book,reader,paths::MAINTENANCE_GATE_BYTES)?;
    book.gate.verified = true;
    book.gate.lock_attempted = true;
    #[allow(deprecated)] // The original Book retains this OFD until consuming close.
    let result = fcntl::flock(book.fd(reader)?.as_raw_fd(),fcntl::FlockArg::LockExclusiveNonblock);
    result.map_err(|_|"fresh-census-m-busy-or-refused")?;
    book.gate.exclusive_acquired = true;
    read_only_gate_post(book,root)
}

#[cfg(feature="macos-installed-fresh-census-control")]
impl Parent {
    fn collect_fresh_census(&mut self, source_path: &str, completed: &str,
        request: CensusRequest<'_>, control: &str, control_manifest: &str) -> Result<Vec<u8>> {
        check(!self.entered && self.child.is_none() && self.command.is_none()
            && self.request_export.is_none() && self.reinstall_input.is_none(),
            "fresh-census-parent-once")?;
        // The authenticated current input/producer originals are retained on
        // this Parent before any native verifier call. No root/gate is created.
        let (input,inventory,raw,selected,_) = self.admit_completed_input_once(source_path,completed)?;
        let prepared = self.book.prepare_existing_maintenance_root(input,inventory,raw)?;
        let root = prepared.destination;
        self.reinstall_input = Some(prepared);
        acquire_existing_gates(&mut self.book,root)?;
        maintenance::reserve_removal_snapshot_work(&mut self.book)?;
        check(maintenance::removal_effective_control_bytes(&self.book)?
            .checked_add(OUTPUT_RESERVE).is_some_and(|n| n <= installation_record::CONTROL_LIMIT as u64),
            "fresh-census-output-budget")?;
        self.book.removal_control_reserved = self.book.removal_control_reserved
            .checked_add(OUTPUT_RESERVE).ok_or("fresh-census-output-budget")?;

        let source = self.source.as_ref().ok_or("fresh-census-source")?;
        let producer = self.producer.as_ref().ok_or("fresh-census-producer")?;
        let prepared = self.reinstall_input.as_ref().ok_or("fresh-census-input")?;
        let current = ReinstallInputRead::parent(&self.book,source,producer,root,
            prepared.input,&prepared.inventory,&prepared.inventory_bytes)?;
        let (scope,body) = match request {
            CensusRequest::CompletedConservation => ("completed-conservation",
                maintenance::fresh_conservation::control_collect_completed(&mut self.book,&current)?),
            CensusRequest::Frontier { invocation } => {
                check(invocation_valid(invocation),"fresh-census-invocation")?;
                let view = FreshRecoveryInput::new(&mut self.book,source,producer,prepared,invocation)?;
                let launcher = applications::FreshRecovery::observe_fresh(&mut self.book,&view)?;
                let observed = maintenance::fresh_conservation::observe(&mut self.book,&view,launcher.as_ref())?;
                let body = observed.control_audit_data(&mut self.book)?;
                view.post(&self.book)?;
                ("fresh-frontier",body)
            },
        };
        check(!body.is_empty() && body.len() <= OUTPUT_LIMIT,"fresh-census-body-bound")?;
        current.post_source(&self.book)?;
        producer.authenticated_post(&self.book,source,true)?;
        read_only_gate_post(&self.book,root)?;
        let observation: Value = serde_json::from_slice(&body).map_err(|_|"fresh-census-body-json")?;
        let value = json!({"schemaVersion":1,"kind":"mrk-disposable-fresh-census-v1",
            "scope":scope,"productSource":PRODUCT_SOURCE,"controlSourceSha256":control,
            "controlManifestSha256":control_manifest,"controlImageSha256":source.image_sha,"target":target(),
            "packageSha256":producer.input.package_sha256_data(),
            "producerDescriptorSha256":hash(producer.input.descriptor_data()),
            "producerSignatureSha256":hash(producer.input.signature_data()),
            "selectionSha256":hash(&selected.encode_data().map_err(|_|"fresh-census-selection")?),
            "observation":observation,"transportState":"pending-original-process-exit",
            "installationQualified":false,"recoveryExecuted":false});
        let mut encoded = serde_json::to_vec(&value).map_err(|_|"fresh-census-output-json")?;
        encoded.push(b'\n');
        check(encoded.len() <= OUTPUT_LIMIT,"fresh-census-output-bound")?;
        Ok(encoded)
    }
}

// Callable source core for the later bound process entry. Success returns
// bytes only after the original Parent closes all native/book resources under
// its original Deadline. The returned body still cannot attest future exit.
#[cfg(feature="macos-installed-fresh-census-control")]
pub(super) fn collect(deadline: Deadline, source_path: &str, completed: &str,
    request: CensusRequest<'_>) -> Result<Vec<u8>> {
    let (control,manifest) = control_binding()?;
    deadline.check_work()?;
    check(unistd::getuid().is_root() && unistd::geteuid().is_root(),"fresh-census-root-required")?;
    let mut parent = Parent::new(deadline)?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
        parent.collect_fresh_census(source_path,completed,request,control,manifest)))
        .unwrap_or(Err("fresh-census-unwind"));
    let settled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
        parent.settle_parent_originals())).unwrap_or(false);
    // Preserve the original collection failure rather than replacing it with
    // a later close/clock refusal. No partial body is exposed after failure.
    let body = result?;
    check(settled && parent.errors.is_empty() && !parent.book.unknown
        && parent.parent_book_settled && parent.book.originals_settled(),
        "fresh-census-original-finality")?;
    parent.book.shared_deadline()?.check_total()?;
    Ok(body)
}

// Existing Parent owns the actual self-child, command, native verifier cells,
// deadline and consuming closes. An interrupted worker sends no RESULT. Keep
// that original failure; this diagnostic never qualifies installation success.
#[cfg(any(feature="macos-installed-fresh-write-cut",feature="macos-installed-fresh-torn-cut"))]
pub(super) fn cut_entry(source:&str,completed:&str,started:u64)->i32 {
    let (control,manifest)=match control_binding(){Ok(value)=>value,Err(_)=>return 78};
    let mut parent=match Deadline::from_entry(started).and_then(Parent::new){Ok(value)=>value,Err(_)=>return 1};
    // Reserve this diagnostic under the same control budget before effects.
    let reserved=parent.book.removal_control_reserved.checked_add(OUTPUT_RESERVE);
    if !reserved.is_some_and(|n|n<=installation_record::CONTROL_LIMIT as u64) {return 1;}
    parent.book.removal_control_reserved=reserved.unwrap();
    let returned=match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||parent.run_completed(source,completed))) {
        Ok(returned)=>returned,
        Err(_)=>{
            parent.note("fresh-cut-parent-unwind");
            // Settle this original child through the existing termination,
            // EOF, wait and close owner under the same original deadline.
            if parent.child.is_some() && (parent.wait.is_none() || parent.output_original.is_some()) {
                let _=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||parent.collect()));
            }
            Err("fresh-cut-parent-unwind")
        }
    };
    let original_failure=match returned {
        Err(error)=>{parent.note(error);Some(error)},
        Ok(_)=>{parent.note("fresh-cut-missed-boundary");None},
    };
    // Actual original source and producer POST before their consuming closes.
    // An unwind here must also reach the same original native/book settlement.
    let (post,binding)=match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let post=parent.source.as_ref().zip(parent.producer.as_ref()).is_some_and(|(source,producer)|
            parent.book.source_post(source).is_ok() && producer.authenticated_post(&parent.book,source,true).is_ok());
        let binding=parent.source.as_ref().zip(parent.producer.as_ref()).map(|(source,producer)|
            (source.image_sha.clone(),producer.input.package_sha256_data().to_owned(),
                hash(producer.input.descriptor_data()),hash(producer.input.signature_data())));
        (post,binding)
    })) {
        Ok(value)=>value,
        Err(_)=>{parent.note("fresh-cut-source-post-unwind");(false,None)},
    };
    let originals=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||parent.settle_parent_originals())).unwrap_or(false);
    let native=parent.producer.as_ref().is_some_and(|producer|producer.signature.settled()
        && producer.entry.settled() && producer.payload.settled());
    let timely=parent.settlement_time();
    let exit=parent.wait.as_ref().and_then(ExitStatus::code);
    let (role,expected)=if cfg!(feature="macos-installed-fresh-write-cut") {("first-payload-write",87)}
        else {("torn-first-payload-frame",88)};
    let witnessed=original_failure==Some("worker-result-incomplete") && parent.errors.len()==1
        && exit==Some(expected) && !parent.wait_unknown && !parent.termination_attempted
        && parent.child.is_some() && parent.output_admitted && parent.output_eof && parent.output_close
        && parent.command_close && parent.command_gate_kernel_retained && parent.command.is_some()
        && originals && native && timely && post && parent.parent_book_settled && !parent.book.unknown
        && parent.book.originals_settled() && invocation_valid(&parent.invocation)
        && parent.maintenance.as_ref().is_some_and(|observed|observed.action==ActionData::FreshInstall);
    if let Some((image,package,descriptor,signature))=binding {
        let value=json!({"schemaVersion":1,"kind":"mrk-disposable-fresh-cut-v1","role":role,
            "productSource":PRODUCT_SOURCE,"controlSourceSha256":control,"controlManifestSha256":manifest,
            "controlImageSha256":image,"packageSha256":package,"producerDescriptorSha256":descriptor,
            "producerSignatureSha256":signature,"invocation":parent.invocation,"target":target(),
            "originalFailure":original_failure,"originalChildExit":exit,"outputEof":parent.output_eof,
            "outputClose":parent.output_close,"commandClose":parent.command_close,
            "parentOriginalsSettled":originals,"nativeSettled":native,"timely":timely,
            "sourcePost":post,"terminationAttempted":parent.termination_attempted,
            "controlledInterruptionWitnessed":witnessed,"installationQualified":false,
            "transportState":"pending-original-process-exit"});
        if let Ok(mut body)=serde_json::to_vec(&value) {body.push(b'\n');
            if body.len()<=OUTPUT_LIMIT {let _=std::io::Write::write(&mut std::io::stderr().lock(),&body);}
        }
    }
    // Even a fully witnessed cut is an original installation failure.
    1
}
