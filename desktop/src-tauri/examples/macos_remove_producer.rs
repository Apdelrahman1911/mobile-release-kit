//! Nonshipping fixed Remove.pkg sidecar emission. Never runs or removes an app.
//! Parent retains original command/finality and memory admission; child success
//! is only the bounded record AFTER genuine signature/static-purpose closure.
#![forbid(unsafe_code)]
#[cfg(all(feature="macos-remove-observer-producer", any(feature="macos-installed-installer",
    feature="macos-installed-remover",feature="macos-installed-installer-fixture",
    feature="macos-installed-removal-abrupt-fixture",feature="macos-installed-removal-observer")))]
compile_error!("observer emission is a separate nonshipping example graph");
#[cfg(all(feature="macos-remove-producer",target_os="macos",target_pointer_width="64",
    any(target_arch="aarch64",target_arch="x86_64")))]
#[path="macos_producer_common/mod.rs"]
mod common;
#[cfg(all(feature="macos-remove-producer",target_os="macos",target_pointer_width="64",
    any(target_arch="aarch64",target_arch="x86_64")))]
mod emitter {
    use std::{ffi::OsString,os::fd::AsFd,path::{Path,PathBuf},time::Instant};
    use super::common::*;
    use mobile_release_desktop::{macos_install_paths as paths,macos_install_record::Inventory,
        macos_install_producer::ProducerData,
        macos_remove_producer::{RemovalData,EmissionBindingData,DESCRIPTOR_FILENAME,SIGNATURE_FILENAME,REMOVER_EXECUTABLE}};
    use mrk_macos_installed_native::{self as native,install_producer::{self,
        ProducerVerifier,SignatureResult,RemovalProgramVerifier,RemovalProgramResult,
        RemovalProducerSigner,PackageSignResult,RemovalProducerVerifier}};
    #[cfg(not(feature="macos-remove-observer-producer"))]
    const INPUTS:[(&str,ReadRole);5]=[("remove-descriptor-input.json",ReadRole::RemoveDescriptor),
        ("producer.json",ReadRole::InstallDescriptor),("producer.sig",ReadRole::Signature),
        ("install-inventory.json",ReadRole::Inventory),("mrk-macos-remove",ReadRole::Program)];
    #[cfg(feature="macos-remove-observer-producer")]
    const INPUTS:[(&str,ReadRole);6]=[("remove-descriptor-input.json",ReadRole::RemoveDescriptor),
        ("producer.json",ReadRole::InstallDescriptor),("producer.sig",ReadRole::Signature),
        ("install-inventory.json",ReadRole::Inventory),("mrk-macos-remove",ReadRole::Program),
        ("installed-mrk-macos-remove",ReadRole::Program)];
    const INPUT_ARGUMENT:&str=if cfg!(feature="macos-remove-observer-producer") {
        "--observer-input-root"
    } else {"--input-root"};
    fn program_binding_data(own:(&str,u64), installed:(&str,u64),
        inventory:(&str,u64,bool), observer:bool)->Result<()> {
        need(own.1>0&&installed.1>0&&inventory.2&&installed.0==inventory.0&&installed.1==inventory.1
            &&(if observer {own.0!=installed.0} else {own==installed}),"installed-remover-binding")
    }

    // Existing Parent uses the same2MiB allowance for supplied native copies,
    // cells and wrappers. This is not Security.framework heap or process RSS.
    fn native_allocation_data(bounds:[Option<usize>;4])->Result<usize> {
        let bytes=bounds.into_iter().try_fold(0usize,|total,next|total.checked_add(next?))
            .ok_or("remove-native-allocation-bound")?;
        need(bytes<=2*1024*1024,"remove-native-allocation-bound")?;Ok(bytes)
    }
    fn arguments(args:&[OsString])->Result<(PathBuf,PathBuf)> {
        need(args.len()==4&&args[0]=="--package-root"&&args[2]==INPUT_ARGUMENT,"arguments")?;
        let root=PathBuf::from(&args[1]);let input=PathBuf::from(&args[3]);
        components(&root)?;components(&input)?;
        need(!input.starts_with(&root)&&!root.starts_with(&input),"separate-private-roots")?;Ok((root,input))
    }
    pub fn run()->Result<()> {
        let start=Instant::now();let args:Vec<_>=std::env::args_os().skip(1).take(5).collect();
        let(root_path,input_path)=arguments(&args)?;let mut book=Book::new(start)?;
        let result=(||->Result<(String,String,String,usize,usize)> {
            // All four originals retain a conservative native supplied-memory
            // allowance before any native call. Separately bounded raw/parser
            // storage and Book's streaming buffer are not hidden in this sum.
            native_allocation_data([ProducerVerifier::project_owned_upper_bound(),
                RemovalProgramVerifier::project_owned_upper_bound(),
                RemovalProducerSigner::project_owned_upper_bound(),
                RemovalProducerVerifier::project_owned_upper_bound()])?;
            book.tick()?;book.pending.set(true);let platform=native::platform();book.pending.set(false);
            platform.map_err(|_|"platform")?;book.tick()?;
            book.pending.set(true);let source=install_producer::source_signer_data();book.pending.set(false);
            let source=source.ok_or("source-signer-unavailable")?;book.tick()?;
            let root=book.parents(&root_path,true)?;book.private_root(root)?;
            let package=book.open(Some(root),"Remove.pkg",false,true)?;book.file_policy(package,PACKAGE_LIMIT)?;
            // Exactly four roster originals: this initial package, initial
            // input below, after json, after sig. Finality uses retained POST.
            book.roster(root,&[("Remove.pkg",book.id(package)?.ino)])?;
            let input_root=book.parents(&input_path,true)?;book.private_root(input_root)?;
            let mut originals=[0usize;INPUTS.len()];
            for (index,(name,role)) in INPUTS.iter().enumerate() {
                let original=book.open(Some(input_root),name,false,true)?;
                if *role==ReadRole::Program {book.program_policy(original)?;}
                else {book.file_policy(original,role.policy().0)?;}
                originals[index]=original;
            }
            let wanted:Vec<_>=INPUTS.iter().zip(originals).map(|((name,_),n)|Ok((*name,book.id(n)?.ino)))
                .collect::<Result<_>>()?;
            #[cfg(not(feature="macos-remove-observer-producer"))]
            book.roster(input_root,&wanted)?;
            #[cfg(feature="macos-remove-observer-producer")]
            book.roster_observer_inputs(input_root,&wanted)?;
            let [input,installed_input,installed_signature,inventory_input,program]=
                [originals[0],originals[1],originals[2],originals[3],originals[4]];
            // Only this compile-fixed observer role has a sixth actual input.
            // It preserves the signed installed program binding, not a forged
            // inventory for our different observer executable.
            #[cfg(feature="macos-remove-observer-producer")]
            let installed_program=originals[5];
            #[cfg(not(feature="macos-remove-observer-producer"))]
            let installed_program=program;
            let (package_hash,_)=book.read(package,ReadRole::Package)?;
            let (descriptor_hash,descriptor)=book.read(input,ReadRole::RemoveDescriptor)?;
            let (installed_hash,installed)=book.read(installed_input,ReadRole::InstallDescriptor)?;
            let (installed_signature_hash,installed_sig)=book.read(installed_signature,ReadRole::Signature)?;
            let (inventory_hash,inventory_raw)=book.read(inventory_input,ReadRole::Inventory)?;
            let (program_hash,_)=book.read(program,ReadRole::Program)?;
            #[cfg(feature="macos-remove-observer-producer")]
            let installed_program_hash=book.read(installed_program,ReadRole::Program)?.0;
            #[cfg(not(feature="macos-remove-observer-producer"))]
            let installed_program_hash=program_hash.as_str();
            // Genuine unchanged Install-v2 signature first. An installed
            // current tuple is not authenticated by a Remove descriptor alone.
            let mut install_verifier=ProducerVerifier::new();
            let install_verified=install_verifier.verify_and_close(&installed,&installed_sig,&mut |point|book.native_point(point));
            if !install_verifier.settled() {book.unknown.set(true);return Err("installed-signature-finality");}
            need(install_verified==SignatureResult::SignatureVerified,"installed-signature-verification")?;
            book.cleanup.set(false);book.all()?;
            let install=ProducerData::parse_data(&installed,target()).map_err(|_|"installed-data")?;
            let current=install.release_set_data().current_data().binding_data();
            let source_commit=option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT").ok_or("source-current-unavailable")?;
            let runtime_manifest=option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256").ok_or("source-runtime-unavailable")?;
            need(current.source_commit==source_commit&&current.release==paths::RELEASE
                &&current.package_version==paths::PACKAGE_VERSION&&current.protocol_sha256==paths::PROTOCOL_SHA
                &&current.runtime_manifest_sha256==runtime_manifest&&current.inventory_sha256==inventory_hash
                &&install.signing_policy_data().matches_source_data(source.team_data(),source.leaf_sha1_data(),source.leaf_sha256_data()),
                "installed-current-source")?;
            let inventory=Inventory::parse(&inventory_raw,runtime_manifest).map_err(|_|"installed-inventory")?;
            let index=inventory.index().map_err(|_|"installed-inventory-index")?;
            let row=index.files.get(paths::REMOVER_INVENTORY_PATH).ok_or("installed-remover-missing")?;
            program_binding_data((&program_hash,book.id(program)?.size as u64),
                (&installed_program_hash,book.id(installed_program)?.size as u64),
                (&row.sha256,row.size,row.executable),cfg!(feature="macos-remove-observer-producer"))?;
            let mut program_verifier=RemovalProgramVerifier::new();
            // Cell flags permit a shared borrow of the ORIGINAL descriptors
            // while the same Book performs complete POST at every checkpoint.
            // No dup, reopen, raw descriptor manufacture or reduced gate.
            let program_verified=program_verifier.verify_and_close(book.fd(input_root)?.as_fd(),book.fd(program)?.as_fd(),
                &input_path,&mut |point|book.native_point(point));
            if !program_verifier.settled() {book.unknown.set(true);return Err("program-finality");}
            need(program_verified==RemovalProgramResult::PurposeVerified,"program-purpose")?;
            book.cleanup.set(false);book.all()?;
            let data=RemovalData::parse_data(&descriptor,target()).map_err(|_|"remove-data")?;
            let expected=EmissionBindingData{target:target(),source_commit,release:paths::RELEASE,protocol_sha256:paths::PROTOCOL_SHA,
                installed_producer_sha256:&installed_hash,installed_inventory_sha256:&inventory_hash,
                package_version:paths::PACKAGE_VERSION,completed_package_sha256:&package_hash,remover_executable_sha256:&program_hash,
                team:source.team_data(),leaf_sha1:source.leaf_sha1_data(),leaf_sha256:source.leaf_sha256_data()};
            data.validate_emission_data(&expected,&installed).map_err(|_|"remove-emission-binding")?;
            need(REMOVER_EXECUTABLE==INPUTS[4].0,"fixed-remover-name")?;
            let mut signer=RemovalProducerSigner::new();
            let signed=signer.sign_and_close(&descriptor,&mut |point|book.native_point(point));
            if !signer.settled() {book.unknown.set(true);return Err("remove-signer-finality");}
            let PackageSignResult::SignatureCreated(signature)=signed else {return Err("remove-signature-not-created");};
            let mut verifier=RemovalProducerVerifier::new();
            let verified=verifier.verify_and_close(&descriptor,signature.as_bytes(),&mut |point|book.native_point(point));
            if !verifier.settled() {book.unknown.set(true);return Err("remove-verification-finality");}
            need(verified==SignatureResult::SignatureVerified,"remove-signature-verification")?;
            book.cleanup.set(false);book.all()?;
            #[cfg(not(feature="macos-remove-observer-producer"))]
            let hashes=[descriptor_hash.as_str(),installed_hash.as_str(),installed_signature_hash.as_str(),inventory_hash.as_str(),program_hash.as_str()];
            #[cfg(feature="macos-remove-observer-producer")]
            let hashes=[descriptor_hash.as_str(),installed_hash.as_str(),installed_signature_hash.as_str(),
                inventory_hash.as_str(),program_hash.as_str(),installed_program_hash.as_str()];
            need(book.read(package,ReadRole::Package)?.0==package_hash,"signed-package-post")?;
            for ((_,role),(n,expected_hash)) in INPUTS.iter().zip(originals.into_iter().zip(hashes)) {
                need(book.read(n,*role)?.0==expected_hash,"signed-input-post")?;
            }
            let json=book.create(root,DESCRIPTOR_FILENAME,&descriptor)?;
            book.roster(root,&[("Remove.pkg",book.id(package)?.ino),(DESCRIPTOR_FILENAME,book.id(json)?.ino)])?;
            let sig=book.create(root,SIGNATURE_FILENAME,signature.as_bytes())?;
            book.roster(root,&[("Remove.pkg",book.id(package)?.ino),(DESCRIPTOR_FILENAME,book.id(json)?.ino),(SIGNATURE_FILENAME,book.id(sig)?.ino)])?;
            book.tick()?;book.pending.set(true);let persisted=native::sync(book.fd(root)?.as_fd(),false);book.pending.set(false);
            persisted.map_err(|_|"sidecar-root-persist")?;
            need(book.read(package,ReadRole::Package)?.0==package_hash,"final-package-post")?;
            for ((_,role),(n,expected_hash)) in INPUTS.iter().zip(originals.into_iter().zip(hashes)) {
                need(book.read(n,*role)?.0==expected_hash,"final-input-post")?;
            }
            // Input exact root metadata + all named/held files retained since
            // its initial complete roster; no fifth roster reservation.
            book.all()?;
            Ok((package_hash,descriptor_hash,hash(signature.as_bytes()),descriptor.len(),signature.as_bytes().len()))
        })();
        let settled=book.finish();
        let(package,descriptor,signature,descriptor_bytes,signature_bytes)=result?;need(settled,"file-finality")?;
        use std::io::Write;
        let line=format!("{{\"schemaVersion\":1,\"kind\":\"mrk-remove-producer-emitted\",\"packageSha256\":\"{package}\",\"descriptorSha256\":\"{descriptor}\",\"signatureSha256\":\"{signature}\",\"descriptorBytes\":{descriptor_bytes},\"signatureBytes\":{signature_bytes}}}\n");
        need(line.len()<=512&&Instant::now()<book.final_end,"final-report-bound")?;
        let mut stdout=std::io::stdout().lock();stdout.write_all(line.as_bytes()).map_err(|_|"final-report-write")?;
        stdout.flush().map_err(|_|"final-report-flush")?;need(Instant::now()<book.final_end,"final-report-deadline")
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn fixed_remove_inputs_rosters_and_original_finality_refuse_install_or_partial_routes() {
            let good=["--package-root","/private/tmp/task/remove",INPUT_ARGUMENT,"/private/tmp/task/input"].map(OsString::from);
            assert!(arguments(&good).is_ok());
            for values in [vec!["--package-root","/private/tmp/task/remove","--descriptor-input","/private/tmp/task/input"],
                vec!["--package-root","/private/tmp/task/remove",INPUT_ARGUMENT,"/private/tmp/task/remove/input"],
                vec!["--package-root","/private/tmp/task/input/remove",INPUT_ARGUMENT,"/private/tmp/task/input"],
                vec!["--package-root","/private/tmp/task/same",INPUT_ARGUMENT,"/private/tmp/task/same"],
                vec!["--package-root","relative",INPUT_ARGUMENT,"/private/tmp/task/input"]] {
                assert!(arguments(&values.into_iter().map(OsString::from).collect::<Vec<_>>()).is_err());
            }
            assert!(arguments(&good[..3]).is_err());
            let foreign=if cfg!(feature="macos-remove-observer-producer") {"--input-root"} else {"--observer-input-root"};
            assert!(arguments(&["--package-root","/private/tmp/task/remove",foreign,"/private/tmp/task/input"]
                .map(OsString::from)).is_err());
            assert!(program_binding_data(("a",7),("a",7),("a",7,true),false).is_ok());
            assert!(program_binding_data(("b",9),("a",7),("a",7,true),true).is_ok());
            for (own,installed,inventory,observer) in [
                (("b",9),("a",7),("a",7,true),false),
                (("a",7),("a",7),("a",7,true),true),
                (("b",9),("b",9),("a",7,true),true),
                (("b",9),("a",8),("a",7,true),true),
                (("b",9),("a",7),("a",7,false),true),
                (("b",0),("a",7),("a",7,true),true)] {
                assert_eq!(program_binding_data(own,installed,inventory,observer),Err("installed-remover-binding"));
            }
            let admitted=native_allocation_data([ProducerVerifier::project_owned_upper_bound(),
                RemovalProgramVerifier::project_owned_upper_bound(),RemovalProducerSigner::project_owned_upper_bound(),
                RemovalProducerVerifier::project_owned_upper_bound()]).unwrap();
            assert!(admitted>0&&admitted<=2*1024*1024);
            assert_eq!(native_allocation_data([Some(2*1024*1024),Some(0),Some(0),Some(0)]),Ok(2*1024*1024));
            for bounds in [[None,Some(1),Some(1),Some(1)],
                [Some(usize::MAX),Some(1),Some(0),Some(0)],
                [Some(2*1024*1024),Some(1),Some(0),Some(0)]] {
                assert_eq!(native_allocation_data(bounds),Err("remove-native-allocation-bound"));
            }
            // The production wrapper admissions are DATA; these checks do
            // not construct a Book, open an original, or call native code.
            let ordinary=[("remove-descriptor-input.json",1),("producer.json",2),("producer.sig",3),
                ("install-inventory.json",4),("mrk-macos-remove",5)];
            for n in 1..=ordinary.len() {assert!(roster_admission_data(&ordinary[..n]).is_ok());}
            assert_eq!(roster_admission_data(&[]),Err("root-roster-bound"));
            let six=[ordinary[0],ordinary[1],ordinary[2],ordinary[3],ordinary[4],("installed-mrk-macos-remove",6)];
            assert_eq!(roster_admission_data(&six),Err("root-roster-bound"));
            #[cfg(feature="macos-remove-observer-producer")]
            {
                assert!(observer_input_roster_data(&six).is_ok());
                assert_eq!(INPUTS.iter().map(|v|v.0).collect::<Vec<_>>(),six.iter().map(|v|v.0).collect::<Vec<_>>());
                for n in 0..six.len() {assert_eq!(observer_input_roster_data(&six[..n]),Err("observer-input-roster"));}
                let mut extra=six.to_vec();extra.push(("unexpected",7));
                assert_eq!(observer_input_roster_data(&extra),Err("observer-input-roster"));
                for n in 0..six.len() {
                    let mut zero=six;zero[n].1=0;
                    assert_eq!(observer_input_roster_data(&zero),Err("observer-input-roster"));
                    let mut unknown=six;unknown[n].0="unexpected";
                    assert_eq!(observer_input_roster_data(&unknown),Err("observer-input-roster"));
                    let mut duplicate=six;duplicate[n].0=six[(n+1)%six.len()].0;
                    assert_eq!(observer_input_roster_data(&duplicate),Err("observer-input-roster"));
                }
                for n in 1..six.len() {
                    let mut reordered=six;reordered.swap(n-1,n);
                    assert_eq!(observer_input_roster_data(&reordered),Err("observer-input-roster"));
                }
            }
            assert_eq!(INPUTS[..5].iter().map(|v|v.0).collect::<Vec<_>>(),
                ["remove-descriptor-input.json","producer.json","producer.sig","install-inventory.json","mrk-macos-remove"]);
            assert_eq!(INPUTS[..5].iter().map(|v|v.1.policy().0).collect::<Vec<_>>(),[16384,65536,512,1048576,67108864]);
            assert_eq!(INPUTS.len(),if cfg!(feature="macos-remove-observer-producer") {6} else {5});
            #[cfg(feature="macos-remove-observer-producer")]
            assert_eq!(INPUTS[5],("installed-mrk-macos-remove",ReadRole::Program));
            assert!(ReadRole::Package.policy().2);assert!(!ReadRole::Program.policy().1&&!ReadRole::Program.policy().2);
            assert!(INPUTS[..4].iter().all(|(_,role)|role.policy().1&&!role.policy().2));
            let count=2*(32+1)+1+INPUTS.len()+2+4;
            assert_eq!(count,if cfg!(feature="macos-remove-observer-producer") {79} else {78});
            assert!(count<=ORIGINAL_LIMIT);
            assert!(3*PACKAGE_LIMIT+6*ReadRole::Program.policy().0+3*(16384+65536+512+1048576)
                +2*(16384+512)+128<READ_LIMIT);
            assert!(3*PACKAGE_LIMIT+3*ReadRole::Program.policy().0+3*(16384+65536+512+1048576)+2*(16384+512)+64<READ_LIMIT);
            assert!(final_ready_data(false,false,true,&[State::Closed,State::Absent]));
            for state in [State::Reserved,State::Acquiring,State::Owned,State::Closing,State::Unknown] {
                assert!(!final_ready_data(false,false,true,&[state]));
            }
            for (unknown,pending,within) in [(true,false,true),(false,true,true),(false,false,false)] {
                assert!(!final_ready_data(unknown,pending,within,&[State::Closed,State::Absent]));
            }
        }
    }
}
fn main()->std::process::ExitCode {
    #[cfg(all(feature="macos-remove-producer",target_os="macos",target_pointer_width="64",
        any(target_arch="aarch64",target_arch="x86_64")))]
    {match emitter::run() {Ok(())=>std::process::ExitCode::SUCCESS,Err(_)=>{
        eprintln!("remove-producer-refused");std::process::ExitCode::from(78)}}}
    #[cfg(not(all(feature="macos-remove-producer",target_os="macos",target_pointer_width="64",
        any(target_arch="aarch64",target_arch="x86_64"))))]
    {eprintln!("remove-producer-unavailable");std::process::ExitCode::from(78)}
}
