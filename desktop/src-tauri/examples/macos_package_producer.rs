//! One nonshipping synchronous packaging child, not a process supervisor.
//! Its parent owns command admission/finality and MUST keep the directory
//! private unless this original child returns0 with the complete final record.
//! Sidecars are outside their own hashed package. No installer authority here.
#![forbid(unsafe_code)]
#[cfg(all(feature="macos-package-producer",target_os="macos",target_pointer_width="64",
    any(target_arch="aarch64",target_arch="x86_64")))]
#[path="macos_producer_common/mod.rs"]
mod common;

#[cfg(all(feature="macos-package-producer",target_os="macos",target_pointer_width="64",
    any(target_arch="aarch64",target_arch="x86_64")))]
mod emitter {
    use std::{ffi::OsString,os::fd::AsFd,path::{Path,PathBuf},time::Instant};
    use super::common::*;
    use mobile_release_desktop::{macos_install_paths as paths,
        macos_install_producer::{ProducerData,EmissionBindingData,DESCRIPTOR_FILENAME,SIGNATURE_FILENAME,DESCRIPTOR_LIMIT}};
    use mrk_macos_installed_native::{self as native,
        install_producer::{self,PackageProducerSigner,PackageSignResult,ProducerVerifier,SignatureResult}};

    fn arguments(args:&[OsString])->Result<(PathBuf,PathBuf)> {
        need(args.len()==4&&args[0]=="--package-root"&&args[2]=="--descriptor-input","arguments")?;
        let root=PathBuf::from(&args[1]);let input=PathBuf::from(&args[3]);
        components(&root)?;components(&input)?;
        need(!input.starts_with(&root),"descriptor-outside-package-root")?;Ok((root,input))
    }
    // This synchronous child never adopts or deletes a partially emitted root.
    // ManuallyDrop retains uncertain originals; process exit is not a pass.
    pub fn run()->Result<()> {
        let start=Instant::now();let args:Vec<_>=std::env::args_os().skip(1).take(5).collect();let(root_path,input_path)=arguments(&args)?;
        let mut book=Book::new(start)?;
        let result=(||->Result<(String,String,String,usize,usize)> {
            book.tick()?;book.pending.set(true);let platform=native::platform();book.pending.set(false);platform.map_err(|_|"platform")?;
            book.tick()?;book.pending.set(true);let source=install_producer::source_signer_data();book.pending.set(false);
            let source=source.ok_or("source-signer-unavailable")?;book.tick()?;
            let root=book.parents(&root_path,true)?;book.private_root(root)?;
            let package=book.open(Some(root),"Install.pkg",false,true)?;book.file_policy(package,PACKAGE_LIMIT)?;
            book.roster(root,&[("Install.pkg",book.id(package)?.ino)])?;
            let parent=book.parents(&input_path,false)?;
            let input_name=input_path.file_name().and_then(|v|v.to_str()).ok_or("descriptor-name")?;
            let input=book.open(Some(parent),input_name,false,true)?;book.file_policy(input,DESCRIPTOR_LIMIT as u64)?;
            let (package_hash,_)=book.read(package,ReadRole::Package)?;let(descriptor_hash,descriptor)=book.read(input,ReadRole::InstallDescriptor)?;
            let data=ProducerData::parse_data(&descriptor,target()).map_err(|_|"descriptor-data")?;
            let expected=EmissionBindingData{target:target(),release:paths::RELEASE,package_version:paths::PACKAGE_VERSION,
                source_commit:option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT").ok_or("source-current-unavailable")?,
                protocol_sha256:paths::PROTOCOL_SHA,
                runtime_manifest_sha256:option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256").ok_or("source-runtime-unavailable")?,
                inventory_sha256:option_env!("MRK_MACOS_INSTALL_INVENTORY_SHA256").ok_or("source-inventory-unavailable")?,
                completed_package_sha256:&package_hash,team:source.team_data(),leaf_sha1:source.leaf_sha1_data(),leaf_sha256:source.leaf_sha256_data()};
            data.validate_emission_data(&expected).map_err(|_|"emission-binding")?;
            let mut signer=PackageProducerSigner::new();
            let signed=signer.sign_and_close(&descriptor,&mut |point|book.native_point(point));
            if !signer.settled() {book.unknown.set(true);return Err("signer-finality");}
            let PackageSignResult::SignatureCreated(signature)=signed else {return Err("signature-not-created");};
            let mut verifier=ProducerVerifier::new();
            let verified=verifier.verify_and_close(&descriptor,signature.as_bytes(),&mut |point|book.native_point(point));
            if !verifier.settled() {book.unknown.set(true);return Err("verification-finality");}
            need(verified==SignatureResult::SignatureVerified,"signature-verification")?;
            book.cleanup.set(false);book.all()?;
            need(book.read(package,ReadRole::Package)?.0==package_hash&&book.read(input,ReadRole::InstallDescriptor)?==(descriptor_hash.clone(),descriptor.clone()),"signed-input-post")?;
            let json=book.create(root,DESCRIPTOR_FILENAME,&descriptor)?;
            book.roster(root,&[("Install.pkg",book.id(package)?.ino),(DESCRIPTOR_FILENAME,book.id(json)?.ino)])?;
            let sig=book.create(root,SIGNATURE_FILENAME,signature.as_bytes())?;
            book.roster(root,&[("Install.pkg",book.id(package)?.ino),(DESCRIPTOR_FILENAME,book.id(json)?.ino),(SIGNATURE_FILENAME,book.id(sig)?.ino)])?;
            book.tick()?;book.pending.set(true);let persisted=native::sync(book.fd(root)?.as_fd(),false);book.pending.set(false);
            persisted.map_err(|_|"sidecar-root-persist")?;
            need(book.read(package,ReadRole::Package)?.0==package_hash&&book.read(input,ReadRole::InstallDescriptor)?==(descriptor_hash.clone(),descriptor.clone()),"final-input-post")?;
            book.all()?;
            Ok((package_hash,descriptor_hash,hash(signature.as_bytes()),descriptor.len(),signature.as_bytes().len()))
        })();
        let settled=book.finish();
        let(package,descriptor,signature,descriptor_bytes,signature_bytes)=result?;need(settled,"file-finality")?;
        // Only bounded public digests/lengths, emitted after actual consuming
        // native/file closes. The parent still must observe original child0.
        use std::io::Write;
        let line=format!("{{\"schemaVersion\":1,\"kind\":\"mrk-package-producer-emitted\",\"packageSha256\":\"{package}\",\"descriptorSha256\":\"{descriptor}\",\"signatureSha256\":\"{signature}\",\"descriptorBytes\":{descriptor_bytes},\"signatureBytes\":{signature_bytes}}}\n");
        need(line.len()<=512&&Instant::now()<book.final_end,"final-report-bound")?;
        let mut stdout=std::io::stdout().lock();stdout.write_all(line.as_bytes()).map_err(|_|"final-report-write")?;
        stdout.flush().map_err(|_|"final-report-flush")?;need(Instant::now()<book.final_end,"final-report-deadline")
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn fixed_cli_and_original_state_data_refuse_ambient_or_partial_routes() {
            let good=["--package-root","/private/tmp/task/final","--descriptor-input","/private/tmp/task/descriptor-input.json"].map(OsString::from);
            assert!(arguments(&good).is_ok());
            for path in ["relative","/","/a/../b","/a//b","/a/./b","/a/","/a\0b"] {assert!(components(Path::new(path)).is_err());}
            assert!(components(Path::new(&format!("/{}","a/".repeat(33)))).is_err());
            for index in [0,2] {let mut bad=good.clone();bad[index]=OsString::from("--identity");assert!(arguments(&bad).is_err());}
            let mut inside=good.clone();inside[3]=OsString::from("/private/tmp/task/final/producer.json");assert!(arguments(&inside).is_err());
            assert!(arguments(&good[..3]).is_err());
            assert!(final_ready_data(false,false,true,&[]));
            assert!(final_ready_data(false,false,true,&[State::Closed,State::Absent]));
            for state in [State::Reserved,State::Acquiring,State::Owned,State::Closing,State::Unknown] {
                assert!(!final_ready_data(false,false,true,&[State::Closed,state]));
            }
            // Fixed Original states, no actual file, Keychain or process calls.
            for (unknown,pending,within) in [(true,false,true),(false,true,true),(false,false,false)] {
                assert!(!final_ready_data(unknown,pending,within,&[State::Closed,State::Absent]));
            }
        }
    }
}

fn main()->std::process::ExitCode {
    #[cfg(all(feature="macos-package-producer",target_os="macos",target_pointer_width="64",
        any(target_arch="aarch64",target_arch="x86_64")))]
    {match emitter::run() {Ok(())=>std::process::ExitCode::SUCCESS,Err(_)=>{
        eprintln!("package-producer-refused");std::process::ExitCode::from(78)}}}
    #[cfg(not(all(feature="macos-package-producer",target_os="macos",target_pointer_width="64",
        any(target_arch="aarch64",target_arch="x86_64"))))]
    {eprintln!("package-producer-unavailable");std::process::ExitCode::from(78)}
}
