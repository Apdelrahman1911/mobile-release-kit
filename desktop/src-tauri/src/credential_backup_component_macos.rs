//! Opt-in native BACKEND component fixture, not Desktop/picker qualification.
//!
//! Uses the real backup child, crypto, APFS SourceBook, pair sink and StoreBook.
//! No GuiFacts, SelectedPair, Keychain candidate or worker join is fabricated.
//! The reviewed caller supplies one fresh empty private APFS directory and
//! cleans only that directory after the exact test process has joined.
use super::*;
#[path = "credential_apple_key_component_macos.rs"]
mod apple_key;
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::Weak,
};
use zeroize::Zeroizing;

const ALLOWANCE: usize = format::WORKING_BYTES;
const CODE_LENGTH: usize = b"mrk-recovery-v1-".len() + 64;
// Conservative fixture/control reserve, not process RSS or production consent.
const FIXTURE_CONTROL: usize = 2 * 1024 * 1024;

struct Vault {
    store: Arc<Mutex<store::StoreBook>>,
    key: Arc<crypto::VaultKey>,
    header: [u8; format::HEADER_BYTES],
}

fn empty_directory(parent: &Path, name: &str) -> Result<PathBuf, Reason> {
    let path = parent.join(name);
    DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| Reason::SourceRefused)?;
    Ok(path)
}

fn fixture_root() -> Result<PathBuf, Reason> {
    let root = std::env::var_os("MRK_MACOS_VAULT_FIXTURE_ROOT")
        .map(PathBuf::from)
        .ok_or(Reason::InvalidRequest)?;
    let stat = fs::symlink_metadata(&root).map_err(|_| Reason::SourceRefused)?;
    if !root.is_absolute()
        || !stat.is_dir()
        || stat.file_type().is_symlink()
        || nix::unistd::geteuid().is_root()
        || stat.uid() != nix::unistd::geteuid().as_raw()
        || stat.mode() & 0o7777 != 0o700
        || fs::read_dir(&root)
            .map_err(|_| Reason::SourceRefused)?
            .next()
            .is_some()
    {
        return Err(Reason::SourceRefused);
    }
    Ok(root)
}

fn new_owner(vault: &Vault, id: u32) -> Arc<OriginalWork> {
    // Normal finite10s/2s owner. No endpoint reset or invented native receipts.
    let owner = OriginalWork::new(id, false, Weak::new());
    let mut work = owner.vault.lock().unwrap();
    work.store = Some(vault.store.clone());
    work.key = Some(vault.key.clone());
    drop(work);
    owner
}

fn initialize(parent: &Path, id: u32) -> Result<Vault, Reason> {
    let original = OriginalWork::new(id, false, Weak::new());
    let identity = crypto::new_identity().map_err(crypto_problem)?;
    let (header, key) = crypto::backup_component_key(identity).map_err(crypto_problem)?;
    let mut book = store::StoreBook::new();
    let application = parent.join("dev.mobile-release-kit.desktop");
    let observation = book
        .inspect(
            store::Location::application_data(&application).map_err(problem)?,
            &mut || original.interrupted(),
        )
        .map_err(problem)?;
    if observation.state != store::Inspection::Uninitialized || observation.root.is_some() {
        return Err(Reason::SourceRefused);
    }
    let absent = asset_source::probe_vault_exclusion(
        &mut original.source.lock().unwrap(),
        None,
        &[],
        &mut || original.interrupted(),
    )?;
    book.prepare_initialize(identity, &absent, &mut || original.interrupted())
        .map_err(problem)?;
    if book
        .reserve_prepared_identity(&mut || original.interrupted())
        .map_err(problem)?
        != identity
    {
        return Err(Reason::SourceChanged);
    }
    book.publish_header(&header, &mut || original.interrupted())
        .map_err(problem)?;
    book.recheck_root(&mut || original.interrupted())
        .map_err(problem)?;
    if !original.source.lock().unwrap().settled() {
        return Err(Reason::CleanupUnknown);
    }
    Ok(Vault {
        store: Arc::new(Mutex::new(book)),
        key: Arc::new(key),
        header,
    })
}

fn material() -> (format::Descriptor, Fields, Vec<u8>) {
    let fields = commands::own_fields(
        Kind::AndroidKeystore,
        &serde_json::json!({
            "storePassword":"synthetic-backup-store", "keyAlias":"synthetic-upload",
            "keyPassword":"synthetic-backup-key"
        }),
    )
    .ok()
    .unwrap();
    let descriptor = format::Descriptor::new(
        Kind::AndroidKeystore,
        Some("Synthetic backup component only".into()),
        vec![true; 3],
        true,
    )
    .unwrap();
    // Header-observed synthetic bytes, NOT a generated/signing-capable JKS.
    // This component proves byte-preserving backup, not keytool/Store signing.
    let mut bytes = Vec::from(0xfeed_feedu32.to_be_bytes());
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(b"MRK synthetic backup body; no signing key");
    (descriptor, fields, bytes)
}

fn same_material(actual: &crypto::AuthenticatedRecord) -> bool {
    let (descriptor, fields, bytes) = material();
    actual.descriptor.kind == descriptor.kind
        && actual.descriptor.label == descriptor.label
        && actual.descriptor.presence() == descriptor.presence()
        && actual.descriptor.has_file()
        && commands::field_names(Kind::AndroidKeystore)
            .iter()
            .all(|name| actual.fields.borrow_value(name) == fields.borrow_value(name))
        && actual
            .file
            .as_ref()
            .is_some_and(|file| file.bytes() == bytes.as_slice())
}

fn seed(vault: &Vault) -> Result<StoredRef, Reason> {
    let owner = new_owner(vault, 2);
    let record = vault.key.new_record_id(&[]).map_err(crypto_problem)?;
    let (descriptor, fields, file) = material();
    let candidate = vault
        .key
        .seal_record(record, None, &descriptor, &fields, Some(&file), ALLOWANCE)
        .map_err(crypto_problem)?;
    let revision = candidate.revision();
    let intent = vault
        .key
        .seal_intent(format::Mutation::New, record, None, Some(&candidate))
        .map_err(crypto_problem)?;
    let mut book = vault.store.lock().unwrap();
    let outcome = book
        .mutate(
            &intent,
            Some(candidate.bytes()),
            None,
            &mut || owner.interrupted(),
            &mut || cleanup_expired(&owner),
        )
        .map_err(problem)?;
    if outcome
        != (store::StorageOutcome {
            effect: store::Effect::KnownApplied,
            durability: store::Durability::Confirmed,
            cleanup: store::Cleanup::Known,
        })
    {
        return Err(Reason::VaultDurabilityUnknown);
    }
    drop(candidate);
    let (bytes, witness, complete) = book
        .read_record(record, true, &mut || owner.interrupted())
        .map_err(problem)?
        .into_parts();
    let opened = vault
        .key
        .open_record(bytes, ALLOWANCE)
        .map_err(crypto_problem)?;
    if !complete
        || opened.record != record
        || opened.revision != revision
        || !same_material(&opened)
    {
        return Err(Reason::VaultCorrupt);
    }
    book.recheck_record(&witness, &mut || owner.interrupted())
        .map_err(problem)?;
    Ok(StoredRef {
        identity: vault.key.identity(),
        record,
        revision,
        original: witness,
    })
}

fn retain(
    owner: &Arc<OriginalWork>,
    content: Content,
    kind: RequestKind,
) -> Result<Request, Reason> {
    let custody = Custody {
        owner_id: owner.id,
        content,
        phase: Phase::Reserved,
        first: None,
        saved: None,
        outcome: None,
    };
    let original = Arc::new(Mutex::new(custody));
    let mut work = owner.vault.lock().unwrap();
    if !work.backup.empty() {
        return Err(Reason::Busy);
    }
    let key = work.key.as_ref().ok_or(Reason::VaultKeyMissing)?;
    let identity = key.identity();
    let book = work
        .store
        .as_ref()
        .ok_or(Reason::VaultCorrupt)?
        .lock()
        .unwrap();
    let live = std::mem::size_of::<OriginalWork>()
        .checked_add(FIXTURE_CONTROL)
        .and_then(|n| n.checked_add(key.retained_bytes()))
        .and_then(|n| book.retained_bytes().and_then(|bytes| n.checked_add(bytes)))
        .and_then(|n| {
            original
                .lock()
                .ok()?
                .retained_bytes()
                .and_then(|bytes| n.checked_add(bytes))
        })
        .ok_or(Reason::Capacity)?;
    drop(book);
    let budget = Budget::from_live(live, 0)?;
    work.backup.inner = Some(original);
    if kind == RequestKind::ImportNew {
        work.outcome = Some(store::StorageOutcome {
            effect: store::Effect::NotStarted,
            durability: store::Durability::NotRun,
            cleanup: store::Cleanup::Pending,
        });
    }
    Ok(Request {
        owner_id: owner.id,
        identity,
        roster: ProjectRoster {
            generation: 1,
            roots: Vec::new(),
        },
        budget,
        kind,
    })
}

fn only_file(parent: &Path, suffix: &str) -> Result<PathBuf, Reason> {
    let mut entries = fs::read_dir(parent).map_err(|_| Reason::SourceRefused)?;
    let entry = entries
        .next()
        .ok_or(Reason::SourceRefused)?
        .map_err(|_| Reason::SourceRefused)?;
    if entries.next().is_some()
        || !entry
            .file_type()
            .map_err(|_| Reason::SourceRefused)?
            .is_file()
        || !entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.ends_with(suffix))
    {
        return Err(Reason::SourceChanged);
    }
    Ok(entry.path())
}

fn export(
    vault: &Vault,
    reference: StoredRef,
    folders: [PathBuf; 2],
    fault: bool,
) -> Result<(Arc<OriginalWork>, Result<ChildResult, Reason>), Reason> {
    let owner = new_owner(vault, if fault { 8 } else { 3 });
    // Normal production selection remains denied for this component owner.
    assert!(asset_source::BackupDestinations::new(&owner, folders.clone()).is_err());
    let mut destination = asset_source::BackupDestinations::new_component_fixture(&owner, folders)?;
    if fault {
        destination.component_stop_after_code_and_lose_close()?;
    }
    let request = retain(
        &owner,
        Content::Export {
            reference,
            output: None,
            destination: Some(destination),
        },
        RequestKind::Export,
    )?;
    assert!(child_admitted(&owner, &request));
    let result = super::super::execute(&owner, Child::Backup(request));
    // No fabricated coordinator/child returned receipt makes this delivered.
    assert!(!retirement_ready(&owner));
    Ok((owner, result))
}

fn restore(
    vault: &Vault,
    paths: [PathBuf; 2],
    id: u32,
) -> Result<(Arc<OriginalWork>, format::Id, Result<ChildResult, Reason>), Reason> {
    let owner = new_owner(vault, id);
    let record = vault.key.new_record_id(&[]).map_err(crypto_problem)?;
    let sources = asset_source::BackupSources::new(paths)?;
    let request = retain(
        &owner,
        Content::ImportNew {
            identity: vault.key.identity(),
            record,
            sources,
        },
        RequestKind::ImportNew,
    )?;
    assert!(child_admitted(&owner, &request));
    let result = super::super::execute(&owner, Child::Backup(request));
    Ok((owner, record, result))
}

fn wrong_code(source: &Path, parent: &Path) -> Result<PathBuf, Reason> {
    let mut code = Zeroizing::new([0u8; CODE_LENGTH]);
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(source)
        .map_err(|_| Reason::SourceRefused)?;
    input
        .read_exact(&mut code[..])
        .map_err(|_| Reason::SourceRefused)?;
    let mut eof = [0u8; 1];
    if input.read(&mut eof).map_err(|_| Reason::SourceRefused)? != 0 {
        return Err(Reason::SourceChanged);
    }
    let input: OwnedFd = input.into();
    nix::unistd::close(input).map_err(|_| Reason::CleanupUnknown)?;
    let last = code.len() - 1;
    code[last] = if code[last] == b'a' { b'b' } else { b'a' }; // Always different, still valid grammar.
    let path = parent.join("wrong-code.mrkcode");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| Reason::SourceRefused)?;
    output
        .write_all(&code[..])
        .map_err(|_| Reason::SourceRefused)?;
    mrk_macos_installed_native::sync(output.as_fd(), true)
        .map_err(|_| Reason::VaultDurabilityUnknown)?;
    let output: OwnedFd = output.into();
    nix::unistd::close(output).map_err(|_| Reason::CleanupUnknown)?;
    Ok(path)
}

fn release(vault: &Vault, id: u32) -> bool {
    let owner = new_owner(vault, id);
    matches!(
        super::super::execute(&owner, Child::Release),
        Ok(ChildResult::Released)
    ) && vault.store.lock().unwrap().settled()
}

#[test]
#[ignore = "requires explicit fresh private macOS APFS component fixture; no picker qualification"]
fn native_apfs_backup_roundtrip_wrong_code_and_lost_close_receipt() {
    let root = fixture_root().expect("explicit empty private fixture required");
    let source = initialize(&empty_directory(&root, "source").unwrap(), 1).unwrap();
    let restored = initialize(&empty_directory(&root, "restored").unwrap(), 4).unwrap();
    let refused = initialize(&empty_directory(&root, "refused").unwrap(), 6).unwrap();
    let mut uncertain_original = None;
    let result = (|| -> Result<(), Reason> {
        let reference = seed(&source)?;
        let folders = [
            empty_directory(&root, "backup")?,
            empty_directory(&root, "recovery")?,
        ];
        let (exported, result) = export(&source, reference, folders.clone(), false)?;
        assert!(matches!(result, Ok(ChildResult::BackupPublished)));
        {
            let work = exported.vault.lock().unwrap();
            let custody = work.backup.inner.as_ref().unwrap().lock().unwrap();
            let Content::Export {
                output: Some(_),
                destination: Some(destination),
                ..
            } = &custody.content
            else {
                return Err(Reason::CleanupUnknown);
            };
            assert!(custody.phase == Phase::ExportCandidate && custody.first.is_none());
            assert!(destination.candidate_ready(&exported) && destination.native_settled());
            assert_eq!(
                destination.component_close_observation(),
                ([1, 1], [true, true], true)
            );
        }
        let paths = [
            only_file(&folders[0], ".mrkbackup")?,
            only_file(&folders[1], ".mrkcode")?,
        ];
        let (imported, record, result) = restore(&restored, paths.clone(), 5)?;
        let Ok(ChildResult::Mutated {
            record: reported,
            row: Some(row),
        }) = result
        else {
            return Err(Reason::VaultCorrupt);
        };
        assert!(reported == record && record != reference.record);
        assert!(
            restored.key.identity() != reference.identity
                && row.authenticated.revision.counter == 1
                && row.authenticated.revision.random != reference.revision.random
        );
        {
            let work = imported.vault.lock().unwrap();
            assert!(new_publication(
                &work.backup,
                restored.key.identity(),
                record,
                &row
            ));
            let mut book = restored.store.lock().unwrap();
            let (bytes, witness, complete) = book
                .read_record(record, true, &mut || imported.interrupted())
                .map_err(problem)?
                .into_parts();
            assert!(complete && witness == row.original);
            let opened = restored
                .key
                .open_record(bytes, ALLOWANCE)
                .map_err(crypto_problem)?;
            assert!(same_material(&opened));
            let custody = work.backup.inner.as_ref().unwrap().lock().unwrap();
            let Content::ImportNew { sources, .. } = &custody.content else {
                return Err(Reason::VaultCorrupt);
            };
            assert!(sources.matches_authenticated_readback(&opened) && sources.native_settled());
        }
        source
            .store
            .lock()
            .unwrap()
            .recheck_record(&reference.original, &mut || false)
            .map_err(problem)?;
        let wrong_folder = empty_directory(&root, "wrong-code")?;
        let wrong = wrong_code(&paths[1], &wrong_folder)?;
        let (bad, _, result) = restore(&refused, [paths[0].clone(), wrong], 7)?;
        assert!(matches!(result, Err(Reason::SourceRefused)));
        {
            let work = bad.vault.lock().unwrap();
            let custody = work.backup.inner.as_ref().unwrap().lock().unwrap();
            assert!(
                custody.phase == Phase::Failed
                    && custody.saved.is_none()
                    && custody.outcome.is_none()
            );
            assert!(custody.native_settled());
            assert!(refused.store.lock().unwrap().storage_outcome().is_none());
            assert!(
                work.outcome
                    == Some(store::StorageOutcome {
                        effect: store::Effect::NotStarted,
                        durability: store::Durability::NotRun,
                        cleanup: store::Cleanup::Pending
                    })
            );
        }
        assert!(only_file(&folders[0], ".mrkbackup")? == paths[0]);
        assert!(only_file(&folders[1], ".mrkcode")? == paths[1]);
        let partial = [
            empty_directory(&root, "partial-backup")?,
            empty_directory(&root, "partial-code")?,
        ];
        let (original, result) = export(&source, reference, partial.clone(), true)?;
        uncertain_original = Some(original.clone()); // Held even if a later assertion fails.
        assert!(matches!(result, Err(Reason::CleanupUnknown)));
        {
            let work = original.vault.lock().unwrap();
            assert!(work.backup.blocks_reuse() && work.backup.recovery_required());
            let custody = work.backup.inner.as_ref().unwrap().lock().unwrap();
            let Content::Export {
                output: Some(_),
                destination: Some(destination),
                ..
            } = &custody.content
            else {
                return Err(Reason::CleanupUnknown);
            };
            assert!(custody.phase == Phase::Failed && custody.first.is_some());
            assert!(
                !destination.candidate_ready(&original)
                    && !destination.native_settled()
                    && !destination.disposal_ready()
            );
            // Actual close calls returned, but one receipt was deliberately
            // hidden from production state. All independent closes still ran.
            assert_eq!(
                destination.component_close_observation(),
                ([1, 1], [true, true], true)
            );
        }
        assert!(!retirement_ready(&original));
        only_file(&partial[1], ".mrkcode")?;
        only_file(&partial[0], ".mrkbackup.pending")?;
        source
            .store
            .lock()
            .unwrap()
            .recheck_record(&reference.original, &mut || false)
            .map_err(problem)?;
        Ok(())
    })();
    // These are real independent Store closes, not a rewrite of the sink's
    // Unknown receipt or Desktop private-disposal/join facts.
    let closed = [
        release(&source, 9),
        release(&restored, 10),
        release(&refused, 11),
    ];
    if let Some(original) = uncertain_original {
        // One bounded test-only uncertain holding survives until this isolated
        // process exits. Do not force-release it or fake a successful retry.
        std::mem::forget(original);
    }
    assert!(
        closed.into_iter().all(|closed| closed),
        "actual component Store close failed"
    );
    assert!(
        result.is_ok(),
        "native backup component failed: {:?}",
        result.err()
    );
    // No fixture files are removed here. Caller cleanup follows process join.
}
