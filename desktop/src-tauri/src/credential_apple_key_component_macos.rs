//! Opt-in Apple-key BACKEND component, not a normal provisioning observation.
//!
//! The existing finite native-component caller supplies exactly three private
//! directories: generated/ (one production-helper private frame), native/ and
//! reopened/ (both empty). Only after THIS test exits successfully may it run
//! the shipped verifier on reopened/pending-apple-key.mrk. Generator/verifier
//! output is private fixture material, NEVER a diagnostic log or artifact.
//!
//! This exercises shared AEAD and real APFS NEW/lock/read/close with a fresh
//! component wrapping key. It makes no ASC Review, SavedSession, keySaved ACK,
//! NativeUse, Keychain, GUI, cancellation, installed-app or quit claim. The
//! fixture was generated before this test; it cannot prove production's
//! reserve-before-generation ordering. No process/task or new owner is added.
use super::*;
use commands::{AppleDistributionKeyFields, APPLE_KEY_PRIVATE_FRAME_LIMIT};
use der_07::pem::Base64Decoder;
use std::{
    fs::File,
    time::{Duration, Instant},
};

const FRAME_NAME: &str = "pending-apple-key.mrk";
const MAGIC: &[u8] = b"MRK-APPLE-DISTRIBUTION-KEY/1\n";
const KEY_ALLOWANCE: usize = crypto::APPLE_KEY_CRYPTO_BYTES;
type Directory = (u64, u64, u32, u32, u32);
type FileState = (Directory, u64, u64, i64, i64, i64, i64);

fn need(value: bool) -> Result<(), Reason> {
    if value {
        Ok(())
    } else {
        Err(Reason::SourceRefused)
    }
}
fn timely(end: Instant) -> Result<(), Reason> {
    need(Instant::now() < end)
}
fn directory(info: &fs::Metadata) -> Result<Directory, Reason> {
    need(
        info.is_dir()
            && info.uid() == nix::unistd::geteuid().as_raw()
            && info.uid() != 0
            && info.mode() & 0o7777 == 0o700,
    )?;
    Ok((info.dev(), info.ino(), info.mode(), info.uid(), info.gid()))
}
fn file_state(info: &fs::Metadata) -> Result<FileState, Reason> {
    need(
        info.is_file()
            && info.uid() == nix::unistd::geteuid().as_raw()
            && info.uid() != 0
            && info.mode() & 0o7777 == 0o600
            && info.nlink() == 1,
    )?;
    Ok((
        (info.dev(), info.ino(), info.mode(), info.uid(), info.gid()),
        info.nlink(),
        info.len(),
        info.mtime(),
        info.mtime_nsec(),
        info.ctime(),
        info.ctime_nsec(),
    ))
}
fn names(path: &Path, expected: &[&str]) -> Result<(), Reason> {
    let mut actual = Vec::new();
    for entry in fs::read_dir(path).map_err(|_| Reason::SourceRefused)? {
        need(actual.len() < expected.len())?;
        actual.push(entry.map_err(|_| Reason::SourceRefused)?.file_name());
    }
    actual.sort();
    let mut expected: Vec<_> = expected
        .iter()
        .map(|name| std::ffi::OsString::from(*name))
        .collect();
    expected.sort();
    need(actual == expected)
}

// Four fixed fixture directory handles only. Actual vault originals remain
// exclusively in the existing StoreBook; these handles cannot settle it.
struct Fixture {
    path: PathBuf,
    held: [File; 4],
    ids: [Directory; 4],
}
impl Fixture {
    fn open() -> Result<Self, Reason> {
        let path = std::env::var_os("MRK_MACOS_VAULT_FIXTURE_ROOT")
            .map(PathBuf::from)
            .ok_or(Reason::InvalidRequest)?;
        need(path.is_absolute() && path != Path::new("/"))?;
        let flags = nix::fcntl::OFlag::O_RDONLY
            | nix::fcntl::OFlag::O_NOFOLLOW
            | nix::fcntl::OFlag::O_DIRECTORY
            | nix::fcntl::OFlag::O_CLOEXEC;
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(flags.bits())
            .open(&path)
            .map_err(|_| Reason::SourceRefused)?;
        let child = |name: &str| -> Result<File, Reason> {
            nix::fcntl::openat(root.as_fd(), name, flags, nix::sys::stat::Mode::empty())
                .map(File::from)
                .map_err(|_| Reason::SourceRefused)
        };
        let generated = child("generated")?;
        let native = child("native")?;
        let reopened = child("reopened")?;
        let held = [root, generated, native, reopened];
        let mut ids = [(0, 0, 0, 0, 0); 4];
        for (index, file) in held.iter().enumerate() {
            ids[index] = directory(&file.metadata().map_err(|_| Reason::SourceRefused)?)?;
        }
        let fixture = Self { path, held, ids };
        fixture.current()?;
        names(&fixture.path.join("generated"), &[FRAME_NAME])?;
        names(&fixture.path.join("native"), &[])?;
        names(&fixture.path.join("reopened"), &[])?;
        Ok(fixture)
    }
    fn current(&self) -> Result<(), Reason> {
        for (index, name) in ["", "generated", "native", "reopened"].iter().enumerate() {
            need(
                directory(
                    &self.held[index]
                        .metadata()
                        .map_err(|_| Reason::SourceRefused)?,
                )? == self.ids[index]
                    && directory(
                        &fs::symlink_metadata(self.path.join(name))
                            .map_err(|_| Reason::SourceRefused)?,
                    )? == self.ids[index],
            )?;
        }
        names(&self.path, &["generated", "native", "reopened"])
    }
    fn close(self) -> bool {
        // All independent closes run; failure is not a successful retirement.
        let mut closed = true;
        for file in self.held.into_iter().rev() {
            let fd: OwnedFd = file.into();
            closed &= nix::unistd::close(fd).is_ok();
        }
        closed
    }
}
struct Input {
    original: Option<File>,
    state: FileState,
    bytes: Zeroizing<Vec<u8>>,
}
impl Input {
    fn read(fixture: &Fixture) -> Result<Self, Reason> {
        let fd = nix::fcntl::openat(
            fixture.held[1].as_fd(),
            FRAME_NAME,
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|_| Reason::SourceRefused)?;
        let mut file = File::from(fd);
        let state = file_state(&file.metadata().map_err(|_| Reason::SourceRefused)?)?;
        let length = usize::try_from(state.2).map_err(|_| Reason::SourceRefused)?;
        need((MAGIC.len() + 13..=APPLE_KEY_PRIVATE_FRAME_LIMIT).contains(&length))?;
        // Size is checked BEFORE reservation/resize/read, never after a generic
        // unbounded reader. No file/user input chooses a larger limit.
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Reason::SourceRefused)?;
        need(bytes.capacity() <= APPLE_KEY_PRIVATE_FRAME_LIMIT)?;
        bytes.resize(length, 0);
        file.read_exact(&mut bytes)
            .map_err(|_| Reason::SourceRefused)?;
        let mut eof = [0; 1];
        need(file.read(&mut eof).map_err(|_| Reason::SourceRefused)? == 0)?;
        let result = Self {
            original: Some(file),
            state,
            bytes,
        };
        result.current(fixture)?;
        Ok(result)
    }
    fn current(&self, fixture: &Fixture) -> Result<(), Reason> {
        fixture.current()?;
        let file = self.original.as_ref().ok_or(Reason::CleanupUnknown)?;
        need(
            file_state(&file.metadata().map_err(|_| Reason::SourceRefused)?)? == self.state
                && file_state(
                    &fs::symlink_metadata(fixture.path.join("generated").join(FRAME_NAME))
                        .map_err(|_| Reason::SourceRefused)?,
                )? == self.state,
        )
    }
    fn close(&mut self) -> bool {
        let Some(file) = self.original.take() else {
            return false;
        };
        let fd: OwnedFd = file.into();
        nix::unistd::close(fd).is_ok()
    }
}

fn decoded(value: &str, limit: usize) -> Result<Zeroizing<Vec<u8>>, Reason> {
    let mut decoder = Base64Decoder::new(value.as_bytes()).map_err(|_| Reason::VaultCorrupt)?;
    let length = decoder.remaining_len();
    need(length > 0 && length <= limit)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Reason::SourceRefused)?;
    need(bytes.capacity() <= limit)?;
    bytes.resize(length, 0);
    decoder
        .decode(&mut bytes)
        .map_err(|_| Reason::VaultCorrupt)?;
    need(decoder.is_finished())?;
    Ok(bytes)
}
fn restored_frame(record: &crypto::AuthenticatedRecord) -> Result<Zeroizing<Vec<u8>>, Reason> {
    // Test-only reconstruction from the FRESH authenticated record, never the
    // generated input/old opened record. No production private getter is added.
    let get = |name| record.fields.borrow_value(name).ok_or(Reason::VaultCorrupt);
    let key = decoded(get("privateKeyPkcs8Base64")?, 3 * 1024)?;
    let csr = get("csrPem")?.as_bytes();
    let spki = decoded(get("publicKeySpkiBase64")?, 1024)?;
    need(!csr.is_empty() && csr.len() <= 4096)?;
    let length = MAGIC.len() + 12 + key.len() + csr.len() + spki.len();
    need(length <= APPLE_KEY_PRIVATE_FRAME_LIMIT)?;
    let mut frame = Zeroizing::new(Vec::new());
    frame
        .try_reserve_exact(length)
        .map_err(|_| Reason::SourceRefused)?;
    need(frame.capacity() <= APPLE_KEY_PRIVATE_FRAME_LIMIT)?;
    frame.extend_from_slice(MAGIC);
    for length in [key.len(), csr.len(), spki.len()] {
        frame.extend_from_slice(&(length as u32).to_be_bytes());
    }
    for part in [&key[..], csr, &spki[..]] {
        frame.extend_from_slice(part);
    }
    need(
        AppleDistributionKeyFields::from_private_frame(&frame)
            .map_err(crypto_problem)?
            .matches_authenticated_readback(record),
    )?;
    Ok(frame)
}
fn output(fixture: &Fixture, frame: &[u8]) -> Result<(), Reason> {
    fixture.current()?;
    need(frame.len() <= APPLE_KEY_PRIVATE_FRAME_LIMIT)?;
    names(&fixture.path.join("reopened"), &[])?;
    let fd = nix::fcntl::openat(
        fixture.held[3].as_fd(),
        FRAME_NAME,
        nix::fcntl::OFlag::O_WRONLY
            | nix::fcntl::OFlag::O_CREAT
            | nix::fcntl::OFlag::O_EXCL
            | nix::fcntl::OFlag::O_NOFOLLOW
            | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| Reason::SourceRefused)?;
    let mut file = File::from(fd);
    let before = file_state(&file.metadata().map_err(|_| Reason::SourceRefused)?)?;
    need(before.2 == 0)?;
    file.write_all(frame).map_err(|_| Reason::SourceRefused)?;
    mrk_macos_installed_native::sync(file.as_fd(), true)
        .map_err(|_| Reason::VaultDurabilityUnknown)?;
    let after = file_state(&file.metadata().map_err(|_| Reason::SourceRefused)?)?;
    need(before.0 == after.0 && after.2 == frame.len() as u64)?;
    let fd: OwnedFd = file.into();
    nix::unistd::close(fd).map_err(|_| Reason::CleanupUnknown)?;
    mrk_macos_installed_native::sync(fixture.held[3].as_fd(), false)
        .map_err(|_| Reason::VaultDurabilityUnknown)?;
    need(
        file_state(
            &fs::symlink_metadata(fixture.path.join("reopened").join(FRAME_NAME))
                .map_err(|_| Reason::SourceRefused)?,
        )? == after,
    )?;
    fixture.current()
}

// Never repeat a failed/unknown Release. The actual original StoreBook remains
// held until this isolated process exits; only the fixture caller cleans files.
fn close_once(vault: &Vault, closed: &mut Option<bool>, id: u32) -> bool {
    *closed.get_or_insert_with(|| release(vault, id))
}

#[test]
#[ignore = "requires explicit private APFS fixture generated by the selected signed Ruby; no provisioning qualification"]
fn native_apfs_apple_key_new_reopen_and_private_reuse() {
    let end = Instant::now() + Duration::from_secs(30);
    let fixture = Fixture::open().expect("fixed private Apple component fixture required");
    let mut input = Input::read(&fixture).expect("bounded original private fixture input required");
    let mut source = None;
    let mut reopened = None;
    let mut source_closed = None;
    let mut reopened_closed = None;
    let result = (|| -> Result<(), Reason> {
        timely(end)?;
        let fields =
            AppleDistributionKeyFields::from_private_frame(&input.bytes).map_err(crypto_problem)?;
        source = Some(initialize(&fixture.path.join("native"), 1)?);
        let vault = source.as_ref().ok_or(Reason::CleanupUnknown)?;
        let owner = new_owner(vault, 2);
        let mut stop = || owner.interrupted() || Instant::now() >= end;
        let mut reserved = crypto::ReservedAppleDistributionKey::reserve(&vault.key, &[])
            .map_err(crypto_problem)?;
        let (identity, record, revision) = reserved.descriptor();
        let candidate = fields
            .seal_new(&mut reserved, &vault.key, KEY_ALLOWANCE)
            .map_err(crypto_problem)?;
        need(candidate.revision() == revision && identity == vault.key.identity())?;
        // Actual token replay and actual AEAD corruption are independent
        // negative checks; neither mutates/poisons the positive Store original.
        need(
            fields
                .seal_new(&mut reserved, &vault.key, KEY_ALLOWANCE)
                .is_err(),
        )?;
        let mut corrupt = candidate.bytes().to_vec();
        let last = corrupt.len().checked_sub(1).ok_or(Reason::VaultCorrupt)?;
        corrupt[last] ^= 1;
        need(matches!(
            vault.key.open_record(corrupt, KEY_ALLOWANCE),
            Err(crypto::Error::Authentication)
        ))?;
        let intent = vault
            .key
            .seal_intent(format::Mutation::New, record, None, Some(&candidate))
            .map_err(crypto_problem)?;
        let first_witness;
        {
            let mut book = vault.store.lock().map_err(|_| Reason::CleanupUnknown)?;
            let outcome = book
                .mutate(
                    &intent,
                    Some(candidate.bytes()),
                    None,
                    &mut stop,
                    &mut || {
                        cleanup_expired(&owner) || Instant::now() >= end + Duration::from_secs(2)
                    },
                )
                .map_err(problem)?;
            need(
                outcome
                    == store::StorageOutcome {
                        effect: store::Effect::KnownApplied,
                        durability: store::Durability::Confirmed,
                        cleanup: store::Cleanup::Known,
                    },
            )?;
            let (bytes, witness, complete) = book
                .read_new_apple_key_record(
                    record,
                    revision,
                    candidate.bytes().len(),
                    KEY_ALLOWANCE,
                    &mut stop,
                )
                .map_err(problem)?
                .into_parts();
            let opened = vault
                .key
                .open_record(bytes, KEY_ALLOWANCE)
                .map_err(crypto_problem)?;
            need(
                complete
                    && reserved.matches_record(&vault.key, &opened)
                    && fields.matches_authenticated_readback(&opened),
            )?;
            book.recheck_record(&witness, &mut stop).map_err(problem)?;
            first_witness = witness;
        }
        input.current(&fixture)?;
        need(close_once(vault, &mut source_closed, 3))?;
        timely(end)?;

        // A fresh actual lock/inventory/header/prefix witness, never a second
        // initialize or a replay of the original NEW result. The component
        // wrapping key intentionally stays in memory; this is NOT unlock.
        reopened = Some(Vault {
            store: Arc::new(Mutex::new(store::StoreBook::new())),
            key: vault.key.clone(),
            header: vault.header,
        });
        let fresh = reopened.as_ref().ok_or(Reason::CleanupUnknown)?;
        let owner = new_owner(fresh, 4);
        let mut stop = || owner.interrupted() || Instant::now() >= end;
        let frame;
        {
            let mut book = fresh.store.lock().map_err(|_| Reason::CleanupUnknown)?;
            let observed = book
                .inspect(
                    store::Location::application_data(
                        &fixture.path.join("native/dev.mobile-release-kit.desktop"),
                    )
                    .map_err(problem)?,
                    &mut stop,
                )
                .map_err(problem)?;
            need(
                book.lease_held()
                    && observed.state == store::Inspection::Locked
                    && observed.header == Some(fresh.header)
                    && observed.reservation == Some(identity.reservation())
                    && observed.records == [record]
                    && observed.root.is_some()
                    && book.storage_outcome().is_none(),
            )?;
            let (prefix, witness, complete) = book
                .read_record(record, false, &mut stop)
                .map_err(problem)?
                .into_parts();
            let descriptor = fresh
                .key
                .open_descriptor(&prefix, KEY_ALLOWANCE)
                .map_err(crypto_problem)?;
            need(
                !complete
                    && descriptor.record == record
                    && descriptor.revision == revision
                    && descriptor.descriptor.kind == Kind::AppleDistributionKey
                    && descriptor.descriptor.label.is_none()
                    && !descriptor.descriptor.has_file()
                    && descriptor.descriptor.presence() == [true; 3]
                    && witness == first_witness,
            )?;
            let (bytes, full_witness, complete) = book
                .read_apple_key_record(&witness, KEY_ALLOWANCE, &mut stop)
                .map_err(problem)?
                .into_parts();
            let opened = fresh
                .key
                .open_record(bytes, KEY_ALLOWANCE)
                .map_err(crypto_problem)?;
            need(
                complete
                    && full_witness == witness
                    && reserved.matches_record(&fresh.key, &opened)
                    && fields.matches_authenticated_readback(&opened),
            )?;
            frame = restored_frame(&opened)?;
            need(frame.as_slice() == input.bytes.as_slice())?;
            book.recheck_record(&witness, &mut stop).map_err(problem)?;
            book.recheck_apple_key_inventory(&[witness], None, &mut stop)
                .map_err(problem)?;
        }
        need(close_once(fresh, &mut reopened_closed, 5))?;
        input.current(&fixture)?;
        need(input.close())?;
        timely(end)?;
        // This fixed private file is usable by the next fixture process only
        // after ALL closes below and this exact test-process success/return.
        output(&fixture, &frame)?;
        timely(end)
    })();
    let source_closed = source
        .as_ref()
        .is_none_or(|v| close_once(v, &mut source_closed, 3));
    let reopened_closed = reopened
        .as_ref()
        .is_none_or(|v| close_once(v, &mut reopened_closed, 5));
    let input_closed = input.original.is_none() || input.close();
    let fixture_closed = fixture.close();
    assert!(
        source_closed
            && reopened_closed
            && input_closed
            && fixture_closed
            && Instant::now() < end + Duration::from_secs(2),
        "actual Apple component original close failed; do not run the verifier"
    );
    assert!(
        result.is_ok(),
        "Apple native backend component refused; no provisioning result"
    );
}
