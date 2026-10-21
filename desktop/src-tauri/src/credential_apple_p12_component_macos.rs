//! Fixed synthetic-P12 BACKEND component on the existing original fixture.
//!
//! The preceding selected-Ruby process used the freshly reopened real key and
//! shared assembler with a synthetic matching certificate, NOT an Apple trust
//! override. This test exercises only shared fixed P12 crypto and actual APFS
//! NEW/readback/fresh reopen/close. It creates no SavedSession, certificate
//! binding, P12SavePermit, NativeUse, assignment or Keychain unlock proof.
//! The next original process may use these private files only after this exact
//! test process has returned successfully and all actual closes below passed.
use super::*;

const P12_MAGIC: &[u8] = b"MRK-APPLE-P12/1\n";
const P12_HEADER: usize = P12_MAGIC.len() + 4 + 64;
const PASSWORD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
// Smaller than the production two-MiB allowance: actual fixture cipher/body
// buffers must fit128KiB BEFORE allocation, retaining the old256KiB FSIZE.
const P12_ALLOWANCE: usize = crypto::CONTROL_BYTES + P12_FIXTURE_LIMIT;
const _: () = assert!(P12_ALLOWANCE <= crypto::APPLE_P12_CRYPTO_BYTES);
const _: () = assert!(P12_ALLOWANCE <= crypto::APPLE_KEY_CRYPTO_BYTES);

fn material(frame: &[u8]) -> Result<(Fields, &[u8]), Reason> {
    need(frame.len() <= P12_FIXTURE_LIMIT)?;
    let meta = commands::apple_p12_output_metadata(frame).map_err(crypto_problem)?;
    let body = frame.get(P12_HEADER..).ok_or(Reason::SourceRefused)?;
    need(meta.p12_bytes == body.len() && !body.is_empty())?;
    let fields = commands::own_fields(Kind::AppleP12, &serde_json::json!({"password":PASSWORD}))
        .map_err(|_| Reason::SourceRefused)?;
    Ok((fields, body))
}

fn matches(record: &crypto::AuthenticatedRecord, body: &[u8]) -> bool {
    record.descriptor.kind == Kind::AppleP12
        && record.descriptor.label.is_none()
        && record.descriptor.has_file()
        && record.descriptor.presence() == [true]
        && record.fields.vault_kind() == Kind::AppleP12
        && record.fields.vault_presence() == [true]
        && record.fields.borrow_value("password") == Some(PASSWORD)
        && record
            .file
            .as_ref()
            .is_some_and(|file| file.bytes() == body)
}

fn output_member(fixture: &Fixture, name: &str, bytes: &[u8]) -> Result<(), Reason> {
    need(
        matches!(name, "distribution.p12" | "p12-password")
            && !bytes.is_empty()
            && bytes.len() <= P12_FIXTURE_LIMIT,
    )?;
    fixture.current()?;
    let fd = nix::fcntl::openat(
        fixture.held[3].as_fd(),
        name,
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
    file.write_all(bytes).map_err(|_| Reason::SourceRefused)?;
    mrk_macos_installed_native::sync(file.as_fd(), true)
        .map_err(|_| Reason::VaultDurabilityUnknown)?;
    let after = file_state(&file.metadata().map_err(|_| Reason::SourceRefused)?)?;
    need(before.0 == after.0 && after.2 == bytes.len() as u64)?;
    let fd: OwnedFd = file.into();
    nix::unistd::close(fd).map_err(|_| Reason::CleanupUnknown)?;
    need(
        file_state(
            &fs::symlink_metadata(fixture.path.join("reopened").join(name))
                .map_err(|_| Reason::SourceRefused)?,
        )? == after,
    )?;
    fixture.current()
}

fn output_record(fixture: &Fixture, record: &crypto::AuthenticatedRecord) -> Result<(), Reason> {
    // ONLY this freshly authenticated record supplies BOTH inputs for the
    // real selected-record extractor. Never reinsert the test password or
    // generated P12 bytes at the output boundary.
    let body = record.file.as_ref().ok_or(Reason::VaultCorrupt)?.bytes();
    let password = record
        .fields
        .borrow_value("password")
        .ok_or(Reason::VaultCorrupt)?;
    need(password.len() == 64 && body.len() <= P12_FIXTURE_LIMIT)?;
    names(&fixture.path.join("reopened"), &[])?;
    output_member(fixture, "distribution.p12", body)?;
    output_member(fixture, "p12-password", password.as_bytes())?;
    mrk_macos_installed_native::sync(fixture.held[3].as_fd(), false)
        .map_err(|_| Reason::VaultDurabilityUnknown)?;
    names(
        &fixture.path.join("reopened"),
        &["distribution.p12", "p12-password"],
    )?;
    fixture.current()
}

#[test]
#[ignore = "requires explicit private APFS P12 fixture from the selected signed Ruby; no Apple provisioning qualification"]
fn native_apfs_apple_p12_new_reopen_and_private_reuse() {
    let end = Instant::now() + Duration::from_secs(30);
    let fixture =
        Fixture::open(FixtureFrame::P12).expect("fixed private P12 component fixture required");
    let mut input =
        Input::read(&fixture).expect("bounded original private P12 fixture input required");
    let mut source = None;
    let mut reopened = None;
    let mut source_closed = None;
    let mut reopened_closed = None;
    let result = (|| -> Result<(), Reason> {
        timely(end)?;
        let (fields, body) = material(&input.bytes)?;
        source = Some(initialize(&fixture.path.join("native"), 1)?);
        let vault = source.as_ref().ok_or(Reason::CleanupUnknown)?;
        let owner = new_owner(vault, 2);
        let mut stop = || owner.interrupted() || Instant::now() >= end;
        let mut reserved =
            crypto::ReservedAppleP12::reserve(&vault.key, &[]).map_err(crypto_problem)?;
        let (identity, record, revision) = reserved.descriptor();
        let candidate = reserved
            .seal_p12(&vault.key, &fields, Ok(body), P12_ALLOWANCE)
            .map_err(crypto_problem)?;
        need(
            candidate.revision() == revision
                && identity == vault.key.identity()
                && candidate.bytes().len() <= P12_FIXTURE_LIMIT,
        )?;
        // Real one-use token and AEAD negatives are isolated from the positive
        // Store original. They cannot turn an uncertain mutation into success.
        need(
            reserved
                .seal_p12(&vault.key, &fields, Ok(body), P12_ALLOWANCE)
                .is_err(),
        )?;
        let mut corrupt = candidate.bytes().to_vec();
        let last = corrupt.len().checked_sub(1).ok_or(Reason::VaultCorrupt)?;
        corrupt[last] ^= 1;
        need(matches!(
            vault.key.open_record(corrupt, P12_ALLOWANCE),
            Err(crypto::Error::Authentication)
        ))?;
        let length = candidate.bytes().len();
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
            drop(candidate); // Known NEW only; no cipher/readback overlap needed.
            let (bytes, witness, complete) = book
                .read_new_apple_p12_record(record, revision, length, P12_ALLOWANCE, &mut stop)
                .map_err(problem)?
                .into_parts();
            need(bytes.len() == length && bytes.capacity() <= P12_FIXTURE_LIMIT)?;
            let opened = vault
                .key
                .open_record(bytes, P12_ALLOWANCE)
                .map_err(crypto_problem)?;
            need(
                complete && reserved.matches_record(&vault.key, &opened) && matches(&opened, body),
            )?;
            book.recheck_record(&witness, &mut stop).map_err(problem)?;
            first_witness = witness;
        }
        input.current(&fixture)?;
        need(close_once(vault, &mut source_closed, 3))?;
        timely(end)?;

        // Fresh actual APFS lock/header/singleton inventory, NOT initialize,
        // gen2, a cached row, or a Keychain cold-unlock claim. The component
        // wrapping key stays in this one native process as in the key test.
        reopened = Some(Vault {
            store: Arc::new(Mutex::new(store::StoreBook::new())),
            key: vault.key.clone(),
            header: vault.header,
        });
        let fresh = reopened.as_ref().ok_or(Reason::CleanupUnknown)?;
        let owner = new_owner(fresh, 4);
        let mut stop = || owner.interrupted() || Instant::now() >= end;
        let restored;
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
                .open_descriptor(&prefix, P12_ALLOWANCE)
                .map_err(crypto_problem)?;
            need(
                !complete
                    && descriptor.record == record
                    && descriptor.revision == revision
                    && descriptor.descriptor.kind == Kind::AppleP12
                    && descriptor.descriptor.label.is_none()
                    && descriptor.descriptor.has_file()
                    && descriptor.descriptor.presence() == [true]
                    && witness == first_witness,
            )?;
            // The existing full-witness reader is kind-agnostic Store IO, not
            // a key loan. Reuse its genuine same-file preallocation bound for
            // this tiny fixture; no generic32MiB fallback/new reader is added.
            let (bytes, current, complete) = book
                .read_apple_key_record(&witness, P12_ALLOWANCE, &mut stop)
                .map_err(problem)?
                .into_parts();
            need(bytes.len() == length && bytes.capacity() <= P12_FIXTURE_LIMIT)?;
            let opened = fresh
                .key
                .open_record(bytes, P12_ALLOWANCE)
                .map_err(crypto_problem)?;
            need(
                complete
                    && current == witness
                    && reserved.matches_record(&fresh.key, &opened)
                    && matches(&opened, body),
            )?;
            book.recheck_record(&witness, &mut stop).map_err(problem)?;
            book.recheck_apple_key_inventory(&[witness], None, &mut stop)
                .map_err(problem)?;
            restored = opened;
        }
        need(close_once(fresh, &mut reopened_closed, 5))?;
        input.current(&fixture)?;
        need(input.close())?;
        timely(end)?;
        output_record(&fixture, &restored)?;
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
        "actual P12 component original close failed; do not run the extractor"
    );
    assert!(
        result.is_ok(),
        "P12 native backend component refused; no Apple provisioning result"
    );
}
