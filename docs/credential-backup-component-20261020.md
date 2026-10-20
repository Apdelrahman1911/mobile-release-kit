# Native backup backend: full readback and component check

Backup is still **production OFF and natively unverified**. This packet does not
enable it. Manual picker testing does not substitute for backend verification.

## Actual defect fixed

The original `import_new` authenticated only the saved descriptor after NEW.
It did not authenticate the persisted payload or compare every restored field
and file before publishing the saved row. The existing parent did not supply
that missing check.

The same import now retains the actual candidate length/random revision,
records the original mutation outcome immediately, and requires
KnownApplied/Confirmed/Known. After retiring the successful ciphertext, it reads
the complete record through the same StoreBook, authenticates all AEAD sections,
and compares the descriptor, every scalar and complete file to the same retained
restored input. It rechecks the original root, read witness and key before
publishing. No extra private JSON copy, replacement, assignment or retry exists.
The original working allowance still excludes retained restored material and
bounds the full ciphertext/decryption allocation. Readback/STOP failure retains
the genuine NEW outcome and failed original; it does not turn that effect into
absence or allocate another record.

## One actual native component selector

New leaf: `credential_backup_component_macos.rs`, nested under the existing
backup child only in test + debug + supported 64-bit Mac builds.

```
asset_session::vault::backup_native::component_tests::native_apfs_backup_roundtrip_wrong_code_and_lost_close_receipt
```

It is ignored by ordinary tests. Root explicitly selects it with `--exact
--ignored --test-threads=1`, supplies `MRK_MACOS_VAULT_FIXTURE_ROOT`, and requires
one pass, no failures and no ignored test in that invocation. A missing fixture
or unsupported filesystem fails; it is not a skipped pass.

Reuse the fresh private APFS fixture/process-join cleanup convention already in
`.github/workflows/desktop-ci.yml` (the native vault lifecycle step). Run this
single selector in the existing next relevant Mac component job and compiler
cache. No new workflow, signed runtime, packaging or notarization is needed.

### Real backend boundary

The fixture creates fresh synthetic initialization keys, locally authenticates
their real crypto headers, and initializes actual StoreBooks/records on APFS.
It never constructs a Keychain candidate or claims Keychain authentication.
Every backup call enters the existing parent
`asset_session_vault::execute(owner, Child::Backup(request))` with that actual
store/key and the retained Request/Custody. Native SourceBook, physical exclusions,
ACL checks, exclusive files, crypto, NEW, readback, sync and close code run as-is.
OriginalWork uses its normal finite clock. No worker or coordinator join receipt
is synthesized; component return is not Desktop delivery/quit evidence.

The sole selection exception is
`BackupDestinations::new_component_fixture(&Arc<OriginalWork>, [PathBuf; 2])`.
Its constructor/currentness marker and two fixed failure cuts exist only in
test + debug Mac code. Production `new` and its native selection predicate stay
unchanged. There is no fake GuiFacts, SelectedPair, renderer path, serialized
permission, alternate writer or shipping command.

### Cases in that selector

1. Export an actually stored synthetic record through both real sinks; require
   exclusive publication, file/directory sync, exact readback and all native
   closes. Capture the two real files and import as NEW into a distinct vault;
   check full authenticated scalar/file equality, fresh full identity/revision,
   and the unchanged source record. The JKS-shaped fixture has an observed
   header and synthetic payload, **not a signing-capable/generated key**.
2. Supply an exact-size, validly encoded but changed recovery-code file. Actual
   input custody/authentication must refuse before NEW. The prior Store outcome
   is not attributed to this request; source files/record remain intact.
3. Stop after the actual code rename/sync/readback while backup is still pending.
   Deliberately hide the first actual file-close return from production state;
   both real file-close calls and independent ACL/directory closes still execute.
   Require Unknown, retained original private output, no reusable/disposable or
   completed candidate, and preserved partial files. This is **injected receipt
   loss over real IO**, not a claim of a kernel close fault. That bounded unknown
   holding remains until the isolated fixture process exits; no receipt reset or
   retry makes it pass. Independent Store closure does not clear this Unknown.

Root cleans only its explicitly owned fixture after the process joins. No private
files, recovery code, plaintext or keys are printed or uploaded by this test.

## Integration and verification

Apply `credential-backup-component-hooks-20261020.patch` after this leaf. Five
existing targets only: backup native child, Mac input/output pair owners,
portable backup codec and the test-only crypto constructor. No source edits were
made in Root's integration worktree by this lane.

Two new portable crypto/readback comparisons cover changed scalars, label,
presence and file; corruption can still pass descriptor authentication but must
fail full payload authentication. The existing scalar-only reseal test also
checks the new matcher. Their exact Root filter is `vault_crypto::backup::tests`.
Do not rerun unrelated suites or previously successful signing stages.

Author validation: rustfmt syntax/format and patch apply/whitespace checks only.
**New Rust cases, actual Mac component IO, genuine two-picker interaction,
original Desktop retirement/quit and installed end-to-end backup remain unrun.**
Any component pass must be reported separately from those remaining checks.
