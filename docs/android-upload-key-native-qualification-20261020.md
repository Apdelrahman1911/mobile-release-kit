# Android upload-key native observation — source handoff

Base: `e45dd1c4c0a52adc018cb1d0aca7fc16f4724e54`.

**No native execution or key generation has occurred for this packet.** The
positive path is ready for distinct source review and the real observer graph
compile. The two STOP selectors are **diagnostic probes, not passing
cancellation qualification**. Do not schedule those probes as expected-green
native tests: the production cancellation-disposal gap below must be resolved
first. The shipping `NATIVE_UPLOAD_KEY_QUALIFIED` remains `false`.

## Existing entry, not another runner

Use the existing actual-main target `installed-shell-observation`, built with
`--no-default-features --features desktop-shell,custom-protocol,macos-installed-observation`
and the admitted Mac target. Its source is
`desktop/src-tauri/tests/installed_shell_observation.rs`; it is not a libtest
worker. No development-runtime, publisher, registration-helper or installer
feature is admissible. The actual build retains the exact compiled
`GITHUB_SHA`, `GITHUB_RUN_ID`, and `GITHUB_RUN_ATTEMPT` tuple.

After Root composes the current signed-runtime/package/source route, the
existing isolated invocation syntax is:

```text
$MRK_PYTHON -I -S -B desktop/tools/macos_aqua_qualification.py \
  --scope upload-key-roundtrip --target aarch64-apple-darwin
```

The target suffix is optional for ARM; the existing other accepted target is
`x86_64-apple-darwin`. The finite selector names are:

| Selector | Meaning / execution status |
| --- | --- |
| `upload-key-roundtrip` | Actual generation/NEW/readback/journal/reopen path; not yet executed. |
| `upload-key-stop-before-go` | Actual UserCancelled after reservation at READY, before private GO; diagnostic-only, not scheduled. |
| `upload-key-stop-after-new` | Actual UserCancelled after NEW/full authenticated readback/native+storage-child joins, before journal; diagnostic-only, not scheduled. |

Each selector is a **separate one-case invocation**, with exclusive fixture
parents. It is not a three-case loop after an unknown owner. The existing
`run_owned` receives only `[PAYLOAD_EXECUTABLE, case]`, a fixed clean app
environment and the fixed state directory. The executable is the unchanged
installed payload:

```text
/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/MacOS/mobile-release-kit-desktop
```

The observer cap is 480 seconds and its outer invocation cap is 495 seconds.
Neither changes the generation's **same original 180/190-second clock**, its
first-failure cleanup cutoff, or any existing vault-helper deadline. No new
clock, process owner, AX selector, DOM selector or cleanup controller is added.
The initial existing real project-picker journey is unchanged. Its original
Relay awaits the new post-picker native steps directly.

The existing runner's `admit()` still requires its historical fixed
`verify/desktop-macos-aqua` push/workflow route and macOS 26. This packet does
**not** activate that workflow, change its supplier pins or relax admission.
Root owns the explicit current-source route composition. Do not manufacture
environment values to impersonate the old route or run the old full matrix.

## Required original inputs

Before the positive invocation:

* Install the current matching signed app/payload, vault helper, catalogue
  query/registration helpers, Python/Store runtime and their genuine source
  records through the current reviewed package route. Reuse valid same-source
  artifacts; do not rebuild/reselect historical suppliers for this fixture.
* Use the existing hosted non-root native user with its genuine available login
  Keychain and existing initial-picker infrastructure. No owner credentials,
  signing accounts, private external key files or provider calls are inputs.
* That **same native account** must already have exactly one recoverable
  protected Android catalogue entry containing the supported JDK. Preparation
  is the existing `choose_android_tool_source` →
  `inspect_android_tool_sources` → `register_android_tool_sources` route, not
  this fixture. The fixture only performs the actual native catalogue
  `Refresh` → `Recover` → `Select` comparisons. It never adopts a path,
  downloads tools, uses PATH keytool or creates a catalogue receipt.
* Do not precreate the fixture Host/service or vault. The existing fixture
  owner creates exclusive native-user parents; the SAME vault/Host bodies then
  create their actual stores under `Control.root()`, not ambient app-data.

The existing fixture producer supplies the fixed public saved `CONFIG` and
`version.properties` (`1.2.3`, build `7`). There is no caller-provided project,
private scalar, output path or JSON credential input. Public project/state
parents are derived from the exact source/run/attempt/case below
`/private/tmp/mrk-macos-aqua-…`. Private fixture app-data is:

```text
<native User::from_uid home>/Library/Application Support/
  mrk-macos-aqua-upload-key-<source>-<run>-<attempt>-<case>/
  <case>/dev.mobile-release-kit.desktop
```

An empty current catalogue or a known negative initialization provider result
is **NOT EXECUTED**, never a successful generation prerequisite. Ambiguous,
stale, changed or unknown originals remain refusals. The fixture never fixes
those by overwriting/adopting data or trying another JDK.

## Positive direct flow and original receipts

1. Existing genuine project picker (asset original 1), vault Open (2),
   PrepareInitialize (3), and Initialize (4).
2. Establish the actual native project context; recover/select the genuine
   protected catalogue; capture the real saved observation lane with
   `observe_release_version`.
3. Call the real `prepare_upload_key_setup` and
   `create_upload_key` bodies. A non-Clone, action-bound installed `Selection`
   is consumed **inside** those bodies, matching the SAME Control/Document,
   sequence and original count. Registering the observation alone never
   enables ordinary renderer status/Prepare/Create.
4. Generation original 5 performs the actual NativeUse reservation, durable
   generation-intent CAS, private CSPRNG, admitted original tool lease,
   fixed producer, NEW vault mutation, complete authenticated private readback,
   journal `record_saved`, publication, all original joins, private disposal,
   NativeUse retirement and terminal clock retirement.
5. A repeated actual Create call must refuse before another original exists.
   Lock, reopen (6), unlock (7), recontextualize and Load/assess (8) the **same
   full StoredRef plus physical read witness**. Then relock and ordinary
   original Quit (9). There is no automatic Bind or backup.

`operationId: 5` in this observer's sample is the asset-session original
serial. It is not the producer's opaque lowerhex operation identity.

The producer observation reads the SAME retained native `UploadKeyRun`.
Positive evidence requires both native inspection and acquisition really
started and returned without failed/error/handle remnants, actual stdout task
return, driver/manager/watchdog joins and the original moved M2/SH close tail.
Neither a parsed terminal nor early no-child retirement is positive evidence.
The pre-disposal `producer` sample is captured at the actual authenticated NEW
boundary. `retainedProducer` is separately read from the current retained
owner; unavailable current evidence is never filled with the historical sample.

The observation retains only a weak original identity, full nonsecret reference
and fixed boolean facts. It owns no additional JKS/key/password/native run.
Actual private bytes never enter its report. Its post-retirement hook is
TRY-only and rechecks the SAME original endpoint before Holding can be dropped.

## Production cancellation gap — do not call the probes a pass

The fixture's cuts call the real `Slot.stop(UserCancelled, original Instant)`
and `parent_stop`; they do not invent retained state. At either cut the current
production `credential_upload_key.rs` retains `Holding`:

* `retirement_ready` requires a non-stopped owner, nonfailed clock and Published.
* `take_for_retirement` creates `UploadKeyDisposal` only for Published.
* `dispose_private` repeats those predicates before disposing the native
  candidate and retiring NativeUse.
* The actual `slot_private_data_empty` gate refuses exit while this Holding
  remains, even if native producers have genuinely returned.

Consequently a normal UserCancelled at the selected pre-GO boundary cannot
currently finish private disposal/quit. This is a real lifecycle limitation,
not qualification evidence and not a reason to extend the deadline. After NEW
but before journal, the actual saved record also cannot be silently forgotten,
overwritten or regenerated.

The probe preserves the actual stopped clock, intent/private/native-use
retention and independent join axes. Its failure diagnostic says
`upload-key-expected-retention`, `observationOnly: true`,
`exitOrDisposalPermission: false`, plus the real repeated-call refusal. It
never produces an expected-green report, calls private metadata readback on
unknown finality, forces exit, clears a receipt or starts the next case.

Before these become cancellation qualification, separately review and implement
an actual known-cancellation disposal path: original no-GO or proven durable
NEW custody, all relevant real joins, retained durable recovery references and
no retry/Bind/regeneration. Unknown native/storage cleanup remains retained.
This packet does not add that production authority.

## Post-return fixture readback

Only the existing owner's genuine `CompletedProcess` path may inspect the
fixed finite native fixture roster. The new helper reuses its held-directory,
nofollow, exact-file and independent-close machinery. It checks the created
encrypted record and service reference namespace by metadata only, including
same UID/GID/device, 0600 single-link files, before/after original identity,
bounded size and exact roster. The service-root reservation remains held across
the service walk and is rechecked before close. No private file body is read,
hashed or exported; report paths never select a file. Files/Keychain row remain
for the disposable account's later retirement, not automatic cleanup.

## Source packet and Root-only hooks

Own leaves:

* `credential_upload_key_observation.rs`: fixed original checkpoints/reference
  and actual Document adapters; no public command.
* `saved_command_upload_key_observation.rs`: same-run nonsecret native facts.
* `installed_shell_observation_macos_upload_key.rs`: finite Control actions and
  post-picker native Relay steps.
* `desktop/tools/macos_upload_key_observation.py`: closed DATA/metadata helper.
* `tests/desktop/test_macos_upload_key_observation.py`: inert full-runner tests.

`android-upload-key-native-qualification-hooks-20261020.patch` is **unapplied**
and touches exactly these ten shared paths for Root composition:

```text
desktop/src-tauri/src/asset_session.rs
desktop/src-tauri/src/asset_session_vault.rs
desktop/src-tauri/src/credential_upload_key.rs
desktop/src-tauri/src/credential_upload_key_controls.rs
desktop/src-tauri/src/installed_shell_observation_macos.rs
desktop/src-tauri/src/installed_shell_observation_macos_vault.rs
desktop/src-tauri/src/saved_command_upload_key.rs
desktop/src-tauri/src/shell.rs
desktop/src-tauri/tests/installed_shell_observation.rs
desktop/tools/macos_aqua_qualification.py
```

The observer's manual module roster predates the current service/Git/tools/
credential graph. Its hunk adds all **38 required missing current-lib module
declarations**, retaining the original platform cfgs, plus the lib's existing
recursion limit 256. The other seven missing lib entries are deliberately
excluded: three forbidden Android helper/publisher roles, two runtime publisher
roles, standalone `installed_cli` main, and unrelated
`macos_install_producer_selection_data`. This is the SAME observer crate, not
a duplicate library/owner. Project's identity fixture depends on this hunk and
does not supply a competing roster edit.

## Actual verification and limits

* Exact complete projected runner + new helper + new test module:
  **19 Python tests passed, 0.015s**, original caller exit 0.
* After the same-device/held-parent-reservation negative was added, the five
  affected full-metadata/readback tests passed **5/5, 0.004s**, caller exit 0.
  These are five of the nineteen, not 24 distinct tests.
* Tests use inert invocation/metadata ports and synthetic public DATA only.
  They cover closed selection/flags, strict sample fields, historical/current
  joins, positive refusal of retention/unknown, fixed-roster/mode/alias/bounds,
  late reservation replacement, failed independent close, no pre-return
  readback/no next call and known no-tools NOT EXECUTED.
* Rustfmt parsed the new leaves and full patched Rust files. Four new embedded
  Rust DATA tests are authored but **unrun**. No Cargo build, AppKit/picker,
  keytool, key generation, Keychain, native custody or installed test was run.
* Patch apply-check passed against the unchanged lane base and Root
  `bdd39bdb`; no shared source file was edited in this lane.

The previous shipping graph's Mac typecheck is not a compile or execution of
these observer hooks. Native success would qualify only the exercised
generation/DER/NEW/readback path. It would not qualify jarsigner, Play, a release
build, automatic assignment, backup, a physical Mac, or any unexecuted STOP
case. No successful probe automatically changes a shipping qualifier.
