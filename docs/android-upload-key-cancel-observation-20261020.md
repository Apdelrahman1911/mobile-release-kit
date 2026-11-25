# Upload-key cancellation: existing Mac observer correction

Base: `5dbd047f`. The accompanying seven-target hook patch is Root-only.
No shipping qualification flag, runtime component, provider command, CI job,
or signing/notarization step is changed. These are the existing three cases,
on the existing installed Observation/Relay and actual native owners.

## What was wrong

The old two STOP cases immediately failed on an *intermediate retained* sample,
even after the production cancellation/recovery implementation was corrected.
The positive-disposal observation tap only covered normal Published generation,
so genuine cancelled cleanup was invisible to the old observer. Normal recovery
also correctly remained unavailable while the shipping qualification flag was
false; registering a test fixture alone must not enable it.

## This bounded change

* The cancellation tap is reached only after the existing `dispose` really
  returns true: original private disposal, required `StoppedNoGo` CAS, and
  NativeUse retirement. It records nonsecret DATA; its return cannot change the
  generation result or drive cleanup. A later sample separately requires the
  original completed clock, empty private holding, actual returned joins,
  closed sources, ended parent and no Document Unknown.
* **RoundTrip:** unchanged Generate → authenticated NEW/readback/journal →
  repeated Create refused → actual lock/open/unlock → Load/Assess → clean quit.
* **StopBeforeGo:** wait for real disposal and durable StoppedNoGo, refuse the
  repeated Create, then actual lock/open/unlock/recontext. Refresh the actual
  saved input, prepare against the same current Host/Store, and explicitly call
  the same real recovery owner with **AcknowledgeUnstarted only**. Require its
  actual completed publication/private disposal and the next preference
  revision before lock/quit. The real journal archives the old cancelled
  intent; the observer never deletes it or issues another Create.
* **StopAfterNew:** wait for real cancellation disposal, refuse repeat, then
  lock/open/unlock and Load/Assess the exact originally authenticated full
  record reference. Preserve the original cancellation and pending reference
  history. This does **not** Bind the record or claim recovery is complete.
* The native-only one-use selector is consumed inside the real recovery
  admission, with the same Control, prepared admission, current context,
  status revision, vault/key/roster and original recovery checks. It cannot
  select RememberBound. Ordinary `upload_key_status` and the ordinary
  qualification flag are unchanged. No generic status bypass is added.
* Reports distinguish `positive` generation from `cancelled-cleanup`, and
  record explicit stopped-intent acknowledgement separately. NoGO has a real
  shared reference namespace but **no keystore**; AfterNEW preserves one
  encrypted record despite cancellation. The existing held-metadata readback
  now checks those two different rosters rather than assuming Host = key.

All three completed cases still have eight Asset originals plus the original
quit. The generation retains its original 180/190/first-failure deadlines;
the later explicit Recovery has its own ordinary existing deadline, never a
renewal of generation. Unknown/partial cleanup remains retained and cannot
be reported as a completed case. No private contents enter reports.

## Files and integration

Owned new code: `desktop/src-tauri/src/credential_upload_key_cancel_observation.rs`.
Owned new tests: `tests/desktop/test_macos_upload_key_cancel_observation.py`.

`android-upload-key-cancel-observation-hooks-20261020.patch` changes only:

1. `credential_upload_key_observation.rs`: child declaration, fixed trace/sample
   fields and shared existing saved-observation/vault adapter.
2. `credential_upload_key_cancellation.rs`: ignored observation-only tap at the
   genuinely successful original disposal cut.
3. `credential_upload_key_controls.rs`: closed recovery action selection; the
   same original prepared-admission identity must match.
4. `credential_upload_key_recovery.rs`: ordinary wrapper plus fixed selected
   admission; tiny cfg-only original revision/request/completion observations.
5. `installed_shell_observation_macos_upload_key.rs`: same three-case flow,
   exact case-bound actions and reports; no new task/runner.
6. `desktop/tools/macos_upload_key_observation.py`: exact report/metadata shapes.
7. Existing `test_macos_upload_key_observation.py`: new explicit fields and
   optional case/Host distinction in its existing synthetic metadata port.

## Validation status and required next checks

* Source patch applies to the stated base; no shared worktree was edited.
* Apple independently accepted the exact four-path/seven-hook source packet.
  After that acceptance, Root authorized the six new passive report tests:
  **6 passed, 0 failed (0.006s), caller exit 0**, using a private five-file
  projection and `python3 -I -S -B`. Its disposable copies were removed; the
  log is retained at `.task-upload-cancel-observation-20261020/test-six.log`.
  No Cargo build, native process/key generation or CI was run in this lane.
* Root's focused passive command after applying the patch:
  `python3 -B -m unittest discover -s tests/desktop -p 'test_macos_upload_key*observation.py'`.
  This reuses the original parser/metadata port and adds six cancellation
  report cases. Synthetic metadata is not native custody evidence.
* Two new Rust DATA tests and the existing selector/sample DATA tests require
  the actual observation-feature Mac graph; they do not qualify native actions.
* Real validation still requires the existing installed native observer, the
  current valid bundled runtime and the actual protected JDK/catalog, followed
  by returned invocations, exact metadata readback and normal quit. Reuse valid
  runtime/JDK components; no reason to repeat signing/notarization for them.

Still separate: actual Bind/RememberBound, encrypted backup/export/import via
the genuine two-picker/two-destination owner, and any shipping availability
decision. Do not fabricate `SelectedPair` or accepted GuiFacts to test backup.
These three cases do not claim signing/Play acceptance, backup, or physical-Mac
verification. Previously accepted Apple native-vault facet remains on its
preserved `task/automation-apple-native-facet-20261020` branch (`d2598c05`).
