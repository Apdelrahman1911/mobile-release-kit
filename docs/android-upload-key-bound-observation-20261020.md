# AfterNEW: explicit Bind and remembered association

Base `4d683e03`; successor to the accepted cancellation observer. This changes
only the existing **StopAfterNew** journey, not the shipping qualification,
key producer, vault/recovery implementations, GUI, or CI workflow.

## Exact original operation

1. Original5 stays cancelled. Require its actual private disposal/NativeUse
   retirement and preserve the one authenticated NEW record and pending intent.
2. Existing Lock/Open6/Unlock7/recontext and Load/Assess8 still use the exact
   original full StoredRef, including the original read witness.
3. Consume **Prepare8's real one-use Bind preview token** through unchanged
   `DocumentBinding::bind`, producing real Bind9/Child::Check. Observe a current
   full BoundLoan after returned joins; a saved descriptor or cleared working
   `SlotData.reference` is not substituted for that loan.
4. Obtain a fresh saved observation and prepare against the same native
   context/Host/Store. The actual recovery projection must offer RememberBound
   for that same full reference and current preference revision.
5. Explicit **Recovery10 / RememberBound** uses the unchanged owner. It captures
   the current BoundLoan before replacing Bind9, runs the actual off-lock
   Child::Check and original one-CAS recovery, then disposes private backing and
   retires NativeUse. The core retains the original generation intent identity;
   this adapter creates no new generation ID, reference, key or signer hash.
6. Require the actual completion/full reference, the still-current BoundLoan,
   original completed publication/disposal, and next preference revision before
   relock and **Quit11**. No missing worker or report grants finality.

RoundTrip remains eight originals plus Quit9. StopBeforeGo remains the existing
explicit AcknowledgeUnstarted Recovery8 plus Quit9. Missing-tools remains four
originals plus Quit5. The native-only selector now matches those exact cases,
paths, roles, and IDs. Ordinary availability and permissions are unchanged.

The generation's original 180/190/first-failure clock is never reset. Bind and
the later explicit Recovery use their own existing ordinary owner deadlines.
Unknowns and lost original outcomes are not retried or converted to completion.

## Reporting and scope

An executed AfterNEW report now requires originalCount11 and two additional
booleans, set only after the corresponding real native observations:
`explicitlyBoundSavedKey` and `rememberedBoundSavedKey`. The generation sample
remains `cancelled-cleanup`/stopped/unassigned-at-that-original-boundary; it is
not rewritten as generation success. `automaticallyAssigned` stays false.

Old AfterNEW Load/Assess-only reports cannot pass this extended case. Other
cases and missing-prerequisite reports cannot borrow the new fields. Normal
quit diagnostics use the actual case's ID, and the finite failure vocabulary
includes both the new steps and the earlier NoGo recovery steps.

**Not covered:** backup/export/import, release signing, Google acceptance,
automatic fingerprint updates, or physical-Mac qualification. No key/password,
private path, record identifier or secret is added to reports.

## Integration and verification

Owned leaf: `desktop/src-tauri/src/credential_upload_key_bound_observation.rs`.
Owned four-case passive test: `tests/desktop/test_macos_upload_key_bound_observation.py`.
Root applies `android-upload-key-bound-observation-hooks-20261020.patch` to:

* `credential_upload_key_observation.rs`: child/trace and fixed existing adapters.
* `credential_upload_key_controls.rs`: exact case-bound nonshipping admission.
* `credential_upload_key_recovery.rs`: cfg-only current projection/loan checks.
* `installed_shell_observation_macos_upload_key.rs`: same original Relay sequence.
* `installed_shell_observation_macos_vault.rs`: exact completion/quit IDs.
* `desktop/tools/macos_upload_key_observation.py`: closed report interpretation.
* `desktop/tools/macos_aqua_qualification.py`: case-specific diagnostics only.
* Existing cancellation test: updated AfterNEW report, unchanged NoGo behavior.

Author checks: Rust syntax/rustfmt source parse and Python AST pass; eight-target
patch applies to the stated base. The **four new + six affected passive tests
passed (10/10, no failures/errors/skips, 0.008s, caller exit0)** using the real
complete DATA parsers in a private six-file projection. No native/core process
owner was invoked. Disposable copies were removed; log retained in
`.task-upload-bound-observation-20261020/test-ten.log`. Unchanged original tests
were not repeated. Focused command after composition:

```sh
python3 -I -S -B -m unittest discover -v -s tests/desktop \
  -p 'test_macos_upload_key_[bc]*observation.py'
```

Distinct source review and Root's actual Mac observation-feature compilation
and native run remain required. The existing selector DATA test is expanded;
it creates no current native originals. Reuse the same valid installed runtime,
protected JDK/catalog and hosted observer—no new pipeline or unrelated signing.
