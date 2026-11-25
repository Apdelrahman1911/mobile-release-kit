# Continue a persisted Bundle-ID setup

This completes discovery/selection for the existing read-only Reconcile path.
It does not add registration, repair a journal, adopt a past native operation,
or make a certificate/profile usable. Service independently plan-reviewed it.

## Actual path

1. Use the existing saved-project/P8-bound **Review** Prepare and its separate
   Start consent. The same grantless Host Ready, NativeUse, Initialize job and
   issuer-wide `inspect_account` remain the only local-state path. No extra
   command, job, filesystem read, provider request or automatic startup is added.
2. Only the original positive Review retirement may project the successful
   **INITIAL** `AccountSnapshot`. The actual native slots (including retirement),
   worker/reader/driver/watchdog and material gates remain mandatory. A failed,
   absent, stopped or unknown original produces no list, not an empty list.
3. The new DATA leaf filters by the current issuer AccountRef, persisted
   ProjectBinding, complete registered-root facts, Bundle ID, team, prefix and
   existing-application flag. It omits private provenance/credential/hash data.
   Other same-account unresolved rows are counted without disclosing details;
   they still participate in the original account-wide reserve fence.
4. After the original Start invocation and a subsequent terminal status read
   return, the current UI offers **Continue previous setup** for each matching
   row. Nothing is selected automatically. Choosing a row retains only its IDs
   and explicitly uses its old display name; no saved identity or key changes.
5. Selection calls existing `prepare(mode="reconcile")`, then requires the
   unchanged read-only consent. Native request construction repeats the full
   project/root/account/identity predicate and existing full target equality
   against a newly read immutable prior row. Neither renderer IDs nor a list
   satisfy these checks. Existing fixed GET/readback remains comparison-only:
   no POST, journal update, original-reservation restoration or uncertainty reset.

An earlier Pending/Unknown stays Pending/Unknown even when Apple returns the
same resource. Denied, incomplete or contradictory data never proves absence.
This does not introduce manual “mark recovered,” retry or quota-consuming work.

## Public DATA and lifetime

`operation.recovery` is nullable and only present on a complete terminal Review:

```
{ schemaVersion: 1, scope: "local-ios-bundle-attempts",
  attempts: [{ reference: { operationId, ownerGeneration }, displayName,
    observedAt, status, reason, nativeSettlement, cancellationRequested }],
  hiddenUnresolved }
```

At most 32 rows/32 KiB; status is capped at 64 KiB. All fields remain historical,
not current account disposition, signing readiness or permission. The private
Register review still requires exactly NotReturned + ReviewRequired; historical
publication is separate and cannot mint that review. A known joined denied or
inconclusive query can show local history without enabling registration.

The detached publication retains no Session, SourceBook, NativeUse, material or
runtime. Its backing/construction and bounded status copies are charged through
the existing retained/active census. Existing worker/frame sizes, one-page GET,
W=1200s/H=1210s, fixed call cap and `min(W, F+10s)` remain unchanged.

Context loss withdraws the optional list and increments the original status
revision even when idle. Only exact history-to-null withdrawal is permitted at
a newer revision; terminal result replacement, list revival/replacement and
Unknown downgrades still refuse. UI selection disappears on currentness loss,
reconnect, pending reads/invocations and uncertainty. Its exact API/witness/epoch
continuation is checked across publications, including the existing Prepare
source refresh; a synchronous cancellation cannot renew that intent.

## Integration

New source is the `apple_provisioning_protocol` child
`desktop/src-tauri/src/apple_provisioning_recovery_selection.rs`, plus the two
focused tests below. Apply `apple-provisioning-resume-hooks-20261020.patch` only
in Root integration. Its 14 existing paths are:

- Native protocol, saved Apple facet/native facet, original saved owner,
  saved Apple tests and real journal tests (six Rust paths).
- Apple types, closed protocol, controller and Bundle registration view.
- The two existing Apple Node fixtures (add nullable recovery only).
- Existing Python worker fixture (three malformed/read-only response variants).
- Ordinary `desktop/package.json` test list (one new test filename, no dependency).

No new lib/bootstrap/bridge/App/Host/Store/transport hook or qualification flag.
The patch applies to Root's current source; the full before/after files are
temporary review copies, not an alternate implementation to commit.

## Verification and limits

Against complete composed sources, not extracted functions:

- `node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 desktop/tests/apple-provisioning-recovery.test.mjs`:
  **10 passed, 0 skipped**, 243.0ms, including original reply/read races, stale
  key/saved context, reentrant cancellation, missing/contradictory lists and
  monotonic withdrawal.
- The two existing Apple controller/protocol suites: **23 passed**, 289ms before
  the narrow withdrawal/continuation amendments; the final new suite exercises them.
- `PYTHONPATH=src python3 -B -m unittest -q tests.unit.test_apple_provisioning_resume`:
  **3 passed**, 0.931s. Uses the complete existing worker and inert provider/C-A-W
  fixture: denied/partial/truncated/foreign data, same-response comparison and
  rejection of changed account/reference/target, with zero real provider calls.
- New leaf formatted and complete modified Rust files parsed with rustfmt only.
  **Eight new Rust tests are authored, not run here**: four DATA scope/bounds
  tests, three original projection/context-loss/missing-join tests, and a real
  temporary Store reopen/read/fence regression. No positive native facts are
  synthesized by these tests.

Root still owns actual Rust/TypeScript graph checks and installed Mac/runtime
qualification. No native, provider, account, private credential, signing or
network operation was executed; this packet enables no capability flag.
