# Use a hosted reservation in the saved-version editor

This is a convenience for **unverified proposed values**, not another allocator
or a native reserved-version handoff. Manual editing remains unchanged. Pasting
does not verify a ledger, refresh Store observations, grant a build, or change
protected CI settings.

## User flow

1. Run the separately configured, protected **reserve-version** Actions workflow
   for the intended saved platforms. Its existing App/Store prerequisites and
   Android temporary-edit consent still apply. Copy the complete result JSON.
2. Select that local project in Desktop. In **Git**, refresh Changes. It must be
   clean at the result's exact source commit and full branch ref.
3. On the Dashboard, expand **Use a version reserved by GitHub Actions**. Paste
   the result and choose **Open and prefill version values**. This uses ordinary
   native Open, not `openReserved`. Missing or changed sources/configuration and
   existing dirty or stale version drafts are refused without overwriting them.
4. Choose **Validate and review values**, inspect the complete native file
   preview, and explicitly confirm **Save version values**. The proposed two
   values must produce the exact expected after-hash. A bad pasted comparison
   refuses only this proposal; it does not accuse native status of corruption.
5. After a successfully observed Save, refresh Changes in Git again. Return to
   the Dashboard and optionally choose **Prefill the commit message**. Only the
   original regular version file may be modified or staged, on the same commit
   and branch. A nonempty message, even whitespace, is never replaced; author
   fields are preserved.
6. In Git, explicitly stage the version file and review the **whole** commit.
   The message has a fixed subject, blank line, and exact reservation trailer.
   No stage, commit, push, or candidate workflow starts automatically. Make the
   one version-only child commit expected by the [CI consumer](version-ci-20261020.md),
   then run the separate candidate workflow.

Git and saved-file observations are independent, **not an atomic snapshot**.
The message shortcut checks current project/path/source compatibility, not the
exact bytes of a future commit. CI remains the ledger/row/one-parent/two-span
authority. An unchanged, failed, lost, late/unknown, or unrelated Save cannot
enable the message shortcut. Navigating to Git after an already-settled Save
does not discard its original submission; pre-Save context/ABA guards remain
strict. Changes to proposed strings retire the import and preserve a manual
draft instead.

## Bounded data and original ownership

- The worker adds only `sourceRef` and `configSha256` from its held source. The
  config hash covers the original raw bytes, not normalized JSON. No extra
  provider/source read or native API is introduced. Old result lines lacking
  those fields need ordinary manual review.
- The parser caps the original input at **8 KiB** before JSON parsing, then
  enforces the closed canonical result shape. Exactly one optional terminal LF
  is allowed. Duplicates, extra fields/lines, tags, invalid values and overlapping
  or empty replacement spans refuse. Two-component marketing names such as
  `1.2` remain supported. Native platform policy still decides valid edits.
- Replacement offsets never drive writes and are not retained. The pasted
  `authorityVariable` is unused data and is not retained or installed.
- Before ordinary Open, the existing App-owned GitRead/Repository instances
  must agree on their actual settled successful Observe and current revision.
  Same-project means the user's selected original service/project and matching
  source, not authenticated hosted project identity.
- Only the existing controller retains its original Open/Prepare/Apply/Close
  and submitted token. All three import pre-send points recheck after listener
  notifications. Draft revision/baseline/absence are captured before Open, so
  pending edits, including edit-and-restore, cannot be overwritten.
- Retiring a proposal can notify subscribers. The outer field edit declines if
  those notifications replace its exact selected draft or original binding;
  the newer draft survives while the original Close remains retained.
- Intentional Save-boundary Git invalidation does not become a new source
  lease and does not deadlock its own native Review. The optional message copy
  requires a genuinely new successful Observe afterward. No native deadlines,
  finality, recovery, or owner gates are weakened.

## Integration and verification

Apply `version-hosted-import-hooks-20261020.patch` to the Root composition:
`App.tsx` supplies the existing immutable service/project/Git instances and a
navigation callback; `package.json` registers the new parser/controller tests.
The patch contains **only those two targets**. Preserve other concurrent App
routes and test-list entries. The author used Root `21270c1d` plus its current
staged Push hooks; exact before/after bytes are retained with the task evidence.

Focused checks (inert ports/fake provider, no native/provider operations):

```sh
/opt/node/current/bin/node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 \
  desktop/tests/hosted-version-import.test.mjs desktop/tests/release-version-edit.test.mjs
PYTHONPATH=src:tests/unit python3 -B -m unittest \
  test_version_hosted.HostedAllocationTests.test_actual_allocator_pending_ack_then_single_put_final_state_and_exact_two_spans
```

The Node cases use actual existing UI controllers with inert native callbacks;
the Python case runs the actual allocator/journal against fake HTTP and owned
temporary fixture files. Neither proves native, DOM, hosted, or provider
behavior. Whole-TypeScript and actual app integration remain Root's separate
checks. No new process, network, dependency, Cargo, or platform test is required
by this source packet.

Author evidence: **46 Node tests passed**, zero failures/skips (1.149 s, including
13 new grouped cases), and the **one affected Python test passed** (0.041 s).
Logs are `.task-version-hosted-import/node-review-fix.log` and
`python-projection.log`; the earlier 45-pass Node runs are retained separately.
Distinct review found a reentrant draft-loss path in proposal retirement. The
new actual-controller regression reproduced the lost build value before the
fix (`draft-reentry-data-before.log`), then passed in both editing and reviewing
phases. Task-owned test callers returned; no worker remains running.
