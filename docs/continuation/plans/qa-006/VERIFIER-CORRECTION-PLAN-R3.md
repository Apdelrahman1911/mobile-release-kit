# QA-006 verifier R3 — strict observation and complete Git-object consumption

**PROPOSED; independent plan approval required.** Ignored verification tooling
only. This is not permission to edit the seven-path first-party candidate,
remediate QA-007, create acceptance/freeze records, or dispatch final gates.

## Reanalysis, evidence and root causes

Read the original QA-006 finding, verifier R2 plan, all current20 helper/static
files and relevant consumers. The distinct R1 implementation review is
REQUEST_CHANGES, report SHA256
`d8075f2907489da26d398ca383a18f5d125d01e7008cac6f211e741ac2177254`.

- **VRI-01:** the numeric reader accepts arbitrary repeated/unordered modifiers;
  `classify_group` equates every Z-prefixed value with stopped. Root's actual
  synthetic-query replay independently confirmed CLEAR for ZE, ZEs, Z++, ZNN
  and Z+E. Valid Darwin ?E/?Es must be recognized as indeterminate, not globally
  malformed or stopped. Read Apple adv_cmds-237 ps state emission and the retained
  real Darwin observations, not merely the existing Ruby test's regular expression.
- **VRI-02:** `git_tree` computes objects but the later native Git consumer requires
  their existence. The independent fresh-repository exact command failed128.
  Root also investigated a no-index replacement: clean differences return1 and
  whitespace differences3 on the actual Apple Git. Root's expectation of0 was
  incorrect, so that exploratory command exited1; its raw results and all13
  reaped children/zero signals/owned scratch cleanup are preserved in
  `reanalysis-verifier-r2/`. Do not relabel the attempt as passed. This plan
  chooses an owned complete object store, not that alternative or a weakened gate.

No consumer finding is added for these ignored-verifier defects; they are QA-006
verification prerequisites. R5 first-party review and QA-007 remain separate.

## Exact VRI-01 behavior

Change `verification-final-r1/process_gate.py` and its controller proof cases.
Separate complete numeric identity parsing, supported state syntax, conservative
liveness classification, and bound-group decisions.

1. Accept an explicit union of supported Linux/Darwin emitted states and ordered,
   nonrepeated modifiers: base `[RSDTtZXIWUH?]`, then `[<N]?X?E?V?L?s?l?\+?`.
   Reject zombie/exiting combinations even if the regular expression matches.
   Preserve duplicate PID, nonnumeric/invalid identity, byte/time/diagnostic and
   empty global-output rejection. Do not collect process argv/environment.
2. A syntactically valid Z state without E is stopped. Base ?, H, X, or E modifier
   means indeterminate. Other supported states are live. Never infer readiness
   or death from `not live`.
3. Validate all rows' identities/syntax, then classify only the recorded group.
   A valid unrelated indeterminate row cannot invalidate an otherwise complete
   absent/stopped target observation. Malformed rows still invalidate the query.
   A foreign UID or reused original leader remains an immediate UNKNOWN conflict.
4. Distinguish a recognized indeterminate group from identity/format UNKNOWN.
   `_group_completion` may reobserve live/indeterminate state only inside its
   original fixed cutoff. Check the cutoff again after the real query returns;
   late CLEAR is not accepted. Persistent uncertainty fails and retains output.
   `observe_groups` used immediately before cleanup may conservatively return
   UNKNOWN rather than retry. No observation authorizes any signal.
5. Retain the direct unreaped-child reservation as the only signal authority;
   no process-controller ownership/cancellation redesign or timeout widening.

## Exact VRI-02 behavior

Keep the computed source tree binding, but reconcile the actual consumer using a
new `verification-final-r1/frozen_diff.py` helper. Update `bindings.py`,
`freeze.py`, `gate_list.py` and the explicit helper inventory. No real index,
ref, object database or user worktree may be written.

1. Add an early **prepare-frozen-diff** gate before any install/build/full test.
   Exclusively create a mode0700 owned bare Git directory under the QA-006 owner,
   with its own identity/ancestry/source-tree marker. Use the fixed trusted Git
   executable, clean environment, no external helpers, no templates/hooks, no
   alternates, no network and no inherited Git config/attributes/replace objects.
   The actual Git object format must be SHA-1; unsupported formats fail explicitly.
2. Materialize the complete base tree/blob graph from the frozen HEAD's tree,
   and the complete proposed tree/blob graph from frozen current bytes/modes.
   Base object reads use explicit IDs from the bound real repository; do not copy
   unrelated objects, refs, the index, all history or other worktree content.
   Verify object type, byte length and canonical SHA-1 while copying/creating;
   the proposed root must equal the independently computed/approved tree.
   Object filenames come only from validated hexadecimal IDs, never source paths.
3. Check every required object with native Git and independently read back its
   hash/type/bytes. Run the actual native `git diff --check` between the two tree
   IDs in the isolated store, with external diff/textconv disabled. Require actual
   exit0, retaining the full bounded raw diagnostic result on failure. This
   includes modifications, deletions, executable modes and untracked additions.
   No special exit-code reinterpretation or omission of untracked files.
4. Seal the complete directory/object inventory, baseline/proposed tree IDs,
   source snapshot, tool identity and actual command/result in a new record.
   Existing owner/store/seal records are conflicts, not resumable/adoptable output.
   Failed preparation retains its exact incomplete objects/evidence; it cannot
   consume a later successful gate or continue to expensive verification.
5. Replace the existing late **diff-check** argv with this helper's `--check`.
   Revalidate freeze/owner/seal/full inventory/all object bytes and rerun the same
   actual Git whitespace command; do not regenerate missing/changed objects.
6. Add **cleanup-frozen-diff** alongside the other final cleanup gates, only after
   prior-gate success/log bindings and fresh accepted worker observations. Use
   the existing descriptor-bound inventory deletion, after another freeze/owner/
   seal/inventory match. Retain diagnostics/IDs/hashes; delete only this owned
   disposable object store. Unknown/replaced/symlinked/content-changed stores or
   failed/unknown worker evidence prohibit deletion. User source, real Git state,
   accepted snapshots, original failures and required wheels remain untouched.
7. Thus the43 existing required gates remain covered, the late diff consumer is
   corrected, and the explicit list gains preparation and cleanup:45 gates.
   Freeze forbids preexisting store/marker/seal/final records. All executable
   helpers and static inputs, including the new helper, are review/freeze-bound.

## Tests and independent verification

Before final authorization, run preparation-only copies in new owned namespaces.
Do not create final acceptance placeholders or run the final dispatcher.

- Real synthetic query children for all five reproduced malformed states, valid
  zombies/modifiers, live states, ?E/?Es/H/X/exiting, malformed Unicode/identity,
  duplicates, foreign UID and reused leader. Include unrelated indeterminate
  rows, target indeterminate-to-stopped inside one cutoff, persistent uncertainty
  and a query returning after the original cutoff. Veto all historical signals.
- Follow the actual `observe_groups`/`prior_workers` cleanup consumption using
  real owned synthetic outputs: malformed/indeterminate/foreign/reused evidence
  must produce zero deletion and zero signals. Only a complete positive control
  can remove its exact owned output, after actual direct children have joined.
- Fresh real synthetic Git repos with absent proposed objects: changed, deleted,
  new/untracked, executable and empty/unchanged cases. Demonstrate actual native
  Git accepts clean graphs and rejects trailing whitespace in both changed and
  newly added files. Compare computed roots with actual Git's object IDs.
- Reject frozen source drift, missing/corrupt/wrong-type objects, altered seal,
  unexpected files, preexisting/replaced/symlink store and identity ambiguity.
  Inject failure during materialization and after native diff before seal; no
  later gate or cleanup may treat incomplete preparation as successful.
- Check both real indexes/refs/source hashes before/after; no alternates or real
  object write; only synthetic/owned graph output may change. Prove complete
  owned-store cleanup and nondeletion of a neighboring foreign control file.
- Rerun controller10/protocol24 and prior25 adverse proofs, safe-path startup,
  shell syntax and every helper AST. Record observed exits, not just assertions.
  A distinct reviewer must inspect actual diff and raw proofs, including the
  new state-to-cleanup and source-to-native-Git contracts.

## Compatibility, security, recovery and documentation

These helpers target the explicitly pinned local Python3.11/Git toolchain and
Linux/macOS numeric formats; production/runtime/package interfaces do not change.
Newly rejected unsupported states fail/retain rather than guess. Approved Git
snapshot/source hashes remain authoritative; a checksum does not create ownership
or authenticity. All Store/credential/build-vs-Store boundaries are unaffected.

Main regression risks are overbroad state acceptance, rejecting legitimate
unrelated Darwin rows, deadline reset/late success, skipping object descendants,
path extraction, accidental writes through Git environment/alternates, premature
seal publication and deletion of an unowned directory. Test each explicitly.
Cancellation, process error and write failure invalidate the run and retain
evidence; do not retry/adopt a partially completed one-shot final invocation.

Update ignored implementation/proof/coverage records only. No public behavior
changed by this verifier plan. Preserve every historical failure and explain
the exploratory no-index exit-code error. After independent implementation
acceptance, the separate safe-isolation/delivery plan is still required for
QA-007's unsafe shared-host Ruby paths. No final freeze/dispatch is authorized
until first-party implementation, verifier and that isolation contract are all
independently accepted. Original findings, protected delivery/actual main CI,
QA-003's later full matrix, fresh whole-repository audit and feature report remain.
