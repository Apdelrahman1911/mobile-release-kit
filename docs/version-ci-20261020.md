# Use an existing reserved version in GitHub Actions

This optional path **consumes a completed shared reservation**. It does not
allocate on a hosted runner, configure GitHub automatically, save a version,
or authorize a build/upload. Manual versions remain the unconfigured default.

## First use

1. Commit configuration and other project changes **before** reserving. Use the
   existing connected counter and current Store-inventory flow in Desktop, or
   the explicitly delegated installed-CLI reservation. Wait for its original
   completed result. Failed/unknown work must settle or recover; do not select
   another candidate to work around it.
2. Open the separate reserved-version editor promptly, review and Apply. Make
   **one version-only commit** directly after the reserved source commit. Keep
   the version file's mode. In the reservation panel's “Use this reserved
   version in GitHub Actions” section, copy the commit message with its exact
   `MRK-Version-Reservation: <candidate UUID> <reservation row SHA-256>` trailer.
   The installed CLI's completed result also supplies this preparation DATA.
   Copying text does not commit files or extend the editor's original lifetime.
3. In the application repository's protected `mobile-candidate` environment,
   set the nonsecret Actions variable `MOBILE_RELEASE_VERSION_AUTHORITY` from
   that completed result. Restrict settings changes and keep the environment's
   existing reviewers/branch restrictions. It contains the already verified
   repository ID, shared project/ledger identity, genesis hash and checkpoint;
   users do not invent those values. Configure once for this same authority.
   Do not replace an existing value with a different counter or an older anchor
   to bypass a refusal.
4. Use pinned tooling containing this consumer and run the candidate workflow
   on that exact commit and full branch ref, with the same enabled-platform
   selection. Existing workflow, build and Store approvals remain required.
   The gate needs only the job's existing `contents: read` GitHub token. It
   receives neither Store credentials nor permission to update the counter.

The variable is intentional CI opt-in, not a reflection of a local GUI checkbox.
Neither variable nor trailer means **unconfigured/manual**, not “automatic
policy verified.” A configured variable without the trailer, or a trailer
without the variable, refuses. Bad settings, missing state, changed source,
expired reads and malformed responses never choose a manual fallback.

## What the consumer checks

`version_ci.verify_reserved_source` uses the existing allocation ledger and
version renderer, not another allocator or repository database:

- Fresh immutable repository-ID checks bracket the fixed ledger ref, ancestry
  from the retained checkpoint and exact commit-pinned ledger read. The existing
  bounded `Ledger` decoder verifies genesis, the full hash chain, versioned
  v1–v4 request/policy replay and monotonic high-water values. Candidate UUID and
  row hash must identify exactly the retained reservation, not a new request.
- Both raw commits are read through the existing owned Git process boundary and
  hashed as Git commit objects. Final commit F has exactly reserved commit B as
  its one parent; both trees also match fresh GitHub commit reads. The final
  selected branch, enabled platforms, configuration and original version hashes
  must match the complete reserved request.
- One **unfiltered** raw B→F diff must contain exactly one same-mode regular-file
  modification at the configured version source. Its before/after blobs are
  hash-checked, and the after bytes must equal the existing exact two-span version
  renderer for the reserved values. Equal off-path entries—including symlinks,
  gitlinks and modes—are not opened or blanket-rejected.

The initial supported association is deliberately one version-only commit.
Merge commits, tags, extra changes (including ignore/config setup), moved version
sources and alternative formatting refuse. The gate never creates that commit.
Rechecking or rerunning consumes the same row and cannot reserve another number.
Existing original workflow intents still govern whether a build/upload may be
repeated; consuming a row is not an exactly-once execution receipt.

The fresh gate is placed before application code/Store authentication in both
platforms' online/build jobs, before fresh Store preparation, and again before
the candidate intent is sealed. Seal requires the checked F/tree/ref to equal
both intent source bindings. Initial resolution and authenticated `resume` or
`complete` recovery do not acquire a new allocation/source prerequisite. A
failed gate counts as a pre-execution failure only with the original complete
job graph and an explicitly skipped execute step.

## Ownership, bounds and limitations

The native export is a pure projection of existing typed `Authority`,
`Checkpoint` and reservation data. Production obtains it only from the original
`Finished` after actual joins and NativeUse retirement, then publishes under the
same final source/currentness guard. Pending, poisoned, mismatched or failed work
cannot export. No renderer path, JSON field or copy output becomes native consent.
Legacy completed statuses without the new copy fields remain readable, but do
not fabricate settings.

Each CI check has one 60-second clock, at most 12 fixed Git reads and 8 fresh
GitHub reads, all through existing owners with the same cancellation guard.
Each call receives its remaining time (at most 10 seconds). Commit/diff output
is at most 16 KiB; each raw GitHub response is at most 1 MiB. Ordinary GitHub
callers' old default bounds are unchanged. These are byte/call/time bounds, not
a Python RSS guarantee. Native copy settings are at most 768 ASCII bytes and
remain within the existing 8 KiB native/2 KiB service status envelopes; there is
no new state namespace, runner, credentials endpoint or permission.

The shared counter coordinates **cooperating** writers using its protected
fixed branch and conditional writes. This read-only consumer neither repairs
nor strengthens that writer contract. Administrators rewriting/deleting state,
outside uploaders and uncoordinated clients are not prevented by a local mutex
or a copied checkpoint. Old Store observations embedded in a row are not fresh
Store eligibility or a complete historical inventory. Existing live Store
preflights remain necessary.

Direct hosted allocation is **not implemented by this slice**. It still needs a
genuine CI-bound current Store-inventory owner (keyless Play WIF and/or the
existing private Apple credential path), the same full candidate request and
durable pending-before-PUT/unknown-send reconciliation across ephemeral-runner
loss. A local `max + 1`, new candidate on retry, copied Desktop loan or temporary
runner file cannot replace those requirements.

## Integration and checks

Apply `version-ci-hooks-20261020.patch` with this module/tests. Its 15 existing
targets are based on `aa73eff3` (only the package test-list context was refreshed
to `d98d6927`, preserving its Git fast-forward test): the workflow runner/YAML; original native
state/finish and public/CLI projections; version panel/parser; test registration
and narrowly scoped old-fixture adaptation. There are no direct shared-tree
edits in the author worktree. Preserve later request-catalogue methods and union
the current package test list when composing.

Focused results in the author lane: **23 Python**, **30 Node** (4 new, 26 existing)
and **2 Ruby / 93 assertions** passed. All provider/Git process boundaries are
synthetic; the actual ledger, renderer, JSON adapter, command routing and parsed
workflow run normally. One added Python fixture initially lacked `history` and
one Ruby fixture needed Psych's YAML-1.1 `on` key handling; both were corrected.
Nine projected Rust files and five Python files passed syntax parsing only.

After integration, the focused commands are:

```sh
PYTHONPATH=src python3 -B -m unittest discover -s tests/unit -p 'test_version_ci*.py'
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 \
  desktop/tests/version-ci.test.mjs desktop/tests/version-reserve.test.mjs \
  desktop/tests/agent-version-reserve-access.test.mjs
ruby tests/workflow/test_version_ci_yaml.rb
```

Three new Rust tests are defined in the existing native state, service protocol
and installed-CLI test modules. They are **unrun** here; the real private-state
fixture checks projection/transitions, not invented native join authority.
Full TypeScript/Rust compilation, Mac/installed behavior and actual GitHub
Actions/provider execution remain unverified by this packet. No real GitHub,
Store, signing, publication or application-project mutation was performed.
