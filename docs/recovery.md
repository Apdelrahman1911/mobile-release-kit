# Recovering an interrupted Store operation

Recovery continues the original candidate; it never rebuilds, re-signs, changes a
version, overwrites evidence, or silently adopts a different Store build. Keep the
original tooling SHA. Do not edit an intent, manifest, receipt, or diagnostic journal.

## What becomes durable before mutation

Every platform and stage first performs a read-only preparation. Its immutable
`<stage>-operation-intent.json` binds the application repository and source tree,
the original operation checkout, version/build, signed artifact hashes, metadata,
Store destination, exact confirmation, predecessor hashes, and observed Store
preconditions. Apple review inputs use domain-separated HMAC commitments, not
plaintext or guessable unsalted hashes.

The workflow then removes preparation credentials, creates an authenticated
`intent-provenance.json`, attests both documents, and uploads the fixed-name intent
artifact. Only after that upload succeeds may it acquire execution credentials
and mutate a Store. Candidate handoffs are retained for 90 days before upload;
the Store job also attests the validated AAB/IPA before mutation.

| Stage | Intent artifact | Final evidence artifact |
|---|---|---|
| Candidate | `mobile-release-candidate-intent-<platform>` | `mobile-release-candidate-evidence-<platform>` |
| External testing | `mobile-release-external-intent-<platform>` | `mobile-release-external-evidence-<platform>` |
| Production preparation | `mobile-release-production-intent-<platform>` | `mobile-release-production-evidence-<platform>` |

Candidate intents also retain the exact platform-scoped `store-metadata.zip` before mutation.
External/production intent bundles include the exact predecessor evidence needed by their operation
under `candidate/` and, for production, `external/`.
Final bundles include the complete original intent bundle under `operation/`, the
raw Store readback, the sealed receipt, a candidate manifest when applicable, and
`workflow-provenance.json`. A missing redundant standalone intent artifact does
not invalidate a final bundle containing its original authenticated proof.

The producer proofs bind every payload file's SHA-256/size, the actual workflow
attempt and job ID, the application repository, and the pinned reusable workflow.
The resolver verifies GitHub attestations, service artifact digests, complete safe
archive layouts, producer-job records, raw/readback agreement, and the full chain.
A checksum alongside untrusted content is not authentication. A job/run marked
successful is not sufficient; conversely, cancellation after a valid final upload
does not invalidate that completed platform. The service does not expose an
independent ZIP uploader-job identity; the proof authenticates payload production.
Archive entry counts and central-directory bytes are bounded before the ZIP
parser allocates entries, including standard single-disk ZIP64 handoffs. Prefixed,
multi-disk, trailing-data, and nonstandard extended ZIP64 layouts are rejected.

## Choose the correct continuation

| Situation | Action |
|---|---|
| Complete authenticated final evidence already exists | Reuse it unchanged. No Store read/write, new attestation, or replacement artifact occurs. |
| Intent exists but final evidence does not | Resume/reconcile that intent and original handoff on its original source checkout. |
| Build succeeded; preparation failed before any possible mutation | Prefer **Re-run failed jobs**. The exact preserved build-job digest is required. Later-attempt preparation also requires proof that every earlier execute step was skipped after a pre-execution failure. |
| Rerun-all finds a handoff without an authenticated intent | Stop. Do not rebuild or treat artifact absence as proof of no previous mutation. |
| Earlier intent/required handoff is expired, deleted, conflicting, or unverifiable | Stop and retain remaining evidence. Restore the exact authentic evidence or obtain owner/Store support resolution; never substitute a rebuild. |
| A complete TestFlight receipt says review is pending | Wait, then make a **new external-testing dispatch**, with the same candidate references and no `recovery_run_id`, to record a newer observation. A rerun preserves the old immutable receipt. |

GitHub's rerun window is shorter than artifact retention. Outside that window,
start a new dispatch of the **same pinned workflow**, supply `recovery_run_id`,
and retain the normal exact stage confirmation, for example
`candidate:ios:1.2.3:123`. A recovery dispatch never prepares replacement authority.
Its current head/ref is authorization to recover; the intent's original
`operationSource` commit/tree controls the application checkout. Those identities
are recorded separately, not made equal by rewriting `GITHUB_SHA`.

Select the run that actually holds the evidence you need. If **A** authorizes an
operation and recovery **B** completes it, a later dispatch **C** reuses B with
`recovery_run_id=B`, retaining A's embedded intent and B's original final bytes.
Rerunning B keeps B's original `recovery_run_id=A` input. Until B has a complete
final, a new recovery must still select A; incomplete B is not an alias to A.
Every resolution, even reference-only reuse, requires the normal exact version/
build confirmation (`both` is supported only for candidate/external selection).

There is no global run search or alias registry. Complete-final reuse applies to
the current run and the explicitly selected run: selecting only A cannot prove
whether a different recovery B already finished. Preserve and use the returned
evidence run IDs, rather than redispatching against A after B completed. For mixed
platform origins, reuse each platform separately or supply its returned evidence
run ID to the next lifecycle stage.

For partial Android/iOS success, use the returned per-platform
`android_evidence_run_id` / `ios_evidence_run_id` and artifact IDs. A successful
Android final may remain in the original run while iOS finishes in a recovery run.
External testing accepts `candidate_android_run_id` and `candidate_ios_run_id`;
production additionally accepts `external_android_run_id` and
`external_ios_run_id`. The common `candidate_run_id` / `external_run_id` inputs
remain convenient when origins are identical. Leave the common input blank for
mixed origins; conflicting common and platform-specific references fail.
References select artifacts, not authority: every consumer authenticates them.
An already-prepared operation must retain its exact original predecessor hashes.

## Google Play reconciliation

Recovery opens a fresh edit rather than replaying an old edit ID. It compares the
complete source/destination tracks, the exact version code and Publisher-reported
AAB SHA-256, and every unrelated release. A completed exact target is read back
without another promotion. A matching uploaded bundle can be attached without
uploading it again. Production also verifies all affected listings and ordered
images against the authenticated metadata target. Unrelated drift stops execution;
there is no automatic rollback or overwrite of someone else's Console changes.

Play has no supported mapping-file digest readback. When a candidate includes a
mapping file, recovery may replace only that version code's mapping with the same
intent-bound bytes and requires an acknowledged edit commit. This is a scoped
same-byte replay, not independent Store proof of the mapping's hash.

Authenticated Android recovery retains the original artifact, signer, configuration,
version and source bindings and checks the AAB's bounded ZIP structure. Completing
evidence or reconciling an accepted bundle does not rerun current signing eligibility:
entering `jarsigner`'s certificate-expiry warning window cannot strand a prior upload.
Every **new logical AAB upload**, including a same-byte retry, still requires full
current validation with the pinned bundletool and Java 21 `jarsigner`/`keytool` in
a credential-free child process. Missing tools, disallowed signature warnings or changed bytes
block that send; there is no fallback to historical validation.

After validation the adapter rereads the complete Store precondition and rechecks
the final file path, size and hash before sending. It never restarts an invalidated
edit automatically. The owned singleton upload sets request retries to zero and
bypasses Supply's outer retry loop; Google's normal same-session resumable upload
and authentication refresh remain distinct from another logical upload. An ambiguous
failure returns to retained-intent reconciliation, not an automatic new send. APKs,
batch uploads, working-directory discovery and ambient binary-path defaults cannot
bypass this boundary.

Local Play dispatch signals survive subsequent validation failures and cancellation.
The 2 MiB journal retains its first upload/mapping dispatch entries plus recent
history (at most 256 entries after each write); compaction never invents or erases a
dispatch. A mismatched, malformed, removed or changed loaded journal is not repaired
or overwritten. Preserve it and use the original authenticated intent in a new
protected invocation with an empty output directory to reconcile Store state.
Workflows serialize Store operations and use one local journal
writer; the journal is not a multi-process release lock or independent provenance.

## Apple candidate attribution

Apple does not expose an uploaded IPA digest or a reliably correlated Transporter
delivery identifier. A later process therefore polls read-only first. A matching
version/build, or continued absence, is not byte-level attribution or permission
to upload again.

After inspecting the original intent/handoff and resolving attribution, an owner
may use a **new protected recovery dispatch** with:

```text
recover-ios-candidate:<intent-sha256>:<exact-ASC-build-resource-id>
```

This adopts only the exact non-expired, valid application/version/build after
server-time and identity checks. The receipt explicitly labels operator-authorized
reconciliation; it does not claim Apple proved IPA byte equality.

If the owner has independently established that no prior upload was accepted,
a new first-attempt recovery dispatch may instead authorize:

```text
retry-ios-candidate-upload:<intent-sha256>:<original-ipa-sha256>
```

Only the retained original IPA may be sent. A timeout or another absence poll is
not independent resolution. The grant cannot be replayed by rerunning the recovery
workflow. If ambiguity remains, continue read-only reconciliation or obtain Apple
support assistance; do not allocate a replacement build to hide the uncertainty.

Expired signing assets do not by themselves prevent reconciliation of an already
accepted build: the original authenticated preparer proof and exact original hashes
remain authoritative for that historical validation. They do not authorize a new
upload. Every Transporter dispatch, including an explicit same-byte retry, performs
full current IPA/signing/profile validation, a final absence read and an immediate
expiry gate. No arbitrary validation date, ignore-expiry option, rebuild or re-sign
is available. Complete-final reuse needs neither native tools nor the original binary.

## Apple resource-creation ambiguity

External testing and App Review preparation reconcile each supported resource
separately, preserving other versions, localizations, review submissions, groups,
and screenshot sets. Apple does not document idempotency or a finite visibility
deadline for these create requests. Later-process absence never automatically
permits another POST, including group relationship insertion.

TestFlight what-to-test writes only target `metadata.iosLocales`. Every other
observed locale keeps its exact text and resource ID. Foreign changes, removal,
replacement, or extra locales—even after one configured write—stop execution; the
toolkit never restores unrelated text over someone else's changes. The original
raw what-to-test digest and configured target must still match the intent.

When required creates remain unobservable, the diagnostic supplies a bounded,
credential-free inventory and an exact confirmation:

```text
retry-ios-operation-creates:<intent-sha256>:<inventory-sha256>
```

The inventory binds the complete public observation, missing logical resources,
their exact parents/dependencies, and target hashes. After independently resolving
whether prior requests were accepted, the owner may authorize it in a **new
protected recovery run, attempt 1**. A changed inventory requires new approval.
Each logical create gets one dispatch budget, consumed before the request; network
errors never restore it. No side-effect write starts before required grants exist.

Screenshot part PUTs can replay the same reserved byte ranges before commit.
An expired or terminally failed incomplete reservation can be replaced only when
its nonce/name/size prove it is owned by this operation and full preservation
checks pass. Original/reference, completed, duplicate, or ambiguous assets are
never deleted. Cancellation after deletion requires fresh create authorization
before another reservation when the outcome is uncertain.

## Local partial evidence and limits

`mobile-release ci <stage>` is a guarded CI interface, not a workstation publishing
command. The reusable workflows coordinate `--prepare-operation`, intent
sealing/attestation/upload, then `--execute-store --operation-intent <original-path>`.
`--validate-operation-intent` validates context without Store execution; it is not
an attestation producer. A successful local JSON checksum or a diagnostic journal
cannot replace the protected workflow's durable authenticated intent.

A valid existing raw receipt can finish failed manifest/receipt persistence without
another Store request. Existing immutable files are never overwritten. A surviving
partial manifest requires its original matching raw observation and producer;
otherwise preserve it and use a new empty output directory with the **same intent
and original artifacts** for reconciliation, not a new candidate build.

Diagnostic journals explain progress but are not promotion authority. They retain
bounded histories and execution claims, omit credentials/private review values and
upload URLs, and are uploaded only after credential cleanup. Recovery still needs
the original HMAC key version and valid account access. Keep that key available for
the retention window; rotate deliberately rather than silently changing old
commitments.

The native validator's private process group is cleaned up on cancellation or
setup/IO failure after launch, including failures before its first output read.
Neither child output nor a failed validator can authorize an upload.

Retention, GitHub/Store availability, and Apple owner-attribution decisions are
external requirements. Neither Store provides a cross-platform transaction or a
general exactly-once network guarantee. Every unprovable transition fails closed;
no recovery path starts a public rollout or enables automatic App Store release.
