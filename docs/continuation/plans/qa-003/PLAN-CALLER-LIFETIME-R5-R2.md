# QA-003 caller-lifetime correction R5-R2 — proposed

Supersedes unapproved R5. Read with approved R2/final R3 and R4-R2. R4's
descriptor correction is implemented and development-tested, not finally
approved. No R5 implementation has begun. This plan does not include QA-004
outer materialization cancellation or newly recorded QA-005 source authority.

## Reanalysis and root cause

R1 implementation review and actual isolated Git/Android reproductions establish
that discovery's Git fsmonitor and Android wrapper/final-copy signer use direct
subprocess execution outside the owned worker protocol. A descendant can survive
failure and overlap later iOS signing/cleanup. Static project selection also
unnecessarily invokes Git while signing is active. The platform loop continues
after build/teardown failure.

R5 plan review independently establishes the second connected cause: existing
catch/loop paths convert unconfirmed lifetime into ordinary failed diagnostics
and then run another command or private validator. The profile reap wrapper
erases ProcessError into ValidationError. Group containment alone does not prove
selector/pipe/descriptor/scratch/handler cleanup; optional discovery cannot
swallow all ProcessError(contained=True). Evidence remains in
PLAN-REVIEW-R5-CHANGES-REQUIRED.md and its actual-caller probes, including failed
initial probe reporting and corrected R2 result. These are not passing fixes.

## A. Structured lifetime failures and safe optional observation

Extend owned_process.ProcessError with an explicit cleanup_complete flag
(default True for compatibility), and a read-only fatal property equal to
not contained or not cleanup_complete. Add ProcessCleanupError(ProcessError)
whose constructor always sets cleanup_complete=False. Preserve dispatched and
contained meanings; do not infer either from a log message. This internal error
remains a ValidationError/CredentialError for external caller compatibility.

The owned runner uses ProcessCleanupError for cancellation ownership/restore
failure, inherited-owner refusal, selector or stream close failure and group
reconciliation failure. Aggregate independent close/reap obligations as now;
contained reports actual group certainty, and cleanup_complete cannot become
True because the group alone was reaped. An original ordinary timeout, malformed
output, bounded-output violation or executable absence is recoverable/optional
only after all cleanup obligations succeed. A native nonzero result already
means complete framed result and cleanup; it stays an ordinary failure.
KeyboardInterrupt/ProcessInterrupted is never optional absence or success.
Handler restoration/cleanup failure during cancellation remains explicit.

Do not expand the runner into a sandbox, kill other tasks/daemons/recycled PIDs,
or change IPC/framing/deadline/parent-death authority. No request retry added.

## B. Profile authentication must preserve fatal cleanup classification

In ios_profiles.py use the fatal error for owned raw-FD close, scratch cleanup,
capture selector/output close, borrowed-owner refusal and handler restoration.
Keep invalid bytes, failed issuer/signature verification, unavailable native
tooling and fully contained malformed completion as ordinary ValidationError.
_reap_profile_group must preserve structured uncontained error instead of
recasting it to ValidationError. Its OSError/SubprocessError fallback must be
fatal because no group-cleanup proof exists.

All independent resource closes still run. Capture cleanup aggregates selector,
group and output outcomes rather than allowing a later stream error to hide the
uncontained group result. Nested scratch/handler failures remain fatal even if
they replace a prior error; no wrapper may represent that combined failure as a
completed optional observation. Preserve borrowed guards, exactly-once close,
fork-owner rules, default cancellation130 and private immutable bytes.

Explicitly propagate fatal ProcessError before broad validation conversion in
credentials._validate_apple_signing_material and the pre-session authentication
in _temporary_apple_signing_environment. No native setup after failed profile
authentication. Completed invalid-profile results remain INVALID.

Review all shared consumers: ios._profile_details/nested identities, _validate_ipa,
ipa_signing_evidence, paired artifact validation in preflight, CI final validation
and Store preparation. Propagate fatal errors out of diagnostic conversions;
credential-free child validators may serialize a failing exit, but never continue
to an upload or claim success. Validate cleanup-error handling through actual
caller control flow with Store-call sentinels, not only exception superclass tests.
No issuer, entitlement, artifact, receipt or Store validation is weakened.

## C. Discovery and omitted Android commands

Add internal discover_project(root, *, include_git=True). Default public discovery
shape remains compatible. False performs the existing static platform scan only;
it starts no command and omits Git context. Use False in both run_ios_build calls,
run_android_build, Android materialization and both effective identity selectors.
Doctor keeps default discovery and reuses its single Git observation for the Git
report field instead of performing a second contradictory read.

discovery._run uses run_owned with root cwd,10s timeout, captured16MiB bound and
scrub_credential_capabilities(os.environ), imported locally to avoid credential/
discovery cycles. Return None only for completed nonzero or nonfatal fully-cleaned
ProcessError. Fatal error/cancellation propagates. Missing root/tool becomes an
optional observation only when no resources were left uncertain. Metadata env
input retains its existing role, not arbitrary runner/environment authority.

Move Android's Gradle wrapper and only the build-time final-copy jarsigner to
run_owned. Preserve argv, --no-daemon, cwd, committed version/build environment,
45min/120s timeouts, Gradle output discard,2MiB private signing capture, signing
capability subset and final-copy/signing order. Independent AAB validators and
Store upload remain untouched. No credential values/output in new errors.

## D. Complete caller/phase abort contract

Every command wrapper below handles ProcessError separately, propagating fatal
errors and retaining ordinary completed/nonfatal validation behavior:

| Wrapper | Fatal result must prevent |
| --- | --- |
| discovery._run → git_context/discover_project | Another Git query or downstream caller work |
| preflight._xcode_toolchain_finding → doctor | Later application/private/native checks |
| _effective_android_identity_finding | Later platform identity query |
| _xcode_application_identities | Later Archive/Debug query |
| _effective_ios_identity_finding prepare | Any Xcode identity query |
| run_project_checks | Next project command/phase/build |
| validate_signing_material platform loop | Firebase check or another platform validator |
| validate_store_material P8 wrapper | Later Store material checks/query |
| profile consumer wrappers in B | Later signing, artifact/project work or Store request |
| run_android_build/final signer/run_ios_build | Next platform or artifact check |

Additionally use explicit phase fail-fast guards so a failed diagnostic cannot
authorize later potentially expensive/private work even when a secondary ordinary
filesystem exception masks the original failure:

- _preflight returns its failing report after doctor, preflight project checks,
  credential prerequisites or private-material phase fails. It adds one actionable
  lifecycle SKIP explaining what was not executed. Metadata/static diagnostics can
  still be collected where they do not execute commands/private materialization.
- run_project_checks stops on first failure (including unavailable placeholder),
  no further command. effective_identity_findings stops after a failing platform;
  failed Debug query does not launch Archive. validate_signing_material stops
  after a failing platform result before Firebase/next platform. Ordinary checks
  keep their individual finding identifiers and failing status, not success.
- Build/materialization/teardown catches expected MobileReleaseError and OSError,
  appends platform failure plus SKIP, then returns immediately. Unexpected Python
  exceptions propagate and cannot advance the loop. KeyboardInterrupt is not
  swallowed. Both platform orders and preserved first-platform output matter.
- Public preflight catches fatal ProcessError separately from busy/pending lease
  admission and returns a fixed process-lifetime FAIL plus SKIP. No-session early
  uncertainty instructs the owner to end this invocation and establish exact
  worker/resource quiescence before retry; it does not invent a recovery session.
  If active signing recorded intent, normal cleanup and original pending recovery
  rules apply. After failure no new command is permitted except already-registered
  independent cleanup/reconciliation. Do not retry ambiguous work automatically.

An account lease covers the full preflight, not only active native signing; the
runner's parent/deadline supervisor contains actually dispatched early helpers.
Refusing uncertain cleanup is not a proof that an escaped/foreign service is dead
and not a grant to delete by PID/name. Preserve the explicit external quiescence
limitation and active-session journal recovery. QA-004 outer-owner cancellation
remains open; early return is not its fix.

## E. QA-005 source guard contradiction is separate, not waived

PLAN-REVIEW-R5 independently confirmed environment fallback can satisfy the CLI
source guard when actual HEAD observation fails. Root has assigned QA-005 and
retained its finding/reproduction/required remediation in the main ledger.
It will receive its own reviewed plan/implementation/gates/commit after QA-004,
before MRK-008/009/fresh final audit. This R5 correction preserves the current
fallback semantics only to keep the separate change scoped; it DOES NOT claim
unknown Git always refuses Store authority. Do not add a false passing regression
or treat mitigations from pinned workflow checkouts as a resolved CLI defect.
Existing positive source/workflow/recovery regressions must remain unchanged.
QA-005 will require actual authoritative HEAD/tree/status checks and real-repo
single-read-failure mutation-sentinel tests. No whole-project READY while open.

## Tests and adversarial verification

1. Actual owned runner: before/after-effect selector/pipe close, group uncertainty,
   handler-restoration refusal, cancellation plus cleanup failure; prove structured
   fatal vs safely contained timeout/missing tool. Observe real owned handles and
   children before fixture fallback; preserve foreign reused descriptors.
2. Profile wrapper: actual reap conversion and public load/credential/IPA consumers,
   group uncertainty combined with stream/scratch failure, owned handler/FD cleanup,
   no follow-on command. Ordinary malformed/untrusted profile stays INVALID; do
   not replace real Apple authority success with a permissive decoder.
3. Discovery: actual fixture Git fsmonitor with synchronous descendants and startup
   rendezvous. Success/nonzero/timeout/default cancellation, output limits, missing
   executable and scrubbed signing/Store/OIDC env. Observe child absent before
   return. Pure discovery in BOTH iOS build calls must not execute fsmonitor; use
   actual configured/discovered container and prepare/create/archive/export path,
   modeled only native/application tools, not project-selection predicates.
4. Android: actual production Gradle/final-copy jarsigner call sites with fictional
   script executables and descendants. Success/nonzero/timeout/cancellation and
   final AAB placement/order, exact version/signing env/no-daemon checks. No real
   Gradle, signing asset or Store. Actual child dead before fallback, not a mock of
   run_owned that asserts its own return value. Shared parent-death/fork tests stay.
5. Per-row table injection plus actual public preflight: inject a structured fatal
   at each before-active boundary and assert downstream sentinels never run.
   Cover contained=True/cleanup_complete=False, swallowed-profile reproduction,
   cancellation, failed ordinary validation, early report/no-session guidance and
   native pending-session recovery. Test phase fail-fast for secondary filesystem
   failure, both platform orders, Android-only, no-build and offline/online modes.
6. Two-platform actual build composition: successful first output retained if the
   second fails; failed first materialization/build/cleanup prevents second platform
   and artifact/project commands. Successful first permits second. Do not synthesize
   a passing artifact result to hide failure. Existing complete return/output and
   credential-scope contracts must remain compatible apart from documented fail-fast.
7. Update only obsolete subprocess mocks at changed boundaries. Add tests to already
   mandatory source/native/wheel caller/composition groups or extend gate inventory
   explicitly. Re-run original probes preserving their negative historical output.

## Files, compatibility, risks, documentation and final gates

Production: owned_process.py, ios_profiles.py, discovery.py, preflight.py,
credentials.py, android.py and ios.py. Call-graph inspection may identify another
shared catch that must propagate; document it and review the actual change.
Tests: owned process/callers, profile/credential/preflight/build/discovery and
local signing composition; isolated fixtures/native gate routing as necessary.
Documentation: local-signing, integration/troubleshooting, credentials/README,
SECURITY/CHANGELOG as needed for precise fail-fast, no-session quiescence, pending
recovery and unchanged QA-004/QA-005 limitations. No config/schema change.

Compatibility changes are intentional reduced diagnostic continuation and fixed
fatal reporting. Positional config/discovery public fields and CLI exit semantics
remain (FAIL1, confirmed cancellation130). No new runtime dependency. Key risks:
misclassified cleanup; broad catch losing fatal state; changed import graph or
version/signing env; exception masking on cleanup; missed pure-discovery caller;
no-build/single-platform regressions; confusing local recovery with Store retry.

Obtain independent approval before implementation. Complete separate native-active
crash-matrix correction plan/review too. Then bind new complete intended-file
inventory, obtain distinct whole-diff implementation approval, freeze exact tree
and run all37+ project gates including Python/native/source-wheel, Ruby/WIF/
Fastlane/Bundler, actionlint, packaging/dependencies/pins and git diff --check.
Only after successful frozen verification: scoped QA-003 commit excluding user
AGENTS, normal protected PR/merge/main CI. Clean only task-owned disposable
outputs/workers. Continue remaining issues, mandatory fresh all-file/all-release-
path audit and conditional READY/feature report; no stage is implicitly delivered.
