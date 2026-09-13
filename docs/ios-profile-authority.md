# Apple provisioning-profile authority

## What is authenticated

Fresh iOS signing preflight, candidate preparation, public signing-evidence
extraction and **every new IPA send** require independent Apple authorization of
the provisioning profile. Merely decoding CMS, finding a certificate in a profile,
signing the containing app, or attesting the workflow does not establish that
Apple issued the profile.

`ios_profiles.py` reads one bounded, non-symlink regular-file snapshot. It
authenticates the outer CMS before reading its plist, then authenticates the
**exact embedded `DER-Encoded-Profile` CMS** before decoding its DER dictionary.
The complete typed identity, grants, certificates and validity fields must still
correlate; see [entitlements](ios-entitlements.md). Primary and nested apps or
extensions use their own profiles. Profileless code cannot borrow those grants.

`ios_profile_auth.py` requires a single attached, definite-length DER SignedData
envelope, id-data payload, version 1 or 3 and exactly one signer. DigestAlgorithms
and SignerInfo must agree on SHA-256, SHA-384 or SHA-512. Input/output are bounded
to 4 MiB; there are at most 16 distinct, bounded certificates. Unsigned, detached,
encrypted, concatenated, malformed, legacy-only or unsupported formats reject.
There is no decode-only fallback or operator override.

System `/usr/bin/openssl cms -verify -binary -inform DER -noverify` verifies the
signature and returns the signer and content to fresh private files. Here
`-noverify` disables **only X.509 trust**: it does not disable signature checking
and never confers authority by itself. Nonzero exit, partial/changed output, a
different payload or a signer absent from the original CMS certificate set fails.

## Production-purpose trust, not generic X.509 trust

`ios_profile_trust.py` passes that actual signer first to Security.framework's
`kSecPolicyAppleiPhoneProvisioningProfileSigning` policy. It supplies explicit
toolkit-pinned Apple roots, disables network fetching and keychain lookup, and
requires anchors-only evaluation. It checks native statuses, disabled settings,
successful evaluation and **Unspecified** trust result, not a user-granted Proceed.
The three-certificate chain must begin with the exact CMS signer, use the exact
production profile-signing/iPhone CA names, and end in a pinned Apple root.
TEST-purpose, macOS-profile, arbitrary self-signed and generic trusted certificates
cannot substitute for the production iOS profile authority.

Only public roots are bundled in `src/mobile_release/data/apple-profile-roots.pem`;
their entire DER set must match these independent SHA-256 pins:

| Apple certificate | SHA-256 |
| --- | --- |
| Apple Root CA | `b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024` |
| Apple Root CA G2 | `c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050` |
| Apple Root CA G3 | `63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179` |

Sources are Apple's HTTPS [Apple Root](https://www.apple.com/appleca/AppleIncRootCertificate.cer),
[G2](https://www.apple.com/certificateauthority/AppleRootCA-G2.cer) and
[G3](https://www.apple.com/certificateauthority/AppleRootCA-G3.cer) endpoints.
There is no runtime download, application-supplied anchor, verification-date
override or trust-policy fallback. Root/purpose changes require a reviewed toolkit
upgrade. The native policy/API semantics are documented in Apple Security at
commit `db15acbe6a7f257a859ad9a3bb86097bfe0679d9` (`SecPolicy.c`,
`SecPolicyPriv.h`, `SecTrustPriv.h`); they are not generic stable cross-platform APIs.
Unavailable required APIs fail closed on unsupported tooling.

Apple's profile-signing policy intentionally omits signer-chain wall-clock
validity and networked revocation checks. This is **offline cryptographic
production issuance**, not proof of current account, device or revocation state.
Authenticated profile CreationDate/ExpirationDate and the application's actual
distribution-certificate validity remain separate current-time gates. The old
public Apple regression CA certificates are not current consumer signing assets.

## Isolation, deadlines and installation

### Original-child and group ownership

The QA-007 native contract uses an outer capture owner, a custodian, a moving
keeper and the profile-validation worker. The fixed Python helpers use `-I -S -B`,
private HOME/TMPDIR, literal system PATH and no inherited Store, signing, OIDC or
injection variables. The custodian establishes a private session; the keeper
starts the worker/OpenSSL in a group named by the keeper's original PID, then
moves itself into the custodian's group before READY. Its live or unreaped
identity reserves the worker group for cleanup even after the worker exits.

Each original direct child needs an exclusive consuming waiter and continuing
waitability, starting **before** native creation, including libc startup/error
cleanup. Read-only native SIGCHLD inspection rejects `SIG_IGN` and `SA_NOCLDWAIT`
without changing the caller's handler. Only helpers reset their own policy and
assert it. A blocked SIGCHLD or nonreaping custom handler is not rejected merely
for being nondefault. Callers must not steal these child statuses or later enable
automatic disposal; admission cannot detect every outside violation. See the
[complete native ownership prerequisites](../SECURITY.md#native-validation-process-ownership).

The custodian alone consumes the keeper's status, **after** permanently retiring
every worker-group signal/probe, including signal zero. For every child, numeric
signal/probe routes retire before the first potentially consuming wait, including
a nonblocking poll. Only a genuinely returned no-result permits another poll.
An ambiguous wait/publication or `ECHILD` is UNKNOWN, never authority to retry a
numeric identity. `EPERM`, an apparent zombie or a completed result is not group
absence; reaping the reservation and then probing again is forbidden.

Native `posix_spawn` actions install only fixed helper descriptors 0–7 and worker
descriptors 0–2, with other inherited descriptors closed **before** interpreter
execution. Owned atomic CLOEXEC duplicates and native buffers remain leased until
their actual creator settles. No caller descriptor census, foreign close or
inherit-then-repair fallback substitutes for this boundary. Imports acquire no
capture processes/descriptors, tasks or native admission.

### Deadlines and result acceptance

The capture, custodian and OpenSSL limits remain 30, 25 and 20 seconds, with one
three-second cleanup grace. All are clamped to the caller's shared
`InspectionDeadline`; nesting, late spawn publication, repeated cancellation or
backpressure must not restart a timeout. The independent custodian watches parent
loss and starts descendant cleanup on genuine worker termination or any failure,
cancellation or deadline. It must not wait for COMMIT or output EOF to start the
cleanup needed to produce that EOF.

After genuine worker/keeper receipts and confirmed group cleanup, the custodian
reads the bounded verified-content file, emits the existing bounded completion
frame and **actually closes** its output writer. Only then can the outer owner
observe real output EOF, validate the result and request COMMIT. COMMIT is not
permission to begin cleanup. A failed, rejected or never-started transaction does
not wait for success-only COMMIT and must not invent child statuses.

To confirm control retirement, the custodian publishes `QUIESCING` while retaining
its original control reader. The outer owner permanently retires further grants,
finishes any valid pending cancellation within its original bound, and closes
its control writer. It never completes a pending positive grant just to deliver
a later cancellation. The custodian requires actual clean control EOF and an
accounted reader close for a confirmed FINAL offer. This notification is neither
a result nor proof of finality; incomplete framing, uncertain writes/closes and
missing EOF remain adverse, and no deadline is renewed.

The separate versioned control protocol has closed no-attempt, reaped and unknown
terminal forms. Its FINAL is only an **offer**, not an accepted result or the
custodian's own wait receipt. Acceptance additionally requires the genuine
custodian wait, status EOF, exact earlier worker/keeper receipts, actual group
absence before retirement, all owned closes and task joins, and final pending
cancellation/error/deadline checks. A kill status, payload marker, protocol PID
or success flag alone cannot pass. Cleanup/close failures veto apparent success;
native output, profile contents and private exception text are never diagnostics.
Producer finality is distinct from authentication success: a proved settled
rejection or lifecycle failure may permit exact-owned scratch cleanup, not
acceptance of a failed profile. A failed FINAL requires the corresponding genuine
custodian outcome and all the proof above. Custodian/keeper error, cancellation,
deadline or close uncertainty after its terminal offer must force an unconfirmed
helper outcome. Final caller cancellation still vetoes authentication acceptance
after physically settled cleanup.
Neither the completion marker nor the control protocol supplies Apple issuer
authority; the independent CMS signature and production-purpose trust gates above
remain mandatory.

### Scratch, installation and cancellation

Profile scratch uses explicit mode-0700 `mkdtemp` ownership and mode-0600 inputs,
not an automatic temporary-directory finalizer. `CaptureFinality` and
`ScratchLease` permit removal only with genuine `NO_PRODUCERS` or `FINALIZED`
evidence **and the unchanged exact directory identity**. A null PID is not proof
that creation was never attempted. UNKNOWN creation, wait, close or task settlement
retains required scratch/native/FD custody across exceptions, garbage collection
and outer unwind; a later capture must not silently abandon it in the same process.
Cleanup uses bounded expected entries and no-follow directory-relative operations;
unexpected entries or a replaced/symlinked scratch root remain failure, not
permission to recurse or remove a different tree. The namespace must cooperate:
the final identity check and removal are not one atomic inode-conditional
operation against hostile concurrent same-UID replacement.

Catchable cancellation attempts bounded cleanup; it does not promise deletion
when finality is unknown. SIGKILL, power loss or runner destruction cannot run
cleanup, and a native call can outlive its deadline without becoming a joined
task. End the affected process and establish producer finality before inspecting
or removing the **exact owned path**, or dispose of the hosted VM. Never delete
other tasks' similarly named directories or retry signals against guessed PIDs.

Local credential checks authenticate before P12 extraction. Temporary signing
authenticates one snapshot and checks current dates/UUID before any keychain
inspection or mutation. It stages those same bytes in a private destination file,
flushes/fsyncs and atomically links without overwriting another profile. Identical
existing profiles are reused; different or unsafe destinations reject. Cleanup
removes only the owned unchanged inode/bytes; replacements/edits survive and
cleanup failure is an error, not success.

Default main-thread cancellation is deferred across file-descriptor/inode
registration, the installation-to-caller cleanup handoff, and fixed keychain,
profile and authentication-resource cleanup. `cancellation.py` registers cleanup
before acquisition, protects its first instruction and exit dispatch, and claims
each cleanup attempt only once. Parent raw descriptors, child/task records, private
channels and scratch have explicit owners; authentication capture borrows the
outer guard until scratch cleanup finishes. A selector/descriptor failure cannot
skip independent child, stream or scratch-finality accounting. Cancellation during
restoration cannot return success; body errors survive successful cleanup, and
cleanup or handler-restoration failures remain errors rather than being hidden by cancellation.

This guard catches only default main-thread SIGINT/SIGTERM, installs SIGINT first
and restores it last. It does not replace custom handlers or install handlers from
worker threads. Setup and the consumer's build body remain interruptible, not
deferred through a successful yield. Repeated guarded signals cannot abandon
registered cleanup; restored host handlers resume their normal behavior. This is
not a universal cancellation API or a promise of SIGKILL/power-loss cleanup.
No profile bytes are written before initial inode identity is known. If that
identity cannot be recovered after an I/O error, the empty
private stage is preserved and cleanup failure is reported; it is never deleted
using pathname guesses. Ambiguous descriptor-close errors are not retried against
a potentially reused descriptor. End that process and inspect only its exact
owned private residues before retrying; do not delete other profiles.

**Separate open blocker QA-003:** overlapping local signing contexts still share
global keychain settings and profile lifetime. Atomic installation alone is not
a concurrency lease. Do not overlap local signing preflights; this is pending
remediation, not an accepted production-readiness limitation.

**Separate open blocker QA-004:** the outer `materialize_build_inputs` scratch and
client-file restoration do not yet use this cancellation-safe ownership. Default
cancellation during those outer cleanup entries can leave decoded material or
temporary client configuration. Inner signing/profile cleanup does not prove those
outer resources were restored. Inspect the exact owned scratch and configured
client targets before retrying; preserve originals and other tasks' files. This
requires separate remediation and prevents a production-readiness verdict.

## Recovery and verification scope

Accepted historical candidates retain their **original authenticated intent and
exact artifact bindings**. Reconciliation/raw-receipt completion does not rerun
today's issuer policy, renew profiles, rebuild or re-sign. Every actual new send,
including a separately authorized retry, must pass current validation. Do not
repin an existing evidence chain to manufacture stronger historical assurance.

Required credential-free regression coverage (not a claim that a run passed):

- `test_ios_profile_authority.py`: malformed CMS, real signature/tamper checks,
  real public Apple production-policy positive and wrong-purpose negatives.
- `test_ios_profile_trust.py`: native ABI, statuses, explicit anchors, disabled
  lookups, result/chain/name checks and CF ownership failure injection.
- `test_profile_processes.py` and the native ownership suites: real original-child
  reservation, spawn/IO cancellation, orphaned pipes, ancestor loss, closed
  terminal schemas, output overflow/backpressure and cleanup before COMMIT.
- `test_ios_profile_installation.py`: exact snapshots, collision/symlink/FIFO
  rejection, partial writes, atomic-link interruption, real acquisition/handoff/
  cleanup signals, failed ownership registration and foreign-file preservation.
- `test_default_cancellation.py`: real signals at raw-reader/source/capture
  acquisition, cleanup dispatch/entry and handler restoration; short/failed IO,
  repeated signals, ambiguous close/foreign FD reuse, failed selector/scratch
  cleanup and exact before-fallback resource assertions.
- Existing entitlement, current-upload and recovery suites: rejection before
  Store access and no retrospective authentication of accepted candidates.

Native ownership controls must cover read-only SIGCHLD admission, original wait
publication and UNKNOWN retirement, actual pre-exec descriptor closure, shared
deadlines, creator/task settlement, exact scratch identity and retained uncertain
scratch through exceptions/GC. Closed schemas and mocks are not native ABI or
cleanup proof. Recompute the complete source and installed-wheel method inventory
from the final source; historical native totals do not include new regressions.

Intentional-UNKNOWN process/resource controls use the fixed singleton captures
and healthy complements in the [isolation contract](verification.md#intentional-unknown-test-isolation).
An expected negative result retains actual custody until genuine outer-domain
disposal; it cannot clear registries, authorize another case or acquire a new
observer to replace a missing original receipt. Known-timely ordinary timeout,
backpressure and I/O-fault fixtures must still prove settled cleanup, not pass
by accepting unexpected UNKNOWN.

Use the [disposable hosted verification workflow](verification.md). Its macOS
source and installed-wheel gates each require complete authority and ordinary
native partitions without skips or missing prerequisites; standalone runner
invocation is not the supported CI entry point. Protected `test` requires both
Linux and macOS success; the installed-wheel gate checks resources outside checkout.
Synthetic signed-profile success uses an explicitly named issuer-policy seam;
the real policy rejects that same input. These tests plus the genuine public
Apple authority positive **are not** a current protected Distribution
archive/export rehearsal. The consumer release owner must perform that
non-public check on the pinned Xcode with their actual supported profiles before
activation; no private profile or Store mutation is needed for repository CI.
