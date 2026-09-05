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

Two fixed toolkit-only Python processes use `-I -S -B`, private HOME/TMPDIR,
literal system PATH and no inherited Store, signing, OIDC or injection variables.
An independent supervisor owns the native worker/OpenSSL process group, watches
its original parent and enforces a 25-second limit even if an ancestor validator
is killed. Parent capture is bounded to 30 seconds, OpenSSL to 20 seconds, within
the shared artifact inspection deadline. Backpressured output remains bounded;
failure or interruption cannot authorize a partial result. Native output and
profile contents never appear in diagnostic errors.

The supervisor retains group ownership even on success: it emits one bounded,
versioned private completion frame, then unconditionally kills its own group,
including itself. Only the exact complete frame **and** intentional kill status
can succeed; ordinary exit, partial marker, extra bytes or a kill alone reject.
The terminal marker commits already verified content, not a checksum-based trust
claim. No new authorization check follows it. Parent deadlines and cancellation
still override completed output. This closes the success handoff race when the
original parent dies before it can clean up descendants.
Parent shutdown has a separate three-second bound and requires both a reaped
leader and observed process-group absence. macOS can return `EPERM` for an
already-zombie group; this triggers bounded reap/retry, never permission-based
success. Unresolved shutdown fails closed, even after a complete result, while
output handles and replaced cancellation handlers still receive cleanup.

The parent owns mode-0700 temporary workspaces and mode-0600 inputs. Catchable
failure/cancellation removes owned scratch and kills/reaps the owned group,
including unexpected descendants after apparent success. Parent SIGKILL, power
loss or runner destruction cannot execute a `finally` block: private scratch can
remain, including a creation-before-spawn window. Hosted-runner disposal or
explicit cleanup of the **exact owned path** is required; never delete other
tasks' similarly named directories.

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
each cleanup attempt only once. Parent raw descriptors, selectors, worker groups
and private scratch have explicit owners; authentication capture borrows the
outer guard until scratch cleanup finishes. A selector/descriptor failure cannot
skip independent group, stream or scratch cleanup. Cancellation during restoration
cannot return success; body errors survive successful cleanup, and cleanup or
handler-restoration failures remain errors rather than being hidden by cancellation.

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

Credential-free regression coverage:

- `test_ios_profile_authority.py`: malformed CMS, real signature/tamper checks,
  real public Apple production-policy positive and wrong-purpose negatives.
- `test_ios_profile_trust.py`: native ABI, statuses, explicit anchors, disabled
  lookups, result/chain/name checks and CF ownership failure injection.
- `test_profile_processes.py`: real process groups, spawn/IO cancellation,
  orphaned pipes, ancestor kill before/after actual supervisor completion,
  malformed/partial frames, output overflow/backpressure and owned cleanup.
- `test_ios_profile_installation.py`: exact snapshots, collision/symlink/FIFO
  rejection, partial writes, atomic-link interruption, real acquisition/handoff/
  cleanup signals, failed ownership registration and foreign-file preservation.
- `test_default_cancellation.py`: real signals at raw-reader/source/capture
  acquisition, cleanup dispatch/entry and handler restoration; short/failed IO,
  repeated signals, ambiguous close/foreign FD reuse, failed selector/scratch
  cleanup and exact before-fallback resource assertions.
- Existing entitlement, current-upload and recovery suites: rejection before
  Store access and no retrospective authentication of accepted candidates.

`python -I tests/workflow/run_native_profile_checks.py` is required on macOS CI
and rejects skips/missing prerequisites. Protected `test` requires both Linux
and macOS jobs; the installed-wheel native gate checks resources outside checkout.
Synthetic signed-profile success uses an explicitly named issuer-policy seam;
the real policy rejects that same input. These tests plus the genuine public
Apple authority positive **are not** a current protected Distribution
archive/export rehearsal. The consumer release owner must perform that
non-public check on the pinned Xcode with their actual supported profiles before
activation; no private profile or Store mutation is needed for repository CI.
