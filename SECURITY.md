# Security policy

## Reporting a vulnerability

Do not open a public issue containing a secret, signing asset, private Store response, tester identity, reviewer contact, or exploitable release-pipeline detail. Use GitHub's private security-advisory reporting for this repository. If private reporting is unavailable, contact the repository owner through a private channel listed on the GitHub account and include only enough non-secret detail to establish contact.

No maintainer will ask for a keystore, P12, provisioning profile, P8 key, password, demo credential, or service-account key to reproduce an issue. Use sanitized fixtures.

## Security boundary

Mobile Release Kit protects the binding among reviewed source, final signed artifacts, Store build IDs, protected promotions, and readback evidence. It cannot prove:

- that an application owner’s legal/privacy/content declarations are truthful;
- that Store agreements, banking, tax, pricing, territories, or tester eligibility are correct;
- that Google, Apple, GitHub, or a runner is uncompromised;
- that a project-specific build script is safe merely because it was configured;
- that a public release should occur.

The final public-release decision is intentionally outside automation.

## Credential rules

- The shared repository and fixtures contain no real credential or account/application identifier.
- Consumers configure fixed environment-scoped names; reusable steps explicitly bind them and
  `secrets: inherit` is forbidden.
- Google CI uses OIDC/Workload Identity Federation rather than exported JSON keys.
- Apple P8, P12, profile, and Android keystore material are scoped to jobs that need them.
- Promotion/production jobs never receive build-signing assets.
- Candidate application build jobs have neither Store credentials nor `id-token: write`; Store/OIDC jobs never invoke application build, prepare, or project-check commands.
- Signed build output crosses to a fresh Store runner through an immutable fixed-name handoff.
  Original preparation verifies its trusted build-output/service digest, safe layout, file hashes,
  final identity and signing. Recovery additionally requires the original attested intent's complete
  artifact binding; artifact names and adjacent checksums alone cannot authorize Store access.
- Fresh iOS preparation inspects the required IPA/archive and supplied symbols on private
  immutable input snapshots. Every native image, bundle/resource counterpart and present dSYM
  must correspond. Signature-neutral hashes permit only bounded signing changes; complete signed
  artifact hashes authenticate the actual retained bytes, including signature-allocation slack
  that native codesign may not cover. UUIDs alone do not authenticate binaries or debug data.
  Original archive/symbol bindings remain mandatory for incomplete-operation execution/recovery.
- Every iOS signed entitlement is compared with its own app/extension's modern DER profile
  content, with typed allowlist rules and explicit architecture selection. Profileless code cannot
  borrow parent grants. Fresh per-slice certificate extraction prevents stale-leaf reuse.
  Both profile CMS layers additionally require real signatures and the exact production Apple
  iOS provisioning issuer under independently pinned roots, with keychain/network lookup disabled.
  Native workers require independent parent-liveness/deadline/process-group containment
  and no inherited Store/signing capabilities; see the process-ownership contract below.
  This is offline issuance, not live revocation status;
  see [profile authority](docs/ios-profile-authority.md). The separately confirmed QA-003
  global local-signing concurrency blocker remains open; atomic profile installation is not
  a lifetime lease and does not justify a READY verdict. QA-004 also remains open:
  default cancellation can interrupt outer build-input scratch/client restoration.
  Inner profile/signing/native-resource ownership does not cover that outer owner.
- Historical Android recovery retains authenticated original signing/identity evidence rather than
  requiring an accepted build to remain eligible for a new upload. Every actual new AAB send repeats
  current pinned native validation in a credential-free child, full Store-state classification and a
  final exact-byte check. It cannot fall back to APK/batch/default discovery or a retrying Supply
  upload. The owned request disables logical retries without replacing Google's resumable protocol.
- Expected public certificate fingerprints are reviewed application policy.
- Local files live outside the repository with restrictive permissions.
- Initialization uses a root-directory lock and private recoverable staging on supported local
  Linux/macOS filesystems. Never commit/upload `.mobile-release-init-prepare/`,
  `.mobile-release-init/` or `.mobile-release-init-cleanup/`: their backups can contain original
  configuration. Ignore installation itself can be interrupted. Preserve pending state and use
  `init --recover`; unknown journals and intervening edits are conflicts, not authorization to
  overwrite or delete user files. This coordinates cooperating commands, not a hostile same-user
  process or a compromised filesystem. See [initialization recovery](docs/init-recovery.md).
- Temporary credential cleanup is attempted on catchable exit paths and failures are reported.
  Profile/signing/authentication owners protect default main-thread cleanup dispatch/entry,
  track exact resources and report ambiguous cleanup without unsafe retries. QA-004 means
  outer materialization still requires correction; it is not an accepted cleanup exception.
  Hard termination/power loss cannot run cleanup; private residual paths and global local-signing
  state require owned cleanup or hosted-runner disposal, not a blanket guarantee of deletion.
- Secret values and private identities are not logged, summarized, cached, attested, or uploaded as artifacts.
- Store jobs remove preparation ADC files before intent attestation/upload, then separately acquire
  execution credentials and remove them before diagnostics/final actions. Apple P8/review/HMAC values
  are step-scoped. Deleting an ADC file is not revoking the Store job's OIDC capability: all pinned
  Actions in an `id-token: write` job remain within that privileged trusted-computing boundary.
- Private Apple review equality uses domain-separated HMAC-SHA256 under a dedicated protected
  256-bit key. Neither private values nor guessable plain hashes enter evidence. Retain its original
  key version for recovery; rotation is an explicit owner responsibility.

## Native validation process ownership

The QA-007 contract applies to current AAB/IPA validation and the private profile
authentication capture. It is not a generic subprocess API or protection from a
hostile same-process reaper. The outer→custodian, custodian→keeper and
keeper→validator edges each require exclusive consumption of the original direct
child's status and continuing waitability, from before native creation through
libc startup/error cleanup and final accounting. Open3 waiters, `Process.detach`,
catch-all waits and implicit subprocess cleanup must not acquire those statuses.
Cooperating callers may wait their own different exact children.

Admission reads native `sigaction(SIGCHLD, NULL, ...)` without changing caller
policy. `SIG_IGN`, `SA_NOCLDWAIT`, unknown ABI or failed inspection rejects before
creation. Blocking SIGCHLD alone is not automatic status disposal; a nonreaping
custom handler need not be replaced. Only fixed helpers reset their own policy
and assert it again. Callers must maintain this prerequisite: an admission
snapshot is not a universal detector of future status theft or policy changes.

The fixed outer owner, custodian, keeper and validator have separate lifetimes.
The custodian owns a private session. The keeper establishes the validator group
with its original PID, starts the validator there, then moves out before READY.
Its live or unreaped original identity reserves that group until the custodian
permanently retires **every** group signal/probe, including signal zero. The
custodian alone may then consume the keeper's status. A saved PID, observed exit,
permission error or success-shaped result is not lifetime authority.

Before the first potentially consuming direct-child wait, including a nonblocking
poll, its numeric signal/probe route is permanently retired and the in-flight
wait is recorded. Only an actually returned no-result permits another poll.
`ECHILD`, lost publication or ambiguous consumption is absorbing **UNKNOWN**,
not permission to probe, signal or wait a guessed replacement identity.

Public `posix_spawn` admission uses Ruby Fiddle with `need_gvl: false` or
CPython `ctypes.CDLL`, rooted native buffers and explicit creator/descriptor custody.
Intended sources are atomically duplicated CLOEXEC at descriptors >=8; there is no
non-atomic fallback. Child file actions install only helper descriptors 0–7 or
validator descriptors 0–2, closing other inherited copies before interpreter
execution. The owner must never enumerate, close or change foreign descriptors
to simulate this boundary. Imports do not acquire capture processes/descriptors,
tasks or native admission. Unknown native-call settlement retains the required
buffers and leases instead of freeing resources still in use.

Cleanup begins on validator termination, failure, cancellation or deadline,
without waiting for result EOF or COMMIT. Unused Ruby writers close after handoff;
profile output closes after descendant finality and **before** COMMIT. A FINAL
frame is only an offer: acceptance requires genuine original validator/keeper/
custodian wait receipts from their respective owners, group absence before
retirement, actual EOFs, owned closes, joined tasks and final
error/cancellation/deadline checks. Failure or proved no-attempt branches need no
success-only COMMIT and invent no status.

Producer finality and validation success are separate. A positively settled
lifecycle failure is not automatically UNKNOWN. Only genuine custodian/keeper
exits `0` (settled normal/rejection handling) and `2` (positively settled lifecycle
failure) can support finality; exit `1`, other codes and signals cannot. A failed
FINAL needs genuine custodian exit `2` and every finality obligation above, not
just the exit code. This helper-only convention does not change the validator's
application exit codes or authorize successful validation. A custodian/keeper
error, cancellation, deadline or uncertain close after its terminal offer must
force the unconfirmed helper outcome, not a positively finalized failure. Final
outer caller-error and cancellation checks still veto validation acceptance
after settled cleanup.

Deadlines and the first failure's single cleanup grace cannot be renewed by a
late result or repeated cancellation. Original caller interruption is preserved
separately from cleanup errors; private native output and automatic task exception
reports are not diagnostics. A native syscall that outlives its cutoff is not a
joined task or a successful cleanup. The deadline owner remains runnable; it does
not forcibly cancel a thread that still holds native resources.

Private profile scratch has an explicit mode-0700 owner, not an automatic
temporary-directory finalizer. Removal requires genuine no-producer/finalized
evidence and the unchanged exact directory identity. UNKNOWN survives exceptions,
garbage collection and outer unwind, retaining still-required task/native/FD
custody and preventing silent reuse in that process. End that process and establish
producer finality before exact-owned-path cleanup or use disposable-runner teardown;
never infer safe deletion from a marker, empty process snapshot or similar name.
Cleanup is bounded and no-follow, not recursive deletion of unexpected content.
This requires a cooperative namespace: a final identity recheck is not an atomic
conditional unlink against hostile concurrent same-UID pathname replacement.

Verification controls that intentionally retain UNKNOWN have no exception to this
custody rule. A passing negative assertion or a nested driver's wait/EOF cannot
clear retained records, authorize reuse/removal or supply a missing native receipt.
They require genuine enclosing-domain disposal, not a newly acquired observer.

These are implementation and verification requirements, not a native pass or an
overall READY verdict. Required source/installed-platform evidence remains
separate from fixture readiness and VM disposal. QA-003 signing lifetime and
QA-004 outer restoration remain independent open blockers.

## Supply-chain rules

- Consumers explicitly select the shared repository, pin its workflows by full commit SHA, and
  provide that same SHA as `tooling_sha`; the reusable core contains no personal account default.
- Shared workflows pin every third-party action by full commit SHA.
- Every reusable job aborts its steps unless `runner.environment == github-hosted`, as defense in
  depth. This first-step assertion is not a server-side scheduling control and cannot prove that an
  eligible malicious runner never received a job payload or secrets.
- Before activation, a repository or organization administrator must verify and preserve runner
  policy/inventory so no self-hosted runner can match the pinned `ubuntu-24.04` or `macos-26`
  labels. Trusted custom runner groups are outside the shared contract.
- Workflow Python calls use safe-path mode and `python -P`, preventing an application package in the current directory from shadowing the pinned release module.
- Runtime dependencies are locked and upgraded through reviewed pull requests.
- Store jobs and capture require exact Ruby 3.3.12, Fiddle 1.1.2 and Bundler 4.0.16
  with the Gem checksums recorded by the lockfile. Missing dependencies reject;
  capture does not install gems or select another runtime. Runtime/ABI upgrades
  require reviewed source and genuine native revalidation.
- Store runtime probes and lanes pin `BUNDLER_VERSION=4.0.16`,
  `BUNDLE_IGNORE_CONFIG=1`, `BUNDLE_AUTO_INSTALL=false` and `BUNDLE_FROZEN=true`
  after environment allowlisting. Explicit admitted bundle locations remain
  supported; ambient configuration cannot authorize automatic installation or
  lockfile rewriting. Admission checks both the isolated helper's default Fiddle
  and the locked bundle's actual loaded origin, not one version string for both.
- A candidate records repository ID, commit, Git tree, configuration/metadata hashes, final artifact hashes, public signers, Store build IDs, and original authorization/actual execution/final producer identities.
- Promotion never rebuilds.
- Reruns fail closed when source, bytes, signer, Store identity, or receipts disagree.
- Before mutation, an attested immutable intent must already exist as a retained service artifact.
  Every final package retains the original intent proof and complete predecessor chain.
- Promotion authenticates fixed-path workflow-dispatch producers in the current application
  repository at their exact run attempt/job and pinned reusable workflow. It does not equate the
  producer with the latest attempt, nor reject a completed platform solely because another job
  failed. Application source, operation checkout, and current recovery dispatch are distinct claims.
- Workflow sidecars authenticate the complete payload inventory, including raw receipts. GitHub's
  service artifact API does not independently identify the uploader job. ZIP digest, producer
  attestation, exact job interval, immutable service selection, and complete chain are all checked;
  none alone is equivalent to the full authority proof.
- Complete final evidence is reused without reissue. Incomplete operations reconcile only under
  original intent and exact bytes. No missing-artifact fallback rebuild, overwrite, or silent Store
  adoption is allowed. See [recovery limitations](docs/recovery.md).
- Apple candidate reconciliation may require explicit owner attribution because Apple supplies no
  uploaded IPA digest. Later-process absence cannot authorize another create/upload request.
  Recovery is not a generic exactly-once network guarantee and never enables public release.

## Supported versions

Until the first stable major release, only the latest `0.x` release receives security fixes. After `v1.0.0`, the latest minor release of the current major is supported. Consumers remain pinned and must upgrade deliberately; security advisories will name affected versions and safe commits.
