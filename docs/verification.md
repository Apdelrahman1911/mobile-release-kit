# Repository verification

## Scope and current status

This documents the smaller QA-006 verification candidate: fixed checks inside
fresh, disposable GitHub-hosted Linux and macOS job VMs. The selected architecture
does not constitute implementation acceptance or a passing native run. Confirm
the final reviewed source and actual Actions results before claiming delivery.

QA-006 corrects Ruby descendant **test-fixture** readiness and makes required
verification safe and reliable. Its fixtures must distinguish startup, genuine
readiness, a reaped leader, live pipe-holding descendants, and cleanup failure.
It does not fix **QA-007**, the separate production native process-group lifetime
authority finding. VM disposal cannot prove that the library cleaned its workers.

Do not run the native/process suites or the CI controller on a shared VPS,
developer login session, or self-hosted runner. Root access is not authorization
to do so. Historical handoff helpers, permissions, receipts and failed runs are
not executable instructions or evidence for this replacement.

## Supported CI entry point

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) is the entry point for
pull requests, pushes to `main`, and manual **verification-only** dispatches.
PRs, main pushes and the default manual `verification_target: full` select both
`ubuntu-24.04` and `macos-26`, Python 3.11, Ruby 3.3.12, and pinned
third-party Actions. Checkout does not persist Git credentials. Project package
installation is not performed by the setup Actions or directly as the runner.

Before dispatch, verify repository/organization runner policy: no self-hosted
runner may match these labels. The first-step `runner.environment` assertion is
defense in depth, not proof of server-side scheduling. Retain actual runner/image
metadata from the Actions job. Do not add container/service/self-hosted fallbacks.

Both native jobs have a 60-minute job timeout and read-only contents permissions.
The separate protected status job `test` succeeds only when **both** predecessors
actually succeed; failed, cancelled, skipped, unavailable or queued is not success.
Never bypass branch protection or dispatch release/Store workflows for testing.

For an intermediate macOS-only correction, manual `verification_target: macos`
omits Linux but runs the **same complete macOS catalog and owner path**. Only a
manual macOS selection can omit Linux; Actions compares its string value without
case sensitivity. Missing, empty or nonmatching values do not omit Linux. Its
aggregate `test` deliberately **fails** because skipped Linux is not a
pass. This supplies platform-specific candidate evidence, never full verification
or merge authority. Event/target-specific concurrency separates partial dispatches
from full PR/main/manual runs.

Publish intermediate candidates to a task-owned branch without an open PR and
explicitly dispatch that reviewed ref; verify the actual source commit, workflow,
run/attempt and image. Never dispatch the historical default-ref implementation
or a release workflow as a fallback. Finish partial runs before advancing the issue
PR, then require fresh full exact-source PR verification, independent acceptance,
normal protected delivery and actual main CI. Do not combine partial runs into an
invented full result or count an unexecuted gate as passed.

## Small implementation and command authority

The helpers under [`.github/scripts/`](../.github/scripts/) have separate roles:

| File | Responsibility |
|---|---|
| `verify_ci.py` | Exact committed-source snapshot, fixed gate catalog, source/wheel inspections, result parsing and sanitized final report. |
| `ci_sandbox.py` | One reserved nonprivileged identity, native isolation admission, original child/stream collection and domain finality. |
| `ci_provider_runtime.py` | Linux-only, bounded permission preparation of the exact selected provider runtimes before any test-identity launch. |
| `ci_prepare.py` | Bounded public dependency acquisition and hash verification; never package installation or project evaluation. |
| `ci_checks.py` | Fixed product checks, complete Python method outcomes, wheel/consumer validation and JDK signer scenarios. |
| `ci_process_observer.c` | macOS-only, unprivileged SDK/libproc observation of one fixture PID; no signaling or process enumeration. |
| `ci_native_authority.py` | Fixed macOS trust-service lookup and synthetic offline-evaluation controls; no general service-request interface. |

These are CI internals, not a general command-execution API. The reviewed
`required_gate_ids()` and `catalog()` select the complete platform sequence.
Do not pass arbitrary user commands, replacement interpreters, custom execution
roles, environment extensions, or shortened/subset gate lists. Internal sandbox
entry roles are not independently supported launch commands.

## Preparation and immutable inputs

The controller requires a clean checkout at the exact supplied commit. It checks
the Git tree, ordinary-file modes and each blob before creating a separate
root-owned immutable source copy; the original checkout is never a build root.

Preparation downloads only public, allowlisted HTTPS inputs selected by
[`.github/verification-tools.json`](../.github/verification-tools.json) and the
checksum-bearing `Gemfile.lock`. Redirects, sizes, aggregate bytes, archive members
and hashes are bounded. Preparation does not run a Gemfile, gemspec, downloaded
installer, project backend, or package import; it does not restore shared caches.

Provider images do not necessarily have permissions compatible with a distinct
numeric test identity. After setup and identity-collision checks, the disposable
Linux VM inventories only its selected Python/Ruby/JDK prefixes and removes
write bits that would let that identity modify them. It does not change owners,
runtime bytes, installation paths, signatures, cache parents or other versions.
Every access ACL, unknown ACL query, unsafe link, changed identity and partial
preparation fails admission. A validated bounded Linux default ACL may remain on
an ordinary directory: it governs new-child inheritance, not current access.
Its exact bytes (or absence) must remain unchanged through preparation and final
recheck; no provider nodes are created afterwards. No ACL is rewritten or removed.
Existing executable/runtime checks and read-only mounts remain mandatory;
permission preparation is not a substitute for native controls.

On the disposable macOS VM, the selected Ruby may be beneath runner HOME with
mode `0750`. The owner pins that exact directory and may add only other-search
(`0750` to `0751`), not read/list/write permission or group membership. The
subject policy permits only inode metadata for the exact canonical strict
ancestors of the selected Ruby prefix within HOME (at most16 directories).
These exact `file-read-metadata` literals do not grant contents, listing, xattrs
or access to descendants; the broad private-read denial remains. Cleanup and
write-positive policies do not gain these exceptions.

Before product execution, fixed outside-policy controls must access synthetic
readable files in HOME and beside the selected Ruby prefix, plus a named HOME
socket. Under the actual subject policy, original/fork-exec/detached controls
must obtain each allowed ancestor's metadata and resolve the selected Ruby path,
while being denied both synthetic files' reads/metadata, HOME/temp listing and
socket access, with no outside delivery. The sibling file lies beneath every
allowed ancestor but outside all admitted runtime prefixes, detecting accidental
subtree grants. No real private file or runner socket is probed. Policy text or
a successful Ruby launch alone cannot establish this effective boundary; the
ordinary Ruby numerical-identity command must also genuinely succeed.

The HOME and sibling-parent directory pins and synthetic fixtures remain owned
by this attempt; no other ancestor's permissions are changed.
Restoration of its original mode and removal of its fixtures require genuine
process finality and matching current identities/permissions; drift or unknown
cleanup remains failure and is left to disposal of this VM. These narrow
preparation operations must never run on a shared host, persistent cache or
consumer's HOME. They are not general permission-repair commands.

After validation, input files become read-only. Actual gem installation, venv
creation, editable installation and normal isolated wheel builds run offline as
the reserved test identity, using local pinned inputs. There is no fallback to
network resolution when an archive is missing or a checksum fails.

The environment is constructed from an allowlist with private HOME/TMP/config
paths, disabled ambient Git/pip/Bundler configuration, offline flags and required
Ruby-contract checks. It does not inherit proxy/preload hooks, SSH-agent sockets,
GitHub/cloud/Store secrets, signing material or interactive credentials. Synthetic
signer fixtures are public test data, not authority for live Store operations.

## Identity, filesystem and native isolation

One numeric UID/GID in 60000–64999 is selected once and reserved exclusively for
the job. Complete NSS and process-credential collision checks must pass; lookup
errors, uncertain visibility or collisions fail rather than choose another ID.
No login account is created, adopted, repaired or deleted. Test descendants have
cleared supplementary groups; they may not regain root or usable sudo authority.

Root owns the outer source/control directories and, before product execution,
the work directory's **parent entries**. Only designated work leaves are writable
by the test identity. Root-owning installed files alone is insufficient if their
parent names can be replaced. Completed installations/build inputs are frozen
only after producer finality. Original runner HOME/temp/control contents remain
inaccessible to product code; only explicitly admitted, non-subject-writable
runtime prefixes are exposed. Beyond the exact ancestor inode metadata described
above, the search-only preparation does not exempt unrelated HOME content or
metadata from the mandatory policy.

Linux uses distribution-provided `bwrap` for PID/network/IPC/UTS separation and
read-only mounts, followed by `setpriv` for the numeric credential drop, cleared
groups, no-new-privileges and zero capabilities. No user-namespace UID translation
is substituted. Temporary device/runtime views do not expose host control sockets.

Before any test-identity launch on that disposable Linux VM, the original owner
pins the single fixed `user.max_user_namespaces` setting, retains its original
value, establishes zero and checks actual readback. Every bubblewrap launch must
pass `--assert-userns-disabled`; numeric entry also requires zero. This prevents
the test identity from creating another user namespace with new mount authority;
dropped capabilities alone are not that guarantee. There is no alternate namespace
mapping or weaker fallback. Conditional restoration requires genuine producer and
reserved-domain finality plus the same node/current zero. Ambiguous effects, drift
or finality failure stay failed for VM disposal; restore and descriptor-close errors
are collected independently. Never apply this host preparation on a shared VPS.

macOS ordinary/product routes use a numeric `Popen` credential drop and inherited
`sandbox-exec` policy.
The ordinary policy denies networking and Mach lookup, restricts writes to task work,
protects runner/control reads, and restricts signals to the same sandbox. Native
controls must prove inheritance through fork/exec and detached descendants.

### Fixed macOS native-authority partition

Actual Apple trust evaluation needs the platform trust service even with explicit
anchors, network access disabled and keychain search disabled. Only the fixed
native-authority partition may look up the two literal endpoints
`com.apple.trustd` and `com.apple.trustd.agent`; Security.framework chooses its
real inherited-bootstrap route. This is not a service permission for ordinary
tests, builds, arbitrary commands or user-supplied inputs. Ordinary policy stays
unchanged and cannot acquire this grant by applying a second sandbox policy.

The same collision-admitted numeric identity executes precisely the five existing
`NativeProfileAuthorityTests` methods and the four unchanged tool prerequisites.
The remaining native tests run separately under ordinary policy. Source and
installed-wheel gates each require two genuine successful captures, their exact
nonempty/disjoint/complete method union, and no skips. Each original capture
retains its own wait, EOF, exit, finality, cleanup and persisted-output facts;
there is no manufactured combined process result. Failure retains completed and
unexecuted partition information and never authorizes a later launch.

Authority entry uses the selected Python with `-I -S -B`, explicit immutable
package specifications, fixed test helpers and fresh exclusive scratch. No
site/.pth startup, ambient configuration or prior writable work is admitted.
Parent inspection compares every selected package module/resource with the
source, including installed-wheel bytes and immutable modes. The unchanged
profile worker uses the same selected package. Its parent directory may be
listed for Python's package finder, but sibling file/module bytes remain denied;
listing a directory is not a site-packages subtree read grant.

Native controls require real outside positives and protected-read/write, inherited
descriptor, foreign-signal and IPv4/IPv6 TCP/UDP denials under the role. Finite
lookup-only controls distinguish known-present forbidden services from service
absence. No trust-store mutation, service management or daemon cleanup is used.

The fixed source-only first-application control uses opaque compiler/apply/free
functions from `/usr/lib/libsandbox.1.dylib`. These are source-backed **private
Apple SPI**, not a promised stable public API. Missing exports, incompatible
types, compilation errors or a failed initial positive fail native admission;
there is no library search or weaker fallback. Its exact immutable helper starts
as the same unprivileged identity, after resource limits, and applies the fixed
policy before any product code, Mach lookup or boundary probe. All other entry
routes retain their sandbox wrapper.

Non-expansion requires a successful first application of those exact owner-pinned
policy bytes, actual outside/ordinary controls, and actual before/after plus an
inherited exec-child's denied lookups. Only a completed application returning
zero, or the ordinary negative's apply-phase `-1` with immediately saved numeric
`EPERM`, qualifies for that comparison; unrelated errors remain failures. This
establishes operation permission refusal and observed non-expansion, not an
undocumented reinitialization-lock cause. Exit71 or English error text cannot
qualify it. Every known compiler resource is independently released, and original
capture/deadline/EOF/finality checks remain mandatory.

The fixed AIA probe uses four fresh synthetic chains/unique loopback issuer URLs
under the same authority policy: direct client networking remains denied, with
no AIA socket exception. The fixed trust-service route must still produce real
online/mutant fetches; a provider that also prevents those fetches fails admission.
After a common explicitly enabled network baseline, the online control must
actually fetch and accept; the offline
control disables networking while retaining certificate-parent lookup. A mutant
omits only that final disabling setter and must be detected by real fetches.
A separate negative ends with both network/keychain getters false, matching
product settings. BasicX509 itself defaults offline: this is not a default-true
claim or proof about deleting the production setter alone. Production policies
and the five real test methods are unchanged. All probe resources have their
original bounded owner and independent cleanup/finality checks.

The original canonical `/usr/bin/codesign` and clean system launch are part of the
Apple OS/provider trust basis for its default offline verification semantics.
File ownership/hashes are not a measured executing-process platform-status bit.
Per-evaluation offline settings also do not promise global OS network silence:
trustd can perform independent system maintenance. Its daemon processes and
caches are not task-owned. No real credentials, Store request or private signing
input is supplied; actual arbitrary project sockets remain denied.

Before product tests, synthetic admission checks exercise credentials, protected
files, ordinary local IPC, inherited descriptors, outside-domain loopback denial,
collector failure cases, and platform cleanup. macOS additionally checks an owned
same-UID outside-sandbox signal sentinel. No real credential or public endpoint
is used to test denial. An ineffective/unavailable boundary prevents all gates.

## Deadlines, output and finality

The controller uses one 3300-second aggregate deadline, plus fixed per-gate bounds;
no failed gate receives a renewed execution allowance. Child CPU, file, descriptor,
process and memory bounds supplement the hosted job timeout. The current capture
limits are 8 MiB per ordinary stream, 16 MiB for selected installer streams, and
256 MiB persisted per attempt. A 4 GiB + 512 MiB disk reserve is maintained.

Each logical native source/wheel gate fixes `min(aggregate_deadline, start+900)`
before package inspection or role preparation. Both subcaptures, preparation,
parsers, process finality and final union reconciliation use that same absolute
cutoff; the second capture does not receive a new900-second budget. Exhausting
the aggregate/explicit endpoint fails immediately, without a renewed grace
period. Original-handle cleanup still runs; uncertain finality cannot pass.

The ordinary per-file logical-size limit is512MiB. Only the exact Linux
`python-full` invocation uses `(1 << 32) + 1MiB`, preserving the genuine sparse
ZIP64 regression rather than splitting, skipping or mocking it. This fixed
profile makes the entire host-backed work tree read-only and overlays only
namespace-private tmpfs leaves:640MiB work/tmp;16MiB each for work/home, config,
cache, gem-cache, bundle-config, bundle-home and checks;128MiB /tmp;16MiB each
for /run and /dev/shm. Their aggregate912MiB bounds **file data**, not total RAM
or inode metadata. Dispatch also requires actual MemAvailable>=1536MiB; existing
CPU/address-space/process/FD/deadline/output limits are unchanged.

Before discovering tests, actual Linux controls verify limits, zero additional
user namespaces, the read-only/capped mount topology and private writable roots.
Every writable mount needs a real write/close/remove positive, the U-owned
host-backed leaf must reject writes with EROFS, and a bounded16MiB capacity
control must reach ENOSPC and clean its file. Failure prevents discovery. The
real ZIP64 test asserts exact logical length, sparse allocated blocks and actual
production parsing/stdlib extraction. Namespace disposal is not product cleanup
and cannot convert failed or incomplete test outcomes into success.

Acceptance requires the actual original launcher wait, zero return code, both
stream EOFs, bounded and reconciled persisted bytes, and an empty reserved-identity
process domain. A PASS-shaped footer, closed stream, or discovered PID cannot
replace those facts. The first error stays latched; write/close/cleanup failures
remain failures even when a previously written result looked successful.

Direct admission invocations also retain pending original-producer custody until
the real collector returns normally. An ambiguous root owner-loss helper can
still create future test-identity work even when its current process census is
empty. Pending custody vetoes idle/finality and Linux-setting or macOS-HOME
restoration; diagnostic wait fields cannot clear it.

Linux process finality uses two complete process/thread credential censuses.
Only known disappearance or membership/birth-identity churn permits discarding
an incomplete pass and starting afresh: at most8 pass invocations per census,
under the caller's unchanged absolute cutoff. No partial row set proves absence.
Initial UID/GID collision admission remains strict and never retries away an
observed collision. Root-enumeration failures, permission/I/O errors, malformed
credentials, bounds and deadline expiry remain failures, not process death.

Only the still-owned direct child may be stopped by the root collector. macOS's
fixed cleanup helper runs as the reserved unprivileged identity, not as a root
PID-list/group killer. Unknown finality blocks later commands, mutable-output
inspection and deletion. Failed state and the identity reservation remain for
VM disposal; they are not reusable evidence or proof of library cleanup.

On successful finality the controller removes task work and prepared inputs using
symlink-safe disposal. Private captures/control survive only until VM disposal.
Never delete shared caches or signal another task to make verification complete.

## Required product coverage, not the retired gate count

The compact source-defined catalog replaces the historical 45-gate/custom-helper
inventory; it does not waive the product behaviors that inventory was meant to test.

| Platform | Required gate families |
|---|---|
| Linux | Offline source installation; full Python discovery; all listed Ruby suites, including native/iOS/Android descendant regressions; Fastfile validation; first-party/template actionlint; real JDK signer checks; wheel build/inspection/install/smoke/consumer and selected installed-wheel Python checks; source integrity. |
| macOS | Offline source installation; exact Xcode 26.3/native tools; source native-profile gate, the three upload-process Ruby suites and separate native signal-observation proof; wheel build/inspection/install/smoke/consumer; installed-wheel native-profile gate; source integrity. |

The original 13-method native suite and both 26-method adapters run without the
separate signal-proof instrumentation. An additional fixed Ruby invocation on
both platforms observes the three real first-close outcomes and post-reap
teardown adversary. Its actual production signal observations and fixture
ownership checks remain distinct from inert negative controls and from the
ordinary suite's results; a veto is a failed proof, not runtime cleanup success.

macOS fixture observations use the owner-admitted, unentitled SDK observer, not
the system `ps` invocation that failed sandbox admission. The outside owner's
trusted census still uses system `ps`. The owner compiles fixed immutable C
source as the reserved identity, requires original producer exit/EOF/domain
finality, checks the binary/signature, and freezes a root-owned copy. Actual
live/descendant, unreaped-zombie, reap-to-absence and foreign-process permission
controls must pass before the fixed fixture selector is published. Darwin
observations with a missing selector fail; module imports remain inert. Linux
retains its existing system-`ps` route. The strict tagged BSD metadata preserves
indeterminate states: they prove neither readiness nor death, and never renew a
deadline. A genuine zombie remains a zombie even when its exit flag is set.
Fixture readiness still needs the independent worker/pipe/marker handshake.
No fixture selector or test canary is added to a production validator environment.

The fixed Xcode26.3/toolchain/SDK inventories and their bounded intermediate
ancestors belong to the trusted hosted-image provider. They must not be owned by
the test identity, world-writable or writable by its only group. Internal links,
complete inventory, hashes, executable/set-ID and signature checks remain required.
Compiler/linker ownership may be nonroot and unrelated-group-write is permitted
under that provider trust model and cleared supplementary groups; the signature
tool `/usr/bin/codesign` still requires root ownership. No provider permission
repair or alternate toolchain is attempted. Rejection diagnostics use the same
stat/lstat observation with fixed roles/indices/predicates, never a guessed path
or a later re-stat presented as the original failure.
Parent-chain checks include the fixed SDK alias's own parents and every canonical
internal-link target's parents, even outside the two inventoried roots; successful
directory checks are shared under the same bounded inventory/deadline.

Clean profile and Ruby fixture-driver environments also bind `TMPDIR`, `TMP`
and `TEMP` to their existing canonical owned case directory. They do not inherit
ambient temporary paths, HOME or configuration. Native assertions check the
actual profile scratch parent and Ruby temporary root; system temporary paths
and a writable working directory are not required.

An unknown observer child may leave private capture scratch. Native worker death
does not authorize deleting it: normal/raw driver cleanup and known outer probe
parents veto removal on residual observer scratch or uncertain bounded directory
enumeration, retaining the original error and unresolved evidence. Only the
independent probes' own original-child reservations or genuine zero-spawn proof
authorize their intentional direct-scratch cleanup. No marker supplies process
ownership, and a residual nested driver cannot be erased by outer teardown.

Source and wheel use separate build copies and venvs. Wheel checks must establish
installed import locations, metadata/RECORD, packaged schemas/templates/Fastlane
files/Apple roots, module and Ruby bootstrap help, and a real consumer's
preview/apply/recover behavior outside the checkout. Source imports cannot stand
in for installed-wheel evidence. Build artifacts are consumed only after finality.

Python discovery is compared with source-derived exact method identities and
terminal outcomes. Linux's explicit macOS-only skip set remains **skipped**, not
passed; those native behaviors require the real macOS gate. Unexpected skips,
empty/incomplete discovery, expected failures and missing outcomes fail. Ruby
and native parsers require complete successful method records and exact totals.

## Evidence, local work and remaining limitations

The sanitized `MRK_CI_RESULT` and step summary bind commit/tree, run ID/attempt,
platform/image, input-manifest/lock hashes, observed tools, ordered gate outcomes,
finality, persisted-byte totals and cleanup status. They are observations of this
attempt, not transferable execution permissions. Retain the workflow/run URL and
actual Actions job outcome; a late publication failure invalidates an earlier
success-shaped summary. Later gates after failure stay `UNEXECUTED`.

Failure diagnostics may identify the fixed ACL attribute or whitelisted Ruby
startup tokens from already captured stderr. They disclose no raw ACL entries,
messages or paths. Ruby tokens are observations, not proof of an operating-system
cause, and never change a failed admission result into success.

Python failures additionally retain at most16 actual failing callbacks: only
source-known parent method IDs, finite outcome/category labels and a real bounded
errno (or null). Subtest parameters, exception messages/arguments/filenames are
excluded. Original failure survives failfast's later count mismatch; the parent
filters the schema/identities and requires an empty callback list on success.
Only genuinely completed fixed storage controls may appear as profile observations;
they never replace original wait/EOF/domain finality or successful test outcomes.

Ruby completion parsing binds each source-known verbose method prefix to exactly
one timed successful terminal before the next method or footer. Ordinary multiline
body logging is allowed; a later method's terminal cannot complete a missing
record. Unknown/duplicate identities, ambiguous terminals, adverse outcomes and
footer/count mismatches fail. Failure observations contain only finite structural
reasons/counts and bounded source-known missing/duplicate IDs, never raw body logs.

Native source/wheel failures can identify the actual failing fixed prerequisite
(`openssl-version`, `clang-discovery`, `dsymutil-discovery`, or `system-code`) or
at most16 source-known test/fixture callbacks. Only finite category/outcome labels
and bounded actual errno/returncode values are published; unknown attribution is
omitted. Repeated failing subtests may share their parent method ID, but duplicate
diagnostic envelopes are rejected. The four prerequisite commands, order, native
checks and timeouts are unchanged. Optional fixed stderr-token labels report
observed text, not a proven operating-system cause. Diagnostic failure preserves
the original failure, and any failure marker prevents native success acceptance.

An AIA comparison failure may additionally publish a closed original-parent
observation after successful capture/finality and responder close/join. It includes
only fixed case labels, exact Boolean values, bounded trust-result/chain counts,
fixture-derived chain/request match flags and fixed `leaf/issuer/root/other`
chain-role labels. A separate closed observation of the already-owned original
CFError reports only OSStatus-domain signed32 codes or `no-error`, `other-domain`,
`unavailable`; no description or arbitrary domain string is read. Diagnostic
availability does not change the trust verdict. The previously observed optional
custom-anchor/name diagnostics are retired from execution, not counted as trust
acceptance; their implementation and failed native evidence remain in history.

After all four original leaf-only cases have closed, one fresh full-presented-chain
offline contrast uses the same online fixture, root-only custom anchor, policy and
cutoff, with both network and keychain lookup disabled and read back. Before that
original owner's close, fixed public native key APIs observe issuer/root key
availability, block size and RSA/SHA256 verification support. Eligible keys check
three original certificate-signature edges and one detached, single-bit altered
issuer-signature negative. The bounded fixed-profile DER envelope reader supplies
the original complete TBSCertificate TLV, never re-encoded fields or a guessed
digest. Remaining TBS fields are opaque; this is not a general X.509 validity parser.
Copied key/data/error references, including after-effect CFError outputs, retain
the original close owner. Unavailable keys and unexecuted checks are explicit;
ordinary unavailable diagnostics never suppress cancellation, cutoff or cleanup
failure. Only closed scalar observations survive successful close/post-close cutoff.

One final fresh offline contrast presents the same root as both leaf input and
sole custom anchor. Its expected chain role is `root`, not the original `leaf`.
Neither contrast can seed an earlier original evaluation. Positive signatures
require an actually executed rejecting altered-signature control for interpretation;
they do not establish trust-service or path acceptance. Root-only acceptance alone
does not prove CA/key-usage/path-length eligibility when that root is a parent.
No diagnostic can rescue an original failure or identify a root cause by itself.
The optional error and finite two-contrast/key/signature diagnostic extensions
are strictly parsed under the unchanged4096-byte record bound. Malformed
records are unavailable; raw routes, certificate digests, captures and messages are
excluded. These fields diagnose an already failed comparison, never replace its
original acceptance oracle or qualify an earlier failed capture, cutoff or cleanup.

Do not upload raw captures, writable-directory globs, private Store data or signing
assets. Reuse evidence only for the exact applicable source/configuration/toolchain.
Protected PR delivery and actual resulting `main` CI are separate required evidence.

Local Linux work is limited to reviewed static inspection and specifically scoped
pure/contract tests that do not launch native/process fixtures, installers or the
sandbox. A filename or mocked pass is not native admission. Full test discovery,
builds and signal-bearing suites belong to the disposable hosted path above.

macOS sandbox availability, policy composition and native service/tool compatibility
are **unverified until actual hosted admission and product checks succeed**.
`sandbox-exec` is deprecated; required service exceptions need narrow review, not
broad Mach/network access or a raw retry. No physical-Mac-only requirement is
currently established. Consumer-private distribution/export rehearsals remain
distinct; see [profile authority](ios-profile-authority.md) and [SECURITY](../SECURITY.md).
Neither candidate code nor passing tests alone establish production readiness.
