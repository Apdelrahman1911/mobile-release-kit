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
It selects `ubuntu-24.04` and `macos-26`, Python 3.11, Ruby 3.3.12, and pinned
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
mandatory sandbox policy is unchanged. Before product execution, fixed
outside-policy controls must access a synthetic readable HOME file and a named
local socket; sandboxed children and descendants must be denied file reads,
metadata and socket access, with no outside delivery. No real private file or
runner socket is probed. This demonstrates the effective privacy boundary
despite the necessary directory traversal. A successful Ruby launch alone is
insufficient.

The HOME directory pin and synthetic fixtures remain owned by this attempt.
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
runtime prefixes are exposed. The search-only compatibility preparation above
does not exempt other HOME content or metadata from the mandatory policy.

Linux uses distribution-provided `bwrap` for PID/network/IPC/UTS separation and
read-only mounts, followed by `setpriv` for the numeric credential drop, cleared
groups, no-new-privileges and zero capabilities. No user-namespace UID translation
is substituted. Temporary device/runtime views do not expose host control sockets.

macOS uses a numeric `Popen` credential drop and inherited `sandbox-exec` policy.
The candidate denies networking and Mach lookup, restricts writes to task work,
protects runner/control reads, and restricts signals to the same sandbox. Native
controls must prove inheritance through fork/exec and detached descendants.

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

Acceptance requires the actual original launcher wait, zero return code, both
stream EOFs, bounded and reconciled persisted bytes, and an empty reserved-identity
process domain. A PASS-shaped footer, closed stream, or discovered PID cannot
replace those facts. The first error stays latched; write/close/cleanup failures
remain failures even when a previously written result looked successful.

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
