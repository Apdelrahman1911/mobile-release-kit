# Repository verification

## Scope and current status

This documents fixed checks inside fresh, disposable GitHub-hosted Linux and
macOS job VMs, including the separate QA-007 production process-ownership
requirements. A documented contract or selected architecture is not implementation
acceptance or a passing native run. Bind the final reviewed source, complete
inventories and actual Actions results before claiming delivery.

The QA-006 Ruby descendant **test-fixture** readiness boundary remains required:
fixtures distinguish startup, genuine readiness, a reaped leader, live
pipe-holding descendants and cleanup failure. That fixture correction does not
itself prove the QA-007 production native process-group lifetime correction.
New owner/protocol/ABI regressions need their own source and installed evidence;
historical gate/method totals and VM disposal cannot prove library cleanup.

Do not run the native/process suites or the CI controller on a shared VPS,
developer login session, or self-hosted runner. Root access is not authorization
to do so. Historical handoff helpers, permissions, receipts and failed runs are
not executable instructions or evidence for this replacement.

## Supported CI entry point

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) is the entry point for
pull requests, pushes to `main`, and manual **verification-only** dispatches.
PRs, main pushes and the default manual `verification_target: full` select both
`ubuntu-24.04` and `macos-26`, primary Python 3.11, exact Ruby 3.3.12/Fiddle 1.1.2,
Bundler 4.0.16, and pinned third-party Actions. Checkout does not persist Git
credentials. Project package installation is not performed by the setup Actions
or directly as the runner.

The workflow also supplies three distinct setup outputs for fixed CPython 3.12,
3.13 and 3.14 compatibility controls. The controller remains bound to its original
3.11 output; later ambient PATH or `pythonLocation` cannot select it. Internal
`--python-312`, `--python-313` and `--python-314` inputs bind those exact selected
executables, not arbitrary alternative interpreter routes. A setup step is not
native admission or a compatibility pass.

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

The normal compatibility path has the exact ordered Linux provider roles
`python`, `ruby`, `jdk`, `python312`, `python313`, `python314`. Each selected Python
executable must resolve directly inside its narrow installation `bin`; broad
HOME/toolcache/framework ancestors cannot stand in for that prefix. Missing,
swapped, overlapping or extra roots reject. All selected roots are inventoried
before any permission change under the original aggregate cutoff and existing
ACL/identity/size bounds; no unselected runtime is repaired. macOS admits only
the corresponding exact selected runtime prefixes, without a new ancestor-
metadata, HOME, network or Mach exception. The legacy three-role shape remains
only for bounded owner-contract controls, not a way to omit required CI versions.

The macOS provider inventory may record protected absent optional
`Frameworks/Tk.framework/PrivateHeaders` and `Frameworks/Tcl.framework/PrivateHeaders`
aliases, at most once each per selected Python role (two per role, eight total).
Only those exact following-stat ENOENTs can enter a finite, read-only two-pass proof of
ordinary protected parents, an internal raw link layout, stable metadata and a
genuinely absent final leaf. Every extra inspection consumes the same original budget
and deadline, without renewal between aliases. Unproven layouts still fail; existing
targets retain all permission checks. This does not repair a provider, claim Tk/Tcl
functionality, or replace native
verification, and assumes the admitted trusted-provider/sandbox boundary.

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
`NativeProfileAuthorityTests` methods after `openssl-version` then `system-code`.
All remaining source-derived native methods run separately under ordinary policy
after `clang-discovery` then `dsymutil-discovery`. Authority runs first, ordinary
second.
OpenSSL is checked before its authority consumers; compiler tools are checked
before their ordinary consumers. Routing is fixed before execution, never selected
as a fallback after failure.

This explicitly amends the earlier rule that all four prerequisites precede any
native test: each prerequisite must precede its applicable consumers. All four
unchanged commands still execute exactly once per successfully completed
source/wheel logical gate. Standalone `all` retains the original four-command
order in both source and installed-wheel forms: `openssl-version`,
`clang-discovery`, `dsymutil-discovery`, then `system-code`.

Source and installed-wheel gates each require the original authority capture,
the healthy ordinary capture and every selected fixed intentional-UNKNOWN
singleton under ordinary policy. Their exact disjoint method union must be
complete, with no skips; the [isolation contract](#intentional-unknown-test-isolation)
and source catalog determine the parts, not a historical capture count.
Each original capture retains its own wait, EOF, exit, domain finality/disposal,
cleanup and persisted-output facts; there is no manufactured combined process
result. Failure retains completed and unexecuted partition information and never
authorizes a later launch. A prerequisite failure stops before that partition's
inventory, product imports or tests; earlier authority success cannot satisfy a
failed logical gate.

Authority entry uses the selected Python with `-I -S -B`, explicit immutable
package specifications, fixed test helpers and fresh exclusive scratch. No
site/.pth startup, ambient configuration or prior writable work is admitted.
Parent inspection compares every selected package module/resource with the
source, including installed-wheel bytes and immutable modes. The fixed
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
policy before any product code, Mach lookup or boundary probe. Other entry routes
retain their sandbox wrapper except for the exact trusted offline baseline below.

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

Each request's exact `-subj` value is `/CN=MRK synthetic {role} {nonce}`, using its
fixed root/issuer/leaf role and case nonce, with explicit `-batch` for noninteractive
operation. `prompt=no` is omitted because provider implementations may prioritize
the configuration DN over `-subj`. This compatibility correction does not establish
historical runner DER or native success. Chain specifications, policies, the
original oracle and deadlines remain unchanged.

A preplanned seventh source-preparation control, `aia-offline-baseline`, follows
the unchanged original six. Original evaluator finality and responder close/join
precede structural-only validation of the complete current three-contrast record;
trust/signature verdicts and chain/request matches do not select or suppress it.
After an exact equality reread of all fixtures, the owner exclusively snapshots
the original online leaf/issuer/root DER into root-owned immutable inputs. No
private keys, regenerated certificates or earlier-run fixtures are admitted.

For this comparison only, the exact trusted helper omits this project's sandbox
wrapper, retaining the same reserved unprivileged identity, environment and resource
bounds. The policy pathname is binding-only, not proof of application. It evaluates
one fresh full-presented-chain trust with both lookup flags explicitly false and
read back; no original cases, signatures or responder are rerun. This is neither a general
policy-off entry nor a way to shed inherited confinement. Ordinary/product
containment stays unchanged.

All input/cancellation/failure/cleanup/idle guards and the original source-gate
deadline remain mandatory; no launch occurs from an exception handler or after a
latched failure. Only after the separate baseline capture/projection and finality/
idle/input/cutoff checks does the unchanged original four-case oracle run once on
original inputs. A completed negative baseline is valid diagnostic data; a positive
is not required. Neither outcome rescues an original failure or waives a gate.
Missing, malformed or unavailable baseline evidence fails preparation; it is not
an observed negative.

Its separate frame retains the 4096-byte bound. The original parent's capture note
contains only fixture-derived chain roles/counts/matches and closed scalar/error
fields; raw DER/hashes/paths remain private. Inside-failure/outside-success
localizes context, not a specific permission or authority to expand policy;
failure in both identifies no certificate/service defect. Later execution, a new
process, immutable input paths/ownership and the omitted wrapper leave cache/time/
service/launch-context differences. False lookup flags prove neither kernel network
isolation nor control of autonomous trustd activity. This comparison does not
establish the OS/provider trust basis.

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
before package inspection or role preparation. All original part captures,
preparation, parsers, process finality and final union reconciliation use that
same absolute cutoff; no later part receives a new 900-second budget. Exhausting
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
| Linux | Offline source installation; ABI/runtime compatibility gates; full Python discovery; all listed Ruby suites, including native/iOS/Android descendant regressions and actual packaged capture; Fastfile validation; first-party/template actionlint; real JDK signer checks; wheel build/inspection/install/smoke/consumer and selected installed-wheel Python checks; source integrity. |
| macOS | Offline source installation; exact Xcode 26.3/native tools; ABI/runtime compatibility gates; all fixed Ruby primitive/helper/capture/adapter suites and separate native signal-observation proof; source native-profile gate; wheel build/inspection/install/smoke/consumer, including actual installed Ruby capture; installed-wheel native-profile gate; source integrity. |

The macOS Ruby gates depend on ordinary admission, including the admitted
process observer, but not profile-authority admission, so run before the source
native-profile gate. The source catalog selects **51 Linux gates and 39 macOS
gates**; these are required inventory counts, not completed or passing runs.
Every selected gate remains required and any failure stops later gates. Recompute
inventories when source changes; historical native totals cannot stand in for
the complete current source-derived method identities and outcomes.

The native capture suite and both platform adapter suites run without the
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

The new runtime inventory includes `fastlane/native_process_spawn.rb`,
`fastlane/native_upload_process.rb`, `mobile_release/_native_process.py` and
`mobile_release/_profile_process.py`, in addition to the existing outer capture
and profile entry points. Required tooling lists, wheel members, proof-copy inputs
and incomplete-install checks must agree. Reading a bootstrap string, loading a
copied source layout or checking `--help` is not the installed Ruby proof: an
actual bounded capture must load the installed helpers from outside the checkout,
with original wait/EOF/finality and complete successful outcomes.
Origin observations measure the outer loaded methods and genuine fixed custodian
spawn; keeper selection is bound transitively by that custodian's reviewed source.
They are not independent child-local origin measurements.
Missing-helper controls must use a separate actual installation of the same
checked wheel, leaving the frozen positive installation untouched. Default
tooling resolution must reject an incomplete selected origin rather than borrow
a checkout-like decoy or another release; an explicitly selected complete tooling
root remains supported. Removal of negative-fixture files requires their original
producer/capture finality, not a guessed successful install.

Python discovery is compared with source-derived exact method identities and
terminal outcomes. Linux's explicit macOS-only skip set remains **skipped**, not
passed; those native behaviors require the real macOS gate. Unexpected skips,
empty/incomplete discovery, expected failures and missing outcomes fail. Ruby
and native parsers require complete successful method records and exact totals.

### Intentional-UNKNOWN test isolation

Some native-process and real-resource controls deliberately leave product custody
UNKNOWN. Each selected control requires its own fixed singleton **original
Session capture**, separate from the healthy complement. This applies to the
approved Python full/wheel/native selections and the Ruby owner, native capture
and platform adapter gates. The [fixed catalog](../.github/scripts/verify_ci.py)
and literal runner inventories define the exact IDs and order. Their disjoint
union must cover each approved selection exactly once; a global method total
does not authorize expanding an installed-wheel selection or pooling negatives.

Python singletons retain separate finite primitive, profile and default/resource
family import closures, with exact selected source or actual installed-wheel
origins. The primitive runner does not gain workflow imports from another family.
There is no generic caller-supplied method selector or broad workflow import grant.

All parts retain one fixed gate endpoint: 900 seconds for the affected Python
gates, 120 for the Ruby owner, 310 for native capture and 300 for each adapter,
always clamped to the original 3300-second job endpoint. Native capture additionally
caps its healthy 17-test partition at 180 seconds and each of its four fixed singletons
at 30 seconds, including preparation, capture, result parsing and finality. Each
singleton keeps its original 15-second driver and 5-second cleanup limits; another 10 seconds
is bounded outer framework/startup/result/finality headroom, not a native deadline
extension. Setup and final-union bookkeeping share a separate 10 seconds. Every
phase cutoff is fixed before its work; unused partition time cannot be donated,
and setup time is deducted from the union allowance. These are finite scheduling
ceilings, not guarantees of a passing run. Other gates retain their shared-cutoff
behavior. The macOS authority capture and 2+2 prerequisite routing remain unchanged.
These splits add no logical gates, jobs, builds, permission profiles or observers.

Before any next part, the existing Session must establish the preceding original
capture's actual wait, stream EOFs, domain finality/disposal and `ensure_idle`.
Each part retains its own result and byte accounting. Success and failure parsers
both use that part's exact IDs; missing, duplicate, failed or unexecuted parts
cannot pass or be replaced with a merged process result. Unexpected failure or
UNKNOWN in a healthy row stops further work. Adverse-state and retained-custody
guards run at every case/setup entry, before any temporary-directory or native
acquisition; ordinary mixed discovery cannot bypass them.

An expected UNKNOWN assertion is **not** confirmed product cleanup. Required
custody records and any remaining scratch stay retained through probe/interpreter
exit until genuine outer-domain disposal. A nested driver's wait/EOF or descendant
cleanup cannot supply a missing original native receipt or prove every child joined.
Keep the real FD-close/reuse, original exception-identity, scratch-identity and
descendant-finality assertions; isolation does not replace those oracles.
Within the affected fixture, only permitted bounded cleanup of already-owned
resources and sanitized reporting remain after UNKNOWN: no fresh observer,
producer or workspace, numeric retry, registry reset or speculative recursive
removal. The existing Session's independently authorized disposal remains
mandatory; it does not retrospectively turn UNKNOWN into a product finality receipt.

Known-timely ordinary timeout, backpressure, rejection and I/O-fault fixtures must
still prove settled cleanup; accepting UNKNOWN instead would hide a failure.
Hard-loss controls must distinguish actual descendant cleanup from fixture EOF
fallback using already-admitted, source-bound evidence, without a new observer
after UNKNOWN. The missing original outer receipt remains disposal-required.

The fixed QA-007 catalog additions are:

| Gates | Required scope |
|---|---|
| `native-process-abi-source`, `native-process-abi-wheel` | Original public-header/compiler evidence, actual per-phase runtime declarations and no-child native API controls before that phase's process tests; each logical gate is bounded to 300 seconds. |
| `python-compat-312-source`, `python-compat-313-source`, `python-compat-314-source`, and matching `-wheel` gates | Six ordinary-policy gates with genuine captures of actual selected runtimes, package origins, atomic FD/native APIs, exact pre-exec maps and real child waits; each complete gate is bounded to 120 seconds. |
| `ruby-native-spawn`, `ruby-native-owner` | Complete source-derived primitive and owner/protocol regression identities, in addition to the existing capture/adapter suites. |
| `ruby-packaged-capture-source`, `ruby-packaged-capture-wheel` | Real source/installed capture and adapter finality; the wheel gate also owns the separate same-wheel missing-helper installation. Each logical gate has one 300-second cutoff, including preparation and finality. |

All use the original 3300-second aggregate deadline. Compatibility gates do not
rerun the whole project matrix, rebuild the wheel or install dependencies for
three more interpreters. Their isolated package-only loader must use the same
already-checked source or actual installed `py3-none-any` wheel bytes, with real
module origins; changing `sys.prefix` or copying a source tree is not installation.
They do not replace the required macOS native source/wheel selections or change
their independent authority/ordinary routing and singleton isolation.

The test-only public-header reporter uses only the admitted distribution
`/usr/bin/x86_64-linux-gnu-gcc-13` on the hosted Linux x86_64 profile, or the exact
already-admitted macOS clang/linker/SDK binding. Linux compiler captures use
literal `/usr/bin:/bin`, not work/venv/Bundler binaries or injected compiler search
paths. Missing tools fail; there is no PATH compiler discovery, installation,
runtime C extension or unconfined root build. Compiler version, build, reporter,
runtime declarations and native controls retain separate original ordinary
captures with real wait/EOF/domain finality. Reusing the original frozen header
record across phases/minors requires unchanged source/compiler/configuration;
each actual runtime declaration and native control still executes.

### QA-007 runtime and lifecycle evidence

The production contract is described in [SECURITY](../SECURITY.md#native-validation-process-ownership)
and [profile authority](ios-profile-authority.md#isolation-deadlines-and-installation).
Its admission/control matrix is additional required coverage, not a replacement
for existing native, upload, entitlement, recovery or fixture tests:

- Admit exact Ruby 3.3.12/Fiddle 1.1.2 in the outer Store integration **and** fixed
  helper, checking actual loaded origins rather than version text alone. Resolve
  the required public native APIs without runtime installation,
  private runtime symbols or a permissive fallback. Python metadata remains
  `>=3.11`; real bounded compatibility controls for CPython 3.11, 3.12, 3.13 and
  3.14 are required. An unavailable line, unsupported ABI or mocked result is not
  a compatibility pass. Additional provider preparation needs its own reviewed
  admission; a version declaration does not grant new paths or permissions.
- Compare the actual supported little-endian LP64 Linux-glibc/Darwin x86_64 and
  arm64/aarch64 public headers, scalar sizes, layouts, constants and signatures.
  Linux requires public closefrom file actions; Darwin requires public
  `POSIX_SPAWN_CLOEXEC_DEFAULT`. Reject missing facilities and unknown ABI before
  acquisition. Do not silently treat musl, another interpreter or Windows as an
  admitted native platform. A header/declaration match on one runner is not a
  native pass for another ABI or interpreter build.
- Exercise the real Ruby **variadic** Fiddle `fcntl` call for
  `F_DUPFD_CLOEXEC` (Linux 1030, Darwin 67), minimum descriptor 8, with a private
  Function per creator. Require actual atomic flags, unchanged original source
  and concurrent independent-instance behavior. Missing variadic support,
  `EINVAL`, lost return publication and a non-atomic fallback mutant must reject;
  post-hoc `F_SETFD` cannot repair the required acquisition boundary.
- Prove read-only SIGCHLD inspection preserves nonreaping caller policy and
  rejects `SIG_IGN`/`SA_NOCLDWAIT` before creation. Keep exclusive exact-child
  waiting and continuing waitability through native startup/publication. An
  earlier policy snapshot is not proof against arbitrary later status theft.
- Prove all inherited non-protocol descriptors close before interpreter startup,
  including deliberately inheritable sentinels and colliding low descriptors.
  Helpers receive exactly the 0–7 map; validators receive only 0–2. Original
  foreign descriptors and flags remain unchanged. Endpoint metadata alone is not
  pipe-pair proof: owned pipe creation and the exact handoff map must establish
  topology. Resource publication, native buffers, acquisition records, source
  leases and creators need real settlement; no import-time acquisition, blanket
  FD sweep or runtime finalizer may hide it.
  Immutable spawn specifications do not freeze the owner's mutable acquisition,
  publication, wait or retirement records. The real Fiddle/CDLL call must release
  the GVL/GIL so its deadline owner can run; a thread wrapper around a blocking
  language constructor is not that evidence.
- Observe custodian/keeper/validator creation and the keeper's move out of its
  still-reserved target group. No numeric group request may occur after group
  retirement or the first consuming keeper wait. No direct numeric route may
  survive its child's first consuming poll. Ruby `nil` or Python `(0, 0)` must be
  a genuine return, never an empty slot; `ECHILD`, wrong/lost wait publication and
  ambiguous startup are UNKNOWN. Decisive mutants must be vetoed before a
  stale-identity syscall, not demonstrated by signaling an unrelated process.
- Withhold COMMIT until **real EOF**: descendant cleanup and the Python payload
  write/close must progress first, and unused Ruby writer copies must already
  close. Permanent withholding fails at the original cutoff. Exercise pre-RUN
  no-attempt, real pre-READY child exit, ordinary rejection, unknown publication,
  partial/duplicate/extra terminal fields and close/join failure without invented
  statuses, absence or success-only phases. A never-started creator needs positive
  closed-launch/empty-effect proof; an attempted but unpublished task is not
  absent, and neither case permits a fabricated join.
  The closed v1 protocol permits a bounded 128 KiB configuration, at most 1 KiB
  per later frame and 16 frames per direction, with fixed fields/edges/phases.
  Validator stdout/stderr never supply control authority.
  For Python control retirement, force partial payload rejection to send a real
  late CANCEL while the custodian retains its original reader. Require
  `QUIESCING`, irreversible grant retirement, actual clean control EOF and reader
  closure before a confirmed FINAL; neither the notification nor an enqueued
  cancellation proves completion. Preserve partial-write uncertainty and the
  original cutoff.
- Exercise success, rejection, timeout, independent stdout/stderr overflow,
  dead validator with live pipe holders, closed pipes with live work, setup
  failure, cancellation and parent loss. Keep Ruby's maximum 3600 seconds and
  independent 64 KiB stream bounds with one five-second first-failure grace;
  Python's 30/25/20/3-second caps remain clamped to the existing inspection
  endpoint. No late return, repeated signal, READY or EOF starts a new allowance.
- Require genuine V/K/C wait receipts, group absence before retirement, real
  data/status EOFs, every owned close, joined tasks and final latches before
  accepting the FINAL offer. Retain the first actual caller cancellation object
  (`Interrupt`/`KeyboardInterrupt` or `SystemExit`) separately from sanitized
  operational and cleanup failures; automatic task exception reporting must not
  leak private data. Include cancellation in the return/close/publication tail,
  not only during normal capture.
  Distinguish positively settled lifecycle failure from UNKNOWN. Only genuine
  custodian/keeper exits `0` (settled normal/rejection) or `2` (settled lifecycle
  failure) can support finality; exit `1`, other codes and signals cannot. A failed
  FINAL needs actual custodian exit `2` and all finality proof, not just a nonzero
  exit. Custodian/keeper post-offer error, cancellation, deadline or close
  uncertainty must veto that helper's confirmed-finality outcome. Final outer
  caller cancellation still vetoes acceptance after physically settled cleanup.
  These private helper outcomes do not change the validator's public application
  exit codes or turn rejection into success.
- Prove explicit mode-0700 scratch ownership and unchanged identity before
  removal. NO_PRODUCERS needs actual closed no-acquisition proof; FINALIZED needs
  complete real accounting. Unknown creation/wait/close/join retains required
  scratch/native/FD/task custody through exceptions, garbage collection and outer
  unwind and prevents silent same-process reuse. A native stall exceeding its
  cutoff cannot be relabeled joined or safe for deletion; native `settled` is not
  a task join or producer-finality receipt.

These controls require applicable native source and installed paths on the
admitted Linux/macOS platforms. Pure parser/state tests, a copied helper tree,
protocol flags or disposal of the verification VM do not substitute for real
runtime/ABI/process observations. The final catalog must reconcile every new
method identity, partition and outcome without changing the five-method authority
partition, 2+2 prerequisites or shared 900-second native logical-gate cutoff.
Every required healthy/singleton capture needs its own genuine finality/disposal;
no control is claimed passed merely because it is listed here.

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

The native first-close cancellation test may additionally report one bounded
`MRK_NATIVE_SETUP_FAILURE` observation for its three fixed setup modes, only when
the original result-kind/driver-status rejection survives the complete fixture
lifetime. Closed categories and true/false/missing/invalid checks retain the
already-read result without publishing private messages, paths or identities.
Reporting uses the same original cutoff and never changes rejection or cleanup
authority. The controller binds it to the exact failing source-known callback in
the healthy partition; successful or duplicate callbacks cannot qualify.

The shared adapter's silent-observer timeout test uses its existing two-second
startup-inclusive fixture budget, rather than racing native bootstrap within
50ms. It still requires the exact observation-deadline error and an actual child
with original wait, creator join, both EOFs and closes. GO/exec-attempt records do
not substitute for finality or prove successful target execution. No production
timeout, cleanup grace or gate allocation is extended by this test correction.

Native source/wheel failures can identify the actual failing fixed prerequisite
(`openssl-version`, `clang-discovery`, `dsymutil-discovery`, or `system-code`) or
at most16 source-known test/fixture callbacks. Only finite category/outcome labels
and bounded actual errno/returncode values are published; unknown attribution is
omitted. Repeated failing subtests may share their parent method ID, but duplicate
diagnostic envelopes are rejected. The four prerequisite commands, native checks
and timeouts are unchanged. Partitioned gates use the 2+2 prerequisite routing
above; standalone `all` retains the original command order. Optional fixed
stderr-token labels report observed text, not a proven operating-system cause.
Diagnostic failure preserves the original failure, and any failure marker prevents
native success acceptance.

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

Two subsequent fresh offline contrasts isolate each attachment: the same issuer
as the only input with the root as sole anchor, then the same leaf as the only input
with the issuer as sole anchor. Their expected chains are `issuer/root` and
`leaf/issuer`, respectively. Each starts only after its predecessor's original
close and post-close cutoff, with both lookup flags verified false. The previously
observed root-only contrast is retired from execution; its source and native
evidence remain in history, not proof about newly generated roots.
No contrast can seed an earlier original evaluation. Positive signatures
require an actually executed rejecting altered-signature control for interpretation;
they do not establish trust-service or path acceptance. One-hop acceptance does
not prove three-certificate composition, and a failed hop does not identify a
particular policy or service defect. The contrasts can share service cache effects
and are not a claim of identical independent cache states.
No diagnostic can rescue an original failure or identify a root cause by itself.
The optional error and finite three-contrast/key/signature diagnostic extensions
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
