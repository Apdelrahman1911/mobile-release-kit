# Synthetic fixed-entry startup diagnostic — not M2 feasibility

This is one narrow, credential-free LaunchServices startup diagnostic. It does
not implement production M2, installation maintenance or a successful GUI flow.
The current source deliberately leaves the payload absent, preserving the same
entry guards and original LaunchServices observer. A completed diagnostic can
expose a rejected original gate descriptor or show that this LS invocation
reached the real ENOENT exec; it cannot establish full-payload startup.

## Exact scope and original fixture

Only the reviewed `desktop-macos-m2-entry.yml` push route is admitted: this
repository's `verify/desktop-macos-m2-entry` branch, exact detached source,
GitHub-hosted macOS26 ARM64 and original unprivileged `runner` account. No manual
command, application, diagnostic mode or directory selector is provided. Root
must separately admit actual source and execution before publishing that route.

The adapter creates one fresh, private, run-bound `/private/tmp/mrk-macos-m2-entry-*`
namespace. `Launch Mobile Release Kit.app` and the deliberately absent
`Mobile Release Kit.app` are synthetic fixture names, not the installed product.
Compile-time constants fix source, paths, bundle IDs, UID/GID and the gate's
original device/inode. The test gate is runner-owned0444; this is not a claim
of production root-owned path authentication.

Darwin assigns new directories and files their parent's group, which need not
be the runner's primary group. Before creating children or running a tool, the
adapter exclusively creates its private0700 root, opens that original without
following links, and checks named/FD identity, owner and mode. Only on that
just-created original may it select the runner's primary group using
`fchown(fd, -1, gid)`; it rechecks identity/ownership/mode and closes each original
once. This is initial creation, never permission repair or adoption. Collision,
failed selection/proof or close error refuses. The empty single-link0444 gate
must independently match the account before the first tool call. Bounded root/
gate stat facts are diagnostic DATA, not ownership/finality receipts.

The entry's `otool` checks still require only system libSystem/dyld and reject
extra linked images, RPATH, dynamic-loader environment commands, routine commands
and initializer sections. Signing and strict verification remain unchanged.
The same reviewed Aqua loader and original `run_owned` controller bound each
compiler, codesign, inspection and observer call. Clean tool environment, exact
source/gate pre/post checks, one-shot closes and original command statuses remain.

## Why this is a diagnostic successor

The original994188a run37084951661/1 returned65 at entry root admission, before
any lock observation. Its artifact had no root stat fields; the particular
historical stat predicate is unobserved. Darwin parent-group inheritance caused
a confirmed fixture preparation assumption to be corrected, without relabelling
that historical failure.

On sourceb9319bbc13b467b03ba9338668dda54224bb0737, run37088152428/1, root/group
preparation and all13 pre-observer commands passed. Owned-direct EX refusal75
and real failed exec76 passed, followed by signed AppKit-payload construction.
One LS call returned one original NSRunningApplication but it was observed
terminated before an accepted payload-start. Observer1 reported
`payload-terminated-before-observation`; no normal Quit was requested, termination
and EX-after were observed, and deadlines held. App exit/signal, early C predicate,
exec errno and AppKit phase were not captured. The identity booleans on that path
were not evaluated, rather than observed mismatches. Its source-confirmation
workflow step was skipped; adapter source pre/post equality is separate evidence.

Those direct cases already occupied `entry-busy.json` and
`entry-failed-exec.json`. They were not GUI evidence. The entry also rejected a
gate FD below3, but the helper consumed a rejecting allocated FD before returning
-1. No actual LS descriptor number was observed; FD0/1/2 is a possible class,
not a diagnosed historical cause. This successor avoids another contaminated
marker and adds only that missing failure-path scalar observation.

## One fresh LS/payload-absent control

There are no preceding direct invocations and no payload creation. After entry
compile/sign/verification/inspection and unchanged observer compilation, the
adapter requires payload and all record names absent before exactly one LS call.
This is nine bounded native commands, not a product/Cargo build or matrix. The
fresh namespace and source/gate/header binding identify the single synthetic
invocation that may publish each exclusive record; no old marker is reused.

The entry still checks argc/account, admitted root, original gate and SH before
one fixed exec. Its capture-capable gate helper performs exactly the original
open, one matching predicate and, on rejection, one consuming close. It copies
only scalar outcomes in memory: allocatedFD before close, errno only from a
failed open, match result and rejected-close result. Existing callers use the
same wrapper without capture. There are no extra diagnostic opens, repeated
predicates, descriptor normalization or successful-phase writes.

Only after the original `gate < 0` verdict has irrevocably selected return66 may
the entry attempt `entry-gate-refused.json`, using its already admitted retained
root. No writer outcome changes66 or allows continued execution. Earliest
argc/account/root refusals remain unchanged, with no new sink or root readmission.
SH refusal75/67, flags68, formatting69, root-close70 and real returned-exec76/71
remain unchanged. The original SH is never closed/unlocked early. The existing
root reopen following successful pre-exec close and returned exec is not a new
reopen after a refused admission.

The gate record has a closed fixed source/case/phase, selectedReturnCode66 and
original numeric open/match/close facts. Open failure uses descriptor-1, positive
errno and null unevaluated match/close; allocated rejection has null errno,
matchfalse and an actual close boolean. False close is retained as an error and
cannot complete the diagnostic. No argv/environment/private strings or OS log
transcripts are exported. `selectedReturnCode` is not an observed app exit status;
a readable record also does not establish the writer's final fsync return.

If entry instead passes these original gates, its one real exec encounters the
absent payload. The unchanged failed-exec record can report ENOENT and SH still
held through an independent EX probe. No pre-exec marker substitutes for the
actual returned exec. The unchanged source retains SH until kernel process exit.

## Observer and report: expected failure is not feasibility

`observe.m` is unchanged. It still makes exactly one NSWorkspace launch with a
new instance requested, substitution/prompts disabled and the original configured
environment. Only its original returned app object is available for normal
termination; there is no PID lookup, second reference, force termination or retry.
Concurrent callback body counts and main-queue handoff remain separate facts.

Original work and final deadlines stay30s and45s, within the unchanged60s owner
bound. Work admission is irreversible and checked after setup/before launch,
after the event pump, after record IO and after final native observations. Late
completion may identify the original for cleanup but never renew work.

The expected observer result is still **1**, with firstFailure exactly early
termination, one callback/body/handoff, no NSError, no accepted payload records,
no normal-Quit request, terminated/EX-after/root-close/timely true, and no work
deadline failure. PID/bundle/executable comparison flags remain unmeasuredfalse
on this early path. The adapter preserves this original result, not a fictitious
normal-Quit success.

After that original owner call returns, the adapter checks entry/observer/source/
gate originals and payload absence, then reads only the two fixed possible
records. The existing bounded nofollow reader proves stable original FD/name,
regular0400, account UID/GID, single link and a4096-byte ceiling. Only initial
lstat ENOENT means missing; disappearance or proof failure after seeing a name
is an error, not absence. Both records present are contradictory and refuse.

The nested diagnostic reports one of:

- `entry-gate-refused`: valid actual gate-admission outcome; a false consuming
  close remains incomplete, never a passing cleanup.
- `entry-reached-exec-enoent`: fresh failed-exec record with both ENOENT and
  original-SH-held true, with no gate-refusal record.
- `unresolved`: missing/noncorresponding branch evidence; never a completed
  diagnostic merely because the LS object terminated.

`expectedControlObserved` describes the bounded branch/observer facts. The
separate top-level `diagnosticComplete` additionally requires source/postcondition
checks and no cleanup error. A zero adapter status means only this explicitly
named diagnostic completed. `feasibilityObserved`, `installedProductQualified`,
`tauriQualified`, `credentialQualified` and `maintenanceAvailable` always remain
false. Incomplete/contradictory/late/close/source failures keep completionfalse
and return nonzero while retaining available bounded facts.

`originalAppExitStatus` staysnull and `allWorkerFinality` remains
`not-established-by-NSRunningApplication`. Termination, callback counts and JSON
records are not app exit, OS-thread-join, all-worker-finality or ownership receipts.
A positive ENOENT control does not qualify successful exec, AppKit or Tauri. A
new gate observation does not retroactively prove b9319bb failed for that reason.
Any actual correction or further discriminant requires its own reviewed source.

## Preservation, cleanup and verification

Existing cleanup conditions are unchanged. Full native `observationComplete`
remainsfalse for this diagnostic, so diagnostic completion alone authorizes no
new removal. Synthetic bundles, app-tmp, gate/records, build/tmp and unknown state
remain for disposable hosted-job retirement. There is no large Cargo build/cache.
Every original compiler/controller call still joins; no shared cache, other task
process or unknown application state is removed. App temporary data remains
separate from controller tmp. The report says what was actually retained.

Only bounded normalized JSON is uploaded. OS stderr is bounded and hashed, not
exported as a transcript or used as an application receipt. Public-source compiler
error excerpts remain bounded when relevant. No project, signing input, Keychain,
Store mutation, installation, production release or availability gate is involved.

The existing small local DATA/inert-FS module now covers diagnostic shape,
contradiction, missing/late/close failure, fixed readers and source ordering.
Mocks do not provide native FD/LaunchServices evidence. The original observer
parser/deadline contracts stay covered; real execution belongs to the reviewed
hosted Mac route after local source/control acceptance. This source contains no
fresh native result and does not claim the diagnostic has run successfully.

## Apple contracts and remaining scope

Apple documents additional LS arguments as an empty default and inserts the app
path first. Its OpenConfiguration has no documented standard-input/output/error
setter. Do not invent one or redirect/normalize descriptors to hide an original
allocation. Successful `execve(2)` preserves PID/real IDs/non-CLOEXEC descriptors
but does not promise sibling-bundle LS identity rebinding. AppKit `run` invokes
`finishLaunching`; absence of another explicit call is not a proven startup bug.
Strict codesign verification is not a C/exec/dyld/AppKit lifetime receipt.

The continuation investigation retains exact document pins; documentation is
not a native implementation trace. Relevant public Apple documentation includes
[NSWorkspace openApplication](https://developer.apple.com/documentation/appkit/nsworkspace/openapplication(at:configuration:completionhandler:)),
[arguments](https://developer.apple.com/documentation/appkit/nsworkspace/openconfiguration/arguments),
[execve](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/execve.2.html),
[finishLaunching](https://developer.apple.com/documentation/appkit/nsapplication/finishlaunching()),
[mkdir](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/mkdir.2.html)
and [open](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/open.2.html).

Production retained-entry layout, native participant/child ownership, ten runtime
constructor joins, vault helper,3/8-FD transfers, provider re-entry/capacity,
update/remove, full-payload identity/activation/normal Quit and distribution remain
separate obligations. Desktop remains NOT READY.
