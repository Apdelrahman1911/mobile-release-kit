# Synthetic full-payload boundary diagnostic — not M2 qualification

This is one credential-free LaunchServices diagnostic using the real synthetic
AppKit payload. It does not implement production M2, Tauri, installation
maintenance or a qualified shipping GUI flow. The existing workflow bytes and
route are unchanged; the result scope is
"m2-full-payload-boundary-diagnostic-only".

The source must be separately reviewed and its original execution admitted.
No full-payload run of this successor is claimed here. A diagnostic exit0 means
only the strict bounded observation completed; feasibilityObserved,
installedProductQualified, tauriQualified, credentialQualified and
maintenanceAvailable remain false even if the synthetic GUI observation works.

## Evidence that motivates this successor

The earlier b9319bbc13b467b03ba9338668dda54224bb0737 run37088152428/1 completed
its original direct entry controls and full synthetic payload construction,
then observed termination before an accepted payload-start record. Its real
application exit/signal, returned exec errno and early payload main phase were
not captured. Unmeasured identity flags on that path were not observed identity
mismatches. Neither a low-descriptor correction nor a missing finishLaunching
call is an established cause.

The fresh payload-absent diagnostic on
a399458782f4a27dfe41f08a8a1351b7837689b1, run37093573976/1, completed with
entry-reached-exec-enoent, execReturnedENOENT:true and originalGateStillHeld:true,
and no gate-refusal record. Result7338B SHA256:
e33b484609cc49d4322847f793800f00ef90db9da0e4a7966086faddcc428928.
That invocation reached its actual execve with the original shared gate held.
Its observer status1/early termination was the intended missing-payload
control result, not a new full-payload failure diagnosis.

This successor restores only the real synthetic payload construction and adds
bounded phase DATA. It does not reinterpret either historical result as a
successful full-payload launch or as proof of a repaired cause.

## Fixed route and original fixture

Only the reviewed desktop-macos-m2-entry.yml push route is admitted: the
verify/desktop-macos-m2-entry branch, exact detached source, GitHub-hosted
macOS26 ARM64 and original unprivileged runner account. No command, mode,
application, directory or diagnostic-case selector is added.

The adapter exclusively creates one private source/run/attempt-bound namespace
under /private/tmp. The fixed entry and payload bundle names are synthetic,
not installed-product paths. Compile-time constants bind source, paths, bundle
IDs, original UID/GID and the newly created gate's device/inode. The runner-owned
0444 gate is not a production root-owned path authentication claim.

Existing original root preparation is unchanged: admit the private parent,
create0700 exclusively, bind its named/FD identity and owner, select its initial
group on that original if necessary, recheck, and consume each descriptor once.
This is initial creation, never permission repair or collision reuse. Failed
admission, group selection, identity or close refuses.

The exact native call roster is twelve:

1. compiler-version
2. sdk-version
3. compile-entry
4. sign-entry
5. verify-entry-signature
6. entry-linked-images
7. entry-load-commands
8. compile-payload
9. sign-payload
10. verify-payload-signature
11. compile-observer
12. one-launchservices-observation

There is one entry invocation through the original NSWorkspace observer.
No direct EX/ENOENT controls precede it, and no launch retry follows it. Payload
compile/sign/strict-verify uses the earlier full-payload construction commands,
not a new compiler or framework configuration. Both bundles and observer are
pinned before and after the one call. Every fixed record and its exclusive
inflight staging name must be absent before launch.

Existing clean command environment, isolated owner loader, source/gate
pre/post checks, bounded capture and actual original command returns remain.
Entry inspection still requires only libSystem/dyld, with no RPATH, initializer,
routine or dynamic-loader environment command. That entry-specific fact says
nothing about system AppKit/Objective-C initialization in the full payload.

## Entry: failures only, no success-path instrumentation

Entry keeps its original argc/account/root/gate guards and exactly one gate
open and matching predicate. Gate-refusal DATA is published only after the
original branch selected66, through the already-admitted root. The selected
return stays66 regardless of diagnostic write success. The record's case is
now fixed to "ls-full-payload"; it is never an observed process exit66.

On the successful entry path the original SH, CLOEXEC transition, argument
formatting, root close and one fixed execve remain unchanged. No diagnostic
open, normalization, duplicated descriptor, extra lock or pre-exec marker is
inserted there.

If the real execve returns, its errno is latched immediately, before root
readmission or any diagnostic helper. The existing failure record now includes:

- case "ls-full-payload" and phase "entry-exec-returned";
- execErrno as the actual latched positive integer;
- execReturnedENOENT, consistent with that errno;
- originalGateStillHeld from the original identity/CLOEXEC/independent EX probe.

Its original selected exit76-or71 logic is unchanged. It still keeps the
original SH open until kernel process exit; there is no early gate close or
unlock. A returned-exec record proves that call returned with that errno, not
an app exit/signal, a loader explanation or all-worker finality. In particular,
a non-ENOENT errno is retained, not replaced with a guessed failure cause.

## Payload: one already-admitted-root main outcome

The original payload order is preserved: enter its autorelease pool; validate
argc/account/canonical inherited arguments; open and admit the original root;
evaluate the original gate predicate once; obtain original PID/CLOEXEC and
executable facts; select the existing refusal or continue to NSApplication.
No constructor or C-main wrapper is added. Root admission is not moved earlier
than the pool, and no failed admission is retried for a diagnostic sink.

One bounded best-effort payload-main.json can be published through that
already-admitted root. Its closed outcome union is:

- main-gate-refused: the original gate predicate rejected, selectedReturnCode65,
  gateMatchAccepted:false, and later handoff fields null.
- main-handoff-refused: the original PID/CLOEXEC predicate rejected,
  selectedReturnCode66, gateMatchAccepted:true and original measured booleans.
- main-admitted-before-appkit: the original C predicates accepted,
  selectedReturnCode null, immediately before the first explicit
  NSApplication.sharedApplication call.

The phase name means that explicit call boundary. It does NOT mean AppKit,
dyld or the Objective-C runtime has not already performed pre-main or pool
initialization. The existing autorelease pool is deliberately still first.

Recorded handoff fields are entryPidPreserved, gateInheritedWithoutCLOEXEC,
gateMarkedCLOEXEC and executableIsPayload. The original main refusal predicate
uses only the first three. A false executable flag therefore remains truthful
DATA, not a newly invented refusal66. These fields do not add a SH-lock probe;
the original later payload/observer checks retain their separate meaning.

The helper uses plain bounded C formatting and the existing exclusive writer.
It does not open/readmit a root, repeat a gate predicate, call a framework,
change CLOEXEC or inspect/convert a lock. Refusal65/66 is irrevocable before the
publication and unchanged even if writing fails. Successful main flow also
does not depend on publication success. No alternate sink or second attempt
is allowed. Earlier argc/account/argument/root failures remain without a safe
external marker. Existing AppKit delegate, payload-start and payload-quit
bodies are unchanged, including the original run/activation/normal-Quit flow.

## Strict parsing and honest unresolved boundary

Each record is private bounded DATA, not a self-authenticating process receipt.
Existing readers require nofollow regular single-link0400 files, admitted
account UID/GID, bounded bytes, stable original FD/name full9 and a consuming
close. Only initial ENOENT is absence; an occupant, read failure, disappearing
original, malformed/duplicate/nonfinite/extra JSON field or changed source
refuses. A readable marker does not prove its writer's last fsync/close.

The new parser requires exact source/case/phase, strict integers rather than
booleans, consistent errno/ENOENT, and exact main-predicate facts/nulls. Entry
gate refusal, returned exec and payload-main records are mutually exclusive.
Payload-start/quit cannot coexist with an entry or main-refusal record. If a
main-admitted record and payload-start are both present, their original static
PID/CLOEXEC/executable facts must agree.

A strict early-termination diagnostic requires the actual observer status1,
the existing early-termination firstFailure, one callback/body/handoff, original
launch/reference/termination/EX-after/root-close/timely facts, no work-deadline
failure, NSError, normal-Quit request, claimed payload identity, complete
observation or payload start/quit record. The selected branch record must
additionally be eligible: gate rejected-close cannot be false, and returned
exec must retain its original SH-held observation.

Alternatively, a full-payload boundary observation requires main-admitted,
actual observer status0 and the entire unchanged supported_observation predicate:
real payload start/quit, identity pairs, original shared-bridge observation,
activation/window/delegate facts, normal Quit and every original observer gate.
The top-level diagnostic flags still do not become product qualification.

Known phase DATA can be retained in an incomplete result. A marker alone does
not complete the diagnostic. Absent markers remain "unresolved", even if other
payload evidence exists. In particular, missing main DATA does not establish a
pre-main crash, exec success, a low-FD problem or an AppKit bug. It can include
entry/exec/loader/runtime/early-main/writer failures that this safe sink cannot
separate. No repeated run or speculative workaround is authorized by absence.

## Original bounds and unknown custody

The existing observer is byte-identical: one launch,30-second work window,
45-second final window and60-second original command-owner timeout. Late work
does not get a new deadline. Only normal terminate on the one returned
NSRunningApplication is allowed. No PID lookup/process scan, forceQuit, broad
OS/crash-log collection, alternate command owner or TCC change is introduced.

Original app exit remains null and all-worker finality stays
not-established-by-NSRunningApplication. A phase result never authorizes
deletion. Cleanup predicates remain unchanged: only proven completed compiler/
controller outputs and their own temp area may be removed after the original
complete observation. Application images, app-tmp, gate and diagnostic records
remain for disposable hosted-job retirement. Unknown app/resource state is
retained, never converted into success by a diagnostic marker.

## Focused local regressions and remaining work

The DATA/inert-FS module contains21 source/parser methods. Existing root
creation, group selection, original consuming-close and native JSON/identity
tests remain. New cases cover exact returned errno, all main union branches,
missing/extra/type/range/refusal inconsistencies, inter-record conflicts,
main/start correspondence, unknown/late/missing markers and source order.
Native C/Objective-C files are only read as text in those tests; no compiler,
LaunchServices, AppKit, fixture owner or native process is selected.

Authoring/static SOURCE checks are not a test result. The old local16 selection
is not silently reused as a21-method grant: Root must separately adopt the
minimal exact input/selection derivative and run it through its original
bounded control. Distinct implementation review and one expressly authorized
native run remain before any new full-payload observation may be claimed.

Production path/root authority, actual Tauri constructor/runtime behavior,
full inherited-FD lifetime joins, credential/vault/signing flows, maintenance
updates/removal and distribution remain outside this synthetic diagnostic.
Desktop/product readiness is not established by this work.
