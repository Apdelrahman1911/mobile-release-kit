# Private Windows launch-selection fixture contract

Status: **SOURCE only; unexecuted; Desktop NOT READY / undelivered.**
This document does not authorize execution. The root-owned reviewed native
execution path, source/compile admission and original process custody are required.

## Scope

The private `windows-installer-selection-fixture` feature extends the existing
protected retained-shell fixtures. It uses the actual one-shot installer
controller, borrowed 570/600-second lifecycle, acquisition, existing-prerequisite
admission, direct publication, activation and launch-selection owners.
There is no new process harness, shipping bridge, CLI command or installer entry.

Compile this feature with the existing protected five-profile/54-row input
roster. All profiles share the same real D/runtime; distinct shell row48 and
controls52/53 produce distinct I/profile values. The new normal-preparation arm
uses Fresh=A, Reuse=B, WrongCaller=C and BadManifest=D as ordinary valid DATA.
It does **not** run the historical wrong-caller or corrupt-manifest behavior.
The original five tests keep their existing behavior.

The composed SOURCE extends the existing closed outer owner with the 24
`SelectionFixtureCase::ALL` cases below and their fixed native observations.
This is implementation SOURCE, not executed verification evidence. Do not
concatenate a selector into a command string, run cases together in one libtest
process, invoke the historical raw path, or infer original finality from stdout.

## Required setup and ownership

- Use a genuinely task-owned disposable Windows native episode and the accepted
  protected fixture stager. OS-derived ProgramFiles, CommonPrograms and the exact
  native64 HKLM registration are real original namespaces, not substitutes.
- Establish positive fixed-name absence/ownership before setup. Never replace an
  existing user's shortcut, registration, retained payload or recovery record.
  The selection owner refuses incompatible occupants and uses no replace rename.
- The existing OS Uninstall parent must be present/protected; only the literal
  MobileReleaseKit child may be created/deleted. Use genuine supported TxR, with
  no nontransactional fallback. OS-derived file roots must be local NTFS on the
  same admitted volume.
- The fixture requires genuine already-present WebView2. Row49 remains inert
  fixture DATA; it is never executed as a vendor installer.
- The selection episode starts with A absent and no selected MRK launch entries.
  Running the historical retained5 first would already consume/create A; do not
  silently reuse it. The historical and selection dispatches require different
  independently admitted fresh VMs; neither route resets a shared namespace.
- Keep source trees, published runtime, retained input trees, canonical profile/
  launch provenance and recovery records needed by later steps. Capture their
  native identities, ACLs, contents and complete bounded rosters through the
  existing outer owner. They are not disposable merely because a child exited.
- Each application invocation has exactly the fixed app-test name followed by
  `--exact --ignored --nocapture --test-threads=1`. Native originals likewise use
  their own single fixed exact selector. The existing original owner
  holds the real process/wait/exit, bounded output and cleanup/finality custody.
  Existing eligibility strings remain selectors only, not native authority.

## Separate preview/apply transport

The fixture process emits at most one canonical, bounded (16 KiB) line:

`MRK_WINDOWS_SELECTION_PREVIEW_V1=<closed JSON>`

For the later matching Apply process, the outer owner supplies these exact bytes
as `MRK_WINDOWS_SELECTION_FIXTURE_PREVIEW`. The decoder rejects unknown fields,
wrong mode, noncanonical encodings, malformed paths/digests and overlong input.
No handle, callback, command or deletion permission is encoded. Apply reopens
the actual originals and compares the complete production preview.

Preview processes must have that environment variable absent. Acquiring Apply
processes also require the existing
`MRK_WINDOWS_RETAINED_FIXTURE_SOURCE` from the actual stager. The source hint
does not choose a destination or skip acquisition admission.

STOP cases emit `MRK_WINDOWS_SELECTION_RECOVERY_V1=<32 lowercase hex>` copied
from the actual selection owner. The outer owner must bind that result to its
real child and newly observed task-owned recovery directory/records before
supplying it as `MRK_WINDOWS_SELECTION_FIXTURE_RECOVERY` to **both** the later
recovery preview and Apply. Non-recovery cases require the variable absent.
A recorded identifier or printed result alone is not ownership/recovery proof.

## Fixed episode order

Each row is a separate original-owned process. Labels map one-to-one to
`windows_installer_controller::selection_fixture::<label_with_underscores>`.
The Apply column names the earlier actual preview whose bytes must be used.

| # | Case label | Input I / mode | Confirmation and expected native behavior |
|---|---|---|---|
| 1 | preview-fresh | A / InstallActivated | No acquisition/selection output; preview proposed A. |
| 2 | select-fresh | A / InstallActivated | Preview1; real acquire54, publish47, existing prerequisite, six-role activation, select A. |
| 3 | preview-reuse | B / InstallActivated | Observe current A, proposed distinct B with same D. |
| 4 | select-reuse | B / InstallActivated | Preview3; acquire B, readonly reuse47, activate, select B; preserve A/D. |
| 5 | preview-verify-reuse | B / RepairSameImage | Readonly54/runtime47; retain this preview also for case9. |
| 6 | verify-reuse | B / RepairSameImage | Preview5; verify without selector moves, registry commit or output bytes. |
| 7 | preview-remove-reuse | B / RemoveSelection | Authenticate launch ownership/provenance, no payload-health dependency. |
| 8 | remove-reuse | B / RemoveSelection | Preview7; remove only launch entries, preserve all retained inputs/D/evidence. |
| 9 | refuse-stale-repair | B / RepairSameImage | Deliberately supply Preview5 after removal; refuse changed snapshot before selection output/effect. |
| 10 | preview-repair-reuse | B / RepairSameImage | Fresh preview of missing entries; real readonly54/runtime47. |
| 11 | repair-reuse | B / RepairSameImage | Preview10; restore canonical B launch entries only. |
| 12 | preview-registry-conflict | B / RemoveSelection | Capture complete B observation while B registration is present. |
| 13 | registry-conflict | B / RemoveSelection | Preview12; genuine second TxR writer, actual ERROR_TRANSACTIONAL_CONFLICT before selector intent/move; rollback/close both owners. |
| 14 | preview-stop-old | C / InstallActivated | Preview next C while B remains selected. |
| 15 | stop-old | C / InstallActivated | Preview14; real acquire/reuse/activate, STOP immediately after successful old-selector rename. |
| 16 | preview-previous | C / RecoverPrevious | Case15 actual recovery ID; observe old B backup and actual partial namespace. |
| 17 | recover-previous | C / RecoverPrevious | Preview16 and same recovery ID; fresh readonly54/runtime47 restores B. |
| 18 | preview-stop-new | D / InstallActivated | Preview next D while B remains selected. |
| 19 | stop-new | D / InstallActivated | Preview18; real acquire/reuse/activate, STOP immediately after successful new-selector rename. |
| 20 | preview-current | D / RecoverCurrent | Case19 actual recovery ID; observe D selector and B derivative registry. |
| 21 | recover-current | D / RecoverCurrent | Preview20 and same recovery ID; fresh readonly54/runtime47 completes D selection. |
| setup | Task-owned payload damage | D only | After joining case21, mutate only a proven task-owned retained payload using the reviewed native setup owner. Preserve selection provenance/entries and all other trees. |
| 22 | preview-remove-damaged | D / RemoveSelection | Ownership/provenance admission succeeds without rereading damaged payload bytes. |
| 23 | remove-damaged | D / RemoveSelection | Preview22; zero payload verification rows, no new-selector move; remove owned launch entries despite damage. |
| setup | Task-owned foreign selector | Fixed shortcut | After joining case23, stage one known task-owned incompatible shortcut occupant with the reviewed setup owner; never use a user's occupant. |
| 24 | refuse-foreign-selector | B / RepairSameImage | Refuse incompatible occupant unchanged, with no producing selection output. |

The TxR conflict must run before the damaged-image removal: its actual second
transaction requires the still-present B registration. The ordering is also
encoded in `SelectionFixtureCase::ALL`.

## Specific native observations to reconcile

- Successful selection/recovery/repair must retain native registry commit
  `(1,0)`, closed before-commit and returned records, native-original closure
  and the original watchdog join. Readonly verification retains all54 input and
  all47 runtime original files through selection settlement.
- Only two STOP return points are armed. They call the existing controller
  `request_stop` **after** the real rename return and expected custody are
  retained, before another producing boundary. No native return is replaced.
  StopOld expects phase-mask3/two closed flushed records; StopNew expects
  phase-mask15/four. A later record/move/commit is a failure, not extra evidence.
- STOP finality still settles every known original and rolls back the genuine
  staged registry transaction. Unknown frames remain retained/failing. Missing
  post-return persistence is uncertainty, never an invented never-entered result.
- TxR conflict uses one second RegistryOwner registered inside the selection
  owner before native work. It stages identical existing values and never
  commits. The production owner must actually receive the conflict return before
  selector intent. Both transactions' original custody/once rollback/close and
  separate staged-byte accounting enter finality. There is no helper process or
  simulated conflict result. If the platform does not yield the required return,
  the test fails; do not manufacture a receipt.
- Stdout reports are closed DATA checked against the actual owner after native
  settlement and watchdog join. The outer owner must independently reconcile
  namespace postconditions, preserved tree/byte/ACL identities and bounded
  generated-output inventory. It must account for preparation/recovery output
  even on failure; Unchanged refers to authoritative selection, not no files.
- Fresh profile/launch provenance and pre-effect records are written through the
  production bounded write/flush/readback/EOF/consuming-close path. No producing
  record is written after returned error/STOP merely to claim a complete journal.
- A derivative native64 registration is not sole launch authority. Only the
  OS-derived CommonPrograms shortcut may select the exact retained-I shell;
  this fixture never launches that shell, resolves a link, uploads or releases.
- Teardown is the reviewed outer owner's task, only after its own original
  processes are joined. Remove only positively owned outputs no longer needed.
  Preserve all required source/evidence and other tasks' resources.

## Review corrections in this source revision

P1: closed FileOwner role budgets retain selection entries90, inputs86 and
runtime72 at the bounded16-component OS-chain limit. Normal/acquisition defaults
remain48; no verified input is closed early to evade the budget. Peak tokens are
THREE, not two: recheck_installer retains the original ProcessToken and opens a
current ProcessToken; collect_installer(current) then reserves a ThreadToken
before the actual no-thread-token return can retire it. The current authoritative
selector has its own explicit allowance.

- Selection entries: 3*(1+16) OS-chain originals +3 product/selection/target
  directories +3*3 provenance originals +2 recovery directories +7 records
  +2 recovery leaves +1 current selector +12 possible new output originals
  +3 token slots =90.
- Readonly inputs: (1+16) OS chain +12 exact InputLayout directories
  (including MRK) +54 leaves +3 token slots =86.
- Readonly runtime: (1+16) OS chain +5 exact runtime directories
  (including MRK) +47 leaves +3 token slots =72.

The focused actual reserve-path regression fills each closed role's non-token
allowance, reserves ProcessToken/ProcessToken/ThreadToken together, rejects one
extra slot and settles the unentered reservations without native calls.

P2: registered NtQueryKey/KeyNameInformation observations bind existing,
transactional and fresh-after originals to exact native64 names. Parent ACLs use
registry rights (not filesystem bit meanings), SymbolicLinkValue is refused,
and fixed names are rechecked after durable intents immediately before selector
moves, before commit and at fresh fixed-HKLM readback. After commit, named
proof uses the ordinary retained Parent and freshly opened ordinary ParentAfter
and After keys; after the actual After snapshot, ParentAfter and the ordinary
Parent names are checked again, including when the leaf is absent. A cached
NoHandle never substitutes for this post-lookup namespace observation.
Completed-transaction Staged/ParentStaged keys are closed only.
No postcommit query-usability or undocumented TxR namespace-lock guarantee is
asserted.

P3: remove plus initial positive absence performs an actual transacted leaf open
and compares fresh absence before a selector move. It does not create a missing
leaf or reuse the earlier cached NoHandle as transaction evidence.

## Remaining evidence — not a pass

Independent implementation acceptance, admitted reconstruction, focused DATA/
feature compilation and the real Windows episode/outer postconditions remain
required. The original product SOURCE capsule excluded independent OUTER changes;
this later composition supplies them against the exact reconciled A0 inventory.
Use complete beforeimage/mode/hash and resulting-tree checks, never whole-donor
overlays. Shipping maintenance bridge, bootstrap/full installer sequencing and
distribution enablement are separate unfinished work.


## Nonshipping retained selection verification profile

The private installer/selection feature gates are additional engineering
interfaces. The 24-case contract above and the integration below have not been
compiled or executed merely because their SOURCE is present. They do not open a
shipping installer, Store operation, arbitrary command or normal-user project path.

The separate `windows-installer-selection` dispatch selects
`windows-installer-selection-v1` on the retained-shell verification ref. It
runs on a **fresh disposable Windows VM**, never after the historical five-case
episode in the same namespace. Its fixed order contains 24 application originals
and 30 native originals: four source stages, an immediate native observer after
each application, and two narrow owned setup operations. The three original
raw-pipe probes precede both episodes. No namespace reset or destructive teardown
is part of either route.

Each application preview travels to its later apply as the **original canonical
JSON bytes**, including explicit null properties. An emitted preview, output DTO,
recovery ID, test name or workflow status is DATA, not native custody. The outer
owner also requires the bound original executable, command, actual zero exit,
two raw EOFs, consuming-close results and source/compiler identities. The original
process/pipe/close loop is unchanged.

The ordered bounded accounting transport records every output origin and actual
rename/registry return, charged and confirmed bytes, closed/flushed recovery
records, and original settlement. STOP-old closes mask3/two records; STOP-new
closes mask15/four records. A genuine transaction conflict can create its recovery
directory before selector intent: **Unchanged does not mean zero output**.
The competitor's report remains its original staging account; its later actual
closure is a separate mandatory observation, not a fabricated report field.

Native observers walk all54 source/image rows and all47 runtime rows. Canonical
tree commitments include each returned full identity, kind, ACL, content digest,
and complete child roster; omitted or sampled rosters do not pass. They preserve
prior originals through cumulative recorded renames, distinguish the one exact
same-length shell damage from protected runtime changes, and validate create-only
foreign-selector refusal. The finite role-derived lifetime-file cap reaches804
at owned damage; the existing40 simultaneous-live cap and original90s endpoint
remain unchanged. Default profiles retain their own256 lifetime cap.

The complete behavioral evidence budget is5,947,392 bytes: each of54 original
stdout+stderr pairs shares64KiB, each original exit record has8KiB, and30 separate
native snapshots have64KiB. The accounting/preview DTO limit is16KiB. Aggregate
limits do not replace per-file bounds. Only a redacted `selection-summary.json`
may be uploaded; raw original output and private native state stay private.

Native steps have3-minute workflow fail-stop envelopes; application steps have
11 minutes so they do not preempt the original570/600-second controller. The
selection-only340-minute job cap is an explicit fail-closed isolated-platform
boundary chosen by Root, **never proof of finality or worst-case completion**.
The original controller ceilings total285 minutes (24*600s +30*90s), whereas
all54 workflow envelopes total354 minutes (24*11min +30*3min). The other listed
probe/acquire/compile/precheck/finalize/retain envelopes add44 minutes, reaching
398 minutes before checkout/tool setup/preparation/upload. Neither340 nor the
hosted360-minute ceiling promises completion if every envelope reaches its
maximum. A job deadline is a failure with unverified finality, not permission to
shorten an original owner deadline. Expected duration requires actual observed
runtime. If the real selected journey approaches the cap, only genuinely
independent fresh-VM episodes may be split after dependency review; no unproved
native state may be transferred. An unavailable, timed-out, cancelled, skipped or
unexecuted original is not a pass and cannot release the next original.

Source review, local DATA/compile checks, actual fresh Windows verification and
protected delivery are separate gates. This documentation and SOURCE packet
supply no native pass or readiness receipt. Desktop and the shipping installer
remain NOT READY / disabled until their complete applicable evidence is accepted.
