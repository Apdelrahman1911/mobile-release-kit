# QA-006 verifier fixture-base amendment — finality plan R4-R3

**PROPOSED — independent plan review required; NOT implementation or execution
authority.** This is the bounded correction for **VFBP-R2-01**, not a new product
or Store finding. It supersedes the finality, propagation and mutable-ledger
parts of rejected R4-R2, not its exact seed/editable contract or any original
R4-R4/R4-R3 requirement. No helper implementation accompanies this plan.

## 1. Original finding, evidence and non-negotiable scope

The immutable basis is `fixture-base-plan-snapshot-r2/` under this directory.
Its 139 members, 4,446,810 bytes, and manifest remain unchanged:

- `BINDINGS.json`: SHA256
  `180ff938b59c59f18b14e28b04211bacb7dcafac4bbb53c3150a672986f83d29`.
- `FIXTURE-BASE-PLAN-R4-R2.md`: SHA256
  `33287b70077bc781993d38d094800e74afbedaec2f828535cdc08d051b7de5b4`.
- `FIXTURE-BASE-MEMBER-REVIEW-R2.md`: SHA256
  `21d518d6fb83e6c2fc694fed353c18bbb65c48dfaf8593d3fc5371f1462873d5`.

The original independent R2 review is
`../verifier-fixture-base-plan-review-r2/PLAN-REVIEW.md`, SHA256
`49e6aaf5bbb91757aabe1806a17811b0610c943b533a9f5dc1bb80ea654d700c`;
its decision SHA256 is
`bba73d793a28a7961c10b4650caaad066a061e53d117e7914c58ffa125a5b21d`.
The decision is **REQUEST_CHANGES**. No later discussion has approved R2.

All line citations below refer to those immutable `current29/` and `drivers/`
copies, not moving drafts. `action_io.py:701-720` can replace the final ledger
at :717 and then fail at check/fsync/check, directory close, later readback or
the action's terminal boundary. `verify-all.py:181-207` can therefore retain a
genuine joint receipt and PASS/outputEvidence bytes after failed parent
finalization. Its best-effort diagnostic may also be absent. The current parent
correctly stops (:197-211), and restart is already rejected (:219-228). The
finding is **not** a demonstrated ordinary continuation of that failed loop.

R2's later disk-only chain cannot distinguish that history from a successfully
returned original action. Checking the next RUNNING row is not enough: it can
be spliced. `bindings.collect:741-768` starts source-snapshot/native Git before
tool probes. `check_frozen:991-1018`, `prepare_wheel:1318-1324` and the observer
entry reach those operations before their late active-ledger check. Admission
must precede *all* such acquisitions, not just the Python version probe.

Retain R2 sections 2, 4, 5 and 7-10 except the explicit replacements here:
source-only minimal creation; exact pip24/setuptools79.0.1 inputs; strict
produced/pre-existing union; genuine same-base offline PEP660 install; exactly
twelve editable files/four directories; independently expected bytes/modes;
empty editable source build/egg-info projection; later genuine full wheel
outputs; immutable original request/seed/source freeze; no partial adoption,
reseed, uninstall, extra installer, retry or TCB reclassification. The original
two source caches and historical53 fixture venv payloads remain out of scope.

## 2. Chosen design and threat boundary

Use **one original-factory-retained live session**, separate **action-local use
tickets**, and **explicit inherited kernel capabilities** for the genuine exec
helpers. A disk receipt is necessary evidence, never the authority to mint
those objects. Do not add a success filename, status marker or resume API.

The trust boundary remains the existing cooperative verifier, not protection
against malicious code already able to replace trusted executing helper source,
read arbitrary private process memory, steal another process's descriptors or
invoke Popen while bypassing every verifier API. Tests may forge/replace all
declared evidence and descriptor arguments; they may not replace the trusted
factory/receiver implementation and then call that replacement an authentic
consumer. A checksum accompanying attacker-selected content is not origin.

There are two independent anchors:

1. In the actual original proof process, the registered factory and session
   objects, original parent PID, case identity and still-retained resources.
2. In an actual exec helper, a **literal original-factory anchor in its trusted
   copied source**, plus possession of the exact inherited kernel objects,
   actual recipient binding and live ancestor channel described in section 5.

The second anchor must not be supplied by request JSON, argv, environment,
another success file or the receiver itself. Otherwise a fake descriptor plus
a fake expected identity would just be another self-authored assertion.

## 3. Original-parent session, successful return and state machine

### 3.1 Factory registration and explicit caller propagation

Add the supporting types/registries to the existing ignored `action_io.py`;
do not introduce an importable plugin or expand the helper filename namespace.
Construct `FixtureSession` only from the live registered original `Proofs`
factory/case capability, before its request and before any base producer.
Constructors require the retained factory registration by identity, not a
boolean, nonce string, PID, arbitrary callback or path. The ordinary public
constructor, a copied/pickled object and a Mapping lookalike cannot register.
Check the real current parent PID; forked/copy-created memory is not the owner.

`full_fixture` returns an explicit case handle containing paths/config/logical
data and the private live session. Update every caller; do not reconstruct the
session with `session_for_path()` or silently infer one from disk. Registry
entries for produced roots remain tombstones after failure/closure until the
owning proof case ends. They prevent deletion or relabelling of a marker from
turning that same root into the generic pre-existing-runner variant.

The original factory selects a finite profile before base creation. Profile,
declared helper roles, source identities, pre-freeze setup seams and the fixed
editable policy are bound in the original request. Existing source/config/test
setup seams occur only in their declared pre-freeze phase. They cannot change
the exact synthetic editable source, seed inputs, authority kind or original
request. The later source/helper/config freeze is finalized once, by the same
parent; a later action cannot re-freeze its way to authority.

### 3.2 Observe the whole action, not its final-looking writes

The original session's action wrapper invokes the real existing action context
and the actual operation. Its **caller-side code after normal return through
the entire context manager** records successful finality. This includes final
ctx.check, revoke/close and, where that action owns handlers, restoration and
terminal_check (`action_io.py:189-224`). `ctx.state == 'closed'` is insufficient.
No child supplies an `actionSucceeded` value or invokes the parent observer.

For seed and editable transitions, retain an immutable in-memory finality fact:
original factory/case/request; actual action identity; exact validated result
references; original seed/source freeze; actual producer/route; and the exact
successful ledger observation when applicable. Register it only on that real
normal-return path. A receipt-write or ledger-replace return alone cannot do so.
No additional file publication is needed to make this fact authoritative.

Separate **historical finality** from **current dispatch authority**:

- Failure before full transition-action return creates no finality fact, even
  when PASS-shaped files are visible. The session becomes terminal for dispatch.
- Once a complete action returned successfully, a later failure does not undo
  that historical fact. It *does* revoke the current session/dispatch and all
  outstanding use tickets/channels; it cannot authorize another gate.
- Cancellation between successful return and issuance is therefore safe:
  successful history may remain, but the next issuance checks the pending flag,
  current session state and original remaining work budget and fails closed.
- Failure/cancellation in a real creation, transition, dispatch, collection,
  finalization or helper role latches that session. Unauthorized use of an
  unrelated/wrong-context object does not mutate another live owner's history.
- An explicitly descriptor-only negative schema inspection is not a successful
  dispatch and grants no native authority. Its expected rejection need not
  falsely erase an earlier completed transition; see section 7.

### 3.3 Permitted progression

```text
registered absent case
  -> original bootstrap action (minimal creation; seed; full validation)
  -> original parent observes whole bootstrap-action success: SEEDED
  -> declared pre-freeze setup/collection -> original source freeze finality
  -> original controller setup and exact attempted-gate save finality
  -> exact declared gate (prelaunch -> real collect -> complete/account)
       prepare-owned-build finality
       -> single original editable transition action
          -> parent observes whole action success: EDITABLE
       -> original wheel / optional separately declared observer / cleanup
  -> original final-accounting action -> terminal, read-only inspection only

any actual session failure/cancellation -> retain evidence; no new dispatch
```

SEEDED native use is permitted only to declared original preparation, collection
or controller roles; a completed seed does not authorize arbitrary commands.
EDITABLE native use additionally requires the original parent's editable
finality fact. No second editable attempt or return to SEEDED is allowed.
Terminal all-PASS evidence is not a no-active-gate exception. An all-PASS route
closes native authority even when the session has no error.

### 3.4 Tickets and collector dispatch authority

Each current action receives an opaque `FixtureUseTicket`, registered by exact
object identity against its session/lease, real ctx, case/evidence/source,
request, freeze, phase, fixed gate/index and declared operation. It expires
at action exit, failure, cancellation or role closure. Its decoded description
is diagnostic only. No serialized/closed/wrong-root ticket can be rebound.

For the existing noneditable split scopes, successful prelaunch returns an
original-session-retained **dispatch reservation**, not a revived Action.
The original collector accepts that exact registered reservation once, binds
it to its own actual start/deadline and actual Popen handle, then consumes it.
Before acquisition it checks original finality, current attempted-gate save,
exact argv/cwd/environment/role, no prior attempt and cancellation. There is
no second prelaunch, retry or fresh budget inside this bridge. Its completion
does not authorize the next gate until the original completion/accounting
action itself has returned successfully.

Editable retains R2's one unreset action/FrozenAuthority across prelaunch,
real installer, independent runtime/source validation, joint receipt and ledger
save. Its `FixtureEditableTransition` remains usable only by the original
parent's joint completion path, never by load/collect/launch or a child.

## 4. Earliest admission and prevention of authority downgrade

Introduce one internal descriptor-only fixture-use admission routine. It checks
the original registered session or inherited lease **before** ordinary frozen
loading, effective-runtime traversal, source/native Git, tool hashing/probing,
application/fixture startup or another helper/native dispatch.

Call it at these actual boundaries, propagating the ticket explicitly:

- `bindings.load_frozen`, `require_authority`, `FrozenAuthority.check/recheck`,
  `check_frozen`, **the beginning of collect before snapshot**, and direct
  `tool_bindings` calls. Initial collection uses the genuine SEEDED pre-freeze
  ticket, not a fabricated FrozenAuthority.
- `owned_outputs.guard_inputs`, effective bootstrap checks, execution-output
  selection, output completion, prepare/seal/cleanup, prior_workers and actual
  wheel/runtime producers; and `frozen_diff._inputs_unchanged`/entry consumers.
- The actual exec/helper entry before its first load, metadata/backend import,
  observer query or source-bootstrap invocation, then before each later action
  and native acquisition. For helper startup itself, the original parent must
  already have validated the base and live exact-dispatch reservation before
  Popen. The receiver cannot retroactively authorize an unchecked startup.
- `native_reader.run` and `process_gate.execute` consume/check the propagated
  current fixture acquisition authority where their caller is fixture-bound;
  fixed native leaves receive no authority descriptors. Existing raw Git/view
  callers retain the same ctx binding through their actual acquisition path.

Keep ordinary FrozenAuthority exact-type, same-root, same-ctx, single-load and
backing-reference checks. A valid capability does not bypass source/runtime/
tool/receipt validation. A valid file chain does not bypass capability checks.
No recursive load_frozen/active_ledger/collect path may implement admission.

Produced classification is checked against the original root registration and
the copied source's literal anchor, independently of mutable input markers.
Changing config, request, scope, bootstrap tag, selected Python or deleting
request/receipt files cannot choose the pre-existing variant. A copied helper
with a produced anchor cannot serve a generic root. In the original parent,
the produced-root tombstone cannot be forgotten after a failed action. Actual
pre-existing runner selection remains bound to its original reviewed config/
bootstrap/interpreter references; it is not a catch-all for missing authority.

This protects the supported guarded APIs and actual callers, not arbitrary
out-of-band user execution of a runtime binary. Negative fresh-action tests
must call the real gate/guard or use the trusted original base for receiver
tests; they must not claim that invoking an unchecked produced Python directly
somehow executed no Python startup.

## 5. Exact cross-exec capability protocol

The source-loaded controller is already in the original parent
(`verify-frozen-diff.py:214-216,673-680`). Do not turn it into another supervisor.
However `legacy_cleanup:1233-1317` really execs prepare/wheel/cleanup helpers,
and `run_runtime_producer:1084-1195` really execs the source-only venv child.
Removing those processes or replacing their completion with a callback would
invalidate the genuine lifecycle. The following transport supports them.

### 5.1 Preallocated source-anchored kernel objects

Before runtime production/request/freeze, the original factory allocates only
the exact slots for its selected profile. Each slot consists of:

- one newly created private regular object in the newly owned case, opened
  separately for issuer write and recipient read, then unlinked while its exact
  original identity/descriptors are retained;
- one child-to-issuer readiness pipe and one issuer-to-child reply/lifetime
  pipe, with all ends CLOEXEC by default;
- a random private fixed-size immutable header, and a bounded initially-empty
  grant region. The original factory retains a read descriptor for the object
  for the whole case, so its inode cannot be recycled into a lookalike.

Use no named reopen/adoption path, memfd-only dependency, temp-directory search
or descriptor discovered from a record. Check actual no-follow creation/type,
owner/link state, identity and access mode. The identity claim uses the retained
regular object's device/inode/type/uid, **not** a presumed portable pipe inode.
The secret header is never logged, put in argv/env or written in report JSON.

Stamp a literal `_FIXTURE_FACTORY_ANCHOR` into a single fixed sentinel in the
copied `action_io.py` before synthetic helper acceptance/request/freeze. The
factory first verifies the source being copied against its original bound
helper bytes. The literal contains case/source/owner identity, original parent
PID, exact finite role/parent-role map, original regular-object identities,
header SHA256 commitments and the preallocated descriptor *locators*. The
unchanged nonfixture module has no such anchor and cannot accept an inherited
fixture lease. No new importable file or generic supplied anchor parameter.

The original request binds the emitted helper source and this public map. The
later freeze binds the same bytes. The grant subsequently binds the real
request/freeze/actual entry source and command; avoid a source/request/grant
self-hash cycle. Where the creation argv contains the request's own digest,
the immutable request declares that single fixed self-reference substitution;
the observing parent resolves it from the original retained request reference.
No child chooses a substitute argument.

Preallocation means no authority FD flags are added to actual argv or env.
Each trusted entry selects its fixed role from its existing validated mode;
the stamped table only tells it which descriptors to validate. FD numbers are
**not authority**. All exact existing route identities stay unchanged except
R2's already-declared editable pip hardening. The parent dispatcher passes
only that role's exact `pass_fds` set with `close_fds=True`.

### 5.2 Ready -> sealed original grant -> GO

Use fixed binary frames, not unbounded JSON or an extensible RPC. The source
declares exact magic/version/field widths, a maximum total header+grant size
within the original locator/record bound, and one READY/one GO per role. Reject
extra/truncated/duplicate/unknown frames. Both collectors charge **all** grant,
control read/write and readback bytes within their existing output/native or
action byte accounting, never on top of the original cap. Small control frames
cannot inherit an unbounded or newly refreshed time allowance.

1. Original parent validates the whole base/source and current role ticket or
   dispatch reservation. It retains all resources before entering real Popen.
2. Only after real Popen returns does the original collector register the actual
   handle/PID and close its transferred endpoint duplicates. A Popen after-effect
   exception never gets a guessed handle or PID grant.
3. The child's existing first action validates the actual inherited RO regular
   descriptor against its literal source anchor, validates exact access/CLOEXEC
   and declared endpoint ownership, generates a fresh receiver nonce, writes
   one fixed READY containing its actual PID/role/nonce, closes readiness write,
   and waits without any further frozen/tool/Git/runtime acquisition.
4. The existing issuer collector services READY while draining the existing
   output streams. It requires exact readiness/EOF, actual registered Popen
   PID, current issuer/session/pending state, fixed role/command and original
   remaining cutoff. No helper can ask it to run a command or mint another slot.
5. The issuer seals the original slot with exact request/source freeze/ledger
   observation/seed-or-editable finality binding, role/index, actual command,
   cwd/environment digests, real issuer/recipient PIDs, fresh nonce, original
   dispatch generation and cutoff, and parent-grant binding when applicable.
   These are fixed-field hashes/identifiers, not arbitrary file selectors.
   Require complete write, fsync/readback and close of its sole permitted writer.
6. Only after those operations succeed does it send exact GO plus the sealed
   grant digest. The child validates the grant against its independently anchored
   kernel object and its own nonce/PID/parent/role, then validates the actual
   original records and runtime through normal guards. A raw GO byte, supplied
   checksum, PID, FD number or file-shaped header alone is never accepted.
7. The reply write end stays only with the live issuer. After GO, the channel
   carries no further grant messages; EOF means revocation. Check pending flag,
   inherited cutoff, channel EOF/error and exact kernel descriptors before each
   subsequent guarded action/acquisition. The receiver restores CLOEXEC before
   continuing. A role failure closes/latches its live authority and channels.

The original parent checks successful transition finality *before issuing this
later grant*. Grant publication is communication of that already established
authority, not a new disk proof that its own publication action succeeded. If
grant write/readback/close/GO fails, no next role is issued; the actual dispatched
child is accounted/disposed under the original collector. A later failure does
not retroactively erase an earlier transition fact. Cooperative cancellation
checks, not an impossible zero-time distributed revocation guarantee, govern
an already-authorized in-flight acquisition; no later dispatch is allowed.

The normative wire/storage shape is deliberately finite: header256 bytes,
grant2048 bytes, READY64 bytes, GO64 bytes; final regular object2304 bytes,
within the existing4KiB locator bound. Use big-endian unsigned fixed-width
integers, SHA256 fields exactly32 bytes and zero padding. Magic fields are
distinct fixed16-byte domain strings for header/grant/READY/GO; version is1.
Reject nonzero reserved fields, other lengths/versions, invalid role/phase
enums, out-of-bound integers, duplicate frames or extra pipe data. Require
initial regular size256 and final size2304, regular type and link count0.

- Header: magic/version/role/parent-role; root PID/device/inode/uid;32-byte
  private random header nonce;32-byte original case/source-owner identity
  commitment; all other bytes zero. The source literal commits these original
  header bytes and independently expected actual kernel identity.
- Grant: magic/version/role/parent-role/phase; issuer PID, recipient PID,
  dispatch generation, exact gate index and original cutoff in monotonic
  nanoseconds; fresh READY nonce; fixed32-byte commitments to header, original
  request reference and bytes, freeze reference, source/policy, exact route/
  command, current ledger observation, original seed/editable finality facts,
  actual entry-source bytes, cwd, environment, parent grant, allowed delegation
  and original current scope. Everything else is zero padding. Pre-freeze and
  bootstrap phases have precisely declared zero inapplicable fields, not an
  optional-field or success fallback. An in-progress bootstrap scope is labelled
  as such and cannot stand in for a completed seed/editable finality fact.
- READY: magic/version/role/reserved padding, actual recipient PID and32-byte
  fresh receiver nonce. GO: magic/version/role/reserved padding and32-byte exact
  sealed-grant digest. Child readiness EOF is required before GO. After GO,
  zero bytes pending (EAGAIN) is a live channel, EOF/error or any additional
  byte is revocation/protocol failure, checked before the next acquisition.

Use offset-explicit descriptor reads/writes so inherited offsets cannot change
what a peer validates. Grant construction/validation uses the fixed enum/field
layout, not a generic payload serializer. Hash commitments bind the original
records but do not establish origin without the independently anchored kernel
object and live actual parent/recipient protocol. Actual-code review must pin
the final exact struct offsets/domain literals and field validators before any
native proof; no implementer may add an extensible message or path field.

### 5.3 One fixed nested delegation, no general forwarding

Only the compound `wheel-install` helper may receive issuer custody for the
root-preallocated `wheel-source-venv` leaf slot. The root grant explicitly binds
that one delegation and its fixed child command. The outer helper cannot create
replacement kernel objects, keys, slots or new roles. Root custody for the
delegated writer/readiness/reply endpoints is transferred/closed exactly once;
the root retains only the original regular RO anchor and its own ancestor
revocation write end, not pipe duplicates that could suppress EOF.

The nested real collector performs the same readiness/PID/nonce/seal/GO protocol
with its actual child. That child receives its own RO slot, the immutable RO
outer grant, and the ancestor lifetime read end. It verifies:

- both kernel/header identities against the original stamped root map;
- the outer grant's actual recipient equals its direct parent's real PID;
- its own grant is the one declared delegation and binds that outer grant;
- source/request/freeze/gate/generation/command agree through the chain;
- both ancestor/direct lifetime channels and inherited cutoffs remain valid.

The leaf cannot delegate and receives no writer or unrelated role endpoint.
Its original source-only venv producer still performs no native child/query/view
work (`owned_outputs.py:993-1081`). Installed pip, target imports, version probes,
Git, numeric worker queries and ordinary leaf commands get **no** capability
descriptors. Their trusted invoking helper checks its live ticket before Popen.
No unauthenticated relay, inherited-all-FDs mode or env-based capability lookup.

### 5.4 Finite profiles and endpoint ownership

Every profile has one base-creation helper slot. Thereafter allocate only:

| Original profile/callers | Additional helper slots | Delegation |
| --- | --- | --- |
| Collection/discovery/tool drift/authority/observation; direct original-parent callers | none | none |
| Ledger one-leaf route | none (the `-c pass` command is a leaf) | none |
| Worker deletion two-gate route | exact `synthetic-cleanup` helper | none |
| Six-gate preparation/lifecycle/VPG schema | prepare, diff-check, cleanup roles; a fault/schema script occupies the same original role | none |
| Original four-gate editable build/wheel cleanup | prepare-owned-build, wheel-install, exact final cleanup | wheel-install -> one source-only venv leaf |
| New, separately named positive observer regression | the same editable route plus one explicit observer before cleanup | same one venv leaf |

Thus the largest declared profile has six helper slots including base creation;
there is no speculative reserve pool. Never insert that observer into the
original four-gate proof or final45. Direct repeated checks keep their original
finite per-case call list, not an unlimited arbitrary `next()` permission.

The existing Bash wheel route is explicitly reconciled, not silently dropped:
`gate_list.py:51` invokes `wheel-smoke.sh`, whose :5-16,35-36,148-151 make many
separate helper execs. It belongs to the unchanged actual final45/pre-existing
runner route, with its already-selected original runner Python (:5). None of
the original produced-fixture profiles invokes that Bash route; their actual
compound wheel is the generated Python helper at :1233-1317. Do not pass a
fixture capability through Bash or claim one leaf grant covers all its execs.
An attempted produced-fixture reroute into this undeclared Bash chain must fail
at original-parent route admission before Bash starts. If a genuinely required
produced-fixture Bash caller is found during actual-code reconciliation, retain
it as an unimplemented boundary and obtain a revised independently reviewed
finite transport plan; do not skip that caller or silently treat it as generic.

The factory owns original descriptors until a declared transfer. The sender
owns only its slot writer/issuer pipe ends and retained anchors; the receiver
owns only its grant reader/readiness writer/reply reader and permitted ancestor
readers. Each transfer has a fixed ownership table and each resource is removed
from that table before its one close attempt. CLOEXEC and exact `pass_fds` are
checked at every actual child boundary. A close-after-effect exception cannot
justify retrying a numeric descriptor that may have been reused. Parent case
closure disposes only its own remaining descriptors, not unrelated processes,
source, retained evidence, caches or historical runtimes.

Cancellation/EOF/truncation/backpressure/selector errors, failure before or after
Popen, writer close/readback/GO failure and unexpected descriptor inheritance
are terminal. If acquisition becomes ambiguous, report UNKNOWN; closing known
issuer endpoints makes an ungranted waiting child self-abort but does not invent
its original parent's reap evidence. Signals remain authorized only by the
original real still-owned handle, never a reported PID or capability record.

## 6. Historical pending snapshot and current ledger transaction

Retain the exact pending editable ledger bytes in exclusive immutable
`FIXTURE-EDITABLE-PENDING-LEDGER.json` **before the attempt**. Validate the actual
current bytes, copy those same bounded bytes, read them back, and bind that
snapshot in `FIXTURE-EDITABLE-ATTEMPT.json`. Do not reserialize an approximately
equivalent dictionary, embed a >jsonString raw blob, or retain a forever-live
reference requiring mutable final-verification.json to stay pending.

Implement a narrow action-local `LedgerObservation`/transaction facility:

1. Validate/read the current actual ledger once, retaining immutable decoded
   contents, exact raw byte/reference observation, current ctx and original
   session's expected gate/index. This lives outside FrozenAuthority's immutable
   backing-reference set. Keep the actual pending observation until save.
2. A produced-fixture FrozenAuthority cannot bind final-verification.json as
   an immutable read_record reference. Convert its consumers (`execution_outputs`,
   `bind_output_completion`, `active_ledger`, `prior_workers`, frozen-diff
   predecessor/bind paths) to the same narrow current-ledger facility. Ordinary
   immutable original references and same-action single authority remain intact.
   The reviewed pre-existing-runner path retains its existing validation/route
   semantics; no generic unbind/rebind or skip-reference API is added.
3. Only the original current controller writer can replace that observed ledger.
   Immediately before the existing replace, compare the current actual bytes
   and identity with its retained observation. This is a guarded compare/
   readback transaction under original exclusive writer ownership, not a claim
   that POSIX os.replace is a kernel compare-and-swap against hostile writers.
4. After replacement, independently read back the exact intended new bytes and
   identity. All fsync/close/recheck/terminal requirements stay in the original
   action. Do not bind a different reference to the same immutable authority,
   load a second FrozenAuthority or reload a runtime to adopt its new contents.
5. The new observation is a pending result until the original parent observes
   full action return. Only then may its live session advance the expected
   current ledger/gate. On after-effect failure retain the candidate bytes and
   invalidate dispatch; do not overwrite them or require a diagnostic to revoke.

Historical finality facts and the pending snapshot stay unchanged as the real
ledger advances, a wheel populates build/egg-info, and cleanup removes generated
outputs. Historical editable evidence validates its original projection, not
obsolete generated files. Current generated-output guards follow the actual
later producer/cleanup lifecycle. The mapped source and complete seed/editable
startup namespace remain protected on every real use.

## 7. Descriptor-only inspection is not native authority

Add a distinct `EvidenceInspection` result from a distinct inspection entry.
It may read bounded original records and apply the **same** strict schema/
reference/producer/predecessor validators used by normal loaders. It cannot
enter ctx._authorities, issue tickets, start a native process, select runtime
startup for execution, open a new view, perform cleanup or create completion.

Do not make `load_frozen(..., allow_inspection=True)` or an overloaded
require_authority accept it. Shared validation functions operate on internal
immutable data; only the genuine live native loader can register a
FrozenAuthority, after section 4 admission. `inspect_predecessor` may reuse the
actual predecessor validators without calling their acquisition-capable entry.
Passing an inspection value into load/check/guard/producer/cleanup/session or
collector interfaces must fail by exact type/registration before acquisition.

This handles terminal all-PASS inspection and the actual VPG69 schema matrix
(`drivers/vpg-schema-child.txt:107-291`). That matrix deliberately mutates and
rebinds fixture records to reach deep validators. Preserve all original labels,
real parser/assertion paths, genuine successful prefix and restored positive
case. Its deep schema negatives use the explicit read-only validation path;
they cannot rewrite the live grant's ledger/freeze bindings. Separately test
that the live native entry rejects the same mutations at admission. Do not
label early capability rejection as proof of each deeper original schema check.
There is no fixture flag that weakens normal predecessor/native validation.

Disk-only inspection reports a valid published candidate chain separately from
original-parent finality, which is **not reconstructible from disk**. It must
not report all-PASS files as resumed execution permission or READY.

## 8. Scope/budget compatibility, before and after

No new supervisor, worker, handshake action, time pool or policy limit. Do not
aggregate every produced gate into a new 120s scope merely because it is more
restrictive: that is not proven compatible with genuine positives. Preserve
separate accounting where it already exists, except R2's explicit editable
single-action requirement.

| Path; immutable source | Existing scope | Planned scope/accounting |
| --- | --- | --- |
| Fixture base, verify-frozen-diff:602-605 | setup action120; native_reader max30 per acquisition | R2 creation+seed under the same original setup action/counters; source helper receive shares its original producer action; no handshake action |
| Authority/config setup, :605-651 | separate existing action120 | unchanged; session records normal return, does not renew setup |
| Collect/freeze/check, :666-671,761-785 | existing distinct action120; each native<=30, active-native1 | unchanged; admission/ticket/source stamp validation consume those same counters |
| Controller setup/start save, verify-all:139-149 | existing action120 per named scope | unchanged; parent-observed successful return advances only live dispatch state |
| Noneditable prelaunch/execute/completion, :153-187 | separate existing prelaunch120; actual collector's original work limit; completion120 | unchanged scope boundaries; prelaunch normal-return reservation consumed by existing collector; completion action grants next role only after full return |
| Exact editable transition, R2 section6 | R2 required merged prelaunch/real child/completion/save | retain that one action120 and <=30 native work; any protocol work shares the same remaining action/native/output counters |
| Compound wheel, owned_outputs:1084-1195,1204-1238 | existing admission/result/payload actions120; actual collectors; literal native routes | unchanged named actions/counters/limits; inherited lease/one nested READY/GO uses existing collector and child's first action |
| Helper receiver, frozen_diff/main, observer, generated producer | current first actual action and existing helper invocation limit | receive and validation run inside that first action; later original actions use live lease, never a renewed helper invocation |
| Finite driver, drivers/run-finite-proofs-r4:184,239-244 | original outer900 for each declared driver | unchanged original parent collector/group deadline; a session/grant never starts another 900s ancestor allowance |
| Actual final45/reviewed-preexisting runner | existing route/native/action/outer policies | no new capability protocol, observer insertion, command change or widened/shortened route budget |

The live collector binds its **actual existing** start/cutoff into a grant.
Child work is capped by that inherited invocation cutoff as well as each
original local action/native limit. The original finite parent continues to
enforce its own already-started outer900 cutoff and owned-group cancellation;
do not synthesize a later `now + 900` as that ancestor. No receiver or relay can
extend any received cutoff. Cancellation/ancestor EOF checks participate at
all subsequent acquisitions; original stop/reap allowances are disposition,
not new useful-work time.

Fixed protocol bytes are accounted against the same existing cap as their
collector: native_reader retains stdout2MiB/stderr256KiB and original action
allBytes/payload/newBytes limits; its total retained/control bytes cannot gain
an additional pool. The gate collector retains its original combined64MiB
budget, charging control/grant I/O within it while reporting actual stdout/
stderr log byte/hash facts separately. Do not falsify its log byte counts to
hide control traffic. Exact fixed-frame bounds also fit original locator/record
limits. New schema fields describing control accounting must be strict and
absent/zero for the unchanged no-channel mode. The original active-native1,
launch/object/graph/tool/name/JSON/inventory/output policies remain unchanged.

The planned compatibility argument is structural, **not a native timing/quota
PASS**: one existing helper stays one real child; ordinary leaves/commands and
original positive prefixes stay real; no extra producer/process/observer is
inserted into existing routes; protocol work has a small finite overhead within
the same limits. Actual seeded+editable R2 namespace traversal plus that overhead
may still exhaust a budget. All required positive profiles must demonstrate fit
under the original limits before acceptance. If they do not, retain the real
failure and obtain review of bounded duplicate-work corrections, never raise
limits, reset a scope or omit a positive route. Independent review must assess
this tradeoff explicitly; root has not approved an implementation.

Keep 4GiB free floor and512MiB fixture admission headroom. Capability objects
are a bounded temporary implementation resource, not permission to delete
retained proof data or any source/cache. Record all actual owned disposals;
UNKNOWN resources block later dispatch. Native feasibility remains UNVERIFIED.

## 9. Exact affected components and integration obligations

Only ignored verifier helpers/copied proof drivers/static review bindings:

- `action_io.py`: original factory/session/ticket/lease registrations, literal
  copied-source anchor sentinel, exact FD ownership/receive protocol, narrow
  ledger observation/transaction, non-upgradable inspection data. Preserve
  existing exception latching and terminal/context revocation semantics.
- `bindings.py`: earliest produced admission, typed authority union/source
  stamp checks, shared strict descriptor validators, distinct native load and
  inspection entry, no implicit state reconstruction before collect/native Git.
- `owned_outputs.py`: R2 seed/editable validators and joint receipt, current
  ledger API, explicit tickets at all producer/guard/bootstrap/cleanup paths,
  inherited one-hop source-venv delegation, source-output lifetime distinctions.
- `verify-all.py`: explicit case/session parameter for the genuine source-loaded
  controller; caller-observed full-action completion, exact attempted-stage and
  dispatch reservations, retained actual producer results before later failure,
  R2 single editable transition action, failure-only accounting and terminal close.
- `native_reader.py`, `process_gate.py`: exact optional registered capability
  dispatch, fixed `pass_fds`, existing selector READY/GO service, current cutoff/
  original output accounting, actual acquisition/close/disposition failures.
  No duck-typed callback that can grant itself a lease or widen budgets.
- `frozen_diff.py`, `prepare-build.py`, `cleanup-build.py`, `cleanup-wheel.py`,
  `observe-owned-workers.py` and executable `owned_outputs` entry: strict first
  receive in existing action, admission before load/check/query, no new fallback.
- `verify-frozen-diff.py`: authentic factory/profile/stamp/slot creation; explicit
  case propagation; actual source_controller/full_fixture/freeze/controller
  call sites; emitted lifecycle/worker/compound scripts and R2 source-only entry.
  Freeze emitted command source before its actual use; do not validate only its
  pathname or publish a script hash after execution as origin.
- `evidence_schemas.py`, `frozen_diff` receipt/predecessor validators and copied
  gate declarations: strict original request/attempt/joint runtime/control
  accounting/inspection schemas, exact concrete route comparisons and rejection
  of unknown fields/type coercion/extra phases. No product schema changes.
- All nine copied drivers, including mapped/VPG/integration callers and emitted
  VPG child text, freezer and finite manifests: propagate real cases/tickets,
  preserve original labels/counts and AST/source bindings, add named finite
  regressions/coverage and freeze the complete actual implementation for review.

Keep original helper namespace count, generic current command semantics and all
original tests. The full affected actual diff will need a separate independent
review, including cross-component callers, not just this protocol description.
Update ignored verifier instructions/coverage; product documentation is unchanged
because no consumer command or Store lifecycle is changed by this amendment.

## 10. Required adversarial, failure and positive tests

Retain every R2 regression and original matrix: **103+62 pure;219 original;
30 mapped;5 integration;143 VPG (69 schema/67 preparation);25 historical
mappings;10 controller;24 protocol;45 real gates/order;13 Ruby files;two
separate Bash syntax commands**. Preserve original218PASS/1FAIL/exit1, quota/
deadline failures and partial cases. None becomes PASS from this plan.

Add a finite named manifest with exact assertion and dangerous entry for each
case. Pure/type/FD-shape tests supplement, not replace, the genuine native
transition/producer/cleanup cases.

### A. Real after-effect finality failures

Use genuine prepare+seed+editable successful prefixes and actual output
validation/publication. Let os.replace of the PASS ledger **really succeed**,
then inject separately: immediate ctx.check cancellation; directory fsync;
post-fsync check; directory/file close after-effect; independent ledger
readback; action final check/revoke; and applicable handler restoration/terminal
failure. Deny failure-diagnostic persistence as well. Preserve the valid-looking
joint receipt/PASS bytes and real producer/log/ownership evidence.

For each case assert the actual controller fails, no next acquisition occurs,
no finality fact was minted for the incomplete action, later gates stay blocked,
and no install/reseed/adoption/cleanup retry occurs. Include a named interrupted
publication/termination simulation with retained files and no surviving grant;
do not claim an actual OS termination test if only an exception was injected.

In a fresh test action invoke the **real** later load/guard/check_frozen/collect/
tool entry at the earliest admission boundary. Count native/target/Git
acquisitions, not just final exit. It must reject with zero acquisitions. A
case that failed earlier setup or never published the PASS-shaped ledger does
not satisfy this obligation.

After genuine full transition return, separately fail a later gate/GO/save.
Assert the earlier historical finality remains true, the current session is
terminal and further dispatch is impossible. This prevents accidentally making
successful original transitions retroactively dependent on all future gates.

### B. Forgery, scope, downgrade and replay

Try next-stage RUNNING spliced into the retained failed ledger; all-PASS terminal
files; extra success filename; missing diagnostic; copied/serialized boolean/
dict/type-lookalike/closed/wrong-action ticket; changed request/source/freeze/
route/owner/predecessor; expired/consumed dispatch; and independent new session
or another factory attempting the old case. Reject before any acquisition.

Combine request/config/bootstrap-tag/scope/selected-Python changes and marker
deletion to request the generic pre-existing path, both in the original parent's
registered root and an actual stamped copied receiver. No downgrade succeeds.
Changed stamped source must be rejected by its original parent source binding,
not relabelled as a newly trusted factory.

Test descriptor-number/env spoof, arbitrary/fake regular object, byte-for-byte
copied header/grant in another kernel object, substituted/replaced/closed FD,
wrong access mode, descriptor alias/extra inheritance, wrong role/source/case/
freeze, old recipient PID/nonce/dispatch, stale sealed slot, missing ancestor,
unauthenticated relay and unauthorized/second/deeper delegation. Use the actual
receiver and Popen/pass_fds path where origin is material, not a fake acceptor.

### C. Channel and actual resource accounting

Inject creation/open/unlink/dup/transfer/Popen-before and Popen-after-effect,
readiness short/extra/EOF, selector registration/read/write, seal fsync/readback/
close, GO short/write/close, live-channel EOF, cancellation, deadline, disk and
outer stop faults. Check bounded original counters, no refreshed timeout, exact
actual row/byte/hash/EOF/error/ownership facts and one-time descriptor closes.
For ambiguous acquisition retain UNKNOWN, never manufacture a reap. Any test
harness disposal needs its own genuine retained child handle and must not erase
the original collector's uncertainty. Check unrelated processes/descriptors are
untouched and leaf pip/Git/import processes inherit no capability endpoints.

### D. Historical/current evidence and inspection

Advance the real ledger from pending -> editable PASS -> wheel -> cleanup,
retaining the exact pending snapshot unchanged. Reject changed snapshot, stale
live reference, same-action rebinding, copied pending bytes as current authority,
changed current observation during save and a second authority reload. Verify
later genuine wheel/cleanup changes do not invalidate historical empty editable
outputs while current source/base startup drift still rejects.

Exercise every inspection -> load/check/guard/producer/cleanup/session/collector
upgrade attempt; zero native acquisition. Terminal all-PASS read-only inspection
is valid evidence viewing but cannot issue a new role. Preserve all69 actual
deep schema assertions with shared real validators, plus native-entry mutation
rejections; do not substitute early capability failure for those assertions.

### E. Genuine positive lifecycle and original budget fit

Demonstrate source-only minimal -> real seed -> parent finalized SEEDED -> exact
initial collect/freeze -> actual prepare -> real same-base editable -> complete
independent twelve-file/four-directory validation -> parent finalized EDITABLE
-> actual next probe -> real compound wheel/venv/install/installed imports/check
-> actual worker observation and guarded cleanup. Keep real PIDs/commands/logs,
predecessors and exact empty editable/full later wheel source outputs.

Run all original collection/authority/observation, worker, six-gate preparation,
actual-source applicability, four-gate cleanup positive/negative prefixes,
mapped/VPG/integration and schema positives through the same session/receiver
mechanism. Add the separately named observer route without changing originals.
Capture original-sized counts, cumulative bytes/time, parent/child cutoffs,
no leaked descriptors/workers and no added producer/retry. If a required
positive cannot fit, the amendment remains unaccepted; do not waive it.

## 11. Review/implementation/verification sequence and outstanding uncertainty

1. Independently review this frozen R3 plan, original R2 finding, actual callers
   and finite transport/ledger/type/scope design. Resolve all requested changes
   before implementation. This document grants no authority itself.
2. Implement only approved ignored helpers/drivers, retain old packages/evidence,
   reconcile every exact caller/schema/route/FD ownership path, freeze the actual
   complete diff and obtain a distinct independent implementation review.
3. Only then obtain separately authorized finite native verification under all
   original prerequisites and limits. Run complete original project/final gates
   afterward as required; targeted passes are not delivery.
4. Reconcile evidence/coverage, perform the still-required fresh full-repository
   audit and remediate any confirmed blockers through the user-required workflow.
   The detailed complete feature report is conditional on final audit acceptance.

Generic nonfixture editable behavior is still a separate unresolved gate, not a
new confirmed defect and not waived. Real generic `pip install -e .[test]` uses
build isolation and parent reported setuptools80.9.0, unlike fixture79.0.1.
Its emitter/caller/source-output contract needs exact separate reconciliation;
this plan neither blesses a generic empty egg-info path nor changes that gate.

This authoring task ran **zero helper imports, installers, native experiments,
behavioral tests, Git or Store operations**. Static source analysis and exclusive
snapshot/hash authoring do not prove installed modes/layouts, FD behavior on
macOS, real cancellation/disposition, budget fit or production readiness.
No build/background worker was started and no build output was created/deleted.
Only new ignored plan/review snapshot records are written; these are required
deliverables. QA-006 remains undelivered; project verdict remains **NOT READY**.
