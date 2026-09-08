# QA-006 — inheritance terminal/selector correction plan R3-R4-R2

**PROPOSED ONLY. Independent plan approval is required before implementation.**
This is a narrow amendment to the inherited R3-R2/R3-R3 experiment, not a product
change, complete-suite permission, cache disposition, or native execution grant.

## Revision basis — SIPR3R4-01

Preserve the rejected R3-R4 proposal byte-for-byte (SHA256
`a472cac5e1be74e4df09114a49fee523e655b59907b8b7422524b624fda576fe`).
The distinct plan review `sandbox-inheritance-correction-plan-review-r3-r4/`
returned REQUEST_CHANGES: report SHA256
`7898991743f3f51e7781e025ddb6981cbebae2429427106e9e9fe5da5bbe7125`,
decision SHA256
`15647b37e046b27a7064416a7e4ac30a077940704e80ca4dd59fc18e6b2b278c`.
SIPR3R4-01 identified mandatory literal Ruby/Bash path rebinding and exact-pair
verification missing from the earlier proposal. Root independently reread
`ruby_relay.rb:10,122–137`, `bash_relay.sh:24`, `test_pure_ruby.rb:112,161–177`
and `test_pure.py:1272–1291`; their old literals/relative loaded pair reproduce
the integration conflict statically. No route or test was launched.

This revision explicitly authorizes only those two runtime literal changes,
an independent complete entry-path regression, distinct safety review of the
exact new Ruby driver/loaded-relay pair, and the remaining Ruby002 invocation
under existing bounds. It also makes the review's O_NONBLOCK/per-owned-fd
PIPE_BUF/raw512-byte and CPython API-admission semantics explicit. There is no
quota reset, wider native authority, product change, or waiver of the two
original helper findings. New independent approval of this revision is required
before implementation; the old proposal/rejection remains historical evidence.

## Reanalysis and reviewed baseline

The distinct R3-R3 actual-code review is **REQUEST_CHANGES**, with two confirmed
Medium helper-only execution blockers:

- SIIR3R3-01: `sender.py:67–75,266–291` emits a success-shaped final through
  cancellation-blind disposition writes, then checks cancellation and can exit1.
  Root cannot wait this orphan. A full success frame, real EOF and actual absence
  therefore still pass `controller.py:407–415,483–494` and `reconcile.py:303–313,
  375–416`. The old test checks only a local exit argument, not those consumers.
- SIIR3R3-02: `controller.py:62–83,620–639,681–684` uses unbound snapshot/baseline
  selectors before reference-content verification. Empty inventories bypass the
  intended scope, and a changed index selector can direct an unapproved read.

Root has reread the original findings, full reviewer report, inherited plan,
sender publication/setup/disposition, runtime cancellation/writing/emitter,
contract/route reconciliation, controller preparation/preproof/query/finalization,
and relevant pure fixtures/tests. Counterexamples are source-derived, not native
reproductions. No helper or Store operation was executed for this reanalysis.

Exact existing evidence (relative to this QA-006 directory):

| Input | SHA-256 |
| --- | --- |
| `SANDBOX-INHERITANCE-PLAN-R3-R3.md` | `fd403e32cbfbfb83f8d88641d9c315c65e620b71b737e2314067c9cd533a35be` |
| `sandbox-inheritance-plan-review-r3-r3/DECISION.json` | `ec9abd81653d211525842461110e4f2390f4da84f9be967e5c2206c216995b64` |
| `sandbox-inheritance-code-review-r3-r3/IMPLEMENTATION-REVIEW.md` | `57080a2ee13237cd72792728cd6749399cccbab13ec8670f976708a6fa5e9214` |
| Rejected review `DECISION.json` | `ff360c282e2a058488d36e908150dcd8d8721f6d06e1f520f744ca84560a88c3` |
| `sandbox-inheritance-r3-r3/CODE-BINDINGS.json` | `4c9910dcf0f95d168f35567210e96c78902eedf002a5b867c1514529fe2badb5` |
| Existing `REFERENCE-BINDINGS.json` | `3674156ff1190a88d12e41cc102fce730ab5654d945c6c9a3bb4ebc9ec33cfd0` |
| `implementation-r6/SNAPSHOT.json` (25,573 bytes;152 source rows) | `abb6503fe36d442b229ed294a423e6fdabd507a49d4c2628d399c2544fa2226a` |
| `implementation-review-r6/BASELINE.json` (32,910 bytes;174 root/user rows;two indexes) | `9afd73ab899717857ecb8ccbac3be16d00fab3ef15836c965a686a473b69d691` |

The product remains toolkit0.3.0, retained HEAD `2beb37336fa8002b69f598fe431082606368310d`.
This plan is not a new Git/remote/tree observation. QA-006/QA-007 remain open.

## Exact implementation scope

Preserve every existing R3-R3 source, rejected package, result, approval and
review unchanged. After approval, create new ignored `sandbox-inheritance-r3-r4/`
with the same nine runtime files, both pure-test files, README and references.
Behavioral changes are confined to `contract.py`, `runtime.py`, `sender.py`,
`reconcile.py`, `controller.py` and `test_pure.py`. Two additional **mandatory
binding-only** runtime edits are part of this reviewed scope:

- `ruby_relay.rb:10`: set BASE to the exact new
  `/ORIGINAL_REPOSITORY/.mobile-release/remediation/QA-006/sandbox-inheritance-r3-r4`
  literal. Its scratch checks, script reads and sender argv must consequently
  name that new package, not the rejected R3-R3 package.
- `bash_relay.sh:24`: retain the exact existing Ruby3.3.12 interpreter/flags and
  context argument, but point the final exec to the new package's
  `sandbox-inheritance-r3-r4/ruby_relay.rb` at the above absolute root.

Both runtime files remain otherwise byte-identical to the frozen old files.
`canary.py`, `python_relay.py` and the full `test_pure_ruby.rb` driver remain
byte-identical; the driver's changed loaded relay means the old pair's test
result cannot transfer. No additional routes or tools are added. The Python
regression independently asserts complete expected literal entry paths against
an explicit new-root constant from this plan, not a value derived from the
actual Ruby BASE or the same argv under test. Cover all eleven constructed
routes; wrong old Ruby BASE or old Bash exec must fail independently, including
in-memory single-literal mutants. Check all seven Ruby-backed contexts/argv and
both multihop routes. Do not execute Ruby/Bash merely to inspect their bindings.

Use a fresh plan/script/reference identity and a new exact approval gate; no old
decision authorizes the new helper. Rebind runtime files, selector references,
test/source snapshots, corrected plan/review lineage and fresh approval identity
together. Do not create `execution-r1` or live approval files while authoring,
testing or reviewing. No stale acceptance may be copied into the new package.

No product, workflow, schema, credential contract, AGENTS, actual source/index/ref,
historical payload/cache, archive helper or verifier implementation changes.

## SIIR3R3-01: a root-verifiable irreversible terminal commitment

### State machine and cancellation contract

Replace the loss-row single-final protocol with:

`owned work/cleanup -> provisional final bytes -> atomic terminal commit -> immediate own exit`.

The provisional final is not success, even if its payload describes complete
work. Only the explicit final commit makes that payload eligible for root's
subsequent EOF/absence validation. This changes the ignored protocol, not a
consumer/public release contract.

Cancellation is honored throughout final serialization, descriptor checks,
provisional transmission, backpressure/select and each commit-write admission.
All such work uses the original disposition/outer cutoff, never a renewed one.
The last pre-dispatch cancellation/time checkpoint is the **admission boundary
for one whole nonblocking `os.write` API invocation**. This is not a claim of
one kernel syscall: CPython may internally retry EINTR after a returning
flag-only signal handler. Such internal retry is part of the already admitted
API invocation; the helper cannot claim an intervening cancellation check.
There is no explicit user-code EINTR retry. An exception returned to the helper
is an uncertain/failed invocation and cannot authorize another commit. If the
admitted API invocation writes the complete commit, publication is irreversible: no later flag snapshot, callback,
handler restoration, return, serialization or other fallible work may turn it
into an unobservable failure. The only next operation is fixed own `_exit(0)`.
Cancellation arriving after successful commit admission/completion does not
retroactively revoke committed work. This is an explicit cooperative
linearization, not a claim to detect every signal atomically with a kernel call.

If an attempt returns EAGAIN/EWOULDBLOCK without writing bytes, no commitment
occurred: return to original-budget select and recheck cancellation immediately
before a new attempt. An observed cancellation then prevents the next attempt.
Do not retry a short/zero write, unexpected return, error or uncertain outcome.
Only the documented all-or-none nonblocking pipe operation supports this boundary.

Root still checks its own cancellation and original deadlines, observes real R
EOF, then obtains exact bounded sender absence using the already authorized
QueryChild path. An orphan exit status remains **unobservable**, never inferred
as exit0. A hard exit after a complete commit does not falsify previously committed
work; missing commit, EOF or absence is failure/unknown, not successful cleanup.

### Producer changes

1. Complete all currently required child/control/ordinary-fd cleanup first. An
   existing primary, secondary, cancellation or unknown state cannot emit a
   success commit. Best-effort failure evidence remains uncommitted and cannot
   admit a QueryChild. Failure needs no second success-shaped frame.
2. Encode a single canonical provisional `final` frame, with a new exact terminal
   mode identifying this protocol. It retains the complete original child waits,
   signals, parent change, descriptor/ownership and error fields. Its full encoded
   bytes (including newline) are frozen and bounded by the unchanged frame cap.
3. Before writing, validate the existing R descriptor identity/direction and set
   nonblocking mode, then require actual `fcntl(F_GETFL)` flags to include
   O_NONBLOCK; FIFO/direction identity alone is insufficient. Recheck that owned
   descriptor's identity/direction/nonblocking state at each commit admission.
   Query only this owned pipe's `os.fpathconf(fd, "PC_PIPE_BUF")`;
   require an integer at least512. Unknown/unsupported values fail closed. This
   is a new explicit owned-fd metadata call, not another process/observer/FFI.
   The pure-test pre-load native veto must also deny `fpathconf` by default.
4. Transmit provisional bytes using the real bounded write loop with
   `guard.completion` checkpoints (not cancellation-blind `guard.disposition`).
   Check after every potentially blocking/select operation and at completion.
5. Pre-encode a canonical `terminal-commit` envelope with the exact next sender
   sequence and `{finalSha256, finalSequence, finalBytes}`. Its envelope already
   binds row, nonce, PID and all original deadlines. The digest covers the actual
   complete provisional encoding. Bound the whole commit including newline to512
   bytes, independently of the larger ordinary frame cap. Oversize is failure,
   never a split commit or enlarged cap.
6. Implement a dedicated atomic commit primitive: prepare all values/lengths,
   validate current owned fd/nonblocking identity, wait for write readiness with
   original checkpoints, check cancellation/time immediately before one
   nonblocking `os.write(fd, whole_commit)`. Do not call generic `write_bytes`
   (which splits and checks after publication). Only a full exact integer-length
   return selects immediate fixed exit0. Failure selects fixed exit1 without
   another commit, new resource, guessed signal or post-success completion call.
   A short write is retained as failed/truncated protocol, not completed by retry.

No public claim of exactly-once delivery or arbitrary-process containment follows.
Checksums bind transmitted bytes to each other; authority remains exact reviewed
code and independently observed owned channels, not the checksum alone.

### Consumers and schemas

- Add the exact sender-only `terminal-commit` kind for loss rows. Reject it on
  ordinary routes and reject old terminal modes in the new loss protocol.
- `route_terminal` must find exactly one provisional final and exactly one
  immediately following sender commit on the independent channel. Require same
  PID/row/nonce/endpoints, next sequence, exact keys/types, correct final length
  and SHA-256, and canonical raw encodings. At consumption independently enforce
  the complete raw commit length, including newline, at most512 bytes; the
  larger FRAME_CAP is not a substitute. Require commit to be the last sender
  event. No duplicate, trailing, replayed, substituted or unexpected event is
  ignored; `Events.complete` and raw/event agreement still apply.
- Correlate the final digest with actual retained raw R bytes, not merely a
  re-serialized attacker-supplied record. Require real R EOF and unchanged full
  route/child/wait/signal/parent proof before `terminal_preproof` can produce
  `awaiting-absence`. Missing commit cannot admit the first observer.
- `query_orphan` and final `reconcile` share this same complete contract. Final
  transport means **committed final + real EOF + validated absence**, not merely
  an existing final dictionary. Keep root cancellation/time/finalization checks.
- Ordinary waitable senders/relays retain their existing real-parent-status
  contract and final checks; do not weaken them to match the orphan protocol.

## SIIR3R3-02: authenticate selectors before every selected-read phase

1. Add both exact snapshot/baseline controls above to `REFERENCE-BINDINGS.json`,
   together with the new plan/review lineage. Preserve inherited named reference
   coverage. Root's eventual independent approval binds the exact reference bytes.
2. In preparation, verify script hashes/plan/matrix and approved reference digest
   first. Strictly parse reference rows, require the two named controls and their
   pinned lengths/digests, then verify **all reference contents**. No selected
   source or index read and no Evidence/child acquisition precedes this barrier.
3. Parse selector controls from the already verified byte buffers, not a new
   unverified path read. Require exact applicable top-level shapes and original
   baseline source/head/tree bindings. Enforce152 nonempty QA-006 rows,174 nonempty
   root/user rows, exact `sha256`/boolean `executable` row shapes, safe canonical
   relative POSIX names, and no duplicates/absolute/parent traversal paths. The
   byte pins freeze the complete actual filename set, not just its count.
4. Require exactly two index keys (`source`,`root`) with exact path/digest rows:
   `ROOT/.git/worktrees/source/index` SHA
   `8ea9408d8d09c7b129cada155704262b00167e7f333e3d1b82638917b1f4d23b`,
   and `ROOT/.git/index` SHA
   `0ddba9fac6daeb32b7f66749135fcc7c4fb049459a7d46b71663ea963e5d6af7`.
   Caller-supplied paths cannot choose other index/secret/control reads. Verify
   the original user AGENTS binding is consistent across snapshot
   `userAgentsSha256`, baseline `rootAgentalSha256` and baseline root inventory
   `AGENTS.md`. Preserve these actual existing field names; the152-row source
   inventory does not contain another AGENTS row.
5. Construct an immutable authority containing the verified control identities/
   digests and frozen source/root/index row tuples. `preservation(authority)`
   consumes only this authority, not mutable dicts or freshly parsed selectors.
   Keep current no-follow/stable-read/mode guards on actual named input leaves.
6. Before final selected reads, reverify both control files against the original
   authority. Drift rejects before any new selected read. Then use the same
   immutable original rows for the final preservation pass. A replacement after
   verification cannot direct a new read or replace the baseline; verified byte
   buffers remain the authority. This is bounded named preservation, not a full
   universe/Git status/cache-liveness claim or hostile same-user defense.
7. Record selector bindings/counts in provisional baseline/results as evidence of
   the actual enforced scope. Keep the original cutoff across validation and
   final preservation. Failure never creates/reuses a different selector set.

## Tests — complete end-to-end dangerous paths, no native execution

Retain all66 current Python method obligations, including original24 and prior
corrections; adapt only genuinely changed loss-frame/authority schemas. Retain
the old false-assurance test in frozen rejected sources and replace its current
oracle with actual cross-owner consumption. Preserve the complete40-case Ruby
obligations and byte-identical Ruby driver, but **run the new driver/loaded-relay
pair under remaining Ruby002 after its distinct exact-pair static safety gate**.
The prior40-case pass is historical only. The Python suite must include the
independent complete entry-path/literal-mutant regressions specified above.

### Terminal regressions

For **both parent-exit and parent-kill**, use the real Emitter/encoder/write/
publish implementation with fictional syscall-level IO, flags, clock and own-exit
sentinel. Feed resulting raw frames (not constructed replacements), true/false
fictional actual Reader EOF and a complete valid route fixture through real
`Row.terminal_preproof`, `Row.query_orphan`, actual fake-backed QueryChild
acquisition/wait/streams/disposition and final `reconcile`. Cover:

- full valid committed path; ordinary sender contract still passes;
- cancellation before the first provisional write; during select/backpressure;
  between provisional chunks; after final byte but before commit admission;
  during EAGAIN/backpressure before the next commit admission;
- cancellation at/after a successfully admitted full atomic commit follows the
  explicit irrevocable semantics: fixed exit0, no subsequent completion/check,
  and root acceptance only if its own independent gates pass;
- root-only cancellation/deadline, sender deadline before commit, and advancement
  beyond the original root cutoff during commit prevent overall row success;
- failures setting nonblocking/reading PIPE_BUF/custody, PIPE_BUF below512 or
  invalid type, oversize commit, zero/short/error/partial provisional or commit
  writes, unsupported return and truncation; no failed commit is retried;
  missing actual O_NONBLOCK, per-fd mismatched PIPE_BUF and a canonical raw
  commit above512 are independently rejected. Test returned EINTR as failure
  without a user-code retry; distinguish OS-contract-valid atomic full writes
  from fakes inventing a partial/error return after an incompatible full commit.
  Internal CPython/kernel retry behavior is not claimed as a pure-test result;
- missing, duplicate, reversed, old-mode, wrong-final-digest/bytes/sequence,
  wrong-row/nonce/PID/deadline/channel, noncanonical encoding, trailing frame,
  retained-writer/no-EOF, failed Reader, and missing/incorrect absence evidence;
- primary/secondary cleanup failure cannot produce an eligible commitment;
- an in-memory old-publication mutant reproduces root false acceptance under the
  old consumer contract and is rejected under the corrected complete consumer;
  never change active files or execute a native mutant.

Each negative asserts no QueryChild admission where preproof should fail, no
success/cleanup eligibility, unchanged attempt/signal budgets, and retained
unknown state. Exit-argument assertions alone are insufficient.

### Selector regressions

Exercise actual preparation/selector-validation/preservation/final-consumer
methods using fictional fixed named file leaves and observed-read logs. Never
mock `preservation()` wholesale. Hold script/approval/reference bindings fixed
while independently removing/substituting/tampering each control; use empty or
wrong-count inventories, malformed types, duplicate keys, missing/extra indexes,
unsafe names, changed index path/digest, inconsistent AGENTS, and wrong source/
tree. Reject **before** any affected selected read, Evidence construction or
child acquisition. Also test schema guards with exact fictional bound controls,
so early digest rejection is not the only exercised assertion.

Cover valid exact controls, control change after initial check, immutable-original
consumer behavior, final-baseline replacement before final selected-read phase,
and original source/index drift. Real no-follow read leaves may be fake-backed;
approval, parsers, frozen authority and preservation comparisons must be real.
No actual source cache or private input is needed for these tests.

## Finite verification, failure/recovery and independent acceptance

This does not reset preparation quotas: existing R3-R3 Python2/4 and Ruby1/2 are
already consumed. Permit only literal new correction Python attempt003, then
conditional004 after complete actual003 evidence if a reviewed correction is
necessary; no implicit retry or fifth invocation. Each retains the original60s
cooperative cutoff and2MiB captured-output cap with native/process/signal/network/
FFI guards active before helper definitions. Preserve raw output, exact source
snapshot and genuine separate outer tool receipt, including any failures.
Before any Ruby invocation, a distinct agent must statically safety-review the
exact new `test_pure_ruby.rb` plus loaded `ruby_relay.rb` pair and its transitive
load/native/process/signal-denial boundaries. An old driver-only or old-relay
review is not sufficient. The reviewer binds both current file digests and
checks complete unchanged40-case obligations and the exactly one BASE literal
change; independent Python/static entry-path proof covers the Bash literal.
After that gate, root may separately inspect/admit only the remaining literal
Ruby002 attempt using the same fixed Ruby3.3.12 interpreter and `--disable-gems`,
original30s cooperative cutoff and2MiB captured-output ceiling. The exact new
pair, plan/safety decision, original Ruby001 source/captures/genuine outer, raw002
stdout/stderr and actual separate outer completion must be retained. Keep the
original Ruby1/2 consumption;002 consumes the second and final invocation even
if it fails. No third run, retry, reset or historical-pass substitution follows.
Pure authoring/review creates no live native execution/approval state.

No runtime experiment or additional pure invocation is authorized by authoring
the plan. Root inspects exact current source/launcher, original attempt accounting
and occupancy before any Python003/conditional004 or Ruby002 dispatch. Unknown,
torn, occupied or incompatible predecessor evidence prevents dispatch, not reuse
or a first-free attempt search. Failure preserves all evidence and outstanding
obligations; a new correction cannot silently enlarge the original quotas.

Full corrected-code/test/reference/doc review by another independent agent is
mandatory after implementation/proofs, with whole diff and sibling routes—not
merely the two patch sites. Code-only acceptance is not a live native execution
grant. All prior limits remain:11 rows,44 route acquisitions/57 execs; at most6
observers gives50/63, hard64/96;30s work+10s disposition,180s outer,64KiB streams,
4KiB ordinary chunks,2MiB captures,8MiB native evidence. A small commit shares
these caps. No new subprocess/observer/signal route, timeout, guessed cleanup,
repeat experiment or host query is added. The one primary experiment remains
consumed and cannot authorize a full-suite run.

Retain incomplete/provisional/failed evidence and stop later rows on failure or
unknown state. Do not recreate, adopt, overwrite, rollback, infer orphan wait,
or issue more queries/signals to turn ambiguity into success. Only already-owned
resources may be disposed under the existing scope. No root cache hold is released.

## Risks, documentation and remaining product work

Review particularly the commit linearization/race, true atomic whole-pipe write,
Python EINTR/error behavior, canonical raw/event binding, all late consumers,
hidden post-commit calls, immutable authority construction, final reread order,
fictional tests accidentally bypassing validators, complete cross-language
entry identity, the changed Ruby loaded pair and protocol budget drift.
POSIX PIPE_BUF atomicity is an external runtime contract; the new owned-fd size
guard and later native gate remain explicit. A named lookup of this host's
`/usr/share/man/man2/write.2` found no file; no local manual verification is claimed.

Update only ignored helper README, implementation/coverage/results/review/progress
records to explain commit eligibility versus unobservable orphan exit, selector
authority, mandatory Ruby/Bash new-root bindings, exact-pair safety/actual002
results versus historical40 cases, actual tests, preserved failed attempts and
outstanding gates. Consumer
docs and product APIs remain unchanged. Stop/join only owned workers; pure tests
start none. Required evidence is not disposable build output.

QA-006 acceptance/full source-native-wheel-hosted gates and protected delivery,
QA-007, QA-003, QA-004, QA-005, MRK-008, MRK-009, a **new first-pass-style full
repository audit**, further confirmed blocker remediation, justified READY and
the separate complete technical feature report all remain mandatory.
