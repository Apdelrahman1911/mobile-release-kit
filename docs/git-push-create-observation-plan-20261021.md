# Create-only Push: existing native observer extension (PLAN)

Base: `6e93436154562a55d738166016b801866f2ac3ae`, isolated
`git-push-create-observation`. No implementation or execution yet. Service owns
the production `PushNewBranch` slice; this packet owns observation only and
depends on that slice's reviewed composition. Root owns shared-file integration.

## 1. Exact product contract and original owner

Use Service's `git_push_new_branch.py`, `git_repository_push_new_branch.py`,
`git_push_new_branch_protocol.rs` and its private `hooks/after` projections.
The existing outer `Action::Push` carries explicit `Kind::PushNewBranch`:
`remote:null`, `localRef == remoteRef == refs/heads/main`, `oldOid == ZERO40`,
and actual born local `newOid`. The genuine original config must have BOTH
`branch.main.remote` and `branch.main.merge` absent. The review has
`trackingRef:null`, basis `first-publication-no-upstream`, and ALL reachable
commits (the fixture has two; production remains bounded to 64).

ZERO does not prove absence. The original helper must parse the exact fresh
advertisement: a sole first `ZERO capabilities^{}` row represents the empty
advertisement; a nonempty advertisement may omit the selected target. Every
occupied target, including the intended new OID, refuses. Neither inaccessible
HTTP, malformed/empty bytes, nor a repository 404 becomes an absent branch.

Reuse the actual existing Push `Control/Registration`, `Record/Step`,
`connect_token -> Connection/Supervisor -> accept_final`, GitRead Observe,
GitLocal Prepare/Apply, SourceBook, native state row/candidate ACK, FD8
`PushInputChannel`, fixed stock-Git/pre-push helper, and all original returns.
Only fixed provider response BYTES are synthetic. No new transport, issuer,
callback owner, journal, Connection assignment, receipt, or public command.

## 2. Five finite cases, one new closed case scope

The fifth case distinguishes a server-side race AFTER advertisement from a
target already occupied at fresh Apply. These are different refusal paths;
combining their labels would overclaim coverage.

| Case | Prepare | Fresh Apply / required actual observations |
| --- | --- | --- |
| `git-push-create-empty` | Sole valid empty sentinel; genuine five-GET dry-run; exact two-commit review | Actual fixed hook and native ACK; stock Git emits `ZERO NEW refs/heads/main`; original body send into the existing bounded sink; one synthetic `ok` and matching later advertisement; genuine joined `PushReturned` and final state CAS |
| `git-push-create-equal` | Advertisement already contains selected `NEW`; genuine three-GET refusal | No review, no Apply call, no hook/body/POST; original Prepare must actually retire before Disconnect/Quit |
| `git-push-create-stale` | Target absent in a nonempty advertisement | Fresh Apply advertises selected `OTHER`; three GETs then refusal before hook/body/POST, no candidate ACK or send, unchanged local repository |
| `git-push-create-race` | Valid empty sentinel | Fresh Apply still sees absent target; after actual hook/ACK the synthetic peer represents a competing `OTHER`. Verify original command still carries expected ZERO, consume the actual body once, return exact `ng ... already exists`; no after-GET or retry. Joined non-success, send-consumed recovery; synthetic peer never becomes `NEW` |
| `git-push-create-held` | Nonempty advertisement omits target | Original body consumed once; complete outer HTTP but truncated receive-status. Same existing refused-helper path holds borrowed FD8 after real returned frame and ordinary pipe closes. Independent original producer/wait/receipt pending observation precedes same-ticket STOP. No after-GET or resend; final remote outcome stays unconfirmed |

The race response is a credential-free synthetic-server case: it proves the
client's expected-ZERO command and refusal/no-resend handling, NOT real GitHub
server CAS, TLS, account authority, or a remote repository mutation.

Old Push three-case scope and Fetch four-case scope remain unchanged. New
fixed `--scope git-push-create-native` is accepted ONLY within the existing
explicit `git-native` installed image; no new bootstrap or packaging roster.
It uses the same four held originals, including unused Fetch entries, through
all POST checks. Ordinary and old singleton-image selectors do not gain this
case scope. Root may call it from the already-installed combined image; this
plan does not add CI dispatch or increase workflow timeouts.

## 3. Fixture, source, and namespace custody

Reuse `macos_git_push_qualification` and the same `Fixtures/run_cases/run_owned`
setup. New fixed case-family helpers change only the exact case tuple, fixture
namespace, config, transcript, expected originals and report predicates.
Fresh private native-home/Application-Support project/config/HOME/TMP only;
same empty template and fixed protected CLT Git. Two tiny actual commits and
one real comparison commit; no remote command during setup. Unlike ordinary
Push setup, do not create a remote config, upstream keys, tracking ref or log.

Retain the same canonical <=4096-byte transcript with actual base/target/other
OIDs. Shared supplier dispatch accepts new Selection ONLY for the matching
fixed new case/token/coordinate/current Binding; old cases remain ordinary
Selection-only. No caller-selected exchange, fixture bytes, or mode upgrade.
The same original `_Fixture` performs bounded reads through its four-lease/
64-call acquisition. The same `_Sink` calls actual `_PushBody.send` and checks
body count/hash plus the bounded command prefix, never assigns `body.sent`.

Native and outer readback require identical original HEAD/current ref/index,
config, HEAD/current reflogs, all six worktree files (including untracked),
and complete bounded object roster. Also check exact retained parent rosters
for continued absence of `refs/remotes` and `logs/refs/remotes`; absence is not
a fabricated tracking FileFact. No upstream configuration is performed.

The existing observer eligibility hook changes from hardcoded ordinary Push
to equality with the SAME live Control's fixed case kind. Apply that equality
at Runtime profile selection, Document/Gate matching, observed Request and
source admission; old Push Control cannot qualify create and vice versa.
Service's separate production nomination remains None. No renderer/env flag
or case-shaped DATA independently admits source/tool/runtime or credentials.

## 4. Settlement, failure, budgets

Prepare-only refusal gets an explicit terminal route: matched original
Prepare receipt, no retained review, then ordinary Disconnect and Quit. Its
report must say Apply was not requested, never claim a joined Apply. Other
cases retain exactly one Prepare and one fresh explicit Apply on the same
selected Document and captured review; no automatic rerun or retry.

Reuse existing helper audits, first-F bridge, returned frame, sole stderr
marker reader and independent Supervisor pending sample. The held case uses
the SAME borrowed FD8 (no dup/second reader/close). A marker is not finality;
only actual child/C-A-W, all-copy EOF, source/runtime/management/Store returns
and native closes can finish. Missing/unknown close or cutoff failure fails
the case and retains originals. Known closed remote-outcome uncertainty stays
non-success/recovery; no fake success from a ref, body count, or Git exit.

Unchanged: 45/55 operation endpoints and earliest F; 120 seconds INCLUDING
setup per case; 600 seconds for this fixed five-case suite, min-clamped without
reset; 160 setup calls/case and 5 seconds/call. The fifth case may receive a
tighter remaining budget, never an extension. Existing Push200 memory,
32MiB single-body/80MiB disk, Source/Runtime descriptor caps and observer1MiB
quote remain. Every added fixed record is counted; no simultaneous old/new
case-family allocation or credit from discarded originals. Actual overflow
or unsupported source layout refuses rather than raising a cap.

## 5. Owned leaves and Root-only hooks

New observation-only leaves (names can be shortened, responsibilities fixed):
* `_git_push_create_observation.py`: fixed new-case provider bytes, audits and
  held-case predicates called by the existing supplier/Entry.
* `installed_shell_observation_macos_git_push_create.rs`: closed new case
  action/review/outcome/report and absent-tracking comparisons, as a child of
  the existing Push observer, not another Control/Record/driver.
* `macos_git_push_create_qualification.py`: fixed new family data/expectations
  delegated to the existing setup/custody/cleanup helpers.
* Targeted Python unit/desktop test leaves and this guide/hook artifact.

Root-only additive hooks: existing three Push Python observation files;
Push native observer/fixture; its original Gate/Runtime/source kind checks;
outer installed observer's fixed namespace roster; existing Push setup,
Aqua fixed case dispatcher and current-runtime scope/expected-count checks.
No Service production leaf, UI, schema9, helper protocol, normal Push behavior,
combined runtime manifest roster, shipping nomination, or ordinary runner edit.
No new process/native owner. Freeze hooks against Root + Service's accepted
production composition, not a stale whole-file overwrite. Service already
owns the mechanical ordinary observer `Some(origin)`/tracking compatibility.

## 6. Focused verification and limits

Before native execution, inert tests with Popen/socket forbidden exercise the
actual same supplier/helper/parser: valid sentinel and missing target, equal
and different occupied targets, ZERO command+single ACK, race `ng`, truncated
status/no later GET, repeated send refusal, wrong kind/token/source binding,
and held marker without producer/EOF never settling. Retain originals on
fake close failure; do not fabricate native close in a passing source test.
Fixture tests cover absent tracking/config before+after, wrong added key/ref,
same deadlines, exact new scope in combined image only, and fail-fast/no
rerun of an entered case. Small Rust DATA tests cover kind isolation,
Prepare-only versus Apply report truth, and non-success/unknown predicates.

Different distinct actual reviewer must inspect the frozen implementation.
Root alone schedules compile/native execution through existing installed
observer. No live repository/network/account/remote writes, no native claim
from inert tests, and no shipping qualification or nomination from this plan.
