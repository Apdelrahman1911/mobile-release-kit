# Create-only Push: existing installed observer

This source-only increment implements accepted plan `445f47a3` in the existing
nonshipping Push observer. It depends on Service's create-only production slice
`da5edb12`, integrated in `51740965`. The fifteen-parent hook also applies to
Root `7be42f3f` (only unrelated Apple UI followed that integration).

**No Mac, stock-Git, provider or native qualification has been run for these
five cases.** The shipping create-only nomination remains `None`. Synthetic
peer bytes cannot prove GitHub's server CAS, TLS or a live account's authority.

## Fixed cases and actual owner boundaries

| Case | Required result from the existing original path |
| --- | --- |
| `git-push-create-empty` | Genuine joined five-GET Prepare, exactly two reachable commits, then one Apply with the real fixed hook, durable candidate ACK, ZERO-to-NEW command and original body sender. Synthetic `ok` plus matching after-advertisement; actual joined `PushReturned` and final CAS. |
| `git-push-create-equal` | Selected target already equals NEW: original three-GET Prepare refuses `target-changed`, no review or Apply. Report explicitly sets `applyRequested:false` and `applyOriginalJoined:false`; original Prepare, Disconnect and Quit still must join. |
| `git-push-create-stale` | Prepare sees a nonempty advertisement without the target. Fresh Apply sees OTHER at that target and refuses before hook/ACK/body/POST. The genuine joined core can retain private transaction recovery paths; this is not reported as a clean Apply or remote success. |
| `git-push-create-race` | Target remains unadvertised through fresh Apply. After the actual hook/ACK, the synthetic peer represents a competing OTHER and returns `ng ... already exists`. Actual command still requires ZERO; one consumed body, no after-GET/resend, joined send-consumed recovery. |
| `git-push-create-held` | Nonempty advertisement omits the target. One actual body send, complete outer HTTP with truncated receive-status; original refused frame and ordinary-pipe closes precede a borrowed-FD8 hold. Independent pending-producer observation then SAME-ticket STOP; no result is inferred from frame, marker, Git exit or process disappearance. |

All cases reuse `Control/Registration`, the genuine `connect_token` completion,
GitRead Observe, GitLocal Prepare/Apply, SourceBook, existing state row and
candidate ACK, original `PushInputChannel`, stock-Git helper, clock, runtime and
management joins. The supplier changes only fixed response bytes and bounded
comparison predicates. It calls the real `_PushBody.send` into the existing
count/hash sink; it does not assign a sent flag or retain another body copy.

Every request is explicitly `PushNewBranch`, `remote:null`, current attached
`refs/heads/main`, expected-old ZERO and actual local NEW. Both raw upstream
configuration keys must be absent. ZERO does not prove absence: only the
existing typed parser admits the exact empty sentinel or nonempty missing
target advertisement. Equal/occupied, inaccessible and malformed remain
distinct refusals. The same live Control's case kind must match at Runtime,
Gate, Request and source admission; ordinary Push cannot nominate the new kind
and a new-kind Control cannot nominate ordinary Push.

Fresh setup uses the same protected CLT and bounded original runner, but does
not configure a remote/upstream or create a tracking reference/log. Independent
before/after reads compare actual config, HEAD/current ref, index, both logs,
all worktree files including untracked content, and the complete bounded object
roster. Exact `refs`/`logs/refs` parent rosters preserve tracking absence; no
missing-file DATA stands in for an original file. Actual Git may format its
fresh config during setup; its captured bytes are preserved, not compared to
an invented serialization. Production parses and refuses upstream keys.

## Integration and unchanged limits

New leaves: `_git_push_create_observation.py`,
`macos_git_push_create_qualification.py`, and
`installed_shell_observation_macos_git_push_create.rs`. The last is a child of
the existing nonshipping Push observer, not a new crate/public module.

Apply `git-push-create-observation-hooks-20261021.patch` after copying the new
leaves. It contains fourteen source hooks and one dormant workflow hunk:

- Existing Python transcript/Supplier/Entry dispatch; old three cases remain
  exactly their own family and selection type.
- Existing fixture/setup, Aqua route and current-runtime driver; strict new
  `--scope git-push-create-native` only within the complete `git-native` image.
- Existing native Push case/step/report, fixture and same-control admission.
  Root's `37bdc526` public strict-JSON/local exact-key correction is preserved.
- Existing Supervisor inspect installs the same original observer Control and
  source facet for the two closed Push kinds, then requires the unchanged
  exact Gate/Control match and one-use set. This fixes the review-found missing
  new-kind dispatch; runtime availability alone never supplied that custody.
- Existing `git_native` workflow step: Fetch returns, ordinary Push returns,
  then the create-only scope is the final `exec`. No next invocation after a
  nonzero/unknown/78 return, no new image, job, signing route or dispatch.

All four bootstraps remain held and checked against the same installed
manifest, including the unused Fetch pair. No roster, public command, grant,
wire schema, native journal or owner is added. The selected new case family
has its own fixed private namespace, preserving the old three-case namespace.

The unchanged per-invocation suite is 600 seconds, each case including setup
120 seconds, Prepare/Apply 45/55 seconds with the original earliest failure.
Setup retains 160 calls/5 seconds per call. Push remains 200 MiB admission,
one 32 MiB body and existing 80 MiB disk allowance; the added case comparisons
fit the existing observer 1 MiB quote, with actual native struct capacity still
charged. No budget credit comes from a presumed discarded original. The same
workflow's 25-minute outer limit now covers twelve cases and their admission
overhead: it is deliberately tighter than every possible worst-case sum, not
a throughput promise or a renewed clock. Native timeout/unknown retains the
existing originals and does not trigger another attempt.

## Verification performed and still required

Actual focused **43/43 inert Python tests passed in 1.984 seconds**, zero skips:
new helper/provider 10, new setup/driver 7, original helper 11, original setup 6,
original route 4 and unchanged current-route 5. They used a fresh UID/GID 65534
public-source projection, empty private HOME/TMP, no inherited capabilities,
isolated/no-site Python, 30-second outer bound and global Popen/socket/DNS
refusals. Tests exercise actual parser/helper/body/control code with inert
syscalls/ACK/provider returns; only tiny task-owned directory reads use actual
FDs. They do **not** constitute C/A/W, CLT, live HTTP or native finality proof.

Initial evidence is retained: a projection omitted the API subpackage and
stopped before tests; two subsequent runs found test-only API/bytes fixture
mistakes before the first case completed. No production guard was loosened.
Final original caller returned zero, its source manifest was rematched, empty
HOME/TMP verified and the successful disposable projection removed.

Ten Python files and nine Rust sources were syntax-parsed only. Five new Mac
DATA tests are authored but **unrun**. Root must compile the combined observer,
review the actual installed fixture and then coordinate the five actual Mac
cases. Ordinary/native qualification flags remain false until their separate
genuine evidence exists; even a future synthetic-peer pass will not prove
real server CAS, TLS or account qualification.
