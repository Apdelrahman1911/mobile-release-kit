# Create-only first/new-branch Push

## Scope and original authority

`push-new-branch` explicitly publishes the current born, attached SHA-1 branch
to the **same branch name** in the selected GitHub repository. The original
bounded config must contain neither `branch.<name>.remote` nor `.merge`;
partial, empty, broken or ambiguous configuration is refused. The Desktop
selection is only a request: the same original Push capture rechecks this,
the actual current Connection/account/repository, root, saved edit, HEAD,
index and reference revision.

Review covers the complete reachable history (1–64 unique commits, ending at
HEAD), with the existing per-tree/object bounds and shallow/LFS/submodule,
hook/signing and unsupported-layout refusals. It uses the existing five GETs,
private view, fixed compare-only pre-push hook and dry-run flush/EOF: no
candidate, ACK or POST. An occupied target, including one already at NEW,
refuses before stock Git could skip the hook as up-to-date. An empty receive
advertisement permits only the sole first zero `capabilities^{}` pseudo-row;
zero is forbidden on an actual ref.

Explicit Apply recaptures the same local sources and remote advertisement.
The original durable candidate ACK precedes the one ordinary ZERO→NEW push.
The server expected-zero check protects against hidden or racing branches;
there is no force, `+` refspec, reset, merge, retry, `-u`, fetch, staging or
local upstream/config/tracking/index/worktree mutation. Kind is retained in
the private FD8 binding, hook, review digest, intent, terminal and journal;
zero never infers a kind or supplies absence authority.

This extends the existing GitLocal/Push owner, not an executor or transport.
The same 45/55-second/first-failure clock, 200 MiB checked admission, 32 MiB
body, 80 MiB private disk envelope, two body leases, exact all-copy EOF,
C/A/W/source/IO jobs, final CAS and NativeUse/Connection retirement remain.
Partial send/status, unknown cleanup or lost ACK retain the original intent
and fence; neither status nor restart authorizes another push. The existing
Activity recovery button may explicitly read a later tip only after the same
known-settled local invocation returns. Matching that tip is DATA, not proof
that this Push succeeded, nor a journal clear or retry grant.

## Integration

Owned source is eleven new code/test leaves plus this guide and
`git-push-new-branch-hooks-20261021.patch`. The patch has 39 existing targets:
10 Python/helper, 20 Rust, eight frontend/roster and one original inert worker
fixture. Exact source pins/target roster are in
`.task-push-new-branch/frozen.json`; complete originals and successors are in
`.task-push-new-branch/current-hooks/{before,after}`.

The final patch is composed against Root
`413cf8fd6166ff927976331f984764cc41bc7b99`, not applied in the author worktree.
Ordinary three-way composition required only the test-roster union and the
ordinary Push foreign-review regression's nullable tracking calculation.
It preserves Root's Initialize `{}` repair, that regression's validity
assertions, existing RemoteCLI support, P12 and all unrelated gates.

Native `Action.remote`, `Review.remote/tracking_ref` and `Intent.remote` are
required-nullable: ordinary Push still requires its existing nonempty strings;
first publication requires explicit null (missing fields refuse). The public
outer GitLocal `Action::Push` carries the closed inner `PushNewBranch` kind.
The same public terminal shape and exact-kind result checks are retained.

Schema 9 adds only typed, skip-none `Row.push_new_branch` after every existing
field. Old 1–8 canonical rows remain byte-preserved; reads never migrate.
Only an explicit original Preparing CAS upgrades the schema, and later
ordinary transitions cannot downgrade it. Tools' separate `Row.upstream`
must be appended **after** `push_new_branch` when Root composes both packets.
Each packet is independently compilable; no peer imports/placeholders exist,
and an earlier reader refuses an unknown peer row rather than dropping it.

This packet's RemoteCLI change is only ordinary Push's `remote: Some(...)`
constructor. It adds no CLI command, grant, history action or new-kind
approval; Credentials owns that separately. Its ordinary observer changes
are likewise only `Some(...)` wrappers. New-kind runtime nomination is
separately `None`; ordinary Push/Fetch/observer evidence cannot enable it.
Git's separately reviewed five-case observer extension is not part of this
packet. Upstream setup is a separately consented local action, not implied by
remote success. Current first-party packaging already enumerates the core
Python package; no new package, dependency, endpoint or permission is added.

## Verification and remaining limits

* **128 distinct Python cases passed:** 23 new (11 closed wire/helper,
  nine original capture/transaction, three original engine) and 105 affected.
  All C/A/W/provider/syscall effects in these tests are deliberate fakes;
  real private test files/FDs and the original control/capture code are used.
* **188 distinct Node cases passed:** 12 new and 176 affected Git/Activity
  cases. Tests exercise the original controller/pending promises, reentrant
  invalidation, kind/currentness, lost response and fresh recovery, not DOM.
* Whole strict frontend TypeScript passed on both the original projection
  and the final composed Root 413 projection. Twenty-three Rust source files
  parsed and 16 Python files passed AST parsing; **this is not Rust compile**.
* Ten new portable Rust DATA cases and the extended Mac nomination regression
  are **UNRUN**. No Cargo, stock Git, native CLT/helper, network/provider or
  installed-app operation was executed by this author for this packet.
  Root must compile/test the combined graph and qualify actual native paths.

Evidence remains in `.task-push-new-branch/*.{log,exit}`. An initial exception
expectation fixture failed and was corrected; an initial combined Python
invocation had 102 passing cases plus a nonexistent-module import failure,
then the correct remaining 23 passed. The later engine fixture reran its 12
affected cases with three new ones (15 passed, no double-counting). An initial
TS projection lacked seven existing public JSON inputs; after adding the
exact inputs both complete projections passed. These failed attempts are
retained, not reported as passing batches. All author callers returned; only
the two exact temporary dependency links were removed afterward.

Root's ten new Rust selectors (three module prefixes, all portable):

```text
git_push_protocol::new_branch::tests::                         (3)
git_local_state::push_new_branch_tests::                       (4)
git_local_protocol::push_worker::new_branch_tests::            (3)
```

The affected ordinary protocol/worker/state/Connection and service Remote
cases should share Root's one integration batch. Mac-only nomination check:
`runtime::git_push::tests::fetch_or_public_source_evidence_never_nominates_a_push_provider`.
Python selectors are the three `test_*push_new_branch` modules; Node selector
is `desktop/tests/git-push-new-branch.test.mjs`. No native readiness, live
remote behavior or shipping nomination is claimed by these source tests.
