# Draft and ready-for-review PR creation

Base: `817f82279b200c2c931864f0bdec570905e40a66`. Independent plan review:
Project, exact `d36a13cf3ce38a4f8446232648a091433b85a57893f22ea35e6974dff0d71ff2`.
Root authorized this isolated source implementation. Shared files are **only**
the detached `github-pull-request-mode-hooks-20261021.patch`; Root composes them.

## Delivered scope

The existing PR page now offers **Draft** (default) or **Ready for review** for
one new same-repository PR between two already-existing remote branches. It uses
the same original Check, private review, explicit Create, Stop, pending journal,
GET-only reconciliation and browser/Activity handoff. Ready creation can notify
reviewers and run repository workflows; it does not mean approved or mergeable.

The existing optional Advanced CLI permission adds `pr-create` to the same
GitHub family/namespace 9, single 32-row pool and three ID-only verbs:
`github-submit`, `github-status`, `github-cancel`. No title, body, token, path,
account or provider URL is added to CLI arguments. Old `draft-pr-create` remains
Draft-only. Publication's separate `setup-publish`/GET-only `setup-reconcile`
contracts remain unchanged. No namespace, executor, queue or transport is added.

This does **not** convert an existing draft, review/approve/merge/close a PR,
push Git commits, publish a release or download artifacts. Those operations are
not claimed as complete. No provider/native/installed journey was run here.

## Exact compatibility and authority

* Only Ready adds `creationMode: "ready-for-review"`, to **both** private `draft`
  input and retained `target.intent`. Absence means Draft; explicit null, boolean,
  `"draft"`, unknown values/fields and duplicate keys refuse. `Prepared.draft`
  must corroborate the retained mode. A false boolean alone cannot authorize it.
* Draft's old canonical input/intent/review, confirmation, protocol string,
  `mrk-draft-pr:` marker, hashes, and immutable intent/claim/receipt/closed files
  remain byte-identical. Loaded records are never migrated or rewritten.
* Core fresh pre-Create checks, private text hashes, native Consent, request/GO
  and public parser bind the same mode. The existing fixed body validator is
  shape-only; `request_role` still compares the exact original Draft/Target/body.
* A mode edit invalidates the actual original review, including ABA edits and
  reentrant callbacks. Original Prepare return is still required; a review event
  alone is not consent. UI pending-journal and native/core prior-attempt fences
  remain **mode-blind** for the same repository ID and base/head pair.
* The same real 201 identity is acknowledged in memory and recorded before
  validating its returned draft bit. Wrong/missing mode, lost receipt write or
  wrong GET mode retains actual ACK/spent claim as unconfirmed/unresolved. An
  unattributed marker or historical closure cannot replay POST.
* New native `PrCreate` requires `agent-pr-create-once-v1` and a real retained
  Ready Prepared; `DraftPrCreate` retains `agent-draft-pr-create-once-v1` and
  requires Draft. The relationship is checked at the existing private-review,
  scope-installation, Create-consumption and registration cuts, in addition to
  pointer identity, root/stamp, private text, IDs/revision, expiry and Entry.
* Same Connection acceptance/control, original relay return and service-history
  ACK remain independent finality requirements. READ cutoff, first-failure,
  unknown/lost callers, revocation and all original joins are unchanged.

No existing time or memory/disk cap changes: 9 GETs for Prepare, at most the same
12 HTTP calls for Create, existing 60-second budget and cleanup, 32 records,
4-KiB record, 192-KiB response, 2-MiB PR retention and 1-MiB same-family Document
debit. Mode is a small inline enum on native DATA; existing actual struct/heap
quotes and admission checks remain authoritative, not an assumption that the
whole Document fits. There is no credit for retired rows or increased quota.

## Owned leaves and shared seams

New source/test leaves:

* `src/mobile_release/github_pull_request_mode.py`
* `tests/unit/test_github_pull_request_mode.py`
* `desktop/src-tauri/src/github_pull_request_mode.rs`
* `desktop/src-tauri/src/github_pull_request_mode_tests.rs`
* `desktop/src/githubPullRequestMode.ts`
* `desktop/tests/github-pull-request-mode.test.mjs`

The detached patch has 21 parents: Python PR core/transport and one old test;
native PR protocol/session, same-family protocol/native decoder and its test,
same requests tests, service Action, installed CLI catalogue and its test;
TS PR protocol/controller/view, Activity description, same-family permission
codec/view, App's exact selected-original dispatch, package test entries, and
the existing publication delegation test's exact kind roster/foreign-kind case.
No original journal/management/worker/Connection transport/lifetime source is
replaced. Full exact pre/post copies and pins are in `.task-pr-mode/hooks`.

The Rust mode is a child of the existing PR protocol root, already included by
the library/installed CLI and separate installed observer; no new crate-root
declaration is needed. `prepare_runtime.py` captures all `.py/.json/.pem` source
under `src/mobile_release`, including the new Python leaf. No bootstrap, fixed
role, qualification/nomination flag or runtime supplier changes.

## Focused evidence and honest failures

All execution used one task-only public-source projection, nonroot UID/GID
65534, empty environment, private 0700 HOME/TMPDIR, no installed dependencies or
host configuration. Python explicitly forbids subprocesses and sockets and has
an original 120-second suite bound. Node uses 384-MiB heap, serial files and
10-second per-test bound; only inert DTO/deferred original calls run. No Git,
provider, token, native or Store operation was invoked.

* **Python 36 PASS**, 0.175s, caller exit 0: 12 new actual core/worker/journal
  cases +16 existing PR +8 existing management. One new case opens the real
  exclusive no-follow journal in private TMPDIR, writes three bounded records,
  closes, cold-reopens and proves cross-mode refusal/unchanged bytes. It retires
  the known successful fixture only after real closes. Other storage/HTTP is
  inert; this is not native or server evidence.
* **Node 94 distinct cases covered successfully**: 13 new mode/actual-controller
  cases and 81 affected existing PR, management, permission and publication
  cases. Exact logs preserve sequence rather than claiming one all-pass caller:
  `node-composed-v2.log` has 57 passes and a publication-file load failure;
  `node-publication-v4.log` has 36 passes and the old exact-kind assertion failure;
  `node-publication-corrected.log` reruns only its two amended cases, both PASS,
  caller exit 0. Remaining unchanged cases were not rerun for cosmetic evidence.
* Initial `node-mode-v1.log`: one test incorrectly compared the existing
  null-prototype parsed object to a normal object; the assertion now compares
  fields. Projection-only publication-file permissions and its two public
  import prerequisites were then corrected (v2/v3 logs retained). The remaining
  old publication expectation was extended to include the new closed kind and
  keep it rejected as a publication reference. No production code was changed
  to suppress these test/projection failures.
* **Composed strict TS noEmit PASS**, 17.789s, original caller joined exit 0.
  Existing dependencies read only, 768-MiB heap, 4.5-GiB entry/3-GiB floor;
  actual minimum available RAM 8,062,443,520 bytes. Compilation cache disabled.
* Five affected Python sources AST-parse; two owned Rust files formatted and
  nine detached Rust parents syntax-parse. **Six new Rust DATA tests and affected
  Rust tests are UNRUN**; no Cargo/native build was done by this lane.

Evidence lives in `.task-pr-mode/results` and the public-source projection pin
list. All original callers returned; the only dependency link and projection
were removed after checking HOME/TMPDIR empty. Initial failures remain retained.
No live GitHub CAS, account/TLS, installed runtime or shipping availability is
inferred from any of these tests.

## Integration / review

Apply only the six new leaves, this guide, and the exact 21-parent Root patch;
do not replace current shared files wholesale. Before/after source pins make
later additive unions explicit. No workflow or selector changes are included.
Root owns combined Rust/native qualification and any actual operation.
Independent ACTUAL source review must be distinct from Project's plan review.
