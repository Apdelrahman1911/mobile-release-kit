# Pull request follow-up — 2026-10-20

## Useful increment

- After the original Create/Reconcile invocation **and** native settlement,
  explicitly read that PR's status, reviews and CI through the existing Activity
  controller. Refresh keeps the selected PR; it does not start another overview.
- Open the selected PR, its full diff, or the exact unused comparison in the
  browser. The browser's account may differ from the app's connected account.
- After an earlier PR with a durable actual-201 acknowledgement is freshly
  confirmed closed, explicitly refresh saved attempts and review a later PR for
  the same branches. No creation, refresh, confirmation or browser call is automatic.

This does not add approval, merge, mark-ready, push, branch mutation or release
authority. Actions retry remains the separately reviewed operation. Activity's
bounded historical results are not an overall approval or merge-eligibility check.

## Existing owners, not new services

`github_pull_request_management.py` extends the original PR reconciliation only.
It uses the same Connection/Setup/HTTP owner, private journal custodian and
original clock/close. The acknowledged-PR path performs four fixed GETs: `/user`,
the repository, the acknowledged PR number, and the repository again. It remains
inside the existing 12-request/aggregate-byte/60-second limits; no POST is added.

Closure requires the actual stored 201 ID and number, original repository IDs,
and original base/head repository and ref. Legitimate conversion from draft,
text changes, merge and moved commit SHAs do not invalidate that immutable
identity. One closed observation is historical, not provider CAS or permanent
absence. The next explicit Create still repeats the existing fresh open-PR query;
a reopened PR blocks it.

The same journal gains one create-only `closed` leaf per attempt, bound to the
actual held intent and receipt byte digests. Original intent/claim/receipt bytes
are never replaced or removed. All prior same-repository/base/head attempts must
have valid closures; unknown, unsent and marker-only attempts stay fenced across
new nonces. The joint cap remains 32 attempts, now at most four fixed leaves each
and `32 * (MAX_RECORD_BYTES + 3072)` bytes. Existing responses retain their bounds.
Old rows without `closed` remain valid; null, malformed, orphan or mismatched
closure data refuses the inventory rather than silently dropping it.

## Closed browser boundary

One new `github_browser_open` main-window command accepts strict duplicate-checked
RAW UTF-8 JSON, at most 1024 bytes. Its three closed selectors carry only original
session/operation or consent IDs, status/connection revisions and conversation/files
choice. The renderer supplies no URL, repository path, number, argv or account.

The same Document/Connection checks original registration/root, saved-edit gate,
session, account/repository pins, current native result/review and peer lifecycle.
It generates only `https://github.com/OWNER/REPO/pull/NUMBER[/files]` or the exact
held SHA comparison. The non-async Tauri entry retains the Doc/Edit gates through
one synchronous ordinary-user/main-thread `NSWorkspace.openURL` request. Native
ASCII grammar is checked again. No process, HTTP, queued callback or new owner.
The reply is only `{state:"request-sent", browserVisibility:"unconfirmed"}`.
Unsupported runtime or unconfirmed handoff offers copying the displayed address,
not a fallback opener or automatic retry. No qualification flag changes.

The existing Activity and PR controllers retain each original browser Promise,
including across context changes/disposal. Their owner reasons block peer work;
original Status/Stop/Close controls stay reachable. Local browser uncertainty
does not pretend to be HTTP/native cleanup settlement. Current completion is
derived only after the genuine original start Promise returns; terminal events
alone cannot enable follow-up. Synchronous listener/parser reentry is rechecked.

## Integration and verification

Apply `github-pull-request-management-hooks-20261020.patch` after the 11 source/test
leaves in this packet. Its 22 shared targets compose against Root
`4f795bf458f63d581ff04dd66e7a39f06ef93eaa`; Actions retry, CLI Commit and branch test
entries are retained. App wiring is one existing PR-panel slot. Both API factories
reuse the current bridge invoker; no separate DesktopApi, transport or controller.
The patch includes the manual installed-observer module graph, native build/file
roster and fixed command permission, plus the literal existing package test entry.
Python packaging uses the existing source-tree copy; no new worker/profile.

Author evidence (inert, not native/provider qualification):

- New Python: **8 passed** in 0.068s, actual PR/journal modules over fake HTTP and
  an in-memory journal backend. Exact closed→reopened, one fresh later POST,
  unknown fences, immutable IDs/digests, orphan/schema/limits and failure cases.
- New Node: **10 passed**, 0 skipped, 380.421056ms, complete existing controllers,
  real bridge factories and deferred fake ports. Original-return ordering,
  currentness/ABA/reentry, retained browser calls, Close and unknown covered.
- Current-Root composed full TypeScript: **passed**. Existing affected Activity/PR
  Node files: **35 passed**, 0 skipped, 413.325918ms. No unchanged new-suite rerun.
- Five new and ten shared Rust files parsed using rustfmt only; Python AST and
  JSON syntax checks passed. This is not type checking or native compilation.
- Three new Rust tests are **defined but unrun**: `browser_wire_accepts_only_original_selectors_not_urls_or_accounts`,
  `closed_history_requires_exact_ack_and_does_not_restore_claim`, and
  `closed_effect_is_reconcile_only_and_original_201_required`.

Focused commands use the composed source projection:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=<after>/src:<after>/tests python3 -B -m unittest -q unit.test_github_pull_request_management
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 <after>/desktop/tests/github-pull-request-management.test.mjs
node <after>/desktop/node_modules/typescript/bin/tsc --noEmit -p <after>/desktop/tsconfig.json
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 <after>/desktop/tests/github-{activity,pull-request}.test.mjs
```

All author callers returned. No live GitHub/config/credential/browser operation,
native build, Cargo, GUI automation, signing, CI or installed qualification was
performed. Root still owns actual Rust graph/Mac checks and final integration.
