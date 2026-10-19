# Local Git read integration — source candidate

This adds **Check local Git access → Refresh changes → inspect selected
differences**, plus local branch comparison and bounded commit identifiers.
It reuses the existing `GitRepositoryController` and panel. No writer is supplied:
staging/commit drafts remain mounted under Advanced, while actual reviews,
errors and original Check/Stop controls remain visible. No fetch, push, account
connection, hook, build, signing or Store action is included.

This is not installed/native qualification. Root must review/apply the separate
hooks, compile the actual graph and qualify the genuine Mac route before delivery.
No existing qualification flag is changed; no fixture/runtime fallback is added.

## Source and Root hooks

Dependencies are the accepted Python read slice (`85cbb35b` in this lane;
`564e6d25` in integration), its fixed `desktop/git_read_bootstrap.py`, the existing
Git repository UI/controller and Root's already integrated `ProgressiveDisclosure`.
The accepted real-Git fixture is separately committed as `96388575`.

New native modules:

- `git_read_protocol.rs`: closed public RAW requests and private child protocol.
- `git_read_sources_macos.rs`: existing SourceBook/Account/SnapshotBook facet.
- `git_read_runtime_macos.rs`: distinct slots of the existing installed Book.
- `supervisor_git_read.rs`: operation-specific arm of the original Supervisor.
- `asset_session_git_read.rs`: same Document's retained ticket and memory status.

New frontend modules are `gitReadProtocol.ts`, `gitReadController.ts` and
`components/LocalGitRead.tsx`; the two existing Git repository files are changed
only for optional read admission/definite-decline handling and progressive UI.

`local-git-read-native-hooks-20261019.patch` contains **17 Root-only paths**, based
on integration `12616a1a`. It adds the closed Supervisor/runtime/source/Document
arms, three shell permissions, bootstrap roster entries, and App/types/bridge
wiring. Root's unrelated `application_service_host.rs` changes are not included.
Apply only after the additive source commit; compose concurrent Version Source
Supervisor and Document hooks, never replace them. Both original domains must
appear in reciprocal pending/STOP/census gates. Version Source may use a distinct
instance of the FS facet, not the GitRead Gate, ticket, profile, clock or receipt.

## Closed transport

All three commands accept UTF-8 JSON **RAW Uint8Array only**, strict duplicate
and unknown-key rejection. Start's envelope-inclusive limit is 96 KiB; status
and cancel are 1024 bytes. There is no renderer filesystem/native snapshot,
tool path, token or arbitrary command input.

| Command | Exact input | Result |
| --- | --- | --- |
| `git_read_status` | `{}` | `Status` |
| `git_read_start` | `{projectId, expectedDocumentRevision, action}` | `StartResult` |
| `git_read_cancel` | `{operationId}` | `Status` |

`action` is `{kind, expectedRevision, paths, staged}`. Observe has a null revision,
empty paths and false staged. Diff has the exact previous observation digest and
1–64 sorted unique relative paths. History has that digest, empty paths and false
staged. The native registered project supplies the root and held controls.

`Status` is `{schemaVersion:1, documentRevision, available, operation}`. Availability
means the fixed installed profile is selectable, not repository compatibility,
file freshness, permission to bypass busy gates, or release readiness. Document
revision is an admission comparison, never a progress-ordering counter.

`StartResult` is `{schemaVersion:1, admission, request, status, reason}`:

- `started` retains the actual Supervisor ticket before returning; reason is null.
- `refused` is minted only before that original roster insertion and repeats the
  exact request. Reasons are invalid-input, stale-observation, unavailable or busy.
  It proves no admission **for that request**, not operation/cleanup finality.
- Ordinary transport loss, malformed response and `cleanup_unknown` never become
  a clean refusal. An older operation disclosed by refusal remains owned, with
  Check/Stop on its original port. No automatic resubmission follows a stale read.

No new event lane: Root serially polls memory-only status while an actual known
read is active. Idle mounting/navigation never starts a file read. Unknown stops
automatic polling but leaves explicit original Check/Stop available.

## Original ownership and freshness

Document admission holds its actual mutex through same-Supervisor ticket
insertion. Gate identity, registered root, registration generation and Document
revision are repeated before inspection, at GO and before successful publication.
Acquisition also uses the existing serialized original Owner/runtime claim.
The original inspection/acquisition/IO/wait/native-settlement/management tasks own
all work. There is no second process driver or newly acquired finality witness.

The native facet opens no-follow held project controls and the fixed physical CLT
Git, checking the entire CLT ancestry is root-owned and not group/world writable.
Private control bytes/hashes and native identities go only to the fixed child.
Python independently freezes/compares inputs under its existing owned process
contract. Unsupported layouts/providers fail closed, without PATH fallback.

Work/hard endpoints are the original 45/55 seconds. Every first failure/STOP keeps
the minimum original 10-second cleanup endpoint; late data never renews it. A
valid child terminal alone cannot retire custody: the same child wait, stdout/
stderr EOF, original stdin close, source/native closes and every actual join are
required. Missing/malformed post-launch terminal or uncertain custody is retained
Unknown, not a synthetic successful cleanup. Known settled refusals remain failures.

Frontend retains every original Start/status/Stop Promise until settlement, even
if a terminal status arrives first or the selected project changes. Actual Unknown
is absorbing; a historical response cannot rewind terminal evidence. An ordinary
lost reply can resolve only through the matching original status, not by replaying
Start. DATA reaches the existing repository controller only after all those
Promises settle and a final API/session/project/epoch check, including after
synchronous listeners. Drafts are never adopted as saved files or discarded.

App keeps one native read controller and at most 64 project/service-bound local
repository controllers; it never retargets or evicts an old draft. Existing
workspace/service/draft intents retire observation eligibility, not original work.
Git admission excludes its own busy signal; peer owners, passive reads and
reconnection reciprocally block. Current shared native policy also requires the
GitHub connection/other private owners to be quiescent; this slice does not relax it.
Original compact Check/Stop remains reachable on other pages.

## Bounds and packaging

- Source ledger: at most 128 records; actual runtime live-FD debit plus 32 reserved
  FDs must still total at most 256. The current runtime term is 67. Hashing is
  streaming with 32 KiB scratch; no 128 MiB executable or 16 MiB index byte copy.
- Native control reservation: existing 128 MiB code/inventory partition, plus
  11 MiB framing/decoded/copy backing, actual source/Owner/Resources sizes. The
  existing 16 MiB Document/non-code admission partition is not enlarged.
  Strict parsing stays at 20,000 nodes/32 depth; public frames stay at 2 MiB.
  Close reads only the retained outcome enum, not another result clone.
- A positively retired public projection has a 2 MiB debit: Observe is at most
  512 bounded paths and 4096 remote names; Diff is at most 256 KiB; History has at
  most 25 identifier/parent/time rows. Messages, author/email and signatures are
  withheld. Pending/unknown originals do not supply a guessed quiescent census.
- Current bootstrap roster grows 16 → 17 (`git_read_bootstrap.py`); legacy six
  remain unchanged. Optional four Store entries make 21, not automatic Store
  activation. `FRESH_SUPPLIER_FILES = 2048 - len(CURRENT_BOOTSTRAPS) - 3` becomes
  2028. Current 16,384 files / 32,768 entries and native 32,768+64 records remain
  unchanged. The selected bootstrap must occur in the actual held manifest.

## Verification and remaining work

Focused inert command:

```sh
/opt/node/current/bin/node --experimental-strip-types --test --test-concurrency=1 desktop/tests/git-read-native.test.mjs
```

Author result: **21 passed, 0 skipped**, 243.331141 ms. Cases cover exact RAW/schema,
real repository-controller handoff, original Promise ordering/Stop, lost reply,
actual Unknown, foreign/ABA/context/listener races, metadata-only history and
typed clean refusal versus malformed/already-observed originals. The unchanged
existing Git repository 29 cases previously passed; they were not repeated.

Five native pure DATA test definitions are present but **not executed**. Only
the installed Rust formatter parsed the new Rust files. No Cargo, compiler,
React/DOM, new private worker, Mac, account, network or real credential run was
performed for this packet. Root must compile/typecheck the integrated graph.

Separately, the accepted disposable real-Git fixture passed all three cases
cumulatively: first case in original session 77375, remaining two in approved
retry 82942 (127.743 s). The original failed enclosing-deadline attempt is not
hidden; no product check was weakened. All owned workers joined and the exact
fresh empty fixture root was identity-checked/removed. This proves only those
core fixture paths, not native caller/runtime/installation qualification.

Remaining delivery gates are actual Mac compilation and original native
CLT/runtime/source/STOP/finality/ordinary UI qualification, reviewed packaging
and a new installer. Writes, remote transport, shared-CLI Git execution and
automatic release/source authority are outside this read-only slice.
