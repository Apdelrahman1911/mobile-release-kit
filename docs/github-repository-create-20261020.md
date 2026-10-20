# Create a GitHub repository — bounded integration packet

## Owner journey

1. Select the app project and enter the intended `OWNER/REPO` in **Connect GitHub**.
2. Verify the existing GitHub account using the existing selected-account CLI or
   explicit token route. An inaccessible/not-found repository does not erase a
   genuinely verified account; it also does not establish that the name is free.
3. In **Create a GitHub repository**, choose your account or an organization.
   **Private is the default.** Public has a separate visible warning.
4. **Review new repository** reads the account, the exact organization/membership
   when applicable, and the intended repository. It does not create anything.
5. Check the exact owner/name/visibility confirmation, then explicitly **Create
   repository**. The review is one-use. No creation is triggered by mounting,
   refreshing, reconnecting, choosing an account or re-running setup.
6. If a request is uncertain, **Check previous attempts** and **Check this attempt
   on GitHub** read only. A name-only match is explicitly *not* this app's success.

This creates only the approved repository via `auto_init:false`. It does not
initialize Git, add a remote, commit, push, upload workflows, change a global CLI
account, request broader access, delete a repository or complete app setup.
The returned repository ID/owner/visibility are checked; local files and the
existing connection's repository observation are not silently updated.

## Original owners and authority

- `github_repository_create.py` is a closed policy on the existing `ReadResult`
  exchange. Fixed API version, endpoints, 8-request/60-second/2-MiB aggregate
  budget and 256-KiB per-response limit use `_github_connection_transport.py`.
  No new TLS/socket/HTTP implementation or general request endpoint.
- Personal creation rechecks `/user`'s immutable ID/login. Organization creation
  additionally rechecks the exact organization ID and active user membership.
  Membership is **not** create permission; GitHub enforces that on the one POST.
  `404` is missing-or-inaccessible, never an authorization/absence proof.
- `_github_repository_create_journal.py` specializes the existing protected
  journal custodian, including its held ancestors, create-only files, locking,
  original postchecks and consuming close. A durable intent and claim precede
  POST. A redacted exact original `201` receipt is persisted **before** readback.
  The same owner ID + repository name is fenced across new nonces/projects.
  Max32 records/96 leaves; orphan, malformed, duplicate, changed or unknown
  inventory is refused, not repaired. No delete, overwrite or resume-write path.
- Reconciliation only rechecks identity/owner and GETs that exact repository.
  A `404` remains unresolved. A found repository without a persisted original
  creation ID remains unattributed. Only exact immutable original receipt
  readback can become `created-observed`; neither case repeats POST.
- The native child remains in the original `ConnectionState`, `DocumentBinding`
  and Supervisor. It retains the real registered root/generation, saved-edit
  witness, selected account, token/session lifetime and typed original ticket.
  Same-Document original GO rechecks those bindings. The existing Setup runtime
  source/ACL/resource slots, clock, first failure and full join/close roster are
  reused. No receipt-shaped DTO manufactures native finality.
- New Setup bootstrap dispatch is fixed to `mrk-github-repository-create/1`.
  Existing runtime preparation packages these four Python modules inside the
  measured `core.zip`; no extra bootstrap, profile qualification flag, installer
  resource exception, fixture gate or historical-roster change.
- Public status contains only bounded reviewed coordinates, account IDs/logins,
  reason tags, consent, retained attempt summaries and redacted repository
  IDs/URLs. Tokens, private response bodies, home/root paths and file descriptors
  are never renderer fields or diagnostics. The original private GO supplies the
  session token directly to the finite worker pipe.

## Root-only hooks

Apply `github-repository-create-hooks-20261020.patch` after the new leaves. It
targets these **15 existing paths**, composed against current Root64205ef9;
all15 were still byte-identical at Root4894c761 during final source comparison:

```
src/mobile_release/_github_connection_transport.py
src/mobile_release/_desktop_github_setup_engine.py
desktop/src-tauri/src/supervisor.rs
desktop/src-tauri/src/github_connection_session.rs
desktop/src-tauri/src/github_publication_session.rs
desktop/src-tauri/src/github_version_enrollment_session.rs
desktop/src-tauri/src/asset_session.rs
desktop/src-tauri/src/lib.rs
desktop/src-tauri/src/shell.rs
desktop/src-tauri/build.rs
desktop/src-tauri/capabilities/main.json
desktop/src/App.tsx
desktop/src/types.ts
desktop/src/bridge.ts
desktop/src/components/GitHubConnection.tsx
```

Seven main-window **RAW UTF-8 JSON byte** commands, each <=1024 bytes, duplicate
and unknown-member refusing; no decoded-object fallback:

| Command suffix (`github_repository_create_…`) | Exact input |
|---|---|
| `status` | `{}` |
| `prepare` | `{sessionId,expectedRevision,expectedConnectionRevision,ownerKind,visibility}` |
| `create` | `{sessionId,expectedRevision,consentId,confirm:true}` |
| `pending` | `{sessionId,expectedRevision,expectedConnectionRevision}` |
| `reconcile` | `{sessionId,expectedRevision,marker}` |
| `discard` | `{sessionId,expectedRevision,consentId}` |
| `cancel` | `{operationId}` |

The existing shell status loop emits `github-repository-create-status` to the
original main window. The bridge uses the existing unwrapped payload listener
and exposes an optional native-only port; preview/absent listener remains null.
No new timer, network listener, process owner, resource count or generic endpoint.

App retains **one** controller across navigation. All peer/new-action gates and
reconnect include its pending reads/starts/stops/closes, review and uncertainty.
Its own admission excludes only itself and borrows the real verified account,
not a repository-positive requirement. Native connection lifecycle/context/heap
hooks include this original and preserve existing publication, enrollment, Git
and private owners. The original compact status/Stop/Close remains reachable on
other pages. The current callback ref avoids stale initial React closures.

The controller retains every original Promise until it actually settles, even
when an event finishes first. It rechecks service/context/epoch/revision/choices
after synchronous listeners before handoff. Known native pre-admission refusal
can release only the unmatched request. Lost/throwing/malformed replies do not
imply no admission. Native cleanup Unknown is absorbing; late replies can expose
only the exact original Stop identity, never clear it or replay Create. An old
review needs explicit Close; rebind/dispose cannot silently discard originals.

## Focused verification and limits

Source-only composition: `/tmp/mrk-repository-create-hooks-lh8hrvtj` (owned
finite copies, exact roster/Root before+after; shared dependencies are not owned).

- **Python14 cumulative PASS:** initial13 pass plus one failed test fixture
  incorrectly counted its inert token literal as18 rather than19. Corrected the
  assertion to the literal; reran that one case, PASS. No production change for
  that correction. `python-tests.log` and `python-frames-rerun.log` retain both.
  Uses fake exchange and in-memory journal IO overrides against the real policy,
  journal codec, runtime frames and composed common transport. No network, home
  reads, credentials, Git, native services or processes.
- **Node16 PASS,0skip,361.088ms:** `node-tests-v2.log`. Actual leaf controller and
  composed bridge/preview, strict parsers and deferred original Promises. The
  first module-load attempt lacked seven public guide JSONs in the temporary
  projection; no tests ran then. Added those exact existing resources, no source
  workaround. Tests cover private/public, account404, explicit one-use consent,
  exact RAW commands, account/project/API ABA, reentrancy, lost acknowledgement,
  terminal-before-reply, independent pending ownership, contradictory/Unknown
  evidence, old Stop/Close, reconciliation and no automatic connection adoption.
- **Actual full frontend TypeScript no-emit PASS** against current Root sources
  plus these leaves/hooks, using existing shared TypeScript dependencies,
  `typescript.log`/`.exit`. Original process joined. No Vite/React DOM claim.
- **Five Rust DATA tests defined, not executed.** Includes the real retirement
  predicate: ordinary completion preserves the connection, explicit retirement
  still consumes the token, and retained status keeps its original session.
  Own four Rust files parsed by rustfmt. Root still must compile the composed
  Rust/shipping graph and choose appropriate inert test execution; this packet
  does not claim it passed.

Reproduction after Root integration (inert only):

```
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:tests/desktop python3 -B -m unittest -v test_github_repository_create
cd desktop
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 tests/github-repository-create.test.mjs
node --max-old-space-size=768 node_modules/typescript/bin/tsc --noEmit --pretty false
```

No actual native/provider/organization/token permissions, Mac resource/ACL/HTTP
qualification, repository creation or installed UX execution was performed.
Production remains gated by the original installed native profile; compiling or
testing this packet is not activation or permission to create a real repository.
