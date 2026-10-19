# Selected-account gh: native integration handoff

This source is **not activated or installed-native-qualified**. The earlier
Provider plus existing HTTP selected-login/immutable-ID binding passed Root’s
11 synthetic Rust tests. The new central graph still needs Root’s integrated
compile/tests and real original Mac qualification; fake output is not login.

## Closed operation and custody

* The distinct `GitHubAuth` domain permits only `--version`, then one
  `auth token --hostname github.com --user LOGIN`, **after the current original
  configuration passes the pre-dispatch guard below**. There is no `auth status`
  inventory (`--json hosts` exists in stock2.88.1 but authenticates accounts over
  HTTP; it is not a local account list), login/switch/logout,
  install, arbitrary command/environment, PATH fallback or alternate account.
* The fixed Python bootstrap uses **unchanged `run_owned` → C/A/W**. Stock gh’s
  keyring timeout may leave `/usr/bin/security` running. Only the actual
  original C/A/W cleanup, not gh wait/EOF alone, can supply its provisional
  private terminal. STOP/timeout/missing terminal/unknown is not a retry.
* A capture has20s work/30s hard endpoints and at most one15s command.
  Stdout/stderr≤8192 each; version≤1024/token≤4098; READY+terminal≤8192 and
  initial≤32768. The complete source/version/token/HTTP/cleanup invocation
  retains one60s ceiling; first failure contracts cleanup to at most10s.
  Parent GO input stays held throughout work; extra input/EOF means STOP.
* Both Rust pipe scratch and retained output are `Zeroizing` from the first
  read. Raw stdout/stderr never reaches public `ReadEnd.bytes`, `ReadOutcome`,
  events, errors, JSON or renderer. Python’s bounded private process/IPC memory
  is not claimed zeroized. Existing HTTP keeps an ordinary private `String`
  after handoff: **no end-to-end zeroization claim**.
* `GhAuthSources` retains the actual `SourceBook`, native real-user `Account`,
  no-follow physical ancestry/file descriptors and `SnapshotBook` ACL frames.
  It checks exact metadata/hash PRE/POSTs for selected physical `gh` and both
  private regular files at native HOME/.config/gh/config.yml and hosts.yml.
  The SAME account/config/tool originals remain held across BOTH captures and
  the existing HTTP identity read. Ambient tokens/routing/loader inputs are
  scrubbed; no renderer path/hash is executable nomination.

### Pre-dispatch migration guard

Stock2.88.1 `internal/ghcmd/cmd.go:52–58` runs MultiAccount migration before
**every command, including `--version`**. `internal/config/config.go:176–202`
skips it only when the effective root version is exactly `"1"`; migration can
write configuration/Keychain and call GraphQL. A POST-only refusal is too late.

The exact pinned dependency is `github.com/cli/go-gh/v2 v2.13.0`:

* `pkg/config/config.go:192–224` loads config.yml as the general map and appends
  nonempty hosts.yml beneath `hosts`. It uses fallback only if the resulting
  general map is empty, **not** when an existing config lacks `version`.
* `ConfigDir:250–262` uses nonempty GH_CONFIG_DIR first; the fixed native-derived
  environment selects the actual admitted HOME/.config/gh, not ambient routing.
* `Get:47–58` returns the selected node's Value. `internal/yamlmap/yaml_map.go`
  requires a root MappingNode (`45–57`); `FindEntry:78–91` takes the first exact
  key Value match. Appended hosts cannot replace root version; an existing root
  hosts key could shadow it, so this profile refuses that form too.

`github_auth_config.rs` and `_desktop_github_auth_config.py` recognize only the
same bounded ordinary ASCII block-mapping subset:13 standard option keys,
unique root version scalar `1`, `'1'` or `"1"`, optional single-level2/4-space
aliases, and simple one-line scalar values/comments. Duplicate/unknown roots,
root hosts, complex keys, multiline/flow scalars, directives, multiple documents,
anchors, aliases, tags, escapes and ambiguous syntax are refused. This is not a
general YAML parser, schema repair or account inventory. Current legacy/unknown
configuration requires manual attention; MRK does not migrate or rewrite it.

Native `GhAuthSources.snapshot` checks a Zeroizing≤64KiB capture of the SAME held
original bytes it hashes, initially before capture admission and on every POST.
The existing working reservation includes that capture and finite parser stack.
The private Python worker checks its matched original descriptor/hash at admit,
every POST, and the final original `run_owned` command seam before C/A/W. Only a
fixed refusal leaves the private parser; no config/token text enters errors.
These are held-original change-detection checkpoints, not an atomic filesystem
write lock against external config changes or installed-native qualification.

The public dependency source was acquired separately by the authorized Cleanup
lane, not executed: config.go SHA256
`a5f63c41231f77e06959b979494e754d43817d382a820c95e0f5221401c90e81`.
The retained ZIP-byte SHA is not a Go module h1 checksum; no such equivalence or
new supplier/native proof is asserted. Shared50-case synthetic fixtures exercise
the finite grammar in both languages; Rust execution remains Root's batch.

## Implemented central graph

`asset_session_gh_auth.rs` retains `Registration` in the actual Document before
any source inspection. It owns the exact `OriginalWork`, document/session
identity, native context Arc, original project registry root/generation, retained idle connection generation,
explicit selected login/repository/request revisions, source set, provider,
original wait handles, consent and monotonic failure state. A `Context` DTO
cannot construct its weak-reference `GitHubAuthGoGate`.

Source Inspect/BeforeHttp/Finish/Close use only the existing `OriginalWork`
`ChildJob`/blocking-worker/join slot. The per-capture Supervisor uses its existing
registry, permit, driver, watchdog, final observer, acquisition, child, pipe,
wait and native settlement owners. It adds a fixed private-output arm, not a
second process manager. The original runtime Book is a distinct existing
`slots!` profile for protected Python/core/**github_auth_bootstrap.py**.

Runtime and selected source originals are rechecked before GO and after work.
The request is retained before gate binding; GO spends the exact role/id/digest
once under the same Document and original Supervisor claim. A valid private
terminal is required before consuming native close. Only `Owner.retire` can
publish its private mailbox after actual driver/watchdog/native/IO joins.
The fixed caller additionally joins that **same retained final observer
JoinHandle**, outside Document, before private consume/serial reallocation.
Missing/failed/cancelled/late join remains unknown; it is not repolled.

One capture reserves the full128MiB existing code-control partition plus the
unchanged16MiB Document/source/other backing. The two captures do not overlap
runtime reservations. Retained source64fds + runtime67fds + control32fds must
fit256. Bounded native request backing is checked before cloning. The original
Document census refuses live gh work; after all joins and HTTP acceptance it
keeps only bounded public finished status, not a retired runtime allocation.

### Consume outside Document, rematch inside

`registered`, role arming, `retain_original`, `finish_selection` and
`finish_prepared_connection` may call the actual gate and run **outside** the
Document mutex. No temporary `take` removes an in-flight owner from admission.
Prepared token output is consume-only, with no Clone/Debug/serde/token getter.

Under that SAME Document lock, the coordinator rematches actual session/context,
project root/generation, repository, selected login/revision, one-use consent
and acknowledged source POST. It then calls `ConnectionState.connect_prepared_gh`
with a private `GitHubAuthConnectionHold` minted only by this original. That
helper rechecks the exact target and uses the existing HTTP admission without
callbacks, waits or a Document re-lock. No duplicate HTTP transport is added.

Initial public revisions are checked only at admission. Later status/capability
churn cannot cancel the operation: pre-HTTP currentness compares the actual
idle ConnectionState session-generation counter (detecting connect/disconnect
ABA) and absence of a private session. Observing legitimate native Closing
uses scope rematch with an explicit Observation check purpose; a concurrent
Closing/body-return transition cannot apply the Work-only veto. It does not
reopen work/GO or manufacture cancellation.

The connection retains the hold along with its actual HTTP ticket. Even a
successful `/user` reply cannot pin identity or mark Connected until the same
source set has POSTed/closed, original child work and coordinator have joined,
and the Document has rematched original scope. Existing `/user` must match the
selected login before immutable account-ID pinning. Wrong target/account never
falls back. Unknown keeps originals and blocks reuse; known failure may retire
only after actual settlement. `GitHubAuthStatus.phase=settled` reports native
custody, not authentication; the original ConnectionState remains the sole
source of authentication status.

## Root-only parent hooks and remaining packaging/route

Transferred implementation paths are supervisor.rs, runtime.rs (GitHubAuth only),
installed_runtime_macos.rs (exact slots), asset_source.rs/asset_source_macos.rs
(gh child/reexports), github_connection_session.rs and the new Doc child.
The ordinary shared parent is **not edited in this lane**:

* `github-auth-document-integration-2026-10-19.patch`: exact child include,
  `DocumentState.gh_auth`, inert defaults, census, ordinary admission/exit/STOP
  hooks, fixed Mac ChildJob/ChildEnd/cleanup arms, and base gate companion.
  Registered edit admission checks gh pending under the SAME Document before
  publisher acceptance or context side effects; STOP/Close remain available.
  `gh_auth::observe_locked` precedes HTTP reconciliation;
  `gh_auth::retire_joined` follows it under the same lock.
* `github-auth-test-defaults-2026-10-19.patch`: two additional existing test-only
  DocumentState literals get `gh_auth: None`; no fake active original.
* Root registers crate modules `github_auth_capture_wire`,
  `github_auth_nomination`, `github_auth_native_owner`, stages the fixed
  bootstrap through the existing inventory/seal, and supplies any actual
  native picker/explicit-register command through the original Document.
  Neutral service/status DTOs do not authorize this operation.

Stock official2.88.1 nomination is separate from custom2.88.1-mrk-history.1.
Root's separate reviewed source-constant nomination amendment supplies the
public stock source and exact target pins; this lane does not alter that file
or manufacture admission from version text or environment bindings.
Missing nomination/profile
means unavailable/no launch, not silent History reuse. The current source
profile requires a physical binary path; a future Homebrew alias resolver needs
its own original alias custody and cannot just canonicalize a user string.

Source review or synthetically matching hashes do not qualify actual installed
runtime/stock executable/config/keyring/HTTP ownership or public delivery.
No real gh, keyring, credentials, account/API calls, external Git or native
signing were used here. Root owns the integrated Rust batch; no Cargo was run
by this lane. The earlier focused log `verification/gh-auth-worker-focused-20261019.log`
records21 Python passes including one actual unchanged C/A/W fixture with only
its own gh-shaped synthetic child/helper. Apple independently ran20 passive
fixtures. Current guard-focused log
`verification/gh-auth-schema-guard-focused-20261019.log` records24 passive Python
passes, including50 shared schema cases and malformed/legacy pre-version/token
zero-command and final-seam config-drift tests; no C/A/W or installed gh was run
in that batch. Central graph tests (five Doc DATA checks, one original
ConnectionState status/epoch check, two original-memory-task observer checks and
two config grammar checks) are **defined, not run** until Root’s integrated graph batch.
