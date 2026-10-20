# Local GitHub CLI account choices — bounded source handoff

This adds **Find local GitHub accounts → choose a name → choose gh & connect**
to the existing GitHub CLI panel and controller. It does not sign in, choose an
account automatically, switch gh's default account, install gh, or authenticate
a listed name. The existing connection owner and its fresh `/user` account-ID
check remain the only source of Connected/account/repository facts. Manual
username entry and the separate PAT route are preserved, never automatic
fallbacks.

## Actual upstream basis

Inspected public source only: cli/cli v2.88.1, commit
`37800dd56a536e69b20d682b770e983c3829c164`, and its go-gh v2.13.0 configuration
reader. `internal/config/config.go`'s `UsersForHost` reads the keys of
`hosts/github.com/users`; `ActiveUser` is a separate value. `TokenForUser`
performs the existing explicitly selected user's token lookup. Conversely,
`pkg/cmd/auth/status/status.go` constructs an HTTP client and collects account
information before its JSON token redaction: that command is **not used**.

The go-gh reader loads general configuration before appending hosts. Its
first-key-wins semantics make root-host shadowing unsafe. The existing held
`config.yml` schema-one/migration guard stays unchanged and is applied before
listing, and again before **any** existing gh capture (including `--version`).

No real configuration, credentials, Keychain, gh command or network was read or
executed for this change. Source archives were the task's approved public copies;
no private-origin evidence was accessed.

## Closed native transport

All four gh-entry commands use their original main-window RAW UTF-8 JSON boundary,
duplicate-key refusal, and 1024-byte total request envelope. No path, token,
arbitrary command, host URL or account-authority object enters these requests.

* New `github_auth_accounts`:
  `{projectId,repository,expectedDocumentRevision,expectedConnectionRevision}`.
  It returns the actual original account-read terminal status, not a start/success
  guess. Native admission refusal is before Entry/dispatch; after admission it
  yields its joined result or retained cleanup-unknown.
* Existing `github_auth_connect`: its original five fields are unchanged. The
  list route additionally sends omitted-only `accountsObservationId`; explicit
  null/unknown fields are refused. Connect's original result/HTTP correlation is
  unchanged.
* Existing `github_auth_status {}` and `github_auth_cancel {operationId}` return
  either the unchanged Connect status or the disjoint account-read status below.
  No pretend `selectedLogin`/HTTP session is inserted for listing.

Account-read status:

```
{schemaVersion:1,kind:"accounts",documentRevision,connectionRevision,available,
 operationId,projectId,repository,
 phase:"reading"|"stopping"|"settled"|"failed"|"cleanup-unknown",reason,
 accounts:null|{observationId,logins:[...],current:boolean}}
```

Only genuinely joined success has `accounts`. Empty names mean that the supported
map listed none, not that credentials/accounts are absent. `available` remains
the real existing qualified profile gate; it is not file/account verification.
Document/connection revisions are fresh admission comparisons, not progress
ordering. `current` describes the retained native scope, not a continuing file
lease or verified account. A late Stop of this same already-joined read returns
its retained result without claiming a new cancellation.

## Original ownership, privacy and bounds

`asset_session_gh_auth_accounts.rs` is a child of the **existing GhAuth Entry**.
It uses the same OriginalWork, ChildJob::GitHubAuth executor, account/ACL/SourceBook,
join bookkeeping, Stop/expiry/quit/census paths, original 60-second ceiling and
first-failure cleanup ceiling. It does not create another execution registry,
Supervisor profile, process, HTTP operation, keyring call or GUI picker.

The source facet opens only the actual native user's fixed gh configuration.
It holds and compares the complete files using the existing checked descriptor
and ACL owners. Each private input is bounded to 64KiB; one zeroizing full-file
buffer and the existing zeroizing streaming scratch are reused. The parser
borrows scalar slices: secret values never become public parse nodes,
diagnostics, exceptions, snapshots or logs.

The supported ordinary block-mapping subset is deliberately finite: 512 lines,
16 hosts, at most 16 unique (ASCII case-insensitive) names per host, and only the
github.com names are projected. Duplicates, aliases, complex keys/values,
unsupported fields, ambiguous indentation, non-ASCII/oversized/partial input
refuse the **whole** list, not a misleading subset. A user can explicitly use the
manual route; that route still must pass the existing source/migration guard.

The private finished witness contains the actual native account, full file
identities/hashes, complete public names, registered project/root generation,
same context/session identities and original comparison revisions. It is not
serializable or Debug-printable. Connect must match the exact retained
observation/member/context under Document, then repeat a fresh SourceBook
inspection and full witness comparison before even the existing version/token
captures. Source changes never become automatic account selection or retry.

The source book remains bounded to 64 slots; its derived roster reserves two
fixed leaves for listing (no tool/runtime descriptors). Added retained names and
witness fit the charged 16KiB source overhead and existing 256KiB Entry backing;
admission uses the original complete `github_auth_admission_bytes` census. Only
the original's actual close and child/coordinator joins permit the bounded
finished entry. An invoke observer retains bounded result DATA plus Weak
Document, never a resource/registration backreference. Unknown originals remain
retained and block reuse.

## Frontend integration (no new App owner)

The same `GitHubGhEntryController` retains the explicit discovery intent, serial
comparison/account reads, original promises and bounded existing status poller.
Every callback rechecks API/port/context/epoch. Names need explicit selection;
context/API/ABA changes retire selection, and a subsequent Status cannot adopt
that old list. A result arriving before its original invoke finishes does not
release its busy ownership. Original Stop/status remain reachable across
navigation and project changes. Cleanup-unknown is absorbing; transport loss
does not prove no admission. No failed read clears username or PAT drafts.

`createGitHubGhApi` adds only the closed RAW account method. Existing Root
`DesktopApi.githubGhEntry`, bridge factory call, retained controller and global
`githubGhBusy` peer/passive/reconnect gates already consume this API. **No App,
bridge, types, connection-controller or PAT changes are required.** The existing
status event listener continues to own genuine GitHub connection facts; listing
adds no event lane or second connection controller.

Apply `github-gh-accounts-hooks-20261020.patch` centrally after integrating the
owned leaves. Its exact seven paths are:

1. `desktop/src-tauri/src/github_auth_sources_macos.rs`
2. `desktop/src-tauri/src/github_auth_entry_protocol.rs`
3. `desktop/src-tauri/src/asset_session_gh_auth.rs`
4. `desktop/src-tauri/src/shell.rs`
5. `desktop/src-tauri/src/lib.rs`
6. `desktop/src-tauri/build.rs`
7. `desktop/src-tauri/capabilities/main.json`

The parent hooks delegate pending/Stop/observe/retire/census and the same child
executor; original Connect/GUI/HTTP behavior is otherwise unchanged. Two existing
DATA test constructors merely set the new optional member to None. The shell
adds the one closed accounts command and uses the union for status/Stop. No
qualification flag, bootstrap roster, runtime resource or privilege is added.

## Focused verification and remaining gates

Author Node evidence uses the actual two controllers and closed encoder with
inert deferred ports/clock only. The final file contains 25 tests (14 existing,
11 account-specific). Cumulative execution: 22 passed initially; one assertion
was corrected to compare the parser's deliberately null-prototype DATA object
by its properties, then that case passed; the added selected-account/mismatch
case also passed. After distinct review, the added terminal-before-older-poll
regression and the two affected original-list/Unknown cases passed (3/3). No
product parser was weakened for that fixture correction.
The cases cover complete/private malformed shapes, serial explicit reads,
no auto-selection/connect, original pending custody, full-list contradictions,
API/context/ABA and descriptor/listener reentrancy, Stop, unknown/lost replies,
explicit manual fallback and retained drafts. An exact original terminal now
overtakes earlier polling DATA without dropping those polling Promises or a
matching cleanup-Unknown; later complete-list contradictions still block. The
native result cell is acquired before consuming its witness, so contention with
the returning observer only defers the same retirement, not the source read or
close. Poison remains unknown.

```
/opt/node/current/bin/node --experimental-strip-types --test \
  --test-isolation=none --test-concurrency=1 desktop/tests/github-gh-entry.test.mjs
```

Actual integrated frontend source (Root `bdd39bdba333` plus these owned files)
passed TypeScript 5.9.3 using the existing dependencies. The first projection
missed seven public JSON catalogues; adding those unchanged source dependencies
resolved its only seven diagnostics. No source typing was weakened. Rustfmt
parsed the new leaves and projected native edits; **this is not Rust typecheck**.
Four new inert Rust parser/witness/request tests are defined, not executed here.
Existing prelaunch migration, native origin, HTTP identity and finality tests are
unchanged and remain Root's shared graph checks.

Root must still compose/compile/test the actual Rust/shipping graph, run genuine
Mac source/cancellation/cleanup and account/HTTP qualification, and review the
owner-facing UI. No native qualification, installer delivery, real account
authentication or production-ready claim follows from fake-port/TypeScript
checks. Existing activation flags remain off.
