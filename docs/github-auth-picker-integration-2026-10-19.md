# Selected-account gh: native user entry

This slice extends the reviewed original gh owner, not its trust policy. It is
source work, **not installed Mac/provider/keyring/HTTP qualification**. No gh,
account, private configuration, keyring, network, Cargo or native UI was used
for this slice's validation. Earlier original-capture evidence is not a test of
the new picker. All existing native availability/profile flags remain required.

## Three closed commands

All three new commands require **RAW UTF-8 JSON bytes**, e.g.
`new TextEncoder().encode(JSON.stringify(body))`. JSON-object invoke bodies are
refused. The production decoder applies its 1024-byte envelope bound and
strict duplicate-key rejection before constructing a command. Existing PAT
and connection commands keep their original encoding.

`github_auth_status {}` and `github_auth_cancel {operationId}` return:

```ts
type AuthStatus = {
  schemaVersion: 1;
  documentRevision: number; connectionRevision: number;
  available: boolean;
  operationId: string | null; projectId: string | null;
  repository: string | null; selectedLogin: string | null;
  phase: 'idle' | 'picking' | 'running' | 'checking-identity' | 'stopping'
       | 'settled' | 'failed' | 'cleanup-unknown';
  reason: GitHubConnectionReason;
  http: null | {sessionId: string; operationId: string};
};
```

`github_auth_connect` accepts exactly `projectId`, `repository`,
`selectedLogin`, `expectedDocumentRevision`, `expectedConnectionRevision`.
Revisions are nonzero, non-exhausted u32 admission comparisons. No path, token,
environment, command, provider, role, source hash or capability is accepted.
The new protocol rejects other keys before copying bounded scalar inputs.

Its invoke observes a native-retained original and returns exactly one of:

```ts
{schemaVersion: 1, operationId: string, outcome: 'http-handoff',
 connection: GitHubConnectionStatus}
{schemaVersion: 1, operationId: string, outcome: 'no-http', auth: AuthStatus}
{schemaVersion: 1, operationId: string, outcome: 'unknown', auth: AuthStatus}
```

Only a genuine same-Document HTTP admission provides `http-handoff`; its
ConnectionStatus may still be checking. The existing HTTP protocol exclusively
owns `/user` login matching, immutable account-ID pinning and Connected.
`settled` in AuthStatus means original custody, never authentication. `no-http`
requires an actual positively joined refusal and no HTTP claim; uncertain claim,
lost scope, missing receipt or incomplete cleanup cannot grant a retry.
Ordinary closed pre-admission errors can occur before creating any original.

The existing connection controller must latch Connect before invoking this
entry. AuthStatus alone cannot clear that latch or become Connected. The exact
original handoff IDs let status correlate its existing connection event; they
are non-authoritative DATA. A late invoke returns its original historical
ConnectionStatus, not another current connection. Ignore it if a newer
connection/session/target is already known; do not regress status. The two
AuthStatus revisions are not progress ordering: native phases can advance
without a Document revision change. Poll serially; no new event/relay is added.
Cancellation has no stale-revision precondition and reaches only its exact
retained native operation.

## Original owner and privacy

Connect synchronously retains the explicit request, original Document/session
identity, project root/generation and idle connection epoch. The SAME
OriginalWork owns a distinct fixed native file picker followed by source
inspection, guarded `--version`, one selected local token read and the existing
HTTP handoff. Picker dispatch is never rfd/compatibility/History/credential-file
authority. A one-file physical `gh` selection remains private bounded path
DATA; unchanged SourceBook decides whether it is the nominated provider.

The account is an explicit bounded user-entered login, unverified until `/user`.
There is no account inventory, auth-status network probe, PATH lookup, switch,
migration, download, implicit install or substitution for the selected account.
The currently admitted stock version/profile may not accept another install or
symlink; refusal does not disable source/config/keyring checks. The pre-launch
schema-one guard from the prior slice remains mandatory before **any** gh run.
PAT connection remains unchanged.

The existing original GUI loop retains construction/poll/close/release
dispatches and joins. Only that actual known GUI return plus a fresh same-Doc
rematch can fill the private path cell. Unknown dispatch never becomes
not-created. Parent hooks compare the retained gh original before locking
GuiFacts, route earliest native refusal to it, and never re-lock Document or
GuiFacts from the hook. Presentation/acceptance does not clear or renew gh's
original 60-second whole-operation ceiling, which includes the picker.

The Connect observer holds only a Weak Document and a bounded one-use result
DATA slot. The slot contains no Registration, OriginalWork, SourceBook,
NativeContext, HTTPWait or runtime backreference. Same-Doc admission records
the actual historical handoff before unlocking; retirement records known
no-HTTP before replacing Entry. A slow/dropped observer cannot retain a retired
runtime after the Document releases its working debit. Native work remains in
the existing original Entry/coordinator/HTTP hold regardless of invoke lifetime.

Admission explicitly adds 256 KiB for the new fixed panel/control/input/path,
public handoff snapshot and serialization overlap. One selected path is bounded
to 4096 bytes; no public path or raw credential is returned, logged or stored.
Existing raw capture/HTTP token privacy is unchanged; this is not a new claim
of end-to-end zeroization.

## Integration (Root only)

Own source paths:

- `desktop/src-tauri/src/github_auth_entry_protocol.rs` (new pure protocol)
- `desktop/src-tauri/src/asset_session_gh_auth.rs` (same original owner)

Apply `github-auth-picker-integration-2026-10-19.patch` to these eight Root-owned
paths only, after the previously accepted central gh graph/parent hooks:

1. `asset_session.rs`: exact GUI response/refusal hooks; all existing purposes
   and guards remain unchanged.
2. `shell.rs`: the three fixed main-window commands/handler entries and one
   distinct Mac DialogChoice.
3. `shell_macos_dialog.rs`: one fixed mapping, no caller initial path, one pure
   routing test; unchanged original GUI custody loop.
4. `desktop/native/macos-installed-native/src/lib.rs`: distinct PanelKind 17.
5. The native crate's `src/native.m`: fixed title, single file, no directories,
   alias resolution or multiple selections; existing start/poll/close/release.
6. Main `lib.rs`: only the new entry protocol declaration.
7. `build.rs`: the three exact AppManifest command entries.
8. `capabilities/main.json`: only the corresponding three main-window command
   permissions; no filesystem/shell/network or wildcard permissions.

`verification/gh-auth-picker-patch-20261019.json` records exact before/after
hashes. The parent base includes the prerequisite
`github-auth-document-integration-current-2026-10-19.patch`; do not reapply
that prerequisite if Root already integrated it. The earlier graph also needs
its existing `github_auth_capture_wire`, `github_auth_nomination` and
`github_auth_native_owner` declarations; the picker patch does not duplicate
them. Root owns actual bridge/renderer wiring and integrated builds.

The artifact uses empty (unprefixed) blank context lines accepted by Git to
avoid whitespace-only tracked patch lines. Apply-check and exact produced
contents are checked on disposable source copies, not by editing Root.

## Focused evidence and limits

Thirteen new Rust tests are defined: four closed decoder cases, eight original
child DATA/observer/receipt cases and one **Mac-only** fixed panel routing case.
The first twelve belong to the core Rust batch; Linux cannot run the Mac panel
test. They cover
no path/token/role input, bad revisions/login, STOP reachability, no-HTTP proof,
late exact one-use handoff, wrong target/non-Connect rejection, lost Document,
observer non-retention, path bounds, GUI receipt requirements and fixed errors.
These are **not executed until Root's scheduled Rust batch**. The GUI/receipt
fixtures are explicitly DATA, never native qualification. Source parsing and
patch checks do not substitute for those tests or installed Mac evaluation.

Root still must compile the combined graph/commands/native panel, run the
focused tests, and qualify actual installed source/runtime/config/keyring,
native picker cancellation/joins and existing HTTP account matching. This
slice does not enable flags, infer account authentication or claim delivery.

Distinct source review caught the initially omitted AppManifest/permission
rows and that the first strict-byte helper was test-only while handlers used
already-parsed JSON Values. Both were corrected in the final patch: all three
handlers use the production RAW helper, and all three generated command
permissions are explicit. No existing PAT route was changed.
