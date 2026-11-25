# In-app GitHub device connection — source integration

Owned source base: `bfb7f9f9e923a90c92ed09779e3a044f0095c605`.
The accompanying `github-device-connect-hooks-20261021.patch` contains only
25 existing-file hooks, composed against actual Root `78c91de8` source. Exact
owned/before/after pins and test selectors are in `.task-github-connect/frozen.json`.
Keep current Play Cleanup, headless-history and complete-document census changes.

## What this implements, and what it does not verify

The existing selected GitHub CLI account and session-token routes stay preferred
and unchanged. The added panel requests an **app-owned, session-only GitHub
OAuth device grant**, without invoking `gh auth login`, changing its active
account/configuration/Keychain, or persisting the OAuth token. It uses the
existing Connection controller, native auth Entry/OriginalWork, Supervisor,
installed runtime Book and fixed TLS implementation. It adds no general runner,
callback server, OAuth refresh service, background poller or new workflow.

**External prerequisite is still missing:** an owner-controlled Mobile Release
Kit OAuth App registered on GitHub.com, with Device Flow enabled, and its genuine
public Client ID. No client secret is required or embedded. The compiled
`github_device_protocol::CLIENT_ID` is intentionally `None`; Start refuses
`device_unconfigured` before Document mutation/native admission. No other app's
ID or placeholder is treated as configured. Normal native/installed-source
requirements remain. Provider/SSO consent and live login are **unexecuted**.
Binding a real ID later is a deliberate publisher source change, not a renderer
or environment parameter and not evidence of successful authentication.

The first scope is exactly `repo`. The unchecked UI consent discloses private
repository **read and write** access; MRK's per-action consent is separate. No
`workflow`, admin, gist or organization scope is added. Workflow-file writes
may require another credential. Token scope strings are comparison DATA, never
an account or effective-permission receipt.

## Closed user flow and native custody

1. Explicit availability Status, then unchecked consent and **Get a code**.
   The same original captures Document/project/root/generation/repository and
   idle Connection epoch. No automatic command is sent on component mount.
2. One protected child POSTs `/login/device/code` at `github.com`. Its private
   code is retained only after real child/IO/source/native/management joins.
   Public DATA exposes only the bounded user code, fixed verification URL and
   conservative remaining/next-check seconds.
3. **Open GitHub** is the existing synchronous main-thread browser adapter's
   fixed `https://github.com/login/device` destination. No user code in URL,
   arbitrary link, clipboard write or visibility/approval receipt.
4. Each explicit **I've authorized — connect** sends one token POST to
   `/login/oauth/access_token`. `authorization_pending` and `slow_down` remain
   healthy continuations of the **same code and original**. Native minimum
   interval is five seconds/provider's greater value; slowdown adds five.
   Status does not poll, refresh expiry, authorize a replacement or retry HTTP.
5. A genuinely joined token moves once, privately, into the existing fresh
   `/user`/repository Connection operation. Only that original's joined result
   supplies account/repository/session facts. Neither OAuth progress nor a
   public Status DTO constructs Connected. The existing pending Connection
   latch waits all actual device invoke Promises, then the same original HTTP
   Status. Event/terminal-before-invoke-return, ABA/reentrant edits, foreign
   sessions and lost replies retain their original instead of reenabling Start.
6. Stop signals that original; Cancel after normal retirement returns only its
   exact historical result. Unknown remains sticky. Local cancellation,
   disconnect or closing the app **does not revoke** a GitHub grant/token.

Public commands are exactly `github_device_{status,start,check,open,cancel}`,
RAW at most1024 bytes, main window/local capability only. Existing installed
fixtures have no device-login grant. The native private framing is separate
from public serde/events/errors; device code/token is never argv/env/disk or a
public log. Python's immutable copies are not claimed to be end-to-end zeroized;
Rust private request/output storage uses the existing zeroizing containers.

## Finite lifetime and resource bounds

* One parent hard endpoint `H=Start+600s`, including cleanup. Work ends at
  `E=min(H-10s, original code-request admission+provider expiry)`.
* A poll needs at least24s before E. Each actual child uses the original10s work/
  12s hard profile; final HTTP admission needs12s and is absolutely bounded by E.
  A later normal Connection session TTL is separate and clamps any token expiry.
* First native/worker F sets the same parent cleanup to `min(F+10s,H)` once.
  Actual child first-F still has its earlier2s cleanup cap. This includes the
  first timeout detected inside the native close loop, not a delayed join time.
* At most120 explicit polls, one active call. No later poll while any previous
  runtime/IO/observer Book remains unjoined. Source POSTs and EOF/native closes
  precede private consume. Lost or failed close never becomes an empty receipt.
* Existing128MiB code plus16MiB non-code admission is unchanged. Each future
  uses actual fixed runtime reservation and complete retained Document census.
  The exact current no-source OriginalWork is traversed via the same deduplicating
  census, never dropped for credit. Active/unknown calls refuse later admission.
* Private request/response are16KiB each, token≤4096 ASCII bytes, device code≤1024,
  scopes≤32×64, provider code interval/expiry≤900. Invalid/duplicate/mixed fields
  refuse. A returned public slot's actual DATA is capped1536 bytes; at most
  Start+120 checked returns plus fixed slot/observer overhead fit the precharged
  256KiB Entry backing. These small late-shell returns do not retain runtime Books.

## Source/API integration

New Rust leaves: `github_device_protocol`, `github_device_native`,
`github_device_runtime_macos`, `supervisor_github_device`,
`asset_session_github_device`. The last is a child of existing `gh_auth`;
its only cross-parent census getter has exact asset-session visibility.

New Python leaves: fixed `desktop/github_device_bootstrap.py`,
`github_device_protocol.py`, `_desktop_github_device.py`. Current protected
runtime preparation/staging rosters include that bootstrap; no supplier or
workflow is changed here. Two closed unauthenticated POST roles extend the
same TLS/CA/framing/close owner, not the old read-only authority. Old transport
profiles, fixed origin, header rules, size limits and no-redirect behavior stay.

New frontend protocol/controller/component and actual-controller tests compose
into App/bridge and the existing Connection latch. The hook includes the exact
handler/build catalogue/local-main ACL rows and native fixed-browser kind.
Native modules are in both library and existing installed-observer declarations;
no CLI native graph or unsupported platform route is added.
The review successor adds only three `None` Device fields to the existing
passive-management Owner fixture and Device to its existing action-profile
refusal arm; it does not create a synthetic successful Device fixture.

## Focused evidence (not native/provider qualification)

* **49 unique Python cases pass** by retained results: `python-device-v4.log`
  has14 new device +34 passing affected transport cases and one inherited
  failure; the exact corrected case alone passes in
  `python-affected-corrected-v1.log` (0.001s). No double-count or broad rerun.
* The inherited case was reproduced unchanged at the old base in
  `python-affected-original-v1.log`. Production's original401 header control is
  `unauthorized`, so `_response_result` correctly returns null status/body before
  reading the sensitive body. The one test-only hook corrects its obsolete
  `401/none` expectation and explicitly asserts control.reason. Its
  `HeadersOnly.read1` trap and no-echo sentinel remain. No production transport
  change was made to satisfy that expectation.
* Actual device failure callback containment is separately fixed/tested: a
  failing first-F observer cannot skip the original response/connection closes;
  an unhandled private guard error records a closed reason before those closes.
  Both regressions are in the14 new device cases, with all IO/CA/TLS/clock faked.
* **72 Node cases pass** in `node-device-v2.log`:18 new +29 Connection +25
  selected-gh cases, actual composed controllers/bridge, all native ports inert.
* Whole current-Root+device TypeScript noEmit **PASS** (`typescript-v3.exit=0`),
  actual caller returned. Earlier failures remain retained. The task-only
  frontend projection uses the existing shared dependency tree, not an install.
* Five owned +13 shared Rust files syntax-parse only; **11 new Rust tests are
  UNCOMPILED/UNRUN**. Nine are portable DATA/in-memory IO; two existing-style
  no-native Document cases are Linux-x64 cfg only. Exact selectors are retained
  in `rust-selectors.txt`; no ignored/native/provider fixture is introduced.

Actual Rust/installed-CLI/macOS graphs, installed runtime/browser/C-A-W source
operations and genuine device-provider authorization remain Root's later work.
No qualification flag, credential persistence, supplier or shipping activation
has been changed. Distinct actual source review is required before integration.
