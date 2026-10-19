# Selected-account gh: closed native integration handoff

This slice is **not activated or native-qualified**. The earlier Provider and
existing HTTP selected-login/immutable-ID binding compiled and passed Root's
11 synthetic Rust tests. New private worker tests do not authenticate an account.

## What is implemented

* A distinct `GitHubAuth` saved-command domain admits only an original fixed
  `--version`, then one local `auth token --hostname github.com --user LOGIN`.
  There is no account-status/list/network command, generic argv/env input,
  installation, auth switch/login/logout or implicit alternate account.
* The fixed bootstrap and Python worker use **unchanged `run_owned` → C/A/W**.
  Stock gh's keyring timeout can leave `/usr/bin/security` alive. Waiting for
  gh and its pipes is not enough; only actual original C/A/W cleanup can produce
  the private terminal. Unknown/missing terminal cannot be retried or consumed.
* Each capture has a 20s original work endpoint, 30s hard endpoint, and one
  at-most-15s command. Stdout/stderr are each bounded at8192 bytes; forwarded
  version≤1024/token≤4098. READY and terminal together≤8192; initial≤32768.
  Parent GO input stays held throughout work; any extra byte/EOF is STOP.
* The binary terminal is private and provisional. No raw stdout/stderr appears
  in events, errors, `ReadOutcome`, renderer DTOs or JSON. The new Rust reader's
  scratch and retained bytes are `Zeroizing` **from the first read**; its normal
  `ReadEnd` is empty except EOF/overflow facts. Python IPC/process memory is
  bounded but not claimed zeroized. Existing HTTP uses an ordinary private
  `String` after handoff; there is no end-to-end zeroization claim.
* `GhAuthSources` is a companion of the actual `SourceBook`: native real-user
  `Account`, original no-follow ancestry/file descriptors, native `SnapshotBook`
  ACL checks and exact metadata/hash PRE/POSTs. It accepts only explicitly
  selected physical `gh`, conventional native HOME/.config/gh, and both private
  regular config.yml/hosts.yml. No PATH/HOME/token/proxy/loader ambient discovery.
* `StockGhNomination` is separate from the patched **2.88.1-mrk-history.1**
  bundled History tool. Absent reviewed stock2.88.1 supplier/executable compile
  bindings means unavailable. Version text or matching an arbitrary supplied
  hash is not source admission. Homebrew symlink paths are not silently
  canonicalized into proof; this first source profile requires the physical
  selected binary. A later picker resolver must retain its actual alias originals.
* `NativeGhProvider` concretely consumes original Supervisor tickets through
  the existing Provider. Arm precedes admission; original ticket is retained
  before currentness checks. A nonsecret wait handle is awaited **outside**
  the Document mutex. Version then one token is a finite one-attempt sequence.
* `finish_prepared_connection` also runs **outside** the Document mutex. It
  consumes the original token into a private `PreparedGhConnection`, with no
  Clone/Debug/serde/token getter. Its original-owner callbacks may lock Document;
  they must not be invoked while that mutex is held. The prepared handoff is
  not admission authority: the same actual Document rematches its original
  registration and consent under lock before the existing HTTP admission.

## Exact Root-owned hooks (ordinary APIs unchanged)

1. Register crate modules `github_auth_capture_wire`, `github_auth_nomination`,
   `github_auth_native_owner`. In `asset_source_macos`, include/re-export
   `github_auth_sources_macos::GhAuthSources`; re-export on the Mac asset-source
   facade only. No shell/renderer/native mutation route is implied by a module.
2. Add distinct `runtime::GitHubAuthInstalledProfile`. Fixed selection is the
   original protected runtime's python/bin/python3, **github_auth_bootstrap.py**,
   core.zip and runtime root. Require existing actual Mac runtime binding and
   separately admitted stock nomination. Stage bootstrap through existing
   inventory/seal/build owner, not an ad-hoc installation or a new feature flag.
   Instantiate the existing macro:
   `slots!(GitHubAuthRuntimeSlots, GitHubAuthInstalledRuntime, runtime::GitHubAuthInstalledProfile)`;
   include `github_auth_runtime_macos.rs` after it. Existing macro inspection,
   prepare/claim, interrupted marking and one-attempt settlement remain unchanged.
3. Add **distinct original** `asset_session::GitHubAuthGoGate`, deriving from
   the actual current Document/project/client/session/explicit selected-login
   consent and retained sources, not a service/status/context DTO.
   Localized companion calls:
   `check_current(&Context) -> Result<(), BridgeError>` and
   `claim(id, request_sha256, &Context, Role, original_claim_closure) -> Result<Vec<u8>, BridgeError>`.
   The latter claims existing `claim_preflight_go` only for **Profile::GitHubAuth**
   and returns exactly the known request's GO. It must bind all context fields.
4. The original registration/work owner retains **the same `GhAuthSources`**
   through version, token and HTTP /user. A capture's runtime Book is per-call;
   do not close the selected-account/config originals at its child EOF. Own and
   join actual source inspections/POSTs before GO, after work and before HTTP
   handoff; rematch current full context after the joins. Native acquisition or
   ACL return loss is absorbing unknown; no mutex across a blocking call/await.
5. Include `supervisor_gh_auth.rs` as a private Supervisor child; re-export only
   `GitHubAuthTicket`, `GitHubAuthWait`, `GitHubAuthReceipt`. Add the fixed Profile
   and AdmissionRequest arm, per-operation mailbox, request, context, gate,
   endpoints and distinct native slots. Use existing registry/permit/driver/
   watchdog/observer, acquisition/child/wait/pipe/management tasks. Register all
   original work before starting it, as the existing admission path does.
6. Call `read_private` for **both** stdout and stderr, not passive read_bounded.
   It returns empty public `ReadEnd.bytes`. Feed READY to `write_private`; its
   POST request is performed/joined by the same driver's actual Resources;
   feed actual wait-return to its held-input release channel. Keep original
   failure endpoints monotonic with this module's Endpoints (max60s whole
   version+token invocation, not a new 30s budget after arbitrary delay).
7. After actual child wait and IO joins, require known exit/EOF/no overflow and
   invoke `Mailbox::decode_before_native_close` **before** any native consuming
   close. A missing/malformed/cleanup-unknown terminal => `owner.unknown`, retain
   original Resources, no new capture. Actual native/source POST and settlement
   joins still follow; only an empty unit marker may enter `ReadOutcome`.
8. `Owner.unknown` calls mailbox.unknown. **Only Owner.retire**, after actual
   driver/watchdog/observer/native/IO settlement, calls mailbox.retire. A private
   terminal or matched ref/identity never substitutes for retirement. Notify the
   same Owner.changed on final/unknown state so its nonsecret wait handle resolves.
9. Native session flow: construct `NativeGhProvider` from actual registered gate
   and context; `arm_version`→fixed Supervisor admission→`retain_original`;
   await returned wait handle outside mutex; recheck original scope/source joins
   and `finish_selection`. Repeat once with `arm_token`→same fixed flow→
   `finish_prepared_connection`, still **outside** the Document mutex. Keep the
   actual provider/source original in its registration; do not release that
   registration or infer retirement merely because a private handoff exists.
   Under the SAME actual Document lock, rematch the retained session identity,
   current native project registry/root/generation, selected login/account
   revision, explicit one-use consent and acknowledged source-work completion.
   Then call **ConnectionState.connect_prepared_gh** with that private handoff
   and the original current target. This helper repeats all target equality but
   performs no owner callback, await, native call or Document re-lock. It reuses
   `connect_selected` and the existing HTTP owner; no extra transport exists.
   The handoff or matching `Context` alone is never authority to call it.
   Existing HTTP /user must match selected login then pin immutable ID before
   Connected. Wrong project/repo/generation/login/identity never chooses another
   account or releases retry. Recheck and join the SAME source owner before
   accepting the HTTP result and before its final consuming close.

### Lock order and one-use handoff

`registered`, role arming, `retain_original`, `finish_selection` and
`finish_prepared_connection` can call the real gate: use them **outside** the
Document mutex. The outer registration retains their actual owner through all
awaits; no temporary `take()` may make in-flight work disappear from admission.
The final `connect_prepared_gh` is the inverse: the actual Document mutex and
original registration/consent stay borrowed throughout its non-awaiting HTTP
admission and original ticket installation. No native wait or source POST may
run under that mutex. A private handoff is consumed on mismatch, never cached
for another project/account or silently used with a different context.

The retained actual gate, not the wire `Context`, binds the Document session
identity, consent and source originals. The source and wire helpers deliberately
cannot create that authority. Central registration needs its own absorbing
pending/unknown admission latch before any original work is entered, including
source inspection; a dropped command reply cannot release it.

## Remaining delivery requirements

The genuine stock supplier nomination, protected staging/profile integration,
actual Document native gate, complete central Supervisor graph and original
source/currentness checks through HTTP need Root's integration/native review.
No source-only parser or synthetic terminal enables them. No real gh, keyring,
credentials, account/API calls, external Git operation or native signing was
used to test this work. Only explicitly owned synthetic temporary fixtures and
one actual unchanged C/A/W fixture with its own gh-shaped child/helper are used.

Focused evidence: `verification/gh-auth-worker-focused-20261019.log` records
21 Python tests passing, including the actual C/A/W fixture. Apple independently
ran the other 20 protocol/operation fixtures. New Rust tests are defined only
(including two prepared-handoff DATA checks); no Cargo/native execution of this
new slice has been performed by this lane. Root owns the integrated Rust batch.
