# Desktop-prepared image Apply: installed CLI delegation

This is an **Import Apply-only** extension of the original image editor. Desktop
still owns the native picker, file selection, Open, Prepare and full destination /
replacement preview. A collapsed Advanced control can allow one CLI request to
apply that exact review. It does not allow Choose, Prepare, ImageRecover, uploads,
new paths, image bytes, automatic approval or a headless editor.

Author base: `f6b8b885584e2706466b5fd55a9c260350f3b519`. Root-only hooks were
composed against `55489017562b4099c5fe011c1275a3354cde7875`. Apple's independent
plan acceptance covered the same Config32 pool and the later original-write
buffer-custody refinement. Root took over distinct implementation review after
Versions' service interruption.

## Use and closed interfaces

1. In the existing metadata image editor, choose files and prepare the local-copy
   preview. Review all destinations and replacements as before.
2. Under Advanced, explicitly acknowledge that review and choose **Allow this
   copy once**. This requires the genuine original Prepare invocation to return.
3. Use the displayed scalar command. The CLI publishes a request receipt before
   sending; the genuine main Webview alone can enter the existing Apply path.
4. Check or stop the same original if its outcome is unconfirmed. Do not resend.
   Revoke does not undo copies; native Close/recovery controls remain separate.

The four fixed installed commands are:

```
mrk metadata-images-scope PROJECT [--json]
mrk metadata-images-submit PROJECT INSTANCE GRANT --reviewed [--json]
mrk metadata-images-status PROJECT INSTANCE REQUEST [--json]
mrk metadata-images-cancel PROJECT INSTANCE REQUEST [--json]
```

MAIN has three fixed access/allow/revoke commands and the existing image Apply
command gains a closed original-request arm. The fixed approval is
`agent-exact-metadata-images-preview-v1`. Requests are at most 4 KiB; service
responses at most 8 KiB. Compact native-derived review DATA contains the original
IDs, platform/locale/type, create/replace/preserve counts, total selected bytes and
a streaming digest of the exact prepared view. It contains no source path, file
content, replacement choices, token or provider authority. The existing private
native 2 MiB image Status is never forwarded onto service IPC.

## Same originals, permission and finality

- `service_metadata_images_book.rs` extends the **existing** Configuration
  `SharedRow` / Book. Configuration, MetadataText, Images, unused image grants and
  revoke-before-Allow nonce tombstones share one non-evicted total32 and one
  occupied-original gate. Unsubmitted rows have no request origin: catalogue and
  exact Query do not invent one. Submitted old requests remain addressable.
- `edit_owner_service_metadata_images.rs` admits only the actual active Import
  Session, Reviewing/opened/prepared/claimed-sequence1, exact private submission,
  prepared view, source registration and original review deadline. Retained
  terminal DATA, recovery and foreign/missing native originals cannot mint a
  grant. Two Doc/source comparisons surround the real Service/READ lookup.
- The private link is installed before the original plan claim/send. CLI preclaim
  precedes the ordinary Apply publication and queue. An ordinary GUI Apply may
  atomically win only an unused grant; its later READ expiry/revoke cannot poison
  that GUI winner. A consumed/Unknown request cannot be regranted or replayed.
- The lease end is the minimum original native review end and same READ end.
  Existing watchdog/STOP tracks the earliest cause. This adds no renewed native,
  cleanup or consent clock.
- Only transient PreparedOriginal/Claim holds the original Session strongly.
  Book/history keep bounded metadata and weak/wake correlation, not image buffers
  or a replacement native runtime.
- Result publication requires actual native manager/driver/watchdog/IO/runtime
  retirement and accepted attribution, the same RAW invocation return, and the
  actual existing service-history write return. Core Terminal/EOF/displayed
  progress alone is insufficient. Missing retirement attribution or failed
  history fences the same original; no positive replacement receipt is created.
  Import effect uses actual `expected_success` / `terminal_admissible`, including
  the distinction between all-preserve Unchanged and copied Committed.
- The frontend permission facet belongs to `MetadataImagesController`. Actual
  pending calls survive terminal events and block API/listener replacement. It
  rematches the same immutable attempt/context/API/epoch after synchronous
  listeners, retains lost Allow/Apply/Revoke, and queries the exact old origin.
  Same-grant countdown DATA can only decrease; returned countdowns are anchored
  to the same actual call start, not delayed receipt time. The scheduled Apply
  rechecks the current same queued/noncancelled request and deadline immediately
  before invocation. No event or cold grant dispatches Apply before the original
  explicit Allow return.

## Buffer custody and complete accounting

The original picker limits remain ten files / 24 MiB and the private Open request
limit remains 33 MiB. `Session.image_written` starts at zero. The original writer
advances it only after a successful, scoped write future has returned and the tiny
private helper has consumed/dropped that exact Vec; the Release update follows
the drop. Admission requires the same Session's Acquire value exactly2. This is
only custody of its original Open+Prepare command buffers, **not** EOF, native
settlement, process exit or resource release. Failed/partial/STOP writes do not
advance it. There is no DTO/boolean proof constructor.

The borrowed image Edit census retains actual active/old-last private capacities,
submission/selection, two native Status copies, Session/link/control/queue costs,
the remaining third-frame Seed+typed decode even for malformed DATA, raw frame
growth and the actual Mac runtime's existing retained-bytes census. It does not
subtract another family's backing or the image payload based on child Prepared.
Opaque/non-Mac active runtime backing refuses this new delegation instead of
assuming zero; ordinary image controls and qualification flags are unchanged.

The image row fits the existing Configuration per-row reservation with a
compile-time size assertion; no second32 pool/reservation is added. The original
`service_ipc_response_memory.rs` donor adds this bounded route to the **same eight
workers' maximum**, not eight additional response reservations. Full Doc lookup +
installation + borrowed image Edit backing must fit the unchanged64 MiB at the
real Allow/Submit/Apply cuts. Compiled fit and active native qualification remain
unverified; the authored default/overbound tests are not pass evidence.

## Packet and integration

Fourteen owned paths: eight Rust leaves, two TS leaves, Advanced component, Node
test, this guide and `service-metadata-images-cli-hooks-20261021.patch`.
The latter contains exactly23 existing targets. Complete current/merged and
original author images, pins and evidence are retained under
`.task-metadata-images-cli/`. `service_ipc_response_memory.rs` is a **Root donor**,
not an owned new file on the older author base. Never replace it with oldbase
content. No App, Python, picker, runtime qualification or CI change is included.
The existing package test command receives the literal new Node test entry.

The refresh preserved Root's bounded-reader/memory/source additions. Its one
three-way conflict was the Configuration memory explanatory header: retain the
current same-eight-worker header and append only the image row-fit assertion.
The review successor refresh changes only three parents: package preserves both
new test entries; asset_session preserves Root's actual PreparedReply; installed
CLI preserves key-reuse capabilities. Other twenty after-images are unchanged.
Hook apply-check against actual55489017 passed; full source graph compilation is
Root's later integration responsibility.

## Author validation (no native execution)

All runs used existing dependencies, actual UID65534/networkless disposable public
projections and joined original callers. No installation, provider, native picker,
image copying, Cargo or UI automation was performed.

- **15 unique new Node cases pass**: initial11/12 plus the single corrected
  disposal/retained-listener case (258 ms), then three review regressions. The
  actual old source failed all three (delayed Allow/Check and post-publication
  dispatch). The narrow corrected run passed those three plus three affected
  cases, **6/6, 0 skipped, 298 ms**. All failures are preserved.
- **72 affected image cases pass**: initial64/72 plus eight corrected fixtures
  (345 ms) which now wait for their genuine deferred invocation returns instead
  of treating terminal events as caller receipts. Initial failures are retained.
- Initial whole composed frontend TypeScript passed, **18.075 s**. The review
  correction changes only the new permission controller/test; its focused Node
  evidence is above. Full TS was not repeated for this narrow correction. Other
  frontend code remains identical; package only retains Root's additional test.
- Eight own / sixteen shared Rust sources parsed only. **18 authored Rust tests
  are uncompiled and unrun**; exact selectors are in the task evidence. They cover
  closed codecs, shared32/tombstones, true three-return ordering, GUI winner,
  READ/STOP, native-original refusals, buffer-helper DATA, actual default/overbound
  Doc census and installed CLI scalar dispatch/receipt. They do not execute the
  real async writer/partial/STOP path, native image process or Mac runtime.
- All seven projections were hash-rematched and safely retired after joined
  callers; logs, tested affected sources, manifests and failures remain in
  `results/`. Shared dependencies were untouched; no task worker remains.

This is source/test evidence for an incremental facade, not a native availability,
memory-fit, installed CLI, image-copy success or Store-readiness claim.
