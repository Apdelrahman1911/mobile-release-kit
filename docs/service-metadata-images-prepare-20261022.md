# Image selection inspection and Prepare through the installed CLI

Source packet based on `324ada874bb5ef3213c60ea339e31590d8e45b8e`.
Independent base plan: Cleanup `ecb0a2c4`; immutable-profile amendment `e88d8efb`.
Root authorized implementation. This guide records author evidence, not native qualification.

## User route and deliberately remaining boundaries

1. In the existing image editor, expand Advanced and enable **CLI preparation for the next selection** before Choose. Use the original native picker/Open. Default is off. A live ordinary selection cannot be retrofitted; it is preserved, not closed or automatically reselected.
2. With the same project's ordinary READ permission, run `mrk metadata-images-read PROJECT INSTANCE REQUEST --json`. The main window inspects only the actual, pristine, opened Import after its original calls have returned. Until then this is queued DATA, not an image/source handle.
3. From the returned Editing observation, submit `mrk metadata-images-prepare PROJECT INSTANCE REQUEST --stdin --json`. The closed JSON is `{ "observationRevision": <returned revision>, "openedSha256": <returned digest>, "choices": [{ "itemId": <original ID>, "replaceExisting": false }] }`. Supply exactly every selected item, in its original order. Only a native-approved replacement may be true.
4. Review the existing complete Desktop preview, explicitly authorize the separate one-use Apply, then use the existing `metadata-images-submit`. Preparation never copies files or grants Apply. The ordinary GUI may instead win the same explicit Apply.

Existing `metadata-images-status`/`cancel` route by the exact stored kind and original IDs. Exact duplicate Read/Prepare observes the same row; changed input or unknown custody cannot rearm it. CLI capabilities disclose native selection/Open, the smaller profile and separate Apply. No paths, image bodies, destination names, baseline values, picker, recovery, headless filesystem access or Store upload are added. Recovery stays Desktop-led. Hashes and public item IDs are comparison DATA, not source authority.

The reply is bounded to8KiB (observation6KiB), with at most10 original item IDs, safe basenames, selected byte/hash summaries, before hash and replacement eligibility. Large native inventories may exceed this explicitly smaller profile: use the ordinary editor, not truncation or an invalid-image claim.

## Exact owner and lifetime integration

- New Read/Prepare children reuse the original Configuration Book, Service READ/alias checks, main-Webview relay, registered project and image `EditOwner`. There is no additional native owner, transport, task, namespace or writer.
- Read retains only a weak identity of the actual Session. It cannot STOP the GUI. Native inspection requires pristine Import/Editing, exact checkout/source/context, original Open write-buffer return (`image_written == 1`) and its live deadline.
- Native Registry admission atomically claims the exact preparation row and installs the same Session link before publication. Both ordinary and delegated Prepare repeat origin exclusion before publisher/error tails. A GUI winner makes a losing CLI call refuse without stopping that GUI original.
- Native creates the actual old Prepare request from the captured checkout/baseline and complete bounded choices. The controller atomically updates only its matching pristine draft and retains the actual API Promise. Prepared DATA, native events or `prepare()`'s boolean do not replace that caller return.
- The same original native Prepared/writer-return/private chain plus returned caller exposes Reviewing/Pending. The existing full preview and separate Apply approval are unchanged. Both lease install and Submit allow only the exact predecessor/private-review/original-READ association to coexist.
- Preparation and Apply occupy **two real rows** under the same shared32, including all unused nonce tombstones. Capacity failure before transfer leaves the predecessor cancellable. Actual Apply preclaim transfers only the predecessor's cancellation control to the specific successor or ordinary GUI; old callbacks/revocation cannot STOP the winner. CLI successor retains its own original READ/earliest-F control.
- No clocks are renewed: original phase30s/review15min, first-F8–10s, same watchdog and100ms known-cleanup sampling. Poison is absorbing. Pending callers, unknown/native retirement and history joins stay retained. Renderer deadlines use original Open/inspection/Prepare Work starts, not reply arrival; coalesced events query the exact old request before a genuinely fresh latest one.

## Immutable reader profile and complete accounting

The strict optional Open boolean is captured before Choose and copied into the Import ticket/Session before registration or any reader byte. Missing=false; nonboolean/recovery/other-domain shapes refuse. The same original Seed/parser uses128KiB whole frames,4096nodes,depth24 from first byte, including the **pre-growth** limit. It persists even if ordinary GUI wins Apply. Default GUI/recovery limits remain512KiB/20k/depth32. There is no late reader-mode switch, parser fallback, quiescence assumption or old-buffer credit.

The profiled Editing future is **17,170,432 fixed bytes**:
`5*4096*512 + 10*128KiB + 2*64KiB + 2*2MiB + 1MiB`, plus actual ABI/wrappers. This includes the remaining Prepared/terminal/Seed/typed/queue/status work. Borrowed current/last/private projection trees, actual native runtime/source backing, full Document plus installation/additional census remain additive under unchanged64MiB. The original33MiB Open buffer is excluded only after its actual successful writer future and owned Vec consuming return, not child Prepared/EOF.

The new typed row fits the existing Config slot through a compile-time size assertion and explicit retained-observation capacity check. Its53,248-byte IPC body term participates in the **same eight-worker maximum**, not eight more workers. No quota rise, discarded history or credential/source credit. Existing default-Document/real-capacity test now checks both old Apply and new Editing quote; active non-Mac opaque runtime still refuses. **Compiled current-layout64MiB fit remains unverified.**

## Frozen layout / integration

Eleven owned source/test leaves:
- Seven Rust children: `service_metadata_images_prepare_{protocol,requests,book,application}.rs`, `edit_owner_service_metadata_images_prepare.rs`, `asset_session_service_metadata_images_prepare.rs`, `installed_cli_metadata_images_prepare.rs`.
- Frontend: `serviceMetadataImagesPrepareProtocol.ts`, `serviceMetadataImagesPrepareController.ts`, `components/AgentMetadataImagesPreparation.tsx`.
- Existing-controller test: `desktop/tests/service-metadata-images-prepare.test.mjs`.

This guide plus `service-metadata-images-prepare-hooks-20261022.patch` make13 staged paths. The33 changed existing parents are **unstaged test copies only**, represented by the detached hook; complete before/after images and pins are under `.task-metadata-images-prepare/hooks`. Roots include lib, installed CLI and manual observer; all three new MAIN calls are in shell invoke/AppManifest/capability. No worker/core Python or native picker code changed.

At current Root532,31 hook targets apply literally; `desktop/package.json` and `installed_cli_ipc.rs` require only additive context unions with the intervening accepted Root changes. Do not whole-file overwrite those parents. Root owns integration; donor source is not a replacement for unrelated Root532 features.

## Actual checks and limitations

All frontend callers used the existing bounded process owner, an owned public projection, UID65534/networkless environment and existing readonly dependencies. Source hashes were rematched after actual joins and only those projections/links removed.

- New actual-controller suite: **9PASS/0fail/0skip**, `results/node-v3.log`.
- Existing image editor/Apply controller suites: **87PASS/0fail/0skip**, `results/node-affected.log`. Total96 distinct methods.
- Whole composed frontend noEmit: **PASS**,20.529s, `results/typescript-v2.log`/`-return.json`; explicit array-presence guards, no casts. Package later adds only the test-list literal.
- Rustfmt syntax-only:31 changed Rust sources, `results/rust-syntax.json`; no Rust compile/test execution.
-15 new Rust selectors and11 meaningfully affected existing selectors: `results/rust-selectors-{new,affected}.txt`, exact source/cfg/effect map `rust-selector-source.json`. All are **UNCOMPILED/UNRUN for this packet**; constructors are unentered DATA/capacity fixtures, not fabricated source/Session/loan/join evidence. They cover same32 both association cuts, original caller/READ/transfer/poison, actual strict decoder10-file profile, CLI grammar/variant, and existing real whole-Doc fit. Deduplicate affected selectors already queued by Root.

Preserved failed evidence: Node-v1 could not strip a TypeScript parameter property; changed to explicit fields. Node-v2 (5pass/4fail) and one diagnostic exposed the real Editing deadline not initialized until the old Prepared branch; fixed only profiled Open to use its original caller start. Node-v3 then passed. TypeScript-v1 returned10 noUncheckedIndexedAccess diagnostics; fixed explicit row/item presence guards and v2 passed. Initial failures, caller/projection/return manifests remain in the task folder; no evidence was replaced with a claimed pass.

Actual-review correction: Tools found that repeated Unknown/STOP observations could wake the original watchdog continuously. The successor makes revision/Notify publication transition-only: first Unknown, and first/earlier STOP (also while Unknown). One added actual Entry test creates/pins the original Notified before control queries, polls with an inert waker and checks both watch revisions and Ready/Pending; no runtime or fake native receipt. Repeated samples are inert, earlier F still updates, and original end/retirement custody stays unchanged. This test is authored/unrun. Original13/33 freeze is preserved in `.task-metadata-images-prepare/review-v1`; unchanged96Node/TS evidence is reused.

No native picker/import/Apply/Store/provider execution, Cargo, full application build, installed qualification or CI run was performed by this author. Native/macOS layout and actual same-original IO/finality remain Root's targeted batch obligations. Independent actual review and Root commit/integration approval are still required.
