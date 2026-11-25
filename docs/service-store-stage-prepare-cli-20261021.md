# Later-stage Store preparation through the existing CLI owner

Base: `658d8cbd397d764dd668c4b1f83990d216ac874c`. This is an incremental
extension of the accepted Store7 preparation packet, not a new Store runner.

## Closed scope

Four additional selections use the **same LocalStorePrepare owner**:
`android-external-testing`, `ios-external-testing`,
`android-production-submit`, and `ios-production-submit`.
`Kind::candidate()` still means only the original two candidate preparations;
`prepares_intent()` additionally selects these four. Access/inventory never
becomes a preparation or an ordinary publishing grant.

The same `store-prepare` and `store-start` ID-only commands, four native bridge
commands, Store Inbox32, deadlines, READ facet, history publisher and native
retirement remain. CLI cannot supply paths, credential fields, an arbitrary
stage, a source override or a new predecessor. This does not extend Execute,
Reconcile, local-history delegation, or any provider/installed nomination.

## Selection, consent and original authority

* Old seven `Selection` encodings remain byte-identical. They omit `later`;
  explicitly present `later:null` is refused. New kinds require an exact typed
  stage/predecessor UUID/predecessor receipt SHA-256 tuple. Missing, partial,
  cross-kind and candidate/stage hybrids refuse.
* The actual current `LaterStage` native Context, saved source/version, original
  core journal and predecessor validation are reused. Displayed history is only
  comparison DATA. It does not establish an earlier native retirement. The
  existing production-stage rules may allow a newly saved metadata/config
  revision; no new equality to an old candidate commit is imposed here.
* Each new selection has a distinct one-use delegation Start consent. Native
  `c.consent()` is used only after exact selected kind/stage/context comparison.
  The GUI's ordinary Start retains its pre-retirement-tail linked-origin guard.
  A Prepared, a status event, a closed caller or a local journal row alone is not
  permission to run or proof of the original three-return finality.
* Native pins retain the original context/primary Weak identity plus exactly
  three optional `(RecordKey, Weak<Payload>)` slots. Old seven still use zero or
  the existing paired key slot. iOS later stages use original contact,
  commitment, and optional demo slots in their fixed order, with actual key,
  revision, payload kind and pointer checks. The existing saved demo policy,
  material/source/currentness checks and private input channel are unchanged.
  No secret values enter a service DTO or these new pins.
* The preview states selected stage, candidate and predecessor comparison,
  nonpublishing Prepare-not-Execute effects and the separate Start phase.
  Android Start may create/delete its original temporary Play edit, invalidate
  another edit, and retain unconfirmed cleanup. Neither platform gains upload,
  promotion, release submission or version-reservation authority.

## Result and custody

Only the same Saved original's actual retirement callback projects a new
`stage-prepare` report from its original decoded terminal. The core's six-frame
protocol, all four intermediate ACKs, context/commands/closure checks, source
proofs, and native cleanup are unchanged. The adapter rechecks the native UUID4
mapping and selected tuple before projecting its closed report. No ordinary
candidate report, query result or external status may substitute for it.

The report carries stage/platform, original stage operation UUID, head sequence,
candidate/predecessor IDs and hashes, intent/store-precondition hashes, fixed
destination and the original six limitations. It contains no credential,
account, source path, raw native Context or receipt authority. The pure service
protocol remains standalone installed-CLI-safe; its UUID comparison has a parity
regression against the actual native mapper, including UUID4 version/variant
bits. CLI JSON exposes the exact typed report; old command grammar is unchanged.

Entry attachment before publication, separate Prepare and Start caller returns,
history acknowledgement, monotone first failure, Stop and absorbing Unknown are
not modified. The renderer controller is unchanged; only its typed input/result
codec and closed App peer classification add the four kinds.

## Memory and integration boundaries

No cap, debit, pool or worker count changes. The full existing Store2MiB quote
still includes all32 retained rows/failed claims,8 worker terms,160KiB conversion,
128KiB native/grant backing and original GUI decode backing. New selection heap
adds one36-byte UUID and one64-byte hash. The maximum new report heap is
`3*36 + 4*64 + 400 + 9` bytes: three UUIDs, four hashes, a100-character UTF-8
Android channel and fixed status. Its six limitations are inline fixed enum
DATA. Actual-capacity guards remain enforced, not only string lengths.

The native fixed3 pin keys add at most `3*32` heap bytes inside the **same**
96KiB Doc +32KiB Saved subquotes of that128KiB, with all original material
descendants separately counted. Actual typed `Entry`/`Scope`/`Native`/public-copy
assertions extend the existing8KiB guards. The full32 mixed original/query/later
test retains the last failed history claim. LocalHistory3 is a separate sibling
packet; no memory slack is borrowed from it. Actual target-layout and composed
admission fit remain unrun and must pass the combined Root batch.

Nine owned implementation/test paths are staged separately from shared parents.
Apply `service-store-stage-prepare-cli-hooks-20261021.patch` once, contextually:

1. `desktop/src/App.tsx`: classify the new four as LocalStorePrepare peers, not
   Preflight, retaining the same original peer/currentness gates.
2. `desktop/src-tauri/src/installed_cli.rs`: add eleven-kind discovery and
   `stagePreparationIsExecution:false`; original four-kind submit facts stay.
3. `desktop/src-tauri/src/asset_session_store_material.rs`: extend only the
   existing real material DATA fixture to test fixed3 pins, same original versus
   a distinct actual payload Arc, and unchanged full loans/currentness.

Root owns composition with the concurrent LocalHistory3 and other App/catalogue
hooks. Do not overwrite shared files with whole after-images.

## Evidence and limitations

* 20 unique focused Node tests passed using the actual codecs and controllers,
  inert promises/DATA and existing nonroot cleared-environment route. First run
  was19PASS/1FAIL: the new fixture called a nonexistent `canStart`. A narrow
  rerun reached a strict comparison of cloned versus null-prototype DATA. Only
  those test assertions were corrected; the final affected test passed.
  Both failed projections/logs remain. Production code was not relaxed.
* One complete composed strict TypeScript `--noEmit` run passed, exit0,17s.
  Original caller joined. Success projection, exact dependency link and the
  public Node cache it generated were retired after exact rematch. Shared
  dependency cache was not changed.
* Eight Rust files parsed via `rustfmt --emit stdout`, with unchanged hashes.
  This is **not** Rust type checking or test execution.
* Six new and five extended Rust selectors are retained under
  `.task-store-stage-prepare/rust-{new,affected}-selectors.txt`. They exercise
  original decoder/UUID parity, exact-kind/null closure, unchanged32/failure
  retention, three-return/public-copy behavior, actual material pins and bounds.
  All are **UNRUN** by the author; Root runs the applicable combined graph.

No native process, Store/GitHub call, real Play edit, credential operation,
provider qualification, UI automation or shipping activation was executed or
claimed by this packet. Review pins and command/evidence records are in
`.task-store-stage-prepare/frozen.json` and `results/`.
