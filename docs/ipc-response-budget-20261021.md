# Existing IPC response backing: C

Source-only allocation correction, not native qualification or a quota increase.
Credentials independently reviewed the complete Service A / Apple B / IPC C
plan; Root authorized C and the narrow shared Version Apply/Prepare amendment.
Cleanup is the distinct actual reviewer. A and B are separate owned packets.

## Integration boundary

Author lane: `ipc-response-budget`, branch `task/ipc-response-budget-20261021`,
base `9a93a96a451dd693199f8c91c0363e2e833a64a9`. All shared edits are the
20-target `docs/ipc-response-budget-hooks-20261021.patch`, never replacements
of whole Root files. Version requests, new Prepare requests and the existing
Version request test preimages are from accepted Root
`f6b8b885584e2706466b5fd55a9c260350f3b519`; the other17 are unchanged9a93
preimages. Exact images/pins are under `.task-ipc-response-budget/parents`.

New leaves are children of existing roots:

* `service_ipc_response_memory.rs`: `application_service::ipc_response_memory`.
* `service_github_action_memory.rs`: `service_github_action_requests::memory`.
* `service_ipc_response_codec_tests.rs`: test-only child of `service_protocol`.

Thus lib, installed CLI and the separate installed observer retain their
existing root declarations; there is no fourth executor or new root module.
The `asset_session.rs` hunk changes only the catalogue debit to the common
pool and two comments. Compose additively with Project B's Apple traversal.

**Required A dependency:** Service's separately frozen compact-report after-images
export `STATUS_HEAP_BYTES=8192` on both `agent_local_checks` and
`agent_build_requests`. Their retained debits are851968 and688128. C covers
their public Local73728 and Build32768 worker terms once; A's851968 removed
worker copies must not be counted again as a C saving.

## Actual allocation change and unchanged lifetime

`service_protocol::encode_response` still calls the exact original
`validate_response` first. It then reuses Metadata's existing two-pass counted
writer for **every** outer response. The first pass bounds the full escaped
serialization before the one exact-capacity output allocation. The closed
immutable DTO, serde bytes, errors and256KiB frame cap are unchanged. Small
validators remain unchanged; their own growable buffers are still charged.
There is no `Value` conversion, JSON normalization or alternate decoder.

Only `installed_cli_ipc::CLIENTS` visibility changes. Its value remains8.
The original `run` admits through one `JoinSet.len()<8`, including finished but
unjoined tasks. `serve_exchange` drops raw bytes before dispatch; dispatch can
clone a parameter while the decoded request remains. Typed response, validator
scratch and encoded output are conservatively counted together. Metadata's
one original Endpoint lease is acquired before a large frame allocation or
any short Metadata dispatch; it remains outside the cancelled exchange future
until the same stream's explicit close path. Existing close uncertainty and
worker joins stay unchanged. No new semaphore, endpoint, clock or queue.

## Exact transferable terms

All numbers below are backing bytes, not RSS. `G` and all inline cells use the
actual compiled target sizes; no unexecuted `sizeof` result is asserted as fact.

| Existing owner | Removed worker term | Retained unchanged |
|---|---:|---|
| Git |8G; G=`128KiB +64*(1024+sizeof(String))+8192 +8192+4096` |all32 rows, both scope/draft copies|
| Version reserve |8*8192 |all32 rows,4*8192 scope/transition|
| Play cleanup / tag |8*8192 |all32 rows,4*8192 scope/transition|
| Upload key |8*13312 |all typed rows, unused scope, old/current native links|
| Version Apply |8*37888 |shared-row amendment below; all non-row scratch|
| Config |8*4096, **raw only** |entire `(32+18)` typed/GUI/native expression|
| Tool setup |8*21504 |all rows/native comparisons/current consent|
| Apple delegation |8*25600 |32*24KiB rows and128KiB relay/history|
| GitHub action pool |8*32768 |786432, derived below; all kinds share32|
| Catalogue |8C |no native/report payload was in this IPC-only route|
| Metadata |M0+8S |ROW, ACTIVE and complete original Endpoint/control debit|
| Version Open/Prepare |8*17408 |shared rows and its separate2*8192 off-IPC term|

The first eight old terms total2699264 on64-bit targets. Identity, Store,
repository-summary and Android-tools mixed quotes are **not extracted**.
In particular, the identity validator's larger scratch is not misrepresented
as a small transferred validator. All old/native/private/history/Store-reader
allocations remain; returning or retiring a worker does not credit a row.

## Checked mixed-eight formula

`R=sizeof(service_protocol::Request)`, `Q=sizeof(Response)`. Actual enum padding
is included, not approximated by the active variant.

```
C = 65536 +sizeof(Catalogue)+64
    +64*(sizeof(catalogue::Request)+96+sizeof(usize))
    +(352+32)*(sizeof(AdditionalRequest)+32)+1024
S = 196608+2R
M0 = 1613824
H = max(65536, 49152+4R+8Q+sizeof(ClientSession)+8192)
O_body = max(G,C,S,Projects,Operations,Local73728,Build32768,
             all other named transferred per-worker terms)
O = O_body+H
M = M0+S+H
pool = max(8O, M+7O)
```

The actual census refuses on arithmetic overflow, H>96KiB or a closed route
larger than G. It does not clamp a size, raise a limit, infer spare capacity or
reuse a returned object as permission. H charges four request cells, eight
complete response cells, the actual private ClientSession, small validator
old/new Vec growth (`3*16KiB`), and8KiB fixed handshake/serde-ID/borrowed-cell
scratch. Heap content is separate, never equated with `sizeof(Response)`.

The generic read bounds are source-derived and exercised by real codecs:

```
Projects =119808 +128*sizeof(ProjectObservation)
           +64*(96+2*sizeof(Platform)+20*sizeof(Requirement)+128)
Operations =65792 +512*sizeof(OperationObservation)+256*(64+128)
```

Two vector capacities cover old/new backing during growth. Project strings are
one32-byte ID and one64-byte digest, with at most2/20 closed enum entries;
operations have two32-byte IDs. Each borrowed validation BTreeSet gets128 bytes
per row. Generic producer data has no arbitrary names, root, free-text issues
or raw report. The encoded bounds include512 bytes of outer envelope and
maximum scalar widths. Catalogue keeps its complete64 detailed+352 additional
rows and one temporary32-ID list; families are enumerated sequentially.

For the pre-VersionPrepare IPC terms plus GitHub, if actual64-bit C>=96KiB and
H<=96KiB, saving is at least `2807296+14R`. VersionPrepare adds another139264
old IPC bytes replaced by the same O, not an extra worker. **This is not a
whole-current-Document fit result:** Version's retained increment, actual new
R/Q, Project B's cells and all other original debts must be included in Root's
one composed census. No stale pre-Version margin is claimed.

## Retained GitHub proof

Keep `32*16KiB +128KiB ancillary +128KiB unassigned slack =786432`.
The new private child computes the real `Entry` (including Mutex<Row>), Scope,
Claim, History, Status, Fact, ReadPermission and Arc/weak/watch/allocator cells.
Scope admission already bounds physical root8192/runtime128/ID64 and the
three Review allocations128/64/128; Submit IDs are reconstructed by the strict
Id constructor. The fixed operation is separately counted. The row quote
includes two genuine redacted projection/transition copies; it contains no
full native Prepared, token or private material. Ancillary includes the
actual Book/inbox/list, unused/current scope and Allow transition, GUI/history
scratch and fixed controls. Both actual row<=16KiB and ancillary<=128KiB are
checked before admitting a scope and by the common census. Old tombstones
remain charged. Existing physical-capacity and shared32 tests are retained.

## Version amendment: same actual Book, not two row pools

Accepted current code has exactly one `Book.rows: Vec<Retained>` with
`Apply(Arc<Entry>)` or `Preparation(Arc<PrepareEntry>)`. Both insertion methods
hold the same Book mutex and refuse len>=32 before constructing a new row;
there is no eviction or third insertion. Native Link/Call holds the same Arc;
Preparation↔Lease links are Weak. Therefore only the row term becomes:

```
32 * max(24576+sizeof(ApplyEntry),25600+sizeof(PrepareEntry))
```

The32*128 nonce/book term and **both**2*8192 off-IPC allowances remain summed.
Distinct old Apply leases stay in each row; the unsubmitted current lease stays
outside the max. In addition, C charges real new typed growth:

```
2*32*(sizeof(Retained)-sizeof(Arc<ApplyEntry>))
+33*(sizeof(OnceLock<Weak<PrepareEntry>>)+alignof(Lease))
```

The first term preserves old/new Vec allocation overlap; the second keeps all
32 old leases plus the unsubmitted lease and alignment. Two new DATA tests
derive the complete private Lease/Scope/Review/current-Book backing and every
mixed row distribution. The original30 retired Prepare+1 ready+1 Apply test
still enforces the actual32 boundary. The route-local19661824 preopen future
and its real default+1MiB payload+additional-debt test are unchanged, not a
new global Document allocation or a replacement for the old Apply future.

## Evidence and required execution

Authored **13 new Rust DATA/codec tests**, one changed existing GH census test;
exact names in `.task-ipc-response-budget/rust-new-selectors.txt` and affected
originals in `rust-affected-selectors.txt`. New tests exercise actual outer
encoding/validation/escaping/capacity, largest closed generic lists, full
Metadata text, unchanged refusal errors, typed growth/overflow, mixed8 and
retained/shared-row arithmetic. They create no Service, files, sockets, native
owner or receipt. The deliberately oversized optional-guidance DTO is labelled
producer-invalid DATA and checks the unchanged StateUnknown encoding failure.

All new Rust tests are **UNRUN**. Only three owned leaf formatting parses,
20 detached parent syntax parses and source whitespace/applicability checks
were performed; no Rust compiler, Cargo, native process, provider or network.
Two initial source-check driver errors (nested Git replay prefix and treating
`--no-index`'s difference exit as a whitespace failure) are retained in task
evidence; corrected source-only replay/checks passed, with no product execution.
The existing affected stalled-Metadata-frame test uses its original bounded
private Service/Store/socket fixture and is for Root's coordinated batch only.
Root must run the new tests, actual mixed32, original full-catalogue and
Metadata lease/encoder tests, the new Version preopen fit and the five prior
failed Document-fit methods in the complete A+B+C+Version image. Native
availability, memory containment and finality are not established by this note.
