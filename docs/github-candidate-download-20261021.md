# Canonical candidate primary download

Source packet based on `8f4c0206cfddb3d4ce2800a46055633a92188463`.
Versions independently accepted plan `32678d4044fbdac24a99690a5962885f29ed51117cb9828963e9b753ad867d75`;
Root authorized implementation. This packet has no native/provider qualification
claim and changes no availability flag, workflow, service, CLI or Store action.

## Delivered path

The existing History panel can explicitly download a verified **candidate** AAB
or IPA through the same History controller, main-window command, Connection,
Supervisor, managed provider, verifier and native source owner. Download freshly
verifies the selected evidence; a displayed History result is not permission.

`github_history_download_primary` accepts only the existing session, two
revisions and selection plus
`consentVersion: "github-candidate-primary-download-v1", confirmed: true`.
Selection must be candidate/Android or candidate/iOS. No path, URL, token,
artifact name, expected digest, account override or replacement option is input.
The native project registration is the destination authority. Ordinary History
and hosted handoff behavior retain their old absent-field/canonical forms.

The only final destination is:

```
release/downloads/candidate-<runId>-attempt-<attempt>-<platform>/
  app-release.aab OR app.ipa
  download-receipt.json
```

The pending sibling is `.candidate-<runId>-attempt-<attempt>-<platform>.pending`.
Both names must initially be absent. Existing final/pending output is refused,
not adopted, overwritten, suffixed, inferred successful or automatically retried.
The receipt is bounded historical provenance, not Store or release authority.
Arbitrary Actions artifacts, GitHub Releases assets, symbols/archives, Save As,
other release stages, automatic import/open/rebuild and CLI export are excluded.

## Same original and publication

* `github_candidate_download.py` is a facet of the real `HistoryOperation`.
  Actual `Verifier.final(allow_current=False)` must return the same retained
  candidate intent and verified proof. The handoff comes from that intent's
  `authorizedBy.runId`, with exact artifact identity/head/size/digest. The
  existing bounded ZIP reader and full flat handoff/checksum validation run
  before the original primary attestation. No Resolver or alternate downloader.
* `HistorySources` retains four extra originals: downloads parent, pending
  directory, primary and receipt. First-use `downloads` is exclusively created
  under the held release parent, prearmed, checked 0700, fsynced and POST-checked.
  An EEXIST race is not adoption. An initially existing private parent is checked
  independently. There is no mkdir-all, chown or permission widening.
* Python opens exactly the captured originals through its existing FD ledger,
  writes bounded blocks, handles short writes, syncs and checks them. Native-owned
  output is not added to Python's temporary deletion roster. Original before/after
  account/repository checks, source POST and ordinary scratch cleanup remain.
* A decoded terminal is only DATA. `download_return_data` additionally requires
  the genuine original successful wait, writer, both readers/EOFs, returned
  handles, empty stderr, complete lifetime and no prior failure before arming the
  retained source facet. Missing/invalid/failed returns cannot arm publication.
* Publication runs once in the **existing registered native_settlement** job,
  before consuming source closes. The already-spent pre-GO history_post job is
  not reused; no new post-success task is created. Same held files are hashed,
  their bounded receipt checked, synced and POST-checked. Same-parent
  `RENAME_EXCL` publishes the directory, then parent sync and source POST follow.
* The original work endpoint, no first failure/STOP, and current exact
  Doc/Edit/Connection/ticket are checked before publication. Cleanup permission
  never authorizes rename. Source/runtime closes, actual native_return and final
  Connection acceptance remain independent necessary cuts. No timer reset.
* Minimal publication/durability phases and fixed relative names live on the
  retained nomination/operation outside the success-only Result. Unknown,
  context loss, revoke and failed close preserve diagnostic DATA; they never
  restore Result, permission, finality or retry. A positive rename with uncertain
  durability remains distinguishable from no rename. Leftovers need manual
  inspection; this slice implements no recovery engine or rollback.

The controller uses the same Work/pending/Cancel/monitor. Checkbox consent binds
the actual private selection epoch, including away-and-back changes. It latches
before synchronous listeners and rechecks original context/API/peer afterward.
An old read response cannot satisfy a download and vice versa. A lost call stays
fenced. Only a genuinely settled verified download is labelled exported.

## Bounds and source inclusion

Existing limits remain: 900/910-second History bounds, first-F+10 cleanup,
120-second child limit, 128 commands, 19 attestations, four downloads/4 GiB total,
1 GiB ZIP/expanded body, 128 Python FDs, 192 combined descriptors, 56 parent/source
slots, 32768 retained IO originals and 4096 created entries. The candidate
schedule uses at most three downloads/four attestations; existing counters may
refuse earlier. Four native source slots and four Python slots are added within,
not beyond, those limits.

Scratch remains 5 GiB. Destination needs 1 GiB + 1 MiB; a common filesystem must
have the **sum**, not the maximum. This free-space check is not a disk reservation.
Primary is at most 1 GiB and receipt at most 4096 bytes. Receipt uses the existing
bounded Seed (128 nodes/depth 6) before allocation. Download-only control debit
is 360448 bytes: two 64 KiB stream blocks, 128 KiB parser backing, one additional
64 KiB retained reply and 32 KiB complete fixed state/pins/trace/path/receipt
overlap. Actual state/capacity checks still apply; this is not a new quota or a
per-family IPC debit. Existing whole-owner admission can refuse insufficient
capacity; numerical native fit has not been measured by this author.

New Rust modules are children of existing History protocol/source modules, not
new crate roots. The existing runtime packaging includes the new Python leaf
with the ordinary held `src/mobile_release` roster. No additional bootstrap,
helper executable, signing route or observer module declaration is needed.

## Exact packet and Root integration

Seven new source/test leaves plus this guide and
`github-candidate-download-hooks-20261021.patch` are the owned packet. The patch
has 21 existing targets; before/after images are in
`.task-candidate-download/parents/{before,after}` and pins/roster in
`.task-candidate-download/frozen.json`. Root applies **hunks**, never replaces
current shared files with old-base after-images.

* Python: workflow handoff adapter; History worker, private protocol and engine.
* Native: History protocol/session/Connection/source/runtime; existing
  Supervisor/history driver/settlement, Document gate and main-window shell.
* Declarative admission: the exact command in the existing build AppManifest
  and `allow-github-history-download-primary` in the **MAIN-only** capability.
  Other windows, scope, remote permissions and commands remain unchanged.
* Frontend: History types/parser/controller/bridge/panel and package test entry.

No changes to Root files were made by this author. The original 19 projections
retain their exact 8f4 preimages; the two declarative additions capture actual
Root 21c preimages. The frontend validation projection applies the same
delta to **actual Root 21cbb9f958b8513b997d4e6aa4c3b8efda7944ee**, preserving
integrated Image/KeyReuse and public API data prerequisites.
All 20 non-package targets apply to that Root. The package default test command
needs only the additive candidate test entry while retaining the newer Image/
KeyReuse entries. An exact current-compatible 21-target patch and that one
before/after package pair are retained in task results for Root composition.

## Evidence and limits of evidence

All logs, original failures, source hashes and literal selectors are retained
in `.task-candidate-download/`; no results were rerun just for freezing.
Root found that the first freeze omitted the build/capability declarations;
the narrow successor adds only those two declarative rows. Their fixed command
membership and unchanged MAIN-only scope were checked directly, with JSON parse
and Rust source parsing. This does not rerun or extend the earlier runtime-test
claims; the original freeze is preserved in task evidence.

* **28 distinct Python PASS**: 13 new, seven unchanged History, eight existing ZIP
  cases. Initial 26 passed in 5.413s; two new actual-run/terminal regressions
  passed in 2.122s. Actual verifier/layout/ZIP/owned small-file writes and cleanup
  are exercised with inert provider signatures/responses. The initial failed
  fixture run is retained: free-space DATA and a missing fixture budget argument
  were corrected, not product limits. These are not native or signature proofs.
* **12 Node PASS** in 0.336s: nine new + three existing History. They cover closed
  input/diagnostics, actual bridge/controller calls, stale/reentrant consent,
  mode substitution, lost call, Unknown and retained Cancel/listener custody.
* **Composed noEmit TS PASS**, 19.789s, actual Root 21c + candidate delta. Original
  caller joined, minimum available RAM 8076922880 bytes, no floor stop. Existing
  dependencies only; own link/projection removed after return.
* Python/Node ran as UID 65534 with bounded outer time, FD/file/heap limits and
  explicit process/network refusal. No gh, Git, provider, native or installation
  operation ran. Original callers joined before disposable projection cleanup.
* Rust source parsing/format checks only. **11 new Rust tests UNRUN**: eight
  protocol/diagnostic/receipt DATA, one real driver-return predicate and two Mac
  SourceBook/output-identity DATA tests. They construct no native receipt. Two
  existing History protocol tests and the existing Mac original-History DATA
  aggregate are materially affected and listed separately.

Required after independent actual review: Root composition and real compiler/
focused Rust graph, then separately authorized installed/native source,
original-return/STOP, first-use parent, no-replace publication and cleanup
qualification. No native rename, protected provider/account/TLS/attestation or
installed journey is claimed here. Existing availability gates stay unchanged.
