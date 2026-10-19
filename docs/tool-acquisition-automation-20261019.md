# Missing-only public tool staging — 2026-10-19

## Status and user-facing boundary

Implemented: the actual bounded cache/download/extraction service, projection of
the existing checked public supplier, and a staged-source picker presentation.
**Not enabled:** the original native acquisition/runtime/cache admission facet
and its fixed bootstrap are not wired. There is no new renderer or CLI download
endpoint, production fallback owner, automatic Start, or installation claim.
No real downloads, tool executions, installation, TLS qualification or hosted
dispatch were performed for this slice.

Call this **staged download, then choose source folders**, not automatic tool
installation. The existing native pickers, `SourceSlots` inspection, review,
explicit approval and protected-copy registration remain mandatory. A staged
path or `result.json` never constructs `SourceSnapshot` or an original picker
`Arc<OriginalWork>`. Native build/signing consumers still acquire their own
protected-tool leases. Neither planner nor downloader supplies a keytool lease.

The default UI should offer **Download required tools** only after the original
native owner has established that no compatible known installation can be
reused. Explain the search scope: registered copies, selected folders and the
declared supported/known locations. This is not proof of absence across the
whole computer. Always retain **Choose existing tools** for other locations.
Do not add unbounded filesystem scanning or run project Gradle wrappers.

## Implemented interfaces

### Same compiled supplier, no copied production pins

`android_supplier_macos::acquisition::for_profile(Profile) -> Option<Projection>`
reads only an **already warmed, already checked** catalogue. It neither warms
the cache nor performs IO. Call it outside short Registry/source/control locks.
The existing original startup may call `prepare_compiled_catalogue_for` as usual.

`Projection` contains private bootstrap bytes, exact reference SHA-256, the
SHA-256 of those **exact emitted bytes**, and the original typed profile. It has
no Deserialize/Clone or conversion to a source/tool/registration grant. Its
four archives and complete member/source-mode/parent mapping derive directly
from the checked `OfficialArchive`, `SourceMemberSpec` and `SourceBinding`
rosters: JDK, SDK platform, SDK build-tools, Gradle. App-signed aapt2/bundletool
are deliberately excluded. Unsupported profiles/aliases/source modes refuse.
No compatible dependency or signed profile was changed.

Python `decode_manifest(bytes) -> Manifest` checks the closed projection with
an 8 MiB input ceiling, exact four-component order, fixed public vendor URL
shapes, exact sizes/hashes, closed member kinds and bounded paths/counts/bytes.
The native owner must compare its exact projection digest before calling the
service; parsing DATA never admits a profile or supplies missing-tool facts.

### Actual staging service

`ToolAcquisition(original_owner).run() -> PreparedSources` is one-use. The
`NativeAcquisitionOwner` protocol is a **required original-native seam**, not an
implemented production owner and not a caller-provided callback endpoint:

| Required owner method | Meaning |
| --- | --- |
| `claim() -> Admission` | Consume the explicit current permit; refuse original active/unknown/recovery fences. |
| `checked_manifest() -> bytes` | Lend the same original compiled projection bound at claim. |
| `checkpoint()` | Recheck original context/generations, absolute deadline and cancellation. |
| `record_intent(bytes)` | Durably bind pending intent before new job creation/network; retain ambiguous publication. |
| `admit_cache_origin(operation, intent_sha256)` | Validate **original settled producer finality** and exact durable intent, not an on-disk result or filename. |
| `public_ca() -> bytes` | Borrow immutable admitted CA data under the new tokenless runtime role. |
| `retain_unknown(original_service)` | Retain original resource objects and native recovery fence. |

Its `cancellation` is the actual same-thread `DefaultCancellation` from the
fixed bootstrap. The service reuses `cancellation_owner`, `CleanupScope`, and
`build_inputs._Directory`, `_FD`, `_mkdir_private`. New bounded scandir and HTTP
objects are retained before acquisition and closed through one-attempt latches.
No existing unrelated `FiniteScratch` role is repurposed.

`Admission` binds operation ID, full original context digest, exact host/profile,
reference/projection digests, positive cache generation, admitted private cache
path **and original directory identity**, absolute deadline, and a complete
partition of required components into missing/compatible. The context digest
must cover project/session, saved-config/static-requirement fingerprints, exact
host and all original catalogue/source/registration/service/diagnostics
generations. These inputs come from native books, never renderer JSON.

All-compatible returns without opening the cache or borrowing CA data. Otherwise
the service rehashes matching settled cache archives before considering network.
A changed known archive is a conflict, not permission to overwrite/redownload it.
Reopening for extraction repeats original identity and complete SHA checks.
Only genuinely missing components are acquired. SDK staging may therefore
contain only one package: the result explicitly says it is **not a complete SDK**
and requires a complete existing SDK/manual assembly, not replacement of a
working SDK or another download of its compatible package.

`PreparedSources.to_data()` has no URLs/absolute paths/leases and sets native
finality, registration and build readiness to false. Return from Python remains
an offer until the original native parent accepts its real joins/final checks.

### Cache, disk and extraction

The native facet admits a preexisting private 0700 cache anchor and its exclusive
operation lease. Each attempt creates one exclusive `tool-<operation>/` directory
with `origin.json`, optional `<component>.archive`, `sources/`, and (only after
full reinspection) `result.json`. Existing jobs are never renamed, overwritten,
truncated, recursively deleted or chmod-ed. At most 32 job directories are
censused; exhaustion is explicit manual maintenance, not automatic eviction.
The native book must block unknown/pending producers **even if no target folder
exists**. Both JSON files are non-authoritative DATA. Failed/partial files remain
for review; successful child return cannot settle the parent book.

Limits: 256 MiB per compressed archive; 512 MiB per regular file; 1 GiB aggregate
expanded file bytes; 32,768 entries including declared parents; expanded file
bytes at most 8x compressed size. Before writes, free space must cover remaining
missing compressed data + expansion + 64 MiB metadata + a 2 GiB reserve. This
does not reserve future privileged-copy space; that existing service performs
its own admission. Free-space checks are repeated before writes.

ZIP uses the existing bounded `android_zip` central-directory policy and
`android_zip_integrity` local/CRC/deflate verifier on the same borrowed original
handle. The exact supplier roster is checked before decompression, then each
member is copied in <=64 KiB chunks to an exclusive output and hashed again.
No `extractall`, project scripts or external extractors are invoked.

JDK gzip uses zlib positive `max_length` only; tar receives a forward-only
bounded reader directly in uncompressed `r:` mode. Deliberately do not wrap it
in tarfile's streaming `_Stream`, which may aggregate an oversized GNU/PAX
metadata request before the inner read sees its bound. Metadata reads are
bounded before allocation. Gzip trailers/concatenation, sparse/device entries,
all links/hardlinks, extra/duplicate members, absolute/drive/dot/traversal paths,
NFC/case-fold collisions and unexpected modes refuse. The existing public
supplier has no source aliases. Its archived JDK setgid directory mode maps
only to the existing admitted source 0755 mode on newly created candidate paths.
These private-cache checks coordinate admitted operations and detect ordinary
changes; they are not protection from a compromised OS/unlocked same-user
process maliciously rewriting the namespace between system calls.

## Exact Root-owned wiring still required (no feature enable before this)

1. Add a distinct closed **ToolAcquisition** facet to the existing
   `saved_command_owner.rs` Domain/Context/Profile/Frame/Terminal sums. Reuse
   `prepare_bound`, `start_bound_checked`, cancellation/context-change/document-
   loss/shutdown and the existing `Resources` startup/child/pipes/decoder/driver/
   manager/final-join lifecycle. Do not reuse offline diagnostics' six-second
   permit or clone a second job owner. Suggested new work/hard profile: 1200s /
   1210s, preserving every existing domain limit.
2. Add the new role to `installed_runtime.rs::Purpose` and an operation-specific
   `ToolAcquisitionRuntimeSlots` around existing one-attempt
   `prepare_once_observed`/`claim_once` mechanics. Admit fixed installed Python,
   this reviewed Core, public CA and private cache roles. **No** account token,
   vault/signing material, arbitrary interpreter, PATH tool, project working
   directory or app-signed-tool replacement role is needed or allowed.
3. Bind original complete **declared-set** known-tool observations and current
   matching project policy before minting the one-use permit. No unresolved
   selected/known copy, partial census or stale cache/registration generation
   can become “missing”. Keep the existing choose/inspect/recovery manual path.
4. Implement the fixed bootstrap/control adapter behind the above Python owner
   seam. Extend only the closed `_desktop_saved_command_control.SavedCommandDomain`
   and exact `source_domain` type cases with its new `ToolAcquisitionInput`; use
   the existing saved-command cancellation slot in `DefaultCancellation`.
   Pass bounded original bootstrap data (manifest <=8 MiB + control <=16 KiB,
   admitted CA <=512 KiB) and capture output <=16 KiB. Use the same native
   `.env_clear()` child policy: no inherited proxy/auth/cookie/netrc/SSL-keylog
   variables; never clear the parent environment. No raw tracebacks/server
   headers/query strings or cache filenames become logs.
5. The native pending/cache book must retain original outcome/finality and exact
   intent before any Python side effect. After client restart, reconnect to that
   same owner; after lost owner/process custody, preserve UNKNOWN instead of
   reconstructing success from JSON or target absence. A positively settled
   failed attempt may later lend a complete archive only after original book
   validation + fresh full hash; never resume ranges or truncate its partials.
6. The renderer/CLI request supplies only project/action + expected observation
   and original permit/operation comparison fields. Do not expose `Admission`,
   manifest, URLs, hashes, missing lists, cache paths or arbitrary callbacks as
   execution inputs. Trigger **Download required tools** explicitly; refresh or
   rerun cannot renew consent. Existing registered/compatible tools win first.
7. After actual native success/currentness acceptance, wire the optional
   `EnvironmentDiagnostics.stagedTools` through `StagedToolSources` to the
   **existing** source-controller picker callbacks. Its mandatory presentation
   state is `settling`, `stale`, `recovery-required`, or `current-staged`; never
   derive `current-staged` from parsing the result or a Start response. Unknown,
   pending and stale presentations contain no continuation actions. No download
   button is included until original admission exists. Ordinary source selection
   must still create actual originals and re-inspect before protected copying.

The public transport is purpose-specific because the existing
`_github_connection_transport._make_live_exchange` is credential-bearing and
api.github.com-only. That transport was not generalized or relaxed. The new
`PublicVendorTransfer` creates no network resources on import/construction; at
copy it uses stdlib http.client with admitted CA bytes, TLS>=1.2, required
certificate/hostname validation, disabled key logging, fixed GET/identity
encoding/Connection-close and no auth/cookies/proxies/retries. Google has no
redirect. GitHub permits one HTTPS redirect to exact
`release-assets.githubusercontent.com/github-production-release-asset/...`,
never a wildcard/userinfo/non-443 host; its bounded service query is neither
logged nor returned. Exact Content-Length, complete SHA-256 and clean framing
are mandatory. Native parent containment/deadlines still own blocking DNS/TLS
and genuinely joined process cleanup; parser tests do not qualify live transport.

## Focused verification

Executed without network/process/tool installation:

```
PYTHONPATH=src python3 -B -m unittest discover -s tests/unit -p test_tool_acquisition.py -v
PYTHONPATH=src python3 -B -m unittest discover -s tests/unit -p test_tool_vendor_transport.py -v
/opt/node/current/bin/node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 \
  desktop/tests/tool-acquisition.test.mjs desktop/tests/tool-preparation.test.mjs desktop/tests/environment-diagnostics.test.mjs
```

21 acquisition tests pass: real descriptor-owned tiny synthetic extraction,
verified-cache zero requests/CA loans, compatible zero cache IO, missing-only
partial SDK, original status fences/restart/absent target, stale/unsupported/
partial admission, space, corruption/truncation/overrun, real malformed ZIP/tar
fixtures, deflate bomb, oversized PAX/GNU metadata, cancellation, source mutation,
and consumed-close/interruption with replacement FD survival. Four transport
DATA tests pass (no sockets/TLS); four new frontend tests plus existing29 pass.
Temporary inert fixture outputs are test-owned and removed; production source
and dependency caches are retained. These are not native/installer passes.

Root schedules compilation/typecheck and only the new native DATA filter:
`android_supplier_macos::acquisition::tests::` (3 tests, no process/network/IO),
`--test-threads=1`, not the historical supplier suite. The child declaration is
already in `android_supplier_macos.rs`; no new crate-root declaration is needed.
Actual installed owner/CA/cache/transport acceptance remains required before
enabling acquisition. Xcode companion packaging/native verification remains the
separate matching-source job described in `tool-preparation-automation-20261019.md`.
