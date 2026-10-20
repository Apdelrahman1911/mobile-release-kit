# Connect an existing shared version counter

This slice adds explicit **Review shared counter → Connect on this computer**
in GitHub’s Advanced section. Manual versions stay the default. It does not
create a branch/counter, reserve a version, change project files, enable CLI
reads, or establish Store/release readiness. No user-supplied genesis SHA is
required. A repository without the supported counter remains unsupported, with
manual-version guidance rather than a reset or an invented genesis.

## Actual path

1. The retained Desktop controller invokes one of four fixed raw commands:
   `version_enrollment_status`, `version_enrollment_review`,
   `version_enrollment_confirm`, `version_enrollment_cancel`. Requests are at
   most 8,192 bytes; only runtime project ID, native review ID or native operation
   ID is accepted. No token, path, authority, state bytes or floor is public input.
2. The original Document captures the registered root, saved-edit stamp, input
   epoch and actual selected ConnectionState account/repository/session pins.
   Its separate connection hold prevents token retirement/replacement while
   this operation is owned. GO rematches those originals under the real
   Document/Edit locks; aside from the existing one-shot GO claim it does not
   reenter Supervisor admission/resources, Host, Store or census while holding
   that gate. The existing native Setup-profile availability gate is
   reused, not broadened by a successful passive read or a renderer flag.
3. The SAME Supervisor uses a distinct typed enrollment arm of its existing
   installed Setup bootstrap, READY/GO writer, EOF reader, native Book and all
   child/IO/driver/watchdog/observer joins. The token is borrowed privately into
   the bounded GO buffer. There is no new subprocess, credential discovery,
   generic HTTP RPC or borrowed Setup approval. A reply is not finality.
4. The Python child uses the existing authenticated GitHub exchange and only
   fixed GET roles. A first review reads `/user`, repository, classic branch
   protection, fixed branch ref, commit-pinned ledger, then ref/protection/
   repository again. Confirm repeats the same review; if a local checkpoint
   exists, one bounded compare read also proves its commit ancestry. The full
   canonical Genesis and reservation chain are validated by the existing
   Python allocator, not reimplemented as Rust policy.
5. Only explicit Connect starts the existing grantless Host native-state path,
   using its fixed native app-data location, complete registered-root exclusion,
   same Store and genuine ProjectBinding. Actual preparation is outside Doc/Edit.
   A retained start-latched job acquires NativeUse and reads VersionAllocations;
   after the fresh HTTP observer actually joins, a second job performs the sole
   namespace CAS. The NativeUse stays retained through that last job and every
   original join. Neither a failed observer nor Drop supplies returned credit.

Human review holds no live child or NativeUse. Confirm consumes the original
review once; a fresh action receives a fresh work interval, not a renewed old
worker. Each action has a 60-second work bound and the Supervisor’s existing
2-second, contraction-only cleanup bound. STOP does not promise that an already
running filesystem syscall had no effect. Unknown startup, state writes,
descriptor closure or joins retain the original operation and block replay.
An IO error records its time in the original blocking job, before delayed
observation. Supervisor retirement also passes its actual retained cleanup
cutoff; later STOP/finish observations can only shorten it. Cleanup checks
surround original NativeUse retirement and final lane release. A late Store
return retains the actual token-retired result but makes the lane Unknown;
retirement is never replayed to obtain a new acknowledgement or time window.

## Authority and state limits

- Fixed branch: `mrk-version-allocations`.
- Fixed path: `release/.mrk-version-allocations-v1.json`.
- Classic protection must be readable and currently enforce administrators,
  disallow force pushes and disallow deletion. Ruleset-only or inaccessible
  protection is not silently treated as equivalent.
- At most 8/9 logical GETs, 10 actual wire attempts, 1 MiB aggregate HTTP body,
  256 KiB per response and a canonical ledger of at most 128 KiB / 64 rows.
- First connection anchors the **current** canonical genesis/full chain and
  checkpoint, including a nonzero sequence. It cannot detect erased history
  before enrollment or promise that branch protection will remain enabled.
- Existing authority, checkpoint, pending intent and selected candidates remain
  exact. A new local mapping never adopts another computer’s candidate or
  advances its retained checkpoint from mere observation. Reconnect still
  requires actual same-slot CAS, even if the bytes are identical. Concurrent
  revision changes refuse; there is no automatic reopen/retry, truncation,
  eviction, downgrade or reset.
- This enrollment path parses at most 256 KiB / 4,096 nodes / depth 20 using the
  SAME strict parser Seed. The full original native Snapshot is retained before
  refusal; the successor is checked before CAS too. Ordinary/recovery allocation
  state remains 1 MiB / 50,000 nodes. Oversized/overcomplex state gives explicit
  manual-version guidance without rewriting it; malformed small state remains
  a recovery refusal.
- The existing Document admission reserves 8 MiB of bounded native/control/state
  backing in its 16 MiB data partition, separately from the existing 128 MiB code
  partition. Byte and node limits cover retained state, canonical/typed copies
  and fixed job/request/reply backing. This is **not** a CPython heap/RSS or OS
  process-memory limit.

## Root integration packet

`version-enrollment-native-hooks-20261020.patch` has 18 fixed targets, refreshed
against Root `fa5ffac765b5000a24cb89b5ae4c4590952fd1b2` plus its Service25/ACL3
working hooks. The two composition conflicts only combined independent App
imports and retained the existing capability description before adding the
counter scope; no existing permission or owner was removed. Apply once,
together with the new modules:

- Python transport profile/roles and existing Setup-bootstrap dispatch.
- Supervisor typed arm and original installed Setup/EOF/settlement selectors;
  original ConnectionState hold, retirement and reciprocal admissions.
- Document state, pure Source/Git GO exclusions, native/credential/passive/quit
  gates and both existing memory censuses. Preserve all Apple/Tools/other owners.
- Fixed parser/port bound and enrollment child registration.
- The same enrollment protocol declaration in the existing installed-shell
  observer's manual module roster; this adds no observer permission or case.
- Four main-window RAW commands, build/capability registration and no event grant.
- Optional native-only Desktop port, retained controller/panel and reciprocal App
  admission. API reconnect/discard cannot drop an owned enrollment. Every
  workspace/account/repository intent retires UI review eligibility; native
  originals still govern admission. Check/Stop remain on the old original while
  promises are held. No mount read, polling, automatic grant or retry is added.

The earlier `version-enrollment-state-limit-20261020.patch` is only the separately
reviewed amendment artifact. Its changes are already included in the full patch;
**do not apply both**.

## Focused checks and remaining qualification

Author checks (synthetic/private DATA only):

- `test_version_enrollment.py`: 13 cases; current-chain review, immutable IDs,
  ref rewind/change, exact previous checkpoint/compare, malformed/capped ledger,
  private wire and control coherence. No HTTP/process execution.
- `test_version_enrollment_transport.py`: 5 cases against the projected actual
  shared transport/bootstrap hooks; closed roles/profile, bounds/cooldown and
  consuming descriptor cleanup including exceptions. All OS/HTTP calls mocked.
  Combined: **18 passed**, 0 skips.
- `desktop/tests/version-enrollment.test.mjs`: **15 passed**, 0 skips; exact
  descriptor-only parsing, explicit one-use review/confirm, original promises,
  immediate Stop, stale/context/account ABA, malformed/unknown, reentrancy and
  no automatic actions. No React/DOM or native execution.
- Five new Rust modules contain **17 tests**, including real private temporary
  Store CAS/preservation, parser complexity, original connection-hold and poison
  predicates, minimum native/job cutoffs, and real Store-mutex retirement with a
  late return. The latter tests check primitive/control behavior, not fabricated
  all-jobs receipts. **Unrun in this lane**; Root owns the combined graph/test batch.
- Rust syntax formatting, Python AST, JSON and Root patch apply-check are source
  checks only. They do not establish Mac linkage, installed-owner behavior,
  native filesystem qualification or authenticated GitHub behavior.

Automatic allocation remains separate and unavailable until its genuine
candidate/source/account/state admission and complete current Store floors are
connected. Existing Apple reads are scoped to a selected train/build, not all
trains; no accepted exhaustive Android app-bound floor owner is supplied here.
Enrollment is neither those observations nor distributed-allocation proof.
