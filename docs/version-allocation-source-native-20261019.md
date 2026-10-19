# Native saved-source read (SOURCE only)

This slice adds a real, closed read to the existing Supervisor and Document.
It does **not** enable version allocation, enroll a repository, obtain an account
or Store floor, change a version, or provide a continuing checkout lease. Manual
version editing is unchanged. No native execution or qualification was performed
for this packet.

## Existing owners, not a second runner

`DocumentBinding::observe_version_allocation_source(project_id, reference)` takes
only a registered runtime project ID and a `refs/heads/` reference. The actual
returned `SavedObservationLane`, original `SavedEditStamp`, control epoch, full
registered root and bounded saved config/version comparison supply all other
inputs. It does not accept renderer paths, hashes, native snapshots or callbacks.
Unsupported/unbound input refuses before source inspection.

The source lane is installed under the same Doc/Edit admission through the
existing Supervisor registration. It retains its ticket and entire reservation
through the actual final observer join. Only then may it keep bounded comparison
DATA instead. A cancelled/failed/late observer wait retains Unknown; it cannot
poll the original join again, drop the ticket for capacity, or enable a new read.

The common `gh_auth::FinalObserverReturn::new/join_original` methods are reused
solely for the actual `Owner.observer` join. The patch changes their visibility
only. The GitHub-specific `receipt()` stays private and unchanged; no credential,
GitHub ticket or account result is borrowed.

The distinct installed profile fixes the existing required
`github_setup_bootstrap.py` to its already-reviewed
`mrk-version-allocation-source/1` dispatch. It uses its own `slots!` instance and
a **separate** original `GitReadSources` instance. It does not borrow Setup or
GitRead admission. That facet's fixed CLT Git, account, complete ancestry,
control-file identity/hash and native closes are required. The legacy local
source default remains `/usr/bin/git`; SOURCE uses only `macos-clt-git/1`.

## Original lifecycle and locks

* One admitted 60-second work / 70-second hard interval and one captured native
  `ClockBridge`; neither source refusal nor retry renews it.
* Existing registered inspection and acquisition retain both original sets.
  Source/account/file IO and both native POST jobs run outside Doc/Edit. A POST
  start latch is released only after its actual join handle is stored in the same
  `Resources`. Lost joins stay retained, never repolled.
* Initial → READY → actual BeforeGo POST/join → short original Doc/Edit/claim
  check → actual GO write → one FIN → stdin shutdown/drop → worker EOF → stdout
  EOF. There is one stdout cursor, no prefetch beyond READY, and no FIN read before
  the actual GO-written signal. This is not `read_preflight` or its EOF schedule.
* The GO check uses only the original lane/request/root/stamp/epoch and the fixed
  Supervisor claim. It does not call general busy/census helpers that re-enter
  Resources while the driver waits for its writer. `matches_epoch` is the existing
  short ControlSlot metadata-book check, **not** an atomic-only API or state IO.
* Actual writer/stdout/stderr and child joins precede AfterWork POST/join and
  consuming native close. Missing/extra/bad FIN, nonzero exit, failed IO or unknown
  source cleanup cannot stand in for nested C/A/W settlement.
* A clean refusal FIN is accepted only with `source:null`, its finite exact
  lifetime, and the original raw first failure. That FIN initially contracts the
  cleanup endpoint without STOP. Only after child/IO and AfterWork return is the
  same mapped failure folded into ordinary `fail_at`, before native close. The
  work cutoff can still veto a late refusal; there is no promised extra grace.
* Native completion runs only in actual `Owner::retire`, outside its registry/
  state/Resources locks. It checks saved currentness again. FIN is not completion.
  Source Unknown itself latches the retained lane and notifies; it does not call
  ControlSlot host-retirement methods while holding Doc.

## Finite backing, not a process-memory claim

The admission invokes the existing same-Document retained census plus its
existing additional saved-lane/evidence/maintenance census **before** EditGuard.
It uses `macos_history_inventory::admission_bytes(D,F)`: the original non-code
allowance stays **16 MiB**, and the installed code/control allowance stays its
separate **128 MiB**. No other domain budget increases.

`VersionAllocationSourceAdmission::reservation_bytes()` charges the actual
target `sizeof` values, not a renderer estimate:

* `VersionAllocationSourceRuntimeSlots::working_reservation_bytes()` checks
  `code_storage_bytes(sizeof(Record), SNAPSHOT_FRAME_BYTES)`, reserves the existing
  full code partition, its actual slot and 128 KiB runtime metadata backing.
* The same `GitReadSources::working_bytes()` charges its original descriptor
  capacity, source cells, path/stream backing and native snapshot frame. The
  actual facet enforces `source_capacity + runtime_live + 32 <= 256` before IO.
* Fixed native/framing terms include Initial × 6, FIN × 5, READY/GO × 4, 256
  bounded JSON cells with key/node allowance, seven Python tool-reader cells,
  two 32 KiB stream buffers, the actual Owner/Resources/Invocation/Mailbox cells,
  and 32 KiB for the finite task/one-shot/control captures. The fixed byte terms
  total 163,328 before the JSON and actual target-sized cells.
* The exact original input capacities and retained Doc lane/completion are added
  before admission. The containing debit remains charged until the original
  observer returns; a smaller FIN never releases it early. Other existing
  censuses count the retained lane, including after it becomes bounded DATA.

These are native/control and explicit framing debits, **not a CPython heap,
allocator or OS RSS bound**. Python retains its existing bounded source readers,
2 MiB Git-output/index limits, 32,768 tracked-entry cap and C/A/W limits. SOURCE
keeps the stricter HEAD 1 KiB, required index 2 MiB, source reader count 96,
Initial 8,192 bytes and seven-command success schedule. The native facet's larger
generic HEAD/index/tool limits never widen these SOURCE limits. There is no
hidden `git --version` call or borrowed GitRead version proof.

## Root composition

Apply `version-allocation-source-native-hooks-20261019.patch` with the two new
children. It was composed against integration `12616a1a` without modifying that
worktree. It wires the closed profiles/slots, original IO and native settlement,
the saved-input projection, reciprocal native admission/copy gates, existing
censuses, accepted-stop paths and exit predicate. The extra test-fixture fields
are `None` only; they do not construct positive native custody.

**Dependency:** integrate the independently reviewed Git packet's
`git_read_protocol::Native`, `asset_source::GitReadSources` and actual CLT ancestry
hardening. Preserve both profiles and both peer gates when composing concurrent
Supervisor/Doc changes. The existing required Setup bootstrap row already covers
SOURCE; do not substitute the new GitRead bootstrap. Add GitRead-pending to SOURCE
admission/GO if the composed pure base does not already enforce that peer, and
Source-pending to GitRead admission/GO. Neither gate may borrow the other's ticket.

There is intentionally no new shell command, renderer availability flag or
allocation route in this packet. A future allocating call must reacquire this
actual source, keep it held through its sole PUT, recheck after durable Pending
ACK immediately before PUT, then check again before publication. Genuine account,
protected shared ledger enrollment, exhaustive current Store floors and authentic
RELEASE_VERSION preview/apply admission remain separate prerequisites.

## Focused checks and limits

Nine Rust tests are defined for strict canonical frames, branch/path inputs,
success-veto/current-source binding, exact refusal/F, no stdout prefetch, actual
GO-written ordering over in-memory duplex pipes, FIN-not-completion, original
cutoff/profile isolation, and real empty-Document admission refusal. They perform
no project/native/process/network work. They were **not run** here; Root owns the
shared Cargo batch. Rustfmt syntax parsing of both children and the projected
shared hooks is only a syntax check.

The accepted Python SOURCE tests remain 36 passing (synthetic held-file/control
fixtures, no Git/native/network execution); unchanged tests were not rerun for
this native packet. No Mac launch, keyring, signing, GH, Store or release operation
was performed or qualified.
