# Optional allocation: original source-only/held-source slice

This source slice does **not** enable automatic allocation. Manual versions stay
the default. No remote write, native process, Git command or Store read has been
qualified by its synthetic tests.

## Actual Python owners

`version_allocation_source.AllocationSourceRun` is retained before opening the
project. The new `allocation-read` arm of **existing** `InvocationCustody` requires
the exact installed `BorrowedAllocationInput`, guard and run before environment
exclusion/root acquisition. It never materializes build/signing/Store inputs,
modifies the environment or calls `ensure_meta`. The original `_Project` checks
the full registered root identity before looking at private project inventories.

The fixed configuration and its selected version file are read with the existing
original `_Reader`, checked for exact size/hash, and actually closed. The existing
`LocalSourceObservation` then holds those files and Git controls continuously. It
accepts the explicitly selected `refs/heads/...` branch without inventing
`localStoreEnabled` or Store authority. The same existing `run_owned` / C-A-W owner
executes only its six fixed initial Git queries, at most one pre-PUT status and
one final status. Each command's **original** `_Outer`/outcome slot is bound before
any command acquisition; command counts or `CompletedProcess` data alone are not
finality. `/usr/bin/git` is the existing core path, **not** a newly established
native executable lease.

The source-only entry uses `mrk-version-allocation-source/1` and the original
bootstrap's duplicated private control/output descriptors. It has no token,
state slot, allocation request, build command or caller path callback. One exact
borrower occupies the existing cancellation slot; it never takes fd0, duplicates
or closes the bootstrap descriptors, or starts a second input cursor. During
GO/ACK, cancellation polling checks only the original clock/FD identities. Active
polling delegates EOF checks to the same `_Dialogue` cursor. A known cancellation
can end a settled borrow, but no borrowing flag is an `inputClosed` claim.

After actual source readers, project/environment and original C-A-W records have
settled, the borrower detaches and original signal handlers restore. Only then
can the source entry send FIN. The sequence is FIN -> original parent stdin-close
-> actual worker EOF -> bootstrap consuming closes -> native stdout EOF and all
original child/IO/runtime joins. `LocalSourceObservation.closed` is an attempted
close flag; the adapter also checks **each original reader's descriptor state**
and actual invocation/ledger closure. A failed close never grants a retry or FIN.

## Limits and allocation handoff

* Source INITIAL <=8,192 bytes; READY/GO <=512 each; FIN <=2,048. Original work
  deadline is at most 60 seconds and finality at most 70, never renewed.
* Configuration <=512 KiB and version file <=64 KiB. Full source topology uses
  the existing <=96 descriptor quote; preliminary readers close before it opens.
  Root is <=24 components; the selected version path <=512 UTF-8 bytes /16 parts.
* At most eight source commands, each <=10 seconds within the original work
  endpoint, with the unchanged C-A-W cleanup allowance. Existing Git output and
  tracked-entry bounds remain 2 MiB /32,768. These are finite input/capture bounds,
  **not** an OS RSS/opaque parser-heap or whole native-document census guarantee.

An allocating invocation must construct the same held run with its **full**
selected durable request and reacquire the original source. Hashes/ref alone do
not substitute for its exact commit/tree. The private `before_put(_Journal)` hook
requires the same dialogue and full request, a completed durable Pending ACK and
no pending state write; it spends its one recheck before status. It belongs
immediately before the existing sole ledger PUT, not before every HTTP exchange.
The final source check occurs after HTTP/state settlement. A failure retains the
pending/resolved reservation: it cannot recycle or bump the candidate.

The current runtime/1 GO has **not** gained a source input, and its HTTP wrapper
does **not yet** invoke this hook. The source-only bootstrap branch is supplied as
a separate Root composition patch. Neither it nor these Python modules authorize
a native allocation invocation; keep that route unavailable.

## Remaining genuine native hooks (not implemented by this slice)

The source-only native arm must retain the same `DocumentBinding`/`Inner`, returned
`SavedObservationLane` Arc, `SavedComparisonData`, `SavedEditStamp`, input epoch,
registration and actual registered root. Initial admission, GO, Pending ACK and
final source acceptance re-match those originals under short pure Doc/Edit gates.
All Host/service mapping, state read/CAS/fsync and account IO remain **outside**
those locks. Only the real Supervisor's original completion/joins can publish
source DATA; that DATA is not a continuing source lease for a later allocation.

Allocation requires a distinct original Connection session/account/repository
nomination and consent, retaining its admitted credential Instant/expiry/cooldown
and original Supervisor resources. Do not relabel Setup/History/read consent,
start a dormant Host, regrant CLI reads, infer an enrollment, or renew a clock.
Protected fixed-ledger enrollment and genuine app-bound exhaustive Store floors
are still unavailable gates. Existing Android tracks/bundles and Apple
selected-train/build queries do not establish complete allocation floors.

The authentic `RELEASE_VERSION` checkout/prepare/preview/Apply handoff remains a
separate explicit action using `prepare_reserved_version_edit`; source DATA or a
reservation must never become unbound manual autofill. A final clean source after
the explicit version edit/commit is separate from the retained pre-edit request.

## Focused checks

`PYTHONPATH=src python3 -B -m unittest discover -s tests/unit -p test_version_allocation_source.py`

18 synthetic cases use task-owned temporary input files, the real fixed readers,
invocation scopes, command admission and pre-IO original slot binding. Git output,
C-A-W outcomes, private descriptors and native state ACKs are explicitly fake.
They cover wrong roots before private reads; saved hash/path and full selected
commit drift; no build/signing/metadata permissions; seven/eight-call schedules;
Pending ACK ordering; post-PUT failure preserving pending state; GO/ACK/EOF cursor
ordering; no borrowed pipe close; and a real file close return-loss injection
after the source's close flag is set. They do not exercise native jobs, real Git,
HTTP, Store state, installed runtime availability or remote durability.
