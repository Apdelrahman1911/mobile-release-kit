# Windows installed-runtime native facts

Private target-only boundary for native `x86_64-pc-windows-msvc`, Rust 1.88,
`windows-sys = 0.61.2`. This is **not** a complete installed-runtime adapter,
capability, QualifiedRuntime, command builder, or process-creation API. Nothing
here enables the Windows profile, public snapshot, Save, COM, or UI integration.

## Caller contract

The existing original Resources owner must register the non-cloneable NativeBook
before releasing its retained blocking worker. Serialize that book under the same
owner's Mutex. Keep the actual book, borrowers, and joins reachable through STOP,
document loss, deadlines, interrupted returns, and settlement. Do not call this
synchronous boundary on a UI/deadline thread, replace its owner, or create another
book to bypass unresolved work. This crate supplies no worker, timer, mutex,
launcher, global registry, or cancellation-by-drop mechanism.

Original keys are non-cloneable, same-book references, not handle owners. Native
HANDLE outputs are written directly into pinned registered slots. All call inputs,
IOSB/count outputs, and buffers belong to a registered pinned arena before entry.
Pending, lost, or contradictory completion retains the exact arena and originals;
never free, read pending output, retry, reopen, or infer absence from a timeout.
Drop performs **no native close** and conservatively preserves unresolved storage.
A leak is memory-safety fallback, not evidence of owner reachability or settlement.

Close retires a known original before its single attempt. A returned close failure
is absorbing Unknown; only other independent known originals can still retire.
Parents cannot close before live/uncertain children. Settlement needs actual
NoHandle/Closed records **and the later owner's original worker/consumer joins**;
NativeBook::settled alone cannot prove the latter. Call mark_interrupted only after
the actual worker returns, never merely because its deadline expired.

## Facts, not admission authority

Observe the current ordinary native token context before OS-location discovery.
Only precise FALSE/ERROR_NO_TOKEN/NULL proves no calling-thread impersonation.
The primary token remains its same original; later rechecks do not create a
permanent context lease or authorize a different executor to impersonate it.
Trusted groups must be deny-only; unapproved privileges are refused even disabled.
Do not export/log account, token, or security facts to a renderer.

Discover Program Files/Windows/System through the selected OS APIs, then inspect
actual original ancestors. Canonical volume/child paths get one acquisition attempt
per book, including definite failures and already-closed originals. Reuse the same
volume original when multiple OS locations share it; no alias/reopen fallback.
The future sealed walk, not renderer input, chooses AuthorityScope and supplies
parent/child full-ID matches, normalized long-name checks, full inventory/digest,
immutable protected-version boundary, and final identity/security/context rechecks.
An ancestor allowing unrelated sibling creation is not permission to mutate or
replace the selected child. Unsupported ACEs or facts refuse; a completed authority
refusal is distinct from unknown native completion requiring retained custody.

Budgets: 48 live originals (including tokens), 8256 records, 2048 file-original
attempts, 8192 enumerated entries, 512 MiB/file, 1 GiB/read book, and 64 KiB/call. At an exact byte limit, at most one
excess byte is observed only to distinguish EOF and is never accepted; exceeding
the global limit prevents further reads on every original. One over-limit directory
batch refuses the whole enumeration budget. Failed cursor/decoder operations are
terminal for that original. No seek, cursor restart, pathname/file-ID reopen, resize,
or acquisition retry is offered.

Still absent: Windows Resources/one-use launch integration, compiled anchors/full
immutable manifest walk, privileged NTFS publication and MSI lifecycle policy,
complete loaded-image/import custody, new shared-core ZIP/manifest, COM/STA and
WebView2 originals, explicit six-method transfer, and installed-app verification.
The production Windows gates must stay closed until those independent joins pass.

## Verification status

This source packet was authored and inspected as DATA only: **not compiled or run**.
The nine inert state/decoder contract definitions remain unchanged. They never
invoke the native dispatcher. In particular, stream decoding is not ReadFile or
directory-EOF transition coverage. A separate ignored hosted_tests contract now
observes the actual native context and either exact elevated-primary refusal or,
only after genuine admission, bounded OS-derived volume-root facts. Its explicit
counts distinguish unexecuted positive cases from observed facts. It does not
qualify pending completion, loaded DLL custody, or the production original owner.
The fixed Windows hosted scope compiles the standalone three-package graph with
Rust 1.98.0; it is not a full app build, proof of the declared 1.88 minimum, runtime
wiring or authorization to run native checks on a shared development host.

The standalone Cargo.lock is a SOURCE-assembled complete graph using the already
locked windows-sys/windows-link packages, not an unreviewed resolution. Future
separately authorized focused compilation must keep that graph locked and target
native AMD64 Windows; a zero-test non-Windows build is not Windows evidence.
