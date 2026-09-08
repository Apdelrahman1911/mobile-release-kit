# Zero-canary parser diagnostic prerequisite — plan R1

**PROPOSED; independent plan and distinct actual-code approval required before execution.**

SFIR-01 in `sandbox-implementation-review-r1/IMPLEMENTATION-REVIEW.md` rejects
generic nonzero/signal death as proof of actual invalid-profile compilation.
The approved primary plan needs a specific real diagnostic, not invented text.
This separate one-shot observation supplies raw native evidence for that oracle;
it is neither a primary matrix row nor a signal-fence or project verification pass.

## Exact scope and behavior

Only a new ignored diagnostic helper, private scratch and evidence may change.
No first-party source/index, AGENTS, runtime, Store, build, credential, keychain,
network, VM or user state is touched. There is no fallback and no retry.

Create one private owned temporary directory with these exact profile bytes:
`(version 1)\n(allow default\n`. Invoke the current pinned `/usr/bin/sandbox-exec`
with `-f <owned-invalid.sb>` followed by the existing pinned Python3.11 utility,
`-I -B -c 'import os; os.write(1,b"MRK_INVALID_PROFILE_REACHED_CHILD\\n")'`.
The child program, if unexpectedly reached, has no fork, signal, worker or
application code. Retain its actual sentinel if present; do not call it rejection.
Use only an explicit non-secret PATH/LANG/LC_ALL/HOME/TMPDIR environment and cwd.

## Ownership, failure and cleanup

The controller explicitly establishes normal waitable SIGCHLD and flag-only
INT/TERM handlers before acquisition, blocks no cancellation indefinitely, and
strongly retains its sole Popen handle. Start one private session. No thread,
detached/automatic reaper, wait-all, group signal or historical-PID authority.

One5s work cutoff covers acquisition and nonblocking pipe reads. Each stdout and
stderr prefix is capped at16KiB before retention; read chunks are at most4KiB.
Retain overflow/error diagnostics as incomplete raw capture, never complete data.
Both pipe EOF and the actual direct-child wait status are required. A normal
leader exit alone cannot establish EOF or any further process lifetime.

Timeout, overflow, read error or cancellation revokes work. Close known input;
within one additional2s disposal allowance, keep attempting the actual owned
wait independently of diagnostic read errors. A KILL is permitted only to the
positive PID of this controller's still-unreaped direct child after its actual
sole-waiter WNOHANG check returned0. No other waiter can release that reservation
before dispatch. Never signal a reaped/unknown child or any group/descendant.
Subprocess._active must be empty before acquisition; retain the handle through
all possible dispatch and record actual reap/returncode before release.

If the child cannot be joined or pipe/ownership state remains unknown, report
failure, retain inputs and do not launch anything else. Do not infer cleanup
from elapsed time, PID absence, destructor polling or sentinel output. Restore
signal policy only after owned cleanup; late cancellation cannot become success.

## Evidence and verification

Archive exact executable/profile/helper hashes, argv, allowlisted environment,
timestamps/deadlines, raw bounded stdout/stderr, flags, actual wait status and
ownership/descriptor disposition. Distinguish a successful observation operation
from any conclusion about parser rejection. Preserve source/index/AGENTS hashes.
Delete only exactly inventoried owned inputs after archival and actual cleanup;
retain evidence and uncertain state. No recursive shared/cache deletion.

Static syntax/actual-code review precedes execution. Only one acquisition and
one invocation are allowed. This independent diagnostic does not silently add
rows, retry or widen the primary32-row/65-acquisition/128-exec experiment. Its
actual stderr may inform a new explicitly reviewed oracle revision; until that
review, primary execution remains unauthorized. Full isolation, R6 acceptance,
complete gates, protected delivery and the fresh full audit all remain required.
