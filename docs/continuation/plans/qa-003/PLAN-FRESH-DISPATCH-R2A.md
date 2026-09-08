# QA-003 fresh verification — exclusive dispatch-log ownership correction

## Reanalysis

The distinct actual-preparation reviewer identified a defect in the new ignored
`QA-003-final-r2/run-once.sh`, not in the product or the seven frozen helpers.
Its exclusive log redirection is inside the conditional runner invocation. Two
cooperating launchers can pass the absence checks; the loser can fail redirection
without executing Python, then publish its own non-run error as `final-run.exit`
before the winner finishes. A log-permission error has the same attribution gap.
This fails closed but does not bind the recorded exit to the intended invocation.
No actual fresh gate has run. Independent shadow reproduction is in progress.

## Planned correction

Preserve the original wrapper verbatim as `run-once.r1.sh`. Change only the active
wrapper's descriptor handoff:

1. Keep `set -euo pipefail`, `noclobber`, exact cwd, and absent-output checks.
2. Claim the log using standalone `exec 9> LOG` **outside** any conditional. A
   failed exclusive open terminates the shell before runner dispatch or exit-file
   writing. This exclusive log also elects one owner among simultaneous launchers.
3. Run the exact original Python/runner command and TMPDIR with
   `>&9 2>&1 9>&-`: stdout/stderr reference the claimed log; the extra raw
   descriptor is not inherited by the runner. Save its real status as before.
4. Close the shell's descriptor, then exclusively persist that owner's status.
   An unexpected exit-file write failure is still a failure; no overwrite/retry.

Bind old/new wrapper hashes, original preparation/plan approval and this amendment
in a separate correction record. Do not alter the original preparation producer,
canonical owner marker, copied freeze/helpers, old failed evidence/installation,
production/test/docs files, approved58 commands, output paths or deadlines.

## Compatibility, security and failure behavior

The shell remains bash with the same toolchain/environment; no umask, native,
Store, credential, package, source identity or recovery policy changes. No Store
mutation is introduced. Descriptor acquisition failure never reports a runner
exit. A loser does not stop the winning process, delete its output or retry.
Controller loss or later write failure still cannot invent successful completion.
The fresh full run remains authorized only once after actual-implementation
approval. Preserve the earlier real EEXIST FAIL and unknown root cause.

## Verification and regression risks

Independent reviewer-owned shadow paths and a bounded fake runner must verify:
normal exit0; actual nonzero; preexisting output refusal; failed log acquisition
without runner/exit creation; two simultaneous launchers with exactly one runner
and correctly bound winning status; no inherited extra fd9; unchanged actual
58-command evaluation, copy/source/owner bindings and initially absent results.
No shadow result is a production gate or replacement for all58 real commands.
Terminate/reap only owned shadow workers and remove only their disposable files.
Then obtain distinct approval of the actual corrected wrapper before real gates.
