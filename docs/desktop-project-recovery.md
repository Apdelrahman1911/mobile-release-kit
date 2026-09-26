# Recover local project build inputs

## Availability

The Recovery screen has a dedicated **Inspect → Review → Recover** flow for
temporary Android/iOS service-configuration inputs managed by the core.
**Native execution remains disabled** until this exact domain, installed runtime
and original lifecycle have passed independent implementation review and native
verification. Source, parser and mock-IPC tests do not enable it. Browser preview
does not manufacture inspections or recovery receipts.

The core path supports Linux and macOS filesystem semantics. Initial native
qualification targets Linux; macOS requires its own actual native evidence.
Windows is unsupported by this recovery path. An available offline check or
Android build does not authorize recovery, and no ambient Python is selected.

## What the flow does

1. Select the same source project in the app and open **Recovery**. Unsaved
   settings remain intact; this action does not use or save the draft.
2. Click **Inspect build-input state**. This is one original, nonmutating core
   inspection—not a background scan, a process probe or a project command.
3. Review the observed state:
   - **Idle:** no pending build-input record was found, not proof that the whole
     project or a release is clean.
   - **Busy/conflict:** the existing owner or changed state prevents this flow.
     Preserve files and the original operation; there is no takeover or force.
   - **Pending, none:** original-worker finality is missing. Recovery is disabled;
     a stopped UI or empty process list cannot establish it.
   - **Pending, original:** the record contains the original consumer-finality
     observation. Current ownership and file checks still have to succeed.
   - **Pending, operator:** a prior operator explicitly asserted quiescence.
     This is labelled as an assertion, not new native proof. This UI cannot make
     that assertion or imitate the core's interactive manual procedure.
   - **Cleanup-only:** input restoration already finished according to the
     validated terminal record. The attempt retires only its remaining metadata,
     not application files.
4. For an eligible observation, click **Review recovery attempt** and read the
   exact session and affected roles. Check the initially unchecked acknowledgement,
   then choose **Recover reviewed build inputs** or **Retire reviewed metadata**.

There are no credential or file inputs for this flow. The app locates the core's
existing record in the native-selected project; do not move, rename, edit or
delete hidden recovery files. Contextual help explains every recorded state and
the difference between original and prior-operator finality.

## Review, preservation and original ownership

The renderer supplies only the registered project ID, draft/baseline generations
and the fixed action. It cannot supply a path, session, private review stamp,
command, tool, worker identity, force flag or alternative confirmation.

A recovery review comes only from a successfully settled original native
inspection. It expires no later than five minutes after that inspection began;
status refresh and a later Prepare cannot renew it. Changes to the project,
registration or review context retire consent. Start consumes it once, including
refused starts and lost responses. A fresh inspection is required for a later
attempt; nothing is automatically retried.

The core checks the actual held project directory against the original native
registration before reading any private recovery namespace. Recovery then
rechecks the validated root/session/control/checkpoint stamp under the same
original project lock as the existing core recovery body. A disappeared or
changed reviewed session is stale—not a successful or absent recovery. Foreign
file changes are preserved, not overwritten to make an attempt succeed.

## Cancellation and results

The native work deadline is 120 seconds from original Start admission; final
settlement has a hard 130-second deadline. The first lifecycle failure or STOP
shortens settlement to at most ten seconds from that event. Status polling never
renews these endpoints. The finite filesystem operation uses the original core
cancellation owner and dispatches no project command or native tool.

Navigation keeps a started operation's status and **Cancel original operation**
available app-wide. Cancellation requests stop, not rollback. Cleanup may have
partly completed after failure, cancellation or a lost response. Missing effect
data is uncertainty, not proof that no files changed.

A core terminal is provisional until all original process, I/O, resource and
native task joins settle. Unknown cleanup retains the original operation and
blocks conflicting work; reconnecting does not replace it. Checking original
status cannot grant another Start or establish that files were restored.

The result covers **one core-managed build-input session only**. It does not
recover saved-file transactions, artifact work folders, signing accounts, Store
operations or releases. Existing file-edit alerts and release-evidence guidance
remain visible and independent. Success here is not project or release readiness.
