# QA-006 — macOS signal-fence feasibility plan R1

**PROPOSED; independent plan approval required.** This authorizes neither a
full project test run nor an unreviewed experiment. Implementation must receive
a distinct safety review before the canary experiment executes. No first-party
change, Store call, VM, signing credential, commit, push, acceptance or final
freeze is part of this proposal.

## 1. Problem and inspected evidence

QA-007 records a real stale process-group signal request in
`fastlane/native_upload_validation.rb:47–57`. QA-006's full native/adapter
regressions necessarily reach that unchanged production code. Existing local
tests have therefore been restricted to guarded pre-entry paths. A process
observation followed by kill is not lasting PID authority and cannot by itself
protect other tasks on the shared Mac.

The previous Colima isolation plan was rejected; no VM was started. Permission
to commit/push a reviewed temporary CI branch before complete verification is
still unanswered. This proposal examines a smaller *local signal-containment*
alternative, without assuming either permission or containment.

Read original QA-006/QA-007 findings, current fixture/ownership/native call sites,
the independent read-only sandbox advisory, and the installed interfaces:

- `/usr/share/man/man7/sandbox.7`: parent-to-child inheritance is documented.
- `/usr/share/man/man1/sandbox-exec.1` and the Xcode SDK `sandbox.h`: deprecated
  interface; activation executes a supplied command only after entering a profile.
- `/System/Library/Sandbox/Profiles/application.sb:5–8,769`: Apple calls the
  policy private/unstable and itself uses `(target same-sandbox)` for `signal`.
- No inspected public interface defines profile versus invocation domain
  identity or per-member negative-PGID enforcement. These are **unverified**.

Do not import Apple's application profile or infer protection from its text.
The installed uncompressed man pages, not an unsuccessful `.gz` lookup, are
the actual documentation inspected. No sandboxed child has been launched.

## 2. Bounded scope and candidate policy

Create only a new ignored preparation directory below `QA-006/` containing the
plan-approved Python controller, static Python canary/relay, static Ruby
inheritance relay, policy files, and raw/results/ownership manifests. Keep
first-party bytes, both real indexes, old failed results and AGENTS unchanged.
Do not modify the unapproved final verifier to conduct this experiment.

Test one exact candidate policy; do not automatically broaden it on failure:

```scheme
(version 1)
(allow default)
(deny signal (require-not (target same-sandbox)))
(deny file-read-data (literal "<owned-domain-marker-path>"))
```

`require-not` and `target same-sandbox` are present in installed policies, but
this exact combination still needs real compilation and behavior proof. The
marker is an existing fictional file in the experiment's own private root;
each effective domain uses a different actual literal. An attempted open must
be denied. Thus a purported domain nonce is an enforced policy rule, not an
unused parameter, comment, filename assumption or output label.

Use the actual absolute `/usr/bin/sandbox-exec -f <owned-profile>` followed by
the pinned absolute Python/Ruby interpreter and static argv. No shell, `eval`,
service launcher, AppleScript, SSH, XPC request, daemon, or arbitrary executable
may be dispatched. Supply only a fresh explicit nonsecret environment with
fixed tool paths, locale, `PYTHONDONTWRITEBYTECODE=1`, and private TMPDIR. Do not
read the user's global configuration or credentials. Hash OS version, relevant
system interfaces, exact executable leaves, scripts, profiles and configuration.

This allow-default policy is intentionally NOT a filesystem/network/secret
sandbox. It cannot replace existing owned-path, clean-environment or Store
authorization boundaries. The proposed experiment uses no network or keychains.

## 3. Safety independent of whether the policy works

Every potential signal recipient must be a synthetic process created for this
experiment. The experiment remains harmless to other tasks if activation or the
signal fence is entirely ineffective. Do not load production capture/fixtures,
whose stale IDs are precisely the reason full verification is not authorized.

- An outer Python owner starts one experiment supervisor in a new session. The
  supervisor creates named canaries/relays in that session, with separate new
  groups as needed. Parent and root tooling are outside every targeted group.
- The supervisor is the sole waiter for each direct external target/group
  leader. It retains the actual returned process handle **without polling or
  reaping it until all signal attempts to that identity are finished**. A ready
  event is required before use. A bounded self-expiry does not release that
  unreaped PID reservation; no other waiter/thread may reap it.
- A same-domain target may instead be acquired by a live, explicitly registered
  sandboxed sub-owner, using the same direct-handle/sole-waiter rule and a
  bounded private parent protocol. The real Ruby/Open3/fork inheritance chain
  is a **sender** chain; its auto-reaped interpreter IDs must never become
  experiment signal targets. Its sender may change group/session while testing
  inherited restrictions, but it signals only a target still reserved by the
  supervisor/sub-owner. No timing assumption about the Open3 wait thread or
  worker expiry substitutes for this reservation, even in a positive control.
- Never authorize a target from a PID file, process name, `ps`, signal0, or a
  prior child status. Only the current immutable registry of actual acquisitions
  may supply an experiment target. Require PID/PGID greater than1, known group
  membership/session, exact ready token, and no finished reservation. Forbid
  zero, minus1, unknown groups, and calls targeting the owner/supervisor group.
- Each mixed group has an independently owned unsandboxed leader retained by
  the supervisor. Sandboxed canaries may join that exact group only within the
  same private session; an acknowledged membership check precedes signaling.
  Mixed-group KILL may kill *all* members if the fence is absent, but every
  member is an expendable owned canary. The sender/owners are outside that group.
- Own pipes before any fallible setup. Each worker has a private control read
  end and a sole supervising writer. Other processes do not inherit that writer;
  all descriptors are CLOEXEC unless individually passed for the fixed protocol.
  EOF instructs normal exit independently of the sandbox or numeric signals.
  Workers have a30s monotonic self-expiry as a last bounded defense, not proof
  that cleanup occurred or permission to release reservations early.
- Acquisition errors with no returned handle are UNKNOWN. Stop dispatching;
  close only acquired descriptors and use EOF/self-expiry. Do not invent a PID
  or stop an unknown process. Known target reservations are reaped only after
  all signal dispatch is irrevocably disabled. No process-name cleanup, pkill,
  or post-reap signaling is permitted.
- INT/TERM handlers set a shared cancellation flag before acquisition. Check
  it at every phase; disable all new dispatch, close known control writers and
  join actual known children on cancellation. No asynchronous handler performs
  cleanup or raises inside acquisition/reap publication. Preserve the original
  error and separate cleanup failure. A failure cannot become a successful probe.

Use no threads, background daemons or build tools. At most eight live synthetic
workers are permitted, at most48 launches per experiment, a180s total work
deadline, a10s known-child cleanup allowance after failure, and each worker's
independent30s expiry. No timeout resets or retries. Bound reads/writes to4KiB,
each stream to64KiB, aggregate output to2MiB and all new files to8MiB. Multiplex
stdout/stderr/control pipes nonblockingly; cap input records and reject duplicate
JSON keys, unknown names, wrong nonces, duplicate readiness and malformed types.
Retain actual exits, cutoff/byte-limit violations and unknown ownership.

## 4. Exact feasibility cases and oracles

Each case is a new set of known owned recipients, not a retry of a failed
case. The same unmodified native Ruby `Process.kill`/Python `os.kill` calls
perform signals; no shim may turn an attempted signal into a canned success.

1. **Activation and enforced identity rule.** The exact policy must execute
   the relay, deny reading its domain marker, and otherwise allow an ordinary
   owned canary handshake. An intentionally invalid profile must return nonzero
   without executing its child. Never fall back to an unsandboxed invocation.
2. **Positive inheritance.** Same-domain descendants created by Python fork,
   exec and a grandchild, and the real Ruby → Open3 → Python → fork chain,
   must receive a sequential SIGUSR1 and later a deliberate KILL. Exercise new
   child process groups/sessions as well as inherited groups. Bind actual launch
   path/parent/group, acknowledgment and wait status; no mocked waiter/status.
3. **Unsandboxed external canaries.** Same-UID experiment-owned targets outside
   the sandbox must not receive positive-PID or negative-PGID SIGUSR1/KILL.
   Require actual EPERM/denial, unchanged receipt counter, and a fresh control
   round-trip showing the canary remains alive. Signal0 alone is insufficient.
4. **Domain equivalence.** Independently launch two relays with identical
   effective policy and two with different enforced marker rules. Record
   actual cross-launch delivery/denial; do not pre-assume whether identical
   policy means the same domain. Distinct effective domains must deny cross-
   signaling before a uniquely bound future test domain can be considered.
   Same-profile delivery, if observed, is a documented domain-sharing property,
   not an automatic pass for cross-domain isolation.
5. **Mixed groups.** A wholly owned target group contains both same-domain
   sandboxed and external unsandboxed canaries. SIGUSR1 and KILL must affect
   only the permitted members. Bind each actual counter/status separately:
   successful group return alone proves neither exclusion nor per-member
   delivery. Repeat with an external different-effective-policy canary.
6. **Negative fence control.** A separately declared no-fence relay signals
   only the same kinds of owned recipients. Actual SIGUSR1 delivery and KILL
   must make the isolation oracle reject it. This expected control rejection
   is not reported as a safe unsandboxed environment or a project test pass.
7. **Failure/cleanup controls.** Invalid child/profile launch, controlled
   pre-dispatch cancellation, cancellation after readiness, and malformed
   ready/control output prohibit new signals and retain actual failure. All
   known children exit through private EOF or observed intended KILL and join;
   no secondary cleanup error may overwrite the initial failure. Preserve
   unresolved resources instead of deleting their evidence.

For every signal case, first verify a live control response. Assign sequential
command IDs; after SIGUSR1 demand an explicit current counter response, not an
old unsolicited receipt. Positive KILL requires the actual negative signal
wait status. Negative KILL requires a new live response before later EOF exit.
Do not coalesce unacknowledged standard signals or infer absence from a missing
log line. Failed or ambiguous protocol/observation means failure/uncertainty.

No physical PID reuse experiment is allowed. Controlled references to *current,
reserved, wholly owned outside targets* exercise the necessary target-authorization
boundary safely. That is not a claim to have reproduced actual collateral damage.

## 5. Review, evidence, cleanup and next decision

1. Obtain independent approval of this exact plan, or revise it.
2. Implement only the ignored static experiment. Safe syntax/static inspection
   is allowed; do not launch it before a **different** reviewer examines the
   actual scripts, ownership, cap enforcement, target registry, signal calls,
   policy bytes, EOF inheritance, and failure/cancellation cleanup.
3. Execute once only after that safety review. Record real argv/environment,
   hashes, readiness/control/signal/delivery/reap evidence, actual controller
   status, per-case expected versus actual results and remaining uncertainty.
   Any policy or script correction needs a new reviewed revision/namespace,
   never edited historical logs or automatic permissive retries.
4. Close/join only this experiment's workers. Archive small synthetic evidence
   and remove only its owned, inventoried disposable scratch after actual joins.
   Keep scripts, policies, raw evidence, ownership/cleanup manifests and reviews.
   Unknown worker/path/identity state means retain the directory and report it.
5. Have the independent reviewer reconcile actual results. A successful
   experiment grants **no full-suite permission by itself**. First author and
   review a distinct verification-launch contract binding a fresh effective
   signal domain to the complete final runner, tool/env/source/owner hashes,
   safe signal use, absence of unsandboxed service escapes, and all existing
   final gates. Native-tool compatibility and source/wheel execution must be
   proved there without skips or broadened permissions.

If the mechanism fails or remains ambiguous, retain NOT READY and use a properly
reviewed disposable VM or explicit hosted-test authorization instead. Do not
waive QA-007, accept guarded subsets as full tests, modify runtime validation,
or consider the original issue delivered. Required protected hosted Linux/macOS
CI, all remaining findings, the fresh full audit and final feature report remain.

**Authoring outcome:** only this ignored proposal is added. No sandbox/test/
build/VM/native worker, signal, package install, code change, commit or push
has been performed. There are no author-owned background workers to stop.
