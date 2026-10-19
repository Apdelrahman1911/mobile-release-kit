# Optional version allocation: private dialogue slice

Manual editing remains the default. This slice does **not** install an available
Desktop, CLI or GitHub allocation command. No live repository/Store request or
native allocation job has been qualified.

## Implemented

- `_desktop_version_allocation_runtime.run_owned` borrows the existing bootstrap's
  private input/output descriptors. It invokes the actual bounded allocator and
  fixed GitHub transport; it does not discover tokens, open local state, create a
  candidate, or invent durability from memory.
- The initial GO carries the already loaded schema3 snapshot and exact durably
  selected request. Only checkpoint, pending, rejected, resolved and reused
  transitions exist. The native state namespace and native revision remain fixed.
- A desired-state digest and revision accompany each transition. The worker waits
  for the exact committed/durable/settled native ACK before continuing. Lost,
  malformed, uncertain or stale ACKs latch the worker; no automatic reopen/retry.
  A pending intent survives an unknown send. Reconciliation is read-only remotely.
- A reused reservation still needs its own real native CAS ACK. A returned
  reservation is allocation DATA, not fresh Store/release eligibility.
- The native wire child reuses the existing state port's typed row/canonical
  codec. One cursor retains the original outstanding `Arc<Step>`. The caller must
  obtain its ACK from the actual state job, not from parsing a result-shaped DTO.
  The borrowed token is encoded only on a private `Zeroizing<Vec<u8>>` GO buffer.
- The fixed native `Jobs` adapter calls the actual state port in start-latched
  blocking jobs. Its original slot/handle precedes release; awaiting borrows the
  handle. Exact native return/error facts survive STOP and failed acknowledgement.
  It must still be installed in the existing Supervisor's Resources/driver; this
  helper does not own or activate another Supervisor or native command.
- A new reservation with absent/stale/incomplete Store floors does not construct
  the live transport. Those inputs still need the original native Store owner;
  accepting their shape is not authentication.

## Exact dialogue

`INITIAL → READY → GO → (STATE → native CAS + join → ACK){0..5} → FIN → stdin close → worker input EOF → stdout EOF`

The actual allocator needs at most four CAS transitions; five is only a framing
ceiling, not an extra selection or remote-write grant. The state namespace may be
up to 1,048,576 bytes. Its base64 expansion is at most 1,398,104 bytes. GO is at
most 1,427,800 bytes, including request16KiB, observations4KiB, worst-case token
JSON escaping and fixed syntax. STATE is at most17,920 bytes, ACK1KiB, FIN32KiB.
Total framed input is bounded by1,441,112 bytes and output by122,880 bytes. These
are **wire bounds**, not a claim about Rust/CPython heap or process RSS.

The retained native raw-clock endpoints clip the original60-second work and
70-second finality endpoints; reads, retries and state waits cannot renew them.
EOF is checked between HTTP exchanges. It does not interrupt an in-flight HTTPS
call: the actual Supervisor STOP, child wait, IO and management joins remain
necessary. FIN alone cannot settle or release an original owner.

## Still required before activation

1. A distinct actual Supervisor allocation arm using its existing runtime,
   driver/watchdog and reader/writer originals. Install the typed `Jobs` adapter
   and its start latch **before** any native IO; join the borrowed handle outside
   Document/Edit locks and retain the actual `StateError`/ACK on every outcome.
   STOP between CAS return and ACK must withhold ACK without discarding the job.
2. Keep one stdout cursor and one outstanding state step, with no competing read
   or eager second-frame processing. The driver holding `Resources` must receive
   bounded state requests rather than having the writer reacquire that mutex.
   Release every Resources/Host/service/state lock before the writer's pure
   original Document/currentness check. Only then release the ACK, including the
   sole pending-ACK permission to attempt the conditional repository PUT.
3. A genuine allocation-specific consent, selected-account/token pin, full
   local→shared enrollment/genesis authority, current source and Store-floor
   admission. Existing setup/read-only grants do not authorize allocation.
   `LocalSourceObservation` is build/store-owned and cannot be relabelled.
   `VersionCheckout` proves saved version/config input, not Git commit/tree/ref.
   Existing selected-build Store queries do not establish an all-trains floor.
4. Final results only after the actual reader/writer/child/runtime/native state
   and management jobs join. Preserve uncertain work and original recovery.
   A reserved edit must separately use the authentic current RELEASE_VERSION
   checkout, existing writer, explicit preview/Apply, and final clean-source
   binding. A worker reservation blob is not edit or release authority.

`version-allocation-dialogue-hooks-20261019.patch` adds only the two native child
declarations and fixed bootstrap dispatch branch. It deliberately adds no
Supervisor availability or public route. Root applies central hooks after review.

## Verification boundary

13 focused synthetic FD/HTTP/native-ACK Python cases pass. No descriptors,
subprocesses, sockets, Store APIs or actual state files are used by those tests.
Nine native wire/private-store fixture tests are defined but **unrun**, including
real job start-latch, post-CAS STOP and native stale-CAS tests; only rustfmt
parsing was checked. Native process/Doc/state-job integration and real
Mac qualification are not covered by these results.
