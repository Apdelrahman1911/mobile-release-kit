# Fixed Apple namespace upgrade and original native-use guard

These two included Rust files extend the **same** `application_state_store::native`
Book/Directory/flock. Apply the accompanying one-file Root packet; no alternate
filesystem owner, namespace argument from a renderer, daemon or automatic repair
is added. The standalone installed CLI still imports no Desktop/native owner.

## Exact native API

- `store.begin_native_use() -> Result<NativeUse, StateError>`: off Doc/Edit/Host
  locks. Retain the returned non-Clone object in `Arc<NativeUse>` before any job GO.
- `store.check_native_use(&NativeUse) -> Result<(), StateError>`: checks the SAME
  live original token, not filesystem health, authorization or task finality.
- `store.enable_apple_provisioning(&NativeUse) -> Result<Snapshot, StateError>`:
  only the separately approved, explicit Desktop schema opt-in job. A state-ready
  result or ordinary lease/read is **not** that consent. Run outside parent locks.
- `store.retire_native_use(&NativeUse) -> Result<(), StateError>`: cleanup only,
  behind the original parent's **all**-jobs-joined receipt, including its final
  journal CAS or positive known-not-entered branch. No boolean/DTO/Drop retirement.
  Wrong store/token and repeat calls refuse; dropping the token leaves `close()`
  Busy. The real parent must retain it through every uncertain join.

The guard is intentionally separate from a provisioning `NativeJoined` witness:
that witness precedes the final journal write and cannot release this native use.
Known joined IO with failed storage may retire the use and close descriptors;
that never clears the original storage error or durable pending state.

## Version boundary

Ordinary first initialization stays byte-exact v1 with the original three files,
tags, checksums and revisions. Apple tag4 access on valid v1 is `Unavailable`, not
empty and not a reason to poison the old three namespaces. Only explicit opt-in
does the following under the same held Book:

1. Check every original state header/checksum/file identity and exact reservation.
2. Exclusively create/fsync `apple-provisioning.upgrade-intent`, then dirsync.
3. Exclusively create/fsync `apple-provisioning.state` at revision0/empty, dirsync.
4. Exclusively create/fsync `.reservation-v2.next` with fixed v2 bytes, dirsync.
5. Recheck originals; rename the owned reservation candidate over the owned v1
   reservation; dirsync and original readback/close. Old three files stay intact.
6. Remove only the same original upgrade intent, dirsync; only then publish v2
   keys into the live Book. Existing v2 enable is a read, never a reset.

Any partial/unknown result poisons the live Book and retains files; no rollback,
reopen, retry or cleanup is attempted. Startup refuses unknown versions, remaining
intent/candidate, unexpected tag4 on v1, and missing or invalid v2 state. If the
last intent removal occurs but its directory fsync/ACK is lost, a later exact
complete v2 layout can be indistinguishable from success. Reopening validates
**current layout only**, never reconstructs the earlier operation's receipt.
No provider action occurs in this upgrade.

## Tests / limits

Nine Rust test methods exercise actual isolated Store originals: v1 no upgrade,
old3 byte/revision/inode and flock/endpoint preservation, five durable cutpoints,
last-unlink uncertainty, missing/mixed states, replaced reservation, wrong and
repeated native tokens, dropped-token close refusal and failed-storage cleanup.

Author evidence: Rust source formatting/parser and packet apply-check only.
**No Cargo/tests/native/provider/credential operation run.** Root owns real-graph
compilation and the Host/Doc/SavedCommand finite-job/witness integration. Source
guard tests do not qualify those native joins or enable Apple availability.
