# Existing-key profile journal increment (2026-10-20)

This packet extends the **same** `AppleProvisioningJournal`/`NativeUse`/private
state namespace. It does not enable profile operations or construct a native
join, private key loan, destination, provider consent or save permit.

## Fixed state and original ownership

- Ordinary reads and Bundle actions retain schema 1 unchanged. The first
  **explicit profile Start**, through `reserve_profile`, atomically appends its
  immutable intent and opts that namespace into schema 2. No automatic startup
  migration, second store, repair or retry exists.
- Combined Bundle + profile history is bounded to 32 rows, 16 KiB per row and
  1 MiB canonical state. Existing Bundle rows retain their exact canonical
  bytes/plan hashes; other namespaces/revisions are untouched.
- A profile intent contains exact source/destination full vault references,
  same issuer-based account, native project/root/config/version provenance,
  target/entitlements hash, selected Bundle/certificate/profile, times and
  original plan/request hashes. The destination is NEW counter 1, in the SAME
  original vault generation. None of this reference DATA proves custody.
- `beforeSha256` binds the original complete native review; it is NOT an empty
  inventory assertion. Native admission must retain and recheck that review,
  current P12/P8 loans, full target and reserved destination before the CAS.
- Creation uses the existing attempt field/transition checks with a separate
  closed `create_profile` enum; the old Bundle Attempt grammar is unchanged.
  Reuse is `reuse-download`, has **no POST/send arm**, and reserves only a NEW
  local profile destination. A sparse 201 is not a usable download.
- Provider result, native joins and local save/readback are independent. Armed,
  written or unknown save remains unresolved even with known native settlement.
  Cancellation and response/download/full-reference facts cannot be erased.
  Both action families consult this whole account fence. Old Bundle requests
  see profile rows only as a coarse unresolved/resolved fence, never their
  private references or a usable historical profile.
- The original profile reservation is retained BEFORE CAS, including a lost
  ACK. `record_profile`/`finish_profile_native` require the same pointer-bound
  reservation and NativeUse; decoding/reopening never reconstructs either.
  A later identical read cannot repair that port's sticky failure or resend.

## Required next original-parent hooks (not implemented by this packet)

The `saved_command_apple_signing.rs` child defines one portable opaque
`AppleProfileNativeJoined`, with **no constructor**. Native minting must occur
only after the same worker/provider/CMS/private receive consumers and the fixed
vault save/readback jobs have actually joined. The final journal CAS follows
that cut; ALL finite jobs (including final CAS) then join before the existing
NativeUse retirement job. That retirement itself must join before public finality.
No test creates a positive native witness.

The parent still must admit/charge full simultaneous decode/typed/encode/readback
scratch and retained ACKs/destination/receive backing on its current finite
census; row/frame limits are not RSS claims. IO continues only in the original
finite jobs, off Document/Edit/Host/Service locks. No tasks are created here.
Unknown local save or journal outcome must stay fenced. Known no-save/saved
private cleanup uses the separately approved original-parent retirement cuts,
not these DATA statuses or a reset to an earlier state.

## Focused source evidence

- Four new passive Python tests of the actual Bundle pending/plan grammar pass
  (0.012 s, no provider/native/file operations). The full original modules were
  used with only the companion Python hook. Initial test expectations were
  corrected to the existing `reconcile` action and existing parser exceptions;
  no production behavior was changed to satisfy those assertions.
- Fourteen Rust tests are authored: seven DATA/hash/transition cases and seven
  real tiny private-directory/CAS/reopen fixtures. They have **not** been compiled
  or run by this agent. Root owns the actual full-graph batch; no extracted
  codec harness, secret fixture or fabricated native success is used.
- New Rust leaves parse with the installed rustfmt. No native/provider/vault
  credential use, Apple request, installed qualification or readiness claim.

Selectors after Root applies the exact six-path companion hook:

```
PYTHONPATH=src python3 -B -m unittest discover -s tests/unit -p test_apple_provisioning_profile_journal_wire.py -q
# Root's existing real-crate test binary filters:
# apple_provisioning_journal::data::profile::tests
# apple_provisioning_journal::profile::tests
```

Core helper `7009f6c8` and its already accepted Python/Ruby evidence are unchanged.
