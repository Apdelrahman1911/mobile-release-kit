# Apple Distribution certificate — same-owner issuance core

This finite core packet is **not an enabled certificate creation feature**. It
adds no key generator, independent private-input/native owner, StoreRuntime,
journal or retry engine. The existing SDK client/transport is constructed only
inside the same original operation. Local tests use fake SDK/data responses
only. No Apple account, agreement, certificate slot or remote service was accessed.

## Existing owners retained

`apple_provisioning_certificate_issuance.py` specializes the existing
`ProvisioningAttempt` and complete `SigningInventory`. The existing
`ProvisioningContext`, `NativeKeyRef`/`PublicCSR`, exact current selected-account
checks, possible-send-before-ACK state, original transport settlement,
cancellation and persisted-attempt reconciliation remain authoritative.

`fastlane/apple_provisioning_certificate_issuance.rb` subclasses the actual
`ReadOwner` for its selected-token, origin, TLS, thread and response checks;
only its fixed certificate companion has write admission. The base owner's
`before_write!` remains false. It reuses the existing scoped transport and raw
response capture and permits only the three existing bounded inventory GETs and
one exact certificate POST with the original public CSR. Redirect/proxy/ambient credentials, arbitrary
paths/requests, raw diagnostic output and implicit retries remain refused.
Private P8 handling remains on the same existing selected-material owner; this
packet does not introduce a private key/CSR command-line interface.

## Reuse and response-loss behavior

- Existing valid certificate plus genuinely matching current native key wins.
  A valid certificate without its private key asks for recovery, not another
  certificate/key. A missing Bundle ID returns to existing registration.
- `create_certificate` is accepted only for the exact saved-key CSR bounded to
  the local RSA2048 producer's 4096-byte CSR profile. A native keySaved ACK and
  separate explicit external approval are prerequisites; their hashes are only
  handoff comparisons, not permissions.
- The same attempt is claimed once before the durable possible-send ACK; the
  actual POST is allowed only after that ACK. A timeout/lost response/uncertain
  transport preserves the original request and key. Inventory absence never
  authorizes another POST or key generation.
- Sparse 201 retains the new resource ID and only attributes actually returned.
  It does not manufacture certificate bytes, expiry, SPKI, team, trust or P12.
  A bounded fresh inventory must reconcile that receipt with the same unique
  current native-verified key/certificate binding.
- Known returned rejection statuses 400/401/403/404/405/409/422 remain separate
  from 429/5xx/unknown possible-send. Guidance asks the user to check permissions,
  agreements and certificate limits while retaining the saved key; provider
  response text and account details are not displayed. There is no revoke,
  rotation, quota count-guess or automatic resubmission path.
- Restoring attempt DATA cannot rearm `execute`. A restored key has a different
  full reference and must be explicitly reconciled; receipt/hash equality alone
  cannot recreate a current native key binding or consent.

## Inputs and missing native integration

The preceding local-key operation must finish NEW/full authenticated readback,
durable keySaved acknowledgement and all original private/native jobs before a
separate certificate operation is admitted. Apple owns the new closed mode and
same-journal-v3 native orchestration; it must acquire a fresh full-ref/witness
stored-key loan, run the bundled restore/reuse verifier and retain the actual
source/account/clock/ACK before calling this core.

The native certificate binding still needs the actual private-key SPKI and
exact current ASC Distribution resource/DER plus the reviewed offline chain,
purpose/team/time checks. A DER parser, `SafeAssessment`, expected fingerprint
or format-only Bind cannot construct that authority. Existing Profile creation
remains a subsequent, separate same-owner operation. Eventual P12 construction,
NEW association, explicit user Bind, independent encrypted backup and installed
Mac verification are **not implemented by this packet**.

## Files and Root packaging

Own source/tests:

- `src/mobile_release/apple_provisioning_certificate_issuance.py`
- `fastlane/apple_provisioning_certificate_issuance.rb`
- `tests/unit/test_apple_provisioning_certificate_issuance.py`
- `tests/workflow/test_apple_provisioning_certificate_issuance.rb`

`apple-distribution-certificate-hooks-20261020.patch` has four shared targets:
the fixed Ruby helper is added to `tooling.py`, wheel data-files and the native
Store required-file roster, and `apple_provisioning_bundle_read.rb` admits only
the exact certificate `Input` class/derived request kind to the existing owner.
It is projected after the local-key packet's two helper rows, with the read
owner from Root `d86ddc92b25c93dc0edf2dcda37dfe1d73317786`. The complete patch
applies to integrated Root `d72637cbd4abc7eb0758730f6e2f85f4158d0595`. Root
must preserve Apple's separate Signing input/kind arms. The real base-owner test still refuses
POST even with the certificate Input and shaped approval. No new dependencies,
executable roles, native mode, capability or availability flag. Root composes
the real parent modes after the Profile/v3 source is ready.

## Evidence and limits

- Python targeted tests: **15/15 PASS** (0.031s), zero skips; strict frame and
  receipt parsing, reuse/no-key recovery, no replay, sparse 201, changed request,
  known rejection vs unknown, and fresh exact certificate reconciliation.
- Ruby targeted tests: **10/10 PASS**, 312 assertions, zero skips (0.037790s).
  The exact seven-source projection includes the real ReadOwner and its two
  Root-only closed input/kind hunks; only the SDK/HTTP response ports are fake.
  The Ruby caller joined and the task projection was removed. No native
  process, key, certificate or account operation.
- No new Rust/native tests or native qualification in this core packet.

The tests verify the bounded core behavior, not Apple's live response shape,
agreements/quotas, native permission, P12 usability or release readiness. Source
review and Root integration are still required before a scoped commit.
