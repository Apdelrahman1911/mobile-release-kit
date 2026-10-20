# Existing-key App Store profile setup — core/helper increment

This is the first source packet of the approved existing-P12 → profile
reuse/create/download → NEW vault save flow. It is **not native activation**.
The native current-key loan, private receive/save slot, journal schema-2 and
explicit association are separate required pieces of that same operation.
No new process owner, HTTP client, release permission or generic command exists.

## Reused owners and exact scope

- `apple_provisioning_signing.py` calls the existing closed API constructors,
  `collect`, typed resources and reuse-first `prepare`. An actual current
  `CertificateBinding` must come from the original P12/private-SPKI + pinned
  chain/policy + fresh selected-account ASC certificate comparison. Its presence
  in synthetic tests is not evidence that this native borrower is implemented.
- The fixed Ruby helper reuses `AppleBundleRead::Input` / explicit `Token.create`
  / no refresh, the same per-instance `ReadOwner` currentness/raw callback, and
  `AppleProvisioning::Adapter` / `ScopedTransport`. Old read and release roles
  remain unchanged. The helper does not load Fastfile or acquire an account.
- Profile modes are `profile-review`, `profile-reuse`, `profile-create`, and
  `profile-reconcile`, on the SAME Apple SavedCommand operation. The existing
  Bundle-ID modes remain separate. This packet defines core/helper support;
  shared worker/native dispatch has not yet been installed for these modes.
- One helper invocation makes exactly one fixed GET or POST. No URL, arbitrary
  request, body, retry count, device/capability or certificate creation enters
  its input. The original parent owns the bounded serial schedule.

## Read / reuse / creation

1. Selected identifier Bundle IDs, Distribution/iOS Distribution certificate
   content, and App Store profile metadata are read through the original P8.
   At most two 200-row pages per collection, 128 KiB/page and 1 MiB aggregate;
   stable total/IDs/termination and exact-origin/path/query cursor checks apply.
   Totals above 400, third pages, unknown/missing data and denied reads are not
   empty inventories. The timestamp precedes the first read.
2. Profile metadata cannot smuggle `profileContent`/`certificateContent` into
   download parsers. All related attributes are checked, including foreign
   profile rows. There are at most 800 total certificate references and 600
   included references per page. Missing relationship totals or referents can
   nominate a known existing profile for exact download/CMS inspection, but
   cannot establish the absence of a reusable profile and authorize creation.
   That limitation participates in the reviewed observation hash.
3. Existing profiles win. Multiple compatible profiles require selection.
   A missing private key directs recovery/import, not certificate creation;
   missing Bundle IDs return to the separate Bundle-ID flow. Existing strict
   modern-prefix and capability policy is preserved.
4. `ProfileCreationAttempt` inherits the actual one-attempt/ACK/cancel/readback
   engine. The exact operation-derived name and one selected bundle/certificate
   relationship are bound by the original plan. The real parent must persist
   its account-wide Pending reservation (including the reserved NEW profile
   destination) and acknowledge it before any POST can enter.
5. A sparse 201 only retains an ID and validated supplied fields. It permits
   an exact GET, not save, assignment, provider success or POST replay. A new
   narrow recovery hook compares that retained sparse receipt with the GET;
   old attempts still compare their full resource hash exactly. Missing/lost
   receipt or new process never reconstructs the live attempt/reservation.
6. GET profile content is bounded to 1 MiB decoded / 1.5 MiB raw JSON / 2 MiB
   private helper frame. The caps are independent; a raw value near its maximum
   may not fit base64 plus header and must be refused, not truncated. These are
   representation/admission bounds, not claims about SDK/socket RSS.

## Two Root-only core hooks

`apple-signing-provisioning-core-hooks-20261020.patch` changes only:

- `apple_provisioning.py`: optional caller deadline (old default retained),
  same deadline to both actual CMS originals and typed profile-entitlement
  policy. Expired original refuses before authentication; first interruptions
  still pass through the unchanged evidence consumer.
- `apple_provisioning_recovery.py`: `_response_matches` default is precisely
  the old ID/full-resource hash condition; only the new profile subclass
  overrides sparse-response comparison. Persistence/one-send/finality logic
  is unchanged.

No shared source file is edited in this lane. The fixed new Ruby helper must
enter Root's literal tooling/packaging roster. Native Ruby/gems may reuse the
unchanged existing component: `prepare_runtime._store_inputs` composes current
first-party tooling separately. A fresh runtime manifest/app and real helper
checks remain necessary; this packet does not qualify them.

## Required remaining native cut

The joint approved flow retains actual P8 + P12 full references, source/guard,
account issuer, NativeUse and explicit mode consent. A successful fixed P12
helper is only public leaf/full-SPKI/chain DATA, not generic signing authority.
The specialist owns its original private loan and reserved NEW profile sink.
The parent still must combine actual fixed offline chain/purpose checks with
fresh ASC type/exact DER and final current full-ref/context checks.

Profile bytes use one bounded private trailer in the SAME original stdout
reader, not public Terminal/serde/base64 status. After provider/CMS/material
consumer joins and save-armed durable ACK, a fixed vault save/readback job runs
**before** NativeJoined → final journal CAS → sealed roster → AllJobsJoined →
NativeUse retirement. Unknown local save/readback fences both Bundle and
profile action families. No work may be appended after FINISH/sealing.
Saved ≠ assigned; explicit association and existing signing-input validation
remain distinct. Dedicated new key/CSR/certificate issuance remains future work.

## Focused evidence

Only new tests, tiny fake provider/SDK envelopes and existing inert fixtures:

- Python: `PYTHONPATH=<actual source projection with the two hooks>:tests/unit
  python3 -B -m unittest -q test_apple_provisioning_signing` — 23 pass, 0.344 s.
- Ruby: `ruby tests/workflow/test_apple_provisioning_signing.rb --name
  /AppleSigningProvisioningTest/` — 10 pass, 263 assertions, 0.073 s, zero skips.
  Initial run found one test expected a returned error instead of the existing
  adapter's raised write refusal; assertion corrected, no production relaxation.

No real P12, key, certificate, profile, vault, SDK account, network, native
process, Keychain, Cargo, installation or Store operation was exercised.
