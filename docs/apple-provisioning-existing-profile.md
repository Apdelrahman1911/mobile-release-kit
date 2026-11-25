# Existing Apple P12/profile reuse — worker validation slice

This slice checks an **existing** public certificate chain and an existing
modern App Store profile. It does not create a key/CSR/certificate/profile, read
an Apple account, import a key into Keychain, install anything or assign a vault
record. No native route is enabled by its presence.

## Exact implemented boundary

New private worker entry in `apple_provisioning_existing.py`:

```python
_inspect_existing_profile_in_worker(
    target: ProvisioningTarget,
    leaf_der: bytes,
    intermediates: tuple[bytes, ...],
    profile_bytes: bytes,
    *, cancellation: DefaultCancellation, deadline: InspectionDeadline,
) -> ExistingProfileComparison
```

Inputs must be the original credentials owner's captured **public** bytes, not
renderer-provided content, expected fingerprints masquerading as observations,
or a later reopen of selected filenames. P12/password/private-key/SPKI extraction
belongs to credentials and is deliberately absent from this entry. The fixed
inputs are at most 64 KiB per certificate, one leaf plus 1–8 unique intermediates,
and one profile of at most 4 MiB. Caller-supplied anchors/policies/dates and
preauthenticated profile dictionaries are not accepted.

The code calls the unchanged `decode_authenticated_profile`,
`ProfileCallEvidence` and `consume_profile_evidence`. Both actual CMS signatures,
production iOS profile-signing purpose and original producer/resource settlement
remain mandatory. A decoded/result-shaped dictionary cannot substitute.

After authentication it uses the actual `_ipa_profile_policy` and typed
`validate_profile_entitlements`: exact selected application/team, no debugging,
App Store/TestFlight grant, no ad-hoc/enterprise devices, exact iOS platform and
App-ID prefix, unique UUID, current typed dates and **exactly one** matching
DeveloperCertificates DER. The existing strict policy does not support legacy
App-ID prefixes different from the Team ID; no relaxed fallback is added.

`apple_provisioning_chain.py` then performs fixed Security/CoreFoundation calls:

- `SecPolicyCreateBasicX509` and `kSecPolicyAppleCodeSigning`, as already used by
  the installed producer verifier, but in this separate purpose/owner. No
  Developer-ID or profile-signing policy is repurposed for the application leaf.
- The unchanged `apple_roots()` supplies the exact three toolkit-pinned public
  Apple roots. Supplied intermediate bytes cannot replace those anchors.
- Explicit anchors-only evaluation; keychain lookup and network fetching are
  disabled and read back. No ambient user trust, root discovery, AIA fetch,
  account credentials, revocation freshness claim or fallback.
- Verify date comes from actual `CFAbsoluteTimeGetCurrent`, not caller DATA.
  All statuses, opaque-object types, evaluation/error outputs and **Unspecified**
  trust result are checked. User-granted Proceed is not accepted.
- The returned bounded, duplicate-free chain must start with the exact captured
  leaf, use only the admitted intermediates and end in an exact pinned root.
  No issuer/CN substring or guessed Apple distribution marker is used.

This proves **generic offline X.509/code-signing validation at that check time**.
It is NOT independently an iOS distribution-purpose result. Only the separately
authenticated modern App Store profile narrows authorization to this exact
existing certificate, Bundle ID, team and grants. The profile is rechecked at
actual current time after native evaluation; conflicting native/worker clock
intervals refuse. Native parent final rematches remain necessary.

The private result retains the same immutable input bytes and comparison
identity/hashes/profile dates/check times. It has no key reference, readiness,
assignment, certificate resource ID, provider action or serialization method.
There is **no conversion to `CertificateBinding`**: this profile-scoped result
must never permit creating another profile, issuing another certificate or
reusing the certificate for another application. It is not release readiness.

## Actual native integration still required

The smallest intended user flow is “Check my existing P12 and App Store profile”.
After genuine native integration, honest output is “Existing P12/profile match
checked offline”, not “Apple account authorized” or “Ready to release”.

1. **Root:** one dedicated fixed `CredentialInspect` saved-command purpose,
   protocol/bootstrap/runtime/OpenSSL and original child/pipe/driver/finality
   hooks. Do not borrow IOSArchive or Store consent/materials. This worker may
   block inside Security: Python deadline checks are **not native containment**.
   Never call these entrypoints from Desktop/UI/native-owner threads. Hold the
   original hard deadline, parent-loss/STOP and actual child termination/join
   gates before interpreting any return. No standalone CLI/bootstrap was added.
2. **Credentials:** obtain the actual currently assigned stored AppleP12 and
   AppleProfile originals. Hold the full random vault/generation/record/revision
   identity plus revision counter and exact context. Extract public leaf/chain
   and derive full SPKI from the **same actual private key** using the separate
   fixed protected OpenSSL role, `_run_private`/`run_owned` and `FiniteScratch`.
   No raw private data crosses to this module. P8 API keys are not signing keys.
3. **Root/credentials:** run the existing bounded Rust certificate candidate on
   that same captured leaf, exact public SPKI and selected team using a fresh
   original native clock. Its syntactic v3/KU/EKU/team/hash facts alone do not
   establish trust or custody. Retain the actual loan and inspected public input
   backing through this worker's finality, not just hashes or reference DATA.
4. **Original owner only:** after the real child/native cleanup joins, rematch
   current source/context/project, full key reference, key/public-SPKI/leaf
   equality and fresh leaf/profile validity. Only a separately authorized
   credentials assignment facet may persist the observed fingerprint or select
   the already captured profile. Current format-only Bind and a saved preference
   cannot synthesize those observations. Any unknown/changed original refuses.

The CF helper reserves reference/out-parameter slots before each producing call
and retains returns before checking STOP. Known references are released in
reverse order, once. Lost native return or release completion poisons the actual
cancellation ledger and forbids further CF work/retries; remaining process-owned
memory must be retired by the original parent's observed worker termination.
Existing CleanupScope first-primary and profile-fatality rules are reused. No
new process, resource-adoption registry or alternate lifetime engine is added.

## Verification limits

Focused tests use obvious non-DER/non-CMS synthetic strings and a fake Security
ABI, including malformed/native rejection, wrong chain/leaf/root/team/profile,
unjoined real evidence refusal, clock/deadline/cancel and ambiguous release.
They never perform a Security call, make a key, invoke OpenSSL or contact Apple.
These tests do **not** qualify macOS, native credential custody/private extraction,
the dedicated original runtime/worker route, installed delivery, account state
or assignment. CSR/issuance and standalone distribution policy remain deferred.
