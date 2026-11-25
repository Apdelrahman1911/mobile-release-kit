# Apple provisioning certificate precursor — untrusted data only

`desktop/src-tauri/src/apple_provisioning_certificate.rs` is a private child of
the existing `credential_apple` parser. Its bounded RustCrypto X.509 inspection
does **not** qualify certificate trust, signing or an Apple provisioning route.
There is deliberately no conversion to Python `CertificateBinding`, assignment,
native `SafeAssessment`, readiness or a serializable result.

## Implemented interface

```rust
inspect_certificate_candidate<'a>(
    captured_der: &'a [u8],
    expected_team: &[u8; 10],
    expected_spki_sha256: &[u8; 32],
    at: SystemTime,
    stop: &mut dyn FnMut() -> bool,
) -> Result<UntrustedCertificateCandidate<'a>, CertificateCandidateFailure>
```

The caller supplies an already captured **public** certificate, comparison team,
comparison time and expected full-SPKI hash. These inputs are not themselves
authenticated or proven current by this function. The result borrows exactly
that input and contains its DER SHA-256, full-SPKI DER SHA-256, comparison team and
time, and parsed notBefore/notAfter seconds. It has no `Clone`, `Debug`, Serde,
trust flag or private-key reference. Accessors remain native-only.

The existing `credential_apple::preflight` provides borrowed maintained-DER
allocation/work admission; `cms::cert::x509` supplies the already locked
`x509-cert 0.2.5` decoder. There is no new parser, dependency, native worker or
cryptographic verification engine. The subset requires:

- Exact single DER certificate and maintained-encoder roundtrip, v3, no unique
  IDs, matching inner/outer signature AlgorithmIdentifier and nonempty aligned
  signature encoding. None of these checks verifies the signature.
- One exact ten-character uppercase ASCII/alphanumeric team OU, typed UTF8String
  or PrintableString; no subject/CN substring, trim, case fold or alternate ID.
- `notBefore <= comparison time < notAfter`, matching the provisioning planner's
  conservative half-open expiry policy, including fractional comparison seconds.
- Present non-CA basic constraints, digitalSignature KU without CA/CRL-signing
  bits, and exactly one codeSigning EKU. These are syntax facts, **not Apple iOS
  distribution purpose**. Missing/unsupported variants require another reviewed
  path, not a relaxed fallback.
- Full-SPKI DER hash including AlgorithmIdentifier, parameters and BIT STRING;
  this is not a hash of only RSA modulus/EC point. Algorithm-specific key bytes
  stay opaque, so the hash does not establish key syntax, strength or custody.
- No duplicate extensions; unknown critical extensions refuse. Unknown
  non-critical contents remain bounded and uninterpreted. Consequently some
  genuine certificates may be unsupported until the correct native policy and
  any required purpose-extension support are reviewed; no coverage is claimed.

Leaf input is at most 64 KiB/2048 admitted nodes. Extensions are at most 32,
4 KiB each/16 KiB total. Every known extension's OCTET-contained DER is separately
preflighted, at most 128 nodes, **before** owned decoding. Other OCTET/BIT contents
are not subsequently decoded. SPKI is at most 16 KiB, public-key/signature byte
strings at most 8 KiB each. Parent depth/sibling/sort-work limits still apply.
Conservative owned scratch is below 10 MiB. STOP is polled through admission,
before/after bounded owned operations, hashing and final return, including errors.

Tests build obviously synthetic public DER through the maintained library, with
fake key/signature bytes. A positive candidate test is deliberately **not** a
signature/trust-positive test. No keys, accounts, native calls or network are used.

## Required original native interface — not implemented or enabled

The existing `ios_profile_trust.py` verifies a **provisioning-profile signer**,
not an application's distribution certificate. The fixed macOS
`install_producer.m` trust role is for the installed Developer-ID producer, not
iOS distribution. Existing P12 textual subject/EKU checks and format-only native
`SafeAssessment` cannot fill the gap. Neither role may be widened or relabeled.

The future admitted native owner must consume the candidate's **same captured
DER** while retaining its original capture/operation leases. Before producing
any `CertificateBinding`, that owner needs all of the following:

1. A source-backed supported Apple **iOS distribution** Security policy, with
   chain-signature, actual distribution-purpose and cryptographic-key checks.
   Generic X.509/codeSigning, profile-signing, Developer-ID, provider type/name,
   subject strings or a passed callback are not substitutes. This precursor
   deliberately does not guess Apple marker OIDs or advertise a policy API.
2. Explicit reviewed/pinned Apple anchors and admitted bounded intermediates;
   offline, anchors-only evaluation, no ambient keychain/user trust or network
   fetching/fallback. Require the exact input leaf in the returned chain and
   exact selected trust anchors, actual native statuses and supported trust
   result. Offline issuance is not proof of current account/revocation status.
3. Fresh original-owner wall-clock validity for the leaf and applicable chain,
   plus exact selected team/context and certificate resource/DER correspondence.
   A caller-supplied earlier comparison time is never currentness evidence.
4. Credentials owner's still-current **full** `NativeKeyRef` loan
   (`vault_id`, `generation_id`, `record_id`, `revision_id`, `revision_counter`),
   exact full-SPKI equality to that loan's public key, and any verified PKCS#10
   relationship. No private-key bytes cross into provisioning; P8 API keys are
   not private distribution-signing keys. Hash equality to an untrusted supplied
   CSR is not proof of a key loan or CSR signature.
5. Original native call/capture/deadline/cancellation/finality/close/join evidence
   and final rematches before publication. No worker JSON, result-shaped data,
   reconstructed receipt or cached booleans grant this authority.

The profile remains independently authenticated through both existing CMS
layers and `ProfileCallEvidence`; a qualified certificate alone is not profile
authority. Assignment still belongs to the existing credentials owner.

Root owns the two module hooks in `credential_apple.rs`/`credential_format.rs`,
the actual application graph and all route availability. This module supplies
only a concrete bounded parser/hash precursor. Native distribution trust,
custody/CSR binding, macOS execution and account provisioning remain unqualified.
