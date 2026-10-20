# Closed local Apple provisioning assessment

Base: `56693d2d`. This is a pure assessment/requiredness extension, not native
credential validation, a provisioning runner or a new release credential grant.

## Pairing

- Exact `purpose: "provisioning"`, **explicit** `executionMode: "local"`,
  `platform: "ios"`, `stage: "candidate"`.
- Only `asc-p8`, `apple-p12`, and `apple-profile`. Missing/default GitHub mode,
  other platforms/stages/kinds and unknown values refuse.
- Each request assesses **one kind**. P8 and P12/password can be assessed without
  any existing profile. The profile row is used only for a separate assessment
  of an existing or newly saved profile; it is **not** an upfront creation gate.
- `local_ios_provisioning_requirements` reuses the existing P12/password/profile
  and P8/key-ID/issuer rows. Firebase, build dependencies, review/demo and HMAC
  commitment inputs are excluded. Disabled iOS remains not applicable.
- Generic `requirements` still rejects `purpose="provisioning"`; old
  full/signing/store output and CI/release policy are unchanged. The existing
  signing-row constructor was factored without changing its row data or order.

The unchanged P8 EC/P-256 and scalar policy, P12 envelope and CMS-envelope rules
still describe only supplied input. They do **not** authenticate a password,
private key, certificate chain or profile. Source custody is not established;
native/service validation is not run; release readiness remains unknown. No
fingerprint, restored Bind, saved-record or native-finality proof is minted.

## Root-only integration

Apply `credential-provisioning-assessment-hooks-20261020.patch` after the two
owned Python source edits and new test leaf. Exactly two shared targets:

1. `desktop/src-tauri/src/credential_assessment.rs`: independent private Purpose
   enum; exact context/kind admission before private scalar copies; result pairing
   and six inert regressions. Existing native query/lifetime/assurance unchanged.
2. `src/mobile_release/api/contracts.py`: assessment-only purpose type literal.

The specialist's separate packet owns native `asset_commands::Purpose`, context
and Mac session-kind/loan checks. Root must also compose the corresponding closed
frontend AssetPurpose/protocol pairing. **No old Signing/Store context or loan can
be relabelled.** Reassessment and explicit Bind occur in the new actual context.

The later private P12 extraction still requires the genuine saved
`distributionCertificateSha256` constraint and its original current key/material
loan. These mechanical assessments do not fill or replace that value. The later
native profile NEW/readback/validation/explicit Bind path remains separate.

## Focused evidence

Actual command (in this lane, clean environment, no private material/IO):

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest -v \
  tests.desktop.test_credential_provisioning_assessment \
  tests.desktop.test_credential_assessment.CredentialAssessmentTests.test_all_unions_have_ordered_constant_fields_and_honest_assurance \
  tests.desktop.test_credential_assessment.CredentialAssessmentTests.test_stage_purpose_platform_service_selection_uses_only_shared_requirements \
  tests.desktop.test_credential_assessment.CredentialAssessmentTests.test_local_google_mode_requires_private_observation_without_changing_ci_requirements \
  tests.desktop.test_credential_assessment.CredentialAssessmentTests.test_ios_signing_dependency_token_uses_same_context_and_shared_requiredness
```

**14/14 PASS, 0.145s**: ten new tests plus four affected existing tests. Original
caller joined exit 0. Log: `.task-provisioning-results/python-provisioning.log`.
All values are synthetic observations or fictional scalar fixtures; no key,
certificate, selected file, provider, process or native owner was exercised.

Rustfmt parsed the actual projected Rust source successfully; **no Rust compile
or test was run**. Root's next real graph can select
`credential_assessment::tests::provisioning_` (six tests). No dependencies,
workflow, availability/qualification flag or release validator changed.
