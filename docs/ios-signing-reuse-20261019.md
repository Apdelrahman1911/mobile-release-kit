# Existing iOS signing-input check

This packet adds one closed mode to the **existing IOSArchive owner, runtime,
worker, private-material borrower and app-owned controller**. It does not add a
runner, bootstrap, provider, credential store, certificate binding or signing
installation. Service independently reviewed the plan.

## Entry and meaning

The existing Releases iOS component offers **Check existing signing inputs**.
Its four existing native commands remain unchanged. Prepare carries the exact
saved config/version and selected signing assignments with
`action: "check-signing"`; native context uses
`operation: "ios-signing-inputs-check"`. Start requires its own one-use
`saved-ios-signing-inputs-check-v1` consent. The original review lasts at most
60 seconds; status never renews it.

The check uses only the assigned P12/password, primary App Store profile and
saved-required iOS Firebase file. Neither a required nor an available
project-read token is borrowed. It does not require an Xcode project/scheme and
does not run saved preparation, archive, export, symbol upload or project code.
The old unsigned/signed/candidate/recovery paths retain their original defaults.

The result is historical `local-ios-signing-inputs-validation` DATA: checkedAt,
exact used config/version/signing references, fixed finding codes and limits.
No private bytes/messages, artifact path, new assignment, readiness, current
private-key proof or `CertificateBinding` is returned. Public inventory and
format assessment do not supply this result. The existing validator's
profile-scoped checks are not a new standalone distribution-trust authority.

## Original path and lifetime

1. Original Document/IOSArchive Prepare and Start gates retain the selected
   native context and same immutable P12/profile payloads. The native borrower
   rejects a check-mode project-token role before borrowing its scalar.
2. Same `IOSNativeBooks`/`IOSArchiveRuntimeSlots` inspect the packaged worker.
   The existing tool Book has a distinct check-only receipt for exactly four
   originals: `/`, `/usr`, `/usr/bin`, `/usr/bin/openssl`. Full-Xcode,
   IPA-validation, upload and recovery receipts cannot stand in for it.
3. Same original source/material request and private frame flow admit the
   account/project leases. The worker enters check-only **before** archive
   namespace creation, materialize_build_inputs, Xcode or SigningSession.
4. Actual `credentials.validate_signing_material` owns its existing
   `FiniteScratch("signing-validation")`, selected bytes, P12 certificate and
   private-key extraction, public-key equality, fingerprint/team/distribution
   policy and authenticated profile/bundle/member/validity checks. Private
   extraction into that owned scratch is necessary; it is not a no-file-read
   inspection. Required Firebase uses the same existing validator.
5. At most seven fixed OpenSSL calls and one logical profile-load evidence are
   admitted. That one load retains **both CMS producer originals** plus its
   reader/decode evidence; its count is not proof that those originals closed.
6. Native Start fixes W=300s and H/cleanup=310s. First failure/STOP tightens all
   settlement to min(original H, F+10s), never signed-export F+120/F+130.
   Child-local work and per-command limits cannot extend that native ceiling.
   Existing command/profile evidence, private scratch, input, handlers, leases,
   descriptor books, child/IO/driver/observer joins and material retirement
   remain mandatory. Unknown is retained; no automatic retry or reset.
7. The same controller retains original invoke/subscription/status custody and
   the same project, saved observations and assignment revisions. Separate
   unchecked consent is required. The main view keeps purpose, inputs, actions
   and consent visible; detailed lifetime/reference explanations use ordinary
   collapsed help. Changed or lost inputs retire the review;
   later status cannot supply new consent. Final result is withheld until the
   existing native terminal path finishes, not at Python's provisional result.

## Root-only integration

Apply `ios-signing-reuse-hooks-20261019.patch` after these additive files. Its
17 original paths are six Python worker/control/selection/protocol files,
seven Rust protocol/owner/tool-book/borrower/test/fixture files and four existing
frontend type/protocol/controller/view files. No App, bridge, shell, lib,
manifest, dependency, generic permission or bootstrap change is needed.

The source projection was based on Root cb6e7c46; these relevant originals were
unchanged at Root 6e0104cb. The exact patch also passed apply-check at
Root bdd39bdb, preserving its intervening independent owner changes. It uses **Root's exact cb6e7c46 credentials parser**,
not a second parser patch or fake-output normalization. Packaging uses the
existing Python package and IOSArchive runtime roster.

The outer native status remains schemaVersion 2 with an explicit optional
`modeCapabilities.signingCheck`. Missing means unavailable; native emits it
explicitly. It defaults **false**, including existing installed-observer masks.
Only genuine mode-specific native qualification may enable it; the old
signed-export or format-validation gate is not borrowed. The complete source
route/UI is present but no installed/native acceptance is claimed here.

## Focused evidence and remaining gates

- 16 Python tests passed in 0.134s on the complete composed actual package with
  the exact Root fingerprint fix. Six closed-protocol tests, six inert original
  owner/wiring tests and four actual-validator/tiny-private-scratch tests. CMS
  and OpenSSL results are explicit synthetic fakes, not real P12/key/cert data.
  Defects cover password, key, fingerprint, team, purpose, lifetime, profile
  bundle/member/expiry and original interruption; 5/7-call paths are checked.
- 9 Node tests passed in 238.478472ms on the complete actual TS controllers and
  protocol with fake ports. They cover no-Xcode entry, role denial, separate
  capability/consent, original one-minute expiry, assignment drift, lost ACK,
  unknown retention, result limits and required-only Firebase.
- Eight Rust tests are authored, **unrun**: six DATA codec/result tests and two
  actual inert original-Session mode/first-STOP/unknown tests. Native Book paths
  are source-inspected only. Rust syntax parsing is not compilation.
- Root must compile the actual combined Rust/TS graph and run its selected
  tests. Mac Security/tool/worker/installed qualification remains separate.
  No native operation, real private input, network, provider or build was used
  for this packet's verification.

Normal integrated commands for the two new passive suites:

```sh
PYTHONPATH=src python3 -B -m unittest discover -s tests/unit -p test_ios_signing_reuse.py -q
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 desktop/tests/ios-signing-reuse.test.mjs
```

Author execution used the complete temporary `after/src`/`after/desktop` source
composition, not extracted function bodies or substituted production modules.
Outputs were returned by the tool; no test log has been retrospectively minted.
