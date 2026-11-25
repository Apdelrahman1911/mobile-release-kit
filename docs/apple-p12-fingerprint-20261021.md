# Saved P12 certificate fingerprint → Settings draft

Base: `78a93478164418a6f7f0fcb38f5dcf1b27f778e7`.
Independent PLAN review: Versions accepted the same-owner, public-DATA handoff.

## Scope and source

- `desktop/src/appleP12Fingerprint.ts`: pure provisional view and an explicit
  one-field ordinary draft edit, not a new controller or native operation.
- Existing `components/AppleP12Setup.tsx` / `AppleBundleRegistration.tsx` display
  the public SHA-256 and offer **Add fingerprint to Settings draft**.
- Existing `desktop/tests/apple-p12-setup.test.mjs` gains nine cases using its
  actual Apple controller/RAW status fixture and the real workspace reducer.
- `apple-p12-fingerprint-hooks-20261021.patch`: **App.tsx only, nine additions**.
  Reuse the existing local draft-admission context, pass the view/click callback,
  and navigate to Settings only after the reducer actually changes the draft.
  No reducer, settings controller, native/protocol, package or availability edit.

The source is the original controller's joined Start + subsequent terminal
read, exact `p12-save` complete/none, strict `assembled` result and separate
NEW `savedP12` reference. The current status must carry that same result/ref.
An output alone, saved reference on a cancelled outcome, or a later withdrawn
reference cannot supply the handoff. The public fingerprint can remain visible
as historical DATA; a historical result cannot edit the current project.

## Intent/currentness and ordinary save

Rendering has no effects. An explicit click rechecks the original controller,
service object, project session, epoch and status, calls that same controller's
`syncProject()`, then recaptures/rechecks **after its synchronous listeners**.
A source change, pending read/invocation, Unknown, cancellation, service/project
ABA, conflicting draft or changed status refuses without a draft edit.

The target is only `ios.distributionCertificateSha256`. The current project
must have a clean, nonstale observed draft and matching saved-config comparison,
revision/baseline, path and catalog text field. Only an absent or literal-empty
value is filled. Exact valid hex/colon syntax is normalized **only to compare**
an already-equal value; existing values and formatting are never replaced.
Malformed, whitespace, null or conflicting values remain for manual review.

The existing App dispatch retires original comparison contexts before the real
workspace reducer. Its existing `expectedSession` check protects against a newer
draft created reentrantly during retirement. The baseline, saved observation,
prior review and `lastSave` are not rewritten. Prior review freshness expires
normally when the draft revision advances. The user then explicitly reviews and
saves through the unchanged Settings/ConfigEdit flow. Nothing assigns a P12,
starts a native check, saves automatically, exports private bytes or claims
signing/revocation readiness.

## Author evidence and limits

- Node 24.20.0, existing P12 test file: **23 passed, 0 failed, 0 skipped**,
  1365.264 ms (14 existing + 9 new), `.task-p12-fingerprint/node.log`.
- Whole frontend `tsc --project desktop/tsconfig.json --noEmit`: **exit 0**,
  using the existing dependency cache and the exact App projection;
  `.task-p12-fingerprint/tsc.log` / `tsc.exit`. Task-only dependency link removed.
- Whitespace and Root patch applicability checked separately at freeze.

No DOM/user-journey execution, Cargo/native/Keychain/provider calls, new trust
binding, live Apple qualification or unknown-save recovery is claimed. The
existing P12 producer and native finality remain the only source of its actual
saved result; synthetic component tests do not qualify Apple trust.
