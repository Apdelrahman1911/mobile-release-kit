# Continue a recorded Apple profile attempt

This slice adds historical **profile** selection beside the existing Bundle-ID
history. It does not resume a save, restore a key loan, retry a POST, or settle
the earlier operation from recorded data.

## User flow

1. Open the same saved app, unlock storage, and assess/select its existing P12
   and App Store Connect P8 in **Set up Apple signing**.
2. Prepare and explicitly authorize the existing signing check. Only its actual
   completed original read can publish matching local history—even when the
   provider decision is blocked by an earlier pending attempt.
3. Choose **Review read-only check** for a recorded attempt. That explicit choice
   adopts its old display name and reference, not its key or save authority.
4. Separately authorize the existing `profile-reconcile` operation. Its current
   native input repeats exact account, stable project/full root, P12 reference,
   target and prior-reference comparisons. Existing GET-only worker code is
   unchanged. Missing or denied readback never permits a new creation request.

Provider, encrypted-save and native-cleanup history are displayed separately.
Recorded readback is not a newly saved/assigned credential. Other unresolved
contexts remain hidden but still block the account. Unknown original work keeps
the same status/cancel controls; history cannot dispose or replace that owner.

## Root hooks and composition

Apply `apple-profile-recovery-hooks-20261020.patch` (eight targets). No new IPC,
runtime profile, capability flag, journal schema or process owner is introduced.
The optional `profileRecovery` field is omitted except on a genuinely retired
ProfileReview. Publication requires the original INITIAL account return, all
native job joins, completed profile parent and existing positive retirement cut.
Context invalidation withdraws it at the existing status revision; terminal DATA
cannot replace or revive it. New backing is explicitly charged by the original
Document census. Original Bundle outputs and same-session profile controls stay.

The new native projection calls the existing Bundle `recovery_history` for the
complete-account joint-32/duplicate/unresolved census, then moves only matching
profile rows from hidden to visible. Apple's parallel key-v3 integration must
extend that existing census for key/certificate rows; this slice inherits it and
does not separately parse or modify those families. All key-v3 parents remain
Apple/Root-owned. The eight-hook patch is against preserved Root source; Root
must retain any concurrent package test entries and controller additions.

## Focused verification

- Complete existing controller + strict parsers: **7 new Node cases passed**;
  **20 affected existing profile/Bundle-history cases passed**, no skips.
- New fixtures cover restart, explicit selection and separate Start, terminal
  event before invoke return, synchronous newer drafts, P12/API/saved ABA drift,
  peer gates, absent/withdrawn/contradictory history and sticky lost ACK.
- Whole projected current frontend TypeScript check passed, using existing
  dependencies. Initial source projection omitted the seven existing preview
  JSONs and mixed a concurrent Git service type change; copying a consistent
  committed dependency graph fixed those projection errors. No product policy
  was relaxed. Initial new test fixture omitted the existing storage capability
  fields; adding its actual inert shape fixed the fixture, not production code.
- Three pure Rust projection tests are defined but **not run here**. They check
  exact native-scope comparison DATA, separate axes/account fences, privacy and
  the full bounded roster. `rustfmt` parsed/formatted only the new Rust leaves.

Commands on the retained complete-source projection:

```sh
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 desktop/tests/apple-profile-recovery.test.mjs
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 desktop/tests/apple-provisioning-recovery.test.mjs desktop/tests/apple-profile-setup.test.mjs
node /path/to/existing/node_modules/typescript/bin/tsc --project desktop/tsconfig.json --noEmit
```

Root still owns integrated Rust/TypeScript verification. No native Mac, provider,
credential, GUI automation, signing, installation or availability claim follows
from these inert/source checks.
