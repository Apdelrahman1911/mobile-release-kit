# P12 continuation on the existing Apple setup owner

This frontend-only slice adds the missing saved-key/certificate → P12 step.
Existing `CredentialSession` already provides private import, exact-record
assessment/assignment, encrypted backup and restore. Those controls, pickers,
private forms and their original `AssetSessionController` are unchanged.

Apply `apple-p12-frontend-hooks-20261020.patch` only together with Cleanup's
matching native P12 increment. There is no new availability flag, bridge,
transport, asynchronous owner or native qualification here.

## Interaction and authority

- The same certificate key chooser supplies the explicit current encrypted
  key ID/revision. A P12 may be reused only from the actual current bound
  Provisioning assignment. A stored row is not an assignment; an unavailable
  assignment never falls back to new assembly.
- The existing four RAW Apple commands gain only `p12-review`, `p12-reuse`,
  `p12-save`, with their exact `local-ios-p12-…-v1` consents. Prepare requires
  the nullable P12 pair; native status omits that pair when absent. Only that
  mode-specific representation is normalized for original-context comparison.
- A genuinely completed original review chooses reuse **or** one new save.
  The same source/P8/key/P12/name/API/epoch witness and original conservative
  300-second review age survive into a separate unchecked, one-use consent.
  Lost Prepare/Start never restores it. No action runs on mounting or selection.
- The same Action/Read/Cancel slots retain their original promises and listener.
  Terminal events cannot publish success before the invocation and subsequent
  status return. `assemble-apple-p12` is the actual Asset operation, not a
  relabeled use-key status; its retained-input helper is correlation-only.
- Result/output metadata always says `p12Saved:false`, `profileSaved:false`,
  `credentialReady:false`, `revocationChecked:false`. The optional `savedP12`
  is separate native detached DATA from actual NEW save, full readback and
  retirement. Known stopped-but-saved is shown with the original failure.
  Complete output without that marker is not saved/ready or a retry right.
  A later original status may withdraw, but not replace/recreate, that marker.
- Open saved credentials is navigation only. Assessment, assignment, backup
  and restore require their existing separate explicit actions. Restoring a
  new unassigned copy does not clear an earlier uncertain save. No P12 history
  adoption/reconcile/reset API exists in this increment; original status and
  cancellation remain the honest available controls.

## Exact composition

New source: `appleP12SetupProtocol.ts`, `components/AppleP12Setup.tsx` and
`tests/apple-p12-setup.test.mjs`.

The nine hook targets are:

1. `assetSessionTypes.ts`: the single real native operation literal.
2. `assetSessionProtocol.ts`: its existing save-family phase/storage restrictions.
3. `appleDistributionKeySetupProtocol.ts`: same-started P12 input correlation.
4. `appleProvisioningTypes.ts`: closed P12 modes/result/saved comparison types.
5. `appleProvisioningProtocol.ts`: strict request/status/result grammar.
6. `appleProvisioningController.ts`: one additional input/review family on the
   existing owner, with all old Bundle/profile/key/certificate paths preserved.
7. `components/AppleBundleRegistration.tsx`: one mounted P12 child and labels;
   the existing shared status/cancel controls remain once and visible.
8. `App.tsx`: preserve attention for unresolved save/output/account-pending.
9. `package.json`: literal new test entry; retain all other test entries.

Native contract sources: `apple_provisioning_p12_protocol.rs`,
`apple_provisioning_p12_journal_data.rs`, and
`asset_session_apple_p12_input.rs` in the `apple-p12` lane. Source P12
references can have revisions above 1; a new `savedP12` must be revision 1.
Output framing metadata is bounded to 1 MiB P12 and exactly 84 header bytes;
no frame, certificate/private bytes or password enters this renderer.

## Verification and remaining limits

Root approved the slice; Credentials independently accepted the plan.
Tests used a finite, task-owned projection of the actual complete frontend
plus these nine hooks, not stub controllers:

- 14 distinct new inert cases passed. The initial null-prototype comparison
  fixture was corrected without changing the parser; its failure is retained.
  The changed and additional cases were rerun narrowly, not a repeated suite.
- 73 affected existing Apple controller/protocol cases passed, zero skips.
- Whole composed TypeScript `--noEmit` passed with existing dependencies,
  768 MiB and a 120-second bound. The first projection lacked three concurrently
  integrated Git permission leaves; that failure and the final success remain
  in `.task-p12-ui`. No dependencies were installed.

Standard focused command after integration:

```sh
cd desktop
NODE_DISABLE_COMPILE_CACHE=1 node --experimental-strip-types --test \
  --test-isolation=none --test-concurrency=1 tests/apple-p12-setup.test.mjs
```

There was no native/Store/Apple, real key/P12, picker, network, build, Cargo,
DOM or CI execution. Native P12 integration/qualification is separate. This
does not establish signing, profile suitability, revocation or release readiness.
