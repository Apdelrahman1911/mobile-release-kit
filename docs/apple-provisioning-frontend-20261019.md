# Bundle-ID registration UI integration

This is the frontend for the separately owned native Bundle-ID operation, not
an extension of Store-access permission. `AppleBundleRegistration.tsx` is new:
the existing `AppleProvisioning.tsx`, `AppleProvisioningProfiles.tsx` and
`LocalStorePreflight` read-only controls stay unchanged.

## Same originals, explicit actions

- `AppleProvisioningController` is held by App, not by the visible panel. Its
  source uses the actual `localStoreProjectObservation` / `localStoreRequest`
  saved-config/version and selected P8 projection. Renderer record IDs,
  revisions and saved labels are comparisons only; native still borrows the
  current original P8, checks its issuer, root, saved inputs and continuity.
- The optional native API has only `prepare_apple_provisioning`,
  `start_apple_provisioning`, `apple_provisioning_status` and
  `cancel_apple_provisioning` RAW commands, with the existing
  `apple-bundle-provisioning-state-changed` event. Preview has no port.
  Requests forbid Access query flags, paths, accounts, journal rows and secrets.
- Prepare is an explicit local action. Root's grantless startup amendment must
  retain/recheck the same Host, Document, Edit stamp, saved source and P8 before
  publishing its original Ready. It must not start an agent endpoint or grant
  CLI access. Mount, navigation and status do not prepare local state.
- Each returned intent has a separate, initially unchecked one-use Start
  consent. Read review, one new-app registration and read-only reconciliation
  use different native consent versions. The UI's 60-second allowance begins
  before its original Prepare invocation, not after a delayed reply.
- Register additionally needs the explicit new-application declaration and
  the exact current original reuse-first review. That UI reference is consumed
  even if Prepare fails. Only native owns the private review lifetime, actual
  account-wide unresolved-attempt fence, durable Pending ACK and one POST.
- Start's read consent describes the fixed local journal initialization/upgrade
  if needed. Root places it inside the existing retained Initialize job, after
  NativeUse; local consent never turns a read query into write permission.

## Retention and honest results

The controller retains the API/listener, original Prepare/Start, status and
Cancel promises. A terminal event cannot settle an outstanding invocation.
After the invoke joins, a new original status read is required before displaying
its result or deriving the UI review reference. Equal-revision contradictions,
unconfirmed calls, foreign replacement and native Unknown remain sticky; a
reconnect or hidden panel cannot erase them. Context/key/name changes retire
consent and request the original cancellation without replacing its owner.

The completed review reference is conservative comparison DATA with a maximum
five-minute UI lifetime. The exact prior registration reference supports only
readback in the same saved/key context. There is no cross-restart attempt
enumeration or “clear unknown” control in this first UI. Missing history is not
absence and cannot authorize retry. Native journal/transport settlement remains
independent from a provider outcome.

Found/not-returned/denied/inconclusive and registration-confirmed/unconfirmed
are distinct. Not-returned concerns this selected key, not global availability.
Configured team text is not team evidence. Completion never means a usable
private key, certificate, authenticated profile, App Store listing, signing
assignment, build or release readiness. Certificate/profile/CSR generation is
not offered by this UI.

## Root-only composition

`apple-provisioning-frontend-hooks-20261019.patch` changes only four frontend
paths: `App.tsx`, `bridge.ts`, `types.ts`, `pages/Dashboard.tsx`. It was generated
against Root `451c989c` frontend sources; its navigation hunk was refreshed for
Root `7d49e8b9`, preserving the original Android tool-setup visibility call.
No actual shared source was edited here.

- App retains the one controller and subscribes to actual saved-version/key
  changes before bootstrap. Existing peer busy gates include Apple; Apple's
  own gate excludes only itself. Peer-state reprojection does not renew consent.
- Reconnect, workspace/version/selection intents, before-unload and disposal
  preserve the original controls and request its original cancellation.
  Idle status reads also retain reciprocal ownership until they return. A clean
  retired port cannot start a fresh read during reconnect; genuinely retained
  work or unknown cleanup keeps its original status controls.
- One optional Dashboard disclosure holds the full UI. Elsewhere, retained
  original status/cancellation stays visible in its compact panel. Failed or
  unconfirmed outcomes keep the Dashboard section open. No setup-readiness
  observation or status is manufactured from this operation.
- Bridge adds the fixed event and optional API factory only. There is no new
  shell command, process, transport, dependency or native availability flag.

## Verification boundary

Author command (Node 24, no emitted files):

```sh
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 \
  desktop/tests/apple-provisioning-protocol.test.mjs \
  desktop/tests/apple-provisioning-controller.test.mjs
```

**23/23 passed**, zero skipped/cancelled, 243.013093 ms. These use the complete
new TypeScript modules, existing saved-input helper and synthetic native API
promises only. They cover exact bounded grammar, separate consent, one Start,
native project-ID grammar, peer re-projection, delayed/event/read/reconnect races, source invalidation, retained
unknown/cancel/disposal and exact readback references. No native process, Apple
account, real credential, private state IO or provider call ran. The hook patch
applies to current Root sources; its four complete temporary outputs were
checked and removed. Actual integrated TypeScript/React graph and installed
Mac/provider qualification remain Root work, not established by these tests.
