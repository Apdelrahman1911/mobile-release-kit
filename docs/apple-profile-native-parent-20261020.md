# Existing Apple signing identity → provisioning profile

This packet connects the existing Apple provisioning Session, Store runtime,
profile journal and vault facet. It does not enable a qualification flag. Rust
and installed-Mac execution remain Root's responsibility; source/parser tests
are not evidence of usable signing credentials or a successful Apple operation.

## Integration

Apply `apple-profile-native-parent-hooks-20261020.patch` to Root's shared files.
It was composed against `649ee310f16ab32317f590b256c827ef7ffcf68f` and includes the
nine already-reviewed facet hooks from `d2598c05`. Its 39 target files
include the one literal addition of `tests/apple-profile-setup.test.mjs` to the
existing Node test script; no new test runner or repeated test invocation. Integrate that commit's six
implementation/test leaves, but **do not apply its old hook patch separately**.
The new parent leaves in this packet and its shared hooks are reviewed together.
The accepted profile core (`7009f6c8`) and schema-2 journal (`ec7e750d`) are
prerequisites, not replaced by this packet. Existing Bundle, certificate-helper,
current-version and native upload-key changes are preserved.

Root composes only the supplied hooks; the protocol, worker, native lifecycle,
private receiver, original source checks and UI/controller behavior are supplied
here rather than left as proposed future Root implementations.

### Owned leaves

- `saved_command_apple_signing.rs`: actual original Session state, PendingAck,
  SavePermit, NoSaveJoined and fixed before/after-final-journal cuts.
- `saved_command_apple_profile_{clock,private,native,review}.rs`: shared clock,
  private stdout receiver, finite original journal jobs and detached result DATA.
- `asset_session_apple_profile{,_input,_material}.rs` and
  `credential_apple_profile_source.rs`: same Asset job/child/coordinator, current
  P8/P12 loans, exact source checks and NEW destination.
- `apple_provisioning_profile_protocol.rs` and its test child: closed profile
  modes and one native public-identity comparison phase.
- `_desktop_apple_profile_{control,private,protocol,worker}.py`: same protected
  Apple worker, current private material, fixed helpers, original CMS and trailer.
- `appleProfileSetup.ts`, `components/AppleSigningSetup.tsx`: result/input DATA
  and beginner-facing controls on the existing Apple controller.
- Focused Python, Ruby and Node tests listed below.

Shared protocol/owner tests add mode dispatch and actual inert Session checks;
existing fixtures receive only the new optional scope/state fields. The quoted
native backing limit includes the added bounded representations, not RSS.

## User flow and scope

1. “Set up Apple signing” selects the explicit local/iOS/candidate/Provisioning
   credential context. It does not reuse Store/Signing loans. The user selects
   the existing encrypted P8 and P12/password and saves the configured expected
   distribution-leaf SHA256. Manual import remains available.
2. Prepare and separately consent to **Review existing signing**. The existing
   grantless local state preparation is reused. This read never generates a key,
   creates a certificate or saves a profile. It checks the current P12 identity
   and complete bounded provider inventory.
3. A fresh, positive, originally settled Review may offer **Reuse this profile**
   or, only when no suitable profile is returned, **Create a profile**. Each has
   its own one-use Start consent. Creation is one supported App Store profile
   POST, never certificate issuance, quota-consuming rotation or revocation.
4. The returned profile is authenticated with the existing strict modern
   App Store profile policy/CMS owner and saved to one reserved NEW encrypted
   profile record. Full authenticated readback precedes saved-reference DATA.
   **Saved is not assigned or release-ready**; existing inspect/Bind and signed
   preflight remain required.
5. Same-session **Check previous request** performs only read reconciliation.
   It cannot resend POST, restore a live save token, adopt a destination or clear
   provider/native/save uncertainty. Persisted unresolved profile rows continue
   fencing both action families after restart. This packet does not add a
   profile historical-row selection UI or treat missing history as absence.

Initial automation supports the modern team-prefix, basic App Store profile
case (`entitlements = {}`). Additional app capabilities, unsupported legacy
prefixes, incomplete inventory, account restrictions and absent matching
Distribution identity remain actionable manual/refusal states. No metadata
count or generic code-signing chain becomes a CertificateBinding.

## Original lifetime and private boundaries

- The SAME SavedSession is retained before attaching the Asset original or
  reserving a destination. Its original W=1200s/H=1210s and earliest F are shared
  by the fixed Asset work; no phase renews a deadline. Cancel/context loss/quit
  tighten the original audit/cleanup endpoints.
- Private input is the same current P8/key-ID/issuer plus P12/password (five
  original fields only for profile modes). The fixed bundled Ruby helper uses
  two original 0600 scratch files, never a password argument/environment or a
  host Ruby/OpenSSL fallback. Its response contains only public DER/SPKI/chain.
- The worker performs pinned offline chain validation. One identity phase on
  the EXISTING reader/writer compares the maintained native X509 candidate,
  exact full SPKI, leaf, expected hash, team, full key reference and clock. Fresh
  ASC Distribution type plus byte-identical DER is additionally required by
  the worker. Syntax/identity ACK alone is not native trust or POST permission.
- All collections must satisfy the accepted complete/unique/scoped inventory
  policy. At most two pages per collection, no auth-error fallback or retry.
  A sparse successful POST retains its exact ID and gets that resource once;
  it never manufactures a usable profile from the sparse response.
- Pending is durably ACKed before the one POST/download save operation. The
  same schema-2 account namespace fences Bundle and profile attempts. Restored
  JSON cannot recreate OriginalReservation, NativeUse or reserved-vault tokens.
- At most 1MiB of profile bytes follows the exact private trailer header on
  the SAME stdout stream. Native receive storage is retained before GO; exact
  request/hash/length/EOF and original pipe/driver/worker returns are required.
  No profile bytes, P12/password or private key enter public status/events.
- After original producer/consumer returns, current source checks and durable
  SaveArmed ACK, the existing Asset child may perform fixed NEW/full readback.
  Save/readback/coordinator return precede NativeJoined and final journal CAS.
  All journal jobs (including final CAS) precede native-use retirement; that
  retirement is itself joined before final private cleanup/publication.
- Final CAS does **not** await future Asset private-empty. After the parent
  proves no more work, the existing same-slot Release continuation closes the
  actual StoreBook. Only its true return/settlement permits retained private
  disposal. Known late Stop does not undo a Published NEW or prevent cleanup;
  the operation's failed/cancelled disposition is preserved.
- NoSaveJoined is cleanup-only and requires the real save slot never entered,
  all worker/receiver/journal/native-use returns and the exact destination's
  independent no-seal/no-claim/no-intent/no-outcome checks. Unknown save/close
  stays retained. A staged Refused or Committed-without-Bind remains in its
  original slot while the proof-gated Release continuation runs; no generic
  staged-work exception or status-based closure was added.

## Bounds and runtime source roster

Profile-only P12 input is capped at 4MiB (global P12 limits are unchanged), P8
16KiB, original stored password 4096 bytes. Identity phase is 128KiB, aggregate
profile JSON 256KiB, private profile trailer 1MiB. Old Bundle/public limits stay
unchanged. The original census includes simultaneous input/receive, decoder,
identity ACK, journal raw/typed/encoded/readback and crypto representations;
these limits are not a claim about SDK/process RSS.

All three literal runtime/packaging rosters include the missing fixed
`apple_provisioning_bundle_registration.rb`, `apple_provisioning_signing.rb` and
`apple_provisioning_p12.rb` as applicable. Root's certificate/key/current-version
helpers remain listed. `Gemfile`/lock/dependencies are unchanged: fresh tooling
composition/runtime manifest/app build is required, not a new gem installation
or re-signing the unchanged native Ruby/gem component merely for Ruby source.
Real fixed-helper/runtime and native operation qualification is still required.

## Focused evidence and remaining gates

Author ran only local synthetic checks, with all tool callers joined:

- New protected-worker tests: **9 passed**, 3.225s. Actual engine, invocation,
  scratch and FD streams; fake C/A/W, native ACK, chain/CMS and provider results.
  `PYTHONPATH=<composed src>:tests/unit python3 -B -m unittest -q tests.unit.test_desktop_apple_profile`
- New fixed ReadOwner integration: **2 passed / 47 assertions**, 0.021s, fake SDK.
  `ruby tests/workflow/test_apple_profile_read_owner.rb --name '/AppleProfileCurrentReadOwnerTest/'`
- New profile controller/parser tests: **10 passed**, 335.898ms. Existing three
  Apple Node suites: **33 passed** in the preceding combined run. Its sole new
  test failure was a null-prototype expected-object assertion, corrected in the
  test; only the ten new tests were rerun afterward. Production was unchanged.
  `node --test desktop/tests/apple-profile-setup.test.mjs` (composed actual TS).
- Rust source syntax: original ten leaves + twenty shared files parsed; final
  rebase's 21 changed shared Rust files also parsed with rustfmt/edition2021.
  No Cargo, native framework, real P12/key/CSR, network/provider or Store write.
- **14 new Rust tests are authored, not run**: six closed decoder/identity DATA,
  four private framing/unknown, two real Slot cleanup guard DATA, one actual
  Terminal mode dispatch and one inert original Session clock/refusal test.
  They do not fabricate positive native key/chain/source/journal join proofs.

Root must run the integrated Rust/TS graphs and exact tests. Installed Mac
positive NEW+readback+late-STOP→Release→quit, true joined NoSave→Release→quit,
unknown/lost-input negatives, genuine private/source/CF/child containment and
runtime/tooling qualification remain outstanding. No feature flag is activated
and no source-only receipt is reported as those successful native operations.
