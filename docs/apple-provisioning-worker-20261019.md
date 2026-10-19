# Bundle-ID worker on the original SavedCommand engine

This packet implements the worker half of the separately consented Bundle-ID
registration flow. It is **not yet a native/installed operation**. The existing
read-query flag, Store release commands, private signing-key/CSR owners and
credential-ready projections are unchanged.

## Actual reused owners

`AppleProvisioningRun` uses the actual Store source readers, online
`InvocationCustody`, `FiniteScratch`, selected P8 material reader/validator,
`StoreRuntimeContext`, five pinned runtime probes, and `run_owned` C/A/W. It
does not subclass the Access run to obtain its authority. The patch adds one
exact source/domain to the existing input, cancellation, engine, material and
command rosters; other domains keep their old grammars and command limits.

The only provider helper is the accepted
`fastlane/apple_provisioning_bundle_registration.rb`. It uses the existing
scoped SDK transport and original raw-before-JSON response capture. No project
command, release Fastfile lane, profile/certificate request or capability
mutation is admitted.

## Closed operation/ACK protocol

`mrk-apple-bundle-provisioning/1` has Review, Register and Reconcile modes.
The new context retains the existing saved-config/version and selected-record
descriptors, an explicit display label, an original review/row reference and
Register-only `newApplication:true`. Native must retain the actual review,
consent, full selected credential loan and continuity veto; these fields are
comparison DATA, not a source of those authorities.

Private context/target/attempt DTOs use the Service journal's exact member
names. Register reconstructs the empty Bundle-only observation and all three
plan/request hashes with the original review timestamp. It repeats a fresh
GET and refuses a changed observation. Review returns bounded private metadata;
native may retain it only after all original joins. A stored row is accepted
only for **read-only comparison**, never restored send/native-finality authority.

Request cap 64 KiB; aggregate output 128 KiB; each intermediate event 16 KiB;
ACK 2048 bytes. The request digest is SHA256 of the **exact original native
encoded request including its newline**, not a second JSON serialization.
The three Register events are `pending`, `attempt`, optional readback `attempt`.
Each ACK binds original operation/generation/nonce/request digest, exact sequence,
next namespace revision and SHA256 of the complete `AttemptUpdate`. Hashes and
sequence counters do not establish durability or native joins.

Native must arm/install its journal job before effects and send ACK only after
the actual durable CAS/readback, original job join and current consent/source/
account checks. The worker consumes the first ACK once before POST. Foreign,
lost, late or failed ACK never authorizes a send/retry. Child terminal success
does not make `nativeSettlement` known or retire NativeUse.

## Timing and limits

Original native A/W/H must include admission, queue and material wait. W=A+1200s,
H=A+1210s; the worker uses supplied raw-uptime endpoints only to tighten its own
deadline. Each provider command is capped at 60s and original remaining W; the
P8 validator is 30s. Review/Reconcile have at most seven commands, Register nine
(P8, five probes, fresh GET, one POST, optional GET). Each helper has a new
finite scratch owned by the same operation; no command is repeated.

The first actual failure is retained. Forward work stops at F. Only an
already-armed journal update can drain its original ACK before min(W,H,F+10s),
and never under fatal/unknown input or scope custody. Terminal output is bounded
by min(H,F+10s). An interrupted existing runtime cleanup can legitimately leave
the original ledger fatal: the worker preserves Unknown/Pending rather than
inventing a known cancellation. Parent remains responsible for its independent
STOP, cancellation journal update, provider/source/material/driver/manager joins,
pre-final-CAS witness, final CAS join and separate all-jobs receipt.

Representation caps are not native RSS/FD/descriptor admission. The parent must
charge actual extra scratch, event/request/ACK and full Service journal job
backing using its existing census. No new resource-qualification framework is
introduced here.

## Verification and remaining integration

`tests/unit/test_desktop_apple_provisioning.py`: **15 PASS**, 2.093s. Tested all
complete original shared modules after the seven-file patch, not extracted
functions. Test fixtures use actual small local files, held pipes, original
input/engine/STOP and scratch cleanup; provider, C/A/W ledger outcomes and
native journal ACKs are explicitly fake. No Ruby/OpenSSL, network, real keys,
native Store, provider or installed account acceptance was exercised. Command:

```
PYTHONPATH=<temporary patched complete src> PYTHONDONTWRITEBYTECODE=1 \
python3 -B -m unittest -q tests.unit.test_desktop_apple_provisioning
```

Pending: native domain/context and actual selected-material/SourceBook admission;
Service journal jobs on the same NativeStateLease outside Doc/Host locks;
genuine witnesses/NativeUse retirement; fixed installed bootstrap and runtime
roster/packaging; native review/consent/currentness and UI. The existing portable
witness types have **no constructors** until the actual parent cut is implemented.
