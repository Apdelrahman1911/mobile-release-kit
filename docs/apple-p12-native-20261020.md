# Apple P12: fresh verification, reuse, or one NEW local package

## Scope and status

This is the native/core companion to frontend commit
`6a95e7490ff488a043e03b55c2a4593abb7bb2ad`. It depends on the accepted certificate
implementation `e307a4adcffc8e345a9c36b51ea1a7225054bcc5`, including its actual
same-worker `AppleDistributionCertificateBinding`. Neither an earlier certificate
operation, UI selection, journal row, nor a certificate hash creates that binding.

The operation is **network-read signing setup**, not offline setup: each explicit
review/reuse/save freshly reads the supported bounded ASC signing inventory. It
does not issue/revoke a certificate, generate/replace a key, create a profile,
upload a release, or change a signing assignment. The sole optional additional
effect is packaging the already stored key into one encrypted PKCS12, followed
by a NEW encrypted vault record. A saved result is **saved-unassigned**, not
sign-ready or backed up.

Source and synthetic tests are not Mac qualification. No native/provider/Keychain
operation, Cargo build, CI dispatch, or availability flag change was performed
for this packet. Integrated Rust/Mac compilation, actual save/cancellation/quit,
and the ordinary assignment/backup journey remain verification work.

## One original operation

* Three closed modes: `p12-review`, `p12-reuse`, `p12-save`, with exact
  `local-ios-p12-*-v1` consent. They use the existing four Apple commands and event,
  current local/iOS/Candidate Provisioning context, saved input/root custody,
  same selected P8, same AppleKeySession and original eleven native job slots.
  No new process owner, generic callback/executor, IPC grant or permission exists.
* Prepare requires the selected key record pair and explicit nullable P12 pair.
  A supplied P12 must be the genuine current bound AppleP12 in the same vault/key/
  context; normal existing Load/Assess/Bind is not bypassed. Its bounded original
  bytes undergo the actual fixed P12 extraction and same-operation certificate
  policy/full-SPKI match. Unrelated P12 rows neither block nor get decrypted.
* Review retains one-use original input/selection comparison and an expiry capped
  by original admission plus 300 seconds. A later explicit reuse/save freshly
  loads/checks the stored key and repeats GET/policy verification. Reuse requires
  the still-current selected assignment. Save requires no selected P12 and a
  matching unconsumed assembly review. Relevant prior same-key/package hints
  require selection/reassessment instead of an implicit duplicate save.
* The existing CertificateSteps is reused only for fixed verifier, complete GET,
  native identity and explicit-root policy phases. Its create/authorize/POST/run
  path is not invoked. The sole certificate child factors its existing positive
  joined producer; P12 does not construct a fake CertificateResult or holder.

## Packaging and NEW publication

1. The same real Asset coordinator opens the original stored-key loan and checks
   current P8/key/optional bound P12, original Store witnesses and complete bounded
   inventory. For save only, it reserves a fresh record/random revision/counter 1
   and native CSPRNG password once. The actual Vault Work owns them before any
   weak publication/private writer. No fresh 10/2-second vault clock is created.
2. The original private stdin writer holds its actual loaded payload borrow until
   return. P12 save adds one fixed password part; review/reuse may add the actual
   selected P12/password. Neither password, private key nor package enters public
   JSON, command arguments, environment, diagnostics or a public byte getter.
3. A distinct `assemble-pkcs12` local intent in the **existing** Apple journal is
   durably CAS-reserved before the assembler. Schema 4 preserves existing v1/v2/v3
   rows; default empty state remains v1. There is no fake provider send bit. All
   modes share the existing 32-row/1-MiB limit; rows/unknown evidence are not evicted
   to permit another attempt. Duplicate/relevant intent requires recovery review.
4. One fixed bundled Ruby/OpenSSL command reads three original 0600 FiniteScratch
   files: stored key envelope, generated password and same-policy leaf. Its
   intermediate/root are the existing certificate policy's literal pinned public
   resources, not user-selected anchors. It creates modern AES-256-CBC/PBES2,
   PBKDF2-HMAC-SHA256 and SHA256-MAC PKCS12 with 100,000 iterations; unsupported
   output refuses, without legacy/provider/default fallback. It reopens the real
   result and compares private key, full SPKI, exact leaf and exact two CA certs.
   These consistency checks do not replace native Apple purpose/association.
5. The original stdout reader reserves one zeroizing private receive book before
   GO. It consumes a bounded binary package immediately after the fixed output
   event, then requires exact original request/digests, raw length, custody ACK,
   subsequent terminal, EOF and actual close. A header/event alone is not a save.
6. Only after actual process/IO/runtime/driver joins and fresh original source
   checks does the certificate child create the same-operation binding. The
   original job roster CAS-arms the local save and delivers an opaque one-use
   AppleP12SavePermit through the existing Asset save channel. No output bytes are
   returned through a generic callback.
7. The fixed vault child seals only NEW/None with that reserved revision. It
   remembers the actual mutation outcome before any later error. Only actual
   KnownApplied/Confirmed/Known releases ciphertext before full readback. The same
   Store reader checks successful-NEW identity/revision/exact length before body
   allocation. Full AEAD readback compares descriptor, every scalar/password,
   actual package bytes and exact reserved record/revision against retained input.
8. Actual original child/coordinator return and same-current publication append
   the new row. Then the same native roster records saved-unassigned, performs
   final CAS and actual NativeUse retirement, and closes/drains the original
   Asset/Store/private sources. It does not wait for its own future disposal to
   authorize those earlier joins. Existing explicit Assess/Bind and independent
   encrypted-backup controls are separate operations, not automatic steps here.

## Failure and retention

| Cut | Required behavior |
| --- | --- |
| No save ever entered, all original producer/IO/runtime/jobs positively returned | Exact opaque NoSave proof may dispose derived P12/password after original Asset/Store cleanup; source key remains; durable known-refused intent remains. |
| Partial private output, lost custody ACK, unknown IO/process/source/journal | Retain original buffers/fence and controls; no absence-derived proof, reassembly, ID reuse or retry. |
| Save armed/claimed, failed seal, uncertain NEW/readback/publication | Cannot become NoSave. Preserve original material and actual outcome even when a later check fails. |
| Full NEW/readback/publication known, later known cancellation | Only existing positive saved cleanup with real parent/all-job/Store/continuation receipts may dispose; cancellation outcome is not rewritten. |

Original status/cancel survive; there is no new `p12-reconcile` action or recovery
engine. Restored/history metadata is not a fresh loan. The source key is never
overwritten, deleted or regenerated.

A normal successful Terminal still signals `owner.stop` solely to close the
finished worker's input. That pipe shutdown is not user cancellation. Only the
P12 post-worker save gate distinguishes it: the actual original Accepted,
settled Complete/assembled Terminal, no first failure/Unknown/context loss,
positive worker/receive/source joins, current consumed review/Document and
same-operation certificate binding are all required within the original work
deadline. The same gate runs before and inside save-armed CAS and at one-use
save dispatch. Global `work_clear`, STOP and pre-worker Pending are unchanged;
genuine cancellation before or after Terminal still prevents a new save.

## Bounds and current-source integration

The existing 1200/1210-second endpoints and earliest failure/cleanup contraction
are retained. At most 15 original commands: six setup, one key verifier/resource
check, six complete bounded GETs, one policy check, and one extraction **or**
assembler. Existing provider aggregate is 1 MiB. P12 adds no POST. At most eight
events, existing 768-KiB certificate JSON/identity budget, one private frame of
84 + at most 1 MiB bytes, native password 64 lower-hex bytes. Selected input P12
is mode-limited to 4 MiB, password to existing Fields 4096 bytes; normal vault/
signing 32-MiB limits are unchanged.

Native future backing is charged by the actual existing Store document quote,
with source/loan/key/payload Arc deduplication, fixed receive and writer overlap,
retained journal/ACK rows and separate 2-MiB maximum crypto readback allowance.
Known ciphertext is retired before allocating authenticated readback; unknown
ciphertext is not refunded. Existing 64/96-MiB document limits and installed
128-MiB reservation are unchanged. This is allocation admission, not a measured
RSS or native-performance claim.

`apple-p12-native-hooks-20261020.patch` contains 42 existing-file changes only.
Before/after sources are retained in `.task-apple-p12/hooks`; base is actual
`cfac439e8d69f68d400a068de540d72520e54dbe`, with the certificate before-image at
`24763339d18c43dcc0100b0b3db1371728d92e0e`. Its seven already accepted callback
visibility fixes are preserved, not reverted. Existing helper literal rosters
in tooling.py, macos_store_runtime.rs and pyproject.toml include the one new Ruby
helper. Signed Ruby/gems may be reused when Gemfile/lock remain unchanged, but
current tooling/runtime manifest must be composed and checked normally.

Shared hooks are Root-only. Frontend companion hooks are separate; no App,
bridge, capability catalogue or frontend source is authored in this packet.

## Focused evidence and remaining tests

* Real synthetic Ruby/OpenSSL: 9 tests / 50 assertions PASS, 1.316964 s. Private
  task scratch only; no child tools/provider/Keychain. Original caller returned
  0 and successful disposable inputs were retired. This is not bundled Mac
  runtime qualification. Log: `.task-apple-p12/results/ruby-assembly-v3.log`.
* Final Python: 34 tests PASS, 4.584 s, original caller73164 returned 0. Includes
  eight whole existing engine/private-input/scratch/ACK paths with fake provider
  and fake C/A/W (Popen forbidden), plus framing/reuse/protocol tests. Log:
  `.task-apple-p12/results/python-final.log`. No native authority is fabricated.
* Seventeen own Rust and 29 changed shared Rust files parsed; 22 Python files
  AST-parsed. **Rust tests are uncompiled/unrun**, not inferred passes.
* Fourteen new Rust tests in own leaves plus one original protocol regression:
  password/frame, one-use reservation/full AEAD codec, raw receive/ACK/EOF/close,
  NoSave-before-save vs attempted/unknown, original review expiry, local journal
  schema/monotonicity and actual task-owned Store CAS/lost-ACK. Only the codec
  test that constructs an AppleP12 descriptor is Mac-gated; it is unrun too.
  No test constructs a certificate binding, NativeJoined or save permit from DTOs.
  The added real original `Inner::accept_at` Accepted/Terminal and `stop_locked`
  regression distinguishes normal input-close from earlier/later cancellation,
  checks minimum F, and still refuses save when actual native joins are absent.
  It is authored/source-parsed only, not an executed native-save test.

Python reproduction (no native work):

```sh
PYTHONPATH="$PWD/.task-apple-p12/projection" python3 -B -m unittest \
  tests.unit.test_desktop_apple_p12_assembly \
  tests.unit.test_desktop_apple_p12_protocol \
  tests.unit.test_desktop_apple_p12_reuse \
  tests.unit.test_desktop_apple_p12_owner
```

Root can select the new Rust module filters `apple_p12::tests`,
`apple_p12_fields::tests`, `p12::private::tests`, `p12::tests` and
`p12_review::tests`, plus the exact original-method regression
`p12_prepare_requires_explicit_selection_and_never_borrows_issuer_ack_modes`.
The new normal-Terminal regression is
`saved_command_owner::apple_key::p12::tests::original_normal_terminal_pipe_stop_is_not_failure_and_never_substitutes_for_save_joins`.
Check compiled enumeration and platform gates rather than treating these source
names or an echoed command as an executed test count.
