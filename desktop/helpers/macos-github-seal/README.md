# Fixed canonical sealed-box helper

This is a **separately built helper with an unconfigured signing nomination**,
not secret provisioning or remote-write qualification. Desktop must never link or call sodium, including
its initializer: the default canonical entropy path can abort the calling
process. This standalone package has no dependency/build-script graph and does
not use the acquired `libsodium-sys-stable` crate. No alternate algorithm, RNG,
low-order-key table, signature implementation or HTTP client is present.

## Exact source and link inputs

- Official libsodium **1.0.22**, archive SHA256
  `adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349`.
  Preserve its complete source roster and canonical configure defaults; its ISC
  license is copied verbatim to `LICENSE.libsodium`. Retained release signatures
  are not yet verified; a checksum is not a signature-verification claim.
- Build the matching static archive and generated headers using the separately
  reviewed existing Mac build owner/compiler/SDK. No dynamic sodium search,
  source download, pkg-config/vcpkg, shared temporary cache or build script.
- Compile `abi-check.c` **without running/linking it**, against those exact
  headers and the same target SDK (`-std=c11 -fsyntax-only` with incompatible
  pointer declarations treated as errors). The generated version header must
  actually say `1.0.22`; ABI26.4 alone is not an exact-version check.
- Only `aarch64-apple-darwin` and `x86_64-apple-darwin`. The proposed fixed Rust
  command is `cargo rustc --frozen --offline --release --target <actual-target>
  --bin mrk-github-seal -- -L native=<actual-owned-target-library-directory>`.
  The dedicated canonical helper build workflow supplies reviewed controls. Static
  linking is required by the source attribute. The owner must bind the actual
  `libsodium.a`, complete library-directory roster, header bytes and resulting
  Mach-O, not trust the supplied directory string. Strip uncontrolled Cargo,
  linker and Rust environment overrides. No `build.rs` is provided.
- Actual per-target linking, absence of a dynamic sodium dependency, signed
  packaged helper identity and original-custody checks remain required. The
  target location is `Contents/Helpers/mrk-github-seal` within the nested payload
  app. The separate signing/enrollment route below supplies it only after an
  actual configured build and signed-capsule nomination.

## One-shot private protocol

No arguments or runtime selectors. Binary stdin is exactly:

```
MRKSEAL1 | u32-big-endian plaintext length | 32-byte recipient key | plaintext | EOF
```

Length is0..49152, maximum input49196 bytes. Empty input is a crypto boundary
case; the calling canonical material-field policy still decides applicability.
No text or Base64 conversion is performed here. One extra EOF probe byte stays
in the same wiped allocation. Output is exactly:

```
MRKBOX01 | u32-big-endian ciphertext length | ciphertext | EOF
```

Ciphertext length must be input length+48, maximum49200 (framed49212). Recipient
keys are handled by the canonical C implementation, not a local blacklist.
Every failure returns nonzero without an error frame, logging or diagnostics.

## Process, buffer and return rules

Before any plaintext read/allocation, the child lowers and reads back its own
core limit to0, CPU ceiling to at most2 seconds, regular-file output ceiling to
at most65536 bytes and descriptor-number limit to at most32. It never raises an
inherited allowance or changes Desktop's limits. A descriptor-number ceiling
below8 or a zero CPU allowance refuses before input. These are child ceilings,
not an observed descriptor count, a whole-operation memory quote or a reset of
the parent's10-second wall endpoint and single2-second cleanup allowance.

The parent must still admit the real inherited originals. The helper takes only
FD0/1/2 after fixed valid-descriptor checks and uses unbuffered `File` I/O; no
`stdin` buffered singleton, JSON, secret string or dynamic command is used.
Canonical entropy-device reads are the only library-internal file exception;
there is no application-file/path API or child-process creation.

Two fixed initialized boxed buffers: input49197 (including EOF probe), output
49200; total98397 payload bytes. Header/owner/control overhead and the canonical
library/runtime, parent writer/material/ciphertext/Base64 copies are **additional**
and must be reserved by the containing owner before spawn. This number is not an
RSS bound. Initialization/allocation happens before a secret enters either box.

After exact input/EOF and the original stdin consuming close, accept only
`sodium_init`0 or1 and `crypto_box_seal`0. Wipe the complete input allocation on
every normal return; after any initializer attempt call `randombytes_close`
once, including failed initialization/sealing. Emit no successful output until
the wipe returned and RNG close returned0. Output is also wiped before release.
All three inherited originals have one checked consuming close, with no EINTR
retry; the first failure wins. A nonzero close or write vetoes helper success.

Fatal signal, panic/allocator abort or forced termination does **not** prove
explicit erasure or library/individual descriptor cleanup. Core-dump suppression
is not a guarantee about OS crash-report, register, compiler or swap copies.
The parent accepts only actual original0 plus exact frame/EOF, writer/readers'
original joins and all source POST/closes. Unknown custody remains unknown;
partial ciphertext, exit alone or the helper's path never grants consent/retry.

## Focused checks (not executed by this source change)

`protocol_tests.rs` has three pure framing groups: exact0/max/raw-byte frames,
truncation/trailing/oversized-body refusal, and output size/write failure. A
non-Mac `cargo test --bin mrk-github-seal` compiles only those tests; a normal
non-Mac helper build is refused. Do not call these tests native crypto evidence.

`macos_tests.rs` retains that **actual canonical-library** group, including all
returned wiping/low-order/first-error assertions, and extends it with eight
sequential real child originals. The existing build owner runs the same exact
selected test twice: ordinary6 then denied2, sharing ONE absolute10-second
endpoint and ONE64KiB captured-output allowance, not two renewed budgets.
The complete build now has23 ordered command originals; both selected test
invocations must pass before any combined eight-case evidence is published.
Three unchanged release-helper children receive public0/3/max binary frames
through actual pipes, close stdin, return exact ciphertext+EOF, close both
reader originals and exit0. Canonical test-only `crypto_box_seal_open` must
recover the exact published fixture; changed ciphertext must fail. Two more
helper children really refuse trailing input and the low-order public key.

One additional fixed-device probe test runs as two child controls: normal
opens/checked closes of both `/dev/urandom` and `/dev/random`, then actual
EPERM/EACCES for both under the second top-level original's fixed network-and-
device-denied policy. The test parent and its two direct children inherit that
policy; no nested sandbox-exec is attempted. The eighth unchanged helper uses
that same policy and valid frame: actual SIGABRT, no
ciphertext, all parent pipe closes/EOF/wait. The canonical backend must be
`sysrandom`; no RNG override/interposer or production protocol is added.
Abort does NOT prove returned erasure, randombytes_close or child-FD closes.
All input/key material is published test DATA, never application credentials.

These are build-parent frame/exit/cleanup and entropy-device-denial checks, not
installed Desktop publisher/Book/material-loan/STOP admission, independent
interoperability, or a shipping qualification. Those native two-phase owner
checks and independent public compatibility evidence remain required.

No native phase slot, material loan, secret transport, UI, packaging selector or
secret feature is activated by these files.


## Fixed signing and package enrollment (SOURCE implemented, not qualified)

`desktop/macos-installed-inputs/github-tool-signing.json` has exactly the seal
helper and GitHub history provider, each for ARM64 and Intel. All nominations
start **unconfigured**. The existing Python-signing workflow has a separate
fixed `verify/desktop-macos-github-tool-signing` push route; it does not run the
Python supplier branch or execute either tool. Each original signing operation
uses the existing Developer ID credential owner and performs one timestamped
sign plus one strict identifier/team/certificate verification, then checks the
unchanged loader/content and every original's retirement. Gh is capped at64MiB,
seal at16MiB; existing Python32MiB and credential limits are unchanged.

A SOURCE-enrolled build capsule has only the fixed binary and
`tool-build-receipt.json`. The normalized receipt must derive from **actual
finalized build evidence**, not a hand-authored success assertion. The gh-only
`buildOrigin` distinguishes the real offline crossbuild from subsequent capsule
publication. Top-level sourceCommit/runId/runAttempt identify that later real
publication; they must not be described as the offline compiler's GitHub run.
The gh source manifest, notice-complete content, actual result/child/namespace
and source/dependency/toolchain POST records remain bound. Existing accepted
notice-complete products can be reused through that reviewed adapter: an
identical rebuild is not intrinsically required. Old PLACEHOLDER-notice probes
cannot be nominated. Real transport artifact IDs are required before download.

After successful original signing and publication, independently enroll the
signed capsule's exact binary and receipt hashes/lengths and profile hashes.
The download action checks its artifact digest and the owner checks the two
exact members; no independent raw-ZIP hash verification is claimed. Neither a
raw binary nor artifact existence is a signing receipt. Do not invent hashes,
replace a SOURCE row with a runtime-discovered value, or mark null profiles ready.

The installed caller passes signed gh to the existing current-runtime overlay
and pairs seal's SHA256/bytes before desktop compilation. App staging preserves
seal0555 and includes the verbatim ISC notice; fixed executable inventory paths
and original-bound verification include both tools. All unchanged signed-input,
Developer ID Installer and notarization requirements still apply. Canonical
runtime/source bindings and current owner/source-pin closure must be enrolled
from real returned artifacts in a subsequent reviewed change. Current helper
`macos_aqua_qualification.load_owner` pins need deliberate reconciliation with
the current cancellation source; this source slice does not relax that check.
No target build, credential use, signing, installed journey or remote provisioning
is claimed by this implementation or its DATA-only regressions.
