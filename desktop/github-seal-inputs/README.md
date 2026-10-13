# Fixed canonical sealed-box build input

`libsodium-1.0.22.tar.gz` is the unchanged public official release nominated at
<https://download.libsodium.org/libsodium/releases/libsodium-1.0.22.tar.gz>:

* Compressed: 2,008,529 bytes, SHA-256
  `adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349`.
* Full decoded tar (including headers/padding/tail): 9,676,800 bytes, SHA-256
  `2f78c3e629fbe938b3b99297d6d5fb02307ea5458c12744554e4377603d5fdb8`.
* The adjacent fixed JSON lists all 814 entries (678 regular files and 136
  directories), their original modes/mtimes/hashes and 76 installed public
  headers. The one generated version header is separately checked against the
  unchanged template and exact version/ABI 1.0.22 / 26.4.

The source's ISC notice is inside the archive and copied unchanged at
`desktop/helpers/macos-github-seal/LICENSE.libsodium`. This is public source,
not an installed/supplier payload. No detached-release-signature or minisig
verification is claimed. A separate optional binding-crate bundled-archive
comparison was refused and is **not** used as build provenance. There is no
syscrate, generated binding, dependency download or moving release selector.

## Fixed native gate

`.github/workflows/desktop-macos-github-seal.yml` is restricted to
`verify/desktop-macos-github-seal`. Its two native macOS26 jobs use an actual
prepared Python3.14.7 interpreter, protected CLT originals and the matching
already-installed Rust toolchain. The existing MRK `run_owned` cancellation
and process-finality implementation owns every native command. This is not
the CPython producer context, a full engineering UI workload, signing,
installation or live GitHub secret provisioning.

The builder admits the exact Git-bound source/archive, extracts only its fixed
ordinary roster into readonly sources, configures out-of-tree, builds one
static library, verifies installed headers/four C ABI symbols, runs the
unchanged official `box_seal` test and the helper's one native returned-wipe
test. The helper binary is limited to 16MiB. Cargo's two-name generated alias,
when present, must match the exact returned artifact and one actual native
`deps` original; exported copies are single-link. No arbitrary library search,
custom crypto verifier, benchmark or upstream full test suite is introduced.

One 900-second work endpoint and 60-second cleanup allowance contain the 22
top-level calls. They are not a count of configure/make's descendant processes.
The existing network-denial sandbox is tested; it is not filesystem isolation
or protection from a hostile process of the same UID. Source/tool POST,
original process/pipe ledger, consuming ordinary closes, handler restoration
and private-scratch retirement precede public output. Settled work census and
output caps are not hard live disk/RSS quotas; physical-memory sampling is not
available-memory measurement.

The uploaded report is **pending the actual entry's exit**. Qualification
requires that exact job/source/target, original entry0, passed final report,
source POST and known retirement; an artifact alone never establishes success.
Unknown custody leaves private quarantine and no public output. Failed jobs may
retain separately settled diagnostic output, not a successful build claim.
Build outputs remain unsigned engineering inputs. Packaging must separately
sign and rebind the exact helper, and the actual two-phase parent still owes
one framed helper seal-to-canonical-open test with its real originals and STOP
handling. Those runtime/credential/entropy-failure claims are not this gate.
