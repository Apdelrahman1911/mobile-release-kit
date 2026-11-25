# Local P12 crypto / APFS component extension

Base: `e4195857c8ae54dbe5ecd330db49a6a32d2a9876`. This is a test-only
successor to the existing Apple-key component, not a shipping admission change.

## Exact packet

New leaves:

- `tests/workflow/apple_p12_component.rb`
- `desktop/src-tauri/src/credential_apple_p12_component_macos.rs`

Apply `apple-p12-component-hooks-20261021.patch` to exactly:

- `desktop/src-tauri/src/credential_apple_key_component_macos.rs`
- `.github/workflows/desktop-macos-components.yml`

Actual before/after copies are in
`.task-apple-p12-component/parents/{before,after}/` in the author worktree.
The first hook is only a closed Key/P12 fixture selection and child module;
existing Key names, input limits, actual FD ownership and Release remain.
No production assembler, certificate policy, vault reader or owner is edited.

## Actual component sequence

The existing SOURCE-selected signed Store Ruby acquisition/signature checks,
Cargo-derived exact test executable and one private workflow owner remain.
Within its **one original 90-second end**, clamping each call to remaining time:

1. Existing key generator → existing APFS key NEW/fresh reopen → shipped key
   verifier, unchanged.
2. New Ruby fixture reads that same freshly reopened PKCS8/CSR/SPKI frame.
   It creates two local synthetic CA keys and a leaf for the ORIGINAL key.
   A valid signed three-certificate chain with a wrong leaf key must first
   refuse; then the real shared `MRKAppleP12Assembly.assemble` creates the P12.
3. One new native ignored test uses `ReservedAppleP12`, ordinary AppleP12
   Fields and the actual StoreBook NEW/None. It requires known durable effect,
   fixed P12 NEW readback and full AEAD/password/file/ref equality. After real
   Release it independently inspects/locks the same APFS vault with a fresh
   StoreBook, checks exact header/singleton/full witness and authenticates again.
4. Only fresh authenticated readback supplies `distribution.p12` AND its
   `p12-password` private file. After both actual Store Releases, private input,
   output and directory closes and the returned native test, the next original
   process runs the **shipped** `apple_provisioning_p12.rb` extractor. Its actual
   leaf/full SPKI must match the assembly frame and original generated key.

The P12 test uses a separate disposable vault fixture; it does not copy or
persist the key component's wrapping key between processes. Its own wrapping
key remains in one test process during fresh StoreBook reopen, not Keychain
cold-unlock or a production key/P12 association.

Native exact selector:

```text
asset_session::vault::backup_native::component_tests::apple_key::p12::native_apfs_apple_p12_new_reopen_and_private_reuse
```

## Bounds and failure custody

- Fixed fixture/private frame/cipher buffers: **128 KiB**. The native quote is
  existing 512-KiB codec control plus 128-KiB body, not a production limit raise.
- NEW uses `read_new_apple_p12_record`. Fresh full read reuses the existing
  kind-agnostic, exact-full-witness `read_apple_key_record` at this smaller
  allowance; it supplies no key loan. P12 kind/ref/material checks still require
  real AEAD. No unbounded/generic-32-MiB reader or new production method is added.
- Existing **256-KiB hard FSIZE remains unchanged**. New phase soft limits are
  128 KiB; previous key phase limits and all other workflow selectors remain.
- Original nofollow/0600/nlink/held metadata/EOF checks and 0700 directories;
  no private output in logs, diagnosticTail, artifacts or uploads. Assertions
  expose fixed errors/counts only. No child inherits the artifact token.
- Expected wrong-key rejection is isolated before positive output. Unexpected
  failure, partial output, timeout or unknown close prevents all later phases
  and successful task-root cleanup. Actual returns, PRE/POST and root close
  still precede the sole cleanup receipt.

## Honest scope / evidence

Production `apple_provisioning_p12_assemble.rb::main` still uses pinned Apple
root/G3 and is NOT invoked with a synthetic Apple identity. No anchor override,
CertificateBinding, P12SavePermit, SavedSession, Pending/keySaved/native-join
witness, assignment or NativeUse is fabricated. No provider, account, signing,
Keychain, GUI, cancellation/quit or normal P12 workflow qualification follows.
The password is explicit fixed 64-hex TEST data, not native password entropy.

Author local check: `/usr/bin/ruby` 3.2.3, Linux, real synthetic OpenSSL:
`ruby tests/workflow/apple_p12_component.rb --self-test`.
**3 tests / 13 assertions / 0 failures / 0 errors / 0 skips**, 1.711411 s.
The wrong-key negative was also counted against real `PKCS12.create`: only
the one positive assembly entered it. The unit process returned; its private
temporary files/directories were removed only after success.

Evidence: `.task-apple-p12-component/ruby-unit-v2.{log,exit}`. Earlier v1
3/12 result is retained, superseded only by the added real-create count.
Rustfmt parsed/checked the two Rust files; the actual embedded workflow Python
parsed with `ast.parse`. **No Cargo, Mac/native, workflow, download or provider
execution by author.** Selected signed-Ruby/APFS P12 execution remains pending
Root's reviewed existing scoped Mac batch. No extra app/supplier rebuild or
signing is requested.
