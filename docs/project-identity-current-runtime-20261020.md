# Current-runtime identity observations

## Scope and hooks

This packet connects the **existing four** `project-identity-native` cases to
current candidate preparation. It does not install anything itself or add a
runner, native operation, UI selector, qualification flag or shipping claim.

`project-identity-current-runtime-hooks-20261020.patch` changes only
`desktop/tools/macos_android_helper_package.py`: its original admission and DATA
selection paths recognize the explicit `MRK_MACOS_NATIVE_SCOPE=project-identity-native`
on `refs/heads/verify/desktop-macos-candidate`, ARM only, with the existing
`installed-shell-observation` role. The ordinary/default branches do not import
the new helper and retain their previous decisions. Unknown scopes, foreign
refs, wrong roles/targets and unlisted phases refuse. No prepared-artifact,
ordinary-image, old Aqua workflow, or old supplier fallback is added.

## Root composition: one current observer, not four packages

Root owns workflow admission, build, signing, installation and actual execution.
Use the existing `desktop-macos-installed.yml` current candidate preparation:

1. Set the explicit native scope **and observer package role before source
   admission**, so `source-admission.json` and finalized `source-binding.json`
   describe the actual artifact. Preserve all ordinary/prepared defaults.
2. Reuse current selected signed Python/gems and the existing
   `restore-selected` → `compose-store-runtime` → `finalize-runtime-binding`
   chain. Retain its computed S/M/binding environment and same work directory.
   Do not select historical supplier archives or substitute old expected M/S.
3. Reuse the current frontend build and original resident/helper/entry/vault/
   remover/CLI preparation. Instead of compiling a desktop image, build only
   the existing observer with the current pinned toolchain and source/run tuple:

   ```sh
   # Existing toolchain/PATH/RUSTC/CARGO_HOME environment, same source and work.
   cd desktop/src-tauri
   /Users/runner/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin/cargo \
     test --locked --no-default-features \
     --features desktop-shell,custom-protocol,macos-installed-observation \
     --target "$MRK_MACOS_TARGET" --test installed-shell-observation \
     --no-run --message-format=json \
     > "$MRK_MACOS_WORK/observer-build.jsonl" \
     2> "$MRK_MACOS_WORK/observer-build.stderr"
   ```

   Keep the original compiler exit status. Reuse the existing observer artifact selection from compiler
   JSON; `stage_macos_installed.observer_cargo_artifact` checks the actual binary,
   source target, features, profile and dependency graph. No test result or
   guessed filename can replace the compiler's returned artifact.
4. Call the existing stager `app` with its current required helper/runtime
   inputs, `--package-role installed-shell-observation`, actual observer
   `--binary`/`--expected-app-binary`, `--observer-cargo-messages` and
   `--observer-cargo-target-dir`. Do **not** pass the desktop-image quartet or
   swap an executable into a previously signed ordinary package.
5. Use the existing sign/verify/notarize/finalize/install owners. In particular,
   `final_package_roles(False, "installed-shell-observation")` still requires
   real notary submission/stapling/validation; `package-install` requires its
   actual successful finalization receipt and caller result. These requirements
   are not bypassed by this packet. Batch compatible observations on this one
   installed observer, rather than repeat preparation for each case. No final
   distribution-image notarization, Xcode, broad test matrix, or extra dependency
   signing is added. The observer package is **nonshipping**, not a deliverable
   installer or an ordinary-ready candidate.

Once that original installation has actually returned successfully, the only
new invocation is:

```sh
# Dedicated step without signing/Store credentials. Original failures propagate.
cd /Users/runner/work/mobile-release-kit/mobile-release-kit
"$MRK_PYTHON" -I -S -B desktop/tools/macos_identity_current_runtime.py \
  --target aarch64-apple-darwin
```

Retain the original exit status and bounded stdout/stderr using the workflow's
existing exclusive output handling. The entry itself does not dispatch Actions,
download, invoke Cargo, sign, notarize, install, request accessibility permission,
or drive DOM/AX selectors. It reuses the existing native fixture's initial
picker owner and direct post-picker identity actions unchanged.

## Actual entry inputs and observations

- Hosted macOS26 ARM64, isolated `-I -S -B` interpreter, ordinary `runner`
  main thread and matching console user; fixed checkout and current candidate
  push/workflow/source/run/attempt. Other platforms/routes refuse before owners.
- `MRK_MACOS_WORK=/Users/runner/work/_temp/mrk-macos-installed.<8 alphanumerics>`
  from the same original preparation, `MRK_MACOS_STORE_RUNTIME=signed-component`,
  plus the existing computed `MRK_MACOS_RUNTIME_BINDING_SHA256`,
  `MRK_BUNDLED_RUNTIME_MANIFEST_SHA256` and `MRK_BUNDLED_RUNTIME_SOURCE_SHA256`.
- Current selected Python/store SOURCE, signing-profile DATA, both current
  build-release inputs, finalized source/runtime bindings and detached HEAD.
  The helper retains these bounded originals in the **existing Fixtures FD
  book** and reuses the stager's exact parsers; no path in a report grants access.
- Mandatory `Fixtures.admit_normal_account_runtime` retains the actual installed
  record/inventory/manifest/core/Python. Computed current M is compared to that
  **same held manifest FD**, not a second open. Original metadata/hash checkpoints
  precede invocation and follow each original case's native return/readback.
- The existing `run_cases` invokes, in order: `identity-android-apply`,
  `identity-ios-apply`, `identity-rollback-recovery`, `identity-committed-cleanup`.
  Their existing clocks remain 165/120/120/120 seconds; each recovery precursor
  keeps its original 30-second bound. Root should reserve one finite invocation
  slot with preparation/margin, not renew any inner clock or use a large matrix.
- The same native observer and parser bind compiled source/run/attempt and
  original Session finality. Independent reads verify identity changes, untouched
  namespaces/other targets, rollback and committed metadata-only cleanup. Later
  same-path edits remain preserved by committed cleanup. Controlled precursors
  are **not process-loss evidence**. No project build, Store, signing-key,
  certificate, namespace-refactor or shipping qualification is inferred.
- Only four successful original returns/readbacks **and actual Fixture closes**
  produce `macos-identity-current-complete`. Unknown/unreturned calls preserve
  their original inflight custody: no later invocation, readback, close or retry.
  A subsequent close error never replaces an earlier original failure.

## Focused evidence

Author ran `python3 -B -m unittest -v test_macos_identity_current_runtime` with
`PYTHONPATH` pointing at the task's disposable public-source projection containing
the applied one-file hook: **13 tests PASS, 0 skips, 0.029s; original caller 0**.
The projection contained 1,799,049 bytes and no installed/native payload.

Tests exercise actual patched package admission (default unchanged), exact
scope/source/role refusals, the actual bounded held-file readers and existing
composed parsers, current-M/installed-FD mismatch, post-read same-name replacement,
and the original `run_cases` order/unknown boundary. Process outcomes, native
reports, precursors and native readback are explicitly inert in lifecycle tests;
`Popen` is forbidden. No native or signing evidence is claimed. Existing identity
case tests were not rerun. Root's distinct source review and actual current Mac
build/install/four-case execution remain required.
