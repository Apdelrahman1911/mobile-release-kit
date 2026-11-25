# Current installed observer: identity, service, and tool setup

Source-only successor to `tool-setup-native-observation-20261020.md`. No native
case, download, installation, signing, service registration, or hosted job was
executed while authoring this packet. Shipping qualification remains unchanged.

## One existing job and one current package

Apply `tool-setup-execution-hooks-20261020.patch` with the seven implementation/
test leaves in this commit. The six shared targets are:

1. `desktop/src-tauri/src/installed_shell_observation_macos.rs`
2. `desktop/tools/macos_aqua_qualification.py`
3. `desktop/tools/macos_identity_current_runtime.py`
4. `desktop/tools/macos_android_dependency_preparation.py`
5. `.github/workflows/desktop-macos-installed.yml`
6. `tests/desktop/test_macos_identity_current_runtime.py`

The existing `engineering-install` job on
`refs/heads/verify/desktop-macos-candidate`, ARM `aarch64-apple-darwin`,
`macos-developer-id`, supplies the current signed/notarized installed observer.
There is no second app/helper build, package, Installer invocation, or new job.
Root must separately approve a verification-source selection of the existing
matrix's `native_scope: tool-setup`; this patch leaves it **disabled**. The fixed
package role is `installed-shell-observation`, never an ordinary shipping image.
The manual `prepared-install`/Xcode-companion dispatches do not select this route.

After that same package's successful standard Installer/readback, existing
steps invoke, in order (all environment and interpreter values come from the
original job; these are not standalone user commands):

```sh
"$MRK_PYTHON" -I -S -B desktop/tools/macos_identity_current_runtime.py --target "$MRK_MACOS_TARGET"
"$MRK_PYTHON" -I -S -B desktop/tools/macos_identity_current_runtime.py --target "$MRK_MACOS_TARGET" --scope tool-service-prerequisite
MRK_ANDROID_PREPARATION_WORK="$MRK_MACOS_WORK" "$MRK_PYTHON" -I -S -B desktop/tools/macos_android_dependency_preparation.py prepare-tool-setup-inputs
"$MRK_PYTHON" -I -S -B desktop/tools/macos_identity_current_runtime.py --target "$MRK_MACOS_TARGET" --scope tool-setup
```

The first invocation retains the existing four identity cases unchanged. Each
subsequent workflow step requires the preceding step's actual success. The
current driver reuses the original `Fixtures`, installed runtime/manifest/source
readers, `run_cases`, and `run_owned`; it does not interpret a prior JSON record
as authority. Every invocation re-admits the same current installed package.

### Existing supplier inputs versus missing preparation

Current Root-tracked `python-signed-runtime-binding.json` nominates ARM artifact
`12242597733`, run `38345366880`/attempt2, signing source
`70ae6f78af7fe240a0406b9f391cd7b43bac592e` (the public handoff reports availability
through October27; no live artifact check was made here). The existing
`store-signed-component.json` nominates ARM artifact `12055694185`, run
`38924519973`/attempt1, source `f05ec74e3d061e5576e5473a62be809932f8372c`.
The ordinary workflow keeps its exact existing gh/support nominations and
verification. No supplier pin, tool version, or source-signing policy changes.

There is **no separately established current Android service helper artifact**
to reuse: the same current job must build/sign/install its existing resident and
registration helpers. The Android support capsule is not that service; Xcode
artifact `12211884317` from run `39301915324` is also not that service. Successful
old logs cannot substitute for original current helper admission. This packet
adds only its missing explicit service prerequisite and fixed source fixtures.

## One bounded service prerequisite

New `installed_shell_observation_macos_tool_service.rs` adds the fixed
`tool-service-prerequisite` case to the existing observer only. It uses the same
Observation/Document and ordinary Saved service owner for exactly one explicit
`RequestRegistration`, followed, only after a positively joined Ready result,
by a fresh saved-context `Check`. The original operation ID, setup/source
generations, action, saved context, coordinator joins and native retirement must
match. `AlreadyRegistered` reuses the service; there is no second request,
settings opener, `launchctl`, bootstrap bypass, or unregister action.

The original Request and Check retain their existing300/310-second bounds.
The enclosing observer750/driver765-second limits are captured once. Ready
requires Enabled and native-settled, nonuncertain results from both originals,
then the normal Quit/relay join before the case report can succeed. A known
pre-admission `android_service_unavailable` is distinct from an admitted/lost
`android_service_unconfirmed` or Unknown result. Known approval/denial/not-found/
unavailable results finish as **unexecuted**, with exit78/manual guidance; later
fixture downloads and tool cases do not start. Lost/unknown results fail and
retain their originals. This prerequisite uses only the fixed seven project
files; it does not read SDK inputs or enter acquisition.

## Fixed protected fixture ABI

Both languages derive the following from the actual native account
`User.dir`/`pwd.getpwuid`, and the compiled/current source/run/attempt tuple.
`HOME`, renderer input, and arbitrary environment paths are not grants.

```text
<native-home>/Library/Application Support/
  mrk-macos-tool-inputs-<source>-<run>-<attempt>/
    tool-setup-cancel-transfer/{jdk/temurin-17.jdk,gradle,sdk/platforms/android-35}
    tool-setup-source-drift/sdk/platforms/android-35
    tool-setup-missing-sdk/sdk/platforms/android-35
  mrk-macos-aqua-<source>-<run>-<attempt>-tool-service-prerequisite/{state,<service-project>}
  mrk-macos-aqua-<source>-<run>-<attempt>-tool-setup/{state,<three-tool-projects>}
  mrk-macos-aqua-tools-<source>-<run>-<attempt>/<tool-case>/dev.mobile-release-kit.desktop
```

The last app-data leaf remains the original product cache owner's responsibility.
Only Tool/service project and supplier fixtures move from `/private/tmp`:
production SourceSlots rejects sticky/writable ancestry there. Identity and all
other observation scopes are unchanged. **No production ancestry exception** is
introduced. Existing home/Library/Application Support ancestry must already
satisfy the unchanged protected-chain policy, or preparation refuses. Only
fixed task leaves are created exclusively0700; no parent repair/chmod/mkdirall.
The original held ancestry and child identities survive construction, source
POST, sealing and independent one-close attempts. Collision, pending, failed
close and lost child retain outputs; they never authorize adoption or retry.

`macos_tool_setup_inputs.py` reuses the existing Acquisition/UiAcquisition,
archive correspondence, NormalPhase and command owner. JDK17, Gradle8.14.5 and
platform35 archives are fetched **once each** (388,193,648 compressed bytes).
The verified platform archive is independently reopened/rehash-checked for the
other two SDK fixtures, not redownloaded or treated as a continuing old FD loan.
Build-tools35 is deliberately absent. No SDK package metadata/license is
synthesized, no sdkmanager or vendor executable runs, and no full SDK readiness
is claimed for these inputs.

Exact expanded source subsets are 578,785,018 bytes/11,938 files for the shared
JDK+Gradle+first platform, then102,589,879 bytes/11,162 files per other platform:
783,964,776 bytes total. At least8GiB free is required in both source and work
filesystems before first creation. All three extraction originals share one
810-second child clock and aggregate8GiB read/1GiB write allowance, including
conservative parent POST reservations. Existing per-original16,384-file/
32,768-entry bounds remain. The existing parent1200-second and owned child
call900-second limits contain the phase; no per-case quota/clock restart.

No new recursive cleanup or service removal is supplied. Task outputs and
sentinels remain in the exact tuple namespaces, especially on unknown/cancel;
the disposable runner is the final disposal boundary. Never unregister an
unrelated service or delete a preexisting colliding namespace.

## Three unchanged native tool journeys

After prerequisite success and independent fixture verification, the driver
runs `tool-setup-cancel-transfer`, `tool-setup-source-drift`, then
`tool-setup-missing-sdk`. Each retains its original2400-second observer/
2415-second caller bound and remains **Check-only** for service readiness.
The existing test-only picker uses the same bound Observation/Doc and ordinary
source reader, not a fabricated selected-source DTO.

* Cancel: original pre-transfer cancellation; no vendor request/registration;
  original child/cache/runtime/IO/driver joins must be observed.
* Drift: same-size task-owned `source.properties` substitution/readback; only
  real retained SourceSlots Inventory/Identity refusal before transfer qualifies.
  Unrelated runtime/protocol/capacity failures are not successful drift tests.
* Positive: reuse compatible JDK17/Gradle8.14.5/platform35, acquire only missing
  build-tools35, assemble the SDK, then ordinary source selection/Inspect/Review/
  protected Register and a fresh selected-catalogue reuse inspection. No update
  of compatible tools and no bypass of protected-copy authority.

The existing job350-minute ceiling also prevails; summed step maxima are not a
guarantee that the job finishes within that ceiling. Native service approval,
actual copying/download, registered reuse and installed finality remain
unexecuted until Root schedules the reviewed job.

## Focused authored evidence and pending gates

40 distinct passive Python tests passed: existing+new tool tests21 (0.432s),
current driver17 (0.040s), then two additional custody/collision tests (0.003s).
No skipped cases. The first driver import failed only because its disposable
public-source projection omitted import-time `build-release.json`; adding that
exact existing public input produced the17 passes. Original failure log retained.
No process, HTTP, SDK, service or Mac native execution was allowed by those tests.

After composition, the complete filters are:

```sh
python3 -B -m unittest discover -s tests/desktop -p 'test_macos_tool_setup_*.py'
python3 -B -m unittest discover -s tests/desktop -p test_macos_identity_current_runtime.py
```

They now enumerate23 and17 cases respectively; unchanged tests were not rerun
just to consolidate counts. Meaningful checks include original admission versus
lost request, same-driver invocation order, failure retention, actual bounded
POSIX source writer/sealer/POST, tampered archive before parser/HTTP, original
parent replacement, and no adoption/deletion of an existing task leaf.

Four Rust files parsed with existing rustfmt1.98.0 (`skip_children=true`); this
is **not typechecking**. The new inert service DATA comparison joins the existing
harness=false observer startup contracts; it has not executed. System Ruby/Psych
parsed the workflow; all nine changed Bash bodies passed `bash -n`; strategy,
default disabled scope, permissions, events and all other jobs stayed unchanged.
Root must compile the actual Mac observer graph and schedule native execution.
Private compact logs/pins are under `.task-tools-execution-20261020/results/`.
