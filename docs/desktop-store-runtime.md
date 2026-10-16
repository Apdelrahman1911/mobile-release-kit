# Bundled macOS Store runtime component

This component builds the repository's Ruby **3.3.12**, Bundler **4.0.16**,
Fastlane **2.235.0** and exact `Gemfile.lock` dependencies. Current macOS runtime
composition and installed-book loans support this optional component; a shipped
application consuming it is not yet verified. It does not authorize direct Store
mutations.

## Publisher build inputs

Run `desktop/tools/build_macos_store_runtime.sh` as an ordinary user on a native
macOS 26 runner with the Xcode command-line tools already installed:

```text
build_macos_store_runtime.sh base RUBY_SOURCE OPENSSL_SOURCE LIBYAML_SOURCE CA_FILE ABSENT_BASE arm64|x86_64
build_macos_store_runtime.sh assemble VERIFIED_BASE GEM_CACHE ABSENT_OUTPUT arm64|x86_64
```

The caller supplies reviewed, authenticated, pristine **release source** trees
for Ruby 3.3.12, OpenSSL 3.5.8 and LibYAML 0.2.5, the locked Ruby-platform `.gem`
cache (including Bundler 4.0.16), and an authenticated PEM CA bundle. Source
version checks are not substitutes for download authentication. Preparation of
these public inputs is separate; this script downloads nothing, never installs
an SDK/Homebrew package, and never modifies global gems or the user's shell.
Use a fresh hosted build runner and a bounded job timeout for compilation.

Build arm64 and x86_64 separately on matching native runners. The script builds
static OpenSSL/LibYAML privately, uses the system SDK's libffi/zlib, and disables
Ruby JITs/shared libruby. Ruby's `--enable-load-relative` and a relative `bundle`
wrapper avoid depending on the build prefix. Do not run other installed gem
binstubs directly: their generated shebangs can contain the original prefix.

Ruby's `install-nodoc` normally invokes `prepare-gems`/`update-gems`, which can
download dependencies. This builder instead selects `install-bin`, `install-lib`
and `install-ext`, excluding bundled gems, then installs the repository's locked
cache with `bundle install --local`, frozen configuration and two jobs maximum.
Bundler bootstrap integrity uses the existing `.github/verification-tools.json`
dependency pin; dependency checksums remain those in `Gemfile.lock`.

## What the component checks

- Exact interpreter/bundle/Fiddle versions and existing native-helper origin/ABI
  admission, both with default gems disabled and under the locked bundle.
- Offline JSON/YAML/zlib/OpenSSL and Fastlane/Google client loads, plus parsing
  the fixed Fastfile exactly as the existing `run_lane.rb --validate` does.
  This parses definitions; it does not execute a lane or contact a Store.
- Explicit CA parsing and a peer/hostname-verifying TLS context. **This is not a
  TLS handshake**, certificate-revocation check or account-access test.
- A real relocation to a directory containing spaces, repeating the checks.
- Standard `lipo`/`otool` checks of every Mach-O file: the selected architecture
  must exist and dylib dependencies must be system libraries. Incompatible
  remaining native helpers fail; the scanner has no architecture exception.
- Ordinary file layout and a hard **512 MiB** component ceiling. Successful
  component construction does not prove room in the combined application.

The build removes only its private scratch directory on exit; a failed final
copy preserves an identifiable partial output rather than deleting a caller's
destination. No signing material, Store credentials or public release is used.

### Explicit optional notification exclusion

The locked `terminal-notifier` 2.0.0 gem contains an **x86_64-only** application.
Static inspection of the checksum-verified Fastlane 2.235.0 gem found its only
callers in the explicit `notification` and `notify` actions, not startup/loading.
The eight fixed MRK lanes and their hooks do not invoke either action. Store
tester notifications are separate server operations and are not removed.

On **both** architectures, the builder therefore removes only
`vendor/terminal-notifier/terminal-notifier.app` from the freshly installed
`terminal-notifier-2.0.0` gem under its own private bundle. It refuses a different
version, path, missing wrapper/license or nonordinary app directory. The Ruby
wrapper, notices, gemspec and lock remain. All remaining Mach-O files still
undergo normal architecture/linkage checks.

This private engine supports MRK's fixed lanes, **not generic Fastlane desktop
notification actions**; the Desktop UI handles its own notifications. Adding a
new supported lane that uses these actions requires restoring a compatible,
reviewed native helper first. The focused fixture test
`ruby tests/desktop/test_macos_store_runtime.rb` verifies the exact exclusion and
refusal boundaries without compiling or executing any native payload.

## Remaining integration and distribution work

1. Retain and reconcile native component results and complete the remaining
   dependency/license review and credential-free live TLS verification. Component
   assembly and all four pre/post-relocation smokes passed on ARM in run
   `38844616192` (job `116792194190`); Intel smoke success was also reported,
   with final artifact reconciliation still separate. These tests are not Store
   access or packaged-app evidence. Retained license metadata is not by itself
   redistribution approval.
2. Verify the combined current macOS payload against the measured bounds below.
   Preparation, stager Store image roles, and the app's same-original runtime
   loan are implemented; full current-source staging and actual installed
   consumption remain integration/native-verification work. Linux/Windows and
   historical supplier limits are not widened.
3. Finish the manifest/signing path: every nested executable and extension must
   receive genuine native verification, Developer ID signing, notarization and
   installed readback. The combined 512 MiB payload ceiling is unchanged.
4. Bind `stores._runtime_environment`/`_require_fastlane_bundle` to the admitted
   immutable component with clean explicit PATH/GEM/BUNDLE/CA configuration.
   Preserve the CI guard and native-process ownership contracts. A locally
   built runtime, credential selection, or parsed draft cannot authorize Store
   access.

## Authoritative implementation references

- [Ruby 3.3.12 build instructions](https://github.com/ruby/ruby/blob/v3_3_12/doc/contributing/building_ruby.md)
- [Ruby configure load-relative option](https://github.com/ruby/ruby/blob/v3_3_12/configure.ac)
- [Ruby installation/update-gems targets](https://github.com/ruby/ruby/blob/v3_3_12/common.mk)
- [Bundler 4.0.16 local installation](https://github.com/ruby/rubygems/blob/v4.0.16/bundler/lib/bundler/man/bundle-install.1.ronn)
- [Bundler frozen/platform/configuration options](https://github.com/ruby/rubygems/blob/v4.0.16/bundler/lib/bundler/man/bundle-config.1.ronn)

## Scoped native component CI

`desktop-macos-store-runtime.yml` builds only this dependency component on
matching Apple Silicon and Intel runners. It does not rerun the launcher,
Desktop, signing or Store workflows. `prepare_macos_store_inputs.py` downloads
public source archives and the existing lock's 99 gems plus Bundler, checks
checksums before extraction, and uses Python's standard safe tar data filter.
The checked-in CA bundle is reused. Acquisition and offline building are
separate steps; nothing from an acquired archive runs during preparation.

Ruby's archive size/checksum come from its official release announcement;
LibYAML's official `pyyaml.org` 0.2.5 release archive was observed as 609,454 bytes
with SHA-256 `c642ae9b75fee120b2d96c712538bd2cf283228d2337df2cf2988e3c02678ef4`.
OpenSSL reuses the existing dependency lock. These are dependency integrity
checks, not duplicated hashes of this repository's build scripts.

The native-base jobs retain an unsigned Ruby/OpenSSL/LibYAML component, CA,
notices and complete tooling for **seven days before Bundler installation**.
Base publication requires default-runtime, native linkage and real relocation
checks. Separate assembly jobs restore that exact base into fresh scratch,
refresh current first-party tooling, install locked gems, and run the complete
bundle/native/relocation checks. Final components remain for three days. Each
job deletes only its own workspace. These are component checks, not installed
application or distribution qualification.

For an assembly failure, use GitHub's **Re-run failed jobs**. The succeeded base
job is not rebuilt. Restore checks the immutable artifact ID, original source,
architecture, versions, native recipe/input DATA and original per-architecture
base-job success; a failed
overall run is intentionally allowed. It accepts only this repository's fixed
workflow from `verify/desktop-macos-store-runtime`, on `push` or
`workflow_dispatch`, never PR/fork artifacts or an arbitrary latest release.

For a tooling/DATA or assembly-script fix at a new commit, dispatch with all four
reuse fields: `base_run_id`, the original full `base_source`, and the exact
`arm64_base_artifact_id` / `x86_64_base_artifact_id`. Native compilation is then
skipped. The current assembly source and original base source are distinct;
`base-origin.json` accompanies the final artifact. Reuse is appropriate only
when the compiled native recipe/dependencies remain applicable; a native input
or compiler-option change needs a fresh base. Empty reuse fields select a new
base build. Artifact expiration/unavailability is a failure, never a pass.

Actions service metadata/digest authenticates the selected ZIP; its bounded
ordinary tar payload is extracted using Python's supported DATA filter into a
fresh directory. No restored binary is executed until this check completes.
The small metadata file also retains the actual base SDK and Clang versions.
Native configure options, deployment target and compiler flags are declared
once and consumed by the builder; restore compares them, the native release
archive digests and the CA digest with current requirements. A native build
logic change outside those options must increment `recipeVersion`. Tooling and
gem-only changes do not invalidate a compatible base. This is native dependency
identity, not a hash of every repository script or a new release authority.
No credentials, signing, installation or Store operations are enabled.

Component tooling includes the shared core's actual `REQUIRED_TOOLING_FILES`
roster, including schemas and workflow/configuration templates. The build-only
`--tooling-only` copy mode uses the core completeness check before/after copying
into an absent destination; it makes no network requests. This DATA-only
addition does not change compiled Ruby or native gems. Earlier native binary
checks remain applicable to those unchanged inputs, but a final assembled
component still needs the complete tooling/relocation smoke and its own digest.

### Current runtime composition (not yet installed execution)

`prepare_runtime.py --profile current --store-component /absolute/component`
can compose an **already authenticated** Store component into `runtime/store/`.
It does not download or run Ruby. It preserves the complete component inventory,
checks required notices/runtime/current core tooling, copies only into absence,
and binds copied bytes into the existing runtime manifest. Only `bin/ruby` and
the fixed `/bin/sh` `bin/bundle` wrapper receive executable modes; other installed
gem binstubs are resources, not additional executable roles.

Current macOS composition uses the measured 16,384-file / 32,768-entry limits
below, with portable paths and the unchanged combined 512-MiB payload ceiling.
A component that cannot fit is refused, not silently trimmed. This DATA
composition is **not** a native architecture/signature check or a Store grant:
final signing must cover every Mach-O, update the manifest to the final signed
bytes, and retain the full signed inventory. Stager/installed-book Store roles
and live runtime loans are implemented but need installed native qualification;
clean core runtime-context integration and local mutation authority remain
separate unfinished work.

The first ARM and Intel component run (`38837216127`, source `9a4bbe69`) compiled Ruby and
its native dependencies, then RubyGems refused to overwrite Ruby's existing
default Bundler launcher. It did **not** reach runtime smoke or relocation.
The corrected bootstrap uses RubyGems' documented `--bindir` to place the
locked gem's generated launchers in fresh build-only scratch. The builder still
invokes the exact Bundler 4.0.16 `exe/bundle` and installs its own relocatable
wrapper; it does not use `--force`, replace global tools or relax checksums.


### Measured macOS composition bounds

The complete relocated ARM Store component contains 6,588 files and 1,273
directories (109,752,638 bytes, 187 native images, longest relative path 162
characters). The prior 2,048-file package cap could not contain it plus CPython. Current macOS composition therefore admits at most 16,384 files and
32,768 total entries, still within the unchanged 512 MiB payload bound. The
historical CPython supplier and Linux/Windows preparation retain their previous
caps. All paths, modes, digests, signed inventory and original-file checks remain.

Mac runtime and installed-inventory JSON have scoped 12 MiB byte limits and
120,000 / 150,000 node ceilings; ordinary IPC remains 20,000 nodes. The app's
installed-file ledger is at most 32,832 records. The privileged installer retains
at most 196,608 lifetime original records, with actual allocation/name/history
costs checked against 128 MiB of installed-control memory and the same 96 live
FD ceiling. Large mixed histories may still be refused; these are caps, not a
claim that every maximal history fits. The read-only app installation check keeps
the existing 48 MiB document backing and separately reserves up to 128 MiB of
installed control (176 MiB peak); general session/credential quotas are unchanged.
Native consumption, signed packaged output and real installation still require
Mac verification. The Ruby bundle setup shim is ordinary non-executable DATA.


Dependency component reuse does not reuse its first-party tooling. Composition
omits the complete artifact `tooling/` subtree, then copies exactly the selected
core's `REQUIRED_TOOLING_FILES` from checked source originals into the fresh
runtime. Old extra tooling is not merged; the artifact itself is unchanged.
Missing or changed current tooling refuses composition. The resulting full
manifest and final Mac signatures cover both dependency bytes and current tools.

The selected `Gemfile` and `Gemfile.lock` must still match the component's actual
dependency inputs (size and SHA-256), because those inputs determined the
installed gemset. Changing either requires gem reassembly from the retained
native base; changing only the first-party Ruby/helper tooling does not.
