# Ubuntu desktop package — development source

This packaging path is incomplete and **not a qualified desktop distribution**.
The Rust publisher and package layout are separate from installed Python/import
qualification, UI/native acceptance, package signing and protected delivery.
The separate normal-shell connection to accepted installed A is limited to
passive help/project/draft operations and has pending native acceptance. It
does not make this package a complete installer or enable Save, credentials,
tools, network or Store actions. Current verification reuses the accepted
runtime package and runs the freshly compiled shell separately; it does not
claim that package contains the new shell.

## What the package owns

- The non-elevated `/usr/bin/mobile-release-kit-desktop` launcher.
- `/usr/lib/mobile-release-kit/mrk-runtime-publish`, a headless Rust helper.
- An inert, exact manifest-named runtime under
  `/usr/lib/mobile-release-kit/runtime-input/x86_64-unknown-linux-gnu/`.
- Desktop integration and the complete admitted runtime/app/publisher notices.

It owns **no `/var/lib/mobile-release-kit` files**. On `configure`, the fixed helper
copies the package input into fresh administrator-controlled objects and publishes
an absent immutable version under `/var/lib/mobile-release-kit/versions/`. No Python,
app, project command, Store request or release workflow is executed by installation.
No end-user Python or Rust installation is needed. The eventual package's actual
OS/ELF dependencies must be admitted and supplied to its dependency field; this
source does not guess them or claim that the present package is installable.

The preexisting `/var` and `/var/lib` ancestors must pass the same protected
ownership, permissions, ACL and filesystem checks; installation never repairs
them. There is no fallback to or migration/deletion of legacy `/opt` versions.

## Retained versions and interrupted installation

Published versions are never overwritten, repaired, adopted, moved or removed by
the application or Debian scripts. An already-running version may still need its
runtime after an upgrade or after its desktop parent exits. Therefore remove and
purge deliberately retain published versions and their disk usage. Package-owned
inert inputs are ordinary Debian files and can be removed normally.

A duplicate manifest version or an existing partial staging directory is an
installation error, including same-version reinstall. The helper preserves partial
state and reports failure instead of attempting repair or rollback. A failure after
publication can leave the version present; failure must not be interpreted as
absence. There is no automatic old-version cleanup. Removal of retained objects
requires separately reviewed offline administrator maintenance after actual
OS-domain shutdown, not a PID scan or an “app closed” assertion.

## Build preparation

`desktop/tools/stage_ubuntu_deb.py` only stages ordinary DATA in a fresh directory
under a private task-owned parent. Run it unprivileged. It does not run Cargo,
`dpkg-deb`, the publisher, a payload, an installer or any subprocess.

Supply original compiled app/publisher outputs, the exact accepted prepared runtime,
the accepted preparation artifact and the separately admitted app/publisher notice
set. Each of the three `*-files` inputs uses the existing sorted JSON record list
`[{"path": "relative-name", "size": 123, "sha256": "..."}]`, with its explicit
independently accepted digest. The compiler list has exactly
`mobile-release-kit-desktop` and `mrk-runtime-publish`. Select a bound two-file
delivery directory, not the entire Cargo target cache.

The preparation-artifact list includes all original members. Staging retains the
38 review/notice members and three original source-kit files, preserving bytes
and relative references under `usr/share/doc/mobile-release-kit/runtime/`.
Only `prepared-runtime.tar`, `preparation.json`, `copy-result.json`,
`copy-report.json`, `source-bindings.json` and `outer.json` are omitted. No archive
is unpacked or notice compressed/rewritten. Separate desktop notices are copied
under `usr/share/doc/mobile-release-kit/desktop/` without collisions.

Additional required inputs are the explicit manifest/protocol digests, Debian
version and concrete reviewed amd64 OS dependencies. Do not infer compiler inputs,
license completeness or native qualification from this tool's copy result. Bind
original compiler source/arguments/output and app/publisher M/Q in the separately
reviewed build. A later owned `dpkg-deb --root-owner-group --build` operation may
assemble the staged files; the tool does not silently perform it.

On errors retain the task's partial output; inspect before removing only proven
task-owned disposable files. Never point staging at sources, credentials, shared
caches or existing deployment/release artifacts.
