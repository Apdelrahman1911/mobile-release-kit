"""Unprivileged, offline Debian file staging; never build/install/launch anything.

Inputs are independently admitted originals, not objects discovered by this tool.
The three inventory arguments reuse the existing [{path,size,sha256}] DATA format.
Their explicit digest pins authenticate those inputs for copying only; they do
not prove compiler provenance, license completeness or native qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat


def _helper(name: str):
    spec = importlib.util.spec_from_file_location("_deb_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


D = _helper("conventional_runtime_data")
P = _helper("prepare_runtime")
Q = _helper("probe_cpython_source_runtime")
SOURCE = Path(__file__).absolute().parents[2]
TEMPLATES = SOURCE / "desktop/packaging/debian"
TARGET = "x86_64-unknown-linux-gnu"
BINARIES = {"mobile-release-kit-desktop": "usr/bin/mobile-release-kit-desktop",
            "mrk-runtime-publish": "usr/lib/mobile-release-kit/mrk-runtime-publish"}
PREPARATION_ONLY = {"prepared-runtime.tar", "preparation.json", "copy-result.json",
                    "copy-report.json", "source-bindings.json", "outer.json"}
KIT_CONTROL = {"components.json", "notice-inventory.json", "reviews/configuration-review.txt",
               "reviews/obligation-review.txt", "source-kit/hosted-evidence.tar",
               "source-kit/hosted-summary.json", "source-kit/retained-files.json"}
DOCS = "usr/share/doc/mobile-release-kit"
MAX_BINARY = 512 << 20
MAX_NOTICES = 64 << 20


def pinned_json(path: Path, digest: str):
    D.sha(digest)
    raw = D.read(path, 1 << 20)
    D.need(hashlib.sha256(raw).hexdigest() == digest, "Release input inventory digest differs")
    return D.decode(raw, 1 << 20)


def exact_files(root: Path, expected: dict[str, dict]) -> None:
    """Reuse the preparer's bounded ordinary-file/tree/case policy."""
    P._root(root)
    actual = {path.relative_to(root).as_posix() for path in P.files(root)}
    D.need(actual == set(expected), "Staging input contains missing or extra files/directories")


def controls(version: str, depends: str, installed_size: int) -> bytes:
    D.need(type(version) is str and re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]{0,63}", version) is not None,
           "A concrete Debian package version is required")
    # Deliberately small syntax for the actual amd64 ELF dependency closure.
    # No substitution variables, alternatives, architecture selectors or newlines.
    package = r"[a-z0-9][a-z0-9+.-]+(?: \((?:>=|=) [0-9][A-Za-z0-9.+:~\-]*\))?"
    D.need(type(depends) is str and len(depends) <= 4096
           and re.fullmatch(package + r"(?:, " + package + r")*", depends) is not None,
           "Explicit reviewed amd64 OS dependencies are required")
    raw = D.read(TEMPLATES / "control.in", 4096)
    for token, value in ((b"@VERSION@", version), (b"@DEPENDS@", depends),
                         (b"@INSTALLED_SIZE@", str(installed_size))):
        D.need(raw.count(token) == 1, "Package control template differs")
        raw = raw.replace(token, value.encode("ascii"))
    return raw


def runtime_records(root: Path, manifest_sha: str, protocol_sha: str) -> dict[str, dict]:
    raw = D.read(root / "manifest.json", 1 << 20)
    # Existing pure fixed-runtime validator; never its executable probe entry.
    Q._selected_records(raw, manifest_sha, protocol_sha)
    rows = D.records(D.decode(raw, 1 << 20)["files"])
    D.need(set(P.BOOTSTRAPS) | {"core.zip", "github-ca.pem", "python/bin/python3"} <= set(rows),
           "Required runtime resources are missing")
    rows = {**rows, "manifest.json": {"path": "manifest.json", "size": len(raw), "sha256": manifest_sha}}
    exact_files(root, rows)
    return rows


def kit_records(root: Path, admitted: dict[str, dict]) -> dict[str, dict]:
    D.need(KIT_CONTROL | PREPARATION_ONLY <= set(admitted), "Prepared delivery control inventory differs")
    D.bound(root / "notice-inventory.json", admitted["notice-inventory.json"])
    notices = D.decode(D.read(root / "notice-inventory.json", 1 << 20))
    D.need(type(notices) is dict and set(notices) == {"files", "profile", "pythonChangeSummary", "schemaVersion"}
           and type(notices["schemaVersion"]) is int and notices["schemaVersion"] == 1
           and notices["profile"] == D.PROFILE and notices["pythonChangeSummary"] == "PYTHON-CHANGES.txt",
           "Prepared notice inventory profile differs")
    notice_rows = D.records(notices["files"])
    expected = KIT_CONTROL | {"notices/" + name for name in notice_rows}
    D.need(set(admitted) == expected | PREPARATION_ONLY, "Prepared delivery has an unreviewed member")
    for name, row in notice_rows.items():
        D.need(D.same(admitted["notices/" + name], {**row, "path": "notices/" + name}),
               "Prepared notice inventory binding differs")
    exact_files(root, admitted)
    # Omit exactly the six preparation-only entries, never a count-based subset.
    return {name: admitted[name] for name in sorted(expected)}


def elf_header(path: Path) -> None:
    original, _ = D._open(path, MAX_BINARY)
    with original:
        header = original.read(20)
    D.need(len(header) == 20 and header[:7] == b"\x7fELF\x02\x01\x01"
           and header[16:18] in (b"\x02\x00", b"\x03\x00") and header[18:20] == b"\x3e\x00",
           "Expected a bound x86_64 ELF compiler output")


def stage(args: argparse.Namespace) -> dict:
    """Copy-only implementation. CLI additionally refuses privileged execution.

    A private output parent and exclusive fresh output are required. Error leaves
    the original partial staging tree for its task owner; there is no automatic
    recursive cleanup or retry. This function is also the bounded DATA-test seam.
    """
    binaries = D.records(pinned_json(args.compiler_files, args.compiler_files_sha256))
    D.need(set(binaries) == set(BINARIES) and all(20 <= row["size"] <= MAX_BINARY for row in binaries.values()),
           "Both exact app and publisher compiler outputs are required")
    native_notices = D.records(pinned_json(args.desktop_notice_files, args.desktop_notice_files_sha256))
    D.need(sum(row["size"] for row in native_notices.values()) <= MAX_NOTICES,
           "Desktop notice inventory exceeds its bound")
    kit = kit_records(args.prepared_artifact, D.records(pinned_json(args.prepared_files, args.prepared_files_sha256)))
    runtime = runtime_records(args.runtime, args.manifest_sha256, args.protocol_sha256)
    exact_files(args.compiled, binaries)
    exact_files(args.desktop_notices, native_notices)
    D.directory(args.output.parent)
    parent = args.output.parent.lstat()
    D.need(parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) & 0o077 == 0,
           "Use a task-owned private output parent")
    D.need(args.output.is_absolute() and ".." not in args.output.parts,
           "An explicit absolute fresh staging directory is required")
    for root in (args.compiled, args.runtime, args.prepared_artifact, args.desktop_notices, SOURCE):
        D.need(not args.output.is_relative_to(root) and not root.is_relative_to(args.output),
               "Staging output must not overlap source inputs")
    mapping: dict[str, tuple[Path, dict, int]] = {}

    def add(source: Path, destination: str, row: dict, mode: int) -> None:
        D.need(destination not in mapping and not destination.startswith("opt/"), "Package member collision")
        mapping[destination] = source, row, mode

    for name, destination in BINARIES.items():
        D.bound(args.compiled / name, binaries[name])
        elf_header(args.compiled / name)
        add(args.compiled / name, destination, binaries[name], 0o755)
    prefix = "usr/lib/mobile-release-kit/runtime-input/" + TARGET + "/" + args.manifest_sha256
    for name, row in runtime.items():
        add(args.runtime / name, prefix + "/" + name, row, 0o555 if name == "python/bin/python3" else 0o444)
    for name, row in kit.items():
        add(args.prepared_artifact / name, DOCS + "/runtime/" + name, row, 0o644)
    for name, row in native_notices.items():
        add(args.desktop_notices / name, DOCS + "/desktop/" + name, row, 0o644)
    for name, destination, mode in (
        ("postinst", "DEBIAN/postinst", 0o755), ("prerm", "DEBIAN/prerm", 0o755), ("postrm", "DEBIAN/postrm", 0o755),
        ("mobile-release-kit.desktop", "usr/share/applications/mobile-release-kit.desktop", 0o644),
        ("README.md", DOCS + "/INSTALLATION.md", 0o644),
    ):
        source = TEMPLATES / name
        add(source, destination, D.file_record(source, 64 << 10), mode)
    installed_size = (sum(row["size"] for name, (_, row, _) in mapping.items() if not name.startswith("DEBIAN/")) + 1023) // 1024
    control = controls(args.version, args.depends, installed_size)
    # Shape/inventory-pin/control checks precede the first output mutation;
    # each payload byte pin is checked again during its exclusive copy/readback.
    args.output.mkdir(mode=0o700)
    directories = {str(parent) for name in (*mapping, "DEBIAN/control") for parent in Path(name).parents if str(parent) != "."}
    for name in sorted(directories, key=lambda value: (len(Path(value).parts), value)):
        (args.output / name).mkdir(mode=0o700)
    for name, (source, row, mode) in sorted(mapping.items()):
        D.copy(source, args.output / name, row, mode)
    D.write(args.output / "DEBIAN/control", control, 0o644)
    # Publish only ordinary package directory modes after all copies/readbacks.
    for name in sorted(directories, key=lambda value: (-len(Path(value).parts), value)):
        os.chmod(args.output / name, 0o755)
    D.need({path.relative_to(args.output).as_posix() for path in P.files(args.output)} == set(mapping) | {"DEBIAN/control"},
           "Final package membership differs")
    return {"files": len(mapping) + 1, "installedSizeKiB": installed_size,
            "runtimeManifestSha256": args.manifest_sha256, "installed": False, "qualified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("compiled", "compiler-files", "runtime", "prepared-artifact", "prepared-files",
                 "desktop-notices", "desktop-notice-files", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("compiler-files-sha256", "manifest-sha256", "protocol-sha256", "prepared-files-sha256",
                 "desktop-notice-files-sha256", "version", "depends"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        D.need(os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid(), "Package staging must run without administrator privileges")
        print(D.canonical(stage(args)).decode("ascii"), end="")
    except (OSError, ValueError, Q.SmokeRefused):
        # These are fixed tool diagnostics; no input paths or private file bodies.
        parser.exit(1, "Debian staging refused; preserve partial output for inspection.\n")


if __name__ == "__main__":
    main()
