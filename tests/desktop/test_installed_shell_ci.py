"""Inert shell compiler/transport contracts; no compiler, GUI or process launch."""
from contextlib import ExitStack
from copy import deepcopy
import ast
import hashlib
import importlib.util
import io
import json
import re
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("installed_shell_ci", SOURCE / "desktop/tools/ci_ubuntu_publication.py")
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)

# Invented DATA for parser/mocked-filesystem tests ONLY; never native material.
ANDROID_MATERIAL_DATA = {"instance": "inert-android", "manifestSha256": "1" * 64,
    "osContractSha256": "2" * 64, "distributionSha256": "3" * 64}
ANDROID_PUBLICATION_DATA = {"documents": {key: {"size": 1, "sha256": digit * 64}
    for key, digit in (("manifest", "1"), ("osContract", "2"), ("sources", "4"))},
    "totals": {"toolFiles": 5, "toolDirectories": 6, "toolBytes": 5, "osFiles": 4, "osAliases": 1, "osBytes": 4}}

_REAL_S_LOCAL = S.local


def android_data_local(name):
    """Only these inert compiler/transport tests use invented source selectors."""
    module = _REAL_S_LOCAL(name)
    if name == "ubuntu_publication_lifecycle":
        module.SHELL_ANDROID_MATERIALS = deepcopy(ANDROID_MATERIAL_DATA)
        module.SHELL_ANDROID_PUBLICATION_DATA = deepcopy(ANDROID_PUBLICATION_DATA)
    return module


def compiler_rows(*, observer_test=False):
    source, target = Path("/source"), Path("/target")
    rows = []
    for role, kind, name, relative, path in (
        ("normal", "bin", "mobile-release-kit-desktop", "src/main.rs", target / S.TARGET / "debug/mobile-release-kit-desktop"),
        ("observer", "test", "installed-shell-observation", "tests/installed_shell_observation.rs",
         target / S.TARGET / "debug/deps/installed_shell_observation-0123456789abcdef"),
    ):
        rows.append({"reason": "compiler-artifact", "package_id": "root", "fresh": False,
                     "manifest_path": str(source / "desktop/src-tauri/Cargo.toml"),
                     "features": S.SHELL_FEATURES, "executable": str(path), "filenames": [str(path)],
                     "target": {"kind": [kind], "name": name, "src_path": str(source / "desktop/src-tauri" / relative)},
                     "profile": {"test": observer_test if role == "observer" else False, "opt_level": "0",
                                 "debug_assertions": True, "overflow_checks": True}})
    rows.insert(0, {"reason": "compiler-artifact", "package_id": "sha2", "features": ["std"], "fresh": False,
                    "executable": None, "target": {"kind": ["lib"], "name": "sha2"},
                    "profile": {"test": False, "opt_level": "3", "debug_assertions": True, "overflow_checks": True}})
    rows.append({"reason": "build-finished", "success": True})
    return rows


def messages(rows):
    return b"".join(json.dumps(row).encode() + b"\n" for row in rows)


def metadata():
    packages = [
        {"id": "root", "name": "mobile-release-kit-desktop", "version": "0.1.2", "source": None,
         "manifest_path": "/source/desktop/src-tauri/Cargo.toml"},
        {"id": "mount", "name": "mrk-linux-mount-observation", "version": "0.1.0", "source": None,
         "manifest_path": "/source/desktop/native/linux-mount-observation/Cargo.toml"},
        {"id": "secret-service", "name": "secret-service", "version": "5.2.0", "source": None,
         "manifest_path": "/source/desktop/vendor/secret-service-5.2.0/Cargo.toml"},
        {"id": "zbus", "name": "zbus", "version": "5.19.0", "source": None,
         "manifest_path": "/source/desktop/vendor/zbus-5.19.0/Cargo.toml"},
    ]
    # The native platform declarations remain distinct from the two maintained
    # SDKs' normal/dev inputs; Cargo resolves both SDKs to their one local source.
    packages[0]["dependencies"] = [
        {"name": name, "path": "/source/desktop/native/" + directory, "target": cfg,
         "source": None, "req": "*", "kind": None, "rename": None, "optional": False,
         "uses_default_features": True, "features": [], "registry": None}
        for name, directory, cfg in (
            ("mrk-linux-mount-observation", "linux-mount-observation",
             'cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))'),
            ("mrk-macos-installed-native", "macos-installed-native",
             'cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))'),
            ("mrk-windows-installed-native", "windows-installed-native",
             'cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))'),
        )
    ]
    packages[0]["dependencies"].append({
        "name": "mrk-windows-installed-native", "path": "/source/desktop/native/windows-installed-native",
        "target": 'cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))',
        "source": None, "req": "*", "kind": "dev", "rename": None, "optional": False,
        "uses_default_features": True, "features": ["qualification-result"], "registry": None,
    })
    for kind, support in ((None, []), ("dev", ["mrk-retrieval-test-support"])):
        packages[0]["dependencies"].append({
            "name": "secret-service", "path": "/source/desktop/vendor/secret-service-5.2.0",
            "target": 'cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))',
            "source": None, "req": "=5.2.0", "kind": kind, "rename": None, "optional": False,
            "uses_default_features": False, "features": ["rt-tokio-crypto-rust", *support], "registry": None,
        })
    for kind, support in ((None, []), ("dev", ["mrk-owned-test-support"])):
        packages[0]["dependencies"].append({
            "name": "zbus", "target": 'cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))',
            "source": "registry+https://github.com/rust-lang/crates.io-index", "req": "=5.19.0", "kind": kind,
            "rename": None, "optional": False, "uses_default_features": False,
            "features": ["tokio", *support], "registry": None,
        })
    fixed = [("tauri", "2.11.5"), ("tauri-build", "2.6.3"), ("gtk", "0.18.2"),
             ("webkit2gtk", "2.0.2"), ("wry", "0.55.1"), ("rfd", "0.15.4"), ("sha2", "0.10.9")]
    for name, version in fixed + [("inert-" + str(index), "1.0.0") for index in range(27)]:
        packages.append({"id": name, "name": name, "version": version,
                         "source": "registry+https://github.com/rust-lang/crates.io-index",
                         "manifest_path": "/private/cargo/registry/src/" + name + "/Cargo.toml"})
    nodes = [{"id": row["id"], "features": [], "deps": []} for row in packages]
    for row in nodes:
        if row["id"] == "root":
            row["features"] = S.SHELL_FEATURES
            row["deps"] = [{"pkg": name} for name in ("mount", "secret-service", "zbus")]
        elif row["id"] == "tauri":
            row["features"] = ["compression", "custom-protocol", "wry"]
        elif row["id"] == "sha2":
            row["features"] = ["std"]
    return {"workspace_root": "/source/desktop/src-tauri", "target_directory": "/target",
            "packages": packages, "resolve": {"root": "root", "nodes": nodes}}


def elf_fixture(*, runpath=None, needed="libgtk-3.so.0", soname=None, interpreter=True, rpath=False,
                kind=3, flags_1=()):
    """Structural ELF DATA only, never an executable instruction body."""
    raw = bytearray(1536)
    raw[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    interpreter_bytes = (interpreter if type(interpreter) is bytes else b"/lib64/ld-linux-x86-64.so.2\0")
    strings = b"\0" + needed.encode("ascii") + b"\0"
    dynamic = [(1, 1), (5, 1024), (10, 0)]
    if runpath:
        value = "unreviewed/path" if runpath is True else runpath
        dynamic.append((15 if rpath else 29, len(strings)))
        strings += value.encode("ascii") + b"\0"
    if soname is not None:
        dynamic.append((14, len(strings)))
        strings += soname.encode("ascii") + b"\0"
    dynamic[2] = (10, len(strings))
    dynamic.extend((0x6FFFFFFB, value) for value in flags_1)
    dynamic.append((0, 0))
    headers = [
        (1, 4, 0, 0, 0, len(raw), len(raw), 4096),
        (2, 4, 640, 640, 640, len(dynamic) * 16, len(dynamic) * 16, 8),
    ]
    if interpreter:
        headers.append((3, 4, 512, 512, 512, len(interpreter_bytes), len(interpreter_bytes), 1))
    struct.pack_into("<HHIQQQIHHHHHH", raw, 16, kind, 62, 1, 0, 64, 0, 0, 64, 56, len(headers), 0, 0, 0)
    for index, values in enumerate(headers):
        struct.pack_into("<IIQQQQQQ", raw, 64 + 56 * index, *values)
    raw[512:512 + len(interpreter_bytes)] = interpreter_bytes
    raw[1024:1024 + len(strings)] = strings
    for index, pair in enumerate(dynamic):
        struct.pack_into("<qQ", raw, 640 + index * 16, *pair)
    return bytes(raw)


def transport_data(work, change=None):
    """Synthetic transport DATA only; ELF/source admission is mocked by callers."""
    source, target = Path("/source"), Path("/target")
    identity = {"sourceSha": "a" * 40, "sourceTree": "b" * 40, "runId": "10", "attempt": "1", "features": S.SHELL_FEATURES}
    source_inputs = [{"path": "inert-source", "size": 1, "sha256": "c" * 64}]
    artifact = work / "admitted-shell"
    artifact.mkdir()
    contents = {}

    def record(name, raw):
        contents[name] = raw
        return {"path": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    elf = {"interpreter": "/lib64/ld-linux-x86-64.so.2", "needed": [], "versionNeeds": {}, "versionDefinitions": [], "soname": None}
    messages_ = compiler_rows()
    selected, units = S.shell_compiled_artifacts(messages(messages_), source, target)
    original, exported, outputs = {}, {}, {}
    for index, (role, leaf) in enumerate(S.SHELL_EXPORTS.items()):
        pin = record(leaf, ("inert " + role + " bytes; not an executable").encode())
        common = {key: pin[key] for key in ("size", "sha256")}
        original[role] = {**common, "path": selected[role]["path"], "identity": [1, 1 + index, 0o100555, 1, pin["size"], 0, 0]}
        exported[role] = {**common, "path": "/producer/public/" + leaf, "identity": [1, 3 + index, 0o100555, 1, pin["size"], 0, 0]}
        outputs[role] = {"file": {**common, "path": exported[role]["path"]}, "elf": elf, "objects": []}
    native = {"outputs": outputs, "osFiles": {}, "manifestSha256": S.C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"],
              "protocolSha256": S.C.CONVENTIONAL_SMOKE_INPUTS["protocolSha256"], "runtime": {name: {} for name in S.RUNTIME_ELF},
              "runtimeObjects": sorted({"libssl.so.3", "libcrypto.so.3", "libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2"}),
              "privateRunpaths": {name: value[1] for name, value in S.RUNTIME_ELF.items()}}
    native["hostBindingsRecord"] = record("shell-host-bindings.json", S.D.canonical({"files": {}}))
    lifecycle = S.local("ubuntu_publication_lifecycle")
    roots = {"suppliers": {}, "caches": {}}
    records = []
    for index, (root, kind) in enumerate(lifecycle.SHELL_DATA_ROOTS):
        row = {"path": ".", "kind": kind, "present": False}
        records.append(record("shell-data-" + str(index) + ".json", S.D.canonical({"entries": [row]})))
        for label, generated in (("suppliers", False), ("caches", True)):
            rows = [row] if lifecycle.shell_generated_data(root) is generated else []
            roots[label][root] = {"kind": kind, "present": False if rows else None, "entryCount": len(rows),
                                  "fileCount": 0, "byteCount": 0, "sha256": hashlib.sha256(S.D.canonical(rows)).hexdigest()}
    native["runtimeData"] = {key: {"roots": rows, "sha256": hashlib.sha256(S.D.canonical(rows)).hexdigest()}
                             for key, rows in roots.items()}
    native["runtimeData"].update(records=records, moduleSelections={}, eglLibraries={})
    frontend = {"sourceInputs": source_inputs, "embeddedBy": "tauri/custom-protocol", "devServer": False, "node": S.C.NODE,
                "dist": {"links": [], "files": [{"path": "index.html", "size": 1, "sha256": "d" * 64}]}}
    compiler = {**identity, "sourceInputs": source_inputs, "source": str(source), "target": str(target), "cargo": "/tools/cargo",
                "manifestSha256": native["manifestSha256"], "protocolSha256": native["protocolSha256"],
                "selections": selected, "compilerUnits": units, "originalArtifacts": original, "exportedArtifacts": exported,
                "nativeInputs": native, "compilerInputs": {"metadataSha256": hashlib.sha256(S.D.canonical(metadata())).hexdigest()}}
    result = {**identity, "compilations": ["normal", "observer"], "cargoBuilds": 1, "frontendBuilds": 1,
              "shellExecuted": False, "observerExecuted": False, "supplierRebuilt": False, "packageBuilt": False,
              "helper11Rerun": False, "qualified": False, "compilerCleanup": deepcopy(S.SHELL_CLEANUP_SUCCESS),
              "commands": [{"phase": "shell-compile", "ordinaryOwnerReturned": True, "exitCode": 0,
                            "argv": S.shell_compile_argv("/tools/cargo", source, target)}]}
    for row in (compiler, result):
        row.update(androidBuildMaterials=deepcopy(ANDROID_MATERIAL_DATA), androidBuildBindings={
            "MRK_ANDROID_TOOL_INSTANCE": "inert-android", "MRK_ANDROID_TOOL_MANIFEST_SHA256": "1" * 64,
            "MRK_ANDROID_OS_CONTRACT_SHA256": "2" * 64}, androidBuildPublication=deepcopy(ANDROID_PUBLICATION_DATA))
    if change is not None:
        change(compiler, result, native, messages_)
    compiler["nativeRecord"] = record("shell-native.json", S.D.canonical(native))
    compiler["frontendRecord"] = record("frontend.json", S.D.canonical(frontend))
    record("compiler.json", S.D.canonical(compiler))
    record("result.json", S.D.canonical(result))
    record("source.json", S.D.canonical({**identity, "sourceInputs": source_inputs}))
    record("shell-compile.stdout", messages(messages_))
    record("shell-compile.stderr", b"")
    record("shell-locked-inputs.stdout", S.D.canonical(metadata()))
    rows = [{"path": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} for name, raw in sorted(contents.items())]
    roster = S.D.canonical({key: identity[key] for key in ("sourceSha", "sourceTree", "runId", "attempt")} | {"files": rows})
    for name, raw in contents.items():
        (artifact / name).write_bytes(raw)
    (artifact / "shell-roster.json").write_bytes(roster)
    return {"GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "2", "MRK_INSTALLED_SHELL_PRODUCER_ATTEMPT": "1",
            "MRK_INSTALLED_SHELL_ARTIFACT_ID": "17", "MRK_INSTALLED_SHELL_ROSTER_SHA256": hashlib.sha256(roster).hexdigest()}, elf, source_inputs


class ShellPackageOwnershipContracts(unittest.TestCase):
    def test_declared_roster_keeps_members_not_usr_merge_directory_destinations(self):
        # Verbatim hosted command597 DATA, not a local package query.
        raw = (b"/.\n/lib\ndiverted by base-files to: /lib.usr-is-merged\n/usr\n/usr/lib\n"
               b"/usr/lib/x86_64-linux-gnu\n/usr/lib/x86_64-linux-gnu/libunwind-coredump.so.0.0.0\n"
               b"/usr/lib/x86_64-linux-gnu/libunwind-ptrace.so.0.0.0\n"
               b"/usr/lib/x86_64-linux-gnu/libunwind-x86_64.so.8.0.1\n"
               b"/usr/lib/x86_64-linux-gnu/libunwind.so.8.0.1\n/usr/share\n/usr/share/doc\n"
               b"/usr/share/doc/libunwind8\n/usr/share/doc/libunwind8/changelog.Debian.gz\n"
               b"/usr/share/doc/libunwind8/copyright\n/usr/lib/x86_64-linux-gnu/libunwind-coredump.so.0\n"
               b"/usr/lib/x86_64-linux-gnu/libunwind-ptrace.so.0\n"
               b"/usr/lib/x86_64-linux-gnu/libunwind-x86_64.so.8\n/usr/lib/x86_64-linux-gnu/libunwind.so.8\n")
        annotation = b"diverted by base-files to: /lib.usr-is-merged\n"
        ordinary = raw.replace(annotation, b"")
        declared = set(ordinary.decode("ascii").splitlines())
        self.assertEqual(S.shell_package_members(raw, b""), declared)
        self.assertEqual(S.shell_package_members(ordinary, b""), declared)
        self.assertNotIn("/lib.usr-is-merged", declared)
        # All fixed top-level directory spellings use the same narrow metadata
        # rule. They do not add runtime/library search roots.
        for alias in ("/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"):
            record = (alias + "\ndiverted by base-files to: " + alias + ".usr-is-merged\n").encode()
            self.assertEqual(S.shell_package_members(record, b""), {alias})
        cases = (
            (b"", b""), (ordinary, b"unexpected diagnostic\n"),
            (b"/entry\n" * 32769, b""), (b"relative\n", b""), (b"/usr/../lib\n", b""),
            (annotation + ordinary, b""), (raw.replace(b"/lib\n", b"/lib\n/usr\n", 1), b""),
            (raw.replace(annotation, annotation * 2), b""),
            (raw + b"/lib\n" + annotation, b""),
            (raw.replace(b"base-files", b"other"), b""),
            (raw.replace(b".usr-is-merged", b".diverted"), b""),
            (raw.replace(b"diverted by base-files", b"locally diverted"), b""),
            (b"/etc\ndiverted by base-files to: /etc.usr-is-merged\n", b""),
            (b"/lib/example.so\ndiverted by base-files to: /lib/example.so.usr-is-merged\n", b""),
        )
        for output, error in cases:
            with self.subTest(output=output[:128], error=error), self.assertRaises(S.D.Refused):
                S.shell_package_members(output, error)

    def test_split_link_provider_and_missing_alternative_retain_exact_suppliers(self):
        # Actual hosted dpkg output, never a local dpkg/process invocation.
        row = {"path": "/usr/bin/pkgconf", "selectedPath": "/usr/bin/pkg-config"}
        stdout = b"pkgconf:amd64: /usr/bin/pkg-config\npkgconf-bin: /usr/bin/pkgconf\n"
        rosters = {"pkgconf:amd64": {row["selectedPath"]}, "pkgconf-bin": {row["path"]}}
        for initial in ({}, {"pkgconf-bin": rosters["pkgconf-bin"]}):
            admitted, queried = [], []
            def admit(name):
                admitted.append(name)
                initial[name] = rosters[name]
            def query(aliases):
                queried.append(aliases)
                return stdout, b""
            self.assertEqual(S.shell_package_owner(row, initial, query, admit), "pkgconf-bin")
            self.assertEqual(set(initial), {"pkgconf:amd64", "pkgconf-bin"})
            self.assertIn("pkgconf:amd64", admitted)
            self.assertEqual(queried, [["/usr/bin/pkg-config", "/usr/bin/pkgconf"]])
            self.assertEqual(S.shell_package_owner(row, initial, query, admit), "pkgconf-bin")
            self.assertEqual(len(queried), 1)  # Both original complete rosters now cover this pair.
        gcc = {"path": "/usr/bin/x86_64-linux-gnu-gcc-13", "selectedPath": "/usr/bin/cc"}
        known = {}
        self.assertEqual(S.shell_package_owner(gcc, known,
            lambda aliases: (b"gcc-13-x86-64-linux-gnu: /usr/bin/x86_64-linux-gnu-gcc-13\n",
                             b"dpkg-query: no path found matching pattern /usr/bin/cc\n"),
            lambda name: known.update({name: {gcc["path"]}})), "gcc-13-x86-64-linux-gnu")
        library = {"path": "/usr/lib/x86_64-linux-gnu/libc.so.6", "selectedPath": "/lib/x86_64-linux-gnu/libc.so.6"}
        self.assertEqual(S.shell_package_owner(library, {"libc6:amd64": {library["selectedPath"]}},
            lambda _: self.fail("Already bound usr-merge spelling must not query again"),
            lambda _: self.fail("Already bound supplier must not be readmitted")), "libc6:amd64")

    def test_ambiguous_alias_only_conflicting_or_incomplete_ownership_refuses(self):
        row = {"path": "/usr/bin/pkgconf", "selectedPath": "/usr/bin/pkg-config"}
        good = b"pkgconf:amd64: /usr/bin/pkg-config\npkgconf-bin: /usr/bin/pkgconf\n"
        rosters = {"pkgconf:amd64": {row["selectedPath"]}, "pkgconf-bin": {row["path"]}}
        cases = (
            (good + b"other: /usr/bin/pkgconf\n", b"", rosters),
            (good + b"pkgconf-bin: /usr/bin/pkgconf\n", b"", rosters),
            (b"pkgconf:amd64: /usr/bin/pkg-config\n", b"dpkg-query: no path found matching pattern /usr/bin/pkgconf\n", rosters),
            (good, b"dpkg-query: no path found matching pattern /usr/bin/pkg-config\n", rosters),
            (good + b"other: /unrelated\n", b"", rosters),
            (b"pkgconf-bin: /usr/bin/pkgconf\n", b"", rosters),
            (good, b"", {"pkgconf:amd64": {row["path"]}, "pkgconf-bin": {row["path"]}}),
        )
        for stdout, stderr, listed in cases:
            with self.subTest(stdout=stdout, stderr=stderr), self.assertRaises(S.D.Refused):
                known = {}
                S.shell_package_owner(row, known, lambda _: (stdout, stderr),
                                      lambda name: known.update({name: listed[name]}))
        with self.assertRaises(S.D.Refused):
            S.shell_package_owner(row, {"pkgconf-bin": {row["path"]}, "other": {row["path"]}},
                                  lambda _: self.fail("Ambiguous cache must refuse before querying"), lambda _: None)

    def test_usr_merge_pairs_are_only_metadata_bound_to_actual_suppliers(self):
        # Verbatim hosted command530 DATA. Diversion targets are never queried,
        # opened, or substituted for the complete ordinary package member list.
        row = {"path": "/usr/lib/x86_64-linux-gnu/libreadline.so.8.2",
               "selectedPath": "/usr/lib/x86_64-linux-gnu/libreadline.so.8"}
        stdout = (b"diversion by libreadline8t64 from: /lib/x86_64-linux-gnu/libreadline.so.8\n"
                  b"diversion by libreadline8t64 to: /lib/x86_64-linux-gnu/libreadline.so.8.usr-is-merged\n"
                  b"diversion by libreadline8t64 from: /lib/x86_64-linux-gnu/libreadline.so.8.2\n"
                  b"diversion by libreadline8t64 to: /lib/x86_64-linux-gnu/libreadline.so.8.2.usr-is-merged\n"
                  b"libreadline8t64:amd64: /usr/lib/x86_64-linux-gnu/libreadline.so.8\n"
                  b"libreadline8t64:amd64: /usr/lib/x86_64-linux-gnu/libreadline.so.8.2\n")
        name = "libreadline8t64:amd64"
        rosters = {name: {row["path"], row["selectedPath"]}}
        known, admitted, queried = {}, [], []
        def admit(package):
            admitted.append(package)
            known[package] = rosters[package]
        def query(aliases):
            queried.append(aliases)
            return stdout, b""
        self.assertEqual(S.shell_package_owner(row, known, query, admit), name)
        self.assertEqual(admitted, [name])
        self.assertEqual(known, rosters)
        self.assertEqual(queried, [["/lib/x86_64-linux-gnu/libreadline.so.8", "/lib/x86_64-linux-gnu/libreadline.so.8.2",
                                   row["selectedPath"], row["path"]]])
        self.assertEqual(S.shell_package_owner(row, known, query, admit), name)
        self.assertEqual(len(queried), 1)

        lines = stdout.splitlines(keepends=True)
        ordinary_alias = b"libreadline8t64:amd64: /lib/x86_64-linux-gnu/libreadline.so.8\n"
        cases = (
            ("local", stdout.replace(b"diversion by libreadline8t64", b"local diversion"), b"", rosters),
            ("general-target", stdout.replace(b".usr-is-merged\n", b".diverted\n"), b"", rosters),
            ("unpaired-to", stdout.replace(lines[0], b""), b"", rosters),
            ("unpaired-from", stdout.replace(lines[1], b""), b"", rosters),
            ("repeated-pair", b"".join(lines[:2]) + stdout, b"", rosters),
            ("unrelated", stdout.replace(b": /lib/", b": /lib/unrelated/"), b"", rosters),
            ("non-lib-source", stdout.replace(b": /lib/", b": /usr/lib/"), b"", rosters),
            ("diagnostic-package-grammar", stdout.replace(b"diversion by libreadline8t64 ", b"diversion by libreadline8t64:amd64 "), b"", rosters),
            ("wrong-package", stdout.replace(b"diversion by libreadline8t64", b"diversion by other"), b"", rosters),
            ("mismatched-pair", stdout.replace(b"diversion by libreadline8t64 to:", b"diversion by other to:", 1), b"", rosters),
            ("ordinary-before", ordinary_alias + stdout, b"", rosters),
            ("ordinary-after", stdout + ordinary_alias, b"", rosters),
            ("missing-conflict", stdout, b"dpkg-query: no path found matching pattern /lib/x86_64-linux-gnu/libreadline.so.8\n", rosters),
            ("missing-usr-supplier", stdout.replace(lines[4], b""),
             b"dpkg-query: no path found matching pattern /usr/lib/x86_64-linux-gnu/libreadline.so.8\n", {name: {row["path"]}}),
            ("false-canonical-owner", stdout.replace(lines[5], lines[5].replace(name.encode(), b"other")), b"",
             {name: {row["selectedPath"]}, "other": {row["path"]}}),
            ("incomplete-roster", stdout, b"", {name: {row["selectedPath"]}}),
            ("diverted-roster-alias", stdout, b"", {name: rosters[name] | {"/lib/x86_64-linux-gnu/libreadline.so.8"}}),
        )
        for label, output, error, listed in cases:
            with self.subTest(case=label), self.assertRaises(S.D.Refused):
                known = {}
                S.shell_package_owner(row, known, lambda _: (output, error),
                                      lambda package: known.update({package: listed[package]}))


class AndroidLocalTransportContracts(unittest.TestCase):
    """Same-job records and actual tiny file copies; no tool/native execution."""

    def context_fixture(self, parent):
        root = parent / "mrk-desktop-ubuntu-publisher-10-1-compile"
        root.mkdir(mode=0o700); (root / "private-compiler").mkdir(mode=0o700)
        material = parent / "mrk-android-material-10-1"
        material.mkdir(mode=0o700); (material / "private").mkdir(mode=0o700)
        original = {"sourceSha": "a" * 40, "runId": "10", "attempt": "1", "source": str(S.SOURCE),
            "root": str(root), "deadline": "1200.0", "runnerUid": S.os.getuid(), "runnerGid": S.os.getgid(),
            "rootIdentity": list(S.directory_identity(root)), "workIdentity": [1, 2, 3, 4, 5], "shellCase": "compile", "job": "compile"}
        S.D.write(root / "preparation.json", S.D.canonical(original))
        roster = S.D.write(root / "private-compiler/shell-roster.json", b"inert-compiler-roster\n")
        S.D.write(material / "private/prepared.json", b"inert-original-material-record\n")
        compiler = {"sourceSha": "a" * 40, "sourceTree": "b" * 40, "runId": "10", "attempt": "1",
                    "androidBuildMaterials": deepcopy(ANDROID_MATERIAL_DATA), "androidBuildPublication": deepcopy(ANDROID_PUBLICATION_DATA)}
        preparation = {"materials": deepcopy(ANDROID_MATERIAL_DATA), "publication": deepcopy(ANDROID_PUBLICATION_DATA),
                       "materialRoot": str(material)}
        return root, compiler, preparation, roster

    def test_same_attempt_original_context_and_private_record_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            with patch.dict(S.os.environ, {"GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "compile",
                                         "RUNNER_TEMP": str(parent)}, clear=True):
                root, compiler, preparation, roster = self.context_fixture(parent)
                transport = S.android_local_transport_record(root, compiler, preparation, roster)
                context = S.android_local_transport_context(transport, compiler_root=root,
                    source_sha="a" * 40, source_tree="b" * 40)
                self.assertEqual(context["runAttempt"], "1")
                self.assertNotIn("artifactId", S.D.canonical(transport).decode())
                self.assertEqual(transport["kind"], "android-same-job-local-v1")
                for field, value in (("runAttempt", "2"), ("job", "other"), ("sourceCommit", "c" * 40), ("sourceTree", "c" * 40)):
                    changed = deepcopy(transport); changed["context"][field] = value
                    with self.subTest(field=field), self.assertRaises(S.D.Refused):
                        S.android_local_transport_context(changed, compiler_root=root, source_sha="a" * 40, source_tree="b" * 40)
                for field in ("compilerRoot", "compilerEvidence", "materialRoot"):
                    changed = deepcopy(transport); changed[field]["identity"][1] += 1
                    with self.subTest(field=field), self.assertRaises(S.D.Refused):
                        S.android_local_transport_context(changed, compiler_root=root, source_sha="a" * 40, source_tree="b" * 40)
                with patch.dict(S.os.environ, {"GITHUB_RUN_ATTEMPT": "2"}), self.assertRaises(S.D.Refused):
                    S.android_local_transport_context(transport, compiler_root=root, source_sha="a" * 40, source_tree="b" * 40)
                path = root / "private-compiler/shell-roster.json"
                path.write_bytes(b"changed-inert-roster\n")
                with self.assertRaises(S.D.Refused):
                    S.android_local_transport_context(transport, compiler_root=root, source_sha="a" * 40, source_tree="b" * 40)

    def copy_fixture(self, parent):
        source, target = parent / "source", parent / "copy"
        source.mkdir(mode=0o700); (source / "jdk").mkdir(mode=0o700); (source / "jdk/bin").mkdir(mode=0o700)
        S.D.write(source / "jdk/bin/java", b"inert executable DATA only\n", 0o500)
        S.D.write(source / "jdk/input.txt", b"bounded fixture data\n", 0o400)
        rows = [{**S.D.file_record(source / name), "path": name} for name in ("jdk/bin/java", "jdk/input.txt")]
        return source, target, rows, ["jdk", "jdk/bin"]

    def test_fresh_exact_private_copy_retains_source_and_uses_no_ordinary_tree_reader(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(S.time, "monotonic", return_value=1.0), \
             patch.object(S.C, "conventional_files", side_effect=AssertionError("ordinary 8192-entry reader must not be used")):
            source, target, rows, directories = self.copy_fixture(Path(temporary))
            result = S.android_copy_private_tree(source, target, rows, directories, deadline=10.0,
                                                role="material", executable=("jdk/bin/java",))
            self.assertEqual((result["files"], result["directories"], result["bytes"]), (2, 2, sum(r["size"] for r in rows)))
            self.assertTrue(result["freshCopies"])
            for row in rows:
                original, copied = source / row["path"], target / row["path"]
                self.assertEqual(original.read_bytes(), copied.read_bytes())
                self.assertNotEqual(original.stat().st_ino, copied.stat().st_ino)
                self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o500 if row["path"].endswith("/java") else 0o400)
            self.assertEqual(sorted(p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_dir()), directories)

    def test_extra_empty_directory_alias_collision_body_drift_and_capacity_refuse(self):
        for failure in ("extra", "missing", "alias", "mode", "collision", "body", "capacity", "late", "directory-roster"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary, \
                 patch.object(S.time, "monotonic", return_value=10.0 if failure == "late" else 1.0):
                source, target, rows, directories = self.copy_fixture(Path(temporary))
                if failure == "extra": (source / "empty").mkdir(mode=0o700)
                if failure == "missing": (source / "jdk/input.txt").unlink()
                if failure == "alias":
                    (source / "jdk/input.txt").unlink(); (source / "jdk/input.txt").symlink_to(source / "jdk/bin/java")
                if failure == "mode": (source / "jdk/input.txt").chmod(0o600)
                if failure == "collision": target.mkdir(mode=0o700); (target / "sentinel").write_bytes(b"preserve")
                if failure == "body":
                    (source / "jdk/input.txt").chmod(0o600); (source / "jdk/input.txt").write_bytes(b"x" * rows[1]["size"])
                    (source / "jdk/input.txt").chmod(0o400)
                if failure == "directory-roster": directories.append("unused")
                actual_statvfs = S.os.statvfs
                with patch.object(S.os, "statvfs", side_effect=(lambda _: SimpleNamespace(f_bavail=0, f_frsize=4096, f_favail=0))
                                  if failure == "capacity" else actual_statvfs), self.assertRaises((S.D.Refused, FileExistsError)):
                    S.android_copy_private_tree(source, target, rows, directories, deadline=10.0,
                                                role="material", executable=("jdk/bin/java",))
                if failure == "collision": self.assertEqual((target / "sentinel").read_bytes(), b"preserve")
                if failure in {"extra", "missing", "alias", "mode", "directory-roster", "capacity", "late"}:
                    self.assertFalse(target.exists())

    def test_original_subdirectory_cannot_be_replaced_by_equal_bytes(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(S.time, "monotonic", return_value=1.0):
            source, target, rows, directories = self.copy_fixture(Path(temporary))
            real_copy = S.D.copy
            def copy(original, destination, row, mode):
                real_copy(original, destination, row, mode)
                if original.name == "java":
                    saved = source / "jdk/retained-original-bin"
                    (source / "jdk/bin").rename(saved)
                    (source / "jdk/bin").mkdir(mode=0o700)
                    S.D.write(source / "jdk/bin/java", (saved / "java").read_bytes(), 0o500)
            with patch.object(S.D, "copy", side_effect=copy), self.assertRaisesRegex(S.D.Refused, "source directory changed"):
                S.android_copy_private_tree(source, target, rows, directories, deadline=10.0,
                                            role="material", executable=("jdk/bin/java",))

    def test_already_copied_target_cannot_drift_or_be_replaced_before_completion(self):
        for replace in (False, True):
            with self.subTest(replace=replace), tempfile.TemporaryDirectory() as temporary, \
                 patch.object(S.time, "monotonic", return_value=1.0):
                source, target, rows, directories = self.copy_fixture(Path(temporary))
                real_copy = S.D.copy
                def copy(original, destination, row, mode):
                    real_copy(original, destination, row, mode)
                    if original.name == "input.txt":
                        prior = target / "jdk/bin/java"
                        body = prior.read_bytes()
                        if replace:
                            saved = Path(temporary) / "retained-original-target"
                            prior.rename(saved)
                            S.D.write(prior, body, 0o500)
                        else:
                            prior.chmod(0o600); prior.write_bytes(b"x" * len(body)); prior.chmod(0o500)
                with patch.object(S.D, "copy", side_effect=copy), self.assertRaisesRegex(
                        S.D.Refused, "Admitted DATA bytes differ|changed or completed late"):
                    S.android_copy_private_tree(source, target, rows, directories, deadline=10.0,
                                                role="material", executable=("jdk/bin/java",))


class PrivateAndroidCommandContracts(unittest.TestCase):
    """Only a mock owner and bounded temporary DATA; never starts a process."""

    def test_original_private_captures_and_public_serialization_are_separate(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(S.time, "monotonic", return_value=1.0):
            root = Path(temporary); (root / "public").mkdir(mode=0o700)
            argv = ["/inert/tool", "https://invalid.example/asset?private-query-marker"]
            result = S.subprocess.CompletedProcess(argv, 0, b"private-output-marker", b"private-diagnostic-marker")
            owner = Mock(return_value=result)
            check = S.Check(root, owner, deadline=10.0, private=True)
            with patch("sys.stdout", new=io.StringIO()) as output:
                self.assertIs(check.command("compile-inert", argv, {}, root, timeout=4), result)
                self.assertIs(check.private_command("material-inert", argv, {}, root, timeout=4), result)
            self.assertEqual(owner.call_count, 2)
            self.assertTrue(all(call.kwargs["timeout"] == 4 and call.kwargs["capture"] is True
                                for call in owner.call_args_list))
            self.assertEqual(list((root / "public").iterdir()), [])
            for role, label in (("compiler", "compile-inert"), ("material", "material-inert")):
                directory = root / ("private-" + role)
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                self.assertEqual((directory / (label + ".stdout")).read_bytes(), result.stdout)
                self.assertEqual((directory / (label + ".stderr")).read_bytes(), result.stderr)
                request = json.loads((directory / (label + ".request.json")).read_bytes())
                self.assertEqual(request["argv"], argv)
                self.assertEqual(json.loads((directory / (label + ".result.json")).read_bytes())["argv"], argv)
            public = S.D.canonical(check.commands) + output.getvalue().encode()
            for forbidden in (b"private-query-marker", b"private-output-marker", b"private-diagnostic-marker", b"argv", b"/inert/tool"):
                self.assertNotIn(forbidden, public)
            self.assertEqual(check.original_commands[0]["argv"], argv)
            self.assertEqual(check.retained, sum(path.stat().st_size for role in ("compiler", "material")
                                                for path in (root / ("private-" + role)).iterdir()))
            self.assertTrue(all(row["ordinaryOwnerReturned"] is True and row["exitCode"] == 0 for row in check.commands))
            pin = {"path": "/private-path-marker", "size": 1, "sha256": "a" * 64}
            identity = {"sourceSha": "a" * 40, "sourceTree": "b" * 40, "runId": "10", "attempt": "1"}
            compiler = {**identity, "features": S.SHELL_FEATURES,
                        "exportedArtifacts": {role: dict(pin) for role in S.SHELL_EXPORTS},
                        "nativeInputs": {"raw": "private-host-marker"}, "source": "/private-source-marker"}
            result = {**identity, "features": S.SHELL_FEATURES, "compilations": ["normal", "observer"],
                "cargoBuilds": 1, "frontendBuilds": 1, "compilerCleanup": deepcopy(S.SHELL_CLEANUP_SUCCESS),
                **{key: False for key in ("shellExecuted", "observerExecuted", "supplierRebuilt", "packageBuilt", "helper11Rerun", "qualified")}}
            preparation = {"materials": deepcopy(ANDROID_MATERIAL_DATA), "publication": deepcopy(ANDROID_PUBLICATION_DATA),
                "provenance": {"policySha256": "c" * 64, "documents": "private-input-marker"}, "materialRoot": "/private-root-marker"}
            records = {name: dict(pin) for name in ("compiler.json", "source.json", "result.json", "shell-roster.json")}
            original = S.D.canonical([compiler, result, preparation, records])
            summary = S.android_compiler_public_summary(compiler, result, preparation, records, check.commands)
            public = S.D.canonical(summary)
            for forbidden in (b"private-path-marker", b"private-host-marker", b"private-input-marker", b"private-source-marker",
                              b"private-root-marker", b"private-output-marker", b"private-diagnostic-marker", b"private-query-marker"):
                self.assertNotIn(forbidden, public)
            self.assertEqual(summary["outputs"]["normal"]["path"], S.SHELL_EXPORTS["normal"])
            self.assertFalse(summary["crossJobReusePermitted"])
            self.assertEqual(S.D.canonical([compiler, result, preparation, records]), original)
            with self.assertRaises(S.D.Refused):
                S.android_compiler_public_summary(compiler, result, preparation, records,
                    [{**check.commands[0], "argv": ["must-not-be-public"]}])

    def test_unknown_owner_nonzero_and_late_completion_stay_failed_without_public_raw_output(self):
        for failure in ("owner", "nonzero", "late"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary, \
                 patch.object(S.time, "monotonic", side_effect=[1.0, 10.0] if failure == "late" else lambda: 1.0), \
                 patch("sys.stdout", new=io.StringIO()), patch("sys.stderr", new=io.StringIO()) as error_output:
                root = Path(temporary); (root / "public").mkdir(mode=0o700)
                argv = ["/inert/tool", "private-argument-marker"]
                result = S.subprocess.CompletedProcess(argv, 7 if failure == "nonzero" else 0,
                                                      b"private-output-marker", b"private-diagnostic-marker")
                owner = Mock(side_effect=RuntimeError("private-error-marker") if failure == "owner" else None, return_value=result)
                check = S.Check(root, owner, deadline=10.0)
                with self.assertRaises((RuntimeError, S.D.Refused)) as refused:
                    check.private_command("material-inert", argv, {}, root)
                self.assertTrue(check.failed)
                S.retain_failure(root, check.phase, check.commands, refused.exception)
                with self.assertRaisesRegex(S.D.Refused, "Prior command failed"):
                    check.private_command("later-inert", argv, {}, root)
                owner.assert_called_once()
                self.assertEqual(check.commands[0]["ordinaryOwnerReturned"], failure != "owner")
                public = (root / "public/failure.json").read_bytes() + error_output.getvalue().encode()
                for forbidden in (b"private-argument-marker", b"private-output-marker", b"private-diagnostic-marker", b"private-error-marker"):
                    self.assertNotIn(forbidden, public)
                self.assertEqual([path.name for path in (root / "public").iterdir()], ["failure.json"])

    def test_collision_request_bound_and_unclosed_retention_never_start_another_owner(self):
        for failure in ("collision", "request-bound", "write", "capture-bound"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary, \
                 patch.object(S.time, "monotonic", return_value=1.0), patch("sys.stdout", new=io.StringIO()):
                root = Path(temporary); (root / "public").mkdir(mode=0o700)
                argv = ["/inert/tool"]
                result = S.subprocess.CompletedProcess(argv, 0, b"abc", b"")
                owner = Mock(return_value=result); check = S.Check(root, owner, deadline=10.0)
                if failure == "collision": (root / "private-material").mkdir(mode=0o700)
                if failure == "request-bound": argv.append("x" * (64 << 10))
                real_write = S.D.write
                def write(path, raw, *args):
                    if failure == "write": raise OSError("private-write-marker")
                    return real_write(path, raw, *args)
                with patch.object(S.D, "write", side_effect=write), self.assertRaises((S.D.Refused, OSError)):
                    check.private_command("material-inert", argv, {}, root, limit=1 if failure == "capture-bound" else 32)
                self.assertTrue(check.failed)
                self.assertEqual(owner.call_count, int(failure == "capture-bound"))
                if failure == "write": self.assertGreater(check.retained, 0)
                self.assertEqual(list((root / "public").iterdir()), [])

    def test_metadata_coalesces_exact_originals_without_raw_stream_deletion_or_roster_growth(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(S.time, "monotonic", return_value=1.0), \
             patch("sys.stdout", new=io.StringIO()):
            root = Path(temporary); (root / "public").mkdir(mode=0o700)
            argv = ["/inert/tool", "private-argument"]
            owner = Mock(return_value=S.subprocess.CompletedProcess(argv, 0, b"private-output", b"private-error"))
            check = S.Check(root, owner, deadline=10.0, private=True)
            check.command("compile-one", argv, {}, root)
            check.command("compile-two", argv, {}, root)
            path = root / "private-compiler"
            originals = {p.name: p.read_bytes() for p in path.iterdir()}
            pin = S.android_close_compiler_metadata(check)
            packed = S.D.decode((path / pin["path"]).read_bytes())
            self.assertEqual(len(packed["files"]), 4)
            for row in packed["files"]:
                raw = S.D.canonical(row["body"])
                self.assertEqual(raw, originals[row["path"]])
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (row["size"], row["sha256"]))
                self.assertFalse((path / row["path"]).exists())
            streams = {name for name in originals if name.endswith((".stdout", ".stderr"))}
            self.assertEqual({p.name for p in path.iterdir()}, streams | {pin["path"]})
            for name in streams: self.assertEqual((path / name).read_bytes(), originals[name])
            self.assertTrue(all(row["argv"] == argv for row in check.original_commands))
            self.assertFalse(check.failed)
            self.assertEqual(list((root / "public").iterdir()), [])

    def test_metadata_drift_collision_or_unknown_owner_preserves_originals(self):
        for failure in ("drift", "collision", "unknown-owner"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary, \
                 patch.object(S.time, "monotonic", return_value=1.0), patch("sys.stdout", new=io.StringIO()):
                root = Path(temporary); (root / "public").mkdir(mode=0o700)
                argv = ["/inert/tool"]
                owner = Mock(return_value=S.subprocess.CompletedProcess(argv, 0, b"private-output", b"private-error"))
                check = S.Check(root, owner, deadline=10.0, private=True)
                check.command("compile-one", argv, {}, root)
                path = root / "private-compiler"
                if failure == "drift": (path / "compile-one.request.json").write_bytes(b"different\n")
                if failure == "collision": S.D.write(path / "private-command-metadata.json", b"preserve\n")
                if failure == "unknown-owner": check.failed = True; check.commands[0]["ordinaryOwnerReturned"] = False
                originals = {p.name: p.read_bytes() for p in path.iterdir()}
                with self.assertRaises((S.D.Refused, FileExistsError)):
                    S.android_close_compiler_metadata(check)
                self.assertTrue(check.failed)
                self.assertEqual({p.name: p.read_bytes() for p in path.iterdir()}, originals)
                owner.assert_called_once()


class AndroidSameJobIntegrationContracts(unittest.TestCase):
    """Real private files/driver integration, with every process/native owner mocked."""

    def test_local_stage_copies_exact_original_documents_and_preserves_refused_partial_inputs(self):
        for fault in (None, "compiler-drift", "collision", "material-recheck", "expired"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
                parent = Path(temporary)
                stack.enter_context(patch.dict(S.os.environ, {"GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_JOB": "compile", "RUNNER_TEMP": str(parent), "MRK_INSTALLED_SHELL_TRANSPORT": "android-same-job-local-v1"}, clear=True))
                stack.enter_context(patch.object(S.time, "monotonic", return_value=10.0 if fault == "expired" else 1.0))
                root, compiler, material, _ = AndroidLocalTransportContracts().context_fixture(parent)
                lifecycle = _REAL_S_LOCAL("ubuntu_publication_lifecycle")
                material_root = Path(material["materialRoot"])
                (material_root / "tools").mkdir(mode=0o700)
                (material_root / "tools/jdk").mkdir(mode=0o700)
                (material_root / "tools/jdk/bin").mkdir(mode=0o700)
                tool_pin = S.D.write(material_root / "tools/jdk/bin/java", b"inert DATA; never an executable body\n", 0o500)
                documents = {}
                for key, name in lifecycle.SHELL_ANDROID_DOCUMENT_NAMES.items():
                    documents[key] = S.android_private_pin(S.D.write(material_root / name, ("inert-" + key + "\n").encode(), 0o400))
                material["materials"].update(manifestSha256=documents["manifest"]["sha256"], osContractSha256=documents["osContract"]["sha256"])
                material["publication"] = {"documents": documents, "totals": {"toolFiles": 1, "toolDirectories": 2,
                    "toolBytes": tool_pin["size"], "osFiles": 4, "osAliases": 1, "osBytes": 4}}
                host_pin = S.D.write(material_root / "private/host.json", b'{"inert":"private-host-marker"}\n', 0o400)
                material["provenance"] = {"documents": {"host": host_pin}}
                prepared = material_root / "private/prepared.json"
                prepared.write_bytes(S.D.canonical(material)); prepared.chmod(0o400)
                compiler.update(androidBuildMaterials=material["materials"], androidBuildPublication=material["publication"])
                compiler_pin = S.D.write(root / "private-compiler/compiler.json", S.D.canonical(compiler))
                compiler_files = [compiler_pin, *(S.D.write(root / "private-compiler" / name,
                    b"inert shell file DATA; never executed\n", 0o555) for name in S.SHELL_EXPORTS.values())]
                roster_path = root / "private-compiler/shell-roster.json"
                roster_path.write_bytes(S.D.canonical({**{key: compiler[key] for key in ("sourceSha", "sourceTree", "runId", "attempt")},
                    "files": sorted(compiler_files, key=lambda row: row["path"])}))
                roster_pin = S.D.file_record(roster_path)
                transport = S.android_local_transport_record(root, compiler, material, roster_pin)
                transport_pin = S.D.write(root / "android-local-transport.json", S.D.canonical(transport), 0o400)
                native = parent / "mrk-desktop-ubuntu-publisher-10-1-observe"
                native.mkdir(mode=0o700)
                for name in ("work", "public"): (native / name).mkdir(mode=0o700)
                engine = SimpleNamespace(read_record=Mock(return_value=material), validate=Mock(
                    side_effect=S.D.Refused("inert final material drift") if fault == "material-recheck" else None))
                plan = {"documents": documents, "totals": material["publication"]["totals"], "directories": ["jdk", "jdk/bin"],
                    "files": [{**tool_pin, "path": "jdk/bin/java", "mode": 0o555}]}
                stack.enter_context(patch.object(S, "local", return_value=engine))
                stack.enter_context(patch.object(lifecycle, "_android_publication_plan", return_value=plan))
                stack.enter_context(patch.dict(S.os.environ, {"MRK_INSTALLED_SHELL_LOCAL_TRANSPORT_SHA256": transport_pin["sha256"],
                    "MRK_INSTALLED_SHELL_ROSTER_SHA256": roster_pin["sha256"], "MRK_INSTALLED_SHELL_PRODUCER_ATTEMPT": "1"}))
                owner = Mock(side_effect=AssertionError("local staging is command-free"))
                check = S.Check(native, owner, deadline=10.0, private=True)
                if fault == "compiler-drift": (root / "private-compiler/compiler.json").write_bytes(b"changed original")
                elif fault == "collision":
                    (native / "work/admitted-shell").mkdir(mode=0o700)
                    S.D.write(native / "work/admitted-shell/sentinel", b"preserve unrelated input")
                if fault:
                    with self.assertRaises((S.D.Refused, FileExistsError)): S.android_stage_local_inputs(check, "a" * 40, lifecycle)
                    self.assertTrue(check.failed)
                    if fault == "collision": self.assertEqual((native / "work/admitted-shell/sentinel").read_bytes(), b"preserve unrelated input")
                else:
                    self.assertEqual(S.android_stage_local_inputs(check, "a" * 40, lifecycle), (transport, material))
                    self.assertFalse(check.failed)
                    self.assertEqual((native / "work/admitted-android/tools/jdk/bin/java").read_bytes(),
                                     (material_root / "tools/jdk/bin/java").read_bytes())
                    self.assertEqual({p.name for p in (native / "work/admitted-android").iterdir()},
                                     {"tools", *lifecycle.SHELL_ANDROID_DOCUMENT_NAMES.values()})
                    self.assertEqual({p.name for p in (native / "private-compiler").iterdir()}, {"android-local-copy.json"})
                owner.assert_not_called()
                self.assertTrue(prepared.exists())  # Failure/success never deletes original preparation.
                self.assertEqual(list((native / "public").iterdir()), [])

    def command_fixture(self, root):
        root.mkdir(mode=0o700)
        (root / "public").mkdir(mode=0o700)
        argv = ["/inert/tool", "private-argument-marker"]
        owner = Mock(return_value=S.subprocess.CompletedProcess(argv, 0, b"private-output-marker", b""))
        check = S.Check(root, owner, deadline=10.0, private=True)
        check.command("compile-inert", argv, {}, root)
        check.private_command("material-inert", argv, {}, root)
        result = {"commands": deepcopy(check.original_commands),
            "privateCommandRoles": {"compiler": ["compile-inert"], "material": ["material-inert"]},
            "privateCaptureRoots": {role: list(value) for role, value in check.private_roots.items()},
            "privateMaterialMetadata": deepcopy(check.private_metadata["material"]),
            "privateCommandMetadata": S.android_close_compiler_metadata(check)}
        artifact = root / "private-compiler"
        rows = {p.name: S.D.file_record(p) for p in artifact.iterdir()}
        transport = {"compilerRoot": {"path": str(root)}, "compilerEvidence": {
            "identity": list(S.directory_identity(artifact))}}
        return artifact, rows, result, transport, owner

    def test_complete_original_command_roles_metadata_captures_and_directory_custody(self):
        faults = (None, "role-overlap", "omitted-argv", "omitted-material", "unknown-owner", "index-pin",
                  "material-body", "material-extra", "material-root", "expired")
        for fault in faults:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary, \
                 patch.object(S.time, "monotonic", return_value=1.0), patch("sys.stdout", new=io.StringIO()):
                artifact, rows, result, transport, owner = self.command_fixture(Path(temporary) / "compile")
                root = artifact.parent
                if fault == "role-overlap": result["privateCommandRoles"]["material"].append("compile-inert")
                elif fault == "omitted-argv": result["commands"][0]["argv"] = ["/inert/other"]
                elif fault == "omitted-material": result["privateMaterialMetadata"].pop()
                elif fault == "unknown-owner": result["commands"][1]["ordinaryOwnerReturned"] = False
                elif fault == "index-pin": result["privateCommandMetadata"]["sha256"] = "0" * 64
                elif fault == "material-body": (root / "private-material/material-inert.stdout").write_bytes(b"different-inert-data")
                elif fault == "material-extra": S.D.write(root / "private-material/extra", b"unapproved")
                elif fault == "material-root":
                    (root / "private-material").rename(root / "retained-original")
                    (root / "private-material").mkdir(mode=0o700)
                if fault:
                    with self.assertRaises(S.D.Refused):
                        S.android_original_command_records(artifact, rows, result, transport, deadline=1.0 if fault == "expired" else 10.0)
                else:
                    S.android_original_command_records(artifact, rows, result, transport, deadline=10.0)
                    self.assertEqual((root / "private-material/material-inert.stdout").read_bytes(), b"private-output-marker")
                    self.assertEqual(list((root / "public").iterdir()), [])
                self.assertEqual(owner.call_count, 2)  # DATA validation never reruns an owner.

    def test_real_compiler_cardinality_fits_unchanged_transport_after_exact_metadata_coalescing(self):
        # The retained target has697 original commands, not a two-command toy
        # roster. These are inert mock results, NOT a compilation/native pass.
        with tempfile.TemporaryDirectory() as temporary, patch.object(S.time, "monotonic", return_value=1.0), \
             patch("sys.stdout", new=io.StringIO()):
            root = Path(temporary); (root / "public").mkdir(mode=0o700)
            argv = ["/inert/tool"]
            owner = Mock(return_value=S.subprocess.CompletedProcess(argv, 0, b"inert\n", b""))
            check = S.Check(root, owner, deadline=10.0, private=True)
            for index in range(697): check.command("inert-" + str(index), argv, {}, root)
            for index in range(31): S.D.write(check.evidence_root / ("record-" + str(index) + ".json"), b"{}\n")
            old_charge = check.retained
            pin = S.android_close_compiler_metadata(check)
            self.assertEqual(len(S.D.decode((check.evidence_root / pin["path"]).read_bytes())["files"]), 1394)
            S.D.write(check.evidence_root / "shell-roster.json", S.D.canonical({"files": [
                S.D.file_record(p) for p in sorted(check.evidence_root.iterdir())]}))
            self.assertEqual(len(list(check.evidence_root.iterdir())), 1427)
            self.assertLessEqual(len(list(check.evidence_root.iterdir())), 1536)
            self.assertEqual(check.retained, old_charge + pin["size"])  # No deletion credit.
            self.assertEqual(owner.call_count, 697)
            self.assertFalse(check.failed)

    def test_actual_native_driver_keeps_success_and_all_failure_uploads_typed_and_private(self):
        for fault in (None, "input", "owner", "finality"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
                parent = Path(temporary)
                source, root = parent / "source", parent / "mrk-desktop-ubuntu-publisher-10-1-observe"
                (source / "desktop/tools").mkdir(parents=True)
                entry = source / "desktop/tools/ubuntu_publication_lifecycle.py"
                entry.write_bytes(b"inert entry DATA only\n")
                root.mkdir(mode=0o700)
                for name in ("work", "public", "cases"): (root / name).mkdir(mode=0o700)
                work = root / "work"
                (work / "admitted-shell").mkdir(mode=0o700)
                S.D.write(work / "admitted-shell/compiler.json", b'{"inert":"private-compiler-marker"}\n')
                library_path = work / "private-library-marker"
                S.D.write(library_path, b"inert library DATA\n")
                compiler_root = parent / "mrk-desktop-ubuntu-publisher-10-1-compile"
                compiler_root.mkdir(mode=0o700)
                transport = {"compilerRoot": {"path": str(compiler_root)}, "privateInput": "private-transport-marker"}
                S.D.write(compiler_root / "android-local-transport.json", S.D.canonical(transport), 0o400)
                pin = {"size": 1, "sha256": "c" * 64}
                compiler = {"sourceSha": "a" * 40, "sourceTree": "b" * 40, "runId": "10", "attempt": "1",
                    "features": S.SHELL_FEATURES, "manifestSha256": "c" * 64, "protocolSha256": "d" * 64,
                    "exportedArtifacts": {}, "nativeRecord": pin, "frontendRecord": pin,
                    "androidBuildMaterials": deepcopy(ANDROID_MATERIAL_DATA), "androidBuildBindings": {},
                    "androidBuildPublication": deepcopy(ANDROID_PUBLICATION_DATA),
                    "androidPreparation": {"path": "/private-preparation-marker", **pin},
                    "androidOsContractInput": {"path": "/private-os-marker", **pin}}
                preparation = {"materials": deepcopy(ANDROID_MATERIAL_DATA), "publication": deepcopy(ANDROID_PUBLICATION_DATA),
                    "provenance": {"policySha256": "e" * 64, "private": "private-host-marker"}}
                lifecycle = _REAL_S_LOCAL("ubuntu_publication_lifecycle")
                lifecycle.SHELL_ANDROID_MATERIALS = deepcopy(ANDROID_MATERIAL_DATA)
                lifecycle.SHELL_ANDROID_PUBLICATION_DATA = deepcopy(ANDROID_PUBLICATION_DATA)
                observed = {"state": lifecycle.result_state({"shell": {}}), "productQualified": False,
                    "sourceSha": "a" * 40, "consumerAttempt": "1", "packageLifecycleQualified": False,
                    "shellPackageBuilt": False, "privateInput": "private-native-marker",
                    "lifecycleDocuments": {"privateInput": "private-lifecycle-marker"},
                    "cases": {case: {"exitCode": 1 if case == "settled-failure" else 0} for case in lifecycle.SHELL_CASES},
                    **{key: {} for key in ("candidateDocuments", "projectPaths", "workflowApply", "sessionInputs", "metadataSave",
                        "versionSave", "toolsOffline", "androidBuild", "androidPublication", "settledFailure")}}
                seen = []
                def owner(argv, **kwargs):
                    seen.append(argv)
                    if argv[0] == "/inert/root-driver":
                        if fault == "owner": raise RuntimeError("private-owner-marker")
                        return S.subprocess.CompletedProcess(argv, 0, b"private-driver-marker", b"")
                    return S.subprocess.CompletedProcess(argv, 0, b"a" * 40 + b"\n" if "rev-parse" in argv else b"", b"")
                def stage(check, sha, actual):
                    self.assertIs(actual, lifecycle)
                    if fault == "input": raise S.D.Refused("private-input-marker /private-path-marker")
                    return transport, preparation
                def collect(path, digest, entry_sha, client, output):
                    self.assertEqual(output, root / "private-compiler")
                    if fault == "finality": raise S.D.Refused("private-finality-marker /private-root-marker")
                    request = lifecycle.decode(path.read_bytes())
                    observed["shellLocalTransport"] = request["shell"]["localTransport"]
                    S.D.write(output / "lifecycle-original.json", b'{"raw":"private-original-marker"}\n')
                    return observed
                for obj, name, replacement in ((S, "resumed_preparation", Mock(return_value=("a" * 40, source, parent, root, 10.0))),
                        (S, "local", Mock(return_value=lifecycle)), (lifecycle, "check_source_pins", Mock()),
                        (S, "installed_u_inputs", Mock(return_value=({"path": str(library_path)}, {},
                            {"sourceSha": "f" * 40, "nativeInputs": {"outputs": {"libtest": {"elf": {}}}}}, {}))),
                        (S, "android_stage_local_inputs", stage),
                        (S, "installed_shell_candidate", Mock(return_value=({}, compiler, {}, "f" * 64, "1", None))),
                        (S, "elf_dependencies", Mock(return_value={})), (S.C, "clean_environment", Mock(return_value={})),
                        (S.C, "conventional_host", Mock()), (S, "shell_tools_inputs_for_observation", Mock(return_value={"raw": "private-tools-marker"})),
                        (S, "installed_shell_os_inputs", Mock(return_value={})), (lifecycle, "compact_shell_loader_policy", Mock(return_value={})),
                        (lifecycle, "service_argv", Mock(return_value=["/inert/root-driver", "private-argument-marker"])),
                        (lifecycle, "verify_service_result", collect), (S, "shell_project_draft_observation", Mock(return_value={})),
                        (S.time, "monotonic", Mock(return_value=1.0))):
                    stack.enter_context(patch.object(obj, name, replacement))
                stack.enter_context(patch.object(S.sys, "path", list(S.sys.path)))
                stack.enter_context(patch.dict(S.sys.modules, {"mobile_release.owned_process": SimpleNamespace(run_owned=owner)}))
                stack.enter_context(patch.dict(S.os.environ, {"MRK_INSTALLED_SHELL_CASE": "observe",
                    "GITHUB_REF": S.SHELL_REF,
                    "MRK_INSTALLED_SHELL_TRANSPORT": "android-same-job-local-v1", "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1",
                    "ImageOS": "ubuntu24", "ImageVersion": "inert", "MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256": hashlib.sha256(entry.read_bytes()).hexdigest()}, clear=True))
                stdout = stack.enter_context(patch("sys.stdout", new=io.StringIO()))
                stderr = stack.enter_context(patch("sys.stderr", new=io.StringIO()))
                if fault:
                    with self.assertRaises((S.D.Refused, RuntimeError)): S.verify_installed_shell()
                    self.assertEqual({p.name for p in (root / "public").iterdir()}, {"failure.json"})
                    failure = S.D.decode((root / "public/failure.json").read_bytes())
                    self.assertFalse(failure["qualified"]); self.assertFalse(failure["cleanupEstablished"])
                    self.assertIn(b"private-", (root / "private-failure.json").read_bytes())
                    self.assertEqual(len(seen), 0 if fault == "input" else 3)
                else:
                    S.verify_installed_shell()
                    self.assertEqual({p.name for p in (root / "public").iterdir()}, {"android-native-summary.json"})
                    summary = S.D.decode((root / "public/android-native-summary.json").read_bytes())
                    self.assertTrue(summary["originalFinalityVerified"])
                    self.assertFalse(summary["qualified"]); self.assertFalse(summary["signingExercised"])
                    self.assertEqual(len(summary["cases"]), len(lifecycle.SHELL_CASES))
                    self.assertEqual(len(seen), 5)
                    private = (root / "private-compiler/result.json").read_bytes()
                    self.assertIn(b"private-tools-marker", private)
                    self.assertIn(b"private-native-marker", private)
                    self.assertIn(b"private-lifecycle-marker", private)
                uploaded = b"".join(p.read_bytes() for p in (root / "public").iterdir())
                displayed = (stdout.getvalue() + stderr.getvalue()).encode()
                for marker in ("argument", "compiler", "transport", "preparation", "os", "host", "native", "tools", "input",
                               "owner", "finality", "root", "path", "driver", "original", "lifecycle"):
                    self.assertNotIn(("private-" + marker + "-marker").encode(), uploaded + displayed)


@patch.object(S, "local", android_data_local)
class InstalledShellCompilerContracts(unittest.TestCase):
    def test_same_job_shell_routes_have_distinct_original_roots_and_preparations(self):
        # Inert private directory/clock fixtures only. The actual hosted-platform
        # admission is mocked; no compiler, native service or process is launched.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source, temp, output = directory / "source", directory / "tmp", directory / "output"
            source.mkdir(); temp.mkdir(); output.write_bytes(b"")
            env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                   "RUNNER_ARCH": "X64", "GITHUB_EVENT_NAME": "push", "GITHUB_REF": S.SHELL_REF,
                   "GITHUB_JOB": "compile", "MRK_UBUNTU_PUBLICATION_VERIFY": "1", "GITHUB_SHA": "a" * 40,
                   "MRK_PUSH_EVENT_AFTER": "a" * 40, "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1",
                   "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit", "GITHUB_WORKSPACE": str(source),
                   "RUNNER_TEMP": str(temp), "GITHUB_OUTPUT": str(output)}
            roots, endpoints = [], []
            previous_umask = S.os.umask(0o077)
            try:
                for index, case in enumerate(("compile", "observe")):
                    environment = {**env, "MRK_INSTALLED_SHELL_CASE": case}
                    with patch.dict(S.os.environ, environment, clear=True), patch.object(S, "SOURCE", source), \
                         patch.object(S.C, "conventional_host"), patch.object(S.os, "getresuid", return_value=(1001,) * 3), \
                         patch.object(S.os, "getresgid", return_value=(1001,) * 3), \
                         patch.object(S.time, "monotonic", return_value=100.0 + index * 25):
                        self.assertEqual(S.route(S.os.environ), "a" * 40)
                        S.prepare()
                        _, _, _, root = S.hosted_paths()
                        raw = (root / "preparation.json").read_bytes()
                        record = S.D.decode(raw)
                        self.assertEqual(root.name, "mrk-desktop-ubuntu-publisher-10-1-" + case)
                        self.assertEqual((record["shellCase"], record["job"]), (case, "compile"))
                        self.assertEqual(float(record["deadline"]), 1300.0 + index * 25)
                        pins = {"MRK_UBUNTU_PUBLICATION_ROOT": str(root),
                                "MRK_UBUNTU_PUBLICATION_PREPARATION_SHA256": hashlib.sha256(raw).hexdigest(),
                                "MRK_UBUNTU_PUBLICATION_DEADLINE": record["deadline"]}
                        with patch.dict(S.os.environ, pins):
                            self.assertEqual(S.resumed_preparation()[-2:], (root, float(record["deadline"])))
                            with patch.object(S.time, "monotonic", return_value=float(record["deadline"])), \
                                 self.assertRaisesRegex(S.D.Refused, "endpoint expired"):
                                S.resumed_preparation()
                            with patch.dict(S.os.environ, {"MRK_INSTALLED_SHELL_CASE": "observe" if case == "compile" else "compile"}), \
                                 self.assertRaisesRegex(S.D.Refused, "Original private root differs"):
                                S.resumed_preparation()
                            changed = {**record, "shellCase": "observe" if case == "compile" else "compile"}
                            changed_raw = S.D.canonical(changed)
                            (root / "preparation.json").write_bytes(changed_raw)
                            with patch.dict(S.os.environ, {"MRK_UBUNTU_PUBLICATION_PREPARATION_SHA256": hashlib.sha256(changed_raw).hexdigest()}), \
                                 self.assertRaisesRegex(S.D.Refused, "binding changed"):
                                S.resumed_preparation()
                            (root / "preparation.json").write_bytes(raw)
                        with self.assertRaises(FileExistsError):
                            S.prepare()
                        self.assertEqual((root / "preparation.json").read_bytes(), raw)
                        roots.append(root); endpoints.append(record["deadline"])
                self.assertNotEqual(roots[0], roots[1])
                self.assertNotEqual(endpoints[0], endpoints[1])
                for change in ({"GITHUB_JOB": "native"}, {"GITHUB_JOB": ""},
                               {"MRK_INSTALLED_CASE": "positive"}, {"MRK_INSTALLED_SHELL_CASE": "host-metadata-only"}):
                    with self.subTest(change=change), self.assertRaises(S.D.Refused):
                        S.route({**env, "MRK_INSTALLED_SHELL_CASE": "compile", **change})
            finally:
                S.os.umask(previous_umask)

    def test_cleanup_removes_only_owned_roots_and_never_follows_link_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "owned"
            (root / "nested").mkdir(parents=True, mode=0o700)
            sentinel = parent / "retained"
            sentinel.write_bytes(b"unrelated retained DATA")
            (root / "nested/readonly").write_bytes(b"disposable DATA")
            (root / "nested/readonly").chmod(0o400)
            (root / "alias").symlink_to(sentinel)
            expected = S.shell_directory_identity(root)
            parents = {parent: S.shell_directory_identity(parent)}
            original_close = S.os.close
            with patch.object(S.time, "monotonic", return_value=1.0), \
                 patch.object(S.os, "close", wraps=original_close) as close:
                S.shell_remove_owned_directory(root, expected, parents, 2.0)
            self.assertEqual(close.call_count, 3)  # Original pair plus rmtree's nested directory.
            self.assertFalse(root.exists())
            self.assertEqual(sentinel.read_bytes(), b"unrelated retained DATA")

    def test_cleanup_refuses_replacements_or_expired_endpoint_before_removing_data(self):
        for refusal in ("target", "parent", "expired", "unavailable"):
            with self.subTest(refusal=refusal), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary) / "parent"
                root = parent / "owned"
                root.mkdir(parents=True, mode=0o700)
                member = root / "data"
                member.write_bytes(b"original DATA")
                expected = S.shell_directory_identity(root)
                parents = {parent: S.shell_directory_identity(parent)}
                if refusal == "target":
                    root.rename(parent / "original")
                    root.mkdir(mode=0o700); member.write_bytes(b"replacement DATA")
                elif refusal == "parent":
                    parent.rename(parent.with_name("original-parent"))
                    root.mkdir(parents=True, mode=0o700); member.write_bytes(b"replacement DATA")
                with patch.object(S.time, "monotonic", return_value=2.0 if refusal == "expired" else 1.0), \
                     patch.object(S.shutil.rmtree, "avoids_symlink_attacks", refusal != "unavailable"), \
                     self.assertRaises(S.D.Refused):
                    S.shell_remove_owned_directory(root, expected, parents, 2.0)
                self.assertEqual(member.read_bytes(), b"replacement DATA" if refusal in {"target", "parent"} else b"original DATA")

    def test_cleanup_preserves_first_failure_and_closes_each_original_once(self):
        for removal_failure in (False, True):
            with self.subTest(removal_failure=removal_failure), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                root = parent / "owned"
                root.mkdir(mode=0o700)
                if removal_failure:
                    (root / "nested").mkdir(mode=0o700)
                    (root / "nested/data").write_bytes(b"disposable DATA")
                else:
                    (root / "data").write_bytes(b"disposable DATA")
                expected = S.shell_directory_identity(root)
                parents = {parent: S.shell_directory_identity(parent)}
                closed, original_close, original_rmtree = [], S.os.close, S.shutil.rmtree
                def close(fd):
                    original_close(fd)
                    closed.append(fd)
                    if len(closed) == 1:
                        raise OSError("injected original close failure")
                def remove(name, *, dir_fd):
                    if removal_failure:
                        raise OSError("injected original removal failure")
                    original_rmtree(name, dir_fd=dir_fd)
                remove.avoids_symlink_attacks = True
                with patch.object(S.time, "monotonic", return_value=1.0), \
                     patch.object(S.shutil, "rmtree", remove), patch.object(S.os, "close", side_effect=close), \
                     self.assertRaisesRegex(OSError, "original removal failure" if removal_failure else "original close failure"):
                    S.shell_remove_owned_directory(root, expected, parents, 2.0)
                # Both original cleanup descriptors are consumed once, even
                # when the first consuming close fails after a prior refusal.
                self.assertEqual(len(closed), len(set(closed)))
                self.assertEqual(len(closed), 2)
                if removal_failure:
                    self.assertEqual((root / "nested/data").read_bytes(), b"disposable DATA")
                else:
                    self.assertFalse(root.exists())


    def test_workflow_transport_route_requires_same_attempt_without_artifact_mixing(self):
        workflow = (SOURCE / S.WORKFLOW).read_text()
        native = workflow.split("      - name: Require the fixed disposable native route", 1)[1].split("      - name:", 1)[0]
        source = native.split("<<'PY'\n", 1)[1].rsplit("          PY", 1)[0]
        source = "\n".join(line.removeprefix("          ") for line in source.splitlines())
        tree = ast.parse(source)
        # This specific embedded policy reads only an inert environment mapping;
        # reject any new tool/filesystem call before executing it in this test.
        self.assertEqual({alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}, {"os", "re"})
        self.assertFalse(any(isinstance(node, ast.ImportFrom) for node in ast.walk(tree)))
        self.assertEqual({ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)},
                         {"os.environ.get", "re.fullmatch", "all", "int", "SystemExit"})
        code = compile(tree, "<inert workflow transport DATA policy>", "exec")
        base = {"MRK_INSTALLED_SHELL_ARTIFACT_ID": "", "MRK_INSTALLED_SHELL_PRODUCER_ATTEMPT": "1", "GITHUB_RUN_ATTEMPT": "1",
                "MRK_INSTALLED_SHELL_TRANSPORT": "android-same-job-local-v1", "MRK_INSTALLED_SHELL_LOCAL_TRANSPORT_SHA256": "a" * 64,
                "MRK_INSTALLED_SHELL_ROSTER_SHA256": "b" * 64}
        for change, admitted in (({}, True), ({"GITHUB_RUN_ATTEMPT": "2"}, False),
                ({"MRK_INSTALLED_SHELL_ARTIFACT_ID": "17"}, False), ({"MRK_INSTALLED_SHELL_LOCAL_TRANSPORT_SHA256": ""}, False),
                ({"MRK_INSTALLED_SHELL_TRANSPORT": "other"}, False), ({"MRK_INSTALLED_SHELL_ROSTER_SHA256": "bad"}, False),
                ({"MRK_INSTALLED_SHELL_PRODUCER_ATTEMPT": "01"}, False),
                ({"MRK_INSTALLED_SHELL_TRANSPORT": "actions-artifact-v1", "MRK_INSTALLED_SHELL_LOCAL_TRANSPORT_SHA256": "",
                  "MRK_INSTALLED_SHELL_ARTIFACT_ID": "17", "GITHUB_RUN_ATTEMPT": "2"}, True)):
            with self.subTest(change=change), patch.dict(S.os.environ, {**base, **change}, clear=True):
                if admitted: exec(code, {})
                else:
                    with self.assertRaises(SystemExit): exec(code, {})



    def test_shell_source_manifest_accepts_actual_version_qualified_hashing_profile(self):
        # Exercise the real admission against the checked-in inputs, not a
        # second synthetic manifest or a mocked shell_source_manifest result.
        rows = S.shell_source_manifest(SOURCE)
        self.assertIn("desktop/src-tauri/Cargo.toml", {row["path"] for row in rows})

    def test_shell_source_manifest_refuses_missing_wrong_or_extra_hashing_overrides(self):
        original = S.tomllib.loads((SOURCE / "desktop/src-tauri/Cargo.toml").read_text(encoding="utf-8"))
        settings = {"opt-level": 3, "debug-assertions": True, "overflow-checks": True}
        overrides = [
            ("missing", {}),
            ("unqualified", {"sha2": settings}),
            ("wrong-version", {"sha2:0.11.0": settings}),
            ("extra-unqualified", {"sha2:0.10.9": settings, "sha2": settings}),
            ("extra-version", {"sha2:0.10.9": settings, "sha2:0.11.0": settings}),
        ]
        for key, value in (("opt-level", 0), ("opt-level", "3"), ("opt-level", 3.0),
                           ("debug-assertions", False), ("debug-assertions", 1),
                           ("overflow-checks", False), ("overflow-checks", 1)):
            overrides.append((f"{key}={value!r}", {"sha2:0.10.9": {**settings, key: value}}))
        for label, package in overrides:
            changed = deepcopy(original)
            changed["profile"]["dev"]["package"] = package
            with self.subTest(case=label), patch.object(S.tomllib, "loads", return_value=changed):
                with self.assertRaisesRegex(S.D.Refused, "complete bounded runtime hashing"):
                    S.shell_source_manifest(SOURCE)

    def test_one_build_exact_production_features_and_two_selected_targets(self):
        argv = S.shell_compile_argv("/tools/cargo", Path("/source"), Path("/target"))
        self.assertEqual(argv[:2], ["/tools/cargo", "build"])
        self.assertEqual(argv[argv.index("--features") + 1], "desktop-shell,custom-protocol")
        self.assertEqual(argv[argv.index("--profile") + 1], "dev")
        self.assertEqual(argv[argv.index("--bin") + 1], "mobile-release-kit-desktop")
        self.assertEqual(argv[argv.index("--test") + 1], "installed-shell-observation")
        self.assertIn("--locked", argv)
        self.assertIn("--offline", argv)
        self.assertIn("--no-default-features", argv)
        self.assertNotIn("test", argv)
        self.assertNotIn("--release", argv)
        self.assertNotIn("development-runtime", " ".join(argv))
        self.assertNotIn("ubuntu-runtime-publisher", " ".join(argv))

    def test_harness_false_observer_does_not_guess_cargo_profile_test_boolean(self):
        for value in (False, True):
            with self.subTest(value=value):
                artifacts, units = S.shell_compiled_artifacts(messages(compiler_rows(observer_test=value)), Path("/source"), Path("/target"))
                self.assertEqual(set(artifacts), {"normal", "observer"})
                self.assertIs(artifacts["normal"]["profile"]["test"], False)
                self.assertIs(artifacts["observer"]["profile"]["test"], value)
                self.assertEqual(len(units), 3)

    def test_stale_wrong_source_feature_profile_or_target_refuses(self):
        changes = (
            lambda rows: rows[1].update(fresh=True),
            lambda rows: rows[2].update(fresh=True),
            lambda rows: rows[1].update(features=["desktop-shell"]),
            lambda rows: rows[2].update(features=[*S.SHELL_FEATURES, "development-runtime"]),
            lambda rows: rows[1]["profile"].update(test=True),
            lambda rows: rows[2]["profile"].update(opt_level="3"),
            lambda rows: rows[2]["profile"].update(debug_assertions=False),
            lambda rows: rows[2]["profile"].update(test=0),
            lambda rows: rows[2]["target"].update(kind=["lib"]),
            lambda rows: rows[2]["target"].update(name="session-gtk-qualification"),
            lambda rows: rows[1]["target"].update(src_path="/other/main.rs"),
            lambda rows: rows[1].update(manifest_path="/other/Cargo.toml"),
            lambda rows: rows[2].update(executable="/target/outside-observer"),
            lambda rows: rows[1].update(filenames=[]),
            lambda rows: rows[-1].update(success=False),
        )
        for change in changes:
            rows = deepcopy(compiler_rows())
            change(rows)
            with self.subTest(change=change), self.assertRaises((S.D.Refused, S.C.CheckFailure)):
                S.shell_compiled_artifacts(messages(rows), Path("/source"), Path("/target"))

    def test_missing_duplicate_extra_and_post_final_artifacts_refuse(self):
        original = compiler_rows()
        for rows in (original[:-1], original[:2] + original[3:], original[:2] + [deepcopy(original[1])] + original[2:],
                     original + [deepcopy(original[1])], original + [{"reason": "new-unselected-kind"}]):
            with self.subTest(rows=rows), self.assertRaises((S.D.Refused, S.C.CheckFailure)):
                S.shell_compiled_artifacts(messages(rows), Path("/source"), Path("/target"))

    def test_full_metadata_rejects_incomplete_or_development_graph(self):
        value = metadata()
        parsed, packages, nodes = S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))
        self.assertEqual(len(packages), 38)
        self.assertEqual(nodes["root"]["features"], S.SHELL_FEATURES)
        # Other-platform declarations must match current SOURCE exactly even
        # though no Mac package becomes active in this Linux-filtered graph.
        for target in ('cfg(all(target_os = "macos", target_arch = "aarch64"))',
                       'cfg(target_os = "macos")'):
            changed = deepcopy(value)
            declaration = next(row for row in changed["packages"][0]["dependencies"]
                               if row["name"] == "mrk-macos-installed-native")
            declaration["target"] = target
            with self.subTest(mac_declaration=target), self.assertRaisesRegex(
                    S.D.Refused, "^Linux Cargo local dependency declarations differ$"):
                S.shell_cargo_metadata(S.D.canonical(changed), Path("/source"), Path("/target"))
        changes = (
            lambda row: row["packages"][0].update(version="0.1.1"),
            lambda row: row["resolve"]["nodes"][0].update(features=[*S.SHELL_FEATURES, "development-runtime"]),
            lambda row: next(item for item in row["resolve"]["nodes"] if item["id"] == "tauri").update(features=["wry"]),
            lambda row: row["packages"].append(deepcopy(next(item for item in row["packages"] if item["id"] == "tauri"))),
            lambda row: next(item for item in row["packages"] if item["id"] == "tauri").update(source="git+https://unreviewed.invalid/repo"),
            lambda row: row.update(target_directory="/source/desktop/src-tauri/target"),
            lambda row: row["resolve"]["nodes"][0].update(deps=[{"pkg": "missing"}]),
        )
        for change in changes:
            value = deepcopy(metadata())
            change(value)
            with self.subTest(change=change), self.assertRaises((S.D.Refused, S.C.CheckFailure)):
                S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))

    def test_declared_platforms_cannot_enter_linux_graph_or_compiler(self):
        _, packages, nodes = S.shell_cargo_metadata(S.D.canonical(metadata()), Path("/source"), Path("/target"))
        local_ids = {"root", "mount", "secret-service", "zbus"}
        self.assertEqual({row["id"] for row in packages.values() if row["source"] is None}, local_ids)
        self.assertEqual(set(nodes) & (local_ids | {"macos", "windows"}), local_ids)
        declared = packages["root"]["dependencies"]
        self.assertEqual(len(declared), 8)
        self.assertEqual({row["name"] for row in declared},
                         {"mrk-linux-mount-observation", "mrk-macos-installed-native", "mrk-windows-installed-native",
                          "secret-service", "zbus"})
        windows = [row for row in declared if row["name"] == "mrk-windows-installed-native"]
        self.assertEqual([(row["kind"], row["features"]) for row in windows],
                         [(None, []), ("dev", ["qualification-result"])])
        # Declaration order and unrelated registry declarations do not change
        # the exact local contract.
        value = metadata()
        value["packages"][0]["dependencies"].append(
            {"name": "sha2", "source": "registry+https://github.com/rust-lang/crates.io-index"})
        value["packages"][0]["dependencies"].reverse()
        S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))
        for index in range(4):
            for field, replacement in (("name", "unreviewed-local"), ("version", "0.2.0"),
                                       ("manifest_path", "/elsewhere/Cargo.toml"),
                                       ("source", "registry+https://github.com/rust-lang/crates.io-index")):
                value = metadata()
                value["packages"][index][field] = replacement
                with self.subTest(package=index, field=field), self.assertRaises(S.D.Refused):
                    S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))
            value = metadata()
            value["packages"].pop(index)
            with self.subTest(missing_package=index), self.assertRaises(S.D.Refused):
                S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))
            value = metadata()
            value["resolve"]["nodes"].pop(index)
            with self.subTest(missing_local_node=index), self.assertRaises(S.D.Refused):
                S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))
        for name in ("secret-service", "zbus"):
            value = metadata()
            duplicate = deepcopy(packages[name])
            duplicate.update(id=name + "-registry", source="registry+https://github.com/rust-lang/crates.io-index",
                             manifest_path="/private/cargo/registry/src/" + name + "/Cargo.toml")
            value["packages"].append(duplicate)
            value["resolve"]["nodes"].append({"id": duplicate["id"], "features": [], "deps": []})
            with self.subTest(duplicate_sdk=name), self.assertRaises(S.D.Refused):
                S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))
        changes = (
            lambda row: row["packages"][0].pop("dependencies"),
            lambda row: row["packages"][0].update(dependencies=None),
            lambda row: row["packages"][0].update(dependencies={}),
            lambda row: row["packages"][0].update(dependencies="not-a-list"),
            lambda row: row["packages"][0]["dependencies"].append(None),
        )
        for change in changes:
            value = metadata()
            change(value)
            with self.subTest(change=change), self.assertRaises(S.D.Refused):
                S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))
        for extra in (
            {"name": "foreign-local", "source": None},
            {"name": "foreign-local"},
            {"name": "foreign-path", "source": "registry+https://github.com/rust-lang/crates.io-index", "path": None},
            {"name": "foreign-path", "source": "git+https://unreviewed.invalid/repo", "path": "/elsewhere"},
            {"name": "mrk-macos-installed-native", "source": "registry+https://github.com/rust-lang/crates.io-index"},
            {"name": "mrk-windows-installed-native", "source": "git+https://unreviewed.invalid/repo"},
        ):
            value = metadata()
            value["packages"][0]["dependencies"].append(extra)
            with self.subTest(extra_declaration=extra), self.assertRaises(S.D.Refused):
                S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))
        field_changes = (
            ("name", "unreviewed-local"), ("name", 0), ("name", []),
            ("path", "/elsewhere"), ("path", False),
            ("target", None), ("target", 'cfg(target_os = "linux")'), ("target", False),
            ("source", "registry+https://github.com/rust-lang/crates.io-index"),
            ("source", "git+https://unreviewed.invalid/repo"), ("source", False),
            ("kind", None), ("kind", "dev"), ("kind", "build"), ("kind", 0),
            ("req", "^0.1.0"), ("req", True),
            ("rename", "unreviewed_alias"), ("rename", 0),
            ("registry", "https://unreviewed.invalid/index"), ("registry", False),
            ("features", []), ("features", ["qualification-result"]),
            ("features", ["qualification-result", "installed-observation"]),
            ("features", ["installed-observation"]), ("features", {}), ("features", False),
            ("optional", True), ("optional", 0), ("optional", None),
            ("uses_default_features", False), ("uses_default_features", 1), ("uses_default_features", None),
            ("unreviewed-field", None),
        )
        for index, declaration in enumerate(declared):
            for mutation in ("missing", "duplicate", "duplicate-replacement"):
                value = metadata()
                dependencies = value["packages"][0]["dependencies"]
                if mutation == "missing":
                    dependencies.pop(index)
                elif mutation == "duplicate":
                    dependencies.append(deepcopy(dependencies[index]))
                else:
                    dependencies[(index + 1) % len(declared)] = deepcopy(dependencies[index])
                with self.subTest(declaration=index, mutation=mutation), self.assertRaises(S.D.Refused):
                    S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))
            for field in declared[index]:
                value = metadata()
                del value["packages"][0]["dependencies"][index][field]
                with self.subTest(declaration=index, missing_field=field), self.assertRaises(S.D.Refused):
                    S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))
            successor = declared[(index + 1) % len(declared)]
            swaps = tuple((field, successor[field]) for field in ("name", "path", "target", "kind") if field in successor)
            bad_path = declaration.get("path", "/source/desktop/vendor/zbus-5.19.0") + "/Cargo.toml"
            for field, replacement in (*field_changes, *swaps, ("path", bad_path)):
                if field in declaration and S.D.canonical(declaration[field]) == S.D.canonical(replacement):
                    continue  # Only identical typed DATA is a no-op, not an accepted mutation.
                value = metadata()
                value["packages"][0]["dependencies"][index][field] = replacement
                with self.subTest(declaration=index, field=field, value=replacement), self.assertRaises(S.D.Refused):
                    S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))
        _, units = S.shell_compiled_artifacts(messages(compiler_rows()), Path("/source"), Path("/target"))
        for platform in ("macos", "windows", "unreviewed"):
            for extra_package, extra_node, extra_edge in (
                (True, False, False), (False, True, False), (False, False, True),
                (True, True, False), (True, False, True), (False, True, True), (True, True, True),
            ):
                value = metadata()
                if extra_package:
                    value["packages"].append(
                        {"id": platform, "name": "mrk-" + platform + "-installed-native", "version": "0.1.0",
                         "source": None,
                         "manifest_path": "/source/desktop/native/" + platform + "-installed-native/Cargo.toml"})
                if extra_node:
                    value["resolve"]["nodes"].append({"id": platform, "features": [], "deps": []})
                if extra_edge:
                    value["resolve"]["nodes"][0]["deps"].append({"pkg": platform})
                with self.subTest(platform=platform, package=extra_package, node=extra_node, edge=extra_edge):
                    with self.assertRaises(S.D.Refused):
                        S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))
            extra = deepcopy(units[0]); extra.update(package_id=platform, features=[])
            with self.subTest(compiler=platform), self.assertRaises(S.D.Refused):
                S.shell_compiler_units([*units, extra], packages, nodes)
        # A registry package may remain accounted without a selected node, but
        # a compiler unit must still belong to BOTH original metadata sets.
        value = metadata()
        inactive_id = value["resolve"]["nodes"].pop()["id"]
        _, inactive_packages, inactive_nodes = S.shell_cargo_metadata(
            S.D.canonical(value), Path("/source"), Path("/target"))
        self.assertIn(inactive_id, inactive_packages)
        self.assertNotIn(inactive_id, inactive_nodes)
        extra = deepcopy(units[0]); extra.update(package_id=inactive_id, features=[])
        with self.assertRaises(S.D.Refused):
            S.shell_compiler_units([*units, extra], inactive_packages, inactive_nodes)

    def test_fixed_local_graph_matches_actual_manifest_data(self):
        # Prevent an internally consistent synthetic graph/validator from
        # silently retaining an obsolete local-source roster. Read only these
        # four fixed manifests; do not run Cargo or follow their declared paths.
        value = metadata()
        root = S.tomllib.loads((SOURCE / "desktop/src-tauri/Cargo.toml").read_text(encoding="utf-8"))
        for package in value["packages"]:
            if package["source"] is None:
                relative = Path(package["manifest_path"]).relative_to("/source")
                manifest = root if package["id"] == "root" else S.tomllib.loads((SOURCE / relative).read_text(encoding="utf-8"))
                self.assertEqual((manifest["package"]["name"], manifest["package"]["version"]),
                                 (package["name"], package["version"]))
        self.assertEqual(S.D.canonical(root.get("patch")), S.D.canonical({
            "crates-io": {"zbus": {"path": "../vendor/zbus-5.19.0"}}}))
        declarations = value["packages"][0]["dependencies"]
        names = {row["name"] for row in declarations}
        expected = []
        for row in declarations:
            fields = {}
            if "path" in row:
                fields["path"] = "../" + Path(row["path"]).relative_to("/source/desktop").as_posix()
            if row["req"] != "*":
                fields["version"] = row["req"]
            if not row["uses_default_features"]:
                fields["default-features"] = False
            if row["features"]:
                fields["features"] = row["features"]
            expected.append({"name": row["name"], "target": row["target"], "kind": row["kind"], "fields": fields})
        actual = []
        for target, table in [(None, root), *root.get("target", {}).items()]:
            for kind, key in ((None, "dependencies"), ("dev", "dev-dependencies"), ("build", "build-dependencies")):
                for name, fields in table.get(key, {}).items():
                    if name in names or isinstance(fields, dict) and "path" in fields:
                        actual.append({"name": name, "target": target, "kind": kind, "fields": fields})
        self.assertEqual(sorted(S.D.canonical(row) for row in actual), sorted(S.D.canonical(row) for row in expected))

    def test_actual_sha2_optimized_profile_is_required_not_inferred(self):
        value = metadata()
        value["packages"].append({"id": "sha2-sdk", "name": "sha2", "version": "0.11.0",
                                  "source": "registry+https://github.com/rust-lang/crates.io-index",
                                  "manifest_path": "/private/cargo/registry/src/sha2-0.11.0/Cargo.toml"})
        value["resolve"]["nodes"].append({"id": "sha2-sdk", "features": ["std"], "deps": []})
        _, packages, nodes = S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))
        rows = compiler_rows()
        newer = deepcopy(rows[0])
        newer["package_id"] = "sha2-sdk"
        rows.insert(-1, newer)
        _, units = S.shell_compiled_artifacts(messages(rows), Path("/source"), Path("/target"))
        S.shell_compiler_units(units, packages, nodes)
        # An optimized SDK SHA-2 unit cannot substitute for the application's
        # missing or unoptimized 0.10.9 unit, even with both versions resolved.
        for key, value in (("opt_level", "0"), ("debug_assertions", False), ("overflow_checks", False)):
            changed = deepcopy(units)
            changed[0]["profile"][key] = value
            with self.subTest(key=key), self.assertRaises(S.D.Refused):
                S.shell_compiler_units(changed, packages, nodes)
        with self.assertRaises(S.D.Refused):
            S.shell_compiler_units(units[1:], packages, nodes)
        changed = deepcopy(units)
        changed[0]["features"] = ["unreviewed-feature"]
        with self.assertRaises(S.D.Refused):
            S.shell_compiler_units(changed, packages, nodes)

    def test_full_metadata_budget_does_not_widen_other_json_profiles(self):
        value = metadata()
        value["metadata"] = [None] * 50000
        raw = S.D.canonical(value)
        with self.assertRaises(S.C.CheckFailure):
            S.C.bounded_json(raw, S.SHELL_METADATA_LIMIT)
        _, packages, _ = S.shell_cargo_metadata(raw, Path("/source"), Path("/target"))
        self.assertEqual(len(packages), 38)
        value["metadata"] = [None] * 200000
        with self.assertRaises(S.C.CheckFailure):
            S.shell_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/target"))
        for budget in (True, 0, 200001):
            with self.subTest(budget=budget), self.assertRaises(S.C.CheckFailure):
                S.C.bounded_json(b"{}", 2, max_nodes=budget)
        for malformed in (b'{"a":1,"a":2}', b'{"a":1.5}', b'{"a":NaN}', b'\xff', b'[' * 17 + b'0' + b']' * 17):
            with self.subTest(malformed=malformed), self.assertRaises(S.C.CheckFailure):
                S.C.bounded_json(malformed, S.SHELL_METADATA_LIMIT, max_nodes=200000)
        with self.assertRaises(S.C.CheckFailure):
            S.C.bounded_json(b"{}", 1, max_nodes=200000)

    def test_only_owned_ignored_generated_source_roots_are_allowed(self):
        S.shell_source_status(b"", ())
        S.shell_source_status(b"!! desktop/node_modules/react/index.js\0!! desktop/dist/index.html\0", S.SHELL_GENERATED)
        generated = b"desktop/src-tauri/permissions/autogenerated/app_info.toml\0"
        S.shell_source_status(b"!! " + generated, (S.SHELL_PERMISSIONS,))
        for raw, roots in ((b" M desktop/src/App.tsx\0", S.SHELL_GENERATED),
                           (b"?? desktop/dist/extra.js\0", S.SHELL_GENERATED),
                           (b"!! desktop/node_modules/react/index.js\0", ()),
                           (b"!! desktop/.cache/extra\0", S.SHELL_GENERATED),
                           (b"!! desktop/dist/../outside\0", S.SHELL_GENERATED),
                           (b"!! desktop/dist/index.html", S.SHELL_GENERATED),
                           (b"!! " + generated, ()),
                           (b"?? " + generated, S.SHELL_GENERATED),
                           (b" M " + generated, S.SHELL_GENERATED),
                           (b"!! desktop/src-tauri/permissions/\0", S.SHELL_GENERATED),
                           (b"!! desktop/src-tauri/permissions/manual.toml\0", S.SHELL_GENERATED),
                           (b"!! desktop/src-tauri/permissions/autogenerated2/app_info.toml\0", S.SHELL_GENERATED)):
            with self.subTest(raw=raw), self.assertRaises(S.D.Refused):
                S.shell_source_status(raw, roots)

    def test_generated_command_permissions_keep_the_whole_parent_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "permissions"
            (root / "autogenerated").mkdir(parents=True)
            member = root / "autogenerated/app_info.toml"
            member.write_bytes(b"inert generated permission DATA\n")
            before = S.shell_permissions_tree(root)
            self.assertEqual(before["directories"], ["autogenerated"])
            self.assertEqual([row["path"] for row in before["files"]], ["autogenerated/app_info.toml"])
            member.write_bytes(b"changed generated permission DATA\n")
            self.assertNotEqual(S.shell_permissions_tree(root), before)
            sibling = root / "manual.toml"
            sibling.write_bytes(b"unrelated source DATA\n")
            with self.assertRaises(S.D.Refused):
                S.shell_permissions_tree(root)
            sibling.unlink()
            (root / "autogenerated2").mkdir()
            with self.assertRaises(S.D.Refused):
                S.shell_permissions_tree(root)

    def test_generated_npm_links_must_stay_inside_the_original_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tree = root / "node_modules"
            (tree / ".bin").mkdir(parents=True)
            (tree / "tool.js").write_bytes(b"inert tool source DATA\n")
            alias = tree / ".bin/tool"
            alias.symlink_to("../tool.js")
            row = S.shell_generated_tree(tree, links=True)
            self.assertEqual(row["links"], [{"path": ".bin/tool", "target": "../tool.js"}])
            with self.assertRaises(S.D.Refused):
                S.shell_generated_tree(tree)
            alias.unlink()
            (root / "outside").write_bytes(b"not an admitted input")
            alias.symlink_to(root / "outside")
            with self.assertRaises(S.D.Refused):
                S.shell_generated_tree(tree, links=True)

    def test_shell_elf_profile_does_not_widen_headless_admission(self):
        self.assertEqual(S.elf_dependencies(elf_fixture(), shell=True)["needed"], ["libgtk-3.so.0"])
        with self.assertRaises(S.D.Refused):
            S.elf_dependencies(elf_fixture())
        with self.assertRaises(S.D.Refused):
            S.elf_dependencies(elf_fixture(runpath=True), shell=True)
        with self.assertRaises(S.D.Refused):
            S.elf_dependencies(elf_fixture(), shell=True, runtime_path="python/bin/python3")

    def test_private_runpath_requires_the_exact_requester_soname_and_path(self):
        for path, (soname, runpath) in S.SHELL_RUNPATHS.items():
            raw = elf_fixture(needed="libc.so.6", soname=soname, runpath=runpath, interpreter=False)
            with self.subTest(requester=path):
                self.assertEqual(S.elf_dependencies(raw, shell=True, shell_path=path)["runpath"], runpath)
                for other in (None, "/usr/lib/x86_64-linux-gnu/unselected.so"):
                    with self.assertRaises(S.D.Refused):
                        S.elf_dependencies(raw, shell=True, shell_path=other)
                with self.assertRaises(S.D.Refused):
                    S.elf_dependencies(raw)
                for changed in (elf_fixture(needed="libc.so.6", soname="wrong.so", runpath=runpath, interpreter=False),
                                elf_fixture(needed="libc.so.6", soname=soname, runpath=runpath + ":/tmp", interpreter=False),
                                elf_fixture(needed="libc.so.6", soname=soname, runpath=runpath, rpath=True, interpreter=False)):
                    with self.assertRaises(S.D.Refused):
                        S.elf_dependencies(changed, shell=True, shell_path=path)

    def test_provider_role_accepts_dual_use_shared_objects_without_changing_records(self):
        path = S.SHELL_LIBRARY_ROOT + "/libcap.so.2"
        for interpreter in (False, True):
            for flags in ((), (0,), (1,)):
                with self.subTest(interpreter=interpreter, flags=flags):
                    raw = elf_fixture(needed="libc.so.6", soname="libcap.so.2", interpreter=interpreter, flags_1=flags)
                    actual = S.shell_elf_record(raw, role="provider", selected=path)
                    self.assertEqual(actual, {"interpreter": "/lib64/ld-linux-x86-64.so.2" if interpreter else None,
                        "needed": ["libc.so.6"], "versionNeeds": {}, "versionDefinitions": [], "soname": "libcap.so.2"})
                    self.assertEqual(actual, S.elf_dependencies(raw, shell=True, shell_path=path))
        raw = elf_fixture()
        for options in ({"shell_provider": True}, {"runtime_path": "python/bin/python3", "shell_provider": True},
                        {"shell": True, "shell_provider": 1}):
            with self.subTest(options=options), self.assertRaises(S.D.Refused):
                S.elf_dependencies(raw, **options)

    def test_provider_role_refuses_executables_pie_duplicate_flags_and_other_loaders(self):
        path = S.SHELL_LIBRARY_ROOT + "/libcap.so.2"
        for options in ({"kind": 2}, {"kind": 2, "interpreter": False}, {"flags_1": (0x08000000,)},
                        {"flags_1": (0x08000001,)}, {"flags_1": (0, 0)},
                        {"interpreter": b"/unreviewed/loader\0"}):
            raw = elf_fixture(needed="libc.so.6", soname="libcap.so.2", **options)
            with self.subTest(options=options), self.assertRaises(S.D.Refused):
                S.shell_elf_record(raw, role="provider", selected=path)
        # The same legitimate program layouts keep their existing role; only
        # promoting them to shared-object providers is refused.
        for options in ({"kind": 2}, {"flags_1": (0x08000000,)}):
            raw = elf_fixture(**options)
            self.assertEqual(S.shell_elf_record(raw, role="program", selected="/usr/bin/inert")["needed"],
                             ["libgtk-3.so.0"])

    def test_private_provider_is_not_promoted_to_the_global_namespace(self):
        path = S.SHELL_LIBRARY_ROOT + "/libproxy.so.1"
        runpath = S.SHELL_RUNPATHS[path][1]
        provider = S.SHELL_LIBRARY_ROOT + "/libproxy/libpxbackend-1.0.so"
        self.assertEqual(S.shell_provider_path(path, runpath, "libpxbackend-1.0.so"), provider)
        for requester, search in ((None, None), (path, None), ("/arbitrary/provider", runpath)):
            with self.assertRaises(S.D.Refused):
                S.shell_provider_path(requester, search, "libpxbackend-1.0.so")
        record = {"file": {"selectedPath": path, "path": path},
                  "elf": {"soname": "libproxy.so.1", "runpath": runpath, "needed": ["libpxbackend-1.0.so"]}}
        candidates = S.shell_private_search([record], {"libpxbackend-1.0.so": {"file": {"selectedPath": provider}}})
        self.assertEqual(len(candidates), 4)
        self.assertEqual([row["path"] for row in candidates if row["selected"]], [provider])
        self.assertEqual(sum("glibc-hwcaps" in row["path"] for row in candidates), 3)

    def test_native_elf_refusal_names_only_the_fixed_public_role_or_path(self):
        selected = S.SHELL_LIBRARY_ROOT + "/gio/modules/inert.so"
        with self.assertRaisesRegex(S.D.Refused, "Shell ELF module " + selected):
            S.shell_elf_record(b"not ELF", role="module", selected=selected)
        with self.assertRaisesRegex(S.D.Refused, "Shell ELF observer:"):
            S.shell_elf_record(b"not ELF", role="observer")
        with self.assertRaises(S.D.Refused):
            S.shell_elf_record(b"not ELF", role="provider", selected="/private/task/input")

    def test_runpath_free_output_cannot_directly_name_a_private_provider(self):
        name = "libpxbackend-1.0.so"
        native = {"sharedObjects": {name: {"file": {"selectedPath": S.SHELL_PRIVATE_PROVIDERS[name] + "/" + name}}}}
        elf = {"interpreter": "/lib64/ld-linux-x86-64.so.2", "soname": None, "needed": [name], "versionNeeds": {}}
        with patch.object(S.D, "file_record", return_value={"size": 1, "sha256": "a" * 64}), \
             patch.object(S.D, "read", return_value=b"inert DATA"), patch.object(S, "shell_elf_record", return_value=elf), \
             self.assertRaisesRegex(S.D.Refused, "Private shell provider"):
            S.finish_shell_native_inputs(native, {role: Path("/inert") / role for role in S.SHELL_EXPORTS}, {})

    def test_transport_preserves_original_producer_and_the_complete_pair(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            environment, elf, inputs = transport_data(work)
            with patch.dict(S.os.environ, environment, clear=True), patch.object(S, "elf_dependencies", return_value=elf), \
                 patch.object(S, "shell_source_manifest", return_value=inputs):
                binaries, compiler, native, digest, producer, artifact = S.installed_shell_candidate(work, "a" * 40)
                self.assertEqual((producer, artifact, compiler["attempt"]), ("1", "17", "1"))
                self.assertEqual(set(binaries), {"normal", "observer"})
                self.assertEqual(digest, environment["MRK_INSTALLED_SHELL_ROSTER_SHA256"])
                self.assertNotEqual(binaries["normal"]["sha256"], binaries["observer"]["sha256"])
                for key, value in (("MRK_INSTALLED_SHELL_PRODUCER_ATTEMPT", "3"), ("MRK_INSTALLED_SHELL_PRODUCER_ATTEMPT", "0"),
                                   ("MRK_INSTALLED_SHELL_ARTIFACT_ID", ""), ("MRK_INSTALLED_SHELL_ARTIFACT_ID", "0"),
                                   ("GITHUB_RUN_ID", "11"), ("MRK_INSTALLED_SHELL_ROSTER_SHA256", "0" * 64)):
                    with self.subTest(field=key, value=value), patch.dict(S.os.environ, {key: value}), self.assertRaises(ValueError):
                        S.installed_shell_candidate(work, "a" * 40)
                (work / "admitted-shell/unlisted").write_bytes(b"extra inert DATA")
                with self.assertRaises(ValueError):
                    S.installed_shell_candidate(work, "a" * 40)

    def test_same_job_candidate_accepts_complete_original_tuple_and_refuses_artifact_or_profile_mixing(self):
        # Exercise the actual candidate path with the existing complete inert
        # compiler fixture, not only a directly called index/parser helper.
        for fault in (None, "artifact", "attempt", "material", "os-input", "index"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary, \
                 patch.object(S.time, "monotonic", return_value=1.0):
                parent = Path(temporary)
                native = parent / "mrk-desktop-ubuntu-publisher-10-1-observe"
                native.mkdir(mode=0o700); work = native / "work"; work.mkdir(mode=0o700)
                env, elf, inputs = transport_data(work)
                root, _, material, _ = AndroidLocalTransportContracts().context_fixture(parent)
                artifact = work / "admitted-shell"
                compiler = S.D.decode((artifact / "compiler.json").read_bytes())
                result = S.D.decode((artifact / "result.json").read_bytes())
                prepared = Path(material["materialRoot"]) / "private/prepared.json"
                for document in (compiler, result):
                    document["androidPreparation"] = {**S.D.file_record(prepared), "path": str(prepared)}
                    document["androidOsContractInput"] = {"path": str(prepared.parent.parent / "os-contract.json"),
                        **ANDROID_PUBLICATION_DATA["documents"]["osContract"]}
                command = result["commands"][0]; command["timeoutSeconds"] = 600
                captures = {suffix: S.android_private_pin(S.D.file_record(artifact / ("shell-compile." + suffix)))
                            for suffix in ("stdout", "stderr")}
                bodies = {"shell-compile.request.json": {key: command[key] for key in ("phase", "argv", "timeoutSeconds")},
                          "shell-compile.result.json": {**command, "captures": captures}}
                index = {"schemaVersion": 1, "scope": "original-private-compiler-command-metadata-v1", "files": [
                    {"path": name, "body": body, "size": len(S.D.canonical(body)), "sha256": hashlib.sha256(S.D.canonical(body)).hexdigest()}
                    for name, body in bodies.items()]}
                result["privateCommandMetadata"] = S.D.write(artifact / "private-command-metadata.json", S.D.canonical(index), 0o400)
                result["privateCommandRoles"] = {"compiler": ["shell-compile"], "material": []}
                result["privateCaptureRoots"] = {"compiler": list(S.directory_identity(root / "private-compiler"))}
                result["privateMaterialMetadata"] = []
                if fault == "material": result["androidPreparation"]["sha256"] = "0" * 64
                elif fault == "os-input": compiler["androidOsContractInput"]["path"] = "/unadmitted/os.json"
                elif fault == "index": result.pop("privateCommandMetadata")
                for name, document in (("compiler.json", compiler), ("result.json", result)):
                    (artifact / name).write_bytes(S.D.canonical(document))
                roster = {key: compiler[key] for key in ("sourceSha", "sourceTree", "runId", "attempt")}
                roster["files"] = [S.D.file_record(path) for path in sorted(artifact.iterdir()) if path.name != "shell-roster.json"]
                (artifact / "shell-roster.json").write_bytes(S.D.canonical(roster))
                for path in artifact.iterdir():
                    target = root / "private-compiler" / path.name
                    if target.exists(): target.write_bytes(path.read_bytes())
                    else: S.D.write(target, path.read_bytes())
                roster_pin = S.D.file_record(artifact / "shell-roster.json")
                env.update(GITHUB_RUN_ATTEMPT="1", GITHUB_JOB="compile", RUNNER_TEMP=str(parent),
                    MRK_INSTALLED_SHELL_ARTIFACT_ID="", MRK_INSTALLED_SHELL_ROSTER_SHA256=roster_pin["sha256"])
                with patch.dict(S.os.environ, env, clear=True), patch.object(S, "elf_dependencies", return_value=elf), \
                     patch.object(S, "shell_source_manifest", return_value=inputs):
                    transport = S.android_local_transport_record(root, compiler, material, roster_pin)
                    if fault == "artifact": S.os.environ["MRK_INSTALLED_SHELL_ARTIFACT_ID"] = "17"
                    elif fault == "attempt": S.os.environ["GITHUB_RUN_ATTEMPT"] = "2"
                    if fault:
                        with self.assertRaises(S.D.Refused): S.installed_shell_candidate(work, "a" * 40, local_transport=transport, deadline=10.0)
                    else:
                        binaries, original, _, _, producer, artifact_id = S.installed_shell_candidate(
                            work, "a" * 40, local_transport=transport, deadline=10.0)
                        self.assertEqual(set(binaries), {"normal", "observer"})
                        self.assertEqual(original, compiler)
                        self.assertEqual(producer, "1"); self.assertIsNone(artifact_id)

    def test_transport_refuses_relabelled_profiles_execution_or_copied_identity(self):
        changes = (
            lambda compiler, result, native, rows: compiler.update(features=["desktop-shell"]),
            lambda compiler, result, native, rows: compiler.update(attempt="2"),
            lambda compiler, result, native, rows: compiler.update(sourceTree="d" * 40),
            lambda compiler, result, native, rows: result.update(shellExecuted=True),
            lambda compiler, result, native, rows: result.update(observerExecuted=True),
            lambda compiler, result, native, rows: result.update(packageBuilt=True),
            lambda compiler, result, native, rows: result.update(cargoBuilds=True),
            lambda compiler, result, native, rows: compiler.pop("androidBuildMaterials"),
            lambda compiler, result, native, rows: result["androidBuildBindings"].update(MRK_ANDROID_TOOL_INSTANCE="different"),
            lambda compiler, result, native, rows: compiler.pop("androidBuildPublication"),
            lambda compiler, result, native, rows: result["androidBuildPublication"]["totals"].update(toolFiles=6),
            lambda compiler, result, native, rows: result.pop("compilerCleanup"),
            lambda compiler, result, native, rows: result["compilerCleanup"].update(workRemoved=False),
            lambda compiler, result, native, rows: result["compilerCleanup"].update(sourceClean=1),
            lambda compiler, result, native, rows: result["compilerCleanup"]["generatedRootsRemoved"].pop(),
            lambda compiler, result, native, rows: result["compilerCleanup"].update(exportsRetained=False),
            lambda compiler, result, native, rows: result["commands"][0].update(ordinaryOwnerReturned=False),
            lambda compiler, result, native, rows: compiler["exportedArtifacts"]["normal"].update(identity=compiler["originalArtifacts"]["normal"]["identity"]),
            lambda compiler, result, native, rows: compiler["originalArtifacts"]["observer"].update(path="/other/observer"),
            lambda compiler, result, native, rows: rows[2].update(fresh=True),
            lambda compiler, result, native, rows: native.update(manifestSha256="d" * 64),
            lambda compiler, result, native, rows: native["runtimeData"]["records"].pop(),
            lambda compiler, result, native, rows: native["runtimeData"]["suppliers"].update(sha256="d" * 64),
        )
        for index, change in enumerate(changes):
            with self.subTest(change=index), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                environment, elf, inputs = transport_data(work, change)
                with patch.dict(S.os.environ, environment, clear=True), patch.object(S, "elf_dependencies", return_value=elf), \
                     patch.object(S, "shell_source_manifest", return_value=inputs), self.assertRaises((S.D.Refused, S.C.CheckFailure)):
                    S.installed_shell_candidate(work, "a" * 40)

    def test_transported_data_and_each_executable_remain_whole_roster_members(self):
        for leaf in (*S.SHELL_EXPORTS.values(), "shell-data-0.json", "shell-host-bindings.json"):
            with self.subTest(member=leaf), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                environment, elf, inputs = transport_data(work)
                (work / "admitted-shell" / leaf).write_bytes(b"different inert DATA")
                with patch.dict(S.os.environ, environment, clear=True), patch.object(S, "elf_dependencies", return_value=elf) as parser, \
                     patch.object(S, "shell_source_manifest", return_value=inputs), self.assertRaises(ValueError):
                    S.installed_shell_candidate(work, "a" * 40)
                parser.assert_not_called()

    def test_generated_module_catalogues_only_select_fixed_bounded_paths(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        gio = next(path for path in lifecycle.SHELL_MODULE_CACHES if path.endswith("giomodule.cache"))
        self.assertEqual(lifecycle.shell_module_cache(gio, b"libinert.so: gsettings-backend\n"),
                         [lifecycle.SHELL_MODULE_CACHES[gio] + "/libinert.so"])
        for path, root in lifecycle.SHELL_MODULE_CACHES.items():
            if path == gio:
                malformed = (b"../escape.so: backend\n", b"libinert.so: backend\nlibinert.so: backend\n")
            else:
                raw = ('# inert catalogue DATA\n"' + root + '/inert.so"\n"inert" "inert"\n\n').encode()
                self.assertEqual(lifecycle.shell_module_cache(path, raw), [root + "/inert.so"])
                malformed = (raw.replace(root.encode(), b"/unselected"), raw + raw, b"invalid catalogue\n")
            for raw in malformed:
                with self.subTest(path=path, raw=raw), self.assertRaises(ValueError):
                    lifecycle.shell_module_cache(path, raw)

    def test_runtime_supplier_summary_is_distinct_from_current_generated_cache(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "font.ttf").write_bytes(b"inert font DATA")
            cache = root / "giomodule.cache"
            cache.write_bytes(b"libone.so: gsettings-backend\n")

            def binding(path, *, directory_only=False, absent=False, limit=0):
                path = Path(path)
                item = path.lstat()
                row = {"path": str(path), "selectedPath": str(path), "links": [], "ancestry": {}}
                if directory_only:
                    return row | {"directory": [item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid]}
                return row | S.D.file_record(path, limit) | {"path": str(path), "identity": list(S.D.state(item))}

            with patch.object(lifecycle, "SHELL_DATA_ROOTS", ((str(root), "directory"),)), \
                 patch.object(lifecycle, "SHELL_MODULE_CACHES", {str(cache): "/fixed/modules"}):
                first = lifecycle.shell_data_snapshot(binding)
                cache.write_bytes(b"libtwo.so: gsettings-backend\n")
                second = lifecycle.shell_data_snapshot(binding)
                self.assertEqual(first["suppliers"], second["suppliers"])
                self.assertNotEqual(first["caches"], second["caches"])
                self.assertNotEqual(first["moduleSelections"], second["moduleSelections"])
                (root / "font.ttf").write_bytes(b"changed supplier DATA")
                self.assertNotEqual(second["suppliers"], lifecycle.shell_data_snapshot(binding)["suppliers"])
                (root / "font.ttf").chmod(0o755)
                with self.assertRaises(ValueError):
                    lifecycle.shell_data_snapshot(binding)

    def test_shell_handoff_keeps_exact_byte_bound_and_separate_endpoint_refusal(self):
        limit = 1 << 20
        overhead = len(S.D.canonical({"data": ""}))
        for size in (limit - 1, limit):
            request = {"data": "x" * (size - overhead)}
            with self.subTest(size=size), patch.object(S.time, "monotonic", return_value=10.0) as clock:
                self.assertEqual(S.shell_handoff_bytes(request, 11.0), S.D.canonical(request))
                self.assertEqual(len(S.shell_handoff_bytes(request, 11.0)), size)
                self.assertEqual(clock.call_count, 2)
        with patch.object(S.time, "monotonic", return_value=12.0) as clock, self.assertRaises(S.D.Refused) as refused:
            S.shell_handoff_bytes({"data": "x" * (limit + 1 - overhead)}, 11.0)
        self.assertEqual(str(refused.exception), "Shell handoff exceeds original byte bound (bytes=1048577, limit=1048576)")
        clock.assert_not_called()  # A byte refusal makes no claim about an unobserved endpoint.
        for now in (11.0, 12.0):
            with self.subTest(now=now), patch.object(S.time, "monotonic", return_value=now), \
                 self.assertRaisesRegex(S.D.Refused, "^Original shell handoff endpoint expired$"):
                S.shell_handoff_bytes({"data": "never print request contents"}, 11.0)



def closed_tools_offline_data(lifecycle, case):
    """Fictional protocol and export DATA, never execution/qualification evidence."""
    offline, cancel = case.startswith("offline-"), case in ("tools-cancel", "offline-cancel")
    drift = case == "offline-drift"
    config = lifecycle.SHELL_TOOLS_OFFLINE_CONFIGS[case]
    config_pin = {"bytes": len(config), "sha256": hashlib.sha256(config).hexdigest()}
    context = {"projectId": "inert_project", "draftRevision": 1, "baselineGeneration": 0,
               "platform": "android", "operation": "offline-preflight" if offline else "build"}
    if offline: context["savedConfig"] = deepcopy(config_pin)
    flags = {key: True for key in ("inspectionJoined", "acquisitionJoined", "attempted", "childWaitedSuccess", "stdinClosed",
        "stdoutEofClosed", "stderrEofClosed", "ioJoined", "coreLifetimeSettled", "runtimeLedgerSettled", "runtimeSettlementJoined",
        "driverJoined", "managerJoined", "observerJoined", "watchdogJoined", "retiredBeforeCutoff")}
    flags.update(noChild=False, activeRetained=False, resourceUnknown=False)
    if case == "tools-cancel":
        flags.update({key: False for key in ("acquisitionJoined", "attempted", "childWaitedSuccess", "stdinClosed", "stdoutEofClosed",
                                             "stderrEofClosed", "coreLifetimeSettled")})
        flags["noChild"] = True
    outcome, reason = (("cancelled", "cancelled") if cancel else ("refused", "saved-config-changed") if drift else
                       ("complete", "none") if offline else ("unavailable", "none"))
    terminal = {"ownerGeneration": "b" * 32, "context": context, "phase": "terminal" if offline else "settled",
                "outcome": outcome, "reason": reason, "result": None}
    terminal.update({"operationId": "a" * 32, "intentUsable": False} if offline else {"runId": "a" * 32, "finality": "settled"})
    if outcome == "unavailable":
        terminal["result"] = {"schemaVersion": 1, "policyVersion": "environment-diagnostics-v1", "context": deepcopy(context),
            "hostPlatform": "linux", "outcome": "unavailable", "commandsAttempted": 0,
            "checks": [{"id": role, "state": "not-run", "reason": "missing-in-supported-lookup", "version": None, "build": None,
                "returnCode": None, "baseline": {"kind": "no-local-policy" if role == "git" else "workflow-reference",
                    "version": None if role == "git" else "21", "build": None}, "assessment": "not-assessed", "help": "Fixed core explanation"}
                for role in ("git", "java", "javac")],
            "lifetime": {"complete": True, "fatal": False, "contained": True, "commandDispatched": False, "commands": 0,
                "inputClosed": True, "handlersRestored": True, "toolDescriptorsClosed": True, "stopObserved": "none"},
            "assurance": {"basis": "local-tool-observation", "toolsAttempted": False, "projectCodeExecuted": False, "projectFilesRead": False,
                "repositoryObserved": False, "sdkInspected": False, "credentialsRead": False, "storeContacted": False,
                "dependencyCompleteness": "unknown", "releaseReadiness": "unknown", "toolCacheEffects": "possible"}}
    elif outcome == "complete":
        status = "FAIL" if case == "offline-negative" else "PASS"
        counts = dict.fromkeys(lifecycle.SHELL_TOOLS_OFFLINE_STATUSES, 0); counts[status] = 1
        terminal["result"] = {"schemaVersion": 1, "scope": "saved-offline-android-no-core-build", "usedConfig": deepcopy(config_pin),
            "findings": [{"ordinal": 0, "check": "configured-project-check", "status": status, "message": "configured-project-check", "projectCheckIndex": 0}],
            "summary": {"total": 1, "shown": 1, "omitted": 0, "counts": counts}, "limitations": list(lifecycle.SHELL_TOOLS_OFFLINE_LIMITATIONS)}
    boundary = "inspection" if case == "tools-cancel" else "settlement" if case in ("tools-settlement", "offline-settlement") else "none"
    traces = {"scriptTrace": lifecycle.SHELL_TOOLS_OFFLINE_TRACES[case].decode("ascii"), "laterTrace": "", "savedConfigChanged": drift}
    receipt = {"schema": "installed-tools-offline-v1", "case": case, "qualificationOnly": True, "builder": "normal", "projectPicker": True,
        "savedObservation": True, "requests": {"toolsStart": 0 if offline else 1, "toolsCancel": 1 if case == "tools-cancel" else 0,
            "offlinePrepare": 1 if offline else 0, "offlineStart": 1 if offline else 0, "offlineCancel": 1 if case == "offline-cancel" else 0},
        "initial": {"toolsAvailable": True, "offlineAvailable": True}, "ui": {"start": True, "consent": offline, "terminal": True, "cancel": cancel},
        "reciprocalBusy": case in ("tools-settlement", "offline-cancel", "offline-settlement"),
        "hold": {"boundary": boundary, "entered": boundary != "none", "released": boundary != "none"},
        "original": {"domain": "offline" if offline else "tools", "id": "a" * 32, "generation": "b" * 32, **flags},
        "terminal": terminal, "fixture": traces}
    fixture = {"fixture": "installed-tools-offline-fixture-v1", "case": case, "rootRetained": True, "originalsAccounted": True,
        "noUnexpectedEntries": True, "noPendingState": True, "beforeCount": 21, "afterCount": 21,
        "mutations": ["project/release/mobile-release.json"] if drift else ["project/script.trace"] if traces["scriptTrace"] else [],
        **traces, "savedConfigBefore": config_pin,
        "savedConfigAfter": {"bytes": len(config) + drift, "sha256": hashlib.sha256(config + (b"\n" if drift else b"")).hexdigest()},
        "before": {"size": 7000, "sha256": "3" * 64}, "after": {"size": 7010 if offline else 7000, "sha256": ("4" if offline else "3") * 64}}
    return receipt, fixture


def android_receipt_data(lifecycle, case):
    """Invented Android terminal DATA; no owner, process, SDK or AAB is created."""
    cancelled, refused = case == "android-build-cancel", case == "android-build-refusals"
    complete = case == "android-build"
    config = lifecycle.SHELL_ANDROID_CONFIG
    version = lifecycle.SHELL_ANDROID_VERSION
    context = {"projectId": "inert_android", "draftRevision": 1, "baselineGeneration": 0,
        "platform": "android", "operation": "android-build-inspect",
        "savedConfig": {"bytes": len(config), "sha256": hashlib.sha256(config).hexdigest()},
        "savedVersion": {"source": "release/version.properties", "bytes": len(version), "sha256": hashlib.sha256(version).hexdigest(),
                        "name": "1.2.3", "build": 7}}
    flags = {key: True for key in ("inspectionJoined", "acquisitionJoined", "attempted", "childWaitedSuccess", "stdinClosed",
        "stdoutEofClosed", "stderrEofClosed", "ioJoined", "coreLifetimeSettled", "runtimeLedgerSettled", "runtimeSettlementJoined",
        "driverJoined", "managerJoined", "observerJoined", "watchdogJoined", "retiredBeforeCutoff")}
    flags.update(domain="android", id="a" * 32, generation="b" * 32, noChild=False, activeRetained=False, resourceUnknown=False)
    selection = {"module": ":app", "variant": "release", "applicationId": "org.example.saved", "task": ":app:bundleRelease"}
    command = {"outcome": "not-dispatched" if refused else "unknown" if cancelled else "exited",
               "exitCode": None if refused or cancelled else 0 if complete else 1}
    findings = [{"ordinal": index, "check": check, "status": status} for index, (check, status) in
                enumerate((("aab-structure", "PASS"), ("aab-manifest", "PASS"), ("signer", "SKIP")))] if complete else []
    counts = {key: 0 for key in ("PASS", "FAIL", "MISSING", "BLOCKED", "INVALID", "SKIP", "MANUAL", "CONFIGURED", "NOT_APPLICABLE")}
    if complete: counts.update(PASS=2, SKIP=1)
    summary = {"total": len(findings), "shown": len(findings), "omitted": 0, "counts": counts}
    activity = {"stage": "accepted" if refused else "disposing-work", "selection": None if refused else selection,
                "command": command, "findings": findings, "summary": summary}
    result = None
    if complete:
        result = {"schemaVersion": 1, "scope": "local-post-build-artifact-observation",
            "usedConfig": deepcopy(context["savedConfig"]), "usedVersion": deepcopy(context["savedVersion"]),
            "selection": deepcopy(selection), "toolchainProfile": "android-local-linux-gnu-x86_64-v1", "command": deepcopy(command),
            "findings": deepcopy(findings), "summary": deepcopy(summary),
            "artifacts": [{"logicalName": "android-aab", "platform": "android", "kind": "aab", "fileName": "app-release.aab",
                "size": 4096, "sha256": "c" * 64, "architectures": [], "unknownAbi": False, "freshness": "not-established"}],
            "assurances": {"structure": "passed", "nativeManifest": "passed", "applicationVersion": "native-checked",
                "signer": "not-inspected", "toolkitSigning": "not-requested", "storeOperation": "not-requested",
                "sourceBinding": "not-established", "releaseReadiness": "not-assessed"},
            "limitations": ["saved-inputs-not-atomic", "project-code-effects-possible", "not-network-isolated",
                "post-run-bytes-may-be-incremental-reused-or-stale", "source-binding-not-established", "artifact-signer-not-inspected",
                "toolkit-signing-not-requested", "store-operation-not-requested", "release-readiness-not-assessed",
                "local-output-observation-not-current-file-authority", "core-terminal-requires-original-native-finality"]}
    terminal = {"operationId": flags["id"], "ownerGeneration": flags["generation"], "context": context,
        "phase": "terminal", "intentUsable": False, "outcome": "complete" if complete else "refused" if refused else "cancelled" if cancelled else "failed",
        "reason": "none" if complete else "saved-version-changed" if refused else "cancelled" if cancelled else "command-failed",
        "stage": activity["stage"], "activity": activity,
        "disposition": {"work": "not-created" if refused else "removed",
            "artifacts": "not-created" if refused else "retained-local-result" if complete else "retained-incomplete"}, "result": result}
    lifetime = {"complete": True, "fatal": False, "contained": True, "commandDispatched": not refused, "commands": 0 if refused else 2 if complete else 1,
        "profileCalls": 0, "inputClosed": True, "handlersRestored": True, "invocationClosed": True, "artifactsClosed": True,
        "toolsClosed": True, "namespaceClosed": True, "stopObserved": "cancelled" if cancelled else "none"}
    fixture = {"sourceControlsAccounted": True, "savedVersionChanged": refused, "gradleBoundary": "" if refused else "active\n",
               "generatedScopesNotExported": ["project/.mobile-release", "project/app/build", "project/build"]}
    return {"schema": "installed-android-build-v2", "case": case, "qualificationOnly": True, "builder": "normal",
        "normalSelection": {"selectedBeforeObservation": True, "observerGranted": False},
        "projectPicker": True, "savedObservation": True, "savedVersionObservation": True,
        "requests": {"androidPrepare": 1, "androidStart": 1, "androidCancel": 1 if cancelled else 0},
        "ui": {"start": True, "consent": True, "terminal": True, "cancel": cancelled}, "busyObserved": cancelled,
        "original": flags, "toolsLedgerSettled": True, "nativeIntegrity": True, "coreLifetime": lifetime, "terminal": terminal, "fixture": fixture,
        "limits": {key: False for key in ("normalActivation", "work3000Expiry", "privateJvmProfile", "noAutoInstall", "allHelperNativeGates", "networkIsolated")}}


def closed_android_data(lifecycle, case):
    receipt = android_receipt_data(lifecycle, case)
    drift = case == "android-build-refusals"
    version = lifecycle.SHELL_ANDROID_VERSION + (b"\n" if drift else b"")
    fixture = {"fixture": "installed-android-build-fixture-v1", "case": case, "rootRetained": True, "originalsAccounted": True,
        **deepcopy(receipt["fixture"]), "beforeCount": 25, "afterCount": 25,
        "mutations": ["project/release/version.properties" if drift else "project/native-stage.trace"],
        "generatedNamespacePresent": not drift, "materials": deepcopy(ANDROID_MATERIAL_DATA),
        "savedConfig": deepcopy(receipt["terminal"]["context"]["savedConfig"]),
        "savedVersionBefore": deepcopy(receipt["terminal"]["context"]["savedVersion"]),
        "savedVersionAfter": {"source": "release/version.properties", "bytes": len(version), "sha256": hashlib.sha256(version).hexdigest(),
                             "name": "1.2.3", "build": 7},
        "before": {"size": 8192, "sha256": "d" * 64}, "after": {"size": 8200, "sha256": "e" * 64}}
    return receipt, fixture


def closed_project_draft_data(lifecycle, *, ordinary=None):
    """Synthetic closed-result schema DATA only; no native/finality claim."""
    # This fresh test-only module gets invented selectors, never host inputs.
    if ordinary is None:
        lifecycle.SHELL_ANDROID_MATERIALS = deepcopy(ANDROID_MATERIAL_DATA)
    receipt = deepcopy(lifecycle.SHELL_PROJECT_RECEIPT)
    fixture = {"fixture": "android-saved-readonly-v1", "rootRetained": True, "hintUnchanged": True,
               "savedOutputsMatched": True, "noUnexpectedEntries": True, "noPendingState": True,
               "entryCount": 7, "sourceBytes": len(lifecycle.SHELL_PROJECT_SOURCE) + len(lifecycle.SHELL_PROJECT_VERSION), "releaseMode": 0o755,
               "config": {"size": len(lifecycle.SHELL_PROJECT_CONFIG), "sha256": hashlib.sha256(lifecycle.SHELL_PROJECT_CONFIG).hexdigest(), "mode": 0o600},
               "gitignore": {"size": len(lifecycle.SHELL_PROJECT_IGNORE), "sha256": hashlib.sha256(lifecycle.SHELL_PROJECT_IGNORE).hexdigest(), "mode": 0o600},
               "before": {"size": 512, "sha256": "a" * 64}, "after": {"size": 1024, "sha256": "b" * 64}}
    candidate = deepcopy(lifecycle.SHELL_LIFECYCLE_RECEIPT)
    candidate_fixture = {"fixture": "android-candidate-documents-v1", "rootRetained": True, "documentsUnchanged": True,
        "noUnexpectedEntries": True, "artifactTargetsAbsent": True, "entryCount": 5, "documentBytes": 11366,
        "directoryMode": 0o700, "fileMode": 0o600,
        "documents": [{"path": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                      for name, raw in lifecycle.SHELL_CANDIDATE_DOCUMENTS.items()],
        "before": {"size": 1536, "sha256": "c" * 64}, "after": {"size": 1536, "sha256": "c" * 64}}
    paths = deepcopy(lifecycle.SHELL_PATH_RECEIPT)
    path_fixture = {"fixture": "project-paths-v1", "rootRetained": True, "originalsRetained": True, "noUnexpectedEntries": True,
        "noPendingState": True, "inertBytesUnchanged": True, "beforeCount": 14, "afterCount": 15, "fileCount": 5, "fileBytes": 130,
        "mutations": ["symlink", "directory-for-file", "file-for-directory", "root-mode"], "rootModes": [0o700, 0o500],
        "before": {"size": 4000, "sha256": "d" * 64}, "after": {"size": 4200, "sha256": "e" * 64}}
    workflows = deepcopy(lifecycle.SHELL_WORKFLOW_RECEIPT)
    workflow_fixture = {"fixture": "android-workflow-apply-v1", "rootRetained": True, "originalsRetained": True, "createdCount": 3,
        "beforeCount": 9, "afterCount": 12, "configurationAbsent": True, "noUnexpectedEntries": True, "noPendingState": True,
        "callers": [{"path": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": 0o640 if index == 0 else 0o600}
                    for index, (name, raw) in enumerate(lifecycle.SHELL_WORKFLOW_CALLERS.items())],
        "before": {"size": 3500, "sha256": "f" * 64}, "after": {"size": 4500, "sha256": "9" * 64}}
    metadata = deepcopy(lifecycle.SHELL_METADATA_RECEIPT)
    metadata_fixture = {"fixture": "android-metadata-save-v1", "rootRetained": True, "preservedOriginals": True,
        "createdCount": 1, "replacedCount": 1, "beforeCount": 13, "afterCount": 14,
        "configurationUnchanged": True, "noUnexpectedEntries": True, "noPendingState": True,
        "files": [{"path": "release/store/android/en-US/" + name, "size": len(raw),
                   "sha256": hashlib.sha256(raw).hexdigest(), "mode": 0o600}
                  for name, raw in (("title.txt", b"Public title"), ("short_description.txt", b"Public summary"),
                                    ("keep.txt", b"untouched\n"), ("full_description.txt", b"Public description"))],
        "before": {"size": 4600, "sha256": "1" * 64}, "after": {"size": 4800, "sha256": "2" * 64}}
    observed = {"state": "normal-shell-installed-runtime-connection-observed", "productQualified": False,
            "packageLifecycleQualified": False, "shellPackageBuilt": False,
            "cases": {
                "normal": {"case": "normal", "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": False, "maps": []},
                "positive": {"case": "positive", "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True,
                             "maps": [], "projectDraft": receipt, "lifecycleDocuments": candidate},
                "quit-outstanding": {"case": "quit-outstanding", "exitCode": 0, "bootstrapReturned": False,
                                     "domAndGtkObserved": True, "maps": [[{"DATA": True}]]},
                "project-paths": {"case": "project-paths", "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True,
                                  "maps": [], "projectPaths": paths},
                "workflow-apply": {"case": "workflow-apply", "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True,
                                   "maps": [], "workflowApply": workflows},
                "metadata-save": {"case": "metadata-save", "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True,
                                  "maps": [], "metadataSave": metadata},
            }, "projectDraft": {"native": deepcopy(receipt), "fixture": fixture},
            "lifecycleDocuments": {"native": deepcopy(candidate), "fixture": candidate_fixture},
            "projectPaths": {"native": deepcopy(paths), "fixture": path_fixture},
            "workflowApply": {"native": deepcopy(workflows), "fixture": workflow_fixture},
            "metadataSave": {"native": deepcopy(metadata), "fixture": metadata_fixture},
            "files": [{"path": "lifecycle-shell-positive-project-" + phase + ".json", **fixture[phase]}
                      for phase in ("before", "after")]
                     + [{"path": "lifecycle-shell-positive-candidate-" + phase + ".json", **candidate_fixture[phase]}
                        for phase in ("before", "after")]
                      + [{"path": "lifecycle-shell-project-paths-" + phase + ".json", **path_fixture[phase]}
                         for phase in ("before", "after")]
                      + [{"path": "lifecycle-shell-workflow-apply-" + phase + ".json", **workflow_fixture[phase]}
                         for phase in ("before", "after")]
                      + [{"path": "lifecycle-shell-metadata-save-" + phase + ".json", **metadata_fixture[phase]}
                         for phase in ("before", "after")]}
    sessions = {}
    maps = [{"role": role, "path": "/inert/" + role, "deviceMajor": 8, "deviceMinor": 2, "inode": index + 1}
            for index, role in enumerate(sorted(lifecycle.PRIVATE_SONAMES | {"python", "ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6"}))]
    for case in lifecycle.SHELL_SESSION_CASES:
        receipt = deepcopy(lifecycle.SHELL_SESSION_RECEIPTS[case])
        changed = case == "session-refusals"
        ios = case == "session-ios-firebase"
        fixture = {"fixture": "ios-firebase-session-v1" if ios else "four-kind-session-v1", "case": case, "rootRetained": True, "originalsAccounted": True,
            "projectUnchanged": True, "sourcesOutsideProject": True, "noUnexpectedEntries": True, "noPendingState": True,
            "beforeCount": 15 if changed else 8 if ios else 9, "afterCount": 14 if changed else 8 if ios else 9,
            "mutations": ["changed-leaf-rename"] if changed else [],
            "before": {"size": 4096 if changed else 3072, "sha256": "7" * 64},
            "after": {"size": 3900 if changed else 3072, "sha256": ("8" if changed else "7") * 64}}
        observed["cases"][case] = {"case": case, "exitCode": 0, "bootstrapReturned": True,
                                  "domAndGtkObserved": True,
                                  "maps": [deepcopy(maps) for _ in range(receipt["behavior"]["assessments"])], "sessionInputs": receipt}
        sessions[case] = {"native": deepcopy(receipt), "fixture": fixture}
        observed["files"].extend({"path": "lifecycle-shell-" + case + "-" + phase + ".json", **fixture[phase]}
                                 for phase in ("before", "after"))
    observed["sessionInputs"] = sessions
    observed["toolsOffline"] = {}
    for case in lifecycle.SHELL_TOOLS_OFFLINE_CASES:
        receipt, fixture = closed_tools_offline_data(lifecycle, case)
        observed["cases"][case] = {"case": case, "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True,
                                   "maps": [], "toolsOffline": receipt}
        observed["toolsOffline"][case] = {"native": deepcopy(receipt), "fixture": fixture}
        observed["files"].extend({"path": "lifecycle-shell-" + case + "-" + phase + ".json", **fixture[phase]} for phase in ("before", "after"))
    if ordinary is None:
        observed["androidBuild"] = {}
    for case in (() if ordinary is not None else lifecycle.SHELL_ANDROID_CASES):
        receipt, fixture = closed_android_data(lifecycle, case)
        observed["cases"][case] = {"case": case, "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True,
                                   "maps": [], "androidBuild": receipt}
        observed["androidBuild"][case] = {"native": deepcopy(receipt), "fixture": fixture}
        observed["files"].extend({"path": "lifecycle-shell-" + case + "-" + phase + ".json", **fixture[phase]} for phase in ("before", "after"))
    observed["cases"]["settled-failure"] = {"case": "settled-failure", "exitCode": 1, "bootstrapReturned": True,
        "domAndGtkObserved": True, "maps": [], "qualified": False, "expectedFailureObserved": True,
        "failureHandoff": "original-quit-relay-loop-returned"}
    observed["settledFailure"] = deepcopy(observed["cases"]["settled-failure"])
    version = deepcopy(lifecycle.SHELL_VERSION_RECEIPT)
    version_fixture = {"fixture": "release-version-save-v1", "rootRetained": True, "preservedOriginals": True,
        "createdFileCount": 1, "beforeCount": 5, "afterCount": 6,
        "configurationUnchanged": True, "ignoreUnchanged": True, "sentinelUnchanged": True,
        "noUnexpectedEntries": True, "noPendingState": True,
        "version": {"path": "version.properties", "size": 34,
                    "sha256": hashlib.sha256(b"VERSION_NAME=2.3.4\nBUILD_NUMBER=8\n").hexdigest(), "mode": 0o600},
        "before": {"size": 2600, "sha256": "5" * 64}, "after": {"size": 2800, "sha256": "6" * 64}}
    observed["cases"]["version-save"] = {"case": "version-save", "exitCode": 0, "bootstrapReturned": True,
        "domAndGtkObserved": True, "maps": [], "versionSave": version}
    observed["versionSave"] = {"native": deepcopy(version), "fixture": version_fixture}
    observed["files"].extend({"path": "lifecycle-shell-version-save-" + phase + ".json", **version_fixture[phase]}
                             for phase in ("before", "after"))
    if ordinary is not None:
        observed["ordinary21"] = deepcopy(ordinary)
        observed["state"] = "ordinary21-shell-installed-runtime-connection-observed"
        pin = {"size": 2048, "sha256": "7" * 64}
        observed["namespacePlaceholders"] = {"fixture": "ordinary21-inert-placeholders-v1",
            "names": ["android-build", "android-build-cancel", "android-build-failure", "android-build-refusals"],
            "namespaceOnly": True, "empty": True, "originalsAccounted": True, "rootRetained": True,
            "before": deepcopy(pin), "after": deepcopy(pin)}
        observed["files"].extend({"path": "lifecycle-shell-ordinary21-placeholders-" + phase + ".json", **pin}
                                 for phase in ("before", "after"))
        raw = S.D.canonical(observed["cases"])
        observed["files"].append({"path": "lifecycle-shell-cases.json", "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        names = {"lifecycle-" + name for name in lifecycle.public_files({"shell": {"ordinary21": ordinary}})
                 | {"client.stdout", "client.stderr"}}
        retained = {row["path"] for row in observed["files"]}
        observed["files"].extend({"path": name, "size": 0, "sha256": hashlib.sha256(b"").hexdigest()}
                                 for name in sorted(names - retained))
    return observed


class InstalledProjectDraftReceiptContracts(unittest.TestCase):

    def test_consumes_one_combined_positive_only_after_matching_closed_export_pins(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        observed = closed_project_draft_data(lifecycle)
        result = S.shell_project_draft_observation(observed, lifecycle)
        self.assertEqual(result, observed["projectDraft"])
        self.assertEqual(result["native"]["schemaVersion"], 4)
        self.assertEqual(result["native"]["fixture"], "android-saved-readonly-v1")
        self.assertEqual(result["native"]["methods"], "14-input-assess")
        self.assertEqual(result["native"]["quit"]["operation"], 7)
        self.assertFalse(result["native"]["passiveActions"])
        self.assertEqual(result["native"]["snapshot"]["sourceFiles"], 2)
        self.assertEqual(result["native"]["save"]["requests"], {"open": 2, "prepare": 2, "apply": 1, "close": 0})
        self.assertTrue(result["native"]["save"]["confirmation"]["keepReviewing"])
        self.assertTrue(result["native"]["save"]["createReleaseDirectory"])
        self.assertEqual(result["native"]["save"]["outcome"], ["committed", "clean", "settled", "none"])
        self.assertEqual(result["native"]["noop"]["outcome"], ["not_started", "not_created", "settled", "cancelled"])
        self.assertEqual(result["native"]["noop"]["nativeReason"], "shutdown")
        self.assertEqual(result["native"]["originals"]["runtimeSettlementJoined"], 2)
        self.assertTrue(result["native"]["readback"]["fresh"])
        guidance = result["native"]["guidance"]
        self.assertTrue(guidance["draftUnchanged"])
        self.assertTrue(guidance["requirements"]["requestResultDomMatched"])
        self.assertEqual(guidance["requirements"]["context"], "android/build")
        self.assertEqual(guidance["requirements"]["roles"], 3)
        self.assertTrue(guidance["github"]["requestResultDomMatched"] and guidance["github"]["explicitInputs"])
        self.assertEqual(guidance["github"]["browserEdit"], "insertText")
        self.assertEqual(guidance["github"]["workflowCount"], 4)
        self.assertFalse(guidance["assuranceActions"])
        self.assertEqual(guidance["releaseReadiness"], "unknown")
        self.assertEqual(result["native"]["savedReads"], {
            "version": {"requestResultDomMatched": True, "pairMatched": True, "name": "1.2.3", "build": 7},
            "metadata": {"observeRequestResultDomMatched": True, "absent": 3, "validateRequestResultDomMatched": True,
                         "browserEdit": "insertText", "draftRetained": True},
            "scope": "single-request-non-atomic",
        })
        encoded = lifecycle.canonical(result["native"])
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertEqual(len(encoded), 2042)
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), "4abcdf39143d07b5ed4a4bd474e983fcdd12a3f24a3e61a1a6bc0ac0bc2bf57a")
        self.assertLessEqual(len(encoded), 2048)
        self.assertTrue(result["fixture"]["savedOutputsMatched"])
        self.assertTrue(result["fixture"]["hintUnchanged"])
        self.assertEqual(result["fixture"]["entryCount"], 7)
        self.assertEqual(result["fixture"]["sourceBytes"], 149)
        self.assertNotEqual(result["fixture"]["before"], result["fixture"]["after"])
        self.assertEqual(set(observed["cases"]), {"normal", "positive", "quit-outstanding", "project-paths", "workflow-apply",
                                                "session-inputs", "session-refusals", "session-loss", "session-deadline", "session-ios-firebase", "metadata-save",
                                                "tools-observed", "tools-cancel", "tools-settlement", "offline-pass", "offline-negative",
                                                "offline-drift", "offline-cancel", "offline-settlement", "settled-failure", "version-save",
                                                "android-build", "android-build-failure", "android-build-cancel", "android-build-refusals"})

    def test_rejects_legacy_partial_mistyped_or_relabelled_positive_receipts(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        mutations = (
            lambda v: v.pop("projectDraft"), lambda v: v["cases"]["positive"].pop("projectDraft"),
            lambda v: v["cases"]["positive"]["projectDraft"].update(methods="six-passive"),
            lambda v: v["cases"]["positive"]["projectDraft"].pop("save"),
            lambda v: v["cases"]["positive"]["projectDraft"].update(schemaVersion=2),
            lambda v: v["projectDraft"]["native"].pop("originals"),
            lambda v: v["projectDraft"]["native"].update(guidance={"draftUnchanged": True}),
            lambda v: v["projectDraft"]["native"].pop("savedReads"),
            lambda v: v["cases"]["positive"].update(exitCode=True),
            lambda v: v["cases"]["positive"].update(domAndGtkObserved=1),
            lambda v: v["cases"]["positive"]["projectDraft"]["select"].update(originalsSettled=False),
            lambda v: v["cases"]["positive"]["projectDraft"]["quit"].update(relayJoined=False),
            lambda v: v["projectDraft"]["native"]["cancel"].update(originalsSettled=1),
            lambda v: v["projectDraft"]["fixture"].update(rootRetained=1),
            lambda v: v["projectDraft"]["fixture"].update(fixture="android-config-save-v1"),
            lambda v: v["projectDraft"]["fixture"].update(hintUnchanged=False),
            lambda v: v["projectDraft"]["fixture"].update(savedOutputsMatched=False),
            lambda v: v["projectDraft"]["fixture"].update(noUnexpectedEntries=False),
            lambda v: v["projectDraft"]["fixture"].update(noPendingState=False),
            lambda v: v["projectDraft"]["fixture"].update(configAbsent=True),
            lambda v: v["projectDraft"]["fixture"].update(entryCount=True),
            lambda v: v["projectDraft"]["fixture"].update(entryCount=6),
            lambda v: v["projectDraft"]["fixture"].update(sourceBytes=0),
            lambda v: v["projectDraft"]["fixture"].update(sourceBytes=len(lifecycle.SHELL_PROJECT_SOURCE)),
            lambda v: v["projectDraft"]["fixture"].update(releaseMode=0o700),
            lambda v: v["projectDraft"]["fixture"]["config"].update(sha256="f" * 64),
            lambda v: v["projectDraft"]["fixture"]["gitignore"].update(mode=0o644),
            lambda v: v["projectDraft"]["fixture"]["before"].update(size=8193),
            lambda v: v["projectDraft"]["fixture"]["after"].update(sha256="unbound"),
            lambda v: v.update(productQualified=True), lambda v: v.update(packageLifecycleQualified=True),
            lambda v: v.update(shellPackageBuilt=True), lambda v: v.update(state="project-draft-qualified"),
            lambda v: v.pop("settledFailure"), lambda v: v["cases"].pop("settled-failure"),
            lambda v: v["cases"]["settled-failure"].update(exitCode=0),
            lambda v: v["cases"]["settled-failure"].update(exitCode=True),
            lambda v: v["cases"]["settled-failure"].update(qualified=True),
            lambda v: v["cases"]["settled-failure"].update(expectedFailureObserved=1),
            lambda v: v["cases"]["settled-failure"].update(failureHandoff="not-observed"),
            lambda v: v["settledFailure"].update(domAndGtkObserved=False),
            lambda v: v.update(settledFailure="diagnostic-only"),
        )
        for mutate in mutations:
            observed = closed_project_draft_data(lifecycle); mutate(observed)
            with self.subTest(mutate=mutate), self.assertRaises((S.D.Refused, ValueError)):
                S.shell_project_draft_observation(observed, lifecycle)

        expected = lifecycle.SHELL_PROJECT_RECEIPT
        variants = {
            "legacy-v2": {**expected, "schemaVersion": 2},
            "prior-R-v3": {**expected, "schemaVersion": 3, "methods": "eleven-passive", "quit": {**expected["quit"], "operation": 3}},
            "predecessor-thirteen": {**expected, "schemaVersion": 3, "methods": "thirteen-passive"},
            "predecessor-twelve": {**expected, "schemaVersion": 3, "methods": "twelve-passive", "quit": {**expected["quit"], "operation": 6}},
            "stale-thirteen-assessment": {**expected, "methods": "13-input-assess"},
            "save-only": {key: child for key, child in expected.items() if key not in {"guidance", "savedReads"}},
            "guidance-only": {key: child for key, child in expected.items() if key not in {"save", "readback", "noop", "originals", "savedReads"}},
            "saved-reads-only": {key: child for key, child in expected.items() if key not in {"save", "readback", "noop", "originals", "guidance"}},
            "partial-guidance": {**expected, "guidance": {"draftUnchanged": True}},
            "wrong-guidance-type": {**expected, "guidance": []},
            "no-saved-reads": {key: child for key, child in expected.items() if key != "savedReads"},
            "partial-saved-reads": {**expected, "savedReads": {"version": expected["savedReads"]["version"]}},
            "wrong-saved-reads-type": {**expected, "savedReads": []},
            "wrong-version-type": {**expected, "savedReads": {**expected["savedReads"], "version": []}},
            "wrong-metadata-type": {**expected, "savedReads": {**expected["savedReads"], "metadata": None}},
        }
        for name, partial in variants.items():
            for side in ("case", "native", "both"):
                observed = closed_project_draft_data(lifecycle)
                if side in {"case", "both"}:
                    observed["cases"]["positive"]["projectDraft"] = deepcopy(partial)
                if side in {"native", "both"}:
                    observed["projectDraft"]["native"] = deepcopy(partial)
                with self.subTest(shape=name, side=side), self.assertRaises((S.D.Refused, ValueError)):
                    S.shell_project_draft_observation(observed, lifecycle)

        def leaves(value, prefix=()):
            for key, child in (value.items() if type(value) is dict else enumerate(value)):
                if type(child) in (dict, list):
                    yield from leaves(child, (*prefix, key))
                else:
                    yield (*prefix, key), child

        for path, original in leaves(lifecycle.SHELL_PROJECT_RECEIPT):
            for mode in ("missing", "changed", "wrong-type"):
                changed = deepcopy(lifecycle.SHELL_PROJECT_RECEIPT)
                parent = changed
                for key in path[:-1]:
                    parent = parent[key]
                if mode == "missing":
                    del parent[path[-1]]
                elif mode == "wrong-type":
                    parent[path[-1]] = int(original) if type(original) is bool else True if type(original) is int else None
                else:
                    parent[path[-1]] = not original if type(original) is bool else original + 1 if type(original) is int else original + "-other"
                # Neither a changed native copy nor two mutually agreeing but
                # invalid copies may replace the strict original receipt.
                for side in ("case", "native", "both"):
                    observed = closed_project_draft_data(lifecycle)
                    if side in {"case", "both"}:
                        observed["cases"]["positive"]["projectDraft"] = deepcopy(changed)
                    if side in {"native", "both"}:
                        observed["projectDraft"]["native"] = deepcopy(changed)
                    with self.subTest(path=path, mode=mode, side=side), self.assertRaises((S.D.Refused, ValueError)):
                        S.shell_project_draft_observation(observed, lifecycle)

    def test_missing_duplicate_or_mismatched_original_inventory_exports_refuse(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        for mutate in (
            lambda v: v["files"].pop(1), lambda v: v["files"].append(deepcopy(v["files"][0])),
            lambda v: v["files"][1].update(sha256="c" * 64), lambda v: v["files"][0].update(size=513),
            lambda v: v["files"][1].update(size=True), lambda v: v["files"][1].update(path="unbound-after.json"),
            lambda v: v["files"][0].update(extra=True),
            lambda v: v["projectDraft"]["fixture"].update(after=deepcopy(v["projectDraft"]["fixture"]["before"])),
        ):
            observed = closed_project_draft_data(lifecycle); mutate(observed)
            with self.subTest(mutate=mutate), self.assertRaises(S.D.Refused):
                S.shell_project_draft_observation(observed, lifecycle)


class InstalledCandidateDocumentsReceiptContracts(unittest.TestCase):
    def test_historical_candidate_key_is_not_a_lifecycle_companion_even_with_new_body(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        for location in ("combined", "positive", "extra"):
            observed = closed_project_draft_data(lifecycle)
            if location == "combined":
                observed["candidateDocuments"] = observed.pop("lifecycleDocuments")
            elif location == "positive":
                positive = observed["cases"]["positive"]
                positive["candidateDocuments"] = positive.pop("lifecycleDocuments")
            else:
                observed["cases"]["positive"]["candidateDocuments"] = deepcopy(lifecycle.SHELL_LIFECYCLE_RECEIPT)
            with self.subTest(location=location), self.assertRaises(S.D.Refused):
                S.shell_project_draft_observation(observed, lifecycle)

    def test_candidate_is_a_separate_bounded_companion_not_replacement_project_proof(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        observed = closed_project_draft_data(lifecycle)
        self.assertEqual(S.shell_project_draft_observation(observed, lifecycle), observed["projectDraft"])
        candidate = observed["lifecycleDocuments"]
        self.assertEqual(candidate["native"], observed["cases"]["positive"]["lifecycleDocuments"])
        raw = lifecycle.canonical(candidate["native"])
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()),
                         (1690, "7d7bef285e1d9aace0e4a5b6811c063ea6e2c2ef058b31bffc4b1cb37c16cb53"))
        self.assertLessEqual(len(raw), 2048)
        self.assertEqual([candidate["native"][key]["operation"] for key in ("cancel", "select", "observe", "stop", "quit")], [3, 4, 5, 6, 7])
        self.assertTrue(candidate["native"]["cancel"]["probeUnstarted"])
        self.assertTrue(candidate["native"]["cancel"]["nativeFinal"])
        self.assertEqual(candidate["native"]["requests"], {"choose": 3, "observe": 1, "cancel": 1})
        self.assertEqual(candidate["native"]["observe"]["method"], "release.evidence.observe")
        self.assertEqual(candidate["native"]["observe"]["stage"], "candidate")
        self.assertEqual(candidate["native"]["opposite"]["boundary"], "native-owner-endpoints")
        self.assertFalse(candidate["native"]["stop"]["gtkCancel"])
        self.assertFalse(candidate["native"]["shared"]["recoveryCurrent"])
        self.assertEqual(candidate["native"]["scope"], {"documents": 3, "formatsDigestsBindingsMatched": True,
            "artifactPayloadsObserved": False, "sourceCompared": False, "signingVerified": False,
            "workflowAuthenticated": False, "storeObserved": False, "releaseReady": False, "recoveryAuthority": False})
        fixture = candidate["fixture"]
        self.assertEqual((fixture["entryCount"], fixture["documentBytes"], fixture["directoryMode"], fixture["fileMode"]), (5, 11366, 0o700, 0o600))
        self.assertEqual(fixture["before"], fixture["after"])
        expected_exports = ["lifecycle-shell-" + family + "-" + phase + ".json"
                            for family in ("positive-project", "positive-candidate", "project-paths",
                                           "workflow-apply", "metadata-save", "version-save", "session-inputs",
                                           "session-refusals", "session-loss", "session-deadline", "session-ios-firebase",
                                           *lifecycle.SHELL_TOOLS_OFFLINE_CASES, *lifecycle.SHELL_ANDROID_CASES)
                            for phase in ("before", "after")]
        self.assertCountEqual([item["path"] for item in observed["files"]], expected_exports)
        # Only this shell profile allows190 root slots plus the same client's
        # two captures. The non-shell128 and aggregate32MiB caps do not change.
        observed["files"].extend({"path": "inert-" + str(index), "size": 0, "sha256": "0" * 64}
                                 for index in range(192 - len(observed["files"])))
        self.assertEqual(len(observed["files"]), 192)
        S.shell_project_draft_observation(observed, lifecycle)
        observed["files"].append({"path": "over-cap", "size": 0, "sha256": "0" * 64})
        self.assertEqual(len(observed["files"]), 193)
        with self.assertRaises(S.D.Refused):
            S.shell_project_draft_observation(observed, lifecycle)

    def test_missing_partial_extra_or_nonpositive_candidate_receipts_refuse(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        mutations = (
            lambda v: v.pop("lifecycleDocuments"), lambda v: v["cases"]["positive"].pop("lifecycleDocuments"),
            lambda v: v["lifecycleDocuments"].pop("native"), lambda v: v["lifecycleDocuments"].pop("fixture"),
            lambda v: v["lifecycleDocuments"].update(extra=True),
            lambda v: v["cases"]["positive"].update(lifecycleDocuments=[]),
            lambda v: v["lifecycleDocuments"].update(native={}),
            lambda v: v["lifecycleDocuments"]["native"].update(selectionId="unbound"),
            lambda v: v["lifecycleDocuments"]["native"].update(scope={"documents": 3}),
            lambda v: v["lifecycleDocuments"]["native"].pop("preserved"),
            lambda v: v["lifecycleDocuments"]["native"].pop("quit"),
            lambda v: v["cases"]["normal"].update(lifecycleDocuments=deepcopy(lifecycle.SHELL_LIFECYCLE_RECEIPT)),
            lambda v: v["cases"]["quit-outstanding"].update(lifecycleDocuments=deepcopy(lifecycle.SHELL_LIFECYCLE_RECEIPT)),
        )
        for mutate in mutations:
            observed = closed_project_draft_data(lifecycle); mutate(observed)
            with self.subTest(mutate=mutate), self.assertRaises((S.D.Refused, ValueError)):
                S.shell_project_draft_observation(observed, lifecycle)

    def test_each_candidate_leaf_requires_typed_original_correspondence_on_both_copies(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        expected = lifecycle.SHELL_LIFECYCLE_RECEIPT
        def leaves(value, prefix=()):
            for key, child in value.items():
                if type(child) is dict:
                    yield from leaves(child, (*prefix, key))
                else:
                    yield (*prefix, key), child
        for path, original in leaves(expected):
            for mode in ("missing", "changed", "wrong-type"):
                changed = deepcopy(expected)
                parent = changed
                for key in path[:-1]:
                    parent = parent[key]
                if mode == "missing":
                    del parent[path[-1]]
                elif mode == "wrong-type":
                    parent[path[-1]] = int(original) if type(original) is bool else True if type(original) is int else None
                else:
                    parent[path[-1]] = not original if type(original) is bool else original + 1 if type(original) is int else original[::-1] if type(original) is list else original + "-other"
                for side in ("case", "native", "both"):
                    observed = closed_project_draft_data(lifecycle)
                    if side in {"case", "both"}:
                        observed["cases"]["positive"]["lifecycleDocuments"] = deepcopy(changed)
                    if side in {"native", "both"}:
                        observed["lifecycleDocuments"]["native"] = deepcopy(changed)
                    with self.subTest(path=path, mode=mode, side=side), self.assertRaises((S.D.Refused, ValueError)):
                        S.shell_project_draft_observation(observed, lifecycle)

    def test_candidate_fixture_flags_bytes_and_both_original_export_pins_are_mandatory(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        mutations = (
            lambda v: v["lifecycleDocuments"].update(fixture=[]),
            lambda v: v["lifecycleDocuments"]["fixture"].update(fixture="android-saved-readonly-v1"),
            lambda v: v["lifecycleDocuments"]["fixture"].update(rootRetained=1),
            lambda v: v["lifecycleDocuments"]["fixture"].update(documentsUnchanged=False),
            lambda v: v["lifecycleDocuments"]["fixture"].update(noUnexpectedEntries=False),
            lambda v: v["lifecycleDocuments"]["fixture"].update(artifactTargetsAbsent=False),
            lambda v: v["lifecycleDocuments"]["fixture"].update(entryCount=True),
            lambda v: v["lifecycleDocuments"]["fixture"].update(entryCount=6),
            lambda v: v["lifecycleDocuments"]["fixture"].update(documentBytes=0),
            lambda v: v["lifecycleDocuments"]["fixture"].update(directoryMode=0o755),
            lambda v: v["lifecycleDocuments"]["fixture"].update(fileMode=0o644),
            lambda v: v["lifecycleDocuments"]["fixture"].update(extra=True),
            lambda v: v["lifecycleDocuments"]["fixture"]["documents"].pop(),
            lambda v: v["lifecycleDocuments"]["fixture"]["documents"].reverse(),
            lambda v: v["lifecycleDocuments"]["fixture"]["documents"][0].update(sha256="f" * 64),
            lambda v: v["lifecycleDocuments"]["fixture"]["documents"][0].update(size=True),
            lambda v: v["lifecycleDocuments"]["fixture"]["documents"][0].update(path="reader-1.2.3-42.aab"),
            lambda v: v["lifecycleDocuments"]["fixture"]["before"].update(size=8193),
            lambda v: v["lifecycleDocuments"]["fixture"]["before"].update(size=True),
            lambda v: v["lifecycleDocuments"]["fixture"]["after"].update(sha256="unbound"),
            lambda v: v["lifecycleDocuments"]["fixture"]["after"].update(extra=True),
            lambda v: v["files"].pop(2), lambda v: v["files"].pop(3),
            lambda v: v["files"].append(deepcopy(v["files"][2])),
            lambda v: v["files"][2].update(sha256="f" * 64), lambda v: v["files"][3].update(size=1537),
            lambda v: v["files"][2].update(size=True), lambda v: v["files"][2].update(path="unbound-before.json"),
            lambda v: v["files"][3].update(extra=True),
        )
        for mutate in mutations:
            observed = closed_project_draft_data(lifecycle); mutate(observed)
            with self.subTest(mutate=mutate), self.assertRaises((S.D.Refused, ValueError)):
                S.shell_project_draft_observation(observed, lifecycle)
        # Matching an altered after export cannot hide changed original nodes.
        observed = closed_project_draft_data(lifecycle)
        observed["lifecycleDocuments"]["fixture"]["after"]["sha256"] = "f" * 64
        observed["files"][3]["sha256"] = "f" * 64
        with self.assertRaises(S.D.Refused):
            S.shell_project_draft_observation(observed, lifecycle)


class HostBindingDiagnosticContracts(unittest.TestCase):
    def test_actual_module_diagnostic_retains_bounded_observed_fields(self):
        message = "Writable/special shell host input"
        for mode, uid, gid in ((0o040777, 0, 0), (0o100664, 1001, 1002)):
            item = S.os.stat_result((mode, 1, 1, 1, uid, gid, 0, 0, 0, 0))
            result = S.shell_host_diagnostic(message, Path("/example/data"), Path("/example"), item)
            self.assertEqual(json.loads(result[len(message) + 2:]), {
                "selectedPath": "/example/data", "component": "/example",
                "mode": format(mode, "06o"), "uid": uid, "gid": gid,
            })
            self.assertLessEqual(len(result), 512)
            self.assertEqual(S.failure_reason(S.D.Refused(result)), result)
        escaped = S.shell_host_diagnostic(message, "/example/\u00e9\n", "/example", item)
        self.assertTrue(all(32 <= ord(character) < 127 for character in escaped))
        self.assertEqual(json.loads(escaped[len(message) + 2:])["selectedPath"], "/example/\u00e9\n")
        self.assertEqual(S.shell_host_diagnostic(message, "/" + "x" * 2048, "/example", item), message)



class InstalledProjectPathReceiptContracts(unittest.TestCase):
    def test_requires_closed_case_roster_and_both_typed_inventory_export_pins(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        observed = closed_project_draft_data(lifecycle)
        self.assertEqual(S.shell_project_draft_observation(observed, lifecycle), observed["projectDraft"])
        paths = observed["projectPaths"]
        raw = lifecycle.canonical(paths["native"])
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (1482, "b3784f485377a9e7b249d5dcac1eae98ae4825dd1e9bf1fbce4b0f2e82698633"))
        self.assertEqual(paths["fixture"]["mutations"], ["symlink", "directory-for-file", "file-for-directory", "root-mode"])
        self.assertEqual(paths["fixture"]["rootModes"], [0o700, 0o500])
        self.assertNotEqual(paths["fixture"]["before"], paths["fixture"]["after"])
        mutations = (
            lambda v: v.pop("projectPaths"), lambda v: v["cases"].pop("project-paths"),
            lambda v: v["cases"]["project-paths"].update(exitCode=True), lambda v: v["cases"]["project-paths"].update(bootstrapReturned=1),
            lambda v: v["cases"]["project-paths"].update(maps=[[]]), lambda v: v["cases"]["positive"].update(projectPaths=v["projectPaths"]["native"]),
            lambda v: v["cases"]["normal"].update(projectPaths=v["projectPaths"]["native"]),
            lambda v: v["cases"]["quit-outstanding"].update(projectPaths=v["projectPaths"]["native"]),
            lambda v: v["projectPaths"]["fixture"].update(rootRetained=1), lambda v: v["projectPaths"]["fixture"].update(beforeCount=True),
            lambda v: v["projectPaths"]["fixture"].update(afterCount=14), lambda v: v["projectPaths"]["fixture"].update(rootModes=[0o700, 0o700]),
            lambda v: v["projectPaths"]["fixture"]["mutations"].reverse(), lambda v: v["projectPaths"]["fixture"].update(extra=True),
            lambda v: v["projectPaths"]["fixture"].pop("inertBytesUnchanged"),
            lambda v: v["projectPaths"]["fixture"].update(after=deepcopy(v["projectPaths"]["fixture"]["before"])),
            lambda v: v["files"].pop(5), lambda v: v["files"].append(deepcopy(v["files"][5])),
            lambda v: v["files"][4].update(sha256="0" * 64), lambda v: v["files"][5].update(size=True),
            lambda v: v["files"][5].update(path="lifecycle-shell-positive-project-after.json"),
            lambda v: v["projectPaths"]["fixture"]["before"].update(size=8193), lambda v: v["projectPaths"]["fixture"]["after"].update(sha256="invalid"),
        )
        for mutate in mutations:
            changed = deepcopy(observed); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises((S.D.Refused, ValueError, KeyError)):
                S.shell_project_draft_observation(changed, lifecycle)

    def test_every_nested_receipt_leaf_is_matched_on_both_original_projections(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        expected = closed_project_draft_data(lifecycle)
        def leaves(value, prefix=()):
            if type(value) is dict:
                for key, child in value.items(): yield from leaves(child, (*prefix, key))
            elif type(value) is list:
                for key, child in enumerate(value): yield from leaves(child, (*prefix, key))
            else: yield prefix, value
        for path, old in leaves(expected["projectPaths"]["native"]):
            for target in ("case", "combined"):
                changed = deepcopy(expected)
                parent = changed["cases"]["project-paths"]["projectPaths"] if target == "case" else changed["projectPaths"]["native"]
                for key in path[:-1]: parent = parent[key]
                parent[path[-1]] = int(old) if type(old) is bool else True if type(old) is int else None
                with self.subTest(path=path, target=target), self.assertRaises((S.D.Refused, ValueError)):
                    S.shell_project_draft_observation(changed, lifecycle)


class InstalledWorkflowApplyReceiptContracts(unittest.TestCase):
    def test_literal_fixture_callers_match_the_existing_shared_proposal_and_resource(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        with patch.object(S.sys, "path", [str(SOURCE / "src"), *S.sys.path]):
            from mobile_release.api import execute
            from mobile_release.workflow_payloads import render_workflow_caller
        suggestion = execute("config.suggest", {"hints": {"platforms": ["android"],
            "androidApplicationId": "org.example.mrk.observed", "versionSource": "version.properties",
            "versionNameKey": "VERSION_NAME", "versionBuildKey": "BUILD_NUMBER"}})
        self.assertEqual(suggestion["draft"], json.loads(lifecycle.SHELL_PROJECT_CONFIG))
        proposal = execute("github.setup.propose", {"draft": suggestion["draft"], "toolingRepository": "example/toolkit",
            "toolingSha": "a" * 40, "suppliedSnapshot": None})
        resource = (SOURCE / "src/mobile_release/api/data/github-setup-v1.json").read_bytes()
        self.assertEqual(hashlib.sha256(resource).hexdigest(), "4d486fc24ebf24271dbb5227174df7c8f28a530a97011e004da643fdad7fe17c")
        self.assertEqual(proposal["templateSet"]["resourceSha256"], hashlib.sha256(resource).hexdigest())
        self.assertFalse(proposal["facts"]["applyAvailable"])
        self.assertFalse(proposal["facts"]["repositoryObserved"])
        names = ["preflight", "candidate", "external-testing", "production-submit"]
        self.assertEqual(list(lifecycle.SHELL_WORKFLOW_CALLERS), [".github/workflows/mobile-" + name + ".yml" for name in names])
        self.assertEqual([len(raw) for raw in lifecycle.SHELL_WORKFLOW_CALLERS.values()], [567, 1379, 2150, 2881])
        for item, (path, raw), name in zip(proposal["workflows"], lifecycle.SHELL_WORKFLOW_CALLERS.items(), names):
            self.assertEqual((item["path"], item["content"].encode(), item["byteLength"], item["sha256"]),
                             (path, raw, len(raw), hashlib.sha256(raw).hexdigest()))
            template = (SOURCE / "templates/workflows" / ("mobile-" + name + ".yml")).read_bytes()
            self.assertEqual(json.loads(resource)["workflows"][name].encode(), template)
            self.assertEqual(render_workflow_caller(template, "example/toolkit", "a" * 40), raw)

    def test_fifth_receipt_is_bounded_ordered_and_separate_from_configuration(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        raw = lifecycle.canonical(lifecycle.SHELL_WORKFLOW_RECEIPT)
        self.assertLessEqual(len(raw), 2048)
        self.assertEqual(lifecycle.shell_workflow_receipt(raw), lifecycle.SHELL_WORKFLOW_RECEIPT)
        lines = [b"MRK_DESKTOP_CAPABILITIES=available\n", b"MRK_DESKTOP_CATALOGUE=returned\n",
                 b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n",
                 lifecycle.SHELL_WORKFLOW_MARKER + raw, b"MRK_INSTALLED_SHELL_OBSERVATION=workflow-apply-verified\n"]
        result = lifecycle.shell_result(b"".join(lines), b"", "workflow-apply", 0, {})
        self.assertEqual(result["workflowApply"], lifecycle.SHELL_WORKFLOW_RECEIPT)
        self.assertNotIn("projectDraft", result)
        for output in (b"".join(lines[:3] + lines[4:]), b"".join(lines + [lines[3]]),
                       b"".join(lines[:3] + [lines[4], lines[3]]), b"".join(lines).replace(lifecycle.SHELL_WORKFLOW_MARKER, lifecycle.SHELL_PATH_MARKER)):
            with self.subTest(output=hashlib.sha256(output).hexdigest()), self.assertRaises(ValueError):
                lifecycle.shell_result(output, b"", "workflow-apply", 0, {})
        for malformed in (raw[:-1], raw + b"\n", b" " + raw, raw + b" " * 2048):
            with self.assertRaises(ValueError):
                lifecycle.shell_workflow_receipt(malformed)

    def test_canonical_update_preview_is_closed_without_apply_and_old_pin_conflict_receipts_are_rejected(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        current = lifecycle.SHELL_WORKFLOW_RECEIPT
        self.assertEqual(current["requests"], {"open": 4, "prepare": 4, "apply": 2, "close": 1, "configuration": [0, 0, 0, 0]})
        self.assertEqual(current["reviews"], {"fullText": True, "canonicalUpdates": 4, "updateClosedWithoutApply": True, "configBlocked": 4})
        self.assertEqual(current["outcomes"][1], ["not_started", "not_created", "settled", "cancelled"])
        self.assertEqual(current["nativeReasons"], ["none", "discarded", "none", "shutdown"])
        self.assertEqual(current["originals"]["writerFrames"], [3, 2, 3, 2])
        self.assertEqual(current["originals"]["stdoutFrames"], [3, 3, 3, 3])
        self.assertEqual(current["confirmation"], {"opened": [2, 0, 1, 0], "keepReviewing": True, "acknowledged": 2})
        # Exact historical changed-pin conflict receipt, not a new native result.
        # A canonical update now has a retained plan and explicit UI Close; a
        # genuine customized-newline conflict remains a separate hosted case.
        historical = deepcopy(current)
        historical["requests"]["close"] = 0
        historical["reviews"] = {"fullText": True, "conflictNoToken": True,
                                  "conflictReason": "existing_workflow_differs", "configBlocked": 4}
        historical["outcomes"][1][-1] = "none"
        historical["nativeReasons"][1] = "none"
        historical["originals"]["stdoutFrames"][1] = 2
        with self.assertRaises(ValueError):
            lifecycle.shell_workflow_receipt(lifecycle.canonical(historical))
        for target in ("case", "combined", "both"):
            changed = closed_project_draft_data(lifecycle)
            if target in ("case", "both"):
                changed["cases"]["workflow-apply"]["workflowApply"] = deepcopy(historical)
            if target in ("combined", "both"):
                changed["workflowApply"]["native"] = deepcopy(historical)
            with self.subTest(target=target), self.assertRaises((S.D.Refused, ValueError)):
                S.shell_project_draft_observation(changed, lifecycle)

        # Source correspondence only. Real native preview/discard, update Apply
        # and rollback remain distinct evidence obligations.

    def test_each_workflow_receipt_leaf_requires_exact_types_on_both_projections(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        expected = closed_project_draft_data(lifecycle)
        self.assertEqual(S.shell_project_draft_observation(expected, lifecycle), expected["projectDraft"])
        def leaves(value, prefix=()):
            if type(value) is dict:
                for key, child in value.items(): yield from leaves(child, (*prefix, key))
            elif type(value) is list:
                for key, child in enumerate(value): yield from leaves(child, (*prefix, key))
            else: yield prefix, value
        for path, old in leaves(expected["workflowApply"]["native"]):
            for target in ("case", "combined", "both"):
                changed = deepcopy(expected)
                copies = []
                if target in ("case", "both"): copies.append(changed["cases"]["workflow-apply"]["workflowApply"])
                if target in ("combined", "both"): copies.append(changed["workflowApply"]["native"])
                for parent in copies:
                    for key in path[:-1]: parent = parent[key]
                    parent[path[-1]] = int(old) if type(old) is bool else True if type(old) is int else None
                with self.subTest(path=path, target=target), self.assertRaises((S.D.Refused, ValueError)):
                    S.shell_project_draft_observation(changed, lifecycle)

    def test_workflow_case_fixture_and_exports_cannot_be_missing_relabelled_or_partial(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        mutations = (
            lambda v: v.pop("workflowApply"), lambda v: v["cases"].pop("workflow-apply"),
            lambda v: v["cases"]["workflow-apply"].pop("workflowApply"), lambda v: v["workflowApply"].pop("fixture"),
            lambda v: v["workflowApply"]["native"].pop("originals"),
            lambda v: v["cases"]["workflow-apply"].update(exitCode=True),
            lambda v: v["cases"]["workflow-apply"].update(domAndGtkObserved=1),
            lambda v: v["cases"]["normal"].update(workflowApply=v["workflowApply"]["native"]),
            lambda v: v["workflowApply"]["fixture"].update(createdCount=True),
            lambda v: v["workflowApply"]["fixture"].update(configurationAbsent=False),
            lambda v: v["workflowApply"]["fixture"].update(noPendingState=1),
            lambda v: v["workflowApply"]["fixture"].update(extra=True),
            lambda v: v["workflowApply"]["fixture"]["callers"].pop(),
            lambda v: v["workflowApply"]["fixture"]["callers"].reverse(),
            lambda v: v["workflowApply"]["fixture"]["callers"][0].update(mode=0o600),
            lambda v: v["workflowApply"]["fixture"]["callers"][1].update(sha256="0" * 64),
            lambda v: v["workflowApply"]["fixture"].update(after=deepcopy(v["workflowApply"]["fixture"]["before"])),
            lambda v: v["workflowApply"]["fixture"]["before"].update(size=8193),
            lambda v: v["files"].pop(6), lambda v: v["files"].pop(7),
            lambda v: v["files"].append(deepcopy(v["files"][6])),
            lambda v: v["files"][6].update(size=True), lambda v: v["files"][7].update(sha256="0" * 64),
            lambda v: v["files"][7].update(path="lifecycle-shell-project-paths-after.json"),
        )
        for mutate in mutations:
            observed = closed_project_draft_data(lifecycle); mutate(observed)
            with self.subTest(mutate=mutate), self.assertRaises((S.D.Refused, ValueError, KeyError)):
                S.shell_project_draft_observation(observed, lifecycle)

    def test_outer_workflow_inventory_preserves_original_identities_and_refuses_unexpected_state(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        value = {"runId": "10", "attempt": "2", "runnerUid": 1001, "runnerGid": 1002}
        namespace = {"root": str(lifecycle.shell_fixture_root(value)), "identity": [1, 5, 0o40755, 0, 0, 7, 4096, 9, 9],
            "children": list(lifecycle.SHELL_FIXTURE_CHILDREN), "control": {"path": str(lifecycle.root_path(value)), "identity": [1, 4, 0o40711, 0, 0]},
            "ancestors": [{"path": name, "identity": [1, index, 0o40755, 0, 0]} for index, name in enumerate(("/", "/var", "/var/lib"), 1)]}
        documents = []
        for installed in (False, True):
            entries = []
            for index, (name, mode, owners, data) in enumerate(lifecycle._shell_workflow_roster(value, installed)):
                directory = lifecycle.stat.S_ISDIR(mode)
                original = [1, 100 + index, mode, *owners, 2 if directory else 1, 4096 if directory else len(data),
                            1800000000000000001, 1800000000000000001]
                row = {"path": name, "kind": "directory" if directory else "file", "identity": original}
                row.update({"children": data} if directory else {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
                entries.append(row)
            documents.append({"schemaVersion": 1, "fixture": "android-workflow-apply-v1", "root": str(lifecycle.shell_fixture_root(value) / "workflow-project"),
                "installed": installed, "entries": entries, "absent": lifecycle._shell_workflow_absent(installed), "namespace": deepcopy(namespace)})
        before, after = map(lifecycle.canonical, documents)
        result = lifecycle.shell_workflow_fixture(value, before, after)
        self.assertEqual((result["createdCount"], result["beforeCount"], result["afterCount"]), (3, 9, 12))
        for mutate in (
            lambda d: d["entries"].pop(), lambda d: d["entries"].append(deepcopy(d["entries"][-1])),
            lambda d: d["entries"][0]["children"].append(".mobile-release-init"),
            lambda d: d["entries"][8]["identity"].__setitem__(1, 999),
            lambda d: d["entries"][8]["identity"].__setitem__(7, 1800000000000000000),
            lambda d: d["entries"][9]["identity"].__setitem__(2, 0o100644),
            lambda d: d["entries"][9].update(size=True),
            lambda d: d["entries"][9].update(sha256="0" * 64),
            lambda d: d["entries"][9]["identity"].__setitem__(1, d["entries"][8]["identity"][1]),
            lambda d: d["namespace"]["children"].pop(), lambda d: d["absent"].remove("release"),
            lambda d: d.update(installed=1),
        ):
            changed = deepcopy(documents[1]); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                lifecycle.shell_workflow_fixture(value, before, lifecycle.canonical(changed))


class InstalledMetadataSaveReceiptContracts(unittest.TestCase):
    def test_metadata_receipt_requires_two_original_reviews_one_apply_and_ordered_completion(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        expected = lifecycle.SHELL_METADATA_RECEIPT
        raw = lifecycle.canonical(expected)
        self.assertLessEqual(len(raw), 2048)
        self.assertEqual(lifecycle.shell_metadata_receipt(raw), expected)
        self.assertEqual(expected["requests"], {"observe": 2, "validate": 1, "open": 2, "prepare": 2, "apply": 1,
            "close": 1, "configuration": [0, 0, 0, 0], "workflow": [0, 0, 0, 0]})
        self.assertEqual(expected["originals"]["writerFrames"], [2, 3])  # Explicit close uses original writer EOF.
        self.assertEqual(expected["originals"]["stdoutFrames"], [3, 3])
        self.assertEqual(expected["reviews"]["actions"], [1, 1, 1])
        self.assertEqual(expected["outcomes"], [["not_started", "not_created", "settled", "cancelled"],
                                               ["committed", "clean", "settled", "none"]])
        lines = [b"MRK_DESKTOP_CAPABILITIES=available\n", b"MRK_DESKTOP_CATALOGUE=returned\n",
                 b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n",
                 lifecycle.SHELL_METADATA_MARKER + raw, b"MRK_INSTALLED_SHELL_OBSERVATION=metadata-save-verified\n"]
        result = lifecycle.shell_result(b"".join(lines), b"", "metadata-save", 0, {})
        self.assertEqual(result["metadataSave"], expected)
        self.assertEqual(set(result), {"case", "exitCode", "bootstrapReturned", "domAndGtkObserved", "maps", "metadataSave"})
        for output in (b"".join(lines[:3] + lines[4:]), b"".join(lines + [lines[3]]),
                       b"".join(lines[:3] + [lines[4], lines[3]]),
                       b"".join(lines).replace(lifecycle.SHELL_METADATA_MARKER, lifecycle.SHELL_WORKFLOW_MARKER),
                       b"".join(lines).replace(b"\n", b"\r\n")):
            with self.subTest(output=hashlib.sha256(output).hexdigest()), self.assertRaises(ValueError):
                lifecycle.shell_result(output, b"", "metadata-save", 0, {})
        for stdout, stderr, code in ((b"", b"".join(lines), 0), (b"".join(lines), lines[3], 0),
                                     (b"".join(lines), b"", 1), (b"".join(lines), b"", False)):
            with self.subTest(code=code), self.assertRaises(ValueError):
                lifecycle.shell_result(stdout, stderr, "metadata-save", code, {})
        for malformed in (raw[:-1], raw + b"\n", b" " + raw, raw + b" " * 2048):
            with self.assertRaises(ValueError):
                lifecycle.shell_metadata_receipt(malformed)

    def test_every_metadata_receipt_leaf_and_original_projection_is_required(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        expected = closed_project_draft_data(lifecycle)
        self.assertEqual(S.shell_project_draft_observation(expected, lifecycle), expected["projectDraft"])

        def leaves(value, prefix=()):
            if type(value) is dict:
                for key, child in value.items(): yield from leaves(child, (*prefix, key))
            elif type(value) is list:
                for key, child in enumerate(value): yield from leaves(child, (*prefix, key))
            else: yield prefix, value

        for path, old in leaves(expected["metadataSave"]["native"]):
            for mode in ("missing", "wrong-type", "changed"):
                receipt = deepcopy(expected["metadataSave"]["native"])
                parent = receipt
                for key in path[:-1]: parent = parent[key]
                if mode == "missing":
                    del parent[path[-1]]
                elif mode == "wrong-type":
                    parent[path[-1]] = int(old) if type(old) is bool else True if type(old) is int else None
                else:
                    parent[path[-1]] = not old if type(old) is bool else old + 1 if type(old) is int else old + "-other"
                for target in ("case", "combined", "both"):
                    changed = deepcopy(expected)
                    if target in ("case", "both"):
                        changed["cases"]["metadata-save"]["metadataSave"] = deepcopy(receipt)
                    if target in ("combined", "both"):
                        changed["metadataSave"]["native"] = deepcopy(receipt)
                    with self.subTest(path=path, mode=mode, target=target), self.assertRaises((S.D.Refused, ValueError)):
                        S.shell_project_draft_observation(changed, lifecycle)

    def test_metadata_fixture_exports_and_domain_cannot_be_substituted(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        mutations = (
            lambda v: v.pop("metadataSave"), lambda v: v["cases"].pop("metadata-save"),
            lambda v: v["cases"]["metadata-save"].pop("metadataSave"), lambda v: v["metadataSave"].pop("fixture"),
            lambda v: v["cases"]["metadata-save"].update(exitCode=True),
            lambda v: v["cases"]["metadata-save"].update(domAndGtkObserved=1),
            lambda v: v["cases"]["metadata-save"].update(workflowApply=v["workflowApply"]["native"]),
            lambda v: v["metadataSave"].update(native=deepcopy(v["sessionInputs"]["session-inputs"]["native"])),
            lambda v: v["cases"]["normal"].update(metadataSave=v["metadataSave"]["native"]),
            lambda v: v["cases"]["workflow-apply"].update(metadataSave=v["metadataSave"]["native"]),
            lambda v: v["metadataSave"]["fixture"].update(preservedOriginals=False),
            lambda v: v["metadataSave"]["fixture"].update(configurationUnchanged=False),
            lambda v: v["metadataSave"]["fixture"].update(createdCount=True),
            lambda v: v["metadataSave"]["fixture"].update(replacedCount=0),
            lambda v: v["metadataSave"]["fixture"].update(noPendingState=1),
            lambda v: v["metadataSave"]["fixture"].update(extra=True),
            lambda v: v["metadataSave"]["fixture"]["files"].pop(),
            lambda v: v["metadataSave"]["fixture"]["files"].reverse(),
            lambda v: v["metadataSave"]["fixture"]["files"][1].update(mode=0o644),
            lambda v: v["metadataSave"]["fixture"]["files"][1].update(sha256="0" * 64),
            lambda v: v["metadataSave"]["fixture"].update(after=deepcopy(v["metadataSave"]["fixture"]["before"])),
            lambda v: v["metadataSave"]["fixture"]["before"].update(size=8193),
            lambda v: v["metadataSave"]["fixture"]["after"].update(sha256="unbound"),
            lambda v: v["files"].pop(8), lambda v: v["files"].pop(9),
            lambda v: v["files"].append(deepcopy(v["files"][8])),
            lambda v: v["files"][8].update(size=True), lambda v: v["files"][9].update(sha256="0" * 64),
            lambda v: v["files"][9].update(path="lifecycle-shell-workflow-apply-after.json"),
        )
        for mutate in mutations:
            changed = closed_project_draft_data(lifecycle); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises((S.D.Refused, ValueError, KeyError)):
                S.shell_project_draft_observation(changed, lifecycle)



class InstalledVersionSaveReceiptContracts(unittest.TestCase):
    def test_combined_consumer_requires_the_three_original_version_reviews_and_exports(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        observed = closed_project_draft_data(lifecycle)
        self.assertEqual(S.shell_project_draft_observation(observed, lifecycle), observed["projectDraft"])
        version = observed["versionSave"]
        self.assertEqual(version["native"]["reviews"]["actions"], ["create", "replace", "preserve"])
        self.assertEqual(version["native"]["requests"]["open"], 3)
        self.assertEqual(version["native"]["originals"]["runtimeSettlementJoined"], 3)
        self.assertEqual(version["native"]["outcomes"][-1], ["unchanged", "not_created", "settled", "none"])
        self.assertEqual(version["native"]["nativeFinality"], ["settled"] * 3)
        self.assertEqual(version["native"]["lateSettled"], [False] * 3)
        self.assertEqual(version["fixture"]["version"]["size"], 34)
        for phase in ("before", "after"):
            exported = [row for row in observed["files"] if row["path"] == "lifecycle-shell-version-save-" + phase + ".json"]
            self.assertEqual(exported, [{"path": "lifecycle-shell-version-save-" + phase + ".json", **version["fixture"][phase]}])

    def test_version_case_native_projection_fixture_and_export_pins_cannot_be_substituted(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        mutations = (
            lambda v: v.pop("versionSave"), lambda v: v["cases"].pop("version-save"),
            lambda v: v["cases"]["version-save"].pop("versionSave"), lambda v: v["versionSave"].pop("fixture"),
            lambda v: v["cases"]["version-save"].update(exitCode=True),
            lambda v: v["cases"]["version-save"].update(bootstrapReturned=1),
            lambda v: v["cases"]["version-save"].update(domAndGtkObserved=False),
            lambda v: v["cases"]["version-save"].update(metadataSave=v["metadataSave"]["native"]),
            lambda v: v["versionSave"].update(native=deepcopy(v["metadataSave"]["native"])),
            lambda v: v["cases"]["version-save"]["versionSave"]["originals"].update(ownersJoined=2),
            lambda v: v["versionSave"]["native"]["originals"].update(runtimeLedgerSettled=2),
            lambda v: v["versionSave"]["native"].update(nativeFinality=["settled", "settled", "retained"]),
            lambda v: v["versionSave"]["native"]["filesystem"].update(preserveFull9=False),
            lambda v: v["cases"]["normal"].update(versionSave=v["versionSave"]["native"]),
            lambda v: v["cases"]["metadata-save"].update(versionSave=v["versionSave"]["native"]),
            lambda v: v["versionSave"]["fixture"].update(preservedOriginals=False),
            lambda v: v["versionSave"]["fixture"].update(configurationUnchanged=False),
            lambda v: v["versionSave"]["fixture"].update(ignoreUnchanged=False),
            lambda v: v["versionSave"]["fixture"].update(sentinelUnchanged=False),
            lambda v: v["versionSave"]["fixture"].update(createdFileCount=True),
            lambda v: v["versionSave"]["fixture"].update(beforeCount=4),
            lambda v: v["versionSave"]["fixture"].update(afterCount=7),
            lambda v: v["versionSave"]["fixture"].update(noPendingState=1),
            lambda v: v["versionSave"]["fixture"]["version"].update(path="release/version.properties"),
            lambda v: v["versionSave"]["fixture"]["version"].update(size=True),
            lambda v: v["versionSave"]["fixture"]["version"].update(mode=0o644),
            lambda v: v["versionSave"]["fixture"]["version"].update(sha256="0" * 64),
            lambda v: v["versionSave"]["fixture"].update(after=deepcopy(v["versionSave"]["fixture"]["before"])),
            lambda v: v["versionSave"]["fixture"]["before"].update(size=8193),
            lambda v: v["versionSave"]["fixture"]["after"].update(sha256="unbound"),
        )
        for mutate in mutations:
            changed = closed_project_draft_data(lifecycle); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises((S.D.Refused, ValueError, KeyError)):
                S.shell_project_draft_observation(changed, lifecycle)
        for phase in ("before", "after"):
            for change in ("missing", "duplicate", "size-type", "size", "hash", "name", "extra"):
                changed = closed_project_draft_data(lifecycle)
                name = "lifecycle-shell-version-save-" + phase + ".json"
                row = next(row for row in changed["files"] if row["path"] == name)
                if change == "missing": changed["files"].remove(row)
                elif change == "duplicate": changed["files"].append(deepcopy(row))
                elif change == "size-type": row["size"] = float(row["size"])
                elif change == "size": row["size"] += 1
                elif change == "hash": row["sha256"] = "0" * 64
                elif change == "name": row["path"] = "lifecycle-shell-metadata-save-" + phase + ".json"
                else: row["qualified"] = True
                with self.subTest(phase=phase, change=change), self.assertRaises((S.D.Refused, ValueError, KeyError)):
                    S.shell_project_draft_observation(changed, lifecycle)


class InstalledSessionReceiptContracts(unittest.TestCase):
    def test_original_four_and_separate_ios_receipts_keep_legacy_id_with_fourteen_normal_methods(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        observed = closed_project_draft_data(lifecycle)
        result = S.shell_project_draft_observation(observed, lifecycle)
        self.assertEqual(result["native"]["methods"], "14-input-assess")
        for name in lifecycle.SHELL_SESSION_CASES:
            receipt = observed["sessionInputs"][name]["native"]
            self.assertEqual(receipt["case"], name)
            self.assertEqual(receipt["methods"], "thirteen-passive-including-supplied-input-assessment")
            self.assertEqual(receipt["profile"], "installed-linux-session-ios-firebase" if name == "session-ios-firebase" else "installed-linux-session-inputs")
            self.assertEqual(len(observed["cases"][name]["maps"]), receipt["behavior"]["assessments"])
            self.assertTrue(all(len(rows) == 6 for rows in observed["cases"][name]["maps"]))
            self.assertEqual(receipt["safety"], {"persistentStorage": False, "storeContacted": False, "signingVerified": False, "releaseReady": False})
            self.assertTrue(all(value is True for value in receipt["originals"].values()))

    def test_ios_case_requires_its_exact_receipt_fixture_counts_and_original_maps(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        case = "session-ios-firebase"
        mutations = (
            lambda doc: doc["sessionInputs"].pop(case), lambda doc: doc["cases"].pop(case),
            lambda doc: doc["cases"][case]["sessionInputs"].update(profile="installed-linux-session-inputs"),
            lambda doc: doc["cases"][case]["sessionInputs"]["behavior"].update(kinds=["android-firebase"]),
            lambda doc: doc["cases"][case]["sessionInputs"]["behavior"].update(assessments=3),
            lambda doc: doc["cases"][case]["sessionInputs"]["behavior"].update(xmlFormatAndBundleIdentityMatched=False),
            lambda doc: doc["cases"][case]["sessionInputs"]["behavior"].update(firebaseMismatchRefused=False),
            lambda doc: doc["cases"][case]["sessionInputs"]["behavior"].update(cancelledReplacementPreservedBytes=False),
            lambda doc: doc["cases"][case]["sessionInputs"]["behavior"].update(discardReopenEmpty=False),
            lambda doc: doc["cases"][case]["maps"].pop(),
            lambda doc: doc["cases"][case]["maps"][0][0].update(inode=True),
            lambda doc: doc["sessionInputs"][case]["fixture"].update(fixture="four-kind-session-v1"),
            lambda doc: doc["sessionInputs"][case]["fixture"].update(beforeCount=9),
            lambda doc: doc["sessionInputs"][case]["fixture"].update(afterCount=9),
            lambda doc: doc["sessionInputs"][case]["fixture"]["after"].update(sha256="0" * 64),
        )
        for mutate in mutations:
            observed = closed_project_draft_data(lifecycle); mutate(observed)
            with self.subTest(mutate=mutate), self.assertRaises((S.D.Refused, ValueError, KeyError)):
                S.shell_project_draft_observation(observed, lifecycle)

    def test_missing_originals_mixed_cases_and_unbound_private_fixture_pins_refuse(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        case = "session-inputs"
        mutations = (
            lambda doc: doc.pop("sessionInputs"), lambda doc: doc["cases"].pop(case),
            lambda doc: doc["cases"].update(unexpected=deepcopy(doc["cases"][case])),
            lambda doc: doc["cases"][case].update(metadataSave=doc["metadataSave"]["native"]),
            lambda doc: doc["cases"]["metadata-save"].update(sessionInputs=doc["cases"][case]["sessionInputs"]),
            lambda doc: doc["sessionInputs"][case].update(native=deepcopy(doc["metadataSave"]["native"])),
            lambda doc: doc["sessionInputs"].pop("session-deadline"),
            lambda doc: doc["cases"][case].update(exitCode=True),
            lambda doc: doc["cases"][case].update(bootstrapReturned=1),
            lambda doc: doc["cases"][case].update(maps=[]),
            lambda doc: doc["cases"][case]["maps"].pop(),
            lambda doc: doc["cases"][case]["maps"].append(deepcopy(doc["cases"][case]["maps"][0])),
            lambda doc: doc["cases"][case]["maps"][0].pop(),
            lambda doc: doc["cases"][case]["maps"][0][0].update(inode=True),
            lambda doc: doc["cases"][case]["maps"][0][0].update(role="not-an-admitted-role"),
            lambda doc: doc["cases"][case]["maps"][0][0].update(privateInput="not-a-map-field"),
            lambda doc: doc["cases"][case]["sessionInputs"].update(methods="twelve-passive"),
            lambda doc: doc["sessionInputs"][case]["native"]["originals"].update(sourceClosed=False),
            lambda doc: doc["sessionInputs"][case].update(native=deepcopy(doc["sessionInputs"]["session-loss"]["native"])),
            lambda doc: doc["cases"]["normal"].update(sessionInputs=doc["cases"][case]["sessionInputs"]),
            lambda doc: doc["sessionInputs"][case]["fixture"].update(projectUnchanged=1),
            lambda doc: doc["sessionInputs"][case]["fixture"].update(noPendingState=False),
            lambda doc: doc["sessionInputs"][case]["fixture"].update(sourcesOutsideProject=False),
            lambda doc: doc["sessionInputs"][case]["fixture"].update(mutations=["changed-leaf-rename"]),
            lambda doc: doc["sessionInputs"]["session-refusals"]["fixture"].update(mutations=[]),
            lambda doc: doc["sessionInputs"][case]["fixture"]["before"].update(size=8193),
            lambda doc: doc["sessionInputs"][case]["fixture"]["after"].update(sha256="0" * 64),
            lambda doc: doc["files"].pop(10), lambda doc: doc["files"].append(deepcopy(doc["files"][10])),
            lambda doc: doc["files"][10].update(size=True),
            lambda doc: doc["files"][11].update(path="lifecycle-shell-session-loss-after.json"),
        )
        for mutate in mutations:
            observed = closed_project_draft_data(lifecycle); mutate(observed)
            with self.subTest(mutate=mutate), self.assertRaises((S.D.Refused, ValueError, KeyError)):
                S.shell_project_draft_observation(observed, lifecycle)


class InstalledAndroidBuildReceiptContracts(unittest.TestCase):
    def test_four_closed_cases_are_an_addition_not_tools_or_offline_authority(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        self.assertIsNone(lifecycle.SHELL_ANDROID_MATERIALS)
        observed = closed_project_draft_data(lifecycle)
        self.assertEqual(S.shell_project_draft_observation(observed, lifecycle), observed["projectDraft"])
        self.assertEqual(set(observed["androidBuild"]), set(lifecycle.SHELL_ANDROID_CASES))
        for name, pair in observed["androidBuild"].items():
            self.assertEqual(pair["native"]["original"]["domain"], "android")
            self.assertEqual(pair["native"]["fixture"], {key: pair["fixture"][key] for key in pair["native"]["fixture"]})
            self.assertTrue(pair["native"]["qualificationOnly"])
            self.assertFalse(pair["native"]["original"]["noChild"])
            self.assertEqual(pair["native"]["coreLifetime"]["commands"], 0 if name == "android-build-refusals" else 2 if name == "android-build" else 1)

    def test_consumer_rejects_every_missing_original_pin_peer_receipt_and_same_copy_forgery(self):
        faults = ("missing-case", "missing-pair", "extra-pair", "extra-result", "maps", "peer-domain", "join", "core-profile",
            "closed-gates", "version", "changed-copy", "fixture-original", "fixture-type", "output-claim",
            "material", "missing-export", "duplicate-export", "wrong-pin", "bool-pin", "same-inventory")
        for name in ("android-build", "android-build-failure", "android-build-cancel", "android-build-refusals"):
            for fault in faults:
                with self.subTest(case=name, fault=fault):
                    lifecycle = S.local("ubuntu_publication_lifecycle")
                    observed = closed_project_draft_data(lifecycle)
                    result, pair = observed["cases"][name], observed["androidBuild"][name]
                    native, fixture = result["androidBuild"], pair["fixture"]
                    if fault == "missing-case": observed["cases"].pop(name)
                    elif fault == "missing-pair": observed["androidBuild"].pop(name)
                    elif fault == "extra-pair": pair["recovered"] = True
                    elif fault == "extra-result": result["toolsOffline"] = deepcopy(native)
                    elif fault == "maps": result["maps"] = [[{"invented": True}]]
                    elif fault == "peer-domain": native["original"]["domain"] = "offline"
                    elif fault == "join": native["original"]["runtimeSettlementJoined"] = False
                    elif fault == "core-profile": native["coreLifetime"]["profileCalls"] = 1
                    elif fault == "closed-gates": native["limits"]["work3000Expiry"] = True
                    elif fault == "version": native["terminal"]["context"]["savedVersion"]["build"] = 8
                    elif fault == "changed-copy": pair["native"]["original"]["watchdogJoined"] = False
                    elif fault == "fixture-original": fixture["originalsAccounted"] = False
                    elif fault == "fixture-type": fixture["beforeCount"] = True
                    elif fault == "output-claim": fixture["noUnexpectedEntries"] = True
                    elif fault == "material": fixture["materials"]["manifestSha256"] = "0" * 64
                    elif fault == "same-inventory": fixture["after"] = deepcopy(fixture["before"])
                    else:
                        exported = next(row for row in observed["files"] if row["path"] == "lifecycle-shell-" + name + "-before.json")
                        if fault == "missing-export": observed["files"].remove(exported)
                        elif fault == "duplicate-export": observed["files"].append(deepcopy(exported))
                        elif fault == "wrong-pin": exported["sha256"] = "0" * 64
                        elif fault == "bool-pin": exported["size"] = True
                    if fault in ("peer-domain", "join", "core-profile", "closed-gates", "version"):
                        pair["native"] = deepcopy(native)  # Two matching copies are NOT original native evidence.
                    with self.assertRaises(ValueError): S.shell_project_draft_observation(observed, lifecycle)

    def test_missing_material_blocks_both_compiler_and_reused_artifact_before_other_inputs(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        with patch.object(S, "local", return_value=lifecycle), patch.object(S, "resumed_preparation") as preparation, \
             patch.object(S.D, "read") as reading, \
             patch.dict(S.os.environ, {"MRK_INSTALLED_SHELL_CASE": "compile",
                 "MRK_ANDROID_TOOL_INSTANCE": "ambient-is-not-admitted", "MRK_ANDROID_TOOL_MANIFEST_SHA256": "a" * 64}, clear=True):
            with self.assertRaisesRegex(ValueError, "material/OS-closure binding is pending"): S.verify_installed_shell_compile()
            with self.assertRaisesRegex(ValueError, "material/OS-closure binding is pending"): S.installed_shell_candidate(Path("/inert"), "a" * 40)
            preparation.assert_not_called(); reading.assert_not_called()



class InstalledToolsOfflineReceiptContracts(unittest.TestCase):
    def test_eight_closed_engineering_cases_preserve_negative_refused_and_no_child_facts(self):
        lifecycle = S.local("ubuntu_publication_lifecycle"); observed = closed_project_draft_data(lifecycle)
        self.assertEqual(S.shell_project_draft_observation(observed, lifecycle), observed["projectDraft"])
        self.assertEqual(len(observed["cases"]), 25)  # Missing scope remains the historical full25, never ordinary21.
        self.assertEqual(set(observed["toolsOffline"]), set(lifecycle.SHELL_TOOLS_OFFLINE_CASES))
        for case, pair in observed["toolsOffline"].items():
            receipt = pair["native"]
            self.assertIs(receipt["qualificationOnly"], True)
            self.assertEqual(observed["cases"][case]["maps"], [])
            self.assertIs(receipt["original"]["noChild"], case == "tools-cancel")
            self.assertEqual(receipt["fixture"]["laterTrace"], "")
            if case in ("tools-observed", "tools-settlement"):
                self.assertEqual(receipt["terminal"]["outcome"], "unavailable")  # Honest refusal is not JDK coverage.
            elif case == "offline-negative":
                self.assertEqual(receipt["terminal"]["outcome"], "complete")
                self.assertEqual(receipt["terminal"]["result"]["summary"]["counts"]["FAIL"], 1)
            elif case == "offline-drift":
                self.assertEqual(receipt["terminal"]["reason"], "saved-config-changed")
                self.assertIs(receipt["original"]["attempted"], True)
                self.assertIsNone(receipt["terminal"]["result"])

    def test_missing_case_changed_finality_forged_fixture_or_original_export_refuses(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        for case in lifecycle.SHELL_TOOLS_OFFLINE_CASES:
            for fault in ("missing-case", "missing-pair", "extra-pair", "missing-receipt", "maps", "wait", "join", "qualification",
                          "same-copy-forgery", "changed-copy", "fixture-count", "later-check", "saved-bytes", "replaced-pin", "missing-export", "duplicate-export"):
                observed = closed_project_draft_data(lifecycle)
                result, pair = observed["cases"][case], observed["toolsOffline"][case]
                if fault == "missing-case": observed["cases"].pop(case)
                elif fault == "missing-pair": observed["toolsOffline"].pop(case)
                elif fault == "extra-pair": pair["recovered"] = True
                elif fault == "missing-receipt": result.pop("toolsOffline")
                elif fault == "maps": result["maps"] = [[{"invented": True}]]
                elif fault == "wait": result["exitCode"] = True
                elif fault == "join": result["toolsOffline"]["original"]["managerJoined"] = False
                elif fault == "qualification": result["toolsOffline"]["qualificationOnly"] = False
                elif fault == "same-copy-forgery":
                    result["toolsOffline"]["original"]["runtimeSettlementJoined"] = False
                    pair["native"] = deepcopy(result["toolsOffline"])
                elif fault == "changed-copy": pair["native"]["original"]["watchdogJoined"] = False
                elif fault == "fixture-count": pair["fixture"]["afterCount"] = 22
                elif fault == "later-check": pair["fixture"]["laterTrace"] = "later\n"
                elif fault == "saved-bytes": pair["fixture"]["savedConfigBefore"]["sha256"] = "0" * 64
                elif fault == "replaced-pin": pair["fixture"]["before"]["sha256"] = "0" * 64
                else:
                    path = "lifecycle-shell-" + case + "-after.json"
                    if fault == "missing-export": observed["files"] = [row for row in observed["files"] if row["path"] != path]
                    else: observed["files"].append(deepcopy(next(row for row in observed["files"] if row["path"] == path)))
                with self.subTest(case=case, fault=fault), self.assertRaises((S.D.Refused, ValueError)):
                    S.shell_project_draft_observation(observed, lifecycle)



def tools_preparation_data():
    """Finite public supplier metadata fiction; never reads the actual host."""
    env = {"GITHUB_REF": S.SHELL_REF, "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
           "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "a" * 40, "RUNNER_TEMP": "/tmp",
           "MRK_SHELL_TOOLS_PREPARATION_EXIT": "0"}
    root = Path("/tmp/mrk-desktop-tools-7-1")
    root_identity = (1, 2, stat.S_IFDIR | 0o700, 1001, 1001)
    nodes = {name: {"kind": "directory", "identity": [1, 100 + index, stat.S_IFDIR | 0o755, 0, 0, 2, 4096, 11, 11]}
             for index, name in enumerate(S.SHELL_TOOLS_DIRECTORIES)}
    nodes.update({name: {"kind": "file", "identity": [1, 200 + index, stat.S_IFREG | 0o755, 0, 0, 1, 64 + index, 11, 11],
                        "path": Path(name).name, "size": 64 + index, "sha256": "d" * 64}
                  for index, name in enumerate(S.SHELL_TOOLS_PROGRAMS)})
    nodes.update({name: {"kind": "symlink", "identity": [1, 300 + index, stat.S_IFLNK | 0o777, 0, 0, 1, len(target), 11, 11], "target": target}
                  for index, (name, target) in enumerate(S.SHELL_TOOLS_LINKS.items())})
    raw = b"".join((name + "\tinstalled\t1.2.3-1\tamd64\t" + ("openjdk-17" if name.startswith("openjdk-") else name)
                    + "\t1.2.3-1\n").encode("ascii") for name in S.SHELL_TOOLS_PACKAGES)
    files = {}
    for phase in ("before", "after"):
        document = {"schema": "fixed-disposable-shell-tools-inputs-v1", "phase": phase, "qualified": False, "sourceSha": env["GITHUB_SHA"],
            "runId": "7", "attempt": "1", "rootIdentity": list(root_identity), "originalStepExit": None if phase == "before" else 0,
            "nodes": deepcopy(nodes), "packageQuery": {"stdout": {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                "stderr": {"size": 0, "sha256": hashlib.sha256(b"").hexdigest()}, "exitCode": 0}}
        files[phase + ".json"] = S.D.canonical(document)
        files[phase + "-packages.tsv"] = raw; files[phase + "-packages.stderr"] = b""; files[phase + "-packages.exit"] = b"0\n"
    return env, root, root_identity, nodes, files


def tools_namespace_source_data():
    """Two finite source pins, not reads of a runner or the checkout."""
    return [{"path": path, "size": 64 + index, "sha256": "e" * 64}
            for index, path in enumerate(S.SHELL_TOOLS_NAMESPACE_SOURCES)]


def tools_namespace_data(disposition="protected"):
    """Successful joined DATA fiction; never constructs or installs anything."""
    env, root, identity, current, files = tools_preparation_data()
    before = S.D.decode(files["before.json"])
    original = deepcopy(before); original["phase"] = "namespace-before"
    if disposition != "protected":
        raw = b"".join(files["before-packages.tsv"].splitlines(keepends=True)[:2])
        stderr = S.SHELL_TOOLS_JDK_MISSING
        query = {"stdout": {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                 "stderr": {"size": len(stderr), "sha256": hashlib.sha256(stderr).hexdigest()}, "exitCode": 1}
        files.update({"before-packages.tsv": raw, "before-packages.stderr": stderr, "before-packages.exit": b"1\n"})
        for document in (original, before):
            document["packageQuery"] = deepcopy(query)
            for name in (S.SHELL_TOOLS_JDK_ROOT, S.SHELL_TOOLS_JDK_ROOT + "/bin", *S.SHELL_TOOLS_PROGRAMS[2:]):
                document["nodes"][name] = {"kind": "parent-unavailable"}
            for name in ("java", "javac"):
                target = "/usr/lib/jvm/temurin-17-jdk-amd64/bin/" + name
                row = document["nodes"]["/etc/alternatives/" + name]
                row["target"] = target; row["identity"][6] = len(target)
        original["nodes"][S.SHELL_TOOLS_NAMESPACE_PARENT] = (
            {"kind": "absent"} if disposition == "absent" else
            {"kind": "refused", "identity": [1, 500, stat.S_IFDIR | 0o777, 0, 0, 7, 4096, 11, 11]})
        if disposition == "absent":
            before["nodes"][S.SHELL_TOOLS_NAMESPACE_PARENT] = {"kind": "absent"}
        else:
            before["nodes"][S.SHELL_TOOLS_JDK_ROOT] = {"kind": "absent"}
    namespace = {"schema": "fixed-disposable-shell-jvm-namespace-before-v1", "qualified": False,
                 "source": str(S.SOURCE), "sourceFiles": tools_namespace_source_data(), "snapshot": original}
    namespace_raw = S.D.canonical(namespace)
    result = {"schema": "fixed-disposable-shell-jvm-namespace-result-v1", "qualified": False,
              "sourceSha": env["GITHUB_SHA"], "runId": env["GITHUB_RUN_ID"], "attempt": env["GITHUB_RUN_ATTEMPT"],
              "root": str(root), "rootIdentity": list(identity), "source": str(S.SOURCE),
              "sourceFiles": tools_namespace_source_data(),
              "namespaceBefore": {"size": len(namespace_raw), "sha256": hashlib.sha256(namespace_raw).hexdigest()},
              "disposition": disposition, "stage": "complete",
              "parents": {path: deepcopy(original["nodes"][path]["identity"]) for path in S.SHELL_TOOLS_NAMESPACE_PARENTS},
              "original": deepcopy(original["nodes"][S.SHELL_TOOLS_NAMESPACE_PARENT].get("identity")),
              "preservation": None, "preserved": None, "fresh": None, "query": None,
              "actions": {key: disposition == "preserve-create" for key in ("preservationCreated", "renameReturned", "freshCreated")},
              "originalFdsClosed": True, "completed": True, "failure": None}
    if disposition == "preserve-create":
        result["preservation"] = {"path": "/usr/lib/mrk-desktop-jvm-original-7-1",
                                  "identity": [1, 501, stat.S_IFDIR | 0o700, 0, 0, 3, 4096, 12, 12]}
        result["preserved"] = deepcopy(result["original"]); result["preserved"][-1] = 12
        result["fresh"] = deepcopy(before["nodes"][S.SHELL_TOOLS_NAMESPACE_PARENT]["identity"])
        result["query"] = {"stdout": "", "stderr": S.SHELL_TOOLS_JDK_MISSING.decode("ascii"), "exitCode": 1,
                           "originalReturned": True, "stdoutEof": True, "stderrEof": True, "streamsClosed": True, "stopSent": False}
    files.update({"before.json": S.D.canonical(before), "namespace-before.json": namespace_raw,
                  "namespace.stdout": S.D.canonical(result), "namespace.stderr": b"", "namespace.exit": b"0\n"})
    return env, root, identity, current, files


def tools_namespace_read(files):
    """Bounded in-memory evidence: no fallback to real source/host files."""
    def read(path, limit):
        if path.name not in files:
            raise FileNotFoundError(path.name)
        raw = files[path.name]
        S.D.need(type(raw) is bytes and len(raw) <= limit, "Fixture read exceeds the production member bound")
        return raw
    return read


class InstalledToolsPreparationContracts(unittest.TestCase):
    def test_metadata_tools_root_requires_the_complete_original_source_route(self):
        env, root, identity, _, _ = tools_preparation_data()
        observer = S.local("observe_hosted_python")
        env.update(GITHUB_REF=S.SHELL_METADATA_REF, MRK_INSTALLED_SHELL_CASE="host-metadata-only",
                   GITHUB_JOB="compile", GITHUB_EVENT_NAME="push", RUNNER_OS="Linux", RUNNER_ARCH="X64",
                   GITHUB_REPOSITORY="Apdelrahman1911/mobile-release-kit", GITHUB_WORKFLOW_SHA="a" * 40,
                   MRK_PUSH_EVENT_AFTER="a" * 40, ImageOS="ubuntu24", ImageVersion="20260920.314.1",
                   GITHUB_WORKFLOW_REF="Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-ubuntu-publication.yml@" + S.SHELL_METADATA_REF)
        for change in ({}, {"GITHUB_RUN_ATTEMPT": "2"}, {"MRK_INSTALLED_SHELL_CASE": "compile"},
                       {"GITHUB_JOB": "observe"}, {"GITHUB_WORKFLOW_SHA": "b" * 40},
                       {"GITHUB_EVENT_NAME": "pull_request"}, {"GITHUB_REPOSITORY": "different/repository"}):
            with self.subTest(change=change), patch.dict(S.os.environ, {**env, **change}, clear=True), \
                 patch.object(S.os, "geteuid", return_value=1001), patch.object(S.C, "conventional_host") as host, \
                 patch.object(S, "directory_identity", return_value=identity) as directory, \
                 patch.object(S, "local", return_value=observer):
                if not change:
                    self.assertEqual(S.shell_tools_input_root(), root)
                    host.assert_called_once_with(S.D); directory.assert_called_once_with(root)
                else:
                    # The shared Python observer has its own typed refusal.
                    with self.assertRaises((S.D.Refused, observer.Refused)):
                        S.shell_tools_input_root()
                    host.assert_not_called(); directory.assert_not_called()

    def test_only_nonroot_fixed_hosted_branch_and_original_fresh_root_are_addressed(self):
        env, root, identity, _, _ = tools_preparation_data()
        for key, replacement in ((None, None), ("GITHUB_REF", S.INSTALLED_REF), ("GITHUB_ACTIONS", "false"),
                                 ("RUNNER_ENVIRONMENT", "self-hosted"), ("GITHUB_RUN_ID", "01"), ("GITHUB_RUN_ATTEMPT", "0"),
                                 ("RUNNER_TEMP", "relative"), ("RUNNER_TEMP", "/tmp/../other")):
            altered = dict(env)
            if key is not None: altered[key] = replacement
            with self.subTest(key=key), patch.dict(S.os.environ, altered, clear=True), patch.object(S.os, "geteuid", return_value=1001), \
                 patch.object(S.C, "conventional_host") as host, patch.object(S, "directory_identity", return_value=identity) as directory:
                if key is None:
                    self.assertEqual(S.shell_tools_input_root(), root); directory.assert_called_once_with(root); host.assert_called_once_with(S.D)
                else:
                    with self.assertRaises(S.D.Refused): S.shell_tools_input_root()
        with patch.dict(S.os.environ, env, clear=True), patch.object(S.os, "geteuid", return_value=0), \
             patch.object(S.C, "conventional_host") as host, patch.object(S, "directory_identity") as directory:
            with self.assertRaises(S.D.Refused): S.shell_tools_input_root()
            host.assert_not_called(); directory.assert_not_called()

    def test_package_query_is_bounded_original_printable_installed_amd64_data(self):
        _, _, _, _, files = tools_preparation_data(); raw = files["before-packages.tsv"]
        self.assertEqual(set(S.shell_tools_package_data(raw)), set(S.SHELL_TOOLS_PACKAGES))
        without_jdk = b"".join(raw.splitlines(keepends=True)[:2])
        self.assertEqual(set(S.shell_tools_package_data(without_jdk)), {"git", "python3.12"})
        for bad in (raw[:-1], b"", b"x" * ((64 << 10) + 1), raw + raw, bytearray(raw), raw.replace(b"amd64", b"arm64", 1),
                    raw.replace(b"installed", b"unpacked", 1), raw.replace(b"git\t", b"other\t", 1),
                    raw.replace(b"\n", b"\r\n"), raw.replace(b"1.2.3-1", b"", 1), raw.replace(b"1.2.3-1", b"x\x00y", 1),
                    b"".join(raw.splitlines(keepends=True)[1:])):
            with self.subTest(raw=bad[:30]), self.assertRaises((S.D.Refused, ValueError)): S.shell_tools_package_data(bad)

    def test_fixed_public_nodes_are_nofollow_parent_guarded_and_stable(self):
        _, _, _, originals, _ = tools_preparation_data()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        for fault in (None, "ancestor-alias", "hardlink", "drift", "appeared"):
            nodes, calls = deepcopy(originals), {}
            if fault == "ancestor-alias": nodes["/usr/lib/jvm"]["identity"][2] = stat.S_IFLNK | 0o777
            if fault == "hardlink": nodes["/usr/bin/git"]["identity"][5] = 2
            def metadata(path):
                name = str(path); calls[name] = calls.get(name, 0) + 1
                if fault == "appeared" and name == S.SHELL_TOOLS_PROGRAMS[2] and calls[name] == 1: raise FileNotFoundError(name)
                values = list(nodes[name]["identity"])
                if fault == "drift" and name == "/usr/bin/git" and calls[name] > 1: values[1] += 1
                return SimpleNamespace(**dict(zip(fields, values)))
            def record(path, limit):
                self.assertEqual(limit, 16 << 20)
                return {key: nodes[str(path)][key] for key in ("path", "size", "sha256")}
            with self.subTest(fault=fault), patch.object(Path, "lstat", metadata), patch.object(S.D, "file_record", side_effect=record) as reading, \
                 patch.object(S.os, "readlink", side_effect=lambda path: nodes[str(path)]["target"]) as linking:
                if fault in ("drift", "appeared"):
                    with self.assertRaises(S.D.Refused): S.shell_tools_input_nodes()
                else:
                    result = S.shell_tools_input_nodes()
                    if fault is None:
                        self.assertEqual(result, originals)
                        self.assertEqual([str(call.args[0]) for call in reading.call_args_list], list(S.SHELL_TOOLS_PROGRAMS))
                    elif fault == "ancestor-alias":
                        self.assertEqual(result["/usr/lib/jvm"]["kind"], "refused")
                        self.assertEqual(result[S.SHELL_TOOLS_PROGRAMS[2]]["kind"], "parent-unavailable")
                        self.assertNotIn(S.SHELL_TOOLS_PROGRAMS[2], calls)
                    else:
                        self.assertEqual(result["/usr/bin/git"]["kind"], "refused")
                        self.assertNotIn("/usr/bin/git", [str(call.args[0]) for call in reading.call_args_list])
                self.assertTrue(all(str(call.args[0]) in S.SHELL_TOOLS_LINKS for call in linking.call_args_list))

    def test_actual_snapshot_is_retained_before_failed_pair_or_original_status_assertions(self):
        for phase, fault in (("before", None), ("before", "absent"), ("before", "query"), ("before", "refused"),
                             ("after", None), ("after", "step"), ("after", "pair"), ("after", "git")):
            env, root, identity, nodes, files = tools_namespace_data()
            if fault == "absent":
                for name in S.SHELL_TOOLS_PROGRAMS[2:]: nodes[name] = {"kind": "absent"}
            if fault == "query": files[phase + "-packages.tsv"] = b"unexpected\n"
            if fault == "refused": nodes["/usr/bin/git"] = {"kind": "refused", "identity": nodes["/usr/bin/git"]["identity"]}
            if fault == "step": env["MRK_SHELL_TOOLS_PREPARATION_EXIT"] = "7"
            if fault == "pair": nodes[S.SHELL_TOOLS_PROGRAMS[2]] = {"kind": "absent"}
            if fault == "git": nodes["/usr/bin/git"]["sha256"] = "0" * 64
            with self.subTest(phase=phase, fault=fault), patch.dict(S.os.environ, env, clear=True), \
                 patch.object(S, "shell_tools_input_root", return_value=root), patch.object(S, "directory_identity", return_value=identity), \
                 patch.object(S, "shell_tools_input_nodes", return_value=nodes), patch.object(S.D, "read", side_effect=lambda path, limit: files[path.name]), \
                 patch.object(S, "_shell_tools_namespace_sources", return_value=tools_namespace_source_data()), \
                 patch.object(S.D, "write") as writing, patch.object(S.sys, "stdout", new_callable=io.StringIO) as stdout:
                if fault in (None, "absent"):
                    self.assertIsNone(S.shell_tools_input_snapshot(phase))
                    self.assertEqual(stdout.getvalue(), ("absent\n" if fault == "absent" else "present\n") if phase == "before" else "")
                else:
                    with self.assertRaises(S.D.Refused): S.shell_tools_input_snapshot(phase)
                writing.assert_called_once()
                self.assertEqual(writing.call_args.args[0], root / (phase + ".json"))
                saved = S.D.decode(writing.call_args.args[1]); self.assertEqual(saved["nodes"], nodes)
                self.assertIs(saved["qualified"], False)
                self.assertEqual(saved["originalStepExit"], None if phase == "before" else int(env["MRK_SHELL_TOOLS_PREPARATION_EXIT"]))

    def test_observation_rebinds_original_packages_aliases_bytes_and_only_stable_parent_identity(self):
        for fault in (None, "directory-time", "git", "python", "jdk", "alias", "ancestor", "before-git", "step", "query", "qualified", "boolean"):
            env, root, identity, nodes, files = tools_namespace_data()
            if fault == "directory-time":
                for path in S.SHELL_TOOLS_DIRECTORIES: nodes[path]["identity"][6:] = [8192, 22, 22]
            if fault in ("git", "python", "jdk"):
                nodes[S.SHELL_TOOLS_PROGRAMS[("git", "python", "jdk").index(fault)]]["sha256"] = "0" * 64
            if fault == "alias": nodes["/usr/bin/java"]["target"] = "/unreviewed/java"
            if fault == "ancestor": nodes["/usr"]["identity"][1] += 1000
            if fault in ("before-git", "step", "query", "qualified", "boolean"):
                phase = "before" if fault == "before-git" else "after"
                document = S.D.decode(files[phase + ".json"])
                if fault == "before-git": document["nodes"]["/usr/bin/git"]["sha256"] = "0" * 64
                elif fault == "step": document["originalStepExit"] = 1
                elif fault == "query": document["packageQuery"]["exitCode"] = 1; files[phase + "-packages.exit"] = b"1\n"
                elif fault == "qualified": document["qualified"] = True
                else: document["nodes"]["/usr/bin/git"]["identity"][5] = True
                files[phase + ".json"] = S.D.canonical(document)
            with self.subTest(fault=fault), patch.dict(S.os.environ, env, clear=True), patch.object(S, "shell_tools_input_root", return_value=root), \
                 patch.object(S, "directory_identity", return_value=identity), patch.object(S, "shell_tools_input_nodes", return_value=nodes), \
                 patch.object(S, "_shell_tools_namespace_sources", return_value=tools_namespace_source_data()), \
                 patch.object(S.D, "read", side_effect=lambda path, limit: files[path.name]):
                if fault in (None, "directory-time"):
                    observed = S.shell_tools_inputs_for_observation(); self.assertIs(observed["qualified"], False)
                    self.assertEqual(len(observed["preparationFiles"]), 12)
                    self.assertEqual(set(observed["packages"]), set(S.SHELL_TOOLS_PACKAGES))
                    self.assertEqual(observed["nodes"]["/usr"]["identity"], nodes["/usr"]["identity"][:5])
                    self.assertEqual(observed["nodes"]["/usr/bin/git"], nodes["/usr/bin/git"])
                else:
                    with self.assertRaises(S.D.Refused): S.shell_tools_inputs_for_observation()

    def test_typed_snapshots_reject_extra_fields_wrong_root_noncanonical_and_bad_pins(self):
        env, root, identity, _, files = tools_preparation_data(); original = S.D.decode(files["before.json"])
        for mutate in (lambda d: d.update(extra=True), lambda d: d.update(phase="after"), lambda d: d.update(sourceSha="b" * 40),
                       lambda d: d["rootIdentity"].__setitem__(0, True), lambda d: d.update(originalStepExit=0),
                       lambda d: d["nodes"].pop("/usr/bin/git"), lambda d: d["nodes"]["/usr/bin/git"].update(size=True),
                       lambda d: d["nodes"]["/usr/bin/git"].update(sha256="z" * 64),
                       lambda d: d["packageQuery"]["stdout"].update(size=True), lambda d: d["packageQuery"].update(exitCode=True)):
            document = deepcopy(original); mutate(document)
            with self.subTest(mutate=mutate), patch.dict(S.os.environ, env, clear=True), patch.object(S, "directory_identity", return_value=identity), \
                 self.assertRaises(S.D.Refused): S._shell_tools_input_document(S.D.canonical(document), "before", root)
        with patch.dict(S.os.environ, env, clear=True), patch.object(S, "directory_identity", return_value=identity):
            for raw in (files["before.json"] + b" ", files["before.json"][:-1], b"x" * ((64 << 10) + 1)):
                with self.assertRaises(S.D.Refused): S._shell_tools_input_document(raw, "before", root)



class InstalledToolsNamespaceContracts(unittest.TestCase):
    def _result(self, fixture, *, strict_before=True, sources=None):
        env, root, identity, nodes, files = fixture
        before = S.D.decode(files["before.json"]) if strict_before else None
        with patch.dict(S.os.environ, env, clear=True), patch.object(S, "directory_identity", return_value=identity), \
             patch.object(S, "shell_tools_input_nodes", return_value=nodes), \
             patch.object(S, "_shell_tools_namespace_sources", return_value=tools_namespace_source_data() if sources is None else sources), \
             patch.object(S.D, "read", side_effect=tools_namespace_read(files)):
            return S._shell_tools_namespace_result(root, before=before)

    def test_only_genuine_absent_pair_and_exact_0777_parent_select_new_construction(self):
        self.assertEqual(S.SHELL_TOOLS_JDK_MISSING,
                         b"dpkg-query: no packages found matching openjdk-17-jdk-headless\n"
                         b"dpkg-query: no packages found matching openjdk-17-jre-headless\n")
        for disposition in ("protected", "absent", "preserve-create"):
            env, root, identity, _, files = tools_namespace_data(disposition)
            raw = files["namespace-before.json"]; original = S.D.decode(raw)
            query = tuple(files["before-packages" + suffix] for suffix in (".tsv", ".stderr", ".exit"))
            with self.subTest(disposition=disposition), patch.dict(S.os.environ, env, clear=True), \
                 patch.object(S, "directory_identity", return_value=identity):
                observed, selected = S.shell_tools_namespace_disposition(raw, root, query)
                self.assertEqual(selected, disposition); self.assertEqual(observed, original)
                self.assertIs(observed["qualified"], False)
                if disposition == "preserve-create":
                    self.assertEqual(observed["snapshot"]["nodes"]["/usr/lib/jvm"]["kind"], "refused")
                    self.assertEqual(observed["snapshot"]["nodes"][S.SHELL_TOOLS_JDK_ROOT], {"kind": "parent-unavailable"})
                    self.assertNotEqual(observed["snapshot"]["nodes"], S.D.decode(files["before.json"])["nodes"])
            self.assertEqual(files["namespace-before.json"], raw)

    def test_partial_installed_unknown_or_ambiguous_package_state_cannot_relocate(self):
        env, root, identity, _, files = tools_namespace_data("preserve-create")
        original = S.D.decode(files["namespace-before.json"])
        absent, installed, missing = files["before-packages.tsv"], files["after-packages.tsv"], S.SHELL_TOOLS_JDK_MISSING
        cases = (
            (installed, b"", b"0\n"),  # An installed pair below an unsafe namespace is not a repair invitation.
            (b"".join(installed.splitlines(keepends=True)[:3]), missing, b"1\n"),
            (absent, b"", b"1\n"), (absent, missing, b"0\n"), (absent, missing, b"2\n"),
            (absent, missing, b"01\n"), (absent, missing, b"1"), (absent, missing, b"256\n"),
            (absent, b"".join(missing.splitlines(keepends=True)[::-1]), b"1\n"),
            (absent, missing + b"another failure\n", b"1\n"), (absent, missing.splitlines(keepends=True)[0], b"1\n"),
            (absent.replace(b"installed", b"unpacked", 1), missing, b"1\n"),
            (absent.replace(b"amd64", b"arm64", 1), missing, b"1\n"),
            (absent.replace(b"git\t", b"other\t", 1), missing, b"1\n"),
            (absent + absent, missing, b"1\n"), (absent[:-1], missing, b"1\n"),
            (b"".join(absent.splitlines(keepends=True)[1:]), missing, b"1\n"),
        )
        for raw, stderr, status in cases:
            document = deepcopy(original)
            document["snapshot"]["packageQuery"] = {
                "stdout": {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                "stderr": {"size": len(stderr), "sha256": hashlib.sha256(stderr).hexdigest()}, "exitCode": int(status)}
            with self.subTest(query=(raw[:20], stderr[:20], status)), patch.dict(S.os.environ, env, clear=True), \
                 patch.object(S, "directory_identity", return_value=identity), self.assertRaises(S.D.Refused):
                S.shell_tools_namespace_disposition(S.D.canonical(document), root, (raw, stderr, status))
        with patch.dict(S.os.environ, env, clear=True), patch.object(S, "directory_identity", return_value=identity):
            with self.assertRaises(S.D.Refused):
                S.shell_tools_namespace_disposition(files["namespace-before.json"], root, [absent, missing, b"1\n"])
            with self.assertRaises(S.D.Refused):
                S.shell_tools_namespace_disposition(files["namespace-before.json"], root, (absent, missing, bytearray(b"1\n")))

    def test_wrong_owner_kind_mode_alias_or_unrelated_refusal_never_selects_repair(self):
        env, root, identity, _, files = tools_namespace_data("preserve-create")
        original = S.D.decode(files["namespace-before.json"])
        query = tuple(files["before-packages" + suffix] for suffix in (".tsv", ".stderr", ".exit"))
        mutations = [
            lambda n: n["/usr/lib/jvm"]["identity"].__setitem__(3, 1001),
            lambda n: n["/usr/lib/jvm"]["identity"].__setitem__(4, 1001),
            lambda n: n["/usr/lib/jvm"]["identity"].__setitem__(2, stat.S_IFLNK | 0o777),
            lambda n: n["/usr/lib/jvm"]["identity"].__setitem__(2, stat.S_IFIFO | 0o777),
            lambda n: n["/usr/lib/jvm"]["identity"].__setitem__(2, stat.S_IFDIR | 0o775),
            lambda n: n["/usr/lib/jvm"]["identity"].__setitem__(2, stat.S_IFDIR | 0o757),
            lambda n: n["/usr/lib/jvm"]["identity"].__setitem__(2, stat.S_IFDIR | 0o1777),
            lambda n: n["/usr/lib/jvm"].update(kind="directory"),
            lambda n: n["/usr/lib/jvm"]["identity"].__setitem__(5, True),
            lambda n: n.__setitem__(S.SHELL_TOOLS_JDK_ROOT, {"kind": "absent"}),
        ]
        for path in (*S.SHELL_TOOLS_NAMESPACE_PARENTS, *S.SHELL_TOOLS_PROGRAMS[:2], *S.SHELL_TOOLS_LINKS):
            mutations.append(lambda n, path=path: n.__setitem__(path, {"kind": "refused", "identity": n[path]["identity"]}))
        for mutate in mutations:
            document = deepcopy(original); mutate(document["snapshot"]["nodes"])
            with self.subTest(mutate=mutate), patch.dict(S.os.environ, env, clear=True), \
                 patch.object(S, "directory_identity", return_value=identity), self.assertRaises(S.D.Refused):
                S.shell_tools_namespace_disposition(S.D.canonical(document), root, query)

    def test_namespace_envelope_is_closed_canonical_typed_source_and_original_query_data(self):
        env, root, identity, _, files = tools_namespace_data("preserve-create")
        original = S.D.decode(files["namespace-before.json"])
        query = tuple(files["before-packages" + suffix] for suffix in (".tsv", ".stderr", ".exit"))
        mutations = (
            lambda d: d.update(extra=True), lambda d: d.update(schema="other"), lambda d: d.update(qualified=0),
            lambda d: d.update(source="/other"), lambda d: d["sourceFiles"].pop(),
            lambda d: d["sourceFiles"].reverse(), lambda d: d["sourceFiles"][0].update(size=True),
            lambda d: d["sourceFiles"][0].update(size=65537), lambda d: d["sourceFiles"][0].update(sha256="z" * 64),
            lambda d: d["sourceFiles"][0].update(extra=True), lambda d: d["snapshot"].update(originalStepExit=0),
            lambda d: d["snapshot"].update(phase="before"), lambda d: d["snapshot"].update(sourceSha="b" * 40),
            lambda d: d["snapshot"].update(runId="8"), lambda d: d["snapshot"].update(attempt="2"),
            lambda d: d["snapshot"]["rootIdentity"].__setitem__(0, True),
            lambda d: d["snapshot"]["packageQuery"]["stdout"].update(sha256="0" * 64),
            lambda d: d["snapshot"]["packageQuery"]["stderr"].update(size=True),
            lambda d: d["snapshot"]["packageQuery"].update(exitCode=True),
        )
        for mutate in mutations:
            document = deepcopy(original); mutate(document)
            with self.subTest(mutate=mutate), patch.dict(S.os.environ, env, clear=True), \
                 patch.object(S, "directory_identity", return_value=identity), self.assertRaises(S.D.Refused):
                S.shell_tools_namespace_disposition(S.D.canonical(document), root, query)
        for raw in (files["namespace-before.json"] + b" ", files["namespace-before.json"][:-1],
                    files["namespace-before.json"][:-2] + b',"qualified":false}\n', b"[]" + b"\n", b"x" * 65537):
            with self.subTest(raw=raw[:30]), patch.dict(S.os.environ, env, clear=True), \
                 patch.object(S, "directory_identity", return_value=identity), self.assertRaises(S.D.Refused):
                S.shell_tools_namespace_disposition(raw, root, query)

    def test_original_namespace_snapshot_is_retained_before_disposition_refusal(self):
        for fault in (None, "wrong-mode", "unrelated", "ambiguous-query", "root-drift"):
            env, root, identity, _, files = tools_namespace_data("preserve-create")
            nodes = S.D.decode(files["namespace-before.json"])["snapshot"]["nodes"]
            if fault == "wrong-mode": nodes["/usr/lib/jvm"]["identity"][2] = stat.S_IFDIR | 0o775
            if fault == "unrelated": nodes["/usr/bin/git"] = {"kind": "refused", "identity": nodes["/usr/bin/git"]["identity"]}
            if fault == "ambiguous-query": files["before-packages.stderr"] += b"unexpected\n"
            root_identity = Mock(return_value=identity)
            if fault == "root-drift": root_identity.side_effect = [identity, (1, 3, stat.S_IFDIR | 0o700, 1001, 1001)]
            with self.subTest(fault=fault), patch.dict(S.os.environ, env, clear=True), \
                 patch.object(S, "shell_tools_input_root", return_value=root), patch.object(S, "directory_identity", root_identity), \
                 patch.object(S, "shell_tools_input_nodes", return_value=nodes), \
                 patch.object(S, "_shell_tools_namespace_sources", return_value=tools_namespace_source_data()), \
                 patch.object(S.D, "read", side_effect=tools_namespace_read(files)), patch.object(S.D, "write") as writing, \
                 patch.object(S.sys, "stdout", new_callable=io.StringIO) as stdout:
                if fault is None:
                    self.assertIsNone(S.shell_tools_namespace_snapshot())
                    self.assertEqual(stdout.getvalue(), "preserve-create\n")
                else:
                    with self.assertRaises(S.D.Refused): S.shell_tools_namespace_snapshot()
                    self.assertEqual(stdout.getvalue(), "")
                writing.assert_called_once()
                self.assertEqual(writing.call_args.args[0], root / "namespace-before.json")
                saved = S.D.decode(writing.call_args.args[1])
                self.assertEqual(saved["snapshot"]["nodes"], nodes)
                self.assertEqual(saved["snapshot"]["phase"], "namespace-before")
                self.assertIsNone(saved["snapshot"]["originalStepExit"])
                self.assertIs(saved["qualified"], False); self.assertIs(saved["snapshot"]["qualified"], False)

    def test_clean_results_bind_all_three_dispositions_and_all_four_original_members(self):
        for disposition in ("protected", "absent", "preserve-create"):
            fixture = tools_namespace_data(disposition); files = fixture[-1]
            expected = {name: {"size": len(files[name]), "sha256": hashlib.sha256(files[name]).hexdigest()}
                        for name in S.SHELL_TOOLS_NAMESPACE_FILES}
            with self.subTest(disposition=disposition):
                self.assertEqual(self._result(fixture), expected)
                # The pre-APT check addresses actual current nodes; the later join uses strict before.
                env, root, identity, _, _ = fixture
                current = S.D.decode(files["before.json"])["nodes"]
                self.assertEqual(self._result((env, root, identity, current, files), strict_before=False), expected)
                self.assertEqual(set(expected), {"namespace-before.json", "namespace.stdout", "namespace.stderr", "namespace.exit"})

    def test_result_requires_original_finality_typed_actions_and_exact_source_run_root_pins(self):
        mutations = (
            lambda d: d.update(completed=False), lambda d: d.update(originalFdsClosed=False),
            lambda d: d.update(stage="fresh-mode"), lambda d: d.update(failure="original-fd-close"),
            lambda d: d.update(qualified=True), lambda d: d.update(extra=True), lambda d: d.pop("query"),
            lambda d: d.update(schema="other"), lambda d: d.update(disposition="protected"),
            lambda d: d.update(sourceSha="b" * 40), lambda d: d.update(runId="8"), lambda d: d.update(attempt="2"),
            lambda d: d.update(root="/tmp/other"), lambda d: d["rootIdentity"].__setitem__(0, True),
            lambda d: d.update(source="/other"), lambda d: d["sourceFiles"][0].update(size=True),
            lambda d: d["sourceFiles"][0].update(sha256="0" * 64), lambda d: d["sourceFiles"].reverse(),
            lambda d: d["namespaceBefore"].update(size=True), lambda d: d["namespaceBefore"].update(sha256="0" * 64),
            lambda d: d["parents"].pop("/usr"), lambda d: d["parents"]["/usr"].__setitem__(1, 999),
            lambda d: d["parents"]["/usr"].__setitem__(0, True), lambda d: d["parents"]["/usr"].pop(),
            lambda d: d["actions"].update(renameReturned=False), lambda d: d["actions"].update(freshCreated=1),
            lambda d: d["actions"].update(preservationCreated=False), lambda d: d["actions"].update(extra=True),
        )
        for mutate in mutations:
            fixture = tools_namespace_data("preserve-create"); files = fixture[-1]
            result = S.D.decode(files["namespace.stdout"]); mutate(result); files["namespace.stdout"] = S.D.canonical(result)
            with self.subTest(mutate=mutate), self.assertRaises(S.D.Refused): self._result(fixture)

    def test_result_refuses_same_inode_wrong_preservation_or_unprotected_fresh_namespace(self):
        mutations = (
            lambda d: d["original"].__setitem__(1, 999),
            lambda d: d["preserved"].__setitem__(1, 999),
            lambda d: d["preserved"].__setitem__(2, stat.S_IFDIR | 0o755),
            lambda d: d["preserved"].__setitem__(3, 1001),
            lambda d: d["fresh"].__setitem__(1, d["original"][1]),
            lambda d: d["fresh"].__setitem__(1, d["preservation"]["identity"][1]),
            lambda d: d["fresh"].__setitem__(0, 2),
            lambda d: d["fresh"].__setitem__(2, stat.S_IFDIR | 0o777),
            lambda d: d["fresh"].__setitem__(2, stat.S_IFLNK | 0o755),
            lambda d: d["fresh"].__setitem__(3, 1001),
            lambda d: d["fresh"].__setitem__(4, True),
            lambda d: d["preservation"].update(path="/usr/lib/mrk-desktop-jvm-original-7-2"),
            lambda d: d["preservation"].update(extra=True),
            lambda d: d["preservation"]["identity"].__setitem__(1, d["original"][1]),
            lambda d: d["preservation"]["identity"].__setitem__(2, stat.S_IFDIR | 0o755),
            lambda d: d["preservation"]["identity"].__setitem__(3, 1001),
            lambda d: d["preservation"]["identity"].__setitem__(0, 2),
        )
        for mutate in mutations:
            fixture = tools_namespace_data("preserve-create"); files = fixture[-1]
            result = S.D.decode(files["namespace.stdout"]); mutate(result); files["namespace.stdout"] = S.D.canonical(result)
            with self.subTest(mutate=mutate), self.assertRaises(S.D.Refused): self._result(fixture)

    def test_original_root_query_requires_both_eofs_original_wait_closes_and_no_stop(self):
        mutations = (
            lambda q: q.update(originalReturned=False), lambda q: q.update(originalReturned=1),
            lambda q: q.update(stdoutEof=False), lambda q: q.update(stderrEof=False),
            lambda q: q.update(streamsClosed=False), lambda q: q.update(streamsClosed=1),
            lambda q: q.update(stopSent=True), lambda q: q.update(exitCode=True), lambda q: q.update(exitCode=0),
            lambda q: q.update(stdout="installed\n"), lambda q: q.update(stderr=""),
            lambda q: q.update(stderr=q["stderr"] + "extra\n"), lambda q: q.update(extra=True),
        )
        for mutate in mutations:
            fixture = tools_namespace_data("preserve-create"); files = fixture[-1]
            result = S.D.decode(files["namespace.stdout"]); mutate(result["query"]); files["namespace.stdout"] = S.D.canonical(result)
            with self.subTest(mutate=mutate), self.assertRaises(S.D.Refused): self._result(fixture)

    def test_noop_results_cannot_claim_query_relocation_creation_or_changed_original(self):
        for disposition in ("protected", "absent"):
            for fault in ("query", "preservation", "preserved", "fresh", "original", "actions"):
                fixture = tools_namespace_data(disposition); files = fixture[-1]
                result = S.D.decode(files["namespace.stdout"])
                if fault == "actions": result["actions"]["renameReturned"] = True
                elif fault == "original": result["original"] = [1, 999, stat.S_IFDIR | 0o755, 0, 0, 2, 4096, 11, 11]
                else: result[fault] = {}
                files["namespace.stdout"] = S.D.canonical(result)
                with self.subTest(disposition=disposition, fault=fault), self.assertRaises(S.D.Refused):
                    self._result(fixture)

    def test_missing_partial_oversized_or_noncanonical_new_member_is_failure(self):
        self.assertEqual(S.SHELL_TOOLS_NAMESPACE_FILES,
                         {"namespace-before.json": 65536, "namespace.stdout": 16384, "namespace.stderr": 4096, "namespace.exit": 4})
        for name, limit in S.SHELL_TOOLS_NAMESPACE_FILES.items():
            for fault in ("missing", "oversized"):
                fixture = tools_namespace_data("preserve-create"); files = fixture[-1]
                if fault == "missing": files.pop(name)
                else: files[name] = b"x" * (limit + 1)
                with self.subTest(name=name, fault=fault), self.assertRaises((S.D.Refused, FileNotFoundError)):
                    self._result(fixture)
        for name, raw in (("namespace.exit", b"1\n"), ("namespace.exit", b"0"), ("namespace.exit", b"00\n"),
                          ("namespace.stderr", b"warning\n"), ("namespace.stdout", b"{}\n"),
                          ("namespace.stdout", b""), ("namespace-before.json", b"{}\n")):
            fixture = tools_namespace_data("preserve-create"); fixture[-1][name] = raw
            with self.subTest(name=name, raw=raw), self.assertRaises(S.D.Refused): self._result(fixture)
        for name in ("namespace-before.json", "namespace.stdout"):
            for fault in ("trailing", "no-newline", "duplicate"):
                fixture = tools_namespace_data("preserve-create"); files = fixture[-1]; raw = files[name]
                files[name] = raw + b" " if fault == "trailing" else raw[:-1] if fault == "no-newline" else raw[:-2] + b',"qualified":false}\n'
                with self.subTest(name=name, fault=fault), self.assertRaises(S.D.Refused): self._result(fixture)

    def test_raw_snapshot_source_pins_and_strict_before_namespace_must_all_correspond(self):
        for fault in ("old-pin", "current-source", "consistent-forged-source", "before-inode", "before-mode",
                      "before-package", "before-git", "before-python", "before-alias", "before-parent"):
            fixture = tools_namespace_data("preserve-create"); files = fixture[-1]
            if fault in ("old-pin", "consistent-forged-source"):
                original = S.D.decode(files["namespace-before.json"])
                if fault == "old-pin": original["snapshot"]["nodes"]["/usr/lib/jvm"]["identity"][-1] += 1
                else: original["sourceFiles"][0]["sha256"] = "0" * 64
                files["namespace-before.json"] = S.D.canonical(original)
                if fault == "consistent-forged-source":
                    result = S.D.decode(files["namespace.stdout"]); result["sourceFiles"] = deepcopy(original["sourceFiles"])
                    raw = files["namespace-before.json"]
                    result["namespaceBefore"] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                    files["namespace.stdout"] = S.D.canonical(result)
            elif fault != "current-source":
                before = S.D.decode(files["before.json"]); nodes = before["nodes"]
                if fault == "before-inode": nodes["/usr/lib/jvm"]["identity"][1] += 1
                elif fault == "before-mode": nodes["/usr/lib/jvm"]["identity"][2] = stat.S_IFDIR | 0o777
                elif fault == "before-package": before["packageQuery"]["exitCode"] = 0
                elif fault == "before-git": nodes["/usr/bin/git"]["sha256"] = "0" * 64
                elif fault == "before-python": nodes["/usr/bin/python3.12"]["sha256"] = "0" * 64
                elif fault == "before-alias": nodes["/etc/alternatives/java"]["target"] = "/other"
                else: nodes["/usr"]["identity"][1] += 1
                files["before.json"] = S.D.canonical(before)
            sources = tools_namespace_source_data()
            if fault == "current-source": sources[0]["sha256"] = "0" * 64
            with self.subTest(fault=fault), self.assertRaises(S.D.Refused): self._result(fixture, sources=sources)

    def test_native_rebinding_keeps_all_twelve_pins_and_rejects_current_namespace_replacement(self):
        for disposition in ("protected", "absent", "preserve-create"):
            for fault in (None, "directory-time", "namespace-inode", "namespace-mode", "namespace-owner",
                          "namespace-result", "namespace-missing", "query-bytes"):
                env, root, identity, nodes, files = tools_namespace_data(disposition)
                if fault == "directory-time":
                    for path in S.SHELL_TOOLS_DIRECTORIES: nodes[path]["identity"][6:] = [8192, 22, 22]
                elif fault == "namespace-inode": nodes["/usr/lib/jvm"]["identity"][1] += 1000
                elif fault == "namespace-mode": nodes["/usr/lib/jvm"]["identity"][2] = stat.S_IFDIR | 0o777
                elif fault == "namespace-owner": nodes["/usr/lib/jvm"]["identity"][3] = 1001
                elif fault == "namespace-result": files["namespace.exit"] = b"1\n"
                elif fault == "namespace-missing": files.pop("namespace.stdout")
                elif fault == "query-bytes": files["before-packages.stderr"] += b"extra\n"
                with self.subTest(disposition=disposition, fault=fault), patch.dict(S.os.environ, env, clear=True), \
                     patch.object(S, "shell_tools_input_root", return_value=root), patch.object(S, "directory_identity", return_value=identity), \
                     patch.object(S, "shell_tools_input_nodes", return_value=nodes), \
                     patch.object(S, "_shell_tools_namespace_sources", return_value=tools_namespace_source_data()), \
                     patch.object(S.D, "read", side_effect=tools_namespace_read(files)):
                    if fault in (None, "directory-time"):
                        observed = S.shell_tools_inputs_for_observation()
                        self.assertIs(observed["qualified"], False)
                        expected = {name: {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} for name, raw in files.items()}
                        self.assertEqual(observed["preparationFiles"], expected); self.assertEqual(len(expected), 12)
                        self.assertEqual(observed["nodes"]["/usr/lib/jvm"]["identity"], nodes["/usr/lib/jvm"]["identity"][:5])
                    else:
                        with self.assertRaises((S.D.Refused, FileNotFoundError)): S.shell_tools_inputs_for_observation()

    def test_protected_namespace_does_not_waive_a_refused_descendant_in_strict_before(self):
        env, root, identity, nodes, files = tools_namespace_data("protected")
        nodes[S.SHELL_TOOLS_PROGRAMS[2]] = {"kind": "refused", "identity": nodes[S.SHELL_TOOLS_PROGRAMS[2]]["identity"]}
        original = S.D.decode(files["namespace-before.json"]); original["snapshot"]["nodes"] = deepcopy(nodes)
        query = tuple(files["before-packages" + suffix] for suffix in (".tsv", ".stderr", ".exit"))
        with patch.dict(S.os.environ, env, clear=True), patch.object(S, "shell_tools_input_root", return_value=root), \
             patch.object(S, "directory_identity", return_value=identity), patch.object(S, "shell_tools_input_nodes", return_value=nodes), \
             patch.object(S.D, "read", side_effect=tools_namespace_read(files)), patch.object(S.D, "write") as writing, \
             patch.object(S, "_shell_tools_namespace_result") as namespace:
            self.assertEqual(S.shell_tools_namespace_disposition(S.D.canonical(original), root, query)[1], "protected")
            with self.assertRaisesRegex(S.D.Refused, "must not repair a refused original"):
                S.shell_tools_input_snapshot("before")
            namespace.assert_not_called(); writing.assert_called_once()
            self.assertEqual(S.D.decode(writing.call_args.args[1])["nodes"], nodes)


    def test_source_pins_read_only_the_two_fixed_original_bounded_leaves(self):
        self.assertEqual(S.SHELL_TOOLS_NAMESPACE_SOURCES,
                         {".github/workflows/desktop-ubuntu-publication.yml": 65536, "desktop/tools/ci_ubuntu_publication.py": 1048576})
        calls = []
        expected = tools_namespace_source_data()
        def record(path, limit):
            relative = str(path.relative_to(S.SOURCE)); calls.append((relative, limit))
            row = next(row for row in expected if row["path"] == relative)
            return {**row, "path": path.name}
        with patch.object(S.D, "file_record", side_effect=record):
            self.assertEqual(S._shell_tools_namespace_sources(), expected)
        self.assertEqual(calls, list(S.SHELL_TOOLS_NAMESPACE_SOURCES.items()))

    def test_pre_apt_check_binds_actual_current_namespace_and_never_runs_the_constructor(self):
        env, root, identity, _, files = tools_namespace_data("preserve-create")
        for fault in (None, "inode", "mode", "owner", "git", "alias", "parent"):
            nodes = S.D.decode(files["before.json"])["nodes"]
            if fault == "inode": nodes["/usr/lib/jvm"]["identity"][1] += 1
            elif fault == "mode": nodes["/usr/lib/jvm"]["identity"][2] = stat.S_IFDIR | 0o777
            elif fault == "owner": nodes["/usr/lib/jvm"]["identity"][3] = 1001
            elif fault == "git": nodes["/usr/bin/git"]["sha256"] = "0" * 64
            elif fault == "alias": nodes["/etc/alternatives/java"]["target"] = "/other"
            elif fault == "parent": nodes["/usr/lib"]["identity"][1] += 1
            with self.subTest(fault=fault), patch.dict(S.os.environ, env, clear=True), \
                 patch.object(S, "shell_tools_input_root", return_value=root) as root_check, \
                 patch.object(S, "directory_identity", return_value=identity), patch.object(S, "shell_tools_input_nodes", return_value=nodes), \
                 patch.object(S, "_shell_tools_namespace_sources", return_value=tools_namespace_source_data()), \
                 patch.object(S.D, "read", side_effect=tools_namespace_read(files)):
                if fault is None: self.assertIsNone(S.shell_tools_namespace_check())
                else:
                    with self.assertRaises(S.D.Refused): S.shell_tools_namespace_check()
                root_check.assert_called_once_with()

    def test_exact_retained_n_failure_stays_failed_at_all_three_strict_gates(self):
        # Run35977908596/1 original before bytes; no filesystem/artifact lookup in this fixture.
        raw = b"{\"attempt\":\"1\",\"nodes\":{\"/\":{\"identity\":[2049,2,16877,0,0,23,4096,1790240000326184300,1790240000326184300],\"kind\":\"directory\"},\"/etc\":{\"identity\":[2049,42,16877,0,0,141,12288,1790240223664180264,1790240223664180264],\"kind\":\"directory\"},\"/etc/alternatives\":{\"identity\":[2049,142,16877,0,0,2,20480,1790240000125185814,1790240000125185814],\"kind\":\"directory\"},\"/etc/alternatives/java\":{\"identity\":[2049,26774,41471,0,0,1,42,1788816239112644255,1788816239119644148],\"kind\":\"symlink\",\"target\":\"/usr/lib/jvm/temurin-17-jdk-amd64/bin/java\"},\"/etc/alternatives/javac\":{\"identity\":[2049,26778,41471,0,0,1,43,1788816239121644118,1788816239131643967],\"kind\":\"symlink\",\"target\":\"/usr/lib/jvm/temurin-17-jdk-amd64/bin/javac\"},\"/usr\":{\"identity\":[2049,1703,16877,0,0,13,4096,1788815577361378084,1788815577361378084],\"kind\":\"directory\"},\"/usr/bin\":{\"identity\":[2049,1704,16877,0,0,2,69632,1790240221858167909,1790240221858167909],\"kind\":\"directory\"},\"/usr/bin/git\":{\"identity\":[2049,80618,33261,0,0,1,4576040,1786408018000000000,1788815929924713318],\"kind\":\"file\",\"path\":\"git\",\"sha256\":\"d4d2ba562243015206d4248edfec871a74786499292d00ed072dbca2f5ae8073\",\"size\":4576040},\"/usr/bin/java\":{\"identity\":[2049,26827,41471,0,0,1,22,1787152358000000000,1788816215176025079],\"kind\":\"symlink\",\"target\":\"/etc/alternatives/java\"},\"/usr/bin/javac\":{\"identity\":[2049,26832,41471,0,0,1,23,1787152359000000000,1788816215186024697],\"kind\":\"symlink\",\"target\":\"/etc/alternatives/javac\"},\"/usr/bin/python3.12\":{\"identity\":[2049,2112,33261,0,0,1,8025024,1784159201000000000,1787804317903610895],\"kind\":\"file\",\"path\":\"python3.12\",\"sha256\":\"a92f0f95e883390c7256b2e441484aac06b1002dbe1d924141a77c8d82f96223\",\"size\":8025024},\"/usr/lib\":{\"identity\":[2049,4243,16877,0,0,107,4096,1788816537255811338,1788816537255811338],\"kind\":\"directory\"},\"/usr/lib/jvm\":{\"identity\":[2049,3954169,16895,0,0,7,4096,1788816261237317659,1788816263267288505],\"kind\":\"refused\"},\"/usr/lib/jvm/java-17-openjdk-amd64\":{\"kind\":\"parent-unavailable\"},\"/usr/lib/jvm/java-17-openjdk-amd64/bin\":{\"kind\":\"parent-unavailable\"},\"/usr/lib/jvm/java-17-openjdk-amd64/bin/java\":{\"kind\":\"parent-unavailable\"},\"/usr/lib/jvm/java-17-openjdk-amd64/bin/javac\":{\"kind\":\"parent-unavailable\"}},\"originalStepExit\":null,\"packageQuery\":{\"exitCode\":1,\"stderr\":{\"sha256\":\"841d88eb2e59bfe3e1525b9f26cf8b8296f257d54b40383a265437016c672aa7\",\"size\":126},\"stdout\":{\"sha256\":\"4b8b4d9ad02fe88236849379cd4a5ef6b994e45044f4f8b06f57e4c3608b5094\",\"size\":158}},\"phase\":\"before\",\"qualified\":false,\"rootIdentity\":[2049,8937776,16832,1001,1001],\"runId\":\"35977908596\",\"schema\":\"fixed-disposable-shell-tools-inputs-v1\",\"sourceSha\":\"3c98fa240e1f7f692ea2123cbe7d16177427d9d3\"}\n"
        self.assertEqual(hashlib.sha256(raw).hexdigest(), "f590cbd15720a4632b3636cf210f568f075136adafa1dd157e5b42eef8d12630")
        before = S.D.decode(raw); after = deepcopy(before); after.update(phase="after", originalStepExit=1)
        after_raw = S.D.canonical(after)
        self.assertEqual(hashlib.sha256(after_raw).hexdigest(), "115ba7598458ba16011bc5810b9bacb86ed5423a330ff41c1ccce2881c6c868f")
        nodes = before["nodes"]; identity = tuple(before["rootIdentity"])
        self.assertEqual(nodes["/usr/lib/jvm"], {"kind": "refused", "identity":
                         [2049, 3954169, 16895, 0, 0, 7, 4096, 1788816261237317659, 1788816263267288505]})
        for name in (S.SHELL_TOOLS_JDK_ROOT, S.SHELL_TOOLS_JDK_ROOT + "/bin", *S.SHELL_TOOLS_PROGRAMS[2:]):
            self.assertEqual(nodes[name], {"kind": "parent-unavailable"})
        package_raw = (b"git\tinstalled\t1:2.55.0-0ppa1~ubuntu24.04.2\tamd64\tgit\t1:2.55.0-0ppa1~ubuntu24.04.2\n"
                       b"python3.12\tinstalled\t3.12.3-1ubuntu0.16\tamd64\tpython3.12\t3.12.3-1ubuntu0.16\n")
        self.assertEqual(hashlib.sha256(package_raw).hexdigest(), "4b8b4d9ad02fe88236849379cd4a5ef6b994e45044f4f8b06f57e4c3608b5094")
        files = {"before.json": raw, "after.json": after_raw}
        for phase in ("before", "after"):
            files.update({phase + "-packages.tsv": package_raw, phase + "-packages.stderr": S.SHELL_TOOLS_JDK_MISSING,
                          phase + "-packages.exit": b"1\n"})
        env, _, _, _, _ = tools_preparation_data()
        env.update(GITHUB_SHA=before["sourceSha"], GITHUB_RUN_ID=before["runId"], GITHUB_RUN_ATTEMPT=before["attempt"],
                   MRK_SHELL_TOOLS_PREPARATION_EXIT="1")
        root = Path("/tmp/mrk-desktop-tools-35977908596-1")
        with patch.dict(S.os.environ, env, clear=True), patch.object(S, "shell_tools_input_root", return_value=root), \
             patch.object(S, "directory_identity", return_value=identity), patch.object(S, "shell_tools_input_nodes", return_value=nodes), \
             patch.object(S.D, "read", side_effect=tools_namespace_read(files)), \
             patch.object(S, "_shell_tools_namespace_result", return_value={"would-not-waive-original": True}) as namespace:
            for phase, reason in (("before", "must not repair a refused original"), ("after", "directory or package query failed")):
                with self.subTest(phase=phase), patch.object(S.D, "write") as writing:
                    with self.assertRaisesRegex(S.D.Refused, reason): S.shell_tools_input_snapshot(phase)
                    writing.assert_called_once_with(root / (phase + ".json"), files[phase + ".json"])
                    namespace.assert_not_called()
            with self.assertRaisesRegex(S.D.Refused, "original preparation failed"):
                S.shell_tools_inputs_for_observation()
            namespace.assert_not_called()



        # The Rust inert contracts and original native UI still need execution.



        # Source correspondence is not Rust execution or installed GTK evidence.


class InstalledFailureLabelSourceContracts(unittest.TestCase):
        # These are source contracts; the inert Rust state tests still require
        # their actual compiled native route, not a substituted Python result.

        # Source correspondence and pure assertion placement are not GTK/native evidence.


    def test_normal_capability_error_literals_match_the_existing_joined_classifier(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        source = (SOURCE / "desktop/src-tauri/src/bridge.rs").read_text()
        classifier = source.split("fn capabilities_failure_line(", 1)[1].split("fn capabilities_cause_line(", 1)[0]
        cause_classifier = source.split("fn capabilities_cause_line(", 1)[1].split("\nstruct RegisteredProject", 1)[0]
        literal_rows = re.findall(r'b"(MRKDBG_DESKTOP_BOOTSTRAP=capabilities-[a-z_-]+)\\n"', classifier)
        cause_rows = re.findall(r'b"(MRKDBG_DESKTOP_BOOTSTRAP=capabilities-cause-[a-z-]+)\\n"', cause_classifier)
        prefix = "MRKDBG_DESKTOP_BOOTSTRAP="
        consumer = lifecycle._shell_normal_markers(b"", b"")["stdout"]["stages"]
        self.assertEqual({line[len(prefix):] for line in literal_rows},
                         {stage for stage in consumer if stage.startswith("capabilities-") and not stage.startswith("capabilities-cause-")})
        self.assertEqual({line[len(prefix):] for line in cause_rows},
                         {stage for stage in consumer if stage.startswith("capabilities-cause-")})
        self.assertLessEqual(max(len(line.encode("ascii")) + 1 for line in literal_rows), 78)
        self.assertLessEqual(max(len(line.encode("ascii")) + 1 for line in cause_rows), 96)

        # Text correspondence only; no native operation, returned spawn or
        # management/custody finality is established by these source assertions.

    def test_literal_allowlists_correspond_to_bounded_rust_step_boundary_encoder(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        source = (SOURCE / "desktop/src-tauri/src/installed_shell_observation.rs").read_text()
        steps = {line.encode("ascii") + b"\n" for line in re.findall(
            r'b"(MRK_INSTALLED_SHELL_FAILURE_STEP=[A-Za-z]+)\\n"', source)}
        boundaries = {line.encode("ascii") + b"\n" for line in re.findall(
            r'b"(MRK_INSTALLED_SHELL_FAILURE_PHASE=[a-z]+)\\n"', source)}
        progress = {line.encode("ascii") + b"\n" for line in re.findall(
            r'b"(MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=[a-z-]+)\\n"', source)}
        path_rejections = source.split("impl PathRejection {", 1)[1].split("struct PathDiagnostic", 1)[0]
        path_tokens = tuple(value.encode("ascii") for value in re.findall(r'=> b"([a-z-]+)"', path_rejections))
        self.assertTrue(all(re.fullmatch(rb"[a-z-]{1,22}", token) for token in path_tokens))
        path_bound = (max(map(len, steps)) + max(map(len, boundaries)) + max(map(len, progress))
                      + len(b"MRK_INSTALLED_SHELL_PATH_FAILURE=v1;index=none;reject=\n") + max(map(len, path_tokens)))
        self.assertEqual(path_bound, 251)
        self.assertLessEqual(path_bound, lifecycle.SHELL_PATH_FAILURE_FRAME_BOUND)
        self.assertEqual(lifecycle.SHELL_PATH_FAILURE_FRAME_BOUND, 256)
        v2_bound = path_bound + len(b";start=999999;now=999999;rsv=m;in=m;out=m;cb=reserved;wait=initial-folder-absent")
        self.assertLessEqual(v2_bound, lifecycle.SHELL_PATH_FAILURE_V2_FRAME_BOUND)
        self.assertEqual(lifecycle.SHELL_PATH_FAILURE_V2_FRAME_BOUND, 384)
        v3_bound = path_bound + len(b";start=999999;now=999999;rsv=m;in=m;out=m;cb=reserved;wait=target-parent-different;h=5o")
        self.assertLessEqual(v3_bound, lifecycle.SHELL_PATH_FAILURE_V3_FRAME_BOUND)
        self.assertEqual(lifecycle.SHELL_PATH_FAILURE_V3_FRAME_BOUND, 384)
        supervisor = (SOURCE / "desktop/src-tauri/src/supervisor.rs").read_text()
        maps = supervisor.split("impl MapRole {", 1)[1].split("impl ObservationFailure {", 1)[0]
        map_tokens = tuple(value.encode("ascii") for value in re.findall(r'b"(map-[a-z-]+)"', maps))
        hosted_block = maps.split("impl HostedMapSpelling {", 1)[1].split("\n    }\n", 1)[0]
        hosted_tokens = tuple(value.encode("ascii") for value in re.findall(r'b"(map-xh-[a-z]{2})"', hosted_block))
        generic = tuple(b"map-x-" + group + b"-" + deleted + history
                        for group in (b"v", b"l", b"c", b"h", b"m", b"o")
                        for deleted, history in ((b"n", b"a"), (b"n", b"p"), (b"d", b"a"), (b"d", b"p")))
        self.assertEqual(lifecycle.SHELL_SESSION_GENERIC_MAP_WORKERS, generic)
        self.assertEqual(len(generic), 24)
        self.assertEqual(lifecycle.SHELL_SESSION_WORKER_JOINS, b"cxf")
        for boundary in boundaries:
            for context in progress:
                self.assertEqual(lifecycle._shell_label_pair(b"MRK_INSTALLED_SHELL_FAILURE_STEP=SelectProject\n" + boundary + context),
                                 {"step": "SelectProject", "boundary": boundary.decode("ascii").strip().split("=", 1)[1],
                                  "bootstrapProgress": context.decode("ascii").strip().split("=", 1)[1]})
        self.assertLessEqual(max(map(len, steps)) + max(map(len, boundaries)) + max(map(len, progress)), 512)
        session_prefix = (b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionReview\n"
                          b"MRK_INSTALLED_SHELL_FAILURE_PHASE=deadline\n"
                          b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n")
        def session_frame(worker, origin=b"supervisor-disabled", detail=b"none", association=b"bound", query=b"cleanup.none.rr"):
            return (session_prefix + b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v2;index=3;evaluations=14;"
                    b"reject=unknown-native-snapshot;wait=original-owner-unsettled;o=" + origin + b";d=" + detail
                    + b";a=" + association + b";q=" + query + b";w=" + worker + b"\n")
        # Exact membership, not prefix acceptance; old refusal tokens remain valid.
        for token in map_tokens + (b"exec-read", b"exec-check"):
            result = lifecycle._shell_label_pair(session_frame(token))
            self.assertIsNotNone(result, token)
            self.assertEqual(result["session"]["firstOrigin"],
                             {"origin": "supervisor-disabled", "detail": "none", "association": "bound",
                              "query": "cleanup.none.rr", "worker": token.decode("ascii")})
        for token in hosted_tokens:
            self.assertIsNone(lifecycle._shell_label_pair(session_frame(token + b"x")))
        for token in (b"map-xh", b"map-xh-", b"map-xh-s", b"map-xh-vz", b"map-xh-sb", b"map-xh-sz-extra",
                      b"MAP-XH-SZ", b"map-xh-s0", b"arbitrary", b"map-xh-sz\x00",
                      b"exec", b"exec-ready", b"exec-readx", b"exec-check-extra", b"exec-check\x00"):
            self.assertIsNone(lifecycle._shell_label_pair(session_frame(token)))
        for token in (hosted_tokens[0], b"exec-read", b"exec-check"):
            for fields in ({"association": b"unassociated"}, {"query": b"na"}, {"query": b"unregistered"},
                           {"origin": b"not-recorded"}, {"detail": b"failed"}):
                self.assertIsNone(lifecycle._shell_label_pair(session_frame(token, **fields)))
        token = hosted_tokens[0]
        frame = session_frame(token)
        for malformed in (frame[:-1], frame[:-2], session_prefix, frame + b"\n", frame + frame,
                          frame.replace(b";w=", b";unexpected="), frame.replace(b"=v2;", b"=v3;"),
                          frame.replace(b";w=", b";w=na;w=")):
            self.assertIsNone(lifecycle._shell_label_pair(malformed))
        longest_session = (len(b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v2;index=none;evaluations=128;reject=;wait=\n")
                           + max(map(len, lifecycle.SHELL_SESSION_REJECTIONS)) + max(map(len, lifecycle.SHELL_SESSION_WAITS)))
        prior_bound = max(map(len, steps)) + max(map(len, boundaries)) + max(map(len, progress)) + longest_session
        self.assertEqual(prior_bound, 311)
        query_bound = max(len(b"unregistered"), len(b"unavailable"), max(map(len, lifecycle.SHELL_SESSION_QUERY_ERRORS))
                          + 1 + max(map(len, lifecycle.SHELL_SESSION_QUERY_CAUSES)) + 1 + 2)
        worker_bound = max(max(map(len, lifecycle.SHELL_SESSION_WORKERS)), max(map(len, lifecycle.SHELL_SESSION_WORKER_STAGES)) + 2)
        complete_bound = (prior_bound + 5 * 3 + max(map(len, lifecycle.SHELL_SESSION_ORIGINS)) + max(map(len, lifecycle.SHELL_SESSION_DETAILS))
                          + max(map(len, lifecycle.SHELL_SESSION_ASSOCIATIONS)) + query_bound + worker_bound)
        self.assertEqual((query_bound, worker_bound, complete_bound), (26, 14, 412))
        self.assertLessEqual(complete_bound, 512)
        callbacks = source.split("impl SessionGtkCallbacks {", 1)[1].split("// Map only cached public DATA", 1)[0]
        callback_tokens = tuple(value.encode("ascii") for value in re.findall(r'=> b"([a-z0-9]{2})"', callbacks))
        self.assertEqual(len(callback_tokens), len(set(callback_tokens)))
        self.assertEqual(lifecycle.SHELL_SESSION_FAILURE_V6_FRAME_BOUND, lifecycle.SHELL_SESSION_FAILURE_V5_FRAME_BOUND - 7 + 3 + max(map(len, callback_tokens)))
        self.assertLessEqual(max(map(len, lifecycle.SHELL_SESSION_V6_WAITS)), max(map(len, lifecycle.SHELL_SESSION_WAITS)))
        self.assertEqual(lifecycle.SHELL_SESSION_FAILURE_V7_FRAME_BOUND, lifecycle.SHELL_SESSION_FAILURE_V6_FRAME_BOUND + 5)
        self.assertEqual(lifecycle.SHELL_SESSION_FAILURE_V7_FRAME_BOUND, 512)
        self.assertEqual(lifecycle.SHELL_WORK_FILE_LIMIT, 64 << 20)
        self.assertEqual({name for name in lifecycle.public_files({"shell": {}}) if name.endswith("failure.labels")},
                         {"shell-settled-failure-failure.labels"})

    def test_assessment_failure_v3_closed_roundtrips_preserve_historical_frames(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        source = (SOURCE / "desktop/src-tauri/src/credential_assessment.rs").read_text()
        packet = source.split("mod assessment_failure {", 1)[1].split("pub(crate) use assessment_failure::Failure", 1)[0]
        origins = tuple(token.encode("ascii") for token in re.findall(r'=> b"([a-z-]+)"', packet.split("enum Origin", 1)[1].split("enum Class", 1)[0]))
        classes = tuple(token.encode("ascii") for token in re.findall(r'=> b"([a-z-]+)"', packet.split("enum Class", 1)[1].split("enum Cause", 1)[0]))
        causes = tuple(token.encode("ascii") for token in re.findall(r'=> b"([a-z-]+)"', packet.split("enum Cause", 1)[1].split("// No raw Value", 1)[0]))
        maxima = tuple(max(map(len, tokens)) for tokens in (origins, classes, causes))
        self.assertEqual(maxima, (7, 22, 11))
        self.assertEqual(lifecycle.SHELL_SESSION_FAILURE_FRAME_BOUND, 412 + 3 * 4 + 7 + 24 + 11)
        self.assertLessEqual(412 + 3 * 4 + sum(maxima), lifecycle.SHELL_SESSION_FAILURE_FRAME_BOUND)
        self.assertLessEqual(lifecycle.SHELL_SESSION_FAILURE_FRAME_BOUND, lifecycle.SHELL_FAILURE_LABEL_LIMIT)
        prefix = (b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionReview\n"
                  b"MRK_INSTALLED_SHELL_FAILURE_PHASE=settlement\n"
                  b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n")
        rejections = {b"known-assessment": b"reply-assessment-invalid-request", b"busy": b"reply-busy",
                      b"shutdown": b"reply-shutting-down", b"timeout": b"reply-query-timeout", b"cleanup": b"reply-cleanup-unknown"}
        def frame(origin=b"none", classification=b"na", cause=b"none"):
            rejection = rejections.get(classification, b"reply-assessment-unavailable")
            return (prefix + b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v3;index=6;evaluations=13;reject=" + rejection
                    + b";wait=native-reply-pending;o=not-recorded;d=none;a=unassociated;q=na;w=na;ao=" + origin
                    + b";ac=" + classification + b";ax=" + cause + b"\n")
        combinations = [(b"none", b"na", b"none"), (b"request", b"serialize", b"none")]
        combinations += [(b"bridge", classification, cause) for classification in lifecycle.SHELL_SESSION_ASSESSMENT_BRIDGE_CLASSES for cause in causes]
        combinations += [(b"result", classification, b"none") for classification in lifecycle.SHELL_SESSION_ASSESSMENT_RESULT_CLASSES]
        for origin, classification, cause in combinations:
            raw = frame(origin, classification, cause)
            parsed = lifecycle._shell_label_pair(raw)
            self.assertIsNotNone(parsed, (origin, classification, cause))
            self.assertEqual(parsed["session"]["assessmentFailure"],
                             {"origin": origin.decode("ascii"), "class": classification.decode("ascii"), "cause": cause.decode("ascii")})
            self.assertEqual(parsed["session"]["rejection"], rejections.get(classification, b"reply-assessment-unavailable").decode("ascii"))
            self.assertEqual(parsed["session"]["lastWait"], "native-reply-pending")
            self.assertEqual(parsed["session"]["firstOrigin"],
                             {"origin": "not-recorded", "detail": "none", "association": "unassociated", "query": "na", "worker": "na"})
            self.assertLessEqual(len(raw), lifecycle.SHELL_SESSION_FAILURE_FRAME_BOUND)
        known = frame(b"bridge", b"known-assessment", b"response")
        for rejection in (b"reply-assessment-invalid-request", b"reply-assessment-limit", b"reply-assessment-version",
                          b"reply-assessment-policy-stale", b"reply-assessment-context-invalid"):
            self.assertIsNotNone(lifecycle._shell_label_pair(known.replace(b"reply-assessment-invalid-request", rejection)))
        raw = frame(b"bridge", b"assessment-unavailable", b"sel-profile")
        # v3 remains historical three-field DATA even after the v5 emitter.
        bound = raw.replace(b"o=not-recorded;d=none;a=unassociated;q=na;w=na;",
                            b"o=supervisor-disabled;d=none;a=bound;q=cleanup.none.rr;w=settle-unknown;")
        self.assertEqual(lifecycle._shell_label_pair(bound)["session"]["assessmentFailure"],
                         lifecycle._shell_label_pair(raw)["session"]["assessmentFailure"])
        v2 = raw.split(b";ao=", 1)[0].replace(b"=v3;", b"=v2;") + b"\n"
        v1 = v2.split(b";o=", 1)[0].replace(b"=v2;", b"=v1;") + b"\n"
        for historical in (v1, v2):
            parsed = lifecycle._shell_label_pair(historical)
            self.assertIsNotNone(parsed)
            self.assertNotIn("assessmentFailure", parsed["session"])
        self.assertNotIn("firstOrigin", lifecycle._shell_label_pair(v1)["session"])
        self.assertIn("firstOrigin", lifecycle._shell_label_pair(v2)["session"])

    def test_assessment_failure_v3_refuses_every_prefix_and_mixed_or_untrusted_packet(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        prefix = (b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionReview\n"
                  b"MRK_INSTALLED_SHELL_FAILURE_PHASE=settlement\n"
                  b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n"
                  b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v3;index=6;evaluations=13;"
                  b"reject=reply-assessment-unavailable;wait=native-reply-pending;"
                  b"o=not-recorded;d=none;a=unassociated;q=na;w=na;")
        def frame(origin=b"bridge", classification=b"assessment-unavailable", cause=b"sel-profile"):
            return prefix + b"ao=" + origin + b";ac=" + classification + b";ax=" + cause + b"\n"
        raw = frame()
        for complete in (raw, frame(b"none", b"na", b"none"), frame(b"result", b"semantics", b"none")):
            self.assertIsNotNone(lifecycle._shell_label_pair(complete))
            for end in range(len(complete)):
                self.assertIsNone(lifecycle._shell_label_pair(complete[:end]), end)
                if end < len(complete) - 1:
                    self.assertIsNone(lifecycle._shell_label_pair(complete[:end] + b"\n"), end)
        for packet in ((b"none", b"serialize", b"none"), (b"none", b"na", b"response"),
                       (b"request", b"na", b"none"), (b"request", b"serialize", b"spawn-exec"),
                       (b"result", b"retryable", b"none"), (b"result", b"shape", b"sel-profile"),
                       (b"bridge", b"semantics", b"none"), (b"bridge", b"serialize", b"response"),
                       (b"bridge", b"other", b"future"), (b"future", b"other", b"none"),
                       (b"bridge", b"busy", b"none"), (b"bridge", b"known-assessment", b"response"),
                       (b"bridge", b"fictional-private-password", b"none"),
                       (b"bridge", b"other", b"/private/credential")):
            self.assertIsNone(lifecycle._shell_label_pair(frame(*packet)), packet)
        for malformed in (raw + b"\n", raw + raw, raw + b"fictional-private-password", raw[:-1] + b";extra=none\n",
                          raw.replace(b"=v3;", b"=v4;"), raw.replace(b"=v3;", b"=v2;"), raw.replace(b"=v3;", b"=v1;"),
                          raw.replace(b";ao=bridge", b""), raw.replace(b";ac=assessment-unavailable", b""),
                          raw.replace(b";ax=sel-profile", b""), raw.replace(b";ao=", b";ao=none;ao="),
                          raw.replace(b";ac=", b";ac=other;ac="), raw.replace(b";ax=", b";ax=none;ax="),
                          raw.replace(b"ao=bridge", b"ao=Bridge"), raw.replace(b"ac=assessment-unavailable", b"ac=assessment_unavailable"),
                          raw.replace(b"index=6;", b"index=06;"), raw.replace(b"q=na;", b"q=timeout.none.rr;"),
                          raw.replace(b"reject=reply-assessment-unavailable;", b"reject=reply-busy;"),
                          raw.replace(b";ax=", b";ax=\x00")):
            self.assertIsNone(lifecycle._shell_label_pair(malformed))

    def test_assessment_failure_v4_retains_the_original_enum_and_closed_cross_fields(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        source = (SOURCE / "desktop/src-tauri/src/credential_assessment.rs").read_text()
        packet = source.split("mod assessment_failure {", 1)[1].split("pub(crate) use assessment_failure::Failure", 1)[0]
        mapper = packet.split("fn admission_token(reason: Option<A>)", 1)[1].split("\n    #[derive", 1)[0]
        mapping = re.findall(r'Some\(A::([A-Za-z]+)\) => b"([a-z-]+)"', mapper)
        admissions = (b"na",) + tuple(token.encode("ascii") for _, token in mapping)
        self.assertEqual(lifecycle.SHELL_SESSION_FAILURE_V4_FRAME_BOUND, 466 + 4 + 22)
        self.assertEqual(lifecycle.SHELL_FAILURE_LABEL_LIMIT - lifecycle.SHELL_SESSION_FAILURE_V4_FRAME_BOUND, 20)
        prefix = (b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionReview\n"
                  b"MRK_INSTALLED_SHELL_FAILURE_PHASE=settlement\n"
                  b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n")
        rejections = {b"known-assessment": b"reply-assessment-invalid-request", b"busy": b"reply-busy",
                      b"shutdown": b"reply-shutting-down", b"timeout": b"reply-query-timeout", b"cleanup": b"reply-cleanup-unknown"}
        def frame(origin=b"bridge", classification=b"runtime-unavailable", cause=b"prepare", admission=b"missing-compile-anchor"):
            rejection = rejections.get(classification, b"reply-assessment-unavailable")
            return (prefix + b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v4;index=6;evaluations=13;reject=" + rejection
                    + b";wait=native-reply-pending;o=not-recorded;d=none;a=unassociated;q=na;w=na;ao=" + origin
                    + b";ac=" + classification + b";ax=" + cause + b";af=" + admission + b"\n")
        combinations = [(b"none", b"na", b"none"), (b"request", b"serialize", b"none")]
        combinations += [(b"bridge", classification, cause) for classification in lifecycle.SHELL_SESSION_ASSESSMENT_BRIDGE_CLASSES
                         for cause in lifecycle.SHELL_SESSION_QUERY_CAUSES]
        combinations += [(b"result", classification, b"none") for classification in lifecycle.SHELL_SESSION_ASSESSMENT_RESULT_CLASSES]
        for origin, classification, cause in combinations:
            for admission in admissions:
                carries = origin == b"bridge" and cause in (b"inspection", b"capability", b"prepare", b"final-claim")
                required = carries and cause != b"inspection"
                allowed = not required if admission == b"na" else carries
                raw = frame(origin, classification, cause, admission)
                parsed = lifecycle._shell_label_pair(raw)
                self.assertEqual(parsed is not None, allowed, (origin, classification, cause, admission))
                if allowed:
                    self.assertEqual(parsed["session"]["assessmentFailure"],
                                     {"origin": origin.decode("ascii"), "class": classification.decode("ascii"),
                                      "cause": cause.decode("ascii"), "admission": admission.decode("ascii")})
                    self.assertEqual(parsed["session"]["rejection"], rejections.get(classification, b"reply-assessment-unavailable").decode("ascii"))
                    self.assertLessEqual(len(raw), lifecycle.SHELL_SESSION_FAILURE_V4_FRAME_BOUND)
        raw = frame()
        # Preserve the historical v4 parser fixture; the live shared pre-GTK
        # Rust contract emits v7. Neither is an installed qualification receipt.
        live = raw.replace(b"=v4;", b"=v7;").replace(b";evaluations=", b";eval=")[:-1] + b";u=na;g=na;h=na\n"
        self.assertEqual(lifecycle._shell_label_pair(live)["session"]["assessmentFailure"],
                         lifecycle._shell_label_pair(raw)["session"]["assessmentFailure"])
        bound = raw.replace(b"o=not-recorded;d=none;a=unassociated;q=na;w=na;",
                            b"o=supervisor-disabled;d=none;a=bound;q=cleanup.none.rr;w=settle-unknown;")
        self.assertEqual(lifecycle._shell_label_pair(bound)["session"]["assessmentFailure"],
                         lifecycle._shell_label_pair(raw)["session"]["assessmentFailure"])
        historical = raw.replace(b"=v4;", b"=v3;").replace(b";af=missing-compile-anchor", b"")
        self.assertEqual(lifecycle._shell_label_pair(historical)["session"]["assessmentFailure"],
                         {"origin": "bridge", "class": "runtime-unavailable", "cause": "prepare"})
        with patch.object(lifecycle, "SHELL_SESSION_FAILURE_V4_FRAME_BOUND", len(raw) - 1):
            self.assertIsNone(lifecycle._shell_label_pair(raw))
            self.assertIsNotNone(lifecycle._shell_label_pair(historical))
        with patch.object(lifecycle, "SHELL_SESSION_FAILURE_FRAME_BOUND", len(historical) - 1):
            self.assertIsNone(lifecycle._shell_label_pair(historical))
            self.assertIsNotNone(lifecycle._shell_label_pair(raw))

    def test_assessment_failure_v4_refuses_prefixes_incompatible_rejections_and_malformed_details(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        prefix = (b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionReview\n"
                  b"MRK_INSTALLED_SHELL_FAILURE_PHASE=settlement\n"
                  b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n"
                  b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v4;index=6;evaluations=13;"
                  b"reject=reply-assessment-unavailable;wait=native-reply-pending;"
                  b"o=not-recorded;d=none;a=unassociated;q=na;w=na;")
        def frame(origin=b"bridge", classification=b"runtime-unavailable", cause=b"prepare", admission=b"missing-compile-anchor"):
            return prefix + b"ao=" + origin + b";ac=" + classification + b";ax=" + cause + b";af=" + admission + b"\n"
        raw = frame()
        for complete in (raw, frame(b"none", b"na", b"none", b"na"), frame(b"result", b"semantics", b"none", b"na")):
            self.assertIsNotNone(lifecycle._shell_label_pair(complete))
            for end in range(len(complete)):
                self.assertIsNone(lifecycle._shell_label_pair(complete[:end]), end)
                if end < len(complete) - 1:
                    self.assertIsNone(lifecycle._shell_label_pair(complete[:end] + b"\n"), end)
        for packet in ((b"none", b"serialize", b"none", b"na"), (b"none", b"na", b"response", b"na"),
                       (b"request", b"na", b"none", b"na"), (b"request", b"serialize", b"prepare", b"namespace"),
                       (b"result", b"retryable", b"none", b"na"), (b"result", b"shape", b"sel-profile", b"na"),
                       (b"bridge", b"semantics", b"prepare", b"namespace"), (b"bridge", b"serialize", b"response", b"na"),
                       (b"bridge", b"other", b"future", b"na"), (b"future", b"other", b"none", b"na"),
                       (b"bridge", b"known-assessment", b"response", b"na")):
            self.assertIsNone(lifecycle._shell_label_pair(frame(*packet)), packet)
        for classification in (b"busy", b"shutdown", b"timeout", b"cleanup"):
            self.assertIsNone(lifecycle._shell_label_pair(frame(classification=classification)))
        for admission in (b"", b"na", b"unknown", b"Namespace", b"namespace\x00", b"/private/credential",
                          b"unsupported_platform", b"native-denied-extra", b"missing-compile-anchorx"):
            self.assertIsNone(lifecycle._shell_label_pair(frame(admission=admission)), admission)
        for malformed in (raw + b"\n", raw + raw, raw[:-1] + b";extra=na\n",
                          raw.replace(b"=v4;", b"=v3;"), raw.replace(b"=v4;", b"=v2;"),
                          raw.replace(b"=v4;", b"=v1;"), raw.replace(b"=v4;", b"=v5;"),
                          raw.replace(b";af=missing-compile-anchor", b""), raw.replace(b";af=", b";af=na;af="),
                          raw.replace(b";ao=bridge", b""), raw.replace(b";ac=runtime-unavailable", b""), raw.replace(b";ax=prepare", b""),
                          raw.replace(b";ax=prepare;af=missing-compile-anchor", b";af=missing-compile-anchor;ax=prepare"),
                          raw.replace(b";ao=", b";ao=none;ao="), raw.replace(b";ac=", b";ac=other;ac="),
                          raw.replace(b";ax=", b";ax=none;ax="), raw.replace(b"ao=bridge", b"ao=Bridge"),
                          raw.replace(b"ac=runtime-unavailable", b"ac=runtime_unavailable"),
                          raw.replace(b"index=6;", b"index=06;"), raw.replace(b"q=na;", b"q=timeout.none.rr;"),
                          raw.replace(b"reject=reply-assessment-unavailable;", b"reject=reply-busy;"),
                          raw.replace(b";af=", b";af=\x00"), raw.replace(b"\n", b"\r\n")):
            self.assertIsNone(lifecycle._shell_label_pair(malformed))

    def test_first_unknown_v5_retains_closed_boundaries_and_legacy_shapes(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        boundaries = (b"na", b"unavailable", b"not-recorded", b"unspecified", b"transfer", b"inspection", b"acquisition",
                      b"native-observe", b"settlement", b"management", b"observer-loss", b"reply-loss", b"clock",
                      b"retire-clock", b"child-missing", b"child-wait", b"io", b"restore-limit", b"dev-observe")
        self.assertEqual(lifecycle.SHELL_SESSION_UNKNOWN_BOUNDARIES, boundaries)
        self.assertEqual((len(boundaries), len(set(boundaries)), max(map(len, boundaries))), (19, 19, 14))
        self.assertEqual(lifecycle.SHELL_SESSION_FAILURE_V5_FRAME_BOUND, 492 + 3 + 14)
        self.assertEqual(lifecycle.SHELL_FAILURE_LABEL_LIMIT - lifecycle.SHELL_SESSION_FAILURE_V5_FRAME_BOUND, 3)
        prefix = (b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionReview\n"
                  b"MRK_INSTALLED_SHELL_FAILURE_PHASE=settlement\n"
                  b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n")
        def frame(association=b"bound", query=b"cleanup.none.pp", worker=b"none-recorded", boundary=b"native-observe",
                  origin=b"supervisor-disabled", detail=b"none"):
            return (prefix + b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v5;index=6;evaluations=13;"
                    b"reject=reply-assessment-unavailable;wait=native-reply-pending;o=" + origin + b";d=" + detail
                    + b";a=" + association + b";q=" + query + b";w=" + worker
                    + b";ao=bridge;ac=runtime-unavailable;ax=prepare;af=missing-compile-anchor;u=" + boundary + b"\n")
        outcomes = [(b"bound", b"cleanup.none.pp", worker, boundary)
                    for boundary in boundaries[3:] for worker in (b"none-recorded", b"unavailable")]
        outcomes += [(b"unassociated", b"na", b"na", b"na"), (b"bound", b"unregistered", b"na", b"na"),
                     (b"bound", b"unavailable", b"unavailable", b"unavailable"),
                     (b"bound", b"none.none.pr", b"none-recorded", b"not-recorded"),
                     (b"bound", b"cleanup.none.pp", b"unavailable", b"not-recorded"),
                     (b"bound", b"unavailable.spawn-other.xf", b"settle-unknown", b"settlement")]
        assessment = {"origin": "bridge", "class": "runtime-unavailable", "cause": "prepare", "admission": "missing-compile-anchor"}
        for association, query, worker, boundary in outcomes:
            raw = frame(association, query, worker, boundary)
            parsed = lifecycle._shell_label_pair(raw)
            self.assertIsNotNone(parsed, (association, query, worker, boundary))
            self.assertEqual(parsed["session"]["firstOrigin"],
                             {"origin": "supervisor-disabled", "detail": "none", "association": association.decode("ascii"),
                              "query": query.decode("ascii"), "worker": worker.decode("ascii"), "unknownBoundary": boundary.decode("ascii")})
            self.assertEqual(parsed["session"]["assessmentFailure"], assessment)
            self.assertLessEqual(len(raw), lifecycle.SHELL_SESSION_FAILURE_V5_FRAME_BOUND)
        # U is neither document-origin detail, worker cause nor original Prepare cause.
        independent = lifecycle._shell_label_pair(frame(worker=b"settle-unknown", boundary=b"transfer", origin=b"op-cleanup", detail=b"deadline"))
        self.assertEqual(independent["session"]["firstOrigin"]["unknownBoundary"], "transfer")
        self.assertEqual(independent["session"]["firstOrigin"]["detail"], "deadline")
        self.assertEqual(independent["session"]["assessmentFailure"], assessment)
        absent = lifecycle._shell_label_pair(frame(b"unassociated", b"na", b"na", b"na", b"not-recorded"))
        self.assertEqual(absent["session"]["firstOrigin"], {"origin": "not-recorded", "detail": "none", "association": "unassociated",
                                                         "query": "na", "worker": "na", "unknownBoundary": "na"})
        raw = frame()
        v4 = raw.replace(b"=v5;", b"=v4;").replace(b";u=native-observe", b"")
        v3 = v4.replace(b"=v4;", b"=v3;").replace(b";af=missing-compile-anchor", b"")
        v2 = v3.replace(b"=v3;", b"=v2;").split(b";ao=", 1)[0] + b"\n"
        v1 = v2.replace(b"=v2;", b"=v1;").split(b";o=", 1)[0] + b"\n"
        base = {"recipeIndex": 6, "evaluations": 13, "rejection": "reply-assessment-unavailable", "lastWait": "native-reply-pending"}
        first_origin = {"origin": "supervisor-disabled", "detail": "none", "association": "bound", "query": "cleanup.none.pp", "worker": "none-recorded"}
        for legacy, extra in ((v1, {}), (v2, {"firstOrigin": first_origin}),
                              (v3, {"firstOrigin": first_origin, "assessmentFailure": {key: value for key, value in assessment.items() if key != "admission"}}),
                              (v4, {"firstOrigin": first_origin, "assessmentFailure": assessment})):
            parsed = lifecycle._shell_label_pair(legacy)
            self.assertEqual(parsed, {"step": "SessionReview", "boundary": "settlement", "bootstrapProgress": "advanced", "session": {**base, **extra}})
        for legacy in (v2, v3, v4):
            old_snapshot = legacy.replace(b";q=cleanup.none.pp;", b";q=unavailable;")
            self.assertEqual(lifecycle._shell_label_pair(old_snapshot)["session"]["firstOrigin"], {**first_origin, "query": "unavailable"})
        plain = prefix.replace(b"SessionReview", b"SelectProject")
        self.assertEqual(lifecycle._shell_label_pair(plain), {"step": "SelectProject", "boundary": "settlement", "bootstrapProgress": "advanced"})
        path = b"MRK_INSTALLED_SHELL_PATH_FAILURE=v1;index=0;reject=not-recorded\n" + plain.replace(b"SelectProject", b"PathActivate")
        self.assertEqual(lifecycle._shell_label_pair(path), {"step": "PathActivate", "boundary": "settlement", "bootstrapProgress": "advanced",
                                                           "path": {"recipeIndex": 0, "rejection": "not-recorded"}})
        # Historical Q unavailable/K readable remains legacy DATA, not a valid v5 state sample.
        self.assertIsNone(lifecycle._shell_label_pair(frame(query=b"unavailable", boundary=b"unavailable")))
        with patch.object(lifecycle, "SHELL_SESSION_FAILURE_V5_FRAME_BOUND", len(raw) - 1):
            self.assertIsNone(lifecycle._shell_label_pair(raw))
            self.assertIsNotNone(lifecycle._shell_label_pair(v4))
        with patch.object(lifecycle, "SHELL_SESSION_FAILURE_V4_FRAME_BOUND", len(v4) - 1):
            self.assertIsNone(lifecycle._shell_label_pair(v4))
            self.assertIsNotNone(lifecycle._shell_label_pair(raw))

    def test_first_unknown_v5_refuses_prefixes_mixed_fields_and_impossible_sentinels(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        prefix = (b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionReview\n"
                  b"MRK_INSTALLED_SHELL_FAILURE_PHASE=settlement\n"
                  b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n"
                  b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v5;index=6;evaluations=13;"
                  b"reject=reply-assessment-unavailable;wait=native-reply-pending;o=supervisor-disabled;d=none;")
        def frame(association=b"bound", query=b"cleanup.none.pp", worker=b"none-recorded", boundary=b"native-observe"):
            return (prefix + b"a=" + association + b";q=" + query + b";w=" + worker
                    + b";ao=bridge;ac=runtime-unavailable;ax=prepare;af=missing-compile-anchor;u=" + boundary + b"\n")
        raw = frame()
        for complete in (raw, frame(boundary=b"not-recorded"), frame(query=b"unavailable", worker=b"unavailable", boundary=b"unavailable"),
                         frame(b"unassociated", b"na", b"na", b"na"), frame(query=b"unregistered", worker=b"na", boundary=b"na")):
            self.assertIsNotNone(lifecycle._shell_label_pair(complete))
            for end in range(len(complete)):
                self.assertIsNone(lifecycle._shell_label_pair(complete[:end]), end)
                if end < len(complete) - 1:
                    self.assertIsNone(lifecycle._shell_label_pair(complete[:end] + b"\n"), end)
        for fields in ((b"unassociated", b"na", b"na", b"not-recorded"), (b"unassociated", b"na", b"na", b"unavailable"),
                       (b"unassociated", b"na", b"na", b"transfer"), (b"unassociated", b"cleanup.none.pp", b"none-recorded", b"not-recorded"),
                       (b"bound", b"na", b"na", b"na"), (b"bound", b"unregistered", b"na", b"not-recorded"),
                       (b"bound", b"unregistered", b"na", b"transfer"), (b"bound", b"unregistered", b"unavailable", b"na"),
                       (b"bound", b"unavailable", b"none-recorded", b"unavailable"), (b"bound", b"unavailable", b"unavailable", b"na"),
                       (b"bound", b"unavailable", b"unavailable", b"not-recorded"), (b"bound", b"unavailable", b"unavailable", b"native-observe"),
                       (b"bound", b"cleanup.none.pp", b"na", b"native-observe"), (b"bound", b"cleanup.none.pp", b"none-recorded", b"na"),
                       (b"bound", b"cleanup.none.pp", b"none-recorded", b"unavailable"), (b"bound", b"cleanup.none.pp", b"unavailable", b"na"),
                       (b"bound", b"cleanup.none.pp", b"unavailable", b"unavailable")):
            self.assertIsNone(lifecycle._shell_label_pair(frame(*fields)), fields)
        for boundary in (b"", b"future", b"Native-observe", b"native_observe", b"native.observe", b"native-observe-extra", b"unavailable\x00", b"/private/input"):
            self.assertIsNone(lifecycle._shell_label_pair(frame(boundary=boundary)), boundary)
        for malformed in (raw + b"\n", raw + raw, raw[:-1] + b";extra=na\n",
                          raw.replace(b";u=native-observe", b""), raw.replace(b";u=", b";u=na;u="), raw.replace(b";u=", b";unknown="),
                          raw.replace(b";af=missing-compile-anchor;u=native-observe", b";u=native-observe;af=missing-compile-anchor"),
                          raw.replace(b";af=", b";af=na;af="), raw.replace(b";af=missing-compile-anchor", b""),
                          raw.replace(b";ao=bridge", b""), raw.replace(b";ax=prepare", b""),
                          raw.replace(b";ac=runtime-unavailable", b";ac=busy"), raw.replace(b";af=missing-compile-anchor", b";af=na"),
                          raw.replace(b";ao=bridge", b";ao=request"), raw.replace(b";u=", b";u=\x00"),
                          raw.replace(b"reject=reply-assessment-unavailable;", b"reject=reply-busy;"),
                          raw.replace(b"index=6;", b"index=06;"), raw.replace(b"evaluations=13;", b"evaluations=129;"),
                          raw.replace(b";q=cleanup.none.pp;", b";q=none.prepare.pp;"), raw.replace(b"\n", b"\r\n")):
            self.assertIsNone(lifecycle._shell_label_pair(malformed))
        for version in (b"v1", b"v2", b"v3", b"v4", b"v6"):
            self.assertIsNone(lifecycle._shell_label_pair(raw.replace(b"=v5;", b"=" + version + b";")))


        # This source correspondence cannot prove GTK readiness or acceptance.

        # Source correspondence is not GTK execution or accepted-path evidence.

        # The actual helper's inert assertions run in the reviewed observer
        # before GTK. Original response, owner and finality evidence is separate.

        # Original GTK signals, destruction, release and joins require native evidence.


        # These are wiring checks, not execution of Rust/GTK/joins. The same
        # helper's deterministic assertions run in the existing observer main;
        # actual native failure-lifecycle coverage still requires its own result.

        # The source contract is not a substitute for the next actual shared
        # normal/observer compiler gate or runtime FD behavior on the host.



class InstalledGitHubReadOnlyRouteContracts(unittest.TestCase):
    def test_github_candidate_cannot_select_android_or_an_arbitrary_skip_route(self):
        # Stop at the first ordinary artifact DATA read; never open a real
        # artifact, compiler, material tree or native program in this test.
        lifecycle = Mock()
        for ref in (S.SHELL_GITHUB_REF, S.SHELL_GITHUB_BOUNDARY_REF):
            with patch.dict(S.os.environ, {"GITHUB_REF": ref}, clear=True), \
                 patch.object(S.D, "read", side_effect=RuntimeError("artifact-data-boundary")) as reading:
                with self.assertRaisesRegex(RuntimeError, "artifact-data-boundary"):
                    S.installed_shell_candidate(Path("/inert"), "a" * 40, lifecycle=lifecycle, github=True)
                reading.assert_called_once()
        lifecycle.assert_not_called()
        for method in ("shell_android_materials", "shell_android_compile_environment", "shell_android_publication_data"):
            getattr(lifecycle, method).assert_not_called()
        for ref, selection, transport in ((S.SHELL_REF, True, None),
                                         (S.SHELL_GITHUB_REF, True, {}),
                                         (S.SHELL_GITHUB_REF, 1, None)):
            with patch.dict(S.os.environ, {"GITHUB_REF": ref}, clear=True), \
                 patch.object(S.D, "read") as reading, self.assertRaises(S.D.Refused):
                S.installed_shell_candidate(Path("/inert"), "a" * 40, lifecycle=lifecycle,
                                            github=selection, local_transport=transport)
            reading.assert_not_called()
        # An omitted GitHub discriminator is a caller/route conflict, not
        # permission to inspect unrelated Android material before refusing.
        with patch.dict(S.os.environ, {"GITHUB_REF": S.SHELL_GITHUB_REF}, clear=True), \
             patch.object(S.D, "read") as reading:
            with self.assertRaisesRegex(S.D.Refused, "GitHub shell candidate requires"):
                S.installed_shell_candidate(Path("/inert"), "a" * 40, lifecycle=lifecycle)
            reading.assert_not_called()
            lifecycle.shell_android_materials.assert_not_called()

    def test_both_fixed_shell_refs_use_only_compile_and_observe_in_the_same_job(self):
        common = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                  "RUNNER_ARCH": "X64", "GITHUB_EVENT_NAME": "push", "GITHUB_JOB": "compile",
                  "MRK_UBUNTU_PUBLICATION_VERIFY": "1", "GITHUB_SHA": "a" * 40, "MRK_PUSH_EVENT_AFTER": "a" * 40,
                  "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "2",
                  "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit"}
        for ref in (S.SHELL_REF, S.SHELL_GITHUB_REF):
            for case in ("compile", "observe"):
                env = {**common, "GITHUB_REF": ref, "MRK_INSTALLED_SHELL_CASE": case}
                self.assertEqual(S.route(env), "a" * 40)
                for change in ({"GITHUB_JOB": "native"}, {"MRK_INSTALLED_CASE": "positive"},
                               {"MRK_INSTALLED_SHELL_CASE": "github-normal-negative"},
                               {"MRK_INSTALLED_SHELL_CASE": True}, {"GITHUB_REF": "refs/heads/main"},
                               {"RUNNER_ENVIRONMENT": "self-hosted"}, {"MRK_UBUNTU_PUBLICATION_VERIFY": False}):
                    with self.subTest(ref=ref, case=case, change=change), self.assertRaises(S.D.Refused):
                        S.route({**env, **change})

    def test_github_branch_uses_the_same_compiler_and_one_service_without_tools_preparation(self):
        argv = S.shell_compile_argv("/compiler", Path("/source"), Path("/target"))
        self.assertEqual(argv[:2], ["/compiler", "build"])
        self.assertEqual(S.SHELL_FEATURES, ["custom-protocol", "desktop-shell"])
        self.assertEqual(argv[argv.index("--features") + 1], "desktop-shell,custom-protocol")
        self.assertIn("--no-default-features", argv)


class InstalledGitHubNormalBoundaryRouteContracts(unittest.TestCase):

    def test_fixed_new_ref_has_only_existing_compile_observe_and_material_helper_routes(self):
        repository, ref, sha = "Apdelrahman1911/mobile-release-kit", S.SHELL_GITHUB_BOUNDARY_REF, "a" * 40
        common = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                  "RUNNER_ARCH": "X64", "GITHUB_EVENT_NAME": "push", "GITHUB_JOB": "compile",
                  "MRK_UBUNTU_PUBLICATION_VERIFY": "1", "GITHUB_SHA": sha, "MRK_PUSH_EVENT_AFTER": sha,
                  "GITHUB_WORKFLOW_SHA": sha, "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "2",
                  "GITHUB_REPOSITORY": repository, "GITHUB_REF": ref,
                  "GITHUB_WORKFLOW_REF": repository + "/.github/workflows/desktop-ubuntu-publication.yml@" + ref,
                  "ImageOS": "ubuntu24", "ImageVersion": "20260922.1.1"}
        policy, python_data = S.local("hosted_glibc_policy"), S.local("observe_hosted_python")
        for case in ("compile", "observe"):
            env = {**common, "MRK_INSTALLED_SHELL_CASE": case}
            self.assertEqual(S.route(env), sha)
            self.assertEqual(python_data.context(env)["GITHUB_REF"], ref)
            if case == "compile":
                self.assertEqual(policy.context(env)["GITHUB_REF"], ref)
            else:
                with self.assertRaises(policy.Refused):
                    policy.context(env)
            for change in ({"GITHUB_REF": ref + "-arbitrary"}, {"MRK_INSTALLED_SHELL_CASE": "github-normal-negative"},
                           {"GITHUB_JOB": "boundary"}, {"GITHUB_EVENT_NAME": "workflow_dispatch"},
                           {"MRK_INSTALLED_SHELL_CASE": True}):
                with self.subTest(case=case, change=change), self.assertRaises((S.D.Refused, KeyError)):
                    S.route({**env, **change})
                with self.assertRaises(python_data.Refused):
                    python_data.context({**env, **change})
                with self.assertRaises(policy.Refused):
                    policy.context({**env, **change})


class InstalledOrdinary21Contracts(unittest.TestCase):
    """The existing inert compiler/artifact/closed-DATA seams, not a runner."""
    def setUp(self):
        self.lifecycle = S.local("ubuntu_publication_lifecycle")
        self.selection = self.lifecycle.shell_ordinary_selection()
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.guards = []
        for module, names in ((self.lifecycle, ("shell_android_materials", "shell_android_compile_environment",
                "shell_android_publication_data", "bind_shell_android_profile", "service_argv", "verify_service_result")),
                (S, ("Check", "prepare", "resumed_preparation", "package_inputs", "installed_u_inputs",
                     "android_stage_local_inputs", "shell_native_inputs", "installed_shell_os_inputs"))):
            for name in names:
                self.guards.append(self.stack.enter_context(patch.object(module, name,
                    side_effect=AssertionError("No preparation, compiler, native or Android work in inert ordinary21 tests"))))
        self.guards.append(self.stack.enter_context(patch.object(S.subprocess, "Popen", side_effect=AssertionError("No subprocess"))))

    def tearDown(self):
        for guard in self.guards: guard.assert_not_called()

    def environment(self):
        return {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
            "GITHUB_EVENT_NAME": "push", "GITHUB_REF": S.SHELL_REF, "GITHUB_JOB": "compile", "MRK_UBUNTU_PUBLICATION_VERIFY": "1",
            "GITHUB_SHA": "a" * 40, "MRK_PUSH_EVENT_AFTER": "a" * 40, "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit", "MRK_INSTALLED_SHELL_CASE": "compile",
            "MRK_INSTALLED_SHELL_SCOPE": "ordinary21-v1", "MRK_INSTALLED_SHELL_TRANSPORT": "actions-artifact-v1",
            "MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256": hashlib.sha256((SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_bytes()).hexdigest()}

    def artifact(self, work, change=None):
        env, elf, inputs = transport_data(work)
        artifact = work / "admitted-shell"
        for name in ("compiler.json", "source.json", "result.json"):
            record = S.D.decode((artifact / name).read_bytes())
            record["ordinary21"] = deepcopy(self.selection)
            if name != "source.json":
                record.update(androidBuildMaterials=None, androidBuildBindings={}, androidBuildPublication=None)
            if change is not None: change(name, record)
            (artifact / name).write_bytes(S.D.canonical(record))
        roster = S.D.decode((artifact / "shell-roster.json").read_bytes())
        roster["files"] = [S.D.file_record(path) for path in sorted(artifact.iterdir()) if path.name != "shell-roster.json"]
        raw = S.D.canonical(roster); (artifact / "shell-roster.json").write_bytes(raw)
        return {**self.environment(), **env, "MRK_INSTALLED_SHELL_ROSTER_SHA256": hashlib.sha256(raw).hexdigest()}, elf, inputs

    def test_scope_requires_exact_artifact_ref_and_never_defaults_to_ordinary21(self):
        env = self.environment()
        with patch.dict(S.os.environ, env, clear=True):
            self.assertEqual(S.installed_shell_scope(self.lifecycle), self.selection)
            self.assertEqual(S.preparation_route()["ordinary21"], self.selection)
        for change in ({"MRK_INSTALLED_SHELL_SCOPE": "ordinary20-v1"}, {"MRK_INSTALLED_SHELL_SCOPE": "full25"},
                       {"MRK_INSTALLED_SHELL_TRANSPORT": "android-same-job-local-v1"},
                       {"MRK_INSTALLED_SHELL_TRANSPORT": ""}, {"MRK_INSTALLED_SHELL_LOCAL_TRANSPORT_SHA256": "1" * 64},
                       {"GITHUB_REF": S.SHELL_GITHUB_REF}, {"GITHUB_REF": S.SHELL_GITHUB_BOUNDARY_REF}, {"GITHUB_REF": "refs/heads/main"}):
            with self.subTest(change=change), patch.dict(S.os.environ, {**env, **change}, clear=True), self.assertRaises(S.D.Refused):
                S.installed_shell_scope(self.lifecycle)
        for absent in ({}, {"MRK_INSTALLED_SHELL_SCOPE": ""}):
            with patch.dict(S.os.environ, absent, clear=True): self.assertIsNone(S.installed_shell_scope(self.lifecycle))

    def test_scope_records_require_present_null_empty_null_and_same_remaining_four(self):
        original = {"ordinary21": deepcopy(self.selection), "androidBuildMaterials": None,
                    "androidBuildBindings": {}, "androidBuildPublication": None}
        S.installed_shell_scope_record(original, self.lifecycle, self.selection, android_contract=True)
        for field, replacement in (("ordinary21", None), ("ordinary21", {}),
                ("androidBuildMaterials", {}), ("androidBuildBindings", []), ("androidBuildPublication", {}),
                ("remainingRequiredCases", []), ("androidPreparation", None), ("androidOsContractInput", {}),
                ("localTransport", {}), ("githubReadOnly", {}), ("androidBuild", {}), ("androidPublication", {})):
            with self.subTest(field=field), self.assertRaises(S.D.Refused):
                S.installed_shell_scope_record({**original, field: replacement}, self.lifecycle, self.selection, android_contract=True)
        for field in original:
            changed = deepcopy(original); changed.pop(field)
            with self.subTest(missing=field), self.assertRaises(S.D.Refused):
                S.installed_shell_scope_record(changed, self.lifecycle, self.selection, android_contract=True)
        with self.assertRaises(S.D.Refused): S.installed_shell_scope_record(original, self.lifecycle, None)
        with self.assertRaises(S.D.Refused): S.installed_shell_scope_record({}, self.lifecycle, self.selection)

    def test_actual_read_only_source_admission_uses_current_pins_without_android_or_an_owner(self):
        def local(name):
            self.assertEqual(name, "ubuntu_publication_lifecycle"); return self.lifecycle
        with patch.dict(S.os.environ, self.environment(), clear=True), patch.object(S, "local", side_effect=local), \
             patch.object(self.lifecycle, "check_source_pins", wraps=self.lifecycle.check_source_pins) as pins, \
             patch.object(S.sys, "stdout", new=io.StringIO()):
            result = S.installed_shell_source_admission()
            self.assertEqual(result, {"sourceSha": "a" * 40, "ordinary21": self.selection})
            pins.assert_called_once_with(SOURCE, android=False)

    def test_source_admission_refuses_stale_entry_or_source_before_any_preparation(self):
        env = self.environment()
        with patch.object(S, "local", return_value=self.lifecycle), patch.object(S, "shell_source_manifest") as manifest:
            with patch.dict(S.os.environ, {**env, "MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256": "0" * 64}, clear=True), self.assertRaises(S.D.Refused):
                S.installed_shell_source_admission()
            with patch.dict(S.os.environ, env, clear=True), patch.dict(self.lifecycle.CORE_PINS,
                    {"__init__.py": (self.lifecycle.CORE_PINS["__init__.py"][0], "0" * 64)}), self.assertRaises(self.lifecycle.Refused):
                S.installed_shell_source_admission()
            manifest.assert_not_called()

    def test_compiler_and_consumer_check_scope_before_original_owner_or_android_entry(self):
        for entry, case in ((S.verify_installed_shell_compile, "compile"), (S.verify_installed_shell, "observe")):
            with self.subTest(case=case), patch.object(S, "local", return_value=self.lifecycle):
                env = {**self.environment(), "MRK_INSTALLED_SHELL_CASE": case, "MRK_INSTALLED_SHELL_SCOPE": "unexpected"}
                with patch.dict(S.os.environ, env, clear=True), self.assertRaises(S.D.Refused): entry()
                env["MRK_INSTALLED_SHELL_SCOPE"] = "ordinary21-v1"
                with patch.dict(S.os.environ, env, clear=True), \
                     patch.object(S, "resumed_preparation", side_effect=RuntimeError("original-owner-boundary")) as original:
                    with self.assertRaisesRegex(RuntimeError, "original-owner-boundary"): entry()
                    original.assert_called_once()

    def test_artifact_admission_checks_actual_original_pair_with_no_android_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); env, elf, inputs = self.artifact(work)
            with patch.dict(S.os.environ, env, clear=True), patch.object(S, "elf_dependencies", return_value=elf), \
                 patch.object(S, "shell_source_manifest", return_value=inputs):
                binaries, compiler, _, digest, producer, artifact = S.installed_shell_candidate(
                    work, "a" * 40, lifecycle=self.lifecycle, ordinary=self.selection)
                self.assertEqual(set(binaries), {"normal", "observer"})
                self.assertEqual((producer, artifact, digest), ("1", "17", env["MRK_INSTALLED_SHELL_ROSTER_SHA256"]))
                self.assertEqual(compiler["ordinary21"], self.selection)
                with self.assertRaises(S.D.Refused): S.installed_shell_candidate(work, "a" * 40, lifecycle=self.lifecycle)

    def test_artifact_rejects_mixed_missing_or_downgraded_source_compiler_and_result_scopes(self):
        mutations = [(name, "ordinary21", "missing") for name in ("source.json", "compiler.json", "result.json")]
        mutations += [(name, key, value) for name in ("compiler.json", "result.json") for key, value in (
            ("ordinary21", None), ("androidBuildMaterials", "missing"), ("androidBuildBindings", "missing"),
            ("androidBuildPublication", "missing"), ("androidBuildMaterials", {}), ("androidBuildBindings", {"MRK_ANDROID_TOOL_INSTANCE": "x"}),
            ("androidBuildPublication", {}), ("androidPreparation", {}), ("androidOsContractInput", {}), ("githubReadOnly", {}))]
        for target, key, value in mutations:
            def change(name, record):
                if name != target: return
                if value == "missing": record.pop(key)
                else: record[key] = value
            with self.subTest(target=target, key=key), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); env, elf, inputs = self.artifact(work, change)
                with patch.dict(S.os.environ, env, clear=True), patch.object(S, "elf_dependencies", return_value=elf), \
                     patch.object(S, "shell_source_manifest", return_value=inputs), self.assertRaises(S.D.Refused):
                    S.installed_shell_candidate(work, "a" * 40, lifecycle=self.lifecycle, ordinary=self.selection)

    def test_ordinary_closed_consumer_preserves_all_common_receipts_and_exact172_exports(self):
        observed = closed_project_draft_data(self.lifecycle, ordinary=self.selection)
        self.assertEqual(len(observed["files"]), 172)
        result = S.shell_project_draft_observation(observed, self.lifecycle, ordinary=self.selection)
        self.assertEqual(result, observed["projectDraft"])
        self.assertIsNone(self.lifecycle.SHELL_ANDROID_MATERIALS)
        self.assertEqual(observed["cases"]["settled-failure"]["exitCode"], 1)

    def test_closed_consumer_rejects_other_scopes_partial_cases_files_and_relabelled_placeholders(self):
        observed = closed_project_draft_data(self.lifecycle, ordinary=self.selection)
        for fault in ("scope-missing", "scope-changed", "old-state", "android", "github", "file-missing", "file-extra", "file-duplicate",
                      "placeholder-empty", "placeholder-before", "case-pin", *self.selection["cases"], "android-build", "github-synthetic"):
            changed = deepcopy(observed)
            if fault == "scope-missing": changed.pop("ordinary21")
            elif fault == "scope-changed": changed["ordinary21"]["remainingRequiredCases"] = []
            elif fault == "old-state": changed["state"] = "normal-shell-installed-runtime-connection-observed"
            elif fault == "android": changed["androidBuild"] = {}
            elif fault == "github": changed["githubReadOnly"] = {}
            elif fault == "file-missing": changed["files"].pop()
            elif fault == "file-extra": changed["files"].append({"path": "lifecycle-shell-android-build.stdout", "size": 0, "sha256": "f" * 64})
            elif fault == "file-duplicate": changed["files"][-1] = deepcopy(changed["files"][0])
            elif fault == "placeholder-empty": changed["namespacePlaceholders"]["empty"] = False
            elif fault == "placeholder-before": changed["namespacePlaceholders"]["before"]["sha256"] = "f" * 64
            elif fault == "case-pin": next(row for row in changed["files"] if row["path"] == "lifecycle-shell-cases.json")["sha256"] = "f" * 64
            elif fault in self.selection["cases"]: changed["cases"].pop(fault)
            else: changed["cases"][fault] = {"case": fault, "exitCode": 0}
            with self.subTest(fault=fault), self.assertRaises(S.D.Refused):
                S.shell_project_draft_observation(changed, self.lifecycle, ordinary=self.selection)
        with self.assertRaises(S.D.Refused): S.shell_project_draft_observation(observed, self.lifecycle)
        observed.pop("ordinary21"); observed["state"] = "normal-shell-installed-runtime-connection-observed"
        with self.assertRaises(S.D.Refused): S.shell_project_draft_observation(observed, self.lifecycle)


if __name__ == "__main__":
    unittest.main()
