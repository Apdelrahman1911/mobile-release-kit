"""Inert shell compiler/transport contracts; no compiler, GUI or process launch."""
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
        {"id": "root", "name": "mobile-release-kit-desktop", "version": "0.1.0", "source": None,
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
             'cfg(all(target_os = "macos", target_arch = "aarch64"))'),
            ("mrk-windows-installed-native", "windows-installed-native",
             'cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))'),
        )
    ]
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

    def test_same_vm_workflow_requires_original_compile_upload_and_cleanup_handoff(self):
        workflow = (SOURCE / S.WORKFLOW).read_text()
        self.assertEqual(workflow.count("uses: actions/checkout@"), 1)
        self.assertNotIn("\n  native:\n", workflow)
        self.assertNotIn("needs.compile", workflow)
        native = workflow.split("      - name: Require the fixed disposable native route", 1)[1]
        self.assertNotIn("apt-get", native)
        self.assertNotIn("prepare_hosted_ubuntu_data.py", native)
        for step in native.split("      - name:"):
            self.assertIn("if:", step)
            if "if: always()" not in step:
                self.assertIn("steps.compile.outcome == 'success' && steps.upload.outcome == 'success'", step)
        self.assertIn("artifact-ids: ${{ steps.upload.outputs.artifact-id }}", native)
        self.assertIn("path: ${{ steps.prepare_native.outputs.root }}/work/admitted-shell", native)
        self.assertIn("MRK_INSTALLED_SHELL_CASE: observe", native)
        # These ordering checks supplement the actual cleanup/transport controls
        # above; the real owner/native path still requires hosted verification.
        source = (SOURCE / "desktop/tools/ci_ubuntu_publication.py").read_text()
        compile_body = source.split("def verify_installed_shell_compile():", 1)[1].split("\ndef verify(", 1)[0]
        milestones = [compile_body.index(text) for text in (
            'check.phase = "shell-generated-cleanup"', 'source_check("clean")',
            'shell_remove_owned_directory(work,', 'D.write(public / "result.json"',
            'D.write(public / "shell-roster.json"', 'output.write("shell_roster_sha256=')]
        self.assertEqual(milestones, sorted(milestones))
        self.assertIn('all(row["ordinaryOwnerReturned"] is True for row in check.commands)', compile_body)
        self.assertIn('shell_source_status(status.stdout, generated)', compile_body)

    def test_paired_shell_source_manifest_binds_the_changed_session_modules(self):
        # Source-only correspondence: no Cargo, native imports or source run.
        tree = ast.parse((SOURCE / "desktop/tools/ci_ubuntu_publication.py").read_text())
        manifest = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "shell_source_manifest")
        paths = next(node.value for node in manifest.body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == "paths" for target in node.targets))
        names = ast.literal_eval(paths)
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue({"desktop/src-tauri/src/" + name + ".rs" for name in (
            "runtime", "bridge", "asset_session", "asset_source", "shell", "installed_shell_observation",
            "supervisor", "installed_shell_shutdown_observation", "error", "protocol", "installed_runtime",
            "passive_management_tests", "credential_assessment", "installed_tools_observation", "environment_diagnostics_owner",
            "environment_diagnostics_protocol", "saved_command_owner", "offline_preflight_owner", "offline_preflight_protocol")} <= set(names))
        self.assertTrue({"desktop/src-tauri/src/main.rs", "desktop/src-tauri/tests/installed_shell_observation.rs"} <= set(names))
        self.assertTrue({"desktop/src/components/EnvironmentDiagnostics.tsx", "desktop/tests/environment-diagnostics.test.mjs"} <= set(names))

    def test_observer_module_roster_matches_production_supported_platforms(self):
        # The actual-main observer has its own crate root. Library compilation
        # alone cannot detect a missing path-included module in that target.
        root = SOURCE / "desktop/src-tauri"
        library = (root / "src/lib.rs").read_text()
        main = (root / "src/main.rs").read_text()
        observer = (root / "tests/installed_shell_observation.rs").read_text()
        production = set(re.findall(r"^(?:pub )?mod ([a-z0-9_]+);$", library, re.MULTILINE))
        observed = set(re.findall(r'^#\[path = "\.\./src/[^"\n]+\.rs"\] mod ([a-z0-9_]+);$', observer, re.MULTILINE))
        self.assertEqual(production - observed, {"installed_runtime_windows", "runtime_publication"})
        self.assertEqual(observed - production, set())
        guard = '#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]\n'
        self.assertIn(guard + 'mod vault_keyring_linux;', library)
        self.assertIn(guard + '#[path = "../src/vault_keyring_linux.rs"] mod vault_keyring_linux;', observer)
        self.assertEqual(observer.count('mod vault_keyring_linux;'), 1)
        self.assertIn('mobile_release_desktop::shell::run()', main)
        self.assertIn('#![forbid(unsafe_code)]', observer)
        self.assertIn('all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",', observer)
        self.assertIn('not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")', observer)
        self.assertIn('fn main() -> std::process::ExitCode { shell::installed_observation::main() }', observer)

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
        changes = (
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
        self.assertEqual(len(declared), 7)
        self.assertEqual({row["name"] for row in declared},
                         {"mrk-linux-mount-observation", "mrk-macos-installed-native", "mrk-windows-installed-native",
                          "secret-service", "zbus"})
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
            ("kind", "dev"), ("kind", "build"), ("kind", 0),
            ("req", "^0.1.0"), ("req", True),
            ("rename", "unreviewed_alias"), ("rename", 0),
            ("registry", "https://unreviewed.invalid/index"), ("registry", False),
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

    def test_transport_refuses_relabelled_profiles_execution_or_copied_identity(self):
        changes = (
            lambda compiler, result, native, rows: compiler.update(features=["desktop-shell"]),
            lambda compiler, result, native, rows: compiler.update(attempt="2"),
            lambda compiler, result, native, rows: compiler.update(sourceTree="d" * 40),
            lambda compiler, result, native, rows: result.update(shellExecuted=True),
            lambda compiler, result, native, rows: result.update(observerExecuted=True),
            lambda compiler, result, native, rows: result.update(packageBuilt=True),
            lambda compiler, result, native, rows: result.update(cargoBuilds=True),
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

    def test_shell_handoff_phase_and_compaction_precede_only_the_shell_service(self):
        tree = ast.parse((SOURCE / "desktop/tools/ci_ubuntu_publication.py").read_text())
        entry = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "verify_installed_shell")
        calls = [node for node in ast.walk(entry) if isinstance(node, ast.Call)]

        def line(name):
            rows = [node.lineno for node in calls if (isinstance(node.func, ast.Name) and node.func.id == name
                    or isinstance(node.func, ast.Attribute) and node.func.attr == name)]
            self.assertEqual(len(rows), 1, name)
            return rows[0]

        phases = [node.lineno for node in ast.walk(entry) if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                          and target.value.id == "check" and target.attr == "phase" for target in node.targets)
                  and isinstance(node.value, ast.Constant) and node.value.value == "shell-handoff"]
        self.assertEqual(len(phases), 1)
        self.assertLess(line("installed_shell_os_inputs"), phases[0])
        self.assertLess(phases[0], line("compact_shell_loader_policy"))
        self.assertLess(line("compact_shell_loader_policy"), line("shell_handoff_bytes"))
        self.assertLess(line("shell_handoff_bytes"), line("service_argv"))
        installed = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "verify_installed")
        self.assertFalse(any(isinstance(node, ast.Call) and (isinstance(node.func, ast.Name) and node.func.id == "shell_handoff_bytes"
                             or isinstance(node.func, ast.Attribute) and node.func.attr == "compact_shell_loader_policy")
                             for node in ast.walk(installed)))


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


def closed_project_draft_data(lifecycle):
    """Synthetic closed-result schema DATA only; no native/finality claim."""
    receipt = deepcopy(lifecycle.SHELL_PROJECT_RECEIPT)
    fixture = {"fixture": "android-saved-readonly-v1", "rootRetained": True, "hintUnchanged": True,
               "savedOutputsMatched": True, "noUnexpectedEntries": True, "noPendingState": True,
               "entryCount": 7, "sourceBytes": len(lifecycle.SHELL_PROJECT_SOURCE) + len(lifecycle.SHELL_PROJECT_VERSION), "releaseMode": 0o755,
               "config": {"size": len(lifecycle.SHELL_PROJECT_CONFIG), "sha256": hashlib.sha256(lifecycle.SHELL_PROJECT_CONFIG).hexdigest(), "mode": 0o600},
               "gitignore": {"size": len(lifecycle.SHELL_PROJECT_IGNORE), "sha256": hashlib.sha256(lifecycle.SHELL_PROJECT_IGNORE).hexdigest(), "mode": 0o600},
               "before": {"size": 512, "sha256": "a" * 64}, "after": {"size": 1024, "sha256": "b" * 64}}
    candidate = deepcopy(lifecycle.SHELL_CANDIDATE_RECEIPT)
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
                             "maps": [], "projectDraft": receipt, "candidateDocuments": candidate},
                "quit-outstanding": {"case": "quit-outstanding", "exitCode": 0, "bootstrapReturned": False,
                                     "domAndGtkObserved": True, "maps": [[{"DATA": True}]]},
                "project-paths": {"case": "project-paths", "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True,
                                  "maps": [], "projectPaths": paths},
                "workflow-apply": {"case": "workflow-apply", "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True,
                                   "maps": [], "workflowApply": workflows},
                "metadata-save": {"case": "metadata-save", "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True,
                                  "maps": [], "metadataSave": metadata},
            }, "projectDraft": {"native": deepcopy(receipt), "fixture": fixture},
            "candidateDocuments": {"native": deepcopy(candidate), "fixture": candidate_fixture},
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
        fixture = {"fixture": "four-kind-session-v1", "case": case, "rootRetained": True, "originalsAccounted": True,
            "projectUnchanged": True, "sourcesOutsideProject": True, "noUnexpectedEntries": True, "noPendingState": True,
            "beforeCount": 15 if changed else 9, "afterCount": 14 if changed else 9,
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
    return observed


class InstalledProjectDraftReceiptContracts(unittest.TestCase):
    def test_consumes_one_combined_positive_only_after_matching_closed_export_pins(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        observed = closed_project_draft_data(lifecycle)
        result = S.shell_project_draft_observation(observed, lifecycle)
        self.assertEqual(result, observed["projectDraft"])
        self.assertEqual(result["native"]["schemaVersion"], 3)
        self.assertEqual(result["native"]["fixture"], "android-saved-readonly-v1")
        self.assertEqual(result["native"]["methods"], "twelve-passive")
        self.assertEqual(result["native"]["quit"]["operation"], 6)
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
        self.assertEqual(len(encoded), 2041)
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), "9896be85da12227c4920d61c65a0c50d6701ca4ae5c405a6d5c6a072a133d9af")
        self.assertLessEqual(len(encoded), 2048)
        self.assertTrue(result["fixture"]["savedOutputsMatched"])
        self.assertTrue(result["fixture"]["hintUnchanged"])
        self.assertEqual(result["fixture"]["entryCount"], 7)
        self.assertEqual(result["fixture"]["sourceBytes"], 149)
        self.assertNotEqual(result["fixture"]["before"], result["fixture"]["after"])
        self.assertEqual(set(observed["cases"]), {"normal", "positive", "quit-outstanding", "project-paths", "workflow-apply",
                                                "session-inputs", "session-refusals", "session-loss", "session-deadline", "metadata-save",
                                                "tools-observed", "tools-cancel", "tools-settlement", "offline-pass", "offline-negative",
                                                "offline-drift", "offline-cancel", "offline-settlement"})

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
        )
        for mutate in mutations:
            observed = closed_project_draft_data(lifecycle); mutate(observed)
            with self.subTest(mutate=mutate), self.assertRaises((S.D.Refused, ValueError)):
                S.shell_project_draft_observation(observed, lifecycle)

        expected = lifecycle.SHELL_PROJECT_RECEIPT
        variants = {
            "legacy-v2": {**expected, "schemaVersion": 2},
            "prior-R-v3": {**expected, "methods": "eleven-passive", "quit": {**expected["quit"], "operation": 3}},
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
    def test_candidate_is_a_separate_bounded_companion_not_replacement_project_proof(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        observed = closed_project_draft_data(lifecycle)
        self.assertEqual(S.shell_project_draft_observation(observed, lifecycle), observed["projectDraft"])
        candidate = observed["candidateDocuments"]
        self.assertEqual(candidate["native"], observed["cases"]["positive"]["candidateDocuments"])
        raw = lifecycle.canonical(candidate["native"])
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()),
                         (1069, "e7a6cf04edfd5b331ca0a2e8fa8afab42d1fdfda1a6cbc40c979188679ac5902"))
        self.assertLessEqual(len(raw), 2048)
        self.assertEqual([candidate["native"][key]["operation"] for key in ("cancel", "select", "observe", "quit")], [3, 4, 5, 6])
        self.assertTrue(candidate["native"]["cancel"]["probeUnstarted"])
        self.assertTrue(candidate["native"]["cancel"]["tokenJoined"])
        self.assertEqual(candidate["native"]["observe"]["requests"], 1)
        self.assertEqual(candidate["native"]["scope"], {"documents": 3, "formatsDigestsBindingsMatched": True,
            "artifactPayloadsObserved": False, "sourceCompared": False, "signingVerified": False,
            "storeObserved": False, "releaseReady": False, "recoveryAuthority": False})
        fixture = candidate["fixture"]
        self.assertEqual((fixture["entryCount"], fixture["documentBytes"], fixture["directoryMode"], fixture["fileMode"]), (5, 11366, 0o700, 0o600))
        self.assertEqual(fixture["before"], fixture["after"])
        expected_exports = ["lifecycle-shell-" + family + "-" + phase + ".json"
                            for family in ("positive-project", "positive-candidate", "project-paths",
                                           "workflow-apply", "metadata-save", "session-inputs",
                                           "session-refusals", "session-loss", "session-deadline", *lifecycle.SHELL_TOOLS_OFFLINE_CASES)
                            for phase in ("before", "after")]
        self.assertCountEqual([item["path"] for item in observed["files"]], expected_exports)
        # Only this shell profile allows160 originals plus the same client's
        # two captures. The non-shell128 and aggregate32MiB caps do not change.
        observed["files"].extend({"path": "inert-" + str(index), "size": 0, "sha256": "0" * 64}
                                 for index in range(162 - len(observed["files"])))
        self.assertEqual(len(observed["files"]), 162)
        S.shell_project_draft_observation(observed, lifecycle)
        observed["files"].append({"path": "over-cap", "size": 0, "sha256": "0" * 64})
        self.assertEqual(len(observed["files"]), 163)
        with self.assertRaises(S.D.Refused):
            S.shell_project_draft_observation(observed, lifecycle)

    def test_missing_partial_extra_or_nonpositive_candidate_receipts_refuse(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        mutations = (
            lambda v: v.pop("candidateDocuments"), lambda v: v["cases"]["positive"].pop("candidateDocuments"),
            lambda v: v["candidateDocuments"].pop("native"), lambda v: v["candidateDocuments"].pop("fixture"),
            lambda v: v["candidateDocuments"].update(extra=True),
            lambda v: v["cases"]["positive"].update(candidateDocuments=[]),
            lambda v: v["candidateDocuments"].update(native={}),
            lambda v: v["candidateDocuments"]["native"].update(selectionId="unbound"),
            lambda v: v["candidateDocuments"]["native"].update(scope={"documents": 3}),
            lambda v: v["candidateDocuments"]["native"].pop("preserved"),
            lambda v: v["candidateDocuments"]["native"].pop("quit"),
            lambda v: v["cases"]["normal"].update(candidateDocuments=deepcopy(lifecycle.SHELL_CANDIDATE_RECEIPT)),
            lambda v: v["cases"]["quit-outstanding"].update(candidateDocuments=deepcopy(lifecycle.SHELL_CANDIDATE_RECEIPT)),
        )
        for mutate in mutations:
            observed = closed_project_draft_data(lifecycle); mutate(observed)
            with self.subTest(mutate=mutate), self.assertRaises((S.D.Refused, ValueError)):
                S.shell_project_draft_observation(observed, lifecycle)

    def test_each_candidate_leaf_requires_typed_original_correspondence_on_both_copies(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        expected = lifecycle.SHELL_CANDIDATE_RECEIPT
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
                    parent[path[-1]] = not original if type(original) is bool else original + 1 if type(original) is int else original + "-other"
                for side in ("case", "native", "both"):
                    observed = closed_project_draft_data(lifecycle)
                    if side in {"case", "both"}:
                        observed["cases"]["positive"]["candidateDocuments"] = deepcopy(changed)
                    if side in {"native", "both"}:
                        observed["candidateDocuments"]["native"] = deepcopy(changed)
                    with self.subTest(path=path, mode=mode, side=side), self.assertRaises((S.D.Refused, ValueError)):
                        S.shell_project_draft_observation(observed, lifecycle)

    def test_candidate_fixture_flags_bytes_and_both_original_export_pins_are_mandatory(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        mutations = (
            lambda v: v["candidateDocuments"].update(fixture=[]),
            lambda v: v["candidateDocuments"]["fixture"].update(fixture="android-saved-readonly-v1"),
            lambda v: v["candidateDocuments"]["fixture"].update(rootRetained=1),
            lambda v: v["candidateDocuments"]["fixture"].update(documentsUnchanged=False),
            lambda v: v["candidateDocuments"]["fixture"].update(noUnexpectedEntries=False),
            lambda v: v["candidateDocuments"]["fixture"].update(artifactTargetsAbsent=False),
            lambda v: v["candidateDocuments"]["fixture"].update(entryCount=True),
            lambda v: v["candidateDocuments"]["fixture"].update(entryCount=6),
            lambda v: v["candidateDocuments"]["fixture"].update(documentBytes=0),
            lambda v: v["candidateDocuments"]["fixture"].update(directoryMode=0o755),
            lambda v: v["candidateDocuments"]["fixture"].update(fileMode=0o644),
            lambda v: v["candidateDocuments"]["fixture"].update(extra=True),
            lambda v: v["candidateDocuments"]["fixture"]["documents"].pop(),
            lambda v: v["candidateDocuments"]["fixture"]["documents"].reverse(),
            lambda v: v["candidateDocuments"]["fixture"]["documents"][0].update(sha256="f" * 64),
            lambda v: v["candidateDocuments"]["fixture"]["documents"][0].update(size=True),
            lambda v: v["candidateDocuments"]["fixture"]["documents"][0].update(path="reader-1.2.3-42.aab"),
            lambda v: v["candidateDocuments"]["fixture"]["before"].update(size=8193),
            lambda v: v["candidateDocuments"]["fixture"]["before"].update(size=True),
            lambda v: v["candidateDocuments"]["fixture"]["after"].update(sha256="unbound"),
            lambda v: v["candidateDocuments"]["fixture"]["after"].update(extra=True),
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
        observed["candidateDocuments"]["fixture"]["after"]["sha256"] = "f" * 64
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


class InstalledSessionReceiptContracts(unittest.TestCase):
    def test_all_four_session_receipts_remain_distinct_from_ordinary_twelve_methods(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        observed = closed_project_draft_data(lifecycle)
        result = S.shell_project_draft_observation(observed, lifecycle)
        self.assertEqual(result["native"]["methods"], "twelve-passive")
        for name in lifecycle.SHELL_SESSION_CASES:
            receipt = observed["sessionInputs"][name]["native"]
            self.assertEqual(receipt["case"], name)
            self.assertEqual(receipt["methods"], "thirteen-passive-including-supplied-input-assessment")
            self.assertEqual(receipt["profile"], "installed-linux-session-inputs")
            self.assertEqual(len(observed["cases"][name]["maps"]), receipt["behavior"]["assessments"])
            self.assertTrue(all(len(rows) == 6 for rows in observed["cases"][name]["maps"]))
            self.assertEqual(receipt["safety"], {"persistentStorage": False, "storeContacted": False, "signingVerified": False, "releaseReady": False})
            self.assertTrue(all(value is True for value in receipt["originals"].values()))

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


class InstalledToolsOfflineReceiptContracts(unittest.TestCase):
    def test_eight_closed_engineering_cases_preserve_negative_refused_and_no_child_facts(self):
        lifecycle = S.local("ubuntu_publication_lifecycle"); observed = closed_project_draft_data(lifecycle)
        self.assertEqual(S.shell_project_draft_observation(observed, lifecycle), observed["projectDraft"])
        self.assertEqual(len(observed["cases"]), 18)
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

    def test_source_consumes_tools_before_and_after_the_same_single_lifecycle(self):
        source = (SOURCE / "desktop/tools/ci_ubuntu_publication.py").read_text()
        tree = ast.parse(source)
        entry = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "verify_installed_shell")
        calls = [node for node in ast.walk(entry) if isinstance(node, ast.Call)]
        binds = sorted(node.lineno for node in calls if isinstance(node.func, ast.Name) and node.func.id == "shell_tools_inputs_for_observation")
        endpoint = [node.lineno for node in calls if isinstance(node.func, ast.Attribute) and node.func.attr == "verify_service_result"]
        self.assertEqual(len(binds), 2); self.assertEqual(len(endpoint), 1)
        self.assertLess(binds[0], endpoint[0]); self.assertLess(endpoint[0], binds[1])
        text = ast.get_source_segment(source, entry)
        for token in ('"toolsOfflineQualificationOnly": True', '"offlineFullWorkDeadlineExercised": False', '"qualified": False',
                      '"compilerRerun": False', '"supplierRebuilt": False', '"packageBuilt": False', '"upgradeOrRefusalRerun": False'):
            self.assertIn(token, text)
        for forbidden in ("apt-get", "update-alternatives", "shell_tools_input_snapshot(", "offline_preflight_owner_tests"):
            self.assertNotIn(forbidden, text)


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


class InstalledToolsPreparationContracts(unittest.TestCase):
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
            env, root, identity, nodes, files = tools_preparation_data()
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
            env, root, identity, nodes, files = tools_preparation_data()
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
                 patch.object(S.D, "read", side_effect=lambda path, limit: files[path.name]):
                if fault in (None, "directory-time"):
                    observed = S.shell_tools_inputs_for_observation(); self.assertIs(observed["qualified"], False)
                    self.assertEqual(len(observed["preparationFiles"]), 8)
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

    def test_preparation_helpers_own_no_process_runner_or_package_commands(self):
        tree = ast.parse((SOURCE / "desktop/tools/ci_ubuntu_publication.py").read_text())
        helpers = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name.startswith(("shell_tools_input", "_shell_tools_input", "shell_tools_package"))]
        self.assertEqual(len(helpers), 6)
        for helper in helpers:
            forbidden = [node for node in ast.walk(helper) if isinstance(node, (ast.Import, ast.ImportFrom)) or isinstance(node, ast.Call)
                         and (isinstance(node.func, ast.Name) and node.func.id in ("Check", "run_owned", "command")
                              or isinstance(node.func, ast.Attribute) and node.func.attr in ("run", "Popen", "command", "system", "execv"))]
            self.assertEqual(forbidden, [], helper.name)


class InstalledFailureLabelSourceContracts(unittest.TestCase):
    def test_fixture_parent_is_readable_but_diagnostic_parent_stays_control_bound(self):
        source = (SOURCE / "desktop/src-tauri/src/installed_shell_observation.rs").read_text()
        parser = source.split("fn control_root_from_executable(", 1)[1].split("fn control_root()", 1)[0]
        self.assertIn('executable.file_name()? != OsStr::new("shell-observer")', parser)
        self.assertIn('root.parent()? != Path::new("/var/lib")', parser)
        self.assertIn('strip_prefix("mrk-ubuntu-native-")?', parser)
        self.assertIn("parts.len() != 2", parser); self.assertIn("part.len() <= 20", parser)
        self.assertIn("!part.starts_with('0')", parser); self.assertIn("byte.is_ascii_digit()", parser)
        self.assertIn('executable.as_os_str() != expected.join("shell-observer").as_os_str()', parser)
        derivation = source.split("fn project_path_from_executable(", 1)[1].split("fn assert_shell_fixture_path_contract()", 1)[0]
        self.assertIn("control_root_from_executable(executable)?", derivation)
        self.assertIn('join(format!("mrk-ubuntu-shell-fixtures-{suffix}"))', derivation)
        self.assertIn('join("positive-project")', derivation)
        self.assertNotIn("std::env::var", parser + derivation)
        capture = source.split("impl PathFixture {", 1)[1].split("    fn verify(", 1)[0]
        self.assertIn("path == root.as_path() { id[2] != 0o040755 }", capture)
        self.assertIn("id[2] & 0o005 != 0o005", capture)
        self.assertLess(source.index("    assert_shell_fixture_path_contract();"), source.index("let returned = super::run_builder("))
        # Source correspondence and pure assertion placement are not GTK/native evidence.

    def test_both_lifecycle_workflow_entry_pins_follow_actual_source(self):
        workflow = (SOURCE / ".github/workflows/desktop-ubuntu-publication.yml").read_text()
        lifecycle = (SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_bytes()
        pins = re.findall(r"MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256: '([0-9a-f]{64})'", workflow)
        self.assertEqual(pins, [hashlib.sha256(lifecycle).hexdigest()] * 2)

    def test_normal_capability_error_literals_match_the_existing_joined_classifier(self):
        lifecycle = S.local("ubuntu_publication_lifecycle")
        source = (SOURCE / "desktop/src-tauri/src/bridge.rs").read_text()
        shell = (SOURCE / "desktop/src-tauri/src/shell.rs").read_text()
        classifier = source.split("fn capabilities_failure_line(", 1)[1].split("fn capabilities_cause_line(", 1)[0]
        cause_classifier = source.split("fn capabilities_cause_line(", 1)[1].split("\nstruct RegisteredProject", 1)[0]
        literal_rows = re.findall(r'b"(MRKDBG_DESKTOP_BOOTSTRAP=capabilities-[a-z_-]+)\\n"', classifier)
        cause_rows = re.findall(r'b"(MRKDBG_DESKTOP_BOOTSTRAP=capabilities-cause-[a-z-]+)\\n"', cause_classifier)
        self.assertEqual(len(literal_rows), 30)
        self.assertEqual(len(set(literal_rows)), 30)
        self.assertEqual(len(cause_rows), 98)
        self.assertEqual(len(set(cause_rows)), 98)
        prefix = "MRKDBG_DESKTOP_BOOTSTRAP="
        consumer = lifecycle._shell_normal_markers(b"", b"")["stdout"]["stages"]
        self.assertEqual({line[len(prefix):] for line in literal_rows},
                         {stage for stage in consumer if stage.startswith("capabilities-") and not stage.startswith("capabilities-cause-")})
        self.assertEqual({line[len(prefix):] for line in cause_rows},
                         {stage for stage in consumer if stage.startswith("capabilities-cause-")})
        self.assertLessEqual(max(len(line.encode("ascii")) + 1 for line in literal_rows), 78)
        self.assertLessEqual(max(len(line.encode("ascii")) + 1 for line in cause_rows), 96)
        for block in (classifier, cause_classifier):
            self.assertNotIn("error.message", block); self.assertNotIn("format!", block)
            self.assertNotIn(".to_string()", block); self.assertNotIn("std::io", block)
        self.assertNotIn("error.code", cause_classifier)
        app_info = source.split("    pub(crate) async fn app_info(", 1)[1].split("    pub(crate) async fn catalog(", 1)[0]
        self.assertEqual(app_info.count("document.passive_query(self, Method::Capabilities, json!({}))"), 1)
        self.assertEqual(app_info.count("query.wait().await"), 1)
        self.assertEqual(app_info.count('#[cfg(feature = "desktop-shell")]'), 2)
        self.assertIn("if let Err(error) = &result", app_info)
        self.assertIn("capabilities_failure_line(CapabilitiesFailureOrigin::QueryWait, error)", app_info)
        self.assertIn("capabilities_failure_line(CapabilitiesFailureOrigin::Admission, &error)", app_info)
        cause_emit = "crate::shell::diagnostic(capabilities_cause_line(error));"
        self.assertEqual(app_info.count(cause_emit), 1)
        self.assertLess(app_info.index("query.wait().await"), app_info.index(cause_emit))
        self.assertLess(app_info.index("if let Err(error) = &result"), app_info.index(cause_emit))
        self.assertIn('#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]', app_info)
        self.assertIn("pub(crate) fn diagnostic(line: &'static [u8])", shell)
        self.assertIn("let _ = std::io::stderr().write_all(line);", shell)
        # Source correspondence does not execute the Rust classifier, a query,
        # or a window and cannot count as native capabilities acceptance.

    def test_closed_causes_preserve_first_error_and_actual_return_boundaries(self):
        supervisor = (SOURCE / "desktop/src-tauri/src/supervisor.rs").read_text()
        installed = (SOURCE / "desktop/src-tauri/src/installed_runtime.rs").read_text()
        runtime = (SOURCE / "desktop/src-tauri/src/runtime.rs").read_text()
        protocol = (SOURCE / "desktop/src-tauri/src/protocol.rs").read_text()
        error = (SOURCE / "desktop/src-tauri/src/error.rs").read_text()
        fail_at = supervisor.split("    fn fail_at(", 1)[1].split("    fn management_ready(", 1)[0]
        self.assertEqual(fail_at, '''&mut self, error: BridgeError, now: Instant) {
        if self.terminal { return; }
        if self.error.is_none() { self.error = Some(error); }
        if self.cleanup_endpoint.is_none() { self.cleanup_endpoint = Some(now.min(self.endpoint) + CLEANUP_TIME); }
    }
''')
        state = supervisor.split("struct OwnerState {", 1)[1].split("\n}", 1)[0]
        self.assertNotIn("cause", state)  # No additional latch/fill/freeze storage.
        unknown = supervisor.split("    fn unknown(&self", 1)[1].split("    fn advance_clock(", 1)[0]
        self.assertEqual(unknown.count("state.error.as_ref().and_then(BridgeError::linux_passive_cause)"), 1)
        self.assertIn("error.with_linux_passive_cause(cause)", unknown)
        retirement = supervisor.split("    fn retirement_result(", 1)[1].split("// The SAME acquisition", 1)[0]
        self.assertIn("self.error.as_ref().and_then(BridgeError::linux_passive_cause)", retirement)
        self.assertNotIn("with_linux_passive_cause", fail_at)
        equality = error.split("impl PartialEq for BridgeError {", 1)[1].split("impl Eq for BridgeError", 1)[0]
        self.assertIn("self.code == other.code && self.message == other.message && self.retryable == other.retryable", equality)
        self.assertNotIn("linux_passive_cause", equality)
        self.assertIn("#[serde(skip)]\n    linux_passive_cause: Option<LinuxPassiveCause>", error)
        self.assertIn("InspectionOutcome::Refused(failure) => Err(passive_inspection_refusal(failure))", installed)
        self.assertIn("InspectionOutcome::Unknown => Err(passive_inspection_unknown(original.observation().failure()))", installed)
        for label in ("SelectionProfileClosed", "SelectionCompileBinding", "SelectionMethodOutsideProfile"):
            self.assertIn("LinuxPassiveCause::" + label, runtime)
        acquisition = supervisor.split("fn acquire_passive_original(", 1)[1].split("async fn settle_passive(", 1)[0]
        self.assertIn("slots.capability().map_err(AcquisitionError::capability)?", acquisition)
        self.assertIn("LinuxPassiveCause::FinalClaimOwnerGate", acquisition)
        after_claim = acquisition.split("prepared.runtime.claim_once().map_err(AcquisitionError::final_claim)?;", 1)[1]
        self.assertEqual(after_claim.split("let result = spawn_passive_original(prepared);", 1)[0],
                         "\n        drop(state); drop(owners);\n        ")
        spawn = supervisor.split("fn spawn_passive_original(")
        self.assertEqual(len(spawn), 3)
        stub, actual = (body.split("\n}", 1)[0] for body in spawn[1:])
        self.assertIn("record_closed_spawn_gate()", stub)
        self.assertNotIn("returned_spawn", stub)
        self.assertIn("prepared.command.spawn().map_err(AcquisitionError::returned_spawn)", actual)
        driver = supervisor.split("async fn drive(", 1)[1].split("// Finite hosted fixtures", 1)[0]
        self.assertLess(driver.index("let acquired = join_slot(&mut resources.acquisition).await"),
                        driver.index("failure.into_bridge_error()"))
        self.assertIn(".map_err(AcquisitionError::preparation)?", supervisor)
        decoder = protocol.split("pub fn decode_response(", 1)[1].split("#[cfg(test)]", 1)[0]
        self.assertLess(decoder.rindex("return Err(BridgeError::protocol())"), decoder.index("LinuxPassiveCause::EngineResponse"))
        for block in (fail_at, unknown, retirement, acquisition, stub, actual, decoder):
            self.assertNotIn("shell::diagnostic", block)
        # Text correspondence only; no native operation, returned spawn or
        # management/custody finality is established by these source assertions.

    def test_literal_allowlists_correspond_to_bounded_rust_step_boundary_encoder(self):
        workflow = (SOURCE / ".github/workflows/desktop-ubuntu-publication.yml").read_text()
        entry = (SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_bytes()
        self.assertEqual(workflow.count("MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256:"), 2)
        self.assertEqual(re.findall(r"MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256: '([0-9a-f]{64})'", workflow),
                         [hashlib.sha256(entry).hexdigest()] * 2)
        lifecycle = S.local("ubuntu_publication_lifecycle")
        source = (SOURCE / "desktop/src-tauri/src/installed_shell_observation.rs").read_text()
        steps = {line.encode("ascii") + b"\n" for line in re.findall(
            r'b"(MRK_INSTALLED_SHELL_FAILURE_STEP=[A-Za-z]+)\\n"', source)}
        boundaries = {line.encode("ascii") + b"\n" for line in re.findall(
            r'b"(MRK_INSTALLED_SHELL_FAILURE_PHASE=[a-z]+)\\n"', source)}
        progress = {line.encode("ascii") + b"\n" for line in re.findall(
            r'b"(MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=[a-z-]+)\\n"', source)}
        self.assertEqual(set(lifecycle.SHELL_FAILURE_STEPS), steps)
        self.assertEqual(set(lifecycle.SHELL_FAILURE_BOUNDARIES), boundaries)
        self.assertEqual(len(lifecycle.SHELL_FAILURE_STEPS), len(steps))
        self.assertEqual(len(lifecycle.SHELL_FAILURE_BOUNDARIES), 8)
        self.assertEqual(set(lifecycle.SHELL_BOOTSTRAP_PROGRESS), progress)
        self.assertEqual(len(lifecycle.SHELL_BOOTSTRAP_PROGRESS), len(progress))
        path_rejections = source.split("impl PathRejection {", 1)[1].split("struct PathDiagnostic", 1)[0]
        path_tokens = tuple(value.encode("ascii") for value in re.findall(r'=> b"([a-z-]+)"', path_rejections))
        self.assertEqual(path_tokens, lifecycle.SHELL_PATH_REJECTIONS)
        self.assertEqual((len(path_tokens), len(set(path_tokens))), (27, 27))
        self.assertTrue(all(re.fullmatch(rb"[a-z-]{1,22}", token) for token in path_tokens))
        path_recipe = source.split("impl PathStep {", 1)[1].split("fn failure_line", 1)[0]
        self.assertEqual(set(re.findall(r"Self::([A-Za-z]+)\(index\)", path_recipe)),
                         {"Browse", "Set", "Activate", "Settled", "ReadField"})
        self.assertIn("=> Some(index)", path_recipe); self.assertIn("_ => None", path_recipe)
        self.assertIn("const PATH_CASES: [PathCase; 11]", source)
        path_bound = (max(map(len, steps)) + max(map(len, boundaries)) + max(map(len, progress))
                      + len(b"MRK_INSTALLED_SHELL_PATH_FAILURE=v1;index=none;reject=\n") + max(map(len, path_tokens)))
        self.assertEqual(path_bound, 251)
        self.assertLessEqual(path_bound, lifecycle.SHELL_PATH_FAILURE_FRAME_BOUND)
        self.assertEqual(lifecycle.SHELL_PATH_FAILURE_FRAME_BOUND, 256)
        self.assertIn("const PATH_FAILURE_FRAME_BOUND: usize = 256;", source)
        encoder = source.split("fn failure_pair(", 1)[1].split("fn assert_failure_pair_contract", 1)[0]
        self.assertLess(encoder.index('b"MRK_INSTALLED_SHELL_PATH_FAILURE=v1;index="'), encoder.index("trace.0.failure_line()"))
        self.assertIn("diagnostic.step == step && session.is_none()", encoder)
        self.assertIn("step.recipe_index().is_some_and(|index| index > 10)", encoder)
        self.assertIn("(Step::Paths(_), _) | (_, Some(_)) => return None", encoder)
        self.assertIn("if path.is_some() && length > PATH_FAILURE_FRAME_BOUND { return None; }", encoder)
        rejections = source.split("impl SessionRejection {", 1)[1].split("enum SessionWait", 1)[0]
        waits = source.split("impl SessionWait {", 1)[1].split("struct SessionDiagnostic", 1)[0]
        for block, expected in ((rejections, lifecycle.SHELL_SESSION_REJECTIONS), (waits, lifecycle.SHELL_SESSION_WAITS)):
            tokens = tuple(value.encode("ascii") for value in re.findall(r'=> b"([a-z-]+)"', block))
            self.assertEqual(tokens, expected)
            self.assertEqual(len(tokens), len(set(tokens)))
            self.assertTrue(all(re.fullmatch(rb"[a-z-]{1,32}", token) for token in tokens))
        token_by_variant = dict(re.findall(r'Self::([A-Za-z]+) => b"([a-z-]+)"', rejections))
        reply = source.split("fn session_reply_rejection(", 1)[1].split("fn session_capability_rejection(", 1)[0]
        capability = source.split("fn session_capability_rejection(", 1)[1].split("fn session_file_wait_pending(", 1)[0]
        asset = (SOURCE / "desktop/src-tauri/src/asset_commands.rs").read_text()
        assessment = (SOURCE / "desktop/src-tauri/src/credential_assessment.rs").read_text()
        asset = asset.split("impl AssetError {", 1)[1].split("pub(crate) fn invalid(", 1)[0]
        assessment = assessment.split("impl AssessmentError {", 1)[1].split("fn invalid(", 1)[0]
        asset_codes = set(re.findall(r'=> "([a-z_]+)"', asset))
        assessment_codes = set(re.findall(r'=> \("([a-z_]+)",', assessment))
        self.assertEqual((len(asset_codes), len(assessment_codes)), (21, 11))
        self.assertEqual(asset_codes & assessment_codes, {"assessment_context_stale"})
        mapped = re.findall(r'"([a-z_]+)" => SessionRejection::([A-Za-z]+)', reply)
        self.assertEqual(len(mapped), 31)
        self.assertEqual({code for code, _ in mapped}, asset_codes | assessment_codes)
        self.assertEqual(len({variant for _, variant in mapped}), 31)
        shortened = {"asset_unsupported_filesystem": "reply-asset-unsupported-fs",
                     "asset_exclusion_unconfirmed": "reply-asset-excl-unconfirmed"}
        for code, variant in mapped:
            self.assertEqual(token_by_variant[variant], shortened.get(code, "reply-" + code.replace("_", "-")))
        self.assertEqual(reply.count("_ => SessionRejection::ReplyCodeUnavailable"), 1)
        self.assertEqual(token_by_variant["ReplyCodeUnavailable"], "reply-code-unavailable")
        reasons = re.findall(r'Some\("([a-z-]+)"\) => SessionRejection::([A-Za-z]+)', capability)
        self.assertEqual(len(reasons), 6)
        self.assertEqual({reason for reason, _ in reasons},
                         {"cleanup-unknown", "shutdown", "document-lost", "unsupported-platform", "unqualified", "closed"})
        for reason, variant in reasons:
            self.assertEqual(token_by_variant[variant], "capability-" + reason)
        self.assertEqual(capability.count("_ => SessionRejection::CapabilityUnavailable"), 1)
        self.assertEqual(token_by_variant["CapabilityUnavailable"], "capability-unavailable")
        session = (SOURCE / "desktop/src-tauri/src/asset_session.rs").read_text()
        query_source = (SOURCE / "desktop/src-tauri/src/installed_shell_shutdown_observation.rs").read_text()
        supervisor = (SOURCE / "desktop/src-tauri/src/supervisor.rs").read_text()
        origins = session.split("impl UnknownOrigin {", 1)[1].split("pub(super) struct FirstOrigin", 1)[0]
        details = session.split("impl OriginDetail {", 1)[1].split("impl UnknownOrigin", 1)[0]
        errors = query_source.split("impl QueryError {", 1)[1].split("enum QueryCause", 1)[0]
        causes = query_source.split("impl QueryCause {", 1)[1].split("fn management_token", 1)[0]
        for block, expected, maximum in ((origins, lifecycle.SHELL_SESSION_ORIGINS, 19), (details, lifecycle.SHELL_SESSION_DETAILS, 15),
                                         (errors, lifecycle.SHELL_SESSION_QUERY_ERRORS, 11), (causes, lifecycle.SHELL_SESSION_QUERY_CAUSES, 11)):
            tokens = tuple(value.encode("ascii") for value in re.findall(r'=> b"([a-z-]+)"', block))
            self.assertEqual(tokens, expected)
            self.assertEqual(len(tokens), len(set(tokens)))
            self.assertLessEqual(max(map(len, tokens)), maximum)
        joins = query_source.split("fn management_token", 1)[1].split("enum QueryProjection", 1)[0]
        self.assertEqual("".join(re.findall(r"=> b'([a-z])'", joins)).encode("ascii"), lifecycle.SHELL_SESSION_MANAGEMENT_JOINS)
        workers = query_source.split("impl WorkerProjection {", 1)[1].split("pub(crate) struct InstalledSessionQueryDiagnostic", 1)[0]
        native = supervisor.split("impl ObservationFailure {", 1)[1].split("impl ChildObservation", 1)[0]
        literals = {value.encode("ascii") for value in re.findall(r'=> b"([a-z-]+)"', workers + native)}
        maps = supervisor.split("impl MapRole {", 1)[1].split("impl ObservationFailure {", 1)[0]
        map_tokens = tuple(value.encode("ascii") for value in re.findall(r'b"(map-[a-z-]+)"', maps))
        self.assertEqual((len(map_tokens), len(set(map_tokens))), (88, 88))
        generic = tuple(b"map-x-" + group + b"-" + deleted + history
                        for group in (b"v", b"l", b"c", b"h", b"m", b"o")
                        for deleted, history in ((b"n", b"a"), (b"n", b"p"), (b"d", b"a"), (b"d", b"p")))
        self.assertEqual(lifecycle.SHELL_SESSION_GENERIC_MAP_WORKERS, generic)
        self.assertEqual(len(generic), 24)
        self.assertTrue(set(generic) <= set(map_tokens))
        self.assertTrue(all(re.fullmatch(rb"[a-z-]{1,14}", token) for token in map_tokens))
        public_table = supervisor.split("    static PUBLIC_MAP_PATH_CANDIDATES: [(&str, &[u8]); 648] = [\n", 1)[1].split("    ];\n", 1)[0]
        public_rows = re.findall(r'^        \("([^"]+)", b"(map-x-[a-z]{2})"\),$', public_table, re.MULTILINE)
        self.assertEqual(public_table.splitlines(), [f'        ("{path}", b"{token}"),' for path, token in public_rows])
        public_paths = [path for path, _ in public_rows]
        public_tokens = tuple(token.encode("ascii") for _, token in public_rows)
        self.assertEqual((len(public_rows), len(set(public_tokens))), (648, 648))
        self.assertEqual(public_paths, sorted(set(public_paths)))
        self.assertTrue(all(path.isascii() and path.isprintable() and
                            (path == "/bin/sh" or path.startswith(("/usr/bin/", "/usr/lib/"))) for path in public_paths))
        self.assertEqual((max(map(len, public_paths)), sum(map(len, public_paths))), (87, 29840))
        self.assertEqual(public_tokens, tuple(b"map-x-" + bytes([97 + index // 26, 97 + index % 26]) for index in range(648)))
        canonical = b"".join(token + b"\t" + path.encode("ascii") + b"\n" for path, token in zip(public_paths, public_tokens))
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), "bf18de45262438226bbc80a1cc8a3c078821b4a1dc88ec16a00961c05c990710")
        self.assertEqual(public_tokens, lifecycle.SHELL_SESSION_PUBLIC_MAP_WORKERS)
        self.assertTrue(set(public_tokens).isdisjoint(map_tokens))
        version = "/var/lib/mobile-release-kit/versions/x86_64-unknown-linux-gnu/e3375ff140d69df54b2445f756711e0245d397ba6ded76e8559732ec2e4e3801"
        accepted = {version + suffix for suffix in ("/python/bin/python3", "/python/lib/libssl.so.3", "/python/lib/libcrypto.so.3")}
        accepted.update(prefix + name for prefix in ("/usr/lib/x86_64-linux-gnu/", "/lib/x86_64-linux-gnu/")
                        for name in ("ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6"))
        accepted.add("/lib64/ld-linux-x86-64.so.2")
        self.assertTrue(set(public_paths).isdisjoint(accepted))
        role = supervisor.split("    fn role(path: &str) -> Option<MapRole> {", 1)[1].split("    #[derive(Clone, Copy)]", 1)[0]
        self.assertEqual(hashlib.sha256(role.encode()).hexdigest(), "aa4101e33f69e2bff0480a304a86c1a7923f82a0592f49de4b329b927b1c18dc")
        parser = supervisor.split("    fn mappings(raw: &[u8], historical: Option<HistoricalPayloadSnapshot>) -> Result<Option<Vec<Mapping>>, MapRefusal> {", 1)[1].split(
            '    #[cfg(all(debug_assertions, any(all(feature = "desktop-shell", feature = "custom-protocol"),\n'
            '        all(not(feature = "desktop-shell"), not(feature = "custom-protocol")))))]', 1)[0]
        refusal = ("need(!executable).map_err(|_| generic_executable_file_refusal("
                   "historical_executable_file_refusal(executable_file_refusal(path), historical, major, minor, inode), path, historical.is_some()))?")
        self.assertEqual(parser.count(refusal), 1)
        self.assertEqual(hashlib.sha256(parser.replace(refusal, "need(!executable).map_err(|_| MapRefusal::ExecutableFile)?").encode()).hexdigest(),
                         "6b884ac9df8f44c52c96a34f926445e11f18564946f4f126e600afbab94d24fe")
        lookup = supervisor.split("    fn executable_file_refusal(path: &str) -> MapRefusal {", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn(".position(|(candidate, _)| path == *candidate)", lookup)
        for forbidden in ("fs::", "original_bytes", "/proc/", "read_link", "canonicalize", "trim", "format!", "to_owned", ".await", "Instant::now"):
            self.assertNotIn(forbidden, lookup)
        self.assertEqual(literals | set(map_tokens) | set(public_tokens) | {b"maps-check"}, set(lifecycle.SHELL_SESSION_WORKERS))
        self.assertEqual(len(lifecycle.SHELL_SESSION_WORKERS), len(set(lifecycle.SHELL_SESSION_WORKERS)))
        self.assertIn("installed_native_fixture::assert_mappings_diagnostic_contract();", query_source)
        stages = re.findall(r'WorkerStage::[A-Za-z]+ => join.token\(b"([a-z]+)-c", b"\1-x", b"\1-f"\)', workers)
        self.assertEqual(tuple(stage.encode("ascii") for stage in stages), lifecycle.SHELL_SESSION_WORKER_STAGES)
        self.assertEqual(lifecycle.SHELL_SESSION_WORKER_JOINS, b"cxf")
        associations = session.split("pub(crate) fn association_token", 1)[1].split("pub(crate) fn query_token", 1)[0]
        self.assertEqual(tuple(value.encode("ascii") for value in re.findall(r'b"([a-z-]+)"', associations)), lifecycle.SHELL_SESSION_ASSOCIATIONS)
        projection = query_source.split("fn session_query_diagnostic(", 1)[1].split("pub(crate) fn assert_installed_session_query_diagnostic_contract", 1)[0]
        self.assertIn("Weak::ptr_eq(&row.asset, asset)", projection)
        self.assertIn("Profile::Passive(Method::AssessCredentials)", projection)
        self.assertEqual(projection.count(".try_lock()"), 3)
        for forbidden in (".lock(", ".await", ".poll(", ".join(", "Instant::now", "row.owner.key", "asset.id", "state.slot"):
            self.assertNotIn(forbidden, projection)
        restore = session.split("fn restore_failed_install_retirement(", 1)[1].split("impl DocumentBinding", 1)[0]
        self.assertLess(restore.index("first_unknown_origin!(state, UnknownOrigin::InstallRetirement, Some(_owner))"), restore.index("state.slot ="))
        snapshot = session.split("fn snapshot(&self, state: &DocumentState)", 1)[1].split("let operation =", 1)[0]
        owner_reason = session.split("fn session_owner_reason(", 1)[1].split("fn observe_session_owner_reason(", 1)[0]
        self.assertEqual(set(re.findall(r"Reason::([A-Za-z]+)", snapshot)),
                         {"CleanupUnknown", "Shutdown", "DocumentLost", "UnsupportedPlatform", "Unqualified", "Closed", "None"})
        self.assertEqual(set(re.findall(r"Reason::([A-Za-z]+)", owner_reason)), {"CleanupUnknown", "Shutdown"})
        for helper in (reply, capability):
            self.assertIn("-> SessionRejection", helper)
            for forbidden in ("format!", "to_owned", "to_string", "BridgeError", "linux_passive_cause", "diagnostic", "snapshot", "self."):
                self.assertNotIn(forbidden, helper)
        for boundary in boundaries:
            for context in progress:
                self.assertEqual(lifecycle._shell_label_pair(b"MRK_INSTALLED_SHELL_FAILURE_STEP=SelectProject\n" + boundary + context),
                                 {"step": "SelectProject", "boundary": boundary.decode("ascii").strip().split("=", 1)[1],
                                  "bootstrapProgress": context.decode("ascii").strip().split("=", 1)[1]})
        self.assertLessEqual(max(map(len, steps)) + max(map(len, boundaries)) + max(map(len, progress)), 512)
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
        self.assertIn("const FAILURE_PAIR_LIMIT: usize = 512;", source)
        self.assertIn("const SESSION_FAILURE_FRAME_BOUND: usize = 412;", source)
        self.assertIn("fn assert_failure_pair_contract()", source)
        self.assertIn("    assert_failure_pair_contract();", source)
        self.assertLess(source.index("    assert_failure_pair_contract();"), source.index("let returned = super::run_builder("))
        pure = source.split("fn assert_failure_pair_contract()", 1)[1].split("// Original destruction facts", 1)[0]
        self.assertIn("SessionStep::ActivateFile(3),evaluations:16", pure)
        self.assertIn("session_file_wait_pending(actual,pending,3,!activating)", pure)
        self.assertIn("retained == Some(if deadline_first { same } else { gtk })", pure)
        # These inert contracts execute before GTK in the reviewed native route;
        # their source presence here is not executed Rust or native evidence.
        self.assertIn("let end = Instant::now() + Duration::from_secs(45);", source)
        self.assertEqual(lifecycle.SHELL_WORK_FILE_LIMIT, 64 << 20)
        commands = (SOURCE / "desktop/src-tauri/src/installed_tools_observation.rs").read_text()
        self.assertTrue('#[path = "installed_tools_observation.rs"]\npub(crate) mod commands;' in source,
                        "The parent must bind the reviewed Tools/Offline module")
        sink = source.split("fn failure_sink(case: Case)", 1)[1].split("\n}\n", 1)[0]
        parent_leaves = sink.split("    let leaf = match case {\n", 1)[1].split("\n    };", 1)[0]
        command_leaves = commands.split("    pub(super) fn failure_leaf(self) -> &'static str { match self {\n", 1)[1].split("\n    } }", 1)[0]
        self.assertEqual(parent_leaves.count("Case::Commands(case) => case.failure_leaf(),"), 1)
        actual_leaves = re.findall(r'=> "([^"\n]*)"', parent_leaves + command_leaves)
        self.assertEqual(actual_leaves, ["shell-" + case + "-failure.labels" for case in lifecycle.SHELL_CASES[1:]])
        self.assertNotIn("shell-normal-failure.labels", source)
        self.assertNotIn("shell-normal-failure.labels", commands)
        self.assertFalse(any(name.endswith("failure.labels") for name in lifecycle.public_files({"shell": {}})))

    def test_folder_selection_waits_for_the_exact_current_folder_before_one_activation(self):
        source = (SOURCE / "desktop/src-tauri/src/shell.rs").read_text()
        selecting = source.split("    pub(super) fn select_observed_folder(", 1)[1].split("    #[cfg(", 1)[0]
        activating = source.split("    pub(super) fn activate_observed_folder(", 1)[1].split("    #[cfg(", 1)[0]
        self.assertEqual(selecting.count("dialog.set_current_folder(path)"), 1)
        self.assertEqual(selecting.count("q.project_selection(id)?"), 1)
        self.assertEqual(selecting.count("q.evidence_selection(id)?"), 1)
        self.assertNotIn(".set_filename(", selecting); self.assertNotIn(".filename(", selecting + activating)
        self.assertNotIn("set_current_folder", activating)
        readiness = "if dialog.current_folder().as_deref() != Some(path) { return Ok(false); }"
        self.assertEqual(activating.count("dialog.current_folder()"), 1)
        self.assertIn("if select {", activating)
        self.assertIn("if evidence { q.evidence_path() } else { q.project_path() }", activating)
        self.assertIn(readiness, activating)
        self.assertLess(activating.index(readiness), activating.index("dialog.widget_for_response(response)"))
        self.assertLess(activating.index(readiness), activating.index("q.project_activation(id, select)?"))
        self.assertLess(activating.index(readiness), activating.index("q.evidence_activation(id, select)?"))
        self.assertEqual(activating.count("button.emit_clicked()"), 1)
        # This source correspondence cannot prove GTK readiness or acceptance.

    def test_picker_return_latch_keeps_response_and_original_finality_independent(self):
        source = (SOURCE / "desktop/src-tauri/src/installed_shell_observation.rs").read_text()
        latch = source.split("    fn activation_returned(", 1)[1].split("    fn settled(", 1)[0]
        self.assertIn("result != Ok(true) || !self.created || !self.activated || self.returned", latch)
        self.assertEqual(latch.count("self.returned = true"), 1)
        self.assertNotIn("self.responded", latch)
        self.assertIn("self.created && self.activated && self.responded && self.destroyed && self.released && self.returned", source)
        self.assertIn("&& self.selected == select && self.filename == select", source)
        for name, next_name, pending, waiting in (
            ("project_gtk_returned", "evidence_created", "Project(step)", ("Step::Cancelled", "Step::Selected")),
            ("evidence_gtk_returned", "native_created", "Evidence(step)", ("Step::EvidenceCancelled", "Step::EvidenceSelected")),
            ("path_gtk_returned", "preview_request", "Path(path)", ("Step::Paths(PathStep::Settled(index))",)),
        ):
            caller = source.split("    fn " + name + "(", 1)[1].split("    pub(super) fn " + next_name, 1)[0]
            self.assertIn("r.pending.take() != Some(Pending::" + pending + ")", caller)
            self.assertEqual(caller.count(".activation_returned(result)"), 1)
            self.assertNotIn(".responded", caller)
            for step in waiting: self.assertIn(step, caller)
        self.assertIn("Ok(true) if matches!(step, Step::Cancel | Step::SelectProject)", source)
        self.assertIn("Ok(true) if matches!(step, Step::CancelEvidence | Step::SelectEvidence)", source)
        self.assertIn("PathStep::Set(i) => (i,true), PathStep::Activate(i) => (i,false)", source)
        self.assertIn("Ok(true) if !selecting =>", source)
        self.assertIn("fn assert_picker_activation_return_contract()", source)
        self.assertLess(source.index("    assert_picker_activation_return_contract();"),
                        source.index("let returned = super::run_builder("))
        # The actual helper's inert assertions run in the reviewed observer
        # before GTK. Original response, owner and finality evidence is separate.

    def test_project_path_cancel_destruction_uses_choice_specific_original_facts(self):
        shell = (SOURCE / "desktop/src-tauri/src/shell.rs").read_text()
        source = (SOURCE / "desktop/src-tauri/src/installed_shell_observation.rs").read_text()
        callback = shell.split("entry.destroy = Some(dialog.connect_destroy(move |_| {", 1)[1].split("}));", 1)[0]
        self.assertIn("destroy_call.upgrade().is_some_and(|call| call.facts().is_some_and(|facts|", callback)
        predicate = "installed_observation::file_destroyed(&facts, matches!(choice, DialogChoice::ProjectPath(_)))"
        self.assertEqual(callback.count(predicate), 1)
        self.assertLess(callback.index("destroyed(&destroy_call)"), callback.index(predicate))
        self.assertLess(callback.index(predicate), callback.index("q.native_destroyed(observed_id, seen)"))
        self.assertNotIn("!facts.declined", callback)
        helper = source.split("pub(super) fn file_destroyed(", 1)[1].split("fn assert_file_destroyed_contract()", 1)[0]
        self.assertIn("facts.destroyed && facts.response && facts.refusal.is_none()", helper)
        self.assertIn("if path_choice { facts.accepted != facts.declined } else { !facts.declined }", helper)
        self.assertNotIn("facts.close_ack", helper); self.assertNotIn("facts.released", helper)
        self.assertIn("(true, false, true, true)", source)  # Path Cancel is declined.
        self.assertIn("(false, false, false, true)", source)  # Ordinary Cancel is not.
        self.assertLess(source.index("    assert_file_destroyed_contract();"),
                        source.index("let returned = super::run_builder("))
        self.assertIn("if !seen || !p.responded || p.destroyed", source)
        self.assertIn("if !seen || !p.destroyed || p.released", source)
        self.assertIn(
            "original.response = None;\n        original.destroy = None;\n"
            "        gtk_fixture!(call, HandlersDetached, 1);",
            shell.split("    fn release_after_destroy(", 1)[1].split("\n    #[cfg(", 1)[0],
        )
        # Original GTK signals, destruction, release and joins require native evidence.

    def test_deadline_label_latches_once_before_report_outside_the_record_lock(self):
        source = (SOURCE / "desktop/src-tauri/src/installed_shell_observation.rs").read_text()
        tick = source.split("    pub(super) fn tick(", 1)[1].split("        let step = {", 1)[0]
        deadline = tick.split("        if Instant::now() >= self.end {", 1)[1].split(
            "        if std::thread::current().id() == self.main", 1)[0]
        self.assertIn("if let Some(mut r) = self.record() {", deadline)
        winner = "if latch_failure(&self.failed, trace, bootstrap, (*step, Boundary::Deadline), progress) {"
        self.assertIn(winner, deadline)
        self.assertLess(deadline.index("SessionDiagnostic::sample(r.step,r.evaluations,r.session.diagnostic)"), deadline.index(winner))
        self.assertLess(deadline.index("PathDiagnostic::sample(r.step)"), deadline.index(winner))
        self.assertIn(winner + "\n                    r.session.diagnostic = diagnostic;\n                    r.paths.diagnostic = path_diagnostic;\n                }", deadline)
        latch = source.split("fn latch_failure(", 1)[1].split("fn latch_session_diagnostic(", 1)[0]
        self.assertEqual(latch.count("failed.swap(true, Ordering::SeqCst)"), 1)
        self.assertIn("if !failed.swap(true, Ordering::SeqCst) { *trace = next_trace; *progress = next_progress; true } else { false }", latch)
        self.assertEqual(deadline.count("Boundary::Deadline"), 1)
        self.assertIn("\n            }\n            self.report_failure(); return;\n        }", deadline)
        self.assertIn("if self.failed.load(Ordering::SeqCst) { self.report_failure(); return; }", tick)
        self.assertIn("if std::thread::current().id() == self.main { self.fail(); self.report_failure(); return; }", tick)
        self.assertNotIn("self.end ||", tick)
        cache = source.split("fn record_at(&self", 1)[1].split("fn session_wait(", 1)[0]
        self.assertIn("if !self.failed.load(Ordering::SeqCst) {\n            r.trace = (r.step, boundary);", cache)
        self.assertIn("r.paths.diagnostic = PathDiagnostic::sample(r.step);\n        }", cache)

    def test_test_only_original_fd_sink_has_one_attempt_before_existing_stderr(self):
        source = (SOURCE / "desktop/src-tauri/src/installed_shell_observation.rs").read_text()
        entry = (SOURCE / "desktop/src-tauri/tests/installed_shell_observation.rs").read_text()
        opener = source.split("fn failure_sink(case: Case)", 1)[1].split("const FAILURE_PAIR_LIMIT", 1)[0]
        self.assertIn("let root = control_root()?;", opener)
        self.assertNotIn("project_path()", opener)
        self.assertIn("OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC", opener)
        self.assertIn("OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK", opener)
        self.assertNotIn("OFlags::CREATE", opener); self.assertNotIn("OFlags::TRUNC", opener)
        self.assertEqual(opener.count("fs::openat("), 1)
        self.assertIn("item.st_mode != 0o100620", opener)
        self.assertIn("item.st_nlink != 1 || item.st_size != 0", opener)
        self.assertIn("before.st_mode != 0o040711", opener)
        reporter = source.split("    fn report_failure(&self)", 1)[1].split("    pub(super) fn attach", 1)[0]
        self.assertEqual(reporter.count("rustix::io::write("), 1)
        self.assertLess(reporter.index("self.failure_reported.swap(true"), reporter.index("rustix::io::write("))
        self.assertLess(reporter.index("rustix::io::write("), reporter.index("super::diagnostic(trace.0.failure_line())"))
        self.assertNotIn("write_all", reporter); self.assertNotIn("loop {", reporter)
        self.assertIn("failure_sink: rustix::fd::OwnedFd", source)
        self.assertIn("#![forbid(unsafe_code)]", entry)
        self.assertIn("not(feature = \"development-runtime\")", entry)
        self.assertIn('target_os = "linux"', entry)
        # The source contract is not a substitute for the next actual shared
        # normal/observer compiler gate or runtime FD behavior on the host.


if __name__ == "__main__":
    unittest.main()
