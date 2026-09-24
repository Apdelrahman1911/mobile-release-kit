"""Inert shell compiler/transport contracts; no compiler, GUI or process launch."""
from copy import deepcopy
import ast
import hashlib
import importlib.util
import json
import re
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch


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
              "helper11Rerun": False, "qualified": False,
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
        _, packages, nodes = S.shell_cargo_metadata(S.D.canonical(metadata()), Path("/source"), Path("/target"))
        _, units = S.shell_compiled_artifacts(messages(compiler_rows()), Path("/source"), Path("/target"))
        S.shell_compiler_units(units, packages, nodes)
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
    return {"state": "normal-shell-installed-runtime-connection-observed", "productQualified": False,
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
        self.assertEqual(set(observed["cases"]), {"normal", "positive", "quit-outstanding", "project-paths", "workflow-apply", "metadata-save"})

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
        self.assertEqual(len(observed["files"]), 8)
        # The original exporter allows at most 128 root files plus the same
        # original client's two captures; adding fixtures cannot raise it.
        observed["files"].extend({"path": "inert-" + str(index), "size": 0, "sha256": "0" * 64} for index in range(122))
        S.shell_project_draft_observation(observed, lifecycle)
        observed["files"].append({"path": "over-cap", "size": 0, "sha256": "0" * 64})
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
    def test_requires_all_five_cases_and_both_typed_inventory_export_pins(self):
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
    def test_sixth_receipt_requires_two_original_reviews_one_apply_and_ordered_completion(self):
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
        classifier = source.split("fn capabilities_failure_line(", 1)[1].split("\nstruct RegisteredProject", 1)[0]
        literal_rows = re.findall(r'b"(MRKDBG_DESKTOP_BOOTSTRAP=capabilities-[a-z_-]+)\\n"', classifier)
        self.assertEqual(len(literal_rows), 30)
        self.assertEqual(len(set(literal_rows)), 30)
        prefix = "MRKDBG_DESKTOP_BOOTSTRAP="
        consumer = lifecycle._shell_normal_markers(b"", b"")["stdout"]["stages"]
        self.assertEqual({line[len(prefix):] for line in literal_rows},
                         {stage for stage in consumer if stage.startswith("capabilities-")})
        self.assertLessEqual(max(len(line.encode("ascii")) + 1 for line in literal_rows), 78)
        self.assertNotIn("error.message", classifier); self.assertNotIn("format!", classifier)
        self.assertNotIn(".to_string()", classifier); self.assertNotIn("std::io", classifier)
        app_info = source.split("    pub(crate) async fn app_info(", 1)[1].split("    pub(crate) async fn catalog(", 1)[0]
        self.assertEqual(app_info.count("document.passive_query(self, Method::Capabilities, json!({}))"), 1)
        self.assertEqual(app_info.count("query.wait().await"), 1)
        self.assertEqual(app_info.count('#[cfg(feature = "desktop-shell")]'), 2)
        self.assertIn("if let Err(error) = &result", app_info)
        self.assertIn("capabilities_failure_line(CapabilitiesFailureOrigin::QueryWait, error)", app_info)
        self.assertIn("capabilities_failure_line(CapabilitiesFailureOrigin::Admission, &error)", app_info)
        self.assertIn("pub(crate) fn diagnostic(line: &'static [u8])", shell)
        self.assertIn("let _ = std::io::stderr().write_all(line);", shell)
        # Source correspondence does not execute the Rust classifier, a query,
        # or a window and cannot count as native capabilities acceptance.

    def test_literal_allowlists_correspond_to_bounded_rust_step_boundary_encoder(self):
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
        for boundary in boundaries:
            for context in progress:
                self.assertEqual(lifecycle._shell_label_pair(b"MRK_INSTALLED_SHELL_FAILURE_STEP=SelectProject\n" + boundary + context),
                                 {"step": "SelectProject", "boundary": boundary.decode("ascii").strip().split("=", 1)[1],
                                  "bootstrapProgress": context.decode("ascii").strip().split("=", 1)[1]})
        self.assertLessEqual(max(map(len, steps)) + max(map(len, boundaries)) + max(map(len, progress)), 512)
        self.assertIn("const FAILURE_PAIR_LIMIT: usize = 512;", source)
        self.assertIn("fn assert_failure_pair_contract()", source)
        self.assertIn("    assert_failure_pair_contract();", source)
        self.assertIn("let end = Instant::now() + Duration::from_secs(45);", source)
        self.assertEqual(lifecycle.SHELL_WORK_FILE_LIMIT, 64 << 20)
        for case in lifecycle.SHELL_CASES[1:]:
            self.assertIn('"shell-' + case + '-failure.labels"', source)
        self.assertNotIn("shell-normal-failure.labels", source)
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
        self.assertIn("if !self.failed.swap(true, Ordering::SeqCst) { r.trace = (r.step, Boundary::Deadline); }", deadline)
        self.assertEqual(deadline.count("Boundary::Deadline"), 1)
        self.assertIn("\n            }\n            self.report_failure(); return;\n        }", deadline)
        self.assertIn("if self.failed.load(Ordering::SeqCst) { self.report_failure(); return; }", tick)
        self.assertIn("if std::thread::current().id() == self.main { self.fail(); self.report_failure(); return; }", tick)
        self.assertNotIn("self.end ||", tick)
        self.assertIn("if !self.failed.load(Ordering::SeqCst) { r.trace = (r.step, boundary); }", source)

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
