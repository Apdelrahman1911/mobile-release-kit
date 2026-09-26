"""Inert publisher CI contract tests; no compiler, process or native operation."""
from copy import deepcopy
import hashlib
import importlib.util
import io
from pathlib import Path
import os
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("publisher_ci", SOURCE / "desktop/tools/ci_ubuntu_publication.py")
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


def elf_data(extra_tag=None, *, definitions=False):
    """A small structural ELF fixture with no executable program body."""
    raw = bytearray(1536)
    strings = b"\0libc.so.6\0GLIBC_2.34\0"
    interpreter = b"/lib64/ld-linux-x86-64.so.2\0"
    raw[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", raw, 16, 3, 62, 1, 0, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    dynamic = [(1, 1), (5, 1024), (10, len(strings)),
               (0x6ffffffe, 1152), (0x6fffffff, 1)]
    if definitions:
        dynamic += [(0x6ffffffc, 1280), (0x6ffffffd, 1)]
    if extra_tag is not None:
        dynamic.append((extra_tag, 1))
    dynamic.append((0, 0))
    for index, values in enumerate((
        (1, 4, 0, 0, 0, len(raw), len(raw), 4096),
        (3, 4, 512, 512, 512, len(interpreter), len(interpreter), 1),
        (2, 4, 640, 640, 640, len(dynamic) * 16, len(dynamic) * 16, 8),
    )):
        struct.pack_into("<IIQQQQQQ", raw, 64 + 56 * index, *values)
    raw[512:512 + len(interpreter)] = interpreter
    for index, pair in enumerate(dynamic):
        struct.pack_into("<qQ", raw, 640 + 16 * index, *pair)
    raw[1024:1024 + len(strings)] = strings
    struct.pack_into("<HHIII", raw, 1152, 1, 1, 1, 16, 0)
    struct.pack_into("<IHHII", raw, 1168, 0, 0, 2, 11, 0)
    if definitions:
        struct.pack_into("<HHHHIII", raw, 1280, 1, 0, 2, 1, 0, 20, 0)
        struct.pack_into("<II", raw, 1300, 11, 0)
    return bytes(raw)


def runtime_elf_data(path, *, runpath=None):
    """Structural RUNPATH fixture only; no executable body and never launched."""
    raw = bytearray(elf_data())
    strings = b"\0libc.so.6\0GLIBC_2.34\0"
    soname, wanted = S.RUNTIME_ELF[path]
    offset = len(strings)
    strings += (wanted if runpath is None else runpath).encode("ascii") + b"\0"
    dynamic = [(1, 1), (5, 1024), (10, 0), (0x6ffffffe, 1152), (0x6fffffff, 1), (29, offset)]
    if soname is not None:
        dynamic.append((14, len(strings)))
        strings += soname.encode("ascii") + b"\0"
        struct.pack_into("<I", raw, 64 + 56, 0)  # Private DSO has no interpreter.
    dynamic[2] = (10, len(strings))
    dynamic.append((0, 0))
    struct.pack_into("<Q", raw, 64 + 112 + 32, len(dynamic) * 16)
    struct.pack_into("<Q", raw, 64 + 112 + 40, len(dynamic) * 16)
    raw[1024:1024 + len(strings)] = strings
    for index, pair in enumerate(dynamic):
        struct.pack_into("<qQ", raw, 640 + 16 * index, *pair)
    return bytes(raw)


def candidate_data(work, change=None):
    """Transport/correspondence DATA, with ELF parsing mocked by its caller."""
    artifact = work / "admitted-candidate"
    artifact.mkdir()
    source, target, sha = Path("/source"), Path("/target"), "a" * 40
    executable = target / S.TARGET / "debug/deps/mobile_release_desktop-0123456789abcdef"
    body = b"inert candidate transport DATA; not an ELF executable"
    pin = {"size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    elf = {"interpreter": "/lib64/ld-linux-x86-64.so.2", "needed": ["libc.so.6"], "soname": None}
    output = {"file": {"path": "/old/public/candidate", **pin}, "elf": elf, "objects": ["ld-linux-x86-64.so.2", "libc.so.6"]}
    compiler = {"sourceSha": sha, "runId": "10", "attempt": "1", "features": [], "source": str(source), "target": str(target),
                "manifestSha256": S.C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"], "protocolSha256": S.C.CONVENTIONAL_SMOKE_INPUTS["protocolSha256"],
                "originalArtifacts": {"candidate": {"path": str(executable), **pin, "identity": [1, 1, 0o100555, 1, len(body), 0, 0, 1001, 1001]}},
                "exportedArtifacts": {"candidate": {"path": "/old/public/candidate", **pin, "identity": [1, 2, 0o100555, 1, len(body), 0, 0, 1001, 1001]}},
                "nativeInputs": {"outputs": {"candidate": output}}}
    message = {"reason": "compiler-artifact", "executable": str(executable), "fresh": False, "features": [],
               "manifest_path": str(source / "desktop/src-tauri/Cargo.toml"),
               "target": {"kind": ["lib"], "name": "mobile_release_desktop", "src_path": str(source / "desktop/src-tauri/src/lib.rs")},
               "profile": {"test": True, "debug_assertions": True, "opt_level": "0"}}
    result = {"sourceSha": sha, "runId": "10", "attempt": "1", "features": [], "compilations": ["candidate"], "candidateExecuted": False,
              "supplierRebuilt": False, "helper11Rerun": False, "qualified": False,
              "commands": [{"phase": "candidate-compile", "exitCode": 0,
                            "argv": S.compile_argv("/tools/cargo", source, target, library=True, candidate=True)}]}
    graph = {"manifestSha256": compiler["manifestSha256"], "protocolSha256": compiler["protocolSha256"], "candidate": output}
    if change is not None:
        change(compiler, result, graph, message)
    contents = {"candidate": body, "compiler.json": S.D.canonical(compiler), "candidate-native.json": S.D.canonical(graph),
                "candidate-compile.stdout": S.D.canonical(message) + S.D.canonical({"reason": "build-finished", "success": True}),
                "source.json": S.D.canonical({"sourceSha": sha}), "result.json": S.D.canonical(result)}
    for name, raw in contents.items():
        (artifact / name).write_bytes(raw)
    rows = [{"path": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} for name, raw in sorted(contents.items())]
    raw = S.D.canonical({"sourceSha": sha, "runId": "10", "attempt": "1", "files": rows})
    (artifact / "candidate-roster.json").write_bytes(raw)
    return {"GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "2", "MRK_INSTALLED_CANDIDATE_PRODUCER_ATTEMPT": "1",
            "MRK_INSTALLED_CANDIDATE_ARTIFACT_ID": "17", "MRK_INSTALLED_CANDIDATE_ROSTER_SHA256": hashlib.sha256(raw).hexdigest()}, elf


def package_rows(files):
    rows = {".": {"type": "directory", "mode": 0o755}}
    for name, raw in files.items():
        for parent in reversed(Path(name).parents):
            if parent.as_posix() != ".":
                rows[parent.as_posix()] = {"type": "directory", "mode": 0o755}
        rows[name] = {"type": "file", "mode": 0o644, "size": len(raw),
                      "sha256": hashlib.sha256(raw).hexdigest()}
    return rows


def package_data(data_files, control_files, *, mutate=None, trailing=False, tar_format=tarfile.USTAR_FORMAT):
    """Construct inert, uncompressed .deb DATA; never call a packaging tool."""
    members = [("debian-binary", b"2.0\n")]
    for archive, files in (("control.tar", control_files), ("data.tar", data_files)):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tar_format) as writer:
            for name, row in package_rows(files).items():
                info = tarfile.TarInfo("./" if name == "." else "./" + name)
                info.mode = row["mode"]
                info.type = tarfile.DIRTYPE if row["type"] == "directory" else tarfile.REGTYPE
                raw = b"" if info.isdir() else files[name]
                info.size = len(raw)
                if mutate is not None:
                    info, raw = mutate(archive, name, info, raw)
                if info is not None:
                    writer.addfile(info, None if info.isdir() else io.BytesIO(raw))
        raw = output.getvalue()
        if trailing and archive == "data.tar":
            raw += b"unaccounted trailing data"
        members.append((archive, raw))
    result = bytearray(b"!<arch>\n")
    for name, raw in members:
        header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(raw):<10}" + chr(96) + "\n"
        result.extend(header.encode("ascii"))
        result.extend(raw)
        if len(raw) % 2:
            result.extend(b"\n")
    return bytes(result)


def native_cargo_data(*, candidate=False, source=Path("/source")):
    """Synthetic graph DATA plus real manifest/lock/notice correspondence.

    This fixture is not a Cargo capture or compilation receipt. The original
    source-bound metadata for each actual profile is admitted separately.
    """
    manifest_paths = (
        "desktop/src-tauri/Cargo.toml",
        "desktop/native/linux-mount-observation/Cargo.toml",
        "desktop/vendor/secret-service-5.2.0/Cargo.toml",
        "desktop/vendor/zbus-5.19.0/Cargo.toml",
    )
    packages = []
    for relative in manifest_paths:
        manifest = S.tomllib.loads((SOURCE / relative).read_text(encoding="utf-8"))
        package = manifest["package"]
        path = source / relative
        packages.append({"id": "path+" + path.parent.as_uri() + "#" + package["name"] + "@" + package["version"],
                         "name": package["name"], "version": package["version"], "license": package["license"],
                         "source": None, "manifest_path": str(path)})
    root_manifest = S.tomllib.loads((SOURCE / manifest_paths[0]).read_text(encoding="utf-8"))
    declarations = []
    for target, table in [(None, root_manifest), *root_manifest.get("target", {}).items()]:
        for kind, section in ((None, "dependencies"), ("dev", "dev-dependencies"), ("build", "build-dependencies")):
            for name, fields in table.get(section, {}).items():
                if not isinstance(fields, dict) or "path" not in fields and name != "zbus":
                    continue
                row = {"name": name, "target": target, "kind": kind, "rename": None, "registry": None,
                       "req": fields.get("version", "*"), "optional": fields.get("optional", False),
                       "features": fields.get("features", []), "uses_default_features": fields.get("default-features", True),
                       "source": None if "path" in fields else "registry+https://github.com/rust-lang/crates.io-index"}
                if "path" in fields:
                    row["path"] = os.path.normpath(str((source / manifest_paths[0]).parent / fields["path"]))
                declarations.append(row)
    packages[0]["dependencies"] = declarations
    notices = S.D.decode((SOURCE / "desktop/packaging/debian/native-notices/inputs.json").read_bytes(), 1 << 20)
    locked = S.tomllib.loads((SOURCE / "desktop/src-tauri/Cargo.lock").read_text(encoding="utf-8"))
    for crate in notices["crates"]:
        name, version = crate["name"], crate["version"]
        packages.append({"id": "registry+https://github.com/rust-lang/crates.io-index#" + name + "@" + version,
                         "name": name, "version": version, "license": crate["license"],
                         "source": "registry+https://github.com/rust-lang/crates.io-index",
                         "manifest_path": "/private/cargo/registry/src/index/" + name + "-" + version + "/Cargo.toml"})
    nodes = [{"id": row["id"], "features": [], "deps": [], "dependencies": []} for row in packages]
    nodes[0]["features"] = [] if candidate else ["ubuntu-runtime-publisher"]
    nodes[0]["deps"] = [{"name": row["name"].replace("-", "_"), "pkg": row["id"],
                        "dep_kinds": [{"kind": None, "target": None}]} for row in packages[1:4]]
    nodes[0]["dependencies"] = [row["id"] for row in packages[1:4]]
    root_id = packages[0]["id"]
    return {"version": 1, "workspace_root": str(source / "desktop/src-tauri"),
            "target_directory": str(source / "desktop/src-tauri/target"), "build_directory": str(source / "desktop/src-tauri/target"),
            "workspace_members": [root_id], "workspace_default_members": [root_id],
            "packages": packages, "resolve": {"root": root_id, "nodes": nodes}}, notices, locked



class PublisherCI(unittest.TestCase):

    def test_native_cargo_profiles_bind_current_manifests_lock_and_notices(self):
        manifest = S.tomllib.loads((SOURCE / "desktop/src-tauri/Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(manifest["features"]["default"], [])
        self.assertEqual(manifest["features"]["ubuntu-runtime-publisher"], [])
        self.assertEqual(manifest["patch"], {"crates-io": {"zbus": {"path": "../vendor/zbus-5.19.0"}}})
        for candidate in (False, True):
            value, notices, locked = native_cargo_data(candidate=candidate)
            with self.subTest(candidate=candidate):
                _, packages, nodes = S.native_cargo_metadata(
                    S.D.canonical(value), Path("/source"), Path("/source/desktop/src-tauri/target"),
                    notices["crates"], locked, candidate=candidate)
                self.assertEqual(len(packages), len(notices["crates"]) + 4)
                self.assertEqual((len(packages), len(notices["crates"]),
                                  sum(row["source"] is None for row in packages.values())), (106, 102, 4))
                self.assertEqual({row["name"] for row in packages.values() if row["source"] is None},
                                 {"mobile-release-kit-desktop", "mrk-linux-mount-observation", "secret-service", "zbus"})
                self.assertEqual(nodes[value["resolve"]["root"]]["features"], [] if candidate else ["ubuntu-runtime-publisher"])
                keys = {(row["name"], row["version"]) for row in notices["crates"]}
                self.assertLess(keys, {(row["name"], row["version"]) for row in locked["package"] if "source" in row})
                self.assertTrue({("ordered-stream", "0.2.0"), ("aes", "0.9.2"), ("zbus_macros", "5.19.0"),
                                 ("sha2", "0.10.9"), ("sha2", "0.11.0")} <= keys)
                # This is an externally expected metadata target, not necessarily
                # the separate private compiler output directory.
                private_target = deepcopy(value)
                private_target.update(target_directory="/private-metadata-target", build_directory="/private-metadata-target")
                S.native_cargo_metadata(S.D.canonical(private_target), Path("/source"), Path("/private-metadata-target"),
                                        notices["crates"], locked, candidate=candidate)
                with self.assertRaises(S.D.Refused):
                    S.native_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/private-metadata-target"),
                                            notices["crates"], locked, candidate=candidate)

    def test_native_inputs_entry_preserves_each_metadata_profile_before_any_tool(self):
        class BeforeTools(Exception):
            pass

        class NoCommands:
            def command(self, *args, **kwargs):
                raise AssertionError("Native DATA entry test reached an external tool")

        original = S.native_source_notice_inputs

        def stop_after_originals(source, admitted, rows):
            observed = original(source, admitted, rows)
            self.assertEqual(len(observed), 6)
            raise BeforeTools

        for candidate in (False, True):
            value, notices, _ = native_cargo_data(candidate=candidate, source=SOURCE)
            with self.subTest(candidate=candidate), tempfile.TemporaryDirectory(prefix="mrk-native-entry-data-") as name:
                work = Path(name)
                # Native notice inventory/readback and source admission are real
                # DATA checks. Suppress duplicate copies, then stop before the
                # first crate-cache, compiler, package or live-host operation.
                with patch.object(S.D, "copy") as copies, \
                     patch.object(S, "native_source_notice_inputs", side_effect=stop_after_originals), \
                     patch.object(S, "protected_host_file", side_effect=AssertionError("Live host access")):
                    with self.assertRaises(BeforeTools):
                        S.native_inputs(NoCommands(), SOURCE, work, {}, "/unused/cargo", "/unused/rustc",
                                        S.D.canonical(value), candidate=candidate)
                    self.assertEqual(copies.call_count, len(notices["files"]) + 1)
        # The existing fixed producer entry must forward its observed profile;
        # a default argument must not silently turn installed compilation on.
        owner = (SOURCE / "desktop/tools/ci_ubuntu_publication.py").read_text(encoding="utf-8")
        self.assertIn("native = native_inputs(check, source, work, environment, cargo, rustc, metadata_raw, candidate=installed_compile)", owner)

    def test_native_cargo_refuses_stale_duplicate_or_substituted_inputs(self):
        original, notices, locked = native_cargo_data()
        changes = (
            ("missing-registry", lambda row: row["packages"].pop()),
            ("extra-registry", lambda row: row["packages"].append(deepcopy(row["packages"][-1]))),
            ("duplicate-id", lambda row: row["packages"][-1].update(id=row["packages"][-2]["id"])),
            ("duplicate-registry-key", lambda row: row["packages"][-1].update(
                name=row["packages"][-2]["name"], version=row["packages"][-2]["version"])),
            ("different-registry-key", lambda row: row["packages"][-1].update(version="99.0.0")),
            ("different-source", lambda row: row["packages"][-1].update(source="registry+https://unreviewed.invalid/index")),
            ("different-license", lambda row: row["packages"][-1].update(license="not-the-original-license")),
            ("sdk-registry-fallback", lambda row: row["packages"][3].update(
                source="registry+https://github.com/rust-lang/crates.io-index")),
            ("sdk-path-substitution", lambda row: row["packages"][2].update(manifest_path="/elsewhere/Cargo.toml")),
            ("foreign-platform", lambda row: row["packages"][3].update(name="mrk-windows-installed-native")),
            ("missing-declaration", lambda row: row["packages"][0]["dependencies"].pop()),
            ("missing-declaration-role", lambda row: next(item for item in row["packages"][0]["dependencies"]
                if item["name"] == "mrk-windows-installed-native" and item["kind"] == "dev").update(features=[])),
            ("relabelled-source-id", lambda row: (
                row["packages"][-1].update(id="not-the-original-cargo-source-id"),
                row["resolve"]["nodes"][-1].update(id="not-the-original-cargo-source-id"))),
        )
        for label, change in changes:
            value = deepcopy(original); change(value)
            with self.subTest(mutation=label), self.assertRaises(S.D.Refused):
                S.native_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/source/desktop/src-tauri/target"),
                                        notices["crates"], locked)
        stale = deepcopy(original)
        stale["packages"] = stale["packages"][:2] + stale["packages"][4:38]
        stale["resolve"]["nodes"] = stale["resolve"]["nodes"][:2] + stale["resolve"]["nodes"][4:38]
        for value, rows in ((original, notices["crates"][:34]), (stale, notices["crates"][:34]),
                            (original, notices["crates"] + [notices["crates"][-1]]),
                            (original, notices["crates"][:-1])):
            with self.subTest(stale_or_duplicate_count=len(rows)), self.assertRaises(S.D.Refused):
                S.native_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/source/desktop/src-tauri/target"),
                                        rows, locked)
        for mutation in ("checksum", "source", "missing", "duplicate"):
            value = deepcopy(locked)
            key = (notices["crates"][0]["name"], notices["crates"][0]["version"])
            row = next(row for row in value["package"] if (row["name"], row["version"]) == key and "source" in row)
            if mutation == "missing":
                value["package"].remove(row)
            elif mutation == "duplicate":
                value["package"].append(deepcopy(row))
            else:
                row[mutation] = "0" * 64 if mutation == "checksum" else "registry+https://unreviewed.invalid/index"
            with self.subTest(lock=mutation), self.assertRaises(S.D.Refused):
                S.native_cargo_metadata(S.D.canonical(original), Path("/source"), Path("/source/desktop/src-tauri/target"),
                                        notices["crates"], value)

    def test_native_cargo_resolve_roots_roles_and_profiles_are_not_interchangeable(self):
        original, notices, locked = native_cargo_data()
        changes = (
            ("workspace", lambda row: row.update(workspace_root="/other")),
            ("target", lambda row: row.update(target_directory="/private-compile-target")),
            ("build-target", lambda row: row.update(build_directory="/private-compile-target")),
            ("members", lambda row: row.update(workspace_members=[row["packages"][1]["id"]])),
            ("default-members", lambda row: row.update(workspace_default_members=[])),
            ("root", lambda row: row["resolve"].update(root=row["packages"][1]["id"])),
            ("profile", lambda row: row["resolve"]["nodes"][0].update(features=[])),
            ("extra-profile", lambda row: row["resolve"]["nodes"][0].update(features=["ubuntu-runtime-publisher", "development-runtime"])),
            ("duplicate-node", lambda row: row["resolve"]["nodes"].append(deepcopy(row["resolve"]["nodes"][-1]))),
            ("foreign-node", lambda row: row["resolve"]["nodes"][-1].update(id="windows")),
            ("missing-local-node", lambda row: row["resolve"]["nodes"].pop(3)),
            ("foreign-edge", lambda row: row["resolve"]["nodes"][0]["deps"][0].update(pkg="windows")),
            ("duplicate-edge", lambda row: row["resolve"]["nodes"][0]["deps"].append(deepcopy(row["resolve"]["nodes"][0]["deps"][0]))),
            ("missing-edge", lambda row: row["resolve"]["nodes"][0].update(deps=[], dependencies=[])),
            ("unbound-edge", lambda row: row["resolve"]["nodes"][0].update(dependencies=[])),
            ("duplicate-role", lambda row: row["resolve"]["nodes"][0]["deps"][0]["dep_kinds"].append({"kind": None, "target": None})),
            ("unknown-role", lambda row: row["resolve"]["nodes"][0]["deps"][0]["dep_kinds"][0].update(kind="unknown")),
            ("duplicate-features", lambda row: row["resolve"]["nodes"][1].update(features=["x", "x"])),
        )
        for label, change in changes:
            value = deepcopy(original); change(value)
            with self.subTest(mutation=label), self.assertRaises(S.D.Refused):
                S.native_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/source/desktop/src-tauri/target"),
                                        notices["crates"], locked)
        for candidate in (False, True):
            value, _, _ = native_cargo_data(candidate=not candidate)
            with self.subTest(wrong_profile=candidate), self.assertRaises(S.D.Refused):
                S.native_cargo_metadata(S.D.canonical(value), Path("/source"), Path("/source/desktop/src-tauri/target"),
                                        notices["crates"], locked, candidate=candidate)
        # Conservatively accounted does not mean active or compiled. Retain the
        # exact registry package while omitting its synthetic resolve node.
        value = deepcopy(original)
        inactive = value["resolve"]["nodes"].pop()["id"]
        _, packages, nodes = S.native_cargo_metadata(
            S.D.canonical(value), Path("/source"), Path("/source/desktop/src-tauri/target"), notices["crates"], locked)
        self.assertIn(inactive, packages)
        self.assertNotIn(inactive, nodes)
        with self.assertRaises(S.D.Refused):
            S.shell_compiler_units([{"package_id": inactive, "features": []}], packages, nodes)

    def test_native_notices_bind_archive_members_and_maintained_source_originals(self):
        _, notices, _ = native_cargo_data()
        rows = S.D.records(notices["files"])
        observed = S.native_source_notice_inputs(SOURCE, notices, rows)
        originals = {row["path"] for row in observed}
        self.assertEqual(originals, {str(SOURCE / row["sourcePath"]) for row in notices["localSourceNotices"]})
        self.assertEqual(len(originals), 6)
        self.assertIn(str(SOURCE / "desktop/vendor/secret-service-5.2.0/MRK-PATCHES.md"), originals)
        self.assertIn(str(SOURCE / "desktop/vendor/zbus-5.19.0/MRK-MAINTAINED.md"), originals)
        members = [member for crate in notices["crates"] for member in crate.get("noticeMembers", [])]
        self.assertEqual(len(members), 127)  # Independently verified new original archive members.
        self.assertTrue(any(member["member"].endswith("/src/spin/LICENSE") for member in members))
        self.assertTrue(any(member["member"].endswith("/LICENSE-THIRD-PARTY") for member in members))
        for field, replacement in (("member", "other/LICENSE"), ("noticePath", "missing/LICENSE"),
                                   ("size", 0), ("sha256", "0" * 64)):
            changed = deepcopy(notices)
            member = next(crate["noticeMembers"][0] for crate in changed["crates"] if "noticeMembers" in crate)
            member[field] = replacement
            with self.subTest(member=field), self.assertRaises(S.D.Refused):
                S.native_source_notice_inputs(SOURCE, changed, rows)
        binding = next(row for row in notices["localSourceNotices"] if row["sourcePath"].endswith("/zbus-5.19.0/LICENSE"))
        with tempfile.TemporaryDirectory(prefix="mrk-native-notice-data-") as name:
            temporary = Path(name)
            selected = temporary / binding["sourcePath"]
            selected.parent.mkdir(parents=True)
            selected.write_bytes(b"Not the maintained SDK's original license.\n")
            with self.assertRaises(S.D.Refused):
                S.native_source_notice_inputs(temporary, {"crates": [], "localSourceNotices": [binding]}, rows)

    def test_ubuntu_supplier_notice_inventory_and_exact_packages(self):
        root = SOURCE / "desktop/packaging/debian/native-notices"
        raw = S.D.read(root / "inputs.json", 1 << 20)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), S.NOTICE_INPUTS_SHA256)
        admitted = S.D.decode(raw, 1 << 20)
        rows = S.D.records(admitted["files"])
        S.C.conventional_files(S.D, root, sorted(
            [*rows.values(), S.D.file_record(root / "inputs.json")], key=lambda row: row["path"]))
        real_open = S.D._open

        def notice_only(path, limit):
            self.assertTrue(path.is_relative_to(root), "Notice lookup touched live host files")
            return real_open(path, limit)

        observed = {}
        with patch.object(S.D, "_open", side_effect=notice_only), \
             patch.object(S, "protected_host_file", side_effect=AssertionError("Live OS notice lookup")):
            for name, expected in admitted["ubuntu"]["packages"].items():
                actual = {key: expected[key] for key in ("version", "architecture", "sourcePackage", "sourceVersion")}
                actual["binaryPackage"] = name + ":amd64"
                owned = {"/" + row["path"] for row in expected["ownedDocumentation"]}
                observed[name] = S.ubuntu_package_notice(admitted, rows, root, actual, owned)
                self.assertEqual(observed[name]["source"], "reviewed-ubuntu-package-member-data")
                self.assertEqual(observed[name]["packageArchive"], expected["archive"])
        self.assertEqual(len(observed), 11)
        self.assertEqual(observed["gcc-13-x86-64-linux-gnu"]["documentationPackages"], ["gcc-13-base"])
        self.assertEqual(observed["libgcc-s1"]["documentationPackages"], ["gcc-14-base"])
        self.assertEqual(observed["binutils-x86-64-linux-gnu"]["documentationPackages"], ["libbinutils", "binutils-common"])
        self.assertEqual(observed["libbinutils"]["documentationPackages"], ["binutils-common"])
        self.assertEqual(observed["libc6"]["documentationPackages"], [])
        for alias, target in (("GPL", "GPL-3"), ("LGPL", "LGPL-3"), ("GFDL", "GFDL-1.3")):
            row = admitted["ubuntu"]["commonLicenses"][alias]
            self.assertEqual(row["alias"]["target"], target)
            self.assertEqual(row["member"]["path"], "usr/share/common-licenses/" + target)

    def test_ubuntu_supplier_notices_refuse_tuple_roster_reference_and_byte_changes(self):
        root = SOURCE / "desktop/packaging/debian/native-notices"
        admitted = S.D.decode(S.D.read(root / "inputs.json", 1 << 20), 1 << 20)
        rows = S.D.records(admitted["files"])
        name = "gcc-13-x86-64-linux-gnu"
        expected = admitted["ubuntu"]["packages"][name]
        actual = {key: expected[key] for key in ("version", "architecture", "sourcePackage", "sourceVersion")}
        actual["binaryPackage"] = name
        owned = {"/" + row["path"] for row in expected["ownedDocumentation"]}
        with patch.object(S, "protected_host_file", side_effect=AssertionError("Live OS notice lookup")):
            for key in ("version", "architecture", "sourcePackage", "sourceVersion"):
                with self.subTest(changed=key), self.assertRaisesRegex(S.D.Refused, "package tuple differs"):
                    S.ubuntu_package_notice(admitted, rows, root, {**actual, key: "other"}, owned)
            with self.assertRaisesRegex(S.D.Refused, "No reviewed Ubuntu notice mapping"):
                S.ubuntu_package_notice(admitted, rows, root, {**actual, "binaryPackage": "other"}, owned)
            with self.assertRaisesRegex(S.D.Refused, "documentation roster differs"):
                S.ubuntu_package_notice(admitted, rows, root, actual, set())
            missing = deepcopy(admitted)
            del missing["ubuntu"]["commonLicenses"]["GPL"]
            with self.assertRaisesRegex(S.D.Refused, "Missing reviewed Ubuntu common license GPL"):
                S.ubuntu_package_notice(missing, rows, root, actual, owned)
            with tempfile.TemporaryDirectory(prefix="mrk-supplier-notice-data-") as name:
                temporary = Path(name)
                target = temporary / expected["copyright"]["noticePath"]
                target.parent.mkdir(parents=True)
                target.write_bytes(b"Not the original Ubuntu copyright.\n")
                with self.assertRaisesRegex(S.D.Refused, "original copyright bytes differ"):
                    S.ubuntu_package_notice(admitted, rows, temporary, actual, owned)

    def test_fixed_route_and_compiler_profiles(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
               "RUNNER_ARCH": "X64", "GITHUB_EVENT_NAME": "push", "GITHUB_REF": S.REF,
               "MRK_UBUNTU_PUBLICATION_VERIFY": "1", "GITHUB_SHA": "a" * 40, "MRK_PUSH_EVENT_AFTER": "a" * 40,
               "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit"}
        self.assertEqual(S.route(env), "a" * 40)
        for key, value in (("GITHUB_EVENT_NAME", "workflow_dispatch"), ("GITHUB_REF", "refs/heads/main"),
                           ("RUNNER_ENVIRONMENT", "self-hosted"), ("MRK_PUSH_EVENT_AFTER", "b" * 40)):
            with self.subTest(field=key), self.assertRaises(ValueError):
                S.route({**env, key: value})
        for library in (False, True):
            argv = S.compile_argv("/tools/cargo", Path("/source"), Path("/target"), library=library)
            self.assertEqual(argv[:2], ["/tools/cargo", "test" if library else "build"])
            self.assertIn("--offline", argv)
            self.assertIn("--locked", argv)
            self.assertEqual(argv[argv.index("--features") + 1], "ubuntu-runtime-publisher")
            self.assertNotIn("development-runtime", argv)
            self.assertEqual("--no-run" in argv, library)

    def test_installed_compile_is_exact_feature_off_and_preserves_default_profile(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
               "GITHUB_EVENT_NAME": "push", "GITHUB_REF": S.INSTALLED_REF, "MRK_UBUNTU_PUBLICATION_VERIFY": "1",
               "GITHUB_SHA": "a" * 40, "MRK_PUSH_EVENT_AFTER": "a" * 40, "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit"}
        for case in ("compile", "positive", "refuse-writable", "refuse-pth"):
            self.assertEqual(S.route({**env, "MRK_INSTALLED_CASE": case}), "a" * 40)
        for changed in (env, {**env, "MRK_INSTALLED_CASE": "other"}, {**env, "GITHUB_REF": S.REF, "MRK_INSTALLED_CASE": "compile"}):
            with self.assertRaises(ValueError):
                S.route(changed)
        argv = S.compile_argv("/tools/cargo", Path("/source"), Path("/target"), library=True, candidate=True)
        self.assertNotIn("--features", argv)
        self.assertEqual(argv[argv.index("--target") + 1], S.TARGET)
        self.assertEqual(argv[argv.index("--jobs") + 1], "1")
        self.assertTrue({"--locked", "--offline", "--no-default-features", "--lib", "--no-run"} <= set(argv))
        with self.assertRaises(ValueError):
            S.compile_argv("/tools/cargo", Path("/source"), Path("/target"), library=False, candidate=True)
        with tempfile.TemporaryDirectory(prefix="mrk-candidate-profile-data-") as name:
            env, _ = candidate_data(Path(name))
            raw = (Path(name) / "admitted-candidate/candidate-compile.stdout").read_bytes()
            self.assertEqual(S.compiled_artifact(raw, Path("/source"), Path("/target"), library=True, candidate=True).name,
                             "mobile_release_desktop-0123456789abcdef")
            with self.assertRaises(ValueError):
                S.compiled_artifact(raw, Path("/source"), Path("/target"), library=True)
            for old, new in ((b'"features":[]', b'"features":["ubuntu-runtime-publisher"]'), (b'"fresh":false', b'"fresh":true'),
                             (b'/source/desktop/src-tauri/src/lib.rs', b'/different/src/lib.rs')):
                with self.assertRaises(ValueError):
                    S.compiled_artifact(raw.replace(old, new), Path("/source"), Path("/target"), library=True, candidate=True)

    def test_installed_candidate_transport_preserves_original_producer_attempt_and_exact_outputs(self):
        with tempfile.TemporaryDirectory(prefix="mrk-candidate-transport-data-") as name:
            work = Path(name)
            env, elf = candidate_data(work)
            with patch.dict(S.os.environ, env, clear=True), patch.object(S, "elf_dependencies", return_value=elf):
                row, compiler, _, _, producer, artifact_id = S.installed_candidate(work, "a" * 40)
                self.assertEqual((producer, artifact_id, compiler["attempt"]), ("1", "17", "1"))
                self.assertEqual(row["path"], str(work / "admitted-candidate/candidate"))
                for key, value in (("MRK_INSTALLED_CANDIDATE_PRODUCER_ATTEMPT", "3"), ("MRK_INSTALLED_CANDIDATE_PRODUCER_ATTEMPT", "0"),
                                   ("MRK_INSTALLED_CANDIDATE_PRODUCER_ATTEMPT", ""), ("MRK_INSTALLED_CANDIDATE_ARTIFACT_ID", ""),
                                   ("MRK_INSTALLED_CANDIDATE_ARTIFACT_ID", "0"), ("GITHUB_RUN_ID", "11"),
                                   ("MRK_INSTALLED_CANDIDATE_ROSTER_SHA256", "0" * 64)):
                    with self.subTest(field=key, value=value), patch.dict(S.os.environ, {key: value}), self.assertRaises(ValueError):
                        S.installed_candidate(work, "a" * 40)
                with self.assertRaises(ValueError):
                    S.installed_candidate(work, "b" * 40)
                (work / "admitted-candidate/unlisted").write_bytes(b"extra inert DATA")
                with self.assertRaises(ValueError):
                    S.installed_candidate(work, "a" * 40)
        workflow = (SOURCE / S.WORKFLOW).read_text()
        native = workflow.split("      - name: Require the fixed disposable native route", 1)[1]
        guard = native.split("      - name: Observe only the hosted Python body", 1)[0]
        # The successor workflow transports the shell pair. Historical J's
        # feature-off helper contract above remains independently covered.
        for name in ("MRK_INSTALLED_SHELL_ARTIFACT_ID", "MRK_INSTALLED_SHELL_ROSTER_SHA256", "MRK_INSTALLED_SHELL_PRODUCER_ATTEMPT"):
            self.assertIn(name, guard)
        self.assertIn("int(values[1]) > int(values[2])", guard)
        self.assertIn("[1-9][0-9]{0,19}", guard)
        self.assertIn("artifact-ids: ${{ steps.upload.outputs.artifact-id }}", native)
        self.assertIn("MRK_INSTALLED_SHELL_PRODUCER_ATTEMPT: ${{ steps.compile.outputs.shell_producer_attempt }}", native)
        self.assertNotIn("admitted-a", native)

    def test_installed_candidate_rejects_relabelled_profiles_copied_identity_and_executed_results(self):
        changes = (lambda compiler, result, graph, message: compiler.update(features=S.FEATURES),
                   lambda compiler, result, graph, message: compiler.update(attempt="2"),
                   lambda compiler, result, graph, message: result.update(candidateExecuted=True),
                   lambda compiler, result, graph, message: result.update(helper11Rerun=True),
                   lambda compiler, result, graph, message: compiler["exportedArtifacts"]["candidate"].update(identity=compiler["originalArtifacts"]["candidate"]["identity"]),
                   lambda compiler, result, graph, message: compiler["originalArtifacts"]["candidate"].update(path="/elsewhere/candidate"),
                   lambda compiler, result, graph, message: message.update(fresh=True))
        for index, change in enumerate(changes):
            with self.subTest(change=index), tempfile.TemporaryDirectory(prefix="mrk-candidate-refusal-data-") as name:
                env, elf = candidate_data(Path(name), change)
                with patch.dict(S.os.environ, env, clear=True), patch.object(S, "elf_dependencies", return_value=elf), self.assertRaises(ValueError):
                    S.installed_candidate(Path(name), "a" * 40)

    def test_actual_u_gate_is_closed_before_any_artifact_access(self):
        with patch.object(S, "INSTALLED_U_INPUTS", None), patch.object(S.C, "conventional_files") as files, patch.object(S.D, "read") as read:
            with self.assertRaisesRegex(ValueError, "independently accepted U"):
                S.installed_u_inputs(Path("/inert-work"))
            files.assert_not_called()
            read.assert_not_called()

    def test_accepted_u_uses_lifecycle_deadline_format_after_complete_byte_admission(self):
        # Synthetic JSON and mocked transport only; the decoder and original
        # finality decision are real. No package/tool/process is opened.
        lifecycle = S.local("ubuntu_publication_lifecycle")
        accepted = {"sourceSha": "a" * 40, "runId": "10", "attempt": "1", "artifactId": "20", "files": []}
        pin = {"size": 1, "sha256": "b" * 64}
        # Fixed generation literals make this independent of the active expected pins.
        current_manifests = {
            "P0": "8ef2fefe057a1773acb8d5d514adc08c28baebc98d4178f448ad2b74be204d66",
            "F1": "6f3005c479a8b14992f9e73135b6c3f21119a014d5212c5603cafa3b3b395757",
        }
        historical_manifests = {
            "P0": "556b2ea59b4b3e9abb9d04a3d263e0fd420e8c44b3f71c478b1f71bdd21ec417",
            "F1": "1270d1d7d9427fff260bb1e79f51c1c3c14145651db87014b0ee9d08d601c112",
        }
        packages = {label: {**pin, "manifestSha256": current_manifests[label],
                            "version": "0.0.0+mrk.lifecycle." + version}
                    for label, version in (("P0", "0"), ("F1", "1"))}
        unit = "mrk-ubuntu-native-10-1.service"
        start = {"sourceSha": accepted["sourceSha"], "entrySha256": "c" * 64, "handoffSha256": "d" * 64,
                 "invocationId": "e" * 32, "deadline": 1231.74561711, "namespaces": {}, "effective": {},
                 "unit": {"Id": unit, "InvocationID": "e" * 32, "Result": "success", "ControlGroup": "/system.slice/" + unit},
                 "events": {"memory.events": {"max": 0, "oom": 0, "oom_kill": 0}, "pids.events": {"max": 0}}}
        body = b"inert result DATA"
        stop = {**deepcopy(start), "completion": {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"},
                "result": {"path": "unit-result.json", "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}}
        result = {"sourceSha": accepted["sourceSha"], "commands": [{"phase": "root-lifecycle", "exitCode": 0}],
                  "lifecycle": {"state": "p0-f1-lifecycle-observed"}, "helper11Rerun": False,
                  "qualified": False, "packages": packages}
        documents = {
            "compiler.json": S.D.canonical({"sourceSha": accepted["sourceSha"], "library": pin}),
            "result.json": S.D.canonical(result),
            "lifecycle-unit-start.json": S.D.canonical(start),
            "lifecycle-unit-stop.json": S.D.canonical(stop),
            "lifecycle-unit-result.json": body,
        }
        with self.assertRaisesRegex(ValueError, "Unexpected DATA scalar"):
            S.D.decode(documents["lifecycle-unit-start.json"])
        with patch.object(S, "INSTALLED_U_INPUTS", accepted), \
             patch.object(S.C, "conventional_files") as files, \
             patch.object(S.D, "read", side_effect=lambda path, limit: documents[path.name]) as read, \
             patch.object(S.D, "file_record", side_effect=lambda path, limit: {"path": path.name, **pin}), \
             patch.object(S, "local", return_value=lifecycle) as loaded, \
             patch.object(lifecycle, "decode", wraps=lifecycle.decode) as decode, \
             patch.object(lifecycle, "verify_finality", wraps=lifecycle.verify_finality) as finality:
            library, observed, compiler, identity = S.installed_u_inputs(Path("/inert-work"))
            files.assert_called_once_with(S.D, Path("/inert-work/admitted-u"), accepted["files"])
            self.assertEqual(set(observed), {"P0", "F1"})
            self.assertEqual(identity, {key: value for key, value in accepted.items() if key != "files"})
            self.assertEqual(decode.call_args_list, [unittest.mock.call(documents[name], 1 << 20)
                                                   for name in ("lifecycle-unit-start.json", "lifecycle-unit-stop.json")])
            finality.assert_called_once_with(start, stop, 0)
            self.assertIs(type(finality.call_args.args[0]["deadline"]), float)
            self.assertEqual(finality.call_args.args[0]["deadline"], 1231.74561711)
            self.assertEqual({label: row["manifestSha256"] for label, row in observed.items()}, current_manifests)
            for labels in (("P0",), ("F1",), ("P0", "F1")):
                with self.subTest(historical=labels):
                    changed = deepcopy(result)
                    for label in labels:
                        changed["packages"][label]["manifestSha256"] = historical_manifests[label]
                    documents["result.json"] = S.D.canonical(changed)
                    with self.assertRaisesRegex(ValueError, "Accepted U package bytes/anchors differ"):
                        S.installed_u_inputs(Path("/inert-work"))
            for label in ("P0", "F1"):
                for field, value in (("size", 2), ("sha256", "0" * 64), ("version", "0.0.0+mrk.lifecycle.99")):
                    with self.subTest(package=label, field=field):
                        changed = deepcopy(result)
                        changed["packages"][label][field] = value
                        documents["result.json"] = S.D.canonical(changed)
                        with self.assertRaisesRegex(ValueError, "Accepted U package bytes/anchors differ"):
                            S.installed_u_inputs(Path("/inert-work"))
            documents["result.json"] = S.D.canonical(result)
            # A changed original endpoint is still a finality failure.
            documents["lifecycle-unit-stop.json"] = S.D.canonical({**stop, "deadline": 1232.74561711})
            with self.assertRaisesRegex(ValueError, "correspondence differs: deadline"):
                S.installed_u_inputs(Path("/inert-work"))
            # Incomplete/changed artifact bytes never reach either parser.
            read.reset_mock(); loaded.reset_mock(); decode.reset_mock(); finality.reset_mock()
            files.side_effect = ValueError("inert complete-member refusal")
            with self.assertRaisesRegex(ValueError, "complete-member refusal"):
                S.installed_u_inputs(Path("/inert-work"))
            read.assert_not_called(); loaded.assert_not_called(); decode.assert_not_called(); finality.assert_not_called()

    def test_only_exact_fresh_compiler_artifact_is_selected(self):
        source, root = Path("/source"), Path("/target")
        for library in (False, True):
            executable = root / S.TARGET / ("debug/deps/mobile_release_desktop-0123456789abcdef" if library else "release/mrk-runtime-publish")
            row = {"reason": "compiler-artifact", "executable": str(executable), "fresh": False,
                   "features": S.FEATURES, "manifest_path": str(source / "desktop/src-tauri/Cargo.toml"),
                   "target": {"kind": ["lib" if library else "bin"], "name": "mobile_release_desktop" if library else "mrk-runtime-publish",
                              "src_path": str(source / "desktop/src-tauri/src" / ("lib.rs" if library else "bin/runtime_publish.rs"))},
                   "profile": {"test": library, "debug_assertions": library, "opt_level": "0" if library else "3"}}
            final = {"reason": "build-finished", "success": True}
            raw = S.D.canonical(row) + S.D.canonical(final)
            self.assertEqual(S.compiled_artifact(raw, source, root, library=library), executable)
            for key, value in (("fresh", True), ("features", []), ("executable", "/different/binary")):
                changed = deepcopy(row)
                changed[key] = value
                with self.subTest(library=library, field=key), self.assertRaises(ValueError):
                    S.compiled_artifact(S.D.canonical(changed) + S.D.canonical(final), source, root, library=library)
            for changed in (S.D.canonical(final), raw + S.D.canonical(final), S.D.canonical(row) * 2 + S.D.canonical(final)):
                with self.assertRaises(ValueError):
                    S.compiled_artifact(changed, source, root, library=library)

    def test_zero_partial_extra_or_failed_tests_are_not_a_pass(self):
        lines = ["running 11 tests", *(f"test {name} ... ok" for name in S.TESTS),
                 "test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.01s"]
        raw = ("\n".join(lines) + "\n").encode("ascii")
        S.test_result(raw, b"")
        for changed in (b"running 0 tests\n", raw.replace(lines[1].encode() + b"\n", b""),
                        raw.replace(b" ... ok", b" ... FAILED", 1), raw + b"test unexpected ... ok\n"):
            with self.assertRaises(ValueError):
                S.test_result(changed, b"")
        with self.assertRaises(ValueError):
            S.test_result(raw, b"unexpected diagnostic")

    def test_single_native_selection_requires_one_actual_exact_pass(self):
        name = "installed_runtime::pure_tests::kernel_scope_is_reviewed_ubuntu"
        self.assertEqual(S.KERNEL_SELECTOR, name)
        raw = ("running 1 test\n"
               f"test {name} ... ok\n"
               "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
               "99 filtered out; finished in 0.01s\n").encode("ascii")
        S.exact_test_result(raw, b"", name)
        for changed in (b"running 0 tests\n", raw.replace(name.encode(), b"different::test"),
                        raw.replace(b" ... ok", b" ... ignored"),
                        raw.replace(b"1 passed; 0 failed", b"0 passed; 1 failed"),
                        raw.replace(b"0 ignored", b"1 ignored"),
                        raw + f"test {name} ... ok\n".encode("ascii")):
            with self.subTest(output=changed), self.assertRaises(ValueError):
                S.exact_test_result(changed, b"", name)
        with self.assertRaises(ValueError):
            S.exact_test_result(raw, b"unexpected diagnostic", name)

    def test_elf_dependency_reader_rejects_loader_overrides_and_out_of_bounds(self):
        observed = S.elf_dependencies(elf_data())
        self.assertEqual(observed["interpreter"], "/lib64/ld-linux-x86-64.so.2")
        self.assertEqual(observed["needed"], ["libc.so.6"])
        self.assertEqual(observed["versionNeeds"], {"libc.so.6": ["GLIBC_2.34"]})
        self.assertEqual(S.elf_dependencies(elf_data(definitions=True))["versionDefinitions"], ["GLIBC_2.34"])
        for tag in (15, 29, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                S.elf_dependencies(elf_data(tag))
        for raw in (elf_data()[:1100], b"inert non-ELF data", elf_data().replace(b"GLIBC_2.34\0", b"GLIBC_2.34x")):
            with self.assertRaises(ValueError):
                S.elf_dependencies(raw)
        outside = bytearray(elf_data())
        struct.pack_into("<Q", outside, 640 + 16 + 8, 1 << 60)
        with self.assertRaises(ValueError):
            S.elf_dependencies(bytes(outside))

    def test_private_runpath_is_allowed_only_for_three_exact_a_objects(self):
        for path, (soname, runpath) in S.RUNTIME_ELF.items():
            raw = runtime_elf_data(path)
            parsed = S.elf_dependencies(raw, runtime_path=path)
            self.assertEqual((parsed["soname"], parsed["runpath"]), (soname, runpath))
            with self.assertRaises(ValueError):
                S.elf_dependencies(raw)
            for different in ("$ORIGIN:/tmp", "/usr/lib", "", "$ORIGIN/../../lib"):
                with self.subTest(path=path, runpath=different), self.assertRaises(ValueError):
                    S.elf_dependencies(runtime_elf_data(path, runpath=different), runtime_path=path)
            with self.assertRaises(ValueError):
                S.elf_dependencies(raw, runtime_path="python/lib/unreviewed.so")
        with self.assertRaises(ValueError):
            S.elf_dependencies(elf_data(), runtime_path="python/bin/python3")

    def test_complete_a_candidate_graph_rejects_missing_versions_and_search_overrides(self):
        def elf(needed, soname=None):
            return {"needed": needed, "soname": soname, "versionNeeds": {}, "versionDefinitions": ["GLIBC_2.34"]}
        os_objects = {"ld-linux-x86-64.so.2": elf([], "ld-linux-x86-64.so.2"),
                      "libc.so.6": elf(["ld-linux-x86-64.so.2"], "libc.so.6"),
                      "libm.so.6": elf(["libc.so.6"], "libm.so.6"),
                      "libgcc_s.so.1": elf(["libc.so.6"], "libgcc_s.so.1")}
        objects = {"python/bin/python3": elf(["libssl.so.3", "libcrypto.so.3", "libm.so.6", "libc.so.6"]),
                   "python/lib/libssl.so.3": elf(["libcrypto.so.3", "libc.so.6"], "libssl.so.3"),
                   "python/lib/libcrypto.so.3": elf(["libc.so.6"], "libcrypto.so.3")}
        native = {"sharedObjects": {name: {"elf": row} for name, row in os_objects.items()},
                  "outputs": {"candidate": {"elf": elf(["libgcc_s.so.1", "libc.so.6"]),
                                               "objects": ["ld-linux-x86-64.so.2", "libc.so.6", "libgcc_s.so.1"]}}}
        rows = {name: {"path": name, "size": 1, "sha256": "a" * 64} for name in S.RUNTIME_ELF}

        def run(records, dependencies=native, selected=objects):
            with patch.object(S.D, "bound"), patch.object(S.D, "read", return_value=b"inert ELF DATA"), \
                 patch.object(S, "elf_dependencies", side_effect=lambda raw, runtime_path: selected[runtime_path]):
                return S.installed_graph(Path("/inert-runtime"), records, dependencies)

        graph = run(rows)
        self.assertEqual(graph["osNames"], sorted(os_objects))
        self.assertEqual(set(graph["runtimeObjects"]), {"ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6", "libssl.so.3", "libcrypto.so.3"})
        for extra in ("python/pyvenv.cfg", "python/bin/python3._pth", "pybuilddir.txt", "python/lib/libgcc_s.so.1",
                      "python/lib/glibc-hwcaps/x86-64-v3/libcrypto.so.3", "python/lib/extra.so"):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                run({**rows, extra: {"path": extra, "size": 0, "sha256": "b" * 64}})
        missing = deepcopy(native)
        del missing["sharedObjects"]["libgcc_s.so.1"]
        with self.assertRaises(ValueError):
            run(rows, missing)
        changed = deepcopy(objects)
        changed["python/lib/libssl.so.3"]["versionNeeds"] = {"libc.so.6": ["GLIBC_UNAVAILABLE"]}
        with self.assertRaises(ValueError):
            run(rows, selected=changed)
        changed = deepcopy(native)
        changed["outputs"]["candidate"]["objects"].remove("libgcc_s.so.1")
        with self.assertRaises(ValueError):
            run(rows, changed)

    def test_ldconfig_tool_must_be_static_native_elf_without_loader_edges(self):
        raw = bytearray(256)
        raw[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
        struct.pack_into("<HHIQQQIHHHHHH", raw, 16, 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        struct.pack_into("<IIQQQQQQ", raw, 64, 1, 4, 0, 0, 0, len(raw), len(raw), 4096)
        S.static_ldconfig(bytes(raw))
        for data in (b"#!/bin/sh\n", elf_data()):
            with self.assertRaises(ValueError):
                S.static_ldconfig(data)
        for tag in (1, 15, 29, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff):
            changed = bytearray(raw)
            struct.pack_into("<IIQQQQQQ", changed, 64, 2, 4, 128, 128, 128, 32, 32, 8)
            struct.pack_into("<qQ", changed, 128, tag, 1)
            struct.pack_into("<qQ", changed, 144, 0, 0)
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                S.static_ldconfig(bytes(changed))

    def test_complete_deb_readback_rejects_changed_unowned_or_hidden_members(self):
        files, controls = {"usr/share/inert": b"DATA"}, {"control": b"Package: inert-fixture\n"}
        expected, expected_control = package_rows(files), package_rows(controls)
        with tempfile.TemporaryDirectory(prefix="mrk-deb-readback-data-") as name:
            path = Path(name) / "fixture.deb"
            path.write_bytes(package_data(files, controls))
            S.deb_readback(path, expected, expected_control)
            # Real manifest-addressed package paths require GNU long-name DATA.
            long_name = "usr/lib/mobile-release-kit/runtime-input/" + "a" * 64 + "/python/bin/python3"
            long_files = {long_name: b"inert long-name payload"}
            path.write_bytes(package_data(long_files, controls, tar_format=tarfile.GNU_FORMAT))
            S.deb_readback(path, package_rows(long_files), expected_control)
            path.write_bytes(package_data(long_files, controls, tar_format=tarfile.PAX_FORMAT))
            with self.assertRaises(ValueError):
                S.deb_readback(path, package_rows(long_files), expected_control)
            for change in ("owner", "mode", "bytes", "missing", "link"):
                def mutate(archive, member, info, raw):
                    if archive == "data.tar" and member == "usr/share/inert":
                        if change == "owner":
                            info.uid = 1000
                        elif change == "mode":
                            info.mode = 0o600
                        elif change == "bytes":
                            raw = b"EVIL"
                        elif change == "missing":
                            return None, b""
                        else:
                            info.type, info.linkname, info.size = tarfile.SYMTYPE, "/outside", 0
                            raw = b""
                    return info, raw
                path.write_bytes(package_data(files, controls, mutate=mutate))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    S.deb_readback(path, expected, expected_control)
            extra = {**files, "usr/share/unexpected": b"extra"}
            path.write_bytes(package_data(extra, controls))
            with self.assertRaises(ValueError):
                S.deb_readback(path, expected, expected_control)
            for name in ("opt/unexpected", "var/lib/mobile-release-kit/versions/unexpected"):
                forbidden = {**files, name: b"never package published versions"}
                path.write_bytes(package_data(forbidden, controls))
                with self.subTest(path=name), self.assertRaises(ValueError):
                    S.deb_readback(path, package_rows(forbidden), expected_control)
            path.write_bytes(package_data(files, controls, trailing=True))
            with self.assertRaises(ValueError):
                S.deb_readback(path, expected, expected_control)

    def test_failed_or_expired_command_never_becomes_success(self):
        with tempfile.TemporaryDirectory(prefix="mrk-publisher-ci-data-") as name:
            root = Path(name)
            (root / "public").mkdir()
            argv = ["/inert-tool"]
            outcome = subprocess.CompletedProcess(argv, 7, b"synthetic output", b"synthetic failure")
            with patch.object(S.time, "monotonic", return_value=100) as clock, patch.object(S.D, "write", wraps=S.D.write):
                owner = unittest.mock.Mock(return_value=outcome)
                check = S.Check(root, owner, deadline=120)
                self.assertEqual(check.end, 120)
                with self.assertRaisesRegex(ValueError, r"failed \(exitCode=7, endpointExpired=False\)"):
                    check.command("failed", argv, {}, root)
                self.assertEqual(owner.call_count, 1)
                self.assertEqual((root / "public/failed.stderr").read_bytes(), b"synthetic failure")
                self.assertEqual(check.commands[0]["exitCode"], 7)
                self.assertTrue(check.failed)
                with self.assertRaises(ValueError):
                    check.command("must-not-launch", argv, {}, root)
                self.assertEqual(owner.call_count, 1)
                expired = S.Check(root, owner, deadline=99)
                with self.assertRaises(ValueError):
                    expired.command("expired", argv, {}, root)
                self.assertEqual(owner.call_count, 1)
                def returned_late(*args, **kwargs):
                    clock.return_value = 121
                    return subprocess.CompletedProcess(argv, 0, b"synthetic late output", b"")
                late_owner = unittest.mock.Mock(side_effect=returned_late)
                late = S.Check(root, late_owner, deadline=120)
                with self.assertRaisesRegex(ValueError, r"late \(exitCode=0, endpointExpired=True\)"):
                    late.command("late", argv, {}, root)
                self.assertEqual(late_owner.call_count, 1)
                self.assertEqual((root / "public/late.stdout").read_bytes(), b"synthetic late output")
                self.assertEqual(late.commands[0]["exitCode"], 0)
                self.assertTrue(late.commands[0]["ordinaryOwnerReturned"])
                self.assertTrue(late.failed)
                with self.assertRaises(ValueError):
                    late.command("late-must-not-launch", argv, {}, root)
                self.assertEqual(late_owner.call_count, 1)

    def test_compiler_hardlink_exports_fresh_verified_data_only(self):
        with tempfile.TemporaryDirectory(prefix="mrk-publisher-copy-data-") as name:
            root = Path(name)
            source, alias, destination = root / "compiler-data", root / "compiler-alias", root / "exported-data"
            source.write_bytes(b"inert compiler DATA; never execute")
            source.chmod(0o700)
            os.link(source, alias)
            before = source.stat()
            result = S.artifact_record(source, copy_to=destination)
            self.assertEqual(result["sha256"], S.D.file_record(destination)["sha256"])
            self.assertNotEqual(before.st_ino, destination.stat().st_ino)
            self.assertEqual(source.stat().st_nlink, 2)
            self.assertEqual(destination.stat().st_nlink, 1)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o555)
            with self.assertRaises(FileExistsError):
                S.artifact_record(source, copy_to=destination)
            self.assertEqual(destination.read_bytes(), source.read_bytes())


if __name__ == "__main__":
    unittest.main()
