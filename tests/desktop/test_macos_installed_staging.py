"""Focused DATA parser definitions; never a native install/GUI qualification.

These tests do not import the core, stage/extract M, launch Python/app children,
write an installation, construct a panel, or fabricate an operation permit.
"""
import ast
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import stat
import struct
from subprocess import CompletedProcess
import sys
import tempfile
import tomllib
from types import FunctionType, SimpleNamespace
import unittest
from unittest import mock

TOOL = None
ANDROID_HELPER = None
if sys.platform in ("darwin", "linux"):
    path = Path(__file__).absolute().parents[2] / "desktop/tools/stage_macos_installed.py"
    spec = importlib.util.spec_from_file_location("macos_installed_staging_data", path)
    TOOL = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(TOOL)
    path = Path(__file__).absolute().parents[2] / "desktop/tools/macos_android_helper_package.py"
    spec = importlib.util.spec_from_file_location("macos_android_helper_packaging_data", path)
    ANDROID_HELPER = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ANDROID_HELPER)


def workflow_step(workflow, name):
    """Select one reviewed named step, without consuming unrelated later steps."""
    marker = "      - name: " + name + "\n"
    if workflow.count(marker) != 1:
        raise AssertionError("expected exactly one workflow step: " + name)
    return workflow.split(marker, 1)[1].split("      - name: ", 1)[0]


def normal_app_steps(workflow):
    return tuple(workflow_step(workflow, name) for name in (
        "Build the ordinary ARM64 desktop image and embedded frontend",
        "Assemble the ordinary image app and sign code inside-out (never --deep)",
        "Bind this completed signed app and current-source runtime into fresh Installer DATA"))


def entry_macho_fixture(*extra, library=b"/usr/lib/libSystem.B.dylib", target="aarch64-apple-darwin"):
    """Inert loader-policy DATA, not a compiled/signed/launched entry."""
    cpu, subtype = {"aarch64-apple-darwin": (0x0100000C, 0), "x86_64-apple-darwin": (0x01000007, 3)}[target]
    def named(command, value, prefix):
        data = value + b"\0"
        length = (prefix + len(data) + 7) // 8 * 8
        header = struct.pack("<III", command, length, prefix)
        return header + bytes(prefix - len(header)) + data + bytes(length - prefix - len(data))
    commands = (struct.pack("<6I", 0x32, 24, 1, 26 << 16, 26 << 16, 0),
                named(0xC, library, 24), named(0xE, b"/usr/lib/dyld", 12),
                struct.pack("<IIQQ", 0x80000028, 24, 0, 0), *extra)
    return struct.pack("<8I", 0xFEEDFACF, cpu, subtype, 2, len(commands),
                       sum(map(len, commands)), 0x200084, 0) + b"".join(commands)


def image_macho_fixture(role="desktop", *extra, install_name=None, library=b"/usr/lib/libSystem.B.dylib", kind=6, target="aarch64-apple-darwin"):
    """Actual MH_DYLIB-shaped inert DATA, never a renamed executable/native pass."""
    cpu, subtype = {"aarch64-apple-darwin": (0x0100000C, 0), "x86_64-apple-darwin": (0x01000007, 3)}[target]
    def named(command, value):
        data = value + b"\0"
        length = (24 + len(data) + 7) // 8 * 8
        return struct.pack("<6I", command, length, 24, 0, 0, 0) + data + bytes(length - 24 - len(data))
    identity = TOOL.IMAGE_INSTALL_NAMES[role].encode("ascii") if install_name is None else install_name
    commands = (struct.pack("<6I", 0x32, 24, 1, 26 << 16, 26 << 16, 0),
                named(0xD, identity), named(0xC, library), *extra)
    return struct.pack("<8I", 0xFEEDFACF, cpu, subtype, kind, len(commands),
                       sum(map(len, commands)), 0x84, 0) + b"".join(commands)


def packaging_fixture(target="aarch64-apple-darwin", *, package=b"synthetic completed package DATA"):
    """Public malformed-certificate-free DATA only; never a signing credential."""
    service = (b"schema=1\napp-identifier=dev.mobile-release-kit.desktop\n"
        b"helper-identifier=dev.mobile-release-kit.desktop.android-register\n"
        b"team-identifier=TEST000001\ndeveloper-id-certificate-sha1=" + b"1" * 40 + b"\n")
    profile = (b"schema=1\nstate=configured\nteam-identifier=TEST000001\nrsa-bits=2048\n"
        b"leaf-certificate-sha1=" + b"1" * 40 + b"\nleaf-certificate-sha256=" + b"2" * 64
        + b"\nissuer-certificate-sha256=" + b"3" * 64 + b"\nroot-certificate-sha256=" + b"4" * 64
        + b"\npublic-key-pkcs1-sha256=" + b"5" * 64 + b"\n")
    prefix = "macos26-arm64-" if target == TOOL.ARM_TARGET else "macos26-x86_64-"
    selection = TOOL.BuildSelection(target, "0.2.0", prefix + "packaging-data-02")
    history = {"schemaVersion": 1, "targets": {name: {"acceptedPredecessors": [], "signingPolicies": []}
               for name in TOOL.MAC_TARGETS}}
    # Independent literal declaration order matching the public PolicyWire
    # schema, not the new descriptor assembly function under test.
    policy = {"schemaVersion": 1, "kind": "mrk-macos-developer-id-code-policy-v1", "teamIdentifier": "TEST000001",
              "leafCertificateSha1": "1" * 40, "leafCertificateSha256": "2" * 64,
              "hardenedRuntime": True, "entitlements": "empty"}
    policy_sha = TOOL.digest(json.dumps(policy, separators=(",", ":")).encode("ascii"))
    current = {"profile": "fixed-macos26-arm64-maintenance-v2" if target == TOOL.ARM_TARGET else "fixed-macos26-x86_64-maintenance-v2",
        "packageIdentifier": TOOL.PACKAGE_ID, "bundleIdentifier": TOOL.BUNDLE_ID,
        "packageVersion": selection.package_version, "release": selection.release, "sourceCommit": "a" * 40,
        "protocolSha256": TOOL.CURRENT_PROTOCOL, "runtimeManifestSha256": "c" * 64, "inventorySha256": "d" * 64,
        "signingPolicySha256": policy_sha, "packageSha256": TOOL.digest(package)}
    descriptor = {"schemaVersion": 2, "kind": "mrk-macos-install-producer-v2", "domain": "MobileReleaseKit-package-producer-v2",
        "target": target, "releaseSet": {"schemaVersion": 2, "current": current, "acceptedPredecessors": []},
        "signingPolicies": [{"sha256": policy_sha, "policy": policy}]}
    return profile, service, selection, history, descriptor


@unittest.skipUnless(ANDROID_HELPER is not None, "POSIX inert packaging DATA only")
class MacAndroidHelperPackagingData(unittest.TestCase):
    """No compiler/codesign/helper/owner execution; every child is a DATA double."""

    def python_image(self, target, flags=0x2):
        # Minimal inert embedded CodeDirectory DATA; never executable proof.
        cpu, subtype = TOOL.target_machine(target)
        payload = b"I" * 16
        directory = struct.pack(">4I", 0xFADE0C02, 44, 0x20500, flags) + bytes(28)
        blob = struct.pack(">5I", 0xFADE0CC0, 64, 1, 0, 20) + directory
        offset = 48 + len(payload)
        return (struct.pack("<8I", 0xFEEDFACF, cpu, subtype, 2, 1, 16, 0, 0)
                + struct.pack("<4I", 0x1D, 16, offset, len(blob)) + payload + blob)

    def python_data_functions(self):
        # Extract only already-reviewed pure functions, not a builder/owner or
        # native module import. Final controls pin these exact SOURCE companions.
        module, root = ANDROID_HELPER, Path(__file__).absolute().parents[2]
        def functions(filename, names, scope):
            path = root / "desktop/tools" / filename
            nodes = [node for node in ast.parse(path.read_text()).body
                     if isinstance(node, ast.FunctionDef) and node.name in names]
            self.assertEqual({node.name for node in nodes}, set(names))
            exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), scope)
            return SimpleNamespace(**{name: scope[name] for name in names})
        def thin(body, machine):
            module.need(type(body) is bytes and len(body) >= 32 and body[:4] == b"\xcf\xfa\xed\xfe"
                        and struct.unpack_from("<I", body, 4)[0] == {"arm64": 0x100000C, "x86_64": 0x1000007}[machine],
                        "inert-thin-fixture")
            return body
        matcher = functions("macos_cpython_orchestrator.py", ("macho_records", "macho_content_valid"),
            {"struct": struct, "need": module.need, "native_slice": thin,
             "LOAD_COMMANDS": {0xC, 0x80000018, 0x8000001F, 0x80000023},
             "LC_ID_DYLIB": 0xD, "LC_RPATH": 0x8000001C, "LC_LOAD_DYLINKER": 0xE})
        transport = functions("macos_python_supplier_transport.py", ("member_header", "project_archive"),
                              {"tarfile": TOOL.tarfile, "TAR_LIMIT": 512 * 1024 * 1024})
        parsed = functions("macos_cpython_source_build.py", ("probe_result",),
                           {"need": module.need, "decode": TOOL.decode, "target_profile": module.build_profile})
        return transport, matcher, parsed

    def python_fixture(self, root, *, target="aarch64-apple-darwin", phase="python-engineering", failure=None):
        module = ANDROID_HELPER
        transport, matcher, parsed = self.python_data_functions()
        checkout, work = root / "checkout", root / "work"
        checkout.mkdir(mode=0o700); work.mkdir(mode=0o700)
        def source(name, body):
            path = checkout / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(body); path.chmod(0o644)
            return path
        producer, service, _selection, _history, _descriptor = packaging_fixture(target)
        if phase == "python-engineering":
            producer, service = b"schema=1\nstate=unconfigured\n", module.UNCONFIGURED_PROFILE
        if failure == "unconfigured":
            producer, service = b"schema=1\nstate=unconfigured\n", module.UNCONFIGURED_PROFILE
        source(module.PROFILE, service); source(module.PRODUCER_PROFILE, producer)
        empty = (Path(__file__).absolute().parents[2] / "desktop/packaging/macos-empty-entitlements.plist").read_bytes()
        source("desktop/packaging/macos-empty-entitlements.plist", empty)
        names = ("macos_python_supplier_transport.py", "macos_cpython_orchestrator.py", "macos_cpython_source_build.py",
                 "macos_cpython_source_probe.py", "stage_macos_installed.py", "macos_android_helper_package.py")
        for name in names:
            source("desktop/tools/" + name, b"# INERT SOURCE fixture; never loaded\n")
        original = {"python/bin/python3": (self.python_image(target), 0o555)}
        required = []
        for index in range(6):
            body = ("INERT NOTICE " + str(index) + "\n").encode("ascii")
            original["python/licenses/notice-" + str(index) + ".txt"] = (body, 0o444)
            required.append({"component": "inert", "path": str(index), "bytes": len(body), "sha256": module.digest(body)})
        original = dict(sorted(original.items()))
        rows = {name: {"path": name, "size": len(body), "sha256": module.digest(body), "mode": mode}
                for name, (body, mode) in original.items()}
        lock = TOOL.canonical({"schemaVersion": 1, "target": {"triple": target, "minimumMacOS": "26.0", "pythonVersion": "3.14.7", "gil": True},
                               "requiredPublicNoticeInputs": required})
        source(TOOL.source_lock_input(target), lock)
        receipt = TOOL.canonical({"schemaVersion": 1, "kind": TOOL.FRESH_SUPPLIER_KIND, "target": target,
            "pythonVersion": "3.14.7", "gil": True, "sourceLockSha256": module.digest(lock),
            "producerSourceSha256": "1" * 64, "recipeSha256": "2" * 64, "toolchainSha256": "3" * 64,
            "inventorySha256": module.digest(TOOL.canonical(list(rows.values()))), "files": list(rows.values()),
            "notices": sorted(name for name in original if name.startswith("python/licenses/")),
            "nativeEvidence": {role: "4" * 64 for role in TOOL.FRESH_EVIDENCE}})
        archive = bytearray()
        for name in sorted(TOOL.directories(rows)):
            archive.extend(transport.member_header(name, 0o555, 0, True, TOOL))
        for name, (body, mode) in original.items():
            archive.extend(transport.member_header(name, mode, len(body), False, TOOL))
            archive.extend(body); archive.extend(bytes((-len(body)) % 512))
        archive.extend(bytes(1024)); archive.extend(bytes((-len(archive)) % 10240)); archive = bytes(archive)
        data = work / "python-supplier-transport"; data.mkdir(mode=0o700)
        for name, body in (("supplier.tar", archive), ("supplier-receipt.json", receipt)):
            (data / name).write_bytes(body); (data / name).chmod(0o400)
        pins = dict(module.PYTHON_SUPPLIERS[target], receiptSha256=module.digest(receipt), tarSha256=module.digest(archive))
        environment = {"GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKFLOW_REF": "Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-python-runtime-signing.yml@refs/heads/verify/desktop-macos-python-runtime-signing-" + phase[7:]}
        clock, observations, snapshots = [10_000_000_000], [], []
        state = SimpleNamespace(known=True)
        def snapshot(path, triple):
            self.assertEqual((path, triple), (checkout, target))
            snapshots.append(True)
            if failure == "source-close" or failure == "source-post-close" and len(snapshots) == 2:
                state.known = False
            body = (checkout / "desktop/tools/macos_cpython_source_probe.py").read_bytes()
            return {"desktop/tools/macos_cpython_source_probe.py": {"size": len(body), "sha256": module.digest(body)}}
        builder = SimpleNamespace(DATA=state, source_snapshot=snapshot, BOOTSTRAP=["inert_%02d" % n for n in range(61)],
                                  INTRINSIC=[], OPTIONAL=[], probe_result=parsed.probe_result)
        # Native host behavior is a DATA double, never a fake Mac qualification.
        probe = SimpleNamespace(native_host_data=lambda triple, **host: triple == target and host == {
            "sysname": "Darwin", "machine": module.build_profile(target)[0], "returned": 0,
            "observed_errno": 0, "length": 4, "translated": 0})
        signed = self.python_image(target, 0x10002 if phase == "python-engineering" else 0x10000)
        def command(argv, **options):
            role = module.PYTHON_ROLES[len(observations)]
            observations.append((role, tuple(argv), options))
            self.assertTrue(options["capture"] and not options["text"] and options["timeout"] > 0)
            self.assertEqual(set(options["environ"]), {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ"})
            self.assertFalse({"GITHUB_TOKEN", "DYLD_INSERT_LIBRARIES", "PYTHONPATH"} & set(options["environ"]))
            if failure == "owner": raise RuntimeError("inert original never returned")
            if role == "python-sign":
                path = Path(argv[-1])
                if failure == "slot-replaced":
                    path.parent.rename(path.parent.with_name("parked-original-slot"))
                    path.parent.mkdir(mode=0o700)
                body = signed if failure != "content" else signed[:48] + b"X" + signed[49:]
                if failure == "flags": body = self.python_image(target, 0x2)
                replacement = path.with_suffix(".next")
                replacement.write_bytes(body); replacement.chmod(0o755)
                os.replace(replacement, path)
                return CompletedProcess(argv, 1 if failure == "sign" else 0, b"", b"inert signing failure" if failure == "sign" else b"")
            if role == "python-verify":
                self.assertEqual(Path(argv[-1]).read_bytes(), signed)
                return CompletedProcess(argv, 1 if failure == "verify" else 0, b"", b"")
            context = json.loads(Path(argv[-1]).read_bytes())
            self.assertEqual((context["target"], context["sourceCommit"]), (target, "a" * 40))
            self.assertEqual((Path(context["payload"]) / "python/bin/python3").read_bytes(), signed)
            self.assertEqual(stat.S_IMODE(Path(context["payload"]).stat().st_mode), 0o555)
            result = {"schemaVersion": 1, "role": role[len("python-"):], "target": target,
                "result": {"nativeHost": {"sysname": "Darwin", "machine": module.build_profile(target)[0],
                    "returned": 0, "observed_errno": 0, "length": 4, "translated": 0}}}
            if failure == "late": clock[0] += 300_000_000_000
            if failure == "wrong-role": result["role"] = "not-the-original-role"
            return CompletedProcess(argv, 9 if failure == "probe" else 0, TOOL.canonical(result), b"")
        owner = SimpleNamespace(run_owned=command)
        operation = module.Operation(owner, checkout, work, phase, environment, TOOL, target=target)
        return SimpleNamespace(operation=operation, modules=(transport, matcher, builder, probe), pins=pins, original=original,
            receipt=receipt, archive=archive, work=work, checkout=checkout, environment=environment, clock=clock,
            observations=observations, signed=signed, target=target, producer=producer, service=service, empty=empty)

    @contextlib.contextmanager
    def python_fixture_call(self, fixture):
        module, operation = ANDROID_HELPER, fixture.operation
        prepare = operation.python_prepare
        original_bound, original_pins, original_clock = module.MAX_HELPER, module.PYTHON_SUPPLIERS, module.time.monotonic_ns
        self.assertEqual(original_bound, 32 * 1024 * 1024)
        try:
            with (mock.patch.object(module, "MAX_HELPER", 64 * 1024),
                  mock.patch.object(module, "PYTHON_SUPPLIERS", {fixture.target: fixture.pins}),
                  mock.patch.object(module.time, "monotonic_ns", side_effect=lambda: fixture.clock[0]),
                  mock.patch.object(operation, "python_prepare", side_effect=lambda: prepare(modules=fixture.modules))):
                yield operation
        finally:
            self.assertEqual(module.MAX_HELPER, original_bound)
            self.assertIs(module.PYTHON_SUPPLIERS, original_pins)
            self.assertIs(module.time.monotonic_ns, original_clock)

    def cargo_rows(self, checkout, target, *, build_target="aarch64-apple-darwin"):
        return normal_cargo_fixture(target, role="resident", checkout=checkout, build_target=build_target)[2] + [
            {"reason": "build-finished", "success": True}]

    def encoded(self, rows):
        return b"\n".join(json.dumps(row).encode("ascii") for row in rows) + b"\n"

    def fixture(self, root, failure=None, owner_error=None, *, build_target="aarch64-apple-darwin"):
        module = ANDROID_HELPER
        release_path = ("desktop/macos-installed-inputs/build-release.json" if build_target == "aarch64-apple-darwin"
                        else "desktop/macos-installed-inputs/build-release-intel.json")
        checkout, work = root / "checkout", root / "work"
        checkout.mkdir(mode=0o700); work.mkdir(mode=0o700)
        profile = checkout / module.PROFILE
        profile.parent.mkdir(parents=True)
        profile.write_bytes(module.UNCONFIGURED_PROFILE if failure != "profile" else module.UNCONFIGURED_PROFILE.replace(b"unconfigured", b"configured"))
        profile.chmod(0o644)
        producer = checkout / module.PRODUCER_PROFILE
        producer.write_bytes(b"schema=1\nstate=unconfigured\n"); producer.chmod(0o644)
        plist = checkout / "desktop/macos-installed-inputs" / (module.IDENTIFIER + ".plist")
        plist.parent.mkdir(parents=True)
        plist.write_bytes(TOOL.android_service_plist())
        plist.chmod(0o644)
        source = Path(__file__).absolute().parents[2]
        for name in ("desktop/native/macos-installed-entry/entry.c", "desktop/native/macos-installed-entry/gate.c",
                     "desktop/native/macos-installed-entry/gate.h", "desktop/native/macos-installed-entry/fixed_paths.h",
                     "desktop/native/macos-installed-entry/image_abi.h", "desktop/native/macos-installed-entry/desktop_facade.c",
                     "desktop/native/macos-installed-entry/resident_facade.c", release_path,
                     "desktop/native/macos-installed-native/src/native.m", "desktop/src-tauri/src/macos_install_fixed_paths.rs"):
            target = checkout / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((source / name).read_bytes()); target.chmod(0o644)
        release = json.loads((checkout / release_path).read_bytes())["release"]
        body = image_macho_fixture("resident", target=("aarch64-apple-darwin" if failure == "wrong-architecture" else build_target))
        observations = []

        def command(argv, **options):
            observations.append((tuple(argv), options))
            if argv[0] == module.direct_rust_tools(build_target)[0]:
                self.assertEqual(argv[argv.index("--target") + 1], build_target)
                target = work / "android-helper-target"
                binary = target / build_target / "release" / module.RESIDENT_IMAGE
                binary.parent.mkdir(parents=True)
                binary.write_bytes(body); binary.chmod(0o700)
                deps = binary.parent / "deps"; deps.mkdir()
                alias = deps / module.RESIDENT_IMAGE
                if failure == "alias":
                    alias.write_bytes(body); alias.chmod(0o700)
                    os.link(binary, deps / "unexpected-alias")
                else:
                    os.link(binary, alias)
                if failure == "owner":
                    if owner_error is not None:
                        raise owner_error
                    raise RuntimeError("DATA double original result unavailable")
                if failure == "image-binding-changed":
                    (checkout / release_path).write_bytes(
                        TOOL.canonical({"schemaVersion": 1, "packageVersion": TOOL.PACKAGE_VERSION,
                                        "release": "macos26-arm64-changed"}))
                output = self.encoded(self.cargo_rows(checkout, target, build_target=build_target))
                diagnostic = (b"error: synthetic helper build failed\n" if failure == "nonzero"
                              else b"warning: synthetic helper build diagnostic\n")
                return CompletedProcess(argv, 101 if failure == "nonzero" else 0,
                                        output.decode() if failure == "malformed" else output, diagnostic)
            if argv[0] == "/usr/bin/xcrun":
                self.assertEqual(argv[1:4], ["--sdk", "macosx", "clang"])
                self.assertEqual(argv[argv.index("-arch") + 1], "arm64" if build_target == "aarch64-apple-darwin" else "x86_64")
                self.assertIn("-DMRK_ENTRY_METADATA_ONLY=1", argv)
                self.assertEqual((options["timeout"], options["output_limit"]), (30, 65536))
                selected = Path(argv[-1])
                role = ("entry" if selected.name == module.ENTRY else
                        "desktop-facade" if selected.name == module.DESKTOP_FACADE else "resident-facade")
                if role != "entry":
                    self.assertIn('-DMRK_IMAGE_SOURCE_COMMIT="' + environment["GITHUB_SHA"] + '"', argv)
                    self.assertIn('-DMRK_IMAGE_RELEASE_ID="' + release + '"', argv)
                if failure == role + "-owner":
                    raise RuntimeError("DATA facade original result unavailable")
                selected.write_bytes(entry_macho_fixture(target=build_target)); selected.chmod(0o700)
                if failure == role + "-source-changed":
                    name = "entry.c" if role == "entry" else role.replace("-facade", "_facade.c")
                    (checkout / "desktop/native/macos-installed-entry" / name).write_bytes(b"changed DATA")
                return CompletedProcess(argv, 0, b"", b"")
            self.assertEqual(argv[0], "/usr/bin/codesign")
            selected = Path(argv[-1])
            if "--sign" in argv:
                resident_image = selected.name == module.RESIDENT_IMAGE
                original = (work / "android-helper-target" / build_target / "release" / module.RESIDENT_IMAGE
                            if resident_image else work / "android-helper-target" / module.HELPER)
                self.assertEqual(original.read_bytes(), body if resident_image else entry_macho_fixture(target=build_target))
                self.assertEqual(original.stat().st_nlink, 2 if resident_image else 1)
                self.assertEqual(selected.stat().st_nlink, 1)
                self.assertNotEqual(selected.stat().st_ino, original.stat().st_ino)
                self.assertEqual(argv[argv.index("--identifier") + 1], module.IDENTIFIER + (".image" if resident_image else ""))
                # Model permitted native signer inode replacement only; no
                # synthetic bytes are executable signature/native evidence.
                replacement = work / "synthetic-signer-output"
                replacement.write_bytes(selected.read_bytes() + b"DATA signature bytes")
                replacement.chmod(0o755)
                replacement.replace(selected)
            elif failure == "changed":
                selected.write_bytes(selected.read_bytes() + b"changed-after-verification")
            return CompletedProcess(argv, 0, b"", b"")

        environment = {"GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40,
                       "MRK_MACOS_INSTALL_SOURCE_COMMIT": "a" * 40, "MRK_MACOS_PACKAGE_ROLE": "ordinary-image",
                       "GITHUB_WORKFLOW_REF": "source-bound-DATA-fixture", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                       "PATH": "/inert/fixed-tools", "HOME": "/Users/runner", "DEVELOPER_DIR": "/inert/clt", "MACOSX_DEPLOYMENT_TARGET": "26.0"}
        owner = SimpleNamespace(run_owned=command)
        return checkout, work, environment, owner, observations

    def test_exact_separate_cargo_graph_rejects_impostor_outputs_and_feature_unification(self):
        module = ANDROID_HELPER
        checkout, target = Path("/inert/source"), Path("/inert/work/android-helper-target")
        rows = self.cargo_rows(checkout, target)
        self.assertEqual(module.artifact(self.encoded(rows), checkout, target), target / "aarch64-apple-darwin/release" / module.RESIDENT_IMAGE)
        for failure in ("extra-executable", "manifest", "features", "native-role", "source", "test", "finish",
                        "renamed-bin", "crate-type", "filenames", "after-finish", "missing-app", "missing-native"):
            changed = json.loads(json.dumps(rows))
            if failure == "extra-executable": changed.insert(0, changed[0].copy())
            elif failure == "manifest": changed[0]["manifest_path"] = "/unrelated/Cargo.toml"
            elif failure == "features": changed[1]["features"].append("desktop-shell")
            elif failure == "native-role": changed[2]["features"].append("installed-observation")
            elif failure == "source": changed[0]["target"]["src_path"] = "/unrelated/main.rs"
            elif failure == "test": changed[0]["profile"]["test"] = True
            elif failure == "finish": changed[-1]["success"] = False
            elif failure == "renamed-bin": changed[0]["target"]["kind"] = ["bin"]
            elif failure == "crate-type": changed[0]["target"]["crate_types"] = ["rlib"]
            elif failure == "filenames": changed[0]["filenames"] = None
            elif failure == "after-finish": changed.append(changed[0].copy())
            elif failure == "missing-app": del changed[1]
            elif failure == "missing-native": del changed[2]
            with self.subTest(failure=failure), self.assertRaises(module.Refused):
                module.artifact(self.encoded(changed), checkout, target)

        # The declared target must match the exact compiler-output location;
        # a valid opposite-architecture graph cannot choose its own selector.
        for selected, opposite in (("aarch64-apple-darwin", "x86_64-apple-darwin"),
                                   ("x86_64-apple-darwin", "aarch64-apple-darwin")):
            paired = self.cargo_rows(checkout, target, build_target=selected)
            self.assertEqual(module.artifact(self.encoded(paired), checkout, target, build_target=selected),
                             target / selected / "release" / module.RESIDENT_IMAGE)
            with self.subTest(selected=selected), self.assertRaisesRegex(module.Refused, "^helper-package-artifact$"):
                module.artifact(self.encoded(paired), checkout, target, build_target=opposite)
        class TargetSubclass(str):
            pass
        for invalid in (None, True, [], {}, "x86_64h-apple-darwin", "x86_64-apple-darwin ", TargetSubclass("x86_64-apple-darwin")):
            with self.subTest(invalid=repr(invalid)), self.assertRaisesRegex(module.Refused, "^closed-build-target$"):
                module.artifact(self.encoded(rows), checkout, target, build_target=invalid)

        # Bind the real headless workspace too: a copied UI lock plus a new
        # helper root can satisfy every synthetic compiler-artifact assertion.
        source = Path(__file__).absolute().parents[2]
        helper_manifest = tomllib.loads((source / module.WORKSPACE / "Cargo.toml").read_text(encoding="utf-8"))
        helper_lock = tomllib.loads((source / module.WORKSPACE / "Cargo.lock").read_text(encoding="utf-8"))
        app_manifest = tomllib.loads((source / "desktop/src-tauri/Cargo.toml").read_text(encoding="utf-8"))
        app_lock = tomllib.loads((source / "desktop/src-tauri/Cargo.lock").read_text(encoding="utf-8"))
        self.assertEqual(helper_manifest["workspace"], {})
        self.assertEqual(helper_manifest["dependencies"], {
            "mobile-release-kit-desktop": {"path": "../../src-tauri", "default-features": False,
                                           "features": ["macos-installed-resident-image"]},
            "mrk-macos-installed-native": {"path": "../../native/macos-installed-native", "features": ["resident-image"]}})
        self.assertIs(helper_manifest["package"]["autobins"], False)
        self.assertEqual(helper_manifest["lib"]["name"], "mrk_resident_image")
        self.assertEqual(helper_manifest["lib"]["path"], "src/lib.rs")
        self.assertEqual(helper_manifest["lib"]["crate-type"], ["cdylib"])
        self.assertEqual(helper_manifest["profile"]["release"]["panic"], "unwind")
        helper_package = helper_manifest["package"]
        app_package = app_manifest["package"]
        self.assertEqual([package for package in helper_lock["package"] if package["name"] == helper_package["name"]], [{
            "name": helper_package["name"], "version": helper_package["version"],
            "dependencies": [app_package["name"], "mrk-macos-installed-native"]}])
        app_rows = [package for package in helper_lock["package"] if package["name"] == app_package["name"]]
        self.assertEqual(len(app_rows), 1)
        self.assertEqual(app_rows[0]["version"], app_package["version"])
        self.assertNotIn("source", app_rows[0])
        shell_dependencies = {feature.removeprefix("dep:") for feature in app_manifest["features"]["desktop-shell"]
                              if feature.startswith("dep:")}
        self.assertTrue(shell_dependencies)
        self.assertTrue(shell_dependencies.isdisjoint(package["name"] for package in helper_lock["package"]))
        self.assertTrue(shell_dependencies.isdisjoint(dependency.split()[0] for dependency in app_rows[0]["dependencies"]))
        # Pruning optional GUI edges must not refresh any surviving supplier.
        pin_fields = ("name", "version", "source", "checksum")
        app_pins = {tuple(package.get(field) for field in pin_fields) for package in app_lock["package"]}
        registry_packages = [package for package in helper_lock["package"] if "source" in package]
        self.assertTrue(registry_packages)
        for package in registry_packages:
            with self.subTest(registry_package=package["name"], version=package["version"]):
                self.assertIn(tuple(package.get(field) for field in pin_fields), app_pins)

        # The explicit producer is not the resident/ordinary graph and is
        # never substituted for any packaged executable.
        for build_target in TOOL.MAC_TARGETS:
            binary = target / build_target / "release/examples/macos_package_producer"
            def artifact_row(directory, package, name, source, features, kind, executable):
                root = checkout / directory
                return {"reason": "compiler-artifact", "package_id": "path+" + root.as_uri() + "#" + package + ("@0.1.1" if package == "mobile-release-kit-desktop" else "@0.1.0"),
                    "manifest_path": str(root / "Cargo.toml"), "features": features, "executable": executable,
                    "target": {"name": name, "src_path": str(root / source), "kind": kind, "crate_types": ["bin"] if kind == ["example"] else ["lib"], "edition": "2021"},
                    "filenames": [executable] if executable else [str(target / (name + ".rlib"))], "fresh": False,
                    "profile": {"test": False, "debug_assertions": False, "opt_level": "3"}}
            producer_rows = [
                artifact_row("desktop/src-tauri", "mobile-release-kit-desktop", "macos_package_producer", "examples/macos_package_producer.rs",
                             ["macos-package-producer"], ["example"], str(binary)),
                artifact_row("desktop/src-tauri", "mobile-release-kit-desktop", "mobile_release_desktop", "src/lib.rs",
                             ["macos-package-producer"], ["lib"], None),
                artifact_row("desktop/native/macos-installed-native", "mrk-macos-installed-native", "mrk_macos_installed_native", "src/lib.rs",
                             ["default", "package-producer-signing"], ["lib"], None),
                {"reason": "build-finished", "success": True}]
            self.assertEqual(module.producer_artifact(self.encoded(producer_rows), checkout, target, build_target), binary)
            for mutation in ("wrong-target", "feature-union", "native-role", "main", "test", "finish", "missing", "duplicate", "extra-bin"):
                changed = copy.deepcopy(producer_rows)
                if mutation == "wrong-target": changed[0]["executable"] = str(target / "foreign/examples/macos_package_producer")
                elif mutation == "feature-union": changed[1]["features"].append("desktop-shell")
                elif mutation == "native-role": changed[2]["features"].append("resident-image")
                elif mutation == "main": changed[0]["target"]["src_path"] = str(checkout / "desktop/src-tauri/src/main.rs")
                elif mutation == "test": changed[0]["profile"]["test"] = True
                elif mutation == "finish": changed[-1]["success"] = False
                elif mutation == "missing": del changed[2]
                elif mutation == "duplicate": changed.insert(1, copy.deepcopy(changed[0]))
                else:
                    extra = copy.deepcopy(changed[0]); extra["target"].update(name="unexpected", kind=["bin"])
                    changed.insert(0, extra)
                with self.subTest(target=build_target, mutation=mutation), self.assertRaises(module.Refused):
                    module.producer_artifact(self.encoded(changed), checkout, target, build_target)

    def test_actual_copy_and_staged_checks_bind_final_bytes_and_retire_each_owned_target(self):
        module = ANDROID_HELPER
        for build_target in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
            with self.subTest(target=build_target), tempfile.TemporaryDirectory() as temporary:
                checkout, work, environment, owner, observations = self.fixture(Path(temporary), build_target=build_target)
                operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL, target=build_target)
                release_input = ("build-release.json" if build_target == "aarch64-apple-darwin" else "build-release-intel.json")
                release = json.loads((checkout / "desktop/macos-installed-inputs" / release_input).read_bytes())["release"]
                registered_peaks, consumed = [], []
                original_register, original_close = operation.register, operation.close

                def register(*args, **kwargs):
                    entry = original_register(*args, **kwargs)
                    registered_peaks.append(sum(item["fd"] is not None for item in operation.entries))
                    return entry

                def close(entry):
                    if entry["fd"] is not None:
                        consumed.append(id(entry))
                    original_close(entry)

                try:
                    with mock.patch.object(operation, "register", register), mock.patch.object(operation, "close", close):
                        expected = operation.execute()
                except module.Refused:
                    failure = json.loads((work / "android-helper-prepare.json").read_bytes()).get("failure", {})
                    self.fail("inert prepare failed: " + json.dumps({
                        "stage": failure.get("stage"), "type": failure.get("type"),
                        "reason": failure.get("reason"), "errno": failure.get("errno"),
                        "peakRegisteredDescriptors": max(registered_peaks, default=0)}, sort_keys=True))
                # This same complete path used to retain99 originals, exceeding the
                # local owner's unchanged nofile64 even before runtime overhead.
                self.assertLessEqual(max(registered_peaks), 42)
                directories = [entry for entry in operation.entries if entry["kind"] == "directory"]
                self.assertEqual(len(directories), 15)
                self.assertTrue(all(consumed.count(id(entry)) == 1 for entry in directories))
                self.assertEqual(expected, module.digest((work / module.HELPER).read_bytes()))
                self.assertFalse((work / "android-helper-target").exists())
                receipt = json.loads((work / "android-helper-prepare.json").read_bytes())
                self.assertTrue(receipt["passed"] and receipt["originalClosesKnown"] and receipt["targetRetired"])
                self.assertEqual(receipt["target"], build_target)
                self.assertEqual(receipt["residentImageCargoArtifact"]["target"], build_target)
                build_argv, build_options = observations[0]
                self.assertEqual([arg for arg in build_argv if arg.startswith("--message-format=")],
                                 ["--message-format=json-render-diagnostics"])
                self.assertEqual((build_options["timeout"], build_options["capture"],
                                  build_options["text"], build_options["output_limit"]),
                                 (480, True, False, 4 * 1024 * 1024))
                diagnostic = b"warning: synthetic helper build diagnostic\n"
                self.assertEqual((work / "android-helper-build.stderr").read_bytes(), diagnostic)
                self.assertEqual(receipt["originalCalls"][0]["stderrSha256"], module.digest(diagnostic))
                self.assertEqual((work / "android-helper-build.jsonl").read_bytes(),
                                 self.encoded(self.cargo_rows(checkout, work / "android-helper-target", build_target=build_target)))
                self.assertEqual(tuple(call["role"] for call in receipt["originalCalls"]), module.PREPARE_ROLES)
                self.assertEqual(len(receipt["originalCalls"]), 8)
                self.assertEqual(receipt["originalCalls"][3]["role"], "entry-build")
                self.assertIn("--lib", build_argv)
                self.assertNotIn("--bin", build_argv)
                self.assertEqual(build_options["environ"]["MRK_IMAGE_RELEASE_ID"], release)
                self.assertEqual(build_options["environ"]["MRK_MACOS_INSTALL_SOURCE_COMMIT"], environment["GITHUB_SHA"])
                self.assertEqual((receipt["imageReleaseId"], receipt["packageRole"]), (release, "ordinary-image"))
                self.assertEqual(operation.resident_image_sha256, module.digest((work / module.RESIDENT_IMAGE).read_bytes()))
                self.assertEqual(operation.desktop_facade_sha256, module.digest((work / module.DESKTOP_FACADE).read_bytes()))
                self.assertEqual((work / module.DESKTOP_FACADE).read_bytes(), entry_macho_fixture(target=build_target))
                self.assertEqual((len(receipt["desktopFacadeSources"]), len(receipt["residentFacadeSources"])), (7, 7))
                self.assertLessEqual((work / "android-helper-prepare.json").stat().st_size, 16384)
                self.assertEqual(operation.entry_sha256, module.digest((work / module.ENTRY).read_bytes()))
                self.assertEqual(len(receipt["entrySources"]), 6)
                self.assertFalse(receipt["entryExecutionObserved"] or receipt["maintenanceQualified"])
                self.assertTrue(all(entry["closed"] for entry in operation.entries))
                self.assertFalse(receipt["androidServiceAuthenticated"] or receipt["androidBuildQualified"] or receipt["productReady"])
                contents = work / "app/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app/Contents"
                helpers = contents / "Helpers"; helpers.mkdir(parents=True)
                nested = helpers / module.HELPER
                nested.write_bytes((work / module.HELPER).read_bytes()); nested.chmod(0o555)
                frameworks = contents / "Frameworks"; frameworks.mkdir()
                resident = frameworks / module.RESIDENT_IMAGE
                resident.write_bytes((work / module.RESIDENT_IMAGE).read_bytes()); resident.chmod(0o555)
                environment["MRK_MACOS_RESIDENT_IMAGE_SHA256"] = operation.resident_image_sha256
                daemons = contents / "Library/LaunchDaemons"; daemons.mkdir(parents=True)
                (daemons / (module.IDENTIFIER + ".plist")).write_bytes(TOOL.android_service_plist())
                (daemons / (module.IDENTIFIER + ".plist")).chmod(0o644)
                for phase in ("verify-before", "verify-after"):
                    actual = module.Operation(owner, checkout, work, phase, environment, TOOL, target=build_target)
                    self.assertEqual(actual.execute(expected), expected)
                    self.assertFalse((work / ("android-helper-" + phase)).exists())
                    verified = json.loads((work / ("android-helper-" + phase + ".json")).read_bytes())
                    self.assertTrue(verified["passed"])
                    self.assertEqual(verified["target"], build_target)
                    self.assertEqual([call["role"] for call in verified["originalCalls"]], [phase, phase + "-resident-image"])
                    self.assertEqual(verified["residentImageSha256"], operation.resident_image_sha256)
                self.assertEqual([item[0][0] for item in observations], [module.direct_rust_tools(build_target)[0]] + ["/usr/bin/codesign"] * 2
                                 + ["/usr/bin/xcrun"] * 3 + ["/usr/bin/codesign"] * 6)
        # A plausible Cargo graph is insufficient: its actual copied image
        # must pass the same selected Intel Mach-O check before publication.
        with tempfile.TemporaryDirectory() as temporary:
            checkout, work, environment, owner, observations = self.fixture(
                Path(temporary), "wrong-architecture", build_target="x86_64-apple-darwin")
            operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL, target="x86_64-apple-darwin")
            with self.assertRaisesRegex(module.Refused, "^helper-package-incomplete$"):
                operation.execute()
            receipt = json.loads((work / "android-helper-prepare.json").read_bytes())
            self.assertFalse(receipt["passed"])
            self.assertEqual(receipt["failure"]["stage"], "compiler-original-copy")
            self.assertTrue(receipt["originalClosesKnown"] and receipt["targetRetired"])
            self.assertEqual(len(observations), 1)
            self.assertFalse((work / module.RESIDENT_IMAGE).exists())

        # Same actual filesystem copy/POST/retirement path, with only original
        # native return values doubled. No signature/kernel behavior is claimed.
        for target in (module.ARM_TARGET, module.INTEL_TARGET):
            for phase in module.PYTHON_PHASES:
                with self.subTest(pythonTarget=target, purpose=phase), tempfile.TemporaryDirectory() as directory:
                    fixture = self.python_fixture(Path(directory), target=target, phase=phase)
                    with self.python_fixture_call(fixture) as operation:
                        self.assertEqual(operation.execute(), module.digest(fixture.signed))
                    self.assertEqual([row[0] for row in fixture.observations], list(module.PYTHON_ROLES))
                    self.assertTrue(operation.receipt["passed"] and operation.receipt["targetRetired"])
                    self.assertTrue(operation.receipt["originalClosesKnown"] and all(row["closed"] for row in operation.entries))
                    self.assertFalse((fixture.work / operation.target_name).exists())
                    self.assertEqual((fixture.work / "python-supplier-transport/supplier.tar").read_bytes(), fixture.archive)
                    self.assertEqual((fixture.work / "python-supplier-transport/supplier-receipt.json").read_bytes(), fixture.receipt)
                    sign = fixture.observations[0][1]
                    self.assertEqual(sign[sign.index("--sign") + 1], "-" if phase == "python-engineering" else "1" * 40)
                    self.assertEqual(sign[sign.index("--options") + 1], "runtime")
                    self.assertIn("--timestamp=none" if phase == "python-engineering" else "--timestamp", sign)
                    self.assertEqual([row[2]["timeout"] for row in fixture.observations], [30, 30, 60, 60, 60, 60])
                    self.assertFalse(operation.receipt["productReady"] or operation.receipt["developerIdOrNotarizationQualified"])
                    if phase == "python-engineering":
                        self.assertFalse((fixture.work / "python3").exists() or (fixture.work / "python-signed-receipt.json").exists())
                    else:
                        signed = (fixture.work / "python3").read_bytes()
                        receipt = (fixture.work / "python-signed-receipt.json").read_bytes()
                        self.assertEqual(signed, fixture.signed)
                        self.assertEqual(stat.S_IMODE((fixture.work / "python3").stat().st_mode), 0o555)
                        value = TOOL.decode(receipt)
                        self.assertEqual(value["originalSupplier"], fixture.pins)
                        self.assertEqual(set(value["nativeEvidence"]), set(module.PYTHON_ROLES))
                        options = SimpleNamespace(target=target, expected_supplier=module.digest(fixture.receipt),
                            expected_signed_python=module.digest(signed), expected_signing_receipt=module.digest(receipt),
                            expected_signing_source="a" * 40, expected_signing_run="123", expected_signing_attempt="1")
                        original_nomination = TOOL.SIGNED_ORIGINAL_SUPPLIERS
                        with mock.patch.object(TOOL, "SIGNED_ORIGINAL_SUPPLIERS", {target: fixture.pins}):
                            self.assertEqual(TOOL.signed_python_receipt(receipt, signed, options, fixture.original, fixture.receipt,
                                fixture.producer, fixture.service, fixture.empty), value)
                        self.assertIs(TOOL.SIGNED_ORIGINAL_SUPPLIERS, original_nomination)
                    # No later native command may use a retired/reopened target.
                    with self.assertRaisesRegex(module.Refused, "python-originals-unknown"):
                        operation.python_call("python-modules", ["never", "executed"])



    def test_directory_reuse_keeps_distinct_file_originals_and_rejects_replaced_ancestry(self):
        module = ANDROID_HELPER
        for replacement in (None, "child", "parent", "root"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                checkout, work, environment, owner, observations = self.fixture(Path(temporary))
                operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL)
                try:
                    operation.open()
                    first = operation.source_original(module.PROFILE, "first-profile", 1024)
                    count = len(operation.entries)
                    second = operation.source_original(module.PROFILE, "second-profile", 1024)
                    self.assertEqual(len(operation.entries), count + 1)
                    self.assertIsNot(first, second)
                    self.assertNotEqual(first["fd"], second["fd"])
                    parent = first["parent_entry"]
                    self.assertIs(parent, second["parent_entry"])
                    self.assertEqual(operation.read(first), operation.read(second))
                    if replacement:
                        selected = {"child": checkout / "desktop/packaging",
                                    "parent": checkout / "desktop", "root": checkout}[replacement]
                        selected.rename(selected.with_name(selected.name + "-original"))
                        selected.mkdir(mode=0o700)
                    with mock.patch.object(module.os, "open", side_effect=AssertionError("must reuse, not reopen")):
                        if replacement:
                            with self.assertRaisesRegex(module.Refused, "directory-original-changed"):
                                operation.descend(operation.source_entry, ("desktop", "packaging"))
                            with self.assertRaisesRegex(module.Refused, "directory-original-changed"):
                                operation.read(first)
                        else:
                            self.assertIs(operation.descend(operation.source_entry, ("desktop", "packaging")), parent)
                finally:
                    operation.finish()
                self.assertTrue(operation.receipt["originalClosesKnown"])
                self.assertTrue(operation.receipt["targetRetired"])
                self.assertFalse(observations)  # No child, compiler or native call.

    def test_directory_reuse_never_reopens_consumed_or_unknown_originals(self):
        module = ANDROID_HELPER
        for unknown in (False, True):
            with self.subTest(unknown=unknown), tempfile.TemporaryDirectory() as temporary:
                checkout, work, environment, owner, observations = self.fixture(Path(temporary))
                operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL)
                try:
                    operation.open()
                    original = operation.source_original(module.PROFILE, "profile", 1024)
                    cached = original["parent_entry"]
                    real_close, attempts = os.close, []

                    def close(fd):
                        attempts.append(fd)
                        real_close(fd)  # Actually discharge this DATA fixture original.
                        if unknown:
                            raise OSError("synthetic close result unavailable")

                    with mock.patch.object(module.os, "close", close):
                        operation.close(cached)
                    self.assertEqual(cached["closed"], not unknown)
                    self.assertIsNone(cached["fd"])
                    with mock.patch.object(module.os, "open", side_effect=AssertionError("must not reopen")), \
                         mock.patch.object(module.os, "close", side_effect=AssertionError("must not retry close")):
                        with self.assertRaisesRegex(module.Refused, "directory-original-unavailable"):
                            operation.descend(operation.source_entry, ("desktop", "packaging"))
                        operation.close(cached)
                    self.assertEqual(len(attempts), 1)
                finally:
                    operation.finish()
                self.assertEqual(operation.receipt["originalClosesKnown"], not unknown)
                self.assertEqual(operation.receipt["targetRetired"], not unknown)
                self.assertFalse(observations)

        with tempfile.TemporaryDirectory() as temporary:
            checkout, work, environment, owner, observations = self.fixture(Path(temporary))
            operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL)
            with mock.patch.object(operation, "prepare", side_effect=OSError(24, "PRIVATE error path")), \
                 self.assertRaises(module.Refused):
                operation.execute()
            receipt = json.loads((work / "android-helper-prepare.json").read_bytes())
            self.assertEqual(receipt["failure"]["errno"], 24)
            self.assertNotIn("PRIVATE", json.dumps(receipt))
            self.assertFalse(receipt["passed"])
            self.assertTrue(receipt["targetRetired"] and receipt["originalClosesKnown"])

    def test_alias_original_return_close_and_signature_failures_never_produce_success(self):
        module = ANDROID_HELPER
        for failure in ("alias", "owner", "malformed", "close", "changed", "nonzero", "entry-owner", "entry-source-changed",
                        "image-close", "image-binding-changed", "desktop-facade-owner", "desktop-facade-source-changed",
                        "resident-facade-owner", "resident-facade-source-changed"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                checkout, work, environment, owner, observations = self.fixture(Path(temporary), failure)
                operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL)
                original_close, injected = os.close, []

                def close(fd):
                    selected_role = "signed-resident-image" if failure == "image-close" else "signed-helper"
                    if failure in ("close", "image-close") and not injected and any(entry["role"] == selected_role and entry["fd"] is None
                            and not entry["closed"] for entry in operation.entries):
                        # Actually discharge the DATA fixture FD, then inject
                        # uncertainty. The production code must not retry it.
                        original_close(fd); injected.append(fd)
                        raise OSError("synthetic close result unavailable")
                    original_close(fd)

                with mock.patch.object(module.os, "close", close), self.assertRaises(module.Refused):
                    operation.execute()
                receipt = json.loads((work / "android-helper-prepare.json").read_bytes())
                self.assertFalse(receipt["passed"])
                uncertain = failure in ("owner", "malformed", "close", "image-close", "entry-owner",
                                        "desktop-facade-owner", "resident-facade-owner")
                self.assertEqual((work / "android-helper-target").exists(), uncertain)
                if failure in ("alias", "owner", "malformed", "nonzero"):
                    self.assertEqual(len(observations), 1)
                if failure.startswith("entry-"):
                    self.assertEqual(len(observations), 4)
                    self.assertFalse((work / module.ENTRY).exists())
                    self.assertEqual(receipt["originalCalls"][-1]["returned"], failure != "entry-owner")
                    self.assertEqual(receipt["failure"]["stage"], "fixed-installed-entry-compiler")
                if failure == "nonzero":
                    call = receipt["originalCalls"][0]
                    self.assertEqual((call["returned"], call["returncode"]), (True, 101))
                    self.assertEqual(receipt["failure"], {"stage": "separate-resident-image-compiler",
                                     "type": "Refused", "reason": "original-nonzero-build"})
                    self.assertTrue(receipt["targetRetired"] and receipt["originalClosesKnown"])
                    self.assertFalse((work / module.HELPER).exists())
                    self.assertIsNone(operation.sha256)
                    self.assertNotIn("helperSha256", receipt)
                    self.assertEqual((work / "android-helper-build.stderr").read_bytes(),
                                     b"error: synthetic helper build failed\n")
                    self.assertEqual((work / "android-helper-build.status").read_bytes(), b"101\n")
                if failure.startswith(("desktop-facade-", "resident-facade-")):
                    role = "desktop" if failure.startswith("desktop-") else "resident"
                    self.assertEqual(len(observations), 5 if role == "desktop" else 6)
                    self.assertEqual(receipt["originalCalls"][-1]["returned"], not failure.endswith("-owner"))
                    self.assertEqual(receipt["failure"]["stage"], role + "-facade-compiler")
                if failure == "image-binding-changed":
                    self.assertEqual(len(observations), 8)
                    self.assertEqual(receipt["failure"]["reason"], "file-original-changed")
                if failure in ("close", "image-close"):
                    self.assertEqual(len(injected), 1)
                    self.assertFalse(receipt["originalClosesKnown"])

        class ProcessErrorData(RuntimeError):
            dispatched, contained, cleanup_complete = True, False, False

            @property
            def args(self):
                raise AssertionError("do not invoke an exception property")

            def __str__(self):
                raise AssertionError("do not render an exception")

        class SubclassData(ProcessErrorData):
            pass

        known = (
            ("owned command output exceeds its bound", "output-bound"),
            ("owned command exceeded its original deadline", "deadline"),
            ("owned command protocol or original ownership is incomplete", "protocol-or-original-ownership"),
            ("owned command original parent ended", "original-parent-ended"),
            ("owned command cleanup could not be confirmed", "cleanup-unconfirmed"),
            ("owned command failed, timed out, or produced incomplete output", "failed-timeout-or-incomplete-output"),
            ("owned command executable could not be started", "exec-rejected"),
            ("owned command was stopped before execution", "stopped-before-execution"),
            ("owned command produced incomplete output", "incomplete-output"),
        )
        cases = [(ProcessErrorData(message), expected) for message, expected in known] + [
            (RuntimeError(known[0][0]), "unclassified"),
            (SubclassData(known[0][0]), "unclassified"),
            (ProcessErrorData(known[0][0] + " PRIVATE"), "unclassified"),
            (ProcessErrorData("PRIVATE" * 4096), "unclassified"),
            (ProcessErrorData(known[0][0], "PRIVATE"), "unclassified"),
            (ProcessErrorData({"PRIVATE": "not string data"}), "unclassified"),
        ]
        for error, expected in cases:
            with tempfile.TemporaryDirectory() as temporary:
                checkout, work, environment, owner, observations = self.fixture(Path(temporary), "owner", error)
                owner.ProcessError = ProcessErrorData
                operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL)
                with self.assertRaises(module.Refused):
                    operation.execute()
                receipt = json.loads((work / "android-helper-prepare.json").read_bytes())
                call = receipt["originalCalls"][0]
                diagnostic = call["originalFailure"]
                self.assertEqual(diagnostic["classification"], expected)
                self.assertEqual(diagnostic["ownerErrorType"], "ProcessError" if type(error) is ProcessErrorData else "other")
                self.assertEqual((diagnostic["timeoutSeconds"], diagnostic["outputLimitBytes"], diagnostic["captureMode"]),
                                 (480, 4 * 1024 * 1024, "bytes"))
                encoded = json.dumps(diagnostic, sort_keys=True, separators=(",", ":")).encode("ascii")
                self.assertLessEqual(len(encoded), 2048)
                self.assertNotIn(b"PRIVATE", encoded)
                self.assertNotIn(b"owned command ", encoded)
                self.assertEqual((receipt["passed"], receipt["targetRetired"], call["returned"]), (False, False, False))
                self.assertNotIn("returncode", call)
                self.assertTrue((work / "android-helper-target").is_dir())
                self.assertFalse((work / "android-helper-build.jsonl").exists())
                self.assertFalse((work / "android-helper-build.stderr").exists())
                self.assertFalse((work / "android-helper-build.status").exists())
                self.assertEqual(len(observations), 1)
                if type(error) is ProcessErrorData:
                    self.assertEqual((call["dispatched"], call["contained"], call["cleanup_complete"]), (True, False, False))

        # Synthetic Python frames only: no owner import, process or native run.
        checkout = Path("/DATA-only/checkout")
        owner = SimpleNamespace(ProcessError=ProcessErrorData)

        def template(depth, recurse, error):
            if depth:
                return recurse(depth - 1, recurse, error)
            raise error

        def trace_data(filename, depth=0, function="data_frame", line=1):
            code = template.__code__.replace(co_filename=filename, co_name=function, co_firstlineno=line)
            traced = FunctionType(code, {})
            try:
                traced(depth, traced, ProcessErrorData(known[0][0]))
            except ProcessErrorData as error:
                return module.original_failure(error, owner, checkout, 480, 4 * 1024 * 1024)
            self.fail("synthetic traceback was not raised")

        for name in ("owned_process.py", "_command_process.py", "_native_process.py", "cancellation.py"):
            diagnostic = trace_data(str(checkout / "src/mobile_release" / name))
            self.assertEqual(diagnostic["frames"], [{"source": "src/mobile_release/" + name,
                                                    "function": "data_frame", "line": 4}])
        exact = str(checkout / "src/mobile_release/_command_process.py")
        for foreign in ("/unrelated/_command_process.py", str(checkout / "src/mobile_release/../mobile_release/_command_process.py")):
            diagnostic = trace_data(foreign)
            self.assertEqual(diagnostic["frames"], [])
            self.assertEqual(diagnostic["foreignFrames"], diagnostic["visitedFrames"])
        diagnostic = trace_data(exact, 12, "x" * 64)
        self.assertEqual(len(diagnostic["frames"]), 8)
        self.assertFalse(diagnostic["tracebackTruncated"])
        self.assertEqual(diagnostic["omittedFrames"], diagnostic["visitedFrames"] - 8)
        self.assertLessEqual(len(json.dumps(diagnostic, sort_keys=True, separators=(",", ":")).encode("ascii")), 2048)
        diagnostic = trace_data(exact, 40)
        self.assertEqual((diagnostic["visitedFrames"], len(diagnostic["frames"]), diagnostic["tracebackTruncated"]), (32, 8, True))
        for function, line in (("PRIVATE\nframe", 1), ("x" * 65, 1), ("data_frame", 1000001)):
            self.assertEqual(trace_data(exact, function=function, line=line)["frames"], [])

        # Even diagnostic inspection failure must re-raise the identical owner
        # exception and leave the uncertain target; this is still a DATA double.
        with tempfile.TemporaryDirectory() as temporary:
            error = ProcessErrorData(known[0][0])
            checkout, work, environment, owner, observations = self.fixture(Path(temporary), "owner", error)
            owner.ProcessError = ProcessErrorData
            operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL)
            try:
                operation.open()
                with mock.patch.object(module, "original_failure", side_effect=KeyboardInterrupt("DATA diagnostic failed")):
                    with self.assertRaises(ProcessErrorData) as caught:
                        operation.call("build", [module.direct_rust_tools(operation.target)[0], "build", "--target", operation.target], module.build_environment(environment, work, TOOL.RELEASE, target=operation.target),
                                       cwd=checkout, timeout=480, limit=4 * 1024 * 1024)
                self.assertIs(caught.exception, error)
                self.assertEqual(operation.calls[0]["originalFailure"], {"schemaVersion": 1, "available": False})
                self.assertFalse(operation.calls[0]["returned"])
            finally:
                operation.finish()
            self.assertTrue((work / "android-helper-target").is_dir())
            self.assertFalse(operation.receipt["targetRetired"])
            self.assertTrue(operation.receipt["originalClosesKnown"])
            self.assertEqual(len(observations), 1)

        # Same original call implementation; no privileged process, mount or
        # signing API is executed. Actual temporary files retain close semantics.
        for mode in ("zero", "nonzero", "unknown", "status-close", "stdout-close", "stderr-close"):
            with self.subTest(package=mode), tempfile.TemporaryDirectory() as temporary:
                checkout, work, environment, _owner, _observed = self.fixture(Path(temporary))
                argv = ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer", "-pkg", "/inert/package-mount/request.pkg", "-target", "/"]
                known = CompletedProcess(argv, 7 if mode == "nonzero" else 0, b"original stdout", b"original stderr")
                owner = SimpleNamespace(run_owned=mock.Mock(side_effect=RuntimeError("original outcome unknown") if mode == "unknown" else None,
                                                          return_value=known))
                operation = module.Operation(owner, checkout, work, "package-install", environment, TOOL)
                events = []
                original_publish, original_close, original_os_close = operation.publish, operation.close, module.os.close
                def publish(name, body, **options):
                    events.append(name)
                    original_publish(name, body, **options)
                    if mode == "status-close" and name == "installer-output.status":
                        raise OSError("DATA status settlement unknown")
                def consumed_unknown(fd):
                    original_os_close(fd)  # Actually close the test FD once; report uncertainty, never retry.
                    raise OSError("DATA consuming output close unknown")
                def close(entry):
                    suffix = "stdout" if mode == "stdout-close" else "stderr"
                    if mode in ("stdout-close", "stderr-close") and entry["role"] == "output-android-helper-installer." + suffix:
                        with mock.patch.object(module.os, "close", consumed_unknown):
                            original_close(entry)
                    else:
                        original_close(entry)
                try:
                    operation.open()
                    with mock.patch.object(operation, "publish", publish), mock.patch.object(operation, "close", close):
                        if mode == "zero":
                            self.assertIs(operation.call("installer", argv, {}, cwd=work, timeout=123, limit=4096), known)
                        else:
                            with self.assertRaises((module.Refused, RuntimeError, OSError)):
                                operation.call("installer", argv, {}, cwd=work, timeout=123, limit=4096)
                    self.assertTrue(operation.installer_entered)  # Actual same-owner invocation, including unknown return.
                    if mode != "unknown":
                        self.assertEqual(events[0], "installer-output.status")
                        self.assertEqual((work / "installer-output.status").read_bytes(), (str(known.returncode) + "\n").encode())
                    else:
                        self.assertEqual(events, [])
                        self.assertFalse((work / "installer-output.status").exists())
                    self.assertEqual(operation.calls[0]["returned"], mode in ("zero", "nonzero", "stdout-close", "stderr-close"))
                    self.assertEqual(operation.calls[0]["capturesSettled"], mode in ("zero", "nonzero"))
                    self.assertEqual(operation.package_settled(), mode in ("zero", "nonzero"))
                    if mode in ("zero", "nonzero"):
                        self.assertEqual((work / "installer-output.txt").read_bytes(), known.stdout + known.stderr)
                        self.assertLess(events.index("installer-output.status"), events.index("android-helper-installer.stdout"))
                    else:
                        # Even a truthful original return cannot dispatch another
                        # diagnostic across late output-close or original uncertainty.
                        with self.assertRaisesRegex(module.Refused, "^package-io-finality-unknown$"):
                            operation.package_diagnostic(SimpleNamespace(), capture=True)
                    if mode in ("stdout-close", "stderr-close"):
                        self.assertEqual(operation.errors[-1]["stage"], "close")
                        self.assertIn("output-android-helper-installer.", operation.errors[-1]["role"])
                    self.assertEqual(owner.run_owned.call_count, 1)
                finally:
                    operation.finish()
                self.assertEqual(operation.receipt["originalClosesKnown"], mode not in ("stdout-close", "stderr-close"))
                self.assertEqual(operation.receipt["targetRetired"], mode in ("zero", "nonzero"))
                self.assertFalse(operation.receipt["passed"])

        # Deadline DATA includes the existing owner's3s cleanup, not a new
        # budget on every call. A late observation or backward clock refuses.
        endpoint = 990_000_000_000
        self.assertEqual(module.package_timeout_data(0, endpoint, 480), 480)
        self.assertEqual(module.package_timeout_data(980_000_000_000, endpoint, 480), 7)
        self.assertEqual(module.package_timeout_data(986_000_000_000, endpoint, 30), 1)
        for now, end, requested in ((987_000_000_000, endpoint, 30), (endpoint, endpoint, 30),
                                     (-1, endpoint, 30), (False, endpoint, 30), (0, endpoint, 481)):
            with self.subTest(now=now, requested=requested), self.assertRaises(module.Refused):
                module.package_timeout_data(now, end, requested)
        environment = {"GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40,
            "GITHUB_WORKFLOW_REF": "DATA", "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}
        operation = module.Operation(SimpleNamespace(), Path("/DATA"), Path("/DATA/work"), "package-install", environment, TOOL)
        operation.package_started = 0; operation.package_observed = 100; operation.package_endpoint = endpoint
        with mock.patch.object(module.time, "monotonic_ns", return_value=99), self.assertRaises(module.Refused):
            operation.package_clock()
        self.assertEqual(operation.package_observed, 100)
        with mock.patch.object(module.time, "monotonic_ns", return_value=100):
            self.assertEqual(operation.package_clock(), 100)
        with mock.patch.object(module.time, "monotonic_ns", return_value=endpoint), self.assertRaises(module.Refused):
            operation.package_clock()

        # Inert mount DATA verifies refusal BEFORE close/detach on unknown
        # originals, failed Installer or missing readback. No mount is created.
        for unknown, entered, zero, readback in ((True, False, False, False), (False, True, False, False),
                                                (False, True, True, False)):
            operation.mount_known = not unknown
            operation.installer_entered, operation.installer_zero, operation.installation_readback = entered, zero, readback
            with (mock.patch.object(operation, "close") as close,
                  mock.patch.object(operation, "recheck_mount") as recheck,
                  mock.patch.object(operation, "package_call") as child,
                  self.assertRaises(module.Refused)):
                operation.detach_package_mount()
            close.assert_not_called(); recheck.assert_not_called(); child.assert_not_called()
        operation.mount_known = True; operation.installer_entered = False
        operation.entries = [{"kind": "mounted-file", "role": "mounted-input", "closed": False},
                             {"kind": "mount", "role": "mount-original", "closed": False}]
        with (mock.patch.object(operation, "recheck_mount"), mock.patch.object(operation, "close") as close,
              mock.patch.object(operation, "package_call") as child, self.assertRaises(module.Refused)):
            operation.detach_package_mount()
        self.assertEqual(close.call_count, 1); child.assert_not_called()
        self.assertFalse(operation.mount_detached)

        # The positive branch uses the same method with inert original-device
        # and filesystem doubles: known closes precede the sole detach call,
        # then the held placeholder is rebound before its empty removal.
        operation.entries = [{"kind": "mounted-file", "role": "mounted-input", "closed": False},
                             {"kind": "mount", "role": "mount-original", "closed": False}]
        operation.calls = [{"returned": True, "capturesSettled": True}]
        operation.errors = []
        operation.mount_device = "/dev/disk99s1"
        operation.mount_placeholder = {"fd": 9}
        operation.work_entry = {"fd": 8}
        events = []
        def closed(entry):
            events.append("close-" + entry["kind"])
            entry["closed"] = True
        def returned(role, argv, **options):
            events.append(role)
            self.assertEqual(argv, ["/usr/bin/hdiutil", "detach", "/dev/disk99s1"])
            self.assertEqual(options, {"timeout": 30})
        with (mock.patch.object(operation, "recheck_mount", side_effect=lambda: events.append("mount-post")),
              mock.patch.object(operation, "close", side_effect=closed),
              mock.patch.object(operation, "package_call", side_effect=returned),
              mock.patch.object(operation, "recheck_directory", side_effect=lambda entry: events.append("placeholder-post")),
              mock.patch.object(module.os, "listdir", return_value=[]),
              mock.patch.object(module.os, "rmdir", side_effect=lambda *args, **kw: events.append("remove-empty-placeholder")),
              mock.patch.object(operation, "package_clock", return_value=100)):
            operation.detach_package_mount()
        self.assertEqual(events, ["mount-post", "close-mounted-file", "close-mount", "distribution-detach",
                                  "placeholder-post", "remove-empty-placeholder"])
        self.assertTrue(operation.mount_detached)

        # Only these three SOURCE-fixed stager I/O calls share this boundary.
        # A primary refusal may mask its local close error; an exception never
        # clears the caller's completion latch or permits another operation.
        io_roles = (("final-audit", "audit_command"), ("result-absence", "installer_result_absent_command"),
                    ("v2-readback", "observation_command"))
        for role, function in io_roles:
            with self.subTest(stager=role), tempfile.TemporaryDirectory() as temporary:
                checkout, work, environment, owner, _ = self.fixture(Path(temporary))
                operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL)
                operation.package_started = operation.package_observed = 0
                operation.package_endpoint = endpoint
                primary = TOOL.Refused("installer-export-name-occupied")
                def direct():
                    try:
                        operation.package_stager_io(role, SimpleNamespace())
                    except BaseException as error:
                        self.assertIs(error, primary)
                        raise
                with (mock.patch.object(operation, "prepare", side_effect=direct),
                      mock.patch.object(TOOL, function, side_effect=primary) as called,
                      mock.patch.object(module.time, "monotonic_ns", return_value=100)):
                    with self.assertRaisesRegex(module.Refused, "^helper-package-incomplete$"):
                        operation.execute()
                self.assertEqual(called.call_count, 1)
                self.assertEqual(operation.stager_io_pending, role)
                self.assertFalse(operation.package_settled())
                self.assertFalse(operation.receipt["targetRetired"] or operation.receipt["originalClosesKnown"])
                self.assertTrue((work / operation.target_name).is_dir())
                self.assertTrue(all(entry["closed"] for entry in operation.entries))
                self.assertEqual(operation.receipt["failure"]["type"], "Refused")
                self.assertEqual(operation.receipt["directStagerIOPending"], role)
                self.assertIn({"stage": "package-stager-io", "operation": role, "type": "CompletionUnknown"},
                              operation.receipt["cleanupErrors"])
                operation.mount_known = True  # No real mount; guard must precede every callback/close.
                with (mock.patch.object(operation, "close") as close,
                      mock.patch.object(operation, "recheck_mount") as recheck,
                      mock.patch.object(operation, "package_call") as child,
                      self.assertRaisesRegex(module.Refused, "^package-mount-finality-unknown$")):
                    operation.detach_package_mount()
                close.assert_not_called(); recheck.assert_not_called(); child.assert_not_called()
                with self.assertRaisesRegex(module.Refused, "^package-io-finality-unknown$"):
                    operation.package_stager_io(role, SimpleNamespace())
                with self.assertRaisesRegex(module.Refused, "^package-io-finality-unknown$"):
                    operation.package_diagnostic(SimpleNamespace(), capture=True)

            clean = module.Operation(SimpleNamespace(), Path("/DATA"), Path("/DATA/work"), "package-install", environment, TOOL)
            clean.package_started = clean.package_observed = 0; clean.package_endpoint = endpoint
            expected, argument = {"DATA": "completed"}, SimpleNamespace()
            with (mock.patch.object(TOOL, function, return_value=expected) as called,
                  mock.patch.object(module.time, "monotonic_ns", return_value=100)):
                self.assertIs(clean.package_stager_io(role, argument), expected)
            called.assert_called_once_with(argument)
            self.assertIsNone(clean.stager_io_pending)
            self.assertTrue(clean.package_settled())

        # Clock/reserve refusal before SAME-owner call dispatch is not entry.
        for role in ("distribution-attach", "installer"):
            owner = SimpleNamespace(run_owned=mock.Mock())
            operation = module.Operation(owner, Path("/DATA"), Path("/DATA/work"), "package-install", environment, TOOL)
            operation.package_started = operation.package_observed = 0; operation.package_endpoint = endpoint
            with mock.patch.object(module.time, "monotonic_ns", return_value=endpoint), self.assertRaises(module.Refused):
                operation.package_call(role, ["/inert"], environment={})
            self.assertEqual(operation.calls, [])
            self.assertFalse(operation.mount_entered or operation.installer_entered)
            owner.run_owned.assert_not_called()

        for cause in ("owner", "sign", "slot-replaced", "content", "flags", "verify", "probe", "wrong-role",
                      "late", "source-close", "source-post-close", "slot-close", "retirement-mode", "publication-close"):
            with self.subTest(pythonFailure=cause), tempfile.TemporaryDirectory() as directory:
                fixture = self.python_fixture(Path(directory), phase="python-shipping", failure=cause)
                operation, original_close, original_chmod = fixture.operation, module.os.close, module.os.fchmod
                injected = []
                def close(fd):
                    match = next((entry for entry in operation.entries if entry["fd"] is None and not entry["closed"]
                                  and entry["role"] == ("python-file-signing-slot/python3" if cause == "slot-close"
                                                        else "python-publication-python3")), None)
                    if cause in ("slot-close", "publication-close") and match is not None and not injected:
                        original_close(fd); injected.append(fd)
                        raise OSError("inert close result unknown")
                    original_close(fd)
                def chmod(fd, mode):
                    if cause == "retirement-mode" and operation.python_retiring and not injected:
                        injected.append(fd)
                        raise OSError("inert mode restore failed")
                    return original_chmod(fd, mode)
                with self.python_fixture_call(fixture), mock.patch.object(module.os, "close", close), mock.patch.object(module.os, "fchmod", chmod):
                    with self.assertRaises((module.Refused, OSError)):
                        operation.execute()
                self.assertFalse(operation.receipt["passed"])
                self.assertFalse((fixture.work / "python-signed-receipt.json").exists())
                self.assertTrue(all(row["fd"] is None for row in operation.entries))
                self.assertTrue(all(row.get("returncode") == 0 for row in operation.calls[:-1]))
                if cause in ("owner", "sign", "slot-replaced", "content", "flags", "slot-close"):
                    self.assertEqual(len(operation.calls), 1)
                if cause == "source-close":
                    self.assertEqual(operation.calls, [])
                if cause in ("probe", "wrong-role", "late"):
                    self.assertEqual(len(operation.calls), 3)
                    self.assertTrue(operation.calls[-1]["returned"] and operation.calls[-1]["capturesSettled"])
                    self.assertTrue(operation.receipt["targetRetired"])
                retained = cause in ("owner", "sign", "slot-replaced", "content", "flags", "source-close", "source-post-close",
                                     "slot-close", "retirement-mode")
                self.assertEqual((fixture.work / operation.target_name).exists(), retained)
                self.assertEqual((fixture.work / "python-supplier-transport/supplier.tar").read_bytes(), fixture.archive)
                if cause == "publication-close":
                    self.assertTrue((fixture.work / "python3").exists())  # Inadmissible partial output, not a capsule.
                    self.assertFalse(operation.receipt["originalClosesKnown"])
                if cause in ("slot-close", "retirement-mode", "publication-close"):
                    self.assertEqual(len(injected), 1)
                    self.assertTrue(operation.errors)
        # An existing primary refusal survives more than one uncertain close;
        # consumed descriptor integers are never retried or adopted.
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.python_fixture(Path(directory), failure="content")
            operation, original_close, faults = fixture.operation, module.os.close, []
            def close(fd):
                entry = next((row for row in operation.entries if row["fd"] is None and not row["closed"]
                    and row["role"] in ("python-file-signing-slot/python3", "python-signed-original")
                    and row["role"] not in faults), None)
                original_close(fd)
                if entry is not None and entry["role"] not in faults:
                    faults.append(entry["role"])
                    raise OSError("inert second error")
            with self.python_fixture_call(fixture), mock.patch.object(module.os, "close", close), self.assertRaises(module.Refused):
                operation.execute()
            self.assertEqual(operation.receipt["failure"]["reason"], "macho-nonsignature-content-changed")
            self.assertEqual(len(faults), 2)
            self.assertEqual(len([row for row in operation.errors if row["stage"] == "close"]), 2)
            self.assertFalse(operation.receipt["targetRetired"] or operation.receipt["passed"])


    def test_clean_environment_and_configured_profile_refuse_any_ad_hoc_fallback(self):
        module = ANDROID_HELPER
        with tempfile.TemporaryDirectory() as temporary:
            checkout, work, environment, owner, observations = self.fixture(Path(temporary), "profile")
            environment.update(RUSTC_WRAPPER="unrelated", CARGO_ENCODED_RUSTFLAGS="unrelated", GITHUB_TOKEN="inert-DATA",
                               MRK_ANDROID_TOOL_INSTANCE="unrelated", MRK_IMAGE_RELEASE_ID="untrusted-release")
            selected = module.build_environment(environment, work, TOOL.RELEASE)
            self.assertEqual(selected["MRK_IMAGE_RELEASE_ID"], TOOL.RELEASE)
            for release in ("", "x" * 64, 'bad"macro', "nonascii-é"):
                with self.subTest(release=release), self.assertRaises(module.Refused):
                    module.build_environment(environment, work, release)
            self.assertEqual(selected["RUSTUP_TOOLCHAIN"], "1.98.1")
            self.assertEqual(selected["RUSTUP_AUTO_INSTALL"], "0")
            for target in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
                directory = "/Users/runner/.rustup/toolchains/stable-" + target + "/bin"
                cleaned = module.build_environment(environment, work, TOOL.RELEASE, target=target)
                self.assertEqual(module.direct_rust_tools(target), (directory + "/cargo", directory + "/rustc"))
                self.assertEqual(cleaned["RUSTC"], directory + "/rustc")
                self.assertEqual(cleaned["PATH"], directory + ":/usr/bin:/bin:/usr/sbin:/sbin")
                self.assertEqual((cleaned["HOME"], cleaned["CARGO_HOME"], cleaned["RUSTUP_HOME"]),
                                 ("/Users/runner", "/Users/runner/.cargo", "/Users/runner/.rustup"))
            for invalid in (None, True, "aarch64-apple-darwin ", "x86_64h-apple-darwin", "../../bin"):
                with self.subTest(target=invalid), self.assertRaises(module.Refused):
                    module.build_environment(environment, work, TOOL.RELEASE, target=invalid)
            for key, value in (("HOME", "/other"), ("CARGO_HOME", "/other"), ("RUSTUP_HOME", "/other"),
                               ("RUSTC", "/Users/runner/.cargo/bin/rustc"), ("RUSTUP_TOOLCHAIN", "1.98.0"),
                               ("RUSTUP_AUTO_INSTALL", "1")):
                with self.subTest(selector=key), self.assertRaises(module.Refused):
                    module.build_environment(dict(environment, **{key: value}), work, TOOL.RELEASE)
            # No host lookup/path discovery or fallback occurs in this pure selector.
            self.assertNotIn("/inert/fixed-tools", selected["PATH"])
            self.assertFalse({"RUSTFLAGS", "RUSTDOC", "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER"} & selected.keys())
            self.assertFalse({"RUSTC_WRAPPER", "CARGO_ENCODED_RUSTFLAGS", "GITHUB_TOKEN", "MRK_ANDROID_TOOL_INSTANCE"} & selected.keys())
            with self.assertRaises(module.Refused):
                module.Operation(owner, checkout, work, "prepare", environment, TOOL).execute()
            self.assertEqual(observations, [])
            self.assertFalse((work / "android-helper-target").exists())

        profile, service, selection, _history, _descriptor = packaging_fixture()
        selected = TOOL.packaging_signing_data(profile, service)
        self.assertEqual((selected.team, selected.leaf_sha1, selected.leaf_sha256, selected.rsa_bits),
                         ("TEST000001", "1" * 40, "2" * 64, 2048))
        self.assertEqual((selected.producer_sha256, selected.service_sha256), (TOOL.digest(profile), TOOL.digest(service)))
        self.assertIsNone(TOOL.packaging_signing_data(b"schema=1\nstate=unconfigured\n", module.UNCONFIGURED_PROFILE, allow_unconfigured=True))
        for producer, helper in ((b"schema=1\nstate=unconfigured\n", module.UNCONFIGURED_PROFILE),
            (profile, module.UNCONFIGURED_PROFILE), (profile, service.replace(b"TEST000001", b"TEST000002")),
            (profile.replace(b"rsa-bits=2048", b"rsa-bits=1024"), service),
            (profile.replace(b"leaf-certificate-sha256=" + b"2" * 64, b"leaf-certificate-sha256=" + b"3" * 64), service),
            (profile + b"extra=1\n", service), (profile[:-1], service)):
            with self.subTest(producerBytes=len(producer), serviceBytes=len(helper)), self.assertRaises(TOOL.Refused):
                TOOL.packaging_signing_data(producer, helper)
        # Real helper copy/readback/close path with command DATA doubles. A
        # configured selected identity never falls back after a signing refusal.
        for failed_sign in (False, True):
            with self.subTest(configuredFailure=failed_sign), tempfile.TemporaryDirectory() as temporary:
                checkout, work, environment, owner, observations = self.fixture(Path(temporary))
                (checkout / module.PROFILE).write_bytes(service)
                (checkout / module.PRODUCER_PROFILE).write_bytes(profile)
                original = owner.run_owned
                def command(argv, **options):
                    returned = original(argv, **options)
                    if failed_sign and argv[0] == "/usr/bin/codesign" and "--sign" in argv:
                        return CompletedProcess(argv, 9, returned.stdout, b"DATA signing refusal")
                    return returned
                owner.run_owned = command
                operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL)
                if failed_sign:
                    with self.assertRaises(module.Refused): operation.execute()
                else:
                    operation.execute()
                sign = [argv for argv, _ in observations if "--sign" in argv]
                self.assertEqual(len(sign), 1 if failed_sign else 2)
                self.assertTrue(all(argv[argv.index("--sign") + 1] == "1" * 40 and "--timestamp" in argv
                                    and "--timestamp=none" not in argv for argv in sign))
                receipt = json.loads((work / "android-helper-prepare.json").read_bytes())
                self.assertEqual(receipt["passed"], not failed_sign)
                self.assertTrue(receipt["targetRetired"] and receipt["originalClosesKnown"])
                self.assertFalse(receipt["developerIdOrNotarizationQualified"] or receipt["androidServiceAuthenticated"])
                if not failed_sign:
                    verified = [argv for argv, _ in observations if "--test-requirement" in argv]
                    self.assertEqual(len(verified), 2)
                    for argv in verified:
                        requirement = argv[argv.index("--test-requirement") + 1]
                        self.assertIn('certificate leaf = H"' + "1" * 40 + '"', requirement)
                        self.assertIn('certificate leaf[subject.OU] = "TEST000001"', requirement)
                        self.assertIn('certificate leaf[field.1.2.840.113635.100.6.1.13]', requirement)
        with (mock.patch.object(TOOL, "source_build_selection", return_value=selection),
              mock.patch.object(TOOL, "read", side_effect=lambda path, *_: profile if path == TOOL.PRODUCER_PROFILE else service)):
            preflight = TOOL.packaging_selection_command(SimpleNamespace(target=selection.target))
        self.assertFalse(preflight["nativeAuthority"])
        self.assertEqual((preflight["target"], preflight["packageVersion"]), (selection.target, "0.2.0"))
        with (mock.patch.object(TOOL, "source_build_selection", return_value=TOOL.BuildSelection(selection.target, "0.1.0", selection.release)),
              mock.patch.object(TOOL, "read", side_effect=lambda path, *_: profile if path == TOOL.PRODUCER_PROFILE else service),
              self.assertRaises(TOOL.Refused)):
            TOOL.packaging_selection_command(SimpleNamespace(target=selection.target))

        self.assertEqual(module.PYTHON_SUPPLIERS, TOOL.SIGNED_ORIGINAL_SUPPLIERS)
        self.assertEqual(module.PHASES, ("prepare", "verify-before", "verify-after", "package-install"))
        for phase in module.PYTHON_PHASES:
            self.assertEqual(module.entrypoint(["inert", phase, "--target", module.INTEL_TARGET]), (phase, module.INTEL_TARGET))
        for phase in ("python-auto", "python-shipping ", "python-engineering-fallback"):
            with self.assertRaises(module.Refused): module.entrypoint(["inert", phase])
        path, entitlements = Path("/inert/python3"), Path("/inert/empty.plist")
        identity = ("TEST000001", "1" * 40)
        for selected in (None, identity):
            command = module.python_sign_command(path, entitlements, "python-engineering", selected)
            self.assertEqual(command[command.index("--sign") + 1], "-")
            self.assertIn("--timestamp=none", command)
        with self.assertRaises(module.Refused): module.python_sign_command(path, entitlements, "python-shipping", None)
        shipping = module.python_sign_command(path, entitlements, "python-shipping", identity)
        self.assertEqual(shipping[shipping.index("--sign") + 1], "1" * 40)
        self.assertNotIn("--deep", shipping)
        self.assertIn("--timestamp", shipping)
        _transport, matcher, _parser = self.python_data_functions()
        for target in (module.ARM_TARGET, module.INTEL_TARGET):
            for phase, flags in (("python-engineering", 0x10002), ("python-shipping", 0x10000)):
                body, machine = self.python_image(target, flags), module.build_profile(target)[0]
                self.assertEqual(module.python_code_flags(body, machine, phase, matcher), [flags])
                for modified in (self.python_image(target, 0x2), self.python_image(target, flags ^ 2),
                                 body[:-1], body + b"x", body[:48] + b"X" + body[49:]):
                    if modified[48:49] == b"X" and len(modified) == len(body):
                        with self.assertRaises(module.Refused): matcher.macho_content_valid(body, modified, machine, signing=True)
                    else:
                        with self.assertRaises((module.Refused, ValueError, struct.error)):
                            module.python_code_flags(modified, machine, phase, matcher)
                # Duplicate/overlapping signature slots cannot be a runtime observation.
                offset = struct.unpack_from("<I", body, 40)[0]
                bad = bytearray(body); struct.pack_into(">I", bad, offset + 8, 2)
                with self.assertRaises(module.Refused): module.python_code_flags(bytes(bad), machine, phase, matcher)
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.python_fixture(Path(directory), phase="python-shipping", failure="unconfigured")
            with self.python_fixture_call(fixture), self.assertRaises((module.Refused, TOOL.Refused)):
                fixture.operation.execute()
            self.assertEqual(fixture.observations, [])
            self.assertFalse((fixture.work / "python3").exists())
        # Source-only dispatch closure: neither native library execution nor a
        # permissive entitlement retry exists in these private Python phases.
        helper_source = (Path(__file__).absolute().parents[2] / "desktop/tools/macos_android_helper_package.py").read_text()
        python_source = helper_source.split("    def python_prepare(", 1)[1].split("    def python_retirement(", 1)[0]
        self.assertNotIn("--deep", python_source)
        self.assertNotIn("allow-jit", python_source)
        self.assertNotIn("disable-library-validation", python_source)
        self.assertNotIn("allow-unsigned-executable-memory", python_source)
        self.assertLess(python_source.index('python_code_flags('), python_source.index('"python-verify"'))
        self.assertLess(python_source.index('"python-verify"'), python_source.index('"signed-payload/"'))
        self.assertEqual(python_source.count('for role in ("modules", "loader", "tls", "cancellation")'), 1)


    def test_ios_recovery_admission_keeps_the_full_package_scope_closed(self):
        module = ANDROID_HELPER
        self.assertEqual(module.PACKAGE_SCOPES, (
            "project-fields", "ios-current-synthetic", "android-inputs",
            "project-fields-android-inputs", "vault-helper-shipping",
            "installation-inspection", "vault-helper-shipping-installation-inspection",
            "project-recovery-pending", "ios-recovery-pending", "doctor-preflight2", "local-edits3",
        ))
        self.assertEqual(module.PHASES, ("prepare", "verify-before", "verify-after", "package-install"))
        sha, ref = "a" * 40, "refs/heads/verify/desktop-macos-aqua"
        work = module.WORK_PARENT / "mrk-macos-aqua.AbC12345"
        environment = {
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
            "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit",
            "GITHUB_WORKSPACE": str(module.CHECKOUT), "GITHUB_SHA": sha, "GITHUB_WORKFLOW_SHA": sha,
            "GITHUB_WORKFLOW_REF": "Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-aqua.yml@" + ref,
            "GITHUB_REF": ref, "MRK_EXPECTED_SHA": sha, "MRK_MACOS_INSTALL_SOURCE_COMMIT": sha,
            "RUSTUP_TOOLCHAIN": "1.98.1", "DEVELOPER_DIR": "/Library/Developer/CommandLineTools", "MACOSX_DEPLOYMENT_TARGET": "26.0",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "MRK_MACOS_WORK": str(work),
            "MRK_MACOS_AQUA_SCOPE": "ios-recovery-pending", "MRK_MACOS_PACKAGE_ROLE": "installed-shell-observation",
        }
        # Only observation doubles: admit() must keep its real scope/source/path checks.
        # This fixed work path is lexical DATA, never created, opened or executed.
        with (mock.patch.object(module.sys, "platform", "darwin"),
              mock.patch.object(module, "__file__", str(module.CHECKOUT / "desktop/tools/macos_android_helper_package.py")),
              mock.patch.multiple(module.os, uname=mock.Mock(return_value=SimpleNamespace(machine="arm64")),
                                  getuid=mock.Mock(return_value=501), geteuid=mock.Mock(return_value=501),
                                  getgid=mock.Mock(return_value=20), getegid=mock.Mock(return_value=20))):
            self.assertEqual(module.admit(environment), work)
            for scope in ("doctor-preflight2", "local-edits3"):
                self.assertEqual(module.admit(dict(environment, MRK_MACOS_AQUA_SCOPE=scope)), work)
            for scope in ("android-registration-lifecycle", "wrapping-keychain-private", "xcode-installed-classification",
                          "supplier", "ios-recovery-pending-extra", "doctor-preflight2-extra", "local-edits3-extra", ""):
                with self.subTest(scope=scope), self.assertRaisesRegex(module.Refused, "^full-package-scope-only$"):
                    module.admit(dict(environment, MRK_MACOS_AQUA_SCOPE=scope))
            for key, value, reason in (
                ("GITHUB_WORKFLOW_SHA", "b" * 40, "hosted-source-bindings"),
                ("GITHUB_EVENT_NAME", "workflow_dispatch", "hosted-source-bindings"),
                ("MRK_MACOS_PACKAGE_ROLE", "ordinary-image", "hosted-source-bindings"),
                ("MRK_MACOS_PACKAGE_ROLE", "", "hosted-source-bindings"),
                ("MRK_MACOS_WORK", str(module.WORK_PARENT / "mrk-macos-installed.AbC12345"), "owned-work-route"),
            ):
                with self.subTest(binding=key), self.assertRaisesRegex(module.Refused, "^" + reason + "$"):
                    changed = dict(environment)
                    changed[key] = value
                    module.admit(changed)
        for phase in module.PHASES:
            self.assertEqual(module.entrypoint(["tool", phase]), (phase, "aarch64-apple-darwin"))
            for target in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
                self.assertEqual(module.entrypoint(["tool", phase, "--target", target]), (phase, target))
        for argv in (["tool"], ["tool", "unknown"], ["tool", "prepare", "--target"],
                     ["tool", "prepare", "--other", "x86_64-apple-darwin"],
                     ["tool", "prepare", "--target", "x86_64h-apple-darwin"],
                     ["tool", "prepare", "--target", "x86_64-apple-darwin", "extra"]):
            with self.subTest(argv=argv), self.assertRaises(module.Refused):
                module.entrypoint(argv)

        ordinary_ref = "refs/heads/verify/desktop-macos-installed"
        ordinary_work = module.WORK_PARENT / "mrk-macos-installed.AbC12345"
        for target, machine, runner in (("aarch64-apple-darwin", "arm64", "ARM64"),
                                         ("x86_64-apple-darwin", "x86_64", "X64")):
            ordinary = dict(environment, GITHUB_REF=ordinary_ref, RUNNER_ARCH=runner,
                GITHUB_WORKFLOW_REF="Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-installed.yml@" + ordinary_ref,
                MRK_MACOS_WORK=str(ordinary_work), MRK_MACOS_PACKAGE_ROLE="ordinary-image")
            uname = mock.Mock(return_value=SimpleNamespace(machine=machine))
            with (self.subTest(target=target), mock.patch.object(module.sys, "platform", "darwin"),
                  mock.patch.object(module.sys, "maxsize", 2 ** 63 - 1),
                  mock.patch.object(module, "__file__", str(module.CHECKOUT / "desktop/tools/macos_android_helper_package.py")),
                  mock.patch.multiple(module.os, uname=uname,
                      getuid=mock.Mock(return_value=501), geteuid=mock.Mock(return_value=501),
                      getgid=mock.Mock(return_value=20), getegid=mock.Mock(return_value=20))):
                self.assertEqual(module.admit(ordinary, target=target), ordinary_work)
                self.assertEqual(uname.call_count, 1)
                with self.assertRaisesRegex(module.Refused, "^hosted-source-bindings$"):
                    module.admit(dict(ordinary, RUNNER_ARCH="X64" if runner == "ARM64" else "ARM64"), target=target)
                uname.return_value = SimpleNamespace(machine="x86_64" if machine == "arm64" else "arm64")
                with self.assertRaisesRegex(module.Refused, "^hosted-native-platform$"):
                    module.admit(ordinary, target=target)
                uname.return_value = SimpleNamespace(machine=machine)
                with mock.patch.object(module.sys, "maxsize", 2 ** 31 - 1), self.assertRaisesRegex(module.Refused, "^hosted-native-platform$"):
                    module.admit(ordinary, target=target)
                observed = uname.call_count
                with self.assertRaisesRegex(module.Refused, "^closed-build-target$"):
                    module.admit(ordinary, target=[])
                self.assertEqual(uname.call_count, observed)
                if target == "x86_64-apple-darwin":
                    with self.assertRaisesRegex(module.Refused, "^closed-workflow-target$"):
                        module.admit(dict(environment, RUNNER_ARCH="X64"), target=target)


    def test_both_workflows_use_one_digest_and_owned_nested_checks_around_app_signing(self):
        root = Path(__file__).absolute().parents[2]
        for filename, assembly, binding in (
            ("desktop-macos-installed.yml", "Assemble the ordinary image app and sign code inside-out (never --deep)",
             "Bind this completed signed app and current-source runtime into fresh Installer DATA"),
            ("desktop-macos-aqua.yml", "Assemble the instrumented observation app with SOURCE-selected signing",
             "Bind this signed app and current-source runtime into fresh Installer DATA"),
        ):
            workflow = (root / ".github/workflows" / filename).read_text()
            build = workflow_step(workflow, "Build and sign the fixed resident image and C facades")
            app, inputs = workflow_step(workflow, assembly), workflow_step(workflow, binding)
            self.assertIn("id: android_helper", build)
            self.assertIn('macos_android_helper_package.py prepare >> "$GITHUB_OUTPUT"', build)
            self.assertNotIn("cargo build", build)
            role = "ordinary-image" if filename == "desktop-macos-installed.yml" else "installed-shell-observation"
            self.assertIn("MRK_MACOS_PACKAGE_ROLE: " + role, workflow)
            roles = ANDROID_HELPER.PREPARE_ROLES + ("verify-before", "verify-before-resident-image",
                                                   "verify-after", "verify-after-resident-image")
            for command_role in roles:
                for suffix in (("jsonl", "stderr", "status") if command_role == "build" else ("stdout", "stderr", "status")):
                    self.assertEqual(workflow.count("/android-helper-" + command_role + "." + suffix), 1)
            for phase in ANDROID_HELPER.PHASES:
                self.assertEqual(workflow.count("/android-helper-" + phase + ".json"), 1)
            for step in (app, inputs):
                self.assertIn("--package-role " + role, step)
                self.assertIn("MRK_MACOS_RESIDENT_IMAGE_SHA256: $" + "{{ steps.android_helper.outputs['resident-image-sha256'] }}", step)
                self.assertIn('--expected-resident-image "$MRK_MACOS_RESIDENT_IMAGE_SHA256"', step)
                self.assertIn("MRK_MACOS_ANDROID_HELPER_SHA256: ${{ steps.android_helper.outputs.sha256 }}", step)
                self.assertIn('--expected-android-helper "$MRK_MACOS_ANDROID_HELPER_SHA256"', step)
            self.assertIn('--android-helper "$MRK_MACOS_WORK/mrk-android-register"', app)
            self.assertLess(app.index("stage_macos_installed.py app"), app.index("macos_android_helper_package.py verify-before"))
            self.assertLess(app.index("macos_android_helper_package.py verify-before"), app.index("/usr/bin/codesign --force --sign \"$MRK_MACOS_SOURCE_SIGNER_SHA1\""))
            self.assertLess(app.index("/usr/bin/codesign --force --sign \"$MRK_MACOS_SOURCE_SIGNER_SHA1\""), app.index("macos_android_helper_package.py verify-after"))
            self.assertIn("MRK_MACOS_ENTRY_SHA256: ${{ steps.android_helper.outputs['entry-sha256'] }}", app)
            self.assertIn('--entry-binary "$MRK_MACOS_WORK/mrk-macos-entry" --expected-entry "$MRK_MACOS_ENTRY_SHA256"', app)
            self.assertIn('--expected-entry "$MRK_MACOS_SIGNED_ENTRY_SHA256" --expected-app-binary "$MRK_MACOS_SIGNED_PAYLOAD_SHA256"', inputs)
            sequence = [app.index(value) for value in (
                '--timestamp "$payload"', 'payload_sha=$(',
                '--timestamp "$MRK_MACOS_WORK/app/Mobile Release Kit.app"',
                'macos_android_helper_package.py verify-after', 'entry_sha=$(')]
            self.assertEqual(sequence, sorted(sequence))
            self.assertNotIn("android-helper-*", workflow)
            self.assertIn('--resident-image "$MRK_MACOS_WORK/libmrk_resident_image.dylib"', app)
            if filename == "desktop-macos-installed.yml":
                self.assertIn('--expected-app-binary "$MRK_MACOS_DESKTOP_FACADE_SHA256"', app)
                self.assertLess(app.index('--timestamp "$desktop_image"'), app.index('--timestamp "$payload"'))
                self.assertEqual(app.count('/usr/bin/codesign --verify --strict "$desktop_image"'), 2)
                self.assertIn('--expected-desktop-image "$MRK_MACOS_SIGNED_DESKTOP_IMAGE_SHA256"', inputs)
            if filename == "desktop-macos-aqua.yml":
                self.assertIn('--expected-app-binary "$MRK_MACOS_OBSERVER_SHA256"', app)
                self.assertIn('--observer-cargo-messages "$MRK_MACOS_WORK/observer-build.jsonl"', app)
                self.assertIn('--observer-cargo-target-dir "$CARGO_TARGET_DIR"', app)
                self.assertNotIn("--desktop-image", app + inputs)
                gates = lambda block: [line.strip() for line in block.splitlines() if line.startswith("        if:")]
                self.assertEqual(gates(build), gates(app))
                self.assertEqual(gates(build), gates(inputs))
                for scope in ("project-recovery-pending", "ios-recovery-pending", "doctor-preflight2", "local-edits3"):
                    self.assertIn(scope, ANDROID_HELPER.PACKAGE_SCOPES)
                    self.assertIn("env.MRK_MACOS_AQUA_SCOPE == '" + scope + "'", " ".join(gates(build)))
                for excluded in ("android-registration-lifecycle", "wrapping-keychain-private", "xcode-installed-classification", "supplier"):
                    self.assertNotIn(excluded, " ".join(gates(build)))


            preflight = workflow_step(workflow, "Require the fixed SOURCE producer identity and release before ordinary signing")
            install_name = ("Application installation uses only standard privileged Installer; app and Python stay nonroot"
                            if filename == "desktop-macos-aqua.yml" else
                            "Standard Installer only is privileged; never execute the app or Python as root")
            installed = workflow_step(workflow, install_name)
            self.assertLess(workflow.index("stage_macos_installed.py packaging-selection"), workflow.index("macos_android_helper_package.py prepare"))
            self.assertIn('MRK_MACOS_SOURCE_SIGNER_SHA1=', preflight)
            self.assertIn('MRK_MACOS_SOURCE_PACKAGE_VERSION=', preflight)
            self.assertIn('row.get("nativeAuthority") is not False', preflight)
            self.assertIn("macos_android_helper_package.py package-install", installed)
            self.assertNotIn("--sign -", app)
            self.assertNotIn("--timestamp=none", app)
            if filename == "desktop-macos-aqua.yml":
                self.assertEqual(gates(preflight), gates(build))
                self.assertEqual(gates(installed), gates(build))

        signing = (root / ".github/workflows/desktop-macos-python-runtime-signing.yml").read_text()
        self.assertEqual(signing.count("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"), 1)
        self.assertEqual(signing.count("github-token:"), 1)
        self.assertIn("persist-credentials: false", signing)
        self.assertIn("max-parallel: 1", signing)
        self.assertIn("fail-fast: false", signing)
        self.assertLess(signing.index("target: x86_64-apple-darwin"), signing.index("target: aarch64-apple-darwin"))
        for target, runner in ((ANDROID_HELPER.ARM_TARGET, "macos-26"), (ANDROID_HELPER.INTEL_TARGET, "macos-26-intel")):
            self.assertIn("target: " + target, signing)
            self.assertIn("runner: " + runner, signing)
            self.assertIn("supplier_run: '" + ANDROID_HELPER.PYTHON_SUPPLIERS[target]["runId"] + "'", signing)
            self.assertIn("supplier_artifact: '" + ANDROID_HELPER.PYTHON_SUPPLIERS[target]["artifactId"] + "'", signing)
        owner = workflow_step(signing, "Sign and probe one derived executable through the same original owner")
        self.assertEqual(owner.count("macos_android_helper_package.py"), 1)
        self.assertIn('"$MRK_PYTHON_SIGNING_PHASE" --target "$MRK_PYTHON_TARGET"', owner)
        self.assertNotIn("cargo", owner)
        self.assertNotIn("sudo", signing)
        self.assertNotIn("notarytool", signing)
        self.assertNotIn("workflow_dispatch", signing)
        self.assertNotIn("--deep", signing)
        self.assertNotIn(".stdout", signing)
        output = workflow_step(signing, "Publish configured capsule only after the original zero exit")
        self.assertIn("steps.sign.outcome == 'success'", output)
        self.assertIn("refs/heads/verify/desktop-macos-python-runtime-signing-shipping", output)
        self.assertIn("/python3\n", output)
        self.assertIn("/python-signed-receipt.json", output)
        self.assertNotIn("*", output)
        self.assertLess(signing.index("Download only the accepted"), signing.index("Sign and probe one derived"))
        self.assertLess(signing.index("Sign and probe one derived"), signing.index("Publish configured capsule"))




def odc(name, mode, body=b"", *, uid=0, gid=0, links=1):
    encoded = name.encode("ascii") + b"\0"
    header = b"070707" + ("%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o" %
        (0, 1, mode, uid, gid, links, 0, 0, len(encoded), len(body))).encode("ascii")
    return header + encoded + body


def package_data(*, uid=0, gid=0, root=".", file_owner=None):
    # Small inert parser input, not a native tar/xar or Installer observation.
    files = {"input/readonly.txt": (b"DATA\n", 0o444), "postinstall": (b"exit 97\n", 0o555)}
    info = (b'<?xml version="1.0"?>\n<pkg-info identifier="dev.mobile-release-kit.desktop.installed" '
            b'version="0.1.1" install-location="/" auth="root"><payload numberOfFiles="0"/>'
            b'<scripts><postinstall file="./postinstall"/></scripts></pkg-info>\n')
    archive = odc(root, stat.S_IFDIR | 0o755, uid=uid, gid=gid)
    archive += odc("./input", stat.S_IFDIR | 0o555, uid=uid, gid=gid)
    for name, (body, mode) in files.items():
        owner = file_owner if file_owner is not None and name == "postinstall" else (uid, gid)
        archive += odc("./" + name, stat.S_IFREG | mode, body, uid=owner[0], gid=owner[1])
    return files, {"PackageInfo": info, "Scripts": archive + odc("TRAILER!!!", 0)}


def original_result(expected, *, stage=".install-" + "d" * 32):
    reason, runtime, app, state, verified, _exit = expected
    recorded = state == "installed" or (runtime == "confirmed" and app == "occupied-refused")
    partial = reason == "open-refused" and runtime == "confirmed"
    metadata = {"state": "recorded" if recorded else "incomplete" if partial else "not-attempted",
                "attemptedFiles": 2 if recorded or partial else 0, "openedFiles": 2 if recorded else 1 if partial else 0,
                "plannedBytes": 10 if recorded or partial else 0, "writtenBytes": 10 if recorded else 6 if partial else 0,
                "writersSettled": True}
    return {"schemaVersion": 1, "state": state, "reason": reason, "release": TOOL.RELEASE,
            "runtimePublication": runtime, "appPublication": app, "staging": stage, "payloadVerified": verified,
            "payloadWritersSettled": True, "originalsSettled": True, "deadlineMetAfterFinalCloses": True, "createdAncestors": [],
            "cleanup": "original-closes-only-no-deletion", "sourceCommit": "a" * 40, "inventorySha256": "b" * 64, "runtimeManifestSha256": "c" * 64, "installationMetadata": metadata,
            "maintenanceGate": {"schemaVersion": 1, "entered": stage is not None,
                "creation": "created" if stage else "not-attempted", "fixedBytes": 30, "writtenBytes": 30 if stage else 0,
                "sealed": stage is not None, "filePersisted": stage is not None, "parentPersisted": stage is not None,
                "writer": "closed" if stage else "not-attempted", "verified": stage is not None,
                "exclusiveAttempted": stage is not None, "exclusiveAcquired": stage is not None,
                "participant": "closed" if stage else "not-attempted", "cleanup": "original-closes-only-permanent-gate-retained"}}


def reported_fixture_data():
    # Inert serialized DATA, never a native observation or root test runner.
    rows = []
    for name, expected in TOOL.FIXTURE_CASES.items():
        stage = None if name in ("occupied-app", "occupied-release") else ".install-" + "d" * 32
        point = {"prepublication-persistence-report": "payload-file-before-any-publication",
                 "postruntime-persistence-report": "stage-directory-after-runtime-rename"}.get(name)
        identity = {"device": 1, "inode": 42, "mode": 0o444, "uid": 0, "gid": 0, "links": 1, "size": len(TOOL.FIXTURE_MARKER),
                    "mtimeSeconds": 1, "mtimeNanoseconds": 0, "ctimeSeconds": 1, "ctimeNanoseconds": 0}
        witness = {"visibleRelativePath": TOOL.visible_occupant(name), "sha256": TOOL.digest(TOOL.FIXTURE_MARKER),
                   "before": dict(identity), "after": dict(identity), "verifiedByOriginalInstaller": True}
        persistence = {"point": point, "actualNativeSucceeded": True, "actualNativeErrno": None, "injectedReportedFailure": True}
        rows.append({"case": name, "passed": True, "proofError": None, "originalResult": original_result(expected, stage=stage), "originalExit": expected[-1],
                     "occupant": witness if point is None else None, "persistence": persistence if point is not None else None,
                     "absenceObservedBeforeCollision": name in ("runtime-publication-collision", "staging-file-collision", "first-publication-second-refusal", "metadata-descriptor-collision"),
                     "stagingOpenErrno": 17 if name in ("staging-file-collision", "metadata-descriptor-collision") else None})
    return {"schemaVersion": 1, "sourceCommit": "a" * 40, "inventorySha256": "b" * 64, "runtimeManifestSha256": "c" * 64,
            "fixtureBase": TOOL.FIXTURE_PREFIX + "a" * 12 + "-" + "e" * 32, "setupError": None, "setupOriginalsSettled": True,
            "setupDeadlineMet": True, "inertCloseDeadlinePolicyTable": True, "fixedCasesComplete": True, "passed": True, "cases": rows,
            "genuineConcurrentRaceObserved": False, "nativeCloseFailureInjected": False, "applicationLaunched": False, "guiSaveQualified": False,
            "qualification": "native-installer-collisions-and-injected-policy-only"}


def log_args(command="installer-log-cursor", *, fixture=False):
    package = ("/work/package-fixture-final/MobileReleaseKit-InstallerFixture.pkg" if fixture else
               "/work/package-mount/MobileReleaseKit-Request-" + "1" * 32 + ".pkg")
    return SimpleNamespace(command=command, fixture=fixture, request_id=None if fixture else "1" * 32, package=Path(package), expected_source="a" * 40,
                           expected_inventory="b" * 64, expected_manifest="c" * 64, run_id="123", run_attempt="1",
                           cursor=Path("/work/cursor.json"), selected_output=Path("/work/selected.txt"))


def log_info(size=0, **changes):
    values = dict(st_dev=1, st_ino=42, st_mode=stat.S_IFREG | 0o640, st_uid=0, st_gid=80,
                  st_nlink=1, st_size=size, st_mtime_ns=1, st_ctime_ns=1)
    values.update(changes)
    return SimpleNamespace(**values)


def result_args(*, fixture=False):
    return SimpleNamespace(input=Path("/work/input"), fixture=fixture, expected_source="a" * 40,
                           expected_inventory="b" * 64, expected_manifest="c" * 64,
                           request_id=None if fixture else f"{101:032x}", expected_package="d" * 64,
                           producer_descriptor=Path("/work/package/producer.json"), producer_signature=Path("/work/package/producer.sig"),
                           installer_status=Path("/work/installer-fixture-output.status" if fixture else "/work/installer-output.status"))


def maintenance_documents(actions=("fresh-install",), *, target="aarch64-apple-darwin"):
    """Synthetic closed records; no real signature, installer or native event."""
    prefix = "macos26-arm64-" if target == "aarch64-apple-darwin" else "macos26-x86_64-"
    profile = "fixed-macos26-arm64-maintenance-v2" if target == "aarch64-apple-darwin" else "fixed-macos26-x86_64-maintenance-v2"
    policy = {"schemaVersion": 1, "kind": "mrk-macos-developer-id-code-policy-v1", "teamIdentifier": "TEAM000001",
              "leafCertificateSha1": "1" * 40, "leafCertificateSha256": "2" * 64, "hardenedRuntime": True, "entitlements": "empty"}
    policy_hash = TOOL.digest(json.dumps(policy, separators=(",", ":")).encode("ascii"))
    def release(number):
        return {"profile": profile, "packageIdentifier": "dev.mobile-release-kit.desktop.installed",
                "bundleIdentifier": "dev.mobile-release-kit.desktop", "packageVersion": f"0.{number}.0",
                "release": prefix + f"ordinary-data-{number}", "sourceCommit": "a" * 40, "protocolSha256": TOOL.CURRENT_PROTOCOL,
                "runtimeManifestSha256": "c" * 64, "inventorySha256": "b" * 64, "signingPolicySha256": policy_hash,
                "packageSha256": "d" * 64 if number == 3 else "e" * 64}
    producer = {"schemaVersion": 2, "kind": "mrk-macos-install-producer-v2", "domain": "MobileReleaseKit-package-producer-v2", "target": target,
                "releaseSet": {"schemaVersion": 2, "current": release(3), "acceptedPredecessors": [release(2)]},
                "signingPolicies": [{"sha256": policy_hash, "policy": policy}]}
    def identity(inode, mode):
        return {"device": 1, "inode": inode, "mode": stat.S_IFDIR | mode, "uid": 0, "gid": 0, "flags": 0}
    records, evidence, previous = {}, [], None
    for index, action in enumerate(actions, 1):
        invocation, request_id = f"{index:032x}", f"{100+index:032x}"
        selected = release(2 if "update" in actions[index:] else 3)
        intent = {"schemaVersion": 2, "kind": "mrk-macos-maintenance-intent-v2", "target": target,
                  "invocation": invocation, "requestId": request_id, "action": action,
                  "previous": None if previous is None else previous["current"]["release"], "next": selected,
                  "previousState": None if previous is None else {"invocation": previous["invocation"],
                      "sha256": TOOL.digest(records[previous["invocation"]][1])}}
        generation = {"release": selected, "instance": f"{1000+index:032x}", "releaseDirectory": identity(200+index, 0o755),
                      "app": {"location": "canonical", "identity": identity(300+index, 0o555)}}
        retained = [] if previous is None else copy.deepcopy(previous["retained"])
        if action == "same-package-noop":
            generation = copy.deepcopy(previous["current"])
        elif action == "restore-fixed-app":
            generation = {**copy.deepcopy(previous["current"]), "app": generation["app"]}
        elif action == "update":
            retained.append({**copy.deepcopy(previous["current"]), "app": {"location": "retained", "invocation": invocation,
                             "identity": copy.deepcopy(previous["current"]["app"]["identity"])}})
        state = {"schemaVersion": 2, "kind": "mrk-macos-maintenance-state-v2", "target": target, "invocation": invocation,
                 "requestId": request_id, "capsuleInvocation": invocation, "intendedAction": action, "phase": "mutation-recorded",
                 "current": generation, "retained": retained, "previousEvidence": list(evidence), "residue": None}
        raw_intent, raw_state = TOOL.canonical(intent) + b"\n", TOOL.canonical(state) + b"\n"
        count = 0 if action == "same-package-noop" else 24577
        writer = {"returned": True, "exitCode": 0, "originalJoined": True, "resultEof": True, "originalClosesKnown": True,
                  "withinOriginalDeadline": True, "payloadWriteCount": count, "payloadWriteBytes": count}
        capsule = {"schemaVersion": 2, "kind": "mrk-macos-maintenance-capsule-v2", "target": target, "invocation": invocation,
                   "requestId": request_id, "intendedAction": action, "previous": intent["previous"], "next": selected,
                   "actualCurrent": selected, "intentSha256": TOOL.digest(raw_intent), "stateSha256": TOOL.digest(raw_state),
                   "outcome": {"fresh-install": "applied", "update": "applied", "same-package-noop": "same-package", "restore-fixed-app": "restored-app"}[action],
                   "writer": writer}
        raw_capsule = TOOL.canonical(capsule) + b"\n"
        records[invocation] = (raw_intent, raw_state, raw_capsule)
        hashes = {"intentSha256": TOOL.digest(raw_intent), "stateSha256": TOOL.digest(raw_state), "capsuleSha256": TOOL.digest(raw_capsule)}
        evidence.append({"invocation": invocation, **hashes})
        evidence.sort(key=lambda row: row["invocation"])
        previous = state
    result = {"schemaVersion": 2, "kind": "maintenance-parent-pending-finalization", "invocation": invocation, "requestId": request_id,
              "resultName": f"MobileReleaseKit-InstallerResult-v2-{request_id}.json",
              "resultFinality": "pending-own-write-readback-close-and-outer-return", "action": action,
              "writerState": {"fresh-install": "installed", "update": "installed", "same-package-noop": "same-package", "restore-fixed-app": "restored-app"}[action],
              "writerExit": 0, **hashes, "payloadWriteCount": count, "payloadWriteBytes": count, "originalWriterJoined": True,
              "parentFinality": "pending-original-closes-and-outer-return", "retainedGate": "parent-command-reference-until-kernel-exit",
              "historicalOuterExit": "unverified"}
    return producer, records, result


def export_document(*, fixture=False, result=None):
    if not fixture:
        return maintenance_documents()[2] if result is None else result
    return {"schemaVersion": 1, "kind": "fixture" if fixture else "ordinary", "sourceCommit": "a" * 40,
            "inventorySha256": "b" * 64, "runtimeManifestSha256": "c" * 64,
            "transportState": "pending-original-export-finalization", "result": {} if result is None else result}


@contextlib.contextmanager
def channel_data(path, body=None, *, private=False):
    # Finite DATA model for the existing original-FD reader. Every OS operation
    # that could touch these numeric tokens is replaced; no fake FD reaches the
    # host, no file is created, and no native ownership/ACL/finality is claimed.
    names, objects, events, opened, closed = {}, {}, [], [], []
    outer = None
    for index, name in enumerate(path.parts[:-1]):
        fd = 40 + index
        task_parent = private and index == len(path.parts) - 2
        names[(outer, name)] = fd
        objects[fd] = log_info(st_ino=fd, st_mode=stat.S_IFDIR | (0o700 if task_parent else 0o755),
                               st_uid=501 if task_parent else 0, st_gid=80, st_nlink=3)
        outer = fd
    leaf = 40 + len(path.parts) - 1
    if body is not None:
        names[(outer, path.name)] = leaf
        objects[leaf] = log_info(len(body), st_ino=leaf, st_mode=stat.S_IFREG | (0o600 if private else 0o444),
                                 st_uid=501 if private else 0, st_gid=80 if private else 0)
    model = SimpleNamespace(names=names, objects=objects, events=events, opened=opened, closed=closed,
                            parent=outer, leaf=leaf, offset=0)
    def named(name, *, dir_fd=None, follow_symlinks=True):
        assert follow_symlinks is False
        fd = names.get((dir_fd, name))
        if fd is None:
            raise FileNotFoundError(TOOL.errno.ENOENT, "inert expected-name absence")
        return objects[fd]
    def acquire(name, flags, *, dir_fd=None):
        fd = names[(dir_fd, name)]
        expected = TOOL.READ_FLAGS | (TOOL.os.O_DIRECTORY if stat.S_ISDIR(objects[fd].st_mode) else 0)
        assert flags == expected and fd not in opened
        opened.append(fd); events.append(("open", fd))
        return fd
    def read(fd, size):
        assert fd == leaf and fd in opened and fd not in closed and size >= 0
        block = body[model.offset:model.offset + size]
        model.offset += len(block); events.append(("read", fd))
        return block
    def close(fd):
        assert fd in opened and fd not in closed
        closed.append(fd); events.append(("close", fd))
    api = mock.Mock(wraps=TOOL.os)
    api.O_DIRECTORY = TOOL.os.O_DIRECTORY
    api.getuid.return_value = api.geteuid.return_value = 501
    api.getgid.return_value = api.getegid.return_value = 20
    api.stat.side_effect = named
    api.open.side_effect = acquire
    api.fstat.side_effect = objects.__getitem__
    api.read.side_effect = read
    api.close.side_effect = close
    model.api, model.named, model.read, model.close = api, named, read, close
    with (mock.patch.object(TOOL, "os", api), mock.patch.object(TOOL, "no_xattrs") as attributes):
        model.attributes = attributes
        yield model


@unittest.skipUnless(TOOL is not None, "Darwin/POSIX DATA tool only")
class MacInstalledData(unittest.TestCase):
    def test_portable_names_and_complete_directory_identity(self):
        for name in ("python/lib/python3.14/encodings/utf_8.py", "app/Contents/_CodeSignature/CodeResources"):
            self.assertTrue(TOOL.safe_path(name))
        for name in ("../x", "a//b", "a/./b", "/root", "a\\b", "NUL.txt", "CON", "x.", "x ", "é.py"):
            self.assertFalse(TOOL.safe_path(name))
        self.assertEqual(TOOL.directories({"a/b": None}), {"a"})
        for files in ({"a": None, "a/b": None}, {"a/B": None, "a/b": None}):
            with self.assertRaises(TOOL.Refused):
                TOOL.directories(files)

    def test_json_rejects_duplicates_and_nonfinite_constants(self):
        self.assertEqual(TOOL.decode(b'{"a":[1,true,null]}'), {"a": [1, True, None]})
        for body in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}', b'{"a":-1e999}'):
            with self.assertRaises(TOOL.Refused):
                TOOL.decode(body)

    def test_build_release_data_is_closed_and_source_selected_without_fallback(self):
        valid = {"schemaVersion": 1, "packageVersion": "1.2.3", "release": "macos26-arm64-example-02"}
        body = TOOL.canonical(valid)
        self.assertEqual(TOOL.build_release_data(body), valid)
        for field, replacement in (
            ("schemaVersion", True), ("schemaVersion", 1.0), ("schemaVersion", 2), ("extra", False),
            ("packageVersion", None), ("packageVersion", "01.2.3"), ("packageVersion", "1.2.3.4"),
            ("packageVersion", "1.2.-3"), ("packageVersion", "4294967296.2.3"),
            ("packageVersion", "1.2.3-beta"), ("release", "macos26-arm64-"),
            ("release", "macos26-arm64-example/02"), ("release", "macos26-arm64-example."),
            ("release", "macos26-arm64-UPPER"), ("release", "macos26-arm64-" + "a" * 128),
        ):
            with self.subTest(field=field, value=replacement), self.assertRaises(TOOL.Refused):
                TOOL.build_release_data(TOOL.canonical({**valid, field: replacement}))
        for raw in (b"", b"[]", b"{}", b"null", b" " * (TOOL.BUILD_RELEASE_LIMIT + 1), body + b" {}",
                    body[:-1] + b',"release":"macos26-arm64-example-02"}'):
            with self.subTest(raw=raw[:80]), self.assertRaises(TOOL.Refused):
                TOOL.build_release_data(raw)
        with mock.patch.object(TOOL, "read", return_value=body) as read:
            self.assertEqual(TOOL.source_build_release(), ("1.2.3", "macos26-arm64-example-02"))
            read.assert_called_once_with(TOOL.BUILD_RELEASE_INPUT, TOOL.BUILD_RELEASE_LIMIT)
        with mock.patch.object(TOOL, "read", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                TOOL.source_build_release()

        arm_identity = (TOOL.PACKAGE_VERSION, TOOL.RELEASE)
        for target, prefix, filename in (("aarch64-apple-darwin", "macos26-arm64-", "build-release.json"),
                                          ("x86_64-apple-darwin", "macos26-x86_64-", "build-release-intel.json")):
            selected = dict(valid, release=prefix + "example-02")
            selected_body = TOOL.canonical(selected)
            with self.subTest(target=target), mock.patch.object(TOOL, "read", return_value=selected_body) as reader:
                self.assertEqual(TOOL.build_release_data(selected_body, target=target), selected)
                self.assertEqual(TOOL.source_build_release(target=target), ("1.2.3", selected["release"]))
                reader.assert_called_once_with(TOOL.DESKTOP / "macos-installed-inputs" / filename, TOOL.BUILD_RELEASE_LIMIT)
                if target == "x86_64-apple-darwin":
                    selection = TOOL.source_build_selection(target)
                    self.assertEqual(tuple(selection), (target, "1.2.3", selected["release"]))
                    with self.assertRaises(AttributeError): selection.release = TOOL.RELEASE
                other = "x86_64-apple-darwin" if target == "aarch64-apple-darwin" else "aarch64-apple-darwin"
                with self.assertRaises(TOOL.Refused): TOOL.build_release_data(selected_body, target=other)
        self.assertEqual((TOOL.PACKAGE_VERSION, TOOL.RELEASE), arm_identity)
        for invalid in (None, True, "x86_64h-apple-darwin", "aarch64-apple-ios", "universal", ""):
            with self.subTest(target=invalid), mock.patch.object(TOOL, "read") as reader:
                with self.assertRaises(TOOL.Refused): TOOL.source_build_release(target=invalid)
                reader.assert_not_called()
        with mock.patch.object(TOOL, "read", side_effect=FileNotFoundError) as reader:
            with self.assertRaises(FileNotFoundError): TOOL.source_build_selection("x86_64-apple-darwin")
            reader.assert_called_once_with(TOOL.DESKTOP / "macos-installed-inputs/build-release-intel.json", TOOL.BUILD_RELEASE_LIMIT)

    def test_manifest_digest_and_original_roster_are_separate_checks(self):
        files = [{"path": name, "sha256": "1" * 64, "size": 1} for name in sorted(TOOL.BOOTSTRAPS | {"core.zip", "github-ca.pem", "python/bin/python3"})]
        manifest = {"schemaVersion": 1, "protocol": 1, "coreVersion": "DATA-only", "target": "aarch64-apple-darwin",
                    "coreSha256": "1" * 64, "protocolSha256": TOOL.PROTOCOL,
                    "inventorySha256": TOOL.digest(TOOL.canonical(files)), "files": files}
        encoded = TOOL.canonical(manifest) + b"\n"
        value, rows = TOOL.manifest_files(encoded, TOOL.digest(encoded))
        self.assertEqual(set(rows), {row["path"] for row in files})
        self.assertNotIn("project_recovery_bootstrap.py", rows)  # Historical supplier roster is unchanged.
        current_only = {"project_recovery_bootstrap.py", "github_preflight_bootstrap.py",
                        "ios_archive_bootstrap.py", "github_release_bootstrap.py"}
        self.assertEqual(TOOL.CURRENT_BOOTSTRAPS, TOOL.BOOTSTRAPS | current_only)
        self.assertEqual(len(TOOL.BOOTSTRAPS), 6)
        self.assertEqual(TOOL.PROTOCOL, "860d1cee0072730a487ac8e632206c69e3ba676cab849b144a61755c4b84e41e")
        checkout = Path(__file__).absolute().parents[2]
        self.assertEqual(TOOL.CURRENT_PROTOCOL, TOOL.digest((checkout / "src/mobile_release/_desktop_engine.py").read_bytes()))
        self.assertIn('pub const PROTOCOL_SHA: &str = "' + TOOL.CURRENT_PROTOCOL + '";',
                      (checkout / "desktop/src-tauri/src/macos_install_paths.rs").read_text())
        self.assertNotEqual(TOOL.PROTOCOL, TOOL.CURRENT_PROTOCOL)
        with self.assertRaisesRegex(TOOL.Refused, "runtime-manifest-shape"):
            TOOL.manifest_files(encoded, TOOL.digest(encoded), current=True)
        for invalid in (None, 0, 1, "current"):
            with self.assertRaisesRegex(TOOL.Refused, "runtime-manifest-profile"):
                TOOL.manifest_files(encoded, TOOL.digest(encoded), current=invalid)
        current_files = sorted([*files, *({"path": name, "sha256": "1" * 64, "size": 1}
                                         for name in current_only)], key=lambda row: row["path"])
        current_manifest = {**manifest, "protocolSha256": TOOL.CURRENT_PROTOCOL,
                            "files": current_files, "inventorySha256": TOOL.digest(TOOL.canonical(current_files))}
        current_body = TOOL.canonical(current_manifest) + b"\n"
        self.assertEqual(set(TOOL.manifest_files(current_body, TOOL.digest(current_body), current=True)[1]),
                         TOOL.CURRENT_BOOTSTRAPS | {"core.zip", "github-ca.pem", "python/bin/python3"})
        with self.assertRaisesRegex(TOOL.Refused, "runtime-manifest-shape"):
            TOOL.manifest_files(current_body, TOOL.digest(current_body))
        for missing in current_only:
            incomplete = [row for row in current_files if row["path"] != missing]
            body = TOOL.canonical({**current_manifest, "files": incomplete,
                                   "inventorySha256": TOOL.digest(TOOL.canonical(incomplete))})
            with self.assertRaisesRegex(TOOL.Refused, "runtime-required-members"):
                TOOL.manifest_files(body, TOOL.digest(body), current=True)
        with self.assertRaises(TOOL.Refused):
            TOOL.manifest_files(encoded, "0" * 64)
        manifest["files"] = list(reversed(files))
        manifest["inventorySha256"] = TOOL.digest(TOOL.canonical(manifest["files"]))
        encoded = TOOL.canonical(manifest)
        with self.assertRaises(TOOL.Refused):
            TOOL.manifest_files(encoded, TOOL.digest(encoded))

        for target, other in (("aarch64-apple-darwin", "x86_64-apple-darwin"), ("x86_64-apple-darwin", "aarch64-apple-darwin")):
            body = TOOL.canonical(dict(current_manifest, target=target))
            with self.subTest(target=target):
                selected, _ = TOOL.manifest_files(body, TOOL.digest(body), current=True, target=target)
                self.assertEqual(selected["target"], target)
                with self.assertRaisesRegex(TOOL.Refused, "runtime-manifest-shape"):
                    TOOL.manifest_files(body, TOOL.digest(body), current=True, target=other)
        with self.assertRaisesRegex(TOOL.Refused, "unqualified-intel-route"):
            TOOL.manifest_files(current_body, TOOL.digest(current_body), target="x86_64-apple-darwin")

    def test_scripts_cpio_is_root_owned_exact_data_not_extracted(self):
        end = odc("TRAILER!!!", 0)
        body = odc(".", stat.S_IFDIR | 0o755) + odc("./input", stat.S_IFDIR | 0o555)
        body += odc("./input/manifest.json", stat.S_IFREG | 0o444, b"{}") + end
        self.assertEqual(TOOL.cpio_members(body), {"input": (None, 0o555), "input/manifest.json": (b"{}", 0o444)})
        bad = [odc("x", stat.S_IFREG | 0o444, b"x", uid=501), odc("x", stat.S_IFREG | 0o444, b"x", links=2),
               odc("x", stat.S_IFLNK | 0o777, b"target"), odc("../x", stat.S_IFREG | 0o444), odc("x", stat.S_IFREG | 0o644)]
        for entry in bad:
            with self.assertRaises(TOOL.Refused):
                TOOL.cpio_members(odc(".", stat.S_IFDIR | 0o755) + entry + end)
        with self.assertRaises(TOOL.Refused):
            TOOL.cpio_members(odc(".", stat.S_IFDIR | 0o755) + odc("x", stat.S_IFREG | 0o444) * 2 + end)

    def test_scripts_root_is_exact_unique_and_owner_bound(self):
        for root in (".", "./"):
            files, members = package_data(root=root)
            self.assertEqual(TOOL.cpio_members(members["Scripts"]), {**files, "input": (None, 0o555)})
        end = odc("TRAILER!!!", 0)
        root = odc(".", stat.S_IFDIR | 0o755)
        bad = [end, root + odc("./", stat.S_IFDIR | 0o755) + end,
               odc(".", stat.S_IFDIR | 0o755, uid=501) + end,
               odc("./", stat.S_IFDIR | 0o755, gid=20) + end,
               odc(".", stat.S_IFDIR | 0o555) + end,
               odc(".", stat.S_IFDIR | 0o755, b"x") + end,
               odc(".", stat.S_IFREG | 0o755) + end]
        bad.extend(root + odc(name, stat.S_IFDIR | 0o555) + end for name in ("", "././", "/", "../x", "./input/", "./input/../x"))
        for archive in bad:
            with self.subTest(archive=archive[:6]), self.assertRaises(TOOL.Refused):
                TOOL.cpio_members(archive)

    def test_original_package_preparation_cannot_substitute_for_root_audit(self):
        files, members = package_data(uid=501, gid=20)
        info = SimpleNamespace(st_uid=501, st_gid=20)
        with (mock.patch.object(TOOL, "packager_ids", return_value=(501, 20)),
              mock.patch.object(TOOL, "tree", return_value=files) as scan,
              mock.patch.object(TOOL, "parent") as parent,
              mock.patch.object(TOOL, "read_at", return_value=(b"original-package", info)),
              mock.patch.object(TOOL, "xar_members", return_value=members) as read_members):
            parent.return_value.__enter__.return_value = (9, "original.pkg")
            result = TOOL.original_package(Path("/scripts"), Path("/original.pkg"))
            self.assertEqual(result, (files, b"original-package", members, TOOL.PACKAGE_ID, (501, 20)))
            scan.assert_called_once_with(Path("/scripts"), packager=True)
            with self.assertRaises(TOOL.Refused):
                TOOL.cpio_members(members["Scripts"])
            wrong_archives = [package_data(uid=0, gid=0)[1]["Scripts"],
                              package_data(uid=501, gid=21)[1]["Scripts"],
                              package_data(uid=501, gid=20, file_owner=(502, 20))[1]["Scripts"],
                              members["Scripts"].replace(b"DATA\n", b"DIFF\n"),
                              members["Scripts"].replace(b"./input/readonly.txt", b"./input/anotherx.txt")]
            for archive in wrong_archives:
                read_members.return_value = {**members, "Scripts": archive}
                with self.assertRaises(TOOL.Refused):
                    TOOL.original_package(Path("/scripts"), Path("/original.pkg"))
            read_members.return_value = {**members, "Bom": b"extra"}
            with self.assertRaises(TOOL.Refused):
                TOOL.original_package(Path("/scripts"), Path("/original.pkg"))
            read_members.return_value = members
            info.st_uid = 0
            with self.assertRaises(TOOL.Refused):
                TOOL.original_package(Path("/scripts"), Path("/original.pkg"))

    def test_package_commands_preserve_original_bytes_and_require_final_root_audit(self):
        files, original_members = package_data(uid=501, gid=20)
        final_members = package_data()[1]
        args = SimpleNamespace(scripts=Path("/scripts"), package=Path("/final.pkg"), original_package=Path("/original.pkg"),
                               output=Path("/fresh-parts"), fixture=False)
        with (mock.patch.object(TOOL, "original_package", return_value=(files, b"original", original_members, TOOL.PACKAGE_ID, (501, 20))) as original,
              mock.patch.object(TOOL, "write_tree") as writer,
              mock.patch.object(TOOL, "read", return_value=b"final"),
              mock.patch.object(TOOL, "xar_members", return_value=final_members) as read_members):
            prepared = TOOL.prepare_package_command(args)
            writer.assert_called_once_with(Path("/fresh-parts"), {"PackageInfo": (original_members["PackageInfo"], 0o444)}, root_mode=0o700)
            self.assertEqual(prepared["qualification"], "caller-owned-original-prepared-not-root-audited-or-installed")
            audited = TOOL.audit_command(args)
            original.assert_called_with(Path("/scripts"), Path("/original.pkg"), fixture=False,
                                        selection=TOOL.source_build_selection(TOOL.ARM_TARGET))
            self.assertEqual(audited["originalPackageSha256"], TOOL.digest(b"original"))
            self.assertEqual(audited["packageInfoSha256"], TOOL.digest(original_members["PackageInfo"]))
            for mutation in (original_members, {**final_members, "PackageInfo": final_members["PackageInfo"] + b"\n"},
                             {**final_members, "Payload": b"extra"}, {"PackageInfo": final_members["PackageInfo"]},
                             {**final_members, "Scripts": final_members["Scripts"].replace(b"DATA\n", b"DIFF\n")}):
                read_members.return_value = mutation
                with self.assertRaises(TOOL.Refused):
                    TOOL.audit_command(args)
            writer.reset_mock()
            original.side_effect = TOOL.Refused("original-package-owner")
            with self.assertRaises(TOOL.Refused):
                TOOL.prepare_package_command(args)
            writer.assert_not_called()
            TOOL.package_format_input_command(args)
            call = writer.call_args
            self.assertEqual(call.args[0], Path("/fresh-parts"))
            self.assertEqual(call.kwargs, {"root_mode": 0o755})
            self.assertEqual(set(call.args[1]), {"input/readonly.txt", "postinstall"})
            self.assertEqual(call.args[1]["input/readonly.txt"][1], 0o444)
            self.assertEqual(call.args[1]["postinstall"][1], 0o555)
            self.assertTrue(call.args[1]["postinstall"][0].endswith(b"exit 97\n"))

        # Completed archive -> existing schema2: target/policy/source/actual
        # package are independent inputs, not learned from installed records.
        package, signed = b"completed DATA only", b"raw signature DATA, not cryptographic evidence"
        for target in TOOL.MAC_TARGETS:
            profile, service, selection, history, expected = packaging_fixture(target, package=package)
            source = TOOL.packaging_signing_data(profile, service)
            def assemble(document):
                return TOOL.packaging_descriptor_data(TOOL.canonical(document), source, selection,
                    source_commit="a" * 40, manifest="c" * 64, inventory="d" * 64, package=TOOL.digest(package))
            descriptor = assemble(history)
            self.assertEqual(TOOL.decode(descriptor), expected)
            self.assertEqual(TOOL.maintenance_producer_data(descriptor, target=target), expected)
            predecessor = dict(expected["releaseSet"]["current"], packageVersion="0.1.1",
                release=selection.release.replace("-02", "-01"), sourceCommit="b" * 40, packageSha256="e" * 64)
            historical = copy.deepcopy(history)
            historical["targets"][target]["acceptedPredecessors"] = [predecessor]
            historical["targets"][target]["signingPolicies"] = expected["signingPolicies"]
            old = TOOL.decode(assemble(historical))
            self.assertEqual(old["releaseSet"]["acceptedPredecessors"], [predecessor])
            self.assertEqual(len(old["signingPolicies"]), 1)  # No duplicate current policy.
            for mutation in ("unknown-target", "target-swap", "newer-history", "duplicate-release", "policy-digest", "unused-policy", "extra", "too-many"):
                changed = copy.deepcopy(historical)
                row = changed["targets"][target]
                if mutation == "unknown-target": changed["targets"]["unknown"] = row
                elif mutation == "target-swap": row["acceptedPredecessors"][0]["profile"] = "foreign-profile"
                elif mutation == "newer-history": row["acceptedPredecessors"][0]["packageVersion"] = "0.3.0"
                elif mutation == "duplicate-release": row["acceptedPredecessors"][0]["release"] = selection.release
                elif mutation == "policy-digest": row["signingPolicies"][0]["sha256"] = "f" * 64
                elif mutation == "unused-policy": row["signingPolicies"].append({"sha256": "f" * 64, "policy": row["signingPolicies"][0]["policy"]})
                elif mutation == "extra": row["unreviewed"] = []
                else: row["acceptedPredecessors"] *= 9
                with self.subTest(target=target, mutation=mutation), self.assertRaises(TOOL.Refused):
                    assemble(changed)
            summary = {"schemaVersion": 1, "kind": "mrk-package-producer-emitted", "packageSha256": TOOL.digest(package),
                "descriptorSha256": TOOL.digest(descriptor), "signatureSha256": TOOL.digest(signed),
                "descriptorBytes": len(descriptor), "signatureBytes": len(signed)}
            emitted = TOOL.canonical(summary) + b"\n"
            self.assertEqual(TOOL.emitted_package_data(emitted, b"", 0, package, descriptor, signed, target=target), summary)
            for output, error, status, archive, desc, signature in (
                (emitted, b"", 1, package, descriptor, signed), (emitted, b"", None, package, descriptor, signed),
                (emitted, b"unexpected", 0, package, descriptor, signed), (emitted[:-1], b"", 0, package, descriptor, signed),
                (emitted, b"", 0, package + b"changed", descriptor, signed),
                (emitted, b"", 0, package, descriptor + b"\n", signed), (emitted, b"", 0, package, descriptor, signed[:-1]),
                (TOOL.canonical(dict(summary, signatureBytes=True)) + b"\n", b"", 0, package, descriptor, signed),
                (TOOL.canonical(dict(summary, extra=True)) + b"\n", b"", 0, package, descriptor, signed)):
                with self.subTest(target=target, status=status, bytes=len(output)), self.assertRaises(TOOL.Refused):
                    TOOL.emitted_package_data(output, error, status, archive, desc, signature, target=target)
        expected = {"Install.pkg": package, "producer.json": descriptor, "producer.sig": signed}
        for name in ("Install.pkg", TOOL.distribution_request_name("1" * 32)):
            actual = {name if key == "Install.pkg" else key: (body, 0o444) for key, body in expected.items()}
            TOOL.distribution_layout_data(list(actual), name, expected, actual)
            for mutation in ("extra", "missing", "writable", "changed", "alias"):
                changed = dict(actual)
                if mutation == "extra": changed["other.pkg"] = (package, 0o444)
                elif mutation == "missing": del changed["producer.sig"]
                elif mutation == "writable": changed[name] = (package, 0o644)
                elif mutation == "changed": changed["producer.json"] = (descriptor + b"\n", 0o444)
                else: changed["Install.pkg" if name != "Install.pkg" else "alias.pkg"] = (package, 0o444)
                with self.subTest(mutation=mutation, name=name), self.assertRaises(TOOL.Refused):
                    TOOL.distribution_layout_data(list(changed), name, expected, changed)
        for request in (None, "", "0" * 32, "A" * 32, "1" * 31, "1" * 33, "../" + "1" * 32):
            with self.subTest(request=request), self.assertRaises(TOOL.Refused):
                TOOL.distribution_request_name(request)
        for invalid_name in ("MobileReleaseKit-Request-" + "0" * 32 + ".pkg", "../Install.pkg", "other.pkg"):
            actual = {invalid_name if key == "Install.pkg" else key: (body, 0o444) for key, body in expected.items()}
            with self.subTest(invalidName=invalid_name), self.assertRaises(TOOL.Refused):
                TOOL.distribution_layout_data(list(actual), invalid_name, expected, actual)
        mount = Path("/fixed/task/package-mount")
        row = {"dev-entry": "/dev/disk99s1", "potentially-mountable": True, "content-hint": "Apple_HFS", "mount-point": str(mount)}
        encoded = lambda rows: TOOL.plistlib.dumps({"system-entities": rows})
        self.assertEqual(TOOL.distribution_mount_data(encoded([row]), b"", 0, mount), "/dev/disk99s1")
        for output, status in ((encoded([row]), 1), (encoded([row]), True), (encoded([row, row]), 0), (encoded([]), 0),
            (encoded([dict(row, **{"mount-point": "/other"})]), 0), (encoded([dict(row, **{"dev-entry": "/dev/../disk99"})]), 0),
            (encoded([dict(row, **{"potentially-mountable": False})]), 0), (encoded([dict(row, private="no")]), 0),
            (b"not a plist", 0), (b"x" * 65537, 0), (b"<!ENTITY x 'unsafe'>", 0), (b"\x00", 0)):
            with self.subTest(status=status, bytes=len(output)), self.assertRaises(TOOL.Refused):
                TOOL.distribution_mount_data(output, b"", status, mount)

    def test_package_workflow_fails_fast_and_gates_every_installer(self):
        # I intentionally has no Aqua workflow: that separately-based source
        # delta is independently composed/reviewed, not fictitiously exercised.
        path = Path(__file__).absolute().parents[2] / ".github/workflows/desktop-macos-installed.yml"
        workflow = path.read_text(encoding="utf-8")
        probe = workflow.index("- name: Fail fast on native Scripts ownership and package format")
        sdk = workflow.index("- name: Fail fast on the selected SDK actual no-ACL and ACE-refusal primitive")
        self.assertLess(probe, sdk)
        self.assertLess(sdk, workflow.index("cargo build --locked --release"))
        self.assertNotIn("/usr/sbin/installer", workflow[probe:sdk])
        for label, scripts, basename in (("package-format", "package-format-scripts", "PackageFormat"),
                                         ("package-fixture", "scripts-fixture", "MobileReleaseKit-InstallerFixture"),
                                         ("package", "scripts", "MobileReleaseKit")):
            start = workflow.index('/usr/bin/pkgbuild --nopayload --scripts "$MRK_MACOS_WORK/' + scripts + '"')
            audit = (workflow.index('macos_android_helper_package.py package-install', start) if label == "package" else
                     workflow.index('> "$MRK_MACOS_WORK/' + label + '-audit.json"', start))
            block = workflow[start:audit]
            self.assertIn('cd "$MRK_MACOS_WORK/' + scripts + '" || exit', block)
            target = '"$MRK_MACOS_WORK/' + label + '-parts/Scripts"'
            guard = '[[ ! -e ' + target + ' && ! -L ' + target + ' ]]'
            command = '/usr/bin/tar -c -z -f ' + target + ' --format=odc --uid=0 --gid=0'
            self.assertIn(guard, block)
            self.assertIn(command, block)
            self.assertLess(block.index(guard), block.index(command))
            self.assertNotIn('/usr/bin/tar -c -z -f - ', block)
            self.assertIn('--no-acls --no-xattrs --no-fflags --no-mac-metadata .', block)
            self.assertNotIn(') > ' + target, block)
            self.assertIn('/bin/mkdir -m 700 "$MRK_MACOS_WORK/' + label + '-final"', block)
            self.assertIn('cd "$MRK_MACOS_WORK/' + label + '-parts" || exit', block)
            final = '$MRK_MACOS_WORK/' + label + '-final/' + basename + '.pkg'
            self.assertIn('/usr/bin/xar -c -f "' + final + '"', block)
            self.assertIn('--compression=none PackageInfo Scripts', block)
            self.assertEqual(block.count('/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC COPYFILE_DISABLE=1'), 2)
            self.assertIn('[[ $tar_status == 0 ]]', block)
            self.assertIn('[[ $xar_status == 0 ]]', block)
            if label == "package":
                self.assertIn('--version "$MRK_MACOS_SOURCE_PACKAGE_VERSION"', block)
                helper = (path.parents[2] / "desktop/tools/macos_android_helper_package.py").read_text()
                self.assertIn('original_package=self.work / "MobileReleaseKit-original.pkg"', helper)
                parsed = ast.parse(helper)
                operation = next(node for node in parsed.body if isinstance(node, ast.ClassDef) and node.name == "Operation")
                methods = {node.name: ast.get_source_segment(helper, node) for node in operation.body if isinstance(node, ast.FunctionDef)}
                package = methods["package_install"]
                self.assertLess(package.index('audit = self.package_stager_io("final-audit",'),
                                package.index('self.package_call("installer",'))
                self.assertIn('if operation == "final-audit":\n                result = self.stager.audit_command(args)',
                              methods["package_stager_io"])
            else:
                self.assertIn('--original-package "$MRK_MACOS_WORK/' + basename + '-original.pkg"', block)
            self.assertNotIn('sudo', block)
            if label == "package-fixture":
                self.assertLess(audit, workflow.index('/usr/sbin/installer -pkg "' + final + '"'))

    def test_package_refusals_are_closed_literals_without_exception_reflection(self):
        class NoReflection:
            def __str__(self):
                raise AssertionError("arbitrary value must not be reflected")
        for reason, literal in TOOL.PACKAGE_REFUSALS.items():
            self.assertTrue(literal.isascii())
            self.assertLessEqual(len(literal), 128)
            self.assertEqual(TOOL.package_refusal_message(TOOL.Refused(reason)), literal + "\n" + TOOL.GENERIC_REFUSAL)
        for error in (TOOL.Refused(), TOOL.Refused("/private/credential=value"), TOOL.Refused(NoReflection()),
                      TOOL.Refused("scripts-root-owner-mode", "/private/extra"), ValueError("scripts-root-owner-mode")):
            self.assertEqual(TOOL.package_refusal_message(error), TOOL.GENERIC_REFUSAL)
        for reason, expected in (("output-mode", "MRK_MACOS_PACKAGE_REFUSED=output-mode\n" + TOOL.GENERIC_REFUSAL),
                                 ("/private/credential=value", TOOL.GENERIC_REFUSAL)):
            stderr = io.StringIO()
            with self.subTest(reason=reason), mock.patch.object(TOOL, "app_command", side_effect=TOOL.Refused(reason)) as action, \
                    contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as stopped:
                TOOL.main(["app", "--binary", "/inert/app", "--entry-binary", "/inert/entry",
                           "--expected-entry", "b" * 64, "--vault-helper", "/inert/helper",
                           "--expected-vault-helper", "a" * 64, "--output", "/inert/output",
                           "--bundletool-archive", "/inert/bundletool", "--aapt2-archive", "/inert/aapt2"])
            action.assert_called_once()
            args = action.call_args.args[0]
            self.assertEqual((args.entry_binary, args.expected_entry), (Path("/inert/entry"), "b" * 64))
            self.assertEqual(stopped.exception.code, 1)
            self.assertEqual(stderr.getvalue(), expected + "\n")

    def test_postinstall_accepts_only_fixed_entry_and_preserves_exec_boundary(self):
        root = Path(__file__).absolute().parents[2]
        stub = (root / "desktop/macos-installed-inputs/postinstall").read_text(encoding="utf-8")
        self.assertTrue(stub.startswith("#!/bin/sh\n"))
        self.assertIn('if [ "${3:-}" != / ]; then', stub)
        self.assertIn('./postinstall)\n        scripts=.', stub)
        self.assertIn('/*/postinstall)\n        scripts=${0%/*}', stub)
        self.assertIn('if ! cd -P "$scripts" 2>/dev/null; then', stub)
        # Exact shell grammar refuses missing/empty/relative first arguments;
        # quoted forwarding preserves spaces without interpreting another field.
        package_guard = 'case "${1:-}" in\n    /*) ;;\n    *) exit 1 ;;\nesac\n'
        self.assertIn(package_guard, stub)
        self.assertLess(stub.index(package_guard), stub.index('case "$0" in'))
        self.assertTrue(stub.endswith('exec ./mrk-macos-install "$PWD/input" "$1"\n'))
        self.assertEqual(stub.count('"$1"'), 1)
        self.assertEqual(stub.count("\nexec "), 1)
        phases = {"entry", "target-ok", "relative-entry", "absolute-entry", "cwd-ok", "pre-exec"}
        refusals = {"target", "entry", "cwd"}
        markers = TOOL.re.findall(r"'(MRK_MACOS_POSTINSTALL_[A-Z]+=[a-z-]+)'", stub)
        self.assertEqual(set(markers), {"MRK_MACOS_POSTINSTALL_PHASE=" + value for value in phases}
                         | {"MRK_MACOS_POSTINSTALL_REFUSED=" + value for value in refusals})
        self.assertEqual(len(markers), len(phases) + len(refusals))
        self.assertLess(stub.index("MRK_MACOS_POSTINSTALL_REFUSED=target"), stub.index("MRK_MACOS_POSTINSTALL_PHASE=target-ok"))
        self.assertLess(stub.index("MRK_MACOS_POSTINSTALL_REFUSED=cwd"), stub.index("MRK_MACOS_POSTINSTALL_PHASE=pre-exec"))
        for forbidden in ("PATH=", "eval ", "sh -c", "sudo ", 'printf "$', "post-exec", "../postinstall)", "    postinstall)", "PACKAGE_PATH", '"$@"'):
            self.assertNotIn(forbidden, stub)
        source = (root / "desktop/src-tauri/src/bin/macos_install.rs").read_text(encoding="utf-8")
        ordinary = source.split("fn entry_kind_data(args: &[String])", 1)[1].split("fn completed_entry(", 1)[0]
        self.assertIn("[_,source,completed] if source.starts_with('/') && completed.starts_with('/') => Ok(EntryKind::CompletedPackage)", ordinary)
        self.assertIn('_ => Err("fixed-completed-package-input-required")', ordinary)
        self.assertIn("let started = match monotonic()", ordinary)
        self.assertIn("completed_entry(&args[1],&args[2],started)", ordinary)
        fixture = source.split("mod fixture {", 1)[1]
        self.assertIn("check(args.len() == 3 && args[2].starts_with('/') && source_bound && table,", fixture)
        self.assertEqual(fixture.count("args[2]"), 1)  # No path open/read or fixture authority.
        self.assertIn("let _ = setup.input(&args[1])?", fixture)
        self.assertIn("for case in CASES {", fixture)

    def test_installer_log_cursor_identity_binding_and_append_boundaries(self):
        binding = TOOL.installer_log_binding(log_args())
        tail, body = b"old log text\n", b"one new line\n"
        identity = TOOL.installer_log_identity(log_info())
        cursor = TOOL.make_log_cursor(binding, identity, len(tail), tail, 0)
        self.assertEqual(TOOL.validate_log_cursor(cursor, binding), cursor)
        self.assertNotIn("old log text", TOOL.canonical(cursor).decode())
        self.assertEqual(cursor["precedingTailSha256"], TOOL.digest(tail))
        self.assertEqual(TOOL.make_log_cursor(binding, identity, 0, b"", 0)["precedingTailBytes"], 0)
        end = len(tail) + len(body)
        TOOL.validate_log_window(cursor, identity, end, tail, body)
        with mock.patch.object(TOOL, "os", mock.Mock(wraps=TOOL.os)) as api:
            api.fstat.return_value = log_info(end + 3)
            api.stat.return_value = log_info(end + 5)
            self.assertEqual(TOOL.log_growth(9, 8, "install.log", identity, end), 5)
        for changed in ({**cursor, "schemaVersion": True}, {**cursor, "offsetBytes": True}, {**cursor, "precedingTailBytes": 0},
                        {**cursor, "growthBeyondSnapshotBytes": True}, {**cursor, "logPath": "/var/log/install.log"},
                        {**cursor, "extra": 1}, {**cursor, "binding": {**binding, "runAttempt": "2"}}):
            with self.assertRaises(TOOL.Refused):
                TOOL.validate_log_cursor(changed, binding)
        for key, value in (("device", 2), ("inode", 43), ("mode", stat.S_IFREG | 0o600), ("uid", 501), ("gid", 20), ("links", 2)):
            with self.subTest(identity=key), self.assertRaises(TOOL.Refused):
                TOOL.validate_log_window(cursor, {**identity, key: value}, end, tail, body)
        for changes in ({"st_uid": 501}, {"st_nlink": 2}, {"st_mode": stat.S_IFREG | 0o666}, {"st_mode": stat.S_IFLNK | 0o777}):
            with self.assertRaises(TOOL.Refused):
                TOOL.installer_log_identity(log_info(**changes))
        for observed_end, anchor, interval in ((len(tail) - 1, tail, b""), (end, b"changed text\n", body),
                                               (end, tail, body[:-1]), (end - 1, tail, body[:-1]),
                                               (len(tail) + TOOL.LOG_INTERVAL_BYTES + 1, tail, b"")):
            with self.assertRaises(TOOL.Refused):
                TOOL.validate_log_window(cursor, identity, observed_end, anchor, interval)
        with self.assertRaises(TOOL.Refused):
            TOOL.make_log_cursor(binding, identity, 7, b"partial", 0)
        for args in (log_args(fixture=True), log_args()):
            args.package = Path("/work/package-final/another.pkg")
            with self.assertRaises(TOOL.Refused):
                TOOL.installer_log_binding(args)


        for request in (None, "", "0" * 32, "2" * 32):
            args = log_args()
            args.request_id = request
            with self.subTest(request=request), self.assertRaises(TOOL.Refused):
                TOOL.installer_log_binding(args)
        args = log_args(fixture=True); args.request_id = "1" * 32
        with self.assertRaises(TOOL.Refused): TOOL.installer_log_binding(args)

    def test_installer_log_selection_is_bounded_raw_and_never_result_authority(self):
        binding = TOOL.installer_log_binding(log_args())
        result_line = b'PackageKit: MRK_MACOS_INSTALL_RESULT={"not":"acceptance"}\n'
        lines = [b"unrelated private neighboring text\n", b"dev.mobile-release-kit.desktop.installed-fixture-suffix\n",
                 b"prefixMRK_MACOS_INSTALL_RESULT={}\n", b"mrk-macos-install-helper\n",
                 ("PackageKit: " + binding["packagePath"] + "\n").encode("ascii"), b"MRK_MACOS_POSTINSTALL_PHASE=relative-entry\r\n",
                 b"./mrk-macos-install: original loader bytes \xff\n", result_line]
        selected, detail = TOOL.select_installer_log(b"".join(lines), binding)
        self.assertEqual(selected, b"".join(lines[4:]))
        self.assertEqual(detail["linesUnselected"], 4)
        self.assertEqual(detail["resultMarkerState"], "unbound")
        self.assertEqual(detail["selectedLines"][0]["relativeOffsetBytes"], len(b"".join(lines[:4])))
        self.assertEqual(detail["selectedLines"][-1]["sha256"], TOOL.digest(result_line))
        self.assertNotIn("private neighboring", TOOL.canonical(detail).decode())
        opposite = b"MRK_MACOS_INSTALL_FIXTURE_RESULT={}\n"
        raw, mixed = TOOL.select_installer_log(result_line + opposite, binding)
        self.assertEqual(raw, result_line + opposite)
        self.assertEqual(mixed["resultMarkerState"], "mixed")
        self.assertEqual(TOOL.select_installer_log(result_line * 2, binding)[1]["resultMarkerState"], "duplicate")
        self.assertEqual(TOOL.select_installer_log(lines[4], binding)[1]["resultMarkerState"], "missing")
        header = b"mrk-macos-install "
        limit_line = header + b"x" * (TOOL.LOG_LINE_BYTES - len(header) - 1) + b"\n"
        for bad in (b"", b"unrelated\n", b"MRK_MACOS_POSTINSTALL_PHASE=unknown-value\n", result_line[:-1],
                    b"x" * (TOOL.LOG_INTERVAL_BYTES + 1), limit_line[:-1] + b"x\n", limit_line * 3):
            with self.assertRaises(TOOL.Refused):
                TOOL.select_installer_log(bad, binding)

    def test_acl_failure_diagnostic_is_finite_and_cannot_be_a_result(self):
        binding = TOOL.installer_log_binding(log_args())
        marker = b"MRK_MACOS_INSTALL_ACL_DIAGNOSTIC=role=input-directory;phase=acl-entry-present;result=1;call=0;errno=0;freeCall=0;freeErrno=0\n"
        selected, detail = TOOL.select_installer_log(b"PackageKit: " + marker, binding)
        self.assertEqual(selected, b"PackageKit: " + marker)
        self.assertEqual(detail["markerCounts"]["acl-diagnostic"], 1)
        self.assertEqual(detail["resultMarkerState"], "missing")
        self.assertEqual(detail["markerCounts"]["ordinary-result"], 0)
        with self.assertRaises(TOOL.Refused):
            TOOL.installer_record(selected)
        for bad in (b"prefix" + marker, marker.replace(b"input-directory", b"arbitrary-path"),
                    marker.replace(b"acl-entry-present", b"unknown-api"), marker.replace(b"errno=0;", b"errno=private;"),
                    marker.replace(b"result=1;", b"result=123456789012;"), marker[:-1] + b";extra=private\n"):
            with self.subTest(marker=bad), self.assertRaises(TOOL.Refused):
                TOOL.select_installer_log(bad, binding)
        native = (Path(__file__).absolute().parents[2] / "desktop/native/macos-installed-native/src/lib.rs").read_text(encoding="utf-8")
        installer = (Path(__file__).absolute().parents[2] / "desktop/src-tauri/src/bin/macos_install.rs").read_text(encoding="utf-8")
        phases = TOOL.re.findall(r'\d+ => "([a-z-]+)"', native.split("let name = match phase {", 1)[1].split("};", 1)[0]) + ["ffi-output"]
        roles = TOOL.re.findall(r'=> "([a-z-]+)"', installer.split("impl AclRole {", 1)[1].split("fn acl_diagnostic", 1)[0])
        for role in roles:
            for phase in phases:
                row = marker.replace(b"input-directory", role.encode()).replace(b"acl-entry-present", phase.encode())
                self.assertLessEqual(len(row), 512)
                self.assertEqual(TOOL.select_installer_log(row, binding)[1]["markerCounts"]["acl-diagnostic"], 1)
        self.assertEqual((len(roles), len(phases)), (6, 13))
        self.assertIn("if line.len() <= 512", installer)
        self.assertIn("let _ = std::io::Write::write_all", installer)

    def test_acl_probe_gate_is_early_nonroot_and_keeps_original_statuses(self):
        root = Path(__file__).absolute().parents[2]
        workflow = (root / ".github/workflows/desktop-macos-installed.yml").read_text(encoding="utf-8")
        marker = "      - name: Fail fast on the selected SDK actual no-ACL and ACE-refusal primitive"
        gate = workflow_step(workflow, "Fail fast on the selected SDK actual no-ACL and ACE-refusal primitive")
        self.assertLess(workflow.index(marker), workflow.index("      - name: Build the ordinary ARM64 desktop image and embedded frontend"))
        self.assertIn("desktop/native/macos-installed-native/src/native.m desktop/native/macos-installed-native/tests/acl_probe.m", gate)
        self.assertIn('/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC "$MRK_MACOS_WORK/acl-probe"', gate)
        self.assertIn('[[ "$(/usr/bin/id -u)" != 0', gate)
        self.assertEqual(gate.count('=("${PIPESTATUS[@]}")'), 2)
        self.assertIn('if [[ ${probe_status[0]} != 0 ]]; then exit "${probe_status[0]}"; fi', gate)
        self.assertIn('compile_status_saved=$?', gate)
        self.assertLess(gate.index('if [[ ${compile_status[0]} != 0 ]]; then exit "${compile_status[0]}"; fi'),
                        gate.index('[[ ${compile_status[1]} == 0 && $compile_status_saved == 0 ]]'))
        self.assertIn("binary_identity=$(/usr/bin/stat -f '%d:%i:%u:%g:%p:%l:%z:%m:%c'", gate)
        self.assertIn("directory_identity=$(/usr/bin/stat -f '%d:%i:%u:%g:%p'", gate)
        self.assertLess(gate.index('== "$binary_identity"'), gate.index('/bin/rm -- "$MRK_MACOS_WORK/acl-probe"'))
        self.assertLess(gate.index('== "$directory_identity"'), gate.index('/bin/rmdir -- "$MRK_MACOS_WORK/acl-probe-data"'))
        self.assertLess(gate.index('> "$MRK_MACOS_WORK/native-acl-probe.status"'), gate.index('/bin/rm -- "$MRK_MACOS_WORK/acl-probe"'))
        self.assertIn('/bin/rmdir -- "$MRK_MACOS_WORK/acl-probe-data"', gate)
        self.assertEqual(gate.count("/usr/bin/tail -c 131072"), 2)
        self.assertNotIn("sudo", gate)
        self.assertNotIn("native-api-link.dylib", workflow)
        probe = (root / "desktop/native/macos-installed-native/tests/acl_probe.m").read_text(encoding="utf-8")
        for value in ("fresh-file-no-acl", "fresh-directory-no-acl", "explicit-empty-no-ace", "real-ace-refused", "invalid-fd-refused"):
            self.assertIn(value, probe)
        self.assertIn("completed == 6 && cleaned && timely()", probe)
        self.assertLess(probe.index("fflush(stdout)"), probe.index("return ok && timely() ? 0 : 1;"))

    def test_installer_log_failures_and_cli_never_manufacture_settlement(self):
        args = log_args()
        tail = b"before\n"
        @TOOL.contextlib.contextmanager
        def failed_close():
            yield 9, 8, "install.log", log_info(len(tail))
            raise TOOL.Refused("original-close-unknown")
        with (mock.patch.object(TOOL, "installer_log_file", side_effect=failed_close),
              mock.patch.object(TOOL, "positioned_log_read", return_value=tail),
              mock.patch.object(TOOL, "log_growth", return_value=0),
              mock.patch.object(TOOL, "write_log_selection") as writer):
            result, status = TOOL.installer_log_diagnostic(args)
            self.assertEqual((result["state"], result["reason"], status), ("unknown", "original-close-unknown", 1))
            writer.assert_not_called()
        with (mock.patch.object(TOOL, "installer_log_file", side_effect=PermissionError("private path must not be reflected")),
              mock.patch.object(TOOL, "write_log_selection") as writer):
            result, status = TOOL.installer_log_diagnostic(args)
            self.assertEqual((result["state"], status, result["selectedOutputState"]), ("unknown", 1, "not-created"))
            self.assertNotIn("private path", TOOL.canonical(result).decode())
            writer.assert_not_called()
        args = log_args("installer-log-capture")
        binding = TOOL.installer_log_binding(args)
        cursor = TOOL.make_log_cursor(binding, TOOL.installer_log_identity(log_info()), len(tail), tail, 0)
        encoded = TOOL.canonical(cursor) + b"\n"
        body = b"MRK_MACOS_INSTALL_RESULT={}\n"
        @TOOL.contextlib.contextmanager
        def log_file():
            yield 9, 8, "install.log", log_info(len(tail) + len(body))
        for write_error in (None, OSError("private exception text must not be reflected")):
            with (mock.patch.object(TOOL, "parent") as parent,
                  mock.patch.object(TOOL, "read_at", return_value=(encoded, log_info(st_uid=TOOL.os.getuid(), st_mode=stat.S_IFREG | 0o600))),
                  mock.patch.object(TOOL, "installer_log_file", side_effect=log_file),
                  mock.patch.object(TOOL, "positioned_log_read", side_effect=[tail, body, tail]),
                  mock.patch.object(TOOL, "log_growth", return_value=7),
                  mock.patch.object(TOOL, "write_log_selection", side_effect=write_error)):
                parent.return_value.__enter__.return_value = (8, "cursor.json")
                result, status = TOOL.installer_log_diagnostic(args)
                self.assertEqual(result["scriptOutputFinality"], "unestablished")
                self.assertEqual(result["authority"], TOOL.LOG_AUTHORITY)
                if write_error is None:
                    self.assertEqual(status, 0)
                    self.assertEqual(result["resultMarkerState"], "unbound")
                    self.assertEqual(result["growthBeyondSnapshotBytes"], 7)
                    self.assertEqual(result["intervalSha256"], TOOL.digest(body))
                    self.assertEqual(result["selectedData"]["sha256"], TOOL.digest(body))
                else:
                    self.assertEqual((status, result["state"], result["reason"]), (1, "unknown", "log-output-unavailable"))
                    self.assertEqual(result["selectedOutputState"], "write-or-close-unknown-preserve-original")
                    self.assertEqual(result["plannedSelectedData"]["sha256"], TOOL.digest(body))
                    self.assertNotIn("private exception", TOOL.canonical(result).decode())
        argv = ["installer-log-cursor", "--package", str(args.package), "--request-id", args.request_id,
                "--expected-source", args.expected_source, "--expected-inventory", args.expected_inventory,
                "--expected-manifest", args.expected_manifest, "--run-id", args.run_id, "--run-attempt", args.run_attempt]
        with (mock.patch.object(TOOL, "os", mock.Mock(wraps=TOOL.os)) as api,
              mock.patch.object(TOOL, "installer_log_diagnostic", return_value=({"state": "unknown"}, 1)) as diagnostic,
              mock.patch.object(TOOL, "print", create=True)):
            api.getuid.return_value = api.geteuid.return_value = 501
            self.assertEqual(TOOL.main(argv), 1)
            diagnostic.reset_mock()
            api.getuid.return_value = 0
            with self.assertRaises(TOOL.Refused):
                TOOL.main(argv)
            diagnostic.assert_not_called()

    def test_installer_workflows_preserve_original_status_and_separate_diagnostics(self):
        root = Path(__file__).absolute().parents[2] / ".github/workflows"
        paths = [root / "desktop-macos-installed.yml"]
        aqua = root / "desktop-macos-aqua.yml"
        if aqua.is_file():
            paths.append(aqua)  # A validates both; I does not pretend it includes A.
        for path in paths:
            workflow = path.read_text(encoding="utf-8")
            installer_name = ("Application installation uses only standard privileged Installer; app and Python stay nonroot"
                              if path.name == "desktop-macos-aqua.yml"
                              else "Standard Installer only is privileged; never execute the app or Python as root")
            names = []
            if path.name == "desktop-macos-installed.yml":
                names.insert(0, ("Standard Installer runs the one fixed fixture, never root libtest or a scenario selector", "installer-fixture"))
            for name, stem in names:
                block = workflow.split("      - name: " + name + "\n", 1)[1].split("      - name: ", 1)[0]
                self.assertIn("set -o noclobber", block)
                self.assertIn("umask 077", block)
                self.assertEqual(block.count("sudo -- /usr/sbin/installer -pkg "), 1)
                self.assertEqual(block.count("installer-log-cursor "), 1)
                self.assertEqual(block.count("installer-log-capture "), 1)
                self.assertEqual(block.count("check-installer-result-absent "), 1)
                precheck = block.split("check-installer-result-absent ", 1)[1].split("          set +e", 1)[0]
                self.assertEqual("--fixture" in precheck, stem == "installer-fixture")
                for option in ("--expected-source", "--expected-inventory", "--expected-manifest"):
                    self.assertIn(option, precheck)
                positions = [block.index(value) for value in (
                    "check-installer-result-absent ", "set +e", "installer-log-cursor ", "cursor_status=$?", "cursor_status_saved=$?",
                    "sudo -- /usr/sbin/installer -pkg ", "installer_status=$?", '"$installer_status" >',
                    "installer_status_saved=$?", "installer-log-capture ", "capture_status=$?", "capture_status_saved=$?",
                    "set -e\n", 'if [[ "$installer_status" != 0 ]]; then exit "$installer_status"; fi',
                    '[[ "$installer_status_saved" == 0 && "$cursor_status_saved" == 0 && "$capture_status_saved" == 0 ]]')]
                self.assertEqual(positions, sorted(positions))
                for filename in (stem + "-output.status", stem + "-log-cursor.json", stem + "-log-cursor.status",
                                 stem + "-log-capture.json", stem + "-log-capture.status", stem + "-log-selected.txt"):
                    self.assertIn('${{ steps.work.outputs.root }}/' + filename, workflow)
                self.assertIn('--installer-status "$MRK_MACOS_WORK/' + stem + '-output.status"', workflow)
                self.assertNotIn("--installer-output", workflow)
                self.assertNotIn("ulimit", block)
                self.assertNotIn('[[ "$capture_status" == 0 ]]', block)
                self.assertNotIn('--installer-output "$MRK_MACOS_WORK/' + stem + '-log-', workflow)
            owned = workflow_step(workflow, installer_name)
            self.assertEqual(owned.count("macos_android_helper_package.py package-install"), 1)
            sequence = [owned.index(value) for value in ("set +e", "macos_android_helper_package.py package-install",
                "package_status=$?", '"$package_status" >', "package_status_saved=$?", "set -e\n",
                'if [[ "$package_status" != 0 ]]', '[[ "$package_status_saved" == 0 ]]')]
            self.assertEqual(sequence, sorted(sequence))
            for forbidden in ("sudo ", "/usr/sbin/installer ", "observe-installation", "--force", "|| true", "ulimit"):
                self.assertNotIn(forbidden, owned)
            self.assertIn("timeout-minutes: 18", owned)
            for filename in ("package-install.status", "android-helper-package-install.json", "package-request-id.txt",
                             "producer-root/producer.json", "producer-root/producer.sig", "distribution/MobileReleaseKit.dmg"):
                self.assertIn('${{ steps.work.outputs.root }}/' + filename, workflow)
        helper = (root.parent.parent / "desktop/tools/macos_android_helper_package.py").read_text()
        parsed = ast.parse(helper)
        operation = next(node for node in parsed.body if isinstance(node, ast.ClassDef) and node.name == "Operation")
        methods = {node.name: ast.get_source_segment(helper, node) for node in operation.body if isinstance(node, ast.FunctionDef)}
        original = methods["call"]
        self.assertLess(original.index("self.owner.run_owned("), original.index('self.publish("installer-output.status"'))
        self.assertLess(original.index('self.publish("installer-output.status"'), original.index('stdoutSha256=digest('))
        package = methods["package_install"]
        self.assertEqual(package.count('self.package_endpoint = self.package_started + 990_000_000_000'), 1)
        before = [package.index(value) for value in ('audit = self.package_stager_io("final-audit",', '"producer-emitter"',
            'self.package_call("distribution-attach",', 'self.package_stager_io("result-absence", args)',
            'self.package_diagnostic(args, capture=False)', 'self.package_call("installer",')]
        self.assertEqual(before, sorted(before))
        self.assertLess(package.index('self.package_call("installer",'), package.index('self.package_stager_io("v2-readback", args)'))
        self.assertLess(package.index('self.package_stager_io("v2-readback", args)'), package.index('self.detach_package_mount()'))
        self.assertIn('"/usr/bin/sudo", "-n", "--", "/usr/sbin/installer"', package)
        self.assertIn('if self.calls and self.calls[-1]["role"] == "installer" and self.package_settled():', package)

        # Entry is inside the SAME call after clock/reserve admission, not a
        # lexical flag earlier in package_install. Every actual capture closes
        # before capturesSettled, including a known nonzero original result.
        wrapper = methods["package_call"]
        positions = [wrapper.index(value) for value in ('need(self.package_settled()',
            'timeout = package_timeout_data(self.package_clock(), self.package_endpoint, timeout)', 'result = self.call(')]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(wrapper.index('result = self.call('), wrapper.rindex('self.package_clock()'))
        for role, field in (("distribution-attach", "mount_entered"), ("installer", "installer_entered")):
            entered = 'self.' + field + ' = True'
            self.assertNotIn(entered, package)
            self.assertEqual(original.count(entered), 1)
            self.assertLess(original.index('role == "' + role + '"'), original.index(entered))
            self.assertLess(original.index(entered), original.index('result = self.owner.run_owned('))
        self.assertLess(original.index('self.publish("installer-output.txt"'), original.index('record["capturesSettled"] = True'))
        self.assertLess(original.index('record["capturesSettled"] = True'), original.index('need(result.returncode == 0 or diagnostic'))
        settled = methods["package_settled"]
        self.assertIn('self.stager_io_pending is None and not self.errors', settled)
        self.assertIn('call["returned"] and call.get("capturesSettled") is True', settled)
        self.assertIn('entry["closed"] for entry in self.entries if entry["role"].startswith("output-")', settled)

        # All three direct stager methods retain their original argument and
        # fixed role. No exception/finally can clear the caller's pending latch.
        bridge = methods["package_stager_io"]
        self.assertIn('need(operation in ("final-audit", "result-absence", "v2-readback")', bridge)
        for predicate, callee in (('if operation == "final-audit":', 'audit_command'),
                                  ('elif operation == "result-absence":', 'installer_result_absent_command'),
                                  ('else:', 'observation_command')):
            self.assertIn(predicate + '\n                result = self.stager.' + callee + '(args)', bridge)
            self.assertEqual(bridge.count('self.stager.' + callee + '(args)'), 1)
        self.assertLess(bridge.index('need(self.package_settled()'), bridge.index('self.package_clock()'))
        self.assertLess(bridge.index('self.package_clock()'), bridge.index('self.stager_io_pending = operation'))
        self.assertLess(bridge.index('self.stager_io_pending = operation'), bridge.index('result = self.stager.audit_command(args)'))
        failed = bridge.split('except BaseException:', 1)[1].split('self.stager_io_pending = None', 1)[0]
        self.assertIn('"type": "CompletionUnknown"', failed)
        self.assertIn('raise', failed)
        self.assertEqual(bridge.count('self.stager_io_pending = None'), 1)
        bridge_node = next(node for node in operation.body if isinstance(node, ast.FunctionDef) and node.name == 'package_stager_io')
        self.assertFalse(next(node for node in bridge_node.body if isinstance(node, ast.Try)).finalbody)
        self.assertIn('self.stager_io_pending is None', methods['finish'])
        self.assertIn('call.get("capturesSettled") is True', methods['finish'])
        self.assertLess(methods['package_diagnostic'].index('need(self.package_settled()'),
                        methods['package_diagnostic'].index('self.package_call('))
        self.assertLess(methods['detach_package_mount'].index('need(self.package_settled()'),
                        methods['detach_package_mount'].index('self.recheck_mount()'))
        self.assertIn('not self.installer_entered or self.installer_zero and self.installation_readback', methods['detach_package_mount'])
        self.assertLess(methods['detach_package_mount'].index('self.close(entry)'), methods['detach_package_mount'].index('"/usr/bin/hdiutil", "detach"'))
        self.assertNotIn('"-force"', methods['detach_package_mount'])
        self.assertNotIn('"-kernel"', package)
        self.assertIn('flags & os.ST_RDONLY', methods['recheck_mount'])
        self.assertIn('self.mount_entered and not self.mount_detached', methods['finish'])
        self.assertIn('self.package_clock()  # Receipt write/readback/closes', methods['execute'])

    def test_installer_export_name_closed_wrapper_and_utf8_bound(self):
        source, inventory, manifest = "a" * 40, "b" * 64, "c" * 64
        for fixture in (False, True):
            document = export_document(fixture=fixture)
            body = TOOL.canonical(document) + b"\n"
            request_id = None if fixture else document["requestId"]
            scope = {"fixture": fixture, "request_id": request_id}
            path = TOOL.installer_result_path(source, inventory, manifest, **scope)
            self.assertEqual(path.parent, Path("/Library/Application Support"))
            self.assertEqual(path.name, f"MobileReleaseKit-InstallerResult-v1-fixture-{source}-{inventory}-{manifest}.json" if fixture
                             else f"MobileReleaseKit-InstallerResult-v2-{request_id}.json")
            self.assertLessEqual(len(path.name.encode("ascii")), 255)
            self.assertEqual(TOOL.installer_result_document(body, source, inventory, manifest, **scope), {} if fixture else document)
            changes = [("schemaVersion", True), ("kind", "other"), ("extra", True)]
            changes += ([("sourceCommit", "f" * 40), ("inventorySha256", "f" * 64), ("runtimeManifestSha256", "f" * 64),
                         ("transportState", "complete"), ("result", [])] if fixture else
                        [("requestId", "f" * 32), ("invocation", request_id), ("invocation", "0" * 32), ("resultName", "latest.json"),
                         ("resultFinality", "complete"), ("parentFinality", "complete"), ("retainedGate", "closed"),
                         ("historicalOuterExit", "verified"), ("originalWriterJoined", 1), ("writerExit", False), ("writerExit", 1),
                         ("writerState", "inverse-recorded"), ("action", "uninstall"), ("payloadWriteCount", True),
                         ("payloadWriteBytes", 0), ("payloadWriteBytes", TOOL.MAX_BYTES + 1), ("stateSha256", "0" * 64)])
            for key, value in changes:
                with self.subTest(key=key, fixture=fixture), self.assertRaises(TOOL.Refused):
                    TOOL.installer_result_document(TOOL.canonical({**document, key: value}) + b"\n", source, inventory, manifest, **scope)
            for key in document:
                bad = dict(document); del bad[key]
                with self.subTest(missing=key, fixture=fixture), self.assertRaises(TOOL.Refused):
                    TOOL.installer_result_document(TOOL.canonical(bad) + b"\n", source, inventory, manifest, **scope)
            schema = b'"schemaVersion":1' if fixture else b'"schemaVersion":2'
            value_field = b'"result":{}' if fixture else b'"writerExit":0'
            for bad in (body[:-1], b"x" * 65536 + b"\n", b"{}\n", b"[]\n", b"\xff\n",
                        body.decode("utf-8").encode("utf-16-be"), body.decode("utf-8").encode("utf-32-be"),
                        body.replace(schema, schema + b',' + schema),
                        body.replace(value_field, value_field.split(b':', 1)[0] + b':NaN'),
                        body.replace(value_field, value_field.split(b':', 1)[0] + b':1e999')):
                with self.subTest(body=bad[:24]), self.assertRaises((TOOL.Refused, ValueError)):
                    TOOL.installer_result_document(bad, source, inventory, manifest, **scope)
        for args in (("A" * 40, inventory, manifest), (source, "b" * 63, manifest), (source, inventory, "../other")):
            with self.assertRaises(TOOL.Refused):
                TOOL.installer_result_path(*args, request_id="1" * 32)
        with self.assertRaises(TOOL.Refused):
            TOOL.installer_result_path(source, inventory, manifest, fixture=1)
        for request in (None, "", "0" * 32, "F" * 32, "1" * 31, "../other", True):
            with self.assertRaises(TOOL.Refused):
                TOOL.installer_result_path(source, inventory, manifest, request_id=request)
        # A valid legacy ordinary wrapper never becomes the new ordinary route.
        with self.assertRaises(TOOL.Refused):
            TOOL.installer_result_document(TOOL.canonical({**export_document(fixture=True), "kind": "ordinary"}) + b"\n",
                                           source, inventory, manifest, request_id="1" * 32)
        for target in TOOL.MAC_TARGETS:
            for actions in (("fresh-install",), ("fresh-install", "same-package-noop", "same-package-noop"),
                            ("fresh-install", "restore-fixed-app"), ("fresh-install", "same-package-noop", "restore-fixed-app", "update")):
                producer, records, result = maintenance_documents(actions, target=target)
                selected = TOOL.maintenance_producer_data(TOOL.canonical(producer), target=target)
                TOOL.maintenance_result_data(TOOL.canonical(result) + b"\n", result["requestId"])
                state, parsed = TOOL.maintenance_history_data(result, records, selected)
                self.assertEqual((state["current"]["release"], len(parsed)), (selected["releaseSet"]["current"], len(actions)))
                names, stages = TOOL.maintenance_roster_data(state, parsed, target)
                self.assertEqual(stages, {f".install-{index:032x}" for index, action in enumerate(actions, 1) if action != "same-package-noop"})
                self.assertIn("installation-v2.json", names)
                self.assertNotIn(f'.maintenance-{state["invocation"]}.state.json', names)
                self.assertTrue(set(TOOL.maintenance_control_names(target, state["current"]["release"]["release"])) <= names)
                self.assertEqual(result["payloadWriteCount"], 0 if actions[-1] == "same-package-noop" else 24577)
        producer, records, result = maintenance_documents(("fresh-install", "same-package-noop", "restore-fixed-app", "update"))
        # Every nested new record is map-only. Hashes and matching inventory alone
        # never excuse a wrong target, arbitrary policy, legacy or reused tuple.
        for path, value in ((["releaseSet"], []), (["releaseSet", "current"], []),
                            (["releaseSet", "current", "packageVersion"], "0.1.0"),
                            (["releaseSet", "current", "sourceCommit"], "0" * 40),
                            (["releaseSet", "current", "profile"], "fixed-macos26-x86_64-maintenance-v2"),
                            (["releaseSet", "acceptedPredecessors"], [producer["releaseSet"]["current"]]),
                            (["signingPolicies"], []), (["signingPolicies"], [[], []]),
                            (["signingPolicies"], producer["signingPolicies"] * 2)):
            bad = copy.deepcopy(producer); cursor = bad
            for key in path[:-1]: cursor = cursor[key]
            cursor[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(TOOL.Refused):
                TOOL.maintenance_producer_data(TOOL.canonical(bad), target=TOOL.ARM_TARGET)
        for key in producer:
            bad = copy.deepcopy(producer); del bad[key]
            with self.assertRaises(TOOL.Refused):
                TOOL.maintenance_producer_data(TOOL.canonical(bad), target=TOOL.ARM_TARGET)
        for key, value in (("teamIdentifier", "wrong"), ("hardenedRuntime", False), ("entitlements", "any"), ("extra", True)):
            bad = copy.deepcopy(producer); bad["signingPolicies"][0]["policy"][key] = value
            with self.assertRaises(TOOL.Refused):
                TOOL.maintenance_producer_data(TOOL.canonical(bad), target=TOOL.ARM_TARGET)
        current = records[result["invocation"]]
        for key, value in (("current", []), ("retained", [[]]), ("previousEvidence", [[]]), ("phase", "inverse-recorded"), ("residue", {})):
            bad = json.loads(current[1]); bad[key] = value
            with self.assertRaises(TOOL.Refused):
                TOOL.maintenance_state_data(TOOL.canonical(bad), producer)
        for path, value in ((["current", "app", "identity", "inode"], True), (["current", "releaseDirectory"], []),
                            (["current", "app"], []), (["current", "app", "identity"], [])):
            bad = json.loads(current[1]); cursor = bad
            for key in path[:-1]: cursor = cursor[key]
            cursor[path[-1]] = value
            with self.assertRaises(TOOL.Refused):
                TOOL.maintenance_state_data(TOOL.canonical(bad), producer)
        for key, value in (("returned", False), ("originalJoined", False), ("resultEof", False), ("withinOriginalDeadline", False),
                           ("originalClosesKnown", False), ("exitCode", True), ("exitCode", 1), ("payloadWriteCount", 24578),
                           ("payloadWriteBytes", 0), ("payloadWriteBytes", TOOL.MAX_BYTES + 1)):
            bad = json.loads(current[2]); bad["writer"][key] = value
            with self.assertRaises(TOOL.Refused):
                TOOL.maintenance_capsule_data(TOOL.canonical(bad), producer, current=True)
        bad = json.loads(current[2]); del bad["writer"]["payloadWriteBytes"]
        with self.assertRaises(TOOL.Refused):
            TOOL.maintenance_capsule_data(TOOL.canonical(bad), producer, current=True)
        # Recompute legitimate byte links around each semantic mutation: these
        # checks cannot pass merely because a changed body had a stale hash.
        for action, change in (("same-package-noop", "instance"), ("restore-fixed-app", "runtime"), ("update", "retained"),
                               ("update", "previous-link"), ("update", "request-reuse"), ("update", "missing-evidence")):
            selected, bodies, exported = maintenance_documents(("fresh-install", action))
            invocation = exported["invocation"]
            intent, state, capsule = [json.loads(body) for body in bodies[invocation]]
            if change == "instance": state["current"]["instance"] = "f" * 32
            elif change == "runtime": state["current"]["releaseDirectory"]["inode"] += 1000
            elif change == "retained": state["retained"] = []
            elif change == "previous-link": intent["previousState"]["sha256"] = "f" * 64
            elif change == "request-reuse":
                old_request = json.loads(bodies[f"{1:032x}"][0])["requestId"]
                intent["requestId"] = state["requestId"] = capsule["requestId"] = exported["requestId"] = old_request
            else: state["previousEvidence"] = []
            raw_intent, raw_state = TOOL.canonical(intent) + b"\n", TOOL.canonical(state) + b"\n"
            capsule["intentSha256"], capsule["stateSha256"] = TOOL.digest(raw_intent), TOOL.digest(raw_state)
            raw_capsule = TOOL.canonical(capsule) + b"\n"
            bodies[invocation] = (raw_intent, raw_state, raw_capsule)
            exported.update(intentSha256=TOOL.digest(raw_intent), stateSha256=TOOL.digest(raw_state), capsuleSha256=TOOL.digest(raw_capsule))
            with self.subTest(change=change), self.assertRaises(TOOL.Refused):
                TOOL.maintenance_history_data(exported, bodies, selected)

    def test_installer_export_absence_accepts_only_enoent_and_settled_parents(self):
        args = result_args()
        path = TOOL.installer_result_path(args.expected_source, args.expected_inventory, args.expected_manifest, request_id=args.request_id)
        with channel_data(path) as model:
            self.assertEqual(TOOL.installer_result_absent_command(args)["state"], "expected-result-name-absent")
            self.assertEqual(model.closed, list(reversed(model.opened)))
            model.attributes.assert_not_called()
        # A perfectly bound old document is still an occupied name, not adoptable.
        with channel_data(path, TOOL.canonical(export_document()) + b"\n") as model:
            with self.assertRaises(TOOL.Refused):
                TOOL.installer_result_absent_command(args)
            self.assertNotIn(model.leaf, model.opened)
            self.assertEqual(model.closed, list(reversed(model.opened)))
        for error in (TOOL.errno.EACCES, TOOL.errno.EIO, TOOL.errno.ENOTDIR):
            with channel_data(path) as model:
                def named(name, **kwargs):
                    if name == path.name:
                        raise OSError(error, "inert metadata refusal")
                    return model.named(name, **kwargs)
                model.api.stat.side_effect = named
                with self.assertRaisesRegex(TOOL.Refused, "installer-export-absence-unknown"):
                    TOOL.installer_result_absent_command(args)
                self.assertEqual(model.closed, list(reversed(model.opened)))
        with channel_data(path) as model:
            def close(fd):
                model.close(fd)
                if fd == model.parent:
                    raise OSError("inert ambiguous parent close")
            model.api.close.side_effect = close
            with self.assertRaisesRegex(TOOL.Refused, "installer-channel-parent-close-unknown"):
                TOOL.installer_result_absent_command(args)
            self.assertEqual(model.closed, list(reversed(model.opened)))

    def test_installer_channel_parent_binds_protection_not_unrelated_child_times(self):
        path = TOOL.installer_result_path("a" * 40, "b" * 64, "c" * 64, request_id="1" * 32)
        with channel_data(path) as model:
            with TOOL.installer_channel_parent(path) as (fd, name):
                self.assertEqual((fd, name), (model.parent, path.name))
                # Protected existing group80 is allowed and never normalized.
                self.assertEqual(model.objects[fd].st_gid, 80)
                model.objects[fd] = SimpleNamespace(**{**model.objects[fd].__dict__, "st_mtime_ns": 99, "st_ctime_ns": 99, "st_nlink": 4})
            self.assertEqual(model.closed, list(reversed(model.opened)))
            model.api.chown.assert_not_called()
            model.api.chmod.assert_not_called()
        for change in ({"st_gid": 81}, {"st_ino": 999}, {"st_uid": 501}, {"st_mode": stat.S_IFDIR | 0o775}):
            with channel_data(path) as model:
                with self.assertRaisesRegex(TOOL.Refused, "installer-channel-parent-changed"):
                    with TOOL.installer_channel_parent(path) as (fd, _name):
                        model.objects[fd] = SimpleNamespace(**{**model.objects[fd].__dict__, **change})
                self.assertEqual(model.closed, list(reversed(model.opened)))
        for mode in (stat.S_IFDIR | 0o775, stat.S_IFDIR | 0o1777, stat.S_IFLNK | 0o755):
            with channel_data(path) as model:
                model.objects[model.parent] = SimpleNamespace(**{**model.objects[model.parent].__dict__, "st_mode": mode})
                with self.assertRaisesRegex(TOOL.Refused, "installer-channel-parent-protection"):
                    with TOOL.installer_channel_parent(path):
                        self.fail("unprotected parent admitted")
                self.assertNotIn(model.parent, model.opened)
                self.assertEqual(model.closed, list(reversed(model.opened)))
        # The v2 observer borrows ordinary root/versions/app directories from
        # this same admitted parent. Exercise their actual named/held checks,
        # not a fabricated directory-verification return value.
        directory_path = TOOL.INSTALL_ROOT.parent / "v2-data-directory"
        for mode in (0o755, 0o555, 0o700):
            with channel_data(directory_path, b"") as model:
                model.objects[model.leaf] = SimpleNamespace(**{**model.objects[model.leaf].__dict__,
                    "st_mode": stat.S_IFDIR | mode, "st_flags": 0})
                with TOOL.installer_channel_parent(directory_path) as (fd, name):
                    with TOOL.maintenance_directory(fd, name, mode) as (held, identity):
                        self.assertEqual(held, model.leaf)
                        self.assertEqual(identity, {"device": model.objects[held].st_dev, "inode": held,
                            "mode": stat.S_IFDIR | mode, "uid": 0, "gid": 0, "flags": 0})
                model.attributes.assert_called_once_with(model.leaf)
                self.assertEqual(model.closed, list(reversed(model.opened)))
                model.api.chmod.assert_not_called()
                model.api.chown.assert_not_called()
        for change in ({"st_ino": 999}, {"st_mode": stat.S_IFDIR | 0o775}, {"st_gid": 80}, {"st_flags": 1}):
            with channel_data(directory_path, b"") as model:
                model.objects[model.leaf] = SimpleNamespace(**{**model.objects[model.leaf].__dict__,
                    "st_mode": stat.S_IFDIR | 0o755, "st_flags": 0})
                with self.subTest(directory_post=change), self.assertRaises(TOOL.Refused):
                    with TOOL.installer_channel_parent(directory_path) as (fd, name):
                        with TOOL.maintenance_directory(fd, name, 0o755):
                            model.objects[model.leaf] = SimpleNamespace(**{**model.objects[model.leaf].__dict__, **change})
                self.assertEqual(model.closed, list(reversed(model.opened)))
        with channel_data(directory_path, b"") as model:
            model.objects[model.leaf] = SimpleNamespace(**{**model.objects[model.leaf].__dict__,
                "st_mode": stat.S_IFDIR | 0o755, "st_flags": 0})
            def close_directory(fd):
                model.close(fd)
                if fd == model.leaf:
                    raise OSError("inert directory consuming-close ambiguity")
            model.api.close.side_effect = close_directory
            with self.assertRaisesRegex(TOOL.Refused, "original-close-unknown"):
                with TOOL.installer_channel_parent(directory_path) as (fd, name):
                    with TOOL.maintenance_directory(fd, name, 0o755):
                        pass
            self.assertEqual(model.closed, list(reversed(model.opened)))

    def test_installer_saved_status_is_exact_private_original_zero(self):
        for fixture in (False, True):
            args = result_args(fixture=fixture)
            with channel_data(args.installer_status, b"0\n", private=True) as model:
                self.assertIsNone(TOOL.installer_success_status(args, fixture=fixture))
                self.assertEqual(model.closed, list(reversed(model.opened)))
                model.attributes.assert_called_once_with(model.leaf)
            for body in (b"1\n", b"00\n", b"0", b"0\r\n"):
                with channel_data(args.installer_status, body, private=True) as model:
                    with self.assertRaises(TOOL.Refused):
                        TOOL.installer_result_readback(args, fixture=fixture)
                    self.assertEqual(model.closed, list(reversed(model.opened)))
            for change in ({"st_uid": 0}, {"st_mode": stat.S_IFREG | 0o644}, {"st_nlink": 2}):
                with channel_data(args.installer_status, b"0\n", private=True) as model:
                    model.objects[model.leaf] = SimpleNamespace(**{**model.objects[model.leaf].__dict__, **change})
                    with self.assertRaisesRegex(TOOL.Refused, "installer-status-private-original"):
                        TOOL.installer_success_status(args, fixture=fixture)
                    self.assertNotIn(model.leaf, model.opened)
            args.installer_status = Path("/work/other.status")
            with self.assertRaisesRegex(TOOL.Refused, "installer-status-original-path"):
                TOOL.installer_success_status(args, fixture=fixture)
        args = result_args()
        with channel_data(args.installer_status, b"0\n", private=True) as model:
            model.objects[model.parent] = SimpleNamespace(**{**model.objects[model.parent].__dict__, "st_mode": stat.S_IFDIR | 0o755})
            with self.assertRaisesRegex(TOOL.Refused, "installer-channel-parent-protection"):
                TOOL.installer_success_status(args)

    def test_installer_export_reader_checks_original_leaf_and_all_closes(self):
        args = result_args()
        path = TOOL.installer_result_path(args.expected_source, args.expected_inventory, args.expected_manifest, request_id=args.request_id)
        body = TOOL.canonical(export_document()) + b"\n"
        with (mock.patch.object(TOOL, "installer_success_status") as status, channel_data(path, body) as model):
            result, summary = TOOL.installer_result_readback(args)
            status.assert_called_once_with(args, fixture=False)
            self.assertEqual(result, export_document())
            self.assertEqual(summary, {"bytes": len(body), "sha256": TOOL.digest(body), "identity": list(TOOL.signature(model.objects[model.leaf])),
                                      "finalityBasis": "original-successful-Installer-return-and-checked-readback"})
            model.attributes.assert_called_once_with(model.leaf)
            self.assertEqual(model.closed, list(reversed(model.opened)))
        for change in ({"st_uid": 501}, {"st_gid": 80}, {"st_mode": stat.S_IFREG | 0o644}, {"st_nlink": 2}, {"st_size": 65537}):
            with mock.patch.object(TOOL, "installer_success_status"), channel_data(path, body) as model:
                model.objects[model.leaf] = SimpleNamespace(**{**model.objects[model.leaf].__dict__, **change})
                with self.assertRaisesRegex(TOOL.Refused, "installer-export-file-policy"):
                    TOOL.installer_result_readback(args)
                self.assertNotIn(model.leaf, model.opened)
                self.assertEqual(model.closed, list(reversed(model.opened)))
        for fault in ("growth", "named-change", "attributes", "leaf-close", "parent-close"):
            with mock.patch.object(TOOL, "installer_success_status"), channel_data(path, body) as model:
                if fault == "growth":
                    model.api.read.side_effect = [body + b"x", b""]
                elif fault == "named-change":
                    def named(name, **kwargs):
                        info = model.named(name, **kwargs)
                        if name == path.name and model.offset:
                            return SimpleNamespace(**{**info.__dict__, "st_ino": 999})
                        return info
                    model.api.stat.side_effect = named
                elif fault == "attributes":
                    model.attributes.side_effect = TOOL.Refused("inert file attributes")
                else:
                    def close(fd):
                        model.close(fd)
                        if fd == (model.leaf if fault == "leaf-close" else model.parent):
                            raise OSError("inert original-close refusal")
                    model.api.close.side_effect = close
                with self.subTest(fault=fault), self.assertRaises(TOOL.Refused):
                    TOOL.installer_result_readback(args)
                self.assertEqual(model.closed, list(reversed(model.opened)))
        # Generation controls and linked v2 records use the existing read_at
        # original, now with a pre-allocation metadata charge and zero flags.
        metadata_path = TOOL.INSTALL_ROOT.parent / "v2-data-record.json"
        metadata = b'{"closed":"data"}\n'
        with channel_data(metadata_path, metadata) as model:
            model.objects[model.leaf] = SimpleNamespace(**{**model.objects[model.leaf].__dict__, "st_flags": 0})
            budget = [17]
            with TOOL.installer_channel_parent(metadata_path) as (fd, name):
                self.assertEqual(TOOL.maintenance_metadata_leaf(fd, name, 65536, budget), metadata)
            self.assertEqual(budget, [17 + len(metadata) * 8 + 4096])
            self.assertEqual(model.events.count(("read", model.leaf)), 2)  # Includes actual empty read.
            self.assertEqual(model.closed, list(reversed(model.opened)))
        for initial in (TOOL.MAINTENANCE_METADATA_BYTES - 4095,
                        TOOL.MAINTENANCE_METADATA_BYTES - 4096 - (len(metadata) - 1) * 8):
            with channel_data(metadata_path, metadata) as model:
                model.objects[model.leaf] = SimpleNamespace(**{**model.objects[model.leaf].__dict__, "st_flags": 0})
                budget = [initial]
                with self.assertRaises(TOOL.Refused):
                    with TOOL.installer_channel_parent(metadata_path) as (fd, name):
                        TOOL.maintenance_metadata_leaf(fd, name, 65536, budget)
                self.assertEqual(budget, [initial])
                self.assertNotIn(model.leaf, model.opened)
                model.api.read.assert_not_called()
                self.assertEqual(model.closed, list(reversed(model.opened)))
        for fault in ("initial-flags", "post-flags", "growth", "close"):
            with channel_data(metadata_path, metadata) as model:
                model.objects[model.leaf] = SimpleNamespace(**{**model.objects[model.leaf].__dict__,
                    "st_flags": 1 if fault == "initial-flags" else 0})
                if fault == "post-flags":
                    def read(fd, size):
                        block = model.read(fd, size)
                        model.objects[model.leaf] = SimpleNamespace(**{**model.objects[model.leaf].__dict__, "st_flags": 1})
                        return block
                    model.api.read.side_effect = read
                elif fault == "growth":
                    model.api.read.side_effect = [metadata + b"x", b""]
                elif fault == "close":
                    def close(fd):
                        model.close(fd)
                        if fd == model.leaf:
                            raise OSError("inert metadata consuming-close ambiguity")
                    model.api.close.side_effect = close
                budget = [0]
                with self.subTest(metadata_fault=fault), self.assertRaises(TOOL.Refused):
                    with TOOL.installer_channel_parent(metadata_path) as (fd, name):
                        TOOL.maintenance_metadata_leaf(fd, name, 65536, budget)
                self.assertEqual(budget, [0])
                self.assertEqual(model.closed, list(reversed(model.opened)))

    def test_installer_observation_cli_requires_status_without_legacy_fallback(self):
        args = result_args()
        options = ["--input", str(args.input), "--expected-source", args.expected_source,
                   "--expected-inventory", args.expected_inventory, "--expected-manifest", args.expected_manifest]
        api = mock.Mock(wraps=TOOL.os)
        api.getuid.return_value = api.geteuid.return_value = 501
        for command, action in (("observe-installation", "observation_command"), ("observe-installer-fixture", "fixture_observation_command")):
            required = [("--installer-status", str(args.installer_status))]
            if command == "observe-installation":
                required.extend((("--request-id", args.request_id), ("--expected-package", args.expected_package),
                                 ("--producer-descriptor", str(args.producer_descriptor)),
                                 ("--producer-signature", str(args.producer_signature))))
            complete = [item for pair in required for item in pair]
            with (mock.patch.object(TOOL, "os", api), mock.patch.object(TOOL, action, return_value={}) as call,
                  mock.patch.object(TOOL, "print", create=True), mock.patch.object(TOOL.sys, "stderr", TOOL.io.StringIO())):
                TOOL.main([command, *options, *complete])
                self.assertEqual(call.call_args.args[0].installer_status, args.installer_status)
                if command == "observe-installation":
                    self.assertEqual(call.call_args.args[0].request_id, args.request_id)
                    self.assertEqual(call.call_args.args[0].producer_descriptor, args.producer_descriptor)
                    self.assertEqual(call.call_args.args[0].producer_signature, args.producer_signature)
                call.reset_mock()
                for omitted, _value in required:
                    incomplete = [item for pair in required if pair[0] != omitted for item in pair]
                    with self.subTest(command=command, required=omitted), self.assertRaises(SystemExit):
                        TOOL.main([command, *options, *incomplete])
                    call.assert_not_called()
                with self.assertRaises(SystemExit):
                    TOOL.main([command, *options, *complete, "--installer-output", "/work/old-output.txt"])
                call.assert_not_called()
        source = (Path(__file__).absolute().parents[2] / "desktop/tools/stage_macos_installed.py").read_text(encoding="utf-8")
        ordinary = source.split("def observation_command(args):", 1)[1].split("def visible_occupant", 1)[0]
        fixture = source.split("def fixture_observation_command(args):", 1)[1].split("def main", 1)[0]
        for block in (ordinary, fixture):
            self.assertIn("installer_result_readback(args", block)
            self.assertNotIn("installer_record(", block)
            self.assertNotIn("fixture_record(", block)
            self.assertNotIn("installer_output", block)
        self.assertIn("maintenance_history_data(result, records, producer)", ordinary)
        self.assertNotIn("bound_original_result(result,", ordinary)
        self.assertLess(ordinary.index("installer_result_readback(args)"), ordinary.index("maintenance_producer_inputs(args"))
        self.assertLess(ordinary.index("maintenance_history_data(result, records, producer)"), ordinary.index("maintenance_generation_readback("))
        self.assertIn('"historicalOuterExit": "unverified"', ordinary)
        self.assertIn("bound_fixture_result(result,", fixture)

    def test_installer_export_source_keeps_dedicated_custody_original_clocks_and_finality(self):
        source = (Path(__file__).absolute().parents[2] / "desktop/src-tauri/src/bin/macos_install.rs").read_text(encoding="utf-8")
        exporter = source.split("struct Export {", 1)[1].split("    impl Install {", 1)[0]
        self.assertIn("Vec::with_capacity(4)", exporter)
        self.assertIn('check(self.originals.len() < 4, "export-original-bound")', exporter)
        self.assertNotIn("Install::new", exporter)
        self.assertNotIn("Duration::", exporter)
        writer = exporter.split("fn write(&mut self, name: &str, bytes: &[u8])", 1)[1].split("fn finish", 1)[0]
        for flag in ("O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK"):
            self.assertIn("OFlag::" + flag, writer)
        self.assertNotIn("create_file", writer)
        self.assertIn("original.mode == 0o100600 && original.uid == 0 && original.links == 1 && original.size == 0", writer)
        self.assertNotIn("original.gid == 0", writer)
        self.assertIn("sealed.size == bytes.len() as i64", writer)
        phases = [writer.index(value) for value in ("let original =", "while written <", "let before_seal =", "unistd::fchown",
                  "stat::fchmod", "let sealed =", "self.persist(n, true)", "self.close(n)", "self.persist(support, false)",
                  "self.named(n)? == sealed", "for (n, role)")]
        self.assertEqual(phases, sorted(phases))
        self.assertIn("for n in (0..self.originals.len()).rev()", exporter)
        self.assertIn("export_final(result, settled, self.unknown, self.end, Instant::now())", exporter)
        self.assertIn("finish_transport(&record, if passed { 0 } else { 1 }, export_end)", source)
        self.assertNotIn("finish_transport(&install.result_record(&final_result), final_result.exit, install.end)", source)
        self.assertIn("pub(super) fn run() -> i32 { worker::entry() }", source)
        self.assertLess(source.index("let export_end = Instant::now() + Duration::from_secs(10);"),
                        source.index('let record = serde_json::json!({"schemaVersion":1,"sourceCommit":source_commit'))
        finish = exporter.split("fn finish_transport", 1)[1]
        self.assertIn('if original_exit == 0 { export_result(record, end) } else { Err("original-installation-failed") }', finish)
        self.assertLess(finish.index("if exit != 0 {"), finish.index("std::io::stdout"))
        self.assertIn("pending-original-export-finalization", exporter)
        self.assertNotIn("remove_file", exporter)
        self.assertNotIn("unlink", exporter)
        directory = source.split("fn directory(&mut self, parent: usize, name: &str, fresh: bool, mode: u32)", 1)[1].split("        fn close", 1)[0]
        self.assertIn('Err(Errno::EEXIST) if !fresh => self.creations[effect].state = "existing-not-modified"', directory)
        created = directory.split('if self.creations[effect].state == "created" {', 1)[1]
        phases = [created.index(value) for value in ("self.protected(n, true, None)", "created_directory_private(before)",
                  "self.check_name(n, true)?; self.clock()?;", "unistd::fchown", 'map_err(|_| "created-directory-owner")?;',
                  "self.clock()?; // A failed/late", "stat::fchmod", "let actual =", "let named =", "created_directory_normalized(before, actual, named, mode)",
                  "self.originals[n].identity = Some(actual)", "self.creations[effect].identity = Some(actual)")]
        self.assertEqual(phases, sorted(phases))
        self.assertEqual(directory.count("unistd::fchown"), 1)
        private = source.split("fn created_directory_private", 1)[1].split("fn created_directory_normalized", 1)[0]
        self.assertNotIn("gid", private)
        self.assertIn("id.uid == 0 && id.mode & 0o7077 == 0", private)
        normalized = source.split("fn created_directory_normalized", 1)[1].split("// Consumes only", 1)[0]
        self.assertIn("actual == named && before.dev == actual.dev && before.ino == actual.ino", normalized)
        self.assertIn("actual.uid == 0 && actual.gid == 0", normalized)
        create_file = source.split("fn create_file", 1)[1].split("fn check_name", 1)[0]
        self.assertIn("self.protected(n, false, Some(0o600))?", create_file)
        # Follow the actual shared-body calls instead of lexical offsets across
        # adjacent Rust methods. Every fallible preparation precedes nonce/staging.
        install = source.split("fn install(&mut self, source: &str)", 1)[1].split("fn prepare_fresh(&mut self, source: &str)", 1)[0]
        phases = [install.index(item) for item in ("self.prepare_fresh(source)?", "getrandom::fill",
                  "self.install_prepared(prepared, &invocation)")]
        self.assertEqual(phases, sorted(phases))
        prepare = source.split("fn prepare_fresh(&mut self, source: &str)", 1)[1].split("fn prepare_fresh_input(", 1)[0]
        self.assertLess(prepare.index("self.input(source)?"), prepare.index("self.prepare_fresh_input(input, inventory, inventory_bytes)"))
        admission = source.split("fn prepare_fresh_input(", 1)[1].split("fn prepare_maintenance_input(", 1)[0]
        phases = [admission.index(item) for item in ("inventory.index()?", "self.absent(destination, paths::APP_NAME)?",
                  "self.absent(versions, paths::RELEASE)?", "self.maintenance_gate(destination)?", "Ok(PreparedFresh")]
        self.assertEqual(phases, sorted(phases))
        for body in (prepare, admission):
            self.assertNotIn("getrandom::fill", body)
            self.assertNotIn("self.stage_name =", body)
        prepared = source.split("fn install_prepared(", 1)[1].split("fn stage_payload(", 1)[0]
        self.assertIn("self.stage_payload(&prepared, invocation, true)?", prepared)
        staging = source.split("fn stage_payload(", 1)[1].split("fn recorded_directory(", 1)[0]
        phases = [staging.index(item) for item in ("worker::invocation_valid(invocation)", "self.stage_name =",
                  "self.directory(prepared.destination, &name, true, 0o700)?", 'self.copy_tree("app"')]
        self.assertEqual(phases, sorted(phases))
        gate = source.split("fn maintenance_gate", 1)[1].split("fn gate_record", 1)[0]
        self.assertIn("Role::GateWriter", gate)
        self.assertIn("Role::GateParticipant", gate)
        self.assertIn("fcntl::FlockArg::LockExclusiveNonblock", gate)
        self.assertNotIn("LockShared", gate)
        self.assertNotIn("unlink", gate)
        self.assertNotIn("rename", gate)
        settlement = source.split("fn settle_originals", 1)[1].split("fn result_record", 1)[0]
        self.assertIn("if Some(n) != gate { self.close(n); }", settlement)
        self.assertIn("if others_settled { self.close(n); }", settlement)
        self.assertIn("std::mem::forget(fd)", settlement)
        self.assertIn("State::KernelExitRetained", settlement)
        self.assertIn("self.gate_protected(reader)", settlement)
        # Exactly two release-metadata files; gate effects have separate fields.
        self.assertIn('"installationMetadata":self.metadata.snapshot', source)
        self.assertIn('"maintenanceGate":self.gate_record()', source)

    def test_macho_header_data_refuses_an_unreviewed_target_or_minimum(self):
        for target, other, cpu, subtype in (("aarch64-apple-darwin", "x86_64-apple-darwin", 0x0100000C, 0),
                                           ("x86_64-apple-darwin", "aarch64-apple-darwin", 0x01000007, 3)):
            header = struct.pack("<8I", 0xFEEDFACF, cpu, subtype, 2, 1, 24, 0, 0)
            build = struct.pack("<6I", 0x32, 24, 1, 26 << 16, 26 << 16, 0)
            TOOL.macho(header + build, target=target)
            TOOL.entry_macho(entry_macho_fixture(target=target), target=target)
            for role in ("desktop", "resident"):
                TOOL.image_macho(image_macho_fixture(role, target=target), role, target=target)
                with self.assertRaises(TOOL.Refused): TOOL.image_macho(image_macho_fixture(role, target=other), role, target=target)
            for body in (b"\0" * 56, header + struct.pack("<6I", 0x32, 24, 1, 25 << 16, 26 << 16, 0), header + build[:-1],
                         struct.pack("<8I", 0xFEEDFACF, cpu, subtype + 1, 2, 1, 24, 0, 0) + build):
                with self.subTest(target=target), self.assertRaises(TOOL.Refused): TOOL.macho(body, target=target)
            with self.assertRaises(TOOL.Refused): TOOL.macho(header + build, target=other)
            with self.assertRaises(TOOL.Refused): TOOL.entry_macho(entry_macho_fixture(target=other), target=target)

    def test_archive_pins_are_the_existing_M_not_new_interpreter_inputs(self):
        self.assertEqual(TOOL.ZIP_SHA, "42a6abab90f9641ba1b8c4aa9bb4202b153d676cc6d135b8227d8690e18275be")
        self.assertEqual(TOOL.TAR_SHA, "c927caedfc5a40290da443989534e85bfdf192934f4650c3747a70c53f68d35a")
        self.assertEqual(TOOL.ORIGINAL_MANIFEST, "7e0b042c82ff567ccfa156974118911e2ba159dbe45020344aaf4d71a28acc44")
        self.assertEqual(set(TOOL.NOTICES), {"21-LLVM-header-license.txt", "22-macOS-SDK-libffi-header-notices.txt"})

    def test_fixed_package_kind_rejects_wrong_identifier_payload_or_extra_hook(self):
        for fixture in (False, True):
            identifier = "dev.mobile-release-kit.desktop.installed" + ("-fixture" if fixture else "")
            body = (f'<pkg-info identifier="{identifier}" version="0.1.1" install-location="/" auth="root">'
                    '<payload numberOfFiles="0"/><scripts><postinstall file="./postinstall"/></scripts></pkg-info>').encode()
            self.assertEqual(TOOL.package_info(body, fixture=fixture), identifier)
            with self.assertRaises(TOOL.Refused):
                TOOL.package_info(body, fixture=not fixture)
            for changed in (body.replace(identifier.encode(), b"arbitrary.package"), body.replace(b'numberOfFiles="0"', b'numberOfFiles="1"'),
                            body.replace(b'</scripts>', b'<preinstall file="other"/></scripts>')):
                with self.assertRaises(TOOL.Refused):
                    TOOL.package_info(changed, fixture=fixture)
        with self.assertRaises(TOOL.Refused):
            TOOL.package_info(body, fixture="arbitrary")

        selection = TOOL.BuildSelection("x86_64-apple-darwin", "2.3.4", "macos26-x86_64-synthetic-01")
        intel = ('<pkg-info identifier="' + TOOL.PACKAGE_ID + '" version="2.3.4" install-location="/" auth="root">'
                 '<scripts><postinstall file="./postinstall"/></scripts></pkg-info>').encode()
        self.assertEqual(TOOL.package_info(intel, selection=selection), TOOL.PACKAGE_ID)
        with self.assertRaises(TOOL.Refused): TOOL.package_info(intel)
        with self.assertRaises(TOOL.Refused): TOOL.package_info(intel, fixture=True, selection=selection)

    def test_original_result_requires_bound_timely_final_closes(self):
        expected = (None, "confirmed", "confirmed", "installed", True, 0)
        result = original_result(expected)
        TOOL.bound_original_result(result, expected, "a" * 40, "b" * 64, "c" * 64)
        for key, value in (("deadlineMetAfterFinalCloses", False), ("originalsSettled", False), ("payloadWritersSettled", False),
                           ("reason", "deadline"), ("state", "unknown-retained"), ("sourceCommit", "f" * 40), ("schemaVersion", True), ("extra", True)):
            with self.subTest(key=key), self.assertRaises(TOOL.Refused):
                TOOL.bound_original_result({**result, key: value}, expected, "a" * 40, "b" * 64, "c" * 64)
        gate = result["maintenanceGate"]
        for key, value in (("entered", False), ("fixedBytes", True), ("fixedBytes", 29), ("writtenBytes", 29),
                           ("sealed", False), ("filePersisted", False), ("parentPersisted", False),
                           ("writer", "owned"), ("verified", False), ("exclusiveAttempted", False),
                           ("exclusiveAcquired", False), ("participant", "unknown"),
                           ("participant", "kernel-exit-retained"), ("cleanup", "deleted"), ("extra", True)):
            with self.subTest(gate=key, value=value), self.assertRaises(TOOL.Refused):
                TOOL.bound_original_result({**result, "maintenanceGate": {**gate, key: value}}, expected,
                                           "a" * 40, "b" * 64, "c" * 64)
        missing = dict(result); del missing["maintenanceGate"]
        with self.assertRaises(TOOL.Refused):
            TOOL.bound_original_result(missing, expected, "a" * 40, "b" * 64, "c" * 64)
        reused = {**gate, "creation": "existing-not-modified", "writtenBytes": 0, "sealed": False,
                  "filePersisted": False, "parentPersisted": False, "writer": "not-attempted"}
        TOOL.bound_original_result({**result, "maintenanceGate": reused}, expected, "a" * 40, "b" * 64, "c" * 64)
        for key, value in (("writtenBytes", 30), ("sealed", True), ("filePersisted", True), ("writer", "closed")):
            with self.subTest(reuse=key), self.assertRaises(TOOL.Refused):
                TOOL.maintenance_gate_result({**reused, key: value}, entered=True)
        unentered = original_result(TOOL.FIXTURE_CASES["occupied-app"], stage=None)["maintenanceGate"]
        TOOL.maintenance_gate_result(unentered, entered=False)
        with self.assertRaises(TOOL.Refused):
            TOOL.maintenance_gate_result({**unentered, "verified": True}, entered=False)

        selection = TOOL.BuildSelection("x86_64-apple-darwin", "0.1.0", "macos26-x86_64-synthetic-01")
        intel = dict(result, release=selection.release)
        TOOL.bound_original_result(intel, expected, "a" * 40, "b" * 64, "c" * 64, selection=selection)
        with self.assertRaises(TOOL.Refused): TOOL.bound_original_result(intel, expected, "a" * 40, "b" * 64, "c" * 64)
        with self.assertRaises(TOOL.Refused):
            TOOL.bound_original_result(dict(intel, originalsSettled=False), expected, "a" * 40, "b" * 64, "c" * 64, selection=selection)

    def test_fixture_result_exact_eight_cases_never_promotes_actual_uncertainty(self):
        self.assertEqual(tuple(TOOL.FIXTURE_CASES), ("occupied-app", "occupied-release", "runtime-publication-collision", "staging-file-collision",
                         "first-publication-second-refusal", "prepublication-persistence-report", "postruntime-persistence-report", "metadata-descriptor-collision"))
        marker = b"MRK_MACOS_INSTALL_FIXTURE_RESULT="
        good = reported_fixture_data()
        log = marker + TOOL.canonical(good) + b"\n"
        self.assertEqual(TOOL.fixture_record(log, "a" * 40, "b" * 64, "c" * 64), good)
        self.assertIs(TOOL.bound_fixture_result(good, "a" * 40, "b" * 64, "c" * 64), good)
        mutations = [(("sourceCommit",), "f" * 40), (("fixtureBase",), "/tmp/arbitrary"),
                     (("fixtureBase",), TOOL.FIXTURE_PREFIX + "f" * 12 + "-" + "e" * 32),
                     (("cases",), good["cases"][:-1]), (("cases",), list(reversed(good["cases"]))),
                     (("nativeCloseFailureInjected",), True), (("genuineConcurrentRaceObserved",), True),
                     (("cases", 2, "originalResult", "runtimePublication"), "unknown"), (("cases", 3, "stagingOpenErrno"), 5),
                     (("cases", 5, "persistence", "actualNativeSucceeded"), False), (("cases", 6, "persistence", "actualNativeErrno"), 5),
                     (("cases", 7, "stagingOpenErrno"), 5), (("cases", 7, "originalResult", "installationMetadata", "openedFiles"), 2),
                     (("cases", 7, "occupant", "visibleRelativePath"), "versions/" + TOOL.RELEASE + "/unrelated"),
                     (("cases", 6, "persistence", "injectedReportedFailure"), False), (("cases", 4, "originalResult", "originalsSettled"), False),
                     (("cases", 4, "originalResult", "deadlineMetAfterFinalCloses"), False), (("cases", 0, "occupant", "after", "inode"), 43),
                     (("cases", 0, "occupant", "visibleRelativePath"), "../../arbitrary"), (("cases", 0, "occupant", "after", "links"), True), (("extra",), True)]
        for path, value in mutations:
            changed = TOOL.decode(TOOL.canonical(good))
            cursor = changed
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(TOOL.Refused):
                TOOL.fixture_record(marker + TOOL.canonical(changed), "a" * 40, "b" * 64, "c" * 64)
            with self.subTest(direct_path=path), self.assertRaises(TOOL.Refused):
                TOOL.bound_fixture_result(changed, "a" * 40, "b" * 64, "c" * 64)
        for changed in (log + log, b"MRK_MACOS_INSTALL_RESULT={}\n" + log):
            with self.assertRaises(TOOL.Refused):
                TOOL.fixture_record(changed, "a" * 40, "b" * 64, "c" * 64)


def installation_record_fixture():
    # Closed DATA only, not a root-owned installation or original receipt.
    names = ["app/" + TOOL.VAULT_HELPER, "app/Contents/Info.plist", "app/" + TOOL.PAYLOAD_INFO,
             "app/" + TOOL.ENTRY_BINARY, "app/" + TOOL.APP_BINARY, "runtime/manifest.json", "runtime/python/bin/python3"]
    rows = [{"path": name, "size": 1, "sha256": ("c" if name == "runtime/manifest.json" else "b") * 64,
             "executable": name in ("app/" + TOOL.ENTRY_BINARY, "app/" + TOOL.VAULT_HELPER, "app/" + TOOL.APP_BINARY, "runtime/python/bin/python3")}
            for name in sorted(names)]
    inventory = TOOL.canonical({"schemaVersion": 1, "release": TOOL.RELEASE,
                                "runtimeManifestSha256": "c" * 64, "files": rows})
    identity = {"device": 1, "inode": 9007199254740993, "mode": stat.S_IFDIR | 0o755, "uid": 0, "gid": 0, "flags": 0}
    release = {**identity, "inode": identity["inode"] + 1}
    record = {"schemaVersion": 1, "basis": "protected-recorded-installation-inventory", "phase": "inventory-recorded",
              "kind": "ordinary", "instance": "d" * 32, "packageIdentifier": TOOL.PACKAGE_ID,
              "packageVersion": TOOL.PACKAGE_VERSION, "bundleIdentifier": TOOL.BUNDLE_ID, "release": TOOL.RELEASE,
              "sourceCommit": "a" * 40, "protocolSha256": TOOL.CURRENT_PROTOCOL, "runtimeManifestSha256": "c" * 64,
              "inventory": {"name": TOOL.INSTALLATION_INVENTORY_NAME, "bytes": len(inventory), "sha256": TOOL.digest(inventory)},
              "policy": "fixed-root-wheel-readonly-v1", "installRoot": identity, "releaseDirectory": release}
    return record, inventory, identity, release


@unittest.skipUnless(TOOL is not None, "POSIX inert DATA definitions only")
class MacInstallationMetadataData(unittest.TestCase):
    def test_optional_android_service_is_exact_nonexecutable_plist_and_bound_helper_pair(self):
        helper, resident = entry_macho_fixture(), image_macho_fixture("resident")
        expected, expected_image = TOOL.digest(helper), TOOL.digest(resident)
        plist = TOOL.plistlib.dumps({"Label": TOOL.ANDROID_SERVICE_LABEL, "BundleProgram": TOOL.ANDROID_HELPER_BUNDLE_PROGRAM,
                                    "MachServices": {TOOL.ANDROID_SERVICE_LABEL: True}})
        helper_path, image_path = Path("/inert/android-helper"), Path("/inert/resident-image")
        args = SimpleNamespace(android_helper=helper_path, expected_android_helper=expected,
                               resident_image=image_path, expected_resident_image=expected_image)
        values = {helper_path: helper, image_path: resident}
        with mock.patch.object(TOOL, "read", side_effect=lambda path, *_: values.get(path, plist)):
            files = TOOL.android_service_files(args)
            self.assertEqual(files, {TOOL.ANDROID_HELPER: (helper, 0o555), TOOL.RESIDENT_IMAGE: (resident, 0o555),
                                     TOOL.ANDROID_SERVICE_PLIST: (plist, 0o644)})
            TOOL.android_service_input(files, expected, expected_image)
            # Empty common structural DATA is not actual app layout admission.
            self.assertEqual(TOOL.android_service_files(SimpleNamespace()), {})
            TOOL.android_service_input({}, None)
            refused = [({name: value for name, value in files.items() if name != missing}, expected, expected_image)
                       for missing in files]
            refused += [(files, None, expected_image), (files, expected, None), ({}, expected, expected_image),
                        ({**files, TOOL.ANDROID_HELPER: (helper + b"changed", 0o555)}, expected, expected_image),
                        ({**files, TOOL.RESIDENT_IMAGE: (resident + b"changed", 0o555)}, expected, expected_image),
                        ({**files, TOOL.ANDROID_HELPER: (helper, 0o444)}, expected, expected_image),
                        ({**files, TOOL.RESIDENT_IMAGE: (resident, 0o444)}, expected, expected_image),
                        ({**files, TOOL.ANDROID_SERVICE_PLIST: (plist, 0o755)}, expected, expected_image),
                        ({**files, TOOL.ANDROID_SERVICE_PLIST: (plist + b"changed", 0o644)}, expected, expected_image)]
            for source, digest, image_digest in refused:
                with self.subTest(source=sorted(source), expected=digest), self.assertRaises(TOOL.Refused):
                    TOOL.android_service_input(source, digest, image_digest)
            for key in vars(args):
                request = SimpleNamespace(**{name: value for name, value in vars(args).items() if name != key})
                with self.subTest(missing=key), self.assertRaises(TOOL.Refused):
                    TOOL.android_service_files(request)
            with self.assertRaises(TOOL.Refused):
                TOOL.android_service_files(SimpleNamespace(**dict(vars(args), expected_android_helper="f" * 64)))
            with self.assertRaises(TOOL.Refused):
                TOOL.android_service_files(SimpleNamespace(**dict(vars(args), expected_resident_image="f" * 64)))
        # Common inventory DATA preserves the JSON/Kind schema and accepts the
        # resident-only observer group, never desktop -> missing resident.
        _, body, _, _ = installation_record_fixture()
        group = (TOOL.ANDROID_HELPER, TOOL.ANDROID_SERVICE_PLIST, TOOL.RESIDENT_IMAGE, TOOL.DESKTOP_IMAGE)
        for bits in range(16):
            selected = [name for index, name in enumerate(group) if bits & (1 << index)]
            accepted = bits in (0, 7, 15)
            value = TOOL.decode(body)
            value["files"].extend({"path": "app/" + name, "size": 1, "sha256": "b" * 64,
                                   "executable": name != TOOL.ANDROID_SERVICE_PLIST} for name in selected)
            value["files"].sort(key=lambda row: row["path"])
            changed = TOOL.canonical(value)
            with self.subTest(group=bits):
                if accepted:
                    TOOL.observation_inventory_bytes(changed, TOOL.digest(changed), "c" * 64)
                else:
                    with self.assertRaises(TOOL.Refused):
                        TOOL.observation_inventory_bytes(changed, TOOL.digest(changed), "c" * 64)
        for image in (TOOL.DESKTOP_IMAGE, TOOL.RESIDENT_IMAGE):
            value = TOOL.decode(changed)
            next(row for row in value["files"] if row["path"] == "app/" + image)["executable"] = False
            encoded = TOOL.canonical(value)
            with self.subTest(noncode=image), self.assertRaises(TOOL.Refused):
                TOOL.observation_inventory_bytes(encoded, TOOL.digest(encoded), "c" * 64)

    def test_closed_record_matches_exact_inventory_tuple_and_full_integer_directory_identity(self):
        record, inventory, root, release = installation_record_fixture()
        def parse(body, payload=inventory):
            return TOOL.installation_record_data(body, payload, "a" * 40, "c" * 64, root, release, "d" * 32)
        self.assertEqual(parse(TOOL.canonical(record)), record)
        for path, value in [(("schemaVersion",), True), (("phase",), "installed"), (("kind",), "fixture"),
                            (("sourceCommit",), "e" * 40), (("protocolSha256",), "e" * 64),
                            (("instance",), "0" * 32), (("installRoot", "inode"), 9007199254740992),
                            (("releaseDirectory", "flags"), 1), (("installRoot", "mtime"), 1),
                            (("installRoot", "uid"), False), (("inventory", "bytes"), True), (("extra",), True)]:
            changed = TOOL.decode(TOOL.canonical(record))
            cursor = changed
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(TOOL.Refused):
                parse(TOOL.canonical(changed))
        for body in (b'{"schemaVersion":1,' + TOOL.canonical(record)[1:], b" " * (TOOL.INSTALLATION_RECORD_LIMIT + 1)):
            with self.assertRaises(TOOL.Refused):
                parse(body)
        with self.assertRaises(TOOL.Refused):
            parse(TOOL.canonical(record), inventory + b" ")
        # Even a self-consistent descriptor digest cannot bless an invalid roster.
        malformed = TOOL.decode(inventory)
        malformed["files"][0]["path"] = "runtime/../unrelated"
        malformed = TOOL.canonical(malformed)
        changed = {**record, "inventory": {**record["inventory"], "bytes": len(malformed), "sha256": TOOL.digest(malformed)}}
        with self.assertRaises(TOOL.Refused):
            parse(TOOL.canonical(changed), malformed)

        selection = TOOL.BuildSelection("x86_64-apple-darwin", "2.3.4", "macos26-x86_64-synthetic-01")
        intel_inventory = TOOL.canonical(dict(TOOL.decode(inventory), release=selection.release))
        intel_record = dict(record, release=selection.release, packageVersion=selection.package_version,
                            inventory=dict(record["inventory"], bytes=len(intel_inventory), sha256=TOOL.digest(intel_inventory)))
        self.assertEqual(TOOL.installation_record_data(TOOL.canonical(intel_record), intel_inventory, "a" * 40, "c" * 64,
                                                     root, release, "d" * 32, selection=selection), intel_record)
        for wrong in (dict(intel_record, release=record["release"]), dict(intel_record, packageVersion=record["packageVersion"])):
            with self.assertRaises(TOOL.Refused):
                TOOL.installation_record_data(TOOL.canonical(wrong), intel_inventory, "a" * 40, "c" * 64,
                                              root, release, "d" * 32, selection=selection)
        with self.assertRaises(TOOL.Refused):
            TOOL.installation_record_data(TOOL.canonical(intel_record), intel_inventory, "a" * 40, "c" * 64, root, release, "d" * 32)
        with self.assertRaises(TOOL.Refused):
            TOOL.observation_inventory_bytes(inventory, TOOL.digest(inventory), "c" * 64, selection=selection)

    def test_metadata_return_accounting_is_required_and_partial_is_not_success(self):
        expected = (None, "confirmed", "confirmed", "installed", True, 0)
        result = original_result(expected)
        TOOL.bound_original_result(result, expected, "a" * 40, "b" * 64, "c" * 64)
        for field, value in (("writersSettled", False), ("openedFiles", 1), ("attemptedFiles", True),
                             ("writtenBytes", 9), ("state", "incomplete"), ("extra", 0)):
            changed = {**result, "installationMetadata": {**result["installationMetadata"], field: value}}
            with self.subTest(field=field), self.assertRaises(TOOL.Refused):
                TOOL.bound_original_result(changed, expected, "a" * 40, "b" * 64, "c" * 64)
        missing = dict(result)
        del missing["installationMetadata"]
        with self.assertRaises(TOOL.Refused):
            TOOL.bound_original_result(missing, expected, "a" * 40, "b" * 64, "c" * 64)
        partial = TOOL.FIXTURE_CASES["metadata-descriptor-collision"]
        value = original_result(partial)
        TOOL.bound_original_result(value, partial, "a" * 40, "b" * 64, "c" * 64)
        self.assertEqual(value["installationMetadata"]["openedFiles"], 1)
        with self.assertRaises(TOOL.Refused):
            TOOL.installation_metadata_result(result["installationMetadata"], partial)

    def test_metadata_leaf_requires_flags_through_original_read_and_positive_close(self):
        # Every numerical FD here is an inert token; all consumers are replaced.
        good = log_info(3, st_mode=stat.S_IFREG | 0o444, st_gid=0, st_flags=0)
        changed = log_info(3, st_mode=stat.S_IFREG | 0o444, st_gid=0, st_flags=1)
        for cause in ("none", "flags", "close"):
            with (mock.patch.object(TOOL.os, "stat", side_effect=[good, good]),
                  mock.patch.object(TOOL.os, "open", return_value=91),
                  mock.patch.object(TOOL.os, "fstat", side_effect=[good, changed if cause == "flags" else good]),
                  mock.patch.object(TOOL.os, "read", side_effect=[b"abc", b""]),
                  mock.patch.object(TOOL, "no_xattrs"),
                  mock.patch.object(TOOL, "close_once", side_effect=TOOL.Refused("synthetic-close-unknown") if cause == "close" else None) as close):
                if cause == "none":
                    self.assertEqual(TOOL.installation_metadata_leaf(90, TOOL.INSTALLATION_RECORD_NAME, 10)[0], b"abc")
                else:
                    with self.subTest(cause=cause), self.assertRaises(TOOL.Refused):
                        TOOL.installation_metadata_leaf(90, TOOL.INSTALLATION_RECORD_NAME, 10)
                close.assert_called_once_with(91)
        # The gate reuses the exact protected leaf reader and cannot accept a
        # convenient empty, replaced, writable or wrong-owner local file.
        gate = TOOL.MAINTENANCE_GATE_BYTES
        for problem in ("none", "content", "mode", "owner", "replacement", "missing"):
            before = log_info(len(gate), st_mode=stat.S_IFREG | (0o644 if problem == "mode" else 0o444),
                              st_uid=501 if problem == "owner" else 0, st_gid=0, st_flags=0)
            after = log_info(len(gate), st_mode=before.st_mode, st_uid=before.st_uid, st_gid=0,
                             st_flags=0, st_ino=before.st_ino + 1) if problem == "replacement" else before
            with (mock.patch.object(TOOL.os, "stat", side_effect=FileNotFoundError() if problem == "missing" else [before, before]),
                  mock.patch.object(TOOL.os, "open", return_value=91),
                  mock.patch.object(TOOL.os, "fstat", side_effect=[before, after]),
                  mock.patch.object(TOOL.os, "read", side_effect=[b"x" * len(gate) if problem == "content" else gate, b""]),
                  mock.patch.object(TOOL, "no_xattrs"), mock.patch.object(TOOL, "close_once") as close):
                if problem == "none":
                    readback = TOOL.maintenance_gate_readback(90)
                    self.assertEqual(readback["bytes"], 30)
                    self.assertFalse(readback["exclusionObserved"] or readback["workerFinalityEstablished"])
                else:
                    with self.subTest(gate_problem=problem), self.assertRaises((TOOL.Refused, FileNotFoundError)):
                        TOOL.maintenance_gate_readback(90)
                if problem == "missing": close.assert_not_called()
                else: close.assert_called_once_with(91)

    def test_metadata_parent_cleanup_consumes_all_originals_and_gates_result(self):
        for target, release in (("aarch64-apple-darwin", TOOL.RELEASE), ("x86_64-apple-darwin", "macos26-x86_64-synthetic-01")):
            selection = TOOL.BuildSelection(target, TOOL.PACKAGE_VERSION, release)
            names = {"runtime", TOOL.INSTALLATION_INVENTORY_NAME, TOOL.INSTALLATION_RECORD_NAME}
            entries = ("MobileReleaseKit", "versions", selection.release)
            info = {entry: log_info(st_ino=index + 101, st_mode=stat.S_IFDIR | 0o755, st_gid=0, st_nlink=3, st_flags=0)
                    for index, entry in enumerate(entries)}
            @contextlib.contextmanager
            def parent(_path):
                yield 100, entries[0]
            for cause in ("none", "close", "drift"):
                stats = [info[name] for name in entries] * 2
                if cause == "drift":
                    stats[-1] = SimpleNamespace(**{**vars(stats[-1]), "st_ino": 999})
                with (mock.patch.object(TOOL, "parent", side_effect=parent),
                      mock.patch.object(TOOL.os, "stat", side_effect=stats) as named,
                      mock.patch.object(TOOL.os, "open", side_effect=[101, 102, 103]),
                      mock.patch.object(TOOL.os, "fstat", side_effect=lambda fd: info[entries[fd - 101]]),
                      mock.patch.object(TOOL.os, "listdir", return_value=list(names)),
                      mock.patch.object(TOOL, "no_xattrs"),
                      mock.patch.object(TOOL, "close_once", side_effect=[TOOL.Refused("synthetic-close-unknown"), None, None] if cause == "close" else None) as close):
                    def observe():
                        with TOOL.installation_metadata_directory(TOOL.INSTALL_ROOT, names, selection=selection) as (_root, _release, fd):
                            self.assertEqual(fd, 103)
                        return "after-real-context-closes"
                    if cause == "none":
                        self.assertEqual(observe(), "after-real-context-closes")
                    else:
                        with self.subTest(cause=cause), self.assertRaises(TOOL.Refused):
                            observe()
                    self.assertEqual([call.args[0] for call in named.call_args_list[:3]], list(entries))
                    self.assertEqual(close.call_args_list, [mock.call(103), mock.call(102), mock.call(101)])

    def test_record_identifiers_match_existing_package_and_bundle_source(self):
        source = Path(__file__).absolute().parents[2]
        info = TOOL.plistlib.loads((source / "desktop/macos-installed-inputs/Info.plist").read_bytes())
        self.assertEqual(info["CFBundleIdentifier"], TOOL.BUNDLE_ID)
        self.assertEqual(info["CFBundleVersion"], TOOL.PACKAGE_VERSION)
        self.assertEqual(info["CFBundleShortVersionString"], TOOL.PACKAGE_VERSION)
        paths = (source / "desktop/src-tauri/src/macos_install_fixed_paths.rs").read_text(encoding="utf-8")
        for key, value in (("PACKAGE_ID", TOOL.PACKAGE_ID), ("FIXTURE_PACKAGE_ID", TOOL.PACKAGE_ID + "-fixture"),
                           ("BUNDLE_ID", TOOL.BUNDLE_ID)):
            self.assertIn(f'pub const {key}: &str = "{value}";', paths)
        selected = TOOL.build_release_data(TOOL.BUILD_RELEASE_INPUT.read_bytes())
        self.assertEqual(selected["packageVersion"], TOOL.PACKAGE_VERSION)
        self.assertEqual(selected["release"], TOOL.RELEASE)
        self.assertEqual(TOOL.HISTORICAL_SUPPLIER_RELEASE, "macos26-arm64-project-draft-01")
        self.assertEqual(TOOL.RELEASE, "macos26-arm64-desktop-01")
        entry_info = TOOL.plistlib.loads(TOOL.source_entry_info())
        self.assertEqual(entry_info, dict(info, CFBundleIdentifier=TOOL.ENTRY_BUNDLE_ID, CFBundleExecutable="mrk-macos-entry"))
        self.assertEqual(TOOL.ANDROID_HELPER_BUNDLE_PROGRAM, "Contents/Helpers/mrk-android-register")
        self.assertEqual(TOOL.ANDROID_HELPER, TOOL.PAYLOAD_RELATIVE + "/" + TOOL.ANDROID_HELPER_BUNDLE_PROGRAM)
        for key, value in (("ENTRY_BUNDLE_ID", TOOL.ENTRY_BUNDLE_ID), ("ENTRY_BINARY", TOOL.ENTRY_BINARY),
                           ("PAYLOAD_NAME", TOOL.PAYLOAD_NAME), ("PAYLOAD_RELATIVE", TOOL.PAYLOAD_RELATIVE),
                           ("PAYLOAD_EXECUTABLE", str(TOOL.INSTALL_ROOT / TOOL.APP_NAME / TOOL.APP_BINARY)),
                           ("ENTRY_INVENTORY_PATH", "app/" + TOOL.ENTRY_BINARY),
                           ("PAYLOAD_INVENTORY_PATH", "app/" + TOOL.APP_BINARY),
                           ("PAYLOAD_INFO_INVENTORY_PATH", "app/" + TOOL.PAYLOAD_INFO),
                           ("VAULT_HELPER_INVENTORY_PATH", "app/" + TOOL.VAULT_HELPER),
                           ("ANDROID_HELPER_INVENTORY_PATH", "app/" + TOOL.ANDROID_HELPER),
                           ("ANDROID_SERVICE_INVENTORY_PATH", "app/" + TOOL.ANDROID_SERVICE_PLIST),
                           ("MAINTENANCE_GATE_NAME", TOOL.MAINTENANCE_GATE_NAME)):
            self.assertIn(f'pub const {key}: &str = "{value}";', paths)
        fixed = (source / "desktop/native/macos-installed-entry/fixed_paths.h").read_text()
        for key, value in (("MRK_ENTRY_EXECUTABLE", str(TOOL.INSTALL_ROOT / TOOL.APP_NAME / TOOL.ENTRY_BINARY)),
                           ("MRK_PAYLOAD_EXECUTABLE", str(TOOL.INSTALL_ROOT / TOOL.APP_NAME / TOOL.APP_BINARY)),
                           ("MRK_MAINTENANCE_GATE_NAME", TOOL.MAINTENANCE_GATE_NAME)):
            self.assertIn(f'#define {key} "{value}"', fixed)
        self.assertEqual(TOOL.MAINTENANCE_GATE_BYTES, b"MRK-MACOS-MAINTENANCE-GATE-v1\n")
        self.assertIn('pub const MAINTENANCE_GATE_BYTES: &[u8] = b"MRK-MACOS-MAINTENANCE-GATE-v1\\n";', paths)
        self.assertIn('#define MRK_MAINTENANCE_GATE_BYTES "MRK-MACOS-MAINTENANCE-GATE-v1\\n"', fixed)
        entry = (source / "desktop/native/macos-installed-entry/entry.c").read_text()
        main = entry.split("int main(", 1)[1]
        phases = [main.index(item) for item in ("mrk_entry_root", "mrk_entry_open_gate", "LOCK_SH | LOCK_NB",
                  "!environment(", "F_SETFD, 0", "mrk_entry_close_ancestors", "execve(")]
        self.assertEqual(phases, sorted(phases))
        self.assertEqual(main.count("execve("), 1)
        self.assertNotIn("getenv(", entry)
        self.assertNotIn("LOCK_UN", entry)
        self.assertIn("memchr(value, 0, available)", entry)
        retained = (source / "desktop/native/macos-installed-entry/gate.c").read_text().split("int mrk_installed_entry_admit", 1)[1]
        self.assertIn("F_SETFD, FD_CLOEXEC", retained)
        self.assertNotIn("flock(", retained)
        self.assertNotIn("close(descriptor", retained)
        native = (source / "desktop/native/macos-installed-native/build.rs").read_text()
        self.assertEqual(native.count('format!("{:?}", installed_paths::PAYLOAD_APP)'), 2)
        shell = (source / "desktop/src-tauri/src/shell.rs").read_text().split("pub fn run()", 1)[1].split("fn builder", 1)[0]
        self.assertLess(shell.index("installed_entry::admit_once"), shell.index("run_builder(builder())"))
        for exclusion in ('not(test)', 'not(feature = "development-runtime")', 'not(feature = "macos-installed-observation")',
                          'not(feature = "macos-installed-installer")', 'not(feature = "macos-installed-installer-fixture")',
                          'not(feature = "macos-android-registration-helper")', 'not(feature = "ubuntu-runtime-publisher")',
                          'not(feature = "windows-runtime-publisher")'):
            self.assertIn(exclusion, shell)
        ui = (source / "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift").read_text()
        basic = ui.split("private func launchCancelAndQuit(profile:", 1)[1].split("private struct FixtureSpec", 1)[0]
        launch = ui.split("private func launchOrdinaryApplication()", 1)[1].split("private func completeNormalQuit(", 1)[0]
        terminal = ui.split("private func completeNormalQuit(", 1)[1].split("private func acceptFinalScenario()", 1)[0]
        self.assertNotIn("app.launch()", ui)
        self.assertEqual(basic.count("try launchOrdinaryApplication()"), 1)
        self.assertEqual(ui.count("NSWorkspace.shared.openApplication(at: Self.outerURL"), 1)
        self.assertIn("XCUIApplication(url: OrdinaryLaunch.payloadURL)", launch)
        self.assertIn('try nativeSheet(window, title: "Choose a mobile project folder")', basic)
        self.assertEqual(basic.count("try gate.probe(busy: true)"), 2)
        self.assertEqual(launch.count("try gate.probe(busy: false)"), 1)
        self.assertEqual(terminal.count("try gate.probe(busy: false)"), 1)
        self.assertLess(terminal.index("owner.observeNormalTermination"), terminal.index("try gate.probe(busy: false)"))
        self.assertEqual(basic.count("try completeNormalQuit(app)"), 1)
        self.assertEqual(basic.count("try acceptFinalScenario()"), 1)
        self.assertIn("directPayloadPreMain=unqualified;allWorkerFinality=unavailable;maintenance=unavailable", basic)
        staging = (source / "desktop/tools/stage_macos_installed.py").read_text()
        supplier = ast.parse(staging)
        reused = next(node for node in supplier.body if isinstance(node, ast.FunctionDef) and node.name == "reused_runtime")
        self.assertIn("HISTORICAL_SUPPLIER_RELEASE", {node.id for node in ast.walk(reused) if isinstance(node, ast.Name)})
        self.assertNotIn("RELEASE", {node.id for node in ast.walk(reused) if isinstance(node, ast.Name)})



@contextlib.contextmanager
def current_data_fixture():
    """Fresh synthetic DATA only; no real supplier archive or executable core."""
    helper = (Path(__file__).absolute().parents[2] / "desktop/tools/prepare_runtime.py").read_bytes()
    with tempfile.TemporaryDirectory(prefix="mrk-macos-current-data-") as directory:
        root = Path(directory)
        checkout = root / "checkout"
        engine = b"# Inert protocol DATA, never imported.\n"
        inputs = {"src/mobile_release/__init__.py": b'__version__ = "0.1.0"\n',
                  "src/mobile_release/_desktop_engine.py": engine,
                  TOOL.CURRENT_CA_SOURCE: b"SYNTHETIC CA DATA, not a trust store\n",
                  TOOL.CURRENT_HELPER_SOURCE: helper}
        inputs.update({"desktop/" + name: ("# current inert " + name + "\n").encode() for name in TOOL.CURRENT_BOOTSTRAPS})
        for name, body in inputs.items():
            path = checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(body)
        archive = root / "supplier.zip"
        archive.write_bytes(b"No actual archive; supplier decoder is mocked.\n")
        supplier = {"python/bin/python3": b"INERT SUPPLIER DATA; NEVER EXECUTED\n",
                    "python/licenses/notice.txt": b"synthetic supplier notice\n"}
        historical = {**supplier, "core.zip": b"historical core, not used", "github-ca.pem": b"historical CA",
                      "manifest.json": b"historical manifest"}
        historical.update({name: b"historical bootstrap" for name in TOOL.BOOTSTRAPS})
        provenance = {"acceptedArchiveSha256": "1" * 64, "acceptedTarSha256": "2" * 64,
                      "originalManifestSha256": "3" * 64, "addedNotices": ["synthetic notice only"]}
        with (mock.patch.object(TOOL, "DESKTOP", checkout / "desktop"),
              mock.patch.object(TOOL, "CURRENT_PROTOCOL", TOOL.digest(engine)),
              mock.patch.object(TOOL, "reused_runtime", return_value=(historical, provenance))):
            yield SimpleNamespace(root=root, checkout=checkout, archive=archive, supplier=supplier, inputs=inputs)


@unittest.skipUnless(sys.platform in ("darwin", "linux"), "POSIX DATA stager")
class MacCurrentRuntimeData(unittest.TestCase):
    def args(self, fixture, command="describe-current-runtime", suffix="description"):
        return SimpleNamespace(command=command, archive=fixture.archive, work=fixture.root / ("work-" + suffix),
                               output=fixture.root / ("output-" + suffix), expected_source="0" * 64,
                               expected_manifest="0" * 64)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "requires the reviewed nonroot POSIX DATA test owner")
    def test_current_projection_and_final_payload_preserve_only_supplier(self):
        with current_data_fixture() as fixture:
            captured, projection, source_digest = TOOL.current_source()
            self.assertEqual(set(captured), set(fixture.inputs))
            self.assertEqual(len(projection) + 1, len(captured))
            self.assertNotIn(TOOL.CURRENT_HELPER_SOURCE, projection)
            self.assertNotIn(TOOL.CURRENT_CA_SOURCE, projection)
            self.assertEqual(projection["desktop/github-ca.pem"], (fixture.inputs[TOOL.CURRENT_CA_SOURCE], 0o444))
            description = TOOL.current_runtime_command(self.args(fixture))
            args = self.args(fixture, "current-runtime", "final")
            args.expected_source = source_digest
            args.expected_manifest = description["successorManifestSha256"]
            result = TOOL.current_runtime_command(args)
            self.assertEqual(result["qualification"], "current-source-staged-no-native-execution")
            self.assertTrue(result["supplierOnlyReuse"])
            self.assertEqual(result["sourceInputCount"], len(fixture.inputs))
            self.assertEqual(result["currentCoreFileCount"], 2)
            self.assertEqual(result["supplierInventorySha256"], description["supplierInventorySha256"])
            final = TOOL.tree(args.output, current_root_mode=0o555)
            self.assertEqual(set(final), set(fixture.supplier) | TOOL.CURRENT_BOOTSTRAPS | {"core.zip", "manifest.json", "github-ca.pem"})
            for name, body in fixture.supplier.items():
                self.assertEqual(final[name], (body, 0o555 if name == "python/bin/python3" else 0o444))
            for name in TOOL.CURRENT_BOOTSTRAPS | {"github-ca.pem"}:
                self.assertEqual(final[name], projection["desktop/" + name])
            TOOL.current_core_matches(final["core.zip"][0], projection)
            self.assertEqual(TOOL.tree(args.work / "source", current_root_mode=0o555), projection)
            self.assertEqual(TOOL.current_source(), (captured, projection, source_digest))

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "requires the reviewed nonroot POSIX DATA test owner")
    def test_source_pin_and_output_conflicts_fail_before_helper_or_writes(self):
        with current_data_fixture() as fixture, mock.patch.object(TOOL, "current_preparer") as prepare:
            args = self.args(fixture, "current-runtime", "stale")
            with mock.patch.object(TOOL, "CURRENT_PROTOCOL", "f" * 64):
                with self.assertRaisesRegex(TOOL.Refused, "current-protocol-source"):
                    TOOL.current_runtime_command(args)
            self.assertFalse(args.work.exists())
            self.assertFalse(args.output.exists())
            with self.assertRaisesRegex(TOOL.Refused, "current-reviewed-source-mismatch"):
                TOOL.current_runtime_command(args)
            self.assertFalse(args.work.exists())
            self.assertFalse(args.output.exists())
            args.expected_source = TOOL.current_source()[2]
            extra = fixture.checkout / "src/mobile_release/extra.py"
            extra.write_bytes(b"# extra current source must change S\n")
            with self.assertRaisesRegex(TOOL.Refused, "current-reviewed-source-mismatch"):
                TOOL.current_runtime_command(args)
            extra.unlink()
            for output in (args.work, args.work / "nested", fixture.checkout / "new-output"):
                args.output = output
                with self.assertRaisesRegex(TOOL.Refused, "current-path-overlap"):
                    TOOL.current_runtime_command(args)
            args = self.args(fixture, "current-runtime", "occupied")
            args.work.mkdir(mode=0o700)
            with self.assertRaisesRegex(TOOL.Refused, "current-output-occupied"):
                TOOL.current_runtime_command(args)
            self.assertTrue(args.work.is_dir())
            args = self.args(fixture, "current-runtime", "parent-mode")
            fixture.root.chmod(0o755)
            try:
                with self.assertRaisesRegex(TOOL.Refused, "current-output-parent-owner-mode"):
                    TOOL.current_runtime_command(args)
            finally:
                fixture.root.chmod(0o700)
            prepare.assert_not_called()

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "requires the reviewed nonroot POSIX DATA test owner")
    def test_current_source_rejects_missing_unknown_or_linked_inputs(self):
        with current_data_fixture() as fixture:
            invalid = fixture.checkout / "src/mobile_release/generated.pyc"
            invalid.write_bytes(b"not source")
            with self.assertRaisesRegex(TOOL.Refused, "current-core-inputs"):
                TOOL.current_source()
            invalid.unlink()
            ca = fixture.checkout / TOOL.CURRENT_CA_SOURCE
            original = fixture.root / "original-ca"
            ca.rename(original)
            with self.assertRaises(FileNotFoundError):
                TOOL.current_source()
            ca.symlink_to(original)
            with self.assertRaisesRegex(TOOL.Refused, "ordinary-file-bound"):
                TOOL.current_source()
            ca.unlink()
            original.rename(ca)
            captured = TOOL.current_source()[0]
            helper = fixture.checkout / TOOL.CURRENT_HELPER_SOURCE
            helper.write_bytes(b"# changed helper DATA must not be evaluated\n")
            with mock.patch.object(TOOL.importlib.util, "spec_from_file_location") as loader:
                with self.assertRaisesRegex(TOOL.Refused, "current-helper-changed"):
                    TOOL.current_preparer(captured)
                loader.assert_not_called()

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "requires the reviewed nonroot POSIX DATA test owner")
    def test_complete_runtime_and_core_correspondence_reject_mutations(self):
        with current_data_fixture() as fixture:
            args = self.args(fixture)
            TOOL.current_runtime_command(args)
            _, projection, _ = TOOL.current_source()
            supplier = {name: (body, 0o555 if name == "python/bin/python3" else 0o444)
                        for name, body in fixture.supplier.items()}
            files = TOOL.tree(args.work / "runtime")
            changed = []
            missing = dict(files)
            del missing["python/licenses/notice.txt"]
            changed.append(missing)
            changed.append({**files, "unexpected.py": (b"extra", 0o600)})
            changed.append({**files, "python/bin/python3": (b"changed supplier", 0o555)})
            changed.append({**files, "python/bin/python3": (fixture.supplier["python/bin/python3"], 0o644)})
            changed.append({**files, "github-ca.pem": (b"stale CA", 0o600)})
            changed.append({**files, "core.zip": (files["core.zip"][0], 0o644)})
            for field, value in (("target", "x86_64-unknown-linux-gnu"), ("protocolSha256", "f" * 64)):
                manifest = TOOL.decode(files["manifest.json"][0])
                manifest[field] = value
                changed.append({**files, "manifest.json": (TOOL.canonical(manifest) + b"\n", 0o600)})
            for candidate in changed:
                with mock.patch.object(TOOL, "tree", return_value=candidate), self.assertRaises(TOOL.Refused):
                    TOOL.current_runtime_files(args.work / "runtime", projection, supplier)
            python_directory = args.work / "runtime/python"
            python_directory.chmod(0o700)
            try:
                with self.assertRaisesRegex(TOOL.Refused, "current-directory-mode-owner"):
                    TOOL.current_runtime_files(args.work / "runtime", projection, supplier)
            finally:
                python_directory.chmod(0o555)
            for candidate in ({name: value for name, value in projection.items() if not name.endswith("_desktop_engine.py")},
                              {**projection, "src/mobile_release/extra.py": (b"extra", 0o444)},
                              {**projection, "src/mobile_release/_desktop_engine.py":
                               (b"x" * len(projection["src/mobile_release/_desktop_engine.py"][0]), 0o444)}):
                with self.assertRaises(TOOL.Refused):
                    TOOL.current_core_matches(files["core.zip"][0], candidate)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "requires the reviewed nonroot POSIX DATA test owner")
    def test_manifest_mismatch_preserves_preparation_but_never_creates_final(self):
        with current_data_fixture() as fixture:
            args = self.args(fixture, "current-runtime", "wrong-manifest")
            args.expected_source = TOOL.current_source()[2]
            with self.assertRaisesRegex(TOOL.Refused, "current-reviewed-manifest-mismatch"):
                TOOL.current_runtime_command(args)
            self.assertTrue((args.work / "runtime/manifest.json").is_file())
            self.assertTrue((args.work / "source/desktop/github-ca.pem").is_file())
            self.assertFalse(args.output.exists())

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "requires the reviewed nonroot POSIX DATA test owner")
    def test_preparation_source_post_and_final_write_failures_stay_failed(self):
        with current_data_fixture() as fixture:
            captured, projection, source_digest = TOOL.current_source()
            preparer = TOOL.current_preparer(captured)
            args = self.args(fixture, "current-runtime", "prepare-failure")
            args.expected_source = source_digest
            def incomplete(source, runtime, target):
                (runtime / "partial-data").write_bytes(b"retained")
                raise ValueError("injected preparation failure")
            with mock.patch.object(TOOL, "current_preparer", return_value=SimpleNamespace(prepare_current=incomplete)):
                with self.assertRaises(ValueError):
                    TOOL.current_runtime_command(args)
            self.assertEqual((args.work / "runtime/partial-data").read_bytes(), b"retained")
            self.assertFalse(args.output.exists())
            self.assertEqual(TOOL.current_source(), (captured, projection, source_digest))
            args = self.args(fixture, "current-runtime", "projection-mode")
            args.expected_source = source_digest
            def writable_projection(source, runtime, target):
                result = preparer.prepare_current(source, runtime, target)
                (source / "desktop").chmod(0o700)
                return result
            with mock.patch.object(TOOL, "current_preparer", return_value=SimpleNamespace(prepare_current=writable_projection)):
                with self.assertRaisesRegex(TOOL.Refused, "current-directory-mode-owner"):
                    TOOL.current_runtime_command(args)
            self.assertFalse(args.output.exists())
            args = self.args(fixture, "current-runtime", "source-post")
            args.expected_source = source_digest
            original = fixture.checkout / "desktop/engine_bootstrap.py"
            def changed_source(source, runtime, target):
                result = preparer.prepare_current(source, runtime, target)
                original.write_bytes(b"# changed after captured source\n")
                return result
            with mock.patch.object(TOOL, "current_preparer", return_value=SimpleNamespace(prepare_current=changed_source)):
                with self.assertRaisesRegex(TOOL.Refused, "current-source-post-changed"):
                    TOOL.current_runtime_command(args)
            self.assertFalse(args.output.exists())
            original.write_bytes(fixture.inputs["desktop/engine_bootstrap.py"])
            description = TOOL.current_runtime_command(self.args(fixture))
            args = self.args(fixture, "current-runtime", "final-write")
            args.expected_source = source_digest
            args.expected_manifest = description["successorManifestSha256"]
            writer = TOOL.write_tree
            def incomplete_final(output, files, **options):
                if output == args.output:
                    output.mkdir(mode=0o700)
                    (output / "partial-data").write_bytes(b"retained final output")
                    raise OSError("injected final publication failure")
                return writer(output, files, **options)
            with mock.patch.object(TOOL, "write_tree", side_effect=incomplete_final):
                with self.assertRaises(OSError):
                    TOOL.current_runtime_command(args)
            self.assertEqual((args.output / "partial-data").read_bytes(), b"retained final output")
            self.assertTrue((args.work / "runtime/manifest.json").is_file())

    def test_new_cli_is_nonroot_and_does_not_change_historical_runtime_route(self):
        with mock.patch.object(TOOL.os, "getuid", return_value=0), mock.patch.object(TOOL, "current_runtime_command") as action:
            with self.assertRaisesRegex(TOOL.Refused, "only-installer-is-privileged"):
                TOOL.main(["describe-current-runtime", "--archive", "/a", "--work", "/w"])
            action.assert_not_called()
        with (mock.patch.object(TOOL.os, "getuid", return_value=501),
              mock.patch.object(TOOL.os, "geteuid", return_value=501),
              mock.patch.object(TOOL, "current_runtime_command", return_value={"data": True}) as current,
              mock.patch.object(TOOL, "runtime_command", return_value={"historical": True}) as historical,
              mock.patch.object(TOOL, "input_command", return_value={"input": True}) as inputs,
              contextlib.redirect_stdout(io.StringIO())):
            TOOL.main(["current-runtime", "--archive", "/a", "--work", "/w", "--expected-source", "a" * 64,
                       "--expected-manifest", "b" * 64, "--output", "/o"])
            args = current.call_args.args[0]
            self.assertEqual((args.archive, args.work, args.output), (Path("/a"), Path("/w"), Path("/o")))
            self.assertEqual((args.expected_source, args.expected_manifest), ("a" * 64, "b" * 64))
            historical.assert_not_called()
            TOOL.main(["runtime", "--archive", "/a", "--expected-manifest", "c" * 64, "--output", "/o"])
            historical.assert_called_once()
            current.assert_called_once()
            for current_profile, flags in ((False, []), (True, ["--current-runtime"])):
                TOOL.main(["input", "--package-role", "installed-shell-observation", "--app", "/app",
                           "--expected-entry", "a" * 64, "--expected-app-binary", "b" * 64, "--runtime", "/runtime",
                           "--expected-manifest", "d" * 64, "--expected-vault-helper", "f" * 64,
                           "--expected-android-helper", "e" * 64, "--expected-resident-image", "9" * 64,
                           "--output", "/input", *flags])
                self.assertIs(inputs.call_args.args[0].current_runtime, current_profile)
                self.assertEqual(inputs.call_args.args[0].expected_vault_helper, "f" * 64)
        for current_profile in (False, True):
            args = SimpleNamespace(runtime=Path("/inert-runtime"), expected_manifest="e" * 64,
                                   current_runtime=current_profile, package_role="installed-shell-observation",
                                   expected_android_helper="a" * 64, expected_resident_image="b" * 64)
            with mock.patch.object(TOOL, "runtime_tree", side_effect=RuntimeError("inert tree boundary")) as tree:
                with self.assertRaisesRegex(RuntimeError, "inert tree boundary"):
                    TOOL.input_command(args)
                tree.assert_called_once_with(args.runtime, args.expected_manifest, current=current_profile)

    def _assert_fresh_python_supplier_workflow(self, workflow):
        admission = workflow_step(workflow, "Admit only this exact disposable-hosted source route")
        self.assertIn("MRK_MACOS_RUNTIME_SUPPLIER: fresh-public-source", workflow)
        self.assertIn('"$MRK_MACOS_RUNTIME_SUPPLIER" == fresh-public-source', admission)
        self.assertIn('"$GITHUB_REPOSITORY" == Apdelrahman1911/mobile-release-kit', admission)
        fields = (
            ("SHA256", "receiptSha256", r"[0-9a-f]{64}"),
            ("TAR_SHA256", "tarSha256", r"[0-9a-f]{64}"),
            ("SOURCE_COMMIT", "source", r"[0-9a-f]{40}"),
            ("RUN_ID", "runId", r"[1-9][0-9]{0,15}"),
            ("RUN_ATTEMPT", "runAttempt", r"[1-9][0-9]{0,15}"),
            ("ARTIFACT_ID", "artifactId", r"[1-9][0-9]{0,15}"),
        )
        for suffix, field, pattern in fields:
            variable = "MRK_MACOS_PYTHON_SUPPLIER_" + suffix
            configured = TOOL.re.findall(r"^      " + variable + ": '(" + pattern + ")'$", workflow, TOOL.re.M)
            # No pending placeholder can become a successful source-bound check.
            self.assertEqual(len(configured), 1, variable)
            self.assertIn('"$' + variable + '" =~ ^' + pattern + '$', admission)
            self.assertIn('"$' + variable + '" == ' + configured[0], admission)
            if suffix in ("RUN_ID", "RUN_ATTEMPT", "ARTIFACT_ID"):
                self.assertLessEqual(int(configured[0]), 9007199254740991)
                self.assertIn('"$' + variable + '" -le 9007199254740991', admission)
            self.assertIn('"' + field + '": os.environ["' + variable + '"]', workflow)
        for fragment in ('"freshPythonSupplier": {',
                         '"origin": os.environ["MRK_MACOS_RUNTIME_SUPPLIER"]',
                         '"repository": "Apdelrahman1911/mobile-release-kit"',
                         '"workflow": ".github/workflows/desktop-macos-cpython-source-build.yml"',
                         '"ref": "refs/heads/verify/desktop-macos-cpython-source-build"'):
            self.assertIn(fragment, workflow)
        for forbidden in ("accepted-native-evidence.zip", "actions/artifacts/10639324707/zip",
                          '"reusedRun":', '"reusedArtifactId":', '"reusedSupplierOnly":'):
            self.assertNotIn(forbidden, workflow)
        names = (
            "Admit only a fresh independently pinned Python transport destination",
            "Download the independently accepted fresh Python transport",
            "Project the pinned fresh Python transport without executing it",
            "Prepare the current payload from the independently accepted fresh Python supplier",
        )
        steps = [workflow_step(workflow, name) for name in names]
        ordered = ["Bind the complete reviewed first-party checkout before compilation", *names,
                   "Build and sign the fixed resident image and C facades"]
        offsets = [workflow.index("      - name: " + name + "\n") for name in ordered]
        self.assertEqual(offsets, sorted(offsets))
        reserve, download, project, runtime = steps
        self.assertIn('[[ ! -e "$MRK_MACOS_WORK/fresh-python-transport" && ! -L "$MRK_MACOS_WORK/fresh-python-transport" ]] || exit 1', reserve)
        self.assertIn('[[ "$MRK_PYTHON" == /* && -x "$MRK_PYTHON" ]] || exit 1', reserve)
        self.assertEqual(workflow.count("uses: actions/download-artifact@"), 1)
        self.assertIn("uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", download)
        self.assertEqual([line.strip() for line in download.split("        with:\n", 1)[1].splitlines() if line.strip()], [
            "artifact-ids: ${{ env.MRK_MACOS_PYTHON_SUPPLIER_ARTIFACT_ID }}",
            "run-id: ${{ env.MRK_MACOS_PYTHON_SUPPLIER_RUN_ID }}",
            "repository: Apdelrahman1911/mobile-release-kit",
            "github-token: ${{ github.token }}",
            "path: ${{ steps.work.outputs.root }}/fresh-python-transport",
            "merge-multiple: 'false'", "digest-mismatch: error", "skip-decompress: 'false'",
        ])
        for block in (project, runtime):
            self.assertEqual(block.count("--target aarch64-apple-darwin"), 1)
            for fragment in ("timeout-minutes: 3", "set -euo pipefail", "set -o noclobber", "umask 077",
                             '/usr/bin/env -i PATH=/usr/bin:/bin HOME="$MRK_MACOS_WORK" TMPDIR="$MRK_MACOS_WORK" LANG=C LC_ALL=C TZ=UTC',
                             '"$MRK_PYTHON" -I -S -B'):
                self.assertEqual(block.count(fragment), 1, fragment)
            for forbidden in ("GH_TOKEN", "github.token", "--archive", "|| true", "set +e"):
                self.assertNotIn(forbidden, block)
        for fragment in ("desktop/tools/macos_python_supplier_transport.py",
                         '--transport-root "$MRK_MACOS_WORK/fresh-python-transport"',
                         '--expected-supplier "$MRK_MACOS_PYTHON_SUPPLIER_SHA256"',
                         '--expected-tar "$MRK_MACOS_PYTHON_SUPPLIER_TAR_SHA256"',
                         '--python-output "$MRK_MACOS_WORK/fresh-python-supplier"',
                         '--receipt-root "$MRK_MACOS_WORK/fresh-python-receipt"',
                         '> "$MRK_MACOS_WORK/fresh-python-transport-result.json"'):
            self.assertEqual(project.count(fragment), 1, fragment)
        for fragment in ('--python-root "$MRK_MACOS_WORK/fresh-python-supplier"',
                         '--supplier-receipt "$MRK_MACOS_WORK/fresh-python-receipt/supplier-receipt.json"',
                         '--expected-supplier "$MRK_MACOS_PYTHON_SUPPLIER_SHA256"'):
            self.assertEqual(runtime.count(fragment), 1, fragment)
        self.assertEqual(workflow.count("            ${{ steps.work.outputs.root }}/fresh-python-transport-result.json\n"), 1)
        for path in ("fresh-python-transport", "fresh-python-supplier", "fresh-python-receipt"):
            self.assertNotIn("            ${{ steps.work.outputs.root }}/" + path + "/", workflow)
        return steps


    def test_aqua_uses_reviewed_current_source_data_before_compilation(self):
        workflow = (Path(__file__).absolute().parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        runtime_name = "Prepare the current payload from the independently accepted fresh Python supplier"
        build_name = "Compile the fixed debug actual-main observer and normal embedded frontend once"
        runtime = workflow_step(workflow, runtime_name)
        build = workflow_step(workflow, build_name)
        self.assertEqual(runtime.count("desktop/tools/stage_macos_installed.py current-runtime"), 1)
        self.assertLess(workflow.index("      - name: " + runtime_name + "\n"),
                        workflow.index("      - name: " + build_name + "\n"))
        self.assertIn("npm ci --ignore-scripts", build)
        self.assertIn("npm run build", build)
        self.assertIn("cargo test --locked --no-default-features --features desktop-shell,custom-protocol,macos-installed-observation", build)
        self.assertIn("--test installed-shell-observation --no-run --message-format=json", build)
        self.assertIn('--work "$MRK_MACOS_WORK/current-runtime-preparation"', workflow)
        self.assertIn('--expected-source "$MRK_BUNDLED_RUNTIME_SOURCE_SHA256"', workflow)
        self.assertIn('--expected-manifest "$MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"', workflow)
        for variable in ("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256", "MRK_BUNDLED_RUNTIME_SOURCE_SHA256"):
            literal = TOOL.re.search(r"^      " + variable + r": ([a-z0-9-]+)$", workflow, TOOL.re.M).group(1)
            self.assertTrue(TOOL.sha(literal))
            self.assertIn('"$' + variable + '" =~ ^[0-9a-f]{64}$', workflow)
            self.assertIn('"$' + variable + '" == ' + literal, workflow)
        fresh_steps = self._assert_fresh_python_supplier_workflow(workflow)
        expected_scopes = ("project-fields", "ios-current-synthetic", "android-inputs", "project-fields-android-inputs",
                           "vault-helper-shipping", "installation-inspection", "vault-helper-shipping-installation-inspection",
                           "project-recovery-pending", "ios-recovery-pending", "doctor-preflight2", "local-edits3")
        expected_condition = "if: success() && (" + " || ".join("env.MRK_MACOS_AQUA_SCOPE == '" + scope + "'" for scope in expected_scopes) + ")"
        for step in fresh_steps:
            conditions = [line.strip() for line in step.splitlines() if line.strip().startswith("if:")]
            self.assertEqual(conditions, [expected_condition])
        # This workflow now selects explicit current scopes; it does not run or
        # qualify the historical four merely by staging the current payload.
        binding = workflow_step(workflow, "Record exact source and actual tool bindings only after route admission")
        self.assertIn('"scopes": selected_scopes, "caseNames": case_names', binding)
        self.assertIn('"unselectedScopes": [scope for scope in native_scopes if scope not in selected_scopes]', binding)
        self.assertIn('"actualAquaSaveGate": "not-yet-executed"', binding)
        for scope, name in (
                ("project-fields", "One project-field Aqua journey through the reviewed original invocation owner"),
                ("android-inputs", "One Android-input Aqua journey through the reviewed original invocation owner"),
                ("ios-current-synthetic", "Nine serial current-iOS Aqua cases through the reviewed original invocation owner")):
            journey = workflow_step(workflow, name)
            self.assertEqual(journey.count("desktop/tools/macos_aqua_qualification.py --scope " + scope + " "), 1)
            self.assertIn("env.MRK_MACOS_AQUA_SCOPE == '" + scope + "'", journey)
            self.assertIn("[[ $status == 0 ]]", journey)
        aqua_owner = (Path(__file__).absolute().parents[2] / "desktop/tools/macos_aqua_qualification.py").read_text(encoding="utf-8")
        self.assertIn('CASES = ("first-save", "noop-stale", "picker-loss", "save-loss")', aqua_owner)
        self.assertIn('return IOS_CASES if scope == "ios-unsigned-archive" else CASES', aqua_owner)

    def test_ordinary_workflow_binds_reviewed_current_payload_before_normal_release(self):
        root = Path(__file__).absolute().parents[2]
        workflow = (root / ".github/workflows/desktop-macos-installed.yml").read_text(encoding="utf-8")
        anchors = {}
        for variable in ("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256", "MRK_BUNDLED_RUNTIME_SOURCE_SHA256",
                         "MRK_BUNDLED_PROTOCOL_SHA256"):
            configured = TOOL.re.findall(r"^      " + variable + r": ([0-9a-f]{64})$", workflow, TOOL.re.M)
            self.assertEqual(len(configured), 1, variable)
            anchors[variable] = configured[0]
            self.assertIn('"$' + variable + '" =~ ^[0-9a-f]{64}$', workflow)
            self.assertIn('"$' + variable + '" == ' + configured[0], workflow)
        # Read the actual bounded source DATA used by the stager, not a copy of
        # its historical pin. No core import, supplier extraction or execution.
        self.assertEqual(anchors["MRK_BUNDLED_RUNTIME_SOURCE_SHA256"], TOOL.current_source()[2])
        # The manifest pin still needs independent runtime-regeneration evidence.
        # Its format, guards and CLI binding here do not establish its authority.
        self.assertEqual(TOOL.CURRENT_PROTOCOL, anchors["MRK_BUNDLED_PROTOCOL_SHA256"])
        self.assertNotEqual(TOOL.PROTOCOL, anchors["MRK_BUNDLED_PROTOCOL_SHA256"])
        for field, variable in (("runtimeManifestSha256", "MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"),
                                ("runtimeSourceInputsSha256", "MRK_BUNDLED_RUNTIME_SOURCE_SHA256"),
                                ("protocolSha256", "MRK_BUNDLED_PROTOCOL_SHA256")):
            self.assertIn('"' + field + '": os.environ["' + variable + '"]', workflow)
        for step in self._assert_fresh_python_supplier_workflow(workflow):
            self.assertNotIn("\n        if:", step)
        command = "desktop/tools/stage_macos_installed.py current-runtime"
        self.assertEqual(workflow.count(command), 1)
        runtime_name = "Prepare the current payload from the independently accepted fresh Python supplier"
        build_name = "Build the ordinary ARM64 desktop image and embedded frontend"
        block = workflow_step(workflow, runtime_name)
        build = workflow_step(workflow, build_name)
        self.assertEqual(block.count(command), 1)
        self.assertLess(workflow.index("      - name: " + runtime_name + "\n"),
                        workflow.index("      - name: " + build_name + "\n"))
        self.assertIn("npm ci --ignore-scripts", build)
        self.assertIn("cargo build --locked --release --manifest-path ../helpers/macos-desktop-image/Cargo.toml --lib", build)
        for fragment in ("timeout-minutes: 3", "set -o noclobber", "umask 077",
                         '--python-root "$MRK_MACOS_WORK/fresh-python-supplier"',
                         '--supplier-receipt "$MRK_MACOS_WORK/fresh-python-receipt/supplier-receipt.json"',
                         '--expected-supplier "$MRK_MACOS_PYTHON_SUPPLIER_SHA256"',
                         '--work "$MRK_MACOS_WORK/current-runtime-preparation"',
                         '--expected-source "$MRK_BUNDLED_RUNTIME_SOURCE_SHA256"',
                         '--expected-manifest "$MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"',
                         '--output "$MRK_MACOS_WORK/runtime" > "$MRK_MACOS_WORK/runtime-result.json"'):
            self.assertEqual(block.count(fragment), 1, fragment)
        for subcommand in ("runtime ", "describe-runtime", "describe-current-runtime"):
            self.assertNotIn("desktop/tools/stage_macos_installed.py " + subcommand, workflow)
        command = "desktop/tools/stage_macos_installed.py input"
        self.assertEqual(workflow.count(command), 1)
        inputs = workflow.split(command, 1)[1].split('inventory=$', 1)[0]
        self.assertEqual(inputs.count("--current-runtime"), 1)
        self.assertIn('--runtime "$MRK_MACOS_WORK/runtime"', inputs)
        self.assertIn('--expected-manifest "$MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"', inputs)
        self.assertIn('--output "$MRK_MACOS_WORK/input"', inputs)

    def test_native_action_roster_and_independent_publisher_bindings(self):
        root = Path(__file__).absolute().parents[2]
        publisher = "b4cb582837a244f67e4c926f2ce2bb42ad8cfe37"
        fields = (("githubPreflightToolingSha", "MRK_GITHUB_PREFLIGHT_TOOLING_SHA"),
                  ("githubReleaseToolingSha", "MRK_GITHUB_RELEASE_TOOLING_SHA"))
        for filename in ("desktop-macos-installed.yml", "desktop-macos-aqua.yml"):
            workflow = (root / ".github/workflows" / filename).read_text()
            admission = workflow_step(workflow, "Admit only this exact disposable-hosted source route")
            for field, variable in fields:
                self.assertEqual(TOOL.re.findall(r"^      " + variable + r": ([0-9a-f]{40})$", workflow, TOOL.re.M), [publisher])
                self.assertIn('"$' + variable + '" =~ ^[0-9a-f]{40}$', admission)
                self.assertIn('"$' + variable + '" == ' + publisher, admission)
                self.assertIn('"' + field + '": os.environ["' + variable + '"]', workflow)
            # Digests must be generated from the actual templates, not provided
            # by CI alongside a different source/application commit.
            for generated in ("MRK_GITHUB_PREFLIGHT_CALLER_SHA256", "MRK_GITHUB_RELEASE_CANDIDATE_SHA256",
                              "MRK_GITHUB_RELEASE_EXTERNAL_SHA256", "MRK_GITHUB_RELEASE_PRODUCTION_SHA256"):
                self.assertNotIn(generated + ":", workflow)
        build = (root / "desktop/src-tauri/build.rs").read_text()
        for _, selector in fields:
            self.assertIn('const SELECTOR: &str = "' + selector + '";', build)
        self.assertEqual(build.count("Sha256::digest(caller.as_bytes())"), 2)
        for template in ("mobile-preflight.yml", "mobile-candidate.yml", "mobile-external-testing.yml", "mobile-production-submit.yml"):
            self.assertIn('include_str!("../../templates/workflows/' + template + '")', build)

        workflow = (root / ".github/workflows/desktop-macos-installed.yml").read_text()
        data = workflow_step(workflow, "Compile and run only fixed native DATA contracts and exact host-Python regressions")
        names = ast.literal_eval(TOOL.re.search(r"          names = (\[\n.*?\n          \])\n", data, TOOL.re.S).group(1))
        digest = lambda selected: TOOL.digest(TOOL.json.dumps(selected, separators=(",", ":")).encode())
        self.assertEqual(len(names), 84)
        self.assertEqual(len(set(names)), 84)
        self.assertEqual(digest(names[:57]), "4a5c62f00838d17f54e0970c209fc44a2b5708314e39437dbb156a25ac42ffa6")
        self.assertEqual(digest(names[57:79]), "f14c3263aadbdaeb0e7d21c821784902289552eb431ce3448726c6631064bfd5")
        self.assertEqual(digest(names[:81]), "293426d49f6bb226563ea325527858b894aa98ac2e72dea6b70875157cfd58e4")
        self.assertEqual(digest(names[:82]), "1cf265f8c97381708d68c1dedc8bc61ebcaf182c104d3021bda8b8211f016d65")
        self.assertEqual(digest(names), "0fd968d2c78e233df8cc344ae3ff27d417bd3c76fb5bde42b3ea8d393f8e7a94")
        self.assertEqual(data.count(digest(names)), 2)
        self.assertEqual(names[79:81], [
            'test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_diagnostics_observes_original_complete_report_and_settled_projection',
            'test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_diagnostics_workflow_has_one_bounded_original_result',
        ])
        self.assertEqual(names[81:82], ['test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_saved_offline_and_empty_recovery_use_original_gui_only'])
        self.assertEqual(names[82:], [
            'test_android_build_tools.MacToolAdmissionDataTests.test_mac_commands_use_exact_contents_home_private_environment_and_inspection_only',
            'test_android_build_tools.OwnerAndCommandDataTests.test_bundletool_requires_original_native_borrow_and_exact_snapshot',
        ])
        sources = ast.literal_eval(TOOL.re.search(r"          source_names = (\(\n.*?\n          \))\n", data, TOOL.re.S).group(1))
        self.assertEqual(len(sources), 77)
        self.assertEqual(len(sources), len(set(sources)))
        self.assertEqual(digest(sources[:53]), "5d544a55d63d5ac1f14f341b0ba51509c6c77e762e2f7e7c964fc9f87ec44bf4")
        self.assertEqual(sources[64:69], (
            "desktop/macos-installed-inputs/build-release.json",
            "desktop/src-tauri/src/macos_build_release.rs",
            "desktop/src-tauri/src/macos_install_fixed_paths.rs",
            "desktop/src-tauri/src/macos_install_paths.rs",
            "desktop/src-tauri/tauri.conf.json",
        ))
        self.assertEqual(sources[69:], (
            "tests/desktop/test_android_build_tools.py",
            "src/mobile_release/android_build_tools.py",
            "src/mobile_release/android_build_tools_macos.py",
            "src/mobile_release/android_build_operation.py",
            "src/mobile_release/_desktop_android_build_files.py",
            "src/mobile_release/android.py",
            "src/mobile_release/credentials.py",
            "src/mobile_release/local_signing.py",
        ))
        for name in names[57:]:
            module, cls, method = name.split(".")
            path = "tests/desktop/" + module + ".py"
            self.assertIn(path, sources)
            definitions = ast.parse((root / path).read_text())
            owner = next(node for node in definitions.body if isinstance(node, ast.ClassDef) and node.name == cls)
            self.assertIn(method, [node.name for node in owner.body if isinstance(node, ast.FunctionDef)])
        for fragment in ('len(names) != 84 or len(set(names)) != 84', 'suite.countTestCases() != 84',
                         'facts["testsRun"] == 84', 'counts.get("testsRun") != 84', '"pythonExpectedCount": 84',
                         '"workflowFilesystemCount": 2', '"imageFilesystemCount": 18', '"evidenceReaderCount": 37',
                         '"githubActionCount": 22', '"test_github_preflight_frames", "test_github_preflight", "test_github_release"'):
            self.assertIn(fragment, data)
        self.assertIn('"normalDiagnosticsSourceCount": 3', data)
        self.assertIn('"androidBuildToolsCallerCount": 2', data)
        self.assertIn('"test_macos_normal_diagnostics_source"', data)
        self.assertIn('"test_android_build_tools"', data)
        for path in ("desktop/github_preflight_bootstrap.py", "desktop/github_release_bootstrap.py",
                     "src/mobile_release/github_preflight.py", "src/mobile_release/github_release.py",
                     "src/mobile_release/_github_action_family.py", "src/mobile_release/_desktop_github_preflight_engine.py"):
            self.assertIn(path, sources)

    def test_ordinary_current_route_preserves_separate_installer_and_aqua_obligations(self):
        root = Path(__file__).absolute().parents[2]
        workflow = (root / ".github/workflows/desktop-macos-installed.yml").read_text(encoding="utf-8")
        normal = "cargo build --locked --release --manifest-path ../helpers/macos-desktop-image/Cargo.toml --lib"
        build, assembly, inputs = normal_app_steps(workflow)
        self.assertEqual(workflow.count(normal), 1)
        self.assertEqual(build.count(normal + " \\\n"), 1)
        self.assertIn('--binary "$MRK_MACOS_WORK/mobile-release-kit-desktop"', assembly)
        self.assertIn('--expected-app-binary "$MRK_MACOS_DESKTOP_FACADE_SHA256"', assembly)
        self.assertIn('--desktop-image "$CARGO_TARGET_DIR/aarch64-apple-darwin/release/libmrk_desktop_image.dylib"', assembly)
        self.assertIn('--expected-desktop-image "$MRK_MACOS_DESKTOP_IMAGE_SHA256"', assembly)
        self.assertIn('--expected-desktop-image "$MRK_MACOS_SIGNED_DESKTOP_IMAGE_SHA256"', inputs)
        self.assertIn("MRK_IMAGE_RELEASE_ID: $" + "{{ steps.android_helper.outputs['image-release-id'] }}", build)
        self.assertIn('--desktop-image-cargo-messages "$MRK_MACOS_WORK/normal-build.jsonl"', assembly)
        self.assertIn('--app "$MRK_MACOS_WORK/app/Mobile Release Kit.app"', inputs)
        # The preview's separate debug DATA contract is not the shipped binary.
        data = workflow_step(workflow, "Compile and run only fixed native DATA contracts and exact host-Python regressions")
        self.assertEqual(workflow.count("macos-installed-observation"), data.count("macos-installed-observation"))
        self.assertEqual(data.count("macos-installed-observation"), 1)
        self.assertIn('"--features", "desktop-shell,custom-protocol,macos-installed-observation"', data)
        self.assertIn('"--test", "installed-shell-observation", "--no-run", "--message-format=json"', data)
        self.assertIn('argv = [str(artifact), "data-contracts"]', data)
        self.assertIn('artifact.parent != root / "cargo-target/aarch64-apple-darwin/debug/deps"', data)
        for block in (build, assembly, inputs):
            for forbidden in ("macos-installed-observation", "installed_shell_observation", "development-runtime"):
                self.assertFalse(forbidden in block, "normal shipping step: " + forbidden)
        for forbidden in ("development-runtime", "macos_aqua_qualification.py", "--scope "):
            self.assertFalse(forbidden in workflow, forbidden)
        self.assertIn("refs/heads/verify/desktop-macos-installed", workflow)
        self.assertIn("$GITHUB_REPOSITORY/.github/workflows/desktop-macos-installed.yml@$GITHUB_REF", workflow)
        self.assertIn('"fixedFixtureCases": 8', workflow)
        self.assertIn('"aclPrimitiveCases": 6', workflow)
        self.assertIn('"selectedRegressionGroups": [2, 1, 2]', workflow)
        self.assertIn('"actualAquaSaveGate": "pending"', workflow)
        self.assertIn("same-request readback and known detach permit use", workflow)
        fixture = workflow.index('sudo -- /usr/sbin/installer -pkg "$MRK_MACOS_WORK/package-fixture-final/MobileReleaseKit-InstallerFixture.pkg"')
        fixture_readback = workflow.index("desktop/tools/stage_macos_installed.py observe-installer-fixture")
        ordinary = workflow.index("macos_android_helper_package.py package-install")
        ordinary_readback = workflow.index('"$package_status_saved" == 0', ordinary)
        fixture_build = workflow.index(
            "cargo build --locked --release --no-default-features --features macos-installed-installer-fixture ")
        ordinary_build = workflow.index(
            "cargo build --locked --release --no-default-features --features macos-installed-installer ")
        self.assertLess(fixture_build, fixture)
        self.assertLess(fixture, fixture_readback)
        self.assertLess(fixture_readback, ordinary_build)
        self.assertLess(ordinary_build, ordinary)
        self.assertLess(ordinary, ordinary_readback)
        self.assertEqual(workflow.count("sudo -- /usr/sbin/installer -pkg "), 1)
        for stem in ("installer-fixture",):
            self.assertIn('--installer-status "$MRK_MACOS_WORK/' + stem + '-output.status"', workflow)
        for path in ("runtime-result.json", "input-result.json", "installer-fixture-observation.json", "installation-observation.json"):
            self.assertIn("$" + "{{ steps.work.outputs.root }}/" + path, workflow)
        guide = (root / "desktop/packaging/macos-installed.md").read_text(encoding="utf-8")
        self.assertIn("ordinary4 remains a separate later obligation", guide)
        self.assertIn("No normal P2/project-picker qualification bit is enabled", guide)



def android_support_fixture(root=Path("/synthetic-mrk-support")):
    # Tiny inert ZIP inputs under a replaced SOURCE manifest, never vendor code.
    rows, values, files, archives = [], {}, {}, []
    for identity, filename, url, members in TOOL.ANDROID_SUPPORT_LAYOUT:
        notices = []
        buffer = io.BytesIO()
        with TOOL.zipfile.ZipFile(buffer, "w", compression=TOOL.zipfile.ZIP_DEFLATED) as archive:
            for member in members:
                body = ("Synthetic public notice: " + identity + "/" + member + "\n").encode()
                archive.writestr(member, body)
                path = TOOL.ANDROID_SUPPORT_PREFIX + "notices/" + identity + "/" + member
                notices.append({"member": member, "resourcePath": path, "size": len(body), "sha256": TOOL.digest(body)})
                files[path] = (body, 0o644)
        body = buffer.getvalue(); path = root / filename
        values[path] = body; archives.append(path)
        resource = TOOL.ANDROID_SUPPORT_PREFIX + filename
        files[resource] = (body, 0o644)
        rows.append({"id": identity, "fileName": filename, "resourcePath": resource, "url": url,
                     "size": len(body), "sha256": TOOL.digest(body), "notices": notices})
    manifest = {"schemaVersion": 1, "platform": "macos", "archives": rows}
    manifest_path = root / "android-support.json"
    values[manifest_path] = TOOL.canonical(manifest)
    return SimpleNamespace(manifest=manifest, manifest_path=manifest_path, values=values, files=files,
                           bundletool_archive=archives[0], aapt2_archive=archives[1])


def normal_cargo_fixture(target=None, *, role="desktop", checkout=None, build_target="aarch64-apple-darwin"):
    # Keep the existing ordinary fixture seam, but bind the real image graph.
    target = target or Path("/synthetic-mrk-preview/cargo-target")
    desktop = checkout / "desktop" if checkout is not None else TOOL.DESKTOP
    name = "mrk_desktop_image" if role == "desktop" else "mrk_resident_image"
    package = "mrk-desktop-image" if role == "desktop" else "mrk-android-register"
    root = desktop / "helpers" / ("macos-desktop-image" if role == "desktop" else "macos-android-register")
    binary = target / build_target / "release" / ("lib" + name + ".dylib")
    profile = {"opt_level": "3", "debug_assertions": False, "test": False}
    artifact = {"reason": "compiler-artifact", "package_id": "path+" + root.as_uri() + "#" + package + "@0.1.0",
        "manifest_path": str(root / "Cargo.toml"), "target": {"name": name, "kind": ["cdylib"],
            "crate_types": ["cdylib"], "src_path": str(root / "src/lib.rs"), "edition": "2021"},
        "profile": dict(profile), "features": [], "filenames": [str(binary)], "executable": None, "fresh": False}
    rows = [artifact]
    app_features = (["custom-protocol", "desktop-shell", "macos-installed-desktop-image"] if role == "desktop"
                    else ["macos-android-registration-helper", "macos-installed-resident-image"])
    native_features = (["default", "desktop-image"] if role == "desktop"
                       else ["android-registration-helper", "default", "resident-image"])
    for directory, package, name, features in (
        (desktop / "src-tauri", "mobile-release-kit-desktop", "mobile_release_desktop", app_features),
        (desktop / "native/macos-installed-native", "mrk-macos-installed-native", "mrk_macos_installed_native", native_features),
    ):
        rows.append({"reason": "compiler-artifact", "package_id": "path+" + directory.as_uri() + "#" + package + ("@0.1.1" if package == "mobile-release-kit-desktop" else "@0.1.0"),
            "manifest_path": str(directory / "Cargo.toml"), "features": features,
            "target": {"name": name, "kind": ["lib"], "crate_types": ["lib"],
                       "src_path": str(directory / "src/lib.rs"), "edition": "2021"},
            "profile": dict(profile), "filenames": [str(binary.parent / "deps" / ("lib" + name + "-0123456789abcdef.rlib"))],
            "executable": None, "fresh": False})
    return target, binary, rows, image_macho_fixture(role, target=build_target)


def observer_cargo_fixture(target=None):
    target, _image, rows, _body = normal_cargo_fixture(target)
    root = TOOL.DESKTOP / "src-tauri"
    binary = target / "aarch64-apple-darwin/debug/deps/installed_shell_observation-0123456789abcdef"
    features = ["custom-protocol", "desktop-shell", "macos-installed-observation"]
    rows[0] = {"reason": "compiler-artifact", "package_id": "path+" + root.as_uri() + "#mobile-release-kit-desktop@0.1.1",
        "manifest_path": str(root / "Cargo.toml"), "features": list(features),
        "target": {"name": "installed-shell-observation", "kind": ["test"], "crate_types": ["bin"],
                   "src_path": str(root / "tests/installed_shell_observation.rs"), "edition": "2021"},
        "profile": {"opt_level": "0", "debug_assertions": True, "test": True},
        "filenames": [str(binary)], "executable": str(binary), "fresh": False}
    for row, selected in zip(rows[1:], (features, ["default", "installed-observation"])):
        row["features"] = list(selected)
        row["profile"] = {"opt_level": "0", "debug_assertions": True, "test": False}
        name = row["target"]["name"]
        row["filenames"] = [str(binary.parent / ("lib" + name + "-0123456789abcdef.rlib"))]
    return target, binary, rows, entry_macho_fixture() + b"observer-only-inert-DATA"


def cargo_lines(*items):
    return b"".join(TOOL.canonical(item) + b"\n" for item in items)


@unittest.skipUnless(TOOL is not None, "POSIX DATA definitions only")
class MacAndroidSupportData(unittest.TestCase):
    def test_source_recipe_is_closed_and_not_a_user_download_configuration(self):
        source_sha, rows = TOOL.android_support_manifest()
        self.assertEqual(source_sha, TOOL.digest(TOOL.ANDROID_SUPPORT_MANIFEST.read_bytes()))
        self.assertEqual([row["id"] for row in rows], ["bundletool", "aapt2"])
        self.assertEqual(sum(row["size"] for row in rows), 36859873)
        self.assertEqual(sum(n["size"] for row in rows for n in row["notices"]), 182223)
        good = android_support_fixture().manifest
        mutations = [lambda v: v.update(extra=True), lambda v: v.update(schemaVersion=True),
            lambda v: v["archives"].reverse(), lambda v: v["archives"][0].update(url="https://untrusted.invalid/tool"),
            lambda v: v["archives"][0].update(size=True), lambda v: v["archives"][0].update(sha256="A" * 64),
            lambda v: v["archives"][0]["notices"][0].update(resourcePath="../LICENSE"),
            lambda v: v["archives"][0]["notices"][0].update(size=1024 * 1024 + 1)]
        for change in mutations:
            value = TOOL.decode(TOOL.canonical(good)); change(value)
            with mock.patch.object(TOOL, "read", return_value=TOOL.canonical(value)), self.assertRaises(TOOL.Refused):
                TOOL.android_support_manifest()

    def test_original_archives_and_notices_are_nonexecuting_data_with_exact_readback(self):
        fixture = android_support_fixture()
        with mock.patch.object(TOOL, "ANDROID_SUPPORT_MANIFEST", fixture.manifest_path), \
                mock.patch.object(TOOL, "read", side_effect=lambda path, *_: fixture.values[path]), \
                mock.patch.object(TOOL, "write_tree") as output:
            source_sha, files = TOOL.android_support_files(fixture)
            self.assertEqual(files, fixture.files)
            # Producer resources are payload-relative; readback sees the assembled app.
            app_files = {TOOL.PAYLOAD_RELATIVE + "/" + name: value for name, value in files.items()}
            self.assertEqual(TOOL.android_support_input(app_files), source_sha)
            with self.assertRaisesRegex(TOOL.Refused, "^android-support-roster$"):
                TOOL.android_support_input(files)
            result = TOOL.android_support_command(fixture)
            self.assertEqual(result["androidSupportManifestSha256"], source_sha)
            self.assertEqual(result["fileCount"], 10)
            self.assertEqual(result["payloadBytes"], sum(len(body) for body, _ in files.values()))
            self.assertEqual({mode for _, mode in files.values()}, {0o644})
            output.assert_not_called()

    def test_archive_identity_is_checked_before_any_zip_parsing(self):
        for change in (lambda b: b + b"extra", lambda b: bytes([b[0] ^ 1]) + b[1:]):
            fixture = android_support_fixture()
            fixture.values[fixture.bundletool_archive] = change(fixture.values[fixture.bundletool_archive])
            with mock.patch.object(TOOL, "ANDROID_SUPPORT_MANIFEST", fixture.manifest_path), \
                    mock.patch.object(TOOL, "read", side_effect=lambda path, *_: fixture.values[path]), \
                    mock.patch.object(TOOL.zipfile, "ZipFile") as parser, self.assertRaisesRegex(TOOL.Refused, "android-support-archive"):
                TOOL.android_support_files(fixture)
            parser.assert_not_called()

    def test_missing_duplicate_or_changed_notice_refuses_before_any_app_output(self):
        for failure in ("missing", "duplicate", "changed"):
            fixture = android_support_fixture()
            first = fixture.manifest["archives"][0]
            buffer = io.BytesIO()
            with TOOL.zipfile.ZipFile(buffer, "w", compression=TOOL.zipfile.ZIP_DEFLATED) as archive:
                for index, notice in enumerate(first["notices"]):
                    data = fixture.files[notice["resourcePath"]][0]
                    if index == 0 and failure == "missing":
                        continue
                    if index == 0 and failure == "changed":
                        data = b"!" + data[1:]
                    archive.writestr(notice["member"], data)
                    if index == 0 and failure == "duplicate":
                        with self.assertWarns(UserWarning):
                            archive.writestr(notice["member"], data)
            archive_bytes = buffer.getvalue()
            first.update(size=len(archive_bytes), sha256=TOOL.digest(archive_bytes))
            fixture.values[fixture.bundletool_archive] = archive_bytes
            fixture.values[fixture.manifest_path] = TOOL.canonical(fixture.manifest)
            target, binary, rows, body = normal_cargo_fixture()
            helper, facade = Path("/synthetic-mrk-support/helper"), Path("/synthetic-mrk-support/facade")
            resident = Path("/synthetic-mrk-support/resident.dylib")
            cargo = Path("/synthetic-mrk-support/desktop-image.jsonl")
            code = entry_macho_fixture()
            fixture.values.update({binary: body, helper: code, facade: code, resident: image_macho_fixture("resident"),
                                   Path("/synthetic-mrk-support/entry"): code,
                                   cargo: cargo_lines(*rows, {"reason": "build-finished", "success": True})})
            args = SimpleNamespace(package_role="ordinary-image", binary=facade, expected_app_binary=TOOL.digest(code),
                desktop_image=binary, expected_desktop_image=TOOL.digest(body),
                desktop_image_cargo_messages=cargo, desktop_image_cargo_target_dir=target,
                vault_helper=helper, expected_vault_helper=TOOL.digest(code),
                android_helper=helper, expected_android_helper=TOOL.digest(code),
                resident_image=resident, expected_resident_image=TOOL.digest(fixture.values[resident]),
                entry_binary=Path("/synthetic-mrk-support/entry"), expected_entry=TOOL.digest(code),
                output=Path("/synthetic-mrk-support/app"), bundletool_archive=fixture.bundletool_archive,
                aapt2_archive=fixture.aapt2_archive)
            original_read = TOOL.read
            with self.subTest(failure=failure), mock.patch.object(TOOL, "ANDROID_SUPPORT_MANIFEST", fixture.manifest_path), \
                    mock.patch.object(TOOL, "read", side_effect=lambda path, *limit: fixture.values[path] if path in fixture.values else original_read(path, *limit)), \
                    mock.patch.object(TOOL, "write_tree") as output, self.assertRaisesRegex(TOOL.Refused, "android-support-notice"):
                TOOL.app_command(args)
            output.assert_not_called()

    def test_both_explicit_archive_arguments_are_required_and_never_discovered(self):
        for command, rest in (("android-support", []), ("app", ["--package-role", "ordinary-image", "--binary", "/a",
                "--expected-app-binary", "b" * 64, "--entry-binary", "/inert/entry", "--expected-entry", "b" * 64,
                "--vault-helper", "/h", "--expected-vault-helper", "a" * 64,
                "--android-helper", "/resident-facade", "--expected-android-helper", "c" * 64,
                "--resident-image", "/resident.dylib", "--expected-resident-image", "d" * 64, "--output", "/out"])):
            for absent in ("--bundletool-archive", "--aapt2-archive"):
                flags = ["--aapt2-archive", "/aapt2"] if absent == "--bundletool-archive" else ["--bundletool-archive", "/bundletool"]
                stderr = io.StringIO()
                action_name = "app_command" if command == "app" else "android_support_command"
                with mock.patch.object(TOOL, action_name) as action, mock.patch.object(TOOL, "read") as reader, \
                        contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as stopped:
                    TOOL.main([command, *rest, *flags])
                self.assertEqual(stopped.exception.code, 2)
                self.assertTrue(stderr.getvalue().endswith("error: the following arguments are required: " + absent + "\n"))
                action.assert_not_called()
                reader.assert_not_called()

    def test_workflows_download_fixed_originals_without_configuration_or_credentials(self):
        root = Path(__file__).absolute().parents[2]
        _, rows = TOOL.android_support_manifest()
        name = "Acquire and verify the two fixed Android support archives as DATA"
        for filename, assembly in (("desktop-macos-installed.yml", "Assemble the ordinary image app and sign code inside-out (never --deep)"),
                                   ("desktop-macos-aqua.yml", "Assemble the instrumented observation app with SOURCE-selected signing")):
            workflow = (root / ".github/workflows" / filename).read_text()
            block = workflow_step(workflow, name)
            self.assertIn("shell: /usr/bin/env -i /bin/bash --noprofile --norc -e -o pipefail {0}", block)
            self.assertEqual(block.count("/usr/bin/env -i PATH=/usr/bin:/bin HOME=\"$work\""), 3)
            self.assertEqual(block.count("/usr/bin/curl -q --fail --silent --show-error --location --max-redirs 3"), 2)
            self.assertEqual(block.count("--proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 90"), 2)
            self.assertIn("set -o noclobber", block)
            self.assertIn("umask 077", block)
            for flag, row in zip(("bundletool", "aapt2"), rows):
                self.assertIn("--url '" + row["url"] + "'", block)
                self.assertIn("--max-filesize " + str(row["size"]), block)
                self.assertIn('> "$work/' + row["fileName"] + '"', block)
                self.assertIn('--' + flag + '-archive "$work/' + row["fileName"] + '"', block)
                self.assertIn('--' + flag + '-archive "$MRK_MACOS_WORK/' + row["fileName"] + '"', workflow_step(workflow, assembly))
            for forbidden in ("GH_TOKEN", "github.token", "--retry", "--netrc", "--insecure", "--location-trusted", "java "):
                self.assertNotIn(forbidden, block)
            self.assertIn("stage_macos_installed.py android-support", block)
            self.assertLess(workflow.index(name), workflow.index("Build and sign the separate fixed vault helper before binding the app"))
            if filename == "desktop-macos-aqua.yml":
                condition = block.splitlines()[0]
                self.assertEqual(condition, workflow_step(workflow, assembly).splitlines()[0])
                self.assertNotIn("xcode-installed-classification", condition)
                self.assertNotIn("wrapping-keychain-private", condition)


@unittest.skipUnless(TOOL is not None, "POSIX DATA definitions only")
class MacNormalPreviewData(unittest.TestCase):
    def test_real_app_copy_preserves_signed_helper_mode_bytes_and_normal_binding(self):
        # Real isolated copy of synthetic DATA for BOTH explicit layouts. No
        # native signature, executable launch or observation-to-image relabeling.
        for role, build_target in (("ordinary-image", "aarch64-apple-darwin"), ("ordinary-image", "x86_64-apple-darwin"),
                                   ("installed-shell-observation", "aarch64-apple-darwin")):
            with self.subTest(role=role, target=build_target), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary).resolve(strict=True)
                fixture = normal_cargo_fixture if role == "ordinary-image" else observer_cargo_fixture
                target, artifact, rows, artifact_body = fixture(work / "cargo-target", **({"build_target": build_target} if role == "ordinary-image" else {}))
                artifact.parent.mkdir(parents=True, mode=0o700)
                artifact.write_bytes(artifact_body)
                facade = work / "desktop-facade-data" if role == "ordinary-image" else artifact
                body = entry_macho_fixture(target=build_target) if role == "ordinary-image" else artifact_body
                if role == "ordinary-image": facade.write_bytes(body)
                helper, entry = work / "signed-vault-helper-data", work / "entry-data"
                helper_body = entry_macho_fixture(target=build_target) + b"vault-signature-DATA"
                helper.write_bytes(helper_body); helper.chmod(0o555)
                entry.write_bytes(entry_macho_fixture(target=build_target))
                resident_facade, resident = work / "signed-resident-facade-data", work / "signed-resident-image-data"
                resident_facade_body = entry_macho_fixture(target=build_target) + b"resident-signature-DATA"
                resident_body = image_macho_fixture("resident", target=build_target) + b"resident-image-signature-DATA"
                resident_facade.write_bytes(resident_facade_body); resident_facade.chmod(0o555)
                resident.write_bytes(resident_body); resident.chmod(0o555)
                messages = cargo_lines(*rows, {"reason": "build-finished", "success": True})
                cargo = work / "cargo.jsonl"; cargo.write_bytes(messages)
                support = android_support_fixture(work)
                for path, data in support.values.items(): path.write_bytes(data)
                originals = {path: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                             for path in (artifact, facade, helper, entry, resident_facade, resident, cargo, *support.values)}
                output = work / "Mobile Release Kit.app"
                args = SimpleNamespace(target=build_target, package_role=role, binary=facade, expected_app_binary=TOOL.digest(body), output=output,
                    entry_binary=entry, expected_entry=TOOL.digest(entry_macho_fixture(target=build_target)),
                    bundletool_archive=support.bundletool_archive, aapt2_archive=support.aapt2_archive,
                    vault_helper=helper, expected_vault_helper=TOOL.digest(helper_body),
                    android_helper=resident_facade, expected_android_helper=TOOL.digest(resident_facade_body),
                    resident_image=resident, expected_resident_image=TOOL.digest(resident_body))
                if role == "ordinary-image":
                    args.desktop_image, args.expected_desktop_image = artifact, TOOL.digest(artifact_body)
                    args.desktop_image_cargo_messages, args.desktop_image_cargo_target_dir = cargo, target
                else:
                    args.observer_cargo_messages, args.observer_cargo_target_dir = cargo, target
                with mock.patch.object(TOOL, "ANDROID_SUPPORT_MANIFEST", support.manifest_path):
                    result = TOOL.app_command(args)
                icon = (TOOL.DESKTOP / "src-tauri/icons/icon.png").read_bytes()
                expected = {TOOL.ENTRY_BINARY: (entry_macho_fixture(target=build_target), 0o755), TOOL.APP_BINARY: (body, 0o755),
                    TOOL.VAULT_HELPER: (helper_body, 0o555), TOOL.ANDROID_HELPER: (resident_facade_body, 0o555),
                    TOOL.RESIDENT_IMAGE: (resident_body, 0o555), TOOL.ANDROID_SERVICE_PLIST: (TOOL.android_service_plist(), 0o644),
                    "Contents/Info.plist": ((TOOL.DESKTOP / "macos-installed-inputs/EntryInfo.plist").read_bytes(), 0o644),
                    TOOL.PAYLOAD_INFO: ((TOOL.DESKTOP / "macos-installed-inputs/Info.plist").read_bytes(), 0o644),
                    "Contents/PkgInfo": (b"APPL????", 0o644), TOOL.PAYLOAD_CONTENTS + "PkgInfo": (b"APPL????", 0o644),
                    "Contents/Resources/icon.png": (icon, 0o644), TOOL.PAYLOAD_CONTENTS + "Resources/icon.png": (icon, 0o644)}
                expected.update({TOOL.PAYLOAD_RELATIVE + "/" + name: value for name, value in support.files.items()})
                if role == "ordinary-image":
                    expected[TOOL.DESKTOP_IMAGE] = (artifact_body, 0o755)
                    self.assertEqual(result["desktopImageCargoArtifact"],
                                     TOOL.image_cargo_artifact(messages, artifact, target, artifact_body, "desktop", target=build_target))
                    self.assertNotIn("observerCargoArtifact", result)
                else:
                    self.assertEqual(result["observerCargoArtifact"],
                                     TOOL.observer_cargo_artifact(messages, artifact, target, artifact_body))
                    self.assertNotIn("desktopImageCargoArtifact", result)
                self.assertEqual(TOOL.tree(output), expected)
                self.assertEqual(result["packageRole"], role)
                self.assertEqual(result["appBinarySha256BeforeSigning"], TOOL.digest(body))
                self.assertEqual(result["vaultHelperSha256"], TOOL.digest(helper_body))
                self.assertEqual(result["residentImageSha256"], TOOL.digest(resident_body))
                self.assertNotIn("normalCargoArtifact", result)
                for path, original in originals.items():
                    self.assertEqual((path.read_bytes(), stat.S_IMODE(path.stat().st_mode)), original)
                for path in (output, output / "Contents", output / "Contents/Helpers", output / "Contents/MacOS"):
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)
                wrong = SimpleNamespace(**dict(vars(args), output=work / "refused-app",
                    target="x86_64-apple-darwin" if build_target == "aarch64-apple-darwin" else "aarch64-apple-darwin"))
                with self.assertRaises(TOOL.Refused): TOOL.app_command(wrong)
                self.assertFalse(wrong.output.exists())

    def test_app_copy_mode_exception_is_only_the_fixed_readonly_helper(self):
        cases = tuple((path, mode) for path in (TOOL.VAULT_HELPER, TOOL.ANDROID_HELPER, TOOL.RESIDENT_IMAGE)
                      for mode in (0o755, 0o644, 0o444)) + (
                      (TOOL.DESKTOP_IMAGE, 0o555), (TOOL.DESKTOP_IMAGE, 0o644),
                      (TOOL.DESKTOP_IMAGE, 0o444), ("Contents/Helpers/other", 0o555))
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve(strict=True)
            for number, (name, mode) in enumerate(cases):
                output = work / ("refused-" + str(number))
                with self.subTest(name=name, mode=mode), self.assertRaisesRegex(TOOL.Refused, "^output-mode$"):
                    TOOL.write_tree(output, {name: (b"inert-copy-data", mode)}, root_mode=0o755, app_signing=True)
                self.assertFalse((output / name).exists())

    def test_only_complete_normal_main_bin_receives_original_byte_binding(self):
        # Historical selector retained; ordinary authority is now the actual
        # cdylib, while appBinary remains its distinct fixed C facade.
        target, binary, rows, image_body = normal_cargo_fixture()
        body, resident = entry_macho_fixture(), image_macho_fixture("resident")
        messages = cargo_lines(*rows, {"reason": "build-finished", "success": True})
        result = TOOL.image_cargo_artifact(messages, binary, target, image_body, "desktop")
        self.assertEqual(result["binarySha256"], TOOL.digest(image_body))
        self.assertEqual(result["cargoMessagesSha256"], TOOL.digest(messages))
        self.assertEqual((result["entrypoint"], result["targetKind"], result["imageRole"]), ("src/lib.rs", "cdylib", "desktop"))
        self.assertFalse(result["profileTest"] or result["instrumented"])
        self.assertEqual(result["qualification"], "actual-cdylib-data-not-launched")
        info = TOOL.source_app_info()
        entry_info = TOOL.source_entry_info()
        base = Path("/synthetic-mrk-preview")
        values = {binary: image_body, base / "facade": body, base / "helper": body, base / "entry": body,
                  base / "resident-image": resident, base / "resident-facade": body,
                  TOOL.DESKTOP / "macos-installed-inputs/EntryInfo.plist": entry_info,
                  base / "cargo.jsonl": messages, TOOL.DESKTOP / "macos-installed-inputs/Info.plist": info,
                  TOOL.DESKTOP / "macos-installed-inputs" / Path(TOOL.ANDROID_SERVICE_PLIST).name: TOOL.android_service_plist(),
                  TOOL.DESKTOP / "src-tauri/icons/icon.png": b"synthetic-icon"}
        support = android_support_fixture(); values.update(support.values)
        args = SimpleNamespace(package_role="ordinary-image", binary=base / "facade", expected_app_binary=TOOL.digest(body),
            output=base / "app", entry_binary=base / "entry", expected_entry=TOOL.digest(body),
            desktop_image=binary, expected_desktop_image=TOOL.digest(image_body),
            desktop_image_cargo_messages=base / "cargo.jsonl", desktop_image_cargo_target_dir=target,
            bundletool_archive=support.bundletool_archive, aapt2_archive=support.aapt2_archive,
            vault_helper=base / "helper", expected_vault_helper=TOOL.digest(body),
            android_helper=base / "resident-facade", expected_android_helper=TOOL.digest(body),
            resident_image=base / "resident-image", expected_resident_image=TOOL.digest(resident))
        with mock.patch.object(TOOL, "read", side_effect=lambda path, *_: values[path]), \
                mock.patch.object(TOOL, "ANDROID_SUPPORT_MANIFEST", support.manifest_path), \
                mock.patch.object(TOOL, "write_tree") as output:
            staged = TOOL.app_command(args)
        self.assertEqual(staged["desktopImageCargoArtifact"], result)
        self.assertEqual(output.call_args.args[1][TOOL.APP_BINARY], (body, 0o755))
        self.assertEqual(output.call_args.args[1][TOOL.DESKTOP_IMAGE], (image_body, 0o755))
        self.assertEqual(output.call_args.args[1][TOOL.RESIDENT_IMAGE], (resident, 0o555))
        self.assertEqual(output.call_args.args[1][TOOL.VAULT_HELPER], (body, 0o555))
        self.assertEqual(staged["vaultHelperSha256"], TOOL.digest(body))
        self.assertNotEqual(staged["appBinarySha256BeforeSigning"], result["binarySha256"])

    def test_test_targets_feature_drift_and_foreign_artifacts_never_stage(self):
        target, binary, original, body = normal_cargo_fixture()
        mutations = [
            ("target", "kind", ["test"]), ("target", "kind", ["bin"]), ("target", "crate_types", ["lib"]),
            ("target", "name", "mobile-release-kit-desktop"), ("target", "edition", "2018"),
            ("target", "src_path", str(TOOL.DESKTOP / "src-tauri/tests/installed_shell_observation.rs")),
            ("profile", "test", True), ("profile", "test", 0), ("profile", "debug_assertions", True),
            ("profile", "opt_level", "0"), (None, "features", ["desktop-shell"]),
            (None, "features", ["desktop-shell", "custom-protocol", "macos-installed-observation"]),
            (None, "features", ["custom-protocol", "desktop-shell", "desktop-shell"]),
            (None, "executable", str(binary)), (None, "filenames", [str(binary), str(target / "foreign")]),
            (None, "filenames", None), (None, "manifest_path", "/foreign/Cargo.toml"),
            (None, "package_id", "registry+foreign"), (None, "fresh", 1), (None, "profile", None),
        ]
        for section, field, value in mutations:
            rows = TOOL.decode(TOOL.canonical(original))
            (rows[0] if section is None else rows[0][section])[field] = value
            messages = cargo_lines(*rows, {"reason": "build-finished", "success": True})
            with self.subTest(section=section, field=field, value=value), self.assertRaises(TOOL.Refused):
                TOOL.image_cargo_artifact(messages, binary, target, body, "desktop")
        for position in (1, 2):
            for field, value in (("features", []), ("features", ["default", "installed-observation"]),
                                 ("manifest_path", "/foreign/Cargo.toml"), ("executable", str(binary))):
                rows = TOOL.decode(TOOL.canonical(original)); rows[position][field] = value
                with self.subTest(library=position, field=field), self.assertRaises(TOOL.Refused):
                    TOOL.image_cargo_artifact(cargo_lines(*rows, {"reason": "build-finished", "success": True}),
                                             binary, target, body, "desktop")
        # A second image role, even with another filename/name, is not a
        # legitimate dependency of the isolated desktop image root.
        other = normal_cargo_fixture(target, role="resident")[2][0]
        with self.assertRaises(TOOL.Refused):
            TOOL.image_cargo_artifact(cargo_lines(*original, other, {"reason": "build-finished", "success": True}),
                                     binary, target, body, "desktop")
        observer_target, observer, rows, executable = observer_cargo_fixture()
        TOOL.observer_cargo_artifact(cargo_lines(*rows, {"reason": "build-finished", "success": True}),
                                    observer, observer_target, executable)
        for index, section, field, value in (
            (0, "target", "kind", ["cdylib"]), (0, "profile", "test", False),
            (0, None, "features", ["custom-protocol", "desktop-shell", "macos-installed-desktop-image"]),
            (1, None, "profile", None), (1, "profile", "test", True),
            (2, None, "features", ["default", "resident-image"]),
        ):
            changed = TOOL.decode(TOOL.canonical(rows))
            (changed[index] if section is None else changed[index][section])[field] = value
            with self.subTest(observer=(index, section, field)), self.assertRaises(TOOL.Refused):
                TOOL.observer_cargo_artifact(cargo_lines(*changed, {"reason": "build-finished", "success": True}),
                                            observer, observer_target, executable)
        with self.assertRaises(TOOL.Refused):
            TOOL.observer_cargo_artifact(cargo_lines(*rows, {"reason": "build-finished", "success": True}),
                                        observer, observer_target, image_macho_fixture())

    def test_original_terminal_success_is_unique_and_not_a_log_hint(self):
        target, binary, rows, body = normal_cargo_fixture()
        end = {"reason": "build-finished", "success": True}
        bad = [cargo_lines(*rows), cargo_lines(*rows, {"reason": "build-finished", "success": False}),
               cargo_lines(*rows, end, end), cargo_lines(*rows, rows[0], end), cargo_lines(end),
               cargo_lines(*rows, end) + b"trailing\n", cargo_lines(*rows, end) + b"\n",
               cargo_lines(*rows) + b'{"reason":"build-finished","success":false,"success":true}\n',
               cargo_lines(*rows, {"reason": "build-finished", "success": 1}),
               cargo_lines(rows[0], end), cargo_lines(rows[0], rows[1], end), cargo_lines(rows[0], rows[2], end)]
        for messages in bad:
            with self.subTest(messages=messages[-80:]), self.assertRaises((TOOL.Refused, ValueError)):
                TOOL.image_cargo_artifact(messages, binary, target, body, "desktop")
        with self.assertRaises(TOOL.Refused):
            TOOL.image_cargo_artifact(cargo_lines(*rows, end), target / "debug" / binary.name, target, body, "desktop")
        with self.assertRaises(TOOL.Refused):
            TOOL.image_cargo_artifact(cargo_lines(*rows, end), binary, Path("relative"), body, "desktop")
        observer_target, observer, observer_rows, observer_body = observer_cargo_fixture()
        for selected in (observer_rows[:1], observer_rows[:2], observer_rows + [observer_rows[0]]):
            with self.subTest(observer_graph=len(selected)), self.assertRaises(TOOL.Refused):
                TOOL.observer_cargo_artifact(cargo_lines(*selected, end), observer, observer_target, observer_body)

    def test_optional_gate_is_paired_and_failure_precedes_any_app_write(self):
        # Historical selector; the gate is mandatory now and has no old-bin,
        # implicit observer, partial image, or mixed-profile fallback.
        target, binary, rows, body = normal_cargo_fixture()
        args = SimpleNamespace(package_role="ordinary-image", binary=Path("/synthetic-mrk-preview/facade"),
            expected_app_binary=TOOL.digest(entry_macho_fixture()), output=Path("/synthetic-mrk-preview/app"),
            desktop_image=binary, expected_desktop_image=TOOL.digest(body),
            desktop_image_cargo_messages=Path("/synthetic-mrk-preview/cargo.jsonl"), desktop_image_cargo_target_dir=target,
            android_helper=Path("/synthetic-mrk-preview/resident-facade"), resident_image=Path("/synthetic-mrk-preview/resident-image"))
        requests = [SimpleNamespace(**{name: value for name, value in vars(args).items() if name != key})
                    for key in ("package_role", "desktop_image", "expected_desktop_image", "desktop_image_cargo_messages",
                                "desktop_image_cargo_target_dir", "android_helper", "resident_image")]
        requests += [SimpleNamespace(**dict(vars(args), package_role="ordinary")),
                     SimpleNamespace(**dict(vars(args), package_role="installed-shell-observation")),
                     SimpleNamespace(**dict(vars(args), observer_cargo_messages=Path("/inert/observer.jsonl"),
                                             observer_cargo_target_dir=target))]
        for request in requests:
            with self.subTest(keys=sorted(vars(request))), mock.patch.object(TOOL, "read") as reader, \
                    mock.patch.object(TOOL, "write_tree") as output, self.assertRaises(TOOL.Refused):
                TOOL.app_command(request)
            reader.assert_not_called(); output.assert_not_called()
        rows[0]["profile"]["test"] = True
        messages = cargo_lines(*rows, {"reason": "build-finished", "success": True})
        values = {args.binary: entry_macho_fixture(), binary: body, args.desktop_image_cargo_messages: messages}
        with mock.patch.object(TOOL, "read", side_effect=lambda path, *_: values[path]), \
                mock.patch.object(TOOL, "write_tree") as output:
            with self.assertRaises(TOOL.Refused):
                TOOL.app_command(args)
            output.assert_not_called()

    def test_helper_loader_paths_are_closed_to_apple_systems_without_environment_or_rpath(self):
        # Bounded Mach-O DATA. This neither signs code nor substitutes for a
        # native dyld/installed-caller/Keychain admission result.
        build = struct.pack("<6I", 0x32, 24, 1, 26 << 16, 26 << 16, 0)
        def named(command, name, *, dylib=True):
            prefix = 24 if dylib else 12
            data = name + b"\0"
            length = (prefix + len(data) + 7) // 8 * 8
            header = struct.pack("<III", command, length, prefix)
            return header + b"\0" * (prefix - len(header)) + data + b"\0" * (length - prefix - len(data))
        def image(*commands):
            commands = (build, *commands)
            return struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, len(commands),
                               sum(map(len, commands)), 0, 0) + b"".join(commands)
        good = named(0xC, b"/usr/lib/libSystem.B.dylib")
        TOOL.macho(image(good, named(0xE, b"/usr/lib/dyld", dylib=False)), system_only=True)
        refused = [named(0xC, b"@rpath/foreign.dylib"),
                   named(0xC, b"/Users/shared/foreign.dylib"),
                   named(0xC, b"/usr/lib/../foreign.dylib"),
                   named(0x8000001C, b"/usr/lib", dylib=False),
                   named(0x27, b"DYLD_LIBRARY_PATH=/tmp", dylib=False),
                   named(0xE, b"/tmp/dyld", dylib=False)]
        for command in refused:
            with self.subTest(command=command[:12]), self.assertRaises(TOOL.Refused):
                TOOL.macho(image(command), system_only=True)
        TOOL.entry_macho(entry_macho_fixture())
        # Entry is stricter than the helper: no native Cocoa initialization,
        # added library, routines, loader environment, or executable stack.
        segments = []
        for name, kind in ((b"__mod_init_func", 0), (b"__mod_term_func", 0), (b"__init_offsets", 0),
                           (b"ordinary", 0x9), (b"ordinary", 0xA), (b"ordinary", 0x15)):
            segment = bytearray(152)
            struct.pack_into("<II", segment, 0, 0x19, 152)
            struct.pack_into("<I", segment, 64, 1)
            segment[72:88] = name.ljust(16, b"\0")
            struct.pack_into("<I", segment, 72 + 64, kind)
            segments.append(bytes(segment))
        bad_entry = [entry_macho_fixture(library=b"/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation"),
                     entry_macho_fixture(good), entry_macho_fixture(struct.pack("<II", 0x1A, 8)),
                     *(entry_macho_fixture(command) for command in refused),
                     *(entry_macho_fixture(segment) for segment in segments)]
        for flags in (0, 0x200084 | 0x20000):
            changed = bytearray(entry_macho_fixture()); struct.pack_into("<I", changed, 24, flags)
            bad_entry.append(bytes(changed))
        for body in bad_entry:
            with self.subTest(entry=TOOL.digest(body)), self.assertRaises(TOOL.Refused):
                TOOL.entry_macho(body)
        # The product dylib may initialize ONLY after the facade's fixed gate.
        # It has a distinct actual file kind, fixed ID and closed Apple closure.
        for role in ("desktop", "resident"):
            TOOL.image_macho(image_macho_fixture(role), role)
            TOOL.image_macho(image_macho_fixture(role, named(0xC,
                b"/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation")), role)
            TOOL.image_macho(image_macho_fixture(role, *segments), role)
            bad = [entry_macho_fixture(), image_macho_fixture(role, kind=2),
                   image_macho_fixture(role, install_name=b"@rpath/renamed-executable.dylib"),
                   image_macho_fixture("resident" if role == "desktop" else "desktop"),
                   image_macho_fixture(role, named(0xD, TOOL.IMAGE_INSTALL_NAMES[role].encode("ascii"))),
                   image_macho_fixture(role, good),
                   image_macho_fixture(role, struct.pack("<II", 0x1A, 8)),
                   image_macho_fixture(role, struct.pack("<IIQQ", 0x80000028, 24, 0, 0))]
            bad += [image_macho_fixture(role, command) for command in refused]
            bad += [image_macho_fixture(role, named(command, b"/usr/lib/libSystem.B.dylib"))
                    for command in (0x80000018, 0x8000001F, 0x20, 0x80000023)]
            for offset, value in ((4, 0x01000007), (8, 2), (24, 0x84 | 0x20000), (28, 1)):
                changed = bytearray(image_macho_fixture(role)); struct.pack_into("<I", changed, offset, value)
                bad.append(bytes(changed))
            for body in bad:
                with self.subTest(role=role, image=TOOL.digest(body)), self.assertRaises(TOOL.Refused):
                    TOOL.image_macho(body, role)

    def test_changed_signed_helper_fails_before_any_app_write(self):
        target, binary, rows, body = normal_cargo_fixture()
        args = SimpleNamespace(package_role="ordinary-image", binary=Path("/inert/facade"),
            expected_app_binary=TOOL.digest(entry_macho_fixture()),
            desktop_image=binary, expected_desktop_image=TOOL.digest(body),
            desktop_image_cargo_messages=Path("/inert/cargo.jsonl"), desktop_image_cargo_target_dir=target,
            android_helper=Path("/inert/resident-facade"), resident_image=Path("/inert/resident-image"),
            vault_helper=Path("/inert/helper"), expected_vault_helper="f" * 64, output=Path("/inert/output"))
        values = {args.binary: entry_macho_fixture(), binary: body, args.vault_helper: entry_macho_fixture(),
                  args.desktop_image_cargo_messages: cargo_lines(*rows, {"reason": "build-finished", "success": True})}
        with mock.patch.object(TOOL, "read", side_effect=lambda path, *_: values[path]), mock.patch.object(TOOL, "write_tree") as output:
            with self.assertRaisesRegex(TOOL.Refused, "helper-final-signed-digest"):
                TOOL.app_command(args)
            output.assert_not_called()

    def test_installer_input_requires_the_same_helper_and_rejects_other_executables(self):
        body = entry_macho_fixture()
        entry = entry_macho_fixture() + b"outer-entry-DATA"
        desktop, resident = image_macho_fixture(), image_macho_fixture("resident")
        info, entry_info, plist = TOOL.source_app_info(), TOOL.source_entry_info(), TOOL.android_service_plist()
        args = SimpleNamespace(package_role="ordinary-image", runtime=Path("/inert/runtime"), expected_manifest="c" * 64,
            current_runtime=True, app=Path("/inert/app"), expected_vault_helper=TOOL.digest(body),
            expected_entry=TOOL.digest(entry), expected_app_binary=TOOL.digest(body), output=Path("/inert/output"),
            expected_android_helper=TOOL.digest(body), expected_resident_image=TOOL.digest(resident),
            expected_desktop_image=TOOL.digest(desktop))
        app = {TOOL.ENTRY_BINARY: (entry, 0o755), TOOL.APP_BINARY: (body, 0o755), TOOL.VAULT_HELPER: (body, 0o555),
               TOOL.ANDROID_HELPER: (body, 0o555), TOOL.RESIDENT_IMAGE: (resident, 0o555),
               TOOL.DESKTOP_IMAGE: (desktop, 0o755), TOOL.ANDROID_SERVICE_PLIST: (plist, 0o644),
               "Contents/Info.plist": (entry_info, 0o644), TOOL.PAYLOAD_INFO: (info, 0o644),
               "Contents/PkgInfo": (b"APPL????", 0o644), TOOL.PAYLOAD_CONTENTS + "PkgInfo": (b"APPL????", 0o644),
               "Contents/Resources/icon.png": (b"icon-data", 0o644), TOOL.PAYLOAD_CONTENTS + "Resources/icon.png": (b"icon-data", 0o644),
               "Contents/_CodeSignature/CodeResources": (b"signature-data", 0o644),
               TOOL.PAYLOAD_CONTENTS + "_CodeSignature/CodeResources": (b"payload-signature-data", 0o644)}
        support = android_support_fixture()
        app.update({TOOL.PAYLOAD_RELATIVE + "/" + name: value for name, value in support.files.items()})
        support_name = next(iter(support.files))
        support_path = TOOL.PAYLOAD_RELATIVE + "/" + support_name
        runtime = {"python/bin/python3": (b"interpreter-data", 0o755)}
        source = {support.manifest_path: support.values[support.manifest_path],
                  TOOL.DESKTOP / "macos-installed-inputs/Info.plist": info,
                  TOOL.DESKTOP / "macos-installed-inputs/EntryInfo.plist": entry_info,
                  TOOL.DESKTOP / "macos-installed-inputs" / Path(TOOL.ANDROID_SERVICE_PLIST).name: plist}
        with (mock.patch.object(TOOL, "runtime_tree", return_value=runtime) as runtime_reader,
              mock.patch.object(TOOL, "tree", return_value=app) as tree,
              mock.patch.object(TOOL, "ANDROID_SUPPORT_MANIFEST", support.manifest_path),
              mock.patch.object(TOOL, "read", side_effect=lambda path, *_: source[path]),
              mock.patch.object(TOOL, "write_tree") as output):
            result = TOOL.input_command(args)
            files = output.call_args.args[1]
            self.assertEqual(result["packageRole"], "ordinary-image")
            for name, data in ((TOOL.VAULT_HELPER, body), (TOOL.ANDROID_HELPER, body),
                               (TOOL.DESKTOP_IMAGE, desktop), (TOOL.RESIDENT_IMAGE, resident)):
                self.assertEqual(files["app/" + name], (data, 0o555))
            inventory = TOOL.decode(files["install-inventory.json"][0])
            self.assertEqual(set(inventory), {"schemaVersion", "release", "runtimeManifestSha256", "files"})
            for path, (data, _) in support.files.items():
                self.assertEqual(files["app/" + TOOL.PAYLOAD_RELATIVE + "/" + path], (data, 0o444))
            missing = [({name: value for name, value in app.items() if name != required}, "signed-app-roster")
                       for required in (TOOL.VAULT_HELPER, TOOL.DESKTOP_IMAGE, TOOL.RESIDENT_IMAGE,
                                        TOOL.ANDROID_HELPER, TOOL.ANDROID_SERVICE_PLIST)]
            mutations = missing + [
                ({**app, TOOL.VAULT_HELPER: (body + b"changed", 0o555)}, "nested-helper-signature-bytes-changed"),
                ({**app, TOOL.APP_BINARY: (body + b"changed", 0o755)}, "final-entry-payload-signature-bytes-changed"),
                ({**app, TOOL.ENTRY_BINARY: (entry + b"changed", 0o755)}, "final-entry-payload-signature-bytes-changed"),
                ({**app, TOOL.DESKTOP_IMAGE: (desktop + b"changed", 0o755)}, "desktop-image-signature-bytes-changed"),
                ({**app, TOOL.RESIDENT_IMAGE: (resident + b"changed", 0o555)}, "android-helper-signature-bytes-changed"),
                ({**app, TOOL.ANDROID_HELPER: (body + b"changed", 0o555)}, "android-helper-signature-bytes-changed"),
                ({**app, TOOL.DESKTOP_IMAGE: (desktop, 0o644)}, "input-executable-scope"),
                ({**app, TOOL.RESIDENT_IMAGE: (resident, 0o444)}, "android-service-plist"),
                ({**app, TOOL.ANDROID_SERVICE_PLIST: (plist, 0o755)}, "android-service-plist"),
                ({**app, "Contents/Helpers/foreign": (body, 0o555)}, "signed-app-roster"),
                ({**app, TOOL.PAYLOAD_CONTENTS + "Frameworks/plugin.dylib": (desktop, 0o555)}, "signed-app-roster"),
                ({name: value for name, value in app.items() if name != support_path}, "signed-app-roster"),
                ({**app, TOOL.PAYLOAD_RELATIVE + "/" + TOOL.ANDROID_SUPPORT_PREFIX + "extra": (b"extra", 0o644)}, "signed-app-roster"),
                ({**app, support_path: (b"changed", 0o644)}, "android-support-resource"),
                ({**app, support_path: (support.files[support_name][0], 0o755)}, "android-support-resource"),
                ({name: value for name, value in app.items() if name != TOOL.PAYLOAD_CONTENTS + "_CodeSignature/CodeResources"}, "signed-app-roster"),
            ]
            for mutation, reason in mutations:
                output.reset_mock(); tree.return_value = mutation
                with self.subTest(reason=reason), self.assertRaisesRegex(TOOL.Refused, reason):
                    TOOL.input_command(args)
                output.assert_not_called()
            # Matching new hashes cannot disguise MH_EXECUTE as either image.
            for path, field in ((TOOL.DESKTOP_IMAGE, "expected_desktop_image"), (TOOL.RESIDENT_IMAGE, "expected_resident_image")):
                tree.return_value = {**app, path: (body, 0o555)}
                changed_args = SimpleNamespace(**dict(vars(args), **{field: TOOL.digest(body)}))
                output.reset_mock()
                with self.subTest(renamed_executable=path), self.assertRaisesRegex(TOOL.Refused, "image-dylib-target"):
                    TOOL.input_command(changed_args)
                output.assert_not_called()
            observer_body = observer_cargo_fixture()[3]
            observer_app = {name: value for name, value in app.items() if name != TOOL.DESKTOP_IMAGE}
            observer_app[TOOL.APP_BINARY] = (observer_body, 0o755)
            observer_args = SimpleNamespace(**dict(vars(args), package_role="installed-shell-observation",
                                                   expected_desktop_image=None, expected_app_binary=TOOL.digest(observer_body)))
            tree.return_value = observer_app
            TOOL.input_command(observer_args)
            self.assertNotIn("app/" + TOOL.DESKTOP_IMAGE, output.call_args.args[1])
            self.assertEqual(output.call_args.args[1]["app/" + TOOL.RESIDENT_IMAGE], (resident, 0o555))
            for selected_args, selected_tree in ((args, observer_app), (observer_args, app)):
                tree.return_value = selected_tree; output.reset_mock()
                with self.assertRaisesRegex(TOOL.Refused, "signed-app-roster"):
                    TOOL.input_command(selected_args)
                output.assert_not_called()
            tree.return_value = app; output.reset_mock()
            with mock.patch.object(TOOL, "PACKAGE_VERSION", "99.0.0"), self.assertRaisesRegex(TOOL.Refused, "app-info-binding"):
                TOOL.input_command(args)
            output.assert_not_called()

        # One paired ordinary Intel flow proves every nested validator and the
        # inventory writer use the caller target, not the ARM module defaults.
        intel_target, intel_release = "x86_64-apple-darwin", "macos26-x86_64-synthetic-01"
        intel_body = entry_macho_fixture(target=intel_target)
        intel_entry = intel_body + b"outer-entry-DATA"
        intel_desktop = image_macho_fixture(target=intel_target)
        intel_resident = image_macho_fixture("resident", target=intel_target)
        intel_app = dict(app)
        for path, data in ((TOOL.ENTRY_BINARY, intel_entry), (TOOL.APP_BINARY, intel_body), (TOOL.VAULT_HELPER, intel_body),
                           (TOOL.ANDROID_HELPER, intel_body), (TOOL.DESKTOP_IMAGE, intel_desktop), (TOOL.RESIDENT_IMAGE, intel_resident)):
            intel_app[path] = (data, app[path][1])
        intel_args = SimpleNamespace(**dict(vars(args), target=intel_target,
            expected_entry=TOOL.digest(intel_entry), expected_app_binary=TOOL.digest(intel_body), expected_vault_helper=TOOL.digest(intel_body),
            expected_android_helper=TOOL.digest(intel_body), expected_desktop_image=TOOL.digest(intel_desktop), expected_resident_image=TOOL.digest(intel_resident)))
        source[TOOL.DESKTOP / "macos-installed-inputs/build-release-intel.json"] = TOOL.canonical({
            "schemaVersion": 1, "packageVersion": "0.1.1", "release": intel_release})
        with (mock.patch.object(TOOL, "runtime_tree", return_value=runtime) as runtime_reader,
              mock.patch.object(TOOL, "tree", return_value=intel_app),
              mock.patch.object(TOOL, "ANDROID_SUPPORT_MANIFEST", support.manifest_path),
              mock.patch.object(TOOL, "read", side_effect=lambda path, *_: source[path]),
              mock.patch.object(TOOL, "write_tree") as output):
            TOOL.input_command(intel_args)
            runtime_reader.assert_called_once_with(args.runtime, args.expected_manifest, current=True, target=intel_target)
            self.assertEqual(TOOL.decode(output.call_args.args[1]["install-inventory.json"][0])["release"], intel_release)
            output.reset_mock()
            with self.assertRaises(TOOL.Refused): TOOL.input_command(SimpleNamespace(**dict(vars(intel_args), target="aarch64-apple-darwin")))
            output.assert_not_called()

    def test_helper_is_separate_signed_before_digest_bound_app_and_not_a_qualification(self):
        root = Path(__file__).absolute().parents[2]
        helper = (root / "desktop/helpers/macos-vault-helper/Cargo.toml").read_text()
        self.assertIn("[workspace]", helper)
        self.assertIn('features = ["vault-helper"]', helper)
        self.assertNotIn("tauri", helper.split("[dependencies]", 1)[1].lower())
        native = (root / "desktop/native/macos-installed-native/build.rs").read_text()
        self.assertIn("release: 1.98.1", native)
        self.assertIn("commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985", native)
        library = (root / "desktop/src-tauri/src/lib.rs").read_text()
        self.assertIn("!mrk_macos_installed_native::VAULT_HELPER_BUILD", library)
        for name in ("desktop-macos-installed.yml", "desktop-macos-aqua.yml"):
            workflow = (root / ".github/workflows" / name).read_text()
            build = workflow.index("--manifest-path desktop/helpers/macos-vault-helper/Cargo.toml")
            helper_sign = workflow.index('--timestamp "$helper"', build)
            digest = workflow.index('output.write("MRK_MACOS_VAULT_HELPER_SHA256=', helper_sign)
            stage = workflow.index("stage_macos_installed.py app", digest)
            app_sign = workflow.index('--timestamp "$MRK_MACOS_WORK/app/Mobile Release Kit.app"', stage)
            self.assertLess(build, helper_sign); self.assertLess(helper_sign, digest)
            self.assertLess(digest, stage); self.assertLess(stage, app_sign)
            self.assertIn('RUSTUP_TOOLCHAIN: "1.98.1"', workflow)
            expected_signers = 4 if name == "desktop-macos-installed.yml" else 3
            self.assertEqual(workflow.count("--options runtime"), expected_signers)
            self.assertEqual(workflow.count("--entitlements desktop/packaging/macos-empty-entitlements.plist"), expected_signers)
            self.assertEqual(workflow.count('--expected-vault-helper "$MRK_MACOS_VAULT_HELPER_SHA256"'), 2)
            # Prohibition text may mention --deep. Inspect only the real shell
            #signing commands, folding their continued arguments without execution.
            commands = workflow.replace('\\\n', " ").splitlines()
            signing = [shlex.split(line, comments=True) for line in commands
                       if line.lstrip().startswith("/usr/bin/codesign ") and "--sign " in line]
            self.assertTrue(signing)
            for command in signing:
                self.assertNotIn("--deep", command)
        self.assertIn("DURABLE_QUALIFIED: bool = false",
                      (root / "desktop/src-tauri/src/asset_session_vault.rs").read_text())

    def preview_fixture(self):
        work = Path("/synthetic-mrk-preview")
        target, binary, rows, body = normal_cargo_fixture(work / "cargo-target")
        messages = cargo_lines(*rows, {"reason": "build-finished", "success": True})
        normal = TOOL.image_cargo_artifact(messages, binary, target, body, "desktop")
        facade = entry_macho_fixture()
        binding = {"source": "a" * 40, "workflowSource": "a" * 40, "tree": "b" * 40,
            "scope": "normal-macos-early-preview", "packageRole": "ordinary-image",
            "instrumented": False, "runId": "123", "runAttempt": "1", "runtimeManifestSha256": "c" * 64}
        expected = {"app/" + TOOL.APP_BINARY: {"sha256": "e" * 64}, "app/" + TOOL.ENTRY_BINARY: {"sha256": "f" * 64},
                    "app/" + TOOL.DESKTOP_IMAGE: {"sha256": "9" * 64}, "app/" + TOOL.RESIDENT_IMAGE: {"sha256": "7" * 64},
                    "app/" + TOOL.ANDROID_HELPER: {"sha256": "8" * 64}, "app/" + TOOL.VAULT_HELPER: {"sha256": "6" * 64},
                    "app/" + TOOL.ANDROID_SERVICE_PLIST: {"sha256": "5" * 64}}
        package = b"synthetic-package-DATA-not-native-Installer-evidence"
        _profile, _service, selection, _history, descriptor_data = packaging_fixture(package=package)
        descriptor, signed, image = TOOL.canonical(descriptor_data) + b"\n", b"not a real signature", b"not a real DMG"
        request, invocation = "1" * 32, "2" * 32
        result = {"schemaVersion": 2, "kind": "maintenance-parent-pending-finalization", "invocation": invocation,
            "requestId": request, "resultName": "MobileReleaseKit-InstallerResult-v2-" + request + ".json",
            "resultFinality": "pending-own-write-readback-close-and-outer-return", "action": "fresh-install",
            "writerState": "installed", "writerExit": 0, "intentSha256": "3" * 64, "stateSha256": "4" * 64,
            "capsuleSha256": "5" * 64, "payloadWriteCount": 1, "payloadWriteBytes": 10, "originalWriterJoined": True,
            "parentFinality": "pending-original-closes-and-outer-return", "retainedGate": "parent-command-reference-until-kernel-exit",
            "historicalOuterExit": "unverified"}
        observed = {"schemaVersion": 2, "sourceCommit": "a" * 40, "release": selection.release,
            "requestId": request, "invocation": invocation, "originalInstallerReturnedZero": True, "originalWriterJoined": True,
            "historicalOuterExit": "unverified", "applicationLaunched": False, "guiSaveQualified": False,
            "completedPackageSha256": TOOL.digest(package), "runtimeManifestSha256": "c" * 64, "inventorySha256": "d" * 64,
            "nonrootReadbackFileCount": len(expected), "originalInstallerResult": result,
            "maintenanceGate": {"state": "protected-permanent-gate-data-correspondence", "bytes": len(TOOL.MAINTENANCE_GATE_BYTES),
                                "exclusionObserved": False, "workerFinalityEstablished": False},
            "installationMetadata": [{"release": selection.release, "instance": invocation, "inventoryBytes": 6,
                "descriptorBytes": 4, "producerDescriptorBytes": len(descriptor), "producerSignatureBytes": len(signed),
                "verifiedCurrentFiles": len(expected), "historicalOuterExit": "unverified"}]}
        emitted = {"schemaVersion": 1, "kind": "mrk-package-producer-emitted", "packageSha256": TOOL.digest(package),
            "descriptorSha256": TOOL.digest(descriptor), "signatureSha256": TOOL.digest(signed),
            "descriptorBytes": len(descriptor), "signatureBytes": len(signed)}
        distribution = {"schemaVersion": 1, "kind": "mrk-ordinary-package-observed-v2", "target": selection.target,
            "packageVersion": selection.package_version, "release": selection.release, "requestId": request,
            "originalInstallerReturnedZero": True, "sameRequestV2Readback": True, "originalMountDetached": True,
            "groupEndpointMet": True, "originalOuterReturnRequired": True, "packageSha256": TOOL.digest(package),
            "descriptorSha256": TOOL.digest(descriptor), "signatureSha256": TOOL.digest(signed), "producerSummary": emitted,
            "userImage": {"file": "MobileReleaseKit.dmg", "bytes": len(image), "sha256": TOOL.digest(image)}}
        owner = {"phase": "package-install", "target": selection.target, "source": "a" * 40, "passed": True,
            "targetRetired": True, "originalClosesKnown": True, "outerFinalityRequired": True, "cleanupErrors": [],
            "originalCalls": [{"role": role, "returned": True, "returncode": 0} for role in TOOL.PACKAGING_CALL_ROLES],
            "distribution": distribution}
        values = {work / "normal-build.jsonl": messages, binary: body, work / "mobile-release-kit-desktop": facade,
            work / "normal-build.status": b"0\n", work / "installer-output.status": b"0\n", work / "package-install.status": b"0\n",
            work / "package-final/MobileReleaseKit.pkg": package, work / "producer-root/Install.pkg": package,
            work / "producer-root/producer.json": descriptor, work / "producer-root/producer.sig": signed,
            work / "distribution/MobileReleaseKit.dmg": image, work / "package-request-id.txt": (request + "\n").encode(),
            TOOL.DESKTOP / "packaging/macos-preview.md": b"# Synthetic preview guide\n"}
        documents = {"source-binding.json": binding, "source-inventory.json": {"source": "a" * 40, "tree": "b" * 40},
            "app-result.json": {"packageRole": "ordinary-image", "desktopImageCargoArtifact": normal,
                                "desktopImageSha256BeforeSigning": TOOL.digest(body), "appBinarySha256BeforeSigning": TOOL.digest(facade),
                                "residentImageSha256": "7" * 64, "androidHelperSha256": "8" * 64,
                                "entryBinarySha256BeforeSigning": "f" * 64, "entryBundleIdentifier": TOOL.ENTRY_BUNDLE_ID,
                                "payloadBundleIdentifier": TOOL.BUNDLE_ID},
            "installation-observation.json": observed, "android-helper-package-install.json": owner,
            "package-audit.json": {"packageSha256": TOOL.digest(package), "packageSize": len(package),
                "packageIdentifier": "dev.mobile-release-kit.desktop.installed",
                "qualification": "scripts-only-package-audited-not-installed-or-GUI-qualified"}}
        values.update({work / name: TOOL.canonical(value) for name, value in documents.items()})
        return work, values, documents, expected, selection

    def test_preview_roster_has_no_raw_evidence_and_keeps_open_and_quit_unexecuted(self):
        work, values, documents, expected, selection = self.preview_fixture()
        args = SimpleNamespace(work=work, output=work / "preview", expected_source="a" * 40)
        with mock.patch.object(TOOL, "read", side_effect=lambda path, *_: values[path]), \
                mock.patch.object(TOOL, "source_build_selection", return_value=selection), \
                mock.patch.object(TOOL, "observation_inventory", return_value=expected), \
                mock.patch.object(TOOL, "write_tree") as output:
            result = TOOL.preview_command(args)
        files = output.call_args.args[1]
        self.assertEqual(set(files), {"MobileReleaseKit.dmg", "README.md", "PREVIEW.json"})
        self.assertEqual(files["MobileReleaseKit.dmg"], (values[work / "distribution/MobileReleaseKit.dmg"], 0o444))
        summary = TOOL.decode(files["PREVIEW.json"][0])
        self.assertEqual(summary["automaticWindowOpen"], "unexecuted")
        self.assertEqual(summary["normalQuit"], "unexecuted")
        self.assertEqual(summary["manualUIAcceptance"], "pending")
        self.assertFalse(summary["fullM2Qualified"] or summary["maintenanceQualified"])
        self.assertEqual(summary["ordinaryEntryRoute"], "unexecuted")
        self.assertEqual(summary["directPayloadPreMain"], "unqualified")
        self.assertEqual(summary["signedEntryBinarySha256"], "f" * 64)
        self.assertEqual(summary["packageRole"], "ordinary-image")
        self.assertEqual(summary["normalBinaryBeforeSigningSha256"], documents["app-result.json"]["appBinarySha256BeforeSigning"])
        self.assertEqual(summary["desktopImageBeforeSigningSha256"], documents["app-result.json"]["desktopImageSha256BeforeSigning"])
        self.assertNotEqual(summary["normalBinaryBeforeSigningSha256"], summary["desktopImageBeforeSigningSha256"])
        self.assertEqual((summary["signedDesktopImageSha256"], summary["signedResidentImageSha256"]), ("9" * 64, "7" * 64))
        self.assertFalse(summary["fullUIQualified"])
        self.assertFalse(summary["distributionQualified"])
        self.assertFalse(summary["productReady"])
        self.assertEqual(result["fileCount"], 3)

        self.assertTrue(summary["originalInstallerReturnedZero"] and summary["originalPackageGroupReturnedZero"]
                        and summary["originalObservationMountDetached"])
        self.assertEqual(summary["requestId"], "1" * 32)
        self.assertEqual(summary["descriptorSha256"], TOOL.digest(values[work / "producer-root/producer.json"]))
        self.assertEqual(summary["signatureSha256"], TOOL.digest(values[work / "producer-root/producer.sig"]))

    def test_failed_original_status_changed_package_or_unsettled_readback_cannot_publish(self):
        failures = [
            ("package-install.status", None, b"1\n"), ("producer-root/producer.sig", None, b"changed"),
            ("producer-root/Install.pkg", None, b"changed"), ("distribution/MobileReleaseKit.dmg", None, b"changed"),
            ("package-request-id.txt", None, b"2" * 32 + b"\n"),
            ("android-helper-package-install.json", "passed", False),
            ("android-helper-package-install.json", "originalClosesKnown", False),
            ("android-helper-package-install.json", "targetRetired", False),
            ("android-helper-package-install.json", "originalCalls", []),
            ("android-helper-package-install.json", "distribution", {}),
            ("installation-observation.json", "historicalOuterExit", "verified"),
            ("installation-observation.json", "requestId", "2" * 32),
            ("installation-observation.json", "originalInstallerResult", {}),
            ("normal-build.status", None, b"1\n"), ("installer-output.status", None, b"20\n"),
            ("source-binding.json", "instrumented", True), ("source-inventory.json", "tree", "f" * 40),
            ("app-result.json", "appBinarySha256BeforeSigning", "f" * 64),
            ("source-binding.json", "packageRole", "installed-shell-observation"),
            ("source-binding.json", "packageRole", None),
            ("app-result.json", "packageRole", "installed-shell-observation"),
            ("app-result.json", "desktopImageSha256BeforeSigning", "f" * 64),
            ("app-result.json", "desktopImageCargoArtifact", {}),
            ("app-result.json", "normalCargoArtifact", {}),
            ("app-result.json", "residentImageSha256", "4" * 64),
            ("app-result.json", "androidHelperSha256", "4" * 64),
            ("mobile-release-kit-desktop", None, b"not-a-C-facade"),
            ("installation-observation.json", "originalInstallerReturnedZero", False),
            ("installation-observation.json", "installationMetadata", None),
            ("installation-observation.json", "installationMetadata", {"state": "incomplete"}),
            ("installation-observation.json", "originalWriterJoined", False),
            ("installation-observation.json", "runtimeManifestSha256", "f" * 64),
            ("installation-observation.json", "nonrootReadbackFileCount", 1),
            ("installation-observation.json", "maintenanceGate", None),
            ("app-result.json", "entryBundleIdentifier", TOOL.BUNDLE_ID),
            ("app-result.json", "entryBinarySha256BeforeSigning", None),
            ("package-audit.json", "packageSha256", "f" * 64),
        ]
        for name, field, value in failures:
            work, values, documents, expected, selection = self.preview_fixture()
            if field is None:
                values[work / name] = value
            else:
                documents[name][field] = value
                values[work / name] = TOOL.canonical(documents[name])
            args = SimpleNamespace(work=work, output=work / "preview", expected_source="a" * 40)
            with self.subTest(name=name, field=field), \
                    mock.patch.object(TOOL, "read", side_effect=lambda path, *_: values[path]), \
                    mock.patch.object(TOOL, "source_build_selection", return_value=selection), \
                    mock.patch.object(TOOL, "observation_inventory", return_value=expected), \
                    mock.patch.object(TOOL, "write_tree") as output:
                with self.assertRaises(TOOL.Refused):
                    TOOL.preview_command(args)
                output.assert_not_called()

    def test_preview_route_targets_only_unrelated_groups_and_retains_package_gates(self):
        root = Path(__file__).absolute().parents[2]
        workflow = (root / ".github/workflows/desktop-macos-installed.yml").read_text()
        selected = {block.splitlines()[0].strip() for block in workflow.split("      - name: ")[1:]
                    if "if: github.ref == 'refs/heads/verify/desktop-macos-installed'" in block}
        self.assertEqual(selected, {
            "Fail fast on the selected SDK actual no-ACL and ACE-refusal primitive",
            "Run only the five reviewed nonroot regressions (exact groups 2, 1, 2)"})
        self.assertIn("      - verify/desktop-macos-preview\n", workflow)
        self.assertIn("--message-format=json", workflow)
        self.assertIn('--desktop-image-cargo-messages "$MRK_MACOS_WORK/normal-build.jsonl"', workflow)
        self.assertIn('--desktop-image-cargo-target-dir "$CARGO_TARGET_DIR"', workflow)
        for name in ("Fail fast on native Scripts ownership and package format (never Installer)",
                     "Build the separate fixed eight-case Installer package from the same completed input",
                     "Standard Installer runs the one fixed fixture, never root libtest or a scenario selector",
                     "Nonroot fixture readback leaves protected0700 staging closed and unchanged",
                     "Build the fixed one-shot root Installer and scripts-only package",
                     "Standard Installer only is privileged; never execute the app or Python as root"):
            block = workflow.split("      - name: " + name + "\n", 1)[1].split("      - name: ", 1)[0]
            self.assertNotIn("if:", block)
        fixture_steps = (
            "Bind this completed signed app and current-source runtime into fresh Installer DATA",
            "Build the separate fixed eight-case Installer package from the same completed input",
            "Standard Installer runs the one fixed fixture, never root libtest or a scenario selector",
            "Nonroot fixture readback leaves protected0700 staging closed and unchanged",
            "Build the fixed one-shot root Installer and scripts-only package")
        positions = [workflow.index("      - name: " + name + "\n") for name in fixture_steps]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(workflow.count('"fixedFixtureCases": 8'), 2)
        self.assertNotIn('"fixedFixtureCases": 0', workflow)
        self.assertLess(workflow.index("macos_android_helper_package.py package-install"), workflow.index("stage_macos_installed.py preview"))
        publish = workflow.split("      - name: Upload only the normal user preview package and guide\n", 1)[1].split("      - name: ", 1)[0]
        self.assertIn("steps.preview.outcome == 'success'", publish)
        self.assertIn("/preview/MobileReleaseKit.dmg", publish)
        self.assertIn("/preview/README.md", publish)
        self.assertIn("/preview/PREVIEW.json", publish)
        self.assertNotIn("**", publish)
        # Observer DATA is independently compiled, never the preview app input.
        for block in normal_app_steps(workflow):
            self.assertNotIn("macos-installed-observation", block)
        for forbidden in ("continue-on-error:", "normal_app_launch_probe", "forceTerminate", "/usr/bin/open ",
                          "workflow_dispatch:"):
            self.assertFalse(forbidden in workflow, forbidden)
        normal_test_name = "Launch the exact ordinary app, Cancel its real Quit sheet, then Quit normally"
        normal_test = workflow_step(workflow, normal_test_name)
        normal_result = workflow_step(workflow, "Preserve original XCTest counts and a closed UI-only result, never a clean-exit claim")
        self.assertLess(workflow.index("stage_macos_installed.py preview"),
                        workflow.index("      - name: " + normal_test_name + "\n"))
        self.assertIn("-only-testing:MRKNormalAppUITests/NormalAppUITests/testLaunchCancelAndQuit", normal_test)
        self.assertIn('"cleanExitStatus": None, "allWorkerFinality": "not-established-by-XCTest-UI-state"', normal_result)
        self.assertIn('"fullUIQualified": False, "distributionQualified": False, "productReady": False', normal_result)
        guide = " ".join((root / "desktop/packaging/macos-preview.md").read_text().split())
        for required in ("package-export receipt is intentionally a **build/Installer/readback snapshot**",
                         "automatic-open and normal-Quit fields remain unexecuted at that stage",
                         "same hosted job subsequently runs one external XCTest scenario",
                         "normal-ui/result.json", "A missing, failed or skipped check is not a pass",
                         "does not prove POSIX exit status or every worker's finality",
                         "Gatekeeper", "Do not disable", "NOT READY / undelivered",
                         "fixed eight-case Installer fixture before ordinary install",
                         "project-relative field-picker journeys", "No Store mutation",
                         "project-field Aqua observer failure is preserved and unresolved"):
            self.assertIn(required, guide)

        for required in ("Ordinary V2 installation requires", "Developer ID Application certificate/key", "shipping profiles are currently unconfigured",
                         "Credential-free engineering fixtures do **not** satisfy", "Notarization and Gatekeeper qualification are separate",
                         "producer.json", "producer.sig", "standalone package copied to writable Downloads is unsupported"):
            self.assertIn(required, guide)


if __name__ == "__main__":
    unittest.main()
