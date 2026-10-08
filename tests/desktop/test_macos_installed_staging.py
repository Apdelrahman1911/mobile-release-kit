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


def workflow_evidence_paths(workflow):
    """Project only the two fixed artifact lists as DATA, never evaluate expressions."""
    installed = "Preserve bounded originals; upload success is never GUI/native acceptance"
    aqua = "Preserve bounded original evidence; upload alone is not an Aqua pass"
    names = [name for name in (installed, aqua) if "      - name: " + name + "\n" in workflow]
    if len(names) != 1:
        raise AssertionError("expected one fixed evidence step")
    block = workflow_step(workflow, names[0])
    if block.count("          path: |\n") != 1:
        raise AssertionError("expected one literal artifact scalar")
    lines = []
    for line in block.split("          path: |\n", 1)[1].splitlines():
        if not line.startswith("            "):
            break
        lines.append(line[12:])
    scalar = "\n".join(lines) + "\n"
    root = "${{ steps.work.outputs.root }}"
    if names[0] == installed:
        opening, closing = "${{ format('", "', steps.work.outputs.root) }}\n"
        if not scalar.startswith(opening) or not scalar.endswith(closing) or len(scalar[4:-4]) > 21000:
            raise AssertionError("expected the sole bounded fixed-root format")
        template = scalar[len(opening):-len(closing)]
        lines = template.split("\n")
        if len(lines) != 287 or len(set(lines)) != 287 or any(not line.startswith("{0}/") for line in lines):
            raise AssertionError("expected the 287 fixed format rows")
        suffixes = [line[3:] for line in lines]
    else:
        if not lines or any(not line.startswith(root + "/") for line in lines):
            raise AssertionError("expected literal Aqua evidence rows")
        suffixes = [line[len(root):] for line in lines]
    for suffix in suffixes:
        if (not suffix.isascii() or any(not (character.isalnum() or character in "_./-") for character in suffix)
                or any(part in ("", ".", "..") for part in suffix[1:].split("/"))):
            raise AssertionError("expected literal artifact suffixes without globs or interpolation")
    return "".join(root + suffix + "\n" for suffix in suffixes)


def normal_app_steps(workflow):
    return tuple(workflow_step(workflow, name) for name in (
        "Build the ordinary selected-target desktop image and embedded frontend",
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

    def notary_fixture(self, root, *, target="aarch64-apple-darwin", role="ordinary-image", failure=None):
        """Actual copy/FD/parser code, inert app/runtime/key and native doubles.

        No key cryptography, Apple endpoint, native tool, payload or service is
        executed. The completed inputs are deliberately not shipping evidence.
        """
        module, source = ANDROID_HELPER, Path(__file__).absolute().parents[2]
        checkout, work = root / "checkout", root / "work"
        checkout.mkdir(mode=0o700); work.mkdir(mode=0o700)
        def put(path, body, mode=0o644):
            path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            path.write_bytes(body); path.chmod(mode)
        producer, service, _selection, _history, _descriptor = packaging_fixture(target)
        for name, body in ((module.PROFILE, service), (module.PRODUCER_PROFILE, producer)):
            put(checkout / name, body)
        for name in ("build-release.json", "build-release-intel.json", "Info.plist", "EntryInfo.plist", module.IDENTIFIER + ".plist"):
            put(checkout / "desktop/macos-installed-inputs" / name,
                (source / "desktop/macos-installed-inputs" / name).read_bytes())
        for name in ("macos_android_helper_package.py", "stage_macos_installed.py"):
            put(checkout / "desktop/tools" / name, (source / "desktop/tools" / name).read_bytes())
        notary_profile = {"schemaVersion": 1, "mode": "app-store-connect-team-key", "teamId": "TEST000001",
                          "keyId": "DATA000001", "issuerId": "11111111-2222-3333-4444-555555555555"}
        put(checkout / module.NOTARY_PROFILE, TOOL.canonical(notary_profile))
        body = entry_macho_fixture(target=target)
        entry, desktop, resident = body + b"inert outer entry", image_macho_fixture(target=target), image_macho_fixture("resident", target=target)
        payload = body if role == "ordinary-image" else body + b"inert observer DATA"
        inputs = checkout / "desktop/macos-installed-inputs"
        files = {TOOL.ENTRY_BINARY: (entry, 0o755), TOOL.APP_BINARY: (payload, 0o755),
            TOOL.VAULT_HELPER: (body, 0o555), TOOL.ANDROID_HELPER: (body, 0o555), TOOL.RESIDENT_IMAGE: (resident, 0o555),
            TOOL.ANDROID_SERVICE_PLIST: ((inputs / (module.IDENTIFIER + ".plist")).read_bytes(), 0o644),
            "Contents/Info.plist": ((inputs / "EntryInfo.plist").read_bytes(), 0o644),
            TOOL.PAYLOAD_INFO: ((inputs / "Info.plist").read_bytes(), 0o644),
            "Contents/PkgInfo": (b"APPL????", 0o644), TOOL.PAYLOAD_CONTENTS + "PkgInfo": (b"APPL????", 0o644),
            "Contents/Resources/icon.png": (b"inert icon", 0o644), TOOL.PAYLOAD_CONTENTS + "Resources/icon.png": (b"inert icon", 0o644),
            "Contents/_CodeSignature/CodeResources": (b"INERT outer seal", 0o644),
            TOOL.PAYLOAD_CONTENTS + "_CodeSignature/CodeResources": (b"INERT inner seal", 0o644)}
        if role == "ordinary-image":
            files[TOOL.DESKTOP_IMAGE] = (desktop, 0o755)
        support = android_support_fixture(inputs)
        put(support.manifest_path, support.values[support.manifest_path])
        files.update({TOOL.PAYLOAD_RELATIVE + "/" + name: value for name, value in support.files.items()})
        app = work / "app" / TOOL.APP_NAME
        for name, (data, mode) in files.items():
            put(app / name, data, mode)
        # Real current manifest/parser correspondence, not a runtime_tree mock.
        runtime = {name: ("INERT runtime DATA " + name + "\n").encode("ascii")
                   for name in TOOL.CURRENT_BOOTSTRAPS | {"core.zip", "github-ca.pem", "python/bin/python3"}}
        rows = [{"path": name, "size": len(data), "sha256": TOOL.digest(data)} for name, data in sorted(runtime.items())]
        manifest = TOOL.canonical({"schemaVersion": 1, "protocol": 1, "coreVersion": "INERT DATA",
            "target": target, "coreSha256": TOOL.digest(runtime["core.zip"]), "protocolSha256": TOOL.CURRENT_PROTOCOL,
            "inventorySha256": TOOL.digest(TOOL.canonical(rows)), "files": rows}) + b"\n"
        runtime["manifest.json"] = manifest
        for name, data in runtime.items():
            put(work / "runtime" / name, data, 0o555 if name == "python/bin/python3" else 0o444)
        capsule = b"INERT original capsule DATA, never a signature or supplier\n"
        put(work / "signed-python-capsule/python-signed-receipt.json", capsule, 0o444)
        selected = {"state": "configured", "signedPythonSha256": TOOL.digest(runtime["python/bin/python3"]),
            "signingReceiptSha256": TOOL.digest(capsule), "sourceInputsSha256": "9" * 64,
            "runtimeManifestSha256": TOOL.digest(manifest), "producerProfileSha256": TOOL.digest(producer),
            "serviceProfileSha256": TOOL.digest(service), "signingSourceCommit": "b" * 40,
            "signingRunId": "321", "signingRunAttempt": "1", "signingArtifactId": "456"}
        nomination = {"schemaVersion": 1, "targets": {name: selected if name == target else {"state": "unconfigured"} for name in TOOL.MAC_TARGETS}}
        put(checkout / "desktop" / TOOL.SIGNED_RUNTIME_BINDING, TOOL.canonical(nomination))
        key = b"-----BEGIN PRIVATE KEY-----\nSU5FUlQgREFUQSBBTkQgTk9UIEEgS0VZ\n-----END PRIVATE KEY-----\n"
        environment = {"GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40, "MRK_MACOS_INSTALL_SOURCE_COMMIT": "a" * 40,
            "GITHUB_WORKFLOW_REF": "source-bound-DATA-fixture", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
            "MRK_MACOS_PACKAGE_ROLE": role, module.NOTARY_KEY_VARIABLE: module.base64.b64encode(key).decode("ascii"),
            "MRK_MACOS_SIGNED_ENTRY_SHA256": TOOL.digest(entry), "MRK_MACOS_SIGNED_PAYLOAD_SHA256": TOOL.digest(payload),
            "MRK_MACOS_VAULT_HELPER_SHA256": TOOL.digest(body), "MRK_MACOS_ANDROID_HELPER_SHA256": TOOL.digest(body),
            "MRK_MACOS_RESIDENT_IMAGE_SHA256": TOOL.digest(resident), "MRK_MACOS_SIGNED_DESKTOP_IMAGE_SHA256": TOOL.digest(desktop)}
        for variable, name in (("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256", "runtimeManifestSha256"),
            ("MRK_BUNDLED_RUNTIME_SOURCE_SHA256", "sourceInputsSha256"), ("MRK_MACOS_SIGNED_PYTHON_SHA256", "signedPythonSha256"),
            ("MRK_MACOS_SIGNING_RECEIPT_SHA256", "signingReceiptSha256"), ("MRK_MACOS_SIGNING_SOURCE_COMMIT", "signingSourceCommit"),
            ("MRK_MACOS_SIGNING_RUN_ID", "signingRunId"), ("MRK_MACOS_SIGNING_RUN_ATTEMPT", "signingRunAttempt")):
            environment[variable] = selected[name]
        # Model a selected Xcode.app alias to its original directory. These
        # files are never executed; the existing owner below is a DATA double.
        applications = checkout / "Applications"
        xcode = applications / "Xcode-selected.app/Contents/Developer"
        for name in ("notarytool", "stapler"):
            put(xcode / "usr/bin" / name, ("INERT tool " + name + "\n").encode("ascii"), 0o755)
        (applications / "Xcode.app").symlink_to("Xcode-selected.app", target_is_directory=True)
        state = SimpleNamespace(clock=[10_000_000_000], key=key, selected=selected, app=app, app_files=files,
            runtime=runtime, xcode=applications / "Xcode.app/Contents/Developer", support=support,
            observations=[], copies=[], original_calls=[], failure=failure, submission="abcdef12-3456-789a-bcde-0123456789ab",
            primary=RuntimeError("INERT private original failure"), operation=None)
        def command(argv, **options):
            operation = state.operation
            role_name = operation.calls[-1]["role"]
            index = len(state.observations)
            self.assertEqual(role_name, module.NOTARY_ROLES[index])
            self.assertFalse(operation.calls[-1]["returned"] or operation.calls[-1]["capturesSettled"])
            self.assertFalse(set(module.CREDENTIAL_VARIABLES + (module.NOTARY_KEY_VARIABLE,)) & set(options["environ"]))
            self.assertEqual(options["cwd"], work)
            self.assertEqual((options["capture"], options["text"]), (True, False))
            self.assertEqual(options["timeout"], 1200 if role_name == "payload-submit" else 180 if role_name == "payload-zip" else 30)
            expected_limit = 4096 if role_name.startswith("resolve-") else 1024 * 1024 if role_name == "payload-log" else 65536
            self.assertEqual(options["output_limit"], expected_limit)
            self.assertEqual(set(options["environ"]), {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ"}
                             | ({"DEVELOPER_DIR"} if role_name.startswith("resolve-") or role_name in
                                ("payload-submit", "payload-log", "staple-inner", "validate-inner", "staple-outer", "validate-outer") else set()))
            if "DEVELOPER_DIR" in options["environ"]:
                self.assertEqual(options["environ"]["DEVELOPER_DIR"], str(state.xcode))
            private = work / operation.target_name / "payload-input"
            self.assertEqual(module.NOTARY_APP_NAME, "MobileReleaseKit.app")
            self.assertNotEqual(module.NOTARY_APP_NAME, TOOL.APP_NAME)
            self.assertTrue(TOOL.safe_path(module.NOTARY_APP_NAME))
            self.assertFalse(TOOL.safe_path(TOOL.APP_NAME))
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((private / module.NOTARY_APP_NAME).stat().st_mode), 0o555)
            self.assertFalse((private / "app").exists() or (private / TOOL.APP_NAME).exists())
            self.assertFalse((work / "input").exists())
            self.assertFalse(operation.credential_calls or operation.credential_contexts)
            state.observations.append((role_name, tuple(argv)))
            if failure == ("owner", role_name):
                raise state.primary
            if failure == ("malformed", role_name):
                return CompletedProcess(["different-original"], 0, b"", b"")
            if failure == ("nonzero", role_name) or failure == ("invalid-log-nonzero", role_name):
                return CompletedProcess(argv, 1, b"", b"INERT private failure")
            output = b""
            if role_name.startswith("resolve-"):
                name = role_name.removeprefix("resolve-")
                # Exercise both accepted spellings of the SAME original tool.
                selected_path = state.xcode / "usr/bin" / name if name == "notarytool" else (state.xcode / "usr/bin" / name).resolve()
                output = (str(selected_path) + "\n").encode("utf-8")
                if failure == "tool-output":
                    output = b"/unrelated/tool\n"
                if failure == "tool-alias":
                    alias = state.xcode.parent.parent
                    alias.unlink(); alias.symlink_to("Xcode-selected.app", target_is_directory=True)
            elif role_name.startswith("verify-"):
                self.assertEqual(argv[:3], ["/usr/bin/codesign", "--verify", "--strict"])
                identifier = TOOL.BUNDLE_ID if "inner" in role_name else TOOL.ENTRY_BUNDLE_ID
                self.assertEqual(argv[3], "-R=" + module.signing_requirement(("TEST000001", "1" * 40), identifier))
                self.assertEqual(Path(argv[-1]), app / TOOL.PAYLOAD_RELATIVE if "inner" in role_name else app)
            elif role_name == "payload-zip":
                self.assertEqual(argv[:4], ["/usr/bin/ditto", "-c", "-k", "--keepParent"])
                self.assertEqual(Path(argv[-2]), private)
                self.assertEqual(Path(argv[-1]), work / operation.target_name / module.NOTARY_ZIP_NAME)
                copied = TOOL.tree(private)
                self.assertIn("runtime/python/bin/python3", copied)
                self.assertIn(module.NOTARY_APP_NAME + "/" + TOOL.APP_BINARY, copied)
                # input_command normalizes only its copy: code555/resource444.
                expected_app = {name: (body, 0o555 if mode & 0o111 else 0o444) for name, (body, mode) in files.items()}
                self.assertEqual({name.removeprefix(module.NOTARY_APP_NAME + "/"): value for name, value in copied.items()
                                  if name.startswith(module.NOTARY_APP_NAME + "/")}, expected_app)
                self.assertFalse(any(name.endswith("/Contents/CodeResources") for name in copied))
                state.copies.append(copied)
                with TOOL.zipfile.ZipFile(argv[-1], "x", compression=TOOL.zipfile.ZIP_DEFLATED) as archive:
                    for name, (data, _mode) in sorted(copied.items()):
                        archive.writestr("payload-input/" + name, data)
                Path(argv[-1]).chmod(0o600)
            elif role_name in ("payload-submit", "payload-log"):
                key_path = work / operation.target_name / "notary-key/AuthKey_DATA000001.p8"
                self.assertEqual(argv[-6:], ["--key", str(key_path), "--key-id", "DATA000001", "--issuer", notary_profile["issuerId"]])
                self.assertEqual((stat.S_IMODE(key_path.stat().st_mode), stat.S_IMODE(key_path.parent.stat().st_mode)), (0o400, 0o700))
                self.assertEqual(key_path.read_bytes(), key)
                self.assertEqual(argv[0], str((state.xcode / "usr/bin/notarytool").resolve()))
                status = "Invalid" if failure == "invalid" or failure == ("invalid-log-nonzero", "payload-log") else "Accepted"
                if role_name == "payload-submit":
                    self.assertEqual(argv[1:-6], ["submit", str(work / operation.target_name / module.NOTARY_ZIP_NAME), "--wait", "--output-format", "json"])
                    output = TOOL.canonical({"id": state.submission, "status": status, "message": "INERT status DATA"})
                else:
                    self.assertEqual(argv[1:-6], ["log", state.submission])
                    output = TOOL.canonical({"logFormatVersion": 1, "jobId": state.submission.upper(), "status": status,
                        "archiveFilename": module.NOTARY_ZIP_NAME, "sha256": operation.notary_zip_sha,
                        "issues": [] if status == "Accepted" else [{"severity": "error", "path": "inert", "message": "INERT invalid DATA"}],
                        "ticketContents": [] if status == "Accepted" else None})
                if failure == ("json", role_name):
                    output = b'{"id":"bad","id":"duplicate"}'
            else:
                self.assertEqual(argv[0], str((state.xcode / "usr/bin/stapler").resolve()))
                inner = role_name.endswith("inner")
                path = app / TOOL.PAYLOAD_RELATIVE if inner else app
                self.assertEqual(argv[1:], ["staple" if role_name.startswith("staple-") else "validate", str(path)])
                self.assertFalse((work / operation.target_name / "notary-key").exists())
                self.assertEqual(operation.receipt["notaryAuthentication"], {"created": True, "closed": True, "retired": True})
                if role_name.startswith("staple-"):
                    put(path / "Contents/CodeResources", b"INERT Apple ticket DATA " + role_name.encode("ascii"),
                        0o755 if failure == "ticket-mode" else 0o444)
                    if failure == "ticket-extra":
                        put(path / "Contents/foreign-ticket", b"INERT unexpected output")
                    if failure == "signed-byte-change":
                        put(app / TOOL.ENTRY_BINARY, entry + b"unexpected", 0o755)
            if failure == ("late", role_name):
                state.clock[0] += 1800 * 1_000_000_000
            if failure == "source-change" and role_name == "verify-inner-before":
                put(checkout / module.PROFILE, service + b"changed")
            return CompletedProcess(argv, 0, output, b"")
        operation = module.Operation(SimpleNamespace(run_owned=command), checkout, work, "notarize-payload", environment, TOOL, target=target)
        state.operation = operation
        return state

    @contextlib.contextmanager
    def notary_fixture_call(self, state):
        module, operation = ANDROID_HELPER, state.operation
        originals = (TOOL.DESKTOP, TOOL.ANDROID_SUPPORT_MANIFEST, module.NOTARY_XCODE, module.WORK_PARENT,
                     module.time.monotonic_ns, module.os.fstatvfs)
        volume = SimpleNamespace(f_frsize=4096, f_bavail=2 * 1024 * 1024)
        try:
            with (mock.patch.object(TOOL, "DESKTOP", operation.checkout / "desktop"),
                  mock.patch.object(TOOL, "ANDROID_SUPPORT_MANIFEST", state.support.manifest_path),
                  mock.patch.object(module, "NOTARY_XCODE", state.xcode),
                  mock.patch.object(module, "WORK_PARENT", operation.work.parent),
                  mock.patch.object(module.time, "monotonic_ns", new=lambda: state.clock[0]),
                  mock.patch.object(module.os, "fstatvfs", new=lambda _fd: volume)):
                yield operation
        finally:
            for actual, expected in zip((TOOL.DESKTOP, TOOL.ANDROID_SUPPORT_MANIFEST, module.NOTARY_XCODE, module.WORK_PARENT,
                                         module.time.monotonic_ns, module.os.fstatvfs), originals):
                self.assertIs(actual, expected)

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

    def credential_fixture(self, operation, *, clock=None, failure=None):
        """Inert public DER/PKCS12-shaped bytes and SAME-owner Security DATA.

        No Security API, key, certificate or native signature is exercised. The
        production private-directory/FD/write/readback/retirement code is real.
        """
        module, checkout, work = ANDROID_HELPER, operation.checkout, operation.work
        certificates = tuple(("INERT PUBLIC CERTIFICATE " + role + "\n").encode("ascii")
                             for role in ("leaf", "issuer", "root"))
        leaf = module.hashlib.sha1(certificates[0]).hexdigest()
        producer, service, _selection, _history, _descriptor = packaging_fixture(operation.target)
        producer = producer.replace(b"1" * 40, leaf.encode("ascii"))
        service = service.replace(b"1" * 40, leaf.encode("ascii"))
        for byte, body in zip((b"2", b"3", b"4"), certificates):
            producer = producer.replace(byte * 64, module.digest(body).encode("ascii"))
        for relative, body in ((module.PROFILE, service), (module.PRODUCER_PROFILE, producer), *(
                ("desktop/packaging/macos-install-producer-certificates/" + role + ".der", body)
                for role, body in zip(("leaf", "issuer", "root"), certificates))):
            path = checkout / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(body); path.chmod(0o644)
        installer, application_leaf = None, leaf
        if operation.phase in module.FINAL_PACKAGE_PHASES:
            certificates = tuple(("INERT INSTALLER CERTIFICATE " + role + "\n").encode("ascii") for role in ("leaf", "issuer", "root"))
            leaf = module.hashlib.sha1(certificates[0]).hexdigest()
            installer = {"schemaVersion": 1, "mode": "developer-id-installer", "teamId": "TEST000001",
                "identityCommonName": "Developer ID Installer: INERT DATA (TEST000001)", "leafSha1": leaf,
                **{field: module.digest(value) for field, value in zip(("leafSha256", "issuerSha256", "rootSha256"), certificates)}}
            for relative, value in ((module.INSTALLER_PROFILE, TOOL.canonical(installer) + b"\n"), *(
                    ("desktop/packaging/macos-installer-certificates/" + role + ".der", value)
                    for role, value in zip(("leaf", "issuer", "root"), certificates))):
                path = checkout / relative
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.write_bytes(value); path.chmod(0o644)
        secret = b"INERT PKCS12 DATA ONLY"
        environment = operation.environment
        environment.update(HOME="/Users/runner", MRK_MACOS_DEVELOPER_ID_P12_BASE64=module.base64.b64encode(secret).decode("ascii"),
                           MRK_MACOS_DEVELOPER_ID_P12_PASSWORD="inert credential password")
        if installer is not None:
            for app_key, installer_key in zip(module.CREDENTIAL_VARIABLES, module.INSTALLER_CREDENTIAL_VARIABLES):
                environment[installer_key] = environment.pop(app_key)
        secret_names = module.INSTALLER_CREDENTIAL_VARIABLES if installer is not None else module.CREDENTIAL_VARIABLES
        initial = ("/Users/runner/Library/Keychains/login.keychain-db", "/Library/Keychains/System.keychain")
        state = SimpleNamespace(initial=initial, search=initial, default=(initial[0],), keychain=None, events=[],
            secret=secret, leaf=leaf, certificates=certificates, producer=producer, service=service,
            installer=installer, application_leaf=application_leaf,
            clock=[10_000_000_000] if clock is None else clock, failure=failure, primary=RuntimeError("INERT PRIVATE original failure"))
        original = operation.owner.run_owned
        def paths(values):
            return b"".join(('    "' + value + '"\n').encode("ascii") for value in values)
        def pem(values):
            return b"".join(b"-----BEGIN CERTIFICATE-----\n" + module.base64.b64encode(value)
                            + b"\n-----END CERTIFICATE-----\n" for value in values)
        state.pem = pem
        def command(argv, **options):
            self.assertFalse(set(module.CREDENTIAL_VARIABLES + module.INSTALLER_CREDENTIAL_VARIABLES
                                 + (module.NOTARY_KEY_VARIABLE,)) & set(options["environ"]))
            if argv[0] != "/usr/bin/security":
                if operation.credential_active is not None and operation.credential_active["ready"]:
                    self.assertEqual(state.search, (state.keychain,))
                    self.assertFalse((Path(state.keychain).parent / "identity.p12").exists())
                    self.assertEqual(options["environ"]["HOME"], "/Users/runner")
                return original(argv, **options)
            record = operation.credential_calls[-1]
            role = record["role"]
            self.assertTrue(record["entered"])
            self.assertFalse(record["returned"] or record["settled"])
            self.assertEqual((options["capture"], options["text"], options["timeout"], options["output_limit"]),
                             (True, False, 30 if role == "installer-chain" else 10, 16384))
            self.assertEqual(set(options["environ"]), {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ"})
            self.assertEqual(options["environ"]["HOME"], "/Users/runner")
            state.events.append((role, tuple(argv)))
            if state.failure == "owner" and role == "search-admit":
                raise state.primary
            if state.failure == "late" and role == "search-admit":
                state.clock[0] += 240_000_000_000
            if state.failure == "root-replaced" and role == "search-admit":
                original_root = Path(state.keychain).parent
                original_root.rename(original_root.with_name(original_root.name + "-original"))
                original_root.mkdir(mode=0o700)
            if state.failure == "restore" and role == "restore":
                return CompletedProcess(argv, 1, b"", b"INERT PRIVATE restore failure")
            output = b""
            if argv[1] == "list-keychains":
                self.assertEqual(argv[2:4], ["-d", "user"])
                if role in ("restrict", "restore"):
                    self.assertEqual(argv[4], "-s")
                    expected = (state.keychain,) if role == "restrict" else state.initial
                    self.assertEqual(tuple(argv[5:]), expected)
                    state.search = expected
                else:
                    self.assertEqual(len(argv), 4)
                    if state.failure == "searchlist" and role == "search-admit":
                        state.search += ("/unrelated/unknown.keychain-db",)
                    output = paths(state.search)
            elif argv[1] == "default-keychain":
                self.assertEqual(argv[2:], ["-d", "user"])
                output = paths(("/unrelated/default.keychain-db",) if state.failure == "default" and role == "default-after" else state.default)
            elif argv[1] == "create-keychain":
                self.assertEqual((argv[2], len(argv[3])), ("-p", 64))
                self.assertNotEqual(argv[3], environment[secret_names[1]])
                state.keychain = argv[-1]
                path = Path(state.keychain)
                self.assertEqual(path.name, "identity.keychain-db")
                self.assertEqual(path.parent.parent, work.parent)
                self.assertTrue(path.parent.name.startswith("mrk-macos-signing-private."))
                self.assertNotEqual(path.parent, work)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
                self.assertFalse(path.exists())
                path.write_bytes(b"INERT opaque private database"); path.chmod(0o664 if state.failure == "database-mode" else 0o644)
                state.search += (state.keychain,)
            elif argv[1] == "set-keychain-settings":
                self.assertEqual(argv[2:], ["-l", "-u", "-t", "240", state.keychain])
            elif argv[1] == "unlock-keychain":
                self.assertEqual((argv[2], len(argv[3]), argv[4]), ("-p", 64, state.keychain))
            elif argv[1] == "import":
                path = Path(argv[2])
                self.assertEqual(path, Path(state.keychain).parent / "identity.p12")
                self.assertEqual(path.read_bytes(), secret)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(argv[3:9], ["-k", state.keychain, "-f", "pkcs12", "-P", environment[secret_names[1]]])
                producer_purpose = operation.credential_active["purpose"] == "producer"
                trusted = str(work / "macos-package-producer") if producer_purpose else "/usr/bin/productsign" if installer is not None else "/usr/bin/codesign"
                self.assertEqual(argv[9:], ["-T", trusted, "-T", "/usr/bin/security"])
                if producer_purpose:
                    self.assertTrue(Path(trusted).is_file())
                    self.assertEqual(stat.S_IMODE(Path(trusted).stat().st_mode), 0o555)
            elif argv[1] == "set-key-partition-list":
                self.assertFalse((Path(state.keychain).parent / "identity.p12").exists())
                partitions = "apple-tool:,cdhash:" + "c" * 40 if operation.credential_active["purpose"] == "producer" else "apple-tool:,apple:"
                self.assertEqual((argv[2], argv[3], argv[4], argv[5], len(argv[6]), argv[7]),
                                 ("-S", partitions, "-s", "-k", 64, state.keychain))
            elif argv[1] == "find-identity":
                self.assertEqual(argv[2:], ["-v", "-p", "basic" if installer is not None else "codesigning", state.keychain])
                selected = "0" * 40 if state.failure == "identity" else leaf
                common_name = installer["identityCommonName"] if installer is not None else "Developer ID Application: INERT DATA (TEST000001)"
                output = ('  1) ' + selected.upper() + ' "' + common_name + '"\n'
                          '     1 valid identities found\n').encode("ascii")
                if state.failure == "duplicate-identity":
                    output += output
            elif argv[1] == "find-certificate":
                self.assertEqual(argv[2:], ["-a", "-p", state.keychain])
                output = pem(certificates + ((b"INERT FOREIGN CERTIFICATE",) if state.failure == "certificates" else ()))
            elif argv[1] == "verify-cert":
                self.assertIsNotNone(installer)
                paths_ = [str(checkout / "desktop/packaging/macos-installer-certificates" / (name + ".der")) for name in ("leaf", "issuer", "root")]
                self.assertEqual(argv, ["/usr/bin/security", "verify-cert", "-p", "pkgSign", "-N", "-L", "-c", paths_[0], "-c", paths_[1], "-r", paths_[2]])
                if state.failure == "installer-chain":
                    return CompletedProcess(argv, 1, b"", b"INERT wrong Installer certificate purpose")
            elif argv[1] == "delete-keychain":
                self.assertEqual(argv[2:], [state.keychain])
                self.assertEqual(state.search, state.initial)
                Path(state.keychain).unlink()
            else:
                self.fail("unexpected private command DATA role")
            return CompletedProcess(argv, 0, output, b"")
        operation.owner.run_owned = command
        return state

    @contextlib.contextmanager
    def credential_fixture_call(self, operation, state):
        module = ANDROID_HELPER
        original_parent, original_clock = module.WORK_PARENT, module.time.monotonic_ns
        try:
            with (mock.patch.object(module, "WORK_PARENT", operation.work.parent),
                  mock.patch.object(module.time, "monotonic_ns", new=lambda: state.clock[0])):
                yield operation
        finally:
            self.assertIs(module.WORK_PARENT, original_parent)
            self.assertIs(module.time.monotonic_ns, original_clock)

    def signed_macho_fixture(self, body):
        """Only permitted embedded-signature DATA changes, never a valid signature."""
        count, size = struct.unpack_from("<II", body, 16)
        end = 32 + size
        self.assertEqual(body[end:end + 16], bytes(16))
        signed = bytearray(body)
        struct.pack_into("<II", signed, 16, count + 1, size + 16)
        struct.pack_into("<4I", signed, end, 0x1D, 16, len(body), 32)
        signed.extend(b"INERT SIGNATURE" + bytes(17))
        self.assertEqual(len(signed), len(body) + 32)
        return bytes(signed)

    def final_package_xar(self, members, *, signed=False):
        """Tiny literal XAR/CMS/ticket shapes, NOT native cryptographic material."""
        records, heap, offset = [], [], 0
        for index, (name, body) in enumerate(members.items(), 1):
            records.append('<file id="' + str(index) + '"><name>' + name + '</name><type>file</type><data>'
                '<length>' + str(len(body)) + '</length><offset>' + str(offset) + '</offset><size>' + str(len(body))
                + '</size><encoding style="application/octet-stream"/></data></file>')
            heap.append(body); offset += len(body)
        if signed:
            records.append('<signature style="RSA"><offset>' + str(offset) + '</offset><size>16</size></signature>'
                '<x-signature style="CMS"><offset>' + str(offset + 16) + '</offset><size>16</size></x-signature>')
            heap.append(b"INERT RSA DATA!!" + b"INERT CMS DATA!!")
        toc = ('<?xml version="1.0"?><xar><toc>' + ''.join(records) + '</toc></xar>').encode('ascii')
        compressed = TOOL.zlib.compress(toc)
        return struct.pack('>IHHQQI', 0x78617221, 28, 1, len(compressed), len(toc), 0) + compressed + b''.join(heap)

    def final_package_fixture(self, root, *, target="aarch64-apple-darwin", role="ordinary-image", failure=None):
        """Real original files/audits/auth custody; only native returns are DATA."""
        module = ANDROID_HELPER
        checkout, work, environment, _owner, _observations = self.fixture(root, build_target=target)
        environment["MRK_MACOS_PACKAGE_ROLE"] = role
        environment[module.NOTARY_KEY_VARIABLE] = module.base64.b64encode(
            b"-----BEGIN PRIVATE KEY-----\nSU5FUlQgUDggREFUQQ==\n-----END PRIVATE KEY-----\n").decode("ascii")
        observations, clock = [], [10_000_000_000]
        selected = TOOL.source_build_selection(target)
        files, packager_members = package_data(uid=os.getuid(), gid=os.getgid(), selection=selected)
        unsigned_members = package_data(selection=selected)[1]
        TOOL.write_tree(work / "scripts", files, root_mode=0o755)
        (work / "package-unsigned").mkdir(mode=0o700)
        original = self.final_package_xar(packager_members)
        unsigned = self.final_package_xar(unsigned_members)
        signed = self.final_package_xar(unsigned_members, signed=True)
        ticket = b"INERT APPENDED PACKAGE TICKET DATA ONLY\0t8lr"
        for path, body in ((work / "MobileReleaseKit-original.pkg", original),
                           (work / "package-unsigned/MobileReleaseKit.pkg", unsigned)):
            path.write_bytes(body); path.chmod(0o600)
        for name in ("stage_macos_installed.py", "macos_android_helper_package.py"):
            path = checkout / "desktop/tools" / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(b"# INERT held driver SOURCE; the real loaded methods are exercised\n"); path.chmod(0o644)
        notary_profile = {"schemaVersion": 1, "mode": "app-store-connect-team-key", "teamId": "TEST000001",
                          "keyId": "INERTKEY01", "issuerId": "11111111-2222-3333-4444-555555555555"}
        profile = checkout / module.NOTARY_PROFILE
        profile.write_bytes(TOOL.canonical(notary_profile) + b"\n"); profile.chmod(0o644)
        state = SimpleNamespace(checkout=checkout, work=work, environment=environment, target=target, role=role,
            original=original, unsigned=unsigned, signed=signed, ticket=ticket, clock=clock, observations=observations,
            failure=failure, primary=RuntimeError("INERT final-package original failure"), tools={}, signature_text=None)

        def command(argv, **options):
            operation = state.operation
            called = operation.calls[-1]["role"]
            observations.append((called, tuple(argv), dict(options)))
            self.assertFalse(set(module.CREDENTIAL_VARIABLES + module.INSTALLER_CREDENTIAL_VARIABLES
                                 + (module.NOTARY_KEY_VARIABLE,)) & set(options["environ"]))
            self.assertEqual(options["cwd"], work)
            self.assertEqual((options["capture"], options["text"]), (True, False))
            self.assertLessEqual(options["timeout"], 1200 if called == "final-package-submit" else 60 if called == "final-package-sign" else 30)
            if failure == called + "-owner":
                raise state.primary
            if failure == called + "-nonzero":
                return CompletedProcess(argv, 1, b"", b"INERT bounded native refusal")
            if failure == called + "-malformed":
                return CompletedProcess(argv, 0, "not bytes", b"")
            if failure == called + "-late":
                clock[0] += 1800_000_000_000
            output = b""
            path = work / operation.target_name / "signed-package/MobileReleaseKit.pkg"
            if called.startswith("final-package-resolve-"):
                name = called.removeprefix("final-package-resolve-")
                self.assertEqual(argv, ["/usr/bin/xcrun", "--find", name])
                output = (str(state.tools[name]["path"]) + "\n").encode("utf-8")
            elif called == "final-package-sign":
                context = operation.credential_active
                self.assertEqual(context["purpose"], "installer")
                self.assertEqual(argv, ["/usr/bin/productsign", "--sign", state.credentials.installer["identityCommonName"],
                    "--keychain", str(context["path"] / "identity.keychain-db"), "--timestamp",
                    str(work / "package-unsigned/MobileReleaseKit.pkg"), str(path)])
                self.assertFalse(path.exists())
                self.assertEqual((work / "package-unsigned/MobileReleaseKit.pkg").read_bytes(), unsigned)
                path.write_bytes(signed); path.chmod(0o600)
                if failure == "signed-input-changed":
                    (work / "package-unsigned/MobileReleaseKit.pkg").write_bytes(unsigned + b"changed")
                elif failure == "signed-roster":
                    (path.parent / "unlisted").write_bytes(b"INERT other native output")
                elif failure == "signed-scripts":
                    changed = dict(unsigned_members, Scripts=unsigned_members["Scripts"].replace(b"DATA\n", b"DIFF\n"))
                    path.write_bytes(self.final_package_xar(changed, signed=True))
            elif called in ("final-package-signature-before", "final-package-signature-after"):
                self.assertIsNone(operation.credential_active)
                self.assertEqual(argv, ["/usr/sbin/pkgutil", "--check-signature", str(path)])
                output = state.signature_text
                if failure == called + "-untrusted":
                    output = output.replace(b"trusted by macOS", b"untrusted by macOS")
                elif failure == called + "-untimestamped":
                    output = output.replace(b"Signed with a trusted timestamp on: INERT DATA\n", b"")
                elif failure == called + "-chain":
                    output = output.replace(state.credentials.installer["identityCommonName"].encode(), b"Developer ID Installer: OTHER (TEST000001)")
            elif called in ("final-package-submit", "final-package-log"):
                self.assertIsNone(operation.credential_active)
                self.assertTrue(all(row["closed"] and row["retired"] for row in operation.credential_contexts))
                self.assertFalse(Path(state.credentials.keychain).parent.exists())
                self.assertIsNotNone(operation.notary_key)
                key = operation.notary_key
                tail = ["--key", str(work / operation.target_name / "notary-key" / key["name"]),
                        "--key-id", notary_profile["keyId"], "--issuer", notary_profile["issuerId"]]
                submission = {"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "status": "Invalid" if failure in ("invalid", "invalid-log-failure") else "Accepted"}
                if called == "final-package-submit":
                    self.assertEqual(argv, [str(state.tools["notarytool"]["path"]), "submit", str(path), "--wait", "--output-format", "json", *tail])
                    output = TOOL.canonical(dict(submission, name="MobileReleaseKit.pkg")) + b"\n"
                    if failure == "submit-json": output = b"{inert malformed JSON\n"
                    if failure == "submit-status": output = TOOL.canonical(dict(submission, status="In Progress"))
                else:
                    self.assertEqual(argv, [str(state.tools["notarytool"]["path"]), "log", submission["id"], *tail])
                    if failure == "invalid-log-failure":
                        return CompletedProcess(argv, 1, b"", b"INERT log failure")
                    value = {"logFormatVersion": 1, "jobId": submission["id"], "status": submission["status"],
                        "archiveFilename": "MobileReleaseKit.pkg", "sha256": module.digest(signed), "issues": None,
                        "ticketContents": [{"path": "MobileReleaseKit.pkg", "digestAlgorithm": "SHA-1", "cdhash": "c" * 40, "arch": None}]}
                    if failure == "log-sha": value["sha256"] = "f" * 64
                    if failure == "log-id": value["jobId"] = "00000000-1111-2222-3333-444444444444"
                    output = TOOL.canonical(value) + b"\n"
            else:
                self.assertIn(called, ("final-package-staple", "final-package-validate"))
                self.assertIsNone(operation.notary_key)
                self.assertEqual(operation.receipt["notaryAuthentication"], {"created": True, "closed": True, "retired": True})
                self.assertFalse((work / operation.target_name / "notary-key").exists())
                self.assertEqual(argv, [str(state.tools["stapler"]["path"]), "staple" if called.endswith("-staple") else "validate", str(path)])
                if called == "final-package-staple":
                    before = path.stat()
                    if failure == "ticket-replaced":
                        replacement = path.with_suffix(".replacement")
                        replacement.write_bytes(signed + ticket); replacement.chmod(0o600); replacement.replace(path)
                    else:
                        with path.open("ab") as output_file:
                            output_file.write(ticket if failure != "ticket-oversize" else b"x" * (1024 * 1024 + 1))
                        if failure == "ticket-prefix":
                            with path.open("r+b") as output_file:
                                output_file.write(b"X")
                        elif failure == "ticket-mode":
                            path.chmod(0o644)
                        self.assertEqual(path.stat().st_ino, before.st_ino)
            return CompletedProcess(argv, 0, output, b"")

        state.operation = module.Operation(SimpleNamespace(run_owned=command), checkout, work, "finalize-package", environment, TOOL, target=target)
        state.credentials = self.credential_fixture(state.operation, clock=clock)
        certificate_rows = []
        for index, body in enumerate(state.credentials.certificates, 1):
            name = state.credentials.installer["identityCommonName"] if index == 1 else "INERT " + ("ISSUER" if index == 2 else "ROOT")
            fingerprint = ' '.join(module.digest(body)[offset:offset + 2].upper() for offset in range(0, 64, 2))
            certificate_rows.append(str(index) + ". " + name + "\n    SHA256 Fingerprint:\n        " + fingerprint + "\n")
        state.signature_text = ('Package "MobileReleaseKit.pkg":\n   Status: signed by a certificate trusted by macOS\n'
            '   Signed with a trusted timestamp on: INERT DATA\n   Certificate Chain:\n' + ''.join(certificate_rows)).encode('utf-8')
        # Hold real tiny executable-mode source originals, but never execute
        # them. Only the selected-system-tool resolver is doubled locally.
        def tool(name):
            path = checkout / "inert-system-tools" / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(b"INERT SYSTEM TOOL SOURCE; NEVER EXECUTE\n"); path.chmod(0o555)
            parent = state.operation.directory(state.operation.source_entry, "inert-system-tools", "inert-tool-source-directory")
            entry = state.operation.original(parent, name, "notary-system-tool", 4096, (0o555,))
            identity = entry["identity"]
            value = {"fixed": path, "path": path, "entry": entry, "ancestors": [(path, identity, None)]}
            state.operation.notary_tools[name] = value
            state.tools[name] = value
            return value
        state.tool = tool
        return state

    @contextlib.contextmanager
    def final_package_fixture_call(self, state):
        module = ANDROID_HELPER
        original_tool = state.operation.notary_tool
        with self.credential_fixture_call(state.operation, state.credentials), \
                mock.patch.object(state.operation, "notary_tool", side_effect=state.tool), \
                mock.patch.object(module, "NOTARY_FREE_FLOOR", 0), mock.patch.object(module, "NOTARY_STORAGE_RESERVE", 2 * 1024 * 1024):
            # Fixture sizes are <2MiB; retain REAL statvfs and a smaller bounded
            # fixture reservation. The production3GiB+2GiB defaults stay fixed.
            yield state.operation
        self.assertEqual(state.operation.notary_tool, original_tool)
        self.assertEqual((module.NOTARY_FREE_FLOOR, module.NOTARY_STORAGE_RESERVE), (3 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024))

    def final_image_fixture(self, root, *, target="aarch64-apple-darwin", failure=None):
        """Same real S3 handoff/book and S4 files; no tool or mount executes.

        Preceding Installer/producer/mount observations below are explicitly
        synthetic DATA. Only the native device/readonly assertion is doubled;
        S4's exact three mounted file reads, POSTs and consuming closes are real.
        """
        module = ANDROID_HELPER
        state = self.final_package_fixture(root, target=target)
        state.environment.update(GITHUB_REF="refs/heads/verify/desktop-macos-preview",
            GITHUB_WORKFLOW_REF="Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-installed.yml@refs/heads/verify/desktop-macos-preview",
            MRK_MACOS_INSTALL_INVENTORY_SHA256="d" * 64, MRK_BUNDLED_RUNTIME_MANIFEST_SHA256="c" * 64)
        state.operation.receipt["workflow"] = state.environment["GITHUB_WORKFLOW_REF"]  # Before any S3 dispatch.
        with self.final_package_fixture_call(state):
            state.operation.execute()
        self.assertTrue(state.operation.receipt["passed"])
        self.assertTrue(all(row["closed"] for row in state.operation.entries))
        state.preceding_operation = state.operation
        for name in module.CREDENTIAL_VARIABLES + module.INSTALLER_CREDENTIAL_VARIABLES:
            state.environment.pop(name, None)
        selected = TOOL.source_build_selection(target)
        package = (state.work / "package-final/MobileReleaseKit.pkg").read_bytes()
        _profile, _service, _unused, _history, descriptor = packaging_fixture(target, package=package)
        policy = descriptor["signingPolicies"][0]["policy"]
        profile = TOOL.packaging_signing_data(state.credentials.producer, state.credentials.service)
        policy.update(leafCertificateSha1=profile.leaf_sha1, leafCertificateSha256=profile.leaf_sha256)
        policy_sha = TOOL.digest(json.dumps(policy, separators=(",", ":")).encode("ascii"))
        descriptor["signingPolicies"][0]["sha256"] = policy_sha
        descriptor["releaseSet"]["current"].update(packageVersion=selected.package_version,
            release=selected.release, signingPolicySha256=policy_sha)
        descriptor = TOOL.canonical(descriptor) + b"\n"
        signed = b"INERT RAW PRODUCER SIGNATURE DATA; NOT A NATIVE SIGNATURE"
        image = b"INERT SIGNED UDIF-LIKE DATA; NOT A REAL IMAGE\n" + bytes(512)
        # Change an existing byte and append a small marker: a DMG is NOT an
        # append-only PKG. Native strict checks/mounted originals remain required.
        final_image = b"T" + image[1:] + b"INERT FINAL IMAGE TICKET\n"
        request, invocation = "1" * 32, "2" * 32
        result = {"schemaVersion": 2, "kind": "maintenance-parent-pending-finalization", "invocation": invocation,
            "requestId": request, "resultName": "MobileReleaseKit-InstallerResult-v2-" + request + ".json",
            "resultFinality": "pending-own-write-readback-close-and-outer-return", "action": "fresh-install",
            "writerState": "installed", "writerExit": 0, "intentSha256": "3" * 64, "stateSha256": "4" * 64,
            "capsuleSha256": "5" * 64, "payloadWriteCount": 1, "payloadWriteBytes": 10, "originalWriterJoined": True,
            "parentFinality": "pending-original-closes-and-outer-return", "retainedGate": "parent-command-reference-until-kernel-exit",
            "historicalOuterExit": "unverified", "registrationReservation": reservation_result_data()}
        observed = {"schemaVersion": 2, "sourceCommit": "a" * 40, "release": selected.release,
            "requestId": request, "invocation": invocation, "originalInstallerReturnedZero": True, "originalWriterJoined": True,
            "historicalOuterExit": "unverified", "applicationLaunched": False, "guiSaveQualified": False,
            "completedPackageSha256": TOOL.digest(package), "runtimeManifestSha256": "c" * 64,
            "inventorySha256": "d" * 64, "originalInstallerResult": result}
        emitted = {"schemaVersion": 1, "kind": "mrk-package-producer-emitted", "packageSha256": TOOL.digest(package),
            "descriptorSha256": TOOL.digest(descriptor), "signatureSha256": TOOL.digest(signed),
            "descriptorBytes": len(descriptor), "signatureBytes": len(signed)}
        distribution = {"schemaVersion": 1, "kind": "mrk-ordinary-package-observed-v2", "target": target,
            "packageVersion": selected.package_version, "release": selected.release, "requestId": request,
            "originalInstallerReturnedZero": True, "sameRequestV2Readback": True, "originalMountDetached": True,
            "groupEndpointMet": True, "originalOuterReturnRequired": True, "packageBytes": len(package),
            "packageSha256": TOOL.digest(package), "descriptorSha256": TOOL.digest(descriptor), "signatureSha256": TOOL.digest(signed),
            "producerSummary": emitted, "sourceProducerProfileSha256": profile.producer_sha256,
            "sourceServiceProfileSha256": profile.service_sha256,
            "userImage": {"file": "MobileReleaseKit.dmg", "bytes": len(image), "sha256": TOOL.digest(image)}}
        final_package_body = (state.work / "android-helper-finalize-package.json").read_bytes()
        owner = {"schemaVersion": 1, "phase": "package-install", "target": target, "source": "a" * 40,
            "workflowSource": "a" * 40, "workflow": state.environment["GITHUB_WORKFLOW_REF"], "runId": "123", "runAttempt": "1",
            "imageSourceCommit": "a" * 40, "imageReleaseId": selected.release,
            "imageReleaseSourceSha256": state.preceding_operation.receipt["imageReleaseSourceSha256"],
            "packageRole": "ordinary-image", "passed": True, "targetRetired": True, "originalClosesKnown": True,
            "outerFinalityRequired": True, "cleanupErrors": [], "directStagerIOPending": None,
            "finalPackageReceiptSha256": TOOL.digest(final_package_body), "distribution": distribution,
            "originalCalls": [{"role": role, "entered": True, "returned": True, "capturesSettled": True, "returncode": 0}
                              for role in TOOL.PACKAGING_CALL_ROLES],
            "credentialOriginals": [{"role": role, "entered": True, "returned": True, "settled": True, "status": 0}
                for role in ("producer-adhoc", "producer-adhoc-verify", "producer-cdhash")
                + (module.CREDENTIAL_ROLES[:17] + ("search-final", "default-after")) * 3],
            "credentialContexts": [{"purpose": purpose, "closed": True, "retired": True, "searchRestored": True, "defaultUnchanged": True}
                for purpose in ("producer", "distribution-image", "observation-image")],
            "packageMount": {"attachEntered": True, "originalKnown": True, "detached": True, "retained": False,
                "installerEntered": True, "installerOriginalZero": True, "sameRequestV2Readback": True, "systemServiceExitClaimed": False}}
        audit = {"packageSha256": TOOL.digest(package), "packageSize": len(package), "packageIdentifier": TOOL.PACKAGE_ID,
                 "qualification": "scripts-only-package-audited-not-installed-or-GUI-qualified"}
        files = {"package-install.status": (b"0\n", 0o600), "installer-output.status": (b"0\n", 0o600),
            "package-finalization.status": (b"0\n", 0o600), "package-request-id.txt": ((request + "\n").encode(), 0o600),
            "android-helper-package-install.json": (TOOL.canonical(owner) + b"\n", 0o600),
            "installation-observation.json": (TOOL.canonical(observed) + b"\n", 0o600),
            "package-audit.json": (TOOL.canonical(audit) + b"\n", 0o600),
            "producer-descriptor-input.json": (descriptor, 0o444), "producer-root/Install.pkg": (package, 0o444),
            "producer-root/producer.json": (descriptor, 0o444), "producer-root/producer.sig": (signed, 0o444),
            "distribution/MobileReleaseKit.dmg": (image, 0o444),
            "distribution/MobileReleaseKit-Observation.dmg": (b"INERT REQUEST-SPECIFIC OBSERVATION IMAGE", 0o444)}
        for relative, (body, mode) in files.items():
            path = state.work / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(body); path.chmod(mode)
        state.failure, state.primary, state.observations, state.tools = failure, RuntimeError("INERT S4 original failure"), [], {}
        state.package, state.descriptor, state.producer_signature = package, descriptor, signed
        state.original_image, state.final_image = image, final_image
        state.prior_files, state.package_owner, state.final_package_body = files, owner, final_package_body
        state.selected, state.request = selected, request

        def command(argv, **options):
            operation, work = state.operation, state.work
            role = operation.calls[-1]["role"]
            state.observations.append((role, tuple(argv), dict(options)))
            self.assertFalse(set(module.CREDENTIAL_VARIABLES + module.INSTALLER_CREDENTIAL_VARIABLES
                                 + (module.NOTARY_KEY_VARIABLE,)) & set(options["environ"]))
            self.assertEqual((options["cwd"], options["capture"], options["text"]), (work, True, False))
            self.assertLessEqual(options["timeout"], {"final-image-submit": 1200, "final-image-verify": 120,
                                                    "final-image-attach": 60}.get(role, 30))
            if failure == role + "-owner": raise state.primary
            if failure == role + "-nonzero": return CompletedProcess(argv, 1, b"", b"INERT original refusal")
            if failure == role + "-malformed": return CompletedProcess(argv, 0, "not bytes", b"")
            if failure == role + "-late": state.clock[0] += 1800_000_000_000
            output, path = b"", work / operation.target_name / "final-image/MobileReleaseKit.dmg"
            if role.startswith("final-image-resolve-"):
                name = role.removeprefix("final-image-resolve-")
                self.assertEqual(argv, ["/usr/bin/xcrun", "--find", name])
                output = (str(state.tools[name]["path"]) + "\n").encode()
            elif role in ("final-image-signature-before", "final-image-signature-after"):
                self.assertIsNone(operation.notary_key)
                self.assertEqual(argv, ["/usr/bin/codesign", "--verify", "--strict", "--test-requirement",
                    module.signing_requirement(operation.signing, "dev.mobile-release-kit.desktop.distribution"), str(path)])
                self.assertEqual(path.read_bytes(), image if role.endswith("-before") else final_image)
            elif role in ("final-image-submit", "final-image-log"):
                self.assertIsNotNone(operation.notary_key)
                self.assertEqual((operation.credential_calls, operation.credential_contexts), ([], []))
                key = operation.notary_key
                tail = ["--key", str(work / operation.target_name / "notary-key" / key["name"]),
                        "--key-id", "INERTKEY01", "--issuer", "11111111-2222-3333-4444-555555555555"]
                submission = {"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                              "status": "Invalid" if failure in ("invalid", "invalid-log-failure") else "Accepted"}
                tool = str(state.tools["notarytool"]["path"])
                if role == "final-image-submit":
                    self.assertEqual(argv, [tool, "submit", str(path), "--wait", "--output-format", "json", *tail])
                    output = TOOL.canonical(dict(submission, name="MobileReleaseKit.dmg"))
                    if failure == "submit-json": output = b"{INERT malformed"
                    if failure == "submit-name": output = TOOL.canonical(dict(submission, name="MobileReleaseKit.pkg"))
                else:
                    self.assertEqual(argv, [tool, "log", submission["id"], *tail])
                    if failure == "invalid-log-failure": return CompletedProcess(argv, 1, b"", b"INERT log refusal")
                    value = {"logFormatVersion": 1, "jobId": submission["id"], "status": submission["status"],
                        "archiveFilename": "MobileReleaseKit.dmg", "sha256": TOOL.digest(image), "issues": None,
                        "ticketContents": [{"path": "MobileReleaseKit.dmg", "digestAlgorithm": "SHA-1", "cdhash": "c" * 40, "arch": None}]}
                    if failure == "log-sha": value["sha256"] = "f" * 64
                    if failure == "nested-null-annotation": value["ticketContents"][0]["path"] += "/Install.pkg"
                    output = TOOL.canonical(value)
            elif role in ("final-image-staple", "final-image-validate"):
                self.assertIsNone(operation.notary_key)
                self.assertEqual(operation.receipt["notaryAuthentication"], {"created": True, "closed": True, "retired": True})
                self.assertFalse((work / operation.target_name / "notary-key").exists())
                self.assertEqual(argv, [str(state.tools["stapler"]["path"]), "staple" if role.endswith("-staple") else "validate", str(path)])
                if role == "final-image-staple":
                    state.copy_inode = path.stat().st_ino
                    if failure == "ticket-replaced":
                        replacement = path.with_suffix(".replacement")
                        replacement.write_bytes(final_image); replacement.chmod(0o600); replacement.replace(path)
                    else:
                        path.write_bytes(final_image if failure != "ticket-oversize" else image + bytes(1024 * 1024 + 1))
                        if failure == "ticket-mode": path.chmod(0o644)
            elif role == "final-image-verify":
                self.assertEqual(argv, ["/usr/bin/hdiutil", "verify", str(path)])
            elif role == "final-image-attach":
                self.assertEqual(argv, ["/usr/bin/hdiutil", "attach", str(path), "-readonly", "-nobrowse", "-noautoopen",
                    "-mountpoint", str(work / "package-mount"), "-plist"])
                for name, body in (("Install.pkg", package), ("producer.json", descriptor), ("producer.sig", signed)):
                    mounted = work / "package-mount" / name
                    mounted.write_bytes(b"changed" if failure == "mounted-bytes" and name == "Install.pkg" else body)
                    mounted.chmod(0o444)
                if failure == "mounted-extra": (work / "package-mount/unlisted").write_bytes(b"INERT")
                output = TOOL.plistlib.dumps({"system-entities": [{"dev-entry": "/dev/disk99s1",
                    "mount-point": str(work / "package-mount"), "potentially-mountable": True}]})
            else:
                self.assertEqual(role, "final-image-detach")
                self.assertEqual(argv, ["/usr/bin/hdiutil", "detach", "/dev/disk99s1"])
                self.assertTrue(all(row["closed"] for row in operation.entries if row["kind"] in ("mounted-file", "mount")))
                self.assertFalse(operation.installer_entered)
                for mounted in (work / "package-mount").iterdir(): mounted.unlink()
            return CompletedProcess(argv, 0, output, b"")

        state.operation = module.Operation(SimpleNamespace(run_owned=command), state.checkout, state.work,
                                           "finalize-image", state.environment, TOOL, target=target)
        # Rebind the existing tool fixture to this fresh original owner. It
        # holds inert executable-mode files but never executes their contents.
        def tool(name):
            path = state.checkout / "inert-system-tools" / name
            parent = state.operation.directory(state.operation.source_entry, "inert-system-tools", "inert-tool-source-directory")
            entry = state.operation.original(parent, name, "notary-system-tool", 4096, (0o555,))
            value = {"fixed": path, "path": path, "entry": entry, "ancestors": [(path, entry["identity"], None)]}
            state.operation.notary_tools[name] = state.tools[name] = value
            return value
        state.tool = tool
        return state

    @contextlib.contextmanager
    def final_image_fixture_call(self, state):
        module, operation = ANDROID_HELPER, state.operation
        original_mount, original_tool = operation.recheck_mount, operation.notary_tool
        def mounted_device_data():
            operation.package_clock()
            operation.recheck_directory(operation.work_entry)
            entry = operation.mount_entry
            self.assertTrue(operation.mount_known and not operation.mount_detached and not entry["closed"])
            named = (operation.work / "package-mount").stat()
            held = os.fstat(entry["fd"])
            identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
            self.assertEqual(identity(named), identity(held))
            self.assertEqual(identity(held), entry["identity"])
            # The real recheck_mount body separately requires ST_RDONLY and
            # a different device. This local DATA fixture is not a real mount.
        with (self.credential_fixture_call(operation, state),
              mock.patch.object(operation, "notary_tool", side_effect=state.tool),
              mock.patch.object(operation, "recheck_mount", side_effect=mounted_device_data),
              mock.patch.object(module, "NOTARY_FREE_FLOOR", 0),
              mock.patch.object(module, "NOTARY_STORAGE_RESERVE", 2 * 1024 * 1024)):
            yield operation
        self.assertEqual(operation.recheck_mount, original_mount)
        self.assertEqual(operation.notary_tool, original_tool)
        self.assertEqual((module.NOTARY_FREE_FLOOR, module.NOTARY_STORAGE_RESERVE), (3 * 1024 ** 3, 2 * 1024 ** 3))

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
                if failure == "superblob":
                    bad = bytearray(body)
                    offset = struct.unpack_from("<I", bad, 40)[0]
                    struct.pack_into(">I", bad, offset, 0)  # Genuinely invalid embedded magic, not allocation padding.
                    body = bytes(bad)
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
        credentials = None
        if phase == "python-shipping" and failure != "unconfigured":
            credentials = self.credential_fixture(operation, clock=clock)
            producer, service = credentials.producer, credentials.service
        return SimpleNamespace(operation=operation, modules=(transport, matcher, builder, probe), pins=pins, original=original,
            receipt=receipt, archive=archive, work=work, checkout=checkout, environment=environment, clock=clock,
            observations=observations, signed=signed, target=target, producer=producer, service=service, empty=empty, credentials=credentials)

    @contextlib.contextmanager
    def python_fixture_call(self, fixture):
        module, operation = ANDROID_HELPER, fixture.operation
        prepare = operation.python_prepare
        original_bound, original_pins, original_clock = module.MAX_HELPER, module.PYTHON_SUPPLIERS, module.time.monotonic_ns
        original_parent = module.WORK_PARENT
        self.assertEqual(original_bound, 32 * 1024 * 1024)
        try:
            with (mock.patch.object(module, "WORK_PARENT", operation.work.parent),
                  mock.patch.object(module, "MAX_HELPER", 64 * 1024),
                  mock.patch.object(module, "PYTHON_SUPPLIERS", {fixture.target: fixture.pins}),
                  mock.patch.object(module.time, "monotonic_ns", side_effect=lambda: fixture.clock[0]),
                  mock.patch.object(operation, "python_prepare", side_effect=lambda: prepare(modules=fixture.modules))):
                yield operation
        finally:
            self.assertEqual(module.MAX_HELPER, original_bound)
            self.assertIs(module.PYTHON_SUPPLIERS, original_pins)
            self.assertIs(module.time.monotonic_ns, original_clock)
            self.assertIs(module.WORK_PARENT, original_parent)

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

        # Closed transient originals remain retained, but membership never
        # traverses that growing history or replaces the real ancestor checks.
        class GuardedHistory(list):
            def __iter__(self):
                raise AssertionError("directory membership scanned original history")

        with tempfile.TemporaryDirectory() as temporary:
            checkout, work, environment, owner, observations = self.fixture(Path(temporary))
            operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL)
            try:
                operation.open()
                original = operation.source_original(module.PROFILE, "registry-live", 1024)
                parent = original["parent_entry"]
                consumed = []
                for index in range(8):
                    entry = operation.source_original(module.PROFILE, "registry-history-" + str(index), 1024)
                    operation.close(entry)
                    consumed.append(entry)
                self.assertEqual(len(operation.entry_registry), len(operation.entries))
                self.assertTrue(all(operation.entry_registry.get(id(entry)) is entry
                                    and entry["closed"] and entry["fd"] is None for entry in consumed))
                history = operation.entries
                with mock.patch.object(operation, "entries", GuardedHistory(history)):
                    operation.recheck_directory(parent)
                self.assertIs(operation.entries, history)
                operation.close(parent)
                self.assertIs(operation.entry_registry.get(id(parent)), parent)
                with self.assertRaisesRegex(module.Refused, "directory-original-unavailable"):
                    operation.recheck_directory(parent)
            finally:
                operation.finish()
            self.assertTrue(operation.receipt["originalClosesKnown"] and operation.receipt["targetRetired"])
            self.assertEqual(len(operation.entry_registry), len(operation.entries))
            self.assertTrue(all(operation.entry_registry.get(id(entry)) is entry for entry in operation.entries))
            self.assertFalse(observations)

        for build_target in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
            with self.subTest(target=build_target), tempfile.TemporaryDirectory() as temporary:
                checkout, work, environment, owner, observations = self.fixture(Path(temporary), build_target=build_target)
                operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL, target=build_target)
                release_input = ("build-release.json" if build_target == "aarch64-apple-darwin" else "build-release-intel.json")
                release = json.loads((checkout / "desktop/macos-installed-inputs" / release_input).read_bytes())["release"]
                registered_peaks, consumed = [0], {}
                active = {id(row): row for row in operation.entries if not row["closed"]}
                original_register, original_close = operation.register, operation.close

                def register(*args, **kwargs):
                    entry = original_register(*args, **kwargs)
                    active[id(entry)] = entry  # Include pending originals before any later fd assignment.
                    registered_peaks[0] = max(registered_peaks[0], sum(item["fd"] is not None for item in active.values()))
                    return entry

                def close(entry):
                    if entry["fd"] is not None:
                        consumed[id(entry)] = consumed.get(id(entry), 0) + 1
                    try:
                        original_close(entry)
                    finally:
                        if entry["closed"] and entry["fd"] is None:
                            active.pop(id(entry), None)

                try:
                    with mock.patch.object(operation, "register", new=register), mock.patch.object(operation, "close", new=close):
                        expected = operation.execute()
                except module.Refused:
                    failure = json.loads((work / "android-helper-prepare.json").read_bytes()).get("failure", {})
                    self.fail("inert prepare failed: " + json.dumps({
                        "stage": failure.get("stage"), "type": failure.get("type"),
                        "reason": failure.get("reason"), "errno": failure.get("errno"),
                        "peakRegisteredDescriptors": max(registered_peaks, default=0)}, sort_keys=True))
                # This same complete path used to retain99 originals, exceeding the
                # local owner's unchanged nofile64 even before runtime overhead.
                self.assertFalse(active)
                self.assertLessEqual(max(registered_peaks), 42)
                directories = [entry for entry in operation.entries if entry["kind"] == "directory"]
                self.assertEqual(len(directories), 15)
                self.assertTrue(all(consumed.get(id(entry), 0) == 1 for entry in directories))
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
                    self.assertEqual(sign[sign.index("--sign") + 1], "-" if phase == "python-engineering" else TOOL.service_signing_data(fixture.service)[1])
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


        # Every new workflow phase traverses the actual fixed selector, held
        # files, same original calls, credential scope, POST and target cleanup.
        # These tiny Mach-O/Keychain return values remain inert DATA only.
        _transport, matcher, _parser = self.python_data_functions()
        for target in (module.ARM_TARGET, module.INTEL_TARGET):
            for phase in module.SIGNING_PHASES:
                with self.subTest(fixedSigning=phase, target=target), tempfile.TemporaryDirectory() as directory:
                    checkout, work, environment, _owner, _observations = self.fixture(Path(directory), build_target=target)
                    environment["CARGO_TARGET_DIR"] = str(work / "cargo-target")
                    for relative, body in (("desktop/packaging/macos-empty-entitlements.plist",
                            (Path(__file__).absolute().parents[2] / "desktop/packaging/macos-empty-entitlements.plist").read_bytes()),
                            ("desktop/tools/macos_cpython_orchestrator.py", b"# INERT held parser SOURCE; DATA functions injected below\n")):
                        path = checkout / relative
                        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        path.write_bytes(body); path.chmod(0o644)
                    app = work / "app/Mobile Release Kit.app"
                    payload = app / "Contents/Helpers/MobileReleaseKitPayload.app"
                    selected = {"sign-vault-helper": work / ("vault-helper-target/" + target + "/release/mrk-vault-keychain"),
                        "sign-desktop-image": payload / "Contents/Frameworks/libmrk_desktop_image.dylib",
                        "sign-desktop-payload": payload, "sign-root-app": app,
                        "sign-root-installer": work / ("cargo-target/" + target + "/release/mrk-macos-install")}[phase]
                    binary = (selected / "Contents/MacOS" / ("mobile-release-kit-desktop" if phase == "sign-desktop-payload" else module.ENTRY)
                              if phase in ("sign-desktop-payload", "sign-root-app") else selected)
                    binary.parent.mkdir(mode=0o700, parents=True)
                    original = (image_macho_fixture("desktop", target=target) if phase == "sign-desktop-image"
                                else entry_macho_fixture(target=target)) + bytes(64)
                    signed = self.signed_macho_fixture(original)
                    binary.write_bytes(original); binary.chmod(0o755)
                    calls = []
                    def fixed(argv, **options):
                        calls.append((tuple(argv), options))
                        self.assertEqual(Path(argv[-1]), selected)
                        if "--sign" in argv:
                            self.assertEqual(argv[argv.index("--sign") + 1], credentials.leaf)
                            self.assertEqual(argv, ["/usr/bin/codesign", "--force", "--sign", credentials.leaf,
                                "--options", "runtime", "--entitlements",
                                str(checkout / "desktop/packaging/macos-empty-entitlements.plist"),
                                "--timestamp", str(selected)])
                            self.assertIn("--timestamp", argv)
                            replacement = binary.with_name(binary.name + ".replacement")
                            replacement.write_bytes(signed); replacement.chmod(0o755); replacement.replace(binary)
                        else:
                            self.assertEqual(argv[:3], ["/usr/bin/codesign", "--verify", "--strict"])
                            self.assertEqual(binary.read_bytes(), signed)
                        return CompletedProcess(argv, 0, b"", b"")
                    operation = module.Operation(SimpleNamespace(run_owned=fixed), checkout, work, phase, environment, TOOL, target=target)
                    credentials = self.credential_fixture(operation)
                    def parser(root, filename, name):
                        self.assertEqual((root, filename, name), (checkout, "macos_cpython_orchestrator.py", "_mrk_credential_signing_content"))
                        return matcher
                    original_loader = module.load_data
                    with self.credential_fixture_call(operation, credentials), mock.patch.object(module, "load_data", side_effect=parser):
                        self.assertEqual(operation.execute(), module.digest(signed))
                    self.assertIs(module.load_data, original_loader)
                    self.assertEqual(len(calls), 2)
                    self.assertEqual([row["role"] for row in operation.calls], [phase, phase + "-verify"])
                    self.assertTrue(operation.receipt["passed"] and operation.receipt["originalClosesKnown"]
                                    and operation.receipt["targetRetired"])
                    self.assertEqual(credentials.search, credentials.initial)
                    self.assertFalse(Path(credentials.keychain).parent.exists())
                    self.assertTrue(all(all(row[key] is True for key in ("closed", "retired", "searchRestored", "defaultUnchanged"))
                                        for row in operation.credential_contexts))
                    public = json.dumps(operation.receipt)
                    self.assertNotIn("INERT PKCS12", public)
                    self.assertNotIn(environment[module.CREDENTIAL_VARIABLES[0]], public)
                    self.assertNotIn(environment[module.CREDENTIAL_VARIABLES[1]], public)
                    self.assertFalse(operation.receipt["developerIdOrNotarizationQualified"] or operation.receipt["productReady"])

        # The producer receives -T/CDHash only after its same compiler-derived
        # copy was actually created, ad-hoc-return verified, POST and sealed0555.
        with tempfile.TemporaryDirectory() as directory:
            checkout, work, environment, _owner, _observations = self.fixture(Path(directory))
            source = checkout / "desktop/tools/macos_cpython_orchestrator.py"
            source.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source.write_bytes(b"# INERT SOURCE parser binding\n"); source.chmod(0o644)
            original = entry_macho_fixture() + bytes(64)
            signed = self.signed_macho_fixture(original)
            compiler = work / "compiled-original"
            compiler.write_bytes(original); compiler.chmod(0o755)
            calls = []
            def producer_call(argv, **options):
                calls.append(tuple(argv))
                if Path(argv[-1]).suffix == ".dmg":
                    image = Path(argv[-1])
                    if argv[:2] == ["/usr/bin/hdiutil", "create"]:
                        self.assertIsNone(operation.credential_active)
                        self.assertFalse(image.exists())
                        image.write_bytes(b"INERT IMAGE DATA\n"); image.chmod(0o600)
                    elif argv[:2] == ["/usr/bin/codesign", "--sign"]:
                        self.assertEqual(argv[2], credentials.leaf)
                        purpose = "observation-image" if image.name.endswith("-Observation.dmg") else "distribution-image"
                        self.assertEqual(operation.credential_active["purpose"], purpose)
                        self.assertTrue(operation.credential_active["ready"])
                        image.write_bytes(image.read_bytes() + b"INERT IMAGE SIGNATURE\n")
                    elif argv[:3] == ["/usr/bin/codesign", "--verify", "--strict"]:
                        self.assertIsNotNone(operation.credential_active)
                        self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o444)
                        self.assertIn("--test-requirement", argv)
                    else:
                        self.assertEqual(argv[:2], ["/usr/bin/hdiutil", "verify"])
                        self.assertIsNone(operation.credential_active)
                    return CompletedProcess(argv, 0, b"", b"")
                if argv[0] == "/usr/bin/codesign":
                    copied = work / "macos-package-producer"
                    self.assertEqual(Path(argv[-1]), copied)
                    if "--sign" in argv:
                        self.assertEqual(argv[argv.index("--sign") + 1], "-")
                        replacement = copied.with_suffix(".next")
                        replacement.write_bytes(signed); replacement.chmod(0o755); replacement.replace(copied)
                    elif "--display" in argv:
                        self.assertEqual(copied.read_bytes(), signed)
                        return CompletedProcess(argv, 0, b"", b"Signature=adhoc\nCDHash=" + b"c" * 40 + b"\n")
                else:
                    self.assertEqual(argv[0], str(work / "macos-package-producer"))
                    self.assertEqual(Path(argv[0]).read_bytes(), signed)
                    self.assertEqual(stat.S_IMODE(Path(argv[0]).stat().st_mode), 0o555)
                return CompletedProcess(argv, 0, b"", b"")
            operation = module.Operation(SimpleNamespace(run_owned=producer_call), checkout, work, "package-install", environment, TOOL)
            credentials = self.credential_fixture(operation)
            operation.service_profile, operation.producer_profile = credentials.service, credentials.producer
            operation.signing = TOOL.service_signing_data(credentials.service)
            operation.package_started = operation.package_observed = credentials.clock[0]
            operation.package_endpoint = credentials.clock[0] + 990_000_000_000
            with self.credential_fixture_call(operation, credentials), mock.patch.object(module, "load_data", return_value=matcher):
                try:
                    operation.open()
                    entry = operation.original(operation.work_entry, compiler.name, "compiler-original", 4096, (0o755,))
                    copied = operation.producer_signing_copy(entry, original)
                    self.assertEqual(copied[1:], (signed, "c" * 40))
                    self.assertEqual(compiler.read_bytes(), original)
                    self.assertEqual([row["role"] for row in operation.credential_calls],
                                     ["producer-adhoc", "producer-adhoc-verify", "producer-cdhash"])
                    self.assertEqual(credentials.events, [])
                    with operation.credential_scope("producer", producer=copied):
                        operation.call("producer-emitter", [str(work / "macos-package-producer"), "--inert-data-only"],
                                       operation.native_environment(), cwd=work, timeout=123, limit=4096)
                    self.assertEqual(operation.package_outputs, [(copied[0], module.digest(signed))])
                    operation.distribution_entry = operation.package_directory("distribution")
                    for label in ("distribution", "observation"):
                        root = operation.package_directory("inert-" + label + "-root")
                        operation.package_file(root, "MobileReleaseKit.pkg", b"INERT FINAL PACKAGE DATA\n")
                        operation.package_roots.append((root, {"MobileReleaseKit.pkg"}))
                        value, path = operation.package_image(root, label)
                        self.assertEqual(value["sha256"], module.digest(path.read_bytes()))
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
                    self.assertEqual(len(operation.credential_calls), 60)  # 3+19 producer, then19+19 App scopes; NOT64 per scope.
                    self.assertEqual([row["purpose"] for row in operation.credential_contexts],
                                     ["producer", "distribution-image", "observation-image"])
                    self.assertTrue(all(all(row[key] is True for key in ("closed", "retired", "searchRestored", "defaultUnchanged"))
                                        for row in operation.credential_contexts))
                    self.assertEqual([row["role"] for row in operation.calls], ["producer-emitter"] + [
                        label + suffix for label in ("distribution", "observation")
                        for suffix in ("-create", "-sign", "-verify-signature", "-verify-image")])
                    self.assertEqual([argv[argv.index("-T") + 1] for role, argv in credentials.events if role == "import"],
                                     [str(work / "macos-package-producer"), "/usr/bin/codesign", "/usr/bin/codesign"])
                    # An absent/foreign active scope refuses BEFORE dispatch;
                    # matching a previous signer/searchlist is not authority.
                    prior = len(calls)
                    for role in ("distribution-sign", "observation-sign"):
                        with self.assertRaisesRegex(module.Refused, "package-image-credential-required"):
                            operation.call(role, ["never", "executed"], operation.native_environment(), cwd=work, timeout=60, limit=65536)
                    self.assertEqual(len(calls), prior)
                finally:
                    operation.finish()
            imported = next(argv for role, argv in credentials.events if role == "import")
            self.assertEqual(imported[imported.index("-T") + 1], str(work / "macos-package-producer"))
            partitions = next(argv for role, argv in credentials.events if role == "partitions")
            self.assertEqual(partitions[partitions.index("-S") + 1], "apple-tool:,cdhash:" + "c" * 40)
            self.assertEqual(len(calls), 12)
            self.assertTrue(operation.receipt["originalClosesKnown"] and operation.receipt["targetRetired"])
            self.assertFalse(operation.receipt["passed"])  # This is not the complete native package-install journey.

        # S2 runs the real current-runtime/input parsers and filesystem copies.
        # All13 children are inert CompletedProcess doubles, never notarization.
        for selected_target in TOOL.MAC_TARGETS:
            for selected_role in TOOL.PACKAGE_ROLES:
                with self.subTest(notary_target=selected_target, role=selected_role), tempfile.TemporaryDirectory() as temporary:
                    state = self.notary_fixture(Path(temporary), target=selected_target, role=selected_role)
                    operation, inputs, peaks, consumed = state.operation, [], [0], {}
                    active = {id(row): row for row in operation.entries if not row["closed"]}
                    actual_input, actual_register, actual_close = TOOL.input_command, operation.register, operation.close
                    def input_call(args, **kwargs):
                        result = actual_input(args, **kwargs)
                        inputs.append((args.output, copy.deepcopy(kwargs.get("ticket_expectations")), dict(result)))
                        return result
                    def register(*args, **kwargs):
                        entry = actual_register(*args, **kwargs)
                        active[id(entry)] = entry
                        peaks[0] = max(peaks[0], sum(row["fd"] is not None for row in active.values()))
                        return entry
                    def close(entry):
                        if entry["fd"] is not None:
                            consumed[id(entry)] = consumed.get(id(entry), 0) + 1
                        try:
                            return actual_close(entry)
                        finally:
                            if entry["closed"] and entry["fd"] is None:
                                active.pop(id(entry), None)
                    with (self.notary_fixture_call(state), mock.patch.object(TOOL, "input_command", side_effect=input_call),
                          mock.patch.object(operation, "register", new=register), mock.patch.object(operation, "close", new=close)):
                        result = operation.execute()
                    receipt = json.loads((operation.work / "android-helper-notarize-payload.json").read_bytes())
                    self.assertTrue(receipt["passed"] and receipt["originalClosesKnown"] and receipt["targetRetired"])
                    self.assertEqual(tuple(row[0] for row in state.observations), module.NOTARY_ROLES)
                    self.assertEqual(len(receipt["originalCalls"]), 13)
                    self.assertEqual((receipt["credentialOriginals"], receipt["credentialContexts"]), ([], []))
                    self.assertEqual(receipt["notaryAuthentication"], {"created": True, "closed": True, "retired": True})
                    self.assertFalse(receipt["developerIdOrNotarizationQualified"] or receipt["productReady"])
                    self.assertFalse((operation.work / operation.target_name).exists())
                    self.assertFalse(active)
                    self.assertLessEqual(max(peaks), 48)
                    self.assertTrue(all(consumed.get(id(row), 0) == 1 and row["closed"] for row in operation.entries))
                    self.assertEqual(len(inputs), 2)
                    self.assertIsNone(inputs[0][1])
                    self.assertEqual(inputs[1][0], operation.work / "input")
                    self.assertEqual(tuple(row["path"] for row in inputs[1][1]), module.NOTARY_TICKETS)
                    self.assertNotEqual(inputs[0][2]["inventorySha256"], result)
                    self.assertEqual(inputs[1][2], json.loads(operation.notary_result))
                    self.assertEqual(result, module.digest((operation.work / "input/install-inventory.json").read_bytes()))
                    self.assertEqual(receipt["payloadNotarization"]["inventorySha256"], result)
                    self.assertEqual(receipt["payloadNotarization"]["runtimeManifestSha256"], state.selected["runtimeManifestSha256"])
                    for row in inputs[1][1]:
                        body = (state.app / row["path"]).read_bytes()
                        self.assertEqual((len(body), module.digest(body)), (row["bytes"], row["sha256"]))
                        self.assertEqual((operation.work / "input/app" / row["path"]).read_bytes(), body)
                    self.assertEqual(state.app, operation.work / "app" / TOOL.APP_NAME)
                    self.assertEqual(state.app.name, "Mobile Release Kit.app")
                    self.assertFalse((operation.work / "app" / module.NOTARY_APP_NAME).exists())
                    for name, (body, mode) in state.app_files.items():
                        self.assertEqual((state.app / name).read_bytes(), body)
                        self.assertEqual(stat.S_IMODE((state.app / name).stat().st_mode), mode)
                    for name, body in state.runtime.items():
                        self.assertEqual((operation.work / "runtime" / name).read_bytes(), body)
                    public = json.dumps(receipt)
                    for secret in (state.key.decode("ascii"), operation.environment[module.NOTARY_KEY_VARIABLE],
                                   "DATA000001", "11111111-2222-3333-4444-555555555555"):
                        self.assertNotIn(secret, public)

        # Actual same-original filesystem/auth/audit/publication transitions;
        # productsign/pkgutil/notarytool/stapler are inert native-return DATA.
        # Both target/role pairs traverse the complete nine-call phase once.
        for target in (module.ARM_TARGET, module.INTEL_TARGET):
            for role in ("ordinary-image", "installed-shell-observation"):
                with self.subTest(finalPackageTarget=target, role=role), tempfile.TemporaryDirectory() as directory:
                    fixture = self.final_package_fixture(Path(directory), target=target, role=role)
                    operation = fixture.operation
                    peak, register, original_close = [0], operation.register, operation.close
                    active = {id(row): row for row in operation.entries if not row["closed"]}
                    def record_original(*args, **kwargs):
                        entry = register(*args, **kwargs)
                        active[id(entry)] = entry
                        peak[0] = max(peak[0], sum(row["fd"] is not None for row in active.values()))
                        return entry
                    def close_original(entry):
                        try:
                            return original_close(entry)
                        finally:
                            if entry["closed"] and entry["fd"] is None:
                                active.pop(id(entry), None)
                    with (self.final_package_fixture_call(fixture), mock.patch.object(operation, "register", new=record_original),
                          mock.patch.object(operation, "close", new=close_original)):
                        returned = operation.execute()
                    self.assertEqual([row[0] for row in fixture.observations], list(module.FINAL_PACKAGE_ROLES))
                    self.assertEqual(tuple(row["role"] for row in operation.credential_calls), module.INSTALLER_CREDENTIAL_ROSTER)
                    self.assertEqual((len(operation.calls), len(operation.credential_calls)), (9, 20))
                    self.assertFalse(active)
                    self.assertLessEqual(max(peak), 60)  # Same inherited64 FD limit, including stdio.
                    self.assertEqual([row[2]["timeout"] for row in fixture.observations], [30, 30, 60, 30, 1200, 30, 30, 30, 30])
                    self.assertEqual(operation.notary_observed, fixture.clock[0])
                    self.assertTrue(operation.receipt["passed"] and operation.receipt["targetRetired"] and operation.receipt["originalClosesKnown"])
                    self.assertTrue(all(row["closed"] for row in operation.entries))
                    self.assertFalse((fixture.work / operation.target_name).exists())
                    self.assertEqual(fixture.credentials.search, fixture.credentials.initial)
                    self.assertEqual(fixture.credentials.default, (fixture.credentials.initial[0],))
                    self.assertFalse(Path(fixture.credentials.keychain).parent.exists())
                    self.assertEqual(operation.receipt["credentialContexts"], [{"purpose": "installer", "searchRestored": True,
                        "defaultUnchanged": True, "retired": True, "closed": True}])
                    self.assertEqual(operation.receipt["notaryAuthentication"], {"created": True, "closed": True, "retired": True})
                    self.assertEqual((fixture.work / "MobileReleaseKit-original.pkg").read_bytes(), fixture.original)
                    self.assertEqual((fixture.work / "package-unsigned/MobileReleaseKit.pkg").read_bytes(), fixture.unsigned)
                    final_path = fixture.work / "package-final/MobileReleaseKit.pkg"
                    final_body = final_path.read_bytes()
                    self.assertEqual(final_body, fixture.signed + fixture.ticket)
                    self.assertEqual(returned, module.digest(final_body))
                    self.assertEqual(stat.S_IMODE(final_path.stat().st_mode), 0o444)
                    self.assertEqual(stat.S_IMODE(final_path.parent.stat().st_mode), 0o700)
                    self.assertEqual(sorted(path.name for path in final_path.parent.iterdir()), ["MobileReleaseKit.pkg"])
                    record_body = (fixture.work / "android-helper-finalize-package.json").read_bytes()
                    self.assertLessEqual(len(record_body), 16384)
                    record = json.loads(record_body)
                    self.assertEqual(record, operation.receipt)
                    self.assertFalse(record["productReady"] or record["developerIdOrNotarizationQualified"])
                    self.assertEqual(record["finalPackage"]["signedSha256"], module.digest(fixture.signed))
                    self.assertEqual(record["finalPackage"]["packageSha256"], returned)
                    self.assertEqual(record["finalPackage"]["ticketRowCount"], 1)
                    for secret in (fixture.environment[module.INSTALLER_CREDENTIAL_VARIABLES[0]],
                                   fixture.environment[module.INSTALLER_CREDENTIAL_VARIABLES[1]],
                                   fixture.environment[module.NOTARY_KEY_VARIABLE]):
                        self.assertNotIn(secret.encode(), record_body)
                    self.assertNotIn(str(fixture.work).encode(), record_body)
                    release_body = (fixture.checkout / operation.release_input).read_bytes()
                    installer_body = (fixture.checkout / module.INSTALLER_PROFILE).read_bytes()
                    notary_body = (fixture.checkout / module.NOTARY_PROFILE).read_bytes()
                    arguments = (fixture.environment, target, fixture.credentials.installer, module.digest(installer_body),
                        module.digest(notary_body), len(final_body), returned,
                        TOOL.build_release_data(release_body, target=target)["release"], module.digest(release_body))
                    self.assertEqual(module.final_package_receipt(record_body, *arguments), record["finalPackage"])
                    with self.assertRaises(module.Refused):
                        operation.final_package_call("final-package-submit", ["never", "dispatch"], maximum=1200)

                    # The next real helper must consume the held zero-status,
                    # closed receipt and current immutable P before any emitter.
                    (fixture.work / "package-finalization.status").write_bytes(b"0\n")
                    (fixture.work / "package-finalization.status").chmod(0o600)
                    later = module.Operation(SimpleNamespace(run_owned=lambda *_a, **_k: self.fail("no native caller in handoff DATA")),
                        fixture.checkout, fixture.work, "package-install", fixture.environment, TOOL, target=target)
                    later.package_started = later.package_observed = fixture.clock[0]
                    later.package_endpoint = fixture.clock[0] + 990_000_000_000
                    later.signing = operation.signing
                    with self.credential_fixture_call(later, fixture.credentials):
                        try:
                            later.open()
                            later.image_binding()
                            directory_entry = later.directory(later.work_entry, "package-final", "final-original-directory")
                            original_entry = later.original(directory_entry, "MobileReleaseKit.pkg", "final-package-original", TOOL.MAX_BYTES, (0o444,))
                            observed = later.package_finalization_input(original_entry, later.read(original_entry))
                            self.assertEqual(observed, record["finalPackage"])
                            self.assertEqual(later.receipt["finalPackageReceiptSha256"], module.digest(record_body))
                            self.assertEqual(later.calls, [])
                            later.package_post()
                            if target == module.ARM_TARGET and role == "ordinary-image":
                                # Retained receipt original is not merely parsed
                                # once and then discarded before the producer.
                                receipt_path = fixture.work / "android-helper-finalize-package.json"
                                receipt_path.write_bytes(record_body + b" ")
                                with self.assertRaises(module.Refused):
                                    later.package_post()
                                self.assertEqual(later.calls, [])
                        finally:
                            later.finish()
                    self.assertTrue(later.receipt["originalClosesKnown"] and later.receipt["targetRetired"])
                    self.assertFalse(later.receipt["passed"])  # Handoff DATA is not installed authority.

                    if target == module.ARM_TARGET and role == "ordinary-image":
                        mutations = (
                            ("source", "b" * 40), ("workflowSource", "b" * 40), ("runAttempt", "2"),
                            ("target", module.INTEL_TARGET), ("packageRole", "installed-shell-observation"),
                            ("imageSourceCommit", "b" * 40), ("imageReleaseId", "unrelated-release"),
                            ("imageReleaseSourceSha256", "f" * 64), ("originalClosesKnown", False),
                            ("targetRetired", False), ("passed", False), ("productReady", True),
                            ("directStagerIOPending", "unclosed"), ("cleanupErrors", [{"type": "OSError"}]),
                        )
                        for name, changed in mutations:
                            value = copy.deepcopy(record); value[name] = changed
                            with self.subTest(finalReceiptField=name), self.assertRaises(module.Refused):
                                module.final_package_receipt(TOOL.canonical(value), *arguments)
                        for name, changed in (("packageSha256", "f" * 64), ("packageBytes", len(final_body) + 1),
                                ("signedBytes", len(final_body)), ("packageMode", 0o600), ("installerProfileSha256", "f" * 64),
                                ("notaryProfileSha256", "f" * 64), ("status", "Invalid"), ("errorCount", 1),
                                ("trustedSignatureBeforeAndAfter", False), ("trustedTimestampBeforeAndAfter", False),
                                ("actualStaplerValidation", False), ("signedPrefixUnchanged", False), ("completeScriptsAudited", False)):
                            value = copy.deepcopy(record); value["finalPackage"][name] = changed
                            with self.subTest(finalPackageField=name), self.assertRaises(module.Refused):
                                module.final_package_receipt(TOOL.canonical(value), *arguments)
                        for section, index, name, changed in (("originalCalls", 2, "returned", False),
                                ("originalCalls", 2, "returncode", 1), ("originalCalls", 4, "role", "unrelated"),
                                ("credentialOriginals", 10, "status", 1), ("credentialOriginals", 10, "role", "identity"),
                                ("credentialContexts", 0, "purpose", "python"), ("credentialContexts", 0, "retired", False)):
                            value = copy.deepcopy(record); value[section][index][name] = changed
                            with self.subTest(finalOriginal=(section, name)), self.assertRaises(module.Refused):
                                module.final_package_receipt(TOOL.canonical(value), *arguments)
                        for value in (dict(record, notaryAuthentication={"created": True, "closed": True, "retired": False}),
                                      dict(record, extra="not authority")):
                            with self.assertRaises(module.Refused):
                                module.final_package_receipt(TOOL.canonical(value), *arguments)
                        with self.assertRaises(module.Refused):
                            module.final_package_receipt(b'{"schemaVersion":1,' + record_body[1:], *arguments)

        # S4 copies ONLY the old signed carrier, mutates that same inode, and
        # keeps the previous Installer/S3/raw producer originals unchanged.
        # The native tools/device status are DATA doubles, never qualification.
        for target in TOOL.MAC_TARGETS:
            with self.subTest(finalImageTarget=target), tempfile.TemporaryDirectory() as directory:
                state = self.final_image_fixture(Path(directory), target=target)
                operation, peaks, consumed = state.operation, [0], {}
                active = {id(row): row for row in operation.entries if not row["closed"]}
                original_register, original_close = operation.register, operation.close
                def register(*args, **kwargs):
                    entry = original_register(*args, **kwargs)
                    active[id(entry)] = entry
                    peaks[0] = max(peaks[0], sum(row["fd"] is not None for row in active.values()))
                    return entry
                def close(entry):
                    if entry["fd"] is not None:
                        consumed[id(entry)] = consumed.get(id(entry), 0) + 1
                    try:
                        return original_close(entry)
                    finally:
                        if entry["closed"] and entry["fd"] is None:
                            active.pop(id(entry), None)
                with (self.final_image_fixture_call(state), mock.patch.object(operation, "register", new=register),
                      mock.patch.object(operation, "close", new=close)):
                    returned = operation.execute()
                path = state.work / "distribution-final/MobileReleaseKit.dmg"
                self.assertEqual((path.read_bytes(), path.stat().st_ino, stat.S_IMODE(path.stat().st_mode)),
                                 (state.final_image, state.copy_inode, 0o444))
                self.assertNotEqual(path.read_bytes()[:1], state.original_image[:1])
                self.assertEqual(returned, TOOL.digest(state.final_image))
                self.assertEqual(tuple(row[0] for row in state.observations), module.FINAL_IMAGE_ROLES)
                self.assertEqual([row[2]["timeout"] for row in state.observations], [30, 30, 30, 1200, 30, 30, 30, 30, 120, 60, 30])
                self.assertEqual([row[2]["output_limit"] for row in state.observations], [4096, 4096, 65536, 65536,
                    1048576, 65536, 65536, 65536, 65536, 65536, 65536])
                self.assertFalse(active)
                self.assertLessEqual(max(peaks), 60)  # Same existing64 descriptor limit including stdio.
                self.assertTrue(all(row["closed"] and consumed.get(id(row), 0) == 1 for row in operation.entries))
                self.assertFalse((state.work / operation.target_name).exists() or (state.work / "package-mount").exists())
                self.assertEqual(set(path.parent.iterdir()), {path})
                for relative, (body, mode) in state.prior_files.items():
                    original = state.work / relative
                    self.assertEqual((original.read_bytes(), stat.S_IMODE(original.stat().st_mode)), (body, mode))
                self.assertEqual((state.work / "package-final/MobileReleaseKit.pkg").read_bytes(), state.package)
                self.assertEqual((state.work / "android-helper-finalize-package.json").read_bytes(), state.final_package_body)
                receipt_body = (state.work / "android-helper-finalize-image.json").read_bytes()
                receipt = json.loads(receipt_body)
                self.assertTrue(receipt["passed"] and receipt["originalClosesKnown"] and receipt["targetRetired"])
                self.assertEqual((receipt["credentialOriginals"], receipt["credentialContexts"]), ([], []))
                self.assertEqual(receipt["notaryAuthentication"], {"created": True, "closed": True, "retired": True})
                self.assertEqual(receipt["finalImageMount"], {"attachEntered": True, "originalKnown": True, "detached": True,
                    "retained": False, "installerEntered": False, "systemServiceExitClaimed": False})
                release_body = (state.checkout / operation.release_input).read_bytes()
                facts = TOOL.final_image_receipt_data(receipt_body, selection=state.selected,
                    binding={"source": "a" * 40, "runId": "123", "runAttempt": "1"}, request=state.request,
                    package=state.package, descriptor=state.descriptor, signed=state.producer_signature,
                    original_image=state.package_owner["distribution"]["userImage"],
                    package_owner=state.prior_files["android-helper-package-install.json"][0],
                    final_package=state.final_package_body, release_body=release_body,
                    profiles=(state.credentials.producer, state.credentials.service,
                              (state.checkout / module.NOTARY_PROFILE).read_bytes()))
                self.assertEqual(facts, receipt["finalImage"])
                self.assertEqual((facts["submittedSha256"], facts["originalImageSha256"]), (TOOL.digest(state.original_image),) * 2)
                self.assertFalse(receipt["distributionQualified"] or receipt["developerIdOrNotarizationQualified"] or receipt["productReady"])
                self.assertNotIn("signedPrefixUnchanged", facts)
                for secret in (state.environment[module.NOTARY_KEY_VARIABLE], "INERTKEY01", "11111111-2222-3333-4444-555555555555"):
                    self.assertNotIn(secret, receipt_body.decode())
                with self.assertRaises(module.Refused):
                    operation.final_image_call("final-image-submit", ["never", "execute"], maximum=1200)





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

        with tempfile.TemporaryDirectory() as temporary:
            checkout, work, environment, owner, observations = self.fixture(Path(temporary))
            operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL)
            attempts = []
            try:
                operation.open()
                original = operation.source_original(module.PROFILE, "registry-original", 1024)
                parent = original["parent_entry"]
                forged = dict(parent)
                self.assertEqual(forged, parent)
                self.assertIsNot(forged, parent)
                with (mock.patch.object(module.os, "stat", side_effect=AssertionError("unregistered stat")),
                      mock.patch.object(module.os, "fstat", side_effect=AssertionError("unregistered fstat"))):
                    for candidate in (None, forged):
                        with self.assertRaisesRegex(module.Refused, "directory-original-unavailable"):
                            operation.recheck_directory(candidate)
                    with mock.patch.dict(operation.entry_registry, {}, clear=True):
                        with self.assertRaisesRegex(module.Refused, "directory-original-unavailable"):
                            operation.recheck_directory(parent)
                self.assertIs(operation.entry_registry.get(id(parent)), parent)
                actual_close = os.close
                def uncertain_close(fd):
                    attempts.append(fd)
                    actual_close(fd)  # Discharge this inert original, then lose only the result.
                    raise OSError(5, "synthetic directory close result unavailable")
                with mock.patch.object(module.os, "close", side_effect=uncertain_close):
                    operation.close(parent)
                self.assertIs(operation.entry_registry.get(id(parent)), parent)
                self.assertIsNone(parent["fd"])
                self.assertFalse(parent["closed"])
                with (mock.patch.object(module.os, "open", side_effect=AssertionError("must not reopen")),
                      mock.patch.object(module.os, "close", side_effect=AssertionError("must not retry close"))):
                    with self.assertRaisesRegex(module.Refused, "directory-original-unavailable"):
                        operation.recheck_directory(parent)
                    operation.close(parent)
            finally:
                operation.finish()
            self.assertEqual(len(attempts), 1)
            self.assertEqual(operation.errors, [{"stage": "close", "role": parent["role"], "type": "OSError"}])
            self.assertFalse(operation.receipt["originalClosesKnown"] or operation.receipt["targetRetired"])
            self.assertTrue((work / operation.target_name).is_dir())
            self.assertIs(operation.entry_registry.get(id(parent)), parent)
            self.assertFalse(observations)

        # A fallible map insertion cannot lose the already-acquired original.
        # An additional uncertain close must not replace its primary failure.
        for unknown_close in (False, True):
            with self.subTest(registryInsertionCloseUnknown=unknown_close), tempfile.TemporaryDirectory() as temporary:
                checkout, work, environment, owner, observations = self.fixture(Path(temporary))
                operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL)
                retained, attempts = [], []
                insertion_error = MemoryError("synthetic registry allocation refused")
                class FailingRegistry(dict):
                    def __setitem__(registry, key, entry):
                        if entry["role"] == "source-signing-profile":
                            self.assertIs(operation.entries[-1], entry)
                            self.assertEqual(key, id(entry))
                            retained.append((entry, entry["fd"]))
                            raise insertion_error
                        return super().__setitem__(key, entry)
                operation.entry_registry = FailingRegistry()
                actual_close = os.close
                def close(fd):
                    actual_close(fd)
                    if retained and not attempts and fd == retained[0][1]:
                        attempts.append(fd)
                        if unknown_close:
                            raise OSError(5, "synthetic registry original close result unavailable")
                with mock.patch.object(module.os, "close", side_effect=close), self.assertRaises(module.Refused):
                    operation.execute()
                self.assertEqual(len(retained), 1)
                entry, fd = retained[0]
                self.assertEqual(attempts, [fd])
                self.assertTrue(any(row is entry for row in operation.entries))
                self.assertNotIn(id(entry), operation.entry_registry)
                self.assertIsNone(entry["fd"])
                self.assertEqual(entry["closed"], not unknown_close)
                receipt = json.loads((work / "android-helper-prepare.json").read_bytes())
                self.assertEqual(receipt["failure"], {"stage": "owned-directory-admission", "type": "MemoryError",
                                                     "reason": "original-operation-refused"})
                self.assertFalse(receipt["passed"])
                self.assertEqual((receipt["originalClosesKnown"], receipt["targetRetired"]), (not unknown_close,) * 2)
                self.assertEqual(len(operation.errors), int(unknown_close))
                self.assertFalse(observations)

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

        for cause in ("owner", "sign", "slot-replaced", "content", "flags", "superblob", "verify", "probe", "wrong-role",
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
                if cause in ("owner", "sign", "slot-replaced", "content", "flags", "superblob", "slot-close"):
                    self.assertEqual(len(operation.calls), 1)
                if cause == "source-close":
                    self.assertEqual(operation.calls, [])
                if cause in ("probe", "wrong-role", "late"):
                    self.assertEqual(len(operation.calls), 3)
                    self.assertTrue(operation.calls[-1]["returned"] and operation.calls[-1]["capturesSettled"])
                    self.assertTrue(operation.receipt["targetRetired"])
                retained = cause in ("owner", "sign", "slot-replaced", "content", "flags", "superblob", "source-close", "source-post-close",
                                     "slot-close", "retirement-mode")
                self.assertEqual((fixture.work / operation.target_name).exists(), retained)
                self.assertEqual((fixture.work / "python-supplier-transport/supplier.tar").read_bytes(), fixture.archive)
                if cause == "publication-close":
                    self.assertTrue((fixture.work / "python3").exists())  # Inadmissible partial output, not a capsule.
                    self.assertFalse(operation.receipt["originalClosesKnown"])
                if cause in ("slot-close", "retirement-mode", "publication-close"):
                    self.assertEqual(len(injected), 1)
                    self.assertTrue(operation.errors)
                if cause == "superblob":
                    self.assertEqual(operation.receipt["failure"],
                        {"stage": "python-sign", "type": "Refused", "reason": "python-signature-superblob"})
                    self.assertTrue(operation.calls[0]["returned"] and operation.calls[0]["capturesSettled"])
                    self.assertEqual(operation.calls[0]["returncode"], 0)
                    diagnostic = operation.receipt["pythonSignatureDiagnostic"]
                    self.assertTrue(diagnostic["available"])
                    self.assertEqual(diagnostic["authority"], "original-byte-data-only")
                    self.assertFalse(diagnostic["predicates"]["magicKnown"])
                    self.assertTrue(all(value is True for key, value in diagnostic["predicates"].items()
                                        if key != "magicKnown"))
                    self.assertEqual(diagnostic["tail"]["bytes"], 0)
                    self.assertEqual(diagnostic["tail"]["nonzeroBytes"], 0)
                    self.assertTrue(diagnostic["tail"]["matchesOriginalInput"])
                    self.assertLessEqual(len(TOOL.canonical(diagnostic)), 1536)
                    self.assertTrue(operation.python_mutation_pending)
                    self.assertFalse(operation.receipt["originalClosesKnown"])
                    self.assertIsNone(operation.python_signed)
                else:
                    self.assertNotIn("pythonSignatureDiagnostic", operation.receipt)
        # Failure of the optional reducer cannot replace the original object,
        # clear mutation custody, advance to verify, or publish a signed capsule.
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.python_fixture(Path(directory), failure="superblob")
            operation, primary, caught = fixture.operation, module.Refused("python-signature-superblob"), []
            prepare = operation.python_prepare
            original_flags, original_diagnostic = module.python_code_flags, module.python_signature_diagnostic
            def observed_prepare(modules=None):
                try:
                    return prepare(modules=modules)
                except BaseException as error:
                    caught.append(error)
                    raise
            try:
                with (mock.patch.object(operation, "python_prepare", side_effect=observed_prepare),
                      self.python_fixture_call(fixture),
                      mock.patch.object(module, "python_code_flags", side_effect=primary),
                      mock.patch.object(module, "python_signature_diagnostic", side_effect=ValueError("inert diagnostic refusal")) as diagnostic,
                      self.assertRaisesRegex(module.Refused, "^helper-package-incomplete$")):
                    operation.execute()
                diagnostic.assert_called_once()
            finally:
                self.assertIs(module.python_code_flags, original_flags)
                self.assertIs(module.python_signature_diagnostic, original_diagnostic)
            self.assertEqual(len(caught), 1)
            self.assertIs(caught[0], primary)
            self.assertEqual(operation.receipt["pythonSignatureDiagnostic"],
                {"schemaVersion": 1, "available": False, "authority": "original-byte-data-only"})
            self.assertEqual(operation.receipt["failure"]["reason"], "python-signature-superblob")
            self.assertEqual(len(operation.calls), 1)
            self.assertFalse(operation.receipt["passed"] or operation.receipt["originalClosesKnown"]
                             or operation.receipt["targetRetired"])
            self.assertTrue(operation.python_mutation_pending and (fixture.work / operation.target_name).is_dir())
            self.assertTrue(all(row["fd"] is None for row in operation.entries))
            self.assertFalse((fixture.work / "python3").exists() or (fixture.work / "python-signed-receipt.json").exists())
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


        # Failures in the SAME real private-file context do not become identity
        # lookup fallbacks, retries or a source of public secret diagnostics.
        for failure in ("identity", "duplicate-identity", "certificates", "searchlist", "default", "owner", "late", "root-replaced", "database-mode"):
            with self.subTest(credentialFailure=failure), tempfile.TemporaryDirectory() as directory:
                fixture = self.python_fixture(Path(directory), phase="python-shipping")
                fixture.credentials.failure = failure
                with self.python_fixture_call(fixture) as operation, self.assertRaisesRegex(module.Refused, "^helper-package-incomplete$"):
                    operation.execute()
                known = failure in ("identity", "duplicate-identity", "certificates")
                self.assertEqual(operation.receipt["originalClosesKnown"], known)
                self.assertEqual(operation.receipt["targetRetired"], known)
                self.assertFalse(operation.receipt["passed"])
                self.assertFalse((fixture.work / "python3").exists() or (fixture.work / "python-signed-receipt.json").exists())
                self.assertEqual(len(fixture.observations), 2 if failure == "default" else 0)
                self.assertTrue(all(entry["closed"] for entry in operation.entries))
                roles = [role for role, _argv in fixture.credentials.events]
                if failure in ("searchlist", "owner", "late", "root-replaced", "database-mode"):
                    self.assertNotIn("restore", roles)
                    self.assertNotIn("delete", roles)
                    self.assertTrue(Path(fixture.credentials.keychain).parent.exists())
                elif known:
                    self.assertEqual(fixture.credentials.search, fixture.credentials.initial)
                    self.assertFalse(Path(fixture.credentials.keychain).parent.exists())
                before = len(fixture.credentials.events)
                with self.assertRaisesRegex(module.Refused, "^credential-dispatch-unknown$"):
                    operation.call("never", ["never"], {}, cwd=fixture.work, timeout=1, limit=1)
                self.assertEqual(len(fixture.credentials.events), before)
                public = json.dumps(operation.receipt)
                for secret in ("INERT PRIVATE", fixture.environment[module.CREDENTIAL_VARIABLES[0]],
                               fixture.environment[module.CREDENTIAL_VARIABLES[1]]):
                    self.assertNotIn(secret, public)

        # A partial original write is not a complete credential file. The
        # pending IO latch prevents dispatch/deletion; actual FDs still close.
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.python_fixture(Path(directory), phase="python-shipping")
            operation = fixture.operation
            original_write, writes = module.os.write, []
            def write(fd, data):
                context = operation.credential_active
                entry = context.get("p12") if context is not None else None
                if entry is not None and entry["fd"] == fd:
                    writes.append(len(data))
                    return original_write(fd, data[:1]) if len(writes) == 1 else 0
                return original_write(fd, data)
            with self.python_fixture_call(fixture), mock.patch.object(module.os, "write", side_effect=write), self.assertRaises(module.Refused):
                operation.execute()
            self.assertIs(module.os.write, original_write)
            self.assertEqual(len(writes), 2)
            self.assertEqual(fixture.credentials.events, [])
            self.assertFalse(operation.receipt["passed"] or operation.receipt["originalClosesKnown"] or operation.receipt["targetRetired"])
            self.assertTrue(all(entry["closed"] for entry in operation.entries))

        # Preserve the original callback exception while collecting BOTH a
        # restore fault and multiple consuming-close faults. No private output
        # becomes public and no later native call or delete is attempted.
        with tempfile.TemporaryDirectory() as directory:
            checkout, work, environment, owner, _observations = self.fixture(Path(directory))
            operation = module.Operation(owner, checkout, work, "prepare", environment, TOOL)
            credentials = self.credential_fixture(operation, failure="restore")
            operation.service_profile, operation.producer_profile = credentials.service, credentials.producer
            operation.signing = TOOL.service_signing_data(credentials.service)
            original_close, faults = module.os.close, []
            primary = RuntimeError("INERT PRIVATE primary callback")
            def close(fd):
                context = operation.credential_active
                original_close(fd)  # Really discharge each DATA fixture original once.
                if context is not None and context["retiring"] and operation.credential_unknown and len(faults) < 2:
                    faults.append(fd)
                    raise OSError("INERT PRIVATE consuming close")
            with self.credential_fixture_call(operation, credentials):
                try:
                    operation.open()
                    with mock.patch.object(module.os, "close", side_effect=close):
                        try:
                            with operation.credential_scope("resident-image"):
                                raise primary
                        except BaseException as error:
                            self.assertIs(error, primary)
                        else:
                            self.fail("the primary callback was swallowed")
                    self.assertIs(module.os.close, original_close)
                    self.assertEqual(len(faults), 2)
                    self.assertEqual(len(set(faults)), 2)
                    self.assertTrue(operation.credential_unknown and operation.credential_failed)
                    roles = [role for role, _argv in credentials.events]
                    self.assertIn("restore", roles)
                    self.assertNotIn("delete", roles)
                    self.assertNotIn("search-final", roles)
                    self.assertEqual([row["type"] for row in operation.errors if row["stage"] == "close"], ["OSError", "OSError"])
                    self.assertEqual(sum(row["stage"] == "credential-unwind" for row in operation.errors), 1)
                finally:
                    operation.finish()
            self.assertFalse(operation.receipt["originalClosesKnown"] or operation.receipt["targetRetired"])
            self.assertNotIn("INERT PRIVATE", json.dumps(operation.receipt))

        # Every fixed original's nonzero is a refusal, never an ignored code.
        # The two potentially mutating failures retain their original tree.
        for selected_role in module.NOTARY_ROLES:
            with self.subTest(notary_nonzero=selected_role), tempfile.TemporaryDirectory() as temporary:
                state = self.notary_fixture(Path(temporary), failure=("nonzero", selected_role))
                operation = state.operation
                with self.notary_fixture_call(state), self.assertRaises(module.Refused):
                    operation.execute()
                self.assertEqual(len(state.observations), module.NOTARY_ROLES.index(selected_role) + 1)
                self.assertFalse(operation.receipt["passed"])
                self.assertEqual(operation.receipt["failure"]["reason"], "original-nonzero-" + selected_role)
                self.assertFalse((operation.work / "input").exists())
                self.assertEqual(operation.receipt["targetRetired"], not selected_role.startswith("staple-"))
                self.assertFalse((operation.work / operation.target_name / "notary-key").exists())
                self.assertNotIn("INERT private failure", json.dumps(operation.receipt))

        cases = (("invalid", 7, True), (("invalid-log-nonzero", "payload-log"), 7, True),
                 (("owner", "payload-submit"), 6, False), (("malformed", "payload-submit"), 6, False),
                 (("json", "payload-submit"), 6, True), (("json", "payload-log"), 7, True),
                 ("tool-output", 1, True), ("tool-alias", 1, False), ("source-change", 3, False),
                 ("ticket-mode", 8, False), ("ticket-extra", 8, False), ("signed-byte-change", 8, False),
                 (("late", "payload-submit"), 6, False))
        for failure, count, retired in cases:
            with self.subTest(notary_failure=failure), tempfile.TemporaryDirectory() as temporary:
                state = self.notary_fixture(Path(temporary), failure=failure)
                operation = state.operation
                with self.notary_fixture_call(state), self.assertRaises(module.Refused):
                    operation.execute()
                self.assertEqual(len(state.observations), count)
                self.assertFalse(operation.receipt["passed"])
                self.assertEqual(operation.receipt["targetRetired"], retired)
                self.assertFalse((operation.work / "input").exists())
                if failure in ("invalid", ("invalid-log-nonzero", "payload-log")):
                    self.assertEqual(operation.receipt["failure"]["reason"], "notary-submission-invalid")
                    self.assertEqual(operation.receipt["notarySubmission"]["status"], "Invalid")
                if failure == ("invalid-log-nonzero", "payload-log"):
                    self.assertEqual(operation.receipt["notaryLogFailure"], {"type": "Refused"})
                if failure in (("owner", "payload-submit"), ("malformed", "payload-submit"), ("late", "payload-submit")):
                    self.assertFalse(operation.receipt["originalClosesKnown"])
                    self.assertTrue((operation.work / operation.target_name / "notary-key/AuthKey_DATA000001.p8").exists())
                self.assertNotIn("INERT private original failure", json.dumps(operation.receipt))

        # Readonly child, same-parent rename: known unchanged failure restores
        # the parent; unknown restoration never admits a later native call.
        for failure in ("rename", "restore", "key-close"):
            with self.subTest(notary_original=failure), tempfile.TemporaryDirectory() as temporary:
                state = self.notary_fixture(Path(temporary))
                operation, faults = state.operation, []
                rename, chmod, close = module.os.rename, module.os.fchmod, module.os.close
                def rename_once(*args, **kwargs):
                    if failure == "rename" and args[:2] == ("app", module.NOTARY_APP_NAME):
                        faults.append("rename")
                        raise OSError(5, "INERT rename refusal")
                    return rename(*args, **kwargs)
                def chmod_once(fd, mode):
                    if failure == "restore" and not faults and operation.notary_copy is not None \
                            and fd == operation.notary_copy["entry"]["fd"] and mode == 0o555:
                        faults.append("restore")
                        chmod(fd, mode)
                        raise OSError(5, "INERT unknown restore return")
                    return chmod(fd, mode)
                def close_once(fd):
                    if failure == "key-close" and not faults and operation.notary_key is not None \
                            and operation.notary_key["entry"].get("identity") is not None \
                            and module.signature(module.os.fstat(fd)) == operation.notary_key["entry"]["identity"]:
                        faults.append("close")
                        close(fd)
                        raise OSError(5, "INERT unknown consumed close")
                    return close(fd)
                with (self.notary_fixture_call(state), mock.patch.object(module.os, "rename", side_effect=rename_once),
                      mock.patch.object(module.os, "fchmod", side_effect=chmod_once),
                      mock.patch.object(module.os, "close", side_effect=close_once), self.assertRaises(module.Refused)):
                    operation.execute()
                self.assertEqual(len(faults), 1)
                self.assertIs(module.os.rename, rename); self.assertIs(module.os.fchmod, chmod); self.assertIs(module.os.close, close)
                self.assertEqual(len(state.observations), 7 if failure == "key-close" else 0)
                self.assertEqual(operation.receipt["targetRetired"], failure == "rename")
                self.assertFalse(operation.receipt["passed"] or (operation.work / "input").exists())
                if failure != "rename":
                    self.assertFalse(operation.receipt["originalClosesKnown"])
                    self.assertTrue((operation.work / operation.target_name).exists())
                if failure == "restore":
                    parent = operation.work / operation.target_name / "payload-input"
                    self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o555)
                    self.assertEqual(stat.S_IMODE((parent / module.NOTARY_APP_NAME).stat().st_mode), 0o555)

        # A spaced private basename is still refused by the real stager tree;
        # fixing the fixed alias must not broaden its path policy or cleanup.
        for alias in (TOOL.APP_NAME, "MobileReleaseKit .app"):
            with self.subTest(notary_private_alias=alias), tempfile.TemporaryDirectory() as temporary:
                state = self.notary_fixture(Path(temporary)); operation = state.operation
                with (self.notary_fixture_call(state), mock.patch.object(module, "NOTARY_APP_NAME", alias),
                      self.assertRaises(module.Refused)):
                    operation.execute()
                self.assertEqual(state.observations, [])
                self.assertFalse(operation.receipt["passed"] or operation.receipt["targetRetired"]
                                 or operation.receipt["originalClosesKnown"])
                self.assertEqual(operation.stager_io_pending, "notary-stager-tree")
                self.assertTrue(operation.notary_mutation_pending)
                self.assertFalse((operation.work / "input").exists())
                parent = operation.work / operation.target_name / "payload-input"
                self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o555)
                self.assertEqual(stat.S_IMODE((parent / alias).stat().st_mode), 0o555)
                self.assertFalse((parent / "app").exists())
                self.assertEqual(state.app.name, TOOL.APP_NAME)
                for name, (body, mode) in state.app_files.items():
                    self.assertEqual((state.app / name).read_bytes(), body)
                    self.assertEqual(stat.S_IMODE((state.app / name).stat().st_mode), mode)

        # A late final receipt cannot yield an original0/successful stdout.
        with tempfile.TemporaryDirectory() as temporary:
            state = self.notary_fixture(Path(temporary)); operation = state.operation
            publisher = operation.publish_receipt
            def late_receipt():
                publisher()
                state.clock[0] += 1800 * 1_000_000_000
            with (self.notary_fixture_call(state), mock.patch.object(operation, "publish_receipt", side_effect=late_receipt),
                  self.assertRaisesRegex(module.Refused, "^notary-group-deadline$")):
                operation.execute()
            self.assertEqual(len(state.observations), 13)
            self.assertTrue(operation.receipt["outerFinalityRequired"])
            self.assertFalse(operation.receipt["productReady"])

        # Every primary fixed role must be an actual typed returned/settled0.
        # Unknown/malformed/nonzero/late originals never become a final-P pass.
        for role in module.FINAL_PACKAGE_ROLES:
            for outcome in ("owner", "nonzero", "malformed", "late"):
                failure = role + "-" + outcome
                with self.subTest(finalOriginal=failure), tempfile.TemporaryDirectory() as directory:
                    fixture = self.final_package_fixture(Path(directory), failure=failure)
                    operation = fixture.operation
                    with self.final_package_fixture_call(fixture), self.assertRaises(module.Refused):
                        operation.execute()
                    expected = list(module.FINAL_PACKAGE_ROLES[:module.FINAL_PACKAGE_ROLES.index(role) + 1])
                    self.assertEqual([row[0] for row in fixture.observations], expected)
                    self.assertFalse(operation.receipt["passed"])
                    self.assertNotIn("finalPackage", operation.receipt)
                    self.assertFalse((fixture.work / "package-final").exists())
                    self.assertFalse(any(row[0] == "producer-emitter" for row in fixture.observations))
                    if outcome in ("owner", "malformed"):
                        self.assertFalse(operation.calls[-1]["returned"])
                        self.assertFalse(operation.receipt["targetRetired"])
                        self.assertTrue((fixture.work / operation.target_name).exists())
                    else:
                        self.assertTrue(operation.calls[-1]["returned"] and operation.calls[-1]["capturesSettled"])
                        self.assertEqual(operation.calls[-1]["returncode"], 1 if outcome == "nonzero" else 0)
                    if role == "final-package-sign":
                        self.assertTrue(operation.signing_mutation_pending)
                        self.assertFalse(operation.receipt["targetRetired"])
                    if role == "final-package-staple":
                        self.assertTrue(operation.notary_mutation_pending)
                        self.assertFalse(operation.receipt["targetRetired"])

        for failure in ("signed-input-changed", "signed-roster", "signed-scripts", "submit-json", "submit-status", "log-sha", "log-id",
                "final-package-signature-before-untrusted", "final-package-signature-before-untimestamped", "final-package-signature-before-chain",
                "final-package-signature-after-untrusted", "final-package-signature-after-untimestamped", "final-package-signature-after-chain",
                "ticket-replaced", "ticket-oversize", "ticket-prefix", "ticket-mode", "invalid", "invalid-log-failure"):
            with self.subTest(finalPackageRefusal=failure), tempfile.TemporaryDirectory() as directory:
                fixture = self.final_package_fixture(Path(directory), failure=failure)
                operation = fixture.operation
                with self.final_package_fixture_call(fixture), self.assertRaises(module.Refused):
                    operation.execute()
                self.assertFalse(operation.receipt["passed"])
                self.assertNotIn("finalPackage", operation.receipt)
                self.assertFalse((fixture.work / "package-final").exists())
                roles = [row[0] for row in fixture.observations]
                if failure.startswith("ticket-"):
                    self.assertEqual(roles[-1], "final-package-staple")
                    self.assertTrue(operation.notary_mutation_pending)
                    self.assertFalse(operation.receipt["targetRetired"])
                if failure in ("invalid", "invalid-log-failure"):
                    self.assertEqual(roles[-2:], ["final-package-submit", "final-package-log"])
                    self.assertNotIn("final-package-staple", roles)
                    self.assertEqual(operation.receipt["failure"]["reason"], "final-package-notary-invalid")
                    self.assertIsNone(operation.notary_key)
                    self.assertEqual(operation.receipt["notaryAuthentication"], {"created": True, "closed": True, "retired": True})
                    self.assertTrue(operation.receipt["targetRetired"] and operation.receipt["originalClosesKnown"])
                    if failure == "invalid-log-failure":
                        self.assertEqual(operation.receipt["notaryLogFailure"], {"type": "Refused"})

        # Wrong private identity, purpose/chain, searchlist/restore, DB mode and
        # unknown Security original preserve the same earlier failure/finality.
        for failure in ("identity", "duplicate-identity", "certificates", "installer-chain", "restore", "default", "owner", "late", "database-mode"):
            with self.subTest(installerCredentialFailure=failure), tempfile.TemporaryDirectory() as directory:
                fixture = self.final_package_fixture(Path(directory))
                fixture.credentials.failure = failure
                operation = fixture.operation
                with self.final_package_fixture_call(fixture), self.assertRaises(module.Refused):
                    operation.execute()
                self.assertFalse(operation.receipt["passed"])
                self.assertNotIn("finalPackage", operation.receipt)
                self.assertNotIn("final-package-submit", [row[0] for row in fixture.observations])
                self.assertFalse((fixture.work / "package-final").exists())
                if failure in ("identity", "duplicate-identity", "certificates", "installer-chain", "database-mode"):
                    self.assertNotIn("final-package-sign", [row[0] for row in fixture.observations])

        # A serialized pass alone never authorizes the next producer. Exercise
        # the actual held handoff, including missing/duplicate status or JSON
        # and a changed final P, without any emitter/Installer invocation.
        for failure in ("missing-status", "nonzero-status", "duplicate-status", "missing-receipt", "duplicate-receipt", "changed-final-p"):
            with self.subTest(finalHandoff=failure), tempfile.TemporaryDirectory() as directory:
                fixture = self.final_package_fixture(Path(directory))
                with self.final_package_fixture_call(fixture):
                    fixture.operation.execute()
                status = fixture.work / "package-finalization.status"
                if failure != "missing-status":
                    status.write_bytes(b"1\n" if failure == "nonzero-status" else b"0\n0\n" if failure == "duplicate-status" else b"0\n")
                    status.chmod(0o600)
                receipt = fixture.work / "android-helper-finalize-package.json"
                if failure == "missing-receipt":
                    receipt.unlink()
                elif failure == "duplicate-receipt":
                    receipt.write_bytes(b'{"schemaVersion":1,' + receipt.read_bytes()[1:])
                elif failure == "changed-final-p":
                    path = fixture.work / "package-final/MobileReleaseKit.pkg"
                    path.chmod(0o600); path.write_bytes(path.read_bytes() + b"FOREIGN AFTER FINAL P"); path.chmod(0o444)
                later = module.Operation(SimpleNamespace(run_owned=lambda *_a, **_k: self.fail("no native handoff on refusal")),
                    fixture.checkout, fixture.work, "package-install", fixture.environment, TOOL, target=fixture.target)
                later.package_started = later.package_observed = fixture.clock[0]
                later.package_endpoint = fixture.clock[0] + 990_000_000_000
                later.signing = fixture.operation.signing
                with self.credential_fixture_call(later, fixture.credentials):
                    try:
                        later.open(); later.image_binding()
                        parent = later.directory(later.work_entry, "package-final", "final-original-directory")
                        original = later.original(parent, "MobileReleaseKit.pkg", "final-package-original", TOOL.MAX_BYTES, (0o444,))
                        with self.assertRaises((module.Refused, FileNotFoundError)):
                            later.package_finalization_input(original, later.read(original))
                        self.assertEqual(later.calls, [])
                    finally:
                        later.finish()
                self.assertFalse(later.receipt["passed"])
                self.assertEqual(later.calls, [])

        # Finite held-original close/publication faults. Close injection first
        # consumes the REAL original FD, then reports uncertainty; no retry is
        # permitted and the retained target cannot acquire success authority.
        for failure in ("key-close", "invalid-key-close", "key-directory-close", "output-close", "mode-after-effect", "rename-after-effect",
                        "published-readback", "receipt-close"):
            with self.subTest(finalPackageBoundary=failure), tempfile.TemporaryDirectory() as directory:
                fixture = self.final_package_fixture(Path(directory), failure="invalid" if failure == "invalid-key-close" else None)
                operation = fixture.operation
                injected = OSError("INERT original close/publication failure")
                observed = []
                original_close, original_fchmod, original_rename = module.os.close, module.os.fchmod, module.os.rename
                original_stream = operation.notary_stream
                def close(fd):
                    chosen = None
                    if not observed:
                        for entry in operation.entries:
                            # Operation.close consumes entry['fd'] before the
                            # syscall. Match its retained original full9 instead.
                            expected = entry.get("identity")
                            if expected is not None and entry["role"] in ("notary-private-key", "notary-key-directory", "final-package-signed-original"):
                                actual = module.os.fstat(fd)
                                same = (actual.st_dev, actual.st_ino) == expected[:2]
                                wanted = {"key-close": "notary-private-key", "invalid-key-close": "notary-private-key", "key-directory-close": "notary-key-directory",
                                          "output-close": "final-package-signed-original"}.get(failure)
                                if same and entry["role"] == wanted:
                                    chosen = failure
                        if failure == "receipt-close":
                            path = fixture.work / "android-helper-finalize-package.json"
                            if path.exists() and (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (path.stat().st_dev, path.stat().st_ino):
                                chosen = failure
                    original_close(fd)
                    if chosen is not None:
                        observed.append(chosen)
                        raise injected
                def chmod(fd, mode):
                    selected = (failure == "mode-after-effect" and not observed and operation.stage == "final-package-mode-and-publication"
                                and operation.final_package_output is not None and fd == operation.final_package_output["fd"] and mode == 0o444)
                    result = original_fchmod(fd, mode)
                    if selected:
                        observed.append(failure)
                        raise injected
                    return result
                def rename(*args, **kwargs):
                    result = original_rename(*args, **kwargs)
                    if failure == "rename-after-effect" and not observed and operation.stage == "final-package-mode-and-publication":
                        observed.append(failure)
                        raise injected
                    return result
                def stream(entry, **kwargs):
                    result = original_stream(entry, **kwargs)
                    if (failure == "published-readback" and not observed and operation.stage == "final-package-mode-and-publication"
                            and entry is operation.final_package_output and entry["parent_entry"].get("name") == "package-final"):
                        observed.append(failure)
                        return "0" * 64
                    return result
                with self.final_package_fixture_call(fixture), mock.patch.object(module.os, "close", side_effect=close), \
                        mock.patch.object(module.os, "fchmod", side_effect=chmod), mock.patch.object(module.os, "rename", side_effect=rename), \
                        mock.patch.object(operation, "notary_stream", side_effect=stream):
                    if failure == "receipt-close":
                        with self.assertRaises(OSError) as raised:
                            operation.execute()
                        self.assertIs(raised.exception, injected)
                    else:
                        with self.assertRaises(module.Refused):
                            operation.execute()
                self.assertEqual(observed, [failure])
                self.assertIs(module.os.close, original_close)
                self.assertIs(module.os.fchmod, original_fchmod)
                self.assertIs(module.os.rename, original_rename)
                if failure != "receipt-close":
                    self.assertFalse(operation.receipt["passed"])
                    self.assertFalse(operation.receipt["originalClosesKnown"])
                    self.assertFalse(operation.receipt["targetRetired"])
                else:
                    # A provisional serialized pass is not a returned helper0.
                    # The following fixed caller still requires its status0.
                    self.assertFalse((fixture.work / "package-finalization.status").exists())
                if failure in ("key-close", "invalid-key-close", "key-directory-close"):
                    self.assertNotIn("final-package-staple", [row[0] for row in fixture.observations])
                if failure == "invalid-key-close":
                    self.assertEqual(operation.receipt["failure"]["reason"], "final-package-notary-invalid")
                    self.assertTrue(operation.errors)
                self.assertFalse(any(row[0] == "producer-emitter" for row in fixture.observations))

        # Missing/cross-purpose secrets and a SOURCE Application leaf are
        # refused before productsign or long notarization, never an ambient key.
        for failure in ("missing-installer-key", "application-secret", "application-leaf", "wrong-public-der", "unconfigured"):
            with self.subTest(installerPurpose=failure), tempfile.TemporaryDirectory() as directory:
                fixture = self.final_package_fixture(Path(directory))
                if failure == "missing-installer-key":
                    fixture.environment.pop(module.INSTALLER_CREDENTIAL_VARIABLES[0])
                elif failure == "application-secret":
                    fixture.environment[module.CREDENTIAL_VARIABLES[0]] = "aW5lcnQ="
                elif failure == "wrong-public-der":
                    (fixture.checkout / "desktop/packaging/macos-installer-certificates/leaf.der").write_bytes(b"FOREIGN PUBLIC DATA")
                else:
                    value = ({"schemaVersion": 1, "mode": "unconfigured"} if failure == "unconfigured"
                             else dict(fixture.credentials.installer, leafSha1=fixture.credentials.application_leaf))
                    (fixture.checkout / module.INSTALLER_PROFILE).write_bytes(TOOL.canonical(value))
                with self.final_package_fixture_call(fixture), self.assertRaises(module.Refused):
                    fixture.operation.execute()
                self.assertFalse(fixture.operation.receipt["passed"])
                self.assertNotIn("final-package-sign", [row[0] for row in fixture.observations])
                self.assertNotIn("final-package-submit", [row[0] for row in fixture.observations])

        # Each of the11 SAME original roles is fail-closed for raised,
        # malformed, nonzero and late return. No late role gains a new clock.
        for role in module.FINAL_IMAGE_ROLES:
            for outcome in ("owner", "malformed", "nonzero", "late"):
                failure = role + "-" + outcome
                with self.subTest(finalImageOriginal=failure), tempfile.TemporaryDirectory() as directory:
                    state = self.final_image_fixture(Path(directory), failure=failure)
                    operation = state.operation
                    with self.final_image_fixture_call(state), self.assertRaises(module.Refused):
                        operation.execute()
                    expected = list(module.FINAL_IMAGE_ROLES[:module.FINAL_IMAGE_ROLES.index(role) + 1])
                    self.assertEqual([row[0] for row in state.observations], expected)
                    self.assertFalse(operation.receipt["passed"])
                    self.assertNotIn("finalImage", operation.receipt)
                    self.assertFalse((state.work / "distribution-final").exists())
                    self.assertFalse(operation.installer_entered)
                    self.assertEqual((state.work / "distribution/MobileReleaseKit.dmg").read_bytes(), state.original_image)
                    if outcome in ("owner", "malformed"):
                        self.assertFalse(operation.calls[-1]["returned"] or operation.receipt["targetRetired"])
                    else:
                        self.assertTrue(operation.calls[-1]["returned"] and operation.calls[-1]["capturesSettled"])
                        self.assertEqual(operation.calls[-1]["returncode"], 1 if outcome == "nonzero" else 0)
                    if role == "final-image-staple":
                        self.assertTrue(operation.notary_mutation_pending)
                        self.assertFalse(operation.receipt["targetRetired"])

        for failure in ("submit-json", "submit-name", "log-sha", "nested-null-annotation", "invalid", "invalid-log-failure",
                        "ticket-replaced", "ticket-oversize", "ticket-mode", "mounted-bytes", "mounted-extra"):
            with self.subTest(finalImageRefusal=failure), tempfile.TemporaryDirectory() as directory:
                state = self.final_image_fixture(Path(directory), failure=failure)
                operation = state.operation
                with self.final_image_fixture_call(state), self.assertRaises(module.Refused): operation.execute()
                self.assertFalse(operation.receipt["passed"] or (state.work / "distribution-final").exists())
                roles = [row[0] for row in state.observations]
                if failure.startswith("submit-"):
                    self.assertEqual(roles[-1], "final-image-submit")
                if failure in ("invalid", "invalid-log-failure"):
                    self.assertEqual(roles[-2:], ["final-image-submit", "final-image-log"])
                    self.assertEqual(operation.receipt["failure"]["reason"], "final-image-notary-invalid")
                    self.assertNotIn("final-image-staple", roles)
                if failure.startswith("ticket-"):
                    self.assertEqual(roles[-1], "final-image-staple")
                    self.assertTrue(operation.notary_mutation_pending)
                    self.assertFalse(operation.receipt["targetRetired"])
                if failure.startswith("mounted-"):
                    self.assertEqual(roles[-2:], ["final-image-attach", "final-image-detach"])
                    self.assertTrue(operation.mount_detached and operation.receipt["originalClosesKnown"])
                    self.assertFalse((state.work / "package-mount").exists())

        # Unknown consuming closes and direct-write/rename returns retain
        # custody. Even a file already moved into its final directory cannot
        # be consumed without the missing actual0 and closed final receipt.
        for failure in ("capture-close", "key-close", "mounted-close", "copy-write", "publication-rename"):
            with self.subTest(finalImageUnknown=failure), tempfile.TemporaryDirectory() as directory:
                state = self.final_image_fixture(Path(directory)); operation = state.operation
                faults = []
                actual_close, actual_write, actual_rename = module.os.close, module.os.write, module.os.rename
                book_close, pending_close = operation.close, {"fd": None}
                selected = {"capture-close": "output-android-helper-final-image-signature-before.stdout",
                            "key-close": "notary-private-key", "mounted-close": "mounted-Install.pkg"}.get(failure)
                def original_close(entry):
                    if not faults and entry["role"] == selected and entry["fd"] is not None:
                        pending_close["fd"] = entry["fd"]
                    return book_close(entry)
                def close(fd):
                    # Bind the exact book FD before Operation.close consumes
                    # its slot; the actual os.close then takes effect once.
                    if not faults and fd == pending_close["fd"]:
                        faults.append(failure); actual_close(fd)
                        raise OSError(5, "INERT uncertain consumed close")
                    return actual_close(fd)
                def write(fd, body):
                    entry = operation.final_image_output
                    if failure == "copy-write" and not faults and entry is not None and fd == entry["fd"]:
                        faults.append(failure); actual_write(fd, body[:1])
                        raise OSError(5, "INERT uncertain partial write")
                    return actual_write(fd, body)
                def rename(*args, **kwargs):
                    if failure == "publication-rename" and not faults and operation.stage == "final-image-owned-publication":
                        faults.append(failure); actual_rename(*args, **kwargs)
                        raise OSError(5, "INERT uncertain completed rename")
                    return actual_rename(*args, **kwargs)
                with (self.final_image_fixture_call(state), mock.patch.object(operation, "close", side_effect=original_close),
                      mock.patch.object(module.os, "close", side_effect=close),
                      mock.patch.object(module.os, "write", side_effect=write), mock.patch.object(module.os, "rename", side_effect=rename),
                      self.assertRaises(module.Refused)):
                    operation.execute()
                self.assertEqual(faults, [failure])
                self.assertIs(module.os.close, actual_close); self.assertIs(module.os.write, actual_write); self.assertIs(module.os.rename, actual_rename)
                self.assertFalse(operation.receipt["passed"] or operation.receipt["targetRetired"] or operation.receipt["originalClosesKnown"])
                self.assertNotIn("finalImage", operation.receipt)
                self.assertTrue((state.work / operation.target_name).exists())
                roles = [row[0] for row in state.observations]
                if failure == "capture-close": self.assertEqual(roles, list(module.FINAL_IMAGE_ROLES[:3]))
                if failure == "key-close": self.assertEqual(roles, list(module.FINAL_IMAGE_ROLES[:5]))
                if failure == "mounted-close":
                    self.assertEqual(roles, list(module.FINAL_IMAGE_ROLES[:10]))
                    self.assertTrue(operation.mount_known and not operation.mount_detached)
                if failure == "copy-write": self.assertEqual(roles, [])
                if failure == "publication-rename":
                    self.assertEqual(roles, list(module.FINAL_IMAGE_ROLES))
                    self.assertTrue((state.work / "distribution-final/MobileReleaseKit.dmg").exists())
                self.assertEqual((state.work / "distribution/MobileReleaseKit.dmg").read_bytes(), state.original_image)
                with self.assertRaises(module.Refused):
                    operation.final_image_call("final-image-detach", ["never", "execute"])



    def test_clean_environment_and_configured_profile_refuse_any_ad_hoc_fallback(self):
        module = ANDROID_HELPER
        with tempfile.TemporaryDirectory() as temporary:
            checkout, work, environment, owner, observations = self.fixture(Path(temporary), "profile")
            environment.update(RUSTC_WRAPPER="unrelated", CARGO_ENCODED_RUSTFLAGS="unrelated", GITHUB_TOKEN="inert-DATA",
                               MRK_ANDROID_TOOL_INSTANCE="unrelated", MRK_IMAGE_RELEASE_ID="untrusted-release",
                               MRK_MACOS_DEVELOPER_ID_P12_BASE64="aW5lcnQ=", MRK_MACOS_DEVELOPER_ID_P12_PASSWORD="inert secret")
            selected = module.build_environment(environment, work, TOOL.RELEASE)
            self.assertEqual(selected["MRK_IMAGE_RELEASE_ID"], TOOL.RELEASE)
            for release in ("", "x" * 64, 'bad"macro', "nonascii-é"):
                with self.subTest(release=release), self.assertRaises(module.Refused):
                    module.build_environment(environment, work, release)
            self.assertEqual(selected["RUSTUP_TOOLCHAIN"], "1.98.1")
            self.assertEqual(selected["RUSTUP_AUTO_INSTALL"], "0")
            for target, toolchain in (("aarch64-apple-darwin", "1.98.1"), ("x86_64-apple-darwin", "1.98.0")):
                directory = "/Users/runner/.rustup/toolchains/stable-" + target + "/bin"
                selected_environment = dict(environment, RUSTUP_TOOLCHAIN=toolchain)
                cleaned = module.build_environment(selected_environment, work, TOOL.RELEASE, target=target)
                self.assertEqual(module.direct_rust_tools(target), (directory + "/cargo", directory + "/rustc"))
                self.assertEqual(module.rust_toolchain(target), toolchain)
                self.assertEqual(cleaned["RUSTUP_TOOLCHAIN"], toolchain)
                absent = dict(selected_environment); del absent["RUSTUP_TOOLCHAIN"]
                self.assertEqual(module.build_environment(absent, work, TOOL.RELEASE, target=target), cleaned)
                receipt = module.Operation(owner, checkout, work, "prepare", selected_environment, TOOL, target=target).receipt
                self.assertEqual((receipt["target"], receipt["toolchain"], receipt["passed"]), (target, toolchain, False))
                for wrong in ("1.98.0" if toolchain == "1.98.1" else "1.98.1", "nightly", None, True):
                    with self.subTest(target=target, selector=wrong), self.assertRaisesRegex(module.Refused, "^direct-rust-source-route$"):
                        module.build_environment(dict(selected_environment, RUSTUP_TOOLCHAIN=wrong), work, TOOL.RELEASE, target=target)
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
            self.assertFalse(set(module.CREDENTIAL_VARIABLES) & selected.keys())
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
                credentials = self.credential_fixture(operation)
                peaks, original_register = [], operation.register
                def register(*args, **kwargs):
                    entry = original_register(*args, **kwargs)
                    peaks.append(sum(row["fd"] is not None for row in operation.entries))
                    return entry
                with self.credential_fixture_call(operation, credentials), mock.patch.object(operation, "register", side_effect=register):
                    if failed_sign:
                        with self.assertRaises(module.Refused): operation.execute()
                    else:
                        operation.execute()
                self.assertLessEqual(max(peaks), 60)  # Actual fixture descriptors, below inherited64 incl stdio.
                self.assertEqual(credentials.search, credentials.initial)
                self.assertFalse(Path(credentials.keychain).parent.exists())
                self.assertTrue(all(all(row[key] is True for key in ("closed", "retired", "searchRestored", "defaultUnchanged"))
                                    for row in operation.credential_contexts))
                self.assertEqual(len(operation.credential_contexts), 1 if failed_sign else 2)
                self.assertLessEqual(len(operation.credential_calls), 64)
                self.assertFalse(set(module.CREDENTIAL_VARIABLES) & operation.native_environment().keys())
                sign = [argv for argv, _ in observations if "--sign" in argv]
                self.assertEqual(len(sign), 1 if failed_sign else 2)
                self.assertTrue(all(argv[argv.index("--sign") + 1] == credentials.leaf and "--timestamp" in argv
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
                        self.assertIn('certificate leaf = H"' + credentials.leaf + '"', requirement)
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
        # The optional reducer distinguishes the actual compound terms, but
        # none of its observations admits a signature rejected by the parser.
        for target in (module.ARM_TARGET, module.INTEL_TARGET):
            body, machine = self.python_image(target, 0x10002), module.build_profile(target)[0]
            offset, size = struct.unpack_from("<II", body, 40)
            good = module.python_signature_diagnostic(body, body, machine, matcher)
            self.assertEqual(set(good), {"schemaVersion", "available", "authority", "input", "output", "signature", "predicates", "tail"})
            self.assertEqual((good["schemaVersion"], good["available"], good["authority"]), (1, True, "original-byte-data-only"))
            self.assertEqual(good["input"], {"bytes": len(body), "sha256": module.digest(body)})
            self.assertEqual(good["output"], good["input"])
            self.assertEqual(good["signature"], {"offset": offset, "allocatedBytes": size,
                "magic": 0xFADE0CC0, "declaredBytes": size, "count": 1})
            self.assertTrue(all(type(value) is int for value in good["signature"].values()))
            self.assertEqual(good["predicates"], {"magicKnown": True, "countAtLeastOne": True,
                "countAtMost32": True, "indexFitsDeclared": True, "declaredFitsAllocation": True, "allocationTailZero": True})
            self.assertTrue(all(type(value) is bool for value in good["predicates"].values()))
            self.assertEqual(good["tail"], {"bytes": 0, "nonzeroBytes": 0, "firstNonzeroOffset": None,
                "lastNonzeroOffset": None, "sha256": module.digest(b""), "matchesOriginalInput": True})
            for word, value, term in ((0, 0, "magicKnown"), (8, 0, "countAtLeastOne"),
                (8, 33, "countAtMost32"), (8, 0xFFFFFFFF, "countAtMost32"),
                (4, 19, "indexFitsDeclared"), (4, 0, "indexFitsDeclared"), (4, 0xFFFFFFFF, "declaredFitsAllocation")):
                bad = bytearray(body); struct.pack_into(">I", bad, offset + word, value); bad = bytes(bad)
                with self.subTest(target=target, word=word, value=value):
                    with self.assertRaisesRegex(module.Refused, "^python-signature-superblob$"):
                        module.python_code_flags(bad, machine, "python-engineering", matcher)
                    row = module.python_signature_diagnostic(body, bad, machine, matcher)
                    self.assertIs(row["predicates"][term], False)
                    self.assertEqual(row["output"], {"bytes": len(bad), "sha256": module.digest(bad)})
                    self.assertLessEqual(len(TOOL.canonical(row)), 1536)
                    if word == 4 and (value < 12 or value > size):
                        self.assertIsNone(row["tail"])
                        self.assertIsNone(row["predicates"]["allocationTailZero"])
            padded = bytearray(body + bytes(16)); struct.pack_into("<I", padded, 44, size + 16); padded = bytes(padded)
            self.assertEqual(module.python_code_flags(padded, machine, "python-engineering", matcher), [0x10002])
            zero = module.python_signature_diagnostic(padded, padded, machine, matcher)
            self.assertEqual(zero["tail"]["bytes"], 16)
            self.assertIs(zero["predicates"]["allocationTailZero"], True)
            bad = bytearray(padded); bad[-15] = 0xA5; bad[-2] = 0x5A; bad = bytes(bad)
            # Allocation padding is not a SuperBlob component or an admission
            # predicate. Its exact bytes remain in the original signed image.
            self.assertEqual(module.python_code_flags(bad, machine, "python-engineering", matcher), [0x10002])
            for word, value, reason in ((16, size, "python-signature-index"),
                (16, size - 7, "python-signature-index"), (16, 19, "python-signature-index"),
                (24, 45, "python-signature-components"), (24, 7, "python-signature-components")):
                malformed = bytearray(bad); struct.pack_into(">I", malformed, offset + word, value)
                with self.subTest(target=target, declaredWord=word, value=value):
                    with self.assertRaisesRegex(module.Refused, "^" + reason + "$"):
                        module.python_code_flags(bytes(malformed), machine, "python-engineering", matcher)
            for original, matches in ((bad, True), (padded, False), (body, None)):
                row = module.python_signature_diagnostic(original, bad, machine, matcher)
                self.assertEqual(row["input"], {"bytes": len(original), "sha256": module.digest(original)})
                self.assertEqual(row["tail"], {"bytes": 16, "nonzeroBytes": 2, "firstNonzeroOffset": 1,
                    "lastNonzeroOffset": 14, "sha256": module.digest(bad[-16:]), "matchesOriginalInput": matches})
                self.assertIs(row["predicates"]["allocationTailZero"], False)
                self.assertLessEqual(len(TOOL.canonical(row)), 1536)
            maximum = bytearray(body + bytes(1024 * 1024 - size))
            struct.pack_into("<I", maximum, 44, 1024 * 1024); maximum = bytes(maximum)
            row = module.python_signature_diagnostic(body, maximum, machine, matcher)
            self.assertEqual(row["tail"]["bytes"], 1024 * 1024 - size)
            self.assertIs(row["tail"]["matchesOriginalInput"], None)
            self.assertIs(row["predicates"]["allocationTailZero"], True)
            self.assertLessEqual(len(TOOL.canonical(row)), 1536)
            oversized = bytearray(maximum + b"\0"); struct.pack_into("<I", oversized, 44, 1024 * 1024 + 1)
            for invalid in (body[:-1], body + b"x", bytes(oversized)):
                with self.assertRaises(module.Refused):
                    module.python_signature_diagnostic(body, invalid, machine, matcher)
            for old, new, arch in ((None, body, machine), (body, bytearray(body), machine),
                                   (b"", body, machine), (body, body, True), (body, body, "aarch64")):
                with self.assertRaises(module.Refused):
                    module.python_signature_diagnostic(old, new, arch, matcher)
            original_bound = module.MAX_HELPER
            try:
                with mock.patch.object(module, "MAX_HELPER", len(body) - 1), self.assertRaises(module.Refused):
                    module.python_signature_diagnostic(body, body, machine, matcher)
            finally:
                self.assertEqual(module.MAX_HELPER, original_bound)
        # Same existing filesystem fixture, with native returns still DATA
        # doubles: a nonzero allocation tail survives verify, hash and publish.
        original_image = self.python_image
        tail = b"\xa5" + bytes(14) + b"\x5a"
        def image_with_allocation_tail(target, flags=0x2):
            image = bytearray(original_image(target, flags) + tail)
            allocated = struct.unpack_from("<I", image, 44)[0]
            struct.pack_into("<I", image, 44, allocated + len(tail))
            return bytes(image)
        for target in (module.ARM_TARGET, module.INTEL_TARGET):
            for phase in module.PYTHON_PHASES:
                with self.subTest(allocationTarget=target, purpose=phase), tempfile.TemporaryDirectory() as directory:
                    with mock.patch.object(self, "python_image", side_effect=image_with_allocation_tail):
                        fixture = self.python_fixture(Path(directory), target=target, phase=phase)
                    with self.python_fixture_call(fixture) as operation:
                        self.assertEqual(operation.execute(), module.digest(fixture.signed))
                    self.assertEqual(operation.python_signed, fixture.signed)
                    self.assertEqual(operation.sha256, module.digest(fixture.signed))
                    self.assertEqual(fixture.signed[-len(tail):], tail)
                    self.assertEqual([row[0] for row in fixture.observations], list(module.PYTHON_ROLES))
                    verify = fixture.observations[1][1]
                    self.assertEqual(verify[:4], ("/usr/bin/codesign", "--verify", "--strict", "--all-architectures"))
                    self.assertTrue(operation.receipt["passed"] and operation.receipt["originalClosesKnown"]
                                    and operation.receipt["targetRetired"] and all(row["closed"] for row in operation.entries))
                    self.assertNotIn("pythonSignatureDiagnostic", operation.receipt)
                    self.assertFalse(operation.receipt["productReady"] or operation.receipt["developerIdOrNotarizationQualified"])
                    self.assertEqual((fixture.work / "python-supplier-transport/supplier.tar").read_bytes(), fixture.archive)
                    if phase == "python-shipping":
                        self.assertEqual((fixture.work / "python3").read_bytes(), fixture.signed)
                    else:
                        self.assertFalse((fixture.work / "python3").exists())
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

        # Canonical bounded secret decoding and finite public query projections;
        # these bytes are inert fixtures, never a key/certificate qualification.
        first, second = module.CREDENTIAL_VARIABLES
        for body in (b"x", b"INERT DATA", b"x" * 32768):
            encoded = module.base64.b64encode(body).decode("ascii")
            self.assertEqual(module.credential_values({first: encoded, second: "inert password"}), (body, "inert password"))
        for encoded, password in ((None, "x"), ("", "x"), ("eA==\n", "x"), ("eB==", "x"),
            ("éA==", "x"), ("!!!!", "x"), ("====", "x"), ("eA=", "x"), ("eA==", ""),
            ("eA==", "x" * 1025), ("eA==", "x\0"), ("eA==", "x\n"), ("eA==", "é"),
            (module.base64.b64encode(b"x" * 32769).decode("ascii"), "x")):
            with self.subTest(encodedLength=len(encoded) if isinstance(encoded, str) else None, passwordLength=len(password)), self.assertRaises(module.Refused):
                module.credential_values({first: encoded, second: password})
        self.assertEqual(module.credential_paths(b'    "/Users/runner/Library/Keychains/login.keychain-db"\n'),
                         ("/Users/runner/Library/Keychains/login.keychain-db",))
        self.assertEqual(module.credential_paths(b""), ())
        for value in (b'"/a"', b'"relative"\n', b'"/a/../b"\n', b'"/a//b"\n', b'"/a\\b"\n',
                      b'"/a"\n"/a"\n', b'"/a\r"\n', b'"/a"\r\n', b"\xff\n",
                      b"".join(('"/keychain' + str(n) + '"\n').encode("ascii") for n in range(17))):
            with self.subTest(pathBytes=len(value)), self.assertRaises(module.Refused): module.credential_paths(value)
        with self.assertRaises(module.Refused): module.credential_paths(b"", single=True)
        certs = (b"INERT LEAF", b"INERT ISSUER", b"INERT ROOT")
        identity = ("TEST000001", module.hashlib.sha1(certs[0]).hexdigest())
        identity_body = ('  1) ' + identity[1].upper() + ' "INERT public identity"\n    1 valid identities found\n').encode("ascii")
        def pem(values):
            return b"".join(b"-----BEGIN CERTIFICATE-----\n" + module.base64.b64encode(value)
                            + b"\n-----END CERTIFICATE-----\n" for value in values)
        for values in (certs, (certs[0],), (certs[2], certs[0])):
            self.assertIsNone(module.credential_identity(identity_body, pem(values), identity, certs))
        for row, body in ((identity_body + identity_body, pem(certs)), (identity_body.replace(b"1 valid", b"2 valid"), pem(certs)),
            (identity_body.replace(identity[1].upper().encode("ascii"), b"0" * 40), pem(certs)),
            (b"\xff", pem(certs)), (identity_body, pem((certs[1],))), (identity_body, pem((certs[0], certs[0]))),
            (identity_body, pem((certs[0], b"INERT FOREIGN"))), (identity_body, pem(certs) + b"trailing")):
            with self.subTest(identityBytes=len(row), certificateBytes=len(body)), self.assertRaises(module.Refused):
                module.credential_identity(row, body, identity, certs)
        display = b"Signature=adhoc\nCDHash=" + b"c" * 40 + b"\n"
        self.assertEqual(module.credential_cdhash(display), "c" * 40)
        for value in (display + b"CDHash=malformed\n", display + display, display + b"Signature=other\n", b"\xff",
                      display.replace(b"adhoc", b"configured"), display.replace(b"c" * 40, b"c" * 39), b"x" * 16385):
            with self.subTest(displayBytes=len(value)), self.assertRaises(module.Refused): module.credential_cdhash(value)
        self.assertEqual(module.PHASES, ("prepare", "verify-before", "verify-after", "package-install"))
        self.assertEqual(module.SIGNING_PHASES, ("sign-vault-helper", "sign-desktop-image", "sign-desktop-payload", "sign-root-app", "sign-root-installer"))
        for phase in module.SIGNING_PHASES:
            for target in (module.ARM_TARGET, module.INTEL_TARGET):
                self.assertEqual(module.entrypoint(["tool", phase, "--target", target]), (phase, target))
            with self.assertRaises(module.Refused): module.entrypoint(["tool", phase, "arbitrary-path"])

        self.assertEqual(module.NOTARY_PHASES, ("notarize-payload",))
        self.assertEqual(len(module.NOTARY_ROLES), 13)
        self.assertEqual(sum(1200 if name == "payload-submit" else 180 if name == "payload-zip" else 30 for name in module.NOTARY_ROLES), 1710)
        for target in TOOL.MAC_TARGETS:
            self.assertEqual(module.entrypoint(["tool", "notarize-payload", "--target", target]), ("notarize-payload", target))
        identity = ("TEST000001", "1" * 40)
        profile = {"schemaVersion": 1, "mode": "app-store-connect-team-key", "teamId": "TEST000001",
                   "keyId": "DATA000001", "issuerId": "11111111-2222-3333-4444-555555555555"}
        self.assertEqual(module.notary_service(TOOL.canonical(profile), identity), profile)
        for changed in ({"schemaVersion": 1, "mode": "unconfigured"}, dict(profile, schemaVersion=True),
                        dict(profile, mode="keychain-profile"), dict(profile, teamId="OTHER00001"), dict(profile, keyId="../key"),
                        dict(profile, issuerId="0" * 36), dict(profile, extra=True)):
            with self.subTest(notary_profile=changed), self.assertRaises(module.Refused):
                module.notary_service(TOOL.canonical(changed), identity)
        for body in (b"", b"x" * 1025, b'{"schemaVersion":1,"schemaVersion":1}', b"\xff", b'{"x":NaN}'):
            with self.subTest(notary_profile_bytes=len(body)), self.assertRaises(module.Refused):
                module.notary_service(body, identity)
        key = b"-----BEGIN PRIVATE KEY-----\nSU5FUlQ=\n-----END PRIVATE KEY-----\n"
        encoded = module.base64.b64encode(key).decode("ascii")
        self.assertEqual(module.notary_key_data({module.NOTARY_KEY_VARIABLE: encoded}), key)
        for value in (None, "", encoded + "\n", encoded + "=", "x" * 10925,
                      module.base64.b64encode(b"not PKCS8 PEM").decode("ascii"),
                      module.base64.b64encode(key.replace(b"\n", b"\r\n")).decode("ascii")):
            with self.subTest(notary_key_type=type(value).__name__), self.assertRaises(module.Refused):
                module.notary_key_data({module.NOTARY_KEY_VARIABLE: value})
        submission = {"id": "abcdef12-3456-789a-bcde-0123456789ab", "status": "Accepted"}
        self.assertEqual(module.notary_submit_data(TOOL.canonical(submission)), submission)
        for changed in (dict(submission, status="In Progress"), dict(submission, status=True), dict(submission, id="unknown"),
                        dict(submission, name="other.zip"), dict(submission, extra=True)):
            with self.subTest(notary_submit=changed), self.assertRaises(module.Refused):
                module.notary_submit_data(TOOL.canonical(changed))
        log = {"logFormatVersion": 1, "jobId": submission["id"].upper(), "status": "Accepted",
               "archiveFilename": module.NOTARY_ZIP_NAME, "sha256": "c" * 64, "issues": None, "ticketContents": []}
        parsed = module.notary_log_data(TOOL.canonical(log), submission, "c" * 64)
        self.assertEqual((parsed["sha256Compared"], parsed["errorCount"], parsed["ticketRowCount"]), (True, 0, 0))
        no_hash = dict(log); del no_hash["sha256"]
        self.assertFalse(module.notary_log_data(TOOL.canonical(no_hash), submission, "c" * 64)["sha256Compared"])
        changes = (dict(log, jobId="99999999-2222-3333-4444-666666666666"), dict(log, sha256="d" * 64),
            dict(log, archiveFilename="another.zip"), dict(log, status="Invalid"), dict(log, logFormatVersion=True),
            dict(log, issues=[{"severity": "error", "path": "inert", "message": "inert error"}]),
            dict(log, issues=[{"severity": "warning", "path": 1, "message": "inert"}]),
            dict(log, issues=[{}] * 2049), dict(log, ticketContents=[{}]), dict(log, extra=True))
        for changed in changes:
            with self.subTest(notary_log_keys=tuple(changed)), self.assertRaises(module.Refused):
                module.notary_log_data(TOOL.canonical(changed), submission, "c" * 64)
        with self.assertRaises(module.Refused):
            module.notary_log_data(b'{"logFormatVersion":1,"logFormatVersion":1}', submission, "c" * 64)

        for reason in ("unconfigured", "p12-inherited", "runtime-binding", "disk-reserve"):
            with self.subTest(notary_admission=reason), tempfile.TemporaryDirectory() as temporary:
                state = self.notary_fixture(Path(temporary)); operation = state.operation
                if reason == "unconfigured":
                    (operation.checkout / module.NOTARY_PROFILE).write_bytes(b'{"schemaVersion":1,"mode":"unconfigured"}\n')
                elif reason == "p12-inherited":
                    operation.environment[module.CREDENTIAL_VARIABLES[0]] = "INERT secret must not leak"
                elif reason == "runtime-binding":
                    operation.environment["MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"] = "e" * 64
                with self.notary_fixture_call(state):
                    with contextlib.ExitStack() as stack:
                        if reason == "disk-reserve":
                            stack.enter_context(mock.patch.object(module.os, "fstatvfs", return_value=SimpleNamespace(f_frsize=4096, f_bavail=1)))
                        with self.assertRaises(module.Refused): operation.execute()
                self.assertEqual(state.observations, [])
                self.assertFalse(operation.receipt["passed"] or (operation.work / "input").exists())
                self.assertFalse((operation.work / operation.target_name).exists())
                self.assertFalse(operation.receipt["notaryAuthentication"]["created"])

        # The public Installer nomination never stands in for a private key,
        # system trust, timestamp, notarization or the current final package.
        certificates = tuple(("INERT INSTALLER CERTIFICATE " + name).encode() for name in ("leaf", "issuer", "root"))
        selection = {"schemaVersion": 1, "mode": "developer-id-installer", "teamId": "TEST000001",
            "identityCommonName": "Developer ID Installer: INERT DATA (TEST000001)",
            "leafSha1": module.hashlib.sha1(certificates[0]).hexdigest(),
            **{key: module.digest(value) for key, value in zip(("leafSha256", "issuerSha256", "rootSha256"), certificates)}}
        self.assertIsNone(module.installer_profile(b'{"schemaVersion":1,"mode":"unconfigured"}\n'))
        self.assertEqual(module.installer_profile(TOOL.canonical(selection)), selection)
        for key, value in (("schemaVersion", True), ("mode", "developer-id-application"), ("teamId", "test000001"),
                ("leafSha1", "0" * 40), ("leafSha256", selection["issuerSha256"]), ("rootSha256", "F" * 64),
                ("identityCommonName", "Developer ID Application: INERT DATA (TEST000001)"),
                ("identityCommonName", "Developer ID Installer: INERT DATA (OTHER00001)"),
                ("identityCommonName", "Developer ID Installer: BAD\nDATA (TEST000001)"),
                ("identityCommonName", "Developer ID Installer: " + "x" * 256 + " (TEST000001)")):
            with self.subTest(installerSelection=key), self.assertRaises(module.Refused):
                module.installer_profile(TOOL.canonical(dict(selection, **{key: value})))
        for value in (b'{"schemaVersion":1,"schemaVersion":1,"mode":"unconfigured"}',
                      TOOL.canonical(dict(selection, extra=True)), b'\xff', b'x' * 1025):
            with self.assertRaises(module.Refused):
                module.installer_profile(value)
        identities = ('  1) ' + selection["leafSha1"].upper() + ' "' + selection["identityCommonName"]
                      + '"\n     1 valid identities found\n').encode()
        pem = b''.join(b"-----BEGIN CERTIFICATE-----\n" + module.base64.b64encode(value)
                       + b"\n-----END CERTIFICATE-----\n" for value in certificates)
        module.installer_identity(identities, pem, selection, certificates)
        for identity_body, certificate_body in ((identities + identities, pem),
                (identities.replace(selection["leafSha1"].upper().encode(), b"0" * 40), pem),
                (identities.replace(b"Developer ID Installer", b"Developer ID Application"), pem),
                (identities, pem + pem), (identities, pem.replace(module.base64.b64encode(certificates[1]), module.base64.b64encode(b"FOREIGN")))):
            with self.assertRaises(module.Refused):
                module.installer_identity(identity_body, certificate_body, selection, certificates)
        signature = ('Package "MobileReleaseKit.pkg":\n   Status: signed by a certificate trusted by macOS\n'
                     '   Signed with a trusted timestamp on: INERT DATA\n   Certificate Chain:\n')
        for index, certificate in enumerate(certificates, 1):
            name = selection["identityCommonName"] if index == 1 else "INERT CHAIN " + str(index)
            sha256 = ' '.join(module.digest(certificate)[i:i + 2].upper() for i in range(0, 64, 2))
            signature += str(index) + '. ' + name + '\n    SHA256 Fingerprint:\n        ' + sha256 + '\n'
        signature = signature.encode()
        path = Path('/DATA-only/MobileReleaseKit.pkg')
        self.assertEqual(module.package_signature_data(signature, selection, certificates, path),
                         {"trusted": True, "timestamp": True, "certificateSha256": [module.digest(value) for value in certificates]})
        self.assertEqual(module.package_signature_data(signature.replace(b'trusted by macOS', b'trusted by Mac OS X'), selection, certificates, path)["trusted"], True)
        for body in (signature.replace(b'trusted by macOS', b'untrusted by macOS'),
                     signature.replace(b'Signed with a trusted timestamp on:', b'Signed without a trusted timestamp on:'),
                     signature.replace(b'1. Developer ID Installer:', b'2. Developer ID Installer:'),
                     signature.replace(selection["identityCommonName"].encode(), b'Developer ID Installer: FOREIGN (TEST000001)'),
                     signature.replace(b'SHA256 Fingerprint:', b'SHA1 Fingerprint:', 1),
                     signature + b'4. FOREIGN\n', signature.replace(b'INERT DATA\n', b'INERT\x00DATA\n', 1), b'x' * 65537):
            with self.assertRaises(module.Refused):
                module.package_signature_data(body, selection, certificates, path)

        # Only these three fixed archive purposes are accepted. The default ZIP
        # parser behavior remains unchanged; null arch is NONAUTHORITY metadata
        # for the exact selected PKG/DMG root, never a nested/null-field bypass.
        submission = {"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "status": "Accepted"}
        for archive in (module.NOTARY_ZIP_NAME, "MobileReleaseKit.pkg", "MobileReleaseKit.dmg"):
            body = TOOL.canonical(dict(submission, name=archive))
            self.assertEqual(module.notary_submit_data(body, archive_name=archive), submission)
            self.assertEqual(module.notary_submit_data(TOOL.canonical(submission), archive_name=archive), submission)
            with self.assertRaises(module.Refused):
                module.notary_submit_data(TOOL.canonical(dict(submission, name="wrong.pkg")), archive_name=archive)
            row = {"path": archive, "digestAlgorithm": "SHA-1", "cdhash": "c" * 40,
                   "arch": None if archive in ("MobileReleaseKit.pkg", "MobileReleaseKit.dmg") else "arm64"}
            log = {"logFormatVersion": 1, "jobId": submission["id"], "status": "Accepted", "archiveFilename": archive,
                   "sha256": "d" * 64, "issues": None, "ticketContents": [row]}
            facts = module.notary_log_data(TOOL.canonical(log), submission, "d" * 64, archive_name=archive)
            self.assertEqual((facts["sha256Compared"], facts["ticketRowCount"], facts["errorCount"]), (True, 1, 0))
            for changed in (dict(row, arch=True), dict(row, arch="null"), dict(row, digestAlgorithm="MD5"),
                            dict(row, cdhash="c" * 64), dict(row, extra="unobserved"),
                            dict(row, path=archive + "/nested", arch=None)):
                with self.assertRaises(module.Refused):
                    module.notary_log_data(TOOL.canonical(dict(log, ticketContents=[changed])), submission, "d" * 64, archive_name=archive)
            if archive == module.NOTARY_ZIP_NAME:
                self.assertEqual(module.notary_submit_data(body), submission)
                self.assertEqual(module.notary_log_data(TOOL.canonical(log), submission, "d" * 64), facts)
                with self.assertRaises(module.Refused):
                    module.notary_log_data(TOOL.canonical(dict(log, ticketContents=[dict(row, arch=None)])), submission, "d" * 64)
        with self.assertRaises(module.Refused):
            module.notary_submit_data(TOOL.canonical(dict(submission, name="MobileReleaseKit.pkg")))
        for archive in ("OtherRelease.dmg", "../MobileReleaseKit.pkg", "MobileReleaseKit.pkg ", None):
            with self.assertRaises(module.Refused): module.notary_submit_data(TOOL.canonical(submission), archive_name=archive)
            with self.assertRaises(module.Refused): module.notary_log_data(b'{}', submission, "d" * 64, archive_name=archive)

        self.assertEqual(module.FINAL_IMAGE_PHASES, ("finalize-image",))
        for target in TOOL.MAC_TARGETS:
            self.assertEqual(module.entrypoint(["inert", "finalize-image", "--target", target]), ("finalize-image", target))
        for argv in (["inert", "finalize-image", "--target", "x86_64h-apple-darwin"],
                     ["inert", "finalize-image", "--path", "/other.dmg"], ["inert", "finalize-image-fallback"]):
            with self.assertRaises(module.Refused): module.entrypoint(argv)
        for failed_input in ("original-status", "installer-status", "final-P-status", "owner-source", "owner-credentials",
                             "unconfigured", "wrong-ref", "p12-present"):
            with self.subTest(finalImageAdmission=failed_input), tempfile.TemporaryDirectory() as directory:
                state = self.final_image_fixture(Path(directory)); operation = state.operation
                if failed_input in ("original-status", "installer-status", "final-P-status"):
                    name = {"original-status": "package-install.status", "installer-status": "installer-output.status",
                            "final-P-status": "package-finalization.status"}[failed_input]
                    (state.work / name).write_bytes(b"1\n")
                elif failed_input in ("owner-source", "owner-credentials"):
                    owner = copy.deepcopy(state.package_owner)
                    if failed_input == "owner-source": owner["source"] = "b" * 40
                    else: owner["credentialOriginals"][3]["settled"] = False
                    (state.work / "android-helper-package-install.json").write_bytes(TOOL.canonical(owner))
                elif failed_input == "unconfigured":
                    (state.checkout / module.PRODUCER_PROFILE).write_bytes(b"schema=1\nstate=unconfigured\n")
                    (state.checkout / module.PROFILE).write_bytes(module.UNCONFIGURED_PROFILE)
                elif failed_input == "wrong-ref": operation.environment["GITHUB_REF"] = "refs/heads/verify/desktop-macos-installed"
                else: operation.environment[module.CREDENTIAL_VARIABLES[0]] = "INERT must not be inherited"
                with self.final_image_fixture_call(state), self.assertRaises(module.Refused): operation.execute()
                self.assertEqual(state.observations, [])
                self.assertFalse(operation.receipt["passed"] or (state.work / "distribution-final").exists())
                self.assertFalse(operation.receipt["notaryAuthentication"]["created"])
                self.assertEqual((state.work / "distribution/MobileReleaseKit.dmg").read_bytes(), state.original_image)




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
        for target, machine, runner, toolchain in (("aarch64-apple-darwin", "arm64", "ARM64", "1.98.1"),
                                                    ("x86_64-apple-darwin", "x86_64", "X64", "1.98.0")):
            ordinary = dict(environment, GITHUB_REF=ordinary_ref, RUNNER_ARCH=runner, RUSTUP_TOOLCHAIN=toolchain,
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
                for wrong in ("1.98.0" if toolchain == "1.98.1" else "1.98.1", "nightly", None, True):
                    with self.subTest(target=target, toolchain=wrong), self.assertRaisesRegex(module.Refused, "^hosted-source-bindings$"):
                        module.admit(dict(ordinary, RUSTUP_TOOLCHAIN=wrong), target=target)
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
                aqua = dict(environment, RUNNER_ARCH=runner, RUSTUP_TOOLCHAIN=toolchain)
                self.assertEqual(module.admit(aqua, target=target), work)
                for phase in module.PHASES:
                    self.assertEqual(module.admit(aqua, target=target, phase=phase), work)
                for scope in module.PACKAGE_SCOPES:
                    self.assertEqual(module.admit(dict(aqua, MRK_MACOS_AQUA_SCOPE=scope), target=target), work)
                for key, value, reason in (
                    ("RUSTUP_TOOLCHAIN", "1.98.0" if toolchain == "1.98.1" else "1.98.1", "hosted-source-bindings"),
                    ("RUNNER_ARCH", "X64" if runner == "ARM64" else "ARM64", "hosted-source-bindings"),
                    ("GITHUB_WORKFLOW_SHA", "b" * 40, "hosted-source-bindings"),
                    ("GITHUB_REF", "refs/heads/main", "closed-workflow-route"),
                    ("GITHUB_WORKFLOW_REF", ordinary["GITHUB_WORKFLOW_REF"], "hosted-source-bindings"),
                    ("MRK_MACOS_PACKAGE_ROLE", "ordinary-image", "hosted-source-bindings"),
                    ("MRK_MACOS_AQUA_SCOPE", "android-registration-lifecycle", "full-package-scope-only"),
                    ("MRK_MACOS_WORK", str(ordinary_work), "owned-work-route")):
                    with self.subTest(target=target, key=key), self.assertRaisesRegex(module.Refused, "^" + reason + "$"):
                        module.admit(dict(aqua, **{key: value}), target=target)
                uname.return_value = SimpleNamespace(machine="x86_64" if machine == "arm64" else "arm64")
                with self.assertRaisesRegex(module.Refused, "^hosted-native-platform$"):
                    module.admit(aqua, target=target)


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
            final_name = "Sign and notarize the completed scripts-only Installer package before final P"
            finalized = workflow_step(workflow, final_name)
            self.assertIn("id: android_helper", build)
            prepare_target = ' --target "$MRK_MACOS_TARGET"'
            self.assertIn('macos_android_helper_package.py prepare' + prepare_target + ' >> "$GITHUB_OUTPUT"', build)
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
            self.assertIn("--package-role " + role, app)
            self.assertIn('--expected-resident-image "$MRK_MACOS_RESIDENT_IMAGE_SHA256"', app)
            self.assertIn('--expected-android-helper "$MRK_MACOS_ANDROID_HELPER_SHA256"', app)
            for step in (app, inputs):
                self.assertIn("MRK_MACOS_RESIDENT_IMAGE_SHA256: $" + "{{ steps.android_helper.outputs['resident-image-sha256'] }}", step)
                self.assertIn("MRK_MACOS_ANDROID_HELPER_SHA256: ${{ steps.android_helper.outputs.sha256 }}", step)
            self.assertIn('--android-helper "$MRK_MACOS_WORK/mrk-android-register"', app)
            self.assertLess(app.index("stage_macos_installed.py app"), app.index("macos_android_helper_package.py verify-before"))
            self.assertLess(app.index("macos_android_helper_package.py verify-before"), app.index("macos_android_helper_package.py sign-desktop-payload"))
            self.assertLess(app.index("macos_android_helper_package.py sign-desktop-payload"), app.index("macos_android_helper_package.py verify-after"))
            self.assertIn("MRK_MACOS_ENTRY_SHA256: ${{ steps.android_helper.outputs['entry-sha256'] }}", app)
            self.assertIn('--entry-binary "$MRK_MACOS_WORK/mrk-macos-entry" --expected-entry "$MRK_MACOS_ENTRY_SHA256"', app)
            # The existing binding step now has one fixed notarization caller;
            # its stdout remains the exact final S1 inventory DATA contract.
            key = ANDROID_HELPER.NOTARY_KEY_VARIABLE
            self.assertIn("        timeout-minutes: 32\n", inputs)
            self.assertIn("RUNNER_ENVIRONMENT: ${{ runner.environment }}", inputs)
            self.assertIn(key + ": ${{ secrets." + key + " }}", inputs)
            run = inputs.split("        run: |\n", 1)[1]
            barrier = "          set +x\n          set +a\n          export -n " + key + "\n          set -euo pipefail\n"
            self.assertTrue(run.startswith(barrier))
            call = ('"$MRK_PYTHON" -I -S -B desktop/tools/macos_android_helper_package.py notarize-payload '
                    '--target "$MRK_MACOS_TARGET" > "$MRK_MACOS_WORK/input-result.json"')
            self.assertEqual(run.count(call), 1)
            self.assertIn(key + '="$' + key + '" \\\n            ' + call, run)
            self.assertNotIn("stage_macos_installed.py input", run)
            self.assertLess(run.index("export -n " + key), run.index(call))
            self.assertLess(run.index(call), run.index("unset " + key))
            self.assertLess(run.index("unset " + key), run.index('inventory=$("$MRK_PYTHON"'))
            self.assertIn('json.loads(data)["inventorySha256"]', run)
            self.assertIn("before.st_size > 2048", run)
            self.assertIn("MRK_MACOS_INSTALL_INVENTORY_SHA256=%s", run)
            self.assertEqual(workflow.count("/android-helper-notarize-payload.json"), 1)
            for notary_role in ANDROID_HELPER.NOTARY_ROLES:
                for suffix in ("stdout", "stderr", "status"):
                    self.assertNotIn("/android-helper-" + notary_role + "." + suffix, workflow)
            self.assertNotIn("MobileReleaseKit-notary-payload.zip", workflow)
            self.assertNotIn("AuthKey_", workflow)
            self.assertNotIn("--keychain-profile", inputs)
            self.assertNotIn("store-credentials", inputs)
            # A separate Installer purpose receives only its two P12 inputs
            # and the P8 key. It runs after the complete Scripts XAR, never
            # on an intermediate before Scripts or after the final P boundary.
            installer_names = ANDROID_HELPER.INSTALLER_CREDENTIAL_VARIABLES
            final_secrets = installer_names + (key,)
            self.assertIn("        timeout-minutes: 32\n", finalized)
            self.assertIn("RUNNER_ENVIRONMENT: ${{ runner.environment }}", finalized)
            final_run = finalized.split("        run: |\n", 1)[1]
            self.assertTrue(final_run.startswith("          set +x\n          set +a\n          export -n "
                + " ".join(final_secrets) + "\n          set -euo pipefail\n"))
            final_call = ('"$MRK_PYTHON" -I -S -B desktop/tools/macos_android_helper_package.py finalize-package '
                          '--target "$MRK_MACOS_TARGET"')
            self.assertEqual(final_run.count(final_call), 1)
            assignment = ' \\\n          '.join(name + '="$' + name + '"' for name in final_secrets)
            self.assertIn(assignment + ' \\\n            ' + final_call, final_run)
            positions = [final_run.index(value) for value in ('export -n ', final_call,
                'finalization_status=$?', 'printf \'%s\\n\' "$finalization_status"', 'finalization_status_saved=$?',
                'unset ' + ' '.join(final_secrets), 'if [[ "$finalization_status" != 0 ]]; then exit "$finalization_status"; fi',
                '[[ "$finalization_status_saved" == 0 ]] || exit "$finalization_status_saved"')]
            self.assertEqual(positions, sorted(positions))
            for secret in final_secrets:
                self.assertEqual(finalized.count(secret + ": ${{ secrets." + secret + " }}"), 1)
                self.assertNotIn("export " + secret, final_run)
                self.assertNotIn('echo "' + secret, final_run)
            for forbidden in ("cargo", "sudo", "MRK_MACOS_DEVELOPER_ID_", "--sign -", "--timestamp=none",
                              "--keychain-profile", "store-credentials"):
                self.assertNotIn(forbidden, finalized)
            for artifact in ("/android-helper-finalize-package.json", "/package-finalization.status"):
                self.assertEqual(workflow.count(artifact), 1 if artifact.endswith(".json") else 2)
            exports = workflow_evidence_paths(workflow)
            if filename == "desktop-macos-installed.yml":
                for old, bad in (("${{ format('{0}/source-binding.json", "${{ format('{1}/source-binding.json"),
                                 ("', steps.work.outputs.root) }}", "', steps.work.outputs.root, github.workspace) }}"),
                                 ("{0}/source-binding.json", "{0}/*"),
                                 ("{0}/source-binding.json", "{0}/../source-binding.json")):
                    self.assertEqual(workflow.count(old), 1)
                    with self.assertRaises(AssertionError):
                        workflow_evidence_paths(workflow.replace(old, bad, 1))
            self.assertIn("${{ steps.work.outputs.root }}/android-helper-finalize-package.json\n", exports)
            self.assertIn("${{ steps.work.outputs.root }}/package-finalization.status\n", exports)
            # Final P is an intentional public artifact; admit this one exact
            # row, never a duplicate, another path or the private signed copy.
            public_package = "${{ steps.work.outputs.root }}/package-final/MobileReleaseKit.pkg"
            export_lines = exports.splitlines()
            self.assertEqual([line.strip() for line in export_lines if "MobileReleaseKit.pkg" in line],
                             [public_package])
            private_exports = "\n".join(line for line in export_lines if line.strip() != public_package)
            for forbidden in ("package-finalization.stdout", "package-finalization.stderr", "signed-package", "AuthKey_",
                              "MobileReleaseKit.pkg", "identity.keychain"):
                self.assertNotIn(forbidden, private_exports)
            for command_role in ANDROID_HELPER.FINAL_PACKAGE_ROLES:
                for suffix in ("stdout", "stderr", "status"):
                    self.assertNotIn("/android-helper-" + command_role + "." + suffix, workflow)
            script_build = workflow_step(workflow, "Build the fixed one-shot root Installer and scripts-only package")
            self.assertIn('/usr/bin/xar -c -f "$MRK_MACOS_WORK/package-unsigned/MobileReleaseKit.pkg"', script_build)
            self.assertNotIn("/package-final/", script_build)
            self.assertLess(workflow.index("      - name: Build the fixed one-shot root Installer and scripts-only package\n"),
                            workflow.index("      - name: " + final_name + "\n"))
            sequence = [app.index(value) for value in (
                'macos_android_helper_package.py sign-desktop-payload', 'payload_sha=$(',
                'macos_android_helper_package.py sign-root-app',
                'macos_android_helper_package.py verify-after', 'entry_sha=$(')]
            self.assertEqual(sequence, sorted(sequence))
            self.assertNotIn("android-helper-*", workflow)
            self.assertIn('--resident-image "$MRK_MACOS_WORK/libmrk_resident_image.dylib"', app)
            if filename == "desktop-macos-installed.yml":
                self.assertIn('--expected-app-binary "$MRK_MACOS_DESKTOP_FACADE_SHA256"', app)
                self.assertLess(app.index('macos_android_helper_package.py sign-desktop-image'), app.index('macos_android_helper_package.py sign-desktop-payload'))
                self.assertEqual(app.count('/usr/bin/codesign --verify --strict "$desktop_image"'), 2)
                self.assertIn("MRK_MACOS_SIGNED_DESKTOP_IMAGE_SHA256", app)
            if filename == "desktop-macos-aqua.yml":
                self.assertIn('--expected-app-binary "$MRK_MACOS_OBSERVER_SHA256"', app)
                self.assertIn('--observer-cargo-messages "$MRK_MACOS_WORK/observer-build.jsonl"', app)
                self.assertIn('--observer-cargo-target-dir "$CARGO_TARGET_DIR"', app)
                self.assertNotIn("--desktop-image", app + inputs)
                gates = lambda block: [line.strip() for line in block.splitlines() if line.startswith("        if:")]
                self.assertEqual(gates(build), gates(app))
                self.assertEqual(gates(build), gates(inputs))
                self.assertEqual(gates(build), gates(finalized))
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
            self.assertLess(workflow.index("      - name: " + final_name + "\n"),
                            workflow.index("      - name: " + install_name + "\n"))
            self.assertNotIn("--sign -", app)
            self.assertNotIn("--timestamp=none", app)
            if filename == "desktop-macos-aqua.yml":
                self.assertEqual(gates(preflight), gates(build))
                self.assertEqual(gates(installed), gates(build))

            # Secrets exist only on the five fixed signing-role steps. Disable
            # shell tracing/allexport and unexport BOTH before any child; pass
            # them inline only to the exact same-owner helper, never to Cargo.
            credential_names = ANDROID_HELPER.CREDENTIAL_VARIABLES
            names = ("Build and sign the fixed resident image and C facades",
                     "Build and sign the separate fixed vault helper before binding the app", assembly,
                     "Build the fixed one-shot root Installer and scripts-only package", install_name)
            actual_steps = dict(block.split("\n", 1) for block in workflow.split("      - name: ")[1:])
            self.assertEqual({name for name, body in actual_steps.items() if "secrets.MRK_MACOS_DEVELOPER_ID_" in body}, set(names))
            self.assertEqual({name for name, body in actual_steps.items() if "secrets.MRK_MACOS_NOTARY_API_KEY_BASE64" in body},
                             {binding, final_name} | ({"Notarize, staple and verify only the final user image"}
                                                      if filename == "desktop-macos-installed.yml" else set()))
            self.assertEqual({name for name, body in actual_steps.items() if "secrets.MRK_MACOS_INSTALLER_P12_" in body}, {final_name})
            for name in names:
                block = workflow_step(workflow, name)
                run = block.split("        run: |\n", 1)[1]
                self.assertTrue(run.startswith("          set +x\n          set +a\n          export -n " + " ".join(credential_names) + "\n          set -euo pipefail\n"))
                self.assertTrue(run.rstrip().endswith("unset " + " ".join(credential_names)))
                lines = run.splitlines()
                for index, line in enumerate(lines):
                    if 'MRK_MACOS_DEVELOPER_ID_P12_BASE64="$MRK_MACOS_DEVELOPER_ID_P12_BASE64"' in line:
                        self.assertEqual(lines[index + 1].strip(), 'MRK_MACOS_DEVELOPER_ID_P12_PASSWORD="$MRK_MACOS_DEVELOPER_ID_P12_PASSWORD" \\')
                        self.assertIn("macos_android_helper_package.py ", lines[index + 2])
                        self.assertNotIn(" env ", line + lines[index + 1])
                helper_lines = [line for line in lines if "macos_android_helper_package.py " in line
                                and not any(phase in line for phase in ("verify-before", "verify-after"))]
                assignments = [line for line in lines if 'MRK_MACOS_DEVELOPER_ID_P12_BASE64="$MRK_MACOS_DEVELOPER_ID_P12_BASE64"' in line]
                self.assertEqual(len(helper_lines), len(assignments))
                for key in credential_names:
                    self.assertEqual(block.count(key + ": ${{ secrets." + key + " }}"), 1)
                    self.assertNotIn('echo "' + key, run)
                    self.assertNotIn("export " + key, run)
            phases = tuple(phase for phase in ANDROID_HELPER.SIGNING_PHASES
                           if filename == "desktop-macos-installed.yml" or phase != "sign-desktop-image")
            signing_target = '"$MRK_MACOS_TARGET"'
            for phase in phases:
                self.assertEqual(workflow.count("/android-helper-" + phase + ".json"), 1)
                self.assertEqual(workflow.count("macos_android_helper_package.py " + phase + " --target " + signing_target), 1)
            if filename == "desktop-macos-installed.yml":
                self.assertEqual(workflow.count("    environment: macos-developer-id\n"), 1)
            else:
                fixed = json.dumps(list(ANDROID_HELPER.PACKAGE_SCOPES), separators=(",", ":"))
                self.assertIn("    environment: ${{ contains(fromJSON('" + fixed + "'), matrix.scope) && 'macos-developer-id' || 'macos-engineering' }}\n", workflow)


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

        header = signing.split("    steps:\n", 1)[0]
        self.assertIn("environment: ${{ github.ref == 'refs/heads/verify/desktop-macos-python-runtime-signing-shipping' && 'macos-developer-id' || 'macos-engineering' }}", header)
        run = owner.split("        run: |\n", 1)[1]
        self.assertTrue(run.startswith("          set +x\n          set +a\n          export -n " + " ".join(ANDROID_HELPER.CREDENTIAL_VARIABLES) + "\n          set -euo pipefail\n"))
        for key in ANDROID_HELPER.CREDENTIAL_VARIABLES:
            self.assertIn(key + ": ${{ github.ref == 'refs/heads/verify/desktop-macos-python-runtime-signing-shipping' && secrets." + key + " || '' }}", owner)
        self.assertIn("ulimit -n 1024", owner)
        self.assertNotIn("ulimit -n 4096", owner)
        self.assertNotIn("actions/import-codesign-certs", signing)

        # SOURCE-to-caller mapping stays explicit even though the fixed helper
        # replaces the old open-ended input CLI spelling. Real tiny filesystem
        # cases above run this same Namespace and both actual S1 calls.
        helper_tree = ast.parse((root / "desktop/tools/macos_android_helper_package.py").read_text())
        operation = next(node for node in helper_tree.body if isinstance(node, ast.ClassDef) and node.name == "Operation")
        phase = next(node for node in operation.body if isinstance(node, ast.FunctionDef) and node.name == "notarize_payload")
        assignments = [node for node in ast.walk(phase) if isinstance(node, ast.Assign)
                       and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "arguments"]
        self.assertEqual(len(assignments), 1)
        argument_call = assignments[0].value
        self.assertEqual(ast.dump(argument_call.func), ast.dump(ast.parse("argparse.Namespace", mode="eval").body))
        expected_arguments = {
            "target": "self.target", "package_role": 'self.environment["MRK_MACOS_PACKAGE_ROLE"]', "current_runtime": "True",
            "expected_entry": 'self.environment.get("MRK_MACOS_SIGNED_ENTRY_SHA256")',
            "expected_app_binary": 'self.environment.get("MRK_MACOS_SIGNED_PAYLOAD_SHA256")',
            "expected_vault_helper": 'self.environment.get("MRK_MACOS_VAULT_HELPER_SHA256")',
            "expected_android_helper": 'self.environment.get("MRK_MACOS_ANDROID_HELPER_SHA256")',
            "expected_resident_image": 'self.environment.get("MRK_MACOS_RESIDENT_IMAGE_SHA256")',
            "expected_desktop_image": 'self.environment.get("MRK_MACOS_SIGNED_DESKTOP_IMAGE_SHA256") if self.environment["MRK_MACOS_PACKAGE_ROLE"] == "ordinary-image" else None',
            "expected_manifest": 'selected["runtimeManifestSha256"]', "app": "app_path", "runtime": 'self.work / "runtime"',
            "output": 'self.work / self.target_name / "payload-input"'}
        self.assertEqual(argument_call.args, [])
        self.assertEqual({row.arg: ast.dump(row.value) for row in argument_call.keywords},
                         {name: ast.dump(ast.parse(value, mode="eval").body) for name, value in expected_arguments.items()})
        self.assertEqual(json.loads((root / ANDROID_HELPER.NOTARY_PROFILE).read_bytes()), {"schemaVersion": 1, "mode": "unconfigured"})
        self.assertEqual(json.loads((root / ANDROID_HELPER.INSTALLER_PROFILE).read_bytes()), {"schemaVersion": 1, "mode": "unconfigured"})
        methods = {node.name: ast.get_source_segment((root / "desktop/tools/macos_android_helper_package.py").read_text(), node)
                   for node in operation.body if isinstance(node, ast.FunctionDef)}
        images = methods["package_image"]
        self.assertLess(images.index('self.package_call(label + "-create"'), images.index('with self.credential_scope(label + "-image")'))
        self.assertLess(images.index('with self.credential_scope(label + "-image")'), images.index('self.package_call(label + "-sign"'))
        self.assertLess(images.index('self.package_call(label + "-verify-signature"'), images.index('self.package_call(label + "-verify-image"'))
        self.assertIn('"package-image-credential-required"', methods["call"])

        installed = (root / ".github/workflows/desktop-macos-installed.yml").read_text()
        aqua = (root / ".github/workflows/desktop-macos-aqua.yml").read_text()
        phase_name = "Notarize, staple and verify only the final user image"
        phase = workflow_step(installed, phase_name)
        self.assertNotIn(phase_name, aqua)
        self.assertIn("if: github.ref == 'refs/heads/verify/desktop-macos-preview'", phase)
        self.assertIn("timeout-minutes: 32", phase)
        key = ANDROID_HELPER.NOTARY_KEY_VARIABLE
        self.assertIn(key + ": ${{ secrets." + key + " }}", phase)
        run = phase.split("        run: |\n", 1)[1]
        self.assertTrue(run.startswith("          set +x\n          set +a\n          export -n " + key + "\n          set -euo pipefail\n"))
        call = '"$MRK_PYTHON" -I -S -B desktop/tools/macos_android_helper_package.py finalize-image --target "$MRK_MACOS_TARGET"'
        self.assertEqual(run.count(call), 1)
        self.assertIn(key + '=\"$' + key + '\" \\\n            ' + call, run)
        positions = [run.index(value) for value in ('export -n ', call, 'image_status=$?',
            'printf \'%s\\n\' "$image_status"', 'image_status_saved=$?', 'unset ' + key,
            'if [[ "$image_status" != 0 ]]; then exit "$image_status"; fi', '[[ "$image_status_saved" == 0 ]] || exit "$image_status_saved"')]
        self.assertEqual(positions, sorted(positions))
        for forbidden in ("cargo", "sudo", "P12", "--sign", "--keychain-profile", "store-credentials", "force", "-kernel"):
            self.assertNotIn(forbidden, phase)
        self.assertLess(installed.index("macos_android_helper_package.py package-install"), installed.index(call))
        self.assertLess(installed.index(call), installed.index("stage_macos_installed.py preview"))
        for role in ANDROID_HELPER.FINAL_IMAGE_ROLES:
            for suffix in ("stdout", "stderr", "status"):
                self.assertEqual(installed.count("/android-helper-" + role + "." + suffix), 1)
        self.assertEqual(installed.count("/android-helper-finalize-image.json"), 1)
        self.assertEqual(installed.count("/image-finalization.status"), 2)
        # Phase-specific dispatch and SAME clock aliases preserve the old
        # package mount implementation rather than a second cleanup owner.
        final = methods["finalize_image"]
        for token in ('self.package_name = "Install.pkg"', 'self.mount_inputs(expected, self.package_name)',
                      'self.mounted_post()', 'self.detach_package_mount()', 'self.final_image_publish()'):
            self.assertIn(token, final)
        self.assertEqual([final.index(value) for value in ('"final-image-staple"', '"final-image-validate"',
            '"final-image-signature-after"', '"final-image-verify"', '"final-image-attach"',
            'self.mount_inputs(', 'self.detach_package_mount()', 'self.final_image_publish()')],
            sorted(final.index(value) for value in ('"final-image-staple"', '"final-image-validate"',
            '"final-image-signature-after"', '"final-image-verify"', '"final-image-attach"',
            'self.mount_inputs(', 'self.detach_package_mount()', 'self.final_image_publish()')))
        self.assertIn('return self.notary_clock()[0]', methods["package_clock"])
        self.assertIn('return self.final_image_call("final-image-detach", argv)', methods["package_call"])
        self.assertIn('after[:6] == before[:6]', methods["final_image_mutated"])
        self.assertIn('abs(after[6] - before[6]) <= 1024 * 1024', methods["final_image_mutated"])
        self.assertNotIn('final_package_stapled', final)





def odc(name, mode, body=b"", *, uid=0, gid=0, links=1):
    encoded = name.encode("ascii") + b"\0"
    header = b"070707" + ("%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o" %
        (0, 1, mode, uid, gid, links, 0, 0, len(encoded), len(body))).encode("ascii")
    return header + encoded + body


def package_data(*, uid=0, gid=0, root=".", file_owner=None, fixture=False, selection=None):
    # Small inert parser input, not a native tar/xar or Installer observation.
    selection = TOOL.selected_build(selection)
    identifier = TOOL.PACKAGE_ID + ("-fixture" if fixture else "")
    files = {"input/readonly.txt": (b"DATA\n", 0o444), "postinstall": (b"exit 97\n", 0o555)}
    info = (f'<?xml version="1.0"?>\n<pkg-info identifier="{identifier}" '
            f'version="{selection.package_version}" install-location="/" auth="root"><payload numberOfFiles="0"/>'
            '<scripts><postinstall file="./postinstall"/></scripts></pkg-info>\n').encode("ascii")
    archive = odc(root, stat.S_IFDIR | 0o755, uid=uid, gid=gid)
    archive += odc("./input", stat.S_IFDIR | 0o555, uid=uid, gid=gid)
    for name, (body, mode) in files.items():
        owner = file_owner if file_owner is not None and name == "postinstall" else (uid, gid)
        archive += odc("./" + name, stat.S_IFREG | mode, body, uid=owner[0], gid=owner[1])
    return files, {"PackageInfo": info, "Scripts": archive + odc("TRAILER!!!", 0)}


def reservation_result_data(*, entered=True, created=True):
    # Synthetic parser DATA only, never an original native lock/close fact.
    return {"schemaVersion": 1, "entered": entered,
            "creation": ("created" if created else "existing-not-modified") if entered else "not-attempted",
            "fixedBytes": 38, "writtenBytes": 38 if entered and created else 0,
            "sealed": entered and created, "filePersisted": entered and created, "parentPersisted": entered and created,
            "writer": "closed" if entered and created else "not-attempted", "verified": entered,
            "exclusiveAttempted": entered and not created, "exclusiveAcquired": entered and not created,
            "participant": "closed" if entered else "not-attempted", "closedUnderMaintenance": entered,
            "verifiedAfterGo": False, "cleanup": "original-closes-only-permanent-reservation-retained"}


def original_result(expected, *, stage=".install-" + "d" * 32, selection=None):
    selection = TOOL.selected_build(selection)
    reason, runtime, app, state, verified, _exit = expected
    recorded = state == "installed" or (runtime == "confirmed" and app == "occupied-refused")
    partial = reason == "open-refused" and runtime == "confirmed"
    metadata = {"state": "recorded" if recorded else "incomplete" if partial else "not-attempted",
                "attemptedFiles": 2 if recorded or partial else 0, "openedFiles": 2 if recorded else 1 if partial else 0,
                "plannedBytes": 10 if recorded or partial else 0, "writtenBytes": 10 if recorded else 6 if partial else 0,
                "writersSettled": True}
    return {"schemaVersion": 1, "state": state, "reason": reason, "release": selection.release,
            "runtimePublication": runtime, "appPublication": app, "staging": stage, "payloadVerified": verified,
            "payloadWritersSettled": True, "originalsSettled": True, "deadlineMetAfterFinalCloses": True, "createdAncestors": [],
            "cleanup": "original-closes-only-no-deletion", "sourceCommit": "a" * 40, "inventorySha256": "b" * 64, "runtimeManifestSha256": "c" * 64, "installationMetadata": metadata,
            "registrationReservation": reservation_result_data(entered=stage is not None),
            "maintenanceGate": {"schemaVersion": 1, "entered": stage is not None,
                "creation": "created" if stage else "not-attempted", "fixedBytes": 30, "writtenBytes": 30 if stage else 0,
                "sealed": stage is not None, "filePersisted": stage is not None, "parentPersisted": stage is not None,
                "writer": "closed" if stage else "not-attempted", "verified": stage is not None,
                "exclusiveAttempted": stage is not None, "exclusiveAcquired": stage is not None,
                "participant": "closed" if stage else "not-attempted", "cleanup": "original-closes-only-permanent-gate-retained"}}


def reported_fixture_data(*, selection=None):
    # Inert serialized DATA, never a native observation or root test runner.
    selection = TOOL.selected_build(selection)
    rows = []
    for name, expected in TOOL.FIXTURE_CASES.items():
        stage = None if name in ("occupied-app", "occupied-release") else ".install-" + "d" * 32
        point = {"prepublication-persistence-report": "payload-file-before-any-publication",
                 "postruntime-persistence-report": "stage-directory-after-runtime-rename"}.get(name)
        identity = {"device": 1, "inode": 42, "mode": 0o444, "uid": 0, "gid": 0, "links": 1, "size": len(TOOL.FIXTURE_MARKER),
                    "mtimeSeconds": 1, "mtimeNanoseconds": 0, "ctimeSeconds": 1, "ctimeNanoseconds": 0}
        witness = {"visibleRelativePath": TOOL.visible_occupant(name, selection=selection), "sha256": TOOL.digest(TOOL.FIXTURE_MARKER),
                   "before": dict(identity), "after": dict(identity), "verifiedByOriginalInstaller": True}
        persistence = {"point": point, "actualNativeSucceeded": True, "actualNativeErrno": None, "injectedReportedFailure": True}
        rows.append({"case": name, "passed": True, "proofError": None, "originalResult": original_result(expected, stage=stage, selection=selection), "originalExit": expected[-1],
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
              "historicalOuterExit": "unverified",
              "registrationReservation": reservation_result_data(created=actions[-1] == "fresh-install")}
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

        # Signing metadata and a container ticket do not change the exact
        # root-owned Scripts payload. Exercise the REAL bounded XAR/CPIO audit;
        # these literal signatures are DATA, not cryptographic/native proof.
        # Preserve real SOURCE release reads; only the nominated package is DATA.
        source_read = TOOL.read
        for target in TOOL.MAC_TARGETS:
            selection = TOOL.source_build_selection(target)
            files, original_members = package_data(uid=501, gid=20, selection=selection)
            root_members = package_data(selection=selection)[1]
            signed_xar = MacAndroidHelperPackagingData.final_package_xar(self, root_members, signed=True)
            args = SimpleNamespace(target=target, scripts=Path("/scripts"), package=Path("/final.pkg"),
                original_package=Path("/original.pkg"), fixture=False)
            with mock.patch.object(TOOL, "original_package", return_value=(files, b"original", original_members, TOOL.PACKAGE_ID, (501, 20))):
                for body in (signed_xar, signed_xar + b"INERT APPENDED TICKET DATA ONLY\0t8lr"):
                    self.assertEqual(TOOL.xar_members(body), root_members)
                    with (self.subTest(signedContainerTarget=target, bytes=len(body)),
                          mock.patch.object(TOOL, "read", side_effect=lambda path, *limits, **keywords:
                              body if path == args.package else source_read(path, *limits, **keywords))):
                        audited = TOOL.audit_command(args)
                    self.assertEqual((audited["packageSize"], audited["packageSha256"]), (len(body), TOOL.digest(body)))
                    self.assertEqual(audited["finalDestinationPayloadEntries"], 0)
                for changed in (original_members, dict(root_members, Payload=b"FORBIDDEN"),
                        dict(root_members, PackageInfo=root_members["PackageInfo"] + b"\n"),
                        dict(root_members, Scripts=root_members["Scripts"].replace(b"DATA\n", b"DIFF\n"))):
                    body = MacAndroidHelperPackagingData.final_package_xar(self, changed, signed=True) + b"INERT TICKET"
                    with (mock.patch.object(TOOL, "read", side_effect=lambda path, *limits, **keywords:
                              body if path == args.package else source_read(path, *limits, **keywords)),
                          self.assertRaises(TOOL.Refused)):
                        TOOL.audit_command(args)

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

        # Both package kinds keep the original packager/root archive distinction.
        # The selected tuple is a fixed command input, never learned from the XML.
        for target in TOOL.MAC_TARGETS:
            prefix = "macos26-arm64-" if target == TOOL.ARM_TARGET else "macos26-x86_64-"
            selection = TOOL.BuildSelection(target, "2.3.4", prefix + "fixture-data-01")
            for fixture in (False, True):
                files, original_members = package_data(uid=501, gid=20, fixture=fixture, selection=selection)
                final_members = package_data(fixture=fixture, selection=selection)[1]
                args = SimpleNamespace(target=target, scripts=Path("/scripts"), package=Path("/final.pkg"),
                    original_package=Path("/original.pkg"), output=Path("/fresh-parts"), fixture=fixture)
                prepared_args = SimpleNamespace(**{**vars(args), "package": args.original_package})
                settled = []
                @contextlib.contextmanager
                def original_parent(path):
                    self.assertEqual(path, Path("/original.pkg"))
                    try:
                        yield 91, "original.pkg"
                    finally:
                        settled.append(path)
                with (self.subTest(target=target, fixture=fixture),
                      mock.patch.object(TOOL, "source_build_selection", return_value=selection) as selected,
                      mock.patch.object(TOOL, "packager_ids", return_value=(501, 20)),
                      mock.patch.object(TOOL, "tree", return_value=files),
                      mock.patch.object(TOOL, "parent", side_effect=original_parent),
                      mock.patch.object(TOOL, "read_at", return_value=(b"original", SimpleNamespace(st_uid=501, st_gid=20))) as original_read,
                      mock.patch.object(TOOL, "read", return_value=b"final"),
                      mock.patch.object(TOOL, "xar_members", side_effect=lambda body: original_members if body == b"original" else final_members),
                      mock.patch.object(TOOL, "original_package", wraps=TOOL.original_package) as original,
                      mock.patch.object(TOOL, "package_info", wraps=TOOL.package_info) as info,
                      mock.patch.object(TOOL, "write_tree") as writer):
                    prepared = TOOL.prepare_package_command(prepared_args)
                    writer.assert_called_once_with(args.output, {"PackageInfo": (original_members["PackageInfo"], 0o444)}, root_mode=0o700)
                    audited = TOOL.audit_command(args)
                    self.assertEqual(selected.call_args_list, [mock.call(target), mock.call(target)])
                    self.assertEqual(len(original.call_args_list), 2)
                    self.assertEqual(len(info.call_args_list), 3)
                    self.assertTrue(all(call.kwargs["selection"] is selection for call in original.call_args_list + info.call_args_list))
                    self.assertEqual(settled, [args.original_package, args.original_package])
                    self.assertEqual(prepared["packageInfoSha256"], TOOL.digest(original_members["PackageInfo"]))
                    self.assertEqual(audited["originalPackageSha256"], TOOL.digest(b"original"))
                    self.assertEqual(audited["packageIdentifier"], TOOL.PACKAGE_ID + ("-fixture" if fixture else ""))
                    self.assertEqual(audited["finalDestinationPayloadEntries"], 0)
                    writer.reset_mock()
                    original_read.return_value = (b"original", SimpleNamespace(st_uid=0, st_gid=0))
                    with self.assertRaises(TOOL.Refused):
                        TOOL.prepare_package_command(prepared_args)
                    writer.assert_not_called()
                    self.assertEqual(len(settled), 3)  # The original parent also settles on refusal.

            # Installer bytes are parsed for the selected CPU before any output.
            inventory = b"synthetic source inventory hash anchor"
            input_files = {"install-inventory.json": (inventory, 0o444)}
            args = SimpleNamespace(target=target, input=Path("/input"), installer=Path("/installer"),
                output=Path("/scripts"), expected_source="a" * 40, expected_inventory=TOOL.digest(inventory), fixture=True)
            bodies = {args.installer: entry_macho_fixture(target=target),
                      TOOL.DESKTOP / "macos-installed-inputs/postinstall": b"#!/bin/sh\nexit 97\n"}
            with (mock.patch.object(TOOL, "source_build_selection", return_value=selection) as selected,
                  mock.patch.object(TOOL, "tree", return_value=input_files),
                  mock.patch.object(TOOL, "read", side_effect=lambda path, *_: bodies[path]),
                  mock.patch.object(TOOL, "write_tree") as writer):
                result = TOOL.scripts_command(args)
                selected.assert_called_once_with(target)
                scripts = writer.call_args.args[1]
                self.assertEqual(scripts["mrk-macos-install"], (bodies[args.installer], 0o555))
                self.assertEqual(scripts["postinstall"], (bodies[TOOL.DESKTOP / "macos-installed-inputs/postinstall"], 0o555))
                self.assertEqual(writer.call_args.kwargs, {"root_mode": 0o755})
                self.assertEqual(result["packageIdentifier"], TOOL.PACKAGE_ID + "-fixture")
                writer.reset_mock()
                opposite = TOOL.INTEL_TARGET if target == TOOL.ARM_TARGET else TOOL.ARM_TARGET
                bodies[args.installer] = entry_macho_fixture(target=opposite)
                with self.assertRaises(TOOL.Refused):
                    TOOL.scripts_command(args)
                writer.assert_not_called()
                args.target = "unknown-apple-darwin"
                with self.assertRaises(TOOL.Refused):
                    TOOL.scripts_command(args)
                writer.assert_not_called()

    def test_package_workflow_fails_fast_and_gates_every_installer(self):
        # I intentionally has no Aqua workflow: that separately-based source
        # delta is independently composed/reviewed, not fictitiously exercised.
        path = Path(__file__).absolute().parents[2] / ".github/workflows/desktop-macos-installed.yml"
        workflow = path.read_text(encoding="utf-8")
        probe = workflow.index("- name: Fail fast on native Scripts ownership and package format")
        sdk = workflow.index("- name: Fail fast on the selected SDK actual no-ACL and ACE-refusal primitive")
        self.assertLess(probe, sdk)
        self.assertLess(sdk, workflow.index('"/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/cargo" build --locked --release'))
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
            destination = label + ("-unsigned" if label == "package" else "-final")
            self.assertIn('/bin/mkdir -m 700 "$MRK_MACOS_WORK/' + destination + '"', block)
            self.assertIn('cd "$MRK_MACOS_WORK/' + label + '-parts" || exit', block)
            final = '$MRK_MACOS_WORK/' + destination + '/' + basename + '.pkg'
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
                final_name = "Sign and notarize the completed scripts-only Installer package before final P"
                finalized = workflow_step(workflow, final_name)
                final_call = 'macos_android_helper_package.py finalize-package --target "$MRK_MACOS_TARGET"'
                self.assertEqual(finalized.count(final_call), 1)
                self.assertLess(start, workflow.index("      - name: " + final_name + "\n"))
                self.assertLess(workflow.index(final_call), audit)
                self.assertIn("        timeout-minutes: 32\n", finalized)
                self.assertIn('if [[ "$finalization_status" != 0 ]]; then exit "$finalization_status"; fi', finalized)
                self.assertIn('[[ "$finalization_status_saved" == 0 ]] || exit 1', finalized)
                self.assertLess(package.index('finalization = self.package_finalization_input(original, body)'),
                                package.index('audit = self.package_stager_io("final-audit",'))
                self.assertLess(package.index('audit = self.package_stager_io("final-audit",'),
                                package.index('descriptor = self.stager.packaging_descriptor_data('))
                self.assertIn('package=digest(body)', package)
                self.assertIn('"final-package-original", self.stager.MAX_BYTES, (0o444,)', package)
                self.assertIn('status_body = self.read(status)\n'
                              '        need(status_body == b"0\\n", "package-finalization-original-status")',
                              methods["package_finalization_input"])
                self.assertIn('final_package_receipt(', methods["package_finalization_input"])
                self.assertIn('source-installer-profile', methods["installer_sources"])
                self.assertLess(methods["finalize_package"].index('self.final_package_publish()'),
                                methods["finalize_package"].index('self.receipt["finalPackage"]'))
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
        self.assertLess(workflow.index(marker), workflow.index("      - name: Build the ordinary selected-target desktop image and embedded frontend"))
        self.assertIn('-arch "$MRK_MACOS_MACHINE"', gate)
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
            exports = workflow_evidence_paths(workflow)
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
                    self.assertIn('${{ steps.work.outputs.root }}/' + filename + '\n', exports)
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
                self.assertIn('${{ steps.work.outputs.root }}/' + filename + '\n', exports)
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
        call_node = next(node for node in operation.body if isinstance(node, ast.FunctionDef) and node.name == "call")
        dispatch = next(node for node in call_node.body if isinstance(node, ast.Try))
        self.assertEqual(len(dispatch.body), 3)
        expected_entries = ast.parse('''if self.phase == "package-install":
    if role == "distribution-attach":
        self.mount_entered = True
    elif role == "installer":
        self.installer_entered = True
if self.phase in FINAL_IMAGE_PHASES and role == "final-image-attach":
    self.mount_entered = True
''').body
        self.assertEqual([ast.dump(node, include_attributes=False) for node in dispatch.body[:2]],
                         [ast.dump(node, include_attributes=False) for node in expected_entries])
        self.assertIsInstance(dispatch.body[2], ast.Assign)
        self.assertIsInstance(dispatch.body[2].value, ast.Call)
        self.assertEqual(ast.dump(dispatch.body[2].value.func, include_attributes=False),
                         ast.dump(ast.parse("self.owner.run_owned", mode="eval").body, include_attributes=False))
        self.assertEqual(original.count('result = self.owner.run_owned('), 1)
        self.assertEqual(original.count('self.mount_entered = True'), 2)
        self.assertEqual(original.count('self.installer_entered = True'), 1)
        package_entry = ast.get_source_segment(helper, dispatch.body[0])
        for role, field in (("distribution-attach", "mount_entered"), ("installer", "installer_entered")):
            entered = 'self.' + field + ' = True'
            self.assertNotIn(entered, package)
            self.assertEqual(package_entry.count(entered), 1)
            self.assertLess(package_entry.index('role == "' + role + '"'), package_entry.index(entered))
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

        # An existing source-approved generation is not silently repaired: only
        # genuine fresh/update parent routes may report creation, never no-op/restore.
        for action in ("fresh-install", "update", "same-package-noop", "restore-fixed-app"):
            actions = (action,) if action == "fresh-install" else ("fresh-install", action)
            _producer, _records, valid = maintenance_documents(actions)
            for created in (False, True):
                changed = {**valid, "registrationReservation": reservation_result_data(created=created)}
                if not created or action in ("fresh-install", "update"):
                    self.assertEqual(TOOL.maintenance_result_data(TOOL.canonical(changed) + b"\n", changed["requestId"]), changed)
                else:
                    with self.assertRaisesRegex(TOOL.Refused, "registration-reservation-not-predecessor-creation"):
                        TOOL.maintenance_result_data(TOOL.canonical(changed) + b"\n", changed["requestId"])
            state, parsed = TOOL.maintenance_history_data(valid, _records, _producer)
            names, _stages = TOOL.maintenance_roster_data(state, parsed, TOOL.ARM_TARGET)
            self.assertIn(TOOL.REGISTRATION_GATE_NAME, names)
            self.assertIn(TOOL.MAINTENANCE_GATE_NAME, names)
            self.assertNotIn("registration-reservation-v2", names)
        for key, value in (("participant", "owned"), ("participant", "unknown"), ("closedUnderMaintenance", False),
                           ("verifiedAfterGo", True), ("exclusiveAcquired", False)):
            changed = {**valid, "registrationReservation": {**reservation_result_data(created=False), key: value}}
            with self.subTest(parent_reservation=key), self.assertRaises(TOOL.Refused):
                TOOL.maintenance_result_data(TOOL.canonical(changed) + b"\n", changed["requestId"])


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

        # R and M must be separate real original ledgers. Existing R_EX is
        # acquired BEFORE M_EX, consumed only while actual M_EX is held, and
        # workers authenticate R only AFTER their actual parent GO+EOF.
        reservation = source.split("fn registration_before_maintenance(", 1)[1].split("fn registration_complete_admitted(", 1)[0]
        self.assertIn("!self.registration.entered && !self.gate.entered", reservation)
        self.assertIn("fcntl::FlockArg::LockExclusiveNonblock", reservation)
        self.assertLess(reservation.index("self.registration_open(destination)?"), reservation.index("fcntl::flock"))
        self.assertLess(reservation.index("self.registration.exclusive_acquired = true"), reservation.index("self.clock()?; self.registration_protected"))
        self.assertNotIn("create_file", reservation)
        complete = source.split("fn registration_complete_admitted(", 1)[1].split("fn registration_after_go(", 1)[0]
        ordered = ("self.gate.verified && self.gate.lock_attempted && self.gate.exclusive_acquired",
                   "self.gate_protected(maintenance)?", "matches!(action, ActionData::FreshInstall | ActionData::Update)",
                   "self.create_file(destination, paths::REGISTRATION_GATE_NAME, Role::ReservationWriter)",
                   "self.write_all(writer, paths::REGISTRATION_GATE_BYTES)", "self.seal_file(writer, false)",
                   "self.persist(destination, false)", "self.registration_open(destination)", "self.close(reader)",
                   "self.registration.closed_under_maintenance = true", "self.registration_ready()")
        self.assertEqual([complete.index(token) for token in ordered], sorted(complete.index(token) for token in ordered))
        self.assertNotIn("self.gate.participant =", complete)
        self.assertNotIn("LockShared", complete)
        worker = source.split("fn registration_after_go(", 1)[1].split("fn registration_ready(", 1)[0]
        self.assertIn("self.worker_go_eof && self.worker_deadline.is_some()", worker)
        self.assertIn("!self.gate.lock_attempted", worker)
        self.assertIn("self.registration_open(destination)?", worker)
        self.assertNotIn("flock", worker)
        self.assertLess(source.index("book.worker_go_eof = true; // Actual complete GO and EOF"),
                        source.index("book.registration_after_go(destination)?"))
        self.assertLess(admission.index("self.registration_before_maintenance(destination)?"), admission.index("self.maintenance_gate(destination)?"))
        self.assertLess(admission.index("maintenance::fresh_registration_roster(self, destination, versions)?"),
                        admission.index("self.registration_complete_admitted(destination, ActionData::FreshInstall)?"))
        selected = source.split("self.book.registration_complete_admitted(observed.prepared.destination, observed.action)?", 1)[0]
        self.assertLess(selected.rindex("maintenance::observe("), selected.rindex("observed.incoming_controls("))
        self.assertIn("selected.predecessor_data().contains(generation.release_data())", source)
        ready = source.split("fn registration_ready(", 1)[1].split("fn gate_protected(", 1)[0]
        for token in ("State::Closed", "self.originals[reader].fd.is_none()", "Identity::of(&named) == self.identity(reader)?", "named.st_flags == 0"):
            self.assertIn(token, ready)
        self.assertIn('"registrationReservation":self.registration_record()', source)
        self.assertIn('"registrationReservation":self.book.registration_record()', source)
        self.assertIn("Role::ReservationWriter", source)
        self.assertIn("Role::ReservationParticipant", source)
        self.assertIn("checked_add(4)", admission)
        self.assertIn("root_cost.files.checked_add(2)", source)
        self.assertIn("paths::REGISTRATION_GATE_BYTES.len()", source)
        # Current application readback is the same bounded Book, not a lock
        # claim, new root, payload count, or silent old-layout fallback.
        observer = (Path(__file__).absolute().parents[2] / "desktop/src-tauri/src/installation_observation_macos.rs").read_text(encoding="utf-8")
        inspect = observer.split("    fn inspect(", 1)[1].split("    pub(crate) fn run(", 1)[0]
        self.assertLess(inspect.index("self.read_record(install, paths::MAINTENANCE_GATE_NAME"),
                        inspect.index("self.read_record(install, paths::REGISTRATION_GATE_NAME"))
        self.assertLess(inspect.index("self.read_record(install, paths::REGISTRATION_GATE_NAME"), inspect.index("self.installed_selection("))
        self.assertIn("paths::MAINTENANCE_GATE_NAME, paths::REGISTRATION_GATE_NAME],", inspect)
        self.assertIn("paths::MAINTENANCE_GATE_NAME.to_owned(),paths::REGISTRATION_GATE_NAME.to_owned(),", observer)
        self.assertIn("const RECORDS: usize = 8256;", observer)
        self.assertNotIn("flock", inspect)
        reader = observer.split("    fn read_record(", 1)[1].split("    fn control_present(", 1)[0]
        self.assertLess(reader.index("self.held_record("), reader.index("self.close(index, end, stop, publish)?"))


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

        for target in TOOL.MAC_TARGETS:
            prefix = "macos26-arm64-" if target == TOOL.ARM_TARGET else "macos26-x86_64-"
            selection = TOOL.BuildSelection(target, "2.3.4", prefix + "fixture-data-01")
            for fixture in (False, True):
                body = package_data(fixture=fixture, selection=selection)[1]["PackageInfo"]
                with self.subTest(target=target, fixture=fixture):
                    self.assertEqual(TOOL.package_info(body, fixture=fixture, selection=selection),
                                     TOOL.PACKAGE_ID + ("-fixture" if fixture else ""))
                    for changed in (body.replace(b'2.3.4', b'2.3.5'),
                                    body.replace(b'numberOfFiles="0"', b'numberOfFiles="1"'),
                                    body.replace(b'</scripts>', b'<preinstall file="other"/></scripts>')):
                        with self.assertRaises(TOOL.Refused):
                            TOOL.package_info(changed, fixture=fixture, selection=selection)
                    with self.assertRaises(TOOL.Refused):
                        TOOL.package_info(body, fixture=not fixture, selection=selection)
                    with self.assertRaises(TOOL.Refused):
                        TOOL.package_info(body, fixture=fixture, selection=selection._replace(package_version="2.3.5"))
                    with self.assertRaises(TOOL.Refused):
                        TOOL.package_info(body, fixture=fixture, selection=selection._replace(target="unknown-apple-darwin"))
                    with self.assertRaises(TOOL.Refused):
                        TOOL.package_info(body, fixture=fixture, selection=selection._replace(release="macos26-foreign-fixture"))

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

        # R has its own closed creation/existing ledger, and no worker-read-only
        # observation or lost close may stand in for the parent's actual overlap.
        reservation = result["registrationReservation"]
        for key, value in (("schemaVersion", True), ("entered", False), ("fixedBytes", True), ("fixedBytes", 37),
                           ("writtenBytes", True), ("writtenBytes", 37), ("sealed", False), ("filePersisted", False),
                           ("parentPersisted", False), ("writer", "owned"), ("verified", False),
                           ("exclusiveAttempted", True), ("exclusiveAcquired", True), ("participant", "unknown"),
                           ("participant", "kernel-exit-retained"), ("closedUnderMaintenance", False),
                           ("closedUnderMaintenance", 1), ("verifiedAfterGo", True), ("cleanup", "deleted"), ("extra", True)):
            with self.subTest(reservation=key, value=value), self.assertRaises(TOOL.Refused):
                TOOL.bound_original_result({**result, "registrationReservation": {**reservation, key: value}}, expected,
                                           "a" * 40, "b" * 64, "c" * 64)
        for key in reservation:
            missing = dict(reservation); del missing[key]
            with self.subTest(missing_reservation=key), self.assertRaises(TOOL.Refused):
                TOOL.registration_reservation_result(missing, entered=True)
        missing = dict(result); del missing["registrationReservation"]
        with self.assertRaises(TOOL.Refused):
            TOOL.bound_original_result(missing, expected, "a" * 40, "b" * 64, "c" * 64)
        reused_r = reservation_result_data(created=False)
        TOOL.bound_original_result({**result, "registrationReservation": reused_r}, expected, "a" * 40, "b" * 64, "c" * 64)
        for key, value in (("writtenBytes", 38), ("sealed", True), ("filePersisted", True), ("parentPersisted", True),
                           ("writer", "closed"), ("exclusiveAttempted", False), ("exclusiveAcquired", False)):
            with self.subTest(reused_reservation=key), self.assertRaises(TOOL.Refused):
                TOOL.registration_reservation_result({**reused_r, key: value}, entered=True)
        empty_r = reservation_result_data(entered=False)
        TOOL.registration_reservation_result(empty_r, entered=False)
        for key in ("entered", "sealed", "filePersisted", "parentPersisted", "verified", "exclusiveAttempted",
                    "exclusiveAcquired", "closedUnderMaintenance", "verifiedAfterGo"):
            with self.subTest(unentered_reservation=key), self.assertRaises(TOOL.Refused):
                TOOL.registration_reservation_result({**empty_r, key: True}, entered=False)
        # Small genuine parser boundary cases charge the new file/38B without
        # allocating a large fixture or changing the real production caps.
        record, inventory_body, root_data, release_data = installation_record_fixture()
        rows = json.loads(inventory_body)["files"]
        for extra, passed in ((4, True), (3, False)):
            with mock.patch.object(TOOL, "MAX_FILES", len(rows) + extra):
                if passed:
                    self.assertEqual(len(TOOL.observation_inventory_bytes(inventory_body, TOOL.digest(inventory_body), "c" * 64)), len(rows))
                else:
                    with self.assertRaisesRegex(TOOL.Refused, "observation-inventory-shape"):
                        TOOL.observation_inventory_bytes(inventory_body, TOOL.digest(inventory_body), "c" * 64)
        total = sum(row["size"] for row in rows) + len(inventory_body) + TOOL.INSTALLATION_RECORD_LIMIT + 30 + 38
        for maximum, passed in ((total, True), (total - 1, False)):
            with mock.patch.object(TOOL, "MAX_BYTES", maximum):
                arguments = (TOOL.canonical(record), inventory_body, "a" * 40, "c" * 64, root_data, release_data, record["instance"])
                if passed:
                    self.assertEqual(TOOL.installation_record_data(*arguments), record)
                else:
                    with self.assertRaisesRegex(TOOL.Refused, "installation-record-total-bound"):
                        TOOL.installation_record_data(*arguments)


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

        for target in TOOL.MAC_TARGETS:
            prefix = "macos26-arm64-" if target == TOOL.ARM_TARGET else "macos26-x86_64-"
            selection = TOOL.BuildSelection(target, "2.3.4", prefix + "fixture-data-01")
            good = reported_fixture_data(selection=selection)
            # Independent literal expectations: the fixture builder does not get
            # to make an ARM fallback self-consistent with the parser under test.
            visible = {"occupied-app": TOOL.APP_NAME + "/occupied.txt",
                "occupied-release": "versions/" + selection.release + "/runtime/occupied.txt",
                "runtime-publication-collision": "versions/" + selection.release + "/runtime/occupied.txt",
                "first-publication-second-refusal": TOOL.APP_NAME + "/occupied.txt",
                "metadata-descriptor-collision": "versions/" + selection.release + "/installation-v1.json"}
            for row in good["cases"]:
                self.assertEqual(row["originalResult"]["release"], selection.release)
                self.assertEqual(TOOL.visible_occupant(row["case"], selection=selection), visible.get(row["case"]))
                if row["occupant"] is not None:
                    self.assertEqual(row["occupant"]["visibleRelativePath"], visible.get(row["case"]))
            self.assertIs(TOOL.bound_fixture_result(good, "a" * 40, "b" * 64, "c" * 64, selection=selection), good)
            self.assertEqual(TOOL.fixture_record(marker + TOOL.canonical(good), "a" * 40, "b" * 64, "c" * 64, selection=selection), good)
            opposite = TOOL.INTEL_TARGET if target == TOOL.ARM_TARGET else TOOL.ARM_TARGET
            other_prefix = "macos26-arm64-" if opposite == TOOL.ARM_TARGET else "macos26-x86_64-"
            other = TOOL.BuildSelection(opposite, selection.package_version, other_prefix + "fixture-data-01")
            with self.assertRaises(TOOL.Refused):
                TOOL.bound_fixture_result(good, "a" * 40, "b" * 64, "c" * 64, selection=other)
            paired_mutations = mutations + [(("schemaVersion",), 2),
                (("cases", 1, "occupant", "visibleRelativePath"), "versions/" + other.release + "/runtime/occupied.txt")]
            paired_mutations += [(("cases", index, "originalResult", "release"), other.release) for index in range(8)]
            paired_mutations += [(("cases", index, "originalResult", "originalsSettled"), False) for index in range(8)]
            for path, value in paired_mutations:
                changed = copy.deepcopy(good)
                cursor = changed
                for key in path[:-1]:
                    cursor = cursor[key]
                cursor[path[-1]] = value
                with self.subTest(target=target, path=path), self.assertRaises(TOOL.Refused):
                    TOOL.bound_fixture_result(changed, "a" * 40, "b" * 64, "c" * 64, selection=selection)

            # Real adapter/control flow with IO boundaries scoped to inert DATA.
            # Nothing opens a fixture stage or confers an actual Installer return.
            args = result_args(fixture=True)
            args.target = target
            base = TOOL.INSTALL_ROOT.parent / good["fixtureBase"]
            expected = {"runtime/data": {"size": 1, "sha256": TOOL.digest(b"X"), "executable": False}}
            exported = {"state": "synthetic-original-export-DATA"}
            events, visited, close_failure = [], [], [False]
            @contextlib.contextmanager
            def fixture_directory(path, names):
                events.append(("enter", path))
                visited.append((path, set(names)))
                try:
                    yield 91
                finally:
                    events.append(("close", path))
                    if close_failure[0] and path == base:
                        raise TOOL.Refused("synthetic-fixture-parent-close")
            def original_readback(_args, *, fixture):
                self.assertIs(_args, args)
                self.assertIs(fixture, True)
                events.append(("original-readback", None))
                return good, exported
            with (mock.patch.object(TOOL, "source_build_selection", return_value=selection) as selected,
                  mock.patch.object(TOOL, "observation_inventory", return_value=expected) as inventory_read,
                  mock.patch.object(TOOL, "installer_result_readback", side_effect=original_readback) as result_read,
                  mock.patch.object(TOOL, "bound_fixture_result", wraps=TOOL.bound_fixture_result) as bound,
                  mock.patch.object(TOOL, "fixture_directory", side_effect=fixture_directory),
                  mock.patch.object(TOOL.os, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0)) as stage_stat,
                  mock.patch.object(TOOL, "observe_occupant") as occupant_read,
                  mock.patch.object(TOOL, "tree", return_value={"data": (b"X", 0o444)}) as runtime_read,
                  mock.patch.object(TOOL, "maintenance_gate_readback", return_value={"state": "synthetic-gate-DATA"}),
                  mock.patch.object(TOOL, "registration_reservation_readback", return_value={"state": "synthetic-R-DATA"}) as reservation_read,
                  mock.patch.object(TOOL, "installation_metadata_readback", return_value={"state": "synthetic-metadata-DATA"}) as metadata_read):
                result = TOOL.fixture_observation_command(args)
                selected.assert_called_once_with(target)
                self.assertIs(inventory_read.call_args.kwargs["selection"], selection)
                self.assertIs(bound.call_args.kwargs["selection"], selection)
                self.assertEqual(events[0], ("original-readback", None))
                self.assertEqual(events[-1], ("close", base))
                self.assertEqual(len(visited), sum(event[0] == "close" for event in events))
                self.assertEqual(visited[0], (base, set(TOOL.FIXTURE_CASES)))
                self.assertEqual([path for path, _ in visited if path.name == selection.release],
                    [base / name / "versions" / selection.release for name in
                     ("occupied-release", "runtime-publication-collision", "first-publication-second-refusal",
                      "postruntime-persistence-report", "metadata-descriptor-collision")])
                self.assertTrue(all(other.release not in path.parts and not path.name.startswith(".install-") for path, _ in visited))
                self.assertEqual(stage_stat.call_count, 6)
                self.assertEqual(reservation_read.call_args_list, [mock.call(91)] * 6)
                for path, names in visited:
                    if path.parent == base:
                        self.assertEqual(TOOL.REGISTRATION_GATE_NAME in names,
                                         path.name not in ("occupied-app", "occupied-release"))
                self.assertEqual([row["registrationReservation"] for row in result["nonrootReadback"]],
                                 [None, None] + [{"state": "synthetic-R-DATA"}] * 6)
                self.assertTrue(all(call.kwargs == {"dir_fd": 91, "follow_symlinks": False} for call in stage_stat.call_args_list))
                self.assertEqual(runtime_read.call_count, 3)
                self.assertTrue(all(call.kwargs == {"installed": True} for call in runtime_read.call_args_list))
                self.assertEqual([call.args[0] for call in occupant_read.call_args_list],
                    [base / name / visible[name] for name in
                     ("occupied-app", "occupied-release", "runtime-publication-collision", "first-publication-second-refusal")])
                self.assertEqual(metadata_read.call_count, 2)
                self.assertTrue(all(call.kwargs["selection"] is selection and call.kwargs["fixture"] is True
                                    for call in metadata_read.call_args_list))
                self.assertIsNone(metadata_read.call_args_list[0].kwargs["occupant"])
                self.assertIs(metadata_read.call_args_list[1].kwargs["occupant"], good["cases"][7]["occupant"])
                self.assertEqual(result["schemaVersion"], 1)
                self.assertIs(result["originalFixtureResult"], good)
                self.assertIs(result["installerResultExport"], exported)
                self.assertEqual([row["case"] for row in result["nonrootReadback"]], list(TOOL.FIXTURE_CASES))
                self.assertTrue(all(row["protectedStagingOpened"] is False for row in result["nonrootReadback"]))
                self.assertFalse(result["applicationLaunched"] or result["guiSaveQualified"] or result["genuineConcurrentRaceObserved"])
                close_failure[0] = True
                with self.assertRaisesRegex(TOOL.Refused, "synthetic-fixture-parent-close"):
                    TOOL.fixture_observation_command(args)
                close_failure[0] = False
                events.clear()
                result_read.side_effect = TOOL.Refused("synthetic-original-not-returned-zero")
                with self.assertRaisesRegex(TOOL.Refused, "synthetic-original-not-returned-zero"):
                    TOOL.fixture_observation_command(args)
                self.assertEqual(events, [])  # Original refusal precedes every installed directory read.


def installation_record_fixture(*, fixture=False, selection=None):
    # Closed DATA only, not a root-owned installation or original receipt.
    selection = TOOL.selected_build(selection)
    names = ["app/" + TOOL.VAULT_HELPER, "app/Contents/Info.plist", "app/" + TOOL.PAYLOAD_INFO,
             "app/" + TOOL.ENTRY_BINARY, "app/" + TOOL.APP_BINARY, "runtime/manifest.json", "runtime/python/bin/python3"]
    rows = [{"path": name, "size": 1, "sha256": ("c" if name == "runtime/manifest.json" else "b") * 64,
             "executable": name in ("app/" + TOOL.ENTRY_BINARY, "app/" + TOOL.VAULT_HELPER, "app/" + TOOL.APP_BINARY, "runtime/python/bin/python3")}
            for name in sorted(names)]
    inventory = TOOL.canonical({"schemaVersion": 1, "release": selection.release,
                                "runtimeManifestSha256": "c" * 64, "files": rows})
    identity = {"device": 1, "inode": 9007199254740993, "mode": stat.S_IFDIR | 0o755, "uid": 0, "gid": 0, "flags": 0}
    release = {**identity, "inode": identity["inode"] + 1}
    record = {"schemaVersion": 1, "basis": "protected-recorded-installation-inventory", "phase": "inventory-recorded",
              "kind": "fixture" if fixture else "ordinary", "instance": "d" * 32,
              "packageIdentifier": TOOL.PACKAGE_ID + ("-fixture" if fixture else ""),
              "packageVersion": selection.package_version, "bundleIdentifier": TOOL.BUNDLE_ID, "release": selection.release,
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

        for target in TOOL.MAC_TARGETS:
            prefix = "macos26-arm64-" if target == TOOL.ARM_TARGET else "macos26-x86_64-"
            selection = TOOL.BuildSelection(target, "2.3.4", prefix + "fixture-data-01")
            for fixture in (False, True):
                record, inventory, root, release = installation_record_fixture(fixture=fixture, selection=selection)
                body = TOOL.canonical(record)
                def selected_record(value, *, expected_protocol=TOOL.CURRENT_PROTOCOL):
                    return TOOL.installation_record_data(value, inventory, "a" * 40, "c" * 64, root, release, "d" * 32,
                        fixture=fixture, selection=selection, expected_protocol=expected_protocol)
                with self.subTest(target=target, fixture=fixture):
                    self.assertEqual(selected_record(body), record)
                    for changed in (dict(record, release=TOOL.RELEASE), dict(record, packageVersion="2.3.5"),
                                    dict(record, kind="ordinary" if fixture else "fixture"),
                                    dict(record, packageIdentifier=TOOL.PACKAGE_ID + ("" if fixture else "-fixture")),
                                    dict(record, protocolSha256="f" * 64)):
                        with self.assertRaises(TOOL.Refused):
                            selected_record(TOOL.canonical(changed))
                    if fixture:
                        with self.assertRaises(TOOL.Refused):
                            selected_record(TOOL.canonical(dict(record, protocolSha256="f" * 64)), expected_protocol="f" * 64)
                    opposite = TOOL.INTEL_TARGET if target == TOOL.ARM_TARGET else TOOL.ARM_TARGET
                    other_prefix = "macos26-arm64-" if opposite == TOOL.ARM_TARGET else "macos26-x86_64-"
                    other = TOOL.BuildSelection(opposite, selection.package_version, other_prefix + "fixture-data-01")
                    with self.assertRaises(TOOL.Refused):
                        TOOL.installation_record_data(body, inventory, "a" * 40, "c" * 64, root, release, "d" * 32,
                                                      fixture=fixture, selection=other)

                args = result_args(fixture=fixture)
                args.target, args.expected_inventory = target, TOOL.digest(inventory)
                original = original_result(TOOL.FIXTURE_CASES["first-publication-second-refusal"], selection=selection)
                original["installationMetadata"].update(plannedBytes=len(inventory) + len(body), writtenBytes=len(inventory) + len(body))
                closed, fail_close, descriptor = [], [False], [body, None]
                installed_root = Path("/synthetic-installed-root")
                @contextlib.contextmanager
                def selected_directory(path, names, *, selection):
                    self.assertEqual(path, installed_root)
                    self.assertEqual(names, {"runtime", TOOL.INSTALLATION_INVENTORY_NAME, TOOL.INSTALLATION_RECORD_NAME})
                    self.assertIs(selection, expected_selection)
                    try:
                        yield root, release, 93
                    finally:
                        closed.append(path)
                        if fail_close[0]:
                            raise TOOL.Refused("synthetic-installation-parent-close")
                expected_selection = selection
                def metadata_leaf(fd, name, limit):
                    self.assertEqual(fd, 93)
                    self.assertIn(name, (TOOL.INSTALLATION_INVENTORY_NAME, TOOL.INSTALLATION_RECORD_NAME))
                    return (inventory, None) if name == TOOL.INSTALLATION_INVENTORY_NAME else tuple(descriptor)
                with (mock.patch.object(TOOL, "read", return_value=inventory) as source_read,
                      mock.patch.object(TOOL, "installation_metadata_directory", side_effect=selected_directory),
                      mock.patch.object(TOOL, "installation_metadata_leaf", side_effect=metadata_leaf),
                      mock.patch.object(TOOL, "installation_record_data", wraps=TOOL.installation_record_data) as record_read):
                    result = TOOL.installation_metadata_readback(args, installed_root, original, fixture=fixture, selection=selection)
                    self.assertEqual(result["state"], "recorded-current-data-correspondence")
                    self.assertEqual(result["instance"], "d" * 32)
                    self.assertEqual(result["originalFinality"], "separate-Installer-status")
                    self.assertEqual(closed, [installed_root])
                    self.assertIs(record_read.call_args.kwargs["selection"], selection)
                    source_read.assert_called_once_with(args.input / TOOL.INSTALLATION_INVENTORY_NAME, 1024 * 1024)
                    fail_close[0] = True
                    with self.assertRaisesRegex(TOOL.Refused, "synthetic-installation-parent-close"):
                        TOOL.installation_metadata_readback(args, installed_root, original, fixture=fixture, selection=selection)
                    fail_close[0] = False
                    if fixture:
                        row = reported_fixture_data(selection=selection)["cases"][7]
                        partial = row["originalResult"]
                        partial["installationMetadata"]["writtenBytes"] = len(inventory)
                        info = SimpleNamespace(st_dev=1, st_ino=42, st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=0,
                            st_nlink=1, st_size=len(TOOL.FIXTURE_MARKER), st_mtime_ns=1000000000, st_ctime_ns=1000000000)
                        descriptor[:] = [TOOL.FIXTURE_MARKER, info]
                        result = TOOL.installation_metadata_readback(args, installed_root, partial, fixture=True,
                            occupant=row["occupant"], selection=selection)
                        self.assertEqual(result["state"], "partial-inventory-and-occupant-preserved")
                        info.st_ino = 43
                        with self.assertRaises(TOOL.Refused):
                            TOOL.installation_metadata_readback(args, installed_root, partial, fixture=True,
                                occupant=row["occupant"], selection=selection)
                        self.assertEqual(len(closed), 4)  # Changed witness refuses after original context settlement.

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

        # The SAME real leaf/readback functions, inert numerical FD consumers.
        # Before-open refusals must not fabricate a close; adopted originals
        # consume exactly once even on content, POST, attributes or close faults.
        raw = TOOL.REGISTRATION_GATE_BYTES
        self.assertEqual(raw, b"MRK-MACOS-REGISTRATION-RESERVATION-v1\n")
        self.assertEqual(len(raw), 38)
        for problem in ("none", "content", "short", "overflow", "size", "symlink", "links", "flags", "mode", "owner",
                        "group", "replacement", "named-replacement", "attributes", "missing", "close"):
            before = log_info(len(raw) + (1 if problem == "size" else 0),
                              st_mode=(stat.S_IFLNK if problem == "symlink" else stat.S_IFREG) | (0o644 if problem == "mode" else 0o444),
                              st_uid=501 if problem == "owner" else 0, st_gid=20 if problem == "group" else 0,
                              st_nlink=2 if problem == "links" else 1, st_flags=1 if problem == "flags" else 0)
            replaced = SimpleNamespace(**{**vars(before), "st_ino": before.st_ino + 1})
            data = b"x" * len(raw) if problem == "content" else raw[:-1] if problem == "short" else raw + b"x" if problem == "overflow" else raw
            with (mock.patch.object(TOOL.os, "stat", side_effect=FileNotFoundError() if problem == "missing" else
                                    [before, replaced if problem == "named-replacement" else before]) as named,
                  mock.patch.object(TOOL.os, "open", return_value=91) as opened,
                  mock.patch.object(TOOL.os, "fstat", side_effect=[before, replaced if problem == "replacement" else before]),
                  mock.patch.object(TOOL.os, "read", side_effect=[data, b""]),
                  mock.patch.object(TOOL, "no_xattrs", side_effect=TOOL.Refused("synthetic-attributes") if problem == "attributes" else None),
                  mock.patch.object(TOOL, "close_once", side_effect=TOOL.Refused("synthetic-close-unknown") if problem == "close" else None) as close):
                if problem == "none":
                    self.assertEqual(TOOL.registration_reservation_readback(90), {
                        "state": "protected-permanent-reservation-data-correspondence", "bytes": 38,
                        "exclusionObserved": False, "workerFinalityEstablished": False})
                else:
                    with self.subTest(reservation_read=problem), self.assertRaises((TOOL.Refused, FileNotFoundError)):
                        TOOL.registration_reservation_readback(90)
                named.assert_any_call(TOOL.REGISTRATION_GATE_NAME, dir_fd=90, follow_symlinks=False)
                if problem in ("size", "symlink", "links", "flags", "missing"):
                    opened.assert_not_called(); close.assert_not_called()
                else:
                    opened.assert_called_once_with(TOOL.REGISTRATION_GATE_NAME, TOOL.READ_FLAGS, dir_fd=90)
                    close.assert_called_once_with(91)


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
        # The shared launcher has one actual request. Its ordinary branch still
        # selects only the fixed outer app, with no engineering environment.
        request = ui.split("        func requestAndAwait() throws {", 1)[1].split("        func observeNormalTermination(", 1)[0]
        ordinary_request = request.split("            case .ordinary:\n", 1)[1].split("            case .engineeringMain(", 1)[0]
        self.assertEqual(ui.count("NSWorkspace.shared.openApplication("), 1)
        self.assertIn("NSWorkspace.shared.openApplication(at: requestURL, configuration: configuration)", request)
        self.assertEqual(ordinary_request.count("requestURL = Self.outerURL"), 1)
        self.assertNotIn("configuration.environment", ordinary_request)
        self.assertIn("init(clock: CaseClock, profile: LaunchProfile = .ordinary)", ui)
        self.assertIn("let owner = OrdinaryLaunch(clock: clock)", launch)
        self.assertIn('ProcessInfo.processInfo.environment["MRK_ENGINEERING_UI_WORK"] == nil', launch)
        self.assertLess(request.index("requested = true"), request.index("NSWorkspace.shared.openApplication("))
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

        self.assertEqual(TOOL.REGISTRATION_GATE_NAME, "registration-reservation-v1")
        self.assertEqual(TOOL.REGISTRATION_GATE_BYTES, b"MRK-MACOS-REGISTRATION-RESERVATION-v1\n")
        self.assertEqual(len(TOOL.REGISTRATION_GATE_BYTES), 38)
        self.assertIn('pub const REGISTRATION_GATE_NAME: &str = "registration-reservation-v1";', paths)
        self.assertIn('pub const REGISTRATION_GATE_BYTES: &[u8] = b"MRK-MACOS-REGISTRATION-RESERVATION-v1\\n";', paths)
        self.assertIn('#define MRK_REGISTRATION_GATE_NAME "registration-reservation-v1"', fixed)
        self.assertIn('#define MRK_REGISTRATION_GATE_BYTES "MRK-MACOS-REGISTRATION-RESERVATION-v1\\n"', fixed)




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

    def _assert_fresh_python_supplier_workflow(self, workflow, *, paired=False):
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
        target_argument = '--target "$MRK_MACOS_TARGET"' if paired else "--target aarch64-apple-darwin"
        matrix_keys = ("supplier_receipt", "supplier_tar", "supplier_source", "supplier_run", "supplier_attempt", "supplier_artifact")
        for (suffix, field, pattern), matrix_key in zip(fields, matrix_keys):
            variable = "MRK_MACOS_PYTHON_SUPPLIER_" + suffix
            if paired:
                self.assertEqual(workflow.count("      " + variable + ": ${{ matrix." + matrix_key + " }}\n"), 1)
                configured = TOOL.re.findall(r"^            " + matrix_key + ": '(" + pattern + ")'$", workflow, TOOL.re.M)
                self.assertEqual(len(configured), 2, variable)
                for value in configured:
                    self.assertIn("expected_" + matrix_key + "=" + value + "\n", admission)
                self.assertIn('"$' + variable + '" == "$expected_' + matrix_key + '"', admission)
            else:
                configured = TOOL.re.findall(r"^      " + variable + ": '(" + pattern + ")'$", workflow, TOOL.re.M)
                self.assertEqual(len(configured), 1, variable)
                self.assertIn('"$' + variable + '" == ' + configured[0], admission)
            # No pending placeholder can become a successful source-bound check.
            self.assertIn('"$' + variable + '" =~ ^' + pattern + '$', admission)
            if suffix in ("RUN_ID", "RUN_ATTEMPT", "ARTIFACT_ID"):
                for value in configured:
                    self.assertLessEqual(int(value), 9007199254740991)
                self.assertIn('"$' + variable + '" -le 9007199254740991', admission)
            self.assertIn('"' + field + '": os.environ["' + variable + '"]', workflow)
        for fragment in ('"freshPythonSupplier": {',
                         '"origin": os.environ["MRK_MACOS_RUNTIME_SUPPLIER"]',
                         '"repository": "Apdelrahman1911/mobile-release-kit"'):
            self.assertIn(fragment, workflow)
        if paired:
            for target, suffix in (("aarch64-apple-darwin", ""), ("x86_64-apple-darwin", "-intel")):
                self.assertIn('"' + target + '": (".github/workflows/desktop-macos-cpython-source-build' + suffix
                              + '.yml", "refs/heads/verify/desktop-macos-cpython-source-build' + suffix + '")', workflow)
            self.assertIn('"workflow": supplier_routes[build_target][0]', workflow)
            self.assertIn('"ref": supplier_routes[build_target][1]', workflow)
        else:
            self.assertIn('"workflow": ".github/workflows/desktop-macos-cpython-source-build.yml"', workflow)
            self.assertIn('"ref": "refs/heads/verify/desktop-macos-cpython-source-build"', workflow)
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
        self.assertEqual(workflow.count("uses: actions/download-artifact@"), 2)
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
            self.assertEqual(block.count(target_argument), 1)
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
        exports = workflow_evidence_paths(workflow)
        self.assertEqual(exports.count("${{ steps.work.outputs.root }}/fresh-python-transport-result.json\n"), 1)
        for path in ("fresh-python-transport", "fresh-python-supplier", "fresh-python-receipt"):
            self.assertNotIn("${{ steps.work.outputs.root }}/" + path + "/", exports)
        selected_name = "Select the fixed configured signed runtime before any payload download"
        capsule_download_name = "Download only the configured signed Python capsule"
        capsule_project_name = "Project the configured capsule as DATA without executing it"
        selected = workflow_step(workflow, selected_name)
        capsule_download = workflow_step(workflow, capsule_download_name)
        capsule_project = workflow_step(workflow, capsule_project_name)
        selected_at = workflow.index("      - name: " + selected_name + "\n")
        self.assertLess(workflow.index("      - name: Select DATA stager Python, not the packaged interpreter\n"), selected_at)
        self.assertLess(selected_at, workflow.index("      - name: Bind the complete reviewed first-party checkout before compilation\n"))
        self.assertLess(selected_at, workflow.index("      - name: Admit the fixed image Rust tools without installing a distribution\n"))
        for name in ("Select fixed frontend compiler", "Select fixed Node only for the native application routes"):
            if "      - name: " + name + "\n" in workflow:
                self.assertLess(selected_at, workflow.index("      - name: " + name + "\n"))
        ordered_capsule = [names[2], capsule_download_name, capsule_project_name, names[3]]
        offsets = [workflow.index("      - name: " + name + "\n") for name in ordered_capsule]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn('[[ ! -e "$MRK_MACOS_WORK/signed-python-transport" && ! -L "$MRK_MACOS_WORK/signed-python-transport" ]] || exit 1', reserve)
        for fragment in ("timeout-minutes: 1", "set -euo pipefail", "umask 077",
                         "desktop/tools/stage_macos_installed.py runtime-signing-selection " + target_argument,
                         '[[ ${#selection} -le 4096 ]] || exit 1', 'value["nativeAuthority"] is not False',
                         'value["sourceInputsSha256"] != os.environ["MRK_BUNDLED_RUNTIME_SOURCE_SHA256"]',
                         '"runtimeManifestSha256": "MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"',
                         'set(value) != set(fields) | fixed', 'os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC',
                         'os.close(fd)'):
            self.assertIn(fragment, selected)
        self.assertNotRegex(workflow, r"(?m)^      MRK_BUNDLED_RUNTIME_MANIFEST_SHA256:")
        for forbidden in ("eval ", "describe-current-runtime", "|| true", "set +e", "--binding"):
            self.assertNotIn(forbidden, selected)
        self.assertEqual([line.strip() for line in capsule_download.split("        with:\n", 1)[1].splitlines() if line.strip()], [
            "artifact-ids: ${{ env.MRK_MACOS_SIGNING_ARTIFACT_ID }}", "run-id: ${{ env.MRK_MACOS_SIGNING_RUN_ID }}",
            "repository: Apdelrahman1911/mobile-release-kit", "github-token: ${{ github.token }}",
            "path: ${{ steps.work.outputs.root }}/signed-python-transport", "merge-multiple: 'false'",
            "digest-mismatch: error", "skip-decompress: 'false'",
        ])
        self.assertIn("uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", capsule_download)
        for fragment in ("timeout-minutes: 3", "set -euo pipefail", "set -o noclobber", "umask 077",
                         "desktop/tools/stage_macos_installed.py project-signed-python", target_argument,
                         '--transport-root "$MRK_MACOS_WORK/signed-python-transport"',
                         '--output "$MRK_MACOS_WORK/signed-python-capsule"'):
            self.assertEqual(capsule_project.count(fragment), 1)
        for fragment in ("--configured-signing", '--signed-python "$MRK_MACOS_WORK/signed-python-capsule/python3"',
                         '--signing-receipt "$MRK_MACOS_WORK/signed-python-capsule/python-signed-receipt.json"',
                         '--expected-signed-python "$MRK_MACOS_SIGNED_PYTHON_SHA256"',
                         '--expected-signing-receipt "$MRK_MACOS_SIGNING_RECEIPT_SHA256"',
                         '--expected-signing-source "$MRK_MACOS_SIGNING_SOURCE_COMMIT"',
                         '--expected-signing-run "$MRK_MACOS_SIGNING_RUN_ID"',
                         '--expected-signing-attempt "$MRK_MACOS_SIGNING_RUN_ATTEMPT"'):
            self.assertEqual(runtime.count(fragment), 1)
        for fragment in ('"signedPythonDerivation": {',
                         '"signingSourceCommit": os.environ["MRK_MACOS_SIGNING_SOURCE_COMMIT"]',
                         '"nominationSha256": os.environ["MRK_MACOS_SIGNING_BINDING_SHA256"]'):
            self.assertIn(fragment, workflow)
        self.assertNotIn("codesign", capsule_project)
        self.assertNotIn("codesign", runtime)
        # The three added calls are DATA only. No suffix or artifact name can
        # authorize another body, and native signing remains a separate owner.
        for path in ("signed-python-transport", "signed-python-capsule"):
            self.assertNotIn("${{ steps.work.outputs.root }}/" + path + "/", exports)
        binding = TOOL.decode((Path(__file__).absolute().parents[2] / "desktop" / TOOL.SIGNED_RUNTIME_BINDING).read_bytes())
        self.assertEqual(set(binding), {"schemaVersion", "targets"})
        self.assertEqual(set(binding["targets"]), set(TOOL.MAC_TARGETS))
        for row in binding["targets"].values():
            if row.get("state") == "unconfigured":
                self.assertEqual(row, {"state": "unconfigured"})  # No fabricated future hash/run/M.
            else:
                self.assertEqual(row.get("state"), "configured")
        return [selected, *steps[:3], capsule_download, capsule_project, runtime]


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
        self.assertIn('"/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/cargo" test --locked --no-default-features --features desktop-shell,custom-protocol,macos-installed-observation', build)
        self.assertIn("--test installed-shell-observation --no-run --message-format=json", build)
        self.assertIn('--target "$MRK_MACOS_TARGET" --test installed-shell-observation', build)
        self.assertIn('os.environ["MRK_MACOS_TARGET"] / "debug/deps"', build)
        for name, command in (("Assemble the instrumented observation app with SOURCE-selected signing", "app"),
                              ("Bind this signed app and current-source runtime into fresh Installer DATA", "input"),
                              ("Build the fixed one-shot root Installer and scripts-only package", "scripts")):
            block = workflow_step(workflow, name)
            self.assertIn("desktop/tools/stage_macos_installed.py " + command + " \\\n"
                          + '            --target "$MRK_MACOS_TARGET" \\\n', block)
        self.assertIn('--work "$MRK_MACOS_WORK/current-runtime-preparation"', workflow)
        self.assertIn('--expected-source "$MRK_BUNDLED_RUNTIME_SOURCE_SHA256"', workflow)
        self.assertIn('--expected-manifest "$MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"', workflow)
        for variable in ("MRK_BUNDLED_RUNTIME_SOURCE_SHA256",):
            literal = TOOL.re.search(r"^      " + variable + r": ([a-z0-9-]+)$", workflow, TOOL.re.M).group(1)
            self.assertTrue(TOOL.sha(literal))
            self.assertIn('"$' + variable + '" =~ ^[0-9a-f]{64}$', workflow)
            self.assertIn('"$' + variable + '" == ' + literal, workflow)
        fresh_steps = self._assert_fresh_python_supplier_workflow(workflow, paired=True)
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
            self.assertEqual(journey.count("desktop/tools/macos_aqua_qualification.py --scope " + scope + ' --target "$MRK_MACOS_TARGET" ' ), 1)
            self.assertIn("env.MRK_MACOS_AQUA_SCOPE == '" + scope + "'", journey)
            self.assertIn("[[ $status == 0 ]]", journey)
        aqua_owner = (Path(__file__).absolute().parents[2] / "desktop/tools/macos_aqua_qualification.py").read_text(encoding="utf-8")
        self.assertIn('CASES = ("first-save", "noop-stale", "picker-loss", "save-loss")', aqua_owner)
        self.assertIn('return IOS_CASES if scope == "ios-unsigned-archive" else CASES', aqua_owner)

    def test_ordinary_workflow_binds_reviewed_current_payload_before_normal_release(self):
        root = Path(__file__).absolute().parents[2]
        workflow = (root / ".github/workflows/desktop-macos-installed.yml").read_text(encoding="utf-8")
        anchors = {}
        for variable in ("MRK_BUNDLED_RUNTIME_SOURCE_SHA256", "MRK_BUNDLED_PROTOCOL_SHA256"):
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
        for step in self._assert_fresh_python_supplier_workflow(workflow, paired=True):
            self.assertNotIn("\n        if:", step)
        command = "desktop/tools/stage_macos_installed.py current-runtime"
        self.assertEqual(workflow.count(command), 1)
        runtime_name = "Prepare the current payload from the independently accepted fresh Python supplier"
        build_name = "Build the ordinary selected-target desktop image and embedded frontend"
        block = workflow_step(workflow, runtime_name)
        build = workflow_step(workflow, build_name)
        self.assertEqual(block.count(command), 1)
        self.assertLess(workflow.index("      - name: " + runtime_name + "\n"),
                        workflow.index("      - name: " + build_name + "\n"))
        self.assertIn("npm ci --ignore-scripts", build)
        self.assertIn('"/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/cargo" build --locked --release --manifest-path ../helpers/macos-desktop-image/Cargo.toml --lib', build)
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

        # Exactly two selected native jobs; the same target must reach every
        # current package consumer, not merely its artifact label.
        matrix = workflow.split("      matrix:\n", 1)[1].split("    env:\n", 1)[0]
        self.assertEqual(matrix, "        include:\n          - target: aarch64-apple-darwin\n            runner: macos-26\n            machine: arm64\n            hosted_job: github-hosted-macos26-arm64\n            supplier_receipt: '2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d'\n            supplier_tar: 'ff7883185cf8226e9366b1ee9a3dcb3eb8ee761dbc1f697f952510a6bd858695'\n            supplier_source: '158cdff422e3837f7ab5e6192af76a578faf6fab'\n            supplier_run: '37467019389'\n            supplier_attempt: '1'\n            supplier_artifact: '11415902210'\n          - target: x86_64-apple-darwin\n            runner: macos-26-intel\n            machine: x86_64\n            hosted_job: github-hosted-macos26-x86_64\n            supplier_receipt: 'a46f6838afdb7c20c3539e8f65891312aa8df10e2de67e9b9e3ddbf449883b4b'\n            supplier_tar: '739cc8b8b3c68daffba8d7b9cb7cb54ca730eef2c5842302ae8a2682bf64d5bd'\n            supplier_source: '079ab2a2c8fef88f01bf909e7669c685f07e1375'\n            supplier_run: '37476532238'\n            supplier_attempt: '1'\n            supplier_artifact: '11419502465'\n")
        self.assertIn("    name: normal-installed-${{ matrix.target }}\n", workflow)
        self.assertIn("    runs-on: ${{ matrix.runner }}\n", workflow)
        for key in ("TARGET", "RUNNER", "MACHINE", "HOSTED_JOB"):
            self.assertEqual(workflow.count("      MRK_MACOS_" + key + ": ${{ matrix." + key.lower() + " }}\n"), 1)
        admission = workflow_step(workflow, "Admit only this exact disposable-hosted source route")
        for target, runner, machine, architecture in (("aarch64-apple-darwin", "macos-26", "arm64", "ARM64"),
                                                       ("x86_64-apple-darwin", "macos-26-intel", "x86_64", "X64")):
            branch = admission.split("            " + target + ")\n", 1)[1].split("              ;;", 1)[0]
            for exact in ('"$MRK_MACOS_RUNNER" == ' + runner, '"$RUNNER_ARCH" == ' + architecture,
                          '"$MRK_MACOS_MACHINE" == ' + machine, '"$(/usr/bin/uname -m)" == ' + machine,
                          '"$MRK_MACOS_HOSTED_JOB" == github-hosted-macos26-' + machine):
                self.assertIn(exact, branch)
        self.assertIn("*) exit 1 ;;", admission)
        for command in ("current-runtime", "packaging-selection", "app", "input", "scripts", "prepare-package", "audit-package",
                        "check-installer-result-absent", "observe-installer-fixture", "preview"):
            lines = workflow.replace('\\\n', ' ').splitlines()
            callers = [line for line in lines if "stage_macos_installed.py " + command + " " in line]
            self.assertTrue(callers, command)
            for line in callers:
                self.assertEqual(line.count('--target "$MRK_MACOS_TARGET"'), 1, command)

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
        data_step = workflow_step(workflow, "Compile and run only fixed native DATA contracts and exact host-Python regressions")
        self.assertEqual(data_step, (
            "        id: data_contracts\n"
            "        if: github.ref == 'refs/heads/verify/desktop-macos-preview'\n"
            "        timeout-minutes: 28\n"
            "        shell: bash\n"
            "        run: |\n"
            "          builtin source ./desktop/tools/macos_installed_data_contracts.sh\n"))
        helper_path = "desktop/tools/macos_installed_data_contracts.sh"
        self.assertEqual(workflow.count("builtin source ./" + helper_path), 1)
        data = (root / helper_path).read_text(encoding="utf-8")
        self.assertTrue(data.startswith("set -euo pipefail\nset -o noclobber\numask 077\n"))
        # This workflow uses only fixed literal scalars. Do not silently ignore
        # a new scalar form or an oversized embedded program (GitHub limit).
        run_lines = workflow.splitlines(keepends=True)
        run_starts = [i for i, line in enumerate(run_lines) if TOOL.re.match(r"^\s*run:", line)]
        self.assertEqual(len(run_starts), 41)
        for start in run_starts:
            self.assertEqual(run_lines[start], "        run: |\n")
            end = start + 1
            while end < len(run_lines) and (not run_lines[end].strip() or run_lines[end].startswith("          ")):
                end += 1
            scalar = "".join(line[10:] if line.startswith("          ") else "\n"
                             for line in run_lines[start + 1:end]).rstrip("\n") + "\n"
            self.assertLessEqual(len(scalar), 21000, "run scalar at line " + str(start + 1))
        names = ast.literal_eval(TOOL.re.search(r"\nnames = (\[\n.*?\n\])\n", data, TOOL.re.S).group(1))
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
        sources = ast.literal_eval(TOOL.re.search(r"\nsource_names = (\(\n.*?\n\))\n", data, TOOL.re.S).group(1))
        self.assertEqual(len(sources), 78)
        self.assertEqual(len(sources), len(set(sources)))
        self.assertEqual(digest(sources[:53]), "5d544a55d63d5ac1f14f341b0ba51509c6c77e762e2f7e7c964fc9f87ec44bf4")
        self.assertEqual(sources[64:69], (
            "desktop/macos-installed-inputs/build-release.json",
            "desktop/src-tauri/src/macos_build_release.rs",
            "desktop/src-tauri/src/macos_install_fixed_paths.rs",
            "desktop/src-tauri/src/macos_install_paths.rs",
            "desktop/src-tauri/tauri.conf.json",
        ))
        self.assertEqual(sources[69:77], (
            "tests/desktop/test_android_build_tools.py",
            "src/mobile_release/android_build_tools.py",
            "src/mobile_release/android_build_tools_macos.py",
            "src/mobile_release/android_build_operation.py",
            "src/mobile_release/_desktop_android_build_files.py",
            "src/mobile_release/android.py",
            "src/mobile_release/credentials.py",
            "src/mobile_release/local_signing.py",
        ))
        self.assertEqual(sources[77:], (helper_path,))
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
        normal = '"/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/cargo" build --locked --release --manifest-path ../helpers/macos-desktop-image/Cargo.toml --lib'
        build, assembly, inputs = normal_app_steps(workflow)
        self.assertEqual(workflow.count(normal), 1)
        self.assertEqual(build.count(normal + " \\\n"), 1)
        self.assertIn('--binary "$MRK_MACOS_WORK/mobile-release-kit-desktop"', assembly)
        self.assertIn('--expected-app-binary "$MRK_MACOS_DESKTOP_FACADE_SHA256"', assembly)
        self.assertIn('--desktop-image "$CARGO_TARGET_DIR/$MRK_MACOS_TARGET/release/libmrk_desktop_image.dylib"', assembly)
        self.assertIn('--expected-desktop-image "$MRK_MACOS_DESKTOP_IMAGE_SHA256"', assembly)
        # The reviewed notary owner now supplies the former direct input CLI.
        delegated = ('desktop/tools/macos_android_helper_package.py notarize-payload '
                     '--target "$MRK_MACOS_TARGET" > "$MRK_MACOS_WORK/input-result.json"')
        self.assertEqual(inputs.count(delegated), 1)
        self.assertIn('desktop_image_sha=$(/usr/bin/shasum -a 256 "$desktop_image")', assembly)
        self.assertIn('MRK_MACOS_SIGNED_DESKTOP_IMAGE_SHA256=%s\\n', assembly)
        self.assertIn('"$entry_sha" "$payload_sha" "$desktop_image_sha" >> "$GITHUB_ENV"', assembly)
        package_source = (root / "desktop/tools/macos_android_helper_package.py").read_text(encoding="utf-8")
        operation = next(node for node in ast.parse(package_source).body
                         if isinstance(node, ast.ClassDef) and node.name == "Operation")
        notarize_node = next(node for node in operation.body
                             if isinstance(node, ast.FunctionDef) and node.name == "notarize_payload")
        notarize = ast.get_source_segment(package_source, notarize_node)
        arguments = [node.value for node in notarize_node.body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == "arguments" for target in node.targets)]
        self.assertEqual(len(arguments), 1)
        self.assertIsInstance(arguments[0], ast.Call)
        self.assertEqual(ast.get_source_segment(package_source, arguments[0].func), "argparse.Namespace")
        for key, expected in (
                ("expected_desktop_image", 'self.environment.get("MRK_MACOS_SIGNED_DESKTOP_IMAGE_SHA256") if self.environment["MRK_MACOS_PACKAGE_ROLE"] == "ordinary-image" else None'),
                ("app", "app_path")):
            self.assertEqual([ast.get_source_segment(package_source, item.value) for item in arguments[0].keywords
                              if item.arg == key], [expected])
        self.assertIn('app_path = self.work / "app" / self.stager.APP_NAME', notarize)
        input_calls = [ast.get_source_segment(package_source, node) for node in ast.walk(notarize_node)
                       if isinstance(node, ast.Call) and any(
                           ast.get_source_segment(package_source, argument) == "self.stager.input_command"
                           for argument in node.args)]
        self.assertEqual(input_calls, [
            'self.notary_io("notary-preflight-input", self.stager.input_command, arguments)',
            'self.notary_io("notary-final-input", self.stager.input_command, arguments, ticket_expectations=tickets)',
        ])
        self.assertIn('arguments.output = self.work / "input"', notarize)
        self.assertIn('self.notary_final["snapshot"]["files"].get("install-inventory.json", (None, None))[1] == result["inventorySha256"]', notarize)
        self.assertIn('body = operation.notary_result.decode("ascii")', package_source)
        self.assertIn('need(sys.stdout.write(body) == len(body), "notary-final-stdout-short-write")', package_source)
        self.assertIn('inventory=$("$MRK_PYTHON" -I -S -B - "$MRK_MACOS_WORK/input-result.json"', inputs)
        self.assertIn('value = json.loads(data)["inventorySha256"]', inputs)
        self.assertIn("printf 'MRK_MACOS_INSTALL_INVENTORY_SHA256=%s\\n' \"$inventory\" >> \"$GITHUB_ENV\"", inputs)
        self.assertIn("MRK_IMAGE_RELEASE_ID: $" + "{{ steps.android_helper.outputs['image-release-id'] }}", build)
        self.assertIn('--desktop-image-cargo-messages "$MRK_MACOS_WORK/normal-build.jsonl"', assembly)
        # The preview's separate debug DATA contract is not the shipped binary.
        data_step = workflow_step(workflow, "Compile and run only fixed native DATA contracts and exact host-Python regressions")
        self.assertEqual(data_step.split("        run: |\n", 1)[1],
                         "          builtin source ./desktop/tools/macos_installed_data_contracts.sh\n")
        data = (root / "desktop/tools/macos_installed_data_contracts.sh").read_text(encoding="utf-8")
        self.assertNotIn("macos-installed-observation", workflow)
        self.assertEqual(data.count("macos-installed-observation"), 1)
        self.assertIn('"--features", "desktop-shell,custom-protocol,macos-installed-observation"', data)
        self.assertIn('"--test", "installed-shell-observation", "--no-run", "--message-format=json"', data)
        self.assertIn('argv = [str(artifact), "data-contracts"]', data)
        self.assertIn('native_machine = machines[build_target]', data)
        self.assertIn('NATIVE_TARGET = " + repr(build_target)', data)
        self.assertIn('NATIVE_MACHINE = " + repr(native_machine)', data)
        self.assertIn('NATIVE_MACHINE == {"aarch64-apple-darwin": "arm64", "x86_64-apple-darwin": "x86_64"}[NATIVE_TARGET]', data)
        self.assertIn('os.uname().machine == NATIVE_MACHINE', data)
        self.assertIn('"target": build_target', data)
        self.assertIn('artifact.parent != root / "cargo-target" / build_target / "debug/deps"', data)
        for block in (build, assembly, inputs):
            for forbidden in ("macos-installed-observation", "installed_shell_observation", "development-runtime"):
                self.assertFalse(forbidden in block, "normal shipping step: " + forbidden)
        for forbidden in ("development-runtime", "--scope ", "qualification.main("):
            self.assertFalse(forbidden in workflow + data, forbidden)
        # The sole qualifier filename loads only the existing process owner;
        # it is not a qualifier CLI or Aqua journey invocation.
        direct = workflow_step(workflow, "Admit the fixed image Rust tools without installing a distribution")
        loader = ("spec = importlib.util.spec_from_file_location('_mrk_direct_rust_existing_owner_loader', "
                  "checkout / 'desktop/tools/macos_aqua_qualification.py')")
        self.assertEqual(workflow.count("macos_aqua_qualification.py"), 1)
        self.assertEqual(direct.count(loader), 1)
        self.assertIn("spec.loader.exec_module(qualification)", direct)
        self.assertIn("owner = qualification.load_owner(checkout)", direct)
        self.assertIn("result = owner.run_owned(argv, environ=environment, cwd=checkout / 'desktop/src-tauri',", direct)
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
            '"/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/cargo" build --locked --release --no-default-features --features macos-installed-installer-fixture ')
        ordinary_build = workflow.index(
            '"/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/cargo" build --locked --release --no-default-features --features macos-installed-installer ')
        self.assertLess(fixture_build, fixture)
        self.assertLess(fixture, fixture_readback)
        self.assertLess(fixture_readback, ordinary_build)
        self.assertLess(ordinary_build, ordinary)
        self.assertLess(ordinary, ordinary_readback)
        self.assertEqual(workflow.count("sudo -- /usr/sbin/installer -pkg "), 1)
        for stem in ("installer-fixture",):
            self.assertIn('--installer-status "$MRK_MACOS_WORK/' + stem + '-output.status"', workflow)
        exports = workflow_evidence_paths(workflow)
        for path in ("runtime-result.json", "input-result.json", "installer-fixture-observation.json", "installation-observation.json"):
            self.assertIn("$" + "{{ steps.work.outputs.root }}/" + path + "\n", exports)
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


def observer_cargo_fixture(target=None, *, build_target="aarch64-apple-darwin"):
    target, _image, rows, _body = normal_cargo_fixture(target, build_target=build_target)
    root = TOOL.DESKTOP / "src-tauri"
    binary = target / build_target / "debug/deps/installed_shell_observation-0123456789abcdef"
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
    return target, binary, rows, entry_macho_fixture(target=build_target) + b"observer-only-inert-DATA"


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
            if filename == "desktop-macos-installed.yml":
                target_assignment = "target='${{ matrix.target }}'"
                target_call = 'stage_macos_installed.py android-support --target "$target"'
                self.assertEqual(block.count(target_assignment), 1)
                self.assertEqual(block.count('--target "$target"'), 1)
                self.assertLess(block.index(target_assignment), block.index(target_call))
                self.assertNotIn("MRK_MACOS_TARGET", block)
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
                                   ("installed-shell-observation", "aarch64-apple-darwin"),
                                   ("installed-shell-observation", "x86_64-apple-darwin")):
            with self.subTest(role=role, target=build_target), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary).resolve(strict=True)
                fixture = normal_cargo_fixture if role == "ordinary-image" else observer_cargo_fixture
                target, artifact, rows, artifact_body = fixture(work / "cargo-target", build_target=build_target)
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
                                     TOOL.observer_cargo_artifact(messages, artifact, target, artifact_body, target=build_target))
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
        for build_target, other_target in ((TOOL.ARM_TARGET, TOOL.INTEL_TARGET), (TOOL.INTEL_TARGET, TOOL.ARM_TARGET)):
            observer_target, observer, rows, executable = observer_cargo_fixture(build_target=build_target)
            messages = cargo_lines(*rows, {"reason": "build-finished", "success": True})
            result = TOOL.observer_cargo_artifact(messages, observer, observer_target, executable, target=build_target)
            self.assertEqual(result["target"], build_target)
            self.assertTrue(result["instrumented"])
            for index, section, field, value in (
                (0, "target", "kind", ["cdylib"]), (0, "profile", "test", False),
                (0, None, "features", ["custom-protocol", "desktop-shell", "macos-installed-desktop-image"]),
                (1, None, "profile", None), (1, "profile", "test", True),
                (2, None, "features", ["default", "resident-image"]),
            ):
                changed = TOOL.decode(TOOL.canonical(rows))
                (changed[index] if section is None else changed[index][section])[field] = value
                with self.subTest(target=build_target, observer=(index, section, field)), self.assertRaises(TOOL.Refused):
                    TOOL.observer_cargo_artifact(cargo_lines(*changed, {"reason": "build-finished", "success": True}),
                                                observer, observer_target, executable, target=build_target)
            for wrong_body in (image_macho_fixture(target=build_target),
                               observer_cargo_fixture(build_target=other_target)[3]):
                with self.subTest(target=build_target, wrong_body=TOOL.digest(wrong_body)), self.assertRaises(TOOL.Refused):
                    TOOL.observer_cargo_artifact(messages, observer, observer_target, wrong_body, target=build_target)
            foreign = observer_target / other_target / "debug/deps" / observer.name
            with self.subTest(target=build_target, wrong_path=True), self.assertRaises(TOOL.Refused):
                TOOL.observer_cargo_artifact(messages, foreign, observer_target, executable, target=build_target)
            changed = TOOL.decode(TOOL.canonical(rows))
            changed[0]["executable"] = str(foreign)
            changed[0]["filenames"] = [str(foreign)]
            with self.subTest(target=build_target, wrong_record=True), self.assertRaises(TOOL.Refused):
                TOOL.observer_cargo_artifact(cargo_lines(*changed, {"reason": "build-finished", "success": True}),
                                            observer, observer_target, executable, target=build_target)
            for refused_target in (other_target, "arm64-apple-darwin", "x86_64h-apple-darwin"):
                with self.subTest(target=build_target, selected=refused_target), self.assertRaises(TOOL.Refused):
                    TOOL.observer_cargo_artifact(messages, observer, observer_target, executable, target=refused_target)

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
        def check_tickets(selected_args, selected_app, reader, writer):
            # Real input/inventory logic with the same inert tree/native fixtures.
            # No ticket fixture is a cryptographic or notarization assertion.
            names = ("Contents/CodeResources", TOOL.PAYLOAD_CONTENTS + "CodeResources")
            tickets = {name: (("inert ticket " + str(index)).encode("ascii"), 0o644)
                       for index, name in enumerate(names)}
            rows = [{"path": name, "bytes": len(tickets[name][0]), "sha256": TOOL.digest(tickets[name][0])}
                    for name in names]
            paired = {**selected_app, **tickets}
            reader.return_value = paired; writer.reset_mock()
            with self.assertRaisesRegex(TOOL.Refused, "signed-app-roster"):
                TOOL.input_command(selected_args)  # Explicit opt-in remains mandatory.
            writer.assert_not_called()
            result = TOOL.input_command(selected_args, ticket_expectations=rows)
            copied = writer.call_args.args[1]
            inventory = TOOL.decode(copied["install-inventory.json"][0])
            indexed = {row["path"]: row for row in inventory["files"]}
            self.assertEqual(result["inventorySha256"], TOOL.digest(copied["install-inventory.json"][0]))
            self.assertEqual(result["qualification"], "fresh-install-input-not-installed")
            for row in rows:
                self.assertEqual(copied["app/" + row["path"]], (tickets[row["path"]][0], 0o444))
                self.assertEqual(indexed["app/" + row["path"]], {
                    "path": "app/" + row["path"], "size": row["bytes"], "sha256": row["sha256"], "executable": False})
            malformed = [[], rows[:1], rows + rows[:1], list(reversed(rows)), tuple(rows),
                         [dict(rows[0], notarized=True), rows[1]],
                         [dict(rows[0], path="Contents/_CodeSignature/CodeResources"), rows[1]]]
            for key, value in (("bytes", True), ("bytes", 0), ("bytes", 1048577),
                               ("bytes", rows[0]["bytes"] + 1), ("sha256", "0" * 64), ("sha256", "invalid")):
                malformed.append([dict(rows[0], **{key: value}), rows[1]])
            for expectations in malformed:
                reader.return_value = paired; writer.reset_mock()
                with self.subTest(role=selected_args.package_role, expectations=expectations), self.assertRaises(TOOL.Refused):
                    TOOL.input_command(selected_args, ticket_expectations=expectations)
                writer.assert_not_called()
            variants = [selected_app, {k: v for k, v in paired.items() if k != names[0]},
                        {k: v for k, v in paired.items() if k != names[1]},
                        {**paired, "Contents/Helpers/Other.app/Contents/CodeResources": (b"inert", 0o444)}]
            for mode in (0o755, 0o644 | 0o2000, 0o664, 0o646):
                variants.append({**paired, names[0]: (tickets[names[0]][0], mode)})
            variants.extend(({**paired, names[0]: (b"", 0o444)},
                             {**paired, names[1]: (b"changed ticket", 0o444)}))
            for mutation in variants:
                reader.return_value = mutation; writer.reset_mock()
                with self.subTest(role=selected_args.package_role, roster=list(mutation)), self.assertRaises(TOOL.Refused):
                    TOOL.input_command(selected_args, ticket_expectations=rows)
                writer.assert_not_called()
            # Boundary-sized ticket remains ordinary bounded DATA in the same inventory.
            boundary = b"X" * (1024 * 1024)
            reader.return_value = {**paired, names[0]: (boundary, 0o444)}
            TOOL.input_command(selected_args, ticket_expectations=[dict(rows[0], bytes=len(boundary), sha256=TOOL.digest(boundary)), rows[1]])
            reader.return_value = {**paired, names[0]: (boundary + b"X", 0o444)}; writer.reset_mock()
            with self.assertRaises(TOOL.Refused):
                TOOL.input_command(selected_args, ticket_expectations=rows)
            writer.assert_not_called()
            reader.return_value = selected_app; writer.reset_mock()

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
            check_tickets(args, app, tree, output)
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
            check_tickets(observer_args, observer_app, tree, output)
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
              mock.patch.object(TOOL, "tree", return_value=intel_app) as signed_tree,
              mock.patch.object(TOOL, "ANDROID_SUPPORT_MANIFEST", support.manifest_path),
              mock.patch.object(TOOL, "read", side_effect=lambda path, *_: source[path]),
              mock.patch.object(TOOL, "write_tree") as output):
            TOOL.input_command(intel_args)
            runtime_reader.assert_called_once_with(args.runtime, args.expected_manifest, current=True, target=intel_target)
            self.assertEqual(TOOL.decode(output.call_args.args[1]["install-inventory.json"][0])["release"], intel_release)
            output.reset_mock()
            with self.assertRaises(TOOL.Refused): TOOL.input_command(SimpleNamespace(**dict(vars(intel_args), target="aarch64-apple-darwin")))
            output.assert_not_called()
            # The instrumented role remains distinct from an ordinary image,
            # but current Intel runtime and every nested target are the same
            # required correspondence. These are parser DATA, not signatures.
            intel_observer = observer_cargo_fixture(build_target=intel_target)[3]
            intel_observer_app = {name: value for name, value in intel_app.items() if name != TOOL.DESKTOP_IMAGE}
            intel_observer_app[TOOL.APP_BINARY] = (intel_observer, 0o755)
            intel_observer_args = SimpleNamespace(**dict(vars(intel_args), package_role="installed-shell-observation",
                expected_desktop_image=None, expected_app_binary=TOOL.digest(intel_observer)))
            signed_tree.return_value = intel_observer_app
            runtime_reader.reset_mock(); output.reset_mock()
            result = TOOL.input_command(intel_observer_args)
            runtime_reader.assert_called_once_with(args.runtime, args.expected_manifest, current=True, target=intel_target)
            self.assertEqual(result["packageRole"], "installed-shell-observation")
            files = output.call_args.args[1]
            self.assertEqual(TOOL.decode(files["install-inventory.json"][0])["release"], intel_release)
            self.assertEqual(files["app/" + TOOL.APP_BINARY], (intel_observer, 0o555))
            self.assertEqual(files["app/" + TOOL.RESIDENT_IMAGE], (intel_resident, 0o555))
            self.assertNotIn("app/" + TOOL.DESKTOP_IMAGE, files)
            check_tickets(intel_args, intel_app, signed_tree, output)
            check_tickets(intel_observer_args, intel_observer_app, signed_tree, output)
            for selected_args, selected_tree in ((intel_args, intel_observer_app), (intel_observer_args, intel_app)):
                signed_tree.return_value = selected_tree; output.reset_mock()
                with self.subTest(target=intel_target, role=selected_args.package_role), self.assertRaisesRegex(TOOL.Refused, "signed-app-roster"):
                    TOOL.input_command(selected_args)
                output.assert_not_called()
            wrong_body = observer_cargo_fixture(build_target=TOOL.ARM_TARGET)[3]
            signed_tree.return_value = {**intel_observer_app, TOOL.APP_BINARY: (wrong_body, 0o755)}
            wrong_args = SimpleNamespace(**dict(vars(intel_observer_args), expected_app_binary=TOOL.digest(wrong_body)))
            output.reset_mock()
            with self.assertRaises(TOOL.Refused):
                TOOL.input_command(wrong_args)
            output.assert_not_called()
            for selected_args in (intel_args, intel_observer_args):
                historical = SimpleNamespace(**dict(vars(selected_args), current_runtime=False))
                runtime_reader.reset_mock(); signed_tree.reset_mock(); output.reset_mock()
                with self.subTest(target=intel_target, historical_role=selected_args.package_role), self.assertRaisesRegex(TOOL.Refused, "unqualified-intel-route"):
                    TOOL.input_command(historical)
                runtime_reader.assert_not_called(); signed_tree.assert_not_called(); output.assert_not_called()

    def test_helper_is_separate_signed_before_digest_bound_app_and_not_a_qualification(self):
        root = Path(__file__).absolute().parents[2]
        helper = (root / "desktop/helpers/macos-vault-helper/Cargo.toml").read_text()
        self.assertIn("[workspace]", helper)
        self.assertIn('features = ["vault-helper"]', helper)
        self.assertNotIn("tauri", helper.split("[dependencies]", 1)[1].lower())
        native = (root / "desktop/native/macos-installed-native/build.rs").read_text()
        self.assertIn("release: 1.98.1", native)
        self.assertIn("commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985", native)
        # SOURCE table DATA only: the actual Rust guard is still exercised by
        # native compilation, never executed or translated by this Python test.
        table_start = 'const CLOCK_TOOLCHAINS: [(&str, &str, &str); 3] = [\n'
        self.assertEqual(native.count(table_start), 1)
        table_body = native.split(table_start, 1)[1].split('\n];', 1)[0]
        clock_rows = ast.literal_eval('[' + table_body + ']')
        self.assertEqual(clock_rows, [
            ("aarch64-apple-darwin", "release: 1.98.1", "commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985"),
            ("x86_64-apple-darwin", "release: 1.98.1", "commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985"),
            ("x86_64-apple-darwin", "release: 1.98.0", "commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea"),
        ])
        for rejected in (
            ("aarch64-apple-darwin", "release: 1.98.0", "commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea"),
            ("x86_64-apple-darwin", "release: 1.98.0", "commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985"),
            ("x86_64-apple-darwin", "release: 1.98.1", "commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea"),
            ("x86_64-apple-darwin", "release: 1.98.2", "commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea"),
            ("x86_64-unknown-linux-gnu", "release: 1.98.0", "commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea"),
        ):
            self.assertNotIn(rejected, clock_rows)
        self.assertIn('let target = std::env::var("TARGET").expect("Cargo native target binding required");', native)
        self.assertIn('assert!(matches!(target.as_str(), "aarch64-apple-darwin" | "x86_64-apple-darwin"),', native)
        for key, expected in (("CARGO_CFG_TARGET_OS", "macos"), ("CARGO_CFG_TARGET_POINTER_WIDTH", "64"),
                              ("CARGO_CFG_TARGET_VENDOR", "apple"), ("CARGO_CFG_TARGET_FAMILY", "unix")):
            self.assertIn('assert_eq!(std::env::var("' + key + '").as_deref(), Ok("' + expected + '")', native)
        self.assertEqual(native.count('std::env::var("TARGET")'), 1)
        query_start = '    let rustc = std::env::var_os("RUSTC").expect("Cargo compiler binding required");\n'
        self.assertEqual(native.count(query_start), 1)
        guard = query_start + native.split(query_start, 1)[1].split('    if qualification {', 1)[0]
        self.assertEqual(guard, '    let rustc = std::env::var_os("RUSTC").expect("Cargo compiler binding required");\n    let version = std::process::Command::new(rustc).args(["--version", "--verbose"])\n        .output().expect("query actual Mac compiler");\n    let version_text = std::str::from_utf8(&version.stdout).expect("compiler version is UTF-8");\n    assert!(version.status.success() && version.stdout.len() <= 4096\n        && CLOCK_TOOLCHAINS.iter().any(|(clock_target, release, commit)| {\n            target.as_str() == *clock_target\n                && version_text.lines().filter(|line| line.starts_with("release:"))\n                    .eq(std::iter::once(*release))\n                && version_text.lines().filter(|line| line.starts_with("commit-hash:"))\n                    .eq(std::iter::once(*commit))\n        }), "Mac app/helper CLOCK_UPTIME_RAW proof requires an exact reviewed target/compiler tuple");\n')
        library = (root / "desktop/src-tauri/src/lib.rs").read_text()
        self.assertIn("!mrk_macos_installed_native::VAULT_HELPER_BUILD", library)
        package_source = (root / "desktop/tools/macos_android_helper_package.py").read_text()
        operation = next(node for node in ast.parse(package_source).body
                         if isinstance(node, ast.ClassDef) and node.name == "Operation")
        fixed_sign = ast.get_source_segment(package_source, next(node for node in operation.body
            if isinstance(node, ast.FunctionDef) and node.name == "fixed_sign"))
        # Every fixed shipping signer uses the same configured identity, runtime
        # option and exact empty-entitlements original; no workflow raw fallback.
        for exact in ('self.phase in SIGNING_PHASES and self.signing is not None',
                      'self.source_original("desktop/packaging/macos-empty-entitlements.plist", "fixed-sign-empty-entitlements", 1024)',
                      'digest(empty) == self.stager.SIGNED_ENTITLEMENTS_SHA256',
                      'arguments = ["--options", "runtime", "--entitlements",',
                      'self.call(self.phase, ["/usr/bin/codesign", "--force", "--sign", self.signing[1], *arguments, "--timestamp", str(path)]',
                      'with self.credential_scope(self.phase):'):
            self.assertIn(exact, fixed_sign)
        self.assertNotIn('"--deep"', fixed_sign)
        # Payload notarization owns the former direct input CLI. Both input
        # passes still receive the same signed vault-helper digest binding.
        notarize = next(node for node in operation.body
                        if isinstance(node, ast.FunctionDef) and node.name == "notarize_payload")
        arguments = [node.value for node in notarize.body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == "arguments" for target in node.targets)]
        self.assertEqual(len(arguments), 1)
        self.assertIsInstance(arguments[0], ast.Call)
        self.assertEqual(ast.get_source_segment(package_source, arguments[0].func), "argparse.Namespace")
        self.assertEqual([ast.get_source_segment(package_source, item.value) for item in arguments[0].keywords
                          if item.arg == "expected_vault_helper"],
                         ['self.environment.get("MRK_MACOS_VAULT_HELPER_SHA256")'])
        input_calls = [ast.get_source_segment(package_source, node) for node in ast.walk(notarize)
                       if isinstance(node, ast.Call) and any(
                           ast.get_source_segment(package_source, argument) == "self.stager.input_command"
                           for argument in node.args)]
        self.assertEqual(input_calls, [
            'self.notary_io("notary-preflight-input", self.stager.input_command, arguments)',
            'self.notary_io("notary-final-input", self.stager.input_command, arguments, ticket_expectations=tickets)',
        ])
        for name in ("desktop-macos-installed.yml", "desktop-macos-aqua.yml"):
            workflow = (root / ".github/workflows" / name).read_text()
            build = workflow.index("--manifest-path desktop/helpers/macos-vault-helper/Cargo.toml")
            helper_sign = workflow.index('macos_android_helper_package.py sign-vault-helper --target "$MRK_MACOS_TARGET"', build)
            digest = workflow.index('output.write("MRK_MACOS_VAULT_HELPER_SHA256=', helper_sign)
            stage = workflow.index("stage_macos_installed.py app", digest)
            app_sign = workflow.index('macos_android_helper_package.py sign-root-app --target "$MRK_MACOS_TARGET"', stage)
            self.assertLess(build, helper_sign); self.assertLess(helper_sign, digest)
            self.assertLess(digest, stage); self.assertLess(stage, app_sign)
            self.assertIn('RUSTUP_TOOLCHAIN: ${{ fromJSON(\'{"aarch64-apple-darwin":"1.98.1","x86_64-apple-darwin":"1.98.0"}\')[matrix.target] }}', workflow)
            self.assertNotIn("RUSTUP_TOOLCHAIN=1.98.1 RUSTUP_AUTO_INSTALL=0", workflow)
            self.assertIn('RUSTUP_TOOLCHAIN="$RUSTUP_TOOLCHAIN" RUSTUP_AUTO_INSTALL=0', workflow)
            phases = ("sign-vault-helper", "sign-desktop-payload", "sign-root-app", "sign-root-installer")
            if name == "desktop-macos-installed.yml":
                phases += ("sign-desktop-image",)
            for phase in phases:
                self.assertEqual(workflow.count("macos_android_helper_package.py " + phase + ' --target "$MRK_MACOS_TARGET"'), 1)
            self.assertEqual(workflow.count("--options runtime"), 0)
            self.assertEqual(workflow.count("--entitlements desktop/packaging/macos-empty-entitlements.plist"), 0)
            vault_argument = '--expected-vault-helper "$MRK_MACOS_VAULT_HELPER_SHA256"'
            self.assertEqual(workflow.count(vault_argument), 1)
            self.assertEqual(workflow[stage:app_sign].count(vault_argument), 1)
            notarize_call = 'macos_android_helper_package.py notarize-payload --target "$MRK_MACOS_TARGET"'
            self.assertEqual(workflow.count(notarize_call), 1)
            self.assertLess(app_sign, workflow.index(notarize_call))
            # Prohibition text may mention --deep. Inspect only the real shell
            #signing commands, folding their continued arguments without execution.
            commands = workflow.replace('\\\n', " ").splitlines()
            signing = [shlex.split(line, comments=True) for line in commands
                       if line.lstrip().startswith("/usr/bin/codesign ") and "--sign " in line]
            self.assertEqual(signing, [["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
                                        "$installer"]]
                             if name == "desktop-macos-installed.yml" else [])
            if name == "desktop-macos-installed.yml":
                fixture = workflow_step(workflow, "Build the separate fixed eight-case Installer package from the same completed input")
                self.assertIn("--features macos-installed-installer-fixture", fixture)
                self.assertIn('installer="$CARGO_TARGET_DIR/$MRK_MACOS_TARGET/release/mrk-macos-install"', fixture)
                self.assertIn('/usr/bin/codesign --force --sign - --timestamp=none "$installer"', fixture)
            for command in signing:
                self.assertNotIn("--deep", command)
        self.assertIn("DURABLE_QUALIFIED: bool = false",
                      (root / "desktop/src-tauri/src/asset_session_vault.rs").read_text())

    def preview_fixture(self, build_target="aarch64-apple-darwin"):
        work = Path("/synthetic-mrk-preview")
        target, binary, rows, body = normal_cargo_fixture(work / "cargo-target", build_target=build_target)
        messages = cargo_lines(*rows, {"reason": "build-finished", "success": True})
        normal = TOOL.image_cargo_artifact(messages, binary, target, body, "desktop", target=build_target)
        facade = entry_macho_fixture(target=build_target)
        binding = {"source": "a" * 40, "workflowSource": "a" * 40, "tree": "b" * 40,
            "scope": "normal-macos-early-preview", "packageRole": "ordinary-image",
            "instrumented": False, "runId": "123", "runAttempt": "1", "runtimeManifestSha256": "c" * 64}
        expected = {"app/" + TOOL.APP_BINARY: {"sha256": "e" * 64}, "app/" + TOOL.ENTRY_BINARY: {"sha256": "f" * 64},
                    "app/" + TOOL.DESKTOP_IMAGE: {"sha256": "9" * 64}, "app/" + TOOL.RESIDENT_IMAGE: {"sha256": "7" * 64},
                    "app/" + TOOL.ANDROID_HELPER: {"sha256": "8" * 64}, "app/" + TOOL.VAULT_HELPER: {"sha256": "6" * 64},
                    "app/" + TOOL.ANDROID_SERVICE_PLIST: {"sha256": "5" * 64}}
        package = b"synthetic-package-DATA-not-native-Installer-evidence"
        _profile, _service, selection, _history, descriptor_data = packaging_fixture(build_target, package=package)
        descriptor, signed, image = TOOL.canonical(descriptor_data) + b"\n", b"not a real signature", b"not a real DMG"
        request, invocation = "1" * 32, "2" * 32
        result = {"schemaVersion": 2, "kind": "maintenance-parent-pending-finalization", "invocation": invocation,
            "requestId": request, "resultName": "MobileReleaseKit-InstallerResult-v2-" + request + ".json",
            "resultFinality": "pending-own-write-readback-close-and-outer-return", "action": "fresh-install",
            "writerState": "installed", "writerExit": 0, "intentSha256": "3" * 64, "stateSha256": "4" * 64,
            "capsuleSha256": "5" * 64, "payloadWriteCount": 1, "payloadWriteBytes": 10, "originalWriterJoined": True,
            "parentFinality": "pending-original-closes-and-outer-return", "retainedGate": "parent-command-reference-until-kernel-exit",
            "historicalOuterExit": "unverified", "registrationReservation": reservation_result_data()}
        observed = {"schemaVersion": 2, "sourceCommit": "a" * 40, "release": selection.release,
            "requestId": request, "invocation": invocation, "originalInstallerReturnedZero": True, "originalWriterJoined": True,
            "historicalOuterExit": "unverified", "applicationLaunched": False, "guiSaveQualified": False,
            "completedPackageSha256": TOOL.digest(package), "runtimeManifestSha256": "c" * 64, "inventorySha256": "d" * 64,
            "nonrootReadbackFileCount": len(expected), "originalInstallerResult": result,
            "registrationReservation": {"state": "protected-permanent-reservation-data-correspondence", "bytes": 38,
                                        "exclusionObserved": False, "workerFinalityEstablished": False},
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
        # Explicitly synthetic final-carrier correspondence, never a native
        # notary/Installer receipt. The real parser is called by preview below.
        final_package = b'{"syntheticFinalPackageReceipt":"not native evidence"}\n'
        owner["finalPackageReceiptSha256"] = TOOL.digest(final_package)
        owner_body = TOOL.canonical(owner)
        release_body = TOOL.canonical({"schemaVersion": 1, "packageVersion": selection.package_version, "release": selection.release})
        notary_profile = TOOL.canonical({"schemaVersion": 1, "mode": "app-store-connect-team-key", "teamId": "TEST000001",
            "keyId": "INERTKEY01", "issuerId": "11111111-2222-3333-4444-555555555555"})
        final_image = b"synthetic final DMG distinct from original"
        submission = {"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "status": "Accepted"}
        final = {"schemaVersion": 1, "kind": "mrk-final-user-image", "target": selection.target,
            "release": selection.release, "packageVersion": selection.package_version, "requestId": request,
            "packageInstallReceiptSha256": TOOL.digest(owner_body), "finalPackageReceiptSha256": TOOL.digest(final_package),
            "packageBytes": len(package), "packageSha256": TOOL.digest(package), "descriptorBytes": len(descriptor),
            "descriptorSha256": TOOL.digest(descriptor), "signatureBytes": len(signed), "signatureSha256": TOOL.digest(signed),
            "producerProfileSha256": TOOL.digest(_profile), "serviceProfileSha256": TOOL.digest(_service),
            "originalImageBytes": len(image), "originalImageSha256": TOOL.digest(image), "submittedSha256": TOOL.digest(image),
            "imageBytes": len(final_image), "imageSha256": TOOL.digest(final_image), "imageMode": 0o444,
            "notaryProfileSha256": TOOL.digest(notary_profile), "submissionId": submission["id"], "status": submission["status"],
            "sha256Compared": True, "errorCount": 0, "warningCount": 0, "ticketRowCount": 1, "logSha256": "e" * 64,
            "strictSignatureBeforeAndAfter": True, "actualStaplerValidation": True, "actualImageVerification": True,
            "finalMountReadOnly": True, "finalMountOriginalsMatch": True, "originalMountDetached": True,
            "assurance": "final-carrier-observation-not-downloaded-install-or-gatekeeper-authority"}
        final_receipt = {"schemaVersion": 1, "phase": "finalize-image", "target": selection.target, "source": "a" * 40,
            "packageRole": "ordinary-image", "workflowSource": "a" * 40,
            "workflow": "Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-installed.yml@refs/heads/verify/desktop-macos-preview",
            "runId": "123", "runAttempt": "1", "toolchain": None, "helperIdentifier": None,
            "originalCalls": [{"role": "final-image-" + role, "entered": True, "returned": True, "capturesSettled": True,
                "returncode": 0, "stdoutSha256": TOOL.digest(b""), "stderrSha256": TOOL.digest(b"")}
                for role in ("resolve-notarytool", "resolve-stapler", "signature-before", "submit", "log", "staple", "validate",
                             "signature-after", "verify", "attach", "detach")],
            "credentialOriginals": [], "credentialContexts": [], "targetRetired": True, "originalClosesKnown": True,
            "passed": True, "outerFinalityRequired": True, "androidServiceAuthenticated": False,
            "androidRegisteredCopyQualified": False, "androidBuildQualified": False,
            "developerIdOrNotarizationQualified": False, "distributionQualified": False, "productReady": False,
            "notaryAuthentication": {"created": True, "closed": True, "retired": True}, "notarySubmission": submission,
            "finalImage": final, "finalImageMount": {"attachEntered": True, "originalKnown": True, "detached": True,
                "retained": False, "installerEntered": False, "systemServiceExitClaimed": False},
            "finalPackageReceiptSha256": TOOL.digest(final_package), "directStagerIOPending": None, "cleanupErrors": [],
            "imageSourceCommit": "a" * 40, "imageReleaseId": selection.release, "imageReleaseSourceSha256": TOOL.digest(release_body)}
        values.update({work / "image-finalization.status": b"0\n", work / "package-finalization.status": b"0\n",
            work / "android-helper-finalize-package.json": final_package,
            work / "distribution-final/MobileReleaseKit.dmg": final_image,
            TOOL.PRODUCER_PROFILE: _profile, TOOL.SERVICE_PROFILE: _service,
            TOOL.DESKTOP / "packaging/macos-notary-service.json": notary_profile,
            TOOL.BUILD_RELEASE_INPUT if selection.target == TOOL.ARM_TARGET else
                TOOL.DESKTOP / "macos-installed-inputs/build-release-intel.json": release_body})
        documents["android-helper-finalize-image.json"] = final_receipt
        values.update({work / name: TOOL.canonical(value) for name, value in documents.items()})
        return work, values, documents, expected, selection

    def test_preview_roster_has_no_raw_evidence_and_keeps_open_and_quit_unexecuted(self):
        for target in TOOL.MAC_TARGETS:
            work, values, documents, expected, selection = self.preview_fixture(target)
            args = SimpleNamespace(work=work, output=work / "preview", expected_source="a" * 40)
            if target != TOOL.ARM_TARGET:
                args.target = target  # The original ARM default still runs.
            with mock.patch.object(TOOL, "read", side_effect=lambda path, *_: values[path]), \
                    mock.patch.object(TOOL, "source_build_selection", return_value=selection) as selected, \
                    mock.patch.object(TOOL, "observation_inventory", return_value=expected) as inventory_read, \
                    mock.patch.object(TOOL, "write_tree") as output:
                result = TOOL.preview_command(args)
            selected.assert_called_once_with(target)
            self.assertIs(inventory_read.call_args.kwargs["selection"], selection)
            files = output.call_args.args[1]
            self.assertEqual(set(files), {"MobileReleaseKit.dmg", "README.md", "PREVIEW.json"})
            self.assertEqual(files["MobileReleaseKit.dmg"], (values[work / "distribution-final/MobileReleaseKit.dmg"], 0o444))
            self.assertNotEqual(files["MobileReleaseKit.dmg"][0], values[work / "distribution/MobileReleaseKit.dmg"])
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
            self.assertEqual(summary["platform"], "macOS26-arm64" if target == TOOL.ARM_TARGET else "macOS26-x86_64")
            self.assertTrue(summary["originalImageFinalizationReturnedZero"] and summary["originalFinalImageMountDetached"])
            self.assertTrue(summary["finalImageScopedNotarizationObserved"])
            self.assertEqual(summary["finalImageReceiptSha256"], TOOL.digest(values[work / "android-helper-finalize-image.json"]))
            self.assertEqual(summary["originalDistributionSha256"], TOOL.digest(values[work / "distribution/MobileReleaseKit.dmg"]))
            self.assertNotEqual(summary["originalDistributionSha256"], TOOL.digest(files["MobileReleaseKit.dmg"][0]))

    def test_failed_original_status_changed_package_or_unsettled_readback_cannot_publish(self):
        failures = [
            ("image-finalization.status", None, b"1\n"), ("package-finalization.status", None, b"1\n"),
            ("distribution-final/MobileReleaseKit.dmg", None, b"changed"),
            ("android-helper-finalize-package.json", None, b"changed raw S3 receipt"),
            ("android-helper-finalize-image.json", "schemaVersion", True),
            ("android-helper-finalize-image.json", "phase", "package-install"),
            ("android-helper-finalize-image.json", "source", "b" * 40),
            ("android-helper-finalize-image.json", "workflowSource", "b" * 40),
            ("android-helper-finalize-image.json", "workflow", "other-workflow"),
            ("android-helper-finalize-image.json", "runAttempt", "2"),
            ("android-helper-finalize-image.json", "packageRole", "installed-shell-observation"),
            ("android-helper-finalize-image.json", "imageReleaseSourceSha256", "f" * 64),
            ("android-helper-finalize-image.json", "passed", False),
            ("android-helper-finalize-image.json", "originalClosesKnown", False),
            ("android-helper-finalize-image.json", "targetRetired", False),
            ("android-helper-finalize-image.json", "outerFinalityRequired", False),
            ("android-helper-finalize-image.json", "productReady", True),
            ("android-helper-finalize-image.json", "distributionQualified", True),
            ("android-helper-finalize-image.json", "developerIdOrNotarizationQualified", True),
            ("android-helper-finalize-image.json", "cleanupErrors", [{"type": "OSError"}]),
            ("android-helper-finalize-image.json", "directStagerIOPending", "unclosed"),
            ("android-helper-finalize-image.json", "credentialOriginals", [{"status": 0}]),
            ("android-helper-finalize-image.json", ("notaryAuthentication", "retired"), False),
            ("android-helper-finalize-image.json", ("notaryAuthentication", "closed"), False),
            ("android-helper-finalize-image.json", ("notarySubmission", "id"), "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"),
            ("android-helper-finalize-image.json", ("finalImageMount", "detached"), False),
            ("android-helper-finalize-image.json", ("finalImageMount", "retained"), True),
            ("android-helper-finalize-image.json", ("finalImageMount", "installerEntered"), True),
            ("android-helper-finalize-image.json", ("finalImageMount", "systemServiceExitClaimed"), True),
            ("android-helper-finalize-image.json", ("originalCalls", 0, "returned"), False),
            ("android-helper-finalize-image.json", ("originalCalls", 10, "capturesSettled"), False),
            ("android-helper-finalize-image.json", ("originalCalls", 10, "returncode"), 1),
            ("android-helper-finalize-image.json", ("originalCalls", 9, "role"), "distribution-attach"),
            ("android-helper-finalize-image.json", ("finalImage", "requestId"), "2" * 32),
            ("android-helper-finalize-image.json", ("finalImage", "packageBytes"), True),
            ("android-helper-finalize-image.json", ("finalImage", "descriptorSha256"), "f" * 64),
            ("android-helper-finalize-image.json", ("finalImage", "signatureBytes"), 1),
            ("android-helper-finalize-image.json", ("finalImage", "submittedSha256"), "f" * 64),
            ("android-helper-finalize-image.json", ("finalImage", "imageMode"), 0o600),
            ("android-helper-finalize-image.json", ("finalImage", "imageBytes"), TOOL.MAX_BYTES + 1),
            ("android-helper-finalize-image.json", ("finalImage", "imageBytes"), 2 * 1024 * 1024),
            ("android-helper-finalize-image.json", ("finalImage", "packageInstallReceiptSha256"), "f" * 64),
            ("android-helper-finalize-image.json", ("finalImage", "finalPackageReceiptSha256"), "f" * 64),
            ("android-helper-finalize-image.json", ("finalImage", "producerProfileSha256"), "f" * 64),
            ("android-helper-finalize-image.json", ("finalImage", "serviceProfileSha256"), "f" * 64),
            ("android-helper-finalize-image.json", ("finalImage", "notaryProfileSha256"), "f" * 64),
            ("android-helper-finalize-image.json", ("finalImage", "status"), "Invalid"),
            ("android-helper-finalize-image.json", ("finalImage", "errorCount"), 1),
            ("android-helper-finalize-image.json", ("finalImage", "ticketRowCount"), 2049),
            ("android-helper-finalize-image.json", ("finalImage", "actualStaplerValidation"), False),
            ("android-helper-finalize-image.json", ("finalImage", "finalMountOriginalsMatch"), False),
            ("android-helper-finalize-image.json", ("finalImage", "finalMountReadOnly"), False),
            ("android-helper-finalize-image.json", ("finalImage", "actualImageVerification"), False),
            ("android-helper-finalize-image.json", ("finalImage", "strictSignatureBeforeAndAfter"), False),
            ("android-helper-finalize-image.json", ("finalImage", "assurance"), "Gatekeeper-approved"),
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
            ("installation-observation.json", "registrationReservation", None),
            ("installation-observation.json", ("registrationReservation", "exclusionObserved"), True),
            ("installation-observation.json", ("registrationReservation", "workerFinalityEstablished"), True),
            ("installation-observation.json", ("originalInstallerResult", "registrationReservation", "closedUnderMaintenance"), False),
            ("app-result.json", "entryBundleIdentifier", TOOL.BUNDLE_ID),
            ("app-result.json", "entryBinarySha256BeforeSigning", None),
            ("package-audit.json", "packageSha256", "f" * 64),
        ]
        for target in TOOL.MAC_TARGETS:
            opposite = TOOL.INTEL_TARGET if target == TOOL.ARM_TARGET else TOOL.ARM_TARGET
            paired_failures = [
                ("android-helper-finalize-image.json", "target", opposite),
                ("android-helper-finalize-image.json", ("finalImage", "target"), opposite),
                ("android-helper-finalize-image.json", ("finalImage", "release"), "macos26-foreign-release"),
                ("android-helper-finalize-image.json", ("finalImage", "packageVersion"), "9.9.9"),
                ("android-helper-package-install.json", "target", opposite),
                ("android-helper-package-install.json", ("distribution", "target"), opposite),
                ("android-helper-package-install.json", ("distribution", "packageVersion"), "9.9.9"),
                ("android-helper-package-install.json", ("distribution", "release"), "macos26-foreign-release"),
                ("installation-observation.json", "schemaVersion", 1),
                ("installation-observation.json", "release", "macos26-foreign-release"),
            ]
            for name, field, value in failures + paired_failures:
                work, values, documents, expected, selection = self.preview_fixture(target)
                if field is None:
                    values[work / name] = value
                else:
                    cursor = documents[name]
                    path = field if type(field) is tuple else (field,)
                    for key in path[:-1]:
                        cursor = cursor[key]
                    cursor[path[-1]] = value
                    values[work / name] = TOOL.canonical(documents[name])
                args = SimpleNamespace(work=work, output=work / "preview", expected_source="a" * 40, target=target)
                with self.subTest(target=target, name=name, field=field), \
                        mock.patch.object(TOOL, "read", side_effect=lambda path, *_: values[path]), \
                        mock.patch.object(TOOL, "source_build_selection", return_value=selection), \
                        mock.patch.object(TOOL, "observation_inventory", return_value=expected), \
                        mock.patch.object(TOOL, "write_tree") as output:
                    with self.assertRaises(TOOL.Refused):
                        TOOL.preview_command(args)
                    output.assert_not_called()

            # Valid other-CPU bytes and valid other-target Cargo rows are not
            # interchangeable with this target, even in an otherwise bound run.
            for mutation in ("facade-cpu", "image-cpu", "cargo-target"):
                work, values, documents, expected, selection = self.preview_fixture(target)
                binary = work / "cargo-target" / target / "release/libmrk_desktop_image.dylib"
                if mutation == "facade-cpu":
                    values[work / "mobile-release-kit-desktop"] = entry_macho_fixture(target=opposite)
                    documents["app-result.json"]["appBinarySha256BeforeSigning"] = TOOL.digest(values[work / "mobile-release-kit-desktop"])
                elif mutation == "image-cpu":
                    values[binary] = image_macho_fixture("desktop", target=opposite)
                    documents["app-result.json"]["desktopImageSha256BeforeSigning"] = TOOL.digest(values[binary])
                else:
                    _target, _binary, rows, _body = normal_cargo_fixture(work / "cargo-target", build_target=opposite)
                    values[work / "normal-build.jsonl"] = cargo_lines(*rows, {"reason": "build-finished", "success": True})
                values[work / "app-result.json"] = TOOL.canonical(documents["app-result.json"])
                args = SimpleNamespace(work=work, output=work / "preview", expected_source="a" * 40, target=target)
                with (self.subTest(target=target, mutation=mutation),
                      mock.patch.object(TOOL, "read", side_effect=lambda path, *_: values[path]),
                      mock.patch.object(TOOL, "source_build_selection", return_value=selection),
                      mock.patch.object(TOOL, "observation_inventory", return_value=expected),
                      mock.patch.object(TOOL, "write_tree") as output):
                    with self.assertRaises(TOOL.Refused):
                        TOOL.preview_command(args)
                    output.assert_not_called()

            for missing in ("image-finalization.status", "android-helper-finalize-image.json", "distribution-final/MobileReleaseKit.dmg"):
                work, values, documents, expected, selection = self.preview_fixture(target)
                del values[work / missing]
                def read(path, *_):
                    if path not in values: raise FileNotFoundError("INERT absent required final image original")
                    return values[path]
                with (self.subTest(target=target, missing=missing), mock.patch.object(TOOL, "read", side_effect=read),
                      mock.patch.object(TOOL, "source_build_selection", return_value=selection),
                      mock.patch.object(TOOL, "observation_inventory", return_value=expected), mock.patch.object(TOOL, "write_tree") as output):
                    with self.assertRaises(FileNotFoundError):
                        TOOL.preview_command(SimpleNamespace(work=work, output=work / "preview", expected_source="a" * 40, target=target))
                    output.assert_not_called()  # Old distribution image was present; no fallback.

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
        self.assertIn("mobile-release-kit-macos26-${{ matrix.target }}-preview-", publish)
        evidence = workflow.split("        id: evidence\n", 1)[1]
        self.assertIn("desktop-macos-installed-${{ matrix.target }}-", evidence)
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
        self.assertIn('desktop/tools/macos_normal_ui_runner.py --target "$MRK_MACOS_TARGET" test-without-building', normal_test)
        self.assertIn('-destination "platform=macOS,arch=$MRK_MACOS_MACHINE"', normal_test)
        self.assertIn('value.get("target") != build_target', normal_result)
        self.assertIn('preview["platform"] != platforms[build_target]', normal_result)
        self.assertIn('"target": build_target, "platform": preview["platform"]', normal_result)
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
                         "Credential-free engineering fixtures do **not** satisfy", "Downloaded-image/Installer interaction and Gatekeeper qualification remain",
                         "producer.json", "producer.sig", "standalone package copied to writable Downloads is unsupported"):
            self.assertIn(required, guide)

        image_name = "Notarize, staple and verify only the final user image"
        image_step = workflow_step(workflow, image_name)
        self.assertIn("if: github.ref == 'refs/heads/verify/desktop-macos-preview'", image_step)
        self.assertIn('macos_android_helper_package.py finalize-image --target "$MRK_MACOS_TARGET"', image_step)
        self.assertLess(workflow.index("macos_android_helper_package.py package-install"), workflow.index("      - name: " + image_name + "\n"))
        self.assertLess(workflow.index("      - name: " + image_name + "\n"), workflow.index("stage_macos_installed.py preview"))
        for phrase in ("The original user DMG is retained unchanged", "no fallback", "Accepted notary result alone",
                       "scoped native verification/mount observations"):
            self.assertIn(phrase, guide)


if __name__ == "__main__":
    unittest.main()
