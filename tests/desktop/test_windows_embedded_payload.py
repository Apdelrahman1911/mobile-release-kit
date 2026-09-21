"""Focused inert Windows publisher DATA tests; never execute supplier bytes.

The synthetic .exe/.dll/.pyd/stdlib files are plain text, not a runtime. Pin
substitution below exists only in unittest patches, not the preparer's API.
Execute only after separate SOURCE/COMMAND acceptance.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SOURCE = Path(__file__).resolve().parents[2]


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, SOURCE / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


payload = load("desktop/tools/prepare_windows_embedded_payload.py", "windows_payload_data")
foundation = load("desktop/tools/ci_foundation.py", "windows_payload_ci_data")


def hosted_environment():
    sha = "b" * 40
    repository = "inert-owner/inert-repository"
    return {"GITHUB_SHA": sha, "GITHUB_REPOSITORY": repository, "GITHUB_RUN_ID": "123456", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REF": foundation.WINDOWS_PAYLOAD_REF, "GITHUB_WORKFLOW_SHA": sha,
            "GITHUB_WORKFLOW_REF": f"{repository}/{foundation.WINDOWS_PAYLOAD_WORKFLOW}@{foundation.WINDOWS_PAYLOAD_REF}",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_JOB": "windows-payload", "MRK_EXPECTED_SHA": sha,
            "MRK_DESKTOP_HOSTED_CHECKS": foundation.WINDOWS_PAYLOAD_SCOPE}


def fixture(root, *, underpth=None):
    source = root / "source"
    package = source / "src/mobile_release"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b'__version__ = "0.3.0"\n')
    (package / "_desktop_engine.py").write_bytes(b"# INERT core, never imported\n")
    desktop = source / "desktop"
    (desktop / "licenses").mkdir(parents=True)
    for name in payload.runtime_preparation.BOOTSTRAPS:
        (desktop / name).write_bytes(b"# INERT bootstrap, never executed\n")
    (desktop / "github-ca.pem").write_bytes(b"INERT CA INVENTORY DATA ONLY\n")
    notice = b"INERT NOTICE INVENTORY DATA ONLY; not real licensing acceptance\n"
    (source / payload.NOTICE_SOURCE).write_bytes(notice)
    files = {name: b"INERT supplier DATA: " + name.encode() for name, _, _ in payload.MEMBERS}
    files["python314._pth"] = payload.UNDERPTH if underpth is None else underpth
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            item = zipfile.ZipInfo(name)
            item.create_system = 0
            item.external_attr = (stat.S_IFREG | 0o600) << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(item, content)
    raw = data.getvalue()
    archive = root / payload.ZIP_NAME
    archive.write_bytes(raw)
    pins = tuple((name, len(content), hashlib.sha256(content).hexdigest()) for name, content in files.items())
    return source, archive, raw, notice, pins


def synthetic_pins(raw, notice, members):
    patches = ExitStack()
    for name, value in {"ZIP_BYTES": len(raw), "ZIP_SHA256": hashlib.sha256(raw).hexdigest(),
                        "NOTICE_BYTES": len(notice), "NOTICE_SHA256": hashlib.sha256(notice).hexdigest(),
                        "MEMBERS": members}.items():
        patches.enter_context(patch.object(payload, name, value))
    return patches


class WindowsEmbeddedPayloadDataTests(unittest.TestCase):
    def test_closed_actual_supplier_roster_keeps_all_native_and_notice_members(self):
        names = [row[0] for row in payload.MEMBERS]
        self.assertEqual(len(names), 37)
        self.assertEqual(len(set(names)), 37)
        self.assertEqual(sum(name.endswith((".exe", ".dll", ".pyd")) for name in names), 33)
        for name in ("python.exe", "pythonw.exe", "python3.dll", "python314.dll", "python.cat",
                     "libtommath.dll", "_zstd.pyd", "vcruntime140.dll", "vcruntime140_1.dll", "LICENSE.txt"):
            self.assertIn(name, names)
        self.assertEqual(payload.ZIP_BYTES, 12673227)
        self.assertEqual(payload.ZIP_SHA256, "d297e5ff019966817ad8502465176139f2d3d840fa4ed84b13bed399a6ab1f15")
        self.assertEqual(len(payload.UNDERPTH), 80)
        self.assertEqual(hashlib.sha256(payload.UNDERPTH).hexdigest(),
                         "2ed7ccda80e9e28ab5877902a9a325586c8a7b7b3e6731d944565bee082e216c")
        self.assertEqual(payload.TARGET, "x86_64-pc-windows-msvc")
        notices = payload.notice_bytes(SOURCE)
        self.assertEqual(payload.NOTICE_BYTES, 240822)
        self.assertEqual(payload.NOTICE_SHA256,
                         "6c814672403bec2064b22e54dbd028b055e0cacdc6837557a66cd5c0a04af360")
        self.assertEqual(len(notices), payload.NOTICE_BYTES)
        self.assertEqual(hashlib.sha256(notices).hexdigest(), payload.NOTICE_SHA256)

    def test_missing_notice_pins_refuse_before_archive_read_or_any_output(self):
        with tempfile.TemporaryDirectory(prefix="mrk-windows-payload-data-") as name:
            root = Path(name)
            with patch.object(payload, "NOTICE_SHA256", None), patch.object(payload, "archive_bytes") as read:
                with self.assertRaisesRegex(payload.PreparationError, "not admitted"):
                    payload.prepare(root / "absent-source", root / payload.ZIP_NAME, root / "runtime")
            read.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])

    def test_notice_content_and_whole_zip_pin_refuse_before_output(self):
        with tempfile.TemporaryDirectory(prefix="mrk-windows-payload-data-") as name:
            root = Path(name)
            source, archive, raw, notice, pins = fixture(root)
            with synthetic_pins(raw, notice, pins):
                (source / payload.NOTICE_SOURCE).write_bytes(notice + b"changed")
                with self.assertRaisesRegex(payload.PreparationError, "notice bytes differ"):
                    payload.prepare(source, archive, root / "runtime")
                self.assertFalse((root / "runtime").exists())
                (source / payload.NOTICE_SOURCE).write_bytes(notice)
                archive.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
                with self.assertRaisesRegex(payload.PreparationError, "whole-ZIP"):
                    payload.prepare(source, archive, root / "runtime")
                self.assertFalse((root / "runtime").exists())

    def test_inert_projection_uses_existing_preparer_and_preserves_every_byte(self):
        with tempfile.TemporaryDirectory(prefix="mrk-windows-payload-data-") as name:
            root = Path(name)
            source, archive, raw, notice, pins = fixture(root)
            runtime = root / "runtime"
            with synthetic_pins(raw, notice, pins):
                result = payload.prepare(source, archive, runtime)
                payload.check_supplier_copy(runtime / "python", notice)
                self.assertEqual(result["qualification"], "prepared-not-native-verified")
                manifest_bytes = (runtime / "manifest.json").read_bytes()
                manifest = json.loads(manifest_bytes)
                self.assertEqual(result["manifestSha256"], hashlib.sha256(manifest_bytes).hexdigest())
                self.assertEqual(manifest["target"], payload.TARGET)
                self.assertEqual(len(manifest["files"]), 46)  # 37 supplier + notice + 8 generated.
                for entry in manifest["files"]:
                    body = (runtime / entry["path"]).read_bytes()
                    self.assertEqual((len(body), hashlib.sha256(body).hexdigest()), (entry["size"], entry["sha256"]))
                for bootstrap in payload.runtime_preparation.BOOTSTRAPS:
                    self.assertEqual((runtime / bootstrap).read_bytes(), (source / "desktop" / bootstrap).read_bytes())
                with self.assertRaisesRegex(payload.PreparationError, "existing output"):
                    payload.prepare(source, archive, runtime)
                self.assertEqual((runtime / "manifest.json").read_bytes(), manifest_bytes)

    def test_extra_startup_files_and_modified_underpth_are_refused_not_repaired(self):
        with tempfile.TemporaryDirectory(prefix="mrk-windows-payload-data-") as name:
            root = Path(name)
            source, archive, raw, notice, pins = fixture(root)
            runtime = root / "runtime"
            with synthetic_pins(raw, notice, pins):
                payload.prepare(source, archive, runtime)
                for extra in ("pyvenv.cfg", "python._pth", "extra.pth", "sitecustomize.py", "usercustomize.py"):
                    path = runtime / "python" / extra
                    path.write_bytes(b"INERT refused extra")
                    with self.assertRaisesRegex(payload.PreparationError, "extra startup"):
                        payload.check_supplier_copy(runtime / "python", notice)
                    self.assertEqual(path.read_bytes(), b"INERT refused extra")
                    path.unlink()  # Only this DATA fixture, never publisher repair.
        with tempfile.TemporaryDirectory(prefix="mrk-windows-payload-data-") as name:
            root = Path(name)
            source, archive, raw, notice, pins = fixture(root, underpth=payload.UNDERPTH + b"import site\r\n")
            with synthetic_pins(raw, notice, pins):
                with self.assertRaisesRegex(payload.PreparationError, "startup policy"):
                    payload.prepare(source, archive, root / "runtime")
            self.assertTrue((root / "runtime/python/python.exe").is_file())
            self.assertFalse((root / "runtime/manifest.json").exists())

    def test_fixed_zip_roster_refuses_metadata_aliases_and_special_members(self):
        with tempfile.TemporaryDirectory(prefix="mrk-windows-payload-data-") as name:
            source, path, raw, notice, pins = fixture(Path(name))
            with synthetic_pins(raw, notice, pins), zipfile.ZipFile(io.BytesIO(raw)) as archive:
                entries = archive.infolist()
                original = entries[0].external_attr
                entries[0].external_attr = (stat.S_IFLNK | 0o777) << 16
                with self.assertRaisesRegex(payload.PreparationError, "metadata"):
                    payload.member_roster(archive)
                entries[0].external_attr = original
                entries[0].filename = "../outside"
                with self.assertRaisesRegex(payload.PreparationError, "member"):
                    payload.member_roster(archive)

    def test_copy_failure_closes_streams_and_preserves_inputs_and_partial_output(self):
        with tempfile.TemporaryDirectory(prefix="mrk-windows-payload-data-") as name:
            root = Path(name)
            source, archive, raw, notice, pins = fixture(root)
            runtime = root / "runtime"
            original_open = Path.open

            def refused_open(path, mode="r", *args, **kwargs):
                if path == runtime / "python/_ctypes.pyd" and mode == "xb":
                    raise OSError("INERT copy refusal")
                return original_open(path, mode, *args, **kwargs)

            with synthetic_pins(raw, notice, pins), patch.object(Path, "open", autospec=True, side_effect=refused_open):
                with self.assertRaisesRegex(OSError, "INERT copy refusal"):
                    payload.prepare(source, archive, runtime)
            self.assertEqual(archive.read_bytes(), raw)
            self.assertTrue((runtime / "python/LICENSE.txt").is_file())
            self.assertFalse((runtime / "manifest.json").exists())

    def test_ci_scope_is_closed_to_windows_payload_phases_and_platform(self):
        scope = foundation.WINDOWS_PAYLOAD_SCOPE
        allowed = {"prepare", "acquire", "compile", "windows-payload", "retain"}
        for phase in allowed:
            foundation.admit_phase(scope, phase)
        for phase in set(foundation.BOUNDARY_PHASES) - allowed | {"windows-snapshot", "github-tls", "environment-native"}:
            with self.assertRaises(foundation.CheckFailure):
                foundation.admit_phase(scope, phase)
        foundation.admit_platform(scope, "windows")
        for platform in ("linux", "macos"):
            with self.assertRaises(foundation.CheckFailure):
                foundation.admit_platform(scope, platform)

    def test_ci_binding_refuses_other_sources_workflows_events_and_retries(self):
        for event in ("workflow_dispatch", "push"):
            admitted = hosted_environment()
            source_field = "MRK_EXPECTED_SHA" if event == "workflow_dispatch" else "MRK_EVENT_AFTER"
            if event == "push":
                admitted.pop("MRK_EXPECTED_SHA")
                admitted.update(GITHUB_EVENT_NAME=event, MRK_EVENT_AFTER=admitted["GITHUB_SHA"])
            # The unused event-specific field is genuinely absent, not an
            # automatically populated second source approval.
            binding = foundation.windows_payload_binding(admitted)
            self.assertEqual(binding["sourceSha"], admitted["GITHUB_SHA"])
            self.assertEqual(binding["attempt"], "1")
            for key, wrong in (("GITHUB_SHA", "0" * 40), ("GITHUB_EVENT_NAME", "pull_request"),
                               ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_RUN_ID", "0"),
                               ("GITHUB_REPOSITORY", "invalid"), ("GITHUB_REF", "refs/heads/main"),
                               ("GITHUB_WORKFLOW_SHA", "c" * 40), ("GITHUB_WORKFLOW_REF", "other/workflow@ref"),
                               (source_field, "c" * 40), (source_field, "0" * 40), (source_field, ""),
                               ("GITHUB_JOB", "windows-snapshot"), ("MRK_DESKTOP_HOSTED_CHECKS", "passive-v1")):
                with self.subTest(event=event, key=key, wrong=wrong), self.assertRaises(foundation.CheckFailure):
                    foundation.windows_payload_binding({**admitted, key: wrong})
            missing = dict(admitted)
            missing.pop(source_field)
            with self.subTest(event=event, missing=source_field), self.assertRaises(foundation.CheckFailure):
                foundation.windows_payload_binding(missing)

    def test_ci_notice_gate_precedes_root_creation_and_any_tool(self):
        with tempfile.TemporaryDirectory(prefix="mrk-windows-payload-data-") as name:
            root = Path(name)
            source = root / "source"
            source.mkdir()
            environment = {**hosted_environment(), "GITHUB_WORKSPACE": str(source), "RUNNER_TEMP": str(root)}
            with patch.dict(foundation.os.environ, environment, clear=True), patch.object(foundation, "windows_payload_module", return_value=payload), \
                    patch.object(foundation, "run", side_effect=AssertionError("No tool may run before notice admission")), \
                    patch.object(payload, "NOTICE_BYTES", None), patch.object(payload, "NOTICE_SHA256", None):
                with self.assertRaisesRegex(payload.PreparationError, "not admitted"):
                    foundation.prepare_windows_payload("windows")
            self.assertEqual(list(root.iterdir()), [source])

    def test_prepared_ci_inventory_and_compile_anchors_refuse_missing_or_changed_binding(self):
        with tempfile.TemporaryDirectory(prefix="mrk-windows-payload-data-") as name:
            root = Path(name)
            source, archive, raw, notice, pins = fixture(root)
            with synthetic_pins(raw, notice, pins), patch.object(foundation, "windows_payload_module", return_value=payload), \
                    patch.object(foundation, "run", side_effect=AssertionError("DATA validation cannot execute tools")):
                prepared = payload.prepare(source, archive, root / "runtime")
                foundation.write_json(root / "windows-prepared.json", prepared)
                context = {"root": str(root), "source": str(source), "coreFiles": foundation.fixed_file_inventory(
                    source / "src", ("mobile_release/_desktop_engine.py",))}
                actual, inventory = foundation.windows_payload_inventory(context)
                self.assertEqual(actual, prepared)
                self.assertEqual(len(inventory), 47)
                self.assertEqual(foundation.windows_payload_compile_anchors(prepared), {
                    "MRK_BUNDLED_RUNTIME_MANIFEST_SHA256": prepared["manifestSha256"],
                    "MRK_BUNDLED_PROTOCOL_SHA256": prepared["protocolSha256"]})
                for key in ("manifestSha256", "protocolSha256"):
                    for bad in (None, "", "f" * 63, True):
                        with self.subTest(key=key, bad=bad), self.assertRaises(foundation.CheckFailure):
                            foundation.windows_payload_compile_anchors({**prepared, key: bad})
                changed = {**prepared, "manifestSha256": "f" * 64}
                (root / "windows-prepared.json").write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaisesRegex(foundation.CheckFailure, "manifest/core/protocol"):
                    foundation.windows_payload_inventory(context)
                self.assertEqual((root / "runtime/python/python.exe").read_bytes(), b"INERT supplier DATA: python.exe")

    def test_failed_phase_claim_cannot_be_replayed_or_used_to_reach_compile(self):
        with tempfile.TemporaryDirectory(prefix="mrk-windows-payload-data-") as name:
            root = Path(name)
            context = {"root": str(root), "sourceSha": "b" * 40, "sourceTree": "c" * 40,
                       "workflowSha256": "d" * 64, "runId": "123456", "attempt": "1"}
            with patch.object(foundation, "run", side_effect=AssertionError("Claim checks cannot execute a tool")):
                foundation.windows_payload_claim(context, "acquire")
                original = (root / "acquire-started.json").read_bytes()
                self.assertEqual(json.loads(original)["status"], "started")
                with self.assertRaises(foundation.CheckFailure):
                    foundation.windows_payload_claim(context, "acquire")
                with self.assertRaises(OSError):
                    foundation.windows_payload_claim(context, "compile")
                self.assertEqual((root / "acquire-started.json").read_bytes(), original)
                self.assertFalse((root / "compile-started.json").exists())
