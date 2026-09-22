"""Focused inert Windows publisher DATA tests; never execute supplier bytes.

The synthetic .exe/.dll/.pyd/stdlib files are plain text, not a runtime. Pin
substitution below exists only in unittest patches, not the preparer's API.
The accepted public CA is opaque DATA, never a synthetic or installed trust store.
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
    (desktop / "cpython-source-inputs").mkdir()
    (source / payload.GITHUB_CA_SOURCE).write_bytes(payload.github_ca_bytes(SOURCE))
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
    values = {"ZIP_BYTES": len(raw), "ZIP_SHA256": hashlib.sha256(raw).hexdigest(), "MEMBERS": members}
    if notice is not None:  # None keeps the actual reviewed notice pins unchanged.
        values.update(NOTICE_BYTES=len(notice), NOTICE_SHA256=hashlib.sha256(notice).hexdigest())
    for name, value in values.items():
        patches.enter_context(patch.object(payload, name, value))
    return patches


def tree_facts(root):
    """Only the disposable DATA fixture; do not follow or print link targets."""
    result = {}
    for path in sorted(root.rglob("*")):
        state = path.lstat()
        if stat.S_ISREG(state.st_mode):
            data = path.read_bytes()
        elif stat.S_ISLNK(state.st_mode):
            data = str(path.readlink()).encode("utf-8")
        else:
            data = b""
        result[path.relative_to(root).as_posix()] = (
            stat.S_IFMT(state.st_mode), stat.S_IMODE(state.st_mode), state.st_nlink,
            len(data), hashlib.sha256(data).hexdigest())
    return result


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
        self.assertEqual(payload.GITHUB_CA_SOURCE, "desktop/cpython-source-inputs/github-ca.pem")
        self.assertEqual(payload.GITHUB_CA_BYTES, 240216)
        self.assertEqual(payload.GITHUB_CA_SHA256,
                         "9cc2a774b5198dcff14d9be1e66091f538975d867ce029a96bce15a55dfd730f")
        ca = payload.github_ca_bytes(SOURCE)
        self.assertEqual((len(ca), hashlib.sha256(ca).hexdigest()),
                         (payload.GITHUB_CA_BYTES, payload.GITHUB_CA_SHA256))
        licence = payload.runtime_preparation.read_checked(
            SOURCE / "desktop/cpython-source-inputs/conventional-review/notices/LICENSE.certifi", limit=989)
        self.assertEqual((len(licence), hashlib.sha256(licence).hexdigest()),
                         (989, "e93716da6b9c0d5a4a1df60fe695b370f0695603d21f6f83f053e42cfc10caf7"))
        self.assertEqual(notices.count(licence), 1)
        self.assertEqual(payload.SOURCE_PROJECTION_NAME, "fullwalk-source")

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
                self.assertFalse((root / payload.SOURCE_PROJECTION_NAME).exists())
                (source / payload.NOTICE_SOURCE).write_bytes(notice)
                archive.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
                with self.assertRaisesRegex(payload.PreparationError, "whole-ZIP"):
                    payload.prepare(source, archive, root / "runtime")
                self.assertFalse((root / "runtime").exists())
                self.assertFalse((root / payload.SOURCE_PROJECTION_NAME).exists())

    def test_inert_projection_uses_existing_preparer_and_preserves_every_byte(self):
        with tempfile.TemporaryDirectory(prefix="mrk-windows-payload-data-") as name:
            root = Path(name)
            source, archive, raw, notice, pins = fixture(root)
            runtime, projection = root / "runtime", root / payload.SOURCE_PROJECTION_NAME
            original_source = tree_facts(source)
            with synthetic_pins(raw, notice, pins), patch.object(
                    payload.runtime_preparation, "prepare", wraps=payload.runtime_preparation.prepare) as common:
                result = payload.prepare(source, archive, runtime)
                common.assert_called_once_with(projection, runtime, payload.TARGET)
                payload.check_supplier_copy(runtime / "python", notice)
                self.assertEqual(result["qualification"], "prepared-not-native-verified")
                manifest_bytes = (runtime / "manifest.json").read_bytes()
                manifest = json.loads(manifest_bytes)
                self.assertEqual(result["manifestSha256"], hashlib.sha256(manifest_bytes).hexdigest())
                self.assertEqual(manifest["target"], payload.TARGET)
                self.assertEqual(len(manifest["files"]), 46)  # 37 supplier + notice + 8 generated.
                self.assertEqual(len(payload.runtime_preparation.files(runtime)), 47)
                for entry in manifest["files"]:
                    body = (runtime / entry["path"]).read_bytes()
                    self.assertEqual((len(body), hashlib.sha256(body).hexdigest()), (entry["size"], entry["sha256"]))
                expected = {
                    path.relative_to(source).as_posix(): path.read_bytes()
                    for path in payload.runtime_preparation.files(source / "src/mobile_release")}
                for bootstrap in payload.runtime_preparation.BOOTSTRAPS:
                    body = (source / "desktop" / bootstrap).read_bytes()
                    self.assertEqual((runtime / bootstrap).read_bytes(), body)
                    expected["desktop/" + bootstrap] = body
                expected["desktop/github-ca.pem"] = (source / payload.GITHUB_CA_SOURCE).read_bytes()
                self.assertEqual((runtime / "github-ca.pem").read_bytes(), expected["desktop/github-ca.pem"])
                self.assertEqual(
                    [path.relative_to(projection).as_posix() for path in payload.runtime_preparation.files(projection)],
                    sorted(expected))
                for relative, body in expected.items():
                    self.assertEqual((projection / relative).read_bytes(), body)
                self.assertEqual(tree_facts(source), original_source)
                self.assertFalse((source / "desktop/github-ca.pem").exists())
                with self.assertRaisesRegex(payload.PreparationError, "existing output"):
                    payload.prepare(source, archive, runtime)
                common.assert_called_once_with(projection, runtime, payload.TARGET)
                self.assertEqual((runtime / "manifest.json").read_bytes(), manifest_bytes)
                self.assertEqual(archive.read_bytes(), raw)

    def test_current_checkout_source_projection_does_not_modify_inputs(self):
        # Real current checkout layout/core as opaque bytes; only supplier pins
        # change. No core import, supplier execution, acquisition or Git command.
        with tempfile.TemporaryDirectory(prefix="mrk-windows-payload-data-") as name:
            root = Path(name)
            _, archive, raw, _, pins = fixture(root)
            runtime, projection = root / "runtime", root / payload.SOURCE_PROJECTION_NAME
            package = SOURCE / "src/mobile_release"
            core_paths = payload.runtime_preparation.files(package)
            paths = core_paths + [SOURCE / "desktop" / name for name in payload.runtime_preparation.BOOTSTRAPS]
            paths += [SOURCE / payload.GITHUB_CA_SOURCE, SOURCE / payload.NOTICE_SOURCE]
            originals = {path.relative_to(SOURCE).as_posix(): payload.runtime_preparation.read_checked(
                path, limit=payload.runtime_preparation.MAX_CORE_BYTES) for path in paths}
            shadow = SOURCE / "desktop/github-ca.pem"
            self.assertFalse(shadow.exists() or shadow.is_symlink())
            with synthetic_pins(raw, None, pins):
                result = payload.prepare(SOURCE, archive, runtime)
            self.assertEqual(result["qualification"], "prepared-not-native-verified")
            self.assertEqual(payload.runtime_preparation.files(package), core_paths)
            for relative, body in originals.items():
                self.assertEqual(payload.runtime_preparation.read_checked(
                    SOURCE / relative, limit=len(body)), body)
            self.assertFalse(shadow.exists() or shadow.is_symlink())
            expected = {relative: body for relative, body in originals.items()
                        if relative not in {payload.GITHUB_CA_SOURCE, payload.NOTICE_SOURCE}}
            expected["desktop/github-ca.pem"] = originals[payload.GITHUB_CA_SOURCE]
            self.assertEqual(
                [path.relative_to(projection).as_posix() for path in payload.runtime_preparation.files(projection)],
                sorted(expected))
            for relative, body in expected.items():
                self.assertEqual((projection / relative).read_bytes(), body)
            self.assertEqual((runtime / "github-ca.pem").read_bytes(), originals[payload.GITHUB_CA_SOURCE])
            self.assertEqual((runtime / "python" / payload.NOTICE_NAME).read_bytes(), originals[payload.NOTICE_SOURCE])
            with zipfile.ZipFile(runtime / "core.zip") as core:
                names = [path.relative_to(SOURCE / "src").as_posix() for path in core_paths]
                self.assertEqual(core.namelist(), names)
                for member in names:
                    self.assertEqual(core.read(member), originals["src/" + member])
            self.assertEqual(len(payload.runtime_preparation.files(runtime)), 47)
            self.assertEqual(archive.read_bytes(), raw)

    def test_fixed_ca_controls_admission_refuses_before_output(self):
        for case in ("missing", "empty", "off-pin", "oversize", "directory", "symlink", "hardlink", "shadow-only"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="mrk-windows-payload-data-") as name:
                root = Path(name)
                source, archive, raw, notice, pins = fixture(root)
                ca = source / payload.GITHUB_CA_SOURCE
                original_ca = ca.read_bytes()
                if case == "missing":
                    ca.unlink()
                elif case == "empty":
                    ca.write_bytes(b"")
                elif case == "off-pin":
                    ca.write_bytes(bytes([original_ca[0] ^ 1]) + original_ca[1:])
                elif case == "oversize":
                    ca.write_bytes(b"x" * (payload.runtime_preparation.MAX_GITHUB_CA_BYTES + 1))
                elif case == "directory":
                    ca.unlink()
                    ca.mkdir()
                elif case in {"symlink", "hardlink"}:
                    target = root / "ca-original.pem"
                    ca.rename(target)
                    if case == "symlink":
                        ca.symlink_to(target)
                    else:
                        ca.hardlink_to(target)
                else:
                    ca.rename(source / "desktop/github-ca.pem")
                original_source = tree_facts(source)
                with synthetic_pins(raw, notice, pins), patch.object(payload, "archive_bytes") as read, patch.object(
                        payload.runtime_preparation, "prepare") as common:
                    with self.assertRaises((OSError, payload.PreparationError)):
                        payload.prepare(source, archive, root / "runtime")
                    read.assert_not_called()
                    common.assert_not_called()
                self.assertFalse((root / "runtime").exists())
                self.assertFalse((root / payload.SOURCE_PROJECTION_NAME).exists())
                self.assertEqual(tree_facts(source), original_source)
                self.assertEqual(archive.read_bytes(), raw)

    def test_source_projection_collision_overlap_and_copy_failure_preserve_inputs(self):
        cases = [(destination, kind) for destination in ("runtime", "projection")
                 for kind in ("file", "empty-directory", "directory", "symlink", "dangling")]
        cases += [("source", "overlap"), ("outputs", "equality"), ("projection", "copy-failure")]
        for destination, kind in cases:
            with self.subTest(destination=destination, kind=kind), tempfile.TemporaryDirectory(
                    prefix="mrk-windows-payload-data-") as name:
                root = Path(name)
                source, archive, raw, notice, pins = fixture(root)
                runtime = source / "runtime" if kind == "overlap" else root / "runtime"
                if kind == "equality":
                    runtime = root / payload.SOURCE_PROJECTION_NAME
                projection = runtime.parent / payload.SOURCE_PROJECTION_NAME
                occupied = runtime if destination == "runtime" else projection
                if kind == "file":
                    occupied.write_bytes(b"INERT occupied output\n")
                elif kind in {"empty-directory", "directory"}:
                    occupied.mkdir()
                    if kind == "directory":
                        (occupied / "sentinel.txt").write_bytes(b"INERT retained output\n")
                elif kind in {"symlink", "dangling"}:
                    occupied.symlink_to(source if kind == "symlink" else root / "absent-target",
                                        target_is_directory=True)
                original_source, original_tree = tree_facts(source), tree_facts(root)
                original_open, streams = Path.open, []

                def refused_open(path, mode="r", *args, **kwargs):
                    if kind == "copy-failure" and path == projection / "src/mobile_release/_desktop_engine.py" and mode == "xb":
                        raise OSError("INERT source projection copy refusal")
                    stream = original_open(path, mode, *args, **kwargs)
                    if mode == "xb":
                        streams.append(stream)
                    return stream

                with synthetic_pins(raw, notice, pins), patch.object(
                        Path, "open", autospec=True, side_effect=refused_open), patch.object(
                        payload.runtime_preparation, "prepare") as common:
                    with self.assertRaises((OSError, payload.PreparationError)):
                        payload.prepare(source, archive, runtime)
                    common.assert_not_called()
                self.assertEqual(tree_facts(source), original_source)
                self.assertEqual(archive.read_bytes(), raw)
                self.assertTrue(all(stream.closed for stream in streams))
                if kind == "copy-failure":
                    self.assertTrue(streams)
                    self.assertTrue((projection / "src/mobile_release/__init__.py").is_file())
                    self.assertEqual((projection / "desktop/github-ca.pem").read_bytes(),
                                     (source / payload.GITHUB_CA_SOURCE).read_bytes())
                    self.assertFalse(runtime.exists())
                    self.assertFalse((runtime / "manifest.json").exists())
                else:
                    self.assertEqual(streams, [])
                    self.assertEqual(tree_facts(root), original_tree)

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

