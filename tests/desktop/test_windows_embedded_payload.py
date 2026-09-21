"""Focused inert Windows publisher DATA tests; never execute supplier bytes.

The synthetic .exe/.dll/.pyd/stdlib files are plain text, not a runtime. Pin
substitution below exists only in unittest patches, not the preparer's API.
Execute only after separate SOURCE/COMMAND acceptance.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PureWindowsPath
import re
import stat
import sys
import tempfile
from types import ModuleType, SimpleNamespace
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
    def test_native_origin_rules_bind_expat_and_system_images(self):
        # Select the actual pure origin/required-image rules and diagnostics,
        # not the whole native module or copied predicates. PureWindowsPath is
        # lexical only; no supplier import, native API or sys.modules mutation.
        source = SOURCE / "tests/native_desktop_payload_windows.py"
        with source.open("rb") as stream:
            raw = stream.read(65537)
        self.assertLessEqual(len(raw), 65536)
        tree = ast.parse(raw, filename=str(source))
        selected = []
        for name in ("SCOPE", "STAGE", "PATH_CHARS", "PAYLOAD_IMAGES", "EXTENSIONS",
                     "REQUIRED_PAYLOAD_IMAGES", "SYSTEM_IMAGES"):
            matches = [node for node in tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
            self.assertEqual(len(matches), 1)
            self.assertEqual(len(matches[0].targets), 1)
            value = matches[0].value
            if name in {"SCOPE", "STAGE", "PATH_CHARS"}:
                self.assertIsInstance(value, ast.Constant)
                self.assertIs(type(value.value), int if name == "PATH_CHARS" else str)
            elif name == "EXTENSIONS":
                self.assertIsInstance(value, ast.Tuple)
                self.assertTrue(all(isinstance(item, ast.Constant) and type(item.value) is str
                                    for item in value.elts))
            else:
                self.assertIsInstance(value, ast.Call)
                self.assertIsInstance(value.func, ast.Name)
                self.assertEqual(value.func.id, "frozenset")
                self.assertEqual(len(value.args), 1)
                self.assertEqual(value.keywords, [])
                self.assertIsInstance(value.args[0], ast.Set)
                items = value.args[0].elts
                if name == "REQUIRED_PAYLOAD_IMAGES":
                    self.assertIsInstance(items[-1], ast.Starred)
                    expansion = ast.parse('(name + ".pyd" for name in EXTENSIONS)', mode="eval").body
                    self.assertEqual(ast.dump(items[-1].value), ast.dump(expansion))
                    items = items[:-1]
                self.assertTrue(all(isinstance(item, ast.Constant) and type(item.value) is str
                                    for item in items))
            selected.append(matches[0])
        for name, kind in (("ProbeFailure", ast.ClassDef), ("require", ast.FunctionDef),
                           ("failure_diagnostic", ast.FunctionDef), ("canonical", ast.FunctionDef),
                           ("require_loaded_payload_images", ast.FunctionDef),
                           ("path_key", ast.FunctionDef), ("require_imported_module_origins", ast.FunctionDef),
                           ("require_system_image_origin", ast.FunctionDef)):
            matches = [node for node in tree.body if getattr(node, "name", None) == name]
            self.assertEqual(len(matches), 1)
            self.assertIsInstance(matches[0], kind)
            self.assertEqual(matches[0].decorator_list, [])
            selected.append(matches[0])
        namespace = {"re": re, "sys": sys, "json": json, "Path": PureWindowsPath}
        exec(compile(ast.Module(body=selected, type_ignores=[]),
                     "<windows-probe-origin-rules-data>", "exec", dont_inherit=True), namespace)
        check, failure = namespace["require_imported_module_origins"], namespace["ProbeFailure"]
        runtime = PureWindowsPath("R:/mrk-data/runtime")
        python, core = runtime / "python", runtime / "core.zip"
        stdlib = python / "python314.zip"

        def loaded(name, origin, archive=None):
            module = ModuleType(name)
            module.__spec__ = SimpleNamespace(name=name, origin=None if origin is None else str(origin),
                                             loader=SimpleNamespace(archive=None if archive is None else str(archive)))
            return module

        def fixture_modules():
            producer = loaded("pyexpat", python / "pyexpat.pyd")
            wrapper = loaded("xml.parsers.expat", stdlib / "xml/parsers/expat.pyc", stdlib)
            modules = {"pyexpat": producer, "xml.parsers.expat": wrapper,
                       "sys": loaded("sys", "built-in"), "_frozen_importlib": loaded("_frozen_importlib", "frozen"),
                       "mobile_release": loaded("mobile_release", core / "mobile_release/__init__.py", core),
                       "json": loaded("json", stdlib / "json/__init__.pyc", stdlib),
                       "_ssl": loaded("_ssl", python / "_ssl.pyd"),
                       "__main__": ModuleType("__main__"), "inert_none_sentinel": None}
            for suffix in ("errors", "model"):
                child = ModuleType("pyexpat." + suffix)
                setattr(producer, suffix, child)
                setattr(wrapper, suffix, child)
                modules["pyexpat." + suffix] = modules["xml.parsers.expat." + suffix] = child
            return modules

        def replace_support(modules, replacement):
            for parent in ("pyexpat", "xml.parsers.expat"):
                setattr(modules[parent], "errors", replacement)
                modules[parent + ".errors"] = replacement

        original = fixture_modules()
        snapshot = dict(original)
        attributes = {name: vars(module).copy() for name, module in original.items() if module is not None}
        self.assertIsNone(check(original, core, stdlib, python))
        self.assertEqual(original, snapshot)
        for name, expected in attributes.items():
            self.assertEqual(vars(original[name]), expected)
        # Parent validation must not depend on registry order or path spelling.
        reordered = {name: value for name, value in original.items() if name not in {"pyexpat", "xml.parsers.expat"}}
        reordered.update({name: original[name] for name in ("pyexpat", "xml.parsers.expat")})
        reordered["pyexpat"].__spec__.origin = str(python / "pyexpat.pyd").swapcase().replace("\\", "/")
        self.assertIsNone(check(reordered, core, stdlib, python))
        at_bound = fixture_modules()
        at_bound.update(("inert_none_" + str(index), None) for index in range(2048 - len(at_bound)))
        self.assertIsNone(check(at_bound, core, stdlib, python))
        for invalid in ([], dict(at_bound, one_extra=None)):
            with self.subTest(bound=type(invalid).__name__), self.assertRaises(failure) as raised:
                check(invalid, core, stdlib, python)
            self.assertEqual((raised.exception.code, raised.exception.module), ("python_module_bound", None))

        mutations = [
            ("missing producer", lambda m: m.pop("pyexpat"), "python_expat_parent_origin", "pyexpat"),
            ("missing wrapper", lambda m: m.pop("xml.parsers.expat"), "python_expat_parent_origin", "xml.parsers.expat"),
            ("non-module producer", lambda m: m.__setitem__("pyexpat", SimpleNamespace(**vars(m["pyexpat"]))),
             "python_expat_parent_origin", "pyexpat"),
            ("non-module wrapper", lambda m: m.__setitem__("xml.parsers.expat", SimpleNamespace(**vars(m["xml.parsers.expat"]))),
             "python_expat_parent_origin", "xml.parsers.expat"),
            ("missing producer name", lambda m: delattr(m["pyexpat"], "__name__"),
             "python_expat_parent_origin", "pyexpat"),
            ("producer path", lambda m: setattr(m["pyexpat"].__spec__, "origin", "R:/outside/pyexpat.pyd"),
             "python_expat_parent_origin", "pyexpat"),
            ("producer spec name", lambda m: setattr(m["pyexpat"].__spec__, "name", "other"),
             "python_expat_parent_origin", "pyexpat"),
            ("wrapper core loader", lambda m: setattr(m["xml.parsers.expat"].__spec__.loader, "archive", str(core)),
             "python_expat_parent_origin", "xml.parsers.expat"),
            ("wrapper core origin", lambda m: m.__setitem__("xml.parsers.expat",
                                                         loaded("xml.parsers.expat", core / "xml/parsers/expat.pyc", core)),
             "python_expat_parent_origin", "xml.parsers.expat"),
            ("wrapper origin", lambda m: setattr(m["xml.parsers.expat"].__spec__, "origin", "R:/outside/expat.pyc"),
             "python_expat_parent_origin", "xml.parsers.expat"),
            ("producer attachment", lambda m: setattr(m["pyexpat"], "errors", ModuleType("pyexpat.errors")),
             "python_expat_support_identity", "pyexpat.errors"),
            ("wrapper attachment", lambda m: setattr(m["xml.parsers.expat"], "errors", ModuleType("pyexpat.errors")),
             "python_expat_support_identity", "pyexpat.errors"),
            ("same-named replacement", lambda m: m.__setitem__("pyexpat.errors", ModuleType("pyexpat.errors")),
             "python_expat_support_identity", "pyexpat.errors"),
            ("non-module support", lambda m: replace_support(m, SimpleNamespace(**vars(m["pyexpat.errors"]))),
             "python_expat_support_identity", "pyexpat.errors"),
            ("canonical name", lambda m: setattr(m["pyexpat.errors"], "__name__", "other"),
             "python_expat_support_metadata", "pyexpat.errors"),
            ("missing spec field", lambda m: delattr(m["pyexpat.errors"], "__spec__"),
             "python_expat_support_metadata", "pyexpat.errors"),
            ("fabricated spec", lambda m: setattr(m["pyexpat.errors"], "__spec__", SimpleNamespace(origin=None)),
             "python_expat_support_metadata", "pyexpat.errors"),
            ("fabricated loader", lambda m: setattr(m["pyexpat.errors"], "__loader__", object()),
             "python_expat_support_metadata", "pyexpat.errors"),
            ("fabricated package", lambda m: setattr(m["pyexpat.errors"], "__package__", "pyexpat"),
             "python_expat_support_metadata", "pyexpat.errors"),
            ("fabricated file", lambda m: setattr(m["pyexpat.errors"], "__file__", None),
             "python_expat_support_metadata", "pyexpat.errors"),
            ("fabricated path", lambda m: setattr(m["pyexpat.errors"], "__path__", []),
             "python_expat_support_metadata", "pyexpat.errors"),
            ("extra alias", lambda m: m.__setitem__("unknown.alias", m["pyexpat.errors"]),
             "python_module_spec_missing", None),
            ("unknown no-spec", lambda m: m.__setitem__("unknown.module", ModuleType("unknown.module")),
             "python_module_spec_missing", None),
            ("unknown missing origin", lambda m: m.__setitem__("unknown.origin", loaded("unknown.origin", None)),
             "python_module_origin_missing", None),
            ("core package from stdlib", lambda m: m.__setitem__("mobile_release",
                                                              loaded("mobile_release", stdlib / "mobile_release/__init__.py", stdlib)),
             "core_import_origin", None),
            ("extension outside", lambda m: setattr(m["_ssl"].__spec__, "origin", "R:/outside/_ssl.pyd"),
             "python_extension_origin", "_ssl.pyd"),
        ]
        for name in ("pyexpat.errors", "pyexpat.model", "xml.parsers.expat.errors", "xml.parsers.expat.model"):
            canonical = "pyexpat." + name.rsplit(".", 1)[1]
            mutations.append(("missing " + name, lambda m, name=name: m.pop(name),
                              "python_expat_support_identity", canonical))
            mutations.append(("None " + name, lambda m, name=name: m.__setitem__(name, None),
                              "python_expat_support_identity", canonical))
        for label, change, code, module in mutations:
            with self.subTest(refusal=label):
                values = fixture_modules()
                change(values)
                with self.assertRaises(failure) as raised:
                    check(values, core, stdlib, python)
                self.assertEqual((raised.exception.code, raised.exception.module), (code, module))
        for origin in ([], {}, 7, False):
            with self.subTest(origin_type=type(origin).__name__):
                values = fixture_modules()
                values["json"].__spec__.origin = origin
                with self.assertRaises(failure) as raised:
                    check(values, core, stdlib, python)
                self.assertEqual((raised.exception.code, raised.exception.module), ("python_module_origin_type", None))
        values = fixture_modules()
        namespace_module = loaded("unknown.namespace", None)
        namespace_module.__spec__.submodule_search_locations = [str(python / "unknown")]
        values["unknown.namespace"] = namespace_module
        with self.assertRaises(failure) as raised:
            check(values, core, stdlib, python)
        self.assertEqual((raised.exception.code, raised.exception.module), ("python_module_origin_missing", None))
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        origin_calls = [index for index, node in enumerate(main.body) if isinstance(node, ast.Expr)
                        and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                        and node.value.func.id == "imported_origins"]
        self.assertEqual(len(origin_calls), 1)
        stage = main.body[origin_calls[0] - 1]
        self.assertIsInstance(stage, ast.Assign)
        self.assertEqual([target.id for target in stage.targets], ["STAGE"])
        self.assertIsInstance(stage.value, ast.Constant)
        self.assertEqual(stage.value.value, "import-origins")

        check_system = namespace["require_system_image_origin"]
        system_directory = "C:/Windows/System32"
        for path in ("C:/Windows/System32/imm32.dll", r"c:\WINDOWS\system32\IMM32.DLL",
                     "C:/Windows/System32/kernel32.dll", r"c:\windows\SYSTEM32\KERNEL32.DLL"):
            with self.subTest(system_image=path):
                self.assertIsNone(check_system(path, system_directory))
        self.assertIsNone(check_system("R:/inert-windows/System32/imm32.dll", "R:/inert-windows/System32"))
        refusals = (
            ("C:/Windows/System32/unknown.dll", "system_image_unlisted", "unknown.dll"),
            ("C:/Windows/System32/imm32-lookalike.dll", "system_image_unlisted", "imm32-lookalike.dll"),
            ("C:/Windows/System32/imm32 copy.dll", "system_image_unlisted", None),
            ("C:/outside/imm32.dll", "system_image_origin", "imm32.dll"),
            ("R:/Windows/System32/imm32.dll", "system_image_origin", "imm32.dll"),
            ("C:/Windows/SysWOW64/IMM32.DLL", "system_image_origin", "imm32.dll"),
            ("C:/Windows/System32-lookalike/imm32.dll", "system_image_origin", "imm32.dll"),
            ("C:/outside/KERNEL32.DLL", "system_image_origin", "kernel32.dll"),
        )
        for path, code, module in refusals:
            with self.subTest(system_refusal=path):
                with self.assertRaises(failure) as raised:
                    check_system(path, system_directory)
                self.assertEqual((raised.exception.code, raised.exception.module), (code, module))

        required, allowed = namespace["REQUIRED_PAYLOAD_IMAGES"], namespace["PAYLOAD_IMAGES"]
        self.assertEqual(required, frozenset({
            "_bz2.pyd", "_ctypes.pyd", "_decimal.pyd", "_elementtree.pyd", "_hashlib.pyd", "_lzma.pyd",
            "_socket.pyd", "_sqlite3.pyd", "_ssl.pyd", "_uuid.pyd", "_zoneinfo.pyd", "_zstd.pyd",
            "libcrypto-3.dll", "libffi-8.dll", "libssl-3.dll", "pyexpat.pyd", "python.exe",
            "python314.dll", "select.pyd", "sqlite3.dll", "unicodedata.pyd", "vcruntime140.dll",
        }))
        self.assertEqual(required, {"python.exe", "python314.dll", "vcruntime140.dll", "libffi-8.dll",
                                   "libcrypto-3.dll", "libssl-3.dll", "sqlite3.dll",
                                   *(name + ".pyd" for name in namespace["EXTENSIONS"])})
        self.assertEqual((len(required), len(allowed), len(namespace["EXTENSIONS"])), (22, 33, 15))
        self.assertLess(required, allowed)
        self.assertNotIn("vcruntime140_1.dll", required)
        self.assertIn("vcruntime140_1.dll", allowed)
        check_required = namespace["require_loaded_payload_images"]
        for seen in (set(required), set(allowed)):
            original = seen.copy()
            self.assertIsNone(check_required(seen))
            self.assertEqual(seen, original)

        namespace["STAGE"] = "loaded-images"
        diagnostic = namespace["failure_diagnostic"]
        envelope = {"scope": namespace["SCOPE"], "status": "failed", "stage": "loaded-images"}
        missing_cases = [(name,) for name in sorted(required)]
        missing_cases.extend([("_ssl.pyd", "python.exe", "libffi-8.dll"), tuple(sorted(required))])
        for missing in missing_cases:
            for reverse in (False, True):
                with self.subTest(missing_images=missing, reverse=reverse):
                    # This helper cannot let extras satisfy required names. The
                    # native loop still rejects unlisted/wrong-origin images first.
                    values = required - set(missing) | {"vcruntime140_1.dll", "unknown.dll", "R:/inert/private.dll"}
                    seen = set(sorted(values, reverse=reverse))
                    original = seen.copy()
                    with self.assertRaises(failure) as raised:
                        check_required(seen)
                    error = raised.exception
                    self.assertEqual((error.code, error.module), ("required_images_missing", None))
                    self.assertEqual(error.missing_images, tuple(sorted(missing)))
                    record = diagnostic(error)
                    self.assertEqual(record, {**envelope, "code": "required_images_missing", "module": None,
                                              "missingImages": sorted(missing)})
                    raw = namespace["canonical"](record) + b"\n"
                    self.assertEqual(json.loads(raw), record)
                    self.assertLess(len(raw), 1024)
                    if len(missing) == 22:
                        self.assertEqual(len(raw), 475)
                    self.assertEqual(seen, original)
        for error, code, module in (
            (failure("system_image_origin", "imm32.dll", missing_images=("python.exe",)),
             "system_image_origin", "imm32.dll"),
            (failure("system_image_unlisted", "R:/inert/private.dll"), "system_image_unlisted", None),
            (ValueError("INERT exception text must not be emitted"), "probe_exception", None),
        ):
            self.assertEqual(diagnostic(error), {**envelope, "code": code, "module": module})
        # Only bounded literal required names may be retained as missing detail.
        for details in (None, [], "python.exe", ("unknown.dll",), ("python.exe", []), ("python.exe",) * 23):
            error = failure("required_images_missing", missing_images=details)
            self.assertEqual(error.missing_images, ())
            self.assertNotIn("missingImages", diagnostic(error))
        error = failure("required_images_missing", missing_images=("python.exe", "_ssl.pyd", "python.exe"))
        self.assertEqual(diagnostic(error)["missingImages"], ["_ssl.pyd", "python.exe"])

    def test_native_dependency_versions_use_exact_cpython_layout(self):
        # Read the native probe only as bounded DATA. Never import or execute
        # its module, behavior(), main(), supplier code or native API calls.
        source = SOURCE / "tests/native_desktop_payload_windows.py"
        with source.open("rb") as stream:
            raw = stream.read(65537)
        self.assertLessEqual(len(raw), 65536)
        tree = ast.parse(raw, filename=str(source))
        selected = []
        for name, kind in (("ProbeFailure", ast.ClassDef), ("require", ast.FunctionDef),
                           ("require_dependency_versions", ast.FunctionDef)):
            matches = [node for node in tree.body if getattr(node, "name", None) == name]
            self.assertEqual(len(matches), 1)
            self.assertIsInstance(matches[0], kind)
            self.assertEqual(matches[0].decorator_list, [])
            selected.append(matches[0])
        namespace = {"re": re}
        exec(compile(ast.Module(body=selected, type_ignores=[]),
                     "<windows-probe-dependency-version-data>", "exec", dont_inherit=True), namespace)
        check = namespace["require_dependency_versions"]
        failure = namespace["ProbeFailure"]
        expected = (3, 5, 0, 7, 0)
        for sqlite in ("", "3.51.1", "x" * 32):
            with self.subTest(accepted_sqlite_length=len(sqlite)):
                self.assertIsNone(check(expected, sqlite))
        wrong_versions = [None, list(expected), (3, 5, 7), expected + (0,),
                          (3, 5, 0, 6, 0), (3, 5, 0, 7, 15), (3, 5, False, 7, 0)]
        wrong_versions.extend(expected[:index] + (float(value),) + expected[index + 1:]
                              for index, value in enumerate(expected))
        for version in wrong_versions:
            with self.subTest(openssl=version), self.assertRaises(failure) as raised:
                check(version, "3.51.1")
            self.assertEqual(raised.exception.code, "native_openssl_version")
            self.assertIsNone(raised.exception.module)
        for sqlite in (None, b"3.51.1", 35101, "x" * 33):
            with self.subTest(sqlite=sqlite), self.assertRaises(failure) as raised:
                check(expected, sqlite)
            self.assertEqual(raised.exception.code, "native_sqlite_version")
            self.assertIsNone(raised.exception.module)

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

    def test_fixed_system_curl_role_preserves_checked_hash_and_generic_policy(self):
        # These Windows names/stat results and >one-chunk bytes are inert DATA.
        # Exercise real role/path/hash/state predicates, not a Windows tool.
        system_root = r"C:\Windows"
        fixed = PureWindowsPath(system_root) / "System32" / "curl.exe"
        content = b"INERT fixed-System32 curl DATA; never executed.\n" + b"x" * (64 * 1024)
        case = self

        def exercise(changes=None, *, refused=False, before_open=False, no_metadata=False, generic=None):
            changes = {} if changes is None else changes
            selected = PureWindowsPath(changes.get("path", fixed))
            common = {"st_dev": 7, "st_ino": 13, "st_nlink": changes.get("links", 2),
                      "st_size": len(content), "st_mtime_ns": 10000, "st_birthtime_ns": 2000,
                      "st_file_attributes": 0x20, "st_reparse_tag": 0}
            named = SimpleNamespace(**{**common, "st_mode": stat.S_IFREG | 0o777, "st_ctime_ns": 2000,
                                       **changes.get("named", {})})
            opened = SimpleNamespace(**{**common, "st_mode": stat.S_IFREG | 0o666, "st_ctime_ns": 3000,
                                        **changes.get("opened", {})})
            after = SimpleNamespace(**{**vars(opened), **changes.get("after", {})})
            last = SimpleNamespace(**{**vars(named), **changes.get("last", {})})
            calls = {"open": 0, "leaf": 0, "parent": 0, "fstat": 0, "bytes": 0, "reads": []}

            class Stream(io.BytesIO):
                def fileno(self):
                    case.assertFalse(self.closed)
                    return 73

                def read(self, size=-1):
                    case.assertGreater(size, 0)
                    case.assertLessEqual(size, 64 * 1024)
                    calls["reads"].append(size)
                    if changes.get("read_error"):
                        raise OSError("INERT read boundary refusal")
                    block = super().read(size)
                    calls["bytes"] += len(block)
                    return block

            stream = Stream(changes.get("body", content))

            class NamedPath:
                def __init__(self, value):
                    self.value = value

                def __str__(self):
                    return str(self.value)

                @property
                def parents(self):
                    return tuple(NamedPath(parent) for parent in self.value.parents)

                def lstat(self):
                    if self.value == selected:
                        calls["leaf"] += 1
                        if calls["leaf"] > 1:
                            case.assertFalse(stream.closed)
                        return named if calls["leaf"] == 1 else last
                    calls["parent"] += 1
                    later = calls["parent"] > len(selected.parents)
                    if later:
                        case.assertFalse(stream.closed)
                    altered = changes.get("parent_after" if later else "parent", {}) if self.value == selected.parent else {}
                    return SimpleNamespace(**{"st_mode": stat.S_IFDIR | 0o777,
                                              "st_file_attributes": 0x10, "st_reparse_tag": 0, **altered})

                def open(self, mode):
                    case.assertEqual(self.value, selected)
                    case.assertEqual(mode, "rb")
                    calls["open"] += 1
                    case.assertEqual(calls["open"], 1)
                    return stream

            def descriptor(fd):
                case.assertEqual(fd, 73)
                case.assertFalse(stream.closed)
                calls["fstat"] += 1
                case.assertLessEqual(calls["fstat"], 2)
                return opened if calls["fstat"] == 1 else after

            root_value = changes.get("root", system_root)
            environment = {} if root_value is None else {"SystemRoot": root_value}
            reader = foundation.windows_payload_curl_sha256 if generic is None else generic
            try:
                with patch.object(foundation, "os", SimpleNamespace(name="nt", environ=environment, fstat=descriptor)), \
                        patch.object(payload.runtime_preparation, "os", SimpleNamespace(name="nt")), \
                        patch.object(foundation, "windows_payload_module", return_value=payload), \
                        patch.object(foundation, "run", side_effect=AssertionError("Curl DATA must not run a tool")):
                    if refused:
                        label = "Windows fixed System32 curl" if generic is None else "ordinary, single-link"
                        with self.assertRaisesRegex(foundation.CheckFailure, label):
                            reader(NamedPath(selected))
                    else:
                        self.assertEqual(reader(NamedPath(selected)), hashlib.sha256(content).hexdigest())
                        self.assertEqual((calls["open"], calls["leaf"], calls["fstat"]), (1, 2, 2))
                        self.assertEqual(calls["parent"], 2 * len(selected.parents))
                        self.assertGreaterEqual(len(calls["reads"]), 2)
                if before_open:
                    self.assertEqual((calls["open"], calls["fstat"], calls["reads"]), (0, 0, []))
                if no_metadata:
                    self.assertEqual((calls["leaf"], calls["parent"]), (0, 0))
                self.assertLessEqual(calls["bytes"], max(0, named.st_size + 1))
                if calls["open"]:
                    self.assertTrue(stream.closed)
            finally:
                # Only this in-memory fixture is ours; unopened fixtures need no
                # product cleanup, and an opened descriptor had to close above.
                stream.close()

        for links in (1, 2, 1024):
            with self.subTest(accepted_links=links):
                exercise({"links": links})
        for root in (None, "", "Windows", r"C:Windows", r"\Windows", r"\\host\share\Windows",
                     r"\\?\C:\Windows", r"C:\Windows\..\Other", r"C:\OtherWindows", system_root + "\0"):
            with self.subTest(root=root):
                exercise({"root": root}, refused=True, before_open=True, no_metadata=True)
        for wrong in (r"C:\Windows\SysWOW64\curl.exe", r"C:\Windows\System32\other.exe",
                      r"C:\Windows\System32\curl.exe:other", r"C:\Windows\System32\..\System32\curl.exe"):
            with self.subTest(path=wrong):
                exercise({"path": wrong}, refused=True, before_open=True, no_metadata=True)
        for changed in ({"links": 0}, {"links": -1}, {"links": 1025}, {"links": True},
                        {"named": {"st_size": 0}}, {"named": {"st_size": 16 * 1024 * 1024 + 1}},
                        {"named": {"st_mode": stat.S_IFDIR | 0o777}},
                        {"named": {"st_file_attributes": 0x420}}, {"named": {"st_reparse_tag": 1}},
                        {"parent": {"st_mode": stat.S_IFREG | 0o777}},
                        {"parent": {"st_file_attributes": 0x410}}, {"parent": {"st_reparse_tag": 1}}):
            with self.subTest(before_open=changed):
                exercise(changed, refused=True, before_open=True)
        for changed in ({"opened": {"st_ino": 14}}, {"opened": {"st_birthtime_ns": 2001}},
                        {"after": {"st_ctime_ns": 3001}}, {"after": {"st_nlink": 3}},
                        {"last": {"st_ino": 14}}, {"last": {"st_file_attributes": 0x420}},
                        {"parent_after": {"st_reparse_tag": 1}}, {"body": content[:-1]},
                        {"body": content + b"x"}, {"read_error": True}):
            with self.subTest(drift=tuple(changed)):
                exercise(changed, refused=True)
        for generic in (foundation.ordinary, foundation.hash_file):
            with self.subTest(unchanged_generic=generic.__name__):
                exercise({"links": 2}, refused=True, before_open=True, generic=generic)

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
        # Exercise real host and event admission without any path/tool/native
        # operation. The fixed image family is not an invented host observation.
        with patch.object(foundation.sys, "platform", "win32"), patch.object(foundation.sys, "version", foundation.PYTHON), \
                patch.object(foundation, "run", side_effect=AssertionError("Host admission must not run a tool")):
            for event in ("workflow_dispatch", "push"):
                admitted = {**hosted_environment(), "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                            "MRK_DESKTOP_PLATFORM": "windows", "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64",
                            "ImageOS": "win25-vs2026"}
                if event == "push":
                    admitted.pop("MRK_EXPECTED_SHA")
                    admitted.update(GITHUB_EVENT_NAME=event, MRK_EVENT_AFTER=admitted["GITHUB_SHA"])
                with patch.dict(foundation.os.environ, admitted, clear=True):
                    self.assertEqual(foundation.admitted_host(retention_only=True), "windows")
                for key, wrong in (("ImageOS", "win25"), ("ImageOS", "win22"), ("ImageOS", "win25-vs2026-altered"),
                                   ("ImageOS", ""), ("ImageOS", None), ("RUNNER_OS", "Linux"),
                                   ("RUNNER_ARCH", "ARM64"), ("RUNNER_ENVIRONMENT", "self-hosted")):
                    changed = dict(admitted)
                    if wrong is None:
                        changed.pop(key)
                    else:
                        changed[key] = wrong
                    with self.subTest(event=event, key=key, wrong=wrong), \
                            patch.dict(foundation.os.environ, changed, clear=True), self.assertRaises(foundation.CheckFailure):
                        foundation.admitted_host(retention_only=True)

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
