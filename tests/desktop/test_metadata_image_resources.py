"""Public image resources from real SOURCE/ZIP loaders, without native operations.

Only task-owned small fixtures are written. Core dependencies are real imports;
no fake core, selected project, native picker, process, Store or network is used.
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile
import zipimport
from contextlib import contextmanager
from importlib.machinery import ModuleSpec, SourceFileLoader
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import metadata_images as images


NAMES = ("metadata-images-v1.json", "metadata-image-help-v1.json")


class MetadataImageResourceTests(unittest.TestCase):
    @contextmanager
    def fixture(self, *, packed=True, overrides=None, missing=None, duplicate=None):
        """Real detached loaders; no sys.path/module replacement or extraction."""
        source_path = Path(images.__file__)
        source = source_path.read_bytes()
        public = {name: (source_path.parent / "api" / "data" / name).read_bytes() for name in NAMES}
        values = {**public, **(overrides or {})}
        name = "mobile_release.metadata_images"
        registered = sys.modules[name]
        with tempfile.TemporaryDirectory(prefix="mrk-public-image-resources-") as temporary:
            root = Path(temporary)
            cache = zipimport._zip_directory_cache
            cache_key = None
            owned_cache = None
            try:
                if packed:
                    path = root / "core.zip"
                    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
                        archive.writestr("mobile_release/metadata_images.py", source)
                        for resource, content in values.items():
                            if resource != missing:
                                archive.writestr("mobile_release/api/data/" + resource, content)
                            if resource == duplicate:
                                with warnings.catch_warnings(record=True):
                                    warnings.simplefilter("always", UserWarning)
                                    archive.writestr("mobile_release/api/data/" + resource, content)
                    cache_key = str(path)
                    self.assertNotIn(cache_key, cache)
                    loader = zipimport.zipimporter(str(path / "mobile_release"))
                    owned_cache = cache[cache_key]
                    spec = loader.find_spec(name)
                else:
                    package = root / "mobile_release"
                    (package / "api" / "data").mkdir(parents=True)
                    path = package / "metadata_images.py"
                    path.write_bytes(source)
                    for resource, content in values.items():
                        if resource != missing:
                            (package / "api" / "data" / resource).write_bytes(content)
                    spec = importlib.util.spec_from_file_location(name, path)
                    loader = spec.loader
                self.assertIsNotNone(spec)
                module = importlib.util.module_from_spec(spec)
                loader.exec_module(module)
                self.assertIs(sys.modules[name], registered)
                yield module, path, public
            finally:
                self.assertIs(sys.modules[name], registered)
                if owned_cache is not None:
                    self.assertIs(zipimport._zip_directory_cache, cache)
                    self.assertIs(cache.get(cache_key), owned_cache)
                    del cache[cache_key]

    def refused(self, module, action):
        with self.assertRaises(module.MetadataImagesInputError) as error:
            action()
        self.assertEqual(error.exception.reason, "catalog_unavailable")
        self.assertEqual(str(error.exception), "Public image input was refused")

    def test_packaged_catalog_and_typed_selection_match_unpacked_without_extraction(self):
        with self.fixture(packed=False) as (unpacked, _, _), self.fixture() as (module, path, _):
            self.assertIs(type(module.__loader__), zipimport.zipimporter)
            expected = unpacked.catalog()
            self.assertEqual(module.catalog(), expected)
            self.assertEqual(module.image_type("android", "icon").max_count, 1)
            ios = next(row for row in expected["types"] if row["platform"] == "ios")
            self.assertEqual(module.image_type("ios", ios["id"]).dimensions,
                             tuple(tuple(pair) for pair in ios["dimensions"]))
            configuration = json.dumps({
                "schemaVersion": 1,
                "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
                "source": {"candidateBranch": "main", "productionBranch": "production"},
                "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
                "ios": {"enabled": True, "bundleId": "org.fixture.app", "identityStatus": "unverified"},
                "metadata": {"root": "public/store", "androidLocales": ["en-US"], "iosLocales": ["en-US"]},
                "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
                "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
            })
            # Exercise the real import-selection consumer, not only a helper.
            selected = module.public_image_selection(configuration, "android", "en-US", "icon")
            self.assertEqual(selected.relative_path("icon.png"), "public/store/android/en-US/images/icon.png")
            selected = module.public_image_selection(configuration, "ios", "en-US", ios["id"])
            self.assertEqual(selected.relative_path("screen.png"),
                             "public/store/ios/screenshots/en-US/" + ios["id"] + "/screen.png")
            self.assertEqual(list(path.parent.iterdir()), [path])
            with self.assertRaises(module.MetadataImagesInputError) as error:
                module.image_type("android", "unknown")
            self.assertEqual(error.exception.reason, "unsupported_type")

    def test_fixed_resources_schema_and_failed_cache_preserve_policy(self):
        for name in NAMES:
            cases = (
                ("missing", {"missing": name}),
                ("duplicate", {"duplicate": name}),
                ("empty", {"overrides": {name: b""}}),
                ("oversized", {"overrides": {name: b"x" * (128 * 1024 + 1)}}),
                ("malformed", {"overrides": {name: b"{not-json"}}),
                ("wrong-shape", {"overrides": {name: b"{}"}}),
            )
            for label, arguments in cases:
                with self.subTest(resource=name, case=label), self.fixture(**arguments) as (module, _, _):
                    self.refused(module, module.catalog)
                    if name == NAMES[0]:
                        self.assertEqual(module._types.cache_info().currsize, 0)
        with self.fixture() as (module, _, public):
            for name in NAMES:
                malformed = json.loads(public[name])
                malformed["schemaVersion"] = True
                with self.subTest(resource=name, case="boolean-version"), \
                        patch.object(module, "_catalog_resource", side_effect=lambda selected: (
                            json.dumps(malformed).encode() if selected == name else public[selected])):
                    self.refused(module, module.catalog)
                module._types.cache_clear()
            with patch.object(module, "open", create=True) as opened:
                self.refused(module, lambda: module._catalog_resource("../project.json"))
                opened.assert_not_called()
            self.assertEqual(module._types.cache_info().maxsize, 1)
            self.assertTrue(module._types())
            with patch.object(module, "_catalog_resource", side_effect=AssertionError("cache lost")):
                self.assertEqual(module.image_type("android", "icon").max_count, 1)

    def test_loader_and_origin_rejections_precede_resource_io(self):
        with self.fixture() as (module, path, _):
            original = module.__loader__
            cases = (
                ("unrecognized", object(), module.__file__),
                ("source-name", SourceFileLoader("different.module", module.__file__), module.__file__),
                ("source-path", SourceFileLoader(module.__name__, str(path)), module.__file__),
                ("origin", original, str(path / "different.py")),
                ("zip-prefix", zipimport.zipimporter(str(path / "other-package")), module.__file__),
            )
            for label, loader, origin in cases:
                spec = ModuleSpec(module.__name__, loader, origin=origin)
                with self.subTest(case=label), patch.object(module, "__spec__", spec), \
                        patch.object(module, "__loader__", loader), \
                        patch.object(module, "open", create=True) as opened:
                    self.refused(module, module.catalog)
                    opened.assert_not_called()
            with patch.object(module, "__loader__", object()), \
                    patch.object(module, "open", create=True) as opened:
                self.refused(module, module.catalog)
                opened.assert_not_called()

    def test_archive_preconstructor_limits_and_member_integrity(self):
        with self.fixture() as (module, path, _):
            body = path.read_bytes()
            end = list(struct.unpack("<4s4H2IH", body[-22:]))
            self.assertEqual(end[0], b"PK\x05\x06")

            def changed(index, value):
                fields = end.copy()
                fields[index] = value
                return body[:-22] + struct.pack("<4s4H2IH", *fields)

            many = end.copy()
            many[3] = many[4] = 2049
            zero = end.copy()
            zero[3] = zero[4] = 0
            cases = (
                ("short", body[:30]),
                ("signature", changed(0, b"bad!")),
                ("split", changed(1, 1)),
                ("count-mismatch", changed(3, end[3] + 1)),
                ("empty", body[:-22] + struct.pack("<4s4H2IH", *zero)),
                ("many", body[:-22] + struct.pack("<4s4H2IH", *many)),
                ("directory-bound", changed(5, 2 * 1024 * 1024 + 1)),
                ("directory-offset", changed(6, end[6] + 1)),
                ("comment", changed(7, 1) + b"x"),
                ("zip64-locator", body[:-42] + b"PK\x06\x07" + body[-38:]),
            )
            for label, malformed in cases:
                with self.subTest(case=label):
                    path.write_bytes(malformed)
                    with patch.object(module, "ZipFile", side_effect=AssertionError("must not construct")) as opened:
                        self.refused(module, module.catalog)
                        opened.assert_not_called()
            fields = end.copy()
            fields[3] = fields[4] = end[4] + 1
            path.write_bytes(body[:-22] + struct.pack("<4s4H2IH", *fields))
            self.refused(module, module.catalog)

            # Mutate only selected central fields in our own already-loaded ZIP.
            # Payloads remain real; invalid CRC is detected by the actual reader.
            name = ("mobile_release/api/data/" + NAMES[0]).encode()
            position, selected = 0, None
            while True:
                position = body.find(b"PK\x01\x02", position)
                if position < 0:
                    break
                length = int.from_bytes(body[position + 28:position + 30], "little")
                if body[position + 46:position + 46 + length] == name:
                    self.assertIsNone(selected)
                    selected = position
                position += 4
            self.assertIsNotNone(selected)
            for label, offset in (("crc", 16), ("encrypted", 8), ("compression", 10)):
                mutated = bytearray(body)
                mutated[selected + offset] ^= 1
                with self.subTest(case=label):
                    path.write_bytes(mutated)
                    self.refused(module, module.catalog)
            path.write_bytes(body)
            with patch.object(module, "ZipFile", side_effect=module.ZlibError("private-resource-canary")):
                self.refused(module, module.catalog)

    def test_read_post_and_each_close_failure_refuse_before_json(self):
        for packed in (False, True):
            faults = (None, "read", "post", "original-close")
            if packed:
                faults += ("member-close", "archive-close")
            for fault in faults:
                with self.subTest(packed=packed, fault=fault), self.fixture(packed=packed) as (module, path, _):
                    real_open, real_zip, real_loads = open, module.ZipFile, module.json.loads
                    events, originals = [], []
                    expected = ["member-close", "archive-close", "original-close"] if packed else ["original-close"]
                    subject = path if packed else path.parent / "api" / "data" / NAMES[0]

                    class Observed:
                        def __init__(self, original, role):
                            self.original, self.role = original, role
                            originals.append(self)

                        def __getattr__(self, name):
                            return getattr(self.original, name)

                        def __enter__(self):
                            self.original.__enter__()
                            return self

                        def __exit__(self, *arguments):
                            result = self.original.__exit__(*arguments)
                            events.append(self.role + "-close")
                            # The real close returns first. Inject an error
                            # report, not an intentionally leaked/UNKNOWN FD.
                            if fault == self.role + "-close":
                                raise OSError("private-resource-canary")
                            return result

                        def read(self, size=-1):
                            selected = self.role == ("member" if packed else "original")
                            if selected and fault == "read":
                                raise OSError("private-resource-canary")
                            content = self.original.read(size)
                            if selected and fault == "post":
                                before = subject.stat()
                                os.utime(subject, ns=(before.st_atime_ns, before.st_mtime_ns + 1))
                            return content

                        def open(self, *arguments, **keywords):
                            if self.role != "archive":
                                raise AssertionError("only the archive opens a member")
                            return Observed(self.original.open(*arguments, **keywords), "member")

                    def opened(*arguments, **keywords):
                        return Observed(real_open(*arguments, **keywords), "original")

                    def archive(*arguments, **keywords):
                        return Observed(real_zip(*arguments, **keywords), "archive")

                    def decoded(content):
                        self.assertEqual(events, expected)
                        events.append("json")
                        return real_loads(content)

                    with patch.object(module, "open", side_effect=opened, create=True), \
                            patch.object(module, "ZipFile", side_effect=archive), \
                            patch.object(module.json, "loads", side_effect=decoded) as loads:
                        if fault is None:
                            self.assertEqual(module.image_type("android", "icon").max_count, 1)
                            loads.assert_called_once()
                        else:
                            self.refused(module, module._types)
                            loads.assert_not_called()
                            self.assertEqual(module._types.cache_info().currsize, 0)
                    self.assertEqual(events[:len(expected)], expected)
                    self.assertEqual(len(originals), len(expected))
                    for observed in originals:
                        if observed.role == "archive":
                            self.assertIsNone(observed.original.fp)
                        else:
                            self.assertTrue(observed.original.closed)

    def test_windows_same_api_identity_retains_ctime_and_reparse_fields(self):
        # Inert Windows stat facts protect the documented API distinction;
        # this is not Windows native qualification and opens no Windows path.
        base = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o666,
                    st_uid=0, st_gid=0, st_nlink=1, st_size=5, st_mtime_ns=6,
                    st_birthtime_ns=7, st_ctime_ns=7, st_file_attributes=32, st_reparse_tag=0)
        named = SimpleNamespace(**base)
        held = SimpleNamespace(**{**base, "st_ctime_ns": 8})
        with self.fixture() as (module, _, _), patch.object(module, "os", SimpleNamespace(name="nt")):
            self.assertTrue(module._resource_same_file(named, held, "core.zip"))
            self.assertNotEqual(module._resource_state(named), module._resource_state(held))
            for key in ("st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns",
                        "st_birthtime_ns", "st_file_attributes", "st_reparse_tag"):
                changed = SimpleNamespace(**{**vars(held), key: getattr(held, key) + 1})
                self.assertFalse(module._resource_same_file(named, changed, "core.zip"), key)
            changed = SimpleNamespace(**{**vars(held), "st_ctime_ns": held.st_ctime_ns + 1})
            self.assertNotEqual(module._resource_state(held), module._resource_state(changed))
            decorated = SimpleNamespace(**{**base, "st_mode": named.st_mode | 0o111})
            self.assertTrue(module._resource_same_file(decorated, held, "core.EXE"))
            self.assertFalse(module._resource_same_file(decorated, held, "core.zip"))


if __name__ == "__main__":
    unittest.main()
