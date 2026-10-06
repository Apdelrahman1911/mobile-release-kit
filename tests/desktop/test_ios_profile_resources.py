"""Fixed public Apple trust data works from the shipped core ZIP, without native APIs."""
from __future__ import annotations

import hashlib
import importlib.util
import os
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
from unittest.mock import patch

from mobile_release import ios_profile_trust as trust
from mobile_release.errors import ValidationError


class AppleProfileResourceTests(unittest.TestCase):
    @contextmanager
    def packaged(self, *, roots: bytes | None = None, missing=False, duplicate=False):
        """A real ZIP loader and only task-owned public files/cache entry."""
        source = Path(trust.__file__).read_bytes()
        public = (Path(trust.__file__).parent / "data/apple-profile-roots.pem").read_bytes()
        roots = public if roots is None else roots
        name = "mobile_release.ios_profile_trust"
        registered = sys.modules[name]
        with tempfile.TemporaryDirectory(prefix="mrk-public-apple-roots-") as temporary:
            path = Path(temporary) / "core.zip"
            with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("mobile_release/ios_profile_trust.py", source)
                if not missing:
                    archive.writestr("mobile_release/data/apple-profile-roots.pem", roots)
                if duplicate:
                    with warnings.catch_warnings(record=True):
                        warnings.simplefilter("always", UserWarning)
                        archive.writestr("mobile_release/data/apple-profile-roots.pem", roots)
            # The constructor creates just this cache entry; no sys.path change,
            # global import-cache invalidation, or module registration is needed.
            key = str(path)
            cache = zipimport._zip_directory_cache
            self.assertNotIn(key, cache)
            owned_cache = None
            try:
                loader = zipimport.zipimporter(str(path / "mobile_release"))
                owned_cache = cache[key]
                spec = loader.find_spec(name)
                self.assertIsNotNone(spec)
                module = importlib.util.module_from_spec(spec)
                loader.exec_module(module)
                self.assertIs(sys.modules[name], registered)
                yield module, path, public
            finally:
                self.assertIs(sys.modules[name], registered)
                if owned_cache is not None:
                    self.assertIs(zipimport._zip_directory_cache, cache)
                    self.assertIs(cache.get(key), owned_cache)
                    del cache[key]

    def test_genuine_zip_import_matches_unpacked_pinned_roots_without_extraction(self):
        expected = trust.apple_roots()
        with self.packaged() as (module, path, _):
            self.assertIs(type(module.__loader__), zipimport.zipimporter)
            self.assertEqual(module.apple_roots(), expected)
            self.assertEqual({hashlib.sha256(item).hexdigest() for item in expected},
                             trust.APPLE_ROOT_SHA256)
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_missing_duplicate_empty_oversized_malformed_and_wrong_anchors_refuse(self):
        public = (Path(trust.__file__).parent / "data/apple-profile-roots.pem").read_bytes()
        first = public.splitlines()[1]
        wrong_pin = public.replace(first, b"A" + first[1:], 1)
        self.assertNotEqual(wrong_pin, public)
        cases = (
            ("missing", {"missing": True}),
            ("duplicate", {"duplicate": True}),
            ("empty", {"roots": b""}),
            ("oversized", {"roots": b"x" * (16 * 1024 + 1)}),
            ("malformed", {"roots": b"not a PEM certificate\n"}),
            ("different-anchor", {"roots": wrong_pin}),
        )
        for label, arguments in cases:
            with self.subTest(case=label), self.packaged(**arguments) as (module, _, _):
                with self.assertRaises(ValidationError):
                    module.apple_roots()

    def test_loader_origin_and_prefix_must_describe_this_exact_module(self):
        with self.packaged() as (module, path, _):
            original = module.__loader__
            cases = (
                ("unrecognized", object(), module.__file__),
                ("source-name", SourceFileLoader("different.module", module.__file__), module.__file__),
                ("source-path", SourceFileLoader(module.__name__, str(path)), module.__file__),
                ("origin", original, str(path / "different.py")),
                ("zip-prefix", zipimport.zipimporter(str(path / "different-package")), module.__file__),
            )
            for label, loader, origin in cases:
                spec = ModuleSpec(module.__name__, loader, origin=origin)
                with self.subTest(case=label), patch.object(module, "__spec__", spec), \
                        patch.object(module, "__loader__", loader), \
                        patch.object(module, "open", create=True) as opened:
                    with self.assertRaises(ValidationError):
                        module.apple_roots()
                    opened.assert_not_called()
            with patch.object(module, "__loader__", object()), \
                    patch.object(module, "open", create=True) as opened:
                with self.assertRaises(ValidationError):
                    module.apple_roots()
                opened.assert_not_called()

    def test_directory_bounds_and_zip64_are_refused_before_zipfile_construction(self):
        with self.packaged() as (module, path, _):
            body = path.read_bytes()
            end = list(struct.unpack("<4s4H2IH", body[-22:]))
            self.assertEqual(end[0], b"PK\x05\x06")

            def changed(index, value):
                fields = end.copy()
                fields[index] = value
                return body[:-22] + struct.pack("<4s4H2IH", *fields)

            zero = end.copy()
            zero[3] = zero[4] = 0
            many = end.copy()
            many[3] = many[4] = 2049
            cases = (
                ("short", body[:30]),
                ("signature", changed(0, b"bad!")),
                ("split", changed(1, 1)),
                ("count-mismatch", changed(3, end[3] + 1)),
                ("empty-directory", body[:-22] + struct.pack("<4s4H2IH", *zero)),
                ("too-many", body[:-22] + struct.pack("<4s4H2IH", *many)),
                ("directory-bound", changed(5, 2 * 1024 * 1024 + 1)),
                ("directory-offset", changed(6, end[6] + 1)),
                ("comment", changed(7, 1) + b"x"),
                ("zip64-locator", body[:-42] + b"PK\x06\x07" + body[-38:]),
            )
            for label, malformed in cases:
                with self.subTest(case=label):
                    path.write_bytes(malformed)
                    with patch.object(module, "ZipFile", side_effect=AssertionError("must not construct")) as opened:
                        with self.assertRaises(ValidationError):
                            module.apple_roots()
                        opened.assert_not_called()
            # An ordinary, bounded EOCD still must match the parsed directory.
            fields = end.copy()
            fields[3] = fields[4] = end[4] + 1
            path.write_bytes(body[:-22] + struct.pack("<4s4H2IH", *fields))
            with self.assertRaises(ValidationError):
                module.apple_roots()

    def test_crc_and_decompression_failures_are_not_trust_acceptance(self):
        with self.packaged() as (module, path, _):
            # Modify only the expected CRC in this owned ZIP's central record,
            # after the real module has been imported. Keep all payload bytes.
            body = bytearray(path.read_bytes())
            name = b"mobile_release/data/apple-profile-roots.pem"
            marker = b"PK\x01\x02"
            position = 0
            selected = None
            while True:
                position = body.find(marker, position)
                if position < 0:
                    break
                length = int.from_bytes(body[position + 28:position + 30], "little")
                if body[position + 46:position + 46 + length] == name:
                    self.assertIsNone(selected)
                    selected = position
                position += 4
            self.assertIsNotNone(selected)
            body[selected + 16] ^= 1
            path.write_bytes(body)
            with self.assertRaises(ValidationError) as error:
                module.apple_roots()
            self.assertNotIn(str(path), str(error.exception))
            self.assertNotIn(name.decode(), str(error.exception))
        # The decompressor's native error is separate from BadZipFile/OSError.
        with self.packaged() as (module, _, _):
            with patch.object(module, "ZipFile", side_effect=module.ZlibError("private-resource-canary")):
                with self.assertRaises(ValidationError) as error:
                    module.apple_roots()
            self.assertNotIn("private-resource-canary", str(error.exception))

    def test_read_and_each_close_failure_still_close_outer_owners_before_any_pin_acceptance(self):
        with self.packaged() as (module, _, _):
            real_open, real_zip, real_pem = open, module.ZipFile, module.pem_certificates
            for fault in (None, "read", "member-close", "archive-close", "original-close"):
                events, originals = [], []
                with self.subTest(fault=fault):
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
                            # Known close returned; an observed close failure
                            # must still refuse acceptance, never retry it.
                            if fault == self.role + "-close":
                                raise OSError("private-resource-canary")
                            return result

                        def read(self, size=-1):
                            if self.role == "member" and fault == "read":
                                raise OSError("private-resource-canary")
                            return self.original.read(size)

                        def open(self, *arguments, **keywords):
                            self.assert_archive_role()
                            return Observed(self.original.open(*arguments, **keywords), "member")

                        def assert_archive_role(self):
                            if self.role != "archive":
                                raise AssertionError("only the archive opens a member")

                    def opened(*arguments, **keywords):
                        return Observed(real_open(*arguments, **keywords), "original")

                    def archive(*arguments, **keywords):
                        return Observed(real_zip(*arguments, **keywords), "archive")

                    def decoded(content):
                        self.assertEqual(events, ["member-close", "archive-close", "original-close"])
                        events.append("pem")
                        return real_pem(content)

                    with patch.object(module, "open", side_effect=opened, create=True), \
                            patch.object(module, "ZipFile", side_effect=archive), \
                            patch.object(module, "pem_certificates", side_effect=decoded) as pem:
                        if fault is None:
                            self.assertEqual(module.apple_roots(), trust.apple_roots())
                            pem.assert_called_once()
                        else:
                            with self.assertRaises(ValidationError) as error:
                                module.apple_roots()
                            pem.assert_not_called()
                            self.assertNotIn("private-resource-canary", str(error.exception))
                    self.assertEqual(events[:3], ["member-close", "archive-close", "original-close"])
                    self.assertEqual(len(originals), 3)
                    for observed in originals:
                        if observed.role == "archive":
                            self.assertIsNone(observed.original.fp)
                        else:
                            self.assertTrue(observed.original.closed)


if __name__ == "__main__":
    unittest.main()
