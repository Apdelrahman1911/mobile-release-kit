"""Bounded synthetic bytes/files only: never keytool, JDK, native or real keys."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from helpers import android_config
from mobile_release import _desktop_upload_key_jks as jks
from mobile_release import _desktop_upload_key_protocol as wire
from mobile_release._desktop_upload_key_saved import UploadKeySaved, bind_saved_bytes
from mobile_release._desktop_upload_key_scratch import UploadKeyScratch
from mobile_release.cancellation import DefaultCancellation
from mobile_release.errors import ConfigurationError
from mobile_release.owned_process import ProcessCleanupError


def fixture():
    return {"protocol": wire.PROTOCOL, "id": "1" * 32, "generation": "2" * 32,
            "contextSha256": "3" * 64, "native": {"uid": 1001, "gid": 1001,
            "executable": "/fixture/jdk/bin/keytool", "tool": {"identity":
            [1, 2, stat.S_IFREG | 0o755, 0, 0, 1, 42, 123, 456], "sha256": "4" * 64}, "saved": {"root": "/fixture/project",
            "identity": [1, 3, stat.S_IFDIR | 0o700, 1001, 1001], "configBytes": 100,
            "configSha256": "5"*64, "draftSha256": "6"*64, "appIdentitySha256": "7"*64}},
            "clock": {"workEndNs": 180_000_000_000, "hardEndNs": 190_000_000_000}}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def private_go(request):
    return bytearray(wire.GO_MAGIC + request.digest + b"a" * 64 + b"b" * 64)


def synthetic_container(password=b"a" * 64, *, certificate=b"\x30\x03\x02\x01\x01"):
    # Deliberately NOT a usable key/certificate. Format-only container fixture.
    def utf(value):
        return struct.pack(">H", len(value)) + value
    encrypted = b"\x30" + b"not-a-private-key" * 3
    body = (struct.pack(">IIII", 0xFEEDFEED, 2, 1, 1) + utf(b"upload") + struct.pack(">q", 1)
            + struct.pack(">I", len(encrypted)) + encrypted + struct.pack(">I", 1) + utf(b"X.509")
            + struct.pack(">I", len(certificate)) + certificate)
    digest = hashlib.sha1(password.decode("ascii").encode("utf-16be") + b"Mighty Aphrodite" + body).digest()
    return body + digest, certificate


class UploadKeyProtocolTests(unittest.TestCase):
    def test_exact_fixed_keytool_commands_and_no_arbitrary_flags(self):
        request = wire.parse_request(encoded(fixture()))
        scratch = Path("/fixture/private")
        generate, export = request.arguments(scratch, export=False), request.arguments(scratch, export=True)
        self.assertIn("-genkeypair", generate)
        self.assertIn("-J-XX:-UsePerfData", generate)
        self.assertEqual(generate[generate.index("-keysize") + 1], "3072")
        self.assertEqual(generate[generate.index("-storetype") + 1], "JKS")
        for args in (generate, export):
            self.assertEqual(args[args.index("-alias") + 1], "upload")
            self.assertEqual(args[args.index("-storepass:env") + 1], wire.STORE_PASSWORD_ENV)
            self.assertEqual(args[args.index("-keypass:env") + 1], wire.KEY_PASSWORD_ENV)
            self.assertNotIn("-storepass", args)
            self.assertNotIn("-keypass", args)
            self.assertNotIn("-file", args)
        self.assertIn("-exportcert", export)
        self.assertNotIn("-rfc", export)
        self.assertNotIn("-genkeypair", export)

    def test_no_extra_role_argv_secret_or_environment_fields(self):
        for key in ("role", "argv", "password", "environment", "retry", "projectPath"):
            value = fixture()
            value[key] = "fixture"
            with self.subTest(key=key), self.assertRaises(wire.ProtocolError):
                wire.parse_request(encoded(value))

    def test_native_source_cannot_be_path_alias_or_unowned_executable(self):
        for path in ("keytool", "/fixture/bin/sh", "/fixture/keytool", "/fixture/../bin/keytool",
                     "/fixture//bin/keytool", "/fixture/\ud800/bin/keytool"):
            value = fixture()
            value["native"]["executable"] = path
            with self.subTest(path=path), self.assertRaises(wire.ProtocolError):
                wire.parse_request(encoded(value))
        for n, invalid in ((2, stat.S_IFLNK | 0o777), (2, stat.S_IFREG | 0o644),
                           (2, stat.S_IFREG | 0o777), (3, 1001), (3, 2002), (5, 2), (6, wire.TOOL_LIMIT + 1)):
            value = fixture()
            value["native"]["tool"]["identity"][n] = invalid
            with self.subTest(n=n), self.assertRaises(wire.ProtocolError):
                wire.parse_request(encoded(value))

    def test_ids_and_parent_clock_are_exact_not_renewable(self):
        for key in ("id", "generation"):
            for invalid in ("0" * 32, "A" * 32, "1" * 31, "1" * 33, 1):
                value = fixture()
                value[key] = invalid
                with self.subTest(key=key, invalid=invalid), self.assertRaises(wire.ProtocolError):
                    wire.parse_request(encoded(value))
        for key, invalid in (("workEndNs", 0), ("hardEndNs", 191_000_000_000),
                             ("workEndNs", 180e9), ("hardEndNs", True)):
            value = fixture()
            value["clock"][key] = invalid
            with self.subTest(key=key), self.assertRaises(wire.ProtocolError):
                wire.parse_request(encoded(value))

    def test_request_rejects_duplicates_coalescing_depth_and_oversize(self):
        raw = encoded(fixture())
        for bad in (raw + raw, raw[:-1], raw.replace(b'"uid":1001', b'"uid":1001,"uid":1001'),
                    b"[" * 64 + b"0" + b"]" * 64 + b"\n", b" " * (wire.REQUEST_LIMIT + 1) + b"\n"):
            with self.subTest(length=len(bad)), self.assertRaises(wire.ProtocolError):
                wire.parse_request(bad)

    def test_private_passwords_stay_out_of_argv_request_and_parent_environment(self):
        request = wire.parse_request(encoded(fixture()))
        original = dict(os.environ)
        raw = private_go(request)
        passwords = wire.Passwords(raw, request)
        environment = passwords.environment(Path("/fixture/private"))
        self.assertEqual(set(environment), {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL",
                                          wire.STORE_PASSWORD_ENV, wire.KEY_PASSWORD_ENV})
        self.assertEqual(environment[wire.STORE_PASSWORD_ENV], "a" * 64)
        self.assertEqual(environment[wire.KEY_PASSWORD_ENV], "b" * 64)
        self.assertEqual(dict(os.environ), original)
        self.assertNotIn("a" * 64, repr(passwords))
        self.assertNotIn("/fixture", repr(request))
        self.assertNotIn("a" * 64, " ".join(request.arguments(Path("/fixture/private"), export=False)))
        passwords.close()
        self.assertEqual(raw, bytearray(wire.GO_LENGTH))
        with self.assertRaises(wire.ProtocolError):
            passwords.environment(Path("/fixture/private"))

    def test_private_go_rejects_wrong_context_and_truncated_or_extra_bytes(self):
        request = wire.parse_request(encoded(fixture()))
        wrong = bytearray(private_go(request)); wrong[len(wire.GO_MAGIC)] ^= 1
        equal = bytearray(wire.GO_MAGIC + request.digest + b"a" * 128)
        for raw in (private_go(request)[:-1], private_go(request) + b"x", wrong, equal,
                    bytearray(wire.GO_MAGIC + request.digest + b"z" * 64 + b"b" * 64)):
            with self.subTest(length=len(raw)), self.assertRaises(wire.ProtocolError):
                wire.Passwords(raw, request)

    def test_binary_terminal_has_only_original_ids_status_lengths(self):
        request = wire.parse_request(encoded(fixture()))
        ready = wire.ready(request)
        self.assertEqual(len(ready), wire.READY_LENGTH)
        self.assertEqual(len(wire.terminal_header(request, "ok", 1024, 2048)), wire.END_HEADER_LENGTH)
        self.assertEqual(wire.RESPONSE_LIMIT, wire.READY_LENGTH + wire.END_HEADER_LENGTH + 80 * 1024)
        self.assertLessEqual(wire.RESPONSE_LIMIT, wire.PRIVATE_BACKING_LIMIT)
        for status in wire.STATUSES[1:]:
            self.assertEqual(len(wire.terminal_header(request, status)), wire.END_HEADER_LENGTH)
            with self.assertRaises(wire.ProtocolError):
                wire.terminal_header(request, status, 1024, 2048)
        for sizes in ((32, 16), (1024, 0), (wire.JKS_LIMIT + 1, 16), (1024, wire.CERTIFICATE_LIMIT + 1)):
            with self.assertRaises(wire.ProtocolError):
                wire.terminal_header(request, "ok", *sizes)


class EmptyJksTests(unittest.TestCase):
    def test_empty_v2_matches_standard_password_integrity_recipe(self):
        password = b"a" * 64
        raw = jks.empty_jks(password)
        expected_body = bytes.fromhex("feedfeed0000000200000000")
        expected_digest = hashlib.sha1(password.decode().encode("utf-16be") + b"Mighty Aphrodite" + expected_body).digest()
        self.assertEqual(raw, expected_body + expected_digest)
        jks.check_empty(raw, password)
        self.assertNotIn(password, raw)

    def test_empty_rejects_wrong_password_integrity_format_and_truncation(self):
        raw = jks.empty_jks(b"a" * 64)
        for altered in (raw[:-1], raw + b"x", b"x" + raw[1:], raw[:15] + b"x" + raw[16:],
                        bytes.fromhex("feedfeed0000000100000000") + raw[12:]):
            with self.assertRaises(wire.ProtocolError):
                jks.check_empty(altered, b"a" * 64)
        with self.assertRaises(wire.ProtocolError):
            jks.check_empty(raw, b"b" * 64)
        for password in (b"a" * 63, b"g" * 64, "a" * 64, b"a" * 65):
            with self.assertRaises(wire.ProtocolError):
                jks.empty_jks(password)

    def test_generated_container_is_exactly_one_alias_private_entry_and_one_der(self):
        raw, certificate = synthetic_container()
        self.assertEqual(jks.generated_certificate(raw, b"a" * 64, certificate), certificate)
        for bad in (raw[:-1], raw + b"x", raw[:20] + b"x" + raw[21:]):
            with self.assertRaises(wire.ProtocolError):
                jks.generated_certificate(bad, b"a" * 64, certificate)
        for password, exported in ((b"b" * 64, certificate), (b"a" * 64, certificate + b"x")):
            with self.assertRaises(wire.ProtocolError):
                jks.generated_certificate(raw, password, exported)

    def test_even_integrity_valid_extra_entries_or_changed_alias_refuse(self):
        raw, certificate = synthetic_container()
        for body in (raw[:-20].replace(b"upload", b"otherx"), raw[:-20] + b"extra",
                     raw[:8] + struct.pack(">I", 2) + raw[12:-20], raw[:12] + struct.pack(">I", 2) + raw[16:-20]):
            digest = hashlib.sha1(("a" * 64).encode("utf-16be") + b"Mighty Aphrodite" + body).digest()
            with self.assertRaises(wire.ProtocolError):
                jks.generated_certificate(body + digest, b"a" * 64, certificate)


class OriginalScratchTests(unittest.TestCase):
    def make(self, root):
        # No handler install, process creation or synthetic process receipt.
        # This original guard has genuinely never admitted a producer.
        guard = DefaultCancellation(ProcessCleanupError, "synthetic scratch cleanup")
        scratch = UploadKeyScratch(Path(root), "1" * 32, guard)
        scratch.acquire()
        return scratch

    def test_app_creates_and_holds_empty_jks_before_any_producer(self):
        with tempfile.TemporaryDirectory(prefix="mrk-upload-fixture-") as root:
            scratch = self.make(root)
            try:
                scratch.initialize(b"a" * 64)
                named = os.stat(scratch.path / "upload.jks", follow_symlinks=False)
                original = os.fstat(scratch.file.number)
                self.assertEqual((named.st_dev, named.st_ino), (original.st_dev, original.st_ino))
                self.assertEqual(stat.S_IMODE(named.st_mode), 0o600)
                scratch.read_original()
                jks.check_empty(memoryview(scratch.raw)[:scratch.length], b"a" * 64)
            finally:
                scratch.cleanup()
            self.assertTrue(scratch.closed)
            self.assertFalse(scratch.path.exists())

    def test_exclusive_creation_never_adopts_preexisting_output(self):
        with tempfile.TemporaryDirectory(prefix="mrk-upload-fixture-") as root:
            scratch = self.make(root)
            foreign = scratch.path / "upload.jks"
            foreign.write_bytes(b"synthetic-foreign")
            with self.assertRaises(wire.ProtocolError):
                scratch.initialize(b"a" * 64)
            with self.assertRaises(wire.ProtocolError):
                scratch.cleanup()
            self.assertEqual(foreign.read_bytes(), b"synthetic-foreign")
            self.assertTrue(scratch.unknown)

    def test_replaced_output_is_preserved_even_with_same_name_and_size(self):
        with tempfile.TemporaryDirectory(prefix="mrk-upload-fixture-") as root:
            scratch = self.make(root)
            scratch.initialize(b"a" * 64)
            output = scratch.path / "upload.jks"
            output.rename(scratch.path / "original-retained-fixture")
            output.write_bytes(jks.empty_jks(b"a" * 64))
            output.chmod(0o600)
            with self.assertRaises(wire.ProtocolError):
                scratch.check()
            with self.assertRaises(wire.ProtocolError):
                scratch.cleanup()
            self.assertTrue(output.exists())
            self.assertTrue((scratch.path / "original-retained-fixture").exists())

    def test_partial_same_original_is_disposable_only_after_actual_no_producer(self):
        with tempfile.TemporaryDirectory(prefix="mrk-upload-fixture-") as root:
            scratch = self.make(root)
            scratch.initialize(b"a" * 64)
            os.ftruncate(scratch.file.number, 3)
            scratch.cleanup()
            self.assertTrue(scratch.closed)
            self.assertFalse(scratch.path.exists())

    def test_foreign_extra_entry_prevents_finite_cleanup_and_unknown_does_not_retry(self):
        with tempfile.TemporaryDirectory(prefix="mrk-upload-fixture-") as root:
            scratch = self.make(root)
            scratch.initialize(b"a" * 64)
            (scratch.path / "foreign").write_bytes(b"fixture")
            with self.assertRaises(wire.ProtocolError):
                scratch.cleanup()
            self.assertTrue((scratch.path / "upload.jks").exists())
            self.assertTrue((scratch.path / "foreign").exists())
            with self.assertRaises(wire.ProtocolError):
                scratch.cleanup()


class SavedInputTests(unittest.TestCase):
    def fixture(self, root, data=None):
        data = android_config(status="unverified") if data is None else data
        raw = (json.dumps(data, indent=2) + "\n").encode("utf-8")
        canonical = json.dumps(data, sort_keys=True, ensure_ascii=False,
                               separators=(",", ":"), allow_nan=False).encode("utf-8")
        app = data["android"]["applicationId"].encode("ascii")
        value = os.stat(root, follow_symlinks=False)
        expected = wire.SavedProject(Path(root),
            (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid),
            len(raw), hashlib.sha256(raw).hexdigest(), hashlib.sha256(canonical).hexdigest(),
            hashlib.sha256(b"dev.mobile-release-kit.desktop/credential-app-identity/v1\0"
                           + b"\x01" + len(app).to_bytes(4, "big") + app).hexdigest())
        return raw, expected

    def write(self, root):
        raw, expected = self.fixture(root)
        release = Path(root) / "release"
        release.mkdir()
        (release / "mobile-release.json").write_bytes(raw)
        guard = DefaultCancellation(ProcessCleanupError, "synthetic saved-input cleanup")
        return UploadKeySaved(expected, guard)

    def test_saved_raw_canonical_draft_and_app_domain_must_all_match(self):
        with tempfile.TemporaryDirectory(prefix="mrk-upload-saved-fixture-") as root:
            raw, expected = self.fixture(root)
            bind_saved_bytes(raw, expected)
            for field in ("config_sha256", "draft_sha256", "app_identity_sha256"):
                with self.subTest(field=field), self.assertRaises(wire.ProtocolError):
                    bind_saved_bytes(raw, replace(expected, **{field: "0" * 64}))
            with self.assertRaises(wire.ProtocolError):
                bind_saved_bytes(raw + b" ", expected)
            data = android_config(status="unverified")
            data["android"]["enabled"] = False
            raw, expected = self.fixture(root, data)
            with self.assertRaises((wire.ProtocolError, ConfigurationError)):
                bind_saved_bytes(raw, expected)

    def test_same_original_is_checked_read_only_before_and_after_use(self):
        with tempfile.TemporaryDirectory(prefix="mrk-upload-saved-fixture-") as root:
            saved = self.write(root)
            try:
                before = (Path(root) / "release/mobile-release.json").read_bytes()
                saved.acquire()
                saved.check()
                self.assertEqual(bytes(saved.raw[:saved.length]), before)
                self.assertEqual((Path(root) / "release/mobile-release.json").read_bytes(), before)
            finally:
                saved.close()
            self.assertTrue(saved.closed)
            saved.clear()
            self.assertEqual(saved.raw, bytearray(len(saved.raw)))

    def test_replaced_same_bytes_or_post_read_changed_config_refuses(self):
        for replacement in (False, True):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory(prefix="mrk-upload-saved-fixture-") as root:
                saved = self.write(root)
                try:
                    saved.acquire()
                    path = Path(root) / "release/mobile-release.json"
                    data = path.read_bytes()
                    if replacement:
                        path.rename(path.with_name("prior-fixture"))
                        path.write_bytes(data)
                    else:
                        path.write_bytes(data.replace(b"com.example.reader", b"com.example.otherx"))
                    with self.assertRaises(wire.ProtocolError):
                        saved.check()
                finally:
                    saved.close()
                self.assertTrue(path.exists())  # No project-file cleanup/adoption.

    def test_root_and_release_link_never_become_saved_authority(self):
        with tempfile.TemporaryDirectory(prefix="mrk-upload-saved-fixture-") as root:
            saved = self.write(root)
            saved.expected = replace(saved.expected, root_identity=(1, 2, 3, 4, 5))
            try:
                with self.assertRaises(wire.ProtocolError):
                    saved.acquire()
            finally:
                saved.close()
        with tempfile.TemporaryDirectory(prefix="mrk-upload-saved-fixture-") as root:
            saved = self.write(root)
            release = Path(root) / "release"
            release.rename(Path(root) / "other-fixture")
            release.symlink_to("other-fixture", target_is_directory=True)
            try:
                with self.assertRaises(OSError):
                    saved.acquire()
            finally:
                saved.close()

    def test_post_read_drift_and_original_close_unknown_do_not_publish_closed(self):
        with tempfile.TemporaryDirectory(prefix="mrk-upload-saved-fixture-") as root:
            saved = self.write(root)
            path = Path(root) / "release/mobile-release.json"
            original_read = os.readv
            def drift(fd, buffers):
                result = original_read(fd, buffers)
                path.write_bytes(path.read_bytes() + b" ")
                return result
            try:
                with patch("mobile_release._desktop_upload_key_saved.os.readv", side_effect=drift):
                    with self.assertRaises(wire.ProtocolError):
                        saved.acquire()
            finally:
                saved.close()
        with tempfile.TemporaryDirectory(prefix="mrk-upload-saved-fixture-") as root:
            saved = self.write(root)
            saved.acquire()
            original_close = saved.file.close
            def returned_but_unknown():
                original_close()  # The synthetic fixture actually settles its FD.
                raise OSError("synthetic missing close acknowledgement")
            with patch.object(saved.file, "close", side_effect=returned_but_unknown):
                with self.assertRaises(OSError):
                    saved.close()
            self.assertFalse(saved.closed)
            self.assertTrue(saved.unknown)
            self.assertEqual(saved.release.close_state, "CLOSED")
            self.assertTrue(all(slot.close_state == "CLOSED" for slot in saved.root.slots))
            with self.assertRaises(wire.ProtocolError):
                saved.clear()


if __name__ == "__main__":
    unittest.main()
