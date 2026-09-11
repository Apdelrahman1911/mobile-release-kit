"""Deterministic work/timeout injection through real artifact inspection paths."""
from __future__ import annotations

import bisect
import os
import plistlib
import struct
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from mobile_release import ios, ios_artifacts, macho
from mobile_release.config import ReleaseVersion
from mobile_release.errors import ValidationError
from mobile_release.inspection import InspectionDeadline, MAX_INSPECTION_SECONDS
from mobile_release.ios_artifacts import inspect_ios_artifact_set, snapshot_ios_artifacts

from .ios_artifact_helpers import artifact_set, fat_image, native_image, packed_artifact_set, table_image
from .ios_profile_helpers import framed_cms, pem


class InspectionBudgetTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-inspection-budget-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "native"

    @staticmethod
    def table_bounds(raw):
        size = struct.unpack_from("<I", raw, 20)[0]
        return struct.unpack_from("<II", raw, 32 + size - 8)

    def test_absolute_deadline_is_read_only_and_never_renewed_by_observation(self):
        with patch("mobile_release.inspection.time.monotonic", return_value=10.25) as clock:
            deadline = InspectionDeadline()
            original = 10.25 + MAX_INSPECTION_SECONDS
            self.assertEqual(deadline.expires_at, original)
            for value in (original + 1, float("inf")):
                with self.subTest(value=value), self.assertRaises(AttributeError):
                    deadline.expires_at = value
            with self.assertRaises(AttributeError):
                del deadline.expires_at
            clock.return_value = original - .25
            deadline.check()
            self.assertEqual(deadline.expires_at, original)
            clock.return_value = original
            with self.assertRaisesRegex(ValidationError, "shared time bound"):
                deadline.check()
            self.assertEqual(deadline.expires_at, original)

    def test_many_sections_and_records_use_real_indexed_lookup_and_chunked_reads(self):
        self.path.write_bytes(table_image(sections=4096, records=20000))
        begin, size = self.table_bounds(self.path.read_bytes())
        reads, lookups = [], []
        read = os.pread

        def observed_read(fd, count, offset):
            if begin <= offset < begin + size:
                reads.append((offset, count))
            return read(fd, count, offset)

        def observed_lookup(starts, offset):
            lookups.append(len(starts))
            return bisect.bisect_right(starts, offset)  # Real logarithmic search, not a stub.

        with patch("mobile_release.macho.os.pread", side_effect=observed_read), patch("mobile_release.macho.bisect_right", side_effect=observed_lookup):
            self.assertEqual(len(macho.inspect_macho(self.path)), 1)
        self.assertEqual(lookups, [4096] * 20000)
        self.assertEqual(sum(length for _offset, length in reads), size)
        self.assertEqual(len(reads), (size + macho.TABLE_CHUNK_BYTES - 1) // macho.TABLE_CHUNK_BYTES)

    def test_table_record_cap_checked_before_payload_and_valid_exact_cap(self):
        read, reads = os.pread, []

        def observed(fd, size, offset):
            reads.append(offset)
            return read(fd, size, offset)

        with patch("mobile_release.macho.MAX_DATA_IN_CODE_RECORDS", 32):
            self.path.write_bytes(table_image(sections=4, records=32))
            self.assertEqual(len(macho.inspect_macho(self.path)), 1)
            raw = table_image(sections=4, records=33)
            self.path.write_bytes(raw)
            table, _size = self.table_bounds(raw)
            with patch("mobile_release.macho.os.pread", side_effect=observed), self.assertRaisesRegex(ValidationError, "record count"):
                macho.inspect_macho(self.path)
            self.assertTrue(reads)
            self.assertTrue(all(offset < table for offset in reads))

    def test_table_entire_range_kind_and_endpoints_still_checked(self):
        source = table_image(sections=4, records=2)
        table, _size = self.table_bounds(source)
        last, _length, _kind = struct.unpack_from("<IHH", source, table)
        for begin, length, kind, valid in ((last, 1, 1, True), (last - 3, 1, 5, True),
                                            (last, 0, 1, False), (last, 1, 0, False),
                                            (last - 4, 1, 1, False), (last + 1, 1, 1, False),
                                            (last - 1, 2, 1, False), (last, 2, 1, False)):
            with self.subTest(begin=begin, length=length, kind=kind):
                raw = bytearray(source)
                struct.pack_into("<IHH", raw, table, begin, length, kind)
                self.path.write_bytes(raw)
                if valid:
                    self.assertEqual(len(macho.inspect_macho(self.path)), 1)
                else:
                    with self.assertRaisesRegex(ValidationError, "outside a code section"):
                        macho.inspect_macho(self.path)

    def test_parser_deadline_inside_command_table_and_hash_closes_descriptor(self):
        raw = table_image(sections=1024, records=20000)
        table, _size = self.table_bounds(raw)
        self.path.write_bytes(raw)
        read = os.pread
        for boundary in ("commands", "table", "hash"):
            fds = []
            with self.subTest(boundary=boundary), patch("mobile_release.inspection.time.monotonic", return_value=0) as clock:
                deadline = InspectionDeadline()

                def observed(fd, count, offset):
                    fds.append(fd)
                    result = read(fd, count, offset)
                    if ((boundary == "commands" and offset == 32) or
                            (boundary == "table" and offset == table) or
                            (boundary == "hash" and 1024 < offset < table and count > 1024)):
                        clock.return_value = MAX_INSPECTION_SECONDS
                    return result

                with patch("mobile_release.macho.os.pread", side_effect=observed), self.assertRaisesRegex(ValidationError, "shared time bound"):
                    macho.inspect_macho(self.path, deadline=deadline)
            self.assertTrue(fds)
            with self.assertRaises(OSError):
                os.fstat(fds[-1])

    def test_fat_slices_cannot_renew_deadline(self):
        self.path.write_bytes(fat_image([native_image(), native_image(subtype=2)]))
        thin, seen = macho._thin, []
        with patch("mobile_release.inspection.time.monotonic", return_value=0) as clock:
            deadline = InspectionDeadline()

            def first(reader, *, dsym):
                seen.append(reader.deadline)
                result = thin(reader, dsym=dsym)
                clock.return_value = MAX_INSPECTION_SECONDS
                return result

            with patch("mobile_release.macho._thin", side_effect=first), self.assertRaisesRegex(ValidationError, "shared time bound"):
                macho.inspect_macho(self.path, deadline=deadline)
        self.assertEqual(seen, [deadline])

    def test_expired_budget_is_not_reset_by_entry_points_or_cached_unpack(self):
        paths = artifact_set(self.root)
        original = {name: path.read_bytes() for name, path in paths.items() if path.is_file()}
        with patch("mobile_release.inspection.time.monotonic", return_value=0) as clock:
            with snapshot_ios_artifacts(paths) as snapshot:
                snapshot.unpack("ios-ipa")
                self.path.write_bytes(native_image())
                info = self.root / "Info.plist"
                info.write_bytes(plistlib.dumps({"x": 1}))
                clock.return_value = MAX_INSPECTION_SECONDS
                operations = (
                    lambda: snapshot.unpack("ios-ipa"),
                    snapshot.assert_unchanged,
                    lambda: macho.inspect_macho(self.path, deadline=snapshot.deadline),
                    lambda: ios_artifacts.typed_plist(info, deadline=snapshot.deadline),
                    lambda: ios_artifacts.safe_extract_zip(paths["ios-ipa"], self.root / "output", deadline=snapshot.deadline),
                )
                for operation in operations:
                    with self.assertRaisesRegex(ValidationError, "shared time bound"):
                        operation()
                temporary = snapshot.temporary
            self.assertFalse(temporary.exists(), "expiry cannot block snapshot cleanup")
        self.assertEqual(original, {name: paths[name].read_bytes() for name in original})

    def test_later_nested_images_keep_snapshot_deadline_and_clean_up(self):
        paths = artifact_set(self.root)
        real, seen = macho.inspect_macho, []
        with patch("mobile_release.inspection.time.monotonic", return_value=0) as clock:
            with self.assertRaisesRegex(ValidationError, "shared time bound"), snapshot_ios_artifacts(paths) as snapshot:
                temporary = snapshot.temporary

                def first(path, *, deadline, **kwargs):
                    self.assertIs(deadline, snapshot.deadline)
                    seen.append(path)
                    result = real(path, deadline=deadline, **kwargs)
                    clock.return_value = MAX_INSPECTION_SECONDS
                    return result

                with patch("mobile_release.ios_artifacts.inspect_macho", side_effect=first):
                    inspect_ios_artifact_set(snapshot, expected_bundle_id="com.example.reader", release=ReleaseVersion("1.2.3", 42), symbols_policy="retain")
            self.assertFalse(temporary.exists())
        self.assertEqual(len(seen), 1)

    def test_timeout_during_copy_closes_source_and_removes_private_outputs(self):
        paths = packed_artifact_set(self.root)
        read, input_file = os.read, ios_artifacts._input
        temporary_paths, descriptors = [], []
        with patch("mobile_release.inspection.time.monotonic", return_value=0) as clock:
            def copying(path, target=None, **kwargs):
                temporary_paths.append(target.parent.parent)
                return input_file(path, target, **kwargs)

            def expired_read(fd, count):
                descriptors.append(fd)
                result = read(fd, count)
                clock.return_value = MAX_INSPECTION_SECONDS
                return result

            with patch("mobile_release.ios_artifacts._input", side_effect=copying), patch("mobile_release.ios_artifacts.os.read", side_effect=expired_read), self.assertRaisesRegex(ValidationError, "shared time bound"):
                with snapshot_ios_artifacts(paths):
                    self.fail("expired snapshot must not be yielded")
            self.assertTrue(temporary_paths)
            self.assertTrue(all(not path.exists() for path in temporary_paths))
            with self.assertRaises(OSError):
                os.fstat(descriptors[0])

    def test_zip_directory_and_extraction_share_original_deadline(self):
        paths = packed_artifact_set(self.root)
        entry_offset, member_read = ios_artifacts._zip_entry_offset, zipfile.ZipExtFile.read
        for boundary in ("directory", "extraction"):
            with self.subTest(boundary=boundary), patch("mobile_release.inspection.time.monotonic", return_value=0) as clock:
                with self.assertRaisesRegex(ValidationError, "shared time bound"), snapshot_ios_artifacts(paths) as snapshot:
                    temporary = snapshot.temporary

                    def offset(header, extra, *, deadline):
                        self.assertIs(deadline, snapshot.deadline)
                        value = entry_offset(header, extra, deadline=deadline)
                        if boundary == "directory":
                            clock.return_value = MAX_INSPECTION_SECONDS
                        return value

                    def extraction(member, *args, **kwargs):
                        value = member_read(member, *args, **kwargs)
                        if boundary == "extraction":
                            clock.return_value = MAX_INSPECTION_SECONDS
                        return value

                    with patch("mobile_release.ios_artifacts._zip_entry_offset", side_effect=offset), patch.object(zipfile.ZipExtFile, "read", extraction):
                        snapshot.unpack("ios-archive")
                self.assertFalse(temporary.exists())

    def test_typed_plist_conversion_checks_shared_clock_after_parsing(self):
        info = self.root / "Info.plist"
        info.write_bytes(plistlib.dumps({"nested": {"value": 1}}))
        from mobile_release import ios_entitlements
        require = ios_entitlements._require
        with patch("mobile_release.inspection.time.monotonic", return_value=0) as clock:
            deadline = InspectionDeadline()

            def conversion(condition, message):
                require(condition, message)
                if message == "iOS plist complexity exceeds its bound":
                    clock.return_value = MAX_INSPECTION_SECONDS

            with patch("mobile_release.ios_entitlements._require", side_effect=conversion), self.assertRaisesRegex(ValidationError, "shared time bound"):
                ios_artifacts.typed_plist(info, deadline=deadline)

    def test_native_expiry_stops_next_child_and_preserves_per_child_timeout(self):
        paths = artifact_set(self.root)
        app = paths["ios-archive"] / "Products/Applications/Reader.app"
        with patch("mobile_release.ios.sys.platform", "darwin"), patch("mobile_release.ios.shutil.which", return_value="/fictional/tool"), patch("mobile_release.inspection.time.monotonic", return_value=0) as clock:
            deadline = InspectionDeadline()

            def child(argv, **kwargs):
                self.assertEqual(kwargs["timeout"], 30)
                self.assertEqual(argv[0], "codesign")
                clock.return_value = MAX_INSPECTION_SECONDS
                return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with patch("mobile_release.ios.subprocess.run", side_effect=child) as run, self.assertRaisesRegex(ValidationError, "shared time bound"):
                ios._nested_codesign_identities(app, self.root, deadline=deadline)
            self.assertEqual(run.call_count, 1)
            with patch("mobile_release.ios.subprocess.run") as run:
                for operation in (lambda: ios._profile_details(app / "embedded.mobileprovision", deadline=deadline),
                                  lambda: ios._codesign_entitlements(app, deadline=deadline),
                                  lambda: ios._codesign_fingerprint(app, self.root, deadline=deadline)):
                    with self.assertRaisesRegex(ValidationError, "shared time bound"):
                        operation()
                run.assert_not_called()


class ProfileNativeDeadlineTests(unittest.TestCase):
    """Real CMS framing/file checks, but no process or issuer-policy execution."""

    def test_native_profile_uses_absolute_cutoff_and_existing_twenty_second_cap(self):
        from mobile_release import ios_profile_auth as auth

        now = 8_000_000_000
        certificate = b"\x30\x01\0"
        for cutoff, timeout in ((None, 20), (now + 60_000_000_000, 20), (now + 3_000_000_000, 3)):
            with self.subTest(cutoff=cutoff), tempfile.TemporaryDirectory(prefix="mrk-profile-clock-") as name:
                root = Path(name)
                with patch.object(auth.time, "monotonic_ns", return_value=now) as clock:
                    def native(_argv, **options):
                        self.assertEqual(options["timeout"], timeout)
                        (root / "native-content.bin").write_bytes(b"fictional payload")
                        (root / "native-signer.pem").write_bytes(pem(certificate))
                        clock.return_value = now + 1_000_000_000
                        return types.SimpleNamespace(returncode=0)

                    with patch.object(auth.subprocess, "run", side_effect=native) as run, patch.object(auth, "verify_profile_signer") as trust:
                        kwargs = {} if cutoff is None else {"deadline_ns": cutoff}
                        self.assertEqual(auth.verify_cms(framed_cms(), root, **kwargs), b"fictional payload")
                    self.assertEqual(run.call_count, 1)
                    trust.assert_called_once_with(certificate, (certificate,))

    def test_expiry_before_native_after_native_and_after_trust_vetoes_valid_content(self):
        from mobile_release import ios_profile_auth as auth

        now, cutoff = 8_000_000_000, 11_000_000_000
        for phase in ("before-native", "after-native", "after-trust"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(prefix="mrk-profile-clock-") as name:
                root = Path(name)
                initial = cutoff if phase == "before-native" else now
                with patch.object(auth.time, "monotonic_ns", return_value=initial) as clock:
                    def native(_argv, **options):
                        self.assertEqual(options["timeout"], 3)
                        (root / "native-content.bin").write_bytes(b"fictional payload")
                        (root / "native-signer.pem").write_bytes(pem(b"\x30\x01\0"))
                        if phase == "after-native":
                            clock.return_value = cutoff
                        return types.SimpleNamespace(returncode=0)

                    def policy(*_args):
                        if phase == "after-trust":
                            clock.return_value = cutoff

                    with patch.object(auth.subprocess, "run", side_effect=native) as run, patch.object(auth, "verify_profile_signer", side_effect=policy) as trust:
                        with self.assertRaisesRegex(ValidationError, "authentication timed out"):
                            auth.verify_cms(framed_cms(), root, deadline_ns=cutoff)
                    self.assertEqual(run.call_count, int(phase != "before-native"))
                    self.assertEqual(trust.call_count, int(phase == "after-trust"))


if __name__ == "__main__":
    unittest.main()
