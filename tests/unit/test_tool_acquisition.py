"""Tiny synthetic files/archives and a fake native book; NOT native acceptance.

No real supplier archive, downloader, TLS connection, executable or installation
is used. PublicVendorTransfer is replaced before every service run. Production
descriptor/cancellation/ZIP/tar code is used on task-owned temporary fixtures.
"""
from dataclasses import replace
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from mobile_release._tool_acquisition_spec import (AcquisitionError, CHUNK, COMPONENTS, Component,
    canonical, decode_manifest, relative)
from mobile_release._tool_acquisition_files import OutputTree, directory_identity
from mobile_release.tool_acquisition import Admission, LOOKUP_SCOPE, ToolAcquisition


def fixtures(*, jdk_mode=0o644):
    archives, payloads = [], {}
    for component in COMPONENTS:
        content = ("Synthetic, inert fixture for " + component.value + "\n").encode("ascii")
        if component is Component.JDK:
            wrapper, name, destination, file_mode = "jdk-17.0.0+0", "jdk-17.0.0+0/Contents/Home/release", "Contents/Home/release", jdk_mode
            url = "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.0%2B0/OpenJDK17U-jdk_aarch64_mac_hotspot_17.0.0_0.tar.gz"
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                item = tarfile.TarInfo(wrapper)
                item.type, item.mode = tarfile.DIRTYPE, 0o2755
                tar.addfile(item)
                item = tarfile.TarInfo(name)
                item.mode, item.size = file_mode, len(content)
                tar.addfile(item, io.BytesIO(content))
            data = gzip.compress(output.getvalue(), mtime=0)
            directory_mode = 0o42755
        else:
            if component is Component.SDK_PLATFORM:
                wrapper, name, destination, file_mode = None, "android-35/source.properties", "platforms/android-35/source.properties", 0o644
                url = "https://dl.google.com/android/repository/platform-35_r02.zip"
            elif component is Component.SDK_BUILD_TOOLS:
                wrapper, name, destination, file_mode = None, "android-15/source.properties", "build-tools/35.0.0/source.properties", 0o644
                url = "https://dl.google.com/android/repository/build-tools_r35_macosx.zip"
            else:
                wrapper, name, destination, file_mode = "gradle-8.0", "gradle-8.0/bin/gradle", "bin/gradle", 0o755
                url = "https://github.com/gradle/gradle-distributions/releases/download/v8.0/gradle-8.0-bin.zip"
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
                if wrapper:
                    item = zipfile.ZipInfo(wrapper + "/")
                    item.create_system, item.external_attr = 3, (0o40755 << 16) | 0x10
                    zipped.writestr(item, b"")
                item = zipfile.ZipInfo(name)
                item.create_system, item.external_attr, item.compress_type = 3, (stat.S_IFREG | file_mode) << 16, zipfile.ZIP_DEFLATED
                zipped.writestr(item, content)
            data, directory_mode = output.getvalue(), 0o40755
        members = []
        if wrapper:
            members.append({"name": wrapper, "kind": "directory", "archiveMode": directory_mode,
                "bytes": 0, "sha256": None, "sourceRelative": None, "sourceMode": None})
        members.append({"name": name, "kind": "file", "archiveMode": stat.S_IFREG | file_mode,
            "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
            "sourceRelative": destination, "sourceMode": file_mode})
        parents = [{"relative": destination.rsplit("/", 1)[0], "mode": 0o755}] if component.group == "sdk" else []
        archives.append({"component": component.value, "url": url, "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "expandedBytes": len(content), "members": members, "parents": parents})
        payloads[component] = data
    return {"schemaVersion": 1, "profile": "macos-arm64", "referenceSha256": "a" * 64, "archives": archives}, payloads


class FixtureBook:
    """Test double; transitions are NOT original native process receipts."""
    def __init__(self):
        self.entries = {}


class FixtureOwner:
    cancellation = None

    def __init__(self, root, manifest, *, name="operation1", missing=COMPONENTS, book=None):
        self.root, self.manifest = root, canonical(manifest)
        parsed = decode_manifest(self.manifest)
        self.book = FixtureBook() if book is None else book
        self.admission = Admission(name, "b" * 64, parsed.profile, parsed.reference_sha256, parsed.projection_sha256,
            1, root, directory_identity(root.stat()), tuple(missing), tuple(part for part in COMPONENTS if part not in missing),
            True, LOOKUP_SCOPE, time.monotonic() + 60)
        self.stale, self.claimed, self.ca_calls, self.checks = False, False, 0, 0
        self.retained = []

    def claim(self):
        if self.claimed:
            raise AcquisitionError("already-used")
        self.claimed = True
        if any(state != "settled" for _, state in self.book.entries.values()):
            raise AcquisitionError("recovery-required")
        self.checkpoint()
        return self.admission

    def checked_manifest(self):
        return self.manifest

    def checkpoint(self):
        self.checks += 1
        if self.stale:
            raise AcquisitionError("stale")

    def admit_cache_origin(self, operation, digest):
        if self.book.entries.get(operation) != (digest, "settled"):
            raise AcquisitionError("recovery-required")

    def record_intent(self, data):
        assert not (self.root / ("tool-" + self.admission.operation_id)).exists()
        assert self.admission.operation_id not in self.book.entries
        self.book.entries[self.admission.operation_id] = (hashlib.sha256(data).hexdigest(), "pending")

    def public_ca(self):
        self.ca_calls += 1
        return b"inert synthetic CA placeholder; live factory is never called"

    def retain_unknown(self, original):
        self.retained.append(original)
        key = self.admission.operation_id
        previous = self.book.entries.get(key, ("0" * 64, "pending"))
        self.book.entries[key] = (previous[0], "unknown")

    def settle_for_test(self, service):
        assert service.files.settled and not service.unknown
        key = self.admission.operation_id
        self.book.entries[key] = (self.book.entries[key][0], "settled")


def fake_transfer(payloads, calls, *, after=None):
    class Transfer:
        unknown = False

        def __init__(self, *, profile, ca_pem, deadline, checkpoint):
            self.check = checkpoint

        def copy(self, archive, write):
            calls.append(archive.component)
            data = payloads[archive.component]
            for offset in range(0, len(data), CHUNK):
                self.check()
                write(data[offset:offset + CHUNK])
            if after is not None:
                after(archive)
    return Transfer


class ToolAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-tools-synthetic-")
        self.root = Path(self.temporary.name) / "cache"
        self.root.mkdir(mode=0o700)
        self.manifest, self.payloads = fixtures()
        self.calls = []

    def tearDown(self):
        # Test-owned inert fixtures only. Production service has no deletion API.
        self.temporary.cleanup()

    def run_service(self, owner, *, after=None, transfer=None):
        service = ToolAcquisition(owner)
        with patch("mobile_release.tool_acquisition.PublicVendorTransfer",
                   fake_transfer(self.payloads, self.calls, after=after) if transfer is None else transfer):
            result = service.run()
        return service, result

    def test_full_staging_uses_actual_bounded_extractors_and_only_manual_picker_offer(self):
        owner = FixtureOwner(self.root, self.manifest)
        service, offer = self.run_service(owner)
        self.assertEqual(self.calls, list(COMPONENTS))
        self.assertTrue(service.files.settled)
        self.assertEqual(owner.book.entries["operation1"][1], "pending")  # Child return is NOT native finality.
        data = offer.to_data()
        self.assertEqual(data["assurance"], {"nativeFinality": False, "registered": False, "readyToBuild": False})
        self.assertEqual([item["next"] for item in data["groups"]], ["choose-native-source"] * 3)
        for archive in decode_manifest(owner.manifest).archives:
            for member in archive.members:
                if member.kind == "file":
                    path = self.root / offer.cache_job / "sources" / archive.component.folder / member.source_relative
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), member.sha256)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), member.source_mode)
        with self.assertRaises(AcquisitionError) as error:
            service.run()
        self.assertEqual(error.exception.reason, "already-used")

    def test_verified_archive_cache_is_first_and_never_borrows_ca_or_opens_network(self):
        owner = FixtureOwner(self.root, self.manifest)
        first, _ = self.run_service(owner)
        owner.settle_for_test(first)
        self.calls.clear()
        second_owner = FixtureOwner(self.root, self.manifest, name="operation2", book=owner.book)
        second, offer = self.run_service(second_owner, transfer=lambda **_: self.fail("cache hit constructed downloader"))
        self.assertEqual(self.calls, [])
        self.assertEqual(second_owner.ca_calls, 0)
        self.assertEqual(offer.reused_archives, COMPONENTS)
        self.assertEqual(offer.downloaded_archives, ())
        self.assertTrue(second.files.settled)

    def test_exact_readonly_source_mode_survives_extraction_and_final_reinspection(self):
        self.manifest, self.payloads = fixtures(jdk_mode=0o444)
        owner = FixtureOwner(self.root, self.manifest, missing=(Component.JDK,))
        service, offer = self.run_service(owner)
        member = decode_manifest(owner.manifest).archives[0].members[-1]
        path = self.root / offer.cache_job / "sources/jdk.jdk" / member.source_relative
        self.assertEqual(member.source_mode, 0o444)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), member.sha256)
        self.assertTrue(service.files.settled)
        self.assertEqual(self.calls, [Component.JDK])
        self.assertFalse(offer.to_data()["assurance"]["nativeFinality"])
        owner.settle_for_test(service)
        self.calls.clear()
        next_owner = FixtureOwner(self.root, self.manifest, name="operation2", missing=(Component.JDK,), book=owner.book)
        changed = self.root / "tool-operation2/sources/jdk.jdk" / member.source_relative
        original_verify = OutputTree.verify

        def changed_mode(tree):
            changed.chmod(0o644)  # A later external edit, never repaired by the service.
            return original_verify(tree)

        with patch.object(OutputTree, "verify", changed_mode), self.assertRaises(AcquisitionError):
            self.run_service(next_owner, transfer=lambda **_: self.fail("cache hit constructed downloader"))
        self.assertEqual(self.calls, [])
        self.assertEqual(stat.S_IMODE(changed.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
        self.assertFalse((self.root / "tool-operation2/result.json").exists())

    def test_existing_compatible_tools_mean_no_cache_open_or_download(self):
        owner = FixtureOwner(self.root, self.manifest, missing=())
        with patch("mobile_release.tool_acquisition.Files", side_effect=AssertionError("cache opened")):
            service, offer = self.run_service(owner, transfer=lambda **_: self.fail("downloader constructed"))
        self.assertIsNone(service.files)
        self.assertEqual(offer.groups, ())
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(owner.book.entries, {})

    def test_missing_only_skips_known_sdk_component_and_does_not_call_partial_sdk_complete(self):
        owner = FixtureOwner(self.root, self.manifest, missing=(Component.SDK_PLATFORM,))
        _, offer = self.run_service(owner)
        self.assertEqual(self.calls, [Component.SDK_PLATFORM])
        self.assertFalse(offer.groups[0].all_required_components_staged)
        self.assertEqual(offer.to_data()["groups"][0]["next"], "complete-sdk-manually")
        self.assertFalse((self.root / offer.cache_job / "sources/android-sdk/build-tools").exists())

    def test_stale_partial_host_and_unknown_tool_census_fail_before_cache_writes(self):
        for changed in ({"census_complete": False}, {"profile": "linux-x64"},
                        {"compatible": ()}, {"cache_generation": 0}, {"lookup_scope": "entire-computer"},
                        {"context_sha256": "wrong"}, {"reference_sha256": "d" * 64}, {"projection_sha256": "e" * 64}):
            owner = FixtureOwner(self.root, self.manifest, missing=(Component.JDK,))
            owner.admission = replace(owner.admission, **changed)
            with self.subTest(changed=changed), self.assertRaises(AcquisitionError):
                self.run_service(owner)
            self.assertEqual(list(self.root.iterdir()), [])
            self.assertEqual(self.calls, [])
        owner = FixtureOwner(self.root, self.manifest)
        owner.stale = True
        with self.assertRaises(AcquisitionError):
            self.run_service(owner)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_insufficient_space_does_not_create_pending_intent_or_job(self):
        owner = FixtureOwner(self.root, self.manifest)
        with patch("mobile_release.tool_acquisition.os.fstatvfs", return_value=SimpleNamespace(f_frsize=4096, f_bavail=1)):
            with self.assertRaises(AcquisitionError) as error:
                self.run_service(owner)
        self.assertEqual(error.exception.reason, "disk-space")
        self.assertEqual(owner.book.entries, {})
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(self.calls, [])

    def test_truncated_or_tampered_download_never_extracts_or_registers(self):
        for kind in ("truncated", "tampered", "extra"):
            with self.subTest(kind=kind):
                root = self.root / kind
                root.mkdir(mode=0o700)
                owner = FixtureOwner(root, self.manifest, missing=(Component.GRADLE,))
                payloads = dict(self.payloads)
                data = payloads[Component.GRADLE]
                payloads[Component.GRADLE] = data[:-1] if kind == "truncated" else b"!" + data[1:] if kind == "tampered" else data + b"!"
                service = ToolAcquisition(owner)
                with patch("mobile_release.tool_acquisition.PublicVendorTransfer", fake_transfer(payloads, [])):
                    with self.assertRaises(AcquisitionError) as error:
                        service.run()
                self.assertIn(error.exception.reason, ("archive-digest", "framing"))
                self.assertTrue(service.files.settled)
                self.assertFalse((root / "tool-operation1/result.json").exists())
                self.assertEqual(list((root / "tool-operation1/sources").iterdir()), [])

    def test_cache_rehash_detects_corruption_and_does_not_redownload_over_it(self):
        owner = FixtureOwner(self.root, self.manifest)
        first, _ = self.run_service(owner)
        owner.settle_for_test(first)
        path = self.root / "tool-operation1/gradle.archive"
        original = path.read_bytes()
        path.write_bytes(b"!" + original[1:])
        self.calls.clear()
        second_owner = FixtureOwner(self.root, self.manifest, name="operation2", book=owner.book)
        with self.assertRaises(AcquisitionError) as error:
            self.run_service(second_owner)
        self.assertEqual(error.exception.reason, "archive-digest")
        self.assertEqual(self.calls, [])
        self.assertFalse((self.root / "tool-operation2").exists())
        self.assertEqual(path.read_bytes(), b"!" + original[1:])

    def test_pending_and_restart_unknown_remain_fences_even_with_absent_target(self):
        for state in ("pending", "unknown"):
            owner = FixtureOwner(self.root, self.manifest)
            owner.book.entries["older"] = ("c" * 64, state)
            with self.subTest(state=state), self.assertRaises(AcquisitionError) as error:
                self.run_service(owner)
            self.assertEqual(error.exception.reason, "recovery-required")
            self.assertEqual(list(self.root.iterdir()), [])
            self.assertEqual(self.calls, [])

    def test_local_result_json_cannot_fabricate_original_settled_cache(self):
        owner = FixtureOwner(self.root, self.manifest)
        first, _ = self.run_service(owner)
        self.assertTrue(first.files.settled)
        # Fresh native book deliberately has no original producer authority.
        second_owner = FixtureOwner(self.root, self.manifest, name="operation2")
        self.calls.clear()
        with self.assertRaises(AcquisitionError) as error:
            self.run_service(second_owner)
        self.assertEqual(error.exception.reason, "recovery-required")
        self.assertEqual(self.calls, [])
        self.assertFalse((self.root / "tool-operation2").exists())

    def test_context_change_after_download_preserves_archive_and_blocks_extraction(self):
        owner = FixtureOwner(self.root, self.manifest, missing=(Component.GRADLE,))
        service = ToolAcquisition(owner)
        with patch("mobile_release.tool_acquisition.PublicVendorTransfer",
                   fake_transfer(self.payloads, self.calls, after=lambda _: setattr(owner, "stale", True))):
            with self.assertRaises(AcquisitionError) as error:
                service.run()
        self.assertEqual(error.exception.reason, "stale")
        self.assertTrue(service.files.settled)
        self.assertTrue((self.root / "tool-operation1/gradle.archive").is_file())
        self.assertFalse((self.root / "tool-operation1/result.json").exists())

    def test_cancel_after_transfer_settles_original_fds_but_retains_pending_native_book(self):
        owner = FixtureOwner(self.root, self.manifest, missing=(Component.GRADLE,))
        service = ToolAcquisition(owner)
        def cancel(_):
            service.guard.cancelled = True
        with patch("mobile_release.tool_acquisition.PublicVendorTransfer", fake_transfer(self.payloads, self.calls, after=cancel)):
            with self.assertRaises(KeyboardInterrupt):
                service.run()
        self.assertTrue(service.files.settled)
        self.assertEqual(owner.book.entries["operation1"][1], "pending")
        self.assertFalse((self.root / "tool-operation1/result.json").exists())

    def test_changed_output_fails_final_exact_hash_inspection(self):
        owner = FixtureOwner(self.root, self.manifest, missing=(Component.GRADLE,))
        original = OutputTree.verify
        def corrupt(tree):
            path = self.root / "tool-operation1/sources/gradle/bin/gradle"
            path.write_bytes(b"changed")
            original(tree)
        with patch.object(OutputTree, "verify", corrupt), self.assertRaises(AcquisitionError):
            self.run_service(owner)
        self.assertFalse((self.root / "tool-operation1/result.json").exists())

    def test_cache_root_symlink_and_foreign_entries_never_follow_or_delete(self):
        target = self.root.parent / "outside"
        target.mkdir(mode=0o700)
        (target / "canary").write_bytes(b"must stay")
        (self.root / "tool-foreign").symlink_to(target, target_is_directory=True)
        owner = FixtureOwner(self.root, self.manifest)
        with self.assertRaises(AcquisitionError):
            self.run_service(owner)
        self.assertEqual((target / "canary").read_bytes(), b"must stay")
        self.assertEqual(self.calls, [])

    def test_actual_zip_symlink_traversal_duplicate_and_bomb_rejected_before_output(self):
        for kind in ("symlink", "traversal", "duplicate", "deflate-bomb"):
            with self.subTest(kind=kind):
                root = self.root / kind
                root.mkdir(mode=0o700)
                manifest, payloads = fixtures()
                output = io.BytesIO()
                with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
                    wrapper = zipfile.ZipInfo("gradle-8.0/")
                    wrapper.create_system, wrapper.external_attr = 3, (0o40755 << 16) | 0x10
                    zipped.writestr(wrapper, b"")
                    item = zipfile.ZipInfo("../outside" if kind == "traversal" else "gradle-8.0/bin/gradle")
                    item.create_system, item.compress_type = 3, zipfile.ZIP_DEFLATED
                    item.external_attr = (0o120777 if kind == "symlink" else 0o100755) << 16
                    zipped.writestr(item, b"0" * (128 * 1024) if kind == "deflate-bomb" else b"unsafe synthetic fixture")
                    if kind == "duplicate":
                        # Case-fold duplicate, without zipfile's noisy exact-name warning.
                        item = zipfile.ZipInfo("GRADLE-8.0/")
                        item.create_system, item.external_attr = 3, (0o40755 << 16) | 0x10
                        zipped.writestr(item, b"")
                data = bytearray(output.getvalue())
                if kind == "deflate-bomb":
                    declared = manifest["archives"][3]["members"][-1]["bytes"]
                    # Matching tiny declared sizes in original local+central
                    # metadata, but the actual deflate expands far beyond them.
                    local = data.find(b"PK\x03\x04", 4)
                    central = data.find(b"PK\x01\x02")
                    central = data.find(b"PK\x01\x02", central + 4)
                    struct.pack_into("<I", data, local + 22, declared)
                    struct.pack_into("<I", data, central + 24, declared)
                payloads[Component.GRADLE] = bytes(data)
                # Synthetic wrong archive pin admits the outer bytes solely to
                # exercise independent strict layout/member checks. No native
                # compiled supplier pin is changed or loaded by this test.
                manifest["archives"][3]["bytes"] = len(data)
                manifest["archives"][3]["sha256"] = hashlib.sha256(data).hexdigest()
                owner = FixtureOwner(root, manifest, missing=(Component.GRADLE,))
                with self.assertRaises(AcquisitionError):
                    self.run_service(owner, transfer=fake_transfer(payloads, []))
                self.assertFalse((root / "tool-operation1/result.json").exists())
                self.assertEqual(list((root / "tool-operation1/sources").iterdir()), [])
                self.assertFalse((root / "outside").exists())

    def test_tar_links_and_oversized_pax_or_gnu_metadata_refuse_before_allocating_payload(self):
        for kind in ("symlink", "hardlink", "pax-size", "gnu-size"):
            with self.subTest(kind=kind):
                root = self.root / kind
                root.mkdir(mode=0o700)
                manifest, payloads = fixtures()
                item = tarfile.TarInfo("jdk-17.0.0+0/Contents/Home/release")
                if kind in ("symlink", "hardlink"):
                    item.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                    item.linkname = "../../must-not-follow"
                else:
                    item.type = tarfile.XHDTYPE if kind == "pax-size" else tarfile.GNUTYPE_LONGNAME
                    item.size = 2 * 1024 * 1024 * 1024
                data = gzip.compress(item.tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 1024, mtime=0)
                payloads[Component.JDK] = data
                manifest["archives"][0]["bytes"] = len(data)
                manifest["archives"][0]["sha256"] = hashlib.sha256(data).hexdigest()
                owner = FixtureOwner(root, manifest, missing=(Component.JDK,))
                with self.assertRaises(AcquisitionError):
                    self.run_service(owner, transfer=fake_transfer(payloads, []))
                self.assertFalse((root / "tool-operation1/result.json").exists())
                self.assertEqual(list((root / "tool-operation1/sources").iterdir()), [])

    def test_interrupted_durable_intent_retains_unknown_before_target_exists(self):
        owner = FixtureOwner(self.root, self.manifest, missing=(Component.GRADLE,))
        record = owner.record_intent
        def interrupted(data):
            record(data)
            raise KeyboardInterrupt
        owner.record_intent = interrupted
        service = ToolAcquisition(owner)
        with patch("mobile_release.tool_acquisition.PublicVendorTransfer", fake_transfer(self.payloads, self.calls)):
            with self.assertRaises(KeyboardInterrupt):
                service.run()
        self.assertTrue(service.unknown)
        self.assertEqual(owner.retained, [service])
        self.assertEqual(owner.book.entries["operation1"][1], "unknown")
        self.assertEqual(list(self.root.iterdir()), [])
        second_owner = FixtureOwner(self.root, self.manifest, name="operation2", book=owner.book)
        with self.assertRaises(AcquisitionError) as error:
            self.run_service(second_owner)
        self.assertEqual(error.exception.reason, "recovery-required")
        self.assertEqual(self.calls, [])

    def test_ambiguous_original_close_retires_number_and_keeps_replacement_untouched(self):
        owner = FixtureOwner(self.root, self.manifest, missing=(Component.GRADLE,))
        service = ToolAcquisition(owner)
        original_close = os.close
        replacement = []
        consumed = []
        canary = self.root.parent / "close-canary"
        canary.write_bytes(b"independent synthetic descriptor")
        original_path = self.root / "tool-operation1/gradle.archive"
        def interrupted_close(fd):
            if not consumed and original_path.exists() and os.fstat(fd).st_ino == original_path.stat().st_ino:
                consumed.append(fd)
                original_close(fd)
                number = os.open(canary, os.O_RDONLY | os.O_CLOEXEC)
                replacement.append(number)
                self.assertEqual(number, fd)
                raise KeyboardInterrupt
            original_close(fd)
        try:
            with patch("mobile_release.tool_acquisition.PublicVendorTransfer", fake_transfer(self.payloads, self.calls)), \
                    patch("mobile_release.build_inputs.os.close", interrupted_close):
                with self.assertRaises(KeyboardInterrupt):
                    service.run()
            self.assertTrue(service.unknown)
            self.assertEqual(owner.retained, [service])
            self.assertEqual(owner.book.entries["operation1"][1], "unknown")
            self.assertEqual(os.read(replacement[0], 128), b"independent synthetic descriptor")
            self.assertFalse((self.root / "tool-operation1/result.json").exists())
        finally:
            for number in replacement:
                original_close(number)  # This test owns the replacement, not Files.


class ManifestTests(unittest.TestCase):
    def test_exact_bytes_and_four_component_closed_roster(self):
        value, _ = fixtures()
        data = canonical(value)
        manifest = decode_manifest(data)
        self.assertEqual(manifest.projection_sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(tuple(item.component for item in manifest.archives), COMPONENTS)
        value["archives"].append(value["archives"][0])
        with self.assertRaises(AcquisitionError):
            decode_manifest(canonical(value))

    def test_traversal_links_duplicates_case_nfc_and_modes_are_closed(self):
        for path in ("../file", "/file", "C:/file", "a\\b", "a/./b", "a//b", "a/..", "a/", "a. ", "a\0b", "e\u0301", "\ud800"):
            with self.subTest(path=repr(path)), self.assertRaises(AcquisitionError):
                relative(path)
        for field, changed in (("kind", "alias"), ("archiveMode", 0o120777), ("archiveMode", 0o104755),
                               ("sourceMode", 0o777), ("sourceMode", True), ("bytes", 2**32)):
            value, _ = fixtures()
            value["archives"][3]["members"][-1][field] = changed
            with self.subTest(field=field, changed=changed), self.assertRaises(AcquisitionError):
                decode_manifest(canonical(value))
        for spelling in ("GRADLE-8.0", "gradle-8.0"):
            value, _ = fixtures()
            item = dict(value["archives"][3]["members"][0])
            item["name"] = spelling
            value["archives"][3]["members"].append(item)
            with self.assertRaises(AcquisitionError):
                decode_manifest(canonical(value))

    def test_invalid_types_overrides_and_ratio_fail_with_fixed_redacted_errors(self):
        for field, changed in (("profile", []), ("schemaVersion", True), ("referenceSha256", "secret-canary"), ("url", "https://example.invalid/secret-canary")):
            value, _ = fixtures()
            if field == "url":
                value["archives"][0][field] = changed
            else:
                value[field] = changed
            with self.assertRaises(AcquisitionError) as error:
                decode_manifest(canonical(value))
            self.assertNotIn("secret-canary", str(error.exception))
        value, _ = fixtures()
        value["archives"][0]["bytes"] = 1
        with self.assertRaises(AcquisitionError) as error:
            decode_manifest(canonical(value))
        self.assertEqual(error.exception.reason, "limit")
        with self.assertRaises(AcquisitionError):
            decode_manifest(b'{"schemaVersion":1,"schemaVersion":1}')


if __name__ == "__main__":
    unittest.main()
