"""Tiny real copy/extraction with a fake native book and fake vendor transport.

No supplier archive, native source/ACL/registration receipt, SDK manager or
network is used. A fixture binding is comparison DATA, not native acceptance.
"""
import copy
from dataclasses import replace
import hashlib
import io
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from mobile_release import _desktop_tool_acquisition_protocol as wire
from mobile_release._tool_acquisition_spec import AcquisitionError, COMPONENTS, Component, canonical, decode_manifest
from mobile_release._tool_acquisition_sdk import CopyBinding, FORMAT, PREFIX, SDK, STAMP, SdkCopy, _Observation, stamp
from mobile_release._tool_acquisition_files import OutputTree
from mobile_release.build_inputs import _Directory
from mobile_release.desktop_tool_acquisition import ToolAcquisitionRun
from mobile_release.tool_acquisition import ToolAcquisition, _Space
from test_tool_acquisition import FixtureOwner, fake_transfer, fixtures
from test_tool_acquisition_partial import subset_request, staged
from test_desktop_tool_acquisition_protocol import parse


def source_fixture(root, component, raw, payloads, *, metadata=False):
    root.mkdir(mode=0o755)
    archive = decode_manifest(canonical(raw)).archive(component)
    for parent in archive.parents:
        (root / parent.relative).mkdir(mode=parent.mode, parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(payloads[component])) as zipped:
        for member in archive.members:
            if member.source_relative is None: continue
            path = root / member.source_relative
            if member.kind == "directory": path.mkdir(mode=member.source_mode, parents=True, exist_ok=True)
            else:
                path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                path.write_bytes(zipped.read(member.name)); path.chmod(member.source_mode)
    if metadata:
        path = root / PREFIX[component] / "package.xml"
        path.write_bytes(b"inert previously checked metadata bytes"); path.chmod(0o644)
    # Match the declared source modes even under the runner's restrictive umask.
    for path in root.rglob("*"):
        if path.is_dir(): path.chmod(0o755)
    # This entire sibling is intentionally not part of the copied roster.
    (root / "platforms" / "android-99").mkdir(mode=0o755, parents=True, exist_ok=True)
    sibling = root / "platforms" / "android-99" / "keep.txt"
    sibling.write_bytes(b"unrelated source remains untouched")
    (root / "licenses").mkdir(); (root / "licenses" / "keep-license").write_bytes(b"no automated acceptance")
    return archive


def binding_data(root, component, manifest):
    """Explicit test-only construction; production derives this in SourceSlots."""
    archive = decode_manifest(canonical(manifest)).archive(component)
    prefix = PREFIX[component]
    members = {member.source_relative: member.kind == "directory" for member in archive.members if member.source_relative is not None}
    members.update({p.relative: True for p in archive.parents if p.relative == prefix or p.relative.startswith(prefix + "/")})
    root_id = stamp(root.stat())
    hashed = hashlib.sha256(b"mrk-sdk-copy-observation/1\0" + bytes.fromhex(manifest["referenceSha256"])
        + bytes([COMPONENTS.index(component)]) + root_id)
    for name in sorted(members, key=lambda path: path.split("/")):
        encoded = name.encode("utf-8")
        hashed.update(b"\1" + struct.pack("<I", len(encoded)) + encoded + bytes([int(members[name])]) + stamp((root / name).stat()))
    metadata = root / prefix / "package.xml"
    hashed.update(b"\2" + bytes([int(metadata.exists())]))
    if metadata.exists(): hashed.update(stamp(metadata.stat()) + hashlib.sha256(metadata.read_bytes()).digest())
    hashed.update(b"\3" + struct.pack("<I", len(members)))
    return {"format": FORMAT, "component": component.value, "root": str(root),
        "rootIdentity": root_id.hex(), "observationSha256": hashed.hexdigest()}


def owner_for(cache, source, component, manifest, *, name="operation1", book=None, missing=None):
    missing = tuple(part for part in SDK if part is not component) if missing is None else missing
    owner = FixtureOwner(cache, manifest, name=name, book=book, missing=missing)
    owner.admission = replace(owner.admission, sdk_copy=CopyBinding.parse(binding_data(source, component, manifest),
        owner.admission.missing, owner.admission.compatible))
    return owner


def tree_snapshot(root):
    return {str(path.relative_to(root)): (path.stat().st_ino, path.stat().st_mode, path.read_bytes())
        for path in root.rglob("*") if path.is_file()}


class SdkAssemblyTests(unittest.TestCase):
    def test_both_directions_copy_checked_half_fetch_only_missing_and_reuse_only_missing_cache(self):
        for component in SDK:
            with self.subTest(component=component), tempfile.TemporaryDirectory(prefix="mrk-sdk-copy-data-") as temp:
                root = Path(temp); cache = root / "cache"; cache.mkdir(mode=0o700)
                manifest, payloads = fixtures()
                source = root / "chosen-sdk"; source_fixture(source, component, manifest, payloads, metadata=True)
                before = tree_snapshot(source)
                owner = owner_for(cache, source, component, manifest); calls = []; quote = []
                class Space(_Space):
                    def __init__(self, files, amount): quote.append(amount); super().__init__(files, amount)
                transfer = fake_transfer(payloads, calls)
                original_copy = transfer.copy
                service = ToolAcquisition(owner)
                def checked_copy(transport, archive, write):
                    self.assertTrue(service.sdk_copy.closed); self.assertTrue(all(s.close_state == "CLOSED" for s in service.sdk_copy.root.slots))
                    return original_copy(transport, archive, write)
                with patch("mobile_release.tool_acquisition.PublicVendorTransfer", transfer), patch.object(transfer, "copy", checked_copy), patch("mobile_release.tool_acquisition._Space", Space):
                    data = service.run().to_data()
                missing = owner.admission.missing
                self.assertEqual(calls, list(missing)); self.assertEqual(owner.ca_calls, 1)
                self.assertEqual(data["schemaVersion"], 2); self.assertEqual(data["copiedSourceComponents"], [component.value])
                self.assertEqual(data["downloadedArchives"], [part.value for part in missing])
                self.assertEqual(data["groups"], [{"group": "sdk", "components": [part.value for part in SDK],
                    "allRequiredComponentsStaged": True, "next": "choose-native-source"}])
                prepared = cache / data["cacheJob"] / "sources" / "android-sdk"
                for part in SDK: self.assertTrue((prepared / PREFIX[part] / "source.properties").is_file())
                self.assertFalse((prepared / PREFIX[component] / "package.xml").exists())
                self.assertFalse((prepared / "platforms" / "android-99").exists()); self.assertFalse((prepared / "licenses").exists())
                self.assertEqual(tree_snapshot(source), before)
                parsed = decode_manifest(canonical(manifest))
                self.assertEqual(quote, [sum(parsed.archive(part).size for part in missing)
                    + sum(parsed.archive(part).expanded_bytes for part in SDK)])
                self.assertEqual(data["assurance"], {"nativeFinality": False, "registered": False, "readyToBuild": False})
                owner.settle_for_test(service)
                second = owner_for(cache, source, component, manifest, name="operation2", book=owner.book)
                with patch("mobile_release.tool_acquisition.PublicVendorTransfer", side_effect=AssertionError("checked cache needs no HTTP")):
                    reused = ToolAcquisition(second).run().to_data()
                self.assertEqual(reused["reusedArchives"], [part.value for part in missing]); self.assertEqual(second.ca_calls, 0)
                self.assertEqual(reused["copiedSourceComponents"], [component.value]); self.assertEqual(tree_snapshot(source), before)

    def test_missing_jdk_and_gradle_still_download_once_and_preserve_sdk_readonly_mode(self):
        with tempfile.TemporaryDirectory(prefix="mrk-sdk-copy-data-") as temp:
            root=Path(temp); cache=root/"cache"; cache.mkdir(mode=0o700)
            manifest,payloads=fixtures(); component=Component.SDK_PLATFORM
            manifest["archives"][1]["members"][0]["sourceMode"]=0o444
            source=root/"sdk"; source_fixture(source,component,manifest,payloads)
            owner=owner_for(cache,source,component,manifest,missing=(Component.JDK,Component.SDK_BUILD_TOOLS,Component.GRADLE)); calls=[]
            with patch("mobile_release.tool_acquisition.PublicVendorTransfer",fake_transfer(payloads,calls)):
                data=ToolAcquisition(owner).run().to_data()
            self.assertEqual(calls,list(owner.admission.missing)); self.assertNotIn(component,calls)
            self.assertEqual([row["group"] for row in data["groups"]],["jdk","sdk","gradle"])
            self.assertEqual((cache/data["cacheJob"]/"sources/android-sdk/platforms/android-35/source.properties").stat().st_mode & 0o777,0o444)
            self.assertEqual((source/"platforms/android-35/source.properties").stat().st_mode & 0o777,0o444)

    def test_changed_bytes_mode_metadata_symlink_or_root_refuse_before_any_vendor_transfer(self):
        for mutation in ("bytes","mode","metadata","symlink","root","extra"):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory(prefix="mrk-sdk-copy-data-") as temp:
                root=Path(temp);cache=root/"cache";cache.mkdir(mode=0o700);manifest,payloads=fixtures();component=Component.SDK_PLATFORM
                source=root/"sdk";source_fixture(source,component,manifest,payloads,metadata=True)
                owner=owner_for(cache,source,component,manifest); file=source/PREFIX[component]/"source.properties"
                if mutation=="bytes": file.write_bytes(b"changed")
                elif mutation=="mode": file.chmod(0o444)
                elif mutation=="metadata": (file.parent/"package.xml").write_bytes(b"changed optional metadata")
                elif mutation=="symlink": file.unlink();file.symlink_to(root/"never-followed")
                elif mutation=="root": source.rename(root/"original-sdk");source.mkdir(mode=0o755)
                else: (file.parent/"unexpected-file").write_bytes(b"not in compiled roster")
                with patch("mobile_release.tool_acquisition.PublicVendorTransfer",side_effect=AssertionError("source tamper must precede HTTP")),self.assertRaises(AcquisitionError):
                    ToolAcquisition(owner).run()
                self.assertEqual(owner.ca_calls,0)

    def test_drift_during_copy_fails_post_before_missing_archive_download(self):
        with tempfile.TemporaryDirectory(prefix="mrk-sdk-copy-data-") as temp:
            root=Path(temp);cache=root/"cache";cache.mkdir(mode=0o700);manifest,payloads=fixtures();component=Component.SDK_PLATFORM
            source=root/"sdk";source_fixture(source,component,manifest,payloads);owner=owner_for(cache,source,component,manifest)
            original=OutputTree.member
            def drift(tree,archive,member,chunks=None):
                result=original(tree,archive,member,chunks)
                if archive.component is component and member.kind=="file": (source/member.source_relative).write_bytes(b"external edit")
                return result
            with patch.object(OutputTree,"member",drift),patch("mobile_release.tool_acquisition.PublicVendorTransfer",side_effect=AssertionError("POST before HTTP")),self.assertRaises(AcquisitionError):
                ToolAcquisition(owner).run()
            self.assertEqual(owner.ca_calls,0)

    def test_ambiguous_original_source_close_retains_unknown_and_still_closes_cache(self):
        with tempfile.TemporaryDirectory(prefix="mrk-sdk-copy-data-") as temp:
            root=Path(temp);cache=root/"cache";cache.mkdir(mode=0o700);manifest,payloads=fixtures();component=Component.SDK_PLATFORM
            source=root/"sdk";source_fixture(source,component,manifest,payloads);owner=owner_for(cache,source,component,manifest)
            original=_Directory.close; calls=[]
            def close(directory):
                original(directory)
                if directory.lexical_path==source: calls.append(directory);raise OSError("synthetic lost close return")
            service=ToolAcquisition(owner)
            with patch.object(_Directory,"close",close),patch("mobile_release.tool_acquisition.PublicVendorTransfer",side_effect=AssertionError("source must close before HTTP")),self.assertRaises(AcquisitionError) as error:
                service.run()
            self.assertEqual(error.exception.reason,"unknown");self.assertEqual(len(calls),1)
            self.assertTrue(service.unknown);self.assertEqual(owner.retained,[service]);self.assertTrue(service.files.settled)
            self.assertFalse(service.sdk_copy.closed);self.assertEqual(owner.ca_calls,0)

    def test_physical_source_destination_overlap_refuses_before_new_job_effect(self):
        with tempfile.TemporaryDirectory(prefix="mrk-sdk-copy-data-") as temp:
            root=Path(temp);manifest,payloads=fixtures();source=root/"sdk";component=Component.SDK_PLATFORM
            source_fixture(source,component,manifest,payloads)
            cache=source/"cache";cache.mkdir(mode=0o700)
            owner=owner_for(cache,source,component,manifest)
            with patch("mobile_release.tool_acquisition.PublicVendorTransfer",side_effect=AssertionError("overlap before HTTP")),self.assertRaises(AcquisitionError): ToolAcquisition(owner).run()
            self.assertFalse((cache/"tool-operation1").exists());self.assertEqual(owner.book.entries,{})

    def test_private_binding_and_versioned_result_reject_wrong_component_extra_fields_and_old_complete_claim(self):
        with tempfile.TemporaryDirectory(prefix="mrk-sdk-copy-data-") as temp:
            manifest,payloads=fixtures();source=Path(temp)/"sdk";source_fixture(source,Component.SDK_PLATFORM,manifest,payloads)
            value=subset_request(["sdk-build-tools"]);copy_input=binding_data(source,Component.SDK_PLATFORM,manifest)
            value["native"]["cache"]["sdkCopy"]=copy_input;parsed=parse(value)
            result=staged(parsed);result.update(schemaVersion=2,copiedSourceComponents=["sdk-platform"])
            result["groups"][0].update(components=["sdk-platform","sdk-build-tools"],allRequiredComponentsStaged=True,next="choose-native-source")
            wire.staged(result,parsed)
            for modify in (lambda v:v.update(component="sdk-build-tools"),lambda v:v.update(url="https://unused.invalid"),
                           lambda v:v.update(root="/sdk/../other"),lambda v:v.update(rootIdentity="00"*STAMP.size)):
                changed=copy.deepcopy(value);modify(changed["native"]["cache"]["sdkCopy"])
                with self.assertRaises(wire.ProtocolError):parse(changed)
            for modify in (lambda v:v.update(schemaVersion=1),lambda v:v.update(copiedSourceComponents=[]),
                           lambda v:v.update(copiedSourceComponents=["sdk-build-tools"]),lambda v:v["downloadedArchives"].insert(0,"sdk-platform")):
                changed=copy.deepcopy(result);modify(changed)
                with self.assertRaises(wire.ProtocolError):wire.staged(changed,parsed)
            old=parse(subset_request(["sdk-build-tools"]));wire.staged(staged(old),old)
            with self.assertRaises(wire.ProtocolError):wire.staged(result,old)

    def test_concrete_run_resources_closed_does_not_omit_sdk_copy_original(self):
        run=object.__new__(ToolAcquisitionRun);run.capture=SimpleNamespace(closed=True);run._unknown=False
        run.acquisition=SimpleNamespace(unknown=False,files=SimpleNamespace(settled=True),sdk_copy=SimpleNamespace(closed=False))
        self.assertFalse(run.closed())

    def test_hash_codec_matches_fixed_rust_vector_and_binds_metadata(self):
        binding=CopyBinding(Component.SDK_PLATFORM,Path("/not-opened"),bytes([8])*68,"0"*64)
        observed=_Observation("07"*32,binding);observed.member("platforms/android-35",True,bytes(68))
        expected=hashlib.sha256(b"mrk-sdk-copy-observation/1\0"+bytes([7])*32+b"\1"+bytes([8])*68
            +b"\1\x14\0\0\0platforms/android-35\1"+bytes(68)+b"\2\0\3\1\0\0\0").hexdigest()
        self.assertEqual(observed.finish(None),expected)
        self.assertEqual(STAMP.size,68)


if __name__=="__main__": unittest.main()
