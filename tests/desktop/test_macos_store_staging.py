"""Actual stager DATA parsers, synthetic Mach-O only; no code execution/signing."""
import struct
import unittest

from test_macos_launcher_staging import TOOL, binary


class StoreStaging(unittest.TestCase):
    def fixture(self, target):
        files = {"store/" + name: (b"inert resource", 0o444) for name in TOOL.STORE_RUNTIME_REQUIRED}
        files["store/bin/ruby"] = (binary(target), 0o555)
        files["store/bin/bundle"] = (b"#!/bin/sh\n# inert wrapper\n", 0o555)
        extension = bytearray(binary(target))
        struct.pack_into('<I', extension, 12, 8)  # Actual MH_BUNDLE header kind.
        files["store/lib/example.bundle"] = (bytes(extension), 0o444)
        return files

    def test_complete_store_group_and_every_native_extension_are_checked(self):
        for target in TOOL.MAC_TARGETS:
            with self.subTest(target=target):
                files = self.fixture(target)
                TOOL.store_runtime_payload(files, current=True, target=target)
                for name, (body, _mode) in files.items():
                    self.assertEqual(TOOL.current_runtime_mode(name, body, None, target=target),
                                     0o555 if name in {"store/bin/ruby", "store/bin/bundle"} else 0o444)
                other = TOOL.INTEL_TARGET if target == TOOL.ARM_TARGET else TOOL.ARM_TARGET
                files["store/lib/example.bundle"] = (binary(other), 0o444)
                with self.assertRaises(TOOL.Refused):
                    TOOL.store_runtime_payload(files, current=True, target=target)
                files["store/lib/example.bundle"] = (binary(target, b"/private/build/libextra.dylib"), 0o444)
                with self.assertRaises(TOOL.Refused):
                    TOOL.store_runtime_payload(files, current=True, target=target)

    def test_partial_groups_ambient_interpreter_and_historical_profiles_refuse(self):
        TOOL.store_runtime_payload({}, current=False, target=TOOL.ARM_TARGET)
        for name in TOOL.STORE_RUNTIME_REQUIRED:
            files = self.fixture(TOOL.ARM_TARGET)
            del files["store/" + name]
            with self.subTest(missing=name), self.assertRaises(TOOL.Refused):
                TOOL.store_runtime_payload(files, current=True, target=TOOL.ARM_TARGET)
        files = self.fixture(TOOL.ARM_TARGET)
        with self.assertRaises(TOOL.Refused):
            TOOL.store_runtime_payload(files, current=False, target=TOOL.ARM_TARGET)
        files["store/bin/bundle"] = (b"#!/usr/bin/env ruby\n", 0o555)
        with self.assertRaises(TOOL.Refused):
            TOOL.store_runtime_payload(files, current=True, target=TOOL.ARM_TARGET)
        # The new bundle-kind route cannot relax old executable-only callers.
        with self.assertRaises(TOOL.Refused):
            TOOL.macho(self.fixture(TOOL.ARM_TARGET)["store/lib/example.bundle"][0], target=TOOL.ARM_TARGET)

    def test_current_manifest_measured_and_maximum_counts_preserve_legacy_and_json_limits(self):
        required=TOOL.CURRENT_BOOTSTRAPS | {"core.zip", "github-ca.pem", "python/bin/python3"}
        def document(count):
            names=sorted(required | {f"store/inert/{index:05}" for index in range(count-len(required))})
            rows=[{"path":name,"size":1,"sha256":"a"*64} for name in names]
            return TOOL.canonical({"schemaVersion":1,"protocol":1,"coreVersion":"test",
                "target":TOOL.ARM_TARGET,"coreSha256":"a"*64,"protocolSha256":TOOL.CURRENT_PROTOCOL,
                "inventorySha256":TOOL.digest(TOOL.canonical(rows)),"files":rows})
        for count in (8622, TOOL.MAX_FILES):
            raw=document(count)
            with self.subTest(count=count):
                _,rows=TOOL.manifest_files(raw,TOOL.digest(raw),current=True)
                self.assertEqual(len(rows),count)
                with self.assertRaises(TOOL.Refused): TOOL.decode(raw)
                with self.assertRaises(TOOL.Refused): TOOL.manifest_files(raw,TOOL.digest(raw),current=False)
        raw=document(TOOL.MAX_FILES+1)
        with self.assertRaises(TOOL.Refused): TOOL.manifest_files(raw,TOOL.digest(raw),current=True)
        with self.assertRaises(TOOL.Refused):
            TOOL.decode(b'{"files":[],"files":[]}',byte_limit=TOOL.INVENTORY_BYTES,node_limit=150000)
        with self.assertRaises(TOOL.Refused):
            TOOL.decode(b' '*(TOOL.INVENTORY_BYTES+1),byte_limit=TOOL.INVENTORY_BYTES,node_limit=150000)
        self.assertEqual(TOOL.FRESH_SUPPLIER_FILES,2032)
        self.assertEqual(TOOL.MAX_BYTES,512*1024*1024)

    def test_combined_directory_entries_refuse_one_over_without_alias_relaxation(self):
        # Each synthetic file has one distinct directory: exercise the actual
        # combined entry admission without creating thousands of disk objects.
        files={f"d{index:05}/f" for index in range(TOOL.MAX_ENTRIES//2)}
        self.assertEqual(len(TOOL.directories(files)),TOOL.MAX_ENTRIES//2)
        with self.assertRaises(TOOL.Refused): TOOL.directories(files | {"extra"})
        with self.assertRaises(TOOL.Refused): TOOL.directories({"d/f","D/f"})
