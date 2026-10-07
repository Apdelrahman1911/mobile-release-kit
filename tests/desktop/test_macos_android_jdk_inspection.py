"""Synthetic byte-only regressions; no vendor payload, file mutation or native run.

The real fixed180MB archive is deliberately NOT read by these tests. It needs
the separately reviewed offline owner and its original finality evidence.
"""
from __future__ import annotations

import ast
import base64
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import struct
import sys
import tarfile
import unittest
import zipfile

_TOOLS = Path(__file__).resolve().parents[2] / "desktop/tools"
_NAME = "mrk_intel_jdk_inspection_correspondence_tests"
if _NAME in sys.modules:
    raise RuntimeError("unexpected inspection correspondence module collision")
_SPEC = importlib.util.spec_from_file_location(_NAME, _TOOLS / "macos_android_supplier_correspondence.py")
C = importlib.util.module_from_spec(_SPEC)
sys.modules[_NAME] = C  # Actual dataclass definition module, not a fake provider.
_SPEC.loader.exec_module(C)
_ISPEC = importlib.util.spec_from_file_location("mrk_intel_jdk_inspection_tests", _TOOLS / "macos_android_jdk_inspection.py")
I = importlib.util.module_from_spec(_ISPEC)
_ISPEC.loader.exec_module(I)


class Original:
    def __init__(self, body=b""):
        self.body, self.reads, self.bindings, self.checks = body, [], 0, 0
        self.expired = self.changed = False

    def checkpoint(self):
        self.checks += 1
        if self.expired:
            raise C.Refused("original-endpoint")

    def verify_binding(self):
        self.bindings += 1
        self.checkpoint()
        if self.changed:
            raise C.Refused("original-binding")

    def read_at(self, offset, count):
        self.reads.append((offset, count))
        return self.body[offset:offset + count]


def zip_bytes(rows):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, body in rows:
            info = zipfile.ZipInfo(name)
            info.create_system = 0
            info.external_attr = 0
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, body)
    return output.getvalue()


def tar_bytes(rows):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in rows:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(body))
    return gzip.compress(output.getvalue(), mtime=0)


def row(name, body, mode=0o100644):
    return (name, "file", mode, len(body), hashlib.sha256(body).hexdigest(), None,
            None, None, None, None, None, None, None, C._hint(body[:16]))


def macho(cpu=I.CPU_X64, subtype=3, size=4096, extent=24):
    header = struct.pack("<8I", 0xFEEDFACF, cpu, subtype, 2, 1, extent, 0, 0)
    command = struct.pack("<II", 0x1B, 24) + b"\0" * 16
    return (header + command).ljust(size, b"\0")


def universal(arm, intel):
    header = struct.pack(">II", 0xCAFEBABE, 2)
    table = struct.pack(">IIIII", 0x0100000C, 0, 4096, len(arm), 12)
    table += struct.pack(">IIIII", I.CPU_X64, 3, 8192, len(intel), 12)
    return (header + table).ljust(4096, b"\0") + arm + intel


def observe_file(body, name="example", *, chunks=65536):
    original = Original()
    arena = I.Arena(original)
    observer = I._Observer(C, arena)
    value = row(name, body)
    observer.begin(value[:4] + (None,) + value[5:-1] + (None,))
    try:
        for offset in range(0, len(body), chunks):
            observer.block(name, offset, body[offset:offset + chunks])
        observer.end(value)
        return observer, arena
    finally:
        observer.dispose_current()


def inspect_bytes(raw, name="test.jmod", arena=None, *, digest=None, chunks=65536):
    # Exercise the real ordered collector with inert bytes, not a pre-hashed
    # shortcut around the production completed-stream/copy binding.
    arena = I.Arena(Original()) if arena is None else arena
    value = row(name, raw)
    if digest is not None:
        value = value[:4] + (digest,) + value[5:]
    observer = I._Observer(C, arena, expected={name: value})
    try:
        observer.begin(value[:4] + (None,) + value[5:-1] + (None,))
        for offset in range(0, len(raw), chunks):
            observer.block(name, offset, raw[offset:offset + chunks])
        observer.end(value)
        assert len(observer.archives) == 1, "synthetic fixture must be a supported archive"
        return observer.archives[0], arena
    finally:
        observer.dispose_current()


class IntelJdkInspectionDataTests(unittest.TestCase):
    def test_observers_preserve_complete_default_archive_and_opaque_namespace_rules(self):
        class Recorder:
            def __init__(self, fail=None):
                self.events, self.payloads, self.fail = [], {}, fail
            def begin(self, value):
                self.events.append(("begin", value))
                self.payloads[value[0]] = bytearray()
                if self.fail == "begin":
                    raise ValueError("original-observer-failure")
            def block(self, name, offset, data):
                if offset != len(self.payloads[name]):
                    raise ValueError("observer-order")
                self.payloads[name].extend(data)
                if self.fail == "block":
                    raise ValueError("original-observer-failure")
            def end(self, value):
                self.events.append(("end", value))
                if self.fail == "end":
                    raise ValueError("original-observer-failure")
        for label, raw in (("jdk", tar_bytes([("dist/empty", b""), ("dist/value", b"actual" * 20000)])),
                           ("gradle", zip_bytes([("dist/empty", b""), ("dist/value", b"actual" * 20000)]))):
            pin = C.Pin(label, len(raw), hashlib.sha256(raw).hexdigest())
            plain = []
            C.compile_archive(Original(raw), pin).publish(plain.append)
            captured, observer = [], Recorder()
            C.compile_archive(Original(raw), pin, observer=observer).publish(captured.append)
            self.assertEqual(captured, plain)
            self.assertEqual([kind for kind, _ in observer.events], ["begin", "end", "begin", "end"])
            for kind, value in observer.events:
                if kind == "end":
                    self.assertEqual(value[4], hashlib.sha256(observer.payloads[value[0]]).hexdigest())
            for failure in ("begin", "block", "end"):
                with self.subTest(label=label, failure=failure):
                    owner, failed = Original(raw), Recorder(failure)
                    with self.assertRaisesRegex(ValueError, "original-observer-failure"):
                        C.compile_archive(owner, pin, observer=failed)
        raw = zip_bytes([("p/C.class", b"one"), ("p/c.class", b"two"), ("日本/Resource.txt", b"three")])
        pin = C.OpaqueZipPin(len(raw), hashlib.sha256(raw).hexdigest())
        report = C.compile_opaque_zip(Original(raw), pin)
        rows = []
        summary = report.consume_rows(rows.append)
        self.assertEqual(summary["files"], 3)
        self.assertEqual({item[0] for item in rows}, {"p/C.class", "p/c.class", "日本/Resource.txt"})
        with self.assertRaisesRegex(C.Refused, "report_finality"):
            report.consume_rows(lambda _: self.fail("a consumed report cannot be reused"))
        with self.assertRaises(C.Refused):
            C.compile_archive(Original(raw), pin)
        with self.assertRaises(C.Refused):
            C.compile_opaque_zip(Original(raw), C.Pin("bundletool", len(raw), pin.sha256))
        for name in ("/absolute", "a/../escape", "a\\b", "a//b"):
            bad = zip_bytes([(name, b"x")])
            with self.subTest(name=name), self.assertRaises(C.Refused):
                C.compile_opaque_zip(Original(bad), C.OpaqueZipPin(len(bad), hashlib.sha256(bad).hexdigest()))
        duplicate = zip_bytes([("same", b"one"), ("diff", b"two")]).replace(b"diff", b"same")
        with self.assertRaises(C.Refused):
            C.compile_opaque_zip(Original(duplicate), C.OpaqueZipPin(len(duplicate), hashlib.sha256(duplicate).hexdigest()))

        # Real parser and Arena: terminal handoff keeps ONE charged row book.
        # The unchanged publisher supplies the exact sorted14-column oracle.
        drain_raw = zip_bytes([(name, body) for name, body in
                               (("p/z.class", b"z"), ("p/A.class", b"A"),
                                ("p/a.class", b"a"), ("日本/notice", b"notice"))])
        drain_pin = C.OpaqueZipPin(len(drain_raw), hashlib.sha256(drain_raw).hexdigest())
        published = []
        C.compile_opaque_zip(Original(drain_raw), drain_pin).publish(published.append)
        published_document = json.loads(published[0])
        expected_rows = [tuple(value) for value in published_document["rows"]]
        charge = lambda value: 1536 + 8 * len(value[0]) + 8 * len(value[5] or "")
        complete_charge = sum(charge(value) for value in expected_rows)
        owner = Original(drain_raw)
        arena = I.Arena(owner)
        terminal = C.compile_opaque_zip(owner, drain_pin, workspace=arena)
        self.assertEqual(arena.held["rows"], complete_charge)
        retained = []

        def retain(value):
            self.assertIs(type(value), tuple)
            self.assertEqual(len(value), 14)
            self.assertTrue(terminal._published)
            self.assertFalse(terminal._capture.names)
            self.assertEqual(len(terminal._capture.rows), len(expected_rows) - len(retained) - 1)
            for operation in (terminal.consume_rows, terminal.publish):
                with self.assertRaisesRegex(C.Refused, "report_finality"):
                    operation(lambda _: self.fail("terminal callback reentry"))
            arena.reserve_rows(charge(value))
            retained.append(value)
            self.assertEqual(arena.held["rows"], complete_charge)

        summary = terminal.consume_rows(retain)
        self.assertEqual(retained, expected_rows)
        for key in ("entryHeaders", "members", "files", "aliases", "expandedBytes"):
            self.assertEqual(summary[key], published_document[key])
        self.assertEqual(summary["rosterReservationBytes"], complete_charge)
        self.assertEqual(arena.peaks["rows"], complete_charge)
        self.assertFalse(terminal._capture.rows)
        self.assertFalse(terminal._capture.names)
        self.assertEqual(terminal._capture.roster, 0)
        retained.clear()
        arena.release_rows(complete_charge)
        self.assertEqual(arena.held["rows"], 0)

        # No real signals or global replacements: fault each exact handoff
        # boundary on local objects, preserving the first exception identity.
        for stage in ("callback", "cancel", "binding", "release", "cleanup"):
            primary = KeyboardInterrupt("local-cancel") if stage == "cancel" else RuntimeError(stage)
            secondary = RuntimeError("secondary-heap-release")

            class FailingOriginal(Original):
                fail_binding = False
                def verify_binding(self):
                    super().verify_binding()
                    if self.fail_binding:
                        raise primary

            class FailingArena(I.Arena):
                fail_release = False
                def release_rows(self, count):
                    if self.fail_release:
                        self.fail_release = False
                        self.failed = True
                        raise secondary if stage == "cleanup" else primary
                    super().release_rows(count)

            failed_owner = FailingOriginal(drain_raw)
            failed_arena = FailingArena(failed_owner)
            failed = C.compile_opaque_zip(failed_owner, drain_pin, workspace=failed_arena)
            kept = []
            failed_arena.fail_release = stage == "release"

            def fail_at_original_boundary(value):
                failed_arena.reserve_rows(charge(value))
                kept.append(value)
                if len(kept) == 1 and stage in ("callback", "cancel", "cleanup"):
                    failed_arena.fail_release = stage == "cleanup"
                    raise primary
                if len(kept) == len(expected_rows) and stage == "binding":
                    failed_owner.fail_binding = True

            with self.subTest(terminal_stage=stage), self.assertRaises(type(primary)) as failure:
                failed.consume_rows(fail_at_original_boundary)
            self.assertIs(failure.exception, primary)
            self.assertTrue(failed._capture.failed)
            self.assertFalse(failed._capture.rows)
            self.assertFalse(failed._capture.names)
            for operation in (failed.consume_rows, failed.publish):
                with self.assertRaisesRegex(C.Refused, "report_finality"):
                    operation(lambda _: self.fail("failed terminal report reused"))
            retained_charge = sum(charge(value) for value in kept)
            kept.clear()
            if stage not in ("release", "cleanup"):
                self.assertEqual(failed_arena.held["rows"], retained_charge)
                failed_arena.release_rows(retained_charge)
                self.assertEqual(failed_arena.held["rows"], 0)
            else:
                # A failed refund is not a successful release or retry grant.
                self.assertTrue(failed_arena.failed)
                self.assertGreater(failed_arena.held["rows"], 0)

    def test_streamed_native_snapshots_bind_actual_slice_and_keep_ambiguous_headers_distinct(self):
        intel, arm = macho(), macho(0x0100000C, 0)
        raw = universal(arm, intel)
        observer, arena = observe_file(raw, "fat", chunks=3)
        self.assertEqual(arena.held["payload"], 0)
        self.assertEqual(len(observer.native), 1)
        actual = observer.native[0]
        self.assertEqual((actual["selectedCpu"], actual["sliceOffset"], actual["sliceBytes"]), ("x86_64", 8192, 4096))
        self.assertEqual(base64.b64decode(actual["prefixBase64"]), raw[:4096])
        self.assertEqual(base64.b64decode(actual["commandsBase64"]), intel[:56])
        self.assertEqual(actual["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(actual["commandsSha256"], hashlib.sha256(intel[:56]).hexdigest())
        direct, _ = observe_file(intel, "thin", chunks=1)
        self.assertEqual(direct.native[0]["sliceOffset"], 0)
        for corrupt in (universal(arm, macho(subtype=4)),
                        universal(arm, macho(size=70000, extent=65536))):
            with self.assertRaises(I.InspectionRefused):
                observe_file(corrupt)
        overlap = bytearray(raw)
        struct.pack_into(">I", overlap, 8 + 20 + 8, 4096)
        with self.assertRaisesRegex(I.InspectionRefused, "native-fat-range"):
            I.selected_slice(bytes(overlap[:160]), len(overlap))
        foreign, _ = observe_file(arm)
        self.assertIsNone(foreign.native[0]["selectedCpu"])
        java = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 61, 1)
        self.assertEqual(I.content_kind(java, len(java)), "java-class-header")
        self.assertEqual(I.content_kind(java[:-1] + b"\0", len(java)), "ambiguous-native")
        self.assertEqual(I.content_kind(b"\xca\xfe\xba\xbe\0\0\0\x05xx", 10), "ambiguous-native")
        unknown, _ = observe_file(b"MZ" + b"opaque" * 40)
        self.assertFalse(unknown.native)
        self.assertEqual(unknown.unknown[0]["format"], "foreign-native")

        # Complete-mode foreign/unresolved prefixes are original bounded stream
        # observations, not an ELF/PE loader or a new native-format permission.
        samples = (
            ("target.so", (b"\x7fELF" + bytes(range(256)) * 20), "ELF", None),
            ("foreign.dll", (b"MZ" + bytes(range(256)) * 20), "PE", None),
            ("future.class", b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 99, 1), None, "ambiguous-native"),
            ("empty.class", b"", None, "class-name-format-disagreement"),
            ("hidden.dylib", b"opaque native-looking name", None, "native-name-format-disagreement"),
        )
        for name, body, foreign_format, problem in samples:
            arena = I.Arena(Original())
            collector = I._Observer(C, arena, complete=True)
            value = row(name, body)
            collector.begin(value[:4] + (None,) + value[5:-1] + (None,))
            try:
                for offset in range(0, len(body), 7):
                    collector.block(name, offset, body[offset:offset + 7])
                collector.end(value)
                facts = collector.foreign if foreign_format else collector.unknown
                self.assertEqual(len(facts), 1)
                observed = facts[0]
                self.assertEqual((observed["name"], observed["bytes"], observed["mode"], observed["sha256"]),
                                 (value[0], value[3], value[2], value[4]))
                prefix = body[:4096]
                self.assertEqual(observed["prefixBytes"], len(prefix))
                self.assertEqual(observed["prefixSha256"], hashlib.sha256(prefix).hexdigest())
                self.assertEqual(base64.b64decode(observed["prefixBase64"]), prefix)
                if foreign_format:
                    self.assertEqual(observed["format"], foreign_format)
                    self.assertEqual(collector.unknown, [])
                else:
                    self.assertEqual(observed["reason"], problem)
                    self.assertEqual(collector.foreign, [])
                self.assertEqual(arena.held["payload"], 0)
                self.assertGreater(arena.held["facts"], 4096)
            finally:
                collector.dispose_current()
        # The128 cap counts all recognized native formats together, not128
        # Mach-O plus another128 foreign objects. Exact128 remains observable.
        foreign = [(f"f-{number:03}.so", b"\x7fELF" + b"x" * 160) for number in range(127)]
        limit_body = zip_bytes(foreign + [("own.dylib", macho())])
        limit = I._inspect_complete_non_jdk(Original(limit_body), C,
            ("sdk-build-tools", len(limit_body), hashlib.sha256(limit_body).hexdigest()))
        self.assertEqual((len(limit.document["nativeMembers"]), len(limit.document["foreignNativeMembers"])), (1, 127))
        overflow = zip_bytes(foreign + [("own.dylib", macho()), ("last.dll", b"MZ" + b"x" * 160)])
        with self.assertRaisesRegex(I.InspectionRefused, "native-member-count"):
            I._inspect_complete_non_jdk(Original(overflow), C,
                ("sdk-build-tools", len(overflow), hashlib.sha256(overflow).hexdigest()))

    def test_complete_jmod_and_zip_censuses_bind_whole_bytes_crc_and_counterparts(self):
        native = macho()
        java = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 61, 1)
        zipped = zip_bytes([("bin/java", native), ("classes/p/C.class", java), ("legal/NOTICE", b"notice")])
        raw = b"JM\x01\x00" + zipped
        name = I.HOME + "jmods/java.base.jmod"
        result, arena = inspect_bytes(raw, name)
        self.assertEqual((result["centralMembers"], result["inspectedMembers"], result["files"]), (3, 3, 3))
        self.assertEqual(result["expandedInspectedBytes"], len(native) + len(java) + 6)
        self.assertEqual(result["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertTrue(result["completeMemberHashes"])
        self.assertFalse(result["nativeExecuted"])
        self.assertFalse(result["supplierAuthority"])
        self.assertEqual(result["formatCounts"]["java-class-header"], 1)
        self.assertEqual(arena.held["payload"], 0)
        self.assertEqual(arena.held["rows"], 0)
        direct, _ = observe_file(native, I.HOME + "bin/java")
        I.counterpart_facts(direct.native, [result], arena)
        self.assertTrue(result["nativeMembers"][0]["counterpart"]["matched"])
        mismatched = dict(direct.native[0], commandsSha256="0" * 64)
        I.counterpart_facts([mismatched], [result], arena)
        self.assertEqual(result["nativeMembers"][0]["counterpart"]["status"], "different-bytes-or-snapshot")
        I.counterpart_facts([], [result], arena)
        self.assertEqual(result["nativeMembers"][0]["counterpart"]["status"], "unmatched")
        changed = bytearray(raw)
        # The first Stored member body begins after the exact local name.
        changed[4 + 30 + len("bin/java") + len(native) - 1] ^= 1
        with self.assertRaisesRegex(C.Refused, "zip_member_crc_or_length"):
            inspect_bytes(bytes(changed), name)
        with self.assertRaisesRegex(I.InspectionRefused, "inner-whole-member-sha"):
            inspect_bytes(raw, name, digest="0" * 64)
        unsupported, _ = observe_file(b"JM\x01\x01" + zipped)
        self.assertFalse(unsupported.archives)
        self.assertEqual(unsupported.unknown[0]["format"], "unsupported-jmod")
        for bad in (b"JM\x01\x00X" + zipped, raw + b"tail"):
            with self.assertRaises((C.Refused, I.InspectionRefused)):
                inspect_bytes(bad, name)
        negative, _ = inspect_bytes(zip_bytes([("日本/notice", b"plain"), ("empty", b"")]), "sealed.zip")
        self.assertEqual(negative["files"], 2)
        self.assertEqual(negative["expandedInspectedBytes"], 5)
        self.assertFalse(negative["nativeMembers"])
        self.assertFalse(negative["unknownMembers"])
        # No-comment, contiguous Stored ZIPs have exact authenticated-parser
        # reads: one whole view + complete locals/CD/payloads + EOCD tail overlap.
        # Streaming collection adds no completed-buffer scan or read discount.
        for material, offset in ((zipped, 0), (raw, 4)):
            view_bytes = len(material) - offset
            required = 2 * view_bytes + min(view_bytes, 65557) - 22
            for chunks in (1, 3, 65536):
                with self.subTest(offset=offset, chunks=chunks):
                    checked, bounded = inspect_bytes(material, name, chunks=chunks)
                    self.assertEqual(checked["zipViewOffset"], offset)
                    self.assertEqual(checked["sha256"], hashlib.sha256(material).hexdigest())
                    self.assertEqual(checked["issuedReadBytes"], required)
                    self.assertEqual(bounded.reads, required)
                    self.assertEqual(bounded.held["payload"], 0)
                    self.assertEqual(bounded.held["rows"], 0)
            # Captured hashes still describe the original stream. Altering only
            # its completed copied buffer must fail the SAME parser admission.
            owner = Original()
            bounded = I.Arena(owner)
            value = row(name, material)
            collector = I._Observer(C, bounded, expected={name: value})
            try:
                collector.begin(value[:4] + (None,) + value[5:-1] + (None,))
                for at in range(0, len(material), 3):
                    collector.block(name, at, material[at:at + 3])
                collector.current["buffer"][offset + 30 + len("bin/java") + len(native) - 1] ^= 1
                with self.assertRaisesRegex(C.Refused, "original_archive_sha256"):
                    collector.end(value)
                self.assertTrue(bounded.failed)
                self.assertFalse(collector.archives)
            finally:
                collector.dispose_current()
            self.assertEqual(bounded.held["payload"], 0)
            self.assertEqual(bounded.held["rows"], 0)
        # A completed row is not permission to recover a failed/missing chunk.
        for failure in ("incomplete", "repeated", "gap"):
            bounded = I.Arena(Original())
            value = row(name, raw)
            collector = I._Observer(C, bounded, expected={name: value})
            try:
                collector.begin(value[:4] + (None,) + value[5:-1] + (None,))
                with self.assertRaisesRegex(I.InspectionRefused, "observer-file-completion|observer-block-order"):
                    if failure == "incomplete":
                        collector.block(name, 0, raw[:-1])
                        collector.end(value)
                    else:
                        collector.block(name, 0, raw[:160])
                        collector.block(name, 0 if failure == "repeated" else 161, raw[160:])
                self.assertTrue(bounded.failed)
                with self.assertRaisesRegex(I.InspectionRefused, "already-failed"):
                    collector.end(value)
                self.assertFalse(collector.archives)
            finally:
                collector.dispose_current()
            self.assertEqual(bounded.held["payload"], 0)

        # Three fixed production roles share this algorithm; fixture pins below
        # are explicitly synthetic, never claimed to match a public archive.
        def specification(component, body, selected=(), required=()):
            return (component, len(body), hashlib.sha256(body).hexdigest(), selected, required)

        def baseline(component, body):
            rows = []
            summary = C.compile_archive(Original(body), C.Pin(
                component, len(body), hashlib.sha256(body).hexdigest())).consume_rows(rows.append)
            return rows, summary

        intel, arm = macho(), macho(0x0100000C, 0)
        for image in (intel, universal(arm, intel), arm):
            body = zip_bytes([("aapt2", image), ("NOTICE", b"retained legal bytes"),
                              ("unselected.jar", b"PK\x03\x04not-an-inspected-inner-zip")])
            rows, summary = baseline("aapt2", body)
            member = next(value for value in rows if value[0] == "aapt2")
            required = ((member[0], member[3], member[4], member[2]),)
            original = Original(body)
            inspection = I._inspect_non_jdk(original, C, specification("aapt2", body, required=required))
            actual = inspection.document
            self.assertEqual(actual["rows"], rows)
            self.assertEqual(actual["outer"], summary)
            self.assertEqual(actual["columns"], list(C.COLUMNS))
            self.assertTrue(actual["completeOuterMemberHashes"])
            self.assertEqual(actual["archiveSha256"], hashlib.sha256(body).hexdigest())
            selected_cpu = None if image is arm else "x86_64"
            self.assertEqual(actual["nativeMembers"][0]["selectedCpu"], selected_cpu)
            self.assertEqual(actual["nativeMembers"][0]["sha256"], hashlib.sha256(image).hexdigest())
            if selected_cpu is not None:
                self.assertEqual(base64.b64decode(actual["nativeMembers"][0]["commandsBase64"]), intel[:56])
            self.assertEqual(actual["selectedInnerArchives"], [])
            self.assertEqual(actual["uninspectedInnerArchiveCount"], 1)
            uninspected = actual["uninspectedInnerArchives"][0]
            self.assertEqual(uninspected["name"], "unselected.jar")
            self.assertTrue(uninspected["completeMemberHash"])
            self.assertFalse(uninspected["interiorInspected"])
            self.assertEqual(inspection.arena.held["rows"],
                             sum(1536 + 8 * len(value[0]) + 8 * len(value[5] or "") for value in rows))
            self.assertEqual(inspection.arena.held["payload"], 0)
            self.assertEqual(actual["issuedReadBytes"], sum(count for _, count in original.reads))
            output = []
            inspection.publish(output.append)
            self.assertEqual(json.loads(output[0])["rows"], [list(value) for value in rows])
            for field in ("nativeExecuted", "nativeClosure", "supplierAuthority"):
                self.assertFalse(actual[field])

        # Complete three selected siblings, each with its own existing nested
        # count/depth boundary, but one aggregate Arena that never refunds reads.
        inner_bodies = [zip_bytes([("native.dylib", intel), ("nested.jar", zip_bytes([
            ("value", bytes([number]))]))]) for number in range(3)]
        selected = tuple((f"gradle/lib/native-{number}.jar", len(body), hashlib.sha256(body).hexdigest())
                         for number, body in enumerate(inner_bodies))
        body = zip_bytes([(entry[0], material) for entry, material in zip(selected, inner_bodies)]
                         + [("gradle/lib/not-selected.jar", b"PK\x03\x04explicitly uninspected"),
                            ("gradle/NOTICE", b"all outer bytes retained")])
        rows, summary = baseline("gradle", body)
        inspection = I._inspect_non_jdk(Original(body), C, specification("gradle", body, selected))
        actual = inspection.document
        self.assertEqual(actual["rows"], rows)
        self.assertEqual(actual["outer"], summary)
        self.assertEqual(len(actual["selectedInnerArchives"]), 3)
        for observed in actual["selectedInnerArchives"]:
            self.assertTrue(observed["completeMemberHashes"])
            self.assertEqual((observed["centralMembers"], observed["inspectedMembers"]), (2, 2))
            self.assertEqual(len(observed["nestedArchives"]), 1)
            self.assertEqual(observed["nativeMembers"][0]["selectedCpu"], "x86_64")
        self.assertEqual(actual["issuedReadBytes"], summary["issuedReadBytes"] + sum(
            observed["issuedReadBytes"] + observed["nestedArchives"][0]["issuedReadBytes"]
            for observed in actual["selectedInnerArchives"]))
        self.assertEqual(actual["uninspectedInnerArchiveCount"], 1)
        self.assertEqual(inspection.arena.held["payload"], 0)
        self.assertEqual(inspection.arena.held["rows"],
                         sum(1536 + 8 * len(value[0]) + 8 * len(value[5] or "") for value in rows))

        for bad_selection, code in (
                (((selected[0][0], selected[0][1], "0" * 64),) + selected[1:], "selected-outer-member-pin"),
                (((selected[0][0], selected[0][1] + 1, selected[0][2]),) + selected[1:], "selected-outer-member-size"),
                ((("gradle/lib/missing.jar", selected[0][1], selected[0][2]),), "non-jdk-complete-outer")):
            with self.subTest(code=code), self.assertRaisesRegex(I.InspectionRefused, code):
                I._inspect_non_jdk(Original(body), C, specification("gradle", body, bad_selection))
        with self.assertRaisesRegex(C.Refused, "original_archive_sha256"):
            I._inspect_non_jdk(Original(body), C, ("gradle", len(body), "0" * 64, selected, ()))
        # A bad selected whole hash refuses before parsing this invalid inner
        # ZIP, not after it has been trusted as a native observation.
        invalid_inner = b"PK\x03\x04not a valid inner archive"
        bad_outer = zip_bytes([("selected.jar", invalid_inner)])
        with self.assertRaisesRegex(I.InspectionRefused, "selected-outer-member-pin"):
            I._inspect_non_jdk(Original(bad_outer), C, specification("gradle", bad_outer,
                                (("selected.jar", len(invalid_inner), "0" * 64),)))
        many_nested = zip_bytes([(f"nested-{number}.jar", zip_bytes([("data", b"x")])) for number in range(4)])
        too_many = zip_bytes([("selected.jar", many_nested)])
        with self.assertRaisesRegex(I.InspectionRefused, "nested-archive-count-or-depth"):
            I._inspect_non_jdk(Original(too_many), C, specification("gradle", too_many,
                                (("selected.jar", len(many_nested), hashlib.sha256(many_nested).hexdigest()),)))

        # Bundletool's existing case-sensitive Java namespace is not normalized
        # into Gradle/AAPT2's physical namespace. A legacy i386+x64 fat object
        # still selects the real x64 snapshot, not the first architecture.
        i386 = (struct.pack("<7I", 0xFEEDFACE, 7, 3, 6, 1, 24, 0)
                + struct.pack("<II", 0x1B, 24) + b"\0" * 16).ljust(4096, b"\0")
        legacy = bytearray(universal(i386, intel))
        struct.pack_into(">II", legacy, 8, 7, 3)
        bundled = zip_bytes([("com/sun/jna/darwin/libjnidispatch.jnilib", bytes(legacy)),
                             ("classes/A.class", java), ("classes/a.class", java)])
        inspected = I._inspect_non_jdk(Original(bundled), C, specification("bundletool", bundled))
        self.assertEqual(inspected.document["outer"]["files"], 3)
        self.assertEqual(inspected.document["nativeMembers"][0]["selectedCpu"], "x86_64")
        self.assertEqual(inspected.document["nativeMembers"][0]["sliceOffset"], 8192)
        for component in ("aapt2", "gradle"):
            with self.assertRaisesRegex(C.Refused, "duplicate_or_case_colliding_member"):
                I._inspect_non_jdk(Original(bundled), C, specification(component, bundled))
        for name in ("../escape", "/absolute", "a//b"):
            malformed = zip_bytes([(name, b"data")])
            with self.assertRaises(C.Refused):
                I._inspect_non_jdk(Original(malformed), C, specification("aapt2", malformed))
        sound = zip_bytes([("aapt2", intel)])
        changed_crc = bytearray(sound)
        changed_crc[30 + len("aapt2") + len(intel) - 1] ^= 1
        changed_local_name = bytearray(sound)
        changed_local_name[30] ^= 1
        changed_central_crc = bytearray(sound)
        central = sound.index(b"PK\x01\x02")
        changed_central_crc[central + 16] ^= 1
        for broken in (changed_crc, changed_local_name, changed_central_crc):
            with self.assertRaises(C.Refused):
                I._inspect_non_jdk(Original(bytes(broken)), C, specification("aapt2", bytes(broken)))
        with self.assertRaisesRegex(I.InspectionRefused, "non-jdk-required-native-row"):
            I._inspect_non_jdk(Original(sound), C, specification("aapt2", sound,
                                required=(("aapt2", len(intel), "0" * 64, 0),)))

        # A compact real bundletool-role fixture exercises unchanged retention
        # and publication: no fake public archive pin, reduced cap or new API.
        compact = zip_bytes([("p/A.class", java), ("p/a.class", java),
                             ("p/" + "long" * 30 + ".class", java),
                             ("META-INF/notice", b"notice")])
        compact_rows, compact_summary = baseline("bundletool", compact)
        compact_owner = Original(compact)
        compact_inspection = I._inspect_non_jdk(
            compact_owner, C, specification("bundletool", compact))
        compact_charge = sum(1536 + 8 * len(value[0]) + 8 * len(value[5] or "")
                             for value in compact_rows)
        self.assertEqual(compact_inspection.document["rows"], compact_rows)
        self.assertEqual(compact_inspection.document["outer"], compact_summary)
        self.assertEqual(compact_inspection.arena.held["rows"], compact_charge)
        self.assertEqual(compact_inspection.arena.peaks["rows"], compact_charge)
        self.assertEqual(compact_inspection.arena.reads, sum(count for _, count in compact_owner.reads))
        compact_output = []
        compact_receipt = compact_inspection.publish(compact_output.append)
        self.assertEqual(json.loads(compact_output[0])["rows"], [list(value) for value in compact_rows])
        self.assertTrue(json.loads(compact_output[0])["completeOuterMemberHashes"])
        self.assertFalse(compact_receipt["nativeExecuted"])
        self.assertFalse(compact_receipt["supplierAuthority"])
        self.assertEqual(compact_receipt["peakReservations"]["rows"], compact_charge)

        # A full311-small-JAR synthetic census exercises the real all-sibling
        # algorithm. These bytes/names are NOT the vendor's311 observed tuples.
        jars = []
        for number in range(311):
            children = [("p/C.class", java)]
            if number == 0:
                children.append(("native.dylib", macho()))
            elif number == 1:
                children.append(("nested.data", zip_bytes([("notice", b"complete nested data")])))
            material = zip_bytes(children)
            jars.append((f"gradle-8.14.5/lib/sibling-{number:03}.jar", material))
        whole = zip_bytes(jars + [("gradle-8.14.5/NOTICE", b"not filtered")])
        complete = I._inspect_complete_non_jdk(Original(whole), C,
            ("gradle", len(whole), hashlib.sha256(whole).hexdigest()))
        value = complete.document
        outer_rows, outer_summary = baseline("gradle", whole)
        self.assertEqual(value["rows"], outer_rows)
        self.assertEqual(value["outer"], outer_summary)
        self.assertTrue(value["completeOuterMemberHashes"])
        self.assertTrue(value["completeInnerCoverage"])
        self.assertEqual(value["uninspectedInnerArchives"], [])
        self.assertEqual(value["uninspectedInnerArchiveCount"], 0)
        self.assertEqual(value["innerInspectionScope"], "all-complete-outer-zip-or-jmod")
        self.assertEqual([(v["name"], v["bytes"], v["sha256"]) for v in value["innerArchives"]],
                         [(name, len(body), hashlib.sha256(body).hexdigest()) for name, body in jars])
        self.assertEqual(len(value["innerArchives"]), 311)
        self.assertIsNone(value["innerArchives"][0]["negativeEvidence"])
        self.assertIsNone(value["innerArchives"][1]["negativeEvidence"])
        self.assertEqual(len(value["innerArchives"][1]["nestedArchives"]), 1)
        for inner in value["innerArchives"][2:]:
            negative = inner["negativeEvidence"]
            self.assertEqual((negative["centralMembers"], negative["inspectedMembers"], negative["files"]), (1, 1, 1))
            self.assertEqual(negative["enumerationSha256"], inner["enumerationSha256"])
            self.assertEqual((negative["nativeMembers"], negative["nestedArchives"]), ([], []))
            self.assertFalse(negative["nativeExecution"])
            self.assertFalse(negative["supplierAuthority"])
        # Complete JMOD retains its actual four-byte view offset and every
        # directory row; a directory does not fabricate a file-format count.
        jmod_zip = zip_bytes([("legal/", b""), ("legal/notice", b"x")])
        jmod_body = b"JM\x01\x00" + jmod_zip
        raw = zip_bytes([("module.jmod", jmod_body)])
        checked_jmod = I._inspect_complete_non_jdk(Original(raw), C,
            ("gradle", len(raw), hashlib.sha256(raw).hexdigest())).document["innerArchives"][0]
        self.assertEqual((checked_jmod["format"], checked_jmod["zipViewOffset"], checked_jmod["bytes"]),
                         ("jmod", 4, len(jmod_body)))
        self.assertEqual(checked_jmod["sha256"], hashlib.sha256(jmod_body).hexdigest())
        self.assertEqual((checked_jmod["centralMembers"], checked_jmod["files"], checked_jmod["directoryMembers"]),
                         (2, 1, 1))
        self.assertEqual(sum(checked_jmod["formatCounts"].values()), 1)
        self.assertEqual(checked_jmod["negativeEvidence"]["expandedInspectedBytes"], 1)
        # The inverse rejects omissions/duplicates even after actual full rows
        # have been obtained; it is not a selected-count assertion alone.
        for changed in (value["innerArchives"][:-1], value["innerArchives"] + value["innerArchives"][:1]):
            observer = I._Observer(C, I.Arena(Original()), complete=True, top_level=True)
            observer.archives = changed
            with self.assertRaisesRegex(I.InspectionRefused, "complete-outer-inner-inverse"):
                I._complete_outer_inverse(outer_rows, observer, observer.arena)
            self.assertTrue(observer.arena.failed)
        for component, prefix, count in (("sdk-platform", "android-35/", 10),
                                         ("sdk-build-tools", "android-15/", 5)):
            children = [(prefix + f"small-{index}.jar", zip_bytes([("p/C.class", java)])) for index in range(count)]
            raw = zip_bytes(children)
            sdk = I._inspect_complete_non_jdk(Original(raw), C,
                (component, len(raw), hashlib.sha256(raw).hexdigest())).document
            self.assertEqual(len(sdk["innerArchives"]), count)
            self.assertTrue(all(child["negativeEvidence"] is not None for child in sdk["innerArchives"]))
            self.assertFalse(sdk["nativeClosure"])
            self.assertFalse(sdk["supplierAuthority"])
        # A suffix/native/foreign/nested/unsupported observation can NEVER be
        # replaced by the empty negative expected for a fixed SDK resource.
        for name, payload in (("p/native.dylib", macho()), ("p/target.so", b"\x7fELF" + b"x" * 80),
                              ("p/foreign.dll", b"MZ" + b"x" * 80),
                              ("p/nested", zip_bytes([("notice", b"x")])),
                              ("p/ambiguous.class", b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 99, 1)),
                              ("p/fake.dylib", b"ordinary bytes"), ("p/empty.class", b""),
                              ("p/program", b"#!/bin/sh\nexit 0\n")):
            child = zip_bytes([(name, payload)])
            raw = zip_bytes([("android-35/android.jar", child)])
            sdk = I._inspect_complete_non_jdk(Original(raw), C,
                ("sdk-platform", len(raw), hashlib.sha256(raw).hexdigest())).document
            self.assertIsNone(sdk["innerArchives"][0]["negativeEvidence"], name)
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            info = zipfile.ZipInfo("opaque-mode"); info.create_system = 3
            info.external_attr = 0o100755 << 16
            archive.writestr(info, b"opaque executable bytes")
        raw = zip_bytes([("android-15/lib/d8.jar", output.getvalue())])
        sdk = I._inspect_complete_non_jdk(Original(raw), C,
            ("sdk-build-tools", len(raw), hashlib.sha256(raw).hexdigest())).document
        self.assertIsNone(sdk["innerArchives"][0]["negativeEvidence"])
        self.assertEqual(sdk["innerArchives"][0]["unknownMembers"][0]["reason"], "executable-opaque")
        for name, payload in (("wrong.jar", b"not an archive"), ("wrong.jmod", zip_bytes([("x", b"x")])),
                              ("empty.jar", zip_bytes([])),  # Existing parser requires a nonempty central census.
                              ("garbage.jar", b"PK\x03\x04not a complete ZIP")):
            raw = zip_bytes([(name, payload)])
            with self.assertRaises((I.InspectionRefused, C.Refused)):
                I._inspect_complete_non_jdk(Original(raw), C,
                    ("gradle", len(raw), hashlib.sha256(raw).hexdigest()))
        # The completed collector still rejects an inner CRC error. The outer
        # hash is intentionally recomputed over the malformed synthetic input.
        broken = bytearray(zip_bytes([("value", b"known bytes")]))
        broken[30 + len("value")] ^= 1
        raw = zip_bytes([("actual.jar", bytes(broken))])
        with self.assertRaises(C.Refused):
            I._inspect_complete_non_jdk(Original(raw), C,
                ("gradle", len(raw), hashlib.sha256(raw).hexdigest()))

    def test_nested_and_simultaneous_workspace_limits_fail_without_resetting_the_original(self):
        leaf = zip_bytes([("value", b"complete")])
        one = zip_bytes([("one.jar", leaf)])
        two = zip_bytes([("two.jar", one)])
        result, arena = inspect_bytes(two, "root.zip")
        self.assertEqual(result["nestedArchives"][0]["nestedArchives"][0]["files"], 1)
        self.assertGreater(arena.expanded, len(leaf) + len(one))
        self.assertEqual(arena.held["payload"], 0)
        for raw in (zip_bytes([("third.jar", two)]),
                    zip_bytes([(f"{index}.jar", leaf) for index in range(4)])):
            with self.assertRaisesRegex(I.InspectionRefused, "nested-archive-count-or-depth"):
                inspect_bytes(raw)
        for kind, reserve, message in (("payload", I.PAYLOAD_LIMIT, "aggregate-payload"),
                                       ("rows", I.ROWS_LIMIT, "aggregate-row")):
            held = I.Arena(Original())
            held.reserve(kind, reserve)
            with self.assertRaisesRegex(I.InspectionRefused, message):
                inspect_bytes(leaf, arena=held)
            self.assertTrue(held.failed)
            held.release(kind, reserve)
            with self.assertRaisesRegex(I.InspectionRefused, "already-failed"):
                held.check()
        expanded = I.Arena(Original())
        expanded.charge_expanded(I.EXPANDED_LIMIT - 3)
        with self.assertRaisesRegex(I.InspectionRefused, "aggregate-inner-expansion"):
            inspect_bytes(zip_bytes([("a", b"12"), ("b", b"34")]), arena=expanded)
        self.assertTrue(expanded.failed)
        self.assertEqual(expanded.held["payload"], 0)
        self.assertEqual(expanded.held["rows"], 0)
        read_bound = I.Arena(Original())
        read_bound.charge_read(I.READ_LIMIT)
        with self.assertRaisesRegex(I.InspectionRefused, "aggregate-issued-read"):
            inspect_bytes(leaf, arena=read_bound)
        self.assertEqual(read_bound.reads, I.READ_LIMIT)
        # All recursive views still contribute their actual independent
        # admission/structural/payload reads to ONE original finite Arena.
        documents = (result, result["nestedArchives"][0],
                     result["nestedArchives"][0]["nestedArchives"][0])
        required = sum(2 * len(body) + min(len(body), 65557) - 22 for body in (two, one, leaf))
        self.assertEqual(sum(item["issuedReadBytes"] for item in documents), required)
        self.assertEqual(arena.reads, required)
        exact = I.Arena(Original())
        exact.charge_read(I.READ_LIMIT - required)
        _, exact = inspect_bytes(two, "root.zip", arena=exact)
        self.assertEqual(exact.reads, I.READ_LIMIT)
        self.assertFalse(exact.failed)
        over = I.Arena(Original())
        over.charge_read(I.READ_LIMIT - required + 1)
        with self.assertRaisesRegex(I.InspectionRefused, "aggregate-issued-read"):
            inspect_bytes(two, "root.zip", arena=over)
        self.assertTrue(over.failed)
        self.assertLessEqual(over.reads, I.READ_LIMIT)
        self.assertEqual(over.held["payload"], 0)
        self.assertEqual(over.held["rows"], 0)
        with self.assertRaisesRegex(I.InspectionRefused, "already-failed"):
            over.check()

        # Four top-level siblings each retain their own existing nested3/depth2
        # constraint, but all actual reads/expansion remain one cumulative Arena.
        child = zip_bytes([("value", b"1234")])
        parent = zip_bytes([("nested", child)])
        body = zip_bytes([(f"sibling-{index}.jar", parent) for index in range(4)])
        pin = C.Pin("gradle", len(body), hashlib.sha256(body).hexdigest())
        original = Original(body)
        arena = I.Arena(original)
        observer = I._Observer(C, arena, complete=True, top_level=True)
        summary = C.compile_archive(original, pin, observer=observer, workspace=arena).consume_rows(lambda _: None)
        I._complete_census(observer, summary)
        self.assertEqual(len(observer.archives), 4)
        self.assertTrue(all(len(archive["nestedArchives"]) == 1 for archive in observer.archives))
        expected_reads = summary["issuedReadBytes"] + sum(
            item["issuedReadBytes"] + item["nestedArchives"][0]["issuedReadBytes"] for item in observer.archives)
        self.assertEqual(arena.reads, expected_reads)
        expected_expansion = sum(item["expandedInspectedBytes"] + item["nestedArchives"][0]["expandedInspectedBytes"]
                                 for item in observer.archives)
        self.assertEqual(arena.expanded, expected_expansion)
        self.assertEqual((arena.held["payload"], arena.held["rows"]), (0, 0))
        for counter, used, bound in (("read", expected_reads, I.READ_LIMIT),
                                      ("expanded", expected_expansion, I.EXPANDED_LIMIT)):
            original = Original(body); limited = I.Arena(original)
            if counter == "read":
                limited.charge_read(bound - used + 1)
            else:
                limited.charge_expanded(bound - used + 1)
            collector = I._Observer(C, limited, complete=True, top_level=True)
            try:
                with self.assertRaisesRegex(I.InspectionRefused, "aggregate-(issued-read|inner-expansion)"):
                    C.compile_archive(original, pin, observer=collector, workspace=limited)
            finally:
                collector.dispose_current()
            self.assertTrue(limited.failed)
            self.assertEqual((limited.held["payload"], limited.held["rows"]), (0, 0))
            with self.assertRaisesRegex(I.InspectionRefused, "already-failed"):
                limited.check()
        for options in ({"top_level": True}, {"complete": 1}, {"complete": True, "expected": {}},
                        {"complete": True, "outer_selection": ()},
                        {"complete": True, "top_level": True, "depth": 1},
                        {"complete": True, "top_level": True, "nested_count": [0]}):
            with self.assertRaisesRegex(I.InspectionRefused, "complete-observer-context"):
                I._Observer(C, I.Arena(Original()), **options)
        fourth_nested = zip_bytes([(f"nested-{number}", child) for number in range(4)])
        raw = zip_bytes([("parent.jar", fourth_nested)])
        with self.assertRaisesRegex(I.InspectionRefused, "nested-archive-count-or-depth"):
            I._inspect_complete_non_jdk(Original(raw), C,
                ("gradle", len(raw), hashlib.sha256(raw).hexdigest()))
        oversized = I.Inspection(I.Arena(Original()), {"data": "x" * (I.OUTPUT_LIMIT + 1)})
        with self.assertRaisesRegex(I.InspectionRefused, "inspection-output-bound"):
            oversized.publish(lambda _: self.fail("oversized output must not escape"))
        self.assertTrue(oversized.arena.failed)
        self.assertFalse(oversized.published)

    def test_fixed_nomination_and_final_publication_never_recover_an_original_failure(self):
        parser_bytes = (_TOOLS / "macos_android_supplier_correspondence.py").read_bytes()
        loader_tree = ast.parse((_TOOLS / "macos_android_supplier_preparation.py").read_bytes())
        pins = {node.targets[0].id: ast.literal_eval(node.value) for node in loader_tree.body
                if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in {"CORRESPONDENCE_BYTES", "CORRESPONDENCE_SHA256"}}
        self.assertEqual(pins, {"CORRESPONDENCE_BYTES": len(parser_bytes),
                                "CORRESPONDENCE_SHA256": hashlib.sha256(parser_bytes).hexdigest()})
        # Exact observed root DATA, not a synthetic native census or host mode.
        root = ["jdk-17.0.20.1+1", "directory", 17901, 0] + [None] * 10
        rows = [root] + [[I.JDK_ROOT + f"metadata-{index}", "directory", 0o40755, 0]
                         + [None] * 10 for index in range(548)]
        unchanged = [value[:] for value in rows]
        expected = {value[0]: tuple(value) for value in rows}
        self.assertEqual(I._correspondence_rows(rows), expected)
        self.assertEqual(len(expected), 549)
        self.assertEqual(expected[root[0]], tuple(root))
        self.assertEqual(rows, unchanged)
        # The root is required exactly once; no row is discarded or renamed.
        for value in (tuple(rows), rows[:-1], rows + [root[:]],
                      [rows[1][:]] + rows[1:], [root[:], root[:]] + rows[2:]):
            with self.assertRaisesRegex(I.InspectionRefused, "original-correspondence-roster"):
                I._correspondence_rows(value)
        for index, value in ((0, root[0] + "/"), (0, root[0] + "-other"),
                             (1, "file"), (1, "link"), (2, 0o40755), (2, True),
                             (3, 1), (3, False)):
            changed = [item[:] for item in rows]
            changed[0][index] = value
            with self.subTest(rootField=index, value=value), self.assertRaisesRegex(
                    I.InspectionRefused, "original-correspondence-roster"):
                I._correspondence_rows(changed)
        for index in range(4, 14):
            changed = [item[:] for item in rows]
            changed[0][index] = "not-null"
            with self.subTest(rootField=index), self.assertRaisesRegex(
                    I.InspectionRefused, "original-correspondence-roster"):
                I._correspondence_rows(changed)
        for name in (root[0] + "0/metadata", root[0] + "-foreign/metadata", "/" + I.JDK_ROOT, None, []):
            changed = [item[:] for item in rows]
            changed[1][0] = name
            with self.subTest(descendant=name), self.assertRaisesRegex(
                    I.InspectionRefused, "original-correspondence-roster"):
                I._correspondence_rows(changed)
        for malformed in (tuple(rows[1]), rows[1][:-1], rows[1] + [None], None):
            changed = [item[:] for item in rows]
            changed[1] = malformed
            with self.assertRaisesRegex(I.InspectionRefused, "original-correspondence-roster"):
                I._correspondence_rows(changed)
        self.assertEqual(rows, unchanged)
        owner = Original(b"never read this as an admitted supplier")
        for forged in (b"{}", b"x" * I.CORRESPONDENCE_BYTES):
            with self.assertRaisesRegex(I.InspectionRefused, "original-correspondence-pin"):
                I.inspect_jdk(owner, forged, C)
        self.assertEqual(owner.reads, [])
        document = {"nativeExecuted": False, "nativeClosure": False, "supplierAuthority": False,
                    "facts": ["one", "two"]}
        arena = I.Arena(Original())
        report = I.Inspection(arena, document)
        published = []
        receipt = report.publish(published.append)
        self.assertEqual(json.loads(published[0]), document)
        self.assertEqual(receipt["sha256"], hashlib.sha256(published[0]).hexdigest())
        self.assertGreaterEqual(receipt["peakReservedBytes"], 8 * I.MIB + 2 * len(published[0]))
        with self.assertRaisesRegex(I.InspectionRefused, "publication-finality"):
            report.publish(lambda _: self.fail("a terminal report cannot publish twice"))
        for failure in ("sink", "binding", "endpoint"):
            with self.subTest(failure=failure):
                original = Original()
                failed = I.Inspection(I.Arena(original), document)
                def sink(_):
                    if failure == "sink":
                        raise ValueError("original-sink-failure")
                    if failure == "binding":
                        original.changed = True
                    else:
                        original.expired = True
                with self.assertRaises((C.Refused, ValueError)):
                    failed.publish(sink)
                self.assertTrue(failed.arena.failed)
                self.assertFalse(failed.published)
                original.changed = original.expired = False  # Cannot reset the inspector latch.
                with self.assertRaisesRegex(I.InspectionRefused, "already-failed"):
                    failed.publish(lambda _: self.fail("failed partial output is not a receipt"))

        self.assertEqual(tuple(value[0] for value in I.NON_JDK_ARCHIVES), ("aapt2", "gradle", "bundletool"))
        self.assertEqual(tuple(value[:3] for value in I.NON_JDK_ARCHIVES), (
            ("aapt2", 4339472, "5d0aec6851fffbc9f6c8a8b50390c0bc976aa0ddf57a8a3a39061ed54b609ad1"),
            ("gradle", 138068841, "6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854"),
            ("bundletool", 32520401, "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29"),
        ))
        self.assertEqual(I.NON_JDK_ARCHIVES[0][4], (("aapt2", 11143368,
            "213e3d049e2c85daa930ed777bbd5627c1c5479a8d6698029b8f9c0161ad0a7e", 0o100755),))
        self.assertEqual(I.NON_JDK_ARCHIVES[1][3], (
            ("gradle-8.14.5/lib/native-platform-osx-amd64-0.22-milestone-28.jar", 12867,
             "61ab872b419deae8cdf37d1a0d5f6916b170ada1226129741fceb3ebd56b950f"),
            ("gradle-8.14.5/lib/gradle-fileevents-0.2.7.jar", 1433862,
             "9f8d26b0057ed645af68c8d4139988d69ee884ad8d009e98a793c08cbdd3d2f8"),
            ("gradle-8.14.5/lib/jansi-1.18.jar", 287352,
             "109e64fc65767c7a1a3bd654709d76f107b0a3b39db32cbf11139e13a6f5229b"),
        ))
        class StringSubclass(str):
            pass
        original = Original(b"no component may redirect this original")
        for component in (None, True, 1, [], {}, b"aapt2", "jdk", "AAPT2", "aapt2/", StringSubclass("aapt2")):
            with self.assertRaisesRegex(I.InspectionRefused, "non-jdk-component"):
                I.inspect_non_jdk(original, component, C)
        self.assertEqual((original.reads, original.checks, original.bindings), ([], 0, 0))
        for component in ("aapt2", "gradle", "bundletool"):
            with self.assertRaises(C.Refused):
                I.inspect_non_jdk(Original(b"synthetic bytes are not the nominated original"), component, C)
        # A real parsed non-JDK DATA report retains the same original until its
        # terminal publication; no resetting a sink/late-original failure.
        body = zip_bytes([("NOTICE", b"tiny synthetic DATA")])
        spec = ("bundletool", len(body), hashlib.sha256(body).hexdigest(), (), ())
        for reason in ("sink", "binding", "endpoint"):
            original = Original(body)
            report = I._inspect_non_jdk(original, C, spec)
            def failing_sink(_):
                if reason == "sink":
                    raise ValueError("original-sink-failure")
                if reason == "binding":
                    original.changed = True
                else:
                    original.expired = True
            with self.assertRaises((C.Refused, ValueError)):
                report.publish(failing_sink)
            self.assertTrue(report.arena.failed)
            self.assertFalse(report.published)
            original.changed = original.expired = False
            with self.assertRaisesRegex(I.InspectionRefused, "already-failed"):
                report.publish(lambda _: self.fail("failed non-JDK output cannot become success"))

        self.assertEqual(I.COMPLETE_NON_JDK_ARCHIVES, (
            ("gradle", 138068841, "6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854"),
            ("sdk-platform", 64273788, "0988cacad01b38a18a47bac14a0695f246bc76c1b06c0eeb8eb0dc825ab0c8e0"),
            ("sdk-build-tools", 76857898, "530cdbd1ec315e1477624d7ed2f0f2962108d69f36eddba5894cef9ea2cedb48"),
        ))
        untouched = Original(b"invalid selection must never touch this original")
        for component in (None, True, 1, [], {}, b"gradle", "jdk", "aapt2", "bundletool", "Gradle", "gradle/", StringSubclass("gradle")):
            with self.assertRaisesRegex(I.InspectionRefused, "complete-non-jdk-component"):
                I.inspect_complete_non_jdk(untouched, component, C)
        self.assertEqual((untouched.reads, untouched.checks, untouched.bindings), ([], 0, 0))
        for component in ("gradle", "sdk-platform", "sdk-build-tools"):
            with self.assertRaises(C.Refused):
                I.inspect_complete_non_jdk(Original(b"not the fixed public body"), component, C)
        body = zip_bytes([("android-35/android.jar", zip_bytes([("notice", b"complete")]))])
        spec = ("sdk-platform", len(body), hashlib.sha256(body).hexdigest())
        passed = I._inspect_complete_non_jdk(Original(body), C, spec)
        output = []; receipt = passed.publish(output.append)
        self.assertEqual(len(output), 1)
        observed = json.loads(output[0])
        self.assertEqual(observed["kind"], "mrk-intel-complete-non-jdk-observation-data-v1")
        self.assertTrue(observed["completeInnerCoverage"])
        self.assertTrue(observed["innerArchives"][0]["negativeEvidence"]["completeMemberHashes"])
        self.assertEqual(receipt["sha256"], hashlib.sha256(output[0]).hexdigest())
        self.assertEqual(receipt["bytes"], len(output[0]))
        self.assertFalse(observed["nativeExecuted"])
        self.assertFalse(observed["nativeClosure"])
        self.assertFalse(observed["supplierAuthority"])
        with self.assertRaisesRegex(I.InspectionRefused, "publication-finality"):
            passed.publish(lambda _: self.fail("no second successful publication"))
        for failure in ("sink", "binding", "endpoint"):
            original = Original(body)
            report = I._inspect_complete_non_jdk(original, C, spec)
            def refuse(_):
                if failure == "sink":
                    raise ValueError("complete-original-sink-failure")
                if failure == "binding":
                    original.changed = True
                else:
                    original.expired = True
            with self.assertRaises((C.Refused, ValueError)):
                report.publish(refuse)
            self.assertTrue(report.arena.failed)
            self.assertFalse(report.published)
            original.changed = original.expired = False
            with self.assertRaisesRegex(I.InspectionRefused, "already-failed"):
                report.publish(lambda _: self.fail("failed complete DATA is not a receipt"))
