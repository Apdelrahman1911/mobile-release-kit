"""Focused passive-DATA regressions for the official-PKG orchestration tool.

No official package, framework or native tool is executed by these tests. Tiny
Mach-O byte fixtures describe parser boundaries, not working macOS binaries.
"""
from __future__ import annotations

import ast
import copy
from contextlib import nullcontext
import importlib.util
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock


PREP = BUILD = None
if sys.platform in ("darwin", "linux"):
    _PATH = Path(__file__).absolute().parents[2] / "desktop/tools/macos_cpython_orchestrator.py"
    _SPEC = importlib.util.spec_from_file_location("macos_cpython_orchestrator_data", _PATH)
    PREP = importlib.util.module_from_spec(_SPEC)
    _SPEC.loader.exec_module(PREP)
    BUILD = PREP.build_data()

ARM = 0x0100000C
INTEL = 0x01000007


def cstring_command(command, value, *, extra_capacity=0):
    """One bounded dylib/dylinker/RPATH DATA string command."""
    prefix = 12 if command in (0x8000001C, 0xE) else 24
    encoded = value.encode("utf-8") + b"\0"
    size = (prefix + len(encoded) + extra_capacity + 7) // 8 * 8
    words = (command, size, prefix) if prefix == 12 else (command, size, prefix, 0, 0, 0)
    return struct.pack("<" + "I" * len(words), *words) + encoded + bytes(size - prefix - len(encoded))


def thin_fixture(cpu=ARM, *, commands=(), payload=b"MRK-PASSIVE-MACHO-DATA"):
    """64-bit little-endian dylib fixture; never a native test receipt."""
    subtype = 0 if cpu == ARM else 3
    command_bytes = b"".join(commands)
    return struct.pack("<8I", 0xFEEDFACF, cpu, subtype, 6, len(commands), len(command_bytes), 0x84, 0) + command_bytes + payload


def fat_fixture(arm, intel):
    """Two disjoint universal2 DATA slices, aligned at64 bytes."""
    arm_offset = 64
    intel_offset = (arm_offset + len(arm) + 63) // 64 * 64
    header = struct.pack(">2I", 0xCAFEBABE, 2)
    header += struct.pack(">5I", ARM, 0, arm_offset, len(arm), 6)
    header += struct.pack(">5I", INTEL, 3, intel_offset, len(intel), 6)
    return (header + bytes(arm_offset - len(header)) + arm
            + bytes(intel_offset - arm_offset - len(arm)) + intel)


def inventory_rows(*files, links=None):
    """Only passive paths: resolution tests never traverse these names."""
    rows = {}
    for name in (*files, *(links or {})):
        for parent in reversed(PurePosixPath(name).parents):
            if str(parent) != ".":
                rows[str(parent)] = {"kind": "directory"}
        rows[name] = {"kind": "file"}
    for name, target in (links or {}).items():
        rows[name] = {"kind": "link", "target": target}
    return rows


class PipeOriginal:
    """A process DATA double with two real, finite, fixture-owned pipe readers.

    No child exists. kill/wait/poll below only record actions on this object.
    The real streams exercise the existing selector/drain/close implementation.
    """
    def __init__(self, *, returncode=0, interrupt=False, wait_error=False, close_error=False, stderr=b""):
        self.returncode, self.interrupt, self.wait_error = returncode, interrupt, wait_error
        self.events, self.streams = [], []
        try:
            for body in (b"ordinary-output\n", stderr):
                reader, writer = os.pipe()
                try:
                    if body:
                        assert os.write(writer, body) == len(body)
                    stream = os.fdopen(reader, "rb", buffering=0)
                    reader = None
                    self.streams.append(stream)
                finally:
                    os.close(writer)
                    if reader is not None:
                        os.close(reader)
            self.stdout, self.stderr = self.streams
            if close_error:
                original = self.stdout
                class CloseFailure:
                    def fileno(self):
                        return original.fileno()

                    def close(self):
                        original.close()
                        raise OSError("inert reported original close failure")
                self.stdout = CloseFailure()
        except BaseException:
            self.close()
            raise

    def poll(self):
        self.events.append("poll")
        if self.interrupt:
            self.interrupt = False
            raise KeyboardInterrupt("inert cancellation observation")
        return self.returncode

    def kill(self):
        self.events.append("kill-original-double")
        self.returncode = -9

    def wait(self, timeout):
        self.events.append(("wait-original-double", timeout))
        if self.wait_error:
            raise OSError("inert original wait unavailable")
        return self.returncode

    def close(self):
        for stream in self.streams:
            if not stream.closed:
                stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


@unittest.skipUnless(PREP is not None, "POSIX passive orchestration DATA only")
class MacCPythonOrchestratorDataTests(unittest.TestCase):
    def test_fixed_package_authority_and_exact_framework_selection(self):
        # Nominated metadata is not a downloaded package or signature receipt.
        digest = "70c5239ad2d62925d2947e46921d0ddd3d35be3d2f0a2d50db33da507dbcb419"
        self.assertEqual(PREP.PACKAGE_URL, "https://www.python.org/ftp/python/3.14.7/python-3.14.7-macos11.pkg")
        self.assertEqual(PREP.PACKAGE_SHA256, digest)
        self.assertEqual(PREP.INTEL_AUX_RELATIVE, "Versions/3.14/bin/python3.14-intel64")
        self.assertEqual(PREP.INTEL_AUX_SIZE, 49712)
        self.assertEqual(PREP.INTEL_AUX_SHA256,
                         "abcc6dc44fbaf4695699ab8d584892b7f5936e03c1986da1098c93d02ba7a771")
        self.assertNotEqual(PREP.INTEL_AUX_RELATIVE, PREP.ENTRY_RELATIVE)
        self.assertIsNone(PREP.package_binding(PREP.PACKAGE_LIMIT, digest))
        for size, value in ((0, digest), (True, digest), (1.0, digest),
                            (PREP.PACKAGE_LIMIT + 1, digest), (1, "0" * 64)):
            with self.subTest(size=size, valid_digest=value == digest), self.assertRaises(PREP.PreparationRefused):
                PREP.package_binding(size, value)

        # Exact observed PackageInfo from the SHA-bound public package,
        # Python_Framework.pkg/PackageInfo (945 bytes, SHA256
        # 1b054010e6fb0733ee35a87acab94c1dc9b619178c3f17da6201515cd327737b).
        # Component version 0 is not runtime-version authority.
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<pkg-info overwrite-permissions="true" relocatable="false" identifier="org.python.Python.PythonFramework-3.14" postinstall-action="none" version="0" format-version="2" generator-version="InstallCmds-864.12 (25G72)" install-location="/Library/Frameworks/Python.framework" auth="root">\n'
            '    <payload numberOfFiles="4201" installKBytes="123109"/>\n'
            '    <bundle path="./Versions/3.14/Resources/Python.app" id="org.python.python" CFBundleShortVersionString="3.14.7" CFBundleVersion="3.14.7"/>\n'
            '    <bundle-version>\n'
            '        <bundle id="org.python.python"/>\n'
            '    </bundle-version>\n'
            '    <upgrade-bundle>\n'
            '        <bundle id="org.python.python"/>\n'
            '    </upgrade-bundle>\n'
            '    <update-bundle/>\n'
            '    <atomic-update-bundle/>\n'
            '    <strict-identifier>\n'
            '        <bundle id="org.python.python"/>\n'
            '    </strict-identifier>\n'
            '    <relocate/>\n'
            '    <scripts>\n'
            '        <postinstall file="./postinstall" timeout="600"/>\n'
            '    </scripts>\n'
            '</pkg-info>'
        )
        self.assertTrue(PREP.framework_component(xml.encode()))
        for version in ("1", "3.14.7", "3.14.7.0", "3.14.6", "00", "0.0", ""):
            with self.subTest(component_version=version), self.assertRaises(PREP.PreparationRefused):
                PREP.framework_component(xml.replace('version="0"', f'version="{version}"').encode())
        with self.assertRaises(PREP.PreparationRefused):
            PREP.framework_component(xml.replace(' version="0"', "").encode())
        for foreign in ("PythonFramework-3.14t", "PythonApplications-3.14"):
            self.assertFalse(PREP.framework_component(xml.replace("PythonFramework-3.14", foreign).encode()))
        bad = [xml.replace("/Library/Frameworks/Python.framework", "/Library/Frameworks/PythonT.framework").encode(),
               b"<!DOCTYPE pkg-info [<!ENTITY x 'bad'>]>" + xml.encode(),
               xml.encode("utf-16-le"), xml.encode("utf-16-be"),
               xml.encode("utf-32-le"), xml.encode("utf-32-be"),
               b"\xff" + xml.encode(), b"\0" + xml.encode(), b"<pkg-info", b"<foreign/>"]
        for number, body in enumerate(bad):
            with self.subTest(malformed_package_info=number), self.assertRaises(PREP.PreparationRefused):
                PREP.framework_component(body)


        # Only public, narrowly selected pkgutil facts may leave the task.
        # These arbitrary subjects remain diagnostics, not accepted trust.
        subject = "Developer ID Installer: Python Software Foundation (PUBLIC1234)"
        modern = "signed by a developer certificate issued by Apple for distribution"
        legacy = "signed by a certificate trusted by macOS"
        prefix = b'Package "/private/MRK-OUTPUT-CANARY.pkg":\n'
        suffix = ("\nCertificate Chain:\n    1. " + subject + "\n"
                  "Other private fixture field: MRK-OUTPUT-CANARY\n").encode()
        fields = {"stdoutSize", "stdoutSha256", "utf8", "legacyTrustPhrasePresent",
                  "psfInstallerSubjectPresent", "statusShape", "statusText", "psfSubjectShape", "psfSubject"}
        for status_text in (legacy, modern):
            raw = prefix + ("   Status: " + status_text).encode() + suffix
            row = PREP.package_signature_observation(raw)
            self.assertEqual(set(row), fields)
            self.assertEqual((row["stdoutSize"], row["stdoutSha256"]),
                             (len(raw), PREP.hashlib.sha256(raw).hexdigest()))
            self.assertIs(row["utf8"], True)
            self.assertIs(row["legacyTrustPhrasePresent"], status_text == legacy)
            self.assertIs(row["psfInstallerSubjectPresent"], True)
            self.assertEqual((row["statusShape"], row["statusText"]), ("single", status_text))
            self.assertEqual((row["psfSubjectShape"], row["psfSubject"]), ("single", subject))
            serialized = PREP.json.dumps(row)
            self.assertNotIn("MRK-OUTPUT-CANARY", serialized)
            self.assertNotIn("/private/", serialized)

        for status_field in (b"\t" + modern.encode(), modern.encode() + b"\r",
                             modern.encode() + b"\x00", b"\x1b[31msigned", b"private/path",
                             b"private\\path", b"private@example", b"A" * 201,
                             "signed\u00a0certificate".encode()):
            with self.subTest(unpublishable_status=status_field):
                row = PREP.package_signature_observation(prefix + b"Status: " + status_field + suffix)
                self.assertEqual((row["statusShape"], row["statusText"]), ("unpublishable", None))
        row = PREP.package_signature_observation(prefix + b"Status: " + b"A" * 200 + suffix)
        self.assertEqual((row["statusShape"], row["statusText"]), ("single", "A" * 200))
        for other in (b"Status: unsigned", b"Status:\tMALFORMED", b"Status: /private/CANARY"):
            row = PREP.package_signature_observation(b"Status: " + modern.encode() + b"\n" + other)
            self.assertEqual((row["statusShape"], row["statusText"]), ("multiple", None))
        row = PREP.package_signature_observation(prefix + b"NotStatus: " + modern.encode())
        self.assertEqual((row["statusShape"], row["statusText"]), ("absent", None))
        row = PREP.package_signature_observation(b"Status: unsigned\nDeveloper ID Installer: Other (PRIVATE123)")
        self.assertEqual((row["psfSubjectShape"], row["psfSubject"]), ("absent", None))
        self.assertIs(row["psfInstallerSubjectPresent"], False)
        row = PREP.package_signature_observation((subject + "\n" + subject).encode())
        self.assertEqual((row["psfSubjectShape"], row["psfSubject"]), ("multiple", None))
        self.assertIs(row["psfInstallerSubjectPresent"], True)
        row = PREP.package_signature_observation(b"Status: signed\n\xff" + subject.encode())
        self.assertIs(row["utf8"], False)
        for key in ("statusText", "psfSubject", "legacyTrustPhrasePresent", "psfInstallerSubjectPresent"):
            self.assertIsNone(row[key])
        self.assertEqual((row["statusShape"], row["psfSubjectShape"]), ("invalid-utf8", "invalid-utf8"))

        # Synthetic parser DATA uses the genuine observed public status and
        # subject, not a certificate or a native signature-verification receipt.
        expected_subject = "Developer ID Installer: Python Software Foundation (BMM5U3QVKW)"
        status_line = ("   Status: " + modern + "\n").encode()
        subject_line = ("    1. " + expected_subject + "\n").encode()
        signed = prefix + status_line + b"Certificate Chain:\n" + subject_line
        self.assertTrue(PREP.package_signature_valid(signed))
        self.assertTrue(PREP.package_signature_valid(status_line + expected_subject.encode()))
        self.assertTrue(PREP.package_signature_valid(
            ("\tStatus: " + modern + "  \n\t2. " + expected_subject + "  \n").encode()))

        refused = [
            None, signed.decode(), bytearray(signed), {}, b"", b" " * (PREP.MIB + 1),
            signed + b"\xff", signed.decode().encode("utf-16"),
            subject_line, status_line, status_line + b"Certificate Chain:\n",
            signed.replace(modern.encode(), legacy.encode()),
            signed.replace(modern.encode(), b"unsigned"),
            signed.replace(modern.encode(), b""),
            signed.replace(modern.encode(), b"unknown positive status"),
            signed.replace(modern.encode(), modern.encode() + b" but untrusted"),
            signed.replace(b"Status: ", b"Status:\t"),
            signed.replace(b"   Status:", "\u00a0Status:".encode()),
            signed.replace(modern.encode(), modern.replace("by a", "by\u00a0a").encode()),
            signed.replace(modern.encode(), modern.encode() + b"\r"),
            signed.replace(modern.encode(), b"\x1b[32m" + modern.encode()),
            signed + b"\0Status: unsigned\n",
            signed + status_line,
            signed + b"Status: unsigned\n",
            signed + b"\tStatus:\tMALFORMED\n",
            signed + "\u00a0Status: unsigned\n".encode(),
            signed.replace(b"BMM5U3QVKW", b"PUBLIC1234"),
            signed.replace(b"Python Software Foundation", b"Another Foundation"),
            signed.replace(subject_line, ("Comment: " + expected_subject + "\n").encode()),
            signed.replace(subject_line, ("    1. " + expected_subject + " extra\n").encode()),
            signed.replace(subject_line, ("    0001. " + expected_subject + "\n").encode()),
            signed.replace(subject_line, ("    1000. " + expected_subject + "\n").encode()),
            signed.replace(subject_line, ("\u00a0" + expected_subject + "\n").encode()),
            signed + subject_line,
            signed + b"    2. Developer ID Installer: Other (PUBLIC1234)\n",
        ]
        for number, body in enumerate(refused):
            with self.subTest(refused_signature=number), self.assertRaisesRegex(
                    PREP.PreparationRefused, r"^package-trusted-PSF-signature$"):
                PREP.package_signature_valid(body)
        # Publishing one public-looking PSF subject does not authenticate its
        # arbitrary TeamID or authorize a public diagnostic dictionary as input.
        diagnostic_only = prefix + status_line + suffix
        self.assertEqual(PREP.package_signature_observation(diagnostic_only)["psfSubjectShape"], "single")
        for value in (diagnostic_only, PREP.package_signature_observation(signed)):
            with self.assertRaises(PREP.PreparationRefused):
                PREP.package_signature_valid(value)

        # These are rejected Python path INPUTS, never native/package evidence.
        # Public-only origin is supplied by the real prepare callsite below.
        phase = "expanded-inventory"
        cases = [
            ("pkg/Payload/caf\u00e9.py", "nonPrintableASCII", "captured"),
            ("pkg/Payload/a\\b", "backslash", "captured"),
            ("pkg/Payload/\udcff.py", "nonPrintableASCII", "captured"),
            ("pkg/Payload/line\nname", "nonPrintableASCII", "captured"),
            ("/private/MRK-PATH-CANARY/file", "absolute", "unsafe-structure"),
            ("pkg/../MRK-PATH-CANARY", "components", "unsafe-structure"),
            ("pkg//MRK-PATH-CANARY", "components", "unsafe-structure"),
            ("pkg/./MRK-PATH-CANARY", "components", "unsafe-structure"),
            ("", "length", "unsafe-structure"),
            ("x" * 4097, "length", "escaped-bound"),
            ("\u00e9" * 8193, "length", "utf8-bound"),
            ("x" * 65537, "length", "input-bound"),
            (b"MRK-PATH-CANARY", "notString", "non-string"),
        ]
        class NoStringification:
            def __str__(self):
                raise AssertionError("diagnostic must not stringify arbitrary inputs")
            def __repr__(self):
                raise AssertionError("diagnostic must not repr arbitrary inputs")
        cases.append((NoStringification(), "notString", "non-string"))
        for number, (name, reason, capture) in enumerate(cases):
            with self.subTest(rejected_public_input=number):
                try:
                    PREP.relative_name(name)
                except PREP.PreparationRefused as original:
                    self.assertEqual(original.args, ("relative-name",))
                    self.assertIs(original.__dict__["_relative_name_input"], name)
                    facts = PREP.public_member_failure(original, phase)
                    self.assertIs(original.__dict__["_relative_name_input"], name)
                    self.assertEqual(original.args, ("relative-name",))
                    self.assertEqual((facts["phase"], facts["spellingState"]), (phase, capture))
                    self.assertIs(facts["reasons"][reason], True)
                    self.assertTrue(all(type(flag) is bool for flag in facts["reasons"].values()))
                    detailed = type(name) is str and len(name) <= 65536
                    self.assertIs(facts["detailsInspected"], detailed)
                    self.assertEqual(facts["characterCount"], len(name) if type(name) is str else None)
                    if detailed:
                        raw = name.encode("utf-8", "surrogatepass")
                        self.assertEqual((facts["utf8Size"], facts["sha256"]),
                                         (len(raw), PREP.hashlib.sha256(raw).hexdigest()))
                    else:
                        self.assertIsNone(facts["utf8Size"])
                        self.assertIsNone(facts["sha256"])
                    if capture == "captured":
                        self.assertEqual(PREP.json.loads(facts["jsonSpelling"]), name)
                        self.assertLessEqual(len(facts["jsonSpelling"].encode("ascii")), 4096)
                        self.assertLessEqual(facts["utf8Size"], 16384)
                    else:
                        self.assertIsNone(facts["jsonSpelling"])
                    self.assertNotIn("MRK-PATH-CANARY", PREP.json.dumps(facts))
                    for unavailable in (None, "unrelated-task", 1):
                        self.assertIsNone(PREP.public_member_failure(original, unavailable))
                else:
                    self.fail("unchanged relative-name policy unexpectedly admitted invalid input")
        for accepted in ("pkg/Public Space/module.py", "a" * 4096):
            self.assertIs(PREP.relative_name(accepted), accepted)
        self.assertIsNone(PREP.public_member_failure(PREP.PreparationRefused("relative-name"), phase))
        self.assertIsNone(PREP.public_member_failure(ValueError("relative-name"), phase))

        # Missing aliases retain the original refusal and inert logical context.
        rows = {"a": {"kind": "link", "target": "dir/link"},
                "dir": {"kind": "directory"},
                "dir/link": {"kind": "link", "target": "../absent"}}
        for requested, inventory, alias, current, missing in (
                ("a/module.py", rows, ("dir/link", "../absent"), "absent/module.py", "absent"),
                ("missing.py", {}, None, "missing.py", "missing.py")):
            with self.assertRaises(PREP.PreparationRefused) as caught:
                PREP.resolve_member(requested, inventory)
            original = caught.exception
            self.assertEqual(original.args, ("member-missing",))
            context = (requested, current, missing, alias)
            self.assertEqual(original._missing_member_context, context)
            facts = PREP.public_member_failure(original, "framework-inventory")
            self.assertEqual((facts["phase"], facts["code"]),
                             ("framework-inventory", "member-missing"))
            self.assertEqual([PREP.json.loads(facts[key]) for key in
                              ("requested", "current", "missingPrefix")], list(context[:3]))
            self.assertEqual(facts["lastAlias"], None if alias is None else
                             {"name": PREP.json.dumps(alias[0]), "target": PREP.json.dumps(alias[1])})
            self.assertEqual(original._missing_member_context, context)
            self.assertIsNone(PREP.public_member_failure(original, "unrelated-task"))
        self.assertIsNone(PREP.public_member_failure(PREP.PreparationRefused("member-missing"), phase))
        self.assertIsNone(PREP.public_member_failure(ValueError("member-missing"), phase))
        for malformed in (None, [], ("a", "b", "c"), ("a", "b", "c", []),
                          ("a", "b", "c", ("alias",)), (NoStringification(), "b", "c", None),
                          ("/private/MRK-PATH-CANARY", "b", "c", None),
                          ("a", "b", "c", ("alias", "a\\b")),
                          ("a" * 4097, "b", "c", None),
                          ("\u00e9" * 1024, "b", "c", None)):
            invalid = PREP.PreparationRefused("member-missing")
            invalid._missing_member_context = malformed
            self.assertIsNone(PREP.public_member_failure(invalid, phase))

        # Finite universal-header facts are public INPUT diagnostics, not a
        # loader grant. The real native failure's exact shape is still unknown.
        original = PREP.PreparationRefused("fat-slice-header")
        header = (0xCAFEBABE, 2, 0, ARM, 0, 64, 32, 6, 0x72613C21, 0x0A3E6863, 0)
        member = ("Versions/3.14/lib/public-input.a", 128, "a" * 64)
        original._fat_slice_header, original._image_member_context = header, member
        facts = PREP.public_member_failure(original, "image-slicing")
        self.assertEqual((facts["code"], facts["sliceIndex"], facts["thinMagicLE"]),
                         ("fat-slice-header", 0, 0x72613C21))
        self.assertEqual(PREP.json.loads(facts["member"]), member[0])
        self.assertEqual((facts["fileSize"], facts["fileSha256"]), member[1:])
        self.assertIs(facts["diagnosticOnly"], True)
        self.assertEqual(original.args, ("fat-slice-header",))
        for phase_value in (None, "framework-inventory", "image-relocation", "unrelated-task"):
            self.assertIsNone(PREP.public_member_failure(original, phase_value))
        for bad_header in (None, list(header), header[:-1], (True,) + header[1:],
                           header[:5] + (-1,) + header[6:], header[:5] + (1 << 64,) + header[6:],
                           header[:2] + (2,) + header[3:], header[:8] + (1 << 32,) + header[9:]):
            original._fat_slice_header = bad_header
            self.assertIsNone(PREP.public_member_failure(original, "image-slicing"))
        original._fat_slice_header = header
        for bad_member in (None, list(member), member[:2], ("/private/MRK-PATH-CANARY", *member[1:]),
                           ("a/../MRK-PATH-CANARY", *member[1:]), ("a\\b", *member[1:]),
                           ("a" * 4097, *member[1:]), (NoStringification(), *member[1:]),
                           (member[0], True, member[2]), (member[0], 64, member[2]),
                           (member[0], PREP.FILE_LIMIT + 1, member[2]), (member[0], 128, "bad")):
            original._image_member_context = bad_member
            self.assertIsNone(PREP.public_member_failure(original, "image-slicing"))
        self.assertIsNone(PREP.public_member_failure(PREP.PreparationRefused("fat-slice-header"), "image-slicing"))

        missing = PREP.PreparationRefused("fat-native-missing")
        missing._image_member_context = member
        context = (0xCAFEBABE, 1, (INTEL,), "arm64", True, (True,))
        missing._fat_native_missing = context
        observed = PREP.public_member_failure(missing, "image-slicing")
        self.assertEqual(observed["tableCpus"], [INTEL])
        self.assertEqual(observed["requestedMachine"], "arm64")
        self.assertIs(observed["allSlicesAreArchives"], True)
        self.assertIs(observed["diagnosticOnly"], True)
        self.assertEqual(missing.args, ("fat-native-missing",))
        for malformed in (None, list(context), context[:-1],
                          (True, *context[1:]), (context[0], True, *context[2:]),
                          (context[0], 2, *context[2:]),
                          (context[0], 1, (True,), *context[3:]),
                          (context[0], 1, (7,), *context[3:]),
                          (context[0], 2, (INTEL, INTEL), *context[3:]),
                          (*context[:3], "x86_64", *context[4:]),
                          (*context[:3], "MRK-PRIVATE-CANARY", *context[4:]),
                          (*context[:4], False, (True,)), (*context[:4], 1, (True,)),
                          (*context[:5], (1,)), (*context[:5], (False, True))):
            missing._fat_native_missing = malformed
            self.assertIsNone(PREP.public_member_failure(missing, "image-slicing"))
        missing._fat_native_missing = context
        self.assertIsNone(PREP.public_member_failure(missing, "image-relocation"))
        for code in ("fat-native-missing", "macho-input", "fat-count", "fat-reserved",
                     "fat-slice-range", "fat-slice-kind", "macho-native-header"):
            closed = PREP.PreparationRefused(code)
            closed._image_member_context = member
            closed._fat_native_missing = context
            facts = PREP.public_member_failure(closed, "image-slicing")
            self.assertEqual(facts["code"], code)
            self.assertEqual(PREP.json.loads(facts["member"]), member[0])
            self.assertIs(facts["diagnosticOnly"], True)
            for unsafe in (("/private/MRK-PRIVATE-CANARY", *member[1:]),
                           ("a/../MRK-PRIVATE-CANARY", *member[1:]),
                           (member[0], True, member[2]), (member[0], member[1], "bad")):
                closed._image_member_context = unsafe
                self.assertIsNone(PREP.public_member_failure(closed, "image-slicing"))
        closed = PREP.PreparationRefused("not-a-reviewed-code")
        closed._image_member_context = member
        self.assertIsNone(PREP.public_member_failure(closed, "image-slicing"))

        # An unavailable diagnostic attribute must not replace the original.
        class AttributeUnavailable(PREP.PreparationRefused):
            def __setattr__(self, name, value):
                if name in {"_relative_name_input", "_missing_member_context"}:
                    raise MemoryError("inert diagnostic allocation failure")
                return super().__setattr__(name, value)
        original = AttributeUnavailable("relative-name")
        original_need = PREP.need
        with mock.patch.object(PREP, "need", side_effect=original):
            try:
                PREP.relative_name("pkg/../rejected")
            except PREP.PreparationRefused as returned:
                self.assertIs(returned, original)
                self.assertEqual(returned.args, ("relative-name",))
                self.assertNotIn("_relative_name_input", returned.__dict__)
            else:
                self.fail("original path refusal was lost")
        self.assertIs(PREP.need, original_need)
        missing_original = AttributeUnavailable("member-missing")
        def missing_need(condition, code):
            if not condition and code == "member-missing":
                raise missing_original
            return original_need(condition, code)
        with mock.patch.object(PREP, "need", side_effect=missing_need):
            with self.assertRaises(PREP.PreparationRefused) as caught:
                PREP.resolve_member("a/module.py", rows)
            self.assertIs(caught.exception, missing_original)
            self.assertEqual(caught.exception.args, ("member-missing",))
            self.assertNotIn("_missing_member_context", caught.exception.__dict__)
        self.assertIs(PREP.need, original_need)

        # The same successful original result feeds diagnostic observation and
        # the raw validator. Only original-known publication can export it.
        source = Path(PREP.__file__).read_text()
        preparation = source[source.index("def prepare(ctx):"):source.index("\ndef main():")]
        original_call = 'signature = engine.run("package", ["--check-signature", str(package)], environment=env)'
        observation = ('package_signature = {"commandIndex": len(engine.records) - 1,\n'
                       '                                 **package_signature_observation(signature["stdout"])}')
        original_guard = 'package_signature_valid(signature["stdout"])'
        self.assertIn("package_signature = None", preparation)
        self.assertEqual(preparation.count(original_guard), 1)
        self.assertNotIn('need("signed by a certificate trusted by"', preparation)
        self.assertLess(preparation.index(original_call), preparation.index(observation))
        self.assertLess(preparation.index(observation), preparation.index(original_guard))
        self.assertLess(preparation.index(original_guard), preparation.index('["--expand-full"'))
        known_publication = preparation[preparation.index('if known:\n        public = root / "public"'):]
        self.assertIn('"packageSignature": package_signature', known_publication)
        preparation_ast = ast.parse(preparation)
        loads = [node for node in ast.walk(preparation_ast)
                 if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == "package_signature"]
        self.assertEqual(len(loads), 1)  # report only, never a permission/READY predicate
        # The same predicate and same exception are retained. No scanner,
        # permission, original-finality or cleanup decision consumes this DATA.
        relative = next(node for node in ast.parse(source).body
                        if isinstance(node, ast.FunctionDef) and node.name == "relative_name")
        expected_predicate = ast.parse(
            'need(type(name) is str and 0 < len(name) <= 4096 and not name.startswith("/")\n'
            '     and "\\\\" not in name and all(32 <= ord(c) < 127 for c in name)\n'
            '     and all(part not in {"", ".", ".."} for part in name.split("/")), "relative-name")'
        ).body[0]
        self.assertEqual(ast.dump(relative.body[0].body[0]), ast.dump(expected_predicate))
        self.assertIsInstance(relative.body[0].handlers[0].body[-1], ast.Raise)
        self.assertIsNone(relative.body[0].handlers[0].body[-1].exc)
        prepared = preparation_ast.body[0]
        primary = next(node for node in prepared.body if isinstance(node, ast.Try))
        handler = primary.handlers[0]
        self.assertEqual(ast.dump(handler.body[0]), ast.dump(ast.parse("failure = error").body[0]))
        diagnostic_try = handler.body[1]
        self.assertIsInstance(diagnostic_try, ast.Try)
        self.assertIsInstance(diagnostic_try.handlers[0].body[0], ast.Pass)
        captures = [node for node in ast.walk(prepared) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == "public_member_failure"]
        self.assertEqual(len(captures), 1)
        self.assertEqual(ast.dump(captures[0]), ast.dump(ast.parse(
            "public_member_failure(error, member_phase)").body[0].value))
        phases = [node for node in ast.walk(prepared) if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == "member_phase" for target in node.targets)]
        armed = [node for node in phases if isinstance(node.value, ast.Constant) and node.value.value is not None]
        expected_phases = {"expanded-inventory", "framework-selection", "framework-inventory", "framework-copy",
                           "image-slicing", "image-relocation", "image-signing", "signed-inventory",
                           "sealed-inventory", "runtime-inventory", "expanded-retirement"}
        self.assertEqual({node.value.value for node in armed}, expected_phases)
        expand = next(node for node in ast.walk(prepared) if isinstance(node, ast.Call)
                      and any(isinstance(value, ast.Constant) and value.value == "--expand-full"
                              for value in ast.walk(node)))
        # Choose the actual engine.run call, not any future enclosing call.
        self.assertIsInstance(expand.func, ast.Attribute)
        self.assertEqual(expand.func.attr, "run")
        self.assertTrue(all(node.lineno > expand.end_lineno for node in armed))
        self.assertIn('member_phase = None\n            recheck_apple(originals)', preparation)
        self.assertIn('"publicMemberFailure": public_member', known_publication)
        loads = [node for node in ast.walk(preparation_ast) if isinstance(node, ast.Name)
                 and isinstance(node.ctx, ast.Load) and node.id == "public_member"]
        self.assertEqual(len(loads), 1)  # report only; never path/READY/cleanup authority


    def test_native_slices_and_load_command_bounds_refuse_ambiguous_data(self):
        load = cstring_command(0xC, "/usr/lib/libSystem.B.dylib")
        arm, intel = thin_fixture(ARM, commands=(load,)), thin_fixture(INTEL, commands=(load,))
        fat = fat_fixture(arm, intel)
        self.assertEqual(PREP.native_slice(fat, "arm64"), arm)
        self.assertEqual(PREP.native_slice(fat, "x86_64"), intel)
        wide_header = struct.pack(">2I", 0xCAFEBABF, 1) + struct.pack(">IIQQII", ARM, 0, 64, len(arm), 6, 0)
        wide = wide_header + bytes(64 - len(wide_header)) + arm
        self.assertEqual(PREP.native_slice(wide, "arm64"), arm)
        damaged = []
        for offset, value in ((4, 0), (4, 9), (28, ARM), (36, 64),
                              (20, len(fat) + 1), (16, 65), (8, 7), (68, INTEL)):
            value_bytes = bytearray(fat)
            struct.pack_into(">I" if offset != 68 else "<I", value_bytes, offset, value)
            damaged.append(bytes(value_bytes))
        reserved = bytearray(wide); struct.pack_into(">I", reserved, 36, 1)
        damaged.extend((bytes(reserved), intel, arm[:31]))
        for number, body in enumerate(damaged):
            with self.subTest(native_slice_boundary=number), self.assertRaises(PREP.PreparationRefused):
                PREP.native_slice(body, "arm64")
        # Preserve the actual rejected header without assuming that every
        # universal member contains a dynamic Mach-O image.
        for prefix in (b"!<arch>\n" + bytes(4), struct.pack("<III", 0xFEEDFACF, ARM, 1)):
            malformed = bytearray(fat); malformed[64:76] = prefix
            with self.assertRaisesRegex(PREP.PreparationRefused, "^fat-slice-header$") as caught:
                PREP.native_slice(bytes(malformed), "arm64")
            self.assertEqual(caught.exception._fat_slice_header,
                             (0xCAFEBABE, 2, 0, ARM, 0, 64, len(arm), 6, *struct.unpack("<III", prefix)))
        class UnavailableHeader(PREP.PreparationRefused):
            def __setattr__(self, name, value):
                if name == "_fat_slice_header":
                    raise MemoryError("inert diagnostic allocation failure")
                return super().__setattr__(name, value)
        original_error = UnavailableHeader("fat-slice-header")
        original_need = PREP.need
        def refuse_header(condition, code):
            if code == "fat-slice-header":
                raise original_error
            return original_need(condition, code)
        try:
            PREP.need = refuse_header
            with self.assertRaises(UnavailableHeader) as caught:
                PREP.native_slice(fat, "arm64")
            self.assertIs(caught.exception, original_error)
        finally:
            PREP.need = original_need
        # FAT32/FAT64 are wrappers, not proof of executable Mach-O content.
        # Real ar-shaped DATA remains byte-identical and never reaches a loader.
        ar_header = b"member.o/       " + b"0           " + b"0     " + b"0     " + b"100644  " + b"4         " + b"`\n"
        self.assertEqual(len(ar_header), 60)
        archive = b"!<arch>\n" + ar_header + b"DATA"
        archives = fat_fixture(archive, archive)
        wide_archives_header = (struct.pack(">2I", 0xCAFEBABF, 2)
                                + struct.pack(">IIQQII", ARM, 0, 128, len(archive), 6, 0)
                                + struct.pack(">IIQQII", INTEL, 3, 256, len(archive), 6, 0))
        wide_archives = (wide_archives_header + bytes(128 - len(wide_archives_header)) + archive
                         + bytes(128 - len(archive)) + archive)
        for universal in (archives, wide_archives):
            before = PREP.hashlib.sha256(universal).digest()
            for machine in ("arm64", "x86_64"):
                self.assertIsNone(PREP.native_slice(universal, machine, archive_data=True))
                with self.assertRaisesRegex(PREP.PreparationRefused, "^fat-slice-header$"):
                    PREP.native_slice(universal, machine)
                with self.assertRaises(PREP.PreparationRefused):
                    PREP.macho_records(universal, machine)
            self.assertEqual(PREP.hashlib.sha256(universal).digest(), before)
        for mixed in (fat_fixture(archive, intel), fat_fixture(arm, archive)):
            with self.assertRaisesRegex(PREP.PreparationRefused, "^fat-slice-kind$"):
                PREP.native_slice(mixed, "arm64", archive_data=True)
        damaged_archives = []
        for offset, value in ((4, 0), (4, 9), (28, ARM), (36, 64),
                              (20, len(archives) + 1), (16, 65), (8, 7)):
            data = bytearray(archives); struct.pack_into(">I", data, offset, value)
            damaged_archives.append(bytes(data))
        reserved_archive = bytearray(wide_archives); struct.pack_into(">I", reserved_archive, 36, 1)
        damaged_archives.append(bytes(reserved_archive))
        incomplete_magic = bytearray(archives); incomplete_magic[71] = ord("X")
        damaged_archives.append(bytes(incomplete_magic))
        for number, data in enumerate(damaged_archives):
            with self.subTest(archive_boundary=number), self.assertRaises(PREP.PreparationRefused):
                PREP.native_slice(data, "arm64", archive_data=True)
        single_header = struct.pack(">2I", 0xCAFEBABF, 1) + struct.pack(">IIQQII", ARM, 0, 64, len(archive), 6, 0)
        single_archive = single_header + bytes(64 - len(single_header)) + archive
        with self.assertRaisesRegex(PREP.PreparationRefused, "^fat-native-missing$") as absent:
            PREP.native_slice(single_archive, "x86_64", archive_data=True)
        self.assertEqual(absent.exception._fat_native_missing,
                         (0xCAFEBABF, 1, (ARM,), "x86_64", True, (True,)))
        with self.assertRaisesRegex(PREP.PreparationRefused, "^fat-native-missing$") as absent:
            PREP.native_slice(wide, "x86_64")
        self.assertEqual(absent.exception._fat_native_missing,
                         (0xCAFEBABF, 1, (ARM,), "x86_64", False, (False,)))
        class UnavailableMissing(PREP.PreparationRefused):
            def __setattr__(self, name, value):
                if name == "_fat_native_missing":
                    raise MemoryError("inert missing-target diagnostic allocation failure")
                return super().__setattr__(name, value)
        original_missing = UnavailableMissing("fat-native-missing")
        def refuse_missing(condition, code):
            if code == "fat-native-missing" and not condition:
                raise original_missing
            return original_need(condition, code)
        with mock.patch.object(PREP, "need", side_effect=refuse_missing):
            with self.assertRaises(UnavailableMissing) as absent:
                PREP.native_slice(wide, "x86_64")
            self.assertIs(absent.exception, original_missing)
        self.assertIs(PREP.need, original_need)
        with self.assertRaises(PREP.PreparationRefused):
            PREP.native_slice(archives, "arm64", archive_data="yes")

        # Suffix only enables classification; it never excludes an actual image.
        # The existing inventory hashes/nonimage POST preserve the whole archive.
        original_read = BUILD.read
        for data, filename, expected in ((archives, "libtclstub.a", None),
                                          (wide_archives, "libtkstub.a", None),
                                          (fat, "still-an-image.a", arm),
                                          (arm, "thin-image.a", arm)):
            path = Path(filename)
            with mock.patch.object(BUILD, "read", return_value=data) as read:
                self.assertEqual(PREP.native_image_bytes(path, "arm64"), expected)
                read.assert_called_once_with(path, PREP.FILE_LIMIT)
            self.assertIs(BUILD.read, original_read)
        with mock.patch.object(BUILD, "read", return_value=archives):
            with self.assertRaisesRegex(PREP.PreparationRefused, "^fat-slice-header$"):
                PREP.native_image_bytes(Path("not-an-archive.dylib"), "arm64")
        self.assertIs(BUILD.read, original_read)

        # The observed public python.o is LLVM link DATA, not a runtime image.
        # These fixtures validate only its wrapper envelope, not executable IR.
        def bitcode_fixture(cpu):
            payload = b"BC\xc0\xdeDATA"
            wrapped = struct.pack("<5I", 0x0B17C0DE, 0, 20, len(payload), cpu) + payload
            return wrapped + bytes((-len(wrapped)) % 16)

        wrapped_arm, wrapped_intel = bitcode_fixture(ARM), bitcode_fixture(INTEL)
        wrapped_unspecified = bitcode_fixture(0xFFFFFFFF)
        bitcodes = fat_fixture(wrapped_arm, wrapped_intel)
        wide_bitcode_header = (struct.pack(">2I", 0xCAFEBABF, 2)
                               + struct.pack(">IIQQII", ARM, 0, 128, len(wrapped_arm), 6, 0)
                               + struct.pack(">IIQQII", INTEL, 3, 256, len(wrapped_intel), 6, 0))
        wide_bitcodes = (wide_bitcode_header + bytes(128 - len(wide_bitcode_header)) + wrapped_arm
                        + bytes(128 - len(wrapped_arm)) + wrapped_intel)
        for universal in (bitcodes, wide_bitcodes, fat_fixture(wrapped_unspecified, wrapped_intel)):
            original_hash = PREP.hashlib.sha256(universal).digest()
            for machine in ("arm64", "x86_64"):
                self.assertIsNone(PREP.native_slice(universal, machine, bitcode_data=True))
                with self.assertRaisesRegex(PREP.PreparationRefused, "^fat-slice-header$"):
                    PREP.native_slice(universal, machine)
                with self.assertRaises(PREP.PreparationRefused):
                    PREP.macho_records(universal, machine)
            self.assertEqual(PREP.hashlib.sha256(universal).digest(), original_hash)
        for wrapped, machine in ((wrapped_arm, "arm64"), (wrapped_intel, "x86_64"),
                                  (wrapped_unspecified, "arm64")):
            self.assertIsNone(PREP.native_slice(wrapped, machine, bitcode_data=True))
            with self.assertRaisesRegex(PREP.PreparationRefused, "^macho-native-header$"):
                PREP.native_slice(wrapped, machine)
            with self.assertRaises(PREP.PreparationRefused):
                PREP.macho_records(wrapped, machine)
        for machine, wrapped in (("x86_64", wrapped_unspecified), ("x86_64", wrapped_arm),
                                  ("arm64", wrapped_intel)):
            with self.assertRaisesRegex(PREP.PreparationRefused, "^bitcode-wrapper-cpu$"):
                PREP.native_slice(wrapped, machine, bitcode_data=True)
        for option in (None, 1, "true", []):
            with self.assertRaisesRegex(PREP.PreparationRefused, "^macho-input$"):
                PREP.native_slice(bitcodes, "arm64", bitcode_data=option)
        with self.assertRaisesRegex(PREP.PreparationRefused, "^macho-input$"):
            PREP.native_slice(bitcodes, "arm64", bitcode_data=True, archive_data=True)
        malformed_wrappers = []
        for offset, value, code in ((0, 0, "header"), (4, 1, "header"), (8, 16, "header"),
                                    (12, 0, "range"), (12, 7, "range"), (12, 16, "range"),
                                    (16, 0, "cpu")):
            changed = bytearray(wrapped_arm)
            struct.pack_into("<I", changed, offset, value)
            malformed_wrappers.append((bytes(changed), code))
        changed = bytearray(wrapped_arm); changed[20] = ord("X")
        malformed_wrappers.append((bytes(changed), "magic"))
        changed = bytearray(wrapped_arm); changed[-1] = 1
        malformed_wrappers.extend(((bytes(changed), "padding"), (wrapped_arm + bytes(16), "range")))
        for number, (body, code) in enumerate(malformed_wrappers):
            with self.subTest(bitcode_wrapper_boundary=number), \
                 self.assertRaisesRegex(PREP.PreparationRefused, "^bitcode-wrapper-" + code + "$"):
                PREP._bitcode_wrapper_data(body, ARM)
        for body, cpu in ((wrapped_arm[:19], ARM), (bytearray(wrapped_arm), ARM),
                          (wrapped_arm, True), (wrapped_arm, 7)):
            with self.assertRaisesRegex(PREP.PreparationRefused, "^bitcode-wrapper-input$"):
                PREP._bitcode_wrapper_data(body, cpu)
        # Even a valid selected slice cannot hide another malformed slice.
        wrong_other = bytearray(wrapped_intel); struct.pack_into("<I", wrong_other, 4, 1)
        with self.assertRaisesRegex(PREP.PreparationRefused, "^bitcode-wrapper-header$"):
            PREP.native_slice(fat_fixture(wrapped_arm, bytes(wrong_other)), "arm64", bitcode_data=True)
        for mixed in (fat_fixture(wrapped_arm, intel), fat_fixture(arm, wrapped_intel)):
            with self.assertRaisesRegex(PREP.PreparationRefused, "^fat-slice-kind$"):
                PREP.native_slice(mixed, "arm64", bitcode_data=True)
        single_bc_header = (struct.pack(">2I", 0xCAFEBABF, 1)
                            + struct.pack(">IIQQII", ARM, 0, 64, len(wrapped_arm), 6, 0))
        single_bitcode = single_bc_header + bytes(64 - len(single_bc_header)) + wrapped_arm
        with self.assertRaisesRegex(PREP.PreparationRefused, "^fat-native-missing$") as absent:
            PREP.native_slice(single_bitcode, "x86_64", bitcode_data=True)
        self.assertEqual(absent.exception._fat_native_missing,
                         (0xCAFEBABF, 1, (ARM,), "x86_64", False, (False,)))
        for data, filename, expected in ((bitcodes, "python.o", None), (wide_bitcodes, "python.o", None),
                                          (wrapped_arm, "python.o", None), (fat, "still-an-image.o", arm),
                                          (arm, "thin-image.o", arm)):
            with mock.patch.object(BUILD, "read", return_value=data) as read:
                self.assertEqual(PREP.native_image_bytes(Path(filename), "arm64"), expected)
                read.assert_called_once_with(Path(filename), PREP.FILE_LIMIT)
            self.assertIs(BUILD.read, original_read)
        for filename in ("python.dylib", "python.a"):
            with mock.patch.object(BUILD, "read", return_value=bitcodes), \
                 self.assertRaisesRegex(PREP.PreparationRefused, "^fat-slice-header$"):
                PREP.native_image_bytes(Path(filename), "arm64")
        self.assertIs(BUILD.read, original_read)

        # One documented Intel-only launcher is retained on ARM, never granted
        # loader/execution authority. Synthetic pin substitutions are local to
        # these parser tests; actual public-package correspondence needs Mac CI.
        executable = bytearray(intel)
        struct.pack_into("<I", executable, 12, 2)
        executable = bytes(executable)
        header = struct.pack(">2I", 0xCAFEBABE, 1) + struct.pack(">5I", INTEL, 3, 64, len(executable), 6)
        auxiliary = header + bytes(64 - len(header)) + executable
        original_pins = (PREP.INTEL_AUX_SIZE, PREP.INTEL_AUX_SHA256)
        auxiliary_path = Path("/private/framework") / PREP.INTEL_AUX_RELATIVE
        with mock.patch.object(BUILD, "read", return_value=auxiliary):
            with self.assertRaisesRegex(PREP.PreparationRefused, "^intel-auxiliary-bytes$"):
                PREP.native_image_bytes(auxiliary_path, "arm64", relative=PREP.INTEL_AUX_RELATIVE)
            with mock.patch.object(PREP, "INTEL_AUX_SIZE", len(auxiliary)), \
                 mock.patch.object(PREP, "INTEL_AUX_SHA256", PREP.hashlib.sha256(auxiliary).hexdigest()):
                self.assertIsNone(PREP.native_image_bytes(auxiliary_path, "arm64", relative=PREP.INTEL_AUX_RELATIVE))
                self.assertEqual(PREP.native_image_bytes(auxiliary_path, "x86_64", relative=PREP.INTEL_AUX_RELATIVE), executable)
                for other_name in (None, "Versions/3.14/bin/other-intel64", PREP.ENTRY_RELATIVE):
                    with self.assertRaisesRegex(PREP.PreparationRefused, "^fat-native-missing$"):
                        PREP.native_image_bytes(auxiliary_path, "arm64", relative=other_name)
                for damaged in (auxiliary[:-1], auxiliary[:-1] + bytes([auxiliary[-1] ^ 1])):
                    with mock.patch.object(BUILD, "read", return_value=damaged), \
                         self.assertRaisesRegex(PREP.PreparationRefused, "^intel-auxiliary-bytes$"):
                        PREP.native_image_bytes(auxiliary_path, "arm64", relative=PREP.INTEL_AUX_RELATIVE)
        # Repin malformed synthetic inputs only to reach structural boundaries.
        malformed = []
        for offset, fmt, value in ((0, ">I", 0xCAFEBABF), (4, ">I", 2), (8, ">I", ARM),
                                   (64, "<I", 0), (76, "<I", 6), (80, "<I", 0)):
            damaged = bytearray(auxiliary); struct.pack_into(fmt, damaged, offset, value)
            malformed.append(bytes(damaged))
        for number, damaged in enumerate(malformed):
            with self.subTest(intel_auxiliary_boundary=number), \
                 mock.patch.object(BUILD, "read", return_value=damaged), \
                 mock.patch.object(PREP, "INTEL_AUX_SIZE", len(damaged)), \
                 mock.patch.object(PREP, "INTEL_AUX_SHA256", PREP.hashlib.sha256(damaged).hexdigest()), \
                 self.assertRaises(PREP.PreparationRefused):
                PREP.native_image_bytes(auxiliary_path, "arm64", relative=PREP.INTEL_AUX_RELATIVE)
        self.assertEqual((PREP.INTEL_AUX_SIZE, PREP.INTEL_AUX_SHA256), original_pins)
        self.assertIs(BUILD.read, original_read)

        with self.assertRaises(PREP.PreparationRefused):
            PREP.macho_records(fat, "arm64")
        records = PREP.macho_records(arm, "arm64")
        self.assertEqual([(r["command"], r["text"]) for r in records], [(0xC, "/usr/lib/libSystem.B.dylib")])
        bad_commands = [thin_fixture(commands=(struct.pack("<II", 0x27, 8),))]
        for offset, value in ((16, 0), (20, len(arm)), (36, 10), (40, len(load))):
            value_bytes = bytearray(arm); struct.pack_into("<I", value_bytes, offset, value)
            bad_commands.append(bytes(value_bytes))
        no_terminator = bytearray(arm)
        no_terminator[32 + 24:32 + len(load)] = b"X" * (len(load) - 24)
        bad_commands.append(bytes(no_terminator))
        for number, body in enumerate(bad_commands):
            with self.subTest(load_command_boundary=number), self.assertRaises(PREP.PreparationRefused):
                PREP.macho_records(body, "arm64")

        # Relocation/signing may change nominated loader/signature fields, not
        # executable/data bytes or unrelated Mach-O commands. These are bytes,
        # not signatures or native runtime evidence.
        uuid = struct.pack("<II", 0x1B, 24) + bytes(range(16))
        image = thin_fixture(commands=(load, uuid))
        self.assertTrue(PREP.macho_content_valid(image, image, "arm64"))
        for offset in (24, 32 + len(load) + 8, len(image) - 1):
            modified = bytearray(image); modified[offset] ^= 1
            with self.subTest(immutable_image_byte=offset), self.assertRaises(PREP.PreparationRefused):
                PREP.macho_content_valid(image, bytes(modified), "arm64")
        renamed = thin_fixture(commands=(cstring_command(0xC, "/usr/lib/libSystem.C.dylib"), uuid))
        self.assertTrue(PREP.macho_content_valid(image, renamed, "arm64"))
        with self.assertRaises(PREP.PreparationRefused):
            PREP.macho_content_valid(image, renamed, "arm64", signing=True)

    def test_private_relocation_is_capacity_bound_and_closed_over_inventory(self):
        caller = "Versions/3.14/lib/python3.14/lib-dynload/_ssl.so"
        dependency = "Versions/3.14/lib/libssl.3.dylib"
        other = "Versions/3.14/alternative/libssl.3.dylib"
        rows = inventory_rows(caller, dependency, other, links={"Versions/Current": "3.14"})
        images = {caller, dependency, other}
        self.assertEqual(PREP.resolve_member("Versions/Current/lib/libssl.3.dylib", rows), dependency)
        rpath = "@loader_path/../.."
        old = "@rpath/libssl.3.dylib"
        new = "@loader_path/../../libssl.3.dylib"
        commands = (cstring_command(0x8000001C, rpath),
                    cstring_command(0xC, old, extra_capacity=64),
                    cstring_command(0xC, "/usr/lib/libSystem.B.dylib"))
        planned = PREP.relocation_plan(thin_fixture(commands=commands), "arm64", caller, rows, images)
        self.assertEqual(planned["arguments"], ["-delete_rpath", rpath, "-change", old, new])
        self.assertEqual(planned["expected"], [(0xC, new), (0xC, "/usr/lib/libSystem.B.dylib")])
        self.assertEqual(planned["removedRpaths"], [rpath])
        self.assertEqual(planned["changes"], [{"command": 0xC, "before": old, "after": new}])
        absolute = PREP.FRAMEWORK_ORIGINAL + "/" + dependency
        direct = PREP.relocation_plan(thin_fixture(commands=(cstring_command(0xC, absolute),)),
                                     "arm64", caller, rows, images)
        self.assertEqual(direct["expected"], [(0xC, new)])
        own_id = PREP.FRAMEWORK_ORIGINAL + "/" + caller
        identity = PREP.relocation_plan(thin_fixture(commands=(cstring_command(0xD, own_id),
                                        cstring_command(0xE, "/usr/lib/dyld"))),
                                        "arm64", caller, rows, images)
        self.assertEqual(identity["arguments"], ["-id", "@loader_path/_ssl.so"])
        self.assertEqual(identity["expected"], [(0xD, "@loader_path/_ssl.so"), (0xE, "/usr/lib/dyld")])
        ambiguous = commands + (cstring_command(0x8000001C,
                               PREP.FRAMEWORK_ORIGINAL + "/Versions/3.14/alternative"),)
        for name, chosen_commands, selected_images in (
                ("ambiguous", ambiguous, images),
                ("capacity", (commands[0], cstring_command(0xC, old)), images),
                ("duplicate-rpath", commands + (commands[0],), images),
                ("external-load", (cstring_command(0xC, "/opt/homebrew/lib/libssl.3.dylib"),), images),
                ("external-dyld", (cstring_command(0xE, "/shared/dyld"),), images),
                ("Apple-traversal", (cstring_command(0xC, "/usr/lib/../local/foreign.dylib"),), images),
                ("external-rpath", commands + (cstring_command(0x8000001C, "/opt/homebrew/lib"),), images),
                ("not-in-image-closure", commands, {caller})):
            with self.subTest(relocation_boundary=name), self.assertRaises(PREP.PreparationRefused):
                PREP.relocation_plan(thin_fixture(commands=chosen_commands), "arm64", caller, rows, selected_images)
        for target in ("../../outside", "/outside", "Current"):
            bad_rows = copy.deepcopy(rows); bad_rows["Versions/Current"]["target"] = target
            with self.subTest(alias_target=target), self.assertRaises(PREP.PreparationRefused):
                PREP.resolve_member("Versions/Current/lib/libssl.3.dylib", bad_rows)
        # Tcl/Tk create this development-only alias even in embedded builds
        # that omit private headers. Inventory preservation is not resolution.
        for component in ("Tcl", "Tk"):
            framework = "Versions/3.14/Frameworks/" + component + ".framework"
            version = framework + "/Versions/9.0"
            alias = framework + "/PrivateHeaders"
            current = framework + "/Versions/Current"
            missing = version + "/PrivateHeaders"
            metadata = inventory_rows(version + "/" + component, links={
                alias: "Versions/Current/PrivateHeaders", current: "9.0"})
            metadata["."] = {"kind": "directory"}
            self.assertIs(PREP.optional_private_header_alias(alias, metadata), True)
            with self.assertRaisesRegex(PREP.PreparationRefused, "^member-missing$"):
                PREP.resolve_member(alias, metadata)
            combined = {**rows, **metadata}
            metadata_load = PREP.FRAMEWORK_ORIGINAL + "/" + alias
            for command in (0xC, 0x8000001C):
                with self.subTest(metadata_runtime_reference=(component, command)), self.assertRaisesRegex(
                        PREP.PreparationRefused, "^member-missing$"):
                    PREP.relocation_plan(thin_fixture(commands=(cstring_command(command, metadata_load),)),
                                         "arm64", caller, combined, images)
            # The exception is not inherited by another alias into the same
            # missing leaf, and a real header directory uses ordinary resolution.
            other_alias = framework + "/OtherHeaders"
            indirect = copy.deepcopy(metadata)
            indirect[other_alias] = {"kind": "link", "target": "PrivateHeaders"}
            self.assertIs(PREP.optional_private_header_alias(other_alias, indirect), False)
            with self.assertRaisesRegex(PREP.PreparationRefused, "^member-missing$"):
                PREP.resolve_member(other_alias, indirect)
            present = copy.deepcopy(metadata); present[missing] = {"kind": "directory"}
            self.assertIs(PREP.optional_private_header_alias(alias, present), False)
            self.assertEqual(PREP.resolve_member(alias, present), missing)
            for selected, field, value in ((alias, "target", "/outside"),
                                            (alias, "target", "Versions/Current/Headers"),
                                            (alias, "target", "Versions/Current/PrivateHeaders/child"),
                                            (alias, "kind", "file"),
                                            (current, "target", "9.1"),
                                            (current, "target", "../outside"),
                                            (current, "kind", "directory")):
                bad = copy.deepcopy(metadata); bad[selected][field] = value
                with self.subTest(optional_metadata_shape=(component, selected, field, value)):
                    self.assertIs(PREP.optional_private_header_alias(alias, bad), False)
            parents = [name for name, row in metadata.items() if row["kind"] == "directory"]
            for parent in parents:
                absent = copy.deepcopy(metadata); del absent[parent]
                rebound = copy.deepcopy(metadata)
                rebound[parent] = {"kind": "link", "target": "9.0"}
                with self.subTest(optional_metadata_parent=(component, parent)):
                    self.assertIs(PREP.optional_private_header_alias(alias, absent), False)
                    self.assertIs(PREP.optional_private_header_alias(alias, rebound), False)
            foreign = {name.replace(component + ".framework", "Other.framework"): row
                       for name, row in metadata.items()}
            self.assertIs(PREP.optional_private_header_alias(
                alias.replace(component + ".framework", "Other.framework"), foreign), False)
            for bad_name, bad_rows in ((None, metadata), (1, metadata), (alias, None), (alias, [])):
                self.assertIs(PREP.optional_private_header_alias(bad_name, bad_rows), False)


    def test_runtime_facts_and_prestart_configuration_stay_private(self):
        root = Path("/task-owned/preparation")
        prefix = str(root / "Python.framework" / PREP.VERSION_RELATIVE)
        entry = str(root / "Python.framework" / PREP.ENTRY_RELATIVE)
        facts = {
            "version": [3, 14, 7], "machine": "arm64", "executable": entry,
            "flags": {"isolated": 1, "noSite": 1, "noBytecode": True}, "prefixes": [prefix] * 4,
            "openssl": {"OPENSSL_CONF": "/dev/null", "OPENSSL_MODULES": str(root / "empty-providers")},
            "sysPath": [prefix + "/lib/python314.zip", prefix + "/lib/python3.14"],
            "modulePaths": [prefix + "/lib/python3.14/hashlib.py"],
            "images": [entry, prefix + "/Python", "/usr/lib/libSystem.B.dylib"],
        }
        self.assertTrue(PREP.runtime_facts_valid(facts, root, "arm64"))
        for field, value in (
                ("version", [3, 14, 6]), ("machine", "x86_64"), ("executable", prefix + "/bin/python3"),
                ("prefixes", [PREP.FRAMEWORK_ORIGINAL + "/Versions/3.14"] * 4),
                ("sysPath", [prefix + "-other/lib/python3.14"]),
                ("modulePaths", [prefix + "/lib/../outside.py"]), ("modulePaths", []),
                ("images", [entry, prefix + "/Python", "/opt/homebrew/lib/libssl.dylib"]),
                ("images", [entry, prefix + "/Python", "/usr/lib/../local/foreign.dylib"]),
                ("images", [entry, "/usr/lib/libSystem.B.dylib"]),
                ("openssl", {"OPENSSL_CONF": "/shared/openssl.cnf", "OPENSSL_MODULES": "/shared/providers"}),
                ("flags", {"isolated": 1, "noSite": 0, "noBytecode": True})):
            bad = copy.deepcopy(facts); bad[field] = value
            with self.subTest(runtime_boundary=field, value=value), self.assertRaises(PREP.PreparationRefused):
                PREP.runtime_facts_valid(bad, root, "arm64")
        base = {"PATH": "/usr/bin:/bin", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHON_FOR_REGEN": entry, "OPENSSL_CONF": "/shared/openssl.cnf", "OPENSSL_MODULES": "/shared/providers"}
        before = dict(base)
        clean = PREP.orchestration_environment(base, root)
        self.assertEqual(base, before)
        self.assertEqual(clean["OPENSSL_CONF"], "/dev/null")
        self.assertEqual(clean["OPENSSL_MODULES"], str(root / "empty-providers"))
        self.assertEqual(clean["PYTHON_FOR_REGEN"], entry)
        for name in ("DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "PYTHONHOME", "PYTHONPATH", "PYTHONUSERBASE"):
            with self.subTest(inherited_loader=name), self.assertRaises(PREP.PreparationRefused):
                PREP.orchestration_environment({**base, name: "/shared/untrusted"}, root)

        # This record is only DATA. Actual source/case originals, complete tree
        # and native startup remain separate preparation checks.
        ctx = {"sourceCommit": "a" * 40, "run": "123", "attempt": "1",
               "target": "aarch64-apple-darwin", "machine": "arm64"}
        identity = [1, 2, stat.S_IFDIR | 0o555, 501, 20, 1, 0, 10, 11]
        record = {"schemaVersion": 1, "state": "READY", "identity": dict(ctx),
                  "packageSha256": PREP.PACKAGE_SHA256, "rootCustody": identity[:5],
                  "providerIdentity": list(identity),
                  "framework": {".": {"kind": "directory", "identity": list(identity)}},
                  "originalsKnown": True, "handlersRestored": True, "intermediatesRetired": True}
        self.assertTrue(PREP.prepared_record_valid(record, ctx))
        partial = copy.deepcopy(record)
        partial["state"] = "PREPARED-NOT-READY"
        for name in ("originalsKnown", "handlersRestored", "intermediatesRetired"):
            del partial[name]
        self.assertTrue(PREP.prepared_record_valid(partial, ctx, ready=False))
        with self.assertRaises(PREP.PreparationRefused):
            PREP.prepared_record_valid(partial, ctx)
        for field in ("originalsKnown", "handlersRestored", "intermediatesRetired"):
            for value in (False, None, 1):
                bad = copy.deepcopy(record); bad[field] = value
                with self.subTest(finality_field=field, value=value), self.assertRaises(PREP.PreparationRefused):
                    PREP.prepared_record_valid(bad, ctx)
        for field, value in (("schemaVersion", True), ("state", "PREPARED-NOT-READY"),
                             ("identity", {**ctx, "sourceCommit": "b" * 40}),
                             ("identity", {**ctx, "machine": "x86_64"}),
                             ("packageSha256", "0" * 64), ("rootCustody", identity[:4]),
                             ("providerIdentity", [True] + identity[1:]), ("framework", {})):
            bad = copy.deepcopy(record); bad[field] = value
            with self.subTest(prepared_record_boundary=field, value=value), self.assertRaises(PREP.PreparationRefused):
                PREP.prepared_record_valid(bad, ctx)
        extra = copy.deepcopy(record); extra["approval"] = True
        with self.assertRaises(PREP.PreparationRefused):
            PREP.prepared_record_valid(extra, ctx)
        for name, row in (("../outside", {"kind": "directory", "identity": list(identity)}),
                          ("bad.py", {"kind": "file", "identity": list(identity), "size": True, "sha256": "a" * 64}),
                          ("bad.py", {"kind": "file", "identity": list(identity), "size": 1, "sha256": "A" * 64}),
                          ("extra", {"kind": "directory", "identity": list(identity), "approval": True})):
            bad = copy.deepcopy(record); bad["framework"][name] = row
            with self.subTest(prepared_inventory_boundary=name, row=row), self.assertRaises(PREP.PreparationRefused):
                PREP.prepared_record_valid(bad, ctx)

        completed = {"schemaVersion": 1, "sourceCommit": ctx["sourceCommit"], "target": ctx["target"],
                     "runId": ctx["run"], "runAttempt": ctx["attempt"], "state": "qualified-supplier",
                     "lifetime": {"complete": True, "fatal": False, "contained": True},
                     "handlers": "RESTORED", "dataFinality": "KNOWN"}
        self.assertTrue(PREP.completed_build_valid(completed, ctx, "success"))
        failed = {**completed, "state": "failed-no-supplier"}
        self.assertTrue(PREP.completed_build_valid(failed, ctx, "failure"))
        with self.assertRaises(PREP.PreparationRefused):
            PREP.completed_build_valid(failed, ctx, "success")
        with self.assertRaises(PREP.PreparationRefused):
            PREP.completed_build_valid({}, ctx, "success")
        for field, value in (("dataFinality", "UNKNOWN"), ("handlers", "UNKNOWN"),
                             ("runAttempt", "2"), ("sourceCommit", "b" * 40),
                             ("lifetime", {"complete": 1, "fatal": False, "contained": True}),
                             ("lifetime", {"complete": True, "fatal": True, "contained": True})):
            bad = copy.deepcopy(completed); bad[field] = value
            with self.subTest(completed_build_boundary=field, value=value), self.assertRaises(PREP.PreparationRefused):
                PREP.completed_build_valid(bad, ctx, "success")

    def test_original_calls_keep_failure_and_unknown_finality_distinct(self):
        tools = {name: "/inert-tools/" + name for name in ("sandbox", "download", "package", "relocate", "sign", "probe")}
        root = Path("/task-owned/preparation")
        actual_data = BUILD.DATA
        self.assertTrue(actual_data.known)
        for result in (0, 17):
            with self.subTest(original_exit=result), PipeOriginal(returncode=result) as original:
                factory = mock.Mock(return_value=original)
                data = BUILD.DataFinality()
                clock = [0.0]
                calls = PREP.FixedCalls(root, tools, data=data, clock=lambda: clock[0], popen=factory)
                if result == 0:
                    self.assertEqual(calls.run("package", ["--check-signature", "input.pkg"], environment={}),
                                     {"stdout": b"ordinary-output\n", "stderr": b""})
                else:
                    with self.assertRaises(PREP.PreparationRefused):
                        calls.run("package", ["--check-signature", "input.pkg"], environment={})
                self.assertTrue(calls.known and data.known)
                self.assertIsNone(calls.active)
                self.assertTrue(calls.records[0]["returned"] and calls.records[0]["settled"])
                self.assertEqual(calls.records[0]["returncode"], result)
                self.assertTrue(all(stream.closed for stream in original.streams))
                self.assertNotIn("kill-original-double", original.events)
                args, kwargs = factory.call_args
                self.assertEqual(args[0][0:2], [tools["sandbox"], "-p"])
                self.assertIn("(deny process-fork)", args[0][2])
                self.assertIn("(deny network*)", args[0][2])
                self.assertEqual(args[0][3:], [tools["package"], "--check-signature", "input.pkg"])
                self.assertTrue(kwargs["close_fds"])
                if result == 0:
                    clock[0] = PREP.PREP_SECONDS - PREP.SETTLE_SECONDS
                    with self.assertRaises(PREP.PreparationRefused):
                        calls.run("package", [], environment={})
                    self.assertEqual(factory.call_count, 1)
                    self.assertEqual(calls.deadline, PREP.PREP_SECONDS)

        # Observe closed categories, never private or unlisted output/path text.
        canary = b"/private/MRK-DIAGNOSTIC-CANARY: "
        for body, count in ((canary + b"Operation not permitted", 1),
                            (canary + b"unrecognized diagnostic", 0),
                            (canary + b"Permission denied; codesign_allocate helper tool cannot be found or used", 2)):
            with self.subTest(sign_categories=count), PipeOriginal(returncode=1, stderr=body) as original:
                calls = PREP.FixedCalls(root, tools, data=BUILD.DataFinality(),
                                        clock=lambda: 0.0, popen=mock.Mock(return_value=original))
                with self.assertRaisesRegex(PREP.PreparationRefused, "^fixed-sign-exit-1$"):
                    calls.run("sign", ["--sign", "-", "input"], environment={})
                row = calls.records[0]
                self.assertTrue(row["settled"] and row["returned"] and calls.known)
                self.assertEqual(row["stderrSize"], len(body))
                self.assertEqual(row["stderrSha256"], PREP.hashlib.sha256(body).hexdigest())
                self.assertEqual(row["signDiagnostic"]["matchedCategories"], count)
                self.assertTrue(row["signDiagnostic"]["observationOnly"])
                self.assertNotIn("CANARY", PREP.json.dumps(row))
                self.assertTrue(all(stream.closed for stream in original.streams))
        self.assertIsNone(PREP.sign_failure_observation(b"x" * 16385))
        self.assertIsNone(PREP.sign_failure_observation(b"\xff"))
        self.assertIsNone(PREP.sign_failure_observation("not bytes"))

        # Small synthetic public inventory DATA, not package/native authority.
        member = PREP.ENTRY_RELATIVE
        nested = PREP.VERSION_RELATIVE + "/Frameworks/Tcl.framework"
        rows = {".": {"kind": "directory"}}
        for name in (member, nested + "/Versions/9.0/Tcl",
                     nested + "/Versions/9.0/Resources/Info.plist",
                     str(PurePosixPath(member).parent.parent / "Info.plist")):
            parts = name.split("/")
            for index in range(1, len(parts)):
                rows["/".join(parts[:index])] = {"kind": "directory"}
            rows[name] = {"kind": "file", "size": 7, "sha256": "a" * 64}
        rows["Versions/Current"] = {"kind": "link", "target": "3.14"}
        framework = str(root) + "/Python.framework"
        target = framework + "/" + member
        sign_args = ["--force", "--sign", "-", "--timestamp=none", target]
        verify_args = ["--verify", "--strict", target]
        signing_context = (member, rows, 0, 2)

        def observe(body, *, arguments=sign_args, context=signing_context):
            return PREP.sign_failure_observation(body, arguments=arguments, root=str(root), signing_context=context)

        for action, arguments, phrase in (("sign", sign_args, "code object is not signed at all"),
                                          ("verify", verify_args, "invalid signature")):
            body = (target + ": " + phrase + "\nIn subcomponent: " + framework + "/" + nested + "\n").encode()
            with self.subTest(sign_action=action), PipeOriginal(returncode=1, stderr=body) as original:
                factory = mock.Mock(return_value=original)
                calls = PREP.FixedCalls(root, tools, data=BUILD.DataFinality(), clock=lambda: 0.0, popen=factory)
                with self.assertRaisesRegex(PREP.PreparationRefused, "^fixed-sign-exit-1$"):
                    calls.run("sign", arguments, environment={}, signing_context=signing_context)
                row = calls.records[0]
                diagnostic = row["signDiagnostic"]
                self.assertEqual(diagnostic["kind"], "closed-codesign-error-observation-v2")
                self.assertEqual(diagnostic["matches"]["unsigned"], action == "sign")
                self.assertEqual(diagnostic["matches"]["signatureInvalid"], action == "verify")
                self.assertEqual(diagnostic["matchedCategories"], 1)
                context = diagnostic["signingContext"]
                self.assertEqual((context["phase"], context["action"], context["ordinal"], context["imageCount"]),
                                 ("image-signing", action, 0, 2))
                self.assertEqual(context["target"], {"relativeMember": member, "kind": "file",
                    "packageMemberBytes": 7, "packageMemberSha256": "a" * 64,
                    "lexicalLayoutCandidate": "application-main-path"})
                objects = context["reportedObjects"]
                self.assertEqual((objects["primaryFields"], objects["subcomponentFields"], objects["matchedFields"]), (1, 1, 2))
                self.assertEqual(objects["matches"], [
                    {"source": "primary", "relativeMember": member, "kind": "file", "viaAlias": False},
                    {"source": "subcomponent", "relativeMember": nested, "kind": "directory", "viaAlias": False}])
                self.assertFalse(objects["multipleSubcomponents"] or objects["overflow"])
                self.assertNotIn(str(root), PREP.json.dumps(row))
                self.assertEqual(factory.call_args.args[0][3:], [tools["sign"], *arguments])
                self.assertTrue(row["settled"] and row["returned"] and calls.known and calls.data.known)
                self.assertTrue(all(stream.closed for stream in original.streams))

        # The real standalone route keeps both original commands/flags, but
        # neither the native operand nor its observation selects a framework.
        slot = str(root / "tmp/macho-sign-0000" / PurePosixPath(member).name)
        for action, arguments in (("sign", ["--force", "--sign", "-", "--timestamp=none", slot]),
                                  ("verify", ["--verify", "--strict", slot])):
            with self.subTest(standalone_action=action), PipeOriginal(
                    returncode=1, stderr=(slot + ": code object is not signed at all").encode()) as original:
                factory = mock.Mock(return_value=original)
                calls = PREP.FixedCalls(root, tools, data=BUILD.DataFinality(), clock=lambda: 0.0, popen=factory)
                with self.assertRaisesRegex(PREP.PreparationRefused, "^fixed-sign-exit-1$"):
                    calls.run("sign", arguments, environment={}, signing_context=signing_context)
                row = calls.records[0]
                context = row["signDiagnostic"]["signingContext"]
                self.assertEqual((context["action"], context["operandRole"]), (action, "standalone-macho"))
                self.assertEqual(context["target"]["relativeMember"], member)
                self.assertEqual(context["reportedObjects"]["matches"], [
                    {"source": "primary", "relativeMember": member, "kind": "file", "viaAlias": False}])
                self.assertNotIn(str(root), PREP.json.dumps(row))
                self.assertNotIn("macho-sign-", PREP.json.dumps(row))
                self.assertEqual(factory.call_args.args[0][3:], [tools["sign"], *arguments])
                self.assertTrue(row["returned"] and row["settled"] and calls.known and calls.data.known)
                self.assertTrue(all(stream.closed for stream in original.streams))
        for wrong in (slot.replace("0000", "0001"), slot + "-foreign", slot + "/../Python"):
            self.assertIsNone(observe(b"invalid signature",
                arguments=["--verify", "--strict", wrong])["signingContext"])

        # An untrusted or unavailable context cannot stop the original call or
        # turn its actual nonzero exit into success, and cannot leak its text.
        with PipeOriginal(returncode=1, stderr=b"invalid signature") as original:
            factory = mock.Mock(return_value=original)
            calls = PREP.FixedCalls(root, tools, data=BUILD.DataFinality(), clock=lambda: 0.0, popen=factory)
            with self.assertRaisesRegex(PREP.PreparationRefused, "^fixed-sign-exit-1$"):
                calls.run("sign", sign_args, environment={}, signing_context=("PRIVATE-CANARY", {}, 0, 1))
            factory.assert_called_once()
            self.assertIsNone(calls.records[0]["signDiagnostic"]["signingContext"])
            self.assertNotIn("PRIVATE-CANARY", PREP.json.dumps(calls.records[0]))

        alias = framework + "/Versions/Current/Resources/Python.app/Contents/MacOS/Python"
        objects = observe(("In subcomponent: " + alias).encode())["signingContext"]["reportedObjects"]
        self.assertEqual(objects["matches"], [{"source": "subcomponent", "relativeMember": member,
                                              "kind": "file", "viaAlias": True}])
        frame_member = nested + "/Versions/9.0/Tcl"
        frame_args = ["--force", "--sign", "-", "--timestamp=none", framework + "/" + frame_member]
        self.assertEqual(observe(b"invalid signature", arguments=frame_args,
            context=(frame_member, rows, 1, 2))["signingContext"]["target"]["lexicalLayoutCandidate"], "framework-main-path")
        mixed = observe(b"invalid signature; code object is not signed at all")
        self.assertTrue(mixed["matches"]["unsigned"] and mixed["matches"]["signatureInvalid"])
        self.assertEqual(mixed["matchedCategories"], 2)

        bad_values = [("/private/PRIVATE-CANARY", "unmatchedFields"),
                      (framework + "-foreign/PRIVATE-CANARY", "unmatchedFields"),
                      (framework + "/absent", "unmatchedFields"),
                      (framework + "/../PRIVATE-CANARY", "malformedFields"),
                      (framework + "/" + member + "\r", "malformedFields"),
                      (framework + "/x\\y", "malformedFields"),
                      (framework + "/" + "x" * 4097, "malformedFields")]
        for value, field in bad_values:
            with self.subTest(sign_object_refusal=field, value_bytes=len(value)):
                objects = observe(("In subcomponent: " + value).encode())["signingContext"]["reportedObjects"]
                self.assertEqual(objects["subcomponentFields"], 1)
                self.assertEqual(objects[field], 1)
                self.assertEqual(objects["matches"], [])
                self.assertNotIn("PRIVATE-CANARY", PREP.json.dumps(objects))
        duplicated = observe(("In subcomponent: " + framework + "/" + nested
            + "\nIn subcomponent: /private/PRIVATE-CANARY").encode())["signingContext"]["reportedObjects"]
        self.assertEqual((duplicated["subcomponentFields"], duplicated["matchedFields"], duplicated["unmatchedFields"]), (2, 1, 1))
        self.assertTrue(duplicated["multipleSubcomponents"])
        ambiguous_rows = {**rows, member + ": extra": {"kind": "file", "size": 9, "sha256": "b" * 64}}
        ambiguous = observe((target + ": extra: invalid signature").encode(),
            context=(member, ambiguous_rows, 0, 2))["signingContext"]["reportedObjects"]
        self.assertEqual(ambiguous["ambiguousFields"], 1)
        self.assertEqual(ambiguous["matches"], [])
        long_line = observe((framework + "/" + "x: " * 20 + "invalid signature").encode())["signingContext"]["reportedObjects"]
        self.assertTrue(long_line["overflow"])
        self.assertEqual((long_line["ambiguousFields"], long_line["matches"]), (1, []))
        many_rows = {**rows, "public": {"kind": "directory"}}
        many_rows.update({"public/file" + str(i): {"kind": "file", "size": 1, "sha256": "c" * 64} for i in range(9)})
        many = observe("\n".join("In subcomponent: " + framework + "/public/file" + str(i) for i in range(9)).encode(),
            context=(member, many_rows, 0, 2))["signingContext"]["reportedObjects"]
        self.assertEqual((many["subcomponentFields"], many["matchedFields"], len(many["matches"])), (9, 9, 8))
        self.assertTrue(many["overflow"] and many["multipleSubcomponents"])
        for bad_context in (None, [member, rows, 0, 2], (member, rows, True, 2), (member, rows, 0, 1025),
                            (member, rows, 2, 2), ("../private", rows, 0, 2), (member, {}, 0, 2)):
            self.assertIsNone(observe(b"invalid signature", context=bad_context)["signingContext"])
        for bad_args in ([], ["--sign", "-", target], ["--verify", "--strict", target + "-foreign"]):
            self.assertIsNone(observe(b"invalid signature", arguments=bad_args)["signingContext"])

        for mode in ("wait-unknown", "close-unknown", "observer-error", "success", "other-role"):
            with self.subTest(sign_diagnostic_boundary=mode), PipeOriginal(
                    returncode=0 if mode=="success" else 1, stderr=b"Permission denied",
                    wait_error=mode=="wait-unknown", close_error=mode=="close-unknown") as original:
                calls = PREP.FixedCalls(root, tools, data=BUILD.DataFinality(),
                                        clock=lambda: 0.0, popen=mock.Mock(return_value=original))
                guard = mock.patch.object(PREP, "sign_failure_observation", side_effect=MemoryError(
                    "inert diagnostic allocation failure")) if mode=="observer-error" else nullcontext()
                original_failure = PREP.PreparationRefused("fixed-sign-exit-1")
                original_need = PREP.need
                def fail_original(condition, code):
                    if not condition and code == "fixed-sign-exit-1":
                        raise original_failure
                    return original_need(condition, code)
                failure_guard = mock.patch.object(PREP, "need", side_effect=fail_original) if mode=="observer-error" else nullcontext()
                with guard, failure_guard:
                    if mode=="success":
                        calls.run("sign", [], environment={})
                    else:
                        expected = OSError if mode=="wait-unknown" else PREP.PreparationRefused
                        with self.assertRaises(expected) as caught:
                            calls.run("package" if mode=="other-role" else "sign", [], environment={})
                        if mode == "observer-error":
                            self.assertIs(caught.exception, original_failure)
                self.assertNotIn("signDiagnostic", calls.records[0])
                self.assertTrue(all(stream.closed for stream in original.streams))

        # A successful original wait or close can itself cross the immutable
        # endpoint or observe cancellation. That remains a known, settled
        # failed operation, never successful output or invented UNKNOWN.
        for event in ("deadline-wait", "deadline-close", "cancel-wait", "cancel-close"):
            with self.subTest(late_original=event):
                now, cancellation = [0.0], {"cancelled": False}
                def observe_late_completion():
                    if event.startswith("deadline"):
                        now[0] = 2.0
                    else:
                        cancellation["cancelled"] = True

                class LateOriginal(PipeOriginal):
                    def wait(self, timeout):
                        result = super().wait(timeout)
                        if event.endswith("wait"):
                            observe_late_completion()
                        return result

                with LateOriginal() as original:
                    if event.endswith("close"):
                        actual_stdout = original.stdout
                        class LateClose:
                            def fileno(self):
                                return actual_stdout.fileno()

                            def close(self):
                                actual_stdout.close()
                                observe_late_completion()
                        original.stdout = LateClose()
                    data = BUILD.DataFinality()
                    factory = mock.Mock(return_value=original)
                    calls = PREP.FixedCalls(root, tools, data=data, clock=lambda: now[0], popen=factory)
                    calls.cancellation = cancellation
                    with self.assertRaises(PREP.PreparationRefused):
                        calls.run("probe", [], environment={}, maximum=2)
                    self.assertTrue(calls.known and data.known)
                    self.assertIsNone(calls.active)
                    self.assertEqual(calls.deadline, PREP.PREP_SECONDS)
                    self.assertEqual(len(calls.records), 1)
                    self.assertTrue(calls.records[0]["returned"] and calls.records[0]["settled"])
                    self.assertEqual(calls.records[0]["returncode"], 0)
                    self.assertTrue(all(stream.closed for stream in original.streams))
                    self.assertNotIn("kill-original-double", original.events)
                    factory.assert_called_once()

        not_entered = mock.Mock(side_effect=AssertionError("invalid tool role must not enter"))
        roles = PREP.FixedCalls(root, tools, data=BUILD.DataFinality(), clock=lambda: 0.0, popen=not_entered)
        for role, online in (("probe", True), ("download", False), ("arbitrary-command", False)):
            with self.subTest(role=role, online=online), self.assertRaises(PREP.PreparationRefused):
                roles.run(role, [], environment={}, online=online)
        not_entered.assert_not_called()

        factory = mock.Mock(side_effect=OSError("inert constructor result unavailable"))
        local = BUILD.DataFinality()
        calls = PREP.FixedCalls(root, tools, data=local, clock=lambda: 0.0, popen=factory)
        with self.assertRaises(OSError):
            calls.run("probe", [], environment={})
        self.assertFalse(calls.known or local.known)
        self.assertFalse(calls.records[0]["returned"] or calls.records[0]["settled"])
        with self.assertRaises(PREP.PreparationRefused):
            calls.run("probe", [], environment={})
        self.assertEqual(factory.call_count, 1)

        for mode in ("interruption", "deadline", "wait-unknown", "close-unknown", "selector-constructor"):
            with self.subTest(original_lifecycle=mode), PipeOriginal(
                    returncode=None if mode in ("interruption", "deadline") else 0,
                    interrupt=mode == "interruption", wait_error=mode == "wait-unknown",
                    close_error=mode == "close-unknown") as original:
                now = [0.0]
                def construct(*_, **__):
                    if mode == "deadline":
                        now[0] = 3.0
                    return original
                data = BUILD.DataFinality()
                calls = PREP.FixedCalls(root, tools, data=data, clock=lambda: now[0], popen=construct)
                expected = KeyboardInterrupt if mode == "interruption" else (
                    OSError if mode in ("wait-unknown", "selector-constructor") else PREP.PreparationRefused)
                selector_fault = mock.patch.object(PREP.selectors, "DefaultSelector",
                    side_effect=OSError("inert selector constructor result unavailable")) if mode == "selector-constructor" else nullcontext()
                with selector_fault, self.assertRaises(expected):
                    calls.run("probe", [], environment={}, maximum=2)
                self.assertTrue(all(stream.closed for stream in original.streams))
                if mode in ("interruption", "deadline"):
                    self.assertTrue(calls.known and data.known and calls.records[0]["settled"])
                    self.assertFalse(calls.records[0]["returned"])
                    self.assertEqual(original.events.count("kill-original-double"), 1)
                    self.assertIsNone(calls.active)
                else:
                    self.assertFalse(calls.known or data.known)
                    self.assertEqual(calls.active, "unknown")

        # A process return does not prove custody of its two original output
        # streams. Partial publication cannot authorize retirement or a retry.
        with PipeOriginal() as original:
            class PartialStreams:
                @property
                def stdout(self):
                    return original.stdout

                @property
                def stderr(self):
                    raise OSError("inert second original stream unavailable")

                def poll(self):
                    return original.poll()

                def wait(self, timeout):
                    return original.wait(timeout)

                def kill(self):
                    return original.kill()
            factory = mock.Mock(return_value=PartialStreams())
            local = BUILD.DataFinality()
            calls = PREP.FixedCalls(root, tools, data=local, clock=lambda: 0.0, popen=factory)
            with self.assertRaises(OSError):
                calls.run("probe", [], environment={})
            self.assertFalse(calls.known or local.known)
            self.assertEqual(calls.active, "unknown")
            self.assertTrue(original.stdout.closed)
            self.assertFalse(original.stderr.closed)
            with self.assertRaises(PREP.PreparationRefused):
                calls.run("probe", [], environment={})
            self.assertEqual(factory.call_count, 1)
            # Only this fixture still owns the deliberately unavailable stream;
            # its context cleanup is not a production-finality success.
        self.assertIs(BUILD.DATA, actual_data)
        self.assertTrue(actual_data.known)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "requires the reviewed nonroot POSIX DATA owner")
    def test_complete_copy_and_retirement_preserve_original_alias_custody(self):
        actual_data = BUILD.DATA
        self.assertTrue(actual_data.known)
        with tempfile.TemporaryDirectory(prefix="mrk-orchestration-data-") as temporary:
            root = Path(temporary)
            deadline = time.monotonic() + 30
            source = root / "source"
            library = source / "Versions/3.14/lib/python3.14"
            library.mkdir(parents=True, mode=0o700)
            (library / "os.py").write_bytes(b"# passive stdlib-shaped DATA\n")
            binary = source / "Versions/3.14/Python"
            binary.write_bytes(b"passive not-executable image DATA"); binary.chmod(0o700)
            os.symlink("3.14", source / "Versions/Current")
            os.symlink("Versions/Current/Python", source / "Python")
            # Exact embedded development aliases stay present and dangling;
            # neither copy nor readonly admission invents target directories.
            private_aliases = []
            for component in ("Tcl", "Tk"):
                framework = source / "Versions/3.14/Frameworks" / (component + ".framework")
                (framework / "Versions/9.0").mkdir(parents=True, mode=0o700)
                os.symlink("9.0", framework / "Versions/Current")
                os.symlink("Versions/Current/PrivateHeaders", framework / "PrivateHeaders")
                private_aliases.append((framework / "PrivateHeaders").relative_to(source).as_posix())
            expected = PREP.scan_tree(source, closure=True, deadline=deadline)
            self.assertEqual(expected["Versions/Current"]["kind"], "link")
            self.assertEqual(expected["Python"]["target"], "Versions/Current/Python")
            for name in private_aliases:
                self.assertIs(PREP.optional_private_header_alias(name, expected), True)
                self.assertTrue((source / name).is_symlink())
                self.assertFalse((source / name).exists())
                with self.assertRaisesRegex(PREP.PreparationRefused, "^member-missing$"):
                    PREP.resolve_member(name, expected)

            successful = root / "successful"
            copied = PREP.copy_framework(source, successful, expected, deadline=deadline)
            self.assertEqual(set(copied), set(expected))
            for name, original in expected.items():
                self.assertEqual(copied[name]["kind"], original["kind"])
                if original["kind"] == "file":
                    self.assertEqual((copied[name]["size"], copied[name]["sha256"]),
                                     (original["size"], original["sha256"]))
                elif original["kind"] == "link":
                    self.assertEqual(copied[name]["target"], original["target"])
            self.assertEqual(stat.S_IMODE((successful / "Versions/3.14/Python").stat().st_mode), 0o700)
            # This is the normal intentional protection phase, not repair of a
            # failed/unknown original. Its resulting identities are captured once.
            for name, row in sorted(copied.items(), key=lambda item: -item[0].count("/")):
                path = successful / name
                if row["kind"] == "directory":
                    path.chmod(0o555)
                elif row["kind"] == "file":
                    path.chmod(0o555 if row["identity"][2] & 0o111 else 0o444)
            protected = PREP.scan_tree(successful, readonly=True, closure=True, deadline=deadline)
            for name in private_aliases:
                self.assertTrue((successful / name).is_symlink())
                self.assertFalse((successful / name).exists())
                self.assertEqual(os.readlink(successful / name), expected[name]["target"])
                self.assertEqual(protected[name], copied[name])
            PREP.retire_tree(successful, protected, known=True, deadline=deadline)
            self.assertFalse(successful.exists() or successful.is_symlink())
            self.assertEqual(PREP.scan_tree(source, closure=True, deadline=deadline), expected)

            occupied = root / "occupied"; occupied.mkdir()
            (occupied / "keep").write_bytes(b"existing task occupant")
            with self.assertRaises(PREP.PreparationRefused):
                PREP.copy_framework(source, occupied, expected, deadline=deadline)
            self.assertEqual((occupied / "keep").read_bytes(), b"existing task occupant")

            unknown = root / "unknown"
            unknown_before = PREP.copy_framework(source, unknown, expected, deadline=deadline)
            for flag in (False, None, 1):
                with self.subTest(unknown_finality=flag), self.assertRaises(PREP.PreparationRefused):
                    PREP.retire_tree(unknown, unknown_before, known=flag, deadline=deadline)
                self.assertEqual(PREP.scan_tree(unknown, closure=True, deadline=deadline), unknown_before)
            # This branch is never re-admitted as known. Only the test's private
            # TemporaryDirectory owns its later disposable-fixture cleanup.
            changed = root / "changed"
            changed_before = PREP.copy_framework(source, changed, expected, deadline=deadline)
            (changed / "Versions/3.14/lib/python3.14/os.py").write_bytes(b"changed original contents")
            with self.assertRaises(PREP.PreparationRefused):
                PREP.retire_tree(changed, changed_before, known=True, deadline=deadline)
            self.assertTrue((changed / "Python").is_symlink())
            self.assertEqual((changed / "Versions/3.14/lib/python3.14/os.py").read_bytes(), b"changed original contents")

            outside = root / "outside"; outside.mkdir()
            (outside / "keep").write_bytes(b"outside the selected tree")
            escaping = root / "escaping"; escaping.mkdir()
            os.symlink("../outside", escaping / "alias")
            with self.assertRaises(PREP.PreparationRefused):
                PREP.scan_tree(escaping, closure=True, deadline=deadline)
            self.assertEqual((outside / "keep").read_bytes(), b"outside the selected tree")
            collision = root / "collision"; collision.mkdir()
            (collision / "module.py").write_bytes(b"a")
            if (collision / "MODULE.py").exists():
                # A case-insensitive native filesystem cannot construct this
                # two-name fixture; the Linux DATA gate exercises scan refusal.
                self.assertTrue((collision / "MODULE.py").samefile(collision / "module.py"))
                self.assertEqual((collision / "module.py").read_bytes(), b"a")
            else:
                (collision / "MODULE.py").write_bytes(b"b")
                with self.assertRaises(PREP.PreparationRefused):
                    PREP.scan_tree(collision, closure=True, deadline=deadline)
                with self.assertRaises(PREP.PreparationRefused):
                    PREP.scan_tree(collision, expanded=True, deadline=deadline)
            hardlink = root / "hardlink"; hardlink.mkdir()
            (hardlink / "original").write_bytes(b"shared DATA inode")
            os.link(hardlink / "original", hardlink / "second")
            with self.assertRaises(PREP.PreparationRefused):
                PREP.scan_tree(hardlink, closure=True, deadline=deadline)
            writable = root / "writable"; writable.mkdir(mode=0o700)
            (writable / "data.py").write_bytes(b"writable closure DATA")
            with self.assertRaises(PREP.PreparationRefused):
                PREP.scan_tree(writable, readonly=True, closure=True, deadline=deadline)
            # Authentic public packages contain native metadata names such as
            # Finder's terminal-CR Icon file. They are inert disposable DATA,
            # never an admitted framework name or a command/loader argument.
            icon_name = "Python_Applications.pkg/Payload/Python 3.14/Icon\r"
            for name in (icon_name, "package/metadata-é.txt"):
                self.assertIs(PREP.expanded_name(name), name)
                with self.assertRaisesRegex(PREP.PreparationRefused, "^relative-name$"):
                    PREP.relative_name(name)
            for name in (None, 1, "", "/outside", "a/../outside", "a/./file", "a//file", "a/",
                         "a\\file", "a/\0file", "a/\ud800", "a" * 4097, "é" * 2049):
                with self.subTest(expanded_name=name), self.assertRaises(PREP.PreparationRefused):
                    PREP.expanded_name(name)
            # This context/record is a tiny explicit DATA fixture. No real Mac,
            # pkgutil command, process completion or supplier is being claimed.
            preparation_root = root / "preparation-data"
            expanded = preparation_root / "expanded"
            icon = expanded / icon_name
            icon.parent.mkdir(parents=True, mode=0o700)
            icon.write_bytes(b"inert Finder icon metadata")
            unicode_name = "Python_Applications.pkg/Payload/Python 3.14/metadata-é.txt"
            (expanded / unicode_name).write_bytes(b"inert UTF-8 filename DATA")
            os.symlink(str(outside), expanded / "outside-alias")
            for flags in ({}, {"closure": True}, {"readonly": True}):
                with self.subTest(strict_role=flags), self.assertRaises(PREP.PreparationRefused):
                    PREP.scan_tree(expanded, deadline=deadline, **flags)
            for flags in ({"closure": True}, {"readonly": True}):
                with self.subTest(mixed_role=flags), self.assertRaisesRegex(
                        PREP.PreparationRefused, "^inventory-role$"):
                    PREP.scan_tree(expanded, expanded=True, deadline=deadline, **flags)
            with self.assertRaisesRegex(PREP.PreparationRefused, "^inventory-role$"):
                PREP.scan_tree(expanded, expanded=1, deadline=deadline)
            public_rows = PREP.scan_tree(expanded, expanded=True, deadline=deadline)
            self.assertEqual(public_rows[icon_name]["kind"], "file")
            self.assertEqual((public_rows[icon_name]["size"], public_rows[icon_name]["sha256"]),
                             (26, PREP.hashlib.sha256(b"inert Finder icon metadata").hexdigest()))
            self.assertEqual(public_rows[unicode_name]["kind"], "file")
            self.assertEqual(public_rows["outside-alias"]["target"], str(outside))
            self.assertEqual(BUILD.decode(BUILD.canonical(public_rows)), public_rows)
            self.assertIn(b'Icon\\r', BUILD.canonical(public_rows))
            unknown_public = root / "unknown-public"
            unknown_public.mkdir(mode=0o700)
            (unknown_public / "Icon\r").write_bytes(b"inert unknown-finality metadata")
            unknown_rows = PREP.scan_tree(unknown_public, expanded=True, deadline=deadline)
            with self.assertRaises(PREP.PreparationRefused):
                PREP.retire_tree(unknown_public, unknown_rows, expanded=True, known=False, deadline=deadline)
            self.assertEqual(PREP.scan_tree(unknown_public, expanded=True, deadline=deadline), unknown_rows)
            # No unknown original is re-admitted as known: the real cleanup
            # route below uses the separate preparation_root fixture.
            ctx = {"root": preparation_root, "sourceCommit": "a" * 40, "run": "1", "attempt": "1",
                   "target": "aarch64-apple-darwin", "machine": "arm64"}
            PREP.capture_cleanup(ctx, deadline=deadline)
            cleanup = PREP.read_record(preparation_root / "cleanup.json")
            self.assertEqual(cleanup["entries"]["expanded"]["inventory"], public_rows)
            public = preparation_root / "public/evidence"
            public.mkdir(parents=True, mode=0o700)
            PREP.atomic_record(public / "prepare-result.json", {
                "identity": PREP.identity_fields(ctx), "originalsKnown": True,
                "handlersRestored": True, "cleanupRecorded": True, "prepared": False})
            PREP.retire(ctx, "failure", "skipped")
            self.assertFalse(expanded.exists() or expanded.is_symlink())
            self.assertEqual({entry.name for entry in preparation_root.iterdir()}, {"public"})
            retirement = PREP.read_record(public / "retirement-result.json")
            self.assertTrue(retirement["orchestratorRetired"])
            self.assertEqual(retirement["retiredEntries"], 1)
            self.assertEqual((outside / "keep").read_bytes(), b"outside the selected tree")
            changed_public = root / "changed-public"
            (changed_public / "metadata").mkdir(parents=True, mode=0o700)
            changed_icon = changed_public / "metadata/Icon\r"
            changed_icon.write_bytes(b"original metadata")
            changed_rows = PREP.scan_tree(changed_public, expanded=True, deadline=deadline)
            changed_icon.write_bytes(b"changed metadata")
            with self.assertRaises(PREP.PreparationRefused):
                PREP.retire_tree(changed_public, changed_rows, expanded=True, known=True, deadline=deadline)
            self.assertEqual(changed_icon.read_bytes(), b"changed metadata")
            self.assertEqual(PREP.scan_tree(source, closure=True, deadline=deadline), expected)

            # Standalone signing uses real, tiny nonroot filesystem originals,
            # but ONLY an inert engine below: no codesign/process is executed.
            # This fixture deliberately retains unsigned bundle-side DATA.
            signing_source = root / "signing-source"
            member = PREP.VERSION_RELATIVE + "/Frameworks/Tcl.framework/Versions/9.0/Tcl"
            original_path = signing_source / member
            original_path.parent.mkdir(parents=True, mode=0o700)
            load = cstring_command(PREP.LC_ID_DYLIB, "@loader_path/Tcl")
            payload = b"MRK-PASSIVE-UNCHANGED-CODE-DATA"
            signature_offset = 32 + len(load) + 16 + len(payload)
            original_image = thin_fixture(commands=(load, struct.pack("<4I", 0x1D, 16, signature_offset, 4)),
                                          payload=payload + b"OLD!")
            signed_image = original_image[:-4] + b"NEW!"
            original_path.write_bytes(original_image); original_path.chmod(0o700)
            script_name = str(PurePosixPath(member).parent / "tclConfig.sh")
            (signing_source / script_name).write_bytes(b"# unsigned configuration DATA, not code\n")
            resources = original_path.parent / "Resources"; resources.mkdir(mode=0o700)
            (resources / "Info.plist").write_bytes(b"passive vendor bundle metadata")
            seal = original_path.parent / "_CodeSignature"; seal.mkdir(mode=0o700)
            (seal / "CodeResources").write_bytes(b"passive unchanged vendor resource seal")
            os.symlink("9.0", original_path.parent.parent / "Current")
            os.symlink("Versions/Current/Tcl", original_path.parent.parent.parent / "Tcl")
            signing_rows = PREP.scan_tree(signing_source, closure=True, deadline=deadline)
            finality_class = BUILD.DataFinality

            cases = ("success", "sign-failure", "verify-failure", "unknown-sign", "late-verify", "cancel-verify",
                     "payload-tamper", "loader-tamper", "extra-output", "output-symlink", "output-hardlink",
                     "verify-replacement", "destination-rebound", "destination-parent-rebound", "slot-parent-rebound",
                     "occupied-slot", "slot-symlink", "output-constructor", "constructor-interrupt",
                     "first-error-close", "close-only", "late-close", "retirement-scan-rebound")
            for scenario in cases:
                with self.subTest(standalone_filesystem=scenario):
                    preparation = root / ("signing-" + scenario); preparation.mkdir(mode=0o700)
                    (preparation / "tmp").mkdir(mode=0o700)
                    framework = preparation / "Python.framework"
                    copied = PREP.copy_framework(signing_source, framework, signing_rows, deadline=deadline)
                    destination = framework / member
                    destination_before = PREP.identity(destination.lstat())
                    nonimages = {name: row for name, row in copied.items() if name != member and row["kind"] != "directory"}
                    slot_root = preparation / "tmp/macho-sign-0000"
                    slot = slot_root / "Tcl"
                    untouched = preparation / "outside"; untouched.mkdir(mode=0o700)
                    (untouched / "keep").write_bytes(b"never select an outside original")
                    if scenario == "occupied-slot":
                        slot_root.mkdir(mode=0o700)
                        (slot_root / "keep").write_bytes(b"never reuse an occupied signing slot")
                    elif scenario == "slot-symlink":
                        os.symlink(untouched, slot_root)

                    fixture_data, books = finality_class(), []
                    operation_error = PREP.PreparationRefused("inert-original-signing-failure")
                    close_error = OSError("inert local original close uncertainty")
                    constructor_error = (KeyboardInterrupt("inert local constructor interruption")
                                         if scenario == "constructor-interrupt" else
                                         OSError("inert output constructor result unavailable"))
                    owner = self

                    class HeldOriginals(finality_class):
                        def __init__(self):
                            super().__init__()
                            self.opened, self.closed, self.dispatches = [], [], 0
                            self.close_fault = False
                            books.append(self)

                        def acquiring(self, constructor, closer, *args, **kwargs):
                            def acquire():
                                self.dispatches += 1
                                if scenario == "constructor-interrupt" and self.dispatches == 3:
                                    raise constructor_error
                                if (scenario == "output-constructor" and args[0] == "Tcl"
                                        and args[1] & os.O_ACCMODE == os.O_RDONLY
                                        and not args[1] & os.O_DIRECTORY):
                                    raise constructor_error
                                value = constructor(*args, **kwargs)
                                self.opened.append(value)
                                return value
                            return super().acquiring(acquire, closer)

                        def close(self, closer, fd):
                            super().close(closer, fd)
                            self.closed.append(fd)
                            if not self.close_fault and scenario in ("first-error-close", "close-only", "late-close"):
                                self.close_fault = True
                                if scenario == "late-close":
                                    engine.now = engine.deadline - PREP.SETTLE_SECONDS
                                else:
                                    self.unknown()
                                    raise close_error

                    class InertSigner:
                        def __init__(self):
                            self.root, self.data = preparation, fixture_data
                            self.now, self.deadline = time.monotonic(), deadline + PREP.SETTLE_SECONDS
                            self.known, self.active, self.calls = True, None, []
                            self.cancellation = {"cancelled": False}
                            self.displaced, self.slot_displaced = None, None
                            self.slot_input_identity, self.signed_identity = None, None
                            self.expected_output = None

                        def clock(self):
                            return self.now

                        def run(self, role, arguments, *, environment, signing_context):
                            number = len(self.calls)
                            owner.assertLess(number, 2)
                            expected_arguments = (["--force", "--sign", "-", "--timestamp=none", str(slot)]
                                                  if number == 0 else ["--verify", "--strict", str(slot)])
                            owner.assertEqual((role, arguments, environment), ("sign", expected_arguments, {}))
                            owner.assertEqual(signing_context, (member, copied, 0, 1))
                            owner.assertIs(BUILD.DATA, fixture_data)
                            owner.assertTrue(BUILD.DATA.known and self.known)
                            owner.assertEqual(len(books), 1)
                            owner.assertGreater(books[0]._pending, 0)
                            owner.assertFalse(books[0].known)  # Intentionally held, NOT global closed-state.
                            owner.assertEqual(PREP.identity(destination.lstat()), destination_before)
                            owner.assertEqual(destination.read_bytes(), original_image)
                            self.calls.append(arguments)
                            if number == 0:
                                self.slot_input_identity = PREP.identity(slot.lstat())
                                owner.assertEqual(slot.read_bytes(), original_image)
                                if scenario in ("sign-failure", "first-error-close", "unknown-sign"):
                                    if scenario == "unknown-sign":
                                        self.known = False
                                        self.data.unknown()
                                    raise operation_error
                                # Apple's real implementation can replace the
                                # slot inode via .cstemp. This simulates ONLY
                                # that filesystem transformation, not a signature.
                                output = signed_image
                                if scenario == "payload-tamper":
                                    output = output.replace(payload, b"BAD" + payload[3:])
                                elif scenario == "loader-tamper":
                                    output = output.replace(b"@loader_path/Tcl", b"@loader_path/Bad")
                                self.expected_output = output
                                pending = slot.with_name(slot.name + ".cstemp")
                                pending.write_bytes(output); pending.chmod(0o700)
                                os.replace(pending, slot)
                                self.signed_identity = PREP.identity(slot.lstat())
                                owner.assertNotEqual(self.signed_identity[:2], self.slot_input_identity[:2])
                                if scenario == "extra-output":
                                    pending.write_bytes(b"unexpected output stays unadmitted")
                                elif scenario == "output-symlink":
                                    slot.unlink(); os.symlink(untouched / "keep", slot)
                                elif scenario == "output-hardlink":
                                    os.link(slot, untouched / "extra-hardlink")
                                elif scenario == "destination-rebound":
                                    self.displaced = destination.with_name("held-destination")
                                    destination.rename(self.displaced)
                                    destination.write_bytes(b"do not mutate this replacement")
                                elif scenario == "destination-parent-rebound":
                                    old_parent = destination.parent
                                    self.displaced = old_parent.with_name("held-parent") / destination.name
                                    old_parent.rename(self.displaced.parent)
                                    old_parent.mkdir(mode=0o700)
                                    destination.write_bytes(b"do not mutate this replacement")
                                elif scenario == "slot-parent-rebound":
                                    self.slot_displaced = slot_root.with_name("held-slot")
                                    slot_root.rename(self.slot_displaced)
                                    slot_root.mkdir(mode=0o700)
                                    slot.write_bytes(b"do not adopt this replacement")
                            else:
                                owner.assertEqual(slot.read_bytes(), self.expected_output)
                                if scenario == "verify-failure":
                                    raise operation_error
                                if scenario == "verify-replacement":
                                    pending = slot.with_name(slot.name + ".cstemp")
                                    pending.write_bytes(signed_image); pending.chmod(0o700)
                                    os.replace(pending, slot)
                                elif scenario == "late-verify":
                                    self.now = self.deadline - PREP.SETTLE_SECONDS
                                elif scenario == "cancel-verify":
                                    self.cancellation["cancelled"] = True
                            return {"stdout": b"", "stderr": b""}

                    engine = InertSigner()
                    original_scan = PREP.scan_tree
                    def scan_rebound(path, **kwargs):
                        # Replace only between the preceding held check and the
                        # terminal inventory. A fresh matching scan cannot adopt
                        # this new inode as the originally verified output.
                        self.assertEqual(Path(path), slot_root)
                        replacement = slot.with_name(slot.name + ".cstemp")
                        replacement.write_bytes(signed_image); replacement.chmod(0o700)
                        os.replace(replacement, slot)
                        return original_scan(path, **kwargs)
                    scan_guard = (mock.patch.object(PREP, "scan_tree", side_effect=scan_rebound)
                                  if scenario == "retirement-scan-rebound" else nullcontext())
                    # These are fixture-local finality books. Neither process
                    # uncertainty nor an injected close poisons the real module
                    # DATA original; every binding is restored by the same with.
                    # Tighten the byte bound for tiny DATA under the original
                    # 32MiB scratch. Capacity/FD/rename checks stay real; native
                    # preparation still uses its unchanged 256MiB FILE_LIMIT.
                    self.assertEqual(PREP.FILE_LIMIT, 256 * PREP.MIB)
                    with mock.patch.object(BUILD, "DATA", fixture_data), mock.patch.object(BUILD, "DataFinality", HeldOriginals), \
                            mock.patch.object(PREP, "FILE_LIMIT", 64 * 1024), scan_guard:
                        if scenario == "success":
                            PREP.sign_owned_image(engine, member, copied, 0, 1, "arm64", environment={},
                                                  root_custody=PREP.identity(preparation.lstat())[:5])
                        else:
                            with self.assertRaises(BaseException) as caught:
                                PREP.sign_owned_image(engine, member, copied, 0, 1, "arm64", environment={},
                                                      root_custody=PREP.identity(preparation.lstat())[:5])
                            if scenario in ("sign-failure", "verify-failure", "unknown-sign", "first-error-close"):
                                self.assertIs(caught.exception, operation_error)
                            elif scenario in ("output-constructor", "constructor-interrupt"):
                                self.assertIs(caught.exception, constructor_error)
                            elif scenario == "close-only":
                                self.assertIs(caught.exception, close_error)
                            else:
                                self.assertIsInstance(caught.exception, (PREP.PreparationRefused, FileExistsError))
                        self.assertEqual(len(books), 1)
                        self.assertCountEqual(books[0].closed, books[0].opened)
                        for fd in books[0].opened:
                            with self.assertRaises(OSError):
                                os.fstat(fd)
                        uncertain = scenario in ("unknown-sign", "output-constructor", "constructor-interrupt",
                                                  "first-error-close", "close-only")
                        self.assertEqual(fixture_data.known, not uncertain)
                        self.assertEqual(engine.known, not uncertain)
                        self.assertEqual(books[0].known, scenario not in
                                         ("output-constructor", "constructor-interrupt", "first-error-close", "close-only"))
                    self.assertIs(BUILD.DATA, actual_data)
                    self.assertIs(BUILD.DataFinality, finality_class)
                    self.assertEqual(PREP.FILE_LIMIT, 256 * PREP.MIB)
                    self.assertTrue(actual_data.known)
                    expected_calls = (0 if scenario in ("occupied-slot", "slot-symlink", "constructor-interrupt")
                                      else 1 if scenario in ("sign-failure", "unknown-sign", "first-error-close",
                                          "extra-output", "output-symlink", "output-hardlink", "output-constructor",
                                          "destination-rebound", "destination-parent-rebound", "slot-parent-rebound") else 2)
                    self.assertEqual(len(engine.calls), expected_calls)
                    committed = scenario in ("success", "close-only", "late-close", "retirement-scan-rebound")
                    held_destination = engine.displaced if engine.displaced is not None else destination
                    self.assertEqual(held_destination.read_bytes(), signed_image if committed else original_image)
                    self.assertEqual(PREP.identity(held_destination.lstat())[:6], destination_before[:6])
                    if engine.displaced is not None:
                        self.assertEqual(destination.read_bytes(), b"do not mutate this replacement")
                    else:
                        for name, before_row in nonimages.items():
                            path = framework / name
                            self.assertEqual(list(PREP.identity(path.lstat())), before_row["identity"])
                            if before_row["kind"] == "link":
                                self.assertEqual(os.readlink(path), before_row["target"])
                            else:
                                self.assertEqual(PREP.hashlib.sha256(path.read_bytes()).hexdigest(), before_row["sha256"])
                    if scenario == "success":
                        self.assertEqual(len(engine.calls), 2)
                        self.assertFalse(slot_root.exists() or slot_root.is_symlink())
                        self.assertEqual(list((preparation / "tmp").iterdir()), [])
                    elif scenario == "constructor-interrupt":
                        self.assertEqual(engine.calls, [])
                        self.assertFalse(slot_root.exists())
                    else:
                        self.assertTrue(slot_root.exists() or slot_root.is_symlink())
                    if scenario == "occupied-slot":
                        self.assertEqual(engine.calls, [])
                        self.assertEqual((slot_root / "keep").read_bytes(), b"never reuse an occupied signing slot")
                    if scenario == "slot-symlink":
                        self.assertEqual(engine.calls, [])
                        self.assertTrue(slot_root.is_symlink())
                    if engine.slot_displaced is not None:
                        self.assertEqual((engine.slot_displaced / "Tcl").read_bytes(), signed_image)
                        self.assertEqual(slot.read_bytes(), b"do not adopt this replacement")
                    self.assertEqual((untouched / "keep").read_bytes(), b"never select an outside original")
                    # The test TemporaryDirectory, not production retirement,
                    # owns disposal of these deliberately failed/unknown DATA
                    # fixtures. No uncertain case is ever re-admitted as known.
            self.assertEqual(PREP.scan_tree(signing_source, closure=True, deadline=deadline), signing_rows)
        self.assertIs(BUILD.DATA, actual_data)
        self.assertTrue(actual_data.known)
