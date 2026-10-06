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
    def __init__(self, *, returncode=0, interrupt=False, wait_error=False, close_error=False):
        self.returncode, self.interrupt, self.wait_error = returncode, interrupt, wait_error
        self.events, self.streams = [], []
        try:
            for body in (b"ordinary-output\n", b""):
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
        self.assertIs(BUILD.DATA, actual_data)
        self.assertTrue(actual_data.known)
