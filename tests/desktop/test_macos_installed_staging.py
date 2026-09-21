"""Focused DATA parser definitions; never a native install/GUI qualification.

These tests do not import the core, stage/extract M, launch Python/app children,
write an installation, construct a panel, or fabricate an operation permit.
"""
import importlib.util
from pathlib import Path
import stat
import struct
import sys
import unittest

TOOL = None
if sys.platform in ("darwin", "linux"):
    path = Path(__file__).absolute().parents[2] / "desktop/tools/stage_macos_installed.py"
    spec = importlib.util.spec_from_file_location("macos_installed_staging_data", path)
    TOOL = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(TOOL)


def odc(name, mode, body=b"", *, uid=0, gid=0, links=1):
    encoded = name.encode("ascii") + b"\0"
    header = b"070707" + ("%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o" %
        (0, 1, mode, uid, gid, links, 0, 0, len(encoded), len(body))).encode("ascii")
    return header + encoded + body


def original_result(expected, *, stage=".install-" + "d" * 32):
    reason, runtime, app, state, verified, _exit = expected
    return {"schemaVersion": 1, "state": state, "reason": reason, "release": TOOL.RELEASE,
            "runtimePublication": runtime, "appPublication": app, "staging": stage, "payloadVerified": verified,
            "payloadWritersSettled": True, "originalsSettled": True, "deadlineMetAfterFinalCloses": True, "createdAncestors": [],
            "cleanup": "original-closes-only-no-deletion", "sourceCommit": "a" * 40, "inventorySha256": "b" * 64, "runtimeManifestSha256": "c" * 64}


def reported_fixture_data():
    # Inert serialized DATA, never a native observation or root test runner.
    rows = []
    for name, expected in TOOL.FIXTURE_CASES.items():
        stage = None if name in ("occupied-app", "occupied-release") else ".install-" + "d" * 32
        point = {"prepublication-persistence-report": "payload-file-before-any-publication",
                 "postruntime-persistence-report": "stage-directory-after-runtime-rename"}.get(name)
        identity = {"device": 1, "inode": 42, "mode": 0o444, "uid": 0, "gid": 0, "links": 1, "size": len(TOOL.FIXTURE_MARKER),
                    "mtimeSeconds": 1, "mtimeNanoseconds": 0, "ctimeSeconds": 1, "ctimeNanoseconds": 0}
        witness = {"visibleRelativePath": TOOL.visible_occupant(name), "sha256": TOOL.digest(TOOL.FIXTURE_MARKER),
                   "before": dict(identity), "after": dict(identity), "verifiedByOriginalInstaller": True}
        persistence = {"point": point, "actualNativeSucceeded": True, "actualNativeErrno": None, "injectedReportedFailure": True}
        rows.append({"case": name, "passed": True, "proofError": None, "originalResult": original_result(expected, stage=stage), "originalExit": expected[-1],
                     "occupant": witness if point is None else None, "persistence": persistence if point is not None else None,
                     "absenceObservedBeforeCollision": name in ("runtime-publication-collision", "staging-file-collision", "first-publication-second-refusal"),
                     "stagingOpenErrno": 17 if name == "staging-file-collision" else None})
    return {"schemaVersion": 1, "sourceCommit": "a" * 40, "inventorySha256": "b" * 64, "runtimeManifestSha256": "c" * 64,
            "fixtureBase": TOOL.FIXTURE_PREFIX + "a" * 12 + "-" + "e" * 32, "setupError": None, "setupOriginalsSettled": True,
            "setupDeadlineMet": True, "inertCloseDeadlinePolicyTable": True, "fixedCasesComplete": True, "passed": True, "cases": rows,
            "genuineConcurrentRaceObserved": False, "nativeCloseFailureInjected": False, "applicationLaunched": False, "guiSaveQualified": False,
            "qualification": "native-installer-collisions-and-injected-policy-only"}


@unittest.skipUnless(TOOL is not None, "Darwin/POSIX DATA tool only")
class MacInstalledData(unittest.TestCase):
    def test_portable_names_and_complete_directory_identity(self):
        for name in ("python/lib/python3.14/encodings/utf_8.py", "app/Contents/_CodeSignature/CodeResources"):
            self.assertTrue(TOOL.safe_path(name))
        for name in ("../x", "a//b", "a/./b", "/root", "a\\b", "NUL.txt", "CON", "x.", "x ", "é.py"):
            self.assertFalse(TOOL.safe_path(name))
        self.assertEqual(TOOL.directories({"a/b": None}), {"a"})
        for files in ({"a": None, "a/b": None}, {"a/B": None, "a/b": None}):
            with self.assertRaises(TOOL.Refused):
                TOOL.directories(files)

    def test_json_rejects_duplicates_and_nonfinite_constants(self):
        self.assertEqual(TOOL.decode(b'{"a":[1,true,null]}'), {"a": [1, True, None]})
        for body in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.assertRaises(TOOL.Refused):
                TOOL.decode(body)

    def test_manifest_digest_and_original_roster_are_separate_checks(self):
        files = [{"path": name, "sha256": "1" * 64, "size": 1} for name in sorted(TOOL.BOOTSTRAPS | {"core.zip", "github-ca.pem", "python/bin/python3"})]
        manifest = {"schemaVersion": 1, "protocol": 1, "coreVersion": "DATA-only", "target": "aarch64-apple-darwin",
                    "coreSha256": "1" * 64, "protocolSha256": TOOL.PROTOCOL,
                    "inventorySha256": TOOL.digest(TOOL.canonical(files)), "files": files}
        encoded = TOOL.canonical(manifest) + b"\n"
        value, rows = TOOL.manifest_files(encoded, TOOL.digest(encoded))
        self.assertEqual(set(rows), {row["path"] for row in files})
        with self.assertRaises(TOOL.Refused):
            TOOL.manifest_files(encoded, "0" * 64)
        manifest["files"] = list(reversed(files))
        manifest["inventorySha256"] = TOOL.digest(TOOL.canonical(manifest["files"]))
        encoded = TOOL.canonical(manifest)
        with self.assertRaises(TOOL.Refused):
            TOOL.manifest_files(encoded, TOOL.digest(encoded))

    def test_scripts_cpio_is_root_owned_exact_data_not_extracted(self):
        end = odc("TRAILER!!!", 0)
        body = odc(".", stat.S_IFDIR | 0o755) + odc("./input", stat.S_IFDIR | 0o555)
        body += odc("./input/manifest.json", stat.S_IFREG | 0o444, b"{}") + end
        self.assertEqual(TOOL.cpio_members(body), {"input": (None, 0o555), "input/manifest.json": (b"{}", 0o444)})
        bad = [odc("x", stat.S_IFREG | 0o444, b"x", uid=501), odc("x", stat.S_IFREG | 0o444, b"x", links=2),
               odc("x", stat.S_IFLNK | 0o777, b"target"), odc("../x", stat.S_IFREG | 0o444), odc("x", stat.S_IFREG | 0o644)]
        for entry in bad:
            with self.assertRaises(TOOL.Refused):
                TOOL.cpio_members(entry + end)
        with self.assertRaises(TOOL.Refused):
            TOOL.cpio_members(odc("x", stat.S_IFREG | 0o444) * 2 + end)

    def test_macho_header_data_refuses_an_unreviewed_target_or_minimum(self):
        header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
        build = struct.pack("<6I", 0x32, 24, 1, 26 << 16, 26 << 16, 0)
        TOOL.macho(header + build)
        for body in (b"\0" * 56, header + struct.pack("<6I", 0x32, 24, 1, 25 << 16, 26 << 16, 0), header + build[:-1]):
            with self.assertRaises(TOOL.Refused):
                TOOL.macho(body)

    def test_archive_pins_are_the_existing_M_not_new_interpreter_inputs(self):
        self.assertEqual(TOOL.ZIP_SHA, "42a6abab90f9641ba1b8c4aa9bb4202b153d676cc6d135b8227d8690e18275be")
        self.assertEqual(TOOL.TAR_SHA, "c927caedfc5a40290da443989534e85bfdf192934f4650c3747a70c53f68d35a")
        self.assertEqual(TOOL.ORIGINAL_MANIFEST, "7e0b042c82ff567ccfa156974118911e2ba159dbe45020344aaf4d71a28acc44")
        self.assertEqual(set(TOOL.NOTICES), {"21-LLVM-header-license.txt", "22-macOS-SDK-libffi-header-notices.txt"})

    def test_fixed_package_kind_rejects_wrong_identifier_payload_or_extra_hook(self):
        for fixture in (False, True):
            identifier = "dev.mobile-release-kit.desktop.installed" + ("-fixture" if fixture else "")
            body = (f'<pkg-info identifier="{identifier}" version="0.1.0" install-location="/" auth="root">'
                    '<payload numberOfFiles="0"/><scripts><postinstall file="./postinstall"/></scripts></pkg-info>').encode()
            self.assertEqual(TOOL.package_info(body, fixture=fixture), identifier)
            with self.assertRaises(TOOL.Refused):
                TOOL.package_info(body, fixture=not fixture)
            for changed in (body.replace(identifier.encode(), b"arbitrary.package"), body.replace(b'numberOfFiles="0"', b'numberOfFiles="1"'),
                            body.replace(b'</scripts>', b'<preinstall file="other"/></scripts>')):
                with self.assertRaises(TOOL.Refused):
                    TOOL.package_info(changed, fixture=fixture)
        with self.assertRaises(TOOL.Refused):
            TOOL.package_info(body, fixture="arbitrary")

    def test_original_result_requires_bound_timely_final_closes(self):
        expected = (None, "confirmed", "confirmed", "installed", True, 0)
        result = original_result(expected)
        TOOL.bound_original_result(result, expected, "a" * 40, "b" * 64, "c" * 64)
        for key, value in (("deadlineMetAfterFinalCloses", False), ("originalsSettled", False), ("payloadWritersSettled", False),
                           ("reason", "deadline"), ("state", "unknown-retained"), ("sourceCommit", "f" * 40), ("schemaVersion", True), ("extra", True)):
            with self.subTest(key=key), self.assertRaises(TOOL.Refused):
                TOOL.bound_original_result({**result, key: value}, expected, "a" * 40, "b" * 64, "c" * 64)

    def test_fixture_result_exact_seven_cases_never_promotes_actual_uncertainty(self):
        self.assertEqual(tuple(TOOL.FIXTURE_CASES), ("occupied-app", "occupied-release", "runtime-publication-collision", "staging-file-collision",
                         "first-publication-second-refusal", "prepublication-persistence-report", "postruntime-persistence-report"))
        marker = b"MRK_MACOS_INSTALL_FIXTURE_RESULT="
        good = reported_fixture_data()
        log = marker + TOOL.canonical(good) + b"\n"
        self.assertEqual(TOOL.fixture_record(log, "a" * 40, "b" * 64, "c" * 64), good)
        mutations = [(("sourceCommit",), "f" * 40), (("fixtureBase",), "/tmp/arbitrary"),
                     (("fixtureBase",), TOOL.FIXTURE_PREFIX + "f" * 12 + "-" + "e" * 32),
                     (("cases",), good["cases"][:-1]), (("cases",), list(reversed(good["cases"]))),
                     (("nativeCloseFailureInjected",), True), (("genuineConcurrentRaceObserved",), True),
                     (("cases", 2, "originalResult", "runtimePublication"), "unknown"), (("cases", 3, "stagingOpenErrno"), 5),
                     (("cases", 5, "persistence", "actualNativeSucceeded"), False), (("cases", 6, "persistence", "actualNativeErrno"), 5),
                     (("cases", 6, "persistence", "injectedReportedFailure"), False), (("cases", 4, "originalResult", "originalsSettled"), False),
                     (("cases", 4, "originalResult", "deadlineMetAfterFinalCloses"), False), (("cases", 0, "occupant", "after", "inode"), 43),
                     (("cases", 0, "occupant", "visibleRelativePath"), "../../arbitrary"), (("cases", 0, "occupant", "after", "links"), True), (("extra",), True)]
        for path, value in mutations:
            changed = TOOL.decode(TOOL.canonical(good))
            cursor = changed
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(TOOL.Refused):
                TOOL.fixture_record(marker + TOOL.canonical(changed), "a" * 40, "b" * 64, "c" * 64)
        for changed in (log + log, b"MRK_MACOS_INSTALL_RESULT={}\n" + log):
            with self.assertRaises(TOOL.Refused):
                TOOL.fixture_record(changed, "a" * 40, "b" * 64, "c" * 64)


if __name__ == "__main__":
    unittest.main()
