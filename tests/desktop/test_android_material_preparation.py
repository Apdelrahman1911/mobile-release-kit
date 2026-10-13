"""Inert DATA/mocked-command checks; no download, decoder, compiler or native run."""
from copy import deepcopy
from contextlib import contextmanager
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("android_material_preparation",
    SOURCE / "desktop/tools/android_material_preparation.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


def inert_files():
    return [{"path": name, "size": 1, "sha256": "a" * 64, "mode": 0o444}
            for name in ("jdk/a", "sdk/a")]


def inert_os():
    return {"schemaVersion": 1, "id": "inert-data-only", "closure": "python-jdk-sdk-gradle-shell-loader-v1",
            "files": [{"path": "/usr/bin/dash", "size": 1, "sha256": "b" * 64, "mode": 0o555}], "aliases": []}


def inert_context():
    return {"sourceCommit": "1" * 40, "sourceTree": "2" * 40, "runId": "17", "runAttempt": "2", "job": "inert"}


def inert_staging(root):
    owner = (os.getuid(), os.getgid())
    directories = {".": M._private(root, owner, directory=True, mode=0o700)[:5]}
    for name in ("tools", "tools/sdk"):
        M._staging_mkdir(root, name, directories, owner)
    return {"directories": directories, "originals": {}, "owner": owner}


def inert_font_consumers():
    # Text fixtures derived from the documented fc-cat/fccat framing only.
    # Never genuine native output, a cache body, or generation provenance.
    root = "/usr/share/fonts/truetype"
    directory = root + "/dejavu"
    font = directory + "/Inert.ttf"
    first = "/var/cache/fontconfig/" + hashlib.md5(root.encode()).hexdigest() + "-le64.cache-9"
    second = "/var/cache/fontconfig/" + hashlib.md5(directory.encode()).hexdigest() + "-le64.cache-9"
    roster = {first: {"directory": root, "subdirectories": [directory], "fonts": []},
              second: {"directory": directory, "subdirectories": [], "fonts": [font]}}
    report = (f'Directory: {root}\nCache: {first}\n--------\n"dejavu" 0 ".dir"\n\n'
              f'Directory: {directory}\nCache: {second}\n--------\n'
              '"Inert.ttf" 0 "Inert:familylang=en:style=Regular"\n').encode()
    return roster, report, font


SDK_TEST_LICENSE = "Inert selected SDK license definition; not terms or consent."


def inert_sdk_license(text):
    M.D.need(text == SDK_TEST_LICENSE, "inert selected licence definition differs")
    return {"id": "android-sdk-license", "normalizedSha1": M.LICENSE_HASH,
            "normalizedSha256": M.LICENSE_NORMALIZED_SHA256}


def inert_sdk_package(name):
    platform = name == "platforms;android-35"
    details = ('<type-details xsi:type="sdk:platformDetailsType"><api-level>35</api-level>'
               '<extension-level>13</extension-level><base-extension>true</base-extension>'
               '<layoutlib api="15"/></type-details>' if platform else
               '<type-details xsi:type="generic:genericDetailsType"/>')
    return (f'<common:repository xmlns:common="{M.COMMON_NAMESPACE}" xmlns:sdk="{M.SDK_NAMESPACE}" '
            f'xmlns:generic="{M.GENERIC_NAMESPACE}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<license id="android-sdk-license" type="text">{SDK_TEST_LICENSE}</license>'
            f'<localPackage path="{name}" obsolete="false">{details}'
            f'<revision><major>{2 if platform else 35}</major><minor>0</minor><micro>0</micro></revision>'
            f'<display-name>Android SDK {"Platform 35" if platform else "Build-Tools 35"}</display-name>'
            '<uses-license ref="android-sdk-license"/></localPackage></common:repository>').encode("ascii")


def inert_sdk_receipt():
    """Synthetic closed-reader DATA only; never a real hosted/licence receipt."""
    rule = {"path": M.SDK_RECEIPT, "classification": M.SDK_RECEIPT_CLASSIFICATION,
        "imagePath": M.SDK_IMAGE_DATA, "sourceRecipe": deepcopy(M.SDK_SOURCE_RECIPE),
        "licenseDefinition": {"id": "android-sdk-license", "normalizedSha1": M.LICENSE_HASH,
                              "normalizedSha256": M.LICENSE_NORMALIZED_SHA256},
        "packages": [{"id": name, **paths} for name, paths in M.SDK_PACKAGE_PATHS.items()]}
    paths = [M.SDK_RECEIPT, M.SDK_IMAGE_DATA,
             *(path for paths in M.SDK_PACKAGE_PATHS.values() for path in paths.values())]
    value = {"hostPolicy": {"inputs": {"files": sorted(paths),
                                    "directories": {}, "absences": []}, "generated": {"sdkLicense": rule}}}
    bodies = {M.SDK_RECEIPT: b"\n" + M.LICENSE_HASH.encode("ascii"), M.SDK_IMAGE_DATA: M.D.canonical([
        {"group": "Operating System", "detail": "Ubuntu\n24.04.5\nLTS"},
        {"group": "Runner Image", "detail": "\n".join(prefix + M.SDK_IMAGE[key] for prefix, key in (
            ("Image: ", "image_name"), ("Version: ", "image_version"),
               ("Included Software: ", "image_url"), ("Image Release: ", "image_release")))}])}
    for name, paths in M.SDK_PACKAGE_PATHS.items():
        bodies[paths["metadataPath"]] = inert_sdk_package(name)
        bodies[paths["propertiesPath"]] = "".join(f"{key}={value}\n" for key, value in M.SDK_PROPERTIES[name].items()).encode()
    host = {"graph": {}, "bindings": {"files": {name: {"fixture": name} for name in bodies}}}
    @contextmanager
    def reader(binding, selected, limit, deadline):
        assert binding == host["bindings"]["files"][selected] and len(bodies[selected]) <= limit
        raw = bodies[selected]
        # Exercise the real closed XML/property parsers without checking licence
        # text into the repository. Only the separate definition comparator is
        # a labelled fixture; this is not current-host or legal evidence.
        with patch.object(M, "_sdk_license_definition", side_effect=inert_sdk_license):
            yield raw, {"binding": deepcopy(binding), "identity": ["inert-original"],
                        "file": {"path": selected, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": 0o644}}
    return value, host, bodies, reader


def inert_font_stage(folder, fault=None):
    """Text-only native-owner stand-in. It never launches a program."""
    base = Path(folder)
    compiler, root = base / "compiler", base / "material"
    compiler.mkdir(mode=0o700)
    root.mkdir(mode=0o700)
    owner = (os.getuid(), os.getgid())
    directories = {".": M._private(root, owner, directory=True, mode=0o700)[:5]}
    for name in ("private", "home", "tmp"):
        M._staging_mkdir(root, name, directories, owner)
    paths = [f"/usr/share/fonts/truetype/dejavu/Fixture{i:03d}.ttf" for i in range(53)]
    roster, blocks = {}, []
    for directory in M.FONT_DIRECTORIES:
        cache = "/var/cache/fontconfig/" + hashlib.md5(directory.encode()).hexdigest() + "-le64.cache-9"
        children = sorted(path for path in M.FONT_DIRECTORIES if str(Path(path).parent) == directory)
        fonts = [path for path in paths if str(Path(path).parent) == directory]
        roster[cache] = {"directory": directory, "subdirectories": children, "fonts": fonts}
        lines = [f'Directory: {directory}', f'Cache: {cache}', '--------']
        lines += [f'"{Path(path).name}" 0 ".dir"' for path in children]
        lines += [f'"{Path(path).name}" 0 "Inert:style=Regular"' for path in fonts]
        blocks.append("\n".join(lines if children or fonts else [*lines, "<empty>"]))
    outputs = {"android-font-cache": ("\n\n".join(blocks) + "\n").encode(),
               "android-font-list": ("\n".join(paths) + "\n").encode()}
    state = {"roster": roster, "paths": paths, "configuration": {}, "files": {}, "directories": {}, "absences": {}}
    check = SimpleNamespace(root=compiler, end=time.monotonic() + 30, failed=False, private_roots={}, calls=[])
    def command(label, argv, env, cwd, *, timeout, limit):
        check.calls.append((label, argv, env, cwd, timeout, limit))
        capture = compiler / "private-material"
        if not capture.exists():
            capture.mkdir(mode=0o700)
            check.private_roots["material"] = M._private(capture, owner, directory=True, mode=0o700)[:5]
        stdout, stderr = outputs[label], b""
        if label == "android-font-cache":
            if fault == "stderr":
                stderr = b"inert failed cache load"
            elif fault == "partial":
                stdout = stdout.split(b"\n\n", 1)[0] + b"\n"
            elif fault == "private-output":
                M.D.write(root / "home/inert-unexpected", b"preserve", 0o400)
        request = {"phase": label, "argv": argv, "timeoutSeconds": timeout}
        captures = {}
        for suffix, raw in (("stdout", stdout), ("stderr", stderr)):
            pin = M.D.write(capture / (label + "." + suffix), raw)
            captures[suffix] = {k: pin[k] for k in ("size", "sha256")}
        M.D.write(capture / (label + ".request.json"), M.D.canonical(request))
        M.D.write(capture / (label + ".result.json"), M.D.canonical({**request, "exitCode": 0,
                  "ordinaryOwnerReturned": True, "captures": captures}))
        return SimpleNamespace(args=argv, returncode=0, stdout=stdout, stderr=stderr)
    check.private_command = command
    return check, root, owner, directories, state


class AndroidMaterialDataTests(unittest.TestCase):
    def test_finite_source_controls_preserve_exact_counts_without_private_paths(self):
        policy = M.policy()
        suppliers = M._control(policy, "suppliers.json")["files"]
        layout = M._control(policy, "layout.json.gz")
        archives = M._control(policy, "archives.json.gz")["archives"]
        self.assertEqual(len(suppliers), 401)
        self.assertEqual(sum(row["size"] for row in suppliers), 678706726)
        self.assertEqual(len({row["id"] for row in suppliers}), 401)
        self.assertEqual(len(layout["files"]), 12371)  # Original/ABI5 leaves plus fixed AGP aapt2 derivation.
        self.assertEqual([row["path"] for row in layout["generated"]], list(M.GENERATED))
        self.assertEqual(len(archives), 13)
        encoded = M.D.canonical([policy, suppliers, layout, archives])
        for forbidden in (b"/root/projects/", b'"identity":', b'"privateKey":', b'"authorization":'):
            self.assertNotIn(forbidden, encoded)
        bodies = {row["id"]: row for row in suppliers}
        for row in layout["files"]:
            self.assertIn(row["source"]["id"], bodies)
            M._tool_path(row["path"])
        notices = [row for row in layout["files"] if row["path"].endswith("ncurses5-COPYRIGHT.txt")]
        self.assertEqual(len(notices), 1)
        self.assertEqual(notices[0]["sha256"], "f0974fb41778e23c94111ff90da0546de8971f8270c58877283d372e6bd7f17e")
        fonts = M._control(policy, "fonts.json")
        self.assertEqual(len(fonts["fontFiles"]), 53)
        self.assertEqual(sum(fonts["files"][name]["size"] for name in fonts["fontFiles"]), 37255936)
        self.assertEqual(len(fonts["configurationFiles"]), 35)
        self.assertEqual(set(fonts["consumers"]), {"/usr/bin/fc-cat", "/usr/bin/fc-list"})
        for row in [*fonts["consumers"].values(), *fonts["providers"].values()]:
            self.assertLessEqual(set(row["elf"]["needed"]), set(fonts["providers"]))
            for name, nodes in row["elf"]["versionNeeds"].items():
                self.assertLessEqual(set(nodes), set(fonts["providers"][name]["elf"]["versionDefinitions"]))

    def test_changed_control_is_refused_before_decompression(self):
        policy = M.policy()
        with tempfile.TemporaryDirectory(prefix="mrk-android-inert-") as folder:
            root = Path(folder)
            (root / "layout.json.gz").write_bytes(b"changed")
            with patch.object(M, "DATA", root), self.assertRaises(M.D.Refused):
                M._control(policy, "layout.json.gz")

    def test_missing_host_policy_refuses_before_creating_or_downloading(self):
        context = inert_context()
        check = SimpleNamespace(end=time.monotonic() + 30, private_command=Mock(), failed=False)
        original = {"runnerUid": 123, "runnerGid": 456, "source": "/source", "root": "/inert/compiler", "deadline": str(check.end)}
        policy = M.policy()
        policy["hostPolicy"] = None  # Explicit absent input; not a permanent production-default assumption.
        with patch.object(M, "_context", return_value=original), patch.object(M.os, "getuid", return_value=123), \
             patch.object(M.os, "getgid", return_value=456), patch.object(M, "policy", return_value=policy), \
             patch.object(M.Path, "mkdir") as mkdir, \
             self.assertRaisesRegex(M.D.Refused, "not yet admitted"):
            M.prepare(check, Path("/source"), Path("/inert/mrk-android-material-17-2"), context=context, host={})
        mkdir.assert_not_called()
        check.private_command.assert_not_called()
        self.assertTrue(check.failed)
        with self.assertRaisesRegex(M.D.Refused, "failure is latched"):
            M.prepare(check, Path("/source"), Path("/inert/mrk-android-material-17-2"), context=context, host={})

    def test_context_rejects_cross_attempt_and_boolean_ids_without_reading_arbitrary_files(self):
        context = {**inert_context(), "preparation": {"path": "/inert/preparation.json", "size": 1, "sha256": "3" * 64}}
        for field, replacement in (("runAttempt", True), ("sourceTree", "x" * 40), ("job", "../../other")):
            changed = deepcopy(context)
            changed[field] = replacement
            with patch.object(M.D, "bound") as read, self.assertRaises(M.D.Refused):
                M._context(changed)
            read.assert_not_called()

    def test_actual_java_adapter_rule_preserves_paragraphs_and_ascii_semantics(self):
        self.assertEqual(M.sdk_license_value("\n   First   line\nwrapped.\n\n  Second paragraph. \n"),
                         "First line wrapped.\n\nSecond paragraph.")
        self.assertEqual(M.sdk_license_value(" \tvalue\u00a0  tail \n"), "value\u00a0 tail")
        self.assertEqual(M.sdk_license_value("First\t line"), "First\tline")

    def test_existing_receipt_bytes_are_preserved_and_never_created(self):
        # Synthetic normalization result isolates receipt framing. Not a real
        # licence fixture, an origin receipt or permission to use any SDK.
        text = "x" * 16960
        sha1 = Mock(return_value=SimpleNamespace(hexdigest=lambda: M.LICENSE_HASH))
        with patch.object(M, "sdk_license_value", return_value=text), \
             patch.object(M, "_sha", return_value=M.LICENSE_NORMALIZED_SHA256), patch.object(M.hashlib, "sha1", sha1):
            for raw in (("\n" + M.LICENSE_HASH).encode(), (M.LICENSE_HASH + "\n").encode()):
                self.assertIs(M.existing_license(raw, "inert"), raw)
            for raw in (b"", b"accepted", b"\n" + b"1" * 40, (M.LICENSE_HASH + "\n" + M.LICENSE_HASH).encode(),
                        (" " + M.LICENSE_HASH).encode()):
                with self.assertRaises(M.D.Refused):
                    M.existing_license(raw, "inert")

    def test_document_tuple_binds_one_source_attempt_and_full_combined_extent(self):
        policy, context = M.policy(), inert_context()
        raw, materials, publication = M._documents(policy, context, inert_files(), inert_os())
        self.assertEqual(materials["manifestSha256"], hashlib.sha256(raw["manifest"]).hexdigest())
        self.assertEqual(materials["osContractSha256"], hashlib.sha256(raw["osContract"]).hexdigest())
        self.assertEqual(json.loads(raw["sources"])["files"], [{"path": "jdk/a", "source": "jdk/a"},
                                                               {"path": "sdk/a", "source": "sdk/a"}])
        self.assertEqual(publication["totals"]["toolBytes"] + publication["totals"]["osBytes"], 3)
        changed = deepcopy(context)
        changed["runAttempt"] = "3"
        self.assertNotEqual(M._documents(policy, changed, inert_files(), inert_os())[1], materials)
        files = inert_files()
        for row in files:
            row["size"] = 512 << 20
        with self.assertRaisesRegex(M.D.Refused, r"tool\+OS byte bound"):
            M._documents(policy, context, files, inert_os())

    def test_real_public_serialization_has_no_private_path_or_unknown_payload(self):
        _, materials, publication = M._documents(M.policy(), inert_context(), inert_files(), inert_os())
        record = {"materials": materials, "publication": publication,
                  "materialRoot": "/private/DO-NOT-EXPORT", "provenance": {"caBody": "DO-NOT-EXPORT"}}
        projection = M.public_summary(record)
        self.assertNotIn(b"DO-NOT-EXPORT", M.D.canonical(projection))
        self.assertFalse(projection["qualification"])
        for target, key, value in (("materials", "rawLicense", "DO-NOT-EXPORT"),
                                   ("publication", "privateInputs", "/private/DO-NOT-EXPORT")):
            changed = deepcopy(record)
            changed[target][key] = value
            with self.assertRaises(M.D.Refused):
                M.public_summary(changed)

    def test_staged_tree_rejects_extra_files_aliases_and_changed_originals(self):
        owner = (os.getuid(), os.getgid())
        with tempfile.TemporaryDirectory(prefix="mrk-android-inert-") as folder:
            root = Path(folder)
            staging = inert_staging(root)
            path = root / "tools/sdk/inert.txt"
            rows = [{"path": "sdk/inert.txt", "size": 7, "sha256": hashlib.sha256(b"fixture").hexdigest(), "mode": 0o444}]
            M._member_output(io.BytesIO(b"fixture"), root, [{**rows[0], "sourceMode": 0o644}],
                             {**rows[0], "mode": 0o644}, time.monotonic() + 30, **staging)
            def tree():
                return M._tree(root, rows, owner, time.monotonic() + 30,
                               directories=staging["directories"], originals=staging["originals"])
            baseline = tree()
            self.assertEqual(len(baseline["files"]), 1)
            self.assertEqual(len(baseline["directories"]), 2)
            (root / "tools/sdk/foreign.txt").write_bytes(b"other")
            with self.assertRaises(M.D.Refused):
                tree()
            (root / "tools/sdk/foreign.txt").unlink()
            original = path.read_bytes()
            path.unlink()
            path.symlink_to("missing")
            with self.assertRaises(M.D.Refused):
                tree()
            path.unlink()
            M.D.write(path, original, 0o400)
            with self.assertRaisesRegex(M.D.Refused, "original created material leaf changed"):
                tree()

    def test_failed_member_copy_keeps_partial_owned_output_without_reporting_success(self):
        with tempfile.TemporaryDirectory(prefix="mrk-android-inert-") as folder:
            root = Path(folder)
            staging = inert_staging(root)
            row = {"path": "sdk/partial", "size": 7, "sha256": "0" * 64, "mode": 0o444, "sourceMode": 0o644}
            with self.assertRaisesRegex(M.D.Refused, "decoded member differs"):
                M._member_output(io.BytesIO(b"fixture"), root, [row], {**row, "mode": 0o644}, time.monotonic() + 30, **staging)
            self.assertEqual((root / "tools/sdk/partial").read_bytes(), b"fixture")
            self.assertFalse(staging["originals"])
            with self.assertRaises(FileExistsError):
                M._member_output(io.BytesIO(b"fixture"), root, [row], {**row, "mode": 0o644}, time.monotonic() + 30, **staging)

    def test_live_writer_or_ancestor_replacement_cannot_be_recensused_as_original(self):
        for replace_directory in (False, True):
            with self.subTest(directory=replace_directory), tempfile.TemporaryDirectory(prefix="mrk-android-inert-") as folder:
                root = Path(folder)
                staging = inert_staging(root)
                path = root / "tools/sdk/inert.txt"
                row = {"path": "sdk/inert.txt", "size": 7, "sha256": hashlib.sha256(b"fixture").hexdigest(),
                       "mode": 0o444, "sourceMode": 0o644}
                class ReplacingStream(io.BytesIO):
                    replaced = False
                    def read(self, limit):
                        if not self.replaced:
                            self.replaced = True
                            if replace_directory:
                                path.parent.rename(root / "tools/original-sdk")
                                path.parent.mkdir(mode=0o700)
                            else:
                                path.rename(root / "tools/sdk/original.txt")
                            # Deliberately identical final bytes/mode. A digest
                            # or final inventory alone would accept this copy.
                            M.D.write(path, b"fixture", 0o400)
                        return super().read(limit)
                with self.assertRaisesRegex(M.D.Refused, "writer/name changed|staging directory was replaced"):
                    M._member_output(ReplacingStream(b"fixture"), root, [row], {**row, "mode": 0o644},
                                     time.monotonic() + 30, **staging)
                self.assertFalse(staging["originals"])
                self.assertEqual(path.read_bytes(), b"fixture")  # Unrecognized replacement is preserved.

    def test_created_directory_replacement_before_staging_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="mrk-android-inert-") as folder:
            root = Path(folder)
            staging = inert_staging(root)
            (root / "tools/sdk").rename(root / "tools/original-sdk")
            (root / "tools/sdk").mkdir(mode=0o700)
            with self.assertRaisesRegex(M.D.Refused, "staging directory was replaced"):
                M._staging_mkdir(root, "tools/sdk/new", staging["directories"], staging["owner"])
            self.assertFalse((root / "tools/sdk/new").exists())

    def test_opened_descriptor_custody_survives_a_close_error(self):
        # Emulate an OS close that releases its descriptor and then reports an
        # error. Never retry that descriptor number; still close the successor.
        for during_fdopen in (False, True):
            with self.subTest(fdopen=during_fdopen), tempfile.TemporaryDirectory(prefix="mrk-android-inert-") as folder:
                root = Path(folder)
                staging = inert_staging(root)
                real_open, real_close = os.open, os.close
                live, failed_fdopen, failed_close = set(), False, False
                def tracked_open(*args, **kwargs):
                    fd = real_open(*args, **kwargs)
                    self.assertNotIn(fd, live)
                    live.add(fd)
                    return fd
                def tracked_close(fd):
                    nonlocal failed_close
                    self.assertIn(fd, live)
                    live.remove(fd)
                    real_close(fd)
                    if not failed_close and (failed_fdopen or not during_fdopen):
                        failed_close = True
                        raise OSError("inert close error after release")
                def refused_fdopen(*args, **kwargs):
                    nonlocal failed_fdopen
                    failed_fdopen = True
                    raise OSError("inert fdopen error")
                with patch.object(M.os, "open", side_effect=tracked_open), \
                     patch.object(M.os, "close", side_effect=tracked_close), \
                     patch.object(M.os, "fdopen", side_effect=refused_fdopen), self.assertRaises(OSError):
                    if during_fdopen:
                        row = {"path": "sdk/inert.txt", "size": 0, "sha256": hashlib.sha256(b"").hexdigest(),
                               "mode": 0o444, "sourceMode": 0o644}
                        M._member_output(io.BytesIO(b""), root, [row], {**row, "mode": 0o644},
                                         time.monotonic() + 30, **staging)
                    else:
                        M._staging_parent(root, "tools/sdk/inert.txt", staging["directories"], staging["owner"])
                self.assertTrue(failed_close)
                self.assertFalse(live)

    def test_font_consumers_join_cache_members_to_complete_full_paths(self):
        roster, report, font = inert_font_consumers()
        self.assertEqual(M._font_cache_report(report, roster), {"cacheFiles": 2, "fontFaces": 1})
        self.assertEqual(M._font_list_report((font + "\n").encode(), [font]), {"fontFiles": 1})
        empty_dir = "/usr/local/share/fonts"
        empty_cache = "/var/cache/fontconfig/" + hashlib.md5(empty_dir.encode()).hexdigest() + "-le64.cache-9"
        empty_report = f"Directory: {empty_dir}\nCache: {empty_cache}\n--------\n<empty>\n".encode()
        self.assertEqual(M._font_cache_report(empty_report, {
            empty_cache: {"directory": empty_dir, "subdirectories": [], "fonts": []}}),
            {"cacheFiles": 1, "fontFaces": 0})

    def test_font_cache_zero_exit_partial_extra_or_malformed_output_cannot_pass(self):
        roster, report, _ = inert_font_consumers()
        # fc-cat main returns0 even after a failed cache load. The complete
        # expected native-output contract, not exit0, must detect this omission.
        variants = [report.split(b"\n\n", 1)[0] + b"\n", report + report,
                    report.replace(b'"Inert.ttf"', b'"Other.ttf"'),
                    report.replace(b'"dejavu" 0 ".dir"', b'"../outside" 0 ".dir"'),
                    report.replace(b'"Inert.ttf" 0', b'"Inert.ttf" 7'),
                    report.replace(b'style=Regular"', b'style=Regular" trailing'),
                    report.replace(b'style=Regular', b'style=Regular\x00'),
                    report.replace(b"cache-9", b"cache-8"), b"x" * ((512 << 10) + 1)]
        for changed in variants:
            with self.subTest(extent=len(changed)), self.assertRaises(M.D.Refused):
                M._font_cache_report(changed, roster)

    def test_font_basename_report_is_not_full_path_authority(self):
        roster, report, font = inert_font_consumers()
        self.assertEqual(M._font_cache_report(report, roster)["fontFaces"], 1)
        # fc-cat's documented formatter strips the full file field. An equal
        # basename from any other directory cannot satisfy fc-list's contract.
        for raw in (b"/unrelated/Inert.ttf\n", (font + "\n" + font + "\n").encode(),
                    (font + ",/unrelated/Inert.ttf\n").encode(), font.encode(), b"", b"\x00\n"):
            with self.subTest(extent=len(raw)), self.assertRaises(M.D.Refused):
                M._font_list_report(raw, [font])

    def test_host_input_delta_preserves_originals_and_routes_structural_bindings(self):
        inputs = {"files": ["/inert/existing", "/inert/new"],
                  "directories": {"/inert/directory": []}, "absences": ["/inert/absent"]}
        policy = {"hostPolicy": {"inputs": inputs}}
        native = {"original": ["unchanged"]}
        bindings = {"files": {"/inert/existing": {"original": "existing", "size": 1}}, "privateSearch": {}}
        snapshot = deepcopy((native, bindings))
        bind = Mock(side_effect=lambda path, **options: {"selectedPath": str(path), "options": options, "size": 1})
        with patch.object(M, "policy", return_value=policy), patch.object(M, "_protected_binding") as file_check, \
             patch.object(M, "_protected_namespace") as namespace, patch.object(M, "_provider_host_inputs") as providers, \
             patch.object(M, "_sdk_receipt_state", return_value={"fixture": "unqualified"}) as receipts:
            host = M.android_host_inputs(native, bindings, bind_path=bind, deadline=time.monotonic() + 30)
        self.assertEqual(providers.call_count, 1)
        self.assertIs(providers.call_args.args[1], host)
        self.assertIs(receipts.call_args.args[1], host)
        self.assertEqual(host["graph"]["androidGenerated"], {"sdkLicense": {"fixture": "unqualified"}})
        self.assertEqual((native, bindings), snapshot)
        self.assertIsNot(host["graph"], native)
        self.assertIsNot(host["bindings"]["files"]["/inert/existing"], bindings["files"]["/inert/existing"])
        self.assertEqual([str(call.args[0]) for call in bind.call_args_list],
                         ["/inert/new", "/inert/directory", "/inert/absent"])
        self.assertEqual(bind.call_args_list[1].kwargs, {"directory_only": True})
        self.assertEqual(bind.call_args_list[2].kwargs, {"absent": True})
        self.assertEqual(file_check.call_count, 2)
        self.assertEqual(namespace.call_count, 2)
        with patch.object(M, "policy", return_value=policy), \
             patch.object(M, "_protected_binding", side_effect=M.D.Refused("original changed")), \
             self.assertRaisesRegex(M.D.Refused, "original changed"):
            M.android_host_inputs(native, bindings, bind_path=bind, deadline=time.monotonic() + 30)
        self.assertEqual((native, bindings), snapshot)

    def test_small_host_roles_limit_first_binding_and_existing_binding_before_hash(self):
        limits = {M.SDK_RECEIPT: 4096, M.SDK_IMAGE_DATA: 64 << 10, "/inert/tool": M.FILE_LIMIT,
                  **{paths["metadataPath"]: 32 << 10 for paths in M.SDK_PACKAGE_PATHS.values()},
                  **{paths["propertiesPath"]: 16 << 10 for paths in M.SDK_PACKAGE_PATHS.values()},
                  **{name: M.CONFIGURATION_LIMIT for name in (*M.NETWORK_ROLES, M.RESOLVER_CANONICAL)}}
        value = {"hostPolicy": {"inputs": {"files": sorted(limits), "directories": {}, "absences": []}}}
        bind = Mock(side_effect=lambda path, **options: {"size": 1})
        deadline = time.monotonic() + 30
        with patch.object(M, "policy", return_value=value), patch.object(M, "_protected_binding"), \
             patch.object(M, "_provider_host_inputs"), patch.object(M, "_sdk_receipt_state", return_value={}):
            M.android_host_inputs({}, {"files": {}}, bind_path=bind, deadline=deadline)
        self.assertEqual({str(call.args[0]): call.kwargs for call in bind.call_args_list},
                         {name: {"limit": limit} for name, limit in limits.items()})
        for name, limit in limits.items():
            value["hostPolicy"]["inputs"]["files"] = [name]
            bind.reset_mock()
            with self.subTest(role=name), patch.object(M, "policy", return_value=value), \
                 patch.object(M, "_protected_binding") as rehash, self.assertRaisesRegex(M.D.Refused, "role extent"):
                M.android_host_inputs({}, {"files": {name: {"size": limit + 1}}}, bind_path=bind, deadline=deadline)
            bind.assert_not_called()
            rehash.assert_not_called()
        # Direct readback callers share the bound before ancestry or file IO.
        binding = {"path": M.SDK_RECEIPT, "selectedPath": M.SDK_RECEIPT, "size": 4097,
                   "sha256": "0" * 64, "identity": [], "links": [], "ancestry": {}}
        with patch.object(M, "_protected_ancestry") as ancestry, patch.object(M.D, "bound") as rehash, \
             self.assertRaises(M.D.Refused):
            M._protected_binding(binding, M.SDK_RECEIPT)
        ancestry.assert_not_called()
        rehash.assert_not_called()

    def test_sdk_correspondence_never_supplies_historical_or_legal_authority(self):
        value, host, bodies, reader = inert_sdk_receipt()
        deadline = time.monotonic() + 30
        with patch.object(M, "_stock_host_original", side_effect=reader), patch.object(M, "_protected_binding"):
            proof = M._sdk_receipt_state(value, host, deadline)
            self.assertNotIn("receiptAuthority", proof)
            self.assertEqual(proof["classification"], "provider-preinstalled-sdk-current-use-v1")
            self.assertEqual(proof["currentUse"], "selected-preinstalled-sdk-no-install-v1")
            self.assertIs(proof["producerExecutionProven"], False)
            self.assertIs(proof["newConsent"], False)
            self.assertEqual(proof["sourceRecipe"], M.SDK_SOURCE_RECIPE)
            self.assertEqual(M._sdk_receipt_bytes(host, proof, deadline), bodies[M.SDK_RECEIPT])
            self.assertEqual(set(proof["packages"]), set(M.SDK_PACKAGE_PATHS))
            for name, paths in M.SDK_PACKAGE_PATHS.items():
                for role, key in (("metadata", "metadataPath"), ("properties", "propertiesPath")):
                    self.assertEqual(proof["packages"][name][role]["file"]["sha256"],
                                     hashlib.sha256(bodies[paths[key]]).hexdigest())
                    self.assertEqual(proof["packages"][name][role]["correspondence"]["package"], name)
            host["graph"]["androidGenerated"] = {"sdkLicense": proof}
            self.assertEqual(M._sdk_receipt_authority(value, host, deadline), proof)
            for change in ({"receiptAuthority": "approved"}, {"preExistingHostedImageReceipt": True}, {"newConsent": True}):
                host["graph"]["androidGenerated"]["sdkLicense"] = {**proof, **change}
                with self.assertRaisesRegex(M.D.Refused, "correspondence changed"):
                    M._sdk_receipt_authority(value, host, deadline)
        bind = Mock()
        with patch.object(M, "policy", return_value=value), self.assertRaises(M.D.Refused):
            M.android_host_inputs({"androidGenerated": {"sdkLicense": proof}}, {"files": {}}, bind_path=bind, deadline=deadline)
        bind.assert_not_called()

    def test_sdk_current_use_requires_every_original_and_rejects_changed_package_proofs(self):
        value, host, bodies, reader = inert_sdk_receipt()
        deadline = time.monotonic() + 30
        for missing in bodies:
            partial = deepcopy(host)
            del partial["bindings"]["files"][missing]
            with self.subTest(missing=missing), patch.object(M, "_stock_host_original") as original, \
                 patch.object(M.D, "write") as write, self.assertRaisesRegex(M.D.Refused, "originals are absent"):
                M._sdk_receipt_state(value, partial, deadline)
            original.assert_not_called()
            write.assert_not_called()
        with patch.object(M, "_stock_host_original", side_effect=reader), patch.object(M, "_protected_binding") as post:
            proof = M._sdk_receipt_state(value, host, deadline)
            self.assertEqual({call.args[1] for call in post.call_args_list}, set(bodies))
            host["graph"]["androidGenerated"] = {"sdkLicense": deepcopy(proof)}
            name = "platforms;android-35"
            host["graph"]["androidGenerated"]["sdkLicense"]["packages"][name]["metadata"]["file"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(M.D.Refused, "correspondence changed"):
                M._sdk_receipt_authority(value, host, deadline)
            host["graph"]["androidGenerated"] = {"sdkLicense": proof}
            bodies[M.SDK_PACKAGE_PATHS[name]["propertiesPath"]] = bodies[M.SDK_PACKAGE_PATHS[name]["propertiesPath"]].replace(
                b"AndroidVersion.ApiLevel=35", b"AndroidVersion.ApiLevel=34")
            with self.assertRaisesRegex(M.D.Refused, "source.properties disagree"):
                M._sdk_receipt_authority(value, host, deadline)

    def test_sdk_local_package_parser_binds_namespace_revision_and_licence_without_installation(self):
        name = "platforms;android-35"
        raw = inert_sdk_package(name)
        with patch.object(M, "_sdk_license_definition", side_effect=inert_sdk_license) as definition:
            observed = M._sdk_local_package(name, raw)
            self.assertEqual(observed["revision"], {"major": 2, "minor": 0, "micro": 0, "preview": 0})
            definition.assert_called_once_with(SDK_TEST_LICENSE)
            self.assertEqual(M._sdk_local_package(name, raw.replace(b"xmlns:sdk=", b"xmlns:renamed=")
                                                .replace(b'sdk:platformDetailsType', b'renamed:platformDetailsType')), observed)
            build = M._sdk_local_package("build-tools;35.0.0", inert_sdk_package("build-tools;35.0.0"))
            self.assertEqual(build["revision"]["major"], 35)
            changes = [raw.replace(b"platforms;android-35", b"platforms;android-34"),
                       b'<?xml version="1.0" encoding="UTF-16"?>' + raw,
                       raw.replace(b'<major>2</major>', b'<major>2</major><major>2</major>'),
                       raw.replace(b'<major>2</major>', b'<major>3</major>'),
                       raw.replace(b'<micro>0</micro>', b'<preview>1</preview>'),
                       raw.replace(b'<api-level>35</api-level>', b'<api-level>34</api-level>'),
                       raw.replace(b'layoutlib api="15"', b'layoutlib api="16"'),
                       raw.replace(b'sdk:platformDetailsType', b'generic:platformDetailsType'),
                       raw.replace(b'<type-details ', b'<type-details xmlns:sdk="urn:unselected" '),
                       raw.replace(f' xmlns:sdk="{M.SDK_NAMESPACE}"'.encode(), b'').replace(
                           b'<license ', f'<license xmlns:sdk="{M.SDK_NAMESPACE}" '.encode()),
                       raw.replace(b'obsolete="false"', b'obsolete="true"'),
                       raw.replace(b'<uses-license ref="android-sdk-license"/>', b'<uses-license ref="unselected"/>'),
                       raw.replace(b'</localPackage>', b'<dependencies/></localPackage>'),
                       raw.replace(b'</common:repository>', b'<localPackage path="platforms;android-35"/></common:repository>'),
                       raw.replace(SDK_TEST_LICENSE.encode(), b'Other inert definition')]
            for changed in changes:
                with self.subTest(changed=changed[:30]), self.assertRaises(M.D.Refused):
                    M._sdk_local_package(name, changed)
        for changed in (b"<!DOCTYPE test>" + raw, b"<!ENTITY local 'value'>" + raw,
                        raw.replace(b"<license ", b"\x00<license "), b"x" * ((32 << 10) + 1)):
            with self.subTest(declaration=changed[:24]), patch.object(M.ET, "iterparse") as parser, self.assertRaises(M.D.Refused):
                M._sdk_local_package(name, changed)
            parser.assert_not_called()
        # Real definition checks still reject fixture or substituted terms.
        with self.assertRaisesRegex(M.D.Refused, "pinned SDK licence definition"):
            M._sdk_license_definition(SDK_TEST_LICENSE)
        for changed in (b"Pkg.Revision=2\nPkg.Revision=2\n", b"Pkg.Revision=2\nPkg.Path=unselected\n",
                        b"Pkg.Revision=35.0.1\n", b"Pkg.Revision=35.0.0\n" + b"x" * (16 << 10)):
            with self.subTest(properties=changed[:40]), self.assertRaises(M.D.Refused):
                M._sdk_source_properties("build-tools;35.0.0", changed)

    def test_sdk_original_protection_close_image_and_deadline_fail_closed(self):
        value, host, bodies, reader = inert_sdk_receipt()
        deadline = time.monotonic() + 30
        with patch.object(M, "_stock_host_original", side_effect=M.D.Refused("inert file-ancestry")), \
             patch.object(M.D, "write") as write, self.assertRaisesRegex(M.D.Refused, "file-ancestry"):
            M._sdk_receipt_state(value, host, deadline)
        write.assert_not_called()
        @contextmanager
        def close_failed(*args):
            with reader(*args) as original:
                yield original
            raise OSError("inert original close failed")
        with patch.object(M, "_stock_host_original", side_effect=reader), patch.object(M, "_protected_binding"):
            proof = M._sdk_receipt_state(value, host, deadline)
        with patch.object(M, "_stock_host_original", side_effect=close_failed):
            with self.assertRaisesRegex(OSError, "close failed"):
                M._sdk_receipt_state(value, host, deadline)
            with self.assertRaisesRegex(OSError, "close failed"):
                M._sdk_receipt_bytes(host, proof, deadline)
        with patch.object(M, "_stock_host_original", side_effect=reader), \
             patch.object(M, "_protected_binding", side_effect=M.D.Refused("inert original changed")), \
             self.assertRaisesRegex(M.D.Refused, "original changed"):
            M._sdk_receipt_state(value, host, deadline)
        wrong_image = bodies[M.SDK_IMAGE_DATA].replace(b"20260920.314.1", b"20260920.315.1")
        with self.assertRaises(M.D.Refused):
            M._sdk_image_identity(wrong_image)
        with patch.object(M, "_stock_host_original") as original, self.assertRaises(M.D.Refused):
            M._sdk_receipt_state(value, host, time.monotonic() - 1)
        original.assert_not_called()

    def test_sdk_staged_copy_requires_actual_private_mode_and_original_identity(self):
        with tempfile.TemporaryDirectory(prefix="mrk-android-receipt-inert-") as folder:
            root, owner = Path(folder), (os.getuid(), os.getgid())
            for name in ("tools", "tools/sdk", "tools/sdk/licenses"):
                (root / name).mkdir(mode=0o700)
            path, raw = root / "tools" / M.GENERATED[2], b"\n" + M.LICENSE_HASH.encode("ascii")
            M.D.write(path, raw, 0o400)
            identity = M._private(path, owner)
            row = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": 0o444}
            deadline = time.monotonic() + 30
            M._sdk_staged_receipt(root, owner, row, identity, raw, deadline)
            path.chmod(0o444)  # A publication mode is not private staging custody.
            with self.assertRaises(M.D.Refused):
                M._sdk_staged_receipt(root, owner, row, identity, raw, deadline)
            path.chmod(0o400)
            identity = M._private(path, owner)
            path.rename(path.with_name("inert-original"))
            M.D.write(path, raw, 0o400)
            with self.assertRaises(M.D.Refused):
                M._sdk_staged_receipt(root, owner, row, identity, raw, deadline)

    def test_network_configuration_rules_are_closed_and_not_github_negative_timing(self):
        deadline = time.monotonic() + 30
        self.assertEqual(M._network_configuration_data("/etc/nsswitch.conf", b"passwd: files\nhosts: files dns\n", deadline),
                         {"databases": {"passwd": ["files"], "hosts": ["files", "dns"]}})
        self.assertEqual(M._network_configuration_data("/etc/host.conf", b"# ordinary\nmulti on\n", deadline), {"multi": True})
        self.assertEqual(M._network_configuration_data("/etc/gai.conf", b"# defaults\n", deadline), {"defaults": True})
        hosts_raw = b"127.0.0.1 localhost\n::1 localhost ip6-localhost\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n"
        self.assertEqual(len(M._network_configuration_data("/etc/hosts", hosts_raw, deadline)["records"]), 4)
        actual = M._network_configuration_data("/etc/resolv.conf",
            b"# default resolver\n; whole-line comment\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n", deadline)
        self.assertEqual(actual, {"nameservers": ["127.0.0.53"], "search": ["."], "options": {
            "timeout": 5, "attempts": 2, "ndots": 1, "edns0": True, "trust-ad": True}})
        self.assertLess(actual["options"]["timeout"] * actual["options"]["attempts"], 12)
        variants = [("/etc/nsswitch.conf", b"hosts: files resolve dns\n"),
                    ("/etc/nsswitch.conf", b"hosts: files [NOTFOUND=return] dns\n"),
                    ("/etc/nsswitch.conf", b"hosts: files dns\nhosts: files dns\n"),
                    ("/etc/host.conf", b"multi on\ntrim .example\n"),
                    ("/etc/gai.conf", b"precedence ::ffff:0:0/96 100\n"),
                    ("/etc/hosts", b"127.0.0.1 localhost\n127.0.0.2 localhost\n"),
                    ("/etc/resolv.conf", b"nameserver 127.0.0.53\noptions timeout:1 timeout:2\n"),
                    ("/etc/resolv.conf", b"nameserver 127.0.0.53\noptions attempts:99\n"),
                    ("/etc/resolv.conf", b"nameserver fe80::1%eth0\n"),
                    ("/etc/resolv.conf", b"nameserver ff02::1\n"),
                    ("/etc/resolv.conf", b"nameserver 127.0.0.53\nsearch example..test\n"),
                    ("/etc/resolv.conf", b"# comment\rnameserver 127.0.0.53\n"),
                    ("/etc/nsswitch.conf", b"# comment\rhosts: files dns\n"),
                    ("/etc/resolv.conf", b"nameserver 127.0.0.53\r\n"),
                    ("/etc/resolv.conf", b" nameserver 127.0.0.53\n"),
                    ("/etc/resolv.conf", b"nameserver 127.0.0.53\nsearch example.test # inline\n"),
                    ("/etc/resolv.conf", b"nameserver 127.0.0.53\nsearch example.test;inline\n"),
                    ("/etc/gai.conf", b"#\0\n"), ("/etc/gai.conf", b"\xff"), ("/etc/gai.conf", b""),
                    ("/etc/gai.conf", b"#\n" * 2049), ("/etc/gai.conf", b"#" * (M.CONFIGURATION_LIMIT + 1))]
        for role, raw in variants:
            with self.subTest(role=role, bytes=len(raw)), self.assertRaises(M.D.Refused):
                M._network_configuration_data(role, raw, deadline)
        from urllib.parse import urlsplit
        hosts = {urlsplit(row["url"]).hostname for row in M._control(M.policy(), "suppliers.json")["files"]}
        for name in hosts | {"services.gradle.org", "downloads.gradle.org", "release-assets.githubusercontent.com"}:
            with self.subTest(host=name), self.assertRaises(M.D.Refused):
                M._network_configuration_data("/etc/hosts", ("127.0.0.1 " + name.upper() + ".\n").encode("ascii"), deadline)

    def test_network_source_rule_rechecks_exact_selected_canonical_and_close(self):
        role, name, raw = "/etc/resolv.conf", M.RESOLVER_CANONICAL, b"nameserver 127.0.0.53\n"
        deadline = time.monotonic() + 30
        aliases = [{"path": role, "target": "../run/systemd/resolve/stub-resolv.conf", "canonical": name}]
        value = {"hostPolicy": {"inputs": {"files": sorted([role, name]), "directories": {}, "absences": []}, "aliases": aliases}}
        host = {"bindings": {"files": {path: {"identity": ["inert-original"]} for path in (role, name)}}}
        row = {"path": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": 0o644}
        rule = {"path": name, "origin": {"kind": "same-vm", "rule": "network-config", "role": role,
                "configuration": M._network_configuration_data(role, raw, deadline)}}
        @contextmanager
        def reader(*args):
            self.assertEqual(args[1], role)
            yield raw, {"binding": {"identity": ["inert-original"]}, "file": row}
        @contextmanager
        def close_failed(*args):
            with reader(*args) as original:
                yield original
            raise OSError("inert original close failed")
        with patch.object(M, "_stock_host_original", side_effect=reader), patch.object(M, "_protected_binding") as recheck, \
             patch.object(M.os, "readlink", return_value=aliases[0]["target"]):
            result = M._network_configuration(value, host, rule, row, deadline)
            self.assertEqual(result["configuration"], rule["origin"]["configuration"])
            recheck.assert_called_once_with(host["bindings"]["files"][name], name)
            changed = deepcopy(rule); changed["origin"]["configuration"]["options"]["timeout"] = 12
            with self.assertRaisesRegex(M.D.Refused, "source rule"):
                M._network_configuration(value, host, changed, row, deadline)
            host["bindings"]["files"][name]["identity"] = ["inert-replacement"]
            with self.assertRaisesRegex(M.D.Refused, "originals differ"):
                M._network_configuration(value, host, rule, row, deadline)
            host["bindings"]["files"][name]["identity"] = ["inert-original"]
            with patch.object(M, "_stock_host_original", side_effect=close_failed), self.assertRaisesRegex(OSError, "close failed"):
                M._network_configuration(value, host, rule, row, deadline)
            aliases[0]["target"] = "/run/systemd/resolve/other.conf"
            with self.assertRaisesRegex(M.D.Refused, "fixed target"):
                M._network_configuration(value, host, rule, row, deadline)

    def test_font_configuration_closes_system_local_and_private_selectors(self):
        names = ["/etc/fonts/fonts.conf", "/etc/fonts/conf.d/50-user.conf", "/etc/fonts/conf.d/51-local.conf"]
        bodies = {names[0]: b'<fontconfig><dir>/usr/share/fonts</dir><dir>/usr/local/share/fonts</dir>'
                  b'<dir prefix="xdg">fonts</dir><dir>~/.fonts</dir><cachedir>/var/cache/fontconfig</cachedir>'
                  b'<cachedir prefix="xdg">fontconfig</cachedir><include ignore_missing="yes">conf.d</include></fontconfig>',
                  names[1]: b'<fontconfig><include prefix="xdg" ignore_missing="yes">fontconfig/fonts.conf</include></fontconfig>',
                  names[2]: b'<fontconfig><include ignore_missing="yes">local.conf</include></fontconfig>'}
        host = {"bindings": {"files": {name: {"path": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                                      for name, raw in bodies.items()}}}
        inputs = {"files": names, "directories": {"/etc/fonts/conf.d": ["50-user.conf", "51-local.conf", "README"]},
                  "absences": ["/etc/fonts/local.conf"]}
        with patch.object(M, "_protected_binding", side_effect=lambda row, _: row), \
             patch.object(M.D, "read", side_effect=lambda path, _: bodies[str(path)]):
            result = M._font_configuration(host, inputs, {"configurationFiles": sorted(names)}, time.monotonic() + 30)
            self.assertEqual(set(result), set(names))
            for altered in (b'<fontconfig><dir>/unrelated</dir></fontconfig>',
                            b'<fontconfig><include prefix="xdg">fontconfig/fonts.conf</include></fontconfig>',
                            b'<fontconfig><include ignore_missing="yes">../../outside</include></fontconfig>',
                            b'<fontconfig><remap-dir as-path="/usr/share/fonts">/other</remap-dir></fontconfig>'):
                bodies[names[1]] = altered
                host["bindings"]["files"][names[1]].update(size=len(altered), sha256=hashlib.sha256(altered).hexdigest())
                with self.subTest(body=altered), self.assertRaises(M.D.Refused):
                    M._font_configuration(host, inputs, {"configurationFiles": sorted(names)}, time.monotonic() + 30)

    def test_font_owner_flow_is_bounded_private_and_command_free_on_readback(self):
        with tempfile.TemporaryDirectory(prefix="mrk-android-font-inert-") as folder:
            check, root, owner, directories, state = inert_font_stage(folder)
            with patch.object(M, "_font_state", return_value=state), patch.object(M, "_host_state", return_value=("inert", {})):
                proof = M._font_consumers(check, {}, {}, root, owner, directories)
                self.assertFalse(check.failed)
                self.assertFalse(proof["generationProvenance"])
                self.assertEqual(proof["counts"], {"cacheFiles": 7, "fontFiles": 53, "fontFaces": 53})
                self.assertEqual(len(check.calls), 2)
                for label, argv, env, cwd, timeout, limit in check.calls:
                    self.assertEqual(timeout, 15)
                    self.assertEqual(cwd, root)
                    self.assertEqual(set(env), {"PATH", "LANG", "LC_ALL", "TZ", "HOME", "TMPDIR", "XDG_RUNTIME_DIR",
                                               "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"})
                    self.assertEqual(env["LC_ALL"], "C.UTF-8")
                    self.assertLessEqual(limit, 512 << 10)
                M._font_readback({}, {}, root, owner, directories, check.root, proof, check.end)
                self.assertEqual(len(check.calls), 2)
                path = root / "private/font-cache.stdout"
                raw = path.read_bytes()
                path.rename(path.with_name("original-font-cache.stdout"))
                M.D.write(path, raw, 0o400)
                with self.assertRaisesRegex(M.D.Refused, "font output original"):
                    M._font_readback({}, {}, root, owner, directories, check.root, proof, check.end)

    def test_font_failure_latches_before_second_consumer_and_preserves_outputs(self):
        for fault in ("stderr", "partial", "private-output", "changed-input", "late"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="mrk-android-font-inert-") as folder:
                check, root, owner, directories, state = inert_font_stage(folder, fault)
                reads, clock = [], [time.monotonic()]
                def font_state(*args):
                    reads.append(None)
                    return {**state, "configuration": {"changed": []}} if fault == "changed-input" and len(reads) > 1 else state
                original_command = check.private_command
                def command(*args, **kwargs):
                    result = original_command(*args, **kwargs)
                    if fault == "late":
                        clock[0] = check.end + 1
                    return result
                check.private_command = command
                with patch.object(M, "_font_state", side_effect=font_state), \
                     patch.object(M, "_host_state", return_value=("inert", {})), \
                     patch.object(M.time, "monotonic", side_effect=lambda: clock[0]):
                    with self.assertRaises(M.D.Refused):
                        M._font_consumers(check, {}, {}, root, owner, directories)
                    self.assertTrue(check.failed)
                    self.assertEqual(len(check.calls), 1)
                    with self.assertRaisesRegex(M.D.Refused, "failure is latched"):
                        M._font_consumers(check, {}, {}, root, owner, directories)
                    self.assertEqual(len(check.calls), 1)
                self.assertTrue((check.root / "private-material/android-font-cache.stdout").exists())
                if fault == "partial":
                    self.assertTrue((root / "private/font-cache.stdout").exists())
                if fault == "private-output":
                    self.assertEqual((root / "home/inert-unexpected").read_bytes(), b"preserve")

    def test_expired_endpoint_and_case_collision_refuse(self):
        with self.assertRaises(M.D.Refused):
            M._point(time.monotonic() - 1)
        for names in (("sdk/File", "sdk/file"), ("sdk/a", "sdk/a/file")):
            with self.assertRaises(M.D.Refused):
                M._parents(names)

    def test_closed_namespace_refuses_unaccounted_temporary_output_without_removal(self):
        owner = (os.getuid(), os.getgid())
        with tempfile.TemporaryDirectory(prefix="mrk-android-inert-") as folder:
            root = Path(folder)
            for name in ("private", "bodies", "decoded", "home", "tmp", "empty-capath", "tools"):
                (root / name).mkdir(mode=0o700)
            for name, _ in M.DOCS.values():
                M.D.write(root / name, b"", 0o400)
            for name in ({key + ".json" for key in M.PRIVATE_DOCS} | set(M.AUXILIARY) | {"prepared.json"}):
                M.D.write(root / "private" / name, b"", 0o400)
            M._closed_namespace(root, owner, time.monotonic() + 30)
            unknown = root / "tmp/unknown-partial"
            M.D.write(unknown, b"preserve", 0o400)
            with self.assertRaisesRegex(M.D.Refused, "unaccounted auxiliary output"):
                M._closed_namespace(root, owner, time.monotonic() + 30)
            self.assertEqual(unknown.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
