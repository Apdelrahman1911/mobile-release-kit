"""Inert DATA/mocked-command checks; no download, decoder, compiler or native run."""
from copy import deepcopy
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
        bindings = {"files": {"/inert/existing": {"original": "existing"}}, "privateSearch": {}}
        snapshot = deepcopy((native, bindings))
        bind = Mock(side_effect=lambda path, **options: {"selectedPath": str(path), "options": options})
        with patch.object(M, "policy", return_value=policy), patch.object(M, "_protected_binding") as file_check, \
             patch.object(M, "_protected_namespace") as namespace, patch.object(M, "_provider_host_inputs") as providers:
            host = M.android_host_inputs(native, bindings, bind_path=bind, deadline=time.monotonic() + 30)
        self.assertEqual(providers.call_count, 1)
        self.assertIs(providers.call_args.args[1], host)
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
