"""Inert DATA/control-flow regressions, not Mac/native/process evidence.

No core owner is imported and no command/native fixture is run. The unsigned-
iOS output-reader tests use disposable regular-file fixtures only; their DATA
does not substitute for required installed hosted Aqua/core/native evidence.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import importlib.util
from importlib.machinery import ModuleSpec
import io
import json
from pathlib import Path
import stat
from subprocess import CompletedProcess
import sys
from types import FunctionType, ModuleType, SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).absolute().parents[2] / "desktop" / "tools" / "macos_aqua_qualification.py"
SPEC = importlib.util.spec_from_file_location("_mrk_macos_aqua_data", PATH)
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)
BINDING = M.Binding("a" * 40, "123", "1")
UID, GID = 501, 20


def captured(value, prefix=b"", suffix=b""):
    return prefix + M.MARKER + json.dumps(value, separators=(",", ":")).encode() + b"\n" + suffix


def initial_snapshot(case):
    files, directories = M.fixture_data(case, False)
    result = {}
    for index, (name, body) in enumerate(files.items(), 1):
        result[name] = M.Node((7, index, stat.S_IFREG | 0o600, UID, GID, 1, len(body), 100, 100), M.digest(body), None)
    for index, (name, (mode, entries)) in enumerate(directories.items(), 100):
        result[name] = M.Node((7, index, stat.S_IFDIR | mode, UID, GID, 2, 4096, 100, 100), None, entries)
    return result


def final_snapshot(case, original):
    files, directories = M.fixture_data(case, True)
    result = dict(original)
    for name, (mode, entries) in directories.items():
        if name in result:
            result[name] = replace(result[name], entries=entries)
        else:
            result[name] = M.Node((7, 200, stat.S_IFDIR | mode, UID, GID, 2, 4096, 101, 101), None, entries)
    for name, body in files.items():
        if name not in result:
            result[name] = M.Node((7, 201, stat.S_IFREG | 0o600, UID, GID, 1, len(body), 101, 101), M.digest(body), None)
        elif name == ".gitignore" and case in ("first-save", "noop-stale"):
            previous = result[name].identity
            identity = (previous[0], 202 if case == "first-save" else previous[1], *previous[2:6], len(body), 101, 101)
            result[name] = M.Node(identity, M.digest(body), None)
        elif name == "version.properties" and case == "ios-version-stale":
            previous = result[name].identity
            result[name] = M.Node((*previous[:7], 101, 101), M.digest(body), None)
    return result


class InertFixtures:
    def __init__(self):
        self.inflight = self.last_returned = False
        self.close_errors = 0
        self.case = self.stage = None
        self.app_returncode = self.inner_failure_step = self.inner_failure_reason = None
        self.inner_failure_context = self.inner_diagnostic_source = None
        self.before, self.reads = [], []

    def before_call(self, case):
        self.case = case
        self.before.append(case)

    def readback(self, case):
        if self.inflight or not self.last_returned:
            raise AssertionError("readback lacks positive original return")
        self.reads.append(case)
        return {"inertTestOnly": True}

    def readback_ios(self, case, report):
        M._ios_report(report, case)
        return self.readback(case)


def context_data():
    return {"pending": {"kind": "native", "step": "CancelProject"},
            "nativeHandler": {"step": "CancelProject", "entered": True, "returned": False},
            "lastPanel": {"step": "CancelProject", "id": 1, "kind": "project",
                          "parentPresent": True, "panelPresent": True, "parentReferencesPanel": False,
                          "panelReferencesParent": True, "panelVisible": False}}


def context_row(value):
    return b"MRK_MACOS_AQUA_FAILURE_CONTEXT=" + json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"


def project_selection_context_data(custody="bound-original-data", recorded="fixture-root-all5", location="outside-namespace"):
    return {"snapshotSource": "record", "pending": None, "nativeHandler": None, "lastPanel": None,
            "projectSelection": {"custody": custody, "recordedObject": recorded, "lexicalLocation": location}}


def project_selection_row(value, reason="project-result-path", step="ProjectSettled"):
    return (f"MRK_MACOS_AQUA_FAILURE_STEP={step}\nMRK_MACOS_AQUA_FAILURE_REASON={reason}\n".encode("ascii")
            + context_row(value) + b"MRK_MACOS_AQUA=failed\n")


def action_context_data(step="CancelProject", *, site=None, domain="objc-exception", error="io"):
    action, kind, panel_id, call_site = {
        "CancelProject": ("project-cancel", "project", 1, "project-cancel"),
        "QuitCancel": ("quit-cancel", "quit", 3, "quit-cancel"),
        "Quit": ("quit-confirm", "quit", 4, "quit-confirm"),
    }[step]
    value = context_data()
    value["pending"] = None
    value["nativeHandler"].update(step=step, returned=True)
    value["lastPanel"].update(step=step, id=panel_id, kind=kind, parentReferencesPanel=True,
                              panelReferencesParent=True, panelVisible=True)
    value["nativeAction"] = {"step": step, "id": panel_id, "action": action, "domain": domain,
                             "site": call_site if site is None else site, "error": error}
    return value


def accessibility_context_data():
    value = context_data()
    value["pending"] = None
    value["nativeHandler"].update(step="OpenProject", returned=True)
    value["lastPanel"].update(step="OpenProject", id=2, parentReferencesPanel=True,
                              panelReferencesParent=True, panelVisible=True)
    value["nativeAction"] = None  # Genuine AX Press has no late native-selector return.
    value["accessibility"] = deepcopy(M.expected_result(BINDING, "first-save")["native"]["projectOpenInput"])
    return value


def completion_context_data(case="first-save"):
    # Saved scalar DATA only; no panel/callback or original poll is simulated.
    return {"snapshotSource": "record", "pending": None, "nativeHandler": None, "lastPanel": None,
            "completionSelection": deepcopy(M.expected_result(BINDING, case)["native"]["projectCompletionSelection"])}


def binding_context_data(case="first-save"):
    # A start can fail before any native handler or Press exists. This DATA
    # fixture deliberately supplies neither, rather than inventing an action.
    return {"pending": None, "nativeHandler": None, "lastPanel": None, "nativeAction": None, "accessibility": None,
            "accessibilityBinding": deepcopy(M.expected_result(BINDING, case)["native"]["projectOpenBinding"])}


def file_failure_context_data(case, index, panel_id):
    # Caller-supplied literal original IDs, not the decoder's roster as oracle.
    # File OpenInput keeps its legacy label; the saved native dispatch does not.
    value = accessibility_context_data()
    step = f"Session(Native({index}))"
    value.update(snapshotSource="record")
    value["nativeHandler"]["step"] = step
    value["lastPanel"].update(step=step, id=panel_id, kind="file")
    value["accessibility"]["id"] = panel_id
    value["accessibilityBinding"] = binding_context_data()["accessibilityBinding"]
    value["completionSelection"] = completion_context_data()["completionSelection"]
    for field in ("accessibilityBinding", "completionSelection"):
        value[field].update(case=case, id=panel_id, kind="file")
    value["accessibilityBinding"]["configuration"].update(fileNameSetterEntered=True, fileNameSetterReturned=True)
    return value


def _inert_command(argv, *, environ, cwd, timeout, capture, text, output_limit):
    """Literal DATA-only body rebound below; no owner import or command call."""
    global recursion
    engine = original_engine
    if mutate_argv:
        argv[1] = "noop-stale"
    argv, cwd, timeout = overrides.get("argv", argv), overrides.get("cwd", cwd), overrides.get("timeout", timeout)
    capture, text = overrides.get("capture", capture), overrides.get("text", text)
    output_limit = overrides.get("output_limit", output_limit)
    if recursion:
        recursion -= 1
        return run_command(argv, environ=environ, cwd=cwd, timeout=timeout, capture=capture,
                           text=text, output_limit=output_limit)
    try:
        raise original_error
    except BaseException as error:
        if duplicate_frame:
            raise error
        raise


def _inert_owned(argv, **options):
    return run_command(argv, **options)


@contextmanager
def inert_exception_owner(*, stderr=None, duplicate=False, recursion=0):
    """Synthetic function/frame DATA fixtures, NEVER evidence of a real owner.

    No source loader/import is used. Expected filenames here exercise the
    origin guard; the actual engine, Store, process and filesystem are absent.
    """
    source = PATH.parents[2] / "src" / "mobile_release"
    owner, command = ModuleType("mobile_release.owned_process"), ModuleType("mobile_release._command_process")
    for module, name in ((owner, "owned_process"), (command, "_command_process")):
        module.__file__ = str(source / (name + ".py"))
        module.__spec__ = ModuleSpec(module.__name__, loader=None, origin=module.__file__)
    for name in ("_Outer", "FrozenCommand", "Manifest"):
        setattr(command, name, type(name, (), {"__module__": command.__name__}))
    manifest = command.Manifest(); manifest.capture, manifest.limit = True, M.OUTPUT_LIMIT
    frozen = command.FrozenCommand()
    frozen.args = (M.EXECUTABLE, "first-save")
    frozen.argv = tuple(arg.encode("ascii") for arg in frozen.args)
    frozen.cwd = str(BINDING.root() / "state" / "first-save").encode("ascii")
    frozen.manifest = manifest
    engine = command._Outer(); engine.frozen, engine.text = frozen, False
    if stderr is None:
        stderr = (b"PRIVATE CHILD LOG\nMRK_MACOS_AQUA_FAILURE_STEP=CancelProject\n"
                  b"MRK_MACOS_AQUA_FAILURE_REASON=observer-deadline\n" + context_row(context_data()))
    engine.outputs = [bytearray(), bytearray(stderr)]
    original = RuntimeError("PRIVATE ORIGINAL ERROR")
    command.original_engine, command.original_error = engine, original
    command.duplicate_frame, command.recursion = duplicate, recursion
    command.overrides = {}
    command.mutate_argv = False
    command.run_command = FunctionType(_inert_command.__code__.replace(co_filename=command.__file__), vars(command), "run_command")
    owner.run_command = command.run_command
    owner.run_owned = FunctionType(_inert_owned.__code__.replace(co_filename=owner.__file__), vars(owner), "run_owned")
    with patch.dict(sys.modules, {owner.__name__: owner, command.__name__: command}):
        yield SimpleNamespace(owner=owner, command=command, engine=engine, frozen=frozen, manifest=manifest, original=original)


@contextmanager
def inert_created_directory(gid=GID):
    """Every filesystem entry is replaced; tokens cannot name real FDs."""
    fixtures = M.Fixtures(BINDING, UID, GID)
    parent, token = object(), object()
    state = SimpleNamespace(
        info=dict(st_dev=7, st_ino=100, st_mode=stat.S_IFDIR | 0o700,
                  st_uid=UID, st_gid=gid, st_nlink=2, st_size=4096,
                  st_mtime_ns=100, st_ctime_ns=100),
        named_changes={}, events=[])

    def opened(name, directory_parent, *, directory):
        assert name == "fresh" and directory_parent is parent and directory
        fixtures.fds.add(token)
        state.events.append("open")
        return token

    def info(fd):
        assert fd is token
        return SimpleNamespace(**state.info)

    def named(name, *, dir_fd, follow_symlinks):
        assert name == "fresh" and dir_fd is parent and follow_symlinks is False
        state.events.append("named")
        return SimpleNamespace(**{**state.info, **state.named_changes})

    def chown(fd, uid, group):
        assert fd is token and uid == -1 and group == GID
        state.events.append("chown")
        state.info.update(st_gid=group, st_ctime_ns=101)

    def chmod(fd, mode):
        assert fd is token and mode == 0o755 and state.info["st_gid"] == GID
        state.events.append("chmod")
        state.info.update(st_mode=stat.S_IFDIR | mode, st_ctime_ns=102)

    with patch.object(M.os, "mkdir") as mkdir, \
            patch.object(fixtures, "_open", side_effect=opened) as opening, \
            patch.object(M.os, "stat", side_effect=named), \
            patch.object(M.os, "fstat", side_effect=info), \
            patch.object(M.os, "fchown", side_effect=chown) as changing_group, \
            patch.object(M.os, "fchmod", side_effect=chmod) as changing_mode:
        yield SimpleNamespace(fixtures=fixtures, parent=parent, token=token, state=state,
                              mkdir=mkdir, opening=opening, chown=changing_group, chmod=changing_mode)


class AquaDataTests(unittest.TestCase):
    def test_current_owner_pins_match_checkout_and_refuse_stale_before_import(self):
        root = PATH.parents[2]
        names = ("owned_process.py", "_command_process.py", "_native_process.py", "cancellation.py")
        self.assertEqual(tuple(M.OWNER_PINS), names)
        for name, expected in M.OWNER_PINS.items():
            path = root / "src" / "mobile_release" / name
            info = path.lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode), name)
            self.assertLessEqual(info.st_size, 256 * 1024, name)
            self.assertEqual(M.digest(path.read_bytes()), expected, name)

        # The positive check above reads only DATA. The actual loader is entered
        # only with the known stale pin, under a blocker installed before entry.
        def core_modules():
            return {name: module for name, module in sys.modules.items()
                    if name == "mobile_release" or name.startswith("mobile_release.")}
        before_modules, before_path, before_pins = core_modules(), sys.path, dict(M.OWNER_PINS)
        before_path_values = list(before_path)
        self.assertEqual(before_modules, {})  # Never delete preexisting modules to make this pass.
        attempted_imports = []
        original_import = __import__

        def no_core_import(name, globals=None, locals=None, fromlist=(), level=0):
            package = globals.get("__package__") if type(globals) is dict else None
            if (name == "mobile_release" or name.startswith("mobile_release.")
                    or level and type(package) is str
                    and (package == "mobile_release" or package.startswith("mobile_release."))):
                attempted_imports.append(name)
                raise AssertionError("core import attempted before stale owner refusal")
            return original_import(name, globals, locals, fromlist, level)

        # Contexts restore the original dictionaries/path even if an assertion
        # fails; the inner assertions detect drift before that restoration.
        with patch.dict(sys.modules), patch.object(sys, "path", list(before_path)):
            with patch("builtins.__import__", no_core_import), patch.dict(M.OWNER_PINS, {
                    "_command_process.py": "075fa6e9838017feb6a1716ab3a75074e3a65dffe8b217613aff7e87c0201f68"}):
                with self.assertRaisesRegex(M.Refused, "^owner-source-pin$") as refused:
                    M.load_owner(root)
                self.assertIs(type(refused.exception), M.Refused)
                self.assertEqual(attempted_imports, [])
                self.assertEqual(sys.path, before_path_values)
                self.assertEqual(core_modules(), before_modules)
            self.assertEqual(M.OWNER_PINS, before_pins)
        self.assertIs(sys.path, before_path)
        self.assertEqual(sys.path, before_path_values)
        self.assertEqual(core_modules(), before_modules)
        self.assertEqual(M.OWNER_PINS, before_pins)

        workflow = (root / ".github/workflows/desktop-macos-aqua.yml").read_text()
        label = "      - name: Check current owner pins before native preparation\n"
        self.assertEqual(workflow.count(label), 1)
        position = workflow.index(label)
        self.assertLess(workflow.index("      - name: Bind the complete reviewed first-party checkout before compilation\n"), position)
        for later in ("Compile headless Mac libraries and run thirteen exact DATA regressions first",
                      "Fail fast on native Scripts ownership and package format (never Installer)",
                      "Download only the exact accepted M archive (no rebuild or fallback)",
                      "Compile the fixed debug actual-main observer and normal embedded frontend once",
                      "Application installation uses only standard privileged Installer; app and Python stay nonroot"):
            self.assertLess(position, workflow.index("      - name: " + later + "\n"))
        step = workflow.split(label, 1)[1].split("\n      - name:", 1)[0]
        for required in (
                "timeout-minutes: 1", '"$MRK_PYTHON" -I -S -B -',
                'path = pathlib.Path("tests/desktop/test_macos_aqua_qualification.py").absolute()',
                'module.AquaDataTests("test_current_owner_pins_match_checkout_and_refuse_stale_before_import")',
                'module.IOSAquaDataTests("test_normal_macos_selection_is_original_bound_without_observer_grants")',
                'module.CurrentIOSAquaDataTests("test_current_reports_are_closed_bounded_and_do_not_claim_successful_signing")',
                'module.CurrentIOSAquaDataTests("test_file_originals_and_retained_signing_records_cannot_be_substituted")',
                'module.ProjectFieldsAquaDataTests("test_complete_project_fields_report_is_bounded_and_fail_closed")',
                'module.ProjectFieldsAquaDataTests("test_original_fixture_restoration_has_only_two_ctime_exceptions")',
                "unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)",
                "result.testsRun != 6", "not result.wasSuccessful()",
                "result.failures, result.errors, result.skipped, result.expectedFailures, result.unexpectedSuccesses",
                "raise SystemExit(1)"):
            self.assertIn(required, step)
        self.assertNotIn("discover(", step)
        self.assertNotIn("loadTestsFrom", step)

        headless_label = "      - name: Compile headless Mac libraries and run thirteen exact DATA regressions first\n"
        self.assertEqual(workflow.count(headless_label), 1)
        self.assertLess(workflow.index(headless_label), workflow.index(
            "      - name: Fail fast on native Scripts ownership and package format (never Installer)\n"))
        headless = workflow.split(headless_label, 1)[1].split("\n      - name:", 1)[0]
        self.assertLess(headless.index("cd desktop/src-tauri"), headless.index("cargo test --locked --no-default-features"))
        self.assertEqual(headless.count("cargo test "), 1)
        self.assertIn("--package mobile-release-kit-desktop --package mrk-macos-installed-native", headless)
        self.assertIn("--lib --no-run --message-format=json", headless)
        self.assertNotIn("--manifest-path", headless)
        self.assertNotIn("--features", headless)
        self.assertIn('cwd="desktop" if name in ("rustc", "cargo") else None', workflow)
        names = headless.split("          names = (\n", 1)[1].split("          )\n", 1)[0]
        self.assertCountEqual(M.re.findall(r'"([^"]+)"', names), (
            "asset_source::macos::tests::private_asset_suffixes_admit_android_without_broadening_apple_formats",
            "asset_source::macos::tests::root_aliases_are_exact_and_physical_protection_is_not_path_text",
            "asset_source::macos::tests::entered_native_checks_remain_uncertain_after_descriptor_book_retirement",
            "asset_source::macos::tests::protected_objects_are_recognized_even_from_another_firmlink_parent_role",
            "asset_source::macos::tests::complete_alias_rosters_are_bounded_before_any_native_acquisition",
            "asset_source::macos::tests::project_fields_are_strict_descendant_data_not_credential_capture",
            "asset_source::macos::tests::project_spellings_are_bounded_without_canonicalization",
            "asset_source::macos::tests::only_local_ownership_aware_apfs_is_admitted",
            "ios_toolchain::tests::fixed_alias_is_only_one_sibling_not_a_path_traversal_or_second_lookup",
            "asset_session::tests::macos_input_context_matrix_keeps_platform_kinds_and_ios_signing_separate",
            "asset_session::tests::macos_cached_record_preview_publication_and_old_context_cannot_bypass_kind_gate",
        ))
        native_names = headless.split("          native_names = (\n", 1)[1].split("          )\n", 1)[0]
        self.assertCountEqual(M.re.findall(r'"([^"]+)"', native_names), (
            "tests::bulk_directory_records_preserve_full_ids_and_refuse_malformed_batches",
            "tests::only_explicit_user_appkit_responses_can_be_accept_or_decline",
        ))
        self.assertIn('"scope": "eleven-main-and-two-native-macos-headless-data-regressions"', headless)
        table = headless.split("          libraries = (\n", 1)[1].split("          )\n", 1)[0]
        self.assertEqual(table,
            '              ("main", "desktop/src-tauri", "mobile-release-kit-desktop", "mobile_release_desktop", [], names, 11, "headless"),\n'
            '              ("native", "desktop/native/macos-installed-native", "mrk-macos-installed-native", "mrk_macos_installed_native",\n'
            '               ["default"], native_names, 2, "headless-native"),\n')
        for required in ("if len(targets) != 2:", "for role, directory, package, library, features, test_names, count, prefix in libraries:",
                         'r.get("target", {}).get("name") == library', "if len(matches) != 1:",
                         'package_id = "path+" + (checkout / directory).as_uri() + "#" + package + "@0.1.0"',
                         'target.get("package_id") != package_id',
                         'target.get("manifest_path") != str(checkout / directory / "Cargo.toml")',
                         'target["target"].get("kind") != ["lib"]', 'target["target"].get("crate_types") != ["lib"]',
                         'target["target"].get("src_path") != str(checkout / directory / "src/lib.rs")',
                         'target.get("profile", {}).get("test") is not True', 'target.get("features") != features',
                         'binary.parent != expected', 're.fullmatch(re.escape(library) + r"-[0-9a-f]+", binary.name)',
                         "for binary, test_names, count, prefix, record in admitted:"):
            self.assertIn(required, headless)
        self.assertLess(headless.index("admitted.append("), headless.index("owner.run_owned("))
        self.assertEqual(headless.count("owner.run_owned("), 1)
        for required in ('[str(binary), "--exact", "--test-threads=1", "--color=never", "--format=pretty", *test_names]',
                         "cwd=work, timeout=30, capture=True, text=False, output_limit=64 * 1024",
                         "type(result) is not subprocess.CompletedProcess", "type(result.stdout) is not bytes",
                         "type(result.stderr) is not bytes", "len(result.stdout) + len(result.stderr) > 64 * 1024",
                         "len(test_names) != count", "len(expected_rows) != count", "len(lines) != count + 2",
                         'heading = f"running {count} " + ("test" if count == 1 else "tests")', 'lines[0] != heading',
                         "len(set(lines[1:-1])) != count", "set(lines[1:-1]) != expected_rows",
                         "{count} passed; 0 failed; 0 ignored; 0 measured;"):
            self.assertIn(required, headless)
        reject = headless.index('if result.returncode != 0 or result.stderr:')
        for output in ("stdout", "stderr", "status"):
            self.assertLess(headless.index('publish(prefix + "-tests.' + output + '"'), reject)
        self.assertLess(headless.index("originals.append(original)"), headless.index("before = os.fstat(binary_fd)"))
        self.assertIn('os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)', headless)
        for required in ('sig(before) != sig(os.fstat(binary_fd))', 'sig(before) != sig(binary.lstat())',
                         'os.pread(binary_fd, min(before.st_size - offset, 1024 * 1024), offset)',
                         'os.pread(binary_fd, 1, before.st_size)', 'return digest.hexdigest()'):
            self.assertIn(required, headless)
        digest_checks = [item.start() for item in M.re.finditer(M.re.escape('if original_digest() != digest:'), headless)]
        self.assertEqual(len(digest_checks), 2)
        self.assertLess(digest_checks[0], headless.index("owner.run_owned("))
        self.assertGreater(digest_checks[1], headless.index('publish(prefix + "-tests.status"'))
        self.assertLess(headless.index('raise ValueError("headless-original-return-contract")'), headless.index("home.rmdir()"))
        settlement = headless.split("          finally:\n", 1)[1]
        self.assertNotIn(".rmdir()", settlement)
        for required in ('descriptor, original["fd"] = original["fd"], None',
                         'original["record"]["artifactOriginalClosed"] = True',
                         'close_errors.append({"role": original["record"]["role"], "type": type(error).__name__})',
                         'if close_errors: receipt["closeErrors"] = close_errors',
                         'receipt[key] = len(receipt["targets"]) == 2 and all(row[key] for row in receipt["targets"])',
                         'receipt["passed"] = ("failure" not in receipt and not close_errors',
                         'and receipt["originalReturned"] and receipt["artifactOriginalUnchanged"] and receipt["artifactOriginalClosed"]',
                         'and all(row["testsPassed"] for row in receipt["targets"]))',
                         'if receipt["passed"]: receipt.update(tests=len(names) + len(native_names), failed=0, ignored=0, measured=0)',
                         'if close_errors and "failure" not in receipt: raise ValueError("headless-original-close-unconfirmed")'):
            self.assertIn(required, settlement)
        self.assertEqual(settlement.count("os.close(descriptor)"), 1)
        self.assertLess(settlement.index("os.close(descriptor)"), settlement.index('receipt["passed"] ='))
        self.assertLess(settlement.index('receipt["passed"] ='), settlement.index('publish("headless-tests.receipt.json", data)'))
        exporter = workflow.split("      - name: Export bounded diagnostics without altering original command evidence\n", 1)[1]
        for required in ('("headless-build.jsonl", "headless-build.status", 4 * 1024 * 1024, "headless-build.admitted.jsonl", False)',
                         '("headless-build.stderr", "headless-build.status", 64 * 1024, "headless-build.stderr.tail.txt", True)',
                         '"unavailable-original-status-missing-or-invalid"'):
            self.assertIn(required, exporter)
        self.assertLess(exporter.index("status, status_meta = snapshot(status_name, 4)"),
                        exporter.index("data, metadata = snapshot(original, limit, tail)"))
        upload = exporter.split("          path: |\n", 1)[1]
        for output in ("headless-build.admitted.jsonl", "headless-build.stderr.tail.txt", "headless-build.status",
                       "headless-tests.stdout", "headless-tests.stderr", "headless-tests.status",
                       "headless-native-tests.stdout", "headless-native-tests.stderr", "headless-native-tests.status",
                       "headless-tests.receipt.json"):
            self.assertIn("${{ steps.work.outputs.root }}/" + output + "\n", upload)
        for unbounded in ("headless-build.jsonl\n", "headless-build.stderr\n", "cargo-target", "*", "**"):
            self.assertNotIn(unbounded, upload)


    def test_directory_link_metadata_never_widens_ordinary_rosters_or_source_acquisition(self):
        root = PATH.parents[2]
        native = (root / "desktop/native/macos-installed-native/src/native.m").read_text()
        decoder = native.split("int mrk_decode_directory_entries(", 1)[1].split("int mrk_entries(", 1)[0]
        self.assertIn("(kind != VREG && kind != VDIR && kind != VLNK)) return EIO;", decoder)
        self.assertIn("out[written + 8] = kind == VDIR ? DT_DIR : (kind == VLNK ? DT_LNK : DT_REG);", decoder)
        self.assertEqual(decoder.count("*used ="), 2)
        self.assertLess(decoder.index("*used = 0;"), decoder.index("for (int n = 0; n < count; ++n)"))
        self.assertLess(decoder.index("offset += length;"), decoder.index("*used = written;"))
        self.assertIn("if (capacity - written < 11 || name_length > capacity - written - 11) return EOVERFLOW;", decoder)
        for forbidden in ("open(", "openat(", "readlink(", "stat(", "getattrlistbulk("):
            self.assertNotIn(forbidden, decoder)
        entries = native.split("int mrk_entries(", 1)[1].split("int mrk_sync(", 1)[0]
        self.assertIn("getattrlistbulk(fd, &request, block, sizeof(block), 0)", entries)
        self.assertIn("return mrk_decode_directory_entries(block, sizeof(block), count, out, capacity, used);", entries)
        runtime = (root / "desktop/src-tauri/src/installed_runtime_macos.rs").read_text()
        walk = runtime.split("    fn walk(", 1)[1].split("    fn inspect(", 1)[0]
        guard = "if !matches!(buffer[offset+8], nix::libc::DT_DIR | nix::libc::DT_REG) { return Err(AdmissionFailure::Inventory); }"
        self.assertEqual(walk.count(guard), 1)
        self.assertLess(walk.index("if used - offset < 11"), walk.index(guard))
        for after in ('if name == "."', 'if path == "manifest.json"', "self.open(Some(parent)"):
            self.assertLess(walk.index(guard), walk.index(after))
        installer = (root / "desktop/src-tauri/src/bin/macos_install.rs").read_text()
        roster = installer.split("        fn roster(", 1)[1].split("        fn copy_file(", 1)[0]
        guard = 'check(matches!(block[offset+8], nix::libc::DT_DIR | nix::libc::DT_REG), "directory-roster")?;'
        self.assertEqual(roster.count(guard), 1)
        self.assertLess(roster.index('check(used-offset >= 11,"directory-record")?;'), roster.index(guard))
        for after in ('if name == "."', "found.insert("):
            self.assertLess(roster.index(guard), roster.index(after))
        for ordinary in (walk, roster):
            self.assertNotIn("DT_LNK", ordinary)
        observer = (root / "desktop/src-tauri/src/installed_shell_observation_macos.rs").read_text()
        rosters = observer.split("fn directory_rosters(", 1)[1].split("struct Fixture {", 1)[0]
        for required in ('if alternate.is_some() && linked.is_some() { return Err(()); }',
                         'if linked.is_some_and(|name| name != "linked.p12" || !entries.contains(&name)) { return Err(()); }',
                         'kind == nix::libc::DT_LNK && linked == Some(name)',
                         '!directory_roster_matches(&actual, entries, alternate)'):
            self.assertIn(required, rosters)
        self.assertIn("directory_with_link(path, uid, mode, entries, None)", observer)
        source = (root / "desktop/src-tauri/src/asset_source_macos.rs").read_text()
        child = source.split("    fn child(", 1)[1].split("    fn chain(", 1)[0]
        acquisition = child.index("self.slots[index].state = OriginalState::Acquiring;")
        self.assertLess(child.index("AtFlags::AT_SYMLINK_NOFOLLOW"), child.index("let expected = identity(&before, file)?;"))
        self.assertLess(child.index("let expected = identity(&before, file)?;"), acquisition)
        self.assertLess(acquisition, child.index("fcntl::openat("))
        self.assertIn("OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK", child)
        self.assertIn("if file { file_identity(stat).map(Identity::File) }", source)
        self.assertIn("if stat.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFREG.bits() { return Err(Reason::SourceRefused); }", source)
        session = (root / "desktop/src-tauri/src/installed_shell_observation_macos_session.rs").read_text()
        self.assertIn('4 | 5 => Some(("refused", "source-refused"))', session)
        self.assertIn('root.join("linked.p12")', session)
        self.assertIn('self.link.as_ref().map(|_| "linked.p12")', session)
        self.assertIn('std::fs::read_link(path).map_err(|_| ())? != Path::new("synthetic.p12")', session)
        self.assertIn('link_fact(&root.join("linked.p12"), uid)?.identity != original.identity', session)


    def test_new_directory_group_normalization_precedes_widening(self):
        for gid in (GID, 0):
            for mode in (0o700, 0o755):
                with self.subTest(gid=gid, mode=mode), inert_created_directory(gid) as f:
                    self.assertIs(f.fixtures._mkdir(f.parent, "fresh", mode), f.token)
                    f.mkdir.assert_called_once_with("fresh", 0o700, dir_fd=f.parent)
                    self.assertEqual(f.fixtures.fds, {f.token})
                    self.assertEqual(f.chown.call_count, int(gid != GID))
                    self.assertEqual(f.chmod.call_count, int(mode != 0o700))
                    events = ["open", "named"] + (["chown"] if gid != GID else []) + ["named"]
                    if mode != 0o700:
                        events += ["chmod", "named"]
                    self.assertEqual(f.state.events, events)
                    self.assertEqual(f.state.info["st_gid"], GID)

    def test_new_directory_refuses_collision_and_untrusted_precheck(self):
        original = FileExistsError("occupied")
        with inert_created_directory(0) as f:
            f.mkdir.side_effect = original
            with self.assertRaises(FileExistsError) as caught:
                f.fixtures._mkdir(f.parent, "fresh", 0o755)
            self.assertIs(caught.exception, original)
            f.opening.assert_not_called()
            f.chown.assert_not_called()
            f.chmod.assert_not_called()
            self.assertEqual(f.fixtures.fds, set())
        for where, changes in (("info", {"st_uid": 0}),
                               ("info", {"st_mode": stat.S_IFDIR | 0o755}),
                               ("info", {"st_mode": stat.S_IFLNK | 0o700}),
                               ("named_changes", {"st_ino": 101}),
                               ("named_changes", {"st_ctime_ns": 101})):
            with self.subTest(where=where, changes=changes), inert_created_directory(0) as f:
                getattr(f.state, where).update(changes)
                with self.assertRaisesRegex(M.Refused, "^fixture-created-directory-custody$"):
                    f.fixtures._mkdir(f.parent, "fresh", 0o755)
                f.chown.assert_not_called()
                f.chmod.assert_not_called()
                self.assertEqual(f.fixtures.fds, {f.token})

    def test_new_directory_failed_normalization_retains_original_close(self):
        original = PermissionError("group change refused")
        with inert_created_directory(0) as f:
            f.chown.side_effect = original
            with self.assertRaises(PermissionError) as caught:
                f.fixtures._mkdir(f.parent, "fresh", 0o755)
            self.assertIs(caught.exception, original)
            f.chown.assert_called_once_with(f.token, -1, GID)
            f.chmod.assert_not_called()
            self.assertEqual(f.fixtures.fds, {f.token})
            with patch.object(M.os, "close") as close:
                f.fixtures.close()
                f.fixtures.close()
                close.assert_called_once_with(f.token)
                self.assertEqual(f.fixtures.fds, set())

    def test_new_directory_postcheck_refuses_group_identity_and_namespace_changes(self):
        for where, changes in (("info", {}),  # Successful return but unchanged group.
                               ("info", {"st_gid": GID, "st_dev": 8}),
                               ("info", {"st_gid": GID, "st_ino": 101}),
                               ("info", {"st_gid": GID, "st_uid": 0}),
                               ("info", {"st_gid": GID, "st_mode": stat.S_IFDIR | 0o755}),
                               ("named_changes", {"st_ino": 101})):
            with self.subTest(where=where, changes=changes), inert_created_directory(0) as f:
                def change(*_):
                    if where == "named_changes":
                        f.state.info["st_gid"] = GID
                    getattr(f.state, where).update(changes)
                f.chown.side_effect = change
                with self.assertRaises(M.Refused):
                    f.fixtures._mkdir(f.parent, "fresh", 0o755)
                f.chown.assert_called_once_with(f.token, -1, GID)
                f.chmod.assert_not_called()
                self.assertEqual(f.fixtures.fds, {f.token})

    def test_literal_data_and_protocol_distinctions(self):
        self.assertEqual((len(M.CONFIG), M.digest(M.CONFIG)), (684, "0c47aaffe3971b122f21ebddf8070ab29014c4b7c79a56e23335ed110f1e6acc"))
        self.assertEqual((len(M.VERSION), len(M.IGNORE_PREFIX), len(M.IGNORE_RULES), len(M.STALE)), (34, 40, 299, 26))
        self.assertEqual(M.SOURCE, b'plugins { id("com.android.application") }\nandroid { defaultConfig { applicationId = "org.example.mrk.observed" } }\n')
        expected = {
            "first-save": [(1, 1, True, 2, True, "committed", "clean", "none", "none", 3),
                           (1, 2, False, 0, False, "not_started", "not_created", "cancelled", "shutdown", 2)],
            "noop-stale": [(1, 1, False, 1, True, "unchanged", "not_created", "none", "none", 3),
                           (2, 1, False, 1, True, "not_started", "not_created", "stale_revision", "none", 3)],
            "picker-loss": [],
            "save-loss": [(1, 1, True, 0, False, "not_started", "not_created", "cancelled", "window_lost", 2)],
        }
        for case, rows in expected.items():
            with self.subTest(case=case):
                report = M.expected_result(BINDING, case)
                observed = [(s["draftRevision"], s["baselineGeneration"], s["createReleaseDirectory"], s["confirmationsOpened"],
                             s["apply"], s["outcome"]["effect"], s["outcome"]["journal"], s["outcome"]["reason"],
                             s["nativeReason"], s["writerFrames"]) for s in report["saveSessions"]]
                self.assertEqual(observed, rows)
                self.assertEqual(M.parse_result(captured(report), b"", BINDING, case), report)

    def test_review_ignore_lengths_match_the_complete_fixture(self):
        initial = M.fixture_data("first-save", False)[0][".gitignore"]
        saved = M.fixture_data("noop-stale", False)[0][".gitignore"]
        self.assertEqual((len(initial), len(saved)), (40, 339))
        self.assertEqual(saved, initial + M.IGNORE_RULES)
        for case in M.CASES:
            for session in M.expected_result(BINDING, case)["saveSessions"]:
                with self.subTest(case=case, draft=session["draftRevision"], baseline=session["baselineGeneration"]):
                    ignore = session["files"][1]
                    self.assertEqual(ignore, {"path": ".gitignore",
                        "action": "append" if session["createReleaseDirectory"] else "preserve",
                        "beforeBytes": len(initial if session["createReleaseDirectory"] else saved),
                        "afterBytes": len(saved)})

    def test_result_diagnostic_locates_schema_field_without_exporting_values_or_unknown_keys(self):
        good = M.expected_result(BINDING, "first-save")
        wrong_value = deepcopy(good); wrong_value["saveSessions"][0]["files"][1]["afterBytes"] = 248
        wrong_type = deepcopy(good); wrong_type["saveSessions"][0]["files"][1]["afterBytes"] = "PRIVATE_ACTUAL_VALUE"
        extra_key = deepcopy(good); extra_key["saveSessions"][0]["files"][1]["PRIVATE_UNKNOWN_KEY"] = "PRIVATE_ACTUAL_VALUE"
        wrong_count = deepcopy(good); wrong_count["saveSessions"].pop()
        for value, label, location in (
            (wrong_value, "result-value", "saveSessions[0].files[1].afterBytes"),
            (wrong_type, "result-type", "saveSessions[0].files[1].afterBytes"),
            (extra_key, "result-keys", "saveSessions[0].files[1]"),
            (wrong_count, "result-count", "saveSessions"),
        ):
            fixtures, calls = InertFixtures(), []
            def runner(argv, **kwargs):
                calls.append(argv)
                return CompletedProcess(args=argv, returncode=0, stdout=captured(value), stderr=b"")
            with self.subTest(label=label), self.assertRaises(M.Refused) as caught:
                M.run_cases(BINDING, fixtures, runner, UID, "runner", self.fail)
            self.assertEqual((str(caught.exception), calls, fixtures.reads), (label, [[M.EXECUTABLE, "first-save"]], []))
            output = io.StringIO()
            M.emit_record(M.diagnostic(caught.exception, None, fixtures), output)
            report = json.loads(output.getvalue())
            self.assertEqual((report["reason"], report["resultLocation"]), (label, location))
            self.assertEqual((report["stage"], report["originalCallReturned"], report["laterCasesStopped"]),
                             ("result-validation", True, True))
            self.assertNotIn("PRIVATE_", output.getvalue())
            with patch.object(M, "_result_location", side_effect=RuntimeError("PRIVATE_DIAGNOSTIC_FAILURE")):
                fallback = M.diagnostic(caught.exception, None, fixtures)
            self.assertEqual(fallback["reason"], label)
            self.assertNotIn("resultLocation", fallback)
            self.assertNotIn("PRIVATE_", json.dumps(fallback))

    def test_result_diagnostic_omits_unsafe_or_unbounded_locations(self):
        for location in (None, (), ["saveSessions"], ("PRIVATE_KEY",), ("saveSessions", True),
                         ("saveSessions", -1), ("saveSessions", 64), ("saveSessions",) * 13,
                         ("staleMarkerWriterReturnedAndClosed",) * 12):
            error = M.Refused("result-value")
            error.result_location = location
            report = M.diagnostic(error, None, None)
            self.assertEqual(report["reason"], "result-value")
            self.assertNotIn("resultLocation", report)
        self.assertEqual(M._result_location(("saveSessions", 63, "files", 0, "beforeBytes")),
                         "saveSessions[63].files[0].beforeBytes")

    def test_review_ignore_bound_uses_the_exact_native_fixture_roster(self):
        # Source/DATA regression only; real DOM execution remains a macOS gate.
        observer = (PATH.parents[1] / "src-tauri" / "src" / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        fixture = M.re.search(r"const IGNORE_LINES: \[&str; ([0-9]+)\] = \[(.*?)\];", observer, M.re.S)
        self.assertIsNotNone(fixture)
        expected = M.IGNORE_RULES.decode("ascii").splitlines()
        self.assertEqual(int(fixture.group(1)), len(expected))
        self.assertEqual(M.re.findall(r'"([^"]+)"', fixture.group(2)), expected)
        script = observer.split("fn script(case: Case, step: Step)", 1)[1].split("\n}\n", 1)[0] + "\n}"
        self.assertIn("if let Step::Session(step) = step { return session::script(step); }", script)
        self.assertEqual(script.count("if(ignore.length>{ignore_limit}||counts.length!==3)throw 0;"), 1,
                         "review-ignore-count-bound")
        self.assertEqual(script.count('Some(format!(r#"'), 1)
        self.assertTrue(script.rstrip().endswith('"#, ignore_limit = IGNORE_LINES.len()))\n}'),
                        "review-ignore-count-argument")
        native = observer.split("    fn review_sample(", 1)[1].split("\n    pub(super) fn open_request(", 1)[0]
        self.assertIn("!view.ignore_additions.iter().map(String::as_str).eq(if create { IGNORE_LINES.as_slice() } else { &[] }.iter().copied())", native)
        body = observer.split("    fn dom_body(", 1)[1].split("    pub(super) fn relay_joined", 1)[0]
        self.assertIn('s.live_review() && s.review.as_ref() == v.get("review")', body)
        self.assertIn('v["project"].as_str() != self.project_path.to_str()', body)

    def test_strict_result_rejects_missing_extra_wrong_type_or_wrong_finality(self):
        good = M.expected_result(BINDING, "first-save")
        variants = []
        for field, replacement in (("schemaVersion", True), ("actualExit", 1), ("originalRelayJoined", False),
                                   ("sourceCommit", "b" * 40), ("shippingBinaryQualified", True)):
            item = deepcopy(good)
            item[field] = replacement
            variants.append(item)
        item = deepcopy(good); del item["native"]["originalDocumentAndQuitSettled"]; variants.append(item)
        item = deepcopy(good); item["native"]["inventedReceipt"] = True; variants.append(item)
        item = deepcopy(good); item["saveSessions"][0]["writerFrames"] = 3.0; variants.append(item)
        item = deepcopy(good); item["saveSessions"][1]["outcome"]["effect"] = "unchanged"; variants.append(item)
        item = deepcopy(good); item["saveSessions"][0]["files"][1]["afterBytes"] = 208; variants.append(item)
        for index, item in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(M.Refused):
                M.parse_result(captured(item), b"", BINDING, "first-save")

    def test_marker_duplicates_failure_json_and_byte_limits(self):
        good = captured(M.expected_result(BINDING, "first-save"))
        duplicate = good.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1', 1)
        invalid = [good + good, duplicate, good.rstrip(b"\n"), b"log " + good,
                   M.MARKER + b" " * (M.JSON_LIMIT + 1) + b"\n", M.MARKER + b'{"x":NaN}\n',
                   M.MARKER + b"\xff\n", good + b"MRK_MACOS_AQUA=failed\n"]
        for index, body in enumerate(invalid):
            with self.subTest(index=index), self.assertRaises(M.Refused):
                M.parse_result(body, b"", BINDING, "first-save")
        for stderr in (b"MRK_MACOS_AQUA_FAILURE_STEP=Review\n", good, b"x" * M.OUTPUT_LIMIT):
            with self.assertRaises(M.Refused):
                M.parse_result(good, stderr, BINDING, "first-save")
        self.assertEqual(M.failure_step(b"", b"MRK_MACOS_AQUA_FAILURE_STEP=Review(1)\n"), "Review(1)")
        self.assertIsNone(M.failure_step(b"", b"MRK_MACOS_AQUA_FAILURE_STEP=PRIVATE_UNKNOWN_DATA\n"))

    def test_failure_reason_records_are_closed_complete_and_unique(self):
        prefix = b"MRK_MACOS_AQUA_FAILURE_REASON"
        good = prefix + b"=native-attachment-lost\n"
        for label in M.FAILURE_REASONS:
            self.assertLessEqual(len(label.encode("ascii")), 48)
            row = prefix + b"=" + label.encode("ascii") + b"\n"
            self.assertEqual(M.failure_reason(row, b""), label)
            self.assertEqual(M.failure_reason(b"", row), label)
        invalid = (b"", good[:-1], b"log " + good, good.replace(b"\n", b"\r\n"),
                   prefix + b"=PRIVATE_UNKNOWN_DATA\n", prefix + b"=\xff\n", prefix + b"=\n",
                   prefix + b"=" + b"a" * 49 + b"\n", good + good,
                   good + prefix + b"?malformed\n", good + b"log " + prefix,
                   good + b"x" * M.OUTPUT_LIMIT)
        for row in invalid:
            with self.subTest(row=row[:80]):
                self.assertIsNone(M.failure_reason(row, b""))
        self.assertIsNone(M.failure_reason(good, prefix + b"=unknown\n"))
        self.assertIsNone(M.failure_reason(good, prefix))
        self.assertIsNone(M.failure_reason(good, "not-bytes"))
        with self.assertRaisesRegex(M.Refused, "^inner-failure-marker$"):
            M.parse_result(captured(M.expected_result(BINDING, "first-save")), good, BINDING, "first-save")

    def test_projectsettled_site_reason_is_still_a_failed_result(self):
        # Synthetic diagnostic DATA only: not the retained native failure or
        # a reconstruction of its unknown project/snapshot result.
        frame = (b"MRK_MACOS_AQUA_FAILURE_STEP=ProjectSettled\n"
                 b"MRK_MACOS_AQUA_FAILURE_REASON=snapshot-error-cleanup\n")
        self.assertEqual(M.failure_step(b"", frame), "ProjectSettled")
        self.assertEqual(M.failure_reason(b"", frame), "snapshot-error-cleanup")
        with self.assertRaisesRegex(M.Refused, "^inner-failure-marker$"):
            M.parse_result(captured(M.expected_result(BINDING, "first-save")), frame, BINDING, "first-save")

    def test_failure_step_rejects_partial_and_ambiguous_exception_buffers(self):
        prefix = b"MRK_MACOS_AQUA_FAILURE_STEP"
        good = prefix + b"=CancelProject\n"
        for step in M.FAILURE_STEPS:
            self.assertEqual(M.failure_step(b"", prefix + b"=" + step.encode("ascii") + b"\n"), step)
        for bad in (good[:-1], b"log " + good, good + good, good + prefix, good + b"log " + prefix,
                    good.replace(b"\n", b"\r\n"), prefix + b"=Prepare(2)\n", prefix + b"=\xff\n"):
            self.assertIsNone(M.failure_step(bad, b""))
        self.assertIsNone(M.failure_step(good, prefix + b"?malformed\n"))
        self.assertIsNone(M.failure_step(good, bytearray()))

    def test_failure_context_is_closed_nullable_and_not_a_receipt(self):
        good = context_data()
        self.assertEqual(M.failure_context(b"", context_row(good)), good)
        empty = {"pending": None, "nativeHandler": None, "lastPanel": None}
        self.assertEqual(M.failure_context(context_row(empty), b""), empty)
        for parent, panel in ((False, False), (True, False), (False, True)):
            value = deepcopy(good)
            value["lastPanel"].update(parentPresent=parent, panelPresent=panel, parentReferencesPanel=None,
                                       panelReferencesParent=None, panelVisible=False if panel else None)
            self.assertEqual(M.failure_context(context_row(value), b""), value)
        for pending in ({"kind": "reload", "step": None}, {"kind": "failure-close", "step": None},
                        {"kind": "dom", "step": "Review(1)"}, {"kind": "dom", "step": "ChooseCancel"},
                        {"kind": "close", "step": "CloseCancel"}):
            value = deepcopy(empty); value["pending"] = pending
            self.assertEqual(M.failure_context(context_row(value), b""), value)
        variants = []
        for target, field, value in (("lastPanel", "id", True), ("lastPanel", "id", 5),
                                     ("lastPanel", "kind", "private-class"), ("lastPanel", "step", "Quit"),
                                     ("lastPanel", "parentPresent", 1), ("lastPanel", "parentReferencesPanel", None),
                                     ("lastPanel", "panelVisible", "false"), ("nativeHandler", "entered", False),
                                     ("nativeHandler", "returned", 1), ("pending", "kind", "foreign"),
                                     ("pending", "step", "Prepare(0)")):
            item = deepcopy(good); item[target][field] = value; variants.append(item)
        item = deepcopy(good); item["lastPanel"].update(panelPresent=False, panelVisible=None); variants.append(item)
        item = deepcopy(good); item["lastPanel"]["path"] = "PRIVATE"; variants.append(item)
        item = deepcopy(good); item["nativeHandler"] = None; variants.append(item)
        item = deepcopy(empty); item["nativeHandler"] = {"step": "Quit", "entered": False, "returned": True}; variants.append(item)
        item = deepcopy(empty); item["pending"] = {"kind": "dom", "step": "ChooseCancel", "sequence": 1}; variants.append(item)
        for item in variants:
            self.assertIsNone(M.failure_context(context_row(item), b""))
        row = context_row(good)
        for bad in (row[:-1], row + row, b"log " + row, row + b"MRK_MACOS_AQUA_FAILURE_CONTEXT?\n",
                    row.replace(b'"id":1', b'"id":1,"id":1'), row.replace(b'"id":1', b'"id":NaN'),
                    b"MRK_MACOS_AQUA_FAILURE_CONTEXT=" + b" " * (M.FAILURE_CONTEXT_LIMIT + 1) + b"\n"):
            self.assertIsNone(M.failure_context(bad, b""))
        with self.assertRaisesRegex(M.Refused, "^inner-failure-marker$"):
            M.parse_result(captured(M.expected_result(BINDING, "first-save")), row, BINDING, "first-save")

    def test_project_selection_axes_are_closed_independent_saved_data(self):
        for case in ("first-save", "noop-stale", "save-loss"):
            for recorded in M.PROJECT_SELECTION_OBJECTS - {"unavailable"}:
                if recorded == "captured-release-all5" and case != "noop-stale":
                    continue
                for reason, locations in M.PROJECT_SELECTION_BOUND_LOCATIONS.items():
                    for location in locations:
                        value = project_selection_context_data(recorded=recorded, location=location)
                        for step in ("OpenProject", "ProjectSettled"):
                            self.assertEqual(M.failure_context(b"", project_selection_row(value, reason, step), case), value)
            for recorded, location in (("fixture-root-all5", "unavailable"), ("unavailable", "outside-namespace"),
                                       ("unavailable", "unavailable")):
                value = project_selection_context_data("unavailable-original-data", recorded, location)
                self.assertEqual(M.failure_context(b"", project_selection_row(value), case), value)
            for recorded in ("fixture-root-all5", "different-object", "unavailable"):
                for location in M.PROJECT_SELECTION_LOCATIONS:
                    value = project_selection_context_data("inconsistent-original-data", recorded, location)
                    self.assertEqual(M.failure_context(b"", project_selection_row(value), case), value)
        historical = context_data()
        self.assertEqual(M.failure_context(context_row(historical), b"", "first-save"), historical)
        # Full current context plus the longest new labels stays within the
        # bounded decoder limit shared with the producer's ceiling.
        full = accessibility_context_data()
        full.update(snapshotSource="record", originalWindow=deepcopy(M.expected_result(BINDING, "first-save")["native"]["originalWindow"]),
                    accessibilityBinding=deepcopy(M.expected_result(BINDING, "first-save")["native"]["projectOpenBinding"]),
                    projectSelection=project_selection_context_data("inconsistent-original-data", "captured-object-metadata-changed")["projectSelection"])
        self.assertEqual(M.failure_context(b"", project_selection_row(full), "first-save"), full)
        self.assertEqual(M.FAILURE_CONTEXT_LIMIT, 8192)
        self.assertLessEqual(len(context_row(full).split(b"=", 1)[1].rstrip(b"\n")), M.FAILURE_CONTEXT_LIMIT)
        self.assertLessEqual(len(project_selection_row(full)), 8448)

    def test_project_selection_rejects_unbound_frames_private_fields_and_inconsistent_shapes(self):
        good = project_selection_context_data()
        variants = []
        for value in (None, True, [], "PRIVATE", {}, {**good["projectSelection"], "path": "/PRIVATE"},
                      {**good["projectSelection"], "sha256": "PRIVATE"}, {**good["projectSelection"], "inode": 1}):
            item = deepcopy(good); item["projectSelection"] = value; variants.append(item)
        for key in good["projectSelection"]:
            item = deepcopy(good); del item["projectSelection"][key]; variants.append(item)
            for value in (None, True, 1, [], {}, "PRIVATE"):
                item = deepcopy(good); item["projectSelection"][key] = value; variants.append(item)
        for recorded, location in (("unavailable", "outside-namespace"), ("fixture-root-all5", "unavailable"),
                                   ("fixture-root-all5", "current-project")):
            variants.append(project_selection_context_data(recorded=recorded, location=location))
        variants.append(project_selection_context_data("unavailable-original-data", "fixture-root-all5", "outside-namespace"))
        variants.append(project_selection_context_data("unavailable-original-data", "unavailable", "current-project"))
        variants.append(project_selection_context_data(recorded="captured-release-all5"))
        for source in (None, "prearm-open-progress", "PRIVATE"):
            item = deepcopy(good); item["snapshotSource"] = source; variants.append(item)
        item = deepcopy(good); del item["snapshotSource"]; variants.append(item)
        for item in variants:
            self.assertIsNone(M.failure_context(b"", project_selection_row(item), "first-save"))
        for reason, locations in M.PROJECT_SELECTION_BOUND_LOCATIONS.items():
            for location in M.PROJECT_SELECTION_LOCATIONS - locations:
                self.assertIsNone(M.failure_context(b"", project_selection_row(project_selection_context_data(location=location), reason), "first-save"))
        for case in ("picker-loss", "PRIVATE", True):
            self.assertIsNone(M.failure_context(b"", project_selection_row(good), case))
        row = project_selection_row(good)
        for bad in (context_row(good), project_selection_row(good, "observer-deadline"), project_selection_row(good, step="Snapshot"),
                    row + b"MRK_MACOS_AQUA_FAILURE_REASON=project-result-path\n",
                    row.replace(b'"custody":"bound-original-data"', b'"custody":"bound-original-data","custody":"bound-original-data"'),
                    row.replace(b'"recordedObject":"fixture-root-all5"', b'"recordedObject":NaN'),
                    row.replace(b'"lexicalLocation":"outside-namespace"', b'"lexicalLocation":"' + b"x" * M.FAILURE_CONTEXT_LIMIT + b'"')):
            self.assertIsNone(M.failure_context(b"", bad, "first-save"))
        with self.assertRaisesRegex(M.Refused, "^inner-failure-marker$"):
            M.parse_result(captured(M.expected_result(BINDING, "first-save")), row, BINDING, "first-save")

    def test_project_selection_original_exception_does_not_become_finality_or_readback(self):
        value = project_selection_context_data()
        with inert_exception_owner(stderr=project_selection_row(value)) as call:
            fixtures = InertFixtures()
            with self.assertRaises(RuntimeError) as caught:
                M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
            self.assertIs(caught.exception, call.original)
            report = M.diagnostic(caught.exception, None, fixtures)
            self.assertEqual(report["innerFailureContext"], value)
            self.assertEqual((report["innerFailureStep"], report["innerFailureReason"]), ("ProjectSettled", "project-result-path"))
            self.assertEqual((report["invocationFinality"], report["innerDiagnosticCompleteness"]), ("unknown", "unknown"))
            self.assertIsNone(report["appReturncode"])
            self.assertFalse(report["originalCallReturned"])
            self.assertTrue(fixtures.inflight)
            self.assertEqual((fixtures.before, fixtures.reads), (["first-save"], []))

    def test_project_chooser_context_preserves_original_returned_scalar_history(self):
        base = {"snapshotSource": "record", "pending": None, "nativeHandler": None, "lastPanel": None}
        for count in (0, 1, 160):
            value = {**base, "dom": {"evaluations": count, "lastProjectChooser": None}}
            self.assertEqual(M.failure_context(context_row(value), b""), value)
        cases = [(False, None, "none"), (True, None, "none"), (True, False, "none")]
        cases += [(True, True, reason) for reason in M.DOM_CHOOSER_REASONS]
        for step in ("ChooseCancel", "ChooseProject"):
            for dashboard, disabled, reason in cases:
                sample = {"step": step, "sequence": 1, "dashboardSelected": dashboard,
                          "buttonDisabled": disabled, "reason": reason}
                # A retained earlier callback remains historical even though
                # more DOM evaluations occurred; it is not a fresh observation.
                value = {**base, "dom": {"evaluations": 160, "lastProjectChooser": sample}}
                self.assertEqual(M.failure_context(context_row(value), b""), value)
        # Even enabled/returned DATA plus a successful-looking result cannot
        # erase the actual failure marker or establish native finality.
        sample = {"step": "ChooseProject", "sequence": 160, "dashboardSelected": True,
                  "buttonDisabled": False, "reason": "none"}
        value = {**base, "dom": {"evaluations": 160, "lastProjectChooser": sample}}
        with self.assertRaisesRegex(M.Refused, "^inner-failure-marker$"):
            M.parse_result(captured(M.expected_result(BINDING, "first-save")), context_row(value), BINDING, "first-save")

    def test_project_chooser_context_refuses_open_types_and_contradictions(self):
        sample = {"step": "ChooseProject", "sequence": 160, "dashboardSelected": True,
                  "buttonDisabled": True, "reason": "metadata-images"}
        base = {"snapshotSource": "record", "pending": None, "nativeHandler": None, "lastPanel": None,
                "dom": {"evaluations": 160, "lastProjectChooser": sample}}
        variants = []
        for key, value in (("evaluations", True), ("evaluations", -1), ("evaluations", 161),
                           ("evaluations", 160.0), ("evaluations", 159), ("extra", "PRIVATE"),
                           ("lastProjectChooser", [])):
            bad = deepcopy(base); bad["dom"][key] = value; variants.append(bad)
        for key, value in (("step", "OpenProject"), ("step", None), ("sequence", True), ("sequence", 0),
                           ("sequence", 161), ("sequence", 160.0), ("dashboardSelected", 1),
                           ("dashboardSelected", False), ("buttonDisabled", 0), ("buttonDisabled", "false"),
                           ("buttonDisabled", False), ("reason", "PRIVATE"), ("reason", []),
                           ("reason", "x" * 4096), ("reasonText", "PRIVATE"), ("window", 1)):
            bad = deepcopy(base); bad["dom"]["lastProjectChooser"][key] = value; variants.append(bad)
        for field in base["dom"]:
            bad = deepcopy(base); del bad["dom"][field]; variants.append(bad)
        for field in sample:
            bad = deepcopy(base); del bad["dom"]["lastProjectChooser"][field]; variants.append(bad)
        for source in ("prearm-open-progress", None):
            bad = deepcopy(base); bad["snapshotSource"] = source; variants.append(bad)
        bad = deepcopy(base); del bad["snapshotSource"]; variants.append(bad)
        for value in (None, [], "PRIVATE"):
            bad = deepcopy(base); bad["dom"] = value; variants.append(bad)
        for bad in variants:
            self.assertIsNone(M.failure_context(context_row(bad), b""))

    def test_project_chooser_diagnostics_use_existing_original_and_unchanged_bounds(self):
        observer = (PATH.parents[1] / "src-tauri" / "src" / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        labels = observer.split("const CHOOSER_REASON_FAMILIES: &[&str] = &[", 1)[1].split("];", 1)[0]
        self.assertEqual(set(M.re.findall(r'"([a-z-]+)"', labels)), M.DOM_CHOOSER_REASONS)
        self.assertIn('if r.evaluations >= 160 { self.fail_with("dom-evaluation-budget"); return; }', observer)
        self.assertIn('else { 45 }', observer)
        self.assertIn('edit::bounded(&failure_context(&self), 8192)', observer)
        self.assertIn('(frame.len() <= 8448).then_some(frame)', observer)
        self.assertIn("self.dom = None;", observer.split("fn at_expiry(", 1)[1].split("fn frame(", 1)[0])
        body = observer.split("    fn dom_body(", 1)[1].split("    pub(super) fn relay_joined", 1)[0]
        self.assertLess(body.index("project_chooser_sample(original, &v)"), body.index("r.last_project_chooser = Some(sample)"))
        self.assertIn('if v["state"] == "wait" && object.len() == 1 { return; }', body)
        self.assertIn('if !project_chooser_data_checks() { return false; }', observer)
        chooser = observer.split("Step::ChooseCancel|Step::ChooseProject =>", 1)[1].split("Step::ReadCancelled =>", 1)[0]
        self.assertIn("document.getElementById('project-choose-reason')", chooser)
        self.assertIn("??'other'", chooser)
        self.assertEqual(chooser.count("b.click()"), 1)
        self.assertLess(chooser.index("if(!b||b.disabled)return {state:'wait',projectChooser}"), chooser.index("b.click()"))
        self.assertIn("return {state:'ready',projectChooser}", chooser)
        self.assertNotIn("projectChooser.reason=reasonText;", chooser)

    def test_original_window_success_requires_the_returned_positive_witness(self):
        for case in M.CASES:
            good = M.expected_result(BINDING, case)
            self.assertEqual(M.parse_result(captured(good), b"", BINDING, case), good)
            variants = []
            missing = deepcopy(good); del missing["native"]["originalWindow"]; variants.append(missing)
            unknown = deepcopy(good); unknown["native"]["originalWindow"] = None; variants.append(unknown)
            for key, value in (("mechanism", "label-lookup"), ("accessorReturned", False),
                               ("nativeReturned", False), ("result", "native-error"),
                               ("admitted", False), ("state", None), ("address", 1)):
                bad = deepcopy(good); bad["native"]["originalWindow"][key] = value; variants.append(bad)
            for key in good["native"]["originalWindow"]["state"]:
                for value in (False, None, 1):
                    bad = deepcopy(good); bad["native"]["originalWindow"]["state"][key] = value; variants.append(bad)
            for bad in variants:
                with self.assertRaises(M.Refused):
                    M.parse_result(captured(bad), b"", BINDING, case)

    def test_original_window_failure_keeps_unknown_unsatisfied_error_and_late_distinct(self):
        base = {"pending": None, "nativeHandler": None, "lastPanel": None}
        positive = M.expected_result(BINDING, "first-save")["native"]["originalWindow"]
        samples = [None, deepcopy(positive)]
        late = deepcopy(positive); late["admitted"] = False; samples.append(late)
        inactive = deepcopy(late); inactive["state"]["active"] = False; samples.append(inactive)
        absent = deepcopy(late); absent["state"] = dict.fromkeys(absent["state"], False); samples.append(absent)
        no_main = deepcopy(absent); no_main["state"].update(applicationPresent=True, active=True); samples.append(no_main)
        for result in ("accessor-error", "entry-refused", "native-error", "invalid-return"):
            error = deepcopy(late); error.update(result=result, state=None, nativeReturned=result != "accessor-error")
            samples.append(error)
        for sample in samples:
            value = {**base, "originalWindow": sample}
            self.assertEqual(M.failure_context(context_row(value), b""), value)
        # Even positive historical DATA cannot turn a failure row into success.
        with self.assertRaisesRegex(M.Refused, "^inner-failure-marker$"):
            M.parse_result(captured(M.expected_result(BINDING, "first-save")),
                           context_row({**base, "originalWindow": positive}), BINDING, "first-save")

    def test_original_window_context_refuses_contradictions_and_open_fields(self):
        base = {"pending": None, "nativeHandler": None, "lastPanel": None}
        good = M.expected_result(BINDING, "first-save")["native"]["originalWindow"]
        variants = []
        for key, value in (("mechanism", "foreign"), ("accessorReturned", False), ("accessorReturned", 1),
                           ("nativeReturned", False), ("nativeReturned", 1), ("result", "foreign"),
                           ("result", "native-error"), ("admitted", 1), ("state", None), ("address", "PRIVATE")):
            bad = deepcopy(good); bad[key] = value; variants.append(bad)
        for key in good:
            bad = deepcopy(good); del bad[key]; variants.append(bad)
        for key in good["state"]:
            bad = deepcopy(good); bad["state"][key] = 1; variants.append(bad)
            bad = deepcopy(good); del bad["state"][key]; variants.append(bad)
        for key in ("applicationPresent", "mainPresent", "active", "originalMain", "ordinaryWindow", "noAttachedSheet"):
            bad = deepcopy(good); bad["state"][key] = False; variants.append(bad)
        bad = deepcopy(good); bad["admitted"] = False; bad["state"]["applicationPresent"] = False; variants.append(bad)
        bad = deepcopy(good); bad["admitted"] = False; bad["state"]["mainPresent"] = False; variants.append(bad)
        bad = deepcopy(good); bad["state"]["windowTitle"] = "PRIVATE"; variants.append(bad)
        for bad in variants:
            self.assertIsNone(M.failure_context(context_row({**base, "originalWindow": bad}), b""))

    def test_semantic_action_actual_return_and_timeout_are_not_completion(self):
        good = accessibility_context_data()
        self.assertEqual(M.failure_context(b"", context_row(good), "first-save"), good)
        for state in ("requested", "queued", "entered", "returned", "joined", "unknown"):
            value = deepcopy(good); sample = value["accessibility"]
            sample.update(state=state, dispatchAttempted=state != "requested", workerRegistered=state != "requested",
                          bodyEntered=state not in ("requested", "queued"), nativeEntered=None,
                          bodyReturned=state in ("returned", "joined", "unknown"), receiptJoined=state == "joined",
                          workerJoined=state == "joined", rechecksSettled=True if state == "joined" else None, barrierRetired=False,
                          expired=True, timely=False, custodyKnown=False if state == "unknown" else True if state == "joined" else None,
                          attempted=None, pressReturned=None, triggered=None, initialOriginalProof=None, originalProof=None,
                          promptChecks={"initial": None, "final": None}, promptButton=None, site=None, error=None)
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)
            self.assertFalse(M._accessibility_succeeded(sample))
            value["snapshotSource"] = "prearm-open-progress"
            value["pending"] = {"kind": "accessibility", "step": "OpenProject"}
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)
            for key, bad in (("pending", None), ("snapshotSource", "current")):
                conflict = deepcopy(value); conflict[key] = bad
                self.assertIsNone(M.failure_context(b"", context_row(conflict), "first-save"))
        # The actual body/receipt can arrive while its original thread is still
        # alive. Neither those facts nor later expiry grant release or success.
        receipt = deepcopy(good); sample = receipt["accessibility"]
        sample.update(state="returned", receiptJoined=False, workerJoined=False, barrierRetired=False)
        self.assertEqual(M.failure_context(b"", context_row(receipt), "first-save"), receipt)
        self.assertFalse(M._accessibility_succeeded(sample))
        for changes in ({"receiptJoined": True}, {"barrierRetired": True, "state": "retired"}):
            invalid = deepcopy(receipt); invalid["accessibility"].update(changes)
            expected = deepcopy(invalid); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(invalid), "first-save"), expected)
        late = deepcopy(good); late["accessibility"].update(expired=True, timely=False)
        self.assertEqual(M.failure_context(b"", context_row(late), "first-save"), late)
        self.assertFalse(M._accessibility_succeeded(late["accessibility"]))
        caught = deepcopy(good); sample = caught["accessibility"]
        sample.update(state="unknown", receiptJoined=False, barrierRetired=False, custodyKnown=False,
                      pressReturned=False, triggered=None, error="objc-exception")
        sample["promptButton"].update(cleanupReturned=False, cfSlotsRetired=16)
        self.assertEqual(M.failure_context(b"", context_row(caught), "first-save"), caught)
        self.assertFalse(M._accessibility_succeeded(sample))
        history = deepcopy(good); history["accessibility"].update(state="unknown", custodyKnown=False)
        self.assertEqual(M.failure_context(b"", context_row(history), "first-save"), history)
        self.assertFalse(M._accessibility_succeeded(history["accessibility"]))

    def test_semantic_closed_parser_rejects_fabricated_old_or_conflicting_facts(self):
        good = accessibility_context_data()
        for key, bad in (("mechanism", "accessibility-confirm-original-open-panel-v1"),
                         ("mechanism", "accessibility-press-original-default-frame-v1"),
                         ("mechanism", "accessibility-press-original-semantic-element-v1"),
                         ("mechanism", "accessibility-press-original-prompt-button-v1"),
                         ("mechanism", "accessibility-press-original-direct-sheet-button-v2"),
                         ("mechanism", "accessibility-press-original-control-container-button-v3"),
                         ("mechanism", "accessibility-select-original-row-and-press-v4"),
                         ("rowSelection", {}), ("selectedTarget", "match"), ("id", True), ("id", 1),
                         ("bodyReturned", False), ("nativeEntered", False), ("receiptJoined", False),
                         ("workerRegistered", False), ("workerJoined", False), ("rechecksSettled", False),
                         ("custodyKnown", False), ("pressReturned", False), ("triggered", None), ("prepared", False),
                         ("expired", True), ("initialOriginalProof", None), ("calls", 0), ("cleanupReturned", True),
                         ("initialProjection", None), ("defaultRecheck", None), ("confirmReturned", True),
                         ("confirmEligibility", None), ("confirmRecheck", None), ("attempts", 2)):
            value = deepcopy(good); value["accessibility"][key] = bad
            expected = deepcopy(value); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), expected, (key, bad))
        for state in ("prepared", "requested", "queued", "entered", "returned", "unknown"):
            value = deepcopy(good)
            value["accessibility"].update(state=state, barrierRetired=False, receiptJoined=False)
            if state == "returned": value["accessibility"]["bodyReturned"] = False
            expected = deepcopy(value); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), expected, state)
        for path in (("initialOriginalProof", "checks", "eligible"), ("originalProof", "checks", "nativeChild"),
                     ("promptChecks", "initial"), ("promptChecks", "final"),
                     *(("promptButton", "checks", key) for key in M.ACCESSIBILITY_BUTTON_CHECKS)):
            value = deepcopy(good); target = value["accessibility"]
            for part in path[:-1]: target = target[part]
            target[path[-1]] = False
            expected = deepcopy(value); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), expected, path)
        for key, bad in (("calls", True), ("calls", 0), ("calls", 513),
                         ("initialNodesExamined", True), ("initialNodesExamined", 0), ("initialNodesExamined", 17),
                         ("recheckNodesExamined", True), ("recheckNodesExamined", 0), ("recheckNodesExamined", 17),
                         ("lastRole", True), ("lastRole", "unknown"), ("lastRole", "Group"),
                         ("lastDepth", True), ("lastDepth", 0), ("lastDepth", 9), ("lastDepth", 3),
                         ("cfSlots", 257), ("cfSlotsRetired", 31), ("cfSlotsRetired", 33),
                         ("cleanupReturned", False), ("axError", True), ("axError", -25215), ("axError", -25199),
                         ("buttonTitle", "PRIVATE"), ("sheet", "PRIVATE")):
            value = deepcopy(good); value["accessibility"]["promptButton"][key] = bad
            expected = deepcopy(value); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), expected, (key, bad))
        for old, current in (("completeSearch", "completeControlProjection"), ("uniqueButton", "uniquePromptButton"),
                             ("finalRecheck", "sameOriginalControlPathRechecked"),
                             ("completeDirectSheetChildren", "completeControlProjection"),
                             ("uniqueDirectPromptButton", "uniquePromptButton"),
                             ("sameDirectButtonRechecked", "sameOriginalControlPathRechecked")):
            for replace in (False, True):
                value = deepcopy(good); checks = value["accessibility"]["promptButton"]["checks"]
                checks[old] = True
                if replace: del checks[current]
                expected = deepcopy(value); expected["accessibility"] = None
                self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), expected, (old, replace))
        for old in ("nodes", "directChildrenExamined"):
            for replace in (False, True):
                value = deepcopy(good); button = value["accessibility"]["promptButton"]
                button[old] = button["initialNodesExamined"]
                if replace: del button["initialNodesExamined"]
                expected = deepcopy(value); expected["accessibility"] = None
                self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), expected, (old, replace))

    def test_success_requires_all_semantic_native_and_original_join_obligations(self):
        for case in M.CASES:
            good = M.expected_result(BINDING, case)
            self.assertEqual(M.parse_result(captured(good), b"", BINDING, case), good)
            if case == "picker-loss": continue
            sample = good["native"]["projectOpenInput"]
            self.assertEqual(sample["mechanism"], "accessibility-preconfigured-original-press-v5")
            for key, bad in (("expired", True), ("timely", False), ("barrierRetired", False), ("receiptJoined", False),
                             ("workerRegistered", False), ("workerJoined", False), ("rechecksSettled", False),
                             ("custodyKnown", False), ("bodyReturned", False), ("triggered", False), ("attempted", False),
                             ("dispatchAttempted", False), ("state", "unknown"), ("initialOriginalProof", None)):
                value = deepcopy(good); value["native"]["projectOpenInput"][key] = bad
                with self.assertRaises(M.Refused, msg=(case, key)): M.parse_result(captured(value), b"", BINDING, case)
            for key in ("accessibilityTrustedWithoutPrompt", "selectedPathMatched", "originalDocumentAndQuitSettled"):
                value = deepcopy(good); value["native"][key] = False
                with self.assertRaises(M.Refused): M.parse_result(captured(value), b"", BINDING, case)
            for count in (1, 6, 16):
                value = deepcopy(good)
                value["native"]["projectOpenInput"]["originalProof"]["children"] = count
                value["native"]["projectOpenBinding"]["binding"]["children"] = count
                self.assertEqual(M.parse_result(captured(value), b"", BINDING, case), value)
            # Literal direct, grouped and bounded-maximum proof DATA; these
            # parser cases do not claim to have observed an AppKit topology.
            for initial, recheck, depth in ((1, 1, 1), (4, 6, 3), (16, 16, 8)):
                value = deepcopy(good)
                value["native"]["projectOpenInput"]["promptButton"].update(
                    calls=512, initialNodesExamined=initial, recheckNodesExamined=recheck,
                    lastRole="Button", lastDepth=depth, cfSlots=256, cfSlotsRetired=256)
                self.assertEqual(M.parse_result(captured(value), b"", BINDING, case), value)

    def test_preconfigured_press_requires_separate_exact_completion(self):
        for case in M.CASES:
            good = M.expected_result(BINDING, case)
            self.assertEqual(M.parse_result(captured(good), b"", BINDING, case), good)
            self.assertEqual(good["native"]["controlReturns"],
                             [case == "first-save", case != "picker-loss", case == "first-save", True])
            old = deepcopy(good); old["native"]["controlReturns"].insert(1, case != "picker-loss")
            with self.assertRaises(M.Refused): M.parse_result(captured(old), b"", BINDING, case)
            if case == "picker-loss":
                for key in ("projectOpenInput", "projectOpenBinding", "projectCompletionSelection"):
                    self.assertIsNone(good["native"][key])
                    bad = deepcopy(good); bad["native"][key] = M.expected_result(BINDING, "noop-stale")["native"][key]
                    with self.assertRaises(M.Refused): M.parse_result(captured(bad), b"", BINDING, case)
                continue
            sample = good["native"]["projectOpenInput"]
            self.assertEqual(sample["mechanism"], "accessibility-preconfigured-original-press-v5")
            self.assertNotIn("rowSelection", sample); self.assertNotIn("selectedTarget", sample)
            self.assertTrue(M._accessibility_succeeded(sample))
            binding = good["native"]["projectOpenBinding"]
            self.assertEqual(binding["mechanism"], "preconfigured-original-sheet-v2")
            for field in ("initialDirectorySetterEntered", "initialDirectorySetterReturned"):
                self.assertIs(binding["configuration"][field], True)
            completion = good["native"]["projectCompletionSelection"]
            self.assertEqual(M._completion_selection_context(completion, case), completion)
            self.assertTrue(M._completion_selection_succeeded(completion))
            # Ready browsing and an actual returned Press cannot supply absent
            # completion or rescue PS's real wrong-object / outside-root result.
            for absent in (None, {}):
                bad = deepcopy(good); bad["native"]["projectCompletionSelection"] = absent
                with self.assertRaises(M.Refused): M.parse_result(captured(bad), b"", BINDING, case)
            missing = deepcopy(good); del missing["native"]["projectCompletionSelection"]
            with self.assertRaises(M.Refused): M.parse_result(captured(missing), b"", BINDING, case)
            for selected in ("empty", "malformed", "multiple", "different", "ordinary-path-disagreement"):
                bad = deepcopy(good); failed = bad["native"]["projectCompletionSelection"]
                failed["facts"]["selection"] = selected
                self.assertEqual(M._completion_selection_context(failed, case), failed)
                self.assertFalse(M._completion_selection_succeeded(failed))
                self.assertIs(failed["facts"]["nativeUnknown"], False)
                self.assertTrue(M._accessibility_succeeded(bad["native"]["projectOpenInput"]))
                with self.assertRaises(M.Refused, msg=(case, selected)): M.parse_result(captured(bad), b"", BINDING, case)
            for field in ("selectedPathMatched", "originalDocumentAndQuitSettled"):
                bad = deepcopy(good); bad["native"][field] = False
                with self.assertRaises(M.Refused): M.parse_result(captured(bad), b"", BINDING, case)

    def test_completion_selection_closed_decoder_rejects_mixed_or_foreign_facts(self):
        good = completion_context_data()
        self.assertEqual(M.failure_context(b"", context_row(good), "first-save"), good)
        def reject(value):
            expected = deepcopy(value); expected["completionSelection"] = None
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), expected)
        for field, invalid in (("mechanism", "public-original-sheet-v1"), ("mechanism", "accessibility-select-original-row-and-press-v4"),
                ("case", "noop-stale"), ("case", "picker-loss"), ("id", True), ("id", 1), ("id", 3),
                ("kind", "quit"), ("pollReturned", False), ("pollReturned", 1), ("pollResult", None),
                ("pollResult", "unknown"), ("pollResult", 1), ("timely", 1), ("timely", None),
                ("facts", []), ("facts", {}), ("facts", "PRIVATE"), ("path", "PRIVATE"), ("rowSelection", {})):
            value = deepcopy(good); value["completionSelection"][field] = invalid; reject(value)
        for field in good["completionSelection"]:
            value = deepcopy(good); del value["completionSelection"][field]; reject(value)
        flags = ("callbackEntered", "urlsReadEntered", "urlsReadReturned", "callbackReturned", "duplicate", "nativeUnknown")
        for field in flags:
            for invalid in (None, 0, 1, "true"):
                value = deepcopy(good); value["completionSelection"]["facts"][field] = invalid; reject(value)
        for field in good["completionSelection"]["facts"]:
            value = deepcopy(good); del value["completionSelection"]["facts"][field]; reject(value)
        for field, invalid in (("response", "ok"), ("response", True), ("response", 1),
                ("selection", "not-ready"), ("selection", "entered-not-returned"), ("selection", True),
                ("selection", 1), ("selectedTarget", "match"), ("urls", ["PRIVATE"]), ("attempts", 2)):
            value = deepcopy(good); value["completionSelection"]["facts"][field] = invalid; reject(value)
        for changes in ({"callbackEntered": False}, {"urlsReadEntered": False}, {"urlsReadReturned": False},
                        {"callbackReturned": False}, {"response": None}, {"response": "decline"},
                        {"selection": None}, {"duplicate": True}):
            value = deepcopy(good); value["completionSelection"]["facts"].update(changes); reject(value)
        # Missing/foreign diagnostic binding removes only the new subframe; it
        # never invents a nativeHandler or changes the saved first failure.
        for case in (None, "noop-stale", "save-loss", "picker-loss", "foreign"):
            expected = deepcopy(good); expected["completionSelection"] = None
            self.assertEqual(M.failure_context(b"", context_row(good), case), expected)
        without_source = deepcopy(good); del without_source["snapshotSource"]
        reject(without_source)
        row = context_row(good)
        duplicated = row.replace(b'"pollReturned":true', b'"pollReturned":true,"pollReturned":true')
        self.assertIsNone(M.failure_context(b"", duplicated, "first-save"))
        self.assertIsNone(M.failure_context(b"", row + row, "first-save"))
        for case in ("noop-stale", "save-loss"):
            value = completion_context_data(case)
            self.assertEqual(M.failure_context(b"", context_row(value), case), value)
            self.assertEqual(value["completionSelection"]["id"], 1)

    def test_prompt_common_limit_preserves_original_effect_and_unknown_retirement(self):
        value = accessibility_context_data(); sample = value["accessibility"]
        sample.update(attempted=False, pressReturned=False, triggered=None, site="control-projection", error="limit",
                      originalProof=None, promptChecks={"initial": True, "final": None})
        sample["promptButton"].update(calls=512, cfSlots=256, cfSlotsRetired=256,
            initialNodesExamined=3, recheckNodesExamined=0, lastRole="Group", lastDepth=2,
            checks={key: index < 2 for index, key in enumerate(M.ACCESSIBILITY_BUTTON_CHECKS)})
        for known in (True, False):
            frame = deepcopy(value); failed = frame["accessibility"]
            if not known:
                failed.update(state="unknown", custodyKnown=False, receiptJoined=False, barrierRetired=False)
                failed["promptButton"].update(cleanupReturned=False, cfSlotsRetired=16)
            self.assertEqual(M.failure_context(b"", context_row(frame), "first-save"), frame)
            self.assertFalse(M._accessibility_succeeded(failed))
            self.assertTrue(failed["workerJoined"])  # Actual join does not repair uncertain CF retirement.
            result = M.expected_result(BINDING, "first-save"); result["native"]["projectOpenInput"] = deepcopy(failed)
            with self.assertRaises(M.Refused): M.parse_result(captured(result), b"", BINDING, "first-save")
            mutations = [("attempted", True), ("pressReturned", True), ("triggered", True), ("error", "none"),
                ("promptButton.calls", 513), ("promptButton.cfSlots", 257), ("promptButton.initialNodesExamined", 17)]
            if not known:
                mutations += [("custodyKnown", True), ("receiptJoined", True), ("barrierRetired", True),
                              ("promptButton.cleanupReturned", True)]
            for path, invalid in mutations:
                bad = deepcopy(frame); target = bad["accessibility"]; parts = path.split(".")
                for part in parts[:-1]: target = target[part]
                target[parts[-1]] = invalid
                expected = deepcopy(bad); expected["accessibility"] = None
                self.assertEqual(M.failure_context(b"", context_row(bad), "first-save"), expected, (known, path))

    def test_completion_returned_error_history_preserves_partial_unknown_data(self):
        good = completion_context_data()
        # These are fixed copied scalar histories, not a native callback emulator.
        changes = ({"urlsReadEntered": False, "urlsReadReturned": False, "selection": None},
                   {"urlsReadReturned": False, "selection": None}, {"selection": None},
                   {"selection": "different"}, {"duplicate": True},
                   {"callbackReturned": False, "urlsReadReturned": False, "selection": None},
                   {"callbackEntered": False, "urlsReadEntered": False, "urlsReadReturned": False,
                    "callbackReturned": False, "response": None, "selection": None})
        for change in changes:
            for timely in (True, False):
                value = deepcopy(good); sample = value["completionSelection"]
                sample.update(pollResult="error", timely=timely)
                sample["facts"].update(nativeUnknown=True, **change)
                before = deepcopy(value)
                self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)
                self.assertEqual(value, before)
                self.assertFalse(M._completion_selection_succeeded(sample))
                result = M.expected_result(BINDING, "first-save"); result["native"]["projectCompletionSelection"] = sample
                with self.assertRaises(M.Refused): M.parse_result(captured(result), b"", BINDING, "first-save")
        # Even a complete responded/match sample cannot hide retained Unknown
        # or a duplicate callback behind an otherwise successful poll status.
        for duplicate in (False, True):
            value = deepcopy(good); sample = value["completionSelection"]
            sample["facts"].update(nativeUnknown=True, duplicate=duplicate)
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)
            self.assertFalse(M._completion_selection_succeeded(sample))
            result = M.expected_result(BINDING, "first-save"); result["native"]["projectCompletionSelection"] = sample
            with self.assertRaises(M.Refused): M.parse_result(captured(result), b"", BINDING, "first-save")
        # A returned error with undecodable DATA is still a returned error, not
        # an invented no-completion Showing result or a lost callback history.
        for state in ("showing", "responded", "closed", "error", "invalid-return"):
            value = deepcopy(good); value["completionSelection"].update(pollResult=state, facts=None)
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)
            self.assertFalse(M._completion_selection_succeeded(value["completionSelection"]))
            if state != "responded":
                value["completionSelection"]["facts"] = deepcopy(good["completionSelection"]["facts"])
                self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)
                self.assertFalse(M._completion_selection_succeeded(value["completionSelection"]))
        for response in ("decline", "other"):
            value = deepcopy(good); sample = value["completionSelection"]
            sample["facts"].update(response=response, urlsReadEntered=False, urlsReadReturned=False, selection=None)
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)
            self.assertFalse(M._completion_selection_succeeded(sample))
        late = deepcopy(good); late["completionSelection"]["timely"] = False
        self.assertEqual(M.failure_context(b"", context_row(late), "first-save"), late)
        self.assertFalse(M._completion_selection_succeeded(late["completionSelection"]))
        # The historical pre-arm snapshot can carry progress, never this later
        # original-poll publication, even if the same id/Press appears there.
        prearm = accessibility_context_data(); sample = prearm["accessibility"]
        prearm.update(snapshotSource="prearm-open-progress", pending={"kind": "accessibility", "step": "OpenProject"})
        sample.update(state="queued", bodyEntered=None, nativeEntered=None, bodyReturned=False,
            receiptJoined=False, workerJoined=False, rechecksSettled=None, barrierRetired=False,
            expired=True, timely=False, custodyKnown=None, attempted=None, pressReturned=None, triggered=None,
            initialOriginalProof=None, originalProof=None, promptChecks={"initial": None, "final": None},
            promptButton=None, site=None, error=None)
        self.assertEqual(M.failure_context(b"", context_row(prearm), "first-save"), prearm)
        for completion in (None, good["completionSelection"]):
            bad = deepcopy(prearm); bad["completionSelection"] = completion
            self.assertIsNone(M.failure_context(b"", context_row(bad), "first-save"))

    def test_completion_known_mismatch_preserves_failed_result_and_outer_finality(self):
        detail = project_selection_context_data(recorded="different-object", location="outside-namespace")
        detail["completionSelection"] = completion_context_data()["completionSelection"]
        detail["completionSelection"]["facts"]["selection"] = "different"
        marker = project_selection_row(detail)
        self.assertEqual(M.failure_context(b"", marker, "first-save"), detail)
        self.assertIs(detail["completionSelection"]["facts"]["nativeUnknown"], False)
        # PS-shaped wrong-object DATA remains a failed selected result even
        # after its ordinary original returns. It does not become native Unknown.
        fixtures, emitted = InertFixtures(), []
        def runner(argv, **_):
            return CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=marker)
        with self.assertRaisesRegex(M.Refused, "^app-return$") as caught:
            M.run_cases(BINDING, fixtures, runner, UID, "runner", emitted.append)
        report = M.diagnostic(caught.exception, None, fixtures)
        self.assertEqual(report["innerFailureContext"], detail)
        self.assertEqual((report["status"], report["appReturncode"], report["innerFailureReason"]),
                         ("failed", 1, "project-result-path"))
        self.assertEqual((report["originalCallReturned"], report["invocationFinality"]), (True, "no-pending-invocation"))
        self.assertEqual((fixtures.before, fixtures.reads, emitted), (["first-save"], [], []))
        # Conversely, a known failed inner witness cannot rescue an outer
        # original that never returned. Preserve that same exception and owner.
        with inert_exception_owner(stderr=marker) as call:
            fixtures = InertFixtures()
            with self.assertRaises(RuntimeError) as caught:
                M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
            self.assertIs(caught.exception, call.original)
            report = M.diagnostic(caught.exception, None, fixtures)
            self.assertEqual(report["innerFailureContext"], detail)
            self.assertEqual((report["innerDiagnosticCompleteness"], report["invocationFinality"]), ("unknown", "unknown"))
            self.assertIsNone(report["appReturncode"]); self.assertFalse(report["originalCallReturned"])
            self.assertEqual((fixtures.before, fixtures.reads), (["first-save"], []))

    def test_completion_context_and_result_envelopes_remain_bounded(self):
        self.assertEqual((M.FAILURE_CONTEXT_LIMIT, M.JSON_LIMIT), (8192, 16383))
        prefix, payload = context_row(context_data())[:-1].split(b"=", 1)
        bounded = prefix + b"=" + payload + b" " * (8192 - len(payload)) + b"\n"
        self.assertEqual(M.failure_context(b"", bounded), context_data())
        self.assertIsNone(M.failure_context(b"", bounded[:-1] + b" \n"))
        for selected, unknown, poll in (("ordinary-path-disagreement", False, "responded"), ("multiple", False, "responded"),
                                        (None, True, "error"), ("different", True, "invalid-return")):
            detail = accessibility_context_data(); detail["snapshotSource"] = "record"
            detail["accessibilityBinding"] = binding_context_data()["accessibilityBinding"]
            detail["originalWindow"] = deepcopy(M.expected_result(BINDING, "first-save")["native"]["originalWindow"])
            detail["completionSelection"] = completion_context_data()["completionSelection"]
            detail["completionSelection"]["facts"].update(selection=selected, nativeUnknown=unknown)
            detail["completionSelection"]["pollResult"] = poll
            self.assertEqual(M.failure_context(b"", context_row(detail), "first-save"), detail)
            self.assertLessEqual(len(context_row(detail).split(b"=", 1)[1].rstrip(b"\n")), M.FAILURE_CONTEXT_LIMIT)
            reason = "native-completion-unknown" if unknown else "native-completion-selection"
            marker = (f"MRK_MACOS_AQUA_FAILURE_STEP=ProjectSettled\nMRK_MACOS_AQUA_FAILURE_REASON={reason}\n".encode("ascii")
                      + context_row(detail) + b"MRK_MACOS_AQUA=failed\n")
            fixtures, emitted = InertFixtures(), []
            def runner(argv, **_):
                return CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=marker)
            with self.assertRaisesRegex(M.Refused, "^app-return$") as caught:
                M.run_cases(BINDING, fixtures, runner, UID, "runner", emitted.append)
            report = M.diagnostic(caught.exception, None, fixtures)
            self.assertEqual(report["innerFailureContext"], detail)
            self.assertEqual((report["status"], report["innerFailureStep"], report["innerFailureReason"]), ("failed", "ProjectSettled", reason))
            self.assertEqual((fixtures.before, fixtures.reads, emitted), (["first-save"], [], []))
            stream = io.StringIO(); M.emit_record(report, stream)
            self.assertEqual(json.loads(stream.getvalue()), report)
            self.assertLessEqual(len(stream.getvalue().rstrip("\n").encode("ascii")), 24576)
        for case in M.CASES:
            good = M.expected_result(BINDING, case)
            self.assertLessEqual(len(captured(good)) - len(M.MARKER) - 1, M.JSON_LIMIT)
            self.assertEqual(M.parse_result(captured(good), b"", BINDING, case), good)

    def test_original_prompt_refusal_keeps_original_proof_and_never_invents_action(self):
        # Preparing can fail before an input worker exists. Retain that exact
        # entry diagnostic rather than dropping the closed failure subframe.
        preparing = accessibility_context_data(); sample = preparing["accessibility"]
        sample.update(prepared=False, requested=False, dispatchAttempted=False, state="prepared",
            bodyEntered=False, nativeEntered=False, bodyReturned=False, receiptJoined=False,
            workerRegistered=False, workerJoined=False, rechecksSettled=None, barrierRetired=False,
            timely=None, custodyKnown=None, attempted=False, pressReturned=False, triggered=None,
            initialOriginalProof=None, originalProof=None, promptChecks={"initial": None, "final": None},
            promptButton=None, site="entry", error="ineligible")
        for error in ("ineligible", "changed", "custody", "malformed"):
            sample["error"] = error
            self.assertEqual(M.failure_context(b"", context_row(preparing), "first-save"), preparing)
            self.assertFalse(M._accessibility_succeeded(sample))
        invalid = deepcopy(preparing); invalid["accessibility"]["site"] = "binding"
        expected = deepcopy(invalid); expected["accessibility"] = None
        self.assertEqual(M.failure_context(b"", context_row(invalid), "first-save"), expected)
        nonentry = deepcopy(preparing); sample = nonentry["accessibility"]
        sample.update(prepared=True, requested=True, dispatchAttempted=True, state="unknown", bodyEntered=True,
            workerRegistered=True, workerJoined=True, rechecksSettled=True, custodyKnown=False,
            site="admission", error="custody")
        self.assertEqual(M.failure_context(b"", context_row(nonentry), "first-save"), nonentry)
        self.assertFalse(M._accessibility_succeeded(sample))
        invalid = deepcopy(nonentry); invalid["accessibility"].update(attempted=None, pressReturned=None)
        expected = deepcopy(invalid); expected["accessibility"] = None
        self.assertEqual(M.failure_context(b"", context_row(invalid), "first-save"), expected)
        initial = accessibility_context_data(); sample = initial["accessibility"]
        sample.update(attempted=False, pressReturned=False, triggered=None, site="initial-original-proof", error="ineligible",
                      originalProof=None, promptChecks={"initial": None, "final": None}, promptButton=None)
        sample["initialOriginalProof"].update(parent=None, panel=None, children=None, originals=None,
            checks={key: False if key == "eligible" else None for key in M.ACCESSIBILITY_PROOF_CHECKS}, site="objects", error="ineligible")
        self.assertEqual(M.failure_context(b"", context_row(initial), "first-save"), initial)
        self.assertFalse(M._accessibility_succeeded(sample))
        invalid = deepcopy(initial); invalid["accessibility"]["promptChecks"]["initial"] = True
        expected = deepcopy(invalid); expected["accessibility"] = None
        self.assertEqual(M.failure_context(b"", context_row(invalid), "first-save"), expected)
        def refused_frame(error, site, completed, initial, recheck=0, role="Button", depth=1):
            value = accessibility_context_data(); sample = value["accessibility"]
            sample.update(attempted=False, pressReturned=False, triggered=None, site=site, error=error,
                          originalProof=None, promptChecks={"initial": True, "final": None})
            sample["promptButton"].update(initialNodesExamined=initial, recheckNodesExamined=recheck, lastRole=role, lastDepth=depth)
            sample["promptButton"]["checks"] = {key: index < completed for index, key in enumerate(M.ACCESSIBILITY_BUTTON_CHECKS)}
            value["accessibilityBinding"] = binding_context_data()["accessibilityBinding"]
            return value

        # Literal refusal DATA, not simulated AX execution: an empty root or
        # admitted Group, an unexpanded Browser, two prompt matches (including
        # a disabled duplicate), malformed/shared children, reparenting, and
        # absent/ambiguous/replaced or ineligible second-pass candidates.
        refusals = (("unsupported", "control-projection", 2, 0, 0, "Sheet", 0),
            ("unsupported", "control-projection", 3, 1, 0, "Group", 1),
            ("unsupported", "control-projection", 3, 1, 0, "Browser", 1),
            ("ambiguous", "control-projection", 3, 6, 0, "Button", 3),
            ("malformed", "control-projection", 2, 2, 0, "not-read", 1),
            ("changed", "control-projection", 2, 2, 0, "not-read", 2),
            ("ineligible", "button", 4, 4, 0, "Button", 3), ("changed", "button", 4, 4, 0, "Button", 3),
            ("unsupported", "button", 5, 4, 0, "Button", 3),
            ("unsupported", "control-recheck", 6, 4, 6, "Button", 3),
            ("ambiguous", "control-recheck", 6, 4, 6, "Button", 3),
            ("changed", "control-recheck", 6, 4, 2, "not-read", 2),
            ("ineligible", "control-recheck", 6, 4, 6, "Button", 3))
        for row in refusals:
            value = refused_frame(*row)
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)
            self.assertFalse(M._accessibility_succeeded(value["accessibility"]))
            for key in ("attempted", "pressReturned", "triggered"):
                bad = deepcopy(value); bad["accessibility"][key] = True
                expected = deepcopy(bad); expected["accessibility"] = None
                self.assertEqual(M.failure_context(b"", context_row(bad), "first-save"), expected)

        # Every frame obeys separate pass counts, not the old cumulative-roster
        # grammar. An early recheck failure cannot borrow first-pass depth.
        for row in (("control-projection", 0, 1, 0, "not-read", 1),
                    ("control-projection", 1, 1, 0, "not-read", 1),
                    ("control-projection", 3, 0, 0, "Sheet", 0),
                    ("control-projection", 2, 2, 1, "not-read", 1),
                    ("button", 5, 4, 1, "Button", 2),
                    ("control-recheck", 6, 0, 1, "not-read", 1),
                    ("control-recheck", 7, 4, 0, "Button", 1),
                    ("control-recheck", 6, 8, 1, "not-read", 2)):
            bad = refused_frame("changed", *row)
            expected = deepcopy(bad); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(bad), "first-save"), expected, row)

        limit_shapes = (("control-title-limit", "Button", 1, 1),
            ("control-child-count-limit", "Sheet", 0, 0), ("control-child-count-limit", "Group", 2, 2),
            ("control-child-copy-limit", "Sheet", 0, 0), ("control-child-copy-limit", "SplitGroup", 2, 2),
            ("control-node-limit", "Group", 1, 1), ("control-depth-limit", "SplitGroup", 8, 8))
        self.assertEqual({shape[0] for shape in limit_shapes}, M.ACCESSIBILITY_CONTROL_LIMIT_SITES)
        for site, role, depth, minimum in limit_shapes:
            for completed in (2, 6):
                def limit_frame(examined):
                    return refused_frame("limit", site, completed, examined if completed == 2 else 16,
                                         examined if completed == 6 else 0, role, depth)
                maximum = 0 if depth == 0 else 16
                for examined in (0, 1, 2, 8, 16, 17):
                    value = limit_frame(examined)
                    expected = deepcopy(value)
                    if not minimum <= examined <= maximum: expected["accessibility"] = None
                    self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), expected,
                                     (site, role, depth, completed, examined))
                    self.assertFalse(M._accessibility_succeeded(value["accessibility"]))
                value = limit_frame(minimum)
                sample = value["accessibility"]
                late = deepcopy(value); late["accessibility"].update(expired=True, timely=False)
                self.assertEqual(M.failure_context(b"", context_row(late), "first-save"), late)
                for cleanup_returned in (True, False):
                    unknown = deepcopy(late); lost = unknown["accessibility"]
                    lost.update(state="unknown", custodyKnown=False, receiptJoined=False,
                                barrierRetired=False, rechecksSettled=False)
                    lost["promptButton"].update(cleanupReturned=cleanup_returned,
                        cfSlotsRetired=lost["promptButton"]["cfSlots"] if cleanup_returned else 16)
                    self.assertEqual(M.failure_context(b"", context_row(unknown), "first-save"), unknown)
                    self.assertFalse(M._accessibility_succeeded(lost))
                for path, invalid in ((("error",), "ambiguous"), (("error",), "none"),
                    (("site",), "control-unknown-limit"), (("site",), "direct-sheet-child-count-limit"),
                    (("site",), "tree-title-limit"),
                    (("site",), "tree-depth-limit"), (("site",), "tree-node-limit"),
                    (("attempted",), None), (("attempted",), True), (("pressReturned",), None),
                    (("nativeEntered",), False), (("initialOriginalProof",), None),
                    (("originalProof",), sample["initialOriginalProof"]),
                    (("promptChecks", "initial"), False), (("promptChecks", "final"), True),
                    (("promptButton", "calls"), 0), (("promptButton", "axError"), -25204),
                    (("promptButton", "lastRole"), "not-read"), (("promptButton", "lastRole"), "Browser"),
                    (("promptButton", "lastDepth"), 9),
                    (("promptButton", "checks"), {key: index < 3 for index, key in enumerate(M.ACCESSIBILITY_BUTTON_CHECKS)})):
                    bad = deepcopy(value); target = bad["accessibility"]
                    for part in path[:-1]: target = target[part]
                    target[path[-1]] = invalid
                    expected = deepcopy(bad); expected["accessibility"] = None
                    self.assertEqual(M.failure_context(b"", context_row(bad), "first-save"), expected, (site, completed, path))
        final = accessibility_context_data(); sample = final["accessibility"]
        sample.update(attempted=False, pressReturned=False, triggered=None, site="original-proof", error="changed")
        sample["promptChecks"]["final"] = False
        self.assertEqual(M.failure_context(b"", context_row(final), "first-save"), final)
        self.assertFalse(M._accessibility_succeeded(sample))
        # Known worker return does not convert an unsettled main recheck/CF
        # original into permission to retire the native release barrier.
        unknown = accessibility_context_data(); sample = unknown["accessibility"]
        sample.update(state="unknown", custodyKnown=False, receiptJoined=False, barrierRetired=False,
                      rechecksSettled=False, error="cleanup-unknown", site="cleanup")
        sample["promptButton"].update(cleanupReturned=False, cfSlotsRetired=16)
        self.assertEqual(M.failure_context(b"", context_row(unknown), "first-save"), unknown)
        self.assertFalse(M._accessibility_succeeded(sample))

    def test_one_original_late_no_entry_can_settle_failure_but_not_succeed(self):
        value = accessibility_context_data(); sample = value["accessibility"]
        sample.update(nativeEntered=False, attempted=False, pressReturned=False, triggered=None,
                      initialOriginalProof=None, originalProof=None, promptChecks={"initial": None, "final": None}, promptButton=None,
                      expired=True, timely=False, site="admission", error="deadline")
        self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)
        self.assertFalse(M._accessibility_succeeded(sample))
        no_dispatch = deepcopy(value)
        no_dispatch["accessibility"].update(requested=False, dispatchAttempted=False, bodyEntered=False,
            bodyReturned=False, receiptJoined=False, workerRegistered=False, workerJoined=False, rechecksSettled=None)
        self.assertEqual(M.failure_context(b"", context_row(no_dispatch), "first-save"), no_dispatch)
        # Request can precede definite spawn refusal; GO may not precede
        # registration. A registered no-GO original must nevertheless join.
        spawn_refused = deepcopy(no_dispatch); spawn_refused["accessibility"]["requested"] = True
        self.assertEqual(M.failure_context(b"", context_row(spawn_refused), "first-save"), spawn_refused)
        no_go = deepcopy(spawn_refused); no_go["accessibility"].update(workerRegistered=True, workerJoined=True, rechecksSettled=True)
        self.assertEqual(M.failure_context(b"", context_row(no_go), "first-save"), no_go)
        for changes in ({"workerJoined": False}, {"rechecksSettled": None}):
            invalid = deepcopy(no_go); invalid["accessibility"].update(changes)
            expected = deepcopy(invalid); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(invalid), "first-save"), expected)
        for key, bad in (("triggered", True), ("timely", True)):
            changed = deepcopy(value); changed["accessibility"][key] = bad
            expected = deepcopy(changed); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(changed), "first-save"), expected)
        no = accessibility_context_data(); no["accessibility"].update(triggered=False, error="cannot-complete")
        no["accessibility"]["promptButton"]["axError"] = -25204
        self.assertEqual(M.failure_context(b"", context_row(no), "first-save"), no)
        self.assertFalse(M._accessibility_succeeded(no["accessibility"]))
        # Even selectedPathMatched/callback-shaped DATA cannot rescue a
        # possibly-acted CannotComplete result; no second Press is allowed.
        result = M.expected_result(BINDING, "first-save"); result["native"]["projectOpenInput"] = no["accessibility"]
        with self.assertRaises(M.Refused): M.parse_result(captured(result), b"", BINDING, "first-save")

    def test_original_identity_edges_and_partial_configuration_are_still_mandatory(self):
        for case in ("first-save", "noop-stale", "save-loss"):
            good = M.expected_result(BINDING, case)
            for name in M.ACCESSIBILITY_PROOF_CHECKS:
                for where in ("projectOpenBinding", "projectOpenInput"):
                    value = deepcopy(good)
                    proof = value["native"][where]["binding" if where == "projectOpenBinding" else "originalProof"]
                    proof["checks"][name] = False
                    with self.assertRaises(M.Refused): M.parse_result(captured(value), b"", BINDING, case)
            for field, bad in (("children", 0), ("children", 17), ("originals", "multiple"), ("parent", "different"), ("panel", "valid")):
                value = deepcopy(good); value["native"]["projectOpenBinding"]["binding"][field] = bad
                with self.assertRaises(M.Refused): M.parse_result(captured(value), b"", BINDING, case)
            for field, bad in (("prompt", "different"), ("prompt", None), ("promptSetterEntered", False), ("promptSetterReturned", False),
                               ("initialDirectorySetterEntered", False), ("initialDirectorySetterReturned", False),
                               ("initialDirectorySetterEntered", 1), ("initialDirectorySetterReturned", None)):
                value = deepcopy(good); value["native"]["projectOpenBinding"]["configuration"][field] = bad
                with self.assertRaises(M.Refused): M.parse_result(captured(value), b"", BINDING, case)
        flags = ("parentSetterEntered", "parentSetterReturned", "promptSetterEntered", "promptSetterReturned",
                 "initialDirectorySetterEntered", "initialDirectorySetterReturned")
        for site, count, error in (("objects", 0, "ineligible"), ("parent-tag", 0, "objc-exception"),
                ("parent-set", 1, "objc-exception"), ("parent-get", 2, "objc-exception"),
                ("prompt-set", 3, "objc-exception"), ("prompt-get", 4, "objc-exception"),
                ("initial-directory-url", 4, "invalid-input"), ("initial-directory-url", 4, "objc-exception"),
                ("initial-directory-set", 5, "objc-exception")):
            value = binding_context_data(); binding = value["accessibilityBinding"]
            binding["start"]["result"] = "io"; binding["binding"] = None
            configured = binding["configuration"]
            for index, flag in enumerate(flags):
                configured[flag] = index < count
            configured.update(parent="match" if count >= 3 else None,
                prompt="match" if site.startswith("initial-directory-") else None, site=site, error=error)
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)
            for field in flags[count:]:
                bad = deepcopy(value); bad["accessibilityBinding"]["configuration"][field] = True
                expected = deepcopy(bad); expected["accessibilityBinding"] = None
                self.assertEqual(M.failure_context(b"", context_row(bad), "first-save"), expected)
            bad = deepcopy(value); bad["accessibilityBinding"]["start"]["result"] = "ok"
            expected = deepcopy(bad); expected["accessibilityBinding"] = None
            self.assertEqual(M.failure_context(b"", context_row(bad), "first-save"), expected)
        for prompt in ("nil", "different", "type-invalid"):
            value = binding_context_data(); binding = value["accessibilityBinding"]
            binding["start"]["result"] = "io"; binding["binding"] = None
            binding["configuration"].update(prompt=prompt, site="prompt-get", error="changed",
                                             initialDirectorySetterEntered=False, initialDirectorySetterReturned=False)
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)
        for panel in ("nil", "type-invalid", "empty", "byte-limit", "nul", "encoding-invalid", "different"):
            value = binding_context_data(); proof = value["accessibilityBinding"]["binding"]
            proof.update(site="stable-identifier", error="changed", panel=panel)
            proof["checks"].update(stableIdentifier=False, finalEligibility=None)
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)

    def test_semantic_binding_wrong_case_and_largest_context_are_bounded(self):
        good = accessibility_context_data(); good["accessibilityBinding"] = binding_context_data()["accessibilityBinding"]
        for key, bad in (("mechanism", "public-original-sheet-default-control-v1"), ("mechanism", "public-original-sheet-v1"), ("case", "save-loss"),
                         ("id", True), ("kind", "quit"), ("defaultControl", {})):
            value = deepcopy(good); value["accessibilityBinding"][key] = bad
            expected = deepcopy(value); expected["accessibilityBinding"] = None
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), expected)
        # Conservative closed-label size fixture only, not claimed native facts.
        largest = deepcopy(good)
        largest["snapshotSource"] = "prearm-open-progress"
        largest["originalWindow"] = deepcopy(M.expected_result(BINDING, "first-save")["native"]["originalWindow"])
        largest["originalWindow"]["admitted"] = False
        largest["originalWindow"]["state"] = dict.fromkeys(largest["originalWindow"]["state"], False)
        for proof in (largest["accessibilityBinding"]["binding"], largest["accessibility"]["initialOriginalProof"],
                      largest["accessibility"]["originalProof"]):
            proof.update(parent="type-invalid", panel="encoding-invalid", originals="multiple", site="panel-attached-sheet", error="cleanup-unknown", children=17)
            proof["checks"] = dict.fromkeys(M.ACCESSIBILITY_PROOF_CHECKS, False)
        largest["accessibility"]["promptChecks"] = {"initial": False, "final": False}
        largest["accessibility"]["promptButton"].update(calls=512, initialNodesExamined=16, recheckNodesExamined=16,
            lastRole="ScrollArea", lastDepth=8, cfSlots=256, cfSlotsRetired=256, cleanupReturned=False, axError=-25214)
        largest["accessibility"]["promptButton"]["checks"] = dict.fromkeys(M.ACCESSIBILITY_BUTTON_CHECKS, False)
        largest["completionSelection"] = completion_context_data()["completionSelection"]
        largest["completionSelection"].update(pollResult="invalid-return", timely=False)
        largest["completionSelection"]["facts"].update(response="decline", selection="ordinary-path-disagreement",
            callbackEntered=False, urlsReadEntered=False, urlsReadReturned=False, callbackReturned=False)
        largest["accessibility"].update(site=max(M.ACCESSIBILITY_SITES, key=lambda site: (len(site), site)),
                                        error="cleanup-unknown", state="requested")
        largest["accessibilityBinding"]["start"]["result"] = "permission-denied"
        largest["projectSelection"] = project_selection_context_data("inconsistent-original-data", "captured-object-metadata-changed")["projectSelection"]
        largest["accessibilityBinding"]["configuration"].update(parent="type-invalid", prompt="type-invalid",
            site="initial-directory-url", error="cleanup-unknown", initialDirectorySetterEntered=False, initialDirectorySetterReturned=False)
        largest["snapshotSource"] = "record"
        largest["dom"] = {"evaluations": 160, "lastProjectChooser": {
            "step": "ChooseProject", "sequence": 160, "dashboardSelected": True,
            "buttonDisabled": True, "reason": "offline-preflight"}}
        self.assertLessEqual(len(context_row(largest).split(b"=", 1)[1].rstrip(b"\n")), M.FAILURE_CONTEXT_LIMIT)

    def test_original_exception_buffers_do_not_change_error_or_finality(self):
        for duplicate in (False, True):
            with self.subTest(repeated_identical_frame=duplicate), inert_exception_owner(duplicate=duplicate) as call:
                fixtures = InertFixtures()
                with patch.object(M, "parse_result", side_effect=AssertionError("must not parse success")), \
                        self.assertRaises(RuntimeError) as caught:
                    M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
                self.assertIs(caught.exception, call.original)
                self.assertEqual((fixtures.before, fixtures.reads), (["first-save"], []))
                self.assertTrue(fixtures.inflight); self.assertFalse(fixtures.last_returned)
                report = M.diagnostic(caught.exception, None, fixtures)
                self.assertEqual((report["innerFailureStep"], report["innerFailureReason"], report["innerFailureContext"]),
                                 ("CancelProject", "observer-deadline", context_data()))
                self.assertEqual(report["innerDiagnosticSource"], "original-exception-buffer")
                self.assertEqual((report["innerDiagnosticCompleteness"], report["invocationFinality"]), ("unknown", "unknown"))
                self.assertIsNone(report["appReturncode"])
                self.assertFalse(report["originalCallReturned"])
                output = io.StringIO(); M.emit_record(report, output)
                self.assertNotIn("PRIVATE", output.getvalue())
                self.assertNotIn(M.EXECUTABLE, output.getvalue())

    def test_native_action_closed_sites_cover_three_remaining_original_actions(self):
        self.assertEqual(set(M.NATIVE_ACTION_STEPS), {"CancelProject", "QuitCancel", "Quit"})
        self.assertEqual(len(M.NATIVE_ACTION_SITES), 36)
        for step, (_, _, _, mask) in M.NATIVE_ACTION_STEPS.items():
            for site, (native_error, actions, exception) in M.NATIVE_ACTION_SITES.items():
                for domain, error, admitted in (
                    ("native-return", native_error or "io", bool(actions & mask) and native_error not in (None, "none", "would-block")),
                    ("objc-exception", "io", bool(actions & mask) and exception),
                    ("native-return", "none", False), ("native-return", "would-block", False),
                ):
                    value = action_context_data(step, site=site, domain=domain, error=error)
                    original = deepcopy(value)
                    row = context_row(value)
                    self.assertLess(len(row) - len(b"MRK_MACOS_AQUA_FAILURE_CONTEXT=\n"), M.FAILURE_CONTEXT_LIMIT)
                    result = M.failure_context(b"", row)
                    expected = deepcopy(value)
                    if not admitted:
                        expected["nativeAction"] = None
                    self.assertEqual(result, expected, (step, site, domain, error))
                    self.assertEqual(value, original)
            value = action_context_data(step, site="original-usability", domain="rust-precondition", error="other")
            self.assertEqual(M.failure_context(context_row(value), b""), value)
        for site in ("directory-utf8", "directory-path", "directory-cstring"):
            value = action_context_data(site=site, domain="rust-precondition", error="invalid-input")
            expected = deepcopy(value); expected["nativeAction"] = None
            self.assertEqual(M.failure_context(context_row(value), b""), expected)
        for step, action in (("SetProject", "project-directory"), ("OpenProject", "project-open")):
            value = action_context_data(); value["nativeAction"].update(step=step, action=action)
            expected = deepcopy(value); expected["nativeAction"] = None
            self.assertEqual(M.failure_context(context_row(value), b""), expected)
        self.assertNotIn("SetProject", M.FAILURE_STEPS); self.assertNotIn("SetProject", M.NATIVE_STEPS)
        value = action_context_data("Quit")
        value["lastPanel"]["id"] = value["nativeAction"]["id"] = 2
        self.assertEqual(M.failure_context(context_row(value), b""), value)

    def test_native_action_missing_invalid_or_stale_data_does_not_replace_context(self):
        good = action_context_data()
        variants = []
        for field, value in (("id", True), ("id", 0), ("id", 5), ("id", 2), ("step", "SetProject"),
                             ("action", "quit-confirm"), ("domain", "PRIVATE EXCEPTION"), ("site", "PRIVATE PATH"),
                             ("error", "PRIVATE ERROR"), ("site", "directory-set"), ("domain", "native-return")):
            item = deepcopy(good); item["nativeAction"][field] = value; variants.append(item)
        for value in (None, [], "PRIVATE", {}, {**good["nativeAction"], "path": "PRIVATE"}):
            item = deepcopy(good); item["nativeAction"] = value; variants.append(item)
        item = deepcopy(good); del item["nativeAction"]["error"]; variants.append(item)
        item = deepcopy(good); item["nativeHandler"]["returned"] = False; variants.append(item)
        item = deepcopy(good); item["lastPanel"] = None; variants.append(item)
        for item in variants:
            expected = deepcopy(item); expected["nativeAction"] = None
            self.assertEqual(M.failure_context(context_row(item), b""), expected)
        self.assertEqual(M.failure_context(context_row(context_data()), b""), context_data())
        row = context_row(good)
        for malformed in (row[:-1], row + row, b"log " + row, row + b"MRK_MACOS_AQUA_FAILURE_CONTEXT?"):
            self.assertIsNone(M.failure_context(malformed, b""))

    def test_native_action_original_exception_stays_unknown_and_stops_later_cases(self):
        good = action_context_data()
        invalid = deepcopy(good); invalid["nativeAction"]["private"] = "PRIVATE"
        reduced = deepcopy(good); reduced["nativeAction"] = None
        prefix = b"MRK_MACOS_AQUA_FAILURE_STEP=CancelProject\nMRK_MACOS_AQUA_FAILURE_REASON=adapter-native-action\n"
        for row, expected in ((context_row(good), good), (context_row(invalid), reduced), (context_row(good)[:-1], None)):
            with inert_exception_owner(stderr=prefix + row) as call:
                fixtures = InertFixtures()
                with self.assertRaises(RuntimeError) as caught:
                    M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
                self.assertIs(caught.exception, call.original)
                self.assertEqual((fixtures.before, fixtures.reads), (["first-save"], []))
                self.assertTrue(fixtures.inflight); self.assertFalse(fixtures.last_returned)
                report = M.diagnostic(caught.exception, None, fixtures)
                self.assertEqual(report["innerFailureContext"], expected)
                self.assertEqual((report["innerFailureStep"], report["innerFailureReason"]), ("CancelProject", "adapter-native-action"))
                self.assertEqual((report["invocationFinality"], report["innerDiagnosticCompleteness"]), ("unknown", "unknown"))
                self.assertIsNone(report["appReturncode"]); self.assertFalse(report["originalCallReturned"])
                output = io.StringIO(); M.emit_record(report, output)
                self.assertNotIn("PRIVATE", output.getvalue())

    def test_exception_snapshot_refuses_foreign_ambiguous_changed_or_unbounded_inputs(self):
        def change_shared_case(call):
            call.command.mutate_argv = True
            call.frozen.args = (M.EXECUTABLE, "noop-stale")
            call.frozen.argv = tuple(arg.encode("ascii") for arg in call.frozen.args)
        mutations = (
            lambda f: setattr(f.command.__spec__, "origin", "/foreign"),
            lambda f: setattr(f.command, "__file__", "/foreign"),
            lambda f: setattr(f.owner, "run_command", FunctionType(f.command.run_command.__code__, dict(vars(f.command)))),
            lambda f: setattr(f.owner, "run_command", FunctionType(f.command.run_command.__code__.replace(co_firstlineno=1), vars(f.command))),
            lambda f: setattr(f.command, "recursion", 1),
            change_shared_case,
            lambda f: f.command.overrides.update(argv=[M.EXECUTABLE, "noop-stale"]),
            lambda f: f.command.overrides.update(cwd=Path("/foreign")),
            lambda f: f.command.overrides.update(timeout=61),
            lambda f: f.command.overrides.update(capture=1),
            lambda f: f.command.overrides.update(text=True),
            lambda f: f.command.overrides.update(output_limit=M.OUTPUT_LIMIT + 1),
            lambda f: setattr(f.command, "original_engine", SimpleNamespace(frozen=f.frozen, text=False, outputs=f.engine.outputs)),
            lambda f: setattr(f.frozen, "args", (M.EXECUTABLE, "noop-stale")),
            lambda f: setattr(f.frozen, "argv", (b"/foreign", b"first-save")),
            lambda f: setattr(f.frozen, "cwd", b"/foreign"),
            lambda f: setattr(f.frozen, "manifest", SimpleNamespace(capture=True, limit=M.OUTPUT_LIMIT)),
            lambda f: setattr(f.manifest, "capture", 1),
            lambda f: setattr(f.manifest, "limit", M.OUTPUT_LIMIT + 1),
            lambda f: setattr(f.engine, "text", True),
            lambda f: setattr(f.engine, "outputs", tuple(f.engine.outputs)),
            lambda f: setattr(f.engine, "outputs", [bytearray()]),
            lambda f: setattr(f.engine, "outputs", [b"", f.engine.outputs[1]]),
            lambda f: setattr(f.engine, "outputs", [bytearray(M.OUTPUT_LIMIT), f.engine.outputs[1]]),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), inert_exception_owner() as call:
                mutation(call)
                fixtures = InertFixtures()
                with self.assertRaises(RuntimeError) as caught:
                    M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
                self.assertIs(caught.exception, call.original)
                self.assertIsNone(fixtures.inner_diagnostic_source)
                self.assertIsNone(fixtures.inner_failure_step)
                self.assertEqual((fixtures.before, fixtures.reads, fixtures.inflight, fixtures.last_returned),
                                 (["first-save"], [], True, False))
        with inert_exception_owner() as call, patch.object(M, "TRACEBACK_LIMIT", 1):
            fixtures = InertFixtures()
            with self.assertRaises(RuntimeError):
                M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
            self.assertIsNone(fixtures.inner_diagnostic_source)

    def test_exception_partial_absent_or_parser_failure_stays_unavailable(self):
        for stderr in (b"", b"PRIVATE ONLY", b"MRK_MACOS_AQUA_FAILURE_STEP=CancelProject",
                       b"MRK_MACOS_AQUA_FAILURE_REASON=observer-deadline\nMRK_MACOS_AQUA_FAILURE_REASON"):
            with inert_exception_owner(stderr=stderr) as call:
                fixtures = InertFixtures()
                with self.assertRaises(RuntimeError) as caught:
                    M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
                self.assertIs(caught.exception, call.original)
                self.assertIsNone(fixtures.inner_diagnostic_source)
        # A complete closed field remains diagnostic even if a separate field
        # is absent/partial. The partial field and capture completeness do not.
        with inert_exception_owner(stderr=(b"MRK_MACOS_AQUA_FAILURE_STEP=CancelProject\n"
                                           b"MRK_MACOS_AQUA_FAILURE_REASON=observer-deadline")) as call:
            fixtures = InertFixtures()
            with self.assertRaises(RuntimeError):
                M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
            self.assertEqual(fixtures.inner_failure_step, "CancelProject")
            self.assertIsNone(fixtures.inner_failure_reason)
            self.assertIsNone(fixtures.inner_failure_context)
            self.assertEqual(fixtures.inner_diagnostic_source, "original-exception-buffer")
        with inert_exception_owner() as call, patch.object(M, "failure_step", side_effect=ValueError("PRIVATE PARSER ERROR")):
            fixtures = InertFixtures()
            with self.assertRaises(RuntimeError) as caught:
                M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
            self.assertIs(caught.exception, call.original)
            self.assertIsNone(fixtures.inner_diagnostic_source)
            self.assertTrue(fixtures.inflight)
        with inert_exception_owner() as call, patch.object(M, "_original_exception_diagnostics", side_effect=ValueError("PRIVATE SNAPSHOT ERROR")):
            fixtures = InertFixtures()
            with self.assertRaises(RuntimeError) as caught:
                M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
            self.assertIs(caught.exception, call.original)
            self.assertIsNone(fixtures.inner_diagnostic_source)

    def test_failure_reason_diagnostic_does_not_promote_nonzero(self):
        cases = [("CancelProject", "asset_source_refused")] + [("ProjectSettled", reason) for reason in (
            "project-result-path", "project-result-path-app-child", "project-result-path-descendant",
            "project-result-path-ancestor", "project-result-path-sibling", "project-result-path-tmp-spelling",
            "project-result-path-data-spelling")]
        for step, reason in cases:
            with self.subTest(step=step, reason=reason):
                fixtures, emitted = InertFixtures(), []
                marker = (f"MRK_MACOS_AQUA_FAILURE_STEP={step}\n"
                          f"MRK_MACOS_AQUA_FAILURE_REASON={reason}\n").encode("ascii")
                detail = None
                if reason in M.PROJECT_SELECTION_BOUND_LOCATIONS:
                    detail = project_selection_context_data(location=sorted(M.PROJECT_SELECTION_BOUND_LOCATIONS[reason])[0])
                    marker += context_row(detail)
                def runner(argv, **_):
                    return CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=marker)
                with self.assertRaisesRegex(M.Refused, "^app-return$") as caught:
                    M.run_cases(BINDING, fixtures, runner, UID, "runner", emitted.append)
                report = M.diagnostic(caught.exception, None, fixtures)
                self.assertEqual((report["status"], report["innerFailureStep"], report["innerFailureReason"]),
                                 ("failed", step, reason))
                self.assertEqual(report["appReturncode"], 1)
                self.assertIs(report["originalCallReturned"], True)
                self.assertEqual(report["invocationFinality"], "no-pending-invocation")
                self.assertFalse(fixtures.inflight)
                self.assertEqual(report["innerDiagnosticSource"], "completed-output")
                self.assertEqual(report["innerDiagnosticCompleteness"], "complete")
                self.assertEqual(report["typedLifetimeFacts"], [])
                self.assertEqual(report["innerFailureContext"], detail)
                self.assertEqual(fixtures.before, ["first-save"])
                self.assertEqual((fixtures.reads, emitted), ([], []))
        self.assertIsNone(M.diagnostic(M.Refused("fixture-refused"), None, None)["innerFailureReason"])

    def test_original_window_source_is_borrowed_passive_and_same_endpoint_only(self):
        source_root = PATH.parents[1] / "src-tauri" / "src"
        shell = (source_root / "shell.rs").read_text(encoding="utf-8")
        observer = (source_root / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        native_root = PATH.parents[1] / "native" / "macos-installed-native" / "src"
        native = (native_root / "native.m").read_text(encoding="utf-8")
        native_rust = (native_root / "lib.rs").read_text(encoding="utf-8")
        hook = shell.split(".on_window_event(|window, event| {", 1)[1].split("if let tauri::WindowEvent::Destroyed = event", 1)[0]
        terminal = "if !matches!(event, tauri::WindowEvent::Destroyed | tauri::WindowEvent::CloseRequested { .. })"
        self.assertIn('feature = "macos-installed-observation"', hook)
        self.assertIn('target_os = "macos"', hook)
        self.assertLess(hook.index(terminal), hook.index("window.try_state::<ShellState>()"))
        self.assertLess(hook.index("window.try_state::<ShellState>()"), hook.index("q.observe_original_window(window)"))
        self.assertNotIn("window.state::<ShellState>()", hook)
        self.assertNotIn("Focused(true)", hook)  # No second-focus dependency.
        body = observer.split("pub(super) fn observe_original_window(", 1)[1].split("pub(super) fn navigation(", 1)[0]
        self.assertEqual(body.count("window.ns_window()"), 1)
        self.assertEqual(body.count("installed_original_window("), 1)
        self.assertLess(body.index("mrk_macos_installed_native::main_thread()"), body.index("window.ns_window()"))
        self.assertLess(body.index("} // No record guard"), body.index("window.ns_window()"))
        self.assertLess(body.index("installed_original_window("), body.index("let Some(mut r) = self.record()"))
        self.assertLess(body.index("let Some(mut r) = self.record()"), body.index("let timely = self.timely()"))
        self.assertLess(body.index("let timely = self.timely()"), body.index("self.failed.load(Ordering::SeqCst)"))
        self.assertLess(body.index("self.failed.load(Ordering::SeqCst)"), body.index("publish_original_window("))
        for forbidden in ("run_on_main_thread", "get_window(", "get_webview_window(", "with_webview(",
                          ".clone()", "Instant::now()", "Duration::", "thread::spawn", "std::mem::forget"):
            self.assertNotIn(forbidden, body)
        self.assertIn('if returned.result != "ok" { self.fail(); }', body)
        publication = observer.split("fn publish_original_window(", 1)[1].split("struct NativeActionSample", 1)[0]
        self.assertIn("if slot.is_some_and(|s| s.admitted) { return; }", publication)
        self.assertIn("returned.admitted = needed && timely && !failed && returned.positive();", publication)
        self.assertIn("r.original_window.is_some_and(|s| s.admitted && s.positive())", observer)
        bootstrap = observer.split("if r.step == Step::Bootstrap {", 1)[1].split("r.step = Step::Environment;", 1)[0]
        for gate in ("!r.original_window.is_some_and(|s| s.admitted)", "!r.info", "!r.catalog", "!r.capability",
                     "!state.document.installed_macos_live()"):
            self.assertIn(gate, bootstrap)
        scalar = native.split("int mrk_observation_original_window(", 1)[1].split("#endif", 1)[0]
        self.assertLess(scalar.index("pthread_main_np()"), scalar.index("NSApplication *app = NSApp"))
        self.assertIn("(uintptr_t)(void *)main == original", scalar)
        self.assertLess(scalar.index("[main attachedSheet]"), scalar.index("*flags = observed"))
        for forbidden in ("sharedApplication", "NSApplicationLoad", "activateIgnoringOtherApps", "setActivationPolicy",
                          "makeKeyAndOrderFront", "CFRunLoop", "dispatch_", "retain", "release", "NSWindow *original"):
            self.assertNotIn(forbidden, scalar)
        decoder = native_rust.split("fn original_window_state(", 1)[1].split("fn semantic_data_check(", 1)[0]
        self.assertIn("flags & !63 != 0", decoder)
        self.assertIn("flags & 4 == 0 && flags & 56 != 0", decoder)
        self.assertIn("flags == 0 && matches!(code, 1 | 2)", decoder)
        self.assertIn('result: "invalid-return", state: None', decoder)
        self.assertIn("original_window_data_check()", native_rust.split("pub fn installed_observation_flags_data_check()", 1)[1])
        checks = observer.split("fn original_window_witness_data_check()", 1)[1].split("\nfn completion_ownership_data_check()", 1)[0]
        self.assertIn("publish_original_window(&mut slot, negative, true, true, false)", checks)
        self.assertIn("publish_original_window(&mut slot, positive, true, true, false)", checks)
        self.assertIn("(true, false, false)", checks)
        self.assertIn("(true, true, true)", checks)
        self.assertIn('first_failure_reason(&first) == Some("observer-deadline")', checks)
        for forbidden in ("installed_original_window(", ".ns_window()", ".value()", "run_on_main_thread"):
            self.assertNotIn(forbidden, checks)

    def test_observer_reason_catalog_and_readiness_call_contract(self):
        source_root = PATH.parents[1] / "src-tauri" / "src"
        observer = (source_root / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        adapter = (source_root / "shell_macos_dialog.rs").read_text(encoding="utf-8")
        errors = (source_root / "asset_commands.rs").read_text(encoding="utf-8")
        document = (source_root / "asset_session.rs").read_text(encoding="utf-8")
        shared = document.split("fn common_document_gate(", 1)[1].split("fn ordinary_asset_platform_gate(", 1)[0]
        self.assertNotIn("cfg!", shared)
        self.assertNotIn("UnsupportedPlatform", shared)
        ordinary = document.split("fn gate(&self,", 1)[1].split("fn project_path_gate(", 1)[0]
        self.assertLess(ordinary.index("self.common_gate(state, session)?"), ordinary.index("ordinary_asset_platform_gate()?"))
        self.assertLess(ordinary.index("ordinary_asset_platform_gate()?"), ordinary.index("self.native_qualified()"))
        predicate = document.split("fn ordinary_asset_platform_gate()", 1)[1].split("fn session_kind_gate(", 1)[0]
        self.assertIn('cfg!(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),', predicate)
        self.assertIn('all(target_os = "macos", target_arch = "aarch64"),\n        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))', predicate)
        self.assertIn("Reason::UnsupportedPlatform", predicate)
        kinds = document.split("fn session_kind_gate(", 1)[1].split("fn preflight_document_gate(", 1)[0]
        self.assertIn('cfg!(all(target_os = "macos", target_arch = "aarch64"))', kinds)
        mac_kind_policy = document.split("fn macos_session_kind(", 1)[1].split("fn session_kind_gate(", 1)[0]
        self.assertIn("&& !macos_session_kind(context.platform, context.stage, context.purpose, kind)", kinds)
        for arm in (
            "Platform::Android => matches!(kind, Kind::AndroidKeystore | Kind::AndroidFirebase | Kind::GoogleWif),",
            "Platform::Project => kind == Kind::ProjectReadToken,",
            "Purpose::Full | Purpose::Store => kind == Kind::AscP8,",
            "Purpose::Signing => matches!(kind, Kind::AppleP12 | Kind::AppleProfile | Kind::IosFirebase | Kind::ProjectReadToken),",
        ):
            self.assertIn(arm, mac_kind_policy)
        self.assertIn("Reason::UnsupportedFormat", kinds)
        contract = document.split("pub(crate) fn assert_project_selection_gate_contract()", 1)[1].split("pub(crate) fn assert_installed_evidence_gate_contract()", 1)[0]
        self.assertIn("assert_eq!(reason(&ready), None)", contract)
        self.assertIn("ordinary_asset_platform_gate().err().map(|error| error.reason), platform", contract)
        self.assertIn("assert!(common_document_gate(&ready, false, || Ok(())).is_ok())", document)
        checks = observer.split("fn observer_data_checks()", 1)[1].split("pub(crate) fn main()", 1)[0]
        self.assertIn("crate::asset_session::assert_project_selection_gate_contract();", checks)
        self.assertIn("crate::runtime::RuntimeConfig::packaged(", checks)
        self.assertIn("!profile.project_selection_profile_available() || profile.project_path_selection_profile_available()", checks)
        self.assertIn("|| profile.evidence_selection_profile_available() { return false; }", checks)
        self.assertNotIn(".resolve(", checks)
        main = observer.split("pub(crate) fn main()", 1)[1]
        for native_entry in ("Fixture::capture(", "Observation::new(", "observe(&q)"):
            self.assertLess(main.index("if !observer_data_checks()"), main.index(native_entry))
        observation = observer.split("fn observe(q: &Arc<Observation>)", 1)[1].split("pub(crate) fn main()", 1)[0]
        self.assertEqual(main.count("observe(&q)"), 1)
        self.assertEqual(observer.count("super::run_builder("), 1)
        self.assertEqual(observation.count("super::run_builder("), 1)
        self.assertLess(observation.index("installed_accessibility_trusted()"), observation.index("if trusted != Ok(true)"))
        self.assertLess(observation.index("if trusted != Ok(true)"), observation.index("super::run_builder("))
        self.assertLess(observation.index("if !q.timely() { return None; }"), observation.index("super::run_builder("))
        reasons = observer.split("const FAILURE_REASONS: &[&str] = &[", 1)[1].split("];", 1)[0]
        labels = M.re.findall(r'"([a-z_-]+)"', reasons)
        self.assertEqual(len(labels), len(set(labels)))
        self.assertEqual(set(labels), M.FAILURE_REASONS)
        closed_codes = set(M.re.findall(r'=> "((?:asset_|assessment_)[a-z_]+)"', errors))
        self.assertTrue(closed_codes <= M.FAILURE_REASONS)
        self.assertTrue(set(M.re.findall(r'=> "(adapter-[a-z-]+)"', adapter)) <= M.FAILURE_REASONS)
        self.assertIn("if !observer_data_checks()", observer)
        readiness = observer.split("fn panel_readiness(", 1)[1].split("const METHODS", 1)[0]
        self.assertNotIn("observe_panel_action(", readiness)
        self.assertNotIn("Instant::now()", readiness)
        self.assertIn('if ever_attached { return Err("native-attachment-lost"); }', readiness)
        self.assertIn("if preconfigured { !native.directory_bound || !native.directory_returned }", readiness)
        self.assertIn("else { native.directory_bound || native.directory_returned || native.directory_ready }", readiness)
        self.assertIn("if same_action_returned || unexpected_setup", readiness)
        action = observer.split("fn native_step(", 1)[1].split("pub(super) fn close_prevented", 1)[0]
        for attachment in ("r.panel_attached[self.case.panel_index(step).ok_or(\"native-step\")?] = true",
                           "r.file_attached[usize::from(i)] = true"):
            self.assertLess(action.index("if !panel_readiness("), action.index(attachment))
            self.assertLess(action.index(attachment), action.index("observe_panel_action(id,action)"))
        self.assertIn('if let Err(reason) = result { self.fail_with(reason); }', action)
        self.assertNotIn("r.pending.take()", action)
        self.assertLess(action.index("let timely = self.timely()"), action.index("let result = self.native_step_body("))
        self.assertLess(action.index("let result = self.native_step_body(step, timely, &mut action_diagnostic,"), action.index("native.returned = true"))
        body = action.split("fn native_step_body(", 1)[1]
        entry = "if !native_step_entry(std::thread::current().id() == self.main, timely)? { return Ok(false); }"
        self.assertLess(body.index(entry), body.index("observed_panel()"))
        quit = observer.split("fn quit_id(self)", 1)[1].split("fn inputs(self)", 1)[0]
        self.assertIn("if let Self::Ios(case) = self { if case.inputs() { return session::quit_original(case); } }", quit)
        self.assertIn("if self == Self::ProjectFields { 12 } else if self == Self::FirstSave { 4 } else { 2 }", quit)
        session = (source_root / "installed_shell_observation_macos_session.rs").read_text(encoding="utf-8")
        self.assertIn("pub(super) fn quit_original(case: Case) -> u32 { case.session_final_original().unwrap_or(0) }", session)
        for branch in ("Step::OpenProject => (self.case.selected_id(),PanelKind::Project)",
                       'Step::Session(session::Step::Native(i)) => (self.case.input_id(i).ok_or("native-step")?,PanelKind::File)',
                       "Step::Quit => (self.case.quit_id(),PanelKind::Quit)",
                       "Step::CancelProject => PanelAction::ProjectCancel",
                       "Step::Session(session::Step::Native(i)) if self.case.input_id(i).is_some() && !self.case.input_accepted(i) => PanelAction::FileCancel"):
            self.assertIn(branch, body)
        admission = observer.split("fn native_step_entry(", 1)[1].split("fn retire_returned_native(", 1)[0]
        self.assertLess(admission.index('if !on_main { return Err("native-wrong-thread"); }'), admission.index("Ok(timely)"))
        self.assertIn('if matches!(result, Err("native-wrong-thread" | "native-pending-custody")) { return; }', action)
        self.assertIn('(false, false, Err("native-wrong-thread"))', observer)
        self.assertIn('(false, true, Err("native-wrong-thread"))', observer)
        self.assertIn('(true, false, Ok(false))', observer)
        self.assertIn("retire_returned_native(&mut original", observer)
        self.assertIn("installed_observation_flags_data_check()", observer)
        native_root = PATH.parents[1] / "native" / "macos-installed-native" / "src"
        native = (native_root / "native.m").read_text(encoding="utf-8")
        rust = (native_root / "lib.rs").read_text(encoding="utf-8")
        self.assertIn("uint32_t attachment = mrk_observation_attachment(s);", native)
        self.assertIn("attachment == MRK_ATTACHMENT_ALL ? 2u : 0u", native)
        self.assertIn("if (!mrk_observation_attached(s)) MRK_ACTION_RETURN(EAGAIN);", native)
        self.assertIn("flags & !0x1fffff == 0", rust)
        self.assertIn("(parent_present && panel_present).then_some", rust)

    def test_native_action_source_keeps_original_calls_status_and_closed_decoder(self):
        native_root = PATH.parents[1] / "native" / "macos-installed-native" / "src"
        native = (native_root / "native.m").read_text(encoding="utf-8")
        rust = (native_root / "lib.rs").read_text(encoding="utf-8")
        table = rust.split("const ACTION_SITES:", 1)[1].split("];", 1)[0]
        rows = M.re.findall(r'\("([a-z-]+)", (-?[0-9]+), ([0-9]+), (true|false)\)', table)
        errors = {-1: None, 0: "none", 1: "permission-denied", 5: "io", 22: "invalid-input", 35: "would-block"}
        self.assertEqual(len(rows), 36)
        self.assertEqual({site: (errors[int(status)], int(actions), exception == "true")
                          for site, status, actions, exception in rows}, M.NATIVE_ACTION_SITES)
        action = native.split("int mrk_panel_observe_action(", 1)[1].split("#undef MRK_ACTION_RETURN", 1)[0]
        calls = ("pthread_main_np()", "mrk_observation_attached(s)",
                 "[s->alert buttons]", "[buttons count]", "[buttons objectAtIndex:",
                 "[button window]", "[button isEnabled]", "[button isHidden]", "cancel:nil]", "[button performClick:nil]")
        for call in calls:
            self.assertEqual(action.count(call), 1, call)
        self.assertLess(action.index("[s->alert buttons]"), action.index("if (!s->alert)"))
        self.assertLess(action.index("[button isEnabled]"), action.index("[button isHidden]"))
        self.assertIn("action != 1 && action != 4 && action != 5 && action != 6", action)
        self.assertIn("if (directory != NULL)", action)
        self.assertNotIn("setDirectoryURL:", action)
        self.assertNotIn("PanelAction::ProjectDirectory", rust)
        self.assertNotIn("ok:nil]", native)
        self.assertNotIn("PanelAction::ProjectOpen", rust)
        for call in ("cancel:nil]", "[button performClick:nil]"):
            self.assertLess(action.index("s->observationActionAttempted = YES"), action.index(call))
            self.assertLess(action.index(call), action.index("s->observationActionReturned = YES"))
        self.assertIn("(void)e; s->unknown = YES;", action)
        self.assertIn("mrk_observation_action_return(diagnostic, 2u, site, EIO)", action)
        controls = M.re.sub(r"//[^\n]*", "", action)
        for forbidden in ("[e ", "respondsToSelector", "NSLog", "endSheet:", "close_once(", "s->selected"):
            self.assertNotIn(forbidden, controls)
        returned = rust.split("pub fn installed_action(", 1)[1].split("#[cfg(test)]", 1)[0]
        self.assertLess(returned.index("*diagnostic = None"), returned.index("self.usable()"))
        self.assertEqual(returned.count("mrk_panel_observe_action("), 1)
        self.assertIn("*diagnostic = action_return_diagnostic(code, status, wire);", returned)
        self.assertIn("Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false)", returned)
        self.assertIn("io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied", returned)
        self.assertIn("Err(error) => { self.unknown = true; Err(error) }", returned)
        source_root = PATH.parents[1] / "src-tauri" / "src"
        adapter = (source_root / "shell_macos_dialog.rs").read_text(encoding="utf-8")
        self.assertIn("returned.map_err(|_| ObservationError::NativeAction(diagnostic))", adapter)
        observer = (source_root / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        self.assertIn("r.last_panel = None; r.native_action = None;", observer)
        self.assertIn('first_failure_reason(&self.failure_reason) == Some("adapter-native-action")', observer)
        self.assertIn("r.native_action = action_diagnostic;", observer)
        report = observer.split("    fn report_failure(", 1)[1].split("    pub(super) fn attach(", 1)[0]
        # Only these original-return reasons may defer their one-shot report.
        # The two P2 additions remain scoped to its native step, and the same
        # pending/entered/not-returned original gates the complete predicate.
        deferred = ('if (matches!(reason, "adapter-native-action" | "native-default-binding")\n'
                    '                || matches!(r.step, Step::ProjectFields(project_fields::Step::Native(_)))\n'
                    '                    && matches!(reason, "adapter-native-observation" | "project-fields-original-contract"))\n'
                    "            && r.pending == Some(Pending::Native(r.step))\n"
                    "            && r.native_dispatch.is_some_and(|native| native.step == r.step && native.entered && !native.returned) {\n"
                    "            return;\n        }")
        self.assertEqual(report.count(deferred), 1)
        self.assertEqual(report.count("r.native_dispatch.is_some_and("), 1)
        self.assertLess(report.index("first_failure_reason(&self.failure_reason)"), report.index("let Ok(r) = self.record.try_lock()"))
        self.assertLess(report.index("let Ok(r) = self.record.try_lock()"), report.index(deferred))
        self.assertLess(report.index(deferred), report.index("FailureSnapshot::from_record(&r)"))
        self.assertLess(report.index("drop(r)"), report.index("self.diagnostic.submit(snapshot.frame(reason))"))
        for forbidden in ("self.timely()", "observe_panel_action(", "observed_panel(", "stderr()", ".write_all(", "self.failed.store(", "self.end ="):
            self.assertNotIn(forbidden, report)
        published = observer.split("        let result = self.native_step_body(", 1)[1].split("    fn native_step_body(", 1)[0]
        self.assertLess(published.index("if let Err(reason) = result { self.fail_with(reason); }"),
                        published.index("let Some(mut r) = self.record()"))
        self.assertLess(published.index("native.returned = true"), published.index("r.native_action = action_diagnostic;"))
        self.assertLess(published.index("r.native_action = action_diagnostic;"), published.index("retire_returned_native("))
        dispatch = observer.split("if matches!(step,Step::CancelProject|", 1)[1].split("if step == Step::Reload", 1)[0]
        self.assertLess(dispatch.index("let Some(mut r) = self.record()"), dispatch.index("if !self.timely() { return; }"))
        for reset in ("r.pending = Some(Pending::Native(step))", "r.native_dispatch =", "r.last_panel =", "r.native_action =",
                      "window.run_on_main_thread("):
            self.assertLess(dispatch.index("if !self.timely() { return; }"), dispatch.index(reset))

    def test_public_prompt_button_binds_only_the_exact_original_panel(self):
        desktop = PATH.parents[1]
        native = (desktop / "native/macos-installed-native/src/native.m").read_text(encoding="utf-8")
        rust = (desktop / "native/macos-installed-native/src/lib.rs").read_text(encoding="utf-8")
        trust = native.split("int mrk_observation_ax_trusted(", 1)[1].split("int mrk_panel_observe_arm_open_identity(", 1)[0]
        for fact in ("kAXTrustedCheckOptionPrompt", "kCFBooleanFalse", "AXIsProcessTrustedWithOptions(options)", "CFRelease(options)"):
            self.assertEqual(trust.count(fact), 1)
        self.assertNotIn("kCFBooleanTrue", trust)
        for forbidden in ("accessibilityPerformConfirm", "accessibilityDefaultButton", "defaultButtonCell]", "MRKDefaultPacket",
                          "AXUIElementCopyElementAtPosition", "CGEventPost", "observationDefaultElement", " ok:"):
            self.assertFalse(forbidden in native, "forbidden native route: " + forbidden)
        configured = native.split("static BOOL mrk_panel_configure_open_identity(MRKInstalledPanel *s) {", 1)[1].split("static BOOL mrk_original_eligible(", 1)[0]
        self.assertEqual(configured.count("setPrompt:prompt]"), 1)
        self.assertLess(configured.index("MRK_ID_PROMPT_ENTERED"), configured.index("setPrompt:prompt]"))
        self.assertLess(configured.index("setPrompt:prompt]"), configured.index("MRK_ID_PROMPT_RETURNED"))
        self.assertIn("d->prompt != MRK_ID_MATCH", configured)
        start = native.split("static int mrk_panel_start_inner(", 1)[1].split("int mrk_panel_start(", 1)[0]
        self.assertLess(start.index("mrk_panel_configure_open_identity(s)"), start.index("beginSheetModalForWindow:"))
        for bound in ("MRK_PROMPT_CALLS = 512", "MRK_PROMPT_CF = 256", "MRK_CONTROL_NODES = 17", "MRK_CONTROL_DEPTH = 8"):
            self.assertTrue(bound in native, "missing native bound: " + bound)
        for retired in ("MRKPromptNode", "MRK_PROMPT_NODES", "MRK_PROMPT_DEPTH", "mrk_ax_scan(", "mrk_ax_direct_roster("):
            self.assertFalse(retired in native, "retired native route: " + retired)
        # The retired owner is s, not the suffix of the new pass identifier.
        # Keep full-source failures compact instead of echoing native.m.
        self.assertIsNone(M.re.search(r"\bs\s*->\s*nodes\b", native), "retired MRKPrompt node storage")
        arrays = native.split("static CFArrayRef mrk_ax_array(", 1)[1].split("static BOOL mrk_ax_equal_attribute(", 1)[0]
        self.assertLess(arrays.index("AXUIElementGetAttributeValueCount"), arrays.index("AXUIElementCopyAttributeValues"))
        self.assertIn("BOOL allow_empty", arrays)
        self.assertIn("BOOL counted = mrk_ax_status(s, count_status)", arrays)
        self.assertIn("if (!expected) { if (!allow_empty) mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED); return NULL; }", arrays)
        self.assertIn("attribute, 0, limit + 1, &slot->array", arrays)
        self.assertIn("count != expected", arrays)
        self.assertNotIn("CFArrayGetValueAtIndex", arrays)  # Typed when the actual node begins below.
        for absent in ("kAXErrorCannotComplete", "kAXErrorAttributeUnsupported", "kAXErrorNoValue", "BOOL absent"):
            self.assertNotIn(absent, arrays)  # An unsupported/failed Count is never an empty container.
        roster = native.split("static BOOL mrk_ax_control_roster(", 1)[1].split("static BOOL mrk_ax_control_path(", 1)[0]
        self.assertEqual(roster.count("kAXChildrenAttribute"), 1)
        self.assertIn("pass->nodes[0] = sheet;", roster)
        self.assertIn("unsigned queued = 1, matches = 0;", roster)
        self.assertIn("mrk_ax_array(s, node, kAXChildrenAttribute, 16, at != 0)", roster)
        no_descend = "if (at && !CFEqual(role, kAXGroupRole) && !CFEqual(role, kAXSplitGroupRole)) continue;"
        self.assertLess(roster.index(no_descend), roster.index("mrk_ax_array("))
        self.assertNotIn("kAXChildrenAttribute", roster.split(no_descend, 1)[0])
        self.assertIn("if (!children) { if (s->result.error) return NO; continue; }", roster)
        self.assertIn("CFEqual(role, kAXButtonRole)", roster)
        self.assertIn("CFEqual(title, prompt)) { matches++; pass->candidate = at; }", roster)
        self.assertIn("for (unsigned previous = 0; previous < queued; ++previous)", roster)
        self.assertIn("previous != at && pass->nodes[previous] && CFEqual(node, pass->nodes[previous])", roster)
        self.assertIn("mrk_ax_equal_attribute(s, node, kAXParentAttribute, pass->nodes[pass->parents[at]])", roster)
        self.assertIn("rechecking ? &s->result.recheck_nodes_examined : &s->result.initial_nodes_examined", roster)
        begun = "s->result.last_depth = pass->depths[at]; s->result.last_role = MRK_ROLE_NOT_READ;"
        self.assertLess(roster.index(begun), roster.index("if (at) (*examined)++"))
        self.assertLess(roster.index("if (at) (*examined)++"), roster.index("mrk_ax_type(s, node"))
        self.assertLess(roster.index("mrk_ax_type(s, node"), roster.index("CFEqual(node,"))
        self.assertLess(roster.index(begun), roster.index("kAXParentAttribute"))
        self.assertLess(roster.index(begun), roster.index("kAXRoleAttribute"))
        self.assertLess(roster.index("mrk_ax_type(s, role, CFStringGetTypeID())"), roster.index("s->result.last_role = mrk_ax_role(role)"))
        self.assertIn("if (!at && pass->roles[at] != MRK_ROLE_SHEET)", roster)
        self.assertIn("pass->parents[queued] = at; pass->depths[queued] = pass->depths[at] + 1; queued++;", roster)
        self.assertLess(roster.index("MRK_CONTROL_DEPTH) return"), roster.index("pass->nodes[queued] ="))
        self.assertLess(roster.index("MRK_CONTROL_NODES - queued"), roster.index("pass->nodes[queued] ="))
        self.assertLess(roster.index("CFStringGetLength(title)"), roster.index("s->result.checks |= 4u"))
        search = roster.split("s->result.checks |= 4u", 1)[0]
        self.assertNotIn("return YES", search)
        self.assertNotIn("break;", search)
        self.assertLess(roster.index("s->result.checks |= 4u"), roster.index("if (matches != 1)"))
        self.assertLess(roster.index("if (matches != 1)"), roster.index("s->result.checks |= 8u"))
        self.assertIn("for (unsigned node = pass->candidate; ; node = pass->parents[node])", roster)
        self.assertIn("pass->chain[pass->chain_count++] = node;", roster)
        self.assertIn("pass->chain_count == MRK_CONTROL_DEPTH + 1", roster)
        self.assertEqual(native.count("(*examined)++"), 1)
        for forbidden in ("kAXEnabledAttribute", "AXUIElementCopyActionNames", "CFRetain", "CFRelease", "s->button ="):
            self.assertNotIn(forbidden, roster)
        projection = native.split("static BOOL mrk_ax_projection(", 1)[1].split("static BOOL mrk_ax_control_roster(", 1)[0]
        for binding in ("kAXIdentifierAttribute", "kAXSheetRole", "kAXParentAttribute", "CFEqual(*parent, found_parent)", "CFEqual(*sheet, found_sheet)"):
            self.assertIn(binding, projection)
        self.assertEqual(projection.count("mrk_ax_type(s, candidate, s->elementType)"), 2)
        path = native.split("static BOOL mrk_ax_control_path(", 1)[1].split("static BOOL mrk_ax_button(", 1)[0]
        for fact in ("const MRKControlPass *original", "original->chain[left - 1]", "original->nodes[at]",
                     "at ? original->nodes[original->parents[at]] : parent", "s->result.last_role != original->roles[at]",
                     "MRK_ROLE_SHEET", "MRK_ROLE_GROUP", "MRK_ROLE_SPLIT_GROUP", "MRK_ROLE_BUTTON"):
            self.assertIn(fact, path)
        reset = "s->result.last_depth = original->depths[at]; s->result.last_role = MRK_ROLE_NOT_READ;"
        for call in ("mrk_ax_type(s, node", "kAXParentAttribute", "kAXRoleAttribute"):
            self.assertLess(path.index(reset), path.index(call))
        button = native.split("static BOOL mrk_ax_button(", 1)[1].split("static BOOL mrk_ax_original(", 1)[0]
        for fact in ("const MRKControlPass *original", "kAXTitleAttribute", "kAXEnabledAttribute", "CFBooleanGetValue", "AXUIElementCopyActionNames", "presses != 1"):
            self.assertIn(fact, button)
        self.assertIn("AXUIElementRef button = s->button;", button)
        self.assertIn("CFEqual(button, original->nodes[original->candidate])", button)
        self.assertLess(button.index("mrk_ax_control_path(s, parent, original)"), button.index("kAXTitleAttribute"))
        self.assertNotIn("kAXChildrenAttribute", button)
        action = native.split("static void mrk_ax_open(", 1)[1].split("void mrk_observation_prompt_press(", 1)[0]
        self.assertEqual(action.count("s->result.calls++; s->elementType = AXUIElementGetTypeID()"), 1)
        self.assertEqual(action.count("AXUIElementCreateApplication(getpid())"), 1)
        self.assertEqual(native.count("AXUIElementPerformAction(button, kAXPressAction)"), 1)
        first_census = "mrk_ax_control_roster(s, sheet, prompt_text->value, NO, &initial)"
        second_census = "mrk_ax_control_roster(s, sheet, prompt_text->value, YES, &rechecked)"
        self.assertIn("MRKControlPass initial = {0}, rechecked = {0};", action)
        self.assertEqual(action.count("mrk_ax_control_roster("), 2)
        self.assertEqual(action.count("mrk_ax_projection("), 2)
        self.assertEqual(action.count("mrk_ax_button(s, parent, &initial, prompt_text->value)"), 2)
        self.assertEqual(native.count("s->button ="), 1)
        self.assertLess(action.index("mrk_ax_original(s, 1)"), action.index(first_census))
        self.assertLess(action.index(first_census), action.index("s->button = initial.nodes[initial.candidate];"))
        self.assertLess(action.index("s->button = initial.nodes[initial.candidate];"), action.index("mrk_ax_button("))
        self.assertLess(action.index("mrk_ax_button("), action.rindex("mrk_ax_projection("))
        self.assertLess(action.rindex("mrk_ax_projection("), action.index(second_census))
        self.assertLess(action.index(second_census), action.index("initial.chain_count != rechecked.chain_count"))
        for same_original in ("CFEqual(initial.nodes[initial.chain[i]], rechecked.nodes[rechecked.chain[i]])",
                              "initial.roles[initial.chain[i]] != rechecked.roles[rechecked.chain[i]]"):
            self.assertLess(action.index("initial.chain_count != rechecked.chain_count"), action.index(same_original))
            self.assertLess(action.index(same_original), action.rindex("mrk_ax_button("))
        self.assertLess(action.rindex("mrk_ax_button("), action.index("s->result.checks |= 64u"))
        self.assertLess(action.index("s->result.checks |= 64u"), action.index("mrk_ax_original(s, 2)"))
        self.assertIn("AXUIElementRef button = s->button;", action)
        self.assertLess(action.index("mrk_ax_original(s, 2)"), action.index("mrk_ax_before(s, button)"))
        self.assertLess(action.index("mrk_ax_before(s, button)"), action.index("MRK_OPEN_ATTEMPTED"))
        self.assertLess(action.index("MRK_OPEN_ATTEMPTED"), action.index("AXUIElementPerformAction"))
        self.assertLess(action.index("AXUIElementPerformAction"), action.index("MRK_OPEN_RETURNED"))
        after_permit = action.split("if (!mrk_ax_before(s, button)) return;", 1)[1]
        for forbidden in ("mrk_ax_copy", "mrk_ax_array", "mrk_ax_original", "mrk_ax_button", "mrk_ax_control_roster", "mrk_ax_control_path", "sleep", "dispatch"):
            self.assertNotIn(forbidden, after_permit)
        timeout = native.split("static BOOL mrk_ax_before(", 1)[1].split("static BOOL mrk_ax_type(", 1)[0]
        self.assertIn("AXUIElementSetMessagingTimeout(element, timeout.seconds)", timeout)
        self.assertIn("s->result.calls > MRK_PROMPT_CALLS - 2", timeout)
        self.assertIn("timeout.seconds <= 0", timeout)
        self.assertIn("timeout.required_ns > 100000000", timeout)
        self.assertLess(timeout.index("AXUIElementSetMessagingTimeout"), timeout.index("mrk_ax_admit(s, timeout.required_ns"))
        entry = native.split("void mrk_observation_prompt_press(", 1)[1]
        self.assertIn("if (pthread_main_np())", entry)
        self.assertIn("enum { MRK_PROMPT_ORIGINALS = 9 };", native)
        self.assertIn("static MRKPrompt mrk_prompt_originals[MRK_PROMPT_ORIGINALS]", native)
        self.assertIn("atomic_load(&mrk_prompt_unknown) || atomic_flag_test_and_set(&mrk_prompt_active)", entry)
        self.assertIn("index >= MRK_PROMPT_ORIGINALS || !atomic_compare_exchange_strong(&mrk_prompt_next, &index, index + 1)", entry)
        self.assertLess(entry.index("atomic_compare_exchange_strong(&mrk_prompt_next"), entry.index("MRKPrompt *s = &mrk_prompt_originals[index]"))
        # A serial successor receives another original ledger, never the old
        # Project ledger. Clearing active must not reset the monotonic roster.
        self.assertIn("if (!(s->result.flags & MRK_OPEN_KNOWN)) atomic_store(&mrk_prompt_unknown, true)", entry)
        self.assertLess(entry.index("*out = s->result"), entry.index("atomic_flag_clear(&mrk_prompt_active)"))
        self.assertNotIn("atomic_store(&mrk_prompt_next", entry)
        self.assertNotIn("atomic_store(&mrk_prompt_unknown, false)", entry)
        cleanup = entry.split("for (unsigned left = s->count; left; --left)", 1)[1]
        self.assertLess(cleanup.index("mrk_ax_admit(s, 0,"), cleanup.index("CFRelease(slot->value)"))
        self.assertLess(cleanup.index("if (!s->cleanupKnown) break;"), cleanup.index("CFRelease(slot->value)"))
        self.assertIn("if (slot->value) CFRelease(slot->value); slot->value = NULL; s->result.released++", entry)
        self.assertIn("s->result.released == s->result.owned", entry)
        self.assertIn("s->admit = NULL; s->recheck = NULL; s->context = NULL;", entry)
        labels = rust.split("const OPEN_ERRORS:", 1)[1].split("];", 1)[0]
        self.assertEqual(set(M.re.findall(r'"([a-z-]+)"', labels)), M.ACCESSIBILITY_ERRORS)
        preparation = rust.split("pub fn installed_open_identity(", 1)[1].split("pub fn installed_open_recheck(", 1)[0]
        self.assertEqual(preparation.count('OpenDiagnostic { site: "entry"'), 3)
        self.assertNotIn('site: "binding"', preparation)
        wire = rust.split("fn open_return(", 1)[1].split("pub struct OpenInputReturn", 1)[0]
        sites = M.re.findall(r'"([a-z-]+)"', wire.split("site: *[", 1)[1].split("]", 1)[0])
        control_sites = ["control-title-limit", "control-child-count-limit", "control-child-copy-limit", "control-node-limit", "control-depth-limit"]
        self.assertEqual(sites[:14], "entry application windows parent-identifier sheet topology control-projection button "
                         "control-recheck initial-original-proof original-proof admission press cleanup".split())
        self.assertEqual(sites[14:19], control_sites)
        self.assertEqual(set(sites[19:]), M.ACCESSIBILITY_SELECTION_SITES)
        self.assertEqual(set(control_sites), M.ACCESSIBILITY_CONTROL_LIMIT_SITES)
        self.assertEqual(set(sites), M.ACCESSIBILITY_SITES)
        enum = native.split("enum { MRK_OPEN_ENTRY = 1u,", 1)[1].split("};", 1)[0]
        native_sites = M.re.findall(r"MRK_OPEN_[A-Z_]+", enum)
        self.assertEqual(native_sites[12:18], ["MRK_OPEN_CLEANUP", "MRK_OPEN_CONTROL_TITLE_LIMIT",
                          "MRK_OPEN_CONTROL_CHILD_COUNT_LIMIT", "MRK_OPEN_CONTROL_CHILD_COPY_LIMIT",
                          "MRK_OPEN_CONTROL_NODE_LIMIT", "MRK_OPEN_CONTROL_DEPTH_LIMIT"])
        self.assertEqual(native_sites[18:], ["MRK_OPEN_SELECTION_PARENT", "MRK_OPEN_SELECTION_PROJECTION",
                          "MRK_OPEN_SELECTION_RECHECK", "MRK_OPEN_SELECTION_SETTABLE", "MRK_OPEN_SELECTION_WRITE", "MRK_OPEN_SELECTION_READBACK"])
        helper = native.split("static BOOL mrk_ax_control_limit(", 1)[1].split("static uint32_t mrk_ax_role(", 1)[0]
        self.assertIn("s->result.site == MRK_OPEN_CONTROL_PROJECTION || s->result.site == MRK_OPEN_CONTROL_RECHECK", helper)
        self.assertIn("&& !s->result.error) s->result.site = site;", helper)
        self.assertIn("return mrk_ax_fail(s, MRK_OPEN_LIMIT);", helper)
        for condition, site, count in (("expected > limit", "COUNT", "expected"), ("count < 0 || count > limit", "COPY", "count")):
            guard = arrays.split(f"if ({condition}) {{", 1)[1].split("\n    }", 1)[0]
            self.assertEqual(guard.strip(),
                f"mrk_ax_control_limit(s, MRK_OPEN_CONTROL_CHILD_{site}_LIMIT);\n        return NULL;")
        for condition, site, section in (("CFStringGetLength(title) > 512", "TITLE", roster),
            ("pass->depths[at] == MRK_CONTROL_DEPTH", "DEPTH", roster),
            ("(unsigned)count > MRK_CONTROL_NODES - queued", "NODE", roster)):
            self.assertIn(f"if ({condition}) return mrk_ax_control_limit(s, MRK_OPEN_CONTROL_{site}_LIMIT)", section)
        self.assertEqual(native.count("mrk_ax_control_limit("), 6)
        role_labels = M.re.findall(r'"([A-Za-z-]+)"', wire.split("last_role: *[", 1)[1].split("]", 1)[0])
        self.assertEqual(tuple(role_labels), M.ACCESSIBILITY_CONTROL_ROLES)
        roles = native.split("static uint32_t mrk_ax_role(", 1)[1].split("static BOOL mrk_ax_status(", 1)[0]
        for role, code in (("Sheet", "SHEET"), ("Group", "GROUP"), ("SplitGroup", "SPLIT_GROUP"), ("Button", "BUTTON"),
                           ("Browser", "BROWSER"), ("Table", "TABLE"), ("Outline", "OUTLINE"), ("ScrollArea", "SCROLL_AREA")):
            self.assertIn(f"if (CFEqual(role, kAX{role}Role)) return MRK_ROLE_{code};", roles)
        self.assertIn("return MRK_ROLE_OPAQUE;", roles)
        self.assertTrue("sizeof(MRKOpenResult) == 80 && sizeof(MRKOpenRecheck) == 48" in native,
                        "native selection/Open wire80B and unchanged recheck48B")
        self.assertTrue("std::mem::size_of::<OpenWire>() != 80" in rust, "Rust selection/Open wire must be80B")
        self.assertIn("std::mem::size_of::<RecheckWire>() != 48", rust)
        self.assertIn("w.checks & (w.checks + 1) != 0", wire)
        self.assertIn("w.calls > 512 || w.initial_nodes_examined > 16 || w.recheck_nodes_examined > 16", wire)
        self.assertIn("w.checks < 63 && w.recheck_nodes_examined != 0", wire)
        self.assertIn("w.checks & 4 != 0 && w.initial_nodes_examined == 0", wire)
        self.assertIn("w.checks == 127 && (w.recheck_nodes_examined == 0 || w.last_role != 4 || w.last_depth == 0", wire)
        self.assertIn("w.site == 9 && (w.checks != 63 || w.last_depth > w.recheck_nodes_examined)", wire)
        for phase in ("3 if w.recheck_nodes_examined == 0 => w.initial_nodes_examined",
                      "63 if w.initial_nodes_examined >= 1 => w.recheck_nodes_examined",
                      "15 => w.last_role == 4 && node", "w.last_role == 1 && w.last_depth == 0 && examined == 0",
                      "18 => container && w.last_depth < 8", "19 => container && w.last_depth == 8"):
            self.assertIn(phase, wire)
        self.assertIn("button.cleanup_returned && w.released != w.owned", wire)
        self.assertIn("r.triggered == Some(false) && w.ax_error == 0", wire)

    def test_preconfigured_source_binds_once_before_presentation_and_exact_completion(self):
        desktop = PATH.parents[1]
        native = (desktop / "native/macos-installed-native/src/native.m").read_text(encoding="utf-8")
        rust = (desktop / "native/macos-installed-native/src/lib.rs").read_text(encoding="utf-8")
        adapter = (desktop / "src-tauri/src/shell_macos_dialog.rs").read_text(encoding="utf-8")
        observer = (desktop / "src-tauri/src/installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        arm = native.split("int mrk_panel_observe_arm_open_identity(", 1)[1].split("void mrk_panel_observe_identity_data(", 1)[0]
        for bound in ("capacity != 4097", "s->attempted || s->unknown || s->observationIdentity.flags",
                      "!mrk_target_path((const char *)target)", "i < capacity; ++i) if (target[i]) return EINVAL"):
            self.assertIn(bound, arm)
        self.assertEqual(native.count("memcpy(s->observationTarget, target, capacity)"), 1)
        for forbidden in ("setDirectoryURL:", "beginSheet", "[NS", "dispatch_", "s->selected", "s->response"):
            self.assertNotIn(forbidden, arm)
        construct = adapter.split("fn construct(", 1)[1].split("fn tick(", 1)[0]
        for binding in ("q.open_identity_scope(owner.id, choice)", "Arc::ptr_eq(&bound_call, call)",
                        "Arc::ptr_eq(&bound_owner, &owner)", "bound_owner.interrupted()", "!q.timely()"):
            self.assertLess(construct.index(binding), construct.index("panel.installed_arm_open_identity(target)"))
        self.assertLess(construct.index("q.open_identity_target(owner.id, choice)"), construct.index("panel.installed_arm_open_identity(target)"))
        self.assertLess(construct.index("panel.installed_arm_open_identity(target)"), construct.index("panel.start(choice)"))
        self.assertLess(construct.index("panel.installed_arm_open_identity(target)"), construct.index("panel.start_project_field(choice, root)"))
        scope = observer.split("pub(super) fn open_identity_scope(", 1)[1].split("pub(super) fn completion_returned(", 1)[0]
        self.assertIn("self.case != Case::PickerLoss && id == self.case.selected_id()", scope)
        self.assertIn("PanelKind::Project => self.case != Case::PickerLoss && id == self.case.selected_id()", scope)
        self.assertIn("PanelKind::File => self.case.file_index(id).is_some_and(|i| self.case.input_accepted(i))", scope)
        self.assertIn("fn input_accepted(self, i: u8) -> bool { matches!(self, Self::Ios(case) if session::accepted(case,i)) }", observer)
        self.assertIn("PanelKind::Quit => false", scope)
        self.assertIn("self.project_path.as_path()", scope)
        configured = native.split("static BOOL mrk_panel_configure_open_identity(MRKInstalledPanel *s) {", 1)[1].split("static BOOL mrk_original_eligible(", 1)[0]
        # Three disjoint purposes, not three competing ways to publish a choice:
        # historical Project/File identity; ordinary P2 initial root; one-use
        # synthetic P2 navigation after that root/options were observed.
        production = native.split("static int mrk_panel_initial_directory(", 1)[1].split("static int mrk_panel_start_inner(", 1)[0]
        navigation = native.split("int mrk_panel_observe_project_field(", 1)[1].split("enum { MRK_OPEN_ENTRY", 1)[0]
        self.assertEqual(native.count("setDirectoryURL:"), 3)
        for purpose in (configured, production, navigation):
            self.assertEqual(purpose.count("setDirectoryURL:"), 1)
        historical = configured.split("d->site = MRK_ID_DIRECTORY_URL;", 1)[1]
        self.assertLess(historical.index("MRK_ID_DIRECTORY_ENTERED"), historical.index("setDirectoryURL:url]"))
        self.assertLess(historical.index("setDirectoryURL:url]"), historical.index("MRK_ID_DIRECTORY_RETURNED"))
        self.assertLess(historical.index("MRK_ID_DIRECTORY_RETURNED"), historical.index("MRK_ID_CONFIG_COMPLETE"))
        self.assertIn("!mrk_target_path(s->observationTarget) || s->observationDirectoryReturned", configured)
        start = native.split("static int mrk_panel_start_inner(", 1)[1].split("int mrk_panel_start(", 1)[0]
        self.assertIn("#ifdef MRK_INSTALLED_OBSERVATION\n        if ((s->observationIdentity.flags & MRK_ID_ARMED)", start)
        self.assertLess(start.index("mrk_panel_configure_open_identity(s)"), start.index("beginSheetModalForWindow:"))
        for options in ("[panel setCanChooseFiles:kind == 3 || kind == 4]", "[panel setCanChooseDirectories:kind == 1 || (kind >= 5 && kind <= 7)]",
                        "[panel setAllowsMultipleSelection:NO]", "[panel setResolvesAliases:NO]"):
            self.assertIn(options, start)
        action = native.split("int mrk_panel_observe_action(", 1)[1].split("#undef MRK_ACTION_RETURN", 1)[0]
        self.assertIn("action != 1 && action != 4 && action != 5 && action != 6", action)
        self.assertNotIn("setDirectoryURL:", action)
        # Do not restore the old mandatory-URL/generic row selector. The new
        # kind4-only typed selection is not an ordinary picker/Project fallback.
        for retired in ("mrk_ax_row_target(", "mrk_ax_select_row(", "kAXURLAttribute"):
            self.assertFalse(retired in native, "retired row route: " + retired)
        ordinary = native.split("static BOOL mrk_ax_control_roster(", 1)[1].split("static BOOL mrk_ax_original(", 1)[0]
        for selecting in ("kAXRowsAttribute", "AXUIElementIsAttributeSettable(", "AXUIElementSetAttributeValue("):
            self.assertNotIn(selecting, ordinary)
        for retired in ("Step::SetProject", "PanelAction::ProjectDirectory", "selected_native"):
            self.assertFalse(retired in observer, "retired action bookkeeping: " + retired)
        self.assertIn("native_actions_returned: [bool; 4]", observer)
        self.assertIn("r.native_actions_returned[1] = true; r.step = Step::ProjectSettled;", observer)
        prepared = adapter.split("pub(crate) fn prepare_open_input(", 1)[1].split("pub(crate) fn open_release_data_check(", 1)[0]
        self.assertLess(prepared.index("identity.targets(target)"), prepared.index("OpenRelease::new()"))
        ready = native.split("static BOOL mrk_observation_directory_ready(", 1)[1].split("static BOOL mrk_observation_selection_parent(", 1)[0]
        self.assertIn("!s->observationDirectoryReturned", ready)
        self.assertIn("[(NSOpenPanel *)s->window directoryURL]", ready)
        self.assertIn("strcmp(path, s->observationTarget) == 0", ready)
        recheck = native.split("void mrk_panel_observe_open_recheck(", 1)[1].split("enum { MRK_PROMPT_CALLS", 1)[0]
        self.assertIn("memcmp(target, s->observationTarget, target_capacity)", recheck)
        self.assertIn("s->observationRechecks = stage;", recheck)
        self.assertIn("r.error = mrk_original_proof(s, &r.proof, NO, stage == 0)", recheck)
        for forbidden in (" URLs]", "setDirectoryURL:", "setNameFieldStringValue:", "memcpy(s->selected", "sleep("):
            self.assertNotIn(forbidden, recheck)
        callback = start.split("s->completion = Block_copy", 1)[1].split("beginSheetModalForWindow:", 1)[0]
        ordinary = ('NSURL *url = [(NSOpenPanel *)s->window URL];\n'
                    '                        const char *path = url && [url isFileURL] ? [url fileSystemRepresentation] : NULL;\n'
                    "                        if (!path || path[0] != '/' || strnlen(path, sizeof(s->selected)) >= sizeof(s->selected)) s->unknown = YES;\n"
                    '                        else memcpy(s->selected, path, strlen(path) + 1);')
        self.assertIn(ordinary, callback)  # The ordinary selected output stays authoritative.
        self.assertLess(callback.index("MRK_COMPLETION_DUPLICATE"), callback.index(ordinary))
        self.assertLess(callback.index(ordinary), callback.index("if (observed) mrk_panel_completion_selection(s)"))
        self.assertLess(callback.index("mrk_panel_completion_selection(s)"), callback.index("MRK_COMPLETION_RETURNED"))
        self.assertLess(callback.index("MRK_COMPLETION_RETURNED"), callback.index("s->callbackActive = NO"))
        self.assertIn("@catch (NSException *e) { (void)e; s->unknown = YES; }", callback)
        completed = native.split("static void mrk_panel_completion_selection(MRKInstalledPanel *s) {", 1)[1].split("static BOOL mrk_observation_directory_ready(", 1)[0]
        # One original completion read is independent of kind4 readiness.
        self.assertEqual(completed.count("[(NSOpenPanel *)s->window URLs]"), 1)
        self.assertEqual(ready.count("[(NSOpenPanel *)s->window URLs]"), 1)
        self.assertEqual(native.count("[(NSOpenPanel *)s->window URLs]"), 2)
        self.assertLess(completed.index("if (d->flags & MRK_COMPLETION_URLS_ENTERED)"), completed.index("d->flags |= MRK_COMPLETION_URLS_ENTERED"))
        self.assertLess(completed.index("d->flags |= MRK_COMPLETION_URLS_ENTERED"), completed.index("[(NSOpenPanel *)s->window URLs]"))
        self.assertLess(completed.index("[(NSOpenPanel *)s->window URLs]"), completed.index("d->flags |= MRK_COMPLETION_URLS_RETURNED"))
        self.assertLess(completed.index("d->flags |= MRK_COMPLETION_URLS_RETURNED"), completed.index("if (!urls)"))
        for gate in ("[urls isKindOfClass:[NSArray class]]", "if (!count)", "else if (count != 1)",
                     "[urls objectAtIndex:0]", "[url isKindOfClass:[NSURL class]] && [url isFileURL]",
                     "!mrk_target_path(path)", "strcmp(path, s->observationTarget) != 0", "strcmp(path, s->selected) != 0"):
            self.assertIn(gate, completed)
        for outcome in ("EMPTY", "MALFORMED", "MULTIPLE", "DIFFERENT", "DISAGREES", "MATCH"):
            self.assertIn("MRK_SELECTION_" + outcome, completed)
        self.assertEqual(native.count("memcpy(s->selected, path, strlen(path) + 1)"), 1)
        for forbidden in ("setDirectoryURL:", "setNameFieldStringValue:", "beginSheet", "memcpy(s->selected",
                          "s->response =", "s->unknown = NO", "dispatch_", "sleep(", "ok:"):
            self.assertNotIn(forbidden, completed)
        configuration = rust.split("fn identity_configuration(", 1)[1].split("pub(super) fn identity_start_return(", 1)[0]
        for gate in ("w.flags & !4095", "let base_flags = w.flags & 511", "(8, 2 | 14) => base_flags == 111",
                     "(9, 14) => base_flags == 239", "(5, 0) => base_flags == 511 && c.complete()",
                     "10 => file_flags == (512 | 1024) && base_flags == 495 && w.error == 14",
                     "11 => file_flags == (512 | 1024 | 2048) && base_flags == 495 && matches!(w.error, 13 | 14)"):
            self.assertIn(gate, configuration)
        identity_checks = rust.split("fn identity_data_check()", 1)[1].split("struct CompletionWire", 1)[0]
        for gate in ("IdentityWire { flags: 511, parent, prompt: 2, site: 5", "c.complete() && !c.file_panel",
                     "IdentityWire { flags: 4095, ..configured }", "c.file_name_setter_entered && c.file_name_setter_returned",
                     "[(2031, 10, 14), (4079, 11, 14), (4079, 11, 13)]"):
            self.assertIn(gate, identity_checks)
        for rejected in ("flags: 127", "flags: 255", "flags: 1023"):
            self.assertIn(rejected, identity_checks)

    def test_completion_source_captures_original_poll_errors_before_release_without_guards(self):
        desktop = PATH.parents[1]
        native = (desktop / "native/macos-installed-native/src/native.m").read_text(encoding="utf-8")
        rust = (desktop / "native/macos-installed-native/src/lib.rs").read_text(encoding="utf-8")
        adapter = (desktop / "src-tauri/src/shell_macos_dialog.rs").read_text(encoding="utf-8")
        observer = (desktop / "src-tauri/src/installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        qualification = PATH.read_text(encoding="utf-8")
        self.assertIn("sizeof(MRKCompletionWire) == 12", native)
        self.assertIn("std::mem::size_of::<CompletionWire>() != 12", rust)
        self.assertIn("struct CompletionWire { flags: u32, response: u32, selection: u32 }", rust)
        decoder = rust.split("fn completion_selection(", 1)[1].split("fn completion_poll_return(", 1)[0]
        for gate in ("w.flags & !63 != 0", "!r.callback_entered && (w.flags & !32 != 0", "r.urls_read_entered && r.response != Some(\"accept\")",
                     "r.urls_read_returned && !r.urls_read_entered", "r.selection.is_some() && !r.urls_read_returned",
                     "r.duplicate && !r.native_unknown", "!r.native_unknown && (!r.callback_entered || !r.callback_returned"):
            self.assertIn(gate, decoder)
        returned = rust.split("fn completion_poll_return(", 1)[1].split("fn completion_data_check()", 1)[0]
        self.assertIn("if status == 0 && w == CompletionWire::default() { return None; }", returned)
        for state in ("showing", "responded", "closed", "error", "invalid-return"):
            self.assertIn('"' + state + '"', returned)
        self.assertEqual(returned.count("mrk_panel_observe_completion_data(original.as_ptr(), &mut wire)"), 1)
        self.assertNotIn("mrk_panel_poll(", returned)
        poll = rust.split("pub fn poll(&mut self)", 1)[1].split("pub fn close_once(", 1)[0]
        self.assertEqual(poll.count("mrk_panel_poll("), 1)
        self.assertLess(poll.index("mrk_panel_poll("), poll.index("observation::completion_return(self.original, state)"))
        self.assertLess(poll.index("observation::completion_return(self.original, state)"), poll.index("match state"))
        self.assertIn("self.observation_identity_armed && !self.observation_completion_captured", poll)
        self.assertLess(poll.index("if let Some(returned) = observation::completion_return"), poll.index("self.observation_completion_captured = true"))
        self.assertIn("_ => { self.unknown = true; Err(io::ErrorKind::Other.into()) }", poll)
        take = rust.split("pub fn take_installed_completion_return(", 1)[1].split("pub fn installed_open_identity(", 1)[0]
        self.assertIn("self.observation_completion.take()", take)
        self.assertNotIn("self.usable()", take); self.assertNotIn("self.observation_completion_captured =", take)
        saved = native.split("void mrk_panel_observe_completion_data(", 1)[1].split("static BOOL mrk_identity_tag(", 1)[0]
        self.assertIn("memcpy(data, &s->observationCompletion, sizeof(*data))", saved)
        self.assertIn("if (s->unknown) data->flags |= MRK_COMPLETION_UNKNOWN", saved)
        for forbidden in ("mrk_panel_poll(", " URLs]", "s->unknown =", "s->observationCompletion =", "release]", "dispatch_"):
            self.assertNotIn(forbidden, saved)
        tick = adapter.split("fn tick(", 1)[1].split("pub(crate) async fn run_owned_dialog", 1)[0]
        for gate in ("observation::body_busy(id)", "!r.release_ready()", "observation::original(entry)",
                     "Arc::ptr_eq(&bound_call, call)", "bound_owner.id != id"):
            self.assertLess(tick.index(gate), tick.index("let polled = panel.poll()"))
        self.assertLess(tick.index("let polled = panel.poll()"), tick.index("panel.take_installed_completion_return()"))
        self.assertLess(tick.index("panel.take_installed_completion_return()"), tick.index("match polled"))
        self.assertLess(tick.index("panel.take_installed_completion_return()"), tick.index("panel.close_once()"))
        self.assertLess(tick.index("panel.take_installed_completion_return()"), tick.index("original.release()"))
        self.assertIn("*completion_return = panel.take_installed_completion_return().map(|data| (id, data))", tick)
        self.assertIn("Err(_) => return Err(()), // No close/release native work after uncertainty.", tick)
        publish = adapter.split("let result = tick(&observing", 1)[1].split("}).is_err()", 1)[0]
        self.assertLess(publish.index("&mut completion_return"), publish.index("q.completion_returned(id, data)"))
        self.assertLess(publish.index("q.completion_returned(id, data)"), publish.index("done.send(result)"))
        for forbidden in ("PANEL.with", ".facts()", "panel.poll()", "panel.release()", "panel.close_once()"):
            self.assertNotIn(forbidden, publish)
        once = observer.split("fn publish_completion(", 1)[1].split("struct NativeDispatch", 1)[0]
        self.assertIn("if !case.accepted_id(id) || slot.is_some()", once)
        accepted = observer.split("fn accepted_id(self, id: u32)", 1)[1].split("fn kind_name(", 1)[0]
        self.assertIn(
            "self != Self::PickerLoss && (id == self.selected_id() || self.file_index(id).is_some_and(|i| self.input_accepted(i))\n"
            "            || self.field_index(id).is_some_and(project_fields::accepts))",
            accepted,
        )
        for route in (
            "fn file_index(self, id: u32) -> Option<u8> { match self { Self::Ios(case) => session::file_index(case,id), _ => None } }",
            "fn input_accepted(self, i: u8) -> bool { matches!(self, Self::Ios(case) if session::accepted(case,i)) }",
            "fn field_index(self, id: u32) -> Option<u8> { (self == Self::ProjectFields).then(|| project_fields::index(id)).flatten() }",
        ):
            self.assertIn(route, observer)
        self.assertLess(once.index('return Err("native-completion-custody")'), once.index("*slot = Some(CompletionSample"))
        published = observer.split("pub(super) fn completion_returned(", 1)[1].split("pub(super) fn identity_start_returned(", 1)[0]
        self.assertIn("let timely = Instant::now() < self.end", published)
        self.assertIn('matches!(returned.poll_result, "error" | "invalid-return")', published)
        self.assertIn("returned.facts.is_some_and(|f| f.native_unknown || f.duplicate)", published)
        for forbidden in ("self.end =", "panel.poll", "selected_path(", ".release(", "refuse_original_at("):
            self.assertNotIn(forbidden, published)
        snapshot = observer.split("impl FailureSnapshot {", 1)[1].split("fn failure_context(", 1)[0]
        self.assertIn("completion_selection: r.completion_selection", snapshot)
        self.assertIn("self.completion_selection = None", snapshot)
        gate = observer.split('if response.operation_id != self.case.selected_id()', 1)[1].split("Step::PickerPending =>", 1)[0]
        for required in ("response.response != NativeResponse::Accept", "response.selected.as_deref() != Some(self.project_path.as_path())",
                         "!response.callback_returned", "!r.completion_selection.is_some_and(|s| s.succeeded(self.case.selected_id()))"):
            self.assertLess(gate.index(required), gate.index("r.project_settled = true"))
        self.assertIn('self.fail_with("native-completion-selection")', gate)
        finish = observer.split("fn finish(&self)", 1)[1].split("fn observe(q:", 1)[0]
        self.assertIn("r.completion_selection.is_none()", finish)
        self.assertIn("let project_open = r.project_open();", finish)
        self.assertIn("let completion_selection = project_open.map(|p| p.2);", finish)
        self.assertIn("completion_selection.is_some_and(|sample| sample.succeeded(self.case.selected_id()))", finish)
        self.assertIn('"projectCompletionSelection":completion_selection.map(CompletionSample::value)', finish)
        history = observer.split("fn project_open(&self)", 1)[1].split("fn open_sample(&self)", 1)[0]
        self.assertIn("if let Some(original) = self.panel_history.first()", history)
        self.assertIn("original.sample.reconciled(original.progress.snapshot()), original.identity, original.completion", history)
        self.assertIn("Some((self.open_sample()?, self.identity_binding?, self.completion_selection?))", history)
        for gate in ("self.panel_history.len() >= if self.project_field_record.is_some() { 9 } else { 7 }", "self.panel_history.iter().any(|p| p.sample.id == id)",
                     "self.pending.is_some() || self.prepared_open.is_some()", "!sample.succeeded() || sample.id != id",
                     '!identity.input_bound(id) || !completion.succeeded(id) || progress.snapshot().state != "retired"'):
            self.assertIn(gate, history)
        self.assertIn("accessibility.is_some_and(|s| s.id == self.case.selected_id() && s.succeeded())", finish)
        self.assertIn("identity_binding.is_some_and(|sample| sample.input_bound(self.case.selected_id()))", finish)
        self.assertIn("!completion_ownership_data_check()", observer)
        for bound in ("MRK_PROMPT_CALLS = 512", "MRK_PROMPT_CF = 256", "MRK_CONTROL_NODES = 17", "MRK_CONTROL_DEPTH = 8"):
            self.assertIn(bound, native)
        self.assertIn("let end = Instant::now() + Duration::from_secs(if matches!(case, Case::Ios(c) if !c.input_only()) { 315 } else { 45 });", observer)
        self.assertIn("let end = self.end.min(Instant::now() + Duration::from_secs(2));", observer)
        self.assertIn("timeout=case_timeout(case), capture=True, text=False, output_limit=OUTPUT_LIMIT", qualification)
        self.assertEqual([M.case_timeout(case) for case in M.CASES], [60] * 4)
        self.assertEqual([M.case_timeout(case) for case in M.IOS_CASES], [325] * 5)
        self.assertIn('len(data.encode("ascii")) <= (40 * 1024 if project_fields else 24 * 1024)', qualification)

    def test_semantic_timeout_uses_independent_relay_and_retains_original_receiver(self):
        desktop = PATH.parents[1]
        observer = (desktop / "src-tauri/src/installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        relay = observer.split("fn accessibility_step(", 1)[1].split("fn native_step(", 1)[0]
        self.assertIn("worker: Option<std::thread::JoinHandle<OpenWorkerReturn>>", observer)
        self.assertIn("returned: Option<OpenActionReceipt>", observer)
        self.assertIn("open_custody: Mutex<Option<OpenFlight>>", observer)
        self.assertLess(relay.index("*custody = Some(OpenFlight"), relay.index('.name("mrk-aqua-open".into()).spawn('))
        self.assertLess(relay.index('.name("mrk-aqua-open".into()).spawn('), relay.index("flight.worker = Some(handle)"))
        self.assertLess(relay.index("flight.worker = Some(handle)"), relay.index("let end = self.end.min("))
        self.assertLess(relay.index("let end = self.end.min("), relay.index("sender.try_send(Some(end))"))
        self.assertLess(relay.index("OpenRecheckSlot { receipt: Some(first_receipt)"), relay.index('.name("mrk-aqua-open".into()).spawn('))
        timed = relay.split("let end = self.end.min(", 1)[1]
        for forbidden in ("self.record()", ".admitted(", ".lock()", ".spawn("):
            self.assertNotIn(forbidden, timed)
        loop = timed.split("        loop {", 1)[1].split("        if flight.returned.is_none()", 2)
        deadline = loop[0]
        self.assertIn("token.expire(); self.fail_with(\"native-default-deadline\")", deadline)
        self.assertIn("if now >= self.end", deadline)
        self.assertIn("let mut deadline_observed = false;", timed)
        self.assertIn("deadline_observed = true;", deadline)
        self.assertLess(timed.index("if now >= end && !deadline_observed"), timed.index("flight.receipt.try_recv()"))
        self.assertLess(timed.index("if now >= end && !deadline_observed"), timed.index("handle.is_finished()"))
        self.assertLess(timed.index("handle.is_finished()"), timed.index('.expect("positively finished original").join()'))
        self.assertIn("let wait_end = if token.expired() { self.end } else { end };", timed)
        self.assertLess(timed.index("flight.worker_returned = Some(returned)"), timed.index("let rechecks_settled ="))
        self.assertLess(timed.index("let rechecks_settled ="), timed.index("let joined = known && token.joined()"))
        self.assertLess(timed.index("let joined = known && token.joined()"), timed.index("let retired = joined && token.retire()"))
        no_go = timed.split("if !go_published && flight.worker_returned == Some(OpenWorkerReturn::NoGo)", 1)[1]
        self.assertIn("flight.returned.is_none()", no_go)
        self.assertIn("flight.input.no_entry(true)", no_go)
        returned = relay.split("let Some(receipt) = flight.returned.as_ref()", 1)[1]
        self.assertIn("let returned_at = receipt.returned_at", returned)
        self.assertIn("token.same(&receipt.token)", returned)
        self.assertIn("let known = worker_retirement_ready(flight.worker_returned, same, rechecks_settled, body.custody_known(), token.state())", returned)
        ready = observer.split("fn worker_retirement_ready(", 1)[1].split("struct OpenFlight", 1)[0]
        self.assertIn("worker == Some(OpenWorkerReturn::Body) && same_receipt && rechecks_settled == Some(true)", ready)
        self.assertIn('body_known && state == "returned"', ready)
        self.assertNotIn("native", ready)  # A known late nonentry can settle without a native action.
        self.assertIn("first_failure_reason(&self.failure_reason) == Some(\"native-default-input\")", returned)
        self.assertIn("let stop_at = if deadline_first { end } else { returned_at.min(end) };", returned)
        self.assertIn("if failed && token.refuse_original_at(stop_at, reason).is_err()", returned)
        for earlier, later in (("token.retire()", "!retire_returned_open("),
                               ("!retire_returned_open(", "if Instant::now() >= end"),
                               ("if Instant::now() >= end", "drop(r); *custody = None; drop(custody);"),
                               ("drop(r); *custody = None; drop(custody);", "token.refuse_original_at(")):
            self.assertLess(returned.index(earlier), returned.index(later))
        worker = observer.split("fn action_worker(", 1)[1].split("fn open_unknown(", 1)[0]
        self.assertLess(worker.index("go.recv()"), worker.index("token.enter()"))
        self.assertLess(worker.index("token.enter()"), worker.index("installed_prompt_button("))
        self.assertLess(worker.index("installed_prompt_button("), worker.index("token.returned()"))
        self.assertLess(worker.index("token.returned()"), worker.index("done.try_send(receipt)"))
        self.assertNotIn("self.record()", worker)
        self.assertNotIn(".join()", worker)
        main = observer.split("fn action_recheck_main(", 1)[1].split("fn worker_admission(", 1)[0]
        self.assertLess(main.index("token.recheck("), main.index("let receipt = OpenRecheckReceipt"))
        self.assertLess(main.index("let receipt = OpenRecheckReceipt"), main.index("done.try_send(receipt)"))
        permit = observer.split("fn worker_admission(", 1)[1].split("fn worker_recheck(", 1)[0]
        self.assertIn("Instant::now() >= self.end", permit)
        self.assertIn("return None;", permit)
        for forbidden in ("self.record()", ".lock()", ".admitted(", "PANEL.with", "run_on_main_thread"):
            self.assertNotIn(forbidden, permit)
        recheck = observer.split("fn worker_recheck(", 1)[1].split("fn action_worker(", 1)[0]
        self.assertLess(recheck.index("slot.dispatched = true"), recheck.index("app.run_on_main_thread("))
        self.assertIn("slot.uncertain = true", recheck)
        self.assertIn("slot.settled(token, stage, self.end)", recheck)
        self.assertIn("receiver.recv_timeout(self.end.saturating_duration_since(Instant::now()))", recheck)
        self.assertIn("[OpenRecheckSlot; 3]", recheck)
        self.assertIn("slot.receipt.take()", recheck)
        self.assertIn("std::mem::ManuallyDrop::new(receiver)", recheck)
        self.assertIn("slot.receipt = Some(std::mem::ManuallyDrop::into_inner(receiver))", recheck)
        self.assertLess(recheck.index("}; // NO ledger/Record/GuiFacts lock"), recheck.index("app.run_on_main_thread("))
        unlocked = recheck.split("}; // NO ledger/Record/GuiFacts lock", 1)[1].split("let Ok(mut ledger) = rechecks.try_lock()", 1)[0]
        for retained_lock in (".lock()", ".try_lock()", "self.record()"):
            self.assertNotIn(retained_lock, unlocked)
        for name in ("parent_receipt", "first_receipt", "final_receipt"):
            self.assertLess(relay.index(f"receipt: Some({name})"), relay.index('.name("mrk-aqua-open".into()).spawn('))
        report = observer.split("fn report_failure(", 1)[1].split("pub(super) fn attach(", 1)[0]
        self.assertLess(report.index("drop(r)"), report.index("self.diagnostic.submit(snapshot.frame(reason))"))
        expiry = report.split("fn report_expiry(", 1)[1]
        for forbidden in ("stderr()", "stdout()", "self.record", "self.open_custody", ".lock()", "write_all", "writeln!"):
            self.assertNotIn(forbidden, expiry)
        self.assertIn("snapshot.at_expiry(progress).frame(reason)", expiry)
        snapshot = observer.split("struct FailureSnapshot", 1)[1].split("fn failure_context(", 1)[0]
        self.assertIn('self.source = "prearm-open-progress"', snapshot)
        self.assertIn("8192", snapshot)
        self.assertIn("context.is_ascii()", snapshot)
        writer = observer.split("struct DiagnosticWriter", 1)[1]
        self.assertIn("pub(crate) struct Observation", writer)
        writer = writer.split("pub(crate) struct Observation", 1)[0]
        self.assertEqual(writer.count(".spawn(move ||"), 1)
        self.assertEqual(writer.count("stderr().lock()"), 1)
        self.assertIn("sync_channel::<Option<Vec<u8>>>(1)", writer)
        self.assertIn("compare_exchange(0, choice", writer)
        self.assertIn("self.sender.try_send(frame)", writer)
        self.assertLess(writer.index("is_finished()"), writer.index(".join()"))
        self.assertIn("owner.returned = Some(returned)", writer)
        self.assertIn("end.saturating_duration_since(Instant::now())", writer)
        self.assertNotIn("Duration::from_secs(", writer)
        self.assertNotIn("OpenAction", writer)
        observe = observer.split("fn observe(q:", 1)[1].split("pub(crate) fn main()", 1)[0]
        self.assertIn("q.finish()", observe)
        self.assertIn("edit::bounded(&report", observe)
        completion = observer.split("let report = observe(&q);", 1)[1]
        self.assertLess(completion.index("q.diagnostic.finish(q.end)"), completion.index("!q.timely()"))
        self.assertIn("q.open_custody.try_lock().map(|custody| custody.is_none()).unwrap_or(false)", completion)
        retain = completion.split("if returned.is_none() || !input_clear {", 1)[1].split("let returned = returned.expect(", 1)[0]
        self.assertLess(retain.index("std::mem::forget(q)"), retain.index("return std::process::ExitCode::FAILURE"))
        self.assertLess(completion.index("!q.timely()"), completion.index("stdout().lock()"))
        self.assertIn("std::mem::forget(q)", completion)
        self.assertNotIn("super::diagnostic", completion)
        self.assertNotIn("q.report_failure()", completion.split("q.diagnostic.finish(q.end)", 1)[1])
        close = observer.split("pub(super) fn close_prevented(", 1)[1].split("fn failure_shutdown(", 1)[0]
        self.assertNotIn("r.pending.take()", close)
        self.assertLess(close.index("let Some(Pending::Close(request))"), close.index("r.pending = None"))

    def test_semantic_reentrancy_defers_poll_close_and_release_until_actual_join(self):
        shell = (PATH.parents[1] / "src-tauri/src/shell_macos_dialog.rs").read_text(encoding="utf-8")
        tick = shell.split("fn tick(call:", 1)[1].split("pub(crate) async fn run_owned_dialog", 1)[0]
        self.assertLess(tick.index("observation::body_busy(id)"), tick.index("PANEL.with("))
        self.assertLess(tick.index("!r.release_ready()"), tick.index("panel.poll()"))
        self.assertLess(tick.index("panel.poll()"), tick.index("panel.close_once()"))
        self.assertIn("enum OpenPhase { Prepared, Requested, Queued, Entered, Returned, Joined, Retired, Unknown }", shell)
        self.assertIn("progress: AtomicU16", shell)
        self.assertIn("let bits = self.progress.load(Ordering::SeqCst)", shell)
        self.assertIn("self.progress.fetch_or(OpenPhase::Unknown as u16", shell)
        self.assertIn("self.progress.fetch_or(OPEN_EXPIRED", shell)
        self.assertIn("queued.snapshot() != (OpenProgress", shell)
        self.assertIn("OpenPhase::Joined, OpenPhase::Retired", shell)
        recheck = shell.split("pub(crate) fn recheck(", 1)[1].split("pub(crate) fn prepare_open_input(", 1)[0]
        self.assertLess(recheck.index("!native::main_thread()"), recheck.index("OpenBodyGuard::enter(self)"))
        self.assertLess(recheck.index("OpenBodyGuard::enter(self)"), recheck.index("PANEL.with("))
        for same in ("Arc::ptr_eq(&call, &self.call)", "Arc::ptr_eq(&owner, &self.owner)", "Arc::ptr_eq(r, &self.release)"):
            self.assertIn(same, recheck)
        self.assertEqual(recheck.count("panel.installed_open_recheck(&self.identity, stage)"), 1)
        self.assertLess(recheck.index("panel.installed_open_recheck("), recheck.index("let after = admit(true)"))
        for forbidden in ("installed_prompt_button(", "observe_panel_action", "self.returned()", "self.retire()"):
            self.assertNotIn(forbidden, recheck)
        refusal = shell.split("pub(crate) fn refuse_original_at(", 1)[1].split("pub(crate) fn identity(", 1)[0]
        self.assertEqual(refusal.count('self.state() != "retired"'), 2)
        self.assertIn("original_admitted(self.id, &self.call, &self.owner, true) != Some(true)", refusal)
        self.assertIn("Reason::SourceRefused | Reason::Deadline", refusal)
        self.assertLess(refusal.index('self.state() != "retired"'), refusal.index("self.call.failed_at(reason, at)"))
        self.assertEqual(refusal.count("self.call.failed_at("), 1)
        for forbidden in ("Instant::now", "PANEL.with", ".installed_", "observe_panel_action", "set_endpoint", ".retire()"):
            self.assertNotIn(forbidden, refusal)
        asset = (PATH.parents[1] / "src-tauri/src/asset_session.rs").read_text(encoding="utf-8")
        failed = asset.split("pub(crate) fn failed(&self,", 1)[1].split("pub(crate) fn begin_response(", 1)[0]
        self.assertIn("self.failed_at(reason, Instant::now());", failed)
        self.assertLess(failed.index("let mut state = document.lock()"), failed.index("fail_gui_original_locked("))
        self.assertLess(failed.index("fail_gui_original_locked("), failed.index("document.bump(&mut state); self.changed();"))
        self.assertNotIn("drop(state)", failed)  # Existing intra-document notification order.
        transition = asset.split("fn fail_gui_original_locked(", 1)[1].split("struct Slot", 1)[0]
        self.assertIn("Arc::ptr_eq(&slot.owner, owner)", transition)
        self.assertIn("Arc::ptr_eq(quit, owner)", transition)
        self.assertLess(transition.index("facts.refusal"), transition.index("slot.stop(reason, at)"))
        self.assertLess(transition.index("slot.stop(reason, at)"), transition.index("stop_quit(state, at)"))
        self.assertLess(transition.index("stop_quit(state, at)"), transition.index("owner.stop()"))
        for forbidden in ("Instant::now", "not_created(", "begin_response(", "selected_path(", "owner.id ==", "state.unknown = false"):
            self.assertNotIn(forbidden, transition)
        native = (PATH.parents[1] / "native/macos-installed-native/src/native.m").read_text(encoding="utf-8")
        release = native.split("int mrk_panel_release(", 1)[1].split("#ifdef MRK_INSTALLED_OBSERVATION\n// No separate window lookup:", 1)[0]
        self.assertIn("s->unknown || s->callbackActive || !s->closed", release)
        self.assertLess(release.index("Block_release(s->completion)"), release.index("[s->window release]"))
        self.assertNotIn("observationDefaultElement", release)
        callback = native.split("s->completion = Block_copy", 1)[1].split("beginSheetModalForWindow:", 1)[0]
        self.assertIn("s->callbackActive = YES", callback)
        self.assertIn("s->callbackActive = NO", callback)
        self.assertNotIn("observationConfirm", callback)
        rust = (PATH.parents[1] / "native/macos-installed-native/src/lib.rs").read_text(encoding="utf-8")
        self.assertNotIn("AxProjection", rust)
        self.assertNotIn("DefaultPacket", rust)
        self.assertIn("fn semantic_data_check()", rust)
        self.assertNotIn("Duration::from_secs(2)", rust)

    def test_dom_callback_custody_wraps_only_the_original_returned_body(self):
        # Source controls only: the actual Rust DATA entry and native callback
        # are executed by the reviewed macOS qualification, not these tests.
        observer = (PATH.parents[1] / "src-tauri" / "src" / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        dispatch = observer.split("if r.evaluations >= 160", 1)[1].split("fn action_original(", 1)[0]
        self.assertLess(dispatch.index("r.evaluations += 1"), dispatch.index("sequence: r.evaluations"))
        self.assertIn("r.pending = Some(Pending::Dom(original)); original", dispatch)
        self.assertIn("if r.pending == Some(Pending::Dom(original)) { r.pending = None; }", dispatch)
        self.assertIn("q.dom(original,&value)", dispatch)
        refused = dispatch.split("if window.eval_with_callback", 1)[1]
        self.assertIn('self.fail_with("dom-dispatch-refused")', refused)
        self.assertNotIn("r.pending = None", refused)
        entry = observer.split("fn dom_step_entry(", 1)[1].split("// Only the wrapper", 1)[0]
        self.assertIn("(1..=160).contains(&original.sequence)", entry)
        self.assertIn("current == original.step && pending == Some(Pending::Dom(original))", entry)
        retirement = observer.split("fn retire_returned_dom(", 1)[1].split("#[derive", 1)[0]
        self.assertIn("*pending != Some(Pending::Dom(original)) { return false; }", retirement)
        self.assertNotIn("current", retirement)
        self.assertNotIn("take()", retirement)
        wrapper = observer.split("    fn dom(", 1)[1].split("    fn dom_body(", 1)[0]
        self.assertIn("let Some(mut r) = self.record() else { return; };", wrapper)
        authenticated = 'if !dom_step_entry(r.pending, r.step, original) { self.fail_with("dom-pending-custody"); return; }'
        self.assertLess(wrapper.index(authenticated), wrapper.index("self.dom_body(&mut r, original, raw)"))
        self.assertLess(wrapper.index("self.dom_body(&mut r, original, raw)"), wrapper.index("retire_returned_dom(&mut r.pending, original)"))
        self.assertEqual(wrapper.count("self.record()"), 1)
        for forbidden in ("catch_unwind", "drop(r)", "r.pending.take()", "r.step !="):
            self.assertNotIn(forbidden, wrapper)
        body = observer.split("    fn dom_body(", 1)[1].split("    pub(super) fn relay_joined", 1)[0]
        for forbidden in ("self.record()", "r.pending", "catch_unwind", "failed.store", "self.end ="):
            self.assertNotIn(forbidden, body)
        self.assertEqual(body.count("if !self.timely() { return; }"), 5)
        for label in ("dom-callback-size", "dom-callback-json", "dom-callback-object", "dom-callback-state"):
            self.assertIn(f'self.fail_with("{label}")', body)
        # Legacy, iOS and session branches retain the original DOM wrapper/cutoff.
        # iOS validates a comparison-DATA candidate; only a timely commit may
        # publish ready flags, and it never clones owner/native custody.
        ios = body.split("if let Step::Ios(step) = step {", 1)[1].split("let review_round =", 1)[0]
        self.assertIn("let mut observed = record.clone();", ios)
        self.assertEqual(ios.count("r.ios_record = Some(observed)"), 2)
        next_commit, final_commit = ios.split("Ok(None) =>", 1)
        for commit in (next_commit, final_commit):
            self.assertLess(commit.index("if !self.timely() { return; }"), commit.index("r.ios_record = Some(observed)"))
        session = body.split("if let Step::Session(step) = step {", 1)[1].split("let review_round =", 1)[0]
        self.assertIn("let mut observed = session.clone();", session)
        self.assertIn("Ok(next) if self.timely() => { r.session_record = Some(observed); r.step = Step::Session(next); }", session)
        before_transition = body.split("let review_round =", 1)[1].split("r.step = match step", 1)[0]
        self.assertTrue(before_transition.rstrip().endswith("if !self.timely() { return; }"))
        self.assertNotRegex(before_transition, r"r\.[a-z_]+\s*(?:\+=|=(?!=))")
        shutdown = observer.split("fn failure_shutdown(", 1)[1].split("    fn dom(", 1)[0]
        self.assertIn("if r.pending.is_some() || r.failure_quit_attempted { return; }", shutdown)
        context = observer[observer.index("fn failure_context("):]
        context = context[:context.index("\n}\n") + 3]
        self.assertIn('Pending::Dom(original) => ("dom", Some(original.step))', context)
        self.assertNotIn("sequence", context)

    def test_picker_result_routes_errors_without_admitting_early_success(self):
        observer = (PATH.parents[1] / "src-tauri" / "src" / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        route = observer.split("fn project_return_route(", 1)[1].split("fn native_step_entry(", 1)[0]
        self.assertLess(route.index("if reload_requested && case == Case::PickerLoss"), route.index("match result"))
        self.assertIn('if project_returned || result.as_ref().is_ok_and(Option::is_some) { return Err("observer-invariant"); }', route)
        self.assertIn("case == Case::FirstSave && matches!(step, Step::CancelProject | Step::CancelSettled)", route)
        self.assertLess(route.index('if cancel && cancel_returned { return Err("cancel-duplicate-result"); }'), route.index("match result"))
        self.assertIn("Err(error) => Err(crate::asset_commands::AssetError::new(error.reason).code)", route)
        self.assertIn("Ok(None) if cancel => Ok(ProjectReturn::Cancelled)", route)
        self.assertIn('Ok(Some(_)) if cancel => Err("cancel-unexpected-project")', route)
        self.assertIn("Ok(Some(_)) if matches!(step, Step::OpenProject | Step::ProjectSettled) => Ok(ProjectReturn::Selected)", route)
        self.assertIn('_ => Err("picker-unexpected-result")', route)
        for forbidden in ("error.code", "error.message", "project_calls", "r.step =", "observe_panel_action"):
            self.assertNotIn(forbidden, route)
        handler = observer.split("pub(super) fn project_result(", 1)[1].split("pub(super) fn snapshot_request(", 1)[0]
        self.assertLess(handler.index("match project_return_route("), handler.index("let Ok(Some(project))"))
        self.assertIn("Err(reason) => { self.fail_with(reason); return; }", handler)
        self.assertIn('let Ok(Some(project)) = result else { self.fail_with("project-result-shape"); return; };', handler)
        classified = "selected_project_failure(r.step, r.project.is_some(), project, &self.project_path, self.case.name())"
        self.assertLess(handler.index(classified), handler.index("r.project_returned = true; r.project = Some(project.clone());"))
        classifier = observer.split("fn selected_project_failure(", 1)[1].split("fn snapshot_error_reason(", 1)[0]
        predicates = ("!matches!(step, Step::OpenProject | Step::ProjectSettled) || already_selected",
                      "Path::new(&project.path) != expected_path", "project.name != expected_name", "!crate::protocol::valid_id(&project.id)")
        self.assertEqual(sorted(classifier.index(value) for value in predicates), [classifier.index(value) for value in predicates])
        for label in ("order", "name", "id"):
            self.assertIn(f'return Some("project-result-{label}")', classifier)
        self.assertIn('if Path::new(&project.path) != expected_path { return Some(project_path_mismatch_reason(Path::new(&project.path), expected_path)); }', classifier)
        self.assertNotIn("project_calls", handler)
        self.assertNotIn("r.step =", handler)

    def test_project_selection_capture_is_immediate_original_data_not_later_success(self):
        source_root = PATH.parents[1] / "src-tauri" / "src"
        asset = (source_root / "asset_session.rs").read_text(encoding="utf-8")
        shell = (source_root / "shell.rs").read_text(encoding="utf-8")
        observer = (source_root / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        result = asset.split("pub(crate) async fn project_result(", 1)[1].split("pub(crate) fn choose_project_path(", 1)[0]
        self.assertEqual(result.count("loop {"), 1)
        self.assertEqual(result.count("self.reconcile();"), 1)
        self.assertEqual(result.count("tokio::time::sleep(Duration::from_millis(50)).await"), 1)
        original = result.split("async fn project_result_original(", 1)[1]
        for predicate in ("let state = self.lock();", "slot.owner.id == id", "if state.unknown",
                          "slot.phase == Phase::Idle && slot.owner.resources_settled()",
                          "slot.reason == Reason::None || slot.reason == Reason::UserCancelled"):
            self.assertLess(original.index(predicate), original.index("capture_project_selection(&self.inner, id, slot, project)"))
        self.assertLess(original.index("capture_project_selection(&self.inner, id, slot, project)"), original.index("return Ok(slot.project.clone());"))
        self.assertIn("return Err(AssetError::new(slot.reason));", original)
        capture = asset.split("pub(super) fn capture_project_selection(", 1)[1].split("pub(crate) fn selection_saved_data_checks()", 1)[0]
        for required in ("slot.operation == Operation::ChooseProject", "slot.owner.id == id", "original_call(document, &slot.owner)",
                         "same_project(saved, project)", "slot.owner.gui.installed_native_response()", "document.bridge.native_project(&project.id)"):
            self.assertIn(required, capture)
        for forbidden in ("installed_macos_project(", "completed(", ".ended.load", "resources_settled(", ".edits", "registry_result(",
                          "native_roster(", ".reconcile(", ".join", ".poll", ".await", "Record", "self.record(", "metadata("):
            self.assertNotIn(forbidden, capture)
        projection = asset.split("fn recorded_identity(", 1)[1].split("fn saved_project_selection(", 1)[0]
        for required in ("root.identity.posix().ok()?.preflight_identity()", "identity.device.parse().ok()?", "identity.inode.parse().ok()?",
                         "u64::from(identity.mode)", "u64::from(identity.uid)", "u64::from(identity.gid)"):
            self.assertIn(required, projection)
        for forbidden in ("metadata(", "std::fs", "as f64", "unwrap_or(0)", "canonicalize"):
            self.assertNotIn(forbidden, projection)
        saved = asset.split("fn saved_project_selection(", 1)[1].split("pub(crate) fn selection_saved_data_checks()", 1)[0]
        self.assertIn("saved.operation_id == id && saved.response == NativeResponse::Accept", saved)
        self.assertIn("!saved.callback_returned", saved)
        self.assertIn("*generation != 2", saved)
        self.assertIn("same_project(project, returned)", saved)
        checks = asset.split("pub(crate) fn selection_saved_data_checks()", 1)[1].split("pub(crate) struct ProjectWitness", 1)[0]
        self.assertIn("owner.gui.installed_native_response()", checks)
        self.assertIn("!owner.resources_settled() || owner.ended.load(Ordering::SeqCst)", checks)
        self.assertIn("book.receipt == JoinReceipt::New", checks)
        self.assertIn("owner.ended.load(Ordering::SeqCst) || owner.project_path_settled(true)", checks)
        self.assertIn("data.for_result(2, &project) != (SelectionCustody::Bound", checks)
        completed = asset.split("fn completed(document:", 1)[1].split("fn same_project(", 1)[0]
        self.assertIn("!owner.ended.load(Ordering::SeqCst) || !owner.resources_settled()", completed)
        self.assertIn("book.receipt == if probed { JoinReceipt::Returned } else { JoinReceipt::New }", completed)
        command = shell.split("async fn choose_project(webview:", 1)[1].split("async fn choose_project_path(", 1)[0]
        self.assertEqual(command.count("state.document.installed_macos_project_result(id, &mut selection).await"), 1)
        self.assertEqual(command.count("state.document.project_result(id).await"), 1)  # Ordinary/Linux return is unchanged.
        self.assertIn("q.project_result(&result);", command)  # Linux/Windows hook signature is unchanged.
        one_arg_gate = command.split("if let Some(q) = &state.observation { q.project_result(&result); }", 1)[0].rsplit("#[cfg(", 1)[1]
        self.assertIn('target_os = "linux"', one_arg_gate)
        self.assertIn('target_os = "windows"', one_arg_gate)
        self.assertNotIn('target_os = "macos"', one_arg_gate)
        two_arg_gate = command.split("if let Some(q) = &state.observation { q.project_result(&result, selection.as_ref()); }", 1)[0].rsplit("#[cfg(", 1)[1]
        self.assertIn('target_os = "macos"', two_arg_gate)
        self.assertNotIn('target_os = "linux"', two_arg_gate)
        self.assertNotIn('target_os = "windows"', two_arg_gate)
        self.assertLess(command.index("}.await;"), command.index("q.project_result(&result, selection.as_ref())"))
        for source in (result, command):
            self.assertIn('feature = "macos-installed-observation"', source)
            self.assertIn('not(feature = "macos-installed-installer")', source)
            self.assertIn('target_os = "macos", target_arch = "aarch64"', source)
        handler = observer.split("pub(super) fn project_result(", 1)[1].split("pub(super) fn snapshot_request(", 1)[0]
        self.assertLess(handler.index("selected_project_failure("), handler.index("ProjectSelectionSample::from_data("))
        self.assertLess(handler.index("if project_selection_failure_reason(reason)"), handler.index("latch_project_selection("))
        self.assertLess(handler.index("latch_project_selection("), handler.index("r.project_returned = true; r.project = Some(project.clone());"))
        for forbidden in ("state.document", "installed_macos_project(", "r.project_witness =", "observe_panel", "metadata("):
            self.assertNotIn(forbidden, handler)

    def test_navigation_observer_cfg_preserves_all_platform_callbacks(self):
        shell = (PATH.parents[1] / "src-tauri/src/shell.rs").read_text(encoding="utf-8")
        def gate(marker):
            return shell.split(marker, 1)[0].rsplit("#[cfg(", 1)[1].split(")]", 1)[0]
        page = gate("let page_observation = observation.clone();")
        self.assertEqual(gate("let navigation_observation = observation.clone();"), page)
        self.assertEqual(gate("if let Some(q) = &navigation_observation {"), page)
        for platform in ("linux", "macos", "windows"):
            self.assertIn('target_os = "' + platform + '"', page)
        navigation = shell.split(".on_navigation(move |url| {", 1)[1].split(".on_page_load(", 1)[0]
        self.assertIn("let route = navigation_windows.navigation(url);", navigation)
        self.assertIn("route != owned_windows::EventRoute::Controlled", navigation)
        self.assertIn("let allowed = navigation.navigation(_trusted);", navigation)
        self.assertIn("if _observed.0 { q.navigation(_observed.1, allowed); }", navigation)
        self.assertIn("qualification::EventKind::Navigation, u32::from(_trusted && allowed)", navigation)

    def test_project_selection_labels_identity_axes_and_first_winner_are_bounded(self):
        source_root = PATH.parents[1] / "src-tauri" / "src"
        asset = (source_root / "asset_session.rs").read_text(encoding="utf-8")
        observer = (source_root / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        custody = asset.split("impl SelectionCustody", 1)[1].split("// Short-lived", 1)[0]
        objects = observer.split("impl RecordedSelectionObject", 1)[1].split("enum SelectionLocation", 1)[0]
        locations = observer.split("impl SelectionLocation", 1)[1].split("struct ProjectSelectionSample", 1)[0]
        for source, expected in ((custody, M.PROJECT_SELECTION_CUSTODY), (objects, M.PROJECT_SELECTION_OBJECTS),
                                 (locations, M.PROJECT_SELECTION_LOCATIONS)):
            self.assertEqual(set(M.re.findall(r'=> "([a-z0-9-]+)"', source)), expected)
        reasons = observer.split("fn project_selection_failure_reason(", 1)[1].split("fn latch_project_selection(", 1)[0]
        self.assertEqual(set(M.re.findall(r'"(project-result-path[a-z-]*)"', reasons)), set(M.PROJECT_SELECTION_BOUND_LOCATIONS))
        sample = observer.split("impl ProjectSelectionSample", 1)[1].split("fn selection_recorded_object(", 1)[0]
        self.assertIn("data.for_result(case.selected_id(), returned)", sample)
        value = sample.split("fn value(self)", 1)[1]
        for forbidden in ("path", "identity", "inode", "hash", "project_witness", "project_returned"):
            self.assertNotIn(forbidden, value)
        axes = observer.split("fn selection_recorded_object(", 1)[1].split("fn project_selection_failure_reason(", 1)[0]
        self.assertIn("identity[..2] == captured[..2]", axes)
        self.assertIn("identity[..] == captured[..5]", axes)
        self.assertIn('namespace.join("state").join(case.name())', axes)
        self.assertIn("selected.starts_with(namespace)", axes)
        for forbidden in ("std::fs", "canonicalize", "metadata(", "observe_panel", "Instant::now", "json!", "digest("):
            self.assertNotIn(forbidden, axes)
        latch = observer.split("fn latch_project_selection(", 1)[1].split("fn project_selection_data_checks()", 1)[0]
        self.assertIn("if latch_failure(first, failed, reason) && project_selection_failure_reason(reason) { *detail = Some(sample); }", latch)
        self.assertNotIn("compare_exchange", latch)
        snapshot = observer.split("struct FailureSnapshot", 1)[1].split("fn failure_context(", 1)[0]
        self.assertIn("project_selection: r.project_selection", snapshot)
        self.assertIn("self.project_selection = None", snapshot)
        self.assertIn('self.source != "record" || !project_selection_failure_reason(reason)', snapshot)
        self.assertIn("8192", snapshot)
        self.assertIn("8448", snapshot)
        checks = observer.split("fn project_selection_data_checks()", 1)[1].split("// Same selected-result", 1)[0]
        for required in ("installed_macos_selection_saved_data_checks()", "changed_links[5] = u64::MAX", "for index in 2..5",
                         "same_object == different", "for first_reason in FAILURE_REASONS", "detail != expected",
                         'latch_failure(&first, &failed, "observer-deadline")'):
            self.assertIn(required, checks)
        self.assertIn("if !project_selection_data_checks() { return false; }", observer.split("fn observer_data_checks()", 1)[1])

    def test_project_path_mismatch_categories_are_bounded_failure_only_data(self):
        observer = (PATH.parents[1] / "src-tauri" / "src" / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        helper = observer.split("fn project_path_mismatch_reason(", 1)[1].split("fn selected_project_failure(", 1)[0]
        labels = M.re.findall(r'"(project-result-path(?:-[a-z-]+)?)"', helper)
        self.assertEqual(set(labels), {"project-result-path", "project-result-path-app-child", "project-result-path-descendant",
                                      "project-result-path-ancestor", "project-result-path-sibling", "project-result-path-tmp-spelling",
                                      "project-result-path-data-spelling"})
        self.assertEqual(len(labels), 7)
        ordered = ('if !bounded(actual_text) || !bounded(expected_text) || actual == expected',
                   'actual.strip_prefix(expected)', 'relative == Path::new("app")',
                   'expected.starts_with(actual)', 'actual.parent() == expected.parent()',
                   'expected_text.strip_prefix("/private/tmp/")', 'actual_text.strip_prefix("/System/Volumes/Data")')
        self.assertEqual(sorted(helper.index(value) for value in ordered), [helper.index(value) for value in ordered])
        for predicate in ("text.len() <= crate::asset_source::PATH_LIMIT", "text.starts_with('/')", "!text.as_bytes().contains(&0)",
                          'text[1..].split(\'/\')', '!part.is_empty() && part != "." && part != ".." && part.len() <= 255',
                          'actual_text.strip_prefix("/tmp/") == Some(suffix)', '== Some(expected_text)'):
            self.assertIn(predicate, helper)
        for forbidden in ("std::fs", "canonicalize", "observe_panel", "Instant::now", "self.", "format!", "json!",
                          "to_owned", "to_string", "collect", "latch_failure", "return None", "return actual_text", "return expected_text"):
            self.assertNotIn(forbidden, helper)
        checks = observer.split("fn project_path_mismatch_data_checks()", 1)[1].split("// Synchronous expressions", 1)[0]
        for category in set(labels):
            self.assertIn(f'"{category}"', checks)
        self.assertIn("for step in [Step::OpenProject, Step::ProjectSettled]", checks)
        self.assertIn('selected_project_failure(step, true, &project, root, "first-save") != Some("project-result-order")', checks)
        data = observer.split("fn project_snapshot_failure_data_checks()", 1)[1].split("fn project_path_mismatch_data_checks()", 1)[0]
        self.assertIn("if !project_path_mismatch_data_checks() { return false; }", data)

    def test_project_snapshot_first_failure_classifiers_preserve_existing_gates(self):
        observer = (PATH.parents[1] / "src-tauri" / "src" / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        errors = observer.split("fn snapshot_error_reason(", 1)[1].split("fn snapshot_value_failure(", 1)[0]
        self.assertIn('_ => "snapshot-error-other"', errors)
        labels = M.re.findall(r'=> "([a-z-]+)"', errors)
        self.assertEqual(len(labels), 13)
        self.assertTrue(set(labels) <= M.FAILURE_REASONS)
        for forbidden in ("format!", ".to_owned(", ".to_string(", ".message", "return code"):
            self.assertNotIn(forbidden, errors)
        values = observer.split("fn snapshot_value_failure(", 1)[1].split("fn project_snapshot_failure_data_checks(", 1)[0]
        ordered = ("snapshot-value-root", "snapshot-value-scope", "snapshot-config-path", "snapshot-value-assurance",
                   "snapshot-value-issues", "snapshot-hints-android", "snapshot-hints-version", "snapshot-discovery-state",
                   "snapshot-config-state", "snapshot-config-data", "snapshot-config-content", "snapshot-config-issues")
        self.assertEqual(sorted(values.index(label) for label in ordered), [values.index(label) for label in ordered])
        for predicate in ('v["root"].as_str() != expected_path.to_str()', 'config["path"] != "release/mobile-release.json"',
                          'hints["android"]["applicationId"] == APP_ID && hints["android"]["module"] == ":app"',
                          'hints["android"]["buildFile"] == "app/build.gradle.kts"',
                          'hints["versionSource"] == "version.properties" && hints["versionNameKey"] == "VERSION_NAME"',
                          'hints["versionBuildKey"] == "BUILD_NUMBER"',
                          'v["discovery"]["partial"] == false && v["discovery"]["state"] == "unverified"',
                          'config["state"] != "format-valid"', 'config["data"] != *base',
                          'config["content"] != json!({"bytes":bytes.len(), "sha256":digest(bytes)})',
                          'config["state"] != "missing"', '!config["data"].is_null()', '!config["content"].is_null()',
                          'issues.len() == 1 && issues[0]["code"] == "config.missing"'):
            self.assertIn(predicate, values)
        self.assertIn("snapshot_value_failure_bytes(v, expected_path, saved, base, CONFIG)", values)
        for forbidden in ("Instant::now", "self.", "std::fs", "observe_panel", "latch_failure", "format!"):
            self.assertNotIn(forbidden, values)
        snapshot = observer.split("pub(super) fn snapshot(&self", 1)[1].split("pub(super) fn suggest_request(", 1)[0]
        guards = ("snapshot_value_failure(value, &self.project_path, saved, &self.base)",
                  "if let Some(reason) = failure", "if !r.snapshot_pending", "if !r.project.as_ref()",
                  "if r.snapshots + 1 != r.snapshot_requests", "r.snapshot_pending = false; r.snapshots += 1;")
        self.assertEqual(sorted(snapshot.index(guard) for guard in guards), [snapshot.index(guard) for guard in guards])
        self.assertIn("Err(error) => Some(snapshot_error_reason(&error.code))", snapshot)
        self.assertNotIn("error.message", snapshot)
        tick = observer.split("pub(super) fn tick(", 1)[1].split("Step::PickerPending =>", 1)[0]
        witness = tick.split("Step::ProjectSettled =>", 1)[1]
        self.assertIn("let Some(returned) = &r.project else { return; };", witness)
        self.assertIn("let Some((project,witness,response)) = state.document.installed_macos_project(self.case.selected_id()) else { return; };", witness)
        self.assertEqual(witness.count("installed_macos_project("), 1)
        for label in ("identity", "response", "selection", "callback"):
            self.assertLess(witness.index(f'self.fail_with("project-witness-{label}")'), witness.index("r.project_witness = Some(witness)"))
        main = observer.split("pub(crate) fn main()", 1)[1]
        self.assertIn('if report.is_none() { q.fail_with("observer-report-unavailable"); q.report_failure(); }', main)
        self.assertLess(main.index("observe(&q)"), main.index('q.fail_with("observer-report-unavailable")'))
        self.assertLess(main.index('q.fail_with("observer-report-unavailable")'), main.index("q.diagnostic.finish(q.end)"))
        data = observer.split("fn observer_data_checks()", 1)[1].split("fn observe(q:", 1)[0]
        self.assertIn("if !project_snapshot_failure_data_checks() { return false; }", data)
        self.assertIn('latch_failure(&first, &failed, "observer-deadline")', data)

    def test_loss_requires_actual_route_but_not_both_events(self):
        for case in ("picker-loss", "save-loss"):
            for denied, started in ((True, False), (False, True), (True, True)):
                value = M.expected_result(BINDING, case)
                value["reload"].update(navigationDenied=denied, secondStarted=started)
                self.assertEqual(M.parse_result(captured(value), b"", BINDING, case), value)
            for denied, started in ((False, False), (1, False), (False, "true")):
                value = M.expected_result(BINDING, case)
                value["reload"].update(navigationDenied=denied, secondStarted=started)
                with self.assertRaises(M.Refused):
                    M.parse_result(captured(value), b"", BINDING, case)

    def test_independent_fixture_identity_roster_and_stale_semantics(self):
        for case in M.CASES:
            with self.subTest(case=case):
                original = initial_snapshot(case)
                final = final_snapshot(case, original)
                M.validate_snapshot(original, final, case, True, UID, GID)
                variants = []
                item = dict(final); item["unexpected-transaction"] = final["keep.txt"]; variants.append(item)
                item = dict(final); item["keep.txt"] = replace(item["keep.txt"], sha256="0" * 64); variants.append(item)
                item = dict(final); identity = list(item["app/build.gradle.kts"].identity); identity[1] += 1000
                item["app/build.gradle.kts"] = replace(item["app/build.gradle.kts"], identity=tuple(identity)); variants.append(item)
                item = dict(final); identity = list(item["keep.txt"].identity); identity[5] = 2
                item["keep.txt"] = replace(item["keep.txt"], identity=tuple(identity)); variants.append(item)
                item = dict(final); identity = list(item["keep.txt"].identity); identity[2] = stat.S_IFLNK | 0o600
                item["keep.txt"] = replace(item["keep.txt"], identity=tuple(identity)); variants.append(item)
                for item in variants:
                    with self.assertRaises(M.Refused):
                        M.validate_snapshot(original, item, case, True, UID, GID)
        original = initial_snapshot("noop-stale")
        final = final_snapshot("noop-stale", original)
        self.assertEqual(final[".gitignore"].identity[6], 365)
        identity = list(final[".gitignore"].identity); identity[1] += 1000
        final[".gitignore"] = replace(final[".gitignore"], identity=tuple(identity))
        with self.assertRaises(M.Refused):
            M.validate_snapshot(original, final, "noop-stale", True, UID, GID)
        original = initial_snapshot("first-save")
        final = final_snapshot("first-save", original)
        self.assertEqual(final["release"].identity[2], stat.S_IFDIR | 0o755)
        identity = list(final[".gitignore"].identity); identity[1] = original[".gitignore"].identity[1]
        final[".gitignore"] = replace(final[".gitignore"], identity=tuple(identity))
        with self.assertRaises(M.Refused):
            M.validate_snapshot(original, final, "first-save", True, UID, GID)

    def test_fixed_invocation_and_environment_never_merge_ambient_inputs(self):
        fixtures, calls, emitted = InertFixtures(), [], []
        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return CompletedProcess(args=argv, returncode=0, stdout=captured(M.expected_result(BINDING, argv[1])), stderr=b"")
        with patch.dict(M.os.environ, {"GITHUB_TOKEN": "not-a-token", "HTTPS_PROXY": "not-a-proxy", "HOME": "/not-used"}):
            M.run_cases(BINDING, fixtures, runner, UID, "runner", emitted.append)
        self.assertEqual(fixtures.before, list(M.CASES))
        self.assertEqual(fixtures.reads, list(M.CASES))
        self.assertEqual(len(emitted), 4)
        for (argv, options), case in zip(calls, M.CASES):
            self.assertEqual(argv, [M.EXECUTABLE, case])
            self.assertEqual({key: options[key] for key in ("timeout", "capture", "text", "output_limit")},
                             {"timeout": 60, "capture": True, "text": False, "output_limit": 2 * 1024 * 1024})
            self.assertEqual(options["cwd"], BINDING.root() / "state" / case)
            environment = options["environ"]
            self.assertEqual(set(environment), {"HOME", "TMPDIR", "PATH", "LANG", "LC_ALL", "TZ", "USER", "LOGNAME", "__CF_USER_TEXT_ENCODING"})
            self.assertEqual(environment["__CF_USER_TEXT_ENCODING"], "0x1F5:0:0")
            self.assertEqual(environment["HOME"], str(options["cwd"] / "home"))
        self.assertFalse(fixtures.inflight)

    def test_owner_exception_preserved_and_excludes_readback_close_later_cases(self):
        fixtures, calls = InertFixtures(), []
        original = KeyboardInterrupt()
        def runner(*args, **kwargs):
            calls.append(args)
            raise original
        with self.assertRaises(KeyboardInterrupt) as caught:
            M.run_cases(BINDING, fixtures, runner, UID, "runner", self.fail)
        self.assertIs(caught.exception, original)
        self.assertTrue(fixtures.inflight)
        self.assertFalse(fixtures.last_returned)
        self.assertEqual((len(calls), fixtures.before, fixtures.reads), (1, ["first-save"], []))
        # No real descriptor is inserted or closed in this inert refusal test.
        originals = M.Fixtures(BINDING, UID, GID)
        originals.inflight = True
        with patch.object(M.os, "close", side_effect=AssertionError("unexpected descriptor close")), self.assertRaises(M.Refused):
            originals.close()

    def test_bad_return_or_receipt_stops_before_readback_and_later_launch(self):
        for returncode, body in ((1, b""), (True, b""), (0, b"no-marker\n")):
            fixtures, calls = InertFixtures(), []
            def runner(argv, **kwargs):
                calls.append(argv)
                return CompletedProcess(args=argv, returncode=returncode, stdout=body, stderr=b"")
            with self.assertRaises(M.Refused):
                M.run_cases(BINDING, fixtures, runner, UID, "runner", self.fail)
            self.assertEqual(fixtures.inflight, type(returncode) is not int)
            self.assertEqual(fixtures.last_returned, type(returncode) is int)
            self.assertEqual((len(calls), fixtures.reads), (1, []))

    def test_foreign_or_malformed_result_never_becomes_original_finality(self):
        argv = [M.EXECUTABLE, "first-save"]
        good = captured(M.expected_result(BINDING, "first-save"))
        results = (SimpleNamespace(args=argv, returncode=0, stdout=good, stderr=b""),
                   CompletedProcess(args=tuple(argv), returncode=0, stdout=good, stderr=b""),
                   CompletedProcess(args=argv, returncode=0, stdout=b"x" * (M.OUTPUT_LIMIT + 1), stderr=b""))
        for result in results:
            fixtures, calls = InertFixtures(), []
            def runner(*args, **kwargs):
                calls.append(args)
                return result
            with self.assertRaises(M.Refused):
                M.run_cases(BINDING, fixtures, runner, UID, "runner", self.fail)
            self.assertTrue(fixtures.inflight)
            self.assertFalse(fixtures.last_returned)
            self.assertEqual((len(calls), fixtures.before, fixtures.reads), (1, ["first-save"], []))

    def test_roster_is_bounded_and_iterator_close_preserves_primary_failure(self):
        class Entries:
            def __init__(self, names=(), failure=None, close_failure=None):
                self.names, self.failure, self.close_failure = iter(names), failure, close_failure
                self.pulls = self.closes = 0
            def __iter__(self):
                return self
            def __next__(self):
                self.pulls += 1
                if self.failure is not None:
                    raise self.failure
                return SimpleNamespace(name=next(self.names))
            def close(self):
                self.closes += 1
                if self.close_failure is not None:
                    raise self.close_failure
        token = object()  # Never an actual directory descriptor.
        fixtures = M.Fixtures(BINDING, UID, GID)
        fixtures.fds.add(token)
        info = SimpleNamespace(st_dev=7, st_ino=100, st_mode=stat.S_IFDIR | 0o700, st_uid=UID, st_gid=GID,
                               st_nlink=2, st_size=4096, st_mtime_ns=100, st_ctime_ns=100)
        def invoke(entries, expected, mismatch=False):
            reader = object()  # Distinct fresh description; never the retained token.
            def open_reader(name, parent, *, directory):
                self.assertEqual(name, ".")
                self.assertIs(parent, token)
                self.assertTrue(directory)
                fixtures.fds.add(reader)
                return reader
            def read_stat(fd):
                self.assertTrue(fd is token or fd is reader)
                return SimpleNamespace(**{**vars(info), "st_ino": 101}) if mismatch and fd is reader else info
            with patch.object(fixtures, "_open", side_effect=open_reader) as opened, \
                    patch.object(M.os, "fstat", side_effect=read_stat), \
                    patch.object(M.os, "scandir", return_value=entries) as scan, \
                    patch.object(M.os, "close") as close:
                try:
                    return fixtures._roster(token, expected, "roster")
                finally:
                    opened.assert_called_once_with(".", token, directory=True)
                    close.assert_called_once_with(reader)
                    self.assertEqual(fixtures.fds, {token})
                    if mismatch:
                        scan.assert_not_called()
                    else:
                        scan.assert_called_once_with(reader)
        entries = Entries(("tmp", "home"))
        self.assertEqual(invoke(entries, ("home", "tmp")), ("home", "tmp"))
        self.assertEqual((entries.pulls, entries.closes), (3, 1))
        entries = Entries(("home", "extra", "must-not-consume"))
        with self.assertRaises(M.Refused):
            invoke(entries, ("home",))
        self.assertEqual((entries.pulls, entries.closes), (2, 1))
        entries = Entries(("home",))
        with self.assertRaises(M.Refused):
            invoke(entries, ("home",), mismatch=True)
        self.assertEqual((entries.pulls, entries.closes), (0, 0))
        original, closing = RuntimeError("iterator failed"), OSError("iterator close failed")
        entries = Entries(failure=original, close_failure=closing)
        with self.assertRaises(RuntimeError) as caught:
            invoke(entries, ())
        self.assertIs(caught.exception, original)
        self.assertEqual((entries.pulls, entries.closes, fixtures.close_errors), (1, 1, 1))
        self.assertIs(fixtures.first_close_error, closing)

    def test_original_file_error_survives_one_spent_cleanup_failure(self):
        fixtures = M.Fixtures(BINDING, UID, GID)
        token = object()  # Not an actual descriptor, even if a mock is broken.
        fixtures.fds.add(token)
        original, closing = RuntimeError("read failed"), OSError("close failed")
        with patch.object(M.os, "close", side_effect=closing) as close:
            with self.assertRaises(RuntimeError) as caught:
                with fixtures._temporary(token):
                    raise original
            self.assertIs(caught.exception, original)
            self.assertEqual(fixtures.close_errors, 1)
            self.assertNotIn(token, fixtures.fds)
            with self.assertRaises(OSError) as caught:
                fixtures.close()
            self.assertIs(caught.exception, closing)
            self.assertEqual(close.call_count, 1)

    def test_public_lifetime_flags_missing_or_nonbool_are_unknown_without_transcripts(self):
        class ProcessError(Exception):
            pass
        class ProcessInterrupted(KeyboardInterrupt):
            pass
        owner = SimpleNamespace(ProcessError=ProcessError, ProcessInterrupted=ProcessInterrupted)
        error = ProcessInterrupted("PRIVATE MESSAGE MUST NOT BE EXPORTED")
        error.dispatched, error.contained = True, 1
        fixtures = InertFixtures(); fixtures.inflight = True
        report = M.diagnostic(error, owner, fixtures)
        self.assertEqual(report["typedLifetimeFacts"], [{"type": "interrupted", "dispatched": True, "contained": None, "cleanupComplete": None}])
        self.assertEqual(report["invocationFinality"], "unknown")
        self.assertEqual(report["innerOutput"], "unavailable")
        output = io.StringIO(); M.emit_record(report, output)
        self.assertNotIn("PRIVATE MESSAGE", output.getvalue())


@contextmanager
def inert_ios_archive():
    """Private, disposable DATA only: no Mach-O, native tool or app invocation."""
    import plistlib
    with tempfile.TemporaryDirectory(prefix="mrk-ios-reader-data-") as directory:
        parent = Path(directory)
        archive = parent / "archive.xcarchive"
        files = {
            "Info.plist": plistlib.dumps({"ApplicationProperties": {"ApplicationPath": "Applications/MRKObserved.app"}}),
            "Products/Applications/MRKObserved.app/Info.plist": plistlib.dumps({"CFBundleIdentifier": "org.example.mrk.observed",
                "CFBundleShortVersionString": "1.2.3", "CFBundleVersion": "7"}),
            "Products/Applications/MRKObserved.app/MRKObserved": b"inert-app-not-executable",
            "dSYMs/MRKObserved.app.dSYM/Contents/Resources/DWARF/MRKObserved": b"inert-symbol-data",
        }
        for name, body in files.items():
            path = archive / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(body)
            path.chmod(0o600)
        for path in archive.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)
        archive.chmod(0o700)
        fixture = M.Fixtures(BINDING, M.os.getuid(), M.os.getgid(), "ios-unsigned-archive")
        fd = fixture._open(parent, directory=True)
        result = {"entries": len(list(archive.rglob("*"))), "bytes": sum(map(len, files.values()))}
        try:
            yield SimpleNamespace(parent=parent, archive=archive, fixtures=fixture, fd=fd, result=result, files=files)
        finally:
            fixture.close()


class IOSAquaDataTests(unittest.TestCase):
    def test_normal_macos_selection_is_original_bound_without_observer_grants(self):
        source = PATH.parents[1] / "src-tauri/src"
        runtime = (source / "runtime.rs").read_text()
        supervisor = (source / "supervisor.rs").read_text()
        document = (source / "asset_session.rs").read_text()
        owner = (source / "saved_command_owner.rs").read_text()
        control = (source / "installed_shell_observation_macos_ios.rs").read_text()
        observer = (source / "installed_shell_observation_macos.rs").read_text()
        producer = (source / "installed_shell_observation_macos_session.rs").read_text()

        self.assertIn("INSTALLED_IOS_SESSION_INPUTS_QUALIFIED: bool = true;", runtime)
        self.assertIn("const NATIVE_QUALIFIED: bool = false;", document)
        passive = runtime.split("fn macos_installed_passive_method(", 1)[1].split("fn linux_installed_passive_method(", 1)[0]
        self.assertNotIn("credentials.assess", passive)
        for name in ("fn admit_once(", "pub(crate) fn admit_installed_session_once("):
            if name not in runtime:  # Both disappear when normal Linux A is composed.
                continue
            cfg = runtime.split(name, 1)[0].rsplit("#[cfg(", 1)[1]
            self.assertIn('target_os = "linux", target_arch = "x86_64", target_env = "gnu"', cfg)
            self.assertNotIn('target_os = "macos"', cfg)
        shared = runtime.split("pub(crate) fn assert_installed_session_selection_contract()", 1)[1].split("// The fixed selector", 1)[0]
        for fact in ("let normal = session_inputs_qualified();", "assert_eq!(first.matches(Some(&original)), normal);",
                     "assert_eq!(first.clone().matches(Some(&original)), normal);", "other.claim_supervisor()",
                     "second_supervisor.claim_supervisor()", "drop(original); first.bind_document(&replacement);"):
            self.assertIn(fact, shared)
        shared_cfg = runtime.split("pub(crate) fn assert_installed_session_selection_contract()", 1)[0].rsplit("#[cfg(", 1)[1]
        self.assertIn('all(target_os = "macos", target_arch = "aarch64")', shared_cfg)
        early = observer.split("fn observer_data_checks()", 1)[1].split("fn observe(q:", 1)[0]
        self.assertIn("crate::runtime::assert_installed_session_selection_contract();", early)
        platform_gate = document.split("fn ordinary_asset_platform_gate()", 1)[1].split("fn session_kind_gate(", 1)[0]
        project_contract = document.split("pub(crate) fn assert_project_selection_gate_contract()", 1)[1].split("\n}", 1)[0]
        supported = 'cfg!(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),\n        all(target_os = "macos", target_arch = "aarch64"),\n        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))'
        self.assertIn("if !" + supported, platform_gate)
        self.assertIn("let platform = if " + supported, project_contract)
        self.assertIn("assert_eq!(ordinary_asset_platform_gate().err().map(|error| error.reason), platform);", project_contract)
        self.assertIn("crate::asset_session::assert_project_selection_gate_contract();", early)

        normal = owner.split("fn ios_unsigned_installed_selected(", 1)[1].split("fn qualified(", 1)[0]
        for term in ('self.domain == SavedCommandDomain::IOSArchive', 'feature = "desktop-shell"',
                     'feature = "custom-protocol"', 'not(feature = "development-runtime")',
                     'not(feature = "ubuntu-runtime-publisher")', 'not(feature = "windows-runtime-publisher")',
                     'not(feature = "macos-installed-installer")', 'target_os = "macos", target_arch = "aarch64"',
                     '&& self.runtime.ios_archive_installed_profile_available()'):
            self.assertIn(term, normal)
        for forbidden in ("ios_observation", "IOS_ARCHIVE_NATIVE_QUALIFIED"):
            self.assertNotIn(forbidden, normal)
        for name in ("IOS_SIGNED_NATIVE_QUALIFIED", "IOS_RECOVERY_NATIVE_QUALIFIED"):
            self.assertIn(f"const {name}: bool = false;", owner)
        qualified = owner.split("fn qualified(&self)", 1)[1].split("fn lock(&self)", 1)[0]
        self.assertIn("if let Some(observation) = book.as_ref()", qualified)
        self.assertIn("return self.runtime.ios_archive_installed_profile_available()", qualified)
        self.assertIn("[ios_wire::Operation::IOSSignedExport, ios_wire::Operation::IOSLocalRecovery]", qualified)
        self.assertIn("|| self.ios_unsigned_installed_selected()\n                            && observation.control.permits_mode(ios_wire::Operation::IOSUnsignedArchive)", qualified)
        self.assertIn("SavedCommandDomain::IOSArchive => self.ios_unsigned_installed_selected()", qualified)
        mode = owner.split("fn ios_mode_qualified(", 1)[1].split("fn start_clocks(", 1)[0]
        self.assertIn("(Some(owner), Some(bound)) => std::ptr::eq(bound.as_ref(), owner)", mode)
        self.assertIn("return same_original && observation.control.permits_mode(selected.operation)", mode)
        self.assertIn("selected.operation != ios_wire::Operation::IOSUnsignedArchive || self.ios_unsigned_installed_selected()", mode)

        sample = document.split("pub(crate) fn observe_installed_macos_normal_selection(", 1)[1].split("pub(crate) fn register_installed_macos_session(", 1)[0]
        self.assertIn("if observation.is_some()", sample)
        self.assertIn("supervisor.assert_installed_session_available(&self.inner.session_identity)?", sample)
        self.assertIn("self.inner.bridge.ios_archive.observe_installed_unsigned_selection()", sample)
        owner_sample = owner.split("pub(crate) fn observe_installed_unsigned_selection(", 1)[1].split("pub(crate) fn admit_installed_ios_observation(", 1)[0]
        for gate in ("r.revision != 0", "r.active.is_some()", "r.prepared.is_some()", "r.last.is_some()",
                     "r.document_lost", "r.exhausted", "self.inner.poisoned.load", "!self.inner.ios_unsigned_installed_selected()", "if slot.is_some()"):
            self.assertIn(gate, owner_sample)
        wrapper = supervisor.split("pub(crate) fn assert_installed_session_available(", 1)[1].split("pub fn disabled(", 1)[0]
        self.assertIn("!owners.is_empty() || self.inner.next.load(Ordering::SeqCst) != 1 || self.stopping() || self.disabled()", wrapper)
        self.assertIn("self.inner.runtime.installed_session_available(identity)", wrapper)
        self.assertNotIn("admit_installed_session_once", wrapper)
        attach = control.split("pub(super) fn attach(", 1)[1].split("pub(super) fn normal_session_registered(", 1)[0]
        self.assertLess(attach.index("Weak::ptr_eq(&bound_owner, &direct)"), attach.index("document.observe_installed_macos_normal_selection()?"))
        self.assertLess(attach.index("document.observe_installed_macos_normal_selection()?"), attach.index("self.normal_selection_observed.set(())"))
        self.assertLess(attach.index("self.normal_selection_observed.set(())"), attach.index("document.admit_installed_ios("))
        self.assertLess(attach.index("document.admit_installed_ios("), attach.index("document.register_installed_macos_session("))
        returned = "document.register_installed_macos_session(SessionRegistration { control: self.clone(), document: doc })?;"
        self.assertLess(attach.index(returned), attach.index("self.normal_session_registration_returned.set(())"))
        self.assertEqual(attach.count("self.normal_session_registration_returned.set(())"), 1)
        history = control.split("pub(super) fn normal_session_registered(", 1)[1].split("pub(crate) fn permits(", 1)[0]
        for fact in ("self.normal_selection_observed.get().is_some()", "self.session_registered.load(Ordering::SeqCst)",
                     "self.normal_session_registration_returned.get().is_some()"):
            self.assertIn(fact, history)
        for forbidden in ("permits()", "Weak::upgrade", "admitted.store", "Arc::new"):
            self.assertNotIn(forbidden, history)
        live = control.split("pub(crate) fn permits(", 1)[1].split("pub(crate) fn claim(", 1)[0]
        for fact in ("self.document.get().and_then(Weak::upgrade).is_some()", "self.owner.get().and_then(Weak::upgrade).is_some()",
                     "self.original.get().and_then(Weak::upgrade)", "!self.failed.load(Ordering::SeqCst)"):
            self.assertIn(fact, live)
        self.assertNotIn("normal_session_registration_returned", live)
        for term in ("Arc::ptr_eq(&bound, original)", "session_registered.compare_exchange(false, true",
                     "registration.claim_original(&wrong)", "registration.claim_original(&document)",
                     "let dead = Arc::downgrade(&document); drop(document); drop(owner);",
                     "|| control.permits() || !control.normal_session_registered()"):
            self.assertIn(term, control)
        self.assertNotIn("SessionAdmission", control)

        methods = M.re.search(r'const METHODS: \[&str; 10\] = \[(.*?)\];', observer, M.re.S)
        self.assertIsNotNone(methods)
        names = M.re.findall(r'"([a-z.]+)"', methods.group(1))
        self.assertEqual(len(names), 10)
        self.assertEqual(len(set(names)), 10)
        self.assertEqual(names.count("credentials.assess"), 1)
        self.assertIn("fn methods(self) -> usize { METHODS.len() }", observer)
        self.assertIn('METHODS.iter().all(|name| methods.iter().filter(available).filter(|m| m["method"].as_str() == Some(*name)).count() == 1)', observer)
        finish = observer.split("fn finish(&self) -> Option<Value>", 1)[1].split("\n}\n\nfn phase(", 1)[0]
        self.assertIn("let normal_registered = self.ios.as_ref().is_some_and(|control| control.normal_session_registered());", finish)
        self.assertEqual(finish.count(".normal_session_registered()"), 1)
        self.assertEqual(finish.count(".report(normal_registered)"), 2)
        self.assertIn("r.session_record.as_ref().is_some_and(|record| record.report(normal_registered).is_some())", finish)
        self.assertIn('report["signingInputs"] = r.session_record.as_ref()?.report(normal_registered)?;', finish)
        self.assertNotIn("record.report().is_some()", finish)
        self.assertIn('"schemaVersion":2,"oneUseOriginalDocumentRegistration":normal_registered', producer)
        self.assertIn('"selection":"ordinary-installed-macos-session"', producer)
        self.assertIn("if !normal_registered ||", producer)
        self.assertIn("signed.report(false).is_some()", producer)
        for case in M.ALL_CASES:
            value = M.expected_result(BINDING, case)
            self.assertEqual(value["methods"], "ten-passive-with-session-assessment")
        for case in ("first-save", "ios-unsigned-archive"):
            old = M.expected_result(BINDING, case); old["methods"] = "nine-passive"
            with self.assertRaises(M.Refused):
                M.parse_result(captured(old), b"", BINDING, case)

    def test_literal_fixture_matches_native_and_has_no_packages_or_scripts(self):
        import plistlib
        import xml.etree.ElementTree as ET
        native = (PATH.parents[1] / "src-tauri/src/installed_shell_observation_macos_ios.rs").read_text()
        expected = {
            "CONFIG": (901, "8d0e73dbbe82672e52a61fd39e8cb363fdaa35052a3267f48bf8f4c299b868cd"),
            "CONFIG_PREREQUISITE": (955, "2dac0a87eb465ae714f8281a2b37c05fbef2f63cbb427a17dc9b9603c87d0a34"),
            "CONFIG_CANCEL": (963, "6253b3df5076f134f9bc7cddfcd49ab98ead1aa5639172b253bee4e4ef923ccc"),
            "PROJECT": (3903, "4c79547c12407d02971ee1ad618b8ea416aef0db97b4b7b5a8aac2516c80e642"),
            "SCHEME": (679, "1d1e0b95797e6a1aae0b22cd96cbd771f2bce63324f49e0142406d3a0c457c83"),
            "MAIN": (736, "503a7dbe4e11346b822d0358828dd932d22d459bbe7301913c01eb70beb131ea"),
            "PLIST": (883, "e95c5837a07db7141f196061f9ed5c35f33b40f0f2ddc26abe5590323226ccdc"),
            "WORKSPACE": (104, "14e75b34da352a734fd05df443ef597fe5c547284cfb8ecfccacfd21cb5c7f93"),
        }
        for name, identity in expected.items():
            with self.subTest(name=name):
                body = getattr(M, "IOS_" + name)
                literal = M.re.search(r"const " + name + r': &\[u8\] = br#"(.*?)"#;', native, M.re.S)
                self.assertIsNotNone(literal)
                self.assertEqual(literal.group(1).encode("ascii"), body)
                self.assertEqual((len(body), M.digest(body)), identity)
        for case in M.IOS_CASES:
            config = json.loads(M.ios_config(case))
            self.assertIs(config["android"]["enabled"], False)
            self.assertEqual(config["ios"]["symbols"], {"policy": "required", "uploadCommand": ["/usr/bin/false"]})
            preparation = config["ios"].get("prepareCommand")
            self.assertEqual(preparation, ["/usr/bin/false"] if case == M.IOS_CASES[0] else ["/bin/sleep", "30"] if case == "ios-cancel" else None)
            files, directories = M.ios_fixture_data(case, False)
            self.assertEqual((len(files), len(directories)), (9, 8))
            self.assertTrue(all(len(body) <= 4096 for body in files.values()))
        self.assertNotIn(b"PBXShellScriptBuildPhase", M.IOS_PROJECT)
        self.assertNotIn(b"packageReferences", M.IOS_PROJECT)
        for line in (b"CODE_SIGNING_ALLOWED = NO", b"CODE_SIGNING_REQUIRED = NO", b'DEBUG_INFORMATION_FORMAT = "dwarf-with-dsym"'):
            self.assertIn(line, M.IOS_PROJECT)
        self.assertEqual(plistlib.loads(M.IOS_PLIST)["CFBundleShortVersionString"], "$(MARKETING_VERSION)")
        self.assertEqual(ET.fromstring(M.IOS_WORKSPACE).find("FileRef").get("location"), "self:")
        self.assertEqual(ET.fromstring(M.IOS_SCHEME).find("ArchiveAction").get("buildConfiguration"), "Release")

    def test_scope_fixed_roster_native_endpoint_and_no_extra_arguments(self):
        self.assertEqual(M.IOS_CASES, ("ios-toolchain-prerequisite", "ios-version-stale", "ios-unsigned-archive", "ios-cancel", "ios-finality"))
        self.assertIsNone(M.argument_scope([]))
        self.assertEqual(M.selected_cases(), M.CASES)
        self.assertEqual(M.argument_scope(["--scope", "ios-unsigned-archive"]), "ios-unsigned-archive")
        self.assertEqual(M.selected_cases("ios-unsigned-archive"), M.IOS_CASES)
        self.assertEqual(M.argument_scope(["--scope", "ios-current-synthetic"]), "ios-current-synthetic")
        self.assertEqual(M.selected_cases("ios-current-synthetic"), M.IOS_CURRENT_CASES)
        for argv in (["ios-unsigned-archive"], ["--scope", "ios-cancel"], ["--scope", "xcode-installed-classification"], ["--scope", "ios-unsigned-archive", "--timeout", "999"],
                     ["--scope", "ios-unsigned-archive", "--scope", "ios-unsigned-archive"], ("--scope", "ios-unsigned-archive"), None):
            with self.subTest(argv=argv), self.assertRaises(M.Refused):
                M.argument_scope(argv)
        for case in ("ios-finality-other", "IOS-FINALITY", "", None):
            with self.assertRaises(M.Refused):
                M.case_timeout(case)
        source = (PATH.parents[1] / "src-tauri/src/installed_shell_observation_macos.rs").read_text()
        self.assertIn("Duration::from_secs(if matches!(case, Case::Ios(c) if !c.input_only()) { 315 } else { 45 })", source)
        self.assertIn("!ios::data_checks()", source)
        child = (PATH.parents[1] / "src-tauri/src/installed_shell_observation_macos_ios.rs").read_text()
        data_check = child.split("pub(super) fn data_checks()", 1)[1].split("pub(super) fn snapshot_failure", 1)[0]
        for forbidden in ("Observation::new", "thread::spawn", "tokio::spawn", "std::process::Command", "file_fact("):
            self.assertNotIn(forbidden, data_check)
        self.assertIn("self.admitted.load(Ordering::SeqCst)", child)
        permits = child.split("pub(crate) fn permits(&self)", 1)[1].split("pub(crate) fn claim", 1)[0]
        self.assertNotIn(".record()", permits)
        self.assertNotIn(".lock()", permits)
        self.assertIn("self.claimed.compare_exchange(false, true", child)
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        self.assertIn("macos_aqua_qualification.py --scope project-fields", workflow)
        self.assertIn("macos_aqua_qualification.py --scope ios-current-synthetic", workflow)
        self.assertIn('"ios-current-synthetic": ("nine-current-ios-Aqua-engineering-cases", [' + ", ".join('"' + case + '"' for case in M.IOS_CURRENT_CASES) + "])", workflow)

    def test_five_reports_and_dynamic_original_ids_are_closed_and_bounded(self):
        for case in M.IOS_CASES:
            with self.subTest(case=case):
                report = M.expected_result(BINDING, case)
                self.assertEqual(M.parse_result(captured(report), b"", BINDING, case), report)
                self.assertLessEqual(len(captured(report)), M.JSON_LIMIT)
                value = report["iosArchive"]
                self.assertEqual(value["prerequisiteOnly"], case == M.IOS_CASES[0])
                if value["prerequisiteOnly"]:
                    self.assertEqual(value["original"]["terminal"]["outcome"], "failed")
                    self.assertIsNone(value["original"]["terminal"]["result"])
                value["context"].update(projectId="project-a", draftRevision=23, baselineGeneration=7)
                operation, generation = "7" * 32, "8" * 32
                snapshots = [value["original"]] + ([value["hold"]["original"]] if value["hold"] else [])
                for snapshot in snapshots:
                    snapshot["facts"].update(operationId=operation, ownerGeneration=generation)
                    terminal = snapshot["terminal"]
                    if terminal["disposition"]["relativeDirectory"] is not None:
                        terminal["disposition"]["relativeDirectory"] = f".mobile-release/desktop-ios-archive/{operation}"
                    if terminal["result"]:
                        terminal["result"].update(archive=f".mobile-release/desktop-ios-archive/{operation}/archive.xcarchive", entries=63, bytes=19317)
                self.assertEqual(M.parse_result(captured(report), b"", BINDING, case), report)

    def test_reports_refuse_missing_joins_unknown_resources_wrong_context_and_false_success(self):
        cases = ("ios-toolchain-prerequisite", "ios-version-stale", "ios-unsigned-archive", "ios-cancel", "ios-finality")
        for case in cases:
            good = M.expected_result(BINDING, case)
            value = good["iosArchive"]
            mutations = [("original", "facts", key) for key, actual in value["original"]["facts"].items() if type(actual) is bool]
            mutations += [("original", "terminal", "lifetime", key) for key in ("complete", "fatal", "contained", "inputClosed", "handlersRestored", "invocationClosed", "snapshotClosed", "filesClosed", "namespaceClosed")]
            for path in mutations:
                bad = deepcopy(good)
                cursor = bad["iosArchive"]
                for part in path[:-1]:
                    cursor = cursor[part]
                cursor[path[-1]] = not cursor[path[-1]]
                with self.subTest(case=case, field=path), self.assertRaises(M.Refused):
                    M.parse_result(captured(bad), b"", BINDING, case)
            for mutation in (
                lambda v: v["context"]["savedVersion"].update(build=8),
                lambda v: v["savedVersionObservation"]["savedConfig"].update(sha256="0" * 64),
                lambda v: v["original"]["facts"].update(workMs=300001),
                lambda v: v["original"]["facts"].update(hardMs=310001),
                lambda v: v["original"]["facts"].update(operationId="../foreign"),
                lambda v: v.update(statusCallsReturned=65),
                lambda v: v.update(statusCallsReturned=True),
                lambda v: v["original"]["terminal"].update(outcome="unknown", reason="cleanup-unknown"),
                lambda v: v["original"]["terminal"]["activity"]["commands"]["xcode-version"].update(outcome="unknown", exitCode=None),
                lambda v: v["original"]["terminal"]["disposition"].update(work="retained-work"),
            ):
                bad = deepcopy(good); mutation(bad["iosArchive"])
                with self.subTest(case=case), self.assertRaises(M.Refused):
                    M.parse_result(captured(bad), b"", BINDING, case)
        bad = M.expected_result(BINDING, "ios-toolchain-prerequisite")
        bad["iosArchive"]["original"]["terminal"]["activity"]["commands"]["prepare"]["exitCode"] = 0
        with self.assertRaises(M.Refused):
            M.parse_result(captured(bad), b"", BINDING, "ios-toolchain-prerequisite")

    def test_cancel_distinguishes_predispatch_and_unavailable_exit_from_unknown_custody(self):
        for outcome, code, counts in (("not-dispatched", None, (2, 3)), ("exited", 0, (3,)), ("unknown", None, (3,))):
            for count in counts:
                value = M._expected_ios_report("ios-cancel")
                command = {"outcome": outcome, "exitCode": code}
                value["original"]["terminal"]["activity"]["commands"]["prepare"] = command
                value["original"]["terminal"]["lifetime"]["commands"] = count
                value["cancel"]["prepareOutcome"] = command
                self.assertIs(M._ios_report(value, "ios-cancel"), value)
                for mutate in (lambda v: v["cancel"].update(activeCommandKillClaimed=True),
                               lambda v: v["original"]["facts"].update(resourceUnknown=True),
                               lambda v: v["original"]["terminal"]["lifetime"].update(complete=False),
                               lambda v: v["original"]["terminal"]["activity"]["commands"]["archive"].update(outcome="exited", exitCode=0)):
                    bad = deepcopy(value); mutate(bad)
                    with self.assertRaises(M.Refused):
                        M._ios_report(bad, "ios-cancel")
        for outcome, code, count in (("unknown", None, 2), ("exited", -15, 3), ("exited", True, 3), ("not-dispatched", 0, 2), ("not-configured", None, 3)):
            value = M._expected_ios_report("ios-cancel")
            command = {"outcome": outcome, "exitCode": code}
            value["original"]["terminal"]["activity"]["commands"]["prepare"] = command
            value["original"]["terminal"]["lifetime"]["commands"] = count
            value["cancel"]["prepareOutcome"] = command
            with self.assertRaises(M.Refused):
                M._ios_report(value, "ios-cancel")

    def test_finality_hold_requires_same_original_core_terminal_and_later_real_joins(self):
        good = M._expected_ios_report("ios-finality")
        for mutate in (
            lambda v: v.update(hold=None),
            lambda v: v["hold"].update(originalReleasedOnce=False),
            lambda v: v["hold"].update(publicSuccessHidden=False),
            lambda v: v["hold"].update(conflictingUiBlocked=False),
            lambda v: v["hold"].update(environmentDiagnosticsBlocked=False),
            lambda v: v["hold"]["original"]["facts"].update(ownerGeneration="c" * 32),
            lambda v: v["hold"]["original"]["facts"].update(observerJoined=True),
            lambda v: v["hold"]["original"]["facts"].update(watchdogJoined=True),
            lambda v: v["hold"]["original"]["facts"].update(retiredBeforeCutoff=True),
            lambda v: v["hold"]["original"]["facts"].update(activeRetained=False),
            lambda v: v["original"]["facts"].update(observerJoined=False),
        ):
            bad = deepcopy(good); mutate(bad)
            with self.assertRaises(M.Refused):
                M._ios_report(bad, "ios-finality")
        bad = deepcopy(good)
        # Break shared inert DATA references to model independently supplied JSON.
        bad["hold"]["original"]["terminal"] = deepcopy(bad["hold"]["original"]["terminal"])
        bad["hold"]["original"]["terminal"]["result"]["entries"] += 1
        with self.assertRaises(M.Refused):
            M._ios_report(bad, "ios-finality")

    def test_ios_invocations_use_only_fixed_argv_clean_environment_and_original_325_seconds(self):
        fixtures, calls, emitted = InertFixtures(), [], []
        fixtures.cases = M.IOS_CASES
        def runner(argv, **options):
            calls.append((argv, options))
            return CompletedProcess(argv, 0, captured(M.expected_result(BINDING, argv[1])), b"")
        with patch.dict(M.os.environ, {"GITHUB_TOKEN": "inert-not-secret", "DEVELOPER_DIR": "/not-used", "DYLD_INSERT_LIBRARIES": "/not-used"}):
            M.run_cases(BINDING, fixtures, runner, UID, "runner", emitted.append, "ios-unsigned-archive")
        self.assertEqual(fixtures.before, list(M.IOS_CASES))
        self.assertEqual(fixtures.reads, list(M.IOS_CASES))
        self.assertEqual(len(emitted), 5)
        for (argv, options), case in zip(calls, M.IOS_CASES):
            self.assertEqual(argv, [M.EXECUTABLE, case])
            self.assertEqual(options["timeout"], 325)
            self.assertEqual(options["cwd"], BINDING.root() / "state" / case)
            self.assertEqual(options["environ"], M.app_environment(options["cwd"], UID, "runner"))
            self.assertEqual(set(options), {"timeout", "cwd", "environ", "capture", "text", "output_limit"})
            self.assertEqual((options["capture"], options["text"], options["output_limit"]), (True, False, M.OUTPUT_LIMIT))
        fixtures.cases = M.CASES
        with self.assertRaisesRegex(M.Refused, "^fixture-scope$"):
            M.run_cases(BINDING, fixtures, self.fail, UID, "runner", self.fail, "ios-unsigned-archive")

    def test_failed_prerequisite_invalid_return_or_original_exception_stops_all_later_cases(self):
        first = M.IOS_CASES[0]
        bad_success = M.expected_result(BINDING, first)
        bad_success["iosArchive"]["original"]["facts"]["nativeIntegrity"] = False
        for result, inflight in ((CompletedProcess([M.EXECUTABLE, first], 1, b"", b""), False),
                                 (CompletedProcess([M.EXECUTABLE, first], 0, captured(bad_success), b""), False),
                                 (CompletedProcess([M.EXECUTABLE, first], True, b"", b""), True),
                                 (SimpleNamespace(returncode=0), True)):
            fixtures, calls = InertFixtures(), []
            fixtures.cases = M.IOS_CASES
            def runner(argv, **_):
                calls.append(argv)
                return result
            with self.assertRaises(M.Refused):
                M.run_cases(BINDING, fixtures, runner, UID, "runner", self.fail, "ios-unsigned-archive")
            self.assertEqual((fixtures.before, fixtures.reads, len(calls)), ([first], [], 1))
            self.assertIs(fixtures.inflight, inflight)
            self.assertIs(fixtures.last_returned, not inflight)
        fixtures = InertFixtures(); fixtures.cases = M.IOS_CASES
        failure = KeyboardInterrupt()
        def interrupt(*_, **__):
            raise failure
        with self.assertRaises(KeyboardInterrupt) as raised:
            M.run_cases(BINDING, fixtures, interrupt, UID, "runner", self.fail, "ios-unsigned-archive")
        self.assertIs(raised.exception, failure)
        self.assertEqual((fixtures.before, fixtures.reads), ([first], []))
        self.assertTrue(fixtures.inflight)
        real = M.Fixtures(BINDING, UID, GID, "ios-unsigned-archive"); real.inflight = True
        with patch.object(M.os, "close", side_effect=AssertionError("unknown invocation must not close")), self.assertRaises(M.Refused):
            real.close()

    def test_original_source_readback_requires_same_stale_version_object_and_exact_roster(self):
        for case in M.IOS_CASES:
            original = initial_snapshot(case)
            final = final_snapshot(case, original)
            self.assertEqual(M.validate_snapshot(original, final, case, True, UID, GID)["files"], 9)
            for name in ("version.properties", "ios/MRKObserved.xcodeproj/project.pbxproj", "release/mobile-release.json"):
                changed = dict(final)
                identity = list(changed[name].identity); identity[1] += 1000
                changed[name] = replace(changed[name], identity=tuple(identity))
                with self.assertRaises(M.Refused):
                    M.validate_snapshot(original, changed, case, True, UID, GID)
            changed = dict(final); changed["ios/foreign"] = final["keep.txt"]
            with self.assertRaises(M.Refused):
                M.validate_snapshot(original, changed, case, True, UID, GID)

    def test_archive_reader_accounts_regular_data_and_never_removes_output(self):
        with inert_ios_archive() as data:
            result = data.fixtures._archive_readback(data.fd, data.result)
            self.assertEqual((result["entries"], result["bytes"]), (data.result["entries"], data.result["bytes"]))
            self.assertTrue(result["savedIdentityMatched"] and result["retainedNotDeleted"])
            self.assertRegex(result["inventorySha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(data.fixtures.fds, {data.fd})
            self.assertEqual({name: (data.archive / name).read_bytes() for name in data.files}, data.files)

    def test_archive_reader_refuses_aliases_special_modes_missing_binary_and_changed_inventory(self):
        variants = ("symlink", "hardlink", "writable", "missing-binary", "directory-binary", "wrong-count", "wrong-bytes", "signed", "collision")
        for variant in variants:
            with self.subTest(variant=variant), inert_ios_archive() as data:
                app = data.archive / "Products/Applications/MRKObserved.app/MRKObserved"
                if variant == "symlink":
                    (data.archive / "alias").symlink_to("Info.plist")
                elif variant == "hardlink":
                    M.os.link(app, data.archive / "alias")
                elif variant == "writable":
                    app.chmod(0o666)
                elif variant == "missing-binary":
                    data.result["entries"] -= 1; data.result["bytes"] -= app.stat().st_size; app.unlink()
                elif variant == "directory-binary":
                    data.result["bytes"] -= app.stat().st_size; app.unlink(); app.mkdir(mode=0o700)
                elif variant == "wrong-count":
                    data.result["entries"] += 1
                elif variant == "wrong-bytes":
                    data.result["bytes"] += 1
                elif variant == "signed":
                    (app.parent / "_CodeSignature").mkdir(mode=0o700); data.result["entries"] += 1
                elif variant == "collision":
                    (data.archive / "info.plist").write_bytes(b""); (data.archive / "info.plist").chmod(0o600)
                with self.assertRaises(M.Refused):
                    data.fixtures._archive_readback(data.fd, data.result)
                self.assertEqual(data.fixtures.fds, {data.fd})

    def test_archive_reader_refuses_changed_identity_invalid_plist_budget_and_expired_readback(self):
        for variant in ("identity", "plist", "deadline", "bytes"):
            with self.subTest(variant=variant), inert_ios_archive() as data:
                if variant in ("identity", "plist"):
                    path = data.archive / "Products/Applications/MRKObserved.app/Info.plist"
                    old = path.read_bytes()
                    new = old.replace(b"org.example.mrk.observed", b"org.example.mrk.changed!") if variant == "identity" else b"not a plist"
                    path.write_bytes(new); data.result["bytes"] += len(new) - len(old)
                if variant == "deadline":
                    with patch("time.monotonic", side_effect=[0, 21]), self.assertRaisesRegex(M.Refused, "^ios-output-readback-deadline$"):
                        data.fixtures._archive_readback(data.fd, data.result)
                elif variant == "bytes":
                    # Project only this original's observed size; do not grow a
                    # sparse file beyond the DATA runner's per-file size limit.
                    path = data.archive / "oversized"
                    payload = b"bounded DATA"
                    path.write_bytes(payload)
                    path.chmod(0o600)
                    real_stat, real_fstat, real_read = M.os.stat, M.os.fstat, M.os.read
                    original = real_stat(path, follow_symlinks=False)
                    original_signature = M.signature(original)
                    original_key = (original.st_dev, original.st_ino)
                    observed = {"stat": 0, "fstat": 0, "read": 0}

                    def projected(info, kind):
                        if (info.st_dev, info.st_ino) != original_key:
                            return info
                        self.assertEqual(M.signature(info), original_signature)
                        observed[kind] += 1
                        fields = {name: getattr(info, name) for name in (
                            "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                            "st_size", "st_mtime_ns", "st_ctime_ns")}
                        fields["st_size"] = 64 * 1024 * 1024 + 1
                        return SimpleNamespace(**fields)

                    def named(*args, **kwargs):
                        return projected(real_stat(*args, **kwargs), "stat")

                    def held(fd):
                        return projected(real_fstat(fd), "fstat")

                    def bounded_read(fd, size):
                        info = real_fstat(fd)
                        if (info.st_dev, info.st_ino) == original_key:
                            observed["read"] += 1
                            self.fail("Oversized DATA must be rejected before reading")
                        return real_read(fd, size)

                    with patch.object(M.os, "stat", named), patch.object(M.os, "fstat", held), \
                            patch.object(M.os, "read", bounded_read), \
                            self.assertRaisesRegex(M.Refused, "^ios-output-byte-budget$"):
                        data.fixtures._archive_readback(data.fd, data.result)
                    self.assertEqual(observed, {"stat": 2, "fstat": 1, "read": 0})
                    self.assertEqual(path.read_bytes(), payload)
                    self.assertEqual(M.signature(real_stat(path, follow_symlinks=False)), original_signature)
                else:
                    with self.assertRaises(M.Refused):
                        data.fixtures._archive_readback(data.fd, data.result)
                self.assertEqual(data.fixtures.fds, {data.fd})


class CurrentIOSAquaDataTests(unittest.TestCase):
    def test_file_failure_samples_are_case_bound_without_widening_project_success(self):
        for case, index, panel_id in (("ios-signing-inputs", 0, 2), ("ios-signed-refusal", 1, 7),
                                      ("ios-signed-cancel", 1, 7)):
            with self.subTest(case=case):
                value = file_failure_context_data(case, index, panel_id)
                self.assertEqual(M.failure_context(b"", context_row(value), case), value)
                self.assertLessEqual(len(context_row(value).split(b"=", 1)[1]) - 1, M.FAILURE_CONTEXT_LIMIT)
                self.assertEqual(value["accessibility"]["step"], "OpenProject")
                for field, result_field, decoder in (
                    ("accessibilityBinding", "projectOpenBinding", M._accessibility_binding_context),
                    ("completionSelection", "projectCompletionSelection", M._completion_selection_context),
                ):
                    self.assertIsNone(decoder(value[field], case))  # Default admission is still Project-only.
                    result = M.expected_result(BINDING, case)
                    result["native"][result_field] = deepcopy(value[field])
                    with self.assertRaises(M.Refused):
                        M.parse_result(captured(result), b"", BINDING, case)
                bad = deepcopy(value); bad["accessibility"]["step"] = bad["nativeHandler"]["step"]
                expected = deepcopy(bad); expected["accessibility"] = None
                self.assertEqual(M.failure_context(b"", context_row(bad), case), expected)
                for field in ("accessibilityBinding", "completionSelection"):
                    bad = deepcopy(value); bad[field]["case"] = "first-save"
                    expected = deepcopy(bad); expected[field] = None
                    self.assertEqual(M.failure_context(b"", context_row(bad), case), expected)
        value = file_failure_context_data("ios-signing-inputs", 0, 2)
        for mutation in (lambda v: v["lastPanel"].update(id=7),
                         lambda v: v["lastPanel"].update(kind="project"),
                         lambda v: v["nativeHandler"].update(step="OpenProject")):
            bad = deepcopy(value); mutation(bad)
            self.assertIsNone(M.failure_context(b"", context_row(bad), "ios-signing-inputs"))

    def test_file_prearm_and_partial_identity_keep_only_saved_original_data(self):
        case = "ios-signing-inputs"
        value = file_failure_context_data(case, 0, 2)
        del value["completionSelection"]
        value.update(snapshotSource="prearm-open-progress", pending={"kind": "accessibility", "step": "OpenProject"})
        value["accessibility"].update(state="queued", bodyEntered=None, nativeEntered=None, bodyReturned=False,
            receiptJoined=False, workerJoined=False, rechecksSettled=None, barrierRetired=False,
            expired=True, timely=False, custodyKnown=None, attempted=None, pressReturned=None, triggered=None,
            initialOriginalProof=None, originalProof=None, promptChecks={"initial": None, "final": None},
            promptButton=None, site=None, error=None)
        self.assertEqual(M.failure_context(b"", context_row(value), case), value)
        for mutation in (lambda v: v["pending"].update(step="Session(Native(0))"),
                         lambda v: v.update(nativeHandler=None, lastPanel=None),
                         lambda v: v["nativeHandler"].update(returned=False),
                         lambda v: v.update(completionSelection=None)):
            bad = deepcopy(value); mutation(bad)
            self.assertIsNone(M.failure_context(b"", context_row(bad), case))

        # Identity-start failure is earlier: no native-handler, panel, Press or
        # completion receipt may be invented to make these diagnostics decode.
        for changes in (
            {"site": "initial-directory-set", "error": "objc-exception", "initialDirectorySetterReturned": False,
             "fileNameSetterEntered": False, "fileNameSetterReturned": False},
            {"site": "file-name-set", "error": "objc-exception", "fileNameSetterReturned": False},
            {"site": "file-name-get", "error": "changed"},
        ):
            partial = binding_context_data(); partial["snapshotSource"] = "record"
            partial["accessibilityBinding"] = file_failure_context_data(case, 0, 2)["accessibilityBinding"]
            sample = partial["accessibilityBinding"]
            sample["start"]["result"] = "io"; sample["binding"] = None
            sample["configuration"].update(changes)
            self.assertEqual(M.failure_context(b"", context_row(partial), case), partial)
            bad = deepcopy(partial); bad["accessibilityBinding"]["configuration"]["fileNameSetterEntered"] = 1
            expected = deepcopy(bad); expected["accessibilityBinding"] = None
            self.assertEqual(M.failure_context(b"", context_row(bad), case), expected)
        for field in ("fileNameSetterEntered", "fileNameSetterReturned"):
            bad = deepcopy(partial); del bad["accessibilityBinding"]["configuration"][field]
            expected = deepcopy(bad); expected["accessibilityBinding"] = None
            self.assertEqual(M.failure_context(b"", context_row(bad), case), expected)

    def test_file_cancel_and_session_quit_diagnostics_do_not_invent_open_receipts(self):
        case, step = "ios-signing-inputs", "Session(Native(6))"
        cancel = action_context_data(site="file-cancel")
        cancel.update(snapshotSource="record")
        cancel["nativeHandler"]["step"] = step
        cancel["lastPanel"].update(step=step, id=11, kind="file")
        cancel["nativeAction"].update(step=step, id=11, action="file-cancel")
        self.assertEqual(M.failure_context(b"", context_row(cancel), case), cancel)
        for field in ("accessibility", "accessibilityBinding", "completionSelection"):
            self.assertNotIn(field, cancel)
        # Native(6)/11 is Cancel, never an armed File Open original. Optional
        # forged File-11 receipts lose only their own diagnostic subframes.
        bad = deepcopy(cancel); foreign = file_failure_context_data(case, 6, 11)
        expected = deepcopy(cancel)
        for field in ("accessibility", "accessibilityBinding", "completionSelection"):
            bad[field] = foreign[field]; expected[field] = None
        self.assertEqual(M.failure_context(b"", context_row(bad), case), expected)
        bad = deepcopy(cancel); bad["nativeHandler"]["returned"] = False
        expected = deepcopy(bad); expected["nativeAction"] = None
        self.assertEqual(M.failure_context(b"", context_row(bad), case), expected)
        self.assertIsNone(M.failure_context(b"", context_row(cancel), "ios-signed-cancel"))
        for case in ("ios-signing-inputs", "ios-signed-refusal", "ios-signed-cancel"):
            value = action_context_data("Quit")
            value["lastPanel"]["id"] = value["nativeAction"]["id"] = 12
            self.assertEqual(M.failure_context(b"", context_row(value), case), value)
            bad = deepcopy(value); bad["nativeAction"]["id"] = 4
            expected = deepcopy(bad); expected["nativeAction"] = None
            self.assertEqual(M.failure_context(b"", context_row(bad), case), expected)
            bad = deepcopy(value); bad["lastPanel"]["id"] = 4
            self.assertIsNone(M.failure_context(b"", context_row(bad), case))

    def test_current_reports_are_closed_bounded_and_do_not_claim_successful_signing(self):
        for case in M.IOS_CURRENT_CASES[len(M.IOS_CASES):]:
            with self.subTest(case=case):
                value = M.expected_result(BINDING, case)
                self.assertEqual(M.parse_result(captured(value), b"", BINDING, case), value)
                self.assertLessEqual(len(captured(value)), M.JSON_LIMIT)
                self.assertIs(value["shippingBinaryQualified"], False)
                self.assertIs(value["distributionQualified"], False)
                if case == "ios-signing-inputs":
                    self.assertNotIn("iosArchive", value)
                    self.assertEqual(value["signingInputs"]["rows"][-1]["source"], "pending")
                    self.assertIsNone(value["signingInputs"]["rows"][-1]["exactNativeSelection"])
                elif case in M.IOS_SIGNED_CASES:
                    self.assertIn(value["iosArchive"]["original"]["terminal"]["outcome"], ("failed", "cancelled"))
                    self.assertIsNone(value["iosArchive"]["original"]["terminal"]["result"])
                else:
                    self.assertIsNone(value["iosArchive"]["savedVersionObservation"])
                    self.assertNotIn("result", value["iosArchive"]["original"]["terminal"])
                for name in ("sourceCommit", "case"):
                    bad = deepcopy(value); bad[name] = "unrelated"
                    with self.assertRaises(M.Refused):
                        M.parse_result(captured(bad), b"", BINDING, case)

    def test_file_originals_and_retained_signing_records_cannot_be_substituted(self):
        for case in M.IOS_SESSION_CASES:
            good = M.expected_result(BINDING, case)
            for mutation in (
                lambda v: v.update(schemaVersion=1),
                lambda v: v.update(oneUseOriginalDocumentRegistration=False),
                lambda v: v.update(oneUseOriginalDocumentRegistration=1),
                lambda v: v.update(selection="observation-grant"),
                lambda v: v.update(originalOperations=11),
                lambda v: v.update(memorySessionLocked=False),
                lambda v: v.update(allOriginalsSettled=False),
                lambda v: v.update(originalProjectAndQuitSettled=False),
                lambda v: v["rows"][0].update(operationId=3),
                lambda v: v["rows"][0].update(originalWorkerAndNativeSettled=False),
                lambda v: v["rows"][0].update(openInputJoined=False),
                lambda v: v["rows"][0]["assessment"].update(state="valid"),
                lambda v: v["rows"][0].update(recordId="/private/material.p12"),
            ):
                bad = deepcopy(good); mutation(bad["signingInputs"])
                with self.subTest(case=case), self.assertRaises(M.Refused):
                    M.parse_result(captured(bad), b"", BINDING, case)
            historical = deepcopy(good)
            receipt = historical["signingInputs"]
            receipt["schemaVersion"] = 1
            receipt["oneUseOriginalDocumentAdmission"] = receipt.pop("oneUseOriginalDocumentRegistration")
            del receipt["selection"]
            with self.subTest(case=case, historical=True), self.assertRaises(M.Refused):
                M.parse_result(captured(historical), b"", BINDING, case)
        for case in M.IOS_SIGNED_CASES:
            good = M.expected_result(BINDING, case)
            # The two actual opaque IDs may vary together, not independently
            # in retained input rows and the original signed-operation context.
            for index, token in enumerate(("1" * 32, "2" * 32)):
                good["signingInputs"]["rows"][index]["recordId"] = token
                good["iosArchive"]["context"]["signing"]["assignments"][index]["recordId"] = token
            self.assertEqual(M.parse_result(captured(good), b"", BINDING, case), good)
            for mutation in (
                lambda v: v["signingInputs"]["rows"][0].update(recordId="3" * 32),
                lambda v: v["iosArchive"]["context"]["signing"]["assignments"][0].update(recordId="4" * 32),
                lambda v: v["signingInputs"]["rows"][1].update(recordId="1" * 32),
                lambda v: v["signingInputs"]["rows"][0].update(assignedContextRevision=2),
                lambda v: v["signingInputs"]["rows"][0].update(keptRevision=True),
            ):
                bad = deepcopy(good); mutation(bad)
                with self.assertRaises(M.Refused):
                    M.parse_result(captured(bad), b"", BINDING, case)
        bad = M.expected_result(BINDING, "ios-signing-inputs")
        bad["signingInputs"]["rows"][-1]["source"] = "refused"
        with self.assertRaises(M.Refused):
            M.parse_result(captured(bad), b"", BINDING, "ios-signing-inputs")

    def test_signed_failure_hold_requires_original_material_and_all_final_joins(self):
        case = "ios-signed-refusal"
        good = M.expected_result(BINDING, case)
        for location in (("original", "facts"), ("original", "terminal", "lifetime"), ("hold", "original", "facts")):
            cursor = good["iosArchive"]
            for part in location:
                cursor = cursor[part]
            for field, actual in cursor.items():
                if type(actual) is not bool:
                    continue
                bad = deepcopy(good); target = bad["iosArchive"]
                for part in location:
                    target = target[part]
                target[field] = not actual
                with self.subTest(location=location, field=field), self.assertRaises(M.Refused):
                    M.parse_result(captured(bad), b"", BINDING, case)
        for mutate in (
            lambda v: v.update(hold=None),
            lambda v: v.update(cleanupMs=240001),
            lambda v: v["original"]["terminal"].update(outcome="complete", reason="none"),
            lambda v: v["original"]["terminal"]["activity"]["commands"]["export"].update(outcome="exited", exitCode=0),
            lambda v: v["original"]["terminal"]["activity"].update(findings=[]),
        ):
            bad = deepcopy(good); mutate(bad["iosArchive"])
            with self.assertRaises(M.Refused):
                M.parse_result(captured(bad), b"", BINDING, case)
        bad = deepcopy(good)
        bad["iosArchive"]["hold"]["original"]["terminal"] = deepcopy(bad["iosArchive"]["original"]["terminal"])
        bad["iosArchive"]["hold"]["original"]["terminal"]["lifetime"]["commands"] += 1
        with self.assertRaises(M.Refused):
            M.parse_result(captured(bad), b"", BINDING, case)

    def test_signed_cancel_binds_actual_boundary_without_inventing_renderer_timing(self):
        case = "ios-signed-cancel"
        good = M.expected_result(BINDING, case)
        value = good["iosArchive"]
        # The renderer may lag the original stream, but it cannot observe a
        # later stage than that same original's eventual terminal frame.
        value["cancel"]["stageAtClick"] = "inputs-bound"
        terminal = value["original"]["terminal"]
        terminal["activity"]["stage"] = "checking-xcode"
        terminal["activity"]["commands"]["xcode-version"] = {"outcome": "unknown", "exitCode": None}
        terminal["lifetime"].update(commands=1, commandDispatched=True)
        terminal["disposition"].update(work="removed", output="retained-incomplete",
            relativeDirectory=".mobile-release/desktop-ios-archive/" + value["original"]["facts"]["operationId"])
        self.assertEqual(M.parse_result(captured(good), b"", BINDING, case), good)
        for mutation in (
            lambda v: v["cancel"].update(stageAtClick="archiving"),
            lambda v: v["cancel"].update(stageAtClick="accepted"),
            lambda v: v["cancel"].update(stageAtClick="validating-signing"),
            lambda v: v["cancel"].update(trigger="renderer-state"),
            lambda v: v["cancel"]["boundary"].update(operationId="f" * 32),
            lambda v: v["cancel"]["boundary"].update(ownerGeneration="f" * 32),
            lambda v: v["cancel"]["boundary"].update(originalTypedFrame=False),
            lambda v: v["original"]["terminal"]["lifetime"].update(stopObserved="none"),
            lambda v: v["original"]["terminal"]["lifetime"].update(materialRetired=False),
            lambda v: v["original"]["terminal"]["lifetime"].update(profileCalls=1),
            lambda v: v["original"]["terminal"]["activity"].update(stage="inputs-bound"),
            lambda v: v["original"]["terminal"]["activity"].update(stage="validating-signing"),
            lambda v: v["original"]["terminal"]["activity"].update(findings=[{"check": "profile-material", "status": "INVALID"}]),
            lambda v: v["original"]["terminal"]["activity"]["commands"]["ios-sdk"].update(outcome="unknown"),
            lambda v: v["original"]["terminal"]["activity"].update(stage="materializing-signing"),
            lambda v: v["original"]["terminal"]["disposition"].update(output="retained-local-result"),
        ):
            bad = deepcopy(good); mutation(bad["iosArchive"])
            with self.assertRaises(M.Refused):
                M.parse_result(captured(bad), b"", BINDING, case)

    def test_empty_recovery_is_config_free_and_never_claims_a_mutation(self):
        case = "ios-recovery-empty"
        good = M.expected_result(BINDING, case)
        for mutation in (
            lambda v: v["context"].update(savedConfig={"bytes": 1, "sha256": "a" * 64}),
            lambda v: v["context"]["recovery"].update(action="account", session="a" * 32),
            lambda v: v["recoveryActions"].update(foreignMutationAttempted=True),
            lambda v: v["recoveryActions"].update(recoveryMutationClaimed=True),
            lambda v: v["recoveryActions"].update(ordinaryButtonsDisabled=False),
            lambda v: v["original"]["terminal"]["report"]["account"].update(status="recovered"),
            lambda v: v["original"]["terminal"]["report"]["project"].update(session="a" * 32),
            lambda v: v["original"]["terminal"].update(result=None),
            lambda v: v["original"]["terminal"]["lifetime"].update(signingClosed=False),
            lambda v: v["original"]["terminal"]["lifetime"].update(profileCalls=1),
        ):
            bad = deepcopy(good); mutation(bad["iosArchive"])
            with self.assertRaises(M.Refused):
                M.parse_result(captured(bad), b"", BINDING, case)
        files, directories = M.ios_fixture_data(case, False)
        self.assertEqual(set(files), {".gitignore", "keep.txt"})
        self.assertEqual(set(directories), {"."})
        self.assertEqual(M.ios_fixture_data(case, True), (files, directories))
        with self.assertRaises(M.Refused):
            M.signing_fixture_inputs(case)

    def test_current_scope_routes_only_fixed_calls_and_preserves_external_inputs(self):
        fixtures, calls, emitted = InertFixtures(), [], []
        fixtures.cases = M.IOS_CURRENT_CASES
        def runner(argv, **options):
            calls.append((argv, options))
            return CompletedProcess(argv, 0, captured(M.expected_result(BINDING, argv[1])), b"")
        M.run_cases(BINDING, fixtures, runner, UID, "runner", emitted.append, "ios-current-synthetic")
        self.assertEqual(fixtures.before, list(M.IOS_CURRENT_CASES))
        self.assertEqual(fixtures.reads, fixtures.before)
        self.assertEqual(len(emitted), 9)
        for (argv, options), case in zip(calls, M.IOS_CURRENT_CASES):
            self.assertEqual(argv, [M.EXECUTABLE, case])
            self.assertEqual(options["cwd"], BINDING.root() / "state" / case)
            self.assertEqual(options["timeout"], 60 if case == "ios-signing-inputs" else 325)
            self.assertEqual(options["environ"], M.app_environment(options["cwd"], UID, "runner"))
        for case in M.IOS_SESSION_CASES:
            files, links = M.signing_fixture_inputs(case)
            self.assertEqual(files["synthetic.p12"], (M.IOS_SYNTHETIC_P12, 0o600))
            self.assertEqual(files["synthetic.mobileprovision"], (M.IOS_SYNTHETIC_PROFILE, 0o600))
            project, _ = M.ios_fixture_data(case, False)
            self.assertNotIn("synthetic.p12", project)
            self.assertNotIn("synthetic.mobileprovision", project)
            if case == "ios-signing-inputs":
                self.assertEqual(files["public.p12"][1], 0o644)
                self.assertEqual(links, {"linked.p12": "synthetic.p12"})
                self.assertEqual(project["overlap.p12"], M.IOS_SYNTHETIC_P12)
            else:
                self.assertEqual(links, {})
                with self.assertRaises(M.Refused):
                    M.ios_fixture_data(case, True)
                for output in (True, False):
                    _, directories = M.ios_fixture_data(case, True, output_created=output)
                    # Output may be named by the root roster, but is independently
                    # verified rather than included in the source-directory snapshot.
                    self.assertEqual(".mobile-release" in directories["."][1], output)
                    self.assertNotIn(".mobile-release", directories)



class AndroidInputsAquaDataTests(unittest.TestCase):
    """Finite parser/source/control DATA; no Android build, native call or service."""

    def test_one_closed_scope_reuses_original_fixture_and_call(self):
        case = M.ANDROID_INPUT_CASE
        self.assertEqual(M.selected_cases(case), (case,))
        self.assertEqual(M.argument_scope(["--scope", case]), case)
        self.assertNotIn(case, M.IOS_CURRENT_CASES)
        self.assertEqual(M.case_timeout(case), 60)
        for argv in (["--scope", case, "--timeout", "999"], ["--scope", case, "--scope", "project-fields"], ["--scope", "android-build"]):
            with self.assertRaises(M.Refused):
                M.argument_scope(argv)
        fixtures, calls, emitted = InertFixtures(), [], []
        fixtures.cases = (case,)
        def runner(argv, **options):
            calls.append((argv, options))
            return CompletedProcess(argv, 0, captured(M.expected_result(BINDING, case)), b"")
        M.run_cases(BINDING, fixtures, runner, UID, "runner", emitted.append, case)
        self.assertEqual(fixtures.before, [case])
        self.assertEqual(fixtures.reads, [case])
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(emitted), 1)
        argv, options = calls[0]
        self.assertEqual(argv, [M.EXECUTABLE, case])
        self.assertEqual(options["cwd"], BINDING.root() / "state" / case)
        self.assertEqual(options["timeout"], 60)
        self.assertEqual(options["environ"], M.app_environment(options["cwd"], UID, "runner"))
        files, directories = M.fixture_data(case, False)
        self.assertEqual(M.fixture_data(case, True), (files, directories))
        self.assertEqual(set(files), {".gitignore", "app/build.gradle.kts", "keep.txt", "overlap.jks", "release/mobile-release.json", "version.properties"})
        self.assertEqual(set(directories), {".", "app", "release"})
        self.assertNotIn(".mobile-release", directories["."][1])
        config = json.loads(files["release/mobile-release.json"])
        self.assertTrue(config["android"]["enabled"])
        self.assertFalse(config["ios"]["enabled"])
        self.assertEqual(config["services"]["androidFirebase"], "required")
        native = (PATH.parents[1] / "src-tauri/src/installed_shell_observation_macos_ios.rs").read_text()
        literal = M.re.search(r'const CONFIG_ANDROID_INPUTS: &\[u8\] = br#"(.*?)"#;', native, M.re.S)
        self.assertIsNotNone(literal)
        self.assertEqual(literal.group(1).encode(), M.ANDROID_INPUT_CONFIG)
        external, links = M.signing_fixture_inputs(case)
        self.assertEqual(set(external), {"synthetic.jks", "google-services.json", "wrong-google-services.json", "public.jks"})
        self.assertEqual(links, {"linked.jks": "synthetic.jks"})
        self.assertEqual(external["public.jks"][1], 0o644)
        self.assertEqual(external["synthetic.jks"], (bytes.fromhex("feedfeed0000000200000000ff0080fe"), 0o600))
        for name in ("google-services.json", "wrong-google-services.json"):
            self.assertNotIn(name, files)
            self.assertEqual(external[name][1], 0o600)
        self.assertEqual(json.loads(external["google-services.json"][0])["client"][0]["client_info"]["android_client_info"]["package_name"], "org.example.mrk.observed")
        self.assertEqual(json.loads(external["wrong-google-services.json"][0])["client"][0]["client_info"]["android_client_info"]["package_name"], "org.example.mrk.other")
        original = initial_snapshot(case)
        M.validate_snapshot(original, dict(original), case, True, UID, GID)
        changed = dict(original); changed["overlap.jks"] = replace(changed["overlap.jks"], sha256="f" * 64)
        with self.assertRaises(M.Refused):
            M.validate_snapshot(original, changed, case, True, UID, GID)
        with self.assertRaises(M.Refused):
            M.fixture_data(case, True, ios_output_created=True)

    def test_report_requires_real_context_retirement_retained_ids_and_mismatch(self):
        case = M.ANDROID_INPUT_CASE
        good = M.expected_result(BINDING, case)
        self.assertEqual(M.parse_result(captured(good), b"", BINDING, case), good)
        self.assertLessEqual(len(captured(good)), M.JSON_LIMIT)
        self.assertNotIn("iosArchive", good)
        self.assertIs(good["shippingBinaryQualified"], False)
        self.assertIs(good["distributionQualified"], False)
        body = good["signingInputs"]
        self.assertEqual([row["operationId"] for row in body["rows"]], [2, 7, 12, 14, 15, 16, 17])
        self.assertEqual(body["originalOperations"], 18)
        self.assertEqual(body["context"], {"platform": "android", "stage": "production", "purpose": "full"})
        self.assertEqual(body["contextTransition"]["assignmentsUnavailable"], 2)
        self.assertEqual(M._result_location(("signingInputs", "contextTransition", "preservedRecords")),
                         "signingInputs.contextTransition.preservedRecords")
        self.assertEqual(body["rows"][2]["assessment"]["issues"], ["identity-mismatch"])
        self.assertIsNone(body["rows"][2]["recordId"])
        self.assertEqual(body["rows"][6]["source"], "pending")
        for row, token in zip(body["rows"][:2], ("1" * 32, "2" * 32)):
            row["recordId"] = token
        self.assertEqual(M.parse_result(captured(good), b"", BINDING, case), good)
        for mutate in (
            lambda v: v.update(originalOperations=12),
            lambda v: v.update(allOriginalsSettled=False),
            lambda v: v.update(oneUseOriginalDocumentRegistration=False),
            lambda v: v.pop("contextTransition"),
            lambda v: v["contextTransition"].update(currentRevision=1),
            lambda v: v["contextTransition"].update(assignmentsUnavailable=1),
            lambda v: v["contextTransition"].update(oldSelectionRetired=False),
            lambda v: v["rows"][0].update(operationId=4),
            lambda v: v["rows"][1].update(recordId=v["rows"][0]["recordId"]),
            lambda v: v["rows"][0].update(keptRevision=True),
            lambda v: v["rows"][0].update(assignedContextRevision=2),
            lambda v: v["rows"][2].update(recordId="3" * 32, keptRevision=1),
            lambda v: v["rows"][2]["assessment"].update(identity="match"),
            lambda v: v["rows"][2]["assessment"].update(issues=[]),
            lambda v: v["rows"][2]["assessment"]["fieldOutcomes"].__setitem__(2, "passed"),
            lambda v: v["rows"][6].update(source="refused"),
            lambda v: v["rows"][6].update(openInputJoined=True),
        ):
            bad = deepcopy(good); mutate(bad["signingInputs"])
            with self.assertRaises(M.Refused):
                M.parse_result(captured(bad), b"", BINDING, case)

    def test_native_cancel_and_quit_are_exactly_case_bound(self):
        case, step = M.ANDROID_INPUT_CASE, "Session(Native(6))"
        self.assertEqual(M._file_native_panels(case), {f"Session(Native({i}))": n for i,n in enumerate((2,7,12,14,15,16,17))})
        for i, identifier in enumerate((2,7,12,14,15,16)):
            self.assertEqual(M._file_open_step(case, identifier), f"Session(Native({i}))")
        self.assertIsNone(M._file_open_step(case, 17))
        self.assertIsNone(M._file_open_step(case, 11))
        cancel = action_context_data(site="file-cancel")
        cancel.update(snapshotSource="record")
        cancel["nativeHandler"]["step"] = step
        cancel["lastPanel"].update(step=step, id=17, kind="file")
        cancel["nativeAction"].update(step=step, id=17, action="file-cancel")
        self.assertEqual(M.failure_context(b"", context_row(cancel), case), cancel)
        self.assertIsNone(M.failure_context(b"", context_row(cancel), "ios-signing-inputs"))
        bad = deepcopy(cancel); bad["lastPanel"]["id"] = 11
        self.assertIsNone(M.failure_context(b"", context_row(bad), case))
        bad = deepcopy(cancel); foreign = file_failure_context_data(case, 6, 17)
        expected = deepcopy(cancel)
        for field in ("accessibility", "accessibilityBinding", "completionSelection"):
            bad[field] = foreign[field]; expected[field] = None
        self.assertEqual(M.failure_context(b"", context_row(bad), case), expected)
        quit = action_context_data("Quit")
        quit["lastPanel"]["id"] = quit["nativeAction"]["id"] = 18
        self.assertEqual(M.failure_context(b"", context_row(quit), case), quit)
        self.assertIsNone(M.failure_context(b"", context_row(quit), "ios-signing-inputs"))
        bad = deepcopy(quit); bad["lastPanel"]["id"] = 12
        self.assertIsNone(M.failure_context(b"", context_row(bad), case))

    def test_ordinary_private_fields_and_context_use_existing_originals(self):
        source = PATH.parents[1] / "src-tauri/src"
        observer = (source / "installed_shell_observation_macos.rs").read_text()
        session = (source / "installed_shell_observation_macos_session.rs").read_text()
        control = (source / "installed_shell_observation_macos_ios.rs").read_text()
        script = session.split("pub(super) fn script(case: Case, step: Step)", 1)[1]
        for text in ("storePassword", "keyAlias", "keyPassword", "fictional-store-password", "fictional-key-alias", "fictional-key-password"):
            self.assertIn(text, script)
        for text in ("selectValue('Release stage','production')", "Request cancel / discard this operation", "Not assigned to the current draft",
                     "The Firebase application identity does not match the submitted project draft.", "i.type!=='password'"):
            self.assertIn(text, script)
        for forbidden in ("setState(", "invoke(", "synthetic.jks", "/private/tmp/"):
            self.assertNotIn(forbidden, script)
        self.assertIn("args.fields == Some(&fields(s.case, i))", session)
        self.assertIn("self.completed == 2 && self.context_revision == Some(1)", session)
        self.assertIn('r["contextRevision"] == 1', session)
        self.assertIn('r["availability"] == "unavailable"', session)
        self.assertIn('if op["phase"] != if mismatch { "selected" } else { "preview" }', session)
        self.assertIn('case.open_id(current) == Some(id) && pending == Some(Pending::Accessibility(id))', observer)
        self.assertIn('const ANDROID_INPUT_ROSTER: &[&str] = &["android-inputs", "state"];', observer)
        self.assertIn('Self::SigningInputs | Self::AndroidInputs => None', control)
        self.assertIn("!c.input_only())", observer)
        data_checks = session.split("pub(super) fn data_checks()", 1)[1].split("impl Observation", 1)[0]
        for forbidden in ("thread::spawn", "tokio::spawn", "std::process::Command", "file_fact("):
            self.assertNotIn(forbidden, data_checks)

    def test_original_book_is_closed_to_its_consumed_case_and_early_quit_stays_safe(self):
        root = PATH.parents[1] / "src-tauri/src"
        document = (root / "asset_session.rs").read_text()
        control = (root / "installed_shell_observation_macos_ios.rs").read_text()
        session = (root / "installed_shell_observation_macos_session.rs").read_text()
        closed = control.split("pub(crate) fn session_final_original(self)", 1)[1].split("pub(super) fn input_only", 1)[0]
        for term in ("Self::AndroidInputs => Some(18)", "Self::SigningInputs | Self::SignedRefusal | Self::SignedCancel => Some(12)", "_ => None"):
            self.assertIn(term, closed)
        self.assertIn("case.session_final_original().and_then(|id| id.checked_sub(1)).unwrap_or(0)", session)
        self.assertIn("case.session_final_original().unwrap_or(0)", session)
        registration = control.split("impl SessionRegistration {", 1)[1].split("impl Admission {", 1)[0]
        for guard in ("Result<Case, BridgeError>", "!self.control.case.inputs()", "!self.control.permits()", "!r.attached", "r.started", "r.loaded",
                      "!self.claim_original(original)", "Ok(self.control.case)"):
            self.assertIn(guard, registration)
        self.assertLess(registration.index("!self.claim_original(original)"), registration.index("Ok(self.control.case)"))
        admission = document.split("pub(crate) fn register_installed_macos_session(", 1)[1].split("pub(crate) fn installed_macos_project_fields_identity", 1)[0]
        self.assertLess(admission.index("let input_case = token.consume(&self.inner.session_identity)?"),
                        admission.index("supervisor.assert_installed_session_available(&self.inner.session_identity)?"))
        self.assertLess(admission.index("supervisor.assert_installed_session_available(&self.inner.session_identity)?"),
                        admission.index("input_case: Some(input_case)"))
        bound = document.split("fn session_original_limit(", 1)[1].split("pub(crate) struct SessionSnapshot", 1)[0]
        for term in ("(false, Some(case)) => case.session_final_original()", "(true, None) => Some(12)", "_ => None",
                     "session_original_limit(self.project_fields.is_some(), self.input_case)"):
            self.assertIn(term, bound)
        record = document.split("pub(super) fn installed_macos_record_original(", 1)[1].split("pub(crate) fn installed_macos_session_snapshot", 1)[0]
        self.assertLess(record.index("let Some(book) = book.as_mut() else { return Ok(()); }"), record.index("book.original_limit()"))
        for term in ("!control.bound(&self.inner.session_identity)", "(2..=12, None)", "book.originals.len() >= limit as usize",
                     "owner.id as usize != book.originals.len() + 1", "!original_call(&self.inner, owner)",
                     "session_original_settled(&self.inner, old)", "book.originals.try_reserve(1)"):
            self.assertIn(term, record)
        for forbidden in (".permits(", ".timely(", ".failed."):
            self.assertNotIn(forbidden, record)
        final = document.split("fn macos_session_selected(", 1)[1].split("fn macos_project_fields_selected", 1)[0]
        for term in ("book.project_fields.is_some() || book.input_case.is_none()", "book.original_limit()", "limit.checked_sub(1)",
                     "book.originals.len() == limit as usize && state.next_operation == limit", "last.id == limit && kind.is_none()",
                     "slot.owner.id == lock_id && slot.operation == Operation::Lock", "slot.owner.stopped()", "slot.cleanup_end.is_some() && slot.discard",
                     "session_original_settled(&self.inner, owner)"):
            self.assertIn(term, final)
        p2 = document.split("fn macos_project_fields_selected(", 1)[1].split("pub(crate) async fn installed_macos_project_result", 1)[0]
        for term in ("book.project_fields.is_some() && book.input_case.is_none()", "book.originals.len() == 12 && state.next_operation == 12",
                     "last.id == 12 && kind.is_none()", "book.originals[1..11].iter().all"):
            self.assertIn(term, p2)
        self.assertIn("session_original_limit(true, Some(case)).is_some()", document)
        self.assertIn("registration.control.case != case", control)
        self.assertIn("for originals in [0, 1, 2, 12, 17, 19]", session)
        self.assertIn("for (originals, id) in [(11,11), (16,16), (17,11), (17,18), (18,17)]", session)


class ProjectFieldsAquaDataTests(unittest.TestCase):
    """Closed P2 comparison/control-flow DATA, never an AppKit/APFS receipt."""

    def test_scope_roots_are_disjoint_closed_and_collisions_are_not_adopted(self):
        ordinary = Path("/private/tmp/mrk-macos-aqua-" + "a" * 40 + "-123-1")
        fields = ordinary.with_name(ordinary.name + "-project-fields")
        self.assertEqual(BINDING.root(), ordinary)
        self.assertEqual(BINDING.root(project_fields=False), ordinary)
        self.assertEqual(BINDING.root(project_fields=True), fields)
        self.assertNotEqual(fields, ordinary)
        for invalid in (0, 1, None, "project-fields"):
            with self.subTest(selector=invalid), self.assertRaisesRegex(M.Refused, "^scope-not-supported$"):
                BINDING.root(project_fields=invalid)
        for scope in (None, "ios-unsigned-archive", "ios-current-synthetic", "project-fields"):
            fixtures = M.Fixtures(BINDING, UID, GID, scope)
            self.assertEqual(fixtures.path, fields if scope == "project-fields" else ordinary)
            self.assertEqual(fixtures.cases, M.selected_cases(scope))
            # An occupied namespace cannot acquire/adopt a later descriptor.
            # These are inert tokens: no real mkdir/open/chmod is attempted.
            parent = object()
            collision = FileExistsError("inert occupied namespace")
            with patch.object(M.os, "mkdir", side_effect=collision) as mkdir, \
                    patch.object(fixtures, "_open", side_effect=AssertionError("collision acquired a descriptor")) as opening:
                with self.assertRaises(FileExistsError) as failed:
                    fixtures._mkdir(parent, fixtures.path.name)
                self.assertIs(failed.exception, collision)
                mkdir.assert_called_once_with(fixtures.path.name, 0o700, dir_fd=parent)
                opening.assert_not_called()
            self.assertEqual(fixtures.fds, set())
        fixtures = InertFixtures()
        fixtures.cases = M.IOS_CURRENT_CASES
        with self.assertRaisesRegex(M.Refused, "^fixture-scope$"):
            M.run_cases(BINDING, fixtures, lambda *args, **kwargs: self.fail("mismatched scope invoked"),
                        UID, "runner", lambda value: self.fail("mismatched scope emitted"), "project-fields")
        self.assertEqual(fixtures.before, [])
        self.assertEqual(fixtures.reads, [])
        self.assertFalse(fixtures.inflight)
        source = (PATH.parents[1] / "src-tauri/src/installed_shell_observation_macos.rs").read_text()
        route = source.split("fn route(case: Case)", 1)[1].split("fn native_recheck_data_check()", 1)[0]
        self.assertIn('let suffix = if case == Case::ProjectFields { "-project-fields" } else { "" };', route)
        self.assertIn('format!("/private/tmp/mrk-macos-aqua-{source}-{run}-{attempt}{suffix}")', route)
        self.assertIn("directory_rosters(&root,uid,0o700,CURRENT_IOS_ROSTER,ios_alternate_roster(case),None)", route)
        self.assertIn('directory(&root,uid,0o700,&[project_fields::NAME,"state"])', route)

    def test_complete_project_fields_report_is_bounded_and_fail_closed(self):
        case = "project-fields"
        good = M.expected_result(BINDING, case)
        self.assertEqual(M.parse_result(captured(good), b"", BINDING, case), good)
        payload = captured(good)[len(M.MARKER):-1]
        self.assertGreater(len(payload), M.JSON_LIMIT)
        self.assertLessEqual(len(payload), M.PROJECT_FIELDS_JSON_LIMIT)
        self.assertEqual((M.JSON_LIMIT, M.PROJECT_FIELDS_JSON_LIMIT, M.FAILURE_CONTEXT_LIMIT, M.OUTPUT_LIMIT),
                         (16383, 32767, 8192, 2 * 1024 * 1024))
        padded = M.MARKER + payload + b" " * (32767 - len(payload)) + b"\n"
        self.assertEqual(M.parse_result(padded, b"", BINDING, case), good)
        with self.assertRaisesRegex(M.Refused, "^result-record$"):
            M.parse_result(padded[:-1] + b" \n", b"", BINDING, case)
        ordinary = captured(M.expected_result(BINDING, "noop-stale"))
        oversized = ordinary[:-1] + b" " * (16384 - (len(ordinary) - len(M.MARKER) - 1)) + b"\n"
        with self.assertRaisesRegex(M.Refused, "^result-record$"):
            M.parse_result(oversized, b"", BINDING, "noop-stale")
        # The success wrapper has its own fixed cap. No failure/ordinary type
        # inherits the larger allowance; bytes are rejected, never truncated.
        for kind, selected_case, limit in (("macos-aqua-case", case, 40960), ("macos-aqua-failure", case, 24576),
                                           ("macos-aqua-case", "noop-stale", 24576), (True, case, 24576),
                                           ("macos-aqua-case", True, 24576)):
            frame = {"type": kind, "case": selected_case, "padding": ""}
            base = len(json.dumps(frame, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii"))
            frame["padding"] = "x" * (limit - base)
            stream = io.StringIO(); M.emit_record(frame, stream)
            self.assertEqual(len(stream.getvalue().encode("ascii")), limit + 1)
            frame["padding"] += "x"; rejected = io.StringIO()
            with self.assertRaisesRegex(M.Refused, "^outer-result-bound$"):
                M.emit_record(frame, rejected)
            self.assertEqual(rejected.getvalue(), "")
        fields = good["projectFields"]
        self.assertEqual(fields["schemaVersion"], 2)
        self.assertEqual(fields["previewValidation"], "invalid-retained-ios-fields")
        self.assertIs(fields["normalProfileAvailable"], False)
        self.assertIs(fields["shippingProfileEnabledByThisReceipt"], False)
        # Literal independent journey roster. The helper's own table is not
        # used as the oracle for IDs, purpose, source entry, masks or results.
        expected = (
            (2, "version.source", "version-source", "inputs/VERSION", None, 6143, True),
            (3, "ios.project", "ios-project", "ios/Example.xcodeproj", None, 6143, True),
            (4, "ios.workspace", "ios-workspace", "ios/Example.xcworkspace", None, 6143, True),
            (5, "metadata.root", "metadata-root", "metadata", None, 6143, True),
            (6, "version.source", "version-source", None, None, 4607, False),
            (7, "metadata.root", "metadata-root", None, None, 4607, False),
            (8, "version.source", "version-source", None, "project_path_unsafe", 6143, False),
            (9, "version.source", "version-source", None, "project_path_unsafe", 6143, True),
            (10, "version.source", "version-source", None, "project_path_unsafe", 6143, True),
            (11, "ios.workspace", "ios-workspace", None, "project_path_changed", 6143, True),
        )
        self.assertEqual(len(fields["rows"]), len(expected))
        for row, (identifier, field, kind, relative, error, mask, started) in zip(fields["rows"], expected):
            accepted = identifier not in (6, 7)
            self.assertEqual(row, {
                "operationId": identifier, "field": field, "kind": kind,
                "nativeResponse": "accept" if accepted else "decline",
                "initialRootAndOptions": {"result": "ok", "facts": mask},
                "nameFieldPreparation": {"returned": True, "result": "ok", "facts": 31} if accepted and kind == "version-source" else None,
                "laterSyntheticNavigation": accepted, "exactNativeSelection": True if accepted else None,
                "sourceBookStarted": started, "originalSourceChildGuiAndCoordinatorSettled": True,
                "relativePath": relative, "errorCode": error, "draftObserved": True})
        histories = fields["acceptedOpenHistories"]
        self.assertEqual([row["operationId"] for row in histories], [1, 2, 3, 4, 5, 8, 9, 10, 11])
        self.assertEqual(len(histories), 9)
        for index, identifier in ((1, 2), (5, 8), (6, 9), (7, 10)):
            original = histories[index]
            action, binding, completion = (original[key] for key in ("selectionInput", "selectionBinding", "selectionCompletion"))
            self.assertEqual(action["mechanism"], "accessibility-version-source-selection-press-v6")
            self.assertEqual(binding["mechanism"], "selection-parent-original-sheet-v3")
            self.assertEqual((action["id"], binding["id"], completion["id"]), (identifier,) * 3)
            self.assertEqual(action["selectionParentProof"]["purpose"], "selection-parent")
            self.assertEqual(binding["binding"]["purpose"], "selection-parent")
            self.assertNotIn("purpose", action["initialOriginalProof"])
            self.assertNotIn("purpose", action["originalProof"])
            self.assertTrue(M._accessibility_succeeded(action))
            # Actual selected-child and selected-row layouts share no fallback.
            child = deepcopy(good)
            child["projectFields"]["acceptedOpenHistories"][index]["selectionInput"]["selection"].update(attribute="SelectedChildren")
            self.assertEqual(M.parse_result(captured(child), b"", BINDING, case), child)
        for mutation in (
            lambda v: v.update(schemaVersion=1),
            lambda v: v.update(normalProfileAvailable=True),
            lambda v: v.update(shippingProfileEnabledByThisReceipt=True),
            lambda v: v.update(oneUseOriginalDocumentRegistration=False),
            lambda v: v.update(allOriginalsSettled=False),
            lambda v: v.update(originalOperations=11),
            lambda v: v.update(fixtureMutationsRestored=False),
            lambda v: v.update(completeDraftAndBaselineMatched=False),
            lambda v: v.update(previewValidation="format-valid"),
            lambda v: v["rows"][0].update(operationId=1),
            lambda v: v["rows"][0].update(kind="file"),
            lambda v: v["rows"][0].update(field="ios.bundleId"),
            lambda v: v["rows"][0].update(sourceBookStarted=False),
            lambda v: v["rows"][0].update(originalSourceChildGuiAndCoordinatorSettled=False),
            lambda v: v["rows"][0]["initialRootAndOptions"].update(facts=4095),
            lambda v: v["rows"][0]["initialRootAndOptions"].update(facts=8191),
            lambda v: v["rows"][0].pop("nameFieldPreparation"),
            lambda v: v["rows"][0].update(nameFieldPreparation=None),
            lambda v: v["rows"][0]["nameFieldPreparation"].update(returned=False),
            lambda v: v["rows"][0]["nameFieldPreparation"].update(result="io"),
            lambda v: v["rows"][0]["nameFieldPreparation"].update(facts=15),
            lambda v: v["rows"][1].update(nameFieldPreparation={"returned": True, "result": "ok", "facts": 31}),
            lambda v: v["rows"][4].update(nameFieldPreparation={"returned": True, "result": "ok", "facts": 31}),
            lambda v: v["rows"][1].update(relativePath="../Example.xcodeproj"),
            lambda v: v["rows"][4].update(nativeResponse="accept", exactNativeSelection=True),
            lambda v: v["rows"][5].update(laterSyntheticNavigation=True),
            lambda v: v["rows"][6].update(sourceBookStarted=True),
            lambda v: v["rows"][9].update(errorCode=None),
            lambda v: v["panelAttachments"].__setitem__(8, False),
            lambda v: v["controlReturns"].__setitem__(5, False),
            lambda v: v["acceptedOpenHistories"].pop(),
            lambda v: v["acceptedOpenHistories"][1].update(operationId=1),
            lambda v: v["acceptedOpenHistories"][1].update(kind="project"),
            lambda v: v["acceptedOpenHistories"][8].update(originalBarrierRetired=False),
            lambda v: v["acceptedOpenHistories"][8].update(originalBindingMatched=False),
            lambda v: v["acceptedOpenHistories"][8].update(originalCompletionMatched=False),
            lambda v: v["acceptedOpenHistories"][1].pop("selectionInput"),
            lambda v: v["acceptedOpenHistories"][5].pop("selectionBinding"),
            lambda v: v["acceptedOpenHistories"][6].pop("selectionCompletion"),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"].update(mechanism="accessibility-preconfigured-original-press-v5"),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"].update(id=8),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"].update(step="OpenProject"),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"].update(selection=None),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"].update(selectionParentProof=None),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"].update(selectionParentPrompt=False),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selectionParentProof"].pop("purpose"),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["initialOriginalProof"].update(purpose="selection-parent"),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"].update(originalProof=None),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"].update(nodes=49),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"].update(matches=0),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"].update(matches=2),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"].update(attribute="Value"),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"].update(depth=0),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"].update(depth=9),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"].update(lastRole="not-read"),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"].update(selected=False),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"].update(returned=False),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"].update(attempted=False),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"]["checks"].update(completeProjection=False),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"]["checks"].update(attributeSettable=False),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"]["checks"].update(singletonOriginalEntryReadback=False),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"].update(workerJoined=False),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"].update(rechecksSettled=False),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"].update(state="unknown", custodyKnown=False),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"].update(expired=True, timely=False),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["promptButton"].update(calls=513),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["promptButton"].update(cfSlots=257, cfSlotsRetired=257),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["promptButton"].update(cfSlotsRetired=119),
            lambda v: v["acceptedOpenHistories"][1]["selectionBinding"].update(id=8),
            lambda v: v["acceptedOpenHistories"][1]["selectionBinding"].update(mechanism="preconfigured-original-sheet-v2"),
            lambda v: v["acceptedOpenHistories"][1]["selectionBinding"]["binding"].pop("purpose"),
            lambda v: v["acceptedOpenHistories"][1]["selectionCompletion"].update(id=8),
            lambda v: v["acceptedOpenHistories"][1]["selectionCompletion"]["facts"].update(selection="multiple"),
            lambda v: v["acceptedOpenHistories"][1]["selectionCompletion"]["facts"].update(selection="ordinary-path-disagreement"),
            lambda v: v["acceptedOpenHistories"][2].update(selectionInput=v["acceptedOpenHistories"][1]["selectionInput"]),
        ):
            bad = deepcopy(good); mutation(bad["projectFields"])
            with self.assertRaises(M.Refused):
                M.parse_result(captured(bad), b"", BINDING, case)

    def test_typed_selection_failures_retain_actual_stage_data_without_open_authority(self):
        # Inert decoded scalars only, not AppKit/AX execution or a native receipt.
        case, step = "project-fields", "ProjectFields(Native(0))"
        good = M.expected_result(BINDING, case)
        history = good["projectFields"]["acceptedOpenHistories"][1]
        frame = accessibility_context_data(); frame.update(snapshotSource="record")
        frame["nativeHandler"]["step"] = step
        frame["lastPanel"].update(step=step, id=2, kind="version-source")
        frame["accessibility"] = deepcopy(history["selectionInput"])
        frame["accessibilityBinding"] = deepcopy(history["selectionBinding"])
        frame["projectFieldPreparation"] = {"operationId": 2, "kind": "version-source", "returned": True,
            "result": "ok", "facts": 6143, "nameFieldPreparation": {"returned": True, "result": "ok", "facts": 31}}
        action = frame["accessibility"]
        action.update(attempted=False, pressReturned=False, triggered=None, initialOriginalProof=None, originalProof=None,
                      promptChecks={"initial": None, "final": None}, site="selection-projection", error="unsupported")
        action["promptButton"].update(checks={key: index < 2 for index, key in enumerate(M.ACCESSIBILITY_BUTTON_CHECKS)},
            calls=100, initialNodesExamined=0, recheckNodesExamined=0, lastRole="Sheet", lastDepth=0, cfSlots=40, cfSlotsRetired=40)
        action["selection"].update(checks={key: index < 1 for index, key in enumerate(M.ACCESSIBILITY_SELECTION_CHECKS)},
            attempted=False, returned=False, selected=None, nodes=8, matches=0, attribute="not-read", lastRole="List", depth=2)
        marker = f"MRK_MACOS_AQUA_FAILURE_STEP={step}\nMRK_MACOS_AQUA_FAILURE_REASON=native-default-action\n".encode("ascii")
        failures = []
        for label, site, error, completed, matches, attribute, selected, ax_error in (
            ("incomplete-roster", "selection-projection", "limit", 0, 1, "not-read", None, 0),
            ("no-entry", "selection-projection", "unsupported", 1, 0, "not-read", None, 0),
            ("distinct-entry-collision", "selection-projection", "ambiguous", 1, 2, "not-read", None, 0),
            ("changed-original-chain", "selection-recheck", "changed", 2, 1, "not-read", None, 0),
            ("not-settable", "selection-settable", "unsupported", 3, 1, "SelectedRows", None, 0),
            ("setter-error", "selection-write", "cannot-complete", 4, 1, "SelectedRows", False, -25204),
            ("empty-readback", "selection-readback", "unsupported", 4, 1, "SelectedChildren", True, 0),
            ("wrong-or-multiple-readback", "selection-readback", "changed", 4, 1, "SelectedRows", True, 0),
        ):
            failed = deepcopy(frame); sample = failed["accessibility"]
            sample.update(site=site, error=error)
            sample["selection"].update(checks={key: index < completed for index, key in enumerate(M.ACCESSIBILITY_SELECTION_CHECKS)},
                matches=matches, attribute=attribute, attempted=selected is not None, returned=selected is not None, selected=selected)
            sample["promptButton"]["axError"] = ax_error
            failures.append((label, failed))
        readback_failed = deepcopy(failures[-1][1])
        parent_refused = deepcopy(frame); sample = parent_refused["accessibility"]
        sample.update(site="selection-parent-proof", error="ineligible", selectionParentPrompt=None)
        sample["selectionParentProof"].update(parent=None, panel=None, children=None, originals=None,
            site="directory", error="ineligible", checks=dict.fromkeys(M.ACCESSIBILITY_PROOF_CHECKS, None))
        sample["selectionParentProof"]["checks"].update(eligible=True, attached=True, directory=False)
        sample["selection"].update(checks=dict.fromkeys(M.ACCESSIBILITY_SELECTION_CHECKS, False), nodes=0, matches=0,
                                   lastRole="not-read", depth=0)
        sample["promptButton"].update(checks=dict.fromkeys(M.ACCESSIBILITY_BUTTON_CHECKS, False), calls=0,
                                      lastRole="not-read", cfSlots=0, cfSlotsRetired=0)
        failures.append(("selection-parent-refused", parent_refused))
        no_url = deepcopy(readback_failed); sample = no_url["accessibility"]
        sample.update(site="initial-original-proof", error="ineligible")
        sample["selection"]["checks"] = dict.fromkeys(M.ACCESSIBILITY_SELECTION_CHECKS, True)
        proof = deepcopy(history["selectionInput"]["initialOriginalProof"])
        proof.update(parent=None, panel=None, children=None, originals=None, site="directory", error="ineligible",
            checks=dict.fromkeys(M.ACCESSIBILITY_PROOF_CHECKS, None))
        proof["checks"].update(eligible=True, attached=True, directory=False)
        sample["initialOriginalProof"] = proof
        self.assertTrue(M._selection_succeeded(sample["selection"]))
        failures.append(("real-selection-but-full-URL-refused", no_url))
        late = deepcopy(no_url); late["accessibility"].update(initialOriginalProof=None, error="deadline", expired=True, timely=False)
        failures.append(("selection-returned-but-original-deadline", late))
        unknown = deepcopy(readback_failed); sample = unknown["accessibility"]
        sample.update(error="custody", state="unknown", custodyKnown=False, receiptJoined=False, barrierRetired=False)
        sample["promptButton"].update(cleanupReturned=False, cfSlotsRetired=0)
        failures.append(("readback-custody-unknown", unknown))
        for label, failed in failures:
            with self.subTest(stage=label):
                wire = marker + context_row(failed)
                self.assertLessEqual(len(context_row(failed).split(b"=", 1)[1].rstrip(b"\n")), M.FAILURE_CONTEXT_LIMIT)
                self.assertEqual(M.failure_context(b"", wire, case), failed)
                self.assertFalse(M._accessibility_succeeded(failed["accessibility"]))
                rejected = deepcopy(good)
                rejected["projectFields"]["acceptedOpenHistories"][1]["selectionInput"] = failed["accessibility"]
                with self.assertRaises(M.Refused): M.parse_result(captured(rejected), b"", BINDING, case)
        for mutation in (
            lambda s: s.update(attempted=True),
            lambda s: s.update(selectionParentPrompt=False),
            lambda s: s["selectionParentProof"].pop("purpose"),
            lambda s: s["selection"].update(nodes=1, matches=2, depth=1),
            lambda s: s["selection"].update(lastRole="not-read"),
            lambda s: s["selection"].update(depth=0),
            lambda s: s["selection"].update(selected=True, returned=True),
            lambda s: s["selection"].update(attribute="SelectedRows"),
        ):
            bad = deepcopy(frame); mutation(bad["accessibility"])
            expected = deepcopy(bad); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", marker + context_row(bad), case), expected)
        bad = deepcopy(parent_refused); bad["accessibility"]["error"] = "unsupported"
        expected = deepcopy(bad); expected["accessibility"] = None
        self.assertEqual(M.failure_context(b"", marker + context_row(bad), case), expected)
        # Old kind4 inputs remain readable as historical failure DATA only.
        historical = deepcopy(frame)
        historical["accessibility"] = deepcopy(good["native"]["projectOpenInput"])
        historical["accessibility"].update(id=2, step=step)
        historical["accessibilityBinding"] = deepcopy(good["native"]["projectOpenBinding"])
        historical["accessibilityBinding"].update(id=2, kind="version-source")
        self.assertEqual(M.failure_context(b"", marker + context_row(historical), case), historical)
        self.assertFalse(M._accessibility_succeeded(historical["accessibility"]))
        self.assertIsNone(M._accessibility_context(historical["accessibility"], None, None,
            case=case, expected_id=2, field_history=True))

    def test_typed_selection_source_keeps_one_bounded_input_and_both_full_url_proofs(self):
        root = PATH.parents[1]
        native = (root / "native/macos-installed-native/src/native.m").read_text()
        rust = (root / "native/macos-installed-native/src/lib.rs").read_text()
        observer = (root / "src-tauri/src/installed_shell_observation_macos.rs").read_text()
        roles = native.split("static unsigned mrk_ax_selection_role(", 1)[1].split("static BOOL mrk_ax_selection_label(", 1)[0]
        for role, code in (("Column", "COLUMN"), ("List", "LIST"), ("Row", "ROW"), ("Cell", "CELL"),
                           ("Image", "IMAGE"), ("StaticText", "TEXT"), ("TextField", "FIELD")):
            self.assertIn(f"if (CFEqual(role, kAX{role}Role)) return MRK_SELECT_{code};", roles)
        label = native.split("static BOOL mrk_ax_selection_label(", 1)[1].split("static BOOL mrk_ax_selection_roster(", 1)[0]
        self.assertIn("CFEqual(value, expected)", label)
        self.assertIn("unsigned entry = p->entries[at]", label)
        self.assertLess(label.index("if (!p->matches[entry])"), label.index("s->result.selection_matches++"))
        self.assertIn("p->candidate = entry; p->label = at; p->label_attribute = attribute", label)
        roster = native.split("static BOOL mrk_ax_selection_roster(", 1)[1].split("static BOOL mrk_ax_select_entry(", 1)[0]
        for condition in ("other != at && p->nodes[other] && CFEqual(node, p->nodes[other])",
                          "mrk_ax_equal_attribute(s, node, kAXParentAttribute, p->nodes[p->parents[at]])",
                          "kind == MRK_ROLE_TABLE || kind == MRK_ROLE_OUTLINE", "kind == MRK_SELECT_LIST",
                          "rows ? kind != MRK_SELECT_ROW", "kind == MRK_ROLE_SHEET || kind == MRK_ROLE_GROUP",
                          "kind == MRK_ROLE_SPLIT_GROUP", "kind == MRK_ROLE_SCROLL_AREA", "kind == MRK_ROLE_BROWSER",
                          "kind == MRK_SELECT_COLUMN", "kind == MRK_SELECT_TEXT || kind == MRK_SELECT_FIELD",
                          "kAXValueAttribute, NO, expected", "kAXTitleAttribute, YES, expected",
                          "rows ? kAXRowsAttribute : kAXChildrenAttribute", "rows || list ? MRK_SELECT_ROWS : 16",
                          "p->depths[at] == MRK_CONTROL_DEPTH", "(unsigned)count > MRK_SELECT_NODES - queued",
                          "p->entries[queued] = rows || list ? queued : entry", "s->result.selection_matches != 1"):
            self.assertIn(condition, roster)
        self.assertLess(roster.index("for (unsigned at = 0; at < queued; ++at)"), roster.index("s->result.selection_checks |= 1u"))
        self.assertLess(roster.index("s->result.selection_checks |= 1u"), roster.index("s->result.selection_matches != 1"))
        for effect in ("AXUIElementSetAttributeValue", "AXUIElementPerformAction"):
            self.assertNotIn(effect, label + roster)
        write = native.split("static BOOL mrk_ax_select_entry(", 1)[1].split("static void mrk_ax_open(", 1)[0]
        for original in ("s->result.selection_checks != 3", "for (unsigned at = p->label;; at = p->parents[at])",
                         "at ? p->nodes[p->parents[at]] : parent", "mrk_ax_selection_role(role) != p->roles[at]",
                         "p->nodes[p->label], p->label_attribute, expected", "p->entries[p->label] != p->candidate",
                         "kind == MRK_ROLE_TABLE || kind == MRK_ROLE_OUTLINE ? kAXSelectedRowsAttribute",
                         "kind == MRK_SELECT_LIST ? kAXSelectedChildrenAttribute : NULL",
                         "mrk_ax_array(s, container, attribute, MRK_SELECT_ROWS, NO)",
                         "CFArrayGetCount(actual) != 1", "CFEqual(value, entry)"):
            self.assertIn(original, write)
        self.assertLess(write.index("AXUIElementIsAttributeSettable(container, attribute, &settable)"), write.index("if (!settable)"))
        self.assertLess(write.index("if (!settable)"), write.index("MRKPromptOwned *selected = mrk_ax_slot(s)"))
        self.assertLess(write.index("mrk_ax_slot(s)"), write.index("CFArrayCreate(NULL, entries, 1, &kCFTypeArrayCallBacks)"))
        setter = "AXUIElementSetAttributeValue(container, attribute, selected->array)"
        self.assertEqual(native.count("AXUIElementSetAttributeValue("), 1)
        self.assertLess(write.index("s->result.selection_flags |= 1u"), write.index(setter))
        self.assertLess(write.index(setter), write.index("s->result.selection_flags |= 2u"))
        self.assertLess(write.index("s->result.selection_flags |= 2u"), write.index("mrk_ax_array(s, container, attribute"))
        self.assertLess(write.index("CFEqual(value, entry)"), write.index("s->result.selection_checks |= 16u"))
        action = native.split("static void mrk_ax_open(", 1)[1].split("void mrk_observation_prompt_press(", 1)[0]
        order = ["mrk_ax_original(s, s->result.selection_mode ? 0 : 1)", "mrk_ax_projection(",
                 "mrk_ax_selection_roster(", "mrk_ax_select_entry(", "mrk_ax_original(s, 1)",
                 "mrk_ax_control_roster(", "mrk_ax_original(s, 2)", "AXUIElementPerformAction(button, kAXPressAction)"]
        positions = [action.index(value) for value in order]
        self.assertEqual(positions, sorted(positions))
        proof = native.split("static int mrk_original_proof(", 1)[1].split("int mrk_panel_observe_open_identity(", 1)[0]
        self.assertEqual(proof.count("selection_parent ? mrk_observation_selection_parent(s) : mrk_observation_directory_ready(s, NULL, NULL, NULL)"), 2)
        identity = native.split("int mrk_panel_observe_open_identity(", 1)[1].split("void mrk_panel_observe_open_recheck(", 1)[0]
        self.assertLess(identity.index("s->observationSelectionSample = 0"), identity.index("original != selectionSample"))
        self.assertLess(identity.index("s->observationSelectionBound = YES"), identity.index("mrk_original_proof(s, p, YES, selection)"))
        observe = native.split("int mrk_panel_observe(", 1)[1].split("// Closed DATA from this one original return.", 1)[0]
        self.assertIn("*flags == 0x5f00fu || *flags == 0x7f01fu", observe)
        self.assertIn("mrk_version_source_name_state(s, s->observationSample, MRK_NAME_ALL)", observe)
        self.assertIn("*flags |= MRK_VERSION_SOURCE_SELECTION_READY", observe)
        self.assertIn("MRK_SELECT_NODES = 49, MRK_SELECT_ROWS = 32", native)
        self.assertIn("MRKSelectionPass selection;", native)
        for forbidden in ("kAXURLAttribute", "kAXFilenameAttribute", "kAXPressAction", "setNameFieldStringValue", "setDirectoryURL",
                          "CGEvent", "NSPasteboard", "sleep(", "dispatch_", "pthread_create", "CFRelease("):
            self.assertNotIn(forbidden, label + roster + write)
        self.assertIn('pub fn matched(self) -> bool { self.purpose == "full-open"', rust)
        self.assertIn('pub fn selection_parent_matched(self) -> bool { self.purpose == "selection-parent"', rust)
        self.assertIn("stage as usize != context.next_recheck", rust)
        self.assertIn("next_recheck: if identity.selection { 0 } else { 1 }", rust)
        self.assertIn("context.rechecks[stage as usize] = Some(returned)", rust)
        recheck = observer.split("    fn worker_recheck(", 1)[1].split("    fn action_worker(", 1)[0]
        self.assertNotIn("stage as usize - 1", recheck)
        self.assertNotIn("sync_channel", recheck)
        self.assertLess(recheck.index("slot.receipt = Some(std::mem::ManuallyDrop::into_inner(receiver))"),
                        recheck.index("if !slot.settled(token, stage, self.end)"))
        self.assertIn('value["selectionInput"] = p.sample.reconciled(p.progress.snapshot()).value()', observer)
        self.assertIn('value["selectionBinding"] = p.identity.value()', observer)
        self.assertIn('value["selectionCompletion"] = p.completion.value()', observer)

    def test_original_fixture_restoration_has_only_two_ctime_exceptions(self):
        case = "project-fields"
        before = initial_snapshot(case)
        after = dict(before)
        for name in ("inputs/link-input", "inputs/kind-input"):
            node = after[name]
            after[name] = replace(node, identity=(*node.identity[:8], 101))
        # Parent directory size/times may change with exclusive rename; its
        # original inode/mode/owner/link count and the exact final roster may not.
        for name in (".", "inputs"):
            node = after[name]
            after[name] = replace(node, identity=(*node.identity[:6], 8192, 102, 102))
        result = M.validate_snapshot(before, after, case, True, UID, GID)
        self.assertEqual(result["projectFieldRestoration"], {
            "originalFileMetadataExceptRenameCtimeMatched": True,
            "allowedRenameCtimeChanges": ["inputs/link-input", "inputs/kind-input"],
            "rootModeRestored": True, "sameDirectoryOriginals": True})
        for name in ("inputs/link-input", "inputs/kind-input"):
            for index in range(8):
                changed = dict(after); facts = list(changed[name].identity); facts[index] += 1
                changed[name] = replace(changed[name], identity=tuple(facts))
                with self.subTest(name=name, fact=index), self.assertRaises(M.Refused):
                    M.validate_snapshot(before, changed, case, True, UID, GID)
        for name in (".", "inputs", "ios/Example.xcodeproj", "metadata"):
            for index in range(6):
                changed = dict(after); facts = list(changed[name].identity); facts[index] += 1
                changed[name] = replace(changed[name], identity=tuple(facts))
                with self.subTest(name=name, fact=index), self.assertRaises(M.Refused):
                    M.validate_snapshot(before, changed, case, True, UID, GID)
        for name, replacement in (
            ("inputs/link-input", replace(after["inputs/link-input"], sha256="0" * 64)),
            ("inputs/link-input", replace(after["inputs/link-input"], identity=(*after["inputs/link-input"].identity[:8], 99))),
            ("inputs/VERSION", replace(after["inputs/VERSION"], identity=(*after["inputs/VERSION"].identity[:8], 101))),
            ("inputs", replace(after["inputs"], entries=("VERSION", "kind-input", "link-original"))),
            (".", replace(after["."], identity=(*after["."].identity[:2], stat.S_IFDIR | 0o500, *after["."].identity[3:]))),
        ):
            changed = dict(after); changed[name] = replacement
            with self.subTest(name=name), self.assertRaises(M.Refused):
                M.validate_snapshot(before, changed, case, True, UID, GID)
        with self.assertRaises(M.Refused):
            M.validate_snapshot(before, after, case, False, UID, GID)
        changed = dict(after); changed["link-original"] = before["inputs/link-input"]
        with self.assertRaises(M.Refused):
            M.validate_snapshot(before, changed, case, True, UID, GID)
        # The outside selected file remains independently original-bound; it
        # cannot be replaced by taking another successful-looking snapshot.
        fixtures = M.Fixtures(BINDING, UID, GID)
        original = {"original": object()}
        fixtures.field_outside_originals[case] = original
        with patch.object(fixtures, "_capture_field_outside", return_value=original):
            fixtures._inputs_unchanged(case)
        with patch.object(fixtures, "_capture_field_outside", return_value={}):
            with self.assertRaisesRegex(M.Refused, "^project-field-outside-original-changed$"):
                fixtures._inputs_unchanged(case)
        self.assertIs(fixtures.field_outside_originals[case], original)

    def test_one_case_route_keeps_original_deadline_environment_and_return_finality(self):
        case = "project-fields"
        self.assertEqual(M.argument_scope(["--scope", case]), case)
        self.assertEqual(M.selected_cases(case), (case,))
        self.assertEqual(M.case_timeout(case), 60)
        for args in ([case], ["--scope", case, "--timeout", "600"], ["--scope", "project-fields-all"], ["--scope", "xcode-installed-classification"]):
            with self.assertRaises(M.Refused):
                M.argument_scope(args)
        fixtures, calls, emitted = InertFixtures(), [], []
        fixtures.cases = (case,)
        def returned(argv, **options):
            calls.append((argv, options))
            return CompletedProcess(argv, 0, captured(M.expected_result(BINDING, case)), b"")
        M.run_cases(BINDING, fixtures, returned, UID, "runner", emitted.append, case)
        self.assertEqual((fixtures.before, fixtures.reads, len(emitted), len(calls)), ([case], [case], 1, 1))
        argv, options = calls[0]
        state = BINDING.root(project_fields=True) / "state" / case
        self.assertEqual(argv, [M.EXECUTABLE, case])
        self.assertEqual(options, {"environ": M.app_environment(state, UID, "runner"), "cwd": state,
            "timeout": 60, "capture": True, "text": False, "output_limit": M.OUTPUT_LIMIT})
        self.assertEqual(set(options["environ"]), {"HOME", "TMPDIR", "PATH", "LANG", "LC_ALL", "TZ", "USER", "LOGNAME", "__CF_USER_TEXT_ENCODING"})
        original = RuntimeError("inert original interruption")
        def unknown(*args, **kwargs):
            raise original
        fixtures = InertFixtures()
        with self.assertRaises(RuntimeError) as failed:
            M.run_cases(BINDING, fixtures, unknown, UID, "runner", emitted.append, case)
        self.assertIs(failed.exception, original)
        self.assertTrue(fixtures.inflight); self.assertFalse(fixtures.last_returned)
        self.assertEqual(fixtures.reads, [])
        fixtures = InertFixtures()
        def foreign(argv, **options):
            return CompletedProcess([M.EXECUTABLE, "first-save"], 0, captured(M.expected_result(BINDING, case)), b"")
        with self.assertRaisesRegex(M.Refused, "^owner-return-contract$"):
            M.run_cases(BINDING, fixtures, foreign, UID, "runner", emitted.append, case)
        self.assertTrue(fixtures.inflight); self.assertEqual(fixtures.reads, [])
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        self.assertIn('"project-fields": ("one-project-fields-Aqua-engineering-case", ["project-fields"])', workflow)
        self.assertIn('"scope": scope_label', workflow)
        self.assertIn('"scopes": selected_scopes, "caseNames": case_names', workflow)
        self.assertIn('"ios-current-synthetic": ("nine-current-ios-Aqua-engineering-cases", [' + ", ".join('"' + name + '"' for name in M.IOS_CURRENT_CASES) + "])", workflow)
        self.assertEqual(workflow.count("macos_aqua_qualification.py --scope project-fields"), 1)
        self.assertEqual(workflow.count("macos_aqua_qualification.py --scope android-inputs"), 1)
        self.assertEqual(workflow.count("macos_aqua_qualification.py --scope ios-current-synthetic"), 1)
        self.assertNotIn("--scope ios-unsigned-archive", workflow)
        p2_label = "      - name: One project-field Aqua journey through the reviewed original invocation owner\n"
        ios_label = "      - name: Nine serial current-iOS Aqua cases through the reviewed original invocation owner\n"
        self.assertLess(workflow.index(p2_label), workflow.index(ios_label))
        p2_step = workflow.split(p2_label, 1)[1].split("\n      - name:", 1)[0]
        ios_step = workflow.split(ios_label, 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("timeout-minutes: 3", p2_step)
        self.assertIn("timeout-minutes: 50", ios_step)
        android_step = workflow.split("      - name: One Android-input Aqua journey through the reviewed original invocation owner\n", 1)[1].split("\n      - name:", 1)[0]
        for step, prefix, scope in ((p2_step, "aqua-project-fields", "project-fields"),
                                   (android_step, "aqua-android-inputs", "android-inputs"),
                                   (ios_step, "aqua", "ios-current-synthetic")):
            selection = "env.MRK_MACOS_AQUA_SCOPE == " + repr(scope)
            if scope in ("project-fields", "android-inputs"):
                selection = "(" + selection + " || env.MRK_MACOS_AQUA_SCOPE == 'project-fields-android-inputs')"
            self.assertEqual([line.strip() for line in step.splitlines() if line.strip().startswith("if:")],
                             ["if: success() && " + selection])
            for required in ("set -euo pipefail", "set -o noclobber", "umask 077", "status=$?", "[[ $status == 0 ]]"):
                self.assertIn(required, step)
            self.assertIn('> "$MRK_MACOS_WORK/' + prefix + '-results.jsonl" 2> "$MRK_MACOS_WORK/' + prefix + '-failure.jsonl"', step)
            status_write = 'printf \'%s\\n\' "$status" > "$MRK_MACOS_WORK/' + prefix + '.status"'
            self.assertLess(step.index("status=$?"), step.index(status_write))
            self.assertLess(step.index(status_write), step.index("[[ $status == 0 ]]"))
            for unsafe in ("continue-on-error", "rm -", "|| true"):
                self.assertNotIn(unsafe, step)
        uploads = workflow.split("          path: |\n", 1)[1]
        for name in ("aqua-project-fields-results.jsonl", "aqua-project-fields-failure.jsonl", "aqua-project-fields.status",
                     "aqua-android-inputs-results.jsonl", "aqua-android-inputs-failure.jsonl", "aqua-android-inputs.status",
                     "aqua-results.jsonl", "aqua-failure.jsonl", "aqua.status"):
            self.assertIn("${{ steps.work.outputs.root }}/" + name + "\n", uploads)
        for preserved in ("Bind the complete reviewed first-party checkout before compilation",
                          "Prepare only the fixed disposable Xcode ancestor before any worker",
                          "Reuse accepted Mac supplier and prepare only the current source payload",
                          "Application installation uses only standard privileged Installer; app and Python stay nonroot"):
            self.assertIn(preserved, workflow)

    @staticmethod
    def _readiness_failure_data():
        # Synthetic decoder DATA shaped like the returned op2 failure, not a
        # replacement receipt for that run's unrecorded readiness getters.
        step = "ProjectFields(Native(0))"
        value = accessibility_context_data()
        value.update(snapshotSource="record", accessibility=None)
        value["nativeHandler"].update(step=step, returned=True)
        value["lastPanel"].update(step=step, id=2, kind="version-source",
                                  directoryBound=True, directoryReturned=True, directoryReady=False,
                                  directoryReadiness="directory-not-matched", waitLocation="open-directory-readiness")
        value["accessibilityBinding"] = deepcopy(M.expected_result(BINDING, "project-fields")["native"]["projectOpenBinding"])
        value["accessibilityBinding"].update(id=2, kind="version-source", binding=None)
        value["projectFieldPreparation"] = {"operationId": 2, "kind": "version-source", "returned": True,
                                             "result": "ok", "facts": 8191}
        marker = f"MRK_MACOS_AQUA_FAILURE_STEP={step}\nMRK_MACOS_AQUA_FAILURE_REASON=observer-deadline\n".encode("ascii")
        return value, marker

    def test_readiness_failure_retains_same_query_and_exact_returned_wait(self):
        value, marker = self._readiness_failure_data()
        for classification in ("not-ready", "directory-not-matched", "filename-not-matched", "selection-not-matched"):
            current = deepcopy(value)
            current["lastPanel"]["directoryReadiness"] = classification
            if classification == "selection-not-matched":
                current["projectFieldPreparation"].update(facts=6143,
                    nameFieldPreparation={"returned": True, "result": "ok", "facts": 31})
            returned = M.failure_context(b"", marker + context_row(current), "project-fields")
            self.assertEqual(returned, current)
            self.assertEqual(returned["projectFieldPreparation"]["facts"],
                             6143 if classification == "selection-not-matched" else 8191)
            self.assertIsNone(returned["accessibility"])
            self.assertIsNone(returned["nativeAction"])
            self.assertIsNone(returned["accessibilityBinding"]["binding"])
            self.assertFalse(returned["lastPanel"]["directoryReady"])
            self.assertEqual(M.failure_reason(b"", marker + context_row(current)), "observer-deadline")
        # A ready query is not proof that the later Open preparation ran.
        value["lastPanel"].update(directoryReady=True, directoryReadiness="ready", waitLocation=None)
        self.assertEqual(M.failure_context(b"", marker + context_row(value), "project-fields"), value)
        self.assertIsNone(value["accessibility"])

    def test_readiness_failure_legacy_and_preparation_do_not_invent_wait(self):
        value, marker = self._readiness_failure_data()
        for key in ("directoryBound", "directoryReturned", "directoryReady", "directoryReadiness", "waitLocation"):
            del value["lastPanel"][key]
        self.assertEqual(M.failure_context(b"", marker + context_row(value), "project-fields"), value)
        self.assertNotIn("directoryReady", value["lastPanel"])
        self.assertNotIn("waitLocation", value["lastPanel"])
        value, marker = self._readiness_failure_data()
        value["lastPanel"].update(directoryReadiness="not-ready", waitLocation=None)
        # The native query can have returned before the enclosing body returns.
        value["nativeHandler"]["returned"] = False
        self.assertEqual(M.failure_context(b"", marker + context_row(value), "project-fields"), value)
        self.assertIsNone(value["lastPanel"]["waitLocation"])

    def test_readiness_failure_rejects_partial_foreign_or_contradictory_data(self):
        value, marker = self._readiness_failure_data()
        for key in ("directoryBound", "directoryReturned", "directoryReady", "directoryReadiness", "waitLocation"):
            bad = deepcopy(value); del bad["lastPanel"][key]
            self.assertIsNone(M.failure_context(b"", marker + context_row(bad), "project-fields"), key)
        for mutation in (
                lambda v: v["lastPanel"].update(directoryBound=1),
                lambda v: v["lastPanel"].update(directoryReturned=1),
                lambda v: v["lastPanel"].update(directoryReady=0),
                lambda v: v["lastPanel"].update(directoryReadiness="filename-ready"),
                lambda v: v["lastPanel"].update(directoryReadiness=None),
                lambda v: v["lastPanel"].update(directoryReadiness=2),
                lambda v: v["lastPanel"].update(directoryReady=True),
                lambda v: v["lastPanel"].update(directoryReadiness="ready"),
                lambda v: v["lastPanel"].update(directoryReturned=False),
                lambda v: v["lastPanel"].update(directoryBound=False),
                lambda v: v["lastPanel"].update(waitLocation="project-field-preparation"),
                lambda v: v["lastPanel"].update(waitLocation=1),
                lambda v: v["lastPanel"].update(directoryReady=True, directoryReadiness="ready"),
                lambda v: v["lastPanel"].update(id=3),
                lambda v: v["lastPanel"].update(path="/not-a-diagnostic-field"),
                lambda v: v["nativeHandler"].update(returned=False),
                lambda v: v.update(snapshotSource="prearm-open-progress")):
            bad = deepcopy(value); mutation(bad)
            self.assertIsNone(M.failure_context(b"", marker + context_row(bad), "project-fields"), bad)
        # Neither file-readiness predicate belongs to a directory original.
        for classification in ("filename-not-matched", "selection-not-matched"):
            bad = deepcopy(value)
            bad["nativeHandler"]["step"] = "ProjectFields(Native(1))"
            bad["lastPanel"].update(step="ProjectFields(Native(1))", id=3, kind="ios-project",
                                    directoryReadiness=classification)
            self.assertIsNone(M.failure_context(b"", marker + context_row(bad), "project-fields"))
        # Kind3 still uses filename text; the new selected-URL token cannot
        # be transplanted even into an otherwise valid original File sample.
        file_value = accessibility_context_data()
        file_value.update(snapshotSource="record", accessibility=None)
        file_value["nativeHandler"]["step"] = "Session(Native(0))"
        file_value["lastPanel"].update(step="Session(Native(0))", id=2, kind="file",
            directoryBound=True, directoryReturned=True, directoryReady=False,
            directoryReadiness="filename-not-matched", waitLocation="open-directory-readiness")
        self.assertEqual(M.failure_context(b"", context_row(file_value), M.ANDROID_INPUT_CASE), file_value)
        file_value["lastPanel"]["directoryReadiness"] = "selection-not-matched"
        self.assertIsNone(M.failure_context(b"", context_row(file_value), M.ANDROID_INPUT_CASE))
        # Selection mismatch cannot be relabelled ready, with or without wait.
        for wait in (None, "open-directory-readiness"):
            bad = deepcopy(value)
            bad["lastPanel"].update(directoryReadiness="selection-not-matched", directoryReady=True, waitLocation=wait)
            self.assertIsNone(M.failure_context(b"", marker + context_row(bad), "project-fields"))
        for step, (identifier, kind) in M.PROJECT_FIELD_PANELS.items():
            if identifier not in (6, 7):
                continue
            bad = deepcopy(value); bad["nativeHandler"]["step"] = step
            bad["lastPanel"].update(step=step, id=identifier, kind=kind)
            self.assertIsNone(M.failure_context(b"", marker + context_row(bad), "project-fields"))
        bad = deepcopy(value)
        bad["nativeHandler"]["step"] = "CancelProject"
        bad["lastPanel"].update(step="CancelProject", id=1, kind="project")
        self.assertIsNone(M.failure_context(b"", marker + context_row(bad), "project-fields"))

    def test_readiness_diagnostic_source_adds_no_query_action_or_wait_owner(self):
        # Closed diagnostics add no query. The functional kind4 predicate uses
        # one selected-URLs getter instead of a save-name getter in the SAME
        # evaluation; these source checks are not simulated AppKit evidence.
        root = PATH.parents[1]
        native = (root / "native/macos-installed-native/src/native.m").read_text()
        rust = (root / "native/macos-installed-native/src/lib.rs").read_text()
        observer = (root / "src-tauri/src/installed_shell_observation_macos.rs").read_text()
        helper = native.split("static BOOL mrk_observation_directory_ready(", 1)[1].split("static BOOL mrk_observation_selection_parent(", 1)[0]
        observe = native.split("int mrk_panel_observe(", 1)[1].split("// Closed DATA from this one original return.", 1)[0]
        self.assertEqual(helper.count("[(NSOpenPanel *)s->window directoryURL]"), 1)
        self.assertEqual(helper.count("[(NSOpenPanel *)s->window nameFieldStringValue]"), 1)
        self.assertEqual(helper.count("[(NSOpenPanel *)s->window URLs]"), 1)
        self.assertLess(helper.index("strcmp(path, expected) == 0"), helper.index("*versionSourceParentReady = YES"))
        self.assertLess(helper.index("*versionSourceParentReady = YES"), helper.index("s->kind == 4 ?"))
        self.assertIn("s->kind == 4 ? s->observationNamePhase == MRK_NAME_ALL", helper)
        self.assertLess(helper.index("s->kind == 4 ?"), helper.index("nameFieldStringValue]"))
        self.assertLess(helper.index("s->kind == 4 ?"), helper.index("[(NSOpenPanel *)s->window URLs]"))
        selection, filename = helper.split("    if (s->kind == 4) {", 1)[1].split("    } else {", 1)
        self.assertNotIn("nameFieldStringValue", selection)
        self.assertNotIn(" URLs]", filename)
        self.assertIn("urls && [urls isKindOfClass:[NSArray class]] && [urls count] == 1", selection)
        self.assertIn("id selected = [urls objectAtIndex:0];", selection)
        self.assertIn("[selected isKindOfClass:[NSURL class]] && [selected isFileURL]", selection)
        self.assertIn("? [selected fileSystemRepresentation] : NULL", selection)
        self.assertIn("selectedPath && mrk_target_path(selectedPath) && strcmp(selectedPath, s->observationTarget) == 0", selection)
        self.assertIn("BOOL ready = NO;", helper)
        self.assertIn("ready ? MRK_DIRECTORY_READY : MRK_FILE_NOT_MATCHED", helper)
        self.assertIn("ready = [[(NSOpenPanel *)s->window nameFieldStringValue] isEqualToString:[target lastPathComponent]];", filename)
        self.assertEqual(native.count("mrk_observation_directory_ready("), 4)
        self.assertEqual(native.count("mrk_observation_directory_ready(s, NULL, NULL, NULL)"), 2)
        self.assertEqual(native.count("setDirectoryURL:"), 3)
        self.assertEqual(native.count("setNameFieldStringValue:"), 2)
        query = "mrk_observation_directory_ready(s, &readiness, &parentReady, &selectionReady)"
        self.assertEqual(observe.count(query), 1)
        self.assertLess(observe.index(query), observe.index("*flags |= readiness << 17;"))
        self.assertLess(observe.index("s->observationParentSample = 0"), observe.index("++s->observationSample"))
        self.assertIn("s->observationSample == UINT32_MAX", observe)
        self.assertIn("parentReady && *flags == 0x1f00fu", observe)
        self.assertLess(observe.index("*flags |= readiness << 17;"), observe.index("*flags |= MRK_VERSION_SOURCE_PARENT_READY"))
        for token in ("setDirectoryURL:", "setNameFieldStringValue:", "dispatch_", "sleep(", "performClick", "AXUIElement",
                      "s->selected", "s->response =", "s->completion(", "observationCompletion", " retain]", " release]"):
            self.assertNotIn(token, helper)
        self.assertIn("flags & !0x1fffff == 0", rust)
        self.assertIn("(flags & 16 != 0) == (readiness == 3)", rust)
        self.assertIn("readiness == 0 || flags & 0x200c == 0x200c", rust)
        self.assertIn("flags & 0x80000 == 0 || flags == 0x9f00f", rust)
        self.assertIn("observation_directory_readiness(kind, 0x4200c)", rust)
        self.assertIn('2 if kind == PanelKind::File => Some("filename-not-matched")', rust)
        self.assertIn('2 if kind == PanelKind::VersionSource => Some("selection-not-matched")', rust)
        self.assertIn("observation_name_sample_valid(kind, 0x9f00f, 1)", rust)
        self.assertIn("!observation_name_sample_valid(kind, 0x6201c, 1)", rust)
        self.assertIn("directory_ready: flags & 16 != 0, directory_readiness", rust)
        dispatch = observer.split("fn native_step(&self", 1)[1].split("fn native_step_body(", 1)[0]
        body = observer.split("fn native_step_body(", 1)[1].split("    fn ", 1)[0]
        self.assertEqual(body.count("observed_panel()"), 1)
        self.assertLess(dispatch.index("self.native_step_body("), dispatch.index("native.returned = true"))
        self.assertLess(dispatch.index("native.returned = true"), dispatch.index('panel.wait_location = Some("open-directory-readiness")'))
        self.assertLess(dispatch.index("r.pending != Some(Pending::Native(step)) || r.step != step"),
                        dispatch.index('panel.wait_location = Some("open-directory-readiness")'))
        self.assertIn("p.step == step && readiness_wait == Some(p.id)", dispatch)
        gate = "if open && !input_ready {"
        self.assertEqual(body.count("*readiness_wait = Some(id);"), 1)
        self.assertLess(body.index("record.prepared(i)"), body.index(gate))
        self.assertLess(body.index("panel.native.version_source_name_ready()"), body.index("prepare_version_source_name(id, panel, &mut returned)"))
        name_call = body.index("prepare_version_source_name(id, panel, &mut returned)")
        self.assertLess(name_call, body.index("return Ok(false);", name_call))
        self.assertLess(body.index("return Ok(false);", name_call), body.index(gate))
        self.assertLess(body.index(gate), body.index("*readiness_wait = Some(id);"))
        self.assertLess(body.index("*readiness_wait = Some(id);"), body.index("prepare_open_input(id, target, selection, binding_return)"))
        wait = body.split(gate, 1)[1].split("        if open {", 1)[0]
        self.assertIn("return Ok(false); // Before any Open action; original deadline remains unchanged.", wait)
        for token in ("observed_panel(", "prepare_open_input(", "prepare_project_field(", "prepare_version_source_name(",
                      "Instant::", "Duration::", "self.record("):
            self.assertNotIn(token, wait)
        sample = observer.split("impl PanelSample {", 1)[1].split("fn same_panel_action_returned(", 1)[0]
        self.assertIn("wait_location: None", sample)
        for field in ("directory_bound", "directory_returned", "directory_ready", "directory_readiness"):
            self.assertIn(f"{field}: native.{field}", sample)

    def test_field_failure_diagnostics_bind_exact_original_and_never_fill_missing_evidence(self):
        case = "project-fields"
        for index, identifier, kind in ((0, 2, "version-source"), (1, 3, "ios-project"), (2, 4, "ios-workspace"),
                                         (3, 5, "metadata-root"), (6, 8, "version-source"), (9, 11, "ios-workspace")):
            step = f"ProjectFields(Native({index}))"
            value = accessibility_context_data()
            value.update(snapshotSource="record")
            value["nativeHandler"]["step"] = step
            value["lastPanel"].update(step=step, id=identifier, kind=kind)
            value["accessibility"].update(step=step, id=identifier)
            value["accessibilityBinding"] = deepcopy(M.expected_result(BINDING, case)["native"]["projectOpenBinding"])
            value["completionSelection"] = deepcopy(M.expected_result(BINDING, case)["native"]["projectCompletionSelection"])
            for field in ("accessibilityBinding", "completionSelection"):
                value[field].update(id=identifier, kind=kind)
            value["projectFieldPreparation"] = {"operationId": identifier, "kind": kind, "returned": True,
                "result": "ok", "facts": 8191 if kind == "version-source" else 6143}
            marker = f"MRK_MACOS_AQUA_FAILURE_STEP={step}\n".encode("ascii")
            self.assertEqual(M.failure_context(b"", marker + context_row(value), case), value)
            self.assertIsNone(M._accessibility_binding_context(value["accessibilityBinding"], case))
            self.assertIsNone(M._completion_selection_context(value["completionSelection"], case))
            for mutation in (lambda v: v["projectFieldPreparation"].update(operationId=12),
                             lambda v: v["projectFieldPreparation"].update(kind="file"),
                             lambda v: v["projectFieldPreparation"].update(returned=1),
                             lambda v: v["projectFieldPreparation"].update(facts=8192),
                             lambda v: v["projectFieldPreparation"].update(facts=512),
                             lambda v: v["projectFieldPreparation"].update(result="would-block", facts=257)):
                bad = deepcopy(value); mutation(bad)
                expected = deepcopy(bad); expected["projectFieldPreparation"] = None
                self.assertEqual(M.failure_context(b"", marker + context_row(bad), case), expected)
            # Missing top-level original step is missing DATA, not permission
            # to infer a preparation from a success-shaped mask or path.
            expected = deepcopy(value); expected["projectFieldPreparation"] = None
            self.assertEqual(M.failure_context(b"", context_row(value), case), expected)
            bad = deepcopy(value); bad["accessibility"]["step"] = "OpenProject"
            expected = deepcopy(bad); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", marker + context_row(bad), case), expected)
            bad = deepcopy(value); bad["lastPanel"]["kind"] = "file"
            self.assertIsNone(M.failure_context(b"", marker + context_row(bad), case))
        for index, identifier, kind, action in ((4, 6, "version-source", "file-cancel"),
                                                (5, 7, "metadata-root", "project-cancel")):
            step = f"ProjectFields(Native({index}))"
            value = action_context_data(site=action)
            value.update(snapshotSource="record")
            value["nativeHandler"]["step"] = step
            value["lastPanel"].update(step=step, id=identifier, kind=kind)
            value["nativeAction"].update(step=step, id=identifier, action=action)
            self.assertEqual(M.failure_context(b"", context_row(value), case), value)
            self.assertIsNone(M._field_open_step(case, identifier))
            self.assertNotIn("accessibility", value)
        for result, flags in (("would-block", 0), ("io", 257), ("io", 511 | 512), ("io", None)):
            value = {"operationId": 2, "kind": "version-source", "returned": True, "result": result, "facts": flags}
            self.assertEqual(M._field_preparation_context(value, case, "ProjectFields(Native(0))"), value)
        for entered, returned in ((False, False), (True, False), (True, True)):
            partial = deepcopy(M.expected_result(BINDING, case)["native"]["projectOpenBinding"])
            partial.update(id=2, kind="version-source", binding=None, mechanism="selection-parent-original-sheet-v3")
            partial["start"]["result"] = "io"
            partial["configuration"].update(site="initial-temporary-close", error="cleanup-unknown",
                initialDirectorySetterEntered=entered, initialDirectorySetterReturned=returned)
            self.assertEqual(M._accessibility_binding_context(partial, case, allow_files=True), partial)
            self.assertIsNone(M._accessibility_binding_context(partial, case))
            bad = deepcopy(partial); bad["configuration"]["error"] = "none"
            self.assertIsNone(M._accessibility_binding_context(bad, case, allow_files=True))
        for step in ("ProjectFields(Native(10))", "ProjectFields(Chosen(10))", "ProjectFields(Read(10))"):
            self.assertNotIn(step, M.FAILURE_STEPS)
        # New frames preserve separate navigation/name receipts. Retained old
        # five-key8191 frames above are not silently upgraded to this shape.
        for index, identifier in ((0, 2), (6, 8), (7, 9), (8, 10)):
            step = f"ProjectFields(Native({index}))"
            base = {"operationId": identifier, "kind": "version-source", "returned": True,
                    "result": "ok", "facts": 6143, "nameFieldPreparation": None}
            self.assertEqual(M._field_preparation_context(base, case, step), base)
            for result, flags in (("ok", 31), ("io", 7), ("io", 15), ("io", 23), ("io", 31),
                                  ("permission-denied", 0), ("already", 31), ("invalid-return", None), ("would-block", None)):
                value = deepcopy(base)
                value["nameFieldPreparation"] = {"returned": True, "result": result, "facts": flags}
                self.assertEqual(M._field_preparation_context(value, case, step), value)
            named = deepcopy(base)
            named["nameFieldPreparation"] = {"returned": True, "result": "ok", "facts": 31}
            for flags in (-1, 2, 4, 8, 16, 27, 32, 8191, True):
                bad = deepcopy(named); bad["nameFieldPreparation"]["facts"] = flags
                self.assertIsNone(M._field_preparation_context(bad, case, step))
            for mutation in (lambda v: v.update(facts=8191), lambda v: v.update(result="io"),
                             lambda v: v["nameFieldPreparation"].update(returned=1),
                             lambda v: v["nameFieldPreparation"].update(result="would-block", facts=0),
                             lambda v: v["nameFieldPreparation"].update(extra=True)):
                bad = deepcopy(named); mutation(bad)
                self.assertIsNone(M._field_preparation_context(bad, case, step))
        for identifier, kind, index in ((3, "ios-project", 1), (6, "version-source", 4)):
            bad = {"operationId": identifier, "kind": kind, "returned": True, "result": "ok", "facts": 6143,
                   "nameFieldPreparation": {"returned": True, "result": "ok", "facts": 31}}
            self.assertIsNone(M._field_preparation_context(bad, case, f"ProjectFields(Native({index}))"))

    def test_source_reuses_original_document_sourcebook_and_draft_only_ui(self):
        root = PATH.parents[1]
        document = (root / "src-tauri/src/asset_session.rs").read_text()
        source = (root / "src-tauri/src/asset_source_macos.rs").read_text()
        runtime = (root / "src-tauri/src/runtime.rs").read_text()
        observer = (root / "src-tauri/src/installed_shell_observation_macos.rs").read_text()
        fields = (root / "src-tauri/src/installed_shell_observation_macos_project_fields.rs").read_text()
        owner = (root / "src-tauri/src/saved_command_owner.rs").read_text()
        self.assertIn("const INSTALLED_MAC_PROJECT_FIELDS_QUALIFIED: bool = false;", runtime)
        for name in ("IOS_SIGNED_NATIVE_QUALIFIED", "IOS_RECOVERY_NATIVE_QUALIFIED"):
            self.assertIn(f"const {name}: bool = false;", owner)
        registration = document.split("pub(crate) fn register_installed_macos_project_fields(", 1)[1].split("pub(super) fn installed_macos_record_original(", 1)[0]
        for guard in ("state.next_operation != 0", "state.slot.is_some()", "state.unknown", "if observation.is_some()",
                      "token.consume(&self.inner.session_identity", "project_fields: Some(control)"):
            self.assertIn(guard, registration)
        for fact in ("Arc::ptr_eq(&d, document)", "self.returned.swap(true", "self.control.claimed.compare_exchange(false, true",
                     "self.bound(document)", "q.timely()"):
            self.assertIn(fact, fields)
        job = document.split("Job::ProjectPath { app, binding } => {", 1)[1].split("Job::", 1)[0]
        self.assertLess(job.index("document.phase(owner, Phase::Capturing)"), job.index("q.path_selected(document, owner, binding.field, &path)"))
        self.assertLess(job.index("q.path_selected(document, owner, binding.field, &path)"), job.index("match child(owner, Child"))
        probe = source.split("pub(crate) fn probe_project_path(", 1)[1].split("#[cfg(test)]", 1)[0]
        self.assertLess(probe.index("project_path_spelling(&root.path"), probe.index("book.begin("))
        self.assertLess(probe.index("book.directory(parent)? != root_identity"), probe.index("for name in parents"))
        for fact in ("book.child(parent, name, false, stop)", "AtFlags::AT_SYMLINK_NOFOLLOW", "book.probes.push(LeafProbe",
                     "book.finish(result, stop)"):
            self.assertIn(fact, probe)
        for forbidden in ("canonicalize(", "read_to_end(", "private_file(", "std::fs::read("):
            self.assertNotIn(forbidden, probe)
        chosen = observer.split("Step::ProjectFields(step) => {", 1)[1].split("Step::Session(step)", 1)[0]
        self.assertLess(chosen.index("record.ready_for_native(i, &snapshot)"), chosen.index("record.native_finished(i"))
        self.assertLess(chosen.index("record.native_finished(i"), chosen.index("fixture.restore(i"))
        for fact in ("publish_directory(file.as_fd(), name, file.as_fd(), saved)",
                     "publish_directory(file.as_fd(), saved, file.as_fd(), name)",
                     "mutation.temporary", "after[..8] != mutation.original[..8]", "self.verify(root, uid)?"):
            self.assertIn(fact, fields)
        script = fields.split("pub(super) fn script(", 1)[1].split("pub(super) fn data_checks()", 1)[0]
        for forbidden in ("invoke(", "__TAURI", "window.", "dispatchEvent(", "new Event(", ".value =", ".value="):
            self.assertNotIn(forbidden, script)
        for literal in ("Browse existing…", "Help: ", "Format validation needs attention", "invalid-retained-ios-fields"):
            self.assertIn(literal, fields)
        self.assertIn('v["validation"]["valid"] == false', fields)
        self.assertIn('rows.len() == 1 && rows[0]["code"] == "config.invalid"', fields)

    def test_production_initial_root_and_later_navigation_have_separate_one_use_custody(self):
        root = PATH.parents[1]
        native = (root / "native/macos-installed-native/src/native.m").read_text()
        rust = (root / "native/macos-installed-native/src/lib.rs").read_text()
        adapter = (root / "src-tauri/src/shell_macos_dialog.rs").read_text()
        observer = (root / "src-tauri/src/installed_shell_observation_macos.rs").read_text()
        fields = (root / "src-tauri/src/installed_shell_observation_macos_project_fields.rs").read_text()
        start = native.split("static int mrk_panel_start_inner(", 1)[1].split("int mrk_panel_start(", 1)[0]
        self.assertLess(start.index("length > 4096"), start.index("s->attempted = YES"))
        self.assertLess(start.index("mrk_panel_configure_open_identity(s)"), start.index("mrk_panel_initial_directory(s, initial, length)"))
        self.assertLess(start.index("mrk_panel_initial_directory(s, initial, length)"), start.index("MRK_ID_CONFIG_COMPLETE"))
        self.assertLess(start.index("MRK_ID_CONFIG_COMPLETE"), start.index("beginSheetModalForWindow:"))
        for fact in ("[panel setCanChooseFiles:kind == 3 || kind == 4]",
                     "[panel setCanChooseDirectories:kind == 1 || (kind >= 5 && kind <= 7)]",
                     "[panel setTreatsFilePackagesAsDirectories:kind >= 5 && kind <= 7]",
                     "[panel setAllowsMultipleSelection:NO]", "[panel setCanCreateDirectories:NO]", "[panel setResolvesAliases:NO]"):
            self.assertIn(fact, start)
        production = native.split("static int mrk_panel_initial_directory(", 1)[1].split("static int mrk_panel_start_inner(", 1)[0]
        navigation = native.split("int mrk_panel_observe_project_field(", 1)[1].split("int mrk_panel_observe_version_source_name(", 1)[0]
        name = native.split("int mrk_panel_observe_version_source_name(", 1)[1].split("// Main-only original proof", 1)[0]
        state = native.split("static BOOL mrk_version_source_name_state(", 1)[1].split("static BOOL mrk_observation_directory_ready(", 1)[0]
        self.assertNotIn("observationTarget", production)
        self.assertIn("memcpy(s->observationInitialRoot, bytes, length)", production)
        for temporary in ("initialDirectory", "initialPath"):
            release = f"[s->{temporary} release]; s->{temporary} = nil;"
            self.assertEqual(production.count(release), 1)
            self.assertEqual(navigation.count(release), 1)
        self.assertIn("if (s->observationProjectField) return EALREADY", navigation)
        self.assertLess(navigation.index("strcmp(path, s->observationInitialRoot)"), navigation.index("[panel setDirectoryURL:"))
        self.assertLess(navigation.index("s->observationProjectField |= 512u"), navigation.index("[panel setDirectoryURL:"))
        self.assertLess(navigation.index("[panel setDirectoryURL:"), navigation.index("s->observationProjectField |= 1024u"))
        self.assertNotIn("setNameFieldStringValue:", navigation)
        self.assertNotIn("[s->observationFieldName release]", navigation)
        self.assertIn("s->kind == 4", state)
        for fact in ("s->observationProjectField == 6143u", "s->observationNamePhase == phase", "s->observationSample == sample",
                     "!s->unknown", "!s->responded", "!s->callbackActive", "!s->closeAttempted", "!s->closed",
                     "!s->observationActionAttempted", "!s->observationActionReturned"):
            self.assertIn(fact, state)
        self.assertLess(name.index("s->observationParentSample = 0"), name.index("sample != granted"))
        self.assertIn("if (s->observationNamePhase) return EALREADY", name)
        self.assertLess(name.index("s->observationNamePhase = MRK_NAME_PHASE_ENTERED"), name.index("mrk_observation_attached(s)"))
        self.assertEqual(name.count("mrk_observation_attached(s)"), 1)
        self.assertEqual(name.count("setNameFieldStringValue:"), 1)
        self.assertLess(name.index("MRK_NAME_SET_ENTERED"), name.index("setNameFieldStringValue:"))
        self.assertLess(name.index("setNameFieldStringValue:"), name.index("MRK_NAME_SET_RETURNED"))
        self.assertLess(name.index("[s->observationFieldName release]"), name.index("MRK_NAME_RETIRED"))
        self.assertIn("s->observationFieldName = nil", name)
        self.assertIn("result == 0 && !mrk_version_source_name_state(s, sample, MRK_NAME_ALL)", name)
        self.assertEqual(name.count("@catch (NSException *e)"), 2)
        for forbidden in ("directoryURL]", "setDirectoryURL:", "nameFieldStringValue]", "return EAGAIN",
                          "dispatch_", "sleep(", "AXUIElement", "s->selected", "s->response =", "s->completion(", "beginSheet", "performClick", "cancel:nil"):
            self.assertNotIn(forbidden, name)
        for forbidden in ("s->selected", "s->response =", "s->completion(", "beginSheet", "performClick", "cancel:nil"):
            self.assertNotIn(forbidden, navigation)
        prepare = adapter.split("pub(crate) fn prepare_project_field(", 1)[1].split("// Retained by", 1)[0]
        prepare_name = adapter.split("pub(crate) fn prepare_version_source_name(", 1)[1].split("pub(crate) fn prepare_project_field(", 1)[0]
        for fact in ("original(entry)?", "entry.open_release.is_some()", "!allowed(&call, &owner)?", "owner.interrupted()"):
            self.assertIn(fact, prepare)
            self.assertIn(fact, prepare_name)
        self.assertIn(".installed_project_field(kind, navigate, returned)", prepare)
        for fact in ("panel.id != id", "entry.id == id", "!panel.action_allowed", "!panel.native.version_source_name_ready()",
                     "panel.native.version_source_parent_ready", ".installed_version_source_name(sample, returned)"):
            self.assertIn(fact, prepare_name)
        self.assertNotIn("observed_panel(", prepare_name)
        method = rust.split("pub fn installed_version_source_name(", 1)[1].split("pub fn installed_project_field(", 1)[0]
        self.assertIn("version_source_parent_matches(&sample, self.original)", method)
        self.assertIn("sample.sample, &mut facts", method)
        self.assertIn("Ok(()) if data.succeeded()", method)
        self.assertIn("Err(error) => { self.unknown = true; Err(error) }", method)
        self.assertNotIn("Ok(false)", method)
        self.assertIn("flags & !6143 == 0", rust)
        self.assertIn("flags & !31 == 0", rust)
        self.assertIn("self.navigation_prepared(i)", fields)
        self.assertIn("if needs_name(i) { r.name_preparation.is_some_and(|p| p.succeeded()) }", fields)
        record_name = fields.split("pub(super) fn name_preparation(&mut self", 1)[1].split("pub(super) fn preparation_sample(", 1)[0]
        self.assertIn("if !self.name_pending(i) { return false; }", record_name)
        self.assertIn("row.name_preparation = Some(value)", record_name)
        self.assertIn("value.succeeded()", record_name)
        dispatch = observer.split("fn native_step(&self", 1)[1].split("fn native_step_body(", 1)[0]
        for publication in ("record.preparation(i, returned)", "record.name_preparation(i, returned)"):
            self.assertLess(dispatch.index("self.native_step_body("), dispatch.index(publication))
            self.assertLess(dispatch.index("native.returned = true"), dispatch.index(publication))
        self.assertIn("native.step == step && native.entered && native.returned", dispatch)
        body = observer.split("fn native_step_body(", 1)[1].split("    fn ", 1)[0]
        phase = body.split("            if !prepared {", 1)[1].split("        if open &&", 1)[0]
        for fact in ("record.name_pending(i)", "r.pending != Some(Pending::Native(step)) || r.step != step", "self.timely()"):
            self.assertIn(fact, phase)
        for forbidden in ("observed_panel(", "Instant::", "Duration::", "dispatch", "spawn", "sleep"):
            self.assertNotIn(forbidden, phase)
        self.assertIn("enum { MRK_PROMPT_ORIGINALS = 9 };", native)
        self.assertIn("project_field_data_check()", rust.split("pub fn installed_observation_flags_data_check()", 1)[1])
        self.assertIn("version_source_name_data_check()", rust.split("fn project_field_data_check()", 1)[1])
        pure = rust.split("fn version_source_name_data_check()", 1)[1].split('unsafe extern "C"', 1)[0]
        for forbidden in ("Panel::", "mrk_panel_", "thread::spawn", "std::fs::"):
            self.assertNotIn(forbidden, pure)


class XcodeInstalledClassificationWorkflowTests(unittest.TestCase):
    def test_source_fixed_read_only_route_excludes_every_build_and_keeps_failure_post(self):
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        self.assertEqual(workflow.count("      MRK_MACOS_AQUA_SCOPE: ${{ matrix.scope }}\n"), 1)
        self.assertNotIn("workflow_dispatch", workflow)
        steps = {}
        for block in workflow.split("      - name: ")[1:]:
            name, body = block.split("\n", 1)
            self.assertNotIn(name, steps)
            steps[name] = body
        admitted = {
            "Admit only this exact disposable-hosted source route",
            "Check out exact reviewed source without retained credentials",
            "Select DATA stager Python, not the packaged interpreter",
            "Reserve fresh private work before every candidate and toolchain query",
            "Bind the complete reviewed first-party checkout before compilation",
        }
        legacy = {
            "Select fixed frontend compiler",
            "Record exact source and actual tool bindings only after route admission",
            "Check current owner pins before native preparation",
            "Compile headless Mac libraries and run thirteen exact DATA regressions first",
            "Fail fast on native Scripts ownership and package format (never Installer)",
            "Download only the exact accepted M archive (no rebuild or fallback)",
            "Reuse accepted Mac supplier and prepare only the current source payload",
            "Compile the fixed debug actual-main observer and normal embedded frontend once",
            "Assemble the instrumented engineering app; ad-hoc sign only the app",
            "Bind this signed app and current-source runtime into fresh Installer DATA",
            "Build the fixed one-shot root Installer and scripts-only package",
            "Application installation uses only standard privileged Installer; app and Python stay nonroot",
            "Nonroot byte/mode readback, not a headless GUI substitute",
            "Verify source stayed unchanged; retire only disposable owned build output",
        }
        classifiers = {
            "Classify installed Xcode originals without preparing or selecting a toolchain":
                "success() && env.MRK_MACOS_AQUA_SCOPE == 'xcode-installed-classification'",
            "Recheck admitted classification/private-native source even after an incomplete observation":
                "always() && (env.MRK_MACOS_AQUA_SCOPE == 'xcode-installed-classification' || env.MRK_MACOS_AQUA_SCOPE == 'wrapping-keychain-private') && steps.source.outcome == 'success'",
            "Preserve bounded classification DATA and original workflow exit evidence":
                "always() && env.MRK_MACOS_AQUA_SCOPE == 'xcode-installed-classification' && steps.source.outcome == 'success'",
        }
        private = {
            "Compile native wrapping variants once and run fixed cohorts and creator-reader pair":
                "success() && env.MRK_MACOS_AQUA_SCOPE == 'wrapping-keychain-private'",
            "Preserve bounded private-cohort public facts and compiler-only diagnostics":
                "always() && env.MRK_MACOS_AQUA_SCOPE == 'wrapping-keychain-private' && steps.source.outcome == 'success'",
        }
        scoped = {
            "Prepare only the fixed disposable Xcode ancestor before any worker": "ios-current-synthetic",
            "One project-field Aqua journey through the reviewed original invocation owner": "project-fields",
            "One Android-input Aqua journey through the reviewed original invocation owner": "android-inputs",
            "Nine serial current-iOS Aqua cases through the reviewed original invocation owner": "ios-current-synthetic",
        }
        legacy_exports = {
            "Export bounded diagnostics without altering original command evidence",
            "Preserve bounded original evidence; upload alone is not an Aqua pass",
        }
        self.assertEqual(set(steps), admitted | legacy | set(classifiers) | set(private) | set(scoped) | legacy_exports)
        for name, body in steps.items():
            gates = [line.strip() for line in body.splitlines() if line.startswith("        if:")]
            if name in admitted:
                expected = []
            elif name in classifiers:
                expected = ["if: " + classifiers[name]]
            elif name in private:
                expected = ["if: " + private[name]]
            elif name in scoped:
                selection = "env.MRK_MACOS_AQUA_SCOPE == " + repr(scoped[name])
                if scoped[name] in ("project-fields", "android-inputs"):
                    selection = "(" + selection + " || env.MRK_MACOS_AQUA_SCOPE == 'project-fields-android-inputs')"
                expected = ["if: success() && " + selection]
            else:
                prefix = "always() && steps.work.outputs.root != ''" if name in legacy_exports else "success()"
                expected = ["if: " + prefix + " && (env.MRK_MACOS_AQUA_SCOPE == 'project-fields' || env.MRK_MACOS_AQUA_SCOPE == 'ios-current-synthetic' || env.MRK_MACOS_AQUA_SCOPE == 'android-inputs' || env.MRK_MACOS_AQUA_SCOPE == 'project-fields-android-inputs')"]
            with self.subTest(step=name):
                self.assertEqual(gates, expected)
        classify = steps["Classify installed Xcode originals without preparing or selecting a toolchain"]
        self.assertIn("timeout-minutes: 2", classify)
        self.assertIn("shell: /usr/bin/env -i /bin/bash --noprofile --norc -e -o pipefail {0}", classify)
        self.assertIn("exec /usr/bin/env -i", classify)
        self.assertIn("'${{ steps.python.outputs.python-path }}' -I -S -B", classify)
        command = "/Users/runner/work/mobile-release-kit/mobile-release-kit/desktop/tools/macos_xcode_host_preparation.py --classify-installed"
        self.assertEqual([line.strip() for line in classify.splitlines() if "macos_xcode_host_preparation.py" in line], [command])
        for forbidden in ("sudo", "xcodebuild", "xcrun", "cargo", "npm", "continue-on-error", "set +e", "|| true", "rm -"):
            self.assertNotIn(forbidden, classify)
        admission = steps["Admit only this exact disposable-hosted source route"]
        self.assertIn('if [[ "$MRK_MACOS_AQUA_SCOPE" != xcode-installed-classification && "$MRK_MACOS_AQUA_SCOPE" != wrapping-keychain-private ]]; then', admission)
        self.assertIn("        id: source\n", steps["Bind the complete reviewed first-party checkout before compilation"])
        post = steps["Recheck admitted classification/private-native source even after an incomplete observation"]
        self.assertIn("git -c core.fsmonitor=false diff --exit-code HEAD --", post)
        self.assertIn("status --porcelain=v1 --untracked-files=all", post)
        self.assertIn('[[ "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]]', post)
        self.assertNotIn("success()", post)
        self.assertNotIn("rm -", post)
        upload = steps["Preserve bounded classification DATA and original workflow exit evidence"]
        self.assertEqual([line.strip() for line in upload.splitlines() if "${{ steps.work.outputs.root }}/" in line], [
            "${{ steps.work.outputs.root }}/source-inventory.json",
            "${{ steps.work.outputs.root }}/xcode-installed-classification-result.json",
        ])
        self.assertIn("if-no-files-found: error", upload)

    def test_selected_scope_keeps_unique_artifacts_and_three_private_variants(self):
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        header = workflow.split("    steps:\n", 1)[0]
        expected_job = (
            "  aqua:\n"
            "    if: github.event_name == 'push' && github.ref == 'refs/heads/verify/desktop-macos-aqua'\n"
            "    name: aqua-${{ matrix.scope }}\n"
            "    permissions:\n"
            "      contents: read\n"
            "    strategy:\n"
            "      fail-fast: false\n"
            "      matrix:\n"
            "        scope:\n"
            "          - project-fields-android-inputs\n"
            "          - wrapping-keychain-private\n"
            "    runs-on: macos-26\n"
            "    timeout-minutes: 75\n"
        )
        self.assertEqual(header.split("jobs:\n", 1)[1].split("    env:\n", 1)[0], expected_job)
        self.assertIn("on:\n  push:\n    branches:\n      - verify/desktop-macos-aqua\n", header)
        self.assertIn("permissions:\n  contents: read\n  actions: read\n", header)
        self.assertIn("concurrency:\n  group: desktop-macos-aqua-${{ github.ref }}\n  cancel-in-progress: false\n", header)
        for line in (
            "      MRK_EXPECTED_SHA: ${{ github.sha }}\n",
            "      MRK_MACOS_INSTALL_SOURCE_COMMIT: ${{ github.sha }}\n",
            "      MRK_MACOS_AQUA_SCOPE: ${{ matrix.scope }}\n",
        ):
            self.assertEqual(header.count(line), 1)
        for forbidden in ("workflow_dispatch", "continue-on-error"):
            self.assertNotIn(forbidden, workflow)
        steps = dict(block.split("\n", 1) for block in workflow.split("      - name: ")[1:])
        compiler = "Compile the fixed debug actual-main observer and normal embedded frontend once"
        self.assertEqual(workflow.count("      - name: " + compiler + "\n"), 1)
        self.assertEqual(steps[compiler].count("cargo test --locked"), 1)
        self.assertEqual(steps[compiler].count("npm run build"), 1)
        private = steps["Compile native wrapping variants once and run fixed cohorts and creator-reader pair"]
        self.assertIn("if: success() && env.MRK_MACOS_AQUA_SCOPE == 'wrapping-keychain-private'", private)
        for required in (
            'for role, features, flags in (("normal", [], ""), ("observer", ["installed-observation"], ""),\n'
            '                                            ("qualification", ["installed-observation"], "--cfg mrk_wrapping_keychain_qualification")):',
            'target = work / ("wrapping-" + role + "-target")',
            'environment = dict(build_env, CARGO_TARGET_DIR=str(target), RUSTFLAGS=flags)',
            'argv = ["cargo", "test", "--locked", "--no-default-features", "--jobs", "2",',
            '"--manifest-path", str(native / "Cargo.toml"),',
            '"--lib", "--no-run", "--message-format=json"]',
            'owner = qualification.load_owner(checkout)',
            'name = "wrapping_keychain::private_fixture::private_keychain_cohort"',
        ):
            self.assertIn(required, private)
        self.assertEqual(private.count('name = "wrapping_keychain::private_fixture::private_keychain_cohort"'), 1)
        self.assertNotIn("npm", private)
        self.assertNotIn("sudo", private)
        artifact_prefix = "desktop-macos-aqua-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}-"
        primary_upload = steps["Preserve bounded original evidence; upload alone is not an Aqua pass"]
        private_upload = steps["Preserve bounded private-cohort public facts and compiler-only diagnostics"]
        self.assertIn("name: " + artifact_prefix + "${{ env.MRK_MACOS_AQUA_SCOPE }}", primary_upload)
        self.assertIn("name: " + artifact_prefix + "wrapping-keychain-private", private_upload)
        resolved = [artifact_prefix + scope for scope in ("project-fields-android-inputs", "wrapping-keychain-private")]
        self.assertEqual(len(set(resolved)), 2)
        private_leaves = ["source-inventory.json", "wrapping-native.receipt.json", "wrapping-native.report.json",
                          "wrapping-before-add.report.json", "wrapping-before-lookup.report.json", "wrapping-creator.report.json",
                          "wrapping-reader.report.json", "wrapping-pair.receipt.json", "wrapping-codec.receipt.json"]
        private_leaves += ["wrapping-" + role + "-build." + suffix
                           for role in ("codec", "normal", "observer", "qualification", "reader")
                           for suffix in ("jsonl", "stderr", "status")]
        self.assertEqual([line.strip() for line in private_upload.splitlines()
                          if "${{ steps.work.outputs.root }}/" in line],
                         ["${{ steps.work.outputs.root }}/" + leaf for leaf in private_leaves])
        for upload in (primary_upload, private_upload):
            self.assertIn("if-no-files-found: error", upload)
        # Exact private leaves exclude native stdout/stderr, the fixture, binaries
        # and Keychain bytes; upload success cannot replace any original result.
        native = PATH.parents[2] / "desktop/native/macos-installed-native/src"
        fixture = (native / "wrapping_keychain_fixture.m").read_text()
        rust = (native / "wrapping_keychain_fixture.rs").read_text()
        save_acl = fixture.split("static int mrk_q_save_acl(", 1)[1].split("static int mrk_q_acl_entry(", 1)[0]
        restore_acl = fixture.split("static int mrk_q_restore_acl(", 1)[1].split("static int mrk_q_mode(", 1)[0]
        self.assertNotIn("acl_delete_fd_np(", fixture)
        self.assertIn("m->removal = filesec_init()", save_acl)
        self.assertIn("filesec_set_property(m->removal, FILESEC_ACL, _FILESEC_REMOVE_ACL)", save_acl)
        self.assertIn("acl_set_fd_np(fd, m->original, ACL_TYPE_EXTENDED) : fchmodx_np(fd, m->removal)", restore_acl)
        self.assertNotIn("fchmodx_np(fd, m->filesec)", restore_acl)
        self.assertNotIn("fchmod(", restore_acl)
        self.assertLess(restore_acl.index("m->restored = 1;"), restore_acl.index("fstatx_np(fd, &restored, m->filesec)"))
        self.assertIn("mrk_w_same(mrk_w_identity(&restored)", restore_acl)
        self.assertIn("q_rc == 0 && restored_present == 0", restore_acl)
        self.assertIn("filesec_free(m->removal)", restore_acl)
        self.assertIn("m->filesec || m->removal || m->original || m->replacement", fixture)
        self.assertIn("!(1..=47).contains(&row.kind)", rust)
        self.assertIn("count(47, 0) != 3 || count(29, 0) != 3 || count(16, 0) != 6 || count(17, 0) != 6", rust)
        self.assertIn("count(15, 1) != 6", rust)
        self.assertIn("count(31, 0) != 6", rust)
        self.assertIn("not 1 <= a[0] <= 47", private)

    def test_paired_native_scopes_share_one_compile_but_not_original_owners(self):
        import ast
        import textwrap
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        steps = dict(block.split("\n", 1) for block in workflow.split("      - name: ")[1:])
        names = list(steps)
        compiler = "Compile the fixed debug actual-main observer and normal embedded frontend once"
        p2 = "One project-field Aqua journey through the reviewed original invocation owner"
        android = "One Android-input Aqua journey through the reviewed original invocation owner"
        self.assertLess(names.index(compiler), names.index(p2))
        self.assertLess(names.index(p2), names.index(android))
        build = steps[compiler]
        self.assertEqual(build.count("cargo test --locked"), 1)
        self.assertEqual(build.count("npm run build"), 1)
        recorded = 'printf \'%s\\n\' "$status" > "$MRK_MACOS_WORK/observer-build.status"'
        rejected = 'if [[ "$status" != 0 ]]; then'
        self.assertLess(build.index(recorded), build.index(rejected))
        self.assertLess(build.index(rejected), build.index('exit "$status"'))
        self.assertLess(build.index('exit "$status"'), build.index("<<'PY_BUILD'"))
        self.assertNotEqual(BINDING.root(project_fields=True), BINDING.root())
        self.assertEqual(M.case_timeout("project-fields"), 60)
        self.assertEqual(M.case_timeout("android-inputs"), 60)
        for name, scope, prefix in ((p2, "project-fields", "aqua-project-fields"),
                                     (android, "android-inputs", "aqua-android-inputs")):
            step = steps[name]
            self.assertIn("timeout-minutes: 3", step)
            self.assertIn("if: success() && (env.MRK_MACOS_AQUA_SCOPE == " + repr(scope)
                          + " || env.MRK_MACOS_AQUA_SCOPE == 'project-fields-android-inputs')", step)
            self.assertEqual(step.count("macos_aqua_qualification.py --scope " + scope), 1)
            for forbidden in ("continue-on-error", "|| true", "--timeout", "rm -"):
                self.assertNotIn(forbidden, step)
            self.assertIn('"$MRK_MACOS_WORK/' + prefix + '.status"', step)
        binding = steps["Record exact source and actual tool bindings only after route admission"]
        script = binding.split("<<'PY'\n", 1)[1].rsplit("\n          PY", 1)[0]
        tree = ast.parse(textwrap.dedent(script))
        tables = [node for node in tree.body if isinstance(node, ast.Assign)
                  and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                  and node.targets[0].id == "scope_cases"]
        self.assertEqual(len(tables), 1)
        cases = ast.literal_eval(tables[0].value)
        self.assertEqual(set(cases), {"project-fields", "android-inputs", "ios-current-synthetic", "project-fields-android-inputs"})
        self.assertEqual(cases["project-fields-android-inputs"][1], ["project-fields", "android-inputs"])
        selection = 'selected_scopes = ["project-fields", "android-inputs"] if aqua_scope == "project-fields-android-inputs" else [aqua_scope]'
        diagnostic = steps["Export bounded diagnostics without altering original command evidence"]
        for step in (binding, diagnostic):
            self.assertIn(selection, step)
            self.assertIn('"unselectedScopes": [scope for scope in native_scopes if scope not in selected_scopes]', step)
        xcode = steps["Prepare only the fixed disposable Xcode ancestor before any worker"]
        self.assertEqual([line.strip() for line in xcode.splitlines() if line.strip().startswith("if:")],
                         ["if: success() && env.MRK_MACOS_AQUA_SCOPE == 'ios-current-synthetic'"])


class BeforeItemStopWorkflowTests(unittest.TestCase):
    """Closed DATA models only; never native receipts, fixture actions or CI passes."""

    @staticmethod
    def functions():
        import ast
        import re
        import textwrap
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        body = workflow.split("<<'PY_WRAPPING'\n", 1)[1].split("\n          PY_WRAPPING", 1)[0]
        module = ast.parse(textwrap.dedent(body))
        names = {"pairs", "parse", "exact_keys", "ints", "settled_raw", "cohort_profile",
                 "admit_before_item_terminal", "public_report", "admit_native_report"}
        bindings = {"name", "creator_entry", "case_names", "native_cohorts"}
        selected = []
        for node in module.body:
            if isinstance(node, ast.FunctionDef) and node.name in names:
                selected.append(node)
            elif (isinstance(node, ast.Assign) and len(node.targets) == 1
                  and isinstance(node.targets[0], ast.Name) and node.targets[0].id in bindings):
                # These are source-fixed literal/tuple references, not executable
                # workflow preparation or a native invocation.
                if any(not isinstance(child, (ast.Tuple, ast.Constant, ast.Name, ast.Load))
                       for child in ast.walk(node.value)):
                    raise AssertionError("private profile must remain literal DATA")
                selected.append(node)
        if {node.name for node in selected if isinstance(node, ast.FunctionDef)} != names:
            raise AssertionError("exact pure validator functions required")
        namespace = {"json": json, "re": re}
        exec(compile(ast.Module(body=selected, type_ignores=[]), "<private-report-DATA-only>", "exec"), namespace)
        return namespace

    @staticmethod
    def terminal_model(terminal):
        """Small deliberately modelled DTO, not observed Security/CF/FD output."""
        phase, operation = (10, 1) if terminal == "StopBeforeAdd" else (11, 2)
        calls = [[value, 1, 1, 0] for value in ((4, 5, 6, 8, 9) if operation == 1 else (4, 5, 6))]
        raw = {
            "header": [2, operation, 14, 0, 16, phase, 229, 0, 3, 2, len(calls), 0, 1, 1, 6, 3, 3, 3],
            "references": [[1, 1, 1, 1, 1, 1], [1, 0, 0, 0, 0, 0]], "calls": calls,
            "descriptors": [[1, 1, 1, 1, 0, 1, 1, 1, 0, 0] for _ in range(4)]
                           + [[1, 0, 0, 0, 0, 0, 0, 0, 0, 0] for _ in range(2)],
            "acl": [7, 7, 7, 0, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            "native": [1, 1, 3, 1, 0, 0, 0, 0, 0],
        }
        case = {"case": terminal, "raw": raw, "selection": [1, 1, 1, 1, 0, 1],
                "acknowledged": False, "scopedValuePresent": False, "comparison": None,
                "comparisonRefused": False, "frameRetired": True, "retainedNativeBytes": 0,
                "expected": True, "nativeReturned": True, "verified": True, "settled": True}
        action = [1, 1, 1, 1, 0, phase, 0, 0, 0]
        caller = {"terminalHarnessHalted": True, "terminalHarnessInvocations": 14,
                  "retirementAdmitted": True, "stopRequested": True}
        return case, action, caller

    def test_terminal_variants_preserve_fixed_roster_and_finality(self):
        import re
        native = PATH.parents[2] / "desktop/native/macos-installed-native/src"
        qualification = (native / "wrapping_keychain_qualification.rs").read_text()
        fixture = (native / "wrapping_keychain_fixture.rs").read_text()
        c = (native / "wrapping_keychain.m").read_text()
        roster = qualification.split("pub const CALL_ROSTER:", 1)[1].split("const _: ()", 1)[0]
        expected = list(self.functions()["case_names"])
        self.assertEqual(re.findall(r"Case::([A-Za-z]+)", roster), expected)
        for value in ("MAX_ADAPTER_INVOCATIONS: usize = 16", "HELPER_SHAPE_CHECKS: u32 = 20",
                      "HELPER_CF_ORIGINALS: u32 = 12"):
            self.assertIn(value, qualification)
        for value in ("const ACTIONS: usize = 17;", "const COHORT_SECONDS: u64 = 45;",
                      "const CALLER_OWNED_CHARGE_LIMIT: usize = 2 * 1024 * 1024;",
                      "const PUBLIC_OUTPUT_LIMIT: usize = 128 * 1024;"):
            self.assertIn(value, fixture)
        call = c.split("static MRKWrappingCall *mrk_w_call(", 1)[1].split("static void mrk_w_return(", 1)[0]
        self.assertLess(call.index("s->result.phase = phase"), call.index("mrk_w_admit(s, MRK_W_BEFORE_CALL)"))
        self.assertLess(call.index("mrk_w_admit(s, MRK_W_BEFORE_CALL)"), call.index("call->entered = 1"))
        callback = fixture.split("let mut admission = |checkpoint: Checkpoint, facts: &Facts|", 1)[1].split("let key =", 1)[0]
        self.assertIn("checkpoint == Checkpoint::BeforeCall && facts.phase() == Some(phase)", callback)
        self.assertLess(callback.index("stop.observe_before_item("), callback.index("clock.request_terminal_stop()"))
        self.assertIn("if case.terminal_stop()", fixture)
        self.assertIn("return self.clock.stop_requested && self.harness.as_ref().is_some_and(Harness::halted)", fixture)
        self.assertIn("!self.acknowledged[..13].iter().all(|v| *v) || self.acknowledged[13]", fixture)
        self.assertIn("!self.cases.iter().all(adapter_settled)", fixture)
        self.assertIn("self.retirement_admitted = true;", fixture)
        self.assertIn("!self.action(Action::Retire, true)", fixture)
        self.assertIn("!self.fixture.retire_allocation()", fixture)
        self.assertEqual(fixture.count("static CLAIMED: AtomicBool"), 1)
        self.assertEqual(fixture.count("static ORIGINAL: AtomicPtr<ManuallyDrop<Cohort>>"), 1)
        fallback = fixture.split("let fallback: &[u8] = match self.terminal {", 1)[1].split("\n        };", 1)[0]
        for scope in ("wrapping-private-common-cohort", "wrapping-private-stop-before-add", "wrapping-private-stop-before-lookup"):
            self.assertEqual(fallback.count(scope), 1)
        self.assertEqual(fallback.count('reportUnavailable\\\":true'), 3)
        for name, terminal in (("private_keychain_cohort", "StopAfterAdd"),
                               ("private_keychain_stop_before_add", "StopBeforeAdd"),
                               ("private_keychain_stop_before_lookup", "StopBeforeLookup")):
            entry = fixture.split("fn " + name + "() {", 1)[1].split("\n}", 1)[0]
            self.assertTrue(entry.lstrip().startswith("let entry = Instant::now();"))
            self.assertIn("run_registered_cohort(entry, Case::" + terminal + ")", entry)
        # Report success is still gated by actual write/flush and the same cutoff.
        for condition in ("cohort.report_written.returned && cohort.report_written.actual == 1",
                          "cohort.report_flushed.returned && cohort.report_flushed.actual == 1 && cohort.clock.live()"):
            self.assertIn(condition, fixture)

    def test_before_item_validator_rejects_effect_or_custody_substitution(self):
        check = self.functions()["admit_before_item_terminal"]
        mutations = [
            ("after-call-not-before", lambda c, a, o: a.__setitem__(4, 1)),
            ("wrong-phase", lambda c, a, o: a.__setitem__(5, 11 if a[5] == 10 else 10)),
            ("invented-add-return", lambda c, a, o: a.__setitem__(6, 1)),
            ("invented-effect", lambda c, a, o: a.__setitem__(8, 1)),
            ("raw-effect", lambda c, a, o: c["raw"]["header"].__setitem__(3, 1)),
            ("stop-not-observed", lambda c, a, o: c["raw"]["header"].__setitem__(6, 225)),
            ("key-bytes", lambda c, a, o: c["raw"]["header"].__setitem__(11, 32)),
            ("item-was-entered", lambda c, a, o: c["raw"]["calls"][0].__setitem__(0, a[5])),
            ("candidate", lambda c, a, o: c.__setitem__("scopedValuePresent", True)),
            ("acknowledged", lambda c, a, o: c.__setitem__("acknowledged", True)),
            ("frame-still-retained", lambda c, a, o: c.__setitem__("retainedNativeBytes", 1)),
            ("frame-not-retired", lambda c, a, o: c.__setitem__("frameRetired", False)),
            ("cf-not-released", lambda c, a, o: c["raw"]["references"][0].__setitem__(5, 0)),
            ("fd-not-closed", lambda c, a, o: c["raw"]["descriptors"][0].__setitem__(7, 0)),
            ("acl-not-settled", lambda c, a, o: c["raw"]["acl"].__setitem__(8, 6)),
            ("harness-not-halted", lambda c, a, o: o.__setitem__("terminalHarnessHalted", False)),
            ("wrong-invocation-count", lambda c, a, o: o.__setitem__("terminalHarnessInvocations", 13)),
            ("retirement-not-admitted", lambda c, a, o: o.__setitem__("retirementAdmitted", False)),
            ("stop-not-requested", lambda c, a, o: o.__setitem__("stopRequested", False)),
        ]
        for terminal in ("StopBeforeAdd", "StopBeforeLookup"):
            model = self.terminal_model(terminal)
            self.assertIsNone(check(*model))  # DATA validation only, never native acceptance.
            for label, mutate in mutations:
                with self.subTest(terminal=terminal, mutation=label):
                    changed = deepcopy(model)
                    mutate(*changed)
                    with self.assertRaises(ValueError):
                        check(*changed)

    def test_partial_public_reports_are_closed_and_not_native_acceptance(self):
        functions = self.functions()
        owed = ["native-exception", "returned-failed-close", "incomplete-acl", "unforced-native-bounds",
                "before-item-stop", "second-executable-creator", "uifail-no-prompt-denial"]
        for entry, scope, terminal, _ in functions["native_cohorts"]:
            partial = {"schemaVersion": 1, "scope": scope, "provisional": True, "outerFinalityRequired": True,
                       "reportUnavailable": True, "cases": [{"case": terminal}], "owed": owed}
            def capture(value):
                stdout = ("running 1 test\nMRK_WRAPPING_PRIVATE_RESULT=" + json.dumps(value) + "\n"
                          + "test " + entry + " ... ok\n"
                          + "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s\n").encode()
                return CompletedProcess(["inert-model-only"], 0, stdout, b"")
            self.assertEqual(functions["public_report"](capture(partial), entry), partial)
            with self.assertRaises(ValueError):
                functions["admit_native_report"](capture(partial), entry)
            for mutated in (dict(partial, scope="INERT_NONPUBLIC_TEXT"),
                            dict(partial, password="INERT_NONPUBLIC_TEXT"),
                            dict(partial, cases=[{"case": "INERT_NONPUBLIC_TEXT"}])):
                with self.assertRaises(ValueError):
                    functions["public_report"](capture(mutated), entry)
            with self.assertRaises(ValueError):
                functions["public_report"](capture(partial), "unregistered-entry")

    def test_one_binary_has_three_fixed_original_entries_and_public_outputs(self):
        functions = self.functions()
        cohorts = functions["native_cohorts"]
        self.assertEqual(len(cohorts), 3)
        self.assertEqual([row[2] for row in cohorts], ["StopAfterAdd", "StopBeforeAdd", "StopBeforeLookup"])
        self.assertEqual(len({row[0] for row in cohorts}), 3)
        self.assertEqual(len({row[3] for row in cohorts}), 3)
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        private = workflow.split("      - name: Compile native wrapping variants once and run fixed cohorts and creator-reader pair\n", 1)[1].split("      - name: ", 1)[0]
        self.assertEqual(private.count('argv = ["cargo", "test", "--locked"'), 1)
        self.assertIn('owner = qualification.load_owner(checkout)', private)
        self.assertIn('for cohort in receipt["nativeCohorts"]:', private)
        self.assertIn('result, row = invoke(cohort["reportPrefix"], [str(qualification_binary["path"]), "--exact", entry,', private)
        self.assertIn('environ=native_env, cwd=work, timeout=90, limit=256 * 1024)', private)
        self.assertIn('sorted([entry + ": test" for entry, _, _, _ in native_cohorts] + [creator_entry + ": test"]) if role == "qualification" else []', private)
        self.assertIn('if observed != (fixture_symbols if role == "qualification" else set()):', private)
        self.assertIn('receipt["nativeReportAdmitted"] = all(row["reportAdmitted"] for row in receipt["nativeCohorts"])', private)
        self.assertLess(private.index('admit_native_report(result, entry)'), private.index('cohort["reportAdmitted"] = True'))
        upload = workflow.split("      - name: Preserve bounded private-cohort public facts and compiler-only diagnostics\n", 1)[1]
        for _, _, _, prefix in cohorts:
            self.assertEqual(upload.count("${{ steps.work.outputs.root }}/" + prefix + ".report.json"), 1)
        for forbidden in ("*.json", "*.keychain", "wrapping-native.stdout", "wrapping-native.stderr"):
            self.assertNotIn(forbidden, upload)


class CreatorReaderUIFailDataTests(unittest.TestCase):
    """Focused labelled DATA/state models. No native process, thread or signing.

    These prove parser/latch/ownership routing, NOT macOS observations or CI.
    The actual native two-original pair remains a separately owned verification.
    """
    @staticmethod
    def functions(include_worker=False):
        import ast
        import hashlib
        import math
        import re
        import struct
        import textwrap
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        body = workflow.split("<<'PY_WRAPPING'\n", 1)[1].split("\n          PY_WRAPPING", 1)[0]
        tree = ast.parse(textwrap.dedent(body))
        names = {"pairs", "parse", "exact_keys", "ints", "settled_raw", "record_bytes", "owner_budget", "launch_admitted",
                 "acknowledge_admitted", "pair_finality", "admit_peer_case", "admit_controls", "public_reader_report",
                 "admit_reader_report", "signature_identity", "distinct_code_identities"}
        if include_worker: names.add("creator_worker")
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        if len(nodes) != len(names): raise AssertionError("fixed pair functions missing or duplicated")
        namespace = {"json": json, "math": math, "hashlib": hashlib, "re": re, "struct": struct,
                     "subprocess": SimpleNamespace(CompletedProcess=CompletedProcess),
                     "creator_identifier": "dev.mobile-release-kit.qualification.wrapping.creator",
                     "reader_identifier": "dev.mobile-release-kit.qualification.wrapping.reader"}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "<inert-pair-data-functions>", "exec"), namespace)
        return namespace

    @staticmethod
    def wire_data():
        import struct
        # Deliberately synthetic scalars; not filesystem/native observations.
        nonce, root = b"n" * 16, (7, 19, UID, GID)
        request = b"MRKQPR01" + struct.pack("<HHI", 1, 2, 0) + nonce + struct.pack("<QQII", *root) + bytes(8)
        ready = (b"MRKQPD01" + struct.pack("<HHI", 1, 1, 0) + nonce
                 + struct.pack("<IIQQIIII", 1, 56, 7, 23, 0o040700, UID, GID, 0)
                 + b"t" * 16 + b"v" * 16 + b"g" * 16 + bytes(8))
        ack = b"MRKQPA01" + struct.pack("<HHI", 1, 2, 0) + nonce + struct.pack("<I", 1) + bytes(12)
        return nonce, root, {"request": request, "ready": ready, "reader-settled": ack}

    def test_fixed_wire_rejects_partial_stale_replayed_wrong_role_and_reserved(self):
        functions = self.functions(); validate = functions["record_bytes"]
        nonce, root, records = self.wire_data()
        for kind, data in records.items():
            with self.subTest(kind=kind):
                self.assertEqual(validate(data, kind, nonce, root), data)
                for invalid in (data[:-1], data + b"\0", bytearray(data), data[:8] + b"\2\0" + data[10:],
                                data[:10] + b"\3\0" + data[12:], data[:12] + b"x" + data[13:],
                                data[:16] + bytes(16) + data[32:], data[:16] + b"z" * 16 + data[32:],
                                data[:-1] + b"x"):
                    with self.assertRaises(ValueError): validate(invalid, kind, nonce, root)
                with self.assertRaises(ValueError): validate(data, kind, b"q" * 16, root)
        with self.assertRaises(ValueError): validate(records["request"], "request", nonce, (7, 20, UID, GID))
        for at, count in ((48, 8), (60, 4), (72, 16), (88, 16), (104, 16)):
            data = bytearray(records["ready"]); data[at:at + count] = bytes(count)
            with self.assertRaises(ValueError): validate(bytes(data), "ready", nonce, root)
        data = records["ready"][:104] + records["ready"][88:104] + records["ready"][120:]
        with self.assertRaises(ValueError): validate(data, "ready", nonce, root)
        data = records["reader-settled"][:32] + bytes(4) + records["reader-settled"][36:]
        with self.assertRaises(ValueError): validate(data, "reader-settled", nonce, root)

    def test_original_endpoints_reserve_cleanup_and_never_renew(self):
        f = self.functions()
        self.assertEqual(f["launch_admitted"](False, 4.0, 5.0, 100.0), 90)
        self.assertEqual(f["owner_budget"](24.1, 35.0, 15), 7)
        for args in ((True, 1, 5, 100), (False, 5, 5, 100), (False, 7, 5, 100), (False, 1, 5, 4)):
            with self.assertRaises(ValueError): f["launch_admitted"](*args)
        for now in (31.1, 32, 35, float("inf"), float("nan")):
            with self.assertRaises(ValueError): f["owner_budget"](now, 35, 15)

    def test_actual_worker_rechecks_after_activation_and_restores_same_guard(self):
        # Execute only the extracted routing function with inert objects: no
        # threading.Thread, Process API, native import, signals, or time sleeps.
        for delayed, initially_aborted, owner_error in ((True, False, False), (False, True, False),
                                                        (False, False, True), (False, False, False)):
            with self.subTest(delayed=delayed, abort=initially_aborted, owner_error=owner_error):
                f = self.functions(include_worker=True); calls = []; now = [1.0]; latch = [initially_aborted]
                class Lock:
                    def __enter__(self): return self
                    def __exit__(self, *args): return False
                class Guard:
                    handler_state = "NOT_INSTALLED"
                    def __init__(self, *args): calls.append("guard-created")
                    def install(self): calls.append("install"); self.handler_state = "ACTIVE"
                    def activate(self):
                        calls.append("activate")
                        if delayed: now[0] = 6.0
                    def restore(self): calls.append("restore"); self.handler_state = "RESTORED"
                    def check(self): calls.append("check")
                def run_owned(*args, **kwargs):
                    calls.append("owner")
                    self.assertIsInstance(kwargs["cancellation"], Guard)
                    self.assertEqual(kwargs["timeout"], 90)
                    if owner_error: raise ValueError("inert owner failure")
                    return CompletedProcess(["inert-data-model"], 0, b"", b"")
                f.update(owner=SimpleNamespace(DefaultCancellation=Guard, ProcessCleanupError=ValueError, run_owned=run_owned),
                         time=SimpleNamespace(monotonic=lambda: now[0]), native_env={})
                holder = {key: False for key in ("bodyEntered", "bodyReturned", "ownerEntered", "ownerReturned",
                                                "guardInstalled", "guardActivated", "guardRestored", "guardChecked")}
                holder.update(result=None, errors=[], guardState="NOT_INSTALLED")
                abort = SimpleNamespace(is_set=lambda: latch[0], set=lambda: latch.__setitem__(0, True))
                f["creator_worker"](holder, Lock(), abort, ["inert-data-model"], Path("/not-executed"), 5.0, 100.0)
                self.assertEqual(calls[-2:], ["restore", "check"])
                self.assertTrue(holder["bodyReturned"])
                self.assertEqual(holder["guardState"], "RESTORED")
                self.assertEqual(calls.count("owner"), int(not delayed and not initially_aborted))
                self.assertEqual(holder["ownerReturned"], not (delayed or initially_aborted or owner_error))
                self.assertEqual(latch[0], delayed or initially_aborted or owner_error)

    def test_grant_and_finality_require_originals_and_preserve_possible_publication_failure(self):
        f = self.functions()
        grant = {"aborted": False, "readerOwnerReturned": True, "readerNativeAdmitted": True, "ackEntered": False}
        f["acknowledge_admitted"](grant, 20.0, 35.0)
        for key in grant:
            changed = dict(grant); changed[key] = not changed[key]
            with self.assertRaises(ValueError): f["acknowledge_admitted"](changed, 20.0, 35.0)
        with self.assertRaises(ValueError): f["acknowledge_admitted"](grant, 35.0, 35.0)
        required = "startAttempted startReturned joinAttempted joinReturned joined joinedBeforeDrain readyAdmitted readerOwnerReturned readerNativeAdmitted creatorNativeAdmitted ackEntered ackReturned ackMayHavePublished ackPublished controlRetired controlOriginalsClosed".split()
        settled = dict.fromkeys(required, True); settled.update(aborted=False, errors=[], ackResult=0, ackErrno=0)
        self.assertTrue(f["pair_finality"](settled))
        for key in required:
            changed = dict(settled); changed[key] = False
            self.assertFalse(f["pair_finality"](changed), key)
        for change in ({"aborted": True}, {"errors": ["inert-error"]}, {"ackResult": -1}, {"ackResult": False},
                       {"ackEntered": True, "ackMayHavePublished": True, "ackReturned": False},
                       {"creatorNativeAdmitted": True, "aborted": True}):
            self.assertFalse(f["pair_finality"](dict(settled, **change)))

    @staticmethod
    def lookup_data(reader):
        # Internally coherent parser DATA, deliberately NOT evidence from macOS.
        refs = [[1, 1, 1, 1, 1, 1] for _ in range(5 if reader else 7)]
        if reader: refs.append([1, 1, 1, 0, 0, 0])
        calls = [[4, 1, 1, 0], [5, 1, 1, 0], [6, 1, 1, 0], [11, 1, 1, -25308 if reader else 0]]
        if not reader: calls.append([12, 1, 1, 0])
        h = [2, 2, 6 if reader else 2, 0, 16, 11 if reader else 0, 1249 if reader else 1145, 0, 1,
             len(refs), len(calls), 0 if reader else 32, 1, 1, 6, 5, 5, 5]
        raw = {"header": h, "references": refs, "calls": calls,
               "descriptors": [[1, 1, 1, 1, 0, 1, 1, 1, 0, 0] for _ in range(6)],
               "acl": [11, 11, 11, 0, 11, 11, 11, 11, 11] + [0] * 12,
               "native": [121, 121, 21, 1, 0, 0, 0, 0, 0]}
        return {"nativeReturned": True, "verified": True, "retainedNativeBytes": 0, "frameRetired": reader,
                "scopedValuePresent": False, "selection": [1, 1, 1, 1, 0, 1],
                "comparison": None if reader else [1, 1, 1, 40960, 1], "raw": raw}

    def test_only_unlocked_actual_returned_interaction_denial_is_accepted(self):
        f = self.functions(); original = self.lookup_data(True)
        f["admit_peer_case"](original, True, 40960)
        for status in (0, -25300, -25293, -128, -25291):
            bad = deepcopy(original); bad["raw"]["calls"][-1][3] = status
            with self.assertRaises(ValueError): f["admit_peer_case"](bad, True, 40960)
        for index, value in ((2, 3), (2, 5), (2, 2), (3, 1), (6, 1253), (8, 0), (11, 32), (12, 0), (17, 4)):
            bad = deepcopy(original); bad["raw"]["header"][index] = value
            with self.assertRaises(ValueError): f["admit_peer_case"](bad, True, 40960)
        for section, index, field, value in (("calls", 3, 2, 0), ("calls", 3, 0, 10),
                                            ("references", 0, 5, 0), ("descriptors", 0, 7, 0)):
            bad = deepcopy(original); bad["raw"][section][index][field] = value
            with self.assertRaises(ValueError): f["admit_peer_case"](bad, True, 40960)
        for key, value in (("frameRetired", False), ("retainedNativeBytes", 40960), ("scopedValuePresent", True),
                           ("selection", [1, 1, 1, True, 0, 1]), ("comparison", [1] * 5)):
            bad = deepcopy(original); bad[key] = value
            with self.assertRaises(ValueError): f["admit_peer_case"](bad, True, 40960)
        creator = self.lookup_data(False); f["admit_peer_case"](creator, False, 40960)
        for field in range(5):
            bad = deepcopy(creator); bad["comparison"][field] = 0
            with self.assertRaises(ValueError): f["admit_peer_case"](bad, False, 40960)

    @staticmethod
    def control_data(role):
        # Closed state model, not a report claimed to have run the native book.
        h = [0] * 32; h[:10] = [1, 1912, role, 4, 0, 0, 0, 0, 1, 1]
        h[10:13] = [1, 0, 1] if role == 1 else [0, 1, 0]; h[13] = 1; h[20] = 6
        h[25:] = [40960, 1, 1, 1, 0, 0, 0]
        if role == 1: h[14:20] = [1, 1, 1, 1, 0, 0]; h[21:23] = [2, 2]
        fds = []
        for i in range(6):
            row = [0] * 26
            if role == 1 or i not in (2, 4):
                row[:4], row[17:20] = [1] * 4, [1] * 3
                if i in (1, 3, 4): row[5:8], row[22:24] = [1, 1, {1:64, 3:128, 4:48}[i]], [1, 1]
                if i == 2: row[9:17] = [1, 1, 128, 0, 1, 1, 0, 0]
            fds.append(row)
        steps = [[1,1,1,1,1], [2,1,1,1,1], [4,1,1,2,1], [4,1,1,1,1], [5,1,1,1,1]] if role == 1 else [[1,1,1,1,1], [3,1,1,1,1], [5,1,1,1,1]]
        return {"role": role, "bookBytes": 3504, "aclFrameBytes": 40960, "blocked": False, "uncertain": False, "complete": True,
                "retained": False, "callbackPanic": False, "allocation": [1,1,1], "free": [1,1,1], "steps": steps,
                "header": h, "fds": fds, "acl": [24,24,24,0,24,24,24,24,24] + [0] * 12,
                "native": [264,264,21,1,0,0,0,0,0], "io": [120,120,1,1,0,0,0,0,0],
                "roster": [1,1,1,0,1,6,6,24,24,6,0,0]}

    def test_control_records_require_exact_original_close_eof_acl_and_fixed_steps(self):
        f = self.functions()
        for role in (1, 2):
            original = self.control_data(role); f["admit_controls"](original, role)
            for section, field, value in (("header", 5, 1), ("header", 8, 0), ("header", 13, 0),
                                           ("acl", 8, 23), ("native", 1, 263), ("io", 1, 119),
                                           ("roster", 4, 0), ("roster", 9, 5), ("free", 1, 0)):
                bad = deepcopy(original); bad[section][field] = value
                with self.assertRaises(ValueError): f["admit_controls"](bad, role)
            for field, value in ((7, 63), (18, 0), (19, 0), (20, -1), (23, 0), (24, 1)):
                bad = deepcopy(original); bad["fds"][1][field] = value
                with self.assertRaises(ValueError): f["admit_controls"](bad, role)
            for field in (1, 2, 3, 4):
                bad = deepcopy(original); bad["steps"][-1][field] = 0
                with self.assertRaises(ValueError): f["admit_controls"](bad, role)
            for key, value in (("retained", True), ("blocked", True), ("uncertain", True), ("callbackPanic", True), ("bookBytes", 4097)):
                bad = deepcopy(original); bad[key] = value
                with self.assertRaises(ValueError): f["admit_controls"](bad, role)

    def test_uncertain_original_has_absorbing_no_next_native_entry_gates(self):
        # Source DATA checks of the actual guards, not a fake pointer/FFI run.
        # Mutated scalar reports are tested by the existing control matrix.
        pair = (PATH.parents[2] / "desktop/native/macos-installed-native/src/wrapping_keychain_pair.rs").read_text()
        step = pair.split("    fn step<", 1)[1].split("    pub(super) fn initialize", 1)[0]
        self.assertIn("if self.uncertain || self.pointer.is_none()", step)
        self.assertLess(step.index("if self.uncertain"), step.index("self.calls[index] ="))
        self.assertLess(step.index("if self.uncertain"), step.index("mrk_wrapping_pair_step("))
        self.assertIn("if !valid || self.raw.header[5] != 0 || self.raw.header[7] != 0 { self.uncertain = true; }", step)
        self.assertIn("self.blocked && action != 5", step)  # Valid known refusal may close once.
        finish = pair.split("    pub(super) fn finish<", 1)[1].split("    pub(super) fn complete", 1)[0]
        self.assertIn("if self.uncertain || self.finish_spent", finish)
        self.assertLess(finish.index("if self.uncertain"), finish.index("self.finish_spent = true"))
        after_cleanup = finish.split("let _actual = self.step(5, None, None, admission);", 1)[1]
        self.assertIn("if self.uncertain || !self.raw.valid", after_cleanup)
        self.assertLess(after_cleanup.index("if self.uncertain"), after_cleanup.index("self.free[0] = 1"))
        self.assertLess(after_cleanup.index("if self.uncertain"), after_cleanup.index("mrk_wrapping_pair_free("))
        self.assertIn("!self.uncertain && !self.blocked && actual_controls", pair)
        self.assertEqual(pair.count("self.uncertain = true"), 1)
        self.assertNotIn("self.uncertain = false", pair)

    def test_reader_public_failure_preserves_status_without_exporting_private_text(self):
        f = self.functions()
        partial = {"schemaVersion": 1, "scope": "wrapping-other-executable-reader", "provisional": True,
                   "outerFinalityRequired": True, "reportUnavailable": True, "lookup": self.lookup_data(True)}
        def captured(value): return CompletedProcess(["inert-data-only"], 101,
            b"MRK_WRAPPING_PEER_RESULT=" + json.dumps(value).encode() + b"\n", b"private stderr NOT exported")
        self.assertEqual(f["public_reader_report"](captured(partial)), partial)
        with self.assertRaises(ValueError): f["admit_reader_report"](captured(partial))
        for value in (dict(partial, path="INERT_PRIVATE_TEXT"), dict(partial, scope="INERT_PRIVATE_TEXT"),
                      dict(partial, lookup={"raw": {"header": ["INERT_PRIVATE_TEXT"]}})):
            with self.assertRaises(ValueError): f["public_reader_report"](captured(value))

    def test_distinct_actual_code_identities_not_different_path_spelling(self):
        f = self.functions()
        creator = {"identifier": f["creator_identifier"], "cdhash": "a" * 40, "requirementSha256": "b" * 64, "fileSha256": "c" * 64}
        reader = {"identifier": f["reader_identifier"], "cdhash": "d" * 40, "requirementSha256": "e" * 64, "fileSha256": "f" * 64}
        f["distinct_code_identities"](creator, reader)
        for field in creator:
            bad = dict(reader); bad[field] = creator[field]
            with self.assertRaises(ValueError): f["distinct_code_identities"](creator, bad)
        display = CompletedProcess(["inert-codesign-data"], 0, b'designated => cdhash H"' + b"a" * 40 + b'"\n',
            ("Identifier=" + f["creator_identifier"] + "\nCDHash=" + "a" * 40 + "\nSignature=adhoc\n").encode())
        self.assertEqual(f["signature_identity"](display, f["creator_identifier"], {})["cdhash"], "a" * 40)
        for invalid in (CompletedProcess([], 1, display.stdout, display.stderr),
                        CompletedProcess([], 0, display.stdout * 2, display.stderr),
                        CompletedProcess([], 0, display.stdout, display.stderr.replace(b"Signature=adhoc", b"Signature=unknown"))):
            with self.assertRaises(ValueError): f["signature_identity"](invalid, f["creator_identifier"], {})

    def test_codesign_designated_forms_preserve_identity_and_closed_refusal_diagnostics(self):
        # Synthetic codesign display DATA, not recovered native output or signing.
        f = self.functions(); identify = f["signature_identity"]; identifier = f["creator_identifier"]
        requirement = b'cdhash H"' + b"a" * 40 + b'"'
        explicit = b"designated => " + requirement + b"\n"
        implicit = b"\n# designated => " + requirement + b"\n\n"
        details = ("Identifier=" + identifier + "\nCDHash=" + "a" * 40 + "\nSignature=adhoc\n").encode()
        boolean_fields = {"originalAdmitted", "asciiDecoded", "identifierMatches", "cdhashValid", "requirementSingleton",
                          "requirementBodyValid", "signatureSingletonAdHoc", "admitted"}
        count_fields = {"identifierCount", "cdhashCount", "explicitRequirementCount", "implicitRequirementCount",
                        "requirementCount", "signatureCount", "adHocSignatureCount"}

        def assert_facts(facts, reason):
            self.assertEqual(set(facts), boolean_fields | count_fields | {"reason"})
            for key in boolean_fields: self.assertIs(type(facts[key]), bool)
            for key in count_fields:
                self.assertIs(type(facts[key]), int); self.assertGreaterEqual(facts[key], 0)
                self.assertLessEqual(facts[key], 16384)
            self.assertEqual(facts["reason"], reason)
            self.assertIs(facts["admitted"], reason == "accepted")
            self.assertNotIn("INERT_PRIVATE", json.dumps(facts))

        identities = []
        for body, counts in ((explicit, (1, 0)), (implicit, (0, 1))):
            facts = {}; display = CompletedProcess([], 0, body, details + b"Executable=/INERT_PRIVATE/path\n")
            identities.append(identify(display, identifier, facts)); assert_facts(facts, "accepted")
            self.assertEqual((facts["explicitRequirementCount"], facts["implicitRequirementCount"]), counts)
            self.assertEqual(facts["requirementCount"], 1)
        self.assertEqual(identities[0], identities[1])
        self.assertEqual(identities[0]["requirementSha256"], f["hashlib"].sha256(requirement).hexdigest())

        cases = [
            (CompletedProcess([], False, explicit, details), "original"),
            (CompletedProcess([], 0, explicit, details + b"x" * 16384), "original"),
            (CompletedProcess([], 0, explicit + b"\xff", details), "ascii"),
            (CompletedProcess([], 0, b"", details), "requirement-count"),
            (CompletedProcess([], 0, implicit + explicit, details), "requirement-count"),
            (CompletedProcess([], 0, implicit * 2, details), "requirement-count"),
            (CompletedProcess([], 0, b"#designated => " + requirement, details), "requirement-count"),
            (CompletedProcess([], 0, b"# designated => \n", details), "requirement-body"),
            (CompletedProcess([], 0, b"# designated => " + b"x" * 2049, details), "requirement-body"),
            (CompletedProcess([], 0, explicit.replace(b' H"', b'\r H"'), details), "requirement-body"),
            (CompletedProcess([], 0, explicit.replace(b' H"', b'\t H"'), details), "requirement-body"),
            (CompletedProcess([], 0, explicit, details.replace(identifier.encode(), b"INERT_PRIVATE_WRONG")), "identifier"),
            (CompletedProcess([], 0, explicit, details + ("Identifier=" + identifier + "\n").encode()), "identifier"),
            (CompletedProcess([], 0, explicit, details.replace(b"a" * 40, b"A" * 40)), "cdhash"),
            (CompletedProcess([], 0, explicit, details + b"CDHash=" + b"a" * 40 + b"\n"), "cdhash"),
            (CompletedProcess([], 0, explicit, details + b"Signature=INERT_PRIVATE_UNKNOWN\n"), "signature"),
            (CompletedProcess([], 0, explicit, details + b"Signature=adhoc\n"), "signature"),
        ]
        for display, reason in cases:
            with self.subTest(reason=reason, stdout_bytes=len(display.stdout)):
                facts = {}
                with self.assertRaises(ValueError): identify(display, identifier, facts)
                assert_facts(facts, reason)
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        self.assertIn('row["identityAdmission"] = identity_facts', workflow)
        self.assertLess(workflow.index('row["identityAdmission"] = identity_facts'),
                        workflow.index('identities.append(signature_identity(result, identifier, identity_facts))'))

    def test_source_fixed_profile_barrier_charges_and_no_candidate_reader(self):
        root = PATH.parents[2]; native = root / "desktop/native/macos-installed-native"
        fixture = (native / "src/wrapping_keychain_fixture.rs").read_text()
        dispatcher = (native / "src/wrapping_keychain_qualification.rs").read_text()
        pair = (native / "src/wrapping_keychain_pair.rs").read_text()
        control = (native / "src/wrapping_keychain_fixture.m").read_text().split("// Fixed creator/reader control book only.", 1)[1]
        workflow = (root / ".github/workflows/desktop-macos-aqua.yml").read_text()
        self.assertIn("CALL_ROSTER: [Case; 14]", dispatcher)
        self.assertIn("MAX_ADAPTER_INVOCATIONS: usize = 16", dispatcher)
        self.assertIn("Original::Data(finish_without_key(returned, None))", dispatcher)
        self.assertIn("(14 + usize::from(self.pair_enabled)) * adapter_bytes", fixture)
        self.assertIn("self.control_bytes, self.control_acl_bytes", fixture)
        self.assertIn("CALLER_OWNED_CHARGE_LIMIT: usize = 2 * 1024 * 1024", fixture)
        run = fixture.split("    fn run(&mut self) -> bool {", 1)[1].split("// Every string emitted", 1)[0]
        self.assertLess(run.index("self.action(action, false)"), run.index("self.creator_barrier()"))
        self.assertLess(run.index("self.creator_barrier()"), run.index("self.case(case)"))
        self.assertLess(run.index("!self.controls.complete()"), run.index("self.action(Action::Retire, true)"))
        self.assertIn("COHORT_SECONDS: u64 = 45", fixture)
        self.assertIn("READER_SECONDS: u64 = 10", pair)
        self.assertIn("POLLS: usize = 128", pair)
        self.assertIn("_Static_assert(sizeof(MRKQPair) <= 4096", control)
        self.assertIn("_Static_assert(errSecInteractionNotAllowed == -25308", control)
        self.assertIn("_Static_assert(RENAME_EXCL == 0x00000004", control)
        self.assertIn("mrk_w_acl_snapshot", control)
        self.assertIn("fdopendir", control); self.assertIn("closedir", control)
        for forbidden in ("SecKeychainCreate", "SecItemAdd", "SecKeychainDelete", "SecKeychainUnlock", "SecKeychainLock", "CFRelease"):
            self.assertNotIn(forbidden, control)
        self.assertIn('name = "wrapping_peer_reader"', (native / "Cargo.toml").read_text())
        self.assertIn('test = false', (native / "Cargo.toml").read_text())
        self.assertIn('compile_error!', (native / "examples/wrapping_peer_reader.rs").read_text())
        body = workflow.split("<<'PY_WRAPPING'\n", 1)[1].split("\n          PY_WRAPPING", 1)[0]
        self.assertLess(body.index('invoke("reader-build"'), body.index('cells = [admit_file(out / "libmrk'))
        self.assertLess(body.index('code_role + "-adhoc-sign"'), body.index('cells = [admit_file(out / "libmrk'))
        self.assertIn('ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)', body)
        self.assertIn('worker.join(max(0, drain_end - time.monotonic()))', body)
        self.assertIn('acknowledge_admitted(pair, time.monotonic(), forward_end)', body)
        self.assertIn('pair["ackMayHavePublished"] = True', body)
        self.assertNotIn('abort.clear', body)
        for forbidden in ('Popen(', 'threading.Timer(', 'os.kill(', 'killpg(', 'os.rename(', 'os.replace(', 'find_library('):
            self.assertNotIn(forbidden, body)
        upload = workflow.split("      - name: Preserve bounded private-cohort public facts and compiler-only diagnostics\n", 1)[1]
        for leaf in ("wrapping-creator.report.json", "wrapping-reader.report.json", "wrapping-pair.receipt.json"):
            self.assertEqual(upload.count("${{ steps.work.outputs.root }}/" + leaf), 1)
        for forbidden in ("wrapping-pair-control", "reader-settled", "*.json", ".keychain", "wrapping-reader.stdout", "wrapping-reader.stderr"):
            self.assertNotIn(forbidden, upload)


class PrivateCodecWorkflowDataTests(unittest.TestCase):
    """Focused synthetic DATA only; never a native/Mac/compiler pass."""

    @staticmethod
    def functions():
        import ast
        import hashlib
        import pathlib
        import re
        import textwrap
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        body = workflow.split("<<'PY_WRAPPING'\n", 1)[1].split("\n          PY_WRAPPING", 1)[0]
        tree = ast.parse(textwrap.dedent(body))
        names = {"pairs", "parse", "admit_codec_compiler", "admit_codec_results", "codec_original_settled",
                 "codec_originals_succeeded", "private_batch_finality", "public_codec_receipt"}
        bindings = {"codec_names", "artifact_roles"}
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        if len(nodes) != len(names): raise AssertionError("fixed codec DATA functions missing or duplicated")
        namespace = {"json": json, "hashlib": hashlib, "pathlib": pathlib, "re": re,
                     "subprocess": SimpleNamespace(CompletedProcess=CompletedProcess),
                     "work": Path("/inert-private-work"), "app": Path("/inert-checkout/desktop/src-tauri"),
                     "codec_library": "mobile_release_desktop"}
        for name in bindings:
            matching = [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                        and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
            if len(matching) != 1: raise AssertionError("fixed codec literal binding")
            namespace[name] = ast.literal_eval(matching[0].value)
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "<inert-codec-data-functions>", "exec"), namespace)
        return namespace

    def test_codec_exact_fifteen_successes_refuse_missing_extra_failed_or_ignored(self):
        f = self.functions(); names = f["codec_names"]
        self.assertEqual(len(names), 15)
        self.assertEqual(sum(name.startswith("vault_crypto::tests::") for name in names), 9)
        self.assertEqual(sum(name.startswith("vault_format::tests::") for name in names), 6)
        lines = ["running 15 tests", *("test " + name + " ... ok" for name in names),
                 "test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 291 filtered out; finished in 0.01s"]
        def original(rows, code=0, stderr=b""):
            return CompletedProcess(["inert-codec-data-only"], code, ("\n".join(rows) + "\n").encode(), stderr)
        check = f["admit_codec_results"]
        self.assertEqual(check(original(lines)), {"testsPassed": True, "tests": 15, "failed": 0, "ignored": 0, "measured": 0, "filtered": 291})
        self.assertEqual(check(original([lines[0], *reversed(lines[1:-1]), lines[-1]]))["tests"], 15)
        invalid = [original(lines, 101), original(lines, False), original(lines, stderr=b"unpublished-diagnostic"),
                   original(lines[:3] + lines[4:]), original(lines[:-1] + ["test unexpected ... ok", lines[-1]]),
                   original(lines[:2] + [lines[1]] + lines[3:]), original(["running 14 tests", *lines[1:]]),
                   original(lines[:-1] + [lines[-1].replace("0 ignored", "1 ignored")]),
                   original(lines[:-1] + [lines[-1].replace("0 failed", "1 failed")]),
                   original(lines[:-1] + [lines[-1].replace("0 measured", "1 measured")]),
                   original(lines[:1] + [lines[1].replace(" ... ok", " ... FAILED")] + lines[2:]),
                   original(lines[:1] + [lines[1].replace(names[0], "vault_store::tests::unselected")] + lines[2:]),
                   CompletedProcess([], 0, b"x" * (64 * 1024 + 1), b"")]
        for index, result in enumerate(invalid):
            with self.subTest(mutation=index), self.assertRaises(ValueError): check(result)

    def test_codec_compiler_requires_exact_app_empty_features_debug_libtest_and_one_artifact(self):
        f = self.functions(); app, work = f["app"], f["work"]
        binary = work / "wrapping-codec-target/aarch64-apple-darwin/debug/deps/mobile_release_desktop-0123456789abcdef"
        artifact = {"reason": "compiler-artifact", "package_id": "path+" + app.as_uri() + "#mobile-release-kit-desktop@0.1.0",
                    "manifest_path": str(app / "Cargo.toml"), "features": [], "executable": str(binary), "filenames": [str(binary)],
                    "target": {"name": "mobile_release_desktop", "kind": ["lib"], "crate_types": ["lib"], "src_path": str(app / "src/lib.rs")},
                    "profile": {"test": True, "debug_assertions": True, "overflow_checks": True, "opt_level": "0"}}
        def captured(rows, code=0): return CompletedProcess(["inert-cargo-json-data"], code,
            b"\n".join(json.dumps(row).encode() for row in rows) + b"\n", b"compiler DATA")
        finish = {"reason": "build-finished", "success": True}
        check = f["admit_codec_compiler"]
        self.assertEqual(check(captured([artifact, finish])), binary)
        mutations = [lambda a: a.__setitem__("package_id", "path+file:///different#mobile-release-kit-desktop@0.1.0"),
                     lambda a: a.__setitem__("manifest_path", str(app.parent / "Cargo.toml")),
                     lambda a: a.__setitem__("features", ["macos-installed-observation"]),
                     lambda a: a["target"].__setitem__("name", "mrk_macos_installed_native"),
                     lambda a: a["target"].__setitem__("kind", ["bin"]),
                     lambda a: a["target"].__setitem__("src_path", str(app / "src/main.rs")),
                     lambda a: a["profile"].__setitem__("test", False),
                     lambda a: a["profile"].__setitem__("debug_assertions", False),
                     lambda a: a["profile"].__setitem__("overflow_checks", False),
                     lambda a: a["profile"].__setitem__("opt_level", "3"),
                     lambda a: a.__setitem__("executable", str(work / "wrapping-qualification-target/debug/test")),
                     lambda a: a.__setitem__("filenames", [str(binary), "unexpected"])]
        for index, mutate in enumerate(mutations):
            changed = deepcopy(artifact); mutate(changed)
            with self.subTest(mutation=index), self.assertRaises(ValueError): check(captured([changed, finish]))
        for rows, code in (([finish], 0), ([artifact, artifact, finish], 0), ([artifact], 0),
                           ([artifact, finish, finish], 0), ([artifact, dict(finish, success=False)], 0),
                           ([artifact, dict(finish, success=1)], 0), ([artifact, finish], False), ([artifact, finish], 101)):
            with self.subTest(rows=len(rows), code=code), self.assertRaises(ValueError): check(captured(rows, code))

    def test_codec_failure_unknown_original_and_each_of_nine_closes_gate_batch_finality(self):
        f = self.functions()
        receipt = {"calls": [{"role": "codec-build", "returned": True, "returncode": 0},
                             {"role": "codec-tests", "returned": True, "returncode": 0}], "nativeOriginalReturned": True,
                   "nativeReportAdmitted": True, "pair": {"passed": True}, "pairNativeObservationsAdmitted": True}
        codec = {"compilerAdmitted": True, "testsPassed": True, "artifactHashRechecked": True, "syntheticDirectoriesRetired": True}
        cells = [{"role": role, "unchanged": True, "closed": True} for role in f["artifact_roles"]]
        check = f["private_batch_finality"]
        self.assertTrue(check(receipt, codec, cells, [], []))
        for key in codec:
            with self.subTest(codec=key): self.assertFalse(check(receipt, dict(codec, **{key: False}), cells, [], []))
        for index, cell in enumerate(cells):
            for key in ("unchanged", "closed"):
                changed = deepcopy(cells); changed[index][key] = False
                with self.subTest(role=cell["role"], finality=key): self.assertFalse(check(receipt, codec, changed, [], []))
        for changed in (cells[:-1], cells + [cells[0]], [cells[0], *cells[:-1]], [dict(cells[0], role="unadmitted"), *cells[1:]]):
            self.assertFalse(check(receipt, codec, changed, [], []))
        for key in ("nativeOriginalReturned", "nativeReportAdmitted", "pairNativeObservationsAdmitted"):
            self.assertFalse(check(dict(receipt, **{key: False}), codec, cells, [], []))
        self.assertFalse(check(dict(receipt, pair={"passed": False}), codec, cells, [], []))
        self.assertFalse(check(receipt, codec, cells, [ValueError("unpublished DATA")], []))
        self.assertFalse(check(receipt, codec, cells, [], [{"role": "codec-binary", "close": False}]))
        settled = f["codec_original_settled"]
        for row in ({"returned": False}, {"returned": True}, {"contained": True, "cleanupComplete": False},
                    {"contained": False, "cleanupComplete": True}, {"returned": True, "returncode": False}):
            calls = [dict(row, role="codec-tests")]
            self.assertFalse(settled(calls))
            self.assertFalse(check(dict(receipt, calls=calls), codec, cells, [], []))
        for row in ({"returned": True, "returncode": 101}, {"dispatched": False}, {"contained": True, "cleanupComplete": True}):
            self.assertTrue(settled([dict(row, role="codec-tests")]))
        self.assertFalse(settled(receipt["calls"] * 2))
        for calls in ([], receipt["calls"][:1], receipt["calls"][1:], receipt["calls"] * 2):
            self.assertFalse(check(dict(receipt, calls=calls), codec, cells, [], []))
        for index in (0, 1):
            for replacement in ({"returned": True, "returncode": False}, {"returned": True, "returncode": 101},
                                {"returned": False, "returncode": 0}, {"dispatched": False},
                                {"contained": True, "cleanupComplete": True}):
                calls = deepcopy(receipt["calls"]); calls[index] = dict(replacement, role=calls[index]["role"])
                with self.subTest(role=index, original=replacement):
                    self.assertFalse(check(dict(receipt, calls=calls), codec, cells, [], []))

    def test_codec_closed_receipt_and_source_sequence_never_publish_raw_outputs_or_skip_finality(self):
        f = self.functions()
        private = "INERT_PRIVATE_TEXT_NOT_FOR_PUBLICATION"
        receipt = {"source": "a" * 40, "workflowSource": "a" * 40, "workflow": "fixed-source-workflow", "runId": "1", "runAttempt": "1",
                   "calls": [{"role": "codec-tests", "returned": True, "returncode": 101, "stdoutBytes": 4, "stderrBytes": 0,
                              "stdoutSha256": "b" * 64, "stderrSha256": "c" * 64, "argv": [private], "stdout": private,
                              "stderr": private, "errorType": private}], "passed": False, "failure": private}
        codec = {"compilerAdmitted": True, "testsPassed": False, "artifactHashRechecked": True,
                 "syntheticDirectoriesRetired": False, "private": private}
        cells = [{"role": "codec-binary", "unchanged": False, "closed": False, "path": private}]
        public = f["public_codec_receipt"](receipt, codec, cells, [ValueError(private)], [])
        self.assertNotIn(private, json.dumps(public))
        self.assertTrue(all(value is None or type(value) in (bool, int, str) for value in public.values()))
        self.assertFalse(public["passed"]); self.assertFalse(public["artifactOriginalClosed"])
        self.assertTrue(public["testOriginalReturned"]); self.assertEqual(public["testReturncode"], 101)
        self.assertTrue(public["receiptProvisionalUntilSourcePostAndStepExitZero"])
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        body = workflow.split("<<'PY_WRAPPING'\n", 1)[1].split("\n          PY_WRAPPING", 1)[0]
        dispatch = body.split('              stage = "codec-target-preparation"', 1)[1].split('              qualification_binary, reader_binary = None, None', 1)[0]
        for required in ('codec_environment = dict(build_env, CARGO_TARGET_DIR=str(codec_target), RUSTFLAGS="")',
                         '"--package", "mobile-release-kit-desktop"', '"--manifest-path", str(app / "Cargo.toml")',
                         'timeout=600, limit=4 * 1024 * 1024)', 'cwd=work, timeout=30, limit=64 * 1024)',
                         '"--exact", "--test-threads=1", "--color=never", "--format=pretty", *codec_names',
                         'codec_home.rmdir()', 'codec_tmp.rmdir()'):
            self.assertIn(required, dispatch)
        self.assertEqual(dispatch.count('invoke("codec-build"'), 1); self.assertEqual(dispatch.count('invoke("codec-tests"'), 1)
        self.assertLess(dispatch.index('publish("wrapping-codec-build.status"'), dispatch.index('admit_codec_compiler(result)'))
        self.assertLess(dispatch.index('admit_file(codec_path, "codec-binary"'), dispatch.index('invoke("codec-tests"'))
        self.assertLess(dispatch.index('invoke("codec-tests"'), dispatch.index('codec.update(admit_codec_results(result))'))
        self.assertIn('receipt["passed"] = private_batch_finality(receipt, codec, files, errors, close_errors)', body)
        self.assertIn('if cell["role"] == "codec-binary" and not codec_original_settled(receipt["calls"]):', body)
        self.assertIn('retainedForUnsettledCodecOriginal', body)
        self.assertIn('if receipt.get("pair", {}).get("startAttempted") and not receipt["pair"]["joined"]:', body)
        self.assertEqual(body.count('os.close(descriptor)  # Spend once;'), 1)
        upload = workflow.split('      - name: Preserve bounded private-cohort public facts and compiler-only diagnostics\n', 1)[1]
        for forbidden in ('wrapping-codec-tests.stdout', 'wrapping-codec-tests.stderr', 'wrapping-codec-target', '*.json'):
            self.assertNotIn(forbidden, upload)

if __name__ == "__main__":
    unittest.main()
