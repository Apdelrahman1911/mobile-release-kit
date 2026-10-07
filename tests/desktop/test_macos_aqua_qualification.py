"""Inert DATA/control-flow regressions, not Mac/native/process evidence.

No core owner is imported and no command/native fixture is run. Invalid inline
producer entries exercise only their refusal footers, before any core/native/FS
operation. The unsigned-
iOS output-reader tests use disposable regular-file fixtures only; their DATA
does not substitute for required installed hosted Aqua/core/native evidence.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import ast
import builtins
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


def aqua_headless_source():
    """Fixed helper SOURCE with the actual same-shell caller, never execution."""
    workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text(encoding="utf-8")
    marker = "      - name: Compile headless Mac libraries and run the exact selected DATA regressions first\n"
    if workflow.count(marker) != 1:
        raise AssertionError("fixed aqua_headless_source step")
    step = workflow.split(marker, 1)[1].split("      - name: ", 1)[0]
    key = "        run: |\n"
    if step.count(key) != 1 or step.split(key, 1)[1].rstrip("\n") != "          builtin source ./desktop/tools/macos_aqua_headless_data.sh":
        raise AssertionError("fixed aqua_headless_source same-shell caller")
    source = (PATH.parents[2] / "desktop/tools/macos_aqua_headless_data.sh").read_text(encoding="utf-8")
    # Keep legacy SOURCE assertions literal without replacing raw YAML policy.
    return "".join("          " + line if line.strip() else line
                   for line in source.splitlines(keepends=True))


def aqua_wrapping_source():
    """Fixed helper SOURCE with the actual same-shell caller, never execution."""
    workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text(encoding="utf-8")
    marker = "      - name: Compile native wrapping variants once and run fixed cohorts and creator-reader pair\n"
    if workflow.count(marker) != 1:
        raise AssertionError("fixed aqua_wrapping_source step")
    step = workflow.split(marker, 1)[1].split("      - name: ", 1)[0]
    key = "        run: |\n"
    if step.count(key) != 1 or step.split(key, 1)[1].rstrip("\n") != "          builtin source ./desktop/tools/macos_aqua_wrapping_private.sh":
        raise AssertionError("fixed aqua_wrapping_source same-shell caller")
    source = (PATH.parents[2] / "desktop/tools/macos_aqua_wrapping_private.sh").read_text(encoding="utf-8")
    # Keep legacy SOURCE assertions literal without replacing raw YAML policy.
    return "".join("          " + line if line.strip() else line
                   for line in source.splitlines(keepends=True))


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
        self.inner_bootstrap_diagnostic = None
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

    def readback_vault(self, case, report):
        M._vault_helper_report(report, case)
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


def bootstrap_context_data():
    return {"snapshotSource": "record", "pending": None, "nativeHandler": None, "lastPanel": None,
            "bootstrap": {"source": "first-failure-record", "step": "Bootstrap", "attached": True,
                          "initialNavigation": True, "started": True, "loaded": True,
                          "info": False, "catalog": False, "capability": True, "methods": 0,
                          "reloadRequested": False, "reloadNavigation": False, "lossSeen": False,
                          "originalWindowAdmitted": True}}


def vault_failure_context_data():
    # Partial DATA only: an unavailable terminal is null, not a negative
    # provider result. These facts do not assert native execution or finality.
    helper = M._expected_vault_original("before-go")
    helper.update(driverReturned=False, driverBeforeCleanup=False, blockingChildJoined=False,
                  exitObserved=False, exitSuccess=None, resourcesSettled=False, allocationsReleased=False,
                  helperSlotsSettled=False, helperGatePostchecked=False, helperGateClosed=False, helperGateUnknown=True,
                  firstFailure="cleanup-unknown", cleanupUnknown=True)
    return {"snapshotSource": "record", "pending": None, "nativeHandler": None, "lastPanel": None,
            "vault": {"source": "first-original-vault-snapshot", "step": "Vault(Initialized)",
                      "observationOnly": True, "snapshot": {
                          "unknown": True, "documentUnknown": True, "exhausted": False,
                          "lostObserved": False, "originalBound": True, "originals": 4,
                          "originalsSettled": False, "empty": False, "operationId": 4,
                          "operationPhase": "unknown", "operationReason": "cleanup-unknown",
                          "operationSettlement": "unknown", "state": "interrupted", "keyPresent": False,
                          "initializePreview": False, "previewConsumed": True,
                          "storage": {"reservation": [True, False], "header": [False, False], "durability": [False, False]},
                          "initialize": helper, "lookup": None,
                          "initializeTransport": {"exitCode": None, "exitSignal": None, "responseBytes": 0},
                          "lookupTransport": None}}}


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


def returned_project_field_context_data(action, admitted, *, expired=False):
    # Inert parser fixture only, not a worker/native/selection receipt.
    case, step = "project-fields", "ProjectFields(Native(0))"
    history = M.expected_result(BINDING, case)["projectFields"]["acceptedOpenHistories"][1]
    value = accessibility_context_data()
    value.update(snapshotSource="prearm-open-return", inputBodyAdmission=admitted,
                 pending={"kind": "accessibility", "step": step},
                 accessibility=deepcopy(action), accessibilityBinding=deepcopy(history["selectionBinding"]))
    value["nativeHandler"]["step"] = step
    value["lastPanel"].update(step=step, id=2, kind="version-source")
    sample = value["accessibility"]
    sample.update(state="unknown" if admitted is None or sample["custodyKnown"] is False else "returned",
                  receiptJoined=False, workerJoined=False, rechecksSettled=None, barrierRetired=False,
                  expired=expired, timely=False if expired else None)
    if admitted is None:
        sample["custodyKnown"] = False
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

        # Follow the live parent pins as SOURCE DATA, without importing helpers.
        def assigned(tree, name):
            values = [node.value for node in tree.body
                      if isinstance(node, ast.Assign) and len(node.targets) == 1
                      and isinstance(node.targets[0], ast.Name)
                      and node.targets[0].id == name]
            self.assertEqual(len(values), 1, name)
            return values[0]

        loader_relative = "desktop/tools/macos_aqua_qualification.py"
        runner_relative = "desktop/tools/macos_normal_ui_runner.py"
        runner_tree = ast.parse((root / runner_relative).read_bytes())
        self.assertEqual(ast.literal_eval(assigned(runner_tree, "LOADER")), loader_relative)
        self.assertEqual(ast.literal_eval(assigned(runner_tree, "LOADER_SHA")),
                         M.digest((root / loader_relative).read_bytes()))

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
        # The reviewed fresh supplier route is DATA-only and precedes the
        # native owner preflight; it does not reuse the removed M-download step.
        previous = workflow.index("      - name: Bind the complete reviewed first-party checkout before compilation\n")
        for earlier in ("Admit only a fresh independently pinned Python transport destination",
                        "Download the independently accepted fresh Python transport",
                        "Project the pinned fresh Python transport without executing it",
                        "Prepare the current payload from the independently accepted fresh Python supplier"):
            supplier_label = "      - name: " + earlier + "\n"
            self.assertEqual(workflow.count(supplier_label), 1)
            current = workflow.index(supplier_label)
            self.assertLess(previous, current)
            self.assertLess(current, position)
            previous = current
        self.assertNotIn("      - name: Download only the exact accepted M archive (no rebuild or fallback)\n", workflow)
        for later in ("Compile headless Mac libraries and run the exact selected DATA regressions first",
                      "Fail fast on native Scripts ownership and package format (never Installer)",
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
                'roster_path = pathlib.Path("tests/desktop/test_installed_shell_ci.py").absolute()',
                'roster_spec = importlib.util.spec_from_file_location("_mrk_macos_observer_roster_preflight", roster_path)',
                'roster_spec.loader.exec_module(roster_module)',
                'roster_module.InstalledShellCompilerContracts("test_observer_module_roster_matches_production_supported_platforms")',
                "unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)",
                "result.testsRun != 7", "not result.wasSuccessful()",
                "result.failures, result.errors, result.skipped, result.expectedFailures, result.unexpectedSuccesses",
                "raise SystemExit(1)"):
            self.assertIn(required, step)
        self.assertNotIn("discover(", step)
        self.assertNotIn("loadTestsFrom", step)

        headless_label = "      - name: Compile headless Mac libraries and run the exact selected DATA regressions first\n"
        self.assertEqual(workflow.count(headless_label), 1)
        self.assertLess(workflow.index(headless_label), workflow.index(
            "      - name: Fail fast on native Scripts ownership and package format (never Installer)\n"))
        headless = aqua_headless_source()
        self.assertLess(headless.index("cd desktop/src-tauri"), headless.index('"/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/cargo" test --locked --no-default-features'))
        self.assertEqual(headless.count('"/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/cargo" test '), 1)
        self.assertIn("--package mobile-release-kit-desktop --package mrk-macos-installed-native", headless)
        self.assertIn("--lib --no-run --message-format=json", headless)
        self.assertNotIn("--manifest-path", headless)
        raw_compiler = headless.split('"$MRK_PYTHON" -I -S -B -', 1)[0]
        self.assertNotIn("--features", raw_compiler)
        self.assertIn('if shipping_gate:\n                      compiler_argv += ["--features", "mrk-macos-installed-native/installed-observation"]', headless)
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
            "asset_session::vault::tests::explicit_vault_loans_supply_two_signing_inputs_and_preserve_actual_borrowed_backing_on_lock",
            "asset_session::vault::tests::bound_loan_publication_refuses_changed_lineage_or_unsettled_original_without_taking_payload",
            "asset_session::vault::tests::loan_currentness_rejects_equal_counter_replacement_new_context_registry_and_reassignment",
            "asset_session::vault::tests::reassigned_loan_census_is_not_refunded_before_off_lock_retirement_and_restore_preserves_it",
            "asset_session::vault::tests::schema_three_advertises_storage_modes_without_opening_or_probing_a_vault",
            "asset_session::vault::tests::encrypted_projection_redacts_locked_read_only_and_mutating_authority",
            "runtime::persistence_selection_keeps_original_document_and_fixed_helper_pin_bounds",
            "asset_session::vault::tests::boxed_loan_cells_are_charged_once_each_while_arc_backing_deduplicates",
            "asset_session::vault::tests::prospective_loan_pointee_preserves_resident_boundary_and_checked_overlap",
            "asset_session::vault::tests::refused_new_or_replacement_loan_keeps_loaded_and_original_box_unchanged",
            "asset_session::images::persistent_memory::tests::image_fixed_partition_boundary_overflow_and_incomplete_heap_refuse",
            "asset_session::images::persistent_memory::tests::image_identity_set_keeps_distinct_allocations_and_refuses_the_148th",
            "asset_session::images::persistent_memory::tests::image_record_assignment_payload_and_context_capacities_share_one_census",
            "asset_session::images::persistent_memory::tests::image_stored_heap_charges_spare_capacity_not_its_inline_cell_twice",
        ))
        native_names = headless.split("          native_names = (\n", 1)[1].split("          )\n", 1)[0]
        self.assertCountEqual(M.re.findall(r'"([^"]+)"', native_names), (
            "tests::bulk_directory_records_preserve_full_ids_and_refuse_malformed_batches",
            "tests::only_explicit_user_appkit_responses_can_be_accept_or_decline",
        ))
        self.assertIn('scope = "twenty-five-main-and-two-native-macos-headless-data-regressions"', headless)
        self.assertIn('"scope": scope', headless)
        table = headless.split("          libraries = (\n", 1)[1].split("          )\n", 1)[0]
        self.assertEqual(table,
            '              ("main", "desktop/src-tauri", "mobile-release-kit-desktop", "mobile_release_desktop", [], names, main_count, "headless"),\n'
            '              ("native", "desktop/native/macos-installed-native", "mrk-macos-installed-native", "mrk_macos_installed_native",\n'
            '               ["default", "installed-observation"] if shipping_gate else ["default"], native_names, native_count, "headless-native"),\n')
        for required in ("if len(targets) != 2:", "for role, directory, package, library, features, test_names, count, prefix in libraries:",
                         'r.get("target", {}).get("name") == library', "if len(matches) != 1:",
                         'package_id = "path+" + (checkout / directory).as_uri() + "#" + package + ("@0.1.1" if package == "mobile-release-kit-desktop" else "@0.1.0")',
                         'target.get("package_id") != package_id',
                         'target.get("manifest_path") != str(checkout / directory / "Cargo.toml")',
                         'target["target"].get("kind") != ["lib"]', 'target["target"].get("crate_types") != ["lib"]',
                         'target["target"].get("src_path") != str(checkout / directory / "src/lib.rs")',
                         'target.get("profile", {}).get("test") is not True', 'target.get("features") != features',
                         'binary.parent != expected', 're.fullmatch(re.escape(library) + r"-[0-9a-f]+", binary.name)',
                         "for binary, test_names, count, prefix, record in admitted:"):
            self.assertIn(required, headless)
        execution_label = "\n              for binary, test_names, count, prefix, record in admitted:\n"
        settlement_label = "\n          finally:\n"
        self.assertEqual(headless.count(execution_label), 1)
        self.assertEqual(headless.count(settlement_label), 1)
        self.assertLess(headless.index("admitted.append("), headless.index(execution_label))
        # The catalogue helper and compiler have their own reviewed original
        # calls; neither is the later, fully admitted library-test execution.
        self.assertEqual(headless.count("owner.run_owned("), 3)
        execution = headless.split(execution_label, 1)[1].split(settlement_label, 1)[0]
        self.assertEqual(execution.count("owner.run_owned("), 1)
        for required in ('[str(binary), "--exact", "--test-threads=1", "--color=never", "--format=pretty", *test_names]',
                         "cwd=work, timeout=30, capture=True, text=False, output_limit=64 * 1024",
                         "type(result) is not subprocess.CompletedProcess", "type(result.stdout) is not bytes",
                         "type(result.stderr) is not bytes", "len(result.stdout) + len(result.stderr) > 64 * 1024",
                         "len(test_names) != count", "len(expected_rows) != count", "len(lines) != count + 2",
                         'heading = f"running {count} " + ("test" if count == 1 else "tests")', 'lines[0] != heading',
                         "len(set(lines[1:-1])) != count", "set(lines[1:-1]) != expected_rows",
                         "{count} passed; 0 failed; 0 ignored; 0 measured;"):
            self.assertIn(required, execution)
        reject = execution.index('if result.returncode != 0 or result.stderr:')
        for output in ("stdout", "stderr", "status"):
            self.assertLess(execution.index('publish(prefix + "-tests.' + output + '"'), reject)
        self.assertLess(execution.index("originals.append(original)"), execution.index("before = os.fstat(binary_fd)"))
        self.assertIn('os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)', execution)
        for required in ('sig(before) != sig(os.fstat(binary_fd))', 'sig(before) != sig(binary.lstat())',
                         'os.pread(binary_fd, min(before.st_size - offset, 1024 * 1024), offset)',
                         'os.pread(binary_fd, 1, before.st_size)', 'return digest.hexdigest()'):
            self.assertIn(required, execution)
        digest_checks = [item.start() for item in M.re.finditer(M.re.escape('if original_digest() != digest:'), execution)]
        self.assertEqual(len(digest_checks), 2)
        self.assertLess(digest_checks[0], execution.index("result = owner.run_owned("))
        self.assertGreater(digest_checks[1], execution.index('publish(prefix + "-tests.status"'))
        self.assertLess(execution.index('raise ValueError("headless-original-return-contract")'), execution.index("home.rmdir()"))
        settlement = headless.split(settlement_label, 1)[1]
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
        self.assertEqual((len(M.VERSION), len(M.IGNORE_PREFIX), len(M.IGNORE_RULES), len(M.STALE)), (34, 40, 414, 26))
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
        self.assertEqual(BINDING.target, M.ARM_TARGET)
        for target, machine, runner, release, lock, platform in (
                (M.ARM_TARGET, "arm64", "ARM64", "build-release.json", "source-lock.json", "macOS26-arm64"),
                (M.INTEL_TARGET, "x86_64", "X64", "build-release-intel.json", "source-lock-intel.json", "macOS26-x86_64")):
            selected = replace(BINDING, target=target).checked()
            self.assertEqual(selected.public(), BINDING.public())  # Rust inner wire remains exactly three fields.
            self.assertEqual(selected.root(), BINDING.root())
            data = M.target_data(target)
            self.assertEqual((data["machine"], data["runner"], data["releaseInput"], data["sourceLock"], data["platform"]),
                             (machine, runner, release, lock, platform))
            self.assertEqual(data["cargo"], "/Users/runner/.rustup/toolchains/stable-" + target + "/bin/cargo")
            self.assertEqual(M.expected_result(selected, "first-save"), M.expected_result(BINDING, "first-save"))
            self.assertEqual(M._gate_new_report(selected, M.VAULT_HELPER_SCOPE)["platform"], platform)
            self.assertEqual(M._capacity_new_report(selected, M.VAULT_HELPER_SCOPE)["platform"], platform)
            toolchain = {"aarch64-apple-darwin": "1.98.1", "x86_64-apple-darwin": "1.98.0"}[target]
            self.assertEqual(data["toolchain"], toolchain)
            self.assertEqual(M._gate_new_report(selected, M.VAULT_HELPER_SCOPE)["toolchain"], toolchain)
            self.assertEqual(M._capacity_new_report(selected, M.VAULT_HELPER_SCOPE)["toolchain"], toolchain)
        for target in (None, [], True, "arm64", "x86_64h-apple-darwin", "x86_64-unknown-linux-gnu"):
            with self.subTest(target=target), self.assertRaises(M.Refused):
                replace(BINDING, target=target).checked()
        with patch.dict(sys.modules):
            import platform
            import pwd
            checkout = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
            for target, machine, runner in ((M.ARM_TARGET, "arm64", "ARM64"), (M.INTEL_TARGET, "x86_64", "X64")):
                environment = {"GITHUB_SHA": BINDING.source, "GITHUB_RUN_ID": BINDING.run, "GITHUB_RUN_ATTEMPT": BINDING.attempt,
                    "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": runner,
                    "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": M.REPOSITORY, "GITHUB_REF": M.REF,
                    "GITHUB_WORKFLOW_REF": M.WORKFLOW, "GITHUB_WORKFLOW_SHA": BINDING.source, "GITHUB_WORKSPACE": str(checkout)}
                def head_info(path):
                    self.assertEqual(path, checkout / '.git/HEAD')
                    return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=41)
                def head_bytes(path):
                    self.assertEqual(path, checkout / '.git/HEAD')
                    return BINDING.source.encode() + b'\n'
                with patch.object(M.sys, 'platform', 'darwin'), patch.object(M.sys, 'maxsize', 2 ** 63 - 1), \
                     patch.object(platform, 'machine', return_value=machine), patch.object(platform, 'mac_ver', return_value=('26.0', (), '')), \
                     patch.object(pwd, 'getpwuid', return_value=SimpleNamespace(pw_name='runner')), \
                     patch.multiple(M.os, getuid=lambda: UID, geteuid=lambda: UID, getgid=lambda: GID, getegid=lambda: GID), \
                     patch.object(Path, 'lstat', head_info), patch.object(Path, 'read_bytes', head_bytes):
                    selected, uid, gid, username = M.admit(environment, checkout, target=target)
                    self.assertEqual((selected, uid, gid, username), (replace(BINDING, target=target), UID, GID, 'runner'))
                    with self.assertRaisesRegex(M.Refused, '^hosted-source-route$'):
                        M.admit(dict(environment, RUNNER_ARCH='X64' if runner == 'ARM64' else 'ARM64'), checkout, target=target)
                    with patch.object(platform, 'machine', return_value='x86_64' if machine == 'arm64' else 'arm64'), self.assertRaisesRegex(M.Refused, '^native-platform$'):
                        M.admit(environment, checkout, target=target)
                    with patch.object(M.sys, 'maxsize', 2 ** 31 - 1), self.assertRaisesRegex(M.Refused, '^native-platform$'):
                        M.admit(environment, checkout, target=target)

    def test_review_ignore_lengths_match_the_complete_fixture(self):
        initial = M.fixture_data("first-save", False)[0][".gitignore"]
        saved = M.fixture_data("noop-stale", False)[0][".gitignore"]
        self.assertEqual((len(initial), len(saved)), (40, 454))
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

    def test_bootstrap_first_failure_data_is_optional_closed_and_not_finality(self):
        good = bootstrap_context_data()
        for reason in M.BOOTSTRAP_FAILURE_REASONS:
            row = project_selection_row(good, reason, "Bootstrap")
            self.assertEqual(M.failure_context(b"", row), good)
            self.assertEqual(M.failure_reason(b"", row), reason)
            with self.assertRaisesRegex(M.Refused, "^inner-failure-marker$"):
                M.parse_result(captured(M.expected_result(BINDING, "first-save")), row, BINDING, "first-save")
        # A later report Step is not the nested first-failure sample's time.
        self.assertEqual(M.failure_context(b"", project_selection_row(good, "bootstrap-info-duplicate", "Environment")), good)
        for count in (14, 64):
            accepted = deepcopy(good); accepted["bootstrap"].update(info=True, catalog=True, methods=count)
            self.assertEqual(M.failure_context(b"", project_selection_row(accepted, "bootstrap-info-duplicate", "Bootstrap")), accepted)
        for admitted in (None, False):
            unknown = deepcopy(good); unknown["bootstrap"]["originalWindowAdmitted"] = admitted
            self.assertEqual(M.failure_context(b"", project_selection_row(unknown, "bootstrap-window-result", "Bootstrap")), unknown)
        historical = deepcopy(good); del historical["bootstrap"]
        for reason in ("observer-invariant", "bootstrap-info-methods-shape", "bootstrap-tick-main-thread"):
            row = project_selection_row(historical, reason, "Bootstrap")
            self.assertEqual(M.failure_context(b"", row), historical)
        row = project_selection_row(good, "bootstrap-info-available-count", "Bootstrap")
        with inert_exception_owner(stderr=row) as call:
            fixtures = InertFixtures()
            with self.assertRaises(RuntimeError) as caught:
                M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
            report = M.diagnostic(caught.exception, None, fixtures)
            self.assertEqual(report["innerFailureContext"], good)
            self.assertEqual(report["invocationFinality"], "unknown")
            self.assertFalse(report["originalCallReturned"])
            self.assertEqual(fixtures.reads, [])

    def test_bootstrap_failure_data_rejects_unbound_contradictory_and_open_shapes(self):
        good = bootstrap_context_data()
        variants = []
        for key, bad in (("source", "later-record"), ("step", "PRIVATE"), ("attached", 1),
                         ("methods", True), ("methods", -1), ("methods", 65), ("methods", 10),
                         ("info", True), ("catalog", True), ("started", False),
                         ("originalWindowAdmitted", 1), ("reloadNavigation", True), ("lossSeen", True)):
            value = deepcopy(good); value["bootstrap"][key] = bad; variants.append(value)
        value = deepcopy(good); value["bootstrap"]["privatePath"] = "PRIVATE"; variants.append(value)
        for count in range(10, 14):
            value = deepcopy(good); value["bootstrap"].update(info=True, catalog=True, methods=count); variants.append(value)
        value = deepcopy(good); del value["bootstrap"]["loaded"]; variants.append(value)
        value = deepcopy(good); value["bootstrap"] = None; variants.append(value)
        for source in (None, "prearm-open-progress", "first-failure-record"):
            value = deepcopy(good); value["snapshotSource"] = source; variants.append(value)
        for value in variants:
            row = project_selection_row(value, "bootstrap-info-available-count", "Bootstrap")
            self.assertIsNone(M.failure_context(b"", row))
        for reason in ("observer-invariant", "bootstrap-unknown", "PRIVATE"):
            self.assertIsNone(M.failure_context(b"", project_selection_row(good, reason, "Bootstrap")))
        row = project_selection_row(good, "bootstrap-info-available-count", "Bootstrap")
        for malformed in (context_row(good), row.replace(b"MRK_MACOS_AQUA_FAILURE_STEP=Bootstrap\n", b""),
                          row + b"MRK_MACOS_AQUA_FAILURE_REASON=observer-deadline\n",
                          row.replace(b'"methods":0', b'"methods":0,"methods":0'), row + context_row(good)):
            self.assertIsNone(M.failure_context(b"", malformed))

    def test_bootstrap_source_keeps_original_guard_order_and_one_first_winner(self):
        observer = (PATH.parents[1] / "src-tauri" / "src" / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        labels = M.re.findall(r'"([a-z_-]+)"', observer.split("const FAILURE_REASONS: &[&str] = &[", 1)[1].split("];", 1)[0])
        self.assertEqual(set(labels), M.FAILURE_REASONS)
        self.assertEqual(len(labels), len(set(labels)))
        self.assertLess(len(labels), 255)
        latch = observer.split("fn latch_bootstrap(", 1)[1].split("// Original appInfo predicates", 1)[0]
        self.assertIn("if latch_failure(first, failed, reason) && bootstrap_failure_reason(reason) { *detail = Some(sample); }", latch)
        self.assertNotIn("compare_exchange", latch)
        classifier = observer.split("fn bootstrap_app_info_failure(", 1)[1].split("fn bootstrap_catalog_failure(", 1)[0]
        order = ("bootstrap-info-runtime-state", "bootstrap-info-runtime-mode", "bootstrap-info-runtime-reason",
                 "bootstrap-info-methods-shape", "bootstrap-info-actions-shape", "bootstrap-info-app-name",
                 "bootstrap-info-app-version", "bootstrap-info-project-selection", "bootstrap-info-project-reason",
                 "bootstrap-info-project-fields", "bootstrap-info-method-count", "bootstrap-info-action-count",
                 "bootstrap-info-available-count", "bootstrap-info-required-method",
                 "bootstrap-info-method-availability", "bootstrap-info-action-availability", "Ok(methods.len())")
        self.assertEqual([classifier.index(v) for v in order], sorted(classifier.index(v) for v in order))
        self.assertIn("project_fields: bool) -> Result<usize, BootstrapAppInfoFailure>", classifier)
        self.assertNotIn("methods: &[Value]", classifier)
        self.assertNotIn("actions: &[Value]", classifier)
        self.assertEqual(classifier.count("info.capabilities.as_ref()"), 2)
        for shape in ("methods", "actions"):
            self.assertIn('Err(Shape("bootstrap-info-' + shape + '-shape"))', classifier)
        for runtime in ("state", "mode", "reason"):
            self.assertIn('Err(Record("bootstrap-info-runtime-' + runtime + '"))', classifier)
        callback = observer.split("pub(super) fn app_info(", 1)[1].split("pub(super) fn catalog(", 1)[0]
        order = ("let classified = match bootstrap_app_info_failure(", "Err(BootstrapAppInfoFailure::Shape(reason))",
                 "self.fail_with(reason); return;", "Err(BootstrapAppInfoFailure::Record(reason)) => Err(reason)",
                 "self.record()", "let methods = match classified", "self.fail_bootstrap(&mut r, reason); return;",
                 "bootstrap-info-duplicate", "bootstrap-info-reload", "r.info = true; r.methods = methods;")
        self.assertEqual([callback.index(v) for v in order], sorted(callback.index(v) for v in order))
        self.assertEqual(callback.count("bootstrap_app_info_failure("), 1)
        self.assertEqual(callback.count("self.record()"), 1)
        self.assertNotIn("info.capabilities", callback)
        catalog = observer.split("pub(super) fn catalog(", 1)[1].split("pub(super) fn project_result(", 1)[0]
        order = ("let failure = bootstrap_catalog_failure(", "self.record()", "bootstrap-catalog-info-order",
                 "bootstrap-catalog-duplicate", "if let Some(reason) = failure", "bootstrap-catalog-reload", "r.catalog = true;")
        self.assertEqual([catalog.index(v) for v in order], sorted(catalog.index(v) for v in order))
        for body in (latch, classifier, callback, catalog):
            for forbidden in ("try_lock", "thread::spawn", "Instant::now", "run_on_main_thread", "ns_window(", "observe_panel("):
                self.assertNotIn(forbidden, body)
        snapshot = observer.split("struct FailureSnapshot", 1)[1].split("fn failure_context(", 1)[0]
        self.assertIn("bootstrap: r.bootstrap_failure", snapshot)
        self.assertIn("self.bootstrap = None;", snapshot.split("fn at_expiry(", 1)[1].split("fn frame(", 1)[0])
        self.assertIn('self.bootstrap.is_some() && (self.source != "record" || !bootstrap_failure_reason(reason))', snapshot)
        self.assertIn('bounded_failure_context(failure_context(&self), self.press_timing(),', snapshot)
        self.assertIn('(frame.len() <= 8448).then_some(frame)', snapshot)
        self.assertIn("if !bootstrap_diagnostic_data_checks() { return false; }", observer)
        bridge = (PATH.parents[1] / "src-tauri" / "src" / "bridge.rs").read_text(encoding="utf-8")
        origin_classifier = bridge.split("fn capabilities_failure_line(", 1)[1].split("fn capabilities_cause_line(", 1)[0]
        rows = M.re.findall(r'=> b"(MRKDBG_DESKTOP_BOOTSTRAP=capabilities-(admission|query-wait)-([a-z_]+))\\n"', origin_classifier)
        expected = {(line + "\n").encode("ascii"): (origin, code) for line, origin, code in rows}
        self.assertEqual((len(rows), len(expected)), (30, 30))
        self.assertEqual(M._BOOTSTRAP_DIAGNOSTIC_LINES, expected)
        self.assertEqual(M._BOOTSTRAP_DIAGNOSTIC_ORIGINS, ("admission", "query-wait"))
        self.assertEqual(M._BOOTSTRAP_DIAGNOSTIC_CODES, (
            "runtime_unavailable", "cleanup_unknown", "invalid_request", "shutting_down", "busy", "unavailable",
            "offline_preflight_busy", "android_build_busy", "environment_diagnostics_busy", "query_timeout",
            "protocol_error", "engine_failed", "io_error", "output_limit", "other",
        ))

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
        self.assertIn('bounded_failure_context(failure_context(&self), self.press_timing(),', observer)
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

    def test_ax_failure_diagnostic_schema_is_closed_and_not_action_authority(self):
        # Inert decoder DATA only. No diagnostic here is a native AX observation.
        operations = (
            "set-messaging-timeout", "copy-attribute-value", "get-attribute-value-count", "copy-attribute-values",
            "copy-action-names", "is-attribute-settable", "set-attribute-value", "perform-action",
            "copy-multiple-attribute-values",
        )
        attributes = (None, "Parent", "Role", "Identifier", "Title", "Value", "Enabled",
                      "Windows", "Children", "Rows", "SelectedChildren", "SelectedRows")
        by_operation = (
            (operations[0], (None,)), (operations[1], attributes[1:7]),
            (operations[2], attributes[7:]), (operations[3], attributes[7:]),
            (operations[4], (None,)), (operations[5], attributes[10:]),
            (operations[6], attributes[10:]), (operations[7], (None,)), (operations[8], (None,)),
        )
        pairs = frozenset((operation, attribute) for operation, allowed in by_operation for attribute in allowed)
        self.assertEqual(len(pairs), 24)
        self.assertEqual(M.ACCESSIBILITY_AX_FAILURE_OPERATIONS, operations)
        self.assertEqual(M.ACCESSIBILITY_AX_FAILURE_ATTRIBUTES, attributes)
        self.assertEqual(M.ACCESSIBILITY_AX_FAILURE_PAIRS, pairs)
        button = M._expected_prompt_button()
        self.assertIsNone(button["axFailure"])
        self.assertIs(M._accessibility_prompt_button(button), button)
        self.assertIsNone(M._accessibility_ax_failure(None, 0))
        for ax_error in range(-25214, -25199):
            for operation, allowed in by_operation:
                for attribute in allowed:
                    with self.subTest(ax_error=ax_error, operation=operation, attribute=attribute):
                        diagnostic = {"operation": operation, "attribute": attribute}
                        self.assertIs(M._accessibility_ax_failure(diagnostic, ax_error), diagnostic)
                        sample = deepcopy(button); sample.update(axError=ax_error, axFailure=diagnostic)
                        self.assertIs(M._accessibility_prompt_button(sample), sample)
                        action = accessibility_context_data()["accessibility"]
                        action["promptButton"] = sample
                        self.assertFalse(M._accessibility_succeeded(action))
        # Every bounded pairing is checked against the independent24-pair table,
        # including well-typed but forbidden pairs and unknown or non-string tags.
        for operation in (*operations, "none", "INERT_PRIVATE", None, True, 1, []):
            for attribute in (*attributes, "INERT_PRIVATE", False, 1, [], {}):
                diagnostic = {"operation": operation, "attribute": attribute}
                valid = (type(operation) is str and (attribute is None or type(attribute) is str)
                         and (operation, attribute) in pairs)
                if valid:
                    self.assertIs(M._accessibility_ax_failure(diagnostic, -25204), diagnostic)
                else:
                    with self.subTest(operation=operation, attribute=attribute), self.assertRaises(M.Refused):
                        M._accessibility_ax_failure(diagnostic, -25204)
        present = {"operation": "perform-action", "attribute": None}
        for ax_error in (True, False, None, "0", 0.0, -25204.0, 1, -1, -25215, -25199, -(1 << 31), (1 << 31) - 1):
            for diagnostic in (None, present):
                with self.subTest(ax_error=ax_error, diagnostic=diagnostic), self.assertRaises(M.Refused):
                    M._accessibility_ax_failure(diagnostic, ax_error)
        for malformed in (None, False, 0, "", [], {}, {"operation": "perform-action"}, {"attribute": None},
                          dict(present, private="INERT_PRIVATE"), dict(present, operation=None),
                          dict(present, attribute=False)):
            with self.subTest(malformed=malformed), self.assertRaises(M.Refused):
                M._accessibility_ax_failure(malformed, -25204)
        with self.assertRaises(M.Refused):
            M._accessibility_ax_failure(present, 0)
        for mutate in (
            lambda v: v.pop("axFailure"),
            lambda v: v.update(axFailure=present),  # Present metadata with zero AX error is contradictory.
            lambda v: v.update(axError=-25204),    # Nonzero AX error cannot have absent metadata.
        ):
            sample = deepcopy(button); mutate(sample)
            with self.assertRaises(M.Refused):
                M._accessibility_prompt_button(sample)
            malformed = accessibility_context_data(); malformed["accessibility"]["promptButton"] = sample
            expected = deepcopy(malformed); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(malformed), "first-save"), expected)
        contradictory = accessibility_context_data()["accessibility"]
        contradictory["promptButton"]["axFailure"] = present
        self.assertFalse(M._accessibility_succeeded(contradictory))
        # A genuine-shaped failed Press packet remains failed, including when an
        # earlier overall deadline is retained beside the actual AX error.
        for error, expired, timely in (("cannot-complete", False, True), ("deadline", True, False)):
            failed = accessibility_context_data()
            failed["accessibility"].update(triggered=False, error=error, expired=expired, timely=timely)
            failed["accessibility"]["promptButton"].update(axError=-25204, axFailure=deepcopy(present))
            self.assertEqual(M.failure_context(b"", context_row(failed), "first-save"), failed)
            self.assertFalse(M._accessibility_succeeded(failed["accessibility"]))
            result = M.expected_result(BINDING, "first-save")
            result["native"]["projectOpenInput"] = failed["accessibility"]
            with self.assertRaises(M.Refused):
                M.parse_result(captured(result), b"", BINDING, "first-save")
        for key in ("operation", "attribute"):
            parts = ("accessibility", "promptButton", "axFailure", key)
            self.assertEqual(M._result_location(parts), ".".join(parts))
        self.assertIsNone(M._result_location(("accessibility", "promptButton", "axFailure", "INERT_PRIVATE")))

    def test_press_timing_diagnostic_is_failure_only_bound_and_closed(self):
        # Synthetic nanoseconds/JSON only, never an AX measurement or receipt.
        diagnostic = {"acknowledgment": "not-acknowledged", "effect": "unknown",
                      "installedAllowanceNs": "99999995", "lastPermitToReturnAdmissionNs": "100123456"}

        def failed(frame):
            frame = deepcopy(frame)
            frame["accessibility"].update(triggered=False, error="cannot-complete", pressDiagnostic=deepcopy(diagnostic))
            frame["accessibility"]["promptButton"].update(axError=-25204,
                axFailure={"operation": "perform-action", "attribute": None})
            return frame

        field = accessibility_context_data()
        field["nativeHandler"]["step"] = "ProjectFields(Native(0))"
        field["lastPanel"].update(step="ProjectFields(Native(0))", id=2, kind="version-source")
        history = M.expected_result(BINDING, "project-fields")["projectFields"]["acceptedOpenHistories"][1]
        field["accessibility"] = deepcopy(history["selectionInput"])
        field["accessibilityBinding"] = deepcopy(history["selectionBinding"])
        fixtures = (("first-save", accessibility_context_data()),
                    ("ios-signing-inputs", file_failure_context_data("ios-signing-inputs", 0, 2)),
                    ("project-fields", field))
        for case, source in fixtures:
            for allowance, elapsed in (("1", "0"), ("100000000", "18446744073709551615"), ("99999995", None)):
                frame = failed(source)
                frame["accessibility"]["pressDiagnostic"].update(
                    installedAllowanceNs=allowance, lastPermitToReturnAdmissionNs=elapsed)
                with self.subTest(case=case, allowance=allowance, elapsed=elapsed):
                    self.assertEqual(M.failure_context(b"", context_row(frame), case), frame)
                    self.assertFalse(M._accessibility_succeeded(frame["accessibility"]))
        frame = failed(accessibility_context_data())
        sample, native, panel = (frame[k] for k in ("accessibility", "nativeHandler", "lastPanel"))
        for changes in ({"error": "deadline", "expired": True, "timely": False}, {"state": "unknown", "custodyKnown": False}):
            changed = deepcopy(frame); changed["accessibility"].update(changes)
            self.assertEqual(M.failure_context(b"", context_row(changed), "first-save"), changed)
            self.assertFalse(M._accessibility_succeeded(changed["accessibility"]))
        for options in ({}, {"historical": True}, {"allow_press_diagnostic": 1},
                        {"allow_press_diagnostic": True, "expected_id": 2},
                        {"allow_press_diagnostic": True, "field_history": True, "expected_id": 2}):
            self.assertIsNone(M._accessibility_context(sample, native, panel, case="first-save", **options))
        for case in (None, "noop-stale", "picker-loss", "INERT_UNKNOWN"):
            self.assertIsNone(M._accessibility_context(sample, native, panel, case=case, allow_press_diagnostic=True))
        for bad_native, bad_panel in (
            (dict(native, step="ProjectSettled"), dict(panel, step="ProjectSettled")),
            (native, dict(panel, id=1)), (native, dict(panel, kind="file")), (None, panel), (native, None),
        ):
            self.assertIsNone(M._accessibility_context(sample, bad_native, bad_panel, case="first-save",
                                                       allow_press_diagnostic=True))
        malformed = [None, False, {}, dict(diagnostic, extra="INERT"), dict(diagnostic, acknowledgment="acknowledged"),
                     dict(diagnostic, effect="no-effect")]
        for key, values in (
            ("installedAllowanceNs", (None, True, 1, 1.0, "", "0", "01", "-1", "+1", "1e2", "100000001", "1000000000", " 1", "1 ", "\u0661")),
            ("lastPermitToReturnAdmissionNs", (False, 0, 0.0, "", "00", "-1", "1e2", "18446744073709551616", "0" * 21)),
        ):
            malformed.extend(dict(diagnostic, **{key: value}) for value in values)
        for value in malformed:
            with self.subTest(diagnostic=value):
                changed = deepcopy(sample); changed["pressDiagnostic"] = value
                self.assertIsNone(M._accessibility_context(changed, native, panel, case="first-save",
                                                           allow_press_diagnostic=True))
        for changes in ({"attempted": False}, {"pressReturned": False}, {"triggered": True}):
            changed = deepcopy(sample); changed.update(changes)
            self.assertIsNone(M._accessibility_context(changed, native, panel, case="first-save",
                                                       allow_press_diagnostic=True))
        for changes in ({"axError": -25202}, {"axFailure": {"operation": "set-messaging-timeout", "attribute": None}}):
            changed = deepcopy(sample); changed["promptButton"].update(changes)
            self.assertIsNone(M._accessibility_context(changed, native, panel, case="first-save",
                                                       allow_press_diagnostic=True))
        for action in (sample, deepcopy(accessibility_context_data()["accessibility"])):
            action = deepcopy(action); action["pressDiagnostic"] = deepcopy(diagnostic)
            result = M.expected_result(BINDING, "first-save"); result["native"]["projectOpenInput"] = action
            with self.assertRaises(M.Refused):
                M.parse_result(captured(result), b"", BINDING, "first-save")
        for key in diagnostic:
            self.assertEqual(M._result_location(("accessibility", "pressDiagnostic", key)),
                             "accessibility.pressDiagnostic." + key)
        self.assertIsNone(M._result_location(("accessibility", "pressDiagnostic", "INERT_PRIVATE")))

    def test_press_timing_source_reuses_admission_and_preserves_baseline(self):
        # Source invariants complement real callback/JSON DATA checks in the
        # already-required native entry; they are not native execution evidence.
        root = PATH.parents[1]
        rust = (root / "native/macos-installed-native/src/lib.rs").read_text()
        observer = (root / "src-tauri/src/installed_shell_observation_macos.rs").read_text()
        helper = PATH.read_text()
        callback = rust.split('unsafe extern "C" fn open_admission<', 1)[1].split('unsafe extern "C" fn open_recheck<', 1)[0]
        ordered = ("context.press.first_return_attempt(after)", "if !matches!(after, 0 | 1)",
                   "(context.admit)(after == 1)", "let now = Instant::now();",
                   "context.press.returned_at = Some(now)", "context.end.saturating_duration_since(now)",
                   "if remaining.is_zero()", "if !allowed", "if after == 0 && required_ns > 0",
                   "context.press.permit = Some((required_ns, now))")
        self.assertEqual([callback.index(item) for item in ordered], sorted(callback.index(item) for item in ordered))
        self.assertEqual(callback.count("Instant::now()"), 1)
        capture = rust.split("struct OpenPressCapture", 1)[1].split("pub struct OpenInputReturn", 1)[0]
        self.assertNotIn("Instant::now()", capture)
        self.assertIn("if after == 1 { self.after_attempted = true; }", capture)
        self.assertIn("checked_duration_since(permitted_at)", capture)
        self.assertIn("u64::try_from(duration.as_nanos()).ok()", capture)
        returned = rust.split("pub fn installed_prompt_button<", 1)[1].split("pub fn installed_accessibility_trusted", 1)[0]
        self.assertLess(returned.index("returned.report = open_return("), returned.index("context.press.timing(returned.report)"))
        self.assertIn("if !press_timing_data_check(failed_press) { return false; }", rust)
        self.assertIn('if !cfg!(panic = "unwind") { return false; }', rust)
        sample = observer.split("impl OpenInputSample", 1)[1].split("struct IdentitySample", 1)[0]
        self.assertIn("self.press_timing = body.native.and_then(|n| n.press_timing);", sample)
        self.assertNotIn("pressDiagnostic", sample.split("fn value(self)", 1)[1])
        encoded = observer.split("fn bounded_failure_context(", 1)[1].split("fn failure_context(", 1)[0]
        self.assertLess(encoded.index("let baseline = edit::bounded(&value, 8192)"), encoded.index("timing.and_then(press_diagnostic_value)"))
        self.assertIn("total <= 8448", encoded)
        self.assertIn("unwrap_or(baseline)", encoded)
        self.assertNotIn(".clone()", encoded)
        self.assertIn("if !press_diagnostic_data_check(full) { return false; }", observer)
        self.assertEqual(helper.count("allow_press_diagnostic=True"), 1)
        self.assertIn("allow_press_diagnostic=False", helper)
        self.assertIn('value["mechanism"] == mechanism', helper)

    def test_ax_failure_source_preserves_original_calls_and_first_status(self):
        # Source and bounded scalar DATA, not an AX emulator, native CaseReturn,
        # worker receipt or proof that a platform operation has executed.
        root = PATH.parents[1]
        native = (root / "native/macos-installed-native/src/native.m").read_text()
        rust = (root / "native/macos-installed-native/src/lib.rs").read_text()
        observer = (root / "src-tauri/src/installed_shell_observation_macos.rs").read_text()
        operation_names = ("NONE", "SET_MESSAGING_TIMEOUT", "COPY_ATTRIBUTE_VALUE", "GET_ATTRIBUTE_VALUE_COUNT",
                           "COPY_ATTRIBUTE_VALUES", "COPY_ACTION_NAMES", "IS_ATTRIBUTE_SETTABLE",
                           "SET_ATTRIBUTE_VALUE", "PERFORM_ACTION", "COPY_MULTIPLE_ATTRIBUTE_VALUES")
        attribute_names = ("NONE", "PARENT", "ROLE", "IDENTIFIER", "TITLE", "VALUE", "ENABLED", "WINDOWS",
                           "CHILDREN", "ROWS", "SELECTED_CHILDREN", "SELECTED_ROWS")
        for prefix, names in (("MRK_AX_OP_", operation_names), ("MRK_AX_ATTR_", attribute_names)):
            actual = M.re.findall(r"\b(" + prefix + r"[A-Z_]+) = ([0-9]+)", native)
            self.assertEqual(actual, [(prefix + name, str(code)) for code, name in enumerate(names)])
        operations = rust.split("const AX_FAILURE_OPERATIONS: [&str; 9] = [", 1)[1].split("];", 1)[0]
        attributes = rust.split("const AX_FAILURE_ATTRIBUTES: [Option<&str>; 12] = [", 1)[1].split("];", 1)[0]
        self.assertEqual(tuple(M.re.findall(r'"([^"]+)"', operations)), M.ACCESSIBILITY_AX_FAILURE_OPERATIONS)
        self.assertEqual((None, *M.re.findall(r'Some\("([^"]+)"\)', attributes)), M.ACCESSIBILITY_AX_FAILURE_ATTRIBUTES)
        self.assertEqual(attributes.count("None"), 1)
        self.assertIn("uint32_t ax_failure_operation, ax_failure_attribute;", native)
        self.assertIn("selection_limit_observed: i64, ax_failure_operation: u32, ax_failure_attribute: u32", rust)
        self.assertIn("sizeof(MRKOpenResult) == 704 && sizeof(MRKOpenRecheck) == 48", native)
        self.assertIn("std::mem::size_of::<OpenWire>() != 704", rust)
        for field, offset in (("selection_limit_observed", 96), ("ax_failure_operation", 104), ("ax_failure_attribute", 108),
                              ("selection_summary_version", 112), ("selection_table_roles", 116), ("selection_outline_roles", 120),
                              ("selection_list_roles", 124), ("selection_entry_roots", 128), ("selection_title_present", 132),
                              ("selection_title_absent", 136), ("selection_value_present", 140), ("selection_outside_entry_role_mask", 144)):
            self.assertIn(f"offsetof(MRKOpenResult, {field}) == {offset}", native)
            self.assertIn(f"std::mem::offset_of!(OpenWire, {field}) != {offset}", rust)
        self.assertIn("std::mem::size_of::<RecheckWire>() != 48", rust)
        status = native.split("static BOOL mrk_ax_status(", 1)[1].split("static MRKPromptOwned *mrk_ax_slot(", 1)[0]
        self.assertTrue(status.startswith(
            "MRKPrompt *s, AXError error, uint32_t operation_code, uint32_t attribute_code) {\n"
            "    if (error == kAXErrorSuccess) return YES;\n"))
        latch = status.split("    if (!s->result.ax_error) {\n", 1)[1].split("\n    }", 1)[0]
        self.assertEqual(latch, "        s->result.ax_error = error;\n"
                               "        s->result.ax_failure_operation = operation_code;\n"
                               "        s->result.ax_failure_attribute = attribute_code;")
        assignments = M.re.findall(r"s->result\.(\w+) = (\w+);", latch)
        self.assertEqual(assignments, [("ax_error", "error"), ("ax_failure_operation", "operation_code"),
                                       ("ax_failure_attribute", "attribute_code")])
        for field, _ in assignments:
            self.assertEqual(native.count("s->result." + field + " ="), 1)
        self.assertLess(status.index("return YES;"), status.index("if (!s->result.ax_error)"))
        self.assertLess(status.index("s->result.ax_failure_attribute ="), status.index("switch (error)"))
        failed = native.split("static BOOL mrk_ax_fail(", 1)[1].split("static BOOL mrk_ax_selecting(", 1)[0]
        self.assertEqual(failed, "MRKPrompt *s, uint32_t error) {\n"
                                 "    if (!s->result.error) s->result.error = error;\n"
                                 "    return NO;\n}\n")
        latch_field = M.re.search(r"if \(!s->result\.(\w+)\) \{", status).group(1)
        overall_field = M.re.search(r"if \(!s->result\.(\w+)\) s->result\.\1 = error;", failed).group(1)

        def scalar_status(state, code, operation, attribute, mapped_error):
            # Replay ONLY the exact source-bound guards/three scalar assignments.
            if code == 0:
                return True
            if not state[latch_field]:
                incoming = {"error": code, "operation_code": operation, "attribute_code": attribute}
                for field, parameter in assignments:
                    state[field] = incoming[parameter]
            if not state[overall_field]:
                state[overall_field] = mapped_error
            return False

        empty = dict(error=0, ax_error=0, ax_failure_operation=0, ax_failure_attribute=0)
        state = deepcopy(empty)
        self.assertTrue(scalar_status(state, 0, 2, 1, 0))
        self.assertEqual(state, empty)
        self.assertFalse(scalar_status(state, -25204, 2, 1, 11))
        first = dict(error=11, ax_error=-25204, ax_failure_operation=2, ax_failure_attribute=1)
        self.assertEqual(state, first)
        self.assertFalse(scalar_status(state, -25202, 3, 9, 10))
        self.assertEqual(state, first)
        self.assertFalse(scalar_status(state, -25204, 2, 2, 11))
        self.assertEqual(state, first)
        self.assertTrue(scalar_status(state, 0, 8, 0, 0))
        self.assertEqual(state, first)
        deadline = dict(empty, error=8)
        self.assertTrue(scalar_status(deadline, 0, 1, 0, 0))
        self.assertEqual(deadline, dict(empty, error=8))
        self.assertFalse(scalar_status(deadline, -25204, 2, 2, 11))
        self.assertEqual(deadline, dict(error=8, ax_error=-25204, ax_failure_operation=2, ax_failure_attribute=2))
        batch = dict(empty, error=8)
        self.assertFalse(scalar_status(batch, -25204, 9, 0, 11))
        batch_first = dict(error=8, ax_error=-25204, ax_failure_operation=9, ax_failure_attribute=0)
        self.assertEqual(batch, batch_first)
        self.assertFalse(scalar_status(batch, -25202, 2, 1, 10))
        self.assertEqual(batch, batch_first)  # Never invent a component attribute for the earlier batch.
        copy = native.split("static CFTypeRef mrk_ax_copy(", 1)[1].split("static CFArrayRef mrk_ax_array(", 1)[0]
        absent_line = "BOOL absent = optional && !slot->value && (status == kAXErrorNoValue || status == kAXErrorAttributeUnsupported);"
        self.assertIn(absent_line, copy)
        self.assertIn("BOOL returned = absent || mrk_ax_status(s, status, MRK_AX_OP_COPY_ATTRIBUTE_VALUE, attribute_code),", copy)
        absent_statuses = tuple(M.re.findall(r"status == (kAXError\w+)", absent_line))
        self.assertEqual(absent_statuses, ("kAXErrorNoValue", "kAXErrorAttributeUnsupported"))

        def copy_status(state, optional, value_present, status_name, code, mapped_error):
            absent = optional and not value_present and status_name in absent_statuses
            return absent or scalar_status(state, code, 2, 4, mapped_error)

        for name, code in (("kAXErrorNoValue", -25212), ("kAXErrorAttributeUnsupported", -25205)):
            state = deepcopy(empty)
            self.assertTrue(copy_status(state, True, False, name, code, 4))
            self.assertEqual(state, empty)
        state = deepcopy(empty)
        self.assertFalse(copy_status(state, True, False, "kAXErrorCannotComplete", -25204, 11))
        self.assertEqual(state, dict(error=11, ax_error=-25204, ax_failure_operation=2, ax_failure_attribute=4))

        def expressions(name_pattern):
            result = []
            for match in M.re.finditer(r"\b" + name_pattern + r"\(", native):
                at, depth = match.end(), 1
                while at < len(native) and depth:
                    depth += (native[at] == "(") - (native[at] == ")")
                    at += 1
                self.assertEqual(depth, 0)
                result.append(native[match.start():at])
            return result

        self.assertEqual(expressions(r"AXUIElement[A-Za-z]+"), [
            "AXUIElementSetMessagingTimeout(element, timeout.seconds)",
            "AXUIElementCopyAttributeValue(element, attribute, &slot->value)",
            "AXUIElementGetAttributeValueCount(element, attribute, &expected)",
            "AXUIElementCopyAttributeValues(element, attribute, 0, limit + 1, &slot->array)",
            "AXUIElementCopyMultipleAttributeValues(element, s->selection_attributes,\n"
            "        kAXCopyMultipleAttributeOptionStopOnError, &slot->array)",
            "AXUIElementCopyActionNames(button, &slot->array)",
            "AXUIElementGetAttributeValueCount(node, kAXChildrenAttribute, &expected)",
            "AXUIElementCopyAttributeValues(node, kAXChildrenAttribute, 0, MRK_SELECT_ROWS + 1, &slot->array)",
            "AXUIElementIsAttributeSettable(container, attribute, &settable)",
            "AXUIElementSetAttributeValue(container, attribute, selected->array)",
            "AXUIElementGetTypeID()", "AXUIElementCreateApplication(getpid())",
            "AXUIElementPerformAction(button, kAXPressAction)",
        ])
        self.assertEqual(expressions("mrk_ax_status")[1:], [
            "mrk_ax_status(s, AXUIElementSetMessagingTimeout(element, timeout.seconds), MRK_AX_OP_SET_MESSAGING_TIMEOUT, MRK_AX_ATTR_NONE)",
            "mrk_ax_status(s, status, MRK_AX_OP_COPY_ATTRIBUTE_VALUE, attribute_code)",
            "mrk_ax_status(s, count_status, MRK_AX_OP_GET_ATTRIBUTE_VALUE_COUNT, attribute_code)",
            "mrk_ax_status(s, status, MRK_AX_OP_COPY_ATTRIBUTE_VALUES, attribute_code)",
            "mrk_ax_status(s, status, MRK_AX_OP_COPY_MULTIPLE_ATTRIBUTE_VALUES, MRK_AX_ATTR_NONE)",
            "mrk_ax_status(s, status, MRK_AX_OP_COPY_ACTION_NAMES, MRK_AX_ATTR_NONE)",
            "mrk_ax_status(s, status, MRK_AX_OP_GET_ATTRIBUTE_VALUE_COUNT, MRK_AX_ATTR_CHILDREN)",
            "mrk_ax_status(s, status, MRK_AX_OP_COPY_ATTRIBUTE_VALUES, MRK_AX_ATTR_CHILDREN)",
            "mrk_ax_status(s, status, MRK_AX_OP_IS_ATTRIBUTE_SETTABLE, attribute_code)",
            "mrk_ax_status(s, status, MRK_AX_OP_SET_ATTRIBUTE_VALUE, attribute_code)",
            "mrk_ax_status(s, status, MRK_AX_OP_PERFORM_ACTION, MRK_AX_ATTR_NONE)",
        ])
        for helper, count in (("mrk_ax_copy", 12), ("mrk_ax_array", 6), ("mrk_ax_equal_attribute", 8),
                              ("mrk_ax_selection_pair", 2), ("mrk_ax_selection_label", 3)):
            self.assertEqual(len(expressions(helper)), count)  # One definition and only these closed uses.
        for call, count in (
            ("mrk_ax_copy(s, element, attribute, NO, attribute_code)", 1),
            ("mrk_ax_array(s, app, kAXWindowsAttribute, 4, NO, MRK_AX_ATTR_WINDOWS)", 1),
            ("mrk_ax_copy(s, candidate, kAXIdentifierAttribute, NO, MRK_AX_ATTR_IDENTIFIER)", 1),
            ("mrk_ax_array(s, found_parent, kAXChildrenAttribute, 16, NO, MRK_AX_ATTR_CHILDREN)", 1),
            ("mrk_ax_copy(s, candidate, kAXRoleAttribute, NO, MRK_AX_ATTR_ROLE)", 1),
            ("mrk_ax_equal_attribute(s, found_sheet, kAXIdentifierAttribute, panel_text, MRK_AX_ATTR_IDENTIFIER)", 1),
            ("mrk_ax_equal_attribute(s, found_sheet, kAXParentAttribute, found_parent, MRK_AX_ATTR_PARENT)", 1),
            ("mrk_ax_equal_attribute(s, node, kAXParentAttribute, pass->nodes[pass->parents[at]], MRK_AX_ATTR_PARENT)", 1),
            ("mrk_ax_copy(s, node, kAXRoleAttribute, NO, MRK_AX_ATTR_ROLE)", 3),
            ("mrk_ax_copy(s, node, kAXTitleAttribute, YES, MRK_AX_ATTR_TITLE)", 1),
            ("mrk_ax_array(s, node, kAXChildrenAttribute, 16, at != 0, MRK_AX_ATTR_CHILDREN)", 1),
            ("mrk_ax_equal_attribute(s, node, kAXParentAttribute, at ? original->nodes[original->parents[at]] : parent, MRK_AX_ATTR_PARENT)", 1),
            ("mrk_ax_equal_attribute(s, button, kAXTitleAttribute, prompt, MRK_AX_ATTR_TITLE)", 1),
            ("mrk_ax_copy(s, button, kAXEnabledAttribute, NO, MRK_AX_ATTR_ENABLED)", 1),
            ("mrk_ax_copy(s, node, attribute, YES, attribute_code)", 1),
            ("mrk_ax_copy(s, p->nodes[at], attribute, optional, attribute_code)", 1),
            ("mrk_ax_selection_pair(s, node, p->nodes[p->parents[at]])", 1),
            ("mrk_ax_selection_label(s, p, at, kAXValueAttribute, NO, expected, MRK_AX_ATTR_VALUE)", 1),
            ("mrk_ax_selection_label(s, p, at, kAXTitleAttribute, YES, expected, MRK_AX_ATTR_TITLE)", 1),
            ("mrk_ax_equal_attribute(s, p->nodes[at], kAXParentAttribute, at ? p->nodes[p->parents[at]] : parent, MRK_AX_ATTR_PARENT)", 1),
            ("mrk_ax_copy(s, p->nodes[at], kAXRoleAttribute, NO, MRK_AX_ATTR_ROLE)", 1),
            ("mrk_ax_equal_attribute(s, p->nodes[p->label], p->label_attribute, expected, p->label_attribute_code)", 1),
            ("mrk_ax_array(s, container, attribute, MRK_SELECT_ROWS, NO, attribute_code)", 1),
        ):
            self.assertEqual(native.count(call), count, call)
        self.assertIn("rows || list ? MRK_SELECT_ROWS : 16, at != 0, rows ? MRK_AX_ATTR_ROWS : MRK_AX_ATTR_CHILDREN", native)
        self.assertIn("CFStringRef label_attribute;", native)
        self.assertIn("uint32_t label_attribute_code;", native)
        self.assertIn("if (s->result.selection_matches == 1) { p->candidate = entry; p->label = at; "
                      "p->label_attribute = attribute; p->label_attribute_code = attribute_code; }", native)
        self.assertIn("if (s->result.selection_flags || s->result.selection_checks != 3 || !p->candidate || !p->label || !p->label_attribute) {", native)
        self.assertIn("if (!attribute) return mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED);\n"
                      "    uint32_t attribute_code = kind == MRK_SELECT_LIST ? MRK_AX_ATTR_SELECTED_CHILDREN : MRK_AX_ATTR_SELECTED_ROWS;", native)
        # The pre-existing selection attribute wire stays1/2, not new AX tag11/10.
        self.assertIn("s->result.selection_attribute = kind == MRK_SELECT_LIST ? 2u : 1u;", native)
        decoder = rust.split("fn ax_failure_return(", 1)[1].split("/// Finite actual AX/CF DATA", 1)[0]
        self.assertIn("if w.ax_error == 0", decoder)
        self.assertIn("(w.ax_failure_operation == 0 && w.ax_failure_attribute == 0).then_some(None)", decoder)
        self.assertIn("(1 | 5 | 8 | 9, 0) | (2, 1..=6) | (3 | 4, 7..=11) | (6 | 7, 10 | 11)", decoder)
        self.assertIn("ax_failure: ax_failure_return(w)?", rust)
        self.assertIn("self.ax_error == 0 && self.ax_failure.is_none()", rust)
        self.assertIn("|| !ax_failure_data_check()", rust)
        self.assertIn("r.diagnostic.error == \"deadline\" && r.button.ax_error == -25204", rust)
        self.assertIn("ax_error: 0, ax_failure_operation: 0, ax_failure_attribute: 0,\n            selection_flags: 7, ..write", rust)
        serializer = observer.split("fn prompt_button_value(", 1)[1].split("struct OpenActionReceipt", 1)[0]
        self.assertIn('"axError":p.ax_error', serializer)
        self.assertIn('"axFailure":p.ax_failure.map(|f| json!({"operation":f.operation,"attribute":f.attribute}))', serializer)

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
                    if path == ("promptButton", "axError"):
                        target["axFailure"] = {"operation": "copy-attribute-value", "attribute": "Parent"}
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
        no["accessibility"]["promptButton"].update(axError=-25204,
            axFailure={"operation": "perform-action", "attribute": None})
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
            lastRole="ScrollArea", lastDepth=8, cfSlots=256, cfSlotsRetired=256, cleanupReturned=False, axError=-25214,
            axFailure={"operation": "get-attribute-value-count", "attribute": "SelectedChildren"})
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
        diagnostics = ((None, None),) + tuple((origin, code) for origin in M._BOOTSTRAP_DIAGNOSTIC_ORIGINS
                                              for code in M._BOOTSTRAP_DIAGNOSTIC_CODES)
        for origin, code in diagnostics:
            expected = {"origin": origin, "code": code} if origin is not None else None
            for duplicate in (False, True):
                with self.subTest(origin=origin, code=code, repeated_identical_frame=duplicate), \
                        inert_exception_owner(duplicate=duplicate) as call:
                    if expected is not None:
                        call.engine.outputs[1].extend(
                            ("MRKDBG_DESKTOP_BOOTSTRAP=capabilities-" + origin + "-" + code + "\n").encode("ascii"))
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
                    self.assertEqual(report["innerBootstrapDiagnostic"], expected)
                    self.assertEqual(report["innerDiagnosticSource"], "original-exception-buffer")
                    self.assertEqual((report["innerDiagnosticCompleteness"], report["invocationFinality"]), ("unknown", "unknown"))
                    self.assertEqual(report["innerOutput"], "unavailable")
                    self.assertIsNone(report["appReturncode"])
                    self.assertFalse(report["originalCallReturned"])
                    output = io.StringIO(); M.emit_record(report, output)
                    for private in ("PRIVATE", M.EXECUTABLE, "MRKDBG_DESKTOP_BOOTSTRAP", "capabilities-"):
                        self.assertNotIn(private, output.getvalue())

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
        marker = b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-runtime_unavailable\n"
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), inert_exception_owner() as call:
                call.engine.outputs[1].extend(marker)
                mutation(call)
                fixtures = InertFixtures()
                with self.assertRaises(RuntimeError) as caught:
                    M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
                self.assertIs(caught.exception, call.original)
                self.assertIsNone(fixtures.inner_diagnostic_source)
                self.assertIsNone(fixtures.inner_failure_step)
                self.assertIsNone(fixtures.inner_bootstrap_diagnostic)
                self.assertIsNone(M.diagnostic(caught.exception, None, fixtures)["innerBootstrapDiagnostic"])
                self.assertEqual((fixtures.before, fixtures.reads, fixtures.inflight, fixtures.last_returned),
                                 (["first-save"], [], True, False))
        with inert_exception_owner() as call, patch.object(M, "TRACEBACK_LIMIT", 1):
            call.engine.outputs[1].extend(marker)
            fixtures = InertFixtures()
            with self.assertRaises(RuntimeError) as caught:
                M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
            self.assertIsNone(fixtures.inner_diagnostic_source)
            self.assertIsNone(fixtures.inner_bootstrap_diagnostic)
            self.assertIs(caught.exception, call.original)

    def test_exception_partial_absent_or_parser_failure_stays_unavailable(self):
        good = b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-admission-runtime_unavailable\n"
        other = b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-cleanup_unknown\n"
        prefix = b"MRKDBG_DESKTOP_BOOTSTRAP"
        ordinary = (
            b"MRKDBG_DESKTOP_BOOTSTRAP=setup-enter\n",
            b"MRKDBG_DESKTOP_BOOTSTRAP=page-start-trusted\n",
            b"MRKDBG_DESKTOP_BOOTSTRAP=page-finish-trusted\n",
            b"MRKDBG_DESKTOP_BOOTSTRAP=app-info-enter\n",
            b"MRKDBG_DESKTOP_BOOTSTRAP=catalog-enter\n",
            b"MRKDBG_DESKTOP_BOOTSTRAP=page-start-untrusted\n",
            b"MRKDBG_DESKTOP_BOOTSTRAP=page-finish-untrusted\n",
        )
        malformed = (
            good[:-1], prefix, prefix + b"=capabilities-admission-",
            b"PRIVATE " + good, b" " + good, good.replace(b"=", b"= "),
            good.replace(b"\n", b"\r\n"), good.replace(b"\n", b" \n"),
            good.replace(b"\n", b"-PRIVATE\n"), good.replace(b"runtime_unavailable", b"unknown_code"),
            good.replace(b"runtime_unavailable", b"RUNTIME_UNAVAILABLE"),
            good.replace(b"runtime_unavailable", b"\xff"), good.replace(b"=", b"?"),
            prefix + b"=capabilities-cause-selection-profile-closed\n", prefix + b"=PRIVATE\n",
            prefix + b"=setup-enter-extra\n", prefix + b"=hook-installed\n",
            b"PRIVATE " + prefix[:-1],
        )
        malformed += tuple(prefix[:length] for length in range(1, len(prefix)))
        absent = (b"", b"PRIVATE ONLY", b"MRK_MACOS_AQUA_FAILURE_STEP=CancelProject",
                  b"MRK_MACOS_AQUA_FAILURE_REASON=observer-deadline\nMRK_MACOS_AQUA_FAILURE_REASON")
        # Ordinary shell rows are non-authorizing context, not failure facts.
        for context in ordinary:
            with self.subTest(context=context):
                self.assertIsNone(M._inner_bootstrap_diagnostic(b"", context))
                self.assertEqual(M._inner_bootstrap_diagnostic(b"", context + good + context),
                                 {"origin": "admission", "code": "runtime_unavailable"})
                for bad in (context[:-1], b"PRIVATE " + context):
                    self.assertIsNone(M._inner_bootstrap_diagnostic(b"", good + bad))
                    self.assertIsNone(M._inner_bootstrap_diagnostic(b"", bad + good))
        ambiguous = malformed + (good + good, good + other, other + good)
        ambiguous += tuple(good + bad for bad in malformed) + tuple(bad + good for bad in malformed)
        for stderr in absent + ambiguous:
            with self.subTest(stderr=stderr), inert_exception_owner(stderr=stderr) as call:
                fixtures = InertFixtures()
                # No stale prior case's closed marker may cross this original.
                fixtures.inner_bootstrap_diagnostic = {"origin": "query-wait", "code": "busy"}
                with self.assertRaises(RuntimeError) as caught:
                    M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
                self.assertIs(caught.exception, call.original)
                self.assertIsNone(fixtures.inner_diagnostic_source)
                report = M.diagnostic(caught.exception, None, fixtures)
                self.assertIsNone(report["innerBootstrapDiagnostic"])
                self.assertEqual((report["innerDiagnosticCompleteness"], report["invocationFinality"]), ("unknown", "unknown"))
                self.assertFalse(report["originalCallReturned"])
                self.assertIsNone(report["appReturncode"])
                self.assertEqual((fixtures.before, fixtures.reads), (["first-save"], []))
                output = io.StringIO(); M.emit_record(report, output)
                for private in ("PRIVATE", "unknown_code", "MRKDBG_DESKTOP_BOOTSTRAP"):
                    self.assertNotIn(private, output.getvalue())
        with inert_exception_owner(stderr=b"PRIVATE ONLY") as call:
            call.engine.outputs[0].extend(good)  # stderr is the only admitted origin.
            fixtures = InertFixtures()
            with self.assertRaises(RuntimeError) as caught:
                M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
            self.assertIs(caught.exception, call.original)
            self.assertIsNone(fixtures.inner_diagnostic_source)
            self.assertIsNone(fixtures.inner_bootstrap_diagnostic)
        # A complete closed marker alone is useful even if unrelated stderr is
        # partial. The informational rows and private tail never leave here.
        informative = (b"PRIVATE START\n" + b"".join(ordinary[:4])
                       + b"MRK_DESKTOP_CAPABILITIES=PRIVATE\n" + good + b"PRIVATE INCOMPLETE TAIL")
        with inert_exception_owner(stderr=informative) as call:
            fixtures = InertFixtures()
            with self.assertRaises(RuntimeError) as caught:
                M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
            self.assertIs(caught.exception, call.original)
            report = M.diagnostic(caught.exception, None, fixtures)
            self.assertEqual(report["innerBootstrapDiagnostic"], {"origin": "admission", "code": "runtime_unavailable"})
            self.assertEqual((report["innerFailureStep"], report["innerFailureReason"], report["innerFailureContext"]),
                             (None, None, None))
            self.assertEqual(report["innerDiagnosticSource"], "original-exception-buffer")
            self.assertEqual((report["innerDiagnosticCompleteness"], report["invocationFinality"]), ("unknown", "unknown"))
            self.assertFalse(report["originalCallReturned"])
            self.assertIsNone(report["appReturncode"])
            self.assertEqual((fixtures.before, fixtures.reads), (["first-save"], []))
            output = io.StringIO(); M.emit_record(report, output)
            self.assertNotIn("PRIVATE", output.getvalue())
            self.assertNotIn("MRKDBG", output.getvalue())
        for stdout, stderr in ((good, b""), (bytearray(), good), (b"", bytearray(good)),
                               ("", good), (b"", None), (b"x" * M.OUTPUT_LIMIT, good)):
            self.assertIsNone(M._inner_bootstrap_diagnostic(stdout, stderr))
        bounded = b"x" * (M.OUTPUT_LIMIT - len(good) - 1) + b"\n" + good
        self.assertEqual(len(bounded), M.OUTPUT_LIMIT)
        self.assertEqual(M._inner_bootstrap_diagnostic(b"", bounded), {"origin": "admission", "code": "runtime_unavailable"})
        self.assertIsNone(M._inner_bootstrap_diagnostic(b"x", bounded))
        # Scan all available stderr; do not truncate away an ambiguous tail.
        bounded = good + b"x" * (M.OUTPUT_LIMIT - len(good) - len(prefix) - 1) + b"\n" + prefix
        self.assertEqual(len(bounded), M.OUTPUT_LIMIT)
        self.assertIsNone(M._inner_bootstrap_diagnostic(b"", bounded))
        with patch.object(M, "_BOOTSTRAP_DIAGNOSTIC_LINES", None):
            self.assertIsNone(M._inner_bootstrap_diagnostic(b"", good))
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
            self.assertIsNone(fixtures.inner_bootstrap_diagnostic)
            self.assertEqual(fixtures.inner_diagnostic_source, "original-exception-buffer")
        for reducer, message in (("failure_step", "PRIVATE PARSER ERROR"),
                                 ("_inner_bootstrap_diagnostic", "PRIVATE BOOTSTRAP PARSER ERROR"),
                                 ("_original_exception_diagnostics", "PRIVATE SNAPSHOT ERROR")):
            with inert_exception_owner() as call, patch.object(M, reducer, side_effect=ValueError(message)):
                call.engine.outputs[1].extend(good)
                fixtures = InertFixtures()
                with self.assertRaises(RuntimeError) as caught:
                    M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
                self.assertIs(caught.exception, call.original)
                self.assertIsNone(fixtures.inner_diagnostic_source)
                self.assertIsNone(fixtures.inner_bootstrap_diagnostic)
                self.assertTrue(fixtures.inflight)
                self.assertFalse(fixtures.last_returned)
                self.assertEqual((fixtures.before, fixtures.reads), (["first-save"], []))

    def test_failure_reason_diagnostic_does_not_promote_nonzero(self):
        cases = [("CancelProject", "asset_source_refused")] + [("ProjectSettled", reason) for reason in (
            "project-result-path", "project-result-path-app-child", "project-result-path-descendant",
            "project-result-path-ancestor", "project-result-path-sibling", "project-result-path-tmp-spelling",
            "project-result-path-data-spelling")]
        bootstrap = b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-runtime_unavailable\n"
        expected = {"origin": "query-wait", "code": "runtime_unavailable"}
        for step, reason in cases:
            for marker_present in (False, True):
                with self.subTest(step=step, reason=reason, marker_present=marker_present):
                    fixtures, emitted = InertFixtures(), []
                    fixtures.inner_bootstrap_diagnostic = {"origin": "admission", "code": "busy"}
                    marker = (f"MRK_MACOS_AQUA_FAILURE_STEP={step}\n"
                              f"MRK_MACOS_AQUA_FAILURE_REASON={reason}\n").encode("ascii")
                    detail = None
                    if reason in M.PROJECT_SELECTION_BOUND_LOCATIONS:
                        detail = project_selection_context_data(location=sorted(M.PROJECT_SELECTION_BOUND_LOCATIONS[reason])[0])
                        marker += context_row(detail)
                    if marker_present:
                        marker += bootstrap
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
                    self.assertEqual(report["innerBootstrapDiagnostic"], expected if marker_present else None)
                    self.assertEqual(fixtures.before, ["first-save"])
                    self.assertEqual((fixtures.reads, emitted), ([], []))
                    output = io.StringIO(); M.emit_record(report, output)
                    self.assertNotIn("MRKDBG_DESKTOP_BOOTSTRAP", output.getvalue())
        for parser_fault in (False, True):
            fixtures, emitted = InertFixtures(), []
            def runner(argv, **_):
                return CompletedProcess(args=argv, returncode=17, stdout=b"PRIVATE", stderr=bootstrap)
            reducer = ValueError("PRIVATE PARSER ERROR") if parser_fault else M._inner_bootstrap_diagnostic
            with patch.object(M, "_inner_bootstrap_diagnostic", side_effect=reducer), \
                    self.assertRaisesRegex(M.Refused, "^app-return$") as caught:
                M.run_cases(BINDING, fixtures, runner, UID, "runner", emitted.append)
            report = M.diagnostic(caught.exception, None, fixtures)
            self.assertEqual(report["innerBootstrapDiagnostic"], None if parser_fault else expected)
            self.assertEqual((report["innerFailureStep"], report["innerFailureReason"], report["innerFailureContext"]),
                             (None, None, None))
            self.assertEqual(report["appReturncode"], 17)
            self.assertIs(report["originalCallReturned"], True)
            self.assertFalse(fixtures.inflight)
            self.assertEqual((report["innerDiagnosticSource"], report["innerDiagnosticCompleteness"]),
                             ("completed-output", "complete"))
            self.assertEqual((report["invocationFinality"], report["innerOutput"]), ("no-pending-invocation", "not-exported"))
            self.assertEqual(report["typedLifetimeFacts"], [])
            self.assertEqual((fixtures.before, fixtures.reads, emitted), (["first-save"], [], []))
            output = io.StringIO(); M.emit_record(report, output)
            self.assertNotIn("PRIVATE", output.getvalue())
            self.assertNotIn("MRKDBG_DESKTOP_BOOTSTRAP", output.getvalue())
        empty = M.diagnostic(M.Refused("fixture-refused"), None, None)
        self.assertIsNone(empty["innerFailureReason"])
        self.assertIsNone(empty["innerBootstrapDiagnostic"])

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
        self.assertIn('if returned.result != "ok" { self.fail_bootstrap(&mut r, "bootstrap-window-result"); }', body)
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
        self.assertIn("|| !profile.evidence_selection_profile_available() { return false; }", checks)
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
                       "Step::Quit => (self.quit_id(),PanelKind::Quit)",
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
        # Native-return and narrowly scoped input-publication deferrals each keep their original gate.
        self.assertEqual(report.count("r.native_dispatch.is_some_and("), 2)
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
        self.assertIn("BOOL counted = mrk_ax_status(s, count_status, MRK_AX_OP_GET_ATTRIBUTE_VALUE_COUNT, attribute_code)", arrays)
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
        self.assertIn("mrk_ax_array(s, node, kAXChildrenAttribute, 16, at != 0, MRK_AX_ATTR_CHILDREN)", roster)
        no_descend = "if (at && !CFEqual(role, kAXGroupRole) && !CFEqual(role, kAXSplitGroupRole)) continue;"
        self.assertLess(roster.index(no_descend), roster.index("mrk_ax_array("))
        self.assertNotIn("kAXChildrenAttribute", roster.split(no_descend, 1)[0])
        self.assertIn("if (!children) { if (s->result.error) return NO; continue; }", roster)
        self.assertIn("CFEqual(role, kAXButtonRole)", roster)
        self.assertIn("CFEqual(title, prompt)) { matches++; pass->candidate = at; }", roster)
        self.assertIn("for (unsigned previous = 0; previous < queued; ++previous)", roster)
        self.assertIn("previous != at && pass->nodes[previous] && CFEqual(node, pass->nodes[previous])", roster)
        self.assertIn("mrk_ax_equal_attribute(s, node, kAXParentAttribute, pass->nodes[pass->parents[at]], MRK_AX_ATTR_PARENT)", roster)
        # Excluded surfaces need a real typed Role, not ancestry or failure-as-absence.
        # Every eligible Group/SplitGroup/Button retains Parent proof before use.
        classified = [
            "CFTypeRef role = mrk_ax_copy(s, node, kAXRoleAttribute, NO, MRK_AX_ATTR_ROLE);",
            "if (!role || !mrk_ax_type(s, role, CFStringGetTypeID())) return NO;",
            "pass->roles[at] = s->result.last_role = mrk_ax_role(role);",
            "if (!at && pass->roles[at] != MRK_ROLE_SHEET) return mrk_ax_fail(s, MRK_OPEN_CHANGED);",
            "if (at && !CFEqual(role, kAXGroupRole) && !CFEqual(role, kAXSplitGroupRole)\n"
            "            && !CFEqual(role, kAXButtonRole)) continue;",
            "if (at && !mrk_ax_equal_attribute(s, node, kAXParentAttribute, pass->nodes[pass->parents[at]], MRK_AX_ATTR_PARENT)) return NO;",
            "if (CFEqual(role, kAXButtonRole)) {",
            "mrk_ax_array(s, node, kAXChildrenAttribute, 16, at != 0, MRK_AX_ATTR_CHILDREN)",
        ]
        positions = [roster.index(item) for item in classified]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(roster.count("kAXParentAttribute"), 1)
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
        self.assertIn("if (!mrk_ax_equal_attribute(s, node, kAXParentAttribute, at ? original->nodes[original->parents[at]] : parent, MRK_AX_ATTR_PARENT)) return NO;", path)
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
        self.assertEqual(action.count("mrk_ax_projection("), 3)
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
        self.assertIn("const unsigned cap = s->result.selection_mode == 1 ? MRK_SELECT_CALLS : MRK_PROMPT_CALLS;", timeout)
        self.assertIn("used > cap - 2", timeout)
        self.assertIn("timeout.seconds <= 0", timeout)
        self.assertIn("timeout.required_ns > 100000000", timeout)
        self.assertLess(timeout.index("AXUIElementSetMessagingTimeout"), timeout.index("mrk_ax_admit(s, timeout.required_ns"))
        reuse_gate = timeout.split("BOOL reuse = ", 1)[1].split(";", 1)[0]
        self.assertEqual(reuse_gate,
                         "s->result.selection_mode == 1 && s->timeout_element == element\n"
                         "        && s->installed_timeout.required_ns && s->installed_timeout.required_ns <= timeout.required_ns")
        self.assertLess(timeout.index("mrk_ax_admit(s, 0, 0, &timeout)"), timeout.index("BOOL reuse"))
        self.assertLess(timeout.index("timeout.required_ns != (uint64_t)ceil"), timeout.index("BOOL reuse"))
        reuse_start = timeout.index("if (reuse) timeout = s->installed_timeout;")
        common_admission = timeout.index("BOOL admitted = mrk_ax_admit(s, timeout.required_ns, 0, NULL);")
        refresh = timeout[reuse_start:timeout.index("    // BOTH paths")]
        self.assertIn("else {\n        s->timeout_element = NULL; s->installed_timeout = (MRKOpenTimeout){0};", refresh)
        self.assertLess(refresh.index("s->timeout_element = NULL"), refresh.index("AXUIElementSetMessagingTimeout"))
        self.assertLess(refresh.index("s->result.calls++"), refresh.index("AXUIElementSetMessagingTimeout"))
        self.assertIn("if (installed && s->result.selection_mode == 1) {\n"
                      "            s->timeout_element = element; s->installed_timeout = timeout;", refresh)
        self.assertNotIn("return ", refresh)  # Neither reuse nor refresh can bypass the common fresh permit.
        self.assertLess(timeout.index("    // BOTH paths"), common_admission)
        self.assertEqual(timeout.count("mrk_ax_admit("), 2)
        self.assertEqual(timeout.count("s->result.calls++"), 1)
        self.assertIn("return installed && admitted;", timeout)
        for forbidden in ("CFEqual(", "while (", "for (", "AXUIElementCreateSystemWide"):
            self.assertNotIn(forbidden, timeout)
        # Truth table for the exact source-bound scalar predicate, not an AX
        # endpoint, setter result, clock observation, native call or permit.
        for selection_mode, same_pointer, cached_ns, allowance_ns, expected in (
            (0, True, 10, 10, False), (1, True, 10, 10, True),
            (1, False, 10, 10, False), (1, True, 0, 10, False),
            (1, True, 11, 10, False), (1, True, 9, 10, True),
            (2, True, 10, 10, False), (1, True, 1, 0, False),
        ):
            with self.subTest(selection_mode=selection_mode, same_pointer=same_pointer,
                              cached_ns=cached_ns, allowance_ns=allowance_ns):
                actual = bool(selection_mode == 1 and same_pointer and cached_ns and cached_ns <= allowance_ns)
                self.assertIs(actual, expected)
        entry = native.split("void mrk_observation_prompt_press(", 1)[1]
        borrowed_clear = "s->selection_attributes = NULL; s->timeout_element = NULL; s->installed_timeout = (MRKOpenTimeout){0};"
        self.assertLess(entry.index(borrowed_clear), entry.index("s->result.owned = s->count;"))
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
                f"if (mrk_ax_selecting(s)) mrk_ax_selection_limit(s, MRK_SELECT_LIMIT_CHILD_{site}, {count}, (uint32_t)limit, 0);\n"
                f"        else mrk_ax_control_limit(s, MRK_OPEN_CONTROL_CHILD_{site}_LIMIT);\n        return NULL;")
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
        self.assertTrue("sizeof(MRKOpenResult) == 704 && sizeof(MRKOpenRecheck) == 48" in native,
                        "native selection/Open wire704B and unchanged recheck48B")
        self.assertTrue("std::mem::size_of::<OpenWire>() != 704" in rust, "Rust selection/Open wire must be704B")
        self.assertIn("offsetof(MRKOpenResult, selection_limit_observed) == 96", native)
        self.assertIn("std::mem::offset_of!(OpenWire, selection_limit_observed) != 96", rust)
        for field, offset in (("ax_failure_operation", 104), ("ax_failure_attribute", 108)):
            self.assertIn(f"offsetof(MRKOpenResult, {field}) == {offset}", native)
            self.assertIn(f"std::mem::offset_of!(OpenWire, {field}) != {offset}", rust)
        self.assertIn("std::mem::size_of::<RecheckWire>() != 48", rust)
        self.assertIn("w.checks & (w.checks + 1) != 0", wire)
        # Whole-call limits come from the validated frozen identity, not the wire.
        for bound in ("const SELECT_CALLS: u32 = 3072;", "const SELECT_CF: u32 = 1024;"):
            self.assertIn(bound, rust)
        limits = rust.split("fn prompt_limits(selecting: bool) -> (u32, u32) {", 1)[1].split("\n    }", 1)[0]
        self.assertEqual(limits.strip(), "if selecting { (SELECT_SAMPLES * SELECT_CALLS, SELECT_SAMPLES * SELECT_CF) } else { (512, 256) }")
        invoke = rust.split("pub fn installed_prompt_button<", 1)[1].split("pub fn installed_accessibility_trusted(", 1)[0]
        valid = "if main_thread() || !identity.valid() { return returned; }"
        original_return = "returned.report = open_return(wire, context.rechecks, context.custody_known, identity.selection);"
        self.assertLess(invoke.index(valid), invoke.index("mrk_observation_prompt_press("))
        self.assertIn("u32::from(identity.selection), open_admission::<F, G>, open_recheck::<F, G>", invoke)
        self.assertLess(invoke.index("mrk_observation_prompt_press("), invoke.index(original_return))
        mode_guard = ("if w.selection_mode != u32::from(selecting) || !selecting && (rechecks[0].is_some()\n"
                      "            || w.selection_checks != 0 || w.selection_flags != 0 || w.selection_nodes != 0 || w.selection_matches != 0\n"
                      "            || w.selection_attribute != 0 || w.selection_last_role != 0 || w.selection_depth != 0 || w.site > 19\n"
                      "            || w.selection_limit != 0 || w.selection_limit_cap != 0 || w.selection_limit_queued != 0\n"
                      "            || w.selection_limit_children != 0 || w.selection_limit_observed != 0\n"
                      "            || w.selection_summary_version != 0 || w.selection_table_roles != 0 || w.selection_outline_roles != 0\n"
                      "            || w.selection_list_roles != 0 || w.selection_entry_roots != 0 || w.selection_title_present != 0\n"
                      "            || w.selection_title_absent != 0 || w.selection_value_present != 0\n"
                      "            || w.selection_outside_entry_role_mask != 0 || w.selection_fixture_label_mask != 0\n"
                      "            || w.selection_expected_label_relations != 0 || w.selection_expected_label_role_mask != 0\n"
                      "            || w.selection_sample != 0 || w.selection_calls_before != 0 || w.selection_cf_before != 0 || w.selection_wait != 0\n"
                      "            || w.selection_pending != [[0; 16]; 7] || w.selection_projection_diagnostic != [0; 20]) { return None; }")
        choose_limits = "let (calls, slots) = prompt_limits(selecting);"
        self.assertEqual(wire.count(choose_limits), 1)
        self.assertLess(wire.index(mode_guard) + len(mode_guard), wire.index(choose_limits))
        self.assertIn("selection_mode: selecting, selection,", wire)
        self.assertIn("w.calls > calls || w.initial_nodes_examined > 16 || w.recheck_nodes_examined > 16", wire)
        self.assertIn("w.last_depth > 8 || w.owned > slots || w.released > w.owned", wire)
        proof = rust.split("impl ControlContainerButtonProof {", 1)[1].split("\n    }", 1)[0]
        self.assertIn("pub fn matched(self) -> bool { self.matched_for_mode(false) }", proof)
        match_mode = proof.split("fn matched_for_mode(self, selecting: bool) -> bool {", 1)[1]
        self.assertIn(choose_limits, match_mode)
        self.assertIn("self.checks == [true; 7] && (1..=calls).contains(&self.calls)", match_mode)
        self.assertIn("&& (1..=slots).contains(&self.cf_slots) && self.cf_slots_retired == self.cf_slots", match_mode)
        self.assertIn("&& self.cleanup_returned && self.ax_error == 0 && self.ax_failure.is_none()", match_mode)
        report = rust.split("impl OpenReport {", 1)[1].split("fn open_return(", 1)[0]
        self.assertIn("self.button.matched_for_mode(self.selection_mode)", report)
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
        for binding in (BINDING, replace(BINDING, target=M.INTEL_TARGET)):
            fixtures, calls, emitted = InertFixtures(), [], []
            def runner(argv, **kwargs):
                calls.append((argv, kwargs))
                return CompletedProcess(args=argv, returncode=0, stdout=captured(M.expected_result(binding, argv[1])), stderr=b"")
            with patch.dict(M.os.environ, {"GITHUB_TOKEN": "not-a-token", "HTTPS_PROXY": "not-a-proxy", "HOME": "/not-used"}):
                M.run_cases(binding, fixtures, runner, UID, "runner", emitted.append)
            self.assertEqual(fixtures.before, list(M.CASES))
            self.assertEqual(fixtures.reads, list(M.CASES))
            self.assertEqual(len(emitted), 4)
            for (argv, options), case in zip(calls, M.CASES):
                self.assertEqual(argv, [M.EXECUTABLE, case])
                self.assertEqual({key: options[key] for key in ("timeout", "capture", "text", "output_limit")},
                                 {"timeout": 60, "capture": True, "text": False, "output_limit": 2 * 1024 * 1024})
                self.assertEqual(options["cwd"], binding.root() / "state" / case)
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
        self.assertIn('all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))', shared_cfg)
        early = observer.split("fn observer_data_checks()", 1)[1].split("fn observe(q:", 1)[0]
        self.assertIn("crate::runtime::assert_installed_session_selection_contract();", early)
        platform_gate = document.split("fn ordinary_asset_platform_gate()", 1)[1].split("fn session_kind_gate(", 1)[0]
        project_contract = document.split("pub(crate) fn assert_project_selection_gate_contract()", 1)[1].split("\n}", 1)[0]
        supported = 'cfg!(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),\n        all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")),\n        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))'
        self.assertIn("if !" + supported, platform_gate)
        self.assertIn("let platform = if " + supported, project_contract)
        self.assertIn("assert_eq!(ordinary_asset_platform_gate().err().map(|error| error.reason), platform);", project_contract)
        self.assertIn("crate::asset_session::assert_project_selection_gate_contract();", early)

        normal = owner.split("fn ios_installed_selected(", 1)[1].split("fn android_original_document_matches(", 1)[0]
        for term in ('self.domain == SavedCommandDomain::IOSArchive', 'feature = "desktop-shell"',
                     'feature = "custom-protocol"', 'not(feature = "development-runtime")',
                     'not(feature = "ubuntu-runtime-publisher")', 'not(feature = "windows-runtime-publisher")',
                     'not(feature = "macos-installed-installer")', 'not(feature = "macos-android-registration-helper")',
                     'target_os = "macos"', '&& ios_wire::Profile::current().is_some()',
                     '&& self.runtime.ios_archive_installed_profile_available()'):
            self.assertIn(term, normal)
        for forbidden in ("ios_observation", "IOS_ARCHIVE_NATIVE_QUALIFIED"):
            self.assertNotIn(forbidden, normal)
        for name in ("IOS_SIGNED_NATIVE_QUALIFIED", "IOS_RECOVERY_NATIVE_QUALIFIED"):
            self.assertNotIn(f"const {name}:", owner)
        selection = owner.split("fn ios_mode_selection(", 1)[1].split("const IOS_WORK", 1)[0]
        self.assertIn("if !installed { return ios_wire::ModeCapabilities::NONE; }", selection)
        self.assertIn("observed.unwrap_or(ios_wire::ModeCapabilities { unsigned: true, signed: true, recovery: true })", selection)
        qualified = owner.split("fn qualified(", 1)[1].split("fn lock(&self)", 1)[0]
        self.assertIn("if let Some(observation) = book.as_ref()", qualified)
        self.assertIn("let modes = self.ios_observed_mode_capabilities(observation);", qualified)
        self.assertIn("return modes.unsigned || modes.signed || modes.recovery;", qualified)
        self.assertNotIn("observation.control.permits_mode(", qualified)
        self.assertIn("SavedCommandDomain::IOSArchive => self.ios_installed_selected()", qualified)
        mode = owner.split("fn ios_mode_qualified(", 1)[1].split("fn start_clocks(", 1)[0]
        self.assertIn("(Some(owner), Some(bound)) => std::ptr::eq(bound.original.as_ref(), owner)", mode)
        self.assertIn("return same_original && self.ios_observed_mode_capabilities(observation).supports(selected.operation)", mode)
        self.assertIn("ios_mode_selection(self.ios_installed_selected(), None).supports(selected.operation)", mode)

        sample = document.split("pub(crate) fn observe_installed_macos_normal_selection(", 1)[1].split("pub(crate) fn register_installed_macos_session(", 1)[0]
        self.assertIn("if observation.is_some()", sample)
        self.assertIn("supervisor.assert_installed_session_available(&self.inner.session_identity)?", sample)
        self.assertIn("self.inner.bridge.ios_archive.observe_installed_unsigned_selection()", sample)
        owner_sample = owner.split("pub(crate) fn observe_installed_unsigned_selection(", 1)[1].split("pub(crate) fn admit_installed_ios_observation(", 1)[0]
        for gate in ("r.revision != 0", "r.active.is_some()", "r.prepared.is_some()", "r.last.is_some()",
                     "r.document_lost", "r.exhausted", "self.inner.poisoned.load", "!self.inner.ios_installed_selected()", "if slot.is_some()"):
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

        methods = M.re.search(r'const METHODS: \[&str; 14\] = \[(.*?)\];', observer, M.re.S)
        self.assertIsNotNone(methods)
        names = M.re.findall(r'"([a-z.]+)"', methods.group(1))
        self.assertEqual(len(names), 14)
        self.assertEqual(len(set(names)), 14)
        self.assertEqual(names.count("credentials.assess"), 1)
        # Compare independent checked-in contracts, not a self-constructed
        # response. Parse core literal DATA without importing the engine.
        syntax = ast.parse((PATH.parents[2] / "src/mobile_release/api/__init__.py").read_text())
        definitions = [node.value for node in syntax.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "METHODS" for target in node.targets)]
        self.assertEqual(len(definitions), 1)
        core_names = ast.literal_eval(definitions[0])
        self.assertEqual(len(core_names), len(names))
        self.assertEqual(set(core_names), set(names))
        passive = runtime.split("fn macos_installed_passive_method(", 1)[1].split("\n}", 1)[0]
        passive_names = M.re.findall(r'"([a-z.]+)"', passive)
        self.assertEqual(len(passive_names), 13)
        self.assertEqual(set(passive_names) | {"credentials.assess"}, set(names))
        self.assertNotIn("credentials.assess", passive_names)
        self.assertIn('installed_passive_method(name) || name == "credentials.assess" && self.installed_session_profile(None)', runtime)
        self.assertIn("fn methods(self) -> usize { METHODS.len() }", observer)
        self.assertIn('methods.iter().filter(available).count() != expected_methods', observer)
        self.assertIn('METHODS.iter().all(|name| methods.iter().filter(available).filter(|m| m["method"].as_str() == Some(*name)).count() == 1)', observer)
        finish = observer.split("fn finish(&self) -> Option<Value>", 1)[1].split("\n}\n\nfn phase(", 1)[0]
        self.assertIn("let normal_registered = self.ios.as_ref().is_some_and(|control| control.normal_session_registered());", finish)
        self.assertEqual(finish.count(".normal_session_registered()"), 1)
        self.assertEqual(finish.count(".report(normal_registered)"), 2)
        self.assertIn("r.session_record.as_ref().is_some_and(|record| record.report(normal_registered).is_some())", finish)
        self.assertIn('report["signingInputs"] = r.session_record.as_ref()?.report(normal_registered)?;', finish)
        ios_arm_start, ios_arm_end = "Case::Ios(case) =>", "\n        };"
        self.assertEqual(finish.count(ios_arm_start), 1)
        ios_tail = finish.split(ios_arm_start, 1)[1]
        self.assertEqual(ios_tail.count(ios_arm_end), 1)
        ios_finish = ios_tail.split(ios_arm_end, 1)[0]
        self.assertTrue(ios_finish.strip())
        self.assertNotIn("record.report().is_some()", ios_finish)
        self.assertIn('"schemaVersion":2,"oneUseOriginalDocumentRegistration":normal_registered', producer)
        self.assertIn('"selection":"ordinary-installed-macos-session"', producer)
        self.assertIn("if !normal_registered ||", producer)
        self.assertIn("signed.report(false).is_some()", producer)
        for case in M.ALL_CASES:
            value = M.expected_result(BINDING, case)
            self.assertEqual(value["methods"], "fourteen-passive-with-session-assessment")
        for case in ("first-save", "ios-unsigned-archive"):
            for old_label in ("nine-passive", "ten-passive-with-session-assessment"):
                old = M.expected_result(BINDING, case); old["methods"] = old_label
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
        self.assertIn("Duration::from_secs(if let Case::Checks(c)=case { c.seconds() } else if let Case::LocalEdits(c)=case { c.seconds() } else if case == Case::Ios(ios::Case::RecoveryPending) { 515 } else if case == Case::PendingRecovery || matches!(case, Case::Ios(c) if !c.input_only()) { 315 } else if matches!(case, Case::Vault(_)) { 120 } else if case == Case::Installation { 80 } else { 45 })", source)
        self.assertIn("!ios::data_checks()", source)
        child = (PATH.parents[1] / "src-tauri/src/installed_shell_observation_macos_ios.rs").read_text()
        data_check = child.split("pub(super) fn data_checks()", 1)[1].split("pub(super) fn snapshot_failure", 1)[0]
        for forbidden in ("Observation::new", "thread::spawn", "tokio::spawn", "std::process::Command", "file_fact("):
            self.assertNotIn(forbidden, data_check)
        self.assertIn("self.admitted.load(Ordering::SeqCst)", child)
        permits = child.split("pub(crate) fn permits(&self)", 1)[1].split("pub(crate) fn claim", 1)[0]
        self.assertNotIn(".record()", permits)
        self.assertNotIn(".lock()", permits)
        self.assertIn("claimed.compare_exchange(before, after, Ordering::SeqCst, Ordering::SeqCst)", child)
        self.assertIn("!self.permits() || !claim_observation_slot(self.case, &self.claimed, index)", child)
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
        self.assertIn('let suffix = if case == Case::ProjectFields { "-project-fields" } else if matches!(case,Case::Vault(_)) { "-vault-helper" } else { "" };', route)
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
        self.assertIs(fields["normalProfileAvailable"], True)
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
                "initialRootAndOptions": {"result": "ok", "facts": mask,
                    "fileFilter": {"facts": 23, "allowedTypes": "unrestricted", "allowsOther": False}
                        if kind == "version-source" else None},
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
            self.assertEqual(action["mechanism"], "accessibility-version-source-selection-press-v8")
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
        # Synthetic current-source DATA only; not a native observation or promised pass.
        for nodes in (49, 50, 64, 127, 128, 255):
            widened = deepcopy(good)
            widened["projectFields"]["acceptedOpenHistories"][1]["selectionInput"]["selection"].update(nodes=nodes)
            with self.subTest(retained_nonroot_nodes=nodes):
                self.assertEqual(M.parse_result(captured(widened), b"", BINDING, case), widened)
        # Later control/Press DATA keeps the selecting envelope; the same
        # standalone button DATA must still fail its ordinary-only decoder.
        for nodes, calls, slots in ((12, 513, 257), (255, 2616, 1016), (255, 3072, 1024)):
            widened = deepcopy(good)
            action = widened["projectFields"]["acceptedOpenHistories"][1]["selectionInput"]
            action["selection"].update(nodes=nodes)
            action["promptButton"].update(calls=calls, cfSlots=slots, cfSlotsRetired=slots)
            with self.subTest(selection_calls=calls, selection_slots=slots):
                self.assertEqual(M.parse_result(captured(widened), b"", BINDING, case), widened)
                self.assertTrue(M._accessibility_succeeded(action))
                with self.assertRaises(M.Refused):
                    M._accessibility_prompt_button(action["promptButton"])
                partial = deepcopy(widened)
                partial["projectFields"]["acceptedOpenHistories"][1]["selectionInput"]["promptButton"]["cfSlotsRetired"] = slots - 1
                with self.assertRaises(M.Refused):
                    M.parse_result(captured(partial), b"", BINDING, case)
        for mutation in (
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"].update(mechanism="accessibility-version-source-selection-press-v6"),
            lambda v: v.update(schemaVersion=1),
            lambda v: v.update(normalProfileAvailable=False),
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
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"].update(nodes=256),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"].update(nodes=True),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["selection"].update(nodes=255.0),
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
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["promptButton"].update(calls=3073),
            lambda v: v["acceptedOpenHistories"][1]["selectionInput"]["promptButton"].update(cfSlots=1025, cfSlotsRetired=1025),
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

        # Current diagnostic DATA is required and closed, never filled from this
        # comparison fixture. Different valid counts are retained verbatim.
        baseline = M.expected_result(BINDING, case)
        selection = baseline["projectFields"]["acceptedOpenHistories"][1]["selectionInput"]["selection"]
        summary = selection["projectionSummary"]
        counts = ("tableRoles", "outlineRoles", "listRoles", "entryRoots", "titlePresent", "titleAbsent", "valuePresent")
        masks = {"outsideEntryRoleMask", "fixtureLabelMask", "expectedLabelRelations", "expectedLabelRoleMask"}
        self.assertEqual(set(summary), {*counts, *masks})
        changed = deepcopy(baseline)
        changed["projectFields"]["acceptedOpenHistories"][1]["selectionInput"]["selection"]["projectionSummary"] = {
            "tableRoles": 1, "outlineRoles": 1, "listRoles": 0, "entryRoots": 3,
            "titlePresent": 2, "titleAbsent": 1, "valuePresent": 1, "outsideEntryRoleMask": 0x1c210,
            "fixtureLabelMask": 9, "expectedLabelRelations": 7, "expectedLabelRoleMask": (1 << 15) | (1 << 16)}
        self.assertEqual(M.parse_result(captured(changed), b"", BINDING, case), changed)
        malformed = [None, {}, [], True, {**summary, "version": 1}, {**summary, "extra": 0},
            {**summary, "tableRoles": 0}, {**summary, "entryRoots": 0}, {**summary, "valuePresent": 0},
            {**summary, "tableRoles": 5, "outlineRoles": 4, "listRoles": 4},
            {**summary, "titlePresent": 9, "titleAbsent": 2, "valuePresent": 2},
            {**summary, "fixtureLabelMask": 7}, {**summary, "expectedLabelRelations": 2},
            {**summary, "expectedLabelRoleMask": 0},
            {**summary, "expectedLabelRoleMask": (1 << 12) | (1 << 13) | (1 << 14)}]
        for key in summary:
            missing = dict(summary); del missing[key]; malformed.append(missing)
        for key in counts:
            for invalid in (True, -1, 13, 1.0, 1 << 32):
                malformed.append({**summary, key: invalid})
        for invalid in (True, -1, 0.0, 1, 1 << 12, 1 << 13, 1 << 17, 1 << 32):
            malformed.append({**summary, "outsideEntryRoleMask": invalid})
        for key, unknown in (("fixtureLabelMask", 32), ("expectedLabelRelations", 8), ("expectedLabelRoleMask", 1 << 4)):
            for invalid in (True, -1, 1.0, unknown, 1 << 32, "VERSION", "/INERT_PRIVATE/path"):
                malformed.append({**summary, key: invalid})
        for index, invalid in enumerate(malformed):
            with self.subTest(summary=index):
                bad = deepcopy(baseline)
                bad["projectFields"]["acceptedOpenHistories"][1]["selectionInput"]["selection"]["projectionSummary"] = invalid
                with self.assertRaises(M.Refused):
                    M.parse_result(captured(bad), b"", BINDING, case)
        bad = deepcopy(baseline)
        del bad["projectFields"]["acceptedOpenHistories"][1]["selectionInput"]["selection"]["projectionSummary"]
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
        action["selection"]["projectionSummary"].update(fixtureLabelMask=0, expectedLabelRelations=0, expectedLabelRoleMask=0)
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
            sample["selection"]["projectionSummary"].update(fixtureLabelMask=1 if matches else 0,
                expectedLabelRelations=1 if matches else 0, expectedLabelRoleMask=(1 << 15) if matches else 0)
            sample["promptButton"]["axError"] = ax_error
            sample["promptButton"]["axFailure"] = ({"operation": "set-attribute-value", "attribute": "SelectedRows"}
                if ax_error != 0 else None)
            if label == "incomplete-roster":
                sample["selection"]["limit"] = {"predicate": "child-count", "observed": 33, "cap": 32, "queued": 9, "children": None}
            failures.append((label, failed))
        readback_failed = deepcopy(failures[-1][1])
        # Two explicitly synthetic alternatives at the old call44/node2 shape.
        # Neither identifies the historical attribute or invents a readiness cause.
        for attribute in ("Parent", "Role"):
            failed = deepcopy(frame); sample = failed["accessibility"]
            sample.update(site="selection-projection", error="cannot-complete")
            sample["promptButton"].update(calls=44, cfSlots=22, cfSlotsRetired=22, axError=-25204,
                axFailure={"operation": "copy-attribute-value", "attribute": attribute})
            sample["selection"].update(checks=dict.fromkeys(M.ACCESSIBILITY_SELECTION_CHECKS, False),
                nodes=2, matches=0, lastRole="not-read", depth=2,
                projectionSummary={**dict.fromkeys(sample["selection"]["projectionSummary"], 0), "tableRoles": 1})
            self.assertIsNone(sample["selection"]["limit"])
            self.assertIsNone(sample["initialOriginalProof"])
            self.assertIsNone(sample["originalProof"])
            self.assertFalse(sample["attempted"])
            self.assertFalse(sample["selection"]["attempted"])
            failures.append(("synthetic-first-copy-" + attribute, failed))
        parent_refused = deepcopy(frame); sample = parent_refused["accessibility"]
        sample.update(site="selection-parent-proof", error="ineligible", selectionParentPrompt=None)
        sample["selectionParentProof"].update(parent=None, panel=None, children=None, originals=None,
            site="directory", error="ineligible", checks=dict.fromkeys(M.ACCESSIBILITY_PROOF_CHECKS, None))
        sample["selectionParentProof"]["checks"].update(eligible=True, attached=True, directory=False)
        sample["selection"].update(checks=dict.fromkeys(M.ACCESSIBILITY_SELECTION_CHECKS, False), nodes=0, matches=0,
                                   lastRole="not-read", depth=0, projectionSummary=None, contentReadiness=None)
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
        # These are alternative inert roster observations, not recovered facts.
        # Present labels with zero matches still do not prove target representation.
        empty_summary = dict.fromkeys(frame["accessibility"]["selection"]["projectionSummary"], 0)
        for label, role, depth, summary in (
            ("summary-no-container", "TextField", 2, {**empty_summary, "outsideEntryRoleMask": 0x1c210}),
            ("summary-container-no-entry", "Table", 2, {**empty_summary, "tableRoles": 1}),
            ("summary-entry-title-absent", "Row", 2, {**empty_summary, "tableRoles": 1, "entryRoots": 1, "titleAbsent": 1}),
            ("summary-entry-title-present", "Row", 2, {**empty_summary, "tableRoles": 1, "entryRoots": 1, "titlePresent": 1}),
            ("summary-entry-value-present", "StaticText", 3,
                {**empty_summary, "tableRoles": 1, "entryRoots": 1, "titleAbsent": 1, "valuePresent": 1}),
            ("summary-fixed-sibling-only", "TextField", 3,
                {**empty_summary, "listRoles": 1, "entryRoots": 1, "valuePresent": 1, "fixtureLabelMask": 8}),
            ("summary-case-only", "TextField", 3,
                {**empty_summary, "listRoles": 1, "entryRoots": 1, "valuePresent": 1,
                 "expectedLabelRelations": 2, "expectedLabelRoleMask": 1 << 16}),
            ("summary-literal-decoration", "StaticText", 3,
                {**empty_summary, "listRoles": 1, "entryRoots": 1, "valuePresent": 1,
                 "expectedLabelRelations": 4, "expectedLabelRoleMask": 1 << 15}),
            ("summary-mixed-nonexact", "StaticText", 3,
                {**empty_summary, "listRoles": 1, "entryRoots": 2, "valuePresent": 2,
                 "expectedLabelRelations": 6, "expectedLabelRoleMask": (1 << 15) | (1 << 16)}),
        ):
            failed = deepcopy(frame)
            failed["accessibility"]["selection"].update(lastRole=role, depth=depth, projectionSummary=summary)
            failures.append((label, failed))
        entered_zero = deepcopy(frame); sample = entered_zero["accessibility"]
        sample.update(error="deadline", expired=True, timely=False)
        sample["selection"].update(checks=dict.fromkeys(M.ACCESSIBILITY_SELECTION_CHECKS, False),
            nodes=0, matches=0, lastRole="not-read", depth=0, projectionSummary=dict(empty_summary))
        failures.append(("entered-zero-summary-before-first-role", entered_zero))
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
            lambda s: s["selection"].update(projectionSummary=None),
            lambda s: s["selection"].pop("projectionSummary"),
            lambda s: s["selection"]["projectionSummary"].update(expectedLabelRelations=1, expectedLabelRoleMask=1 << 15),
            lambda s: s["selection"]["projectionSummary"].update(expectedLabelRelations=2),
            lambda s: s["selection"]["projectionSummary"].update(expectedLabelRoleMask=1 << 15),
        ):
            bad = deepcopy(frame); mutation(bad["accessibility"])
            expected = deepcopy(bad); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", marker + context_row(bad), case), expected)
        bad = deepcopy(parent_refused); bad["accessibility"]["error"] = "unsupported"
        expected = deepcopy(bad); expected["accessibility"] = None
        self.assertEqual(M.failure_context(b"", marker + context_row(bad), case), expected)
        bad = deepcopy(entered_zero); bad["accessibility"]["selection"]["projectionSummary"] = None
        expected = deepcopy(bad); expected["accessibility"] = None
        self.assertEqual(M.failure_context(b"", marker + context_row(bad), case), expected)
        bad = deepcopy(failures[2][1])  # Existing distinct-entry-collision DATA.
        bad["accessibility"]["selection"]["projectionSummary"]["entryRoots"] = 1
        expected = deepcopy(bad); expected["accessibility"] = None
        self.assertEqual(M.failure_context(b"", marker + context_row(bad), case), expected)
        # Same native DATA before actual worker/receipt retirement, not success.
        return_marker = f"MRK_MACOS_AQUA_FAILURE_STEP={step}\nMRK_MACOS_AQUA_FAILURE_REASON=native-default-input\n".encode("ascii")
        original_failure = failures[1][1]["accessibility"]  # Existing no-entry vector.
        for admitted in (True, False, None):
            for expired in (False, True):
                returned = returned_project_field_context_data(original_failure, admitted, expired=expired)
                self.assertEqual(M.failure_context(b"", return_marker + context_row(returned), case), returned)
                self.assertFalse(M._accessibility_succeeded(returned["accessibility"]))
                self.assertIs(returned["inputBodyAdmission"], admitted)
                self.assertEqual(returned["accessibility"]["site"], "selection-projection")
                self.assertEqual(returned["accessibility"]["error"], "unsupported")
        # A successful native report and a false post-return admission are distinct.
        admission_only = returned_project_field_context_data(history["selectionInput"], False)
        self.assertEqual(M.failure_context(b"", return_marker + context_row(admission_only), case), admission_only)
        self.assertEqual(admission_only["accessibility"]["error"], "none")
        self.assertFalse(M._accessibility_succeeded(admission_only["accessibility"]))
        good_return = returned_project_field_context_data(original_failure, True)
        for mutate in (
            lambda v: v.pop("inputBodyAdmission"),
            lambda v: v.update(inputBodyAdmission=1),
            lambda v: v.update(inputBodyAdmission="true"),
            lambda v: v.update(snapshotSource="record"),
            lambda v: v.update(snapshotSource="prearm-open-progress"),
            lambda v: v.update(completionSelection=None),
            lambda v: v.update(dom=None),
            lambda v: v.update(accessibilityBinding=None),
            lambda v: v["accessibility"].update(id=3),
            lambda v: v["accessibility"].update(step="ProjectFields(Native(1))"),
            lambda v: v["accessibility"].update(mechanism="accessibility-version-source-selection-press-v7"),
            lambda v: v["accessibility"].update(state="entered", bodyReturned=False),
            lambda v: v["accessibility"].update(timely=True),
            lambda v: v["accessibility"].update(timely=False),
            lambda v: v["accessibility"].update(receiptJoined=True),
            lambda v: v["accessibility"].update(barrierRetired=True),
            lambda v: v["accessibility"].update(rechecksSettled=True),
            lambda v: v["accessibility"].update(nativeEntered=None),
            lambda v: v["accessibility"].update(promptButton=None),
            lambda v: v["accessibilityBinding"].update(id=3),
            lambda v: v["accessibilityBinding"]["configuration"].update(site="directory-set"),
            lambda v: v.update(rawLabel="INERT_NONPUBLIC_TEXT"),
        ):
            bad = deepcopy(good_return); mutate(bad)
            with self.subTest(returned_input_mutation=repr(mutate)):
                self.assertIsNone(M.failure_context(b"", return_marker + context_row(bad), case))
        bad = deepcopy(admission_only); bad["inputBodyAdmission"] = True
        self.assertIsNone(M.failure_context(b"", return_marker + context_row(bad), case))
        for other_case in (None, "first-save", "project-recovery-pending"):
            self.assertIsNone(M.failure_context(b"", return_marker + context_row(good_return), other_case))
        for altered in (return_marker.replace(b"native-default-input", b"observer-invariant"),
                        return_marker.replace(b"Native(0)", b"Native(1)")):
            self.assertIsNone(M.failure_context(b"", altered + context_row(good_return), case))
        duplicate = return_marker + context_row(good_return) + context_row(good_return)
        self.assertIsNone(M.failure_context(b"", duplicate, case))
        success = deepcopy(good); success["inputBodyAdmission"] = False
        with self.assertRaises(M.Refused):
            M.parse_result(captured(success), b"", BINDING, case)
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

    def test_content_readiness_is_contiguous_bounded_data_and_never_action_authority(self):
        # Inert current-protocol DATA only. Not a simulated clock/AX worker,
        # native readiness observation, returned original or platform receipt.
        good = M.expected_result(BINDING, "project-fields")

        def progress(count):
            value = deepcopy(good)
            action = value["projectFields"]["acceptedOpenHistories"][1]["selectionInput"]
            action["selection"]["contentReadiness"] = {
                "sample": count + 1, "callsBefore": count * 707, "cfBefore": count * 434, "wait": 0,
                "pending": [[i + 1, i * 707, (i + 1) * 707, i * 434, (i + 1) * 434,
                             182, 8, 16, 43, 24, 0, 1, 0, 0, 0, 2] for i in range(count)]}
            action["promptButton"].update(calls=count * 707 + 221, cfSlots=count * 434 + 120,
                                         cfSlotsRetired=count * 434 + 120)
            return value, action

        for count in range(8):
            value, action = progress(count)
            with self.subTest(complete_pending_samples=count):
                self.assertEqual(M.parse_result(captured(value), b"", BINDING, "project-fields"), value)
                self.assertTrue(M._accessibility_succeeded(action))
                self.assertEqual(len(action["selection"]["contentReadiness"]["pending"]), count)
                if count:
                    with self.assertRaises(M.Refused):
                        M._accessibility_prompt_button(action["promptButton"])  # Ordinary limits stay unchanged.

        for mutate in (
            lambda a: a["selection"].pop("contentReadiness"),
            lambda a: a["selection"].update(contentReadiness=None),
            lambda a: a["selection"]["contentReadiness"].update(sample=0),
            lambda a: a["selection"]["contentReadiness"].update(sample=9),
            lambda a: a["selection"]["contentReadiness"].update(sample=True),
            lambda a: a["selection"]["contentReadiness"].update(callsBefore=1415),
            lambda a: a["selection"]["contentReadiness"].update(cfBefore=869),
            lambda a: a["selection"]["contentReadiness"].update(wait=1),
            lambda a: a["selection"]["contentReadiness"].update(wait=2),
            lambda a: a["selection"]["contentReadiness"].update(wait=3),
            lambda a: a["selection"]["contentReadiness"]["pending"].pop(),
            lambda a: a["selection"]["contentReadiness"]["pending"].append([0] * 16),
            lambda a: a["selection"]["contentReadiness"]["pending"].reverse(),
            lambda a: a["selection"]["contentReadiness"]["pending"][0].append(0),
            lambda a: a["promptButton"].update(calls=1414 + 3073),
            lambda a: a["promptButton"].update(cfSlots=868 + 1025, cfSlotsRetired=868 + 1025),
            lambda a: a["promptButton"].update(cfSlotsRetired=987),
            lambda a: a.update(barrierRetired=False),
            lambda a: a.update(workerJoined=False),
        ):
            value, action = progress(2); mutate(action)
            with self.assertRaises(M.Refused):
                M.parse_result(captured(value), b"", BINDING, "project-fields")
        # Each tuple cell is closed: gaps/overlap, budgets, grammar, ambiguity,
        # prior actions/errors and wait failures cannot become a pending sample.
        for index, malformed in ((0, 2), (1, 1), (2, 3073), (3, 1), (4, 1025),
                                  (5, 256), (6, 9), (7, 17), (8, 183), (9, 32),
                                  (10, 1), (11, 3), (12, 1), (13, 1), (14, 8), (15, 3)):
            value, action = progress(2)
            action["selection"]["contentReadiness"]["pending"][0][index] = malformed
            with self.subTest(tuple_cell=index), self.assertRaises(M.Refused):
                M.parse_result(captured(value), b"", BINDING, "project-fields")
        for index in (0, 1, 2, 4, 11, 15):
            value, action = progress(2)
            action["selection"]["contentReadiness"]["pending"][0][index] = True
            with self.subTest(boolean_cell=index), self.assertRaises(M.Refused):
                M.parse_result(captured(value), b"", BINDING, "project-fields")

        def stopped(count, wait, error):
            _, action = progress(count)
            action.update(attempted=False, pressReturned=False, triggered=None, initialOriginalProof=None,
                          originalProof=None, promptChecks={"initial": None, "final": None},
                          site="selection-projection", error=error, expired=error == "deadline",
                          timely=error != "deadline")
            action["promptButton"].update(
                checks={key: i < 2 for i, key in enumerate(M.ACCESSIBILITY_BUTTON_CHECKS)},
                calls=count * 707 + 707, cfSlots=count * 434 + 434, cfSlotsRetired=count * 434 + 434,
                initialNodesExamined=0, recheckNodesExamined=0, lastRole="not-read", lastDepth=0)
            selection = action["selection"]
            selection.update(checks={key: i == 0 for i, key in enumerate(M.ACCESSIBILITY_SELECTION_CHECKS)},
                             attempted=False, returned=False, selected=None, nodes=182, matches=0,
                             attribute="not-read", lastRole="TextField", depth=8)
            selection["projectionSummary"].update(tableRoles=1, entryRoots=43, titleAbsent=43, valuePresent=43,
                fixtureLabelMask=24, expectedLabelRelations=0, expectedLabelRoleMask=0)
            selection["contentReadiness"]["wait"] = wait
            if error == "objc-exception":
                action.update(state="unknown", custodyKnown=False, receiptJoined=False, barrierRetired=False)
                action["promptButton"].update(cleanupReturned=False, cfSlotsRetired=0)
            return action

        for count, wait, error in ((0, 0, "deadline"), (2, 1, "objc-exception"), (2, 2, "deadline"),
                                   (2, 3, "ax-other"), (7, 0, "unsupported")):
            action = stopped(count, wait, error)
            with self.subTest(sample=count + 1, wait=wait, stopped=error):
                self.assertEqual(M._accessibility_context(action, None, None,
                    expected_id=2, case="project-fields", field_history=True), action)
                self.assertFalse(M._accessibility_succeeded(action))
                value = deepcopy(good)
                value["projectFields"]["acceptedOpenHistories"][1]["selectionInput"] = action
                with self.assertRaises(M.Refused):
                    M.parse_result(captured(value), b"", BINDING, "project-fields")
        for wait, matches, error in ((2, 2, "ambiguous"), (3, 0, "deadline"), (2, 0, "none")):
            action = stopped(2, wait, error); action["selection"]["matches"] = matches
            self.assertIsNone(M._accessibility_context(action, None, None,
                expected_id=2, case="project-fields", field_history=True))
        eighth = stopped(7, 2, "deadline")
        self.assertIsNone(M._accessibility_context(eighth, None, None,
            expected_id=2, case="project-fields", field_history=True))

        # The largest complete pending-history count shares the existing closed
        # failure envelope, with no raw strings, larger cap or fake native receipt.
        maximum = stopped(7, 0, "unsupported")
        bounded = returned_project_field_context_data(maximum, True, expired=True)
        bounded["projectFieldPreparation"] = {"operationId": 2, "kind": "version-source", "returned": True,
            "result": "ok", "facts": 6143, "fileFilter": {"facts": 23, "allowedTypes": "unrestricted", "allowsOther": False},
            "nameFieldPreparation": {"returned": True, "result": "ok", "facts": 31}}
        marker = b"MRK_MACOS_AQUA_FAILURE_STEP=ProjectFields(Native(0))\nMRK_MACOS_AQUA_FAILURE_REASON=native-default-input\n"
        payload = json.dumps(bounded, separators=(",", ":")).encode("ascii")
        self.assertLessEqual(len(payload), M.FAILURE_CONTEXT_LIMIT)
        self.assertLessEqual(len(marker + context_row(bounded) + b"MRK_MACOS_AQUA=failed\n"), 8448)
        self.assertEqual(M.failure_context(b"", marker + context_row(bounded), "project-fields"), bounded)
        self.assertFalse(M._accessibility_succeeded(bounded["accessibility"]))
        # Historical v7 remains readable only as failure DATA. It cannot borrow
        # the v8 history envelope or qualify a new successful field journey.
        old = stopped(0, 0, "unsupported")
        old["mechanism"] = "accessibility-version-source-selection-press-v7"
        old["selection"].pop("contentReadiness"); old["selection"].pop("projectionDiagnostic")
        frame = accessibility_context_data(); step = "ProjectFields(Native(0))"
        frame.update(snapshotSource="record", accessibility=old)
        frame["nativeHandler"]["step"] = step
        frame["lastPanel"].update(step=step, id=2, kind="version-source")
        self.assertEqual(M.failure_context(b"", context_row(frame), "project-fields"), frame)
        self.assertFalse(M._accessibility_succeeded(old))
        self.assertIsNone(M._accessibility_context(old, None, None,
            expected_id=2, case="project-fields", field_history=True))
        old_success = deepcopy(good)
        old_action = old_success["projectFields"]["acceptedOpenHistories"][1]["selectionInput"]
        old_action["mechanism"] = old["mechanism"]; old_action["selection"].pop("contentReadiness")
        old_action["selection"].pop("projectionDiagnostic")
        with self.assertRaises(M.Refused):
            M.parse_result(captured(old_success), b"", BINDING, "project-fields")

    def test_first_zero_projection_diagnostic_is_closed_indeterminate_data_not_selection_authority(self):
        # Pure parser vectors. No AX emulation, clock, native return or receipt.
        action = M.expected_result(BINDING, "project-fields")["projectFields"]["acceptedOpenHistories"][1]["selectionInput"]
        selection, button = action["selection"], action["promptButton"]
        selection.update(checks={key: i == 0 for i, key in enumerate(M.ACCESSIBILITY_SELECTION_CHECKS)},
                         attempted=False, returned=False, selected=None, matches=0, attribute="not-read")
        selection["projectionSummary"].update(fixtureLabelMask=24, expectedLabelRelations=0, expectedLabelRoleMask=0)
        diagnostic = dict(zip(("version", "state", "normalFixtureMask", "callsBefore", "callsAfter", "cfBefore", "cfAfter",
            "eligibleFrontiers", "attemptedFrontiers", "addedNodes", "maxDepth", "alternateValueMask",
            "frontierLabelMask", "outsideFieldMask", "alternateRoleMask", "frontierRoleMask",
            "unavailable", "omissions", "duplicates", "nonStringValues"),
            (1, "returned-complete", 24, 205, 221, 110, 120, 1, 1, 1, 4, 0, 2, 1, 0, 1 << 15, 0, 0, 0, 0)))

        def parsed(data, error="none", current=None, counters=None):
            current = deepcopy(selection if current is None else current)
            current["projectionDiagnostic"] = data
            return M._accessibility_selection(current, button if counters is None else counters,
                                              "selection-projection", error, content=True)

        for data, error in ((None, "deadline"), (diagnostic, "none"),
                            ({**diagnostic, "frontierRoleMask": 1 << 4}, "none"),
                            ({**diagnostic, "state": "entered"}, "objc-exception"),
                            ({**diagnostic, "state": "returned-incomplete", "unavailable": 32}, "none"),
                            ({**diagnostic, "state": "returned-incomplete", "omissions": 32}, "none"),
                            ({**diagnostic, "state": "returned-incomplete"}, "deadline")):
            with self.subTest(state=None if data is None else data["state"], error=error):
                value = parsed(data, error)
                self.assertEqual(value["projectionDiagnostic"], data)
                self.assertFalse(M._selection_succeeded(value))
        outside_only = {**diagnostic, "addedNodes": 0, "maxDepth": 0, "frontierLabelMask": 0, "frontierRoleMask": 0}
        value = parsed(outside_only)
        self.assertEqual(value["projectionDiagnostic"]["outsideFieldMask"], 1)
        self.assertEqual(value["projectionDiagnostic"]["frontierLabelMask"], 0)
        self.assertFalse(M._selection_succeeded(value))  # Prefilled VERSION cannot select an entry.
        later = deepcopy(selection)
        later["contentReadiness"] = {"sample": 2, "callsBefore": 221, "cfBefore": 120, "wait": 0,
            "pending": [[1, 0, 221, 0, 120, 12, 4, 16, 2, 24, 0, 1, 0, 0, 0, 2]]}
        later["projectionSummary"]["fixtureLabelMask"] = 0
        counters = {**button, "calls": 300, "cfSlots": 160, "cfSlotsRetired": 160}
        self.assertEqual(parsed(diagnostic, current=later, counters=counters)["projectionDiagnostic"], diagnostic)
        with self.assertRaises(M.Refused):
            parsed({**diagnostic, "normalFixtureMask": 0}, current=later, counters=counters)
        with self.assertRaises(M.Refused):
            parsed({**diagnostic, "state": "entered"}, "objc-exception", current=later, counters=counters)

        for field, invalid in (("version", 0), ("version", True), ("state", "complete"),
            ("callsBefore", 0), ("callsBefore", 222), ("callsAfter", 3073), ("cfAfter", 1025),
            ("eligibleFrontiers", 13), ("attemptedFrontiers", 65), ("addedNodes", 65), ("maxDepth", 9),
            ("normalFixtureMask", 32), ("alternateRoleMask", 1 << 4), ("frontierRoleMask", 1 << 3),
            ("frontierLabelMask", 0), ("unavailable", 64), ("omissions", 1024), ("duplicates", 65),
            ("nonStringValues", 11), ("unavailable", 32), ("omissions", 32), ("nonStringValues", 1),
            ("state", "entered"), ("state", "returned-incomplete")):
            with self.subTest(field=field, invalid=invalid), self.assertRaises(M.Refused):
                parsed({**diagnostic, field: invalid})
        for data in ({}, [], True, {**diagnostic, "rawLabel": "VERSION"},
                     {key: value for key, value in diagnostic.items() if key != "outsideFieldMask"}):
            with self.assertRaises(M.Refused): parsed(data)
        missing = deepcopy(selection); missing.pop("projectionDiagnostic")
        with self.assertRaises(M.Refused):
            M._accessibility_selection(missing, button, "selection-projection", "deadline", content=True)

    def test_first_zero_projection_source_keeps_original_owner_caps_and_action_grammar(self):
        root = PATH.parents[1]
        native = (root / "native/macos-installed-native/src/native.m").read_text()
        rust = (root / "native/macos-installed-native/src/lib.rs").read_text()
        observer = (root / "src-tauri/src/installed_shell_observation_macos.rs").read_text()
        diagnostic = native.split("// Diagnostic-only reads use the original timeout/admission and CF custody.", 1)[1]
        diagnostic = diagnostic.split("static BOOL mrk_ax_selection_label(", 1)[0]
        self.assertIn("sizeof(MRKProjectionDiagnostic) == 80", native)
        self.assertIn("offsetof(MRKOpenResult, selection_projection_diagnostic) == 624", native)
        self.assertIn("selection_projection_diagnostic: [u32; 20]", rust)
        self.assertIn("std::mem::offset_of!(OpenWire, selection_projection_diagnostic) != 624", rust)
        self.assertIn("MRK_DIAG_FRONTIERS = 64, MRK_DIAG_NODES = 64, MRK_DIAG_CALLS = 1024, MRK_DIAG_CF = 512", native)
        self.assertIn("MRK_SELECT_NODES = 256, MRK_SELECT_ROWS = 32, MRK_SELECT_CALLS = 3072, MRK_SELECT_CF = 1024", native)
        for bound in ("MRK_DIAG_CALLS - calls", "MRK_DIAG_CF - slots", "MRK_SELECT_CALLS - calls",
                      "MRK_SELECT_CF - slots", "MRK_SELECT_TOTAL_CALLS - calls", "MRK_SELECT_TOTAL_CF - slots"):
            self.assertIn(bound, diagnostic)
        self.assertIn("mrk_ax_copy(s, node, attribute, YES, attribute_code)", diagnostic)
        self.assertIn("if (!mrk_ax_diag_credit(s, 2, 1)) return NULL;", diagnostic)
        children = diagnostic.split("static BOOL mrk_ax_diag_children(", 1)[1].split("static BOOL mrk_ax_diag_frontier(", 1)[0]
        self.assertLess(children.index("if (expected > MRK_SELECT_ROWS)"), children.index("AXUIElementCopyAttributeValues("))
        self.assertLess(children.index("MRKPromptOwned *slot = mrk_ax_slot(s)"), children.index("AXUIElementCopyAttributeValues("))
        self.assertIn("mrk_ax_admit(s, 0, 0, NULL)", children)
        self.assertIn("original_count + d->added_nodes == MRK_SELECT_NODES", children)
        self.assertLess(children.index("if (!CFEqual(parent, node))"), children.index("q->nodes[at] = child"))
        self.assertIn("if (known) continue;", children)
        self.assertIn("if (depth >= MRK_CONTROL_DEPTH)", children)
        frontier, probe = diagnostic.split("static BOOL mrk_ax_diag_frontier(", 1)[1].split("static void mrk_ax_projection_diagnostic_probe(", 1)
        self.assertNotIn("MRK_ROLE_BUTTON", frontier)  # Do not scan all original Buttons.
        added = probe.split("for (unsigned at = 0; at < d->added_nodes; ++at) {", 1)[1].split("for (unsigned at = 0; at < original_count; ++at) {", 1)[0]
        self.assertIn("BOOL button = role == MRK_ROLE_BUTTON;", added)
        self.assertIn("if ((entry || button) && !mrk_ax_diag_label(s, q->nodes[at], role, kAXTitleAttribute", added)
        self.assertIn("if ((text || entry || button) && !mrk_ax_diag_label(s, q->nodes[at], role, kAXValueAttribute", added)
        self.assertNotIn("MRK_DIAG_OMIT_ROLE", added)
        self.assertEqual(added.count("continue;"), 1)
        self.assertIn("if (text || role == MRK_SELECT_IMAGE) continue;", added)
        self.assertIn("if (!mrk_ax_diag_children(s, p, original_count, q->nodes[at], q->depths[at])) return;", added)
        self.assertIn("const MRKSelectionPass *p = &s->selection[0];", diagnostic)
        self.assertLess(diagnostic.index("d->version = 1u; d->state = 1u;"),
                        diagnostic.index("mrk_ax_projection_diagnostic_probe(s, p, original_count)"))
        self.assertIn("if (d->version) return;", diagnostic)
        self.assertIn("} @finally {", diagnostic)
        self.assertIn("d->calls_after = s->result.calls; d->cf_after = s->count;", diagnostic)
        self.assertIn("if (returned) d->state = s->result.error || d->unavailable || d->omissions || d->non_string_values", diagnostic)
        for forbidden in ("AXUIElementSetAttributeValue", "AXUIElementPerformAction", "CFRelease(",
                          "CFStringGetCString", "UTF8String", "printf(", "pthread_create", "dispatch_", "nanosleep"):
            self.assertNotIn(forbidden, diagnostic)
        self.assertNotRegex(diagnostic, r"s->result\.selection_(?:matches|checks|flags|nodes)\s*(?:=(?!=)|\|=|\+\+)")
        action = native.split("static void mrk_ax_open(", 1)[1].split("void mrk_observation_prompt_press(", 1)[0]
        self.assertEqual(action.count("mrk_ax_first_zero_diagnostic(s, sheet)"), 1)
        self.assertLess(action.index("if (s->result.selection_matches == 1) break;"), action.index("mrk_ax_first_zero_diagnostic(s, sheet)"))
        self.assertLess(action.index("mrk_ax_first_zero_diagnostic(s, sheet)"), action.index("mrk_ax_content_wait(s)"))
        next_sample = native.split("static BOOL mrk_ax_next_content_sample(", 1)[1].split("static BOOL mrk_ax_select_entry(", 1)[0]
        self.assertNotIn("projection_diagnostic", next_sample)
        matching = rust.split("impl VersionSourceSelection {", 1)[1].split("fn content_readiness_data_check(", 1)[0]
        self.assertNotIn("projection_diagnostic", matching)
        success = PATH.read_text().split("def _selection_succeeded(", 1)[1].split("def _accessibility_selection_limit(", 1)[0]
        self.assertNotIn("projectionDiagnostic", success)
        serialized = observer.split('"projectionDiagnostic":p.projection_diagnostic.map(|r| json!({', 1)[1].split("}))", 1)[0]
        self.assertEqual(len(M.re.findall(r'"([A-Za-z]+)":', serialized)), 20)

    def test_content_readiness_uses_original_owner_wait_budgets_and_bounded_filter_diagnostics(self):
        # SOURCE/closed scalar DATA only. Sleep return is not readiness, source
        # checks are not native execution, and these frames are not receipts.
        root = PATH.parents[1]
        native = (root / "native/macos-installed-native/src/native.m").read_text()
        rust = (root / "native/macos-installed-native/src/lib.rs").read_text()
        observer = (root / "src-tauri/src/installed_shell_observation_macos.rs").read_text()
        wait = native.split("static BOOL mrk_ax_content_wait(", 1)[1].split("static BOOL mrk_ax_next_content_sample(", 1)[0]
        advance = native.split("static BOOL mrk_ax_next_content_sample(", 1)[1].split("static BOOL mrk_ax_select_entry(", 1)[0]
        action = native.split("static void mrk_ax_open(", 1)[1].split("void mrk_observation_prompt_press(", 1)[0]
        roster = native.split("static BOOL mrk_ax_selection_roster(", 1)[1].split("static BOOL mrk_ax_content_wait(", 1)[0]
        write = native.split("static BOOL mrk_ax_select_entry(", 1)[1].split("static void mrk_ax_open(", 1)[0]
        for guard in ("s->result.error", "s->result.selection_checks != 1", "s->result.selection_matches",
                      "s->result.selection_flags", "s->result.flags", "s->result.selection_wait",
                      "s->result.selection_sample >= MRK_SELECT_SAMPLES"):
            self.assertIn(guard, wait)
        self.assertEqual(wait.count("nanosleep("), 1)
        self.assertEqual(wait.count("mrk_ax_admit("), 2)
        ordering = ("mrk_ax_admit(s, 50000000u, 0, NULL)", "s->result.selection_wait = 1u",
                    "nanosleep(&interval, NULL)", "s->result.selection_wait = status == 0 ? 2u : 3u",
                    "mrk_ax_fail(s, MRK_OPEN_OTHER)", "mrk_ax_admit(s, 0, 0, NULL)")
        positions = [wait.index(value) for value in ordering]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("return returned && admitted;", wait)
        for forbidden in ("while (", "for (", "dispatch_", "pthread_create", "Instant::", "CFRelease(", "mrk_ax_projection"):
            self.assertNotIn(forbidden, wait)
        self.assertIn("s->result.selection_sample = ordinal + 1", advance)
        self.assertIn("s->result.selection_pending[ordinal - 1] = (MRKContentPending)", advance)
        self.assertLess(advance.index("s->result.selection_pending[ordinal - 1] ="),
                        advance.index("s->result.selection_sample = ordinal + 1"))
        self.assertIn("s->result.selection_calls_before = s->result.calls", advance)
        self.assertIn("s->result.selection_cf_before = s->count", advance)
        for forbidden in ("s->result.error =", "s->result.calls =", "s->count =", "s->result.selection_flags =",
                          "s->result.flags =", "CFRelease(", "memset(", "s->selection["):
            self.assertNotIn(forbidden, advance)
        self.assertEqual(native.count("s->result.selection_pending[ordinal - 1] ="), 1)
        self.assertIn("MRK_SELECT_SAMPLES = 8, MRK_SELECT_PENDING = MRK_SELECT_SAMPLES - 1", native)
        self.assertIn("MRK_SELECT_TOTAL_CALLS = MRK_SELECT_SAMPLES * MRK_SELECT_CALLS", native)
        self.assertIn("MRK_SELECT_TOTAL_CF = MRK_SELECT_SAMPLES * MRK_SELECT_CF", native)
        self.assertIn("sizeof(MRKContentPending) == 64", native)
        for field, offset in (("selection_sample", 160), ("selection_pending", 176)):
            self.assertIn(f"offsetof(MRKOpenResult, {field}) == {offset}", native)
            self.assertIn(f"std::mem::offset_of!(OpenWire, {field}) != {offset}", rust)
        self.assertIn("s->result.selection_sample == MRK_SELECT_SAMPLES", action)
        self.assertLess(action.index("if (s->result.selection_matches == 1) break;"),
                        action.index("mrk_ax_content_wait(s)"))
        self.assertLess(action.index("mrk_ax_content_wait(s)"), action.index("mrk_ax_next_content_sample(s)"))
        self.assertEqual(action.count("mrk_ax_original(s, s->result.selection_mode ? 0 : 1)"), 1)
        self.assertEqual(action.count("mrk_ax_select_entry("), 1)
        self.assertEqual(action.count("AXUIElementPerformAction("), 1)
        self.assertIn("MRKSelectionPass *p = &s->selection[s->result.selection_sample - 1];", roster)
        self.assertIn("if (p->nodes[0])", roster)
        self.assertIn("MRKSelectionPass *p = &s->selection[s->result.selection_sample - 1];", write)
        self.assertEqual(native.count("AXUIElementSetAttributeValue("), 1)
        self.assertIn("if (s->result.selection_matches > 1) return mrk_ax_fail(s, MRK_OPEN_AMBIGUOUS);", roster)
        self.assertIn("if (s->result.selection_matches == 1) s->result.selection_checks |= 2u;", roster)
        self.assertIn("rows || list ? MRK_SELECT_ROWS : 16, at != 0", roster)  # Empty root is unsupported, not pending.
        self.assertIn("required_ns > 100_000_000", rust)
        self.assertIn("remaining.as_nanos() < u128::from(required_ns)", rust)
        self.assertIn("context.end.saturating_duration_since(Instant::now())", rust)
        self.assertIn("self.end.min(Instant::now() + Duration::from_secs(2))", observer)
        self.assertIn("edit::bounded(&failure_context(&self), 8192)", observer)
        self.assertIn("(frame.len() <= 8448).then_some(frame)", observer)
        filter_source = native.split("static BOOL mrk_panel_observe_file_filter(", 1)[1].split("int mrk_panel_observe_project_field(", 1)[0]
        for getter in ("[panel allowedContentTypes]", "[panel allowsOtherFileTypes]"):
            self.assertEqual(filter_source.count(getter), 1)
        self.assertIn("if (s->observationFileFilter) return NO;", filter_source)
        for forbidden in ("setAllowed", "setAllows", "UTF8String", "for (", "while (", " retain]", " release]"):
            self.assertNotIn(forbidden, filter_source)
        navigation = native.split("int mrk_panel_observe_project_field(", 1)[1].split("int mrk_panel_observe_version_source_name(", 1)[0]
        self.assertLess(navigation.index("s->observationProjectField != 511u || !mrk_panel_observe_file_filter"),
                        navigation.index("[panel setDirectoryURL:"))
        self.assertIn("*filter = s->observationFileFilter; return result;", navigation)
        self.assertIn('file_filter: filter_valid.then_some(filter)', rust)
        good = M.expected_result(BINDING, "project-fields")
        for flags, allowed, other in ((1, None, None), (3, None, None), (7, "unrestricted", None),
                                       (11, "restricted", None), (23, "unrestricted", False),
                                       (27, "restricted", False), (55, "unrestricted", True), (59, "restricted", True)):
            diagnostic = {"facts": flags, "allowedTypes": allowed, "allowsOther": other}
            self.assertEqual(M._file_filter_context(diagnostic), diagnostic)
            if flags in (23, 27, 55, 59):
                value = deepcopy(good)
                value["projectFields"]["rows"][0]["initialRootAndOptions"]["fileFilter"] = diagnostic
                self.assertEqual(M.parse_result(captured(value), b"", BINDING, "project-fields"), value)
            else:
                with self.assertRaises(M.Refused): M._file_filter_context(diagnostic, complete=True)
        for diagnostic in (None, {"facts": 0, "allowedTypes": None, "allowsOther": None},
                            {"facts": True, "allowedTypes": None, "allowsOther": None},
                            {"facts": 63, "allowedTypes": "unrestricted", "allowsOther": True},
                            {"facts": 23, "allowedTypes": "restricted", "allowsOther": False},
                            {"facts": 23, "allowedTypes": "unrestricted", "allowsOther": 0}):
            with self.assertRaises(M.Refused): M._file_filter_context(diagnostic, complete=True)
        # Largest current success report: all four VersionSource histories at
        # the full 8-pass AX/CF envelopes, plus maximum-length complete filter DATA.
        largest = deepcopy(good)
        pending = [[i + 1, i * 3072, (i + 1) * 3072, i * 1024, (i + 1) * 1024,
                    255, 8, 16, 255, 31, 6, 1, 0, 0, 0, 2] for i in range(7)]
        for index in (1, 5, 6, 7):
            action = largest["projectFields"]["acceptedOpenHistories"][index]["selectionInput"]
            action["selection"].update(nodes=255, depth=8, attribute="SelectedChildren")
            action["selection"]["contentReadiness"] = {
                "sample": 8, "callsBefore": 21504, "cfBefore": 7168, "wait": 0, "pending": deepcopy(pending)}
            action["selection"]["projectionDiagnostic"] = {
                "version": 1, "state": "returned-incomplete", "normalFixtureMask": 31,
                "callsBefore": 2048, "callsAfter": 3072, "cfBefore": 512, "cfAfter": 1024,
                "eligibleFrontiers": 255, "attemptedFrontiers": 64, "addedNodes": 0, "maxDepth": 0,
                "alternateValueMask": 31, "frontierLabelMask": 0, "outsideFieldMask": 31,
                "alternateRoleMask": 0x7004, "frontierRoleMask": 0, "unavailable": 63,
                "omissions": 1023, "duplicates": 2048, "nonStringValues": 100}
            action["promptButton"].update(calls=24576, cfSlots=8192, cfSlotsRetired=8192,
                                         initialNodesExamined=16, recheckNodesExamined=16, lastDepth=8)
        for row in largest["projectFields"]["rows"]:
            if row["kind"] == "version-source":
                row["initialRootAndOptions"]["fileFilter"] = {"facts": 23, "allowedTypes": "unrestricted", "allowsOther": False}
        self.assertEqual(M.parse_result(captured(largest), b"", BINDING, "project-fields"), largest)
        self.assertLessEqual(len(captured(largest)) - len(M.MARKER) - 1, M.PROJECT_FIELDS_JSON_LIMIT)
        # Conservative complete-shape failure-size DATA only; contradictory
        # maxima are deliberately NOT presented to the parser as a native event.
        frame = accessibility_context_data(); frame["snapshotSource"] = "record"
        frame["pending"] = {"kind": "accessibility", "step": "ProjectFields(Native(0))"}
        frame["nativeHandler"]["step"] = "ProjectFields(Native(0))"
        frame["lastPanel"].update(step="ProjectFields(Native(0))", id=2, kind="version-source",
            directoryBound=False, directoryReturned=False, directoryReady=False,
            directoryReadiness="selection-not-matched", waitLocation="open-directory-readiness")
        frame["accessibility"] = deepcopy(largest["projectFields"]["acceptedOpenHistories"][1]["selectionInput"])
        frame["accessibilityBinding"] = deepcopy(largest["projectFields"]["acceptedOpenHistories"][1]["selectionBinding"])
        frame["completionSelection"] = deepcopy(largest["projectFields"]["acceptedOpenHistories"][1]["selectionCompletion"])
        frame["originalWindow"] = deepcopy(good["native"]["originalWindow"])
        frame["projectSelection"] = project_selection_context_data("inconsistent-original-data", "captured-object-metadata-changed")["projectSelection"]
        frame["projectFieldPreparation"] = {"operationId": 2, "kind": "version-source", "returned": True,
            "result": "permission-denied", "facts": 6143,
            "fileFilter": {"facts": 23, "allowedTypes": "unrestricted", "allowsOther": False},
            "nameFieldPreparation": {"returned": True, "result": "permission-denied", "facts": 31}}
        frame["dom"] = {"evaluations": 160, "lastProjectChooser": {
            "step": "ChooseProject", "sequence": 160, "dashboardSelected": False,
            "buttonDisabled": False, "reason": "offline-preflight"}}
        action = frame["accessibility"]
        action.update(site="control-child-count-limit", error="cleanup-unknown", state="requested",
                      timely=False, custodyKnown=False, triggered=False)
        action["promptChecks"] = {"initial": False, "final": False}
        action["promptButton"].update(cleanupReturned=False, lastRole="ScrollArea", axError=-25214,
            axFailure={"operation": "get-attribute-value-count", "attribute": "SelectedChildren"})
        action["promptButton"]["checks"] = dict.fromkeys(M.ACCESSIBILITY_BUTTON_CHECKS, False)
        action["selection"]["checks"] = dict.fromkeys(M.ACCESSIBILITY_SELECTION_CHECKS, False)
        action["selection"]["projectionSummary"] = {key: 255 for key in action["selection"]["projectionSummary"]}
        action["selection"]["projectionSummary"].update(outsideEntryRoleMask=0x1c210,
            fixtureLabelMask=31, expectedLabelRelations=7, expectedLabelRoleMask=0x1f004)
        action["selection"]["limit"] = {"predicate": "child-copy-count", "observed": -9223372036854775808,
                                       "cap": 1024, "queued": 256, "children": 32}
        for proof in (frame["accessibilityBinding"]["binding"], action["selectionParentProof"],
                      action["initialOriginalProof"], action["originalProof"]):
            proof.update(parent="type-invalid", panel="encoding-invalid", originals="multiple",
                         site="panel-attached-sheet", error="cleanup-unknown", children=17)
            proof["checks"] = dict.fromkeys(M.ACCESSIBILITY_PROOF_CHECKS, False)
        frame["accessibilityBinding"]["start"]["result"] = "permission-denied"
        frame["accessibilityBinding"]["configuration"].update(parent="type-invalid", prompt="type-invalid",
            site="initial-directory-url", error="cleanup-unknown", initialDirectorySetterEntered=False,
            initialDirectorySetterReturned=False)
        frame["completionSelection"].update(pollResult="invalid-return", timely=False)
        frame["completionSelection"]["facts"].update(response="decline", selection="ordinary-path-disagreement",
            callbackEntered=False, urlsReadEntered=False, urlsReadReturned=False, callbackReturned=False)
        payload = context_row(frame)
        self.assertLessEqual(len(payload.split(b"=", 1)[1].rstrip(b"\n")), M.FAILURE_CONTEXT_LIMIT)
        marker = (b"MRK_MACOS_AQUA_FAILURE_STEP=ProjectFields(Native(0))\n"
                  b"MRK_MACOS_AQUA_FAILURE_REASON=native-default-input\n")
        self.assertLessEqual(len(marker + payload + b"MRK_MACOS_AQUA=failed\n"), 8448)

    def test_selection_limit_scalars_are_closed_original_counts_not_success(self):
        # Synthetic DATA only; never recovered/native branch observations.
        good = M.expected_result(BINDING, "project-fields")["projectFields"]["acceptedOpenHistories"][1]["selectionInput"]
        action = deepcopy(good)
        action.update(attempted=False, pressReturned=False, triggered=None, initialOriginalProof=None, originalProof=None,
                      promptChecks={"initial": None, "final": None}, site="selection-projection", error="limit")
        action["promptButton"].update(checks={key: index < 2 for index, key in enumerate(M.ACCESSIBILITY_BUTTON_CHECKS)},
            calls=202, initialNodesExamined=0, recheckNodesExamined=0, lastRole="Sheet", lastDepth=0, cfSlots=88, cfSlotsRetired=88)
        action["selection"].update(checks=dict.fromkeys(M.ACCESSIBILITY_SELECTION_CHECKS, False),
            attempted=False, returned=False, selected=None, nodes=24, matches=0, attribute="not-read", lastRole="Row", depth=4,
            limit={"predicate": "label-length", "observed": 513, "cap": 512, "queued": 25, "children": None})
        action["selection"]["projectionSummary"].update(fixtureLabelMask=0, expectedLabelRelations=0, expectedLabelRoleMask=0)

        def admit(sample):
            self.assertEqual(M._accessibility_selection(sample["selection"], sample["promptButton"], sample["site"], sample["error"], content=True),
                             sample["selection"])
            self.assertFalse(M._selection_succeeded(sample["selection"]))
            self.assertFalse(M._accessibility_succeeded(sample))

        cases = [
            ("label-length", 513, 512, 25, None, "Row", 4),
            ("label-length", (1 << 63) - 1, 512, 25, None, "StaticText", 4),
            ("child-count", 17, 16, 25, None, "Row", 4),
            ("child-count", 33, 32, 25, None, "Table", 4),
            ("child-copy-count", 17, 16, 25, None, "Group", 4),
            ("child-copy-count", -(1 << 63), 32, 25, None, "List", 4),
            ("queue-capacity", 256, 256, 256, 1, "Row", 4),
            ("queue-capacity", 247, 256, 247, 10, "Row", 4),
            ("depth", 8, 8, 256, 16, "Row", 8),  # Depth is FIRST even if both bounds refuse.
            ("ax-call-budget", 3072, 3072, 25, None, "not-read", 4),
            ("cf-slot-budget", 1024, 1024, 25, None, "not-read", 4),
        ]
        for predicate, observed, cap, queued, children, role, depth in cases:
            with self.subTest(predicate=predicate, observed=observed):
                sample = deepcopy(action)
                sample["selection"].update(lastRole=role, depth=depth,
                    limit=dict(predicate=predicate, observed=observed, cap=cap, queued=queued, children=children))
                if predicate == "ax-call-budget": sample["promptButton"]["calls"] = observed
                if predicate == "cf-slot-budget": sample["promptButton"].update(cfSlots=observed, cfSlotsRetired=observed)
                admit(sample)
        # No fake zero queue/children after leaving the projection; the last
        # completed roster's counters are not new recheck/readback observations.
        for site, completed, selected, predicate, observed, cap in (
            ("selection-recheck", 2, None, "ax-call-budget", 3071, 3072),
            ("selection-settable", 3, None, "cf-slot-budget", 1024, 1024),
            ("selection-readback", 4, True, "child-count", 33, 32),
            ("selection-readback", 4, True, "child-copy-count", -1, 32),
        ):
            sample = deepcopy(action); sample["site"] = site
            sample["selection"].update(checks={key: index < completed for index, key in enumerate(M.ACCESSIBILITY_SELECTION_CHECKS)},
                matches=1, attempted=selected is not None, returned=selected is not None, selected=selected,
                attribute="SelectedRows" if completed >= 3 else "not-read",
                limit=dict(predicate=predicate, observed=observed, cap=cap, queued=None, children=None))
            sample["selection"]["projectionSummary"].update(fixtureLabelMask=1, expectedLabelRelations=1, expectedLabelRoleMask=1 << 15)
            if predicate == "ax-call-budget": sample["promptButton"]["calls"] = observed
            if predicate == "cf-slot-budget": sample["promptButton"].update(cfSlots=observed, cfSlotsRetired=observed)
            admit(sample)
            for key in ("queued", "children"):
                bad = deepcopy(sample); bad["selection"]["limit"][key] = 0
                with self.assertRaises(M.Refused):
                    M._accessibility_selection(bad["selection"], bad["promptButton"], bad["site"], bad["error"], content=True)
        for patch_data in (
            {"predicate": "INERT_PRIVATE"}, {"observed": 512}, {"observed": True}, {"observed": 513.0},
            {"observed": 1 << 63}, {"observed": -(1 << 63) - 1}, {"cap": True}, {"cap": 0}, {"cap": 513},
            {"queued": None}, {"queued": 0}, {"queued": 24}, {"queued": 257}, {"queued": True},
            {"children": 0}, {"children": 1}, {"private": "INERT_PRIVATE"},
            {"predicate": "child-count", "observed": 16, "cap": 16},
            {"predicate": "child-count", "observed": 33, "cap": 32},
            {"predicate": "child-copy-count", "observed": 0, "cap": 16},
            {"predicate": "queue-capacity", "observed": 255, "cap": 256, "queued": 255, "children": 1},
            {"predicate": "queue-capacity", "observed": 256, "cap": 256, "queued": 256, "children": 17},
            # Historical cap claims are not current-source refusal predicates.
            {"predicate": "queue-capacity", "observed": 49, "cap": 49, "queued": 49, "children": 1},
            {"predicate": "queue-capacity", "observed": 128, "cap": 128, "queued": 128, "children": 1},
            {"predicate": "ax-call-budget", "observed": 512, "cap": 512},
            {"predicate": "cf-slot-budget", "observed": 256, "cap": 256},
            {"predicate": "depth", "observed": 8, "cap": 8, "children": 1},
            {"predicate": "ax-call-budget", "observed": 3070, "cap": 3072},
            {"predicate": "cf-slot-budget", "observed": 1023, "cap": 1024},
        ):
            bad = deepcopy(action); bad["selection"]["limit"].update(patch_data)
            # Match counters so exact stale/underfilled caps, not a different
            # counter mismatch, are what refuse these current-wire claims.
            if patch_data.get("predicate") == "ax-call-budget":
                bad["promptButton"]["calls"] = patch_data["observed"]
            if patch_data.get("predicate") == "cf-slot-budget":
                bad["promptButton"].update(cfSlots=patch_data["observed"], cfSlotsRetired=patch_data["observed"])
            with self.subTest(refused=patch_data), self.assertRaises(M.Refused):
                M._accessibility_selection(bad["selection"], bad["promptButton"], bad["site"], bad["error"], content=True)
        for mutation in (
            lambda a: a["selection"].pop("limit"),
            lambda a: a["selection"].update(limit=None),
            lambda a: a.update(site="selection-write"),
            lambda a: a.update(error="deadline"),
            lambda a: a["promptButton"].update(axError=-25204,
                axFailure={"operation": "copy-attribute-value", "attribute": "Parent"}),
        ):
            bad = deepcopy(action); mutation(bad)
            with self.assertRaises(M.Refused):
                M._accessibility_selection(bad["selection"], bad["promptButton"], bad["site"], bad["error"], content=True)
        self.assertIsNone(good["selection"]["limit"])
        self.assertTrue(M._selection_succeeded(good["selection"]))
        forged = deepcopy(good); forged["selection"]["limit"] = deepcopy(action["selection"]["limit"])
        self.assertFalse(M._selection_succeeded(forged["selection"]))
        with self.assertRaises(M.Refused):
            M._accessibility_selection(forged["selection"], forged["promptButton"], forged["site"], forged["error"], content=True)
        for absent in (None, {"predicate": None, "observed": None, "cap": None, "queued": None, "children": None}):
            bad = deepcopy(action); bad["selection"]["limit"] = absent
            with self.assertRaises(M.Refused):
                M._accessibility_selection(bad["selection"], bad["promptButton"], bad["site"], bad["error"], content=True)

    def test_selection_limit_source_preserves_first_error_and_query_budgets(self):
        native = (PATH.parents[1] / "native/macos-installed-native/src/native.m").read_text()
        rust = (PATH.parents[1] / "native/macos-installed-native/src/lib.rs").read_text()
        observer = (PATH.parents[1] / "src-tauri/src/installed_shell_observation_macos.rs").read_text()
        helper = native.split("static BOOL mrk_ax_selection_limit(", 1)[1].split("static BOOL mrk_ax_control_limit(", 1)[0]
        self.assertIn("if (!s->result.error && mrk_ax_selecting(s))", helper)
        self.assertIn("return mrk_ax_fail(s, MRK_OPEN_LIMIT);", helper)
        for forbidden in ("AXUIElement", "CFArrayGet", "CFStringGet", "mrk_ax_copy(", "mrk_ax_array("):
            self.assertNotIn(forbidden, helper)
        self.assertIn("if (!s->result.error) s->result.error = error;", native)
        self.assertIn("s->result.site == MRK_OPEN_SELECTION_PROJECTION ? s->selection_queued : 0", helper)
        for bound in ("MRK_PROMPT_CALLS = 512", "MRK_PROMPT_CF = 256", "MRK_SELECT_NODES = 256",
                      "MRK_SELECT_CALLS = 3072", "MRK_SELECT_CF = 1024",
                      "MRK_CONTROL_DEPTH = 8", "MRK_SELECT_ROWS = 32", "MRK_PROMPT_ORIGINALS = 9"):
            self.assertIn(bound, native)
        arenas = native.split("enum { MRK_PROMPT_CALLS =", 1)[1].split("static atomic_uint mrk_prompt_next", 1)[0]
        for retained in (
            "AXUIElementRef nodes[MRK_SELECT_NODES];",
            "unsigned parents[MRK_SELECT_NODES], depths[MRK_SELECT_NODES], roles[MRK_SELECT_NODES], entries[MRK_SELECT_NODES];",
            "BOOL matches[MRK_SELECT_NODES]; unsigned candidate, label;",
            "MRKSelectionPass selection[MRK_SELECT_SAMPLES];",
            "CFArrayRef selection_attributes;", "AXUIElementRef timeout_element;", "MRKOpenTimeout installed_timeout;",
            "static MRKPrompt mrk_prompt_originals[MRK_PROMPT_ORIGINALS];",
            "MRKPromptOwned owned[MRK_SELECT_TOTAL_CF]; unsigned count;",
            "_Static_assert(sizeof(mrk_prompt_originals) <= 1152u * 1024u,",
            "MRK_SELECT_CF >= 3u * MRK_SELECT_NODES + 8u * MRK_CONTROL_NODES + 6u * MRK_CONTROL_DEPTH + 64u",
            "MRK_SELECT_CALLS >= 8u * MRK_SELECT_NODES + 20u * MRK_CONTROL_NODES + 12u * MRK_CONTROL_DEPTH + 132u",
        ):
            self.assertIn(retained, arenas)
        label = native.split("static BOOL mrk_ax_selection_label(", 1)[1].split("static BOOL mrk_ax_selection_roster(", 1)[0]
        self.assertEqual(label.count("CFStringGetLength(value)"), 1)
        self.assertIn("if (length > 512)", label)
        roster = native.split("static BOOL mrk_ax_selection_roster(", 1)[1].split("static BOOL mrk_ax_content_wait(", 1)[0]
        self.assertLess(roster.index("s->selection_queued = queued;"), roster.index("mrk_ax_type(s, node"))
        self.assertLess(roster.index("if (p->depths[at] == MRK_CONTROL_DEPTH)"),
                        roster.index("if ((unsigned)count > MRK_SELECT_NODES - queued)"))
        self.assertEqual(roster.count("CFArrayGetCount(children)"), 1)
        self.assertIn("rows || list ? MRK_SELECT_ROWS : 16", roster)
        self.assertIn("p->nodes[0] = sheet; unsigned queued = 1;", roster)
        self.assertIn("for (unsigned other = 0; other < queued; ++other)", roster)
        self.assertIn("p->nodes[queued] = (AXUIElementRef)CFArrayGetValueAtIndex(children, child);", roster)
        self.assertIn("p->parents[queued] = at; p->depths[queued] = p->depths[at] + 1;", roster)
        self.assertIn("p->entries[queued] = rows || list ? queued : entry; queued++;", roster)
        self.assertEqual(M.re.findall(r"\bqueued\s*(?:\+\+|--|[+-]?=(?!=))", roster),
                         ["queued =", "queued++"])
        for recycled in ("--queued", "memmove(", "memset(", "p->nodes[at] = NULL", "% MRK_SELECT_NODES"):
            self.assertNotIn(recycled, roster)
        pair = native.split("static CFTypeRef mrk_ax_selection_pair(", 1)[1].split("static BOOL mrk_ax_projection(", 1)[0]
        self.assertIn("if (!s->selection_attributes) {", pair)
        self.assertEqual(pair.count("CFArrayCreate("), 1)
        self.assertEqual(pair.count("mrk_ax_slot(s)"), 2)  # One fixed attribute array; one original result per node.
        self.assertEqual(pair.count("s->result.calls++"), 1)
        self.assertEqual(pair.count("AXUIElementCopyMultipleAttributeValues("), 1)
        # Algebra for successful nonroot nodes with one still-fitting timeout.
        # No tree shape, native timing, partial result or actual receipt is invented.
        for labels, counted, copied, old_calls, paired_calls, old_slots, paired_slots in (
            (0, 0, 0, 4, 2, 2, 1), (1, 0, 0, 6, 3, 3, 2),
            (0, 1, 0, 6, 3, 2, 1), (0, 1, 1, 8, 4, 3, 2),
            (1, 1, 0, 8, 4, 3, 2), (1, 1, 1, 10, 5, 4, 3),
        ):
            self.assertEqual(old_calls, 2 * (2 + labels + counted + copied))
            self.assertEqual(paired_calls, 1 + (1 + labels + counted + copied))
            self.assertEqual(old_slots, 2 + labels + copied)
            self.assertEqual(paired_slots, 1 + labels + copied)
            self.assertEqual(old_calls - 2 * (1 + labels + counted + copied), 2)
        # The fixed request array adds one original slot, not one per node.
        # Each sample includes its own setup and possible final tail within3072;
        # ordinary originals stay512. Aggregate counters never reset.
        slots = native.split("static MRKPromptOwned *mrk_ax_slot(", 1)[1].split("static BOOL mrk_ax_admit(", 1)[0]
        self.assertIn("const unsigned cap = s->result.selection_mode == 1 ? MRK_SELECT_CF : MRK_PROMPT_CF;", slots)
        self.assertIn("if (used == cap || s->count == total_cap)", slots)
        self.assertNotRegex(native, r"s->result\.calls\s*(?:=(?!=)|-=|--)")
        decoder = rust.split("fn selection_limit_return(", 1)[1].split("/// The actual selecting", 1)[0]
        labels = M.re.findall(r'"([a-z-]+)"', decoder.split("predicate: *[", 1)[1].split("]", 1)[0])
        self.assertEqual(tuple(labels), M.ACCESSIBILITY_SELECTION_LIMITS)
        self.assertIn("selection_limit_observed: i64", rust)
        self.assertIn("sizeof(CFIndex) == sizeof(int64_t)", native)
        self.assertIn("w.selection_limit_queued <= w.selection_nodes", decoder)
        self.assertIn("(21..=25).contains(&w.site) && w.error == 7", decoder)
        self.assertIn('"limit":p.limit.map(|r| json!({"predicate":r.predicate,"observed":r.observed,"cap":r.cap,"queued":r.queued,"children":r.children}))', observer)

        # Summary counters/local CFString comparisons annotate only existing
        # admitted observations. No new AX query, traversal or label output.
        self.assertLess(roster.index("s->result.selection_summary_version = 2u;"),
                        roster.index("for (unsigned at = 0; at < queued; ++at)"))
        self.assertLess(roster.index("if (!at && kind != MRK_ROLE_SHEET)"),
                        roster.index("s->result.selection_table_roles++;"))
        for role, counter in (("MRK_ROLE_TABLE", "table_roles"), ("MRK_ROLE_OUTLINE", "outline_roles"), ("MRK_SELECT_LIST", "list_roles")):
            self.assertIn(f"if (kind == {role}) s->result.selection_{counter}++;", roster)
        entry = roster.split("if (entry == at) {", 1)[1].split("} else if", 1)[0]
        self.assertLess(entry.index("return mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED);"),
                        entry.index("s->result.selection_entry_roots++;"))
        self.assertLess(label.index("if (s->result.error) return NO;"), label.index("if (!value) {"))
        absent = label.split("if (!value) {", 1)[1].split("\n    }", 1)[0]
        self.assertEqual(absent.strip(), "if (optional) s->result.selection_title_absent++;\n        return optional;")
        for counter in ("title_present", "value_present"):
            self.assertLess(label.index("mrk_ax_type(s, value, CFStringGetTypeID())"), label.index(f"s->result.selection_{counter}++"))
            self.assertLess(label.index("if (length > 512)"), label.index(f"s->result.selection_{counter}++"))
            self.assertLess(label.index(f"s->result.selection_{counter}++"), label.index("CFEqual(value, expected)"))
        for counter in ("table_roles", "outline_roles", "list_roles", "entry_roots", "title_present", "title_absent", "value_present"):
            self.assertEqual((label + roster).count(f"s->result.selection_{counter}++"), 1)
        self.assertEqual(label.count("mrk_ax_copy("), 1)
        self.assertEqual(label.count("CFStringGetLength("), 1)
        self.assertEqual(label.count("CFEqual("), 1)
        self.assertIn("BOOL exact = CFEqual(value, expected);\n    if (exact) {", label)
        self.assertLess(label.index("p->matches[entry] = YES;"), label.index("mrk_ax_selection_label_summary(s,"))
        diagnostic = native.split("static void mrk_ax_selection_label_summary(", 1)[1].split("static unsigned mrk_ax_selection_role(", 1)[0]
        self.assertEqual(M.re.findall(r'CFSTR\("([^\"]+)"\)', diagnostic),
                         ["VERSION", "link-input", "kind-input", "inputs", "version.properties"])
        self.assertIn("CFEqual(value, fixture_labels[i])", diagnostic)
        self.assertIn("CFStringCompare(value, expected, kCFCompareCaseInsensitive)", diagnostic)
        self.assertIn("CFStringFind(value, expected, 0).location != kCFNotFound", diagnostic)
        self.assertIn("uint32_t relations = exact ? 1u : 0u;", diagnostic)
        self.assertIn("if (!exact) {", diagnostic)
        for forbidden in ("AXUIElement", "mrk_ax_copy", "mrk_ax_slot", "CFStringGetCString", "UTF8String", "printf", "candidate", "selection_matches", "selection_checks"):
            self.assertNotIn(forbidden, diagnostic)
        cutoff = roster.split("if (!entry && !rows && !list && !structural) {", 1)[1].split("\n        }", 1)[0]
        self.assertLess(cutoff.index("if (kind == MRK_SELECT_ROW || kind == MRK_SELECT_CELL) return"),
                        cutoff.index("s->result.selection_outside_entry_role_mask |= 1u << kind;"))
        self.assertLess(cutoff.index("s->result.selection_outside_entry_role_mask |= 1u << kind;"), cutoff.index("continue;"))
        self.assertEqual(roster.count("s->result.selection_outside_entry_role_mask |="), 1)
        self.assertEqual(sum(1 << M.ACCESSIBILITY_SELECTION_ROLES.index(role)
                            for role in ("Button", "opaque", "Image", "StaticText", "TextField")), 0x1c210)
        summary_decoder = rust.split("fn selection_projection_summary_return(", 1)[1].split("/// The actual selecting", 1)[0]
        self.assertIn("w.selection_summary_version == 0", summary_decoder)
        self.assertIn("w.selection_summary_version != 2", summary_decoder)
        self.assertIn("w.selection_outside_entry_role_mask & !0x1c210 != 0", summary_decoder)
        self.assertLess(summary_decoder.index("counts.iter().any(|&n| n > w.selection_nodes)"), summary_decoder.index("let roles ="))
        self.assertIn("w.selection_matches > w.selection_entry_roots", summary_decoder)
        self.assertIn("w.selection_matches > w.selection_title_present + w.selection_value_present", summary_decoder)
        self.assertIn("w.selection_fixture_label_mask & !31 != 0", summary_decoder)
        self.assertIn("w.selection_expected_label_relations & !7 != 0", summary_decoder)
        self.assertIn("w.selection_expected_label_role_mask & !0x1f004 != 0", summary_decoder)
        self.assertEqual(sum(1 << M.ACCESSIBILITY_SELECTION_ROLES.index(role)
                            for role in ("Group", "Row", "Cell", "Image", "StaticText", "TextField")), 0x1f004)
        matching = rust.split("impl VersionSourceSelection {", 1)[1].split("fn selection_return(", 1)[0]
        self.assertNotIn("projection_summary", matching)
        opening = rust.split("impl OpenReport {", 1)[1].split("fn open_return(", 1)[0]
        self.assertNotIn("projection_summary", opening)
        qualification = PATH.read_text()
        success = qualification.split("def _selection_succeeded(", 1)[1].split("def _accessibility_selection_limit(", 1)[0]
        self.assertNotIn("projectionSummary", success)
        self.assertIn('or selection["projectionSummary"] is not None', qualification)
        observed = observer.split("fn selection_value(", 1)[1].split("fn prompt_button_value(", 1)[0]
        fields = observed.split('"projectionSummary":p.projection_summary.map(|r| json!({', 1)[1].split("}))", 1)[0]
        self.assertEqual(set(M.re.findall(r'"([A-Za-z]+)":', fields)),
            {"tableRoles", "outlineRoles", "listRoles", "entryRoots", "titlePresent", "titleAbsent", "valuePresent", "outsideEntryRoleMask",
             "fixtureLabelMask", "expectedLabelRelations", "expectedLabelRoleMask"})

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
        roster = native.split("static BOOL mrk_ax_selection_roster(", 1)[1].split("static BOOL mrk_ax_content_wait(", 1)[0]
        for condition in ("other != at && p->nodes[other] && CFEqual(node, p->nodes[other])",
                          "mrk_ax_selection_pair(s, node, p->nodes[p->parents[at]])",
                          "kind == MRK_ROLE_TABLE || kind == MRK_ROLE_OUTLINE", "kind == MRK_SELECT_LIST",
                          "rows ? kind != MRK_SELECT_ROW", "kind == MRK_ROLE_SHEET || kind == MRK_ROLE_GROUP",
                          "kind == MRK_ROLE_SPLIT_GROUP", "kind == MRK_ROLE_SCROLL_AREA", "kind == MRK_ROLE_BROWSER",
                          "kind == MRK_SELECT_COLUMN", "kind == MRK_SELECT_TEXT || kind == MRK_SELECT_FIELD",
                          "kAXValueAttribute, NO, expected", "kAXTitleAttribute, YES, expected",
                          "rows ? kAXRowsAttribute : kAXChildrenAttribute", "rows || list ? MRK_SELECT_ROWS : 16",
                          "p->depths[at] == MRK_CONTROL_DEPTH", "(unsigned)count > MRK_SELECT_NODES - queued",
                          "p->entries[queued] = rows || list ? queued : entry", "s->result.selection_matches > 1"):
            self.assertIn(condition, roster)
        self.assertLess(roster.index("for (unsigned at = 0; at < queued; ++at)"), roster.index("s->result.selection_checks |= 1u"))
        self.assertLess(roster.index("s->result.selection_checks |= 1u"), roster.index("s->result.selection_matches > 1"))
        pair = native.split("static CFTypeRef mrk_ax_selection_pair(", 1)[1].split("static BOOL mrk_ax_projection(", 1)[0]
        self.assertIn("const void *names[] = { kAXParentAttribute, kAXRoleAttribute };", pair)
        self.assertIn("CFArrayCreate(NULL, names, 2, &kCFTypeArrayCallBacks)", pair)
        self.assertLess(pair.index("MRKPromptOwned *attributes = mrk_ax_slot(s)"), pair.index("CFArrayCreate("))
        self.assertLess(pair.index("mrk_ax_type(s, attributes->value, CFArrayGetTypeID())"),
                        pair.index("s->selection_attributes = attributes->array"))
        batch_call = "AXUIElementCopyMultipleAttributeValues(element, s->selection_attributes,\n" \
                     "        kAXCopyMultipleAttributeOptionStopOnError, &slot->array)"
        self.assertEqual(pair.count(batch_call), 1)
        self.assertLess(pair.index("MRKPromptOwned *slot = mrk_ax_slot(s)"), pair.index(batch_call))
        self.assertLess(pair.index("mrk_ax_before(s, element)"), pair.index("s->result.calls++"))
        self.assertLess(pair.index("s->result.calls++"), pair.index(batch_call))
        self.assertLess(pair.index(batch_call), pair.index("mrk_ax_status(s, status, MRK_AX_OP_COPY_MULTIPLE_ATTRIBUTE_VALUES, MRK_AX_ATTR_NONE)"))
        self.assertLess(pair.index(batch_call), pair.index("admitted = mrk_ax_admit(s, 0, 0, NULL)"))
        self.assertIn("if (!copied || !admitted || !mrk_ax_type(s, slot->value, CFArrayGetTypeID())) return NULL;", pair)
        self.assertIn("if (CFArrayGetCount(slot->array) != 2) { mrk_ax_fail(s, MRK_OPEN_MALFORMED); return NULL; }", pair)
        self.assertLess(pair.index("CFArrayGetCount(slot->array) != 2"), pair.index("CFArrayGetValueAtIndex(slot->array, 0)"))
        self.assertLess(pair.index("mrk_ax_type(s, parent, s->elementType)"), pair.index("CFEqual(parent, expected_parent)"))
        self.assertIn("if (!CFEqual(parent, expected_parent)) { mrk_ax_fail(s, MRK_OPEN_CHANGED); return NULL; }", pair)
        self.assertLess(pair.index("CFEqual(parent, expected_parent)"), pair.index("CFArrayGetValueAtIndex(slot->array, 1)"))
        self.assertIn("return mrk_ax_type(s, role, CFStringGetTypeID()) ? role : NULL;", pair)
        for forbidden in ("mrk_ax_copy(", "mrk_ax_array(", "AXValueGet", "CFRelease(", "while (", "for (",
                          "kAXTitleAttribute", "kAXValueAttribute", "kAXChildrenAttribute", "kAXRowsAttribute"):
            self.assertNotIn(forbidden, pair)
        self.assertIn("CFTypeRef role = at ? mrk_ax_selection_pair(s, node, p->nodes[p->parents[at]])\n"
                      "            : mrk_ax_copy(s, node, kAXRoleAttribute, NO, MRK_AX_ATTR_ROLE);", roster)
        for effect in ("AXUIElementSetAttributeValue", "AXUIElementPerformAction"):
            self.assertNotIn(effect, label + roster)
        write = native.split("static BOOL mrk_ax_select_entry(", 1)[1].split("static void mrk_ax_open(", 1)[0]
        for original in ("s->result.selection_checks != 3", "for (unsigned at = p->label;; at = p->parents[at])",
                         "at ? p->nodes[p->parents[at]] : parent", "mrk_ax_selection_role(role) != p->roles[at]",
                         "p->nodes[p->label], p->label_attribute, expected", "p->entries[p->label] != p->candidate",
                         "kind == MRK_ROLE_TABLE || kind == MRK_ROLE_OUTLINE ? kAXSelectedRowsAttribute",
                         "kind == MRK_SELECT_LIST ? kAXSelectedChildrenAttribute : NULL",
                         "mrk_ax_array(s, container, attribute, MRK_SELECT_ROWS, NO, attribute_code)",
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
        self.assertIn("MRK_SELECT_NODES = 256, MRK_SELECT_ROWS = 32", native)
        self.assertIn("MRKSelectionPass selection[MRK_SELECT_SAMPLES];", native)
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

        # The new failure snapshot copies one original return, never AppKit/AX.
        diagnostic = observer.split("fn received_input(self,", 1)[1].split("    fn frame(", 1)[0]
        for required in ("token.same(&receipt.token)", "input_return_time_matches(receipt.returned_at, now, end)",
                         "project_field_return_scope(case, self.step, token.id)", "sample.step != self.step",
                         "token.identity().selects_version_source()", "self.pending != Some(Pending::Accessibility(token.id))",
                         "snapshot.input_body_admission = Some(receipt.body.admitted)", 'snapshot.source = "prearm-open-return"'):
            self.assertIn(required, diagnostic)
        projected = observer.split("fn received_input_sample(", 1)[1].split("#[derive(Clone, Copy)]\nstruct FailureSnapshot", 1)[0]
        for required in ("let native = body.native?; let report = native.report?;",
                         "report.selection_mode != sample.selection", "sample.timely = progress.expired.then_some(false)",
                         "sample.worker_joined = worker_joined", "body.succeeded()", "progress.joined || progress.retired"):
            self.assertIn(required, projected)
        for forbidden in ("sample.complete(", "Some(true); // timely", "installed_prompt_button(", ".recheck(",
                          "std::thread", "run_on_main_thread", "mrk_", "Some(\"admission\")"):
            self.assertNotIn(forbidden, diagnostic + projected)
        generic = observer.split("    fn report_failure(&self)", 1)[1].split("    fn report_expiry(", 1)[0]
        for required in ('reason == "native-default-input"', "Instant::now() < self.end", "r.prepared_open.is_none()",
                         "r.pending == Some(Pending::Accessibility(sample.id))", "sample.native_entered.is_none()",
                         "input_publication_live(progress.snapshot())"):
            self.assertIn(required, generic)
        live = observer.split("fn input_publication_live(", 1)[1].split("fn input_return_time_matches(", 1)[0]
        self.assertIn('"entered" => !progress.returned, "returned" => progress.returned, _ => false', live)
        self.assertIn("!progress.joined && !progress.retired", live)
        worker = observer.split("    fn action_worker(", 1)[1].split("    fn open_unknown(", 1)[0]
        self.assertLess(worker.index('self.fail_with("native-default-input")'), worker.index("if !token.returned()"))
        self.assertLess(worker.index("if !token.returned()"), worker.index("done.try_send(receipt)"))
        relay = observer.split("    fn accessibility_step(", 1)[1].split("    fn native_step(", 1)[0]
        loop = relay.split("        let mut deadline_observed = false;", 1)[1]
        first = loop.split("if flight.worker.as_ref()", 1)[0]
        self.assertLess(first.index('token.expire(); self.fail_with("native-default-deadline")'),
                        first.index("flight.receipt.try_recv()"))
        self.assertLess(first.index("if now >= self.end"), first.index("flight.receipt.try_recv()"))
        self.assertLess(first.index("flight.receipt.try_recv()"), first.index("self.report_open_return(flight, expiry_report)"))
        late = loop.split("flight.worker_returned = Some(returned)", 1)[1].split("                break;", 1)[0]
        self.assertLess(late.index('token.expire(); self.fail_with("native-default-deadline")'),
                        late.index("flight.receipt.try_recv()"))
        self.assertLess(late.index("Instant::now() < self.end"), late.index("flight.receipt.try_recv()"))
        self.assertLess(late.index("flight.receipt.try_recv()"), late.index("self.report_open_return(flight, true)"))
        report = observer.split("    fn report_open_return(", 1)[1].split("    pub(super) fn attach(", 1)[0]
        self.assertIn("if expiry { self.report_expiry(flight.baseline, flight.token.progress()); }", report)
        self.assertIn("return; // A refused/oversized frame still spends the same one-shot writer.", report)
        self.assertNotIn("recv_timeout", report + diagnostic)

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
        self.assertIn("const INSTALLED_MAC_PROJECT_FIELDS_QUALIFIED: bool = true;", runtime)
        ios_selection = owner.split("fn ios_installed_selected(", 1)[1].split("fn android_original_document_matches(", 1)[0]
        self.assertNotIn("PROJECT_FIELDS", ios_selection)
        self.assertNotIn("ios_observation", ios_selection)
        self.assertIn("&& self.runtime.ios_archive_installed_profile_available()", ios_selection)
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
        actual_source = workflow + aqua_headless_source() + aqua_wrapping_source()
        self.assertEqual(workflow.count("      MRK_MACOS_AQUA_SCOPE: ${{ matrix.scope }}\n"), 1)
        self.assertNotIn("workflow_dispatch", actual_source)
        steps = {}
        for block in workflow.split("      - name: ")[1:]:
            name, body = block.split("\n", 1)
            self.assertNotIn(name, steps)
            steps[name] = body
        # Literal run-size contract; raw policy is never replaced by helper SOURCE.
        for raw in steps.values():
            if "        run: |\n" in raw:
                lines = raw.split("        run: |\n", 1)[1].splitlines(keepends=True)
                decoded = "".join(line[10:] if line.startswith("          ") else line for line in lines).rstrip("\n") + "\n"
                self.assertLessEqual(len(decoded), 21000)
        admitted = {
            "Admit only this exact disposable-hosted source route",
            "Check out exact reviewed source without retained credentials",
            "Select DATA stager Python, not the packaged interpreter",
            "Reserve fresh private work before every candidate and toolchain query",
            "Bind the complete reviewed first-party checkout before compilation",
        }
        legacy = {
            "Select the fixed configured signed runtime before any payload download",
            "Download only the configured signed Python capsule",
            "Project the configured capsule as DATA without executing it",
            "Select fixed frontend compiler",
            "Record exact source and actual tool bindings only after route admission",
            "Check current owner pins before native preparation",
            "Fail fast on native Scripts ownership and package format (never Installer)",
            "Acquire and verify the two fixed Android support archives as DATA",
            "Admit only a fresh independently pinned Python transport destination",
            "Download the independently accepted fresh Python transport",
            "Project the pinned fresh Python transport without executing it",
            "Prepare the current payload from the independently accepted fresh Python supplier",
            "Require the fixed SOURCE producer identity and release before ordinary signing",
            "Build and sign the fixed resident image and C facades",
            "Build and sign the separate fixed vault helper before binding the app",
            "Compile the fixed debug actual-main observer and normal embedded frontend once",
            "Assemble the instrumented observation app with SOURCE-selected signing",
            "Bind this signed app and current-source runtime into fresh Installer DATA",
            "Build the fixed one-shot root Installer and scripts-only package",
            "Sign and notarize the completed scripts-only Installer package before final P",
            "Application installation uses only standard privileged Installer; app and Python stay nonroot",
            "Verify source stayed unchanged; retire only disposable owned build output",
        }
        toolchain = {
            "Admit the fixed image Rust tools without installing a distribution":
                "success() && (env.MRK_MACOS_AQUA_SCOPE == 'project-fields' || env.MRK_MACOS_AQUA_SCOPE == 'ios-current-synthetic' || env.MRK_MACOS_AQUA_SCOPE == 'android-inputs' || env.MRK_MACOS_AQUA_SCOPE == 'project-fields-android-inputs' || env.MRK_MACOS_AQUA_SCOPE == 'vault-helper-shipping' || env.MRK_MACOS_AQUA_SCOPE == 'installation-inspection' || env.MRK_MACOS_AQUA_SCOPE == 'vault-helper-shipping-installation-inspection' || env.MRK_MACOS_AQUA_SCOPE == 'wrapping-keychain-private' || env.MRK_MACOS_AQUA_SCOPE == 'android-registration-lifecycle' || env.MRK_MACOS_AQUA_SCOPE == 'project-recovery-pending' || env.MRK_MACOS_AQUA_SCOPE == 'ios-recovery-pending' || env.MRK_MACOS_AQUA_SCOPE == 'doctor-preflight2' || env.MRK_MACOS_AQUA_SCOPE == 'local-edits3')",
        }
        classifiers = {
            "Classify installed Xcode originals without preparing or selecting a toolchain":
                "success() && env.MRK_MACOS_AQUA_SCOPE == 'xcode-installed-classification'",
            "Recheck admitted classification/private-native source even after an incomplete observation":
                "always() && (env.MRK_MACOS_AQUA_SCOPE == 'xcode-installed-classification' || env.MRK_MACOS_AQUA_SCOPE == 'wrapping-keychain-private' || env.MRK_MACOS_AQUA_SCOPE == 'android-registration-lifecycle') && steps.source.outcome == 'success'",
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
            "Three ordinary Mac capacity DATA cases from the same compiled app-test original": "vault-helper-shipping",
            "One installed no-GO shipping-helper gate-custody control before any Aqua entry": "vault-helper-shipping",
            "Three serial shipping-helper journeys through the original document and invocation owner": "vault-helper-shipping",
            "One installation-inspection Aqua journey through the reviewed original invocation owner": "installation-inspection",
            "Check pending recovery SOURCE and DATA contracts before native preparation": "project-recovery-pending",
            "One real pending iOS build-input recovery through ordinary Inspect and explicit Recover": "project-recovery-pending",
            "Check pending account SOURCE and DATA contracts before native preparation": "ios-recovery-pending",
            "One real pending account recovery through ordinary Inspect and exact Recover": "ios-recovery-pending",
            "Nine serial current-iOS Aqua cases through the reviewed original invocation owner": "ios-current-synthetic",
            "Two serial doctor and saved offline Aqua journeys through the reviewed original invocation owner": "doctor-preflight2",
            "Three serial local-edit Aqua journeys through the reviewed original invocation owner": "local-edits3",
        }
        lifecycle = {
            "Compile headless Mac libraries and run the exact selected DATA regressions first":
                "success() && (env.MRK_MACOS_AQUA_SCOPE == 'project-fields' || env.MRK_MACOS_AQUA_SCOPE == 'ios-current-synthetic' || env.MRK_MACOS_AQUA_SCOPE == 'android-inputs' || env.MRK_MACOS_AQUA_SCOPE == 'project-fields-android-inputs' || env.MRK_MACOS_AQUA_SCOPE == 'vault-helper-shipping' || env.MRK_MACOS_AQUA_SCOPE == 'installation-inspection' || env.MRK_MACOS_AQUA_SCOPE == 'vault-helper-shipping-installation-inspection' || env.MRK_MACOS_AQUA_SCOPE == 'android-registration-lifecycle' || env.MRK_MACOS_AQUA_SCOPE == 'project-recovery-pending' || env.MRK_MACOS_AQUA_SCOPE == 'ios-recovery-pending' || env.MRK_MACOS_AQUA_SCOPE == 'doctor-preflight2' || env.MRK_MACOS_AQUA_SCOPE == 'local-edits3')",
            "Export bounded diagnostics without altering original command evidence":
                "always() && steps.work.outputs.root != '' && (env.MRK_MACOS_AQUA_SCOPE == 'project-fields' || env.MRK_MACOS_AQUA_SCOPE == 'ios-current-synthetic' || env.MRK_MACOS_AQUA_SCOPE == 'android-inputs' || env.MRK_MACOS_AQUA_SCOPE == 'project-fields-android-inputs' || env.MRK_MACOS_AQUA_SCOPE == 'vault-helper-shipping' || env.MRK_MACOS_AQUA_SCOPE == 'installation-inspection' || env.MRK_MACOS_AQUA_SCOPE == 'vault-helper-shipping-installation-inspection' || env.MRK_MACOS_AQUA_SCOPE == 'android-registration-lifecycle' || env.MRK_MACOS_AQUA_SCOPE == 'project-recovery-pending' || env.MRK_MACOS_AQUA_SCOPE == 'ios-recovery-pending' || env.MRK_MACOS_AQUA_SCOPE == 'doctor-preflight2' || env.MRK_MACOS_AQUA_SCOPE == 'local-edits3')",
            "Preserve bounded Android lifecycle results and original workflow exit evidence":
                "always() && env.MRK_MACOS_AQUA_SCOPE == 'android-registration-lifecycle' && steps.source.outcome == 'success'",
        }
        legacy_exports = {
            "Preserve bounded original evidence; upload alone is not an Aqua pass",
        }
        self.assertEqual(set(steps), admitted | legacy | set(toolchain) | set(classifiers) | set(private) | set(scoped) | set(lifecycle) | legacy_exports)
        for name, body in steps.items():
            gates = [line.strip() for line in body.splitlines() if line.startswith("        if:")]
            if name in admitted:
                expected = []
            elif name in toolchain:
                expected = ["if: " + toolchain[name]]
            elif name in classifiers:
                expected = ["if: " + classifiers[name]]
            elif name in private:
                expected = ["if: " + private[name]]
            elif name in lifecycle:
                expected = ["if: " + lifecycle[name]]
            elif name in scoped:
                selection = "env.MRK_MACOS_AQUA_SCOPE == " + repr(scoped[name])
                if scoped[name] in ("project-fields", "android-inputs"):
                    selection = "(" + selection + " || env.MRK_MACOS_AQUA_SCOPE == 'project-fields-android-inputs')"
                elif scoped[name] in ("vault-helper-shipping", "installation-inspection"):
                    selection = "(" + selection + " || env.MRK_MACOS_AQUA_SCOPE == 'vault-helper-shipping-installation-inspection')"
                expected = ["if: success() && " + selection]
            else:
                prefix = "always() && steps.work.outputs.root != ''" if name in legacy_exports else "success()"
                expected = ["if: " + prefix + " && (env.MRK_MACOS_AQUA_SCOPE == 'project-fields' || env.MRK_MACOS_AQUA_SCOPE == 'ios-current-synthetic' || env.MRK_MACOS_AQUA_SCOPE == 'android-inputs' || env.MRK_MACOS_AQUA_SCOPE == 'project-fields-android-inputs' || env.MRK_MACOS_AQUA_SCOPE == 'vault-helper-shipping' || env.MRK_MACOS_AQUA_SCOPE == 'installation-inspection' || env.MRK_MACOS_AQUA_SCOPE == 'vault-helper-shipping-installation-inspection' || env.MRK_MACOS_AQUA_SCOPE == 'project-recovery-pending' || env.MRK_MACOS_AQUA_SCOPE == 'ios-recovery-pending' || env.MRK_MACOS_AQUA_SCOPE == 'doctor-preflight2' || env.MRK_MACOS_AQUA_SCOPE == 'local-edits3')"]
            with self.subTest(step=name):
                self.assertEqual(gates, expected)
        clock = steps["Admit the fixed image Rust tools without installing a distribution"]
        self.assertNotIn("xcode-installed-classification", clock)
        self.assertIn("timeout-minutes: 4", clock)
        self.assertNotIn("rustup toolchain install", actual_source)
        self.assertNotIn("rustup update", actual_source)
        self.assertNotIn("rustup override", actual_source)
        self.assertLess(workflow.index("Bind the complete reviewed first-party checkout before compilation"), workflow.index("Admit the fixed image Rust tools without installing a distribution"))
        self.assertLess(workflow.index("Admit the fixed image Rust tools without installing a distribution"), workflow.index("Compile headless Mac libraries"))
        for required in ("('toolchains/stable-' + build_target + '/bin')", "line.partition(':')[0].strip() == 'commit-hash'",
                         "line.partition(':')[0].strip() == 'release'", "line.partition(':')[0].strip() == 'host'", "RUSTUP_AUTO_INSTALL='0'",
                         "owner = qualification.load_owner(checkout)", "pending_call = True",
                         "pending_call = False", "if not pending_call:", "no_configuration(); check_originals()",
                         "('config', 'config.toml', 'credentials', 'credentials.toml')",
                         "timeout=15, capture=True, text=False, output_limit=4096"):
            self.assertIn(required, clock)
        for required in ("machines = {'aarch64-apple-darwin': 'arm64', 'x86_64-apple-darwin': 'x86_64'}",
                         "if build_target not in machines:", "os.uname().machine == machines[build_target]"):
            self.assertIn(required, clock)
        self.assertEqual(clock.count("result = owner.run_owned("), 1)
        self.assertEqual(clock.count("for tool in ('rustc', 'cargo'):"), 1)
        self.assertLess(clock.index("no_configuration(); check_originals()"), clock.index("result = owner.run_owned("))
        self.assertLess(clock.index("row['closed'] = True"), clock.index("print('Fixed direct Rust' + rust_release"))

        # Evaluate only these shape-pinned pure predicates, never a workflow
        # block, command, import, configuration read or source-selected callable.
        expected_tuples = {
            "aarch64-apple-darwin": ("1.98.1", "48a229ceaefd4985c50990b14116b6d856af0985"),
            "x86_64-apple-darwin": ("1.98.0", "88d9e12ae178fab0fb5cc050a94da85685d449ea"),
        }
        def program(block, marker):
            opening, closing = "<<'" + marker + "'\n", "\n          " + marker
            self.assertEqual(block.count(opening), 1)
            body = block.split(opening, 1)[1].split(closing, 1)[0]
            rows = body.splitlines()
            self.assertTrue(all(not row or row.startswith(" " * 10) for row in rows))
            parsed = ast.parse("\n".join(row[10:] for row in rows))
            maps = [node.value for node in ast.walk(parsed) if isinstance(node, ast.Assign)
                    and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == "rust_tuples"]
            self.assertEqual(len(maps), 1)
            self.assertEqual(ast.literal_eval(maps[0]), expected_tuples)
            return parsed
        def need_predicate(parsed, reason):
            values = [node.args[0] for node in ast.walk(parsed) if isinstance(node, ast.Call)
                      and isinstance(node.func, ast.Name) and node.func.id == "need" and len(node.args) == 2
                      and isinstance(node.args[1], ast.Constant) and node.args[1].value == reason]
            self.assertEqual(len(values), 1)
            return values[0]
        def refusal_predicate(parsed, reason):
            values = [node.test for node in ast.walk(parsed) if isinstance(node, ast.If) and len(node.body) == 1
                      and isinstance(node.body[0], ast.Raise) and isinstance(node.body[0].exc, ast.Call)
                      and isinstance(node.body[0].exc.func, ast.Name) and node.body[0].exc.func.id == "ValueError"
                      and len(node.body[0].exc.args) == 1 and isinstance(node.body[0].exc.args[0], ast.Constant)
                      and node.body[0].exc.args[0].value == reason]
            self.assertEqual(len(values), 1)
            return values[0]
        for filename in ("desktop-macos-installed.yml", "desktop-macos-aqua.yml"):
            source = (PATH.parents[2] / ".github/workflows" / filename).read_text()
            direct = program(source, "PY_DIRECT_RUST")
            stages = [("direct", [
                (need_predicate(direct, "direct-rust-version-host"),
                 "lines[0].startswith(tool + ' ') and [line for line in lines if line.partition(':')[0].strip() == 'release'] == ['release: ' + rust_release] and [line for line in lines if line.partition(':')[0].strip() == 'host'] == ['host: ' + build_target]", False, False),
                (need_predicate(direct, "direct-rust-clock-commit"),
                 "[line for line in lines if line.partition(':')[0].strip() == 'commit-hash'] == ['commit-hash: ' + rust_commit]", False, True),
            ])]
            if filename == "desktop-macos-installed.yml":
                later = program(source, "PY_EFFECTIVE_RUST")
                stages.append(("effective", [
                    (refusal_predicate(later, "effective tool version output refused"),
                     "not output.startswith(tool + ' ') or [line for line in lines if line.partition(':')[0].strip() == 'release'] != ['release: ' + rust_release] or [line for line in lines if line.partition(':')[0].strip() == 'host'] != ['host: ' + build_target]", True, False),
                    (refusal_predicate(later, "effective compiler differs from reviewed Apple clock binding"),
                     "tool == 'rustc' and [line for line in lines if line.partition(':')[0].strip() == 'commit-hash'] != ['commit-hash: ' + rust_commit]", True, False),
                ]))
            else:
                block = source.split("      - name: Record exact source and actual tool bindings only after route admission\n", 1)[1].split("      - name: ", 1)[0]
                later = program(block, "PY")
                stages.append(("source-binding", [(refusal_predicate(later, "direct Rust source binding differs from admitted image"),
                    "not output.startswith(name + ' ') or [line for line in lines if line.partition(':')[0].strip() == 'release'] != ['release: ' + rust_release] or [line for line in lines if line.partition(':')[0].strip() == 'host'] != ['host: ' + build_target] or name == 'rustc' and [line for line in lines if line.partition(':')[0].strip() == 'commit-hash'] != ['commit-hash: ' + rust_commit]", True, False)]))
            # Each original query must refuse on its own; one stronger earlier
            # admission must not hide a weaker later record's predicate.
            for stage, specs in stages:
                predicates = []
                for actual, expected, inverted, rust_only in specs:
                    self.assertEqual(ast.dump(actual, include_attributes=False), ast.dump(ast.parse(expected, mode="eval").body, include_attributes=False))
                    predicates.append((compile(ast.Expression(actual), "<fixed-inert-rust-predicate>", "eval"), inverted, rust_only))
                for target, (release, commit) in expected_tuples.items():
                    other = "x86_64-apple-darwin" if target == "aarch64-apple-darwin" else "aarch64-apple-darwin"
                    for tool in ("rustc", "cargo"):
                        lines = [tool + " " + release + " (inert)", "release: " + release, "host: " + target, "commit-hash: " + commit]
                        cases = [("valid", lines), ("wrong-tool", ["other " + release, *lines[1:]])]
                        fields = [("release", 1, expected_tuples[other][0]), ("host", 2, other)]
                        if tool == "rustc": fields.append(("commit-hash", 3, expected_tuples[other][1]))
                        for field, index, wrong in fields:
                            cases.extend([
                                ("wrong-" + field, [*lines[:index], field + ": " + wrong, *lines[index+1:]]),
                                ("missing-" + field, [*lines[:index], *lines[index+1:]]),
                                ("repeated-" + field, lines + [lines[index]]),
                                ("conflicting-" + field, lines + [field + ": " + wrong]),
                                ("spacing-" + field, [*lines[:index], lines[index].replace(": ", ":  "), *lines[index+1:]]),
                                ("key-spacing-" + field, lines + [" " + field + " : " + wrong]),
                            ])
                        if tool == "cargo":
                            cases.append(("cargo-commit-unpinned", [*lines[:3], "commit-hash: independently-unpinned"]))
                        for label, observed in cases:
                            variables = dict(tool=tool, name=tool, build_target=target, rust_release=release,
                                             rust_commit=commit, lines=observed, output="\n".join(observed))
                            admitted = all(bool(eval(code, {"__builtins__": {}}, variables)) != inverted
                                           for code, inverted, rust_only in predicates if not rust_only or tool == "rustc")
                            with self.subTest(workflow=filename, stage=stage, target=target, tool=tool, mutation=label):
                                self.assertEqual(admitted, label in ("valid", "cargo-commit-unpinned"))
        for forbidden in ("shutil.which", ".resolve(", "CARGO_NET_OFFLINE=", "cargo fetch", "os.chmod", "os.unlink", "os.mkdir"):
            self.assertNotIn(forbidden, clock)
        direct = "/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo"
        for name in ("Compile headless Mac libraries and run the exact selected DATA regressions first",
                     "Compile native wrapping variants once and run fixed cohorts and creator-reader pair",
                     "Build and sign the separate fixed vault helper before binding the app",
                     "Compile the fixed debug actual-main observer and normal embedded frontend once",
                     "Build the fixed one-shot root Installer and scripts-only package"):
            selected_direct = direct if name == "Compile native wrapping variants once and run fixed cohorts and creator-reader pair" else '"/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/cargo"'
            selected_source = (aqua_wrapping_source() if name == "Compile native wrapping variants once and run fixed cohorts and creator-reader pair"
                               else aqua_headless_source() if name == "Compile headless Mac libraries and run the exact selected DATA regressions first"
                               else steps[name])
            self.assertIn(selected_direct, selected_source)
            self.assertNotIn('["cargo",', selected_source)
        mixed = steps["Compile the fixed debug actual-main observer and normal embedded frontend once"]
        self.assertLess(mixed.index("npm run build"), mixed.index('PATH="/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin:/usr/bin:/bin:/usr/sbin:/sbin"'))
        self.assertIn('RUSTC="/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc"', aqua_wrapping_source())
        classify = steps["Classify installed Xcode originals without preparing or selecting a toolchain"]
        self.assertIn("timeout-minutes: 2", classify)
        self.assertIn("shell: /usr/bin/env -i /bin/bash --noprofile --norc -e -o pipefail {0}", classify)
        self.assertIn("exec /usr/bin/env -i", classify)
        self.assertIn("'${{ steps.python.outputs.python-path }}' -I -S -B", classify)
        command = "/Users/runner/work/mobile-release-kit/mobile-release-kit/desktop/tools/macos_xcode_host_preparation.py --classify-installed --target '${{ matrix.target }}'"
        self.assertEqual([line.strip() for line in classify.splitlines() if "macos_xcode_host_preparation.py" in line], [command])
        for forbidden in ("sudo", "xcodebuild", "xcrun", "cargo", "npm", "continue-on-error", "set +e", "|| true", "rm -"):
            self.assertNotIn(forbidden, classify)
        admission = steps["Admit only this exact disposable-hosted source route"]
        self.assertIn('if [[ "$MRK_MACOS_AQUA_SCOPE" != xcode-installed-classification && "$MRK_MACOS_AQUA_SCOPE" != wrapping-keychain-private && "$MRK_MACOS_AQUA_SCOPE" != android-registration-lifecycle ]]; then', admission)
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

        # Nonpackage classifiers/private/lifecycle routes choose no protected
        # identity environment and never receive a credential-bearing step.
        environment_line = next(line for line in workflow.splitlines() if line.startswith("    environment: "))
        self.assertTrue(environment_line.endswith("&& 'macos-developer-id' || 'macos-engineering' }}"))
        for excluded in ("xcode-installed-classification", "wrapping-keychain-private", "android-registration-lifecycle"):
            self.assertNotIn(excluded, environment_line)
        for name, body in steps.items():
            if "secrets.MRK_MACOS_DEVELOPER_ID_" in body:
                gate = next(line for line in body.splitlines() if line.startswith("        if:"))
                for excluded in ("xcode-installed-classification", "wrapping-keychain-private", "android-registration-lifecycle"):
                    self.assertNotIn(excluded, gate)
        self.assertNotIn("MRK_MACOS_DEVELOPER_ID_", classify + post + upload)

    def test_selected_scope_keeps_unique_artifacts_and_three_private_variants(self):
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        actual_source = workflow + aqua_headless_source() + aqua_wrapping_source()
        header = workflow.split("    steps:\n", 1)[0]
        expected_job = (
            '  aqua:\n    if: github.event_name == \'push\' && github.ref == \'refs/heads/verify/desktop-macos-aqua\'\n    name: aqua-${{ matrix.scope }}-${{ matrix.target }}\n    environment: ${{ contains(fromJSON(\'["project-fields","ios-current-synthetic","android-inputs","project-fields-android-inputs","vault-helper-shipping","installation-inspection","vault-helper-shipping-installation-inspection","project-recovery-pending","ios-recovery-pending","doctor-preflight2","local-edits3"]\'), matrix.scope) && \'macos-developer-id\' || \'macos-engineering\' }}\n    permissions:\n      contents: read\n      actions: read\n    strategy:\n      fail-fast: false\n      matrix:\n        include:\n          - scope: local-edits3\n            target: aarch64-apple-darwin\n            runner: macos-26\n            supplier_receipt: \'2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d\'\n            supplier_tar: \'ff7883185cf8226e9366b1ee9a3dcb3eb8ee761dbc1f697f952510a6bd858695\'\n            supplier_source: \'158cdff422e3837f7ab5e6192af76a578faf6fab\'\n            supplier_run: \'37467019389\'\n            supplier_attempt: \'1\'\n            supplier_artifact: \'11415902210\'\n          - scope: local-edits3\n            target: x86_64-apple-darwin\n            runner: macos-26-intel\n            supplier_receipt: \'a46f6838afdb7c20c3539e8f65891312aa8df10e2de67e9b9e3ddbf449883b4b\'\n            supplier_tar: \'739cc8b8b3c68daffba8d7b9cb7cb54ca730eef2c5842302ae8a2682bf64d5bd\'\n            supplier_source: \'079ab2a2c8fef88f01bf909e7669c685f07e1375\'\n            supplier_run: \'37476532238\'\n            supplier_attempt: \'1\'\n            supplier_artifact: \'11419502465\'\n    runs-on: ${{ matrix.runner }}\n    timeout-minutes: ${{ matrix.scope == \'doctor-preflight2\' && 212 || contains(fromJSON(\'["project-fields","ios-current-synthetic","android-inputs","project-fields-android-inputs","vault-helper-shipping","installation-inspection","vault-helper-shipping-installation-inspection","project-recovery-pending","ios-recovery-pending","doctor-preflight2","local-edits3"]\'), matrix.scope) && 137 || 75 }}\n'
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
            self.assertNotIn(forbidden, actual_source)
        steps = dict(block.split("\n", 1) for block in workflow.split("      - name: ")[1:])
        compiler = "Compile the fixed debug actual-main observer and normal embedded frontend once"
        self.assertEqual(workflow.count("      - name: " + compiler + "\n"), 1)
        self.assertEqual(steps[compiler].count('"/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/cargo" test --locked'), 1)
        self.assertEqual(steps[compiler].count("npm run build"), 1)
        private = steps["Compile native wrapping variants once and run fixed cohorts and creator-reader pair"]
        self.assertIn("if: success() && env.MRK_MACOS_AQUA_SCOPE == 'wrapping-keychain-private'", private)
        private = aqua_wrapping_source()
        for required in (
            'for role, features, flags in (("normal", [], ""), ("observer", ["installed-observation"], ""),\n'
            '                                            ("qualification", ["installed-observation"], "--cfg mrk_wrapping_keychain_qualification")):',
            'target = work / ("wrapping-" + role + "-target")',
            'environment = dict(build_env, CARGO_TARGET_DIR=str(target), RUSTFLAGS=flags)',
            'argv = ["/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo", "test", "--locked", "--no-default-features", "--jobs", "2",',
            '"--manifest-path", str(native / "Cargo.toml"),',
            '"--lib", "--no-run", "--message-format=json"]',
            'owner = qualification.load_owner(checkout)',
            'name = "common"',
        ):
            self.assertIn(required, private)
        self.assertEqual(private.count('name = "common"'), 1)
        self.assertNotIn("npm", private)
        self.assertNotIn("sudo", private)
        artifact_prefix = "desktop-macos-aqua-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}-"
        primary_upload = steps["Preserve bounded original evidence; upload alone is not an Aqua pass"]
        private_upload = steps["Preserve bounded private-cohort public facts and compiler-only diagnostics"]
        self.assertIn("name: " + artifact_prefix + "${{ env.MRK_MACOS_AQUA_SCOPE }}-${{ matrix.target }}", primary_upload)
        self.assertIn("name: " + artifact_prefix + "wrapping-keychain-private", private_upload)
        resolved = [artifact_prefix + "local-edits3-" + target
                    for target in ("aarch64-apple-darwin", "x86_64-apple-darwin")]
        resolved.append(artifact_prefix + "wrapping-keychain-private")
        self.assertEqual(len(set(resolved)), 3)
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
        helper = "Three serial shipping-helper journeys through the original document and invocation owner"
        installation = "One installation-inspection Aqua journey through the reviewed original invocation owner"
        self.assertLess(names.index(compiler), names.index(p2))
        self.assertLess(names.index(p2), names.index(android))
        self.assertLess(names.index(compiler), names.index(helper))
        self.assertLess(names.index(helper), names.index(installation))
        for once in (compiler, 'Assemble the instrumented observation app with SOURCE-selected signing',
                     "Build the fixed one-shot root Installer and scripts-only package",
                     "Application installation uses only standard privileged Installer; app and Python stay nonroot"):
            self.assertEqual(workflow.count("      - name: " + once + "\n"), 1)
        build = steps[compiler]
        self.assertEqual(build.count('"/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/cargo" test --locked'), 1)
        self.assertEqual(build.count("npm run build"), 1)
        recorded = 'printf \'%s\\n\' "$status" > "$MRK_MACOS_WORK/observer-build.status"'
        rejected = 'if [[ "$status" != 0 ]]; then'
        self.assertLess(build.index(recorded), build.index(rejected))
        self.assertLess(build.index(rejected), build.index('exit "$status"'))
        self.assertLess(build.index('exit "$status"'), build.index("<<'PY_BUILD'"))
        self.assertNotEqual(BINDING.root(project_fields=True), BINDING.root())
        self.assertNotEqual(BINDING.root(vault_helper=True), BINDING.root(installation_inspection=True))
        self.assertEqual(M.case_timeout("installation-inspection"), 95)
        self.assertEqual(M.case_timeout("project-fields"), 60)
        self.assertEqual(M.case_timeout("android-inputs"), 60)
        for name, scope, prefix, paired, minutes in (
                (p2, "project-fields", "aqua-project-fields", "project-fields-android-inputs", 3),
                (android, "android-inputs", "aqua-android-inputs", "project-fields-android-inputs", 3),
                (helper, "vault-helper-shipping", "aqua-vault-helper", "vault-helper-shipping-installation-inspection", 8),
                (installation, "installation-inspection", "aqua-installation-inspection", "vault-helper-shipping-installation-inspection", 3)):
            step = steps[name]
            self.assertIn("timeout-minutes: " + str(minutes), step)
            self.assertIn("if: success() && (env.MRK_MACOS_AQUA_SCOPE == " + repr(scope)
                          + " || env.MRK_MACOS_AQUA_SCOPE == " + repr(paired) + ")", step)
            self.assertEqual(step.count("macos_aqua_qualification.py --scope " + scope), 1)
            for forbidden in ("continue-on-error", "|| true", "--timeout", "rm -"):
                self.assertNotIn(forbidden, step)
            status_write = 'printf \'%s\\n\' "$status" > "$MRK_MACOS_WORK/' + prefix + '.status"'
            self.assertLess(step.index("status=$?"), step.index(status_write))
            self.assertLess(step.index(status_write), step.index("[[ $status == 0 ]]"))
            for leaf in (prefix + "-results.jsonl", prefix + "-failure.jsonl", prefix + ".status"):
                self.assertIn('${{ steps.work.outputs.root }}/' + leaf + "\n", workflow)
        for paired in ("project-fields-android-inputs", "vault-helper-shipping-installation-inspection"):
            with self.assertRaises(M.Refused):
                M.argument_scope(["--scope", paired])
            with self.assertRaises(M.Refused):
                M.selected_cases(paired)
        binding = steps["Record exact source and actual tool bindings only after route admission"]
        script = binding.split("<<'PY'\n", 1)[1].rsplit("\n          PY", 1)[0]
        tree = ast.parse(textwrap.dedent(script))
        tables = [node for node in tree.body if isinstance(node, ast.Assign)
                  and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                  and node.targets[0].id == "scope_cases"]
        self.assertEqual(len(tables), 1)
        cases = ast.literal_eval(tables[0].value)
        self.assertEqual(set(cases), {"project-fields", "android-inputs", "ios-current-synthetic", "project-fields-android-inputs", M.VAULT_HELPER_SCOPE, "installation-inspection", "vault-helper-shipping-installation-inspection", M.RECOVERY_CASE, M.IOS_ACCOUNT_CASE, "doctor-preflight2", "local-edits3"})
        self.assertEqual(cases["doctor-preflight2"][1], list(M.LOCAL_CHECK_CASES))
        self.assertEqual(cases["local-edits3"][1], list(M.LOCAL_EDIT_CASES))
        self.assertEqual(cases["project-fields-android-inputs"][1], ["project-fields", "android-inputs"])
        self.assertEqual(cases["installation-inspection"][1], ["installation-inspection"])
        self.assertEqual(cases["vault-helper-shipping-installation-inspection"][1], [*M.VAULT_HELPER_CASES, "installation-inspection"])
        self.assertEqual(cases[M.RECOVERY_CASE][1], [M.RECOVERY_CASE])
        selection = 'selected_scopes = ["project-fields", "android-inputs"] if aqua_scope == "project-fields-android-inputs" else ["vault-helper-shipping", "installation-inspection"] if aqua_scope == "vault-helper-shipping-installation-inspection" else [aqua_scope]'
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
        script = aqua_wrapping_source()
        body = script.split("<<'PY_WRAPPING'\n", 1)[1].split("\n          PY_WRAPPING", 1)[0]
        module = ast.parse(textwrap.dedent(body))
        names = {"pairs", "parse", "exact_keys", "ints", "settled_policy", "settled_raw", "cohort_profile",
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
        namespace = {"json": json, "re": re, "subprocess": SimpleNamespace(CompletedProcess=CompletedProcess)}
        exec(compile(ast.Module(body=selected, type_ignores=[]), "<private-report-DATA-only>", "exec"), namespace)
        return namespace

    @staticmethod
    def policy_data(kind=1, role=1, original=1, namespace_child=False):
        """Closed synthetic policy DTO, never a receipt of a native call."""
        if kind == 0:
            return {"header": [0] * 18, "calls": [[0] * 7 for _ in range(5)]}
        if kind == 3:
            return {"header": [1, 3, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1],
                    "calls": [[0] * 7 for _ in range(5)]}
        child = int(namespace_child)
        return {"header": [1, kind, role, 1, 1, 1, original, 1, 1, 1, 0, 0, 1, 0, 0, child, child, child],
                "calls": [[1, 1, 0, 0, 0, value, 1] for value in (original, 0, 0, original, original)]}

    @staticmethod
    def terminal_model(terminal):
        """Small deliberately modelled DTO, not observed Security/CF/FD output."""
        phase, operation = (10, 1) if terminal == "StopBeforeAdd" else (11, 2)
        calls = [[value, 1, 1, 0] for value in ((4, 5, 6, 8, 9) if operation == 1 else (4, 5, 6))]
        raw = {
            "header": [3, operation, 14, 0, 16, phase, 229, 0, 3, 2, len(calls), 0, 1, 1, 6, 3, 3, 3],
            "references": [[1, 1, 1, 1, 1, 1], [1, 0, 0, 0, 0, 0]], "calls": calls,
            "descriptors": [[1, 1, 1, 1, 0, 1, 1, 1, 0, 0] for _ in range(4)]
                           + [[1, 0, 0, 0, 0, 0, 0, 0, 0, 0] for _ in range(2)],
            "acl": [7, 7, 7, 0, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            "native": [1, 1, 3, 1, 0, 0, 0, 0, 0],
            "policy": BeforeItemStopWorkflowTests.policy_data(),
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
        helper = (native.parent / "examples/wrapping_private_cohort.rs").read_text()
        entry = helper.split("fn main() {", 1)[1]
        self.assertTrue(entry.lstrip().startswith("let entry = std::time::Instant::now();"))
        self.assertIn("cohort_entry(entry, mode);", entry)
        self.assertIn("run_registered_variant(entry, terminal, pair);", fixture)
        for mode, variant in (("common", "Common"), ("stop-before-add", "StopBeforeAdd"),
                              ("stop-before-lookup", "StopBeforeLookup"), ("creator-pair", "CreatorPair")):
            self.assertIn('Some("' + mode + '") => CohortMode::' + variant, helper)
        for obsolete in ("private_keychain_cohort", "private_keychain_stop_before_add",
                         "private_keychain_stop_before_lookup", "private_keychain_creator_pair"):
            self.assertNotIn("fn " + obsolete + "(", fixture)
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
            partial = {"schemaVersion": 2, "scope": scope, "provisional": True, "outerFinalityRequired": True,
                       "reportUnavailable": True, "cases": [{"case": terminal}], "owed": owed}
            def capture(value):
                stdout = ("MRK_WRAPPING_PRIVATE_RESULT=" + json.dumps(value) + "\n").encode()
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
        private = aqua_wrapping_source()
        self.assertEqual(private.count('argv = ["/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo", "test", "--locked"'), 1)
        self.assertIn('owner = qualification.load_owner(checkout)', private)
        self.assertIn('for cohort in receipt["nativeCohorts"]:', private)
        self.assertIn('result, row = invoke(cohort["reportPrefix"], [str(cohort_binary["path"]), entry],', private)
        self.assertIn('environ=native_env, cwd=work, timeout=90, limit=256 * 1024)', private)
        self.assertIn('private = [line for line in lines if "wrapping_keychain::private_fixture::" in line]', private)
        self.assertIn('if private:\n                      raise ValueError("wrapping-rust-cfg-exclusion")', private)
        self.assertIn('cell["role"] == "qualification-archive" and observed != fixture_symbols', private)
        self.assertIn('if "_mrk_wrapping_private_process_role" in symbols:', private)
        self.assertIn('receipt["nativeReportAdmitted"] = all(row["reportAdmitted"] for row in receipt["nativeCohorts"])', private)
        self.assertLess(private.index('admit_native_report(result, entry)'), private.index('cohort["reportAdmitted"] = True'))
        upload = workflow.split("      - name: Preserve bounded private-cohort public facts and compiler-only diagnostics\n", 1)[1]
        for _, _, _, prefix in cohorts:
            self.assertEqual(upload.count("${{ steps.work.outputs.root }}/" + prefix + ".report.json"), 1)
        for forbidden in ("*.json", "*.keychain", "wrapping-native.stdout", "wrapping-native.stderr"):
            self.assertNotIn(forbidden, upload)


class PrivateProcessPolicyDataTests(unittest.TestCase):
    """Source-bound parser/size DATA only: no SDK, process or native receipts."""

    @staticmethod
    def cohort_data():
        # This deliberately minimal parser model is not a claim that its
        # original operations ran. Native/owner evidence must come from macOS.
        f = BeforeItemStopWorkflowTests.functions()
        template, _, _ = BeforeItemStopWorkflowTests.terminal_model("StopBeforeAdd")
        cases = []
        outcomes = (0, 12, 1, 2, 4, 3, 2, 10, 10, 10, 10, 10, 5, 14)
        effects = (0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 1, 0, 1)
        for i, name in enumerate(f["case_names"]):
            case = deepcopy(template)
            case.update(ordinal=i + 1, case=name, evidence=(
                "production-selector-only" if i == 0 else "helper-shape-only" if i == 1 else "synthetic-provider-only"),
                acknowledged=i != 13, helperCounts=[20, 20, 20] if i == 1 else [0, 0, 0],
                frameRetired=i not in (3, 6), comparison=[1, 1, 1, 40960, 1] if i in (3, 6) else None)
            case["raw"]["header"][2:4] = [outcomes[i], effects[i]]
            case["raw"]["policy"] = BeforeItemStopWorkflowTests.policy_data(namespace_child=i == 11)
            cases.append(case)
        namespace = deepcopy(template["raw"])
        namespace["header"][1] = 2; namespace["header"][12] = 0
        namespace["policy"] = BeforeItemStopWorkflowTests.policy_data(kind=0)
        caller = dict.fromkeys(("runEntered runReturned completed originalSlotRetained registered retirementAdmitted "
                               "stopRequested materialWiped").split(), True)
        caller.update(dict.fromkeys(("deadlineObserved poisoned callbackOrCallerPanic harnessRefused").split(), False))
        caller.update(chargedBytes=1024 * 1024, chargeLimit=2 * 1024 * 1024, nativeAbi=0x51460201,
            fixtureFrameBytes=131072, adapterFrameBytes=40960, stage=300, clockChecks=300,
            forwardAdmissions=200, retirementAdmissions=100, materialGetter=[1, 1, 1],
            bindingGetter=[1, 1, 1], fixtureAllocation=[1, 1, 1, 1, 1, 1])
        return {
            "schemaVersion": 2, "scope": "wrapping-private-common-cohort",
            "provisional": True, "outerFinalityRequired": True, "shippingBinaryQualified": False,
            "distributionQualified": False, "perQueryUIFailQualified": False, "processNonInteractionQualified": False,
            "atomicProviderFdAttestation": False, "cutoffSeconds": 45, "adapterInvocationBound": 14,
            "fixtureActionBound": 17, "caller": caller,
            "originalActions": {"postAdd": [1, 1, 1, 1, 1, 10, 1, 0, 1], "terminalStop": [1, 1, 1, 1, 1, 10, 1, 0, 1]},
            "fixtureReturns": [[i + 1, 1, 1, 1, 0, 0, 0, 0] for i in range(17)],
            "fixture": {"verified": True, "header": [2, 33200, 17, 1, 10, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                "actions": [[1, 1, 1, 1, 0, 1]] + [[i + 1, 1, 1, 1, 1, 1] for i in range(1, 17)],
                "calls": [[1, 1, 1, 0, 0]], "references": [[1] * 6 for _ in range(10)],
                "selections": [[1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, int(i != 0), 1] for i in range(4)],
                "namespace": namespace,
                "policies": [BeforeItemStopWorkflowTests.policy_data(kind=3 if i == 12 else 2) for i in range(17)]},
            "cases": cases,
            "owed": ["native-exception", "returned-failed-close", "incomplete-acl", "unforced-native-bounds",
                     "before-item-stop", "second-executable-creator", "uifail-no-prompt-denial"],
        }

    @staticmethod
    def reader_data():
        value = dict.fromkeys(("provisional outerFinalityRequired runEntered runReturned completed originalSlotRetained "
                               "registered lookupStarted denialAccepted").split(), True)
        value.update(dict.fromkeys(("deadlineObserved poisoned callbackOrCallerPanic lookupRefused "
                                    "globalWindowSurveillance shippingIdentityQualified perQueryUIFailQualified "
                                    "processNonInteractionQualified").split(), False))
        value.update(schemaVersion=2, scope="wrapping-other-executable-reader", cutoffSeconds=10,
            adapterInvocationBound=1, chargedBytes=262144, chargeLimit=512 * 1024, adapterFrameBytes=40960, clockChecks=200,
            controls=CreatorReaderUIFailDataTests.control_data(2), lookup=CreatorReaderUIFailDataTests.lookup_data(True))
        return value

    @staticmethod
    def captured(value, peer=False):
        marker = b"MRK_WRAPPING_PEER_RESULT=" if peer else b"MRK_WRAPPING_PRIVATE_RESULT="
        return CompletedProcess(["inert-parser-DATA-only"], 0,
            marker + json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n", b"")

    def test_same_policy_contract_requires_exact_five_returned_calls_and_original_boolean(self):
        check = BeforeItemStopWorkflowTests.functions()["settled_policy"]
        for kind, role in ((1, 1), (1, 2), (2, 1)):
            for original in (0, 1):
                good = BeforeItemStopWorkflowTests.policy_data(kind, role, original)
                self.assertIsNone(check(good, kind, role))
                for section, index, field, value in (
                        ("header", None, 0, 0), ("header", None, 2, 0),
                        ("header", None, 5, 0), ("header", None, 6, 255),
                        ("header", None, 8, 0), ("header", None, 9, 0),
                        ("header", None, 10, 1), ("header", None, 12, 0),
                        ("header", None, 13, 1), ("header", None, 14, 1),
                        ("calls", 1, 5, 1), ("calls", 2, 5, 1),
                        ("calls", 3, 1, 0), ("calls", 3, 4, -1),
                        ("calls", 3, 5, 1 - original), ("calls", 4, 5, 1 - original),
                        ("calls", 4, 6, 0), ("calls", 4, 0, True)):
                    bad = deepcopy(good)
                    target = bad[section] if index is None else bad[section][index]
                    target[field] = value
                    with self.subTest(kind=kind, role=role, original=original, mutation=(section, index, field)):
                        with self.assertRaises(ValueError): check(bad, kind, role)
                for calls in (good["calls"][:-1], good["calls"] + [good["calls"][-1]]):
                    with self.assertRaises(ValueError): check(dict(good, calls=calls), kind, role)
        namespace = BeforeItemStopWorkflowTests.policy_data(kind=3)
        self.assertIsNone(check(namespace, 3))
        with self.assertRaises(ValueError): check(namespace, 1)
        forged = deepcopy(namespace); forged["calls"][3] = [1, 1, 0, 0, 0, 1, 1]
        with self.assertRaises(ValueError): check(forged, 3)
        with self.assertRaises(ValueError): check(namespace, 3, 2)

    def test_cohort_admission_binds_namespace_child_to_settled_outer_and_all_fixture_guards(self):
        f = BeforeItemStopWorkflowTests.functions(); good = self.cohort_data()
        self.assertEqual(f["admit_native_report"](self.captured(good)), good)
        failures = [
            ("obsolete-schema", lambda v: v.__setitem__("schemaVersion", 1)),
            ("per-query-claim", lambda v: v.__setitem__("perQueryUIFailQualified", True)),
            ("premature-process-claim", lambda v: v.__setitem__("processNonInteractionQualified", True)),
            ("missing-guard", lambda v: v["cases"][2]["raw"].pop("policy")),
            ("old-native-ABI", lambda v: v["cases"][2]["raw"]["header"].__setitem__(0, 2)),
            ("wrong-operation-role", lambda v: v["cases"][2]["raw"]["policy"]["header"].__setitem__(2, 2)),
            ("outer-child-not-observed", lambda v: v["cases"][11]["raw"]["policy"]["header"].__setitem__(15, 0)),
            ("outer-restore-failed", lambda v: v["cases"][11]["raw"]["policy"]["calls"][3].__setitem__(4, -1)),
            ("outer-restore-not-returned", lambda v: v["cases"][11]["raw"]["policy"]["calls"][3].__setitem__(1, 0)),
            ("standalone-missing", lambda v: v["fixture"]["policies"].pop()),
            ("standalone-restoration-failed", lambda v: v["fixture"]["policies"][0]["calls"][3].__setitem__(4, -1)),
            ("namespace-claimed-guard", lambda v: v["fixture"]["policies"].__setitem__(12, BeforeItemStopWorkflowTests.policy_data(kind=2))),
            ("namespace-resource-claimed-guard", lambda v: v["fixture"]["namespace"].__setitem__("policy", BeforeItemStopWorkflowTests.policy_data())),
        ]
        for name, mutate in failures:
            bad = deepcopy(good); mutate(bad)
            with self.subTest(mutation=name), self.assertRaises(ValueError):
                f["admit_native_report"](self.captured(bad))
        private = deepcopy(good); private["cases"][2]["raw"]["policy"]["secret"] = "INERT_PRIVATE_TEXT"
        with self.assertRaises(ValueError): f["public_report"](self.captured(private))
        result = self.captured(good)
        for invalid in (
                CompletedProcess([], False, result.stdout, b""),
                CompletedProcess([], 101, result.stdout, b""),
                CompletedProcess([], 0, result.stdout, b"INERT_PRIVATE_STDERR"),
                CompletedProcess([], 0, b"running 1 test\n" + result.stdout + b"test result: ok. 1 passed\n", b""),
                CompletedProcess([], 0, result.stdout + result.stdout, b"")):
            with self.assertRaises(ValueError): f["admit_native_report"](invalid)

    def test_reader_report_requires_helper_role_and_never_self_qualifies_process_or_query(self):
        f = CreatorReaderUIFailDataTests.functions(); good = self.reader_data()
        self.assertEqual(f["admit_reader_report"](self.captured(good, True)), good)
        for mutate in (
                lambda v: v.__setitem__("schemaVersion", 1),
                lambda v: v.__setitem__("perQueryUIFailQualified", True),
                lambda v: v.__setitem__("processNonInteractionQualified", True),
                lambda v: v["lookup"]["raw"]["policy"]["header"].__setitem__(2, 1),
                lambda v: v["lookup"]["raw"]["policy"]["calls"][3].__setitem__(4, -1),
                lambda v: v["lookup"]["raw"]["policy"]["calls"][4].__setitem__(1, 0)):
            bad = deepcopy(good); mutate(bad)
            with self.assertRaises(ValueError): f["admit_reader_report"](self.captured(bad, True))
        script = aqua_wrapping_source()
        body = script.split("<<'PY_WRAPPING'\n", 1)[1].split("\n          PY_WRAPPING", 1)[0]
        final = body.split('receipt["passed"] = private_batch_finality(', 1)[1]
        self.assertIn('receipt["perQueryUIFailQualified"] = False', final)
        self.assertIn('receipt["processNonInteractionQualified"] = receipt["passed"]', final)
        self.assertNotIn('receipt["perQueryUIFailQualified"] = receipt["passed"]', body)

    def test_both_helper_compiler_originals_bind_fixed_example_source_profile_and_path(self):
        import textwrap
        script = aqua_wrapping_source()
        # Execute only this actual DATA admission slice, stopping BEFORE any
        # compiler-original file copy, signing, descriptor or helper invocation.
        first = "                      reader_rows = [parse(line) for line in result.stdout.splitlines()]"
        last = "                      reader_path = copy_reader_compiler_original("
        self.assertEqual(script.count(first), 1); self.assertEqual(script.count(last), 1)
        source = textwrap.dedent(script[script.index(first):script.index(last)])
        code = compile(source, "<two-helper-compiler-DATA-only>", "exec")
        native = Path("/inert/native"); target = Path("/inert/qualification-target")
        package = "path+" + native.as_uri() + "#mrk-macos-installed-native@0.1.0"
        def artifact(name):
            executable = str(target / ("aarch64-apple-darwin/debug/examples/" + name))
            return {"reason": "compiler-artifact", "package_id": package,
                "manifest_path": str(native / "Cargo.toml"), "features": ["installed-observation"],
                "executable": executable, "filenames": [executable],
                "target": {"name": name, "kind": ["example"], "crate_types": ["bin"],
                           "src_path": str(native / ("examples/" + name + ".rs"))},
                "profile": {"test": False, "debug_assertions": True}}
        rows = [artifact("wrapping_peer_reader"), artifact("wrapping_private_cohort"),
                {"reason": "build-finished", "success": True}]
        def run(selected):
            f = BeforeItemStopWorkflowTests.functions()
            f.update(native=native, target=target, package=package, pathlib=SimpleNamespace(Path=Path),
                result=CompletedProcess([], 0, b"\n".join(json.dumps(row).encode() for row in selected), b""))
            exec(code, f)
            return f
        admitted = run(rows)
        self.assertEqual(set(admitted["helper_artifacts"]), {"wrapping_peer_reader", "wrapping_private_cohort"})
        for index in (0, 1):
            for mutate in (
                    lambda a: a["target"].__setitem__("name", "unregistered-helper"),
                    lambda a: a["target"].__setitem__("src_path", str(native / "src/lib.rs")),
                    lambda a: a["target"].__setitem__("kind", ["lib"]),
                    lambda a: a["profile"].__setitem__("test", True),
                    lambda a: a["profile"].__setitem__("debug_assertions", False),
                    lambda a: a.__setitem__("features", []),
                    lambda a: a.__setitem__("executable", "/inert/unbound-copy"),
                    lambda a: a.__setitem__("package_id", "unrelated-package")):
                changed = deepcopy(rows); mutate(changed[index])
                with self.subTest(helper=index), self.assertRaises(ValueError): run(changed)
        for changed in (rows[:1] + rows[2:], rows + [rows[0]], [rows[0], rows[0], rows[-1]],
                        rows[:-1], rows + [rows[-1]], rows[:-1] + [{"reason": "build-finished", "success": False}]):
            with self.assertRaises(ValueError): run(changed)

    def test_process_scope_cleanup_and_activation_remain_narrow_source_boundaries(self):
        root = PATH.parents[2]; native = root / "desktop/native/macos-installed-native"
        c = (native / "src/wrapping_keychain.m").read_text()
        fixture = (native / "src/wrapping_keychain_fixture.m").read_text()
        rust = (native / "src/wrapping_keychain.rs").read_text()
        cohort = (native / "src/wrapping_keychain_fixture.rs").read_text()
        pair = (native / "src/wrapping_keychain_pair.rs").read_text()
        self.assertEqual(c.count("SecKeychainSetUserInteractionAllowed("), 1)
        self.assertEqual(c.count("SecKeychainGetUserInteractionAllowed("), 1)
        self.assertIn('#include "wrapping_keychain_fixture.m"', c)
        self.assertNotIn("} mrk_w_process;", fixture)
        role = c.split("static uint32_t mrk_w_private_role(void) {", 1)[1].split("\n}", 1)[0]
        self.assertLess(role.index("pthread_main_np() != 1"), role.index("mrk_wrapping_private_process_role()"))
        acquire = c.split("static int mrk_w_policy_acquire(", 1)[1].split("static void mrk_w_policy_call(", 1)[0]
        self.assertLess(acquire.index("if (!role)"), acquire.index("mrk_w_process.pid"))
        native_return = c.split("void mrk_wrapping_run(", 1)[1].split("uint32_t mrk_wrapping_qualification_abi", 1)[0]
        self.assertLess(native_return.index("mrk_w_cleanup(s)"), native_return.index("mrk_w_policy_finish("))
        self.assertLess(native_return.index("mrk_w_policy_finish("), native_return.index("MRK_W_BEFORE_DELIVERY"))
        self.assertLess(native_return.index("s->interaction.cleanup = NULL"), native_return.index("s->result.run_returned = 1"))
        independent = rust.split('extern "C" fn cleanup_admission_bridge(', 1)[1].split("/// Holds the actual outcome", 1)[0]
        self.assertIn("original.admit_current(slot)", independent)
        current = rust.split("    fn admit_current(", 1)[1].split("    fn admit_at(", 1)[0]
        cutoff = rust.split("    fn admit_at(", 1)[1].split("    fn failed(", 1)[0]
        self.assertIn('#[cfg(feature = "vault-helper")]\n        if self.transported {', current)
        for original in (current, cutoff):
            self.assertIn("!matches!(slot, 3 | 4) || self.seen & (1 << slot) != 0", original)
            self.assertIn("slot == 4 && self.seen & (1 << 3) == 0", original)
            self.assertIn("self.seen |= 1 << slot; self.checks += 1;", original)
            self.assertIn("if self.uncertain || self.panic.is_some() { return Admission::Unknown; }", original)
        self.assertIn("let result = crate::vault_helper::cleanup_admission();", current)
        self.assertIn("Admission::Unknown => self.uncertain = true", current)
        self.assertIn("Admission::Cutoff => self.expired = true", current)
        self.assertIn("return if self.uncertain { Admission::Unknown }", current)
        self.assertIn("else if self.expired { Admission::Cutoff } else { Admission::Continue }", current)
        self.assertLess(current.index("crate::vault_helper::cleanup_admission()"),
                        current.index("self.admit_at(slot, Instant::now())"))
        self.assertIn("if self.cutoff.is_none_or(|cutoff| now >= cutoff) { self.expired = true; }", cutoff)
        self.assertIn("if self.expired { Admission::Cutoff } else { Admission::Continue }", cutoff)
        for forbidden in ("AdmissionBridge", "bridge.admission", "ReaderPhase", ".native(", "forward.panic"):
            self.assertNotIn(forbidden, independent)
        self.assertIn("!matches!(slot, 3 | 4)", rust)
        self.assertIn("now >= cutoff", rust)
        self.assertEqual(cohort.count("CleanupAdmission::from_original_cutoff(clock.cutoff)"), 3)
        self.assertEqual(pair.count("CleanupAdmission::from_original_cutoff(clock.cutoff)"), 1)
        self.assertIn("action == MRK_Q_POST_ADD", fixture)
        self.assertIn("!memcmp(binding, &f->pin, sizeof(f->pin))", fixture)
        self.assertIn("action > MRK_Q_POST_ADD && !f->namespace_parent_settled", fixture)
        self.assertIn("mrk_p_finality(policy, resources_settled && !mrk_w_process.poisoned)", c)
        self.assertIn("outer->policy->namespace_completed = completed != 0", fixture)
        for leaf, expected_role in (("wrapping_private_cohort.rs", 1), ("wrapping_peer_reader.rs", 2)):
            helper = (native / "examples" / leaf).read_text()
            main = helper.split("fn main() {", 1)[1]
            self.assertEqual(helper.count('pub extern "C" fn mrk_wrapping_private_process_role()'), 1)
            self.assertIn("if ACTIVE.load(Ordering::Acquire) { " + str(expected_role) + " } else { 0 }", helper)
            self.assertLess(main.index("args"), main.index("ACTIVE.swap(true"))
            self.assertNotIn("std::thread", helper)
        app = (root / "desktop/src-tauri/src/lib.rs").read_text()
        private_guard = (
            "#[cfg(any(mrk_wrapping_keychain_qualification, mrk_wrapping_keychain_qualification_native))]\n"
            'compile_error!("process-only wrapping qualification is forbidden in the Desktop application");\n'
        )
        self.assertEqual(app.count(private_guard), 1)
        app_build = (root / "desktop/src-tauri/build.rs").read_text()
        for name in ("mrk_wrapping_keychain_qualification", "mrk_wrapping_keychain_qualification_native"):
            self.assertEqual(app_build.count('println!("cargo:rustc-check-cfg=cfg(' + name + ')");'), 1)
        script = aqua_wrapping_source()
        self.assertIn('["/usr/bin/nm", "-u", str(cell["path"])]', script)
        self.assertIn('role != "qualification" and imported & policy_imports', script)
        self.assertIn('("creator", cohort_path, creator_identifier)', script)

    def test_largest_source_bounded_projection_including_all_policy_books_fits_existing_output_cap(self):
        # Conservative scalar widths and complete reachable arrays, NOT a native
        # success DTO. Descriptors are <=64 ancestry components +5 checkpoints;
        # 72 is physical capacity, not a reachable count. Two source-fixed
        # selector/helper cases cannot own paths.
        model = self.cohort_data()
        policy = {"header": [1, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 8, 1, 1, 1, 1, 1, 1],
                  "calls": [[1, 1, 1, 1, -(1 << 31), 255, 1] for _ in range(5)]}
        raw = {"header": [3, 2, 17, 3, 21, 21, 2047, -(1 << 31), (1 << 32) - 1, 24, 12, 32, 1, 64, 69, 5, 5, 5],
            "references": [[1] * 6 for _ in range(24)],
            "calls": [[21, 1, 1, -(1 << 31)] for _ in range(12)],
            "descriptors": [[1, 1, 1, 1, -(1 << 31), 1, 1, 1, -(1 << 31), -(1 << 31)] for _ in range(69)],
            "acl": [51200] * 21, "native": [300000, 300000, 21, 1, -(1 << 31), -(1 << 31), 21, -(1 << 31), -(1 << 31)],
            "policy": policy}
        for i, case in enumerate(model["cases"]):
            case["raw"] = deepcopy(raw)
            if i < 2:
                case["raw"]["references"] = [[1] * 6 for _ in range(12 if i == 1 else 0)]
                case["raw"]["calls"] = []; case["raw"]["descriptors"] = []
        model["fixture"]["calls"] = [[47, 1, 1, -(1 << 31), -(1 << 63)] for _ in range(1024)]
        model["fixture"]["header"][3] = 1024
        model["fixture"]["selections"] = [[1, 1, 1, 2, 64, 64, 64, 64, 65, 65, 65, 4225, 4225, 1, 1] for _ in range(4)]
        model["fixture"]["namespace"] = deepcopy(raw)
        model["fixture"]["policies"] = [deepcopy(policy) for _ in range(17)]
        # Creator positive is the fifteenth adapter. Use a separate conservative
        # envelope allowance for the existing <=300-scalar control DTO and its
        # keys/booleans, at worst signed64 width; its actual parser is tested above.
        positive = {"nativeReturned": True, "verified": True, "retainedNativeBytes": 65536,
                    "frameRetired": False, "scopedValuePresent": False, "selection": [1] * 6,
                    "comparison": [1, 1, 1, 65536, 1], "raw": deepcopy(raw)}
        model["scope"] = "wrapping-private-creator-pair"
        model["adapterInvocationBound"] = 15
        model["caller"].update(terminalHarnessHalted=True, terminalHarnessInvocations=14)
        model["pair"] = {"positiveAccepted": True, "comparisonRefused": False, "barrierCompleted": True,
                         "totalAdapterCalls": 15, "waits": 127, "controls": None, "positive": positive}
        control = CreatorReaderUIFailDataTests.control_data(1)
        def numeric_width(node):
            if type(node) is dict: return {key: numeric_width(value) for key, value in node.items()}
            if type(node) is list: return [numeric_width(value) for value in node]
            return -(1 << 63) if type(node) is int else node
        control_width = len(json.dumps(numeric_width(control), separators=(",", ":")).encode("ascii"))
        self.assertLessEqual(control_width, 8192)
        encoded = self.captured(model).stdout
        # Reserve another1KiB for wider bounded caller counters/action indices,
        # Boolean spellings and optional terminal fields outside the raw books.
        self.assertLessEqual(len(encoded) + 8192 + 1024, 128 * 1024)
        native = PATH.parents[2] / "desktop/native/macos-installed-native/src"
        c = (native / "wrapping_keychain.m").read_text()
        self.assertIn("mode == MRK_W_Q_SELECTOR", c)
        self.assertIn("selector_boundary_returned = 1;", c)
        self.assertIn("mode != MRK_W_Q_HELPERS", c)
        self.assertIn("mrk_w_qualification_helpers(s); return;", c)
        rust = (native / "wrapping_keychain.rs").read_text()
        for constant in ("MAX_CF_REFERENCES: usize = 24", "MAX_SECURITY_CALLS: usize = 12",
                         "MAX_DESCRIPTORS: usize = 72", "MAX_ACL_SNAPSHOTS: u32 = 400",
                         "MAX_ACL_ENTRIES: u32 = 128", "MAX_NATIVE_CALLS: u32 = 300_000"):
            self.assertIn(constant, rust)
        self.assertIn("self.descriptor_count != self.directory_count + NAMESPACE_CHECKPOINTS", rust)
        self.assertIn("MAX_PATH_COMPONENTS: u32 = 64", rust)
        self.assertIn("NAMESPACE_CHECKPOINTS: u32 = 5", rust)
        fixture = (native / "wrapping_keychain_fixture.rs").read_text()
        self.assertIn("const CALLS: usize = 1024", fixture)
        self.assertIn("const ACTIONS: usize = 17", fixture)
        self.assertIn("const PUBLIC_OUTPUT_LIMIT: usize = 128 * 1024", fixture)
        self.assertIn("self.fixtures.capacity() * size_of::<FixtureReturn>()", fixture)
        self.assertIn("self.cases.capacity() * size_of::<CaseReturn>()", fixture)
        self.assertIn("if charged > CALLER_OWNED_CHARGE_LIMIT", fixture)



    def test_rust_policy_data_gate_requires_four_exact_original_successes_and_real_finality(self):
        f = PrivateCodecWorkflowDataTests.functions()
        names = f["policy_names"]
        expected = tuple("wrapping_keychain::policy_contract_tests::" + name for name in (
            "policy_failure_preserves_effect_and_blocks_known_candidate",
            "cleanup_uses_original_endpoint_and_spends_only_two_slots",
            "cleanup_bridge_does_not_reenter_or_drop_poisoned_forward_callback",
            "application_entries_do_not_invoke_provider_or_admission"))
        self.assertEqual(names, expected)
        rows = ["running 4 tests", *("test " + name + " ... ok" for name in names),
                "test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.01s"]
        def original(lines, code=0, stderr=b""):
            return CompletedProcess(["inert-policy-DATA-only"], code, ("\n".join(lines) + "\n").encode(), stderr)
        check = f["admit_policy_results"]
        self.assertEqual(check(original(rows)), {"testsPassed": True, "tests": 4, "failed": 0,
                                                "ignored": 0, "measured": 0, "filtered": 8})
        invalid = [original(rows, 101), original(rows, False), original(rows, stderr=b"unpublished-DATA"),
                   original(rows[:2] + rows[3:]), original(rows[:2] + [rows[1]] + rows[3:]),
                   original(rows[:-1] + ["test unrelated::test ... ok", rows[-1]]),
                   original(rows[:-1] + [rows[-1].replace("0 ignored", "1 ignored")]),
                   original(rows[:-1] + [rows[-1].replace("0 failed", "1 failed")]),
                   original(rows[:-1] + [rows[-1].replace("4 passed", "3 passed")]),
                   original([rows[0], rows[1].replace(" ... ok", " ... FAILED"), *rows[2:]])]
        for index, result in enumerate(invalid):
            with self.subTest(mutation=index), self.assertRaises(ValueError): check(result)
        settled = f["policy_original_settled"]
        self.assertTrue(settled([]))  # No test child exists, not a passing result.
        for data in ({"returned": False}, {"returned": True}, {"returned": True, "returncode": False},
                     {"contained": True, "cleanupComplete": False}, {"contained": False, "cleanupComplete": True}):
            self.assertFalse(settled([dict(data, role="normal-policy-tests")]))
        for data in ({"returned": True, "returncode": 101}, {"dispatched": False},
                     {"contained": True, "cleanupComplete": True}):
            self.assertTrue(settled([dict(data, role="normal-policy-tests")]))
        returned = {"role": "normal-policy-tests", "returned": True, "returncode": 0}
        self.assertFalse(settled([returned, returned]))
        script = aqua_wrapping_source()
        body = script.split("<<'PY_WRAPPING'\n", 1)[1].split("\n          PY_WRAPPING", 1)[0]
        dispatch = body.split('                  if role == "normal":\n', 1)[1].split('                  if role == "qualification":\n', 1)[0]
        for required in ('"--exact", "--test-threads=1", "--color=never", "--format=pretty", *policy_names',
                         'cwd=work, timeout=30, limit=64 * 1024)', 'policy_home.rmdir()', 'policy_tmp.rmdir()',
                         'policy.update(admit_policy_results(result))', 'file_digest(cells[1]) != cells[1]["sha256"]'):
            self.assertIn(required, dispatch)
        self.assertEqual(body.count('invoke("normal-policy-tests"'), 1)
        self.assertLess(dispatch.index('invoke("normal-policy-tests"'), dispatch.index('policy.update(admit_policy_results(result))'))
        self.assertIn('if cell["role"] == "normal-binary" and not policy_original_settled(receipt["calls"]):', body)
        self.assertIn('retainedForUnsettledPolicyOriginal', body)
        self.assertIn('originals_succeeded(receipt["calls"], ("normal-build", "normal-list", "normal-policy-tests"))', body)
        self.assertNotIn('publish("wrapping-policy-tests', body)

class CreatorReaderUIFailDataTests(unittest.TestCase):
    """Focused labelled DATA/state models. No native process, thread or signing.

    These prove parser/latch/ownership routing, NOT macOS observations or CI.
    The actual native two-original pair remains a separately owned verification.
    """
    @staticmethod
    def functions(include_worker=False, include_pair=False, include_reader_call=False):
        import ast
        import hashlib
        import math
        import re
        import struct
        import textwrap
        script = aqua_wrapping_source()
        body = script.split("<<'PY_WRAPPING'\n", 1)[1].split("\n          PY_WRAPPING", 1)[0]
        tree = ast.parse(textwrap.dedent(body))
        names = {"pairs", "parse", "exact_keys", "ints", "settled_policy", "settled_raw", "record_bytes", "owner_budget", "launch_admitted",
                 "acknowledge_admitted", "pair_finality", "admit_peer_case", "admit_controls", "public_reader_report",
                 "admit_reader_report", "signature_identity", "distinct_code_identities", "sig",
                 "pair_directory_same", "pair_prelaunch_mark", "pair_prelaunch_failure",
                 "reader_owner_failure_facts", "reader_owner_elapsed",
                 "reader_phase_registration", "reader_phase_identity", "reader_phase_header", "reader_phase_bound",
                 "reader_phase_prepare", "reader_phase_projection", "reader_phase_writer_settled", "reader_phase_collect"}
        if include_worker: names.add("creator_worker")
        if include_pair: names.add("run_creator_reader")
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        if len(nodes) != len(names): raise AssertionError("fixed pair functions missing or duplicated")
        namespace = {"json": json, "math": math, "hashlib": hashlib, "re": re, "struct": struct, "stat": stat,
                     "subprocess": SimpleNamespace(CompletedProcess=CompletedProcess),
                     "creator_identifier": "dev.mobile-release-kit.qualification.wrapping.creator",
                     "reader_identifier": "dev.mobile-release-kit.qualification.wrapping.reader"}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "<inert-pair-data-functions>", "exec"), namespace)
        if include_reader_call:
            # Actual source slices, with only DATA doubles supplied by the tests.
            # Stop before binary/file checks and ACK; native admission still runs.
            for label, first, last in (
                    ("reader_record_code", "              reader_record = {", "              reader_original = "),
                    ("reader_call_code", "                  reader_started = time.monotonic()\n",
                     "                  for original in (creator, reader):\n"
                     '                      if file_digest(original) != original["sha256"]: raise ValueError("pair-prerelease-binary-changed")\n')):
                if body.count(first) != 1 or body.count(last) != 1:
                    raise AssertionError("fixed reader call boundaries missing or duplicated")
                left, right = body.index(first), body.index(last)
                if left >= right: raise AssertionError("fixed reader call boundaries reordered")
                namespace[label] = compile(textwrap.dedent(body[left:right]), "<inert-reader-" + label + ">", "exec")
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

    def test_directory_custody_changes_links_not_file_identity_or_exact_rosters(self):
        f = self.functions(); same = f["pair_directory_same"]
        pin = SimpleNamespace(st_dev=7, st_ino=19, st_mode=0o040700, st_uid=UID, st_gid=GID,
                              st_nlink=2, st_size=4096, st_mtime_ns=100, st_ctime_ns=100)
        # Synthetic fixed request/ready/ACK creation, publication and removal,
        # not filesystem/APFS evidence. All link observations are retained.
        phases = ((), ("request",), ("request", "ready.next"), ("request", "ready"),
                  ("request", "ready", "reader-settled.next"), ("request", "ready", "reader-settled"),
                  ("ready", "reader-settled"), ("reader-settled",), ())
        for index, roster in enumerate(phases):
            actual = SimpleNamespace(**{**vars(pin), "st_nlink": 2 + len(roster), "st_size": 4096 + index,
                                        "st_mtime_ns": 100 + index, "st_ctime_ns": 100 + index})
            self.assertTrue(same(actual, pin)); self.assertTrue(same(pin, actual))
            self.assertEqual(f["sig"](actual)[3], actual.st_nlink)
        for field, value in (("st_dev", 8), ("st_ino", 20), ("st_mode", 0o040755), ("st_mode", 0o120700),
                             ("st_uid", UID + 1), ("st_gid", GID + 1)):
            self.assertFalse(same(SimpleNamespace(**{**vars(pin), field: value}), pin))
        file = SimpleNamespace(**{**vars(pin), "st_mode": 0o100600, "st_nlink": 1, "st_size": 64})
        self.assertFalse(same(file, file))
        for field in vars(file):
            changed = SimpleNamespace(**{**vars(file), field: getattr(file, field) + 1})
            self.assertNotEqual(f["sig"](changed), f["sig"](file), field)
        native = (PATH.parents[1] / "native/macos-installed-native/src/wrapping_keychain_fixture.m").read_text()
        compare = native.split("static int mrk_qp_directory_same(", 1)[1].split("static int mrk_qp_shape(", 1)[0]
        self.assertIn("S_ISDIR(a->st_mode) && S_ISDIR(b->st_mode)", compare)
        self.assertEqual(set(M.re.findall(r"a->(st_[a-z_]+)", compare)), {"st_dev", "st_ino", "st_mode", "st_uid", "st_gid"})
        regular = native.split("static int mrk_qp_same(", 1)[1].split("static int mrk_qp_directory_same(", 1)[0]
        for field in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtimespec", "st_ctimespec"):
            self.assertIn("a->" + field, regular)
        root = native.split("static int mrk_qp_root(", 1)[1].split("static int mrk_qp_open(", 1)[0]
        self.assertEqual(root.count("mrk_qp_directory_same("), 3); self.assertNotIn("mrk_qp_same(", root)
        roster = native.split("static int mrk_qp_roster(", 1)[1].split("static int mrk_qp_", 1)[0]
        self.assertIn("mrk_qp_directory_same(&held, &p->pins[0])", roster)
        self.assertNotIn("mrk_qp_same(", roster)
        self.assertIn("s->st_nlink == 1 && s->st_size == (off_t)length", native)
        self.assertIn("mrk_qp_same(&p->pins[2], &p->pins[3], 0)", native)
        self.assertIn("mrk_qp_same(&held, &p->pins[i], 1)", native)
        self.assertIn("No partial/EINTR retry.", native)
        self.assertIn("One original close; NEVER retry.", native)
        script = aqua_wrapping_source()
        pair = script.split("          def run_creator_reader(", 1)[1].split("          try:\n              # Version queries", 1)[0]
        self.assertNotIn("sig(root_pin)[:6]", pair)
        self.assertNotIn("actual.st_nlink != 2", pair)
        self.assertIn('sig(ack_cell["pin"])[:7] != sig(staging["pin"])[:7]', pair)
        self.assertIn('sig(request_cell["pin"]) != sig(request_written["pin"])', pair)
        self.assertIn('if set(os.listdir(root_fd)) != {"request", "ready", "reader-settled"}', pair)
        self.assertIn('if os.listdir(root_fd): raise ValueError("pair-control-not-empty")', pair)
        self.assertIn('stage = "wrapping-creator-reader"\n              run_creator_reader(cohort_binary, reader_binary)', script)

    def test_prelaunch_first_failure_labels_are_closed_and_later_errors_do_not_replace(self):
        f = self.functions()
        data = {"phase": "setup", "predicate": None, "returned": False, "firstFailure": None}
        f["pair_prelaunch_mark"](data, "file-sync", "request-write")
        f["pair_prelaunch_failure"](data)
        first = deepcopy(data)
        f["pair_prelaunch_mark"](data, "control-close", "launch")
        f["pair_prelaunch_failure"](data)
        self.assertEqual(data, first)
        self.assertEqual(data["firstFailure"], {"phase": "request-write", "predicate": "file-sync"})
        for predicate, phase in (("INERT_PRIVATE\n", None), ("file-sync", "INERT_PRIVATE"), ("", "setup")):
            with self.assertRaises(ValueError): f["pair_prelaunch_mark"](data, predicate, phase)
            self.assertEqual(data, first)
        done = {"phase": "launch", "predicate": "worker-start", "returned": True, "firstFailure": None}
        f["pair_prelaunch_failure"](done); f["pair_prelaunch_mark"](done, "control-close")
        self.assertEqual(done, {"phase": "launch", "predicate": "worker-start", "returned": True, "firstFailure": None})
        self.assertNotIn("INERT_PRIVATE", json.dumps(data))

    def test_actual_prelaunch_routing_uses_original_facts_without_private_exception_text(self):
        # Extracted routing only, entirely inert OS/thread/libc doubles. No
        # native process, real FD, filesystem mutation, sleep or signing.
        for failure, phase, predicate in (
            ("links-only", "binary-admission", "binary-digest"),
            ("root-mode", "root-admission", "root-mode"),
            ("account", "root-admission", "ordinary-account"),
            ("root-held", "request-write", "root-held-binding"),
            ("root-named", "request-write", "root-named-binding"),
            ("write", "request-write", "file-write"),
            ("short-write", "request-write", "file-write-length"),
            ("sync", "request-write", "file-sync"),
            ("file-shape", "request-write", "file-shape"),
            ("hardlink", "request-write", "file-shape"),
            ("symlink", "request-write", "file-shape"),
            ("file-held", "request-write", "file-held-binding"),
            ("file-named", "request-write", "file-named-binding"),
            ("short-read", "request-read", "file-read-length"),
            ("eof", "request-read", "file-eof-length"),
            ("readback", "request-readback", "readback"),
        ):
            with self.subTest(failure=failure):
                f = self.functions(include_pair=True)
                state = {"data": b"", "written": False, "fileStats": 0}
                closed, published = [], {}
                class Lock:
                    def __enter__(self): return self
                    def __exit__(self, *args): return False
                class Event:
                    value = False
                    def set(self): self.value = True
                    def is_set(self): return self.value
                def error(): raise OSError("INERT_PRIVATE/path\nsecret-control-bytes")
                def directory(named=False):
                    return SimpleNamespace(st_dev=7, st_ino=19 + int(state["written"] and failure == ("root-named" if named else "root-held")),
                        st_mode=0o040755 if failure == "root-mode" else 0o040700, st_uid=UID, st_gid=GID,
                        st_nlink=3 if state["written"] else 2, st_size=4097 if state["written"] else 4096,
                        st_mtime_ns=101 if state["written"] else 100, st_ctime_ns=101 if state["written"] else 100)
                def regular(named=False):
                    return SimpleNamespace(st_dev=7, st_ino=20 + int(failure == "file-held" and state["fileStats"] >= 2 and not named),
                        st_mode=0o120600 if failure == "symlink" else 0o100644 if failure == "file-shape" else 0o100600,
                        st_uid=UID, st_gid=GID, st_nlink=2 if failure == "hardlink" else 1,
                        st_size=len(state["data"]), st_mtime_ns=100, st_ctime_ns=101 if named and failure == "file-named" else 100)
                def fstat(fd):
                    if fd == 4: return directory()
                    self.assertIn(fd, (5, 6)); state["fileStats"] += 1
                    return regular()
                def named_stat(leaf, *, dir_fd, follow_symlinks):
                    self.assertFalse(follow_symlinks)
                    return directory(True) if leaf == "wrapping-pair-control" else regular(True)
                def open_file(leaf, flags, mode=None, *, dir_fd=None):
                    self.assertTrue(flags & 64)  # Source's no-follow bit on every original.
                    if dir_fd is None: return 3
                    if leaf == "wrapping-pair-control": return 4
                    self.assertEqual(leaf, "request")
                    return 5 if flags & 4 else 6
                def write(fd, data):
                    self.assertEqual(fd, 5)
                    if failure == "write": error()
                    state.update(data=data, written=True)
                    return len(data) - int(failure == "short-write")
                def sync(fd):
                    if failure == "sync": error()
                def pread(fd, length, offset):
                    self.assertEqual(fd, 6)
                    if offset: return b"x" if failure == "eof" else b""
                    result = state["data"]
                    if failure == "short-read": return result[:-1]
                    if failure == "readback": return b"x" + result[1:]
                    return result
                def close(fd):
                    self.assertNotIn(fd, closed); closed.append(fd)
                    if failure == "sync" and fd == 3: error()  # Independent later failure, not replacement.
                os_double = SimpleNamespace(open=open_file, fstat=fstat, stat=named_stat, write=write, fsync=sync, pread=pread, close=close,
                    mkdir=lambda *a, **k: None, urandom=lambda n: b"n" * n, getuid=lambda: 0 if failure == "account" else UID,
                    geteuid=lambda: UID, getgid=lambda: GID, getegid=lambda: GID,
                    O_RDONLY=1, O_WRONLY=2, O_CREAT=4, O_EXCL=8, O_DIRECTORY=16, O_NONBLOCK=32, O_NOFOLLOW=64, O_CLOEXEC=128)
                f.update(os=os_double, receipt={"calls": []}, originals=[], work=Path("/INERT_PRIVATE/task"),
                    time=SimpleNamespace(monotonic=lambda: 0.0), threading=SimpleNamespace(Lock=Lock, Event=Event, Thread=lambda **k: error()),
                    ctypes=SimpleNamespace(CDLL=lambda *a, **k: SimpleNamespace(renameatx_np=SimpleNamespace()),
                        c_int=int, c_char_p=bytes, c_uint=int), file_digest=lambda original: "changed",
                    creator_entry="inert-creator", creator_worker=None,
                    publish=lambda leaf, data: published.__setitem__(leaf, json.loads(data)))
                creator = {"path": Path("/INERT_PRIVATE/creator"), "sha256": "unchanged"}
                reader = {"path": Path("/INERT_PRIVATE/reader"), "sha256": "unchanged"}
                with self.assertRaises(ValueError): f["run_creator_reader"](creator, reader)
                pair = published["wrapping-pair.receipt.json"]
                self.assertEqual(pair["prelaunch"]["firstFailure"], {"phase": phase, "predicate": predicate})
                self.assertFalse(pair["prelaunch"]["returned"]); self.assertFalse(pair["startAttempted"])
                self.assertFalse(pair["worker"]["bodyEntered"]); self.assertFalse(pair["passed"])
                self.assertNotIn("INERT_PRIVATE", json.dumps(pair))
                self.assertEqual(len(closed), len(set(closed)))
                if failure == "sync":
                    self.assertEqual(pair["errors"], ["OSError", "OSError"])
                    self.assertFalse(pair["controlOriginalsClosed"])
                else:
                    self.assertTrue(pair["controlOriginalsClosed"])
                if failure in ("links-only", "short-read", "eof", "readback"):
                    self.assertEqual(pair["directoryLinks"], {"initial": 2, "held": 3, "named": 3})
                    request = next(row for row in pair["controlCalls"] if row["role"] == "request")
                    self.assertTrue(request["openEntered"] and request["openReturned"])
                    self.assertTrue(request["readEntered"] and request["readReturned"])
                if phase == "request-write":
                    request = next(row for row in pair["controlCalls"] if row["role"] == "request")
                    self.assertFalse(request["openEntered"])

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
        required = "startAttempted startReturned joinAttempted joinReturned joined joinedBeforeDrain readyAdmitted readerOwnerReturned readerNativeAdmitted creatorNativeAdmitted ackEntered ackReturned ackMayHavePublished ackPublished controlRetired controlOriginalsClosed readerPhaseRetired".split()
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
        h = [3, 2, 6 if reader else 2, 0, 16, 11 if reader else 0, 1249 if reader else 1145, 0, 1,
             len(refs), len(calls), 0 if reader else 32, 1, 1, 6, 5, 5, 5]
        raw = {"header": h, "references": refs, "calls": calls,
               "descriptors": [[1, 1, 1, 1, 0, 1, 1, 1, 0, 0] for _ in range(6)],
               "acl": [11, 11, 11, 0, 11, 11, 11, 11, 11] + [0] * 12,
               "native": [121, 121, 21, 1, 0, 0, 0, 0, 0],
               "policy": BeforeItemStopWorkflowTests.policy_data(role=2 if reader else 1)}
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

    def test_reader_owner_failure_categories_are_closed_without_private_text(self):
        f = self.functions(); project = f["reader_owner_failure_facts"]
        class ProcessError(Exception):
            def __str__(self): raise AssertionError("owner exception must not be formatted")
            def __repr__(self): raise AssertionError("owner exception must not be formatted")
        class ProcessInterrupted(KeyboardInterrupt): pass
        class DerivedError(ProcessError): pass
        owner = SimpleNamespace(ProcessError=ProcessError, ProcessInterrupted=ProcessInterrupted)
        categories = {
            "owned command executable could not be started": "exec-not-started",
            "owned command was stopped before execution": "stopped-before-exec",
            "owned command produced incomplete output": "incomplete-output",
            "owned command output exceeds its bound": "output-bound",
            "owned command cleanup could not be confirmed": "cleanup-unconfirmed",
            "owned command exceeded its original deadline": "owner-deadline",
            "owned command protocol or original ownership is incomplete": "owner-protocol-incomplete",
            "owned command failed, timed out, or produced incomplete output": "owner-failure-unknown",
        }
        unknown = {"dispatched": None, "contained": None, "cleanupComplete": None,
                   "ownerFailureCategory": "owner-failure-unknown"}
        for message, category in categories.items():
            for error_type in (ProcessError, DerivedError):
                self.assertEqual(project(error_type(message), owner), dict(unknown, ownerFailureCategory=category))
        known = "owned command executable could not be started"; sentinel = "INERT_PRIVATE_OWNER_DETAIL"
        class StringChild(str): pass
        class TupleChild(tuple): pass
        class ListArguments(ProcessError):
            @property
            def args(self): return [known]
        class TupleChildArguments(ProcessError):
            @property
            def args(self): return TupleChild((known,))
        alien = ValueError(known); alien.dispatched = alien.contained = alien.cleanup_complete = True
        errors = (ProcessError(sentinel), ProcessError(), ProcessError(object()),
                  ListArguments(), TupleChildArguments(), alien)
        for message in categories:
            errors += (ProcessError(message + " " + sentinel), ProcessError(sentinel + " " + message),
                       ProcessError(message, sentinel), ProcessError(message.encode()), ProcessError(StringChild(message)))
        for index, error in enumerate(errors):
            with self.subTest(case=index):
                actual = project(error, owner)
                self.assertEqual(actual, unknown)
                self.assertNotIn(sentinel, json.dumps(actual, allow_nan=False))

    def test_reader_owner_lifetime_facts_require_exact_bools(self):
        project = self.functions()["reader_owner_failure_facts"]
        owner = SimpleNamespace(ProcessError=type("ProcessError", (Exception,), {}),
                                ProcessInterrupted=type("ProcessInterrupted", (KeyboardInterrupt,), {}))
        class BoolTrap:
            def __bool__(self): raise AssertionError("no lifetime truthiness coercion")
        missing = object()
        for error_type in (owner.ProcessError, owner.ProcessInterrupted):
            for index, value in enumerate((missing, True, False, None, 0, 1, "true", "false", BoolTrap())):
                with self.subTest(kind=error_type.__name__, case=index):
                    error = error_type("INERT_PRIVATE_OWNER_DETAIL")
                    if value is not missing:
                        error.dispatched = error.contained = error.cleanup_complete = value
                    expected = value if type(value) is bool else None
                    interrupted = error_type is owner.ProcessInterrupted
                    self.assertEqual(project(error, owner), {
                        "dispatched": expected, "contained": expected,
                        "cleanupComplete": None if interrupted else expected,
                        "ownerFailureCategory": "interrupted" if interrupted else "owner-failure-unknown",
                    })

    def test_reader_owner_elapsed_is_finite_optional_data_not_a_budget(self):
        elapsed = self.functions()["reader_owner_elapsed"]
        self.assertEqual(elapsed(10.0, 13.25), 3.25)
        self.assertEqual(elapsed(10.0, 10.0), 0.0)
        self.assertEqual(elapsed(10.0, 35.0), 25.0)  # Not clamped to the 15-second owner budget.
        class FloatChild(float): pass
        invalid = ((10, 13.0), (10.0, 13), (True, 2.0), (1.0, False), ("10", 11.0), (10.0, None),
                   (object(), 10.0), (10.0, object()), (FloatChild(10.0), 11.0), (10.0, FloatChild(11.0)),
                   (float("nan"), 10.0), (10.0, float("nan")), (float("inf"), 11.0), (10.0, float("inf")),
                   (-float("inf"), 11.0), (10.0, -float("inf")), (12.0, 11.0), (-1.7e308, 1.7e308))
        for index, samples in enumerate(invalid):
            with self.subTest(case=index): self.assertIsNone(elapsed(*samples))

    def test_reader_owner_raise_preserves_original_and_budget_when_diagnostics_fail(self):
        # Actual call/registration source, not a reconstructed call state machine.
        # DATA doubles only; outer worker cleanup and native finality are not simulated.
        for interrupted in (False, True):
            for fail_projection, fail_clock in ((False, False), (True, False), (False, True), (True, True)):
                with self.subTest(interrupted=interrupted, projection=fail_projection, clock=fail_clock):
                    f = self.functions(include_reader_call=True)
                    owner = SimpleNamespace(ProcessError=type("ProcessError", (Exception,), {}),
                                            ProcessInterrupted=type("ProcessInterrupted", (KeyboardInterrupt,), {}))
                    error_type = owner.ProcessInterrupted if interrupted else owner.ProcessError
                    original = error_type("INERT_PRIVATE_OWNER_DETAIL")
                    original.dispatched = True; original.contained = original.cleanup_complete = False
                    calls, clock_phases, published = [], [], []
                    f.update(owner=owner, reader={"path": "/inert-reader"}, native_env={"INERT": "DATA"}, control=object(),
                             forward_end=45.0, pair={"aborted": False, "readerOwnerReturned": False,
                                                   "readerNativeAdmitted": False, "ackEntered": False})
                    exec(f["reader_record_code"], f)
                    record = f["reader_record"]
                    self.assertEqual(record, {"role": "wrapping-peer-reader", "argv": ["/inert-reader"],
                        "timeoutSeconds": None, "outputBound": 256 * 1024, "entered": False, "returned": False,
                        "ownerCallPhase": "registered", "dispatched": None, "contained": None,
                        "cleanupComplete": None, "ownerFailureCategory": None, "ownerAttemptElapsedSeconds": None})
                    f["reader_original"] = {"record": record, "result": None, "error": None}
                    def run_owned(argv, **kwargs):
                        self.assertEqual(record["ownerCallPhase"], "calling")
                        self.assertIs(record["entered"], True)
                        calls.append((argv, kwargs)); raise original
                    def monotonic():
                        clock_phases.append(record["ownerCallPhase"])
                        if len(clock_phases) == 1: return 10.0
                        self.assertEqual(len(clock_phases), 2)
                        self.assertIs(f["reader_original"]["error"], original)
                        if fail_clock: raise KeyboardInterrupt("INERT_OPTIONAL_CLOCK_ERROR")
                        return 13.25
                    def unavailable_projection(error, selected_owner):
                        self.assertIs(error, original); self.assertIs(selected_owner, owner)
                        self.assertIs(f["reader_original"]["error"], original)
                        raise KeyboardInterrupt("INERT_OPTIONAL_PROJECTION_ERROR")
                    owner.run_owned = run_owned
                    f.update(time=SimpleNamespace(monotonic=monotonic), publish=lambda *args: published.append(args))
                    if fail_projection: f["reader_owner_failure_facts"] = unavailable_projection
                    with self.assertRaises(error_type) as caught: exec(f["reader_call_code"], f)
                    self.assertIs(caught.exception, original)
                    self.assertIs(f["reader_original"]["error"], original); self.assertIsNone(f["reader_original"]["result"])
                    self.assertEqual(clock_phases, ["registered", "raised"]); self.assertEqual(len(calls), 1)
                    self.assertIs(calls[0][0], record["argv"])
                    self.assertEqual(calls[0][1], {"environ": f["native_env"], "cwd": f["control"], "timeout": 15,
                                                  "capture": True, "text": False, "output_limit": 256 * 1024})
                    self.assertEqual(record["timeoutSeconds"], 15); self.assertEqual(f["forward_end"], 45.0)
                    self.assertEqual(record["ownerCallPhase"], "raised"); self.assertEqual(record["errorType"], error_type.__name__)
                    self.assertIs(record["returned"], False); self.assertIs(f["pair"]["readerOwnerReturned"], False)
                    expected = {"dispatched": True, "contained": False, "cleanupComplete": None if interrupted else False,
                                "ownerFailureCategory": "interrupted" if interrupted else "owner-failure-unknown"}
                    for key, value in expected.items(): self.assertEqual(record[key], None if fail_projection else value)
                    self.assertEqual(record["ownerAttemptElapsedSeconds"], None if fail_clock else 3.25)
                    self.assertEqual(published, []); self.assertIs(f["pair"]["readerNativeAdmitted"], False)
                    with self.assertRaises(ValueError): f["acknowledge_admitted"](f["pair"], 14.0, f["forward_end"])
                    self.assertIs(f["pair"]["ackEntered"], False)
                    for sentinel in ("INERT_PRIVATE_OWNER_DETAIL", "INERT_OPTIONAL_CLOCK_ERROR", "INERT_OPTIONAL_PROJECTION_ERROR"):
                        self.assertNotIn(sentinel, json.dumps(record, allow_nan=False))

    def test_reader_owner_nonzero_return_keeps_public_report_and_native_rejection(self):
        for fail_clock in (False, True):
            with self.subTest(clock=fail_clock):
                f = self.functions(include_reader_call=True)
                partial = {"schemaVersion": 2, "scope": "wrapping-other-executable-reader", "provisional": True,
                           "outerFinalityRequired": True, "reportUnavailable": True, "lookup": self.lookup_data(True)}
                result = CompletedProcess(["inert-data-only"], 101,
                    b"MRK_WRAPPING_PEER_RESULT=" + json.dumps(partial).encode() + b"\n", b"INERT_PRIVATE_STDERR")
                calls, clock_phases, projected, published = [], [], [], []
                f.update(reader={"path": "/inert-reader"}, native_env={"INERT": "DATA"}, control=object(), forward_end=45.0,
                         pair={"aborted": False, "readerOwnerReturned": False, "readerNativeAdmitted": False, "ackEntered": False})
                exec(f["reader_record_code"], f); record = f["reader_record"]
                f["reader_original"] = {"record": record, "result": None, "error": None}
                def run_owned(argv, **kwargs):
                    self.assertEqual(record["ownerCallPhase"], "calling"); self.assertIs(record["entered"], True)
                    calls.append((argv, kwargs)); return result
                def monotonic():
                    clock_phases.append(record["ownerCallPhase"])
                    if len(clock_phases) == 1: return 10.0
                    self.assertEqual(len(clock_phases), 2); self.assertIs(f["reader_original"]["result"], result)
                    if fail_clock: raise KeyboardInterrupt("INERT_OPTIONAL_CLOCK_ERROR")
                    return 13.25
                def unexpected_projection(*args):
                    projected.append(args); raise AssertionError("ordinary nonzero result is not an owner failure")
                f.update(owner=SimpleNamespace(run_owned=run_owned), time=SimpleNamespace(monotonic=monotonic),
                         reader_owner_failure_facts=unexpected_projection, publish=lambda *args: published.append(args))
                with self.assertRaises(ValueError): exec(f["reader_call_code"], f)
                self.assertIs(f["reader_original"]["result"], result); self.assertIsNone(f["reader_original"]["error"])
                self.assertEqual(clock_phases, ["registered", "returned"]); self.assertEqual(len(calls), 1)
                self.assertIs(calls[0][0], record["argv"])
                self.assertEqual(calls[0][1], {"environ": f["native_env"], "cwd": f["control"], "timeout": 15,
                                              "capture": True, "text": False, "output_limit": 256 * 1024})
                self.assertEqual(record["timeoutSeconds"], 15); self.assertEqual(f["forward_end"], 45.0)
                self.assertEqual(record["ownerCallPhase"], "returned"); self.assertIs(record["returned"], True)
                self.assertIs(f["pair"]["readerOwnerReturned"], True); self.assertIs(f["pair"]["readerNativeAdmitted"], False)
                self.assertNotIn("errorType", record); self.assertEqual(record["returncode"], 101); self.assertEqual(projected, [])
                for key in ("dispatched", "contained", "cleanupComplete", "ownerFailureCategory"): self.assertIsNone(record[key])
                self.assertEqual(record["ownerAttemptElapsedSeconds"], None if fail_clock else 3.25)
                self.assertEqual(len(published), 1); self.assertEqual(published[0][0], "wrapping-reader.report.json")
                self.assertEqual(json.loads(published[0][1]), partial)
                self.assertNotIn("stdout", record); self.assertNotIn("stderr", record)
                self.assertNotIn("INERT_PRIVATE_STDERR", json.dumps(record, allow_nan=False))
                self.assertNotIn(b"INERT_PRIVATE_STDERR", published[0][1])
                with self.assertRaises(ValueError): f["acknowledge_admitted"](f["pair"], 14.0, f["forward_end"])
                self.assertIs(f["pair"]["ackEntered"], False)

    def test_reader_public_failure_preserves_status_without_exporting_private_text(self):
        f = self.functions()
        partial = {"schemaVersion": 2, "scope": "wrapping-other-executable-reader", "provisional": True,
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
        script = aqua_wrapping_source()
        self.assertIn('row["identityAdmission"] = identity_facts', script)
        self.assertLess(script.index('row["identityAdmission"] = identity_facts'),
                        script.index('identities.append(signature_identity(result, identifier, identity_facts))'))

    def test_peer_settled_requires_verified_zero_helpers_for_both_originals(self):
        # Source contract plus labelled scalar DATA, never a native CaseReturn,
        # fixture, Keychain call or success receipt.
        native = PATH.parents[1] / "native/macos-installed-native/src"
        pair = (native / "wrapping_keychain_pair.rs").read_text()
        qualification = (native / "wrapping_keychain_qualification.rs").read_text()

        def definition(source, signature):
            self.assertEqual(source.count(signature), 1)
            return source.split(signature, 1)[1].split("\n}", 1)[0]

        peer = definition(pair, "pub(super) fn peer_settled(row: &CaseReturn) -> bool {")
        declaration, expression = peer.strip().split(";", 1)
        self.assertEqual(declaration, "let f = row.facts()")
        clauses = tuple(" ".join(clause.split()) for clause in expression.split("&&"))
        gates = (
            "f.native_run_returned()", "f.verified_native_run_receipt()",
            "f.custody() == Custody::Settled", "!f.callback_panicked()",
            "!f.native_exception()", "!f.stopped()", "f.ordinary_user_admitted()",
            "row.selection().verified()", "row.selection().account_selected()",
            "row.selection().fixture_selected()", "row.selection().root_identity_matched()",
            "row.selection().callbacks_cleared()", "!row.selection().selector_boundary_returned()",
        )
        helper_clause = "row.selection().helper_counts() == Some((0, 0, 0))"
        self.assertEqual(clauses, (*gates, helper_clause))

        counts_source = qualification.split(
            "pub fn helper_counts(&self) -> Option<(u32, u32, u32)> {", 1)[1].split("\n    }", 1)[0]
        self.assertEqual(" ".join(counts_source.split()),
                         "self.verified.then_some((self.raw.helpers_entered, self.raw.helpers_returned, "
                         "self.raw.helper_matches.count_ones()))")
        valid = qualification.split("impl Observation {", 1)[1].split("fn complete_helpers(", 1)[0]
        self.assertIn("if mode != HELPERS && (self.helpers_entered != 0 || self.helpers_returned != 0 "
                      "|| self.helper_matches != 0) { return false; }", " ".join(valid.split()))
        lookup = qualification.split("impl PeerLookup {", 1)[1]
        self.assertIn("mrk_wrapping_qualification_run(frame, FIXTURE, &self.fixture, Operation::Lookup.raw(),", lookup)
        self.assertIn("observation.valid(raw, FIXTURE)", lookup)

        # Interpret only the closed conjunction above over synthetic clause
        # values. The Option tuple requirement is taken from the source clause.
        required_counts = tuple(int(value) for value in clauses[-1].split(" == Some((", 1)[1][:-2].split(","))

        def admits(verified, counts, failed_gate=None):
            values = dict.fromkeys(gates, True)
            values["row.selection().verified()"] = verified
            values[helper_clause] = counts == required_counts
            if failed_gate is not None:
                values[failed_gate] = False
            return all(values[clause] for clause in clauses)

        helper_rows = ((0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1),
                       (1, 1, 0), (1, 1, 1), (2, 2, 3), (0, 0, 1 << 31))
        for verified in (False, True):
            for entered, returned, matches in helper_rows:
                counts = (entered, returned, matches.bit_count()) if verified else None
                with self.subTest(verified=verified, helpers=(entered, returned, matches)):
                    self.assertEqual(admits(verified, counts),
                                     verified and (entered, returned, matches) == (0, 0, 0))
        # Absence must not become a fallback, even with all other gates true;
        # a zero tuple must not bypass the independent verification gate.
        self.assertFalse(admits(True, None))
        self.assertFalse(admits(False, (0, 0, 0)))
        for gate in gates:
            with self.subTest(failed_gate=gate):
                self.assertFalse(admits(True, (0, 0, 0), gate))

        # The creator candidate and the distinct reader UIFail denial must
        # both pass this same gate, not separate absent-or-zero substitutes.
        for signature, case in (
            ("pub(super) fn creator_lookup_ready(row: &CaseReturn) -> bool {", "CreatorControlLookup"),
            ("fn reader_denied(row: &CaseReturn) -> bool {", "OtherExecutableLookup"),
        ):
            consumer = definition(pair, signature)
            with self.subTest(consumer=case):
                self.assertEqual(consumer.count("peer_settled(row)"), 1)
                self.assertIn("row.case() == Case::" + case + " && peer_settled(row) &&",
                              " ".join(consumer.split()))
                self.assertNotIn("||", consumer)

    def phase_model(self, fault=None):
        # Fixed inert filesystem DATA; no descriptor, file, process or clock is opened.
        f = self.functions()
        def meta(inode, mode, size=0):
            return SimpleNamespace(st_dev=7, st_ino=inode, st_mode=mode, st_uid=UID, st_gid=GID,
                st_nlink=1 if mode == 0o100600 else 2, st_size=size, st_mtime_ns=100, st_ctime_ns=100)
        parent, root = meta(30, 0o040700), meta(31, 0o040700)
        model = {"present": fault == "collision", "bytes": b"unrelated-inert-original" if fault == "collision" else b"",
                 "replacement": False, "fileStats": 0, "checks": 0, "collecting": False, "collectionReads": 0, "closeDone": False}
        calls = []
        def fstat(fd):
            calls.append(("fstat", fd))
            if fd == 10: return parent
            self.assertEqual(fd, 7); model["fileStats"] += 1
            if fault == "first-stat" and model["fileStats"] == 1: raise OSError("INERT_PRIVATE_STAT")
            return meta(32, 0o100600, len(model["bytes"]))
        def named(leaf, *, dir_fd, follow_symlinks):
            calls.append(("stat", leaf)); self.assertEqual((leaf, dir_fd, follow_symlinks), ("wrapping-reader-phase.bin", 10, False))
            if not model["present"]: raise FileNotFoundError()
            return meta(33 if model["replacement"] else 32, 0o100600, len(model["bytes"]))
        def open_file(leaf, flags, mode, *, dir_fd):
            calls.append(("open", leaf)); self.assertEqual((leaf, flags, mode, dir_fd), ("wrapping-reader-phase.bin", 63, 0o600, 10))
            if model["present"]: raise FileExistsError("INERT_PRIVATE_COLLISION")
            model["present"] = True; return 7
        def write(fd, data):
            calls.append(("write", fd)); self.assertEqual(fd, 7)
            length = 127 if fault == "short-write" else len(data)
            model["bytes"] = data[:length]; return length
        def sync(fd):
            calls.append(("sync", fd))
            if fault == "sync": raise OSError("INERT_PRIVATE_SYNC")
        def read(fd, size, offset):
            calls.append(("read", size, offset)); self.assertEqual(fd, 7)
            if model["collecting"]: model["collectionReads"] += 1
            return model["bytes"][offset:offset + size]
        def unlink(leaf, *, dir_fd):
            calls.append(("unlink", leaf)); self.assertEqual((leaf, dir_fd), ("wrapping-reader-phase.bin", 10))
            model["present"] = False
        def close(fd):
            calls.append(("close", fd)); self.assertEqual(fd, 7); model["closeDone"] = True
            if fault == "close": raise OSError("INERT_PRIVATE_CLOSE")
        def check():
            model["checks"] += 1
            if fault == "deadline-after-write" and model["checks"] == 3:
                raise ValueError("INERT_ORIGINAL_CUTOFF")
        def collection_check():
            model["collecting"] = True; calls.append(("collection-clock",))
            if (fault == "collect-before-read" or fault == "collect-after-read" and model["collectionReads"] >= 2
                    or fault == "collect-after-close" and model["closeDone"]):
                raise ValueError("INERT_ORIGINAL_DRAIN_CUTOFF")
        f["phase_collect_check"] = collection_check
        f["os"] = SimpleNamespace(fstat=fstat, stat=named, open=open_file, write=write, fsync=sync, pread=read, unlink=unlink, close=close,
            getuid=lambda: UID, geteuid=lambda: UID, getgid=lambda: GID, getegid=lambda: GID,
            O_RDWR=1, O_CREAT=2, O_EXCL=4, O_NOFOLLOW=8, O_NONBLOCK=16, O_CLOEXEC=32)
        f["owner"] = SimpleNamespace(ProcessError=type("ProcessError", (Exception,), {}),
                                    ProcessInterrupted=type("ProcessInterrupted", (KeyboardInterrupt,), {}))
        original = {"record": {"entered": False, "returned": False}, "result": None, "error": None}
        return f, f["reader_phase_registration"](), root, original, model, calls, check

    def test_reader_phase_codec_keeps_only_valid_unique_history_without_private_bytes(self):
        import struct
        f, cell, root, original, model, calls, check = self.phase_model()
        def projection(state, events, elapsed):
            return {"state": state, "events": events, "elapsedMilliseconds": elapsed,
                    "elapsedRounding": "floor", "clockOrigin": "reader-entry",
                    "clockSample": "pre-diagnostic-write-admission", "historyOnly": True, "currentCallKnown": False}
        self.assertEqual(cell["record"]["projection"], projection("unavailable", [], []))
        f["reader_phase_prepare"](cell, 10, root, check)
        header = cell["header"]; decode = f["reader_phase_projection"]
        self.assertEqual(header[:8], b"MRKQDG02")
        self.assertEqual(len(header), 128); self.assertEqual(len(model["bytes"]), 2176)
        self.assertEqual(decode(model["bytes"], header), projection("empty", [], []))
        def record(slot, event, elapsed=0):
            payload = (elapsed << 8) | event
            return struct.pack("<4I", 0x32514744, slot, payload, 0x4d524b32 ^ slot ^ payload)
        first = record(1, 1); second = record(2, 77, 17)  # phase4/open BeforeCall, NOT API entered.
        valid = header + first + second + bytes(2048 - 32)
        expected = projection("prefix", ["diagnostic-opened", "native:open:before-call"], [0, 17])
        prefix = projection("partial", ["diagnostic-opened"], [0])
        self.assertEqual(decode(valid, header), expected)
        # Truncation anywhere in one final record preserves only the preceding record and its time.
        for length in (1, 4, 8, 12, 15):
            raw = header + first + second[:length] + bytes(2048 - 16 - length)
            self.assertEqual(decode(raw, header), prefix)
        old = struct.pack("<4I", 0x31514744, 2, 77, 0x4d524b31 ^ 2 ^ 77)
        corrupt_time = second[:9] + bytes([second[9] ^ 1]) + second[10:]
        bad_magic = struct.pack("<4I", 0x32514745, 2, (17 << 8) | 77, 0x4d524b32 ^ 2 ^ ((17 << 8) | 77))
        for tail in (record(2, 1, 19), record(3, 77, 17), record(2, 0), record(2, 25),
                     record(2, 64), record(2, 149), record(2, 255), old, corrupt_time, bad_magic,
                     b"INERT_PRIVATE!!!" + b"X"):
            raw = header + first + tail + bytes(2048 - 16 - len(tail))
            actual = decode(raw, header)
            self.assertEqual(actual, prefix)
            self.assertNotIn("INERT_PRIVATE", json.dumps(actual))
        gap = header + first + bytes(16) + record(3, 77, 17) + bytes(2048 - 48)
        self.assertEqual(decode(gap, header), prefix)
        legacy_header = b"MRKQDG01" + header[8:]
        for data, pin in ((valid[:-1], header), (valid + b"x", header), (bytearray(valid), header),
                          (valid, b"x" + header[1:]), (b"x" * 2176, b"x" * 128),
                          (legacy_header + valid[128:], legacy_header)):
            with self.assertRaises(ValueError): decode(data, pin)
        # Explicit cleanup of model resources only; this test creates no real output.
        self.assertEqual(f["reader_phase_collect"](cell, 10, original, f["phase_collect_check"]), [])
        self.assertTrue(cell["record"]["retired"])

    def test_reader_phase_partial_preparation_collision_and_close_failures_keep_original_custody(self):
        for fault in ("collision", "first-stat", "short-write", "sync", "deadline-after-write", "close",
                      "collect-before-read", "collect-after-read", "collect-after-close"):
            with self.subTest(fault=fault):
                f, cell, root, original, model, calls, check = self.phase_model(fault)
                if fault in ("close", "collect-before-read", "collect-after-read", "collect-after-close"):
                    f["reader_phase_prepare"](cell, 10, root, check)
                else:
                    with self.assertRaises((OSError, ValueError)): f["reader_phase_prepare"](cell, 10, root, check)
                collect_start = len(calls)
                errors = f["reader_phase_collect"](cell, 10, original, f["phase_collect_check"])
                before = list(calls)
                self.assertIs(f["reader_phase_collect"](cell, 10, original, f["phase_collect_check"]), errors)
                self.assertEqual(calls, before)  # No repeat read/unlink/close.
                self.assertEqual(sum(c[0] == "close" for c in calls), int(fault != "collision"))
                if fault == "collision":
                    self.assertEqual(model["bytes"], b"unrelated-inert-original")
                    self.assertTrue(model["present"]); self.assertFalse(cell["record"]["acquired"])
                    self.assertFalse(any(c[0] in ("write", "read", "unlink", "close") for c in calls))
                elif fault in ("first-stat", "collect-before-read", "collect-after-read"):
                    self.assertTrue(model["present"]); self.assertTrue(cell["record"]["closed"])
                    self.assertFalse(cell["record"]["retired"]); self.assertTrue(errors)
                else:
                    self.assertFalse(model["present"])
                    self.assertEqual(cell["record"]["retired"], fault != "close")
                if fault.startswith("collect-"):
                    self.assertTrue(errors); self.assertTrue(all(type(e) is ValueError for e in errors))
                    self.assertTrue(cell["record"]["closed"]); self.assertIsNone(cell["fd"])
                    self.assertEqual(model["collectionReads"], 0 if fault == "collect-before-read" else 2)
                    self.assertEqual(cell["record"]["retired"], fault == "collect-after-close")
                    if fault == "collect-before-read":
                        self.assertFalse(any(c[0] in ("fstat", "stat", "read", "unlink") for c in calls[collect_start:]))
                if fault == "close":
                    self.assertEqual([type(e) for e in errors], [OSError])
                    self.assertFalse(cell["record"]["closed"]); self.assertIsNone(cell["fd"])
                self.assertNotIn("INERT_PRIVATE", json.dumps(cell["record"]))

    def test_reader_phase_writer_finality_refuses_any_unknown_or_conflicting_lifetime(self):
        f, cell, root, original, model, calls, check = self.phase_model()
        settle = f["reader_phase_writer_settled"]; owner = f["owner"]
        self.assertTrue(settle(original))  # No writer was ever attempted.
        original["record"]["returned"] = True; self.assertFalse(settle(original))
        original["record"]["returned"] = False
        original["record"]["entered"] = True
        self.assertFalse(settle(original))
        error = owner.ProcessError("INERT_PRIVATE_TIMEOUT"); error.contained = error.cleanup_complete = True
        original["error"] = error
        self.assertTrue(settle(original))
        original["record"]["returned"] = True; self.assertFalse(settle(original))
        original["record"]["returned"] = False
        for field in ("contained", "cleanup_complete"):
            for value in (False, None, 1, "true"):
                setattr(error, field, value); self.assertFalse(settle(original))
            setattr(error, field, True)
        conflict = owner.ProcessError("INERT_PRIVATE_CLEANUP"); conflict.contained = True; conflict.cleanup_complete = False
        error.__cause__ = conflict; self.assertFalse(settle(original))
        error.__cause__ = owner.ProcessInterrupted("INERT_PRIVATE_INTERRUPT"); self.assertFalse(settle(original))
        error.__cause__ = None
        alien = ValueError("owned command exceeded its original deadline"); alien.contained = alien.cleanup_complete = True
        original["error"] = alien; self.assertFalse(settle(original))
        original["error"] = None; original["record"]["returned"] = True
        original["result"] = CompletedProcess(["inert"], 101, b"", b"")
        self.assertTrue(settle(original))  # Failed command can have settled writer custody.
        original["result"] = CompletedProcess(["inert"], False, b"", b""); self.assertFalse(settle(original))

    def test_reader_phase_collection_preserves_owner_error_refuses_replacement_and_never_reads_live_writer(self):
        import struct
        for condition in ("unknown", "replacement", "partial", "settled"):
            with self.subTest(condition=condition):
                f, cell, root, original, model, calls, check = self.phase_model()
                f["reader_phase_prepare"](cell, 10, root, check)
                error = f["owner"].ProcessError("INERT_PRIVATE_TIMEOUT")
                error.contained = True; error.cleanup_complete = condition != "unknown"
                original["record"]["entered"] = True; original["error"] = error
                payload = (123 << 8) | 1
                record = struct.pack("<4I", 0x32514744, 1, payload, 0x4d524b32 ^ 1 ^ payload)
                model["bytes"] = cell["header"] + record + (b"private tail!!!x" if condition == "partial" else bytes(16)) + bytes(2016)
                model["replacement"] = condition == "replacement"
                start = len(calls)
                errors = f["reader_phase_collect"](cell, 10, original, f["phase_collect_check"])
                self.assertIs(original["error"], error); self.assertIsNone(original["result"])
                later = calls[start:]
                if condition == "unknown":
                    self.assertEqual(later, []); self.assertEqual(cell["fd"], 7); self.assertFalse(cell["record"]["retired"])
                elif condition == "replacement":
                    self.assertFalse(any(c[0] in ("read", "unlink") for c in later))
                    self.assertTrue(model["present"]); self.assertTrue(cell["record"]["closed"]); self.assertTrue(errors)
                else:
                    self.assertFalse(model["present"]); self.assertTrue(cell["record"]["retired"])
                    self.assertEqual(cell["record"]["projection"]["state"], "partial" if condition == "partial" else "prefix")
                    self.assertEqual(bool(errors), condition == "partial")
                    self.assertEqual(cell["record"]["projection"]["elapsedMilliseconds"], [123])
                self.assertEqual(len(cell["record"]["projection"]["events"]), len(cell["record"]["projection"]["elapsedMilliseconds"]))
                self.assertFalse(cell["record"]["projection"]["currentCallKnown"])
                self.assertNotIn("private", json.dumps(cell["record"]))


    def test_reader_phase_timing_is_original_entry_bounded_historical_data(self):
        import struct
        f, cell, root, original, model, calls, check = self.phase_model()
        f["reader_phase_prepare"](cell, 10, root, check)
        header = cell["header"]; decode = f["reader_phase_projection"]
        def record(sequence, event, elapsed):
            payload = (elapsed << 8) | event
            return struct.pack("<4I", 0x32514744, sequence, payload, 0x4d524b32 ^ sequence ^ payload)
        def snapshot(rows):
            records = b"".join(record(i + 1, event, elapsed) for i, (event, elapsed) in enumerate(rows))
            return header + records + bytes(2048 - len(records))
        # Synthetic PRE-WRITE admission samples, not API entry/completion or owner elapsed.
        rows = [(10, 0), (105, 4), (106, 9000), (11, 9999)]
        expected_events = ["peer-run-before", "native:lookup:before-call",
                           "native:lookup:after-call", "peer-run-returned"]
        actual = decode(snapshot(rows), header)
        self.assertEqual(actual, {"state": "prefix", "events": expected_events,
            "elapsedMilliseconds": [0, 4, 9000, 9999], "elapsedRounding": "floor",
            "clockOrigin": "reader-entry", "clockSample": "pre-diagnostic-write-admission",
            "historyOnly": True, "currentCallKnown": False})
        tied = decode(snapshot([(event, 0) for event, _ in rows]), header)
        self.assertEqual(tied["elapsedMilliseconds"], [0, 0, 0, 0])
        self.assertEqual(tied["events"], expected_events); self.assertEqual(tied["state"], "prefix")
        # An absent after-call keeps only history, even though an owner could later time out.
        only_before = decode(snapshot(rows[:2]), header)
        self.assertEqual(only_before["events"], expected_events[:2])
        self.assertEqual(only_before["elapsedMilliseconds"], [0, 4])
        self.assertIs(only_before["historyOnly"], True); self.assertIs(only_before["currentCallKnown"], False)
        first = record(1, 10, 100)
        partial = dict(actual, state="partial", events=["peer-run-before"], elapsedMilliseconds=[100])
        for tail in (record(2, 105, 99), record(2, 105, 10000), record(2, 105, 0xffffff),
                     record(2, 10, 101), struct.pack("<4I", 0x32514744, 2, 0xffffffff, 0x4d524b32 ^ 2 ^ 0xffffffff)):
            self.assertEqual(decode(header + first + tail + bytes(2016), header), partial)
        # All108 IDs remain available exactly once, within the unchanged128 slots.
        events = list(range(1, 25)) + list(range(65, 149))
        full = decode(snapshot([(event, i * 93) for i, event in enumerate(events)]), header)
        self.assertEqual(full["state"], "prefix"); self.assertEqual(len(full["events"]), 108)
        self.assertEqual(len(set(full["events"])), 108)
        self.assertEqual(full["elapsedMilliseconds"], [i * 93 for i in range(108)])
        self.assertEqual(full["elapsedMilliseconds"][-1], 9951)
        self.assertIs(full["currentCallKnown"], False)
        self.assertEqual(f["reader_phase_collect"](cell, 10, original, f["phase_collect_check"]), [])
        self.assertTrue(cell["record"]["retired"])

    def test_reader_phase_timing_source_uses_only_existing_clock_and_write_admissions(self):
        root = PATH.parents[2]; native = root / "desktop/native/macos-installed-native"
        pair = (native / "src/wrapping_keychain_pair.rs").read_text()
        fixture = (native / "src/wrapping_keychain_fixture.m").read_text()
        native_calls = (native / "src/wrapping_keychain.m").read_text()
        script = aqua_wrapping_source()
        clock = pair.split("struct ReaderClock {", 1)[1].split("// One qualification-only diagnostic original", 1)[0]
        self.assertIn("entry: Instant", clock)
        self.assertIn("entry, cutoff: entry.checked_add(Duration::from_secs(READER_SECONDS))", clock)
        self.assertIn("elapsed_millis: None", clock)
        self.assertEqual(clock.count("Instant::now()"), 1)
        self.assertEqual(clock.count("self.checks += 1;"), 1)
        self.assertLess(clock.index("self.elapsed_millis = None;"), clock.index("self.cutoff.is_none_or("))
        self.assertLess(clock.index("self.cutoff.is_none_or(|cutoff| {"), clock.index("let now = Instant::now();"))
        self.assertIn("now.checked_duration_since(self.entry)", clock)
        self.assertIn("u32::try_from(elapsed.as_millis()).ok()", clock)
        self.assertIn("now >= cutoff", clock)
        self.assertIn("if self.poisoned { Admission::Unknown } else if self.late { Admission::Cutoff } else { Admission::Continue }", clock)
        for forbidden in ("unwrap_or(", "unwrap_or_default(", "Duration::from_millis(", "std::thread", "sleep("):
            self.assertNotIn(forbidden, clock)
        self.assertIn("READER_PHASE_MILLIS_LIMIT: u32 = (READER_SECONDS * 1000) as u32", pair)
        phase = pair.split("impl ReaderPhase {", 1)[1].split("struct Reader {", 1)[0]
        marker = phase.split("    fn marker(", 1)[1].split("    fn native(", 1)[0]
        self.assertLess(marker.index("clock.admit() == Admission::Continue"), marker.index("clock.elapsed_millis"))
        self.assertIn(".filter(|millis| *millis < READER_PHASE_MILLIS_LIMIT && self.writes < 128)", marker)
        sample = marker.split("let Some(elapsed_millis) = clock.elapsed_millis", 1)[1].split("let slot =", 1)[0]
        self.assertIn("self.failed = true; return clock.admit();", sample)
        self.assertIn("let payload = (elapsed_millis << 8) | event;", marker)
        self.assertIn("READER_PHASE_GUARD ^ (slot + 1) ^ payload", marker)
        self.assertEqual(marker.count("clock.admit()"), 4)  # Same pre-I/O, two failure exits, final post-I/O.
        self.assertEqual(marker.count("mrk_wrapping_reader_phase_write("), 1)
        self.assertTrue(marker.rstrip().endswith("clock.admit()\n    }"))
        self.assertNotIn("Instant::now", marker)
        self.assertNotIn("Admission::Continue;", marker)
        route = phase.split("    fn native(", 1)[1].split("    fn finish(", 1)[0]
        self.assertEqual(route.count("Checkpoint::"), 4)
        self.assertEqual(route.count("self.marker("), 1)
        self.assertNotIn("security_calls(", route)  # No added native status category.
        entry = pair.split("pub fn reader_entry(entry: Instant) {", 1)[1]
        self.assertIn("Reader::empty(entry)", entry)
        helper = (native / "examples/wrapping_peer_reader.rs").read_text()
        main = helper.split("fn main() {", 1)[1]
        self.assertTrue(main.lstrip().startswith("let entry = std::time::Instant::now();"))
        self.assertIn("private_pair::reader_entry(entry);", main)
        self.assertNotIn("let entry = Instant::now();", entry)
        self.assertIn("size_of::<ManuallyDrop<Self>>()", pair)
        self.assertIn("fds: [PhaseFd; 3]", pair)
        self.assertIn("READER_PHASE_BYTES: usize = 2176", pair)
        writer = fixture.split("int64_t mrk_wrapping_reader_phase_write(", 1)[1].split("int32_t mrk_wrapping_reader_phase_close(", 1)[0]
        self.assertIn("if (fd < 0 || !record || slot >= 128)", writer)
        self.assertIn("return pwrite(fd, record, 16, 128 + (off_t)slot * 16);", writer)
        self.assertEqual(writer.count("pwrite("), 1); self.assertNotIn("MRKQDG", writer)
        self.assertIn("kSecUseAuthenticationUIFail", native_calls)
        self.assertIn("READER_SECONDS: u64 = 10", pair)
        self.assertIn("owner_budget(reader_started, forward_end, 15)", script)

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
        body = aqua_wrapping_source().split("<<'PY_WRAPPING'\n", 1)[1].split("\n          PY_WRAPPING", 1)[0]
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

        # Diagnostic history uses the same clocks and a fixed sibling, not the
        # control records, user inputs, a new owner, or public raw output.
        self.assertIn("READER_PHASE_BYTES: usize = 2176", pair)
        self.assertIn("READER_CHARGE_LIMIT: usize = 512 * 1024", pair)
        self.assertIn("size_of::<ManuallyDrop<Self>>()", pair)
        self.assertIn("phase: ReaderPhase", pair)
        phase = pair.split("impl ReaderPhase {", 1)[1].split("struct Reader {", 1)[0]
        self.assertIn("self.fds.iter_mut().rev()", phase)
        self.assertIn("self.initialized && !self.failed && closed", phase)
        self.assertIn('b"MRKQDG02"', phase)
        self.assertIn("self.bytes[128..].iter().any", phase)
        self.assertIn("self.fds[role].file = Some(ManuallyDrop::new", phase)
        marker = phase.split("    fn marker(", 1)[1].split("    fn native(", 1)[0]
        self.assertLess(marker.index("self.seen |= bit"), marker.index("mrk_wrapping_reader_phase_write"))
        self.assertTrue(marker.rstrip().endswith("clock.admit()\n    }"))  # Fresh after IO, not a saved Continue.
        consume = pair.split("impl PhaseFd {", 1)[1].split("struct ReaderPhase {", 1)[0]
        self.assertLess(consume.index("self.file.take()"), consume.index("mrk_wrapping_reader_phase_close(fd)"))
        self.assertEqual(consume.count("mrk_wrapping_reader_phase_close(fd)"), 1)
        self.assertIn("reader.phase_panic.is_none()", pair)
        actual = pair.split("impl Reader {", 1)[1].split("    fn build_report", 1)[0]
        self.assertLess(actual.index("self.original = Some(actual)"), actual.index("phase.marker(11, clock)"))
        shim = control.split("// Qualification-only fixed diagnostic sibling.", 1)[1]
        self.assertIn('openat(parent, "wrapping-reader-phase.bin", O_RDWR | flags)', shim)
        self.assertIn("O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC", shim)
        self.assertEqual(shim.count("return pwrite("), 1)
        self.assertEqual(shim.count("return close(fd)"), 1)
        for forbidden in ("O_CREAT", "O_TRUNC", "getenv(", "setenv(", "fsync(", "while (", "for ("):
            self.assertNotIn(forbidden, shim)
        self.assertIn("started + 5, started + 20, started + 35, started + 100", body)
        self.assertIn("owner_budget(reader_started, forward_end, 15)", body)
        pair_body = body.split("          def run_creator_reader(creator, reader):", 1)[1]
        self.assertLess(pair_body.index("phase_original = reader_phase_registration()"), pair_body.index("worker.start()"))
        self.assertLess(pair_body.index("pair-prelaunch-binary-changed"), pair_body.index("reader_phase_prepare("))
        self.assertLess(pair_body.index("reader_phase_prepare("), pair_body.index("threading.Thread("))
        self.assertLess(pair_body.index("worker.join("), pair_body.index("reader_phase_collect("))
        self.assertIn('pair["readerPhaseRetired"] = phase_original["record"]["retired"]', pair_body)
        self.assertNotIn("wrapping-reader-phase.bin", upload)
        collect = body.split("          def reader_phase_collect(", 1)[1].split("          def pair_finality(", 1)[0]
        self.assertLess(collect.index("os.close(fd)"), collect.rindex("check_time()"))
        drain = pair_body.split("              def reader_phase_check_time():", 1)[1].split("              def resource(", 1)[0]
        self.assertIn("time.monotonic() >= drain_end", drain)
        self.assertNotIn("abort.is_set()", drain)  # Settled failed owner still gets diagnostics inside its unchanged drain.
        self.assertIn("reader_phase_collect(phase_original, parent_fd, reader_original, reader_phase_check_time)", pair_body)
        tail = pair_body.split('pair["worker"]["timeoutSeconds"] = holder.get("timeoutSeconds")', 1)[1]
        self.assertLess(tail.index("reader_phase_check_time()"), tail.index('pair["aborted"] = abort.is_set()'))
        self.assertLess(tail.index('except BaseException as error: fail(error)'), tail.index('pair["errors"] = '))
        self.assertLess(tail.index('pair["errors"] = '), tail.index('pair["passed"] = pair_finality(pair)'))
        for name in ("account", "open", "write", "close"):
            self.assertIn('"_mrk_wrapping_reader_phase_' + name + '"', body)
        self.assertIn('role != "qualification" and observed_phase', body)
        self.assertIn('cell["role"] == "qualification-archive" and observed_phase != reader_phase_symbols', body)
        self.assertIn('(reader_binary, pair_symbols | reader_phase_symbols)', body)
        self.assertIn('not (required | {"_mrk_wrapping_private_process_role"}) <= symbols', body)


class PrivateCodecWorkflowDataTests(unittest.TestCase):
    """Focused synthetic DATA only; never a native/Mac/compiler pass."""

    @staticmethod
    def functions():
        import ast
        import hashlib
        import pathlib
        import re
        import textwrap
        script = aqua_wrapping_source()
        body = script.split("<<'PY_WRAPPING'\n", 1)[1].split("\n          PY_WRAPPING", 1)[0]
        tree = ast.parse(textwrap.dedent(body))
        names = {"pairs", "parse", "admit_codec_compiler", "admit_fixed_data_results", "admit_codec_results",
                 "admit_policy_results", "fixed_test_original_settled", "codec_original_settled", "policy_original_settled",
                 "originals_succeeded", "codec_originals_succeeded", "private_batch_finality", "public_codec_receipt"}
        bindings = {"codec_names", "policy_names", "artifact_roles"}
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
        artifact = {"reason": "compiler-artifact", "package_id": "path+" + app.as_uri() + "#mobile-release-kit-desktop@0.1.1",
                    "manifest_path": str(app / "Cargo.toml"), "features": [], "executable": str(binary), "filenames": [str(binary)],
                    "target": {"name": "mobile_release_desktop", "kind": ["lib"], "crate_types": ["lib"], "src_path": str(app / "src/lib.rs")},
                    "profile": {"test": True, "debug_assertions": True, "overflow_checks": True, "opt_level": "0"}}
        def captured(rows, code=0): return CompletedProcess(["inert-cargo-json-data"], code,
            b"\n".join(json.dumps(row).encode() for row in rows) + b"\n", b"compiler DATA")
        finish = {"reason": "build-finished", "success": True}
        check = f["admit_codec_compiler"]
        self.assertEqual(check(captured([artifact, finish])), binary)
        mutations = [lambda a: a.__setitem__("package_id", "path+file:///different#mobile-release-kit-desktop@0.1.1"),
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

    def test_codec_failure_unknown_original_and_each_of_eleven_closes_gate_batch_finality(self):
        f = self.functions()
        receipt = {"calls": [{"role": role, "returned": True, "returncode": 0}
                             for role in ("codec-build", "codec-tests", "normal-build", "normal-list", "normal-policy-tests")],
                   "nativeOriginalReturned": True, "nativeReportAdmitted": True,
                   "pair": {"passed": True}, "pairNativeObservationsAdmitted": True,
                   "policyData": {"testsPassed": True, "artifactHashRechecked": True, "syntheticDirectoriesRetired": True}}
        codec = {"compilerAdmitted": True, "testsPassed": True, "artifactHashRechecked": True, "syntheticDirectoriesRetired": True}
        self.assertEqual(len(f["artifact_roles"]), 11)
        cells = [{"role": role, "unchanged": True, "closed": True} for role in f["artifact_roles"]]
        check = f["private_batch_finality"]
        self.assertTrue(check(receipt, codec, cells, [], []))
        for key in codec:
            with self.subTest(codec=key): self.assertFalse(check(receipt, dict(codec, **{key: False}), cells, [], []))
        for key in receipt["policyData"]:
            changed = deepcopy(receipt); changed["policyData"][key] = False
            with self.subTest(policy=key): self.assertFalse(check(changed, codec, cells, [], []))
        self.assertFalse(check(dict(receipt, policyData={}), codec, cells, [], []))
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
        for calls in ([], receipt["calls"][:1], receipt["calls"][1:], receipt["calls"] * 2,
                      *([row for row in receipt["calls"] if row["role"] != role]
                        for role in ("normal-build", "normal-list", "normal-policy-tests"))):
            self.assertFalse(check(dict(receipt, calls=calls), codec, cells, [], []))
        for index in range(len(receipt["calls"])):
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
        body = aqua_wrapping_source().split("<<'PY_WRAPPING'\n", 1)[1].split("\n          PY_WRAPPING", 1)[0]
        dispatch = body.split('              stage = "codec-target-preparation"', 1)[1].split('              qualification_binary, reader_binary, cohort_binary = None, None, None', 1)[0]
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


class ShippingVaultHelperAquaDataTests(unittest.TestCase):
    """SOURCE/parser/custody DATA, never native Keychain or helper qualification."""

    def test_first_unknown_sample_preserves_partial_null_and_historical_data_without_finality(self):
        good = vault_failure_context_data()
        before = deepcopy(good)
        before["vault"]["snapshot"].update(operationId=None, operationPhase=None, operationReason=None,
                                            operationSettlement=None, state=None, storage=None, initialize=None,
                                            initializeTransport=None)
        historical = deepcopy(good); del historical["vault"]
        for case in M.VAULT_HELPER_CASES:
            for value in (good, before, historical):
                row = project_selection_row(value, "vault-finality-contract", "Vault(Initialized)")
                self.assertEqual(M.failure_context(b"", row, case), value)
                with self.assertRaisesRegex(M.Refused, "^inner-failure-marker$"):
                    M.parse_result(captured(M.expected_result(BINDING, case)), row, BINDING, case)
        for code, signal, count in ((64, None, 0), (0, None, 16385), (255, None, 1),
                                    (None, 9, 8), (None, 127, 32), (None, None, 16384)):
            value = deepcopy(good)
            value["vault"]["snapshot"]["initializeTransport"] = {"exitCode": code, "exitSignal": signal, "responseBytes": count}
            row = project_selection_row(value, "vault-finality-contract", "Vault(Initialized)")
            self.assertEqual(M.failure_context(b"", row, M.VAULT_HELPER_CASES[0]), value)
            with self.assertRaisesRegex(M.Refused, "^inner-failure-marker$"):
                M.parse_result(captured(M.expected_result(BINDING, M.VAULT_HELPER_CASES[0])), row, BINDING, M.VAULT_HELPER_CASES[0])
        # Retain every closed partial outcome, not only provider-success and
        # provider-negative subsets used by successful result parsing.
        provider = (PATH.parents[1] / "src-tauri/src/vault_keyring_macos.rs").read_text()
        for name, field in (("outcome", "addOutcome"), ("problem", "firstFailure")):
            body = provider.split(f"fn {name}(value:", 1)[1].split("} }", 1)[0]
            labels = M.re.findall(r'=>"([a-z-]+)"', body)
            self.assertEqual(len(labels), 18 if name == "outcome" else 12)
            for label in labels:
                value = deepcopy(good); value["vault"]["snapshot"]["initialize"][field] = label
                self.assertEqual(M.failure_context(b"", project_selection_row(value, "vault-finality-contract", "Vault(Initialized)"),
                                                 M.VAULT_HELPER_CASES[0]), value)

    def test_first_unknown_sample_rejects_open_shapes_types_and_invented_partial_facts(self):
        good = vault_failure_context_data()
        variants = []
        for key, bad in (("unknown", False), ("documentUnknown", 1), ("originals", True), ("originals", 8),
                         ("originals", -1), ("operationId", True), ("operationId", 0), ("operationId", 5),
                         ("operationId", None), ("operationPhase", None), ("operationPhase", "PRIVATE"),
                         ("operationReason", "PRIVATE"), ("operationSettlement", "complete"), ("state", "PRIVATE"),
                         ("storage", {"reservation": [True, 1], "header": [False, False], "durability": [False, False]})):
            value = deepcopy(good); value["vault"]["snapshot"][key] = bad; variants.append(value)
        value = deepcopy(good); value["vault"]["snapshot"]["documentUnknown"] = False; variants.append(value)
        for path in (("vault",), ("vault", "snapshot"), ("vault", "snapshot", "initialize"), ("vault", "snapshot", "storage")):
            for missing in (False, True):
                value = deepcopy(good); target = value
                for key in path: target = target[key]
                if missing: del target[next(iter(target))]
                else: target["privatePath"] = "PRIVATE"
                variants.append(value)
        for key, bad in (("go", 1), ("authSettled", 0), ("exitSuccess", "false"), ("pipeClosed", [True, True]),
                         ("pipeClosed", [True, True, 1]), ("addEffect", True), ("addEffect", -1), ("addEffect", 2**32),
                         ("addOutcome", "PRIVATE"), ("firstFailure", "PRIVATE")):
            value = deepcopy(good); value["vault"]["snapshot"]["initialize"][key] = bad; variants.append(value)
        value = deepcopy(good); value["vault"]["snapshot"]["lookup"] = {}; variants.append(value)
        for transport in ({}, [], {"exitCode": None, "exitSignal": None, "responseBytes": 0, "privatePath": "PRIVATE"},
                          {"exitCode": 64, "exitSignal": 9, "responseBytes": 0}):
            value = deepcopy(good); value["vault"]["snapshot"]["initializeTransport"] = transport; variants.append(value)
        for key, bad in (("exitCode", True), ("exitCode", -1), ("exitCode", 256), ("exitCode", "64"),
                         ("exitSignal", False), ("exitSignal", 0), ("exitSignal", 128), ("exitSignal", 9.0),
                         ("responseBytes", None), ("responseBytes", True), ("responseBytes", -1), ("responseBytes", 16386)):
            value = deepcopy(good); value["vault"]["snapshot"]["initializeTransport"][key] = bad; variants.append(value)
        value = deepcopy(good); value["vault"]["snapshot"]["lookupTransport"] = {}; variants.append(value)
        for value in variants:
            with self.subTest(value=value):
                self.assertIsNone(M.failure_context(b"", project_selection_row(value, "vault-finality-contract", "Vault(Initialized)"),
                                                  M.VAULT_HELPER_CASES[0]))

    def test_first_unknown_sample_is_bound_to_the_original_case_step_reason_and_record(self):
        good = vault_failure_context_data()
        for case, reason, step in ((None, "vault-finality-contract", "Vault(Initialized)"),
                                   ("first-save", "vault-finality-contract", "Vault(Initialized)"),
                                   (M.VAULT_HELPER_CASES[0], "observer-deadline", "Vault(Initialized)"),
                                   (M.VAULT_HELPER_CASES[0], "vault-finality-contract", "Vault(Unlocked)"),
                                   (M.VAULT_HELPER_CASES[0], "vault-finality-contract", "ProjectSettled")):
            self.assertIsNone(M.failure_context(b"", project_selection_row(good, reason, step), case))
        for path, bad in ((["snapshotSource"], "prearm-open-progress"), (["snapshotSource"], None),
                          (["vault", "source"], "later-record"), (["vault", "step"], "Vault(Unlocked)"),
                          (["vault", "observationOnly"], 1), (["vault", "snapshot"], None)):
            value = deepcopy(good); target = value
            for key in path[:-1]: target = target[key]
            target[path[-1]] = bad
            self.assertIsNone(M.failure_context(b"", project_selection_row(value, "vault-finality-contract", "Vault(Initialized)"),
                                              M.VAULT_HELPER_CASES[0]))
        row = project_selection_row(good, "vault-finality-contract", "Vault(Initialized)")
        for malformed in (context_row(good), row + context_row(good), row.replace(b'"originals":4', b'"originals":4,"originals":4')):
            self.assertIsNone(M.failure_context(b"", malformed, M.VAULT_HELPER_CASES[0]))

    def test_full_first_unknown_envelope_fits_existing_limits_with_both_helpers_and_picker_facts(self):
        case = M.VAULT_HELPER_CASES[0]
        native = M.expected_result(BINDING, case)["native"]
        value = vault_failure_context_data()
        value.update(nativeHandler={"step": "OpenProject", "entered": True, "returned": True}, nativeAction=None,
                     pending={"kind": "dom", "step": "Vault(Initialized)"},
                     lastPanel={"step": "OpenProject", "id": 1, "kind": "project", "parentPresent": True,
                                "panelPresent": True, "parentReferencesPanel": True, "panelReferencesParent": True,
                                "panelVisible": True, "directoryBound": True, "directoryReturned": True,
                                "directoryReady": True, "directoryReadiness": "ready", "waitLocation": None},
                     originalWindow=native["originalWindow"], accessibility=native["projectOpenInput"],
                     accessibilityBinding=native["projectOpenBinding"], completionSelection=native["projectCompletionSelection"],
                     dom={"evaluations": 160, "lastProjectChooser": {"step": "ChooseProject", "sequence": 160,
                          "dashboardSelected": True, "buttonDisabled": True, "reason": "project-recovery"}})
        snapshot = value["vault"]["snapshot"]
        snapshot.update(originals=7, operationId=7, operationPhase="assessing", operationReason="vault-provider-unsupported",
                        operationSettlement="late-known", state="uninitialized")
        # false is the longest Boolean encoding, including nullable facts;
        # use maximal fixed-width counters and longest original vocabularies.
        helper = M._expected_vault_original("initialize")
        for key, item in list(helper.items()):
            if item is None or type(item) is bool: helper[key] = False
        helper.update(addOutcome="authentication-failed", firstFailure="unsupported-provider", addEffect=2**32-1,
                      pipeClosed=[False, False, False])
        snapshot.update(initialize=helper, lookup=deepcopy(helper),
                        storage={key: [False, False] for key in ("reservation", "header", "durability")})
        for key in ("initializeTransport", "lookupTransport"):
            snapshot[key] = {"exitCode": None, "exitSignal": None, "responseBytes": 16385}
        row = project_selection_row(value, "vault-finality-contract", "Vault(Initialized)")
        self.assertLessEqual(len(json.dumps(value, separators=(",", ":")).encode("ascii")), 8192)
        self.assertLessEqual(len(row), 8448)
        self.assertEqual(M.failure_context(b"", row, case), value)

    def test_unknown_source_keeps_first_winner_sample_and_original_success_gates(self):
        root = PATH.parents[1] / "src-tauri/src"
        vault = (root / "installed_shell_observation_macos_vault.rs").read_text()
        observer = (root / "installed_shell_observation_macos.rs").read_text()
        document = (root / "asset_session.rs").read_text()
        latch = vault.split("fn latch_unknown(", 1)[1].split("#[derive(Default)]", 1)[0]
        self.assertIn('snapshot.unknown && super::latch_failure(first, failed, "vault-finality-contract")', latch)
        self.assertIn("*detail = Some(FailureSample { step, snapshot });", latch)
        tick = vault.split("pub(super) fn vault_tick(", 1)[1].split("if !snapshot.originals_settled", 1)[0]
        order = ("document.installed_macos_vault_snapshot()", "if snapshot.unknown", "self.record.lock()",
                 "if r.step == super::Step::Vault(step)", "&mut r.vault_failure, step, snapshot")
        self.assertEqual([tick.index(v) for v in order], sorted(tick.index(v) for v in order))
        self.assertEqual(tick.count("document.installed_macos_vault_snapshot()"), 1)
        sample = document.split("pub(crate) fn installed_macos_vault_snapshot(", 1)[1].split("fn macos_vault_selected(", 1)[0]
        self.assertEqual(sample.count("state.lifetime.original_bound()"), 1)
        self.assertIn("|| !original_bound", sample)
        self.assertIn("document_unknown:state.unknown,exhausted:state.exhausted,lost_observed:state.lost_observed,original_bound", sample)
        for name in ("initialize", "lookup"):
            pair = sample.split(f"({name}, {name}_transport) = {{", 1)[1].split("};", 1)[0]
            self.assertEqual(pair.count("owner.keyring.try_lock()"), 1)
            self.assertIn("(keyring.qualification_snapshot(), keyring.qualification_transport_snapshot())", pair)
            self.assertNotIn("qualification_storage", pair)
        frame = observer.split("struct FailureSnapshot", 1)[1].split("fn failure_context(", 1)[0]
        self.assertIn("vault: r.vault_failure", frame)
        self.assertIn("self.vault = None;", frame.split("fn at_expiry(", 1)[1].split("fn frame(", 1)[0])
        self.assertIn('reason != "vault-finality-contract"', frame)
        self.assertIn("self.step != Step::Vault(sample.step)", frame)
        self.assertIn("if detail.is_none_or(|s|s.step!=Step::Initialized", vault)
        self.assertIn('super::latch_failure(&first,&failed,"observer-deadline")', vault)
        for forbidden in ("Instant::now", "try_lock", "run_on_main_thread", "thread::spawn"):
            self.assertNotIn(forbidden, latch)

    def test_enabled_candidate_selector_is_reported_honestly_without_native_finality_substitution(self):
        root = PATH.parents[2]
        runtime = (root / "desktop/src-tauri/src/runtime.rs").read_text()
        observer = (root / "desktop/src-tauri/src/installed_shell_observation_macos_vault.rs").read_text()
        self.assertIn("INSTALLED_MAC_PERSISTENCE_QUALIFIED: bool = true;", runtime)
        self.assertIn('"normalPersistenceEnabled":crate::runtime::INSTALLED_MAC_PERSISTENCE_QUALIFIED', observer)
        self.assertIn("if !self.final_originals", observer)
        self.assertIn("!control.completed()", observer)
        for case in M.VAULT_HELPER_CASES:
            for negative in (False, True) if case != M.VAULT_HELPER_CASES[1] else (False,):
                report = M._expected_vault_helper(case, negative=negative)
                self.assertIs(report["normalPersistenceEnabled"], True)
                self.assertEqual(report["mechanism"], "original-document-shipping-helper-v1")
                self.assertEqual(M._vault_helper_report(report, case), report)
                for value in (False, 0, 1, None, "true"):
                    malformed = deepcopy(report); malformed["normalPersistenceEnabled"] = value
                    with self.subTest(case=case, negative=negative, value=value), self.assertRaises(M.Refused):
                        M._vault_helper_report(malformed, case)

    def test_closed_scope_uses_disjoint_real_home_route_and_original_invocation(self):
        self.assertEqual(M.selected_cases(M.VAULT_HELPER_SCOPE), M.VAULT_HELPER_CASES)
        self.assertEqual(M.argument_scope(["--scope", M.VAULT_HELPER_SCOPE]), M.VAULT_HELPER_SCOPE)
        self.assertEqual([M.case_timeout(case) for case in M.VAULT_HELPER_CASES], [135] * 3)
        with self.assertRaises(M.Refused):
            BINDING.root(project_fields=True, vault_helper=True)
        for home in ("/", "relative", "/Users//runner", "/Users/../runner", "/Users/runner/"):
            with self.assertRaises(M.Refused):
                M.vault_fixture_path(BINDING, home, M.VAULT_HELPER_CASES[0])
        home = "/Users/runner"
        path = M.vault_fixture_path(BINDING, home, M.VAULT_HELPER_CASES[0])
        self.assertEqual(path, Path(home) / "Library/Application Support" /
            f"mrk-macos-aqua-vault-{BINDING.source}-{BINDING.run}-{BINDING.attempt}" /
            M.VAULT_HELPER_CASES[0] / "dev.mobile-release-kit.desktop")
        fixtures, emitted, calls = InertFixtures(), [], []
        fixtures.cases = M.VAULT_HELPER_CASES
        def returned(argv, **kwargs):
            case = argv[1]
            self.assertEqual(argv, [M.EXECUTABLE, case])
            state = BINDING.root(vault_helper=True) / "state" / case
            self.assertEqual(kwargs["cwd"], state)
            self.assertEqual(kwargs["timeout"], 135)
            self.assertEqual(kwargs["environ"], M.app_environment(state, UID, "runner"))
            calls.append(case)
            return CompletedProcess(argv, 0, captured(M.expected_result(BINDING, case)), b"")
        result = M.run_cases(BINDING, fixtures, returned, UID, "runner", emitted.append, M.VAULT_HELPER_SCOPE)
        self.assertEqual(result, ())
        self.assertEqual(calls, list(M.VAULT_HELPER_CASES))
        self.assertEqual(fixtures.reads, calls)
        self.assertEqual([row["case"] for row in emitted], calls)

    def test_missing_actual_receipts_and_finality_or_application_consumption_mutations_fail(self):
        for case in M.VAULT_HELPER_CASES:
            report = M.expected_result(BINDING, case)
            self.assertEqual(M.parse_result(captured(report), b"", BINDING, case), report)
            absent = deepcopy(report); del absent["vaultHelper"]
            with self.assertRaises(M.Refused):
                M.parse_result(captured(absent), b"", BINDING, case)
            helper = report["vaultHelper"]["initializeHelper"]
            for field in ("tryWaitEntered", "tryWaitReturned", "exitObserved", "stdoutEof", "stderrEof",
                          "helperSlotsSettled", "driverReturned", "driverBeforeCleanup", "blockingChildJoined",
                          "helperGateAcquired", "helperGateSpawnEntered", "helperGatePostchecked", "helperGateClosed",
                          "resourcesSettled", "allocationsReleased"):
                bad = deepcopy(report); bad["vaultHelper"]["initializeHelper"][field] = False
                with self.subTest(case=case, field=field), self.assertRaises(M.Refused):
                    M.parse_result(captured(bad), b"", BINDING, case)
            for field in ("waitEntered", "waitFailed", "killAttempted", "killFailed", "cleanupUnknown", "helperGateUnknown", "outputFailed", "stderrSeen"):
                bad = deepcopy(report); bad["vaultHelper"]["initializeHelper"][field] = True
                with self.subTest(case=case, field=field), self.assertRaises(M.Refused):
                    M.parse_result(captured(bad), b"", BINDING, case)
            for index in range(3):
                bad = deepcopy(report); bad["vaultHelper"]["initializeHelper"]["pipeClosed"][index] = False
                with self.assertRaises(M.Refused):
                    M.parse_result(captured(bad), b"", BINDING, case)
            for field in ("allOriginalsSettled", "finalDocumentEmpty", "previewConsumedOnce"):
                bad = deepcopy(report); bad["vaultHelper"][field] = False
                with self.assertRaises(M.Refused):
                    M.parse_result(captured(bad), b"", BINDING, case)
            if case != M.VAULT_HELPER_CASES[0]:
                for field in ("applicationCandidateConstructed", "applicationCandidateTaken", "applicationCallbackReturned"):
                    bad = deepcopy(report); bad["vaultHelper"]["initializeHelper"][field] = True
                    with self.assertRaises(M.Refused):
                        M.parse_result(captured(bad), b"", BINDING, case)
                bad = deepcopy(report); bad["vaultHelper"]["storage"]["header"] = [True, True]
                with self.assertRaises(M.Refused):
                    M.parse_result(captured(bad), b"", BINDING, case)
            self.assertIs(type(helper["tryWaitEntered"]), bool)

    def test_preadd_refusal_is_not_executed_not_a_fake_positive_and_other_cases_continue(self):
        fixtures, emitted = InertFixtures(), []
        fixtures.cases = M.VAULT_HELPER_CASES
        def returned(argv, **_):
            case = argv[1]; report = M.expected_result(BINDING, case)
            if case != M.VAULT_HELPER_CASES[1]:
                report["vaultHelper"] = M._expected_vault_helper(case, negative=True)
            return CompletedProcess(argv, 0, captured(report), b"")
        result = M.run_cases(BINDING, fixtures, returned, UID, "runner", emitted.append, M.VAULT_HELPER_SCOPE)
        self.assertEqual(result, (M.VAULT_HELPER_CASES[0], M.VAULT_HELPER_CASES[2]))
        self.assertEqual(fixtures.reads, list(M.VAULT_HELPER_CASES))
        self.assertEqual([row["observer"]["vaultHelper"]["testResult"] for row in emitted],
                         ["not-executed", "expected-stop", "not-executed"])
        report = M._expected_vault_helper(M.VAULT_HELPER_CASES[2], negative=True)
        for field, value in (("addEffect", 3), ("addItemCallsAbsent", False), ("addPrerequisiteRefused", False),
                             ("nativeCandidateConsumed", True), ("lookupSettled", True), ("addSettled", None)):
            bad = deepcopy(report); bad["initializeHelper"][field] = value
            with self.subTest(field=field), self.assertRaises(M.Refused):
                M._vault_helper_report(bad, M.VAULT_HELPER_CASES[2])
        bad = deepcopy(report); bad["testResult"] = "expected-stop"
        with self.assertRaises(M.Refused):
            M._vault_helper_report(bad, M.VAULT_HELPER_CASES[2])
        source = PATH.read_text()
        self.assertIn("return 2 if not_executed else 0", source)
        self.assertIn("focusedCasesPassed=not not_executed", source)

    def test_native_parent_preparation_refuses_collisions_and_unsafe_ancestry_without_repair(self):
        # No real home/account file is touched: only fixed fake namespace DATA.
        native = SimpleNamespace(pw_uid=UID, pw_dir="/Users/runner")
        safe = SimpleNamespace(st_dev=7, st_ino=100, st_mode=stat.S_IFDIR | 0o755,
            st_uid=UID, st_gid=GID, st_nlink=2, st_size=4096, st_mtime_ns=1, st_ctime_ns=1)
        fixtures = M.Fixtures(BINDING, UID, GID, M.VAULT_HELPER_SCOPE)
        with patch("pwd.getpwuid", return_value=native), patch.object(fixtures, "_open", return_value=50), \
             patch.object(M.os, "fstat", return_value=safe), patch.object(M.os, "stat", return_value=safe), \
             patch.object(fixtures, "_mkdir", side_effect=FileExistsError("occupied")) as mkdir:
            with self.assertRaises(FileExistsError):
                fixtures._prepare_vault_parents()
            self.assertEqual(mkdir.call_count, 1)
            self.assertEqual(mkdir.call_args.args[1], f"mrk-macos-aqua-vault-{BINDING.source}-{BINDING.run}-{BINDING.attempt}")
        unsafe = SimpleNamespace(**{**vars(safe), "st_mode": stat.S_IFDIR | 0o777})
        fixtures = M.Fixtures(BINDING, UID, GID, M.VAULT_HELPER_SCOPE)
        with patch("pwd.getpwuid", return_value=native), patch.object(fixtures, "_open", return_value=50), \
             patch.object(M.os, "fstat", return_value=unsafe), patch.object(M.os, "stat", return_value=unsafe), \
             patch.object(fixtures, "_mkdir") as mkdir:
            with self.assertRaises(M.Refused):
                fixtures._prepare_vault_parents()
            mkdir.assert_not_called()

    def test_private_output_accounting_is_bounded_and_refuses_links_modes_and_unexpected_files(self):
        # Disposable DATA files: no encrypted vault/provider/native qualification.
        for mutation in (None, "size", "mode", "link", "extra"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="mrk-vault-readback-data-") as temporary:
                root = Path(temporary); case = M.VAULT_HELPER_CASES[0]
                (root / case / "dev.mobile-release-kit.desktop" / "credential-vault-v1").mkdir(parents=True)
                parent = root / case; app = parent / "dev.mobile-release-kit.desktop"; vault = app / "credential-vault-v1"
                for path in (parent, app, vault): path.chmod(0o700)
                for name, length in (("vault-lock", 0), ("initialization-reservation", 48), ("vault-header", 104)):
                    (vault / name).write_bytes(b"x" * length); (vault / name).chmod(0o600)
                if mutation == "size": (vault / "vault-header").write_bytes(b"x" * 105)
                if mutation == "mode": (vault / "initialization-reservation").chmod(0o644)
                if mutation == "link":
                    (vault / "initialization-reservation").unlink()
                    (vault / "initialization-reservation").symlink_to("vault-header")
                if mutation == "extra": (vault / "unrelated").write_bytes(b"not admitted")
                fixtures = M.Fixtures(BINDING, M.os.getuid(), M.os.getgid(), M.VAULT_HELPER_SCOPE)
                fixtures.vault_namespace = fixtures._open(str(root), directory=True)
                fixtures.vault_parents[case] = fixtures._open(case, fixtures.vault_namespace, directory=True)
                fixtures.last_returned = True
                try:
                    with patch.object(fixtures, "readback", return_value={"sourceUnchanged": True}), \
                         patch.object(fixtures, "_vault_namespace_current") as ancestry:
                        if mutation is not None:
                            with self.assertRaises((M.Refused, OSError)):
                                fixtures.readback_vault(case, M._expected_vault_helper(case))
                        else:
                            result = fixtures.readback_vault(case, M._expected_vault_helper(case))
                            self.assertEqual(result["vaultOutput"]["retainedPrivateBytes"], 152)
                            self.assertEqual(result["vaultOutput"]["controlFileCount"], 3)
                            self.assertFalse(result["vaultOutput"]["privateContentsExported"])
                            ancestry.assert_called_once_with()
                            with self.assertRaises(M.Refused):
                                fixtures.readback_vault(case, M._expected_vault_helper(case))
                finally:
                    fixtures.close()
                self.assertFalse(fixtures.fds)

    def test_workflow_adds_only_closed_support_and_keeps_default_matrix_and_helper_graph(self):
        root = PATH.parents[2]
        workflow = (root / ".github/workflows/desktop-macos-aqua.yml").read_text()
        header = workflow.split("    steps:\n", 1)[0]
        self.assertIn("    permissions:\n      contents: read\n      actions: read\n", header)
        self.assertIn(
            "        include:\n          - scope: local-edits3\n            target: aarch64-apple-darwin\n            runner: macos-26\n            supplier_receipt: '2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d'\n            supplier_tar: 'ff7883185cf8226e9366b1ee9a3dcb3eb8ee761dbc1f697f952510a6bd858695'\n            supplier_source: '158cdff422e3837f7ab5e6192af76a578faf6fab'\n            supplier_run: '37467019389'\n            supplier_attempt: '1'\n            supplier_artifact: '11415902210'\n          - scope: local-edits3\n            target: x86_64-apple-darwin\n            runner: macos-26-intel\n            supplier_receipt: 'a46f6838afdb7c20c3539e8f65891312aa8df10e2de67e9b9e3ddbf449883b4b'\n            supplier_tar: '739cc8b8b3c68daffba8d7b9cb7cb54ca730eef2c5842302ae8a2682bf64d5bd'\n            supplier_source: '079ab2a2c8fef88f01bf909e7669c685f07e1375'\n            supplier_run: '37476532238'\n            supplier_attempt: '1'\n            supplier_artifact: '11419502465'\n    runs-on: ${{ matrix.runner }}\n", header)
        self.assertNotIn("          - vault-helper-shipping-installation-inspection\n", header)
        blocks = dict(block.split("\n", 1) for block in workflow.split("      - name: ")[1:])
        run = blocks["Three serial shipping-helper journeys through the original document and invocation owner"]
        self.assertIn("if: success() && (env.MRK_MACOS_AQUA_SCOPE == 'vault-helper-shipping' || env.MRK_MACOS_AQUA_SCOPE == 'vault-helper-shipping-installation-inspection')", run)
        self.assertEqual(run.count("macos_aqua_qualification.py --scope vault-helper-shipping"), 1)
        self.assertIn("[[ $status == 0 ]]", run)
        for forbidden in ("security unlock", "create-keychain", "default-keychain", "list-keychains", "continue-on-error"):
            self.assertNotIn(forbidden, run)
        self.assertIn("aqua-vault-helper-results.jsonl", workflow)
        self.assertNotIn("mrk-macos-aqua-vault-*", workflow)
        driver = (root / "desktop/src-tauri/src/asset_session_keyring_macos.rs").read_text()
        checkpoint = driver.index("Checkpoint::SuccessfulAddTerminal")
        self.assertLess(checkpoint, driver.index("if done{break;}", checkpoint))
        provider = (root / "desktop/src-tauri/src/vault_keyring_macos.rs").read_text()
        self.assertIn("self.terminal.as_ref().is_some_and(|t|t.valid && t.input_closed)", provider)
        self.assertIn("fn only_valid_decoded_terminal_input_retirement_suppresses_stop_control", provider)
        vault = (root / "desktop/src-tauri/src/asset_session_vault.rs").read_text()
        self.assertTrue("DURABLE_QUALIFIED: bool = false" in vault,
                        "the global durable-storage gate must remain disabled")
        self.assertTrue("Qualification::Ordinary => self.persistence_qualified()," in vault,
                        "ordinary storage must use the current document qualification")
        self.assertTrue("DURABLE_QUALIFIED || document.inner.bridge.installed_persistence_available(&document.inner.session_identity)" in vault,
                        "installed storage qualification must remain bound to the original session")
        self.assertTrue("self.gate(state, false)?;" in vault,
                        "durable operations must retain the ordinary document gate")


class AndroidRegistrationLifecycleWorkflowTests(unittest.TestCase):
    @staticmethod
    def source():
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        blocks = dict(block.split("\n", 1) for block in workflow.split("      - name: ")[1:])
        headless = aqua_headless_source()
        body = headless.split("<<'PY_HEADLESS'\n", 1)[1].split("          PY_HEADLESS", 1)[0]
        return workflow, blocks, headless, ast.parse("\n".join(line[10:] for line in body.splitlines()))

    def test_exact_twelve_route_excludes_app_suppliers_and_preserves_original_test_results(self):
        workflow, blocks, headless, tree = self.source()
        actual_source = workflow + aqua_headless_source() + aqua_wrapping_source()
        selected = next(node for node in tree.body if isinstance(node, ast.If)
                        and isinstance(node.test, ast.Name) and node.test.id == "android_lifecycle"
                        and any(isinstance(child, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "names"
                                for t in child.targets) for child in node.body))
        values = {target.id: ast.literal_eval(node.value) for node in selected.body if isinstance(node, ast.Assign)
                  for target in node.targets if isinstance(target, ast.Name) and target.id in ("names", "native_names")}
        self.assertEqual(values["names"], (
            "saved_command_owner::android_registration::service_setup::callback_lifecycle_tests::callback_stamp_needs_exclusive_capture_return_then_original_owner_finality",
            "saved_command_owner::android_registration::service_setup::callback_lifecycle_tests::deferred_reuses_only_same_private_owner_action_serial_and_unadmitted_cell",
            "saved_command_owner::android_registration::service_setup::callback_lifecycle_tests::main_gate_only_defers_at_admission_and_preserves_actual_f_on_short_lock_contention",
            "saved_command_owner::android_registration::service_setup::callback_lifecycle_tests::register_observation_failure_is_at_real_return_and_stop_keeps_original_deadlines",
            "saved_command_owner::android_registration::client::tests::enqueued_busy_and_processed_are_distinct_and_finish_never_precedes_its_ack",
            "saved_command_owner::android_registration::client::tests::ack_rejects_wrong_account_nonce_sequence_payload_and_earlier_failure",
            "saved_command_owner::android_registration::client::tests::same_original_ready_reproof_and_current_gates_precede_transfer",
            "saved_command_owner::android_registration::client::tests::mismatched_reproof_lost_go_and_earlier_failure_close_original_barriers",
            "saved_command_owner::android_registration::client::tests::finish_requires_the_actual_source_handle_consumption_not_worker_return",
            "saved_command_owner::android_registration::client::tests::go_loss_and_peer_failure_still_run_preparation_and_independent_native_release",
            "saved_command_owner::android_registration::client::tests::native_clock_preserves_bidirectional_earliest_f_without_echo_or_renewal",
        ))
        self.assertEqual(values["native_names"], (
            "android_registration::tests::never_started_client_retires_its_actual_signal_without_arming_or_native_entry",
        ))
        self.assertEqual(len(set(values["names"] + values["native_names"])), 12)
        for text in ('main_count, native_count = 11, 1', 'main_count, native_count = 25, 2',
                     '"--jobs", "1"', '"--lib", "--no-run", "--message-format=json"',
                     'timeout=480', 'output_limit=4 * 1024 * 1024',
                     'calls_entered == calls_returned == 3', 'if android_lifecycle and not receipt["passed"]',
                     'len(expected_rows) != count', 'set(lines[1:-1]) != expected_rows',
                     '0 failed; 0 ignored; 0 measured;', 'shutil.rmtree.avoids_symlink_attacks',
                     'os.mkdir("cargo-target", 0o700, dir_fd=work_fd)',
                     'shutil.rmtree("cargo-target", dir_fd=work_fd)', 'target_fd = work_fd = None'):
            self.assertIn(text, headless)
        self.assertLess(headless.index('calls_entered += 1'), headless.index('compiler = owner.run_owned('))
        self.assertEqual(headless.count('compiler = owner.run_owned('), 1)
        self.assertEqual(headless.count('receipt["compilerOriginalReturned"] = True'), 1)
        compiler_start = headless.index('compiler = owner.run_owned(')
        compiler_end = headless.index('receipt["compilerOriginalReturned"] = True', compiler_start)
        compiler_span = headless[compiler_start:compiler_end]
        self.assertEqual(compiler_span.count('headless-original-compiler-return-contract'), 1)
        self.assertEqual(compiler_span.count('calls_returned += 1'), 1)
        self.assertLess(compiler_span.index('headless-original-compiler-return-contract'),
                        compiler_span.index('calls_returned += 1'))
        self.assertLess(headless.index('os.close(descriptor)'), headless.index('shutil.rmtree("cargo-target"'))
        for name in ("Select fixed frontend compiler", "Record exact source and actual tool bindings only after route admission",
                     "Check current owner pins before native preparation", "Fail fast on native Scripts ownership and package format (never Installer)",
                     "Acquire and verify the two fixed Android support archives as DATA",
                     "Select the fixed configured signed runtime before any payload download",
                     "Download only the configured signed Python capsule",
                     "Project the configured capsule as DATA without executing it",
                     "Admit only a fresh independently pinned Python transport destination",
                     "Download the independently accepted fresh Python transport",
                     "Project the pinned fresh Python transport without executing it",
                     "Prepare the current payload from the independently accepted fresh Python supplier",
                     "Build and sign the separate fixed vault helper before binding the app",
                     "Compile the fixed debug actual-main observer and normal embedded frontend once",
                     "Application installation uses only standard privileged Installer; app and Python stay nonroot",
                     "Compile native wrapping variants once and run fixed cohorts and creator-reader pair",
                     "Verify source stayed unchanged; retire only disposable owned build output"):
            gate = next(line for line in blocks[name].splitlines() if line.startswith("        if:"))
            self.assertNotIn("android-registration-lifecycle", gate)
        export = blocks["Export bounded diagnostics without altering original command evidence"]
        self.assertIn('if aqua_scope == "android-registration-lifecycle": streams = streams[:2]', export)
        upload = blocks["Preserve bounded Android lifecycle results and original workflow exit evidence"]
        paths = [line.strip().split("/", 1)[1] for line in upload.splitlines() if "${{ steps.work.outputs.root }}/" in line]
        self.assertEqual(paths, ["source-inventory.json", "headless-build.admitted.jsonl", "headless-build.stderr.tail.txt", "headless-build.status",
            "headless-tests.stdout", "headless-tests.stderr", "headless-tests.status", "headless-native-tests.stdout",
            "headless-native-tests.stderr", "headless-native-tests.status", "headless-tests.receipt.json", "bounded-diagnostics.json"])
        self.assertIn("if-no-files-found: error", upload)
        for forbidden in ("workflow_dispatch", "continue-on-error: true"):
            self.assertNotIn(forbidden, actual_source)
        compiler_argv = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                             and any(isinstance(target, ast.Name) and target.id == "compiler_argv" for target in node.targets))
        expected_argv = ast.parse('[rust_bin + "/cargo", "test", "--locked", "--no-default-features", "--jobs", "1",'
                                  '"--target", build_target, "--package", "mobile-release-kit-desktop",'
                                  '"--package", "mrk-macos-installed-native", "--lib", "--no-run", "--message-format=json"]', mode="eval").body
        self.assertEqual(ast.dump(compiler_argv.value, include_attributes=False), ast.dump(expected_argv, include_attributes=False))
        self.assertNotIn("--features", [node.value for node in compiler_argv.value.elts if isinstance(node, ast.Constant)])
        feature_branches = [node for node in ast.walk(tree) if isinstance(node, ast.If)
                            and any(isinstance(child, ast.AugAssign) and isinstance(child.target, ast.Name)
                                    and child.target.id == "compiler_argv" for child in node.body)]
        self.assertEqual(len(feature_branches), 1)
        self.assertIsInstance(feature_branches[0].test, ast.Name)
        self.assertEqual(feature_branches[0].test.id, "shipping_gate")
        for forbidden in ("npm", "codesign", "installer", "run_cases("):
            self.assertNotIn(forbidden, headless)

        self.assertNotIn("MRK_MACOS_DEVELOPER_ID_", headless + upload)
        for body in blocks.values():
            if "secrets.MRK_MACOS_DEVELOPER_ID_" in body:
                gate = next(line for line in body.splitlines() if line.startswith("        if:"))
                self.assertNotIn("android-registration-lifecycle", gate)
        environment_line = next(line for line in workflow.splitlines() if line.startswith("    environment: "))
        self.assertNotIn("android-registration-lifecycle", environment_line)
        self.assertTrue(environment_line.endswith("|| 'macos-engineering' }}"))

    def test_actual_finalizer_needs_all_owned_returns_and_keeps_each_cleanup_failure(self):
        # Execute ONLY the actual finally statements and pure directory shape
        # function against private DATA facades. No real FD/filesystem/owner,
        # compiler, process, native action, receipt or directory is produced.
        _, _, _, tree = self.source()
        final = next(node for node in tree.body if isinstance(node, ast.Try) and node.finalbody)
        directory = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "directory_identity")
        body = ast.Module(body=[deepcopy(directory), *deepcopy(final.finalbody)], type_ignores=[])
        self.assertFalse(any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(body)))
        code = compile(ast.fix_missing_locations(body), "<original-headless-finalizer-DATA>", "exec")
        for case in ("pass", "owner-unknown", "returned-compiler-failure", "artifact-close-failure",
                     "target-collision", "cleanup-failure", "directory-close-failure"):
            with self.subTest(case=case):
                events, publications, retired = [], [], [False]
                root_info = SimpleNamespace(st_dev=7, st_ino=101, st_mode=stat.S_IFDIR | 0o700, st_uid=501, st_gid=20)
                target_info = SimpleNamespace(st_dev=7, st_ino=102, st_mode=stat.S_IFDIR | 0o700, st_uid=501, st_gid=20)
                collision = SimpleNamespace(st_dev=7, st_ino=999, st_mode=stat.S_IFDIR | 0o700, st_uid=501, st_gid=20)
                def close(fd):
                    self.assertIn(fd, (17, 18, 19, 20)); events.append(("close", fd))
                    if (case == "artifact-close-failure" and fd == 17
                            or case == "directory-close-failure" and fd == 20): raise OSError("injected DATA close")
                def lookup(name, *, dir_fd, follow_symlinks):
                    self.assertEqual((name, dir_fd, follow_symlinks), ("cargo-target", 19, False))
                    if retired[0]: raise FileNotFoundError("retired DATA name")
                    return collision if case == "target-collision" else target_info
                def remove(name, *, dir_fd):
                    self.assertEqual((name, dir_fd), ("cargo-target", 19)); events.append(("remove", name))
                    if case == "cleanup-failure": raise OSError("injected DATA cleanup")
                    retired[0] = True
                def publish(name, raw):
                    self.assertEqual(name, "headless-tests.receipt.json"); publications.append(json.loads(raw))
                targets = [] if case in ("owner-unknown", "returned-compiler-failure") else [
                    {"role": role, "originalReturned": True, "artifactOriginalUnchanged": True,
                     "artifactOriginalClosed": False, "testsPassed": True} for role in ("main", "native")]
                receipt = {"targets": targets, "compilerOriginalReturned": case != "owner-unknown",
                           "cargoTargetRetired": False, "cargoTargetOriginalClosed": False, "workOriginalClosed": False}
                if not targets: receipt["failure"] = {"stage": "original-compiler", "type": "DataFailure"}
                originals = [{"fd": fd, "record": record} for fd, record in zip((17, 18), targets)]
                namespace = {"__builtins__": {"ValueError": ValueError, "BaseException": BaseException,
                        "FileNotFoundError": FileNotFoundError, "type": type, "len": len, "all": all},
                    "os": SimpleNamespace(getuid=lambda: 501, getgid=lambda: 20, close=close,
                        fstat=lambda fd: root_info if fd == 19 else target_info, stat=lookup),
                    "shutil": SimpleNamespace(rmtree=remove), "stat": stat, "json": json,
                    "work": SimpleNamespace(lstat=lambda: root_info), "work_fd": 19, "target_fd": 20,
                    "work_original": (7, 101, root_info.st_mode, 501, 20), "target_original": (7, 102, target_info.st_mode, 501, 20),
                    "android_lifecycle": True, "owned_headless": True, "shipping_gate": False,
                    "calls_entered": 1 if not targets else 3,
                    "calls_returned": 0 if case == "owner-unknown" else 1 if not targets else 3,
                    "receipt": receipt, "originals": originals, "cleanup_errors": [], "publish": publish,
                    "names": tuple(range(11)), "native_names": (0,)}
                raised = None
                try: exec(code, namespace)
                except ValueError as error: raised = error
                self.assertEqual(len(publications), 1)
                result = publications[0]
                self.assertEqual(result["passed"], case == "pass")
                self.assertEqual(result["cargoTargetRetired"], case in ("pass", "returned-compiler-failure", "directory-close-failure"))
                self.assertEqual(len([event for event in events if event == ("close", 19)]), 1)
                self.assertEqual(len([event for event in events if event == ("close", 20)]), 1)
                for original in originals:
                    self.assertIsNone(original["fd"])
                if case in ("owner-unknown", "artifact-close-failure", "target-collision"):
                    self.assertFalse(any(event[0] == "remove" for event in events))
                if case == "pass":
                    self.assertIsNone(raised); self.assertEqual(result["tests"], 12)
                    self.assertEqual(events, [("close", 17), ("close", 18), ("remove", "cargo-target"), ("close", 20), ("close", 19)])
                elif case == "artifact-close-failure":
                    self.assertEqual(result["closeErrors"], [{"role": "main", "type": "OSError"}]); self.assertIsNotNone(raised)
                elif case in ("target-collision", "cleanup-failure", "directory-close-failure"):
                    self.assertEqual(len(result["cleanupErrors"]), 1); self.assertIsNotNone(raised)
                else:
                    self.assertIn("failure", result); self.assertIsNone(raised)


def shipping_gate_libtest_data(names, filtered=19):
    """Inert libtest-shaped bytes, never a native result or evidence file."""
    count = len(names)
    return (f"\nrunning {count} " + ("test" if count == 1 else "tests") + "\n"
            + "\n".join("test " + name + " ... ok" for name in names)
            + f"\n\ntest result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; {filtered} filtered out; finished in 0.01s\n\n").encode()


def shipping_gate_headless_data(binding=BINDING):
    checkout = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
    work = Path("/Users/runner/work/_temp/mrk-macos-aqua.ABCDE123")
    receipt = {"schemaVersion": 1, "scope": M.SHIPPING_GATE_DATA_SCOPE, "source": binding.source,
        "workflowSource": binding.source, "workflow": M.WORKFLOW, "runId": binding.run, "runAttempt": binding.attempt,
        "names": list(M.SHIPPING_GATE_MAIN_TESTS + M.SHIPPING_GATE_NATIVE_TESTS), "targets": [],
        "originalReturned": True, "artifactOriginalUnchanged": True, "artifactOriginalClosed": True,
        "passed": True, "shippingBinaryQualified": False, "distributionQualified": False,
        "compilerOriginalReturned": True, "cargoTargetRetired": False, "cargoTargetOriginalClosed": True,
        "workOriginalClosed": True, "genuineServiceQualified": False, "protectedCopyQualified": False,
        "compilerArgv": M.shipping_gate_compiler_argv(binding.target), "ownerCallsEntered": 3, "ownerCallsReturned": 3,
        "headlessCustodyRetained": False, "cargoTargetRetentionReason": "required-follow-on-build-and-gate-control",
        "cargoTargetOriginal": ["7", "101", str(stat.S_IFDIR | 0o700), str(UID), str(GID)],
        "workOriginal": ["7", "100", str(stat.S_IFDIR | 0o700), str(UID), str(GID)],
        "tests": 13, "failed": 0, "ignored": 0, "measured": 0}
    bodies, rows = {"headless-build.status": b"0\n"}, []
    selected = (("main", "desktop/src-tauri", "mobile-release-kit-desktop", "mobile_release_desktop", [], M.SHIPPING_GATE_MAIN_TESTS, "headless"),
        ("native", "desktop/native/macos-installed-native", "mrk-macos-installed-native", "mrk_macos_installed_native",
         ["default", "installed-observation"], M.SHIPPING_GATE_NATIVE_TESTS, "headless-native"))
    for index, (role, directory, package, library, features, names, prefix) in enumerate(selected):
        path = str(work / "cargo-target" / binding.target / "debug/deps" / (library + "-123abc"))
        package_id = "path+" + (checkout / directory).as_uri() + "#" + package + ("@0.1.1" if package == "mobile-release-kit-desktop" else "@0.1.0")
        # Deliberately beyond binary64 exact precision; only integers/strings.
        identity = (7, 2**60 + index + 1, stat.S_IFREG | 0o700, UID, GID, 1, 3, 2**60 + 3, 2**60 + 4)
        artifact = {"path": path, "sha256": M.digest(b"abc"), "full9": [str(v) for v in identity],
                    "identity": [identity[0], identity[1], identity[2], identity[5], identity[3], identity[4], *identity[6:]]}
        stdout = shipping_gate_libtest_data(names)
        receipt["targets"].append({"role": role, "packageId": package_id, "features": features, "names": list(names),
            "originalReturned": True, "artifactOriginalUnchanged": True, "artifactOriginalClosed": True, "testsPassed": True,
            "artifact": artifact, "returncode": 0, "stdoutSha256": M.digest(stdout), "stderrSha256": M.digest(b""),
            "tests": len(names), "failed": 0, "ignored": 0, "measured": 0, "filtered": 19})
        bodies.update({prefix + "-tests.stdout": stdout, prefix + "-tests.stderr": b"", prefix + "-tests.status": b"0\n"})
        rows.append({"reason": "compiler-artifact", "package_id": package_id, "manifest_path": str(checkout / directory / "Cargo.toml"),
            "features": features, "profile": {"test": True}, "executable": path,
            "target": {"name": library, "kind": ["lib"], "crate_types": ["lib"], "src_path": str(checkout / directory / "src/lib.rs")}})
    rows.append({"reason": "build-finished", "success": True})
    bodies["headless-build.jsonl"] = b"".join(json.dumps(row).encode() + b"\n" for row in rows)
    receipt["compilerJsonSha256"] = M.digest(bodies["headless-build.jsonl"])
    bodies["headless-tests.receipt.json"] = json.dumps(receipt).encode()
    return checkout, work, bodies, receipt, rows


@contextmanager
def shipping_gate_stager_data():
    """Real current SOURCE parser import, never installed/native readback."""
    previous = dict(sys.modules)
    name = "_mrk_shipping_gate_parser_data"
    if name in previous:
        raise AssertionError("inert stager fixture already imported")
    try:
        with patch.dict(sys.modules):
            path = PATH.with_name("stage_macos_installed.py")
            spec = importlib.util.spec_from_file_location(name, path)
            stage = importlib.util.module_from_spec(spec)
            sys.modules[name] = stage
            spec.loader.exec_module(stage)
            yield stage
    finally:
        if set(sys.modules) != set(previous) or any(sys.modules[key] is not module for key, module in previous.items()):
            raise AssertionError("real stager fixture module originals not restored")


def shipping_gate_installation_data(stage, binding=BINDING, *, action="fresh-install", retained=0):
    """Synthetic schema2 DATA for the real parser; no signature/history witness."""
    target = M.target_data(binding.target)
    body = (PATH.parents[1] / "macos-installed-inputs" / target["releaseInput"]).read_bytes()
    release = stage.build_release_data(body, target=binding.target)
    selection = stage.BuildSelection(binding.target, release["packageVersion"], release["release"])
    environment = {"MRK_MACOS_INSTALL_INVENTORY_SHA256": "b" * 64, "MRK_BUNDLED_RUNTIME_MANIFEST_SHA256": "c" * 64}
    # Accepted PolicyWire field order, but no Keychain/credential/native action.
    policy = {"schemaVersion": 1, "kind": "mrk-macos-developer-id-code-policy-v1", "teamIdentifier": "AB12CD34EF",
        "leafCertificateSha1": "a" * 40, "leafCertificateSha256": "b" * 64, "hardenedRuntime": True, "entitlements": "empty"}
    policy_sha = M.digest(json.dumps(policy, separators=(",", ":")).encode())
    current = {"profile": "fixed-macos26-" + ("arm64" if binding.target == M.ARM_TARGET else "x86_64") + "-maintenance-v2",
        "packageIdentifier": stage.PACKAGE_ID, "bundleIdentifier": stage.BUNDLE_ID,
        "packageVersion": selection.package_version, "release": selection.release, "sourceCommit": binding.source,
        "protocolSha256": stage.CURRENT_PROTOCOL, "runtimeManifestSha256": "c" * 64, "inventorySha256": "b" * 64,
        "signingPolicySha256": policy_sha, "packageSha256": "d" * 64}
    old = [{**current, "packageVersion": "0.0." + str(i + 1), "release": target["releasePrefix"] + "retained-" + str(i + 1),
            "sourceCommit": "f" * 40, "packageSha256": format(i + 1, "064x")} for i in range(retained)]
    producer = {"schemaVersion": 2, "kind": "mrk-macos-install-producer-v2", "domain": "MobileReleaseKit-package-producer-v2",
        "target": binding.target, "releaseSet": {"schemaVersion": 2, "current": current, "acceptedPredecessors": old},
        "signingPolicies": [{"sha256": policy_sha, "policy": policy}]}
    descriptor = stage.canonical(producer) + b"\n"
    request, invocation = "1" * 32, "2" * 32
    states = {"fresh-install": "installed", "update": "installed", "same-package-noop": "same-package", "restore-fixed-app": "restored-app"}
    original = {"schemaVersion": 2, "kind": "maintenance-parent-pending-finalization", "invocation": invocation,
        "requestId": request, "resultName": "MobileReleaseKit-InstallerResult-v2-" + request + ".json",
        "resultFinality": "pending-own-write-readback-close-and-outer-return", "action": action, "writerState": states[action],
        "writerExit": 0, "intentSha256": "5" * 64, "stateSha256": "6" * 64, "capsuleSha256": "7" * 64,
        "payloadWriteCount": 0 if action == "same-package-noop" else 4,
        "payloadWriteBytes": 0 if action == "same-package-noop" else 4096, "originalWriterJoined": True,
        "parentFinality": "pending-original-closes-and-outer-return", "retainedGate": "parent-command-reference-until-kernel-exit",
        "historicalOuterExit": "unverified"}
    # Deliberately different from canonical semantic reserialization; the gate
    # must keep original export bytes/hash as separately reported readback DATA.
    raw_export = json.dumps(original, indent=2).encode() + b"\n"
    metadata = []
    for index, generation in enumerate((current, *old)):
        descriptor_bytes = len(descriptor) if index == 0 else 512
        metadata.append({"release": generation["release"], "instance": (invocation if action in ("fresh-install", "update") else "3" * 32)
            if index == 0 else format(index + 16, "032x"), "inventoryBytes": 64, "descriptorBytes": 32,
            "producerDescriptorBytes": descriptor_bytes, "producerSignatureBytes": 256,
            "verifiedCurrentFiles": 4 if index == 0 else 0, "declaredPayloadFiles": 4,
            "declaredBytes": 64 + 32 + descriptor_bytes + 256 + 100, "historicalOuterExit": "unverified"})
    value = {"schemaVersion": 2, "sourceCommit": binding.source, "inventorySha256": "b" * 64,
        "runtimeManifestSha256": "c" * 64, "completedPackageSha256": "d" * 64, "release": selection.release,
        "requestId": request, "invocation": invocation, "originalInstallerReturnedZero": True, "originalWriterJoined": True,
        "nonrootReadbackFileCount": 4, "originalInstallerResult": original,
        "installerResultExport": {"bytes": len(raw_export), "sha256": M.digest(raw_export),
            "identity": [7, 2**60 + 1, stat.S_IFREG | 0o444, 1, 0, 0, len(raw_export), 2**60 + 2, 2**60 + 3],
            "finalityBasis": "original-successful-Installer-return-and-checked-readback"},
        "installationMetadata": metadata,
        "maintenanceGate": {"state": "protected-permanent-gate-data-correspondence", "bytes": len(stage.MAINTENANCE_GATE_BYTES),
                            "exclusionObserved": False, "workerFinalityEstablished": False},
        "producerSignatureAuthority": "native-parent-and-application-checks-separate", "historicalOuterExit": "unverified",
        "applicationLaunched": False, "guiSaveQualified": False, "aquaGate": "required-separate-actual-session",
        "qualification": "engineering-install-observed-not-runtime-or-GUI-acceptance"}
    summary = {"schemaVersion": 1, "kind": "mrk-package-producer-emitted", "packageSha256": "d" * 64,
        "descriptorSha256": M.digest(descriptor), "signatureSha256": "e" * 64, "descriptorBytes": len(descriptor), "signatureBytes": 256}
    receipt = {"schemaVersion": 1, "phase": "package-install", "target": binding.target, "source": binding.source,
        "workflowSource": binding.source, "workflow": M.WORKFLOW, "runId": binding.run, "runAttempt": binding.attempt,
        "packageRole": "installed-shell-observation",
        "toolchain": {"aarch64-apple-darwin": "1.98.1", "x86_64-apple-darwin": "1.98.0"}[binding.target], "helperIdentifier": "dev.mobile-release-kit.desktop.android-register",
        "passed": True, "originalClosesKnown": True, "targetRetired": True, "outerFinalityRequired": True,
        "directStagerIOPending": None, "cleanupErrors": [], "androidServiceAuthenticated": False,
        "androidRegisteredCopyQualified": False, "androidBuildQualified": False, "developerIdOrNotarizationQualified": False, "productReady": False,
        "originalCalls": [{"role": role, "entered": True, "returned": True, "capturesSettled": True, "returncode": 0,
            "stdoutSha256": M.digest(b""), "stderrSha256": M.digest(b"")} for role in stage.PACKAGING_CALL_ROLES],
        "packageMount": {"attachEntered": True, "originalKnown": True, "detached": True, "retained": False,
            "installerEntered": True, "installerOriginalZero": True, "sameRequestV2Readback": True, "systemServiceExitClaimed": False},
        "distribution": {"schemaVersion": 1, "kind": "mrk-ordinary-package-observed-v2", "target": binding.target,
            "packageVersion": selection.package_version, "release": selection.release, "requestId": request,
            "packageSha256": "d" * 64, "packageBytes": 1024, "descriptorSha256": M.digest(descriptor), "signatureSha256": "e" * 64,
            "producerSummary": summary, "userImage": {"file": "MobileReleaseKit.dmg", "sha256": "8" * 64, "bytes": 4096},
            "observationImage": {"file": "MobileReleaseKit-Observation.dmg", "sha256": "9" * 64, "bytes": 4096},
            "sourceProducerProfileSha256": "a" * 64, "sourceServiceProfileSha256": "b" * 64,
            "originalInstallerReturnedZero": True, "sameRequestV2Readback": True, "originalMountDetached": True,
            "mountIdentity": [8, 20, stat.S_IFDIR | 0o555, 0, 0], "groupEndpointMet": True, "originalOuterReturnRequired": True,
            "developerIdPurposeAuthority": "native-parent-and-application-checks-separate", "notarizationQualified": False,
            "gatekeeperQualified": False, "systemServiceExitClaimed": False, "productReady": False}}
    audit = {"schemaVersion": 1, "packageSha256": "d" * 64, "packageSize": 1024, "originalPackageSha256": "4" * 64,
        "packageInfoSha256": "5" * 64, "packageIdentifier": stage.PACKAGE_ID, "scriptFileCount": 8,
        "finalDestinationPayloadEntries": 0, "qualification": "scripts-only-package-audited-not-installed-or-GUI-qualified"}
    anchors = {"package-install.status": b"0\n", "package-request-id.txt": request.encode() + b"\n",
        "package-audit.json": stage.canonical(audit) + b"\n", "producer-descriptor-input.json": descriptor,
        "android-helper-package-install.json": stage.canonical(receipt) + b"\n"}
    return selection, environment, value, anchors


class ShippingGateControlWiringDataTests(unittest.TestCase):
    def test_fixed_shipping_feature_graph_thirteen_and_installed_control_phase_order(self):
        workflow, blocks, headless, tree = AndroidRegistrationLifecycleWorkflowTests.source()
        branches = [node for node in tree.body if isinstance(node, ast.If) and isinstance(node.test, ast.Name)
                    and node.test.id == "shipping_gate" and any(isinstance(child, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "names" for target in child.targets) for child in node.body)]
        self.assertEqual(len(branches), 1)
        values = {target.id: ast.literal_eval(node.value) for node in branches[0].body if isinstance(node, ast.Assign)
                  for target in node.targets if isinstance(target, ast.Name) and target.id in ("names", "native_names")}
        self.assertEqual(values["names"], M.SHIPPING_GATE_MAIN_TESTS)
        self.assertEqual(values["native_names"], M.SHIPPING_GATE_NATIVE_TESTS)
        self.assertEqual([name.rsplit("::", 1)[1] for name in values["names"] + values["native_names"]], [
            "a_known_native_failure_projection_does_not_invent_cleanup_uncertainty",
            "participant_never_uses_terminal_or_missing_child_as_exit_finality",
            "failed_pipe_close_publishes_first_before_the_next_original_consume",
            "refusal_never_fabricates_driver_return_join_native_cleanup_or_refund",
            "cleanup_projection_observes_a_stop_arriving_during_original_settlement",
            "an_unknown_original_projection_cannot_reopen_cleanup_on_a_later_callback",
            "prearm_and_pre_go_stop_have_no_native_allocation", "parent_pre_stop_retires_only_an_inert_gate_and_cannot_reenter",
            "prepare_and_spawn_are_distinct_one_shot_state_claims", "code_settlement_never_implies_gate_postcheck_or_unknown_close_finality",
            "even_a_closed_spawned_gate_requires_its_actual_postcheck", "cleanup_gate_correspondence_does_not_erase_a_previous_failure",
            "an_entered_unreturned_native_arm_is_never_empty_or_settled"])
        self.assertIn('main_count, native_count = 6, 7', headless)
        self.assertIn('["default", "installed-observation"] if shipping_gate else ["default"]', headless)
        self.assertEqual(headless.count('compiler_argv += ["--features", "mrk-macos-installed-native/installed-observation"]'), 1)
        self.assertIn('if (shipping_gate or catalogue_gate) and calls_entered != calls_returned:', headless)
        self.assertIn('required-follow-on-build-and-gate-control', headless)
        self.assertIn('"headless-shipping-gate-finality-unconfirmed"', headless)
        self.assertNotIn('"--ignored"', headless)
        label = "One installed no-GO shipping-helper gate-custody control before any Aqua entry"
        control = blocks[label]
        self.assertLess(workflow.index('      - name: Application installation uses only standard privileged Installer; app and Python stay nonroot'), workflow.index("      - name: " + label))
        self.assertLess(workflow.index("      - name: " + label), workflow.index("      - name: One project-field Aqua journey"))
        self.assertIn("env.MRK_MACOS_AQUA_SCOPE == 'vault-helper-shipping-installation-inspection'", control)
        self.assertIn('RUNNER_ENVIRONMENT: ${{ runner.environment }}', control.split('        run: |', 1)[0])
        self.assertIn('qualification.shipping_gate_control_main(target=os.environ["MRK_MACOS_TARGET"])', control)
        self.assertIn('[[ "$status" == 0 && "$saved" == 0 ]]', control)
        for name in (M.SHIPPING_GATE_REPORT, M.SHIPPING_GATE_STATUS):
            self.assertIn('${{ steps.work.outputs.root }}/' + name, workflow)
        source = PATH.read_text()
        main = source.rsplit('\ndef main():\n', 1)[1]
        self.assertLess(main.index('shipping_gate = require_shipping_gate_receipt('), main.index('fixtures.prepare()'))
        self.assertIn('shippingGateControl=shipping_gate', main)
        self.assertNotIn('workflow_dispatch', workflow)
        self.assertIn(
            "        include:\n          - scope: local-edits3\n            target: aarch64-apple-darwin\n            runner: macos-26\n            supplier_receipt: '2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d'\n            supplier_tar: 'ff7883185cf8226e9366b1ee9a3dcb3eb8ee761dbc1f697f952510a6bd858695'\n            supplier_source: '158cdff422e3837f7ab5e6192af76a578faf6fab'\n            supplier_run: '37467019389'\n            supplier_attempt: '1'\n            supplier_artifact: '11415902210'\n          - scope: local-edits3\n            target: x86_64-apple-darwin\n            runner: macos-26-intel\n            supplier_receipt: 'a46f6838afdb7c20c3539e8f65891312aa8df10e2de67e9b9e3ddbf449883b4b'\n            supplier_tar: '739cc8b8b3c68daffba8d7b9cb7cb54ca730eef2c5842302ae8a2682bf64d5bd'\n            supplier_source: '079ab2a2c8fef88f01bf909e7669c685f07e1375'\n            supplier_run: '37476532238'\n            supplier_attempt: '1'\n            supplier_artifact: '11419502465'\n    runs-on: ${{ matrix.runner }}\n", workflow)

    def test_actual_shipping_headless_finalizer_retains_required_target_and_unknown_originals(self):
        _, _, _, tree = AndroidRegistrationLifecycleWorkflowTests.source()
        final = next(node for node in tree.body if isinstance(node, ast.Try) and node.finalbody)
        directory = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'directory_identity')
        selected = ast.Module(body=[deepcopy(directory), *deepcopy(final.finalbody)], type_ignores=[])
        self.assertFalse(any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(selected)))
        code = compile(ast.fix_missing_locations(selected), '<actual-shipping-headless-finalizer-DATA>', 'exec')
        for outcome in ('pass', 'owner-unknown', 'artifact-close-error', 'target-replaced', 'directory-close-error'):
            with self.subTest(outcome=outcome):
                events, publications = [], []
                root = SimpleNamespace(st_dev=7, st_ino=100, st_mode=stat.S_IFDIR | 0o700, st_uid=UID, st_gid=GID)
                target = SimpleNamespace(st_dev=7, st_ino=101, st_mode=stat.S_IFDIR | 0o700, st_uid=UID, st_gid=GID)
                foreign = SimpleNamespace(st_dev=7, st_ino=999, st_mode=stat.S_IFDIR | 0o700, st_uid=UID, st_gid=GID)
                def close(fd):
                    events.append(fd)
                    if outcome == 'artifact-close-error' and fd == 17 or outcome == 'directory-close-error' and fd == 20:
                        raise OSError('inert one-attempt close failure')
                records = [{'role': role, 'originalReturned': True, 'artifactOriginalUnchanged': True,
                            'artifactOriginalClosed': False, 'testsPassed': True} for role in ('main', 'native')]
                if outcome == 'owner-unknown': records[1]['originalReturned'] = False
                receipt = {'targets': records, 'compilerOriginalReturned': True, 'cargoTargetRetired': False,
                           'cargoTargetOriginalClosed': False, 'workOriginalClosed': False}
                if outcome == 'owner-unknown': receipt['failure'] = {'stage': 'native-original-call', 'type': 'InertFailure'}
                originals = [{'fd': fd, 'record': record} for fd, record in zip((17, 18), records)]
                def publish(name, body):
                    self.assertEqual(name, 'headless-tests.receipt.json'); publications.append(json.loads(body))
                namespace = {'__builtins__': {'ValueError': ValueError, 'BaseException': BaseException, 'FileNotFoundError': FileNotFoundError,
                    'type': type, 'len': len, 'all': all}, 'os': SimpleNamespace(getuid=lambda: UID, getgid=lambda: GID, close=close,
                    fstat=lambda fd: root if fd == 19 else target,
                    stat=lambda *args, **kwargs: foreign if outcome == 'target-replaced' else target), 'stat': stat, 'json': json,
                    'shutil': SimpleNamespace(rmtree=lambda *args, **kwargs: self.fail('shipping target must not be retired before follow-on work')),
                    'work': SimpleNamespace(lstat=lambda: root), 'work_fd': 19, 'target_fd': 20,
                    'work_original': (7, 100, root.st_mode, UID, GID), 'target_original': (7, 101, target.st_mode, UID, GID),
                    'android_lifecycle': False, 'shipping_gate': True, 'owned_headless': True,
                    'calls_entered': 3, 'calls_returned': 2 if outcome == 'owner-unknown' else 3,
                    'receipt': receipt, 'originals': originals, 'cleanup_errors': [], 'publish': publish,
                    'names': tuple(range(6)), 'native_names': tuple(range(7))}
                raised = None
                try: exec(code, namespace)
                except ValueError as error: raised = error
                self.assertEqual(len(publications), 1)
                result = publications[0]
                self.assertEqual(result['passed'], outcome == 'pass')
                self.assertFalse(result['cargoTargetRetired'])
                self.assertEqual(len(events), len(set(events)))
                if outcome == 'owner-unknown':
                    self.assertEqual(events, []); self.assertTrue(result['headlessCustodyRetained'])
                    self.assertEqual([row['fd'] for row in originals], [17, 18]); self.assertIsNone(raised)
                else:
                    self.assertEqual(events, [17, 18, 20, 19])
                    self.assertTrue(all(row['fd'] is None for row in originals))
                    self.assertFalse(result['headlessCustodyRetained'])
                    if outcome == 'pass':
                        self.assertIsNone(raised); self.assertEqual(result['tests'], 13)
                        self.assertEqual(result['cargoTargetRetentionReason'], 'required-follow-on-build-and-gate-control')
                    else:
                        self.assertIsNotNone(raised)
                        self.assertTrue(result.get('closeErrors') or result.get('cleanupErrors'))

    def test_exact_libtest_never_accepts_ignored_or_underrun_or_startup_refusal(self):
        names = (M.SHIPPING_GATE_TEST,)
        raw = shipping_gate_libtest_data(names)
        self.assertEqual(M._gate_libtest(raw, b"", 0, names), 19)
        for changed, stderr, code in (
            (raw.replace(b'running 1 test', b'running 0 tests'), b'', 0),
            (raw.replace(b' ... ok', b' ... ignored'), b'', 0),
            (raw.replace(b'0 ignored', b'1 ignored'), b'', 0),
            (raw.replace(M.SHIPPING_GATE_TEST.encode(), b'another_test'), b'', 0),
            (raw + b'extra\n', b'', 0), (raw, b'diagnostic', 0),
            (raw, b'', 64), (raw, b'', 67), (raw, b'', False), (b'', b'', 0)):
            with self.subTest(code=code, changed=changed[:20]), self.assertRaises(M.Refused):
                M._gate_libtest(changed, stderr, code, names)

    def test_headless_compiler_feature_full9_and_original_data_mutations_fail(self):
        for binding in (BINDING, replace(BINDING, target=M.INTEL_TARGET)):
            checkout, work, bodies, receipt, rows = shipping_gate_headless_data(binding)
            actual, native = M._gate_headless(bodies, binding, checkout, work)
            self.assertEqual(actual, receipt)
            self.assertEqual(native, receipt['targets'][1]['artifact'])
            self.assertEqual(receipt["compilerArgv"][0], M.target_data(binding.target)["cargo"])
            changes = (
                lambda value: value["compilerArgv"].__setitem__(0, "cargo"),
                lambda value: value["compilerArgv"].__setitem__(0, "/Users/runner/.cargo/bin/cargo"),
                lambda value: value.update(ownerCallsReturned=2),
                lambda value: value.update(compilerOriginalReturned=1),
                lambda value: value.update(cargoTargetRetired=True),
                lambda value: value.update(runAttempt='2'),
                lambda value: value['targets'][1].update(features=['default', 'vault-helper']),
                lambda value: value['targets'][0].update(features=['installed-observation']),
                lambda value: value['targets'][1].update(artifactOriginalClosed=False),
                lambda value: value['targets'][1]['artifact']['full9'].__setitem__(1, str(2**60 + 3)),
                lambda value: value['targets'][1]['artifact']['full9'].__setitem__(7, float(2**60)),
                lambda value: value['targets'][1]['artifact'].update(path='/tmp/foreign'),
                lambda value: value['targets'][1].update(names=['other']),
            )
            for mutate in changes:
                changed = deepcopy(receipt); mutate(changed)
                with self.assertRaises(M.Refused):
                    M._gate_headless({**bodies, 'headless-tests.receipt.json': json.dumps(changed).encode()}, binding, checkout, work)
            for kind in ('finish-number', 'wrong-features', 'extra-target', 'wrong-source'):
                changed = deepcopy(rows)
                if kind == 'finish-number': changed[-1]['success'] = 1
                elif kind == 'wrong-features': changed[1]['features'] = ['default']
                elif kind == 'extra-target': changed.insert(0, deepcopy(changed[0]))
                else: changed[1]['target']['src_path'] = '/tmp/foreign/src/lib.rs'
                raw = b''.join(json.dumps(row).encode() + b'\n' for row in changed)
                updated = {**receipt, 'compilerJsonSha256': M.digest(raw)}
                with self.subTest(kind=kind), self.assertRaises(M.Refused):
                    M._gate_headless({**bodies, 'headless-build.jsonl': raw,
                                     'headless-tests.receipt.json': json.dumps(updated).encode()}, binding, checkout, work)
            changed = deepcopy(receipt)
            bad = bodies['headless-native-tests.stdout'].replace(b'0 ignored', b'1 ignored')
            changed['targets'][1]['stdoutSha256'] = M.digest(bad)
            with self.assertRaises(M.Refused):
                M._gate_headless({**bodies, 'headless-native-tests.stdout': bad,
                                 'headless-tests.receipt.json': json.dumps(changed).encode()}, binding, checkout, work)
            opposite = M.INTEL_TARGET if binding.target == M.ARM_TARGET else M.ARM_TARGET
            with self.assertRaises(M.Refused):
                M._gate_headless(bodies, replace(binding, target=opposite), checkout, work)
            self.assertEqual(receipt["compilerArgv"][6:8], ["--target", binding.target])

    def test_outer_installation_metadata_gate_and_export_keep_nested_original_contract(self):
        with shipping_gate_stager_data() as stage:
            for target in (M.ARM_TARGET, M.INTEL_TARGET):
                binding = replace(BINDING, target=target)
                for action, retained in (("fresh-install", 0), ("update", 1), ("update", 8),
                        ("same-package-noop", 0), ("same-package-noop", 8), ("restore-fixed-app", 0), ("restore-fixed-app", 8)):
                    selection, environment, value, anchors = shipping_gate_installation_data(stage, binding, action=action, retained=retained)
                    def invoke(observed=value, originals=anchors, selected=selection, status=b"0\n"):
                        return M._gate_installation(stage.canonical(observed), status, binding, environment, stage, selected, originals)
                    with self.subTest(target=target, action=action, retained=retained):
                        self.assertEqual(invoke(), value)
                        self.assertNotEqual(value['installerResultExport']['sha256'], M.digest(stage.canonical(value['originalInstallerResult']) + b'\n'))
                        self.assertNotEqual(value['installerResultExport']['bytes'], len(stage.canonical(value['originalInstallerResult']) + b'\n'))
                        if action in ("same-package-noop", "restore-fixed-app"):
                            self.assertNotEqual(value['installationMetadata'][0]['instance'], value['invocation'])
                    # Each action uses the actual joined-writer/state/count parser.
                    for key, replacement in (("writerState", "installed" if action in ("same-package-noop", "restore-fixed-app") else "same-package"),
                                             ("writerExit", True), ("originalWriterJoined", False), ("requestId", "a" * 32),
                                             ("resultFinality", "complete"), ("parentFinality", "complete"),
                                             ("retainedGate", "closed"), ("historicalOuterExit", "verified"),
                                             ("payloadWriteCount", 1 if action == "same-package-noop" else 0)):
                        bad = deepcopy(value); bad['originalInstallerResult'][key] = replacement
                        with self.subTest(action=action, key=key), self.assertRaises(stage.Refused): invoke(bad)
                    if action in ("fresh-install", "update"):
                        bad = deepcopy(value); bad['installationMetadata'][0]['instance'] = '3' * 32
                        with self.assertRaises(M.Refused): invoke(bad)
                    if action == 'update':
                        bad = deepcopy(value); bad['installationMetadata'] = bad['installationMetadata'][:1]
                        with self.assertRaises(M.Refused): invoke(bad)
                    if action == 'fresh-install':
                        bad = deepcopy(value); bad['installationMetadata'].append(deepcopy(bad['installationMetadata'][0]))
                        with self.assertRaises(M.Refused): invoke(bad)

                selection, environment, value, anchors = shipping_gate_installation_data(stage, binding, action='update', retained=8)
                changes = (
                    lambda row: row.update(extra=True), lambda row: row.update(schemaVersion=True), lambda row: row.update(schemaVersion=1),
                    lambda row: row.update(sourceCommit='f' * 40), lambda row: row.update(requestId='f' * 32),
                    lambda row: row.update(completedPackageSha256='f' * 64), lambda row: row.update(invocation='f' * 32),
                    lambda row: row.update(applicationLaunched=True), lambda row: row.update(guiSaveQualified=True),
                    lambda row: row.update(originalInstallerReturnedZero=1), lambda row: row.update(nonrootReadbackFileCount=True),
                    lambda row: row.update(producerSignatureAuthority='authenticated'), lambda row: row.update(historicalOuterExit='verified'),
                    lambda row: row['installationMetadata'][1].update(release=selection.release),
                    lambda row: row['installationMetadata'][1].update(release=M.target_data(target)['releasePrefix'] + 'foreign'),
                    lambda row: row['installationMetadata'][1].update(instance=row['installationMetadata'][0]['instance']),
                    lambda row: row['installationMetadata'][1].update(verifiedCurrentFiles=1),
                    lambda row: row['installationMetadata'][0].update(declaredPayloadFiles=3),
                    lambda row: row['installationMetadata'][1].update(declaredPayloadFiles=2048),
                    lambda row: row['installationMetadata'][1].update(declaredBytes=stage.MAX_BYTES),
                    lambda row: row['installationMetadata'][0].update(declaredBytes=1),
                    lambda row: row['installationMetadata'][0].update(producerDescriptorBytes=1),
                    lambda row: row['installationMetadata'][0].update(producerSignatureBytes=1),
                    lambda row: row['installationMetadata'][0].update(inventoryBytes=True),
                    lambda row: row['installationMetadata'][0].update(descriptorBytes=8193),
                    lambda row: row['installationMetadata'][0].update(historicalOuterExit='verified'),
                    lambda row: row['maintenanceGate'].update(workerFinalityEstablished=True),
                    lambda row: row['maintenanceGate'].update(exclusionObserved=True),
                    lambda row: row['installerResultExport'].update(bytes=1),
                    lambda row: row['installerResultExport'].update(finalityBasis='receipt-only'),
                    lambda row: row['installerResultExport']['identity'].__setitem__(3, 0),
                )
                for index, mutate in enumerate(changes):
                    bad = deepcopy(value); mutate(bad)
                    with self.subTest(target=target, mutation=index), self.assertRaises(M.Refused): invoke(bad, anchors, selection)
                for name, replacement in (("package-install.status", b"1\n"), ("package-install.status", b"0"),
                                          ("package-request-id.txt", b"0" * 32 + b"\n"),
                                          ("package-request-id.txt", b"2" * 32 + b"\n"),
                                          ("package-request-id.txt", b"1" * 32)):
                    with self.subTest(anchor=name), self.assertRaises((M.Refused, stage.Refused)):
                        invoke(value, {**anchors, name: replacement}, selection)
                for name, changes in (
                    ("package-audit.json", [lambda row: row.update(packageSha256='f' * 64), lambda row: row.update(packageSize=True)]),
                    ("producer-descriptor-input.json", [lambda row: row.update(target=M.ARM_TARGET if target == M.INTEL_TARGET else M.INTEL_TARGET),
                        lambda row: row['releaseSet']['current'].update(protocolSha256='f' * 64),
                        lambda row: row['releaseSet']['current'].update(sourceCommit='f' * 40)]),
                    ("android-helper-package-install.json", [lambda row: row.update(runAttempt='2'), lambda row: row.update(passed=1),
                        lambda row: row.update(toolchain='1.98.1' if target == M.INTEL_TARGET else '1.98.0'),
                        lambda row: row.update(toolchain='nightly'), lambda row: row.update(toolchain=None),
                        lambda row: row.update(toolchain=True),
                        lambda row: row.update(failure={}), lambda row: row.update(originalClosesKnown=False),
                        lambda row: row.update(targetRetired=False), lambda row: row.update(directStagerIOPending='v2-readback'),
                        lambda row: row.update(developerIdOrNotarizationQualified=True),
                        lambda row: row['packageMount'].update(detached=False), lambda row: row['originalCalls'][0].update(returned=False),
                        lambda row: row['originalCalls'][0].update(capturesSettled=False), lambda row: row['originalCalls'][0].update(returncode=1),
                        lambda row: row['originalCalls'][0].update(role='other'), lambda row: row['originalCalls'].pop(),
                        lambda row: row['distribution'].update(requestId='f' * 32), lambda row: row['distribution'].update(packageBytes=1025),
                        lambda row: row['distribution'].update(descriptorSha256='f' * 64),
                        lambda row: row['distribution'].update(originalInstallerReturnedZero=False),
                        lambda row: row['distribution'].update(sameRequestV2Readback=False),
                        lambda row: row['distribution'].update(groupEndpointMet=False),
                        lambda row: row['distribution']['producerSummary'].update(descriptorBytes=1),
                        lambda row: row['distribution']['producerSummary'].update(signatureBytes=16385)])):
                    for index, mutate in enumerate(changes):
                        bad = json.loads(anchors[name]); mutate(bad)
                        with self.subTest(anchor=name, mutation=index), self.assertRaises((M.Refused, stage.Refused)):
                            invoke(value, {**anchors, name: stage.canonical(bad) + b'\n'}, selection)
                with self.assertRaises(M.Refused): invoke(value, anchors, selection, b'1\n')
                with self.assertRaises(M.Refused):
                    invoke(value, anchors, stage.BuildSelection(M.ARM_TARGET if target == M.INTEL_TARGET else M.INTEL_TARGET,
                                                               selection.package_version, selection.release))
                # Exact same exception object, not a generic success/error adapter.
                failure = stage.Refused('inert-nested-original-refusal')
                with patch.object(stage, 'maintenance_result_data', side_effect=failure), self.assertRaises(stage.Refused) as caught:
                    invoke(value, anchors, selection)
                self.assertIs(caught.exception, failure)

    def test_control_receipt_cannot_hide_missing_late_or_unknown_original_facts(self):
        checkout, work, bodies, headless, _rows = shipping_gate_headless_data()
        bodies['installation-observation.json'] = b'inert source-bound installation DATA'
        native = headless['targets'][1]['artifact']
        value = M._gate_new_report(BINDING, M.VAULT_HELPER_SCOPE)
        value.update(headlessReceiptSha256=M.digest(bodies['headless-tests.receipt.json']),
            compilerJsonSha256=headless['compilerJsonSha256'], installationReadbackSha256=M.digest(bodies['installation-observation.json']),
            artifact=native, ownerEntered=True, originalCallReturned=True, ownerReturncode=0, ownerElapsedNanoseconds='1234',
            stdoutSha256=M.digest(shipping_gate_libtest_data((M.SHIPPING_GATE_TEST,))), stderrSha256=M.digest(b''),
            stdoutBytes=len(shipping_gate_libtest_data((M.SHIPPING_GATE_TEST,))), stderrBytes=0,
            namedTestPassed=True, sourceReadbacksUnchanged=True, artifactOriginalUnchanged=True, artifactCloseAttempts=1,
            artifactOriginalClosed=True, artifactRetired=True, fixtureDirectoriesRetired=True, fixtureHandlesClosed=True, passed=True)
        accepted = M._gate_completion(json.dumps(value).encode(), BINDING, M.VAULT_HELPER_SCOPE, bodies, headless, native)
        self.assertTrue(accepted['parentReferenceCloseNoGoGateControlPassed'])
        self.assertFalse(accepted['actualParentProcessDisappearanceEstablished'])
        for key, replacement in (
            ('passed', 1), ('runAttempt', '2'), ('headlessReceiptSha256', '0' * 64),
            ('stdoutBytes', True), ('stdoutBytes', -1), ('stdoutBytes', 65537), ('stdoutBytes', 1.0),
            ('stderrBytes', False), ('stderrBytes', 1), ('stderrBytes', '0'),
            ('installationReadbackSha256', '0' * 64), ('ownerElapsedNanoseconds', '30000000000'),
            ('originalCallReturned', False), ('ownerReturncode', 67), ('artifactCloseAttempts', 0),
            ('artifactOriginalClosed', False), ('fixtureDirectoriesRetired', False), ('artifactRetired', False),
            ('cleanupErrors', [{'stage': 'close', 'reason': 'unknown', 'type': 'OSError'}]),
            ('actualParentProcessDisappearanceEstablished', True), ('allWorkerPopulationsQualified', True)):
            with self.subTest(key=key), self.assertRaises(M.Refused):
                M._gate_completion(json.dumps({**value, key: replacement}).encode(), BINDING, M.VAULT_HELPER_SCOPE, bodies, headless, native)
        for changed in (b'', b'{}', json.dumps({key: item for key, item in value.items() if key != 'artifactOriginalClosed'}).encode(),
                        json.dumps({key: item for key, item in value.items() if key != 'stdoutBytes'}).encode(),
                        json.dumps({key: item for key, item in value.items() if key != 'stderrBytes'}).encode(),
                        json.dumps(value).encode()[:-1] + b',"passed":true}'):
            with self.assertRaises(M.Refused):
                M._gate_completion(changed, BINDING, M.VAULT_HELPER_SCOPE, bodies, headless, native)

    def run_inert_lifecycle(self, outcome):
        # Plain task-owned DATA files only. The injected callable never launches
        # a process, imports an owner, enters native code or produces evidence.
        with tempfile.TemporaryDirectory(prefix='mrk-gate-wiring-data-') as temporary:
            work = Path(temporary); target = work / 'cargo-target'; deps = target / 'aarch64-apple-darwin/debug/deps'
            deps.mkdir(parents=True)
            for path in (work, target, target / 'aarch64-apple-darwin', target / 'aarch64-apple-darwin/debug', deps): path.chmod(0o700)
            binary = deps / 'mrk_macos_installed_native-123abc'
            binary.write_bytes(b'inert DATA, never executable by this test\n'); binary.chmod(0o700)
            original = M.signature(binary.stat())
            native = {'path': str(binary), 'sha256': M.digest(binary.read_bytes()), 'full9': [str(v) for v in original],
                      'identity': [original[0], original[1], original[2], original[5], original[3], original[4], *original[6:]]}
            headless = {'cargoTargetOriginal': [str(v) for v in M.signature(target.stat())[:5]], 'compilerJsonSha256': 'b' * 64}
            bodies = {'headless-tests.receipt.json': b'inert headless DATA', 'installation-observation.json': b'inert installed DATA'}
            fixtures = M.Fixtures(BINDING, M.os.getuid(), M.os.getgid(), M.VAULT_HELPER_SCOPE)
            calls, closes, stages = [], [], []
            real_close, real_rmdir, close_original = M.os.close, M.os.rmdir, fixtures._close
            sentinel = RuntimeError('private exception text must not be exported')
            def dependencies(current, binding, checkout, selected, environment):
                self.assertIs(current, fixtures); self.assertEqual(selected, work)
                fixtures.gate_work = M._gate_directory(fixtures, str(work), private=True)
                return bodies, headless, native
            def owner(argv, **kwargs):
                calls.append((list(argv), kwargs))
                self.assertEqual(argv, [str(binary), '--exact', '--ignored', '--test-threads=1', '--color=never', '--format=pretty', M.SHIPPING_GATE_TEST])
                self.assertEqual(kwargs, {'environ': {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(work / 'shipping-gate-control/home'),
                    'TMPDIR': str(work / 'shipping-gate-control/tmp'), 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'},
                    'cwd': work / 'shipping-gate-control', 'timeout': 30, 'capture': True, 'text': False, 'output_limit': 65536})
                if outcome == 'owner-exception': raise sentinel
                if outcome == 'foreign-return': return CompletedProcess(['foreign'], 0, b'', b'')
                if outcome == 'changed-artifact': binary.write_bytes(b'changed inert original')
                stdout = shipping_gate_libtest_data((M.SHIPPING_GATE_TEST,))
                return CompletedProcess(argv, 1 if outcome == 'primary-and-close' else 0, stdout, b'')
            def close(fd):
                closes.append(fd)
                real_close(fd)
                if outcome in ('close-error', 'primary-and-close') and fixtures.gate_artifact is not None and fd == fixtures.gate_artifact['fd']:
                    raise OSError('inert report failure after one actual DATA close')
                if outcome == 'post-unlink-directory-close' and fd == fixtures.gate_work:
                    self.assertFalse(binary.exists())
                    raise OSError('inert remaining parent-directory close failure after exact unlink')
            def close_entry(fd):
                if outcome == 'unexpected-close-call' and fixtures.gate_artifact is not None and fd == fixtures.gate_artifact['fd']:
                    closes.append(fd)
                    raise RuntimeError('inert consuming call has no known close result')
                return close_original(fd)
            def rmdir(name, *, dir_fd=None):
                stages.append(('rmdir', name))
                if outcome == 'retirement-error' and name == 'tmp': raise OSError('inert empty-directory refusal')
                return real_rmdir(name, dir_fd=dir_fd)
            readings = iter((100, 30_000_000_100 if outcome == 'late-return' else 200))
            try:
                with patch.object(M, '_gate_dependencies', dependencies), patch.object(M.os, 'close', close), \
                     patch.object(fixtures, '_close', close_entry), patch.object(M.os, 'rmdir', rmdir):
                    result = M.run_shipping_gate_control(BINDING, fixtures, owner, PATH.parents[2], work,
                        {'MRK_MACOS_AQUA_SCOPE': M.VAULT_HELPER_SCOPE}, clock=lambda: next(readings))
                self.assertEqual(len(calls), 1)
                self.assertNotIn('private exception text', json.dumps(result))
                if outcome in ('owner-exception', 'foreign-return'):
                    self.assertTrue(fixtures.inflight); self.assertFalse(result['originalCallReturned'])
                    self.assertEqual(closes, []); self.assertEqual(stages, [])
                    self.assertTrue(binary.exists()); self.assertTrue(fixtures.fds)
                else:
                    self.assertTrue(result['originalCallReturned']); self.assertFalse(fixtures.inflight)
                    if outcome == 'unexpected-close-call':
                        self.assertEqual(fixtures.fds, {fixtures.gate_artifact['fd']})
                        self.assertEqual(stages, [])
                        self.assertFalse(result['fixtureHandlesClosed'])
                    else:
                        self.assertFalse(fixtures.fds)
                    self.assertEqual(len(closes), len(set(closes)))
                    self.assertEqual(result['artifactCloseAttempts'], 1)
                    self.assertEqual(result['passed'], outcome == 'pass')
                    self.assertEqual(binary.exists(), outcome not in ('pass', 'post-unlink-directory-close'))
                    self.assertEqual(result['stdoutBytes'], len(shipping_gate_libtest_data((M.SHIPPING_GATE_TEST,))))
                    self.assertEqual(result['stderrBytes'], 0)
                return result
            finally:
                # Explicit test-side cleanup is authorized by this INERT fake's
                # no-process construction, never by a runtime unknown result.
                fixtures.inflight = False
                for fd in tuple(fixtures.fds):
                    try: fixtures._close(fd)
                    except OSError: pass

    @unittest.skipUnless(M.os.name == 'posix', 'POSIX DATA-only original FD fixture')
    def test_actual_control_owner_unknown_or_foreign_return_never_closes_or_retires(self):
        for outcome in ('owner-exception', 'foreign-return'):
            with self.subTest(outcome=outcome):
                result = self.run_inert_lifecycle(outcome)
                self.assertFalse(result['passed'])
                self.assertEqual(result['artifactCloseAttempts'], 0)
                self.assertFalse(result['fixtureHandlesClosed'])
                self.assertIsNotNone(result['failure'])

    @unittest.skipUnless(M.os.name == 'posix', 'POSIX DATA-only original FD fixture')
    def test_actual_control_known_return_postchecks_and_one_attempt_cleanup_gate_success(self):
        for outcome in ('pass', 'late-return', 'changed-artifact', 'close-error', 'unexpected-close-call', 'retirement-error', 'primary-and-close', 'post-unlink-directory-close'):
            with self.subTest(outcome=outcome):
                result = self.run_inert_lifecycle(outcome)
                if outcome == 'pass':
                    self.assertIsNone(result['failure']); self.assertEqual(result['cleanupErrors'], [])
                    self.assertTrue(result['artifactRetired']); self.assertTrue(result['fixtureDirectoriesRetired'])
                elif outcome == 'primary-and-close':
                    self.assertEqual(result['failure']['reason'], 'gate-libtest-original-result')
                    self.assertTrue(result['cleanupErrors']); self.assertFalse(result['artifactOriginalClosed'])
                elif outcome in ('close-error', 'unexpected-close-call', 'retirement-error'):
                    self.assertTrue(result['cleanupErrors']); self.assertFalse(result['passed'])
                elif outcome == 'post-unlink-directory-close':
                    self.assertTrue(result['artifactRetired']); self.assertTrue(result['fixtureDirectoriesRetired'])
                    self.assertFalse(result['fixtureHandlesClosed']); self.assertTrue(result['cleanupErrors'])
                    self.assertFalse(result['passed'])
                else:
                    self.assertIsNotNone(result['failure']); self.assertFalse(result['artifactRetired'])

    def test_missing_same_run_control_status_refuses_before_aqua_and_preserves_close_failure(self):
        checkout, work, bodies, headless, _rows = shipping_gate_headless_data()
        bodies['installation-observation.json'] = b'inert installation'
        native = headless['targets'][1]['artifact']
        for mode in ('missing', 'status-failed', 'primary-and-close'):
            primary = FileNotFoundError('inert missing receipt')
            cleanup = OSError('inert source dependency close failure')
            def close():
                if mode == 'primary-and-close': raise cleanup
            fixture = SimpleNamespace(gate_work=17, close=close)
            events = []
            def read(_fixtures, name, parent, limit):
                events.append(name)
                if mode in ('missing', 'primary-and-close'): raise primary
                return (b'{}' if name == M.SHIPPING_GATE_REPORT else b'1\n'), {}
            with patch.object(M, 'Fixtures', return_value=fixture), \
                 patch.object(M, '_gate_dependencies', return_value=(bodies, headless, native)), \
                 patch.object(M, '_gate_file', read), patch.object(M, '_gate_recheck') as recheck:
                with self.assertRaises((FileNotFoundError, M.Refused)) as caught:
                    M.require_shipping_gate_receipt(BINDING, UID, GID, checkout, work,
                        {'MRK_MACOS_AQUA_SCOPE': M.VAULT_HELPER_SCOPE})
                if mode == 'primary-and-close':
                    self.assertIs(caught.exception, primary)
                    self.assertIs(caught.exception.__cause__, cleanup)
                recheck.assert_not_called()
            self.assertTrue(events)
        with shipping_gate_stager_data() as stage:
            selection, environment, observed, anchors = shipping_gate_installation_data(stage)
            checkout, work, headless_bodies, headless, _rows = shipping_gate_headless_data()
            all_bodies = {**headless_bodies, **anchors, 'installation-observation.json': stage.canonical(observed),
                          'installer-output.status': b'0\n'}
            limits = {'package-install.status': 4, 'package-request-id.txt': 33, 'package-audit.json': 16384,
                      'producer-descriptor-input.json': 65536, 'android-helper-package-install.json': 16384}
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            work_stat = SimpleNamespace(**dict(zip(fields, tuple(int(v) for v in headless['workOriginal']) + (2, 4096, 100, 100))))
            route = dict(environment, MRK_MACOS_AQUA_SCOPE=M.VAULT_HELPER_SCOPE, CARGO_TARGET_DIR=str(work / 'cargo-target'))
            fixture, read_limits = SimpleNamespace(), {}
            def admitted_file(current, name, parent, bound):
                self.assertIs(current, fixture); self.assertEqual(parent, 17)
                self.assertNotIn(name, read_limits); read_limits[name] = bound
                return all_bodies[name], {}
            with patch.object(M, '_gate_directory', return_value=17), patch.object(M, '_gate_file', admitted_file), \
                 patch.object(M.os, 'fstat', return_value=work_stat), patch.object(M, '_gate_load_stager', return_value=(stage, selection)) as loaded:
                admitted, selected_headless, selected_native = M._gate_dependencies(fixture, BINDING, checkout, work, route)
            self.assertEqual(admitted, all_bodies); self.assertEqual(selected_headless, headless)
            self.assertEqual(selected_native, headless['targets'][1]['artifact'])
            self.assertEqual(len(read_limits), 16)
            self.assertEqual({name: read_limits[name] for name in limits}, limits)
            loaded.assert_called_once_with(fixture, checkout, target=M.ARM_TARGET)
            for missing, limit in limits.items():
                for unknown_close in (False, True):
                    primary, cleanup = FileNotFoundError('inert missing package anchor'), OSError('inert original close unknown')
                    events, closed = [], []
                    def close():
                        closed.append(True)
                        if unknown_close: raise cleanup
                    fixture = SimpleNamespace(gate_work=None, close=close)
                    def read(current, name, parent, bound):
                        self.assertIs(current, fixture); self.assertEqual(parent, 17)
                        events.append((name, bound))
                        if name == missing:
                            self.assertEqual(bound, limit)
                            raise primary
                        return all_bodies[name], {}
                    with patch.object(M, 'Fixtures', return_value=fixture), patch.object(M, '_gate_directory', return_value=17), \
                         patch.object(M, '_gate_file', read), patch.object(M.os, 'fstat', return_value=work_stat), \
                         patch.object(M, '_gate_load_stager') as loaded, patch.object(M, '_gate_completion') as completion:
                        with self.subTest(missing=missing, unknown_close=unknown_close), self.assertRaises(FileNotFoundError) as caught:
                            M.require_shipping_gate_receipt(BINDING, UID, GID, checkout, work, route)
                        self.assertIs(caught.exception, primary)
                        if unknown_close: self.assertIs(caught.exception.__cause__, cleanup)
                        loaded.assert_not_called(); completion.assert_not_called()
                    self.assertEqual(closed, [True]); self.assertEqual(events[-1], (missing, limit))

            # The actual fixed loader holds ALL THREE SOURCE originals through
            # import/use, selects Intel from its already captured bytes, and
            # neither closes originals early nor calls source_build_selection.
            previous = dict(sys.modules)
            with patch.dict(sys.modules):
                held, posts = [], []
                def source_file(fixture, name, parent, limit):
                    self.assertIsNone(parent); self.assertEqual(limit, 256 * 1024)
                    raw = Path(name).read_bytes()
                    row = {'name': name, 'sha256': M.digest(raw)}; held.append(row)
                    return raw, row
                def post(row, capture=False):
                    self.assertTrue(any(row is original for original in held)); posts.append(row)
                    return b'', row['sha256']
                with patch.object(M, '_gate_file', source_file), patch.object(M, '_gate_file_read', post):
                    loaded, selected = M._gate_load_stager(SimpleNamespace(), PATH.parents[2], target=M.INTEL_TARGET)
                self.assertEqual(selected.target, M.INTEL_TARGET)
                self.assertTrue(selected.release.startswith('macos26-x86_64-'))
                self.assertEqual([row['name'] for row in held], [str(PATH.parents[2] / name) for name in M.SHIPPING_GATE_SOURCE_PINS])
                self.assertEqual(len(held), 3); self.assertEqual(posts, held)
                self.assertIs(sys.modules['_mrk_shipping_gate_stager'], loaded)
            self.assertEqual(set(sys.modules), set(previous))
            self.assertTrue(all(sys.modules[name] is original for name, original in previous.items()))

            # Genuine disposable regular-file DATA checks exercise unchanged
            # same-original POST and consuming-close behavior for EACH new file.
            for changed, limit in limits.items():
                for fault in ('post-change', 'unknown-close'):
                    with tempfile.TemporaryDirectory(prefix='mrk-gate-v2-anchors-') as temporary:
                        root = Path(temporary); root.chmod(0o700)
                        for name, body in anchors.items():
                            path = root / name; path.write_bytes(body); path.chmod(0o444 if name == 'producer-descriptor-input.json' else 0o600)
                        fixture = M.Fixtures(BINDING, M.os.getuid(), M.os.getgid(), M.VAULT_HELPER_SCOPE)
                        try:
                            fixture.gate_work = M._gate_directory(fixture, str(root), private=True)
                            for name, bound in limits.items():
                                body, _original = M._gate_file(fixture, name, fixture.gate_work, bound)
                                self.assertEqual(body, anchors[name])
                            M._gate_recheck(fixture)
                            if fault == 'post-change':
                                path = root / changed; path.chmod(0o600); path.write_bytes(b'changed inert DATA')
                                with self.assertRaises(M.Refused): M._gate_recheck(fixture)
                            else:
                                fd = next(row['fd'] for row in fixture.gate_files if row['name'] == changed)
                                original_close, attempts, failure = M.os.close, [], OSError('inert after-consuming close')
                                def close_once(value):
                                    attempts.append(value); original_close(value)
                                    if value == fd: raise failure
                                with patch.object(M.os, 'close', side_effect=close_once), self.assertRaises(OSError) as caught:
                                    fixture.close()
                                self.assertIs(caught.exception, failure)
                                self.assertEqual(attempts.count(fd), 1); self.assertFalse(fixture.fds)
                                self.assertEqual(fixture.close_errors, 1)
                        finally:
                            if fixture.fds: fixture.close()



def inert_recovery_inventories():
    """Exact integer DATA only; not files, generated journals or receipts."""
    next_inode = 2**60
    def node(body=None):
        nonlocal next_inode
        next_inode += 1
        identity = (7, next_inode, (stat.S_IFDIR | 0o700) if body is None else (stat.S_IFREG | 0o600),
                    UID, GID, 9 if body is None else 1, 4096 if body is None else len(body), 2**60, 2**60)
        return M.Node(identity, None if body is None else M.digest(body), () if body is None else None)
    def rosters(rows):
        for name, row in tuple(rows.items()):
            if row.sha256 is None:
                rows[name] = replace(row, entries=tuple(sorted(path.rsplit("/", 1)[-1] for path in rows
                                    if path != "." and str(Path(path).parent) == name)))
        return rows
    def moved(row):
        return replace(row, identity=(*row.identity[:8], row.identity[8] + 7))
    initial = rosters({".": node(), "project": node(), **{name: node(body) for name, body in M.RECOVERY_FILES.items()}})
    generated = dict(initial)
    pending = "project/.mobile-release/build-inputs"
    generated.update({"project/.mobile-release": node(), pending: node(),
                      pending + "/header.json": node(b"inert header bytes"), pending + "/intent.json": node(b"inert intent bytes"),
                      pending + "/checkpoint-000.json": node(b"inert checkpoint bytes"),
                      pending + "/backup-1": moved(initial["project/GoogleService-Info.plist"]),
                      "project/GoogleService-Info.plist": node(M.RECOVERY_FOREIGN),
                      "project/google-services.json": moved(initial["project/google-services.json"])})
    rosters(generated)
    before = dict(generated)
    before["project/saved-foreign-ios"] = moved(before.pop("project/GoogleService-Info.plist"))
    rosters(before)
    after = {name: row for name, row in before.items() if name != pending and not name.startswith(pending + "/")}
    after["project/GoogleService-Info.plist"] = moved(generated[pending + "/backup-1"])
    rosters(after)
    return initial, generated, before, after


def inert_recovery_producer():
    return {"schemaVersion": 1, "scope": "real-core-project-recovery-fixture-v1", "case": M.RECOVERY_CASE,
            "materializationOutcome": "expected-cleanup-failure", "coreFatal": True, "commands": 0, "profileCalls": 0,
            "attemptedDescriptors": 12, "neverOpenedDescriptors": 1, "attemptedDescriptorsClosed": True,
            "handlersRestored": True, "invocationReleased": True, "originalQuiescenceRecorded": True,
            "retirementInterceptions": 0, "observersRestored": True,
            "restored": {"android-services": True, "ios-services": False}, "followupCoreOrFilesystemOperation": False}


class InertRecoveryFixtures(InertFixtures):
    def __init__(self):
        super().__init__()
        self.cases = (M.RECOVERY_CASE,)
        self.path = BINDING.root(recovery=True)
        self.recovery_produced = False
        self.accepted = []
        self.fds = set()
        self.first_close_error = None

    def recovery_runtime_paths(self):
        return "/inert/current/runtime/python/bin/python3", "/inert/current/runtime/core.zip"

    def accept_recovery_producer(self, value):
        if self.inflight or not self.last_returned:
            raise AssertionError("generation precedes original return")
        self.accepted.append(value)
        self.recovery_produced = True

    def before_call(self, case):
        if not self.recovery_produced:
            raise AssertionError("app precedes authenticated failed materialization")
        super().before_call(case)

    def readback_recovery(self, report):
        M._recovery_report(report)
        return super().readback(M.RECOVERY_CASE)


class PrecursorFailureDiagnosticDataTests(unittest.TestCase):
    @staticmethod
    def detail(kind):
        project = kind == "project-recovery-producer"
        category = "runtime" if project else "refused"
        value = {"schemaVersion": 2, "reason": "fixture-check-failed" if project else "native-account-entry",
                 "exceptionCategory": category, "sourceSites": [1, 2],
                 "tracebackLinksSeen": 2, "sourceSitesComplete": True,
                 "exceptionGraph": {"raised": 0, "caught": None, "complete": True, "boundRoles": [0],
                     "nodes": [{"category": category, "errno": None, "sites": [[0, 1], [0, 2]],
                         "tracebackLinksSeen": 2, "tracebackComplete": True, "unmappedFrames": 0,
                         "sitesTruncated": False, "cause": None, "context": None, "suppressed": False}]}}
        if project:
            value["caughtExceptionCategory"] = "none"
        return value

    @staticmethod
    def record(kind, value):
        marker = M._precursor_spec(kind)[1]
        return marker + json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"

    def invalid_entry(self, program, argv, *, encode_fault=False, emit_fault=False):
        # Actual source, deliberately invalid first entry: no core/native/FS
        # calls, no subprocess and no synthetic native-success receipt.
        imports, writes = [], []
        ordinary_import = builtins.__import__
        def guarded_import(name, *args, **kwargs):
            imports.append(name)
            if name == "mobile_release" or name.startswith("mobile_release."):
                raise AssertionError("invalid entry must precede core import")
            return ordinary_import(name, *args, **kwargs)
        stdout, stderr = io.StringIO(), io.StringIO()
        def refused_write(value):
            writes.append(value)
            raise RuntimeError("private-emission-error-canary")
        namespace = {"__name__": "_invalid_precursor_entry"}
        with patch.object(sys, "argv", argv), patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr), \
                patch.object(builtins, "__import__", side_effect=guarded_import), \
                patch.object(M.os, "open", side_effect=AssertionError("no fixture access")) as opened, \
                patch.object(M.subprocess, "Popen", side_effect=AssertionError("no original dispatch")) as dispatched:
            if encode_fault:
                with patch.object(M.json, "dumps", side_effect=RuntimeError("private-encoding-error-canary")):
                    with self.assertRaises(SystemExit) as raised:
                        exec(compile(program, "<string>", "exec"), namespace)
            elif emit_fault:
                with patch.object(stderr, "write", side_effect=refused_write):
                    with self.assertRaises(SystemExit) as raised:
                        exec(compile(program, "<string>", "exec"), namespace)
            else:
                with self.assertRaises(SystemExit) as raised:
                    exec(compile(program, "<string>", "exec"), namespace)
        self.assertEqual(raised.exception.code, 1)
        opened.assert_not_called(); dispatched.assert_not_called()
        self.assertFalse(any(name == "mobile_release" or name.startswith("mobile_release.") for name in imports))
        self.assertEqual(stdout.getvalue(), "")
        for value in writes:
            self.assertNotIn("private-emission-error-canary", value)
            self.assertNotIn("Traceback", value)
        return stderr.getvalue().encode()

    def footer(self, kind, original, caught=None, *, modules=None, through=None):
        # Only the actual footer fragment: the synthetic raising prefix is NOT
        # the producer, native execution, a successful core fixture or finality.
        program = M._precursor_spec(kind)[0]
        marker = "except BaseException as _failure_error:\n"
        _, boundary, body = program.partition(marker)
        self.assertEqual(boundary, marker)
        prefix = "try:\n    raise _test_original\n" if through is None else (
            "def _test_own_failure():\n    raise _test_original\ntry:\n    _test_through(_test_own_failure)\n")
        fragment = prefix + marker + body
        namespace = {"__name__": "_inert_precursor_footer", "sys": sys, "json": json,
                     "Refused": type("Refused", (Exception,), {}), "_test_original": original,
                     "caught": caught, "_test_through": through}
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["-c", "/inert-precursor-core"]), \
                patch.dict(sys.modules, modules or {}), patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr), \
                patch.object(builtins, "__import__", side_effect=AssertionError("footer must not import")) as imported, \
                patch.object(M.os, "open", side_effect=AssertionError("footer must not open")) as opened, \
                patch.object(M.subprocess, "Popen", side_effect=AssertionError("footer must not dispatch")) as dispatched:
            with self.assertRaises(SystemExit) as exited:
                exec(compile(fragment, "<string>", "exec"), namespace)
        self.assertEqual(exited.exception.code, 1)
        imported.assert_not_called(); opened.assert_not_called(); dispatched.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        raw = stderr.getvalue().encode()
        self.assertNotIn(b"PRIVATE_", raw); self.assertNotIn(b"Traceback", raw)
        self.assertNotIn(b"/inert-", raw)
        detail = M._precursor_child_failure(raw, kind)
        self.assertIsNotNone(detail)
        return detail

    def test_precursor_envelope_is_separate_bounded_and_never_exports_private_buffers(self):
        canary = b"PRIVATE_ACCOUNT_PATH_OR_CREDENTIAL_CANARY"
        for kind in ("project-recovery-producer", "ios-account-produce", "ios-account-observe"):
            for code, stdout, stderr in ((1, b"", self.record(kind, self.detail(kind))),
                                         (0, b"{}\n", canary), (1, canary + b"\n", canary),
                                         (1, b"two\nlines\n", b""), (1, b"unterminated", b"")):
                result = CompletedProcess([], code, stdout, stderr)
                value = M._precursor_diagnostic(result, kind)
                self.assertEqual((value["kind"], value["returncode"], value["stdoutBytes"], value["stderrBytes"]),
                                 (kind, code, len(stdout), len(stderr)))
                self.assertEqual(value["envelope"], {"zeroReturncode": code == 0, "emptyStderr": stderr == b"",
                    "stdoutNonemptyWithinLimit": bool(stdout), "stdoutFinalNewline": stdout.endswith(b"\n"),
                    "stdoutSingleLine": b"\n" not in stdout[:-1]})
                fixture = M.Fixtures(BINDING, UID, GID, M.RECOVERY_CASE)
                fixture.last_returned = True; fixture.precursor_diagnostic = value
                public = M.diagnostic(M.Refused("recovery-producer-failed"), None, fixture)
                self.assertIsNone(public["appReturncode"]); self.assertIsNone(public["innerFailureReason"])
                self.assertEqual(public["precursorDiagnostic"], value)
                stream = io.StringIO(); M.emit_record(public, stream)
                self.assertNotIn(canary.decode(), stream.getvalue())
                self.assertLessEqual(len(stream.getvalue().encode()), 24*1024 + 1)
            for code in (-(2**31)-1, 2**31, True):
                with self.assertRaises(M.Refused): M._precursor_diagnostic(CompletedProcess([], code, b"", b""), kind)
            for code in (0, 2, -9):
                value = M._precursor_diagnostic(CompletedProcess([], code, b"", self.record(kind, self.detail(kind))), kind)
                self.assertNotIn("childFailure", value)

    def test_child_failure_schema_is_closed_single_canonical_record(self):
        for kind in ("project-recovery-producer", "ios-account-produce", "ios-account-observe"):
            good = self.detail(kind); record = self.record(kind, good)
            self.assertEqual(M._precursor_child_failure(record, kind), good)
            bad_records = [record[:-1], record + b"x", record + record, b"prefix" + record,
                           record.replace(b'"schemaVersion":2', b'"schemaVersion":2,"schemaVersion":2'),
                           record.replace(b'"schemaVersion":2', b'"schemaVersion":NaN'),
                           record.replace(b'{', b'{ ', 1), b"x"*(M.PRECURSOR_FAILURE_LIMIT + 1)]
            for field, value in (("schemaVersion", True), ("schemaVersion", 1), ("reason", "private-field-canary"),
                                 ("exceptionCategory", "private-error-canary"), ("exceptionCategory", "none"),
                                 ("sourceSites", [True]), ("sourceSites", [0]),
                                 ("sourceSites", [len(M._precursor_spec(kind)[0].splitlines()) + 1]),
                                 ("sourceSites", [1]*5), ("tracebackLinksSeen", 33),
                                 ("tracebackLinksSeen", True), ("tracebackLinksSeen", 1), ("sourceSitesComplete", 1)):
                bad = {**good, field: value}; bad_records.append(self.record(kind, bad))
            bad_records.append(self.record(kind, {**good, "private": "private-value-canary"}))
            missing = dict(good); missing.pop("reason"); bad_records.append(self.record(kind, missing))
            if kind == "project-recovery-producer":
                bad_records.append(self.record(kind, {**good, "caughtExceptionCategory": "private-caught-canary"}))
            else:
                bad_records.append(self.record(kind, {**good, "caughtExceptionCategory": "none"}))
            for field, changed in (("raised", True), ("raised", 1), ("caught", True), ("caught", 3),
                                   ("boundRoles", []), ("boundRoles", [0, 0]), ("boundRoles", [0, 12]),
                                   ("boundRoles", [True]), ("complete", False), ("nodes", []),
                                   ("nodes", good["exceptionGraph"]["nodes"]*2)):
                bad = deepcopy(good); bad["exceptionGraph"][field] = changed
                bad_records.append(self.record(kind, bad))
            for field, changed in (("category", "PRIVATE_TYPE_CANARY"), ("category", "none"), ("category", "os"),
                                   ("errno", True), ("errno", 4096), ("errno", 13),
                                   ("sites", [[1, 1]]), ("sites", [[False, 1]]), ("sites", [[0, True]]),
                                   ("sites", [[0, 1_000_001]]), ("sites", [[0, 1]]*9),
                                   ("tracebackComplete", False), ("tracebackComplete", 1),
                                   ("unmappedFrames", 1), ("unmappedFrames", True), ("sitesTruncated", True),
                                   ("cause", True), ("cause", -2), ("cause", -1), ("cause", 1),
                                   ("context", "PRIVATE_CONTEXT_CANARY"), ("suppressed", 1)):
                bad = deepcopy(good); bad["exceptionGraph"]["nodes"][0][field] = changed
                bad_records.append(self.record(kind, bad))
            bad = deepcopy(good); bad["exceptionGraph"]["nodes"][0]["private"] = "private-value-canary"
            bad_records.append(self.record(kind, bad))
            for bad in bad_records:
                self.assertIsNone(M._precursor_child_failure(bad, kind))
                if len(bad) > M._precursor_spec(kind)[3]:
                    with self.assertRaises(M.Refused):
                        M._precursor_diagnostic(CompletedProcess([], 1, b"", bad), kind)
                    continue  # Aggregate command cap remains stricter where applicable.
                reduced = M._precursor_diagnostic(CompletedProcess([], 1, b"", bad), kind)
                self.assertNotIn("childFailure", reduced)
                self.assertNotIn("private-", json.dumps(reduced))
            # Conservative serialized bound, including both legacy categories,
            # errno, longest actual closed enums, marker and newline. This is
            # inert bound arithmetic, not a claimed observation/valid graph.
            category = max(M.PRECURSOR_FAILURE_CATEGORIES, key=len)
            worst = deepcopy(good)
            worst.update(reason=max(M._precursor_spec(kind)[2], key=len), exceptionCategory=category,
                         sourceSites=[1_000_000]*4, tracebackLinksSeen=32, sourceSitesComplete=False)
            if kind == "project-recovery-producer": worst["caughtExceptionCategory"] = category
            node = {"category": category, "errno": 4095, "sites": [[11, 1_000_000]]*8,
                    "tracebackLinksSeen": 32, "tracebackComplete": False, "unmappedFrames": 32,
                    "sitesTruncated": False, "cause": None, "context": None, "suppressed": False}
            worst["exceptionGraph"] = {"raised": 0, "caught": None, "nodes": [node]*4,
                                       "complete": False, "boundRoles": list(range(12))}
            self.assertLessEqual(len(self.record(kind, worst)), M.PRECURSOR_FAILURE_LIMIT)
            self.assertEqual(M.PRECURSOR_FAILURE_LIMIT, 2048)

    def test_invalid_entry_exercises_both_actual_footers_without_core_or_native_access(self):
        for kind in ("project-recovery-producer", "ios-account-produce"):
            program = M._precursor_spec(kind)[0]
            stderr = self.invalid_entry(program, [])
            detail = M._precursor_child_failure(stderr, kind)
            self.assertIsNotNone(detail); self.assertTrue(detail["sourceSitesComplete"])
            self.assertGreaterEqual(len(detail["sourceSites"]), 2)
            self.assertEqual(detail["tracebackLinksSeen"], len(detail["sourceSites"]))
            self.assertEqual(detail["reason"], "fixture-check-failed" if kind == "project-recovery-producer" else "native-account-entry")
            self.assertTrue(any("need(len(sys.argv)" in program.splitlines()[site - 1] for site in detail["sourceSites"]))
            graph = detail["exceptionGraph"]
            self.assertEqual(graph["boundRoles"], [0]); self.assertIsNone(graph["caught"])
            self.assertTrue(graph["complete"]); self.assertEqual(len(graph["nodes"]), 1)
            self.assertEqual(graph["nodes"][0]["sites"], [[0, line] for line in detail["sourceSites"]])
            self.assertEqual(graph["nodes"][0]["unmappedFrames"], 0)
            self.assertNotIn(b"Traceback", stderr)

    def test_foreign_string_frames_and_total_traceback_cutoff_never_become_own_sites(self):
        foreign = {}
        exec(compile("def depth(n):\n    if n: return depth(n-1)\n    raise RuntimeError('PRIVATE_FOREIGN_TRACE_CANARY')\n"
                     "def short(self): return depth(0)\ndef long(self): return depth(40)\n", "<string>", "exec"), foreign)
        for kind in ("project-recovery-producer", "ios-account-produce"):
            program = M._precursor_spec(kind)[0]
            expected = {i + 1 for i, line in enumerate(program.splitlines()) if "need(len(sys.argv)" in line or line == "try:main()"}
            for long in (False, True):
                argv = type("ForeignArgv", (), {"__len__": foreign["long" if long else "short"]})()
                stderr = self.invalid_entry(program, argv)
                detail = M._precursor_child_failure(stderr, kind)
                self.assertIsNotNone(detail)
                self.assertEqual(set(detail["sourceSites"]), expected)
                self.assertEqual(detail["sourceSitesComplete"], not long)
                self.assertLessEqual(detail["tracebackLinksSeen"], 32)
                if long: self.assertEqual(detail["tracebackLinksSeen"], 32)
                node = detail["exceptionGraph"]["nodes"][0]
                self.assertEqual(node["tracebackComplete"], not long)
                self.assertGreater(node["unmappedFrames"], 0)
                self.assertEqual(node["sites"], [[0, line] for line in detail["sourceSites"]])
                self.assertNotIn(b"PRIVATE_FOREIGN_TRACE_CANARY", stderr)
        # Existing namespaces only: these are inert synthetic modules, never
        # imported first-party code. Their fixed co_filename is not opened.
        modules = {}
        for name, class_name in (("build_inputs", "BuildInputError"), ("owned_process", "ProcessCleanupError")):
            module = ModuleType("mobile_release." + name)
            module.__file__ = "/inert-precursor-core/mobile_release/" + name + ".py"
            text = ("class " + class_name + "(Exception):\n"
                    "    def __str__(self): raise AssertionError('PRIVATE_STR_CANARY')\n"
                    "    def __repr__(self): raise AssertionError('PRIVATE_REPR_CANARY')\n"
                    "def fail(depth=0):\n"
                    "    if depth: return fail(depth-1)\n"
                    "    raise " + class_name + "('PRIVATE_MESSAGE_CANARY')\n"
                    "def through(callback, depth=12):\n"
                    "    if depth: return through(callback, depth-1)\n"
                    "    callback()\n")
            exec(compile(text, module.__file__, "exec"), module.__dict__)
            modules[module.__name__] = module
        def observed(name, depth=0):
            try: modules["mobile_release." + name].fail(depth)
            except BaseException as error: return error
            self.fail("synthetic exception did not occur")
        for kind in ("project-recovery-producer", "ios-account-produce"):
            project = kind == "project-recovery-producer"
            original = RuntimeError("PRIVATE_OUTER_CANARY") if project else observed("owned_process")
            caught = observed("build_inputs") if project else None
            os_error, value_error = PermissionError(13, "PRIVATE_ACCOUNT_PATH_CANARY"), ValueError("PRIVATE_VALUE_CANARY")
            if project:
                original.__cause__ = caught
                caught.__cause__, caught.__context__ = os_error, value_error
            else:
                original.__cause__, original.__context__ = os_error, value_error
            os_error.__cause__ = original  # A cycle is an original edge, not truncation.
            detail = self.footer(kind, original, caught, modules=modules)
            graph = detail["exceptionGraph"]
            self.assertEqual(graph["caught"], 1 if project else None)
            self.assertTrue(graph["complete"])
            root = graph["nodes"][1 if project else 0]
            self.assertEqual(root["category"], "build-input" if project else "process-cleanup")
            self.assertTrue(any(role == (1 if project else 6) for role, _ in root["sites"]))
            self.assertTrue(any(node["category"] == "permission" and node["errno"] == 13 for node in graph["nodes"]))
            self.assertTrue(any(node["cause"] == 0 for node in graph["nodes"]))
            # A long chain cannot displace the already retained project root.
            value_error.__cause__ = TypeError("PRIVATE_EXTRA_CAUSE")
            value_error.__cause__.__context__ = KeyError("PRIVATE_EXTRA_CONTEXT")
            detail = self.footer(kind, original, caught, modules=modules)
            graph = detail["exceptionGraph"]
            self.assertEqual(len(graph["nodes"]), 4); self.assertFalse(graph["complete"])
            self.assertEqual(graph["caught"], 1 if project else None)
            self.assertTrue(any(node["cause"] == -1 or node["context"] == -1 for node in graph["nodes"]))
        # Admit no same-path foreign namespace and no same-name class. Neither
        # can manufacture a core source/type classification or expose a name.
        core = modules["mobile_release.owned_process"]
        foreign = {"Error": core.ProcessCleanupError}
        exec(compile("def fail():\n    raise Error('PRIVATE_FOREIGN_CORE_CANARY')\n", core.__file__, "exec"), foreign)
        try: foreign["fail"]()
        except BaseException as error: original = error
        detail = self.footer("ios-account-produce", original, modules=modules)
        self.assertEqual(detail["exceptionCategory"], "process-cleanup")
        self.assertFalse(any(role == 6 for role, _ in detail["exceptionGraph"]["nodes"][0]["sites"]))
        unknown = type("ProcessCleanupError", (Exception,), {"__module__": "mobile_release.owned_process"})("PRIVATE_UNKNOWN_CLASS_CANARY")
        detail = self.footer("ios-account-produce", unknown, modules=modules)
        self.assertEqual(detail["exceptionCategory"], "other")
        original = observed("owned_process")
        core.__file__ = "/PRIVATE_WRONG_CORE_PATH_CANARY"
        detail = self.footer("ios-account-produce", original, modules=modules)
        self.assertEqual(detail["exceptionCategory"], "other")
        self.assertNotIn(6, detail["exceptionGraph"]["boundRoles"])
        core.__file__ = "/inert-precursor-core/mobile_release/owned_process.py"
        detail = self.footer("ios-account-produce", observed("owned_process", 12), modules=modules)
        node = detail["exceptionGraph"]["nodes"][0]
        self.assertTrue(node["sitesTruncated"]); self.assertTrue(node["tracebackComplete"])
        self.assertEqual(len(node["sites"]), 8)
        self.assertTrue(detail["sourceSitesComplete"])
        # A later own frame survives legacy cap4 even after eight mixed core
        # sites. Filtering the graph's retained eight would incorrectly lose it.
        detail = self.footer("ios-account-produce", RuntimeError("PRIVATE_MIXED_TRACE_CANARY"),
                             modules=modules, through=core.through)
        node = detail["exceptionGraph"]["nodes"][0]
        self.assertTrue(node["sitesTruncated"]); self.assertTrue(detail["sourceSitesComplete"])
        self.assertIn(2, detail["sourceSites"])
        self.assertNotIn([0, 2], node["sites"])

    def test_footer_reduction_and_emission_faults_keep_nonzero_refusal_without_raw_text(self):
        for program in (M.SHELL_RECOVERY_PRODUCER, M.IOS_ACCOUNT_CORE_PROGRAM):
            self.assertEqual(self.invalid_entry(program, [], encode_fault=True), b"")
            self.assertEqual(self.invalid_entry(program, [], emit_fault=True), b"")


class PendingProjectRecoveryAquaDataTests(unittest.TestCase):
    def test_scope_and_pair_parser_are_closed_without_enabling_ios_modes(self):
        case = M.RECOVERY_CASE
        self.assertEqual(M.selected_cases(case), (case,))
        self.assertEqual(M.argument_scope(["--scope", case]), case)
        self.assertEqual(M.case_timeout(case), 325)
        self.assertEqual(M.selected_cases(), M.CASES)
        self.assertNotIn(case, M.IOS_CURRENT_CASES)
        for args in (["--scope", case, "--retry"], ["--scope", "project-recovery-partial"], [case]):
            with self.assertRaises(M.Refused): M.argument_scope(args)
        value = M.expected_result(BINDING, case)
        self.assertEqual(M.parse_result(captured(value), b"", BINDING, case), value)
        mutations = [("ordinaryProfileAvailableBeforeAdmission", False), ("requests", [1, 1, 1, 2]),
                     ("replies", [1, 1, 1, 0]), ("statusCallsReturned", 97), ("statusCallsReturned", True),
                     ("freshUncheckedReview", False), ("explicitAcknowledgement", False), ("exactSessionReviewed", False),
                     ("signedModesActivated", True), ("shippingBinaryQualified", True), ("hardMs", 130001)]
        for name, changed in mutations:
            bad = deepcopy(value); bad["projectRecovery"][name] = changed
            with self.subTest(name=name), self.assertRaises(M.Refused):
                M.parse_result(captured(bad), b"", BINDING, case)
        checkout = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
        work = Path("/Users/runner/work/_temp/mrk-macos-aqua.ABCDE123")
        for target, release_input, source_lock in ((M.ARM_TARGET, "build-release.json", "source-lock.json"),
                                                  (M.INTEL_TARGET, "build-release-intel.json", "source-lock-intel.json")):
            binding = replace(BINDING, target=target)
            fixture = M.Fixtures(binding, UID, GID, M.RECOVERY_CASE)
            reached = RuntimeError("inert stop before any installed-root open")
            paths = []
            rows = [{"path": name, "sha256": sha * 64, "size": 3} for name, sha in
                    (("core.zip", "4"), ("python/bin/python3", "5"))]
            manifest = {"schemaVersion": 1, "protocol": 1, "coreVersion": "0.1.1", "target": target,
                "coreSha256": rows[0]["sha256"], "protocolSha256": "6" * 64,
                "inventorySha256": M.digest(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("ascii")),
                "files": rows}
            result = {"schemaVersion": 1, "qualification": "current-source-staged-no-native-execution",
                "supplierOrigin": "fresh-public-source", "supplierReceiptSha256": "d" * 64,
                "supplierProfile": "mrk-macos-cpython-source-supplier-v1", "pythonVersion": "3.14.7", "gil": True,
                "supplierSourceLockSha256": "e" * 64, "sourceInputsSha256": "7" * 64,
                "release": M.target_data(target)["releasePrefix"] + "desktop-01", "target": target,
                "coreSha256": manifest["coreSha256"], "protocolSha256": manifest["protocolSha256"],
                "inventorySha256": manifest["inventorySha256"]}
            def read(_parent, name, _uid, _limit):
                path = Path(name); paths.append(path)
                if path == checkout / "desktop/macos-installed-inputs" / release_input:
                    return (), "f" * 64, json.dumps({"schemaVersion": 1, "packageVersion": "0.1.1",
                        "release": M.target_data(target)["releasePrefix"] + "desktop-01"}).encode()
                if path == work / "runtime-result.json":
                    return (), "f" * 64, json.dumps({**result, "successorManifestSha256": M.digest(json.dumps(manifest).encode())}).encode()
                if path == checkout / "desktop/macos-cpython-source-inputs" / source_lock: return (), "e" * 64, b"inert lock"
                self.assertEqual(path, work / "runtime/manifest.json")
                raw = json.dumps(manifest).encode()
                return (), M.digest(raw), raw
            with patch.object(fixture, '_recovery_read', side_effect=read), patch.object(fixture, '_open', side_effect=reached) as opened:
                if target == M.INTEL_TARGET:
                    with self.assertRaisesRegex(M.Refused, '^recovery-intel-fresh-supplier$'):
                        fixture.admit_recovery_runtime(checkout, work)
                    self.assertEqual(paths, [])
                with self.assertRaises(RuntimeError) as caught:
                    fixture.admit_recovery_runtime(checkout, work, supplier_origin="fresh-public-source", supplier_receipt_sha256="d" * 64)
                self.assertIs(caught.exception, reached)
                self.assertEqual(paths[:3], [checkout / "desktop/macos-installed-inputs" / release_input,
                    work / "runtime-result.json", checkout / "desktop/macos-cpython-source-inputs" / source_lock])
                self.assertEqual(paths[3:], [work / "runtime/manifest.json"])
                opened.assert_called_once_with('/', directory=True)
                opened.reset_mock()
                paths.clear(); result['supplierSourceLockSha256'] = 'f' * 64
                with self.assertRaisesRegex(M.Refused, '^recovery-fresh-source-lock$'):
                    fixture.admit_recovery_runtime(checkout, work, supplier_origin="fresh-public-source", supplier_receipt_sha256="d" * 64)
                self.assertEqual(len(paths), 3)
                opened.assert_not_called()
                result['supplierSourceLockSha256'] = 'e' * 64
                opposite = M.INTEL_TARGET if target == M.ARM_TARGET else M.ARM_TARGET
                for value, key, changed, reason in ((result, 'target', opposite, 'recovery-current-runtime-binding'),
                        (result, 'release', 'foreign-release', 'recovery-current-runtime-binding'),
                        (manifest, 'target', opposite, 'recovery-current-manifest')):
                    original = value[key]
                    try:
                        value[key] = changed
                        with self.subTest(target=target, key=key, reason=reason), self.assertRaisesRegex(M.Refused, '^' + reason + '$'):
                            fixture.admit_recovery_runtime(checkout, work, supplier_origin="fresh-public-source", supplier_receipt_sha256="d" * 64)
                    finally:
                        value[key] = original
                    opened.assert_not_called()

    def test_both_originals_every_join_and_exact_review_session_are_required(self):
        good = M._expected_recovery_report()
        for i in (0, 1):
            for key in M.RECOVERY_JOINS:
                bad = deepcopy(good); bad["originals"][i]["facts"][key] = False
                with self.subTest(original=i, join=key), self.assertRaises(M.Refused): M._recovery_report(bad)
            for key in ("noChild", "activeRetained", "resourceUnknown"):
                bad = deepcopy(good); bad["originals"][i]["facts"][key] = True
                with self.subTest(original=i, flag=key), self.assertRaises(M.Refused): M._recovery_report(bad)
            for key, value in (("accepted", False), ("coreTerminal", False), ("coreFatal", True), ("reviewMinted", i != 0)):
                bad = deepcopy(good); bad["originals"][i][key] = value
                with self.subTest(original=i, flag=key), self.assertRaises(M.Refused): M._recovery_report(bad)
        for path, changed in ((["prepared", 1, "operationId"], good["prepared"][0]["operationId"]),
                              (["prepared", 1, "ownerGeneration"], good["prepared"][0]["ownerGeneration"]),
                              (["prepared", 1, "context", "review", "session"], "f"*32),
                              (["prepared", 1, "context", "draftRevision"], 2),
                              (["originals", 1, "projection", "result", "recoveredSession"], "f"*32),
                              (["originals", 0, "projection", "result", "observation", "roles"], ["ios-services"]),
                              (["originals", 0, "projection", "phase"], "unknown")):
            bad = deepcopy(good); cursor = bad
            for part in path[:-1]: cursor = cursor[part]
            cursor[path[-1]] = changed
            with self.subTest(path=path), self.assertRaises(M.Refused): M._recovery_report(bad)

    def test_actual_returned_producer_then_app_then_independent_readback(self):
        fixtures = InertRecoveryFixtures(); calls, emitted = [], []
        fixtures.precursor_diagnostic = {"stale": "must-not-survive"}
        def run(argv, **options):
            calls.append((tuple(argv), options))
            if len(calls) == 1:
                self.assertTrue(fixtures.inflight); self.assertFalse(fixtures.last_returned)
                self.assertEqual(options["timeout"], 30); self.assertEqual(options["output_limit"], 2048)
                self.assertEqual(argv[1:6], ["-I", "-S", "-B", "-c", M.SHELL_RECOVERY_PRODUCER])
                return CompletedProcess(argv, 0, json.dumps(inert_recovery_producer()).encode() + b"\n", b"")
            self.assertEqual(len(calls), 2); self.assertEqual(argv, [M.EXECUTABLE, M.RECOVERY_CASE])
            self.assertEqual(options["timeout"], 325)
            return CompletedProcess(argv, 0, captured(M.expected_result(BINDING, M.RECOVERY_CASE)), b"")
        self.assertEqual(M.run_cases(BINDING, fixtures, run, UID, "runner", emitted.append, M.RECOVERY_CASE), ())
        self.assertEqual(len(calls), 2); self.assertEqual(len(fixtures.accepted), 1)
        self.assertIsNone(fixtures.precursor_diagnostic)
        self.assertEqual(fixtures.before, [M.RECOVERY_CASE]); self.assertEqual(fixtures.reads, [M.RECOVERY_CASE])
        self.assertEqual(len(emitted), 1); self.assertTrue(fixtures.last_returned); self.assertFalse(fixtures.inflight)
        output = io.StringIO(); M.emit_record(emitted[0], output)
        self.assertLessEqual(len(output.getvalue().encode()), 24*1024+1)

    def test_unknown_producer_return_preserves_original_and_never_reads_or_dispatches(self):
        error = RuntimeError("inert original exception")
        for kind in ("exception", "none", "foreign", "wrong-argv", "wrong-buffer", "oversize"):
            fixtures = InertRecoveryFixtures(); calls, emitted = [], []
            def run(argv, **options):
                calls.append(argv)
                if kind == "exception": raise error
                if kind == "none": return None
                if kind == "foreign": return SimpleNamespace(args=argv, returncode=0, stdout=b"{}\n", stderr=b"")
                return CompletedProcess(["foreign"] if kind == "wrong-argv" else argv, 0,
                                        "{}\n" if kind == "wrong-buffer" else b"x"*2049 if kind == "oversize" else b"{}\n", b"")
            fixtures.precursor_diagnostic = {"stale": "must-not-survive"}
            with patch.object(M, "_precursor_diagnostic", side_effect=AssertionError("unknown original is not readable")) as reduced:
                with self.subTest(kind=kind), self.assertRaises((M.Refused, RuntimeError)) as caught:
                    M.run_cases(BINDING, fixtures, run, UID, "runner", emitted.append, M.RECOVERY_CASE)
            reduced.assert_not_called(); self.assertIsNone(fixtures.precursor_diagnostic)
            if kind == "exception": self.assertIs(caught.exception, error)
            self.assertEqual(len(calls), 1); self.assertTrue(fixtures.inflight); self.assertFalse(fixtures.last_returned)
            self.assertEqual((fixtures.before, fixtures.reads, fixtures.accepted, emitted), ([], [], [], []))
            with self.assertRaises(M.Refused): M.Fixtures.close(fixtures)

    def test_semantic_producer_failure_is_not_permission_for_fixture_work_or_app(self):
        for kind in ("exit", "stderr", "json", "incomplete", "lifetime", "wrong-restoration"):
            fixtures = InertRecoveryFixtures(); calls, emitted = [], []
            value = inert_recovery_producer()
            if kind == "incomplete": value.pop("invocationReleased")
            if kind == "lifetime": value["attemptedDescriptorsClosed"] = False
            if kind == "wrong-restoration": value["restored"]["ios-services"] = True
            def run(argv, **options):
                calls.append(argv)
                return CompletedProcess(argv, 1 if kind == "exit" else 0,
                                        b"invalid\n" if kind == "json" else json.dumps(value).encode() + b"\n",
                                        b"unexpected" if kind == "stderr" else b"")
            with self.subTest(kind=kind), self.assertRaises((M.Refused, ValueError)):
                M.run_cases(BINDING, fixtures, run, UID, "runner", emitted.append, M.RECOVERY_CASE)
            self.assertEqual(len(calls), 1); self.assertFalse(fixtures.inflight); self.assertTrue(fixtures.last_returned)
            self.assertEqual((fixtures.before, fixtures.reads, fixtures.accepted, emitted), ([], [], [], []))
            self.assertEqual(fixtures.precursor_diagnostic["kind"], "project-recovery-producer")
            self.assertEqual(fixtures.precursor_diagnostic["returncode"], 1 if kind == "exit" else 0)
            self.assertEqual(fixtures.precursor_diagnostic["envelope"]["emptyStderr"], kind != "stderr")
            self.assertIsNone(fixtures.app_returncode); self.assertIsNone(fixtures.inner_failure_reason)
            M.Fixtures.close(fixtures)  # Empty inert original book, no OS close.

    def test_precursor_reducer_fault_preserves_identical_semantic_error_and_no_next_call(self):
        fixture = InertRecoveryFixtures(); calls, emitted = [], []
        original = M.Refused("recovery-producer-failed")
        def owner(argv, **options):
            calls.append(argv)
            return CompletedProcess(argv, 1, b"", b"private-buffer-canary")
        with patch.object(M, "recovery_producer_result", side_effect=original), \
                patch.object(M, "_precursor_diagnostic", side_effect=RuntimeError("private-reducer-canary")) as reduced:
            with self.assertRaises(M.Refused) as raised:
                M.run_cases(BINDING, fixture, owner, UID, "runner", emitted.append, M.RECOVERY_CASE)
        self.assertIs(raised.exception, original); reduced.assert_called_once()
        self.assertEqual(len(calls), 1); self.assertFalse(fixture.inflight); self.assertTrue(fixture.last_returned)
        self.assertIsNone(fixture.precursor_diagnostic)
        self.assertEqual((fixture.before, fixture.reads, fixture.accepted, emitted), ([], [], [], []))

    def test_four_inventory_stages_preserve_exact_full9_and_original_restoration(self):
        stages = inert_recovery_inventories()
        summary = M._recovery_final(*stages, UID, GID)
        self.assertEqual([row["stage"] for row in summary["inventories"]], ["initial", "generated", "before", "after"])
        self.assertTrue(summary["originalTargetsRestored"]); self.assertTrue(summary["foreignPreserved"])
        self.assertFalse(summary["privateContentsExported"])
        raw = M._recovery_inventory_bytes(stages[0]); data = json.loads(raw)
        self.assertGreater(data["project"]["identity"][1], 2**53)
        self.assertEqual(tuple(data["project"]["identity"]), stages[0]["project"].identity)
        for path in ("project/unrelated.txt", "project/saved-foreign-ios", "project/GoogleService-Info.plist", "project/google-services.json"):
            bad = list(stages); bad[3] = dict(bad[3]); row = bad[3][path]
            bad[3][path] = replace(row, identity=(row.identity[0], row.identity[1]+1000, *row.identity[2:]))
            with self.subTest(substitution=path), self.assertRaises(M.Refused): M._recovery_final(*bad, UID, GID)
        for mode in ("missing", "gap", "modified"):
            bad = list(stages); bad[1] = dict(bad[1]); name = "project/.mobile-release/build-inputs/checkpoint-000.json"
            row = bad[1].pop(name)
            if mode == "gap": bad[1][name.replace("000", "001")] = row
            if mode == "modified": bad[1][name] = replace(row, sha256="a"*64)
            with self.subTest(checkpoint=mode), self.assertRaises(M.Refused): M._recovery_final(*bad, UID, GID)

    def test_exclusive_darwin_rename_is_one_fixed_call_and_collision_never_falls_back(self):
        # Deliberately inert ctypes module: this test never loads a library or
        # invokes a native operation, including on a genuine Mac test host.
        for returned in (0, -1):
            calls, loads = [], []
            class Rename:
                def __call__(self, *args): calls.append(args); return returned
            rename = Rename(); fake = ModuleType("ctypes")
            fake.c_int, fake.c_char_p, fake.c_uint = object(), object(), object()
            fake.get_errno = lambda: 17
            def load(name, **options): loads.append((name, options)); return SimpleNamespace(renameatx_np=rename)
            fake.CDLL = load
            with patch.object(M.sys, "platform", "darwin"), patch.dict(sys.modules, {"ctypes": fake}):
                if returned:
                    with self.assertRaises(OSError) as caught: M._preserve_recovery_conflict_exclusive(17)
                    self.assertEqual(caught.exception.errno, 17)
                else: M._preserve_recovery_conflict_exclusive(17)
            self.assertEqual(loads, [("/usr/lib/libSystem.B.dylib", {"use_errno": True})])
            self.assertEqual(calls, [(17, b"GoogleService-Info.plist", 17, b"saved-foreign-ios", 4)])
            self.assertEqual(rename.argtypes, [fake.c_int, fake.c_char_p, fake.c_int, fake.c_char_p, fake.c_uint])
            self.assertIs(rename.restype, fake.c_int)

    def test_workflow_support_is_targeted_and_keeps_the_selected_matrix(self):
        root = PATH.parents[2]
        workflow = (root / ".github/workflows/desktop-macos-aqua.yml").read_text()
        header = workflow.split("    runs-on:", 1)[0]
        matrix = header.split("      matrix:\n", 1)[1]
        self.assertEqual(matrix, "        include:\n          - scope: local-edits3\n            target: aarch64-apple-darwin\n            runner: macos-26\n            supplier_receipt: '2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d'\n            supplier_tar: 'ff7883185cf8226e9366b1ee9a3dcb3eb8ee761dbc1f697f952510a6bd858695'\n            supplier_source: '158cdff422e3837f7ab5e6192af76a578faf6fab'\n            supplier_run: '37467019389'\n            supplier_attempt: '1'\n            supplier_artifact: '11415902210'\n          - scope: local-edits3\n            target: x86_64-apple-darwin\n            runner: macos-26-intel\n            supplier_receipt: 'a46f6838afdb7c20c3539e8f65891312aa8df10e2de67e9b9e3ddbf449883b4b'\n            supplier_tar: '739cc8b8b3c68daffba8d7b9cb7cb54ca730eef2c5842302ae8a2682bf64d5bd'\n            supplier_source: '079ab2a2c8fef88f01bf909e7669c685f07e1375'\n            supplier_run: '37476532238'\n            supplier_attempt: '1'\n            supplier_artifact: '11419502465'\n")
        selected = [line.strip()[len("- scope: "):] for line in matrix.splitlines() if line.strip().startswith("- scope: ")]
        # Recovery stays implemented but unselected; only the paired local3 cohort runs.
        self.assertEqual(selected, ["local-edits3", "local-edits3"])
        blocks = dict(block.split("\n", 1) for block in workflow.split("      - name: ")[1:])
        step = blocks["One real pending iOS build-input recovery through ordinary Inspect and explicit Recover"]
        self.assertIn("if: success() && env.MRK_MACOS_AQUA_SCOPE == 'project-recovery-pending'", step)
        self.assertIn("timeout-minutes: 7", step)
        self.assertEqual(step.count("macos_aqua_qualification.py --scope project-recovery-pending"), 1)
        self.assertIn("[[ $status == 0 ]]", step)
        self.assertNotIn("continue-on-error", step)
        for name in ("aqua-project-recovery-results.jsonl", "aqua-project-recovery-failure.jsonl", "aqua-project-recovery.status"):
            self.assertIn("${{ steps.work.outputs.root }}/" + name, workflow)
        for name in ("recovery-initial.json", "recovery-generated.json", "recovery-before.json", "recovery-after.json"):
            self.assertNotIn(name, workflow)
        for name, body in blocks.items():
            if "xcode-installed-classification" in name.lower() or "wrapping" in name.lower():
                self.assertNotIn("--scope project-recovery-pending", body)


class ShippingCapacityDataWiringTests(unittest.TestCase):
    def test_three_exact_names_use_ordinary_mac_module_without_changing_thirteen(self):
        prefix = 'installed_runtime::android_registration_source::storage_capacity_tests::'
        names = ('phase_checked_allocation_uses_exact_admitted_records_without_native_entry',
                 'source_heap_formula_keeps_fourth_alias_string_and_checked_limits',
                 'observed_sha_text_has_exact_charged_capacity')
        self.assertEqual(M.SHIPPING_CAPACITY_TESTS, tuple(prefix + name for name in names))
        source = (PATH.parents[2] / 'desktop/src-tauri/src/android_registration_source_macos.rs').read_text()
        for name in names:
            self.assertIn('fn ' + name + '()', source)
        ordinary = (PATH.parents[2] / 'desktop/src-tauri/src/installed_runtime_macos.rs').read_text()
        self.assertIn('#[cfg(not(feature = "macos-android-registration-helper"))]\n#[path = "android_registration_source_macos.rs"]\nmod android_registration_source;', ordinary)
        main = (PATH.parents[2] / 'desktop/src-tauri/src/lib.rs').read_text()
        self.assertIn('#[cfg(all(target_os = "macos", target_arch = "aarch64"))]\n#[path = "installed_runtime_macos.rs"]\nmod installed_runtime;', main)
        checkout, work, bodies, _receipt, _rows = shipping_gate_headless_data()
        receipt, _native = M._gate_headless(bodies, BINDING, checkout, work)
        self.assertEqual((len(M.SHIPPING_GATE_MAIN_TESTS), len(M.SHIPPING_GATE_NATIVE_TESTS)), (6, 7))
        self.assertEqual((receipt['tests'], receipt['ownerCallsEntered'], receipt['ownerCallsReturned']), (13, 3, 3))
        self.assertEqual(receipt['targets'][0]['features'], [])
        self.assertTrue(set(M.SHIPPING_CAPACITY_TESTS).isdisjoint(receipt['names']))

    def test_workflow_keeps_one_separate_shipping_only_call_before_follow_on_builds(self):
        workflow = (PATH.parents[2] / '.github/workflows/desktop-macos-aqua.yml').read_text()
        blocks = dict(block.split('\n', 1) for block in workflow.split('      - name: ')[1:])
        label = 'Three ordinary Mac capacity DATA cases from the same compiled app-test original'
        step = blocks[label]
        self.assertIn("if: success() && (env.MRK_MACOS_AQUA_SCOPE == 'vault-helper-shipping' || env.MRK_MACOS_AQUA_SCOPE == 'vault-helper-shipping-installation-inspection')", step)
        self.assertIn('timeout-minutes: 2', step)
        self.assertIn('RUNNER_ENVIRONMENT: ${{ runner.environment }}', step)
        self.assertEqual(step.count('qualification.shipping_capacity_data_main(target=os.environ["MRK_MACOS_TARGET"])'), 1)
        self.assertIn('[[ "$status" == 0 && "$saved" == 0 ]]', step)
        for forbidden in ('cargo ', '--features', '--ignored', 'continue-on-error', 'workflow_dispatch'):
            self.assertNotIn(forbidden, step)
        self.assertLess(workflow.index('      - name: Compile headless Mac libraries'), workflow.index('      - name: ' + label))
        self.assertLess(workflow.index('      - name: ' + label), workflow.index('      - name: Compile native wrapping variants once'))
        self.assertIn(
            "        include:\n          - scope: local-edits3\n            target: aarch64-apple-darwin\n            runner: macos-26\n            supplier_receipt: '2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d'\n            supplier_tar: 'ff7883185cf8226e9366b1ee9a3dcb3eb8ee761dbc1f697f952510a6bd858695'\n            supplier_source: '158cdff422e3837f7ab5e6192af76a578faf6fab'\n            supplier_run: '37467019389'\n            supplier_attempt: '1'\n            supplier_artifact: '11415902210'\n          - scope: local-edits3\n            target: x86_64-apple-darwin\n            runner: macos-26-intel\n            supplier_receipt: 'a46f6838afdb7c20c3539e8f65891312aa8df10e2de67e9b9e3ddbf449883b4b'\n            supplier_tar: '739cc8b8b3c68daffba8d7b9cb7cb54ca730eef2c5842302ae8a2682bf64d5bd'\n            supplier_source: '079ab2a2c8fef88f01bf909e7669c685f07e1375'\n            supplier_run: '37476532238'\n            supplier_attempt: '1'\n            supplier_artifact: '11419502465'\n    runs-on: ${{ matrix.runner }}\n", workflow)
        headless = aqua_headless_source()
        self.assertNotIn('SHIPPING_CAPACITY', headless)
        self.assertIn('main_count, native_count = 6, 7', headless)
        self.assertIn('calls_entered == calls_returned == 3', headless)
        control = blocks['One installed no-GO shipping-helper gate-custody control before any Aqua entry']
        self.assertIn('qualification.shipping_gate_control_main(target=os.environ["MRK_MACOS_TARGET"])', control)
        self.assertNotIn('capacity', control)
        upload = blocks['Preserve bounded original evidence; upload alone is not an Aqua pass']
        unrelated = blocks['Preserve bounded Android lifecycle results and original workflow exit evidence']
        for name in (M.SHIPPING_CAPACITY_REPORT, M.SHIPPING_CAPACITY_STATUS):
            self.assertEqual(upload.count('${{ steps.work.outputs.root }}/' + name), 1)
            self.assertNotIn(name, unrelated)
        added = PATH.read_text().split('# Independent capacity DATA3', 1)[1].split('\ndef diagnostic(', 1)[0]
        for forbidden in ('os.unlink(', 'shutil.rmtree', 'subprocess.run(', '_gate_settle(', '_gate_dependencies('):
            self.assertNotIn(forbidden, added)

    def test_dependency_admission_reuses_unchanged_thirteen_and_rejects_feature_or_receipt_drift(self):
        for binding in (BINDING, replace(BINDING, target=M.INTEL_TARGET)):
            checkout, work, base_bodies, base_receipt, base_rows = shipping_gate_headless_data(binding)
            work_values = tuple(int(value) for value in base_receipt['workOriginal']) + (2, 4096, 2**60, 2**60)
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            work_stat = SimpleNamespace(**dict(zip(fields, work_values)))
            expected_names = {'headless-tests.receipt.json', 'headless-build.jsonl', 'headless-build.status'}
            for prefix in ('headless', 'headless-native'):
                expected_names.update(prefix + suffix for suffix in ('-tests.stdout', '-tests.stderr', '-tests.status'))
            def invoke(receipt, rows, environment=None):
                bodies = dict(base_bodies)
                bodies['headless-build.jsonl'] = b''.join(json.dumps(row).encode() + b'\n' for row in rows)
                receipt = deepcopy(receipt)
                receipt['compilerJsonSha256'] = M.digest(bodies['headless-build.jsonl'])
                bodies['headless-tests.receipt.json'] = json.dumps(receipt).encode()
                seen, fixture = [], SimpleNamespace()
                def read(current, name, parent, limit):
                    self.assertIs(current, fixture); self.assertEqual(parent, 17)
                    seen.append((name, limit))
                    return bodies[name], {}
                environment = environment if environment is not None else {
                    'MRK_MACOS_AQUA_SCOPE': M.VAULT_HELPER_SCOPE, 'CARGO_TARGET_DIR': str(work / 'cargo-target')}
                with patch.object(M, '_gate_directory', return_value=17), patch.object(M, '_gate_file', read), \
                     patch.object(M.os, 'fstat', return_value=work_stat):
                    result = M._capacity_dependencies(fixture, binding, checkout, work, environment)
                self.assertEqual({name for name, _limit in seen}, expected_names)
                self.assertEqual(len(seen), 9)
                self.assertEqual(dict(seen)['headless-tests.receipt.json'], 16384)
                self.assertEqual(dict(seen)['headless-build.jsonl'], 4 * 1024 * 1024)
                self.assertEqual(dict(seen)['headless-build.status'], 4)
                for prefix in ('headless', 'headless-native'):
                    self.assertEqual([dict(seen)[prefix + suffix] for suffix in ('-tests.stdout', '-tests.stderr', '-tests.status')], [65536, 65536, 4])
                return result
            _bodies, headless, app = invoke(base_receipt, base_rows)
            self.assertEqual(app, headless['targets'][0]['artifact'])
            self.assertNotEqual(app['path'], headless['targets'][1]['artifact']['path'])
            self.assertEqual((headless['tests'], headless['ownerCallsEntered'], headless['ownerCallsReturned']), (13, 3, 3))
            for key, value in (('tests', 16), ('ownerCallsEntered', 4), ('ownerCallsReturned', 4),
                               ('names', base_receipt['names'] + list(M.SHIPPING_CAPACITY_TESTS)), ('passed', 1), ('workOriginal', ['7', '999', *base_receipt['workOriginal'][2:]])):
                with self.subTest(key=key), self.assertRaises(M.Refused):
                    invoke({**base_receipt, key: value}, base_rows)
            changed_rows = deepcopy(base_rows)
            changed_rows[0]['features'] = ['macos-android-registration-helper']
            with self.assertRaises(M.Refused):
                invoke(base_receipt, changed_rows)
            for environment in ({'MRK_MACOS_AQUA_SCOPE': M.RECOVERY_CASE, 'CARGO_TARGET_DIR': str(work / 'cargo-target')},
                                {'MRK_MACOS_AQUA_SCOPE': M.VAULT_HELPER_SCOPE, 'CARGO_TARGET_DIR': str(work / 'other-target')}):
                with self.subTest(environment=environment), self.assertRaises(M.Refused):
                    invoke(base_receipt, base_rows, environment)
            opposite = M.INTEL_TARGET if binding.target == M.ARM_TARGET else M.ARM_TARGET
            changed = deepcopy(base_receipt)
            changed["compilerArgv"] = M.shipping_gate_compiler_argv(opposite)
            with self.assertRaises(M.Refused):
                invoke(changed, base_rows)

    def test_exact_capacity_three_output_never_accepts_missing_ignored_or_duplicate_cases(self):
        names = M.SHIPPING_CAPACITY_TESTS
        good = shipping_gate_libtest_data(names)
        self.assertEqual(M._gate_libtest(good, b'', 0, names), 19)
        variants = (shipping_gate_libtest_data(names[:2]), shipping_gate_libtest_data((names[0], names[0], names[2])),
                    good.replace(b' ... ok', b' ... ignored', 1), good.replace(b'0 ignored', b'1 ignored'),
                    good.replace(b'3 passed', b'0 passed'), good + b'unowned extra row\n')
        for raw in variants:
            with self.subTest(raw=raw[:40]), self.assertRaises(M.Refused):
                M._gate_libtest(raw, b'', 0, names)
        for stderr, code in ((b'inert stderr', 0), (b'', 1), (b'', True)):
            with self.subTest(code=code), self.assertRaises(M.Refused):
                M._gate_libtest(good, stderr, code, names)

    def run_inert_capacity(self, outcome):
        # Disposable DATA-only files and an injected non-executing callable.
        # No native process, genuine input or evidence file exists in this test.
        with tempfile.TemporaryDirectory(prefix='mrk-capacity-wiring-data-') as temporary:
            work = Path(temporary); target = work / 'cargo-target'; relative = Path('aarch64-apple-darwin/debug/deps')
            deps = target / relative
            deps.mkdir(parents=True)
            for path in (work, target, target / 'aarch64-apple-darwin', target / 'aarch64-apple-darwin/debug', deps): path.chmod(0o700)
            binary, native = deps / 'mobile_release_desktop-123abc', deps / 'mrk_macos_installed_native-123abc'
            for path in (binary, native):
                path.write_bytes(b'inert DATA, never executed by this test\n'); path.chmod(0o700)
            input_path = work / 'inert-headless-data'
            input_path.write_bytes(b'inert headless DATA'); input_path.chmod(0o600)
            original = M.signature(binary.stat())
            target_original, native_original = M.signature(target.stat())[:5], (M.signature(native.stat()), M.digest(native.read_bytes()))
            app = {'path': str(binary), 'sha256': M.digest(binary.read_bytes()), 'full9': [str(v) for v in original],
                   'identity': [original[0], original[1], original[2], original[5], original[3], original[4], *original[6:]]}
            headless = {'cargoTargetOriginal': [str(v) for v in target_original], 'compilerJsonSha256': 'b' * 64}
            if outcome == 'pre-artifact-hash': app['sha256'] = '0' * 64
            if outcome == 'pre-target-identity': headless['cargoTargetOriginal'][1] = str(target_original[1] + 1)
            fixtures = M.Fixtures(BINDING, M.os.getuid(), M.os.getgid(), M.VAULT_HELPER_SCOPE)
            calls, closes, retirements, reads, ticks = [], [], [], [], []
            real_close, real_rmdir, close_original, read_original = M.os.close, M.os.rmdir, fixtures._close, M._gate_file
            sentinel = RuntimeError('private exception text must not be exported')
            def dependencies(current, binding, checkout, selected, environment):
                self.assertIs(current, fixtures); self.assertEqual(selected, work)
                fixtures.gate_work = M._gate_directory(fixtures, str(work), private=True)
                body, _record = M._gate_file(fixtures, input_path.name, fixtures.gate_work, 16384)
                return {'headless-tests.receipt.json': body}, headless, app
            def read(current, name, parent, limit, *, capture=True):
                reads.append(name)
                return read_original(current, name, parent, limit, capture=capture)
            def owner(argv, **kwargs):
                calls.append((list(argv), kwargs))
                self.assertEqual(argv, [str(binary), '--exact', '--test-threads=1', '--color=never', '--format=pretty', *M.SHIPPING_CAPACITY_TESTS])
                self.assertEqual(kwargs, {'environ': {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(work / 'shipping-capacity-data/home'),
                    'TMPDIR': str(work / 'shipping-capacity-data/tmp'), 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'},
                    'cwd': work / 'shipping-capacity-data', 'timeout': 30, 'capture': True, 'text': False, 'output_limit': 65536})
                if outcome == 'owner-exception': raise sentinel
                if outcome == 'foreign-return': return CompletedProcess(['foreign'], 0, b'', b'')
                if outcome == 'bool-returncode': return CompletedProcess(argv, True, b'', b'')
                if outcome == 'text-output': return CompletedProcess(argv, 0, 'inert text, not bytes', b'')
                if outcome == 'oversize-output': return CompletedProcess(argv, 0, b'x' * 65537, b'')
                if outcome == 'changed-artifact': binary.write_bytes(b'changed inert original')
                if outcome == 'replaced-artifact':
                    binary.rename(deps / 'retained-original-app')
                    binary.write_bytes(b'inert replacement'); binary.chmod(0o700)
                if outcome == 'changed-input': input_path.write_bytes(b'changed inert source')
                if outcome == 'replaced-target':
                    target.rename(work / 'retained-original-target'); target.mkdir(mode=0o700)
                stdout = shipping_gate_libtest_data(M.SHIPPING_CAPACITY_TESTS[:2] if outcome == 'two-tests' else M.SHIPPING_CAPACITY_TESTS)
                if outcome == 'ignored-case': stdout = stdout.replace(b' ... ok', b' ... ignored', 1)
                return CompletedProcess(argv, 1 if outcome == 'primary-and-close' else 0, stdout,
                                        b'inert stderr' if outcome == 'stderr' else b'')
            def close(fd):
                closes.append(fd)
                real_close(fd)
                if outcome in ('close-error', 'primary-and-close') and fixtures.gate_artifact is not None and fd == fixtures.gate_artifact['fd']:
                    raise OSError('inert reporting failure after one actual DATA close')
                if outcome == 'directory-close' and fd == fixtures.gate_work:
                    raise OSError('inert original-directory close reporting failure')
            def close_entry(fd):
                if outcome == 'unexpected-close-call' and fixtures.gate_artifact is not None and fd == fixtures.gate_artifact['fd']:
                    closes.append(fd)
                    raise RuntimeError('inert consuming call without a known close result')
                return close_original(fd)
            def rmdir(name, *, dir_fd=None):
                retirements.append(name)
                if outcome == 'retirement-error' and name == 'tmp': raise OSError('inert empty-directory refusal')
                return real_rmdir(name, dir_fd=dir_fd)
            start = 2**60 + 123
            readings = iter((start, start + (30_000_000_000 if outcome == 'late-return' else 100),
                             start + (30_000_000_001 if outcome == 'late-return' else 30_000_000_000 if outcome == 'late-final-close'
                                      else 50 if outcome == 'backwards-final-clock' else 200)))
            def clock():
                value = next(readings); ticks.append(value)
                if len(ticks) == 3:
                    self.assertTrue(closes)  # The final gate is after consuming-close attempts.
                return value
            try:
                with patch.object(M, '_capacity_dependencies', dependencies), patch.object(M, '_gate_file', read), \
                     patch.object(M.os, 'close', close), patch.object(fixtures, '_close', close_entry), patch.object(M.os, 'rmdir', rmdir):
                    result = M.run_shipping_capacity_data(BINDING, fixtures, owner, PATH.parents[2], work,
                        {'MRK_MACOS_AQUA_SCOPE': M.VAULT_HELPER_SCOPE}, clock=clock)
                pre_refused = outcome in ('pre-artifact-hash', 'pre-target-identity')
                unknown = outcome in ('owner-exception', 'foreign-return', 'bool-returncode', 'text-output', 'oversize-output')
                self.assertEqual(len(calls), 0 if pre_refused else 1)
                self.assertEqual(result['ownerCallsEntered'], len(calls))
                self.assertEqual(result['ownerCallsReturned'], 0 if pre_refused or unknown else 1)
                self.assertNotIn('private exception text', json.dumps(result))
                self.assertNotIn(native.name, reads)
                self.assertFalse(result['artifactRetired']); self.assertFalse(result['cargoTargetRetired'])
                retained_target = work / 'retained-original-target' if outcome == 'replaced-target' else target
                retained_native = retained_target / relative / native.name
                self.assertEqual(M.signature(retained_target.stat())[:5], target_original)
                self.assertEqual((M.signature(retained_native.stat()), M.digest(retained_native.read_bytes())), native_original)
                self.assertTrue((retained_target / relative / binary.name).exists())
                if unknown:
                    self.assertTrue(fixtures.inflight); self.assertFalse(result['originalCallReturned'])
                    self.assertEqual(closes, []); self.assertEqual(retirements, []); self.assertEqual(len(ticks), 1)
                    self.assertTrue(fixtures.fds); self.assertEqual(result['artifactCloseAttempts'], 0)
                    self.assertIsNone(result['stdoutSha256']); self.assertIsNone(result['finalElapsedNanoseconds'])
                else:
                    self.assertFalse(fixtures.inflight)
                    self.assertEqual(len(closes), len(set(closes)))
                    self.assertEqual(result['artifactCloseAttempts'], 0 if outcome == 'pre-target-identity' else 1)
                    self.assertEqual(len(ticks), 0 if pre_refused else 3)
                    if outcome == 'unexpected-close-call':
                        self.assertEqual(fixtures.fds, {fixtures.gate_artifact['fd']}); self.assertEqual(retirements, [])
                    else:
                        self.assertFalse(fixtures.fds)
                self.assertEqual(result['passed'], outcome == 'pass')
                if outcome == 'pass':
                    self.assertIsNone(result['failure']); self.assertEqual(result['cleanupErrors'], [])
                    self.assertEqual(retirements, ['tmp', 'home', 'shipping-capacity-data'])
                    self.assertTrue(result['fixtureDirectoriesRetired']); self.assertTrue(result['fixtureHandlesClosed'])
                    self.assertTrue(result['deadlineMetAfterFinalCloses']); self.assertEqual(result['ownerElapsedNanoseconds'], '100')
                    self.assertEqual(result['finalElapsedNanoseconds'], '200')
                    self.assertEqual((result['tests'], result['failed'], result['ignored'], result['measured']), (3, 0, 0, 0))
                    for flag in ('nativeSourceOperationQualified', 'genuineCatalogueQualified', 'combinedBudgetFitEstablished', 'shippingBinaryQualified', 'distributionQualified'):
                        self.assertFalse(result[flag])
                return result
            finally:
                # Only the fake's no-process construction authorizes this
                # test-side DATA cleanup, never a runtime UNKNOWN observation.
                fixtures.inflight = False
                for fd in tuple(fixtures.fds):
                    try: close_original(fd)
                    except OSError: pass

    @unittest.skipUnless(M.os.name == 'posix', 'POSIX DATA-only original FD fixture')
    def test_live_app_or_target_binding_failure_stops_before_any_owner_call(self):
        for outcome in ('pre-artifact-hash', 'pre-target-identity'):
            with self.subTest(outcome=outcome):
                result = self.run_inert_capacity(outcome)
                self.assertFalse(result['originalCallReturned']); self.assertIsNotNone(result['failure'])
                self.assertFalse(result['fixtureDirectoriesRetired'])

    @unittest.skipUnless(M.os.name == 'posix', 'POSIX DATA-only original FD fixture')
    def test_unknown_or_malformed_original_return_never_rechecks_closes_or_retires(self):
        for outcome in ('owner-exception', 'foreign-return', 'bool-returncode', 'text-output', 'oversize-output'):
            with self.subTest(outcome=outcome):
                result = self.run_inert_capacity(outcome)
                self.assertFalse(result['sourceReadbacksUnchanged']); self.assertFalse(result['fixtureHandlesClosed'])
                self.assertFalse(result['deadlineMetAfterFinalCloses'])

    @unittest.skipUnless(M.os.name == 'posix', 'POSIX DATA-only original FD fixture')
    def test_known_original_finality_requires_exact_three_postchecks_once_closes_and_same_final_deadline(self):
        for outcome in ('pass', 'two-tests', 'ignored-case', 'stderr', 'late-return', 'late-final-close', 'backwards-final-clock',
                        'changed-artifact', 'replaced-artifact', 'changed-input', 'replaced-target',
                        'close-error', 'unexpected-close-call', 'retirement-error', 'primary-and-close', 'directory-close'):
            with self.subTest(outcome=outcome):
                result = self.run_inert_capacity(outcome)
                self.assertTrue(result['originalCallReturned'])
                if outcome == 'late-final-close':
                    self.assertTrue(result['namedTestsPassed']); self.assertTrue(result['fixtureHandlesClosed'])
                    self.assertFalse(result['deadlineMetAfterFinalCloses'])
                    self.assertEqual(result['finalElapsedNanoseconds'], '30000000000')
                    self.assertEqual(result['failure']['reason'], 'capacity-final-deadline')
                elif outcome == 'late-return':
                    self.assertTrue(result['fixtureHandlesClosed']); self.assertFalse(result['deadlineMetAfterFinalCloses'])
                    self.assertEqual(result['failure']['reason'], 'capacity-owner-deadline')
                elif outcome == 'backwards-final-clock':
                    self.assertTrue(result['fixtureHandlesClosed']); self.assertFalse(result['deadlineMetAfterFinalCloses'])
                    self.assertEqual(result['failure']['reason'], 'capacity-final-clock')
                elif outcome == 'primary-and-close':
                    self.assertEqual(result['failure']['reason'], 'gate-libtest-original-result')
                    self.assertTrue(result['cleanupErrors']); self.assertFalse(result['artifactOriginalClosed'])
                elif outcome in ('close-error', 'unexpected-close-call', 'retirement-error', 'directory-close'):
                    self.assertTrue(result['cleanupErrors'])
                elif outcome in ('changed-artifact', 'replaced-artifact', 'changed-input', 'replaced-target'):
                    self.assertFalse(result['sourceReadbacksUnchanged']); self.assertIsNotNone(result['failure'])

    def test_entry_reports_nonzero_for_failure_without_native_admission_or_retry(self):
        environment = {'MRK_MACOS_AQUA_SCOPE': M.VAULT_HELPER_SCOPE, 'MRK_MACOS_WORK': '/inert/work'}
        for passed in (True, False, 1):
            result = M._capacity_new_report(BINDING, M.VAULT_HELPER_SCOPE)
            result['passed'] = passed
            emitted, owner = [], SimpleNamespace(run_owned=lambda *_args, **_kwargs: self.fail('no native owner permitted'))
            with patch.dict(M.os.environ, environment, clear=True), patch.object(M, 'admit', return_value=(BINDING, UID, GID, 'inert')), \
                 patch.object(M, 'load_owner', return_value=owner), patch.object(M.os, 'umask'), \
                 patch.object(M, 'run_shipping_capacity_data', return_value=result) as run, patch.object(M, 'emit_record', side_effect=lambda value, stream: emitted.append(value)):
                status = M.shipping_capacity_data_main()
            self.assertEqual(status, 0 if passed is True else 1)
            self.assertEqual(run.call_count, 1); self.assertEqual(emitted, [result])
        with patch.dict(M.os.environ, environment, clear=True), patch.object(M, 'admit', side_effect=RuntimeError('private exception text')), \
             patch.object(M, 'load_owner') as load, patch.object(M, 'emit_record') as emit:
            self.assertEqual(M.shipping_capacity_data_main(), 1)
            load.assert_not_called()
            self.assertEqual(emit.call_count, 1)
            self.assertFalse(emit.call_args.args[0]['passed'])
            self.assertNotIn('private exception text', json.dumps(emit.call_args.args[0]))

class CatalogueHeadlessControlDataTests(unittest.TestCase):
    """Synthetic closed-parser/batch controls, not compiler or native evidence.

    The existing module imports qualification M under its admitted DATA closure.
    This class never calls M; only its one pinned public headless SOURCE read is
    real I/O; every batch owner, clock, digest, directory, publisher and FD is inert.
    """

    _SCRIPT_BYTES = 48542
    _SCRIPT_SHA256 = "c6efa4f622e3784ecd89129f89986352aac2faf5f5f647bb62aa9a5a3f7a6735"
    _HELPER_SHA256 = "9a25cbc411843de619678e9db1739762e5dd4a1c7415a29d39f6575d5992763c"

    @classmethod
    def setUpClass(cls):
        import hashlib
        import os
        import re

        source = Path(__file__).absolute().parents[2] / "desktop/tools/macos_aqua_headless_data.sh"
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                    value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        fds = []
        try:
            directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            fds.append(directory)
            for component in source.parts[1:-1]:
                directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                fds.append(directory)
            descriptor = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            fds.append(descriptor)
            info = os.fstat(descriptor)
            before = identity(info)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != cls._SCRIPT_BYTES
                    or before != identity(os.stat(source.name, dir_fd=directory, follow_symlinks=False))):
                raise AssertionError("catalogue-control-source-original")
            parts = []
            for offset in range(0, cls._SCRIPT_BYTES, 65536):
                length = min(65536, cls._SCRIPT_BYTES - offset)
                block = os.pread(descriptor, length, offset)
                if len(block) != length:
                    raise AssertionError("catalogue-control-source-short-read")
                parts.append(block)
            raw = b"".join(parts)
            if (len(raw) != cls._SCRIPT_BYTES or os.pread(descriptor, 1, len(raw)) != b""
                    or hashlib.sha256(raw).hexdigest() != cls._SCRIPT_SHA256
                    or before != identity(os.fstat(descriptor))
                    or before != identity(os.stat(source.name, dir_fd=directory, follow_symlinks=False))):
                raise AssertionError("catalogue-control-source-binding")
        finally:
            for descriptor in reversed(fds):
                os.close(descriptor)
        # Same literal indentation view after authenticating the actual helper.
        text = "".join("          " + line if line.strip() else line
                       for line in raw.decode("utf-8", "strict").splitlines(keepends=True))
        begin = "          # BEGIN_CATALOGUE_HEADLESS_CONTROL\n"
        end = "          # END_CATALOGUE_HEADLESS_CONTROL\n"
        if text.count(begin) != 1 or text.count(end) != 1:
            raise AssertionError("catalogue-control-literal-markers")
        first, last = text.index(begin), text.index(end)
        if last <= first:
            raise AssertionError("catalogue-control-literal-boundaries")
        lines = text[first:last + len(end)].splitlines(keepends=True)
        if any(not line.startswith("          ") and line != "\n" for line in lines):
            raise AssertionError("catalogue-control-literal-indent")
        block = "".join(line[10:] if line.startswith("          ") else line for line in lines)
        functions = tuple(line.split("(", 1)[0][4:] for line in block.splitlines() if line.startswith("def "))
        if (functions != ("catalogue_u64_sum", "parse_catalogue_budget", "check_catalogue_budget",
                          "exact_headless_result", "run_catalogue_batch")
                or hashlib.sha256(block.encode("utf-8")).hexdigest() != cls._HELPER_SHA256):
            raise AssertionError("catalogue-control-fixed-definition-binding")
        cls._helper_source = block
        cls._sha256 = staticmethod(hashlib.sha256)
        cls._regex = SimpleNamespace(fullmatch=re.fullmatch, escape=re.escape)

    def _namespace(self):
        safe = {name: getattr(builtins, name) for name in (
            "BaseException", "ValueError", "type", "int", "str", "bytes", "tuple",
            "len", "any", "all", "set", "list", "dict", "zip", "enumerate", "min", "max")}
        def forbidden(*_args, **_kwargs):
            raise AssertionError("no-real-batch-operation")
        namespace = {"__builtins__": safe, "re": self._regex,
            "hashlib": SimpleNamespace(sha256=self._sha256),
            "subprocess": SimpleNamespace(CompletedProcess=CompletedProcess),
            "os": SimpleNamespace(close=forbidden), "time": SimpleNamespace(monotonic_ns=forbidden),
            "publish": forbidden, "work": "/inert/work", "calls_entered": 0,
            "calls_returned": 0, "stage": "inert-not-entered"}
        # Only the fixed SOURCE definitions above, never parsed result/output.
        # No M, import/open, real os/subprocess module, owner or producer is exposed.
        exec(self._helper_source, namespace, namespace)
        return namespace

    @staticmethod
    def _budget(over_cap=False):
        # Explicit small synthetic integers, independent of the implementation's
        # arithmetic; neither these bytes nor the over-cap variant are Mac totals.
        rows = [
            b'catalogue_budget document_rows=[("document_cells", 1), ("saved_fields", 1), ("records", 1), ("assignments", 1), ("context", 1), ("slot_projection", 1), ("picker_originals", 1), ("other_registries", 0)]',
            b"catalogue_budget common document=7 owner_cells=2 runtime_heap=3 sources_heap=4 catalog_heap=5 service_heap=6 dispatcher=7 observation_identity=8",
            b"catalogue_budget source inspection=20 proposal_work=10 reproof=20 reproof_work=6 old_source=5 old_operation=4 source_review=7 proposal_heap=8 old_review=9 source_task=2 coordinator=3 inspection_tasks=11",
            b"catalogue_budget register client=6 preparation=31 settled=12 phase=44 tasks=3 task_reserved=4",
            b"catalogue_budget case=fresh_inspect previous=47 control_slot=2 checked=3 retained_review=0 phase=30 new_owner=4 final_tasks=11 total=92 limit=67108864 headroom=67108772 over=0",
            b"catalogue_budget case=inspect_retained_review previous=59 control_slot=5 checked=3 retained_review=9 phase=30 new_owner=4 final_tasks=11 total=104 limit=67108864 headroom=67108760 over=0",
            b"catalogue_budget case=register_retained_review previous=63 control_slot=5 checked=7 retained_review=9 phase=44 new_owner=6 final_tasks=0 total=113 limit=67108864 headroom=67108751 over=0",
        ]
        if over_cap:
            rows[1] = rows[1].replace(b"owner_cells=2 ", b"owner_cells=67108864 ")
            rows[4] = b"catalogue_budget case=fresh_inspect previous=67108909 control_slot=2 checked=3 retained_review=0 phase=30 new_owner=4 final_tasks=11 total=67108954 limit=67108864 headroom=0 over=90"
            rows[5] = b"catalogue_budget case=inspect_retained_review previous=67108921 control_slot=5 checked=3 retained_review=9 phase=30 new_owner=4 final_tasks=11 total=67108966 limit=67108864 headroom=0 over=102"
            rows[6] = b"catalogue_budget case=register_retained_review previous=67108925 control_slot=5 checked=7 retained_review=9 phase=44 new_owner=6 final_tasks=0 total=67108975 limit=67108864 headroom=0 over=111"
        return b"\n".join(rows) + b"\n"

    @staticmethod
    def _pretty(names, filtered):
        count = len(names)
        heading = f"running {count} " + ("test" if count == 1 else "tests")
        rows = [heading, *("test " + name + " ... ok" for name in names),
                f"test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; {filtered} filtered out; finished in 0.01s"]
        return ("\n" + "\n".join(rows) + "\n\n").encode("utf-8")

    def _drive(self, first="pass", second="pass", *, ticks=None, close_error=False,
               retire_error=None, digest_bad_at=None):
        namespace = self._namespace()
        names = tuple(f"inert::ordinary_{index:02d}" for index in range(25)) + (
            namespace["CATALOGUE_ROUNDTRIP_TEST"], namespace["CATALOGUE_BUDGET_TEST"])
        record = {"role": "main", "names": names, "testsPassed": False,
                  "originalReturned": False, "artifactOriginalUnchanged": False, "artifactOriginalClosed": False}
        original = {"fd": 31337, "record": record}
        calls, returned, closed, retired, publications, events, clock_reads, digest_reads = [], [], [], [], {}, [], [], []
        schedule = iter(ticks if ticks is not None else (
            0, 100_000_000, 200_000_000, 3_000_000_000, 3_100_000_000,
            4_000_000_000, 4_100_000_000, 4_200_000_000))
        def clock():
            value = next(schedule)
            clock_reads.append(value)
            return value
        def original_digest():
            digest_reads.append(None)
            return "f" * 64 if digest_bad_at is not None and len(digest_reads) >= digest_bad_at else "e" * 64
        def close(descriptor):
            closed.append(descriptor)
            events.append(("close", descriptor))
            if close_error:
                raise OSError("inert-consuming-close")
        class Directory:
            def __init__(self, name):
                self.name = name
            def __str__(self):
                return "/inert/" + self.name
            def rmdir(self):
                retired.append(self.name)
                events.append(("retire", self.name))
                if retire_error == self.name:
                    raise OSError("inert-retirement")
        def publish(name, body):
            if name in publications or type(body) is not bytes:
                raise AssertionError("inert-original-publication")
            publications[name] = body
        actions = (first, second)
        def run_owned(argv, **kwargs):
            index = len(calls)
            calls.append((tuple(argv), dict(kwargs)))
            events.append(("owner", index))
            action = actions[index]
            if action == "owner-exception":
                raise RuntimeError("inert-unknown-original")
            selected, filtered = (names[:-1], 101) if index == 0 else (names[-1:], 202)
            stdout = self._pretty(selected, filtered)
            stderr = b"" if index == 0 else self._budget(action == "over-cap")
            returncode = 0
            if action == "nonzero":
                returncode = 1
            elif action == "bad-stdout":
                stdout = b"unrecognized synthetic stdout\n"
            elif action == "unexpected-stderr":
                stderr = b"unrecognized synthetic stderr\n"
            elif action == "panic":
                stderr += b"synthetic panic trailer\n"
            elif action in ("exhaust", "oversize"):
                size = 65536 if action == "exhaust" else 65537
                stdout += b"\n" * (size - len(stdout))
            result = CompletedProcess(list(argv), returncode, stdout, stderr)
            if action == "foreign-return":
                result = SimpleNamespace(args=list(argv), returncode=0, stdout=stdout, stderr=stderr)
            elif action == "bool-returncode":
                result.returncode = True
            elif action == "text-output":
                result.stdout = stdout.decode("utf-8")
            elif action == "tuple-args":
                result.args = tuple(argv)
            elif action == "wrong-args":
                result.args = ["inert-other"]
            elif action == "mutated-argv":
                argv[-1] = "inert-mutated"
            returned.append(result)
            return result
        namespace.update(os=SimpleNamespace(close=close), publish=publish)
        error = None
        try:
            namespace["run_catalogue_batch"](SimpleNamespace(run_owned=run_owned), "/inert/main", names,
                27, "headless", record, original, original_digest, "e" * 64, Directory("home"),
                Directory("tmp"), clock=clock)
        except BaseException as caught:
            error = caught
        return SimpleNamespace(namespace=namespace, names=names, record=record, original=original,
            calls=calls, returned=returned, closed=closed, retired=retired, publications=publications,
            events=events, clock_reads=clock_reads, digest_reads=digest_reads, error=error)

    def test_canonical_closed_rows_retain_all_typed_totals_and_u64_boundaries(self):
        namespace = self._namespace()
        value = namespace["parse_catalogue_budget"](self._budget())
        self.assertIsNone(namespace["check_catalogue_budget"](value))
        rows = [value[key] for key in ("documentRows", "common", "source", "register")]
        numbers = [number for row in rows for number in row.values()]
        numbers += [number for row in value["cases"] for key, number in row.items() if key != "name"]
        self.assertEqual(len(numbers), 67)
        self.assertTrue(all(type(number) is int for number in numbers))
        self.assertEqual([row["total"] for row in value["cases"]], [92, 104, 113])
        self.assertEqual([row["name"] for row in value["cases"]], list(namespace["CATALOGUE_CASE_NAMES"]))
        maximum = (1 << 64) - 1
        self.assertEqual(namespace["catalogue_u64_sum"](maximum, 0), maximum)
        for values in ((True,), (-1,), (maximum + 1,), (maximum, 1)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                namespace["catalogue_u64_sum"](*values)

    def test_closed_parser_refuses_malformed_order_prefixes_and_noncanonical_numbers(self):
        parse = self._namespace()["parse_catalogue_budget"]
        raw = self._budget()
        rows = raw[:-1].split(b"\n")
        malformed = [
            b"", raw[:-1], b"prefix\n" + raw, raw + b"synthetic panic trailer\n",
            raw.replace(b"\n", b"\r\n"), raw.replace(b"document=7", b"document=07"),
            raw.replace(b"document=7", b"document=+7"), raw.replace(b"document=7", b"document=-7"),
            raw.replace(b"owner_cells=2", b"owner_cells=18446744073709551616"),
            raw.replace(b"owner_cells=2 runtime_heap=3", b"runtime_heap=3 owner_cells=2"),
            raw.replace(b'("document_cells", 1)', b'("document_cells",1)'),
            b"\n".join([rows[0], rows[2], rows[1], *rows[3:]]) + b"\n",
            b"\n".join([*rows[:4], rows[5], rows[4], rows[6]]) + b"\n",
            raw.replace(b"fresh_inspect", b"fresh_unknown"), raw.replace(b"document=7", b"document=\xff"),
            b"x" * 2406, bytearray(raw), True,
        ]
        for index, body in enumerate(malformed):
            with self.subTest(index=index), self.assertRaises(ValueError):
                parse(body)

    def test_numeric_checks_refuse_arithmetic_overflow_and_unchanged_cap(self):
        namespace = self._namespace()
        value = namespace["parse_catalogue_budget"](self._budget())
        mutations = [
            ("common", "document", 8), ("common", "owner_cells", (1 << 64) - 1),
            ("source", "reproof", 19), ("register", "phase", 43),
            ("register", "tasks", 5), ("cases", "previous", 48),
            ("cases", "total", 93), ("cases", "headroom", 67108773),
            ("cases", "limit", 67108865),
        ]
        for section, key, number in mutations:
            with self.subTest(section=section, key=key):
                broken = deepcopy(value)
                (broken[section][0] if section == "cases" else broken[section])[key] = number
                with self.assertRaises(ValueError):
                    namespace["check_catalogue_budget"](broken)
        over = namespace["parse_catalogue_budget"](self._budget(True))
        self.assertEqual([row["over"] for row in over["cases"]], [90, 102, 111])
        with self.assertRaisesRegex(ValueError, "unchanged-whole-owner-cap"):
            namespace["check_catalogue_budget"](over)

    def test_two_original_calls_share_deadline_bytes_and_consuming_main_close(self):
        run = self._drive()
        self.assertIsNone(run.error)
        self.assertEqual((run.namespace["calls_entered"], run.namespace["calls_returned"]), (2, 2))
        self.assertEqual(len(run.calls), 2)
        first, second = run.calls
        common = ("/inert/main", "--exact", "--test-threads=1", "--color=never", "--format=pretty")
        self.assertEqual(first[0], common + run.names[:-1])
        self.assertEqual(second[0], common + ("--nocapture", run.names[-1]))
        self.assertEqual((first[1]["timeout"], second[1]["timeout"]), (30, 26))
        for _, options in run.calls:
            self.assertEqual(set(options), {"environ", "cwd", "timeout", "capture", "text", "output_limit"})
            self.assertIs(options["capture"], True)
            self.assertIs(options["text"], False)
            self.assertEqual(options["cwd"], "/inert/work")
            self.assertEqual(options["environ"], {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "HOME": "/inert/home", "TMPDIR": "/inert/tmp", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"})
        first_bytes = len(run.returned[0].stdout) + len(run.returned[0].stderr)
        self.assertEqual((first[1]["output_limit"], second[1]["output_limit"]), (65536, 65536 - first_bytes))
        self.assertEqual(run.record["batchOutputBytes"], sum(len(row.stdout) + len(row.stderr) for row in run.returned))
        self.assertEqual([row["filtered"] for row in run.record["invocations"]], [101, 202])
        self.assertNotIn("returncode", run.record)
        self.assertNotIn("filtered", run.record)
        self.assertEqual(run.closed, [31337])
        self.assertEqual(run.retired, ["home", "tmp"])
        self.assertIsNone(run.original["fd"])
        self.assertEqual(run.record["artifactCloseAttempts"], 1)
        self.assertEqual(run.record["finalElapsedNanoseconds"], "4200000000")
        self.assertTrue(run.record["testsPassed"])
        self.assertTrue(run.record["deadlineMetAfterFinalCloses"])
        self.assertEqual(set(run.publications), {prefix + suffix for prefix in ("headless", "headless-catalogue")
                                               for suffix in ("-tests.stdout", "-tests.stderr", "-tests.status")})
        for index, prefix in enumerate(("headless", "headless-catalogue")):
            self.assertEqual(run.publications[prefix + "-tests.stdout"], run.returned[index].stdout)
            self.assertEqual(run.publications[prefix + "-tests.stderr"], run.returned[index].stderr)
            self.assertEqual(run.publications[prefix + "-tests.status"], b"0\n")

    def test_known_first_failure_late_return_or_exhaustion_stops_second_call(self):
        scenarios = [
            ("nonzero", {}), ("bad-stdout", {}), ("unexpected-stderr", {}), ("exhaust", {}),
            ("pass", {"ticks": (0, 30_000_000_000, 30_000_000_000)}),
            ("pass", {"ticks": (0, 100_000_000, 200_000_000, 30_000_000_000, 30_000_000_000)}),
            ("pass", {"digest_bad_at": 2}),
        ]
        for first, options in scenarios:
            with self.subTest(first=first, options=options):
                run = self._drive(first, **options)
                self.assertIsInstance(run.error, ValueError)
                self.assertEqual((len(run.calls), run.namespace["calls_entered"], run.namespace["calls_returned"]), (1, 1, 1))
                self.assertFalse(run.record["testsPassed"])
                self.assertFalse(run.record["headlessCustodyRetained"])
                self.assertEqual(run.closed, [31337])
                self.assertEqual(run.retired, ["home", "tmp"])
                self.assertIsNone(run.original["fd"])
                if first == "exhaust":
                    self.assertEqual(run.record["batchOutputBytes"], 65536)
                    self.assertTrue(run.record["invocations"][0]["testsPassed"])

    def test_unknown_original_returns_never_authorize_another_call_or_close(self):
        unknown = ("owner-exception", "foreign-return", "bool-returncode", "text-output",
                   "tuple-args", "wrong-args", "mutated-argv", "oversize")
        for action in unknown:
            with self.subTest(first=action):
                run = self._drive(action)
                self.assertIsNotNone(run.error)
                self.assertEqual((len(run.calls), run.namespace["calls_entered"], run.namespace["calls_returned"]), (1, 1, 0))
                self.assertEqual((len(run.digest_reads), len(run.clock_reads)), (1, 1))
                self.assertEqual(run.publications, {})
                self.assertEqual((run.closed, run.retired), ([], []))
                self.assertEqual(run.original["fd"], 31337)
                self.assertTrue(run.record["headlessCustodyRetained"])
                self.assertFalse(run.record["testsPassed"])
        second = self._drive(second="owner-exception")
        self.assertIsNotNone(second.error)
        self.assertEqual((len(second.calls), second.namespace["calls_entered"], second.namespace["calls_returned"]), (2, 2, 1))
        self.assertEqual((second.closed, second.retired), ([], []))
        self.assertEqual(second.original["fd"], 31337)
        self.assertTrue(second.record["headlessCustodyRetained"])

    def test_aggregate_failure_preserves_original_raw_and_typed_overcap_observation(self):
        for action in ("over-cap", "panic"):
            with self.subTest(action=action):
                run = self._drive(second=action)
                self.assertIsInstance(run.error, ValueError)
                self.assertEqual((len(run.calls), run.namespace["calls_returned"]), (2, 2))
                observed = run.record["invocations"][1]
                self.assertTrue(observed["originalReturned"])
                self.assertFalse(observed["testsPassed"])
                self.assertEqual(run.publications["headless-catalogue-tests.stderr"], run.returned[1].stderr)
                self.assertEqual(observed["stderrSha256"], self._sha256(run.returned[1].stderr).hexdigest())
                if action == "over-cap":
                    self.assertIn("unchanged-whole-owner-cap", str(run.error))
                    self.assertEqual([row["total"] for row in observed["catalogueBudget"]["cases"]],
                                     [67108954, 67108966, 67108975])
                    self.assertEqual([row["over"] for row in observed["catalogueBudget"]["cases"]], [90, 102, 111])
                else:
                    self.assertNotIn("catalogueBudget", observed)
                    self.assertTrue(run.returned[1].stderr.endswith(b"synthetic panic trailer\n"))
                self.assertEqual(run.closed, [31337])
                self.assertIsNone(run.original["fd"])
                self.assertFalse(run.record["testsPassed"])

    def test_known_finality_errors_still_close_once_without_promoting_success(self):
        ordinary = (0, 100_000_000, 200_000_000, 3_000_000_000, 3_100_000_000, 4_000_000_000, 4_100_000_000)
        for options in ({"close_error": True}, {"retire_error": "home"},
                        {"ticks": ordinary + (30_000_000_000,)}, {"ticks": ordinary + (4_000_000_000,)}):
            with self.subTest(options=options):
                run = self._drive(**options)
                self.assertIsInstance(run.error, ValueError)
                self.assertEqual((run.namespace["calls_entered"], run.namespace["calls_returned"]), (2, 2))
                self.assertTrue(all(row["testsPassed"] for row in run.record["invocations"]))
                self.assertEqual(run.closed, [31337])
                self.assertEqual(run.retired, ["home", "tmp"])
                self.assertEqual(run.record["artifactCloseAttempts"], 1)
                self.assertIsNone(run.original["fd"])
                self.assertTrue(run.record["cleanupErrors"])
                self.assertFalse(run.record["testsPassed"])
                self.assertFalse(run.record["deadlineMetAfterFinalCloses"])
                if options.get("close_error"):
                    self.assertFalse(run.record["artifactOriginalClosed"])



class LocalEditsAquaDataTests(unittest.TestCase):
    """Pure DATA/SOURCE regressions. No native owner or target process is run."""

    @staticmethod
    def changed_snapshot(case, original):
        files, directories = M.fixture_data(case, True)
        current = dict(original)
        for name, (_mode, entries) in directories.items():
            current[name] = replace(current[name], entries=entries)
        for index, (name, body) in enumerate(files.items(), 1):
            before = original.get(name)
            if before is not None and before.sha256 == M.digest(body):
                continue
            current[name] = M.Node((7, 1000 + index, stat.S_IFREG | 0o600, UID, GID, 1, len(body), 200, 200),
                                   M.digest(body), None)
        return current

    def test_local_edits_scope_and_original_call_limits(self):
        cases = ("local-metadata-text", "local-release-version", "local-github-apply")
        self.assertEqual(M.LOCAL_EDIT_CASES, cases)
        self.assertEqual(M.selected_cases(M.LOCAL_EDITS_SCOPE), cases)
        self.assertEqual(M.argument_scope(["--scope", "local-edits3"]), M.LOCAL_EDITS_SCOPE)
        self.assertEqual(M.selected_cases(), M.CASES)
        self.assertEqual([M.case_timeout(case) for case in cases], [135, 105, 195])
        self.assertEqual(sum(M.case_timeout(case) for case in cases), 435)
        for argv in (["--scope", cases[0]], ["--scope", "local-edits3", "--timeout", "900"], ["--scope", "LOCAL-EDITS3"]):
            with self.subTest(argv=argv), self.assertRaises(M.Refused):
                M.argument_scope(argv)
        local_root = BINDING.root(local_edits=True)
        self.assertTrue(local_root.name.endswith("-local-edits"))
        self.assertNotEqual(local_root, BINDING.root())
        with self.assertRaises(M.Refused):
            BINDING.root(local_edits=True, project_fields=True)
        with self.assertRaises(M.Refused):
            BINDING.root(local_edits=1)
        fixtures = InertFixtures()
        fixtures.cases = cases
        def readback(case):
            if fixtures.inflight or not fixtures.last_returned:
                raise AssertionError("no original return")
            fixtures.reads.append(case)
            original = initial_snapshot(case)
            return M.validate_snapshot(original, self.changed_snapshot(case, original), case, True, UID, GID)
        fixtures.readback = readback
        calls, emitted = [], []
        def returned(argv, **kwargs):
            calls.append((argv, kwargs))
            return CompletedProcess(argv, 0, captured(M.expected_result(BINDING, argv[1])), b"")
        self.assertEqual(M.run_cases(BINDING, fixtures, returned, UID, "runner", emitted.append, M.LOCAL_EDITS_SCOPE), ())
        self.assertEqual(fixtures.before, list(cases)); self.assertEqual(fixtures.reads, list(cases))
        self.assertEqual(len(calls), 3); self.assertEqual(len(emitted), 3)
        for (argv, options), case in zip(calls, cases):
            self.assertEqual(argv, [M.EXECUTABLE, case])
            self.assertEqual(options["cwd"], local_root / "state" / case)
            self.assertEqual(options["timeout"], M.case_timeout(case))
            self.assertEqual(options["output_limit"], 2 * 1024 * 1024)
            self.assertIs(options["capture"], True); self.assertIs(options["text"], False)
            self.assertNotIn("MOBILE_RELEASE_TOOLING_ROOT", options["environ"])
        for case in cases:
            expected = M.expected_result(BINDING, case)
            self.assertFalse(expected["shippingBinaryQualified"])
            self.assertFalse(expected["localEdits"]["physicalDropdownGestureQualified"])
            self.assertEqual(M.parse_result(captured(expected), b"", BINDING, case), expected)
            for field, value in (("originalFinalities", False), ("sameOriginalSessions", True),
                                 ("physicalDropdownGestureQualified", True), ("imagesDoctorVaultRestartQualified", True)):
                changed = deepcopy(expected); changed["localEdits"][field] = value
                with self.subTest(case=case, field=field), self.assertRaises(M.Refused):
                    M.parse_result(captured(changed), b"", BINDING, case)
        unknown = InertFixtures(); unknown.cases = cases
        original_error = RuntimeError("inert unreturned original")
        def unreturned(*_args, **_kwargs):
            raise original_error
        with self.assertRaises(RuntimeError) as caught:
            M.run_cases(BINDING, unknown, unreturned, UID, "runner", lambda _value: self.fail("no record"), M.LOCAL_EDITS_SCOPE)
        self.assertIs(caught.exception, original_error)
        self.assertTrue(unknown.inflight); self.assertFalse(unknown.last_returned)
        self.assertEqual(unknown.before, [cases[0]]); self.assertEqual(unknown.reads, [])
        for target in (M.ARM_TARGET, M.INTEL_TARGET):
            self.assertEqual(M.entry_arguments(["--target", target]), (None, target))
            self.assertEqual(M.entry_arguments(["--scope", M.LOCAL_EDITS_SCOPE, "--target", target]), (M.LOCAL_EDITS_SCOPE, target))
        self.assertEqual(M.entry_arguments([]), (None, M.ARM_TARGET))
        self.assertEqual(M.entry_arguments(["--scope", M.LOCAL_EDITS_SCOPE]), (M.LOCAL_EDITS_SCOPE, M.ARM_TARGET))
        for argv in ((), ["--target"], ["--target", M.INTEL_TARGET, "--scope", M.LOCAL_EDITS_SCOPE],
                     ["--scope", M.LOCAL_EDITS_SCOPE, "--target", M.INTEL_TARGET, "--target", M.INTEL_TARGET],
                     ["--scope", M.LOCAL_EDITS_SCOPE, "--target", "arm64"], ["--target", None],
                     ["--target", M.INTEL_TARGET, "extra"]):
            with self.subTest(argv=argv), self.assertRaises(M.Refused):
                M.entry_arguments(argv)

    def test_local_edits_exact_readback_and_stale_file_preservation(self):
        self.assertEqual(M.LOCAL_VERSION_AFTER, M.LOCAL_VERSION_BEFORE.replace(b"1.2.3", b"2.3.4").replace(b"BUILD_NUMBER=7", b"BUILD_NUMBER=8"))
        self.assertIn(b"  VERSION_NAME = 2.3.4  \n", M.LOCAL_VERSION_AFTER)
        self.assertIn(b"UNRELATED = keep-this-value\n", M.LOCAL_VERSION_AFTER)
        resource = (PATH.parents[2] / "src/mobile_release/api/data/github-setup-v1.json").read_bytes()
        self.assertEqual(M.digest(resource), M.LOCAL_WORKFLOW_RESOURCE_SHA256)
        templates = json.loads(resource)["workflows"]
        for identity, size in zip(("preflight", "candidate", "external-testing", "production-submit"), (1479, 2303, 3079, 3816)):
            path = f".github/workflows/mobile-{identity}.yml"
            generated = templates[identity].replace("__MOBILE_RELEASE_KIT_SHA__", "a" * 40).replace("__MOBILE_RELEASE_KIT_REPOSITORY__", "example/toolkit").encode()
            self.assertEqual(M.LOCAL_WORKFLOWS[path], generated); self.assertEqual(len(generated), size)
        metadata_config = json.loads(M.local_edit_config(M.LOCAL_EDIT_CASES[0]))
        self.assertTrue(metadata_config["ios"]["enabled"])
        self.assertEqual(metadata_config["metadata"]["iosLocales"], ["en-US"])
        self.assertEqual(metadata_config["ios"]["identityStatus"], "unverified")
        for case, count in zip(M.LOCAL_EDIT_CASES, ((14, 8), (5, 3), (10, 5))):
            before = initial_snapshot(case); after = self.changed_snapshot(case, before)
            files, directories = M.fixture_data(case, True)
            self.assertEqual((len(files), len(directories)), count)
            self.assertLessEqual(sum(map(len, files.values())), 1024 * 1024)
            self.assertTrue(all(mode == 0o700 for mode, _entries in directories.values()))
            data = M.validate_snapshot(before, after, case, True, UID, GID)
            self.assertEqual(data["localEdits"]["sha256"], M._expected_local_edits(case)["fixture"]["sha256"])
            self.assertTrue(data["transactionResidueAbsent"])
            for kind in ("sentinel-content", "sentinel-identity", "journal", "mode", "directory-link"):
                changed = dict(after)
                if kind == "sentinel-content":
                    changed["keep.txt"] = replace(changed["keep.txt"], sha256="0" * 64)
                elif kind == "sentinel-identity":
                    node = changed["keep.txt"]; changed["keep.txt"] = replace(node, identity=(node.identity[0], 9999, *node.identity[2:]))
                elif kind == "journal":
                    changed[".mobile-release-version"] = changed["."]
                elif kind == "mode":
                    node = changed["keep.txt"]; changed["keep.txt"] = replace(node, identity=(*node.identity[:2], stat.S_IFREG | 0o644, *node.identity[3:]))
                else:
                    node = changed["."]; changed["."] = replace(node, identity=(*node.identity[:5], node.identity[5]+1, *node.identity[6:]))
                with self.subTest(case=case, kind=kind), self.assertRaises(M.Refused):
                    M.validate_snapshot(before, changed, case, True, UID, GID)
            if case == "local-github-apply":
                name = ".github/workflows/mobile-preflight.yml"
                self.assertEqual(files[name], M.LOCAL_WORKFLOWS[name] + M.LOCAL_STALE)
                changed = dict(after); node = changed[name]; body = M.LOCAL_WORKFLOWS[name]
                changed[name] = replace(node, identity=(*node.identity[:6], len(body), *node.identity[7:]), sha256=M.digest(body))
                with self.assertRaises(M.Refused):
                    M.validate_snapshot(before, changed, case, True, UID, GID)
            else:
                name = "version.properties" if case == "local-release-version" else "release/store/android/en-US/short_description.txt"
                changed = dict(after); node = changed[name]
                changed[name] = replace(node, identity=(*before[name].identity[:2], *node.identity[2:]))
                with self.assertRaisesRegex(M.Refused, "^fixture-local-replacement$"):
                    M.validate_snapshot(before, changed, case, True, UID, GID)

    def test_local_edit_callbacks_and_finality_are_same_domain_source_bound(self):
        rust = PATH.parents[1] / "src-tauri/src"
        child = (rust / "installed_shell_observation_macos_local_edits.rs").read_text()
        parent = (rust / "installed_shell_observation_macos.rs").read_text()
        shell = (rust / "shell.rs").read_text()
        owner = (rust / "edit_owner.rs").read_text()
        for domain, prefix in (("Workflow", "workflow"), ("Metadata", "metadata"), ("Version", "version")):
            self.assertIn(f"Installed{domain}Finality", child)
            self.assertIn(f"installed_{prefix}_observation_final(id)", child)
            self.assertIn(f"pub(crate) struct Installed{domain}Finality", owner)
            self.assertIn(f"pub(crate) fn installed_{prefix}_observation_final", owner)
        for fact in ("inspection_joined", "acquisition_joined", "child_waited_success", "stdin_closed", "stdout_eof_closed",
                     "stderr_eof_closed", "io_joined", "driver_joined", "watchdog_joined", "manager_joined",
                     "runtime_ledger_settled", "runtime_settlement_joined"):
            self.assertIn("f." + fact, child)
        for token in ('["domain","projectId","sessionId","ownerGeneration"]', 'p["sessionId"]==f.session_id',
                      's.finality.as_ref().is_some_and(|f|f.matches(&s.projection))', 'r.local_edits.as_ref().is_some_and(local_edits::Record::stale_ready)',
                      'f.after(&root,uid,index,proposal)', 'r.fixture.verify(true)', '!local_edits::data_checks()'):
            self.assertIn(token, child + parent)
        for hook in ("workflow_open_request", "workflow_prepare_request", "workflow_apply_request", "workflow_close_request",
                     "metadata_open_request", "metadata_prepare_request", "metadata_apply_request",
                     "version_open_request", "version_prepare_request", "version_apply_request",
                     "local_release_version_request", "local_release_version"):
            self.assertIn(hook, shell)
        component = (PATH.parents[1] / "src/components/MetadataTextEditor.tsx").read_text()
        self.assertIn('<option value="" disabled>No enabled configured locale</option>', component)
        self.assertIn('<optgroup label="Current saved configuration">{state.choices.map', component)
        for token in ("options.length!==3", "options[0].value!==''", "!options[0].disabled",
                      "text(options[0])!=='No enabled configured locale'", "options[0].parentElement!==s",
                      "options.slice(1).some", "options[1].value===options[2].value",
                      "s.selectedIndex!==1", "s.value!==options[1].value"):
            self.assertIn(token, child)
        self.assertIn('s.selectedIndex=2;s.dispatchEvent(new Event(\'change\',{bubbles:true}))', child)
        self.assertNotIn("options.length!==2||options.some", child)
        self.assertIn("Current saved configuration", child)
        self.assertIn("s.finality.is_none()", child)
        self.assertIn("self.sessions[..2].iter().all(Session::complete)", child)
        self.assertIn("held[..6]!=original.identity[..6]", child)
        self.assertIn("file.sync_all()", child)
        self.assertIn("nix::unistd::close(std::os::fd::OwnedFd::from(file))", child)
        self.assertIn('"physicalDropdownGestureQualified":false', child)
        for name in ("mismatched_or_out_of_order_original_is_refused", "incomplete_finality_cannot_finish_or_authorize_stale_append"):
            self.assertIn("fn " + name + "()", child)
        # New paths observe the ordinary wrappers, never call IPC directly or
        # create new process/native owners or writer grants.
        for forbidden in ("__TAURI__", "__TAURI_INTERNALS__", "invoke(", "std::process::Command", "thread::spawn", "tokio::spawn",
                          "INSTALLED_MAC_PROJECT_FIELDS_QUALIFIED = true"):
            self.assertNotIn(forbidden, child)
        self.assertIn('all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol"', owner)
        self.assertIn('target_os = "macos", target_arch = "aarch64"', owner)

    def test_local_edits_workflow_scope_is_opt_in(self):
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-aqua.yml").read_text()
        matrix = workflow.split("      matrix:\n", 1)[1].split("    runs-on:", 1)[0]
        self.assertEqual(matrix, "        include:\n          - scope: local-edits3\n            target: aarch64-apple-darwin\n            runner: macos-26\n            supplier_receipt: '2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d'\n            supplier_tar: 'ff7883185cf8226e9366b1ee9a3dcb3eb8ee761dbc1f697f952510a6bd858695'\n            supplier_source: '158cdff422e3837f7ab5e6192af76a578faf6fab'\n            supplier_run: '37467019389'\n            supplier_attempt: '1'\n            supplier_artifact: '11415902210'\n          - scope: local-edits3\n            target: x86_64-apple-darwin\n            runner: macos-26-intel\n            supplier_receipt: 'a46f6838afdb7c20c3539e8f65891312aa8df10e2de67e9b9e3ddbf449883b4b'\n            supplier_tar: '739cc8b8b3c68daffba8d7b9cb7cb54ca730eef2c5842302ae8a2682bf64d5bd'\n            supplier_source: '079ab2a2c8fef88f01bf909e7669c685f07e1375'\n            supplier_run: '37476532238'\n            supplier_attempt: '1'\n            supplier_artifact: '11419502465'\n")
        self.assertEqual(matrix.count("- scope: local-edits3\n"), 2)
        self.assertNotIn("workflow_dispatch:", workflow.split("permissions:", 1)[0])
        self.assertIn('"local-edits3": ("three-local-edit-Aqua-engineering-cases", ["local-metadata-text", "local-release-version", "local-github-apply"])', workflow)
        self.assertEqual(workflow.count("|| env.MRK_MACOS_AQUA_SCOPE == 'local-edits3')"), 26)
        runner = workflow.split("      - name: Three serial local-edit Aqua journeys", 1)[1].split("      - name:", 1)[0]
        for required in ("if: success() && env.MRK_MACOS_AQUA_SCOPE == 'local-edits3'", "timeout-minutes: 9", "set -o noclobber", "umask 077",
                         "RUNNER_ENVIRONMENT: ${{ runner.environment }}", "git -c core.fsmonitor=false diff --exit-code HEAD",
                         'macos_aqua_qualification.py --scope local-edits3 --target "$MRK_MACOS_TARGET"', "status=$?", '[[ $status == 0 ]] || exit "$status"'):
            self.assertIn(required, runner)
        for suffix in ("results.jsonl", "failure.jsonl", "status"):
            self.assertIn("${{ steps.work.outputs.root }}/aqua-local-edits3-" + suffix if suffix != "status"
                          else "${{ steps.work.outputs.root }}/aqua-local-edits3.status", workflow)
        admission = workflow.split("      - name: Admit only this exact disposable-hosted source route\n", 1)[1].split("      - name:", 1)[0]
        self.assertEqual(workflow.count("      MRK_MACOS_TARGET: ${{ matrix.target }}\n"), 1)
        self.assertEqual(workflow.count("      MRK_MACOS_RUNNER: ${{ matrix.runner }}\n"), 1)
        self.assertIn('case "$MRK_MACOS_TARGET" in', admission)
        self.assertIn("*) exit 1 ;;", admission)
        source_pin = "fa624512af03437f075f2da10357b3808d1a58c8f36e1db6103bc2abe54150e0"
        self.assertEqual(workflow.count("      MRK_BUNDLED_RUNTIME_SOURCE_SHA256: " + source_pin + "\n"), 1)
        self.assertEqual(admission.count('"$MRK_BUNDLED_RUNTIME_SOURCE_SHA256" == ' + source_pin), 1)
        expected_suppliers = (('aarch64-apple-darwin', 'macos-26', 'arm64', 'ARM64', '2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d', 'ff7883185cf8226e9366b1ee9a3dcb3eb8ee761dbc1f697f952510a6bd858695', '158cdff422e3837f7ab5e6192af76a578faf6fab', '37467019389', '1', '11415902210'), ('x86_64-apple-darwin', 'macos-26-intel', 'x86_64', 'X64', 'a46f6838afdb7c20c3539e8f65891312aa8df10e2de67e9b9e3ddbf449883b4b', '739cc8b8b3c68daffba8d7b9cb7cb54ca730eef2c5842302ae8a2682bf64d5bd', '079ab2a2c8fef88f01bf909e7669c685f07e1375', '37476532238', '1', '11419502465'))
        fields = (('SHA256', 'supplier_receipt'), ('TAR_SHA256', 'supplier_tar'), ('SOURCE_COMMIT', 'supplier_source'), ('RUN_ID', 'supplier_run'), ('RUN_ATTEMPT', 'supplier_attempt'), ('ARTIFACT_ID', 'supplier_artifact'))
        for target, runner_label, machine, runner_arch, *pins in expected_suppliers:
            branch = admission.split("            " + target + ")\n", 1)[1].split("              ;;", 1)[0]
            for expected in ('"$MRK_MACOS_RUNNER" == ' + runner_label, '"$RUNNER_ARCH" == ' + runner_arch,
                             '"$(/usr/bin/uname -m)" == ' + machine):
                self.assertIn(expected, branch)
            if target == "x86_64-apple-darwin":
                self.assertIn('"$MRK_MACOS_AQUA_SCOPE" == local-edits3', branch)
            for (suffix, key), value in zip(fields, pins):
                self.assertEqual(branch.count("expected_" + key + "=" + value + "\n"), 1)
                self.assertEqual(workflow.count("      MRK_MACOS_PYTHON_SUPPLIER_" + suffix + ": ${{ matrix." + key + " }}\n"), 1)
                self.assertEqual(admission.count('"$MRK_MACOS_PYTHON_SUPPLIER_' + suffix + '" == "$expected_' + key + '"'), 1)
        selection = workflow.split("      - name: Select the fixed configured signed runtime before any payload download\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn('"runtimeManifestSha256": "MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"', selection)
        self.assertIn("desktop/tools/stage_macos_installed.py runtime-signing-selection", selection)
        self.assertIn('value["state"] != "configured"', selection)
        self.assertIn('value["target"] != os.environ["MRK_MACOS_TARGET"]', selection)
        self.assertIn('--target "$MRK_MACOS_TARGET"', selection)
        self.assertNotIn("      MRK_BUNDLED_RUNTIME_MANIFEST_SHA256:", workflow)
        runtime = workflow.split("      - name: Prepare the current payload from the independently accepted fresh Python supplier\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("--configured-signing", runtime)
        self.assertIn('--expected-manifest "$MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"', runtime)
        self.assertNotIn("pending-independent-current-", workflow)
        self.assertNotIn("pending-independent-supplier-", workflow)
        source = PATH.read_text()
        run = source.split("def run_cases(", 1)[1].split("def recovery_supplier_route", 1)[0]
        self.assertEqual(run.count("result = run_owned(argv,"), 1)
        for required in ('type(result) is subprocess.CompletedProcess', 'need(result.returncode == 0, "app-return")',
                         'report = parse_result', 'readback = fixtures.readback_ios', '"fixture-local-readback"'):
            self.assertIn(required, run)
        self.assertLess(run.index('need(result.returncode == 0, "app-return")'), run.index('report = parse_result'))
        self.assertLess(run.index('report = parse_result'), run.index('"fixture-local-readback"'))
        self.assertLess(run.index('"fixture-local-readback"'), run.index('emit({"schemaVersion": 1'))


class LocalChecksAquaDataTests(unittest.TestCase):
    """Inert returned DATA/SOURCE and one private file fixture, never native work."""

    @staticmethod
    def returned_data(case):
        # Explicit test DATA, not synthetic native authority in production.
        value = M.expected_result(BINDING, case)
        checks = value["localChecks"]
        context = {"projectId": "public-project", "draftRevision": 0, "baselineGeneration": 1,
                   "platform": "android", "operation": "build"}
        if case == "local-tool-observations":
            for index, roles in enumerate((("developer-selection", "git", "java", "javac"), ("developer-selection", "git", "xcode"))):
                rows = []
                for role in roles:
                    baseline = {"kind": "no-local-policy", "version": None, "build": None}
                    if role in ("java", "javac"):
                        baseline = {"kind": "workflow-reference", "version": "21", "build": None}
                    if role == "xcode":
                        baseline = {"kind": "exact-pin", "version": "26.0", "build": "17A324"}
                    row = {"id": role, "state": "completed", "reason": "observed", "version": None,
                           "build": None, "returnCode": 0, "baseline": baseline, "assessment": "not-assessed"}
                    if role in ("git", "java"):
                        row.update(version="2.49.0" if role == "git" else "21.0.2", assessment="no-local-policy")
                    elif role in ("javac", "xcode"):
                        row.update(state="not-run", reason="missing-in-supported-lookup" if role == "javac" else "full-xcode-not-selected", returnCode=None)
                    rows.append(row)
                checks["tools"].append({"runId": str(index+1)*32, "ownerGeneration": ("a", "c")[index]*32,
                    "context": {**context, "platform": ("android", "ios")[index]}, "statusRevision": (4, 8)[index],
                    "phase": "settled", "finality": "settled", "outcome": "complete", "commandsAttempted": (3, 2)[index],
                    "checks": rows, "sameOriginal": True, "rendered": True, "staleAfterContextChange": index == 0})
        else:
            context.update(draftRevision=1, operation="offline-preflight", savedConfig={"bytes": len(M.CONFIG), "sha256": M.digest(M.CONFIG)})
            findings = [{"ordinal": index, "check": name, "status": status, "message": name, "projectCheckIndex": None}
                        for index, (name, status) in enumerate((("version-source", "PASS"), ("android-gradle-wrapper", "MISSING"), ("workspace-private-output", "PASS")))]
            counts = dict.fromkeys(M.LOCAL_CHECK_STATUSES, 0); counts.update(PASS=2, MISSING=1)
            checks["offline"] = {"operationId": "3"*32, "ownerGeneration": "b"*32, "context": context,
                "statusRevision": 6, "phase": "terminal", "outcome": "complete", "sameOriginal": True,
                "dirtyDraftObserved": True, "explicitConsent": True, "startArrivalObserved": True, "startArrivalLate": False,
                "rendered": True, "draftDiscardedThroughUi": True, "result": {"schemaVersion": 1,
                    "scope": "saved-offline-android-no-core-build", "usedConfig": deepcopy(context["savedConfig"]),
                    "findings": findings, "summary": {"total": 3, "shown": 3, "omitted": 0, "counts": counts},
                    "limitations": list(M.LOCAL_CHECK_LIMITATIONS)}}
        return value

    def test_local_checks_scope_uses_original_rosters_and_deadlines(self):
        cases = ("local-tool-observations", "local-saved-offline")
        self.assertEqual(M.LOCAL_CHECK_CASES, cases)
        self.assertEqual(M.selected_cases("doctor-preflight2"), cases)
        self.assertEqual(M.argument_scope(["--scope", "doctor-preflight2"]), "doctor-preflight2")
        self.assertEqual(M.selected_cases(), M.CASES)
        self.assertEqual([M.case_timeout(c) for c in cases], [105, 1875])
        self.assertEqual(sum(M.case_timeout(c) for c in cases), 1980)
        self.assertEqual(M.LOCAL_CHECK_IDS, (("developer-selection", "git", "java", "javac"), ("developer-selection", "git", "xcode")))
        self.assertTrue(BINDING.root(local_checks=True).name.endswith("-doctor-preflight"))
        for kwargs in ({"local_checks": 1}, {"local_checks": True, "local_edits": True}):
            with self.assertRaises(M.Refused): BINDING.root(**kwargs)
        for argv in (["--scope", cases[0]], ["--scope", "doctor-preflight2", "--timeout", "9999"]):
            with self.assertRaises(M.Refused): M.argument_scope(argv)
        for case in cases:
            files, dirs = M.fixture_data(case, False)
            self.assertEqual((len(files), len(dirs)), (5, 3))
            self.assertEqual(M.fixture_data(case, True), (files, dirs))
            self.assertLess(sum(map(len, files.values())), 65536)
            self.assertEqual(set(files), {".gitignore", "app/build.gradle.kts", "keep.txt", "release/mobile-release.json", "version.properties"})
            self.assertNotIn("gradlew", files)
            # Real private regular files and held original descriptors. No core
            # import, tool invocation, fixture hook or native finality is faked.
            with tempfile.TemporaryDirectory(prefix="mrk-doctor-data-") as temporary:
                root = Path(temporary)
                for name, (mode, _entries) in dirs.items():
                    if name != ".": (root / name).mkdir()
                    (root / name).chmod(mode)
                for name, body in files.items():
                    (root / name).write_bytes(body); (root / name).chmod(0o600)
                fixture = M.Fixtures(BINDING, M.os.getuid(), M.os.getgid(), M.LOCAL_CHECK_SCOPE)
                fixture.projects[case] = fixture._open(str(root), directory=True)
                try:
                    original = fixture._capture(case, False)
                    fixture.originals[case] = original
                    fixture.last_returned = True  # Only this file-reader test's inert precondition.
                    with patch.object(fixture, "_namespace") as namespace:
                        observed = fixture.readback(case)
                        namespace.assert_called_once_with()
                    self.assertEqual(observed["localChecks"], self.returned_data(case)["localChecks"]["fixture"])
                    self.assertEqual(fixture._capture(case, True), original)
                    self.assertEqual(len(fixture.fds), 1)
                    # Changed bytes are not repaired or accepted by readback.
                    (root / "keep.txt").write_bytes(b"changed-public-sentinel")
                    with patch.object(fixture, "_namespace"), self.assertRaises(M.Refused): fixture.readback(case)
                finally:
                    fixture.close()
                self.assertEqual(fixture.fds, set()); self.assertEqual(fixture.close_errors, 0)
        fixtures = InertFixtures(); fixtures.cases = cases
        def readback(case):
            if fixtures.inflight or not fixtures.last_returned: raise AssertionError("original must return")
            fixtures.reads.append(case)
            return M.validate_snapshot(initial_snapshot(case), initial_snapshot(case), case, True, UID, GID)
        fixtures.readback = readback
        calls, emitted = [], []
        def returned(argv, **kwargs):
            calls.append((argv, kwargs))
            return CompletedProcess(argv, 0, captured(self.returned_data(argv[1])), b"")
        self.assertEqual(M.run_cases(BINDING, fixtures, returned, UID, "runner", emitted.append, M.LOCAL_CHECK_SCOPE), ())
        self.assertEqual(fixtures.before, list(cases)); self.assertEqual(fixtures.reads, list(cases))
        self.assertEqual(len(emitted), 2)
        for (argv, opts), case in zip(calls, cases):
            self.assertEqual(argv, [M.EXECUTABLE, case])
            self.assertEqual(opts["timeout"], M.case_timeout(case))
            self.assertEqual(opts["cwd"], BINDING.root(local_checks=True) / "state" / case)
            self.assertEqual(opts["output_limit"], 2*1024*1024)
            self.assertIs(opts["capture"], True); self.assertIs(opts["text"], False)
        unknown = InertFixtures(); unknown.cases = cases
        original_error = RuntimeError("inert original has no returned result")
        def unreturned(*_args, **_kwargs): raise original_error
        with self.assertRaises(RuntimeError) as caught:
            M.run_cases(BINDING, unknown, unreturned, UID, "runner", lambda _: self.fail("no publication"), M.LOCAL_CHECK_SCOPE)
        self.assertIs(caught.exception, original_error)
        self.assertTrue(unknown.inflight); self.assertFalse(unknown.last_returned)
        self.assertEqual(unknown.before, [cases[0]]); self.assertEqual(unknown.reads, [])

    def test_local_checks_reject_mismatched_partial_and_false_positive_results(self):
        for case in M.LOCAL_CHECK_CASES:
            good = self.returned_data(case)
            self.assertEqual(M.parse_result(captured(good), b"", BINDING, case), good)
            self.assertEqual(good["localChecks"]["releaseReadiness"], "not-assessed")
            self.assertFalse(good["shippingBinaryQualified"])
            with self.assertRaises(M.Refused):
                M.parse_result(captured(M.expected_result(BINDING, case)), b"", BINDING, case)
            mutations = [(('releaseReadiness',), 'ready'), (('physicalDropdownGestureTested',), True),
                         (('sameOriginalNativeTerminals',), 1), (('exactFixtureReadback',), False),
                         (('fixture', 'sha256', 'keep.txt'), '0'*64)]
            if case == M.LOCAL_CHECK_CASES[0]:
                mutations += [(('tools', 0, 'runId'), 'wrong'), (('tools', 1, 'runId'), '1'*32),
                    (('tools', 1, 'ownerGeneration'), 'a'*32), (('tools', 1, 'statusRevision'), 4),
                    (('tools', 1, 'context', 'draftRevision'), 1), (('tools', 0, 'phase'), 'checking'),
                    (('tools', 0, 'finality'), 'pending'), (('tools', 0, 'outcome'), 'failed'),
                    (('tools', 0, 'staleAfterContextChange'), False), (('tools', 1, 'staleAfterContextChange'), True),
                    (('tools', 1, 'rendered'), False), (('tools', 0, 'commandsAttempted'), 4),
                    (('tools', 0, 'checks', 0, 'id'), 'xcode'), (('tools', 0, 'checks', 1, 'returnCode'), 3),
                    (('tools', 0, 'checks', 1, 'assessment'), 'match'), (('tools', 0, 'checks', 3, 'state'), 'completed'),
                    (('tools', 1, 'checks', 2, 'assessment'), 'match')]
            else:
                mutations += [(('offline', 'operationId'), 'wrong'), (('offline', 'phase'), 'running'),
                    (('offline', 'outcome'), 'failed'), (('offline', 'startArrivalObserved'), False),
                    (('offline', 'startArrivalLate'), True), (('offline', 'startArrivalLate'), 0),
                    (('offline', 'dirtyDraftObserved'), False), (('offline', 'explicitConsent'), False),
                    (('offline', 'draftDiscardedThroughUi'), False), (('offline', 'rendered'), False),
                    (('offline', 'context', 'savedConfig', 'sha256'), '0'*64), (('offline', 'result', 'usedConfig', 'bytes'), len(M.CONFIG)+1),
                    (('offline', 'result', 'limitations'), []), (('offline', 'result', 'summary', 'omitted'), 1),
                    (('offline', 'result', 'summary', 'counts', 'PASS'), 3), (('offline', 'result', 'findings', 1, 'status'), 'PASS'),
                    (('offline', 'result', 'findings', 1, 'ordinal'), 2), (('offline', 'result', 'findings', 1, 'projectCheckIndex'), 0)]
            for path, replacement in mutations:
                changed = deepcopy(good); slot = changed['localChecks']
                for part in path[:-1]: slot = slot[part]
                slot[path[-1]] = replacement
                with self.subTest(case=case, path=path), self.assertRaises(M.Refused):
                    M.parse_result(captured(changed), b"", BINDING, case)
        good = self.returned_data("local-tool-observations")
        self.assertEqual(good['localChecks']['tools'][1]['checks'][2]['reason'], 'full-xcode-not-selected')
        for run in good['localChecks']['tools']:
            for row in run['checks']:
                if row['id'] != 'developer-selection':
                    row.update(state='not-run', reason='missing-in-supported-lookup', version=None, build=None, returnCode=None, assessment='not-assessed')
            run['commandsAttempted'] = 1
        with self.assertRaises(M.Refused): M.parse_result(captured(good), b'', BINDING, 'local-tool-observations')
        # Mismatch is an actual negative observation, not a fabricated PASS.
        mismatch = self.returned_data('local-tool-observations')
        xcode = mismatch['localChecks']['tools'][1]['checks'][2]
        xcode.update(state='completed', reason='observed', version='25.0', build='16A100', returnCode=0, assessment='mismatch')
        mismatch['localChecks']['tools'][1]['commandsAttempted'] = 3
        self.assertEqual(M.parse_result(captured(mismatch), b'', BINDING, 'local-tool-observations'), mismatch)
        offline = self.returned_data('local-saved-offline')['localChecks']['offline']
        self.assertEqual(offline['result']['summary']['counts']['MISSING'], 1)
        # A replacement original or changed fixed file is not an exact readback.
        case = 'local-saved-offline'; before = initial_snapshot(case)
        for name, field in (('keep.txt', 1), ('.', 5), ('release/mobile-release.json', 8)):
            changed = dict(before); node = changed[name]; identity = list(node.identity); identity[field] += 1
            changed[name] = replace(node, identity=tuple(identity))
            with self.assertRaises(M.Refused): M.validate_snapshot(before, changed, case, True, UID, GID)

    def test_local_checks_ui_workflow_and_same_original_source_bindings(self):
        root = PATH.parents[2]; rust = root / 'desktop/src-tauri/src'
        child = (rust / 'installed_shell_observation_macos_checks.rs').read_text()
        parent = (rust / 'installed_shell_observation_macos.rs').read_text()
        shell = (rust / 'shell.rs').read_text()
        environment = (root / 'desktop/src/pages/Environment.tsx').read_text()
        controller = (root / 'desktop/src/environment.ts').read_text()
        tool_ui = (root / 'desktop/src/components/EnvironmentDiagnostics.tsx').read_text()
        offline_ui = (root / 'desktop/src/components/OfflinePreflight.tsx').read_text()
        fields = (root / 'desktop/src/components/Fields.tsx').read_text()
        help_data = json.loads((root / 'src/mobile_release/api/data/field-help.json').read_text())
        # Bind the real two-option Environment control, not the three-option
        # Metadata editor's disabled placeholder or a reducer shortcut.
        self.assertIn('<option value="android">Android</option><option value="ios">iOS</option>', environment)
        self.assertIn("s.options.length!==2", child)
        self.assertIn("s.selectedIndex=1;s.dispatchEvent(new Event('change',{bubbles:true}))", child)
        self.assertIn('diagnosticsController.setContext(platform, operation)', environment)
        context_body = controller.split('  setContext(', 1)[1].split('  private current(', 1)[0]
        self.assertIn('this.invalidate({ platform, operation', context_body)
        self.assertNotIn('refresh()', context_body)
        self.assertIn('controller.start()', tool_ui)
        self.assertIn('Complete means the finite check roster finished, not that every tool matched.', tool_ui)
        self.assertIn('acknowledged original Start', child)
        self.assertIn('Earlier / stale tool observations', child)
        self.assertIn('Core resource observations — provisional, not native finality', tool_ui)
        self.assertIn('controller.prepare()', offline_ui)
        self.assertIn('controller.start(consent.operationId, consent.ownerGeneration)', offline_ui)
        self.assertIn('Unsaved draft changes are NOT used.', child + offline_ui)
        self.assertIn('Complete is not PASS or release readiness.', child + offline_ui)
        self.assertIn("document.execCommand('insertText',false,'public-offline-draft')", child)
        self.assertIn('onChange', fields)
        # The actual catalogue, not a guessed display-name selector.
        self.assertIn('Candidate branch', json.dumps(help_data))
        for text in ('Discard draft changes', 'Discard this in-memory draft?', 'Discard draft', "draft('main',false)"):
            self.assertIn(text, child)
        for action, actual in (('checks_tools_request(value);', 'state.document.start_environment_diagnostics(args)'),
                              ('checks_prepare_request(&value);', 'state.document.prepare_offline_preflight(args)'),
                              ('checks_start_request(&value);', 'state.document.start_offline_preflight(args)')):
            start = shell.index(action); end = shell.index(actual, start)
            self.assertGreater(end, start)
            self.assertNotIn('return', shell[start:end]); self.assertNotIn('?', shell[start:end])
        late = child.split('fn observe(&mut self,elapsed:Duration)', 1)[1].split('struct ToolRun', 1)[0]
        self.assertLess(late.index('self.observed=true'), late.index('if self.late'))
        self.assertIn('self.late=elapsed>Duration::from_secs(30)', late)
        self.assertIn('assert!(late.observed&&late.late)', child)
        self.assertIn('checks::Record::new(c,started)', parent)
        self.assertIn('let end = started + Duration::from_secs', parent)
        self.assertIn('if record.waiting(wait){return;}', parent)
        self.assertIn('r.fixture.verify(true)', parent)
        self.assertIn('r.native_actions_returned==[false,true,false,true]', parent)
        self.assertIn('record.readback().is_err()', parent)
        self.assertIn('p["finality"]=="settled"', child)
        self.assertIn('p["phase"]=="terminal"', child)
        self.assertIn('same(old,p,"operationId")', child)
        self.assertIn('same(&run.projection,p,"runId")', child)
        for name in ('environment_diagnostics_owner.rs', 'saved_command_owner.rs'):
            owner = (rust / name).read_text()
            self.assertIn('let Poll::Ready(result) = Pin::new(handle).poll', owner)
            self.assertIn('record_join(&owner.watchdog_return, result)', owner)
            self.assertIn('final_clock_clear(', owner)
            self.assertIn('Arc::ptr_eq(&active.owner, &owner)', owner)
            if name == 'environment_diagnostics_owner.rs':
                self.assertIn('id: nonce()?, generation: nonce()?', owner)
                self.assertIn('last.run_id == ticket.id || last.owner_generation == ticket.generation', owner)
                self.assertIn('r.projection["ownerGeneration"]==p["ownerGeneration"]', child)
        for forbidden in ('__TAURI__', '__TAURI_INTERNALS__', 'invoke(', 'std::process::Command', 'thread::spawn', 'tokio::spawn',
                          '.start_offline_preflight(', '.start_environment_diagnostics(', '.cancel_offline_preflight(', '.cancel_environment_diagnostics('):
            self.assertNotIn(forbidden, child)
        workflow = (root / '.github/workflows/desktop-macos-aqua.yml').read_text()
        matrix = workflow.split('      matrix:\n', 1)[1].split('    runs-on:', 1)[0]
        self.assertNotIn('doctor-preflight2', matrix)
        self.assertEqual(matrix, "        include:\n          - scope: local-edits3\n            target: aarch64-apple-darwin\n            runner: macos-26\n            supplier_receipt: '2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d'\n            supplier_tar: 'ff7883185cf8226e9366b1ee9a3dcb3eb8ee761dbc1f697f952510a6bd858695'\n            supplier_source: '158cdff422e3837f7ab5e6192af76a578faf6fab'\n            supplier_run: '37467019389'\n            supplier_attempt: '1'\n            supplier_artifact: '11415902210'\n          - scope: local-edits3\n            target: x86_64-apple-darwin\n            runner: macos-26-intel\n            supplier_receipt: 'a46f6838afdb7c20c3539e8f65891312aa8df10e2de67e9b9e3ddbf449883b4b'\n            supplier_tar: '739cc8b8b3c68daffba8d7b9cb7cb54ca730eef2c5842302ae8a2682bf64d5bd'\n            supplier_source: '079ab2a2c8fef88f01bf909e7669c685f07e1375'\n            supplier_run: '37476532238'\n            supplier_attempt: '1'\n            supplier_artifact: '11419502465'\n")
        self.assertIn("timeout-minutes: ${{ matrix.scope == 'doctor-preflight2' && 212 || contains(fromJSON('[\"project-fields\",\"ios-current-synthetic\",\"android-inputs\",\"project-fields-android-inputs\",\"vault-helper-shipping\",\"installation-inspection\",\"vault-helper-shipping-installation-inspection\",\"project-recovery-pending\",\"ios-recovery-pending\",\"doctor-preflight2\",\"local-edits3\"]'), matrix.scope) && 137 || 75 }}", workflow)
        self.assertEqual(workflow.count("|| env.MRK_MACOS_AQUA_SCOPE == 'doctor-preflight2' ||"), 26)
        step = workflow.split('      - name: Two serial doctor and saved offline Aqua journeys', 1)[1].split('      - name:', 1)[0]
        for required in ("if: success() && env.MRK_MACOS_AQUA_SCOPE == 'doctor-preflight2'", 'timeout-minutes: 35',
                         'set -o noclobber', 'umask 077', 'RUNNER_ENVIRONMENT: ${{ runner.environment }}',
                         'macos_aqua_qualification.py --scope doctor-preflight2 --target "$MRK_MACOS_TARGET"', '[[ $status == 0 ]] || exit "$status"'):
            self.assertIn(required, step)
        self.assertIn('"doctor-preflight2": ("two-doctor-preflight-Aqua-engineering-cases", ["local-tool-observations", "local-saved-offline"])', workflow)
        for name in ('results.jsonl', 'failure.jsonl'):
            self.assertIn('${{ steps.work.outputs.root }}/aqua-doctor-preflight2-' + name, workflow)
        self.assertIn('${{ steps.work.outputs.root }}/aqua-doctor-preflight2.status', workflow)
        self.assertNotIn('workflow_dispatch:', workflow.split('permissions:', 1)[0])
        source = PATH.read_text()
        run = source.split('def run_cases(', 1)[1].split('def recovery_supplier_route', 1)[0]
        self.assertEqual(run.count('result = run_owned(argv,'), 1)
        self.assertLess(run.index('need(result.returncode == 0, "app-return")'), run.index('report = parse_result'))
        self.assertLess(run.index('report = parse_result'), run.index('readback["localChecks"]'))
        self.assertLess(run.index('readback["localChecks"]'), run.index('emit({"schemaVersion": 1'))
        for name in ('actual_context_and_terminal_are_required', 'complete_report_never_promotes_readiness'):
            self.assertIn('fn ' + name + '()', child)

if __name__ == "__main__":
    unittest.main()
