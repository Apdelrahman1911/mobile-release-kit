"""Inert DATA/control-flow regressions, not Mac/native/process evidence.

No core owner is imported, no command/native fixture is run, and no candidate
process or filesystem readback is substituted for required hosted Aqua cases.
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


def context_data():
    return {"pending": {"kind": "native", "step": "CancelProject"},
            "nativeHandler": {"step": "CancelProject", "entered": True, "returned": False},
            "lastPanel": {"step": "CancelProject", "id": 1, "kind": "project",
                          "parentPresent": True, "panelPresent": True, "parentReferencesPanel": False,
                          "panelReferencesParent": True, "panelVisible": False}}


def context_row(value):
    return b"MRK_MACOS_AQUA_FAILURE_CONTEXT=" + json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"


def action_context_data(step="OpenProject", *, site=None, domain="objc-exception", error="io"):
    action, kind, panel_id, call_site = {
        "CancelProject": ("project-cancel", "project", 1, "project-cancel"),
        "SetProject": ("project-directory", "project", 2, "directory-set"),
        "OpenProject": ("project-open", "project", 2, "project-open"),
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


def unrequested_recheck():
    return {"state": "unrequested", **dict.fromkeys(M.ACCESSIBILITY_RECHECK_FLAGS, False),
            "timely": None, "custodyKnown": None, "proof": None}


def accessibility_context_data():
    value = action_context_data()
    value["nativeAction"] = None  # The old selector is historical DATA only.
    value["accessibility"] = deepcopy(M.expected_result(BINDING, "first-save")["native"]["projectOpenInput"])
    return value


def binding_context_data(case="first-save"):
    # A start can fail before any native handler or Press exists. This DATA
    # fixture deliberately supplies neither, rather than inventing an action.
    return {"pending": None, "nativeHandler": None, "lastPanel": None, "nativeAction": None, "accessibility": None,
            "accessibilityBinding": deepcopy(M.expected_result(BINDING, case)["native"]["projectOpenBinding"])}


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
        self.assertEqual((len(M.VERSION), len(M.IGNORE_PREFIX), len(M.IGNORE_RULES), len(M.STALE)), (34, 40, 208, 26))
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

    def test_accessibility_samples_distinguish_preparation_unknown_and_actual_return(self):
        value = accessibility_context_data()
        examples = [deepcopy(value)]
        same_first = deepcopy(value)
        same_first["lastPanel"]["id"] = same_first["accessibility"]["id"] = 1
        examples.append(same_first)
        historical = deepcopy(value)
        historical["nativeHandler"] = {"step": "Quit", "entered": False, "returned": False}
        historical["lastPanel"] = None
        historical["pending"] = {"kind": "native", "step": "Quit"}
        examples.append(historical)
        sample = value["accessibility"]
        flags = ("attempted", "pressReturned", "identityMatched", "controlMatched", "cleanupReturned", "nativeRechecked")
        sample.update(prepared=False, entered=False, returned=False, retired=False, attempted=False, pressReturned=False,
                      identityMatched=None, controlMatched=None, cleanupReturned=None, nativeRechecked=None,
                      phase=None, calls=None, initialProjection=None, finalProjection=None,
                      nativeRecheck=unrequested_recheck(), site="binding", error="unsupported")
        examples.append(deepcopy(value))
        sample.update(prepared=True, site=None, error=None)
        examples.append(deepcopy(value))
        sample.update(retired=True, site="entry", error="deadline")
        examples.append(deepcopy(value))  # Positive no-FFI-entry is not native return.
        sample.update(entered=True, retired=False, **dict.fromkeys(flags), site=None, error=None)
        value["pending"] = {"kind": "accessibility", "step": "OpenProject"}
        examples.append(deepcopy(value))
        sample.update(returned=True, site="entry", error="custody")
        examples.append(deepcopy(value))  # Invalid returned ABI cannot retire.
        for error in ("unsupported", "ambiguous", "malformed", "limit", "deadline", "ineligible", "invalid-element"):
            sample.update(attempted=False, pressReturned=False, identityMatched=False, controlMatched=False,
                          nativeRechecked=False, cleanupReturned=True, retired=True, phase="initial", calls=6,
                          initialProjection={"windows": 1, "children": None, "sheets": None, "matched": False},
                          site="parent-identity", error=error)
            value["pending"] = None
            examples.append(deepcopy(value))
        value = accessibility_context_data()
        value["accessibility"]["error"] = "cannot-complete"  # Spent, possibly effective attempt; never retried.
        examples.append(deepcopy(value))
        value["accessibility"].update(pressReturned=False, cleanupReturned=False, retired=False, error="objc-exception")
        value["pending"] = {"kind": "accessibility", "step": "OpenProject"}
        examples.append(deepcopy(value))
        for value in examples:
            with self.subTest(sample=value["accessibility"]):
                self.assertEqual(M.failure_context(context_row(value), b""), value)
                self.assertLess(len(context_row(value)), M.FAILURE_CONTEXT_LIMIT)
                with self.assertRaisesRegex(M.Refused, "^inner-failure-marker$"):
                    M.parse_result(captured(M.expected_result(BINDING, "first-save")), context_row(value), BINDING, "first-save")

    def test_accessibility_malformed_data_never_replaces_existing_failure_context(self):
        good = accessibility_context_data()
        for field, bad in (("id", True), ("id", 1), ("id", 3), ("step", "Quit"), ("mechanism", "accessibility-press"),
                           ("prepared", False), ("entered", False), ("attempted", False), ("pressReturned", None),
                           ("returned", False), ("retired", 1), ("identityMatched", False), ("controlMatched", False),
                           ("cleanupReturned", False), ("site", "private-selector"), ("error", "PRIVATE"),
                           ("nativeRechecked", False), ("nativeRecheck", None), ("phase", "initial"), ("calls", True),
                           ("initialProjection", None), ("finalProjection", None), ("identifier", "PRIVATE")):
            value = deepcopy(good); value["accessibility"][field] = bad
            expected = deepcopy(good); expected["accessibility"] = None
            self.assertEqual(M.failure_context(context_row(value), b""), expected, (field, bad))
        for field, bad in (("id", 1), ("kind", "quit")):
            value = deepcopy(good); value["lastPanel"][field] = bad
            expected = deepcopy(value); expected["accessibility"] = None
            self.assertEqual(M.failure_context(context_row(value), b""), expected)
        for missing_panel, returned in ((True, True), (False, False)):
            value = deepcopy(good); value["nativeHandler"]["returned"] = returned
            if missing_panel:
                value["lastPanel"] = None
            expected = deepcopy(value); expected["accessibility"] = None
            self.assertEqual(M.failure_context(context_row(value), b""), expected)
        row = context_row(good)
        self.assertIsNone(M.failure_context(row.replace(b'"attempted":true', b'"attempted":true,"attempted":false'), b""))
        empty = {"pending": None, "nativeHandler": None, "lastPanel": None, "nativeAction": None, "accessibility": None}
        self.assertEqual(M.failure_context(context_row(empty), b""), empty)

    def test_success_requires_actual_trust_and_one_retired_public_press(self):
        fields = ("prepared", "entered", "attempted", "pressReturned", "returned", "retired", "identityMatched",
                  "controlMatched", "cleanupReturned", "nativeRechecked")
        for case in M.CASES:
            good = M.expected_result(BINDING, case)
            self.assertEqual(M.parse_result(captured(good), b"", BINDING, case), good)
            variants = []
            for bad in (False, None, 1):
                value = deepcopy(good); value["native"]["accessibilityTrustedWithoutPrompt"] = bad; variants.append(value)
            if case == "picker-loss":
                self.assertIsNone(good["native"]["projectOpenInput"])
                value = deepcopy(good); value["native"]["projectOpenInput"] = accessibility_context_data()["accessibility"]
                variants.append(value)
            else:
                self.assertEqual(good["native"]["projectOpenInput"]["mechanism"], "accessibility-press-original-sheet-v1")
                for field in fields:
                    for bad in (False, None, 1):
                        value = deepcopy(good); value["native"]["projectOpenInput"][field] = bad; variants.append(value)
                for field, bad in (("error", "cannot-complete"), ("site", "default-button"), ("mechanism", "accessibility-press"),
                                   ("id", 3), ("phase", "final"), ("nativeRecheck", unrequested_recheck())):
                    value = deepcopy(good); value["native"]["projectOpenInput"][field] = bad; variants.append(value)
            for value in variants:
                with self.assertRaises(M.Refused):
                    M.parse_result(captured(value), b"", BINDING, case)

    def test_original_sheet_native_proof_and_exact_aggregate_call_budget_are_mandatory(self):
        good = M.expected_result(BINDING, "first-save")
        for proof_path in (("projectOpenBinding", "binding"), ("projectOpenInput", "nativeRecheck", "proof")):
            for check in M.ACCESSIBILITY_PROOF_CHECKS:
                for bad in (False, None, 1):
                    value = deepcopy(good); proof = value["native"]
                    for part in proof_path:
                        proof = proof[part]
                    proof["checks"][check] = bad
                    with self.assertRaises(M.Refused):
                        M.parse_result(captured(value), b"", BINDING, "first-save")
        # Variable topology is allowed only when the complete two-pass count
        # leaves exactly1..8 ancestry edges within the unchanged64-call budget.
        for windows, children, final_windows, final_children, edges in ((1, 1, 1, 1, 1), (2, 3, 1, 4, 2), (4, 4, 3, 3, 5)):
            value = deepcopy(good); sample = value["native"]["projectOpenInput"]
            sample["initialProjection"].update(windows=windows, children=children)
            sample["finalProjection"].update(windows=final_windows, children=final_children)
            sample["calls"] = 2 * (13 + windows + children + final_windows + final_children + edges)
            self.assertEqual(M.parse_result(captured(value), b"", BINDING, "first-save"), value)
            for bad in (True, None, 35, 65, sample["calls"] + 1, 2 * (13 + windows + children + final_windows + final_children)):
                broken = deepcopy(value); broken["native"]["projectOpenInput"]["calls"] = bad
                with self.assertRaises(M.Refused):
                    M.parse_result(captured(broken), b"", BINDING, "first-save")
        for path in ("initialProjection", "finalProjection"):
            for field, bad in (("windows", 5), ("children", 17), ("sheets", 0), ("sheets", 2), ("matched", False), ("children", True)):
                value = deepcopy(good); value["native"]["projectOpenInput"][path][field] = bad
                with self.assertRaises(M.Refused):
                    M.parse_result(captured(value), b"", BINDING, "first-save")

    def test_native_recheck_unknown_negative_and_joined_receipts_are_not_interchangeable(self):
        good = accessibility_context_data()
        success = good["accessibility"]["nativeRecheck"]
        for field, bad in (("state", "unknown"), ("state", "queued"), ("timely", False), ("custodyKnown", False),
                           ("proof", None), *((key, False) for key in M.ACCESSIBILITY_RECHECK_FLAGS)):
            value = deepcopy(good); value["accessibility"]["nativeRecheck"][field] = bad
            expected = deepcopy(value); expected["accessibility"] = None
            self.assertEqual(M.failure_context(context_row(value), b""), expected)
        # A timely known-negative receipt permits no Press. It may retire only
        # with the actual original AX return/cleanup/custody, unlike Unknown.
        value = deepcopy(good); sample = value["accessibility"]
        sample.update(attempted=False, pressReturned=False, identityMatched=False, controlMatched=False,
                      nativeRechecked=False, phase="native-recheck", calls=12, finalProjection=None,
                      site="native-recheck", error="ineligible")
        sample["nativeRecheck"].update(nativeEntered=False, proof=None)
        self.assertEqual(M.failure_context(context_row(value), b""), value)
        value["accessibility"]["nativeRecheck"] = {**unrequested_recheck(), "state": "unknown", "requested": True,
            "dispatchAttempted": True, "timely": False}
        sample.update(retired=False, error="deadline")
        self.assertEqual(M.failure_context(context_row(value), b""), value)
        sample["retired"] = True
        expected = deepcopy(value); expected["accessibility"] = None
        self.assertEqual(M.failure_context(context_row(value), b""), expected)
        # In-flight DATA does not claim native non-entry simply because the
        # original main body has not returned any native-entry facts yet.
        sample.update(returned=False, retired=False, site=None, error=None,
                      **dict.fromkeys(("attempted", "pressReturned", "identityMatched", "controlMatched", "cleanupReturned",
                                       "nativeRechecked", "phase", "calls", "initialProjection", "finalProjection")))
        sample["nativeRecheck"] = {**unrequested_recheck(), "state": "entered", "requested": True,
                                   "dispatchAttempted": True, "bodyEntered": True}
        self.assertEqual(M.failure_context(context_row(value), b""), value)
        self.assertEqual(success["state"], "joined")  # Fixtures do not alias the expected proof.

    def test_early_binding_matrix_is_diagnostic_but_late_identity_is_mandatory(self):
        for case in ("first-save", "noop-stale", "save-loss"):
            for parent in ("nil", "match", "different", "type-invalid"):
                good = M.expected_result(BINDING, case)
                sample = good["native"]["projectOpenBinding"]
                sample["configuration"]["parent"] = parent
                self.assertEqual(M.parse_result(captured(good), b"", BINDING, case), good)
                context = binding_context_data(case); context["accessibilityBinding"] = deepcopy(sample)
                self.assertEqual(M.failure_context(context_row(context), b"", case), context)
                if parent == "match":
                    continue
                sample["binding"].update(parent=parent, site="parent-identifier", error="unsupported")
                sample["binding"]["checks"]["parentIdentifier"] = False
                context["accessibilityBinding"] = deepcopy(sample)
                self.assertEqual(M.failure_context(context_row(context), b"", case), context)
                with self.assertRaisesRegex(M.Refused, "^project-open-binding$"):
                    M.parse_result(captured(good), b"", BINDING, case)
        for panel in ("nil", "type-invalid", "empty", "byte-limit", "nul", "encoding-invalid", "different"):
            good = M.expected_result(BINDING, "first-save"); proof = good["native"]["projectOpenBinding"]["binding"]
            proof.update(panel=panel, site="stable-identifier", error="changed")
            proof["checks"].update(stableIdentifier=False, finalEligibility=None)
            context = binding_context_data(); context["accessibilityBinding"]["binding"] = proof
            self.assertEqual(M.failure_context(context_row(context), b"", "first-save"), context)
            self.assertIs(proof["checks"]["panelIdentifier"], True)
            for field, bad in (("site", "panel-identifier"), ("error", "unsupported"), ("finalEligibility", True)):
                broken = deepcopy(context); target = broken["accessibilityBinding"]["binding"]
                if field == "finalEligibility":
                    target["checks"][field] = bad
                else:
                    target[field] = bad
                expected = deepcopy(broken); expected["accessibilityBinding"] = None
                self.assertEqual(M.failure_context(context_row(broken), b"", "first-save"), expected)
            with self.assertRaises(M.Refused):
                M.parse_result(captured(good), b"", BINDING, "first-save")
        missing = M.expected_result(BINDING, "first-save"); missing["native"]["projectOpenBinding"] = None
        with self.assertRaises(M.Refused):
            M.parse_result(captured(missing), b"", BINDING, "first-save")
        picker = M.expected_result(BINDING, "picker-loss")
        picker["native"]["projectOpenBinding"] = binding_context_data()["accessibilityBinding"]
        with self.assertRaises(M.Refused):
            M.parse_result(captured(picker), b"", BINDING, "picker-loss")

    def test_binding_partial_returns_remain_data_without_action_or_finality(self):
        flags = ("parentSetterEntered", "parentSetterReturned")
        examples = []
        for result in ("permission-denied", "io", "invalid-input", "already", "other"):
            context = binding_context_data(); sample = context["accessibilityBinding"]
            sample["start"]["result"] = result; sample["binding"] = None
            sample["configuration"].update(attempted=False, **dict.fromkeys(flags, False), parent=None, site=None, error=None)
            examples.append(context)
        for site, error, bits, parent in (
            ("objects", "ineligible", (False, False), None), ("parent-tag", "invalid-input", (False, False), None),
            ("parent-tag", "objc-exception", (False, False), None), ("parent-set", "objc-exception", (True, False), None),
            ("parent-get", "objc-exception", (True, True), None), ("complete", "none", (True, True), "different"),
        ):
            context = binding_context_data(); sample = context["accessibilityBinding"]
            sample["start"]["result"] = "io"; sample["binding"] = None
            sample["configuration"].update(**dict(zip(flags, bits)), parent=parent, site=site, error=error)
            examples.append(context)
        for attempted, site, error, eligible in ((False, "objects", "custody", None),
                                                (True, "objects", "ineligible", False),
                                                (True, "attachment", "objc-exception", True)):
            context = binding_context_data()
            context["accessibilityBinding"]["binding"] = {"returned": True, "attempted": attempted,
                "checks": {**dict.fromkeys(M.ACCESSIBILITY_PROOF_CHECKS), "eligible": eligible},
                "parent": None, "panel": None, "children": None, "originals": None, "site": site, "error": error}
            examples.append(context)
        for context in examples:
            self.assertEqual(M.failure_context(context_row(context), b"", "first-save"), context)
            self.assertIsNone(context["nativeHandler"])
            self.assertIsNone(context["accessibility"])
        with inert_exception_owner(stderr=context_row(examples[8])) as call:
            fixtures = InertFixtures()
            with self.assertRaises(RuntimeError) as caught:
                M.run_cases(BINDING, fixtures, call.owner.run_owned, UID, "runner", self.fail)
            self.assertIs(caught.exception, call.original)
            self.assertEqual(fixtures.inner_failure_context, examples[8])
            self.assertTrue(fixtures.inflight)
            self.assertFalse(fixtures.last_returned)
            self.assertIsNone(fixtures.app_returncode)
            self.assertEqual(fixtures.before, ["first-save"])
            self.assertEqual(fixtures.reads, [])

    def test_binding_malformed_or_wrong_case_drops_only_new_diagnostic(self):
        good = accessibility_context_data()
        good["accessibilityBinding"] = binding_context_data()["accessibilityBinding"]
        variants = []
        for path, bad in (
            (("mechanism",), "public-accessibility-identifier"), (("case",), "noop-stale"), (("id",), True), (("id",), 1),
            (("kind",), "quit"), (("tag",), "PRIVATE"), (("start", "returned"), False), (("start", "returned"), 1),
            (("start", "result"), "permission-denied"), (("start", "result"), "unknown-status"),
            (("configuration", "parentSetterEntered"), False), (("configuration", "panelSetterReturned"), True),
            (("configuration", "parent"), None), (("configuration", "panel"), "match"),
            (("configuration", "error"), "unsupported"), (("configuration", "site"), "parent-get"),
            (("binding", "returned"), False), (("binding", "returned"), 1), (("binding", "attempted"), False),
            (("binding", "parent"), "nil"), (("binding", "panel"), "different"), (("binding", "children"), True),
            (("binding", "children"), 17), (("binding", "originals"), "multiple"),
            (("binding", "site"), "parent-set"), (("binding", "error"), "PRIVATE"),
        ):
            value = deepcopy(good); target = value["accessibilityBinding"]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = bad; variants.append(value)
        for value in variants:
            expected = deepcopy(value); expected["accessibilityBinding"] = None
            self.assertEqual(M.failure_context(context_row(value), b"", "first-save"), expected)
        for case in (None, "noop-stale", "picker-loss", "unknown"):
            expected = deepcopy(good); expected["accessibilityBinding"] = None
            self.assertEqual(M.failure_context(context_row(good), b"", case), expected)
        duplicate = context_row(good).replace(b'"result":"ok"', b'"result":"ok","result":"io"')
        self.assertIsNone(M.failure_context(duplicate, b"", "first-save"))
        # Conservative closed-scalar upper bound, not actual/native evidence.
        largest = deepcopy(good)
        largest["accessibilityBinding"]["start"]["result"] = "permission-denied"
        largest["accessibilityBinding"]["configuration"].update(parent="type-invalid", site="parent-get", error="cleanup-unknown")
        for proof in (largest["accessibilityBinding"]["binding"], largest["accessibility"]["nativeRecheck"]["proof"]):
            proof.update(parent="type-invalid", panel="encoding-invalid", children=17, originals="multiple",
                         site="panel-attached-sheet", error="cleanup-unknown", returned=False, attempted=False)
            proof["checks"] = dict.fromkeys(M.ACCESSIBILITY_PROOF_CHECKS, False)
        largest["accessibility"].update(site="parent-identity", error="cleanup-unknown", phase="native-recheck", calls=64)
        largest["accessibility"]["nativeRecheck"]["state"] = "not-dispatched"
        self.assertEqual(M.FAILURE_CONTEXT_LIMIT, 4096)
        self.assertLess(len(context_row(largest)), M.FAILURE_CONTEXT_LIMIT)

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

    def test_native_action_closed_sites_cover_all_five_original_actions(self):
        self.assertEqual(set(M.NATIVE_ACTION_STEPS), {"CancelProject", "SetProject", "OpenProject", "QuitCancel", "Quit"})
        self.assertEqual(len(M.NATIVE_ACTION_SITES), 35)
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
            value = action_context_data("SetProject", site=site, domain="rust-precondition", error="invalid-input")
            self.assertEqual(M.failure_context(context_row(value), b""), value)
        for step, panel_id in (("SetProject", 1), ("OpenProject", 1), ("Quit", 2)):
            value = action_context_data(step)
            value["lastPanel"]["id"] = value["nativeAction"]["id"] = panel_id
            self.assertEqual(M.failure_context(context_row(value), b""), value)

    def test_native_action_missing_invalid_or_stale_data_does_not_replace_context(self):
        good = action_context_data()
        variants = []
        for field, value in (("id", True), ("id", 0), ("id", 5), ("id", 1), ("step", "SetProject"),
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
        prefix = b"MRK_MACOS_AQUA_FAILURE_STEP=OpenProject\nMRK_MACOS_AQUA_FAILURE_REASON=adapter-native-action\n"
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
                self.assertEqual((report["innerFailureStep"], report["innerFailureReason"]), ("OpenProject", "adapter-native-action"))
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
        fixtures, emitted = InertFixtures(), []
        marker = (b"MRK_MACOS_AQUA_FAILURE_STEP=CancelProject\n"
                  b"MRK_MACOS_AQUA_FAILURE_REASON=asset_source_refused\n")
        def runner(argv, **_):
            return CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=marker)
        with self.assertRaisesRegex(M.Refused, "^app-return$") as caught:
            M.run_cases(BINDING, fixtures, runner, UID, "runner", emitted.append)
        report = M.diagnostic(caught.exception, None, fixtures)
        self.assertEqual((report["status"], report["innerFailureStep"], report["innerFailureReason"]),
                         ("failed", "CancelProject", "asset_source_refused"))
        self.assertEqual(report["appReturncode"], 1)
        self.assertEqual(report["innerDiagnosticSource"], "completed-output")
        self.assertEqual(report["innerDiagnosticCompleteness"], "complete")
        self.assertEqual(report["typedLifetimeFacts"], [])
        self.assertEqual(fixtures.before, ["first-save"])
        self.assertEqual((fixtures.reads, emitted), ([], []))
        self.assertIsNone(M.diagnostic(M.Refused("fixture-refused"), None, None)["innerFailureReason"])

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
        predicate = document.split("fn ordinary_asset_platform_gate()", 1)[1].split("fn preflight_document_gate(", 1)[0]
        self.assertIn('cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))', predicate)
        self.assertIn("Reason::UnsupportedPlatform", predicate)
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
        for native_entry in ("Fixture::capture(", "Observation::new(", "super::run_builder("):
            self.assertLess(main.index("if !observer_data_checks()"), main.index(native_entry))
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
        self.assertIn("native.directory_bound || native.directory_returned || native.directory_ready || same_action_returned", readiness)
        action = observer.split("fn native_step(", 1)[1].split("pub(super) fn close_prevented", 1)[0]
        self.assertLess(action.index("if !panel_readiness("), action.index("r.panel_attached[(id - 1) as usize] = true"))
        self.assertLess(action.index("r.panel_attached[(id - 1) as usize] = true"), action.index("observe_panel_action(id,action)"))
        self.assertIn('if let Err(reason) = result { self.fail_with(reason); }', action)
        self.assertNotIn("r.pending.take()", action)
        self.assertLess(action.index("let timely = self.timely()"), action.index("let result = self.native_step_body("))
        self.assertLess(action.index("let result = self.native_step_body(step, timely, &mut action_diagnostic,"), action.index("native.returned = true"))
        body = action.split("fn native_step_body(", 1)[1]
        entry = "if !native_step_entry(std::thread::current().id() == self.main, timely)? { return Ok(false); }"
        self.assertLess(body.index(entry), body.index("observed_panel()"))
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
        self.assertIn("flags & !0x1ffff == 0", rust)
        self.assertIn("(parent_present && panel_present).then_some", rust)

    def test_native_action_source_keeps_original_calls_status_and_closed_decoder(self):
        native_root = PATH.parents[1] / "native" / "macos-installed-native" / "src"
        native = (native_root / "native.m").read_text(encoding="utf-8")
        rust = (native_root / "lib.rs").read_text(encoding="utf-8")
        table = rust.split("const ACTION_SITES:", 1)[1].split("];", 1)[0]
        rows = M.re.findall(r'\("([a-z-]+)", (-?[0-9]+), ([0-9]+), (true|false)\)', table)
        errors = {-1: None, 0: "none", 1: "permission-denied", 5: "io", 22: "invalid-input", 35: "would-block"}
        self.assertEqual(len(rows), 35)
        self.assertEqual({site: (errors[int(status)], int(actions), exception == "true")
                          for site, status, actions, exception in rows}, M.NATIVE_ACTION_SITES)
        action = native.split("int mrk_panel_observe_action(", 1)[1].split("#undef MRK_ACTION_RETURN", 1)[0]
        calls = ("pthread_main_np()", "mrk_observation_attached(s)",
                 "[NSString stringWithUTF8String:directory]", "[NSURL fileURLWithPath:text isDirectory:YES]",
                 "setDirectoryURL:url]", "[s->alert buttons]", "[buttons count]", "[buttons objectAtIndex:",
                 "[button window]", "[button isEnabled]", "[button isHidden]", "cancel:nil]", "[button performClick:nil]")
        for call in calls:
            self.assertEqual(action.count(call), 1, call)
        self.assertLess(action.index("[s->alert buttons]"), action.index("if (!s->alert)"))
        self.assertLess(action.index("[button isEnabled]"), action.index("[button isHidden]"))
        self.assertIn("action < 1 || action > 5 || action == 3", action)
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
        deferred = ('if matches!(reason, "adapter-native-action" | "native-ax-binding") && r.pending == Some(Pending::Native(r.step))\n'
                    "            && r.native_dispatch.is_some_and(|native| native.step == r.step && native.entered && !native.returned) {\n"
                    "            return;\n        }")
        self.assertIn(deferred, report)
        self.assertLess(report.index("let Ok(r) = self.record.try_lock()"), report.index(deferred))
        self.assertLess(report.index(deferred), report.index("self.failure_reported.swap(true"))
        for forbidden in ("self.timely()", "observe_panel_action(", "observed_panel(", "drop(r)", "self.failed.store(", "self.end ="):
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

    def test_public_ax_trust_and_exact_original_identity_have_no_fallback(self):
        desktop = PATH.parents[1]
        native = (desktop / "native/macos-installed-native/src/native.m").read_text(encoding="utf-8")
        build = (desktop / "native/macos-installed-native/build.rs").read_text(encoding="utf-8")
        observer = (desktop / "src-tauri/src/installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        link = build.split('if std::env::var_os("CARGO_FEATURE_INSTALLED_OBSERVATION")', 1)[1].split("\n    }", 1)[0]
        self.assertIn("framework=ApplicationServices", link)
        self.assertEqual(build.count("framework=ApplicationServices"), 1)
        self.assertIn("#ifdef MRK_INSTALLED_OBSERVATION\n#import <ApplicationServices/ApplicationServices.h>", native)
        trust = native.split("int mrk_observation_ax_trusted(", 1)[1].split("int mrk_panel_observe_arm_open_identity(", 1)[0]
        for required in ("kAXTrustedCheckOptionPrompt", "kCFBooleanFalse", "AXIsProcessTrustedWithOptions(options)", "CFRelease(options)"):
            self.assertEqual(trust.count(required), 1)
        self.assertNotIn("kCFBooleanTrue", trust)
        main = observer.split("pub(crate) fn main()", 1)[1]
        self.assertLess(main.index("Fixture::capture("), main.index("installed_accessibility_trusted()"))
        self.assertLess(main.index("installed_accessibility_trusted()"), main.index("super::run_builder("))
        refused = main.split("if trusted != Ok(true)", 1)[1].split("r.ax_trusted = true", 1)[0]
        self.assertIn('"native-ax-not-trusted"', refused)
        self.assertIn("return std::process::ExitCode::FAILURE", refused)
        start = native.split("int mrk_panel_start(", 1)[1].split("int mrk_panel_poll(", 1)[0]
        self.assertLess(start.index("setReleasedWhenClosed:NO"), start.index("mrk_panel_configure_open_identity(s)"))
        self.assertLess(start.index("mrk_panel_configure_open_identity(s)"), start.index("beginSheetModalForWindow:"))
        stopped = start.split("!mrk_panel_configure_open_identity(s)", 1)[1].split("#endif", 1)[0]
        self.assertIn("s->unknown = YES; return EIO;", stopped)
        self.assertNotIn("return EPERM;", stopped)
        configuration = native.split("static BOOL mrk_panel_configure_open_identity(MRKInstalledPanel *s) {", 1)[1].split(
            "static BOOL mrk_original_eligible(", 1)[0]
        self.assertEqual(configuration.count("setAccessibilityIdentifier:"), 1)
        self.assertEqual(configuration.count("[s->parent accessibilityIdentifier]"), 1)
        self.assertNotIn("[s->window accessibilityIdentifier]", configuration)
        self.assertNotIn("[s->window setAccessibilityIdentifier:", native)
        self.assertLess(configuration.index("MRK_ID_CONFIG_ATTEMPTED"), configuration.index("[NSUUID UUID]"))
        self.assertLess(configuration.index("MRK_ID_PARENT_ENTERED"), configuration.index("[s->parent setAccessibilityIdentifier:"))
        self.assertLess(configuration.index("[s->parent setAccessibilityIdentifier:"), configuration.index("MRK_ID_PARENT_RETURNED"))
        self.assertLess(configuration.index("d->parent ="), configuration.index("MRK_ID_CONFIG_COMPLETE"))
        self.assertNotIn("MRK_ID_MATCH", configuration)
        self.assertIn("@throw;", configuration)
        copied = native.split("void mrk_panel_observe_identity_data(", 1)[1].split("static BOOL mrk_identity_tag(", 1)[0]
        self.assertEqual(copied.count("memcpy("), 1)
        for forbidden in ("[s->", "[NS", "release]", "retain]", "mrk_panel_poll", "mrk_main_thread("):
            self.assertNotIn(forbidden, copied)
        identifier = native.split("static uint32_t mrk_original_identifier(", 1)[1].split(
            "static BOOL mrk_panel_configure_open_identity(", 1)[0]
        for required in ("length > 63", "characterAtIndex:i] == 0", "bytes_needed > 63", "getBytes:bytes maxLength:63",
                         "remainingRange:&remainder", "remainder.length", "used != bytes_needed", "mrk_identity_utf8(bytes)",
                         "[roundtrip isEqualToString:text]"):
            self.assertIn(required, identifier)
        self.assertNotIn("allowLossyConversion", identifier)
        topology = native.split("static BOOL mrk_original_topology(", 1)[1].split("static int mrk_original_proof(", 1)[0]
        for required in ("[s->parent sheets]", "count == 1 && [sheets objectAtIndex:0] == s->window",
                         "[s->window sheets]", "[s->window attachedSheet] == nil", "[s->parent accessibilityChildren]",
                         "count > 16", "[children objectAtIndex:i] == s->window", "originals == 1",
                         "[s->window accessibilityParent] == s->parent", "NSAccessibilitySheetRole"):
            self.assertIn(required, topology)
        proof = native.split("static int mrk_original_proof(", 1)[1].split("int mrk_panel_observe_open_identity(", 1)[0]
        for required in ("mrk_original_eligible(s)", "mrk_observation_attached(s)", "mrk_observation_directory_ready(s)",
                         "[s->parent accessibilityIdentifier]", "[s->window accessibilityIdentifier]",
                         "if (freeze) memcpy(s->observationPanelTag, current, 64)", "MRK_PROOF_STABLE",
                         "memcmp(current, s->observationPanelTag, 64)", "MRK_PROOF_FINAL"):
            self.assertIn(required, proof)
        self.assertEqual(proof.count("mrk_original_topology(s, p)"), 2)
        self.assertLess(proof.index("if (freeze) memcpy("), proof.index("mrk_original_topology(s, p)"))
        binding = native.split("int mrk_panel_observe_open_identity(", 1)[1].split("typedef union", 1)[0]
        self.assertEqual(binding.count("capacity != 64"), 2)
        self.assertIn("if (p->site) return MRK_AX_INELIGIBLE", binding)
        self.assertIn("mrk_original_proof(s, p, YES)", binding)
        self.assertIn("mrk_original_proof(s, p, NO)", binding)
        for forbidden in ("setAccessibilityIdentifier:", "NSUUID", "observationActionAttempted =", "observationActionReturned =",
                          "s->selected", "s->completion("):
            self.assertNotIn(forbidden, binding + proof + topology)
        ax = native.split("// Public AX input", 1)[1]
        self.assertEqual(ax.count("AXUIElementCreateApplication(getpid())"), 1)
        for forbidden in ("AXUIElementCreateSystemWide", "kAXTitleAttribute", "kAXPositionAttribute", "CGEvent",
                          "AXUIElementPostKeyboardEvent", "NSSelectorFromString", "objc_msgSend", "ok:nil]"):
            self.assertNotIn(forbidden, ax)

    def test_public_ax_queries_are_bounded_timed_per_use_and_press_is_single(self):
        native_root = PATH.parents[1] / "native/macos-installed-native/src"
        native = (native_root / "native.m").read_text(encoding="utf-8")
        rust = (native_root / "lib.rs").read_text(encoding="utf-8")
        before = native.split("static BOOL mrk_ax_before(", 1)[1].split("static CFTypeRef mrk_ax_copy(", 1)[0]
        self.assertIn("MRK_AX_CALL_LIMIT - 2", before)
        self.assertLess(before.index("mrk_ax_admit(s, 0, 0, &timeout)"), before.index("AXUIElementSetMessagingTimeout(element, timeout.seconds)"))
        self.assertLess(before.index("AXUIElementSetMessagingTimeout(element, timeout.seconds)"),
                        before.index("mrk_ax_admit(s, timeout.required_ns, 0, NULL)"))
        timeout = rust.split("fn ax_timeout(", 1)[1].split("struct AxAdmission", 1)[0]
        for required in ("remaining_ns.min(100_000_000)", "seconds.to_bits().checked_sub(1)?", ".ceil() as u64",
                         "remaining_ns > 0 && remaining_ns >= required_ns"):
            self.assertIn(required, timeout)
        callback = rust.split('unsafe extern "C" fn ax_admission', 1)[1].split("pub fn installed_accessibility_trusted", 1)[0]
        self.assertLess(callback.index("(context.admit)(after_press == 1)"), callback.index("context.end.saturating_duration_since(Instant::now())"))
        self.assertIn("catch_unwind", callback)
        self.assertIn("std::mem::forget(payload)", callback)
        self.assertIn("observer_end.min(Instant::now() + Duration::from_secs(2))", rust)
        self.assertNotIn("context.end =", rust)
        arrays = native.split("static CFArrayRef mrk_ax_array(", 1)[1].split("static AXUIElementRef mrk_ax_identified(", 1)[0]
        self.assertLess(arrays.index("mrk_ax_before(s, element)"), arrays.index("AXUIElementCopyAttributeValues("))
        self.assertIn("attribute, 0, limit + 1, &slot->array", arrays)
        self.assertIn("count < 0 || count >= limit + 1", arrays)
        identified = native.split("static AXUIElementRef mrk_ax_identified(", 1)[1].split("static BOOL mrk_ax_projection(", 1)[0]
        self.assertIn("if (found) { mrk_ax_fail(s, MRK_AX_AMBIGUOUS); return NULL; }", identified)
        self.assertIn("if (!found) mrk_ax_fail(s, MRK_AX_UNSUPPORTED);", identified)
        projection = native.split("static BOOL mrk_ax_projection(", 1)[1].split("static void mrk_ax_open(", 1)[0]
        for required in ("kAXWindowsAttribute, 4", "kAXChildrenAttribute, 16", "kAXSheetRole", "if (sheets != 1)",
                         "CFEqual(expected_parent, parent)", "CFEqual(expected_panel, panel)",
                         "CFEqual(identifier, panel_text)", "CFEqual(link, parent)"):
            self.assertIn(required, projection)
        body = native.split("static void mrk_ax_open(", 1)[1].split("void mrk_observation_ax_press(", 1)[0]
        self.assertEqual(body.count("mrk_ax_projection("), 2)
        self.assertEqual(body.count("s->recheck(s->context)"), 1)
        self.assertLess(body.index("&s->result.initial"), body.index("s->recheck(s->context)"))
        self.assertLess(body.index("s->recheck(s->context)"), body.index("parent, panel, &repeated_parent"))
        self.assertLess(body.index("&s->result.final_projection"), body.index("kAXDefaultButtonAttribute"))
        self.assertIn("CFStringCreateWithBytes", body)
        self.assertIn("kCFStringEncodingUTF8, false", body)
        for required in ("kAXButtonRole", "CFBooleanGetValue(enabled)", "edge < 8", "CFEqual(link, chain[i])", "CFEqual(link, panel)",
                         "CFEqual(repeated, control)"):
            self.assertIn(required, body)
        self.assertEqual(body.count("kAXDefaultButtonAttribute"), 2)
        for site in ("MRK_AX_DEFAULT", "MRK_AX_RECHECK"):
            self.assertIn(f"mrk_ax_copy(s, parent, kAXDefaultButtonAttribute, {site})", body)
        self.assertNotIn("mrk_ax_copy(s, panel, kAXDefaultButtonAttribute", body)
        self.assertLess(body.index("CFEqual(repeated, control)"), body.index("mrk_ax_before(s, (AXUIElementRef)control)"))
        press = body.split("if (!mrk_ax_before(s, (AXUIElementRef)control)) return;", 1)[1]
        self.assertEqual(native.count("AXUIElementPerformAction("), 1)
        self.assertLess(press.index("s->result.flags |= MRK_AX_ATTEMPTED"), press.index("AXUIElementPerformAction("))
        self.assertLess(press.index("AXUIElementPerformAction("), press.index("s->result.flags |= MRK_AX_PRESS_RETURNED"))
        for forbidden in ("mrk_ax_copy(", "mrk_ax_array(", "mrk_ax_before(", "EAGAIN", "while (", "for ("):
            self.assertNotIn(forbidden, press)
        cleanup = native.split("void mrk_observation_ax_press(", 1)[1].split("#endif", 1)[0]
        self.assertIn("MRKAXOwned owned[80]", native)
        self.assertLess(cleanup.index("s.owned[s.count].value = NULL"), cleanup.index("CFRelease(original)"))
        self.assertEqual(cleanup.count("CFRelease(original)"), 1)
        self.assertIn("s.cleanupKnown = NO", cleanup)
        self.assertLess(cleanup.index("mrk_ax_admit(&s, 0,"), cleanup.index("if (s.cleanupKnown)"))
        for table, expected in (("AX_SITES", M.ACCESSIBILITY_SITES), ("AX_ERRORS", M.ACCESSIBILITY_ERRORS)):
            rows = rust.split(f"const {table}:", 1)[1].split("];", 1)[0]
            self.assertEqual(set(M.re.findall(r'"([a-z-]+)"', rows)), expected)

    def test_public_ax_handoff_keeps_original_barrier_and_does_not_forge_native_flags(self):
        root = PATH.parents[1] / "src-tauri/src"
        adapter = (root / "shell_macos_dialog.rs").read_text(encoding="utf-8")
        observer = (root / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        packet = adapter.split("struct PreparedOpenInput", 1)[1].split("impl PreparedOpenInput", 1)[0]
        for required in ("native::OpenIdentity", "Arc<GuiCall>", "Arc<OriginalWork>", "Arc<OpenRelease>"):
            self.assertIn(required, packet)
        for forbidden in ("CFTypeRef", "AXUIElementRef", "*mut", "Option<Panel>"):
            self.assertNotIn(forbidden, packet)
        gate = adapter.split("fn original_admitted(", 1)[1].split("pub(crate) struct PreparedOpenInput", 1)[0]
        self.assertIn("owner.id != id", gate)
        self.assertIn("!Arc::ptr_eq(&owner, original) || !Arc::ptr_eq(&owner.gui, call)", gate)
        self.assertIn("if after_press", gate)  # Do not reject a real early callback as a pre-action response.
        release = adapter.split("            let release = {", 1)[1].split("        if released {", 1)[0]
        self.assertLess(release.index("barrier.release_ready()"), release.index("facts.release_queued = true"))
        self.assertLess(release.index("facts.release_queued = true"), release.index("entry.panel.take()"))
        self.assertIn("OpenPhase::Unknown", adapter)
        self.assertIn("open_release_data_check()", observer)
        tick = observer.split("pub(super) fn tick(", 1)[1].split("let state = app.state", 1)[0]
        self.assertLess(tick.index("if self.accessibility_step(app)"), tick.rindex("if !self.timely()"))
        run = observer.split("fn accessibility_step(", 1)[1].split("fn native_step(", 1)[0]
        self.assertEqual(run.count("r.prepared_open.take()"), 1)
        self.assertEqual(run.count("input.press("), 1)
        self.assertLess(run.index("input.no_entry("), run.index("input.enter()"))
        self.assertLess(run.index("input.enter()"), run.index("input.press("))
        returned = run.split("let result = input.press(", 1)[1]
        self.assertLess(returned.index('self.fail_with("native-ax-input")'), returned.index("let Some(mut r) = self.record()"))
        self.assertLess(returned.index("input.returned(&result, matching && input.admitted(true).is_some())"),
                        returned.index("retire_returned_open("))
        self.assertLess(returned.index("if !retired"), returned.index("r.native_actions_returned[2] = true"))
        for forbidden in ("run_on_main_thread(", "tokio::spawn", "std::thread::spawn", ".await", "observe_panel_action("):
            self.assertNotIn(forbidden, run)
        wrapper = observer.split("fn native_step(", 1)[1].split("fn native_step_body(", 1)[0]
        self.assertLess(wrapper.index("self.native_step_body("), wrapper.index("native.returned = true"))
        self.assertLess(wrapper.index("native.returned = true"), wrapper.index("r.prepared_open = Some(input)"))
        self.assertLess(wrapper.index("native.returned = true"), wrapper.index("sample.binding = Some(returned.binding)"))
        self.assertLess(wrapper.index("sample.binding = Some(returned.binding)"), wrapper.index("r.prepared_open = Some(input)"))
        self.assertIn("sample.configuration == returned.configuration", wrapper)
        body = observer.split("fn native_step_body(", 1)[1].split("pub(super) fn close_prevented", 1)[0]
        self.assertIn("prepare_open_input(id, binding_return)", body)
        self.assertIn("return Ok(false); // Deliberately NOT a native action return.", body)
        self.assertNotIn("PanelAction::ProjectOpen", observer)
        report = observer.split("fn report_failure(", 1)[1].split("pub(super) fn attach(", 1)[0]
        self.assertLess(report.index('"native-ax-input" | "native-ax-custody"'), report.index("self.failure_reported.swap(true"))
        scope = observer.split("pub(super) fn open_identity_scope(", 1)[1].split("pub(super) fn identity_start_returned(", 1)[0]
        self.assertIn("self.case != Case::PickerLoss && id == self.case.selected_id()", scope)
        self.assertIn("matches!(kind, mrk_macos_installed_native::PanelKind::Project)", scope)
        code = M.re.sub(r"//[^\n]*", "", scope)
        for forbidden in (".record(", "project_calls", "r.step", "Step::"):
            self.assertNotIn(forbidden, code)
        construct = adapter.split("fn construct(", 1)[1].split("fn ", 1)[0]
        self.assertLess(construct.index("*book = Some(OriginalPanel"), construct.index("installed_arm_open_identity()"))
        self.assertLess(construct.index("!q.timely()"), construct.index("installed_arm_open_identity()"))
        self.assertLess(construct.index("installed_arm_open_identity()"), construct.index("let returned = panel.start(choice)"))
        self.assertLess(construct.index("let returned = panel.start(choice)"), construct.index("take_installed_identity_start_return()"))
        self.assertLess(construct.index("take_installed_identity_start_return()"), construct.index("returned.map_err("))
        delivered = adapter.split("let result = construct(&creating, kind,", 1)[1].split("}).is_err()", 1)[0]
        self.assertLess(delivered.index("q.identity_start_returned(id, data)"), delivered.index("done.send(result)"))
        for forbidden in ("installed_observation(", "PANEL.with(", ".facts(", "run_on_main_thread("):
            self.assertNotIn(forbidden, delivered)
        published = observer.split("pub(super) fn identity_start_returned(", 1)[1].split("fn report_failure(", 1)[0]
        self.assertLess(published.index("r.identity_binding = Some("), published.index("if !returned.succeeded()"))
        rust = (PATH.parents[1] / "native/macos-installed-native/src/lib.rs").read_text(encoding="utf-8")
        started = rust.split("pub fn start(", 1)[1].split("pub fn poll(", 1)[0]
        self.assertLess(started.index("self.observation_start = None"), started.index("self.usable()?"))
        self.assertLess(started.index("mrk_panel_start("), started.index("observation::identity_start_return("))
        self.assertLess(started.index("observation::identity_start_return("), started.index("let result = result(status)"))
        self.assertIn("error.kind() != io::ErrorKind::PermissionDenied) { self.unknown = true; }", started)
        self.assertIn("identity_data_check()", rust)  # Existing hosted DATA entry, not local native execution.

    def test_native_recheck_uses_one_same_deadline_request_and_original_custody(self):
        root = PATH.parents[1] / "src-tauri/src"
        adapter = (root / "shell_macos_dialog.rs").read_text(encoding="utf-8")
        observer = (root / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        token = adapter.split("pub(crate) struct OpenRecheck", 1)[1].split("pub(crate) struct OpenRecheckBody", 1)[0]
        for required in ("native::OpenIdentity", "Arc<GuiCall>", "Arc<OriginalWork>", "Arc<OpenRelease>"):
            self.assertIn(required, token)
        for forbidden in ("*mut", "AXUIElement", "CFTypeRef", "Option<Panel>"):
            self.assertNotIn(forbidden, token)
        state = adapter.split("impl OpenRelease", 1)[1].split("fn original_admitted(", 1)[0]
        self.assertIn("RecheckPhase::Unrequested, RecheckPhase::NotDispatched, RecheckPhase::Joined", state)
        self.assertIn("self.recheck_unknown(); return false;", state)
        identity = adapter.split("impl OpenRecheck {", 1)[1].split("pub(crate) fn state(", 1)[0]
        for required in ("Arc::ptr_eq(&self.call", "Arc::ptr_eq(&self.owner", "Arc::ptr_eq(&self.release"):
            self.assertIn(required, identity)
        request = observer.split("fn final_native_recheck(", 1)[1].split("fn accessibility_step(", 1)[0]
        self.assertEqual(request.count("std::sync::mpsc::sync_channel(1)"), 1)
        self.assertEqual(request.count("app.run_on_main_thread("), 1)
        self.assertEqual(request.count("receipt.recv_timeout(remaining)"), 1)
        self.assertLess(request.index("s.dispatch_attempted = true"), request.index("app.run_on_main_thread("))
        self.assertLess(request.index("end.saturating_duration_since(Instant::now())"), request.index("receipt.recv_timeout(remaining)"))
        self.assertLess(request.index("token.same(&returned.token)"), request.index("token.joined()"))
        self.assertLess(request.index("token.joined()"), request.index("s.receipt_joined = true"))
        self.assertIn("Instant::now() >= end", request.split("s.receipt_joined = true", 1)[1])
        for forbidden in ("std::thread::spawn", "tokio::spawn", "Duration::from_secs", "loop {", "end ="):
            self.assertNotIn(forbidden, request)
        main = observer.split("fn recheck_main(", 1)[1].split("fn final_native_recheck(", 1)[0]
        self.assertLess(main.index('token.state() == "unknown"'), main.index("token.observe(end,"))
        self.assertLess(main.index("token.observe(end,"), main.index("token.returned()"))
        self.assertLess(main.index("token.returned()"), main.index("s.body_returned = true"))
        self.assertLess(main.index("s.body_returned = true"), main.index("done.try_send("))
        after_send = main.split("done.try_send(", 1)[1]
        for forbidden in ("token.observe(", "PANEL.with(", "run_on_main_thread(", "token.joined("):
            self.assertNotIn(forbidden, after_send)
        unknown = observer.split("fn recheck_unknown(", 1)[1].split("fn recheck_main(", 1)[0]
        self.assertLess(unknown.index("token.unknown()"), unknown.index("self.recheck_sample("))

    def test_dom_callback_custody_wraps_only_the_original_returned_body(self):
        # Source controls only: the actual Rust DATA entry and native callback
        # are executed by the reviewed macOS qualification, not these tests.
        observer = (PATH.parents[1] / "src-tauri" / "src" / "installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        dispatch = observer.split("if r.evaluations >= 160", 1)[1].split("fn open_admission(", 1)[0]
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
        self.assertLess(wrapper.index(authenticated), wrapper.index("self.dom_body(&mut r, original.step, raw)"))
        self.assertLess(wrapper.index("self.dom_body(&mut r, original.step, raw)"), wrapper.index("retire_returned_dom(&mut r.pending, original)"))
        self.assertEqual(wrapper.count("self.record()"), 1)
        for forbidden in ("catch_unwind", "drop(r)", "r.pending.take()", "r.step !="):
            self.assertNotIn(forbidden, wrapper)
        body = observer.split("    fn dom_body(", 1)[1].split("    pub(super) fn relay_joined", 1)[0]
        for forbidden in ("self.record()", "r.pending", "catch_unwind", "failed.store", "self.end ="):
            self.assertNotIn(forbidden, body)
        self.assertEqual(body.count("if !self.timely() { return; }"), 2)
        for label in ("dom-callback-size", "dom-callback-json", "dom-callback-object", "dom-callback-state"):
            self.assertIn(f'self.fail_with("{label}")', body)
        before_transition = body.split("r.step = match step", 1)[0]
        self.assertTrue(before_transition.rstrip().endswith("if !self.timely() { return; }"))
        self.assertNotRegex(before_transition, r"r\.[a-z_]+\s*(?:\+=|=(?!=))")
        shutdown = observer.split("fn failure_shutdown(", 1)[1].split("    fn dom(", 1)[0]
        self.assertIn("if r.pending.is_some() || r.failure_quit_attempted { return; }", shutdown)
        context = observer.split("fn failure_context(", 1)[1].split("pub(super) struct Observation", 1)[0]
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
        self.assertIn("!matches!(r.step, Step::OpenProject | Step::ProjectSettled) || r.project.is_some()", handler)
        self.assertIn("Path::new(&project.path) != self.project_path || project.name != self.case.name() || !crate::protocol::valid_id(&project.id)", handler)
        self.assertNotIn("project_calls", handler)
        self.assertNotIn("r.step =", handler)

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
        self.assertEqual(final[".gitignore"].identity[6], 274)
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


if __name__ == "__main__":
    unittest.main()
