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


def project_selection_context_data(custody="bound-original-data", recorded="fixture-root-all5", location="outside-namespace"):
    return {"snapshotSource": "record", "pending": None, "nativeHandler": None, "lastPanel": None,
            "projectSelection": {"custody": custody, "recordedObject": recorded, "lexicalLocation": location}}


def project_selection_row(value, reason="project-result-path", step="ProjectSettled"):
    return (f"MRK_MACOS_AQUA_FAILURE_STEP={step}\nMRK_MACOS_AQUA_FAILURE_REASON={reason}\n".encode("ascii")
            + context_row(value) + b"MRK_MACOS_AQUA=failed\n")


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


def accessibility_context_data():
    value = action_context_data()
    value["nativeAction"] = None  # The old selector is historical DATA only.
    value["accessibility"] = deepcopy(M.expected_result(BINDING, "first-save")["native"]["projectOpenInput"])
    return value


def selection_limit_context_data(site, role, depth, nodes, queued, count):
    """Inert successor-policy geometry, not reconstructed native evidence."""
    value = accessibility_context_data(); sample = value["accessibility"]
    sample.update(attempted=False, pressReturned=False, triggered=None, site=site, error="limit",
                  originalProof=None, selectedTarget=None, promptChecks={"initial": True, "final": None})
    sample["promptButton"].update(calls=100, cfSlots=45, cfSlotsRetired=45,
        initialNodesExamined=0, recheckNodesExamined=0, lastRole="not-read", lastDepth=0,
        checks={key: index < 2 for index, key in enumerate(M.ACCESSIBILITY_BUTTON_CHECKS)})
    sample["rowSelection"].update(checks=dict.fromkeys(M.ACCESSIBILITY_SELECTION_CHECKS, False),
        nodesExamined=nodes, attempted=False, returned=False, setterSucceeded=None,
        limit={"role": role, "depth": depth, "count": count, "queuedNodes": queued})
    return value


# Same successor-policy family as the Rust DATA seam. The historical Outline20
# refusal remains bound to the original source, never relabelled successful.
SELECTION_LIMIT_SHAPES = (
    ("selection-count-limit", "Sheet", 0, 0, 1, 17),
    ("selection-count-limit", "Sheet", 0, 0, 1, (1 << 63) - 1),
    ("selection-count-limit", "Group", 1, 1, 2, 17),
    ("selection-count-limit", "SplitGroup", 8, 8, 9, (1 << 63) - 1),
    ("selection-count-limit", "ScrollArea", 3, 12, 17, 17),
    ("selection-count-limit", "Table", 1, 1, 2, (1 << 63) - 1),
    ("selection-count-limit", "Outline", 8, 48, 49, 33),
    ("selection-copy-limit", "Sheet", 0, 0, 1, -(1 << 63)),
    ("selection-copy-limit", "Sheet", 0, 0, 1, -1),
    ("selection-copy-limit", "Sheet", 0, 0, 1, 17),
    ("selection-copy-limit", "Sheet", 0, 0, 1, (1 << 63) - 1),
    ("selection-copy-limit", "Group", 1, 1, 2, -1),
    ("selection-copy-limit", "SplitGroup", 8, 8, 9, -(1 << 63)),
    ("selection-copy-limit", "ScrollArea", 3, 12, 17, (1 << 63) - 1),
    ("selection-copy-limit", "Table", 1, 1, 2, 33),
    ("selection-copy-limit", "Outline", 8, 48, 49, -(1 << 63)),
    ("selection-node-limit", "Group", 3, 12, 34, 16),
    ("selection-node-limit", "SplitGroup", 7, 20, 40, 10),
    ("selection-node-limit", "ScrollArea", 3, 12, 49, 1),
    ("selection-node-limit", "Table", 3, 12, 18, 32),
    ("selection-node-limit", "Outline", 7, 48, 49, 1),
    ("selection-depth-limit", "Group", 8, 8, 9, 1),
    ("selection-depth-limit", "SplitGroup", 8, 8, 9, 8),
    ("selection-depth-limit", "ScrollArea", 8, 12, 17, 16),
    ("selection-depth-limit", "Table", 8, 8, 49, 32),  # Depth wins even if the queue also overflows.
    ("selection-depth-limit", "Outline", 8, 48, 49, 32),
)


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
        # stricter unchanged decoder limit, not just the producer's ceiling.
        full = accessibility_context_data()
        full.update(snapshotSource="record", originalWindow=deepcopy(M.expected_result(BINDING, "first-save")["native"]["originalWindow"]),
                    accessibilityBinding=deepcopy(M.expected_result(BINDING, "first-save")["native"]["projectOpenBinding"]),
                    projectSelection=project_selection_context_data("inconsistent-original-data", "captured-object-metadata-changed")["projectSelection"])
        self.assertEqual(M.failure_context(b"", project_selection_row(full), "first-save"), full)
        self.assertEqual(M.FAILURE_CONTEXT_LIMIT, 4096)
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
                          promptChecks={"initial": None, "final": None}, promptButton=None, rowSelection=None, selectedTarget=None, site=None, error=None)
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
                         ("mechanism", "accessibility-press-original-control-container-button-v3"), ("id", True), ("id", 1),
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
            self.assertEqual(sample["mechanism"], "accessibility-select-original-row-and-press-v4")
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

    def test_real_selection_setter_and_selected_url_are_separate_closed_facts(self):
        good = accessibility_context_data()
        self.assertEqual(M.failure_context(b"", context_row(good), "first-save"), good)
        for field, bad in (("attempted", False), ("returned", False), ("setterSucceeded", False),
                           ("setterSucceeded", None), ("nodesExamined", True), ("nodesExamined", 1), ("nodesExamined", 49),
                           ("url", "PRIVATE"), ("attempts", 2)):
            value = deepcopy(good); value["accessibility"]["rowSelection"][field] = bad
            expected = deepcopy(value); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), expected, field)
        for key in M.ACCESSIBILITY_SELECTION_CHECKS:
            value = deepcopy(good); value["accessibility"]["rowSelection"]["checks"][key] = False
            expected = deepcopy(value); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), expected, key)
        for selected, error in (("not-ready", "ineligible"), ("different", "changed"),
                                ("malformed", "malformed"), ("multiple", "ambiguous"),
                                ("entered-not-returned", "custody")):
            value = deepcopy(good); sample = value["accessibility"]
            sample.update(attempted=False, pressReturned=False, triggered=None, site="original-proof",
                          error=error, selectedTarget=selected)
            if selected == "entered-not-returned":
                sample.update(state="unknown", custodyKnown=False, receiptJoined=False, barrierRetired=False)
                sample["promptButton"].update(cleanupReturned=False, cfSlotsRetired=0)
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value, selected)
            self.assertFalse(M._accessibility_succeeded(sample))
            result = M.expected_result(BINDING, "first-save"); result["native"]["projectOpenInput"] = deepcopy(sample)
            with self.assertRaises(M.Refused): M.parse_result(captured(result), b"", BINDING, "first-save")
            for key in ("attempted", "pressReturned", "triggered"):
                bad = deepcopy(value); bad["accessibility"][key] = True
                expected = deepcopy(bad); expected["accessibility"] = None
                self.assertEqual(M.failure_context(b"", context_row(bad), "first-save"), expected, (selected, key))
        # Row discovery/write failure precedes both button passes. Its own
        # bounded counter never stands in for either button pass's progress.
        for error, attempted, returned, status in (("unsupported", False, False, None),
                ("changed", False, False, None), ("malformed", False, False, None),
                ("ambiguous", False, False, None), ("limit", False, False, None),
                ("cannot-complete", True, True, False), ("objc-exception", True, False, None),
                ("deadline", True, True, True)):
            value = deepcopy(good); sample = value["accessibility"]
            sample.update(attempted=False, pressReturned=False, triggered=None,
                site="selection-write" if attempted else "selection", error=error, originalProof=None,
                selectedTarget=None, promptChecks={"initial": True, "final": None})
            sample["promptButton"].update(initialNodesExamined=0, recheckNodesExamined=0, lastRole="not-read", lastDepth=0,
                checks={key: index < 2 for index, key in enumerate(M.ACCESSIBILITY_BUTTON_CHECKS)},
                axError=-25204 if error == "cannot-complete" else 0)
            sample["rowSelection"].update(attempted=attempted, returned=returned, setterSucceeded=status,
                checks=dict.fromkeys(M.ACCESSIBILITY_SELECTION_CHECKS, attempted), nodesExamined=36 if error == "ambiguous" else 2)
            if error == "objc-exception":
                sample.update(state="unknown", custodyKnown=False, receiptJoined=False, barrierRetired=False)
                sample["promptButton"].update(cleanupReturned=False, cfSlotsRetired=0)
            if error == "deadline": sample.update(expired=True, timely=False)
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value, error)
            self.assertFalse(M._accessibility_succeeded(sample))
            if error == "objc-exception":
                # The actual worker may join, but an unreturned selector can
                # never supply known CF, receipt or barrier retirement.
                self.assertTrue(sample["workerJoined"])
                for fields, button_fields in (({"error": "unsupported"}, {}), ({"site": "cleanup"}, {}),
                        ({}, {"axError": -25204}), ({}, {"cfSlotsRetired": 1}),
                        ({}, {"cleanupReturned": True, "cfSlotsRetired": sample["promptButton"]["cfSlots"]}),
                        ({"state": "retired", "error": "unsupported", "custodyKnown": True, "receiptJoined": True, "barrierRetired": True},
                         {"cleanupReturned": True, "cfSlotsRetired": sample["promptButton"]["cfSlots"]})):
                    bad = deepcopy(value); bad["accessibility"].update(fields)
                    bad["accessibility"]["promptButton"].update(button_fields)
                    expected = deepcopy(bad); expected["accessibility"] = None
                    self.assertEqual(M.failure_context(b"", context_row(bad), "first-save"), expected, (fields, button_fields))
            bad = deepcopy(value); bad["accessibility"].update(attempted=True, selectedTarget="match")
            expected = deepcopy(bad); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(bad), "first-save"), expected, error)
        for selected in (None, "not-ready", "different", "multiple", True, "PRIVATE"):
            value = deepcopy(good); value["accessibility"]["selectedTarget"] = selected
            expected = deepcopy(value); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), expected, selected)

    def test_selection_capacity_preserves_wide_scalars_and_role_specific_geometry(self):
        # Decoder DATA, not evidence of a native layout or a successful setter.
        for nodes in (17, 36, 48):
            result = M.expected_result(BINDING, "first-save")
            result["native"]["projectOpenInput"]["rowSelection"]["nodesExamined"] = nodes
            self.assertEqual(M.parse_result(captured(result), b"", BINDING, "first-save"), result)
        for role in ("Table", "Outline"):
            for count in (20, 32):
                for site in ("selection-count-limit", "selection-copy-limit", "selection-node-limit"):
                    #17+20 fits;17+32 exactly fills49. A local refusal cannot
                    # claim either as an overflow under the successor policy.
                    value = selection_limit_context_data(site, role, 3, 12, 17, count)
                    expected = deepcopy(value); expected["accessibility"] = None
                    self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), expected,
                                     (role, count, site))
            for site in ("selection-count-limit", "selection-copy-limit"):
                value = selection_limit_context_data(site, role, 3, 12, 17, 33)
                self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)
            # Count/Copy's row bound wins before depth/queue capacity decisions.
            value = selection_limit_context_data("selection-node-limit", role, 3, 12, 17, 33)
            expected = deepcopy(value); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), expected)
        value = selection_limit_context_data("selection-count-limit", "Group", 3, 12, 17, 17)
        self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)

    def test_post_selection_common_limit_preserves_effect_and_unknown_retirement(self):
        value = accessibility_context_data(); sample = value["accessibility"]
        sample.update(attempted=False, pressReturned=False, triggered=None, site="control-projection", error="limit",
                      originalProof=None, selectedTarget=None, promptChecks={"initial": True, "final": None})
        sample["rowSelection"]["nodesExamined"] = 36
        sample["promptButton"].update(calls=512, cfSlots=256, cfSlotsRetired=256,
            initialNodesExamined=3, recheckNodesExamined=0, lastRole="Group", lastDepth=2,
            checks={key: index < 2 for index, key in enumerate(M.ACCESSIBILITY_BUTTON_CHECKS)})
        for known in (True, False):
            frame = deepcopy(value); failed = frame["accessibility"]
            if not known:
                failed.update(state="unknown", custodyKnown=False, receiptJoined=False, barrierRetired=False)
                failed["promptButton"].update(cleanupReturned=False, cfSlotsRetired=16)
            self.assertEqual(M.failure_context(b"", context_row(frame), "first-save"), frame)
            self.assertTrue(M._row_selection_succeeded(failed["rowSelection"]))
            self.assertFalse(M._accessibility_succeeded(failed))
            self.assertTrue(failed["workerJoined"])  # Actual join does not repair uncertain CF retirement.
            self.assertEqual(failed["rowSelection"], sample["rowSelection"])
            result = M.expected_result(BINDING, "first-save"); result["native"]["projectOpenInput"] = deepcopy(failed)
            with self.assertRaises(M.Refused): M.parse_result(captured(result), b"", BINDING, "first-save")
            mutations = [("rowSelection.attempted", False), ("rowSelection.returned", False),
                ("rowSelection.setterSucceeded", None), ("attempted", True), ("pressReturned", True),
                ("triggered", True), ("error", "none"), ("promptButton.calls", 513),
                ("promptButton.cfSlots", 257), ("promptButton.initialNodesExamined", 17)]
            if not known:
                mutations += [("custodyKnown", True), ("receiptJoined", True), ("barrierRetired", True),
                              ("promptButton.cleanupReturned", True)]
            for path, invalid in mutations:
                bad = deepcopy(frame); target = bad["accessibility"]; parts = path.split(".")
                for part in parts[:-1]: target = target[part]
                target[parts[-1]] = invalid
                expected = deepcopy(bad); expected["accessibility"] = None
                self.assertEqual(M.failure_context(b"", context_row(bad), "first-save"), expected, (known, path))

    def test_selection_limit_tuple_and_cleanup_history_are_failure_only(self):
        self.assertEqual({shape[0] for shape in SELECTION_LIMIT_SHAPES}, M.ACCESSIBILITY_SELECTION_LIMIT_SITES)
        for shape in SELECTION_LIMIT_SHAPES:
            value = selection_limit_context_data(*shape)
            samples = [value]
            late = deepcopy(value); late["accessibility"].update(expired=True, timely=False); samples.append(late)
            for cleanup_returned, retired in ((True, 45), (False, 16), (False, 0)):
                for worker_joined in (True, False):
                    unknown = deepcopy(late); sample = unknown["accessibility"]
                    sample.update(state="unknown", custodyKnown=False, receiptJoined=False, barrierRetired=False,
                                  rechecksSettled=False, workerJoined=worker_joined)
                    sample["promptButton"].update(cleanupReturned=cleanup_returned, cfSlotsRetired=retired)
                    samples.append(unknown)
            for frame in samples:
                sample = frame["accessibility"]
                self.assertEqual(M.failure_context(b"", context_row(frame), "first-save"), frame, shape)
                self.assertEqual(sample["rowSelection"]["limit"], value["accessibility"]["rowSelection"]["limit"])
                self.assertEqual((sample["promptButton"]["lastRole"], sample["promptButton"]["lastDepth"]), ("not-read", 0))
                self.assertEqual((sample["promptButton"]["calls"], sample["promptButton"]["cfSlots"]), (100, 45))
                self.assertFalse(M._row_selection_succeeded(sample["rowSelection"]))
                self.assertFalse(M._accessibility_succeeded(sample))
                result = M.expected_result(BINDING, "first-save"); result["native"]["projectOpenInput"] = deepcopy(sample)
                with self.assertRaises(M.Refused, msg=shape): M.parse_result(captured(result), b"", BINDING, "first-save")
            # The same scalar prefix without a local tuple is still the old
            # generic selection/limit, not an invented array/depth conclusion.
            generic = deepcopy(value); generic["accessibility"]["site"] = "selection"
            generic["accessibility"]["rowSelection"]["limit"] = None
            self.assertEqual(M.failure_context(b"", context_row(generic), "first-save"), generic)

    def test_selection_limit_closed_decoder_rejects_tuple_and_effect_mismatches(self):
        def reject(frame, label):
            expected = deepcopy(frame); expected["accessibility"] = None
            self.assertEqual(M.failure_context(b"", context_row(frame), "first-save"), expected, label)

        for site, depth, count in (("selection-count-limit", 3, 17), ("selection-copy-limit", 3, -1),
                                  ("selection-node-limit", 3, 1), ("selection-depth-limit", 8, 1)):
            value = selection_limit_context_data(site, "ScrollArea", depth, 12,
                                                 49 if site == "selection-node-limit" else 17, count)
            for key in value["accessibility"]["rowSelection"]:
                bad = deepcopy(value); del bad["accessibility"]["rowSelection"][key]
                reject(bad, (site, "missing-row-field", key))
            for key in value["accessibility"]["rowSelection"]["limit"]:
                bad = deepcopy(value); del bad["accessibility"]["rowSelection"]["limit"][key]
                reject(bad, (site, "missing-limit-field", key))
            for key, invalid in (("array", "Children"), ("path", "PRIVATE"), ("reason", "node"), ("visited", 12)):
                bad = deepcopy(value); bad["accessibility"]["rowSelection"]["limit"][key] = invalid
                reject(bad, (site, "extra-limit-field", key))
            for invalid in (None, {}, [], True, 1, 17.0, "limit"):
                bad = deepcopy(value); bad["accessibility"]["rowSelection"]["limit"] = invalid
                reject(bad, (site, "limit-type", invalid))
            for key, invalid in (("depth", True), ("depth", False), ("depth", 3.0), ("depth", -1), ("depth", 9),
                ("count", True), ("count", False), ("count", 17.0), ("count", -1.0), ("count", "17"),
                ("count", 1 << 63), ("count", -(1 << 63) - 1),
                ("queuedNodes", True), ("queuedNodes", False), ("queuedNodes", 17.0), ("queuedNodes", -1),
                ("queuedNodes", 0), ("queuedNodes", 1), ("queuedNodes", 12), ("queuedNodes", 50), ("queuedNodes", 1 << 32),
                ("role", True), ("role", None), ("role", "Row"), ("role", "Button"), ("role", "Browser"),
                ("role", "opaque"), ("role", "not-read"), ("role", "Window"), ("role", "unknown")):
                bad = deepcopy(value); bad["accessibility"]["rowSelection"]["limit"][key] = invalid
                reject(bad, (site, key, invalid))
            counts = {"selection-count-limit": (-(1 << 63), -1, 0, 1, 16), "selection-copy-limit": (0, 1, 16),
                      "selection-node-limit": (-(1 << 63), -1, 0, 17, (1 << 63) - 1),
                      "selection-depth-limit": (-(1 << 63), -1, 0, 17, (1 << 63) - 1)}[site]
            for invalid in counts:
                bad = deepcopy(value); bad["accessibility"]["rowSelection"]["limit"]["count"] = invalid
                reject(bad, (site, "count-predicate", invalid))
            for role, local_depth, nodes, queued in (("Sheet", 0, 12, 17), ("Sheet", 1, 1, 2),
                ("Sheet", 0, 0, 2), ("Group", 0, 0, 1), ("Table", 0, 1, 2), ("Group", 2, 1, 2)):
                bad = deepcopy(value); selection = bad["accessibility"]["rowSelection"]
                selection["nodesExamined"] = nodes
                selection["limit"].update(role=role, depth=local_depth, queuedNodes=queued)
                reject(bad, (site, role, local_depth, nodes, queued))
            for invalid in (True, 12.0, -1, 0, 49):
                bad = deepcopy(value); bad["accessibility"]["rowSelection"]["nodesExamined"] = invalid
                reject(bad, (site, "nodes", invalid))
            for key in M.ACCESSIBILITY_SELECTION_CHECKS:
                bad = deepcopy(value); bad["accessibility"]["rowSelection"]["checks"][key] = True
                reject(bad, (site, "selection-proof", key))
            for path, invalid in (("rowSelection.attempted", True), ("rowSelection.attempted", None),
                ("rowSelection.returned", True), ("rowSelection.setterSucceeded", True), ("rowSelection.setterSucceeded", False),
                ("attempted", True), ("attempted", None), ("pressReturned", True), ("pressReturned", None),
                ("triggered", True), ("triggered", False), ("error", "none"), ("error", "deadline"),
                ("error", "objc-exception"), ("error", "unsupported"), ("nativeEntered", False), ("bodyReturned", False),
                ("initialOriginalProof", None), ("originalProof", value["accessibility"]["initialOriginalProof"]),
                ("promptChecks.initial", False), ("promptChecks.initial", None), ("promptChecks.final", True),
                ("promptChecks.final", False), ("selectedTarget", "match"), ("selectedTarget", "different"),
                ("selectedTarget", "not-ready"), ("promptButton.calls", 0), ("promptButton.calls", 513),
                ("promptButton.axError", -25204), ("promptButton.axError", True), ("promptButton.cfSlots", 0),
                ("promptButton.cfSlots", 257), ("promptButton.initialNodesExamined", 1), ("promptButton.recheckNodesExamined", 1),
                ("promptButton.lastRole", "Sheet"), ("promptButton.lastRole", "Group"), ("promptButton.lastDepth", 1),
                ("promptButton.checks", dict.fromkeys(M.ACCESSIBILITY_BUTTON_CHECKS, False)),
                ("promptButton.checks.completeControlProjection", True)):
                bad = deepcopy(value); parts = path.split("."); target = bad["accessibility"]
                for part in parts[:-1]: target = target[part]
                target[parts[-1]] = invalid
                reject(bad, (site, path, invalid))
            swaps = {"selection-count-limit": ("selection-node-limit", "selection-depth-limit"),
                     "selection-copy-limit": ("selection-count-limit", "selection-node-limit", "selection-depth-limit"),
                     "selection-node-limit": ("selection-count-limit", "selection-copy-limit", "selection-depth-limit"),
                     "selection-depth-limit": ("selection-count-limit", "selection-copy-limit", "selection-node-limit")}[site]
            for swapped in (*swaps, *sorted(M.ACCESSIBILITY_SITES - M.ACCESSIBILITY_SELECTION_LIMIT_SITES),
                            "selection-unknown-limit", None):
                bad = deepcopy(value); bad["accessibility"]["site"] = swapped
                reject(bad, (site, "site", swapped))
            # An actually joined worker does not repair unreturned CF cleanup.
            unknown = deepcopy(value); sample = unknown["accessibility"]
            sample.update(state="unknown", custodyKnown=False, receiptJoined=False, barrierRetired=False,
                          expired=True, timely=False, rechecksSettled=True)
            sample["promptButton"].update(cleanupReturned=False, cfSlotsRetired=16)
            self.assertEqual(M.failure_context(b"", context_row(unknown), "first-save"), unknown)
            self.assertTrue(sample["workerJoined"])
            for updates, button_updates in (({"receiptJoined": True}, {}),
                ({"receiptJoined": True, "barrierRetired": True}, {}), ({"custodyKnown": True}, {}),
                ({}, {"cleanupReturned": True}), ({}, {"cfSlotsRetired": 46})):
                bad = deepcopy(unknown); bad["accessibility"].update(updates)
                bad["accessibility"]["promptButton"].update(button_updates)
                reject(bad, (site, "unknown-retirement", updates, button_updates))
            success = accessibility_context_data()
            success["accessibility"]["rowSelection"]["limit"] = deepcopy(value["accessibility"]["rowSelection"]["limit"])
            self.assertFalse(M._row_selection_succeeded(success["accessibility"]["rowSelection"]))
            self.assertFalse(M._accessibility_succeeded(success["accessibility"]))
            reject(success, (site, "tuple-on-success"))
        for shape in (("selection-node-limit", "Group", 3, 12, 34, 15),  # Exactly remaining capacity, no overflow.
                      ("selection-node-limit", "Sheet", 0, 0, 1, 16),
                      ("selection-depth-limit", "Sheet", 0, 0, 1, 16),
                      ("selection-node-limit", "Group", 8, 8, 49, 1),
                      ("selection-depth-limit", "Group", 7, 7, 49, 1)):
            reject(selection_limit_context_data(*shape), shape)

    def test_selection_limit_context_and_result_envelopes_remain_bounded(self):
        self.assertEqual((M.FAILURE_CONTEXT_LIMIT, M.JSON_LIMIT), (4096, 16383))
        sizes = []
        for site, depth, count in (("selection-count-limit", 3, (1 << 63) - 1), ("selection-copy-limit", 8, -(1 << 63)),
                                  ("selection-node-limit", 7, 16), ("selection-depth-limit", 8, 16)):
            detail = selection_limit_context_data(site, "ScrollArea", depth, 12,
                                                  49 if site == "selection-node-limit" else 17, count)
            detail["accessibilityBinding"] = binding_context_data()["accessibilityBinding"]
            detail["originalWindow"] = deepcopy(M.expected_result(BINDING, "first-save")["native"]["originalWindow"])
            marker = (b"MRK_MACOS_AQUA_FAILURE_STEP=OpenProject\nMRK_MACOS_AQUA_FAILURE_REASON=native-default-input\n"
                      + context_row(detail) + b"MRK_MACOS_AQUA=failed\n")
            self.assertLessEqual(len(context_row(detail).split(b"=", 1)[1].rstrip(b"\n")), M.FAILURE_CONTEXT_LIMIT)
            fixtures, emitted = InertFixtures(), []
            def runner(argv, **_):
                return CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=marker)
            with self.assertRaisesRegex(M.Refused, "^app-return$") as caught:
                M.run_cases(BINDING, fixtures, runner, UID, "runner", emitted.append)
            report = M.diagnostic(caught.exception, None, fixtures)
            self.assertEqual(report["innerFailureContext"], detail)
            self.assertEqual((report["status"], report["appReturncode"], report["innerFailureStep"], report["innerFailureReason"]),
                             ("failed", 1, "OpenProject", "native-default-input"))
            self.assertEqual((report["originalCallReturned"], report["invocationFinality"]), (True, "no-pending-invocation"))
            self.assertEqual((fixtures.before, fixtures.reads, emitted), (["first-save"], [], []))
            stream = io.StringIO(); M.emit_record(report, stream); wire = stream.getvalue()
            self.assertEqual(json.loads(wire), report)
            self.assertLessEqual(len(wire.rstrip("\n").encode("ascii")), 24576)
            sizes.append(len(wire.rstrip("\n").encode("ascii")))
        self.assertLessEqual(sum(sizes), 98304)  # Four DATA examples, not four executed native failures.
        for case in M.CASES:
            good = M.expected_result(BINDING, case)
            self.assertEqual(M.parse_result(captured(good), b"", BINDING, case), good)
            if case == "picker-loss": continue
            self.assertIsNone(good["native"]["projectOpenInput"]["rowSelection"]["limit"])
            for shape in SELECTION_LIMIT_SHAPES:
                bad = deepcopy(good)
                bad["native"]["projectOpenInput"]["rowSelection"]["limit"] = selection_limit_context_data(*shape)["accessibility"]["rowSelection"]["limit"]
                with self.assertRaises(M.Refused): M.parse_result(captured(bad), b"", BINDING, case)

    def test_original_prompt_refusal_keeps_original_proof_and_never_invents_action(self):
        # Preparing can fail before an input worker exists. Retain that exact
        # entry diagnostic rather than dropping the closed failure subframe.
        preparing = accessibility_context_data(); sample = preparing["accessibility"]
        sample.update(prepared=False, requested=False, dispatchAttempted=False, state="prepared",
            bodyEntered=False, nativeEntered=False, bodyReturned=False, receiptJoined=False,
            workerRegistered=False, workerJoined=False, rechecksSettled=None, barrierRetired=False,
            timely=None, custodyKnown=None, attempted=False, pressReturned=False, triggered=None,
            initialOriginalProof=None, originalProof=None, promptChecks={"initial": None, "final": None},
            promptButton=None, rowSelection=None, selectedTarget=None, site="entry", error="ineligible")
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
                      originalProof=None, promptChecks={"initial": None, "final": None}, promptButton=None, rowSelection=None, selectedTarget=None)
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
                          originalProof=None, selectedTarget=None, promptChecks={"initial": True, "final": None})
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
        sample.update(attempted=False, pressReturned=False, triggered=None, site="original-proof", error="changed", selectedTarget=None)
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
                      initialOriginalProof=None, originalProof=None, promptChecks={"initial": None, "final": None}, promptButton=None, rowSelection=None, selectedTarget=None,
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
            for field, bad in (("prompt", "different"), ("prompt", None), ("promptSetterEntered", False), ("promptSetterReturned", False)):
                value = deepcopy(good); value["native"]["projectOpenBinding"]["configuration"][field] = bad
                with self.assertRaises(M.Refused): M.parse_result(captured(value), b"", BINDING, case)
        for site, count in (("parent-tag", 0), ("parent-set", 1), ("parent-get", 2), ("prompt-set", 3), ("prompt-get", 4)):
            value = binding_context_data(); binding = value["accessibilityBinding"]
            binding["start"]["result"] = "io"; binding["binding"] = None
            configured = binding["configuration"]
            for index, flag in enumerate(("parentSetterEntered", "parentSetterReturned", "promptSetterEntered", "promptSetterReturned")):
                configured[flag] = index < count
            configured.update(parent="match" if count >= 3 else None, prompt=None, site=site, error="objc-exception")
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)
        for prompt in ("nil", "different", "type-invalid"):
            value = binding_context_data(); binding = value["accessibilityBinding"]
            binding["start"]["result"] = "io"; binding["binding"] = None
            binding["configuration"].update(prompt=prompt, site="prompt-get", error="changed")
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)
        for panel in ("nil", "type-invalid", "empty", "byte-limit", "nul", "encoding-invalid", "different"):
            value = binding_context_data(); proof = value["accessibilityBinding"]["binding"]
            proof.update(site="stable-identifier", error="changed", panel=panel)
            proof["checks"].update(stableIdentifier=False, finalEligibility=None)
            self.assertEqual(M.failure_context(b"", context_row(value), "first-save"), value)

    def test_semantic_binding_wrong_case_and_largest_context_are_bounded(self):
        good = accessibility_context_data(); good["accessibilityBinding"] = binding_context_data()["accessibilityBinding"]
        for key, bad in (("mechanism", "public-original-sheet-default-control-v1"), ("case", "save-loss"),
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
        largest["accessibility"]["rowSelection"].update(checks=dict.fromkeys(M.ACCESSIBILITY_SELECTION_CHECKS, False),
            nodesExamined=16, attempted=False, returned=False, setterSucceeded=False,
            limit={"role": "ScrollArea", "depth": 8, "count": -(1 << 63), "queuedNodes": 17})
        largest["accessibility"]["selectedTarget"] = "entered-not-returned"
        largest["accessibility"].update(site=max(M.ACCESSIBILITY_SITES, key=lambda site: (len(site), site)),
                                        error="cleanup-unknown", state="requested")
        largest["accessibilityBinding"]["start"]["result"] = "permission-denied"
        largest["projectSelection"] = project_selection_context_data("inconsistent-original-data", "captured-object-metadata-changed")["projectSelection"]
        largest["accessibilityBinding"]["configuration"].update(parent="type-invalid", prompt="type-invalid", site="prompt-get", error="cleanup-unknown")
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
        checks = observer.split("fn original_window_witness_data_check()", 1)[1].split("fn observer_data_checks()", 1)[0]
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
                 "setDirectoryURL:browse]", "[s->alert buttons]", "[buttons count]", "[buttons objectAtIndex:",
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
        deferred = ('if matches!(reason, "adapter-native-action" | "native-default-binding") && r.pending == Some(Pending::Native(r.step))\n'
                    "            && r.native_dispatch.is_some_and(|native| native.step == r.step && native.entered && !native.returned) {\n"
                    "            return;\n        }")
        self.assertIn(deferred, report)
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
        start = native.split("int mrk_panel_start(", 1)[1].split("int mrk_panel_poll(", 1)[0]
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
        self.assertIn("mrk_ax_array(s, node, kAXChildrenAttribute, 16, at != 0, 0, 0, 0)", roster)
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
        self.assertIn("atomic_flag_test_and_set(&mrk_prompt_claimed)", entry)
        self.assertNotIn("atomic_flag_clear", entry)
        cleanup = entry.split("for (unsigned left = s->count; left; --left)", 1)[1]
        self.assertLess(cleanup.index("mrk_ax_admit(s, 0,"), cleanup.index("CFRelease(slot->value)"))
        self.assertLess(cleanup.index("if (!s->cleanupKnown) break;"), cleanup.index("CFRelease(slot->value)"))
        self.assertIn("if (slot->value) CFRelease(slot->value); slot->value = NULL; s->result.released++", entry)
        self.assertIn("s->result.released == s->result.owned", entry)
        self.assertIn("s->admit = NULL; s->recheck = NULL; s->context = NULL;", entry)
        labels = rust.split("const OPEN_ERRORS:", 1)[1].split("];", 1)[0]
        self.assertEqual(set(M.re.findall(r'"([a-z-]+)"', labels)), M.ACCESSIBILITY_ERRORS)
        preparation = rust.split("pub fn installed_open_identity(", 1)[1].split("pub fn installed_open_recheck(", 1)[0]
        self.assertEqual(preparation.count('OpenDiagnostic { site: "entry"'), 2)
        self.assertNotIn('site: "binding"', preparation)
        wire = rust.split("fn open_return(", 1)[1].split("pub struct OpenInputReturn", 1)[0]
        sites = M.re.findall(r'"([a-z-]+)"', wire.split("site: *[", 1)[1].split("]", 1)[0])
        control_sites = ["control-title-limit", "control-child-count-limit", "control-child-copy-limit", "control-node-limit", "control-depth-limit"]
        selection_sites = ["selection-count-limit", "selection-copy-limit", "selection-node-limit", "selection-depth-limit"]
        self.assertEqual(sites[:14], "entry application windows parent-identifier sheet topology control-projection button "
                         "control-recheck initial-original-proof original-proof admission press cleanup".split())
        self.assertEqual(sites[14:], control_sites + ["selection", "selection-write"] + selection_sites)
        self.assertEqual(set(control_sites), M.ACCESSIBILITY_CONTROL_LIMIT_SITES)
        self.assertEqual(set(selection_sites), M.ACCESSIBILITY_SELECTION_LIMIT_SITES)
        self.assertEqual(set(sites), M.ACCESSIBILITY_SITES)
        enum = native.split("enum { MRK_OPEN_ENTRY = 1u,", 1)[1].split("};", 1)[0]
        self.assertEqual(M.re.findall(r"MRK_OPEN_[A-Z_]+", enum)[-12:], ["MRK_OPEN_CLEANUP", "MRK_OPEN_CONTROL_TITLE_LIMIT",
                         "MRK_OPEN_CONTROL_CHILD_COUNT_LIMIT", "MRK_OPEN_CONTROL_CHILD_COPY_LIMIT",
                         "MRK_OPEN_CONTROL_NODE_LIMIT", "MRK_OPEN_CONTROL_DEPTH_LIMIT", "MRK_OPEN_SELECTION", "MRK_OPEN_SELECTION_WRITE",
                         "MRK_OPEN_SELECTION_COUNT_LIMIT", "MRK_OPEN_SELECTION_COPY_LIMIT", "MRK_OPEN_SELECTION_NODE_LIMIT", "MRK_OPEN_SELECTION_DEPTH_LIMIT"])
        helper = native.split("static BOOL mrk_ax_control_limit(", 1)[1].split("static BOOL mrk_ax_selection_limit(", 1)[0]
        self.assertIn("s->result.site == MRK_OPEN_CONTROL_PROJECTION || s->result.site == MRK_OPEN_CONTROL_RECHECK", helper)
        self.assertIn("&& !s->result.error) s->result.site = site;", helper)
        self.assertIn("return mrk_ax_fail(s, MRK_OPEN_LIMIT);", helper)
        for condition, site, count in (("expected > limit", "COUNT", "expected"), ("count < 0 || count > limit", "COPY", "count")):
            guard = arrays.split(f"if ({condition}) {{", 1)[1].split("\n    }", 1)[0]
            self.assertEqual(guard.strip(),
                f"if (selection_queued) mrk_ax_selection_limit(s, MRK_OPEN_SELECTION_{site}_LIMIT, selection_role, selection_depth, selection_queued, {count});\n"
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
        self.assertTrue("sizeof(MRKOpenResult) == 72" in native, "native selection/press result wire must be72B")
        self.assertTrue("std::mem::size_of::<OpenWire>() != 72" in rust, "Rust selection/press result wire check must be72B")
        for field, offset in (("selection_limit_queued", 60), ("selection_limit_count", 64)):
            self.assertIn(f"offsetof(MRKOpenResult, {field}) == {offset}", native)
            self.assertIn(f"std::mem::offset_of!(OpenWire, {field}) != {offset}", rust)
        self.assertIn("sizeof(CFIndex) == sizeof(int64_t)", native)
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

    def test_real_selection_source_binds_root_row_and_one_selected_urls_gate(self):
        desktop = PATH.parents[1]
        native = (desktop / "native/macos-installed-native/src/native.m").read_text(encoding="utf-8")
        rust = (desktop / "native/macos-installed-native/src/lib.rs").read_text(encoding="utf-8")
        adapter = (desktop / "src-tauri/src/shell_macos_dialog.rs").read_text(encoding="utf-8")
        observer = (desktop / "src-tauri/src/installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        action = native.split("int mrk_panel_observe_action(", 1)[1].split("#undef MRK_ACTION_RETURN", 1)[0]
        self.assertEqual(action.count("setDirectoryURL:browse]"), 1)
        self.assertIn("[url URLByDeletingLastPathComponent]", action)
        self.assertLess(action.index("memcpy(s->observationTarget, directory, length + 1)"), action.index("setDirectoryURL:browse]"))
        self.assertIn("memcpy(s->observationDirectory, parentPath, strlen(parentPath) + 1)", action)
        self.assertIn("PanelAction::ProjectDirectory(&self.project_path)", observer)
        self.assertIn("prepare_open_input(id, &self.project_path, binding_return)", observer)
        prepared = adapter.split("pub(crate) fn prepare_open_input(", 1)[1].split("pub(crate) fn open_release_data_check(", 1)[0]
        self.assertLess(prepared.index("identity.targets(target)"), prepared.index("OpenRelease::new()"))
        self.assertIn("target: [u8; 4097]", rust)
        self.assertIn("bytes[end..].iter().all(|b| *b == 0)", rust)
        self.assertIn("identity.target.as_ptr(), identity.target.len()", rust)
        selected = native.split("static BOOL mrk_ax_row_target(", 1)[1].split("static void mrk_ax_open(", 1)[0]
        for fact in ("kAXURLAttribute", "CFURLGetTypeID()", "CFURLCopyScheme", 'CFSTR("file")',
                     "CFURLGetFileSystemRepresentation", "strcmp((const char *)path, target)",
                     "kAXRowsAttribute", "MRK_ROLE_TABLE", "MRK_ROLE_OUTLINE", "MRK_ROLE_SCROLL_AREA",
                     "kAXRowRole", "MRK_SELECTION_NODES - queued", "pass->depths[at] == MRK_CONTROL_DEPTH",
                     "pass->nodes[other]", "kAXParentAttribute", "selection_nodes_examined++"):
            self.assertIn(fact, selected)
        for forbidden in ("kAXTitleAttribute", "kAXSelectedAttribute", "kAXBrowserRole", "last_role =", "last_depth =",
                          "initial_nodes_examined", "recheck_nodes_examined", "CFRetain", "CFRelease"):
            self.assertNotIn(forbidden, selected)
        roster = selected.split("static BOOL mrk_ax_selection_roster(", 1)[1].split("static BOOL mrk_ax_select_row(", 1)[0]
        self.assertIn("if (matches != 1) return mrk_ax_fail(s, matches ? MRK_OPEN_AMBIGUOUS : MRK_OPEN_UNSUPPORTED)", roster)
        self.assertIn("for (unsigned at = 0; at < queued; ++at)", roster)
        self.assertIn("if (matched) { matches++; pass->candidate = at; }", roster)
        self.assertNotIn("break;", roster.split("if (matches != 1)", 1)[0])
        self.assertNotIn("return YES", roster.split("if (matches != 1)", 1)[0])
        self.assertLess(roster.index("if (matches != 1)"), roster.index("selection_checks |= 1u"))
        self.assertEqual(native.count("AXUIElementIsAttributeSettable("), 1)
        self.assertEqual(native.count("AXUIElementSetAttributeValue("), 1)
        write = selected.split("static BOOL mrk_ax_select_row(", 1)[1]
        self.assertIn("s->result.selection_flags || s->result.selection_checks != 1u", write)
        self.assertLess(write.index("mrk_ax_row_target("), write.index("AXUIElementIsAttributeSettable"))
        self.assertLess(write.index("AXUIElementIsAttributeSettable"), write.index("if (!settable)"))
        self.assertLess(write.index("MRKPromptOwned *selected = mrk_ax_slot(s)"), write.index("CFArrayCreate"))
        self.assertIn("const void *rows[] = { row };", write)
        self.assertLess(write.index("mrk_ax_before(s, container)", write.index("CFArrayCreate")), write.index("selection_flags |= 1u"))
        self.assertLess(write.index("selection_flags |= 1u"), write.index("AXUIElementSetAttributeValue"))
        self.assertLess(write.index("AXUIElementSetAttributeValue"), write.index("selection_flags |= 2u"))
        self.assertIn("status == kAXErrorSuccess", write)
        opened = native.split("static void mrk_ax_open(", 1)[1].split("void mrk_observation_prompt_press(", 1)[0]
        self.assertLess(opened.index("mrk_ax_original(s, 1)"), opened.index("mrk_ax_selection_roster"))
        self.assertLess(opened.index("mrk_ax_selection_roster"), opened.index("mrk_ax_select_row"))
        self.assertLess(opened.index("mrk_ax_select_row"), opened.index("mrk_ax_control_roster"))
        self.assertIn("if (!mrk_ax_selection_roster(s, sheet, target, &selection) || !mrk_ax_select_row(s, parent, &selection, target)) return;", opened)
        self.assertLess(opened.index("mrk_ax_original(s, 2)"), opened.index("AXUIElementPerformAction"))
        self.assertEqual(native.count("AXUIElementPerformAction(button, kAXPressAction)"), 1)
        recheck = native.split("void mrk_panel_observe_open_recheck(", 1)[1].split("enum { MRK_PROMPT_CALLS", 1)[0]
        self.assertIn("memcmp(target, s->observationTarget, target_capacity)", recheck)
        self.assertIn("s->observationRechecks = stage;", recheck)
        self.assertLess(recheck.index("if (!r.error && stage == 2)"), recheck.index("[(NSOpenPanel *)s->window URLs]"))
        self.assertLess(recheck.index("r.selected_target = MRK_TARGET_ENTERED"), recheck.index("[(NSOpenPanel *)s->window URLs]"))
        self.assertEqual(native.count("[(NSOpenPanel *)s->window URLs]"), 1)
        self.assertIn("else if (count != 1) r.selected_target = MRK_TARGET_MULTIPLE", recheck)
        self.assertIn("strcmp(path, s->observationTarget) == 0 ? MRK_TARGET_MATCH : MRK_TARGET_DIFFERENT", recheck)
        self.assertLess(recheck.index("[(NSOpenPanel *)s->window URLs]"), recheck.rindex("mrk_original_eligible(s)"))
        for forbidden in ("setDirectoryURL:", "setNameFieldStringValue:", "while (", "sleep(", "s->selected =", "memcpy(s->selected"):
            self.assertNotIn(forbidden, recheck)
        self.assertEqual(native.count("memcpy(s->selected, path, strlen(path) + 1)"), 1)
        self.assertIn("NSURL *url = [(NSOpenPanel *)s->window URL];", native)
        self.assertIn('self.selection.matched() && self.selected_target == Some("match")', rust)
        self.assertIn('matches!((self.stage, self.selected_target), (1, None) | (2, Some("match")))', rust)
        self.assertIn("sizeof(MRKOpenRecheck) == 52", native)
        self.assertIn("std::mem::size_of::<RecheckWire>() != 52", rust)

    def test_selection_limit_source_is_failure_only_and_preserves_budgets(self):
        desktop = PATH.parents[1]
        native = (desktop / "native/macos-installed-native/src/native.m").read_text(encoding="utf-8")
        rust = (desktop / "native/macos-installed-native/src/lib.rs").read_text(encoding="utf-8")
        observer = (desktop / "src-tauri/src/installed_shell_observation_macos.rs").read_text(encoding="utf-8")
        qualification = PATH.read_text(encoding="utf-8")
        for bound in ("MRK_SELECTION_NODES = 49", "MRK_SELECTION_ROWS = 32"):
            self.assertIn(bound, native)
        control_storage = native.split("} MRKControlPass;", 1)[0].rsplit("typedef struct {", 1)[1]
        selection_storage = native.split("} MRKSelectionPass;", 1)[0].rsplit("typedef struct {", 1)[1]
        for field in ("nodes", "parents", "depths", "roles"):
            self.assertIn(f"{field}[MRK_CONTROL_NODES]", control_storage)
            self.assertIn(f"{field}[MRK_SELECTION_NODES]", selection_storage)
        self.assertIn("chain[MRK_CONTROL_DEPTH + 1]", selection_storage)
        self.assertIn("const MRKSelectionPass *pass", native)
        self.assertIn("MRKSelectionPass selection = {0};", native)
        helper = native.split("static BOOL mrk_ax_selection_limit(", 1)[1].split("static uint32_t mrk_ax_role(", 1)[0]
        gate = "if (s->result.site == MRK_OPEN_SELECTION && !s->result.error) {"
        for fact in ("s->result.site = site", "s->result.last_role = role", "s->result.last_depth = depth",
                     "s->result.selection_limit_queued = queued", "s->result.selection_limit_count = (int64_t)count"):
            self.assertEqual(helper.count(fact), 1)
            self.assertLess(helper.index(gate), helper.index(fact))
            self.assertLess(helper.index(fact), helper.index("return mrk_ax_fail(s, MRK_OPEN_LIMIT)"))
        for forbidden in ("AXUIElement", "CFArrayGet", "CFGet", "CFRetain", "CFRelease", "malloc(", "calloc(",
                          "mrk_ax_copy(", "mrk_ax_array(", "mrk_ax_admit(", "sleep(", "dispatch", "@try"):
            self.assertNotIn(forbidden, helper)
        self.assertEqual(native.count("mrk_ax_selection_limit("), 5)
        self.assertEqual(native.count("s->result.selection_limit_queued ="), 1)
        self.assertEqual(native.count("s->result.selection_limit_count ="), 1)
        self.assertIn("uint32_t selection_limit_queued; int64_t selection_limit_count; } MRKOpenResult;", native)
        self.assertIn("selection_limit_queued: u32, selection_limit_count: i64 }", rust)
        arrays = native.split("static CFArrayRef mrk_ax_array(", 1)[1].split("static BOOL mrk_ax_equal_attribute(", 1)[0]
        self.assertIn("uint32_t selection_role, uint32_t selection_depth, uint32_t selection_queued", arrays)
        self.assertLess(arrays.index("if (!counted || !admitted) return NULL"), arrays.index("if (expected < 0)"))
        self.assertLess(arrays.index("if (expected < 0)"), arrays.index("MRK_OPEN_SELECTION_COUNT_LIMIT"))
        self.assertLess(arrays.index("if (!copied || !admitted || !mrk_ax_type"), arrays.index("CFArrayGetCount(slot->array)"))
        self.assertLess(arrays.index("CFArrayGetCount(slot->array)"), arrays.index("MRK_OPEN_SELECTION_COPY_LIMIT"))
        self.assertLess(arrays.index("MRK_OPEN_SELECTION_COPY_LIMIT"), arrays.index("if (count != expected)"))
        self.assertEqual(native.count("mrk_ax_array("), 5)
        for context in ("mrk_ax_array(s, app, kAXWindowsAttribute, 4, NO, 0, 0, 0)",
                        "mrk_ax_array(s, found_parent, kAXChildrenAttribute, 16, NO, 0, 0, 0)",
                        "mrk_ax_array(s, node, kAXChildrenAttribute, 16, at != 0, 0, 0, 0)"):
            self.assertEqual(native.count(context), 1)
        roster = native.split("static BOOL mrk_ax_selection_roster(", 1)[1].split("static BOOL mrk_ax_select_row(", 1)[0]
        self.assertIn("mrk_ax_array(s, node, rows ? kAXRowsAttribute : kAXChildrenAttribute, rows ? MRK_SELECTION_ROWS : 16, at != 0,\n"
                      "            kind, pass->depths[at], queued)", roster)
        depth = ("if (count && pass->depths[at] == MRK_CONTROL_DEPTH)\n"
                 "            return mrk_ax_selection_limit(s, MRK_OPEN_SELECTION_DEPTH_LIMIT, kind, pass->depths[at], queued, count)")
        nodes = ("if ((unsigned)count > MRK_SELECTION_NODES - queued)\n"
                 "            return mrk_ax_selection_limit(s, MRK_OPEN_SELECTION_NODE_LIMIT, kind, pass->depths[at], queued, count)")
        self.assertLess(roster.index("CFIndex count = CFArrayGetCount(children)"), roster.index(depth))
        self.assertLess(roster.index(depth), roster.index(nodes))
        self.assertLess(roster.index(nodes), roster.index("pass->nodes[queued] ="))
        self.assertLess(roster.index("kind = pass->roles[at]"), roster.index("mrk_ax_array("))
        for forbidden in ("last_role =", "last_depth =", "selection_limit_queued =", "selection_limit_count ="):
            self.assertNotIn(forbidden, roster)
        for function in ("AXUIElementGetAttributeValueCount", "AXUIElementCopyAttributeValues", "AXUIElementCopyAttributeValue",
                         "AXUIElementCopyActionNames", "AXUIElementIsAttributeSettable", "AXUIElementSetAttributeValue",
                         "AXUIElementPerformAction"):
            self.assertEqual(native.count(function + "("), 1, function)
        wire = rust.split("fn open_return(", 1)[1].split("pub struct OpenInputReturn", 1)[0]
        local = wire.split("let limit = if matches!(w.site, 22..=25)", 1)[1].split("let selection = RowSelectionProof", 1)[0]
        for fact in ("w.error != 7", "w.ax_error != 0", "w.checks != 3", "w.flags & 7 != 0",
                     "w.initial_nodes_examined != 0", "w.recheck_nodes_examined != 0",
                     "w.selection_checks != 0", "w.selection_flags != 0", "w.calls == 0", "w.owned == 0",
                     "!rechecks[0].is_some_and(OpenRecheckReturn::matched)", "rechecks[1].is_some()",
                     "!(1..=49).contains(&w.selection_limit_queued)", "w.selection_limit_queued < w.selection_nodes_examined + 1",
                     "w.last_role == 1 && w.last_depth == 0 && w.selection_nodes_examined == 0",
                     "w.selection_limit_queued == 1", "matches!(w.last_role, 2 | 3 | 6 | 7 | 8)",
                     "w.last_depth <= w.selection_nodes_examined", "if matches!(w.last_role, 6 | 7) { 32 } else { 16 }",
                     "22 => count > array_limit && (root || container)",
                     "23 => (count < 0 || count > array_limit) && (root || container)",
                     "24 => (1..=array_limit).contains(&count) && count > i64::from(49 - w.selection_limit_queued)",
                     "&& container && w.last_depth < 8", "25 => (1..=array_limit).contains(&count) && container && w.last_depth == 8",
                     "if w.selection_limit_queued != 0 || w.selection_limit_count != 0 { return None; }"):
            self.assertIn(fact, local)
        self.assertIn(".get(if limit.is_some() { 0 } else { w.last_role as usize })?", wire)
        self.assertIn("last_depth: if limit.is_some() { 0 } else { w.last_depth }", wire)
        self.assertIn("|| limit.is_none() && w.last_depth > w.initial_nodes_examined.max(w.recheck_nodes_examined)", wire)
        selection = rust.split("impl RowSelectionProof {", 1)[1].split("pub struct ControlContainerButtonProof", 1)[0]
        self.assertIn("(2..=48).contains(&self.nodes_examined)", selection)
        self.assertIn("w.selection_nodes_examined > 48", wire)
        self.assertIn("&& self.limit.is_none()", selection)
        rendered = observer.split("fn row_selection_value(", 1)[1].split("struct OpenActionReceipt", 1)[0]
        self.assertIn('p.limit.map(|l| json!({"role":l.role,"depth":l.depth,"count":l.count,"queuedNodes":l.queued_nodes}))', rendered)
        self.assertIn('"limit":limit', rendered)
        self.assertIn('and value["limit"] is None', qualification)
        self.assertIn('set(limit) == {"role", "depth", "count", "queuedNodes"}', qualification)
        for bound in ("MRK_PROMPT_CALLS = 512", "MRK_PROMPT_CF = 256", "MRK_CONTROL_NODES = 17", "MRK_CONTROL_DEPTH = 8"):
            self.assertIn(bound, native)
        self.assertIn("let end = Instant::now() + Duration::from_secs(45);", observer)
        self.assertIn("let end = self.end.min(Instant::now() + Duration::from_secs(2));", observer)
        self.assertIn("timeout=60, capture=True, text=False, output_limit=OUTPUT_LIMIT", qualification)
        self.assertIn('len(data.encode("ascii")) <= 24 * 1024', qualification)

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
        self.assertLess(relay.index("OpenRecheckSlot { receipt: first_receipt"), relay.index('.name("mrk-aqua-open".into()).spawn('))
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
        self.assertIn("slot.receipt.recv_timeout(self.end.saturating_duration_since(Instant::now()))", recheck)
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
        writer = observer.split("struct DiagnosticWriter", 1)[1].split("pub(super) struct Observation", 1)[0]
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
        release = native.split("int mrk_panel_release(", 1)[1].split("// Observation helpers", 1)[0]
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
        for required in ("root.identity.preflight_identity()", "identity.device.parse().ok()?", "identity.inode.parse().ok()?",
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
        self.assertIn("q.project_result(&result);", command)  # Linux hook signature is unchanged.
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
                          'config["content"] != json!({"bytes":CONFIG.len(), "sha256":digest(CONFIG)})',
                          'config["state"] != "missing"', '!config["data"].is_null()', '!config["content"].is_null()',
                          'issues.len() == 1 && issues[0]["code"] == "config.missing"'):
            self.assertIn(predicate, values)
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
