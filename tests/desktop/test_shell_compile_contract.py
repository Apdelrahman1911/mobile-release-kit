"""In-memory compiler-only contracts; no compiler, application or native execution."""
from __future__ import annotations

from copy import deepcopy
import contextlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import unittest
from unittest.mock import patch

HELPER = Path(__file__).resolve().parents[2] / "desktop/tools/ci_foundation.py"
SPEC = importlib.util.spec_from_file_location("desktop_shell_compile_contract", HELPER)
assert SPEC is not None and SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


def environment() -> dict[str, str]:
    return {"GITHUB_SHA": "1" * 40, "GITHUB_WORKFLOW_SHA": "1" * 40,
            "GITHUB_REPOSITORY": "fictional/project", "GITHUB_REF": helper.COMPILE_REF,
            "GITHUB_WORKFLOW_REF": f"fictional/project/{helper.COMPILE_WORKFLOW}@{helper.COMPILE_REF}",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_NAME": "push"}


def context() -> dict:
    return {**helper.compile_workflow_binding(environment()), "platform": "linux",
            "workflowSha256": "2" * 64, "executionScope": helper.COMPILE_SCOPE}


def receipt(phase: str) -> dict:
    binding = context()
    return {"schemaVersion": 1, "scope": helper.COMPILE_EVIDENCE_SCOPE, "phase": phase, "status": "passed",
            **{key: binding[key] for key in ("sourceSha", "platform", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt")},
            "rust": {"release": helper.RUST, "target": helper.TARGETS["linux"]}, "node": helper.NODE,
            "checks": [{"check": check, "exitCode": 0} for check in helper.COMPILE_CHECKS[phase]]}


def mac_environment(target="aarch64-apple-darwin", mode="full4"):
    arch, _, images, _, _ = helper.MAC_COMPILE_HOSTS[target]
    value = {**environment(), "GITHUB_REF": helper.MAC_COMPILE_REF,
             "GITHUB_WORKFLOW_REF": f"fictional/project/{helper.MAC_COMPILE_WORKFLOW}@{helper.MAC_COMPILE_REF}",
             "MRK_MACOS_TARGET": target, "MRK_MACOS_COMPILE_MODE": mode, "MRK_COMPILE_SELECTION": "both",
             "RUNNER_OS": "macOS", "RUNNER_ARCH": arch, "ImageOS": images[0],
             "GITHUB_WORKSPACE": "/inert/source", "RUNNER_TEMP": "/inert/tmp", "PATH": "/selected/bin",
             "GITHUB_OUTPUT": "/inert/output", "MRK_DESKTOP_PLATFORM": "macos",
             "MRK_DESKTOP_HOSTED_CHECKS": helper.MAC_COMPILE_SCOPE}
    if mode == "vault-only":
        value.update(GITHUB_EVENT_NAME="workflow_dispatch", MRK_COMPILE_SELECTION="remaining", MRK_EXPECTED_SHA="1" * 40)
    if mode in ("app-only", "observer-only"):
        value.update(GITHUB_EVENT_NAME="workflow_dispatch", MRK_COMPILE_SELECTION=mode, MRK_EXPECTED_SHA="1" * 40)
    return value


def mac_context(target="aarch64-apple-darwin", mode="full4"):
    vault = ["mac-vault-bin-compile-only", "desktop/helpers/macos-vault-helper/Cargo.toml", "release", "", "mrk-vault-keychain"]
    return {**helper.compile_workflow_binding(mac_environment(target, mode), helper.MAC_COMPILE_SCOPE),
            "root": "/inert/tmp/mrk-desktop-foundation-original", "source": "/inert/source", "git": "/usr/bin/git",
            "platform": "macos", "sourceTree": "3" * 40, "workflowSha256": "2" * 64,
            "executionScope": helper.MAC_COMPILE_SCOPE,
            # Synthetic context only; never an admitted native/source receipt.
            "macCompile": {"target": target, "mode": mode, "release": helper.MAC_COMPILE_HOSTS[target][4] + "desktop-01",
                           "sources": [], "graphs": ([["mac-observer-compile-only", "desktop/src-tauri/Cargo.toml", "test",
                                        "desktop-shell,custom-protocol,macos-installed-observation", "installed-shell-observation"]] if mode == "observer-only" else [["mac-normal-bin-compile-only", "desktop/src-tauri/Cargo.toml", "release",
                                        "desktop-shell,custom-protocol", "mobile-release-kit-desktop"]] if mode == "app-only" else
                                      [vault, *([list(row) for row in helper.MAC_COMPILE_GRAPHS] if mode == "full4" else [])]),
                           "execution": "compile-only"}}


def engineering_environment():
    value = mac_environment()
    value.pop("MRK_COMPILE_SELECTION")
    value.pop("MRK_MACOS_COMPILE_MODE")
    value.update(GITHUB_REF=helper.ENGINEERING_COMPILE_REF,
                 GITHUB_WORKFLOW_REF=f"fictional/project/{helper.ENGINEERING_COMPILE_WORKFLOW}@{helper.ENGINEERING_COMPILE_REF}",
                 MRK_DESKTOP_HOSTED_CHECKS=helper.ENGINEERING_COMPILE_SCOPE,
                 MRK_MACOS_WORK="/inert/tmp/mrk-macos-engineering-ui.ABCdef12")
    return value


def engineering_context():
    env = engineering_environment()
    return {**helper.compile_workflow_binding(env, helper.ENGINEERING_COMPILE_SCOPE),
            "root": "/inert/tmp/mrk-desktop-foundation-original", "source": "/inert/source", "git": "/usr/bin/git",
            "platform": "macos", "sourceTree": "3" * 40, "workflowSha256": "2" * 64,
            "executionScope": helper.ENGINEERING_COMPILE_SCOPE, "engineeringWork": env["MRK_MACOS_WORK"]}


# Independent SOURCE expectations, not copied from the production tuple map.
# These are synthetic probe/receipt DATA; only a later real -vV can qualify it.
MAC_RUST_EXPECTED = {
    "aarch64-apple-darwin": {"release": "1.98.1", "commitHash": "48a229ceaefd4985c50990b14116b6d856af0985",
                             "target": "aarch64-apple-darwin"},
    "x86_64-apple-darwin": {"release": "1.98.0", "commitHash": "88d9e12ae178fab0fb5cc050a94da85685d449ea",
                           "target": "x86_64-apple-darwin"},
}


def memory_paths(events):
    class Stream:
        def __init__(self, *args, **kwargs):
            self.name = str(args[0]) if args else "memory"
        def __enter__(self):
            return self
        def __exit__(self, *args):
            events.append(("closed", self.name))
        def write(self, value):
            events.append(("write", self.name, value))
            return len(value)
    class MemoryPath(PurePosixPath):
        def resolve(self, strict=False):
            return self
        def exists(self):
            return False
        def is_symlink(self):
            return False
        def mkdir(self, **kwargs):
            events.append(("mkdir", str(self)))
        def touch(self, **kwargs):
            events.append(("touch", str(self)))
        def rglob(self, pattern):
            return iter(())
        def open(self, *args, **kwargs):
            events.append(("open", str(self), args))
            return Stream(self)
    return MemoryPath, Stream


# Independent fixed-selector DATA, never a caller-provided test filter.
SOURCE_SLOTS_CASE = "installed_runtime::android_registration_source::storage_capacity_tests::phase_checked_allocation_uses_exact_admitted_records_without_native_entry"


def source_slots_environment():
    value = mac_environment("x86_64-apple-darwin")
    value.pop("MRK_COMPILE_SELECTION")
    value.pop("MRK_MACOS_COMPILE_MODE")
    value.update(GITHUB_REF="refs/heads/verify/desktop-macos-intel-source-slots",
                 GITHUB_WORKFLOW_REF="fictional/project/.github/workflows/desktop-macos-intel-source-slots.yml@refs/heads/verify/desktop-macos-intel-source-slots",
                 MRK_DESKTOP_HOSTED_CHECKS="macos-intel-source-slots-v1")
    return value


def source_slots_context():
    return {**helper.compile_workflow_binding(source_slots_environment(), helper.SOURCE_SLOTS_SCOPE),
            "root": "/inert/tmp/mrk-desktop-foundation-original", "source": "/inert/source", "git": "/usr/bin/git",
            "platform": "macos", "sourceTree": "3" * 40, "workflowSha256": "2" * 64,
            "executionScope": "macos-intel-source-slots-v1", "rustup": None,
            "sourceSlots": {"target": "x86_64-apple-darwin", "features": ["development-runtime"],
                            "testTarget": "lib", "test": SOURCE_SLOTS_CASE}}


def source_slots_result():
    return {"test": SOURCE_SLOTS_CASE, "running": 1, "passed": 1, "failed": 0,
            "ignored": 0, "measured": 0, "filtered": 7}


def source_slots_stdout():
    return ("\nrunning 1 test\ntest " + SOURCE_SLOTS_CASE + " ... ok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.03s\n\n").encode()


def source_slots_receipt(phase):
    bound = source_slots_context()
    checks = ["rust-version-target", "mac-cargo-version"] + (
        ["mac-source-slots-locked-metadata"] if phase == "acquire" else ["headless-test-compile-only", "mac-source-slots-data-test"])
    value = {"schemaVersion": 1, "scope": "desktop-macos-intel-source-slots-data-v1", "phase": phase, "status": "passed",
             **{key: bound[key] for key in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha",
                                           "workflowRef", "workflowSha256", "runId", "attempt", "sourceSlots")},
             "rust": deepcopy(MAC_RUST_EXPECTED["x86_64-apple-darwin"]), "node": None,
             "checks": [{"check": check, "exitCode": 0} for check in checks]}
    if phase == "compile":
        value["testResult"] = source_slots_result()
    return value


# Independent expected tuple in actual lexical libtest output order.
INITIALIZATION_CASES = (
    'edit_owner::workflow_domain_tests::initialization_intent_original_slot_and_recovery_finality_are_closed',
    'project_initialization_edit_protocol::tests::complete_inventory_and_redacted_review_remain_closed_and_bounded',
    'project_initialization_edit_protocol::tests::fixed_open_and_response_shapes_never_borrow_other_edit_intents',
    'project_initialization_edit_protocol::tests::recovery_keeps_historical_effects_but_never_mints_clean_before_apply',
)


def initialization_environment():
    return {**source_slots_environment(), "GITHUB_EVENT_NAME": "workflow_dispatch", "MRK_EXPECTED_SHA": "1" * 40,
            "MRK_SOURCE_SLOTS_SELECTION": "project-initialization4"}


def initialization_context():
    return {**source_slots_context(), **helper.compile_workflow_binding(initialization_environment(), helper.SOURCE_SLOTS_SCOPE),
            "sourceSlots": {"target": "x86_64-apple-darwin", "features": ["development-runtime"],
                            "testTarget": "lib", "tests": list(INITIALIZATION_CASES)}}


def initialization_result():
    return {"tests": list(INITIALIZATION_CASES), "running": 4, "passed": 4, "failed": 0,
            "ignored": 0, "measured": 0, "filtered": 7}


def initialization_stdout():
    return ("\nrunning 4 tests\n" + "".join("test " + name + " ... ok\n" for name in INITIALIZATION_CASES)
            + "\ntest result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.03s\n\n").encode()


def initialization_receipt(phase):
    value = source_slots_receipt(phase)
    value.update(scope="desktop-macos-project-initialization-data-v1", sourceSlots=initialization_context()["sourceSlots"],
                 sourceSlotsSelection="project-initialization4")
    if phase == "compile":
        value["testResult"] = initialization_result()
    return value


ARTIFACT_CASES = (
    'artifact_inspection_protocol::tests::actual_profile_counts_and_negative_checks_never_replace_original_finality',
    'artifact_inspection_protocol::tests::exact_result_frames_and_status_headroom_do_not_truncate_or_accept_unbounded_strings',
    'artifact_inspection_protocol::tests::originals_have_lossless_full_tuples_without_claiming_payload_or_native_custody',
    'artifact_inspection_protocol::tests::selected_ids_are_closed_distinct_and_never_paths_or_other_domain_consent',
    'installed_runtime::installed_github_action_original_slots_are_inert_and_uncertainty_is_absorbing',
    'runtime::macos_github_actions_profile_data_contract',
    'saved_command_owner::artifact_inputs::tests::missing_original_table_cannot_be_loaned_or_consumed_and_metadata_census_is_checked',
    'saved_command_owner::tests::artifact_original_closure_distinguishes_unentered_from_claimed_and_unreturned_workers',
    'saved_command_owner::tests::artifact_two_frames_without_selected_originals_never_publish_and_first_stop_never_renews',
    'supervisor::macos_github_actions_original_data_contract',
)


def artifact_environment():
    return {**source_slots_environment(), "GITHUB_EVENT_NAME": "workflow_dispatch", "MRK_EXPECTED_SHA": "1" * 40,
            "MRK_SOURCE_SLOTS_SELECTION": "artifact-setup10"}


def artifact_context():
    return {**source_slots_context(), **helper.compile_workflow_binding(artifact_environment(), helper.SOURCE_SLOTS_SCOPE),
            "sourceSlots": {"target": "x86_64-apple-darwin", "features": ["development-runtime"],
                            "testTarget": "lib", "tests": list(ARTIFACT_CASES)}}


def artifact_result():
    return {"tests": list(ARTIFACT_CASES), "running": 10, "passed": 10, "failed": 0,
            "ignored": 0, "measured": 0, "filtered": 7}


def artifact_stdout():
    return ("\nrunning 10 tests\n" + "".join("test " + name + " ... ok\n" for name in ARTIFACT_CASES)
            + "\ntest result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.03s\n\n").encode()


def artifact_receipt(phase):
    value = source_slots_receipt(phase)
    value.update(scope="desktop-macos-artifact-setup-data-v1", sourceSlots=artifact_context()["sourceSlots"],
                 sourceSlotsSelection="artifact-setup10")
    if phase == "compile":
        value["testResult"] = artifact_result()
    return value


ENVIRONMENT_CASES = ("supervisor::macos_github_actions_original_data_contract",)


def environment_setup_environment():
    return {**source_slots_environment(), "GITHUB_EVENT_NAME": "workflow_dispatch", "MRK_EXPECTED_SHA": "1" * 40,
            "MRK_SOURCE_SLOTS_SELECTION": "environment-setup1"}


def environment_setup_context():
    return {**source_slots_context(), **helper.compile_workflow_binding(environment_setup_environment(), helper.SOURCE_SLOTS_SCOPE),
            "sourceSlots": {"target": "x86_64-apple-darwin", "features": ["development-runtime"],
                            "testTarget": "lib", "tests": list(ENVIRONMENT_CASES)}}


def environment_setup_result():
    return {"tests": list(ENVIRONMENT_CASES), "running": 1, "passed": 1, "failed": 0,
            "ignored": 0, "measured": 0, "filtered": 7}


def environment_setup_stdout():
    return ("\nrunning 1 test\n" + "".join("test " + name + " ... ok\n" for name in ENVIRONMENT_CASES)
            + "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.03s\n\n").encode()


def environment_setup_receipt(phase):
    value = source_slots_receipt(phase)
    value.update(scope="desktop-macos-environment-setup-data-v1", sourceSlots=environment_setup_context()["sourceSlots"],
                 sourceSlotsSelection="environment-setup1")
    if phase == "compile":
        value["testResult"] = environment_setup_result()
    return value


def source_slots_paths(events, captures):
    MemoryPath, _ = memory_paths(events)
    class Capture(io.StringIO):
        def __init__(self, path):
            super().__init__()
            self.path = str(path)
        def __exit__(self, *args):
            captures[self.path] = self.getvalue().encode()
            events.append(("closed", self.path))
            return super().__exit__(*args)
    class SlotsPath(MemoryPath):
        def open(self, *args, **kwargs):
            events.append(("open", str(self), args))
            return Capture(self)
    def writer(path, stream):
        assert str(path) == stream.path
        return (1, 3, 0o100600, 501, 20, 1, len(stream.getvalue().encode()), 1, 1)
    def read(path, expected):
        body = captures[str(path)]
        assert len(body) == expected[6]
        return body if path.name == "source-slots-test.stdout" else b""
    return SlotsPath, writer, read


# Literal B selection independent from the production tuple; all source bodies
# below are inert DATA, not genuine package/signature/native inputs.
INTEL_REMOVAL_CASES = [
    "installer::worker::tests::original_join_requires_eof_closes_matching_return_and_timely_sources",
    "installer::worker::tests::private_frames_require_fixed_binding_shapes_bounds_and_no_future_finality",
    "installer::worker::tests::same_absolute_endpoint_reserves_settlement_and_rejects_backwards_or_overflow",
]


def intel_removal_environment():
    value = source_slots_environment()
    value.update(GITHUB_REF="refs/heads/verify/desktop-macos-intel-removal-abrupt",
                 GITHUB_WORKFLOW_REF="fictional/project/.github/workflows/desktop-macos-intel-source-slots.yml@refs/heads/verify/desktop-macos-intel-removal-abrupt",
                 MRK_PUSH_EVENT_AFTER=value["GITHUB_SHA"])
    return value


def intel_removal_bodies():
    return {
        "desktop/macos-installed-inputs/build-release-intel.json": b'{"schemaVersion":1,"packageVersion":"0.1.1","release":"macos26-x86_64-desktop-01"}',
        "desktop/src-tauri/Cargo.toml": b'[package]\nversion = "0.1.1"\n',
        "desktop/src-tauri/tauri.conf.json": b'{"version":"0.1.1"}',
    }


def intel_removal_build():
    return {"release": "macos26-x86_64-desktop-01", "sources": [
        {"path": name, "size": len(body), "sha256": helper.hashlib.sha256(body).hexdigest()}
        for name, body in intel_removal_bodies().items()]}


def intel_removal_context():
    value = source_slots_context()
    value.update(helper.compile_workflow_binding(intel_removal_environment(), helper.SOURCE_SLOTS_SCOPE))
    value.update(sourceSlots={"target": "x86_64-apple-darwin", "features": ["macos-installed-removal-abrupt-fixture"],
                              "testTarget": "bin", "binary": "mrk-macos-remove", "tests": list(INTEL_REMOVAL_CASES)},
                 sourceSlotsBuild=intel_removal_build())
    return value


def intel_removal_result():
    return {"tests": list(INTEL_REMOVAL_CASES), "running": 3, "passed": 3, "failed": 0,
            "ignored": 0, "measured": 0, "filtered": 7}


def intel_removal_stdout():
    return ("\nrunning 3 tests\n" + "".join("test " + name + " ... ok\n" for name in INTEL_REMOVAL_CASES)
            + "\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.03s\n\n").encode()


def intel_removal_receipt(phase):
    value, bound = source_slots_receipt(phase), intel_removal_context()
    value.update(scope="desktop-macos-intel-removal-abrupt-data-v1", workflowRef=bound["workflowRef"],
                 sourceSlots=deepcopy(bound["sourceSlots"]), sourceSlotsBuild=deepcopy(bound["sourceSlotsBuild"]))
    if phase == "compile":
        value["testResult"] = intel_removal_result()
    return value


# Separate fixed four-name nomination: no derived expected result from provider.
HISTORY_APP_CASES = [
    "github_history_protocol::tests::closed_history_commands_frames_and_original_context",
    "github_history_protocol::tests::complete_history_result_shapes_and_retained_status_are_bounded",
    "runtime::macos_github_actions_profile_data_contract",
    "supervisor::macos_github_actions_original_data_contract",
]


def history_app_environment(target):
    value = mac_environment(target)
    value.update(GITHUB_EVENT_NAME="workflow_dispatch", MRK_EXPECTED_SHA=value["GITHUB_SHA"],
                 MRK_COMPILE_SELECTION="history-app4", MRK_MACOS_COMPILE_MODE="history-app4")
    return value


def history_app_context(target):
    value = mac_context(target)
    value.update(helper.compile_workflow_binding(history_app_environment(target), helper.MAC_COMPILE_SCOPE))
    value["macCompile"].update(mode="history-app4", execution="compile-and-selected-data", tests=list(HISTORY_APP_CASES),
        graphs=[["headless-test-compile-only", "desktop/src-tauri/Cargo.toml", "test", "development-runtime", "lib"],
                list(helper.MAC_COMPILE_GRAPHS[0])])
    return value


def history_app_result():
    return {"tests": list(HISTORY_APP_CASES), "running": 4, "passed": 4, "failed": 0,
            "ignored": 0, "measured": 0, "filtered": 7}


def history_app_stdout():
    return ("\nrunning 4 tests\n" + "".join("test " + name + " ... ok\n" for name in HISTORY_APP_CASES)
            + "\ntest result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.04s\n\n").encode()


def history_app_receipt(target, phase):
    bound = history_app_context(target)
    value = {"schemaVersion": 1, "scope": "desktop-macos-history-app-data-v1", "phase": phase, "status": "passed",
             **{key: bound[key] for key in ("sourceSha", "platform", "workflowPath", "workflowSha", "workflowRef",
                                           "workflowSha256", "runId", "attempt", "sourceTree", "macCompile")},
             "rust": deepcopy(MAC_RUST_EXPECTED[target]), "node": helper.NODE,
             "checks": [{"check": name, "exitCode": 0} for name in helper.MAC_HISTORY_CHECKS[phase]]}
    if phase == "compile":
        value["testResult"] = history_app_result()
    return value


def observer_data_fixture():
    """Real SOURCE rosters with inert metadata; never a native result witness."""
    raw = (HELPER.parents[2] / "desktop/tools/macos_installed_data_contracts.sh").read_bytes()
    body, sources, tests = helper.mac_observer_data_selection(raw)
    rows = [{"path": name, "size": len(raw) if name == helper.MAC_OBSERVER_DATA_SCRIPT else 1,
             "sha256": helper.hashlib.sha256(raw).hexdigest() if name == helper.MAC_OBSERVER_DATA_SCRIPT else "4" * 64}
            for name in sorted(sources)]
    inventory = helper.canonical_json({"files": rows}) + b"\n"
    bound = mac_context()
    bound["root"] = "/Users/runner/work/_temp/mrk-desktop-foundation-inert"
    bound["source"] = "/Users/runner/work/mobile-release-kit/mobile-release-kit"
    bound["macCompile"].update(mode="observer-data", execution="compile-and-fixed-data",
        graphs=[["mac-observer-fixed-data", "desktop/src-tauri/Cargo.toml", "test",
                 "desktop-shell,custom-protocol,macos-installed-observation", "installed-shell-observation"]],
        data={"sourceCount": 78, "sourceInventorySha256": helper.hashlib.sha256(inventory).hexdigest(),
              "scriptSha256": helper.hashlib.sha256(raw).hexdigest(), "pythonCount": 84,
              "selectionSha256": "0fd968d2c78e233df8cc344ae3ff27d417bd3c76fb5bde42b3ea8d393f8e7a94"})
    private = {"schemaVersion": 1, "scope": "ci-observer-fixed-data-and-selected-host-python-regressions",
        "sourceCommit": bound["sourceSha"], "sourceTree": bound["sourceTree"],
        "sourceInventorySha256": bound["macCompile"]["data"]["sourceInventorySha256"],
        "frozenSelectionSha256": bound["macCompile"]["data"]["selectionSha256"], "pythonExpectedCount": 84,
        "ciContext": {key: bound[key] for key in ("workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt")},
        "sourceRows": rows, "pythonTestIds": list(tests),
        "commands": [{"phase": phase, "originalReturned": True, "returnCode": 0, "outputComplete": True,
                      "captureClosed": True, "timedOut": False, "outputOverflow": False}
                     for phase in ("mount", "apfs", "build", "rust", "python")],
        "artifact": {"sha256": "5" * 64, "identity": [1, 2, 0o100700, 1000, 1000, 1, 64, 3, 4],
                     "unchangedAfterRun": True, "originalClosed": True},
        "pythonCounts": {"testsRun": 84, "failures": 0, "errors": 0, "skipped": 0,
                         "expectedFailures": 0, "unexpectedSuccesses": 0, "testIds": list(tests), "actualHostBeforeAndAfter": True},
        "ciAggregatePassed": True, "ciSourcePost": True, "ciTemporaryEmpty": True, "passed": True, "failure": None}
    return raw, body, bound, private


def observer_data_child_functions(body):
    # Compile only the three named pure definitions, never the SOURCE top-level,
    # environment admission, subprocess imports, or the five original commands.
    names = ("data_failure_json", "ci_data_admission", "ci_data_seconds")
    parsed = helper.ast.parse(body)
    selected = [node for node in parsed.body if isinstance(node, helper.ast.FunctionDef) and node.name in names]
    if tuple(node.name for node in selected) != names:
        raise AssertionError("fixed CI DATA pure definitions differ")
    namespace = {"__builtins__": __builtins__, "json": json, "hashlib": helper.hashlib, "re": helper.re, "Path": Path}
    exec(compile(helper.ast.Module(body=selected, type_ignores=[]), "<genuine-ci-data-admission>", "exec"), namespace)
    return namespace


class ShellCompileContractTests(unittest.TestCase):
    def test_observer_data_selection_and_dispatch_are_source_fixed(self):
        raw, body, bound, private = observer_data_fixture()
        selected_body, sources, tests = helper.mac_observer_data_selection(raw)
        self.assertEqual(selected_body, body)
        self.assertEqual((len(sources), len(tests)), (78, 84))
        self.assertEqual(tuple(private["pythonTestIds"]), tests)
        self.assertEqual(helper.hashlib.sha256(json.dumps(list(tests), separators=(",", ":")).encode()).hexdigest(),
                         "0fd968d2c78e233df8cc344ae3ff27d417bd3c76fb5bde42b3ea8d393f8e7a94")
        helper.mac_observer_data_binding(bound["macCompile"]["data"])
        parsed = helper.ast.parse(body)
        assignments = {node.targets[0].id: node for node in parsed.body if isinstance(node, helper.ast.Assign)
                       and len(node.targets) == 1 and isinstance(node.targets[0], helper.ast.Name)}
        lines = body.splitlines(keepends=True)
        def altered(name, value):
            node = assignments[name]
            changed = "".join(lines[:node.lineno - 1]) + name + " = " + repr(value) + "\n" + "".join(lines[node.end_lineno:])
            return b"<<'PY_DATA_CONTRACTS'\n" + changed.encode() + b"\nPY_DATA_CONTRACTS\n"
        bad_sources = [tuple(sources[:-1]), (sources[0], *sources[:-1]), tuple("../escape" if i == 0 else name for i, name in enumerate(sources)),
                       tuple(name.replace("macos_installed_data_contracts.sh", "unrelated.sh") for name in sources)]
        malformed = [b"", raw + b"suffix", raw.replace(b"<<'PY_DATA_CONTRACTS'", b"<<'OTHER'"), b"x" * (128 * 1024 + 1),
                     raw.replace(b"\nPY_DATA_CONTRACTS\n", b"\nnames = []\nPY_DATA_CONTRACTS\n"),
                     *[altered("source_names", value) for value in bad_sources],
                     altered("names", list(reversed(tests))), altered("names", list(tests[:-1]))]
        for value in malformed:
            with self.subTest(selection_bytes=len(value)), self.assertRaises((helper.CheckFailure, ValueError, SyntaxError)):
                helper.mac_observer_data_selection(value)
        env = mac_environment()
        env.update(GITHUB_EVENT_NAME="workflow_dispatch", MRK_COMPILE_SELECTION="observer-data",
                   MRK_MACOS_COMPILE_MODE="observer-data", MRK_EXPECTED_SHA=env["GITHUB_SHA"])
        self.assertEqual(helper.mac_compile_mode(env, "aarch64-apple-darwin"), "observer-data")
        self.assertEqual([list(row) for row in helper.mac_compile_graphs("aarch64-apple-darwin", "observer-data")], bound["macCompile"]["graphs"])
        self.assertEqual(helper.mac_compile_checks("aarch64-apple-darwin", "observer-data")["compile"],
                         ("rust-version-target", "mac-cargo-version", "node-version", "typescript-no-emit", "vite-assets", "mac-observer-fixed-data"))
        for key, value in (("GITHUB_EVENT_NAME", "push"), ("MRK_COMPILE_SELECTION", "both"), ("MRK_MACOS_COMPILE_MODE", "observer-only"),
                           ("MRK_MACOS_TARGET", "x86_64-apple-darwin"), ("GITHUB_RUN_ID", "0"), ("GITHUB_RUN_ATTEMPT", "01")):
            with self.subTest(admission=key), self.assertRaises(helper.CheckFailure):
                helper.mac_compile_mode({**env, key: value}, "aarch64-apple-darwin")
        with self.assertRaises(helper.CheckFailure):
            helper.mac_compile_graphs("x86_64-apple-darwin", "observer-data")
        for key, value in (("GITHUB_REF", "refs/heads/main"), ("MRK_EXPECTED_SHA", "2" * 40), ("GITHUB_WORKFLOW_SHA", "2" * 40)):
            with self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding({**env, key: value}, helper.MAC_COMPILE_SCOPE)
        self.assertEqual(helper.mac_compile_graphs("aarch64-apple-darwin", "observer-only"), helper.MAC_COMPILE_GRAPHS[1:2])
        self.assertEqual(helper.mac_compile_checks("aarch64-apple-darwin", "observer-only")["compile"][-1], "mac-observer-compile-only")

    def test_observer_data_child_admission_and_containing_clock(self):
        _, body, bound, private = observer_data_fixture()
        functions = observer_data_child_functions(body)
        admission, seconds = functions["ci_data_admission"], functions["ci_data_seconds"]
        root = Path(bound["root"])
        binary = "/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin"
        env = {"MRK_MACOS_DATA_MODE": "ci-observer-data-v1", "MRK_MACOS_TARGET": "aarch64-apple-darwin",
               "MRK_DESKTOP_CI_ROOT": str(root), "GITHUB_WORKSPACE": bound["source"],
               "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": helper.MAC_COMPILE_REF,
               "GITHUB_WORKFLOW_REF": bound["workflowRef"], "GITHUB_SHA": bound["sourceSha"], "GITHUB_WORKFLOW_SHA": bound["workflowSha"],
               "GITHUB_RUN_ID": bound["runId"], "GITHUB_RUN_ATTEMPT": bound["attempt"], "MRK_EXPECTED_SHA": bound["sourceSha"],
               "RUSTC": binary + "/rustc", "RUSTUP_AUTO_INSTALL": "0", "CARGO_BUILD_JOBS": "1",
               "MRK_MACOS_INSTALL_SOURCE_COMMIT": bound["sourceSha"], "MRK_IMAGE_RELEASE_ID": bound["macCompile"]["release"],
               **{key: str(root / leaf) for key, leaf in (("HOME", "home"), ("CARGO_HOME", "cargo"), ("RUSTUP_HOME", "rustup"),
                                                          ("TMPDIR", "tmp"), ("CARGO_TARGET_DIR", "target"))}}
        context_raw = helper.canonical_json(bound)
        compiler = {**MAC_RUST_EXPECTED["aarch64-apple-darwin"], "cargo": binary + "/cargo", "rustc": binary + "/rustc"}
        root_identity = [1, 2, 0o40700, 1000, 1000, 1, 0, 3, 4]
        request = {"schemaVersion": 1, "admission": "ci-observer-data-v1", "contextSha256": helper.hashlib.sha256(context_raw).hexdigest(),
                   "rootIdentity": [1, 2, 1000], "compiler": compiler, "inventory": {"files": private["sourceRows"]},
                   "deadlineMonotonicNs": 101 * 1000000000}
        result = admission(helper.canonical_json(request), context_raw, env, root_identity, 1000000000)
        self.assertEqual(result[0]["source"], bound["sourceSha"])
        self.assertEqual(result[1], helper.canonical_json(request["inventory"]) + b"\n")
        self.assertEqual(result[2:], (compiler, request["deadlineMonotonicNs"], bound))
        for key, value in (("admission", "installed"), ("schemaVersion", True), ("contextSha256", "0" * 64),
                           ("rootIdentity", [1, 3, 1000]), ("compiler", {**compiler, "release": "1.98.0"}),
                           ("deadlineMonotonicNs", 1000000000), ("deadlineMonotonicNs", 1802 * 1000000000),
                           ("inventory", {"files": list(reversed(private["sourceRows"]))})):
            with self.subTest(request=key), self.assertRaises(ValueError):
                admission(helper.canonical_json({**request, key: value}), context_raw, env, root_identity, 1000000000)
        for key, value in (("MRK_MACOS_DATA_MODE", ""), ("GITHUB_EVENT_NAME", "push"), ("GITHUB_REF", "refs/heads/main"),
                           ("GITHUB_RUN_ATTEMPT", "3"), ("HOME", "/inert/foreign"), ("RUSTUP_AUTO_INSTALL", "1"),
                           ("RUSTC", "/usr/bin/rustc"), ("CARGO_TARGET_DIR", "/inert/target"), ("MRK_EXPECTED_SHA", "2" * 40)):
            with self.subTest(environment=key), self.assertRaises(ValueError):
                admission(helper.canonical_json(request), context_raw, {**env, key: value}, root_identity, 1000000000)
        for key, value in (("sourceTree", "bad"), ("workflowSha256", "bad"), ("runId", "0"), ("macCompile", {**bound["macCompile"], "execution": "compile-only"})):
            bad_context = helper.canonical_json({**bound, key: value})
            bad_request = {**request, "contextSha256": helper.hashlib.sha256(bad_context).hexdigest()}
            with self.subTest(context=key), self.assertRaises(ValueError):
                admission(helper.canonical_json(bad_request), bad_context, env, root_identity, 1000000000)
        for malformed in (b'{"schemaVersion":1,"schemaVersion":1}', b'{"bad":NaN}', b"[" * 33 + b"]" * 33, b"x" * 65537):
            with self.assertRaises(ValueError):
                admission(malformed, context_raw, env, root_identity, 1000000000)
        for cap in (15, 30, 120, 1440):
            self.assertEqual(seconds(cap, 2000 * 1000000000, 1000000000, 2000000000), cap)
            self.assertEqual(seconds(cap, 10 * 1000000000, 1000000000, 2500000000), 7)
        for args in ((16, 10, 1, 2), (True, 10, 1, 2), (15, 10, 3, 2), (15, 10, 1, 10), (15, 999999999, 0, 0)):
            with self.assertRaises(ValueError):
                seconds(*args)
        self.assertIn('ci_mode = os.environ.get("MRK_MACOS_DATA_MODE", "")', body)
        self.assertIn('if ci_mode not in ("", "ci-observer-data-v1"):', body)
        self.assertIn('root = Path(os.environ["MRK_MACOS_WORK"])', body)
        self.assertIn('rust_binding = None', body)

    def test_observer_data_result_keeps_original_prefix_and_cleanup_authority(self):
        _, body, bound, private = observer_data_fixture()
        complete = helper.mac_observer_data_result(private, bound, 0)
        self.assertIs(helper.validate_mac_observer_data_result(complete), complete)
        self.assertEqual([row["phase"] for row in complete["commands"]], ["mount", "apfs", "build", "rust", "python"])
        self.assertEqual(complete["pythonCounts"]["testsRun"], 84)
        for field in ("nativeVaultTestsExecuted", "uiExecutedByThisBatch", "nativeTlsQualified", "allWorkerFinalityEstablished"):
            self.assertIs(complete[field], False)
        written = []
        with patch.object(helper, "write_json", side_effect=lambda path, value: written.append(deepcopy(value))):
            helper.phase_receipt(bound, "compile", list(helper.MAC_OBSERVER_DATA_CHECKS["compile"]), node=helper.NODE, mac_observer_result=complete)
        self.assertEqual(len(written), 1)
        self.assertEqual(written[0]["scope"], "desktop-macos-observer-data-v1")
        helper.validate_compile_receipt(written[0], bound, "compile")
        with self.assertRaises(helper.CheckFailure):
            helper.validate_compile_receipt(written[0], mac_context(mode="observer-only"), "compile")
        self.assertIsNone(complete["guardCode"])
        self.assertIsNone(complete["pythonFailure"])
        for change in (lambda x: x.update(guardCode="unclassified"), lambda x: x.update(pythonFailure={}),
                       lambda x: x.update(wrapperReturnCode=1), lambda x: x["commands"][3].update(returnCode=101),
                       lambda x: x["commands"][3].update(captureClosed=False), lambda x: x["commands"][3].update(outputOverflow=True),
                       lambda x: x["commands"].pop(), lambda x: x["artifact"].update(unchangedAfterRun=False),
                       lambda x: x["artifact"].update(originalClosed=False), lambda x: x["pythonCounts"].update(testsRun=83),
                       lambda x: x["pythonCounts"].update(skipped=1), lambda x: x.update(sourcePost=None),
                       lambda x: x.update(temporaryEmpty=False), lambda x: x.update(allWorkerFinalityEstablished=True),
                       lambda x: x.update(extra="not admitted")):
            bad = deepcopy(written[0]); change(bad["dataResult"])
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_receipt(bad, bound, "compile")
        prefix = deepcopy(private)
        prefix.update(commands=prefix["commands"][:4], pythonCounts=None, ciAggregatePassed=None, ciSourcePost=None,
                      ciTemporaryEmpty=None, passed=False, failure="private inert failure text")
        prefix["commands"][-1]["returnCode"] = 101
        site = {"source": "desktop/src-tauri/tests/installed_shell_observation.rs", "line": 17, "column": 9}
        self.assertIn(site["source"], [row["path"] for row in private["sourceRows"]])
        failure = {"schemaVersion": 1, "kind": "mrk-native-data-contract-failure-diagnostics-v1", "phase": "rust",
                   "originalReturncode": 101, **{key: prefix["commands"][-1][key] for key in ("originalReturned", "outputComplete", "captureClosed", "timedOut", "outputOverflow")},
                   "diagnosticOnly": True, "productReady": False, "source": bound["sourceSha"], "workflowSource": bound["workflowSha"],
                   "runId": bound["runId"], "runAttempt": bound["attempt"], "target": "aarch64-apple-darwin", "rustPanic": site,
                   "guardCode": "command-not-complete", "python": None}
        observed = helper.mac_observer_data_result(prefix, bound, 1, failure=failure)
        self.assertEqual((observed["wrapperReturnCode"], observed["commands"][-1]["returnCode"]), (1, 101))
        self.assertEqual(observed["rustPanic"], site)
        self.assertEqual(observed["guardCode"], "command-not-complete")
        self.assertIsNone(observed["pythonFailure"])
        self.assertTrue(all(observed[key] is None for key in ("pythonCounts", "aggregatePassed", "sourcePost", "temporaryEmpty")))
        self.assertNotIn("private inert failure text", json.dumps(observed))
        with self.assertRaises(helper.CheckFailure):
            helper.validate_mac_observer_data_result(observed)
        # Execute only the genuine fixed pure reducers, never the native body.
        parsed = helper.ast.parse(body)
        wanted = {"DATA_FAILURE_GUARDS", "data_failure_json", "data_failure_python", "data_failure_cargo",
                  "data_failure_rust_panic", "data_failure_rust_panic_diagnostic", "data_failure_document"}
        nodes, found = [], set()
        for node in parsed.body:
            name = node.name if isinstance(node, helper.ast.FunctionDef) else (
                node.targets[0].id if isinstance(node, helper.ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], helper.ast.Name) else None)
            if name in wanted:
                nodes.append(node); found.add(name)
        self.assertEqual(found, wanted)
        namespace = {"json": json, "hashlib": helper.hashlib, "re": helper.re}
        exec(compile(helper.ast.Module(body=nodes, type_ignores=[]), "<genuine-observer-failure-data>", "exec"), namespace)
        context = {"source": bound["sourceSha"], "workflowSource": bound["workflowSha"],
                   "runId": bound["runId"], "runAttempt": bound["attempt"], "target": "aarch64-apple-darwin"}
        sources = {row["path"] for row in private["sourceRows"]}
        spelling = "tests/../src/installation.rs"
        self.assertNotIn("desktop/src-tauri/src/installation.rs", sources)
        opaque_result = None
        for raw, state in ((b"\nthread 'main' (42) panicked at tests/../src/installation.rs:4271:9:\nPRIVATE_PANIC_PAYLOAD\n", "unmapped-source"),
                           (b"thread 'main' panicked at tests/installed_shell_observation.rs:17:9:\nPRIVATE_PANIC_PAYLOAD\n", "observed"),
                           (b"PRIVATE_PANIC_PAYLOAD without a header\n", "header-missing")):
            genuine = json.loads(namespace["data_failure_document"](prefix["commands"][-1],
                {"stdout": b"", "stderr": raw}, "command-not-complete", context, private["pythonTestIds"], sources, bound["source"]))
            copied = helper.mac_observer_data_result(prefix, bound, 1, failure=genuine)
            self.assertEqual(copied["rustPanicDiagnostic"]["parseState"], state)
            self.assertEqual(copied["rustPanicDiagnostic"], genuine["rustPanicDiagnostic"])
            self.assertEqual((copied["wrapperReturnCode"], copied["commands"][-1]["returnCode"]), (1, 101))
            self.assertNotIn("PRIVATE_PANIC_PAYLOAD", json.dumps(copied))
            if state == "unmapped-source":
                opaque_result = copied
                self.assertIsNone(copied["rustPanic"])
                self.assertEqual(copied["rustPanicDiagnostic"], {"parseState": state,
                    "spellingSha256": helper.hashlib.sha256(spelling.encode("ascii")).hexdigest(), "line": 4271, "column": 9})
                self.assertNotIn(spelling, json.dumps(copied))
            elif state == "observed":
                self.assertEqual(copied["rustPanic"], site)
            else:
                self.assertIsNone(copied["rustPanic"])
                self.assertTrue(all(copied["rustPanicDiagnostic"][key] is None for key in ("spellingSha256", "line", "column")))
            with self.assertRaises(helper.CheckFailure):
                helper.validate_mac_observer_data_result(copied)
        opaque = opaque_result["rustPanicDiagnostic"]
        unverified = {**failure, "rustPanic": None, "rustPanicDiagnostic": opaque}
        self.assertIs(helper.validate_mac_observer_data_result({**complete, "rustPanicDiagnostic": None})["rustPanicDiagnostic"], None)
        self.assertIsNone(helper.mac_observer_data_result(prefix, bound, 1, failure={**unverified, "rustPanicDiagnostic": None}).get("rustPanicDiagnostic"))
        for state in ("input-invalid", "empty", "bounds", "header-missing", "header-multiple", "header-format", "coordinate-range"):
            empty = {"parseState": state, "spellingSha256": None, "line": None, "column": None}
            self.assertEqual(helper.mac_observer_data_result(prefix, bound, 1, failure={**unverified, "rustPanicDiagnostic": empty})["rustPanicDiagnostic"], empty)
        for change in (lambda x: x.update(parseState="raw arbitrary prose"), lambda x: x.update(parseState=[]),
                       lambda x: x.update(spellingSha256="F" * 64), lambda x: x.update(spellingSha256=True),
                       lambda x: x.update(line=True), lambda x: x.update(line=0), lambda x: x.update(column=1000001),
                       lambda x: x.update(raw="PRIVATE_PANIC_PAYLOAD"), lambda x: x.pop("column"),
                       lambda x: x.update(parseState="header-format"), lambda x: x.update(parseState="observed")):
            bad = deepcopy(opaque); change(bad)
            with self.assertRaises(helper.CheckFailure):
                helper.mac_observer_data_result(prefix, bound, 1, failure={**unverified, "rustPanicDiagnostic": bad})
        for bad in ([], "PRIVATE_PANIC_PAYLOAD", False):
            with self.assertRaises(helper.CheckFailure):
                helper.mac_observer_data_result(prefix, bound, 1, failure={**unverified, "rustPanicDiagnostic": bad})
        self.assertEqual(helper.mac_observer_data_result(prefix, bound, 1, failure={**unverified,
            "rustPanicDiagnostic": {**opaque, "spellingSha256": "0" * 64}})["rustPanicDiagnostic"]["spellingSha256"], "0" * 64)
        for diagnostic in (opaque, {**opaque, "parseState": "observed"}):
            with self.assertRaises(helper.CheckFailure):
                helper.mac_observer_data_result(prefix, bound, 1, failure={**failure, "rustPanicDiagnostic": diagnostic})
        for key, bad in (("originalReturned", False), ("outputComplete", False), ("captureClosed", False),
                         ("timedOut", True), ("outputOverflow", True), ("returnCode", 1)):
            changed = deepcopy(prefix); changed["commands"][-1][key] = bad
            sidecar = {**unverified, "originalReturncode" if key == "returnCode" else key: bad}
            with self.assertRaises(helper.CheckFailure):
                helper.mac_observer_data_result(changed, bound, 1, failure=sidecar)
        with self.assertRaises(helper.CheckFailure):
            helper.validate_mac_observer_data_result({**complete, "rustPanicDiagnostic": opaque})
        for field, value in (("source", "2" * 40), ("phase", "build"), ("captureClosed", False),
                             ("rustPanic", {**site, "source": "desktop/src-tauri/src/not-in-inventory.rs"}),
                             ("rustPanic", {**site, "line": True}), ("rustPanic", {**site, "column": 1000001}),
                             ("rustPanic", {**site, "raw": "never exported"})):
            with self.assertRaises(helper.CheckFailure):
                helper.mac_observer_data_result(prefix, bound, 1, failure={**failure, field: value})
        for change in (lambda x: x.update(sourceCommit="2" * 40), lambda x: x["ciContext"].update(attempt="3"),
                       lambda x: x["sourceRows"][0].update(sha256="6" * 64), lambda x: x["pythonTestIds"].reverse(),
                       lambda x: x["commands"][0].update(phase="rust"), lambda x: x["commands"][0].update(returnCode=True),
                       lambda x: x["pythonCounts"].update(actualHostBeforeAndAfter=False), lambda x: x.update(passed=False)):
            bad = deepcopy(private); change(bad)
            with self.assertRaises(helper.CheckFailure):
                helper.mac_observer_data_result(bad, bound, 0)
        python_private = deepcopy(private)
        python_private.update(pythonCounts=None, ciAggregatePassed=True, ciSourcePost=None, ciTemporaryEmpty=None,
                              passed=False, failure="private Python assertion prose")
        python_private["commands"][-1]["returnCode"] = 1
        # Use the16 longest actual84 identifiers, retained in fixed roster order.
        longest = set(sorted(private["pythonTestIds"], key=len, reverse=True)[:16])
        rows = [{"kind": "failure", "id": name} for name in private["pythonTestIds"] if name in longest]
        python = {"testsRun": 84, "failures": 65535, "errors": 65535, "skipped": 65535,
                  "expectedFailures": 65535, "unexpectedSuccesses": 65535, "actualHostBeforeAndAfter": True,
                  "failureTests": rows, "classifiedTestCount": 168, "omittedTestCount": 152, "unclassifiedTestCount": 65535}
        supplement = {**failure, "phase": "python", "originalReturncode": 1, "rustPanic": None, "python": python}
        python_result = helper.mac_observer_data_result(python_private, bound, 1, failure=supplement)
        self.assertEqual(python_result["pythonFailure"], python)
        self.assertEqual(len(python_result["pythonFailure"]["failureTests"]), 16)
        self.assertNotIn("private Python assertion prose", json.dumps(python_result))
        self.assertIsNone(python_result["rustPanic"])
        self.assertEqual(python_result["commands"][-1]["returnCode"], 1)
        for change in (lambda x: x.update(guardCode="arbitrary raw prose"), lambda x: x.update(phase="rust"),
                       lambda x: x.update(originalReturncode=101), lambda x: x.update(captureClosed=False),
                       lambda x: x["python"].update(extra="raw"), lambda x: x["python"].update(testsRun=85),
                       lambda x: x["python"].update(classifiedTestCount=167), lambda x: x["python"].update(omittedTestCount=153),
                       lambda x: x["python"].update(unclassifiedTestCount=65536),
                       lambda x: x["python"]["failureTests"].reverse(), lambda x: x["python"]["failureTests"].append(rows[0]),
                       lambda x: x["python"]["failureTests"][0].update(id="unselected.test"),
                       lambda x: x["python"]["failureTests"][0].update(kind="skipped")):
            bad = deepcopy(supplement); change(bad)
            with self.assertRaises(helper.CheckFailure):
                helper.mac_observer_data_result(python_private, bound, 1, failure=bad)
        # A conservative serialized-budget fixture, not SOURCE/native authority:
        #13 compiler rows at their maximum path/size spelling plus dense16IDs.
        dense_mac = deepcopy(bound["macCompile"])
        dense_mac["sources"] = [{"path": str(i) + "/" + "p" * 237, "size": 1048576, "sha256": "f" * 64} for i in range(13)]
        dense = {"schemaVersion": 1, "scope": "desktop-macos-observer-data-v1", "phase": "compile",
                 "status": "failed-or-unknown", "lastFixedStage": "mac-observer-fixed-data", "originalCommandReturnCode": 1,
                 "dataResult": python_result, "macCompile": dense_mac,
                 **{key: bound[key] for key in ("sourceSha", "sourceTree", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt")}}
        self.assertLessEqual(len(helper.canonical_json(dense)) + 1, 16384)
        dense["dataResult"] = opaque_result  # Real Rust-only shape; not a combined Python/Rust claim.
        self.assertLessEqual(len(helper.canonical_json(dense)) + 1, 16384)
        self.assertEqual(dense["dataResult"]["commands"][-1]["returnCode"], 101)
        with self.assertRaises(helper.CheckFailure):
            helper.validate_mac_observer_data_result(python_result)
        forged = helper.mac_observer_data_result(private, bound, 1)
        self.assertEqual(forged["wrapperReturnCode"], 1)
        with self.assertRaises(helper.CheckFailure):
            helper.validate_mac_observer_data_result(forged)
        unknown = deepcopy(prefix)
        unknown["commands"][-1].update(returnCode=None, originalReturned=None, captureClosed=None)
        self.assertIsNone(helper.mac_observer_data_result(unknown, bound, 1)["commands"][-1]["returnCode"])

    def test_observer_data_parent_preserves_first_return_and_source_post(self):
        _, body, original, private_original = observer_data_fixture()
        binary = "/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin"
        for fault in ("none", "rust101", "opaque", "opaque-malformed", "unknown", "private-malformed", "source-post", "reserve", "publication"):
            with self.subTest(fault=fault), helper.tempfile.TemporaryDirectory() as directory:
                root = Path(directory); root.chmod(0o700)
                root_stat = root.lstat()
                if fault == "none":
                    # Only an inert Path port: no native path is opened. Feed
                    # the real parent's request/env into the real child reducer.
                    class OriginalRoot(type(root)):
                        def lstat(self):
                            return root_stat
                    root = OriginalRoot(original["root"])
                bound = deepcopy(original); bound["root"] = str(root)
                private = deepcopy(private_original)
                if fault in ("rust101", "opaque", "opaque-malformed", "publication"):
                    private.update(commands=private["commands"][:4], pythonCounts=None, ciAggregatePassed=None,
                                   ciSourcePost=None, ciTemporaryEmpty=None, passed=False, failure="private")
                    private["commands"][-1]["returnCode"] = 101
                context_raw = helper.canonical_json(bound)
                selected = bound["macCompile"]["data"]
                input_calls, reads, runs, writes, caps = [], [], [], [], []
                primary = helper.CheckFailure("original child failed")
                if fault in ("rust101", "opaque", "opaque-malformed", "publication"):
                    primary._returned_command = ("mac-observer-fixed-data", 1)
                def inputs(source):
                    input_calls.append(str(source))
                    changed = {**selected, "scriptSha256": "0" * 64} if fault == "source-post" and len(input_calls) == 2 else selected
                    return changed, body.encode(), private["sourceRows"], tuple(private["pythonTestIds"])
                def read(path, limit, **kw):
                    reads.append((str(path), limit, kw))
                    if path.name == "context.json": return context_raw
                    if path.name == "result.json": return b"{}" if fault == "private-malformed" else helper.canonical_json(private)
                    if path.name == "failure-diagnostics.json" and fault in ("opaque", "opaque-malformed"):
                        diagnostic = {"parseState": "unmapped-source", "spellingSha256": "a" * 64, "line": 17, "column": 9}
                        if fault == "opaque-malformed": diagnostic["spellingSha256"] = "PRIVATE_INVALID_DIAGNOSTIC"
                        return helper.canonical_json({"schemaVersion": 1, "kind": "mrk-native-data-contract-failure-diagnostics-v1",
                            "phase": "rust", "originalReturncode": 101, "source": bound["sourceSha"], "workflowSource": bound["workflowSha"],
                            "runId": bound["runId"], "runAttempt": bound["attempt"], "target": "aarch64-apple-darwin",
                            **{key: private["commands"][-1][key] for key in ("originalReturned", "outputComplete", "captureClosed", "timedOut", "outputOverflow")},
                            "diagnosticOnly": True, "productReady": False, "guardCode": "command-not-complete", "python": None,
                            "rustPanic": None, "rustPanicDiagnostic": diagnostic})
                    raise OSError("optional sidecar absent")
                def invoke(argv, **kw):
                    runs.append((argv, kw))
                    if fault in ("rust101", "opaque", "opaque-malformed", "unknown", "publication"): raise primary
                    return ""
                def publish(path, value):
                    if fault == "publication" and path.name == "compile-checks.json": raise KeyboardInterrupt()
                    writes.append((path.name, deepcopy(value)))
                def remaining(cap):
                    caps.append(cap)
                    return 30 if fault == "reserve" else min(cap, 80)
                with patch.object(helper, "mac_observer_data_inputs", side_effect=inputs), \
                        patch.object(helper, "mac_observer_data_read", side_effect=read), \
                        patch.object(helper, "run", side_effect=invoke), patch.object(helper, "write_json", side_effect=publish), \
                        patch.object(helper.time, "monotonic_ns", return_value=1000000000), \
                        patch.dict(helper.os.environ, {"PATH": "/inert/bin", "UNEXPECTED_SECRET": "inert forbidden value"}, clear=True):
                    if fault == "none":
                        result = helper.mac_observer_data_checks(binary + "/cargo", root, Path(bound["source"]),
                            {"RUSTC": binary + "/rustc", "RUSTUP_AUTO_INSTALL": "0", "UNEXPECTED_SECRET": "inert forbidden value"}, remaining, bound)
                        self.assertEqual(result["wrapperReturnCode"], 0)
                    else:
                        with self.assertRaises(helper.CheckFailure) as caught:
                            helper.mac_observer_data_checks(binary + "/cargo", root, Path(bound["source"]),
                                {"RUSTC": binary + "/rustc", "RUSTUP_AUTO_INSTALL": "0"}, remaining, bound)
                        if fault in ("rust101", "opaque", "opaque-malformed", "unknown", "publication"): self.assertIs(caught.exception, primary)
                self.assertEqual(len(runs), 0 if fault == "reserve" else 1)
                if runs:
                    argv, kw = runs[0]
                    self.assertEqual(argv, [helper.sys.executable, "-I", "-S", "-B", "-c", body])
                    self.assertEqual((kw["check"], kw["cwd"], kw["timeout"]), ("mac-observer-fixed-data", root, 80))
                    self.assertEqual((kw["output"], kw["diagnostics"]), (helper.subprocess.DEVNULL, helper.subprocess.DEVNULL))
                    self.assertNotIn("UNEXPECTED_SECRET", kw["env"])
                    self.assertEqual(kw["env"]["MRK_MACOS_DATA_MODE"], "ci-observer-data-v1")
                    self.assertEqual(kw["env"]["CARGO_TARGET_DIR"], str(root / "target"))
                    self.assertEqual(kw["env"]["HOME"], str(root / "home"))
                    request = next(value for name, value in writes if name == "observer-data-request.json")
                    self.assertEqual(request["deadlineMonotonicNs"], 51 * 1000000000)
                    self.assertEqual(request["contextSha256"], helper.hashlib.sha256(context_raw).hexdigest())
                    self.assertEqual(request["compiler"], {**MAC_RUST_EXPECTED["aarch64-apple-darwin"], "cargo": binary + "/cargo", "rustc": binary + "/rustc"})
                    if fault == "none":
                        original_identity = [root_stat.st_dev, root_stat.st_ino, root_stat.st_mode, root_stat.st_uid,
                                             root_stat.st_gid, root_stat.st_nlink, root_stat.st_size, root_stat.st_mtime_ns, root_stat.st_ctime_ns]
                        admitted = observer_data_child_functions(body)["ci_data_admission"](
                            helper.canonical_json(request), context_raw, kw["env"], original_identity, 1000000000)
                        self.assertEqual(admitted[2], request["compiler"])
                        self.assertEqual(admitted[3], request["deadlineMonotonicNs"])
                        self.assertEqual(admitted[4], bound)
                if fault == "unknown":
                    self.assertEqual([Path(path).name for path, _, _ in reads], ["context.json"])
                self.assertEqual(len(input_calls), 2 if fault in ("none", "source-post") else 1)
                failures = [value for name, value in writes if name == "compile-checks.json"]
                if fault not in ("none", "publication"):
                    self.assertEqual(len(failures), 1)
                    failed = failures[0]
                    self.assertEqual(failed["status"], "failed-or-unknown")
                    self.assertLessEqual(len(helper.canonical_json(failed)) + 1, 16384)
                    self.assertEqual(failed["originalCommandReturnCode"], 1 if fault in ("rust101", "opaque", "opaque-malformed") else None if fault in ("unknown", "reserve") else 0)
                    if fault in ("rust101", "opaque", "opaque-malformed"):
                        self.assertEqual(failed["dataResult"]["commands"][-1]["returnCode"], 101)
                        self.assertIsNone(failed["dataResult"]["sourcePost"])
                        self.assertNotIn("PRIVATE_INVALID_DIAGNOSTIC", json.dumps(failed))
                        if fault == "opaque":
                            self.assertEqual(failed["dataResult"]["rustPanicDiagnostic"]["parseState"], "unmapped-source")
                        else:
                            self.assertIsNone(failed["dataResult"].get("rustPanicDiagnostic"))
                    if fault in ("unknown", "private-malformed", "reserve"):
                        self.assertIsNone(failed["dataResult"])
                else:
                    self.assertEqual(failures, [])

    def test_observer_data_phase_routes_one_full_five_original(self):
        _, _, bound, private = observer_data_fixture()
        result = helper.mac_observer_data_result(private, bound, 0)
        binary = "/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin"
        for phase, failed in (("acquire", False), ("compile", False), ("compile", True)):
            events, calls, writes, children = [], [], [], []
            MemoryPath, _ = memory_paths(events)
            primary = helper.CheckFailure("original fixed DATA wrapper failed")
            def invoke(argv, **kw):
                calls.append((list(map(str, argv)), kw))
                return helper.NODE if kw["check"] == "node-version" else ""
            def child(cargo, root, source, env, remaining, context):
                children.append((cargo, root, source, dict(env), remaining(1680), deepcopy(context)))
                self.assertEqual([kw["check"] for _, kw in calls], ["node-version", "typescript-no-emit", "vite-assets"])
                if failed: raise primary
                return deepcopy(result)
            with patch.object(helper, "Path", MemoryPath), patch.object(helper, "source_unchanged"), \
                    patch.object(helper, "mac_compile_source_guard"), patch.object(helper, "mac_compile_inputs", return_value=bound["macCompile"]), \
                    patch.object(helper, "tools", return_value=(binary + "/cargo", None)), patch.object(helper, "ordinary"), \
                    patch.object(helper.shutil, "which", return_value="/selected/bin/node"), patch.object(helper.time, "monotonic", return_value=100.0), \
                    patch.object(helper, "run", side_effect=invoke), patch.object(helper, "mac_observer_data_checks", side_effect=child), \
                    patch.object(helper, "mac_observer_compile", side_effect=AssertionError("duplicate compiler forbidden")), \
                    patch.object(helper, "write_json", side_effect=lambda path, value: writes.append(deepcopy(value))), \
                    patch.dict(helper.os.environ, {"PATH": "/inert/bin"}, clear=True):
                if failed:
                    with self.assertRaises(helper.CheckFailure) as caught:
                        helper.phase_mac_compile(phase, bound)
                    self.assertIs(caught.exception, primary)
                else:
                    helper.phase_mac_compile(phase, bound)
            self.assertEqual(len(children), 0 if phase == "acquire" else 1)
            self.assertEqual([kw["check"] for _, kw in calls],
                             ["mac-normal-locked-metadata", "node-version", "npm-locked-no-scripts"] if phase == "acquire" else
                             ["node-version", "typescript-no-emit", "vite-assets"])
            if phase == "acquire":
                self.assertEqual(calls[0][0][calls[0][0].index("--features") + 1], "desktop-shell,custom-protocol,macos-installed-observation")
                self.assertIn("--ignore-scripts", calls[-1][0])
            else:
                self.assertEqual(children[0][4], 1680)
            if failed:
                self.assertEqual(writes, [])
            else:
                self.assertEqual(len(writes), 1)
                helper.validate_compile_receipt(writes[0], bound, phase)
                self.assertEqual(writes[0]["scope"], "desktop-macos-observer-data-v1")
                self.assertEqual("dataResult" in writes[0], phase == "compile")

    def test_observer_data_original_reads_are_bounded_and_closed(self):
        raw, body, bound, private = observer_data_fixture()
        # All78 names are the genuine SOURCE tuple, but these tiny fixture bytes
        # are inert. Exercise the real inventory/selector join, not a stub.
        with helper.tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for row in private["sourceRows"]:
                path = root / row["path"]; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw if row["path"] == helper.MAC_OBSERVER_DATA_SCRIPT else b"x")
                path.chmod(0o600)
            selected, actual_body, rows, tests = helper.mac_observer_data_inputs(root)
            self.assertEqual(selected, {**bound["macCompile"]["data"],
                "sourceInventorySha256": helper.hashlib.sha256(helper.canonical_json({"files": rows}) + b"\n").hexdigest()})
            self.assertEqual(actual_body, body.encode())
            self.assertEqual(tests, tuple(private["pythonTestIds"]))
            self.assertEqual([row["path"] for row in rows], [row["path"] for row in private["sourceRows"]])
            changed = root / next(row["path"] for row in rows if row["path"] != helper.MAC_OBSERVER_DATA_SCRIPT)
            changed.write_bytes(b"xx")
            self.assertNotEqual(helper.mac_observer_data_inputs(root)[0]["sourceInventorySha256"], selected["sourceInventorySha256"])
            changed.unlink()
            with self.assertRaises((helper.CheckFailure, OSError)):
                helper.mac_observer_data_inputs(root)
        with helper.tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "source"; source.write_bytes(b"original")
            source.chmod(0o600)
            self.assertEqual(helper.mac_observer_data_read(source, 16384, private=True), b"original")
            self.assertEqual(helper.mac_observer_data_read(source, 128 * 1024), b"original")
            real_close, real_pread = helper.os.close, helper.os.pread
            # Exercise both64KiB chunks and the EOF probe on the same original
            # descriptor, without a second path open or an unbounded pass.
            stable = b"s" * 65537
            source.write_bytes(stable)
            with patch.object(helper.os, "pread", wraps=real_pread) as reread:
                self.assertEqual(helper.mac_observer_data_read(source, 128 * 1024, private=True), stable)
            self.assertEqual([(call.args[1], call.args[2]) for call in reread.call_args_list],
                             [(65536, 0), (1, 65536), (1, 65537)])
            self.assertEqual(len({call.args[0] for call in reread.call_args_list}), 1)
            for fault in ("mode", "empty", "bound", "link", "hardlink", "early", "changed",
                          "same-metadata", "pread-error", "pread-early", "pread-extra"):
                source.write_bytes(b"original"); source.chmod(0o600)
                selected = source
                with contextlib.ExitStack() as stack:
                    closed = stack.enter_context(patch.object(helper.os, "close", wraps=real_close))
                    if fault == "mode": source.chmod(0o644)
                    if fault == "empty": source.write_bytes(b"")
                    if fault == "bound": source.write_bytes(b"x" * 16385)
                    if fault == "link":
                        selected = root / "link"; selected.symlink_to(source)
                    if fault == "hardlink": helper.os.link(source, root / "hardlink")
                    if fault == "early": stack.enter_context(patch.object(helper.os, "read", return_value=b""))
                    if fault == "changed":
                        real_read = helper.os.read
                        def changing(fd, size):
                            value = real_read(fd, size)
                            source.write_bytes(b"changed!")
                            return value
                        stack.enter_context(patch.object(helper.os, "read", side_effect=changing))
                    if fault == "same-metadata":
                        # Deterministic coarse-timestamp port: every other
                        # identity field is genuine, only the two time fields
                        # retain their original values during the real rewrite.
                        identity = helper.source_slots_identity
                        before = identity(source.stat())
                        stack.enter_context(patch.object(helper, "source_slots_identity",
                            side_effect=lambda info: identity(info)[:7] + before[7:]))
                        real_read = helper.os.read
                        def same_tick(fd, size):
                            value = real_read(fd, size)
                            source.write_bytes(b"changed!")
                            self.assertEqual(helper.source_slots_identity(source.stat()), before)
                            return value
                        stack.enter_context(patch.object(helper.os, "read", side_effect=same_tick))
                    if fault == "pread-error":
                        stack.enter_context(patch.object(helper.os, "pread", side_effect=OSError("inert second-pass error")))
                    if fault == "pread-early":
                        stack.enter_context(patch.object(helper.os, "pread", return_value=b""))
                    if fault == "pread-extra":
                        stack.enter_context(patch.object(helper.os, "pread",
                            side_effect=lambda fd, size, offset: b"x" if offset == 8 else real_pread(fd, size, offset)))
                    with self.subTest(read=fault), self.assertRaises((helper.CheckFailure, OSError)) as refused:
                        helper.mac_observer_data_read(selected, 16384, private=True)
                    if fault == "same-metadata":
                        self.assertIn("original input bytes changed", str(refused.exception))
                    self.assertEqual(closed.call_count, 0 if fault == "link" else 1)
                if fault == "hardlink": (root / "hardlink").unlink()
            with self.assertRaises(helper.CheckFailure):
                helper.mac_observer_data_read(source, 65536)

    def test_compile_scope_refuses_every_native_phase_before_context_or_tools(self):
        with patch.object(helper, "load_context", side_effect=AssertionError("context must not be opened")), \
                patch.object(helper, "tools", side_effect=AssertionError("no tool may be selected")):
            for phase in ("native", "config-owner", "config-task-loss", "config-owner-delta",
                          "config-transaction-eof", "config-core", "windows-snapshot", "unexpected"):
                with self.subTest(phase=phase), self.assertRaises(helper.CheckFailure):
                    helper.phase(phase, "linux", helper.COMPILE_SCOPE)
        for phase in helper.COMPILE_PHASES:
            helper.admit_phase(helper.COMPILE_SCOPE, phase)
        helper.admit_phase(helper.BOUNDARY_SCOPE, "native")  # No native call.
        with self.assertRaises(helper.CheckFailure):
            helper.admit_phase("unknown", "compile")

        with patch.object(helper, "load_context", side_effect=AssertionError("no source IO")):
            for phase in ("native", "windows-snapshot", "environment-native", "workflow-owner", "unknown"):
                with self.subTest(phase=phase), self.assertRaises(helper.CheckFailure):
                    helper.phase(phase, "macos", helper.MAC_COMPILE_SCOPE)
            for platform in ("linux", "windows", "unknown"):
                for phase in helper.COMPILE_PHASES:
                    with self.subTest(platform=platform, phase=phase), self.assertRaises(helper.CheckFailure):
                        helper.phase(phase, platform, helper.MAC_COMPILE_SCOPE)
        for target in helper.MAC_COMPILE_HOSTS:
            env = mac_environment(target)
            self.assertEqual(helper.mac_compile_target(env), target)
            for key, bad in (("MRK_MACOS_TARGET", "foreign"), ("RUNNER_ARCH", "other"),
                             ("RUNNER_OS", "Linux"), ("ImageOS", "macos15")):
                with self.subTest(target=target, key=key), self.assertRaises(helper.CheckFailure):
                    helper.mac_compile_target({**env, key: bad})
        self.assertEqual(helper.RUST, "1.98.0")
        self.assertEqual(helper.TARGETS["macos"], "aarch64-apple-darwin")

        # The new lane compiles one real main binary; it cannot invoke any UI,
        # native fixture, installed, or writer phase through this compiler API.
        with patch.object(helper, "load_context", side_effect=AssertionError("no context IO")), \
                patch.object(helper, "tools", side_effect=AssertionError("no compiler selection")):
            for phase in ("native", "engineering-main-test", "windows-snapshot", "workflow-owner", "config-owner", "unknown"):
                with self.subTest(engineering_phase=phase), self.assertRaises(helper.CheckFailure):
                    helper.phase(phase, "macos", helper.ENGINEERING_COMPILE_SCOPE)
            for platform in ("linux", "windows", "unknown"):
                for phase in helper.COMPILE_PHASES:
                    with self.subTest(engineering_platform=platform, phase=phase), self.assertRaises(helper.CheckFailure):
                        helper.phase(phase, platform, helper.ENGINEERING_COMPILE_SCOPE)
        for phase in helper.COMPILE_PHASES:
            helper.admit_phase(helper.ENGINEERING_COMPILE_SCOPE, phase)
        self.assertEqual(helper.ENGINEERING_COMPILE_FEATURES, "desktop-shell,custom-protocol,development-runtime")
        self.assertEqual(helper.ENGINEERING_APP_IDENTIFIER, "dev.mobile-release-kit.engineering-ui")
        self.assertEqual(helper.ENGINEERING_COMPILE_TARGET, "aarch64-apple-darwin")
        self.assertEqual(helper.compiler_binding(engineering_context()), MAC_RUST_EXPECTED["aarch64-apple-darwin"])
        with self.assertRaises(helper.CheckFailure):
            helper.compiler_binding({**engineering_context(), "platform": "linux"})

        # This distinct native DATA profile still cannot dispatch a native
        # product/fixture phase or borrow another host's feature graph.
        with patch.object(helper, "load_context", side_effect=AssertionError("no context IO")), \
                patch.object(helper, "tools", side_effect=AssertionError("no tool selection")):
            for phase in ("native", "workflow-owner", "config-core", "windows-snapshot", "engineering-main-test", "unexpected"):
                with self.subTest(source_slots_phase=phase), self.assertRaises(helper.CheckFailure):
                    helper.phase(phase, "macos", helper.SOURCE_SLOTS_SCOPE)
            for platform in ("linux", "windows", "unknown"):
                for phase in helper.COMPILE_PHASES:
                    with self.subTest(source_slots_platform=platform, phase=phase), self.assertRaises(helper.CheckFailure):
                        helper.phase(phase, platform, helper.SOURCE_SLOTS_SCOPE)
        for phase in ("prepare", "acquire", "compile", "clean"):
            helper.admit_phase(helper.SOURCE_SLOTS_SCOPE, phase)
        self.assertEqual(helper.SOURCE_SLOTS_TEST, SOURCE_SLOTS_CASE)
        self.assertEqual(helper.source_slots_selection(), source_slots_context()["sourceSlots"])
        self.assertEqual(helper.compiler_binding(source_slots_context()), MAC_RUST_EXPECTED["x86_64-apple-darwin"])
        for bad in ({**source_slots_context(), "platform": "linux"},
                    {**source_slots_context(), "executionScope": helper.MAC_COMPILE_SCOPE}):
            with self.assertRaises(helper.CheckFailure):
                helper.phase_source_slots("compile", bad)
        changed = source_slots_context()
        changed["sourceSlots"]["features"] = ["registration-helper"]
        with self.assertRaises(helper.CheckFailure):
            helper.phase_source_slots("compile", changed)

        # B is a closed second compiler/DATA selection, not a new native entry.
        b = intel_removal_context()
        self.assertEqual(helper.source_slots_selection(True), b["sourceSlots"])
        self.assertTrue(helper.source_slots_is_removal(b))
        self.assertFalse(helper.source_slots_is_removal(source_slots_context()))
        self.assertEqual(helper.compiler_binding(b), MAC_RUST_EXPECTED["x86_64-apple-darwin"])
        for value in (None, 0, 1, "removal-abrupt", [], {}):
            with self.assertRaises(helper.CheckFailure):
                helper.source_slots_selection(value)
        with patch.object(helper, "tools", side_effect=AssertionError("no tool")), \
                patch.object(helper, "source_unchanged", side_effect=AssertionError("no source IO")):
            for key, value in (("features", ["macos-installed-removal-abrupt-fixture", "development-runtime"]),
                               ("binary", "mobile-release-kit-desktop"), ("tests", INTEL_REMOVAL_CASES[:2]),
                               ("target", "aarch64-apple-darwin"), ("testTarget", "lib")):
                bad = deepcopy(b); bad["sourceSlots"][key] = value
                with self.subTest(b_selector=key), self.assertRaises(helper.CheckFailure):
                    helper.phase_source_slots("compile", bad)
            for value in (helper.MAC_COMPILE_SCOPE, "native", "fixture"):
                with self.assertRaises(helper.CheckFailure):
                    helper.phase_source_slots(value, b)
            for bad in ({**b, "workflowRef": source_slots_context()["workflowRef"]},
                        {**source_slots_context(), "sourceSlots": b["sourceSlots"]}):
                with self.assertRaises(helper.CheckFailure):
                    helper.phase_source_slots("compile", bad)

    def test_compile_binding_requires_actual_fixed_workflow_ref_source_and_attempt(self):
        original = environment()
        expected = helper.compile_workflow_binding(original)
        self.assertEqual(expected["sourceSha"], "1" * 40)
        for key, value in (("GITHUB_REF", "refs/heads/main"), ("GITHUB_SHA", "bad"),
                           ("GITHUB_WORKFLOW_SHA", "3" * 40), ("GITHUB_WORKFLOW_REF", "other/workflow"),
                           ("GITHUB_REPOSITORY", "other/project"), ("GITHUB_RUN_ID", "0"),
                           ("GITHUB_RUN_ATTEMPT", "-1"), ("GITHUB_EVENT_NAME", "pull_request")):
            with self.subTest(key=key), self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding({**original, key: value})
        dispatched = {**original, "GITHUB_EVENT_NAME": "workflow_dispatch"}
        with self.assertRaises(helper.CheckFailure):
            helper.compile_workflow_binding(dispatched)
        self.assertEqual(helper.compile_workflow_binding({**dispatched, "MRK_EXPECTED_SHA": "1" * 40}), expected)

        for target in helper.MAC_COMPILE_HOSTS:
            env = mac_environment(target)
            binding = helper.compile_workflow_binding(env, helper.MAC_COMPILE_SCOPE)
            self.assertEqual(binding["workflowPath"], helper.MAC_COMPILE_WORKFLOW)
            for key, bad in (("GITHUB_REF", helper.COMPILE_REF), ("GITHUB_WORKFLOW_SHA", "4" * 40),
                             ("GITHUB_WORKFLOW_REF", environment()["GITHUB_WORKFLOW_REF"]), ("GITHUB_RUN_ATTEMPT", "0")):
                with self.subTest(key=key), self.assertRaises(helper.CheckFailure):
                    helper.compile_workflow_binding({**env, key: bad}, helper.MAC_COMPILE_SCOPE)
            release = {"schemaVersion": 1, "packageVersion": "0.1.1", "release": helper.MAC_COMPILE_HOSTS[target][4] + "desktop-01"}
            cargo, tauri = b'[package]\nversion = "0.1.1"\n', b'{"version":"0.1.1"}'
            self.assertEqual(helper.mac_compile_release(json.dumps(release).encode(), target, cargo, tauri), release["release"])
            for bad in ({**release, "schemaVersion": True}, {**release, "extra": 1}, {**release, "packageVersion": "0.1.0"},
                        {**release, "release": "foreign-desktop-01"}):
                with self.subTest(bad=bad), self.assertRaises(helper.CheckFailure):
                    helper.mac_compile_release(json.dumps(bad).encode(), target, cargo, tauri)
            with self.assertRaises(helper.CheckFailure):
                helper.mac_compile_release(b'{"schemaVersion":1,"schemaVersion":1}', target, cargo, tauri)
        # Every actual row is checked independently before original root allocation.
        pairs = (("aarch64-apple-darwin", "full4"), ("x86_64-apple-darwin", "full4"),
                 ("aarch64-apple-darwin", "vault-only"))
        for target, mode in pairs:
            env = mac_environment(target, mode)
            self.assertEqual(helper.mac_compile_mode(env, target), mode)
            self.assertEqual([list(row) for row in helper.mac_compile_graphs(target, mode)], mac_context(target, mode)["macCompile"]["graphs"])
            for key in ("MRK_COMPILE_SELECTION", "MRK_MACOS_COMPILE_MODE", "MRK_MACOS_TARGET"):
                missing = dict(env); del missing[key]
                with self.subTest(target=target, mode=mode, missing=key), self.assertRaises(helper.CheckFailure):
                    helper.mac_compile_mode(missing, target)
            for bad in ("normal3", "arbitrary", "", None, False):
                with self.subTest(mode=bad), self.assertRaises(helper.CheckFailure):
                    helper.mac_compile_mode({**env, "MRK_MACOS_COMPILE_MODE": bad}, target)
            with self.assertRaises(helper.CheckFailure):
                helper.mac_compile_mode({**env, "GITHUB_EVENT_NAME": "pull_request"}, target)
            with self.assertRaises(helper.CheckFailure):
                helper.mac_compile_mode({**env, "MRK_COMPILE_SELECTION": "other"}, target)
        for target in helper.MAC_COMPILE_HOSTS:
            for selection in ("arm", "intel", "remaining"):
                mode = "vault-only" if selection == "remaining" and target == "aarch64-apple-darwin" else "full4"
                env = {**mac_environment(target, mode), "GITHUB_EVENT_NAME": "workflow_dispatch",
                       "MRK_EXPECTED_SHA": "1" * 40, "MRK_COMPILE_SELECTION": selection}
                if selection == "arm" and target != "aarch64-apple-darwin" or selection == "intel" and target != "x86_64-apple-darwin":
                    with self.assertRaises(helper.CheckFailure):
                        helper.mac_compile_mode(env, target)
                else:
                    self.assertEqual(helper.mac_compile_mode(env, target), mode)
        for target, mode in (("x86_64-apple-darwin", "vault-only"), ("unknown", "full4")):
            with self.assertRaises(helper.CheckFailure):
                helper.mac_compile_graphs(target, mode)
        env = mac_environment("aarch64-apple-darwin", "vault-only")
        with self.assertRaises(helper.CheckFailure):
            helper.mac_compile_mode({**env, "GITHUB_EVENT_NAME": "push"}, "aarch64-apple-darwin")
        with self.assertRaises(helper.CheckFailure):
            helper.mac_compile_mode({**env, "MRK_MACOS_COMPILE_MODE": "full4"}, "aarch64-apple-darwin")

        # Actual SOURCE input/hash and separate-manifest configuration guards,
        # with only bounded inert BytesIO edges (no source fixture execution).
        source_names = ("desktop/src-tauri/Cargo.toml", "desktop/src-tauri/Cargo.lock",
                        "desktop/helpers/macos-desktop-image/Cargo.toml", "desktop/helpers/macos-desktop-image/Cargo.lock",
                        "desktop/src-tauri/tauri.conf.json", "desktop/native/macos-installed-native/build.rs",
                        "desktop/packaging/macos-android-service-signing.profile", "desktop/packaging/macos-install-producer-signing.profile",
                        "desktop/helpers/macos-vault-helper/Cargo.toml", "desktop/helpers/macos-vault-helper/Cargo.lock",
                        "desktop/helpers/macos-vault-helper/src/main.rs", "desktop/native/macos-installed-native/Cargo.toml")
        fake_bodies, present, symlinks, streams, guards = {}, set(), set(), [], []
        class SourcePath(PurePosixPath):
            def open(self, mode):
                self_outer.assertEqual(mode, "rb")
                stream = io.BytesIO(fake_bodies[str(self)])
                streams.append(stream)
                return stream
            def exists(self):
                return str(self) in present
            def is_symlink(self):
                return str(self) in symlinks
        self_outer = self
        for target, mode in pairs:
            release = {"schemaVersion": 1, "packageVersion": "0.1.1", "release": helper.MAC_COMPILE_HOSTS[target][4] + "desktop-01"}
            release_name = "desktop/macos-installed-inputs/" + helper.MAC_COMPILE_HOSTS[target][3]
            fake_bodies = {"/inert/source/" + name: b"inert source data\n" for name in source_names}
            fake_bodies["/inert/source/desktop/src-tauri/Cargo.toml"] = b'[package]\nversion="0.1.1"\n'
            fake_bodies["/inert/source/desktop/src-tauri/tauri.conf.json"] = b'{"version":"0.1.1"}'
            fake_bodies["/inert/source/" + release_name] = json.dumps(release).encode()
            streams.clear()
            with patch.object(helper, "ordinary"):
                actual = helper.mac_compile_inputs(SourcePath("/inert/source"), target, mode)
            self.assertEqual(actual["mode"], mode)
            self.assertEqual(actual["graphs"], mac_context(target, mode)["macCompile"]["graphs"])
            self.assertEqual([row["path"] for row in actual["sources"]], [*source_names, release_name])
            self.assertTrue(streams and all(stream.closed for stream in streams))
            for row in actual["sources"]:
                raw = fake_bodies["/inert/source/" + row["path"]]
                self.assertEqual((row["size"], row["sha256"]), (len(raw), helper.hashlib.sha256(raw).hexdigest()))
        with patch.object(helper, "no_cargo_configuration", side_effect=lambda paths: guards.append(tuple(map(str, paths)))):
            helper.mac_compile_source_guard(SourcePath("/inert/source"), SourcePath("/inert/root"))
            self.assertEqual(guards[-1][:3], ("/inert/source/desktop/helpers/macos-desktop-image",
                                            "/inert/source/desktop/helpers/macos-vault-helper", "/inert/source/desktop/helpers"))
            for relative in ("macos-desktop-image", "macos-vault-helper"):
                path = "/inert/source/desktop/helpers/" + relative + "/target"
                for state in (present, symlinks):
                    state.add(path)
                    with self.assertRaises(helper.CheckFailure):
                        helper.mac_compile_source_guard(SourcePath("/inert/source"), SourcePath("/inert/root"))
                    state.clear()

        workflow = (HELPER.parents[2] / helper.MAC_COMPILE_WORKFLOW).read_text(encoding="utf-8")
        arm_row = '{"platform":"macos","os":"macos-26","target":"aarch64-apple-darwin","mode":"full4"}'
        intel_row = '{"platform":"macos","os":"macos-26-intel","target":"x86_64-apple-darwin","mode":"full4"}'
        arm_vault = '{"platform":"macos","os":"macos-26","target":"aarch64-apple-darwin","mode":"vault-only"}'
        matrix = ("        include: ${{ fromJSON(inputs.target == 'observer-data' && '[" + arm_row.replace('full4', 'observer-data') + "]' || inputs.target == 'observer-only' && '[" + arm_row.replace('full4', 'observer-only') + "]' || inputs.target == 'app-only' && '[" + arm_row.replace('full4', 'app-only') + ',' + intel_row.replace('full4', 'app-only') + "]' || inputs.target == 'history-app4' && '[" + arm_row.replace('full4', 'history-app4') + ',' + intel_row.replace('full4', 'history-app4') + "]' || inputs.target == 'remaining' && '[" + arm_vault + ',' + intel_row + "]' || "
                  "inputs.target == 'arm' && '[" + arm_row + "]' || inputs.target == 'intel' && '[" + intel_row + "]' || '[" + arm_row + ',' + intel_row + "]') }}\n")
        self.assertEqual(workflow.count(matrix), 1)
        self.assertIn("      target:\n"
                      "        description: Fixed compiler rows; History DATA, app-only both architectures, observer-only ARM compile, or observer-data ARM fixed five-phase DATA\n"
                      "        required: false\n"
                      "        type: choice\n"
                      "        default: both\n"
                      "        options: [both, arm, intel, remaining, history-app4, app-only, observer-only, observer-data]\n", workflow)
        self.assertIn("      MRK_COMPILE_SELECTION: ${{ inputs.target || 'both' }}\n", workflow)
        self.assertIn("      MRK_MACOS_COMPILE_MODE: ${{ matrix.mode }}\n", workflow)
        admission = workflow.split("      - name: Require exact disposable verification source\n", 1)[1].split(
            "      - name: Check out exact source without persisted credentials\n", 1)[0]
        self.assertIn('          if [[ "$GITHUB_EVENT_NAME" == workflow_dispatch ]]; then\n'
                      '            [[ "$MRK_EXPECTED_SHA" == "$GITHUB_SHA" ]]\n'
                      '            case "$MRK_COMPILE_SELECTION" in\n'
                      '              observer-data) [[ "$MRK_MACOS_COMPILE_MODE" == observer-data && "$MRK_MACOS_TARGET" == aarch64-apple-darwin ]] ;;\n'
                      '              observer-only) [[ "$MRK_MACOS_COMPILE_MODE" == observer-only && "$MRK_MACOS_TARGET" == aarch64-apple-darwin ]] ;;\n'
                      '              app-only) [[ "$MRK_MACOS_COMPILE_MODE" == app-only && ( "$MRK_MACOS_TARGET" == aarch64-apple-darwin || "$MRK_MACOS_TARGET" == x86_64-apple-darwin ) ]] ;;\n'
                      '              history-app4) [[ "$MRK_MACOS_COMPILE_MODE" == history-app4 && ( "$MRK_MACOS_TARGET" == aarch64-apple-darwin || "$MRK_MACOS_TARGET" == x86_64-apple-darwin ) ]] ;;\n'
                      '              both) [[ "$MRK_MACOS_COMPILE_MODE" == full4 ]] ;;\n'
                      '              arm) [[ "$MRK_MACOS_TARGET" == aarch64-apple-darwin && "$MRK_MACOS_COMPILE_MODE" == full4 ]] ;;\n'
                      '              intel) [[ "$MRK_MACOS_TARGET" == x86_64-apple-darwin && "$MRK_MACOS_COMPILE_MODE" == full4 ]] ;;\n'
                      '              remaining) [[ ( "$MRK_MACOS_TARGET" == aarch64-apple-darwin && "$MRK_MACOS_COMPILE_MODE" == vault-only ) || ( "$MRK_MACOS_TARGET" == x86_64-apple-darwin && "$MRK_MACOS_COMPILE_MODE" == full4 ) ]] ;;\n'
                      '              *) exit 1 ;;\n'
                      '            esac\n'
                      '          else\n'
                      '            [[ "$GITHUB_EVENT_NAME" == push && "$MRK_COMPILE_SELECTION" == both && "$MRK_MACOS_COMPILE_MODE" == full4 ]]\n'
                      '          fi\n', admission)
        self.assertIn('[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ && "$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA" ]]', admission)
        self.assertIn('[[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-normal-compile ]]', admission)
        self.assertIn('[[ "$GITHUB_WORKFLOW_REF" == "$GITHUB_REPOSITORY/.github/workflows/desktop-macos-normal-compile.yml@$GITHUB_REF" ]]', admission)
        self.assertIn('[[ "$RUNNER_ENVIRONMENT" == github-hosted ]]', admission)
        header = workflow.split('    steps:\n', 1)[0]
        self.assertIn("    timeout-minutes: ${{ matrix.target == 'x86_64-apple-darwin' && 120 || (matrix.mode == 'full4' || matrix.mode == 'history-app4' || matrix.mode == 'app-only' || matrix.mode == 'observer-only' || matrix.mode == 'observer-data') && 50 || 45 }}\n", header)
        self.assertIn('      fail-fast: false\n      max-parallel: 2\n', header)
        acquire = workflow.split('      - name: Acquire locked active-platform inputs without npm scripts\n', 1)[1].split('      - name:', 1)[0]
        compile_step = workflow.split('      - name: Compile selected graphs and only explicitly selected fixed DATA\n', 1)[1].split('      - name:', 1)[0]
        self.assertIn('        timeout-minutes: 15\n', acquire)
        self.assertIn("        timeout-minutes: ${{ matrix.target == 'x86_64-apple-darwin' && 92 || (matrix.mode == 'full4' || matrix.mode == 'history-app4' || matrix.mode == 'app-only' || matrix.mode == 'observer-only' || matrix.mode == 'observer-data') && 32 || 25 }}\n", compile_step)
        self.assertIn("      - name: Select fixed frontend compiler\n        if: matrix.mode == 'full4' || matrix.mode == 'history-app4' || matrix.mode == 'app-only' || matrix.mode == 'observer-only' || matrix.mode == 'observer-data'\n", workflow)
        self.assertIn("desktop-macos-normal-compile-${{ matrix.target }}-${{ matrix.mode }}-", workflow)
        self.assertNotIn("ubuntu-", workflow)
        self.assertNotIn("windows-2025", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertEqual(workflow.count("ci_foundation.py compile'"), 1)
        self.assertIn("MRK_DESKTOP_HOSTED_CHECKS: macos-normal-compile-v1", workflow)
        cleanup = workflow.split("      - name: Immediately remove positively settled compiler outputs\n", 1)[1]
        # Artifact retention can fail after the compiler settles (actual Intel
        # ENOTFOUND). Cleanup is tied to original prepare/compile outcomes, not
        # uploader success; failed/unknown/skipped/cancelled compile stays held.
        self.assertEqual(workflow.count("        id: compile\n"), 1)
        self.assertIn("        id: compile\n", compile_step)
        self.assertIn("        if: always() && steps.prepare.outcome == 'success' && steps.compile.outcome == 'success'\n", cleanup)
        self.assertNotIn("        if: success()\n", cleanup)
        self.assertNotIn("continue-on-error:", workflow)  # Upload failure remains a job failure.
        self.assertIn("ci_foundation.py clean'", cleanup)

        engineering = engineering_environment()
        selected = helper.compile_workflow_binding(engineering, helper.ENGINEERING_COMPILE_SCOPE)
        self.assertEqual(selected["workflowPath"], ".github/workflows/desktop-macos-engineering-ui.yml")
        for key, bad in (("GITHUB_REF", helper.MAC_COMPILE_REF), ("GITHUB_WORKFLOW_SHA", "f" * 40),
                         ("GITHUB_WORKFLOW_REF", environment()["GITHUB_WORKFLOW_REF"]),
                         ("GITHUB_RUN_ID", "0"), ("GITHUB_RUN_ATTEMPT", "0"),
                         ("GITHUB_EVENT_NAME", "workflow_dispatch")):
            with self.subTest(engineering_binding=key), self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding({**engineering, key: bad, "MRK_EXPECTED_SHA": "1" * 40}, helper.ENGINEERING_COMPILE_SCOPE)
        # Actual new workflow source is also nominated, not a synthetic manifest.
        engineering_workflow = (HELPER.parents[2] / helper.ENGINEERING_COMPILE_WORKFLOW).read_text(encoding="utf-8")
        self.assertEqual([line.strip() for line in engineering_workflow.splitlines() if line.lstrip().startswith("branches:")],
                         ["branches: [verify/desktop-macos-engineering-ui, verify/desktop-macos-xctest-compile]"])
        self.assertIn("  engineering-main:\n    if: github.ref == 'refs/heads/verify/desktop-macos-engineering-ui'\n", engineering_workflow)
        self.assertIn('[[ "$GITHUB_EVENT_NAME" == push && "$GITHUB_REF" == refs/heads/verify/desktop-macos-engineering-ui ]] || exit 1', engineering_workflow)
        # A shared workflow trigger does not grant the ordinary engineering job
        # to the compile-only ref; its actual helper binding is still exact.
        compile_only = {**engineering, "GITHUB_REF": "refs/heads/verify/desktop-macos-xctest-compile",
                        "GITHUB_WORKFLOW_REF": "fictional/project/.github/workflows/desktop-macos-engineering-ui.yml@refs/heads/verify/desktop-macos-xctest-compile"}
        with self.assertRaises(helper.CheckFailure):
            helper.compile_workflow_binding(compile_only, helper.ENGINEERING_COMPILE_SCOPE)
        self.assertIn("environment: macos-engineering", engineering_workflow)
        self.assertIn("runs-on: macos-26", engineering_workflow)
        self.assertIn("MRK_DESKTOP_HOSTED_CHECKS: macos-engineering-ui-compile-v1", engineering_workflow)
        self.assertNotIn("secrets.", engineering_workflow)
        self.assertNotIn("macos-26-intel", engineering_workflow)
        self.assertNotIn("--configured-signing", engineering_workflow)
        self.assertNotIn("workflow_dispatch:", engineering_workflow)
        upload = engineering_workflow.split("      - name: Retain only bounded compiler and engineering evidence", 1)[1].split("      - name: Dispose only", 1)[0]
        self.assertNotIn("*.stdout", upload)
        self.assertNotIn("*.stderr", upload)
        self.assertIn("/normal-ui/engineering-smoke.json", upload)
        self.assertIn("/normal-ui/engineering-summary.status", upload)
        self.assertNotIn("/normal-ui/*", upload)
        self.assertEqual(engineering_workflow.count('--work "$MRK_MACOS_WORK"'), 3)
        self.assertIn('--expected-source "$MRK_CURRENT_SOURCE" --expected-manifest "$MRK_CURRENT_MANIFEST"', engineering_workflow)
        self.assertIn("set -o noclobber", engineering_workflow)
        self.assertEqual(engineering_workflow.count("ci_foundation.py compile'"), 1)
        self.assertIn("--engineering-main-test", engineering_workflow)
        self.assertIn("--engineering-main-summary", engineering_workflow)
        self.assertIn("engineering-summary.status", engineering_workflow)
        self.assertLess(engineering_workflow.index("--engineering-main-summary"), engineering_workflow.index("ci_foundation.py clean'"))

        fixed = source_slots_environment()
        binding = helper.compile_workflow_binding(fixed, helper.SOURCE_SLOTS_SCOPE)
        self.assertEqual(binding["workflowPath"], ".github/workflows/desktop-macos-intel-source-slots.yml")
        for key, bad in (("GITHUB_SHA", "0" * 40), ("GITHUB_WORKFLOW_SHA", "a" * 40),
                         ("GITHUB_REF", helper.MAC_COMPILE_REF), ("GITHUB_WORKFLOW_REF", "foreign/workflow"),
                         ("GITHUB_RUN_ID", "0"), ("GITHUB_RUN_ATTEMPT", "0"), ("GITHUB_EVENT_NAME", "pull_request")):
            with self.subTest(source_slots_field=key), self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding({**fixed, key: bad}, helper.SOURCE_SLOTS_SCOPE)
        with self.assertRaises(helper.CheckFailure):
            helper.compile_workflow_binding({**fixed, "GITHUB_EVENT_NAME": "workflow_dispatch"}, helper.SOURCE_SLOTS_SCOPE)
        self.assertEqual(helper.compile_workflow_binding({**fixed, "GITHUB_EVENT_NAME": "workflow_dispatch",
                         "MRK_EXPECTED_SHA": "1" * 40}, helper.SOURCE_SLOTS_SCOPE), binding)
        workflow = (HELPER.parents[2] / helper.SOURCE_SLOTS_WORKFLOW).read_text(encoding="utf-8")
        self.assertEqual(workflow.count("runs-on: macos-26-intel"), 1)
        self.assertIn("branches: [verify/desktop-macos-intel-source-slots, verify/desktop-macos-intel-removal-abrupt]", workflow)
        self.assertIn('[[ "$GITHUB_EVENT_NAME" == push && "$MRK_PUSH_EVENT_AFTER" == "$GITHUB_SHA" ]]', workflow)
        self.assertIn("MRK_PUSH_EVENT_AFTER: ${{ github.event.after }}", workflow)
        self.assertEqual(workflow.count("type: string"), 1)
        self.assertIn('[[ "$MRK_EXPECTED_SHA" == "$GITHUB_SHA" ]]', workflow)
        self.assertIn('[[ "$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA" ]]', workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("timeout-minutes: 40", workflow)
        self.assertEqual(workflow.count("timeout-minutes: 16"), 2)
        for phase in ("prepare", "acquire", "compile", "clean"):
            self.assertEqual(workflow.count('desktop/tools/ci_foundation.py ' + phase + "'"), 1)
        self.assertIn("if: success() && steps.allocation.outcome == 'success'", workflow)
        upload = workflow.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]
        self.assertEqual([line.strip() for line in upload.splitlines()],
                         ["${{ steps.prepare.outputs.root }}/" + name for name in
                          ("public-bindings.json", "acquire-checks.json", "compile-checks.json", "source-slots-failure.json")])
        for forbidden in ("actions/setup-node", "npm ", "--ignored", "--selector", "matrix:", ".stdout", ".stderr", "secrets."):
            self.assertNotIn(forbidden, workflow)

        # Actual direct-tools admission checks each original selected field,
        # including contradictory/space-mangled duplicates, before Cargo runs.
        original = "release: 1.98.0\ncommit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\nhost: x86_64-apple-darwin"
        probes = (original, original + "\nrelease: 1.98.1", original + "\n release : 1.98.0",
                  original + "\ncommit-hash: " + "a" * 40, original + "\nhost: aarch64-apple-darwin",
                  original.replace("release: 1.98.0", "release: 1.98.1"),
                  original.replace("commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea", ""))
        for probe in probes:
            calls = []
            def invoke(argv, **kw):
                calls.append((list(argv), kw))
                return probe if kw["check"] == "rust-version-target" else "cargo 1.98.1 (abcdef123 2026-09-01)"
            env = {"PATH": "/selected/bin"}
            with self.subTest(source_slots_probe=probe), patch.object(helper, "ordinary"), \
                    patch.object(helper, "run", side_effect=invoke):
                if probe == original:
                    cargo, rustc = helper.tools(source_slots_context(), env)
                    prefix = "/Users/runner/.rustup/toolchains/stable-x86_64-apple-darwin/bin/"
                    self.assertEqual((cargo, rustc), (prefix + "cargo", prefix + "rustc"))
                    self.assertEqual([kw["check"] for _, kw in calls], ["rust-version-target", "mac-cargo-version"])
                    self.assertEqual(env["RUSTUP_AUTO_INSTALL"], "0")
                else:
                    with self.assertRaises(helper.CheckFailure):
                        helper.tools(source_slots_context(), env)
                    self.assertEqual([kw["check"] for _, kw in calls], ["rust-version-target"])

        events = []
        MemoryPath, _ = memory_paths(events)
        bound = source_slots_context()
        loaded = deepcopy(bound)
        with patch.dict(helper.os.environ, {**fixed, "MRK_DESKTOP_CI_ROOT": bound["root"]}, clear=True), \
                patch.object(helper, "Path", MemoryPath), patch.object(helper, "ordinary"), \
                patch.object(helper, "hash_file", return_value=bound["workflowSha256"]), \
                patch.object(helper, "read_bounded_json", side_effect=lambda *args: deepcopy(loaded)), \
                patch.object(helper, "source_slots_source_guard"):
            self.assertEqual(helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE), bound)
            for key, bad in (("target", "aarch64-apple-darwin"), ("features", ["desktop-shell"]),
                             ("testTarget", "bin"), ("test", "other::test")):
                loaded = deepcopy(bound); loaded["sourceSlots"][key] = bad
                with self.subTest(selection=key), self.assertRaises(helper.CheckFailure):
                    helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)
            for key, bad in (("sourceSlots", None), ("sourceTree", "0" * 40), ("source", "/foreign/source")):
                loaded = {**deepcopy(bound), key: bad}
                with self.assertRaises(helper.CheckFailure):
                    helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)

        # The B push does not rely on workflow_dispatch/default-branch delivery.
        fixed_b = intel_removal_environment()
        b = intel_removal_context()
        selected = helper.compile_workflow_binding(fixed_b, helper.SOURCE_SLOTS_SCOPE)
        self.assertEqual(selected["workflowRef"], b["workflowRef"])
        for key, value in (("GITHUB_EVENT_NAME", "workflow_dispatch"), ("GITHUB_EVENT_NAME", "pull_request"),
                           ("MRK_PUSH_EVENT_AFTER", "2" * 40), ("MRK_PUSH_EVENT_AFTER", ""),
                           ("GITHUB_SHA", "0" * 40), ("GITHUB_REF", "refs/heads/main"),
                           ("GITHUB_WORKFLOW_REF", source_slots_context()["workflowRef"])):
            with self.subTest(b_binding=key), self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding({**fixed_b, key: value, "MRK_EXPECTED_SHA": "1" * 40}, helper.SOURCE_SLOTS_SCOPE)
        # Old DATA1 still accepts its actual exact-SHA dispatch and needs no after.
        legacy = source_slots_environment()
        self.assertEqual(helper.compile_workflow_binding({**legacy, "GITHUB_EVENT_NAME": "workflow_dispatch",
                         "MRK_EXPECTED_SHA": "1" * 40}, helper.SOURCE_SLOTS_SCOPE),
                         helper.compile_workflow_binding(legacy, helper.SOURCE_SLOTS_SCOPE))
        build = intel_removal_build()
        self.assertIs(helper.validate_source_slots_build(build), build)
        for key, value in (("release", "macos26-arm64-desktop-01"), ("release", "macos26-x86_64-" + "x" * 50),
                           ("sources", []), ("sources", list(reversed(build["sources"]))), ("extra", True)):
            with self.assertRaises(helper.CheckFailure):
                helper.validate_source_slots_build({**build, key: value})
        for key, value in (("size", True), ("size", 4097), ("sha256", "0" * 64), ("path", "foreign")):
            bad = deepcopy(build); bad["sources"][0][key] = value
            with self.assertRaises(helper.CheckFailure):
                helper.validate_source_slots_build(bad)
        # Real fixed reader/decoder with inert byte ports; no SOURCE fixture IO.
        bodies, read_sizes, closes = intel_removal_bodies(), [], []
        class SourceBytes(io.BytesIO):
            def read(self, limit):
                read_sizes.append(limit)
                return super().read(limit)
            def close(self):
                closes.append(True)
                super().close()
        class BuildPath(PurePosixPath):
            def open(self, mode):
                self_outer.assertEqual(mode, "rb")
                key = self.relative_to("/inert/source").as_posix()
                return SourceBytes(bodies[key])
        self_outer = self
        with patch.object(helper, "ordinary"):
            self.assertEqual(helper.source_slots_build_inputs(BuildPath("/inert/source")), build)
            self.assertEqual(read_sizes, [4097, 1024 * 1024 + 1, 1024 * 1024 + 1])
            self.assertEqual(len(closes), 3)
            initial = intel_removal_bodies()
            for key, value in (("desktop/macos-installed-inputs/build-release-intel.json", b"x" * 4097),
                               ("desktop/macos-installed-inputs/build-release-intel.json", b""),
                               ("desktop/src-tauri/Cargo.toml", b'[package]\nversion = "0.1.2"\n'),
                               ("desktop/src-tauri/tauri.conf.json", b'{"version":"0.1.2"}')):
                bodies = {**initial, key: value}
                with self.subTest(build_source=key), self.assertRaises(helper.CheckFailure):
                    helper.source_slots_build_inputs(BuildPath("/inert/source"))
        events = []
        MemoryPath, _ = memory_paths(events)
        loaded = deepcopy(b)
        with patch.dict(helper.os.environ, {**fixed_b, "MRK_DESKTOP_CI_ROOT": b["root"]}, clear=True), \
                patch.object(helper, "Path", MemoryPath), patch.object(helper, "ordinary"), \
                patch.object(helper, "hash_file", return_value=b["workflowSha256"]), \
                patch.object(helper, "read_bounded_json", side_effect=lambda *args: deepcopy(loaded)), \
                patch.object(helper, "source_slots_source_guard"), \
                patch.object(helper, "source_slots_build_inputs", return_value=deepcopy(build)) as input_read:
            self.assertEqual(helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE), b)
            self.assertEqual(str(input_read.call_args.args[0]), b["source"])
            for key, value in (("release", "macos26-x86_64-foreign"), ("sources", list(reversed(build["sources"])))):
                loaded = deepcopy(b); loaded["sourceSlotsBuild"][key] = value
                with self.assertRaises(helper.CheckFailure):
                    helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)
            loaded = deepcopy(b); loaded["sourceSlotsBuild"]["sources"][0]["sha256"] = "a" * 64
            with self.assertRaises(helper.CheckFailure):
                helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)
            loaded = deepcopy(b); loaded["sourceSlots"] = source_slots_context()["sourceSlots"]
            with self.assertRaises(helper.CheckFailure):
                helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)


        # C uses the SAME original workflow/owner with one actual dispatch-only
        # tuple. A stale task cannot switch between C and the legacy default.
        cenv, c = initialization_environment(), initialization_context()
        self.assertEqual(helper.SOURCE_SLOTS_INITIALIZATION_TESTS, INITIALIZATION_CASES)
        self.assertEqual(tuple(sorted(INITIALIZATION_CASES)), INITIALIZATION_CASES)
        self.assertEqual(helper.source_slots_selection(initialization=True), c["sourceSlots"])
        self.assertFalse(helper.source_slots_is_removal(c)); self.assertTrue(helper.source_slots_is_initialization(c))
        for value in (None, 0, 1, [], {}, "allocation1", "project-initialization4"):
            with self.assertRaises(helper.CheckFailure):
                helper.source_slots_selection(initialization=value)
        with self.assertRaises(helper.CheckFailure):
            helper.source_slots_selection(True, initialization=True)
        for key, value in (("MRK_SOURCE_SLOTS_SELECTION", "foreign"), ("MRK_SOURCE_SLOTS_SELECTION", None),
                           ("GITHUB_EVENT_NAME", "push"), ("GITHUB_REF", helper.SOURCE_SLOTS_REMOVAL_REF),
                           ("MRK_EXPECTED_SHA", "2" * 40), ("GITHUB_WORKFLOW_SHA", "2" * 40)):
            with self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding({**cenv, key: value}, helper.SOURCE_SLOTS_SCOPE)
        for wrong in ({**c, "sourceSlotsSelection": None}, {**c, "sourceSlotsBuild": intel_removal_build()},
                      {**c, "sourceSlots": source_slots_context()["sourceSlots"]},
                      {**c, "workflowRef": intel_removal_context()["workflowRef"]}):
            with self.assertRaises(helper.CheckFailure):
                helper.source_slots_is_removal(wrong)
        self.assertIn("options: [allocation1, project-initialization4, artifact-setup10, environment-setup1]", workflow)
        self.assertIn("MRK_SOURCE_SLOTS_SELECTION: ${{ inputs.selection || 'allocation1' }}", workflow)
        self.assertIn('[[ "$GITHUB_EVENT_NAME" == workflow_dispatch && "$GITHUB_REF" == refs/heads/verify/desktop-macos-intel-source-slots ]]', workflow)
        events = []
        MemoryPath, _ = memory_paths(events)
        loaded = deepcopy(c)
        with patch.dict(helper.os.environ, {**cenv, "MRK_DESKTOP_CI_ROOT": c["root"]}, clear=True), \
                patch.object(helper, "Path", MemoryPath), patch.object(helper, "ordinary"), \
                patch.object(helper, "hash_file", return_value=c["workflowSha256"]), \
                patch.object(helper, "read_bounded_json", side_effect=lambda *args: deepcopy(loaded)), \
                patch.object(helper, "source_slots_source_guard"):
            self.assertEqual(helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE), c)
            loaded = source_slots_context()
            with self.assertRaises(helper.CheckFailure):
                helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)
            loaded = deepcopy(c)
            with patch.dict(helper.os.environ, {"MRK_SOURCE_SLOTS_SELECTION": "allocation1"}), self.assertRaises(helper.CheckFailure):
                helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)
            for key, value in (("tests", list(reversed(INITIALIZATION_CASES))), ("testTarget", "bin"),
                               ("features", ["desktop-shell"]), ("target", "aarch64-apple-darwin")):
                loaded = deepcopy(c); loaded["sourceSlots"][key] = value
                with self.assertRaises(helper.CheckFailure):
                    helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)

        # D uses the SAME original workflow/owner with one actual dispatch-only
        # tuple. A stale task cannot switch between C and the legacy default.
        artifact_env, artifact_bound = artifact_environment(), artifact_context()
        with self.assertRaises(helper.CheckFailure):
            helper.compile_workflow_binding({**artifact_env, "MRK_SOURCE_SLOTS_SELECTION": "artifact-inspection7"}, helper.SOURCE_SLOTS_SCOPE)
        with self.assertRaises(helper.CheckFailure):
            helper.source_slots_is_artifact({**artifact_bound, "sourceSlotsSelection": "artifact-inspection7"})
        self.assertEqual(helper.SOURCE_SLOTS_ARTIFACT_TESTS, ARTIFACT_CASES)
        self.assertEqual(tuple(sorted(ARTIFACT_CASES)), ARTIFACT_CASES)
        self.assertEqual(helper.source_slots_selection(artifact=True), artifact_bound["sourceSlots"])
        self.assertFalse(helper.source_slots_is_removal(artifact_bound)); self.assertTrue(helper.source_slots_is_artifact(artifact_bound))
        self.assertFalse(helper.source_slots_is_initialization(artifact_bound))
        with self.assertRaises(helper.CheckFailure):
            helper.source_slots_selection(initialization=True, artifact=True)
        for value in (None, 0, 1, [], {}, "allocation1", "artifact-setup10"):
            with self.assertRaises(helper.CheckFailure):
                helper.source_slots_selection(artifact=value)
        with self.assertRaises(helper.CheckFailure):
            helper.source_slots_selection(True, artifact=True)
        for key, value in (("MRK_SOURCE_SLOTS_SELECTION", "foreign"), ("MRK_SOURCE_SLOTS_SELECTION", None),
                           ("GITHUB_EVENT_NAME", "push"), ("GITHUB_REF", helper.SOURCE_SLOTS_REMOVAL_REF),
                           ("MRK_EXPECTED_SHA", "2" * 40), ("GITHUB_WORKFLOW_SHA", "2" * 40)):
            with self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding({**artifact_env, key: value}, helper.SOURCE_SLOTS_SCOPE)
        for wrong in ({**artifact_bound, "sourceSlotsSelection": None}, {**artifact_bound, "sourceSlotsBuild": intel_removal_build()},
                      {**artifact_bound, "sourceSlots": source_slots_context()["sourceSlots"]},
                      {**artifact_bound, "workflowRef": intel_removal_context()["workflowRef"]}):
            with self.assertRaises(helper.CheckFailure):
                helper.source_slots_is_removal(wrong)
        self.assertIn("options: [allocation1, project-initialization4, artifact-setup10, environment-setup1]", workflow)
        self.assertIn("MRK_SOURCE_SLOTS_SELECTION: ${{ inputs.selection || 'allocation1' }}", workflow)
        self.assertIn('[[ "$GITHUB_EVENT_NAME" == workflow_dispatch && "$GITHUB_REF" == refs/heads/verify/desktop-macos-intel-source-slots ]]', workflow)
        events = []
        MemoryPath, _ = memory_paths(events)
        loaded = deepcopy(artifact_bound)
        with patch.dict(helper.os.environ, {**artifact_env, "MRK_DESKTOP_CI_ROOT": artifact_bound["root"]}, clear=True),\
                patch.object(helper, "Path", MemoryPath), patch.object(helper, "ordinary"),\
                patch.object(helper, "hash_file", return_value=artifact_bound["workflowSha256"]),\
                patch.object(helper, "read_bounded_json", side_effect=lambda *args: deepcopy(loaded)),\
                patch.object(helper, "source_slots_source_guard"):
            self.assertEqual(helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE), artifact_bound)
            loaded = initialization_context()
            with self.assertRaises(helper.CheckFailure):
                helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)
            loaded = source_slots_context()
            with self.assertRaises(helper.CheckFailure):
                helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)
            loaded = deepcopy(artifact_bound)
            with patch.dict(helper.os.environ, {"MRK_SOURCE_SLOTS_SELECTION": "allocation1"}), self.assertRaises(helper.CheckFailure):
                helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)
            for key, value in (("tests", list(reversed(ARTIFACT_CASES))), ("testTarget", "bin"),
                               ("features", ["desktop-shell"]), ("target", "aarch64-apple-darwin")):
                loaded = deepcopy(artifact_bound); loaded["sourceSlots"][key] = value
                with self.assertRaises(helper.CheckFailure):
                    helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)

        # Environment uses the SAME original workflow/owner with one actual dispatch-only
        # tuple. A stale task cannot switch between C and the legacy default.
        environment_setup_env, environment_setup_bound = environment_setup_environment(), environment_setup_context()
        with self.assertRaises(helper.CheckFailure):
            helper.compile_workflow_binding({**environment_setup_env, "MRK_SOURCE_SLOTS_SELECTION": "environment-setup2"}, helper.SOURCE_SLOTS_SCOPE)
        with self.assertRaises(helper.CheckFailure):
            helper.source_slots_is_environment_setup({**environment_setup_bound, "sourceSlotsSelection": "environment-setup2"})
        self.assertEqual(helper.SOURCE_SLOTS_ENVIRONMENT_TESTS, ENVIRONMENT_CASES)
        self.assertEqual(tuple(sorted(ENVIRONMENT_CASES)), ENVIRONMENT_CASES)
        self.assertEqual(helper.source_slots_selection(environment_setup=True), environment_setup_bound["sourceSlots"])
        self.assertFalse(helper.source_slots_is_removal(environment_setup_bound)); self.assertTrue(helper.source_slots_is_environment_setup(environment_setup_bound))
        self.assertFalse(helper.source_slots_is_initialization(environment_setup_bound))
        self.assertFalse(helper.source_slots_is_artifact(environment_setup_bound))
        with self.assertRaises(helper.CheckFailure):
            helper.source_slots_selection(initialization=True, environment_setup=True)
        for value in (None, 0, 1, [], {}, "allocation1", "environment-setup1"):
            with self.assertRaises(helper.CheckFailure):
                helper.source_slots_selection(environment_setup=value)
        with self.assertRaises(helper.CheckFailure):
            helper.source_slots_selection(True, environment_setup=True)
        for key, value in (("MRK_SOURCE_SLOTS_SELECTION", "foreign"), ("MRK_SOURCE_SLOTS_SELECTION", None),
                           ("GITHUB_EVENT_NAME", "push"), ("GITHUB_REF", helper.SOURCE_SLOTS_REMOVAL_REF),
                           ("MRK_EXPECTED_SHA", "2" * 40), ("GITHUB_WORKFLOW_SHA", "2" * 40)):
            with self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding({**environment_setup_env, key: value}, helper.SOURCE_SLOTS_SCOPE)
        for wrong in ({**environment_setup_bound, "sourceSlotsSelection": None}, {**environment_setup_bound, "sourceSlotsBuild": intel_removal_build()},
                      {**environment_setup_bound, "sourceSlots": source_slots_context()["sourceSlots"]},
                      {**environment_setup_bound, "workflowRef": intel_removal_context()["workflowRef"]}):
            with self.assertRaises(helper.CheckFailure):
                helper.source_slots_is_removal(wrong)
        events = []
        MemoryPath, _ = memory_paths(events)
        loaded = deepcopy(environment_setup_bound)
        with patch.dict(helper.os.environ, {**environment_setup_env, "MRK_DESKTOP_CI_ROOT": environment_setup_bound["root"]}, clear=True),\
                patch.object(helper, "Path", MemoryPath), patch.object(helper, "ordinary"),\
                patch.object(helper, "hash_file", return_value=environment_setup_bound["workflowSha256"]),\
                patch.object(helper, "read_bounded_json", side_effect=lambda *args: deepcopy(loaded)),\
                patch.object(helper, "source_slots_source_guard"):
            self.assertEqual(helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE), environment_setup_bound)
            loaded = initialization_context()
            with self.assertRaises(helper.CheckFailure):
                helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)
            loaded = source_slots_context()
            with self.assertRaises(helper.CheckFailure):
                helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)
            loaded = deepcopy(environment_setup_bound)
            with patch.dict(helper.os.environ, {"MRK_SOURCE_SLOTS_SELECTION": "allocation1"}), self.assertRaises(helper.CheckFailure):
                helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)
            for key, value in (("tests", list(ARTIFACT_CASES)), ("testTarget", "bin"),
                               ("features", ["desktop-shell"]), ("target", "aarch64-apple-darwin")):
                loaded = deepcopy(environment_setup_bound); loaded["sourceSlots"][key] = value
                with self.assertRaises(helper.CheckFailure):
                    helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)

        # Both actual host rows bind one closed dispatch-only core+shipping mode.
        self.assertEqual(tuple(HISTORY_APP_CASES), helper.MAC_HISTORY_TESTS)
        self.assertEqual(HISTORY_APP_CASES, sorted(HISTORY_APP_CASES))
        workflow = (HELPER.parents[2] / ".github/workflows/desktop-macos-normal-compile.yml").read_text()
        self.assertIn("options: [both, arm, intel, remaining, history-app4, app-only, observer-only, observer-data]", workflow)
        self.assertIn("history-app4) [[", workflow)
        for target in MAC_RUST_EXPECTED:
            env, bound = history_app_environment(target), history_app_context(target)
            self.assertEqual(helper.mac_compile_target(env), target)
            self.assertEqual(helper.mac_compile_mode(env, target), "history-app4")
            self.assertEqual([list(row) for row in helper.mac_compile_graphs(target, "history-app4")], bound["macCompile"]["graphs"])
            self.assertEqual(helper.compiler_binding(bound), MAC_RUST_EXPECTED[target])
            for key, value in (("MRK_COMPILE_SELECTION", "both"), ("MRK_MACOS_COMPILE_MODE", "full4"),
                               ("GITHUB_EVENT_NAME", "push"), ("GITHUB_EVENT_NAME", "pull_request"),
                               ("MRK_COMPILE_SELECTION", "history-app5")):
                with self.subTest(history_target=target, key=key), self.assertRaises(helper.CheckFailure):
                    helper.mac_compile_mode({**env, key: value}, target)
            for key, value in (("MRK_EXPECTED_SHA", "2" * 40), ("GITHUB_REF", helper.SOURCE_SLOTS_REF),
                               ("GITHUB_WORKFLOW_SHA", "2" * 40)):
                with self.assertRaises(helper.CheckFailure):
                    helper.compile_workflow_binding({**env, key: value}, helper.MAC_COMPILE_SCOPE)
            events = []
            MemoryPath, _ = memory_paths(events)
            loaded = deepcopy(bound)
            class HistoryContextPath(MemoryPath):
                def read_text(self, **kwargs):
                    return json.dumps(loaded)
            with patch.dict(helper.os.environ, {**env, "MRK_DESKTOP_CI_ROOT": bound["root"]}, clear=True), \
                    patch.object(helper, "Path", HistoryContextPath), patch.object(helper, "ordinary"), \
                    patch.object(helper, "hash_file", return_value=bound["workflowSha256"]), \
                    patch.object(helper, "mac_compile_inputs", return_value=bound["macCompile"]):
                self.assertEqual(helper.load_context("macos", helper.MAC_COMPILE_SCOPE), bound)
                for field, value in (("tests", HISTORY_APP_CASES[:-1]), ("execution", "compile-only"),
                                     ("mode", "full4"), ("graphs", bound["macCompile"]["graphs"][:1])):
                    loaded = deepcopy(bound); loaded["macCompile"][field] = value
                    with self.assertRaises(helper.CheckFailure):
                        helper.load_context("macos", helper.MAC_COMPILE_SCOPE)

        # Actual public prepare output distinguishes this exact selected-DATA
        # mode from unchanged compile-only modes; all IO remains in-memory.
        for target, mode in (("aarch64-apple-darwin", "history-app4"),
                             ("x86_64-apple-darwin", "history-app4"),
                             ("aarch64-apple-darwin", "full4"),
                             ("x86_64-apple-darwin", "full4"),
                             ("aarch64-apple-darwin", "vault-only")):
            selected = mode == "history-app4"
            env = history_app_environment(target) if selected else mac_environment(target, mode)
            bound = history_app_context(target) if selected else mac_context(target, mode)
            events, written = [], []
            MemoryPath, ZipStream = memory_paths(events)
            def git_only(argv, **kw):
                if kw["check"] == "source-clean":
                    self.assertEqual(list(map(str, argv)), ["/usr/bin/git", "diff", "--no-ext-diff", "--no-textconv", "--exit-code", "--quiet", "HEAD", "--"])
                    return ""
                self.assertEqual(list(map(str, argv)), ["/usr/bin/git", "rev-parse",
                    "HEAD" if kw["check"] == "source-head" else "HEAD^{tree}"])
                self.assertIn(kw["check"], ("source-head", "source-tree"))
                return bound["sourceSha"] if kw["check"] == "source-head" else bound["sourceTree"]
            def select_git(name):
                self.assertEqual(name, "git")
                return "/usr/bin/git"
            with patch.dict(helper.os.environ, env, clear=True), \
                    patch.object(helper, "Path", MemoryPath), patch.object(helper, "run", side_effect=git_only), \
                    patch.object(helper, "ordinary"), patch.object(helper, "hash_file", return_value="2" * 64), \
                    patch.object(helper, "mac_compile_source_guard"), patch.object(helper, "no_cargo_configuration"), \
                    patch.object(helper, "mac_compile_inputs", return_value=deepcopy(bound["macCompile"])), \
                    patch.object(helper, "write_json", side_effect=lambda path, value: written.append((str(path), deepcopy(value)))), \
                    patch.object(helper.shutil, "which", side_effect=select_git), \
                    patch.object(helper.tempfile, "mkdtemp", return_value=bound["root"]), \
                    patch.object(helper.zipfile, "ZipFile", ZipStream), \
                    io.StringIO() as stdout, contextlib.redirect_stdout(stdout):
                helper.prepare("macos", helper.MAC_COMPILE_SCOPE)
            public = next(value for path, value in written if path.endswith("/public-bindings.json"))
            self.assertEqual("test-execution" not in public["notQualified"], selected)
            self.assertEqual("other-tests" in public["notQualified"], selected)
            self.assertEqual(public["macCompile"]["execution"], "compile-and-selected-data" if selected else "compile-only")
            self.assertEqual(public["scope"], helper.MAC_HISTORY_EVIDENCE if selected else helper.compile_profile(helper.MAC_COMPILE_SCOPE)["evidence"])
            self.assertTrue({"signed-runtime", "Developer-ID-identity", "service-registration", "ordinary-UI"}.issubset(public["notQualified"]))

        # App-only is a strict dispatch-only shipping graph, never History DATA.
        for target in MAC_RUST_EXPECTED:
            app_env, app_bound = mac_environment(target, "app-only"), mac_context(target, "app-only")
            self.assertEqual(helper.mac_compile_mode(app_env, target), "app-only")
            self.assertEqual([list(row) for row in helper.mac_compile_graphs(target, "app-only")], app_bound["macCompile"]["graphs"])
            self.assertEqual(helper.compiler_binding(app_bound), MAC_RUST_EXPECTED[target])
            self.assertEqual(app_bound["macCompile"]["execution"], "compile-only")
            for field, bad in (("GITHUB_EVENT_NAME", "push"), ("GITHUB_EVENT_NAME", "pull_request"),
                               ("MRK_COMPILE_SELECTION", "both"), ("MRK_MACOS_COMPILE_MODE", "history-app4"),
                               ("MRK_MACOS_COMPILE_MODE", "full4"), ("MRK_MACOS_COMPILE_MODE", "app"),
                               ("MRK_MACOS_TARGET", "other")):
                with self.subTest(app_target=target, field=field), self.assertRaises(helper.CheckFailure):
                    helper.mac_compile_mode({**app_env, field: bad}, target)
            for field, bad in (("MRK_EXPECTED_SHA", "2" * 40), ("GITHUB_WORKFLOW_SHA", "2" * 40),
                               ("GITHUB_REF", "refs/heads/main")):
                with self.assertRaises(helper.CheckFailure):
                    helper.compile_workflow_binding({**app_env, field: bad}, helper.MAC_COMPILE_SCOPE)
        self.assertIn('app-only) [[ "$MRK_MACOS_COMPILE_MODE" == app-only', workflow)
        self.assertIn("matrix.mode == 'full4' || matrix.mode == 'history-app4' || matrix.mode == 'app-only' || matrix.mode == 'observer-only' || matrix.mode == 'observer-data'", workflow)
        self.assertIn('"target":"aarch64-apple-darwin","mode":"app-only"', workflow)
        self.assertIn('"target":"x86_64-apple-darwin","mode":"app-only"', workflow)
        self.assertIn('"$GITHUB_EVENT_NAME" == push && "$MRK_COMPILE_SELECTION" == both && "$MRK_MACOS_COMPILE_MODE" == full4', workflow)


        # Exactly one manual ARM graph, never a new platform or runtime role.
        observer_env = mac_environment("aarch64-apple-darwin", "observer-only")
        observer = mac_context("aarch64-apple-darwin", "observer-only")
        self.assertEqual(helper.mac_compile_mode(observer_env, "aarch64-apple-darwin"), "observer-only")
        self.assertEqual([list(row) for row in helper.mac_compile_graphs("aarch64-apple-darwin", "observer-only")],
                         observer["macCompile"]["graphs"])
        self.assertEqual(observer["macCompile"]["execution"], "compile-only")
        self.assertNotIn("tests", observer["macCompile"])
        for key, value in (("GITHUB_EVENT_NAME", "push"), ("MRK_COMPILE_SELECTION", "both"),
                           ("MRK_MACOS_COMPILE_MODE", "full4"), ("MRK_MACOS_TARGET", "x86_64-apple-darwin")):
            with self.subTest(observer_binding=key), self.assertRaises(helper.CheckFailure):
                helper.mac_compile_mode({**observer_env, key: value}, "aarch64-apple-darwin")
        with self.assertRaises(helper.CheckFailure):
            helper.mac_compile_graphs("x86_64-apple-darwin", "observer-only")
        self.assertEqual(workflow.count('"target":"aarch64-apple-darwin","mode":"observer-only"'), 1)
        self.assertNotIn('"target":"x86_64-apple-darwin","mode":"observer-only"', workflow)
        self.assertNotIn("environment:", workflow)
        self.assertEqual(workflow.count("/compile-checks.json"), 1)
        self.assertNotIn("source-slots-compile.stdout", workflow)
        self.assertNotIn("source-slots-compile.stderr", workflow)

    def test_compile_cleanup_requires_complete_matching_original_positive_receipts(self):
        for phase in helper.COMPILE_CHECKS:
            original = receipt(phase)
            self.assertEqual(helper.validate_compile_receipt(original, context(), phase), original)
            for key, value in (("schemaVersion", True), ("scope", "passive-development-foundation-only"),
                               ("sourceSha", "3" * 40), ("platform", "macos"), ("runId", "124"),
                               ("attempt", "1"), ("workflowPath", ".github/workflows/desktop-foundation.yml"),
                               ("workflowSha", "4" * 40), ("workflowRef", "other/workflow"),
                               ("workflowSha256", "5" * 64), ("status", "failed"), ("node", "other"),
                               ("rust", {"release": helper.RUST, "target": "wrong"}),
                               ("checks", original["checks"][:-1]), ("extra", False)):
                with self.subTest(phase=phase, key=key), self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt({**original, key: value}, context(), phase)
            for exit_code in (False, 1, None):
                broken = deepcopy(original)
                broken["checks"][0]["exitCode"] = exit_code
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(broken, context(), phase)
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_receipt(None, context(), phase)
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_receipt(original, {**context(), "executionScope": helper.BOUNDARY_SCOPE}, phase)

        self.assertEqual(helper.MAC_COMPILE_RUST,
                         {target: (value["release"], value["commitHash"])
                          for target, value in MAC_RUST_EXPECTED.items()})
        for target, expected_rust in MAC_RUST_EXPECTED.items():
            bound = mac_context(target)
            self.assertEqual(helper.compiler_binding(bound), expected_rust)
            other_target = next(value for value in MAC_RUST_EXPECTED if value != target)
            other_rust = MAC_RUST_EXPECTED[other_target]
            for phase in helper.MAC_COMPILE_CHECKS:
                original = {"schemaVersion": 1, "scope": "desktop-macos-normal-compile-only-v1", "phase": phase, "status": "passed",
                    **{key: bound[key] for key in ("sourceSha", "platform", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt", "sourceTree", "macCompile")},
                    "rust": deepcopy(expected_rust), "node": helper.NODE,
                    "checks": [{"check": name, "exitCode": 0} for name in helper.MAC_COMPILE_CHECKS[phase]]}
                self.assertEqual(helper.validate_compile_receipt(original, bound, phase), original)
                published = []
                with patch.object(helper, "write_json", side_effect=lambda path, value: published.append((str(path), deepcopy(value)))):
                    helper.phase_receipt(bound, phase, list(helper.MAC_COMPILE_CHECKS[phase]), node=helper.NODE)
                self.assertEqual(published, [(bound["root"] + "/" + phase + "-checks.json", original)])
                for key, bad in (("rust", {"release": "1.98.0", "target": target}), ("sourceTree", "4" * 40),
                                 ("macCompile", {**bound["macCompile"], "graphs": bound["macCompile"]["graphs"][:-1]}),
                                 ("checks", original["checks"][:-1])):
                    with self.subTest(target=target, key=key), self.assertRaises(helper.CheckFailure):
                        helper.validate_compile_receipt({**original, key: bad}, bound, phase)
                for bad_rust in ({**expected_rust, "release": "1.0.0"},
                                 {**expected_rust, "commitHash": "0" * 40},
                                 {**expected_rust, "target": other_target},
                                 {**other_rust, "target": target}):
                    with self.subTest(target=target, phase=phase, rust=bad_rust), self.assertRaises(helper.CheckFailure):
                        helper.validate_compile_receipt({**original, "rust": bad_rust}, bound, phase)
                failed = deepcopy(original)
                failed["checks"][-1]["exitCode"] = 1
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(failed, bound, phase)
            calls = []
            positive_version = ("rustc " + expected_rust["release"] + "\nrelease: " + expected_rust["release"]
                                + "\ncommit-hash: " + expected_rust["commitHash"] + "\nhost: " + target + "\n")
            version = positive_version
            def probe(argv, **kw):
                calls.append((argv, kw))
                return version if kw["check"] == "rust-version-target" else "cargo 1.98.0 (abcdef123 2026-09-01)"
            with patch.object(helper, "ordinary"), patch.object(helper, "run", side_effect=probe), \
                    patch.object(helper.shutil, "which", side_effect=AssertionError("no ambient compiler")):
                env = {"PATH": "/selected/bin"}
                cargo, rustc = helper.tools(bound, env)
                prefix = "/Users/runner/.rustup/toolchains/stable-" + target + "/bin/"
                self.assertEqual((cargo, rustc), (prefix + "cargo", prefix + "rustc"))
                self.assertEqual([row[0] for row in calls], [[rustc, "-vV"], [cargo, "--version"]])
                self.assertEqual(env["RUSTC"], rustc)
                self.assertEqual(env["RUSTUP_AUTO_INSTALL"], "0")
                calls.clear()
                helper.tools(bound, {"PATH": "/selected/bin"}, timeout_for=lambda cap: min(cap, 3))
                self.assertEqual([row[1]["timeout"] for row in calls], [3, 3])
                wrong_versions = (
                    positive_version.replace("release: " + expected_rust["release"], "release: 1.0.0"),
                    positive_version.replace("commit-hash: " + expected_rust["commitHash"], "commit-hash: " + "0" * 40),
                    positive_version.replace("host: " + target, "host: " + other_target),
                    "rustc " + other_rust["release"] + "\nrelease: " + other_rust["release"]
                    + "\ncommit-hash: " + other_rust["commitHash"] + "\nhost: " + target + "\n",
                )
                for version in wrong_versions:
                    calls.clear()
                    with self.subTest(target=target, version=version), self.assertRaises(helper.CheckFailure):
                        helper.tools(bound, {"PATH": "/selected/bin"})
                    self.assertEqual([row[1]["check"] for row in calls], ["rust-version-target"])

        # A vault-only receipt cannot claim Node or any unentered normal graph.
        bound = mac_context("aarch64-apple-darwin", "vault-only")
        checks = {"acquire": ("rust-version-target", "mac-cargo-version", "mac-vault-locked-metadata"),
                  "compile": ("rust-version-target", "mac-cargo-version", "mac-vault-bin-compile-only")}
        for phase, selected in checks.items():
            value = {"schemaVersion": 1, "scope": "desktop-macos-normal-compile-only-v1", "phase": phase, "status": "passed",
                     **{key: bound[key] for key in ("sourceSha", "platform", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt", "sourceTree", "macCompile")},
                     "rust": deepcopy(MAC_RUST_EXPECTED["aarch64-apple-darwin"]), "node": None,
                     "checks": [{"check": check, "exitCode": 0} for check in selected]}
            self.assertEqual(helper.validate_compile_receipt(value, bound, phase), value)
            emitted = []
            with patch.object(helper, "write_json", side_effect=lambda path, frame: emitted.append((str(path), deepcopy(frame)))):
                helper.phase_receipt(bound, phase, list(selected), node=None)
                self.assertEqual(emitted, [(bound["root"] + "/" + phase + "-checks.json", value)])
                emitted.clear()
                with self.assertRaises(helper.CheckFailure):
                    helper.phase_receipt(bound, phase, list(helper.MAC_COMPILE_CHECKS[phase]), node=helper.NODE)
                self.assertFalse(emitted)
            for key, bad in (("node", helper.NODE), ("checks", value["checks"][:-1]),
                             ("checks", [{"check": check, "exitCode": 0} for check in helper.MAC_COMPILE_CHECKS[phase]]),
                             ("macCompile", mac_context()["macCompile"]), ("sourceSha", "4" * 40)):
                with self.subTest(phase=phase, key=key), self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt({**value, key: bad}, bound, phase)
            altered = deepcopy(bound["macCompile"]); del altered["mode"]
            bad_contexts = (altered, {**bound["macCompile"], "mode": None},
                            {**bound["macCompile"], "mode": "normal3"},
                            {**bound["macCompile"], "mode": "full4"},
                            {**bound["macCompile"], "target": "x86_64-apple-darwin"},
                            {**bound["macCompile"], "graphs": []})
            for bad in bad_contexts:
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(value, {**bound, "macCompile": bad}, phase)
        full = mac_context()
        normal_only = deepcopy(full["macCompile"])
        normal_only["graphs"] = normal_only["graphs"][1:]
        with self.assertRaises(helper.CheckFailure):
            helper.validate_compile_receipt(value, {**full, "macCompile": normal_only}, "compile")

        # Reuse the actual direct Mac tools and phase receipt code with local
        # original-command doubles. No rustup discovery/install or libtest is
        # performed by this fixed main-only profile; old profiles above persist.
        bound = engineering_context()
        expected_checks = {
            "acquire": ("rust-version-target", "mac-cargo-version", "locked-platform-metadata", "node-version", "npm-locked-no-scripts"),
            "compile": ("rust-version-target", "mac-cargo-version", "node-version", "typescript-no-emit", "vite-assets", "tauri-debug-compile-only"),
        }
        self.assertEqual(helper.ENGINEERING_COMPILE_CHECKS, expected_checks)
        for phase, checks in expected_checks.items():
            calls, events, published, discovered = [], [], [], []
            MemoryPath, _ = memory_paths(events)
            def original_call(argv, **kwargs):
                calls.append((list(map(str, argv)), {**kwargs, "env": dict(kwargs["env"])}))
                if kwargs["check"] == "rust-version-target":
                    return "rustc 1.98.1\nrelease: 1.98.1\ncommit-hash: 48a229ceaefd4985c50990b14116b6d856af0985\nhost: aarch64-apple-darwin\n"
                if kwargs["check"] == "mac-cargo-version":
                    return "cargo 1.98.1 (abcdef123 2026-09-01)"
                if kwargs["check"] == "node-version":
                    return "v24.20.0"
                return ""
            def selected_tool(name):
                discovered.append(name)
                self.assertEqual(name, "node")
                return "/selected/bin/node"
            with patch.object(helper, "Path", MemoryPath), patch.object(helper, "load_context", return_value=bound), \
                    patch.object(helper, "copy_engineering_main", return_value={"relativePath": "target/engineering-main/mobile-release-kit-desktop", "bytes": 32, "sha256": "4" * 64}), \
                    patch.object(helper, "source_unchanged"), patch.object(helper, "ordinary"), \
                    patch.object(helper, "no_cargo_configuration"), patch.object(helper, "run", side_effect=original_call), \
                    patch.object(helper.shutil, "which", side_effect=selected_tool), \
                    patch.dict(helper.os.environ, {"PATH": "/selected/bin"}, clear=True), \
                    patch.object(helper, "write_json", side_effect=lambda path, value: published.append((str(path), deepcopy(value)))):
                helper.phase(phase, "macos", helper.ENGINEERING_COMPILE_SCOPE)
            self.assertEqual([row[1]["check"] for row in calls], list(checks))
            self.assertEqual(discovered, ["node"])
            self.assertEqual(len(published), 1)
            value = published[0][1]
            self.assertEqual(value["scope"], "desktop-macos-engineering-ui-compile-only-v1")
            self.assertEqual(value["engineeringWork"], bound["engineeringWork"])
            self.assertEqual(value["sourceTree"], bound["sourceTree"])
            self.assertEqual(value["rust"], MAC_RUST_EXPECTED["aarch64-apple-darwin"])
            self.assertEqual(helper.validate_compile_receipt(value, bound, phase), value)
            for key, bad in (("scope", helper.COMPILE_EVIDENCE_SCOPE), ("engineeringWork", "/foreign/work"),
                             ("sourceTree", "f" * 40), ("checks", value["checks"][:-1]),
                             ("rust", MAC_RUST_EXPECTED["x86_64-apple-darwin"])):
                with self.subTest(engineering_receipt=key, phase=phase), self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt({**value, key: bad}, bound, phase)
            cargo_commands = [row for row in calls if row[0][0].endswith("/cargo") and row[1]["check"] != "mac-cargo-version"]
            self.assertEqual(len(cargo_commands), 1)
            argv, kwargs = cargo_commands[0]
            self.assertTrue(argv[0].startswith("/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin/"))
            self.assertIn("--locked", argv)
            self.assertEqual(argv[argv.index("--features") + 1], "desktop-shell,custom-protocol,development-runtime")
            self.assertEqual(kwargs["env"]["RUSTUP_AUTO_INSTALL"], "0")
            self.assertEqual(kwargs["env"]["TAURI_CONFIG"], '{"identifier":"dev.mobile-release-kit.engineering-ui"}')
            self.assertNotIn("test", argv)
            if phase == "compile":
                self.assertIn("--offline", argv)
                self.assertEqual(argv[argv.index("--bin") + 1], "mobile-release-kit-desktop")
                self.assertEqual(kwargs["timeout"], 1500)
            self.assertTrue(all(not any("rustup" == part for part in row[0]) for row in calls))

        # Exercise the real streaming copy with in-memory original descriptors.
        # Cargo's primary has TWO links, but the newly published file must have
        # exactly one. No host path/open/write or binary execution occurs here.
        OriginalOS = helper.os
        class CopyOS:
            def __init__(self, fault):
                self.fault, self.nodes, self.fds, self.opened, self.closed = fault, {}, {}, [], []
                self.writes = 0
                self.next_fd = 100
                for flag in ("O_RDONLY", "O_RDWR", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_CREAT", "O_EXCL"):
                    setattr(self, flag, getattr(OriginalOS, flag))
                root = PurePosixPath(bound["root"])
                for path in (root, root / "target", root / "target/aarch64-apple-darwin", root / "target/aarch64-apple-darwin/debug"):
                    self.add(str(path), 0o40700)
                self.source = str(root / "target/aarch64-apple-darwin/debug/mobile-release-kit-desktop")
                self.output = str(root / "target/engineering-main/mobile-release-kit-desktop")
                self.add(self.source, 0o100755, b"actual compiled main fixture bytes", links=2)
                if fault == "source-symlink":
                    self.nodes[self.source]["mode"] = 0o120777
            def add(self, path, mode, body=b"", links=1):
                self.nodes[path] = {"mode": mode, "body": bytearray(body), "links": links, "ino": len(self.nodes) + 10}
            def get(self, path, dir_fd=None):
                return str(PurePosixPath(self.fds[dir_fd]) / str(path)) if dir_fd is not None else str(path)
            def geteuid(self):
                return 501
            def open(self, path, flags, mode=0o777, *, dir_fd=None):
                name = self.get(path, dir_fd)
                if flags & self.O_CREAT:
                    if name in self.nodes:
                        raise FileExistsError("exclusive fixture output")
                    self.add(name, 0o100000 | mode)
                node = self.nodes[name]
                if node["mode"] & 0o170000 == 0o120000:
                    raise OSError("no-follow fixture")
                if flags & self.O_DIRECTORY:
                    self.assert_directory(node)
                fd = self.next_fd
                self.next_fd += 1
                self.fds[fd] = name
                self.opened.append(fd)
                return fd
            def assert_directory(self, node):
                if node["mode"] & 0o170000 != 0o40000:
                    raise OSError("directory fixture")
            def mkdir(self, path, mode, *, dir_fd=None):
                name = self.get(path, dir_fd)
                if name in self.nodes:
                    raise FileExistsError("directory exists")
                self.add(name, 0o40000 | mode)
            def details(self, name):
                node = self.nodes[name]
                class Details:
                    pass
                value = Details()
                values = dict(st_dev=1, st_ino=node["ino"], st_mode=node["mode"], st_uid=501, st_gid=20,
                              st_nlink=node["links"], st_size=len(node["body"]), st_mtime_ns=1, st_ctime_ns=1)
                if name == self.source and self.fault == "oversized":
                    values["st_size"] = 256 * 1024 * 1024 + 1
                if name == self.source and self.fault == "original-changed" and self.writes:
                    values["st_mtime_ns"] = 2
                if name == self.output and self.fault == "copy-hardlink":
                    values["st_nlink"] = 2
                for key, item in values.items():
                    setattr(value, key, item)
                return value
            def fstat(self, fd):
                return self.details(self.fds[fd])
            def stat(self, path, *, dir_fd=None, follow_symlinks=True):
                if follow_symlinks:
                    raise AssertionError("copy must not follow names")
                return self.details(self.get(path, dir_fd))
            def pread(self, fd, size, offset):
                name = self.fds[fd]
                body = bytes(self.nodes[name]["body"])
                if name == self.source and self.fault == "early-eof":
                    body = body[:-1]
                if name == self.output and self.fault == "readback-changed":
                    body = b"!" + body[1:]
                return body[offset:offset + size]
            def write(self, fd, body):
                if self.fault == "write-zero":
                    return 0
                size = min(len(body), 3)  # Real code must complete partial writes.
                self.nodes[self.fds[fd]]["body"].extend(body[:size])
                self.writes += 1
                return size
            def fsync(self, fd):
                if self.fault == "fsync-failed":
                    raise OSError("fixture fsync")
            def close(self, fd):
                name = self.fds.pop(fd)
                self.closed.append(fd)
                if self.fault == "close-failed" and name == self.source:
                    raise OSError("consumed fixture close")
        for fault in (None, "source-symlink", "oversized", "original-changed", "copy-hardlink",
                      "early-eof", "readback-changed", "write-zero", "fsync-failed", "close-failed", "timeout", "late-close"):
            original = CopyOS(fault)
            class Clock:
                calls = 0
                def monotonic(self):
                    self.calls += 1
                    return (31 if fault == "timeout" and self.calls > 1
                            or fault == "late-close" and original.opened and len(original.closed) == len(original.opened) else 0)
            with self.subTest(copy_fault=fault), patch.object(helper, "os", original), patch.object(helper, "time", Clock()):
                if fault is None:
                    copied = helper.copy_engineering_main(bound)
                    self.assertEqual(copied, {"relativePath": "target/engineering-main/mobile-release-kit-desktop",
                        "bytes": 34, "sha256": helper.hashlib.sha256(b"actual compiled main fixture bytes").hexdigest()})
                    self.assertEqual(bytes(original.nodes[original.output]["body"]), b"actual compiled main fixture bytes")
                    self.assertEqual(original.nodes[original.source]["links"], 2)
                    self.assertEqual(original.nodes[original.output]["links"], 1)
                    self.assertGreater(original.writes, 1)
                else:
                    with self.assertRaises((helper.CheckFailure, OSError)):
                        helper.copy_engineering_main(bound)
            self.assertEqual(original.fds, {})
            self.assertEqual(sorted(original.closed), sorted(original.opened))
            self.assertEqual(len(original.closed), len(set(original.closed)))
        self.assertIs(helper.os, OriginalOS)
        for bad in ({"relativePath": "target/debug/foreign", "bytes": 1, "sha256": "4" * 64},
                    {"relativePath": helper.ENGINEERING_MAIN_RELATIVE, "bytes": True, "sha256": "4" * 64},
                    {"relativePath": helper.ENGINEERING_MAIN_RELATIVE, "bytes": 256 * 1024 * 1024 + 1, "sha256": "4" * 64},
                    {"relativePath": helper.ENGINEERING_MAIN_RELATIVE, "bytes": 1, "sha256": "0" * 64}):
            with self.subTest(copy_receipt=bad), self.assertRaises(helper.CheckFailure):
                helper.validate_engineering_main(bad)

        # Exact completion DATA is separate from mere compile receipts. A
        # missing/nonzero/unknown UI original cannot authorize even first delete.
        digests = {key: "a" * 64 for key in ("compilerReceiptSha256", "runtimeResultSha256", "runtimeManifestSha256",
            "testAdmissionSha256", "summaryAdmissionSha256", "nativeSummarySha256")}
        completed = {"schemaVersion": 1, "scope": "engineering-main-ui-smoke-only", "status": "passed",
            **{key: bound[key] for key in ("sourceSha", "sourceTree", "workflowPath", "workflowSha", "workflowRef",
                                         "workflowSha256", "runId", "attempt", "engineeringWork")},
            "compilerRoot": bound["root"], "target": "aarch64-apple-darwin", **digests,
            "compilerBinarySha256": "4" * 64, "runtimeRosterSha256": "b" * 64, "applicationRosterSha256": "c" * 64,
            "testIdentifier": "MRKNormalAppUITests/NormalAppUITests/testEngineeringMainCatalogueAndQuit",
            "testCounts": {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0},
            "sameOriginalNormalQuitObserved": True, "cleanExitStatus": None, "allWorkerFinality": "not-established",
            "fullUIQualified": False, "productReady": False, "sourcePrePostMatched": True, "inputPrePostMatched": True,
            "inputOriginalClosesCompleted": True, "generatedRunnerOriginalClosesCompleted": True,
            "originalCommandsReturned": True, "originalWrapperZeroRequired": True}
        compiled = {"compiledMain": {"relativePath": "target/engineering-main/mobile-release-kit-desktop", "bytes": 32, "sha256": "4" * 64}}
        self.assertEqual(len(completed), 36)
        self.assertIs(helper.validate_engineering_cleanup(completed, bound, compiled, digests), completed)
        for key, bad in (("sourceSha", "f" * 40), ("sourceTree", "e" * 40), ("runId", "456"), ("attempt", "3"),
                         ("compilerRoot", "/foreign/root"), ("engineeringWork", "/foreign/work"),
                         ("target", "x86_64-apple-darwin"), ("sameOriginalNormalQuitObserved", False),
                         ("inputOriginalClosesCompleted", False), ("generatedRunnerOriginalClosesCompleted", False),
                         ("sourcePrePostMatched", False), ("inputPrePostMatched", False), ("originalCommandsReturned", False),
                         ("originalWrapperZeroRequired", False), ("cleanExitStatus", 0), ("allWorkerFinality", "known"),
                         ("fullUIQualified", True), ("productReady", True), ("compilerBinarySha256", "5" * 64),
                         ("compilerReceiptSha256", "6" * 64), ("runtimeResultSha256", "7" * 64),
                         ("nativeSummarySha256", "8" * 64), ("unexpected", True)):
            with self.subTest(cleanup_field=key), self.assertRaises(helper.CheckFailure):
                helper.validate_engineering_cleanup({**completed, key: bad}, bound, compiled, digests)
        for counts in ({**completed["testCounts"], "skippedTests": 1}, {**completed["testCounts"], "totalTestCount": 2},
                       {**completed["testCounts"], "passedTests": True}):
            with self.assertRaises(helper.CheckFailure):
                helper.validate_engineering_cleanup({**completed, "testCounts": counts}, bound, compiled, digests)
        with patch.object(helper, "engineering_cleanup", side_effect=helper.CheckFailure("unknown UI original")) as terminal, \
                patch.object(helper.shutil, "rmtree", side_effect=AssertionError("must not delete before positive UI")):
            with self.assertRaises(helper.CheckFailure):
                helper.clean_compile(bound)
            terminal.assert_called_once_with(bound)

        # A compile0 is not the DATA test: both original checks, exact selector,
        # one nonignored result and the same source/tree/run are mandatory.
        bound = source_slots_context()
        for phase in ("acquire", "compile"):
            positive = source_slots_receipt(phase)
            self.assertEqual(helper.validate_compile_receipt(positive, bound, phase), positive)
            published = []
            with patch.object(helper, "write_json", side_effect=lambda path, value: published.append((str(path), deepcopy(value)))):
                helper.phase_receipt(bound, phase, [row["check"] for row in positive["checks"]], node=None,
                                     source_slots_result=source_slots_result() if phase == "compile" else None)
            self.assertEqual(published, [(bound["root"] + "/" + phase + "-checks.json", positive)])
            for key, bad in (("scope", "desktop-macos-normal-compile-only-v1"), ("sourceTree", "4" * 40),
                             ("sourceSha", "4" * 40), ("workflowSha256", "4" * 64), ("attempt", "3"),
                             ("node", helper.NODE), ("rust", MAC_RUST_EXPECTED["aarch64-apple-darwin"]),
                             ("checks", positive["checks"][:-1]), ("checks", list(reversed(positive["checks"]))),
                             ("extra", None), ("sourceSlots", {**positive["sourceSlots"], "features": []})):
                with self.subTest(source_slots_phase=phase, field=key), self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt({**deepcopy(positive), key: bad}, bound, phase)
            for check_index in range(len(positive["checks"])):
                for exit_code in (False, 1, None):
                    bad = deepcopy(positive); bad["checks"][check_index]["exitCode"] = exit_code
                    with self.assertRaises(helper.CheckFailure):
                        helper.validate_compile_receipt(bad, bound, phase)
            changed = deepcopy(bound); changed["sourceSlots"]["target"] = "aarch64-apple-darwin"
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_receipt(positive, changed, phase)
        for bad in (None, {}, {**source_slots_result(), "passed": 0}, {**source_slots_result(), "running": 2},
                    {**source_slots_result(), "passed": True}, {**source_slots_result(), "ignored": 1},
                    {**source_slots_result(), "failed": 1}, {**source_slots_result(), "measured": 1},
                    {**source_slots_result(), "test": "other::test"}, {**source_slots_result(), "filtered": -1},
                    {**source_slots_result(), "filtered": 65536}, {**source_slots_result(), "filtered": False},
                    {**source_slots_result(), "extra": 0}):
            with self.subTest(result=bad), self.assertRaises(helper.CheckFailure):
                helper.validate_compile_receipt({**source_slots_receipt("compile"), "testResult": bad}, bound, "compile")
        missing = source_slots_receipt("compile"); del missing["testResult"]
        with self.assertRaises(helper.CheckFailure):
            helper.validate_compile_receipt(missing, bound, "compile")
        with self.assertRaises(helper.CheckFailure):
            helper.validate_compile_receipt({**source_slots_receipt("acquire"), "testResult": source_slots_result()}, bound, "acquire")
        published = []
        with patch.object(helper, "write_json", side_effect=lambda *args: published.append(args)):
            for wrong_node, wrong_result in ((helper.NODE, source_slots_result()), (None, None)):
                with self.assertRaises(helper.CheckFailure):
                    helper.phase_receipt(bound, "compile", [row["check"] for row in source_slots_receipt("compile")["checks"]],
                                         node=wrong_node, source_slots_result=wrong_result)
            with self.assertRaises(helper.CheckFailure):
                helper.phase_receipt(bound, "acquire", [row["check"] for row in source_slots_receipt("acquire")["checks"]],
                                     source_slots_result=source_slots_result())
        self.assertFalse(published)
        positive_stdout = source_slots_stdout()
        self.assertEqual(helper.source_slots_test_result(positive_stdout), source_slots_result())
        for broken in (b"", b"\xff", positive_stdout.decode(), b" " * (1024 * 1024 + 1),
                       positive_stdout.replace(b"running 1 test", b"running 0 tests"),
                       positive_stdout.replace(b"running 1 test", b"running 2 tests"),
                       positive_stdout.replace(b"1 passed", b"0 passed"),
                       positive_stdout.replace(b"0 failed", b"1 failed"),
                       positive_stdout.replace(b"0 ignored", b"1 ignored"),
                       positive_stdout.replace(b"... ok", b"... ignored"),
                       positive_stdout.replace(SOURCE_SLOTS_CASE.encode(), b"other::test"),
                       positive_stdout.replace(b"7 filtered", b"65536 filtered"),
                       b"compiler diagnostic\n" + positive_stdout, positive_stdout + positive_stdout):
            with self.subTest(stdout=broken[:80]), self.assertRaises(helper.CheckFailure):
                helper.source_slots_test_result(broken)


        b = intel_removal_context()
        for phase in ("acquire", "compile"):
            expected = intel_removal_receipt(phase)
            self.assertEqual(helper.validate_compile_receipt(expected, b, phase), expected)
            published = []
            with patch.object(helper, "write_json", side_effect=lambda path, value: published.append((str(path), deepcopy(value)))):
                helper.phase_receipt(b, phase, [row["check"] for row in expected["checks"]], node=None,
                                     source_slots_result=intel_removal_result() if phase == "compile" else None)
            self.assertEqual(published, [(b["root"] + "/" + phase + "-checks.json", expected)])
            for wrong, ctx in ((source_slots_receipt(phase), b), (expected, source_slots_context())):
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(wrong, ctx, phase)
            for key, value in (("sourceSlotsBuild", None), ("sourceSlots", source_slots_context()["sourceSlots"]),
                               ("scope", "desktop-macos-intel-source-slots-data-v1"), ("sourceTree", "f" * 40)):
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt({**expected, key: value}, b, phase)
        valid = intel_removal_stdout()
        self.assertEqual(helper.source_slots_removal_test_result(valid), intel_removal_result())
        swapped = valid.replace(INTEL_REMOVAL_CASES[0].encode(), b"swap").replace(
            INTEL_REMOVAL_CASES[1].encode(), INTEL_REMOVAL_CASES[0].encode()).replace(b"swap", INTEL_REMOVAL_CASES[1].encode())
        for bad in (b"", b"\xff", valid.decode(), b"x" * (1024 * 1024 + 1), source_slots_stdout(),
                    valid.replace(b"running 3", b"running 0"), valid.replace(b"3 passed", b"2 passed"),
                    valid.replace(b"0 ignored", b"1 ignored"), valid.replace(b"0 failed", b"1 failed"),
                    valid.replace(b"... ok", b"... ignored", 1), valid[:-3], valid + b"extra\n", valid + valid,
                    valid.replace(INTEL_REMOVAL_CASES[0].encode(), INTEL_REMOVAL_CASES[1].encode()),
                    valid.replace(("test " + INTEL_REMOVAL_CASES[0] + " ... ok\n").encode(), b""),
                    valid.replace(b"7 filtered", b"65536 filtered"), swapped):
            with self.subTest(b_output=str(bad)[:60]), self.assertRaises(helper.CheckFailure):
                helper.source_slots_removal_test_result(bad)
        for key, value in (("passed", True), ("failed", 1), ("running", 2), ("filtered", False),
                           ("tests", list(reversed(INTEL_REMOVAL_CASES))), ("tests", tuple(INTEL_REMOVAL_CASES))):
            with self.assertRaises(helper.CheckFailure):
                helper.validate_source_slots_removal_result({**intel_removal_result(), key: value})

        # Exercise the actual selected B phase and owner branches, not a model.
        order = ["rust-version-target", "mac-cargo-version", "headless-test-compile-only", "mac-source-slots-data-test"]
        for fault in (None, "compile-returned", "compile-unknown", "test-returned", "wrong-result", "read", "close",
                      "source-post", "projection-post", "late-test", "reverse", "late-receipt"):
            events, captures, calls, published, clock, posts = [], {}, [], [], [100.0], []
            SlotsPath, writer, read = source_slots_paths(events, captures)
            class FailingClosePath(SlotsPath):
                def open(self, *args, **kwargs):
                    stream = super().open(*args, **kwargs)
                    if fault != "close" or self.name != "source-slots-compile.stderr":
                        return stream
                    class Guard:
                        def __enter__(self):
                            return stream.__enter__()
                        def __exit__(self, *args):
                            stream.__exit__(*args)
                            raise OSError("consumed close unknown")
                    return Guard()
            def source_post(*args, **kwargs):
                posts.append("source")
                if fault == "source-post" and posts.count("source") == 2:
                    raise helper.CheckFailure("actual source POST")
            def build_post(path):
                self.assertEqual(str(path), b["source"])
                posts.append("build")
                if fault == "projection-post" and posts.count("build") == 2:
                    return {**intel_removal_build(), "release": "macos26-x86_64-changed"}
                return intel_removal_build()
            def invoke(argv, **kw):
                calls.append((list(map(str, argv)), {**kw, "env": dict(kw["env"])}))
                check = kw["check"]
                if check == "rust-version-target":
                    return "release: 1.98.0\ncommit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\nhost: x86_64-apple-darwin"
                if check == "mac-cargo-version":
                    return "cargo 1.98.0 (abcdef123 2026-09-01)"
                if check == "headless-test-compile-only" and fault in ("compile-returned", "compile-unknown"):
                    error = helper.CheckFailure("actual compile failure")
                    if fault == "compile-returned":
                        error._returned_command = (check, 101)
                    raise error
                if check == "mac-source-slots-data-test":
                    kw["output"].write((source_slots_stdout() if fault == "wrong-result" else valid).decode())
                    if fault == "test-returned":
                        error = helper.CheckFailure("actual test failure"); error._returned_command = (check, 101); raise error
                    if fault == "late-test": clock[0] = 970.0
                    if fault == "reverse": clock[0] = 99.0
                return ""
            def capture_read(path, original, **kwargs):
                if fault == "read":
                    raise helper.CheckFailure("actual output readback")
                return read(path, original)
            def publish(path, value):
                published.append((str(path), deepcopy(value)))
                if fault == "late-receipt" and path.name == "compile-checks.json": clock[0] = 970.0
            with self.subTest(b_phase=fault), patch.object(helper, "Path", FailingClosePath), \
                    patch.object(helper, "ordinary"), patch.object(helper, "source_unchanged", side_effect=source_post), \
                    patch.object(helper, "source_slots_source_guard"), patch.object(helper, "source_slots_build_inputs", side_effect=build_post), \
                    patch.object(helper, "run", side_effect=invoke), patch.object(helper, "source_slots_writer", side_effect=writer), \
                    patch.object(helper, "source_slots_read", side_effect=capture_read), patch.object(helper, "write_json", side_effect=publish), \
                    patch.object(helper, "source_slots_compiler_diagnostic", return_value={"state": "unavailable", "reason": "cargo-json-unavailable", "returnCode": 101, "errors": [], "sources": []}), \
                    patch.object(helper.time, "monotonic", side_effect=lambda: clock[0]), \
                    patch.dict(helper.os.environ, {"PATH": "/selected/bin", "MRK_MACOS_DEVELOPER_ID_P12_BASE64": "inert-not-forwarded"}, clear=True):
                if fault is None:
                    helper.phase_source_slots("compile", b)
                else:
                    with self.assertRaises((helper.CheckFailure, OSError)):
                        helper.phase_source_slots("compile", b)
            checks = [kw["check"] for _, kw in calls]
            self.assertEqual(checks, order[:-1] if fault in ("compile-returned", "compile-unknown", "read", "close") else order)
            for argv, kw in calls:
                if "output" not in kw: continue
                common = ["--locked", "--offline", "--jobs", "1", "--no-default-features", "--features", "macos-installed-removal-abrupt-fixture",
                          "--target", "x86_64-apple-darwin", "--manifest-path", b["source"] + "/desktop/src-tauri/Cargo.toml",
                          "--target-dir", b["root"] + "/target", "--bin", "mrk-macos-remove"]
                tail = ["--message-format=short", "--color", "never"] + (["--no-run"] if kw["check"] == "headless-test-compile-only"
                        else ["--", "--exact", "--test-threads=1", "--format", "pretty", "--color", "never", *INTEL_REMOVAL_CASES])
                self.assertNotIn("--message-format=json,json-diagnostic-short", argv)
                self.assertNotIn("RUSTFLAGS", kw["env"])
                self.assertNotIn("CARGO_ENCODED_RUSTFLAGS", kw["env"])
                self.assertEqual(argv, ["/Users/runner/.rustup/toolchains/stable-x86_64-apple-darwin/bin/cargo", "test", *common, *tail])
                self.assertEqual(kw["timeout"], 600 if kw["check"] == "headless-test-compile-only" else 150)
                self.assertEqual(kw["env"]["MRK_MACOS_INSTALL_SOURCE_COMMIT"], b["sourceSha"])
                self.assertEqual(kw["env"]["MRK_IMAGE_RELEASE_ID"], b["sourceSlotsBuild"]["release"])
                self.assertNotIn("MRK_MACOS_DEVELOPER_ID_P12_BASE64", kw["env"])
                self.assertTrue(kw["output"].closed and kw["diagnostics"].closed)
            passed = [value for path, value in published if path.endswith("/compile-checks.json")]
            failures = [value for path, value in published if path.endswith("/source-slots-failure.json")]
            self.assertEqual(passed, [intel_removal_receipt("compile")] if fault in (None, "late-receipt") else [])
            self.assertEqual(len(failures), int(fault is not None))
            for failure in failures:
                self.assertEqual(failure["scope"], "desktop-macos-intel-removal-abrupt-data-v1")
                self.assertEqual(failure["sourceSlots"], b["sourceSlots"])
                self.assertEqual(failure["sourceSlotsBuild"], b["sourceSlotsBuild"])
                self.assertEqual(failure["status"], "failed-or-unknown")
                self.assertLessEqual(len(json.dumps(failure).encode()), 16384)
                if fault in ("compile-returned", "test-returned"):
                    self.assertEqual(failure["originalCommandReturnCode"], 101)
                if fault == "compile-unknown": self.assertIsNone(failure["originalCommandReturnCode"])
            if fault is None:
                self.assertEqual(posts, ["source", "build", "build", "source"])
                self.assertEqual(len([event for event in events if event[0] == "closed"]), 4)


        # C's result and receipt are not old allocation/remover qualification.
        c, positive = initialization_context(), initialization_stdout()
        self.assertEqual(helper.source_slots_initialization_test_result(positive), initialization_result())
        swapped = positive.replace(INITIALIZATION_CASES[0].encode(), b"swap").replace(
            INITIALIZATION_CASES[1].encode(), INITIALIZATION_CASES[0].encode()).replace(b"swap", INITIALIZATION_CASES[1].encode())
        for broken in (b"", b"\xff", positive.decode(), b"x" * (1024 * 1024 + 1), source_slots_stdout(), intel_removal_stdout(),
                       positive.replace(b"running 4 tests", b"running 0 tests"), positive.replace(b"4 passed", b"0 passed"),
                       positive.replace(b"0 failed", b"1 failed"), positive.replace(b"0 ignored", b"1 ignored"),
                       positive.replace(b"... ok", b"... ignored", 1), positive.replace(b"7 filtered", b"65536 filtered"),
                       positive.replace(INITIALIZATION_CASES[0].encode(), INITIALIZATION_CASES[1].encode()),
                       positive.replace(("test " + INITIALIZATION_CASES[0] + " ... ok\n").encode(), b""),
                       positive + positive, positive + b"extra\n", swapped):
            with self.assertRaises(helper.CheckFailure):
                helper.source_slots_initialization_test_result(broken)
        for key, value in (("passed", True), ("running", 3), ("ignored", 1), ("filtered", False),
                           ("tests", list(reversed(INITIALIZATION_CASES))), ("tests", tuple(INITIALIZATION_CASES))):
            with self.assertRaises(helper.CheckFailure):
                helper.validate_source_slots_initialization_result({**initialization_result(), key: value})
        for phase in ("acquire", "compile"):
            expected = initialization_receipt(phase); published = []
            self.assertEqual(helper.validate_compile_receipt(expected, c, phase), expected)
            with patch.object(helper, "write_json", side_effect=lambda path, value: published.append((str(path), deepcopy(value)))):
                helper.phase_receipt(c, phase, [row["check"] for row in expected["checks"]], node=None,
                                     source_slots_result=initialization_result() if phase == "compile" else None)
            self.assertEqual(published, [(c["root"] + "/" + phase + "-checks.json", expected)])
            for other in (source_slots_context(), intel_removal_context()):
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(expected, other, phase)
            for key, value in (("scope", helper.SOURCE_SLOTS_EVIDENCE), ("sourceSlotsSelection", "allocation1"),
                               ("sourceSlots", source_slots_context()["sourceSlots"]), ("node", helper.NODE), ("attempt", "100")):
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt({**expected, key: value}, c, phase)
        for result in (source_slots_result(), intel_removal_result(), None):
            with patch.object(helper, "write_json", side_effect=AssertionError("no false publication")), self.assertRaises(helper.CheckFailure):
                helper.phase_receipt(c, "compile", list(helper.SOURCE_SLOTS_CHECKS["compile"]), source_slots_result=result)

        # D's result and receipt are not old allocation/remover qualification.
        artifact_bound, artifact_positive = artifact_context(), artifact_stdout()
        self.assertEqual(helper.source_slots_artifact_test_result(artifact_positive), artifact_result())
        # The unpublished old7 is no longer a successful selector or receipt.
        artifact_old_cases = tuple(name for name in ARTIFACT_CASES if name not in (ARTIFACT_CASES[4], ARTIFACT_CASES[5], ARTIFACT_CASES[9]))
        self.assertEqual(len(artifact_old_cases), 7)
        artifact_old_stdout = ("\nrunning 7 tests\n" + "".join("test " + name + " ... ok\n" for name in artifact_old_cases)
            + "\ntest result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.03s\n\n").encode()
        with self.assertRaises(helper.CheckFailure):
            helper.source_slots_artifact_test_result(artifact_old_stdout)
        artifact_old_result = {**artifact_result(), "tests": list(artifact_old_cases), "running": 7, "passed": 7}
        with self.assertRaises(helper.CheckFailure):
            helper.validate_source_slots_artifact_result(artifact_old_result)
        for artifact_added_index in (4, 5, 9):
            artifact_added_row = ("test " + ARTIFACT_CASES[artifact_added_index] + " ... ok\n").encode()
            for artifact_bad in (artifact_positive.replace(artifact_added_row, b""),
                                 artifact_positive.replace(artifact_added_row, artifact_added_row * 2),
                                 artifact_positive.replace(ARTIFACT_CASES[artifact_added_index].encode(), ARTIFACT_CASES[0].encode())):
                with self.assertRaises(helper.CheckFailure):
                    helper.source_slots_artifact_test_result(artifact_bad)
        artifact_added_swap = artifact_positive.replace(ARTIFACT_CASES[4].encode(), b"swap").replace(
            ARTIFACT_CASES[5].encode(), ARTIFACT_CASES[4].encode()).replace(b"swap", ARTIFACT_CASES[5].encode())
        with self.assertRaises(helper.CheckFailure):
            helper.source_slots_artifact_test_result(artifact_added_swap)
        swapped = artifact_positive.replace(ARTIFACT_CASES[0].encode(), b"swap").replace(
            ARTIFACT_CASES[1].encode(), ARTIFACT_CASES[0].encode()).replace(b"swap", ARTIFACT_CASES[1].encode())
        for broken in (b"", b"\xff", artifact_positive.decode(), b"x" * (1024 * 1024 + 1), source_slots_stdout(), intel_removal_stdout(), initialization_stdout(),
                       artifact_positive.replace(b"running 10 tests", b"running 0 tests"), artifact_positive.replace(b"10 passed", b"0 passed"),
                       artifact_positive.replace(b"0 failed", b"1 failed"), artifact_positive.replace(b"0 ignored", b"1 ignored"),
                       artifact_positive.replace(b"... ok", b"... ignored", 1), artifact_positive.replace(b"7 filtered", b"65536 filtered"),
                       artifact_positive.replace(ARTIFACT_CASES[0].encode(), ARTIFACT_CASES[1].encode()),
                       artifact_positive.replace(("test " + ARTIFACT_CASES[0] + " ... ok\n").encode(), b""),
                       artifact_positive + artifact_positive, artifact_positive + b"extra\n", swapped):
            with self.assertRaises(helper.CheckFailure):
                helper.source_slots_artifact_test_result(broken)
        for key, value in (("passed", True), ("running", 3), ("ignored", 1), ("filtered", False),
                           ("tests", list(reversed(ARTIFACT_CASES))), ("tests", tuple(ARTIFACT_CASES))):
            with self.assertRaises(helper.CheckFailure):
                helper.validate_source_slots_artifact_result({**artifact_result(), key: value})
        for phase in ("acquire", "compile"):
            expected = artifact_receipt(phase); published = []
            self.assertEqual(helper.validate_compile_receipt(expected, artifact_bound, phase), expected)
            for artifact_stale in ({**expected, "sourceSlotsSelection": "artifact-inspection7"},
                                   {**expected, "scope": "desktop-macos-artifact-inspection-data-v1"}):
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(artifact_stale, artifact_bound, phase)
            if phase == "compile":
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt({**expected, "testResult": artifact_old_result}, artifact_bound, phase)
            with patch.object(helper, "write_json", side_effect=lambda path, value: published.append((str(path), deepcopy(value)))):
                helper.phase_receipt(artifact_bound, phase, [row["check"] for row in expected["checks"]], node=None,
                                     source_slots_result=artifact_result() if phase == "compile" else None)
            self.assertEqual(published, [(artifact_bound["root"] + "/" + phase + "-checks.json", expected)])
            for other in (source_slots_context(), intel_removal_context(), initialization_context()):
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(expected, other, phase)
            for key, value in (("scope", helper.SOURCE_SLOTS_EVIDENCE), ("sourceSlotsSelection", "allocation1"),
                               ("sourceSlots", source_slots_context()["sourceSlots"]), ("node", helper.NODE), ("attempt", "100")):
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt({**expected, key: value}, artifact_bound, phase)
        for artifact_bad_result in (source_slots_result(), intel_removal_result(), initialization_result(), None):
            with patch.object(helper, "write_json", side_effect=AssertionError("no false publication")), self.assertRaises(helper.CheckFailure):
                helper.phase_receipt(artifact_bound, "compile", list(helper.SOURCE_SLOTS_CHECKS["compile"]), source_slots_result=artifact_bad_result)

        # Environment's exact one-case receipt cannot borrow old DATA1/4/10.
        env_bound=environment_setup_context(); positive=environment_setup_stdout()
        self.assertEqual(helper.SOURCE_SLOTS_ENVIRONMENT_TESTS, ENVIRONMENT_CASES)
        self.assertEqual(helper.source_slots_environment_test_result(positive),environment_setup_result())
        for bad in (b"",b"\xff",positive.decode(),b"x"*(1024*1024+1),source_slots_stdout(),intel_removal_stdout(),
                    initialization_stdout(),artifact_stdout(),positive+positive,positive+b"extra\n",
                    positive.replace(b"running 1 test",b"running 0 tests"),positive.replace(b"1 passed",b"0 passed"),
                    positive.replace(b"0 failed",b"1 failed"),positive.replace(b"0 ignored",b"1 ignored"),
                    positive.replace(b"... ok",b"... ignored"),positive.replace(b"7 filtered",b"65536 filtered"),
                    positive.replace(ENVIRONMENT_CASES[0].encode(),helper.SOURCE_SLOTS_TEST.encode())):
            with self.assertRaises(helper.CheckFailure):helper.source_slots_environment_test_result(bad)
        for key,value in (("passed",True),("running",0),("ignored",1),("filtered",False),
                          ("tests",list(ARTIFACT_CASES)),("tests",tuple(ENVIRONMENT_CASES))):
            with self.assertRaises(helper.CheckFailure):helper.validate_source_slots_environment_result({**environment_setup_result(),key:value})
        for phase in ("acquire","compile"):
            expected=environment_setup_receipt(phase);published=[]
            self.assertEqual(helper.validate_compile_receipt(expected,env_bound,phase),expected)
            for other in (source_slots_context(),intel_removal_context(),initialization_context(),artifact_context()):
                with self.assertRaises(helper.CheckFailure):helper.validate_compile_receipt(expected,other,phase)
            for key,value in (("scope",helper.SOURCE_SLOTS_EVIDENCE),("sourceSlotsSelection","artifact-setup10"),
                              ("sourceSlots",artifact_context()["sourceSlots"]),("node",helper.NODE),("attempt","100")):
                with self.assertRaises(helper.CheckFailure):helper.validate_compile_receipt({**expected,key:value},env_bound,phase)
            with patch.object(helper,"write_json",side_effect=lambda path,value:published.append((str(path),deepcopy(value)))):
                helper.phase_receipt(env_bound,phase,[row["check"] for row in expected["checks"]],node=None,
                                     source_slots_result=environment_setup_result() if phase=="compile" else None)
            self.assertEqual(published,[(env_bound["root"]+"/"+phase+"-checks.json",expected)])
        for bad in (source_slots_result(),intel_removal_result(),initialization_result(),artifact_result(),None):
            with patch.object(helper,"write_json",side_effect=AssertionError("no false publication")),self.assertRaises(helper.CheckFailure):
                helper.phase_receipt(env_bound,"compile",list(helper.SOURCE_SLOTS_CHECKS["compile"]),source_slots_result=bad)

        # Strict DATA cannot be borrowed by compile-only or another selection.
        self.assertEqual(helper.mac_history_test_result(history_app_stdout()), history_app_result())
        positive = history_app_stdout()
        wrongs = [b"", positive + b"extra\n", positive.replace(b"4 tests", b"0 tests"),
                  positive.replace(b"4 passed", b"0 passed"), positive.replace(b"0 ignored", b"1 ignored"),
                  positive.replace(b" ... ok", b" ... FAILED", 1), positive.replace(b"7 filtered", b"true filtered"),
                  positive.replace(HISTORY_APP_CASES[0].encode(), HISTORY_APP_CASES[1].encode()),
                  positive.replace(HISTORY_APP_CASES[0].encode(), b"other::test"), b"\xff", b" " * (1024 * 1024 + 1)]
        for wrong in wrongs:
            self.assertNotEqual(wrong, positive)
            with self.assertRaises(helper.CheckFailure):
                helper.mac_history_test_result(wrong)
        for field, wrong in (("running", True), ("passed", 3), ("failed", 1), ("ignored", 1),
                             ("filtered", 65536), ("tests", list(reversed(HISTORY_APP_CASES)))):
            with self.assertRaises(helper.CheckFailure):
                helper.validate_mac_history_result({**history_app_result(), field: wrong})
        for target in MAC_RUST_EXPECTED:
            bound = history_app_context(target)
            for phase in ("acquire", "compile"):
                expected = history_app_receipt(target, phase); written = []
                self.assertLess(len(json.dumps(expected).encode()), 16384)
                self.assertEqual(helper.validate_compile_receipt(expected, bound, phase), expected)
                with patch.object(helper, "write_json", side_effect=lambda path, value: written.append(deepcopy(value))):
                    helper.phase_receipt(bound, phase, list(helper.MAC_HISTORY_CHECKS[phase]), node=helper.NODE,
                                         mac_history_result=history_app_result() if phase == "compile" else None)
                self.assertEqual(written, [expected])
                for field, wrong in (("scope", "desktop-macos-normal-compile-only-v1"), ("node", None),
                                     ("checks", expected["checks"][:-1]), ("sourceSha", "a" * 40),
                                     ("rust", MAC_RUST_EXPECTED[next(t for t in MAC_RUST_EXPECTED if t != target)])):
                    with self.assertRaises(helper.CheckFailure):
                        helper.validate_compile_receipt({**expected, field: wrong}, bound, phase)
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(expected, mac_context(target), phase)
            bad = history_app_receipt(target, "compile"); del bad["testResult"]
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_receipt(bad, bound, "compile")
            with patch.object(helper, "write_json", side_effect=AssertionError("no false receipt")), self.assertRaises(helper.CheckFailure):
                helper.phase_receipt(bound, "compile", list(helper.MAC_HISTORY_CHECKS["compile"]), node=helper.NODE)
            # Actual clean entry cannot reach consuming cleanup with changed source.
            order = []
            with patch.object(helper, "source_unchanged", side_effect=lambda *a, **kw: order.append("source")), \
                    patch.object(helper, "mac_compile_source_guard", side_effect=lambda *a: order.append("guard")), \
                    patch.object(helper, "mac_compile_inputs", return_value=bound["macCompile"]), \
                    patch.object(helper, "clean_compile", side_effect=lambda *a: order.append("cleanup")):
                helper.phase_mac_compile("clean", bound)
                self.assertEqual(order, ["source", "guard", "cleanup"])
                order.clear()
                with patch.object(helper, "mac_compile_inputs", return_value={}), self.assertRaises(helper.CheckFailure):
                    helper.phase_mac_compile("clean", bound)
                self.assertEqual(order, ["source", "guard"])

    def test_compile_cleanup_never_adopts_native_or_unexpected_outputs(self):
        names = set(helper.COMPILER_DIRECTORIES + helper.EMPTY_NATIVE_DIRECTORIES + helper.COMPILER_PRIVATE_FILES + helper.COMPILE_PUBLIC_FILES)
        helper.validate_compile_inventory(names, set())
        for altered in (names | {"native-checks.json"}, names | {"foreign-output"}, names - {"compile-checks.json"}):
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_inventory(altered, set())
        with self.assertRaises(helper.CheckFailure):
            helper.validate_compile_inventory(names, {"native"})

        pairs = (("aarch64-apple-darwin", "full4"), ("x86_64-apple-darwin", "full4"),
                 ("aarch64-apple-darwin", "vault-only"),
                 ("aarch64-apple-darwin", "app-only"), ("x86_64-apple-darwin", "app-only"),
                 ("aarch64-apple-darwin", "observer-only"))
        for target, mode in pairs:
            expected_rust = MAC_RUST_EXPECTED[target]
            events, calls, written, guards, input_calls = [], [], [], [], []
            MemoryPath, Stream = memory_paths(events)
            bound = mac_context(target, mode)
            def invoke(argv, **kw):
                calls.append((list(map(str, argv)), kw))
                if kw["check"] == "source-head":
                    return bound["sourceSha"]
                if kw["check"] == "source-tree":
                    return bound["sourceTree"]
                if kw["check"] == "rust-version-target":
                    return ("release: " + expected_rust["release"] + "\ncommit-hash: "
                            + expected_rust["commitHash"] + "\nhost: " + target)
                if kw["check"] == "mac-cargo-version":
                    return "cargo 1.98.0 (abcdef123 2026-09-01)"
                if kw["check"] == "node-version":
                    self.assertIn(mode, ("full4", "app-only", "observer-only"))
                    return helper.NODE
                return ""
            def selected(name):
                self.assertIn(name, ("git", "node") if mode in ("full4", "app-only", "observer-only") else ("git",))
                return "/usr/bin/git" if name == "git" else "/selected/bin/node"
            def selected_inputs(source, selected_target, selected_mode):
                input_calls.append((str(source), selected_target, selected_mode))
                return deepcopy(mac_context(selected_target, selected_mode)["macCompile"])
            with patch.dict(helper.os.environ, mac_environment(target, mode), clear=True), \
                    patch.object(helper, "Path", MemoryPath), patch.object(helper, "run", side_effect=invoke), \
                    patch.object(helper, "ordinary"), patch.object(helper, "hash_file", return_value="5" * 64), \
                    patch.object(helper, "mac_compile_inputs", side_effect=selected_inputs), \
                    patch.object(helper, "no_cargo_configuration", side_effect=lambda paths: guards.append(tuple(map(str, paths)))), \
                    patch.object(helper, "write_json", side_effect=lambda path, value: written.append((str(path), deepcopy(value)))), \
                    patch.object(helper.shutil, "which", side_effect=selected), \
                    patch.object(helper.tempfile, "mkdtemp", return_value=bound["root"]), \
                    patch.object(helper.zipfile, "ZipFile", Stream), patch.object(helper.time, "monotonic", return_value=100.0):
                with io.StringIO() as prepared_stdout, contextlib.redirect_stdout(prepared_stdout):
                    helper.prepare("macos", helper.MAC_COMPILE_SCOPE)
                    self.assertEqual(prepared_stdout.getvalue(),
                        "Prepared bounded source ZIP and source-bound synthetic check inputs.\n")
                prepared = next(value for path, value in written if path.endswith("context.json"))
                public = next(value for path, value in written if path.endswith("public-bindings.json"))
                self.assertIsNone(prepared["rustup"])
                self.assertEqual(prepared["macCompile"], bound["macCompile"])
                self.assertEqual(public["macCompile"], prepared["macCompile"])
                self.assertEqual(public["expectedRust"], expected_rust["release"])
                self.assertEqual(public["compiler"], expected_rust)
                self.assertEqual(helper.compiler_binding(prepared), expected_rust)
                self.assertTrue(any("/inert/source/desktop/helpers/macos-desktop-image" in paths
                                    and "/inert/source/desktop/helpers/macos-vault-helper" in paths
                                    and "/inert/source/desktop/helpers" in paths for paths in guards))
                helper.phase_mac_compile("acquire", prepared)
            self.assertTrue(input_calls and all(row == (bound["source"], target, mode) for row in input_calls))
            if mode in ("app-only", "observer-only"):
                self.assertIn("test-execution", public["notQualified"])
                self.assertEqual(public["scope"], "desktop-macos-normal-compile-only-v1")
            metadata_names = ("mac-vault-locked-metadata", "mac-normal-locked-metadata", "mac-image-locked-metadata") if mode == "full4" else ("mac-normal-locked-metadata",) if mode in ("app-only", "observer-only") else ("mac-vault-locked-metadata",)
            commands = [row for row in calls if row[1]["check"] in metadata_names]
            self.assertEqual([row[1]["check"] for row in commands], list(metadata_names))
            self.assertEqual([row[0][0] for row in commands],
                             ["/Users/runner/.rustup/toolchains/stable-" + target + "/bin/cargo"] * len(commands))
            expected_paths = ["desktop/helpers/macos-vault-helper/Cargo.toml"] + (["desktop/src-tauri/Cargo.toml", "desktop/helpers/macos-desktop-image/Cargo.toml"] if mode == "full4" else [])
            if mode in ("app-only", "observer-only"):
                expected_paths = ["desktop/src-tauri/Cargo.toml"]
            self.assertEqual([row[0][-1] for row in commands], [bound["source"] + "/" + path for path in expected_paths])
            self.assertEqual([row[0][1] for row in commands], ["metadata"] * len(commands))
            if mode in ("app-only", "observer-only"):
                self.assertEqual(commands[0][0][commands[0][0].index("--features") + 1],
                                 "desktop-shell,custom-protocol,macos-installed-observation" if mode == "observer-only" else "desktop-shell,custom-protocol")
            else:
                self.assertNotIn("--features", commands[0][0])
            if mode == "full4":
                self.assertEqual(commands[1][0][commands[1][0].index("--features") + 1], "desktop-shell,custom-protocol,macos-installed-observation")
                self.assertNotIn("--features", commands[2][0])
            for argv, kw in commands:
                self.assertIn("--locked", argv)
                self.assertEqual(argv[argv.index("--filter-platform") + 1], target)
                self.assertEqual(kw["timeout"], 600)
            self.assertFalse(any("rustup" == Path(arg).name for row, _ in calls for arg in row))
            receipt_value = next(value for path, value in written if path.endswith("acquire-checks.json"))
            expected_checks = ["rust-version-target", "mac-cargo-version", *metadata_names] + (["node-version", "npm-locked-no-scripts"] if mode in ("full4", "app-only", "observer-only") else [])
            self.assertEqual(receipt_value["rust"], expected_rust)
            self.assertEqual(receipt_value["node"], helper.NODE if mode in ("full4", "app-only", "observer-only") else None)
            self.assertEqual(receipt_value["checks"], [{"check": name, "exitCode": 0} for name in expected_checks])
            output_names = ["target/mac-vault-metadata.json", "metadata.json", "target/mac-image-metadata.json"] if mode == "full4" else ["metadata.json"]
            for name in output_names:
                self.assertTrue(any(event[:2] == ("closed", bound["root"] + "/" + name) for event in events))
            if mode == "vault-only":
                self.assertFalse(any(row[1]["check"] in ("node-version", "npm-locked-no-scripts") for row in calls))

            # Actual retained-context reader recomputes mode+SOURCE, not a
            # caller-provided graph list or a mode-less default.
            loaded_frame = deepcopy(prepared)
            class ContextPath(MemoryPath):
                def read_text(self, **kwargs):
                    self_outer.assertTrue(str(self).endswith('/context.json'))
                    return json.dumps(loaded_frame)
            self_outer = self
            load_env = {**mac_environment(target, mode), "MRK_DESKTOP_CI_ROOT": bound["root"]}
            with patch.dict(helper.os.environ, load_env, clear=True), patch.object(helper, "Path", ContextPath), \
                    patch.object(helper, "ordinary"), patch.object(helper, "hash_file", return_value="5" * 64), \
                    patch.object(helper, "mac_compile_inputs", side_effect=selected_inputs):
                self.assertEqual(helper.load_context("macos", helper.MAC_COMPILE_SCOPE), prepared)
                for bad_mode in (None, "normal3", "other"):
                    loaded_frame = deepcopy(prepared)
                    if bad_mode is None:
                        del loaded_frame["macCompile"]["mode"]
                    else:
                        loaded_frame["macCompile"]["mode"] = bad_mode
                    with self.assertRaises(helper.CheckFailure):
                        helper.load_context("macos", helper.MAC_COMPILE_SCOPE)
                loaded_frame = deepcopy(prepared)
                loaded_frame["macCompile"]["graphs"] = []
                with self.assertRaises(helper.CheckFailure):
                    helper.load_context("macos", helper.MAC_COMPILE_SCOPE)

            cleanup_order = []
            with patch.object(helper, "source_unchanged", side_effect=lambda *args, **kw: cleanup_order.append("source")), \
                    patch.object(helper, "mac_compile_source_guard", side_effect=lambda *args: cleanup_order.append("guard")), \
                    patch.object(helper, "mac_compile_inputs", return_value=bound["macCompile"]), \
                    patch.object(helper, "clean_compile", side_effect=lambda *args: cleanup_order.append("cleanup")):
                helper.phase_mac_compile("clean", bound)
                self.assertEqual(cleanup_order, ["source", "guard", "cleanup"])
                cleanup_order.clear()
                with patch.object(helper, "mac_compile_inputs", return_value={}), self.assertRaises(helper.CheckFailure):
                    helper.phase_mac_compile("clean", bound)
                self.assertEqual(cleanup_order, ["source", "guard"])

            # Invoke actual cleanup against a finite, original in-memory tree.
            # The same parser/validator checks both receipts before any delete.
            files, directories, symbolic, cleanup_events = {}, set(), set(), []
            source_outputs = [bound["source"] + "/" + rel for rel in ("desktop/node_modules", "desktop/dist", "desktop/src-tauri/gen")]
            class MemoryReceipt(io.BytesIO):
                def __init__(self, path, value):
                    super().__init__(value); self.path = path
                def close(self):
                    if not self.closed:
                        cleanup_events.append(("close", self.path))
                    super().close()
            class CleanPath(PurePosixPath):
                def exists(self):
                    return str(self) in files or str(self) in directories
                def is_symlink(self):
                    return str(self) in symbolic
                def is_dir(self):
                    return str(self) in directories
                def stat(self):
                    class Info:
                        st_file_attributes = 0
                    result = Info(); result.st_size = len(files.get(str(self), b''))
                    return result
                lstat = stat
                def open(self, mode):
                    self_outer.assertEqual(mode, "rb")
                    return MemoryReceipt(str(self), files[str(self)])
                def iterdir(self):
                    return iter(CleanPath(name) for name in sorted(set(files) | directories) if PurePosixPath(name).parent == self)
                def rmdir(self):
                    self_outer.assertFalse(list(self.iterdir()))
                    directories.remove(str(self)); cleanup_events.append(("rmdir", str(self)))
                def unlink(self):
                    del files[str(self)]; cleanup_events.append(("unlink", str(self)))
            def reset_tree():
                files.clear(); directories.clear(); symbolic.clear(); cleanup_events.clear()
                directories.update(bound["root"] + "/" + name for name in helper.COMPILER_DIRECTORIES + helper.EMPTY_NATIVE_DIRECTORIES)
                if mode in ("full4", "app-only", "observer-only"):
                    directories.update(source_outputs)
                files.update({bound["root"] + "/" + name: b"inert data" for name in helper.COMPILER_PRIVATE_FILES + helper.COMPILE_PUBLIC_FILES})
                for phase in ("acquire", "compile"):
                    checks = expected_checks if phase == "acquire" else ["rust-version-target", "mac-cargo-version", "mac-vault-bin-compile-only"] + (["node-version", "typescript-no-emit", "vite-assets", "mac-normal-bin-compile-only", "mac-observer-compile-only", "mac-image-compile-only"] if mode == "full4" else [])
                    if mode in ("app-only", "observer-only") and phase == "compile":
                        checks = ["rust-version-target", "mac-cargo-version", "node-version",
                                  "typescript-no-emit", "vite-assets", "mac-observer-compile-only" if mode == "observer-only" else "mac-normal-bin-compile-only"]
                    frame = {"schemaVersion": 1, "scope": "desktop-macos-normal-compile-only-v1", "phase": phase, "status": "passed",
                             **{key: bound[key] for key in ("sourceSha", "platform", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt", "sourceTree", "macCompile")},
                             "rust": deepcopy(expected_rust), "node": helper.NODE if mode in ("full4", "app-only", "observer-only") else None,
                             "checks": [{"check": check, "exitCode": 0} for check in checks]}
                    files[bound["root"] + "/" + phase + "-checks.json"] = json.dumps(frame).encode()
            def original_file(path):
                helper.require(str(path) in files and str(path) not in symbolic, "inert original file differs")
            def remove_tree(path):
                value = str(path)
                self.assertIn(value, directories)
                self.assertNotIn(value, symbolic)
                cleanup_events.append(("rmtree", value))
                for name in list(files):
                    if name.startswith(value + "/"):
                        del files[name]
                for name in list(directories):
                    if name == value or name.startswith(value + "/"):
                        directories.remove(name)
            def no_deletion():
                self.assertFalse(any(event[0] in ("rmtree", "rmdir", "unlink") for event in cleanup_events))
            with patch.object(helper, "Path", CleanPath), patch.object(helper, "ordinary", side_effect=original_file), \
                    patch.object(helper.shutil, "rmtree", side_effect=remove_tree):
                reset_tree()
                with io.StringIO() as cleanup_stdout, contextlib.redirect_stdout(cleanup_stdout):
                    helper.clean_compile(bound)
                    self.assertEqual(cleanup_stdout.getvalue(),
                        "Removed settled compiler-only outputs; preserved exactly three public receipts. No native qualification.\n")
                self.assertEqual(set(files), {bound["root"] + "/" + name for name in helper.COMPILE_PUBLIC_FILES})
                self.assertFalse(directories)
                first_delete = next(index for index, event in enumerate(cleanup_events) if event[0] == "rmtree")
                self.assertEqual([event[0] for event in cleanup_events[:first_delete]], ["close", "close"])
                if mode == "vault-only":
                    self.assertTrue(all(not value.startswith(bound["source"] + "/") for event, value in cleanup_events if event == "rmtree"))
                    for path in source_outputs:
                        for state in (directories, symbolic):
                            reset_tree(); state.add(path)
                            with self.assertRaises(helper.CheckFailure):
                                helper.clean_compile(bound)
                            no_deletion()
                else:
                    reset_tree(); directories.remove(source_outputs[0])
                    with self.assertRaises(helper.CheckFailure):
                        helper.clean_compile(bound)
                    no_deletion()
                reset_tree(); del files[bound["root"] + "/compile-checks.json"]
                with self.assertRaises(helper.CheckFailure):
                    helper.clean_compile(bound)
                no_deletion()
                reset_tree()
                key = bound["root"] + "/compile-checks.json"
                foreign = json.loads(files[key]); foreign["sourceSha"] = "9" * 40
                files[key] = json.dumps(foreign).encode()
                with self.assertRaises(helper.CheckFailure):
                    helper.clean_compile(bound)
                no_deletion()

        # Actual prepare + acquisition, with only original IO/commands replaced
        # by finite in-memory doubles. No Node/rustup or extra graph enters.
        bound = source_slots_context()
        events, captures, written, calls, guards = [], {}, [], [], []
        SlotsPath, writer, read = source_slots_paths(events, captures)
        _, ZipStream = memory_paths(events)
        def invoke_slots(argv, **kw):
            calls.append((list(map(str, argv)), {**kw, "env": dict(kw["env"])}))
            if kw["check"] == "source-head":
                return bound["sourceSha"]
            if kw["check"] == "source-tree":
                return bound["sourceTree"]
            if kw["check"] == "rust-version-target":
                return "release: 1.98.0\ncommit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\nhost: x86_64-apple-darwin"
            if kw["check"] == "mac-cargo-version":
                return "cargo 1.98.0 (abcdef123 2026-09-01)"
            if kw["check"] == "mac-source-slots-locked-metadata":
                kw["output"].write('{"packages":[]}\n')
                self.assertIsNotNone(kw["diagnostics"])
            return ""
        def only_git(name):
            self.assertEqual(name, "git")
            return "/usr/bin/git"
        with patch.dict(helper.os.environ, source_slots_environment(), clear=True), \
                patch.object(helper, "Path", SlotsPath), patch.object(helper, "run", side_effect=invoke_slots), \
                patch.object(helper, "ordinary"), patch.object(helper, "hash_file", return_value="2" * 64), \
                patch.object(helper, "no_cargo_configuration", side_effect=lambda paths: guards.append(tuple(map(str, paths)))), \
                patch.object(helper, "write_json", side_effect=lambda path, value: written.append((str(path), deepcopy(value)))), \
                patch.object(helper.shutil, "which", side_effect=only_git), \
                patch.object(helper.tempfile, "mkdtemp", return_value=bound["root"]), \
                patch.object(helper.zipfile, "ZipFile", ZipStream), patch.object(helper.time, "monotonic", return_value=100.0), \
                patch.object(helper, "source_slots_writer", side_effect=writer), patch.object(helper, "source_slots_read", side_effect=read):
            with io.StringIO() as prepared_stdout, contextlib.redirect_stdout(prepared_stdout):
                helper.prepare("macos", helper.SOURCE_SLOTS_SCOPE)
                self.assertEqual(prepared_stdout.getvalue(), "Prepared bounded source ZIP and source-bound synthetic check inputs.\n")
            prepared = next(value for path, value in written if path.endswith("/context.json"))
            public = next(value for path, value in written if path.endswith("/public-bindings.json"))
            self.assertIsNone(prepared["rustup"])
            self.assertEqual(prepared["sourceSlots"], bound["sourceSlots"])
            self.assertEqual(public["sourceSlots"], bound["sourceSlots"])
            self.assertEqual(public["sourceTree"], bound["sourceTree"])
            self.assertEqual(public["compiler"], MAC_RUST_EXPECTED["x86_64-apple-darwin"])
            self.assertIsNone(public["node"])
            self.assertNotIn("test-execution", public["notQualified"])
            self.assertTrue({"other-tests", "supplier-native-loading", "Apple-provider-closure", "service-registration",
                             "signing", "installed-runtime"}.issubset(public["notQualified"]))
            helper.phase_source_slots("acquire", prepared)
        legacy_calls, legacy_written = list(calls), list(written)
        calls.clear(); written.clear(); events.clear(); captures.clear()
        b = intel_removal_context()
        with patch.dict(helper.os.environ, intel_removal_environment(), clear=True), \
                patch.object(helper, "Path", SlotsPath), patch.object(helper, "run", side_effect=invoke_slots), \
                patch.object(helper, "ordinary"), patch.object(helper, "hash_file", return_value="2" * 64), \
                patch.object(helper, "no_cargo_configuration"), \
                patch.object(helper, "source_slots_build_inputs", return_value=intel_removal_build()) as build_input, \
                patch.object(helper, "write_json", side_effect=lambda path, value: written.append((str(path), deepcopy(value)))), \
                patch.object(helper.shutil, "which", side_effect=only_git), \
                patch.object(helper.tempfile, "mkdtemp", return_value=b["root"]), \
                patch.object(helper.zipfile, "ZipFile", ZipStream), patch.object(helper.time, "monotonic", return_value=100.0), \
                patch.object(helper, "source_slots_writer", side_effect=writer), patch.object(helper, "source_slots_read", side_effect=read):
            with io.StringIO() as ignored, contextlib.redirect_stdout(ignored):
                helper.prepare("macos", helper.SOURCE_SLOTS_SCOPE)
            prepared_b = next(value for path, value in written if path.endswith("/context.json"))
            public_b = next(value for path, value in written if path.endswith("/public-bindings.json"))
            self.assertEqual(prepared_b["sourceSlots"], b["sourceSlots"])
            self.assertEqual(public_b["sourceSlotsBuild"], intel_removal_build())
            self.assertEqual(public_b["scope"], "desktop-macos-intel-removal-abrupt-data-v1")
            self.assertIsNone(public_b["node"])
            helper.phase_source_slots("acquire", prepared_b)
            self.assertEqual(build_input.call_count, 4)  # prepare input+POST, acquire PRE+POST
        acquired_b = [(argv, kw) for argv, kw in calls if kw["check"] == "mac-source-slots-locked-metadata"]
        self.assertEqual(len(acquired_b), 1)
        b_argv, b_kw = acquired_b[0]
        self.assertEqual(b_argv, ["/Users/runner/.rustup/toolchains/stable-x86_64-apple-darwin/bin/cargo", "metadata",
                                 "--locked", "--format-version", "1", "--no-default-features", "--features", "macos-installed-removal-abrupt-fixture",
                                 "--filter-platform", "x86_64-apple-darwin", "--manifest-path", b["source"] + "/desktop/src-tauri/Cargo.toml"])
        self.assertNotIn("--offline", b_argv)
        self.assertEqual(b_kw["env"]["MRK_MACOS_INSTALL_SOURCE_COMMIT"], b["sourceSha"])
        self.assertEqual(b_kw["env"]["MRK_IMAGE_RELEASE_ID"], intel_removal_build()["release"])
        self.assertEqual(b_kw["timeout"], 600)
        self.assertTrue(b_kw["output"].closed and b_kw["diagnostics"].closed)
        self.assertEqual(next(value for path, value in written if path.endswith("/acquire-checks.json")), intel_removal_receipt("acquire"))
        calls[:], written[:] = legacy_calls, legacy_written
        metadata = [(argv, kw) for argv, kw in calls if kw["check"] == "mac-source-slots-locked-metadata"]
        self.assertEqual(len(metadata), 1)
        argv, kw = metadata[0]
        self.assertEqual(argv, ["/Users/runner/.rustup/toolchains/stable-x86_64-apple-darwin/bin/cargo", "metadata",
                               "--locked", "--format-version", "1", "--no-default-features", "--features", "development-runtime",
                               "--filter-platform", "x86_64-apple-darwin", "--manifest-path", bound["source"] + "/desktop/src-tauri/Cargo.toml"])
        self.assertEqual(kw["timeout"], 600)
        self.assertEqual(next(value for path, value in written if path.endswith("/acquire-checks.json")), source_slots_receipt("acquire"))
        self.assertEqual([kw["check"] for _, kw in calls if kw["check"] not in ("source-head", "source-tree", "source-clean")],
                         ["rust-version-target", "mac-cargo-version", "mac-source-slots-locked-metadata"])
        self.assertTrue(any(bound["root"] + "/home" in row and bound["root"] + "/cargo" in row for row in guards))
        self.assertTrue(kw["output"].closed and kw["diagnostics"].closed)

        # Actual ambient/config/adjacent-output refusal, without touching disk.
        paths = set()
        class GuardPath(PurePosixPath):
            def exists(self):
                return str(self) in paths
            def is_symlink(self):
                return str(self) in paths
        with patch.dict(helper.os.environ, {}, clear=True):
            helper.source_slots_source_guard(GuardPath(bound["source"]), GuardPath(bound["root"]))
            for relative in ("desktop/node_modules", "desktop/dist", "desktop/src-tauri/gen", "desktop/src-tauri/target",
                             "desktop/helpers/macos-vault-helper/target", "desktop/src-tauri/.cargo/config.toml"):
                paths.add(bound["source"] + "/" + relative)
                with self.subTest(adjacent=relative), self.assertRaises(helper.CheckFailure):
                    helper.source_slots_source_guard(GuardPath(bound["source"]), GuardPath(bound["root"]))
                paths.clear()
            for relative in ("home/.cargo/config", "cargo/.cargo/config.toml"):
                paths.add(bound["root"] + "/" + relative)
                with self.assertRaises(helper.CheckFailure):
                    helper.source_slots_source_guard(GuardPath(bound["source"]), GuardPath(bound["root"]))
                paths.clear()
            for flag in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                         "CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_X86_64_APPLE_DARWIN_RUSTFLAGS", "CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER"):
                with patch.dict(helper.os.environ, {flag: ""}), self.assertRaises(helper.CheckFailure):
                    helper.source_slots_source_guard(GuardPath(bound["source"]), GuardPath(bound["root"]))

        # Reuse the finite cleanup tree defined above, but replace its synthetic
        # normal receipts with this profile's exact acquisition+DATA originals.
        # The existing classes close reads and record every inert deletion.
        def reset_slots_tree():
            files.clear(); directories.clear(); symbolic.clear(); cleanup_events.clear()
            directories.update(bound["root"] + "/" + name for name in helper.COMPILER_DIRECTORIES + helper.EMPTY_NATIVE_DIRECTORIES)
            files.update({bound["root"] + "/" + name: b"inert data" for name in helper.COMPILER_PRIVATE_FILES + helper.COMPILE_PUBLIC_FILES})
            for phase_name in ("acquire", "compile"):
                files[bound["root"] + "/" + phase_name + "-checks.json"] = json.dumps(source_slots_receipt(phase_name)).encode()
        source_order = []
        with patch.object(helper, "Path", CleanPath), patch.object(helper, "ordinary", side_effect=original_file), \
                patch.object(helper.shutil, "rmtree", side_effect=remove_tree), \
                patch.object(helper, "source_unchanged", side_effect=lambda *args, **kw: source_order.append("source")), \
                patch.object(helper, "source_slots_source_guard", side_effect=lambda *args: source_order.append("guard")):
            reset_slots_tree()
            with io.StringIO() as cleanup_stdout, contextlib.redirect_stdout(cleanup_stdout):
                helper.phase_source_slots("clean", bound)
                self.assertEqual(cleanup_stdout.getvalue(), "Removed settled compiler-only outputs; preserved exactly three public receipts. No native qualification.\n")
            self.assertEqual(source_order, ["source", "guard"])
            self.assertEqual(set(files), {bound["root"] + "/" + name for name in helper.COMPILE_PUBLIC_FILES})
            self.assertFalse(directories)
            for fault in ("failure-summary", "foreign-output", "missing-receipt", "ignored", "native-output", "frontend", "symlink"):
                reset_slots_tree()
                if fault in ("failure-summary", "foreign-output"):
                    files[bound["root"] + ("/source-slots-failure.json" if fault == "failure-summary" else "/foreign")] = b"{}"
                elif fault == "missing-receipt":
                    del files[bound["root"] + "/compile-checks.json"]
                elif fault == "ignored":
                    value = source_slots_receipt("compile"); value["testResult"]["ignored"] = 1
                    files[bound["root"] + "/compile-checks.json"] = json.dumps(value).encode()
                elif fault == "native-output":
                    files[bound["root"] + "/native/foreign"] = b"original"
                elif fault == "frontend":
                    directories.add(bound["source"] + "/desktop/dist")
                else:
                    symbolic.add(bound["root"] + "/target")
                with self.subTest(cleanup_fault=fault), self.assertRaises(helper.CheckFailure):
                    helper.phase_source_slots("clean", bound)
                no_deletion()


        # Same real cleanup code, B positive receipts only. Cross-selection or
        # changed build inputs cannot authorize even the first inert deletion.
        bound = intel_removal_context()
        def reset_b_tree():
            reset_slots_tree()
            for phase_name in ("acquire", "compile"):
                files[bound["root"] + "/" + phase_name + "-checks.json"] = json.dumps(intel_removal_receipt(phase_name)).encode()
        with patch.object(helper, "Path", CleanPath), patch.object(helper, "ordinary", side_effect=original_file), \
                patch.object(helper.shutil, "rmtree", side_effect=remove_tree), patch.object(helper, "source_unchanged"), \
                patch.object(helper, "source_slots_source_guard"), \
                patch.object(helper, "source_slots_build_inputs", return_value=intel_removal_build()) as build_input:
            reset_b_tree()
            with io.StringIO() as ignored, contextlib.redirect_stdout(ignored):
                helper.phase_source_slots("clean", bound)
            self.assertFalse(directories)
            self.assertEqual(set(files), {bound["root"] + "/" + name for name in helper.COMPILE_PUBLIC_FILES})
            self.assertEqual(build_input.call_count, 1)
            for fault in ("legacy-acquire", "legacy-compile", "failure", "foreign", "projection", "frontend", "ignored"):
                reset_b_tree()
                if fault.startswith("legacy-"):
                    phase_name = fault.removeprefix("legacy-")
                    files[bound["root"] + "/" + phase_name + "-checks.json"] = json.dumps(source_slots_receipt(phase_name)).encode()
                elif fault in ("failure", "foreign"):
                    files[bound["root"] + ("/source-slots-failure.json" if fault == "failure" else "/foreign")] = b"{}"
                elif fault == "projection":
                    build_input.return_value = {**intel_removal_build(), "release": "macos26-x86_64-changed"}
                elif fault == "frontend": directories.add(bound["source"] + "/desktop/dist")
                else:
                    frame = intel_removal_receipt("compile"); frame["testResult"]["ignored"] = 1
                    files[bound["root"] + "/compile-checks.json"] = json.dumps(frame).encode()
                with self.subTest(b_cleanup=fault), self.assertRaises(helper.CheckFailure):
                    helper.phase_source_slots("clean", bound)
                no_deletion()
                build_input.return_value = intel_removal_build()

    def test_compile_receipt_bytes_reject_duplicate_nonfinite_extra_or_oversized_frames(self):
        value = receipt("compile")
        raw = json.dumps(value, separators=(",", ":")).encode()
        self.assertEqual(helper.parse_compile_receipt(raw), value)
        for broken in (raw.replace(b'"schemaVersion":1', b'"schemaVersion":0,"schemaVersion":1'),
                       raw.replace(b'"exitCode":0', b'"exitCode":1,"exitCode":0', 1),
                       raw + b'{}', b'{"secret":"not real","bad":NaN}', b'\xff', b' ' * 16385, b''):
            with self.assertRaises(helper.CheckFailure):
                helper.parse_compile_receipt(broken)

        bound = mac_context()
        calls, receipts, clock = [], [], [100.0]
        def invoke(argv, **kw):
            calls.append((list(argv), deepcopy({key: value for key, value in kw.items() if key != "output"})))
            return helper.NODE if kw["check"] == "node-version" else ""
        with patch.object(helper, "source_unchanged"), patch.object(helper, "mac_compile_source_guard"), \
                patch.object(helper, "mac_compile_inputs", return_value=bound["macCompile"]), \
                patch.object(helper, "tools", return_value=("/direct/cargo", "/direct/rustc")), \
                patch.object(helper.shutil, "which", return_value="/selected/bin/node"), \
                patch.object(helper, "run", side_effect=invoke), \
                patch.object(helper, "phase_receipt", side_effect=lambda *args, **kw: receipts.append((args, kw))), \
                patch.object(helper.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.dict(helper.os.environ, {"PATH": "/selected/bin", "MRK_MACOS_DEVELOPER_ID_P12_BASE64": "synthetic-never-exported"}, clear=True):
            helper.phase_mac_compile("compile", bound)
            builds = [(argv, kw) for argv, kw in calls if kw["check"] in {row[0] for row in helper.MAC_COMPILE_GRAPHS}]
            self.assertEqual(len(builds), 3)
            self.assertEqual([kw["timeout"] for _, kw in builds], [1500, 1500, 1500])
            self.assertEqual([argv[1] for argv, _ in builds], ["build", "test", "build"])
            self.assertEqual([argv[argv.index("--target-dir") + 1] for argv, _ in builds], [bound["root"] + "/target"] * 3)
            self.assertEqual(builds[0][0][-5:], ["--release", "--features", "desktop-shell,custom-protocol", "--bin", "mobile-release-kit-desktop"])
            self.assertEqual(builds[1][0][-5:], ["--features", "desktop-shell,custom-protocol,macos-installed-observation", "--test", "installed-shell-observation", "--no-run"])
            self.assertEqual(builds[2][0][-2:], ["--release", "--lib"])
            self.assertNotIn("--features", builds[2][0])
            for argv, kw in builds:
                self.assertIn("--offline", argv)
                self.assertEqual(argv[argv.index("--jobs") + 1], "1")
                self.assertNotIn("development-runtime", argv)
                self.assertNotIn("MRK_MACOS_DEVELOPER_ID_P12_BASE64", kw["env"])
                self.assertNotIn("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256", kw["env"])
                self.assertEqual(kw["env"]["MRK_MACOS_INSTALL_SOURCE_COMMIT"], bound["sourceSha"])
                self.assertEqual(kw["env"]["MRK_IMAGE_RELEASE_ID"], bound["macCompile"]["release"])
            self.assertEqual(len(receipts), 1)
            self.assertEqual([kw["check"] for _, kw in calls],
                             ["mac-vault-bin-compile-only", "node-version", "typescript-no-emit", "vite-assets",
                              "mac-normal-bin-compile-only", "mac-observer-compile-only", "mac-image-compile-only"])
            vault_argv, vault_kw = calls[0]
            self.assertEqual(vault_argv[-5:], ["--manifest-path", bound["source"] + "/desktop/helpers/macos-vault-helper/Cargo.toml",
                                             "--release", "--bin", "mrk-vault-keychain"])
            self.assertNotIn("--features", vault_argv)
            self.assertEqual(vault_kw["timeout"], 1500)
            self.assertEqual(vault_argv[vault_argv.index("--jobs") + 1], "1")
            self.assertIn("--locked", vault_argv)
            self.assertIn("--offline", vault_argv)
            self.assertEqual(receipts[0][0][2], list(helper.MAC_COMPILE_CHECKS["compile"]))
            calls.clear(); receipts.clear()
            def vault_failed(argv, **kw):
                result = invoke(argv, **kw)
                if kw["check"] == "mac-vault-bin-compile-only":
                    raise helper.CheckFailure("original vault compiler failed")
                return result
            with patch.object(helper, "run", side_effect=vault_failed), self.assertRaisesRegex(helper.CheckFailure, "original vault compiler failed"):
                helper.phase_mac_compile("compile", bound)
            self.assertEqual([kw["check"] for _, kw in calls], ["mac-vault-bin-compile-only"])
            self.assertFalse(receipts)
            calls.clear(); receipts.clear()
            intel = mac_context("x86_64-apple-darwin")
            with patch.object(helper, "mac_compile_inputs", return_value=intel["macCompile"]):
                helper.phase_mac_compile("compile", intel)
            intel_builds = [(argv, kw) for argv, kw in calls if kw["check"] in {row[0] for row in helper.MAC_COMPILE_GRAPHS}]
            self.assertEqual(len(intel_builds), 3)
            self.assertEqual([kw["timeout"] for _, kw in intel_builds], [2700, 2700, 2700])
            for argv, kw in intel_builds:
                self.assertEqual(argv[argv.index("--target") + 1], "x86_64-apple-darwin")
                self.assertEqual(kw["env"]["MRK_IMAGE_RELEASE_ID"], intel["macCompile"]["release"])
            self.assertEqual(len(receipts), 1)
            calls.clear(); receipts.clear()
            def failed(argv, **kw):
                result = invoke(argv, **kw)
                if kw["check"] == "mac-normal-bin-compile-only":
                    raise helper.CheckFailure("original compiler failed")
                return result
            with patch.object(helper, "run", side_effect=failed), self.assertRaisesRegex(helper.CheckFailure, "original compiler failed"):
                helper.phase_mac_compile("compile", bound)
            self.assertFalse(receipts)
            self.assertFalse(any(kw["check"] == "mac-observer-compile-only" for _, kw in calls))
            calls.clear()
            def late(argv, **kw):
                result = invoke(argv, **kw)
                if kw["check"] == "mac-normal-bin-compile-only":
                    clock[0] = 1901.0
                return result
            with patch.object(helper, "run", side_effect=late), self.assertRaises(helper.CheckFailure):
                helper.phase_mac_compile("compile", bound)
            self.assertFalse(receipts)
            self.assertFalse(any(kw["check"] == "mac-observer-compile-only" for _, kw in calls))
            clock[0] = 100.0
            def late_publication(*args, **kw):
                receipts.append((args, kw))
                clock[0] = 1901.0
            with patch.object(helper, "phase_receipt", side_effect=late_publication), self.assertRaises(helper.CheckFailure):
                helper.phase_mac_compile("compile", bound)
            # Retained bytes are diagnostic only without this original phase0.
            self.assertEqual(len(receipts), 1)

            # Synthetic scheduling DATA only, not measured Intel completion.
            # Vault retains1500s; Intel normal caps2700s; all share one endpoint.
            calls.clear(); receipts.clear(); clock[0] = 100.0
            elapsed = {"mac-normal-bin-compile-only": 2100.0,
                       "mac-observer-compile-only": 1050.0,
                       "mac-image-compile-only": 975.0}
            def elapsed_original(argv, **kw):
                result = invoke(argv, **kw)
                clock[0] += elapsed.get(kw["check"], 0.0)
                return result
            with patch.object(helper, "mac_compile_inputs", return_value=intel["macCompile"]), \
                    patch.object(helper, "run", side_effect=elapsed_original):
                helper.phase_mac_compile("compile", intel)
            progressed = [(argv, kw) for argv, kw in calls if kw["check"] in elapsed]
            self.assertEqual([kw["check"] for _, kw in progressed], list(elapsed))
            self.assertEqual([kw["timeout"] for _, kw in progressed], [2700, 2700, 2220])
            self.assertEqual([argv for argv, _ in progressed], [argv for argv, _ in intel_builds])
            self.assertEqual(clock[0], 4225.0)
            self.assertEqual(len(receipts), 1)

            for selected, budget in ((bound, 1800), (intel, 5400)):
                with self.subTest(target=selected["macCompile"]["target"]), \
                        patch.object(helper, "mac_compile_inputs", return_value=selected["macCompile"]):
                    calls.clear(); receipts.clear(); clock[0] = 100.0
                    with patch.object(helper, "run", side_effect=failed), self.assertRaisesRegex(helper.CheckFailure, "original compiler failed"):
                        helper.phase_mac_compile("compile", selected)
                    self.assertFalse(receipts)
                    self.assertFalse(any(kw["check"] in ("mac-observer-compile-only", "mac-image-compile-only") for _, kw in calls))
                    for returned_clock in (100.0 + budget - 30, 99.0):
                        calls.clear(); receipts.clear(); clock[0] = 100.0
                        def expired_original(argv, **kw):
                            result = invoke(argv, **kw)
                            if kw["check"] == "mac-normal-bin-compile-only":
                                clock[0] = returned_clock
                            return result
                        with patch.object(helper, "run", side_effect=expired_original), self.assertRaisesRegex(
                                helper.CheckFailure, "endpoint expired or clock reversed"):
                            helper.phase_mac_compile("compile", selected)
                        self.assertFalse(receipts)
                        self.assertFalse(any(kw["check"] in ("mac-observer-compile-only", "mac-image-compile-only") for _, kw in calls))
                    calls.clear(); receipts.clear(); clock[0] = 100.0
                    def expired_publication(*args, **kw):
                        receipts.append((args, kw))
                        clock[0] = 100.0 + budget - 30
                    with patch.object(helper, "phase_receipt", side_effect=expired_publication), self.assertRaisesRegex(
                            helper.CheckFailure, "endpoint expired or clock reversed"):
                        helper.phase_mac_compile("compile", selected)
                    self.assertEqual(len(receipts), 1)
                    self.assertEqual(sum(kw["check"] in elapsed for _, kw in calls), 3)

            # Fixed ARM remaining row: only the original vault compiler enters.
            vault = mac_context("aarch64-apple-darwin", "vault-only")
            calls.clear(); receipts.clear(); clock[0] = 100.0
            with patch.object(helper, "mac_compile_inputs", return_value=vault["macCompile"]), \
                    patch.object(helper.shutil, "which", side_effect=AssertionError("no frontend in vault-only")):
                helper.phase_mac_compile("compile", vault)
                self.assertEqual([kw["check"] for _, kw in calls], ["mac-vault-bin-compile-only"])
                self.assertEqual(calls[0][1]["timeout"], 1470)
                self.assertEqual(calls[0][0], vault_argv)
                self.assertEqual(receipts, [((vault, "compile", ["rust-version-target", "mac-cargo-version", "mac-vault-bin-compile-only"]), {"node": None})])
                calls.clear(); receipts.clear()
                with patch.object(helper, "run", side_effect=vault_failed), self.assertRaises(helper.CheckFailure):
                    helper.phase_mac_compile("compile", vault)
                self.assertFalse(receipts)
                for returned_clock in (1570.0, 99.0):
                    calls.clear(); receipts.clear(); clock[0] = 100.0
                    def vault_late(argv, **kw):
                        result = invoke(argv, **kw)
                        clock[0] = returned_clock
                        return result
                    with patch.object(helper, "run", side_effect=vault_late), self.assertRaisesRegex(helper.CheckFailure, "endpoint expired or clock reversed"):
                        helper.phase_mac_compile("compile", vault)
                    self.assertEqual([kw["check"] for _, kw in calls], ["mac-vault-bin-compile-only"])
                    self.assertFalse(receipts)
                calls.clear(); receipts.clear(); clock[0] = 100.0
                def vault_late_publication(*args, **kw):
                    receipts.append((args, kw)); clock[0] = 1570.0
                with patch.object(helper, "phase_receipt", side_effect=vault_late_publication), self.assertRaisesRegex(helper.CheckFailure, "endpoint expired or clock reversed"):
                    helper.phase_mac_compile("compile", vault)
                self.assertEqual(len(receipts), 1)
            for bad in ({key: value for key, value in vault["macCompile"].items() if key != "mode"},
                        {**vault["macCompile"], "mode": "other"}, {**vault["macCompile"], "graphs": []}):
                calls.clear(); receipts.clear(); clock[0] = 100.0
                with self.assertRaises(helper.CheckFailure):
                    helper.phase_mac_compile("compile", {**vault, "macCompile": bad})
                self.assertFalse(calls)
                self.assertFalse(receipts)

        # Original success is insufficient without the exact one-test stdout,
        # source POST and the unchanged aggregate endpoint. Both raw streams
        # remain private, exclusive and consuming-closed even on failure.
        bound = source_slots_context()
        expected_order = ["rust-version-target", "mac-cargo-version", "headless-test-compile-only", "mac-source-slots-data-test"]
        for fault in (None, "compile-nonzero", "test-nonzero", "zero-tests", "ignored", "readback", "source-post",
                      "late-test", "reversed-test", "late-receipt", "publication-failure", "expired-before-tools"):
            events, captures, calls, publications, clock = [], {}, [], [], [100.0]
            SlotsPath, writer, read = source_slots_paths(events, captures)
            source_calls = []
            def source_original(*args, **kw):
                source_calls.append("source")
                if fault == "source-post" and len(source_calls) == 2:
                    raise helper.CheckFailure("source original changed")
            def original(argv, **kw):
                calls.append((list(map(str, argv)), {**kw, "env": dict(kw["env"])}))
                if kw["check"] == "rust-version-target":
                    return "release: 1.98.0\ncommit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\nhost: x86_64-apple-darwin"
                if kw["check"] == "mac-cargo-version":
                    return "cargo 1.98.0 (abcdef123 2026-09-01)"
                if kw["check"] == "headless-test-compile-only":
                    if fault in ("compile-nonzero", "publication-failure"):
                        raise helper.CheckFailure("original compile nonzero")
                elif kw["check"] == "mac-source-slots-data-test":
                    body = source_slots_stdout()
                    if fault == "zero-tests":
                        body = body.replace(b"running 1 test", b"running 0 tests").replace(b"1 passed", b"0 passed")
                    if fault == "ignored":
                        body = body.replace(b"0 ignored", b"1 ignored")
                    kw["output"].write(body.decode())
                    if fault == "test-nonzero":
                        raise helper.CheckFailure("original test nonzero")
                    if fault == "late-test":
                        clock[0] = 970.0
                    if fault == "reversed-test":
                        clock[0] = 99.0
                return ""
            def read_original(path, expected):
                if fault == "readback":
                    raise helper.CheckFailure("output original changed")
                return read(path, expected)
            def publication(path, value):
                if fault == "publication-failure":
                    raise OSError("inert publication failure")
                publications.append((str(path), deepcopy(value)))
                if fault == "late-receipt" and path.name == "compile-checks.json":
                    clock[0] = 970.0
            observed_clock = []
            def clock_original():
                observed_clock.append(clock[0])
                return 970.0 if fault == "expired-before-tools" and len(observed_clock) > 1 else clock[0]
            with self.subTest(original_fault=fault), patch.object(helper, "Path", SlotsPath), \
                    patch.object(helper, "ordinary"), patch.object(helper, "source_unchanged", side_effect=source_original), \
                    patch.object(helper, "source_slots_source_guard"), patch.object(helper, "run", side_effect=original), \
                    patch.object(helper, "source_slots_writer", side_effect=writer), patch.object(helper, "source_slots_read", side_effect=read_original), \
                    patch.object(helper, "write_json", side_effect=publication), patch.object(helper.time, "monotonic", side_effect=clock_original), \
                    patch.dict(helper.os.environ, {"PATH": "/selected/bin", "MRK_MACOS_DEVELOPER_ID_P12_BASE64": "synthetic-not-forwarded"}, clear=True):
                if fault is None:
                    helper.phase_source_slots("compile", bound)
                else:
                    with self.assertRaises(helper.CheckFailure):
                        helper.phase_source_slots("compile", bound)
            checks = [kw["check"] for _, kw in calls]
            if fault == "expired-before-tools":
                self.assertFalse(checks)
            elif fault in ("compile-nonzero", "publication-failure", "readback"):
                self.assertEqual(checks, expected_order[:-1])
            else:
                self.assertEqual(checks, expected_order)
            commands = [(argv, kw) for argv, kw in calls if "output" in kw]
            for argv, kw in commands:
                self.assertIn("--locked", argv); self.assertIn("--offline", argv)
                self.assertEqual(argv[argv.index("--jobs") + 1], "1")
                self.assertIn("--no-default-features", argv)
                self.assertEqual(argv[argv.index("--features") + 1], "development-runtime")
                self.assertEqual(argv[argv.index("--target") + 1], "x86_64-apple-darwin")
                self.assertEqual(argv[argv.index("--manifest-path") + 1], bound["source"] + "/desktop/src-tauri/Cargo.toml")
                self.assertEqual(argv[argv.index("--target-dir") + 1], bound["root"] + "/target")
                self.assertIn("--lib", argv)
                self.assertFalse(any(value in argv for value in ("--ignored", "--release", "registration-helper", "desktop-shell")))
                self.assertEqual(kw["env"]["RUSTUP_AUTO_INSTALL"], "0")
                self.assertEqual(kw["env"]["GITHUB_SHA"], bound["sourceSha"])
                self.assertNotIn("MRK_MACOS_DEVELOPER_ID_P12_BASE64", kw["env"])
                self.assertTrue(kw["output"].closed and kw["diagnostics"].closed)
                self.assertEqual(kw["timeout"], 600 if kw["check"] == "headless-test-compile-only" else 150)
                if kw["check"] == "headless-test-compile-only":
                    self.assertEqual(argv[-2:], ["--message-format=json,json-diagnostic-short", "--no-run"])
                else:
                    self.assertNotIn("--message-format=json", argv)
                    self.assertNotIn("--message-format=json,json-diagnostic-short", argv)
                    self.assertNotIn("--no-run", argv)
                    self.assertEqual(argv[-4:], [SOURCE_SLOTS_CASE, "--", "--exact", "--test-threads=1"])
            passed = [value for path, value in publications if path.endswith("/compile-checks.json")]
            failures = [value for path, value in publications if path.endswith("/source-slots-failure.json")]
            self.assertEqual(passed, [source_slots_receipt("compile")] if fault in (None, "late-receipt") else [])
            self.assertEqual(len(failures), 0 if fault in (None, "publication-failure") else 1)
            for failure in failures:
                expected_fields = {"schemaVersion", "scope", "phase", "status", "lastFixedStage",
                    "sourceSha", "sourceTree", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt"}
                if failure["lastFixedStage"] == "headless-test-compile-only":
                    expected_fields.add("compilerDiagnostic")
                    self.assertEqual(failure["compilerDiagnostic"], {"state": "unavailable", "reason": "original-unavailable",
                                     "returnCode": None, "errors": [], "sources": []})
                if failure["lastFixedStage"] in {"headless-test-compile-only", "mac-source-slots-data-test"}:
                    expected_fields.add("originalCommandReturnCode")
                    self.assertEqual(failure["originalCommandReturnCode"], None if fault in {
                        "compile-nonzero", "test-nonzero"} else 0)
                self.assertEqual(set(failure), expected_fields)
                self.assertEqual(failure["status"], "failed-or-unknown")
                self.assertLessEqual(len(json.dumps(failure).encode()), 16384)
                self.assertNotIn("synthetic-not-forwarded", json.dumps(failure))
            if fault is None:
                self.assertEqual(len(source_calls), 2)
                self.assertTrue(all(event[2] == ("x",) for event in events if event[0] == "open"))
                self.assertEqual(len([event for event in events if event[0] == "closed"]), 4)
                # Successful commands may legitimately leave both raw streams
                # empty except for the mandatory actual libtest stdout.
                self.assertEqual(captures[bound["root"] + "/target/source-slots-compile.stdout"], b"")
                self.assertEqual(captures[bound["root"] + "/target/source-slots-test.stderr"], b"")

        # Original success is insufficient without the exact four-test stdout,
        # source POST and the unchanged aggregate endpoint. Both raw streams
        # remain private, exclusive and consuming-closed even on failure.
        initialization_bound = initialization_context()
        expected_order = ["rust-version-target", "mac-cargo-version", "headless-test-compile-only", "mac-source-slots-data-test"]
        for fault in (None, "compile-nonzero", "test-nonzero", "zero-tests", "ignored", "readback", "source-post",
                      "late-test", "reversed-test", "late-receipt", "publication-failure", "expired-before-tools"):
            events, captures, calls, publications, clock = [], {}, [], [], [100.0]
            SlotsPath, writer, read = source_slots_paths(events, captures)
            source_calls = []
            def source_original(*args, **kw):
                source_calls.append("source")
                if fault == "source-post" and len(source_calls) == 2:
                    raise helper.CheckFailure("source original changed")
            def original(argv, **kw):
                calls.append((list(map(str, argv)), {**kw, "env": dict(kw["env"])}))
                if kw["check"] == "rust-version-target":
                    return "release: 1.98.0\ncommit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\nhost: x86_64-apple-darwin"
                if kw["check"] == "mac-cargo-version":
                    return "cargo 1.98.0 (abcdef123 2026-09-01)"
                if kw["check"] == "headless-test-compile-only":
                    if fault in ("compile-nonzero", "publication-failure"):
                        raise helper.CheckFailure("original compile nonzero")
                elif kw["check"] == "mac-source-slots-data-test":
                    body = initialization_stdout()
                    if fault == "zero-tests":
                        body = body.replace(b"running 4 tests", b"running 0 tests").replace(b"4 passed", b"0 passed")
                    if fault == "ignored":
                        body = body.replace(b"0 ignored", b"1 ignored")
                    kw["output"].write(body.decode())
                    if fault == "test-nonzero":
                        raise helper.CheckFailure("original test nonzero")
                    if fault == "late-test":
                        clock[0] = 970.0
                    if fault == "reversed-test":
                        clock[0] = 99.0
                return ""
            def read_original(path, expected):
                if fault == "readback":
                    raise helper.CheckFailure("output original changed")
                return read(path, expected)
            def publication(path, value):
                if fault == "publication-failure":
                    raise OSError("inert publication failure")
                publications.append((str(path), deepcopy(value)))
                if fault == "late-receipt" and path.name == "compile-checks.json":
                    clock[0] = 970.0
            observed_clock = []
            def clock_original():
                observed_clock.append(clock[0])
                return 970.0 if fault == "expired-before-tools" and len(observed_clock) > 1 else clock[0]
            with self.subTest(original_fault=fault), patch.object(helper, "Path", SlotsPath), \
                    patch.object(helper, "ordinary"), patch.object(helper, "source_unchanged", side_effect=source_original), \
                    patch.object(helper, "source_slots_source_guard"), patch.object(helper, "run", side_effect=original), \
                    patch.object(helper, "source_slots_writer", side_effect=writer), patch.object(helper, "source_slots_read", side_effect=read_original), \
                    patch.object(helper, "write_json", side_effect=publication), patch.object(helper.time, "monotonic", side_effect=clock_original), \
                    patch.dict(helper.os.environ, {"PATH": "/selected/bin", "MRK_MACOS_DEVELOPER_ID_P12_BASE64": "synthetic-not-forwarded"}, clear=True):
                if fault is None:
                    helper.phase_source_slots("compile", initialization_bound)
                else:
                    with self.assertRaises(helper.CheckFailure):
                        helper.phase_source_slots("compile", initialization_bound)
            checks = [kw["check"] for _, kw in calls]
            if fault == "expired-before-tools":
                self.assertFalse(checks)
            elif fault in ("compile-nonzero", "publication-failure", "readback"):
                self.assertEqual(checks, expected_order[:-1])
            else:
                self.assertEqual(checks, expected_order)
            commands = [(argv, kw) for argv, kw in calls if "output" in kw]
            for argv, kw in commands:
                self.assertIn("--locked", argv); self.assertIn("--offline", argv)
                self.assertEqual(argv[argv.index("--jobs") + 1], "1")
                self.assertIn("--no-default-features", argv)
                self.assertEqual(argv[argv.index("--features") + 1], "development-runtime")
                self.assertEqual(argv[argv.index("--target") + 1], "x86_64-apple-darwin")
                self.assertEqual(argv[argv.index("--manifest-path") + 1], initialization_bound["source"] + "/desktop/src-tauri/Cargo.toml")
                self.assertEqual(argv[argv.index("--target-dir") + 1], initialization_bound["root"] + "/target")
                self.assertIn("--lib", argv)
                self.assertFalse(any(value in argv for value in ("--ignored", "--release", "registration-helper", "desktop-shell")))
                self.assertEqual(kw["env"]["RUSTUP_AUTO_INSTALL"], "0")
                self.assertEqual(kw["env"]["GITHUB_SHA"], initialization_bound["sourceSha"])
                self.assertNotIn("MRK_MACOS_DEVELOPER_ID_P12_BASE64", kw["env"])
                self.assertTrue(kw["output"].closed and kw["diagnostics"].closed)
                self.assertEqual(kw["timeout"], 600 if kw["check"] == "headless-test-compile-only" else 150)
                if kw["check"] == "headless-test-compile-only":
                    self.assertEqual(argv[-2:], ["--message-format=json,json-diagnostic-short", "--no-run"])
                else:
                    self.assertNotIn("--message-format=json", argv)
                    self.assertNotIn("--message-format=json,json-diagnostic-short", argv)
                    self.assertNotIn("--no-run", argv)
                    self.assertEqual(argv[argv.index("--"):], ["--", "--exact", "--test-threads=1", "--format", "pretty", "--color", "never", *INITIALIZATION_CASES])
            passed = [value for path, value in publications if path.endswith("/compile-checks.json")]
            failures = [value for path, value in publications if path.endswith("/source-slots-failure.json")]
            self.assertEqual(passed, [initialization_receipt("compile")] if fault in (None, "late-receipt") else [])
            self.assertEqual(len(failures), 0 if fault in (None, "publication-failure") else 1)
            for failure in failures:
                expected_fields = {"schemaVersion", "scope", "phase", "status", "lastFixedStage",
                    "sourceSha", "sourceTree", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt"}
                if failure["lastFixedStage"] == "headless-test-compile-only":
                    expected_fields.add("compilerDiagnostic")
                    self.assertEqual(failure["compilerDiagnostic"], {"state": "unavailable", "reason": "original-unavailable",
                                     "returnCode": None, "errors": [], "sources": []})
                if failure["lastFixedStage"] in {"headless-test-compile-only", "mac-source-slots-data-test"}:
                    expected_fields.add("originalCommandReturnCode")
                    self.assertEqual(failure["originalCommandReturnCode"], None if fault in {
                        "compile-nonzero", "test-nonzero"} else 0)
                expected_fields.update(("sourceSlots", "sourceSlotsSelection"))
                self.assertEqual(failure["scope"], "desktop-macos-project-initialization-data-v1")
                self.assertEqual(failure["sourceSlots"], initialization_bound["sourceSlots"])
                self.assertEqual(failure["sourceSlotsSelection"], "project-initialization4")
                self.assertEqual(set(failure), expected_fields)
                self.assertEqual(failure["status"], "failed-or-unknown")
                self.assertLessEqual(len(json.dumps(failure).encode()), 16384)
                self.assertNotIn("synthetic-not-forwarded", json.dumps(failure))
            if fault is None:
                self.assertEqual(len(source_calls), 2)
                self.assertTrue(all(event[2] == ("x",) for event in events if event[0] == "open"))
                self.assertEqual(len([event for event in events if event[0] == "closed"]), 4)
                # Successful commands may legitimately leave both raw streams
                # empty except for the mandatory actual libtest stdout.
                self.assertEqual(captures[initialization_bound["root"] + "/target/source-slots-compile.stdout"], b"")
                self.assertEqual(captures[initialization_bound["root"] + "/target/source-slots-test.stderr"], b"")

        # Original success is insufficient without the exact ten-test stdout,
        # source POST and the unchanged aggregate endpoint. Both raw streams
        # remain private, exclusive and consuming-closed even on failure.
        artifact_bound = artifact_context()
        expected_order = ["rust-version-target", "mac-cargo-version", "headless-test-compile-only", "mac-source-slots-data-test"]
        for fault in (None, "compile-nonzero", "test-nonzero", "zero-tests", "ignored", "readback", "source-post",
                      "late-test", "reversed-test", "late-receipt", "publication-failure", "expired-before-tools"):
            events, captures, calls, publications, clock = [], {}, [], [], [100.0]
            SlotsPath, writer, read = source_slots_paths(events, captures)
            source_calls = []
            def source_original(*args, **kw):
                source_calls.append("source")
                if fault == "source-post" and len(source_calls) == 2:
                    raise helper.CheckFailure("source original changed")
            def original(argv, **kw):
                calls.append((list(map(str, argv)), {**kw, "env": dict(kw["env"])}))
                if kw["check"] == "rust-version-target":
                    return "release: 1.98.0\ncommit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\nhost: x86_64-apple-darwin"
                if kw["check"] == "mac-cargo-version":
                    return "cargo 1.98.0 (abcdef123 2026-09-01)"
                if kw["check"] == "headless-test-compile-only":
                    if fault in ("compile-nonzero", "publication-failure"):
                        raise helper.CheckFailure("original compile nonzero")
                elif kw["check"] == "mac-source-slots-data-test":
                    body = artifact_stdout()
                    if fault == "zero-tests":
                        artifact_before_zero = body
                        body = body.replace(b"running 10 tests", b"running 0 tests").replace(b"10 passed", b"0 passed")
                        self.assertNotEqual(body, artifact_before_zero)
                    if fault == "ignored":
                        body = body.replace(b"0 ignored", b"1 ignored")
                    kw["output"].write(body.decode())
                    if fault == "test-nonzero":
                        raise helper.CheckFailure("original test nonzero")
                    if fault == "late-test":
                        clock[0] = 970.0
                    if fault == "reversed-test":
                        clock[0] = 99.0
                return ""
            def read_original(path, expected):
                if fault == "readback":
                    raise helper.CheckFailure("output original changed")
                return read(path, expected)
            def publication(path, value):
                if fault == "publication-failure":
                    raise OSError("inert publication failure")
                publications.append((str(path), deepcopy(value)))
                if fault == "late-receipt" and path.name == "compile-checks.json":
                    clock[0] = 970.0
            observed_clock = []
            def clock_original():
                observed_clock.append(clock[0])
                return 970.0 if fault == "expired-before-tools" and len(observed_clock) > 1 else clock[0]
            with self.subTest(original_fault=fault), patch.object(helper, "Path", SlotsPath), \
                    patch.object(helper, "ordinary"), patch.object(helper, "source_unchanged", side_effect=source_original), \
                    patch.object(helper, "source_slots_source_guard"), patch.object(helper, "run", side_effect=original), \
                    patch.object(helper, "source_slots_writer", side_effect=writer), patch.object(helper, "source_slots_read", side_effect=read_original), \
                    patch.object(helper, "write_json", side_effect=publication), patch.object(helper.time, "monotonic", side_effect=clock_original), \
                    patch.dict(helper.os.environ, {"PATH": "/selected/bin", "MRK_MACOS_DEVELOPER_ID_P12_BASE64": "synthetic-not-forwarded"}, clear=True):
                if fault is None:
                    helper.phase_source_slots("compile", artifact_bound)
                else:
                    with self.assertRaises(helper.CheckFailure):
                        helper.phase_source_slots("compile", artifact_bound)
            checks = [kw["check"] for _, kw in calls]
            if fault == "expired-before-tools":
                self.assertFalse(checks)
            elif fault in ("compile-nonzero", "publication-failure", "readback"):
                self.assertEqual(checks, expected_order[:-1])
            else:
                self.assertEqual(checks, expected_order)
            commands = [(argv, kw) for argv, kw in calls if "output" in kw]
            for argv, kw in commands:
                self.assertIn("--locked", argv); self.assertIn("--offline", argv)
                self.assertEqual(argv[argv.index("--jobs") + 1], "1")
                self.assertIn("--no-default-features", argv)
                self.assertEqual(argv[argv.index("--features") + 1], "development-runtime")
                self.assertEqual(argv[argv.index("--target") + 1], "x86_64-apple-darwin")
                self.assertEqual(argv[argv.index("--manifest-path") + 1], artifact_bound["source"] + "/desktop/src-tauri/Cargo.toml")
                self.assertEqual(argv[argv.index("--target-dir") + 1], artifact_bound["root"] + "/target")
                self.assertIn("--lib", argv)
                self.assertFalse(any(value in argv for value in ("--ignored", "--release", "registration-helper", "desktop-shell")))
                self.assertEqual(kw["env"]["RUSTUP_AUTO_INSTALL"], "0")
                self.assertEqual(kw["env"]["GITHUB_SHA"], artifact_bound["sourceSha"])
                self.assertNotIn("MRK_MACOS_DEVELOPER_ID_P12_BASE64", kw["env"])
                self.assertTrue(kw["output"].closed and kw["diagnostics"].closed)
                self.assertEqual(kw["timeout"], 600 if kw["check"] == "headless-test-compile-only" else 150)
                if kw["check"] == "headless-test-compile-only":
                    self.assertEqual(argv[-2:], ["--message-format=json,json-diagnostic-short", "--no-run"])
                else:
                    self.assertNotIn("--message-format=json", argv)
                    self.assertNotIn("--message-format=json,json-diagnostic-short", argv)
                    self.assertNotIn("--no-run", argv)
                    self.assertEqual(argv[argv.index("--"):], ["--", "--exact", "--test-threads=1", "--format", "pretty", "--color", "never", *ARTIFACT_CASES])
            passed = [value for path, value in publications if path.endswith("/compile-checks.json")]
            failures = [value for path, value in publications if path.endswith("/source-slots-failure.json")]
            self.assertEqual(passed, [artifact_receipt("compile")] if fault in (None, "late-receipt") else [])
            self.assertEqual(len(failures), 0 if fault in (None, "publication-failure") else 1)
            for failure in failures:
                expected_fields = {"schemaVersion", "scope", "phase", "status", "lastFixedStage",
                    "sourceSha", "sourceTree", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt"}
                if failure["lastFixedStage"] == "headless-test-compile-only":
                    expected_fields.add("compilerDiagnostic")
                    self.assertEqual(failure["compilerDiagnostic"], {"state": "unavailable", "reason": "original-unavailable",
                                     "returnCode": None, "errors": [], "sources": []})
                if failure["lastFixedStage"] in {"headless-test-compile-only", "mac-source-slots-data-test"}:
                    expected_fields.add("originalCommandReturnCode")
                    self.assertEqual(failure["originalCommandReturnCode"], None if fault in {
                        "compile-nonzero", "test-nonzero"} else 0)
                expected_fields.update(("sourceSlots", "sourceSlotsSelection"))
                self.assertEqual(failure["scope"], "desktop-macos-artifact-setup-data-v1")
                self.assertEqual(failure["sourceSlots"], artifact_bound["sourceSlots"])
                self.assertEqual(failure["sourceSlotsSelection"], "artifact-setup10")
                self.assertEqual(set(failure), expected_fields)
                self.assertEqual(failure["status"], "failed-or-unknown")
                self.assertLessEqual(len(json.dumps(failure).encode()), 16384)
                self.assertNotIn("synthetic-not-forwarded", json.dumps(failure))
            if fault is None:
                self.assertEqual(len(source_calls), 2)
                self.assertTrue(all(event[2] == ("x",) for event in events if event[0] == "open"))
                self.assertEqual(len([event for event in events if event[0] == "closed"]), 4)
                # Successful commands may legitimately leave both raw streams
                # empty except for the mandatory actual libtest stdout.
                self.assertEqual(captures[artifact_bound["root"] + "/target/source-slots-compile.stdout"], b"")
                self.assertEqual(captures[artifact_bound["root"] + "/target/source-slots-test.stderr"], b"")

        # Original success is insufficient without the exact one-test stdout,
        # source POST and the unchanged aggregate endpoint. Both raw streams
        # remain private, exclusive and consuming-closed even on failure.
        environment_setup_bound = environment_setup_context()
        expected_order = ["rust-version-target", "mac-cargo-version", "headless-test-compile-only", "mac-source-slots-data-test"]
        for fault in (None, "compile-nonzero", "test-nonzero", "zero-tests", "ignored", "readback", "source-post",
                      "late-test", "reversed-test", "late-receipt", "publication-failure", "expired-before-tools"):
            events, captures, calls, publications, clock = [], {}, [], [], [100.0]
            SlotsPath, writer, read = source_slots_paths(events, captures)
            source_calls = []
            def source_original(*args, **kw):
                source_calls.append("source")
                if fault == "source-post" and len(source_calls) == 2:
                    raise helper.CheckFailure("source original changed")
            def original(argv, **kw):
                calls.append((list(map(str, argv)), {**kw, "env": dict(kw["env"])}))
                if kw["check"] == "rust-version-target":
                    return "release: 1.98.0\ncommit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\nhost: x86_64-apple-darwin"
                if kw["check"] == "mac-cargo-version":
                    return "cargo 1.98.0 (abcdef123 2026-09-01)"
                if kw["check"] == "headless-test-compile-only":
                    if fault in ("compile-nonzero", "publication-failure"):
                        raise helper.CheckFailure("original compile nonzero")
                elif kw["check"] == "mac-source-slots-data-test":
                    body = environment_setup_stdout()
                    if fault == "zero-tests":
                        environment_setup_before_zero = body
                        body = body.replace(b"running 1 test", b"running 0 tests").replace(b"1 passed", b"0 passed")
                        self.assertNotEqual(body, environment_setup_before_zero)
                    if fault == "ignored":
                        body = body.replace(b"0 ignored", b"1 ignored")
                    kw["output"].write(body.decode())
                    if fault == "test-nonzero":
                        raise helper.CheckFailure("original test nonzero")
                    if fault == "late-test":
                        clock[0] = 970.0
                    if fault == "reversed-test":
                        clock[0] = 99.0
                return ""
            def read_original(path, expected):
                if fault == "readback":
                    raise helper.CheckFailure("output original changed")
                return read(path, expected)
            def publication(path, value):
                if fault == "publication-failure":
                    raise OSError("inert publication failure")
                publications.append((str(path), deepcopy(value)))
                if fault == "late-receipt" and path.name == "compile-checks.json":
                    clock[0] = 970.0
            observed_clock = []
            def clock_original():
                observed_clock.append(clock[0])
                return 970.0 if fault == "expired-before-tools" and len(observed_clock) > 1 else clock[0]
            with self.subTest(environment_setup_fault=fault), patch.object(helper, "Path", SlotsPath), \
                    patch.object(helper, "ordinary"), patch.object(helper, "source_unchanged", side_effect=source_original), \
                    patch.object(helper, "source_slots_source_guard"), patch.object(helper, "run", side_effect=original), \
                    patch.object(helper, "source_slots_writer", side_effect=writer), patch.object(helper, "source_slots_read", side_effect=read_original), \
                    patch.object(helper, "write_json", side_effect=publication), patch.object(helper.time, "monotonic", side_effect=clock_original), \
                    patch.dict(helper.os.environ, {"PATH": "/selected/bin", "MRK_MACOS_DEVELOPER_ID_P12_BASE64": "synthetic-not-forwarded"}, clear=True):
                if fault is None:
                    helper.phase_source_slots("compile", environment_setup_bound)
                else:
                    with self.assertRaises(helper.CheckFailure):
                        helper.phase_source_slots("compile", environment_setup_bound)
            checks = [kw["check"] for _, kw in calls]
            if fault == "expired-before-tools":
                self.assertFalse(checks)
            elif fault in ("compile-nonzero", "publication-failure", "readback"):
                self.assertEqual(checks, expected_order[:-1])
            else:
                self.assertEqual(checks, expected_order)
            commands = [(argv, kw) for argv, kw in calls if "output" in kw]
            for argv, kw in commands:
                self.assertIn("--locked", argv); self.assertIn("--offline", argv)
                self.assertEqual(argv[argv.index("--jobs") + 1], "1")
                self.assertIn("--no-default-features", argv)
                self.assertEqual(argv[argv.index("--features") + 1], "development-runtime")
                self.assertEqual(argv[argv.index("--target") + 1], "x86_64-apple-darwin")
                self.assertEqual(argv[argv.index("--manifest-path") + 1], environment_setup_bound["source"] + "/desktop/src-tauri/Cargo.toml")
                self.assertEqual(argv[argv.index("--target-dir") + 1], environment_setup_bound["root"] + "/target")
                self.assertIn("--lib", argv)
                self.assertFalse(any(value in argv for value in ("--ignored", "--release", "registration-helper", "desktop-shell")))
                self.assertEqual(kw["env"]["RUSTUP_AUTO_INSTALL"], "0")
                self.assertEqual(kw["env"]["GITHUB_SHA"], environment_setup_bound["sourceSha"])
                self.assertNotIn("MRK_MACOS_DEVELOPER_ID_P12_BASE64", kw["env"])
                self.assertTrue(kw["output"].closed and kw["diagnostics"].closed)
                self.assertEqual(kw["timeout"], 600 if kw["check"] == "headless-test-compile-only" else 150)
                if kw["check"] == "headless-test-compile-only":
                    self.assertEqual(argv[-2:], ["--message-format=json,json-diagnostic-short", "--no-run"])
                else:
                    self.assertNotIn("--message-format=json", argv)
                    self.assertNotIn("--message-format=json,json-diagnostic-short", argv)
                    self.assertNotIn("--no-run", argv)
                    self.assertEqual(argv[argv.index("--"):], ["--", "--exact", "--test-threads=1", "--format", "pretty", "--color", "never", *ENVIRONMENT_CASES])
            passed = [value for path, value in publications if path.endswith("/compile-checks.json")]
            failures = [value for path, value in publications if path.endswith("/source-slots-failure.json")]
            self.assertEqual(passed, [environment_setup_receipt("compile")] if fault in (None, "late-receipt") else [])
            self.assertEqual(len(failures), 0 if fault in (None, "publication-failure") else 1)
            for failure in failures:
                expected_fields = {"schemaVersion", "scope", "phase", "status", "lastFixedStage",
                    "sourceSha", "sourceTree", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt"}
                if failure["lastFixedStage"] == "headless-test-compile-only":
                    expected_fields.add("compilerDiagnostic")
                    self.assertEqual(failure["compilerDiagnostic"], {"state": "unavailable", "reason": "original-unavailable",
                                     "returnCode": None, "errors": [], "sources": []})
                if failure["lastFixedStage"] in {"headless-test-compile-only", "mac-source-slots-data-test"}:
                    expected_fields.add("originalCommandReturnCode")
                    self.assertEqual(failure["originalCommandReturnCode"], None if fault in {
                        "compile-nonzero", "test-nonzero"} else 0)
                expected_fields.update(("sourceSlots", "sourceSlotsSelection"))
                self.assertEqual(failure["scope"], "desktop-macos-environment-setup-data-v1")
                self.assertEqual(failure["sourceSlots"], environment_setup_bound["sourceSlots"])
                self.assertEqual(failure["sourceSlotsSelection"], "environment-setup1")
                self.assertEqual(set(failure), expected_fields)
                self.assertEqual(failure["status"], "failed-or-unknown")
                self.assertLessEqual(len(json.dumps(failure).encode()), 16384)
                self.assertNotIn("synthetic-not-forwarded", json.dumps(failure))
            if fault is None:
                self.assertEqual(len(source_calls), 2)
                self.assertTrue(all(event[2] == ("x",) for event in events if event[0] == "open"))
                self.assertEqual(len([event for event in events if event[0] == "closed"]), 4)
                # Successful commands may legitimately leave both raw streams
                # empty except for the mandatory actual libtest stdout.
                self.assertEqual(captures[environment_setup_bound["root"] + "/target/source-slots-compile.stdout"], b"")
                self.assertEqual(captures[environment_setup_bound["root"] + "/target/source-slots-test.stderr"], b"")

        # The unchanged run owner keeps its private-output contract and actual
        # original exit/timeout handling; subprocess.run is never entered here.
        with io.StringIO() as output, io.StringIO() as diagnostics, io.StringIO() as notices, \
                contextlib.redirect_stdout(notices), patch.object(helper.subprocess, "run") as original_run:
            helper.run(["/fixed/cargo"], check="mac-source-slots-data-test", cwd=PurePosixPath("/inert"), env={},
                       timeout=150, output=output, diagnostics=diagnostics)
            self.assertEqual(original_run.call_args.kwargs["stdout"], output)
            self.assertEqual(original_run.call_args.kwargs["stderr"], diagnostics)
            self.assertTrue(original_run.call_args.kwargs["check"])
            self.assertEqual(original_run.call_count, 1)
            for fields in ({"capture": True, "output": output, "diagnostics": diagnostics}, {"diagnostics": diagnostics}):
                with self.assertRaises(helper.CheckFailure):
                    helper.run(["/fixed/cargo"], check="mac-source-slots-data-test", cwd=PurePosixPath("/inert"), env={}, timeout=150, **fields)
            self.assertEqual(original_run.call_count, 1)
            for error in (helper.subprocess.CalledProcessError(101, ["/fixed/cargo"]),
                          helper.subprocess.TimeoutExpired(["/fixed/cargo"], 150), OSError("inert")):
                original_run.side_effect = error
                with self.assertRaises(helper.CheckFailure) as failure:
                    helper.run(["/fixed/cargo"], check="mac-source-slots-data-test", cwd=PurePosixPath("/inert"), env={},
                               timeout=150, output=output, diagnostics=diagnostics)
                self.assertEqual(type(failure.exception), helper.CheckFailure)
                if isinstance(error, helper.subprocess.CalledProcessError):
                    self.assertEqual(str(failure.exception), "Fixed check mac-source-slots-data-test exited 101")
                    self.assertEqual(failure.exception.__dict__["_returned_command"], ("mac-source-slots-data-test", 101))
                else:
                    self.assertNotIn("_returned_command", failure.exception.__dict__)

        # Exercise the actual no-follow bounded original reader with inert FD
        # bindings, not a mock return from the parser. No host open/read/close.
        actual_os = helper.os
        class Info:
            st_dev, st_ino, st_mode, st_uid, st_gid, st_nlink = 1, 2, 0o100600, 501, 20, 1
            st_mtime_ns, st_ctime_ns = 3, 4
            def __init__(self, size):
                self.st_size = size
        class OriginalOS:
            O_RDONLY, O_NOFOLLOW = actual_os.O_RDONLY, actual_os.O_NOFOLLOW
            O_CLOEXEC, O_NONBLOCK = actual_os.O_CLOEXEC, actual_os.O_NONBLOCK
            def __init__(self, body, fault):
                self.body, self.fault, self.position, self.closes, self.fstats, self.opened = body, fault, 0, [], 0, []
                self.info = Info(len(body))
                if fault == "oversize": self.info.st_size = 1024 * 1024 + 1
                if fault == "mode": self.info.st_mode = 0o100644
                if fault == "link": self.info.st_nlink = 2
                if fault == "uid": self.info.st_uid = 502
            def geteuid(self): return 501
            def open(self, path, flags):
                self.opened.append((str(path), flags))
                return 77
            def fstat(self, fd):
                self_outer.assertEqual(fd, 77)
                self.fstats += 1
                if self.fault == "post" and self.fstats == 2:
                    self.info.st_mtime_ns += 1
                return self.info
            def read(self, fd, size):
                self_outer.assertEqual(fd, 77)
                self_outer.assertLessEqual(size, 65536)
                if self.fault == "early": return b""
                if self.fault == "tail" and self.position == len(self.body): return b"x"
                result = self.body[self.position:self.position + size]; self.position += len(result)
                return result
            def close(self, fd):
                self_outer.assertEqual(fd, 77); self.closes.append(fd)
        class ReadPath(PurePosixPath):
            def lstat(self):
                if original.fault == "named":
                    altered = Info(original.info.st_size); altered.st_ino = 8
                    return altered
                return original.info
        self_outer = self
        for name, body in (("source-slots-test.stdout", source_slots_stdout()), ("source-slots-test.stderr", b""),
                           ("metadata.json", b'{"packages":[]}')):
            faults = (None, "named", "mode", "link", "uid", "post", "tail") + (("early",) if body else ())
            if name != "metadata.json": faults += ("oversize",)
            for fault in faults:
                original = OriginalOS(body, fault)
                expected = helper.source_slots_identity(original.info)
                path = ReadPath("/inert/target") / name
                with self.subTest(read_name=name, fault=fault), patch.object(helper, "os", original):
                    if fault is None:
                        self.assertEqual(helper.source_slots_read(path, expected), body if name == "source-slots-test.stdout" else b"")
                    else:
                        with self.assertRaises(helper.CheckFailure):
                            helper.source_slots_read(path, expected)
                self.assertEqual(original.closes, [77])
                self.assertEqual(original.opened, [(str(path), actual_os.O_RDONLY | actual_os.O_NOFOLLOW | actual_os.O_CLOEXEC | actual_os.O_NONBLOCK)])
        original = OriginalOS(b"", None)
        with patch.object(helper, "os", original):
            with self.assertRaises(helper.CheckFailure):
                helper.source_slots_read(ReadPath("/inert/metadata.json"), helper.source_slots_identity(original.info))
            with self.assertRaises(helper.CheckFailure):
                helper.source_slots_read(ReadPath("/inert/unselected"), helper.source_slots_identity(original.info))
        self.assertEqual(original.closes, [77])
        self.assertEqual(len(original.opened), 1)
        class Writer:
            def fileno(self): return 77
        for fault in (None, "named", "mode", "link", "uid"):
            original = OriginalOS(b"inert", fault)
            with self.subTest(writer_fault=fault), patch.object(helper, "os", original):
                if fault is None:
                    self.assertEqual(helper.source_slots_writer(ReadPath("/inert/source-slots-test.stdout"), Writer()),
                                     helper.source_slots_identity(original.info))
                else:
                    with self.assertRaises(helper.CheckFailure):
                        helper.source_slots_writer(ReadPath("/inert/source-slots-test.stdout"), Writer())
            self.assertFalse(original.closes)  # The surrounding original stream owns close, not this check.

        # Observer-only stdout uses the installed DATA graph's four-MiB budget.
        # Default stdout and observer stderr stay at two/one MiB respectively.
        observer_limit = 4 * 1024 * 1024
        self.assertEqual(helper.MAC_OBSERVER_STDOUT_LIMIT, observer_limit)
        for observer_mode, name, cap in ((False, "source-slots-compile.stdout", 2 * 1024 * 1024),
                                         (True, "source-slots-compile.stdout", observer_limit),
                                         (True, "source-slots-compile.stderr", 1024 * 1024)):
            for extra in (0, 1):
                original = OriginalOS(b"x" * (cap + extra), None)
                expected = helper.source_slots_identity(original.info)
                path = ReadPath("/inert/target") / name
                with self.subTest(observer_budget=observer_mode, output=name, extra=extra), patch.object(helper, "os", original):
                    if extra:
                        with self.assertRaises(helper.CheckFailure) as refused:
                            helper.source_slots_read(path, expected, observer=observer_mode)
                        facts = refused.exception.__dict__["_source_slots_capture_admission"]
                        self.assertEqual(facts, {"schemaVersion": 1, "output": name, "limitBytes": cap,
                            "writerBytes": cap + 1, "openedBytes": cap + 1, "failedCheck": "byte-bound",
                            "readerClosed": True, "partialObservation": True})
                        self.assertEqual(original.position, 0)
                        self.assertEqual(helper.source_slots_capture_admission(facts, observer=observer_mode), facts)
                        if observer_mode and name.endswith("stdout"):
                            self.assertIsNone(helper.source_slots_capture_admission(facts))
                    else:
                        self.assertEqual(helper.source_slots_read(path, expected, observer=observer_mode), b"")
                        self.assertEqual(original.position, cap)
                        self.assertEqual(original.fstats, 2)
                self.assertEqual(original.closes, [77])
                self.assertEqual(original.opened, [(str(path), actual_os.O_RDONLY | actual_os.O_NOFOLLOW | actual_os.O_CLOEXEC | actual_os.O_NONBLOCK)])
        original = OriginalOS(b"x" * observer_limit, None)
        with patch.object(helper, "os", original):
            retained = helper.source_slots_read(ReadPath("/inert/source-slots-compile.stdout"),
                helper.source_slots_identity(original.info), retain=True, observer=True)
        self.assertEqual(retained, original.body)
        self.assertEqual(original.position, observer_limit)
        self.assertEqual(original.closes, [77])
        for mode, name in ((1, "source-slots-compile.stdout"), (None, "source-slots-compile.stdout"),
                           ("true", "source-slots-compile.stdout"), (True, "metadata.json"),
                           (True, "source-slots-test.stdout")):
            original = OriginalOS(b"inert", None)
            with self.subTest(invalid_observer=mode, output=name), patch.object(helper, "os", original), self.assertRaises(helper.CheckFailure):
                helper.source_slots_read(ReadPath("/inert") / name, helper.source_slots_identity(original.info), observer=mode)
            self.assertEqual(original.opened, [])
            self.assertEqual(original.closes, [])

        # Failed Cargo JSON is optional DATA, not a new success/cleanup path.
        # All path names below are inert; only a fixed Git metadata double is
        # consulted, never a SOURCE body, compiler, dependency or native API.
        source = bound["source"]
        stdout_limit = 2 * 1024 * 1024  # Only complete compiler stdout; all other stream caps stay fixed.
        app = "desktop/src-tauri"
        native = "desktop/native/macos-installed-native"
        private = "synthetic-private-diagnostic-must-not-escape"
        def primary(name, line=19, column=7):
            return {"file_name": name, "line_start": line, "column_start": column, "is_primary": True}
        def message(code="E0433", spans=None, wording=private, package=app):
            return {"reason": "compiler-message", "manifest_path": source + "/" + package + "/Cargo.toml",
                    "message": {"level": "error", "code": None if code is None else {"code": code, "explanation": private},
                                "message": wording, "spans": [primary("src/lib.rs")] if spans is None else spans,
                                "rendered": private}}
        terminal = {"reason": "build-finished", "success": False}
        def cargo_bytes(rows):
            return b"".join((json.dumps(row, separators=(",", ":")) + "\n").encode() for row in rows)
        blob = "a" * 40
        simple_raw = cargo_bytes([message(), terminal])
        metadata = "100644 blob " + blob + "\t" + app + "/src/lib.rs\0"
        calls, source_checks = [], []
        def metadata_original(argv, **kw):
            calls.append((argv, kw))
            self.assertEqual(source_checks, ["post"])
            return metadata
        with patch.object(helper, "source_unchanged", side_effect=lambda *a, **kw: source_checks.append("post")), \
                patch.object(helper, "run", side_effect=metadata_original), patch.dict(helper.os.environ, {"PATH": "/fixed/bin"}, clear=True):
            diagnostic = helper.source_slots_compiler_diagnostic(bound, simple_raw, b"", 101, timeout_for=lambda cap: cap)
        self.assertEqual(diagnostic, {"state": "complete", "reason": None, "returnCode": 101,
            "errors": [{"category": "compiler-error", "code": "E0433", "package": "mobile-release-kit-desktop",
                        "spans": [{"source": 0, "line": 19, "column": 7}], "unboundSpans": 0}],
            "sources": [{"path": app + "/src/lib.rs", "gitBlob": blob}]})
        self.assertEqual(len(calls), 1)
        argv, fields = calls[0]
        self.assertEqual(argv, [bound["git"], "ls-tree", "-z", "--full-tree", bound["sourceSha"], "--", app + "/src/lib.rs"])
        self.assertEqual(fields["check"], "source-slots-diagnostic-source")
        self.assertEqual(str(fields["cwd"]), source)
        self.assertEqual(fields["timeout"], 15)
        self.assertTrue(fields["capture"])
        self.assertEqual(fields["env"]["HOME"], bound["root"] + "/home")
        self.assertNotIn(private, json.dumps(diagnostic))
        self.assertNotIn(source, json.dumps(diagnostic))

        kinds = [message("E0599", [primary(source + "/" + app + "/src/lib.rs")]),
                 message(None, [primary("src/lib.rs")]),
                 message(None, [], "linking with `cc` failed: exit status: 1 " + private),
                 message("E0308", [primary("build.rs")], package=native),
                 message("E0001", [primary("/foreign/" + private + ".rs")], package="foreign")]
        stderr = ("error: failed to run custom build command for `mrk-macos-installed-native v0.1.0 (" + private + ")`\n"
                  "error: failed to run custom build command for `foreign-package v9.9.9`\n").encode()
        records = helper.source_slots_diagnostic_records(cargo_bytes(kinds + [terminal]), stderr, source)
        self.assertEqual([row["category"] for row in records], ["compiler-error", "compiler-error-without-code", "linker-error",
                         "compiler-error", "compiler-error", "build-script-failure", "build-script-failure"])
        self.assertEqual([row["code"] for row in records], ["E0599", None, None, "E0308", "E0001", None, None])
        self.assertEqual(records[3]["spans"][0]["path"], native + "/build.rs")
        self.assertEqual(records[4]["unboundSpans"], 1)
        self.assertEqual(records[5]["package"], "mrk-macos-installed-native")
        self.assertEqual(records[6]["package"], "unknown")
        self.assertNotIn(private, json.dumps(records))
        for bad_path in ("../src/lib.rs", "src/../lib.rs", "src//lib.rs", "src/./lib.rs", "src/*.rs", "src/a\0.rs",
                         "/foreign/src/lib.rs", source + "-other/" + app + "/src/lib.rs", "file:///src/lib.rs",
                         "lib.rs", "desktop/not-a-package/lib.rs", "desktop/src-tauri-other/lib.rs", "src/lib.txt"):
            with self.subTest(unbound_path=bad_path):
                row = helper.source_slots_diagnostic_records(cargo_bytes([message(spans=[primary(bad_path)]), terminal]), b"", source)[0]
                self.assertEqual(row["spans"], [])
                self.assertEqual(row["unboundSpans"], 1)
        for good_path in ("src/lib.rs", app + "/src/lib.rs", source + "/" + app + "/src/lib.rs"):
            row = helper.source_slots_diagnostic_records(cargo_bytes([message(spans=[primary(good_path)]), terminal]), b"", source)[0]
            self.assertEqual(row["spans"], [{"path": app + "/src/lib.rs", "line": 19, "column": 7}])
        # The observed integration crate uses literal tests/../src imports.
        # Bind this single known alias only for the explicit observer route;
        # raw diagnostics, arbitrary parent traversal and foreign crates stay out.
        aliases = ("tests/../src/lib.rs", app + "/tests/../src/lib.rs",
                   source + "/" + app + "/tests/../src/lib.rs")
        for alias in aliases:
            raw = cargo_bytes([message(spans=[primary(alias)]), terminal])
            self.assertEqual(helper.source_slots_diagnostic_records(raw, b"", source)[0]["unboundSpans"], 1)
            row = helper.source_slots_diagnostic_records(raw, b"", source, observer=True)[0]
            self.assertEqual(row["spans"], [{"path": app + "/src/lib.rs", "line": 19, "column": 7}])
            self.assertEqual(row["unboundSpans"], 0)
        for prefix in ("tests/", app + "/tests/", source + "/" + app + "/tests/"):
            raw = cargo_bytes([message(spans=[primary(prefix + "installed_shell_observation.rs")]), terminal])
            row = helper.source_slots_diagnostic_records(raw, b"", source, observer=True)[0]
            self.assertEqual(row["spans"][0]["path"], app + "/tests/installed_shell_observation.rs")
        for bad_path in ("tests/../../src/lib.rs", "tests/../src/../lib.rs", "tests/../src/./lib.rs",
                         "tests/../src//lib.rs", "tests/../src/a\0.rs", "tests/../src/lib.txt",
                         "tests/../src/" + "x" * 479 + ".rs", "tests/../../native/macos-installed-native/src/lib.rs"):
            raw = cargo_bytes([message(spans=[primary(bad_path)]), terminal])
            row = helper.source_slots_diagnostic_records(raw, b"", source, observer=True)[0]
            self.assertEqual((row["spans"], row["unboundSpans"]), ([], 1))
        exact_limit = "tests/../src/" + "x" * 478 + ".rs"
        self.assertEqual(len(app + "/" + exact_limit), 512)
        row = helper.source_slots_diagnostic_records(
            cargo_bytes([message(spans=[primary(exact_limit)]), terminal]), b"", source, observer=True)[0]
        self.assertEqual(row["unboundSpans"], 0)
        self.assertEqual(row["spans"][0]["path"], app + "/src/" + "x" * 478 + ".rs")
        for package in (native, "foreign"):
            raw = cargo_bytes([message(spans=[primary(aliases[0])], package=package), terminal])
            self.assertEqual(helper.source_slots_diagnostic_records(raw, b"", source, observer=True)[0]["unboundSpans"], 1)
        for invalid in (1, None, "true"):
            with self.assertRaises(helper.CheckFailure):
                helper.source_slots_diagnostic_records(simple_raw, b"", source, observer=invalid)
        observer_bound = dict(bound, executionScope=helper.MAC_COMPILE_SCOPE,
                              workflowPath=helper.MAC_COMPILE_WORKFLOW, macCompile={"mode": helper.MAC_OBSERVER_MODE})
        observer_raw = cargo_bytes([message(spans=[primary(aliases[0])]), terminal])
        for present in (True, False):
            calls.clear(); source_checks.clear()
            with patch.object(helper, "source_unchanged", side_effect=lambda *a, **kw: source_checks.append("post")), \
                    patch.object(helper, "run", side_effect=metadata_original if present else lambda *a, **kw: ""), \
                    patch.dict(helper.os.environ, {"PATH": "/fixed/bin"}, clear=True):
                result = helper.source_slots_compiler_diagnostic(observer_bound, observer_raw, b"", 101,
                                                                  timeout_for=lambda cap: cap)
            self.assertEqual(result["returnCode"], 101)
            self.assertEqual(result["state"], "complete")
            self.assertEqual(result["sources"], [{"path": app + "/src/lib.rs", "gitBlob": blob}] if present else [])
            self.assertEqual(result["errors"][0]["unboundSpans"], 0 if present else 1)
            if present:
                self.assertEqual(calls[0][0][-1], app + "/src/lib.rs")
                self.assertEqual(result["errors"][0]["spans"], [{"source": 0, "line": 19, "column": 7}])
            else:
                self.assertEqual(result["errors"][0]["spans"], [])
            self.assertNotIn(private, json.dumps(result))
            self.assertNotIn(source, json.dumps(result))
        malformed = [b"", simple_raw[:-1], simple_raw + b"\n", simple_raw + cargo_bytes([terminal]), b"\xff\n",
                     simple_raw.replace(b'"level":"error"', b'"level":"error","level":"error"'),
                     simple_raw.replace(b'"line_start":19', b'"line_start":NaN'),
                     cargo_bytes([message()]), cargo_bytes([message(), {"reason": "build-finished", "success": True}]),
                     cargo_bytes([message("E12345"), terminal]), cargo_bytes([message(spans=[primary("src/lib.rs", True)]), terminal]),
                     cargo_bytes([message(spans=[primary("src/lib.rs", 0)]), terminal]),
                     cargo_bytes([message(spans=[primary("src/lib.rs", column=1048577)]), terminal]),
                     cargo_bytes([message()] * 17 + [terminal]), cargo_bytes([message(spans=[primary("src/lib.rs")] * 33), terminal]),
                     cargo_bytes([message(spans=[primary("src/" + str(n) + ".rs") for n in range(9)]), terminal]),
                     cargo_bytes([{"reason": "compiler-artifact"}] * 4096 + [terminal]), b"x" * (stdout_limit + 1)]
        for overflow in (b"1e9999", b"-1e9999"):
            malformed.append(b'{"reason":"compiler-artifact","ignored":{"nested":' + overflow + b'}}\n' + simple_raw)
            malformed.append(simple_raw.replace(b'"reason":"compiler-message"',
                             b'"reason":"compiler-message","ignored":{"nested":' + overflow + b'}'))
        finite = b'{"reason":"compiler-artifact","ignored":{"nested":[1.25,-1e300]}}\n' + simple_raw
        self.assertEqual(helper.source_slots_diagnostic_records(finite, b"", source),
                         helper.source_slots_diagnostic_records(simple_raw, b"", source))
        # Genuine complete JSON envelopes cross the old byte limit without
        # losing terminal/error validation or escaping the small public result.
        prefix, suffix = b'{"reason":"compiler-artifact","opaque":"', b'"}\n'
        for size in (1406142, stdout_limit, stdout_limit + 1):
            padded = prefix + b"x" * (size - len(prefix + suffix + simple_raw)) + suffix + simple_raw
            self.assertEqual(len(padded), size)
            with self.subTest(compiler_diagnostic_bytes=size):
                if size > stdout_limit:
                    with self.assertRaises(helper.CheckFailure):
                        helper.source_slots_diagnostic_records(padded, b"", source)
                else:
                    self.assertEqual(helper.source_slots_diagnostic_records(padded, b"", source),
                                     helper.source_slots_diagnostic_records(simple_raw, b"", source))
                    with patch.object(helper, "source_unchanged"), patch.object(helper, "run", return_value=metadata), \
                            patch.dict(helper.os.environ, {"PATH": "/fixed/bin"}, clear=True):
                        bounded = helper.source_slots_compiler_diagnostic(bound, padded, b"", 101, timeout_for=lambda cap: cap)
                    self.assertEqual(bounded, diagnostic)
                    self.assertLessEqual(len(json.dumps(bounded).encode()), 12288)
                    self.assertNotIn(private, json.dumps(bounded))
        for raw in malformed:
            with self.subTest(malformed_bytes=len(raw)), self.assertRaises(helper.CheckFailure):
                helper.source_slots_diagnostic_records(raw, b"", source)
        with self.assertRaises(helper.CheckFailure):
            helper.source_slots_diagnostic_records(simple_raw, b"x" * (1024 * 1024 + 1), source)
        for fault in ("missing", "bad-mode", "duplicate", "extra-path", "partial", "large", "source", "clock"):
            returned = {"missing": "", "bad-mode": metadata.replace("100644", "120000"), "duplicate": metadata * 2,
                        "extra-path": metadata.replace(app + "/src/lib.rs", native + "/src/lib.rs"),
                        "partial": metadata[:-1], "large": metadata * 200}.get(fault, metadata)
            with self.subTest(metadata_fault=fault), patch.object(helper, "run", return_value=returned) as metadata_run, \
                    patch.object(helper, "source_unchanged", side_effect=helper.CheckFailure("inert source") if fault == "source" else None), \
                    patch.dict(helper.os.environ, {"PATH": "/fixed/bin"}, clear=True):
                def remaining(cap):
                    if fault == "clock": raise helper.CheckFailure("inert late")
                    return cap
                observed = helper.source_slots_compiler_diagnostic(bound, simple_raw, b"", 101, timeout_for=remaining)
            if fault == "missing":
                self.assertEqual(observed["state"], "complete")
                self.assertEqual(observed["sources"], [])
                self.assertEqual(observed["errors"][0]["spans"], [])
                self.assertEqual(observed["errors"][0]["unboundSpans"], 1)
            else:
                self.assertEqual(observed["state"], "unavailable")
                self.assertEqual(observed["errors"], [])
                self.assertEqual(observed["sources"], [])
            if fault in ("source", "clock"):
                self.assertEqual(metadata_run.call_count, 0)
        with patch.object(helper, "source_unchanged", side_effect=AssertionError("not reached")), \
                patch.object(helper, "run", side_effect=AssertionError("not reached")):
            self.assertEqual(helper.source_slots_compiler_diagnostic(bound, b"partial", b"", 101, timeout_for=lambda cap: cap)["reason"], "cargo-json-unavailable")
            self.assertEqual(helper.source_slots_compiler_diagnostic(bound, cargo_bytes([terminal]), b"", 101, timeout_for=lambda cap: cap)["reason"], "no-error-records")

        # Retaining the compile originals adds no weak reader: full identity,
        # byte cap, EOF, post-stat and consuming close are still mandatory.
        for name in ("source-slots-compile.stdout", "source-slots-compile.stderr"):
            for fault in (None, "named", "mode", "link", "uid", "post", "tail", "early", "oversize"):
                original = OriginalOS(simple_raw, fault)
                if name == "source-slots-compile.stdout" and fault == "oversize":
                    original.info.st_size = stdout_limit + 1
                expected = helper.source_slots_identity(original.info)
                with self.subTest(retained_name=name, fault=fault), patch.object(helper, "os", original):
                    if fault is None:
                        self.assertEqual(helper.source_slots_read(ReadPath("/inert") / name, expected, retain=True), simple_raw)
                    else:
                        with self.assertRaises(helper.CheckFailure):
                            helper.source_slots_read(ReadPath("/inert") / name, expected, retain=True)
                self.assertEqual(original.closes, [77])
        for name, size, retain, admitted in (
                ("source-slots-compile.stdout", 1406142, False, True),
                ("source-slots-compile.stdout", stdout_limit, True, True),
                ("source-slots-compile.stdout", stdout_limit + 1, True, False),
                ("source-slots-compile.stderr", 1024 * 1024, True, True),
                ("source-slots-compile.stderr", 1024 * 1024 + 1, True, False)):
            original = OriginalOS(b"x" * size, None)
            with self.subTest(capture_budget=(name, size, retain)), patch.object(helper, "os", original):
                if admitted:
                    value = helper.source_slots_read(ReadPath("/inert") / name,
                        helper.source_slots_identity(original.info), retain=retain)
                    self.assertEqual(len(value), size if retain else 0)
                    self.assertEqual(original.position, size)
                else:
                    with self.assertRaises(helper.CheckFailure):
                        helper.source_slots_read(ReadPath("/inert") / name,
                            helper.source_slots_identity(original.info), retain=retain)
                    self.assertEqual(original.position, 0)  # Reject before any body read.
            self.assertEqual(original.closes, [77])
        for name, retain in (("source-slots-test.stdout", True), ("metadata.json", True), ("source-slots-compile.stdout", 1)):
            original = OriginalOS(b"x", None)
            with patch.object(helper, "os", original), self.assertRaises(helper.CheckFailure):
                helper.source_slots_read(ReadPath("/inert") / name, helper.source_slots_identity(original.info), retain=retain)
            self.assertFalse(original.opened)
        class CloseFailureOS(OriginalOS):
            def close(self, fd):
                super().close(fd)
                raise OSError("inert consuming close uncertainty")
        original = CloseFailureOS(simple_raw, None)
        with patch.object(helper, "os", original), self.assertRaises(OSError):
            helper.source_slots_read(ReadPath("/inert/source-slots-compile.stdout"), helper.source_slots_identity(original.info), retain=True)
        self.assertEqual(original.closes, [77])

        # B short output keeps warnings/errors in original captures but exports no text tails.
        short_warning = ("warning: " + private + "\n").encode()
        short_error = (source + "/" + app + "/src/lib.rs:19:7: error[E0433]: " + private + "\n").encode()
        b_context = intel_removal_context()
        short_records = helper.source_slots_short_diagnostic_records(short_warning, short_error, source)
        self.assertEqual(short_records, [{"category": "compiler-error", "code": "E0433", "package": "mobile-release-kit-desktop",
            "spans": [{"path": app + "/src/lib.rs", "line": 19, "column": 7}], "unboundSpans": 0}])
        self.assertNotIn(private, json.dumps(short_records))
        self.assertEqual(helper.source_slots_short_diagnostic_records(b"", short_error, source), short_records)
        self.assertEqual(helper.source_slots_short_diagnostic_records(short_warning, b"", source), [])
        for path in ("src/lib.rs", "../src/lib.rs", "/foreign/private.rs", source + "-other/" + app + "/src/lib.rs",
                     app + "/src/../lib.rs", app + "/src//lib.rs", app + "/src/./lib.rs", "desktop/src-tauri-other/src/lib.rs"):
            with self.subTest(short_unbound=path):
                rows = helper.source_slots_short_diagnostic_records(b"", (path + ":19:7: error[E0433]: " + private + "\n").encode(), source)
                self.assertEqual(rows[0]["spans"], [])
                self.assertEqual(rows[0]["unboundSpans"], 1)
                self.assertNotIn(path, json.dumps(rows))
        for path, package in ((app + "/src/lib.rs", "mobile-release-kit-desktop"),
                              (source + "/" + native + "/src/lib.rs", "mrk-macos-installed-native")):
            rows = helper.source_slots_short_diagnostic_records(b"", (path + ":1048576:1048576: error: body\n").encode(), source)
            self.assertEqual(rows[0]["package"], package)
            self.assertEqual(rows[0]["spans"][0]["line"], 1048576)
        rows = helper.source_slots_short_diagnostic_records(b"", (
            "error[E0308]: " + private + "\nerror: linking with `cc` failed: " + private + "\n"
            "error: failed to run custom build command for `mrk-macos-installed-native v0.1.0`\n").encode(), source)
        self.assertEqual([row["category"] for row in rows], ["compiler-error", "linker-error", "build-script-failure"])
        self.assertEqual(rows[-1]["package"], "mrk-macos-installed-native")
        malformed_short = [short_error[:-1], short_error.replace(b"error[E0433]", b"error[E04333]"),
            short_error.replace(b":19:7:", b":0:7:"), short_error.replace(b":19:7:", b":1048577:7:"),
            short_error.replace(b":19:7:", b":19:1048577:"), short_error.replace(b"/src/lib.rs", b"/src/\xff.rs"),
            b"x" * 8193 + b"\n", b"\n" * 4097, b"error[E0433]: body\n" * 17]
        malformed_short.append(b"".join((app + "/src/" + str(i) + ".rs:1:1: error[E0433]: body\n").encode() for i in range(9)))
        for body in malformed_short:
            with self.subTest(short_refusal=len(body)), self.assertRaises(helper.CheckFailure):
                helper.source_slots_short_diagnostic_records(body, b"", source)
        self.assertEqual(len(helper.source_slots_short_diagnostic_records(b"error[E0433]: body\n" * 16, b"", source)), 16)
        # Exact byte/count bounds use finite lines, not an artificially oversized single line.
        for limit, is_stderr in ((2 * 1024 * 1024, False), (1024 * 1024, True)):
            padded = (b"w" * 8191 + b"\n") * (limit // 8192)
            args = (b"", padded) if is_stderr else (padded, b"")
            self.assertEqual(helper.source_slots_short_diagnostic_records(*args, source), [])
            args = (b"", padded + b"\n") if is_stderr else (padded + b"\n", b"")
            with self.assertRaises(helper.CheckFailure): helper.source_slots_short_diagnostic_records(*args, source)
        self.assertEqual(helper.source_slots_short_diagnostic_records(b"x" * 8192 + b"\n", b"", source), [])
        self.assertEqual(helper.source_slots_short_diagnostic_records(b"\n" * 4096, b"", source), [])
        with patch.object(helper, "source_unchanged"), patch.object(helper, "run", return_value=metadata):
            self.assertEqual(helper.source_slots_compiler_diagnostic(b_context, short_warning, short_error, 101,
                timeout_for=lambda cap: cap), diagnostic)
        with patch.object(helper, "source_unchanged", side_effect=AssertionError("no source IO")), \
                patch.object(helper, "run", side_effect=AssertionError("no command")):
            for code in (0, True, -1, 256, None):
                value = helper.source_slots_compiler_diagnostic(b_context, short_warning, short_error, code, timeout_for=lambda cap: cap)
                self.assertEqual(value["reason"], "cargo-short-unavailable")
                self.assertEqual(value["state"], "unavailable")
            self.assertEqual(helper.source_slots_compiler_diagnostic(b_context, short_warning, b"", 101,
                timeout_for=lambda cap: cap)["reason"], "no-error-records")

        # The actual run() manufactures the private returned-original witness.
        # Only subprocess.run is doubled. No fake success/unknown witness may
        # unlock capture parsing, and later faults cannot replace that error.
        actual_run = helper.run
        for short, fault in ((short, fault) for short in (False, True) for fault in (
                None, "signal", "timeout", "start", "unknown", "witness-bool", "flush", "writer-post", "close",
                "read", "source", "metadata", "deadline", "late-metadata", "malformed", "publication")):
            selected_bound = b_context if short else bound
            events, captures, streams, publications, originals, raised, reads, clock, source_checks = [], {}, [], [], [], [], [], [100.0], []
            BasePath, writer, _ = source_slots_paths(events, captures)
            class FailureCapture(io.StringIO):
                def __init__(self, path):
                    super().__init__(); self.path = str(path); streams.append(self)
                def flush(self):
                    if fault == "flush" and self.path.endswith(".stdout") and self.getvalue():
                        raise OSError("inert flush failure")
                    return super().flush()
                def __exit__(self, *args):
                    captures[self.path] = self.getvalue().encode()
                    events.append(("closed", self.path))
                    try:
                        return super().__exit__(*args)
                    finally:
                        if fault == "close" and self.path.endswith(".stderr"):
                            raise OSError("inert writer close uncertainty")
            class FailurePath(BasePath):
                def open(self, *args, **kw):
                    self_outer.assertEqual(args, ("x",))
                    return FailureCapture(self)
            def subprocess_original(argv, **kw):
                originals.append((list(map(str, argv)), dict(kw)))
                if argv[0] == "/fixed/cargo":
                    self.assertIn("--message-format=short" if short else "--message-format=json,json-diagnostic-short", argv)
                    if short: self.assertEqual(argv[-4:], ["--message-format=short", "--color", "never", "--no-run"])
                    self.assertEqual(argv[-1], "--no-run")
                    self.assertEqual(kw["timeout"], 600)
                    self.assertTrue(kw["check"])
                    kw["stdout"].write((b"partial" if fault == "malformed" else (short_warning if short else simple_raw)).decode())
                    kw["stderr"].write(short_error.decode() if short else private)
                    if fault == "deadline": clock[0] = 970.0
                    if fault == "timeout": raise helper.subprocess.TimeoutExpired(argv, 600)
                    if fault == "start": raise OSError("inert startup")
                    raise helper.subprocess.CalledProcessError(-9 if fault == "signal" else 101, argv)
                self.assertEqual(argv, [bound["git"], "ls-tree", "-z", "--full-tree", bound["sourceSha"], "--", app + "/src/lib.rs"])
                self.assertTrue(all(stream.closed for stream in streams))
                self.assertEqual(len(reads), 2)
                if fault == "metadata": raise OSError("inert Git error")
                if fault == "late-metadata": clock[0] = 970.0
                class Returned:
                    stdout = metadata
                return Returned()
            def observe_run(argv, **kw):
                try:
                    return actual_run(argv, **kw)
                except helper.CheckFailure as error:
                    if kw["check"] == "headless-test-compile-only":
                        raised.append(error)
                        if fault == "unknown": error.__dict__.pop("_returned_command", None)
                        if fault == "witness-bool": error._returned_command = (kw["check"], True)
                    raise
            def writer_post(path, stream):
                if fault == "writer-post" and stream.getvalue():
                    raise helper.CheckFailure("inert original writer changed")
                return writer(path, stream)
            def read_returned(path, expected, *, retain=False):
                self.assertTrue(retain)
                self.assertEqual(len(streams), 2)
                self.assertTrue(all(stream.closed for stream in streams))
                reads.append(path.name)
                if fault == "read": raise helper.CheckFailure("inert original capture changed")
                self.assertEqual(expected[6], len(captures[str(path)]))
                return captures[str(path)]
            def source_post(*args, **kw):
                source_checks.append("checked")
                if len(source_checks) == 2:
                    self.assertTrue(all(stream.closed for stream in streams))
                    self.assertEqual(len(reads), 2)
                    if fault == "source": raise helper.CheckFailure("inert changed source")
            def failure_publication(path, value):
                self.assertEqual(path.name, "source-slots-failure.json")
                if fault == "publication": raise OSError("inert publication")
                publications.append(deepcopy(value))
            with self.subTest(short=short, returned_original_fault=fault), contextlib.redirect_stdout(io.StringIO()), \
                    patch.object(helper, "Path", FailurePath), patch.object(helper, "tools", return_value=("/fixed/cargo", None)), \
                    patch.object(helper, "source_unchanged", side_effect=source_post), patch.object(helper, "source_slots_source_guard"), \
                    patch.object(helper, "source_slots_build_inputs", return_value=intel_removal_build()), \
                    patch.object(helper.subprocess, "run", side_effect=subprocess_original), patch.object(helper, "run", side_effect=observe_run), \
                    patch.object(helper, "source_slots_writer", side_effect=writer_post), patch.object(helper, "source_slots_read", side_effect=read_returned), \
                    patch.object(helper, "write_json", side_effect=failure_publication), patch.object(helper.time, "monotonic", side_effect=lambda: clock[0]), \
                    patch.dict(helper.os.environ, {"PATH": "/fixed/bin"}, clear=True), self.assertRaises(helper.CheckFailure) as failure:
                helper.phase_source_slots("compile", selected_bound)
            self.assertEqual(len(raised), 1)
            self.assertIs(failure.exception, raised[0])
            self.assertEqual(type(failure.exception), helper.CheckFailure)
            self.assertEqual(len(streams), 2)
            self.assertTrue(all(stream.closed for stream in streams))
            self.assertEqual(len([argv for argv, _ in originals if argv[0] == "/fixed/cargo"]), 1)
            self.assertEqual(len(publications), 0 if fault == "publication" else 1)
            for value in publications:
                self.assertEqual(value["status"], "failed-or-unknown")
                self.assertEqual(value["lastFixedStage"], "headless-test-compile-only")
                observed = value["compilerDiagnostic"]
                self.assertEqual(observed["state"], "complete" if fault is None else "unavailable")
                self.assertEqual(observed["returnCode"], None if fault in ("signal", "timeout", "start", "unknown", "witness-bool") else 101)
                self.assertNotIn(private, json.dumps(value))
                self.assertNotIn(source + "/", json.dumps(value))
                self.assertLessEqual(len(json.dumps(value).encode()), 16384)
                if fault is None:
                    self.assertEqual(observed, diagnostic)
            if fault in ("signal", "timeout", "start", "unknown", "witness-bool", "flush", "writer-post", "close", "deadline"):
                self.assertFalse(reads)
                self.assertEqual(len(originals), 1)
            if fault in ("read", "source", "malformed"):
                self.assertEqual(len(originals), 1)


        # Cargo short rendering keeps the complete structured error and warning
        # records. Only their unused rendered strings differ, never severity or spans.
        full_error, short_error, warning = message(), message(), message()
        full_error["message"]["rendered"] = "long source excerpt\n" * 100
        short_error["message"]["rendered"] = "src/lib.rs:19:7: error[E0433]\n"
        warning["message"]["level"] = "warning"
        warning["message"]["rendered"] = "src/lib.rs:2:1: warning\n"
        full_frames = cargo_bytes([warning, full_error, terminal])
        short_frames = cargo_bytes([warning, short_error, terminal])
        self.assertIn(b'"warning"', full_frames)
        self.assertIn(b'"warning"', short_frames)
        self.assertLess(len(short_frames), len(full_frames))
        self.assertEqual(helper.source_slots_diagnostic_records(full_frames, b"", source),
                         helper.source_slots_diagnostic_records(short_frames, b"", source))
        self.assertEqual(helper.source_slots_diagnostic_records(short_frames, b"", source)[0]["code"], "E0433")
        padded_warning = deepcopy(warning)
        padded_warning["message"]["rendered"] = ""
        padding = observer_limit - len(cargo_bytes([padded_warning, short_error, terminal]))
        self.assertGreater(padding, 0)
        padded_warning["message"]["rendered"] = "x" * padding
        observer_frames = cargo_bytes([padded_warning, short_error, terminal])
        self.assertEqual(len(observer_frames), observer_limit)
        self.assertIn(b'"level":"warning"', observer_frames)
        self.assertEqual(helper.source_slots_diagnostic_records(observer_frames, b"", source, observer=True),
                         helper.source_slots_diagnostic_records(short_frames, b"", source, observer=True))
        with self.assertRaises(helper.CheckFailure):
            helper.source_slots_diagnostic_records(observer_frames, b"", source)
        padded_warning["message"]["rendered"] += "x"
        over_observer_frames = cargo_bytes([padded_warning, short_error, terminal])
        self.assertEqual(len(over_observer_frames), observer_limit + 1)
        with self.assertRaises(helper.CheckFailure):
            helper.source_slots_diagnostic_records(over_observer_frames, b"", source, observer=True)
        with self.assertRaises(helper.CheckFailure):
            helper.source_slots_diagnostic_records(short_frames, b"x" * (1024 * 1024 + 1), source, observer=True)

        # Each actual reader predicate is distinguished without an extra lstat,
        # owner query, payload read or close. The original rejection stays identical.
        class AdmissionOS(OriginalOS):
            def __init__(self, body, fault):
                super().__init__(body, fault); self.trace = []
            def fstat(self, fd):
                self.trace.append("fstat"); return super().fstat(fd)
            def geteuid(self):
                self.trace.append("geteuid"); return super().geteuid()
            def read(self, fd, size):
                self.trace.append("read"); return super().read(fd, size)
            def close(self, fd):
                self.trace.append("close"); return super().close(fd)
        class AdmissionPath(ReadPath):
            def lstat(self):
                original.trace.append("lstat"); return super().lstat()
        for fault, label in (("opened", "opened-identity"), ("named", "named-identity"),
                             ("type", "regular-file"), ("uid", "owner"), ("link", "single-link"),
                             ("mode", "private-mode"), ("oversize", "byte-bound"), ("empty", "nonempty-metadata")):
            original = AdmissionOS(b"" if fault == "empty" else b"inert", fault)
            if fault == "type": original.info.st_mode = 0o040600
            if fault == "oversize": original.info.st_size = stdout_limit + 1
            expected = helper.source_slots_identity(original.info)
            if fault == "opened": expected = (1, 999, *expected[2:])
            name = "metadata.json" if fault == "empty" else "source-slots-compile.stdout"
            with self.subTest(admission=fault), patch.object(helper, "os", original), self.assertRaises(helper.CheckFailure) as refused:
                helper.source_slots_read(AdmissionPath("/inert") / name, expected)
            facts = refused.exception.__dict__["_source_slots_capture_admission"]
            self.assertEqual(str(refused.exception), "SourceSlots private output is changed or oversized")
            self.assertEqual(facts, {"schemaVersion": 1, "output": name,
                "limitBytes": 16 * 1024 * 1024 if name == "metadata.json" else stdout_limit,
                "writerBytes": expected[6], "openedBytes": original.info.st_size,
                "failedCheck": label, "readerClosed": True, "partialObservation": True})
            self.assertEqual(original.trace, ["fstat"] + ([] if fault == "opened" else ["lstat"])
                + ([] if fault in {"opened", "named", "type"} else ["geteuid"]) + ["close"])
            self.assertEqual(original.closes, [77])
            self.assertLessEqual(len(json.dumps(facts).encode()) + 1, 1024)
            self.assertNotIn("/inert", json.dumps(facts))
        valid_facts = {"schemaVersion": 1, "output": "source-slots-compile.stdout", "limitBytes": stdout_limit,
            "writerBytes": stdout_limit + 1, "openedBytes": stdout_limit + 1, "failedCheck": "byte-bound",
            "readerClosed": True, "partialObservation": True}
        self.assertEqual(helper.source_slots_capture_admission(valid_facts), valid_facts)
        self.assertIsNot(helper.source_slots_capture_admission(valid_facts), valid_facts)
        self.assertIsNone(helper.source_slots_capture_admission(valid_facts, observer=True))
        for mode in (1, None, "true"):
            self.assertIsNone(helper.source_slots_capture_admission(valid_facts, observer=mode))
        self.assertIsNone(helper.source_slots_capture_admission(
            {**valid_facts, "output": "metadata.json", "limitBytes": 16 * 1024 * 1024}, observer=True))
        for key, value in (("schemaVersion", True), ("output", "/private/unselected"), ("limitBytes", True),
                           ("limitBytes", 1024 * 1024), ("limitBytes", 16 * 1024 * 1024), ("writerBytes", True), ("writerBytes", -1),
                           ("openedBytes", 1 << 63), ("openedBytes", 1.0), ("failedCheck", "arbitrary-text"),
                           ("readerClosed", 1), ("partialObservation", False), ("extra", "x" * 2048)):
            with self.subTest(malformed_fact=key, value=value):
                self.assertIsNone(helper.source_slots_capture_admission({**valid_facts, key: value}))
        for value in (None, [], {}, {key: value for key, value in valid_facts.items() if key != "readerClosed"}):
            self.assertIsNone(helper.source_slots_capture_admission(value))
        for name in ("metadata.json", "source-slots-metadata.stderr", "source-slots-test.stdout", "source-slots-test.stderr"):
            cap = 16 * 1024 * 1024 if name == "metadata.json" else 1024 * 1024
            self.assertIsNotNone(helper.source_slots_capture_admission({**valid_facts, "output": name, "limitBytes": cap}))
        for fault in ("optional", "close"):
            original = OriginalOS(b"inert", "oversize") if fault == "optional" else CloseFailureOS(b"inert", "oversize")
            original.info.st_size = stdout_limit + 1
            with self.subTest(admission_after_close=fault), patch.object(helper, "os", original), \
                    patch.object(helper, "source_slots_capture_admission", side_effect=ValueError("inert optional failure")) as optional:
                with self.assertRaises(helper.CheckFailure if fault == "optional" else OSError) as refused:
                    helper.source_slots_read(ReadPath("/inert/source-slots-compile.stdout"), helper.source_slots_identity(original.info))
                if fault == "optional":
                    self.assertNotIn("_source_slots_capture_admission", refused.exception.__dict__)
                    self.assertEqual(str(refused.exception), "SourceSlots private output is changed or oversized")
                else:
                    optional.assert_not_called()
                    self.assertNotIn("_source_slots_capture_admission", refused.exception.__context__.__dict__)
            self.assertEqual(original.closes, [77])

        # Use the real run() and reader with inert subprocess/FD originals. Zero
        # is a command observation, not a passing phase; no DATA follows refusal.
        actual_read = helper.source_slots_read
        for fault in ("oversize", "named", "reader-close", "nonzero-read", "startup", "test-startup",
                      "test-nonzero", "malformed-facts", "publication"):
            events, captures, calls, publications, run_failures, read_failures, closed = [], {}, [], [], [], [], []
            SlotsPath, writer, memory_read = source_slots_paths(events, captures)
            def capture_original(argv, **kw):
                calls.append(list(argv))
                self.assertEqual(argv[0], "/fixed/cargo"); self.assertTrue(kw["check"])
                if "--no-run" in argv:
                    self.assertIn("--message-format=json,json-diagnostic-short", argv)
                    self.assertEqual(kw["timeout"], 600)
                    if fault == "startup": raise OSError("inert startup")
                    if fault not in {"test-startup", "test-nonzero"}:
                        kw["stdout"].write("x" * (stdout_limit + 1))
                    if fault == "nonzero-read": raise helper.subprocess.CalledProcessError(101, argv)
                else:
                    self.assertEqual(argv[-4:], [SOURCE_SLOTS_CASE, "--", "--exact", "--test-threads=1"])
                    self.assertFalse(any(arg.startswith("--message-format=") for arg in argv))
                    self.assertEqual(kw["timeout"], 150)
                    if fault == "test-startup": raise OSError("inert DATA startup")
                    raise helper.subprocess.CalledProcessError(102, argv)
                return helper.subprocess.CompletedProcess(argv, 0)
            def capture_run(argv, **kw):
                try: return actual_run(argv, **kw)
                except helper.CheckFailure as error:
                    run_failures.append(error); raise
            def read_admitted(path, expected, *, retain=False):
                self.assertTrue(all(kind != "open" or any(row[:2] == ("closed", item) for row in events)
                    for kind, item, *tail in events))
                reader_type = CloseFailureOS if fault == "reader-close" else OriginalOS
                original = reader_type(captures[str(path)], "named" if fault == "named" else None)
                original.info.st_ino, original.info.st_mtime_ns, original.info.st_ctime_ns = 3, 1, 1
                class ClosedPath(PurePosixPath):
                    def lstat(self):
                        if original.fault == "named":
                            changed = Info(original.info.st_size); changed.st_ino = 999; return changed
                        return original.info
                try:
                    with patch.object(helper, "os", original):
                        return actual_read(ClosedPath(str(path)), expected, retain=retain)
                except BaseException as error:
                    read_failures.append(error)
                    if fault == "malformed-facts" and type(error) is helper.CheckFailure:
                        error._source_slots_capture_admission = {**valid_facts, "openedBytes": True}
                    raise
                finally:
                    closed.extend(original.closes)
            def publish_failure(path, value):
                self.assertEqual(path.name, "source-slots-failure.json")
                if fault == "publication": raise OSError("inert failed publication")
                publications.append(deepcopy(value))
            with self.subTest(admission_original=fault), contextlib.redirect_stdout(io.StringIO()), patch.object(helper, "Path", SlotsPath), \
                    patch.object(helper, "tools", return_value=("/fixed/cargo", None)), patch.object(helper, "source_unchanged"), \
                    patch.object(helper, "source_slots_source_guard"), patch.object(helper.subprocess, "run", side_effect=capture_original), \
                    patch.object(helper, "run", side_effect=capture_run), patch.object(helper, "source_slots_writer", side_effect=writer), \
                    patch.object(helper, "source_slots_read", side_effect=read_admitted), patch.object(helper, "write_json", side_effect=publish_failure), \
                    patch.object(helper.time, "monotonic", return_value=100.0), patch.dict(helper.os.environ, {"PATH": "/fixed/bin"}, clear=True), \
                    self.assertRaises(OSError if fault == "reader-close" else helper.CheckFailure) as failed:
                helper.phase_source_slots("compile", bound)
            self.assertIs(failed.exception, run_failures[0] if run_failures else read_failures[0])
            self.assertEqual(len(calls), 2 if fault in {"test-startup", "test-nonzero"} else 1)
            self.assertEqual(len(publications), 0 if fault == "publication" else 1)
            for failure in publications:
                self.assertEqual(failure["status"], "failed-or-unknown")
                self.assertEqual(failure["lastFixedStage"], "mac-source-slots-data-test" if fault.startswith("test-") else "headless-test-compile-only")
                self.assertEqual(failure["originalCommandReturnCode"], None if fault in {"startup", "test-startup"}
                    else 101 if fault == "nonzero-read" else 102 if fault == "test-nonzero" else 0)
                self.assertEqual("captureAdmission" in failure, fault in {"oversize", "named", "nonzero-read"})
                if "captureAdmission" in failure:
                    self.assertEqual(failure["captureAdmission"]["failedCheck"], "named-identity" if fault == "named" else "byte-bound")
                    self.assertEqual(failure["captureAdmission"]["output"], "source-slots-compile.stdout")
                if not fault.startswith("test-"):
                    self.assertEqual(failure["compilerDiagnostic"]["returnCode"], 101 if fault == "nonzero-read" else None)
                    self.assertEqual(failure["compilerDiagnostic"]["state"], "unavailable")
                self.assertLessEqual(len(json.dumps(failure).encode()) + 1, 16384)
                self.assertNotIn("inert ", json.dumps(failure))
                self.assertNotIn("/inert", json.dumps(failure))
            self.assertTrue(all(fd == 77 for fd in closed))


        # Secondary interrupts from optional decoration must not replace the
        # already-established reader refusal or the first returned101 original.
        # Reuse the exact actual-run/reader doubles above, resetting all state.
        actual_admission = helper.source_slots_capture_admission
        for code in (0, 101):
            for secondary in (KeyboardInterrupt, SystemExit):
                for interruption_at in (1, 2, 3):
                    fault = "nonzero-read" if code == 101 else "oversize"
                    events, captures, calls, publications, run_failures, read_failures, closed = [], {}, [], [], [], [], []
                    SlotsPath, writer, memory_read = source_slots_paths(events, captures)
                    admission_calls = []
                    def optional_interruption(value, *, observer=False):
                        self.assertIs(observer, False)
                        admission_calls.append(value)
                        if len(admission_calls) == interruption_at:
                            raise secondary("inert secondary decoration interrupt")
                        return actual_admission(value, observer=observer)
                    with self.subTest(returned_code=code, secondary=secondary.__name__, optional_stage=interruption_at), contextlib.redirect_stdout(io.StringIO()), \
                            patch.object(helper, "Path", SlotsPath), patch.object(helper, "tools", return_value=("/fixed/cargo", None)), \
                            patch.object(helper, "source_unchanged"), patch.object(helper, "source_slots_source_guard"), \
                            patch.object(helper.subprocess, "run", side_effect=capture_original), patch.object(helper, "run", side_effect=capture_run), \
                            patch.object(helper, "source_slots_writer", side_effect=writer), patch.object(helper, "source_slots_read", side_effect=read_admitted), \
                            patch.object(helper, "source_slots_capture_admission", side_effect=optional_interruption), \
                            patch.object(helper, "write_json", side_effect=publish_failure), patch.object(helper.time, "monotonic", return_value=100.0), \
                            patch.dict(helper.os.environ, {"PATH": "/fixed/bin"}, clear=True), self.assertRaises(helper.CheckFailure) as failed:
                        helper.phase_source_slots("compile", bound)
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(len(read_failures), 1)
                    self.assertIs(failed.exception, run_failures[0] if code else read_failures[0])
                    self.assertEqual(len(admission_calls), 3)
                    self.assertEqual(closed, [77])
                    self.assertEqual(len(publications), 1)
                    self.assertEqual(publications[0]["status"], "failed-or-unknown")
                    self.assertEqual(publications[0]["lastFixedStage"], "headless-test-compile-only")
                    self.assertEqual(publications[0]["originalCommandReturnCode"], code)
                    self.assertNotIn("captureAdmission", publications[0])
                    self.assertEqual(publications[0]["compilerDiagnostic"]["returnCode"], 101 if code else None)
                    self.assertEqual(publications[0]["compilerDiagnostic"]["state"], "unavailable")
                    self.assertNotIn("secondary", json.dumps(publications[0]))
                    self.assertLessEqual(len(json.dumps(publications[0]).encode()) + 1, 16384)

        # Full new production phase, actual closed DATA captures and shipping
        # command ordering; only existing IO/command ports are inert doubles.
        for target in MAC_RUST_EXPECTED:
            for fault in (None, "compile101", "compile-return", "compile-close", "test-close", "test-reader", "zero-tests",
                          "compile-return-and-close", "backwards", "late-core", "source-post", "late-shipping", "late-receipt"):
                bound = history_app_context(target)
                calls, events, captures, published, clock, source_calls = [], [], {}, [], [100.0], []
                SlotsPath, writer, read = source_slots_paths(events, captures)
                endpoint = 1900.0 if target == "aarch64-apple-darwin" else 5500.0
                class HistoryPath(SlotsPath):
                    @contextlib.contextmanager
                    def open(self, *args, **kwargs):
                        with super().open(*args, **kwargs) as stream:
                            yield stream
                        if ((fault in ("compile-close", "compile-return-and-close") and self.name == "source-slots-compile.stdout")
                                or fault == "test-close" and self.name == "source-slots-test.stdout"):
                            raise helper.CheckFailure("inert close unknown")
                def invoke_history(argv, **kw):
                    check = kw["check"]
                    calls.append((list(argv), {key: val for key, val in kw.items() if key not in ("output", "diagnostics")}))
                    if check == "headless-test-compile-only":
                        if fault == "compile101":
                            kw["output"].write(simple_raw.decode())
                            refused = helper.CheckFailure("original compiler101")
                            refused._returned_command = (check, 101)
                            raise refused
                        kw["output"].write('{"reason":"build-finished","success":true}\n')
                        if fault in ("compile-return", "compile-return-and-close"):
                            raise helper.CheckFailure("first compiler refusal")
                        if fault == "backwards": clock[0] = 99.0
                        if fault == "late-core": clock[0] = endpoint - 30
                    elif check == "mac-source-slots-data-test":
                        body = history_app_stdout()
                        if fault == "zero-tests":
                            body = body.replace(b"running 4 tests", b"running 0 tests")
                            self.assertNotEqual(body, history_app_stdout())
                        kw["output"].write(body.decode())
                    elif check == "mac-normal-bin-compile-only" and fault == "late-shipping":
                        clock[0] = endpoint
                    elif check == "source-slots-diagnostic-source":
                        self.assertEqual(fault, "compile101")
                        return metadata
                    return helper.NODE if check == "node-version" else ""
                def read_history(path, expected, *, retain=False):
                    self.assertIn(("closed", str(path)), events)
                    if fault == "test-reader" and path.name == "source-slots-test.stdout":
                        raise helper.CheckFailure("inert original reader failed")
                    if retain:
                        self.assertEqual(len(captures[str(path)]), expected[6])
                        return captures[str(path)]
                    return read(path, expected)
                def post_history(*args, **kwargs):
                    source_calls.append(True)
                    if fault == "source-post" and len(source_calls) == 2:
                        raise helper.CheckFailure("inert source changed")
                def publish_history(path, value):
                    published.append(deepcopy(value))
                    if fault == "late-receipt": clock[0] = endpoint
                with self.subTest(history_target=target, fault=fault), \
                        patch.object(helper, "Path", HistoryPath), patch.object(helper, "source_unchanged", side_effect=post_history), \
                        patch.object(helper, "mac_compile_source_guard"), patch.object(helper, "mac_compile_inputs", return_value=bound["macCompile"]), \
                        patch.object(helper, "tools", return_value=("/direct/cargo", "/direct/rustc")), \
                        patch.object(helper.shutil, "which", return_value="/selected/bin/node"), \
                        patch.object(helper, "run", side_effect=invoke_history), patch.object(helper, "source_slots_writer", side_effect=writer), \
                        patch.object(helper, "source_slots_read", side_effect=read_history), \
                        patch.object(helper, "write_json", side_effect=publish_history), \
                        patch.object(helper.time, "monotonic", side_effect=lambda: clock[0]), \
                        patch.dict(helper.os.environ, {"PATH": "/selected/bin"}, clear=True):
                    if fault is None:
                        helper.phase_mac_compile("compile", bound)
                    elif fault == "compile-return-and-close":
                        with self.assertRaisesRegex(helper.CheckFailure, "first compiler refusal"):
                            helper.phase_mac_compile("compile", bound)
                    else:
                        with self.assertRaises(helper.CheckFailure):
                            helper.phase_mac_compile("compile", bound)
                checks = [kw["check"] for _, kw in calls]
                self.assertTrue(checks)
                self.assertEqual(checks[0], "headless-test-compile-only")
                self.assertFalse(any("vault" in check or "observer" in check or "image" in check for check in checks))
                if fault is None:
                    self.assertEqual(checks, list(helper.MAC_HISTORY_CHECKS["compile"])[2:])
                    self.assertEqual(published, [history_app_receipt(target, "compile")])
                    self.assertEqual(len(source_calls), 2)
                    self.assertEqual(calls[0][1]["timeout"], 600)
                    self.assertEqual(calls[1][1]["timeout"], 150)
                    self.assertEqual(calls[-1][1]["timeout"], 1500 if target == "aarch64-apple-darwin" else 2700)
                    for argv, kw in (calls[0], calls[1], calls[-1]):
                        self.assertIn("--locked", argv); self.assertIn("--offline", argv)
                        self.assertEqual(argv[argv.index("--target") + 1], target)
                        self.assertEqual(argv[argv.index("--target-dir") + 1], bound["root"] + "/target")
                        self.assertEqual(argv[argv.index("--jobs") + 1], "1")
                    self.assertIn("--no-run", calls[0][0]); self.assertIn("--lib", calls[0][0])
                    self.assertEqual(calls[1][0][calls[1][0].index("--") + 1:],
                                     ["--exact", "--test-threads=1", "--format", "pretty", "--color", "never", *HISTORY_APP_CASES])
                    self.assertEqual(calls[-1][0][-5:], ["--release", "--features", "desktop-shell,custom-protocol", "--bin", "mobile-release-kit-desktop"])
                    self.assertEqual(captures[bound["root"] + "/target/source-slots-test.stdout"], history_app_stdout())
                else:
                    positive_receipts = [row for row in published if row["status"] == "passed"]
                    self.assertEqual(len(positive_receipts), 1 if fault == "late-receipt" else 0)
                    if fault in ("compile101", "compile-return", "compile-return-and-close", "compile-close", "backwards", "late-core",
                                 "zero-tests", "test-reader", "test-close"):
                        self.assertEqual(len(published), 1)
                        self.assertEqual(published[0]["status"], "failed-or-unknown")
                        self.assertLessEqual(len(json.dumps(published[0], separators=(",", ":")).encode()) + 1, 16384)
                        with self.assertRaises(helper.CheckFailure):
                            helper.validate_compile_receipt(published[0], bound, "compile")
                    if fault == "compile101":
                        self.assertEqual(checks, ["headless-test-compile-only", "source-slots-diagnostic-source"])
                        self.assertEqual(published[0]["originalCommandReturnCode"], 101)
                        self.assertEqual(published[0]["compilerDiagnostic"]["state"], "complete")
                        self.assertEqual(published[0]["compilerDiagnostic"]["errors"][0]["code"], "E0433")
                        self.assertEqual(published[0]["compilerDiagnostic"]["sources"], [{"path": app + "/src/lib.rs", "gitBlob": blob}])
                        self.assertNotIn(private, json.dumps(published[0]))
                    if fault in ("compile-return", "compile-return-and-close", "compile-close", "backwards", "late-core"):
                        self.assertEqual(checks, ["headless-test-compile-only"])
                    if fault in ("zero-tests", "test-reader", "test-close"):
                        self.assertEqual(checks, ["headless-test-compile-only", "mac-source-slots-data-test"])

            # Acquisition uses separate locked feature graphs, never compiles
            # or executes tests and stops before npm after a metadata failure.
            for fail_metadata in (False, True):
                bound = history_app_context(target); events, calls, published = [], [], []
                MemoryPath, _ = memory_paths(events)
                def acquire_history(argv, **kw):
                    calls.append((list(argv), kw))
                    if fail_metadata and kw["check"] == "mac-source-slots-locked-metadata":
                        raise helper.CheckFailure("inert metadata refusal")
                    return helper.NODE if kw["check"] == "node-version" else ""
                with patch.object(helper, "Path", MemoryPath), patch.object(helper, "source_unchanged"), \
                        patch.object(helper, "mac_compile_source_guard"), patch.object(helper, "mac_compile_inputs", return_value=bound["macCompile"]), \
                        patch.object(helper, "tools", return_value=("/direct/cargo", "/direct/rustc")), \
                        patch.object(helper.shutil, "which", return_value="/selected/bin/node"), patch.object(helper, "ordinary"), \
                        patch.object(helper, "run", side_effect=acquire_history), \
                        patch.object(helper, "write_json", side_effect=lambda path, value: published.append(deepcopy(value))), \
                        patch.object(helper.time, "monotonic", return_value=100.0), \
                        patch.dict(helper.os.environ, {"PATH": "/selected/bin"}, clear=True):
                    if fail_metadata:
                        with self.assertRaises(helper.CheckFailure): helper.phase_mac_compile("acquire", bound)
                    else:
                        helper.phase_mac_compile("acquire", bound)
                self.assertEqual([kw["check"] for _, kw in calls],
                                 ["mac-source-slots-locked-metadata"] if fail_metadata else list(helper.MAC_HISTORY_CHECKS["acquire"])[2:])
                self.assertEqual(published, [] if fail_metadata else [history_app_receipt(target, "acquire")])
                if not fail_metadata:
                    self.assertEqual([argv[argv.index("--features") + 1] for argv, _ in calls[:2]],
                                     ["development-runtime", "desktop-shell,custom-protocol"])
                    for argv, kw in calls[:2]:
                        self.assertEqual(argv[1], "metadata"); self.assertIn("--locked", argv)
                        self.assertEqual(argv[argv.index("--filter-platform") + 1], target)
                        self.assertEqual(kw["timeout"], 600)



        # Same real phase/receipt functions: app-only never enters auxiliary work.
        app_checks = {
            "acquire": ["rust-version-target", "mac-cargo-version", "mac-normal-locked-metadata", "node-version", "npm-locked-no-scripts"],
            "compile": ["rust-version-target", "mac-cargo-version", "node-version", "typescript-no-emit", "vite-assets", "mac-normal-bin-compile-only"],
        }
        for app_target in MAC_RUST_EXPECTED:
            app_bound = mac_context(app_target, "app-only")
            for app_phase, checks in app_checks.items():
                expected = {"schemaVersion": 1, "scope": "desktop-macos-normal-compile-only-v1", "phase": app_phase,
                            "status": "passed", **{key: deepcopy(app_bound[key]) for key in (
                                "sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha", "workflowRef",
                                "workflowSha256", "runId", "attempt", "macCompile")},
                            "rust": deepcopy(MAC_RUST_EXPECTED[app_target]), "node": helper.NODE,
                            "checks": [{"check": check, "exitCode": 0} for check in checks]}
                self.assertEqual(helper.mac_compile_checks(app_target, "app-only")[app_phase], tuple(checks))
                self.assertEqual(helper.validate_compile_receipt(expected, app_bound, app_phase), expected)
                for key, wrong in (("node", None), ("checks", expected["checks"][:-1]),
                                   ("checks", expected["checks"] + [{"check": "headless-test-compile-only", "exitCode": 0}]),
                                   ("macCompile", history_app_context(app_target)["macCompile"]),
                                   ("scope", helper.MAC_HISTORY_EVIDENCE), ("testResult", history_app_result())):
                    with self.assertRaises(helper.CheckFailure):
                        helper.validate_compile_receipt({**expected, key: wrong}, app_bound, app_phase)
                for fail_at in (None, *checks, "source-post"):
                    app_events, app_calls, app_writes, app_posts = [], [], [], []
                    AppPath, _ = memory_paths(app_events)
                    def app_run(argv, **kw):
                        app_calls.append((list(map(str, argv)), kw))
                        if kw["check"] == fail_at:
                            raise helper.CheckFailure("inert selected failure")
                        return helper.NODE if kw["check"] == "node-version" else ""
                    def app_tools(context, env, **kw):
                        app_run(["/direct/rustc", "-vV"], check="rust-version-target", env=env)
                        app_run(["/direct/cargo", "--version"], check="mac-cargo-version", env=env)
                        return "/direct/cargo", "/direct/rustc"
                    def app_post(*args, **kwargs):
                        app_posts.append("source")
                        if fail_at == "source-post" and len(app_posts) == 2:
                            raise helper.CheckFailure("inert source changed")
                    with patch.object(helper, "Path", AppPath), patch.object(helper, "source_unchanged", side_effect=app_post), \
                            patch.object(helper, "mac_compile_source_guard"), \
                            patch.object(helper, "mac_compile_inputs", return_value=app_bound["macCompile"]), \
                            patch.object(helper, "tools", side_effect=app_tools), patch.object(helper, "ordinary"), \
                            patch.object(helper.shutil, "which", return_value="/selected/bin/node"), \
                            patch.object(helper, "run", side_effect=app_run), \
                            patch.object(helper, "mac_history_data_checks", side_effect=AssertionError("no headless or DATA original")), \
                            patch.object(helper, "write_json", side_effect=lambda path, value: app_writes.append(deepcopy(value))), \
                            patch.object(helper.time, "monotonic", return_value=100.0), \
                            patch.dict(helper.os.environ, {"PATH": "/selected/bin", "MRK_MACOS_GITHUB_SEAL_SHA256": "a" * 64,
                                                          "MRK_MACOS_GITHUB_SEAL_BYTES": "1"}, clear=True):
                        if fail_at is None:
                            helper.phase_mac_compile(app_phase, app_bound)
                        else:
                            with self.assertRaises(helper.CheckFailure):
                                helper.phase_mac_compile(app_phase, app_bound)
                    entered = [kw["check"] for _, kw in app_calls]
                    self.assertEqual(entered, checks[:checks.index(fail_at) + 1] if fail_at in checks else checks)
                    self.assertEqual(app_writes, [expected] if fail_at is None else [])
                    for argv, kw in app_calls:
                        self.assertNotIn("MRK_MACOS_GITHUB_SEAL_SHA256", kw["env"])
                        self.assertNotIn("MRK_MACOS_GITHUB_SEAL_BYTES", kw["env"])
                        self.assertNotIn("test", argv)
                    if fail_at is None:
                        self.assertEqual(app_posts, ["source", "source"])
                        if app_phase == "compile":
                            argv, kw = app_calls[-1]
                            self.assertEqual(argv, ["/direct/cargo", "build", "--locked", "--offline", "--jobs", "1",
                                "--no-default-features", "--target", app_target, "--target-dir", app_bound["root"] + "/target",
                                "--manifest-path", app_bound["source"] + "/desktop/src-tauri/Cargo.toml", "--release",
                                "--features", "desktop-shell,custom-protocol", "--bin", "mobile-release-kit-desktop"])
                            self.assertEqual(kw["timeout"], 2700 if app_target == "x86_64-apple-darwin" else 1500)
                            self.assertEqual(kw["env"]["MRK_MACOS_INSTALL_SOURCE_COMMIT"], app_bound["sourceSha"])
                        else:
                            self.assertEqual(app_calls[2][0], ["/direct/cargo", "metadata", "--locked", "--format-version", "1",
                                "--no-default-features", "--features", "desktop-shell,custom-protocol", "--filter-platform", app_target,
                                "--manifest-path", app_bound["source"] + "/desktop/src-tauri/Cargo.toml"])
                            self.assertEqual(app_calls[2][1]["timeout"], 600)
                            self.assertIn(("closed", app_bound["root"] + "/metadata.json"), app_events)
                with patch.object(helper, "write_json", side_effect=AssertionError("no DATA publication")), self.assertRaises(helper.CheckFailure):
                    helper.phase_receipt(app_bound, app_phase, checks, node=helper.NODE, mac_history_result=history_app_result())


        # The same phase/decoder, with inert originals: same installed compilation
        # graph/cwd and short JSON rendering, not identical diagnostic argv.
        # No test execution; failed output can never authorize cleanup.
        observer = mac_context("aarch64-apple-darwin", "observer-only")
        raw_error = (json.dumps({"reason": "compiler-message", "manifest_path": observer["source"] + "/desktop/src-tauri/Cargo.toml",
            "message": {"level": "error", "code": {"code": "E0433"}, "message": "synthetic private prose",
                        "spans": [{"is_primary": True, "file_name": "src/bridge.rs", "line_start": 467, "column_start": 9}]}})
            + '\n{"reason":"build-finished","success":false}\n').encode()
        admission_faults = {"admission-byte", "admission-stderr", "returned101-admission", "malformed-admission",
                            "noncompile-admission", "optional-admission", "returned101-optional", "returned101-publication"}
        for fault in (None, "returned101", "unknown", "timeout", "returned101-close", "close", "reader", "overflow", "late",
                      *sorted(admission_faults)):
            events, captures, calls, publications, original_errors, reader_errors, reader_facts = [], {}, [], [], [], [], []
            clock = [100.0]
            ObserverPath, writer, read = source_slots_paths(events, captures)
            original_open = ObserverPath.open
            def opened(path, *args, **kwargs):
                stream = original_open(path, *args, **kwargs)
                original_exit = type(stream).__exit__
                if fault in ("returned101-close", "close") and path.name == "source-slots-compile.stderr":
                    class BadClose(type(stream)):
                        def __exit__(self, *exc):
                            original_exit(self, *exc)
                            raise helper.CheckFailure("synthetic consuming close uncertainty")
                    stream = BadClose(path)
                return stream
            def invoke_observer(argv, **kw):
                check = kw["check"]
                calls.append((list(argv), {k: v for k, v in kw.items() if k not in ("output", "diagnostics")}))
                if check == "mac-observer-compile-only":
                    kw["output"].write(raw_error.decode() if fault and fault.startswith("returned101") else '{"reason":"build-finished","success":true}\n')
                    if fault in ("unknown", "timeout") or fault and fault.startswith("returned101"):
                        error = helper.CheckFailure("synthetic first original failure")
                        if fault.startswith("returned101"):
                            error._returned_command = (check, 101)
                        original_errors.append(error)
                        raise error
                    if fault == "late": clock[0] = 1900.0
                if check == "source-slots-diagnostic-source":
                    return "100644 blob " + "a" * 40 + "\tdesktop/src-tauri/src/bridge.rs\0"
                return helper.NODE if check == "node-version" else ""
            bound_observer = observer
            def read_observer(path, expected, *, retain=False, observer=False):
                self.assertIs(observer, True)
                self.assertIn(("closed", str(path)), events)
                self.assertIn(("closed", bound_observer["root"] + "/target/source-slots-compile.stdout"), events)
                self.assertIn(("closed", bound_observer["root"] + "/target/source-slots-compile.stderr"), events)
                if fault in ("reader", "overflow"):
                    raise helper.CheckFailure("synthetic " + fault + " original admission")
                if fault in admission_faults and (fault != "admission-stderr" or path.name == "source-slots-compile.stderr"):
                    cap = 1024 * 1024 if path.name.endswith("stderr") else observer_limit
                    facts = {"schemaVersion": 1, "output": path.name, "limitBytes": cap,
                        "writerBytes": expected[6] if fault == "admission-stderr" else cap + 1,
                        "openedBytes": expected[6] if fault == "admission-stderr" else cap + 1,
                        "failedCheck": "named-identity" if fault == "admission-stderr" else "byte-bound",
                        "readerClosed": True, "partialObservation": True}
                    if fault == "malformed-admission": facts["readerClosed"] = False
                    if fault == "noncompile-admission": facts.update(output="metadata.json", limitBytes=16 * 1024 * 1024)
                    error = helper.CheckFailure("synthetic original capture refusal")
                    error._source_slots_capture_admission = facts
                    reader_errors.append(error); reader_facts.append(deepcopy(facts))
                    raise error
                return captures[str(path)] if retain else read(path, expected)
            def publish_observer(path, value):
                self.assertEqual(path.name, "compile-checks.json")
                publications.append(deepcopy(value))
                if fault == "returned101-publication": raise KeyboardInterrupt("synthetic optional publication failure")
            with self.subTest(observer_fault=fault), contextlib.ExitStack() as stack:
                for manager in (
                    patch.object(helper, "Path", ObserverPath), patch.object(ObserverPath, "open", opened),
                    patch.object(helper, "source_unchanged"), patch.object(helper, "mac_compile_source_guard"),
                    patch.object(helper, "mac_compile_inputs", return_value=observer["macCompile"]),
                    patch.object(helper, "tools", return_value=("/direct/cargo", "/direct/rustc")),
                    patch.object(helper.shutil, "which", return_value="/selected/bin/node"),
                    patch.object(helper, "run", side_effect=invoke_observer),
                    patch.object(helper, "source_slots_writer", side_effect=writer),
                    patch.object(helper, "source_slots_read", side_effect=read_observer),
                    patch.object(helper, "write_json", side_effect=publish_observer),
                    patch.object(helper.time, "monotonic", side_effect=lambda: clock[0]),
                    patch.dict(helper.os.environ, {"PATH": "/selected/bin", "MRK_MACOS_DEVELOPER_ID_P12_BASE64": "synthetic-never-exported"}, clear=True),
                ): stack.enter_context(manager)
                if fault in ("optional-admission", "returned101-optional"):
                    stack.enter_context(patch.object(helper, "source_slots_capture_admission",
                        side_effect=SystemExit("synthetic optional fact validation failure")))
                if fault is None:
                    helper.phase_mac_compile("compile", observer)
                else:
                    with self.assertRaises(helper.CheckFailure) as failed:
                        helper.phase_mac_compile("compile", observer)
                    if original_errors: self.assertIs(failed.exception, original_errors[0])
                    elif reader_errors: self.assertIs(failed.exception, reader_errors[0])
            self.assertEqual([kw["check"] for _, kw in calls if kw["check"] != "source-slots-diagnostic-source"],
                             ["node-version", "typescript-no-emit", "vite-assets", "mac-observer-compile-only"])
            argv, call = next(row for row in calls if row[1]["check"] == "mac-observer-compile-only")
            self.assertEqual(argv, ["/direct/cargo", "test", "--locked", "--no-default-features", "--features",
                "desktop-shell,custom-protocol,macos-installed-observation", "--target", "aarch64-apple-darwin",
                "--test", "installed-shell-observation", "--no-run", "--message-format=json,json-diagnostic-short"])
            self.assertEqual(str(call["cwd"]), observer["source"] + "/desktop/src-tauri")
            self.assertEqual(call["timeout"], 1440)
            self.assertEqual(call["env"]["CARGO_TARGET_DIR"], observer["root"] + "/target")
            self.assertNotIn("MRK_MACOS_DEVELOPER_ID_P12_BASE64", call["env"])
            self.assertNotIn("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256", call["env"])
            self.assertEqual(len(publications), 1)
            record = publications[0]
            if fault is None:
                self.assertEqual(helper.validate_compile_receipt(record, observer, "compile"), record)
                self.assertEqual(record["checks"][-1], {"check": "mac-observer-compile-only", "exitCode": 0})
                self.assertNotIn("testResult", record)
            else:
                self.assertEqual(record["status"], "failed-or-unknown")
                with self.assertRaises(helper.CheckFailure): helper.validate_compile_receipt(record, observer, "compile")
                self.assertEqual(record["originalCommandReturnCode"], 101 if fault.startswith("returned101") else None if fault in ("unknown", "timeout") else 0)
                self.assertEqual(record["compilerDiagnostic"]["state"], "complete" if fault == "returned101" else "unavailable")
                self.assertEqual("captureAdmission" in record,
                    fault in {"admission-byte", "admission-stderr", "returned101-admission", "returned101-publication"})
                if "captureAdmission" in record:
                    self.assertEqual(record["captureAdmission"], reader_facts[0])
                    self.assertEqual(record["captureAdmission"]["readerClosed"], True)
                    self.assertEqual(record["captureAdmission"]["partialObservation"], True)
                if fault == "returned101":
                    self.assertEqual(record["compilerDiagnostic"]["errors"][0]["code"], "E0433")
                    self.assertEqual(record["compilerDiagnostic"]["sources"][0]["gitBlob"], "a" * 40)
                self.assertNotIn("synthetic", json.dumps(record))
                self.assertNotIn("/inert", json.dumps(record["compilerDiagnostic"]))
                self.assertLessEqual(len(json.dumps(record, separators=(",", ":")).encode()) + 1, 16384)

if __name__ == "__main__":
    unittest.main()
