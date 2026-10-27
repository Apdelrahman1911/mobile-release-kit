"""Passive closed-source/fixture tests; no Mac, vendor, process or service IO."""
from contextlib import ExitStack
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / "desktop/tools" / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


INPUTS = load("_tool_execution_inputs", "macos_tool_setup_inputs.py")
A = load("_tool_execution_preparation", "macos_android_dependency_preparation.py")
N = load("_tool_execution_clock", "macos_normal_ui_runner.py")
P = load("_tool_execution_relative", "macos_android_supplier_preparation.py")
OBS = load("_tool_execution_observer", "macos_aqua_qualification.py")
T = OBS.TOOLS


def service(ready=True, *, nonentry=False):
    return {"mechanism": "same-original-tool-service-prerequisite-v1",
        "execution": "ready" if ready else "not-executed-prerequisite",
        "finding": "ready" if ready else "service-unavailable" if nonentry else "approval-required",
        "requestCalls": 1, "checkCalls": int(ready), "normalQuitOriginal": 2,
        "requestAdmitted": not nonentry, "checkAdmitted": ready,
        "requestSettled": not nonentry, "checkSettled": ready, "knownNonentry": nonentry,
        "sameOriginalBindings": True, "allOriginalsSettled": True, "projectSentinelPreserved": True,
        "sourceInputsRead": False, "toolAcquisitionEntered": False, "settingsOpened": False,
        "serviceUnregistered": False, "productionQualified": False}


class PassiveOnly(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("no native/process")))
        self.stack.enter_context(patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("no HTTP")))
        self.stack.enter_context(patch.object(A, "N", N))
        self.stack.enter_context(patch.object(A, "P", P))


class ServiceReports(PassiveOnly):
    def test_failed_registration_and_fresh_read_only_check_preserve_both_originals(self):
        value = service(False)
        value.update(checkCalls=1, checkAdmitted=True, checkSettled=True)
        value['requestTerminal'] = {'validation': 'terminal', 'statusValid': True, 'phase': 'refused',
            'reason': 'service-unavailable', 'prerequisite': 'service-unavailable',
            'observation': {'state': 'not-found', 'outcome': 'error', 'mutationEntered': True,
                'mutationReturned': True, 'mutationUncertain': False, 'nativeSettled': True},
            'registrationReturn': {'accepted': False, 'error': 'service-error-code-1'}}
        value['terminal'] = {'validation': 'terminal', 'statusValid': True, 'phase': 'refused',
            'reason': 'approval-required', 'prerequisite': 'approval-required',
            'observation': {'state': 'requires-approval', 'outcome': 'observed', 'mutationEntered': False,
                'mutationReturned': False, 'mutationUncertain': False, 'nativeSettled': True}}
        self.assertIs(T.service_report(value, OBS.need), value)
        for change in ({'nativeSettled': False}, {'mutationReturned': False}, {'mutationUncertain': True}):
            changed = copy.deepcopy(value)
            changed['requestTerminal']['observation'].update(change)
            with self.subTest(change=change), self.assertRaises(OBS.Refused):
                T.service_report(changed, OBS.need)
        changed = copy.deepcopy(value)
        changed['requestTerminal']['registrationReturn']['accepted'] = True
        with self.assertRaises(OBS.Refused):
            T.service_report(changed, OBS.need)
        for change in ({'mutationEntered': True, 'mutationReturned': True}, {'nativeSettled': False}):
            changed = copy.deepcopy(value)
            changed['terminal']['observation'].update(change)
            with self.subTest(check=change), self.assertRaises(OBS.Refused):
                T.service_report(changed, OBS.need)
        changed = copy.deepcopy(value)
        changed['terminal'].update(phase='complete', reason='none', prerequisite='ready')
        changed['terminal']['observation']['state'] = 'enabled'
        changed['finding'] = 'service-unavailable'
        self.assertIs(T.service_report(changed, OBS.need), changed)
        changed = copy.deepcopy(value)
        changed.update(execution='ready', finding='ready')
        changed['terminal'].update(phase='complete', reason='none', prerequisite='ready')
        changed['terminal']['observation']['state'] = 'enabled'
        with self.assertRaises(OBS.Refused):
            T.service_report(changed, OBS.need)

    def test_original_registration_error_is_visible_without_claiming_readiness(self):
        value = service(False)
        value['finding'] = 'service-not-found'
        value['terminal'] = {'validation': 'terminal', 'statusValid': True, 'phase': 'refused',
            'reason': 'service-unavailable', 'prerequisite': 'service-unavailable',
            'observation': {'state': 'not-found', 'outcome': 'error', 'mutationEntered': True,
                'mutationReturned': True, 'mutationUncertain': False, 'nativeSettled': True},
            'registrationReturn': {'accepted': False, 'error': 'job-plist-not-found'}}
        self.assertIs(T.service_report(value, OBS.need), value)
        binding = OBS.Binding('a' * 40, '1', '1')
        expected = OBS.expected_result(binding, T.SERVICE_CASE)
        expected['toolSetup'] = value
        framed = OBS.MARKER + json.dumps(expected, separators=(',', ':')).encode() + b'\n'
        self.assertEqual(OBS.parse_result(framed, b'', binding, T.SERVICE_CASE)['toolSetup'], value)
        for change in ({'error': 'private/path'}, {'accepted': 1}, {'code': 8}):
            changed = copy.deepcopy(value)
            changed['terminal']['registrationReturn'].update(change)
            with self.subTest(change=change), self.assertRaises(OBS.Refused):
                T.service_report(changed, OBS.need)
        for change in ({'mutationReturned': False}, {'nativeSettled': False}, {'mutationUncertain': True}):
            changed = copy.deepcopy(value)
            changed['terminal']['observation'].update(change)
            with self.subTest(change=change), self.assertRaises(OBS.Refused):
                T.service_report(changed, OBS.need)
        # A refused reservation retains the pre-status, with no native call.
        refused = copy.deepcopy(value)
        del refused['terminal']['registrationReturn']
        refused['terminal']['observation'].update(outcome='refused', mutationEntered=False, mutationReturned=False)
        self.assertIs(T.service_report(refused, OBS.need), refused)
        changed = copy.deepcopy(value)
        changed.update(execution='ready', finding='ready', checkCalls=1, checkAdmitted=True, checkSettled=True)
        with self.assertRaises(OBS.Refused):
            T.service_report(changed, OBS.need)

    def test_ready_and_known_nonentry_are_distinct_after_real_caller_boundary(self):
        for value in (service(), service(False), service(False, nonentry=True)):
            self.assertIs(T.service_report(value, OBS.need), value)
            binding = OBS.Binding("a" * 40, "1", "1")
            expected = OBS.expected_result(binding, T.SERVICE_CASE)
            self.assertIsNone(expected["toolSetup"])
            expected["toolSetup"] = value
            framed = OBS.MARKER + json.dumps(expected, separators=(",", ":")).encode() + b"\n"
            self.assertEqual(OBS.parse_result(framed, b"", binding, T.SERVICE_CASE)["toolSetup"], value)
        # Request settled, followed by typed pre-admission Check refusal.
        value = service(False, nonentry=True)
        value.update(checkCalls=1, requestAdmitted=True, requestSettled=True)
        self.assertIs(T.service_report(value, OBS.need), value)

    def test_lost_admission_unknown_or_extra_registration_cannot_be_a_report(self):
        changes = (dict(requestCalls=2), dict(checkCalls=2), dict(requestCalls=True),
                   dict(requestSettled=False), dict(checkSettled=False), dict(knownNonentry=True),
                   dict(normalQuitOriginal=1), dict(allOriginalsSettled=False), dict(sourceInputsRead=True),
                   dict(settingsOpened=True), dict(serviceUnregistered=True), dict(productionQualified=True),
                   dict(finding="unknown"), dict(path="/not-an-authority"))
        for change in changes:
            value = service()
            value.update(change)
            with self.subTest(change=change), self.assertRaises(OBS.Refused):
                T.service_report(value, OBS.need)
        value = service(False, nonentry=True)
        value["requestAdmitted"] = True  # Admitted/lost is never typed nonentry.
        with self.assertRaises(OBS.Refused):
            T.service_report(value, OBS.need)

    def test_service_fixture_is_only_seven_project_files_no_source_preparation(self):
        self.assertEqual(OBS.selected_cases(T.SERVICE_SCOPE), T.SERVICE_CASES)
        self.assertEqual(OBS.case_timeout(T.SERVICE_CASE), 765)
        fixtures = OBS.Fixtures(OBS.Binding("a" * 40, "1", "1"), 501, 20, T.SERVICE_SCOPE)
        self.assertIsNone(fixtures.path)  # Actual pwd/held ancestry precedes use.
        files, directories = OBS.fixture_data(T.SERVICE_CASE, False)
        self.assertEqual(set(files), {"app/build.gradle.kts", "build.gradle.kts", "gradle/wrapper/gradle-wrapper.properties",
                                     "release/mobile-release.json", "version.properties", "keep.txt", ".gitignore"})
        self.assertEqual(len(directories), 5)
        self.assertIsNone(fixtures.tool_namespace)
        self.assertEqual(fixtures.tool_entered, set())

    def test_functional_first_snapshots_match_unchanged_saved_fixture_config(self):
        from mobile_release.api._snapshot import project_snapshot

        observer = (ROOT / "desktop/src-tauri/src/installed_shell_observation_macos.rs").read_text()
        snapshot = observer.split("pub(super) fn snapshot(&self", 1)[1].split("pub(super) fn suggest_request(", 1)[0]
        saved = snapshot.split("let saved = ", 1)[1].split(";", 1)[0]
        for variant in ("Case::ToolSetup(_)", "Case::Cli", "Case::GitCli(_)",
                        "Case::GitFetch(_)", "Case::GitPush(_)", "Case::GitUpstream"):
            self.assertIn(variant, saved)
        self.assertIn("r.snapshot_requests == 2", saved)  # Existing first-save refresh stays saved.
        self.assertIn("snapshot_value_failure(value, &self.project_path, saved, &self.base)", snapshot)

        # These service/tool, CLI and Git journeys already carry this saved,
        # credential-free config. No Store tree, SDK, Git process or native owner
        # is needed for their original passive project snapshot to be format-valid.
        cases = (*T.SERVICE_CASES, *T.CASES, *T.PUBLIC.CASES, *OBS.CLI.CASES,
                 *OBS.GIT_CLI.CASES, *OBS.FETCH.CASES, *OBS.PUSH.ALL_CASES, *OBS.UPSTREAM.CASES)
        with tempfile.TemporaryDirectory(prefix=".tool-snapshot-data-") as temporary:
            for case in cases:
                with self.subTest(case=case):
                    root = Path(temporary) / case
                    root.mkdir(mode=0o700)
                    files, _ = OBS.fixture_data(case, False)
                    for name, body in files.items():
                        path = root / name
                        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        path.write_bytes(body)
                    before = {name: ((root / name).stat().st_ino, (root / name).read_bytes()) for name in files}
                    value = project_snapshot(str(root))
                    self.assertEqual(before, {name: ((root / name).stat().st_ino, (root / name).read_bytes()) for name in files})
                    self.assertEqual(files["release/mobile-release.json"], OBS.CONFIG)
                    self.assertEqual(value["config"]["state"], "format-valid")
                    self.assertEqual(value["config"]["data"], json.loads(OBS.CONFIG))
                    self.assertEqual(value["config"]["content"], {
                        "bytes": len(OBS.CONFIG), "sha256": hashlib.sha256(OBS.CONFIG).hexdigest()})
                    self.assertEqual(value["config"]["issues"], [])
                    self.assertEqual(value["issues"], [])
                    self.assertFalse(value["discovery"]["partial"])
                    self.assertFalse((root / "release/store").exists())

    def test_service_and_tool_project_roots_share_native_home_abi_not_tmp_or_home_env(self):
        binding = OBS.Binding("a" * 40, "2", "1")
        with patch.dict(os.environ, {"HOME": "/foreign", "TMPDIR": "/foreign"}):
            for flag, suffix in (("tool_setup", T.SCOPE), ("tool_service", T.SERVICE_SCOPE)):
                path = binding.root(**{flag: True}, native_home="/Users/runner")
                self.assertEqual(path, Path("/Users/runner/Library/Application Support")
                                 / f"mrk-macos-aqua-{binding.source}-2-1-{suffix}")
                self.assertNotEqual(path.parent, Path("/private/tmp"))
                with self.assertRaises(OBS.Refused):
                    binding.root(**{flag: True})
        # Existing identity/non-tools namespaces are unchanged.
        self.assertEqual(binding.root(identity_native=True).parent, Path("/private/tmp"))

    def test_tool_parent_replacement_refuses_and_same_existing_close_retains_fds(self):
        temporary = tempfile.TemporaryDirectory(prefix=".tool-parent-passive-", dir=ROOT)
        self.addCleanup(temporary.cleanup)
        home = Path(temporary.name)
        (home / "Library").mkdir(mode=0o700)
        support = home / "Library/Application Support"
        support.mkdir(mode=0o700)
        fixtures = OBS.Fixtures(OBS.Binding("a" * 40, "2", "1"), os.getuid(), os.getgid(), T.SERVICE_SCOPE)
        self.addCleanup(fixtures.close)
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir=str(home))
        with patch("pwd.getpwuid", return_value=account):
            T.prepare_namespace(fixtures, OBS.need, OBS.signature)
        self.assertFalse(fixtures.path.exists())  # This test creates no fixture.
        retained = set(fixtures.fds)
        self.assertGreater(len(retained), 2)
        support.rename(home / "Library/retained")
        support.mkdir(mode=0o700)
        with self.assertRaises(OBS.Refused):
            T.namespace_current(fixtures, OBS.need, OBS.signature)
        self.assertEqual(fixtures.fds, retained)
        fixtures.close()
        self.assertFalse(fixtures.fds)

    def test_public_cold_empty_sdk_is_exclusive_current_and_separate_from_old_three(self):
        # Real private mkdir/open/close only; no native/source receipt or tool IO.
        with tempfile.TemporaryDirectory(prefix=".tool-public-parents-", dir=ROOT) as temporary:
            home = Path(temporary)
            (home / "Library").mkdir(mode=0o700)
            (home / "Library/Application Support").mkdir(mode=0o700)
            account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir=str(home))
            for number, mutation in enumerate(("replace", "foreign-entry"), 1):
                binding = OBS.Binding("a" * 40, str(number), "1")
                public = OBS.Fixtures(binding, os.getuid(), os.getgid(), T.PUBLIC.SCOPE)
                old = OBS.Fixtures(binding, os.getuid(), os.getgid(), T.SCOPE)
                duplicate = OBS.Fixtures(binding, os.getuid(), os.getgid(), T.PUBLIC.SCOPE)
                owners = (public, old, duplicate)
                try:
                    with patch("pwd.getpwuid", return_value=account):
                        T.prepare_parents(public, OBS.need, OBS.signature)
                        T.prepare_parents(old, OBS.need, OBS.signature)
                        # Same binding, distinct CLOSED namespaces. No overwrite/adopt.
                        with self.assertRaises(FileExistsError):
                            T.prepare_parents(duplicate, OBS.need, OBS.signature)
                    cold_parent = public.tool_paths[T.PUBLIC.COLD].parent
                    sdk = cold_parent / T.EMPTY_SDK
                    before = public.tool_empty_sdk
                    self.assertEqual(OBS.signature(sdk.stat()), before)
                    self.assertEqual(set(p.name for p in cold_parent.iterdir()), {T.EMPTY_SDK})
                    self.assertNotEqual(cold_parent.parent, old.tool_paths[T.CASES[0]].parent.parent)
                    self.assertEqual(set(p.name for p in cold_parent.parent.iterdir()), {T.PUBLIC.COLD})
                    self.assertEqual(set(p.name for p in old.tool_paths[T.CASES[0]].parent.parent.iterdir()), set(T.CASES))
                    retained = set(public.fds)
                    T.parents_current(public, OBS.need, OBS.signature)
                    T.parents_current(old, OBS.need, OBS.signature)
                    self.assertEqual(public.fds, retained)  # The SDK FD really returned/closed.
                    self.assertIsNone(old.tool_empty_sdk)
                    if mutation == "replace":
                        sdk.rename(cold_parent / "retained-empty-sdk")
                        sdk.mkdir(mode=0o700)
                    else:
                        (sdk / "foreign").write_bytes(b"retained foreign input\n")
                    with self.assertRaises(OBS.Refused):
                        T.parents_current(public, OBS.need, OBS.signature)
                    self.assertEqual(public.tool_empty_sdk, before)  # No recensus/adoption.
                    self.assertEqual(public.fds, retained)
                    if mutation == "foreign-entry":
                        self.assertEqual((sdk / "foreign").read_bytes(), b"retained foreign input\n")
                finally:
                    for owner in owners:
                        owner.close()
                        self.assertFalse(owner.fds)
                        self.assertEqual(owner.close_errors, 0)


class FixtureContext(PassiveOnly):
    def test_current_context_passes_environment_and_accepts_four_native_values(self):
        self.check_context(retained=False)

    def test_retained_context_uses_original_product_namespace_not_current_helper_run(self):
        self.check_context(retained=True)

    def check_context(self, *, retained):
        source = A.UI_CONSUMER_SOURCE if retained else A.SOURCE
        work = Path("/Users/runner/work/_temp/mrk-macos-installed.ABCDef12")
        product = ("b" * 40, "23", "2", work)
        environment = {"MRK_MACOS_NATIVE_SCOPE": INPUTS.SCOPE, "MRK_MACOS_TARGET": INPUTS.TARGET,
            "MRK_ANDROID_PREPARATION_WORK": str(work), "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "900", "GITHUB_RUN_ATTEMPT": "1"}
        if retained:
            environment.update(MRK_CANDIDATE_MODE="install-retained-observer", MRK_CANDIDATE_SOURCE=product[0])
        account = SimpleNamespace(pw_uid=501, pw_gid=20, pw_name="runner", pw_dir="/Users/runner")
        native_calls = []
        def native(env, *, retained=False):
            native_calls.append((dict(env), retained))
            return 501, 20, "runner", ("macos-26", "26.6")
        driver = SimpleNamespace(_native_user=native, current_context=Mock(return_value=product),
                                 retained_fixture_context=Mock(return_value=product))
        with patch.object(A, "SOURCE", source), \
             patch.object(A, "__file__", str(source / "desktop/tools/macos_android_dependency_preparation.py")), \
             patch.object(A, "RUN_SCOPE", A.TOOL_SCOPE), patch.object(A, "load", return_value=driver), \
             patch.object(INPUTS, "__file__", str(source / "desktop/tools/macos_tool_setup_inputs.py")), \
             patch.object(INPUTS, "_CONTEXT", None), patch.object(sys, "version_info", (3, 14, 7)), \
             patch("pwd.getpwuid", return_value=account), patch.dict(os.environ, environment, clear=True):
            self.assertEqual(INPUTS.context(A), (work, INPUTS.TARGET))
            self.assertEqual(INPUTS._CONTEXT[:4], product)
            self.assertEqual(INPUTS._CONTEXT[4], INPUTS.source_root(*product[:3], account.pw_dir, A.need))
            self.assertEqual(native_calls, [(environment, retained)])
            selected = driver.retained_fixture_context if retained else driver.current_context
            other = driver.current_context if retained else driver.retained_fixture_context
            selected.assert_called_once_with(os.environ, INPUTS.TARGET, *([501, 20] if retained else []))
            other.assert_not_called()
            self.assertEqual(os.environ["GITHUB_SHA"], "a" * 40)
            self.assertEqual(os.environ["GITHUB_RUN_ID"], "900")
            with self.assertRaisesRegex(A.Refused, "tool-input-fixed-entry"):
                INPUTS.context(A)

    def test_retained_context_refuses_wrong_helper_before_native_or_namespace_use(self):
        driver = SimpleNamespace(_native_user=Mock(), retained_fixture_context=Mock())
        environment = {"MRK_MACOS_NATIVE_SCOPE": INPUTS.SCOPE, "MRK_MACOS_TARGET": INPUTS.TARGET,
                       "MRK_CANDIDATE_MODE": "install-retained-observer"}
        with patch.object(A, "__file__", str(A.SOURCE / "desktop/tools/macos_android_dependency_preparation.py")), \
             patch.object(A, "RUN_SCOPE", A.TOOL_SCOPE), patch.object(A, "load", return_value=driver), \
             patch.object(INPUTS, "__file__", str(A.SOURCE / "desktop/tools/macos_tool_setup_inputs.py")), \
             patch.object(INPUTS, "_CONTEXT", None), patch.object(sys, "version_info", (3, 14, 7)), \
             patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(A.Refused, "tool-input-retained-helper"):
                INPUTS.context(A)
            self.assertIsNone(INPUTS._CONTEXT)
        driver._native_user.assert_not_called()
        driver.retained_fixture_context.assert_not_called()

    def test_failed_retained_receipt_never_publishes_a_fixture_context(self):
        source = A.UI_CONSUMER_SOURCE
        driver = SimpleNamespace(_native_user=Mock(return_value=(501, 20, "runner", ("macos-26", "26.6"))),
            retained_fixture_context=Mock(side_effect=ValueError("unverified retained install")))
        environment = {"MRK_MACOS_NATIVE_SCOPE": INPUTS.SCOPE, "MRK_MACOS_TARGET": INPUTS.TARGET,
                       "MRK_CANDIDATE_MODE": "install-retained-observer"}
        with patch.object(A, "SOURCE", source), \
             patch.object(A, "__file__", str(source / "desktop/tools/macos_android_dependency_preparation.py")), \
             patch.object(A, "RUN_SCOPE", A.TOOL_SCOPE), patch.object(A, "load", return_value=driver), \
             patch.object(INPUTS, "__file__", str(source / "desktop/tools/macos_tool_setup_inputs.py")), \
             patch.object(INPUTS, "_CONTEXT", None), patch.object(sys, "version_info", (3, 14, 7)), \
             patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(ValueError, "unverified retained install"):
                INPUTS.context(A)
            self.assertIsNone(INPUTS._CONTEXT)

    def test_child_receives_actual_host_and_current_helper_identity_without_credentials(self):
        class StoppedBeforeChild(Exception):
            pass
        work = Path("/Users/runner/work/_temp/mrk-macos-installed.ABCDef12")
        root = Path("/Users/runner/Library/Application Support") / ("mrk-macos-tool-inputs-" + "b" * 40 + "-23-2")
        environment = {key: "fixture" for key in (
            "GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_SHA", "GITHUB_WORKFLOW_SHA",
            "GITHUB_WORKFLOW_REF", "GITHUB_WORKSPACE", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_ENVIRONMENT",
            "RUNNER_OS", "RUNNER_ARCH", "MRK_EXPECTED_SHA", "MRK_MACOS_INSTALL_SOURCE_COMMIT", "MRK_MACOS_STORE_RUNTIME",
            "MRK_MACOS_NATIVE_SCOPE", "MRK_MACOS_PACKAGE_ROLE", "MRK_MACOS_WORK", "MRK_MACOS_TARGET", "MRK_ANDROID_PREPARATION_WORK")}
        environment.update(GITHUB_SHA="a" * 40, GITHUB_RUN_ID="900", GITHUB_TOKEN="inert-test-token",
            MRK_MACOS_RUNNER="macos-26", MRK_MACOS_MACHINE="arm64", MRK_MACOS_HOSTED_JOB="github-hosted-macos26-arm64")
        for retained in (False, True):
            selected_env = dict(environment)
            source = A.SOURCE
            if retained:
                source = A.UI_CONSUMER_SOURCE
                selected_env.update(MRK_CANDIDATE_MODE="install-retained-observer", MRK_CANDIDATE_SOURCE="b" * 40)
            native = Mock()
            native.call.side_effect = StoppedBeforeChild
            factory = Mock(return_value=native)
            normal = SimpleNamespace(NormalPhase=factory, load_normal_owner=Mock(return_value="inert-owner"))
            attempt = {"roots": [], "inflight": False}
            with self.subTest(retained=retained), patch.object(A, "SOURCE", source), patch.object(A, "N", normal), \
                 patch.object(A, "chain", return_value=([11], ["inert-parent"])), \
                 patch.object(A, "publish_preparation"), patch.object(A, "source_original"), \
                 patch.object(A, "clean_environment", return_value={"PATH": "/usr/bin:/bin"}), \
                 patch.object(INPUTS, "_new", side_effect=lambda a, p, n, c: {"path": p["path"] / n}), \
                 patch.object(INPUTS, "_binding", return_value={}), patch.object(INPUTS, "_ATTEMPT", attempt), \
                 patch.object(INPUTS, "_CONTEXT", ("b" * 40, "23", "2", work, root, 501, 20)), \
                 patch("os.fstatvfs", return_value=SimpleNamespace(f_bavail=8 << 30, f_frsize=1)), \
                 patch.dict(os.environ, selected_env, clear=True):
                with self.assertRaises(StoppedBeforeChild):
                    INPUTS._parent(A, work, {"path": work, "fds": [12]}, "inert-clock")
            factory.assert_called_once()
            _, child, cwd, _ = factory.call_args.args
            self.assertEqual(cwd, A.UI_CONSUMER_SOURCE.parent if retained else source)
            self.assertEqual((child["GITHUB_SHA"], child["GITHUB_RUN_ID"]), ("a" * 40, "900"))
            for key in ("MRK_MACOS_RUNNER", "MRK_MACOS_MACHINE", "MRK_MACOS_HOSTED_JOB"):
                self.assertEqual(child[key], environment[key])
            self.assertNotIn("GITHUB_TOKEN", child)
            self.assertEqual(child.get("MRK_CANDIDATE_SOURCE"), "b" * 40 if retained else None)
            self.assertEqual(child["MRK_ANDROID_ACQUISITION_CHILD"], "1")
            self.assertEqual(native.call.call_args.args[1], [sys.executable, "-I", "-S", "-B",
                str(source / "desktop/tools/macos_android_dependency_preparation.py"), A.TOOL_COMMANDS[1]])


class FixturePreparation(PassiveOnly):
    def test_unreturned_child_retains_all_roots_and_close_failure_never_masks_first_error(self):
        roots = [{"fds": [1], "originals": ["first"]}, {"fds": [2], "originals": ["second"]}]
        attempt = {"roots": roots, "inflight": True}
        first = RuntimeError("inert original failure")
        close = OSError("inert close failure")
        # DATA-only original-book routing, not an actual descriptor/close proof.
        with patch.object(INPUTS, "_ATTEMPT", attempt), patch.object(A, "close_chain", side_effect=[close, None]) as consume:
            self.assertIs(INPUTS._close(A, first), first)
            consume.assert_not_called()
            attempt["inflight"] = False
            self.assertIs(INPUTS._close(A, first), first)
            self.assertEqual(consume.call_args_list, [unittest.mock.call([2], ["second"]),
                                                     unittest.mock.call([1], ["first"])])
        self.assertEqual(attempt["roots"], roots)

    def test_existing_task_leaf_is_not_adopted_overwritten_or_deleted(self):
        temporary = tempfile.TemporaryDirectory(prefix=".tool-collision-passive-", dir=ROOT)
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        parent = A.admit_work(root)
        self.addCleanup(lambda: A.close_chain(parent["fds"], parent["originals"]) if parent["fds"] else None)
        existing = root / INPUTS.CASES[0]
        existing.mkdir(mode=0o700)
        marker = existing / "preserve"
        marker.write_bytes(b"retained original interruption\n")
        before = A.nine(existing.stat())
        attempt = {"roots": [], "inflight": False}
        context = ("a" * 40, "2", "1", root, root, os.getuid(), os.getgid())
        with patch.object(INPUTS, "_ATTEMPT", attempt), patch.object(INPUTS, "_CONTEXT", context):
            with self.assertRaises(FileExistsError):
                INPUTS._new(A, parent, INPUTS.CASES[0], N.PhaseClock(810, now=lambda: 10))
        self.assertEqual(attempt["roots"], [])
        self.assertEqual(A.nine(existing.stat()), before)
        self.assertEqual(marker.read_bytes(), b"retained original interruption\n")

    def test_fixed_native_home_layout_and_no_tmp_or_environment_fallback(self):
        root = INPUTS.source_root("a" * 40, "2", "1", "/Users/runner", A.need)
        self.assertEqual(root, Path("/Users/runner/Library/Application Support/mrk-macos-tool-inputs-" + "a" * 40 + "-2-1"))
        with patch.dict(os.environ, {"HOME": "/foreign"}):
            self.assertEqual(INPUTS.source_root("a" * 40, "2", "1", "/Users/runner", A.need), root)
        for home in ("/", "relative", "/Users/runner/../other", "/Users//runner"):
            with self.subTest(home=home), self.assertRaises(A.Refused):
                INPUTS.source_root("a" * 40, "2", "1", home, A.need)
        # Real ordinary ancestry refusal, not a pretend successful Mac source.
        if Path("/tmp").is_dir() and Path("/tmp").stat().st_mode & 0o022:
            # Darwin's /tmp is a symlink: O_NOFOLLOW refuses it at open,
            # before the writable-ancestry policy can produce A.Refused.
            with self.assertRaises((A.Refused, NotADirectoryError)):
                A.chain(Path("/tmp"), retained=True)
        self.assertEqual(INPUTS.CASES, T.RUN_ORDER)

    def test_actual_current_catalogue_three_subsets_fit_each_existing_original(self):
        clock = N.PhaseClock(1200, now=lambda: 10)
        with patch.object(A, "SOURCE", ROOT):
            values = INPUTS.expected_cases(A, A.ui_source_roster(clock))
        self.assertEqual(tuple(sum(v[2] for v in value.values()) for value in values), INPUTS.BYTES)
        self.assertEqual(tuple(sum(v[0] == "file" for v in value.values()) for value in values), INPUTS.FILES)
        self.assertEqual(sum(INPUTS.BYTES), 783964776)
        self.assertTrue(all(len(value) <= A.ENTRIES and count <= A.FILES for value, count in zip(values, INPUTS.FILES)))
        self.assertTrue(all("build-tools" not in path and v[0] != "metadata" for value in values for path, v in value.items()))
        self.assertTrue(any(path.startswith("jdk/") for path in values[0]))
        self.assertTrue(all(path.startswith("sdk/") or path == "sdk" for value in values[1:] for path in value))
        archives = [r for r in A.ARCHIVES if r["role"] in INPUTS.ROLES]
        self.assertEqual([r["role"] for r in archives], list(INPUTS.ROLES))
        self.assertEqual(sum(r["bytes"] for r in archives), INPUTS.ARCHIVE_BYTES)

    def test_same_clock_aggregate_read_and_prewrite_debits_never_reset_per_case(self):
        clock = N.PhaseClock(810, now=lambda: 10)
        shared = INPUTS._Reads(A, clock)
        self.assertEqual(shared.maximum + INPUTS.parent_read_reserve(A), A.READ_BYTES)
        shared.reads = shared.maximum - 1
        shared.read(1)
        with self.assertRaises(A.Refused):
            shared.read(1)
        shared.writes = A.TOOL_BYTES - 1
        shared.file(1)
        with self.assertRaises(A.Refused):
            shared.file(1)
        self.assertEqual(shared.writes, A.TOOL_BYTES)
        self.assertEqual(clock.deadline - clock.started, 810_000_000_000)

    def test_new_source_uses_same_writer_roster_sealer_and_post_on_tiny_public_fixture(self):
        # A task-owned protected Linux DATA tree exercises byte/mode/close
        # mechanics only, not Mac ancestry, ACL, native acceptance or an archive.
        temporary = tempfile.TemporaryDirectory(prefix=".tool-input-passive-", dir=ROOT)
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source, work = root / "source", root / "work"
        source.mkdir(mode=0o700)
        work.mkdir(mode=0o700)
        held = A.admit_work(source)
        self.addCleanup(lambda: A.close_chain(held["fds"], held["originals"]) if held["fds"] else None)
        body = b"public synthetic fixture\n"
        path = "sdk/platforms/android-35/source.properties"
        sha = hashlib.sha256(body).hexdigest()
        expected = {p: ("directory", 0o755, 0, None) for p in ("sdk", "sdk/platforms", "sdk/platforms/android-35")}
        expected[path] = ("file", 0o644, len(body), sha)
        clock = N.PhaseClock(810, now=lambda: 10)
        shared = INPUTS._Reads(A, clock)
        original = INPUTS._case_type(A)(work, held, expected, 1, shared)
        self.assertIs(original.clock, clock)
        original.role = next(r for r in original.archives if r["role"] == "sdk-platform")
        row = ("android-35/source.properties", "file", 0o100644, len(body), sha)
        original.begin(row)
        original.block(row[0], 0, body)
        original.end(row)
        roster = original.seal()
        self.assertEqual(shared.writes, len(body))
        self.assertEqual((source / path).read_bytes(), body)
        self.assertEqual((source / path).stat().st_mode & 0o777, 0o644)
        self.assertEqual(source.stat().st_mode & 0o777, 0o700)
        self.assertEqual(A._ui_tool_post(work, clock, expected, source), (roster, len(body), 1, 3))
        (source / path).write_bytes(b"changed synthetic bytes\n")
        with self.assertRaises(A.Refused):
            A._ui_tool_post(work, clock, expected, source)
        self.assertFalse(original.active)
        self.assertIsNone(original.archive_fd)

    def test_archive_reopen_refuses_tamper_before_correspondence_and_consumes_own_fd(self):
        temporary = tempfile.TemporaryDirectory(prefix=".tool-archive-passive-", dir=ROOT)
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source, work = root / "source", root / "work"
        source.mkdir(mode=0o700)
        work.mkdir(mode=0o700)
        path = work / "platform"
        path.write_bytes(b"original")
        path.chmod(0o600)
        before = A.nine(path.stat())
        role = {"role": "sdk-platform", "bytes": 8, "sha256": hashlib.sha256(b"original").hexdigest(), "archivePrefix": "android-35"}
        held = A.admit_work(source)
        self.addCleanup(lambda: A.close_chain(held["fds"], held["originals"]) if held["fds"] else None)
        compile_call = self.stack.enter_context(patch.object(A, "C", SimpleNamespace(compile_archive=lambda *args, **kw: self.fail("tamper reached parser"))))
        with patch.object(A, "ARCHIVES", [role]):
            original = INPUTS._case_type(A)(work, held, {}, 1, INPUTS._Reads(A, N.PhaseClock(810, now=lambda: 10)))
        path.write_bytes(b"tampered")
        with self.assertRaises(A.Refused):
            original.replay_platform((path, before))
        self.assertIsNone(original.archive_fd)
        self.assertEqual(path.read_bytes(), b"tampered")


class PublicAcquisitionReadback(PassiveOnly):
    """Real tiny private files and original readers, never acquisition/HTTP."""
    def setUp(self):
        super().setUp()
        self.stack.enter_context(patch("socket.socket", side_effect=AssertionError("no socket")))
        self.temp = tempfile.TemporaryDirectory(prefix="mrk-tool-readback-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.public = T.PUBLIC
        self.f = OBS.Fixtures(OBS.Binding("a" * 40, "1", "1"), os.getuid(), os.getgid(), self.public.SCOPE)
        self.f.last_returned = True
        self.application = self.f._open(str(self.root), directory=True)
        self.f.parent = self.application
        self.addCleanup(self.close_files)

    def close_files(self):
        self.assertFalse(self.f.inflight)
        for fd in tuple(self.f.fds):
            self.assertTrue(self.f._close(fd))
        self.assertEqual(self.f.close_errors, 0)

    def directory(self, relative):
        path = self.root / relative
        path.mkdir(mode=0o700, parents=True)
        # pathlib's intermediate default mode is not fixture authority.
        for parent in (path, *path.parents):
            if parent == self.root:
                break
            os.chmod(parent, 0o700)
        return path

    def file(self, relative, raw=b"inert-only\n"):
        path = self.root / relative
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def partial(self):
        operation = "1" * 32
        job = "tool-cache-v1/archives/tool-" + operation
        self.directory(job + "/sources")
        self.file(job + "/origin.json")
        archive = self.file(job + "/" + self.public.ARCHIVE, b"x" * self.public.MIN_CUT)
        c = OBS.CLI.Fixture(self.f)
        c.application_fd = self.application
        cut = self.public.TransferCut(c, operation)
        return c, cut, archive

    def capture(self, cut):
        calls = OBS.CLI.Calls(clock=lambda: 10.0, case=self.public.CANCEL)
        return cut.capture(calls)

    def test_actual_stat_cut_retains_three_dirs_and_rejects_foreign_inode_without_reading_archive(self):
        c, cut, archive = self.partial()
        # Real tiny test-owned descriptors exercise the fixed residual slots;
        # they are not claimed to be the protected installed thirteen roles.
        for _ in range(13):
            c.retain(self.f._open(".", self.application, directory=True))
        with patch("os.pread", side_effect=AssertionError("archive content reader forbidden")):
            before = self.capture(cut)
            self.assertEqual(len(c.extra), OBS.CLI.FD_LIMIT)
            self.assertEqual(before[6], self.public.MIN_CUT)
            with archive.open("ab") as writer:
                writer.write(b"one more returned chunk")
            after = cut.returned()
            self.assertEqual(before[:6], after[:6])
            self.assertGreater(after[6], before[6])
            replacement = self.file(str(archive.relative_to(self.root)) + ".replacement", b"z" * self.public.MIN_CUT)
            os.replace(replacement, archive)  # Only a unit-test-owned fixture.
            with self.assertRaisesRegex(ValueError, "substitution"):
                cut.returned()
            self.assertEqual(archive.stat().st_size, self.public.MIN_CUT)

    def test_no_full_or_truncated_archive_no_success_row_or_second_job_can_pass(self):
        _, cut, archive = self.partial()
        before = self.capture(cut)
        original_stat = os.stat
        def full(name, *args, **kw):
            s = original_stat(name, *args, **kw)
            if name == self.public.ARCHIVE:
                return SimpleNamespace(st_dev=s.st_dev, st_ino=s.st_ino, st_mode=s.st_mode,
                    st_uid=s.st_uid, st_gid=s.st_gid, st_nlink=s.st_nlink, st_size=self.public.ARCHIVE_BYTES)
            return s
        # Full-size metadata DATA, not a 77MB allocation or download.
        with patch("os.stat", side_effect=full), self.assertRaisesRegex(ValueError, "file-shape"):
            cut.returned()
        other = self.directory("tool-cache-v1/archives/tool-" + "2" * 32)
        with self.assertRaisesRegex(OBS.Refused, "only-original-job"):
            cut.returned()
        other.rmdir()  # Remove only this test's own empty negative fixture.
        self.file(str(archive.parent.relative_to(self.root)) + "/result.json")
        with self.assertRaisesRegex(OBS.Refused, "job-roster"):
            cut.returned()
        self.assertEqual(cut.cut, before)

    def test_original_clock_cut_and_symlink_refusal_are_not_a_new_timer_or_retry(self):
        _, cut, archive = self.partial()
        archive.unlink()
        archive.symlink_to("origin.json")
        with self.assertRaisesRegex(ValueError, "file-shape"):
            cut.sample()
        tick, waits = [10.0], []
        calls = SimpleNamespace(success_end=2410.0, clock=lambda: tick[0], check=lambda: None,
            stop=SimpleNamespace(wait=lambda delay: (waits.append(delay), tick.__setitem__(0, tick[0] + 61))))
        with patch.object(cut, "sample", return_value=None), self.assertRaisesRegex(ValueError, "not-observed"):
            cut.capture(calls)
        self.assertEqual(waits, [self.public.POLL_INTERVAL] * 2)
        self.assertIsNone(cut.cut)

    def test_warm_job_uses_exact_producer_roster_without_new_archive_or_extra_job(self):
        cold, warm = "1" * 32, "2" * 32
        self.directory("tool-cache-v1/origins")
        self.file("tool-cache-v1/.lease")
        for number, operation in enumerate((cold, warm)):
            job = "tool-cache-v1/archives/tool-" + operation
            self.directory(job + "/sources")
            self.file(job + "/origin.json"); self.file(job + "/result.json")
            if number == 0:
                for part in self.public.PARTS:
                    self.file(job + "/" + part + ".archive")
        value = {"execution": "executed", "coldOperation": cold, "warmOperation": warm}
        before = self.f.fds.copy()
        self.public.cold_readback(self.f, self.application, value)
        self.assertEqual(self.f.fds, before)  # Every temporary original closed.
        new_archive = self.file("tool-cache-v1/archives/tool-" + warm + "/jdk.archive")
        with self.assertRaisesRegex(OBS.Refused, "producer-or-warm-roster"):
            self.public.cold_readback(self.f, self.application, value)
        new_archive.unlink()
        self.directory("tool-cache-v1/archives/tool-" + "3" * 32)
        with self.assertRaisesRegex(OBS.Refused, "two-original-jobs"):
            self.public.cold_readback(self.f, self.application, value)
        self.assertEqual(self.f.fds, before)

    def test_whole_remaining_disk_is_checked_before_the_original_case_admission(self):
        for case, payload in ((self.public.COLD, self.public.COLD_WARM_BYTES),
                              (self.public.CANCEL, self.public.COPY_BYTES + self.public.ARCHIVE_BYTES)):
            total = payload + self.public.METADATA + self.public.RESERVE
            with patch("os.fstatvfs", return_value=SimpleNamespace(f_bavail=total - 1, f_frsize=1)), \
                 self.assertRaisesRegex(ValueError, "disk-prerequisite"):
                self.public.space_before(self.f, case)
            with patch("os.fstatvfs", return_value=SimpleNamespace(f_bavail=total, f_frsize=1)):
                self.public.space_before(self.f, case)
        self.f.inflight = True
        try:
            with patch("os.fstatvfs", side_effect=AssertionError("after admission")), \
                 self.assertRaisesRegex(ValueError, "space-order"):
                self.public.space_before(self.f, self.public.COLD)
        finally:
            self.f.inflight = False


if __name__ == "__main__":
    unittest.main()
