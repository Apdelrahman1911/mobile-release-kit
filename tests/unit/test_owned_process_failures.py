"""Typed command/caller failures without resurrecting a second process owner.

Risk migration: old Popen/profile/scratch/signal scenarios now use reviewed
profile_process_owner/default_cancellation/profile_resource_fixture coverage.
Command grant/close-once/first-failure/fork contracts are CommandContractTests;
real group/output/callback/exec/fork cuts are OwnedProcessTests. These caller
cases retain fail-fast platform ordering and preserve completed first output.
InertCommandFailureTests has no native/FD/thread/signal effect; the two-platform
build method below is native-owner-only and is not in the inert local selector.
"""
from __future__ import annotations

import base64
import signal
import shutil
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import android, credentials, discovery, ios, ios_profiles, owned_process as owned
from mobile_release import _command_process as command
from mobile_release import local_signing as signing, preflight as preflight_module
from mobile_release.config import load_config
from mobile_release.errors import CredentialError, ValidationError
from mobile_release.reporting import Finding, Report, Status

from .helpers import android_config, ios_config, write_project
from .ios_artifact_helpers import artifact_set
from .test_owned_process import original_command_outcomes, all_original_commands_final


class InertCommandFailureTests(unittest.TestCase):
    def setUp(self):
        from .test_lifetime_evidence import fork_registry_model
        self.enterContext(fork_registry_model())
        self.engines = []
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(signal, "getsignal", return_value=lambda *_: None))
        self.stack.enter_context(patch.object(signal, "signal", side_effect=AssertionError("signal mutation")))
        self.stack.enter_context(patch.object(command.native.Acquisition, "_runtime", side_effect=AssertionError("native effect")))
        self.stack.enter_context(patch.object(command.threading.Thread, "start", side_effect=AssertionError("thread effect")))
        self.addCleanup(self.remove_inert_roots)

    def remove_inert_roots(self):
        for engine in self.engines:
            # These test roots never acquired a raw resource or creator. Drop
            # only their intentionally injected UNKNOWN reference, not another
            # task's or a real native operation's retained custody.
            self.assertTrue(all(not acq.attempted and not acq.leases for acq in engine.ctx.acquisitions))
            self.assertFalse(engine.ctx.tasks)
            if engine in command._RETAINED:
                command._RETAINED.remove(engine)

    def invoke_callback_without_native(self, callback):
        def body(engine, _argv, _env, _cwd, _capture, _limit, started):
            self.engines.append(engine)
            started(1)  # Diagnostic integer deliberately supplies no authority.
        with patch.object(command._Outer, "body", new=body):
            return owned.run_owned(["fictional"], on_start=callback)

    def test_prior_typed_callback_debt_survives_this_commands_positive_no_target_finality(self):
        for original in (owned.ProcessCleanupError("earlier cleanup", dispatched=True),
                         owned.ProcessError("earlier containment", dispatched=True, contained=False)):
            with self.subTest(kind=type(original).__name__):
                def callback(_pid): raise original
                with self.assertRaises(owned.ProcessError) as caught:
                    self.invoke_callback_without_native(callback)
                self.assertIs(caught.exception, original)
                self.assertTrue(original.fatal and original.dispatched)
                outcome = self.engines[-1].slot.read()
                self.assertIsNotNone(outcome.original_finality)
                self.assertEqual(outcome.no_target.kind, "NO_W_CREATION")
                self.assertFalse(outcome.create_w.attempted or outcome.run_tool.attempted)

    def test_typed_context_debt_cannot_be_hidden_by_later_generic_callback_error(self):
        prior = owned.ProcessCleanupError("private-prior", dispatched=True, contained=False)
        def callback(_pid):
            try: raise prior
            except owned.ProcessError: raise ValueError("private-later")
        with self.assertRaises(owned.ProcessError) as caught:
            self.invoke_callback_without_native(callback)
        self.assertTrue(caught.exception.fatal and caught.exception.dispatched)
        self.assertFalse(caught.exception.contained or caught.exception.cleanup_complete)
        self.assertNotIn("private", str(caught.exception))

    def test_same_first_interruption_survives_secondary_cleanup_failure(self):
        cleanup = command._Outer.cleanup
        for original in (KeyboardInterrupt(), SystemExit(73)):
            with self.subTest(kind=type(original).__name__):
                def callback(_pid): raise original
                def failed_cleanup(engine):
                    cleanup(engine)
                    raise OSError("private-cleanup")
                with patch.object(command._Outer, "cleanup", new=failed_cleanup):
                    with self.assertRaises(type(original)) as caught:
                        self.invoke_callback_without_native(callback)
                self.assertIs(caught.exception, original)
                self.assertTrue(self.engines[-1].guard.lifetime_ledger.fatal)
                self.assertIsNone(self.engines[-1].slot.read().original_finality)

    def test_no_c_validation_failure_has_complete_no_target_protocol_not_a_target_result(self):
        original_init = command._Outer.__init__
        def init(engine, *args, **kwargs):
            original_init(engine, *args, **kwargs)
            self.engines.append(engine)
        with patch.object(command._Outer, "__init__", new=init):
            with self.assertRaises(owned.ProcessError):
                owned.run_owned(["fictional\0invalid"])
        engine = self.engines[-1]
        outcome = engine.slot.read()
        self.assertIsNotNone(outcome.original_finality)
        self.assertEqual(outcome.result_integrity, "complete")
        self.assertEqual(outcome.no_target.kind, "NO_W_CREATION")
        self.assertEqual(outcome.termination, "unavailable")
        self.assertIsNone(outcome.returncode)
        self.assertFalse(engine.ctx.child_acquisition.attempted)
        self.assertFalse(outcome.create_w.attempted or outcome.run_tool.attempted)
        self.assertFalse(engine.guard.lifetime_ledger.fatal)


class BeforeActiveFailureTests(unittest.TestCase):
    def setUp(self):
        if self._testMethodName == "test_actual_two_platform_builds_fail_fast_and_retain_completed_first_platform_output":
            self.root = Path(tempfile.mkdtemp(prefix="mrk-before-active-native-")).resolve()
            observation = original_command_outcomes()
            outcomes = observation.__enter__()
            self.addCleanup(observation.__exit__, None, None, None)
            def remove_settled():
                if not all_original_commands_final(outcomes):
                    self.fail(f"original finality unconfirmed; preserving build fixture {self.root}")
                shutil.rmtree(self.root)
            self.addCleanup(remove_settled)
        else:
            scratch = tempfile.TemporaryDirectory(prefix="mrk-before-active-")
            self.addCleanup(scratch.cleanup)
            self.root = Path(scratch.name).resolve()
        value = ios_config()
        value["projectChecks"]["preflight"] = [["fictional-first"], ["must-not-run"]]
        value["ios"]["prepareCommand"] = ["fictional-prepare"]
        self.ios = load_config(write_project(self.root / "ios", value, platform="ios"))
        self.android = load_config(write_project(self.root / "android", android_config()))

    def failure(self, kind):
        return (owned.ProcessError("fictional lifetime failure", dispatched=True, contained=False)
                if kind == "group" else owned.ProcessCleanupError("fictional cleanup failure", dispatched=True))

    def test_each_before_active_command_wrapper_propagates_fatal_without_later_work(self):
        calls = (
            (discovery, lambda: discovery.git_context(self.root, {"GITHUB_REPOSITORY": "fictional/app"})),
            (preflight_module, preflight_module._xcode_toolchain_finding),
            (preflight_module, lambda: preflight_module._effective_android_identity_finding(self.android)),
            (preflight_module, lambda: preflight_module._xcode_application_identities(self.ios, configuration="Debug")),
            (preflight_module, lambda: preflight_module._effective_ios_identity_finding(self.ios)),
            (preflight_module, lambda: preflight_module.run_project_checks(self.ios, "preflight", environ={})),
        )
        for kind in ("group", "resource"):
            for index, (module, call) in enumerate(calls):
                with self.subTest(kind=kind, caller=index), \
                     patch.object(preflight_module, "sys", SimpleNamespace(platform="darwin")), \
                     patch.object(preflight_module.shutil, "which", return_value="/fictional/tool"), \
                     patch.object(module, "run_owned", side_effect=self.failure(kind)) as run, \
                     self.assertRaises(owned.ProcessError) as caught:
                    call()
                self.assertTrue(caught.exception.fatal)
                run.assert_called_once()

    def test_private_profile_failure_stops_certificate_firebase_and_next_platform(self):
        values = {"MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64": base64.b64encode(b"fictional-p12").decode(),
                  "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64": base64.b64encode(b"fictional-profile").decode(),
                  "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": "fictional"}
        for kind in ("group", "resource"):
            with self.subTest(kind=kind), \
                 patch.object(ios_profiles, "load_authenticated_profile", side_effect=self.failure(kind)), \
                 patch.object(credentials, "_run_private") as native, \
                 patch.object(credentials, "_validate_firebase_material") as firebase, \
                 patch.object(credentials, "_validate_android_material") as android, \
                 self.assertRaises(owned.ProcessError):
                credentials.validate_signing_material(self.ios, values=values, platforms=("ios", "android"))
            native.assert_not_called()
            firebase.assert_not_called()
            android.assert_not_called()

    def test_actual_ipa_consumers_preserve_fatal_profile_errors_and_ordinary_invalid_diagnostics(self):
        artifacts = artifact_set(self.root / "artifacts", nested=False)
        for kind in ("group", "resource", "ordinary"):
            error = self.failure(kind) if kind != "ordinary" else owned.ProcessError("fixed completed invalid profile", dispatched=True)
            with self.subTest(kind=kind), patch.object(ios, "sys", SimpleNamespace(platform="darwin")), \
                 patch.object(ios.shutil, "which", return_value="/fictional/tool"), \
                 patch.object(ios, "_profile_details", side_effect=error) as authentication, \
                 patch.object(ios, "_codesign_entitlements") as entitlements, \
                 patch.object(ios, "_codesign_fingerprint") as fingerprint:
                arguments = dict(expected_bundle_id="com.example.reader", expected_team_id="ABCDE12345",
                                 expected_fingerprint="b" * 64, release=self.ios.release_version(), require_tools=True)
                if kind == "ordinary":
                    findings, interval = ios.validate_ipa_current_signing(artifacts["ios-ipa"], **arguments)
                    self.assertIsNone(interval)
                    self.assertTrue(any(item.code == "ios.ipa.validation" and item.status == Status.FAIL for item in findings))
                else:
                    with self.assertRaises(owned.ProcessError) as caught:
                        ios.validate_ipa_current_signing(artifacts["ios-ipa"], **arguments)
                    self.assertTrue(caught.exception.fatal)
                    self.assertEqual(caught.exception.dispatched, error.dispatched)
                    self.assertFalse(caught.exception.contained and not error.contained)
                authentication.assert_called_once()
                entitlements.assert_not_called()
                fingerprint.assert_not_called()
                authentication.reset_mock()
                with self.assertRaises(owned.ProcessError):
                    ios.ipa_signing_evidence(artifacts["ios-ipa"])
                authentication.assert_called_once()
                fingerprint.assert_not_called()

    def test_failed_validation_and_project_query_loops_do_not_advance(self):
        failed = Finding("injected", Status.INVALID, "fictional invalid result")
        with patch.object(credentials, "_validate_android_material", return_value=failed) as android, \
             patch.object(credentials, "_validate_apple_signing_material") as apple, \
             patch.object(credentials, "_validate_firebase_material") as firebase:
            self.assertEqual(credentials.validate_signing_material(self.android, values={}, platforms=("android", "ios")), [failed])
        android.assert_called_once()
        apple.assert_not_called()
        firebase.assert_not_called()
        with patch.object(preflight_module, "run_owned", return_value=subprocess.CompletedProcess([], 7)) as run:
            findings = preflight_module.run_project_checks(self.ios, "preflight", environ={})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, Status.FAIL)
        run.assert_called_once()
        self.ios.data["ios"].pop("prepareCommand")
        with patch.object(preflight_module, "sys", SimpleNamespace(platform="darwin")), \
             patch.object(preflight_module.shutil, "which", return_value="/fictional/tool"), \
             patch.object(preflight_module, "_xcode_application_identities", return_value=(set(), "failed")) as query:
            self.assertEqual(preflight_module._effective_ios_identity_finding(self.ios).status, Status.BLOCKED)
        query.assert_called_once_with(self.ios, configuration="Debug", execution_source=None, cancellation=None)

    def test_secondary_filesystem_error_cannot_resume_next_platform_identity_query(self):
        self.android.data["ios"] = dict(self.ios.data["ios"])
        real_temporary = tempfile.TemporaryDirectory

        class Temporary(real_temporary):
            def __exit__(self, *args):
                super().__exit__(*args)
                raise OSError("fictional secondary filesystem cleanup failure")

        with patch.object(preflight_module.tempfile, "TemporaryDirectory", Temporary), \
             patch.object(preflight_module, "run_owned", side_effect=self.failure("group")) as run, \
             patch.object(preflight_module, "_effective_ios_identity_finding") as later:
            findings = preflight_module.effective_identity_findings(self.android, ("android", "ios"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, Status.BLOCKED)
        run.assert_called_once()
        later.assert_not_called()

    def test_p8_failure_does_not_read_adc_or_advance_private_validation(self):
        adc = self.root / "adc.json"
        adc.write_text('{"type":"authorized_user"}')
        adc.chmod(0o600)
        values = {
            "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64": base64.b64encode(b"fictional-p8").decode("ascii"),
            "GOOGLE_APPLICATION_CREDENTIALS": str(adc),
        }
        for kind in ("group", "resource"):
            original = self.failure(kind)

            def failed_p8(selected_path, *, execution_source=None, cancellation=None):
                self.assertIsNotNone(cancellation)
                self.assertEqual(selected_path().read_bytes(), b"fictional-p8")
                raise original

            with self.subTest(kind=kind), patch.object(credentials, "_validate_selected_p8", side_effect=failed_p8) as p8, \
                 patch.object(credentials, "read_external_bytes", side_effect=AssertionError("later ADC read")) as adc_read, \
                 self.assertRaises(owned.ProcessError) as caught:
                credentials.validate_store_material(self.ios, values=values, platforms=("ios", "android"))
            p8.assert_called_once()
            adc_read.assert_not_called()
            self.assertTrue(caught.exception.fatal)
            self.assertTrue(caught.exception.dispatched)
            if not original.contained:
                self.assertFalse(caught.exception.contained)
            if not original.cleanup_complete:
                self.assertFalse(caught.exception.cleanup_complete)
            self.assertEqual(adc.read_bytes(), b'{"type":"authorized_user"}')

    def test_failed_prerequisite_phases_stop_later_private_work_in_offline_and_signing_modes(self):
        failure = Finding("fictional-failure", Status.FAIL, "Failed prerequisite")
        phases = ("doctor", "run_project_checks", "credential_findings", "validate_signing_material", "effective_identity_findings")
        home = self.root / "phase-home"
        home.mkdir(mode=0o700)

        @contextmanager
        def lease(*, cancellation):
            self.assertIsNotNone(cancellation)
            with signing.local_signing_lease(home=home, cancellation=cancellation) as owner:
                self.assertIs(owner.cancellation, cancellation)
                yield owner

        for mode in ("offline", "signing"):
            applicable = phases if mode == "signing" else (phases[0], phases[1], phases[-1])
            for phase in applicable:
                with self.subTest(mode=mode, phase=phase), ExitStack() as stack:
                    stack.enter_context(patch.object(preflight_module, "local_signing_lease", side_effect=lease))
                    stack.enter_context(patch.object(preflight_module, "metadata_findings", return_value=[]))
                    stack.enter_context(patch.object(preflight_module, "resolve_credential_values", return_value={}))
                    mocks = {name: stack.enter_context(patch.object(preflight_module, name, return_value=[])) for name in phases}
                    mocks["doctor"].return_value = Report("fixture")
                    mocks[phase].return_value = Report("fixture", [failure]) if phase == "doctor" else [failure]
                    sentinels = [stack.enter_context(patch.object(preflight_module, name)) for name in (
                        "materialize_build_inputs", "run_ios_build", "run_android_build", "_selected_store_material", "online_preflight_findings")]
                    report = preflight_module.preflight(self.ios, mode=mode, platforms=("ios",), run_builds=True)
                    self.assertFalse(report.ok)
                    self.assertIn(failure, report.findings)
                    for name in phases[phases.index(phase) + 1:]:
                        mocks[name].assert_not_called()
                    for sentinel in sentinels:
                        sentinel.assert_not_called()
                self.assertEqual(signing.signing_status(home=home)["status"], "idle")

    def test_actual_two_platform_builds_fail_fast_and_retain_completed_first_platform_output(self):
        for order in (("android", "ios"), ("ios", "android")):
            for failure_index in (None, 0, 1):
                with self.subTest(order=order, failure_index=failure_index):
                    value = ios_config()
                    value["ios"].pop("prepareCommand", None)
                    value["android"] = android_config()["android"]
                    value["metadata"]["androidLocales"] = ["en-US"]
                    root = self.root / ("-".join(order) + "-" + str(failure_index))
                    config = load_config(write_project(root, value, platform="ios"))
                    failed_platform = order[failure_index] if failure_index is not None else None
                    (root / "app").mkdir()
                    (root / "app/build.gradle.kts").write_text('plugins { id("com.android.application") }')
                    original = root / "app/build/outputs/bundle/release/app.aab"
                    original.parent.mkdir(parents=True)
                    original.write_bytes(b"fictional unvalidated Android output")
                    wrapper = root / "gradlew"
                    wrapper.write_text("#!/bin/sh\nexit " + ("7" if failed_platform == "android" else "0") + "\n")
                    wrapper.chmod(0o700)

                    def native(argv, *_args, **_kwargs):
                        if failed_platform == "ios":
                            raise ValidationError("fictional iOS build failure")
                        archive = Path(argv[argv.index("-archivePath") + 1])
                        archive.mkdir()
                        (archive / "fictional-build-output").write_bytes(b"fictional unvalidated iOS output")

                    with patch.object(preflight_module, "doctor", return_value=Report("fixture")), \
                         patch.object(preflight_module, "metadata_findings", return_value=[]), \
                         patch.object(preflight_module, "effective_identity_findings", return_value=[]), \
                         patch.object(preflight_module, "run_android_build", wraps=android.run_android_build) as android_build, \
                         patch.object(preflight_module, "run_ios_build", wraps=ios.run_ios_build) as ios_build, \
                         patch.object(preflight_module, "run_project_checks", wraps=preflight_module.run_project_checks) as checks, \
                         patch.object(preflight_module, "validate_aab", wraps=android.validate_aab) as aab_validation, \
                         patch.object(preflight_module, "validate_xcarchive", wraps=ios.validate_xcarchive) as archive_validation, \
                         patch.object(ios, "sys", SimpleNamespace(platform="darwin")), patch.object(ios, "_run_checked", new=native):
                        report = preflight_module.preflight(config, mode="offline", platforms=order, run_builds=True)
                    # These files are intentionally NOT valid release artifacts.
                    # Successful builds must reach real failing validation, never
                    # a mocked PASS used to hide the lifecycle behavior.
                    self.assertFalse(report.ok)
                    calls = {"android": android_build.call_count, "ios": ios_build.call_count}
                    self.assertEqual(calls[order[0]], 1)
                    self.assertEqual(calls[order[1]], int(failure_index != 0))
                    if failure_index is not None:
                        self.assertEqual(checks.call_count, 1)  # Initial checks only.
                        aab_validation.assert_not_called()
                        archive_validation.assert_not_called()
                    else:
                        aab_validation.assert_called_once()
                        archive_validation.assert_called_once()
                    if failure_index != 0:
                        retained = (root / ".mobile-release/build/android/app-release.aab" if order[0] == "android" else
                                    root / ".mobile-release/build/ios/archive.xcarchive/fictional-build-output")
                        self.assertTrue(retained.is_file())
                        self.assertIn(b"fictional unvalidated", retained.read_bytes())

    def test_signed_materialization_build_and_teardown_failure_never_enters_later_platform(self):
        self.ios.data["android"] = android_config()["android"]
        home = self.root / "signed-phase-home"
        home.mkdir(mode=0o700)
        owners = []

        @contextmanager
        def lease(*, cancellation):
            self.assertIsNotNone(cancellation)
            with signing.local_signing_lease(home=home, cancellation=cancellation) as owner:
                self.assertIs(owner.cancellation, cancellation)
                owners.append(owner)
                yield owner

        for order in (("android", "ios"), ("ios", "android")):
            for failed_index in (0, 1):
                for phase in ("entry", "build", "cleanup"):
                    with self.subTest(order=order, failed_index=failed_index, phase=phase), ExitStack() as stack:
                        calls, completed = [], []
                        failed = order[failed_index]

                        @contextmanager
                        def materialize(_config, *, platforms, cancellation, build_inputs, signing_lease, **_kwargs):
                            self.assertIs(signing_lease, owners[-1])
                            self.assertIs(cancellation, signing_lease.cancellation)
                            self.assertIs(build_inputs.cancellation, cancellation)
                            self.assertIs(build_inputs.invocation.child, build_inputs)
                            build_inputs.invocation.require(root=_config.root, cancellation=cancellation,
                                                            signing_lease=signing_lease)
                            platform = platforms[0]
                            calls.append((platform, "entry"))
                            if platform == failed and phase == "entry":
                                raise OSError("fictional input preparation failure")
                            try:
                                yield {}
                            finally:
                                calls.append((platform, "cleanup"))
                                if platform == failed and phase == "cleanup":
                                    raise OSError("fictional cleanup failure")

                        def build(platform, *, cancellation, **kwargs):
                            self.assertIs(cancellation, owners[-1].cancellation)
                            if platform == "android":
                                self.assertIs(kwargs["build_inputs"].cancellation, cancellation)
                            calls.append((platform, "build"))
                            if platform == failed and phase == "build":
                                raise owned.ProcessCleanupError("fictional build cleanup failure", dispatched=True)
                            path = self.root / (platform + "-retained-output")
                            path.write_bytes(b"fictional unvalidated completed output")
                            completed.append(path)
                            return {"android-aab" if platform == "android" else "ios-ipa": path}

                        for name, result in (("doctor", Report("fixture")), ("metadata_findings", []),
                                             ("resolve_credential_values", {}), ("credential_findings", []),
                                             ("validate_signing_material", []), ("effective_identity_findings", []),
                                             ("run_project_checks", [])):
                            stack.enter_context(patch.object(preflight_module, name, return_value=result))
                        stack.enter_context(patch.object(preflight_module, "local_signing_lease", side_effect=lease))
                        stack.enter_context(patch.object(preflight_module, "materialize_build_inputs", side_effect=materialize))
                        stack.enter_context(patch.object(preflight_module, "run_android_build", side_effect=lambda *_a, **kwargs: build("android", **kwargs)))
                        stack.enter_context(patch.object(preflight_module, "run_ios_build", side_effect=lambda *_a, **kwargs: build("ios", **kwargs)))
                        validators = [stack.enter_context(patch.object(preflight_module, name)) for name in ("validate_aab", "validate_ipa", "snapshot_ios_artifacts")]
                        report = preflight_module.preflight(self.ios, mode="signing", platforms=order, run_builds=True)
                        self.assertFalse(report.ok)
                        self.assertTrue(calls)
                        if failed_index == 0:
                            self.assertTrue(all(platform == failed for platform, _ in calls))
                        else:
                            self.assertEqual(calls[:3], [(order[0], "entry"), (order[0], "build"), (order[0], "cleanup")])
                            self.assertTrue(completed)
                        for path in completed:
                            self.assertEqual(path.read_bytes(), b"fictional unvalidated completed output")
                        for validator in validators:
                            validator.assert_not_called()
                    self.assertEqual(signing.signing_status(home=home)["status"], "idle")

    def test_public_preflight_aborts_fatal_initial_check_in_every_mode_without_fake_session_recovery(self):
        from mobile_release import build_inputs

        home = self.root / "home"
        home.mkdir(mode=0o700)

        @contextmanager
        def lease(*, cancellation):
            self.assertIsNotNone(cancellation)
            with signing.local_signing_lease(home=home, cancellation=cancellation) as owner:
                self.assertIs(owner.cancellation, cancellation)
                yield owner

        for mode in ("online", "offline", "signing"):
            for builds in (False, True):
                for kind in ("group", "resource"):
                    with self.subTest(mode=mode, builds=builds, kind=kind), ExitStack() as stack:
                        def fail_doctor(config, platforms, *, execution_source=None, cancellation=None):
                            invocation = build_inputs._ENV_OWNER  # Passive observation, never authority manufacture.
                            self.assertIs(type(invocation), build_inputs.InvocationCustody)
                            self.assertIs(config, self.ios)
                            self.assertEqual(platforms, ("ios",))
                            self.assertIs(cancellation, invocation.cancellation)
                            self.assertEqual(invocation.root, config.root)
                            self.assertTrue(invocation.active and invocation.reserved)
                            if mode == "online":
                                self.assertEqual(invocation.mode, "online")
                                self.assertIsNone(invocation.project_owner)
                                self.assertFalse(invocation.project_started)
                            else:
                                self.assertEqual(invocation.mode, "build")
                                self.assertIsNotNone(invocation.project_owner)
                                self.assertTrue(invocation.project_started)
                                self.assertIs(invocation.project_owner.guard, cancellation)
                                self.assertEqual(invocation.project_owner.root, config.root)
                            if mode == "signing" and builds:
                                self.assertIs(type(execution_source), command.AccountExecutionSource)
                                self.assertIs(execution_source._lease, invocation.signing_lease)
                                self.assertIs(execution_source._locked_source, invocation.signing_lease._locked_source)
                                self.assertIs(invocation.signing_lease.cancellation, cancellation)
                            else:
                                self.assertIsNone(invocation.signing_lease)
                                self.assertIsNone(execution_source)
                            raise self.failure(kind)

                        stack.enter_context(patch.object(preflight_module, "local_signing_lease", side_effect=lease))
                        doctor = stack.enter_context(patch.object(preflight_module, "doctor", side_effect=fail_doctor))
                        sentinels = [stack.enter_context(patch.object(preflight_module, name)) for name in (
                            "resolve_credential_values", "run_project_checks", "validate_signing_material",
                            "_selected_store_material", "run_android_build", "run_ios_build", "online_preflight_findings")]
                        report = preflight_module.preflight(self.ios, mode=mode, platforms=("ios",), run_builds=builds)
                        self.assertFalse(report.ok)
                        doctor.assert_called_once()
                        failure = next(item for item in report.findings if item.code == "preflight.process-lifetime")
                        self.assertIn("early command failure does not create", failure.remediation)
                        for sentinel in sentinels:
                            sentinel.assert_not_called()
                    self.assertEqual(signing.signing_status(home=home)["status"], "idle")

    def test_online_fatal_material_and_runner_stop_following_work_without_signing_or_application(self):
        p8_name = "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"
        values = {p8_name: base64.b64encode(b"fictional-p8").decode("ascii")}
        validate_material = credentials.SelectedStoreMaterial.validate
        for kind in ("group", "resource"):
            for target in ("material", "runner"):
                with self.subTest(kind=kind, target=target), ExitStack() as stack:
                    original = self.failure(kind)
                    stack.enter_context(patch.object(preflight_module, "doctor", return_value=Report("fixture")))
                    stack.enter_context(patch.object(preflight_module, "resolve_credential_values", return_value=values))
                    stack.enter_context(patch.object(preflight_module, "credential_findings", return_value=[]))
                    selection = stack.enter_context(patch.object(preflight_module, "_selected_store_material",
                                                                  wraps=preflight_module._selected_store_material))
                    validation = stack.enter_context(patch.object(credentials.SelectedStoreMaterial, "validate",
                                                                   autospec=True, side_effect=validate_material))
                    # Only the unavailable P8 policy result is fictional. The
                    # selection, validation state, scratch, environment and
                    # invocation stay real; no command outcome/finality is made.
                    p8 = stack.enter_context(patch.object(credentials, "_validate_selected_p8", return_value=Finding(
                        "fictional-p8-policy", Status.PASS, "Fictional P8 policy seam, not native authentication")))
                    native = stack.enter_context(patch.object(credentials, "_run_private",
                                                               side_effect=AssertionError("unmodeled native operation")))
                    if target == "material":
                        p8.side_effect = original

                    def query(*, config, release, platforms, material, invocation):
                        self.assertIs(config, self.ios)
                        self.assertEqual(platforms, ("ios",))
                        self.assertIs(material, validation.call_args.args[0])
                        self.assertIs(invocation, selection.call_args.kwargs["invocation"])
                        material.require(config=config, platforms=platforms, invocation=invocation)
                        self.assertEqual(preflight_module.os.environ.get(p8_name), values[p8_name])
                        raise original

                    runner = stack.enter_context(patch.object(preflight_module, "online_preflight_findings", side_effect=query))
                    sentinels = [stack.enter_context(patch.object(preflight_module, name)) for name in (
                        "run_project_checks", "effective_identity_findings", "validate_signing_material",
                        "materialize_build_inputs", "run_ios_build", "run_android_build", "local_signing_lease")]
                    report = preflight_module.preflight(self.ios, mode="online", platforms=("ios",), run_builds=True)
                    self.assertFalse(report.ok)
                    self.assertTrue(any(item.code == "preflight.process-lifetime" for item in report.findings))
                    selection.assert_called_once()
                    validation.assert_called_once()
                    p8.assert_called_once()
                    material = validation.call_args.args[0]
                    invocation = selection.call_args.kwargs["invocation"]
                    self.assertIs(material._invocation, invocation)
                    self.assertIs(material._scratch.cancellation, invocation.cancellation)
                    self.assertIs(selection.call_args.kwargs["cancellation"], invocation.cancellation)
                    self.assertIs(p8.call_args.kwargs["cancellation"], invocation.cancellation)
                    self.assertEqual(material._state, "closed")
                    self.assertFalse(invocation.active or invocation.project_started)
                    self.assertEqual(runner.call_count, int(target == "runner"))
                    native.assert_not_called()
                    for sentinel in sentinels:
                        sentinel.assert_not_called()

    def test_missing_adc_static_diagnostic_never_opens_private_files_or_runs_p8(self):
        values = {"MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH": "/fictional/private/p8"}
        with patch.object(credentials, "read_external_bytes") as private_read, \
             patch.object(credentials, "_validate_selected_p8") as p8, \
             patch.object(credentials, "finite_scratch") as scratch:
            findings = credentials.validate_store_material(self.ios, values=values, platforms=("ios", "android"))
        self.assertEqual([(item.code, item.status) for item in findings], [("credential-material.google-adc", Status.MISSING)])
        private_read.assert_not_called()
        p8.assert_not_called()
        scratch.assert_not_called()

    def test_public_online_prerequisite_and_unrelated_diagnostic_contract(self):
        p8_name = "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"
        values = {p8_name: base64.b64encode(b"fictional-p8").decode("ascii")}
        validate_material = credentials.SelectedStoreMaterial.validate
        for missing in (None, "version", "identity", "credentials", "material"):
            with self.subTest(missing=missing), ExitStack() as stack:
                report = Report("doctor", [Finding("unrelated-signing", Status.MISSING, "Unrelated signing input")])
                stack.enter_context(patch.object(preflight_module, "doctor", return_value=report))
                stack.enter_context(patch.object(preflight_module, "resolve_credential_values", return_value=values))
                inventory = stack.enter_context(patch.object(preflight_module, "credential_findings", return_value=[]))
                selection = stack.enter_context(patch.object(preflight_module, "_selected_store_material",
                                                              wraps=preflight_module._selected_store_material))
                validation = stack.enter_context(patch.object(credentials.SelectedStoreMaterial, "validate",
                                                               autospec=True, side_effect=validate_material))
                # This policy-only stub is not native authentication or an
                # original command/finality receipt. All material custody is real.
                p8 = stack.enter_context(patch.object(credentials, "_validate_selected_p8", return_value=Finding(
                    "fictional-p8-policy", Status.PASS, "Fictional P8 policy seam, not native authentication")))
                native = stack.enter_context(patch.object(credentials, "_run_private",
                                                           side_effect=AssertionError("unmodeled native operation")))

                def query(*, config, release, platforms, material, invocation):
                    self.assertIs(config, self.ios)
                    self.assertEqual(platforms, ("ios",))
                    self.assertIs(material, validation.call_args.args[0])
                    self.assertIs(invocation, selection.call_args.kwargs["invocation"])
                    material.require(config=config, platforms=platforms, invocation=invocation)
                    self.assertEqual(preflight_module.os.environ.get(p8_name), values[p8_name])
                    return [Finding("online", Status.PASS, "Fictional ownership finding")]

                online = stack.enter_context(patch.object(preflight_module, "online_preflight_findings", side_effect=query))
                sentinels = [stack.enter_context(patch.object(preflight_module, name)) for name in (
                    "run_project_checks", "effective_identity_findings", "materialize_build_inputs",
                    "run_ios_build", "run_android_build", "local_signing_lease")]
                stack.enter_context(patch.dict(self.ios.data["ios"], {"identityStatus": "unverified"}))
                if missing == "version":
                    from mobile_release.config import ConfigurationError
                    stack.enter_context(patch.object(type(self.ios), "release_version", side_effect=ConfigurationError("No version")))
                if missing == "identity":
                    self.ios.data["ios"]["identityStatus"] = "blocked"
                if missing == "credentials":
                    inventory.return_value = [Finding("credential-missing", Status.MISSING, "No credential")]
                if missing == "material":
                    p8.return_value = Finding("invalid-material", Status.INVALID, "Invalid credential")
                result = preflight_module.preflight(self.ios, mode="online", platforms=("ios",), run_builds=True)
                self.assertIs(result, report)
                self.assertFalse(result.ok)
                self.assertEqual(selection.call_count, int(missing in (None, "material")))
                self.assertEqual(validation.call_count, int(missing in (None, "material")))
                self.assertEqual(p8.call_count, int(missing in (None, "material")))
                self.assertEqual(online.call_count, int(missing is None))
                if validation.called:
                    material = validation.call_args.args[0]
                    invocation = selection.call_args.kwargs["invocation"]
                    self.assertIs(material._invocation, invocation)
                    self.assertIs(material._scratch.cancellation, invocation.cancellation)
                    self.assertIs(selection.call_args.kwargs["cancellation"], invocation.cancellation)
                    self.assertIs(p8.call_args.kwargs["cancellation"], invocation.cancellation)
                    self.assertEqual(material._state, "closed")
                    self.assertFalse(invocation.active or invocation.project_started)
                native.assert_not_called()
                for sentinel in sentinels:
                    sentinel.assert_not_called()


if __name__ == "__main__":
    unittest.main()
