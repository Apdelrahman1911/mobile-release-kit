"""Real input/scratch owners with inert tools; no process or Store access."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from mobile_release import stores
from mobile_release._command_process import CommandCallEvidence
from mobile_release._store_runtime import StoreRuntimeContext
from mobile_release.build_inputs import finite_scratch, invocation_custody
from mobile_release.config import load_config
from mobile_release.credentials import _selected_store_material
from mobile_release.errors import StoreOperationError, ValidationError
from mobile_release.owned_process import ProcessError
from mobile_release.reporting import Status
from mobile_release.tooling import REQUIRED_TOOLING_FILES

from .helpers import android_config, write_project


class StoreRuntimeContextTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            config = load_config(write_project(root / "application", android_config()))
            runtime = root / "Installed runtime with spaces"
            for name in ("ruby", "bundle"):
                path = runtime / "store/bin" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"inert fixture; must never execute\n")
                path.chmod(0o755)
            for name in REQUIRED_TOOLING_FILES:
                path = runtime / "store/tooling" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"inert tooling fixture\n")
            with patch.dict(os.environ, {"TMPDIR": str(root)}, clear=True), patch.object(
                    subprocess, "Popen", side_effect=AssertionError("no real child permitted")):
                with invocation_custody(config.root, mode="online") as invocation:
                    yield root, config, runtime, invocation

    @contextmanager
    def selected(self, root, config, invocation):
        adc = root / "explicit-account.json"
        # Tests only the existing owned selection, not real key authentication.
        adc.write_bytes(b'{"type":"service_account","synthetic":true}')
        adc.chmod(0o600)
        with _selected_store_material(config,
                values={"GOOGLE_APPLICATION_CREDENTIALS": str(adc)},
                platforms=("android",), invocation=invocation) as material:
            self.assertEqual([finding.status for finding in material.validate()], [Status.PASS])
            yield material

    def test_clean_environment_keeps_runtime_paths_through_final_filter(self):
        with self.fixture() as (root, config, runtime, invocation), finite_scratch(
                layout="online-runner", cancellation=invocation.cancellation, parent=root) as home:
            context = StoreRuntimeContext.installed(runtime, invocation=invocation, private_home=home)
            with patch.dict(os.environ, {
                    "HOME": "/foreign", "PATH": "/foreign", "GOOGLE_APPLICATION_CREDENTIALS": "/foreign/key",
                    "RUBYOPT": "-r/foreign", "RUBYLIB": "/foreign", "GITHUB_ACTIONS": "true",
                    "BUNDLE_PATH": "/foreign", "SSL_CERT_FILE": "/foreign"}, clear=False):
                supplied = context.environment()
                environment = stores._runtime_environment(supplied)
            for name, value in supplied.items():
                self.assertEqual(environment[name], value, name)
            self.assertEqual(environment["PATH"].split(":"),
                             [str(runtime / "store/bin"), "/usr/bin", "/bin", "/usr/sbin", "/sbin"])
            self.assertEqual(environment["HOME"], str(home._path))
            self.assertEqual(environment["TMPDIR"], str(home._path))
            self.assertEqual(environment["BUNDLE_PATH"], str(runtime / "store/bundle"))
            self.assertEqual(environment["SSL_CERT_FILE"], str(runtime / "store/ca.pem"))
            self.assertEqual(environment["GEM_HOME"], str(runtime / "store/lib/ruby/gems/3.3.0"))
            for name in ("RUBYOPT", "RUBYLIB", "GITHUB_ACTIONS", "GOOGLE_APPLICATION_CREDENTIALS"):
                self.assertNotIn(name, environment)
            self.assertEqual(environment["BUNDLE_IGNORE_CONFIG"], "1")
            self.assertEqual(environment["BUNDLE_AUTO_INSTALL"], "false")
            supplied["PATH"] = "/changed-return-value"
            self.assertNotEqual(context.environment()["PATH"], supplied["PATH"])

    def test_context_rejects_wrong_or_closed_owner_and_missing_or_linked_interpreter(self):
        with self.fixture() as (root, config, runtime, invocation):
            with finite_scratch(layout="online-runner", cancellation=invocation.cancellation, parent=root) as home:
                context = StoreRuntimeContext.installed(runtime, invocation=invocation, private_home=home)
                for project, owner in ((root, invocation), (config.root, object())):
                    with self.assertRaises(StoreOperationError):
                        context.require(root=project, invocation=owner)
                ruby = runtime / "store/bin/ruby"
                ruby.unlink()
                with self.assertRaises(StoreOperationError):
                    context.environment()
                ruby.symlink_to(runtime / "store/bin/bundle")
                with self.assertRaises(StoreOperationError):
                    context.environment()
                ruby.unlink()
                ruby.write_bytes(b"still inert"); ruby.chmod(0o755)
                context.require(root=config.root, invocation=invocation)
            self.assertFalse(home._path.exists())
            with self.assertRaises(ValidationError):
                context.environment()

    def test_all_existing_probes_use_selected_tools_environment_and_original_cancellation(self):
        marker = "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2"
        outputs = ("3.3.12", "4.0.16", "", marker, marker)
        with self.fixture() as (root, config, runtime, invocation), finite_scratch(
                layout="online-runner", cancellation=invocation.cancellation, parent=root) as home:
            context = StoreRuntimeContext.installed(runtime, invocation=invocation, private_home=home)
            calls = []

            def probe(argv, **kwargs):
                index = len(calls); calls.append(tuple(argv))
                environment = kwargs["environ"]
                self.assertEqual(environment["PATH"].split(":")[0], str(runtime / "store/bin"))
                self.assertEqual(environment["BUNDLE_GEMFILE"], str(context.tooling_root / "Gemfile"))
                self.assertEqual(environment["SSL_CERT_FILE"], str(runtime / "store/ca.pem"))
                self.assertEqual(environment["GEM_HOME"], context.environment()["GEM_HOME"])
                self.assertEqual(environment["FASTLANE_OPT_OUT_USAGE"], "true")
                self.assertIs(kwargs["cancellation"], invocation.cancellation)
                self.assertEqual((kwargs["cwd"], kwargs["capture"], kwargs["timeout"]),
                                 (context.tooling_root, True, 60))
                return subprocess.CompletedProcess(argv, 0, stdout=outputs[index], stderr="")

            with patch("mobile_release.stores.run_owned", side_effect=probe):
                stores._require_fastlane_bundle(context.tooling_root,
                    cancellation=invocation.cancellation, runtime_context=context)
            self.assertEqual(len(calls), 5)
            self.assertEqual(calls[0], ("ruby", "-e", "print RUBY_VERSION"))
            self.assertEqual(calls[1:3], [("bundle", "--version"), ("bundle", "check")])
            with patch("mobile_release.stores.run_owned") as run:
                with self.assertRaises(StoreOperationError):
                    stores._require_fastlane_bundle(context.tooling_root,
                        cancellation=invocation.cancellation, runtime_context=context, source_environment={})
                run.assert_not_called()

    def test_online_lane_keeps_actual_seal_private_selection_and_no_ambient_outputs(self):
        with self.fixture() as (root, config, runtime, invocation), finite_scratch(
                layout="online-runner", cancellation=invocation.cancellation, parent=root) as home, \
                self.selected(root, config, invocation) as material:
            context = StoreRuntimeContext.installed(runtime, invocation=invocation, private_home=home)
            ambient = root / "foreign-output.json"
            ambient.write_bytes(b"unrelated existing output")
            calls, directories, selected_paths = [], [], []

            def lane(argv, **kwargs):
                calls.append(tuple(argv)); environment = kwargs["environ"]
                self.assertIs(type(kwargs["_evidence"]), CommandCallEvidence)
                self.assertEqual(kwargs["_evidence"]._expected[0], tuple(argv))
                self.assertEqual(dict(kwargs["_evidence"]._expected[2]),
                                 {os.fsencode(k): os.fsencode(v) for k, v in environment.items()})
                self.assertIs(kwargs["cancellation"], invocation.cancellation)
                self.assertEqual((kwargs["capture"], kwargs["timeout"]), (False, 900))
                cwd = Path(kwargs["cwd"]); directories.append(cwd)
                self.assertEqual(cwd.parent, home._path)
                self.assertEqual(environment["HOME"], str(home._path))
                self.assertEqual(environment["BUNDLE_PATH"], str(runtime / "store/bundle"))
                self.assertEqual(environment["SSL_CERT_FILE"], str(runtime / "store/ca.pem"))
                report = Path(environment["MOBILE_RELEASE_PREFLIGHT_READBACK_PATH"])
                self.assertTrue(report.is_relative_to(config.root / ".mobile-release/store"))
                self.assertNotEqual(report, ambient)
                selected_path = Path(environment["GOOGLE_APPLICATION_CREDENTIALS"])
                selected_paths.append(selected_path)
                self.assertNotEqual(selected_path, root / "explicit-account.json")
                self.assertEqual(json.loads(selected_path.read_bytes()), {"type": "service_account", "synthetic": True})
                for name in ("GITHUB_ACTIONS", "RUBYOPT", "RUBYLIB"):
                    self.assertNotIn(name, environment)
                # No fake writer receipt or successful Store authentication.
                return subprocess.CompletedProcess(argv, 1)

            with patch.dict(os.environ, {"MOBILE_RELEASE_PREFLIGHT_READBACK_PATH": str(ambient),
                    "GOOGLE_APPLICATION_CREDENTIALS": "/foreign/adc", "GITHUB_ACTIONS": "true",
                    "TMPDIR": "/missing-ambient-scratch"}, clear=False), patch(
                    "mobile_release.stores.resolve_tooling_root", side_effect=AssertionError("ambient tooling")), patch(
                    "mobile_release.stores._require_fastlane_bundle") as probe, patch(
                    "mobile_release.stores.run_owned", side_effect=lane):
                findings = stores.online_preflight_findings(config=config, release=config.release_version(),
                    platforms=("android",), material=material, invocation=invocation, runtime_context=context)
            probe.assert_called_once_with(context.tooling_root, cancellation=invocation.cancellation,
                                          runtime_context=context)
            self.assertEqual(calls, [("bundle", "exec", "ruby", str(context.tooling_root / "fastlane/run_lane.rb"),
                                     "android_online_preflight")])
            self.assertEqual([item.status for item in findings], [Status.FAIL])
            self.assertEqual(ambient.read_bytes(), b"unrelated existing output")
            self.assertTrue(all(not path.exists() for path in directories))
            self.assertEqual(list(home._path.iterdir()), [])
        self.assertTrue(all(not path.exists() for path in selected_paths))

    def test_fatal_process_facts_survive_existing_arbitration_and_stop_further_probes(self):
        with self.fixture() as (root, config, runtime, invocation), finite_scratch(
                layout="online-runner", cancellation=invocation.cancellation, parent=root) as home:
            context = StoreRuntimeContext.installed(runtime, invocation=invocation, private_home=home)
            failure = ProcessError("synthetic unknown child", dispatched=True, contained=False, cleanup_complete=False)
            with patch("mobile_release.stores.run_owned", side_effect=failure) as run:
                with self.assertRaises(ProcessError) as caught:
                    stores._require_fastlane_bundle(context.tooling_root,
                        cancellation=invocation.cancellation, runtime_context=context)
                # Existing first-primary arbitration deliberately wraps typed
                # fatal errors; their conservative facts must survive intact.
                self.assertEqual((caught.exception.dispatched, caught.exception.contained,
                                  caught.exception.cleanup_complete), (True, False, False))
                self.assertTrue(caught.exception.fatal)
                self.assertEqual(run.call_count, 1)

    def test_private_home_does_not_adopt_or_delete_unregistered_child_output(self):
        # The fixture owns its entire temporary tree; production cleanup must
        # preserve unknown files rather than pretending a broad cache is safe.
        with self.assertRaises(ProcessError) as final:
            with self.fixture() as (root, config, runtime, invocation):
                with self.assertRaises(ProcessError):
                    with finite_scratch(layout="online-runner", cancellation=invocation.cancellation, parent=root) as home:
                        context = StoreRuntimeContext.installed(runtime, invocation=invocation, private_home=home)
                        foreign = context.private_directory / "unexpected-cache"
                        foreign.write_bytes(b"not an enrolled scratch output")
                self.assertEqual(foreign.read_bytes(), b"not an enrolled scratch output")
                # The real invocation must retain fatal cleanup even after a
                # caller catches the inner exception; final exit cannot pass.
                self.assertTrue(invocation.cancellation.lifetime_ledger.fatal)
        self.assertTrue(final.exception.fatal)


if __name__ == "__main__":
    unittest.main()
