"""Inert routing + real bounded public-file readers, never Mac qualification.

The lifetime tests keep the existing run_cases control flow but explicitly fake
the process result, precursor, native report and independent readback. No core
owner, native command, installed path, key, signing or provider is used.
"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).absolute().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "desktop/tools" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


M = load("_identity_current_test", "macos_identity_current_runtime.py")
A = load("_identity_current_aqua_test", "macos_aqua_qualification.py")
STAGE = load("_identity_current_stage_test", "stage_macos_installed.py")
PACKAGE = load("_identity_current_package_test", "macos_android_helper_package.py")
BINDING = A.Binding("a" * 40, "123", "1")


def environment():
    return {
        "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64", "GITHUB_EVENT_NAME": "push",
        "MRK_MACOS_RUNNER": "macos-26", "MRK_MACOS_MACHINE": "arm64",
        "MRK_MACOS_HOSTED_JOB": "github-hosted-macos26-arm64",
        "GITHUB_REPOSITORY": M.REPOSITORY, "GITHUB_REF": M.REF,
        "GITHUB_WORKSPACE": str(M.CHECKOUT), "GITHUB_WORKFLOW_REF": M.WORKFLOW,
        "GITHUB_SHA": BINDING.source, "GITHUB_WORKFLOW_SHA": BINDING.source,
        "MRK_EXPECTED_SHA": BINDING.source, "MRK_MACOS_INSTALL_SOURCE_COMMIT": BINDING.source,
        "GITHUB_RUN_ID": BINDING.run, "GITHUB_RUN_ATTEMPT": BINDING.attempt,
        "MRK_MACOS_NATIVE_SCOPE": M.SCOPE, "MRK_MACOS_PACKAGE_ROLE": M.ROLE,
        "MRK_MACOS_STORE_RUNTIME": "signed-component",
        "MRK_MACOS_WORK": "/Users/runner/work/_temp/mrk-macos-installed.Abc12345",
        "RUSTUP_TOOLCHAIN": "1.98.1", "DEVELOPER_DIR": "/Library/Developer/CommandLineTools",
        "MACOSX_DEPLOYMENT_TARGET": "26.0",
    }


class InertOnly(unittest.TestCase):
    def setUp(self):
        no_process = patch("subprocess.Popen", side_effect=AssertionError("native/process execution forbidden"))
        no_process.start()
        self.addCleanup(no_process.stop)


class CurrentRouteTests(InertOnly):
    def test_two_git_cli_singletons_require_same_closed_combined_image_and_real_host_gate(self):
        env = {**environment(), "MRK_MACOS_NATIVE_SCOPE": M.GIT_SCOPE,
               "MRK_MACOS_RUNNER": "xcode-27", "MRK_MACOS_HOSTED_JOB": "github-hosted-xcode27-arm64"}
        self.assertEqual(M.GIT_CLI_SCOPES, ("git-index-cli-native", "git-branch-cli-native"))
        for scope, case in zip(M.GIT_CLI_SCOPES, ("git-index-cli", "git-branch-cli")):
            with self.subTest(scope=scope):
                args = ["--target", M.TARGET, "--scope", scope]
                self.assertEqual(M.arguments(args), scope)
                self.assertEqual(M.observation_scope(env, scope), scope)
                self.assertEqual(A.selected_cases(scope), (case,))
                self.assertEqual(A.CLI._policy(case), (8, 5, 120, 135) if case == "git-index-cli" else (5, 3, 120, 135))
                code, observed, owner, run, error = self.main_with_host_data(env, "27.0.1", scope)
                self.assertEqual((code, error), (0, ""))
                observed.assert_called_once_with(); owner.assert_called_once_with()
                self.assertEqual(run.call_args.kwargs["scope"], scope)
                self.assertEqual(run.call_args.kwargs["host"], ("xcode-27", "27.0.1"))
                for wrong in (args + ["extra"], args[:-1] + [case], ["--target", A.INTEL_TARGET, *args[2:]]):
                    with self.assertRaises(M.Refused): M.arguments(wrong)
                for native in (M.SCOPE, M.TOOLS_SCOPE, M.FETCH_SCOPE, M.PUSH_SCOPE, scope, "disabled"):
                    with self.subTest(native=native), self.assertRaises(M.Refused):
                        M.observation_scope({**env, "MRK_MACOS_NATIVE_SCOPE": native}, scope)
        for old_tool in (M.SCOPE, M.SERVICE_SCOPE, M.TOOLS_SCOPE, M.CLI_SCOPE, M.PUBLIC_TOOLS_SCOPE):
            with self.subTest(old_tool=old_tool), self.assertRaises(M.Refused):
                M.observation_scope(env, old_tool)

    def test_public_acquisition_is_only_a_closed_tool_image_selector_not_a_new_package_role(self):
        args = ["--target", M.TARGET, "--scope", M.TOOLS_SCOPE, "--tool-cases", "public-acquisition"]
        self.assertEqual(M.arguments(args), M.PUBLIC_TOOLS_SCOPE)
        env = {**environment(), "MRK_MACOS_NATIVE_SCOPE": M.TOOLS_SCOPE}
        self.assertEqual(M.observation_scope(env, M.PUBLIC_TOOLS_SCOPE), M.PUBLIC_TOOLS_SCOPE)
        self.assertEqual(M.package_role(env, "package-install", M.TARGET), M.ROLE)
        for wrong in (["--target", M.TARGET, "--scope", M.PUBLIC_TOOLS_SCOPE], args + ["extra"],
                      ["--target", A.INTEL_TARGET, *args[2:]], args[:-1] + ["all"]):
            with self.subTest(args=wrong), self.assertRaises(M.Refused):
                M.arguments(wrong)
        for native in (M.SCOPE, M.GIT_SCOPE, M.PUBLIC_TOOLS_SCOPE, "disabled"):
            with self.subTest(native=native), self.assertRaises(M.Refused):
                M.observation_scope({**env, "MRK_MACOS_NATIVE_SCOPE": native}, M.PUBLIC_TOOLS_SCOPE)

    def main_with_host_data(self, env, version, scope, *, machine="arm64"):
        # These substituted host observations are DATA only. main, context,
        # _native_user and the before-owner refusal ordering are actual code;
        # no installed owner or Mac native work is invoked.
        import stat
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, env, clear=True))
            stack.enter_context(patch.object(sys, "argv", ["entry", "--target", M.TARGET, "--scope", scope]))
            stack.enter_context(patch.object(M, "__file__", str(M.CHECKOUT / "desktop/tools/macos_identity_current_runtime.py")))
            stack.enter_context(patch.object(M.Path, "cwd", return_value=M.CHECKOUT))
            stack.enter_context(patch("platform.machine", return_value=machine))
            observed = stack.enter_context(patch("platform.mac_ver", return_value=(version, (), "arm64")))
            stack.enter_context(patch("pwd.getpwuid", return_value=SimpleNamespace(pw_name="runner")))
            for name, value in (("getuid", 501), ("geteuid", 501), ("getgid", 20), ("getegid", 20)):
                stack.enter_context(patch.object(M.os, name, return_value=value))
            stack.enter_context(patch.object(M.os, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFCHR, st_uid=501)))
            stack.enter_context(patch.object(M.os, "umask"))
            stack.enter_context(patch.object(M.sys, "platform", "darwin"))
            stack.enter_context(patch.object(M.sys, "flags", SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1)))
            owner = stack.enter_context(patch.object(M, "_load_observer", return_value=SimpleNamespace(Binding=A.Binding)))
            run = stack.enter_context(patch.object(M, "_run", return_value=0))
            error = stack.enter_context(redirect_stderr(io.StringIO()))
            result = M.main()
        return result, observed, owner, run, error.getvalue()

    def test_selected_mac27_uses_existing_four_driver_scopes_after_one_checked_host_observation(self):
        env27 = {**environment(), "MRK_MACOS_NATIVE_SCOPE": M.GIT_SCOPE,
                 "MRK_MACOS_RUNNER": "xcode-27", "MRK_MACOS_HOSTED_JOB": "github-hosted-xcode27-arm64"}
        env, version = env27, "27.0.1"
        for scope in (M.FETCH_SCOPE, M.PUSH_SCOPE, M.PUSH_CREATE_SCOPE, M.UPSTREAM_SCOPE):
            with self.subTest(version=version, scope=scope):
                self.assertEqual(M.current_context(env, M.TARGET)[0], BINDING.source)
                for phase in M.PACKAGE_PHASES + M.DATA_PHASES:
                    self.assertEqual(M.package_role(env, phase, M.TARGET), M.ROLE)
                result, observed, owner, run, error = self.main_with_host_data(env, version, scope)
                self.assertEqual((result, error), (0, ""))
                observed.assert_called_once_with()
                owner.assert_called_once_with()
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.kwargs["host"], (env["MRK_MACOS_RUNNER"], version))
                self.assertEqual(run.call_args.kwargs["scope"], scope)

    def test_old_host_stays_admitted_and_wrong_or_missing_profile_refuses_before_owner(self):
        result, observed, owner, run, error = self.main_with_host_data(environment(), "26.0.1", M.SCOPE)
        self.assertEqual((result, error), (0, ""))
        observed.assert_called_once_with()
        owner.assert_called_once_with()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs["host"], ("macos-26", "26.0.1"))
        env27 = {**environment(), "MRK_MACOS_NATIVE_SCOPE": M.GIT_SCOPE,
                 "MRK_MACOS_RUNNER": "xcode-27", "MRK_MACOS_HOSTED_JOB": "github-hosted-xcode27-arm64"}
        rejected = [(env27, "26.0.1", M.FETCH_SCOPE),
                    ({**environment(), "MRK_MACOS_NATIVE_SCOPE": M.GIT_SCOPE}, "27.0.1", M.FETCH_SCOPE)]
        for scope, request in ((M.SCOPE, M.SCOPE), (M.TOOLS_SCOPE, M.SCOPE),
                               (M.FETCH_SCOPE, M.FETCH_SCOPE), (M.PUSH_SCOPE, M.PUSH_SCOPE)):
            rejected.append(({**env27, "MRK_MACOS_NATIVE_SCOPE": scope}, "27.0.1", request))
        for key, value in (("MRK_MACOS_RUNNER", "macos-latest"), ("MRK_MACOS_RUNNER", "xcode-27-xlarge"),
                           ("MRK_MACOS_HOSTED_JOB", "github-hosted-macos26-arm64"),
                           ("MRK_MACOS_MACHINE", "x86_64"), ("RUNNER_ARCH", "X64"),
                           ("MRK_MACOS_PACKAGE_ROLE", "ordinary-image"), ("GITHUB_REF", "refs/heads/main")):
            rejected.append(({**env27, key: value}, "27.0.1", M.FETCH_SCOPE))
        for key in ("MRK_MACOS_RUNNER", "MRK_MACOS_MACHINE", "MRK_MACOS_HOSTED_JOB"):
            absent = dict(env27); absent.pop(key)
            rejected.append((absent, "27.0.1", M.FETCH_SCOPE))
        for version in ("28.0.1", "027.0.1", "27.0.1\n", "27.0.1\u2028", "27.0.1extra", "27." + "0" * 32):
            rejected.append((env27, version, M.FETCH_SCOPE))
        for env, version, scope in rejected:
            with self.subTest(env=env, version=version, scope=scope):
                result, _observed, owner, run, error = self.main_with_host_data(env, version, scope)
                self.assertEqual(result, 1)
                self.assertEqual(json.loads(error)["reason"], "entry-refused")
                owner.assert_not_called(); run.assert_not_called()
        result, _, owner, run, _ = self.main_with_host_data(env27, "27.0.1", M.FETCH_SCOPE, machine="x86_64")
        self.assertEqual(result, 1)
        owner.assert_not_called(); run.assert_not_called()

    def test_only_explicit_current_arm_scope_and_fixed_preparation_phases(self):
        env = environment()
        for phase in M.PACKAGE_PHASES + M.DATA_PHASES:
            self.assertEqual(M.package_role(env, phase, M.TARGET), M.ROLE)
        for phase in (None, "finalize-image", "sign-desktop-image", "sign-store-runtime", "sign-applications-launcher", "run", "xcode-setup-verify"):
            with self.subTest(phase=phase), self.assertRaises(M.Refused):
                M.package_role(env, phase, M.TARGET)
        for key, value in (("MRK_MACOS_NATIVE_SCOPE", "all"), ("MRK_MACOS_NATIVE_SCOPE", ""),
                           ("GITHUB_REF", "refs/heads/verify/desktop-macos-aqua"),
                           ("MRK_MACOS_PACKAGE_ROLE", "ordinary-image")):
            with self.subTest(key=key, value=value), self.assertRaises(M.Refused):
                M.package_role({**env, key: value}, "package-install", M.TARGET)
        with self.assertRaises(M.Refused):
            M.package_role(env, "prepare", A.INTEL_TARGET)
        for value in (None, "disabled"):
            ordinary = {**env, "MRK_MACOS_PACKAGE_ROLE": "ordinary-image"}
            if value is None:
                ordinary.pop("MRK_MACOS_NATIVE_SCOPE")
            else:
                ordinary["MRK_MACOS_NATIVE_SCOPE"] = value
            self.assertIsNone(M.package_role(ordinary, "any-original-decision", A.INTEL_TARGET))

    def test_current_context_has_no_ref_source_supplier_or_prepared_fallback(self):
        env = environment()
        self.assertEqual(M.current_context(env, M.TARGET),
                         (BINDING.source, BINDING.run, BINDING.attempt, Path(env["MRK_MACOS_WORK"])))
        for key, value in (("GITHUB_WORKFLOW_SHA", "b" * 40), ("GITHUB_SHA", "0" * 40),
                           ("MRK_MACOS_INSTALL_SOURCE_COMMIT", "b" * 40),
                           ("GITHUB_RUN_ATTEMPT", "0"), ("GITHUB_EVENT_NAME", "workflow_dispatch"),
                           ("MRK_MACOS_STORE_RUNTIME", "historical"), ("MRK_MACOS_AQUA_SCOPE", M.SCOPE),
                           ("MRK_MACOS_WORK", env["MRK_MACOS_WORK"] + "/../other")):
            with self.subTest(key=key), self.assertRaises(M.Refused):
                M.current_context({**env, key: value}, M.TARGET)

    def test_actual_package_hooks_keep_default_role_and_validate_native_and_data_routes(self):
        # DATA-only host observations, not Darwin, signatures or a native entry.
        with ExitStack() as stack:
            for name, value in (("getuid", 501), ("geteuid", 501), ("getgid", 20), ("getegid", 20)):
                stack.enter_context(patch.object(PACKAGE.os, name, return_value=value))
            stack.enter_context(patch.object(PACKAGE.os, "uname", return_value=SimpleNamespace(machine="arm64")))
            stack.enter_context(patch.object(PACKAGE.sys, "platform", "darwin"))
            stack.enter_context(patch.object(PACKAGE, "__file__", str(PACKAGE.CHECKOUT / "desktop/tools/macos_android_helper_package.py")))
            loader = stack.enter_context(patch.object(PACKAGE, "load_data", return_value=M))
            ordinary = {**environment(), "MRK_MACOS_NATIVE_SCOPE": "disabled", "MRK_MACOS_PACKAGE_ROLE": "ordinary-image"}
            self.assertEqual(PACKAGE.admit(ordinary, phase="prepare"), Path(ordinary["MRK_MACOS_WORK"]))
            PACKAGE.tool_data_context(ordinary, M.DATA_PHASES[0], M.TARGET)
            loader.assert_not_called()
            self.assertEqual(PACKAGE.admit(environment(), phase="prepare"), Path(ordinary["MRK_MACOS_WORK"]))
            self.assertEqual(loader.call_args.args[1], "macos_identity_current_runtime.py")
            PACKAGE.tool_data_context(environment(), M.DATA_PHASES[0], M.TARGET)
            env27 = {**environment(), "MRK_MACOS_NATIVE_SCOPE": M.GIT_SCOPE,
                     "MRK_MACOS_RUNNER": "xcode-27", "MRK_MACOS_HOSTED_JOB": "github-hosted-xcode27-arm64"}
            self.assertEqual(PACKAGE.admit(env27, phase="prepare"), Path(ordinary["MRK_MACOS_WORK"]))
            PACKAGE.tool_data_context(env27, M.DATA_PHASES[0], M.TARGET)
            for method in (lambda env: PACKAGE.admit(env, phase="prepare"),
                           lambda env: PACKAGE.tool_data_context(env, M.DATA_PHASES[0], M.TARGET)):
                with self.assertRaises(M.Refused):
                    method({**env27, "MRK_MACOS_NATIVE_SCOPE": M.TOOLS_SCOPE})
                with self.assertRaises(M.Refused):
                    method({**environment(), "MRK_MACOS_NATIVE_SCOPE": "unknown"})
                with self.assertRaises(PACKAGE.Refused):
                    method({**environment(), "GITHUB_WORKFLOW_SHA": "b" * 40})
            with self.assertRaises(M.Refused):
                PACKAGE.admit(environment(), phase="finalize-image")

    def test_rejected_entry_never_imports_or_prepares_an_original_owner(self):
        with patch.dict(os.environ, {**environment(), "GITHUB_REF": "refs/heads/other"}, clear=True), \
             patch.object(sys, "argv", ["entry", "--target", M.TARGET]), \
             patch.object(M, "_native_user") as native, patch.object(M, "_load_observer") as owner, \
             redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(M.main(), 1)
        native.assert_not_called()
        owner.assert_not_called()
        self.assertEqual(json.loads(stderr.getvalue())["reason"], "entry-refused")

    def test_one_tool_package_permits_only_existing_three_explicit_invocations(self):
        env = {**environment(), "MRK_MACOS_NATIVE_SCOPE": M.TOOLS_SCOPE}
        self.assertEqual(M.current_context(env, M.TARGET)[0], BINDING.source)
        for scope in (M.SCOPE, M.SERVICE_SCOPE, M.TOOLS_SCOPE):
            self.assertEqual(M.observation_scope(env, scope), scope)
            self.assertEqual(M.arguments(["--target", M.TARGET, "--scope", scope]), scope)
        self.assertEqual(M.arguments(["--target", M.TARGET]), M.SCOPE)
        for scope in (M.SERVICE_SCOPE, M.TOOLS_SCOPE, "all", "../other", "tool-setup-missing-sdk"):
            with self.subTest(scope=scope), self.assertRaises(M.Refused):
                M.observation_scope(environment(), scope)
        with self.assertRaises(M.Refused):
            M.package_role({**env, "MRK_MACOS_NATIVE_SCOPE": M.SERVICE_SCOPE}, "prepare", M.TARGET)
        for args in (["--scope", M.TOOLS_SCOPE], ["--target", M.TARGET, "--scope", "all"],
                     ["--target", A.INTEL_TARGET, "--scope", M.TOOLS_SCOPE]):
            with self.assertRaises(M.Refused):
                M.arguments(args)


class CurrentBindingFilesTests(InertOnly):
    def setUp(self):
        super().setUp()
        self.temp = tempfile.TemporaryDirectory(prefix="mrk-identity-current-data-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.checkout, self.work = self.root / "checkout", self.root / "work"
        for name in ("checkout", "work", "installed", "checkout/.git", "checkout/desktop",
                     "checkout/desktop/macos-installed-inputs", "checkout/desktop/packaging"):
            (self.root / name).mkdir(mode=0o700)
        self.fixtures = A.Fixtures(BINDING, os.getuid(), os.getgid(), M.SCOPE)
        self.addCleanup(self.fixtures.close)
        self.admissions = []
        # Only the installed-owner/platform seam is inert; every new reader and
        # selected/composed binding parser below is the actual implementation.
        self.fixtures.admit_normal_account_runtime = lambda *args, **kw: self.admissions.append((args, kw))
        self.fixtures.recovery_runtime_paths = lambda: ("INERT", "INERT")
        self.fixtures.normal_stager_registrations = [STAGE]
        self.put(self.checkout / ".git/HEAD", (BINDING.source + "\n").encode())
        manifest = b"INERT installed manifest bytes; no installed/native authority\n"
        self.put(self.root / "installed/manifest.json", manifest)
        parent = self.fixtures._open(str(self.root / "installed"), directory=True)
        fd = self.fixtures._open("manifest.json", parent)
        self.manifest_fd = fd
        self.fixtures.recovery_runtime_originals = [(parent, "manifest.json", fd, A.signature(os.fstat(fd)))]
        producer = ("schema=1\nstate=configured\nteam-identifier=TESTTEAM01\nrsa-bits=2048\n"
                    + "leaf-certificate-sha1=" + "1" * 40 + "\nleaf-certificate-sha256=" + "2" * 64
                    + "\nissuer-certificate-sha256=" + "3" * 64 + "\nroot-certificate-sha256=" + "4" * 64
                    + "\npublic-key-pkcs1-sha256=" + "5" * 64 + "\n").encode()
        service = ("schema=1\napp-identifier=" + STAGE.BUNDLE_ID + "\nhelper-identifier=" + STAGE.ANDROID_SERVICE_LABEL
                   + "\nteam-identifier=TESTTEAM01\ndeveloper-id-certificate-sha1=" + "1" * 40 + "\n").encode()
        for name, body in (("macos-install-producer-signing.profile", producer),
                           ("macos-android-service-signing.profile", service)):
            self.put(self.checkout / "desktop/packaging" / name, body)
        python = dict(state="configured", signedPythonSha256="6" * 64, signingReceiptSha256="7" * 64,
            sourceInputsSha256="8" * 64, runtimeManifestSha256="9" * 64,
            producerProfileSha256=STAGE.digest(producer), serviceProfileSha256=STAGE.digest(service),
            signingSourceCommit="b" * 40, signingRunId="234", signingRunAttempt="1", signingArtifactId="567")
        self.put(self.checkout / "desktop" / STAGE.SIGNED_RUNTIME_BINDING, STAGE.canonical({"schemaVersion": 1,
            "targets": {M.TARGET: python, A.INTEL_TARGET: {"state": "unconfigured"}}}))
        store = dict(schemaVersion=1, state="configured", source="c" * 40, runId="345", runAttempt="1",
                     artifacts={M.TARGET: "678", A.INTEL_TARGET: "679"})
        store_body = STAGE.canonical(store)
        self.put(self.checkout / "desktop" / STAGE.SIGNED_STORE_SELECTION, store_body)
        store = dict(STAGE.signed_store_selection_data(store_body), receiptSha256="a" * 64,
                     archiveSha256="b" * 64, artifactDigest="sha256:" + "c" * 64)
        self.runtime = dict(schemaVersion=1, kind="current-signed-store-runtime", target=M.TARGET,
            sourceInputsSha256="d" * 64, runtimeManifestSha256=STAGE.digest(manifest), store=store,
            python={key: value for key, value in python.items() if key not in ("state", "sourceInputsSha256", "runtimeManifestSha256")})
        self.env = environment()
        info = self.work.stat()
        self.source = dict(source=BINDING.source, workflowSource=BINDING.source, runId=BINDING.run,
            runAttempt=BINDING.attempt, target=M.TARGET, packageRole=M.ROLE,
            workDirectory=[info.st_dev, info.st_ino, info.st_uid])
        self.bind()

    def put(self, path, body):
        path.write_bytes(body)
        path.chmod(0o600)

    def bind(self):
        body = STAGE.canonical(self.runtime)
        self.source.update(runtimeBindingSha256=STAGE.digest(body),
            runtimeManifestSha256=self.runtime["runtimeManifestSha256"],
            runtimeSourceInputsSha256=self.runtime["sourceInputsSha256"], signedStoreDerivation=self.runtime["store"])
        self.env.update(MRK_MACOS_RUNTIME_BINDING_SHA256=STAGE.digest(body),
            MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=self.runtime["runtimeManifestSha256"],
            MRK_BUNDLED_RUNTIME_SOURCE_SHA256=self.runtime["sourceInputsSha256"])
        self.put(self.work / "runtime-binding.json", body)
        self.put(self.work / "source-binding.json", STAGE.canonical(self.source))

    def admit(self):
        with patch.object(M, "CHECKOUT", self.checkout):
            M._admit_runtime(A, self.fixtures, BINDING, self.work, self.env)

    def test_real_readers_join_computed_m_to_same_manifest_fd_not_legacy_nomination(self):
        self.admit()
        self.assertEqual(self.admissions, [((self.checkout, self.work), {"application_source": BINDING.source})])
        records = [row for row in self.fixtures.gate_files if row["name"] == "manifest.json"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["fd"], self.manifest_fd)
        self.assertEqual(records[0]["sha256"], self.runtime["runtimeManifestSha256"])
        M._current(A, self.fixtures)
        self.fixtures.close()
        self.assertFalse(self.fixtures.fds)

    def test_self_consistent_but_different_manifest_is_not_installed_authority(self):
        self.runtime["runtimeManifestSha256"] = "e" * 64
        self.bind()
        with self.assertRaisesRegex(A.Refused, "identity-native-current-manifest"):
            self.admit()

    def test_different_source_work_or_ordinary_role_refuses(self):
        for key, wrong in (("source", "b" * 40), ("workDirectory", [1, 2, 3]), ("packageRole", "ordinary-image")):
            original = self.source[key]
            self.source[key] = wrong
            self.bind()
            with self.subTest(key=key), self.assertRaises((A.Refused, STAGE.Refused)):
                self.admit()
            self.source[key] = original

    def test_post_case_binding_replacement_preserves_foreign_file_and_refuses(self):
        self.admit()
        path = self.work / "source-binding.json"
        body = path.read_bytes()
        replacement = self.work / "replacement"
        self.put(replacement, body)
        replacement.replace(path)
        with self.assertRaises(A.Refused):
            M._current(A, self.fixtures)
        self.assertEqual(path.read_bytes(), body)

    def test_source_binding_bound_is_before_parse(self):
        self.put(self.work / "source-binding.json", b"x" * 65537)
        with patch.object(STAGE, "composed_source_binding_data", side_effect=AssertionError("oversize parsed")), \
             self.assertRaisesRegex(A.Refused, "gate-original-file"):
            self.admit()


class OriginalCallFlowTests(InertOnly):
    def execute(self, *, failure=None, close_failure=None, admission_failure=None, run_cases=None, scope=M.SCOPE, not_ready=False):
        events, errors = [], []
        fixtures = A.Fixtures(BINDING, 501, 20, scope)
        def prepare():
            events.append("prepare")
            if scope in (M.TOOLS_SCOPE, M.SERVICE_SCOPE, M.PUBLIC_TOOLS_SCOPE):
                # Inert comparison only, never native pwd or a created fixture.
                fixtures.path = A.TOOLS.fixture_path(BINDING, "/Users/runner", service=scope == M.SERVICE_SCOPE,
                    public_acquisition=scope == M.PUBLIC_TOOLS_SCOPE, need=A.need)
        fixtures.prepare = prepare
        fixtures.recovery_runtime_paths = lambda: events.append("runtime-post")
        fixtures.before_call = lambda case: (events.append(("before", case)), setattr(fixtures, "case", case))

        def close():
            events.append("close")
            if close_failure:
                raise close_failure

        fixtures.close = close

        def admit(*args):
            events.append("admit-current-runtime")
            if admission_failure:
                raise admission_failure

        def original(argv, **options):
            self.assertTrue(fixtures.inflight)
            self.assertIn("admit-current-runtime", events)
            self.assertEqual(argv, [A.EXECUTABLE, fixtures.case])
            self.assertEqual(options["timeout"], A.case_timeout(fixtures.case))
            self.assertEqual(options["environ"], A.app_environment(options["cwd"], 501, "runner"))
            events.append(("original-inert-call", fixtures.case))
            if failure:
                raise failure
            return subprocess.CompletedProcess(argv, 0, b"INERT REPORT", b"")

        def readback(_fixtures, case, report, *extra):
            self.assertFalse(fixtures.inflight)
            self.assertTrue(fixtures.last_returned)
            events.append(("inert-readback", case))
            return {"inertOnly": True}

        def diagnose(error, owner, current):
            errors.append(error)
            return {"inertOnly": True, "unknown": current.inflight}

        owner = SimpleNamespace(run_owned=original)
        with ExitStack() as stack:
            stack.enter_context(patch.object(A, "Fixtures", return_value=fixtures))
            stack.enter_context(patch.object(M, "_admit_runtime", side_effect=admit))
            owner_load = stack.enter_context(patch.object(A, "load_owner", return_value=owner))
            stack.enter_context(patch.object(A.identity_qualification, "before_invocation", return_value=None))
            stack.enter_context(patch.object(A.identity_qualification, "readback", side_effect=readback))
            stack.enter_context(patch.object(A.TOOLS, "readback", side_effect=readback))
            stack.enter_context(patch.object(A.TOOLS, "service_readback", side_effect=readback))
            if scope == M.PUBLIC_TOOLS_SCOPE:
                # Routing-only stub. The separate CLI tests use the real Calls
                # and thread; neither fixture manufactures native authority.
                stack.enter_context(patch.object(A.CLI, "invoke", side_effect=lambda f, call, argv, env, state:
                    call(argv, environ=env, cwd=state, timeout=A.case_timeout(argv[1]))))
            parsed = {"projectIdentity": {"inertOnly": True}} if scope == M.SCOPE else {"toolSetup": {
                "execution": "not-executed-prerequisite" if not_ready else "ready",
                "testResult": "not-executed" if not_ready else "INERT ONLY"}}
            if scope == M.PUBLIC_TOOLS_SCOPE:
                stack.enter_context(patch.object(A, "parse_result", side_effect=lambda raw, stderr, binding, case:
                    {"toolSetup": {"execution": "not-executed-prerequisite" if not_ready and case == A.PUBLIC_TOOLS.COLD else "executed",
                                   "testResult": "not-executed" if not_ready and case == A.PUBLIC_TOOLS.COLD else "INERT ONLY"}}))
            else:
                stack.enter_context(patch.object(A, "parse_result", return_value=parsed))
            stack.enter_context(patch.object(A, "diagnostic", side_effect=diagnose))
            if run_cases:
                stack.enter_context(patch.object(A, "run_cases", side_effect=run_cases))
            out, err = io.StringIO(), io.StringIO()
            stack.enter_context(redirect_stdout(out)); stack.enter_context(redirect_stderr(err))
            env = environment()
            if scope != M.SCOPE:
                env["MRK_MACOS_NATIVE_SCOPE"] = M.TOOLS_SCOPE
            status = M._run(A, BINDING, 501, 20, "runner", Path(env["MRK_MACOS_WORK"]), env, scope=scope)
        return status, events, [json.loads(line) for line in out.getvalue().splitlines()], errors, fixtures, owner_load

    def test_same_run_cases_dispatches_exact_four_after_admission_and_close_precedes_complete(self):
        status, events, rows, errors, fixtures, _ = self.execute()
        self.assertEqual(status, 0)
        self.assertEqual(errors, [])
        self.assertEqual([row[1] for row in events if type(row) is tuple and row[0] == "original-inert-call"], list(A.identity_qualification.CASES))
        self.assertEqual(events[:2], ["prepare", "admit-current-runtime"])
        self.assertEqual(events[-1], "close")
        self.assertEqual([row["case"] for row in rows[:-1]], list(A.identity_qualification.CASES))
        self.assertEqual(rows[-1]["type"], "macos-identity-current-complete")
        self.assertFalse(rows[-1]["shippingBinaryQualified"])
        self.assertFalse(rows[-1]["processLossEvidence"])
        self.assertFalse(fixtures.inflight)

    def test_unreturned_original_stops_later_calls_readbacks_and_close(self):
        first = RuntimeError("INERT pending original")
        status, events, rows, errors, fixtures, _ = self.execute(failure=first)
        self.assertEqual(status, 1)
        self.assertTrue(fixtures.inflight)
        self.assertEqual(errors, [first])
        self.assertEqual(rows, [])
        self.assertNotIn("close", events)
        self.assertEqual(len([row for row in events if type(row) is tuple and row[0] == "original-inert-call"]), 1)
        self.assertFalse(any(type(row) is tuple and row[0] == "inert-readback" for row in events))

    def test_current_runtime_refusal_does_not_load_owner_and_close_cannot_mask_it(self):
        first = RuntimeError("INERT runtime refusal")
        status, events, rows, errors, _, owner = self.execute(admission_failure=first, close_failure=OSError("INERT close"))
        self.assertEqual(status, 1)
        owner.assert_not_called()
        self.assertEqual(errors, [first])
        self.assertEqual(events, ["prepare", "admit-current-runtime", "close"])
        self.assertEqual(rows, [])

    def test_missing_reordered_or_close_failed_observations_never_emit_complete(self):
        def reordered(binding, fixtures, owner, uid, username, emit, scope):
            emit({"case": A.identity_qualification.CASES[1]})
            return ()
        for kwargs in ({"run_cases": lambda *args, **kw: ()}, {"run_cases": reordered},
                       {"close_failure": OSError("INERT close failure")}):
            with self.subTest(kind=next(iter(kwargs))):
                status, events, rows, errors, _, _ = self.execute(**kwargs)
                self.assertEqual(status, 1)
                self.assertTrue(errors)
                self.assertIn("close", events)
                self.assertFalse(any(row.get("type") == "macos-identity-current-complete" for row in rows))

    def test_same_driver_uses_one_service_case_and_existing_tool_run_order(self):
        for scope, cases, kind in ((M.SERVICE_SCOPE, A.TOOLS.SERVICE_CASES, "macos-tool-service-current-complete"),
                                   (M.TOOLS_SCOPE, A.TOOLS.RUN_ORDER, "macos-tool-setup-current-complete")):
            with self.subTest(scope=scope):
                status, events, rows, errors, fixtures, _ = self.execute(scope=scope)
                self.assertEqual(status, 0)
                self.assertEqual(errors, [])
                self.assertEqual([e[1] for e in events if type(e) is tuple and e[0] == "original-inert-call"], list(cases))
                self.assertEqual(events[-1], "close")
                self.assertEqual(rows[-1]["type"], kind)
                self.assertFalse(rows[-1]["shippingBinaryQualified"])
                self.assertFalse(fixtures.inflight)

    def test_known_unexecuted_service_never_counts_as_pass_or_starts_tool_cases(self):
        status, events, rows, errors, fixtures, _ = self.execute(scope=M.SERVICE_SCOPE, not_ready=True)
        self.assertEqual(status, 78)
        self.assertEqual(errors, [])
        self.assertEqual(events[-1], "close")
        self.assertEqual([e[1] for e in events if type(e) is tuple and e[0] == "original-inert-call"], list(A.TOOLS.SERVICE_CASES))
        self.assertEqual(rows[-1]["type"], "macos-tool-current-unexecuted")
        self.assertEqual(rows[-1]["notExecuted"], list(A.TOOLS.SERVICE_CASES))
        self.assertFalse(fixtures.inflight)

    def test_lost_service_original_is_not_known_nonentry_or_retry(self):
        first = RuntimeError("INERT lost admitted service")
        status, events, rows, errors, fixtures, _ = self.execute(scope=M.SERVICE_SCOPE, failure=first)
        self.assertEqual(status, 1)
        self.assertEqual(errors, [first])
        self.assertEqual(rows, [])
        self.assertTrue(fixtures.inflight)
        self.assertNotIn("close", events)
        self.assertEqual(len([e for e in events if type(e) is tuple and e[0] == "original-inert-call"]), 1)

    def test_public_pair_same_driver_close_order_and_cold_prerequisite_do_not_hide_cli_failure(self):
        for missing in (False, True):
            status, events, rows, errors, fixtures, _ = self.execute(scope=M.PUBLIC_TOOLS_SCOPE, not_ready=missing)
            self.assertEqual(status, 78 if missing else 0)
            self.assertEqual(errors, [])
            self.assertEqual([e[1] for e in events if type(e) is tuple and e[0] == "original-inert-call"], list(A.PUBLIC_TOOLS.CASES))
            self.assertEqual(events[-1], "close")
            self.assertFalse(fixtures.inflight)
            self.assertEqual(rows[-1]["type"], "macos-tool-current-unexecuted" if missing else "macos-tool-public-acquisition-current-complete")
            if missing:
                self.assertEqual(rows[-1]["notExecuted"], [A.PUBLIC_TOOLS.COLD])
        first = RuntimeError("inert CLI/app original did not return")
        status, events, rows, errors, fixtures, _ = self.execute(scope=M.PUBLIC_TOOLS_SCOPE, failure=first)
        self.assertEqual((status, rows, errors), (1, [], [first]))
        self.assertTrue(fixtures.inflight)
        self.assertNotIn("close", events)
        self.assertEqual([e[1] for e in events if type(e) is tuple and e[0] == "original-inert-call"], [A.PUBLIC_TOOLS.CANCEL])


if __name__ == "__main__":
    unittest.main()
