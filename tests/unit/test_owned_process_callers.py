"""Exercise real descendant lifetime through every synchronous preflight caller."""
from __future__ import annotations

import json
import os
import plistlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import mobile_release
from mobile_release import android, credentials, discovery, ios, local_signing as signing
from mobile_release import preflight as preflight_module
from mobile_release import owned_process as owned
from mobile_release import _command_process as command
from mobile_release.credentials import _run_private
from mobile_release.ios import _run_checked
from mobile_release.owned_process import ProcessError, run_owned
from mobile_release.config import load_config
from mobile_release.errors import ValidationError
from .helpers import ios_config, android_config, write_project
from .ios_entitlement_helpers import profile
from .local_signing_helpers import NativeSigningModel, fictional_signing_profile
from .test_owned_process import original_command_outcomes, all_original_commands_final


@contextmanager
def bounded_commands(mode, heartbeat=None):
    """Real common deadline; never advance cleanup's clock past its endpoint."""
    check = command._Context.check
    issued = []
    def checked(context):
        if (mode == "cancel" and context.role == "O" and heartbeat is not None
                and heartbeat.is_file() and not issued):
            issued.append(True)
            os.kill(os.getpid(), signal.SIGINT)
        return check(context)
    with original_command_outcomes() as outcomes:
        original = command.run_command
        def run(*args, **kwargs):
            kwargs["timeout"] = min(kwargs["timeout"], 4 if mode == "timeout" else 15)
            return original(*args, **kwargs)
        with patch.object(command, "run_command", new=run), patch.object(command._Context, "check", new=checked):
            yield outcomes


@contextmanager
def settled_native_fixture(prefix):
    """Preserve failed/UNKNOWN account and command fixtures for the case owner."""
    root = Path(tempfile.mkdtemp(prefix=prefix)).resolve()
    with original_command_outcomes() as outcomes:
        try:
            yield root
        except BaseException as error:
            if hasattr(error, "add_note"):
                error.add_note(f"preserving native fixture {root}")
            raise
        else:
            if not all_original_commands_final(outcomes):
                raise AssertionError(f"original finality unconfirmed; preserving native fixture {root}")
            shutil.rmtree(root)


class OwnedCallerTests(unittest.TestCase):
    def run_case(self, caller, mode):
        name = tempfile.mkdtemp(prefix="mrk-caller-lifetime-")
        root=Path(name); bin_dir=root/'bin';bin_dir.mkdir()
        ready, heartbeat, stop = (root/name for name in ('ready','heartbeat','stop'))
        code=(f'import os,time;from pathlib import Path;Path({str(ready)!r}).write_text(str(os.getpid()));'
              f'\nend=time.monotonic()+12\nwhile not Path({str(stop)!r}).exists() and time.monotonic()<end: Path({str(heartbeat)!r}).write_text(str(time.monotonic()));time.sleep(.01)')
        child=[sys.executable,'-I','-S','-B','-c',code]
        client=(f'import subprocess,sys,time;from pathlib import Path;subprocess.Popen({child!r},stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);'
                f'\nwhile not Path({str(ready)!r}).exists(): time.sleep(.01)\n'
                + ('time.sleep(30)' if mode=='timeout' else f'sys.exit({7 if mode=="failure" else 0})'))
        executable=bin_dir/'xcodebuild';executable.write_text('#!'+sys.executable+'\n'+client);executable.chmod(0o700)
        # Consumer configuration deliberately rejects shell/control bytes.
        # Invoke the real on-disk client, not a multiline -c argument that
        # is invalid before the process-lifetime boundary is reached.
        args=[sys.executable,'-I','-S','-B',str(executable)]
        env={'PATH':str(bin_dir)+':/usr/bin:/bin', 'HOME':str(root), 'LC_ALL':'C'}
        def bounded(argv, **kwargs):
            kwargs['timeout']=15
            return run_owned(argv, **kwargs)
        outcomes = []
        try:
            with patch.dict(os.environ,env,clear=True),patch.object(preflight_module,'run_owned',side_effect=bounded), \
                 bounded_commands(mode, heartbeat) as outcomes:
                if caller=='private':
                    try: result=_run_private(args,environ=env,timeout=15)
                    except ProcessError: self.assertEqual(mode,'timeout')
                    else: self.assertEqual(result.returncode,7 if mode=='failure' else 0)
                elif caller=='ios-build':
                    if mode=='success': _run_checked(args,root,15)
                    else:
                        from mobile_release.errors import ValidationError
                        with self.assertRaises(ValidationError): _run_checked(args,root,15)
                elif caller=='xcode-version':
                    with patch.object(preflight_module, "sys", SimpleNamespace(platform="darwin")):
                        preflight_module._xcode_toolchain_finding()
                elif caller=='xcode-identities':
                    config=load_config(write_project(root/'project',ios_config(),platform='ios'))
                    preflight_module._xcode_application_identities(config,configuration='Debug')
                elif caller=='ios-first-prepare':
                    value=ios_config();value['ios']['prepareCommand']=args
                    config=load_config(write_project(root/'project',value,platform='ios'))
                    # The actual first prepare uses the owned runner. Suppress
                    # only subsequent identity queries to isolate this client.
                    with patch.object(preflight_module, "sys", SimpleNamespace(platform="darwin")),patch.object(preflight_module,'_xcode_application_identities',return_value=(set(),'fixture-stop')):
                        preflight_module._effective_ios_identity_finding(config)
                elif caller=='gradle-identity':
                    config=load_config(write_project(root/'project',android_config()))
                    wrapper=config.root/'gradlew';wrapper.write_text('#!'+sys.executable+'\n'+client);wrapper.chmod(0o700)
                    preflight_module._effective_android_identity_finding(config)
                elif caller=='project-check':
                    value=android_config();value['projectChecks']['preflight']=[args]
                    config=load_config(write_project(root/'project',value))
                    preflight_module.run_project_checks(config,'preflight',environ=env)
                else: self.fail('unknown caller')
            self.assertTrue(ready.is_file(),'real descendant never acknowledged startup')
            before=heartbeat.read_text();time.sleep(.03)
            self.assertEqual(heartbeat.read_text(),before)
            self.assertTrue(all_original_commands_final(outcomes))
        finally:
            stop.touch()  # Cooperative fixture only; not a PID/group route.
            if all_original_commands_final(outcomes):
                shutil.rmtree(root)
            else:
                raise AssertionError(f"original command finality unconfirmed; preserving {root}")

    def test_every_entry_reaps_started_descendants_on_success_nonzero_and_timeout(self):
        for caller in ('private','ios-build','xcode-version','xcode-identities','ios-first-prepare','gradle-identity','project-check'):
            for mode in ('success','failure','timeout'):
                with self.subTest(caller=caller,mode=mode): self.run_case(caller,mode)

    # Active-command original-O death is deliberately exercised by the
    # persistent matrix's native-effect before/after crash73 cases: genuine
    # case-worker receipts plus original C fence and fresh account recovery.
    # Do not reintroduce a parallel Popen+marker-PID cleanup authority here.


class BuildDiscoveryCallerTests(unittest.TestCase):
    """Real Git/fictional tool executables, original owners and real descendants."""

    def monitored(self, root, executable, mode, *, before="", after=""):
        ready, heartbeat, stop = (root / name for name in ("ready", "heartbeat", "stop"))
        child = (
            "import os,time\nfrom pathlib import Path\n"
            f"Path({str(ready)!r}).write_text(str(os.getpid()))\n"
            "end=time.monotonic()+12\n"
            f"while not Path({str(stop)!r}).exists() and time.monotonic()<end:\n"
            f" Path({str(heartbeat)!r}).write_text(str(time.monotonic()))\n time.sleep(.01)\n"
        )
        script = (
            "#!" + sys.executable + "\nimport os,sys,subprocess,time,json\nfrom pathlib import Path\n"
            + before + "\n"
            + f"worker=subprocess.Popen({[sys.executable, '-I', '-S', '-B', '-c', child]!r},"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            + f"while not Path({str(heartbeat)!r}).exists(): time.sleep(.01)\n"
            + ("worker.wait(timeout=14)\n" if mode in {"timeout", "cancel"} else "")
            + ("sys.exit(7)\n" if mode == "failure" else after + "\n")
        )
        executable.write_text(script)
        executable.chmod(0o700)
        return ready, heartbeat, stop

    def observed_absent(self, ready, heartbeat, outcomes):
        self.assertTrue(ready.is_file() and heartbeat.is_file(), "descendant never acknowledged startup")
        observed = heartbeat.read_text()
        time.sleep(.025)
        self.assertEqual(heartbeat.read_text(), observed)
        self.assertTrue(all_original_commands_final(outcomes))

    def finish(self, root, stop, outcomes):
        stop.touch()
        if not all_original_commands_final(outcomes):
            self.fail(f"original command finality unconfirmed; preserving fictional fixture {root}")
        shutil.rmtree(root)

    def test_real_git_fsmonitor_descendants_finish_before_discovery_returns_or_cancels(self):
        for mode in ("success", "failure", "timeout", "cancel"):
            with self.subTest(mode=mode):
                root = Path(tempfile.mkdtemp(prefix="mrk-owned-git-")).resolve()
                home, project = root / "home", root / "project"
                home.mkdir(mode=0o700)
                config = load_config(write_project(project, android_config()))
                hook = root / "fsmonitor"
                ready, heartbeat, stop = self.monitored(root, hook, mode, after="sys.stdout.write('fictional-token\\0')")
                environment = {"PATH": "/opt/homebrew/bin:/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C",
                               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
                outcomes = []
                try:
                    with patch.dict(os.environ, environment, clear=True), \
                         bounded_commands(mode, heartbeat) as outcomes:
                        for args in (("init", "-q"), ("add", "."),
                                     ("-c", "user.name=Fictional", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "Fixture"),
                                     ("config", "core.fsmonitor", str(hook))):
                            self.assertEqual(run_owned(["git", *args], cwd=project, environ=environment, timeout=15).returncode, 0)
                        if mode == "cancel":
                            with self.assertRaises(KeyboardInterrupt):
                                discovery.discover_project(config.root)
                        else:
                            result = discovery.discover_project(config.root)
                            self.assertIn("git", result)
                    self.observed_absent(ready, heartbeat, outcomes)
                finally:
                    self.finish(root, stop, outcomes)

    def test_discovery_optional_missing_tool_bounds_and_capability_scrubbing(self):
        with settled_native_fixture("mrk-discovery-inputs-") as root:
            self.assertIsNone(discovery._run(root, [str(root / "absent")]))
            self.assertIsNone(discovery._run(root, [sys.executable, "-I", "-S", "-B", "-c", "raise SystemExit(7)"]))
            with patch.object(discovery, "OUTPUT_LIMIT", 64):
                self.assertIsNone(discovery._run(root, [sys.executable, "-I", "-S", "-B", "-c", 'print("x"*1000)']))
            secrets = {"MOBILE_RELEASE_APPLE_API_KEY_P8_BASE64": "fictional", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "fictional",
                       "GOOGLE_APPLICATION_CREDENTIALS": "/fictional/adc", "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "fictional"}
            code = f"import os,json;print(json.dumps([key for key in {list(secrets)!r} if key in os.environ]))"
            with patch.dict(os.environ, secrets, clear=False):
                self.assertEqual(json.loads(discovery._run(root, [sys.executable, "-I", "-S", "-B", "-c", code])), [])

    def test_actual_gradle_and_final_copy_signer_reap_descendants_on_all_outcomes(self):
        for caller in ("gradle", "signer"):
            for mode in ("success", "failure", "timeout", "cancel"):
                with self.subTest(caller=caller, mode=mode):
                    root = Path(tempfile.mkdtemp(prefix="mrk-owned-android-")).resolve()
                    config = load_config(write_project(root / "project", android_config()))
                    binary = root / "bin"
                    binary.mkdir()
                    source = config.root / "app/build/outputs/bundle/release/original.aab"
                    source.parent.mkdir(parents=True)
                    source.write_bytes(b"fictional-unsigned-bundle")
                    copied = config.root / ".mobile-release/build/android/app-release.aab"
                    keystore = root / "fictional-keystore"
                    keystore.write_bytes(b"fictional-keystore")
                    signing_values = {"MOBILE_RELEASE_ANDROID_KEYSTORE_PATH": str(keystore),
                                      "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "fixture-password",
                                      "MOBILE_RELEASE_ANDROID_KEY_ALIAS": "fixture-alias",
                                      "MOBILE_RELEASE_ANDROID_KEY_PASSWORD": "fixture-key-password"}
                    environment = {"PATH": str(binary) + ":/usr/bin:/bin", "HOME": str(root), "LC_ALL": "C",
                                   "MOBILE_RELEASE_VERSION_NAME": "9.9.9", "MOBILE_RELEASE_BUILD_NUMBER": "999", **signing_values}
                    wrapper = config.root / "gradlew"
                    if caller == "gradle":
                        before = ("assert sys.argv[1:]==['--no-daemon','--stacktrace',':app:bundleRelease']\n"
                                  "assert os.environ['MOBILE_RELEASE_VERSION_NAME']=='1.2.3'\n"
                                  "assert os.environ['MOBILE_RELEASE_BUILD_NUMBER']=='42'\n"
                                  "assert os.environ['MOBILE_RELEASE_REQUIRE_SIGNING']=='false'")
                        ready, heartbeat, stop = self.monitored(root, wrapper, mode, before=before)
                    else:
                        wrapper.write_text("#!/bin/sh\nexit 0\n")
                        wrapper.chmod(0o700)
                        before = (f"assert Path(sys.argv[-2])==Path({str(copied)!r})\n"
                                  f"assert Path({str(copied)!r}).read_bytes()==Path({str(source)!r}).read_bytes()\n"
                                  "assert sys.argv[1:3]==['-keystore'," + repr(str(keystore)) + "]\n"
                                  "assert '-storepass:env' in sys.argv and '-keypass:env' in sys.argv\n"
                                  "assert 'MOBILE_RELEASE_APPLE_API_KEY_P8_BASE64' not in os.environ\n"
                                  "assert 'ACTIONS_ID_TOKEN_REQUEST_TOKEN' not in os.environ\n"
                                  "assert 'MOBILE_RELEASE_ANDROID_KEYSTORE_PATH' not in os.environ\n"
                                  "assert os.environ['MOBILE_RELEASE_ANDROID_KEY_PASSWORD']=='fixture-key-password'")
                        ready, heartbeat, stop = self.monitored(root, binary / "jarsigner", mode, before=before,
                                                                     after="Path(sys.argv[-2]).write_bytes(b'fictional-final-copy')")
                    calls = []

                    def bounded(argv, **kwargs):
                        calls.append((list(argv), kwargs["timeout"], kwargs["capture"]))
                        self.assertEqual(kwargs["timeout"], 120 if argv[0] == "jarsigner" else 45 * 60)
                        kwargs["timeout"] = 15
                        return run_owned(argv, **kwargs)

                    outcomes = []
                    try:
                        with patch.dict(os.environ, environment, clear=True), patch.object(android, "run_owned", new=bounded), \
                             bounded_commands(mode, heartbeat) as outcomes:
                            if mode == "success":
                                result = android.run_android_build(config, signed=caller == "signer")
                                self.assertEqual(result["android-aab"], copied)
                                self.assertEqual(copied.read_bytes(), b"fictional-final-copy" if caller == "signer" else source.read_bytes())
                            else:
                                with self.assertRaises(KeyboardInterrupt if mode == "cancel" else ValidationError):
                                    android.run_android_build(config, signed=caller == "signer")
                        self.observed_absent(ready, heartbeat, outcomes)
                        self.assertEqual(source.read_bytes(), b"fictional-unsigned-bundle")
                        self.assertEqual(len(calls), 1 if caller == "gradle" else 2)
                        self.assertFalse(calls[0][2])
                        if caller == "signer":
                            self.assertTrue(calls[-1][2])
                    finally:
                        self.finish(root, stop, outcomes)

    def test_actual_ios_prepare_archive_export_discovery_never_executes_git(self):
        for explicit in (False, True):
            with self.subTest(explicit=explicit), settled_native_fixture("mrk-static-ios-discovery-") as root:
                home, private = root / "home", root / "private"
                home.mkdir(mode=0o700)
                private.mkdir(mode=0o700)
                value = ios_config()
                if not explicit:
                    value["ios"].pop("project")
                    value["ios"].pop("scheme")
                value["ios"]["prepareCommand"] = ["fictional-prepare"]
                config = load_config(write_project(root / "project", value, platform="ios"))
                original = config.root / "iosApp/Reader.xcodeproj"
                if explicit:
                    shutil.rmtree(original)  # Configured preparation must create the absent container.
                p12, source = private / "p12", private / "profile"
                p12.write_bytes(b"fictional-p12")
                source.write_bytes(b"fictional-profile")
                model = NativeSigningModel(home)
                native_calls = []

                def runner(argv, **kwargs):
                    if Path(argv[0]).name not in {"fictional-prepare", "xcodebuild"}:
                        return model(argv, **kwargs)
                    # The production C/A/W owner still supplies the genuine
                    # scope outcome/fence. Only fictional artifact contents are
                    # projected after that command, never a synthetic receipt.
                    revision = model.revisions
                    result = model(["build"], **kwargs)
                    self.assertEqual(model.revisions, revision + 1)
                    native_calls.append(list(argv))
                    if argv[0] == "fictional-prepare":
                        original.mkdir(parents=True, exist_ok=True)
                        (original / "project.pbxproj").write_text("PRODUCT_BUNDLE_IDENTIFIER = com.example.reader;\n")
                        shared = original / "xcshareddata/xcschemes/Reader.xcscheme"
                        shared.parent.mkdir(parents=True, exist_ok=True)
                        shared.write_text("<Scheme/>")
                    elif "-exportArchive" in argv:
                        export = Path(argv[argv.index("-exportPath") + 1])
                        options = plistlib.loads(Path(argv[argv.index("-exportOptionsPlist") + 1]).read_bytes())
                        self.assertFalse(options["uploadSymbols"])
                        self.assertEqual(options["provisioningProfiles"], {"com.example.reader": profile()["UUID"]})
                        export.mkdir()
                        (export / "fixture.ipa").write_bytes(b"fictional-unvalidated-ipa")
                    else:
                        self.assertIn("MARKETING_VERSION=1.2.3", argv)
                        self.assertIn("CURRENT_PROJECT_VERSION=42", argv)
                        self.assertEqual(kwargs["environ"]["MOBILE_RELEASE_DEFER_EXTERNAL_UPLOADS"], "1")
                        archive = Path(argv[argv.index("-archivePath") + 1])
                        (archive / "dSYMs").mkdir(parents=True)
                        (archive / "dSYMs/fictional").write_bytes(b"fictional-unvalidated-symbols")
                    return result

                with patch.object(ios, "sys", SimpleNamespace(platform="darwin")), \
                     patch.object(credentials, "_run_private", new=runner), \
                     patch.object(credentials, "_authenticated_signing_profile", new=fictional_signing_profile), \
                     patch.object(discovery, "run_owned", side_effect=AssertionError("static discovery executed Git")) as git:
                    with signing.local_signing_lease(home=home) as lease:
                        with credentials._temporary_apple_signing_environment(p12=p12, password="fictional", profile=source,
                                                                            directory=private, lease=lease) as env:
                            with patch.dict(os.environ, {"MOBILE_RELEASE_IOS_PROFILE_SPECIFIER": env["MOBILE_RELEASE_IOS_PROFILE_SPECIFIER"]}):
                                result = ios.run_ios_build(config, signed=True, signing_session=lease.active)
                            self.assertEqual(result["ios-ipa"].read_bytes(), b"fictional-unvalidated-ipa")
                            self.assertEqual((result["ios-dsyms"] / "fictional").read_bytes(), b"fictional-unvalidated-symbols")
                            self.assertIsNone(lease.active.state["inflight"])
                git.assert_not_called()
                self.assertEqual(len(native_calls), 3)
                self.assertEqual(model.preferences, model.original)
                self.assertEqual(signing.signing_status(home=home)["status"], "idle")


if __name__=='__main__':unittest.main()
