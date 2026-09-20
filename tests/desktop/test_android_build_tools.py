"""Inert source contracts, NOT installed-profile or native qualification evidence.

All inventories, owner state, descriptor numbers and observations are fabricated
DATA. The version spellings intentionally name no supported installed tuple.
Every selected filesystem/process boundary is replaced before use: no real tool
directory, file descriptor, process, namespace, credential, installer or network
fixture is acquired. These tests do not prove a native profile or Gradle parser.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import shlex
import stat
import threading
import types
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, PropertyMock, patch

from mobile_release import android_build_tools as subject
from mobile_release._desktop_android_build_files import AndroidBuildFiles, OriginalAndroidArtifact
from mobile_release.android_build_operation import AndroidBuildOperation
from mobile_release.config import ReleaseVersion
from mobile_release.owned_process import ProcessCleanupError


ROOT = subject.PREFIX + "inert-data"
WORK = Path('/inert/project a\'" $();`\\name/work')


def file_data(path, *, mode=0o644, size=7, digest="a" * 64):
    return {"path": path, "size": size, "sha256": digest, "mode": mode}


def manifest_data():
    return {
        "schemaVersion": 1, "profile": subject.PROFILE, "target": subject.TARGET,
        "instance": "inert-data", "launchContract": subject.LAUNCH_CONTRACT,
        "versions": {"jdkVendor": "inert-data", "jdkVersion": "0.0-inert", "gradleVersion": "0.0-inert",
                     "agpVersion": "0.0-inert", "sdkPlatform": "android-1",
                     "sdkPlatformRevision": "0.0-inert", "sdkBuildToolsVersion": "0.0-inert"},
        "gradleDistribution": {"url": "https://services.gradle.org/distributions/gradle-0.0-inert-bin.zip",
                               "sha256": "b" * 64},
        "bundletool": {"version": subject.BUNDLETOOL_VERSION, "sha256": subject.BUNDLETOOL_SHA256},
        "roles": dict(subject.TOOL_ROLES),
        "files": [file_data("bundletool/bundletool.jar", digest=subject.BUNDLETOOL_SHA256),
                  file_data("gradle/bin/gradle", mode=0o755), file_data("jdk/bin/java", mode=0o755),
                  file_data("jdk/bin/javac", mode=0o755), file_data("sdk/licenses/inert-license-data")],
        "osProfile": {"id": "inert-os-data-only", "inventorySha256": "c" * 64,
                      "shell": subject.OS_SHELL, "executableDirectory": subject.OS_EXECUTABLE_DIRECTORY,
                      "helpers": ["sed", "uname", "xargs"],
                      "files": [file_data("/usr/bin/" + name, mode=0o755)
                                for name in ("dash", "sed", "uname", "xargs")]},
    }


def encoded(document=None):
    raw = json.dumps(manifest_data() if document is None else document,
                     separators=(",", ":"), sort_keys=True).encode("ascii")
    return raw, binding_data(raw)


def binding_data(raw):
    return {"schemaVersion": 1, "profile": subject.PROFILE, "root": ROOT,
            "rootIdentity": {"device": "1", "inode": "50", "mode": stat.S_IFDIR | 0o755, "uid": 0, "gid": 0},
            "inventorySha256": hashlib.sha256(raw).hexdigest()}


def profile_data(document=None):
    raw, binding = encoded(document)
    return subject._parse_manifest(raw, subject._binding(binding))


def selection_data():
    profile = profile_data()
    return {"wrapper_properties": ("# generated wrapper DATA\r\n! comment\r\ndistributionUrl="
            + profile.distribution_url.replace(":", "\\:") + "\r\ndistributionSha256Sum="
            + profile.distribution_sha256 + "\r\n").encode("ascii"),
            "local_properties": None, "root_gradle_properties": None,
            "module_gradle_properties": None, "daemon_jvm_properties": None}


class Ledger:
    def __init__(self):
        self.complete = self.contained = True
        self.fatal = False
        self.errors = []

    def _remember(self, error):
        self.errors.append(error)

    def verdict(self):
        return types.SimpleNamespace(complete=self.complete, contained=self.contained, fatal=self.fatal,
                                     command_dispatched=False, profile_dispatched=False)


class Guard:
    def __init__(self):
        self.pid, self.depth = os.getpid(), 0
        self.lifetime_ledger = Ledger()

    def _check_owner(self):
        return None

    def _abort(self, error):
        self.lifetime_ledger.fatal = True
        self.lifetime_ledger._remember(error)

    @contextmanager
    def deferred(self, *, check_on_exit=False):
        self.depth += 1
        try:
            yield
        finally:
            self.depth -= 1


def inert_operation():
    # Actual operation type, deliberately fabricated fields: constructor/owner
    # predicates only. There is no input descriptor, invocation or native owner.
    operation = object.__new__(AndroidBuildOperation)
    operation.pid, operation.thread = os.getpid(), threading.current_thread()
    operation.guard = Guard()
    operation.source = types.SimpleNamespace(operation=operation, guard=operation.guard, active=True,
        request_returned=True, close_claimed=False, failure_observed=Mock())
    operation.guard._android_build_source = operation.source
    operation.request = types.SimpleNamespace(native={"toolchain": encoded()[1]})
    operation.inputs = types.SimpleNamespace(release=ReleaseVersion("1.2.3", 7), task=":app:bundleRelease",
        saved=types.SimpleNamespace(configuration=types.SimpleNamespace(module=":app")))
    operation.files = object.__new__(AndroidBuildFiles)
    operation.files.operation = operation
    operation.tools, operation.close_claimed, operation._artifact = None, False, None
    operation.counters = {}
    operation.checkpoint, operation.cleanup_checkpoint = Mock(), Mock()

    def charge(name, amount, limit):
        previous = operation.counters.get(name, 0)
        if type(amount) is not int or amount < 0 or previous > limit - amount:
            raise subject.AndroidToolError("input-limit")
        operation.counters[name] = previous + amount

    def fail(reason):
        raise subject.AndroidToolError(reason)

    operation.charge, operation.fail = charge, fail
    return operation


def inert_tools(*, selected=True):
    operation = inert_operation()
    tools = subject.AndroidValidationTools(operation, operation.request.native["toolchain"])
    operation.tools = tools
    tools.profile, tools._acquired = profile_data(), True
    if selected:
        tools._project_claimed = True
        tools._project_data = subject._selection_data(selection_data(), tools.profile, root_module=False)
    return tools


class Slot:
    def __init__(self, label, events):
        self.number, self.label, self.events = 17, label, events
        self.open_state, self.close_state, self.calls = "OPEN", "NOT_ATTEMPTED", 0

    def close(self):
        self.calls += 1
        self.events.append(self.label)
        self.number, self.close_state = None, "CLOSED"


def observed(*, inode=17, mode=stat.S_IFREG | 0o644, size=7, uid=0, links=1):
    return types.SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=0,
                                 st_size=size, st_nlink=links, st_mtime_ns=11, st_ctime_ns=13)


class ManifestDataTests(unittest.TestCase):
    def test_complete_raw_manifest_is_the_anchor_not_just_files(self):
        raw, native = encoded()
        binding = subject._binding(native)
        profile = subject._parse_manifest(raw, binding)
        self.assertEqual(profile.binding, binding)
        self.assertEqual(dict(profile.versions)["gradleVersion"], "0.0-inert")
        self.assertEqual(profile.os_identity, "inert-os-data-only")
        self.assertEqual(profile.helpers, ("sed", "uname", "xargs"))
        self.assertNotIn(subject.MANIFEST_NAME, [item.path for item in profile.files])
        array_bytes = json.dumps(manifest_data()["files"]).encode("ascii")
        with self.assertRaises(subject.AndroidToolError):
            subject._parse_manifest(raw, subject._binding({**native, "inventorySha256": hashlib.sha256(array_bytes).hexdigest()}))
        for section, key, value in (("versions", "jdkVersion", "1-inert"), ("roles", "java", "jdk/bin/javac"),
                                    ("osProfile", "id", "another-os"), ("gradleDistribution", "sha256", "d" * 64)):
            changed = manifest_data()
            changed[section][key] = value
            with self.subTest(section=section), self.assertRaises(subject.AndroidToolError):
                subject._parse_manifest(encoded(changed)[0], binding)
        with self.assertRaises(subject.AndroidToolError):
            subject._parse_manifest(raw + b"\n", binding)

    def test_binding_is_closed_root_owned_and_fixed_to_published_instance(self):
        original = encoded()[1]
        for field, value in (("root", "/inert/tools"), ("root", ROOT + "/"), ("root", subject.PREFIX + "../tools"),
                             ("root", subject.PREFIX + "UPPER"), ("schemaVersion", True),
                             ("inventorySha256", "A" * 64), ("qualified", True)):
            with self.subTest(field=field, value=value), self.assertRaises(subject.AndroidToolError):
                subject._binding({**original, field: value})
        for field, value in (("uid", 123), ("mode", stat.S_IFDIR | 0o777), ("inode", "0"),
                             ("device", "01"), ("mode", stat.S_IFREG | 0o755)):
            changed = {**original, "rootIdentity": {**original["rootIdentity"], field: value}}
            with self.subTest(field=field, value=value), self.assertRaises(subject.AndroidToolError):
                subject._binding(changed)

    def test_closed_roles_versions_distribution_and_os_fields(self):
        changes = ((None, "extra", 1), (None, "launchContract", "another"), ("roles", "java", "jdk/other-java"),
                   ("roles", "sdk", "sdk/"), ("versions", "jdkVersion", ""),
                   ("versions", "sdkPlatform", "android-01"), ("versions", "arbitraryOption", "x"),
                   ("bundletool", "version", "0"), ("bundletool", "sha256", "d" * 64),
                   ("gradleDistribution", "url", []), ("gradleDistribution", "url", {}),
                   ("gradleDistribution", "url", "https://inert.invalid/gradle.zip"),
                   ("osProfile", "shell", "/bin/sh"), ("osProfile", "executableDirectory", "/inert/bin"),
                   ("osProfile", "helpers", ["sed", "uname"]), ("osProfile", "inventorySha256", "missing"))
        for section, key, value in changes:
            data = manifest_data()
            (data if section is None else data[section])[key] = value
            with self.subTest(section=section, key=key, value=value), self.assertRaises(subject.AndroidToolError):
                profile_data(data)
        for field in manifest_data():
            data = manifest_data()
            del data[field]
            with self.subTest(missing=field), self.assertRaises(subject.AndroidToolError):
                profile_data(data)

    def test_missing_extra_unsafe_files_and_directory_aliases_refuse(self):
        cases = []
        missing = manifest_data(); missing["files"].pop(2); cases.append(missing)
        for path in (subject.MANIFEST_NAME, "../java", "/jdk/bin/java", "sdk/./data", "sdk/a/../data",
                     "sdk/a.", "sdk/" + "a" * 256, "sdk/" + "a/" * 16 + "data"):
            data = manifest_data(); data["files"].append(file_data(path)); cases.append(data)
        for paths in (("jdk/bin/java",), ("jdk/bin/JAVA",), ("jdk/BIN/data",), ("jdk/bin/java/data",)):
            data = manifest_data()
            data["files"].extend(file_data(path) for path in paths)
            data["files"].sort(key=lambda item: item["path"])
            cases.append(data)
        for field, value in (("size", -1), ("size", True), ("size", subject.MAX_FILE_BYTES + 1),
                             ("mode", 0o666), ("mode", 0o4755), ("sha256", "A" * 64), ("link", "other")):
            data = manifest_data(); data["files"][0][field] = value; cases.append(data)
        unordered = manifest_data(); unordered["files"].reverse(); cases.append(unordered)
        native = manifest_data(); native["osProfile"]["files"][0]["path"] = "/bin/dash"; cases.append(native)
        helper = manifest_data(); helper["osProfile"]["files"][0]["mode"] = 0o644; cases.append(helper)
        for index, data in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(subject.AndroidToolError):
                profile_data(data)

    def test_bounds_cover_tool_and_os_files_in_one_aggregate(self):
        for field, count in (("files", subject.MAX_TOOL_FILES + 1), ("os", subject.MAX_OS_FILES + 1)):
            data = manifest_data()
            if field == "files":
                data[field] = [data[field][0]] * count
            else:
                data["osProfile"]["files"] = [data["osProfile"]["files"][0]] * count
            with self.subTest(field=field), self.assertRaises(subject.AndroidToolError):
                profile_data(data)
        data = manifest_data()
        data["files"][2]["size"] = subject.MAX_FILE_BYTES
        data["osProfile"]["files"][0]["size"] = subject.MAX_FILE_BYTES
        with self.assertRaises(subject.AndroidToolError):
            profile_data(data)
        with self.assertRaises(subject.AndroidToolError):
            subject._parse_manifest(b" " * (subject.MAX_MANIFEST_BYTES + 1), subject._binding(encoded()[1]))

    def test_malformed_json_is_fixed_refusal(self):
        for raw in (b'{"schemaVersion":1,"schemaVersion":1}', b'{"n":1.2}', b'{"n":NaN}', b'{"n":true}',
                    b'{"n":null}', b'{"n":9007199254740992}', b'{"n":"\\ud800"}', b'\xef\xbb\xbf{}', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(subject.AndroidToolError) as raised:
                subject._parse_manifest(raw, subject._binding(binding_data(raw)))
            self.assertEqual(str(raised.exception), "The required Android tool profile could not be admitted")


class SelectionDataTests(unittest.TestCase):
    def test_properties_documented_escape_crlf_comment_subset(self):
        raw = b" # comment\r\n!other\r\n url = https\\://host/path\r\nkey\\=part:value\\ with\\:literal\\=parts\\\\\r\n"
        self.assertEqual(subject._properties(raw), {"url": "https://host/path", "key=part": "value with:literal=parts\\"})
        self.assertEqual(subject._properties(b"key\t:\tvalue\nempty\n"), {"key": "value", "empty": ""})
        self.assertEqual(subject._selection_data(selection_data(), profile_data(), root_module=False)[0][0], "wrapper_properties")

    def test_unsupported_or_duplicate_properties_do_not_become_absence(self):
        for raw in (b"x=1\nx:2", b"x\\ y=1\nx\\ y=2", b"x=a\\\ny=b", b"x=\\u0061", b"x=\\t", b"x=\\q",
                    b"x=tail\\", b"x=1\ry=2", b"x=\xff", b"x=\x00", b"=value"):
            with self.subTest(raw=raw), self.assertRaises(subject.AndroidToolError):
                subject._properties(raw)
        for raw in (b"x" * (subject.MAX_PROPERTY_LINE + 1), b"\n" * subject.MAX_PROPERTY_LINES):
            with self.assertRaises(subject.AndroidToolError):
                subject._properties(raw)

    def test_wrapper_and_selection_record_fail_closed(self):
        for key, value in (("wrapper_properties", None), ("wrapper_properties", b"distributionUrl=other"),
                           ("wrapper_properties", bytearray(b"x")), ("local_properties", "sdk.dir=other"),
                           ("daemon_jvm_properties", b""), ("extra", None)):
            data = selection_data(); data[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(subject.AndroidToolError):
                subject._selection_data(data, profile_data(), root_module=False)
        data = selection_data(); del data["local_properties"]
        with self.assertRaises(subject.AndroidToolError):
            subject._selection_data(data, profile_data(), root_module=False)
        data = selection_data(); data["local_properties"] = b"#" * (subject.MAX_SELECTION_BYTES + 1)
        with self.assertRaises(subject.AndroidToolError):
            subject._selection_data(data, profile_data(), root_module=False)

    def test_sdk_jdk_jvm_and_download_conflicts_refuse(self):
        for text in ("sdk.dir=/inert/sdk", "SDK.dir=/inert/sdk", "ndk.dir=/inert/ndk", "ndk.symlinkdir=/inert/ndk",
                     "cmake.dir=/inert/cmake", "flutter.sdk=/inert/flutter"):
            data = selection_data(); data["local_properties"] = text.encode("ascii")
            with self.subTest(local=text), self.assertRaises(subject.AndroidToolError):
                subject._selection_data(data, profile_data(), root_module=False)
        conflicts = ("org.gradle.java.home=/inert/java", "org.gradle.jvmargs=-Xmx9g", "org.gradle.daemon=true",
                     "org.gradle.java.installations.paths=/inert/jdk", "org.gradle.java.installations.fromEnv=JAVA_HOME",
                     "org.gradle.java.installations.auto-detect=true", "org.gradle.java.installations.auto-download=true",
                     "android.builder.sdkDownload=true", "systemProp.java.home=/inert/java",
                     "systemProp.org.gradle.java.home=/inert/java", "kotlin.daemon.jvmargs=-Xmx9g",
                     "org.gradle.parallel=true", "org.gradle.workers.max=20", "user.home=/inert/home")
        for field in ("root_gradle_properties", "module_gradle_properties"):
            for text in conflicts:
                data = selection_data(); data[field] = text.encode("ascii")
                with self.subTest(field=field, text=text), self.assertRaises(subject.AndroidToolError):
                    subject._selection_data(data, profile_data(), root_module=False)
        data = selection_data()
        data["local_properties"] = ("sdk.dir=" + ROOT + "/sdk\n").encode("ascii")
        data["root_gradle_properties"] = ("\n".join(key + "=" + value for key, value in subject._fixed_properties(ROOT))
                                           + "\nversionName=1.2.3\n").encode("ascii")
        subject._selection_data(data, profile_data(), root_module=False)

    def test_root_module_requires_identical_observation(self):
        data = selection_data(); data["root_gradle_properties"] = b"x=y"
        with self.assertRaises(subject.AndroidToolError):
            subject._selection_data(data, profile_data(), root_module=True)
        data["module_gradle_properties"] = data["root_gradle_properties"]
        result = subject._selection_data(data, profile_data(), root_module=True)
        self.assertEqual(dict(result)["module_gradle_properties"], b"x=y")

    def test_once_only_selection_retains_immutable_bytes_and_cannot_retry_failure(self):
        tools, data = inert_tools(selected=False), selection_data()
        with patch.object(tools, "check") as checked:
            tools.check_project_inputs(data)
            retained = tools._project_data
            data["wrapper_properties"] = b"changed"
            self.assertIsInstance(retained, tuple)
            self.assertNotEqual(dict(retained)["wrapper_properties"], data["wrapper_properties"])
            with self.assertRaises(subject.AndroidToolError):
                tools.check_project_inputs(selection_data())
            self.assertEqual(checked.call_count, 2)
        tools = inert_tools(selected=False)
        with patch.object(tools, "check"):
            with self.assertRaises(subject.AndroidToolError):
                tools.check_project_inputs({})
            with self.assertRaises(subject.AndroidToolError):
                tools.check_project_inputs(selection_data())
        self.assertTrue(tools._project_claimed)
        self.assertIsNone(tools._project_data)


class OwnerAndCommandDataTests(unittest.TestCase):
    def test_foreign_constructor_and_replaced_owner_refuse_before_io(self):
        with patch.object(subject.os, "open") as opened, patch.object(subject.os, "scandir") as scanned:
            with self.assertRaises(subject.AndroidToolError):
                subject.AndroidValidationTools(types.SimpleNamespace(), encoded()[1])
            for mutate in (lambda t: setattr(t.operation, "tools", object()),
                           lambda t: setattr(t.operation, "request", object()),
                           lambda t: setattr(t.source, "operation", object()),
                           lambda t: setattr(t.guard, "_android_build_source", object()),
                           lambda t: setattr(t.source, "active", False),
                           lambda t: setattr(t.source, "close_claimed", True),
                           lambda t: setattr(t.inputs, "release", ReleaseVersion("1.2.3", 7)),
                           lambda t: setattr(t.inputs, "task", ":other:bundleRelease"),
                           lambda t: setattr(t, "pid", -1), lambda t: setattr(t, "thread", object())):
                tools = inert_tools(); mutate(tools)
                with self.assertRaises(subject.AndroidToolError):
                    tools.acquire()
        opened.assert_not_called(); scanned.assert_not_called()

    def test_environment_is_fresh_fixed_and_uses_existing_release_contract(self):
        tools = inert_tools()
        poison = {name: "ambient-not-forwarded" for name in ("JAVA_OPTS", "GRADLE_OPTS", "JAVA_TOOL_OPTIONS",
                  "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH", "PYTHONPATH", "ENV", "BASH_ENV",
                  "LD_PRELOAD", "SSH_AUTH_SOCK", "AWS_SECRET_ACCESS_KEY", "MOBILE_RELEASE_BUILD_NUMBER")}
        with patch.object(subject.os, "environ", poison), patch.object(tools, "check"), \
             patch.object(AndroidBuildFiles, "work_path", new_callable=PropertyMock, return_value=WORK):
            env = tools.command_environment(WORK, tools.release)
            another = tools.command_environment(WORK, tools.release)
            self.assertIsNot(env, another)
            self.assertEqual({key: value for key, value in env.items() if key.startswith("MOBILE_RELEASE_")},
                             {"MOBILE_RELEASE_VERSION_NAME": "1.2.3", "MOBILE_RELEASE_BUILD_NUMBER": "7",
                              "MOBILE_RELEASE_REQUIRE_SIGNING": "false"})
            self.assertEqual(env["HOME"], str(WORK)); self.assertEqual(env["TMPDIR"], str(WORK))
            self.assertEqual(env["PATH"], ROOT + "/jdk/bin:/usr/bin")
            self.assertEqual(env["ANDROID_SDK_ROOT"], ROOT + "/sdk")
            self.assertEqual(shlex.split(env["JAVA_OPTS"]), list(subject._jvm_arguments(WORK)))
            self.assertFalse(set(poison).difference({"JAVA_OPTS", "MOBILE_RELEASE_BUILD_NUMBER"}).intersection(env))
            self.assertFalse(set(poison.values()).intersection(env.values()))
            env["HOME"] = "changed"
            self.assertEqual(another["HOME"], str(WORK))
            with self.assertRaises(subject.AndroidToolError):
                tools.command_environment(WORK, ReleaseVersion("1.2.3", 7))
            with self.assertRaises(subject.AndroidToolError):
                tools.command_environment(Path("/inert/other"), tools.release)

    def test_gradle_argv_is_fixed_shell_installed_script_and_private_jvm_data(self):
        tools = inert_tools()
        with patch.object(tools, "check"), \
             patch.object(AndroidBuildFiles, "work_path", new_callable=PropertyMock, return_value=WORK), \
             patch("mobile_release.android.run_owned") as dispatched, patch.object(subject.os, "open") as opened:
            argv = tools.gradle_command(tools.task, WORK)
            self.assertEqual(argv[:2], (subject.OS_SHELL, ROOT + "/gradle/bin/gradle"))
            self.assertEqual(argv[-1], ":app:bundleRelease")
            for flag in ("--no-daemon", "--no-watch-fs", "--no-parallel", "--console=plain", "--stacktrace", "--max-workers=2"):
                self.assertIn(flag, argv)
            self.assertEqual(argv[argv.index("--project-cache-dir") + 1], str(WORK / "project-cache"))
            self.assertEqual(argv[argv.index("--gradle-user-home") + 1], str(WORK / "gradle-home"))
            jvm = next(value.split("=", 1)[1] for value in argv if value.startswith("-Dorg.gradle.jvmargs="))
            # POSIX round-trip DATA only; the actual installed script/daemon
            # parser and launch-control support still require native qualification.
            self.assertEqual(shlex.split(jvm), list(subject._jvm_arguments(WORK)))
            for key, value in subject._fixed_properties(ROOT):
                self.assertIn(f"-D{key}={value}", argv); self.assertIn(f"-P{key}={value}", argv)
            self.assertNotIn("gradlew", argv); self.assertNotIn("/usr/bin/env", argv)
            with self.assertRaises(subject.AndroidToolError):
                tools.gradle_command(":other:bundleRelease", WORK)
        dispatched.assert_not_called(); opened.assert_not_called()

    def test_bundletool_requires_original_native_borrow_and_exact_snapshot(self):
        tools, snapshot = inert_tools(), WORK.parent / "artifacts/app-release.aab"
        artifact = object.__new__(OriginalAndroidArtifact)
        artifact.files, artifact._native, artifact._reader, artifact.check = tools.files, True, None, Mock()
        tools.files.artifact = tools.files._original_artifact = tools.operation._artifact = artifact
        with patch.object(tools, "check"), \
             patch.object(AndroidBuildFiles, "work_path", new_callable=PropertyMock, return_value=WORK), \
             patch.object(OriginalAndroidArtifact, "path", new_callable=PropertyMock, return_value=snapshot), \
             patch("mobile_release.android.run_owned") as dispatched:
            argv = tools.bundletool_command(snapshot)
            self.assertEqual(argv[0], ROOT + "/jdk/bin/java")
            self.assertEqual(argv[1:1 + len(subject._jvm_arguments(WORK, bundletool=True))],
                             subject._jvm_arguments(WORK, bundletool=True))
            self.assertEqual(argv[-6:], ("-jar", ROOT + "/bundletool/bundletool.jar", "dump", "manifest",
                                       "--bundle=" + str(snapshot), "--module=base"))
            with self.assertRaises(subject.AndroidToolError):
                tools.bundletool_command(Path("/inert/foreign.aab"))
            artifact._native = False
            with self.assertRaises(subject.AndroidToolError):
                tools.bundletool_command(snapshot)
            artifact._native, artifact._reader = True, object()
            with self.assertRaises(subject.AndroidToolError):
                tools.bundletool_command(snapshot)
            artifact._reader, tools.files._original_artifact = None, object()
            with self.assertRaises(subject.AndroidToolError):
                tools.bundletool_command(snapshot)
        dispatched.assert_not_called()

    def test_builders_refuse_before_selection_and_checks_do_not_rehash(self):
        tools = inert_tools(selected=False)
        with patch.object(tools, "_read") as read, patch.object(tools, "_check_metadata") as checked:
            tools.check(); tools.check()
            self.assertEqual(checked.call_count, 2)
            for call in (lambda: tools.gradle_command(tools.task, WORK),
                         lambda: tools.command_environment(WORK, tools.release),
                         lambda: tools.bundletool_command(Path("/inert/aab"))):
                with self.assertRaises(subject.AndroidToolError):
                    call()
        read.assert_not_called()


class OriginalLifetimeDataTests(unittest.TestCase):
    def test_fixed_acl_and_capability_observations_require_explicit_absence(self):
        tools = inert_tools()
        with patch.object(subject.os, "getxattr", side_effect=OSError(errno.ENODATA, "inert")) as attrs:
            tools._absent_attributes(17, directory=True)
        self.assertEqual([call.args for call in attrs.call_args_list],
                         [(17, "system.posix_acl_access"), (17, "security.capability"), (17, "system.posix_acl_default")])
        for result in (b"", b"grant-data"):
            with patch.object(subject.os, "getxattr", return_value=result), self.assertRaises(subject.AndroidToolError):
                tools._absent_attributes(17, directory=False)
        with patch.object(subject.os, "getxattr", side_effect=OSError(errno.ENOTSUP, "inert")), \
             self.assertRaises(subject.AndroidToolError):
            tools._absent_attributes(17, directory=False)

    def test_original_directory_names_are_closed_and_iterator_slot_is_serial(self):
        class Entries:
            def __init__(self, names):
                self.values = iter(types.SimpleNamespace(name=name) for name in names)
                self.closes = 0

            def __next__(self):
                return next(self.values)

            def close(self):
                self.closes += 1

        for names in (("java", "javac"), ("java",), ("java", "javac", "extra"), ("java", "java")):
            tools, entries = inert_tools(), Entries(names)
            tools._directories[ROOT] = 11
            with patch.object(subject.os, "scandir", return_value=entries) as scan:
                if names == ("java", "javac"):
                    tools._inventory_names(ROOT, {"java", "javac"})
                else:
                    with self.assertRaises(subject.AndroidToolError):
                        tools._inventory_names(ROOT, {"java", "javac"})
            scan.assert_called_once_with(11)
            self.assertEqual(entries.closes, 1)
            self.assertEqual(tools.iterators[0].close_state, "CLOSED")
        tools = inert_tools()
        tools._directories[ROOT] = 11
        tools.slots = [Slot("DATA-only", [])] * subject.MAX_DESCRIPTORS
        with patch.object(subject.os, "scandir") as scan, self.assertRaises(subject.AndroidToolError):
            tools._inventory_names(ROOT, set())
        scan.assert_not_called()

    def test_protected_observations_refuse_nonroot_links_special_and_writable(self):
        for data in (observed(uid=123), observed(links=2), observed(mode=stat.S_IFLNK | 0o777),
                     observed(mode=stat.S_IFIFO | 0o644), observed(mode=stat.S_IFREG | 0o666),
                     observed(mode=stat.S_IFREG | 0o4755)):
            with self.assertRaises(subject.AndroidToolError):
                subject._identity(data)

    def test_named_replacement_cannot_be_adopted(self):
        tools = inert_tools()
        record = subject._Record(11, "java", Slot("java", []), False, True,
                                 identity=subject._identity(observed()))
        with patch.object(tools, "_protected", return_value=record.identity), \
             patch.object(subject.os, "stat", return_value=observed(inode=99)) as named, \
             patch.object(subject.os, "open") as opened:
            with self.assertRaises(subject.AndroidToolError):
                tools._check_record(record)
        named.assert_called_once_with("java", dir_fd=11, follow_symlinks=False)
        self.assertEqual(record.identity[1], 17)
        opened.assert_not_called()

    def test_read_uses_original_number_bounded_chunks_and_precharges(self):
        tools, raw = inert_tools(), b"x" * subject.READ_CHUNK + b"end"
        record = subject._Record(11, "java", Slot("java", []), False, True,
                                 identity=subject._identity(observed(size=len(raw))))
        with patch.object(tools, "_check_record") as checked, patch.object(subject.os, "lseek", return_value=0) as seek, \
             patch.object(subject.os, "read", side_effect=[raw[:subject.READ_CHUNK], raw[subject.READ_CHUNK:]]) as read:
            digest, kept = tools._read(record, len(raw), keep=True)
        seek.assert_called_once_with(17, 0, os.SEEK_SET)
        self.assertEqual([call.args for call in read.call_args_list], [(17, subject.READ_CHUNK), (17, 3)])
        self.assertEqual(tools.operation.counters["tool-file-read-bytes"], len(raw))
        self.assertEqual(checked.call_count, 2)
        self.assertEqual((digest, kept), (hashlib.sha256(raw).hexdigest(), raw))

    def test_reverse_original_close_and_retired_source_observation(self):
        tools, events = inert_tools(), []
        tools._acquired = False
        tools.ancestry = types.SimpleNamespace(slots=[Slot("ancestor", events), Slot("instance", events)])
        tools.slots = [Slot("manifest", events), Slot("java", events)]
        tools.close()
        self.assertEqual(events, ["java", "manifest", "instance", "ancestor"])
        self.assertTrue(tools.closed())
        tools.source.close_claimed = True
        tools.guard._android_build_source = None  # Actual engine retires the input before terminal DATA.
        self.assertTrue(tools.closed())
        tools.close()  # Already-known closure is read-only/idempotent, not another consuming close.
        self.assertEqual(len(events), 4)
        with self.assertRaises(subject.AndroidToolError):
            tools.check()
        tools.slots[0].close_state = "UNKNOWN"
        self.assertFalse(tools.closed())
        tools.operation.tools = object()
        with self.assertRaises(subject.AndroidToolError):
            tools.closed()

    def test_claimed_close_or_retired_source_alone_is_not_closed(self):
        tools = inert_tools()
        tools._close_claimed = True
        tools.guard._android_build_source = None
        tools.source.close_claimed = True
        self.assertFalse(tools.closed())

    def test_consumers_must_settle_before_any_original_tool_close(self):
        for field in ("complete", "contained"):
            tools = inert_tools()
            tools._acquired = False
            tools.slots = [Slot("java", [])]
            setattr(tools.guard.lifetime_ledger, field, False)
            with self.subTest(field=field), self.assertRaises(ProcessCleanupError):
                tools.close()
            self.assertEqual(tools.slots[0].calls, 0)
            self.assertFalse(tools.closed())

    def test_final_digest_pass_is_once_and_cleanup_never_uses_work_admission(self):
        tools, events = inert_tools(), []
        manifest_slot, java_slot = Slot("manifest", events), Slot("java", events)
        tools.slots = [manifest_slot, java_slot]
        tools.manifest = subject._Record(11, subject.MANIFEST_NAME, manifest_slot, False, True,
                                        identity=subject._identity(observed(size=4)))
        spec = subject._FileSpec("jdk/bin/java", 7, "d" * 64, 0o755)
        java = subject._Record(11, "java", java_slot, False, True, identity=subject._identity(observed()), spec=spec)
        tools.records = [tools.manifest, java]
        tools.operation.close_claimed = True
        tools.guard.cancelled = True
        tools.operation.checkpoint.side_effect = AssertionError("work admission during cleanup")

        def read(record, size, **kwargs):
            tools._point()
            return (tools.binding.sha256 if record is tools.manifest else spec.sha256), None

        with patch.object(tools, "_check_metadata", side_effect=tools._point), patch.object(tools, "_read", side_effect=read) as reads:
            tools.close(); tools.close()
        self.assertEqual(reads.call_count, 2)
        self.assertTrue(tools._final_hash_claimed)
        self.assertTrue(tools.closed())
        tools.operation.checkpoint.assert_not_called()
        self.assertGreater(tools.operation.cleanup_checkpoint.call_count, 0)
        self.assertEqual(events, ["java", "manifest"])

    def test_failed_final_observation_still_closes_independent_slots(self):
        tools, events = inert_tools(), []
        tools.slots = [Slot("manifest", events), Slot("java", events)]
        failure = subject.AndroidToolError()
        with patch.object(tools, "_check_metadata", side_effect=failure):
            with self.assertRaises(subject.AndroidToolError):
                tools.close()
        self.assertIs(tools._first_error, failure)
        self.assertEqual(events, ["java", "manifest"])
        self.assertTrue(tools.closed())  # Closure is not successful tool admission.
        self.assertFalse(tools._unknown_seen)

    def test_ambiguous_numeric_close_retires_once_and_retains_unknown(self):
        tools, events = inert_tools(), []
        tools._acquired = False
        original = subject._FD(tools.guard)
        original.number, original.open_state = 71, "OPEN"  # DATA; never acquired.
        sibling = Slot("sibling", events)
        tools.slots = [sibling, original]
        with patch.object(subject.os, "close", side_effect=OSError(errno.EINTR, "inert")) as closed:
            with self.assertRaises(ProcessCleanupError):
                tools.close()
            with self.assertRaises(ProcessCleanupError):
                tools.close()
        closed.assert_called_once_with(71)
        self.assertIsNone(original.number)
        self.assertEqual(original.close_state, "UNKNOWN")
        self.assertEqual(events, ["sibling"])
        self.assertFalse(tools.closed())

    def test_iterator_close_and_wrapped_acquisition_ambiguity_never_retry(self):
        tools = inert_tools()
        tools._directories[ROOT] = 11
        with patch.object(subject.os, "scandir", side_effect=OSError(errno.ENOENT, "inert")) as scan:
            with self.assertRaises(ProcessCleanupError):
                tools._inventory_names(ROOT, set())
        scan.assert_called_once_with(11)
        self.assertEqual(len(tools.iterators), 1)
        self.assertEqual(tools.iterators[0].state, "UNKNOWN")  # Wrapper errno is not the direct builtin receipt.
        tools = inert_tools()
        iterator = subject._Entries(tools)
        iterator.state = "OPEN"
        iterator.value = types.SimpleNamespace(close=Mock(side_effect=OSError(errno.EINTR, "inert")))
        for _ in range(2):
            with self.assertRaises(ProcessCleanupError):
                iterator.close()
        iterator.value.close.assert_called_once_with()
        self.assertEqual(iterator.close_state, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
