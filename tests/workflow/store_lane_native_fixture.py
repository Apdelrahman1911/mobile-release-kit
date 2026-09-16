"""One controller-selected native Store case; never a standalone safety owner.

The existing verification Session must bound and dispose each fresh Python
capture. Imports are inert. This fixture never clears retained product state,
spawns with subprocess/Popen, sends a signal, or calls a Store service.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import signal
import stat
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass
from pathlib import Path

PREFIX = "workflow.test_store_lane_native.StoreLaneNativeTests."
CASE_ROWS = (
    ("ordinary-at-exit-control", "test_real_success_exit_and_original_fd_retirement"),
    ("success0", "test_real_success_exit_and_original_fd_retirement"),
    ("ordinary75", "test_real_ordinary_failure_is_settled75_without_receipt"),
    ("system-exit0", "test_arbitrary_system_exit_is_unknown76"),
    ("system-exit75", "test_arbitrary_system_exit_is_unknown76"),
    ("terminal-close-return-loss", "test_real_close_and_link_return_loss_refuse_binding"),
    ("terminal-link-return-loss", "test_real_close_and_link_return_loss_refuse_binding"),
    ("nested-ios-success", "test_real_nested_family_settles_before_composite_disposal"),
    ("nested-android-success", "test_real_nested_family_settles_before_composite_disposal"),
    ("nested-android-inherited-pipe", "test_real_nested_family_settles_before_composite_disposal"),
    ("bridge-success", "test_pinned_fastlane_bridges_own_generated_entries_before_dispatch"),
    ("bridge-ordinary-error", "test_pinned_fastlane_bridges_own_generated_entries_before_dispatch"),
    ("clock-brackets", "test_native_shared_clock_labels_samples_and_expiry"),
    ("clock-expired", "test_native_shared_clock_labels_samples_and_expiry"),
    ("clock-wrong-label", "test_native_shared_clock_labels_samples_and_expiry"),
)
MAX_FILE = 1024 * 1024
MAX_JSON = 65_536
MAX_CASE = 8 * 1024 * 1024
MAX_ENTRIES = 128
STORE_FILES = frozenset({
    *("fastlane/" + name for name in (
        "release_support.rb", "native_process_spawn.rb", "native_upload_process.rb", "store_lane_lifetime.rb",
        "native_upload_validation.rb", "ios_upload_validation.rb", "android_upload_validation.rb", "Fastfile",
        "run_lane.rb", "store_document.rb", "store_lane_runtime.rb", "store_lane_resources.rb", "store_lane_fastlane_bridges.rb")),
    *("src/mobile_release/" + name for name in (
        "__init__.py", "ios_upload_validation.py", "android_upload_validation.py", "_native_process.py", "_profile_process.py",
        "_command_process.py", "_store_lane_contract.py", "_store_lane_evidence.py", "_store_lane_files.py", "owned_process.py",
        "cancellation.py", "_lifetime_evidence.py", "errors.py", "inspection.py")),
})
FIXTURES = (
    "tests/workflow/store_lane_native_fixture.rb",
    "tests/workflow/installed_ruby_capture_fixture.rb",
    "tests/workflow/upload_process_fixture.rb",
    "tests/workflow/upload_process_ownership.rb",
)
AUTHORITY = {"attempt": 1, "callerPath": ".github/workflows/candidate.yml",
    "event": "workflow_dispatch", "headSha": "a" * 40, "ref": "refs/heads/main",
    "reusableCommit": "b" * 40, "reusablePath": ".github/workflows/candidate.yml",
    "reusableRepository": "synthetic/project", "runId": 1, "workflow": "candidate"}
_CONFIGURATION = None


def need(condition, reason):
    if not condition:
        raise AssertionError("Store native fixture: " + reason)


def pairs(items):
    value = {}
    for key, item in items:
        need(key not in value, "duplicate JSON field")
        value[key] = item
    return value


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_JSON, "bounded JSON")
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def identity(value):
    return {"device": value.st_dev, "inode": value.st_ino, "uid": value.st_uid,
            "gid": value.st_gid, "mode": stat.S_IMODE(value.st_mode)}


def canonical(path, *, directory=False):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts and path == path.resolve(strict=True)
         and not path.is_symlink(), "canonical path")
    value = path.stat(follow_symlinks=False)
    need(stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode), "path type")
    return path


def file_binding(path):
    path = canonical(path)
    before = path.stat(follow_symlinks=False)
    need(before.st_nlink == 1 and before.st_size <= MAX_FILE, "bound source file")
    raw = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "source changed during read")
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "device": before.st_dev, "inode": before.st_ino, "mode": before.st_mode,
            "uid": before.st_uid, "gid": before.st_gid}


def write_exclusive(path, raw, mode=0o600):
    need(type(raw) is bytes and len(raw) <= MAX_FILE, "fixture write bound")
    number = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        original = os.fstat(number)
        need(stat.S_ISREG(original.st_mode) and original.st_uid == os.geteuid() and
             stat.S_IMODE(original.st_mode) == mode and original.st_nlink == 1, "original fixture writer")
        pending = memoryview(raw)
        while pending:
            count = os.write(number, pending)
            need(type(count) is int and 0 < count <= len(pending), "fixture writer progress")
            pending = pending[count:]
        os.fsync(number)
        return identity(original)
    finally:
        os.close(number)


def json_bytes(value):
    result = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    need(len(result) <= MAX_JSON, "fixture JSON bound")
    return result


def case_inventory(phase):
    need(phase in ("source", "wheel"), "native phase")
    return CASE_ROWS if phase == "source" else CASE_ROWS[1:]


@dataclass(frozen=True)
class Configuration:
    phase: str
    source: Path
    prefix: Path
    module_root: Path
    ruby: Path
    binding_file: Path
    case_directory: Path
    deadline: float
    subcase: str
    wheel: Path | None = None
    wheel_sha256: str | None = None

    def validate(self):
        need((self.subcase, dict(CASE_ROWS).get(self.subcase)) in case_inventory(self.phase), "closed native subcase")
        need(sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 11) and
             all(getattr(sys.flags, name, None) == 1 for name in
                 ("isolated", "ignore_environment", "no_user_site", "no_site", "safe_path", "dont_write_bytecode")),
             "qualified isolated CPython3.11 entry")
        for path in (self.source, self.prefix, self.module_root):
            canonical(path, directory=True)
        canonical(self.ruby)
        need(os.access(self.ruby, os.X_OK), "qualified Ruby executable")
        need(Path(__file__).resolve() == self.source / "tests/workflow/store_lane_native_fixture.py", "fixed source fixture")
        need((self.phase == "source" and self.prefix == self.source and self.module_root == self.source / "src") or
             (self.phase == "wheel" and not self.prefix.is_relative_to(self.source) and
              self.module_root.is_relative_to(self.prefix) and not self.module_root.is_relative_to(self.source)), "source/wheel origin separation")
        need(type(self.deadline) is float and math.isfinite(self.deadline) and
             0 < self.deadline - time.monotonic() <= 300, "original phase deadline")
        path = canonical(self.binding_file)
        value = path.stat()
        need(value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o600 and value.st_size <= MAX_JSON, "phase binding custody")
        if self.phase == "wheel":
            need(isinstance(self.wheel, Path) and type(self.wheel_sha256) is str and
                 re.fullmatch(r"[0-9a-f]{64}", self.wheel_sha256) is not None, "original wheel selection")
            wheel = canonical(self.wheel)
            need(wheel.name.endswith(".whl") and not wheel.is_relative_to(self.source), "original wheel is a separate artifact")
        else:
            need(self.wheel is None and self.wheel_sha256 is None, "source phase is not wheel evidence")
        # The controller owns these names; the subject only owns the five
        # writable leaves. Derive placement from explicit source/case data,
        # never from HOME (which has already changed on repeated validation).
        work = self.source.parent / "work"
        ordinal = tuple(name for name, _ in case_inventory(self.phase)).index(self.subcase) + 1
        expected = work / "store-lane" / self.phase / f"case-{ordinal:02d}"
        need(self.source.name == "source" and self.case_directory == expected, "fixed native case directory")
        root = canonical(self.case_directory, directory=True).stat(follow_symlinks=False)
        for path in (work, work / "store-lane", expected.parent, expected):
            value = canonical(path, directory=True).stat(follow_symlinks=False)
            need((value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode), value.st_dev) ==
                 (0, 0, 0o755, root.st_dev), "root-held native case path")
        for name in ("home", "tmp", "gem-cache", "bundle-config", "bundle-home"):
            value = canonical(expected / name, directory=True).stat(follow_symlinks=False)
            need((value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode), value.st_dev) ==
                 (os.geteuid(), os.getegid(), 0o700, root.st_dev), "native case leaf custody")
        for key, name in (("GEM_SPEC_CACHE", "gem-cache"), ("BUNDLE_APP_CONFIG", "bundle-config"),
                          ("BUNDLE_USER_HOME", "bundle-home")):
            need(os.environ.get(key) == str(expected / name), "native case cache selector")
        selected = tuple(os.environ.get(key) for key in ("HOME", "TMPDIR", "TMP", "TEMP"))
        need(selected in ((str(work / "home"),) + (str(work / "tmp"),) * 3,
                          (str(expected / "home"),) + (str(expected / "tmp"),) * 3), "native case environment placement")
        need(tempfile.tempdir is None or type(tempfile.tempdir) is str and tempfile.tempdir == str(expected / "tmp"),
             "foreign cached temporary directory")

    def select_environment(self):
        self.validate()  # No mutation or project/fixture import before custody checks.
        scratch = str(self.case_directory / "tmp")
        if tempfile.tempdir is None:
            # Do not ask tempfile to probe ambient/global fallback candidates.
            # Only this fresh process's uninitialized cache may be initialized.
            tempfile.tempdir = scratch
        need(tempfile.gettempdir() == scratch, "native case temporary directory")
        os.environ.update(HOME=str(self.case_directory / "home"), TMPDIR=scratch, TMP=scratch, TEMP=scratch)

    def remaining(self):
        left = self.deadline - time.monotonic()
        need(left >= 1, "original phase exhausted")
        return min(20, int(left))

    def binding(self):
        self.validate()
        value = decode(self.binding_file.read_bytes())
        need(type(value) is dict and value.keys() == {"prefix", "toolingRoot", "moduleRoot", "sourceRoot", "files",
             "recordPath", "recordSha256", "directUrlPath", "wheelSha256"}, "phase binding shape")
        tooling = self.source / "fastlane" if self.phase == "source" else self.prefix / "share/mobile-release-kit/fastlane"
        need(value["prefix"] == str(self.prefix) and value["sourceRoot"] == str(self.source) and
             value["moduleRoot"] == str(self.module_root) and value["toolingRoot"] == str(tooling), "phase binding paths")
        need(type(value["files"]) is dict and value["files"].keys() == STORE_FILES, "exact closed Store profile")
        for name, row in value["files"].items():
            need(type(name) is str and name.startswith(("fastlane/", "src/mobile_release/")) and
                 not any(part in ("", ".", "..") for part in name.split("/")), "profile relative path")
            destination = tooling / name.removeprefix("fastlane/") if name.startswith("fastlane/") else self.module_root / name.removeprefix("src/")
            need(row == file_binding(destination), "actual phase file binding")
            need(row["sha256"] == file_binding(self.source / name)["sha256"], "phase/source content equality")
        if self.phase == "wheel":
            record = canonical(value["recordPath"])
            need(record.is_relative_to(self.prefix) and hashlib.sha256(record.read_bytes()).hexdigest() == value["recordSha256"], "unchanged actual installed RECORD")
            direct = canonical(value["directUrlPath"])
            need(direct == record.parent / "direct_url.json" and value["wheelSha256"] == self.wheel_sha256,
                 "actual wheel archive binding required")
            need(self.wheel.stat().st_size <= 64 * 1024 * 1024 and
                 hashlib.sha256(self.wheel.read_bytes()).hexdigest() == self.wheel_sha256, "unchanged original wheel archive")
        else:
            need(all(value[name] is None for name in ("recordPath", "recordSha256", "directUrlPath", "wheelSha256")), "source is not installed evidence")
        return value


def configure(configuration):
    global _CONFIGURATION
    need(type(configuration) is Configuration and _CONFIGURATION is None, "one original selected case per Python domain")
    configuration.validate()
    _CONFIGURATION = configuration


def selected(method):
    need(_CONFIGURATION is not None and dict(CASE_ROWS)[_CONFIGURATION.subcase] == method,
         "native methods require an exact controller selection; raw discovery is not authorized")
    return _CONFIGURATION


class Case:
    def __init__(self, configuration):
        self.config = configuration
        self.binding = configuration.binding()
        self.retained = False
        self.summary = None
        self.started = False
        self.persisted_files = {}

    def _origins(self):
        allowed = {name.removeprefix("src/").removesuffix(".py").replace("/", ".")
                   for name in self.binding["files"] if name.startswith("src/")}
        allowed.remove("mobile_release.__init__")
        allowed.add("mobile_release")
        for name, module in tuple(sys.modules.items()):
            if name == "mobile_release" or name.startswith("mobile_release."):
                need(name in allowed, "unexpected first-party native import")
                relative = "src/mobile_release/__init__.py" if name == "mobile_release" else "src/" + name.replace(".", "/") + ".py"
                need(Path(module.__file__).resolve() == Path(self.binding["files"][relative]["path"]), "loaded source/wheel Python origin")
        need(self.config.binding() == self.binding, "bound installation changed")

    def _environment(self):
        # The Session already supplies admitted offline tooling. Keep only its
        # explicit noncredential execution settings; never copy Store secrets.
        names = {"PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "CI", "TERM", "GEM_HOME", "GEM_PATH", "GEM_SPEC_CACHE", "GEMRC",
                 "BUNDLE_GEMFILE", "BUNDLE_PATH", "BUNDLE_FROZEN", "BUNDLE_IGNORE_CONFIG", "BUNDLE_DISABLE_SHARED_GEMS",
                 "BUNDLE_APP_CONFIG", "BUNDLE_USER_HOME", "BUNDLE_RETRY", "BUNDLE_VERSION", "BUNDLE_CACHE_PATH",
                 "FASTLANE_HIDE_CHANGELOG", "FASTLANE_OPT_OUT_USAGE", "FASTLANE_SKIP_UPDATE_CHECK", "FASTLANE_SKIP_REPORTING",
                 "FASTLANE_SKIP_DOCS", "MOBILE_RELEASE_TEST_PROCESS_OBSERVER", "DEVELOPER_DIR", "JAVA_HOME",
                 "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_ATTR_NOSYSTEM", "GIT_TERMINAL_PROMPT", "GIT_CONFIG_COUNT", "GIT_OPTIONAL_LOCKS"}
        env = {name: value for name, value in os.environ.items() if name in names}
        need("PATH" in env and "HOME" in env and "BUNDLE_GEMFILE" in env, "admitted offline tool environment")
        env.update(LANG="C", LC_ALL="C", FASTLANE_HIDE_CHANGELOG="true", FASTLANE_OPT_OUT_USAGE="true",
                   FASTLANE_SKIP_DOCS="true", FASTLANE_SKIP_UPDATE_CHECK="true", FASTLANE_SKIP_REPORTING="true")
        env.update(TMPDIR=str(self.root), TMP=str(self.root), TEMP=str(self.root))
        return env

    def _request(self):
        request = {"version": 1, "phase": self.config.phase, "mode": self.config.subcase,
                   "root": str(self.root), "sourceRoot": str(self.config.source), "binding": self.binding,
                   "fixtureFiles": {name: file_binding(self.config.source / name)["sha256"] for name in FIXTURES},
                   "diagnostic": str(self.root / "observation.json"), "nested": None,
                   "wheel": None if self.config.wheel is None else str(self.config.wheel)}
        # The primitive rows reuse the finite success request layout, not a
        # generic Ruby driver or an environment-selected executable.
        if self.config.subcase in ("clock-brackets", "ordinary-at-exit-control"):
            request["mode"] = "success0"
        request["diagnosticIdentity"] = write_exclusive(self.root / "observation.json", b"")
        return request

    def _nested(self, request):
        mode = self.config.subcase
        if not mode.startswith("nested-"):
            return
        platform = "ios" if mode == "nested-ios-success" else "android"
        directory = self.root / "nested"
        directory.mkdir(mode=0o700)
        app = directory / "app"
        app.mkdir(mode=0o700)
        (app / "release").mkdir(mode=0o700)
        for path in (app / "release/mobile-release.json", app / "intent.json"):
            write_exclusive(path, b"{}\n")
        extension = "ipa" if platform == "ios" else "aab"
        artifact = app / ("candidate." + extension)
        raw = ("bounded synthetic " + platform + " artifact").encode("ascii")
        write_exclusive(artifact, raw)
        value = {"documentType": platform + "-current-upload-validation", "schemaVersion": 1,
                 "operationIntentSha256": "a" * 64, extension + "Sha256": hashlib.sha256(raw).hexdigest(), extension + "Size": len(raw)}
        if platform == "ios":
            value.update(notBefore="2020-01-01T00:00:00Z", notAfter="2099-01-01T00:00:00Z")
        fixture_request = directory / "validator-request.json"
        validator = directory / "trusted-validator"
        helper = self.config.source / "tests/workflow/installed_ruby_capture_fixture.rb"
        # JSON string syntax is Ruby string syntax for these canonical ASCII
        # paths; no command/eval input is interpolated from a caller's project.
        source = f"#!{self.config.ruby}\nrequire {json.dumps(str(helper))}\nexit! InstalledRubyCaptureFixture.validator({json.dumps(str(fixture_request))})\n"
        write_exclusive(validator, source.encode("utf-8"), 0o700)
        write_exclusive(fixture_request, json_bytes({"version": 1, "root": str(directory), "mode": "descendant" if mode.endswith("inherited-pipe") else "success",
            "deadline": self.config.deadline, "value": value}))
        request["nested"] = {"root": str(directory), "platform": platform, "app": str(app),
                             "artifact": str(artifact), "validator": str(validator), "value": value}

    def _normal_command(self, argv, *, env, cwd, capture=True):
        from mobile_release.owned_process import run_owned
        self._origins()
        return run_owned(argv, environ=env, cwd=cwd, timeout=self.config.remaining(), capture=capture, output_limit=MAX_JSON)

    def _primitive(self, request_path):
        mode = self.config.subcase
        fixture = self.config.source / "tests/workflow/store_lane_native_fixture.rb"
        argv = [str(self.config.ruby), str(fixture)]
        if mode == "ordinary-at-exit-control":
            result = self._normal_command([*argv, "at-exit-control", str(request_path)], env=self._environment(), cwd=self.root)
            need(result.returncode == 0 and result.stdout == "" and result.stderr == "", "ordinary Ruby hook control result")
            need((self.root / "at-exit.json").read_bytes() == b"ordinary-at-exit-ran\n", "armed at_exit observable")
            return {"ordinaryHookObserved": True}
        from mobile_release import _store_lane_contract as wire
        info = time.get_clock_info("monotonic")
        samples = []
        for _ in range(3):
            before = time.monotonic_ns()
            result = self._normal_command([*argv, "clock", str(request_path)], env=self._environment(), cwd=self.root)
            after = time.monotonic_ns()
            need(result.returncode == 0 and result.stderr == "", "native clock sample command")
            value = decode(result.stdout.encode("utf-8"))
            need(value["label"] == wire.clock_label() and value["rubyEngine"] == "ruby" and value["rubyVersion"] == "3.3.12" and
                 type(value["nanoseconds"]) is int and before <= value["nanoseconds"] <= after and
                 type(value["helperNanoseconds"]) is int and before <= value["helperNanoseconds"] <= after and
                 type(value["fixtureNanoseconds"]) is int and before <= value["fixtureNanoseconds"] <= after and
                 type(value["installedClockSeconds"]) is float and before / 1e9 <= value["installedClockSeconds"] <= after / 1e9 and
                 value["clockIdentifier"] == value["fixtureIdentifier"], "actual unshifted shared native clock")
            expected = self.binding["files"]["fastlane/native_process_spawn.rb"]
            need(value["clockOrigin"]["path"] == expected["path"] and value["clockOrigin"]["sha256"] == expected["sha256"], "actual product clock origin")
            samples.append({"before": before, "ruby": value["nanoseconds"], "after": after, "label": value["label"],
                            "helper": value["helperNanoseconds"], "fixture": value["fixtureNanoseconds"],
                            "installed": value["installedClockSeconds"], "clockIdentifier": value["clockIdentifier"]})
        return {"clockSamples": samples, "pythonImplementation": sys.implementation.name,
                "pythonClock": info.implementation, "platform": sys.platform}

    def _runtime_only(self, request_path, env):
        from mobile_release import _store_lane_contract as wire
        runtime = self.root / "runtime-only"
        runtime.mkdir(mode=0o700)
        for name in ("runner", "tmp"):
            (runtime / name).mkdir(mode=0o700)
        value = runtime.stat()
        run = time.monotonic_ns() + wire.RUN_NS
        env.update({"MOBILE_RELEASE_OPERATION": "ios_testflight_internal", "MOBILE_RELEASE_STORE_MODE": "prepare",
            "MOBILE_RELEASE_STORE_RECEIPT_PATH": str(self.root / "raw.json"), "MOBILE_RELEASE_ASC_APP_ID": "123456789",
            "MOBILE_RELEASE_ASC_KEY_ID": "NATIVEKEY1", wire.PREFIX + "NONCE": os.urandom(16).hex(),
            wire.PREFIX + "ROOT": str(runtime), wire.PREFIX + "ROOT_ID": f"{value.st_dev}:{value.st_ino}",
            wire.PREFIX + "CLOCK": wire.clock_label(), wire.PREFIX + "RUN_DEADLINE_NS": str(run),
            wire.PREFIX + "HARD_DEADLINE_NS": str(run + wire.CLEANUP_NS), "TMPDIR": str(runtime / "tmp"),
            "TMP": str(runtime / "tmp"), "TEMP": str(runtime / "tmp")})
        result = self._normal_command(["bundle", "exec", "ruby", str(self.launcher), "ios_testflight_internal"],
                                      env=env, cwd=runtime / "runner", capture=False)
        need(result.returncode == 76 and not (self.root / "raw.json").exists() and
             not (runtime / "terminal.json").exists() and not (self.root / "at-exit.json").exists(), "runtime-only refusal")
        if self.config.subcase == "clock-expired":
            observed = self._observation()
            need(observed["clock"]["entered"] < observed["clock"]["run"] <= observed["clock"]["after"] and
                 observed["clock"]["label"] == wire.clock_label(), "real expiry reached active check")
        else:
            need((self.root / "observation.json").stat().st_size == 0, "wrong label refused before runtime resource admission")
        return {"runtimeOnly": True, "returncode": result.returncode, "compositeSealShortened": False,
                "observation": observed if self.config.subcase == "clock-expired" else None}

    def _observation(self):
        path = self.root / "observation.json"
        need(identity(path.stat(follow_symlinks=False)) == self.request["diagnosticIdentity"] and path.stat().st_nlink == 1,
             "original observer file retained")
        result = decode(path.read_bytes())
        need(result["mode"] == self.request["mode"] and result["phase"] == self.config.phase and result["atExitArmed"] is True,
             "original diagnostic case")
        need(result["exitOrigin"]["source"] is None and result["exitOrigin"]["arity"] == -1 and
             result["fchdirOrigin"]["source"] is None and result["fchdirOrigin"]["arity"] == 1, "unchanged native terminal APIs")
        need(not (self.root / "at-exit.json").exists(), "product exit must not run at_exit")
        for item in result["slots"]:
            need(item["calls"] == item["returns"] == 1 and item["closed"] is True, "each original File close returned once")
        need(result["originalSlotsCovered"] is True and result["observerRestored"] is True,
             "observer covers actual original slots and restores its own hooks")
        return result

    def _account_outputs(self):
        # Count directories too, do not follow a symlink, and inspect outputs
        # before product disposal as well as before fixture disposal. The outer
        # original Session separately accounts for its own capture/IPC files.
        pending, count = [(self.root, 0)], 0
        root = self.root.stat(follow_symlinks=False)
        while pending:
            directory, depth = pending.pop()
            need(depth <= 20, "persisted directory depth")
            with os.scandir(directory) as entries:
                for entry in entries:
                    count += 1
                    need(count <= MAX_ENTRIES, "persisted total entry count")
                    value = entry.stat(follow_symlinks=False)
                    need(value.st_dev == root.st_dev and value.st_uid == os.geteuid() and
                         not stat.S_ISLNK(value.st_mode), "persisted output owner/type")
                    if stat.S_ISDIR(value.st_mode):
                        need(stat.S_IMODE(value.st_mode) == 0o700, "private persisted directory")
                        pending.append((Path(entry.path), depth + 1))
                    else:
                        need(stat.S_ISREG(value.st_mode) and value.st_size <= MAX_FILE and
                             stat.S_IMODE(value.st_mode) in (0o600, 0o700) and value.st_nlink in (1, 2), "persisted file bound")
                        if entry.name.endswith(".json"):
                            need(value.st_size <= MAX_JSON, "persisted diagnostic bound")
                        key = (value.st_dev, value.st_ino)
                        self.persisted_files[key] = max(self.persisted_files.get(key, 0), value.st_size)
        need(len(self.persisted_files) <= MAX_ENTRIES and sum(self.persisted_files.values()) <= MAX_CASE, "all observed persisted case bytes")

    def _composite(self, env):
        from mobile_release import _store_lane_contract as wire
        from mobile_release._store_lane_evidence import StoreLaneCallEvidence, StoreLaneEvidenceError
        from mobile_release._store_lane_files import StoreLaneFiles, StoreLaneAttempt
        from mobile_release.cancellation import CleanupScope, DefaultCancellation
        from mobile_release.owned_process import ProcessCleanupError, run_owned
        self._origins()
        app = self.root / "app"
        app.mkdir(mode=0o700)
        output = app / "raw.json"
        artifact = app / "candidate.ipa"
        write_exclusive(artifact, b"synthetic-no-credential-ipa\n")
        lane = "android_internal_upload" if self.config.subcase.startswith("nested-android") else "ios_testflight_internal"
        guard = DefaultCancellation(ProcessCleanupError, "native Store fixture owner did not settle")
        record = StoreLaneCallEvidence(guard, lane=lane, output=output, nonce=os.urandom(16))
        files = StoreLaneFiles(record, guard, app_root=app, mode="execute")
        attempt = StoreLaneAttempt(record, guard, app_root=app, mode="execute",
            intent_sha256=hashlib.sha256(b"synthetic native Store intent").digest(), executed_by=dict(AUTHORITY))
        owners = (files, attempt)
        def close_originals():
            first = None
            for owner in owners:
                try:
                    owner.close()
                except BaseException as error:
                    first = error if first is None else first
            if first is not None:
                raise first
        scope = CleanupScope(guard, close_originals, owns_cancellation=True, first_primary=True)
        original_handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        expected_error = None
        result = None
        payload = None
        try:
            try:
                with scope:
                    guard.install()
                    guard.activate()
                    files.acquire()
                    attempt.acquire()
                    prepared = files.prepare_environment({**env, "MOBILE_RELEASE_OPERATION": lane,
                        "MOBILE_RELEASE_STORE_MODE": "execute", "MOBILE_RELEASE_STORE_RECEIPT_PATH": str(output),
                        "MOBILE_RELEASE_ASC_APP_ID": "123456789", "MOBILE_RELEASE_ASC_KEY_ID": "NATIVEKEY1",
                        "MOBILE_RELEASE_IOS_IPA_PATH": str(artifact)})
                    timing = files.timing
                    argv = record.seal_command(runner=self.launcher, cwd=files.cwd, environ=prepared, cancellation=guard)
                    command = record.command_evidence(cancellation=guard)
                    self.config.remaining()  # The enclosing Session enforces the shorter original case bound.
                    result = run_owned(argv, environ=prepared, cwd=files.cwd, timeout=3600, capture=False,
                                       cancellation=guard, _evidence=command)
                    expected_code = (76 if self.config.subcase in ("system-exit0", "system-exit75",
                        "terminal-close-return-loss", "terminal-link-return-loss") else
                        75 if self.config.subcase in ("ordinary75", "bridge-ordinary-error") else 0)
                    need(result.returncode == expected_code, "fixed native row exit status")
                    need(files.timing is timing and command._lane_timing is timing and command._timing_consumed is True,
                         "same original3600s timing consumed")
                    outcome = record._outcome()
                    need(outcome is not None and outcome.no_target is None and outcome.result_integrity == "complete" and
                         outcome.termination == "normal-exit" and outcome.returncode == result.returncode and
                         guard.lifetime_ledger.verdict().contained is True, "original native C/A/W result and family closure")
                    observed = self._observation()
                    need(observed["binding"]["run_deadline_ns"] == timing.run and
                         observed["binding"]["hard_deadline_ns"] == timing.hard and
                         observed["binding"]["clock"] == timing.clock, "same original Ruby endpoints")
                    root = files.root_path
                    marker = app / ".mobile-release/store/lane-attempts-v1" / attempt.name
                    self._account_outputs()
                    if result.returncode == 76:
                        self.retained = True
                        marker_before = marker.read_bytes(), identity(marker.stat())
                        try:
                            files.read_terminal()
                        except StoreLaneEvidenceError as error:
                            expected_error = error
                        need(expected_error is not None, "unknown76 cannot bind plausible terminal files")
                        verdict = record.finish(cancellation=guard, primary=expected_error)
                        need(verdict.failed and verdict.command_finality_confirmed and record._terminal is None and
                             not verdict.dependents_settled and not verdict.receipt_acceptable,
                             "family closure alone cannot settle composite")
                        for operation in (files.dispose, attempt.retire):
                            try:
                                operation()
                            except StoreLaneEvidenceError:
                                pass
                            else:
                                raise AssertionError("unknown composite granted dependent removal")
                        need(root.is_dir() and (marker.read_bytes(), identity(marker.stat())) == marker_before,
                             "original unresolved root/marker preserved")
                        self.summary = {"returncode": 76, "retainedProductRoot": str(root),
                                        "retainedMarker": str(marker), "commandFinality": True,
                                        "terminalBound": False, "receiptAcceptable": False,
                                        "terminalNames": sorted(path.name for path in root.iterdir() if path.name.startswith("terminal.")),
                                        "observation": observed}
                        raise expected_error
                    need(result.returncode in (0, 75), "fixed runtime return")
                    primary = RuntimeError("fixed original75 caller failure") if result.returncode == 75 else None
                    terminal_paths = (root / "terminal.part", root / "terminal.json")
                    left, right = (item.stat() for item in terminal_paths)
                    need(left.st_nlink == right.st_nlink == 2 and identity(left) == identity(right), "actual two-name terminal inode")
                    terminal = files.read_terminal(primary=primary)
                    need(terminal is not None and terminal is record._terminal, "original reader publication")
                    verdict = record.finish(cancellation=guard, primary=primary)
                    need(verdict.dependents_settled and not verdict.receipt_acceptable, "receipt waits for actual disposal/marker retirement")
                    inventory = tuple(files.inventory)
                    payload = files.checked_document() if result.returncode == 0 else None
                    if payload is not None:
                        need(decode(payload) == {"fixture": "synthetic-no-store", "version": 1}, "original synthetic document bytes")
                    files.dispose()
                    need(not root.exists() and files.phase == "DISPOSED" and files.handles_closed(), "actual product file disposal")
                    attempt.retire()
                    need(not marker.exists() and attempt.phase == "RETIRED" and attempt.handles_closed(), "actual original marker retirement")
                    after = record.verdict(cancellation=guard)
                    if result.returncode == 0:
                        need(record.receipt_acceptable(lane=lane, output=output, sha256=hashlib.sha256(payload).digest(), cancellation=guard)
                             and after.receipt_acceptable, "final original receipt gate")
                    else:
                        need(not after.receipt_acceptable and not output.exists() and record._primary is primary and
                             observed["ordinaryPrimarySame"] is True, "ordinary failure stays original and never a receipt")
                    self.summary = {"returncode": result.returncode, "inventoryRoles": [entry.role for entry in inventory],
                                    "receiptAcceptable": after.receipt_acceptable, "commandFinality": True,
                                    "terminalBound": True, "productFilesDisposed": True, "attemptRetired": True,
                                    "observation": observed}
            finally:
                scope.__exit__(*sys.exc_info())
        except StoreLaneEvidenceError as error:
            need(expected_error is error and result is not None and result.returncode == 76, "only declared native76 refusal is accepted")
        need(guard.handler_state == "RESTORED" and all(signal.getsignal(number) is handler for number, handler in original_handlers.items()),
             "original handlers restored")
        if result.returncode == 0:
            record.require_receipt(lane=lane, output=output, sha256=hashlib.sha256(payload).digest(), cancellation=guard)
        self.summary["handlersRestored"] = True
        return self.summary

    def run(self):
        from workflow.profile_process_fixture import FixtureWorkspace
        need(not self.started, "original case cannot be reused")
        self.started = True
        with FixtureWorkspace(prefix="mrk-store-native-") as workspace:
            self.root = workspace.path.resolve(strict=True)
            need(not self.root.is_relative_to(self.config.source), "native scratch outside source")
            self.request = self._request()
            self._nested(self.request)
            request_path = self.root / "request.json"
            write_exclusive(request_path, json_bytes(self.request))
            request_before = file_binding(request_path)
            launch = self.root / "launcher"
            launch.mkdir(mode=0o700)
            (launch / "fastlane").mkdir(mode=0o700)
            self.launcher = launch / "fastlane/run_lane.rb"
            write_exclusive(self.launcher, (self.config.source / "tests/workflow/store_lane_native_fixture.rb").read_bytes())
            launcher_before = file_binding(self.launcher)
            env = self._environment()
            env["MOBILE_RELEASE_TEST_STORE_NATIVE_REQUEST"] = str(request_path)
            if self.config.subcase in ("clock-brackets", "ordinary-at-exit-control"):
                facts = self._primitive(request_path)
            elif self.config.subcase in ("clock-expired", "clock-wrong-label"):
                facts = self._runtime_only(request_path, env)
            else:
                facts = self._composite(env)
            self._origins()
            need(file_binding(self.launcher) == launcher_before and file_binding(request_path) == request_before and
                 decode(request_path.read_bytes()) == self.request, "original bound launcher/request unchanged")
            self._account_outputs()
            self.summary = {"version": 1, "phase": self.config.phase, "subcase": self.config.subcase,
                "testId": PREFIX + dict(CASE_ROWS)[self.config.subcase], "caseRoot": str(self.root),
                "productRetained": self.retained, "persistedBytes": sum(self.persisted_files.values()), "launcher": launcher_before,
                "request": request_before,
                "bindingSha256": hashlib.sha256(json_bytes(self.binding)).hexdigest(), "facts": facts}
            if self.retained:
                workspace.retain()  # No inner cleanup/adoption/reset of genuine fatal state.
            else:
                workspace.allow_removal()
        self.summary["fixtureRemoved"] = not self.root.exists()
        need(self.summary["fixtureRemoved"] != self.retained, "original fixture exit postcondition")
        return self.summary


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("source", "wheel"), required=True)
    for name in ("source-root", "prefix", "module-root", "ruby", "binding-file", "case-directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--deadline", type=float, required=True)
    parser.add_argument("--subcase", choices=tuple(name for name, _ in CASE_ROWS), required=True)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--wheel-sha256")
    args = parser.parse_args(arguments)
    configuration = Configuration(args.phase, args.source_root, args.prefix, args.module_root,
                                  args.ruby, args.binding_file, args.case_directory, args.deadline, args.subcase,
                                  args.wheel, args.wheel_sha256)
    configuration.select_environment()
    # -I/-S plus the exact original module root: no checkout fallback in wheel.
    sys.path[:0] = [str(configuration.module_root), str(configuration.source / "tests")]
    from workflow import store_lane_native_fixture as fixture
    from workflow import test_store_lane_native as tests
    from workflow.run_native_profile_checks import _result_class, _publish_failure
    fixture.configure(fixture.Configuration(args.phase, args.source_root, args.prefix, args.module_root,
                                            args.ruby, args.binding_file, args.case_directory, args.deadline, args.subcase,
                                            args.wheel, args.wheel_sha256))
    identifier = PREFIX + dict(CASE_ROWS)[args.subcase]
    case = tests.StoreLaneNativeTests(dict(CASE_ROWS)[args.subcase])
    state = {"failed": False, "records": []}
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, failfast=True, descriptions=False,
        resultclass=_result_class((identifier,), state)).run(unittest.TestSuite((case,)))
    success = result.wasSuccessful() and not result.skipped and not state["failed"] and result.testsRun == 1
    if not success:
        _publish_failure("tests", state["records"])
        return 1
    need(case.observation is not None, "native callback without original case observations")
    raw = json_bytes(case.observation)
    # Ordinary bounded original stdout, read only after the enclosing Session's
    # separate wait/EOF/domain/idle proof. These bytes grant no cleanup authority.
    written = sys.stdout.write("MRK_STORE_NATIVE_RESULT=" + raw.decode("ascii"))
    need(written == len("MRK_STORE_NATIVE_RESULT=") + len(raw), "complete native result observation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
