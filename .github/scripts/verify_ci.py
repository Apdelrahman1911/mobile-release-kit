"""Fixed, credential-free CI sequence for disposable GitHub-hosted job VMs.

The platform adapter owns isolation and real child finality. This module owns
source provenance, the finite product-check sequence and a permanently failing
result when any command, parser, inspection or final cleanup fails. Import is
inert; no old verification framework, account service or PASS-file is used.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import traceback
from typing import Callable


AGGREGATE_SECONDS = 3300
DISK_RESERVE = 4 * 1024**3 + 512 * 1024**2
RUBY_SUITES = (
    ("ruby-support", "test_fastlane_support.rb", 12),
    ("ruby-native-capture", "test_native_upload_validation.rb", 13),
    ("ruby-play_store", "test_play_store.rb", 0),
    ("ruby-play_lanes", "test_play_lanes.rb", 0),
    ("ruby-apple_store", "test_apple_store.rb", 0),
    ("ruby-apple_lanes", "test_apple_lanes.rb", 0),
    ("ruby-apple_production", "test_apple_production.rb", 0),
    ("ruby-apple_production_lane", "test_apple_production_lane.rb", 0),
    ("ruby-apple_asset_upload", "test_apple_asset_upload.rb", 0),
    ("ruby-ios_upload_validation", "test_ios_upload_validation.rb", 26),
    ("ruby-android_upload_validation", "test_android_upload_validation.rb", 26),
    ("ruby-workflow-yaml", "test_workflow_yaml.rb", 0),
    ("ruby-supply-wif", "test_supply_wif.rb", 0),
)
NATIVE_RUBY_IDS = (
    "ruby-native-capture", "ruby-ios_upload_validation", "ruby-android_upload_validation",
)
_BEFORE_TESTS = (
    "source-copy", "source-environment", "source-dependencies", "bundler",
    "bundle-install", "editable-install", "source-freeze", "source-pip-check", "bundle-check",
)
_WHEEL = (
    "wheel-copy", "wheel-build", "wheel-inspect", "wheel-environment", "wheel-pip",
    "wheel-install", "wheel-freeze", "wheel-pip-check", "wheel-smoke", "wheel-consumer",
)


class VerificationError(RuntimeError):
    def __init__(self, code: str):
        self.code = code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", code) else "VERIFICATION_FAILURE"
        super().__init__(self.code)


@dataclasses.dataclass(frozen=True)
class Paths:
    source: Path
    work: Path
    inputs: Path
    python: Path
    ruby: Path
    version: str = "0.3.0"
    java_home: Path | None = None

    @property
    def source_python(self) -> Path:
        return self.work / "source-venv/bin/python"

    @property
    def wheel_python(self) -> Path:
        return self.work / "wheel-venv/bin/python"

    @property
    def checks(self) -> Path:
        return self.source / ".github/scripts/ci_checks.py"

    @property
    def wheel(self) -> Path:
        return self.work / f"wheels/mobile_release_kit-{self.version}-py3-none-any.whl"

    @property
    def bundle(self) -> tuple[str, ...]:
        base = self.work / "bundler/gems/bundler-4.0.16"
        return str(self.ruby), "-I", str(base / "lib"), str(base / "exe/bundle")


@dataclasses.dataclass(frozen=True)
class Step:
    id: str
    kind: str = "command"
    argv: tuple[str, ...] = ()
    cwd: Path | None = None
    env: tuple[tuple[str, str], ...] = ()
    seconds: int = 120
    parser: str = "exit"
    expected_tests: int = 0


@dataclasses.dataclass(frozen=True)
class CheckResult:
    ok: bool
    details: dict = dataclasses.field(default_factory=dict)
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class Report:
    ok: bool
    rows: tuple[dict, ...]
    error: str | None


def required_gate_ids(platform: str) -> tuple[str, ...]:
    if platform == "linux":
        return (*_BEFORE_TESTS, "python-full", *(row[0] for row in RUBY_SUITES),
                "fastfile", "actionlint", "jdk-signers", *_WHEEL, "python-wheel", "source-integrity")
    if platform == "macos":
        return (*_BEFORE_TESTS, "native-tools", "native-profile-source", *NATIVE_RUBY_IDS,
                *_WHEEL, "native-profile-wheel", "source-integrity")
    raise VerificationError("UNSUPPORTED_PLATFORM")


def environment(paths: Paths, platform: str) -> tuple[tuple[str, str], ...]:
    work = paths.work
    binary_roots = [paths.source_python.parent, work / "bundler/bin", paths.ruby.parent]
    if paths.java_home is not None:
        binary_roots.append(paths.java_home / "bin")
    binary_roots.extend(map(Path, ("/usr/bin", "/bin", "/usr/sbin", "/sbin")))
    env = {
        "PATH": ":".join(map(str, binary_roots)), "HOME": str(work / "home"),
        "TMPDIR": str(work / "tmp"), "TMP": str(work / "tmp"), "TEMP": str(work / "tmp"),
        "TZ": "UTC", "CI": "1",
        "LANG": "en_US.UTF-8" if platform == "macos" else "C.UTF-8",
        "LC_ALL": "en_US.UTF-8" if platform == "macos" else "C.UTF-8", "TERM": "dumb",
        "PYTHONSAFEPATH": "1", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_CONFIG_FILE": "/dev/null", "PIP_NO_INDEX": "1", "PIP_NO_CACHE_DIR": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1",
        "PIP_FIND_LINKS": str(paths.inputs / "python"),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": "0", "GIT_OPTIONAL_LOCKS": "0",
        "GEM_HOME": str(work / "bundler"), "GEM_PATH": str(work / "bundler"),
        "GEM_SPEC_CACHE": str(work / "gem-cache"), "GEMRC": "/dev/null",
        "BUNDLE_GEMFILE": str(paths.source / "Gemfile"), "BUNDLE_PATH": str(work / "bundle"),
        "BUNDLE_CACHE_PATH": str(paths.inputs / "gems"), "BUNDLE_FROZEN": "1",
        "BUNDLE_IGNORE_CONFIG": "1", "BUNDLE_DISABLE_SHARED_GEMS": "1",
        "BUNDLE_APP_CONFIG": str(work / "bundle-config"), "BUNDLE_USER_HOME": str(work / "bundle-home"),
        "BUNDLE_RETRY": "0", "BUNDLE_VERSION": "4.0.16",
        "FASTLANE_HIDE_CHANGELOG": "true", "FASTLANE_OPT_OUT_USAGE": "true",
        "FASTLANE_SKIP_UPDATE_CHECK": "true", "FASTLANE_SKIP_REPORTING": "true",
        "MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS": "1",
        "MOBILE_RELEASE_TEST_PYTHON": str(paths.source_python),
    }
    if platform == "macos":
        env["DEVELOPER_DIR"] = "/Applications/Xcode_26.3.app/Contents/Developer"
    if paths.java_home is not None:
        env["JAVA_HOME"] = str(paths.java_home)
    return tuple(sorted(env.items()))


def catalog(paths: Paths, platform: str, *, deadline: float) -> tuple[Step, ...]:
    """Finite data-only dispatch; materialization/launches belong to the caller."""
    required_gate_ids(platform)
    if (paths.source / "src/mobile_release/local_signing.py").exists():
        # The separate QA-003 patch needs its complete native-active matrix.
        # Refuse it until that issue deliberately integrates its own catalog.
        raise VerificationError("LOCAL_SIGNING_MATRIX_REQUIRES_CATALOG_AMENDMENT")
    if type(deadline) is not float or not math.isfinite(deadline):
        raise VerificationError("INVALID_DEADLINE")
    env = environment(paths, platform)
    steps: dict[str, Step] = {}

    def command(name, argv, *, seconds=120, parser="exit", tests=0, cwd=None):
        steps[name] = Step(name, argv=tuple(map(str, argv)), cwd=cwd or paths.work,
                           env=env, seconds=seconds, parser=parser, expected_tests=tests)

    def operation(name):
        steps[name] = Step(name, kind="inspection")

    def python(executable, *args):
        return (str(executable), "-I", "-B", *map(str, args))

    def check(name, executable, *, seconds=300, more=()):
        command(name, python(executable, paths.checks, "--check", name,
                            "--source-root", paths.source, "--work-root", paths.work / "checks",
                            "--deadline", repr(deadline), *more), seconds=seconds, parser="check")

    for name in ("source-copy", "source-freeze", "wheel-copy", "wheel-inspect", "wheel-freeze",
                 "wheel-consumer", "source-integrity"):
        operation(name)
    command("source-environment", python(paths.python, "-m", "venv", "--copies", paths.work / "source-venv"), seconds=180)
    command("source-dependencies", python(paths.source_python, "-m", "pip", "install", "--no-index", "--no-compile",
            "--find-links", paths.inputs / "python", "--require-hashes",
            "-r", paths.inputs / "python/pip-requirements.txt",
            "-r", paths.inputs / "python/build-requirements.txt",
            "-r", paths.inputs / "python/test-requirements.txt"), seconds=1200)
    command("bundler", (paths.ruby, paths.ruby.parent / "gem", "install", "--local", "--no-document",
            "--install-dir", paths.work / "bundler", paths.inputs / "gems/bundler-4.0.16.gem"), seconds=300)
    command("bundle-install", (*paths.bundle, "install", "--local", "--jobs", "2", "--retry", "0"), seconds=1200)
    command("editable-install", python(paths.source_python, "-m", "pip", "install", "--no-index", "--no-compile",
            "--find-links", paths.inputs / "python", "--no-deps", "--editable", paths.work / "source-build"), seconds=900)
    command("source-pip-check", python(paths.source_python, "-m", "pip", "check"))
    command("bundle-check", (*paths.bundle, "check"))
    check("python-full", paths.source_python, seconds=900)
    native = paths.source / "tests/workflow/run_native_profile_checks.py"
    command("native-tools", ("/usr/bin/xcodebuild", "-version"), parser="xcode")
    command("native-profile-source", python(paths.source_python, native), seconds=900, parser="native")
    for name, filename, count in RUBY_SUITES:
        if not count and name != "ruby-supply-wif":
            # The actual complete source provides the number of literal tests.
            # Dynamically generated adapter contracts have explicit reviewed totals.
            count = ruby_literal_tests(paths.source / "tests/workflow" / filename)
        command(name, (*paths.bundle, "exec", paths.ruby, paths.source / "tests/workflow" / filename,
                        *(("--verbose",) if name != "ruby-supply-wif" else ())),
                seconds=180 if name == "ruby-native-capture" else 300 if name in NATIVE_RUBY_IDS else 180,
                parser="supply" if name == "ruby-supply-wif" else "minitest", tests=count)
    command("fastfile", (*paths.bundle, "exec", paths.ruby, paths.source / "fastlane/run_lane.rb", "--validate"), seconds=180)
    workflow_paths = sorted((paths.source / ".github/workflows").glob("*.yml"))
    workflow_paths += sorted((paths.source / "templates/workflows").glob("*.yml"))
    command("actionlint", (paths.inputs / "actionlint/actionlint", "-no-color", "-ignore",
            'property "workflow_(repository|sha|ref)" is not defined in object type', *workflow_paths))
    check("jdk-signers", paths.source_python, seconds=600)
    command("wheel-build", python(paths.source_python, "-m", "pip", "wheel", "--no-index",
            "--find-links", paths.inputs / "python", "--no-deps", "--wheel-dir", paths.work / "wheels",
            paths.work / "wheel-build"), seconds=900)
    command("wheel-environment", python(paths.python, "-m", "venv", "--copies", paths.work / "wheel-venv"), seconds=180)
    command("wheel-pip", python(paths.wheel_python, "-m", "pip", "install", "--no-index", "--no-compile",
            "--find-links", paths.inputs / "python", "--require-hashes", "-r", paths.inputs / "python/pip-requirements.txt"), seconds=300)
    command("wheel-install", python(paths.wheel_python, "-m", "pip", "install", "--no-index", "--no-compile",
            "--no-deps", paths.wheel), seconds=300)
    command("wheel-pip-check", python(paths.wheel_python, "-m", "pip", "check"))
    check("wheel-smoke", paths.wheel_python, more=("--wheel", str(paths.wheel), "--ruby", str(paths.ruby)))
    check("python-wheel", paths.wheel_python, seconds=900)
    command("native-profile-wheel", python(paths.wheel_python, native, "--installed-wheel"), seconds=900, parser="native")
    wheel_env = dict(env)
    wheel_env["PATH"] = str(paths.wheel_python.parent) + ":" + wheel_env["PATH"]
    wheel_env["MOBILE_RELEASE_TEST_PYTHON"] = str(paths.wheel_python)
    for name in ("wheel-pip", "wheel-install", "wheel-pip-check", "wheel-smoke", "python-wheel", "native-profile-wheel"):
        steps[name] = dataclasses.replace(steps[name], env=tuple(sorted(wheel_env.items())))
    return tuple(steps[name] for name in required_gate_ids(platform))


def ruby_literal_tests(path: Path) -> int:
    source = path.read_text(encoding="utf-8")
    count = len(re.findall(r"^\s*def test_[A-Za-z0-9_]+\s*(?:\([^\n]*\))?\s*$", source, re.MULTILINE))
    if count < 1:
        raise VerificationError("RUBY_SUITE_EMPTY")
    return count


def ruby_expected_ids(source: Path, gate: str) -> tuple[str, ...]:
    """The fixed suite's real method identities, including its shared contracts."""
    rows = [row for row in RUBY_SUITES if row[0] == gate and row[0] != "ruby-supply-wif"]
    if len(rows) != 1:
        raise VerificationError("RUBY_SUITE_UNKNOWN")
    raw = (source / "tests/workflow" / rows[0][1]).read_text(encoding="utf-8")
    classes = list(re.finditer(r"(?m)^class ([A-Za-z0-9_:]+) < Minitest::Test[^\S\n]*$", raw))
    if not classes:
        raise VerificationError("RUBY_STATIC_INVENTORY")
    extra = []
    if gate in {"ruby-ios_upload_validation", "ruby-android_upload_validation"}:
        if raw.count("  include UploadProcessFixture::Contracts\n") != 1:
            raise VerificationError("RUBY_SHARED_CONTRACT_MISSING")
        shared = (source / "tests/workflow/upload_process_fixture.rb").read_text(encoding="utf-8")
        sections = shared.split("  module Contracts\n")
        if len(sections) != 2:
            raise VerificationError("RUBY_SHARED_CONTRACT_AMBIGUOUS")
        shared = sections[1].split("\nif $PROGRAM_NAME == __FILE__", 1)[0]
        literal = re.findall(r"(?m)^    def (test_[A-Za-z0-9_]+)\s*$", shared)
        if (len(literal) != 11 or shared.count("%w[async signals policies unknown].each do |family|") != 1
                or shared.count('define_method("test_process_ownership_#{family}_through_both_real_fixture_callers")') != 1):
            raise VerificationError("RUBY_DYNAMIC_CONTRACT_DRIFT")
        extra.extend(literal)
        extra.extend(f"test_process_ownership_{family}_through_both_real_fixture_callers"
                     for family in ("async", "signals", "policies", "unknown"))
    result = []
    for owner in classes:
        # These reviewed files use ordinary top-level classes and unindented
        # closing `end`; unsupported construction fails rather than inventing IDs.
        body = raw[owner.end():].split("\nend\n", 1)[0]
        names = re.findall(r"(?m)^  def (test_[A-Za-z0-9_]+)\s*$", body)
        if "  include UploadProcessFixture::Contracts\n" in body:
            names.extend(extra)
        if not names or len(names) != len(set(names)):
            raise VerificationError("RUBY_STATIC_INVENTORY")
        result.extend(f"{owner[1]}#{name}" for name in names)
    if len(result) != len(set(result)):
        raise VerificationError("RUBY_DUPLICATE_METHOD")
    return tuple(sorted(result))


def execute_pipeline(steps: tuple[Step, ...], perform: Callable[[Step], CheckResult], *, platform: str) -> Report:
    """A recorder seam tests dispatch/failure semantics without starting workers."""
    if tuple(step.id for step in steps) != required_gate_ids(platform):
        raise VerificationError("REQUIRED_GATE_INVENTORY")
    rows = [{"id": step.id, "status": "UNEXECUTED"} for step in steps]
    error = None
    for index, step in enumerate(steps):
        rows[index]["status"] = "RUNNING"
        try:
            value = perform(step)
            if type(value) is not CheckResult or type(value.ok) is not bool:
                raise VerificationError("INVALID_CHECK_RESULT")
            if not value.ok:
                rows[index]["details"] = value.details
                raise VerificationError(value.error or "CHECK_FAILED")
            rows[index].update(status="PASS", details=value.details)
        except BaseException as exc:
            error = exc.code if isinstance(exc, VerificationError) else "CHECK_EXECUTION_FAILED"
            rows[index].update(status="FAIL", error=error)
            if not isinstance(exc, VerificationError):
                frames = traceback.extract_tb(exc.__traceback__)
                rows[index]["location"] = [Path(frames[-1].filename).name, frames[-1].lineno] if frames else []
                rows[index]["exception"] = type(exc).__name__
            break
    return Report(error is None, tuple(rows), error)


def check_clock(deadline: float) -> None:
    if type(deadline) is not float or not math.isfinite(deadline) or time.monotonic() >= deadline:
        raise VerificationError("AGGREGATE_DEADLINE")


def check_capacity(path: Path, prospective: int = 0) -> None:
    if shutil.disk_usage(path).free - prospective < DISK_RESERVE:
        raise VerificationError("DISK_HEADROOM")


def _module(directory: Path, name: str):
    spec = importlib.util.spec_from_file_location(f"_mrk_disposable_{name}", directory / f"{name}.py")
    if spec is None or spec.loader is None:
        raise VerificationError("HELPER_MODULE_MISSING")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return module


def read_regular(path: Path, *, deadline: float, maximum: int = 8 * 1024**2) -> bytes:
    """Ordinary bounded read; callers already own immutable source or finality."""
    check_clock(deadline)
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
        raise VerificationError("FILE_PARENT_ALIAS")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 <= before.st_size <= maximum:
            raise VerificationError("FILE_TYPE_OR_BOUND")
        chunks = []
        left = before.st_size
        while left:
            check_clock(deadline)
            chunk = os.read(fd, min(left, 65536))
            if not chunk:
                raise VerificationError("FILE_SHORT_READ")
            chunks.append(chunk)
            left -= len(chunk)
        if os.read(fd, 1):
            raise VerificationError("FILE_GREW")
        after = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                                   value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after):
            raise VerificationError("FILE_CHANGED_DURING_READ")
        return b"".join(chunks)
    finally:
        # A close is attempted once; ambiguity fails the enclosing operation.
        close_owned(fd)


def create_file(path: Path, data: bytes, *, mode: int, deadline: float) -> None:
    check_clock(deadline)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            check_clock(deadline)
            written = os.write(fd, view[:65536])
            if not 0 < written <= min(len(view), 65536):
                raise VerificationError("FILE_SHORT_WRITE")
            view = view[written:]
        os.fchmod(fd, mode)
    finally:
        close_owned(fd)


def close_owned(fd: int) -> None:
    """One close attempt, with an earlier exception kept as the first failure."""
    primary = sys.exc_info()[1]
    try:
        os.close(fd)
    except BaseException as cleanup:
        if primary is not None:
            raise BaseExceptionGroup("operation and descriptor close failed", [primary, cleanup]) from None
        raise


def trusted_command(argv: tuple[str, ...], *, deadline: float, cwd: Path | None = None) -> bytes:
    """Only fixed provider/Git introspection; never project/build/test commands."""
    check_clock(deadline)
    allowed = {"/usr/bin/git", str(Path(sys.executable).resolve())}
    if argv[0] not in allowed:
        raise VerificationError("TRUSTED_COMMAND_NOT_FIXED")
    result = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False, timeout=min(30, deadline - time.monotonic()),
                            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/empty",
                                 "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                                 "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"})
    if result.returncode != 0 or len(result.stdout) + len(result.stderr) > 4 * 1024**2:
        raise VerificationError("TRUSTED_INTROSPECTION_FAILED")
    return result.stdout


def snapshot_source(checkout: Path, destination: Path, commit: str, *, deadline: float) -> tuple[dict, dict]:
    """Copy the exact committed ordinary-file tree; no worktree/index mutation."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise VerificationError("COMMIT_BINDING")
    git = ("/usr/bin/git", "-c", f"safe.directory={checkout}", "-C", str(checkout))
    actual = trusted_command((*git, "rev-parse", "HEAD"), deadline=deadline).strip().decode("ascii")
    tree = trusted_command((*git, "rev-parse", "HEAD^{tree}"), deadline=deadline).strip().decode("ascii")
    if actual != commit or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise VerificationError("CHECKOUT_COMMIT_MISMATCH")
    if trusted_command((*git, "status", "--porcelain=v1", "--untracked-files=all"), deadline=deadline):
        raise VerificationError("CHECKOUT_NOT_CLEAN")
    entries = trusted_command((*git, "ls-tree", "-rz", "--full-tree", "HEAD"), deadline=deadline).split(b"\0")
    if entries[-1] or not 1 <= len(entries) - 1 <= 512:
        raise VerificationError("SOURCE_INVENTORY_BOUND")
    check_capacity(destination.parent, 16 * 1024**2)
    destination.mkdir(mode=0o755)
    inventory = {}
    for entry in entries[:-1]:
        check_clock(deadline)
        header, raw_name = entry.split(b"\t", 1)
        mode, kind, blob = header.decode("ascii").split()
        name = raw_name.decode("utf-8")
        relative = Path(name)
        if (mode not in ("100644", "100755") or kind != "blob" or relative.is_absolute()
                or ".." in relative.parts or ".git" in relative.parts or relative.as_posix() != name
                or re.search(r"[\x00-\x1f\x7f\\]", name) or name in inventory):
            raise VerificationError("SOURCE_ENTRY")
        raw = read_regular(checkout / relative, deadline=deadline)
        if bool((checkout / relative).stat().st_mode & 0o111) != (mode == "100755"):
            raise VerificationError("SOURCE_CHECKOUT_MODE")
        if hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest() != blob:
            raise VerificationError("SOURCE_BLOB_MISMATCH")
        target = destination / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        create_file(target, raw, mode=0o555 if mode == "100755" else 0o444, deadline=deadline)
        inventory[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "git_mode": mode}
    freeze_tree(destination, deadline=deadline)
    return inventory, {"commit": actual, "tree": tree, "files": len(inventory)}


def freeze_tree(root: Path, *, deadline: float, link_roots: tuple[Path, ...] = ()) -> None:
    """Root makes a genuinely quiescent owned tree read-only, never follows links."""
    if root.resolve(strict=True) != root or not stat.S_ISDIR(root.lstat().st_mode):
        raise VerificationError("FREEZE_ROOT_NOT_DIRECTORY")
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        check_clock(deadline)
        for name in dirs + files:
            path = Path(directory) / name
            value = path.lstat()
            if stat.S_ISLNK(value.st_mode):
                target = path.resolve(strict=True)
                if not link_roots or not any(target == allowed or target.is_relative_to(allowed)
                                              for allowed in link_roots):
                    raise VerificationError("FREEZE_UNAPPROVED_LINK")
                os.chown(path, 0, 0, follow_symlinks=False)
                continue  # Standard venv links stay links; immutable parents bind names.
            if not (stat.S_ISDIR(value.st_mode) or stat.S_ISREG(value.st_mode)):
                raise VerificationError("FREEZE_SPECIAL_FILE")
            if stat.S_ISREG(value.st_mode) and value.st_nlink != 1:
                raise VerificationError("FREEZE_HARDLINK")
            os.chown(path, 0, 0, follow_symlinks=False)
            os.chmod(path, 0o555 if stat.S_ISDIR(value.st_mode) or value.st_mode & 0o111 else 0o444)
        os.chown(directory, 0, 0)
        os.chmod(directory, 0o555)


def verify_source(root: Path, inventory: dict, *, deadline: float, generated: bool = False) -> None:
    if root.resolve(strict=True) != root or not stat.S_ISDIR(root.lstat().st_mode):
        raise VerificationError("SOURCE_ROOT_NOT_DIRECTORY")
    actual = set()
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        check_clock(deadline)
        for name in dirs + files:
            path = Path(directory) / name
            if path.is_symlink():
                raise VerificationError("SOURCE_SYMLINK")
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if generated and (relative.startswith("build/") or relative.startswith("src/mobile_release_kit.egg-info/")):
                continue
            actual.add(relative)
            expected = inventory.get(relative)
            if expected is None:
                raise VerificationError("SOURCE_UNEXPECTED_FILE")
            raw = read_regular(path, deadline=deadline)
            if len(raw) != expected["bytes"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]:
                raise VerificationError("SOURCE_CONTENT_DRIFT")
            if bool(path.stat().st_mode & 0o111) != (expected["git_mode"] == "100755"):
                raise VerificationError("SOURCE_MODE_DRIFT")
    if actual != set(inventory):
        raise VerificationError("SOURCE_INVENTORY_DRIFT")


def walk_error(_error: OSError) -> None:
    raise VerificationError("FILESYSTEM_WALK_FAILED")


def copy_build(source: Path, destination: Path, inventory: dict, uid: int, gid: int, *, deadline: float) -> None:
    destination.mkdir(mode=0o700)
    for relative, expected in inventory.items():
        check_clock(deadline)
        path = destination / relative
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        data = read_regular(source / relative, deadline=deadline)
        if hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise VerificationError("BUILD_COPY_SOURCE_CHANGED")
        create_file(path, data, mode=0o755 if expected["git_mode"] == "100755" else 0o644, deadline=deadline)
    for directory, dirs, files in os.walk(destination, followlinks=False, onerror=walk_error):
        check_clock(deadline)
        for name in files:
            os.chown(Path(directory) / name, uid, gid)
        os.chown(directory, uid, gid)


def validate_inputs(root: Path, value: dict, *, deadline: float) -> dict:
    """Validate only the live return of the original DATA producer, not inputs.json."""
    files = value["files"]
    expected = {item["path"]: item for item in files}
    if len(expected) != len(files) or not 100 <= len(files) <= 150:
        raise VerificationError("INPUT_INVENTORY_BOUND")
    actual = set()
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
        check_clock(deadline)
        for name in dirs + names:
            if (Path(directory) / name).is_symlink():
                raise VerificationError("INPUT_SYMLINK")
        actual.update((Path(directory) / name).relative_to(root).as_posix() for name in names)
    if actual != set(expected):
        raise VerificationError("INPUT_INVENTORY_MISMATCH")
    for name, item in expected.items():
        path = root / name
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise VerificationError("INPUT_PATH")
        raw = read_regular(path, deadline=deadline, maximum=16 * 1024**2)
        if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise VerificationError("INPUT_BYTES_CHANGED")
    if value["actionlint"] is not None:
        os.chmod(root / value["actionlint"], 0o555)
    freeze_tree(root, deadline=deadline)
    return {"files": len(files), "bytes": sum(item["bytes"] for item in files),
            "tools_sha256": value["manifest_sha256"], "lock_sha256": value["lock_sha256"]}


def parse_capture(step: Step, result, paths: Paths, platform: str, checks) -> CheckResult:
    if (not result.ok or type(result.returncode) is not int or result.returncode != 0
            or result.waited is not True or result.stdout_eof is not True or result.stderr_eof is not True
            or result.domain_finality is not True or result.primary_error is not None or result.cleanup_errors):
        raise VerificationError("COMMAND_EXIT_OR_FINALITY")
    stdout = result.stdout.decode("utf-8", "strict")
    stderr = result.stderr.decode("utf-8", "strict")
    details = {"returncode": result.returncode, "stdout_bytes": len(result.stdout),
               "stderr_bytes": len(result.stderr), "seconds": round(result.duration, 3)}
    if step.parser == "minitest":
        matches = re.findall(r"(?m)^(\d+) runs, (\d+) assertions, (\d+) failures, (\d+) errors, (\d+) skips\s*$", stdout)
        if len(matches) != 1:
            raise VerificationError("MINITEST_RESULT_MISSING")
        runs, assertions, failures, errors, skips = map(int, matches[0])
        if runs != step.expected_tests or assertions < 1 or failures or errors or skips:
            raise VerificationError("MINITEST_RESULT_REJECTED")
        completed = re.findall(r"(?m)^([A-Za-z0-9_:]+#test_[A-Za-z0-9_]+)\s*=.*?\s=\s\.\s*$", stdout)
        expected = ruby_expected_ids(paths.source, step.id)
        if len(completed) != runs or len(expected) != runs or tuple(sorted(completed)) != expected:
            raise VerificationError("MINITEST_COMPLETION_INVENTORY")
        details.update(tests=runs, assertions=assertions, completed=completed)
    elif step.parser == "supply":
        if stdout != "locked Fastlane Supply WIF contract: PASS\n":
            raise VerificationError("SUPPLY_RESULT")
    elif step.parser == "native":
        expected = checks.expected_python_ids(paths.source, "native")
        footers = re.findall(r"(?m)^Ran (\d+) tests? in [0-9.]+s\s*$", stderr)
        if footers != [str(len(expected))] or not re.search(r"(?m)^OK\s*$", stderr) or "skipped" in stderr:
            raise VerificationError("NATIVE_PYTHON_RESULT")
        completed = re.findall(r"(?m)^(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\) \.\.\. ok\s*$", stderr)
        observed = tuple(sorted(owner if owner.endswith("." + name) else f"{owner}.{name}"
                                for name, owner in completed))
        if observed != expected:
            raise VerificationError("NATIVE_PYTHON_INVENTORY")
        details.update(tests=len(expected), completed=list(observed))
    elif step.parser == "xcode":
        if stdout.strip().splitlines() != ["Xcode 26.3", "Build version 17C529"]:
            raise VerificationError("XCODE_VERSION")
        details["version"] = "Xcode26.3/17C529"
    elif step.parser == "check":
        lines = [line[len("MRK_CHECK_RESULT="):] for line in stdout.splitlines() if line.startswith("MRK_CHECK_RESULT=")]
        if len(lines) != 1 or len(lines[0]) > 256 * 1024:
            raise VerificationError("CHECK_SUMMARY_BOUND")
        summary = strict_json(lines[0])
        if (type(summary) is not dict or set(summary) != {"check", "ok", "tests", "details"}
                or summary.get("check") != step.id or summary.get("ok") is not True
                or type(summary["tests"]) is not list or type(summary["details"]) is not dict):
            raise VerificationError("CHECK_SUMMARY_REJECTED")
        # The source-anchored entrypoint checks actual methods/outcomes; parent
        # independently verifies expected complete identities after real finality.
        if step.id in ("python-full", "python-wheel"):
            selection = "full" if step.id == "python-full" else "wheel"
            expected = checks.expected_python_ids(paths.source, selection)
            tests = summary.get("tests")
            if type(tests) is not list or tuple(sorted(row["id"] for row in tests)) != expected:
                raise VerificationError("PYTHON_COMPLETION_INVENTORY")
            allowed = checks.linux_allowed_skips() if platform == "linux" and selection == "full" else frozenset()
            skips = {row["id"] for row in tests if row["outcome"] == "skip"}
            if skips != allowed or any(row["outcome"] not in ("ok", "skip") for row in tests):
                raise VerificationError("PYTHON_UNEXPECTED_SKIP_OR_FAILURE")
        details["summary"] = summary
    elif step.parser != "exit":
        raise VerificationError("UNKNOWN_RESULT_PARSER")
    return CheckResult(True, details)


def strict_json(text: str):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise VerificationError("JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    def constant(_value):
        raise VerificationError("JSON_NONFINITE")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def failure_details(result, step: Step | None = None, paths: Paths | None = None) -> dict:
    """Public-safe observations only; never forward raw child diagnostics."""
    value = {"returncode": result.returncode, "waited": result.waited,
             "stdout_eof": result.stdout_eof, "stderr_eof": result.stderr_eof,
             "domain_finality": result.domain_finality, "timed_out": result.timed_out,
             "cancelled": result.cancelled, "stdout_bytes": len(result.stdout),
             "stderr_bytes": len(result.stderr), "persisted": list(result.persisted),
             "seconds": round(result.duration, 3), "cleanup_error_count": len(result.cleanup_errors)}
    # These are fixed source file/line and exception-class observations, not
    # raw exceptions, fixture logs, private paths, environment or signing data.
    text = result.stderr.decode("utf-8", "replace")
    value["locations"] = [[name, int(line)] for name, line in re.findall(
        r'File "[^"\r\n]*/(ci_sandbox\.py|ci_checks\.py)", line ([0-9]{1,6})', text)][-8:]
    value["exception_types"] = re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception)):", text)[-8:]
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        if not line.startswith("MRK_CHECK_RESULT=") or len(line) > 256 * 1024:
            continue
        try:
            data = strict_json(line.split("=", 1)[1])
            if type(data) is not dict or type(data.get("details")) is not dict:
                continue
            detail = data["details"]
            code = detail.get("error")
            if type(code) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", code):
                value["helper_error"] = code
            locations = detail.get("failure_locations", [])
            value["helper_locations"] = [row for row in locations if type(row) is dict
                and set(row) == {"file", "line"} and type(row["file"]) is str
                and re.fullmatch(r"(?:tests/|src/|\.github/scripts/)[A-Za-z0-9_./-]{1,180}", row["file"])
                and ".." not in Path(row["file"]).parts and type(row["line"]) is int and 0 < row["line"] < 1000000][-16:]
        except (ValueError, KeyError, TypeError, VerificationError, RecursionError):
            pass
    if step is not None and paths is not None and step.parser == "minitest":
        try:
            expected = set(ruby_expected_ids(paths.source, step.id))
            text = result.stdout.decode("utf-8", "replace")
            # Only source-known test IDs and first-party relative locations.
            # Exception messages, assertion values and raw captures stay private.
            failed = re.findall(r"(?m)^([A-Za-z0-9_:]+#test_[A-Za-z0-9_]+)(?: \[[^\r\n]{1,512}\])?:\s*$", text)
            value["failed_tests"] = sorted(expected.intersection(failed))
            allowed = {"tests/workflow/" + row[1] for row in RUBY_SUITES}
            allowed.update("tests/workflow/" + name for name in
                           ("upload_process_fixture.rb", "upload_process_ownership.rb"))
            allowed.update("fastlane/" + name for name in
                           ("native_upload_validation.rb", "ios_upload_validation.rb",
                            "android_upload_validation.rb", "release_support.rb"))
            locations = re.findall(r"((?:tests/workflow|fastlane)/[A-Za-z0-9_]+\.rb):([1-9][0-9]{0,5})", text)
            value["ruby_locations"] = sorted({(name, int(line)) for name, line in locations
                                                if name in allowed})[:32]
            footers = re.findall(r"(?m)^(\d{1,9}) runs, (\d{1,9}) assertions, (\d{1,9}) failures, "
                                 r"(\d{1,9}) errors, (\d{1,9}) skips\s*$", text)
            value["minitest_observations"] = [list(map(int, row)) for row in footers[:2]]
        except (VerificationError, OSError, UnicodeError):
            value["ruby_diagnostics_unavailable"] = True
    return value


def canonical_directory(value: Path) -> Path:
    if not value.is_absolute():
        raise VerificationError("ABSOLUTE_DIRECTORY_REQUIRED")
    result = value.resolve(strict=True)
    if not stat.S_ISDIR(result.lstat().st_mode):
        raise VerificationError("DIRECTORY_REQUIRED")
    return result


def make_layout(paths: Paths, session, *, deadline: float) -> None:
    """Hold the immutable children's parent; only designated leaves are mutable.

    Root ownership of child files alone is insufficient if the subject can
    rename their parent entries. Admission uses its initial private work tree;
    before project execution root permanently takes custody of its top level.
    """
    session.ensure_idle()
    os.chown(paths.work, 0, 0)
    os.chmod(paths.work, 0o755)
    for name in ("source-venv", "wheel-venv", "bundler", "bundle", "gem-cache",
                 "bundle-config", "bundle-home", "wheels", "checks"):
        check_clock(deadline)
        path = paths.work / name
        path.mkdir(mode=0o700)
        os.chown(path, session.uid, session.gid)


def inspect_editable(paths: Paths, *, deadline: float) -> dict:
    site = paths.work / "source-venv/lib/python3.11/site-packages"
    metadata = site / f"mobile_release_kit-{paths.version}.dist-info"
    direct = strict_json(read_regular(metadata / "direct_url.json", deadline=deadline).decode("utf-8"))
    if direct != {"dir_info": {"editable": True}, "url": (paths.work / "source-build").as_uri()}:
        raise VerificationError("EDITABLE_ORIGIN")
    pth = site / f"__editable__.mobile_release_kit-{paths.version}.pth"
    if read_regular(pth, deadline=deadline) != (str(paths.work / "source-build/src") + "\n").encode("utf-8"):
        raise VerificationError("EDITABLE_PROJECTION")
    return {"editable": True, "backend": "setuptools==80.9.0", "source_copy": "source-build/src"}


def validate_tool_permissions(prefixes: tuple[Path, ...], session, *, deadline: float) -> None:
    """Provider runtimes are trusted, but the numerical subject cannot edit them.

    This is a bounded permissions check, not a homemade OS/package source map.
    System runtime symlinks are allowed; their actual destinations are checked.
    """
    count = 0
    for root in prefixes:
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
            check_clock(deadline)
            for path in (Path(directory), *(Path(directory) / name for name in dirs + files)):
                count += 1
                if count > 100000:
                    raise VerificationError("PROVIDER_RUNTIME_INVENTORY_BOUND")
                info = path.stat()  # Provider-controlled links, not mutable outputs.
                if (info.st_uid == session.uid or info.st_mode & 0o002
                        or info.st_gid == session.gid and info.st_mode & 0o020):
                    raise VerificationError("PROVIDER_RUNTIME_SUBJECT_WRITABLE")


def tool_evidence(paths: Paths, session, platform: str, *, deadline: float) -> dict:
    validate_tool_permissions(session.tool_prefixes, session, deadline=deadline)
    data = {"python": {"version": sys.version.split()[0], "sha256": hashlib.sha256(
                read_regular(paths.python, deadline=deadline, maximum=64 * 1024**2)).hexdigest()},
            "ruby": {"sha256": hashlib.sha256(read_regular(paths.ruby, deadline=deadline,
                                                             maximum=64 * 1024**2)).hexdigest()}}
    ruby = session.run([str(paths.ruby), "--version"], cwd=paths.work,
                       env=dict(environment(paths, platform)), seconds=15)
    version = ruby.stdout.decode("utf-8", "strict").strip()
    if not ruby.ok or ruby.stderr or not re.fullmatch(r"ruby 3\.3\.12 \([^\r\n]{1,150}\) \[[A-Za-z0-9_.-]+\]", version):
        raise VerificationError("RUBY_VERSION_OR_FINALITY")
    data["ruby"]["version"] = version
    data["platform"] = dict(zip(("system", "node", "release", "version", "machine"), os.uname()))
    data["platform"].pop("node")  # A host name is not useful public evidence.
    return data


def perform_step(step: Step, paths: Paths, session, checks, inventory: dict,
                 platform: str, *, deadline: float) -> CheckResult:
    check_clock(deadline)
    session.ensure_idle()
    # Allow room for this gate's finite install/build rather than filling the VM.
    check_capacity(paths.work, 1024**3 if step.id in {"bundle-install", "wheel-build"} else 64 * 1024**2)
    if step.kind == "command":
        value = session.run(list(step.argv), cwd=step.cwd, env=dict(step.env), seconds=step.seconds,
                            output_limit=(16 if "install" in step.id or step.id == "source-dependencies" else 8) * 1024**2,
                            cpu_seconds=300 if step.id in {"bundle-install", "wheel-build", "python-full"} else 180)
        if not value.ok:
            return CheckResult(False, failure_details(value, step, paths), "COMMAND_EXIT_OR_FINALITY")
        try:
            return parse_capture(step, value, paths, platform, checks)
        except VerificationError as exc:
            return CheckResult(False, failure_details(value, step, paths), exc.code)
    if step.kind != "inspection":
        raise VerificationError("UNKNOWN_GATE_KIND")
    details = {}
    if step.id in {"source-copy", "wheel-copy"}:
        destination = paths.work / ("source-build" if step.id == "source-copy" else "wheel-build")
        copy_build(paths.source, destination, inventory, session.uid, session.gid, deadline=deadline)
        details = {"files": len(inventory)}
    elif step.id == "source-freeze":
        verify_source(paths.work / "source-build", inventory, generated=True, deadline=deadline)
        # Seal all installed code AND root-owned parent names before any test.
        for name in ("source-build", "source-venv", "bundler", "bundle"):
            current = paths.work / name
            links = (current, *session.tool_prefixes) if name != "source-build" else ()
            freeze_tree(current, deadline=deadline, link_roots=links)
        details = inspect_editable(paths, deadline=deadline)
    elif step.id == "wheel-inspect":
        freeze_tree(paths.work / "wheels", deadline=deadline)
        if list((paths.work / "wheels").iterdir()) != [paths.wheel]:
            raise VerificationError("WHEEL_OUTPUT_INVENTORY")
        details = checks.inspect_project_wheel(paths.wheel, paths.source, deadline=deadline)
    elif step.id == "wheel-freeze":
        current = paths.work / "wheel-venv"
        freeze_tree(current, deadline=deadline, link_roots=(current, *session.tool_prefixes))
    elif step.id == "wheel-consumer":
        details = checks.inspect_wheel_consumer(paths.work / "checks/wheel-consumer", paths.source, deadline=deadline)
    elif step.id == "source-integrity":
        verify_source(paths.source, inventory, deadline=deadline)
        verify_source(paths.work / "source-build", inventory, generated=True, deadline=deadline)
        verify_source(paths.work / "wheel-build", inventory, generated=True, deadline=deadline)
        details = {"files": len(inventory), "golden_and_build_copies": True}
    else:
        raise VerificationError("UNIMPLEMENTED_INSPECTION")
    check_clock(deadline)
    return CheckResult(True, details)


def error_details(exc: BaseException) -> dict:
    frames = traceback.extract_tb(exc.__traceback__)
    return {"error": exc.code if isinstance(exc, VerificationError) else "CONTROLLER_FAILURE",
            "exception": type(exc).__name__,
            "location": [Path(frames[-1].filename).name, frames[-1].lineno] if frames else []}


def publish_summary(path: Path, report: dict, *, runner_temp: Path, deadline: float) -> None:
    check_clock(deadline)
    if (path.resolve(strict=True) != path or not path.is_relative_to(runner_temp)
            or not re.fullmatch(r"step_summary_[A-Za-z0-9_-]+", path.name)):
        raise VerificationError("SUMMARY_DESTINATION")
    encoded = json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(encoded) > 768 * 1024:
        raise VerificationError("PUBLIC_SUMMARY_BOUND")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        check_clock(deadline)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 128 * 1024:
            raise VerificationError("SUMMARY_FILE_STATE")
        text = b"## Mobile Release Kit isolated verification\n\n```json\n" + encoded + b"\n```\n"
        pending = memoryview(text)
        while pending:
            check_clock(deadline)
            count = os.write(fd, pending[:65536])
            if not 0 < count <= min(len(pending), 65536):
                raise VerificationError("SUMMARY_SHORT_WRITE")
            pending = pending[count:]
        os.fsync(fd)
        check_clock(deadline)
    finally:
        close_owned(fd)
    check_clock(deadline)
    # Only this sanitized report, never raw private captures, enters job logs.
    print("MRK_CI_RESULT=" + encoded.decode("ascii"), flush=True)
    check_clock(deadline)


def finalize_report(report: dict, session, *, summary: Path | None, runner_temp: Path | None,
                    start: float, deadline: float) -> int:
    """Final close, publication and timer restoration cannot turn failure green."""
    def fail(exc: BaseException, *, cleanup: bool = False) -> None:
        report["ok"] = False
        if cleanup:
            report["cleanup_errors"].append(error_details(exc))
        elif "error" not in report:
            report.update(error_details(exc))

    try:
        if session is not None:
            try:
                # Keep the original independent alarm during final publication.
                session.close(keep_timer=True)
                check_clock(deadline)
            except BaseException as exc:
                fail(exc, cleanup=True)
            report["finality"] = session.domain_finality
            report["persisted_capture_bytes"] = session.persisted_bytes
            if session.domain_finality is not True or session.failure is not None or session.cleanup_errors:
                report["cleanup_errors"].append({"session_cleanup_error_count": len(session.cleanup_errors)})
                report["ok"] = False
        elif report["ok"]:
            raise VerificationError("SUCCESS_WITHOUT_ORIGINAL_SESSION")
        report["seconds"] = round(time.monotonic() - start, 3)
        if summary is None or runner_temp is None:
            raise VerificationError("NO_SAFE_SUMMARY_DESTINATION")
        publish_summary(summary, report, runner_temp=runner_temp, deadline=deadline)
    except BaseException as exc:
        fail(exc)
        print("MRK_CI_PUBLICATION_FAILED=" + json.dumps(error_details(exc), sort_keys=True), flush=True)
    finally:
        if session is not None:
            try:
                session.finish()
            except BaseException as exc:
                fail(exc, cleanup=True)
                print("MRK_CI_FINAL_CLEANUP_FAILED=" + json.dumps(error_details(exc), sort_keys=True), flush=True)
            if session.failure is not None or session.cleanup_errors:
                report["ok"] = False
        try:
            check_clock(deadline)
        except BaseException as exc:
            fail(exc)
            print("MRK_CI_FINAL_DEADLINE_FAILED", flush=True)
    return 0 if report["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--platform", choices=("linux", "macos"), required=True)
    for name in ("source", "python", "ruby", "runner-home", "runner-temp", "summary"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("commit", "run-id", "run-attempt", "image"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--java-home", type=Path)
    args = parser.parse_args(argv)
    start = time.monotonic()
    deadline = start + AGGREGATE_SECONDS
    session = None
    report = {"schema": 1, "ok": False, "platform": args.platform, "rows": [], "cleanup_errors": []}
    runner_temp = summary = None
    try:
        if (os.getuid() != 0 or os.geteuid() != 0 or not sys.flags.isolated or not sys.flags.dont_write_bytecode
                or sys.version_info[:2] != (3, 11)
                or sys.platform != {"linux": "linux", "macos": "darwin"}[args.platform]):
            raise VerificationError("ROOT_HOSTED_PYTHON_PLATFORM_REQUIRED")
        if (not re.fullmatch(r"[1-9][0-9]{0,19}", args.run_id)
                or not re.fullmatch(r"[1-9][0-9]{0,5}", args.run_attempt)
                or not re.fullmatch(r"[A-Za-z0-9_.+/-]{1,100}", args.image)
                or not re.fullmatch(r"[0-9a-f]{40}", args.commit)):
            raise VerificationError("HOSTED_RUN_BINDING")
        os.umask(0o077)
        checkout = canonical_directory(args.source)
        runner_home = canonical_directory(args.runner_home)
        runner_temp = canonical_directory(args.runner_temp)
        summary = args.summary.resolve(strict=True)
        python, ruby = args.python.resolve(strict=True), args.ruby.resolve(strict=True)
        if python != Path(sys.executable).resolve() or python.parent.name != "bin" or ruby.parent.name != "bin":
            raise VerificationError("TRUSTED_RUNTIME_BINDING")
        if (args.platform == "linux") != (args.java_home is not None):
            raise VerificationError("PLATFORM_TOOL_CONTRACT")
        java = canonical_directory(args.java_home) if args.java_home else None
        prefixes = tuple(dict.fromkeys((Path(sys.base_prefix).resolve(strict=True), ruby.parent.parent,
                                       *((java,) if java else ()))))
        parent = Path("/tmp" if args.platform == "linux" else "/private/tmp")
        check_capacity(parent, 256 * 1024**2)
        root = Path(tempfile.mkdtemp(prefix=f"mrk-ci-{args.run_id}-{args.run_attempt}-", dir=parent))
        os.chmod(root, 0o755)
        inventory, source_binding = snapshot_source(checkout, root / "source", args.commit, deadline=deadline)
        report.update(source=source_binding, run_id=args.run_id, run_attempt=args.run_attempt, image=args.image)
        directory = root / "source/.github/scripts"
        sandbox = _module(directory, "ci_sandbox")
        prepare = _module(directory, "ci_prepare")
        checks = _module(directory, "ci_checks")
        session = sandbox.Session("linux" if args.platform == "linux" else "darwin", root,
                                  python=python, ruby=ruby, runner_home=runner_home, runner_temp=runner_temp,
                                  tool_prefixes=prefixes, deadline=deadline)
        paths = Paths(root / "source", session.work, root / "inputs", python, ruby, java_home=java)
        steps = catalog(paths, args.platform, deadline=deadline)
        report["rows"] = [{"id": step.id, "status": "UNEXECUTED"} for step in steps]
        report["phase"] = "input-preparation"
        produced = prepare.prepare_inputs(source_root=paths.source, destination=paths.inputs,
                                          platform=args.platform, deadline=deadline)
        report["inputs"] = validate_inputs(paths.inputs, produced, deadline=deadline)
        report["phase"] = "native-admission"
        session.admit()
        report["admission"] = session.admission_results
        make_layout(paths, session, deadline=deadline)
        report["tools"] = tool_evidence(paths, session, args.platform, deadline=deadline)
        report["phase"] = "product-gates"

        def perform(step):
            print("MRK_CI_GATE=" + step.id, flush=True)
            return perform_step(step, paths, session, checks, inventory, args.platform, deadline=deadline)

        result = execute_pipeline(steps, perform, platform=args.platform)
        report["rows"] = list(result.rows)
        if not result.ok:
            raise VerificationError(result.error or "PIPELINE_FAILED")
        session.ensure_idle()
        # The checkout has never been a project execution or mutable output root.
        git = ("/usr/bin/git", "-c", f"safe.directory={checkout}", "-C", str(checkout))
        if trusted_command((*git, "status", "--porcelain=v1", "--untracked-files=all"), deadline=deadline):
            raise VerificationError("ORIGINAL_CHECKOUT_CHANGED")
        if trusted_command((*git, "rev-parse", "HEAD"), deadline=deadline).strip().decode() != args.commit:
            raise VerificationError("ORIGINAL_CHECKOUT_COMMIT_CHANGED")
        # No walk/removal until all actual subject writers are gone. Python's
        # descriptor-relative rmtree never follows a project-created symlink.
        if not shutil.rmtree.avoids_symlink_attacks:
            raise VerificationError("SAFE_DISPOSAL_UNAVAILABLE")
        for disposable in (paths.work, paths.inputs):
            check_clock(deadline)
            shutil.rmtree(disposable)
        report["disposal"] = {"work_and_inputs_removed": True, "private_control": "VM-disposal"}
        check_clock(deadline)
        report["ok"] = True
    except BaseException as exc:
        report.update(error_details(exc))
        report["ok"] = False
        if session is not None:
            session.fail(report["error"])
            report["admission"] = session.admission_results
    return finalize_report(report, session, summary=summary, runner_temp=runner_temp,
                           start=start, deadline=deadline)


if __name__ == "__main__":
    raise SystemExit(main())
