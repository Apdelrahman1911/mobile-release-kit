"""Fixed product checks for the reviewed, disposable CI sandbox.

Importing this module neither imports the product nor starts a process.  The
archive, consumer and AST validators are also used by the outside-identity
controller *after* producer finality.  CLI modes run only inside that boundary;
their JSON is an observation, never authority for exit, EOF or domain cleanup.
There is deliberately no generic command mode, receipt file or renewed budget.
"""
from __future__ import annotations

import argparse
import ast
import base64
import contextlib
import csv
import email.parser
import hashlib
import importlib
import importlib.metadata
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import stat
import subprocess
import sys
import sysconfig
import time
import tomllib
import traceback
import unittest
import zipfile


VERSION = "0.3.0"
RESULT_PREFIX = "MRK_CHECK_RESULT="
CHECKS = ("python-full", "python-wheel", "wheel-smoke", "jdk-signers")
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_WHEEL_BYTES = 64 * 1024 * 1024
MAX_TREE_ENTRIES = 2048
MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_RESULT_BYTES = 256 * 1024
WHEEL_PATTERNS = (
    "test_init_transaction.py", "test_ios_entitlements.py", "test_ios_plist_binary.py",
)
NATIVE_PATTERNS = (
    "test_ios_profile_authority.py", "test_ios_profile_trust.py",
    "test_ios_profile_installation.py", "test_default_cancellation.py",
    "test_profile_processes.py", "test_macho_native.py",
)
# Exact method identities, not a count, file-wide exemption or skip-message match.
LINUX_MACOS_SKIPS = frozenset({
    "unit.test_ios_profile_authority.NativeProfileAuthorityTests.test_actual_signature_integrity_and_exact_signer_are_checked_before_policy",
    "unit.test_ios_profile_authority.NativeProfileAuthorityTests.test_complete_two_layer_synthetic_signature_succeeds_only_with_explicit_policy_seam",
    "unit.test_ios_profile_authority.NativeProfileAuthorityTests.test_default_policy_rejects_even_valid_signature_with_production_looking_fake_issuer",
    "unit.test_ios_profile_authority.NativeProfileAuthorityTests.test_real_production_policy_accepts_apple_public_issuer_not_test_or_macos_purpose",
    "unit.test_ios_profile_authority.NativeProfileAuthorityTests.test_signed_outer_cannot_authorize_unsigned_or_substituted_inner_profile",
    "unit.test_macho_native.NativeMachOTests.test_real_dsym_and_independently_valid_different_build_pair_rejected",
    "unit.test_macho_native.NativeMachOTests.test_real_fat_resigning_relocates_slices_without_changing_images",
    "unit.test_macho_native.NativeMachOTests.test_real_native_der_and_nonhost_slice_entitlement_mismatch",
    "unit.test_macho_native.NativeMachOTests.test_real_resigned_same_uuid_changed_code_or_linkedit_remains_different",
    "unit.test_macho_native.NativeMachOTests.test_real_sdk_support_copy_unsigned_to_signed_keeps_vendor_original",
    "unit.test_macho_native.NativeMachOTests.test_real_unsigned_and_signature_growth_shrink_with_residual_slack",
    "unit.test_macho_native.NativePlistTests.test_native_binary_invalid_markers_and_spans_are_rejected_before_conversion",
    "unit.test_macho_native.NativePlistTests.test_native_data_reference_divergence_is_rejected_not_normalized",
    "unit.test_macho_native.NativePlistTests.test_native_date_bits_and_wide_integer_semantics_are_not_rounded_into_equality",
    "unit.test_macho_native.NativePlistTests.test_native_original_numeric_reference_eight_nine_digit_boundary",
    "unit.test_macho_native.NativePlistTests.test_native_real_bits_preserve_signed_zero_width_and_finite_boundaries",
    "unit.test_macho_native.NativePlistTests.test_supported_lexical_values_match_actual_native_binary_conversion",
})
TOOLING_FILES = (
    "Gemfile", "Gemfile.lock", "fastlane/Fastfile", "fastlane/play_store.rb",
    "fastlane/apple_store.rb", "fastlane/apple_production.rb", "fastlane/apple_asset_upload.rb",
    "fastlane/apple_create_retry.rb", "fastlane/ios_upload_validation.rb",
    "fastlane/android_upload_validation.rb", "fastlane/native_upload_validation.rb",
    "fastlane/release_support.rb", "fastlane/run_lane.rb", "schemas/candidate.schema.json",
    "schemas/project.schema.json", "schemas/receipt.schema.json",
    "schemas/store-operation-intent.schema.json", "templates/mobile-release.json",
    "templates/workflows/mobile-candidate.yml", "templates/workflows/mobile-external-testing.yml",
    "templates/workflows/mobile-preflight.yml", "templates/workflows/mobile-production-submit.yml",
)
TEST_REQUIREMENTS = (
    "attrs==26.1.0", "jsonschema==4.25.1", "jsonschema-specifications==2025.9.1",
    "referencing==0.36.2", "rpds-py==0.27.1",
    "typing-extensions==4.16.0; python_version < '3.13'",
)
LICENSE_SHA256 = "7d381db63decbfe663092a8537c1a1c1a9121d60ffe5938f401ad1346bdf9148"
APPLE_ROOTS_SHA256 = "c704ce9bc7d65280e2893c2235c2434dba8cbce00f659787492714ca441b1e93"
IGNORE_LINES = (
    ".mobile-release/", ".mobile-release-init-prepare/", ".mobile-release-init/",
    ".mobile-release-init-cleanup/",
)
SKELETON_FILES = (
    "title.txt", "short_description.txt", "full_description.txt", "changelogs/default.txt",
)
ANDROID_FIXTURE = (
    b'plugins { id("com.android.application") }\n'
    b'android { namespace = "com.example.wheelsmoke"; defaultConfig { applicationId = "com.example.wheelsmoke" } }\n'
)
TOOLING_REPOSITORY = "example/mobile-release-kit"
TOOLING_SHA = "1" * 40
HELP_OPTIONS = {
    "workflow": {"--help"},
    "android_upload_validation": {"--aab", "--app-root", "--config-path", "--help", "--intent-sha256", "--operation-intent"},
    "ios_upload_validation": {"--ipa", "--app-root", "--config-path", "--help", "--intent-sha256", "--operation-intent"},
}
JDK_CASES = (
    ("outside-warning-window", "-1d", "209", True),
    ("inside-warning-window", "-1d", "178", False),
    ("expired", "-400d", "200", False),
    ("not-yet-valid", "+1d", "365", False),
)
JDK_DIAGNOSTICS = {
    "inside-warning-window": "This jar contains entries whose signer certificate will expire within six months.",
    "expired": "This jar contains entries whose signer certificate has expired.",
    "not-yet-valid": "This jar contains entries whose signer certificate is not yet valid.",
}
JDK_PASSWORD_NAME = "MRK_SYNTHETIC_PASSWORD"
JDK_PASSWORD = "disposable-test-password"  # Public synthetic fixture, not a credential.
JDK_POLICY_REJECTION = "jarsigner rejected the final AAB signature or signed content"
JAVA_OPTIONS = (
    "-Xms32m", "-Xmx256m", "-XX:MaxMetaspaceSize=256m",
    "-XX:CompressedClassSpaceSize=128m", "-XX:ReservedCodeCacheSize=128m",
)
INSPECTION_ENVIRONMENT_NAMES = frozenset({
    "CI", "DEVELOPER_DIR", "HOME", "JAVA_HOME", "LANG", "LC_ALL", "LC_CTYPE", "PATH",
    "RUNNER_TEMP", "SDKROOT", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "TZ",
})


class CheckError(RuntimeError):
    """A fixed, public-safe failure code. Raw diagnostics stay in private capture."""

    def __init__(self, code: str, locations=(), *, cleanup_errors=()):
        super().__init__(code)
        self.locations = list(locations)
        self.cleanup_errors = list(cleanup_errors)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise CheckError(code)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _exact(left: object, right: object) -> bool:
    return _json_bytes(left) == _json_bytes(right)


def _json(data: bytes) -> object:
    _require(type(data) is bytes and 0 < len(data) <= MAX_FILE_BYTES, "JSON_SIZE")

    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    def constant(_value):
        raise CheckError("JSON_NONFINITE")

    return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=constant)


def _read_regular(path: Path, maximum: int = MAX_FILE_BYTES, *, deadline: float | None = None) -> bytes:
    if deadline is not None:
        _remaining(deadline, 3300)
    descriptor, primary, cleanup_error, data = None, None, None, None
    try:
        # Keep custody of the original descriptor: fdopen construction itself
        # can fail, and a failed close must never cause a retry on a reused FD.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        _require(type(maximum) is int and maximum >= 0 and stat.S_ISREG(info.st_mode)
                 and 0 <= info.st_size <= maximum, "REGULAR_FILE_REQUIRED")
        chunks, remaining = [], info.st_size
        while remaining:
            if deadline is not None:
                _remaining(deadline, 3300)
            chunk = os.read(descriptor, min(65536, remaining))
            _require(type(chunk) is bytes and 0 < len(chunk) <= remaining, "FILE_SIZE_CHANGED")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                                  value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        _require(identity(after) == identity(info), "FILE_SIZE_CHANGED")
        data = b"".join(chunks)
        if deadline is not None:
            _remaining(deadline, 3300)
    except BaseException as error:
        primary = error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_error = error
    if cleanup_error is not None:
        if type(primary) is CheckError:
            primary.cleanup_errors.append("FILE_CLOSE_FAILED")
        elif primary is not None:
            code = "CHECK_INTERRUPTED" if isinstance(primary, (KeyboardInterrupt, SystemExit)) else "FILE_READ_FAILED"
            raise CheckError(code, cleanup_errors=("FILE_CLOSE_FAILED",)) from primary
        else:
            raise CheckError("FILE_CLOSE_FAILED", cleanup_errors=("FILE_CLOSE_FAILED",)) from cleanup_error
    if primary is not None:
        raise primary
    return data


def _tree(root: Path, *, deadline: float) -> tuple[dict[str, bytes], set[str]]:
    """Bounded ordinary-file tree; caller supplies a finalized/quiescent root."""
    _require(root.is_dir() and not root.is_symlink(), "TREE_ROOT")
    files, directories, total, count, pending = {}, set(), 0, 0, [root]
    # scandir is streamed: os.walk would first materialize every name in one
    # directory, before a Python-side entry limit could reject that directory.
    while pending:
        _remaining(deadline, 3300)
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                _remaining(deadline, 3300)
                count += 1
                _require(count <= MAX_TREE_ENTRIES, "TREE_LIMIT")
                path = Path(entry.path)
                info = entry.stat(follow_symlinks=False)
                name = path.relative_to(root).as_posix()
                if stat.S_ISDIR(info.st_mode):
                    directories.add(name)
                    pending.append(path)
                    continue
                _require(stat.S_ISREG(info.st_mode), "TREE_SPECIAL_FILE")
                available = min(MAX_FILE_BYTES, MAX_WHEEL_BYTES - total)
                _require(0 <= info.st_size <= available, "TREE_LIMIT")
                data = _read_regular(path, available, deadline=deadline)
                _require(len(data) == info.st_size and len(data) <= available, "TREE_FILE_CHANGED")
                total += len(data)
                files[name] = data
    return files, directories


def _remaining(deadline: float, maximum: float) -> float:
    _require(type(deadline) is float and math.isfinite(deadline), "DEADLINE_VALUE")
    value = deadline - time.monotonic()
    _require(value > 0, "DEADLINE_EXPIRED")
    return min(value, maximum)


def linux_allowed_skips() -> frozenset[str]:
    return LINUX_MACOS_SKIPS


def expected_python_ids(source_root: Path, selection: str = "full", *, deadline: float | None = None) -> tuple[str, ...]:
    """Statically derive the exact methods; never import or execute a test file.

    Unsupported dynamic/inherited test construction fails rather than reducing
    coverage silently.  This checkout uses direct unittest.TestCase subclasses.
    """
    _require(selection in {"full", "wheel", "native"}, "TEST_SELECTION")
    tests = Path(source_root) / "tests"
    patterns = WHEEL_PATTERNS if selection == "wheel" else NATIVE_PATTERNS
    paths = sorted(tests.rglob("test*.py"))
    if selection != "full":
        paths = [path for path in paths if path.name in patterns]
        _require(sorted(path.name for path in paths) == sorted(patterns), "TEST_PATTERN_INVENTORY")
    result = []
    for path in paths:
        module = ".".join(path.relative_to(tests).with_suffix("").parts)
        parsed = ast.parse(_read_regular(path, deadline=deadline), filename=str(path))
        classes = set()
        module_ids = []
        for node in parsed.body:
            if not isinstance(node, ast.ClassDef):
                continue
            _require(node.name not in classes, "TEST_DUPLICATE_CLASS")
            classes.add(node.name)
            methods = [item.name for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and item.name.startswith("test")]
            if not methods:
                continue
            _require(any(isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name)
                         and base.value.id == "unittest" and base.attr == "TestCase" for base in node.bases),
                     "TEST_UNSUPPORTED_CLASS")
            _require(len(methods) == len(set(methods)), "TEST_DUPLICATE_METHOD")
            module_ids.extend(f"{module}.{node.name}.{method}" for method in methods)
        _require(bool(module_ids), "TEST_EMPTY_MODULE")
        result.extend(module_ids)
    _require(bool(result) and len(result) == len(set(result)), "TEST_EMPTY_OR_DUPLICATE_INVENTORY")
    if selection == "full":
        _require(len(LINUX_MACOS_SKIPS) == 17 and LINUX_MACOS_SKIPS <= set(result), "TEST_NATIVE_INVENTORY_DRIFT")
    return tuple(sorted(result))


def validate_test_outcomes(expected, outcomes, platform: str) -> None:
    _require(platform in {"linux", "darwin", "macos"}, "TEST_PLATFORM")
    _require(type(expected) in {list, tuple} and bool(expected) and len(expected) == len(set(expected)), "TEST_EXPECTED_IDS")
    _require(type(outcomes) is list and len(outcomes) == len(expected), "TEST_OUTCOME_COUNT")
    observed = {}
    for row in outcomes:
        _require(type(row) is dict and set(row) == {"id", "outcome"}, "TEST_OUTCOME_SHAPE")
        identifier, outcome = row["id"], row["outcome"]
        _require(type(identifier) is str and identifier in expected and identifier not in observed, "TEST_OUTCOME_ID")
        _require(type(outcome) is str and outcome in {"ok", "skip"}, "TEST_NOT_SUCCESSFUL")
        observed[identifier] = outcome
    permitted = set(expected) & LINUX_MACOS_SKIPS if platform == "linux" else set()
    _require({identifier for identifier, outcome in observed.items() if outcome == "skip"} == permitted,
             "TEST_UNEXPECTED_OR_MISSING_SKIP")


def _failure_locations(error, source_root: Path) -> list[dict[str, object]]:
    result = []
    for frame in traceback.extract_tb(error[2])[-8:]:
        path = Path(frame.filename)
        if path.is_absolute() and path.is_relative_to(source_root):
            result.append({"file": path.relative_to(source_root).as_posix(), "line": frame.lineno})
        elif path.name == "ci_checks.py":
            result.append({"file": ".github/scripts/ci_checks.py", "line": frame.lineno})
    return result


def run_python_tests(source_root: Path, selection: str, deadline: float, observations: list) -> dict:
    expected = expected_python_ids(source_root, selection, deadline=deadline)
    _remaining(deadline, 3300)
    if selection == "full":
        _require(sys.platform == "linux" and os.environ.get("MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS") == "1",
                 "FULL_DISCOVERY_ENVIRONMENT")
    else:
        inspect_installed_wheel(source_root, deadline=deadline)
    allowed = LINUX_MACOS_SKIPS if sys.platform == "linux" else frozenset()
    failures = []

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            _remaining(deadline, 3300)
            identifier = test.id()
            _require(identifier in expected and identifier not in {item["id"] for item in observations}, "TEST_STARTED_ID")
            observations.append({"id": identifier, "outcome": "incomplete"})
            super().startTest(test)

        def record(self, test, outcome, error=None):
            if error is not None:
                failures.extend(_failure_locations(error, source_root))
            identifier = getattr(test, "test_case", test).id()
            rows = [row for row in observations if row["id"] == identifier]
            if len(rows) != 1:
                self.stop()
                raise CheckError("TEST_EVENT_WITHOUT_START", failures[-16:])
            if rows[0]["outcome"] in {"incomplete", "ok"}:
                rows[0]["outcome"] = outcome
            if outcome not in {"ok", "skip"} or outcome == "skip" and identifier not in allowed:
                self.stop()

        def addSuccess(self, test):
            self.record(test, "ok")
            super().addSuccess(test)

        def addError(self, test, error):
            self.record(test, "error", error)
            super().addError(test, error)

        def addFailure(self, test, error):
            self.record(test, "failure", error)
            super().addFailure(test, error)

        def addSkip(self, test, reason):
            self.record(test, "skip")
            super().addSkip(test, reason)

        def addExpectedFailure(self, test, error):
            self.record(test, "expected-failure", error)
            super().addExpectedFailure(test, error)

        def addUnexpectedSuccess(self, test):
            self.record(test, "unexpected-success")
            super().addUnexpectedSuccess(test)

        def addSubTest(self, test, subtest, error):
            if error is not None:
                self.record(test, "failure" if issubclass(error[0], test.failureException) else "error", error)
            super().addSubTest(test, subtest, error)

    def flatten(suite):
        for test in suite:
            if isinstance(test, unittest.TestSuite):
                yield from flatten(test)
            else:
                yield test.id()

    with contextlib.redirect_stdout(sys.stderr):
        suite = unittest.TestSuite()
        for pattern in ("test*.py",) if selection == "full" else WHEEL_PATTERNS:
            loader = unittest.TestLoader()
            suite.addTests(loader.discover(str(source_root / "tests"), pattern=pattern))
            _require(not loader.errors, "TEST_DISCOVERY_ERROR")
        actual = list(flatten(suite))
        _require(len(actual) == len(set(actual)) and tuple(sorted(actual)) == expected, "TEST_LOADED_INVENTORY")
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, failfast=True, resultclass=Result).run(suite)
    _remaining(deadline, 3300)
    try:
        validate_test_outcomes(expected, observations, sys.platform)
    except CheckError as error:
        error.locations = failures[-16:]
        raise
    _require(result.wasSuccessful() and result.testsRun == len(expected), "TEST_RESULT")
    return {"executed": result.testsRun, "skipped": len(result.skipped), "failure_locations": failures}


def _headers(data: bytes):
    _require(0 < len(data) <= MAX_FILE_BYTES and b"\0" not in data, "WHEEL_METADATA_SIZE")
    value = email.parser.BytesParser().parsebytes(data)
    _require(not value.defects, "WHEEL_METADATA_PARSE")
    return value


def _header(value, name: str, expected: str | None = None) -> str:
    items = value.get_all(name, [])
    _require(len(items) == 1 and type(items[0]) is str and (expected is None or items[0] == expected),
             "WHEEL_METADATA_HEADER")
    return items[0]


def _source_package(source_root: Path, *, deadline: float) -> dict[str, bytes]:
    project = tomllib.loads(_read_regular(source_root / "pyproject.toml", deadline=deadline).decode("utf-8"))
    _require(_exact(project["build-system"], {"requires": ["setuptools==80.9.0"], "build-backend": "setuptools.build_meta"}),
             "SOURCE_BUILD_BACKEND")
    fields = project["project"]
    for key, expected in (("name", "mobile-release-kit"), ("version", VERSION), ("requires-python", ">=3.11"),
                          ("license", "MIT"), ("license-files", ["LICENSE"]), ("dependencies", []),
                          ("optional-dependencies", {"test": list(TEST_REQUIREMENTS)}),
                          ("scripts", {"mobile-release": "mobile_release.cli:main"})):
        _require(_exact(fields.get(key), expected), "SOURCE_PACKAGE_CONTRACT")
    files, directories = _tree(source_root / "src/mobile_release", deadline=deadline)
    _require(directories == {"data"} and "__init__.py" in files and "__main__.py" in files
             and set(files) == {name for name in files if "/" not in name and name.endswith(".py")} | {"data/apple-profile-roots.pem"},
             "SOURCE_PACKAGE_FILES")
    _require(hashlib.sha256(files["data/apple-profile-roots.pem"]).hexdigest() == APPLE_ROOTS_SHA256
             and hashlib.sha256(_read_regular(source_root / "LICENSE", deadline=deadline)).hexdigest() == LICENSE_SHA256,
             "SOURCE_PUBLIC_RESOURCE_PINS")
    return files


def _validate_metadata(metadata, source_root: Path, *, deadline: float) -> None:
    for key, expected in (("Metadata-Version", "2.4"), ("Name", "mobile-release-kit"), ("Version", VERSION),
                          ("Requires-Python", ">=3.11"), ("License-Expression", "MIT"), ("License-File", "LICENSE"),
                          ("Description-Content-Type", "text/markdown")):
        _header(metadata, key, expected)
    _require(metadata.get_all("Provides-Extra", []) == ["test"], "WHEEL_EXTRAS")
    requirements = metadata.get_all("Requires-Dist", [])
    expected = [item + '; extra == "test"' if ";" not in item else item + ' and extra == "test"'
                for item in TEST_REQUIREMENTS]
    normalize = lambda item: re.sub(r"\s+", "", item).replace("'", '"')
    _require(sorted(map(normalize, requirements)) == sorted(map(normalize, expected)), "WHEEL_RUNTIME_OR_UNPINNED_DEPENDENCY")
    project = tomllib.loads(_read_regular(source_root / "pyproject.toml", deadline=deadline).decode("utf-8"))["project"]
    _header(metadata, "Summary", project["description"])
    _header(metadata, "Author", "Mobile Release Kit contributors")
    readme = _read_regular(source_root / "README.md", deadline=deadline)
    # Setuptools writes a final newline after the original long description.
    _require(metadata.get_payload(decode=True) in (readme, readme + b"\n"), "WHEEL_README_BYTES")


def inspect_project_wheel(wheel_path: Path, source_root: Path, *, deadline: float) -> dict:
    """Validate the entire actual build artifact before installing it (data only)."""
    data = _read_regular(Path(wheel_path), MAX_WHEEL_BYTES, deadline=deadline)
    package = _source_package(Path(source_root), deadline=deadline)
    dist = f"mobile_release_kit-{VERSION}.dist-info/"
    shared = f"mobile_release_kit-{VERSION}.data/data/share/mobile-release-kit/"
    expected = {"mobile_release/" + name: value for name, value in package.items()}
    expected.update({shared + name: _read_regular(Path(source_root) / name, deadline=deadline) for name in TOOLING_FILES})
    expected[dist + "licenses/LICENSE"] = _read_regular(Path(source_root) / "LICENSE", deadline=deadline)
    generated = {dist + name for name in ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD")}
    members, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        _require(len(archive.infolist()) <= 2048, "WHEEL_MEMBER_LIMIT")
        for member in archive.infolist():
            _remaining(deadline, 3300)
            name, mode = member.filename, member.external_attr >> 16
            _require(name and name == member.orig_filename and not PurePosixPath(name).is_absolute()
                     and "\\" not in name and all(part not in {"", ".", ".."} for part in name.split("/"))
                     and not any(ord(character) < 32 or ord(character) == 127 for character in name)
                     and not member.is_dir() and not member.flag_bits & 1
                     and stat.S_IFMT(mode) in {0, stat.S_IFREG} and not mode & 0o7000,
                     "WHEEL_UNSAFE_MEMBER")
            _require(name not in members and member.file_size <= MAX_FILE_BYTES, "WHEEL_DUPLICATE_OR_OVERSIZED_MEMBER")
            total += member.file_size
            _require(total <= MAX_WHEEL_BYTES, "WHEEL_EXPANDED_LIMIT")
            members[name] = archive.read(member)
            _require(len(members[name]) == member.file_size, "WHEEL_MEMBER_SIZE")
    _require(set(members) == set(expected) | generated, "WHEEL_COMPLETE_INVENTORY")
    _require(all(members[name] == value for name, value in expected.items()), "WHEEL_FIRST_PARTY_BYTES")
    records = list(csv.reader(io.StringIO(members[dist + "RECORD"].decode("utf-8", "strict")), strict=True))
    _require(len(records) == len(members) and all(len(row) == 3 for row in records)
             and len({row[0] for row in records}) == len(records) and {row[0] for row in records} == set(members),
             "WHEEL_RECORD_INVENTORY")
    for name, digest, size in records:
        _remaining(deadline, 3300)
        if name == dist + "RECORD":
            _require(digest == size == "", "WHEEL_RECORD_SELF")
        else:
            encoded = base64.urlsafe_b64encode(hashlib.sha256(members[name]).digest()).rstrip(b"=").decode("ascii")
            _require(digest == "sha256=" + encoded and size == str(len(members[name])), "WHEEL_RECORD_BYTES")
    _validate_metadata(_headers(members[dist + "METADATA"]), Path(source_root), deadline=deadline)
    wheel = _headers(members[dist + "WHEEL"])
    _header(wheel, "Wheel-Version", "1.0")
    _header(wheel, "Root-Is-Purelib", "true")
    generator = _header(wheel, "Generator")
    _require(wheel.get_all("Tag", []) == ["py3-none-any"]
             and members[dist + "top_level.txt"] == b"mobile_release\n"
             and members[dist + "entry_points.txt"] == b"[console_scripts]\nmobile-release = mobile_release.cli:main\n",
             "WHEEL_ENTRY_CONTRACT")
    return {"sha256": hashlib.sha256(data).hexdigest(), "member_count": len(members),
            "module_count": len(package) - 1, "tooling_count": len(TOOLING_FILES), "generator": generator,
            "runtime_dependencies": [], "license_sha256": LICENSE_SHA256, "roots_sha256": APPLE_ROOTS_SHA256}


def inspect_installed_wheel(source_root: Path, *, deadline: float) -> dict:
    """Actual product/resource imports: call only in the reviewed sandbox."""
    _remaining(deadline, 3300)
    _require(os.getuid() != 0 and sys.prefix != sys.base_prefix
             and sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1, "WHEEL_INTERPRETER_ISOLATION")
    import mobile_release
    from mobile_release.ios_profile_trust import apple_roots
    from mobile_release.tooling import REQUIRED_TOOLING_FILES, resolve_tooling_root

    prefix = Path(sys.prefix).resolve()
    package_root = Path(sysconfig.get_path("purelib")).resolve() / "mobile_release"
    tooling_root = prefix / "share/mobile-release-kit"
    _require(package_root.is_relative_to(prefix) and not prefix.is_relative_to(source_root)
             and Path(mobile_release.__file__).resolve() == package_root / "__init__.py"
             and resolve_tooling_root(environ={}) == tooling_root, "WHEEL_INSTALLED_ORIGIN")
    expected_package = _source_package(source_root, deadline=deadline)
    package, _ = _tree(package_root, deadline=deadline)
    tooling, _ = _tree(tooling_root, deadline=deadline)
    _require(package == expected_package and set(tooling) == set(TOOLING_FILES)
             and set(REQUIRED_TOOLING_FILES) == set(TOOLING_FILES)
             and all(tooling[name] == _read_regular(source_root / name, deadline=deadline) for name in TOOLING_FILES),
             "WHEEL_INSTALLED_RESOURCE_BYTES")
    distribution = importlib.metadata.distribution("mobile-release-kit")
    _require(Path(distribution.locate_file("")).resolve() == package_root.parent, "WHEEL_METADATA_ORIGIN")
    dist_info = package_root.parent / f"mobile_release_kit-{VERSION}.dist-info"
    _validate_metadata(_headers(_read_regular(dist_info / "METADATA", deadline=deadline)), source_root, deadline=deadline)
    _require(hashlib.sha256(_read_regular(dist_info / "licenses/LICENSE", deadline=deadline)).hexdigest() == LICENSE_SHA256,
             "WHEEL_INSTALLED_LICENSE")
    for name in expected_package:
        if name.endswith(".py") and name not in {"__main__.py", "__init__.py"}:
            _remaining(deadline, 3300)
            module = importlib.import_module("mobile_release." + name[:-3])
            _require(Path(module.__file__).resolve() == package_root / name, "WHEEL_MODULE_ORIGIN")
    _require(len(apple_roots()) == 3 and mobile_release.__version__ == VERSION, "WHEEL_ACTUAL_ROOTS_OR_VERSION")
    installed = {}
    for item in importlib.metadata.distributions():
        _remaining(deadline, 3300)
        name = re.sub(r"[-_.]+", "-", _header(item.metadata, "Name")).lower()
        _require(name not in installed and Path(item.locate_file("")).resolve().is_relative_to(prefix), "WHEEL_DISTRIBUTION_ORIGIN")
        installed[name] = item.version
    return {"module_count": len(expected_package) - 1, "tooling_count": len(tooling), "roots_count": 3,
            "runtime_dependencies": [], "distributions": installed}


def expected_consumer_configuration(applied: bool = False) -> dict:
    value = {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "main"},
        "android": {"enabled": True, "applicationId": "com.example.wheelsmoke", "identityStatus": "unverified"},
        "ios": {"enabled": False},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }
    if applied:
        value["$schema"] = f"https://raw.githubusercontent.com/{TOOLING_REPOSITORY}/{TOOLING_SHA}/schemas/project.schema.json"
    return value


def _consumer_files(source_root: Path, *, deadline: float) -> dict[str, bytes]:
    expected = {"app/build.gradle.kts": ANDROID_FIXTURE, ".gitignore": ("\n".join(IGNORE_LINES) + "\n").encode("ascii")}
    expected.update({"release/store/android/en-US/" + name: b"" for name in SKELETON_FILES})
    for name in TOOLING_FILES:
        if name.startswith("templates/workflows/"):
            data = _read_regular(source_root / name, deadline=deadline)
            for placeholder, replacement in ((b"__MOBILE_RELEASE_KIT_SHA__", TOOLING_SHA.encode("ascii")),
                                             (b"__MOBILE_RELEASE_KIT_REPOSITORY__", TOOLING_REPOSITORY.encode("ascii"))):
                _require(placeholder in data, "CALLER_TEMPLATE_PLACEHOLDER")
                data = data.replace(placeholder, replacement)
            _require(b"__MOBILE_RELEASE_KIT_" not in data, "CALLER_TEMPLATE_UNKNOWN_PLACEHOLDER")
            expected[".github/workflows/" + Path(name).name] = data
    return expected


def inspect_wheel_consumer(consumer_root: Path, source_root: Path, *, deadline: float) -> dict:
    """Repeat outside the sandbox after finality, before adopting mutable output."""
    expected = _consumer_files(Path(source_root), deadline=deadline)
    files, directories = _tree(Path(consumer_root), deadline=deadline)
    names = set(expected) | {"release/mobile-release.json"}
    parents = {parent.as_posix() for name in names for parent in Path(name).parents if parent != Path(".")}
    _require(set(files) == names and directories == parents, "CONSUMER_COMPLETE_INVENTORY")
    _require(all(files[name] == data for name, data in expected.items()), "CONSUMER_FILE_BYTES")
    _require(_exact(_json(files["release/mobile-release.json"]), expected_consumer_configuration(True)), "CONSUMER_CONFIGURATION")
    _require(all(not (Path(consumer_root) / name).lstat().st_mode & 0o111 for name in names), "CONSUMER_EXECUTABLE_FILE")
    return {"file_count": len(files), "caller_count": 4, "default_note_bytes": 0, "transaction_state": []}


def _run_child(argv, *, cwd: Path, deadline: float, seconds: float = 120,
               environment: dict | None = None, status: int = 0, echo: bool = True) -> subprocess.CompletedProcess:
    """Ordinary bounded subprocess collection, only inside the outer sandbox.

    The outer controller owns whole-domain cleanup. This function only kills or
    waits its original Popen child, never a discovered PID or a process group.
    """
    cutoff = min(deadline, time.monotonic() + _remaining(deadline, seconds))
    process = None
    selector = selectors.DefaultSelector()
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    errors = []
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=environment if environment is not None else dict(os.environ),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        for name in streams:
            handle = getattr(process, name)
            os.set_blocking(handle.fileno(), False)
            selector.register(handle, selectors.EVENT_READ, name)
        while selector.get_map():
            for key, _ in selector.select(_remaining(cutoff, 0.2)):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = streams[key.data]
                _require(len(target) + len(chunk) <= MAX_STREAM_BYTES, "CHILD_OUTPUT_LIMIT")
                target.extend(chunk)
                if echo:
                    sys.stderr.buffer.write(chunk)
                    sys.stderr.buffer.flush()
        returncode = process.wait(timeout=_remaining(cutoff, seconds))
        _require(type(returncode) is int and returncode == status, "CHILD_EXIT_STATUS")
        _remaining(cutoff, seconds)
        result = subprocess.CompletedProcess(argv, returncode, bytes(streams["stdout"]), bytes(streams["stderr"]))
    finally:
        # Any close/wait/stop failure invalidates the observation, including
        # errors after otherwise successful stdout or a zero direct exit.
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=max(0.0, min(5.0, deadline - time.monotonic())))
            except BaseException:
                errors.append("CHILD_FINAL_WAIT")
            for name in streams:
                try:
                    handle = getattr(process, name)
                    if handle is not None:
                        handle.close()
                except BaseException:
                    errors.append("CHILD_STREAM_CLOSE")
        try:
            selector.close()
        except BaseException:
            errors.append("CHILD_SELECTOR_CLOSE")
        if errors:
            primary = sys.exc_info()[1]
            code = str(primary) if type(primary) is CheckError else "CHILD_FINALITY_FAILED"
            raise CheckError(code, cleanup_errors=errors) from primary
    _remaining(deadline, seconds)
    return result


def _help(data: bytes, module: str) -> list[str]:
    text = data.decode("utf-8", "strict")
    options = set(re.findall(r"(?<![\w-])--[a-z][a-z0-9-]*", text))
    _require(text.startswith("usage:") and options == HELP_OPTIONS[module], "MODULE_HELP_CONTRACT")
    return sorted(options)


def wheel_smoke(source_root: Path, work_root: Path, wheel_path: Path, ruby: Path, deadline: float) -> dict:
    archive = inspect_project_wheel(wheel_path, source_root, deadline=deadline)
    installed = inspect_installed_wheel(source_root, deadline=deadline)
    consumer = work_root / "wheel-consumer"
    consumer.mkdir(mode=0o700)
    (consumer / "app").mkdir(mode=0o700)
    (consumer / "app/build.gradle.kts").write_bytes(ANDROID_FIXTURE)
    console = Path(sys.prefix) / "bin/mobile-release"
    _read_regular(console, deadline=deadline)

    def child(argv, *, parse_json=False):
        result = _run_child(argv, cwd=consumer, deadline=deadline)
        _require(not result.stderr, "CLI_UNEXPECTED_STDERR")
        return _json(result.stdout) if parse_json else result.stdout

    version = child([str(console), "--version"])
    _require(version == f"mobile-release {VERSION}\n".encode("ascii"), "CLI_VERSION")
    preview = child([str(console), "init", "--root", str(consumer)], parse_json=True)
    _require(type(preview) is dict and set(preview) == {"discovery", "proposedConfiguration"}
             and _exact(preview["proposedConfiguration"], expected_consumer_configuration()), "CLI_PREVIEW")
    preview_files, preview_dirs = _tree(consumer, deadline=deadline)
    _require(preview_files == {"app/build.gradle.kts": ANDROID_FIXTURE} and preview_dirs == {"app"}, "CLI_PREVIEW_MUTATION")
    applied = child([str(console), "init", "--root", str(consumer), "--apply", "--tooling-repository", TOOLING_REPOSITORY,
                     "--tooling-sha", TOOLING_SHA], parse_json=True)
    created = (set(_consumer_files(source_root, deadline=deadline)) - {"app/build.gradle.kts"}) | {"release/mobile-release.json"}
    _require(type(applied) is dict and set(applied) == {"created", "updated", "requiresReview"}
             and applied["requiresReview"] is True and applied["updated"] == [] and type(applied["created"]) is list
             and sorted(applied["created"]) == sorted(created), "CLI_APPLY")
    observation = inspect_wheel_consumer(consumer, source_root, deadline=deadline)
    recovered = child([str(console), "init", "--root", str(consumer), "--recover"], parse_json=True)
    _require(_exact(recovered, {"recovery": "no-op", "requiresReview": True}), "CLI_RECOVER")
    inspect_wheel_consumer(consumer, source_root, deadline=deadline)
    child([str(console), "--help"])
    help_results = {}
    tooling = Path(sys.prefix) / "share/mobile-release-kit"
    package_parent = Path(sysconfig.get_path("purelib")).resolve()
    _require(ruby.is_absolute() and ruby.is_file() and os.access(ruby, os.X_OK), "BOOTSTRAP_RUBY_UNAVAILABLE")
    for module in HELP_OPTIONS:
        data = child([sys.executable, "-I", "-B", "-m", "mobile_release." + module, "--help"])
        help_results[module] = _help(data, module)
        if module == "workflow":
            continue
        platform = module.removesuffix("_upload_validation")
        constant = "AndroidUploadValidation" if platform == "android" else "IosUploadValidation"
        expected = ('import runpy,sys;sys.path.insert(0,sys.argv.pop(1));'
                    f'runpy.run_module("mobile_release.{module}",run_name="__main__")').encode("ascii")
        source = _read_regular(source_root / "fastlane" / (module + ".rb"), deadline=deadline)
        literals = re.findall(rb"(?m)^    BOOTSTRAP = '([^'\r\n]+)'\.freeze$", source)
        _require(literals == [expected], "BOOTSTRAP_SOURCE_CONTRACT")
        actual = child([str(ruby), "-r", str(tooling / "fastlane" / (module + ".rb")), "-e",
                        f"print(MobileReleaseKit::{constant}::BOOTSTRAP)"])
        _require(actual == expected, "BOOTSTRAP_ACTUAL_RUBY_CONSTANT")
        bootstrap = child([sys.executable, "-I", "-S", "-B", "-c", actual.decode("ascii"), str(package_parent), "--help"])
        _require(_help(bootstrap, module) == help_results[module], "BOOTSTRAP_HELP_CONTRACT")
    _remaining(deadline, 3300)
    return {"archive": archive, "installed": installed, "consumer": observation, "recovery": "no-op",
            "module_help": help_results, "ruby_bootstraps": ["android", "ios"]}


def validate_jdk_diagnostics(scenario: str, returncode: int, stdout: bytes, stderr: bytes) -> None:
    _require(scenario in {item[0] for item in JDK_CASES} and type(returncode) is int and returncode == 4,
             "JDK_STRICT_STATUS")
    text = (stdout + stderr).decode("utf-8", "strict")
    lines = tuple(line.strip() for line in text.splitlines() if line.strip())
    _require(len([line for line in lines if re.fullmatch(r"jar verified(?:, with signer errors)?\.", line, re.I)]) == 1,
             "JDK_VERIFIED_DIAGNOSTIC")
    expected = () if scenario == "outside-warning-window" else (JDK_DIAGNOSTICS[scenario],)
    _require(tuple(line for line in lines if line in JDK_DIAGNOSTICS.values()) == expected, "JDK_VALIDITY_DIAGNOSTIC")
    _require(not re.search(r"(?i)(?:disabled algorithm|algorithm (?:is )?disabled|algorithm constraints|treated as unsigned|"
                          r"unsigned entr|weak algorithm|certificate (?:is )?revoked|invalid signature|digest error|keyusage|"
                          r"extendedkeyusage|netscapecerttype|jarsigner error:|exception in thread|picked up .*options)", text),
             "JDK_UNRELATED_NATIVE_ERROR")
    _require(all(not re.search(r"(?i)(?:expired|not yet valid|expire within|will expire)", line) or line in expected
                 for line in lines), "JDK_UNCLASSIFIED_VALIDITY_DIAGNOSTIC")


def jdk_signers(source_root: Path, work_root: Path, deadline: float) -> dict:
    _remaining(deadline, 3300)
    _require(sys.platform == "linux" and os.getuid() != 0
             and sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1, "JDK_PLATFORM")
    from mobile_release import android
    _require(_read_regular(Path(android.__file__), deadline=deadline)
             == _read_regular(source_root / "src/mobile_release/android.py", deadline=deadline), "JDK_PRODUCT_BYTES")
    home = Path(os.environ.get("JAVA_HOME", ""))
    _require(home.is_absolute() and home.is_dir(), "JDK_HOME")
    tools = {}
    for name in ("java", "keytool", "jarsigner"):
        selected = shutil.which(name)
        expected = (home / "bin" / name).resolve(strict=True)
        _require(selected is not None and Path(selected).resolve() == expected and expected.is_file(), "JDK_TOOL_ORIGIN")
        tools[name] = str(expected)
    environment = {name: value for name, value in os.environ.items() if name in INSPECTION_ENVIRONMENT_NAMES and value}
    environment.update({"LANG": "C", "LC_ALL": "C"})
    root = work_root / "jdk-signers"
    root.mkdir(mode=0o700)
    calls = []

    def call(name, arguments, directory, *, password=False, status=0, seconds=120, echo=True):
        env = dict(environment)
        if password:
            env[JDK_PASSWORD_NAME] = JDK_PASSWORD
        # The product intentionally excludes JAVA_TOOL_OPTIONS. Explicit JVM
        # transport options enforce the same reviewed memory allowance without
        # altering validity policy or injecting a "Picked up ..." diagnostic.
        options = list(JAVA_OPTIONS) if name == "java" else ["-J" + option for option in JAVA_OPTIONS]
        value = _run_child([tools[name], *options, *arguments], cwd=directory, deadline=deadline, seconds=seconds,
                           environment=env, status=status, echo=echo)
        calls.append({"tool": name, "status": value.returncode})
        return value

    version = call("java", ["-version"], root, seconds=30)
    first_line = (version.stdout + version.stderr).decode("utf-8", "strict").splitlines()[0]
    match = re.fullmatch(r'(?:openjdk|java) version "(21(?:\.[0-9]+){0,3}(?:\+[0-9]+)?)"(?: .*)?', first_line)
    _require(match is not None, "JDK_VERSION")
    cases = []
    for scenario, start, days, should_accept in JDK_CASES:
        _remaining(deadline, 3300)
        directory = root / scenario
        directory.mkdir(mode=0o700)
        keystore, jar = directory / "synthetic.p12", directory / "synthetic.jar"
        with zipfile.ZipFile(jar, "x", compression=zipfile.ZIP_STORED) as archive:
            member = zipfile.ZipInfo("content.txt", (2000, 1, 1, 0, 0, 0))
            member.create_system, member.external_attr = 3, (stat.S_IFREG | 0o600) << 16
            archive.writestr(member, b"Non-executable synthetic signing-policy fixture.")
        call("keytool", ["-genkeypair", "-alias", "synthetic", "-keyalg", "RSA", "-keysize", "2048", "-sigalg", "SHA256withRSA",
                         "-dname", "CN=MRK Disposable Test", "-startdate", start, "-validity", days, "-storetype", "PKCS12",
                         "-keystore", str(keystore), "-storepass:env", JDK_PASSWORD_NAME, "-keypass:env", JDK_PASSWORD_NAME,
                         "-noprompt"], directory, password=True)
        call("jarsigner", ["-keystore", str(keystore), "-storetype", "PKCS12", "-storepass:env", JDK_PASSWORD_NAME,
                           "-keypass:env", JDK_PASSWORD_NAME, "-digestalg", "SHA-256", "-sigalg", "SHA256withRSA",
                           str(jar), "synthetic"], directory, password=True)
        independent = call("jarsigner", ["-verify", "-strict", str(jar)], directory, status=4)
        validate_jdk_diagnostics(scenario, independent.returncode, independent.stdout, independent.stderr)
        certificate = call("keytool", ["-exportcert", "-alias", "synthetic", "-keystore", str(keystore), "-storetype", "PKCS12",
                                       "-storepass:env", JDK_PASSWORD_NAME], directory, password=True, echo=False).stdout
        _require(0 < len(certificate) <= 64 * 1024 and certificate.startswith(b"\x30"), "JDK_DER_EXPORT")

        class ProductRunner:
            """Module-local transport only; all native bytes remain genuine."""
            PIPE = subprocess.PIPE
            TimeoutExpired = subprocess.TimeoutExpired

            def __init__(self):
                self.results = []

            def run(self, argv, **kwargs):
                index = len(self.results)
                _require(index < 2, "JDK_EXTRA_PRODUCT_CALL")
                expected_argv = ["jarsigner", "-verify", "-strict", str(jar)] if index == 0 else ["keytool", "-printcert", "-jarfile", str(jar)]
                _require(argv == expected_argv and kwargs == {"env": environment, "text": True, "stdout": subprocess.PIPE,
                         "stderr": subprocess.PIPE, "timeout": 120 if index == 0 else 30, "check": False}, "JDK_PRODUCT_CALL")
                value = call(argv[0], argv[1:], directory, status=4 if index == 0 else 0, seconds=120 if index == 0 else 30)
                self.results.append(value)
                return subprocess.CompletedProcess(argv, value.returncode, value.stdout.decode("utf-8", "strict"), value.stderr.decode("utf-8", "strict"))

        facade = ProductRunner()
        original, original_run = android.subprocess, subprocess.run
        _require(original is subprocess, "JDK_PRODUCT_BINDING")
        try:
            android.subprocess = facade
            rejected = False
            try:
                accepted = android._verify_jar_signature(jar)
            except android.ValidationError as error:
                _require(not should_accept and type(error) is android.ValidationError and str(error) == JDK_POLICY_REJECTION
                         and len(facade.results) == 1, "JDK_REJECTION_CLASSIFICATION")
                accepted, rejected = False, True
            _require(accepted is should_accept and rejected is (not should_accept) and len(facade.results) == 1, "JDK_PRODUCT_POLICY")
            actual = facade.results[0]
            validate_jdk_diagnostics(scenario, actual.returncode, actual.stdout, actual.stderr)
            fingerprint = android._signer_fingerprint(jar)
            _require(len(facade.results) == 2 and fingerprint == hashlib.sha256(certificate).hexdigest(), "JDK_PRODUCT_FINGERPRINT")
        finally:
            _require(android.subprocess is facade and subprocess.run is original_run, "JDK_BINDING_CUSTODY")
            android.subprocess = original
        _require(fingerprint not in {item["fingerprint"] for item in cases}, "JDK_REUSED_CERTIFICATE")
        cases.append({"id": scenario, "accepted": accepted, "strict_status": 4, "fingerprint": fingerprint})
    _require(len(calls) == 25 and len(cases) == 4, "JDK_CALL_INVENTORY")
    _remaining(deadline, 3300)
    return {"version": match[1], "native_calls": calls, "cases": cases}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--check", choices=CHECKS, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--deadline", type=float, required=True)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--ruby", type=Path)
    args = parser.parse_args(argv)
    observations = []
    report = {"check": args.check, "ok": False, "tests": observations, "details": {}}
    try:
        _remaining(args.deadline, 3300)
        _require(args.deadline - time.monotonic() <= 3300, "AGGREGATE_DEADLINE_RANGE")
        _require(os.getuid() != 0 and sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1, "SANDBOX_INVOCATION")
        source = args.source_root.resolve(strict=True)
        work = args.work_root.resolve(strict=True)
        _require(source.is_dir() and work.is_dir() and not work.is_relative_to(source) and not source.is_relative_to(work), "CHECK_ROOTS")
        _require((args.check == "wheel-smoke") == (args.wheel is not None), "CHECK_WHEEL_ARGUMENT")
        _require((args.check == "wheel-smoke") == (args.ruby is not None), "CHECK_RUBY_ARGUMENT")
        os.umask(0o077)
        os.chdir(work)
        if args.check in {"python-full", "python-wheel"}:
            details = run_python_tests(source, "full" if args.check == "python-full" else "wheel", args.deadline, observations)
        elif args.check == "wheel-smoke":
            details = wheel_smoke(source, work, args.wheel.resolve(strict=True), args.ruby, args.deadline)
        else:
            details = jdk_signers(source, work, args.deadline)
        _remaining(args.deadline, 3300)
        report["details"] = details
        report["ok"] = True
    except BaseException as error:
        code = str(error) if type(error) is CheckError else "UNEXPECTED_CHECK_ERROR"
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            code = "CHECK_INTERRUPTED"
        locations = error.locations if type(error) is CheckError and error.locations else _failure_locations(sys.exc_info(), args.source_root)
        report["details"] = {"error": code, "failure_locations": locations}
        if type(error) is CheckError and error.cleanup_errors:
            report["details"]["cleanup_errors"] = error.cleanup_errors
    encoded = _json_bytes(report)
    _require(len(encoded) <= MAX_RESULT_BYTES, "CHECK_RESULT_LIMIT")
    sys.stdout.write(RESULT_PREFIX + encoded.decode("ascii") + "\n")
    sys.stdout.flush()
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
