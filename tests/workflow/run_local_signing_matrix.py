"""Finite matrix phase/reducer entry points; execution custody stays in verify_ci.

A phase is invoked exactly once inside the original ordinary Session capture.
There is no raw launcher, wheel discovery subprocess, ambient GitHub metadata,
recorded-PID cleanup or fall-back from an incomplete CI scope to local success.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import stat
import sys
import time
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "tests"))

from workflow import local_signing_matrix_contract as contract
from workflow import local_signing_case_owner as case_owner
from workflow import local_signing_matrix_diagnostic as matrix_diagnostic

SHARD_SECONDS = 420
PAIR_SECONDS = 900


def write_record(path, value):
    """Create-only diagnostic/public data, not a finality capability."""
    data = contract.canonical(value) + b"\n"
    descriptor = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        view = memoryview(data)
        while view:
            count = os.write(descriptor, view[:65536])
            contract.require(type(count) is int and 0 < count <= min(65536, len(view)), "record short write")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        closing, descriptor = descriptor, None
        if closing is not None:
            os.close(closing)


def validate_actual_results(directory, expected, *, operating_system, deadline=None):
    path = directory / "results.jsonl.gz"
    info = path.lstat()
    contract.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                     and 0 < info.st_size <= contract.MAX_RESULTS_BYTES, "actual results file state")
    with path.open("rb") as stream:
        content = stream.read(contract.MAX_RESULTS_BYTES + 1)
    return contract.validate_actual_results(content, expected, operating_system=operating_system, deadline=deadline)


def operating_system():
    contract.require(sys.platform in ("linux", "darwin"), "matrix requires Linux or macOS")
    return "macos-26" if sys.platform == "darwin" else "ubuntu-24.04"


def explicit_metadata(args):
    if args.local:
        contract.require(all(getattr(args, name) is None for name in ("repository", "commit", "run_id", "run_attempt", "job")),
                         "local scope must not contain partial CI metadata")
        return {"kind": "local", "repository": None, "commit": None, "runId": None, "attempt": 1, "job": "local"}
    contract.require(all(getattr(args, name) is not None for name in ("repository", "commit", "run_id", "run_attempt", "job")),
                     "complete explicit workflow metadata required")
    return {"kind": "github", "repository": args.repository, "commit": args.commit,
            "runId": args.run_id, "attempt": args.run_attempt, "job": args.job}


def phase(args, scope):
    """Observe once after original inner finally blocks, never replace failure."""
    context = [None]
    matrix_diagnostic.CURRENT = None
    try:
        return _phase(args, scope, context)
    except BaseException as error:
        try:
            matrix_diagnostic.emit(context[0], (
                type(error), error, BaseException.__dict__["__traceback__"].__get__(error, BaseException),
            ))
        except BaseException:
            pass
        raise
    finally:
        matrix_diagnostic.CURRENT = None


def _phase(args, scope, diagnostic_context):
    """Only now import the fixture/product, after the fixed CLI/root admission."""
    contract.require(all(getattr(sys.flags, name, None) == 1 for name in (
        "isolated", "ignore_environment", "no_user_site", "no_site", "safe_path", "dont_write_bytecode")),
        "matrix phase requires isolated no-site interpreter")
    deadline = args.deadline
    contract.require(type(deadline) is float and math.isfinite(deadline)
                     and 0 < deadline - time.monotonic() <= SHARD_SECONDS, "original phase deadline required")
    package = (ROOT.parent / "work/source-build/src/mobile_release" if args.phase == "source" else
               ROOT.parent / "work/wheel-venv/lib/python3.11/site-packages/mobile_release")
    output = ROOT.parent / "work/signing-matrix" / args.phase
    contract.require(args.package_root == package and package.resolve(strict=True) == package
                     and args.output == output and not output.exists() and not output.is_symlink(), "fixed phase roots differ")
    contract.require(args.shard is not None and args.local_reduction is False, "phase selection incomplete")
    # Source-defined admission precedes all product/fixture imports and work.
    catalog = contract.layered_catalog()
    selected = tuple(catalog.shard_ids(scope["os"], args.shard))
    package_files = contract.package_manifest(package, deadline=deadline)
    definitions = contract.definitions_manifest(ROOT, deadline=deadline)
    try:
        # Reuse the original admitted manifests; no additional reads/resolution.
        source_map = tuple(sorted(
            [(str(ROOT / name), name) for name in definitions if name.endswith(".py")]
            + [(str(package / name), "src/mobile_release/" + name)
               for name in package_files if name.endswith(".py")]))
        regression_ids = tuple(identifier for identifier in selected
                               if catalog.case(identifier, scope["os"]).kind == "regression")
        diagnostic_context[0] = matrix_diagnostic.Phase(
            args.phase, deadline, scope["os"], args.shard, selected, regression_ids, source_map,
            contract.diagnostic_child_bindings(scope["os"], args.shard, deadline=deadline))
        matrix_diagnostic.CURRENT = diagnostic_context[0]
    except BaseException:
        pass  # Optional metadata cannot alter original phase admission/work.
    output.mkdir(mode=0o700)
    contract.before_deadline(deadline)
    sys.path[:0] = [str(package.parent), str(ROOT / "tests")]
    from workflow import local_signing_persistent_fixture as fixture
    from workflow import local_signing_layered_fixture as layered
    from mobile_release import local_signing
    contract.require(Path(local_signing.__file__).resolve().parent == package, "wrong actual production import")
    fixture.PHASE_DEADLINE = deadline
    layered.run_phase(output, args.shard, scope, package, package_files, definitions, deadline=deadline)
    matrix_diagnostic.mark("postconditions")
    contract.before_deadline(deadline)
    for name, module in tuple(sys.modules.items()):
        if name == "mobile_release" or name.startswith("mobile_release."):
            origin = getattr(module, "__file__", None)
            contract.require(type(origin) is str and Path(origin).resolve().is_relative_to(package), "phase import escaped bound package")
    matrix_diagnostic.mark("publication")
    record = {"schema": 2, "phase": args.phase, "shard": args.shard, "scope": scope,
              "status": "phase-finished", "productionRoot": str(package)}
    print("MRK_MATRIX_PHASE=" + contract.canonical(record).decode("ascii"), flush=True)
    contract.before_deadline(deadline)
    return 0


class SigningAdapterResult(unittest.TestResult):
    """First fixed-smoke failure is latched before optional diagnostic projection."""
    def __init__(self, phase, deadline, source_map):
        super().__init__()
        self.phase, self.deadline, self.source_map = phase, deadline, source_map
        self.started, self.succeeded = [], []
        self.failed = False
        self.first_failure = None
        self.context = None
        self.current_test = None
        self.command_worker_origins = None

    def startTest(self, test):
        contract.before_deadline(self.deadline)
        identifier = test.id()
        contract.require(not self.shouldStop and self.current_test is None and identifier in contract.ADAPTER_TEST_IDS
                         and identifier not in self.started, "adapter unexpected or duplicate start")
        self.current_test = test
        self.started.append(identifier)
        self.context = (self.phase, identifier, self.source_map)
        case_owner.ADAPTER_CASE_FAILURE = None
        case_owner.ADAPTER_CASE_PROGRESS = None
        case_owner.ADAPTER_DIAGNOSTIC_CONTEXT = self.context  # Immutable before any original child fork.
        super().startTest(test)

    def stopTest(self, test):
        contract.require(self.current_test is test, "adapter foreign test completion")
        self.current_test = None
        case_owner.ADAPTER_DIAGNOSTIC_CONTEXT = None
        case_owner.ADAPTER_CASE_FAILURE = None
        case_owner.ADAPTER_CASE_PROGRESS = None
        super().stopTest(test)

    def addSuccess(self, test):
        contract.before_deadline(self.deadline)
        identifier = test.id()
        contract.require(not self.failed and not self.shouldStop and self.current_test is test
                         and self.context[1] == identifier and identifier in self.started
                         and identifier not in self.succeeded,
                         "adapter duplicate or unstarted success")
        origins = getattr(test, "_adapter_command_worker_origins", None)
        if identifier == contract.ADAPTER_TEST_IDS[0]:
            contract.require(self.command_worker_origins is None, "adapter worker origins already supplied")
            self.command_worker_origins = dict(contract.validate_adapter_origins(origins, "commandWorker"))
        else:
            contract.require(origins is None, "adapter foreign worker origins provider")
        self.succeeded.append(identifier)
        super().addSuccess(test)

    def reject(self, test, outcome, error=None):
        first = not self.failed
        self.failed = True
        self.stop()
        if first:
            self.first_failure = (test.id(), outcome)
            try:
                contract.emit_adapter_failure(self.context, "unittest", outcome, error, deadline=self.deadline,
                                               case=case_owner.adapter_case_failure(self.context),
                                               progress=case_owner.adapter_case_progress(self.context))
            except BaseException:
                pass  # No optional observation can change the first original failure.

    def addError(self, test, error):
        self.reject(test, "error", error)
        super().addError(test, error)

    def addFailure(self, test, error):
        self.reject(test, "failure", error)
        super().addFailure(test, error)

    def addSkip(self, test, reason):
        self.reject(test, "skip")
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, error):
        self.reject(test, "expected-failure", error)
        super().addExpectedFailure(test, error)

    def addUnexpectedSuccess(self, test):
        self.reject(test, "unexpected-success")
        super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, error):
        if error is not None:
            self.reject(test, "failure" if issubclass(error[0], test.failureException) else "error", error)
        super().addSubTest(test, subtest, error)


def adapter_source_map(package, *, deadline):
    """Resolve a closed filename map BEFORE any test or failure is observed."""
    result = []
    for relative in contract.ADAPTER_FAILURE_TEST_FILES:
        contract.before_deadline(deadline)
        path = ROOT / relative
        contract.require(path.is_file() and not path.is_symlink() and path.resolve(strict=True) == path,
                         "adapter diagnostic source path")
        result.append((str(path), relative))
    for relative in contract.package_manifest(package, deadline=deadline):
        if relative.endswith(".py"):
            path = package / relative
            contract.require(path.resolve(strict=True) == path, "adapter diagnostic package path")
            result.append((str(path), "src/mobile_release/" + relative))
    contract.before_deadline(deadline)
    return tuple(sorted(result))


def adapter_phase(args, scope):
    """Observe one escaping exception only after the actual phase's finally."""
    context, stage = None, ["admission"]
    try:
        # Code filenames are prebound data, not paths resolved after a failure.
        # An unavailable optional context never replaces original admission.
        try:
            deadline, selected = args.deadline, args.adapter_phase
            if (type(deadline) is float and math.isfinite(deadline)
                    and 0 < deadline - time.monotonic() <= SHARD_SECONDS
                    and type(selected) is str and selected in {"source", "wheel"}):
                candidate = (selected, deadline, (
                    (adapter_phase.__code__.co_filename, contract.ADAPTER_PHASE_FAILURE_FILES[0]),
                    (contract.require.__code__.co_filename, contract.ADAPTER_PHASE_FAILURE_FILES[1]),
                ))
                contract._adapter_phase_context(candidate)
                context = candidate
        except Exception:
            pass
        return _adapter_phase(args, scope, stage)
    except BaseException as error:
        try:
            contract.emit_adapter_phase_failure(context, stage[0], (
                type(error), error, BaseException.__dict__["__traceback__"].__get__(error, BaseException),
            ))
        except BaseException:
            pass
        raise


def _adapter_phase(args, scope, stage):
    """Fixed diagnostic smoke, never a source/wheel matrix proof producer."""
    contract.require(all(getattr(sys.flags, name, None) == 1 for name in (
        "isolated", "ignore_environment", "no_user_site", "no_site", "safe_path", "dont_write_bytecode")),
        "adapter phase requires isolated no-site interpreter")
    deadline = args.deadline
    contract.require(type(deadline) is float and math.isfinite(deadline)
                     and 0 < deadline - time.monotonic() <= SHARD_SECONDS, "original adapter deadline required")
    selected = args.adapter_phase
    package = (ROOT.parent / "work/source-build/src/mobile_release" if selected == "source" else
               ROOT.parent / "work/wheel-venv/lib/python3.11/site-packages/mobile_release")
    output = ROOT.parent / "work/signing-adapter" / selected
    contract.require(args.package_root == package and package.resolve(strict=True) == package
                     and args.output == output and not output.exists() and not output.is_symlink(), "fixed adapter roots differ")
    stage[0] = "inventory"
    expected = contract.adapter_test_ids(ROOT, deadline=deadline)
    output.mkdir(mode=0o700)
    stage[0] = "imports"
    sys.path[:0] = [str(package.parent), str(ROOT / "tests")]
    from workflow import local_signing_persistent_fixture as fixture
    from workflow import profile_process_fixture as profile_fixture
    from mobile_release import local_signing
    from unit import local_signing_persistent as model
    contract.require(Path(local_signing.__file__).resolve().parent == package, "wrong adapter production import")
    fixture.PHASE_DEADLINE = deadline  # BEFORE importing/constructing/running the selected suite.
    contract.require(not fixture._CASE_CUSTODY and not fixture._CASE_RECOVERY_DEBT, "adapter inherited retained cases")
    stage[0] = "inventory"
    source_map = adapter_source_map(package, deadline=deadline)
    previous_tempdir = tempfile.tempdir
    tempfile.tempdir = str(output)

    try:
        stage[0] = "inventory"
        contract.before_deadline(deadline)
        loader = unittest.TestLoader()
        tests = [loader.loadTestsFromName(identifier) for identifier in expected]
        contract.require(not loader.errors and all(suite.countTestCases() == 1 for suite in tests), "adapter exact suite inventory")
        # Actual methods must come from the fixed source test file, not a loader
        # error surrogate, generated test or an imported lookalike definition.
        for identifier, suite in zip(expected, tests):
            test = next(iter(suite))
            method = getattr(test, test._testMethodName)
            contract.require(test.id() == identifier and Path(method.__func__.__code__.co_filename).resolve()
                             == ROOT / contract.ADAPTER_TEST_FILES[identifier], "adapter actual method origin")
        stage[0] = "suite"
        result = SigningAdapterResult(selected, deadline, source_map)
        result.failfast = True
        unittest.TestSuite(tests).run(result)
        stage[0] = "postconditions"
        contract.before_deadline(deadline)
        contract.require(not result.failed and result.wasSuccessful() and not fixture._CASE_CUSTODY
                         and not fixture._CASE_RECOVERY_DEBT and not model._RETAINED_MODEL_LIFETIMES,
                         "adapter failed or retained cases")
        profile_fixture.assert_fixture_idle()
        contract.require(not profile_fixture._RETAINED_WORKSPACES, "adapter retained fixture workspace")
        contract.require(not any(output.iterdir()), "adapter retained output")
        stage[0] = "origins"
        origins = {"parent": contract.actual_adapter_origins(package, "parent", deadline=deadline),
                   "commandWorker": result.command_worker_origins}
        stage[0] = "publication"
        record = {"schema": "mrk-signing-adapter-phase-v2", "phase": selected, "scope": scope,
                  "status": "adapter-only", "productionRoot": str(package), "startedIds": result.started,
                  "successfulIds": result.succeeded, "testsRun": result.testsRun, "origins": origins, "casePathsRemoved": True}
        contract.validate_adapter_record(record, scope, selected, package)
        contract.before_deadline(deadline)
        print("MRK_SIGNING_ADAPTER_PHASE=" + contract.canonical(record).decode("ascii"), flush=True)
        contract.before_deadline(deadline)
        return 0
    finally:
        case_owner.ADAPTER_DIAGNOSTIC_CONTEXT = None
        tempfile.tempdir = previous_tempdir  # Never implicitly clean retained fixture output.


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--phase", choices=("source", "wheel"))
    selection.add_argument("--adapter-phase", choices=("source", "wheel"))
    selection.add_argument("--reduce", type=Path, metavar="PROOF_DIRECTORY")
    parser.add_argument("--shard", type=int, choices=range(contract.SHARDS))
    parser.add_argument("--package-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--deadline", type=float)
    parser.add_argument("--os", choices=contract.OPERATING_SYSTEMS, required=True)
    parser.add_argument("--repository")
    parser.add_argument("--commit")
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt", type=int)
    parser.add_argument("--job", choices=("test-signing-matrix", "test-signing-adapter", "test"))
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--local-reduction", action="store_true")
    args = parser.parse_args(argv)
    actual_os = operating_system()
    contract.require(args.os == actual_os, "requested OS differs from actual host")
    metadata = explicit_metadata(args)
    if args.adapter_phase is not None:
        contract.require(args.shard is None and not args.local and not args.local_reduction,
                         "adapter excludes shard/local/reduction selections")
        scope = contract.adapter_scope_from_metadata(metadata, actual_os)
    else:
        scope = contract.scope_from_metadata(metadata, actual_os, producer=args.phase is not None)
    contract.require(args.output.is_absolute() and args.output.parent.resolve(strict=True) == args.output.parent
                     and not args.output.exists() and not args.output.is_symlink(), "fresh canonical output required")
    if args.phase is not None:
        return phase(args, scope)
    if args.adapter_phase is not None:
        return adapter_phase(args, scope)
    contract.require(args.shard is None and args.package_root is None and args.deadline is None, "invalid reducer arguments")
    contract.require(args.local == args.local_reduction, "local reduction requires both explicit local selections")
    # This bounded reducer has no process/native code or cleanup authority.
    candidates = ((name, contract.read_proof(path)) for name, path in contract.proof_paths(args.reduce.absolute()))
    report = contract.reconcile(candidates, scope,
        contract.digest(contract.package_manifest(ROOT / "src/mobile_release")),
        contract.digest(contract.definitions_manifest(ROOT)),
        operating_systems=(actual_os,) if args.local_reduction else contract.OPERATING_SYSTEMS)
    write_record(args.output, report)
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
