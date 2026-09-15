"""Positive original-unittest completion gates task-owned native scratch removal.

This is test lifecycle code, not process custody or a raw native test launcher.
Failed/unknown cases retain their files for their original verification Session.
"""
from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path


def _identity(root):
    value = root.lstat()
    assert stat.S_ISDIR(value.st_mode) and stat.S_IMODE(value.st_mode) == 0o700, \
        "native case root is not a private original directory"
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def assert_native_cases_idle(root=None):
    """Observe only already-loaded original ledgers; never clear/adopt custody."""
    model = sys.modules.get("unit.local_signing_persistent")
    if model is not None:
        assert not model._RETAINED_MODEL_LIFETIMES, "original native model custody is retained"
    profile = sys.modules.get("workflow.profile_process_fixture")
    if profile is not None:
        profile.assert_fixture_idle()
    for name, ledgers in (("mobile_release.ios_profiles", ("_PROFILE_SCRATCH_LEASES", "_PROFILE_RESOURCE_SCOPES")),
                          ("mobile_release._profile_process", ("_CUSTODY",))):
        module = sys.modules.get(name)
        if module is not None:
            for ledger in ledgers:
                assert not getattr(module, ledger), "original profile lifetime is retained"
    fixture = sys.modules.get("workflow.local_signing_persistent_fixture")
    if fixture is not None:
        for ledger in (fixture._CASE_CUSTODY, fixture._CASE_RECOVERY_DEBT):
            assert type(ledger) is dict, "native case ledger representation changed"
            assert all(type(key) is str and Path(key).is_absolute() for key in ledger), "native case ledger root changed"
            assert not any(root is None or Path(key).is_relative_to(root) for key in ledger), \
                "original case or recovery evidence remains"


def _before_bound_deadline(result):
    fixture = sys.modules.get("workflow.local_signing_persistent_fixture")
    deadline = None if fixture is None else fixture.PHASE_DEADLINE
    supplied = getattr(result, "regression_deadline", None)
    if supplied is not None:
        assert deadline == supplied, "original G phase endpoint changed"
    if deadline is not None:
        # Only after a real matrix phase bound this endpoint; ordinary unittest
        # runs retain their existing enclosing gate, not a made-up phase clock.
        from workflow.local_signing_matrix_contract import before_deadline
        before_deadline(deadline)


class NativeCaseWorkspaceMixin:
    """Keep standard TestCase.run and all independent addCleanup callbacks."""

    def run(self, result=None):
        assert getattr(self, "_native_case_run", None) is None, "native test run reentered"
        owned_result = result is None
        if owned_result:
            result = self.defaultTestResult()
        outcomes = {}
        for name in ("skipped", "expectedFailures", "unexpectedSuccesses"):
            values = getattr(result, name, None)
            assert type(values) is list, "original unittest outcome list unavailable"
            outcomes[name] = (values, tuple(values))
        method = getattr(self, self._testMethodName)
        expecting_failure = (getattr(type(self), "__unittest_expecting_failure__", False)
                             or getattr(method, "__unittest_expecting_failure__", False))
        binding = {"result": result, "pid": os.getpid(), "outcomes": outcomes,
                   "tearDown": False, "expectingFailure": expecting_failure}
        self._native_case_run = binding
        started = False
        try:
            if owned_result:
                start = getattr(result, "startTestRun", None)
                if start is not None:
                    start()
                started = True
            return super().run(result)
        finally:
            try:
                if owned_result and started:
                    stop = getattr(result, "stopTestRun", None)
                    if stop is not None:
                        stop()
            finally:
                self._native_case_run = None

    def tearDown(self):
        super().tearDown()
        binding = getattr(self, "_native_case_run", None)
        assert type(binding) is dict and binding["pid"] == os.getpid(), "original unittest binding lost"
        binding["tearDown"] = True

    def native_case_directory(self, *, prefix):
        binding = getattr(self, "_native_case_run", None)
        assert type(binding) is dict and not binding["expectingFailure"], "native root needs original ordinary test run"
        assert getattr(self, "_native_case_root", None) is None, "native test root already allocated"
        # Register before any other test cleanup, so the disposer observes all
        # earlier cleanup outcomes and never deletes beneath an open ExitStack.
        assert type(getattr(self, "_cleanups", None)) is list and not self._cleanups, \
            "native root disposer must be the first cleanup"
        root = Path(tempfile.mkdtemp(prefix=prefix)).resolve()
        identity = _identity(root)
        self._native_case_root = root
        self.addCleanup(self._dispose_native_case, root, identity, binding)
        return root

    def _dispose_native_case(self, root, identity, binding):
        assert self._native_case_run is binding and binding["pid"] == os.getpid(), "original test run changed; retain root"
        result = binding["result"]
        assert binding["tearDown"] is True and not binding["expectingFailure"], "teardown not complete; retain root"
        assert result.wasSuccessful() is True and not result.shouldStop and not getattr(result, "regression_failed", False), \
            "original test result failed or stopped; retain root"
        for name, (values, before) in binding["outcomes"].items():
            actual = getattr(result, name, None)
            assert actual is values and type(actual) is list and len(actual) == len(before) \
                and all(left is right for left, right in zip(actual, before)), "current case skipped or result changed; retain root"
        # CPython3.11/3.12 source-bound readonly representation check. Never
        # inspect _outcome.success: it is temporarily true inside each cleanup.
        assert type(getattr(self, "_cleanups", None)) is list and not self._cleanups, \
            "later cleanup remains; retain root"
        assert_native_cases_idle(root)
        _before_bound_deadline(result)
        assert _identity(root) == identity, "original native root identity changed; retain root"
        assert shutil.rmtree.avoids_symlink_attacks, "safe native root removal unavailable"
        shutil.rmtree(root)
        try:
            root.lstat()
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("native root removal did not establish absence")
        self._native_case_root = None
