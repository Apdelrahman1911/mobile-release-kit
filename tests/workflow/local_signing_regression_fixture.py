"""Finite original unittest lifecycles inside the admitted signing matrix phase.

No native owner is started by importing this module. The phase supplies its
fresh private parent and unchanged endpoint; neither CLI nor ambient environment
can select an arbitrary test or helper. G observations are not old-method `ok`s.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import FunctionType

from workflow import local_signing_regression_catalog as catalog


class RegressionResult(unittest.TestResult):
    """One original TestCase, absorbing failure before optional projection."""

    def __init__(self, test, *, deadline):
        super().__init__()
        self.failfast = True
        self.regression_deadline = deadline
        self.regression_failed = False
        self.test = test
        self.started = self.stopped = self.succeeded = 0
        self.first_failure = None

    def startTest(self, test):
        from workflow.local_signing_matrix_contract import before_deadline
        assert test is self.test and self.started == 0 and not self.shouldStop, "unexpected G testcase start"
        before_deadline(self.regression_deadline)
        self.started += 1
        super().startTest(test)

    def stopTest(self, test):
        assert test is self.test and self.started == 1 and self.stopped == 0, "unexpected G testcase stop"
        super().stopTest(test)
        self.stopped += 1

    def addSuccess(self, test):
        from workflow.local_signing_matrix_contract import before_deadline
        assert test is self.test and self.started == 1 and self.succeeded == 0, "unexpected G testcase success"
        assert not self.regression_failed and not self.shouldStop and self.wasSuccessful(), "failed G testcase cannot succeed"
        before_deadline(self.regression_deadline)
        self.succeeded += 1
        super().addSuccess(test)

    def reject(self, outcome):
        self.regression_failed = True
        self.stop()
        if self.first_failure is None:
            self.first_failure = outcome

    def addError(self, test, error):
        self.reject("error")
        super().addError(test, error)

    def addFailure(self, test, error):
        self.reject("failure")
        super().addFailure(test, error)

    def addSkip(self, test, reason):
        self.reject("skip")
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, error):
        self.reject("expected-failure")
        super().addExpectedFailure(test, error)

    def addUnexpectedSuccess(self, test):
        self.reject("unexpected-success")
        super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, error):
        if error is not None:
            self.reject("subtest-failure")
        super().addSubTest(test, subtest, error)


def _bound_method(original, name, expected_file):
    """Bind the actual function object, not just a source-looking old method ID."""
    method = vars(original).get(name)
    assert type(method) is FunctionType and method.__name__ == name \
        and method.__qualname__ == original.__qualname__ + "." + name \
        and method.__module__ == original.__module__, "G original/helper function identity changed"
    module = sys.modules.get(original.__module__)
    assert module is not None and method.__globals__ is vars(module) \
        and Path(method.__code__.co_filename).resolve() == expected_file \
        and Path(module.__file__).resolve() == expected_file, "G original/helper defining source changed"
    assert not getattr(method, "__unittest_skip__", False), "G cannot execute a skipped original/helper"
    assert not getattr(method, "__unittest_expecting_failure__", False), "G expected-failure original/helper is unsupported"
    return method


def _runtime_case(descriptor):
    """Fixed original classes/helpers, imported only after phase admission."""
    from workflow.local_signing_workload import PROFILE_SIGNAL_SECONDS
    assert catalog.SIGNAL_MODES == set(PROFILE_SIGNAL_SECONDS), "original PB3 signal mode authority changed"
    from unit.test_local_signing import LocalSigningTests
    from unit.test_local_signing_profile_identity import ProfileIdentityTests
    from unit.test_local_signing_failures import SigningFailureTests
    from unit.test_local_signing_recovery import SigningRecoveryTests, SigningCrashMatrixTests
    from unit.test_local_signing_native import SigningAccountNativeTests
    from unit.test_local_signing_composition import SigningCompositionTests
    from unit.test_ios_profile_installation import ProfileInstallationSignalTests, ProfileCredentialFlowTests
    from unit.test_local_signing_attempts import RecoveryAttemptTests

    originals = (LocalSigningTests, ProfileIdentityTests, SigningFailureTests, SigningRecoveryTests,
                 SigningCrashMatrixTests, SigningAccountNativeTests, SigningCompositionTests,
                 ProfileInstallationSignalTests, ProfileCredentialFlowTests, RecoveryAttemptTests)
    classes = {value.__module__ + "." + value.__name__: value for value in originals}
    cls_name, method_name = descriptor.original_method.rsplit(".", 1)
    assert cls_name in classes and method_name in catalog.METHODS[cls_name], "G original method authority differs"
    original = classes[cls_name]
    expected_file = Path(__file__).resolve().parents[1] / (original.__module__.replace(".", "/") + ".py")
    _bound_method(original, method_name, expected_file)
    assert not getattr(original, "__unittest_skip__", False), "G cannot execute a skipped original"
    assert not getattr(original, "__unittest_expecting_failure__", False), "G expected-failure original is unsupported"
    if descriptor.helper == "whole":
        return original(method_name)
    for name in catalog.HELPER_METHODS[descriptor.helper]:
        _bound_method(original, name, expected_file)

    class Variant:
        def __init__(self):
            self.descriptor = descriptor
            super().__init__("runTest")

    class LocalVariant(Variant, LocalSigningTests):
        def runTest(self):
            if descriptor.helper == "native-effect":
                self.run_native_failure_variant(descriptor.variant)
            else:
                assert descriptor.helper == "special-profile"
                value, = (item for item in catalog.SPECIAL_PROFILE_NATIVE_VARIANTS if item[0] == descriptor.variant)
                self.run_native_special_profile_variant(value)

    class IdentityVariant(Variant, ProfileIdentityTests):
        def runTest(self):
            if descriptor.helper == "profile-owner":
                value, = (item for item in catalog.PROFILE_OWNER_NATIVE_VARIANTS if item[0] == descriptor.variant)
                self.run_native_owner_variant(value)
            else:
                assert descriptor.helper == "profile-borrowed"
                value, = (item for item in catalog.PROFILE_BORROWED_NATIVE_VARIANTS if item[0] == descriptor.variant)
                self.run_native_borrowed_variant(value)

    class FailureVariant(Variant, SigningFailureTests):
        def runTest(self):
            assert descriptor.helper == "handler-restoration"
            self.run_handler_restoration_variant(tuple(descriptor.variant.split("/")))

    class AccountVariant(Variant, SigningAccountNativeTests):
        def runTest(self):
            if descriptor.helper == "handoff":
                self.run_handoff_variant(descriptor.variant)
            else:
                assert descriptor.helper == "inherited"
                self.run_inherited_variant(descriptor.variant)

    class CompositionVariant(Variant, SigningCompositionTests):
        def runTest(self):
            assert descriptor.helper == "preflight" and sys.platform == "darwin"
            if descriptor.variant == "healthy":
                self.exercise_full_preflight()
            else:
                self.run_preflight_cancellation_variant(tuple(descriptor.variant.split("/")))

    class SignalVariant(Variant, ProfileInstallationSignalTests):
        def runTest(self):
            assert descriptor.helper == "profile-signal"
            self.run_regression_boundary(descriptor.variant)

    variants = {LocalSigningTests: LocalVariant, ProfileIdentityTests: IdentityVariant,
                SigningFailureTests: FailureVariant, SigningAccountNativeTests: AccountVariant,
                SigningCompositionTests: CompositionVariant, ProfileInstallationSignalTests: SignalVariant}
    assert original in variants and catalog.SPLITS[method_name][0] == descriptor.helper \
        and descriptor.variant in catalog.SPLITS[method_name][1], "G fixed helper/variant authority changed"
    return variants[original]()


def run_case(parent, identifier):
    """Run exactly one typed execution; derived aliases are never dispatched."""
    descriptor = catalog.case(identifier)
    assert descriptor.kind == "execution", "semantic contribution cannot start a second execution"
    assert sys.platform in {"linux", "darwin"}, "unsupported G native platform"
    platform = "macos-26" if sys.platform == "darwin" else "ubuntu-24.04"
    assert platform in descriptor.platforms, "G execution not supported on this platform"
    assert all(getattr(sys.flags, name, None) == 1 for name in (
        "isolated", "ignore_environment", "no_user_site", "no_site", "safe_path", "dont_write_bytecode")), \
        "G requires admitted isolated no-site interpreter"
    from workflow import local_signing_persistent_fixture as fixture
    from workflow.local_signing_matrix_contract import before_deadline
    from unit.local_signing_workspace import assert_native_cases_idle

    parent = Path(parent)
    assert parent.resolve(strict=True) == parent and not parent.is_symlink() and not list(parent.iterdir()), "fresh G parent required"
    assert (parent.lstat().st_mode & 0o777) == 0o700, "G parent must be private"
    context = fixture.pin_case_context(parent)
    before_deadline(fixture.PHASE_DEADLINE)
    assert_native_cases_idle()
    test = _runtime_case(descriptor)
    fixture.check_case_context(parent, context)
    result = RegressionResult(test, deadline=fixture.PHASE_DEADLINE)
    previous = tempfile.tempdir
    tempfile.tempdir = str(parent)
    try:
        returned = test.run(result)
        assert returned is result and result.testsRun == 1 \
            and (result.started, result.stopped, result.succeeded) == (1, 1, 1) \
            and result.wasSuccessful() is True and not result.regression_failed and not result.shouldStop, \
            "original G testcase failed: " + str(result.first_failure)
        assert_native_cases_idle()
        assert not list(parent.iterdir()), "original G scratch/evidence is still retained"
        fixture.check_case_context(parent, context)
        evidence = "regression-" + fixture.digest(identifier)
        fixture.write_json(parent / (evidence + ".json"), {
            "schema": "mrk-signing-regression-case-v1", "case": descriptor.record(),
            "originalTestcaseCompleted": True, "typedVariant": descriptor.helper != "whole",
            "testsRun": 1, "setupBodyTeardownCleanupsReturned": True,
            "originalWorkersSettled": True, "caseRemoved": True,
        })
        fixture.check_phase_context(context)
        return {"caseId": identifier, "status": "regression-case", "evidence": evidence + ".json",
                "caseRemoved": True, "originalWorkersSettled": True}
    finally:
        tempfile.tempdir = previous


def semantic_contributions(parent, identifier, evidence):
    """Original specialized assertions on the one canonical private execution.

    Called by the canonical semantic fixture BEFORE case removal. Returned IDs
    are typed coverage observations only; root's exact union closes the old
    method after every contribution, not after an arbitrary successful prefix.
    """
    required = catalog.semantic_contributions(identifier)
    if not required:
        return ()
    from workflow import local_signing_persistent_fixture as fixture
    from workflow import local_signing_semantic_catalog as semantic_catalog

    assert evidence["schema"] == "mrk-signing-semantic-case-v1"
    assert evidence["case"] == semantic_catalog.case(identifier).record()
    steps = evidence["steps"]
    assert type(steps) is list and steps and len({step["name"] for step in steps}) == len(steps)
    for step in steps:
        fixture.assert_original_return(step["original"], expected=fixture.CRASH if step["name"] == "seed" else 0)
    if identifier == "C/fence/04":
        assert [step["name"] for step in steps] == ["seed", "semantic-main"]
        cut = steps[0]["observation"]
        assert cut["edge"] == "partial"
        original = cut["originalCFenceObservation"]
        assert original["originalWorker"] is True and original["originalReadClosed"] is True
        assert 0 < original["written"] < original["total"]
        assert bytes.fromhex(original["actualReadHex"]) == bytes.fromhex(original["operandHex"])[:original["written"]]
        final = steps[1]
        assert (final["manual"], final["expected"], final["observation"]["result"]["status"]) == ("none", "recovered", "recovered")
        assert final["observation"]["idleAndRenewedAdmission"] is True
        assert evidence["negativeEvidence"] == []
    elif identifier == "S/active-build-pending/none":
        assert [step["name"] for step in steps] == ["seed", "semantic-main", "semantic-resolution"]
        cut = steps[0]["observation"]
        assert cut["selector"]["occurrence"] == 3 and cut["physicalWrite"]["properPrefix"] is True
        durable, live = cut["snapshot"]["controls"]["state.json"]["value"], cut["context"]["liveState"]
        assert (durable["inflight"]["phase"], live["inflight"]["phase"]) == ("ARMED", "SETTLED")
        assert durable["native"][fixture.signing.DB_NAME] != live["native"][fixture.signing.DB_NAME]
        negative, final = steps[1:]
        assert (negative["manual"], negative["expected"]) == ("none", "refused-unknown-resource")
        assert negative["observation"]["refused"] is not None and negative["observation"]["idleAndRenewedAdmission"] is False
        stem = "semantic-" + fixture.digest(identifier) + "-negative"
        assert evidence["negativeEvidence"] == [stem + ".json"]
        assert fixture.read_case_json(parent, stem) == negative
        assert (final["manual"], final["expected"], final["observation"]["result"]["status"]) == \
            ("resolve", "recovered-with-conflict", "recovered-with-conflict")
        assert final["observation"]["idleAndRenewedAdmission"] is True
    elif identifier == "H/full-context":
        assert [step["name"] for step in steps] == ["healthy"]
        inventory = steps[0]["observation"]
        operations = {event["operation"] for event in inventory["events"]}
        assert {"buffer.write", "buffer.flush", "buffer.close", "link", "native/build", "native/import",
                "native-effect/replace/" + fixture.signing.DB_NAME,
                "command-fence/PENDING_WRITE", "command-fence/DATA_FSYNC", "command-fence/FINAL_LINK",
                "command-fence/DIRECTORY_FSYNC"} <= operations
        assert inventory["snapshot"]["preferences"] == inventory["snapshot"]["original"]
        assert not inventory["snapshot"]["ownedRemaining"]
    else:
        assert identifier in {f"F/{number:02}" for number in range(1, 16)}
        variant = semantic_catalog.case(identifier).variant
        by_name = {step["name"]: step for step in steps}
        if variant in {"foreign-default", "reordered-search", "deleted-search", "foreign-profile"}:
            assert by_name["focused-main"]["observation"]["result"]["status"] == "recovered-with-conflict"
        elif variant in {"profile-inplace-edit", "terminal-profile-reappeared", "terminal-native-reappeared",
                         "manual-wrong", "manual-eof", "manual-cancel"}:
            negative = by_name["focused-refusal"]["observation"]
            assert negative["freshAdmission"] == "pending" and negative["resourcesPreserved"] is True
        elif variant == "borrowed-profile":
            value = by_name["focused-main"]
            assert value["manual"] == "none" and value["expected"] == "recovered"
            assert value["observation"]["refused"] is None and value["observation"]["result"]["status"] == "recovered"
        elif variant == "auto-add-ambiguous-create":
            value = by_name["focused-refusal"]
            assert value["manual"] == "none" and value["expected"] == "refused-unknown-resource"
            assert value["observation"]["refused"] is not None
        elif variant == "foreign-native-db":
            for mode in ("none", "resolve"):
                observed = by_name["focused-" + mode]["observation"]
                assert observed["freshAdmission"] == "pending" and observed["resourcesPreserved"] is True
                assert observed["before"]["preferences"] == observed["after"]["preferences"]
    return required
