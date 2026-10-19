"""Fake Security ABI only: NO native/trust-positive certificate or private key.

The deliberately non-DER leaf/intermediate strings below exercise call framing,
cleanup and negative outcomes. Only existing bundled public root bytes are real.
Passing this suite does not qualify macOS, distribution purpose or a key loan.
"""
from __future__ import annotations

import ctypes as C
import math
import sys
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import apple_provisioning_chain as chain
from mobile_release.apple_provisioning_api import ProvisioningError
from mobile_release.cancellation import DefaultCancellation
from mobile_release.errors import ValidationError
from mobile_release.inspection import InspectionDeadline
from mobile_release.ios_profile_trust import apple_roots
from mobile_release.owned_process import ProcessCleanupError, ProcessError


LEAF = b"synthetic non-DER existing leaf; not a trust fixture"
INTERMEDIATE = b"synthetic non-DER intermediate; not a CA"
NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)


@contextmanager
def active_guard():
    guard = DefaultCancellation(ProcessCleanupError, "synthetic guard restoration failed")
    try:
        guard.install()
        guard.activate()
        yield guard
    finally:
        guard.restore()


class Function:
    def __init__(self, owner, name, function):
        self.owner, self.name, self.function = owner, name, function

    def __call__(self, *arguments):
        self.owner.calls.append((self.name, arguments))
        result = self.function(*arguments)
        if self.owner.cancel_after == self.name:
            self.owner.guard.cancelled = True
        if self.owner.expire_after == self.name:
            self.owner.deadline._expires_at = 0
        if self.owner.raise_after == self.name:
            raise OSError("native-private-canary")
        if self.owner.interrupt_after == self.name:
            raise self.owner.interruption
        return -50 if self.owner.failed_status == self.name else result


class NativeAPI:
    """A local deterministic ABI model, never an original native trust owner."""

    TYPES = {name: index + 1 for index, name in enumerate(
        ("CFData", "CFArray", "CFDate", "CFString", "SecCertificate", "SecPolicy", "SecTrust"))}

    def __init__(self, *, behavior=None, failed_status=None, raise_after=None, cancel_after=None,
                 expire_after=None, interrupt_after=None):
        self.behavior, self.failed_status, self.raise_after = behavior, failed_status, raise_after
        self.cancel_after, self.expire_after, self.interrupt_after = cancel_after, expire_after, interrupt_after
        self.interruption = KeyboardInterrupt()
        self.roots = apple_roots()  # Actual fixed PUBLIC bundle, not a trust test.
        self.created, self.released, self.calls, self.buffers, self.loads = [], [], [], [], []
        self.objects, self.certificates, self.offline = {42: ("CFString", b"synthetic policy identifier")}, {}, {}
        self.security, self.foundation = SimpleNamespace(), SimpleNamespace()
        self.native_time = NOW.timestamp() - chain._CF_UNIX_EPOCH
        self.guard, self.deadline = None, None
        functions = {
            "CFRelease": lambda value: self.released.append(value),
            "CFGetTypeID": self.type_id,
            "CFDataCreate": lambda allocator, value, size: self.new("CFData", bytes(value[:size])),
            "CFDataGetLength": lambda value: -1 if behavior == "data-negative" else (
                chain.MAX_CERTIFICATE_BYTES + 1 if behavior == "data-oversize" else len(self.value(value))),
            "CFDataGetBytePtr": self.data_pointer,
            "CFArrayCreate": lambda allocator, values, count, callbacks: self.new("CFArray", list(values[:count])),
            "CFArrayGetCount": lambda value: len(self.value(value)),
            "CFArrayGetValueAtIndex": lambda value, index: self.value(value)[index],
            "CFAbsoluteTimeGetCurrent": lambda: self.native_time,
            "CFDateCreate": lambda allocator, at: self.new("CFDate", at),
            "CFDateGetAbsoluteTime": lambda value: self.value(value) + (1 if behavior == "date-changed" else 0),
            "SecCertificateCreateWithData": self.certificate,
            "SecCertificateCopyData": lambda value: self.new("CFData", self.value(value)),
            "SecPolicyCreateBasicX509": lambda: self.new("SecPolicy", "generic-x509"),
            "SecPolicyCreateWithProperties": lambda identifier, options: None if behavior == "policy-null" else self.new("SecPolicy", "generic-code-signing"),
            "SecTrustCreateWithCertificates": lambda certificates, policies, out: self.output(out, self.new("SecTrust", (certificates, policies))),
            "SecTrustSetAnchorCertificates": lambda trust, roots: 0,
            "SecTrustSetAnchorCertificatesOnly": lambda trust, only: 0,
            "SecTrustSetNetworkFetchAllowed": lambda trust, allowed: self.setting("network", allowed),
            "SecTrustSetKeychainsAllowed": lambda trust, allowed: self.setting("keychains", allowed),
            "SecTrustGetNetworkFetchAllowed": lambda trust, out: self.output(out, 1 if behavior == "network-on" else self.offline["network"]),
            "SecTrustGetKeychainsAllowed": lambda trust, out: self.output(out, 1 if behavior == "keychains-on" else self.offline["keychains"]),
            "SecTrustSetVerifyDate": lambda trust, date: 0,
            "SecTrustEvaluateWithError": self.evaluate,
            "SecTrustGetTrustResult": lambda trust, out: self.output(out, 1 if behavior == "user-proceed" else 4),
            "SecTrustCopyCertificateChain": self.returned_chain,
        }
        for name, type_id in self.TYPES.items():
            functions[name + "GetTypeID"] = lambda value=type_id: value
        for name, function in functions.items():
            setattr(self.foundation if name.startswith("CF") else self.security,
                    name, Function(self, name, function))

    @staticmethod
    def pointer(value):
        return value.value if isinstance(value, C.c_void_p) else value

    def value(self, pointer):
        return self.objects[self.pointer(pointer)][1]

    def type_id(self, pointer):
        kind = self.objects[self.pointer(pointer)][0]
        if self.behavior == "type-" + kind:
            return 999
        return self.TYPES[kind]

    def new(self, kind, value):
        pointer = 100 + len(self.created)
        self.created.append(pointer)
        self.objects[pointer] = (kind, value)
        return pointer

    @staticmethod
    def output(out, value):
        out._obj.value = value
        return 0

    def certificate(self, allocator, value):
        raw = self.value(value)
        if self.behavior == "malformed-leaf" and raw == LEAF:
            return None
        pointer = self.new("SecCertificate", raw)
        self.certificates[raw] = pointer
        return pointer

    def data_pointer(self, value):
        if self.behavior == "data-null":
            return None
        buffer = C.create_string_buffer(self.value(value))
        self.buffers.append(buffer)
        return C.addressof(buffer)

    def setting(self, name, allowed):
        self.offline[name] = allowed
        return 0

    def evaluate(self, trust, out):
        if self.behavior == "evaluation-error":
            out._obj.value = self.new("CFError", "unread private native description")
        return self.behavior != "evaluation-false"

    def returned_chain(self, trust):
        values = [self.certificates[LEAF], self.certificates[INTERMEDIATE], self.certificates[self.roots[0]]]
        if self.behavior == "chain-short":
            values.pop()
        elif self.behavior == "chain-long":
            values.append(values[-1])
        elif self.behavior == "wrong-leaf":
            values[0] = values[1]
        elif self.behavior == "wrong-root":
            values[-1] = values[1]
        elif self.behavior == "duplicate":
            values[1] = values[0]
        elif self.behavior == "null-certificate":
            values[1] = None
        elif self.behavior == "foreign-intermediate":
            # Borrowed child of returned native array, not a caller-owned ref.
            self.objects[9000] = ("SecCertificate", b"unadmitted ambient certificate")
            values[1] = 9000
        return self.new("CFArray", values)

    def load(self, name):
        self.loads.append(name)
        if name == "/System/Library/Frameworks/Security.framework/Security":
            return self.security
        if name == "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation":
            return self.foundation
        raise AssertionError("unexpected native library")

    def invoke(self, *, leaf=LEAF, intermediates=(INTERMEDIATE,)):
        with active_guard() as guard:
            self.guard, self.deadline = guard, InspectionDeadline()
            with patch("ctypes.CDLL", side_effect=self.load), \
                    patch.object(C.c_void_p, "in_dll", return_value=C.c_void_p(42)), \
                    patch.object(chain, "apple_roots", return_value=self.roots), \
                    patch.object(sys, "platform", "darwin"):
                return chain._verify_leaf_chain_in_worker(leaf, intermediates,
                    cancellation=guard, deadline=self.deadline)


class ExistingChainABITests(unittest.TestCase):
    def test_fake_abi_uses_only_fixed_generic_policies_explicit_roots_and_native_time(self):
        api = NativeAPI()
        self.assertEqual(api.invoke(), NOW)  # DATA-only fake response, NOT trust.
        self.assertEqual(api.released, api.created[::-1])
        calls = dict(api.calls)
        self.assertEqual(len(api.loads), 2)
        self.assertEqual(calls["SecPolicyCreateWithProperties"][0].value, 42)
        self.assertIsNone(calls["SecPolicyCreateWithProperties"][1])
        self.assertEqual(calls["SecTrustSetAnchorCertificatesOnly"][1], 1)
        self.assertEqual(api.offline, {"network": 0, "keychains": 0})
        self.assertEqual([api.value(value) for value in api.value(calls["SecTrustSetAnchorCertificates"][1])], list(api.roots))
        self.assertEqual([api.value(value) for value in api.value(calls["SecTrustCreateWithCertificates"][0])], [LEAF, INTERMEDIATE])
        self.assertEqual(api.value(calls["SecTrustSetVerifyDate"][1]), api.native_time)
        self.assertNotIn("SecCertificateCopyCommonName", calls)
        self.assertFalse(any("Import" in name or "SecItem" in name for name in calls))
        self.assertEqual(api.security.SecTrustEvaluateWithError.argtypes, [C.c_void_p, C.POINTER(C.c_void_p)])
        self.assertEqual(api.foundation.CFAbsoluteTimeGetCurrent.restype, C.c_double)

    def test_each_nonzero_status_refuses_and_releases_even_populated_out_parameter(self):
        for name in ("SecTrustCreateWithCertificates", "SecTrustSetAnchorCertificates", "SecTrustSetAnchorCertificatesOnly",
                     "SecTrustSetNetworkFetchAllowed", "SecTrustSetKeychainsAllowed", "SecTrustGetNetworkFetchAllowed",
                     "SecTrustGetKeychainsAllowed", "SecTrustSetVerifyDate", "SecTrustGetTrustResult"):
            with self.subTest(native=name):
                api = NativeAPI(failed_status=name)
                with self.assertRaises(ProvisioningError):
                    api.invoke()
                self.assertEqual(api.released, api.created[::-1])
                self.assertFalse(api.guard.lifetime_ledger.fatal)

    def test_malformed_chain_wrong_leaf_root_and_user_trust_never_fall_back(self):
        behaviors = ("policy-null", "malformed-leaf", "network-on", "keychains-on", "evaluation-error", "evaluation-false",
                     "user-proceed", "chain-short", "chain-long", "wrong-leaf", "wrong-root", "duplicate",
                     "foreign-intermediate", "null-certificate", "data-negative", "data-oversize", "data-null", "date-changed")
        for behavior in behaviors:
            with self.subTest(fault=behavior):
                api = NativeAPI(behavior=behavior)
                with self.assertRaises(ProvisioningError):
                    api.invoke()
                self.assertEqual(api.released, api.created[::-1])
                self.assertLessEqual(sum(name == "SecTrustEvaluateWithError" for name, _ in api.calls), 1)

    def test_every_cf_type_checked_before_typed_access(self):
        for kind in NativeAPI.TYPES:
            with self.subTest(kind=kind):
                api = NativeAPI(behavior="type-" + kind)
                with self.assertRaises(ProvisioningError):
                    api.invoke()
                self.assertEqual(api.released, api.created[::-1])

    def test_bounds_and_ambiguous_inputs_refuse_before_library_or_certificate_calls(self):
        variants = ((b"", (INTERMEDIATE,)), (bytearray(LEAF), (INTERMEDIATE,)),
                    (b"x" * (chain.MAX_CERTIFICATE_BYTES + 1), (INTERMEDIATE,)), (LEAF, ()),
                    (LEAF, [INTERMEDIATE]), (LEAF, (LEAF,)), (LEAF, (INTERMEDIATE, INTERMEDIATE)),
                    (LEAF, (b"",)), (LEAF, tuple(str(i).encode() for i in range(9))))
        for leaf, intermediates in variants:
            with self.subTest(leaf_type=type(leaf), count=len(intermediates)):
                api = NativeAPI()
                with self.assertRaises(ProvisioningError):
                    api.invoke(leaf=leaf, intermediates=intermediates)
                self.assertEqual(api.loads, [])
                self.assertEqual(api.created, [])
        api = NativeAPI()
        with self.assertRaises(ProvisioningError):
            api.invoke(intermediates=(api.roots[0],))
        self.assertEqual(api.loads, [])

    def test_bad_native_clock_and_altered_date_refuse_not_historical_validation(self):
        for value in (math.nan, math.inf, -math.inf, -chain._CF_UNIX_EPOCH - 1, 253402300800):
            with self.subTest(clock=value):
                api = NativeAPI()
                api.native_time = value
                with self.assertRaises(ProvisioningError):
                    api.invoke()
                self.assertEqual(api.released, api.created[::-1])
                self.assertNotIn("SecTrustEvaluateWithError", dict(api.calls))

    def test_missing_library_or_symbol_never_invents_policy_or_success(self):
        api = NativeAPI()
        del api.security.SecTrustSetKeychainsAllowed
        with self.assertRaises(ProvisioningError) as failure:
            api.invoke()
        self.assertEqual(failure.exception.code, "existing_chain_unavailable")
        self.assertEqual(api.created, [])
        with active_guard() as guard, patch.object(sys, "platform", "darwin"), \
                patch.object(chain, "apple_roots", return_value=api.roots), \
                patch("ctypes.CDLL", side_effect=OSError("native-private-canary")), \
                self.assertRaises(ProvisioningError) as failure:
            chain._verify_leaf_chain_in_worker(LEAF, (INTERMEDIATE,), cancellation=guard, deadline=InspectionDeadline())
        self.assertNotIn("canary", str(failure.exception))

    def test_non_macos_and_foreign_guard_refuse_before_native_calls(self):
        with active_guard() as guard, patch.object(sys, "platform", "linux"), patch("ctypes.CDLL") as call:
            with self.assertRaises(ProvisioningError) as failure:
                chain._verify_leaf_chain_in_worker(LEAF, (INTERMEDIATE,), cancellation=guard, deadline=InspectionDeadline())
            self.assertEqual(failure.exception.code, "existing_chain_unavailable")
            with self.assertRaises(ProvisioningError) as failure:
                chain._verify_leaf_chain_in_worker(LEAF, (INTERMEDIATE,), cancellation=object(), deadline=InspectionDeadline())
            self.assertEqual(failure.exception.code, "invalid_inspection_owner")
            call.assert_not_called()

    def test_second_active_guard_cannot_shadow_actual_handler_owner(self):
        with active_guard(), patch("ctypes.CDLL") as call:
            other = DefaultCancellation(ProcessCleanupError, "synthetic other guard")
            try:
                # A second guard can have zero owned handlers. Its ACTIVE state
                # alone must not override the real handler-owning original.
                other.install()
                other.activate()
                with self.assertRaises(ProcessCleanupError):
                    chain._verify_leaf_chain_in_worker(LEAF, (INTERMEDIATE,), cancellation=other,
                                                       deadline=InspectionDeadline())
            finally:
                other.restore()
            call.assert_not_called()

    def test_cancellation_after_return_retains_created_objects_then_releases_once(self):
        for name in ("CFDataCreate", "SecTrustCreateWithCertificates", "SecTrustEvaluateWithError", "SecTrustCopyCertificateChain"):
            with self.subTest(native=name):
                api = NativeAPI(cancel_after=name)
                with self.assertRaises(KeyboardInterrupt):
                    api.invoke()
                self.assertEqual(api.released, api.created[::-1])

    def test_expired_shared_deadline_stops_even_after_native_evaluation(self):
        api = NativeAPI(expire_after="SecTrustEvaluateWithError")
        with self.assertRaises(ValidationError):
            api.invoke()
        self.assertEqual(api.released, api.created[::-1])
        self.assertNotIn("SecTrustCopyCertificateChain", dict(api.calls))

    def test_lost_native_return_poisoned_guard_preserves_process_backing_no_release_or_retry(self):
        for name in ("CFDataCreate", "SecTrustCreateWithCertificates", "SecTrustEvaluateWithError"):
            with self.subTest(native=name):
                api = NativeAPI(raise_after=name)
                with self.assertRaises(ProcessError) as failure:
                    api.invoke()
                self.assertTrue(failure.exception.fatal)
                self.assertTrue(api.guard.lifetime_ledger.fatal)
                self.assertEqual(api.released, [])
                self.assertEqual(api.calls[-1][0], name)
                self.assertNotIn("canary", str(failure.exception))

    def test_release_ambiguity_is_absorbing_and_never_becomes_success_or_ordinary_invalid(self):
        api = NativeAPI(raise_after="CFRelease")
        with self.assertRaises(ProcessError) as failure:
            api.invoke()
        self.assertTrue(failure.exception.fatal)
        self.assertTrue(api.guard.lifetime_ledger.fatal)
        self.assertEqual(len(api.released), 1)
        self.assertEqual(api.calls[-1][0], "CFRelease")
        self.assertNotIn("canary", str(failure.exception))

    def test_first_interruption_survives_unknown_native_call_with_fatal_sidecar(self):
        api = NativeAPI(interrupt_after="SecTrustCreateWithCertificates")
        with self.assertRaises(KeyboardInterrupt) as failure:
            api.invoke()
        self.assertIs(failure.exception, api.interruption)
        self.assertTrue(api.guard.lifetime_ledger.fatal)
        self.assertEqual(api.released, [])

    def test_first_release_interruption_is_not_replaced_by_cleanup_message(self):
        for interruption in (KeyboardInterrupt(), SystemExit(2)):
            api = NativeAPI(interrupt_after="CFRelease")
            api.interruption = interruption
            with self.subTest(interruption=type(interruption)), self.assertRaises(type(interruption)) as failure:
                api.invoke()
            self.assertIs(failure.exception, interruption)
            self.assertTrue(api.guard.lifetime_ledger.fatal)
            self.assertEqual(len(api.released), 1)
            self.assertEqual(api.calls[-1][0], "CFRelease")


if __name__ == "__main__":
    unittest.main()
