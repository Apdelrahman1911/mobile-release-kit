"""Native ABI/status/ownership contracts, independent of native-policy positives."""
from __future__ import annotations

import ctypes as C
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release.errors import ValidationError
from mobile_release.ios_profile_trust import apple_roots, verify_profile_signer

from .ios_profile_helpers import public_certificates


class Function:
    def __init__(self, owner, name, call):
        self.owner, self.name, self.call = owner, name, call

    def __call__(self, *args):
        self.owner.calls.append((self.name, args))
        result = self.call(*args)
        if self.name == self.owner.failed_status:
            return -50
        return result


class NativeAPI:
    """Only an ABI/ownership model. Actual Apple-policy positives live elsewhere."""
    def __init__(self, *, failed_status=None, behavior=None):
        self.failed_status, self.behavior = failed_status, behavior
        self.calls, self.created, self.released, self.buffers = [], [], [], []
        self.objects, self.certificates = {}, {}
        self.offline = {}
        self.security, self.foundation = SimpleNamespace(), SimpleNamespace()
        self.roots = apple_roots()
        self.inputs = public_certificates()
        self.leaf = self.inputs["ios_provisioning_profile.cer"]
        self.intermediate = self.inputs["AppleiPhoneCA.cer"]
        functions = {
            "CFRelease": lambda obj: self.released.append(obj),
            "CFDataCreate": lambda allocator, data, size: self.new(bytes(data[:size])),
            "CFDataGetLength": lambda obj: 0 if behavior == "data-length" else len(self.objects[obj]),
            "CFDataGetBytePtr": self.data_bytes,
            "CFArrayCreate": lambda allocator, values, count, callbacks: self.new(list(values[:count])),
            "CFArrayGetCount": lambda obj: len(self.objects[obj]),
            "CFArrayGetValueAtIndex": lambda obj, index: self.objects[obj][index],
            "CFStringGetCString": self.copy_string,
            "CFStringGetLength": lambda obj: len(self.objects[obj]),
            "SecCertificateCreateWithData": self.new_certificate,
            "SecCertificateCopyData": lambda obj: self.new(self.objects[obj]),
            "SecCertificateCopyCommonName": self.common_name,
            "SecPolicyCreateWithProperties": lambda identifier, options: None if behavior == "missing-policy" else self.new("production-policy"),
            "SecTrustCreateWithCertificates": lambda certs, policy, out: self.output(out, self.new("trust")),
            "SecTrustSetAnchorCertificates": lambda trust, anchors: 0,
            "SecTrustSetAnchorCertificatesOnly": lambda trust, only: 0,
            "SecTrustSetNetworkFetchAllowed": lambda trust, allowed: self.set_offline("network", allowed),
            "SecTrustSetKeychainsAllowed": lambda trust, allowed: self.set_offline("keychains", allowed),
            "SecTrustGetNetworkFetchAllowed": lambda trust, out: self.output(out, 1 if behavior == "network-enabled" else self.offline["network"]),
            "SecTrustGetKeychainsAllowed": lambda trust, out: self.output(out, 1 if behavior == "keychains-enabled" else self.offline["keychains"]),
            "SecTrustEvaluateWithError": self.evaluate,
            "SecTrustGetTrustResult": lambda trust, out: self.output(out, 1 if behavior == "user-proceed" else 4),
            "SecTrustCopyCertificateChain": self.chain,
        }
        for name, function in functions.items():
            setattr(self.foundation if name.startswith("CF") else self.security, name, Function(self, name, function))

    def new(self, value):
        pointer = len(self.created) + 100
        self.created.append(pointer)
        self.objects[pointer] = value
        return pointer

    @staticmethod
    def output(out, value):
        out._obj.value = value
        return 0

    def new_certificate(self, allocator, data):
        cert = self.new(self.objects[data])
        self.certificates[self.objects[data]] = cert
        return cert

    def data_bytes(self, obj):
        if self.behavior == "data-pointer":
            return None
        buffer = C.create_string_buffer(self.objects[obj])
        self.buffers.append(buffer)
        return C.addressof(buffer)

    def set_offline(self, key, value):
        self.offline[key] = value
        return 0

    def common_name(self, cert, out):
        if self.objects[cert] == self.leaf:
            name = b"Apple iPhone OS Provisioning Profile Signing"
            if self.behavior == "wrong-leaf-name":
                name += b" TEST"
            if self.behavior == "hidden-name-suffix":
                name += b"\0TEST"
        else:
            name = b"wrong CA" if self.behavior == "wrong-ca-name" else b"Apple iPhone Certification Authority"
        return self.output(out, self.new(name))

    def copy_string(self, obj, buffer, length, encoding):
        if self.behavior == "string-conversion":
            return 0
        value = self.objects[obj] + b"\0"
        C.memmove(buffer, value, len(value))
        return 1

    def evaluate(self, trust, error):
        assert self.offline == {"network": 0, "keychains": 0}
        if self.behavior == "error-object":
            error._obj.value = self.new("CFError")
        return self.behavior != "evaluate-false"

    def chain(self, trust):
        chain = [self.certificates[self.leaf], self.certificates[self.intermediate], self.certificates[self.roots[0]]]
        if self.behavior == "wrong-signer":
            chain[0] = chain[1]
        elif self.behavior == "wrong-root":
            chain[2] = chain[0]
        elif self.behavior == "wrong-order":
            chain.reverse()
        elif self.behavior == "chain-length":
            chain.pop()
        elif self.behavior == "null-certificate":
            chain[1] = None
        return self.new(chain)

    def load(self, path):
        return self.security if path.endswith("/Security") else self.foundation

    def invoke(self):
        with patch("ctypes.CDLL", side_effect=self.load), patch.object(C.c_void_p, "in_dll", return_value=C.c_void_p(99)):
            verify_profile_signer(self.leaf, (self.intermediate, self.leaf))


class NativeTrustContractTests(unittest.TestCase):
    def test_explicit_production_policy_offline_anchors_results_and_reverse_ownership(self):
        api = NativeAPI()
        api.invoke()
        calls = dict(api.calls)
        self.assertEqual(api.released, api.created[::-1])
        self.assertEqual(calls["SecPolicyCreateWithProperties"][0].value, 99)
        self.assertIsNone(calls["SecPolicyCreateWithProperties"][1])
        self.assertEqual(calls["SecTrustSetAnchorCertificatesOnly"][1], 1)
        self.assertEqual(calls["SecTrustSetNetworkFetchAllowed"][1], 0)
        self.assertEqual(calls["SecTrustSetKeychainsAllowed"][1], 0)
        self.assertEqual([api.objects[item] for item in api.objects[calls["SecTrustSetAnchorCertificates"][1]]], list(api.roots))
        presented = api.objects[calls["SecTrustCreateWithCertificates"][0]]
        self.assertEqual([api.objects[item] for item in presented], [api.leaf, api.intermediate])
        for name in ("SecTrustSetNetworkFetchAllowed", "SecTrustSetKeychainsAllowed", "SecTrustSetAnchorCertificatesOnly"):
            function = getattr(api.security, name)
            self.assertEqual(function.restype, C.c_int32)
            self.assertEqual(function.argtypes, [C.c_void_p, C.c_ubyte])
        self.assertEqual(api.security.SecTrustEvaluateWithError.argtypes, [C.c_void_p, C.POINTER(C.c_void_p)])
        self.assertEqual(api.security.SecCertificateCopyCommonName.restype, C.c_int32)

    def test_each_nonzero_osstatus_rejects_and_releases_even_returned_error_objects(self):
        names = ("SecTrustCreateWithCertificates", "SecTrustSetAnchorCertificates", "SecTrustSetAnchorCertificatesOnly",
                 "SecTrustSetNetworkFetchAllowed", "SecTrustSetKeychainsAllowed", "SecTrustGetNetworkFetchAllowed",
                 "SecTrustGetKeychainsAllowed", "SecTrustGetTrustResult", "SecCertificateCopyCommonName")
        for name in names:
            with self.subTest(api=name):
                api = NativeAPI(failed_status=name)
                with self.assertRaises(ValidationError):
                    api.invoke()
                self.assertEqual(api.released, api.created[::-1])
                called = [item[0] for item in api.calls]
                if name not in {"SecTrustGetTrustResult", "SecCertificateCopyCommonName"}:
                    self.assertNotIn("SecTrustEvaluateWithError", called)

    def test_evaluation_user_trust_chain_and_name_faults_fail_without_fallback(self):
        for behavior in ("missing-policy", "network-enabled", "keychains-enabled", "evaluate-false", "error-object",
                         "user-proceed", "chain-length", "null-certificate", "wrong-signer", "wrong-order",
                         "wrong-root", "wrong-leaf-name", "wrong-ca-name", "hidden-name-suffix", "string-conversion",
                         "data-length", "data-pointer"):
            with self.subTest(fault=behavior):
                api = NativeAPI(behavior=behavior)
                with self.assertRaises(ValidationError):
                    api.invoke()
                self.assertEqual(api.released, api.created[::-1])

    def test_unavailable_framework_or_required_symbol_never_degrades_to_generic_trust(self):
        api = NativeAPI()
        for absent in ("SecTrustSetKeychainsAllowed", "SecTrustCopyCertificateChain", "SecPolicyCreateWithProperties"):
            function = getattr(api.security, absent)
            delattr(api.security, absent)
            with self.subTest(api=absent), self.assertRaisesRegex(ValidationError, "unavailable"):
                api.invoke()
            setattr(api.security, absent, function)
        with patch("ctypes.CDLL", side_effect=OSError("private-native-canary")), self.assertRaisesRegex(ValidationError, "unavailable") as error:
            verify_profile_signer(api.leaf, (api.leaf, api.intermediate))
        self.assertNotIn("private-native-canary", str(error.exception))


if __name__ == "__main__":
    unittest.main()
