"""Read-only Apple provisioning-signature purpose verification in an isolated worker.

Policy semantics: Apple Security db15acbe6a7f257a859ad9a3bb86097bfe0679d9,
SecPolicyCreateiPhoneProvisioningProfileSigning / SecTrustSetKeychainsAllowed.
No generic trust, user anchors, network retrieval, date override or TEST purpose.
Apple's profile policy intentionally omits signer-chain time/network revocation;
authenticated profile dates and the application's signing validity are separate.
"""
from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

from .errors import ValidationError

MAX_CERTIFICATE_BYTES = 64 * 1024
MAX_CERTIFICATES = 16
APPLE_ROOT_SHA256 = frozenset({
    "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
    "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
    "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
})


def require(condition: bool) -> None:
    if not condition:
        raise ValidationError("provisioning CMS signature or Apple production issuer is invalid or unsupported")


def pem_certificates(content: bytes) -> tuple[bytes, ...]:
    require(type(content) is bytes and 0 < len(content) <= MAX_CERTIFICATE_BYTES * MAX_CERTIFICATES * 2)
    pattern = rb"-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----"
    certificates, position = [], 0
    for match in re.finditer(pattern, content):
        require(not content[position:match.start()].strip())
        body = match[1].replace(b"\r", b"").replace(b"\n", b"")
        try:
            decoded = base64.b64decode(body, validate=True)
        except ValueError:
            raise ValidationError("provisioning certificate encoding is invalid") from None
        require(0 < len(decoded) <= MAX_CERTIFICATE_BYTES and base64.b64encode(decoded) == body)
        certificates.append(decoded)
        require(len(certificates) <= MAX_CERTIFICATES)
        position = match.end()
    require(bool(certificates) and not content[position:].strip() and len(set(certificates)) == len(certificates))
    return tuple(certificates)


def apple_roots() -> tuple[bytes, ...]:
    # Public Apple CA certificates only, pinned independently of the artifact.
    from .ios_profiles import read_profile_bytes

    roots = pem_certificates(read_profile_bytes(Path(__file__).parent / "data/apple-profile-roots.pem", maximum=16 * 1024))
    require(len(roots) == 3 and {hashlib.sha256(item).hexdigest() for item in roots} == APPLE_ROOT_SHA256)
    return roots


def verify_profile_signer(signer: bytes, certificates: tuple[bytes, ...]) -> None:
    """Authenticate the exact CMS signer, not any convenient presented certificate."""
    import ctypes as C

    require(0 < len(certificates) <= MAX_CERTIFICATES and signer in certificates)
    require(len(set(certificates)) == len(certificates))
    require(all(type(item) is bytes and 0 < len(item) <= MAX_CERTIFICATE_BYTES for item in certificates))
    roots = apple_roots()
    owned = []
    release = None
    try:
        security = C.CDLL("/System/Library/Frameworks/Security.framework/Security")
        foundation = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        pointer = C.c_void_p

        def bind(library, name, result, arguments):
            function = getattr(library, name)
            function.restype, function.argtypes = result, arguments
            return function

        release = bind(foundation, "CFRelease", None, [pointer])
        data_create = bind(foundation, "CFDataCreate", pointer, [pointer, pointer, C.c_long])
        data_length = bind(foundation, "CFDataGetLength", C.c_long, [pointer])
        data_bytes = bind(foundation, "CFDataGetBytePtr", pointer, [pointer])
        array_create = bind(foundation, "CFArrayCreate", pointer, [pointer, pointer, C.c_long, pointer])
        array_count = bind(foundation, "CFArrayGetCount", C.c_long, [pointer])
        array_item = bind(foundation, "CFArrayGetValueAtIndex", pointer, [pointer, C.c_long])
        string_bytes = bind(foundation, "CFStringGetCString", C.c_ubyte, [pointer, pointer, C.c_long, C.c_uint32])
        string_length = bind(foundation, "CFStringGetLength", C.c_long, [pointer])
        cert_create = bind(security, "SecCertificateCreateWithData", pointer, [pointer, pointer])
        cert_data = bind(security, "SecCertificateCopyData", pointer, [pointer])
        cert_name = bind(security, "SecCertificateCopyCommonName", C.c_int32, [pointer, C.POINTER(pointer)])
        policy_create = bind(security, "SecPolicyCreateWithProperties", pointer, [pointer, pointer])
        trust_create = bind(security, "SecTrustCreateWithCertificates", C.c_int32, [pointer, pointer, C.POINTER(pointer)])
        set_anchors = bind(security, "SecTrustSetAnchorCertificates", C.c_int32, [pointer, pointer])
        anchors_only = bind(security, "SecTrustSetAnchorCertificatesOnly", C.c_int32, [pointer, C.c_ubyte])
        network = bind(security, "SecTrustSetNetworkFetchAllowed", C.c_int32, [pointer, C.c_ubyte])
        keychains = bind(security, "SecTrustSetKeychainsAllowed", C.c_int32, [pointer, C.c_ubyte])
        get_network = bind(security, "SecTrustGetNetworkFetchAllowed", C.c_int32, [pointer, C.POINTER(C.c_ubyte)])
        get_keychains = bind(security, "SecTrustGetKeychainsAllowed", C.c_int32, [pointer, C.POINTER(C.c_ubyte)])
        evaluate = bind(security, "SecTrustEvaluateWithError", C.c_bool, [pointer, C.POINTER(pointer)])
        get_result = bind(security, "SecTrustGetTrustResult", C.c_int32, [pointer, C.POINTER(C.c_uint32)])
        copy_chain = bind(security, "SecTrustCopyCertificateChain", pointer, [pointer])

        def own(value):
            require(bool(value))
            owned.append(value)
            return value

        def out_call(function, *arguments):
            result = pointer()
            status = function(*arguments, C.byref(result))
            if result.value:
                owned.append(result.value)
            require(status == 0 and bool(result.value))
            return result.value

        def certificate(raw):
            return own(cert_create(None, own(data_create(None, raw, len(raw)))))

        def array(values):
            # Values outlive this non-retaining caller array. SecTrust copies
            # presented/anchor certificates into its own retaining arrays, so
            # releasing caller references cannot invalidate the trust object.
            return own(array_create(None, (pointer * len(values))(*values), len(values), None))

        def encoded(cert):
            data = own(cert_data(cert))
            length = data_length(data)
            require(0 < length <= MAX_CERTIFICATE_BYTES)
            location = data_bytes(data)
            require(bool(location))
            return C.string_at(location, length)

        def common_name(cert):
            name = out_call(cert_name, cert)
            buffer = C.create_string_buffer(4096)
            require(bool(string_bytes(name, buffer, len(buffer), 0x08000100)))  # UTF-8
            require(string_length(name) == len(buffer.value))  # Exact ASCII names; no embedded NUL suffix.
            return buffer.value

        identifier = pointer.in_dll(security, "kSecPolicyAppleiPhoneProvisioningProfileSigning")
        require(bool(identifier.value))
        policy = own(policy_create(identifier, None))
        presented = array([certificate(signer), *(certificate(item) for item in certificates if item != signer)])
        trust = out_call(trust_create, presented, policy)
        require(set_anchors(trust, array([certificate(item) for item in roots])) == 0)
        require(anchors_only(trust, 1) == 0 and network(trust, 0) == 0 and keychains(trust, 0) == 0)
        for getter in (get_network, get_keychains):
            allowed = C.c_ubyte(1)
            require(getter(trust, C.byref(allowed)) == 0 and allowed.value == 0)
        error = pointer()
        accepted = evaluate(trust, C.byref(error))
        if error.value:
            owned.append(error.value)
        require(bool(accepted) and not error.value)
        result = C.c_uint32()
        require(get_result(trust, C.byref(result)) == 0 and result.value == 4)  # Unspecified, NOT user Proceed.
        chain = own(copy_chain(trust))
        require(array_count(chain) == 3)
        leaf, intermediate, anchor = (array_item(chain, index) for index in range(3))
        require(bool(leaf) and bool(intermediate) and bool(anchor))
        require(encoded(leaf) == signer)
        require(common_name(leaf) == b"Apple iPhone OS Provisioning Profile Signing")
        require(common_name(intermediate) == b"Apple iPhone Certification Authority")
        require(hashlib.sha256(encoded(anchor)).hexdigest() in APPLE_ROOT_SHA256)
    except (AttributeError, OSError, ValueError):
        raise ValidationError("supported macOS Apple provisioning-profile trust APIs are unavailable") from None
    finally:
        if release is not None:
            for value in reversed(owned):
                release(value)
