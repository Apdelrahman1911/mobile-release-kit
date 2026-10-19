"""Fixed read-only Security calls for the *CredentialInspect child*, not Desktop.

This is generic offline X.509/code-signing validation, NOT an Apple distribution
purpose or a current key loan. Only the separate authenticated App Store profile
can narrow the existing-leaf use below. There is no CertificateBinding producer.

Security calls can block. The original dedicated native child owner must admit
these inputs, contain this worker and join it before using any output. Python
checkpoints neither contain native calls nor establish that owner. No entrypoint,
runtime/consent adapter or installed/native qualification is added here.
"""
from __future__ import annotations

import math
import sys
from datetime import datetime, timezone

from .apple_provisioning_api import ProvisioningError, require
from .cancellation import CleanupScope, DefaultCancellation, cancellation_owner
from .inspection import InspectionDeadline
from .ios_profile_trust import MAX_CERTIFICATE_BYTES, apple_roots
from .owned_process import ProcessCleanupError
from ._profile_callers import fatal_cancellation_error

MAX_INTERMEDIATES = 8
_MAX_REFERENCES = 96
_CF_UNIX_EPOCH = 978307200
_NATIVE_ERROR = "Apple certificate native-call settlement is unknown; end this inspection worker"


def _checkpoint(cancellation: DefaultCancellation, deadline: InspectionDeadline) -> None:
    # Borrow the actual existing same-thread cancellation owner. This check is
    # not evidence of a native worker, account scope, credential loan or consent.
    require(type(cancellation) is DefaultCancellation and type(deadline) is InspectionDeadline,
            "invalid_inspection_owner")
    owner, owns = cancellation_owner(cancellation, ProcessCleanupError, _NATIVE_ERROR)
    require(owner is cancellation and not owns, "invalid_inspection_owner")
    owner.check()
    deadline.check()


def _inputs(leaf_der: bytes, intermediates: tuple[bytes, ...]) -> None:
    require(type(leaf_der) is bytes and 0 < len(leaf_der) <= MAX_CERTIFICATE_BYTES,
            "invalid_existing_certificate")
    require(type(intermediates) is tuple and 1 <= len(intermediates) <= MAX_INTERMEDIATES
            and all(type(value) is bytes and 0 < len(value) <= MAX_CERTIFICATE_BYTES
                    for value in intermediates), "invalid_existing_chain")
    require(leaf_der not in intermediates and len(set(intermediates)) == len(intermediates),
            "invalid_existing_chain")


class _CFReferences:
    """One worker call's CF references; no cleanup retry or reconstructed book.

    A reference slot exists BEFORE its create/copy/out-parameter call. A lost
    native return is not permission to release a guessed pointer, call again or
    continue work. The actual cancellation ledger is poisoned; the original
    parent must end/join this process. CF memory then belongs to that process,
    not to a new Python cleanup or an adopted numeric pointer.
    """

    def __init__(self, release, cancellation: DefaultCancellation, deadline: InspectionDeadline) -> None:
        self.release = release
        self.cancellation, self.deadline = cancellation, deadline
        self.slots: list[int | None] = []
        self.in_call = False
        self.close_claimed = False

    def call(self, function, *arguments):
        _checkpoint(self.cancellation, self.deadline)
        require(not self.in_call and not self.close_claimed, "invalid_inspection_owner")
        self.in_call = True
        result = function(*arguments)
        self.in_call = False
        # Callers retain any returned/out-parameter reference before their next
        # checkpoint. A STOP immediately after creation cannot leak that slot.
        return result

    def object(self, function, *arguments) -> int:
        _checkpoint(self.cancellation, self.deadline)
        require(not self.in_call and not self.close_claimed, "invalid_inspection_owner")
        require(len(self.slots) < _MAX_REFERENCES, "existing_chain_capacity")
        index = len(self.slots)
        self.slots.append(None)
        self.in_call = True
        result = function(*arguments)
        self.slots[index] = result or None
        self.in_call = False
        _checkpoint(self.cancellation, self.deadline)
        require(bool(result), "existing_chain_invalid")
        return result

    def output(self, function, pointer_type, *arguments) -> int:
        import ctypes as C

        _checkpoint(self.cancellation, self.deadline)
        require(not self.in_call and not self.close_claimed, "invalid_inspection_owner")
        require(len(self.slots) < _MAX_REFERENCES, "existing_chain_capacity")
        index = len(self.slots)
        self.slots.append(None)
        output = pointer_type()
        self.in_call = True
        status = function(*arguments, C.byref(output))
        self.slots[index] = output.value
        self.in_call = False
        _checkpoint(self.cancellation, self.deadline)
        require(status == 0 and bool(output.value), "existing_chain_invalid")
        return output.value

    def evaluate(self, function, pointer_type, trust) -> None:
        import ctypes as C

        _checkpoint(self.cancellation, self.deadline)
        require(not self.in_call and not self.close_claimed, "invalid_inspection_owner")
        require(len(self.slots) < _MAX_REFERENCES, "existing_chain_capacity")
        index = len(self.slots)
        self.slots.append(None)
        error = pointer_type()
        self.in_call = True
        accepted = function(trust, C.byref(error))
        self.slots[index] = error.value  # Even success plus CFError is a refusal.
        self.in_call = False
        _checkpoint(self.cancellation, self.deadline)
        require(bool(accepted) and not error.value, "existing_chain_invalid")

    def close(self) -> None:
        if self.close_claimed:
            return
        self.close_claimed = True
        if self.in_call:
            # Unknown call completion may still use borrowed references. Do not
            # attempt another native call, even release, on this path.
            raise ProcessCleanupError(_NATIVE_ERROR, contained=False)
        while self.slots:
            value = self.slots.pop()  # Retire BEFORE the one release attempt.
            if value is None:
                continue
            try:
                self.release(value)
            except BaseException as error:
                # Remaining backing is held by the process until its original
                # parent observes termination. No subsequent CF call is safe.
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise  # Existing CleanupScope retains this first primary.
                raise ProcessCleanupError(_NATIVE_ERROR, contained=False) from None


def _verify_leaf_chain_in_worker(leaf_der: bytes, intermediates: tuple[bytes, ...], *,
                                 cancellation: DefaultCancellation,
                                 deadline: InspectionDeadline) -> datetime:
    """Check only offline generic chain/codeSigning; return its native check time.

    PRIVATE worker primitive. Never call on the Desktop/UI/native owner thread.
    No private key, profile, policy selector, anchor or caller date is accepted.
    The return is comparison DATA, not a trusted distribution/assignment token.
    """
    import ctypes as C

    _inputs(leaf_der, intermediates)
    _checkpoint(cancellation, deadline)
    require(sys.platform == "darwin", "existing_chain_unavailable")
    roots = apple_roots()
    _checkpoint(cancellation, deadline)
    require(leaf_der not in roots and all(value not in roots for value in intermediates),
            "invalid_existing_chain")
    try:
        security = C.CDLL("/System/Library/Frameworks/Security.framework/Security")
        foundation = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        pointer, status = C.c_void_p, C.c_int32

        def bind(library, name, result, arguments):
            function = getattr(library, name)
            function.restype, function.argtypes = result, arguments
            return function

        release = bind(foundation, "CFRelease", None, [pointer])
        type_id = bind(foundation, "CFGetTypeID", C.c_ulong, [pointer])
        types = {}
        for name, library in (("CFData", foundation), ("CFArray", foundation),
                              ("CFDate", foundation), ("CFString", foundation),
                              ("SecCertificate", security), ("SecPolicy", security), ("SecTrust", security)):
            types[name] = bind(library, name + "GetTypeID", C.c_ulong, [])
        data_create = bind(foundation, "CFDataCreate", pointer, [pointer, pointer, C.c_long])
        data_length = bind(foundation, "CFDataGetLength", C.c_long, [pointer])
        data_bytes = bind(foundation, "CFDataGetBytePtr", pointer, [pointer])
        array_create = bind(foundation, "CFArrayCreate", pointer, [pointer, pointer, C.c_long, pointer])
        array_count = bind(foundation, "CFArrayGetCount", C.c_long, [pointer])
        array_item = bind(foundation, "CFArrayGetValueAtIndex", pointer, [pointer, C.c_long])
        current_time = bind(foundation, "CFAbsoluteTimeGetCurrent", C.c_double, [])
        date_create = bind(foundation, "CFDateCreate", pointer, [pointer, C.c_double])
        date_time = bind(foundation, "CFDateGetAbsoluteTime", C.c_double, [pointer])
        cert_create = bind(security, "SecCertificateCreateWithData", pointer, [pointer, pointer])
        cert_data = bind(security, "SecCertificateCopyData", pointer, [pointer])
        basic_policy = bind(security, "SecPolicyCreateBasicX509", pointer, [])
        signing_policy = bind(security, "SecPolicyCreateWithProperties", pointer, [pointer, pointer])
        trust_create = bind(security, "SecTrustCreateWithCertificates", status, [pointer, pointer, C.POINTER(pointer)])
        set_anchors = bind(security, "SecTrustSetAnchorCertificates", status, [pointer, pointer])
        anchors_only = bind(security, "SecTrustSetAnchorCertificatesOnly", status, [pointer, C.c_ubyte])
        network = bind(security, "SecTrustSetNetworkFetchAllowed", status, [pointer, C.c_ubyte])
        keychains = bind(security, "SecTrustSetKeychainsAllowed", status, [pointer, C.c_ubyte])
        get_network = bind(security, "SecTrustGetNetworkFetchAllowed", status, [pointer, C.POINTER(C.c_ubyte)])
        get_keychains = bind(security, "SecTrustGetKeychainsAllowed", status, [pointer, C.POINTER(C.c_ubyte)])
        verify_date = bind(security, "SecTrustSetVerifyDate", status, [pointer, pointer])
        evaluate = bind(security, "SecTrustEvaluateWithError", C.c_bool, [pointer, C.POINTER(pointer)])
        trust_result = bind(security, "SecTrustGetTrustResult", status, [pointer, C.POINTER(C.c_uint32)])
        copy_chain = bind(security, "SecTrustCopyCertificateChain", pointer, [pointer])
        identifier = pointer.in_dll(security, "kSecPolicyAppleCodeSigning")
        require(bool(identifier.value), "existing_chain_unavailable")
    except (AttributeError, OSError, ValueError):
        raise ProvisioningError("existing_chain_unavailable") from None

    references = _CFReferences(release, cancellation, deadline)
    scope = CleanupScope(cancellation, references.close, owns_cancellation=False, first_primary=True)
    try:
        try:
            with scope:
                def typed(value, kind):
                    require(bool(value) and references.call(type_id, value) == references.call(types[kind]),
                            "existing_chain_invalid")
                    return value

                def data(raw):
                    return typed(references.object(data_create, None, raw, len(raw)), "CFData")

                def certificate(raw):
                    return typed(references.object(cert_create, None, data(raw)), "SecCertificate")

                def array(values):
                    # Non-retaining caller array; its values outlive it. SecTrust
                    # retains copies of its own inputs, as in the profile owner.
                    return typed(references.object(array_create, None, (pointer * len(values))(*values),
                                                   len(values), None), "CFArray")

                def encoded(value):
                    typed(value, "SecCertificate")
                    raw = typed(references.object(cert_data, value), "CFData")
                    size = references.call(data_length, raw)
                    require(0 < size <= MAX_CERTIFICATE_BYTES, "existing_chain_invalid")
                    location = references.call(data_bytes, raw)
                    require(bool(location), "existing_chain_invalid")
                    result = C.string_at(location, size)
                    _checkpoint(cancellation, deadline)
                    return result

                typed(identifier, "CFString")
                policies = array([typed(references.object(basic_policy), "SecPolicy"),
                                  typed(references.object(signing_policy, identifier, None), "SecPolicy")])
                presented = array([certificate(value) for value in (leaf_der, *intermediates)])
                anchors = array([certificate(value) for value in roots])
                trust = typed(references.output(trust_create, pointer, presented, policies), "SecTrust")
                for function, value in ((set_anchors, anchors), (anchors_only, 1), (network, 0), (keychains, 0)):
                    require(references.call(function, trust, value) == 0, "existing_chain_invalid")
                for getter in (get_network, get_keychains):
                    allowed = C.c_ubyte(1)
                    require(references.call(getter, trust, C.byref(allowed)) == 0 and allowed.value == 0,
                            "existing_chain_invalid")
                native_time = references.call(current_time)
                require(math.isfinite(native_time) and 0 <= native_time + _CF_UNIX_EPOCH < 253402300799,
                        "existing_chain_invalid")
                date = typed(references.object(date_create, None, native_time), "CFDate")
                require(references.call(date_time, date) == native_time, "existing_chain_invalid")
                require(references.call(verify_date, trust, date) == 0, "existing_chain_invalid")
                checked_at = datetime.fromtimestamp(native_time + _CF_UNIX_EPOCH, timezone.utc)
                references.evaluate(evaluate, pointer, trust)
                result = C.c_uint32(0)
                require(references.call(trust_result, trust, C.byref(result)) == 0 and result.value == 4,
                        "existing_chain_invalid")  # Unspecified, never user Proceed.
                chain = typed(references.object(copy_chain, trust), "CFArray")
                count = references.call(array_count, chain)
                require(3 <= count <= len(intermediates) + 2, "existing_chain_invalid")
                values = tuple(encoded(references.call(array_item, chain, index)) for index in range(count))
                require(values[0] == leaf_der and values[-1] in roots and len(set(values)) == len(values)
                        and all(value in intermediates for value in values[1:-1]), "existing_chain_invalid")
                _checkpoint(cancellation, deadline)
        finally:
            # Existing original cleanup frame; closes once even if the with-exit
            # handoff itself was interrupted. Ambiguous CF calls never replay.
            scope.__exit__(*sys.exc_info())
    except BaseException as error:
        fatal = fatal_cancellation_error(error, cancellation, _NATIVE_ERROR)
        if fatal is not None:
            raise fatal from None
        raise
    _checkpoint(cancellation, deadline)
    return checked_at
