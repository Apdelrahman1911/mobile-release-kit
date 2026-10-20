"""Selected-record P12 reuse in the SAME original Apple operation.

Only the existing original P12Extraction touches the selected P12/password.
Its actual private-key/leaf/SPKI result is compared to this operation's fresh
stored-key verifier AND selected current certificate/policy phase. No record
scan, new PKCS12, copied assignment or descriptor-only reuse is performed.
The returned object is comparison DATA; native current BoundLoan + original
producer/IO joins + the same-operation certificate holder remain mandatory.
"""
from __future__ import annotations

import hashlib

from .apple_provisioning_api import ProvisioningError
from ._desktop_apple_provisioning_p12 import P12Extraction


MODES = frozenset(("p12-review", "p12-reuse"))


def _need(value):
    if not value:
        raise ProvisioningError("apple_p12_reuse_requires_current_selected_record")


def _compare(leaf, spki, expected_leaf, expected_spki):
    """Bounded exact comparison, deliberately NOT a key/trust constructor."""
    _need(all(type(value) is bytes for value in (leaf, spki, expected_leaf, expected_spki))
          and 0 < len(leaf) <= 64 * 1024 and 0 < len(spki) <= 16 * 1024
          and leaf == expected_leaf and spki == expected_spki)
    return hashlib.sha256(leaf).hexdigest(), hashlib.sha256(spki).hexdigest()


class P12ReuseWork:
    __slots__ = ("_operation", "_source", "_runtime", "_steps", "_selected", "_extraction",
                 "_started", "_complete", "_failure", "_comparison")

    def __init__(self, operation):
        from .desktop_apple_provisioning import AppleProvisioningRun
        from ._desktop_apple_p12_worker import P12Steps
        _need(type(operation) is AppleProvisioningRun and operation.source.require_operation() is operation
              and operation.request.context["mode"] in MODES and operation._p12_reuse is None
              and operation._p12_extraction is None and type(operation._p12_steps) is P12Steps
              and operation.runtime is not None and operation.invocation is not None)
        operation.checkpoint()
        self._operation, self._source, self._runtime, self._steps = (
            operation, operation.source, operation.runtime, operation._p12_steps)
        self._selected = self._extraction = self._failure = self._comparison = None
        self._started = self._complete = False
        operation._p12_reuse = self  # Retain even a subsequent admission refusal.
        self._selected = operation.request.native["p12"]["selectedP12"]
        _need(type(self._selected) is dict and self._source.profile_material(operation) is not None)

    def __repr__(self):
        return "<P12ReuseWork original selected record>"

    def _binding(self):
        op = self._operation
        _need(op._p12_reuse is self and op._p12_steps is self._steps and op.source is self._source
              and op.runtime is self._runtime and op.source.require_operation() is op
              and op.request.context["mode"] in MODES and op.request.native["p12"]["selectedP12"] is self._selected)
        op.checkpoint()
        self._steps.certificate.current_key()
        self._runtime.require(root=op.root, invocation=op.invocation)
        return op

    def run(self):
        op = self._binding()
        _need(not self._started and not self._complete and self._failure is None)
        self._started = True
        try:
            # Constructor binds itself to the SAME operation before scratch
            # acquisition; no independently fabricated public extraction DTO.
            self._extraction = P12Extraction(op)
            self._extraction.run()
            self._comparison = self._compare_originals()
            self._complete = True
            return self
        except BaseException as error:
            self._failure = True
            op.remember(error)
            raise

    def _compare_originals(self):
        op = self._binding()
        child = self._extraction
        _need(type(child) is P12Extraction and op._p12_extraction is child)
        leaf, spki, _chain = child.certificate_inputs(op)
        certificate = self._steps.certificate
        policy = certificate.policy
        _need(policy is not None and policy.result is not None and certificate.policy_ack is not None
              and certificate.identity is not None and not certificate.identity["ambiguous"]
              and certificate.identity["selected"] is not None and op._distribution_key is not None)
        _csr, expected_spki = op._distribution_key.verified_public_parts(op)
        leaf_hash, spki_hash = _compare(leaf, spki, policy.leaf, expected_spki)
        _need(leaf_hash == certificate.identity["selected"]["certificateSha256"]
              and leaf_hash == certificate.policy_result["certificateSha256"]
              and spki_hash == certificate.public_csr.public_key_sha256
              and spki_hash == certificate.policy_result["publicKeySha256"])
        # Existing embedded CA bags are not nominated as Apple trust anchors.
        # Fresh explicit pinned-chain verification already belongs to policy.
        return {"sourceP12": dict(self._selected),
                "p12Sha256": op.request.native["p12"]["p12Sha256"],
                "certificateSha256": leaf_hash, "publicKeySha256": spki_hash,
                "policyAckSha256": certificate.policy_ack}

    def comparison(self, operation):
        _need(operation is self._operation and self._complete and self._failure is None)
        _need(self._compare_originals() == self._comparison)
        return dict(self._comparison)

    def private_closed(self):
        # This does NOT retire the extraction or infer its closure from result
        # DATA. The original operation's existing cleanup calls child.retire.
        return self._extraction is not None and self._extraction.private_closed()
