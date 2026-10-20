"""One supported Apple Distribution certificate request for a DURABLY saved key.

This is the certificate-only child contract of the existing Apple operation,
not a second runner, HTTP client, key generator or journal. The original native
owner must retain the actual current pending-key record/loan and consume its
durable keySaved ACK before it supplies PublicCSR or authorizes this attempt.
Neither PublicCSR, an ACK digest nor a restored receipt is such authority.

The unchanged ProvisioningAttempt owns the possible-send-before-ACK, one-POST,
current-account, cancellation and original-transport gates. A sparse 201 only
retains a resource ID for a fresh bounded inventory; no certificate/profile,
P12, assignment, release readiness or issuance permission is manufactured here.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, replace
from datetime import datetime

from . import apple_provisioning_api as api
from .apple_provisioning import (
    CertificateBinding, Observation, PendingMutation, ProvisioningContext,
    ProvisioningPlan, ProvisioningTarget, PublicCSR, prepare,
)
from .apple_provisioning_recovery import AttemptRecord, ProvisioningAttempt
from .apple_provisioning_signing import SigningInventory

SCOPE = "saved-apple-distribution-key-certificate"
CSR_LIMIT = 4096  # Exact local RSA2048 producer/storage profile, not arbitrary CSR input.
RAW_LIMIT = 128 * 1024
FRAME_LIMIT = 192 * 1024
RECEIPT_LIMIT = 1024
_READS = frozenset({"list_bundle_ids", "list_certificates", "list_profiles"})
# Apple's public Certificate.Attributes schema (2026-10-20) also defines these
# informational properties. They are bounded/typed and then discarded, never
# used to infer a native identity, certificate purpose or account permission.
_INFORMATION = frozenset({"displayName", "name", "serialNumber"})
_ATTRIBUTES = frozenset({"certificateType", "platform", "expirationDate", "certificateContent", "activated"}) | _INFORMATION


def validate_request(request: api.AppleRequest, target: ProvisioningTarget, *, csr: PublicCSR | None) -> None:
    api.validate_request(request)
    api.require(request.kind in _READS | {"create_certificate"}, "unsupported_certificate_operation")
    if request.kind == "list_bundle_ids":
        api.require(dict(request.query)["filter[identifier]"] == target.bundle_id, "bundle_identity_conflict")
    if request.kind == "create_certificate":
        api.require(type(csr) is PublicCSR and len(csr.csr_pem) <= CSR_LIMIT
                    and request == api.create_certificate(csr.csr_pem), "saved_public_csr_required")


def prepare_certificate(context: ProvisioningContext, target: ProvisioningTarget, inventory: SigningInventory, *,
                        bindings: tuple[CertificateBinding, ...], csr: PublicCSR | None,
                        pending: tuple[PendingMutation, ...], now: datetime) -> ProvisioningPlan:
    """Reuse first. The same complete three-inventory reader is reused unchanged.

    A valid existing certificate without its actual private-key binding asks
    for recovery; it never consumes another certificate slot to work around a
    missing key. A missing Bundle ID belongs to the existing registration flow.
    Pending/unknown account operations still precede any new-key/POST proposal.
    """
    api.require(type(inventory) is SigningInventory and (csr is None or type(csr) is PublicCSR
                and len(csr.csr_pem) <= CSR_LIMIT), "invalid_certificate_plan")
    api.require(type(pending) is tuple and len(pending) <= 32 and all(type(row) is PendingMutation for row in pending),
                "invalid_pending_inventory")
    plan = prepare(context, target, inventory.observation, bindings=bindings, csr=csr, pending=pending, now=now,
                   selected_key=csr.key_ref if csr is not None else None)
    if plan.action in {"download_profile", "create_profile"}:
        return replace(plan, action="reuse_certificate", reason="existing_distribution_certificate",
                       request=None, csr=None)
    if plan.action == "register_bundle_id":
        return replace(plan, action="manual", reason="bundle_registration_required", request=None, csr=None)
    if plan.request is not None:
        validate_request(plan.request, target, csr=csr)
    return plan


def response_from_frame(raw: bytes, *, context_sha256: str, operation_id: str, target: ProvisioningTarget,
                        request: api.AppleRequest, csr: PublicCSR | None, key_saved_ack_sha256: str | None,
                        ack_sha256: str | None, settled: bool) -> api.AppleResponse:
    """Private raw body plus genuine original finality, never a helper claim.

    ACK strings only compare the handoff. The same native parent checks the
    actual durable key/save and possible-send ACKs before starting the helper.
    No response-shaped field or parsed receipt can supply those permissions.
    """
    validate_request(request, target, csr=csr)
    api.identifier(operation_id)
    api.require(type(context_sha256) is str and api.HEX_RE.fullmatch(context_sha256) is not None
                and type(settled) is bool, "invalid_adapter_result")
    for ack in (key_saved_ack_sha256, ack_sha256):
        api.require(ack is None if request.method == "GET" else
                    type(ack) is str and api.HEX_RE.fullmatch(ack) is not None, "invalid_adapter_result")
    api.require(type(raw) is bytes and 0 < len(raw) <= FRAME_LIMIT, "invalid_adapter_result")
    value = api.document(raw)
    api.require(set(value) == {"schemaVersion", "scope", "contextSha256", "bundleId", "operationId",
                              "requestSha256", "keySavedAckSha256", "ackSha256", "response"}
                and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["scope"] == SCOPE
                and value["contextSha256"] == context_sha256 and value["bundleId"] == target.bundle_id
                and value["operationId"] == operation_id and value["requestSha256"] == api.request_sha256(request)
                and value["keySavedAckSha256"] == key_saved_ack_sha256 and value["ackSha256"] == ack_sha256,
                "invalid_adapter_result")
    result = value["response"]
    api.require(type(result) is dict and set(result) == {"status", "bodyBase64", "failure"}, "invalid_adapter_result")
    status, encoded, failure = (result[name] for name in ("status", "bodyBase64", "failure"))
    api.require(status is None or type(status) is int and 100 <= status <= 599, "invalid_adapter_result")
    api.require(failure is None or failure == "provider_request_unconfirmed", "invalid_adapter_result")
    if failure is not None:
        api.require(encoded is None, "invalid_adapter_result")
        if status in {400, 401, 403, 404, 405, 409, 422}:
            # Keep a positively returned rejection distinct from a possible
            # send/lost response. No private agreement/quota/account detail.
            return api.AppleResponse(status, b"{}", settled)
        raise api.ProvisioningError("provider_outcome_unknown")
    api.require(type(status) is int and type(encoded) is str and encoded.isascii()
                and 0 < len(encoded) <= 4 * ((RAW_LIMIT + 2) // 3), "invalid_adapter_result")
    try:
        body = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise api.ProvisioningError("invalid_adapter_result") from None
    api.require(0 < len(body) <= RAW_LIMIT and base64.b64encode(body).decode("ascii") == encoded,
                "invalid_adapter_result")
    return api.AppleResponse(status, body, settled)


@dataclass(frozen=True, repr=False)
class CertificateCreationReceipt:
    """Private sparse-response DATA only, safe to keep in the SAME journal row.

    Absent attributes stay absent. Actual DER/SPKI/team/time/purpose and current
    key custody still come from a fresh native certificate binding. This small
    record does not contain a private key, CSR or a certificate body.
    """
    resource_id: str
    certificate_type: str | None
    expires_at: datetime | None
    certificate_sha256: str | None

    def __post_init__(self):
        api.identifier(self.resource_id)
        api.require(self.certificate_type is None or type(self.certificate_type) is str
                    and self.certificate_type == "DISTRIBUTION", "wrong_certificate_type")
        api.require(self.expires_at is None or type(self.expires_at) is datetime and self.expires_at.tzinfo is not None,
                    "invalid_creation_receipt")
        if self.expires_at is not None:
            object.__setattr__(self, "expires_at", api.utc(self.expires_at))
        api.require(self.certificate_sha256 is None or type(self.certificate_sha256) is str
                    and api.HEX_RE.fullmatch(self.certificate_sha256) is not None, "invalid_creation_receipt")

    def private_record(self) -> bytes:
        return api.canonical({"schemaVersion": 1, "resourceId": self.resource_id,
            "certificateType": self.certificate_type,
            "expiresAt": None if self.expires_at is None else self.expires_at.isoformat(),
            "certificateSha256": self.certificate_sha256})

    @property
    def sha256(self) -> str:
        # Different domain from an ordinary full-resource hash on purpose.
        return api.digest(b"MRK-APPLE-CERTIFICATE-CREATION-RECEIPT/1\0" + self.private_record())

    @classmethod
    def from_private_record(cls, raw: bytes) -> CertificateCreationReceipt:
        api.require(type(raw) is bytes and 0 < len(raw) <= RECEIPT_LIMIT, "invalid_creation_receipt")
        value = api.document(raw)
        api.require(set(value) == {"schemaVersion", "resourceId", "certificateType", "expiresAt", "certificateSha256"}
                    and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1, "invalid_creation_receipt")
        result = cls(value["resourceId"], value["certificateType"], None if value["expiresAt"] is None else
                     api.timestamp(value["expiresAt"]), value["certificateSha256"])
        api.require(result.private_record() == raw, "noncanonical_creation_receipt")
        return result

    @classmethod
    def parse(cls, response: api.AppleResponse, before: Observation) -> CertificateCreationReceipt:
        api.require(type(response) is api.AppleResponse and response.status == 201 and type(response.body) is bytes
                    and 0 < len(response.body) <= RAW_LIMIT, "unexpected_provider_status")
        payload = api._checked_response(response)
        api.require(set(payload) <= {"data", "links", "meta"}, "invalid_provider_response")
        data = payload.get("data")
        api.require(type(data) is dict and data.get("type") == "certificates"
                    and set(data) <= {"type", "id", "attributes", "links"}, "invalid_provider_response")
        resource_id = api.identifier(data.get("id"))
        api.require(resource_id not in {row.resource_id for row in before.certificates}, "creation_returned_existing_resource")
        attributes = data.get("attributes", {})
        api.require(type(attributes) is dict and set(attributes) <= _ATTRIBUTES, "invalid_provider_response")
        for name in _INFORMATION & attributes.keys():
            value = attributes[name]
            api.require(type(value) is str and len(value) <= 1024 and len(value.encode("utf-8")) <= 4096
                        and all(ord(character) >= 32 and ord(character) != 127 for character in value),
                        "invalid_provider_response")
        api.require("activated" not in attributes or type(attributes["activated"]) is bool, "invalid_provider_response")
        api.require("certificateType" not in attributes or attributes["certificateType"] == "DISTRIBUTION",
                    "wrong_certificate_type")
        api.require("platform" not in attributes or attributes["platform"] is None or
                    type(attributes["platform"]) is str and attributes["platform"] in {"IOS", "UNIVERSAL"},
                    "wrong_certificate_type")
        return cls(resource_id, attributes.get("certificateType"), api.timestamp(attributes["expirationDate"])
                   if "expirationDate" in attributes else None,
                   api.digest(api._content(attributes["certificateContent"], api.MAX_CERTIFICATE_BYTES))
                   if "certificateContent" in attributes else None)

    def matches(self, certificate: api.Certificate) -> bool:
        return (type(certificate) is api.Certificate and certificate.resource_id == self.resource_id
                and certificate.certificate_type == "DISTRIBUTION"
                and (self.expires_at is None or certificate.expires_at == self.expires_at)
                and (self.certificate_sha256 is None or api.digest(certificate.content) == self.certificate_sha256))


class CertificateCreationAttempt(ProvisioningAttempt):
    """Same real one-attempt engine; only sparse certificate receipt differs."""
    def __init__(self, plan: ProvisioningPlan, before: Observation):
        api.require(plan.action == "create_certificate", "invalid_certificate_plan")
        validate_request(plan.request, plan.target, csr=plan.csr)
        self.receipt: CertificateCreationReceipt | None = None
        self._receipt_conflict = False
        super().__init__(plan, before)

    @classmethod
    def resume(cls, plan: ProvisioningPlan, before: Observation, record: AttemptRecord, *,
               receipt: CertificateCreationReceipt | None) -> CertificateCreationAttempt:
        # Restoring DATA cannot rearm execute or renew write consent. The same
        # owner must still supply its authentic persisted native-finality and
        # current-key/account evidence to the unchanged reconcile method.
        api.require(type(record) is AttemptRecord, "invalid_creation_receipt")
        api.require(receipt is None if record.response_resource_id is None else
                    type(receipt) is CertificateCreationReceipt and receipt.resource_id == record.response_resource_id
                    and receipt.sha256 == record.response_resource_sha256, "invalid_creation_receipt")
        result = super().resume(plan, before, record)
        result.receipt = receipt
        return result

    def retain_returned_response(self, response: api.AppleResponse) -> CertificateCreationReceipt:
        """Keep DATA from the same genuinely returned 201 before late checks.

        The fixed provider calls this only after its actual C/A/W return and
        raw-response binding. It does not authorize a write or supply those
        native facts. In particular a restored row, absent/unsettled result or
        pre-send/failed-ACK attempt cannot acquire a receipt through this cut.
        """
        api.require(type(response) is api.AppleResponse and response.settled is True
                    and self._action_gate.locked(), "original_transport_unsettled")
        receipt = CertificateCreationReceipt.parse(response, self.before)
        with self._state_gate:
            api.require(self._entered and self.record.possible_send
                        and self.record.context == self.plan.context and self.record.plan_sha256 == self.plan.sha256
                        and self.record.status not in {"prepared", "failed", "succeeded", "cancelled"},
                        "operation_not_reconcilable")
            if self.receipt is not None and self.receipt != receipt:
                self._receipt_conflict = True
            api.require(not self._receipt_conflict, "conflicting_creation_receipt")
            if self.receipt is None:
                self.receipt = receipt
            return self.receipt

    def _save(self, owner, record: AttemptRecord) -> AttemptRecord:
        # Same state/cancellation gate as the base implementation. Do not call
        # the base while holding its non-reentrant lock. Only this certificate
        # child merges the already-returned immutable receipt; Bundle/Profile
        # paths and their original persistence/first-failure behavior are intact.
        with self._state_gate:
            if self.receipt is not None:
                if record.response_resource_id is not None and (
                        record.response_resource_id != self.receipt.resource_id or record.response_resource_sha256 != self.receipt.sha256):
                    self._receipt_conflict = True
                record = replace(record, possible_send=True, response_resource_id=self.receipt.resource_id,
                                 response_resource_sha256=self.receipt.sha256)
            if self._receipt_conflict:
                record = replace(record, status="unknown", reason="provider_result_requires_reconciliation")
            record = replace(record, cancel_requested=record.cancel_requested or self._cancel.is_set())
            if record.status == "succeeded" and record.cancel_requested:
                record = replace(record, status="cancelled", reason="cancelled_after_settlement")
            self.record = record
        try:
            owner.persist(record)
        except Exception:
            with self._state_gate:
                self.record = replace(self.record, status="recovery_required", reason="journal_settlement_required")
        return self.record

    def _response_identity(self, response: api.AppleResponse) -> tuple[str, str]:
        receipt = self.retain_returned_response(response)
        return receipt.resource_id, receipt.sha256

    def _response_matches(self, resource: api.Certificate) -> bool:
        return (type(self.receipt) is CertificateCreationReceipt
                and self.record.response_resource_id == self.receipt.resource_id
                and self.record.response_resource_sha256 == self.receipt.sha256 and self.receipt.matches(resource))


def recovery_guidance(record: AttemptRecord) -> str:
    """Fixed plain-language next step, not a new state/permission projection."""
    if record.status in {"failed", "cancelled"} and record.reason == "provider_rejected_request":
        return "Apple refused the request. Check account permissions, agreements and certificate limits; keep the saved key."
    if record.reason == "resource_found_review_required":
        return "A matching certificate was found. Review it with the saved key before continuing; do not create another key."
    if record.status == "succeeded":
        return "The certificate matches the saved key. Finish signing setup, then assign and back up the signing identity."
    return "Keep the saved key. Check the original request and refresh Apple’s certificate list; do not repeat certificate creation."
