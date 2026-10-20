"""One-attempt provisioning execution and conservative read-only reconciliation.

Persistence/authorization/settlement are callbacks on the original native owner,
not booleans from Apple, a renderer or a newly discovered PID. A sent/possibly
sent request is never reissued by this object. Reconciliation can identify an
asset for explicit owner review without claiming that MRK created it.
"""
from __future__ import annotations

from _thread import LockType
from dataclasses import dataclass, field, replace
from datetime import datetime
from threading import Event, Lock
from typing import Protocol

from . import apple_provisioning_api as api
from .apple_provisioning import (
    BUNDLE_ID_SCOPE, MAX_OBSERVATION_AGE, SIGNING_SCOPE, CertificateBinding, Observation, PendingMutation, ProvisioningContext,
    ProvisioningPlan, ProvisioningProvider,
)


@dataclass(frozen=True, repr=False)
class ProvisioningApproval:
    context: ProvisioningContext
    plan_sha256: str
    action: str


@dataclass(frozen=True, repr=False)
class AttemptRecord:
    context: ProvisioningContext
    plan_sha256: str
    action: str
    status: str
    reason: str
    possible_send: bool = False
    response_resource_id: str | None = None
    response_resource_sha256: str | None = None
    observed_resource_id: str | None = None
    cancel_requested: bool = False

    def pending(self) -> PendingMutation:
        return PendingMutation(self.context.account_ref, self.context.operation_id, self.action, self.status)

    def summary(self) -> dict:
        # Resource IDs, CSR, bodies, private native references and provider error
        # detail are deliberately absent. Recovery ownership is not readiness.
        return {"operationId": self.context.operation_id, "action": self.action,
                "status": self.status, "reason": self.reason,
                "retryAllowed": False, "credentialReady": False,
                "cancellationRequested": self.cancel_requested}


class ProvisioningOwner(Protocol):
    def authorize(self, plan: ProvisioningPlan, approval: ProvisioningApproval) -> None:
        """Check current registered context, native key loan, consent/account lease."""

    def persist(self, record: AttemptRecord) -> None:
        """Acknowledge durable publication before a send; failure vetoes that send."""

    def transport_settled(self, record: AttemptRecord) -> bool:
        """Original owner's actual lifecycle finality, never just response-shaped JSON."""

    def reconciliation_current(self, plan: ProvisioningPlan, record: AttemptRecord) -> bool:
        """Current registered context/account lease/native key inspection loan.

        Read-only recovery does not renew or reconstruct expired write consent.
        The durable record must belong to this original owner and selected scope.
        """


_MUTATIONS = frozenset({"register_bundle_id", "create_certificate", "create_profile"})
_REJECTED = frozenset({400, 401, 403, 404, 405, 409, 422})


@dataclass(repr=False)
class ProvisioningAttempt:
    plan: ProvisioningPlan
    before: Observation = field(repr=False)
    record: AttemptRecord = field(init=False)
    _entered: bool = field(default=False, init=False, repr=False)
    _action_gate: LockType = field(default_factory=Lock, init=False, repr=False)
    _state_gate: LockType = field(default_factory=Lock, init=False, repr=False)
    _cancel: Event = field(default_factory=Event, init=False, repr=False)

    def __post_init__(self) -> None:
        api.require(self.plan.action in _MUTATIONS and self.plan.request is not None
                    and self.plan.request.method == "POST" and self.plan.request.kind == self.plan.action
                    and self.before.available
                    and self.before.context == self.plan.context and self.before.bundle_id == self.plan.target.bundle_id
                    and self.before.sha256 == self.plan.observation_sha256, "invalid_mutation_plan")
        api.require(self.before.scope == SIGNING_SCOPE or self.before.scope == BUNDLE_ID_SCOPE
                    and self.plan.action == "register_bundle_id", "observation_scope_changed")
        if self.before.scope == BUNDLE_ID_SCOPE:
            api.require(self.before.bundles == () and self.plan.target.entitlements_json == b"{}"
                        and all(value is None for value in (self.plan.bundle, self.plan.certificate,
                                                           self.plan.binding, self.plan.profile, self.plan.csr)),
                        "invalid_mutation_plan")
        api.validate_request(self.plan.request)
        if self.plan.action == "create_certificate":
            api.require(self.plan.csr is not None and self.plan.bundle is not None
                        and self.plan.request == api.create_certificate(self.plan.csr.csr_pem), "invalid_mutation_plan")
        elif self.plan.action == "create_profile":
            api.require(self.plan.bundle is not None and self.plan.certificate is not None
                        and self.plan.binding is not None, "invalid_mutation_plan")
            name = "MRK-" + api.digest(self.plan.context.operation_id.encode("utf-8"))[:24]
            api.require(self.plan.request == api.create_profile(name, self.plan.bundle.resource_id,
                                                               self.plan.certificate.resource_id), "invalid_mutation_plan")
        else:
            api.require(self.plan.target.existing_application is False and self.plan.request == api.register_bundle_id(
                self.plan.target.bundle_id, self.plan.target.display_name), "invalid_mutation_plan")
        self.record = AttemptRecord(self.plan.context, self.plan.sha256, self.plan.action, "prepared", "approval_required")

    @classmethod
    def resume(cls, plan: ProvisioningPlan, before: Observation, record: AttemptRecord) -> ProvisioningAttempt:
        """Original durable record only; restarting never grants another send.

        The caller still needs original persisted transport finality. Loading a
        matching record does not manufacture that evidence or adopt a process.
        """
        api.require(type(record) is AttemptRecord and record.context == plan.context
                    and record.plan_sha256 == plan.sha256 and record.action == plan.action
                    and record.possible_send is True and type(record.cancel_requested) is bool
                    and record.status in {"running", "unknown", "recovery_required", "cancellation_requested", "succeeded"},
                    "invalid_recovery_record")
        for resource_id in (record.response_resource_id, record.observed_resource_id):
            if resource_id is not None:
                api.identifier(resource_id)
        api.require((record.response_resource_id is None and record.response_resource_sha256 is None)
                    or (record.response_resource_id is not None and type(record.response_resource_sha256) is str
                        and api.HEX_RE.fullmatch(record.response_resource_sha256) is not None), "invalid_recovery_record")
        result = cls(plan, before)
        result.record = record
        if record.cancel_requested:
            result._cancel.set()
        result._entered = True
        return result

    def request_cancel(self) -> None:
        """Mark the original owner's durably acknowledged cancellation request.

        The native cancellation owner persists the request and stops/joins its
        original transport. This local latch does neither and cannot claim that
        a sent request was cancelled at Apple. It remains callable during send.
        """
        with self._state_gate:
            if self.record.status in {"succeeded", "failed", "cancelled"}:
                return
            self._cancel.set()
            if self.record.status == "prepared":
                self.record = replace(self.record, status="cancelled", reason="cancelled_before_send", cancel_requested=True)
            else:
                self.record = replace(self.record, status="cancellation_requested", cancel_requested=True)

    def _save(self, owner: ProvisioningOwner, record: AttemptRecord) -> AttemptRecord:
        with self._state_gate:
            record = replace(record, cancel_requested=record.cancel_requested or self._cancel.is_set())
            if record.status == "succeeded" and record.cancel_requested:
                record = replace(record, status="cancelled", reason="cancelled_after_settlement")
            self.record = record
        try:
            owner.persist(record)
        except Exception:
            # No automatic journal retry and never report success when its
            # durable result is uncertain. Retain the original object in owner.
            with self._state_gate:
                self.record = replace(self.record, status="recovery_required", reason="journal_settlement_required")
        return self.record

    def execute(self, approval: ProvisioningApproval, fresh: Observation, provider: ProvisioningProvider,
                owner: ProvisioningOwner, *, now: datetime) -> AttemptRecord:
        # Reject concurrent/reentrant entry before any owner callback. This is
        # only a local guard; durable account-wide one-attempt admission remains
        # the original owner's responsibility across objects/processes/restarts.
        api.require(self._action_gate.acquire(blocking=False), "operation_busy")
        try:
            return self._execute(approval, fresh, provider, owner, now=now)
        finally:
            self._action_gate.release()

    def _execute(self, approval: ProvisioningApproval, fresh: Observation, provider: ProvisioningProvider,
                 owner: ProvisioningOwner, *, now: datetime) -> AttemptRecord:
        api.require(not self._entered and self.record.status == "prepared", "operation_already_attempted")
        api.require(approval.context == self.plan.context and approval.action == self.plan.action
                    and approval.plan_sha256 == self.plan.sha256 == self.record.plan_sha256, "approval_changed")
        api.require(fresh.available and fresh.context == self.plan.context
                    and fresh.scope == self.before.scope
                    and fresh.sha256 == self.plan.observation_sha256
                    and fresh.observed_at <= api.utc(now) < self.plan.valid_until, "observation_changed")
        try:
            owner.authorize(self.plan, approval)
            provider.check(self.plan.context)
        except Exception:
            raise api.ProvisioningError("authorization_changed") from None
        if self.plan.binding is not None:
            api.require(self.plan.binding.matches(self.plan.certificate, self.plan.target, api.utc(now)), "certificate_expired")
        self._entered = True
        # Arm possible-send BEFORE the durable callback. A crash just after its
        # return cannot leave an apparently retryable operation in the journal.
        with self._state_gate:
            armed = replace(self.record, status="running", reason="readback_required", possible_send=True,
                            cancel_requested=self._cancel.is_set())
            self.record = armed
        try:
            owner.persist(armed)
        except Exception:
            # In this still-live owner, no provider call occurred. A recovered
            # journal may conservatively say possible-send; preserve it.
            with self._state_gate:
                self.record = replace(self.record, status="recovery_required", reason="journal_settlement_required", possible_send=False)
            return self.record
        try:
            owner.authorize(self.plan, approval)
            provider.check(self.plan.context)
        except Exception:
            return self._save(owner, replace(self.record, status="failed", reason="authorization_changed", possible_send=False))
        if self.record.cancel_requested:
            return self._save(owner, replace(self.record, status="cancelled", reason="cancelled_before_send", possible_send=False))

        try:
            response = provider.send(self.plan.request)
        except BaseException as error:
            record = self._save(owner, replace(self.record, status="unknown", reason="provider_outcome_unknown"))
            if not isinstance(error, Exception):
                raise
            return record

        try:
            settled = (type(response) is api.AppleResponse and type(response.settled) is bool
                       and response.settled and owner.transport_settled(self.record))
        except Exception:
            settled = False
        if not settled:
            return self._save(owner, replace(self.record, status="unknown", reason="original_transport_unsettled"))
        try:
            owner.authorize(self.plan, approval)
            provider.check(self.plan.context)
        except Exception:
            return self._save(owner, replace(self.record, status="unknown", reason="authorization_changed_after_send"))
        if type(response.status) is int and response.status in _REJECTED:
            status = "cancelled" if self.record.cancel_requested else "failed"
            return self._save(owner, replace(self.record, status=status, reason="provider_rejected_request"))

        try:
            resource_id, resource_sha256 = self._response_identity(response)
        except (api.ProvisioningError, ValueError, TypeError):
            return self._save(owner, replace(self.record, status="unknown", reason="provider_result_requires_reconciliation"))
        # A good response is not readback, native authentication, assignment or
        # final release evidence. Keep previous successes/IDs; never clean them
        # up through a revoke/delete after a later failure.
        return self._save(owner, replace(self.record, status="recovery_required", reason="readback_required",
                                         response_resource_id=resource_id, response_resource_sha256=resource_sha256))

    def _response_identity(self, response: api.AppleResponse) -> tuple[str, str]:
        if self.before.scope == BUNDLE_ID_SCOPE:
            api.require(response.status == 201, "unexpected_provider_status")
        value = api.single(response, self.plan.request.resource_type, inspect_page=(
            lambda page: api.validate_profile_included(page, self.before.bundles, self.before.certificates,
                                                       bundle_id=self.plan.target.bundle_id)
        ) if self.plan.action == "create_profile" else None)
        if self.plan.action == "register_bundle_id":
            resource = api.BundleId.parse(value)
            api.require(resource.identifier == self.plan.target.bundle_id and resource.platform in {"IOS", "UNIVERSAL"}
                        and resource.seed_id == self.plan.target.app_id_prefix, "bundle_identity_conflict")
        elif self.plan.action == "create_certificate":
            resource = api.Certificate.parse(value)
            api.require(resource.certificate_type == "DISTRIBUTION", "wrong_certificate_type")
        else:
            resource = api.Profile.parse(value)
            attributes = api.document(self.plan.request.body)["data"]["attributes"]
            api.require(resource.name == attributes["name"] and resource.state == "ACTIVE"
                        and resource.bundle_id_resource == self.plan.bundle.resource_id
                        and resource.certificate_resources == (self.plan.certificate.resource_id,), "profile_identity_mismatch")
        resource_id = resource.resource_id
        api.require(resource_id not in self._before_ids(), "creation_returned_existing_resource")
        return resource_id, api.resource_sha256(resource)

    def _before_ids(self) -> set[str]:
        values = {"register_bundle_id": self.before.bundles, "create_certificate": self.before.certificates,
                  "create_profile": self.before.profiles}[self.plan.action]
        return {value.resource_id for value in values}

    def reconcile(self, observation: Observation, owner: ProvisioningOwner, *,
                  bindings: tuple[CertificateBinding, ...], now: datetime) -> AttemptRecord:
        api.require(self._action_gate.acquire(blocking=False), "operation_busy")
        try:
            return self._reconcile(observation, owner, bindings=bindings, now=now)
        finally:
            self._action_gate.release()

    def _reconcile(self, observation: Observation, owner: ProvisioningOwner, *,
                   bindings: tuple[CertificateBinding, ...], now: datetime) -> AttemptRecord:
        api.require(self._entered and self.record.possible_send and self.record.status not in {"failed", "cancelled"},
                    "operation_not_reconcilable")
        if self.record.status == "succeeded":
            return self.record
        api.require(observation.context == self.plan.context and observation.bundle_id == self.plan.target.bundle_id
                    and observation.scope == self.before.scope,
                    "observation_context_changed")
        now = api.utc(now)
        api.require(observation.observed_at >= self.before.observed_at
                    and observation.observed_at <= now < observation.observed_at + MAX_OBSERVATION_AGE,
                    "stale_reconciliation")
        if not observation.available:
            return self._save(owner, replace(self.record, status="unknown", reason="reconciliation_read_unavailable"))
        try:
            current = owner.reconciliation_current(self.plan, self.record)
        except Exception:
            current = False
        if current is not True:
            return self._save(owner, replace(self.record, status="unknown", reason="reconciliation_context_changed"))
        try:
            matches = self._matching_resources(observation, bindings, now)
        except api.ProvisioningError:
            return self._save(owner, replace(self.record, status="recovery_required", reason="resource_validation_required"))
        if len(matches) != 1:
            # In particular, an empty later inventory NEVER permits a second
            # create. Apple does not document an issuance idempotency token.
            reason = "provider_outcome_still_unknown" if not matches else "ambiguous_recovery_resources"
            return self._save(owner, replace(self.record, status="unknown", reason=reason))
        matched = matches[0]
        matched_id = matched.resource_id
        try:
            settled = owner.transport_settled(self.record)
            current = owner.reconciliation_current(self.plan, self.record)
        except Exception:
            settled = False
            current = False
        if current is not True:
            return self._save(owner, replace(self.record, status="unknown", reason="reconciliation_context_changed"))
        if settled is not True:
            return self._save(owner, replace(self.record, status="unknown", reason="original_transport_unsettled",
                                             observed_resource_id=matched_id))
        if self.record.response_resource_id is None:
            # A resource matching name/Bundle ID/SPKI may have been created by
            # another client. Surface it for explicit native-owner review; do
            # not silently attribute/adopt it or enable the next write.
            return self._save(owner, replace(self.record, status="recovery_required", reason="resource_found_review_required",
                                             observed_resource_id=matched_id))
        if not self._response_matches(matched):
            return self._save(owner, replace(self.record, status="unknown", reason="response_readback_disagrees"))
        status = "cancelled" if self.record.cancel_requested else "succeeded"
        return self._save(owner, replace(self.record, status=status,
                                         reason="cancelled_after_settlement" if self.record.cancel_requested else "provider_resource_confirmed",
                                         observed_resource_id=matched_id))

    def _response_matches(self, resource) -> bool:
        # Default full-resource comparison stays unchanged. The profile-only
        # subclass compares its retained sparse 201 receipt to the exact GET.
        return (resource.resource_id == self.record.response_resource_id
                and api.resource_sha256(resource) == self.record.response_resource_sha256)

    def _matching_resources(self, observation: Observation, bindings: tuple[CertificateBinding, ...],
                            now: datetime) -> list[api.BundleId | api.Certificate | api.Profile]:
        excluded = self._before_ids()
        if self.plan.action == "register_bundle_id":
            return [b for b in observation.bundles if b.resource_id not in excluded
                    and b.identifier == self.plan.target.bundle_id and b.platform in {"IOS", "UNIVERSAL"}
                    and b.seed_id == self.plan.target.app_id_prefix]
        if self.plan.action == "create_certificate":
            api.require(len({b.certificate_id for b in bindings}) == len(bindings), "ambiguous_native_binding")
            result = []
            for certificate in observation.certificates:
                if certificate.resource_id in excluded or certificate.certificate_type != "DISTRIBUTION":
                    continue
                matching = [b for b in bindings if b.certificate_id == certificate.resource_id]
                if not matching:
                    # New cert metadata/format success without native key match
                    # must remain pending, not make quota consumption repeatable.
                    continue
                binding = matching[0]
                if (binding.matches(certificate, self.plan.target, now) and binding.key_ref == self.plan.csr.key_ref
                        and binding.public_key_sha256 == self.plan.csr.public_key_sha256):
                    result.append(certificate)
            return result
        api.require(len({b.certificate_id for b in bindings}) == len(bindings), "ambiguous_native_binding")
        api.require(any(api.resource_sha256(b) == api.resource_sha256(self.plan.bundle) for b in observation.bundles),
                    "bundle_identity_conflict")
        current_certificates = [c for c in observation.certificates if c.resource_id == self.plan.certificate.resource_id]
        current_bindings = [b for b in bindings if b.certificate_id == self.plan.certificate.resource_id]
        api.require(len(current_certificates) == len(current_bindings) == 1
                    and api.resource_sha256(current_certificates[0]) == api.resource_sha256(self.plan.certificate)
                    and current_bindings[0].key_ref == self.plan.binding.key_ref
                    and current_bindings[0].public_key_sha256 == self.plan.binding.public_key_sha256
                    and current_bindings[0].matches(current_certificates[0], self.plan.target, now),
                    "native_certificate_mismatch")
        attributes = api.document(self.plan.request.body)["data"]["attributes"]
        return [p for p in observation.profiles if p.resource_id not in excluded
                and p.name == attributes["name"] and p.bundle_id_resource == self.plan.bundle.resource_id
                and p.certificate_resources == (self.plan.certificate.resource_id,)
                and p.state == "ACTIVE" and p.created_at <= now < p.expires_at]
