"""Fixed existing-P12 profile steps of ONE AppleProvisioningRun.

This is not a second process/credential/provider owner. It borrows the original
Store runtime, private material, command admissions, duplex ACKs and deadlines.
The native Session alone owns account CAS, reserved NEW save and final joins.
"""
from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from . import _desktop_apple_profile_protocol as wire
from . import apple_provisioning_api as api
from . import apple_provisioning_signing as signing
from .apple_provisioning import CertificateBinding, authenticate_downloaded_profile
from .apple_provisioning_chain import _verify_leaf_chain_in_worker
from .apple_provisioning_recovery import ProvisioningApproval
from ._desktop_apple_profile_private import ProfileOutput
from ._desktop_apple_provisioning_p12 import P12Extraction, _expected
from .build_inputs import finite_scratch
from .desktop_store_preflight import _Refused
from .inspection import InspectionDeadline
from .owned_process import run_owned


class ProfileSteps:
    def __init__(self, operation):
        from .desktop_apple_provisioning import AppleProvisioningRun
        wire.need(type(operation) is AppleProvisioningRun and operation.source.require_operation() is operation
                  and operation.request.context["mode"] in wire.MODES and operation._profile is None)
        self.operation = operation
        operation._profile = self  # Retain before original deadline/output admission.
        self.deadline = InspectionDeadline()
        self.deadline._expires_at = min(self.deadline.expires_at, operation.source.work_end)
        self.identity = self.identity_bytes = self.leaf = self.spki = self.chain = None
        self.inventory = self.selection = self.download = None
        self._provider_phase = "new"
        self._list_index = 0
        self._pages = 0
        self._next_page = None
        self._lists = (api.list_bundle_ids(operation.target.bundle_id), api.list_certificates(), api.list_profiles())
        ProfileOutput(operation)

    def _bound(self):
        op = self.operation
        wire.need(op._profile is self and op.source.require_operation() is op and op.request.context["mode"] in wire.MODES)
        return op

    def current_material(self):
        op = self._bound()
        selected = op.request.native["signing"]
        parts = op.source.profile_material(op)
        wire.need(api.digest(parts[3]) == selected["p12Sha256"]
                  and _expected(op.config.section("ios").get("distributionCertificateSha256")) == selected["expectedCertificateSha256"])

    def identity_current(self, *, audit=False):
        op = self._bound()
        wire.need(self.identity is not None and self.identity is op.source._profile_identity
                  and api.canonical(self.identity) == self.identity_bytes
                  and self.identity["certificateSha256"] == op.request.native["signing"]["expectedCertificateSha256"]
                  and self.identity["certificateSha256"] == api.digest(self.leaf)
                  and self.identity["publicKeySha256"] == api.digest(self.spki))
        if audit:
            # An armed audit may preserve failure/uncertainty, never authorize
            # another provider call or refresh a stale private loan.
            op.source.audit_point()
            return
        op.check(op.context)
        self.deadline.check()
        op._p12_extraction.current(op)
        now = datetime.now(timezone.utc).timestamp()
        wire.need(self.identity["notBefore"] <= now < self.identity["notAfter"]
                  and 0 <= now - self.identity["checkedAt"] < 300)

    def _identity(self):
        op = self._bound()
        wire.need(self.identity is None and op.source.reply_step == 0 and op._next_command == 6)
        self.current_material()
        extraction = P12Extraction(op).run()
        self.leaf, self.spki, self.chain = extraction.certificate_inputs(op)
        self.deadline.check()
        at = _verify_leaf_chain_in_worker(self.leaf, self.chain, cancellation=op.guard, deadline=self.deadline)
        self.deadline.check()
        payload = wire.identity_payload(op.request, self.leaf, self.spki, self.chain, at)
        self.identity = op.source.exchange("identity", payload)
        self.identity_bytes = api.canonical(self.identity)
        wire.need(0 <= self.identity["checkedAt"] - int(at.timestamp()) < 300)
        self.identity_current()

    def bindings(self):
        op = self._bound()
        self.identity_current()
        wire.need(type(self.inventory) is signing.SigningInventory)
        not_before = datetime.fromtimestamp(self.identity["notBefore"], timezone.utc)
        not_after = datetime.fromtimestamp(self.identity["notAfter"], timezone.utc)
        source = wire.key_ref(op.request.native["signing"]["sourceKey"])
        result = []
        for certificate in self.inventory.observation.certificates:
            # The native syntax candidate alone is NOT the producer. Here the
            # SAME original P12/key match and pinned offline chain have returned,
            # and fresh ASC identifies these EXACT bytes as Distribution.
            if certificate.content == self.leaf and certificate.expires_at == not_after:
                wire.need(certificate.certificate_type in api.CERTIFICATE_TYPES)
                result.append(CertificateBinding(certificate.resource_id, api.digest(self.leaf), api.digest(self.spki),
                    source, op.target.team_id, not_before, not_after))
        return tuple(result)

    def helper_argv(self):
        op = self._bound()
        return ("bundle", "exec", "ruby", str(op.runtime.tooling_root / "fastlane/apple_provisioning_signing.rb"))

    def helper_environment(self):
        op = self._bound()
        request = op._wire_request
        wire.need(request is not None)
        signing.validate_request(request, op.target, op.request.operation_id)
        values = op.material.lane_environment(platform="ios")
        wire.need(set(values) == {"MOBILE_RELEASE_ASC_KEY_ID", "MOBILE_RELEASE_ASC_ISSUER_ID", "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"})
        result = op._base_environment()
        result.update(values)
        result.update(SPACESHIP_TIMEOUT="30", MOBILE_RELEASE_ASC_BUNDLE_ID=op.target.bundle_id,
            MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT=api.digest(api.canonical(wire.common.core_context_wire(op.context))),
            MOBILE_RELEASE_ASC_SIGNING_STEP=request.kind, MOBILE_RELEASE_ASC_SIGNING_OPERATION_ID=op.request.operation_id)
        if "cursor" in dict(request.query):
            result["MOBILE_RELEASE_ASC_SIGNING_CURSOR"] = dict(request.query)["cursor"]
        if request.method == "POST":
            wire.need(op.source._ack_consumed and self.selection is not None and request == op.plan.request)
            result.update(MOBILE_RELEASE_ASC_SIGNING_PLAN_SHA256=op.plan.sha256,
                MOBILE_RELEASE_ASC_SIGNING_ACK_SHA256=op.source._pending_ack,
                MOBILE_RELEASE_ASC_SIGNING_BUNDLE_RESOURCE_ID=op.plan.bundle.resource_id,
                MOBILE_RELEASE_ASC_SIGNING_CERTIFICATE_RESOURCE_ID=op.plan.certificate.resource_id)
        elif request.kind == "download_profile":
            result["MOBILE_RELEASE_ASC_SIGNING_PROFILE_RESOURCE_ID"] = request.path.rsplit("/", 1)[1]
        return result

    def _admit_request(self, request):
        op = self._bound()
        self.identity_current()
        signing.validate_request(request, op.target, op.request.operation_id)
        if self._provider_phase == "new":
            wire.need(op._next_command == 7 and self._list_index == 0)
            self._provider_phase = "inventory"
        if self._provider_phase == "inventory":
            wire.need(self._list_index < 3 and request == (self._next_page or self._lists[self._list_index])
                      and self._pages < 2 and op.source.reply_step == 1)
            self._pages += 1
            return
        wire.need(self._provider_phase == "selected" and self.inventory is not None)
        if request.method == "POST":
            wire.need(op.request.context["mode"] == "profile-create" and request == op.plan.request
                      and op.source.reply_step == 2 and op.attempt is not None)
            self._provider_phase = "posted"  # Before ACK consumption or scratch.
            op.source.consume_pending_ack(op, request)
        else:
            wire.need(request.kind == "download_profile" and op.request.context["mode"] in {"profile-reuse", "profile-reconcile"}
                      and op.plan is not None and request == op.plan.request
                      and (op.source.reply_step == 2 if op.request.context["mode"] == "profile-reuse" else op.source.reply_step == 1))
            self._provider_phase = "downloaded"

    def send(self, request):
        op = self._bound()
        # Only a successful returned sparse201 can advance to its ONE exact GET.
        if self._provider_phase == "posted":
            self.identity_current()
            wire.need(op.request.context["mode"] == "profile-create" and op.source.reply_step == 3
                      and type(op.attempt) is signing.ProfileCreationAttempt and op.attempt.receipt is not None
                      and op.attempt.record.status == "recovery_required" and op.attempt.record.reason == "readback_required"
                      and op._last_persisted == op.attempt.record and request == api.download_profile(op.attempt.receipt.resource_id))
            self._provider_phase = "downloaded"
        else:
            self._admit_request(request)
        op._wire_request = request
        try:
            with finite_scratch(layout="online-runner", cancellation=op.guard, parent=op.runtime.private_directory) as runner:
                op._wire_runner = runner
                self.identity_current()
                previous = op.guard.lifetime_ledger.verdict().commands
                with op.runtime.command(self.helper_argv(), capture=True):
                    result = run_owned(self.helper_argv(), cwd=runner._path, environ=self.helper_environment(), capture=True,
                        text=False, timeout=60, output_limit=signing.FRAME_LIMIT, cancellation=op.guard)
                self.identity_current()
                verdict = op.guard.lifetime_ledger.verdict()
                wire.need(verdict.cleanup_complete and verdict.contained and verdict.command_dispatched is not None
                          and verdict.commands == previous + 1 and verdict.profile_calls == 0
                          and result.returncode == 0 and type(result.stdout) is bytes and result.stderr == b"")
                response = signing.response_from_frame(result.stdout,
                    context_sha256=api.digest(api.canonical(wire.common.core_context_wire(op.context))),
                    operation_id=op.request.operation_id, target=op.target, request=request,
                    ack_sha256=op.source._pending_ack if request.method == "POST" else None, settled=True)
            self.identity_current()
            if request.method == "POST":
                op._post_receipt = (op.guard.lifetime_ledger, verdict.commands)
            if self._provider_phase == "inventory" and response.status == 200:
                payload = api.document(response.body)
                next_link = payload.get("links", {}).get("next") if type(payload.get("links")) is dict else None
                if next_link is not None:
                    self._next_page = api._next_request(self._lists[self._list_index], next_link)
                else:
                    self._list_index += 1
                    self._pages = 0
                    self._next_page = None
                    if self._list_index == 3:
                        self._provider_phase = "selected"
            return response
        except BaseException as error:
            op.remember(error)
            raise
        finally:
            op._wire_request = op._wire_runner = None

    def authorize(self, plan, approval):
        op = self._bound()
        wire.need(op.request.context["mode"] == "profile-create" and op.plan is plan and op.approval is approval
                  and approval.context == op.context and approval.plan_sha256 == plan.sha256 and approval.action == "create_profile")
        self.identity_current()
        wire.need(datetime.now(timezone.utc) < plan.valid_until)

    def _update(self, provider, *, download=None):
        op = self._bound()
        return {"sequence": op.source.reply_step, "provider": provider, "download": download,
                "save": "not-entered", "savedReference": None, "cancelRequested": op.source.stop_reason == "cancelled"}

    def _persist_update(self, update):
        op = self._bound()
        if op.source.reply_step == 1:
            payload = {"observedAt": self.inventory.observation.observed_at.isoformat(), "validUntil": op.plan.valid_until.isoformat(),
                       "beforeSha256": op.plan.observation_sha256, "selection": self.selection, "update": update}
            kind = "profile-pending"
        else:
            payload, kind = {"update": update}, "profile-attempt"
        op.source.exchange(kind, payload)

    def persist(self, record):
        op = self._bound()
        wire.need(op.attempt is not None and record.context == op.context and record.plan_sha256 == op.plan.sha256)
        download = self.download if record.status in {"succeeded", "cancelled"} and record.reason in {
            "provider_resource_confirmed", "cancelled_after_settlement"} else None
        update = self._update({"kind": "creation", "record": wire.record_wire(record)}, download=download)
        update["cancelRequested"] |= record.cancel_requested
        self._persist_update(update)
        op._last_persisted = record

    def transport_settled(self, record):
        op = self._bound()
        wire.need(op.attempt is not None and record.context == op.context and record.plan_sha256 == op.plan.sha256)
        verdict = op.guard.lifetime_ledger.verdict()
        return (op._post_receipt is not None and op._post_receipt[0] is op.guard.lifetime_ledger
                and op._post_receipt[1] <= verdict.commands <= 15 and verdict.cleanup_complete and verdict.contained
                and verdict.profile_calls <= 1 and op._pending is None)

    def reconciliation_current(self, plan, record):
        op = self._bound()
        wire.need(op.plan is plan and op._last_persisted == record)
        self.identity_current()
        return True

    def _result(self, decision, reason, profile=None):
        op = self._bound()
        value = {"schemaVersion": 1, "scope": "local-ios-profile-setup", "mode": op.request.context["mode"],
            "decision": decision, "reason": reason, "bundleId": op.target.bundle_id,
            "profileResourceId": None if profile is None else profile.resource_id,
            "profileUUID": None if profile is None else profile.uuid,
            "saved": False, "credentialReady": False, "cancellationRequested": op.source.stop_reason == "cancelled",
            "limitations": list(wire.LIMITATIONS)}
        wire.validate_result(value, op.request)
        op.report = value

    def _observed(self, decision, reason, selected):
        op = self._bound()
        before = self.inventory.observation
        op.source.engine.provisioning_event("profile-observed", {"observedAt": before.observed_at.isoformat(),
            "validUntil": (before.observed_at + timedelta(seconds=300)).isoformat(), "beforeSha256": before.sha256,
            "available": before.available, "relationshipsComplete": self.inventory.profile_relationships_complete,
            "decision": decision, "reason": reason, "selection": selected})

    @staticmethod
    def _blocked_reason(plan, inventory):
        if not inventory.observation.available:
            return "inventory-unavailable"
        return {"earlier_account_operation_unresolved": "pending-setup", "profile_relationship_evidence_incomplete": "inventory-incomplete",
            "multiple_compatible_profiles": "profile-selection-required", "capability_setup_required": "capabilities-manual",
            "bundle_registration_required": "bundle-required", "existing_application_identity_missing": "bundle-required",
            "existing_distribution_identity_required": "identity-required", "existing_certificate_key_unavailable": "identity-required",
            "multiple_owned_certificates": "identity-required"}.get(plan.reason, "selection-changed")

    def _authenticated(self, plan, response):
        op = self._bound()
        self.identity_current()
        result = authenticate_downloaded_profile(plan, response, cancellation=op.guard,
            now=datetime.now(timezone.utc), deadline=self.deadline)
        self.identity_current()
        return result

    def run(self):
        op = self._bound()
        self._identity()
        self.inventory = signing.observe_signing(op.context, op.target, op, now=datetime.now(timezone.utc))
        self.identity_current()
        mode = op.request.context["mode"]
        pending = wire.common.pending(op.request.native["pending"], op.context.account_ref)
        selected_profile = None
        if mode in wire.SAVE_MODES:
            reviewed = op.request.native["signing"]["review"]
            wire.need(datetime.now(timezone.utc) < wire.common.timestamp(reviewed["validUntil"]))
            if reviewed["selection"]["profile"] is not None:
                selected_profile = reviewed["selection"]["profile"]["resourceId"]
        elif mode == "profile-reconcile":
            return self._reconcile()
        op.plan = signing.prepare_existing_profile(op.context, op.target, self.inventory, bindings=self.bindings(),
            selected_key=wire.key_ref(op.request.native["signing"]["sourceKey"]), pending=pending,
            now=datetime.now(timezone.utc), selected_profile=selected_profile)
        if op.plan.action not in {"download_profile", "create_profile"}:
            reason = self._blocked_reason(op.plan, self.inventory)
            if mode == "profile-review":
                self._observed("blocked", reason, None)
            self._result("blocked", reason)
            return
        self.selection = wire.selection_wire(op.plan)
        if mode == "profile-review":
            decision, reason = (("reuse-available", "reuse-existing-profile") if op.plan.action == "download_profile"
                                else ("create-available", "profile-create-review"))
            self._observed(decision, reason, self.selection)
            self._result(decision, reason, op.plan.profile)
            return
        if not wire.same_choice(self.selection, op.request.native["signing"]["review"]["selection"]):
            self._result("blocked", "selection-changed")
            return
        if mode == "profile-reuse":
            wire.need(op.plan.action == "download_profile")
            self._persist_update(self._update({"kind": "download-pending"}))
            try:
                response = op.send(op.plan.request)
                signing.validate_reused_download(op.plan, response, now=datetime.now(timezone.utc))
                authenticated = self._authenticated(op.plan, response)
                op._profile_output.retain_authenticated(op.plan, authenticated)
                self.download = {"profile": wire.profile_wire(authenticated.profile), **op._profile_output.download_metadata()}
                self._persist_update(self._update({"kind": "download-returned"}, download=self.download))
            except BaseException:
                # The durable reservation already fences the account. No GET,
                # ACK or local save is retried to turn failure into success.
                raise
            self._result("download-returned", "profile-returned", authenticated.profile)
            return
        wire.need(mode == "profile-create" and op.plan.action == "create_profile")
        op.approval = ProvisioningApproval(op.context, op.plan.sha256, "create_profile")
        op.attempt = signing.ProfileCreationAttempt(op.plan, self.inventory)
        record = op.attempt.execute(op.approval, self.inventory.observation, op, op, now=datetime.now(timezone.utc))
        if (op.source.first_failure is None and record.status == "recovery_required" and record.reason == "readback_required"
                and record.response_resource_id is not None and op._last_persisted == record):
            response = op.send(api.download_profile(record.response_resource_id))
            plan = signing.created_download_plan(op.attempt, response, now=datetime.now(timezone.utc))
            authenticated = self._authenticated(plan, response)
            op._profile_output.retain_authenticated(plan, authenticated)
            self.download = {"profile": wire.profile_wire(authenticated.profile), **op._profile_output.download_metadata()}
            # Original complete inventory plus this exact retained-response GET
            # is enough to compare that ONE returned ID. It is not published as
            # a fresh complete inventory or used to authorize any further write.
            readback = replace(self.inventory.observation,
                profiles=self.inventory.observation.profiles + (authenticated.profile,))
            op.attempt.reconcile(readback, op, bindings=self.bindings(), now=datetime.now(timezone.utc))
            if op.attempt.record.status == "succeeded":
                self._result("download-returned", "profile-returned", authenticated.profile)
                return
        self._result("creation-unconfirmed", "provider-unconfirmed")

    def _reconcile(self):
        op = self._bound()
        before, prior = self.inventory.observation, op.request.native["signing"]["prior"]
        reason, profile = ("inconclusive" if not before.available else "not-returned"), None
        if before.available:
            candidates = [p for p in before.profiles if (p.resource_id == prior["profileResourceId"]
                if prior["profileResourceId"] is not None else p.name == prior["profileName"])]
            if len(candidates) == 1:
                candidate = candidates[0]
                plan = signing.prepare_existing_profile(op.context, op.target, self.inventory, bindings=self.bindings(),
                    selected_key=wire.key_ref(op.request.native["signing"]["sourceKey"]), pending=(),
                    now=datetime.now(timezone.utc), selected_profile=candidate.resource_id)
                if plan.action == "download_profile":
                    op.plan = plan
                    response = op.send(plan.request)
                    signing.validate_reused_download(plan, response, now=datetime.now(timezone.utc))
                    authenticated = self._authenticated(plan, response)
                    profile = authenticated.profile
                    reason = "same-response" if prior["profileResourceId"] is not None else "unattributed"
                    if prior["profileSha256"] is not None and api.digest(profile.content) != prior["profileSha256"]:
                        reason, profile = "inconclusive", None
            elif candidates:
                reason = "inconclusive"
        self._observed("comparison-only", reason, None)
        self._result("comparison-only", reason, profile)
