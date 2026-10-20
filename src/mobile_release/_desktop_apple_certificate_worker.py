"""Fresh stored-key certificate steps of ONE existing AppleProvisioningRun.

No new provider/process owner. The original retained key verifier, P8, full
native key loan, fixed policy helper, account CAS/ACK and final joins all remain
required. Only a separate certificate-create consent can send one POST. The
returned binding is volatile and never a P12, vault save or assignment.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from . import _desktop_apple_certificate_protocol as wire
from . import _desktop_apple_certificate_control as control
from . import apple_provisioning_api as api
from . import apple_provisioning_signing as signing
from . import apple_provisioning_certificate_issuance as issuance
from .apple_provisioning import CertificateBinding, PublicCSR
from .apple_provisioning_recovery import ProvisioningApproval
from ._desktop_apple_certificate_private import CertificatePolicyWork
from ._desktop_apple_distribution_key import AppleDistributionKeyWork
from .build_inputs import FiniteScratch, finite_scratch
from .owned_process import run_owned


class CertificateSteps:
    def __init__(self, operation):
        from .desktop_apple_provisioning import AppleProvisioningRun
        wire.need(type(operation) is AppleProvisioningRun and operation.source.require_operation() is operation
                  and operation.request.context["mode"] in wire.MODES and operation._certificate is None)
        self.operation = operation
        operation._certificate = self
        self.public_csr = self.key_payload = self.key_ack = self.key_ack_bytes = None
        self.key_saved_ack = self.inventory = self.initial = None
        self.policy = self.policy_result = self.policy_ack = None
        self.identity = self.identity_payload = self.identity_ack = None
        self._exchange = None
        self._key_sent = self._policy_sent = self._pending_sent = False
        self.pending_returned = False
        self._identities = self._identity_bytes = self._updates = self._raw_bytes = 0
        self._round = self._list_index = self._pages = 0
        self._next_page = None
        self._phase = "new"
        self._provider_scratches = 0
        self._policy_scratch = False
        self._post_original = self._post_raw = self._post_response = self._post_retained = None
        self._body_failed = False
        self._platforms = {}
        self._lists = (api.list_bundle_ids(operation.target.bundle_id), api.list_certificates(), api.list_profiles())

    def _bound(self):
        op = self.operation
        wire.need(op._certificate is self and op.source.require_operation() is op and op.request.context["mode"] in wire.MODES)
        return op

    @staticmethod
    def frame_limit():
        return issuance.FRAME_LIMIT

    def bind_scratch(self, scratch):
        op = self._bound()
        maximum = 13 if op.request.context["mode"] == "certificate-create" else 6
        wire.need(type(scratch) is FiniteScratch and scratch.cancellation is op.guard
                  and not scratch.active and not scratch.claimed and not scratch.created
                  and scratch.journal is None and scratch._lane_binding is None and scratch.slot.number is None
                  and op.invocation is not None and 3 <= len(op.scratches) < 5 + maximum)
        if len(op.scratches) == 3:
            wire.need(scratch.layout == "apple-distribution-key" and op._distribution_key is not None
                      and op._next_command == 6 and self._phase == "new")
            op.scratches.append(scratch)
            op._distribution_key.bind_scratch(scratch)
        elif scratch.layout == "online-runner":
            wire.need(op._wire_request is not None and self._provider_scratches < maximum
                      and self._phase in {"inventory", "posted"})
            self._provider_scratches += 1
            op.scratches.append(scratch)
        else:
            wire.need(scratch.layout == "apple-distribution-certificate" and self.policy is not None
                      and not self._policy_scratch and op._wire_request is None
                      and self._phase == "inventory-complete")
            self._policy_scratch = True
            op.scratches.append(scratch)
            self.policy.bind_scratch(scratch)

    def current_key(self, *, require_history=False):
        op = self._bound()
        op.check(op.context)
        wire.need(self.public_csr is not None and self.key_payload is not None and self.key_ack is not None
                  and api.canonical(self.key_ack) == self.key_ack_bytes and op._distribution_key is not None)
        csr, spki = op._distribution_key.verified_public_parts(op)
        wire.need(self.public_csr.key_ref == wire.key_ref(op.request.native["certificate"]["sourceKey"])
                  and csr == self.public_csr.csr_pem and api.digest(spki) == self.public_csr.public_key_sha256
                  and self.key_payload == wire.key_payload(op.request, csr, spki))
        if require_history:
            history = op.request.native["certificate"]["keyPreparation"]
            wire.need(history is not None and wire.common.sha(self.key_saved_ack)
                      and history["csrSha256"] == api.digest(csr) and history["publicKeySha256"] == api.digest(spki))

    def admit_exchange(self, kind, payload):
        op = self._bound()
        wire.need(self._exchange is None)
        if kind == "certificate-key":
            wire.need(not self._key_sent and op.source.reply_step == 0 and op._next_command == 7
                      and self.key_payload is payload and op._distribution_key is not None)
            self._key_sent = True
        elif kind == "certificate-identities":
            self.current_key()
            wire.need(self._identities < 2 and payload["batch"] == self._identities + 1 == self._round
                      and self._phase == "inventory-complete" and self.inventory is not None
                      and self.inventory.observation.available and self.inventory.profile_relationships_complete)
            size = len(api.canonical(payload))
            wire.need(self._identity_bytes + size <= wire.IDENTITIES_LIMIT)
            self._identity_bytes += size
            self._identities += 1
        elif kind == "certificate-policy":
            self.current_key()
            wire.need(not self._policy_sent and self.identity is not None and self.identity["selected"] is not None
                      and self.policy is not None and self.policy.result is not None and self.policy_result is payload)
            self._policy_sent = True
        elif kind == "certificate-pending":
            self.current_key(require_history=True)
            wire.need(not self._pending_sent and self._updates == 0 and self._identities == 1
                      and self.identity is not None and self.identity["selected"] is None and not self.identity["ambiguous"]
                      and self._phase == "inventory-complete" and op.plan is not None and op.plan.action == "create_certificate"
                      and payload["update"]["sequence"] == 1)
            self._pending_sent = True
            self._updates = 1
        elif kind == "certificate-attempt":
            wire.need(self.pending_returned and self._updates in {1, 2} and payload["update"]["sequence"] == self._updates + 1)
            self._updates += 1
        else:
            wire.need(False)
        self._exchange = (kind, api.canonical(payload))

    def accept_exchange(self, kind, payload, result, digest):
        wire.need(self._exchange == (kind, api.canonical(payload)))
        if kind == "certificate-key":
            self.key_ack = result
            self.key_ack_bytes = api.canonical(result)
            self.key_saved_ack = result["keySavedAckSha256"]
        elif kind == "certificate-identities":
            self.identity, self.identity_payload, self.identity_ack = result, payload, digest
        elif kind == "certificate-policy":
            self.policy_ack = digest
        elif kind == "certificate-pending":
            self.pending_returned = True
        self._exchange = None

    def helper_argv(self):
        op = self._bound()
        return ("bundle", "exec", "ruby", str(op.runtime.tooling_root / "fastlane/apple_provisioning_certificate_issuance.rb"))

    def helper_environment(self):
        op = self._bound()
        request = op._wire_request
        wire.need(request is not None)
        issuance.validate_request(request, op.target, csr=self.public_csr)
        selected = op.material.lane_environment(platform="ios")
        wire.need(set(selected) == {"MOBILE_RELEASE_ASC_KEY_ID", "MOBILE_RELEASE_ASC_ISSUER_ID", "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"})
        values = op._base_environment()
        values.update(selected)
        values.update(SPACESHIP_TIMEOUT="30", MOBILE_RELEASE_ASC_BUNDLE_ID=op.target.bundle_id,
            MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT=api.digest(api.canonical(wire.common.core_context_wire(op.context))),
            MOBILE_RELEASE_ASC_CERTIFICATE_STEP=request.kind, MOBILE_RELEASE_ASC_CERTIFICATE_OPERATION_ID=op.request.operation_id)
        if "cursor" in dict(request.query):
            values["MOBILE_RELEASE_ASC_CERTIFICATE_CURSOR"] = dict(request.query)["cursor"]
        if request.method == "POST":
            wire.need(op.source._ack_consumed and self.pending_returned and request == op.plan.request and wire.common.sha(self.key_saved_ack))
            values.update(MOBILE_RELEASE_ASC_CERTIFICATE_PLAN_SHA256=op.plan.sha256,
                MOBILE_RELEASE_ASC_CERTIFICATE_KEY_SAVED_ACK_SHA256=self.key_saved_ack,
                MOBILE_RELEASE_ASC_CERTIFICATE_ACK_SHA256=op.source._pending_ack,
                MOBILE_RELEASE_ASC_CERTIFICATE_CSR_BASE64=base64.b64encode(self.public_csr.csr_pem).decode("ascii"))
        return values

    def _admit_request(self, request):
        op = self._bound()
        self.current_key(require_history=request.method == "POST")
        issuance.validate_request(request, op.target, csr=self.public_csr)
        # Admit the next original only while its entire fixed raw capacity fits
        # the operation's cumulative budget. Never fetch a truncated last page.
        wire.need(self._raw_bytes <= wire.RAW_TOTAL_LIMIT - issuance.RAW_LIMIT)
        if request.method == "POST":
            wire.need(op.request.context["mode"] == "certificate-create" and self._phase == "inventory-complete"
                      and self._round == 1 and self.pending_returned and op.attempt is not None and request == op.plan.request)
            self._phase = "posted" # One entry even if ACK consumption then fails.
            control.consume_pending(op.source, op, request)
            return
        wire.need(self._phase == "inventory" and self._round in {1, 2} and self._list_index < 3
                  and request == (self._next_page or self._lists[self._list_index]) and self._pages < 2)
        self._pages += 1

    def send(self, request):
        op = self._bound()
        self._admit_request(request)
        op._wire_request = request
        try:
            with finite_scratch(layout="online-runner", cancellation=op.guard, parent=op.runtime.private_directory) as runner:
                op._wire_runner = runner
                self.current_key(require_history=request.method == "POST")
                previous = op.guard.lifetime_ledger.verdict().commands
                with op.runtime.command(self.helper_argv(), capture=True):
                    completed = run_owned(self.helper_argv(), cwd=runner._path, environ=self.helper_environment(),
                        capture=True, text=False, timeout=60, output_limit=issuance.FRAME_LIMIT, cancellation=op.guard)
                    verdict = op.guard.lifetime_ledger.verdict()
                    wire.need(verdict.cleanup_complete and verdict.contained and verdict.command_dispatched is not None
                              and verdict.commands == previous + 1 and verdict.profile_calls == 0
                              and completed.returncode == 0 and type(completed.stdout) is bytes and completed.stderr == b"")
                    if request.method == "POST":
                        control.capture_returned_post(self, completed)
                    response = issuance.response_from_frame(completed.stdout,
                        context_sha256=api.digest(api.canonical(wire.common.core_context_wire(op.context))),
                        operation_id=op.request.operation_id, target=op.target, request=request, csr=self.public_csr,
                        key_saved_ack_sha256=self.key_saved_ack if request.method == "POST" else None,
                        ack_sha256=op.source._pending_ack if request.method == "POST" else None, settled=True)
                    if request.method == "POST":
                        op._post_receipt = (op.guard.lifetime_ledger, verdict.commands)
                        if response.status == 201:
                            # The certificate-only Attempt retains its sparse ID
                            # BEFORE a later STOP/source/scratch/chain/read fails.
                            # This is not confirmation or a second POST allowance.
                            op.attempt.retain_returned_response(response)
                            self._post_response, self._post_retained = response, op.attempt.receipt
                    self._raw_bytes += len(response.body)
                    wire.need(self._raw_bytes <= wire.RAW_TOTAL_LIMIT)
                self.current_key(require_history=request.method == "POST")
            self.current_key(require_history=request.method == "POST")
            if request.method == "GET" and response.status == 200:
                page = api.document(response.body)
                if request.kind == "list_certificates":
                    rows = page.get("data")
                    wire.need(type(rows) is list)
                    for row in rows:
                        attributes = row.get("attributes") if type(row) is dict else None
                        wire.need(type(attributes) is dict and attributes.get("platform") in {"IOS", "UNIVERSAL"})
                        identity = api.identifier(row.get("id"))
                        wire.need(identity not in self._platforms and len(self._platforms) < wire.CERTIFICATES)
                        self._platforms[identity] = attributes["platform"]
                link = page.get("links", {}).get("next") if type(page.get("links")) is dict else None
                if link is not None:
                    self._next_page = api._next_request(self._lists[self._list_index], link)
                else:
                    self._list_index += 1
                    self._pages, self._next_page = 0, None
                    if self._list_index == 3:
                        self._phase = "inventory-complete"
            return response
        except BaseException as error:
            op.remember(error)
            raise
        finally:
            op._wire_request = op._wire_runner = None

    def inventory_read(self):
        op = self._bound()
        self.current_key()
        wire.need(self._round < (2 if op.request.context["mode"] == "certificate-create" else 1))
        if self._round:
            wire.need(self._phase == "posted" and op.attempt.receipt is not None and op._last_persisted == op.attempt.record
                      and op.attempt.record.status == "recovery_required" and op.attempt.record.reason == "readback_required")
        else:
            wire.need(self._phase == "new")
        self._round += 1
        self._phase, self._list_index, self._pages, self._next_page, self._platforms = "inventory", 0, 0, None, {}
        self.inventory = signing.observe_signing(op.context, op.target, op, now=datetime.now(timezone.utc))
        self.current_key()
        if self._round == 1:
            self.initial = self.inventory
        if not self.inventory.observation.available or not self.inventory.profile_relationships_complete:
            return ()
        wire.need(self._phase == "inventory-complete")
        payload = wire.candidates_payload(op.request, self.inventory, self._platforms, self._round, self.public_csr.public_key_sha256)
        control.exchange(op.source, "certificate-identities", payload)
        return self.bindings()

    def bindings(self):
        op = self._bound()
        self.current_key()
        wire.need(self.identity is not None and self.identity_payload is not None and self.identity_ack is not None)
        selected = self.identity["selected"]
        if selected is None:
            return ()
        rows = [row for row in self.inventory.observation.certificates if row.resource_id == selected["resourceId"]]
        wire.need(len(rows) == 1 and rows[0].certificate_type == "DISTRIBUTION" and api.digest(rows[0].content) == selected["certificateSha256"]
                  and rows[0].expires_at.timestamp() == selected["notAfter"] and not self.identity["ambiguous"])
        wire.need(self.policy is None) # One leaf-policy command total, not per candidate/batch.
        self.policy_result = CertificatePolicyWork(op, rows[0].content, self.identity_ack).run()
        control.exchange(op.source, "certificate-policy", self.policy_result)
        self.current_key()
        now = datetime.now(timezone.utc)
        checked = wire.common.timestamp(self.policy_result["checkedAt"])
        wire.need(self.policy_ack is not None and 0 <= (now - checked).total_seconds() < 300
                  and 0 <= now.timestamp() - self.identity["checkedAt"] < 300
                  and selected["notBefore"] <= now.timestamp() < selected["notAfter"])
        return (CertificateBinding(rows[0].resource_id, selected["certificateSha256"], self.public_csr.public_key_sha256,
            self.public_csr.key_ref, op.target.team_id, datetime.fromtimestamp(selected["notBefore"], timezone.utc), rows[0].expires_at),)

    def authorize(self, plan, approval):
        op = self._bound()
        wire.need(op.request.context["mode"] == "certificate-create" and op.plan is plan and op.approval is approval
                  and plan.csr is self.public_csr and approval.context == op.context and approval.action == "create_certificate"
                  and approval.plan_sha256 == plan.sha256 and datetime.now(timezone.utc) < plan.valid_until)
        self.current_key(require_history=True)

    def _selection(self, plan):
        wire.need(plan.bundle is not None and plan.action == "create_certificate")
        bundle = plan.bundle
        return {"bundle": {"resourceId": bundle.resource_id, "identifier": bundle.identifier, "platform": bundle.platform, "seedId": bundle.seed_id},
            "beforeSha256": plan.observation_sha256, "planSha256": plan.sha256,
            "csrSha256": api.digest(self.public_csr.csr_pem), "publicKeySha256": self.public_csr.public_key_sha256}

    def persist(self, record):
        op = self._bound()
        wire.need(op.attempt is not None and op.plan is not None and record.context == op.context and record.plan_sha256 == op.plan.sha256)
        update = {"sequence": self._updates + 1, "record": wire.record_wire(record),
            "receipt": api.document(op.attempt.receipt.private_record()) if op.attempt.receipt is not None else None}
        if not self.pending_returned:
            payload = {"observedAt": self.initial.observation.observed_at.isoformat(), "validUntil": op.plan.valid_until.isoformat(),
                "selection": self._selection(op.plan), "requestBodySha256": api.digest(op.plan.request.body), "update": update}
            kind = "certificate-pending"
        else:
            payload, kind = {"update": update}, "certificate-attempt"
        control.exchange(op.source, kind, payload)
        op._last_persisted = record

    def transport_settled(self, record):
        op = self._bound()
        wire.need(op.attempt is not None and record.context == op.context and record.plan_sha256 == op.plan.sha256)
        verdict = op.guard.lifetime_ledger.verdict()
        return (op._post_receipt is not None and op._post_receipt[0] is op.guard.lifetime_ledger
                and op._post_receipt[1] <= verdict.commands <= 21 and verdict.cleanup_complete and verdict.contained
                and verdict.profile_calls == 0 and op._pending is None)

    def reconciliation_current(self, plan, record):
        self.authorize(plan, self.operation.approval)
        return record is self.operation.attempt.record and self.transport_settled(record)

    def result(self, decision, reason, *, identity=None, comparison=None, previous=None):
        op = self._bound()
        value = {"schemaVersion": 1, "scope": "local-ios-distribution-certificate", "mode": op.request.context["mode"],
            "decision": decision, "reason": reason, "certificateId": identity, "attempt": None if previous is None else wire.summary(previous),
            "comparison": comparison, "p12Saved": False, "profileSaved": False, "credentialReady": False, "revocationChecked": False}
        wire.validate_result(value, op.request)
        return value

    def _decision(self, plan):
        if not self.initial.observation.available or not self.initial.profile_relationships_complete:
            return "blocked", "inventory-unavailable"
        if plan.action == "reuse_certificate":
            return "reuse", "existing-certificate"
        if plan.action == "create_certificate":
            return ("request-review", "certificate-required") if self.key_saved_ack is not None else ("blocked", "key-history-unavailable")
        if plan.action == "reconcile":
            return "blocked", "account-pending"
        if plan.reason == "bundle_registration_required" or plan.bundle is None and not self.initial.observation.bundles:
            return "blocked", "bundle-registration-required"
        if plan.action in {"recover_existing_key", "select_existing_certificate", "select_existing_profile"}:
            return "blocked", "existing-certificate-needs-key"
        return "blocked", "inventory-unavailable"

    def _reconcile(self, bindings):
        op = self._bound()
        prior = op.request.native["certificate"]["prior"]
        wire.need(prior["csrSha256"] == api.digest(self.public_csr.csr_pem) and prior["publicKeySha256"] == self.public_csr.public_key_sha256)
        comparison, identity = "inconclusive", None
        if self.inventory.observation.available and self.inventory.profile_relationships_complete:
            if len(bindings) == 1:
                identity = bindings[0].certificate_id
                receipt = wire.receipt(prior["receipt"], prior["record"])
                current = next(row for row in self.inventory.observation.certificates if row.resource_id == identity)
                comparison = "unattributed" if receipt is None else "same-response" if receipt.matches(current) else "different-response"
            elif self.identity is not None and not self.identity["ambiguous"]:
                prior_id = prior["record"]["responseResourceId"]
                if not self.inventory.observation.certificates or prior_id is not None and all(
                        row.resource_id != prior_id for row in self.inventory.observation.certificates):
                    comparison = "not-returned"
        op.report = self.result("comparison-only", "comparison-only", identity=identity, comparison=comparison, previous=prior["record"])

    def run(self):
        op = self._bound()
        op.check(op.context)
        wire.need(op._next_command == 6)
        child = AppleDistributionKeyWork(op).run() # Fixed resource preflight + real fresh PKCS8/CSR/SPKI verifier.
        csr, spki = child.verified_public_parts(op)
        self.public_csr = PublicCSR(wire.key_ref(op.request.native["certificate"]["sourceKey"]), csr, api.digest(spki))
        self.key_payload = wire.key_payload(op.request, csr, spki)
        control.exchange(op.source, "certificate-key", self.key_payload)
        bindings = self.inventory_read()
        if op.request.context["mode"] == "certificate-reconcile":
            self._reconcile(bindings)
            return
        pending = wire.common.pending(op.request.native["pending"], op.context.account_ref)
        op.plan = issuance.prepare_certificate(op.context, op.target, self.initial, bindings=bindings,
            csr=self.public_csr, pending=pending, now=datetime.now(timezone.utc))
        decision, reason = self._decision(op.plan)
        if op.request.context["mode"] == "certificate-review":
            before = self.initial.observation
            payload = {"observedAt": before.observed_at.isoformat(), "validUntil": (before.observed_at + timedelta(seconds=300)).isoformat(),
                "beforeSha256": before.sha256, "decision": decision, "reason": reason,
                "selection": self._selection(op.plan) if decision == "request-review" else None}
            wire.validate_event(op.request, "certificate-observed", payload, op.source.reply_step + 1)
            op.source.engine.provisioning_event("certificate-observed", payload)
            op.report = self.result(decision, reason, identity=op.plan.certificate.resource_id if decision == "reuse" else None)
            return
        if decision != "request-review":
            op.report = self.result(decision, reason, identity=op.plan.certificate.resource_id if decision == "reuse" else None)
            return
        review = op.request.native["certificate"]["review"]
        selected = self._selection(op.plan)
        wire.need(datetime.now(timezone.utc) < wire.common.timestamp(review["validUntil"])
                  and all(selected[name] == review["selection"][name] for name in ("bundle", "csrSha256", "publicKeySha256")))
        op.approval = ProvisioningApproval(op.context, op.plan.sha256, "create_certificate")
        op.attempt = issuance.CertificateCreationAttempt(op.plan, self.initial.observation)
        record = op.attempt.execute(op.approval, self.initial.observation, op, op, now=datetime.now(timezone.utc))
        if (op.source.first_failure is None and record.status == "recovery_required" and record.reason == "readback_required"
                and record.response_resource_id is not None and op._last_persisted == record):
            bindings = self.inventory_read()
            op.attempt.reconcile(self.inventory.observation, op, bindings=bindings, now=datetime.now(timezone.utc))
        record = op.attempt.record
        decision = "request-confirmed" if record.status == "succeeded" else "request-unconfirmed"
        reason = "certificate-confirmed" if decision == "request-confirmed" else "provider-rejected" if (
            record.status == "failed" and record.reason == "provider_rejected_request") else "provider-outcome-unconfirmed"
        op.report = self.result(decision, reason, identity=record.response_resource_id, previous=wire.record_wire(record))
