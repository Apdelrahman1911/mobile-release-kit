"""Fresh GET-only signing setup and one optional local P12 packaging step.

The existing certificate child performs only its fixed verifier/inventory/
identity/policy phases. Its create/authorize/run/POST paths are not invoked.
The existing native parent separately checks current key/P12 loans and mints
its certificate holder after actual producer joins; these are comparison DATA.
"""
from datetime import datetime, timedelta, timezone

from . import _desktop_apple_p12_protocol as wire
from . import _desktop_apple_p12_control as control
from . import _desktop_apple_certificate_protocol as certificate_wire
from . import _desktop_apple_certificate_control as certificate_control
from . import apple_provisioning_api as api
from .apple_provisioning import PublicCSR
from ._desktop_apple_certificate_worker import CertificateSteps
from ._desktop_apple_distribution_key import AppleDistributionKeyWork
from .build_inputs import FiniteScratch


def relevant_previous(previous, spki_sha256, certificate_sha256):
    """Bounded recovery hints only. Unrelated multi-project rows do not block.

    Same-key rows need explicit candidate selection/reassessment even if the
    older certificate differs. No decrypt-all scan, implicit record adoption,
    history deletion or metadata-as-key-proof is performed here.
    """
    wire.need(type(previous) is list and len(previous) <= 32 and wire.common.sha(spki_sha256)
              and wire.common.sha(certificate_sha256))
    return any(row["publicKeySha256"] == spki_sha256 or row["certificateSha256"] == certificate_sha256
               for row in previous)


class P12Steps:
    def __init__(self, operation):
        from .desktop_apple_provisioning import AppleProvisioningRun
        wire.need(type(operation) is AppleProvisioningRun and operation.source.require_operation() is operation
                  and operation.request.context["mode"] in wire.MODES and operation._p12_steps is None
                  and operation._certificate is None)
        self.operation = operation
        self.certificate = self.selected = self.pending_payload = self.pending_ack = None
        self._exchange = None
        self.pending_returned = self.output_returned = self._ran = self._extra_scratch = False
        operation._p12_steps = self  # Retain before its existing child binds.
        self.certificate = CertificateSteps(operation)

    def _bound(self):
        op = self.operation
        wire.need(op._p12_steps is self and op._certificate is self.certificate
                  and op.source.require_operation() is op and op.request.context["mode"] in wire.MODES
                  and op.plan is None and op.attempt is None and op.approval is None)
        return op

    def bind_scratch(self, scratch):
        op = self._bound()
        if scratch.layout not in {"apple-p12-assembly", "apple-provisioning-p12"}:
            self.certificate.bind_scratch(scratch)
            return
        wire.need(type(scratch) is FiniteScratch and not self._extra_scratch and self.selected is not None
                  and self.certificate.policy_ack is not None and scratch.cancellation is op.guard
                  and not scratch.active and not scratch.claimed and not scratch.created
                  and scratch.journal is None and scratch._lane_binding is None and scratch.slot.number is None
                  and 5 <= len(op.scratches) <= 11)
        child = op._p12_assembly if scratch.layout == "apple-p12-assembly" else op._p12_extraction
        wire.need(child is not None and (scratch.layout != "apple-p12-assembly" or op.request.context["mode"] == "p12-save"))
        self._extra_scratch = True
        op.scratches.append(scratch)
        child.bind_scratch(scratch)

    def current_selection(self):
        op = self._bound()
        self.certificate.current_key()
        certificate = self.certificate
        wire.need(self.selected is not None and certificate.identity is not None and not certificate.identity["ambiguous"]
                  and certificate.identity["selected"] is not None and certificate.policy_ack is not None
                  and certificate.policy_result is not None and certificate.policy is not None)
        now = datetime.now(timezone.utc)
        choice = self.selected
        wire.need(choice["certificate"]["certificateSha256"] == api.digest(certificate.policy.leaf)
                  and choice["certificate"]["publicKeySha256"] == certificate.public_csr.public_key_sha256
                  and choice["csrSha256"] == api.digest(certificate.public_csr.csr_pem)
                  and 0 <= (now - certificate.initial.observation.observed_at).total_seconds() < 300
                  and 0 <= (now - wire.common.timestamp(certificate.policy_result["checkedAt"])).total_seconds() < 300
                  and wire.common.timestamp(choice["certificate"]["notBefore"]) <= now
                  < wire.common.timestamp(choice["certificate"]["expiresAt"]))
        return choice

    def extra_child(self):
        """The one fixed local command, after this original policy ACK.

        There is no caller-selected argv or callback. The ordinary parent
        command admission still owns cwd/env/capture/limits and actual C/A/W.
        """
        op = self._bound()
        self.current_selection()
        wire.need(self._extra_scratch and op._wire_request is None)
        if op.request.context["mode"] == "p12-save":
            from ._desktop_apple_p12_assembly import P12AssemblyWork
            child = op._p12_assembly
            wire.need(type(child) is P12AssemblyWork and self.pending_returned
                      and child._operation is op and child._started)
        else:
            from ._desktop_apple_provisioning_p12 import P12Extraction
            child = op._p12_extraction
            wire.need(type(child) is P12Extraction and op._p12_reuse is not None
                      and child._operation is op and child._started)
        return child

    def assembly_inputs(self, operation):
        wire.need(operation is self.operation and operation.request.context["mode"] == "p12-save")
        choice = self.current_selection()["certificate"]
        return self.certificate.policy.leaf, choice["certificateSha256"], choice["publicKeySha256"]

    def admit_exchange(self, kind, payload):
        op = self._bound()
        self.current_selection()
        wire.need(self._exchange is None and op.request.context["mode"] == "p12-save")
        if kind == "p12-pending":
            wire.need(not self.pending_returned and self.pending_payload is payload and self.pending_ack is None
                      and op._p12_assembly is None and op._p12_output is not None and op.source.reply_step == 3)
        else:
            wire.need(kind == "p12-output" and self.pending_returned and not self.output_returned
                      and op._p12_output is not None and op.source.reply_step == 4
                      and op._p12_output.metadata() == payload)
        self._exchange = kind, api.canonical(payload)

    def accept_exchange(self, kind, payload, result, digest):
        wire.need(self._exchange == (kind, api.canonical(payload)))
        if kind == "p12-pending":
            self.pending_ack = digest
            self.pending_returned = True
        else:
            wire.need(kind == "p12-output")
            self.operation._p12_output.accept_custody(result, digest)
            self.output_returned = True
        self._exchange = None

    def _choice(self, bindings):
        op = self._bound()
        inventory = self.certificate.initial
        if not inventory.observation.available or not inventory.profile_relationships_complete:
            return None, "inventory-unavailable"
        if any(row.unresolved for row in wire.common.effective_pending(op.request.native, op.context.account_ref)):
            return None, "account-pending"
        bundles = [row for row in inventory.observation.bundles
                   if row.identifier == op.target.bundle_id and row.seed_id == op.target.app_id_prefix
                   and row.platform in {"IOS", "UNIVERSAL"}]
        if len(bindings) != 1 or len(bundles) != 1:
            return None, "certificate-required"
        bound, bundle = bindings[0], bundles[0]
        certificate = next((row for row in inventory.observation.certificates if row.resource_id == bound.certificate_id), None)
        wire.need(certificate is not None and certificate.certificate_type == "DISTRIBUTION")
        choice = {"bundle": {"resourceId": bundle.resource_id, "identifier": bundle.identifier,
                   "platform": bundle.platform, "seedId": bundle.seed_id},
            "certificate": {"resourceId": certificate.resource_id, "certificateType": "DISTRIBUTION",
                "notBefore": bound.not_before.isoformat(), "expiresAt": bound.not_after.isoformat(),
                "certificateSha256": bound.certificate_sha256, "publicKeySha256": bound.public_key_sha256},
            "csrSha256": api.digest(self.certificate.public_csr.csr_pem), "beforeSha256": inventory.observation.sha256}
        wire.selection(choice, op.request.native["target"])
        return choice, None

    def _result(self, decision, reason, *, output=None, reused=None):
        op = self._bound()
        selected = self.selected["certificate"] if decision != "blocked" else None
        value = {"schemaVersion": 1, "scope": "local-ios-p12-setup", "mode": op.request.context["mode"],
            "decision": decision, "reason": reason,
            "certificateId": None if selected is None else selected["resourceId"],
            "certificateSha256": None if selected is None else selected["certificateSha256"],
            "publicKeySha256": None if selected is None else selected["publicKeySha256"],
            "output": output, "reused": reused, "p12Saved": False, "profileSaved": False,
            "credentialReady": False, "revocationChecked": False}
        return wire.validate_result(value, op.request)

    def run(self):
        op = self._bound()
        wire.need(not self._ran and op._next_command == 6)
        self._ran = True
        child = AppleDistributionKeyWork(op).run()
        csr, spki = child.verified_public_parts(op)
        phase = self.certificate
        phase.public_csr = PublicCSR(wire.key_ref(op.request.native["p12"]["sourceKey"]), csr, api.digest(spki))
        phase.key_payload = certificate_wire.key_payload(op.request, csr, spki)
        certificate_control.exchange(op.source, "certificate-key", phase.key_payload)
        bindings = phase.inventory_read()  # Fixed complete GET-only list scope; no create/authorize/run.
        self.selected, reason = self._choice(bindings)
        mode, selected_p12 = op.request.context["mode"], op.request.native["p12"]["selectedP12"]
        reused = None
        if reason is None:
            self.current_selection()
            if mode != "p12-review":
                review = op.request.native["p12"]["review"]
                if (datetime.now(timezone.utc) >= wire.common.timestamp(review["validUntil"])
                        or not wire.same_assets(self.selected, review["selection"])):
                    reason = "selection-changed"
            if reason is None and selected_p12 is not None:
                from ._desktop_apple_p12_reuse import P12ReuseWork
                reused = P12ReuseWork(op).run().comparison(op)
            elif reason is None and relevant_previous(op.request.native["p12"]["previous"],
                    self.selected["certificate"]["publicKeySha256"], self.selected["certificate"]["certificateSha256"]):
                reason = "select-existing-package"
        if mode == "p12-review":
            decision = "blocked" if reason else "reuse-review" if reused is not None else "assemble-review"
            reason = reason or ("current-package-review" if reused is not None else "new-package-review")
            observed = phase.initial.observation.observed_at
            payload = {"observedAt": observed.isoformat(), "validUntil": (observed + timedelta(seconds=300)).isoformat(),
                "decision": decision, "reason": reason, "selection": None if decision == "blocked" else self.selected}
            wire.validate_event(op.request, "p12-observed", payload, op.source.reply_step + 1)
            op.source.engine.provisioning_event("p12-observed", payload)
            op.report = self._result(decision, reason, reused=reused if decision != "blocked" else None)
        elif reason is not None:
            op.report = self._result("blocked", reason)
        elif mode == "p12-reuse":
            wire.need(reused is not None)
            op.report = self._result("reused", "existing-package", reused=reused)
        else:
            from ._desktop_apple_p12_private import P12Output
            from ._desktop_apple_p12_assembly import P12AssemblyWork
            output = P12Output(op)  # Before Pending/assembler/output acquisition.
            observed = phase.initial.observation.observed_at
            self.pending_payload = {"observedAt": observed.isoformat(), "validUntil": (observed + timedelta(seconds=300)).isoformat(),
                                    "selection": self.current_selection(), "update": wire.initial_update()}
            control.exchange(op.source, "p12-pending", self.pending_payload)
            assembled = P12AssemblyWork(op).run()
            output.retain_returned(assembled)
            metadata = output.metadata()
            control.exchange(op.source, "p12-output", metadata)
            op.report = self._result("assembled", "producer-returned", output=metadata)
