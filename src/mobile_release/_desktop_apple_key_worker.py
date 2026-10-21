"""Reuse-first key review/local preparation on ONE AppleProvisioningRun.

Read consent uses the existing bounded signing inventory and raw SDK adapter.
Local preparation is a separate one-use consent: it does no Apple POST and
starts its fixed generator only after the original durable Pending ACK.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from . import _desktop_apple_key_protocol as wire
from . import _desktop_apple_key_control as control
from . import apple_provisioning_api as api
from . import apple_provisioning_signing as signing
from .apple_provisioning import prepare
from ._desktop_apple_key_private import KeyOutput
from ._desktop_apple_distribution_key import AppleDistributionKeyWork
from .build_inputs import finite_scratch
from .desktop_store_preflight import _Refused
from .owned_process import run_owned


class KeySteps:
    def __init__(self, operation):
        from .desktop_apple_provisioning import AppleProvisioningRun
        wire.need(type(operation) is AppleProvisioningRun and operation.source.require_operation() is operation
                  and operation.request.context["mode"] in wire.LOCAL_MODES and operation._key_steps is None)
        self.operation = operation
        self.inventory = None
        self._list_index = self._pages = 0
        self._next_page = None
        self._lists = (api.list_bundle_ids(operation.target.bundle_id), api.list_certificates(), api.list_profiles())
        operation._key_steps = self
        if operation.request.context["mode"] == "key-prepare":
            KeyOutput(operation)

    def _bound(self):
        operation = self.operation
        wire.need(operation._key_steps is self and operation.source.require_operation() is operation
                  and operation.request.context["mode"] in wire.LOCAL_MODES)
        return operation

    def frame_limit(self):
        operation = self._bound()
        wire.need(operation.request.context["mode"] == "key-review")
        return signing.FRAME_LIMIT

    def helper_argv(self):
        operation = self._bound()
        wire.need(operation.request.context["mode"] == "key-review")
        return ("bundle", "exec", "ruby", str(operation.runtime.tooling_root / "fastlane/apple_provisioning_signing.rb"))

    def helper_environment(self):
        operation = self._bound()
        request = operation._wire_request
        wire.need(operation.request.context["mode"] == "key-review" and request is not None
                  and request.method == "GET" and request.kind in {row.kind for row in self._lists})
        signing.validate_request(request, operation.target, operation.request.operation_id)
        values = operation.material.lane_environment(platform="ios")
        wire.need(set(values) == {"MOBILE_RELEASE_ASC_KEY_ID", "MOBILE_RELEASE_ASC_ISSUER_ID", "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"})
        result = operation._base_environment()
        result.update(values)
        result.update(SPACESHIP_TIMEOUT="30", MOBILE_RELEASE_ASC_BUNDLE_ID=operation.target.bundle_id,
            MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT=api.digest(api.canonical(wire.common.core_context_wire(operation.context))),
            MOBILE_RELEASE_ASC_SIGNING_STEP=request.kind, MOBILE_RELEASE_ASC_SIGNING_OPERATION_ID=operation.request.operation_id)
        if "cursor" in dict(request.query):
            result["MOBILE_RELEASE_ASC_SIGNING_CURSOR"] = dict(request.query)["cursor"]
        return result

    def send(self, request):
        operation = self._bound()
        operation.check(operation.context)
        wire.need(operation.request.context["mode"] == "key-review" and request.method == "GET"
                  and self._list_index < 3 and request == (self._next_page or self._lists[self._list_index])
                  and self._pages < 2 and operation.source.reply_step == 0 and 6 <= operation._next_command < 12)
        signing.validate_request(request, operation.target, operation.request.operation_id)
        self._pages += 1  # Before the same command/scratch can have any effect.
        operation._wire_request = request
        try:
            with finite_scratch(layout="online-runner", cancellation=operation.guard,
                                parent=operation.runtime.private_directory) as runner:
                operation._wire_runner = runner
                operation.check(operation.context)
                previous = operation.guard.lifetime_ledger.verdict().commands
                with operation.runtime.command(self.helper_argv(), capture=True):
                    result = run_owned(self.helper_argv(), cwd=runner._path, environ=self.helper_environment(), capture=True,
                        text=False, timeout=60, output_limit=signing.FRAME_LIMIT, cancellation=operation.guard)
                operation.check(operation.context)
                verdict = operation.guard.lifetime_ledger.verdict()
                wire.need(verdict.cleanup_complete and verdict.contained and verdict.command_dispatched is not None
                          and verdict.commands == previous + 1 and verdict.profile_calls == 0
                          and result.returncode == 0 and type(result.stdout) is bytes and result.stderr == b"")
                response = signing.response_from_frame(result.stdout,
                    context_sha256=api.digest(api.canonical(wire.common.core_context_wire(operation.context))),
                    operation_id=operation.request.operation_id, target=operation.target,
                    request=request, ack_sha256=None, settled=True)
            operation.check(operation.context)
            if response.status == 200:
                payload = api.document(response.body)
                link = payload.get("links", {}).get("next") if type(payload.get("links")) is dict else None
                if link is not None:
                    self._next_page = api._next_request(self._lists[self._list_index], link)
                else:
                    self._list_index += 1
                    self._pages = 0
                    self._next_page = None
            return response
        except BaseException as error:
            operation.remember(error)
            raise
        finally:
            operation._wire_request = operation._wire_runner = None

    def _result(self, decision, reason):
        operation = self._bound()
        value = {"schemaVersion": 1, "scope": "local-ios-distribution-key", "mode": operation.request.context["mode"],
            "decision": decision, "reason": reason, "saved": False, "certificateRequested": False, "credentialReady": False}
        wire.validate_result(value, operation.request)
        return value

    def review(self):
        operation = self._bound()
        wire.need(operation.request.context["mode"] == "key-review" and operation._next_command == 6)
        self.inventory = signing.observe_signing(operation.context, operation.target, operation, now=datetime.now(timezone.utc))
        operation.check(operation.context)
        before = self.inventory.observation
        pending = wire.common.effective_pending(operation.request.native, operation.context.account_ref)
        selection = None
        if any(row.unresolved for row in pending):
            decision, reason = "blocked", "account-pending"
        elif not before.available or not self.inventory.profile_relationships_complete:
            decision, reason = "blocked", "inventory-unavailable"
        elif operation.request.native["key"]["vaultInventory"]["keys"]:
            # Attribution to an account is NOT inferred from a local key. Any
            # actual existing stored key takes recovery/selection first.
            decision, reason = "recover-existing-key", "existing-key"
        else:
            plan = prepare(operation.context, operation.target, before, bindings=(), csr=None,
                           pending=pending, now=datetime.now(timezone.utc))
            if plan.action == "prepare_csr" and plan.bundle is not None:
                decision, reason = "prepare-review", "local-key-required"
                bundle = plan.bundle
                selection = {"bundle": {"resourceId": bundle.resource_id, "identifier": bundle.identifier,
                    "platform": bundle.platform, "seedId": bundle.seed_id}, "beforeSha256": before.sha256, "planSha256": plan.sha256}
            elif plan.action == "recover_existing_key":
                decision, reason = "recover-existing-key", "existing-certificate"
            elif plan.bundle is None:
                decision, reason = "bundle-required", "bundle-registration-required"
            else:
                decision, reason = "blocked", "inventory-unavailable"
        payload = {"observedAt": before.observed_at.isoformat(),
            "validUntil": (before.observed_at + timedelta(seconds=300)).isoformat(),
            "decision": decision, "reason": reason, "selection": selection}
        wire.validate_event(operation.request, "key-observed", payload, 1)
        operation.source.engine.provisioning_event("key-observed", payload)
        operation.check(operation.context)
        operation.report = self._result(decision, reason)

    def prepare(self):
        operation = self._bound()
        wire.need(operation.request.context["mode"] == "key-prepare" and operation._next_command == 6
                  and operation.request.native["key"]["vaultInventory"]["keys"] == 0)
        if any(row.unresolved for row in wire.common.effective_pending(operation.request.native, operation.context.account_ref)):
            raise _Refused("journal-unavailable")
        operation.plan = wire.expected_plan(operation.request)
        wire.need(datetime.now(timezone.utc) < operation.plan.valid_until)
        payload = {"observedAt": operation.request.native["key"]["review"]["observedAt"],
            "validUntil": operation.plan.valid_until.isoformat(), "beforeSha256": operation.plan.observation_sha256,
            "planSha256": operation.plan.sha256, "update": wire.initial_update()}
        control.pending(operation.source, payload)
        # No inventory result alone reaches here: native rechecks exact full
        # inventory/context and durably reserves the destination before ACK.
        child = None
        first = None
        try:
            operation.check(operation.context)
            child = AppleDistributionKeyWork(operation)
            child.run()
        except BaseException as error:
            first = error
            operation.remember(error)
        try:
            if child is not None and child._frame is not None and child._parts is not None:
                operation._key_output.retain_returned(child)
                control.transfer(operation.source, operation._key_output)
            elif child is None or child._never_generated():
                operation._key_output.report_never_generated(child)
            else:
                raise wire.common.ProtocolError()  # Never discard/renew a possible key.
        except BaseException as error:
            operation.remember(error)
            if first is None:
                first = error
        if first is not None:
            raise first
        wire.need(operation._key_output._ack is not None)
        operation.report = self._result("produced", "producer-returned")

    def run(self):
        operation = self._bound()
        operation.check(operation.context)
        self.review() if operation.request.context["mode"] == "key-review" else self.prepare()
