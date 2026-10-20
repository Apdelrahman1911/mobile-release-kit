"""Bundle-ID-only worker on the original saved Store/runtime/material owners.

This is a closed domain, not Store release execution or the old metadata-read
permission. Native admission, full selected-P8 custody, account-wide state,
review consent and all native joins remain on the SAME SavedCommand Session.
There is no credential discovery, direct HTTP, new process runner, signing-key
generation, certificate/profile issuance, revocation or retry here.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import threading
import time
from uuid import UUID

from . import _desktop_apple_provisioning_protocol as wire
from . import apple_provisioning_api as api
from . import apple_provisioning_bundle_registration as bundles
from ._desktop_apple_provisioning_control import AppleProvisioningInput
from ._store_runtime import StoreRuntimeContext
from .apple_provisioning_recovery import ProvisioningApproval, ProvisioningAttempt
from .build_inputs import FiniteScratch, finite_scratch, invocation_custody
from .cancellation import DefaultCancellation
from .credentials import SelectedStoreMaterial, _selected_store_material, store_material_prerequisite_findings
from .desktop_store_preflight import StorePreflightRun, _Refused
from .owned_process import PRIVATE_OUTPUT_LIMIT, run_owned
from .reporting import FAILING_STATUSES
from .stores import _fastlane_probe_commands, _require_fastlane_bundle, _runtime_environment
from .tooling import _complete_tooling_root


class AppleProvisioningRun:
    def __init__(self, request, guard, source):
        wire.require(type(request) is wire.AppleProvisioningRequest and type(guard) is DefaultCancellation
            and type(source) is AppleProvisioningInput and source.guard is guard and guard._apple_provisioning_source is source
            and source.active and source.request_returned and source.initial is request
            and threading.current_thread() is threading.main_thread())
        self.request, self.guard, self.source = request, guard, source
        self.operation = self
        self.root = Path(request.native["projectRoot"])
        self._request_bytes = self._request_data()
        self.invocation = self.runtime = self.config = self.material = None
        self.scratches, self.directories, self.reads = [], [], []
        self.primary = self.report = None
        self._ran = self._close_claimed = False
        self._next_command = 0
        self._pending = self._pending_argv = self._pending_capture = None
        self._command_claimed = False
        self._apple_material = self._received = self._received_material = None
        self.context = wire.core_context(request.native["provisioning"])
        self.target = wire.target(request.native["target"])
        self._profile = self._p12_extraction = self._profile_output = None
        self._key_steps = self._distribution_key = self._key_output = None
        if request.context["mode"] in wire.PROFILE_MODES:
            from ._desktop_apple_profile_protocol import target
            self.target = target(request)
        if request.context["mode"] in wire.KEY_MODES:
            from ._desktop_apple_key_protocol import target
            self.target = target(request)
        self.plan = self.attempt = self.approval = None
        self._wire_phase = "new"
        self._wire_request = self._wire_runner = None
        self._post_receipt = None
        self._last_persisted = None
        source.bind_operation(self)  # Before the first filesystem/process effect.
        if request.context["mode"] in wire.PROFILE_MODES:
            from ._desktop_apple_profile_worker import ProfileSteps
            ProfileSteps(self)
        if request.context["mode"] in wire.KEY_MODES:
            from ._desktop_apple_key_worker import KeySteps
            KeySteps(self)

    # Reuse the actual fixed source readers/material/scratch cleanup. Their
    # checks call THIS exact operation and its original cancellation owner.
    _request_data = StorePreflightRun._request_data
    bind_invocation = StorePreflightRun.bind_invocation
    _read = StorePreflightRun._read
    _saved = StorePreflightRun._saved
    _source_post = StorePreflightRun._source_post
    validate_apple_shape = staticmethod(StorePreflightRun.validate_apple_shape)
    _received_post = StorePreflightRun._received_post
    apple_material_command = StorePreflightRun.apple_material_command

    def close(self):
        StorePreflightRun.close(self)
        if self._p12_extraction is not None:
            self._p12_extraction.retire(self)
        if self._key_output is not None:
            self._key_output.retire_worker()
        self.material = None

    def remember(self, error):
        if self.request.context["mode"] == "key-prepare" and not isinstance(error, KeyboardInterrupt):
            self.source._key_body_failed = True  # Every later ordinary failure also vetoes the custody tail.
        StorePreflightRun.remember(self, error)
        if self.source.stop_reason == "cancelled" and self.attempt is not None:
            self.attempt.request_cancel()

    def checkpoint(self):
        wire.require(self.source.require_operation() is self and not self._close_claimed
                     and self._request_bytes == self._request_data())
        try:
            self.guard.check()
            self.source._clock()
            wire.require(self.source.first_failure is None)
        except BaseException:
            if self.source.stop_reason == "cancelled" and self.attempt is not None:
                self.attempt.request_cancel()
            raise

    def bind_scratch(self, scratch):
        layouts = ("online-runner", "store-selection", "store-selection")
        if self._profile is not None:
            layouts += ("apple-provisioning-p12",) + ("online-runner",) * 8
        elif self._key_steps is not None:
            layouts += ("online-runner",) * (6 if self.request.context["mode"] == "key-review" else 1)
        else:
            layouts += ("online-runner",) * (3 if self.request.context["mode"] == "register" else 1)
        wire.require(type(scratch) is FiniteScratch and scratch.cancellation is self.guard
            and len(self.scratches) < len(layouts) and scratch.layout == layouts[len(self.scratches)]
            and self.invocation is not None and scratch.journal is None and scratch._lane_binding is None)
        self.scratches.append(scratch)  # Before that original scratch acquires.
        if scratch.layout == "apple-provisioning-p12":
            wire.require(self._profile is not None and self._p12_extraction is not None)
            self._p12_extraction.bind_scratch(scratch)
        elif self.request.context["mode"] == "key-prepare" and len(self.scratches) == 4:
            wire.require(self._distribution_key is not None)
            self._distribution_key.bind_scratch(scratch)

    def _helper_argv(self):
        if self._key_steps is not None:
            return self._key_steps.helper_argv()
        if self._profile is not None:
            return self._profile.helper_argv()
        return ("bundle", "exec", "ruby", str(self.runtime.tooling_root / "fastlane/apple_provisioning_bundle_registration.rb"))

    def _base_environment(self):
        environment = _runtime_environment(self.runtime.environment())
        environment.update(BUNDLE_GEMFILE=str(self.runtime.tooling_root / "Gemfile"), FASTLANE_HIDE_CHANGELOG="true",
            FASTLANE_OPT_OUT_USAGE="true", FASTLANE_SKIP_DOCS="true", FASTLANE_SKIP_UPDATE_CHECK="true")
        return environment

    def _helper_environment(self):
        if self._key_steps is not None:
            return self._key_steps.helper_environment()
        if self._profile is not None:
            return self._profile.helper_environment()
        wire.require(type(self.material) is SelectedStoreMaterial and self._wire_request is not None)
        selected = self.material.lane_environment(platform="ios")
        wire.require(set(selected) == {"MOBILE_RELEASE_ASC_KEY_ID", "MOBILE_RELEASE_ASC_ISSUER_ID",
                                       "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"})
        environment = self._base_environment()
        environment.update(selected)
        environment.update(SPACESHIP_TIMEOUT="30", MOBILE_RELEASE_ASC_BUNDLE_ID=self.target.bundle_id,
            MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT=api.digest(api.canonical(wire.core_context_wire(self.context))),
            MOBILE_RELEASE_ASC_PROVISIONING_STEP="register" if self._wire_request.method == "POST" else "inspect",
            MOBILE_RELEASE_ASC_PROVISIONING_OPERATION_ID=self.request.operation_id)
        if self._wire_request.method == "POST":
            wire.require(self.source._ack_consumed and self.plan is not None and wire.sha(self.source._pending_ack))
            environment.update(MOBILE_RELEASE_ASC_PROVISIONING_PLAN_SHA256=self.plan.sha256,
                MOBILE_RELEASE_ASC_PROVISIONING_ACK_SHA256=self.source._pending_ack,
                MOBILE_RELEASE_ASC_PROVISIONING_DISPLAY_NAME_BASE64=base64.b64encode(self.target.display_name.encode("utf-8")).decode("ascii"))
        return environment

    @contextmanager
    def command(self, runtime, argv, *, capture):
        self.checkpoint()
        wire.require(type(runtime) is StoreRuntimeContext and runtime is self.runtime and self._pending is None
            and capture is True and self._next_command < wire.command_count(self.request.context["mode"]))
        index = self._next_command
        if index == 0:
            expected = self.apple_material_command(self._apple_material)
        elif index < 6:
            expected = _fastlane_probe_commands(runtime.tooling_root)[index - 1]
        elif index == 6 and self.request.context["mode"] == "key-prepare":
            wire.require(self._distribution_key is not None and self._wire_request is None)
            expected = self._distribution_key.argv(runtime)
        elif index == 6 and self._profile is not None:
            wire.require(self._p12_extraction is not None and self._wire_request is None)
            expected = self._p12_extraction.argv(runtime)
        else:
            wire.require(self._wire_request is not None and self._wire_runner is not None)
            expected = self._helper_argv()
        wire.require(tuple(argv) == expected)
        self._next_command += 1
        self._pending, self._pending_argv, self._pending_capture = index, expected, True
        self._command_claimed = False
        try:
            yield
        except BaseException as error:
            self.remember(error)
            raise
        finally:
            self._pending = self._pending_argv = self._pending_capture = None

    def command_arguments(self, argv, *, environ, cwd, capture, text, output_limit, on_start,
                          cleanup, execution_scope, journal_binding, evidence):
        self.checkpoint()
        wire.require(self._pending is not None and not self._command_claimed)
        self._command_claimed = True
        wire.require(tuple(argv) == self._pending_argv and capture is True and on_start is None and cleanup is False
                     and execution_scope is None and journal_binding is None and evidence is None)
        if self._pending == 0:
            expected_env, expected_cwd, limit, expected_text = self.runtime.environment(), self.runtime.tooling_root, 4096, True
        elif self._pending < 6:
            expected_env, expected_cwd, limit, expected_text = self._base_environment(), self.runtime.tooling_root, PRIVATE_OUTPUT_LIMIT, True
        elif self._pending == 6 and self.request.context["mode"] == "key-prepare":
            from ._desktop_apple_distribution_key import PRIVATE_LIMIT
            self._private_current()
            self._distribution_key.admit_command(self.runtime, argv, environ=environ)
            expected_env, expected_cwd, limit, expected_text = self._base_environment(), self._distribution_key._scratch._path, PRIVATE_LIMIT, False
        elif self._pending == 6 and self._profile is not None:
            self._p12_extraction.admit_command(self.runtime, argv, environ=environ)
            expected_env, expected_cwd, limit, expected_text = self._base_environment(), self.runtime.tooling_root, PRIVATE_OUTPUT_LIMIT, False
        else:
            self._private_current()
            expected_env, expected_cwd, limit, expected_text = self._helper_environment(), self._wire_runner._path, (
                PRIVATE_OUTPUT_LIMIT if self._profile is not None else self._key_steps.frame_limit() if self._key_steps is not None else bundles.FRAME_LIMIT), False
        wire.require(type(environ) is dict and environ == expected_env and cwd == expected_cwd
                     and type(output_limit) is int and output_limit == limit and text is expected_text)
        # The original run_owned seam repeats current source/material checks;
        # not only the earlier caller preparing argv/environment.
        self._source_post(); self._received_post()

    def command_limits(self, timeout, capture, output_limit):
        self.checkpoint()
        wire.require(self._pending is not None and self._command_claimed and capture is True)
        if self._pending == 6 and self.request.context["mode"] == "key-prepare":
            from ._desktop_apple_distribution_key import PRIVATE_LIMIT
            return min(timeout, 60), min(output_limit, PRIVATE_LIMIT)
        limit = (self._key_steps.frame_limit() if self._pending >= 6 and self._key_steps is not None else
            bundles.FRAME_LIMIT if self._pending >= 6 and self._profile is None else PRIVATE_OUTPUT_LIMIT)
        return min(timeout, 30 if self._pending == 0 else 60), min(output_limit, limit)

    def _target_current(self):
        self.checkpoint()
        ios = self.config.section("ios")
        if (not self.config.platform_enabled("ios") or ios.get("identityStatus") == "blocked"
                or ios.get("bundleId") != self.target.bundle_id or ios.get("teamId") != self.target.team_id):
            raise _Refused("query-prerequisites")
        if (self.request.context["mode"] == "review" and not self.target.existing_application
                and (ios.get("identityStatus") == "approved" or ios.get("appStoreAppId"))):
            raise _Refused("registration-blocked")
        if self.request.context["mode"] == "register" and (
                ios.get("identityStatus") != "unverified" or ios.get("appStoreAppId") or self.target.existing_application
                or self.target.app_id_prefix != self.target.team_id or not self.request.context["newApplication"]):
            raise _Refused("registration-blocked")

    def _private_current(self):
        self._target_current(); self._source_post(); self._received_post()
        wire.require(type(self.material) is SelectedStoreMaterial and type(self.runtime) is StoreRuntimeContext)
        self.material.require(config=self.config, platforms=("ios",), invocation=self.invocation)
        self.runtime.require(root=self.root, invocation=self.invocation)
        self.validate_apple_shape(self._received_material)
        issuer = UUID(self._received_material[2].decode("ascii")).bytes
        wire.require(api.digest(b"mrk:apple-provisioning-account:1\0" + issuer) == self.context.account_ref)

    def check(self, context):
        wire.require(context == self.context)
        self._private_current()

    def send(self, request):
        if self._key_steps is not None:
            return self._key_steps.send(request)
        if self._profile is not None:
            return self._profile.send(request)
        self.check(self.context)
        get = api.list_bundle_ids(self.target.bundle_id)
        if self._wire_phase == "new":
            wire.require(request == get and self._next_command == 6)
            self._wire_phase = "first-read"
        elif request.method == "POST":
            wire.require(self.request.context["mode"] == "register" and self._wire_phase == "first-read"
                         and self.plan is not None and request == self.plan.request and self._next_command == 7)
            self._wire_phase = "post-armed"  # Before ACK consumption/scratch.
            self.source.consume_pending_ack(self, request)
        else:
            wire.require(self.request.context["mode"] == "register" and self._wire_phase == "post-armed"
                         and request == get and self._next_command == 8 and self.attempt is not None
                         and self.attempt.record.status == "recovery_required" and self.attempt.record.reason == "readback_required"
                         and self.attempt.record.response_resource_id is not None and self.source.reply_step == 2
                         and self._last_persisted == self.attempt.record)
            self._wire_phase = "readback"
        self._wire_request = request
        try:
            with finite_scratch(layout="online-runner", cancellation=self.guard, parent=self.runtime.private_directory) as runner:
                self._wire_runner = runner
                self.check(self.context)
                previous = self.guard.lifetime_ledger.verdict().commands
                environment = self._helper_environment()
                with self.runtime.command(self._helper_argv(), capture=True):
                    completed = run_owned(self._helper_argv(), cwd=runner._path, environ=environment, capture=True,
                        text=False, timeout=60, output_limit=bundles.FRAME_LIMIT, cancellation=self.guard)
                self.check(self.context)
                verdict = self.guard.lifetime_ledger.verdict()
                wire.require(verdict.cleanup_complete and verdict.contained and verdict.command_dispatched is not None
                             and verdict.profile_calls == 0 and verdict.commands == previous + 1)
                wire.require(type(completed.returncode) is int and completed.returncode == 0
                             and type(completed.stdout) is bytes and completed.stderr == b"")
                response = bundles.response_from_frame(completed.stdout,
                    context_sha256=api.digest(api.canonical(wire.core_context_wire(self.context))), operation_id=self.request.operation_id,
                    target=self.target, request=request, ack_sha256=self.source._pending_ack if request.method == "POST" else None,
                    settled=True)  # ONLY after the real retained run_owned ledger above.
            self.check(self.context)
            if request.method == "POST":
                self._post_receipt = (self.guard.lifetime_ledger, verdict.commands)
            return response
        except BaseException as error:
            self.remember(error)
            raise
        finally:
            self._wire_request = self._wire_runner = None

    def authorize(self, plan, approval):
        if self._profile is not None:
            return self._profile.authorize(plan, approval)
        wire.require(self.plan is plan and self.approval is approval and self.request.context["mode"] == "register"
                     and plan.context == self.context and plan.target == self.target and approval.context == self.context
                     and approval.plan_sha256 == plan.sha256 and approval.action == "register_bundle_id")
        self.check(self.context)
        wire.require(datetime.now(timezone.utc) < plan.valid_until)

    def persist(self, record):
        if self._profile is not None:
            return self._profile.persist(record)
        wire.require(self.attempt is not None and record.context == self.context and record.plan_sha256 == self.plan.sha256)
        sequence = self.source.reply_step + 1
        update = {"sequence": sequence, "record": wire.attempt_wire(record)}
        if sequence == 1:
            payload = {"observedAt": self.request.native["reviewedAt"], "validUntil": self.plan.valid_until.isoformat(),
                "beforeSha256": self.plan.observation_sha256, "planSha256": self.plan.sha256,
                "requestBodySha256": api.digest(self.plan.request.body), "update": update}
        else:
            payload = {"update": update}
        try:
            self.source.exchange("pending" if sequence == 1 else "attempt", payload)
            self._last_persisted = record
        except BaseException as error:
            self.remember(error)
            raise

    def transport_settled(self, record):
        if self._profile is not None:
            return self._profile.transport_settled(record)
        wire.require(self.attempt is not None and record.context == self.context and record.plan_sha256 == self.plan.sha256)
        verdict = self.guard.lifetime_ledger.verdict()
        return (self._post_receipt is not None and self._post_receipt[0] is self.guard.lifetime_ledger
                and self._post_receipt[1] <= verdict.commands <= 9 and verdict.cleanup_complete and verdict.contained
                and verdict.profile_calls == 0 and self._pending is None)

    def reconciliation_current(self, plan, record):
        if self._profile is not None:
            return self._profile.reconciliation_current(plan, record)
        wire.require(self.plan is plan and self.attempt is not None and record.context == self.context
                     and record.plan_sha256 == plan.sha256 and self._last_persisted == record)
        self.check(self.context)
        return True  # Current SAME-run check; never restored journal authority.

    @staticmethod
    def _observation(observed):
        if observed.available:
            return "found" if observed.bundles else "not-returned"
        return "not-permitted" if observed.reason == "account_access_denied" else "inconclusive"

    def _result(self, observed, decision, *, comparison=None):
        value = {"schemaVersion": 1, "scope": "local-ios-bundle-provisioning", "mode": self.request.context["mode"],
            "observation": self._observation(observed), "decision": decision,
            "attempt": None if self.attempt is None else self.attempt.record.summary(), "comparison": comparison,
            "limitations": list(wire.LIMITATIONS)}
        wire.validate_result(value, self.request)
        return value

    def _read_only(self):
        observed = bundles.observe_bundle(self.context, self.target, self, now=datetime.now(timezone.utc))
        self.check(self.context)
        comparison = None
        if self.request.context["mode"] == "reconcile":
            decision = "comparison-only"
            record = self.request.native["prior"]["attempt"]["record"]
            comparison = "inconclusive" if not observed.available else "not-returned"
            if observed.available and observed.bundles:
                found = observed.bundles[0]
                comparison = ("unattributed" if record["responseResourceId"] is None else
                    "same-response" if found.resource_id == record["responseResourceId"] and
                    api.resource_sha256(found) == record["responseResourceSha256"] else "different-response")
        else:
            plan = bundles.prepare_bundle(self.context, self.target, observed,
                pending=wire.pending(self.request.native["pending"], self.context.account_ref), now=datetime.now(timezone.utc))
            decision = {"reuse_bundle_id": "reuse", "register_bundle_id": "review-required"}.get(plan.action, "blocked")
        bundle = None
        if observed.bundles:
            found = observed.bundles[0]
            bundle = {"resourceId": found.resource_id, "identifier": found.identifier, "platform": found.platform, "seedId": found.seed_id}
        self.source.engine.provisioning_event("observed", {"observedAt": observed.observed_at.isoformat(),
            "observation": self._observation(observed), "bundle": bundle,
            "beforeSha256": observed.sha256 if observed.available else None, "decision": decision})
        self.check(self.context)
        self.report = self._result(observed, decision, comparison=comparison)

    def _register(self):
        before, self.plan = wire.expected_plan(self.request)
        pending = wire.pending(self.request.native["pending"], self.context.account_ref)
        wire.require(not any(row.unresolved for row in pending))
        fresh = bundles.observe_bundle(self.context, self.target, self, now=datetime.now(timezone.utc))
        self.check(self.context)
        plan = bundles.prepare_bundle(self.context, self.target, fresh, pending=pending, now=datetime.now(timezone.utc))
        if plan.action != "register_bundle_id":
            self.report = self._result(fresh, "reuse" if plan.action == "reuse_bundle_id" else "blocked")
            return
        self.approval = ProvisioningApproval(self.context, self.plan.sha256, "register_bundle_id")
        self.attempt = ProvisioningAttempt(self.plan, before)
        record = self.attempt.execute(self.approval, fresh, self, self, now=datetime.now(timezone.utc))
        if (self.source.first_failure is None and record.status == "recovery_required" and record.reason == "readback_required"
                and record.response_resource_id is not None and self._last_persisted == record):
            fresh = bundles.observe_bundle(self.context, self.target, self, now=datetime.now(timezone.utc))
            self.attempt.reconcile(fresh, self, bindings=(), now=datetime.now(timezone.utc))
        decision = "registration-confirmed" if self.attempt.record.status == "succeeded" else "registration-unconfirmed"
        self.report = self._result(fresh, decision)

    def run(self):
        self.checkpoint()
        wire.require(not self._ran and sys.platform == "darwin" and os.getcwd() == self.request.native["cwd"])
        self._ran = True
        try:
            self.config, _ = self._saved()
            self._target_current()
            if self.request.context["mode"] in {"register", "profile-reuse", "profile-create", "key-prepare"} and any(
                    row.unresolved for row in wire.pending(self.request.native["pending"], self.context.account_ref)):
                raise _Refused("journal-unavailable")
            with invocation_custody(self.root, mode="online", cancellation=self.guard) as invocation:
                with finite_scratch(layout="online-runner", cancellation=self.guard, parent=Path("/private/tmp")) as home:
                    self.runtime = StoreRuntimeContext.installed(Path(self.request.native["cwd"]), invocation=invocation, private_home=home)
                    with finite_scratch(layout="store-selection", cancellation=self.guard, parent=home._path) as received:
                        original = self.source.receive_material(self, received)
                        self._received, self._received_material = (received, original), self.source._material
                        self._received_post()
                        values = {"MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH": str(received.require(original)),
                            "MOBILE_RELEASE_ASC_KEY_ID": self._received_material[1].decode("ascii"),
                            "MOBILE_RELEASE_ASC_ISSUER_ID": self._received_material[2].decode("ascii")}
                        findings = store_material_prerequisite_findings(values=values, platforms=("ios",))
                        with _selected_store_material(self.config, values=values, platforms=("ios",),
                                invocation=invocation, scratch_parent=home._path) as material:
                            self.material = material
                            findings.extend(material.validate(runtime_context=self.runtime))
                            if any(row.status in FAILING_STATUSES for row in findings):
                                raise _Refused("credentials-unavailable")
                            needed = ("apple_provisioning.rb", "apple_provisioning_bundle_read.rb") + (
                                ("apple_distribution_key.rb",) if self.request.context["mode"] == "key-prepare" else
                                ("apple_provisioning_signing.rb",) if self.request.context["mode"] == "key-review" else
                                ("apple_provisioning_p12.rb", "apple_provisioning_signing.rb") if self._profile is not None else
                                ("apple_provisioning_bundle_registration.rb",))
                            tooling = self.runtime.tooling_root
                            if not _complete_tooling_root(tooling) or any((tooling / "fastlane" / name).is_symlink()
                                    or not (tooling / "fastlane" / name).is_file() for name in needed):
                                raise _Refused("query-prerequisites")
                            self.check(self.context)
                            _require_fastlane_bundle(tooling, cancellation=self.guard, runtime_context=self.runtime)
                            if self._key_steps is not None:
                                self._key_steps.run()
                            elif self._profile is not None:
                                self._profile.run()
                            else:
                                self._register() if self.request.context["mode"] == "register" else self._read_only()
                            if self.source.first_failure is None:
                                self.check(self.context)
        except BaseException as error:
            self.remember(error)
            raise
        finally:
            self.close()

    def closed(self):
        wire.require(self.source.operation is self)
        invocation_closed = self.invocation is None or self.invocation._apple_provisioning_closed(self)
        return (self._close_claimed and self._pending is None and invocation_closed
            and (self._p12_extraction is None or self._p12_extraction.private_closed())
            and (self._key_output is None or self._key_output.worker_closed())
            and (self._distribution_key is None or self._distribution_key.private_closed())
            and all(directory.slots and all(slot.number is None and slot.close_state == "CLOSED" for slot in directory.slots)
                    for directory in self.directories)
            and all(s.claimed and not s.active and s._cleanup_complete and not s.created
                    and all(slot.number is None and slot.close_state == "CLOSED" for slot in (*s.writer_slots, s.slot, *s.parent.slots))
                    for s in self.scratches))

    def terminal(self):
        verdict = self.guard.lifetime_ledger.verdict()
        if verdict.profile_calls > (1 if self._profile is not None else 0) or verdict.commands > wire.command_count(self.request.context["mode"]):
            self.guard._abort(wire.ProtocolError()); verdict = self.guard.lifetime_ledger.verdict()
        if time.monotonic() >= self.source.work_end:
            self.source.stop("timed-out")
        elif self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")
        lifetime = {"complete": verdict.complete, "fatal": verdict.fatal, "contained": verdict.contained,
            "commandDispatched": verdict.command_dispatched, "commands": verdict.commands, "profileCalls": verdict.profile_calls,
            "inputClosed": self.source.material_closed(), "handlersRestored": self.guard.handler_state == "RESTORED",
            "invocationClosed": self.closed(), "stopObserved": self.source.stop_reason}
        settled = (verdict.cleanup_complete and verdict.contained and verdict.command_dispatched is not None
            and lifetime["inputClosed"] and lifetime["handlersRestored"] and lifetime["invocationClosed"])
        result = None
        if not settled:
            outcome, reason = "unknown", "cleanup-unknown"
        elif self.source.stop_reason != "none":
            outcome = reason = self.source.stop_reason
        elif isinstance(self.primary, _Refused):
            outcome, reason = "refused", self.primary.reason
        elif self.primary is not None or self.report is None:
            outcome, reason = "failed", "command-incomplete"
        else:
            outcome, reason, result = "complete", "none", self.report
        return {"schemaVersion": 1, "context": self.request.context, "outcome": outcome, "reason": reason,
                "result": result, "lifetime": lifetime}
