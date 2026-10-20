"""Check assigned iOS signing inputs within the ORIGINAL IOSArchive worker.

No owner, runner, material import, certificate binding or provider is created
here.  The original worker enters this branch before its archive namespace and
uses its existing private material, account lease, fixed tools and validators.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib

from . import _desktop_ios_signing_reuse_protocol as wire
from ._desktop_ios_archive_protocol import SIGNED_CLOSE_FIELDS, require
from .reporting import Status

_CODES = {"credential-material.apple-p12": "signing-material",
          "credential-material.apple-profile": "profile-material",
          "credential-material.ios-firebase": "firebase-material"}


def public_findings(rows) -> list[dict]:
    # Finding messages can describe private inputs and are deliberately absent.
    return wire.findings([{"check": _CODES.get(row.code, "other-core-finding"),
                           "status": row.status.value} for row in rows])


def run_check(run, bound) -> None:
    from .desktop_ios_archive import IOSArchiveRun
    from .ios_archive_operation import BoundIOSInputs
    from .credentials import validate_signing_material
    require(type(run) is IOSArchiveRun and type(bound) is BoundIOSInputs
            and run.source.signing_check and wire.is_check(run.request.context)
            and run._candidate is None and run.operation.inputs is bound)
    operation, signing = run.operation, run.operation.signing
    require(signing is not None and signing.lease is not None and signing.session is None
            and operation._local_candidate is None and run._candidate_inputs is None
            and run._local_handoff is None)
    operation.advance("checking-signing-tools")
    operation.prepare_signing_check()
    signing.bind_values()
    operation.advance("validating-signing")
    signing.phase = "validating-signing"
    # This original validator owns FiniteScratch('signing-validation'), the
    # captured P12/password/profile, two authenticated CMS producers and up to
    # seven fixed OpenSSL calls.  It never installs a Keychain/profile/session.
    run.findings = validate_signing_material(bound.config, values=signing.values,
        platforms=("ios",), execution_source=signing.lease.execution_source(), cancellation=run.guard)
    rows = public_findings(run.findings)
    if ({row["check"] for row in rows} != wire.expected_checks(run.request.context)
            or any(row["status"] != Status.PASS.value for row in rows)):
        operation.fail("signing-validation-failed")
    require(signing.inputs_closed() and signing.commands_settled() and signing.session is None
            and signing.materialization is None and signing.materialized is None
            and signing.lease.active is None and operation.files.namespace is None
            and operation.files.work is None and operation.snapshot_binding.owner is None)
    operation.advance("checking-inputs")
    operation.check_inputs()
    operation.files.check_tools()
    selected = bound.saved.configuration
    result = {"schemaVersion": 1, "scope": wire.SCOPE,
        "checkedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "usedConfig": {"bytes": len(selected.raw), "sha256": hashlib.sha256(selected.raw).hexdigest()},
        "usedVersion": {"source": selected.source, "bytes": len(bound.saved.version_raw),
            "sha256": hashlib.sha256(bound.saved.version_raw).hexdigest(),
            "name": bound.saved.release.name, "build": bound.saved.release.build},
        "usedSigning": run.request.context["signing"], "checks": rows, "limitations": list(wire.LIMITATIONS)}
    wire.result_data(result, run.request.context)
    operation.checkpoint()
    run._candidate = result  # DATA only; actual closes/native joins still veto.


def terminal(run, lifetime: dict, dispatched) -> dict:
    from .desktop_ios_archive import IOSArchiveRun
    require(type(run) is IOSArchiveRun and run.source.signing_check and wire.is_check(run.request.context))
    settled = (lifetime["complete"] and not lifetime["fatal"] and lifetime["contained"]
               and all(lifetime[key] for key in SIGNED_CLOSE_FIELDS) and dispatched is not None)
    outcome, reason = run._failure(dispatched) if settled else ("unknown", "cleanup-unknown")
    value = {"schemaVersion": 1, "context": run.request.context, "outcome": outcome, "reason": reason,
        "activity": {"stage": run.operation.stage, "findings": public_findings(run.findings)},
        "disposition": run.operation.disposition(),
        "result": run._candidate if outcome == "complete" else None, "lifetime": lifetime}
    wire.validate_terminal(value, run.request)
    return value
