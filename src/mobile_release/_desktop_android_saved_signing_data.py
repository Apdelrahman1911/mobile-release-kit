"""Pure saved Android signing receipt comparisons for the existing owners.

This module contains DATA predicates only. It does not import Android build,
tool discovery, process/native ownership, materialization or execution code.
Actual original evidence and independent expected values remain caller-owned.
"""
from __future__ import annotations

import re


def _need(value, message):
    if not value:
        raise ValueError(message)


SAVED_SIGNING_CASES = (
    "android-saved-signing",
    "android-saved-signing-wrong-fingerprint",
    "android-saved-signing-cancel",
)


def validate_saved_signing_case(case, projection, lifetime, *, saved_config, saved_version,
                               selection, certificate_sha256, original, dispatch):
    """Strict original-result DATA comparison; no native authority is created.

    The existing outer installed owner first validates its raw receipt, genuine
    UI/session route, source/input fixture custody, restoration and all-outcome
    POST. Expected saved values and the actual generated certificate digest
    come from those independent originals, NOT back out of this projection.
    No request/native metadata is fabricated to satisfy another validator.
    Acceptance here alone proves neither execution nor installed qualification.
    """
    from mobile_release import _desktop_android_build_protocol as wire
    from mobile_release.config import FINGERPRINT_RE

    _need(type(case) is str and case in SAVED_SIGNING_CASES, "Different saved signing case")
    # Apply the existing finite JSON DATA grammar even when the outer owner has
    # already decoded its receipt; reject extra/raw fields and booleans-as-ints.
    wire._structure([projection, lifetime, saved_config, saved_version, selection,
                     certificate_sha256, original, dispatch])
    wire._keys(projection, {"operationId", "ownerGeneration", "context", "phase", "intentUsable",
                           "outcome", "reason", "stage", "activity", "disposition", "result"})
    yes = ("inspectionJoined", "acquisitionJoined", "attempted", "childWaitedSuccess", "stdinClosed",
           "stdoutEofClosed", "stderrEofClosed", "ioJoined", "coreLifetimeSettled", "runtimeLedgerSettled",
           "runtimeSettlementJoined", "driverJoined", "managerJoined", "observerJoined", "watchdogJoined",
           "retiredBeforeCutoff")
    no = ("noChild", "activeRetained", "resourceUnknown")
    wire._keys(original, {"domain", "id", "generation", *yes, *no})
    _need(original["domain"] == "android"
          and all(type(original[key]) is str and re.fullmatch(r"[0-9a-f]{32}", original[key]) is not None
                  for key in ("id", "generation"))
          and all(original[key] is True for key in yes) and all(original[key] is False for key in no),
          "Saved signing original native owners have not settled")
    _need(projection["operationId"] == original["id"] and projection["ownerGeneration"] == original["generation"]
          and projection["phase"] == "terminal" and projection["intentUsable"] is False,
          "Saved signing terminal is not the original settled operation")

    context = wire.context(projection["context"])
    expected_config, expected_version = wire.content(saved_config), wire.saved_version(saved_version)
    expected_selection = wire._selection(selection)
    _need(context["savedConfig"] == expected_config and context["savedVersion"] == expected_version
          and context["signing"] is not None
          and [row["kind"] for row in context["signing"]["assignments"]] == ["android-keystore", "android-firebase"],
          "Saved signing inputs are not the original assigned fixture")
    selected_certificate = context["artifactValidation"]["uploadCertificateSha256"]
    _need(context["artifactValidation"]["mode"] == "upload-signature"
          and type(selected_certificate) is str and FINGERPRINT_RE.fullmatch(selected_certificate) is not None
          and type(certificate_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", certificate_sha256) is not None
          and FINGERPRINT_RE.fullmatch(certificate_sha256) is not None,
          "Saved signing certificate comparison is missing or malformed")

    cancelled = case == "android-saved-signing-cancel"
    mismatch = case == "android-saved-signing-wrong-fingerprint"
    _need((selected_certificate.lower() != certificate_sha256) is mismatch,
          "Saved signing certificate does not match the intended real case")
    activity = wire._activity(projection["activity"])
    life = wire._lifetime(lifetime)
    disposition = wire._disposition(projection["disposition"])
    wire._signed_command_prefix(activity, life)
    _need(activity["signing"] is not None and activity["selection"] == expected_selection
          and projection["stage"] == activity["stage"], "Saved signing original activity differs")
    _need(life["complete"] is True and life["fatal"] is False and life["contained"] is True
          and life["commandDispatched"] is True and life["commands"] == (1 if mismatch else 3 if cancelled else 6)
          and life["profileCalls"] == 0 and all(life[key] is True for key in wire._CLOSE_FIELDS)
          and life["stopObserved"] == ("cancelled" if cancelled else "none"),
          "Saved signing original command prefix or lifetime is incomplete")
    _need(disposition == {"work": "removed", "artifacts": "retained-incomplete" if mismatch or cancelled
                          else "retained-local-result"}, "Saved signing original output disposition differs")

    wire._keys(dispatch, {"observed", "operationId", "ownerGeneration", "stage", "cancelAfter"})
    _need(type(dispatch["observed"]) is bool and type(dispatch["cancelAfter"]) is bool
          and dispatch == {"observed": not mismatch, "operationId": None if mismatch else original["id"],
                           "ownerGeneration": None if mismatch else original["generation"],
                           "stage": None if mismatch else "signing", "cancelAfter": cancelled},
          "Saved signing dispatch/cancel observation is missing or from another original")
    zero, unused = {"outcome": "exited", "exitCode": 0}, {"outcome": "not-dispatched", "exitCode": None}
    signing = activity["signing"]
    _need(signing["validationCommand"] == zero, "Saved signing did not validate its real keystore command")
    if mismatch:
        _need(projection["outcome"] == "failed" and projection["reason"] == "signing-invalid"
              and activity["stage"] == "validating-signing" and signing["validationPassed"] is False
              and signing["materialization"] == "not-started" and activity["command"] == unused
              and signing["signingCommand"] == unused and projection["result"] is None
              and activity["findings"]
              and all(row["check"] == "other-core-finding" for row in activity["findings"])
              and any(row["status"] == "INVALID" for row in activity["findings"]),
              "Wrong saved fingerprint did not stop before Gradle and signing")
        return
    _need(signing["validationPassed"] is True and signing["materialization"] == "restored"
          and activity["command"] == zero, "Saved signing material/build completion is unproven")
    if cancelled:
        _need(projection["outcome"] == "cancelled" and projection["reason"] == "cancelled"
              and activity["stage"] == "signing" and signing["signingCommand"] == {"outcome": "unknown", "exitCode": None}
              and not activity["findings"] and projection["result"] is None,
              "Cancellation missed actual signing dispatch or observed a completed signer")
        return

    _need(projection["outcome"] == "complete" and projection["reason"] == "none"
          and activity["stage"] == "disposing-work" and signing["signingCommand"] == zero,
          "Saved signing success is not an actual completed six-command run")
    result = projection["result"]
    wire.validate_result(result)
    _need(result["usedConfig"] == expected_config and result["usedVersion"] == expected_version
          and result["artifactValidation"] == context["artifactValidation"]
          and all(result[key] == activity[key] for key in ("selection", "command", "signing", "findings", "summary"))
          and wire._inspection_commands(result["findings"], context["artifactValidation"]) + 2 == life["commands"],
          "Saved signing result lost its original inputs, commands or activity")
    required = {"structure": "passed", "nativeManifest": "passed", "applicationVersion": "native-checked",
                "signature": "passed", "signer": "matches-saved-upload-certificate", "toolkitSigning": "verified",
                "storeOperation": "not-requested", "sourceBinding": "not-established", "releaseReadiness": "not-assessed"}
    _need(result["assurances"] == required and result["artifacts"][0]["architectures"] == []
          and result["artifacts"][0]["unknownAbi"] is False,
          "Saved signing fixture did not pass actual signature, leaf and native manifest checks")
