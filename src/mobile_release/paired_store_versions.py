"""One current Android+iOS inventory on the SAME original Store operation.

The two summaries are DATA, never two reusable native receipts. The native
caller retains one exact Both/VersionInventory context, its Google and P8
assignments, earliest clock, source and actual final joins. Neither a partial
result nor an older single-platform observation can supply this pair.
"""
from __future__ import annotations

from . import android_store_versions as android
from . import ios_store_versions as ios
from . import version_policy as policy

QUERY = "paired-current-versions"
CONSENT = "local-paired-current-versions-edit-v1"
RESULT_SCOPE = "local-shared-current-version-inventory"
POLICY_SCOPE = "require-current-shared-inventory"
PLATFORMS = ("android", "ios")
COMMANDS = 13  # One P8 validator, then each reader's five probes + fixed query.
LIMITATIONS = list(android.LIMITATIONS)


def selected_query(context: dict) -> bool:
    return context.get("platform") == "both" and context.get("query") == QUERY


def query_prerequisites(config) -> bool:
    return android.query_prerequisites(config) and ios.query_prerequisites(config)


def unavailable() -> dict:
    return {"android": android.unavailable("not-checked"), "ios": ios.unavailable("not-checked")}


def valid_summary(value: object) -> bool:
    return (type(value) is dict and set(value) == set(PLATFORMS)
            and android.valid_summary(value["android"]) and ios.valid_summary(value["ios"]))


def observed(value: object) -> bool:
    return valid_summary(value) and all(value[p]["observation"] == "observed" for p in PLATFORMS)


def valid_result(value: object) -> bool:
    from ._desktop_store_preflight_protocol import CHECKS, STATUSES
    from .reporting import FAILING_STATUSES
    if not (type(value) is dict and set(value) == {"schemaVersion", "scope", "findings", "limitations", "currentVersions"}
            and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["scope"] == RESULT_SCOPE and value["limitations"] == LIMITATIONS
            and valid_summary(value["currentVersions"])
            and type(value["findings"]) is list and len(value["findings"]) <= 16):
        return False
    return all(type(row) is dict and set(row) == {"check", "status"}
               and type(row["check"]) is str and row["check"] in CHECKS
               and type(row["status"]) is str and row["status"] in STATUSES
               and (not observed(value["currentVersions"])
                    or row["status"] not in FAILING_STATUSES and row["check"] != "store-access")
               for row in value["findings"])


def project_result(findings, summary: dict) -> dict:
    from ._desktop_store_preflight_protocol import project_result as access_result
    # Keep the original per-kind redaction allowlist; no private error text or
    # provider response is copied into a new paired presentation shape.
    rows = []
    for finding in findings:
        platform = "android" if finding.code in {"credential-material.google-adc", "store.online.android"} else "ios"
        rows.extend(access_result([finding], platform=platform)["findings"])
    result = {"schemaVersion": 1, "scope": RESULT_SCOPE, "findings": rows,
              "limitations": list(LIMITATIONS), "currentVersions": summary}
    policy._need(valid_result(result))
    return result


def read_saved_versions(operation, config, material):
    """Sequential fixed readers, not a new command/material/cleanup owner."""
    from .credentials import SelectedStoreMaterial
    from .desktop_store_preflight import StorePreflightRun
    from .reporting import FAILING_STATUSES
    policy._need(type(operation) is StorePreflightRun and selected_query(operation.request.context)
                 and operation.source.require_operation() is operation
                 and type(material) is SelectedStoreMaterial and query_prerequisites(config))
    operation.checkpoint()
    material.require(config=config, platforms=PLATFORMS, invocation=operation.invocation)
    result = unavailable()
    findings, result["ios"] = ios.read_saved_versions(operation, config, material)
    # A failed, incomplete or unsupported first inventory MUST NOT open a Play
    # edit. No attempt to salvage the pair by using an older iOS observation.
    if result["ios"]["observation"] == "observed" and not any(f.status in FAILING_STATUSES for f in findings):
        operation._source_post(); operation._received_post()
        material.require(config=config, platforms=PLATFORMS, invocation=operation.invocation)
        extra, result["android"] = android.read_saved_versions(operation, config, material)
        findings.extend(extra)
    operation._source_post(); operation._received_post()
    policy._need(valid_summary(result))
    return findings, result


def parse_observations(value: object):
    policy._need(type(value) is list and len(value) == 2, "store-platform-mismatch")
    return (android.CurrentInventory.parse(value[0]), ios.CurrentInventory.parse(value[1]))


def constraints(observations, enabled, identity_revision, context_revision, selected, *, now):
    policy._need(type(selected) is policy.VersionPolicy and selected.store_scope == POLICY_SCOPE, "invalid-policy")
    policy._need(enabled == PLATFORMS and type(observations) is tuple and len(observations) == 2
                 and type(observations[0]) is android.CurrentInventory
                 and type(observations[1]) is ios.CurrentInventory, "store-platform-mismatch")
    policy._match(identity_revision, policy._DIGEST)
    policy._match(context_revision, policy._DIGEST)
    policy._integer(now, (1 << 63) - 1)
    # The SAME original admission supplies both timestamps. Two individually
    # fresh reads under different contexts/earliest clocks are not this pair.
    policy._need(observations[0].observed_at == observations[1].observed_at, "store-identity-changed")
    for original in observations:
        policy._need(original.identity_revision == identity_revision
                     and original.context_revision == context_revision, "store-identity-changed")
        policy._need(0 <= now - original.observed_at <= selected.store_max_age_seconds, "store-observation-stale")
    return max(o.max_build for o in observations), observations[1].marketing_version


def propose(selected, *, source, base, allocated, enabled, identity_revision, context_revision, observations, now):
    increment = selected.increment_for(source)
    base = policy.version(base, enabled, automatic=True)
    allocated = policy.version(allocated, enabled, automatic=True)
    floor, marketing = constraints(observations, enabled, identity_revision, context_revision, selected, now=now)
    build = max(base.build, allocated.build, floor) + 1
    policy._need(build <= policy.IOS_INTEGER_MAX_BUILD, "ios-integer-build-exhausted")
    policy._need(build <= selected.build_ceiling, "build-exhausted")
    name = max((base.name, allocated.name, *((marketing,) if marketing is not None else ())), key=policy.numeric_version)
    major, minor, patch = policy.numeric_version(name)
    if increment != "build":
        name = ".".join(map(str, {"patch": (major, minor, patch + 1), "minor": (major, minor + 1, 0),
                                 "major": (major + 1, 0, 0)}[increment]))
    return policy.version(policy.ReleaseVersion(name, build), enabled, automatic=True)


def check_reserved(reserved, selected, *, enabled, identity_revision, context_revision, observations, now):
    policy.version(reserved, enabled, automatic=True)
    floor, name = constraints(observations, enabled, identity_revision, context_revision, selected, now=now)
    policy._need(reserved.build > floor and (name is None or policy.numeric_version(reserved.name)
                 >= policy.numeric_version(name)), "reservation-consumed")
