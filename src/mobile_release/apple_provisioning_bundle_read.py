"""One saved Bundle-ID read on the original local Store-access owner.

No credential discovery, HTTP client, process owner, retries or provisioning
writes live here. The returned comparison DATA is provisional: the existing
StorePreflightRun and native Session still owe all their original joins/POSTs.
In particular, this module never manufactures AppleResponse.settled evidence.
"""
from __future__ import annotations

import base64
import binascii
from pathlib import Path

from . import apple_provisioning_api as api
from .reporting import Finding, Status

QUERY = "bundle-id-registration"
CONSENT = "local-ios-bundle-id-read-v1"
SCOPE = "local-ios-bundle-id-registration-read"
RAW_LIMIT = 32 * 1024
FRAME_LIMIT = 64 * 1024
QUERY_SECONDS = 60
OBSERVATIONS = frozenset({"found", "not-returned", "not-permitted", "inconclusive", "not-checked"})
LIMITATIONS = ["non-publishing", "no-project-commands", "no-build-or-signing", "no-release-readiness",
              "point-in-time-account-access", "saved-inputs-not-atomic", "no-team-verification",
              "no-global-availability-claim", "no-provisioning-changes"]
_CHECKS = frozenset({"credential-format", "query-prerequisites", "runtime-unavailable", "bundle-unavailable"})
_STATUSES = frozenset(item.value for item in Status)


def selected_query(context: dict) -> bool:
    return context.get("query") == QUERY and context.get("platform") == "ios"


def fixed_argv(tooling_root: Path) -> tuple[str, ...]:
    return ("bundle", "exec", "ruby", str(tooling_root / "fastlane/apple_provisioning_bundle_read.rb"))


def query_prerequisites(config) -> bool:
    """Only this read's saved inputs; no app ID/TestFlight group is needed."""
    try:
        if not config.platform_enabled("ios") or config.section("ios").get("identityStatus") == "blocked":
            return False
        api.list_bundle_ids(config.section("ios").get("bundleId"))
        return True
    except api.ProvisioningError:
        return False


def observation_from_frame(raw: bytes, *, context_sha256: str, bundle_id: str) -> str:
    """Validate the ORIGINAL pre-JSON HTTP bytes, not an SDK-normalized Hash.

    This describes at most one completed response page. A missing continuation,
    count, row or permission cannot imply global availability. Transport/native
    finality is deliberately not an input or an output of this DATA parser.
    """
    api.list_bundle_ids(bundle_id)
    api.require(type(context_sha256) is str and api.HEX_RE.fullmatch(context_sha256) is not None,
                "invalid_bundle_read_context")
    try:
        api.require(type(raw) is bytes and 0 < len(raw) <= FRAME_LIMIT)
        frame = api.document(raw)
        api.require(set(frame) == {"schemaVersion", "contextSha256", "bundleId", "response"}
                    and type(frame["schemaVersion"]) is int and frame["schemaVersion"] == 1
                    and frame["contextSha256"] == context_sha256 and frame["bundleId"] == bundle_id)
        response = frame["response"]
        api.require(type(response) is dict and set(response) == {"status", "bodyBase64", "failure"})
        status, encoded, failure = (response[k] for k in ("status", "bodyBase64", "failure"))
        api.require(status is None or type(status) is int and 100 <= status <= 599)
        api.require(failure is None or failure == "provider_request_unconfirmed")
        if failure is not None:
            api.require(encoded is None)
            return "not-permitted" if status in (401, 403) else "inconclusive"
        api.require(type(status) is int and type(encoded) is str and encoded.isascii()
                    and 0 < len(encoded) <= 4 * ((RAW_LIMIT + 2) // 3))
        original = base64.b64decode(encoded, validate=True)
        api.require(0 < len(original) <= RAW_LIMIT and base64.b64encode(original).decode("ascii") == encoded)
        if status in (401, 403):
            return "not-permitted"
        # A list GET has a 200 response. 404/204/redirects are not an empty list.
        api.require(status == 200)
        document = api.document(original)
        api.require("errors" not in document and "error" not in document)
        rows, links, meta = (document.get(k) for k in ("data", "links", "meta"))
        api.require(type(rows) is list and len(rows) <= 200 and type(links) is dict
                    and links.get("next") is None and type(meta) is dict)
        paging = meta.get("paging")
        api.require(type(paging) is dict and type(paging.get("total")) is int
                    and paging["total"] == len(rows))
        bundles = tuple(api.BundleId.parse(row) for row in rows)
        api.require(len({item.resource_id for item in bundles}) == len(bundles))
        # Unknown/contradictory attributes are not interpreted as team evidence.
        api.require(all(set(row["attributes"]) == {"identifier", "platform", "seedId"} for row in rows))
        api.require(all(item.identifier == bundle_id and item.platform in {"IOS", "UNIVERSAL"}
                        for item in bundles) and len(bundles) <= 1)
        return "found" if bundles else "not-returned"
    except (api.ProvisioningError, ValueError, TypeError, KeyError, UnicodeError, binascii.Error):
        return "inconclusive"


def valid_result(value: object) -> bool:
    if not (type(value) is dict and set(value) == {"schemaVersion", "scope", "findings", "limitations", "observation"}
            and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["scope"] == SCOPE
            and type(value["observation"]) is str and value["observation"] in OBSERVATIONS
            and value["limitations"] == LIMITATIONS and type(value["findings"]) is list
            and len(value["findings"]) <= 16):
        return False
    return all(type(row) is dict and set(row) == {"check", "status"}
               and type(row["check"]) is str and row["check"] in _CHECKS
               and type(row["status"]) is str and row["status"] in _STATUSES for row in value["findings"])


def project_result(findings: list[Finding], observation: str) -> dict:
    from ._desktop_store_preflight_protocol import project_result as access_result
    value = access_result(findings, platform="ios")
    value.update(scope=SCOPE, observation=observation, limitations=list(LIMITATIONS))
    api.require(valid_result(value), "invalid_bundle_read_result")
    return value


def read_saved_bundle_id(operation, config, material) -> tuple[list[Finding], str]:
    """Called only inside the existing StorePreflightRun's selected-material loan.

    The final command replaces that run's ordinary Fastfile access query. Its
    same P8 validator and five installed-runtime probes remain the first six
    commands. Unknown commands/cleanup propagate to that original run; they do
    not become a successful observation or grant another attempt.
    """
    from ._store_runtime import StoreRuntimeContext
    from .build_inputs import finite_scratch
    from .credentials import SelectedStoreMaterial
    from .desktop_store_preflight import StorePreflightRun
    from .errors import StoreOperationError
    from .owned_process import ProcessError, run_owned
    from .stores import _require_fastlane_bundle, _runtime_environment
    from .tooling import _complete_tooling_root

    api.require(type(operation) is StorePreflightRun and selected_query(operation.request.context)
                and operation.source.require_operation() is operation and type(material) is SelectedStoreMaterial,
                "bundle_read_original_unavailable")
    operation.checkpoint()
    runtime, invocation = operation.runtime, operation.invocation
    api.require(type(runtime) is StoreRuntimeContext and query_prerequisites(config), "bundle_read_original_unavailable")
    material.require(config=config, platforms=("ios",), invocation=invocation)
    runtime.require(root=config.root, invocation=invocation)
    bundle_id = config.section("ios")["bundleId"]
    request = api.list_bundle_ids(bundle_id)
    context_sha256 = api.digest(api.canonical(operation.request.context))
    tooling = runtime.tooling_root
    if not _complete_tooling_root(tooling) or any(
        (tooling / name).is_symlink() or not (tooling / name).is_file()
        for name in ("fastlane/apple_provisioning.rb", "fastlane/apple_provisioning_bundle_read.rb")
    ):
        return [Finding("store.online.fastfile", Status.FAIL, "Bundled Bundle-ID reader is unavailable.",
                        category="store-access")], "not-checked"
    try:
        _require_fastlane_bundle(tooling, cancellation=operation.guard, runtime_context=runtime)
    except ProcessError:
        raise
    except StoreOperationError:
        return [Finding("store.online.bundle", Status.FAIL, "Pinned Store dependencies are unavailable.",
                        category="store-access")], "not-checked"

    def current():
        operation._source_post()
        operation._received_post()
        material.require(config=config, platforms=("ios",), invocation=invocation)
        runtime.require(root=config.root, invocation=invocation)
        api.require(api.list_bundle_ids(config.section("ios")["bundleId"]) == request,
                    "bundle_read_original_changed")

    with finite_scratch(layout="online-runner", cancellation=operation.guard,
                        parent=runtime.private_directory) as runner:
        current()
        selected = material.lane_environment(platform="ios")
        api.require(set(selected) == {"MOBILE_RELEASE_ASC_KEY_ID", "MOBILE_RELEASE_ASC_ISSUER_ID",
                                      "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"}, "bundle_read_original_unavailable")
        environment = _runtime_environment(runtime.environment())
        environment.update(selected)
        environment.update({"BUNDLE_GEMFILE": str(tooling / "Gemfile"), "SPACESHIP_TIMEOUT": "30",
                            "FASTLANE_HIDE_CHANGELOG": "true", "FASTLANE_OPT_OUT_USAGE": "true",
                            "FASTLANE_SKIP_DOCS": "true", "FASTLANE_SKIP_UPDATE_CHECK": "true",
                            "MOBILE_RELEASE_ASC_BUNDLE_ID": bundle_id,
                            "MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT": context_sha256})
        argv = fixed_argv(tooling)
        with runtime.command(argv, capture=True):
            completed = run_owned(argv, cwd=runner._path, environ=environment, capture=True, text=False,
                                  timeout=QUERY_SECONDS, output_limit=FRAME_LIMIT, cancellation=operation.guard)
        current()
        if (type(completed.returncode) is not int or completed.returncode != 0
                or type(completed.stdout) is not bytes or completed.stderr != b""):
            observation = "inconclusive"
        else:
            observation = observation_from_frame(completed.stdout, context_sha256=context_sha256, bundle_id=bundle_id)
    current()
    return [], observation
