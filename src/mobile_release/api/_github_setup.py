"""Closed GitHub setup proposals: shipped text and caller-owned data only.

No repository observation, credentials, subprocess, network, file transaction or
Apply token. Resource reads select the executing package, never a project, URL,
tooling environment override or neighboring installation. A supplied hash is an
assertion to compare, not custody of any original file or repository revision.
"""
from __future__ import annotations

import hashlib
import json
import re
from importlib.resources import files
from typing import Any, cast

from .. import __version__
from ..config import MAX_CONFIG_BYTES
from ..credential_requirements import ENVIRONMENT_NAMES, STAGES
from ..errors import ConfigurationError, ValidationError
from ..workflow_payloads import (REPOSITORY_PLACEHOLDER, SHA_PLACEHOLDER,
                                 normalize_tooling_reference, pinned_schema_reference,
                                 render_workflow_caller)
from ._json import bounded_json_text
from ._preview import _validate
from .contracts import (ApiError, GitHubProposalFacts, GitHubSetupHelp,
                        GitHubSetupResult, assurance)

WORKFLOWS = (
    ("preflight", ".github/workflows/mobile-preflight.yml"),
    ("candidate", ".github/workflows/mobile-candidate.yml"),
    ("external-testing", ".github/workflows/mobile-external-testing.yml"),
    ("production-submit", ".github/workflows/mobile-production-submit.yml"),
)
INPUT_IDS = ("toolingRepository", "toolingSha", "suppliedSnapshot")
GUIDANCE_IDS = ("source-authority", "protected-environments", "runner-policy",
                "credentials", "preflight-and-releases", "scope")
MAX_RESOURCE_BYTES = 128 * 1024
MAX_WORKFLOW_BYTES = 16 * 1024
MAX_WORKFLOWS_BYTES = 64 * 1024
MAX_SNAPSHOT_FILE_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 256 * 1024
MAX_DOCUMENT_NODES = 8_000
MAX_DOCUMENT_DEPTH = 28
_HELP_FIELDS = frozenset({"id", "label", "what", "why", "where", "format", "failure"})
_DIGEST = re.compile(r"[0-9a-f]{64}")
_REQUIREMENT_NAME = re.compile(r"MOBILE_RELEASE_[A-Z0-9_]+")
_RESOURCE_ERROR = "The bundled GitHub setup resource is unavailable or invalid; no alternate resource was used"
_INPUT_ERROR = "GitHub setup input does not satisfy the bounded proposal contract"
_OUTPUT_ERROR = "The complete GitHub setup proposal exceeds its output contract"


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("Invalid closed GitHub setup data")


def _object(value: object, keys: set[str] | frozenset[str]) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys)
    return cast(dict[str, Any], value)


def _text(value: object, maximum: int, *, plain: bool = False) -> str:
    _require(type(value) is str and 0 < len(value) <= maximum)
    text = cast(str, value)
    _require(len(text.encode("utf-8")) <= maximum)
    if plain:
        _require(bool(text.strip()) and all(ord(char) >= 32 and ord(char) != 127 for char in text))
    return text


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        _require(key not in value)
        value[key] = item
    return value


def _nonfinite(_value: str) -> None:
    raise ValueError("Non-finite bundled JSON")


def _help(value: object) -> GitHubSetupHelp:
    help_data = _object(value, {"schemaVersion", "inputs", "guidance"})
    _require(type(help_data["schemaVersion"]) is int and help_data["schemaVersion"] == 1)
    for key, ids in (("inputs", INPUT_IDS), ("guidance", GUIDANCE_IDS)):
        items = help_data[key]
        _require(type(items) is list and len(items) == len(ids))
        for item, identity in zip(items, ids):
            entry = _object(item, _HELP_FIELDS | {"requiredness"} if key == "inputs" else _HELP_FIELDS)
            _require(entry["id"] == identity)
            _text(entry["label"], 96, plain=True)
            for field in ("what", "why", "where", "format", "failure"):
                _text(entry[field], 1024, plain=True)
            if key == "inputs":
                _require(entry["requiredness"] == ("optional" if identity == "suppliedSnapshot" else "required"))
    return cast(GitHubSetupHelp, help_data)


def _read_resource_bytes() -> bytes:
    # Trusted fixed names only. Works for the selected source/wheel/core ZIP
    # package origin; no asset lookup through MOBILE_RELEASE_TOOLING_ROOT.
    with files("mobile_release.api").joinpath("data", "github-setup-v1.json").open("rb") as source:
        return source.read(MAX_RESOURCE_BYTES + 1)


def _resource() -> tuple[bytes, dict[str, Any]]:
    try:
        raw = _read_resource_bytes()
        _require(type(raw) is bytes and len(raw) <= MAX_RESOURCE_BYTES)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
        bounded_json_text(value, max_bytes=MAX_RESOURCE_BYTES, max_nodes=8000, max_depth=16)
        resource = _object(value, {"schemaVersion", "workflows", "help"})
        _require(type(resource["schemaVersion"]) is int and resource["schemaVersion"] == 1)
        templates = _object(resource["workflows"], {identity for identity, _ in WORKFLOWS})
        total = 0
        for identity, _ in WORKFLOWS:
            template = _text(templates[identity], MAX_WORKFLOW_BYTES)
            total += len(template.encode("utf-8"))
            _require(SHA_PLACEHOLDER in template and REPOSITORY_PLACEHOLDER in template)
        _require(total <= MAX_WORKFLOWS_BYTES)
        _help(resource["help"])
        return raw, resource
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, ConfigurationError):
        raise ApiError("resource_unavailable", _RESOURCE_ERROR) from None


def github_setup_help() -> GitHubSetupHelp:
    """Pre-input catalogue help; each call returns newly read/admitted data."""
    _, resource = _resource()
    return cast(GitHubSetupHelp, resource["help"])


def _snapshot(value: object) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    container = _object(value, {"workflows"})
    records = container["workflows"]
    _require(type(records) is list and len(records) <= len(WORKFLOWS))
    allowed = {identity for identity, _ in WORKFLOWS}
    selected: dict[str, dict[str, Any]] = {}
    for record in records:
        _require(type(record) is dict)
        state = record.get("state")
        if state == "absent":
            item = _object(record, {"id", "state"})
        else:
            item = _object(record, {"id", "state", "byteLength", "sha256"})
            _require(state == "present")
            size, digest = item["byteLength"], item["sha256"]
            _require(type(size) is int and 0 <= size <= MAX_SNAPSHOT_FILE_BYTES)
            _require(type(digest) is str and _DIGEST.fullmatch(digest) is not None)
        identity = item["id"]
        _require(type(identity) is str and identity in allowed and identity not in selected)
        selected[identity] = item
    return selected


def _admit(draft: object, repository: object, sha: object, snapshot: object) -> tuple[str, str, dict[str, dict[str, Any]]]:
    try:
        _require(type(draft) is dict)
        bounded_json_text(draft, max_bytes=MAX_CONFIG_BYTES, max_nodes=MAX_DOCUMENT_NODES,
                          max_depth=MAX_DOCUMENT_DEPTH)
        bounded_json_text({"draft": draft, "toolingRepository": repository, "toolingSha": sha,
                           "suppliedSnapshot": snapshot}, max_bytes=1024 * 1024,
                          max_nodes=20_000, max_depth=32)
        repository, sha = normalize_tooling_reference(repository, sha)
        selected = _snapshot(snapshot)
        return repository, sha, selected
    except (ValueError, TypeError, UnicodeError, RecursionError, ConfigurationError, ValidationError):
        # No rejected value, unknown key, path or raw CLI/core exception escapes.
        raise ApiError("invalid_params", _INPUT_ERROR) from None


def _facts(snapshot: object) -> GitHubProposalFacts:
    return {
        "githubContacted": False, "repositoryObserved": False, "toolingRefResolved": False,
        "templateCompatibility": "unknown", "comparisonBasis": "caller-supplied-digest-summary",
        "snapshotProvided": snapshot is not None, "applyAvailable": False,
    }


def _requirements(values: object) -> None:
    """Bound the existing core descriptors, never derive separate requirements."""
    _require(type(values) is list and len(values) <= 128)
    seen: set[tuple[str, str, str]] = set()
    for value in values:
        item = _object(value, {"name", "kind", "stage", "platform", "environment", "alternatives", "reason", "state"})
        name = _text(item["name"], 96)
        _require(_REQUIREMENT_NAME.fullmatch(name) is not None)
        _require(item["kind"] in ("secret", "variable", "file", "manual"))
        _require(item["stage"] in STAGES and item["platform"] in ("android", "ios", "project"))
        _require(item["environment"] == ENVIRONMENT_NAMES[item["stage"]] and item["state"] == "unknown")
        key = (name, item["stage"], item["platform"])
        _require(key not in seen)
        seen.add(key)
        alternatives = item["alternatives"]
        _require(type(alternatives) is list and len(alternatives) <= 2)
        for alternative in alternatives:
            _require(_REQUIREMENT_NAME.fullmatch(_text(alternative, 96)) is not None)
        _text(item["reason"], 1024)


def _finish(result: dict[str, Any]) -> GitHubSetupResult:
    try:
        _requirements(result["validation"]["requirements"])
        bounded_json_text(result, max_bytes=MAX_RESULT_BYTES, max_nodes=8000, max_depth=16)
    except (ValueError, TypeError, UnicodeError, RecursionError, ConfigurationError):
        raise ApiError("proposal_output_limit", _OUTPUT_ERROR) from None
    return cast(GitHubSetupResult, result)


def propose_github_setup(draft: object, tooling_repository: object, tooling_sha: object,
                         supplied_snapshot: object) -> GitHubSetupResult:
    repository, sha, selected = _admit(draft, tooling_repository, tooling_sha, supplied_snapshot)
    # This deliberately reuses the existing redacted policy/requirements result,
    # not api.validate_draft's raw ConfigurationError rendering.
    validation = _validate(cast(dict[str, Any], draft))
    result: dict[str, Any] = {
        "schemaVersion": 1, "state": "invalid", "validation": validation,
        "facts": _facts(supplied_snapshot), "assurance": assurance("schema-policy"),
    }
    if not validation["valid"]:
        return _finish(result)
    raw, resource = _resource()
    workflows: list[dict[str, Any]] = []
    total = 0
    try:
        _require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", _text(__version__, 32)) is not None)
        for identity, path in WORKFLOWS:
            content = render_workflow_caller(resource["workflows"][identity].encode("utf-8"), repository, sha)
            _require(0 < len(content) <= MAX_WORKFLOW_BYTES)
            total += len(content)
            _require(total <= MAX_WORKFLOWS_BYTES)
            digest = hashlib.sha256(content).hexdigest()
            supplied = selected.get(identity)
            comparison = "not-supplied"
            if supplied is not None:
                comparison = ("reported-absent" if supplied["state"] == "absent" else
                              "supplied-digest-match" if supplied["byteLength"] == len(content)
                              and supplied["sha256"] == digest else "supplied-digest-differs")
            workflows.append({"id": identity, "path": path, "content": content.decode("utf-8"),
                              "byteLength": len(content), "sha256": digest, "comparison": comparison})
        source = cast(dict[str, Any], draft)["source"]
        candidate, production = (_text(source[key], 1024) for key in ("candidateBranch", "productionBranch"))
        schema_reference = _text(pinned_schema_reference(repository, sha), 512)
    except (ValueError, TypeError, UnicodeError, RecursionError, ValidationError):
        raise ApiError("proposal_output_limit", _OUTPUT_ERROR) from None
    result.update({
        "state": "proposed",
        "templateSet": {"coreVersion": __version__, "resourceVersion": 1,
                        "resourceSha256": hashlib.sha256(raw).hexdigest()},
        "tooling": {"repository": repository, "sha": sha, "schemaReference": schema_reference, "state": "format-only"},
        "workflows": workflows,
        "settings": {"configPath": "release/mobile-release.json",
                     "sourcePolicy": {"candidateBranch": candidate, "productionBranch": production, "basis": "configured-policy"},
                     "environments": [{"stage": stage, "name": ENVIRONMENT_NAMES[stage]} for stage in STAGES],
                     "guidanceIds": list(GUIDANCE_IDS)},
    })
    return _finish(result)
