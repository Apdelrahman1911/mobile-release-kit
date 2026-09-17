"""Passive desktop API v1. Never invoke CLI/report emitters or native processes.

Only the closed read-only methods below are implemented. Stateful/native operations need
a separately reviewed owner and cannot be added as a generic callable bridge.
"""
from __future__ import annotations

import sys
from typing import Any

from .. import __version__
from ..config import parse_config_text
from ..errors import ConfigurationError
from ._catalog import catalog, requirement_descriptors
from ._json import bounded_json_text
from ._preview import preview_config, suggest_config
from ._github_setup import propose_github_setup
from ._snapshot import project_snapshot, snapshot_available
from .contracts import ApiError, CapabilitiesResult, ValidateResult, assurance, issue

__all__ = ["ApiError", "execute"]
METHODS = ("capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview",
           "github.setup.propose")
_FUTURE_ACTIONS = (
    "project.initialize", "config.save", "doctor", "preflight.offline",
    "preflight.signing", "preflight.online", "android.build", "ios.build",
    "assets.import", "credentials.vault", "metadata.edit", "github.authenticate",
    "github.setup", "release.candidate", "release.external-testing", "release.production",
    "artifacts.verify", "history.load", "recovery.inspect", "recovery.apply",
)


def capabilities() -> CapabilitiesResult:
    host = ("linux" if sys.platform.startswith("linux") else "macos" if sys.platform == "darwin"
            else "windows" if sys.platform == "win32" else "other")
    return {
        "coreVersion": __version__, "apiVersion": 1,
        "hostPlatform": host, "mode": "read-only-foundation",
        "methods": [
            {"method": name, "available": name != "project.snapshot" or snapshot_available(),
             "reason": ("Requires the reviewed POSIX static reader; Windows filesystem snapshots are unavailable."
                        if name == "project.snapshot" and not snapshot_available()
                        else "Implemented passive API; no native, signing or Store verification.")}
            for name in METHODS
        ],
        "actions": [{"id": action, "available": False,
                     "reason": "Not implemented in the read-only desktop foundation; no action was performed."}
                    for action in _FUTURE_ACTIONS],
        "limitations": [
            "Static hints and format-valid configuration do not establish release readiness.",
            "No configuration is saved and no project, Git or native tool is executed.",
            "No credential values, Store services, release evidence or recovery journals are inspected.",
            "Windows static filesystem reads and native release execution remain unavailable pending reviewed backends.",
            "A native desktop bridge and packaged standalone runtime require their own verification.",
        ],
    }


def validate_draft(draft: object) -> ValidateResult:
    try:
        data = parse_config_text(bounded_json_text(draft))
    except ConfigurationError as error:
        return {"valid": False, "state": "invalid", "issues": [issue("config.invalid", str(error))],
                "requirements": [], "assurance": assurance("schema-policy")}
    return {"valid": True, "state": "format-valid", "issues": [],
            "requirements": requirement_descriptors(data), "assurance": assurance("schema-policy")}


def execute(method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a closed passive service after independent parameter admission."""
    if type(method) is not str or method not in METHODS:
        raise ApiError("unknown_method", "Unknown or unavailable desktop core method")
    if type(params) is not dict or any(type(key) is not str for key in params):
        raise ApiError("invalid_params", "Method parameters must be a JSON object with string keys")
    allowed = {"project.snapshot": {"root", "configPath"}, "config.validate": {"draft"},
               "config.suggest": {"hints"}, "config.preview": {"base", "draft"},
               "github.setup.propose": {"draft", "toolingRepository", "toolingSha", "suppliedSnapshot"}}.get(method, set())
    required = {"root"} if method == "project.snapshot" else allowed
    if set(params) - allowed or required - set(params):
        raise ApiError("invalid_params", "Unknown or missing parameters for the selected method")
    if method == "capabilities":
        return capabilities()
    if method == "catalog":
        return catalog()
    if method == "config.validate":
        return validate_draft(params["draft"])
    if method == "config.suggest":
        return suggest_config(params["hints"])
    if method == "config.preview":
        return preview_config(params["base"], params["draft"])
    if method == "github.setup.propose":
        return propose_github_setup(params["draft"], params["toolingRepository"], params["toolingSha"], params["suppliedSnapshot"])
    return project_snapshot(params["root"], params.get("configPath", "release/mobile-release.json"))
