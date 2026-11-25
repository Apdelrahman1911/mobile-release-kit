"""Selected protected-workflow Store reads on the existing owned-process path.

The fixed Ruby readers remain the sole provider callers. Play's temporary edit
is an explicit external effect, not a read-only GET. Its original input, raw
return and cleanup stay private here; no native receipt or caller DTO is used.
"""
from __future__ import annotations

import base64
import math
import os
import re

from . import ios_store_versions as ios
from . import android_store_versions as android
from . import version_policy as policy
from ._desktop_github_engine import _decode_json
from .build_inputs import finite_scratch
from .owned_process import run_owned
from .stores import _runtime_environment

_KEY = "MOBILE_RELEASE_ASC_KEY_ID"
_ISSUER = "MOBILE_RELEASE_ASC_ISSUER_ID"
_P8 = "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"
_GOOGLE = "MOBILE_RELEASE_PLAY_SERVICE_ACCOUNT_JSON_BASE64"
_GAC = "GOOGLE_APPLICATION_CREDENTIALS"
_IOS = (_KEY, _ISSUER, _P8)
_LIMIT = 16 * 1024


def _decode_selected(encoded, reason):
    from .version_hosted import need
    need(encoded.isascii() and 0 < len(encoded) <= 4 * ((_LIMIT + 2) // 3), reason)
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError:
        need(False, reason)
    need(0 < len(raw) <= _LIMIT and base64.b64encode(raw).decode("ascii") == encoded, reason)
    return raw


def _google_identity(raw):
    """Bounded input shape only; Ruby owns key/auth validation and fixed token IO."""
    from .version_hosted import need
    try:
        value = _decode_json(raw, limit=_LIMIT, nodes=64, depth=2)
        required = {"type", "project_id", "private_key_id", "private_key", "client_email", "client_id", "token_uri"}
        optional = {"auth_uri", "auth_provider_x509_cert_url", "client_x509_cert_url", "universe_domain"}
        need(type(value) is dict and required <= value.keys() <= required | optional
             and all(type(v) is str and v and "\0" not in v for v in value.values())
             and value["type"] == "service_account" and value["token_uri"] == "https://oauth2.googleapis.com/token"
             and re.fullmatch(r"[a-z][a-z0-9-]{4,61}[a-z0-9]", value["project_id"]) is not None
             and re.fullmatch(r"[a-zA-Z0-9._-]{1,64}@" + re.escape(value["project_id"]) + r"\.iam\.gserviceaccount\.com", value["client_email"]) is not None
             and re.fullmatch(r"[a-fA-F0-9]{40}", value["private_key_id"]) is not None
             and re.fullmatch(r"[0-9]{1,32}", value["client_id"]) is not None, "google")
        return {name: value[name] for name in ("project_id", "client_email", "client_id", "private_key_id")}
    except (ValueError, TypeError, KeyError):
        need(False, "google")


class Material:
    def __init__(self, tooling, *, platform="ios"):
        from .version_hosted import need, _PLATFORMS
        need(platform in _PLATFORMS, "admission")
        self.tooling = tooling
        self.platform = platform
        self.enabled = _PLATFORMS[platform]
        self.used = False
        self._source = self._context = None
        self._ios_used = self._play_used = False
        self._ios_inventory = None
        self._play_original = self._play_return = self._play_edit_id = None
        self._play_selection = self._play_snapshot = self._play_runner = None
        self._play_cleanup = None
        self._play_closed = self._play_consumed = False
        self.selected = {name: os.environ.get(name, "") for name in (*_IOS, _GOOGLE, _GAC)}
        need(not self.selected[_GAC], "google")  # Never borrow ambient WIF/ADC.
        if "ios" in self.enabled:
            need(re.fullmatch(r"[A-Z0-9]{10}", self.selected[_KEY]) is not None
                 and re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", self.selected[_ISSUER]) is not None,
                 "store")
            self.private = _decode_selected(self.selected[_P8], "store")
        else:
            need(not any(self.selected[name] for name in _IOS), "store")
        if "android" in self.enabled:
            self.google = _decode_selected(self.selected[_GOOGLE], "google")
            self.google_identity = _google_identity(self.google)
        else:
            need(not self.selected[_GOOGLE], "google")
        from .version_hosted_play_recovery import Capture
        self.recovery = Capture(enabled="android" in self.enabled)
        self.runtime = _runtime_environment(os.environ)
        # No GitHub credential, proxy, Ruby loader injection or ambient CA path.
        self.runtime.pop("SSL_CERT_DIR", None)
        self.runtime["SSL_CERT_FILE"] = str(tooling / "desktop/cpython-source-inputs/github-ca.pem")

    def __repr__(self):
        return "<HostedVersionMaterial private>"

    def check(self):
        from .version_hosted import need
        need(all(os.environ.get(name, "") == value for name, value in self.selected.items()), "store")
        self.recovery.check()

    def context(self, source):
        from .version_hosted import need
        self.check()
        need(source.enabled == self.enabled and (self._source is None or self._source is source), "store")
        if self.platform == "ios":
            # This exact pre-existing digest is part of immutable iOS requests.
            value = {"purpose": "hosted-ios-current-inventory/1", "source": source.binding.value(),
                "appId": source.app_id, "bundleId": source.bundle_id,
                "keyId": self.selected[_KEY], "issuerId": self.selected[_ISSUER]}
        else:
            value = {"purpose": "hosted-" + self.platform + "-current-inventory/1",
                "source": source.binding.value(), "packageName": source.package,
                "google": self.google_identity}
            if self.platform == "both":
                value.update(appId=source.app_id, bundleId=source.bundle_id,
                             keyId=self.selected[_KEY], issuerId=self.selected[_ISSUER])
        digest = policy.digest(value)
        need(self._context is None or self._context == digest, "store")
        self._source, self._context = source, digest
        return digest

    def observe(self, source, context_revision):
        from .version_hosted import need
        need(self.platform == "ios", "store")
        return self.observe_ios(source, context_revision)

    def _environment(self):
        return {**self.runtime, "BUNDLE_GEMFILE": str(self.tooling / "Gemfile"),
            "FASTLANE_HIDE_CHANGELOG": "true", "FASTLANE_OPT_OUT_USAGE": "true",
            "FASTLANE_SKIP_DOCS": "true", "FASTLANE_SKIP_UPDATE_CHECK": "true"}

    def observe_ios(self, source, context_revision):
        from .version_hosted import need
        need("ios" in self.enabled and not self._ios_used and not self._play_used
             and context_revision == self.context(source), "store")
        self.used = self._ios_used = True  # Failed/partial/unknown reads cannot be retried.
        source.remaining()
        # The actual C/A/W timed child receives only this original's remaining
        # work time. Its fixed ordinary 3s cleanup is not a fresh native clock.
        timeout = math.floor(source.end - source.last)
        need(1 <= timeout <= ios.QUERY_SECONDS, "store")
        env = {**self._environment(), **{name: self.selected[name] for name in _IOS}, "SPACESHIP_TIMEOUT": "30",
            "MOBILE_RELEASE_ASC_APP_ID": source.app_id, "MOBILE_RELEASE_ASC_BUNDLE_ID": source.bundle_id,
            "MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT": context_revision}
        with finite_scratch(layout="online-runner", cancellation=source.guard) as runner:
            source.remaining()
            timeout = math.floor(source.end - source.last)
            need(timeout >= 1, "store")
            completed = run_owned(ios.fixed_argv(self.tooling), cwd=runner._path, environ=env,
                capture=True, text=False, output_limit=ios.FRAME_LIMIT, timeout=timeout,
                cancellation=source.guard)
            source.remaining()
            need(type(completed.returncode) is int and completed.returncode == 0
                 and type(completed.stdout) is bytes and 0 < len(completed.stdout) <= ios.FRAME_LIMIT
                 and completed.stderr == b"", "store")
            summary = ios.summary_from_frame(completed.stdout, context_sha256=context_revision,
                app_id=source.app_id, bundle_id=source.bundle_id)
            need(summary["observation"] == "observed", "store")
        source.remaining()  # Real scratch closes/cleanup, not just a Ruby frame.
        need(context_revision == self.context(source), "store")
        self._ios_inventory = ios.CurrentInventory(source.identity, context_revision, summary["revision"],
            source.observed_at, summary["maxBuild"], summary["marketingVersion"],
            tuple(summary["counts"][kind] for kind in ios.COLLECTIONS))
        return self._ios_inventory

    def observe_android(self, source, context_revision, original):
        from .version_hosted import PlayQuery, need
        need("android" in self.enabled and not self._play_used and type(original) is PlayQuery
             and context_revision == self.context(source)
             and (self.platform != "both" or self._ios_inventory is not None), "store")
        self.used = self._play_used = True
        self._play_original = original  # Never reconstructed from a returned summary.
        source.remaining()
        with finite_scratch(layout="store-selection", cancellation=source.guard) as selected:
            self._play_selection = selected
            self._play_snapshot = selected.put("google-adc", self.google)
            path = selected.require(self._play_snapshot)
            with finite_scratch(layout="online-runner", cancellation=source.guard) as runner:
                self._play_runner = runner
                source.remaining()
                need(context_revision == self.context(source), "store")
                # Opt-in retention leaves 8s before the parent's original end,
                # inclusive of the owned child's up-to-3s cleanup tail.
                hard_end = min(source.end - (8 if self.recovery.enabled else 0), source.last + android.QUERY_SECONDS)
                read_end = min(source.last + android.READ_SECONDS, hard_end - 10)
                need(source.last < read_end, "store")
                selected.require(self._play_snapshot)
                env = {**self._environment(), **self.recovery.environment(), _GAC: str(path),
                    "MOBILE_RELEASE_PLAY_PACKAGE": source.package, "MOBILE_RELEASE_PLAY_CONTEXT": context_revision,
                    "MOBILE_RELEASE_PLAY_READ_END_NS": str(math.floor(read_end * 1_000_000_000)),
                    "MOBILE_RELEASE_PLAY_HARD_END_NS": str(math.floor(hard_end * 1_000_000_000))}
                completed = run_owned(android.fixed_argv(self.tooling), cwd=runner._path, environ=env,
                    capture=True, text=False, output_limit=android.FRAME_LIMIT,
                    timeout=math.floor(hard_end - source.last), cancellation=source.guard)
                # Retain the offered private raw return/ID BEFORE a late clock,
                # parser, material check or close can fail. It is not authority.
                self._play_return = completed
                self._retain_play_id(completed.stdout, source.package, context_revision)
                source.remaining()
                need(type(completed.returncode) is int and completed.returncode == 0
                     and type(completed.stdout) is bytes and 0 < len(completed.stdout) <= android.FRAME_LIMIT
                     and completed.stderr == b"", "play-pending")
                summary = android.summary_from_frame(self.recovery.frame(completed, source.package, context_revision),
                    context_sha256=context_revision, package_name=source.package)
                need(android.valid_summary(summary), "play-pending")
                selected.require(self._play_snapshot)
                need(context_revision == self.context(source), "store")
            selected.require(self._play_snapshot)
        source.remaining()
        need(context_revision == self.context(source), "store")
        self._play_cleanup = summary["temporaryEdit"]
        self._play_closed = True  # Only after BOTH actual scratch owners close.
        return summary

    def _retain_play_id(self, raw, package, context):
        try:
            frame = android._json(raw, frame=True)
            effect = frame.get("temporaryEdit")
            if (frame.get("scope") == android.SCOPE and frame.get("contextSha256") == context
                    and frame.get("packageName") == package and type(effect) is dict
                    and effect.get("insertAttempted") is True and type(effect.get("editId")) is str
                    and android._EDIT.fullmatch(effect["editId"]) is not None):
                self._play_edit_id = effect["editId"]  # Private untrusted DATA only.
        except (ValueError, TypeError):
            pass  # Raw remains retained even when no exact ID can be parsed.

    def _consume_play_cleanup(self, source, original):
        from .version_hosted import need
        need(source is self._source and original is self._play_original and self._play_used
             and self._play_closed and not self._play_consumed
             and self._play_cleanup in {"deleted", "not-started"}, "play-pending")
        source.remaining()
        need(self.context(source) == self._context, "store")
        self._play_consumed = True  # A lost clear ACK cannot retry this transition.
