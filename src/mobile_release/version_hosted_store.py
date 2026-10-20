"""One selected protected-workflow P8 read on the existing owned-process path.

No credential discovery, keyfile, native receipt, HTTP implementation, Fastfile
or uploader. Ruby's existing exact raw reader remains the sole ASC caller.
"""
from __future__ import annotations

import base64
import math
import os
import re

from . import ios_store_versions as ios
from . import version_policy as policy
from .build_inputs import finite_scratch
from .owned_process import run_owned
from .stores import _runtime_environment

_KEY = "MOBILE_RELEASE_ASC_KEY_ID"
_ISSUER = "MOBILE_RELEASE_ASC_ISSUER_ID"
_P8 = "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"


class Material:
    def __init__(self, tooling):
        from .version_hosted import need
        self.tooling = tooling
        self.used = False
        self.selected = {name: os.environ.get(name, "") for name in (_KEY, _ISSUER, _P8)}
        need(re.fullmatch(r"[A-Z0-9]{10}", self.selected[_KEY]) is not None
             and re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", self.selected[_ISSUER]) is not None,
             "store")
        encoded = self.selected[_P8]
        need(encoded.isascii() and 0 < len(encoded) <= 4 * ((16 * 1024 + 2) // 3), "store")
        try:
            self.private = base64.b64decode(encoded, validate=True)
        except ValueError:
            need(False, "store")
        need(0 < len(self.private) <= 16 * 1024 and base64.b64encode(self.private).decode("ascii") == encoded, "store")
        self.runtime = _runtime_environment(os.environ)
        # No GitHub credential, proxy, Ruby loader injection or ambient CA path.
        self.runtime.pop("SSL_CERT_DIR", None)
        self.runtime["SSL_CERT_FILE"] = str(tooling / "desktop/cpython-source-inputs/github-ca.pem")

    def __repr__(self):
        return "<HostedVersionMaterial private>"

    def check(self):
        from .version_hosted import need
        need(all(os.environ.get(name, "") == value for name, value in self.selected.items()), "store")

    def context(self, source):
        self.check()
        return policy.digest({"purpose": "hosted-ios-current-inventory/1", "source": source.binding.value(),
            "appId": source.app_id, "bundleId": source.bundle_id,
            "keyId": self.selected[_KEY], "issuerId": self.selected[_ISSUER]})

    def observe(self, source, context_revision):
        from .version_hosted import need
        need(not self.used and context_revision == self.context(source), "store")
        self.used = True  # Failed/partial/unknown reads cannot be retried.
        source.remaining()
        # The actual C/A/W timed child receives only this original's remaining
        # work time. Its fixed ordinary 3s cleanup is not a fresh native clock.
        timeout = math.floor(source.end - source.last)
        need(1 <= timeout <= ios.QUERY_SECONDS, "store")
        env = {**self.runtime, **self.selected, "BUNDLE_GEMFILE": str(self.tooling / "Gemfile"),
            "SPACESHIP_TIMEOUT": "30", "FASTLANE_HIDE_CHANGELOG": "true", "FASTLANE_OPT_OUT_USAGE": "true",
            "FASTLANE_SKIP_DOCS": "true", "FASTLANE_SKIP_UPDATE_CHECK": "true",
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
        return ios.CurrentInventory(source.identity, context_revision, summary["revision"],
            source.observed_at, summary["maxBuild"], summary["marketingVersion"],
            tuple(summary["counts"][kind] for kind in ios.COLLECTIONS))
