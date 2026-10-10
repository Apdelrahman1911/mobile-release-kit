"""Config-only original filesystem contracts; no network, process or material.

Tests create tiny synthetic projects only in a task-controlled TemporaryDirectory.
No user project discovery, credential read or remote Setup action is performed.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release import github_setup_secret_inputs as inputs
from mobile_release import _github_connection_transport as transport
from mobile_release.api import _snapshot as snapshot


def draft():
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "production"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
        "ios": {"enabled": False},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def budget():
    return transport._Budget(time.monotonic(), _profile=transport._ExchangeProfile.SETUP)


class SecretConfigurationTests(unittest.TestCase):
    def setUp(self):
        holder = tempfile.TemporaryDirectory(prefix="mrk-secret-config-test-")
        self.addCleanup(holder.cleanup)
        self.root = Path(holder.name)
        (self.root / "release").mkdir()
        self.path = self.root / inputs.CONFIGURATION_PATH
        self.data = draft()
        self.raw = (json.dumps(self.data, indent=2) + "\n").encode()
        self.path.write_bytes(self.raw)
        details = self.root.stat()
        encoded = canonical(self.data)
        self.source = {"root": str(self.root), "rootIdentity": {
            "device": str(details.st_dev), "inode": str(details.st_ino), "mode": details.st_mode,
            "uid": details.st_uid, "gid": details.st_gid}, "draft": inputs._digest(encoded),
            "platform": "android", "purpose": "signing", "material": {"encoding": "utf8", "plaintextBytes": 7}}
        self.selection = {"kind": "environment_secret", "mode": "create", "stage": "candidate",
            "requirement": "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD", "source": {
                "recordId": "a" * 32, "recordRevision": 0, "contextRevision": 0}}

    def test_actual_config_originals_canonical_raw_requirement_and_finality(self):
        owner = budget()
        with inputs.observe_secret_configuration(self.source, self.selection, budget=owner) as observed:
            value = observed.value()
            self.assertEqual(value["savedConfig"], inputs._digest(self.raw))
            self.assertEqual(value["canonicalConfig"], self.source["draft"])
            self.assertNotEqual(value["savedConfig"], value["canonicalConfig"])
            self.assertEqual(value["requirement"], {"name": self.selection["requirement"], "kind": "secret", "stage": "candidate", "platform": "android"})
            held = [descriptor for descriptor, _ in observed._reader.held_leaves]
            self.assertEqual(len(held), 1)
            self.assertEqual(os.fstat(held[0]).st_ino, self.path.stat().st_ino)
            value["savedConfig"]["sha256"] = "0" * 64
            self.assertEqual(observed.value()["savedConfig"], inputs._digest(self.raw))
            ledger = observed._budget
        self.assertTrue(ledger.closed)
        self.assertFalse(ledger.handles)
        self.assertEqual(ledger.live, 0)
        for descriptor in held:
            with self.assertRaises(OSError):
                os.fstat(descriptor)
        with self.assertRaises(inputs.SecretConfigurationError):
            observed.value()
        with self.assertRaises(inputs.SecretConfigurationError):
            with inputs.observe_secret_configuration(self.source, self.selection, budget=owner):
                self.fail("same owner credit was renewed")
        self.assertEqual(owner._secret_configuration_claimed, inputs.CONFIGURATION_WORK_BYTES)
        # Informational Unicode URI is never fetched; UTF-8 canonical bytes,
        # not ASCII wire JSON or raw whitespace, bind the native draft.
        self.data["$schema"] = "https://example.invalid/é/🧪.json"
        self.path.write_bytes(json.dumps(self.data, ensure_ascii=True).encode("ascii"))
        self.source["draft"] = inputs._digest(canonical(self.data))
        with inputs.observe_secret_configuration(self.source, self.selection, budget=budget()) as unicode_observed:
            self.assertEqual(unicode_observed.value()["canonicalConfig"], self.source["draft"])

        # The new wrapper reaches the SAME original config loan, rather than
        # constructing a secret source or substituting a DATA configuration.
        selected = {**self.selection, "kind": "environment_variable", "requirement": "MOBILE_RELEASE_ANDROID_KEY_ALIAS"}
        source = {**self.source, "material": inputs._digest(b"release.alias")}
        owner = budget()
        with inputs.observe_variable_configuration(source, selected, budget=owner) as observed:
            value = observed.value(); ledger = observed._budget
            self.assertIs(ledger.owner, owner)
            self.assertEqual(value["requirement"], {"name": selected["requirement"], "kind": "variable", "stage": "candidate", "platform": "android"})
            self.assertEqual(value["savedConfig"], inputs._digest(self.path.read_bytes()))
            self.assertEqual(value["canonicalConfig"], source["draft"])
        self.assertTrue(ledger.closed); self.assertFalse(ledger.handles); self.assertEqual(ledger.live, 0)
        with self.assertRaises(inputs.SecretConfigurationError):
            with inputs.observe_variable_configuration(source, selected, budget=owner): pass  # Same owner cannot renew.
        with self.assertRaises(inputs.SecretConfigurationError):
            with inputs.observe_secret_configuration(source, selected, budget=budget()): pass
        for foreign in ("OPERATION_COMMITMENT_KEY_VERSION", self.selection["requirement"]):
            with self.assertRaises(inputs.SecretConfigurationError):
                with inputs.observe_variable_configuration(source, {**selected, "requirement": foreign}, budget=budget()): pass

        # Actual Setup engine dispatch + actual filesystem configuration + fixed
        # six-step reader. Only private FD/frame ports and HTTP replies are DATA;
        # this is not a native admission, network or child-settlement fixture.
        from types import SimpleNamespace
        from mobile_release import _desktop_github_setup_engine as fixed_engine
        from mobile_release import github_setup_remote as remote
        from mobile_release import github_setup_variable_runtime as variable_runtime
        frames, retired, exchanges = [], [], []
        initial = {"protocol": remote.PROTOCOL, "id": "variable_engine", "action": {"kind": "prepare",
            "target": {"projectBinding": "a" * 64, "repository": "owner/repo", "accountId": "1", "repositoryId": "2", "selection": selected},
            "prepared": None, "source": source}}
        first = canonical(initial) + b"\n"; request = remote.parse_initial(first)
        final = canonical({"protocol": remote.PROTOCOL, "id": request.id,
            "go": {"requestSha256": request.digest, "token": "INERT_TOKEN", "value": "release.alias"}}) + b"\n"
        descriptors = iter((101, 102))
        proxy = SimpleNamespace(path=os.path, devnull=os.devnull, O_RDONLY=os.O_RDONLY,
            dup=lambda fd: next(descriptors), set_inheritable=lambda *_: None, open=lambda *_: 103,
            dup2=lambda *args, **kwargs: None, close=retired.append)
        def exchange_factory(_token, **kwargs):
            self.assertEqual(_token, "INERT_TOKEN")
            self.assertIs(kwargs["_setup_budget"].profile, transport._ExchangeProfile.SETUP)
            def exchange(method, path, body, *, _role):
                transport._request_limits(transport._ExchangeProfile.SETUP, _role, method, path)
                transport._setup_body(transport._ExchangeProfile.SETUP, _role, body, path=path)
                exchanges.append((method, path, _role))
                if path == "/user": data = {"id": 1, "login": "owner"}
                elif path == "/repos/owner/repo":
                    data = {"id": 2, "full_name": "owner/repo", "default_branch": "main", "visibility": "private", "archived": False, "permissions": {"admin": True}}
                elif _role is transport._ResponseRole.SETUP_VARIABLE_READ:
                    return transport.ReadResult({"status": 404, "body": None, "failure": "none"}, transport._control())
                else: data = {"id": 3, "name": "mobile-candidate"}
                return transport.ReadResult({"status": 200, "body": data, "failure": "none"}, transport._control())
            return exchange
        with patch.object(fixed_engine, "os", proxy), patch.object(fixed_engine, "_read_initial", return_value=first), \
             patch.object(fixed_engine, "_read_request", return_value=final), \
             patch.object(fixed_engine, "_write_response", side_effect=lambda fd, raw: frames.append((fd, raw))), \
             patch.object(transport, "_make_live_exchange", side_effect=exchange_factory), \
             patch.object(remote, "_make_secret_reader", side_effect=AssertionError("Variable entered secret path")), \
             patch.object(remote, "_make_live_reader", side_effect=AssertionError("Variable entered old settings path")):
            self.assertEqual(fixed_engine.main(started=time.monotonic(), runtime_dir=str(self.root)), 0)
        self.assertEqual(retired, [103, 102, 101]); self.assertEqual(len(exchanges), 6)
        self.assertTrue(all(row[0] == "GET" for row in exchanges)); self.assertEqual(len(frames), 2)
        self.assertEqual(json.loads(frames[0][1]), json.loads(remote.ready_frame(request)))
        outcome = json.loads(frames[1][1])["result"]
        self.assertEqual((outcome["reason"], outcome["effect"], outcome["writeClaimed"]), ("none", "not-started", False))
        self.assertEqual(outcome["prepared"]["after"]["value"]["text"], "release.alias")
        self.assertNotIn("INERT_TOKEN", frames[1][1].decode())

    def test_closed_source_policy_and_changed_original_refuse(self):
        for node, key, value in [("rootIdentity", "inode", "0"), ("draft", "sha256", "0" * 64),
                                 ("rootIdentity", "uid", True), ("material", "plaintextBytes", 49153)]:
            with self.subTest(node=node, key=key):
                source = copy.deepcopy(self.source)
                source[node][key] = value
                with self.assertRaises(inputs.SecretConfigurationError):
                    with inputs.observe_secret_configuration(source, self.selection, budget=budget()):
                        self.fail("bad source admitted")
        for name in ("MOBILE_RELEASE_ANDROID_KEY_ALIAS", "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH",
                     "MOBILE_RELEASE_IOS_REVIEW_PASSWORD", "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64"):
            selection = copy.deepcopy(self.selection)
            selection["requirement"] = name
            source = copy.deepcopy(self.source)
            if name.endswith("BASE64"):
                source["material"]["encoding"] = "base64"
            with self.subTest(name=name), self.assertRaises(inputs.SecretConfigurationError):
                with inputs.observe_secret_configuration(source, selection, budget=budget()):
                    self.fail("unrequired/variable/unsupported secret admitted")
        project = copy.deepcopy(self.data)
        project["source"]["projectReadTokenRequired"] = True
        self.path.write_bytes(canonical(project))
        source = copy.deepcopy(self.source)
        source["draft"] = inputs._digest(canonical(project))
        source["platform"] = "project"
        selection = copy.deepcopy(self.selection)
        selection["requirement"] = "MOBILE_RELEASE_PROJECT_READ_TOKEN"
        with inputs.observe_secret_configuration(source, selection, budget=budget()) as observed_project:
            self.assertEqual(observed_project.value()["requirement"]["platform"], "project")
        self.path.write_bytes(self.raw)
        with self.assertRaises(inputs.SecretConfigurationError):
            with inputs.observe_secret_configuration(self.source, self.selection, budget=budget()) as observed:
                self.path.write_bytes(self.raw + b" ")
                observed.checkpoint()
        self.path.write_bytes(self.raw)
        with self.assertRaises(inputs.SecretConfigurationError):
            with inputs.observe_secret_configuration(self.source, self.selection, budget=budget()) as observed:
                replacement = self.path.with_name("replacement.json")
                replacement.write_bytes(self.raw)
                os.replace(replacement, self.path)
                observed.checkpoint()

    def test_unsafe_missing_alias_malformed_and_oversize_config_refuse(self):
        self.path.unlink()
        with self.assertRaises(inputs.SecretConfigurationError):
            with inputs.observe_secret_configuration(self.source, self.selection, budget=budget()):
                self.fail("missing")
        self.path.symlink_to("missing.json")
        with self.assertRaises(inputs.SecretConfigurationError):
            with inputs.observe_secret_configuration(self.source, self.selection, budget=budget()):
                self.fail("link")
        self.path.unlink()
        self.path.write_bytes(self.raw)
        alias = self.path.with_name("MOBILE-RELEASE.JSON")
        alias.write_bytes(b"{}")
        with self.assertRaises(inputs.SecretConfigurationError):
            with inputs.observe_secret_configuration(self.source, self.selection, budget=budget()):
                self.fail("portable alias")
        alias.unlink()
        os.link(self.path, alias)
        with self.assertRaises(inputs.SecretConfigurationError):
            with inputs.observe_secret_configuration(self.source, self.selection, budget=budget()):
                self.fail("hardlink")
        alias.unlink()
        for raw in (b"{", b'{"schemaVersion":1,"schemaVersion":1}', b"[" * 29 + b"]" * 29,
                    b" " * (inputs.MAX_CONFIG_BYTES + 1)):
            self.path.write_bytes(raw)
            with self.subTest(length=len(raw)), self.assertRaises(inputs.SecretConfigurationError):
                with inputs.observe_secret_configuration(self.source, self.selection, budget=budget()):
                    self.fail("bad config")

    def test_original_budget_boundaries_deadline_and_close_failure_are_absorbing(self):
        with self.assertRaises(inputs.SecretConfigurationError):
            inputs._SecretConfigurationBudget(object(), str(self.root))
        wrong = transport._Budget(time.monotonic())
        with self.assertRaises(inputs.SecretConfigurationError):
            inputs._SecretConfigurationBudget(wrong, str(self.root))
        for field, maximum, action in (
            ("reads", inputs._MAX_READ_REQUESTS, lambda b: b.read_request(1)),
            ("opens", inputs._MAX_OPENS, lambda b: b._acquire()),
            ("live", inputs._MAX_LIVE, lambda b: b._acquire()),
        ):
            ledger = inputs._SecretConfigurationBudget(budget(), str(self.root))
            setattr(ledger, field, maximum - 1)
            action(ledger)
            with self.assertRaises(inputs.SecretConfigurationError):
                action(ledger)
            setattr(ledger, field, 0)
            with self.assertRaises(inputs.SecretConfigurationError):
                ledger.check()
        for raw in (b"0", b'"escaped \\\" [ text"', b"[" * 28 + b"0" + b"]" * 28):
            inputs._json_prelude(raw, inputs._SecretConfigurationBudget(budget(), str(self.root)))
        for raw in (b"[" * 29 + b"0" + b"]" * 29, b"[" + b"0," * 8000 + b"0]"):
            with self.assertRaises(inputs.SecretConfigurationError):
                inputs._json_prelude(raw, inputs._SecretConfigurationBudget(budget(), str(self.root)))
        inputs._json_prelude(b"[" + b"0," * 7998 + b"0]", inputs._SecretConfigurationBudget(budget(), str(self.root)))
        with self.assertRaises(inputs.SecretConfigurationError) as checkpoint_error:
            with inputs.observe_secret_configuration(self.source, self.selection, budget=budget()) as observed:
                observed._budget.checks = inputs._MAX_CHECKPOINTS - 1
                observed.checkpoint()
                observed.checkpoint()
        self.assertEqual(checkpoint_error.exception.reason, "resources-unavailable")
        self.assertFalse(checkpoint_error.exception.cleanup_unknown)
        self.assertFalse(inputs.SecretConfigurationError("configuration-changed").cleanup_unknown)
        for count, succeeds in ((inputs._MAX_ENTRIES - 1, True), (inputs._MAX_ENTRIES, False)):
            owner_entries = budget()
            ledger = inputs._SecretConfigurationBudget(owner_entries, str(self.root))
            # Empty actual directory still debits its EOF advance.
            empty = self.root / "empty"
            empty.mkdir(exist_ok=True)
            descriptor = ledger.open_fd(str(empty), snapshot._directory_flags())
            ledger.entries_seen = count
            try:
                if succeeds:
                    with ledger.entries(descriptor) as entries:
                        self.assertEqual(list(entries), [])
                else:
                    with self.assertRaises(inputs.SecretConfigurationError):
                        with ledger.entries(descriptor) as entries:
                            list(entries)
            finally:
                ledger.close()
        owner = budget()
        with self.assertRaises(inputs.SecretConfigurationError):
            with inputs.observe_secret_configuration(self.source, self.selection, budget=owner) as observed:
                owner.monotonic = lambda: owner.end
                observed.checkpoint()
        original_close = os.close
        closed = []
        def close_then_fail(descriptor):
            original_close(descriptor)
            closed.append(descriptor)
            if len(closed) == 1:
                raise OSError("inert known close-after-return fault")
        with patch.object(os, "close", close_then_fail):
            with self.assertRaises(inputs.SecretConfigurationError) as close_error:
                with inputs.observe_secret_configuration(self.source, self.selection, budget=budget()) as observed:
                    originals = set(observed._budget.handles)
        self.assertEqual(set(closed), originals)
        self.assertEqual(len(closed), len(originals))
        self.assertTrue(observed._budget.close_unknown)
        self.assertTrue(close_error.exception.cleanup_unknown)
        with self.assertRaises(AttributeError):
            close_error.exception.cleanup_unknown = False
        self.assertTrue(observed._budget.closed)
        self.assertFalse(observed._budget.handles)
        owner = budget()
        def close_then_late(descriptor):
            original_close(descriptor)
            owner.monotonic = lambda: owner.end
        # Every original still closes; late final close cannot grant success.
        with patch.object(os, "close", close_then_late), self.assertRaises(inputs.SecretConfigurationError) as late_error:
            with inputs.observe_secret_configuration(self.source, self.selection, budget=owner):
                pass

        self.assertFalse(late_error.exception.cleanup_unknown)
        # A remaining original debit is also unknown, even without a close flag.
        with self.assertRaises(inputs.SecretConfigurationError) as remaining_error:
            with inputs.observe_secret_configuration(self.source, self.selection, budget=budget()) as observed:
                observed._budget.live += 1
        self.assertFalse(observed._budget.close_unknown)
        self.assertFalse(observed._budget.handles)
        self.assertTrue(remaining_error.exception.cleanup_unknown)

        # Keep an earlier resource refusal even if an independent close fails.
        self.path.write_bytes(b"[" + b"0," * 8000 + b"0]")
        closed.clear()
        with patch.object(os, "close", close_then_fail), self.assertRaises(inputs.SecretConfigurationError) as first_error:
            with inputs.observe_secret_configuration(self.source, self.selection, budget=budget()):
                self.fail("oversized token graph admitted")
        self.assertEqual(first_error.exception.reason, "resources-unavailable")
        self.assertTrue(first_error.exception.cleanup_unknown)
        self.assertEqual(len(set(closed)), len(closed))

        self.path.write_bytes(self.raw)
        selected = {**self.selection, "kind": "environment_variable", "requirement": "MOBILE_RELEASE_ANDROID_KEY_ALIAS"}
        source = {**self.source, "material": inputs._digest(b"release.alias")}
        closed.clear()
        with patch.object(os, "close", close_then_fail), self.assertRaises(inputs.SecretConfigurationError) as variable_close:
            with inputs.observe_variable_configuration(source, selected, budget=budget()) as observed:
                originals = set(observed._budget.handles)
                raise inputs.SecretConfigurationError("material-changed")
        self.assertEqual(variable_close.exception.reason, "material-changed")
        self.assertTrue(variable_close.exception.cleanup_unknown)
        self.assertEqual(set(closed), originals); self.assertEqual(len(closed), len(originals))
        self.assertFalse(observed._budget.handles)
        with self.assertRaises(inputs.SecretConfigurationError) as changed:
            with inputs.observe_variable_configuration(source, selected, budget=budget()) as observed:
                replacement = self.path.with_name("variable-replacement.json")
                replacement.write_bytes(self.raw); os.replace(replacement, self.path)
                observed.checkpoint()
        self.assertEqual(changed.exception.reason, "configuration-changed")
        self.assertFalse(changed.exception.cleanup_unknown)
