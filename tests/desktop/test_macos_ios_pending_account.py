"""Bounded DATA regressions only; no core/native import, child or account action.

The literal native producer is inspected as SOURCE and is never executed here.
Synthetic reports below cannot provide runtime/native qualification evidence.
"""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import stat
from subprocess import CompletedProcess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).absolute().parents[2]
PATH = ROOT / "desktop/tools/macos_aqua_qualification.py"
SPEC = importlib.util.spec_from_file_location("_mrk_pending_account_data", PATH)
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)
UID, GID = 501, 20
BINDING = M.Binding("a" * 40, "123", "1")


def private_data():
    home = "/Users/runner"
    return {"home": home, "homeIdentity": [7, 1, stat.S_IFDIR | 0o700, UID, GID],
            "leaseIdentity": [7, 2, stat.S_IFDIR | 0o700, UID, GID],
            "sessionIdentity": [7, 3, stat.S_IFDIR | 0o700, UID, GID],
            "nativeIdentity": [7, 4, stat.S_IFDIR | 0o700, UID, GID], "token": "e" * 32,
            "baseline": {"default": home + "/Library/Keychains/login.keychain-db", "search": [home + "/Library/Keychains/login.keychain-db"]},
            "members": [{"path": home + "/Library/Keychains/login.keychain-db", "identity": [7, 5, stat.S_IFREG | 0o600, UID, GID, 1]}],
            "controls": {name: {"bytes": 2, "sha256": M.digest(b"{}")} for name in ("intent.json", "state.json")},
            "native": {"signing.keychain-db": {"device": 7, "inode": 6}}}


def child_data(mode):
    result = {"schemaVersion": 1, "scope": "real-core-pending-account-fixture-v1" if mode == "produce" else "real-core-account-baseline-readback-v1",
              "case": M.IOS_ACCOUNT_CASE, "commands": 17 if mode == "produce" else 2, "profileCalls": 0,
              "commandFinalities": True, "leaseClosed": True, "sessionClosed": True, "handlersRestored": True,
              "fixtureDescriptorsClosed": True, "originalDeadlineMet": True, "keychainContentsRead": False}
    if mode == "produce":
        result.update(pendingLeft=True, private=private_data())
    else:
        result.update(pendingAbsent=True, baselinePreferencesMatched=True, baselineMemberIdentitiesMatched=True)
    return result


def returned(argv, mode, value=None):
    return CompletedProcess(argv, 0, json.dumps(child_data(mode) if value is None else value, separators=(",", ":")).encode() + b"\n", b"")


class InertAccountFixtures:
    def __init__(self):
        self.cases = (M.IOS_ACCOUNT_CASE,)
        self.path = BINDING.root()
        self.inflight = self.last_returned = False
        self.account_produced = self.account_app_returned = self.account_readback = False
        self.account_attempts = {"produce": False, "observe": False}
        self.account_private_sha = "f" * 64
        self.account_home = "/Users/runner"
        self.events = []

    def recovery_runtime_paths(self):
        if self.inflight:
            raise AssertionError("runtime read during unknown invocation")
        return "/inert-installed/python3", "/inert-installed/core.zip"

    def accept_account_producer(self, value):
        if self.inflight or not self.last_returned:
            raise AssertionError("producer did not return")
        self.events.append("producer-accepted")
        self.account_produced = True

    def _account_current(self, *, after):
        if self.inflight:
            raise AssertionError("readback during unknown invocation")
        self.events.append("after-readback" if after else "before-readback")


def normal_observation(binding=BINDING):
    return dict(schemaVersion=1, sourceCommit=binding.source, target=binding.target, runId=binding.run,
        runAttempt=binding.attempt, fixtureSha256=M.digest(str(binding.root() / M.IOS_ACCOUNT_CASE).encode()),
        sessionSha256=M.digest(private_data()["token"].encode()), inspectUnchecked=True, recoverUnchecked=True, ordinaryQuit=True,
        inspect=dict(operationId="1" * 32, ownerGeneration="2" * 32, phase="terminal", outcome="complete", reason="none", accountStatus="pending"),
        recover=dict(operationId="3" * 32, ownerGeneration="4" * 32, phase="terminal", outcome="complete", reason="none", accountStatus="recovered"))


class PendingAccountRecoveryDataTests(unittest.TestCase):
    def test_normal_observation_is_current_bound_and_distinct_from_debug_protocol(self):
        for target in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
            binding = M.Binding(BINDING.source, BINDING.run, BINDING.attempt, target)
            value = normal_observation(binding)
            self.assertIs(M.normal_account_observation(value, binding), value)
            with self.assertRaises(M.Refused): M._ios_pending_report(value)
            with self.assertRaises(M.Refused): M.normal_account_observation(M._expected_ios_pending_report(), binding)
            for key, changed in (("schemaVersion", True), ("sourceCommit", "b" * 40), ("target", "other"),
                    ("runId", "124"), ("runAttempt", "2"), ("fixtureSha256", "f" * 64),
                    ("sessionSha256", "private-token"), ("inspectUnchecked", False), ("recoverUnchecked", 1),
                    ("ordinaryQuit", False), ("allWorkerFinality", True)):
                bad = deepcopy(value); bad[key] = changed
                with self.subTest(field=key), self.assertRaises(M.Refused): M.normal_account_observation(bad, binding)
            for side in ("inspect", "recover"):
                for key, changed in (("operationId", "nothex"), ("ownerGeneration", "nothex"), ("phase", "unknown"),
                                     ("outcome", "failed"), ("reason", "busy"), ("accountStatus", "absent"), ("lifetime", {})):
                    bad = deepcopy(value); bad[side][key] = changed
                    with self.subTest(side=side, field=key), self.assertRaises(M.Refused): M.normal_account_observation(bad, binding)
            for key in ("operationId", "ownerGeneration"):
                bad = deepcopy(value); bad["recover"][key] = bad["inspect"][key]
                with self.assertRaises(M.Refused): M.normal_account_observation(bad, binding)

    def test_normal_acceptance_requires_same_original_runner_post_and_native_readback(self):
        def fixture():
            f = M.Fixtures(BINDING, UID, GID, M.IOS_ACCOUNT_CASE)
            f.last_returned = f.account_produced = True
            f.account_private = private_data()
            f.normal_account_original = CompletedProcess(["inert-original"], 0, b"observed", b"")
            return f
        observation = normal_observation(BINDING)
        proof = dict(originalProductsPrePostMatched=True, originalClosesCompleted=True,
                     strictCodesignOriginalZero=True, reSignedOrRepaired=False)
        for fault in (None, "inflight", "not-returned", "no-producer", "already-accepted", "different-original", "nonzero",
                      "bool-return", "token", "native-post", *proof):
            f = fixture(); original = f.normal_account_original; receipt = dict(proof)
            if fault == "inflight": f.inflight = True
            if fault == "not-returned": f.last_returned = False
            if fault == "no-producer": f.account_produced = False
            if fault == "already-accepted": f.account_app_returned = True
            if fault == "different-original": original = CompletedProcess(original.args, 0, original.stdout, b"")
            if fault == "nonzero": original.returncode = 1
            if fault == "bool-return": original.returncode = False
            if fault == "token": f.account_private["token"] = "f" * 32
            if fault in proof: receipt[fault] = not proof[fault]
            with patch.object(f, "_account_current", side_effect=M.Refused("inert-native-post") if fault == "native-post" else None) as post:
                if fault is not None:
                    with self.subTest(fault=fault), self.assertRaises(M.Refused): f.accept_normal_account_app(observation, original, receipt)
                    self.assertIsNone(f.normal_account_observation_sha)
                    if fault != "already-accepted": self.assertFalse(f.account_app_returned)
                    if fault != "native-post": post.assert_not_called()
                else:
                    f.accept_normal_account_app(observation, original, receipt)
                    post.assert_called_once_with(after=True)
                    self.assertTrue(f.account_app_returned); self.assertIsNotNone(f.normal_account_observation_sha)
                    with self.assertRaises(M.Refused): f.accept_normal_account_app(observation, original, receipt)
                    with self.assertRaises(M.Refused): f.readback_normal_account(observation)
                    f.account_readback = True
                    f.account_producer_attestation = {k: v for k, v in child_data("produce").items() if k != "private"}
                    f.account_readback_attestation = child_data("observe")
                    f.account_baseline_files = [object()]
                    with patch.object(f, "readback", return_value={"syntheticProjectComparison": True}) as project:
                        checked = f.readback_normal_account(deepcopy(observation))
                        project.assert_called_once_with(M.IOS_ACCOUNT_CASE)
                        self.assertEqual(checked["producer"], f.account_producer_attestation)
                        self.assertEqual(checked["nativeReadback"], child_data("observe"))
                        self.assertEqual(checked["nativeBaselineMembers"], 1)
                        self.assertNotIn("private", checked["producer"])
                        self.assertNotIn(private_data()["token"], json.dumps(checked))
                        for changed in (dict(observation, sessionSha256="f" * 64), dict(observation, recoverUnchecked=False)):
                            with self.assertRaises(M.Refused): f.readback_normal_account(changed)
                    with patch.object(f, "readback", side_effect=M.Refused("inert-project-post")):
                        with self.assertRaisesRegex(M.Refused, "inert-project-post"): f.readback_normal_account(observation)
                    post.side_effect = M.Refused("inert-native-post")
                    with self.assertRaisesRegex(M.Refused, "inert-native-post"): f.readback_normal_account(observation)

    def test_runtime_retained_collect_reads_real_original_without_changing_digest_only_mode(self):
        # Actual tiny filesystem/FD lifecycle, no native/account operation.
        import os
        import tempfile
        body = b'{"manifest":"actual retained bytes"}\n'
        for retain, collect in ((False, False), (True, False), (True, True)):
            with self.subTest(retain=retain, collect=collect), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "manifest.json"; path.write_bytes(body); path.chmod(0o600)
                f = M.Fixtures(BINDING, os.getuid(), os.getgid(), M.IOS_ACCOUNT_CASE)
                try:
                    before, digest, contents = f._recovery_read(None, str(path), os.getuid(), 1024, 0o600,
                                                              retain=retain, collect=collect)
                    self.assertEqual(digest, M.digest(body)); self.assertEqual(before[6], len(body))
                    self.assertEqual(contents, body if collect or not retain else b"")
                    self.assertEqual(len(f.recovery_runtime_originals), int(retain))
                    if retain:
                        parent, name, fd, identity = f.recovery_runtime_originals[0]
                        self.assertIsNone(parent); self.assertEqual(name, str(path)); self.assertEqual(identity, before)
                        self.assertEqual(M.signature(os.fstat(fd)), before); self.assertIn(fd, f.fds)
                    else: self.assertFalse(f.fds)
                finally: f.close()
                self.assertFalse(f.fds)
                if retain:
                    with self.assertRaises(OSError): os.fstat(fd)
                self.assertEqual(path.read_bytes(), body)
        for options in ({"collect": True, "limit": 1024*1024+1}, {"collect": 1, "limit": 1024}, {"retain": 1, "limit": 1024}):
            f = M.Fixtures(BINDING, os.getuid(), os.getgid(), M.IOS_ACCOUNT_CASE)
            with patch.object(f, "_open", side_effect=AssertionError("must refuse before opening")) as opened:
                with self.assertRaises(M.Refused): f._recovery_read(None, "/inert", os.getuid(), **options)
                opened.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"; path.write_bytes(body); path.chmod(0o600)
            f = M.Fixtures(BINDING, os.getuid(), os.getgid(), M.IOS_ACCOUNT_CASE)
            read = os.read; changed = []
            def original_read(fd, limit):
                value = read(fd, limit)
                if not changed:
                    changed.append(fd); path.write_bytes(body + b"changed")
                return value
            try:
                with patch.object(M.os, "read", side_effect=original_read), self.assertRaises(M.Refused):
                    f._recovery_read(None, str(path), os.getuid(), 1024, 0o600, retain=True, collect=True)
                self.assertFalse(f.recovery_runtime_originals); self.assertTrue(f.fds)
            finally: f.close()
            self.assertFalse(f.fds)

    def test_pair_matches_closed_dynamic_originals_and_every_finality_is_required(self):
        value = M._expected_ios_pending_report()
        for i, (operation, generation) in enumerate((("1" * 32, "2" * 32), ("3" * 32, "4" * 32))):
            value["prepared"][i].update(operationId=operation, ownerGeneration=generation)
            value["prepared"][i]["context"]["projectId"] = "current-project"
            value["originals"][i]["facts"].update(operationId=operation, ownerGeneration=generation)
            value["originals"][i]["terminal"]["report"]["account"]["session"] = "9" * 32
        value["prepared"][1]["context"]["recovery"]["session"] = "9" * 32
        value["statusCallsReturned"] = 12
        self.assertEqual(M._ios_pending_report(value), value)
        for i in range(2):
            facts = value["originals"][i]["facts"]
            for field, entry in facts.items():
                if type(entry) is bool:
                    bad = deepcopy(value); bad["originals"][i]["facts"][field] = not entry
                    with self.subTest(original=i, field=field), self.assertRaises(M.Refused):
                        M._ios_pending_report(bad)
            for field in ("complete", "contained", "handlersRestored", "inputClosed", "invocationClosed", "snapshotClosed",
                          "filesClosed", "namespaceClosed", "signingClosed", "buildInputsClosed", "materialRetired"):
                bad = deepcopy(value); bad["originals"][i]["terminal"]["lifetime"][field] = False
                with self.subTest(original=i, field=field), self.assertRaises(M.Refused):
                    M._ios_pending_report(bad)

    def test_pair_refuses_reused_session_order_consent_and_changed_budget(self):
        mutations = (
            lambda v: v["originals"].reverse(),
            lambda v: v["prepared"][1].update(operationId=v["prepared"][0]["operationId"]),
            lambda v: v["prepared"][1].update(ownerGeneration=v["prepared"][0]["ownerGeneration"]),
            lambda v: v["originals"][1]["terminal"]["report"]["account"].update(session="f" * 32),
            lambda v: v["originals"][0]["terminal"]["report"]["account"].update(next="manual"),
            lambda v: v["originals"][1]["terminal"]["lifetime"].update(commands=0),
            lambda v: v["originals"][1]["terminal"]["lifetime"].update(commands=33),
            lambda v: v["originals"][1]["terminal"]["lifetime"].update(profileCalls=1),
            lambda v: v.update(freshUncheckedReviews=False), lambda v: v.update(explicitAcknowledgements=False),
            lambda v: v.update(observationMs=515001), lambda v: v.update(outerInvocationMs=525001),
            lambda v: v.update(requests=[1, 1, 1, 2]), lambda v: v.update(statusCallsReturned=True),
            lambda v: v.update(shippingBinaryQualified=True), lambda v: v.update(extra=True),
        )
        for mutation in mutations:
            value = M._expected_ios_pending_report(); mutation(value)
            with self.subTest(mutation=mutations.index(mutation)), self.assertRaises(M.Refused):
                M._ios_pending_report(value)

    def test_private_baseline_is_finite_same_account_and_never_keychain_contents(self):
        original = private_data()
        self.assertEqual(M._ios_account_private(original, UID, "/Users/runner"), original)
        mutations = (
            lambda v: v.update(home="/Users/another"), lambda v: v.update(token="foreign"),
            lambda v: v["homeIdentity"].__setitem__(3, 0), lambda v: v["leaseIdentity"].__setitem__(2, stat.S_IFDIR | 0o775),
            lambda v: v["baseline"].update(search=[]), lambda v: v["baseline"].update(search=v["baseline"]["search"] * 9),
            lambda v: v["baseline"].update(default="/Users/runner/foreign"),
            lambda v: v["members"][0].update(path="/Users/another/Library/Keychains/login.keychain-db"),
            lambda v: v["members"][0]["identity"].__setitem__(2, stat.S_IFLNK | 0o600),
            lambda v: v["members"][0]["identity"].__setitem__(5, 2),
            lambda v: v["native"]["signing.keychain-db"].update(inode=5),
            lambda v: v["controls"]["state.json"].update(bytes=512*1024+1),
            lambda v: v.update(keychainContents="must-never-be-accepted"),
        )
        for mutation in mutations:
            value = deepcopy(original); mutation(value)
            with self.subTest(mutation=mutations.index(mutation)), self.assertRaises(M.Refused):
                M._ios_account_private(value, UID, "/Users/runner")
        value = deepcopy(original); raw = "/Users/runner/Library/Keychains/../foreign"
        value["baseline"] = {"default": raw, "search": [raw]}; value["members"][0]["path"] = raw
        with self.assertRaises(M.Refused): M._ios_account_private(value, UID, "/Users/runner")

        # Real outer adoption, including its native role routing, original FD
        # registry, private hashes and rosters. Every OS operation is inert.
        private = private_data()
        private["native"][M.IOS_ACCOUNT_LOCK_NAME] = {"device": 7, "inode": 7}
        fixture = M.Fixtures(BINDING, UID, GID, M.IOS_ACCOUNT_CASE)
        fixture.account_home = private["home"]; fixture.last_returned = True
        home = Path(private["home"]); lease = home / ".mobile-release-signing"
        session = lease / ("session-" + private["token"]); native = session / "keychain"
        state = Path("/inert-account-state")
        entries = {}
        for path, identity in ((Path("/"), [7, 20, stat.S_IFDIR | 0o755, 0, 0]),
                (Path("/Users"), [7, 21, stat.S_IFDIR | 0o755, 0, 0]),
                (home, private["homeIdentity"]), (lease, private["leaseIdentity"]),
                (session, private["sessionIdentity"]), (native, private["nativeIdentity"]),
                (home / "Library", [7, 22, stat.S_IFDIR | 0o700, UID, GID]),
                (home / "Library/Keychains", [7, 23, stat.S_IFDIR | 0o700, UID, GID]),
                (state, [7, 24, stat.S_IFDIR | 0o700, UID, GID])):
            entries[path] = (tuple(identity) + (2, 0, 100, 100), None)
        for path, inode, mode, body in ((Path(private["members"][0]["path"]), 5, 0o600, b"baseline"),
                (native / "signing.keychain-db", 6, 0o600, b"inert native DB"),
                (native / M.IOS_ACCOUNT_LOCK_NAME, 7, 0o400, b""),
                (session / "intent.json", 8, 0o600, b"{}"), (session / "state.json", 9, 0o600, b"{}")):
            entries[path] = ((7, inode, stat.S_IFREG | mode, UID, GID, 1, len(body), 100, 100), body)
        handles = {90: state}; next_fd = [100]
        fixture.states[M.IOS_ACCOUNT_CASE] = 90; fixture.fds.add(90)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        def info(path): return SimpleNamespace(**dict(zip(fields, entries[path][0])))
        def route(name, parent): return Path(name) if parent is None else handles[parent] / name
        def opening(name, flags, mode=0o600, *, dir_fd=None):
            path = route(name, dir_fd)
            self.assertEqual(flags & (M.os.O_NOFOLLOW | M.os.O_NONBLOCK | M.os.O_CLOEXEC),
                             M.os.O_NOFOLLOW | M.os.O_NONBLOCK | M.os.O_CLOEXEC)
            if flags & M.os.O_CREAT:
                self.assertEqual(path, state / "account-baseline.json")
                self.assertTrue(flags & M.os.O_EXCL); self.assertNotIn(path, entries); self.assertEqual(mode, 0o600)
                entries[path] = ((7, 25, stat.S_IFREG | 0o600, UID, GID, 1, 0, 100, 100), b"")
            self.assertIn(path, entries)
            if flags & M.os.O_DIRECTORY: self.assertTrue(stat.S_ISDIR(entries[path][0][2]))
            next_fd[0] += 1; handles[next_fd[0]] = path; return next_fd[0]
        def named(name, *, dir_fd, follow_symlinks):
            self.assertIs(follow_symlinks, False); return info(route(name, dir_fd))
        def writing(fd, body):
            path = handles[fd]; self.assertEqual(path, state / "account-baseline.json")
            row, old = entries[path]; body = old + body
            entries[path] = (row[:6] + (len(body),) + row[7:], body); return len(body) - len(old)
        def reading(fd, size, offset):
            path = handles[fd]
            self.assertIn(path.name, ("intent.json", "state.json", "account-baseline.json"))
            return entries[path][1][offset:offset + size]
        class Listing:
            def __init__(self, fd):
                self.rows = iter(SimpleNamespace(name=path.name) for path in entries if path != handles[fd] and path.parent == handles[fd])
            def __iter__(self): return self
            def __next__(self): return next(self.rows)
            def close(self): pass
        with patch.object(M.os, "open", side_effect=opening), patch.object(M.os, "fstat", side_effect=lambda fd: info(handles[fd])), \
                patch.object(M.os, "stat", side_effect=named), patch.object(M.os, "get_inheritable", return_value=False), \
                patch.object(M.os, "write", side_effect=writing), patch.object(M.os, "pread", side_effect=reading), \
                patch.object(M.os, "scandir", side_effect=Listing), patch.object(M.os, "close", side_effect=lambda fd: handles.pop(fd)):
            try:
                fixture.accept_account_producer({**child_data("produce"), "private": private})
                self.assertTrue(fixture.account_produced)
                self.assertEqual({row[1] for row in fixture.account_native_files}, {"signing.keychain-db", M.IOS_ACCOUNT_LOCK_NAME})
                self.assertTrue(all(len(row) == 5 for row in fixture.account_native_files))
                self.assertEqual(entries[state / "account-baseline.json"][0][2], stat.S_IFREG | 0o600)
                control = session / "state.json"; original_control = entries[control]
                entries[control] = (original_control[0], b"[]")  # Same metadata cannot replace the private hash.
                with self.assertRaises(M.Refused): fixture._account_current(after=False)
                entries[control] = original_control
                database = native / "signing.keychain-db"; row, body = entries[database]
                entries[database] = (row[:6] + (len(body) + 1, 101, 101), body + b"x")
                fixture._account_current(after=False)  # Native DB content/timestamps are not a private-control hash.
            finally:
                fixture.close()
        self.assertEqual(handles, {}); self.assertEqual(fixture.account_fds, set()); self.assertEqual(fixture.fds, set())

    def test_private_receipt_refuses_incomplete_ambiguous_or_unbounded_returns(self):
        for mode in ("produce", "observe"):
            good = returned([], mode)
            self.assertEqual(M._ios_account_child_result(good, mode, UID, "/Users/runner"), child_data(mode))
            for result in (CompletedProcess([], 1, good.stdout, b""), CompletedProcess([], 0, good.stdout, b"error"),
                           CompletedProcess([], 0, good.stdout + good.stdout, b""), CompletedProcess([], 0, b"{}" * 9000 + b"\n", b""),
                           CompletedProcess([], 0, b'{"x":1,"x":2}\n', b""), CompletedProcess([], 0, b"{\n", b"")):
                with self.assertRaises(M.Refused): M._ios_account_child_result(result, mode, UID, "/Users/runner")
            for field in ("commandFinalities", "leaseClosed", "sessionClosed", "handlersRestored", "fixtureDescriptorsClosed", "originalDeadlineMet"):
                value = child_data(mode); value[field] = False
                with self.assertRaises(M.Refused): M._ios_account_child_result(returned([], mode, value), mode, UID, "/Users/runner")

    def test_original_child_clocks_clean_environment_and_one_use_calls(self):
        fixture = InertAccountFixtures(); calls = []
        fixture.precursor_diagnostic = {"stale": "must-not-survive"}
        def owner(argv, **options):
            mode = argv[7]; calls.append(mode)
            self.assertEqual(argv[1:5], ["-I", "-S", "-B", "-c"])
            self.assertEqual(argv[5], M.IOS_ACCOUNT_CORE_PROGRAM)
            self.assertEqual(options["timeout"], 180 if mode == "produce" else 90)
            self.assertEqual(options["output_limit"], 16*1024 if mode == "produce" else 2048)
            self.assertNotIn("HOME", options["environ"])
            self.assertEqual(set(options["environ"]), {"TMPDIR", "PATH", "LANG", "LC_ALL", "TZ", "USER", "LOGNAME", "__CF_USER_TEXT_ENCODING"})
            self.assertEqual(int(argv[9]), 1_000_000_000 + (150 if mode == "produce" else 60)*1_000_000_000)
            self.assertEqual(int(argv[10]) - int(argv[9]), 25_000_000_000)
            self.assertTrue(fixture.inflight)
            return returned(argv, mode)
        with patch("time.monotonic_ns", side_effect=[1_000_000_000, 2_000_000_000, 3_000_000_000]):
            M._run_ios_account_child(fixture, owner, UID, "runner", "produce")
        self.assertFalse(fixture.inflight); self.assertTrue(fixture.last_returned)
        self.assertIsNone(fixture.precursor_diagnostic)
        with self.assertRaises(M.Refused): M._run_ios_account_child(fixture, owner, UID, "runner", "produce")
        with self.assertRaises(M.Refused): M._run_ios_account_child(fixture, owner, UID, "runner", "observe")
        fixture.account_app_returned = True
        with patch("time.monotonic_ns", side_effect=[1_000_000_000, 2_000_000_000, 3_000_000_000]):
            M._run_ios_account_child(fixture, owner, UID, "runner", "observe")
        self.assertEqual(calls, ["produce", "observe"])
        self.assertTrue(fixture.account_readback)
        self.assertIsNone(fixture.precursor_diagnostic)
        with self.assertRaises(M.Refused): M._run_ios_account_child(fixture, owner, UID, "runner", "observe")

    def test_unknown_or_late_original_return_never_enters_app_or_readback(self):
        error = RuntimeError("inert lost original return")
        def lost(*args, **kwargs): raise error
        def foreign(argv, **kwargs): return returned(["foreign"], "produce")
        for owner in (lost, foreign):
            fixture = InertAccountFixtures()
            with patch("time.monotonic_ns", return_value=1_000_000_000), \
                    patch.object(M, "_precursor_diagnostic", side_effect=AssertionError("no unknown capture")) as reduced:
                with self.assertRaises((RuntimeError, M.Refused)) as raised:
                    M._run_ios_account_child(fixture, owner, UID, "runner", "produce")
            reduced.assert_not_called(); self.assertIsNone(fixture.precursor_diagnostic)
            if owner is lost: self.assertIs(raised.exception, error)
            self.assertTrue(fixture.inflight); self.assertFalse(fixture.last_returned)
            self.assertFalse(fixture.account_produced); self.assertEqual(fixture.events, [])
            with self.assertRaises(M.Refused): M._run_ios_account_child(fixture, owner, UID, "runner", "observe")
        fixture = InertAccountFixtures()
        with patch("time.monotonic_ns", side_effect=[1_000_000_000, 176_000_000_000]), \
                patch.object(M, "_precursor_diagnostic", side_effect=AssertionError("no late capture")) as reduced:
            with self.assertRaises(M.Refused):
                M._run_ios_account_child(fixture, lambda argv, **kw: returned(argv, "produce"), UID, "runner", "produce")
        self.assertFalse(fixture.inflight); self.assertTrue(fixture.last_returned)
        self.assertFalse(fixture.account_produced); self.assertTrue(fixture.account_attempts["produce"])
        reduced.assert_not_called(); self.assertIsNone(fixture.precursor_diagnostic)
        self.assertEqual(fixture.events, [])

    def test_returned_precursor_failure_keeps_role_private_data_and_adoption_separate(self):
        for mode in ("produce", "observe"):
            fixture = InertAccountFixtures(); calls = []
            fixture.account_produced = fixture.account_app_returned = mode == "observe"
            private = b"PRIVATE_BASELINE_ACCOUNT_CANARY\n"
            def owner(argv, **options):
                calls.append(argv)
                return CompletedProcess(argv, 1, private, b"PRIVATE_NATIVE_ERROR_CANARY")
            with patch("time.monotonic_ns", side_effect=[1_000_000_000, 2_000_000_000]) as clock:
                with self.assertRaisesRegex(M.Refused, "ios-account-child-failed"):
                    M._run_ios_account_child(fixture, owner, UID, "runner", mode)
            value = fixture.precursor_diagnostic
            self.assertEqual(value["kind"], "ios-account-" + mode)
            self.assertEqual(value["returncode"], 1); self.assertEqual(value["stdoutBytes"], len(private))
            self.assertNotIn("PRIVATE_", json.dumps(value)); self.assertNotIn("childFailure", value)
            self.assertEqual(clock.call_count, 2); self.assertEqual(len(calls), 1)
            self.assertFalse(fixture.inflight); self.assertTrue(fixture.last_returned)
            self.assertFalse(fixture.account_readback)
            self.assertEqual(fixture.account_produced, mode == "observe")
            self.assertEqual(fixture.events, ["after-readback"] if mode == "observe" else [])

    def test_diagnostic_fault_preserves_identical_parser_error_and_original_deadline(self):
        for mode in ("produce", "observe"):
            fixture = InertAccountFixtures(); calls = []
            fixture.account_produced = fixture.account_app_returned = mode == "observe"
            original = M.Refused("ios-account-child-failed")
            def owner(argv, **options):
                calls.append(argv)
                return CompletedProcess(argv, 1, b"", b"private-original-canary")
            with patch("time.monotonic_ns", side_effect=[1_000_000_000, 2_000_000_000]) as clock, \
                    patch.object(M, "_ios_account_child_result", side_effect=original), \
                    patch.object(M, "_precursor_diagnostic", side_effect=RuntimeError("private-reducer-canary")) as reduced:
                with self.assertRaises(M.Refused) as raised:
                    M._run_ios_account_child(fixture, owner, UID, "runner", mode)
            self.assertIs(raised.exception, original); reduced.assert_called_once()
            self.assertEqual(clock.call_count, 2); self.assertEqual(len(calls), 1)
            self.assertIsNone(fixture.precursor_diagnostic)
            self.assertFalse(fixture.inflight); self.assertTrue(fixture.last_returned)
            self.assertFalse(fixture.account_readback)
            self.assertEqual(fixture.events, ["after-readback"] if mode == "observe" else [])

    def test_three_originals_are_serial_and_failure_never_dispatches_the_next_leg(self):
        class Fixtures(InertAccountFixtures):
            def before_call(inner, case):
                self.assertTrue(inner.account_produced); self.assertFalse(inner.inflight)
                inner.events.append("before-app")

            def accept_account_app(inner, report):
                self.assertFalse(inner.inflight); self.assertTrue(inner.last_returned)
                M._ios_pending_report(report)
                inner.account_app_returned = True
                inner.events.append("app-accepted")

            def readback_account(inner, report):
                self.assertTrue(inner.account_readback); self.assertFalse(inner.inflight)
                M._ios_pending_report(report)
                inner.events.append("final-readback")
                return {"inertComparisonOnly": True}

        for fault in (None, "producer-unknown", "app-failed"):
            fixture = Fixtures(); calls = []; emitted = []
            def owner(argv, **options):
                self.assertTrue(fixture.inflight)
                if argv[0] == M.EXECUTABLE:
                    calls.append("app")
                    self.assertTrue(fixture.account_produced)
                    value = M.expected_result(BINDING, M.IOS_ACCOUNT_CASE)
                    body = M.MARKER + json.dumps(value, separators=(",", ":")).encode() + b"\n"
                    return CompletedProcess(argv, 1 if fault == "app-failed" else 0, body, b"")
                mode = argv[7]; calls.append(mode)
                if fault == "producer-unknown": raise RuntimeError("inert unknown original")
                if mode == "observe": self.assertTrue(fixture.account_app_returned)
                return returned(argv, mode)
            with patch("time.monotonic_ns", return_value=1_000_000_000):
                if fault is None:
                    self.assertEqual(M.run_cases(BINDING, fixture, owner, UID, "runner", emitted.append, M.IOS_ACCOUNT_CASE), ())
                else:
                    with self.assertRaises((M.Refused, RuntimeError)):
                        M.run_cases(BINDING, fixture, owner, UID, "runner", emitted.append, M.IOS_ACCOUNT_CASE)
            self.assertEqual(calls, ["produce"] if fault == "producer-unknown" else ["produce", "app"] if fault else ["produce", "app", "observe"])
            self.assertEqual(len(emitted), 0 if fault else 1)
            if fault is None: self.assertEqual(fixture.events[-1], "final-readback")
            self.assertEqual(fixture.inflight, fault == "producer-unknown")

    def test_account_descriptor_limit_precedes_open_and_close_is_consuming(self):
        fixture = M.Fixtures(BINDING, UID, GID, M.IOS_ACCOUNT_CASE)
        fixture.account_fds = set(range(32))
        with patch.object(fixture, "_open", side_effect=AssertionError("must not open")) as opened:
            with self.assertRaises(M.Refused): fixture._account_open("inert")
            opened.assert_not_called()
        fixture.fds = {99}; fixture.account_fds = {99}
        with patch.object(M.os, "close", side_effect=OSError("inert close result unavailable")) as closed:
            self.assertFalse(fixture._close(99))
            self.assertNotIn(99, fixture.fds); self.assertNotIn(99, fixture.account_fds)
            with self.assertRaises(M.Refused): fixture._close(99)
            closed.assert_called_once_with(99)
        self.assertEqual(fixture.close_errors, 1); self.assertIsNotNone(fixture.first_close_error)

        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        def admit(role, name, mode, size, allowed, *, changed=None, named_change=None, **options):
            fixture = M.Fixtures(BINDING, UID, GID, M.IOS_ACCOUNT_CASE)
            row = [7, 6, stat.S_IFREG | mode, UID, GID, 1, size, 100, 100]
            if changed is not None: row[changed[0]] = changed[1]
            named = list(row)
            if named_change is not None: named[named_change[0]] = named_change[1]
            kwargs = {"role": role, "identity": {"device": 7, "inode": 6} if role == "native" else None,
                      "body_hash": "f" * 64 if role == "private" else None, "limit": 128*1024*1024}
            kwargs.update(options)
            private_role = role == "private" and name in ("intent.json", "state.json", "account-baseline.json") and kwargs["body_hash"] is not None and kwargs["identity"] is None
            native_role = role == "native" and name in ("signing.keychain-db", M.IOS_ACCOUNT_LOCK_NAME) and kwargs["identity"] is not None and kwargs["body_hash"] is None
            with self.subTest(role=role, name=name, mode=mode, size=size, changed=changed, named_change=named_change, options=options), \
                    patch.object(fixture, "_account_open", return_value=99) as opened, patch.object(fixture, "_account_hash") as hashed, \
                    patch.object(M.os, "fstat", return_value=SimpleNamespace(**dict(zip(fields, row)))), \
                    patch.object(M.os, "stat", return_value=SimpleNamespace(**dict(zip(fields, named)))) as named_stat:
                if allowed:
                    observed = fixture._account_file(10, name, **kwargs)
                    self.assertEqual(observed, (10, name, 99, tuple(row), kwargs["body_hash"]))
                    if private_role: hashed.assert_called_once_with(observed)
                    else: hashed.assert_not_called()
                    named_stat.assert_called_once_with(name, dir_fd=10, follow_symlinks=False)
                else:
                    with self.assertRaises(M.Refused): fixture._account_file(10, name, **kwargs)
                    hashed.assert_not_called()
                if not (private_role or native_role): opened.assert_not_called()
        for mode in (0o400, 0o404, 0o440, 0o444):
            admit("native", M.IOS_ACCOUNT_LOCK_NAME, mode, 0, True, limit=64*1024*1024)
        admit("native", "signing.keychain-db", 0o600, 64*1024*1024, True)
        admit("native", "signing.keychain-db", 0o600, 64*1024*1024+1, False)
        for name, cap in (("intent.json", 512*1024), ("state.json", 512*1024), ("account-baseline.json", 12*1024)):
            admit("private", name, 0o600, 2, True)
            admit("private", name, 0o400, 2, False)
            admit("private", name, 0o600, cap+1, False)
        for mode in (0o000, 0o200, 0o600, 0o644, 0o401, 0o1400, 0o4400):
            admit("native", M.IOS_ACCOUNT_LOCK_NAME, mode, 0, False)
        admit("native", M.IOS_ACCOUNT_LOCK_NAME, 0o400, 1, False)
        admit("native", "signing.keychain-db", 0o400, 2, False)
        for role, name in (("private", M.IOS_ACCOUNT_LOCK_NAME), ("private", "signing.keychain-db"),
                           ("native", "state.json"), ("native", "unknown"), ("unknown", "state.json")):
            admit(role, name, 0o600, 0, False)
        admit("native", M.IOS_ACCOUNT_LOCK_NAME, 0o400, 0, False, body_hash="f" * 64)
        admit("private", "state.json", 0o600, 2, False, identity={"device": 7, "inode": 6})
        admit("private", "state.json", 0o600, 2, False, body_hash=None)
        for changed in ((0, 8), (1, 16), (3, UID+1), (5, 2), (2, stat.S_IFLNK | 0o400), (2, stat.S_IFDIR | 0o400)):
            admit("native", M.IOS_ACCOUNT_LOCK_NAME, 0o400, 0, False, changed=changed)
        for changed in ((6, 1), (7, 101), (8, 101)):
            admit("native", M.IOS_ACCOUNT_LOCK_NAME, 0o400, 0, False, named_change=changed)
        admit("native", "signing.keychain-db", 0o600, 2, False, limit=1)

    def test_independent_readback_refuses_baseline_substitution_or_retained_owned_name(self):
        fixture = M.Fixtures(BINDING, UID, GID, M.IOS_ACCOUNT_CASE)
        fixture.account_private = private_data(); fixture.account_home = "/Users/runner"; fixture.account_lease = 11
        fixture._roster = lambda fd, roster, label: self.assertEqual((fd, roster), (11, ()))
        baseline = (7, 5, stat.S_IFREG | 0o600, UID, GID, 1, 12, 100, 100)
        owned = (7, 6, stat.S_IFREG | 0o600, UID, GID, 1, 12, 100, 100)
        fixture.account_baseline_files = [(18, "login.keychain-db", 14, baseline)]
        fixture.account_native_files = [(13, "signing.keychain-db", 15, owned, None)]
        live = {14: baseline, 15: (*owned[:5], 0, *owned[6:])}
        named = {(18, "login.keychain-db"): baseline}
        def info(row):
            return SimpleNamespace(**dict(zip(("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"), row)))
        def named_info(name, *, dir_fd, follow_symlinks):
            self.assertIs(follow_symlinks, False)
            if (dir_fd, name) not in named: raise FileNotFoundError()
            return info(named[dir_fd, name])
        with patch.object(M.os, "fstat", side_effect=lambda fd: info(live[fd])), patch.object(M.os, "stat", side_effect=named_info):
            fixture._account_current(after=True)
            named[18, "login.keychain-db"] = (7, 105, *baseline[2:])
            with self.assertRaises(M.Refused): fixture._account_current(after=True)
            named[18, "login.keychain-db"] = baseline
            live[15] = owned
            with self.assertRaises(M.Refused): fixture._account_current(after=True)
            live[15] = (*owned[:5], 0, *owned[6:]); named[13, "signing.keychain-db"] = owned
            with self.assertRaises(M.Refused): fixture._account_current(after=True)
            del named[13, "signing.keychain-db"]
            lock = (7, 7, stat.S_IFREG | 0o400, UID, GID, 1, 0, 100, 100)
            fixture.account_native_files.append((13, M.IOS_ACCOUNT_LOCK_NAME, 16, lock, None))
            live[16] = (*lock[:5], 0, *lock[6:])
            fixture._account_current(after=True)
            for changed in ((1, 107), (2, stat.S_IFREG | 0o600), (5, 1), (6, 1)):
                row = list(live[16]); row[changed[0]] = changed[1]; original = live[16]; live[16] = tuple(row)
                with self.assertRaises(M.Refused): fixture._account_current(after=True)
                live[16] = original
            named[13, M.IOS_ACCOUNT_LOCK_NAME] = lock
            with self.assertRaises(M.Refused): fixture._account_current(after=True)
            live[15] = owned; named[13, "signing.keychain-db"] = owned; live[16] = lock
            fixture._roster = lambda fd, roster, label: self.assertEqual((fd, roster), (11, ("session-" + "e" * 32,)))
            fixture._account_current(after=False)
            live[16] = (*lock[:6], 1, *lock[7:])
            with self.assertRaises(M.Refused): fixture._account_current(after=False)
            live[16] = lock; named[13, M.IOS_ACCOUNT_LOCK_NAME] = (*lock[:6], 1, *lock[7:])
            with self.assertRaises(M.Refused): fixture._account_current(after=False)

    def test_closed_scope_fixture_and_public_parser_do_not_widen_nine_case_roster(self):
        self.assertEqual(M.argument_scope(["--scope", M.IOS_ACCOUNT_CASE]), M.IOS_ACCOUNT_CASE)
        self.assertEqual(M.selected_cases(M.IOS_ACCOUNT_CASE), (M.IOS_ACCOUNT_CASE,))
        self.assertNotIn(M.IOS_ACCOUNT_CASE, M.IOS_CURRENT_CASES); self.assertEqual(len(M.IOS_CURRENT_CASES), 9)
        self.assertEqual(M.case_timeout(M.IOS_ACCOUNT_CASE), 525)
        files, directories = M.fixture_data(M.IOS_ACCOUNT_CASE, False)
        self.assertEqual(set(files), {".gitignore", "keep.txt"})
        self.assertEqual(M.fixture_data(M.IOS_ACCOUNT_CASE, True), (files, directories))
        value = M.expected_result(BINDING, M.IOS_ACCOUNT_CASE)
        capture = M.MARKER + json.dumps(value, separators=(",", ":")).encode() + b"\n"
        self.assertLessEqual(len(capture) - len(M.MARKER) - 1, M.JSON_LIMIT)
        self.assertEqual(M.parse_result(capture, b"", BINDING, M.IOS_ACCOUNT_CASE), value)

    def test_current_core_source_and_targeted_workflow_preserve_owners_and_private_data(self):
        source = M.IOS_ACCOUNT_CORE_PROGRAM
        for required in ("signing.local_signing_lease(cancellation=guard)", "session.open(create=True)", "session.prepare(",
                         "session.activate()", "session.observe(journal=False)", "command_finality()", "scope.__exit__(*sys.exc_info())",
                         "time.monotonic_ns()<work", "time.monotonic_ns()<final", "len(fds)<32", "len(baseline[\"search\"])<=8"):
            self.assertIn(required, source)
        for forbidden in ("session.cleanup_native(", "session.cleanup_profile(", "session.finish(", "_normal_execution_revoked = False",
                          "delete-keychain", "security import", "os.unlink(", "os.rmdir(", "subprocess.run(", "subprocess.Popen("):
            self.assertNotIn(forbidden, source)
        self.assertIn('result=run_owned(argv,**options);row[2]=result', source)
        owner = (ROOT / "desktop/src-tauri/src/saved_command_owner.rs").read_text()
        selection = owner.split("fn ios_mode_selection(", 1)[1].split("const IOS_WORK", 1)[0]
        self.assertIn("if !installed { return ios_wire::ModeCapabilities::NONE; }", selection)
        self.assertIn("ios_mode_selection(self.ios_installed_selected(), Some(", owner)
        self.assertIn("return same_original && self.ios_observed_mode_capabilities(observation).supports(selected.operation)", owner)
        self.assertIn('originals: [Option<InstalledIOSOriginal>; 2]', owner)
        self.assertIn('Arc::ptr_eq(&inspected.original, &first.original)', owner)
        self.assertIn('observation.control.slot_for(selected)', owner)
        # Legacy signed/unsigned cases remain slot0-only. Both overrides are
        # compiled only on the intended native observation target; keep their
        # existing clocks while preventing a removed single-original field
        # from escaping focused local SOURCE checks.
        signed = owner.split("let clocks = if prepared.projection.context.signed_ios()\n", 1)[1].split("let material_matches", 1)[0]
        unsigned = owner.split("fn start_clocks(&self, admitted: Instant) -> Clocks {", 1)[1].split("fn offline_installed_selected", 1)[0]
        for block, operation, selected in ((signed, "IOSSignedExport", "Clocks::installed_ios_signed(admitted_at)"),
                                           (unsigned, "IOSUnsignedArchive", "Clocks::installed_ios(admitted)")):
            self.assertIn(f"o.originals[0].is_none() && o.control.permits_mode(ios_wire::Operation::{operation})", block)
            self.assertNotIn("o.original.", block)
            self.assertIn(selected, block)
        workflow = (ROOT / ".github/workflows/desktop-macos-aqua.yml").read_text()
        self.assertEqual(workflow.count("macos_aqua_qualification.py --scope ios-recovery-pending"), 1)
        step = workflow.split("      - name: One real pending account recovery through ordinary Inspect and exact Recover\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("timeout-minutes: 15", step)
        self.assertIn("[[ $status == 0 ]] || exit \"$status\"", step)
        exports = workflow.split("      - name: Preserve bounded original evidence; upload alone is not an Aqua pass\n", 1)[1].split("      - name:", 1)[0]
        self.assertNotIn("account-baseline.json", exports); self.assertNotIn(".mobile-release-signing", exports)
        for leaf in ("aqua-ios-account-results.jsonl", "aqua-ios-account-failure.jsonl", "aqua-ios-account.status"):
            self.assertIn("${{ steps.work.outputs.root }}/" + leaf + "\n", exports)


if __name__ == "__main__":
    unittest.main()
