"""Inert R native3 admission/receipt and fake-original custody contracts.

No compiler, UI, service, socket, credential, real journal or native helper is
started. Invented receipt DATA is parser coverage, never qualification evidence.
"""
from copy import deepcopy
import ast
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2]


def source_module(name, path):
    spec = importlib.util.spec_from_file_location(name, SOURCE / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = source_module("release_original_data_helpers", "tests/desktop/test_ubuntu_publication_lifecycle.py")
L = H.L
S = source_module("release_original_ci_data", "desktop/tools/ci_ubuntu_publication.py")
P = source_module("release_peer_input_data", "desktop/src-tauri/tests/fixtures/github_release_peer.py")
CASES = ("github-release-normal-pending", "github-release-response-loss", "github-release-pre-go-revocation")


def route_data(case="compile"):
    return {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64", "GITHUB_EVENT_NAME": "push", "GITHUB_REF": S.SHELL_GITHUB_RELEASE_REF,
        "GITHUB_JOB": "compile", "MRK_UBUNTU_PUBLICATION_VERIFY": "1", "GITHUB_SHA": "a" * 40,
        "MRK_PUSH_EVENT_AFTER": "a" * 40, "GITHUB_RUN_ID": "17", "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit", "MRK_INSTALLED_SHELL_CASE": case,
        "MRK_INSTALLED_SHELL_SCOPE": L.SHELL_GITHUB_RELEASE_PROFILE, "MRK_INSTALLED_SHELL_TRANSPORT": "actions-artifact-v1"}


def handoff_data():
    value = H.github_handoff_data(); value["shell"].pop("githubReadOnly")
    value["shell"]["githubRelease"] = L.shell_github_release_selection()
    binaries = {name: {"path": "/task/" + name, "size": 12, "sha256": "c" * 64} for name in ("normal", "observer")}
    value["shell"].update(binaries=binaries, loaderPolicy={}, compiler={
        "sourceSha": value["sourceSha"], "runId": value["runId"], "attempt": "1", "features": L.SHELL_FEATURES,
        "manifestSha256": L.M, "protocolSha256": L.Q, "exportedArtifacts": deepcopy(binaries),
        "androidBuildMaterials": None, "androidBuildBindings": {}, "androidBuildPublication": None,
        "githubRelease": L.shell_github_release_selection()})
    return value


def journal_bodies():
    intent = b'{"fictional-parser-data":true}\n'
    run = L.canonical({"schemaVersion": 1, "intentSha256": hashlib.sha256(intent).hexdigest(), "runId": "9001", "attempt": 1})
    return intent, run


def receipt_data(case):
    normal, loss, revocation = (case == name for name in CASES)
    index = CASES.index(case)
    kinds = (("connect", "pending"), ("connect", "prepare", "dispatch", "pending", "reconcile"), ("connect", "prepare", "dispatch"))[index]
    marker = None if normal else "a" * 32
    intent, run = journal_bodies()
    journal = {"marker": marker, "intentBytes": None if normal else len(intent),
        "intentSha256": None if normal else hashlib.sha256(intent).hexdigest(), "runBytes": len(run) if loss else None,
        "runSha256": hashlib.sha256(run).hexdigest() if loss else None, "runId": "9001" if loss else None,
        "attempt": 1 if loss else None, "leafCount": (0, 2, 1)[index]}
    manifest = L.M if normal else L.SHELL_GITHUB_PAYLOADS["D-S"]["manifestSha256"]
    callers = {stage: row[1] for stage, row in L.SHELL_GITHUB_RELEASE_CALLERS.items()}
    peer = {key: True for key in ("acquisitionJoined", "spawned", "waited", "exitSuccess", "stdoutJoined", "stderrJoined",
        "stdoutEof", "stderrEof", "ready", "settled", "withinEndpoint", "protocolChecked")}
    peer.update({key: False for key in ("stopAttempted", "stdoutOverflow", "stderrOverflow")})
    peer.update(exitCode=0, stdoutBytes=4096, stderrBytes=0,
        control={**{key: True for key in ("acquired", "started", "joined", "writeComplete", "shutdownComplete", "productSettled", "withinEndpoint", "released")}, "failed": False},
        terminal={"schemaVersion": 1, "scope": "github-release-installed-peer-v1", "case": case.removeprefix("github-"), "state": "finished",
            "ownerTag": "b" * 16, "manifestSha256": manifest, "peerSha256": L.SHELL_GITHUB_RELEASE_PEER_PIN[1],
            "toolingSha": L.SHELL_GITHUB_RELEASE_TOOLING_SHA, "callerSha256": callers, "primaryPort": 18443, "status": "passed",
            "requests": (4, 25, 14)[index], "posts": int(loss), "decryptedBytes": 1234, "intentBeforeResponse": loss,
            "allSocketsClosed": True, "inputsCheckedClosed": True, "otherJournalAbsent": True, "code": None,
            "completion": {"bytes": 1, "eof": True, "closed": True, "primaryEmpty": True, "primaryUnexpected": 0, "primaryClosed": True, "redirect": None},
            "journal": journal})
    originals = []
    for i, kind in enumerate(kinds):
        negative = revocation and i == 2
        role = "N" if normal and i == 1 else "D-S"
        maps = [{"role": name, "path": row["paths"][0], **{key: row[key] for key in ("deviceMajor", "deviceMinor", "inode")}}
            for name, row in sorted(H.github_map_data()[role].items()) if not (kind == "pending" or negative) or name not in ("libssl.so.3", "libcrypto.so.3")]
        originals.append({"operationId": ("github-read-" if i == 0 else "github-release-") + str(i + 7), "kind": kind,
            "manifestSha256": L.SHELL_GITHUB_PAYLOADS[role]["manifestSha256"],
            "reason": "cancelled" if negative else "tls-failed" if kind == "dispatch" else "none",
            "effect": "not-sent" if negative else "potentially-applied" if kind == "dispatch" else "none",
            "marker": None if i == 0 else marker, "terminal": True, "originalObserverJoined": True, "nativeSettled": True,
            "environmentClear": True, "readyObserved": i > 0, "claimReturned": i > 0, "goWritten": i > 0 and not negative,
            "goClaimed": i > 0 and not negative, "tokenAbsent": None if i == 0 or negative else kind == "pending",
            "negative": negative, "wasUnknown": False, "errorCode": "cancelled" if negative else None,
            "firstError": "cancelled" if negative else None, "exitCode": 70 if negative else 0, "exitSignal": None,
            "ownedStopAttempted": False, "settledNs": (i + 1) * 10_000_000, "maps": maps})
    scheduling = dict.fromkeys(("readyNs", "revocationReplyNs", "writerReleasedNs", "claimReturnedNs", "cleanupEndpointNs"))
    scheduling.update(mechanism="original-writer-scheduling" if revocation else "none", kernelCloseFaultInjected=False)
    if revocation:
        scheduling.update(readyNs=21_000_000, revocationReplyNs=26_000_000, writerReleasedNs=27_000_000,
                          claimReturnedNs=28_000_000, cleanupEndpointNs=2_025_000_000)
    return {"schemaVersion": 1, "fixture": "github-release-installed-v1", "case": case, "sourceCommit": "a" * 40,
        "normalManifestSha256": L.M, "productManifestSha256": manifest, "connectionManifestSha256": L.SHELL_GITHUB_PAYLOADS["D-S"]["manifestSha256"],
        "protocolSha256": L.Q, "toolingSha": L.SHELL_GITHUB_RELEASE_TOOLING_SHA, "callerSha256": callers,
        "peerSha256": L.SHELL_GITHUB_RELEASE_PEER_PIN[1], "project": {"cancelSettled": True, "registered": True, "snapshot": True},
        "nativeSession": {"connect": 1, "prepare": int(not normal), "dispatch": int(not normal), "pending": int(not revocation),
            "reconcile": int(loss), "disconnect": 1, "retainedStatus": True, "pendingReloaded": not revocation,
            "tokenFieldCleared": True, "reviewVisible": not normal, "typedConfirmation": not normal, "consentObserved": not normal,
            "originalDeclarationsDistinct": loss, "dispatchEffect": None if normal else "potentially-applied" if loss else "not-sent",
            "dispatchReason": None if normal else "tls-failed" if loss else "cancelled", "runObserved": loss,
            "retirement": {"mode": "disconnected", "authorityRemoved": True, "terminalPreserved": True, "recoveryPreserved": True}},
        "scheduling": scheduling, "originals": originals, "peer": peer,
        "quit": {"originalsFinal": True, "relayJoined": True, "gtkSettled": True, "exit": True}, "notProven": list(L.SHELL_GITHUB_RELEASE_NOT_PROVEN)}


def projection_data(value, case, receipt):
    start = 200 + 100 * CASES.index(case)
    def directory(inode):
        return [1, inode, stat.S_IFDIR | 0o700, value["runnerUid"], value["runnerGid"], 3, 4096, 9_007_199_254_740_993, 9_007_199_254_740_995]
    dirs = {name: directory(start + index) for index, name in enumerate(("gui", "home", *L.SHELL_GITHUB_RELEASE_JOURNAL_DIRECTORIES))}
    journal = receipt["peer"]["terminal"]["journal"]
    files = {journal["marker"] + "." + kind + ".json": {
        "identity": [1, start + 20 + index, stat.S_IFREG | 0o400, value["runnerUid"], value["runnerGid"], 1, journal[kind + "Bytes"], 7, 9],
        "size": journal[kind + "Bytes"], "sha256": journal[kind + "Sha256"]} for index, (kind, _) in enumerate(L._shell_github_release_journal_kinds(case))}
    return {"schema": "installed-github-release-journal-v1", "sourceSha": value["sourceSha"], "runId": value["runId"], "attempt": value["attempt"],
        "case": case, "home": str(L.root_path(value) / ("gui-" + case) / "home"),
        "created": {"root": H.fixture_namespace_data(value)["control"]["identity"], "gui": dirs["gui"][:5], "home": dirs["home"][:5]},
        "directories": dirs, "files": files, "journal": deepcopy(journal)}


class FakeInputOS:
    """Logical descriptors only. No file descriptor or native process is created."""
    O_RDONLY, O_NOFOLLOW, O_CLOEXEC = os.O_RDONLY, os.O_NOFOLLOW, os.O_CLOEXEC
    O_NONBLOCK, O_DIRECTORY = os.O_NONBLOCK, os.O_DIRECTORY

    def __init__(self):
        self.nodes, self.bodies, self.handles, self.opened, self.closed, self.reads = {}, {}, {}, [], [], []
        self.open_failure = None
        self.close_failure = self.read_failure = False

    @staticmethod
    def stat_row(row):
        return SimpleNamespace(**dict(zip(("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"), row)))

    def directory(self, path, owner=0, mode=0o755):
        for selected in reversed((Path(path), *Path(path).parents)):
            if str(selected) not in self.nodes:
                self.nodes[str(selected)] = self.stat_row([1, len(self.nodes) + 1, stat.S_IFDIR | mode, owner, 0 if owner == 0 else 1001, 2, 4096, 7, 9])

    def file(self, path, raw=b"fictional", owner=0, mode=0o444):
        self.directory(Path(path).parent, owner, 0o755 if owner == 0 else 0o700)
        self.nodes[str(path)] = self.stat_row([1, len(self.nodes) + 1, stat.S_IFREG | mode, owner, 0 if owner == 0 else 1001, 1, len(raw), 7, 9])
        self.bodies[str(path)] = raw

    def path(self, name, dir_fd):
        return str(Path(self.handles[dir_fd][0]) / name) if dir_fd is not None else str(name)

    def stat(self, name, *, dir_fd=None, follow_symlinks=False):
        assert follow_symlinks is False
        return self.nodes[self.path(name, dir_fd)]

    def open(self, name, flags, *, dir_fd=None):
        assert flags & self.O_NOFOLLOW and flags & self.O_CLOEXEC
        path = self.path(name, dir_fd)
        if path == self.open_failure:
            raise OSError(errno.EACCES, "fake suffix open refusal")
        fd = 100 + len(self.opened)
        self.handles[fd] = [path, self.nodes[path], 0]; self.opened.append(fd)
        return fd

    def fstat(self, fd):
        if fd in self.closed:
            raise OSError(errno.EBADF, "fake original already consumed")
        return self.handles[fd][1]

    def getegid(self):
        return 1001

    def listxattr(self, fd):
        self.fstat(fd)
        return []

    def read(self, fd, maximum):
        self.reads.append(fd)
        if self.read_failure:
            raise OSError("fake read refusal")
        handle = self.handles[fd]
        raw = self.bodies[handle[0]][handle[2]:handle[2] + maximum]; handle[2] += len(raw)
        return raw

    def pread(self, fd, maximum, offset):
        self.fstat(fd)
        return self.bodies[self.handles[fd][0]][offset:offset + maximum]

    def scandir(self, fd):
        self.fstat(fd)
        parent = Path(self.handles[fd][0])
        return FakeEntries([Path(path).name for path in self.nodes if Path(path) != parent and Path(path).parent == parent])

    def close(self, fd):
        assert fd not in self.closed
        self.closed.append(fd)
        if self.close_failure:
            self.close_failure = False
            raise OSError("fake close refusal")


class FakeEntries:
    def __init__(self, names):
        self.entries = iter(SimpleNamespace(name=name) for name in names)
    def __enter__(self):
        return self.entries
    def __exit__(self, *args):
        return False


def fake_journal(value, case, receipt):
    data, fake = projection_data(value, case, receipt), FakeInputOS()
    root = L.root_path(value); home = Path(data["home"])
    fake.nodes[str(root)] = fake.stat_row([*data["created"]["root"], 4, 4096, 7, 9])
    paths = {"gui": home.parent, "home": home, **{name: home / name for name in L.SHELL_GITHUB_RELEASE_JOURNAL_DIRECTORIES}}
    fake.nodes.update({str(paths[name]): fake.stat_row(row) for name, row in data["directories"].items()})
    journal = home / L.SHELL_GITHUB_RELEASE_JOURNAL_DIRECTORIES[-1]
    for name, row in data["files"].items():
        fake.nodes[str(journal / name)] = fake.stat_row(row["identity"])
        fake.bodies[str(journal / name)] = journal_bodies()[0 if name.endswith("intent.json") else 1]
    return fake, data


def closed_data():
    value = handoff_data()
    def pin(raw):
        return {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    project = H.github_fixture_data(value)
    project_pin, material_pin = pin(L.canonical(project)), pin(b"fictional-materials\n")
    fixture = {"project": project["project"], "namespace": project["namespace"], "unchanged": True,
        "sourceSha256": hashlib.sha256(L.SHELL_PROJECT_SOURCE).hexdigest(), "versionSha256": hashlib.sha256(L.SHELL_PROJECT_VERSION).hexdigest(),
        "releaseConfigCreated": False, "sourceSha": value["sourceSha"], "before": project_pin, "after": deepcopy(project_pin)}
    cases, journals, captures = {}, {}, {}
    for case in CASES:
        receipt = receipt_data(case)
        cases[case] = {"case": case, "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True, "maps": [], "githubRelease": receipt}
        data = projection_data(value, case, receipt)
        journals[case] = {"capture": pin(L.canonical(data)), "originals": data}
        captures["shell-" + case + "-journal.json"] = journals[case]["capture"]
    captures["shell-cases.json"] = pin(L.canonical(cases))
    for phase in ("before", "after"):
        captures["shell-github-materials-" + phase + ".json"] = material_pin
        captures["shell-github-project-" + phase + ".json"] = project_pin
    github = {"selection": L.shell_github_release_selection(), "expectedMaps": H.github_map_data(),
        "materials": {"before": material_pin, "after": deepcopy(material_pin)}, "fixture": fixture,
        "casesCapture": captures["shell-cases.json"], "journals": journals, "normalDestinationAction": False,
        "normalTransportPositive": False, "remainingCoverage": list(L.SHELL_GITHUB_RELEASE_NOT_PROVEN)}
    return {"state": "installed-github-release-native3-observed", "productQualified": False, "packageLifecycleQualified": False,
        "shellPackageBuilt": False, "serviceQualified": False, "sourceSha": value["sourceSha"], "consumerAttempt": value["attempt"],
        "unit": L.root_path(value).name + ".service", "githubRelease": github, "cases": cases,
        "files": [{"path": "lifecycle-" + name, **captures.get(name, pin(b"fictional-export\n"))}
                  for name in sorted(L.public_files(value) | {"client.stdout", "client.stderr"})]}


class GitHubReleaseNativeRouteContracts(unittest.TestCase):
    def test_exact_route_scope_and_ambient_bindings_refuse_before_preparation(self):
        for case in ("compile", "observe"):
            env = route_data(case)
            self.assertEqual(S.route(env), env["GITHUB_SHA"])
            with patch.dict(S.os.environ, env, clear=True):
                self.assertIsNone(S.installed_shell_scope(L))
                selection = S.installed_shell_release_selection(L)
                self.assertEqual(selection, L.shell_github_release_selection())
                with patch.object(S, "local", return_value=L):
                    self.assertEqual(S.preparation_route(), {"shellCase": case, "job": "compile", "githubRelease": selection})
            for key, bad in (("GITHUB_JOB", "observe"), ("MRK_INSTALLED_SHELL_CASE", CASES[0]), ("GITHUB_EVENT_NAME", "workflow_dispatch"),
                ("RUNNER_ENVIRONMENT", "self-hosted"), ("GITHUB_REF", "refs/heads/main"), ("MRK_PUSH_EVENT_AFTER", "b" * 40),
                ("MRK_INSTALLED_CASE", "positive"), ("MRK_INSTALLED_SHELL_SCOPE", "")):
                with self.subTest(case=case, key=key), self.assertRaises(S.D.Refused): S.route({**env, key: bad})
        for key, bad in [(key, "") for key in S.SHELL_GITHUB_RELEASE_ENVIRONMENT] + [
            ("MRK_GITHUB_PREFLIGHT_TOOLING_SHA", ""), ("MRK_INSTALLED_SHELL_TRANSPORT", "android-same-job-local-v1"),
            ("MRK_INSTALLED_SHELL_LOCAL_TRANSPORT_SHA256", "a" * 64), ("MRK_INSTALLED_SHELL_SCOPE", "ordinary21-v1")]:
            with self.subTest(key=key), patch.dict(S.os.environ, {**route_data(), key: bad}, clear=True), self.assertRaises(S.D.Refused):
                S.installed_shell_release_selection(L)
        for ref in (S.SHELL_REF, S.SHELL_RECOVERY_REF, S.SHELL_GITHUB_REF, S.SHELL_GITHUB_PREFLIGHT_REF):
            with patch.dict(S.os.environ, {"GITHUB_REF": ref}, clear=True): self.assertIsNone(S.installed_shell_release_selection(L))
            with patch.dict(S.os.environ, {**route_data(), "GITHUB_REF": ref}, clear=True), self.assertRaises(S.D.Refused): S.installed_shell_scope(L)

    def test_independent_compiler_contract_and_canonical_three_callers(self):
        selection = L.shell_github_release_selection(); compiler = handoff_data()["shell"]["compiler"]
        S.installed_shell_release_record(compiler, L, selection, android_contract=True)
        for field, bad in (("githubPreflight", {}), ("githubReadOnly", {}), ("ordinary21", {}), ("projectRecovery", {}),
            ("androidBuildMaterials", {}), ("androidBuildBindings", []), ("androidBuildPublication", {}), ("androidPreparation", {})):
            with self.subTest(field=field), self.assertRaises(S.D.Refused):
                S.installed_shell_release_record({**compiler, field: bad}, L, selection, android_contract=True)
        with self.assertRaises(S.D.Refused): S.installed_shell_release_record({}, L, selection)
        with self.assertRaises(S.D.Refused): S.installed_shell_release_record(compiler, L, None)
        environment = {"PATH": "/inert"}; S.installed_shell_release_environment(environment, L, selection)
        self.assertEqual(environment, {"PATH": "/inert", "MRK_GITHUB_RELEASE_TOOLING_SHA": L.SHELL_GITHUB_RELEASE_TOOLING_SHA})
        for key in S.SHELL_GITHUB_RELEASE_ENVIRONMENT | {"MRK_GITHUB_PREFLIGHT_TOOLING_SHA"}:
            with self.subTest(key=key), self.assertRaises(S.D.Refused): S.installed_shell_release_environment({key: ""}, L, selection)
        self.assertNotEqual(selection["toolingSha"], L.SHELL_GITHUB_PREFLIGHT_TOOLING_SHA)
        S.installed_shell_release_sources(SOURCE, L, selection)
        for stage, row in selection["callers"].items():
            raw = (SOURCE / row["template"]["path"]).read_bytes()
            rendered = raw.replace(b"__MOBILE_RELEASE_KIT_REPOSITORY__", b"Apdelrahman1911/mobile-release-kit").replace(
                b"__MOBILE_RELEASE_KIT_SHA__", selection["toolingSha"].encode())
            self.assertEqual((len(rendered), hashlib.sha256(rendered).hexdigest()), L.SHELL_GITHUB_RELEASE_CALLERS[stage])
        with patch.object(S.D, "file_record", return_value={"size": 1, "sha256": "0" * 64}), self.assertRaises(S.D.Refused):
            S.installed_shell_release_sources(SOURCE, L, selection)

    def test_finite_three_route_handoff_remains_distinct_from_other_families(self):
        value = handoff_data()
        self.assertEqual(L.shell_cases(value), CASES); self.assertIsNone(L.shell_handoff(value, []))
        self.assertEqual(L.result_state(value), "installed-github-release-native3-observed")
        self.assertFalse(L.shell_android(value) or L.shell_normal_boundaries(value))
        for key in ("githubPreflight", "githubReadOnly", "ordinary21", "projectRecovery", "androidPublication", "localTransport"):
            for scope in ("shell", "compiler"):
                bad = deepcopy(value); target = bad["shell"] if scope == "shell" else bad["shell"]["compiler"]; target[key] = {}
                with self.subTest(key=key, scope=scope), self.assertRaises(L.Refused): L.shell_handoff(bad, [])
        for case in CASES:
            env = L.shell_environment(value, case)
            self.assertEqual(env["HOME"], str(L.root_path(value) / ("gui-" + case) / "home"))
            self.assertFalse(set(env) & {"GH_TOKEN", "GITHUB_TOKEN", "HTTPS_PROXY", "SSLKEYLOGFILE", "SSL_CERT_FILE", "PYTHONPATH"})
            self.assertIn("shell-" + case + "-journal.json", L.public_files(value))

    def test_three_schedules_and_pending_normal_v_originals_are_actual_contracts(self):
        for case, owners, requests, posts in zip(CASES, (2, 5, 3), (4, 25, 14), (0, 1, 0)):
            receipt = receipt_data(case); maps = H.github_map_data()
            self.assertEqual(L.shell_github_release_receipt(L.canonical(receipt), case, maps), receipt)
            capture = H.github_capture_data(case, receipt).replace(L.SHELL_GITHUB_MARKER, L.SHELL_GITHUB_RELEASE_MARKER)
            self.assertEqual(L.shell_result(capture, b"", case, 0, maps)["githubRelease"], receipt)
            self.assertEqual(len(receipt["originals"]), owners)
            self.assertEqual((receipt["peer"]["terminal"]["requests"], receipt["peer"]["terminal"]["posts"]), (requests, posts))
            for altered in (capture.replace(L.SHELL_GITHUB_RELEASE_MARKER, L.SHELL_GITHUB_PREFLIGHT_MARKER), capture + b"MRK_EXTRA=bad\n"):
                with self.assertRaises(L.Refused): L.shell_result(altered, b"", case, 0, maps)
            with self.assertRaises(L.Refused): L.shell_result(capture, b"", case, 1, maps)
        normal = receipt_data(CASES[0])
        self.assertNotEqual(normal["originals"][0]["manifestSha256"], normal["originals"][1]["manifestSha256"])
        self.assertTrue(normal["originals"][1]["tokenAbsent"])
        self.assertIsNone(normal["peer"]["terminal"]["journal"]["marker"])
        callers = {stage: (SOURCE / row["template"]["path"]).read_bytes().replace(b"__MOBILE_RELEASE_KIT_REPOSITORY__", b"Apdelrahman1911/mobile-release-kit").replace(
            b"__MOBILE_RELEASE_KIT_SHA__", P.TOOLING.encode()) for stage, row in L.shell_github_release_selection()["callers"].items()}
        for case, requests, posts in zip(P.CASES, (4, 25, 14), (0, 1, 0)):
            schedule = P.schedule(case, callers)
            self.assertEqual(len(schedule), requests); self.assertEqual(sum(row[0] == "POST" for row in schedule), posts)
        self.assertNotEqual(P.SOURCE, P.ORIGINAL)
        body = P.canonical({"ref": "production", "return_run_details": True, "inputs": {"platform": "ios", "confirmation": "production-submit:ios:1.2.3:42",
            "recovery_run_id": "", "recovery_confirmation": "", "desktop_request": "a" * 32, "desktop_source_sha": P.SOURCE,
            "desktop_expected_ref": "refs/heads/production", "candidate_run_id": "101", "external_run_id": "102"}})
        self.assertEqual(P.dispatch_marker(body), "a" * 32)
        with self.assertRaises(ValueError): P.dispatch_marker(body.replace(b"1.2.3:42", b"2.0.0:99"))

    def test_failure_latching_go_finality_and_revocation_timing_cannot_be_downgraded(self):
        for case in CASES:
            receipt = receipt_data(case); action = len(receipt["originals"]) - 1
            mutations = [(("sourceCommit",), "0" * 40), (("toolingSha",), L.SHELL_GITHUB_PREFLIGHT_TOOLING_SHA),
                (("callerSha256", "candidate"), "0" * 64), (("connectionManifestSha256",), L.M), (("peerSha256",), "f" * 64),
                (("originals", action, "nativeSettled"), False), (("originals", action, "terminal"), False),
                (("originals", action, "originalObserverJoined"), False), (("originals", action, "wasUnknown"), True),
                (("originals", action, "goClaimed"), not receipt["originals"][action]["goClaimed"]),
                (("originals", action, "goWritten"), not receipt["originals"][action]["goWritten"]),
                (("originals", action, "operationId"), receipt["originals"][0]["operationId"]),
                (("peer", "control", "released"), False), (("peer", "control", "productSettled"), False),
                (("peer", "stdoutEof"), False), (("peer", "terminal", "otherJournalAbsent"), False),
                (("peer", "terminal", "inputsCheckedClosed"), False), (("peer", "terminal", "posts"), 2),
                (("peer", "terminal", "completion", "eof"), False), (("quit", "originalsFinal"), False), (("notProven",), [])]
            if case == CASES[0]:
                mutations += [(("productManifestSha256",), receipt["connectionManifestSha256"]),
                              (("originals", 1, "tokenAbsent"), False), (("peer", "terminal", "journal", "runId"), "9001")]
            elif case == CASES[1]:
                mutations += [(("nativeSession", "originalDeclarationsDistinct"), False), (("nativeSession", "typedConfirmation"), False),
                    (("nativeSession", "pendingReloaded"), False), (("originals", 2, "effect"), "accepted"), (("originals", 3, "tokenAbsent"), False)]
            else:
                mutations += [(("originals", 2, "firstError"), "cleanup_unknown"), (("originals", 2, "errorCode"), None),
                    (("scheduling", "writerReleasedNs"), receipt["scheduling"]["revocationReplyNs"] - 1),
                    (("scheduling", "cleanupEndpointNs"), receipt["originals"][2]["settledNs"]),
                    (("scheduling", "kernelCloseFaultInjected"), True), (("originals", 2, "tokenAbsent"), False)]
            for path, bad in mutations:
                changed = deepcopy(receipt); H.github_data_set(changed, path, bad)
                with self.subTest(case=case, path=path), self.assertRaises(L.Refused): L.shell_github_release_receipt(L.canonical(changed), case, H.github_map_data())
        revoked = receipt_data(CASES[2]); revoked["originals"][-1].update(exitCode=None, exitSignal=9, ownedStopAttempted=True)
        L.shell_github_release_receipt(L.canonical(revoked), CASES[2], H.github_map_data())
        revoked["originals"][-1]["ownedStopAttempted"] = False
        with self.assertRaises(L.Refused): L.shell_github_release_receipt(L.canonical(revoked), CASES[2], H.github_map_data())

    def test_zero_one_two_leaf_originals_retain_full9_and_close_once(self):
        value = handoff_data()
        for case, leaves in zip(CASES, (0, 2, 1)):
            receipt = receipt_data(case); fake, data = fake_journal(value, case, receipt)
            with self.subTest(case=case), patch.object(L, "os", fake), patch.object(L, "directory"), \
                 patch.object(L, "_ROOT", L.root_path(value)), patch.dict(L._SHELL_GITHUB_RELEASE_HOMES, {case: data["created"]}, clear=True):
                self.assertEqual(L._shell_github_release_journal_snapshot(value, case, receipt), data)
            self.assertEqual(len(fake.opened), 7 + leaves)
            self.assertEqual(fake.closed, list(reversed(fake.opened)))
            self.assertEqual(set(fake.reads), set(fake.opened[7:]))
            raw = L.canonical(data); self.assertIn(b"9007199254740993", raw)
            self.assertEqual(L.shell_github_release_journal_data(value, case, raw, receipt), data)

    def test_extra_or_other_family_roster_is_refused_before_any_journal_read(self):
        value = handoff_data()
        for case in CASES:
            for other_family in (False, True):
                receipt = receipt_data(case); fake, data = fake_journal(value, case, receipt)
                root = Path(data["home"]) / L.SHELL_GITHUB_RELEASE_JOURNAL_DIRECTORIES[-1]
                path = root.parent / "github-preflight" if other_family else root / ("f" * 32 + ".run.json")
                fake.nodes[str(path)] = fake.stat_row([1, 999, stat.S_IFREG | 0o400, 1001, 1001, 1, 1, 7, 9])
                with self.subTest(case=case, other_family=other_family), patch.object(L, "os", fake), patch.object(L, "directory"), \
                     patch.object(L, "_ROOT", L.root_path(value)), patch.dict(L._SHELL_GITHUB_RELEASE_HOMES, {case: data["created"]}, clear=True), self.assertRaises(L.Refused):
                    L._shell_github_release_journal_snapshot(value, case, receipt)
                self.assertEqual(fake.reads, []); self.assertEqual(fake.closed, list(reversed(fake.opened)))

    def test_journal_failure_and_later_case_drift_never_publish_success(self):
        value = handoff_data(); case = CASES[1]
        for fault in ("mode", "read", "close"):
            receipt = receipt_data(case); fake, data = fake_journal(value, case, receipt)
            if fault == "mode": fake.nodes[next(iter(fake.bodies))].st_mode = stat.S_IFREG | 0o600
            else: setattr(fake, fault + "_failure", True)
            with self.subTest(fault=fault), patch.object(L, "os", fake), patch.object(L, "directory"), \
                 patch.object(L, "_ROOT", L.root_path(value)), patch.dict(L._SHELL_GITHUB_RELEASE_HOMES, {case: data["created"]}, clear=True), self.assertRaises((L.Refused, OSError)):
                L._shell_github_release_journal_snapshot(value, case, receipt)
            self.assertEqual(fake.closed, list(reversed(fake.opened)))
        completed = {case: (receipt_data(case), projection_data(value, case, receipt_data(case))) for case in CASES}
        homes = {case: row[1]["created"] for case, row in completed.items()}
        for fault in (None, "earlier-drift", "missing-case"):
            current = deepcopy(completed)
            if fault == "missing-case": current.pop(CASES[1])
            def snapshot(v, case, receipt):
                data = deepcopy(completed[case][1])
                if fault == "earlier-drift" and case == CASES[0]: data["directories"]["home"][8] += 1
                return data
            with self.subTest(fault=fault), patch.object(L, "_FAILED", False), patch.object(L, "_END", 20), \
                 patch.object(L.time, "monotonic", return_value=10), patch.dict(L._SHELL_GITHUB_RELEASE_COMPLETED, current, clear=True), \
                 patch.dict(L._SHELL_GITHUB_RELEASE_HOMES, homes, clear=True), patch.object(L, "_shell_github_release_journal_snapshot", side_effect=snapshot), patch.object(L, "_retain") as retained:
                if fault is None:
                    L._shell_github_release_journals_final(value)
                    self.assertEqual([call.args[0] for call in retained.call_args_list], ["shell-" + case + "-journal.json" for case in CASES])
                else:
                    with self.assertRaises(L.Refused): L._shell_github_release_journals_final(value)
                    retained.assert_not_called()

    def test_failed_or_wrong_original_command_cannot_open_private_journal(self):
        value, case = handoff_data(), CASES[0]
        command = {"phase": "shell-" + case, "argv": L.shell_argv(value, case), "exitCode": 0}
        for fault in ("failed", "owner", "command", "source", "missing-native"):
            current = deepcopy(command); observed = {"exitCode": 0, "githubRelease": receipt_data(case)}
            if fault == "command": current["exitCode"] = 1
            if fault == "source": observed["githubRelease"]["sourceCommit"] = "b" * 40
            if fault == "missing-native": observed.pop("githubRelease")
            with self.subTest(fault=fault), patch.object(L, "_FAILED", fault == "failed"), \
                 patch.object(L, "_OWNER", None if fault == "owner" else object()), patch.object(L, "_END", 20), \
                 patch.object(L.time, "monotonic", return_value=10), patch.object(L, "_COMMANDS", [current]), \
                 patch.dict(L._SHELL_GITHUB_RELEASE_COMPLETED, {}, clear=True), patch.object(L, "_shell_github_release_journal_snapshot") as snapshot, self.assertRaises(L.Refused):
                L._shell_github_release_after(value, case, observed)
            snapshot.assert_not_called()

    def test_closed_ci_export_and_native_source_limits_are_not_relabelled(self):
        observed = closed_data()
        self.assertEqual(S.shell_github_release_observation(observed, L, runner_uid=1001, runner_gid=1001), observed["githubRelease"])
        mutations = ((("state",), "installed-github-preflight-synthetic-observed"), (("serviceQualified",), True), (("githubPreflight",), {}),
            (("githubRelease", "remainingCoverage"), []), (("githubRelease", "selection", "productionToolingDelivered"), True),
            (("githubRelease", "journals", CASES[0], "originals", "directories", "home", 8), 9_007_199_254_740_996),
            (("files",), observed["files"][:-1]))
        for path, bad in mutations:
            changed = deepcopy(observed); H.github_data_set(changed, path, bad)
            with self.subTest(path=path), self.assertRaises((L.Refused, S.D.Refused)):
                S.shell_github_release_observation(changed, L, runner_uid=1001, runner_gid=1001)
        with self.assertRaises(S.D.Refused): S.shell_github_observation(observed, L)
        with self.assertRaises(S.D.Refused): S.shell_github_preflight_observation(observed, L, runner_uid=1001, runner_gid=1001)
        # Self-consistent rehashed journal exports still cannot substitute a
        # different common original than the actual registered namespace.
        changed = deepcopy(observed)
        for case, pair in changed["githubRelease"]["journals"].items():
            pair["originals"]["created"]["root"][1] += 1000
            raw = L.canonical(pair["originals"])
            pair["capture"] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            next(row for row in changed["files"] if row["path"] == "lifecycle-shell-" + case + "-journal.json").update(pair["capture"])
        with self.assertRaises(S.D.Refused): S.shell_github_release_observation(changed, L, runner_uid=1001, runner_gid=1001)

    def test_workflow_and_prerequisite_source_admission_are_exact_and_bounded(self):
        raw = (SOURCE / S.WORKFLOW).read_bytes(); workflow = raw.decode()
        self.assertLessEqual(len(raw), 65536)
        self.assertIn(S.SHELL_GITHUB_RELEASE_REF + ":compile", workflow)
        self.assertIn("scope != 'github-release-native3-v1' or transport != 'actions-artifact-v1'", workflow)
        self.assertIn("persist-credentials: false", workflow); self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("permissions:\n  contents: read\n  actions: read", workflow)
        self.assertNotIn("MRK_GITHUB_RELEASE_TOOLING_SHA:", workflow); self.assertNotIn("workflow_dispatch:", workflow)
        policy, observer = S.local("hosted_glibc_policy"), S.local("observe_hosted_python")
        self.assertIn((S.SHELL_GITHUB_RELEASE_REF, "compile", "compile"), policy.ROUTES)
        self.assertNotIn((S.SHELL_GITHUB_RELEASE_REF, "compile", "observe"), policy.ROUTES)
        self.assertNotIn((S.SHELL_GITHUB_RELEASE_REF, "publisher-helpers", None), policy.ROUTES)
        for case in ("compile", "observe"): self.assertIn((S.SHELL_GITHUB_RELEASE_REF, case, "compile"), observer.ROUTES)
        for case, job in (("compile", "observe"), ("observe", "observe"), ("observe", "recovery-negative"),
            ("host-metadata-only", "compile")):
            self.assertNotIn((S.SHELL_GITHUB_RELEASE_REF, case, job), observer.ROUTES)
        pins = re.findall(r"MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256: '([0-9a-f]{64})'", workflow)
        self.assertEqual(pins, [hashlib.sha256((SOURCE / L.ENTRY).read_bytes()).hexdigest()] * 5)
        records = S.shell_source_manifest(SOURCE)
        paths = {row["path"] for row in records}
        for path in ("desktop/github_release_bootstrap.py", "src/mobile_release/github_release.py", "src/mobile_release/_github_preflight_journal.py",
            "desktop/src-tauri/src/github_release_native_observation.rs", "desktop/src-tauri/src/installed_shell_release_observation.rs",
            "desktop/src/githubReleaseController.ts", "desktop/src/githubReleaseTypes.ts", "desktop/src/components/GitHubRelease.tsx"):
            self.assertIn(path, paths)
        source = (SOURCE / L.ENTRY).read_text(); tree = ast.parse(source)
        snapshot = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_shell_github_release_journal_snapshot")
        calls = {ast.unparse(n.func) for n in ast.walk(snapshot) if isinstance(n, ast.Call)}
        self.assertFalse(calls & {"os.chmod", "os.unlink", "shutil.rmtree", "command"})
        self.assertIn("verify_finality(start, stop, client_result.returncode, github=shell_github(value))", source)


class SharedSourcePrefixContracts(unittest.TestCase):
    source = Path("/var/lib/mrk-ubuntu-native-10-2/github-peer/github_release_peer.py")

    def fixed(self, fake):
        paths = [self.source, self.source.with_name("github_tls_peer.py"),
                 *(self.source.with_name("mobile-" + stage + ".yml") for stage in P.CALLERS),
                 *(self.source.with_name("github_tls") / name for name in ("api-valid.pem", "server-key.pem"))]
        inputs = []
        for path in paths:
            fake.file(path); P.acquire(inputs, path, 100, hashlib.sha256(b"fictional").hexdigest())
        return inputs

    def test_all_three_exact_peaks_preserve_original_inputs_below_unchanged_64(self):
        for case, expected in zip(P.CASES, (25, 39, 38)):
            fake = FakeInputOS()
            with self.subTest(case=case), patch.object(P, "os", fake):
                inputs = self.fixed(fake); anchor = inputs[0]
                self.assertEqual(len(fake.opened), 14)
                root = P.journal_root(self.source, case); fake.directory(root, 1001, 0o700)
                for kind in (() if case == P.CASES[0] else ("intent", "run") if case == P.CASES[1] else ("intent",)):
                    fake.file(root / ("a" * 32 + "." + kind + ".json"), owner=1001, mode=0o400)
                if case == P.CASES[2]: inputs.append(P.Input(root, 1, owner=1001, mode=0o700, private_parent=True, directory=True, anchor=anchor))
                for kind in (() if case == P.CASES[0] else ("intent", "run") if case == P.CASES[1] else ("intent",)):
                    inputs.append(P.Input(root / ("a" * 32 + "." + kind + ".json"), 100, owner=1001, mode=0o400, private_parent=True, anchor=anchor))
                inputs.append(P.Input(root, 2, owner=1001, mode=0o700, private_parent=True, directory=True, anchor=anchor))
                inputs.append(P.Input(root.parent, 1, owner=1001, mode=0o700, private_parent=True, directory=True, anchor=anchor))
                self.assertEqual(len(fake.opened), expected); self.assertEqual(P.INPUT_FD_PEAKS[case], expected)
                self.assertLess(expected + 3 + 3 + 4, 64)
                for original in reversed(inputs): original.check(); original.close()
                self.assertEqual(fake.closed, list(reversed(fake.opened)))
                self.assertTrue(all(original.closed for original in inputs))
        self.assertIn("(resource.RLIMIT_NOFILE, 64)", (SOURCE / "desktop/src-tauri/tests/fixtures/github_release_peer.py").read_text())

    def test_borrower_lifetime_close_authority_and_anchor_replacement_refusal(self):
        fake = FakeInputOS(); fake.file(self.source); target = self.source.with_name("github_tls") / "api-valid.pem"; fake.file(target)
        with patch.object(P, "os", fake):
            anchor = P.Input(self.source, 100, owner=0, mode=0o444)
            borrower = P.Input(target, 100, owner=0, mode=0o444, anchor=anchor)
            self.assertIs(borrower.anchor, anchor); self.assertEqual(borrower.borrowed, 5)
            owned = borrower.slots[borrower.borrowed:]; source_slots = list(anchor.slots)
            borrower.close(); borrower.close(); self.assertEqual(fake.closed, list(reversed(owned)))
            anchor.check(); self.assertFalse(anchor.closed); anchor.close()
            self.assertEqual(fake.closed, list(reversed(owned)) + list(reversed(source_slots)))
        for fault in ("closed", "changed"):
            fake = FakeInputOS(); fake.file(self.source); fake.file(target)
            with self.subTest(fault=fault), patch.object(P, "os", fake):
                anchor = P.Input(self.source, 100, owner=0, mode=0o444); borrower = P.Input(target, 100, owner=0, mode=0o444, anchor=anchor)
                owned = borrower.slots[borrower.borrowed:]
                if fault == "closed": anchor.close()
                else:
                    changed = deepcopy(fake.nodes[str(self.source.parent.parent)]); changed.st_ino += 1000
                    fake.nodes[str(self.source.parent.parent)] = changed
                with self.assertRaises(ValueError): borrower.check()
                with self.assertRaises(ValueError): borrower.close()
                self.assertEqual(fake.closed[-len(owned):], list(reversed(owned)))
                anchor.close(); self.assertEqual(len(fake.closed), len(set(fake.closed)))

    def test_suffix_construction_append_and_close_failures_keep_anchor_owned(self):
        class RefusedAppend(list):
            def append(self, value): raise MemoryError("fake list append refusal")
        for fault in ("open", "read", "append", "close"):
            fake = FakeInputOS(); fake.file(self.source); target = self.source.with_name("github_tls") / "api-valid.pem"; fake.file(target)
            with self.subTest(fault=fault), patch.object(P, "os", fake):
                anchor = P.Input(self.source, 100, owner=0, mode=0o444); source_slots = list(anchor.slots)
                if fault == "open": fake.open_failure = str(target)
                if fault == "read": fake.read_failure = True
                if fault in ("open", "read"):
                    with self.assertRaises(OSError): P.Input(target, 100, owner=0, mode=0o444, anchor=anchor)
                elif fault == "append":
                    with self.assertRaises(MemoryError): P.acquire(RefusedAppend([anchor]), target, 100, hashlib.sha256(b"fictional").hexdigest())
                else:
                    borrower = P.Input(target, 100, owner=0, mode=0o444, anchor=anchor); fake.close_failure = True
                    with self.assertRaises(ValueError): borrower.close()
                    self.assertTrue(borrower.closed)
                self.assertTrue(set(fake.closed).isdisjoint(source_slots)); fake.read_failure = False; anchor.check()
                self.assertEqual(fake.closed, list(reversed(fake.opened[len(source_slots):])))
                anchor.close(); self.assertEqual(fake.closed, list(reversed(fake.opened)))


if __name__ == "__main__":
    unittest.main()
