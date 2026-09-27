"""Inert G route/receipt and fake-filesystem controls, never native evidence.

No compiler, GUI, service, network, credential or real journal is used. The
fictional wire rows below prove parser/ownership gates, not a successful run.
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


H = source_module("preflight_original_data_helpers", "tests/desktop/test_ubuntu_publication_lifecycle.py")
L = H.L
S = source_module("preflight_original_ci_data", "desktop/tools/ci_ubuntu_publication.py")


def handoff_data():
    value = H.github_handoff_data()
    value["shell"].pop("githubReadOnly")
    value["shell"]["githubPreflight"] = L.shell_github_preflight_selection()
    binaries = {name: {"path": "/task/" + name, "size": 12, "sha256": "c" * 64} for name in ("normal", "observer")}
    value["shell"].update(binaries=binaries, loaderPolicy={}, compiler={
        "sourceSha": value["sourceSha"], "runId": value["runId"], "attempt": "1", "features": L.SHELL_FEATURES,
        "manifestSha256": L.M, "protocolSha256": L.Q, "exportedArtifacts": deepcopy(binaries),
        "androidBuildMaterials": None, "androidBuildBindings": {}, "androidBuildPublication": None,
        "githubPreflight": L.shell_github_preflight_selection()})
    return value


def journal_bodies():
    intent = b'{"fictional-parser-data":true}\n'
    digest = hashlib.sha256(intent).hexdigest()
    run = L.canonical({"schemaVersion": 1, "intentSha256": digest, "runId": "9001", "attempt": 1})
    return intent, run


def receipt_data(case):
    cases = ("github-preflight-success", "github-preflight-response-loss", "github-preflight-pre-go-revocation",
             "github-preflight-journal-collision", "github-preflight-finality-refusal")
    case_index = cases.index(case)
    loss, revocation, collision, late = (case_index == value for value in (1, 2, 3, 4))
    negative_case = case_index >= 2
    marker = "defab"[case_index] * 32
    intent, run = journal_bodies()
    journal = {"marker": marker, "intentBytes": len(intent), "intentSha256": hashlib.sha256(intent).hexdigest(),
               "runBytes": None if revocation else len(run), "runSha256": None if revocation else hashlib.sha256(run).hexdigest(),
               "runId": None if revocation else "9001", "attempt": None if revocation else 1,
               "leafCount": 1 if revocation else 2, "runReadBeforeCollision": collision}
    peer = {key: True for key in ("acquisitionJoined", "spawned", "waited", "exitSuccess", "stdoutJoined", "stderrJoined",
                                  "stdoutEof", "stderrEof", "ready", "settled", "withinEndpoint", "protocolChecked")}
    peer.update({key: False for key in ("stopAttempted", "stdoutOverflow", "stderrOverflow")})
    peer.update(exitCode=0, stdoutBytes=4096, stderrBytes=0,
        control={**{key: True for key in ("acquired", "started", "joined", "writeComplete", "shutdownComplete",
                                          "productSettled", "withinEndpoint", "released")}, "failed": False},
        terminal={"schemaVersion": 1, "scope": "github-preflight-installed-peer-v1", "case": case.removeprefix("github-"),
            "state": "finished", "ownerTag": "a" * 16, "manifestSha256": L.SHELL_GITHUB_PAYLOADS["D-S"]["manifestSha256"],
            "peerSha256": L.SHELL_GITHUB_PREFLIGHT_PEER_PIN[1], "toolingSha": L.SHELL_GITHUB_PREFLIGHT_TOOLING_SHA,
            "callerSha256": L.SHELL_GITHUB_PREFLIGHT_CALLER[1], "primaryPort": 18443, "status": "passed",
            "requests": (20, 21, 10, 21, 15)[case_index], "posts": 0 if revocation else 1, "decryptedBytes": 1234,
            "intentBeforeResponse": not revocation, "allSocketsClosed": True, "inputsCheckedClosed": True, "code": None,
            "completion": {"bytes": 1, "eof": True, "closed": True, "primaryEmpty": True,
                           "primaryUnexpected": 0, "primaryClosed": True, "redirect": None}, "journal": journal})
    maps = [{"role": name, "path": row["paths"][0], **{key: row[key] for key in ("deviceMajor", "deviceMinor", "inode")}}
            for name, row in sorted(H.github_map_data()["D-S"].items())]
    kinds = (("connect", "prepare", "dispatch", "track"),
             ("connect", "prepare", "dispatch", "pending", "reconcile"),
             ("connect", "prepare", "dispatch"), ("connect", "prepare", "dispatch", "prepare", "dispatch"),
             ("connect", "prepare", "dispatch"))[case_index]
    originals = []
    for index, kind in enumerate(kinds):
        negative = negative_case and index == len(kinds) - 1
        before = negative and (revocation or collision)
        reason, effect, error, first = "none", "none", None, None
        if kind == "dispatch":
            reason, effect = ("tls-failed", "potentially-applied") if loss else ("none", "accepted")
        if negative:
            reason, effect = (("cleanup-unknown", "potentially-applied") if late else
                              ("cancelled", "not-sent") if revocation else ("response-invalid", "not-sent"))
            first = "protocol_error" if collision else "cancelled"
            error = "cleanup_unknown" if late else first
        originals.append({"operationId": ("github-read-" if index == 0 else "github-preflight-") + str(index + 7),
            "kind": kind, "manifestSha256": L.SHELL_GITHUB_PAYLOADS["D-S"]["manifestSha256"], "reason": reason, "effect": effect,
            "marker": None if index == 0 else marker, "terminal": True, "originalObserverJoined": True,
            "nativeSettled": True, "environmentClear": True, "readyObserved": index > 0 and not (negative and collision),
            "claimReturned": index > 0 and not (negative and collision), "goWritten": index > 0 and not before,
            "goClaimed": index > 0 and not before, "negative": negative, "wasUnknown": negative and late,
            "errorCode": error, "firstError": first, "exitCode": 70 if before else 0, "exitSignal": None,
            "ownedStopAttempted": False, "settledNs": (index + 1) * 10_000_000_000,
            "maps": [deepcopy(row) for row in maps if not (kind == "pending" or before)
                     or row["role"] not in ("libssl.so.3", "libcrypto.so.3")]})
    scheduling = {key: None for key in ("readyNs", "revocationReplyNs", "writerReleasedNs", "claimReturnedNs",
        "settlementReservedNs", "settlementEnteredNs", "cancelReplyNs", "cleanupEndpointNs", "unknownReceiptNs",
        "unknownDomNs", "settlementReleasedNs")}
    scheduling.update(mechanism="original-writer-scheduling" if revocation else "same-original-marker" if collision
        else "original-settlement-scheduling" if late else "none", kernelCloseFaultInjected=False,
        markerReused=collision, readyNs=25_000_000_000, claimReturnedNs=26_000_000_000)
    if revocation:
        scheduling.update(revocationReplyNs=26_000_000_000, writerReleasedNs=26_500_000_000, claimReturnedNs=27_000_000_000)
    if late:
        scheduling.update(settlementReservedNs=27_000_000_000, settlementEnteredNs=27_100_000_000,
            cancelReplyNs=27_300_000_000, cleanupEndpointNs=29_200_000_000, unknownReceiptNs=29_200_000_000,
            unknownDomNs=29_300_000_000, settlementReleasedNs=29_400_000_000)
    last_dispatch = [row for row in originals if row["kind"] == "dispatch"][-1]
    retirement = ({"mode": "late-unknown", "unknownPreserved": True, "newWorkDenied": True,
                   "initialDisplayedPending": 0, "lateNativeRecoveryRetained": True, "lateDisplayedPending": 0} if late else
                  {"mode": "disconnected", "authorityRemoved": True, "terminalPreserved": True, "recoveryPreserved": True})
    return {"schemaVersion": 1, "fixture": "github-preflight-installed-negative-v1" if negative_case else "github-preflight-installed-v2",
        "case": case, "sourceCommit": "a" * 40, "normalManifestSha256": L.M,
        "productManifestSha256": L.SHELL_GITHUB_PAYLOADS["D-S"]["manifestSha256"],
        "protocolSha256": L.Q, "toolingSha": L.SHELL_GITHUB_PREFLIGHT_TOOLING_SHA,
        "callerSha256": L.SHELL_GITHUB_PREFLIGHT_CALLER[1], "peerSha256": L.SHELL_GITHUB_PREFLIGHT_PEER_PIN[1],
        "project": {"cancelSettled": True, "registered": True, "snapshot": True},
        "nativeSession": {"connect": 1, "prepare": 2 if collision else 1, "dispatch": 2 if collision else 1,
            "observe": 0 if negative_case else 1, "disconnect": 0 if late else 1, "pending": 1 if loss else 0,
            "pendingReloaded": loss, "retainedStatus": True, "tokenFieldCleared": True, "reviewVisible": True,
            "consentObserved": True, "dispatchEffect": last_dispatch["effect"], "dispatchReason": last_dispatch["reason"],
            "runObserved": not negative_case, "retirement": retirement},
        "scheduling": scheduling, "originals": originals, "peer": peer,
        "quit": {"originalsFinal": True, "relayJoined": True, "gtkSettled": True, "exit": True},
        "notProven": list(L.SHELL_GITHUB_PREFLIGHT_NOT_PROVEN)}


def capture_data(case, receipt):
    return H.github_capture_data(case, receipt).replace(L.SHELL_GITHUB_MARKER, L.SHELL_GITHUB_PREFLIGHT_MARKER)


def projection_data(value, case, receipt):
    start = 200 + 100 * L.SHELL_GITHUB_PREFLIGHT_CASES.index(case)
    def directory(inode):
        return [1, inode, stat.S_IFDIR | 0o700, value["runnerUid"], value["runnerGid"], 3, 4096, 7, 9]
    dirs = {name: directory(start + index) for index, name in enumerate(("gui", "home", *L.SHELL_GITHUB_PREFLIGHT_JOURNAL_DIRECTORIES))}
    journal = receipt["peer"]["terminal"]["journal"]
    files = {journal["marker"] + "." + kind + ".json": {
        "identity": [1, start + 20 + index, stat.S_IFREG | 0o400, value["runnerUid"], value["runnerGid"], 1, journal[kind + "Bytes"], 7, 9],
        "size": journal[kind + "Bytes"], "sha256": journal[kind + "Sha256"]} for index, kind in enumerate(("intent",) if case.endswith("pre-go-revocation") else ("intent", "run"))}
    return {"schema": "installed-github-preflight-journal-v1", "sourceSha": value["sourceSha"], "runId": value["runId"],
        "attempt": value["attempt"], "case": case, "home": str(L.root_path(value) / ("gui-" + case) / "home"),
        "created": {"root": [1, 99, stat.S_IFDIR | 0o711, 0, 0], "gui": dirs["gui"][:5], "home": dirs["home"][:5]},
        "directories": dirs, "files": files, "journal": deepcopy(journal)}


class FakeJournalOS:
    """No operating-system descriptors or filesystem actions: eight/nine fake originals."""
    O_RDONLY, O_NOFOLLOW, O_CLOEXEC = os.O_RDONLY, os.O_NOFOLLOW, os.O_CLOEXEC
    O_NONBLOCK, O_DIRECTORY = os.O_NONBLOCK, os.O_DIRECTORY

    def __init__(self, value, case, receipt):
        self.data = projection_data(value, case, receipt)
        self.nodes, self.bodies, self.handles, self.closed, self.reads, self.opened = {}, {}, {}, [], [], []
        self.close_failure = self.read_failure = self.post_change = False
        self.root = str(L.root_path(value))
        self.gui, self.home = self.root + "/gui-" + case, self.data["home"]
        paths = {"gui": self.gui, "home": self.home, **{name: self.home + "/" + name for name in L.SHELL_GITHUB_PREFLIGHT_JOURNAL_DIRECTORIES}}
        self.nodes[self.root] = self.stat_row([*self.data["created"]["root"], 4, 4096, 7, 9])
        self.nodes.update({paths[name]: self.stat_row(row) for name, row in self.data["directories"].items()})
        journal = self.home + "/" + L.SHELL_GITHUB_PREFLIGHT_JOURNAL_DIRECTORIES[-1]
        for name, row in self.data["files"].items():
            path = journal + "/" + name
            self.nodes[path] = self.stat_row(row["identity"])
            self.bodies[path] = journal_bodies()[0 if name.endswith("intent.json") else 1]

    @staticmethod
    def stat_row(row):
        return SimpleNamespace(**dict(zip(("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"), row)))

    def path(self, name, dir_fd):
        return str(Path(self.handles[dir_fd][0]) / name) if dir_fd is not None else str(name)

    def stat(self, name, *, dir_fd=None, follow_symlinks=False):
        assert follow_symlinks is False
        return self.nodes[self.path(name, dir_fd)]

    def open(self, name, flags, *, dir_fd=None):
        assert flags & self.O_NOFOLLOW and flags & self.O_CLOEXEC
        path = self.path(name, dir_fd)
        fd = 100 + len(self.opened)
        self.handles[fd] = [path, self.nodes[path], 0]
        self.opened.append(fd)
        return fd

    def fstat(self, fd):
        if fd in self.closed:
            raise OSError(errno.EBADF, "fake consumed descriptor")
        return self.handles[fd][1]

    def listxattr(self, fd):
        return []

    def scandir(self, fd):
        parent = Path(self.handles[fd][0])
        names = [Path(path).name for path in self.nodes if Path(path).parent == parent]
        return _FakeEntries(names)

    def read(self, fd, maximum):
        self.reads.append(fd)
        if self.read_failure:
            raise OSError("injected original read failure")
        handle = self.handles[fd]
        raw = self.bodies[handle[0]][handle[2]:handle[2] + maximum]
        handle[2] += len(raw)
        if self.post_change and not raw:
            changed = deepcopy(self.nodes[handle[0]])
            changed.st_ino += 10000
            self.nodes[handle[0]] = changed
        return raw

    def close(self, fd):
        assert fd not in self.closed
        self.closed.append(fd)
        if self.close_failure and len(self.closed) == 1:
            raise OSError("injected original close failure")


class _FakeEntries:
    def __init__(self, names):
        self.entries = iter(SimpleNamespace(name=name) for name in names)
    def __enter__(self):
        return self.entries
    def __exit__(self, *args):
        return False


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
    for case in L.SHELL_GITHUB_PREFLIGHT_CASES:
        receipt = receipt_data(case)
        cases[case] = {"case": case, "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True, "maps": [], "githubPreflight": receipt}
        data = projection_data(value, case, receipt)
        journals[case] = {"capture": pin(L.canonical(data)), "originals": data}
        captures["shell-" + case + "-journal.json"] = journals[case]["capture"]
    captures["shell-cases.json"] = pin(L.canonical(cases))
    for phase in ("before", "after"):
        captures["shell-github-materials-" + phase + ".json"] = material_pin
        captures["shell-github-project-" + phase + ".json"] = project_pin
    github = {"selection": L.shell_github_preflight_selection(), "expectedMaps": H.github_map_data(),
        "materials": {"before": material_pin, "after": deepcopy(material_pin)}, "fixture": fixture,
        "casesCapture": captures["shell-cases.json"], "journals": journals,
        "normalDestinationAction": False, "normalTransportPositive": False, "remainingCoverage": list(L.SHELL_GITHUB_PREFLIGHT_NOT_PROVEN)}
    return {"state": "installed-github-preflight-synthetic-observed", "productQualified": False,
        "packageLifecycleQualified": False, "shellPackageBuilt": False, "serviceQualified": False,
        "sourceSha": value["sourceSha"], "consumerAttempt": value["attempt"], "unit": L.root_path(value).name + ".service",
        "githubPreflight": github, "cases": cases,
        "files": [{"path": "lifecycle-" + name, **captures.get(name, pin(b"fictional-export\n"))}
                  for name in sorted(L.public_files(value) | {"client.stdout", "client.stderr"})]}


class GitHubPreflightNativeRouteContracts(unittest.TestCase):

    def test_negative_lifecycle_first_failure_exit_and_scheduling_mutations_refuse(self):
        for case in L.SHELL_GITHUB_PREFLIGHT_CASES[2:]:
            receipt = receipt_data(case)
            last = len(receipt["originals"]) - 1
            self.assertEqual(L.shell_github_preflight_receipt(L.canonical(receipt), case, H.github_map_data()), receipt)
            mutations = [
                (("originals", last, "wasUnknown"), not receipt["originals"][last]["wasUnknown"]),
                (("originals", last, "goWritten"), not receipt["originals"][last]["goWritten"]),
                (("originals", last, "firstError"), "cleanup_unknown"),
                (("originals", last, "errorCode"), None),
                (("originals", last, "exitCode"), True),
                (("originals", last, "ownedStopAttempted"), 0),
                (("originals", last, "settledNs"), True),
                (("nativeSession", "runObserved"), True),
                (("nativeSession", "retirement", "mode"), "cleared"),
                (("scheduling", "kernelCloseFaultInjected"), True),
                (("scheduling", "markerReused"), not receipt["scheduling"]["markerReused"]),
                (("peer", "terminal", "journal", "leafCount"), True),
                (("peer", "terminal", "journal", "runReadBeforeCollision"), not case.endswith("journal-collision")),
            ]
            for name, value in receipt["scheduling"].items():
                if name.endswith("Ns"):
                    mutations.append((("scheduling", name), True if value is not None else 1))
            if case.endswith("pre-go-revocation"):
                mutations += [(("scheduling", "writerReleasedNs"), receipt["scheduling"]["readyNs"] - 1),
                              (("originals", last, "goClaimed"), True), (("peer", "terminal", "posts"), 1),
                              (("peer", "terminal", "journal", "runId"), "9001")]
            elif case.endswith("journal-collision"):
                mutations += [(("originals", last, "readyObserved"), True), (("originals", last, "claimReturned"), True),
                              (("originals", last, "reason"), "network-unavailable")]
            else:
                mutations += [(("scheduling", "settlementReleasedNs"), receipt["scheduling"]["unknownDomNs"] - 1),
                              (("scheduling", "cleanupEndpointNs"), receipt["scheduling"]["cancelReplyNs"]),
                              (("nativeSession", "retirement", "initialDisplayedPending"), 1),
                              (("nativeSession", "retirement", "lateDisplayedPending"), 1),
                              (("nativeSession", "retirement", "unknownPreserved"), False),
                              (("nativeSession", "retirement", "lateNativeRecoveryRetained"), False)]
            for path, bad in mutations:
                changed = deepcopy(receipt); H.github_data_set(changed, path, bad)
                with self.subTest(case=case, path=path), self.assertRaises(L.Refused):
                    L.shell_github_preflight_receipt(L.canonical(changed), case, H.github_map_data())

    def test_collision_error_correspondence_and_owned_pre_go_stop_are_not_success(self):
        case = "github-preflight-journal-collision"
        for error, reason in (("protocol_error", "response-invalid"), ("engine_failed", "network-unavailable"), ("io_error", "network-unavailable")):
            receipt = receipt_data(case)
            receipt["originals"][-1].update(errorCode=error, firstError=error, reason=reason)
            receipt["nativeSession"]["dispatchReason"] = reason
            self.assertEqual(L.shell_github_preflight_receipt(L.canonical(receipt), case, H.github_map_data()), receipt)
        for case in ("github-preflight-pre-go-revocation", "github-preflight-journal-collision"):
            receipt = receipt_data(case)
            receipt["originals"][-1].update(exitCode=None, exitSignal=9, ownedStopAttempted=True)
            self.assertEqual(L.shell_github_preflight_receipt(L.canonical(receipt), case, H.github_map_data()), receipt)
            receipt["originals"][-1]["ownedStopAttempted"] = False
            with self.assertRaises(L.Refused):
                L.shell_github_preflight_receipt(L.canonical(receipt), case, H.github_map_data())

    def test_all_five_journal_rosters_hold_exact_one_or_two_original_leaves(self):
        value = handoff_data()
        for case, leaves in zip(L.SHELL_GITHUB_PREFLIGHT_CASES, (2, 2, 1, 2, 2)):
            receipt = receipt_data(case); fake = FakeJournalOS(value, case, receipt)
            with self.subTest(case=case), patch.object(L, "os", fake), patch.object(L, "directory"), \
                 patch.object(L, "_ROOT", L.root_path(value)), \
                 patch.dict(L._SHELL_GITHUB_PREFLIGHT_HOMES, {case: fake.data["created"]}, clear=True):
                self.assertEqual(L._shell_github_preflight_journal_snapshot(value, case, receipt), fake.data)
            self.assertEqual(len(fake.opened), 7 + leaves)
            self.assertEqual(fake.closed, list(reversed(fake.opened)))
            self.assertEqual(set(fake.reads), set(fake.opened[-leaves:]))

    def test_revocation_extra_run_refuses_before_any_private_leaf_read(self):
        value, case = handoff_data(), "github-preflight-pre-go-revocation"
        receipt = receipt_data(case); fake = FakeJournalOS(value, case, receipt)
        intent = next(iter(fake.bodies))
        extra = intent.removesuffix(".intent.json") + ".run.json"
        fake.nodes[extra] = fake.nodes[intent]
        fake.bodies[extra] = journal_bodies()[1]
        with patch.object(L, "os", fake), patch.object(L, "directory"), patch.object(L, "_ROOT", L.root_path(value)), \
             patch.dict(L._SHELL_GITHUB_PREFLIGHT_HOMES, {case: fake.data["created"]}, clear=True), self.assertRaises(L.Refused):
            L._shell_github_preflight_journal_snapshot(value, case, receipt)
        self.assertEqual(fake.reads, [])
        self.assertEqual(fake.closed, list(reversed(fake.opened)))

    def test_fixed_route_requires_same_job_five_cases_and_original_source_event(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64", "GITHUB_EVENT_NAME": "push", "GITHUB_REF": S.SHELL_GITHUB_PREFLIGHT_REF,
            "GITHUB_JOB": "compile", "MRK_UBUNTU_PUBLICATION_VERIFY": "1", "GITHUB_SHA": "a" * 40,
            "MRK_PUSH_EVENT_AFTER": "a" * 40, "GITHUB_RUN_ID": "17", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit"}
        for case in ("compile", "observe"):
            selected = {**env, "MRK_INSTALLED_SHELL_CASE": case}
            self.assertEqual(S.route(selected), env["GITHUB_SHA"])
            for key, bad in (("GITHUB_JOB", "observe"), ("MRK_INSTALLED_SHELL_CASE", "github-preflight-success"),
                             ("GITHUB_EVENT_NAME", "workflow_dispatch"), ("RUNNER_ENVIRONMENT", "self-hosted"),
                             ("GITHUB_REF", "refs/heads/main"), ("MRK_PUSH_EVENT_AFTER", "b" * 40),
                             ("MRK_INSTALLED_CASE", "positive")):
                with self.subTest(case=case, key=key), self.assertRaises(S.D.Refused):
                    S.route({**selected, key: bad})

    def test_exact_additive_scope_keeps_ordinary_readonly_and_boundaries_separate(self):
        value = handoff_data()
        self.assertEqual(L.shell_cases(value), ("github-preflight-success", "github-preflight-response-loss",
            "github-preflight-pre-go-revocation", "github-preflight-journal-collision", "github-preflight-finality-refusal"))
        self.assertEqual((len(L.SHELL_ORDINARY_CASES), len(L.SHELL_ANDROID_CASES), len(L.SHELL_GITHUB_CASES), len(L.SHELL_GITHUB_BOUNDARY_CASES)), (21, 4, 22, 2))
        self.assertIsNone(L.SHELL_GITHUB_BOUNDARY_HOST_PROFILE)
        self.assertIsNone(L.shell_handoff(value, []))
        self.assertEqual(L.result_state(value), "installed-github-preflight-synthetic-observed")
        self.assertEqual(len(L.public_files(value)), 89)
        self.assertFalse(L.shell_android(value) or L.shell_normal_boundaries(value))
        for field in ("ordinary21", "projectRecovery", "githubReadOnly", "androidPublication", "localTransport"):
            bad = deepcopy(value); bad["shell"][field] = {}
            with self.subTest(field=field), self.assertRaises(L.Refused): L.shell_handoff(bad, [])
        for profile in (L.SHELL_RECOVERY_PROFILE, L.SHELL_RECOVERY_NEGATIVE_PROFILE):
            recovery = deepcopy(value)
            recovery["shell"].pop("githubPreflight")
            recovery["shell"]["projectRecovery"] = L.shell_recovery_selection(profile)
            recovery["shell"]["compiler"].pop("githubPreflight")
            recovery["shell"]["compiler"]["projectRecovery"] = L.shell_recovery_compile_selection()
            self.assertIsNone(L.shell_handoff(recovery, []))
            self.assertEqual(L.shell_cases(recovery), tuple(recovery["shell"]["projectRecovery"]["cases"]))
            mixed = deepcopy(recovery); mixed["shell"]["githubPreflight"] = L.shell_github_preflight_selection()
            for parser in (L.shell_recovery, L.shell_cases):
                with self.subTest(profile=profile, parser=parser.__name__), self.assertRaises(L.Refused): parser(mixed)
            with self.subTest(profile=profile), self.assertRaises(L.Refused): L.shell_handoff(mixed, [])
            recovery["shell"]["compiler"]["githubPreflight"] = L.shell_github_preflight_selection()
            with self.subTest(profile=profile, compiler=True), self.assertRaises(L.Refused): L.shell_handoff(recovery, [])
        mixed = deepcopy(value); mixed["shell"]["compiler"]["projectRecovery"] = L.shell_recovery_compile_selection()
        with self.assertRaises(L.Refused): L.shell_handoff(mixed, [])
        for case in L.SHELL_GITHUB_PREFLIGHT_CASES:
            env = L.shell_environment(value, case)
            self.assertEqual(env["HOME"], str(L.root_path(value) / ("gui-" + case) / "home"))
            self.assertFalse(set(env) & {"GH_TOKEN", "GITHUB_TOKEN", "HTTPS_PROXY", "SSLKEYLOGFILE", "SSL_CERT_FILE", "PYTHONPATH"})
            self.assertIn("shell-" + case + "-journal.json", L.public_files(value))

    def test_compiler_selection_presence_absence_and_nonempty_tooling_are_exact(self):
        selection = L.shell_github_preflight_selection()
        for ref in (S.SHELL_REF, S.SHELL_RECOVERY_REF, S.SHELL_GITHUB_REF, S.SHELL_GITHUB_BOUNDARY_REF, S.SHELL_GITHUB_PREFLIGHT_REF):
            with patch.dict(S.os.environ, {"GITHUB_REF": ref}, clear=True):
                chosen = S.installed_shell_preflight_selection(L)
                self.assertEqual(chosen, selection if ref == S.SHELL_GITHUB_PREFLIGHT_REF else None)
                env = {"PATH": "/inert"}
                S.installed_shell_preflight_environment(env, L, chosen)
                self.assertEqual(env.get("MRK_GITHUB_PREFLIGHT_TOOLING_SHA"), L.SHELL_GITHUB_PREFLIGHT_TOOLING_SHA if chosen else None)
                record = {"githubPreflight": selection} if chosen else {}
                S.installed_shell_preflight_record(record, L, chosen)
                with self.assertRaises(S.D.Refused):
                    S.installed_shell_preflight_record({} if chosen else {"githubPreflight": selection}, L, chosen)
        with self.assertRaises(S.D.Refused): S.installed_shell_preflight_environment({"MRK_GITHUB_PREFLIGHT_TOOLING_SHA": ""}, L, selection)
        compiler = handoff_data()["shell"]["compiler"]
        S.installed_shell_preflight_record(compiler, L, selection, android_contract=True)
        for field, bad in (("androidBuildMaterials", {}), ("androidBuildBindings", []), ("androidBuildPublication", {}),
                           ("githubReadOnly", {}), ("ordinary21", {}), ("projectRecovery", {}), ("androidPreparation", {})):
            with self.subTest(field=field), self.assertRaises(S.D.Refused):
                S.installed_shell_preflight_record({**compiler, field: bad}, L, selection, android_contract=True)
        recovery = {key: deepcopy(value) for key, value in compiler.items() if key != "githubPreflight"}
        recovery["projectRecovery"] = L.shell_recovery_compile_selection()
        S.installed_shell_scope_record(recovery, L, recovery["projectRecovery"], android_contract=True)
        S.installed_shell_preflight_record(recovery, L, None, android_contract=True)
        mixed = {**recovery, "githubPreflight": selection}
        with self.assertRaises(S.D.Refused):
            S.installed_shell_scope_record(mixed, L, recovery["projectRecovery"], android_contract=True)
        with self.assertRaises(S.D.Refused): S.installed_shell_preflight_record(mixed, L, None, android_contract=True)
        wrong = deepcopy(selection); wrong["toolingSha"] = "0" * 40
        with self.assertRaises(S.D.Refused): S.installed_shell_preflight_record({"githubPreflight": wrong}, L, wrong)

    def test_exact_source_peer_and_rendered_caller_bindings_precede_preparation(self):
        selection = L.shell_github_preflight_selection()
        self.assertEqual({row["path"] for row in selection["peerSources"]}, {
            "desktop/src-tauri/tests/fixtures/" + path for path in ("github_preflight_peer.py", "github_tls_peer.py", "github_tls/api-valid.pem", "github_tls/server-key.pem")})
        self.assertEqual(set(L.shell_github_preflight_peer_pins()), {"github_preflight_peer.py", "github_tls_peer.py", "mobile-preflight.yml", "github_tls/api-valid.pem", "github_tls/server-key.pem"})
        raw = (SOURCE / selection["caller"]["template"]["path"]).read_bytes()
        self.assertEqual((raw.count(b"__MOBILE_RELEASE_KIT_REPOSITORY__"), raw.count(b"__MOBILE_RELEASE_KIT_SHA__")), (1, 2))
        rendered = raw.replace(b"__MOBILE_RELEASE_KIT_REPOSITORY__", b"Apdelrahman1911/mobile-release-kit").replace(
            b"__MOBILE_RELEASE_KIT_SHA__", L.SHELL_GITHUB_PREFLIGHT_TOOLING_SHA.encode("ascii"))
        self.assertEqual((len(rendered), hashlib.sha256(rendered).hexdigest()), L.SHELL_GITHUB_PREFLIGHT_CALLER)
        S.installed_shell_preflight_sources(SOURCE, L, selection)
        with patch.object(S.D, "file_record", return_value={"size": 1, "sha256": "0" * 64}), self.assertRaises(S.D.Refused):
            S.installed_shell_preflight_sources(SOURCE, L, selection)
        with patch.object(L, "SHELL_GITHUB_PREFLIGHT_PEER_PIN", None), self.assertRaises(L.Refused): L.shell_github_preflight_selection()

    def test_typed_five_case_original_journeys_keep_pending_and_exact_posts(self):
        maps = H.github_map_data()
        for case in L.SHELL_GITHUB_PREFLIGHT_CASES:
            receipt = receipt_data(case)
            self.assertEqual(L.shell_github_preflight_receipt(L.canonical(receipt), case, maps), receipt)
            self.assertEqual(L.shell_result(capture_data(case, receipt), b"", case, 0, maps)["githubPreflight"], receipt)
            self.assertEqual(len(receipt["originals"]), (4, 5, 3, 5, 3)[L.SHELL_GITHUB_PREFLIGHT_CASES.index(case)])
            self.assertEqual(receipt["peer"]["terminal"]["posts"], 0 if case.endswith("pre-go-revocation") else 1)
            for raw in (capture_data(case, receipt).replace(L.SHELL_GITHUB_PREFLIGHT_MARKER, L.SHELL_GITHUB_MARKER),
                        capture_data(case, receipt) + b"MRK_EXTRA=unadmitted\n"):
                with self.assertRaises(L.Refused): L.shell_result(raw, b"", case, 0, maps)
            with self.assertRaises(L.Refused): L.shell_result(capture_data(case, receipt), b"", case, 1, maps)
        loss = receipt_data("github-preflight-response-loss")
        self.assertEqual([row["kind"] for row in loss["originals"]], ["connect", "prepare", "dispatch", "pending", "reconcile"])
        self.assertEqual(loss["nativeSession"]["pending"], 1)
        self.assertTrue(loss["nativeSession"]["pendingReloaded"])

    def test_lifecycle_source_and_finality_mutations_refuse(self):
        case = "github-preflight-response-loss"
        receipt = receipt_data(case)
        mutations = ((("sourceCommit",), "0" * 40), (("toolingSha",), "f" * 40), (("callerSha256",), "f" * 64),
            (("peerSha256",), "f" * 64), (("schemaVersion",), True), (("nativeSession", "pending"), 0),
            (("nativeSession", "pendingReloaded"), False), (("nativeSession", "dispatchEffect"), "accepted"),
            (("originals", 3, "marker"), "f" * 32), (("originals", 3, "readyObserved"), False),
            (("originals", 3, "goWritten"), False), (("originals", 3, "nativeSettled"), False),
            (("originals", 3, "operationId"), receipt["originals"][2]["operationId"]),
            (("originals", 3, "originalObserverJoined"), False), (("originals", 2, "effect"), "none"),
            (("peer", "control", "released"), False), (("peer", "stdoutEof"), False),
            (("peer", "terminal", "requests"), 20), (("peer", "terminal", "posts"), 2),
            (("peer", "terminal", "inputsCheckedClosed"), False), (("peer", "terminal", "completion", "eof"), False),
            (("quit", "originalsFinal"), False), (("notProven",), []))
        for path, bad in mutations:
            changed = deepcopy(receipt); H.github_data_set(changed, path, bad)
            with self.subTest(path=path), self.assertRaises(L.Refused):
                L.shell_github_preflight_receipt(L.canonical(changed), case, H.github_map_data())
        for changed in (receipt["originals"][:3] + receipt["originals"][4:], receipt["originals"] + [receipt["originals"][3]]):
            with self.assertRaises(L.Refused):
                L.shell_github_preflight_receipt(L.canonical({**receipt, "originals": changed}), case, H.github_map_data())

    def test_pending_map_subset_is_actual_and_does_not_relax_other_originals(self):
        case = "github-preflight-response-loss"
        receipt, maps = receipt_data(case), H.github_map_data()
        rows = receipt["originals"][0]["maps"]
        mandatory = [row for row in rows if row["role"] not in ("libssl.so.3", "libcrypto.so.3")]
        optional = [row for row in rows if row["role"] in ("libssl.so.3", "libcrypto.so.3")]
        for extra in ([], optional[:1], optional):
            changed = deepcopy(receipt)
            changed["originals"][3]["maps"] = sorted(mandatory + extra, key=lambda row: row["role"])
            L.shell_github_preflight_receipt(L.canonical(changed), case, maps)
        for bad in (mandatory[:-1], mandatory + [mandatory[0]], [{**row, "inode": row["inode"] + 1} for row in mandatory],
                    [{**row, "path": "/unadmitted"} for row in mandatory]):
            changed = deepcopy(receipt); changed["originals"][3]["maps"] = bad
            with self.assertRaises(L.Refused): L.shell_github_preflight_receipt(L.canonical(changed), case, maps)
        changed = deepcopy(receipt); changed["originals"][2]["maps"] = mandatory
        with self.assertRaises(L.Refused): L.shell_github_preflight_receipt(L.canonical(changed), case, maps)
        with self.assertRaises(L.Refused): L._shell_original_child_map(L.canonical(mandatory), maps["D-S"])

    def test_journal_data_requires_fixed_home_two_immutable_leaves_and_canonical_run(self):
        value, case = handoff_data(), "github-preflight-success"
        receipt = receipt_data(case); data = projection_data(value, case, receipt)
        self.assertEqual(L.shell_github_preflight_journal_data(value, case, L.canonical(data), receipt), data)
        name = data["journal"]["marker"] + ".run.json"
        for path, bad in ((("home",), "/other/home"), (("directories", ".local", 3), 0),
                         (("directories", ".local", 1), data["directories"]["home"][1]),
                         (("files", name, "identity", 5), 2), (("files", name, "identity", 2), stat.S_IFREG | 0o600),
                         (("files", name, "identity", 0), 2), (("files", name, "size"), True),
                         (("journal", "runId"), "9002"), (("journal", "runSha256"), "e" * 64)):
            changed = deepcopy(data); H.github_data_set(changed, path, bad)
            with self.subTest(path=path), self.assertRaises(L.Refused):
                L.shell_github_preflight_journal_data(value, case, L.canonical(changed), receipt)
        journal = deepcopy(data["journal"]); journal["runSha256"] = "e" * 64
        with self.assertRaises(L.Refused): L.shell_github_preflight_journal_receipt(journal, journal["marker"], case)
        changed = deepcopy(data); changed["files"]["another.intent.json"] = deepcopy(changed["files"][name])
        with self.assertRaises(L.Refused): L.shell_github_preflight_journal_data(value, case, L.canonical(changed), receipt)

    def test_journal_readback_holds_all_originals_through_post_and_checked_close(self):
        value, case = handoff_data(), "github-preflight-success"
        receipt = receipt_data(case); fake = FakeJournalOS(value, case, receipt)
        with patch.object(L, "os", fake), patch.object(L, "directory"), patch.object(L, "_ROOT", L.root_path(value)), \
             patch.dict(L._SHELL_GITHUB_PREFLIGHT_HOMES, {case: fake.data["created"]}, clear=True):
            self.assertEqual(L._shell_github_preflight_journal_snapshot(value, case, receipt), fake.data)
        self.assertEqual(len(fake.opened), 9)
        self.assertEqual(fake.closed, list(reversed(fake.opened)))
        self.assertEqual(set(fake.reads), set(fake.opened[-2:]))

    def test_journal_failure_closes_every_original_and_never_reads_alias_or_extra_roster(self):
        value, case = handoff_data(), "github-preflight-success"
        receipt = receipt_data(case)
        for fault in ("read", "post", "close", "extra", "alias", "symlink", "mode"):
            fake = FakeJournalOS(value, case, receipt)
            if fault in ("read", "post", "close"):
                setattr(fake, {"read": "read_failure", "post": "post_change", "close": "close_failure"}[fault], True)
            elif fault == "extra":
                fake.nodes[fake.home + "/.local/extra"] = deepcopy(fake.nodes[fake.home])
            else:
                paths = list(fake.bodies)
                if fault == "alias": fake.nodes[paths[1]].st_ino = fake.nodes[paths[0]].st_ino
                elif fault == "symlink": fake.nodes[paths[1]].st_mode = stat.S_IFLNK | 0o777
                else: fake.nodes[paths[1]].st_mode = stat.S_IFREG | 0o600
            with self.subTest(fault=fault), patch.object(L, "os", fake), patch.object(L, "directory"), \
                 patch.object(L, "_ROOT", L.root_path(value)), \
                 patch.dict(L._SHELL_GITHUB_PREFLIGHT_HOMES, {case: fake.data["created"]}, clear=True), \
                 self.assertRaises((L.Refused, OSError)):
                L._shell_github_preflight_journal_snapshot(value, case, receipt)
            self.assertEqual(fake.closed, list(reversed(fake.opened)))
            if fault in ("extra", "alias", "symlink", "mode"): self.assertEqual(fake.reads, [])

    def test_failed_unsettled_or_wrong_source_case_never_opens_a_private_journal(self):
        value, case = handoff_data(), "github-preflight-success"
        command = {"phase": "shell-" + case, "argv": L.shell_argv(value, case), "exitCode": 0}
        for fault in ("failed", "owner", "command", "source", "missing-native"):
            current = deepcopy(command)
            observed = {"exitCode": 0, "githubPreflight": receipt_data(case)}
            if fault == "command": current["exitCode"] = 1
            if fault == "source": observed["githubPreflight"]["sourceCommit"] = "b" * 40
            if fault == "missing-native": observed.pop("githubPreflight")
            with self.subTest(fault=fault), patch.object(L, "_FAILED", fault == "failed"), \
                 patch.object(L, "_OWNER", None if fault == "owner" else object()), patch.object(L, "_END", 20), \
                 patch.object(L.time, "monotonic", return_value=10), patch.object(L, "_COMMANDS", [current]), \
                 patch.dict(L._SHELL_GITHUB_PREFLIGHT_COMPLETED, {}, clear=True), \
                 patch.object(L, "_shell_github_preflight_journal_snapshot") as snapshot, self.assertRaises(L.Refused):
                L._shell_github_preflight_after(value, case, observed)
            snapshot.assert_not_called()

    def test_final_recheck_requires_all_five_distinct_homes_before_any_export(self):
        value = handoff_data()
        completed = {case: (receipt_data(case), projection_data(value, case, receipt_data(case))) for case in L.SHELL_GITHUB_PREFLIGHT_CASES}
        homes = {case: row[1]["created"] for case, row in completed.items()}
        for fault in (None, "earlier-drift", "missing-case"):
            current = deepcopy(completed)
            if fault == "missing-case": current.pop(L.SHELL_GITHUB_PREFLIGHT_CASES[1])
            def snapshot(v, case, receipt):
                data = deepcopy(completed[case][1])
                if fault == "earlier-drift" and case == L.SHELL_GITHUB_PREFLIGHT_CASES[0]: data["directories"]["home"][8] += 1
                return data
            with self.subTest(fault=fault), patch.object(L, "_FAILED", False), patch.object(L, "_END", 20), \
                 patch.object(L.time, "monotonic", return_value=10), patch.dict(L._SHELL_GITHUB_PREFLIGHT_COMPLETED, current, clear=True), \
                 patch.dict(L._SHELL_GITHUB_PREFLIGHT_HOMES, homes, clear=True), \
                 patch.object(L, "_shell_github_preflight_journal_snapshot", side_effect=snapshot), patch.object(L, "_retain") as retained:
                if fault is None:
                    L._shell_github_preflight_journals_final(value)
                    self.assertEqual([call.args[0] for call in retained.call_args_list], ["shell-" + case + "-journal.json" for case in L.SHELL_GITHUB_PREFLIGHT_CASES])
                else:
                    with self.assertRaises(L.Refused): L._shell_github_preflight_journals_final(value)
                    retained.assert_not_called()

    def test_closed_ci_receipt_requires_original_journal_exports_and_unproven_limits(self):
        observed = closed_data()
        self.assertEqual(S.shell_github_preflight_observation(observed, L, runner_uid=1001, runner_gid=1001), observed["githubPreflight"])
        case = L.SHELL_GITHUB_PREFLIGHT_CASES[1]
        mutations = ((("state",), "installed-github-readonly-synthetic-observed"), (("serviceQualified",), True),
            (("githubReadOnly",), {}), (("projectRecovery",), {}), (("githubPreflight", "remainingCoverage"), []),
            (("githubPreflight", "journals", case, "capture", "sha256"), "0" * 64),
            (("githubPreflight", "journals", case, "originals", "home"), "/other/home"),
            (("cases", case, "githubPreflight", "nativeSession", "pendingReloaded"), False),
            (("files",), observed["files"][:-1]))
        for path, bad in mutations:
            changed = deepcopy(observed); H.github_data_set(changed, path, bad)
            with self.subTest(path=path), self.assertRaises((L.Refused, S.D.Refused)):
                S.shell_github_preflight_observation(changed, L, runner_uid=1001, runner_gid=1001)
        with self.assertRaises(S.D.Refused): S.shell_github_observation(observed, L)
        with self.assertRaises(S.D.Refused): S.shell_github_preflight_observation(H.github_closed_observation_data(), L, runner_uid=1001, runner_gid=1001)

    def test_fixed_workflow_gate_and_prerequisite_routes_remain_additive(self):
        workflow = (SOURCE / S.WORKFLOW).read_text()
        first = workflow.split("      - name: Require one exact disposable preparation route", 1)[1].split("      - name:", 1)[0]
        self.assertIn("id: route", first)
        self.assertIn(S.SHELL_GITHUB_PREFLIGHT_REF + ":compile", first)
        self.assertIn("printf 'native=true\\n'", first)
        self.assertEqual(workflow.count("if: steps.route.outputs.native == 'true'") + workflow.count("if: always() && steps.route.outputs.native == 'true'"), 14)
        self.assertIn("if: steps.route.outputs.native == 'true' || github.ref == 'refs/heads/verify/desktop-shell-host-metadata'", workflow)
        self.assertNotIn("MRK_GITHUB_PREFLIGHT_TOOLING_SHA:", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("permissions:\n  contents: read\n  actions: read", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        policy, observer = S.local("hosted_glibc_policy"), S.local("observe_hosted_python")
        self.assertIn((S.SHELL_GITHUB_PREFLIGHT_REF, "compile", "compile"), policy.ROUTES)
        for case in ("compile", "observe"):
            self.assertIn((S.SHELL_GITHUB_PREFLIGHT_REF, case, "compile"), observer.ROUTES)
        self.assertNotIn((S.SHELL_GITHUB_PREFLIGHT_REF, "compile", "observe"), policy.ROUTES)
        pins = re.findall(r"MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256: '([0-9a-f]{64})'", workflow)
        self.assertEqual(pins, [hashlib.sha256((SOURCE / L.ENTRY).read_bytes()).hexdigest()] * 5)

    def test_original_success_finality_and_accounting_gates_precede_journal_work(self):
        source = (SOURCE / L.ENTRY).read_text()
        unit = source.split("def unit_start():", 1)[1].split("\ndef ", 1)[0]
        self.assertLess(unit.index("cases[case] = shell_result("), unit.index("_shell_github_preflight_after(value"))
        self.assertLess(unit.index("_shell_github_preflight_after(value"), unit.index("_shell_fixtures_final(value"))
        self.assertIn("verify_finality(start, stop, client_result.returncode, github=shell_github(value))", source)
        self.assertIn("verify_finality(start, stop, 0, github=shell_github(value))", source)
        self.assertIn("required += sum(bound for kinds in journal_kinds for _, bound in kinds)", source)
        self.assertIn("github_nodes += count * 4 + sum(map(len, journal_kinds))", source)
        kinds = [L._shell_github_preflight_journal_kinds(case) for case in L.SHELL_GITHUB_PREFLIGHT_CASES]
        self.assertEqual(sum(bound for row in kinds for _, bound in row), 5 * 8192 + 4 * 512)
        self.assertEqual(5 * 4 + sum(map(len, kinds)), 29)
        supervisor = (SOURCE / "desktop/src-tauri/src/supervisor.rs").read_text()
        self.assertIn("pub const CLEANUP_TIME: Duration = Duration::from_secs(2);", supervisor)
        tree = ast.parse(source)
        snapshot = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_shell_github_preflight_journal_snapshot")
        names = {ast.unparse(n.func) for n in ast.walk(snapshot) if isinstance(n, ast.Call)}
        self.assertFalse(names & {"os.chmod", "os.unlink", "os.remove", "shutil.rmtree", "command"})
        self.assertIn("os.open", names); self.assertIn("_shell_github_close", names)


if __name__ == "__main__":
    unittest.main()
