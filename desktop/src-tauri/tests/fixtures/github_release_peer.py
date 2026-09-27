"""Three finite installed release observations, never a general HTTP server.

SOURCE is not execution permission. The reviewed installed-shell original Peer
owns this child, all three pipes, the unchanged 16-second endpoint and finality.
Only the synthetic owner/app account and one noncredential token are accepted.
No GitHub or Store request is made by this fixture; its sole listener is local.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import socket
import ssl
import stat
import sys
import types

CASES = ("release-normal-pending", "release-response-loss", "release-pre-go-revocation")
REQUESTS = dict(zip(CASES, (4, 25, 14)))
SCOPE = "github-release-installed-peer-v1"
MODE = "github-release-installed-tls-v1"
TOOLING = "4c89f77c7a1e3f0b538a99ab12069b245484205d"  # Observation source candidate; not delivered tooling.
CALLERS = {
    "candidate": (2322, "693119d27471d9894c250cc4326547258afba446fc40620a1923b334563a8837"),
    "external-testing": (3098, "82dc6d39910a4363b9432fbbda96f51f1a6c4ac543670a40bee8fb6a0c813397"),
    "production-submit": (3835, "b16776c8de7862eaba316d330a05cacb2c36f338f22880897dcdca8f53157188"),
}
MANIFEST = "90a4ff34a02f3bc72d1909261dbe9d77c9d0fbbf8c89d33fb296c976eaedaadb"
N = "acebf377f172ef49b79eab4a0edbf72c2222a869cacb24b21d234551da6152ba"
PYTHON = "/var/lib/mobile-release-kit/versions/x86_64-unknown-linux-gnu/" + N + "/python/bin/python3"
SUPPORT_SHA = "5e917b35b320b05cb3c7fcf1bc7ad02ab9fcd44e29f743b53a8471da96ac475c"
SOURCE, TREE, ORIGINAL = "a" * 40, "e" * 40, "f" * 40
REPOSITORY = {"id": 22, "full_name": "owner/app", "default_branch": "main", "visibility": "private",
              "archived": False, "permissions": {"pull": True, "push": True, "admin": False}}
ACCOUNT = {"id": 11, "login": "owner"}
VERSION = b"VERSION_NAME=2.0.0\nBUILD_NUMBER=99\n"
CONFIGURATION = {
    "schemaVersion": 1,
    "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
    "source": {"candidateBranch": "main", "productionBranch": "production"},
    "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified",
                "externalTrack": {"name": "beta", "kind": "closed"}},
    "ios": {"enabled": True, "bundleId": "org.fixture.app", "identityStatus": "unverified",
            "externalTestFlightGroup": "External fixtures", "review": {"usesNonExemptEncryption": False, "demoAccountRequired": True}},
    "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": ["en-US"]},
    "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
    "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
}
CONFIG = json.dumps(CONFIGURATION, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()

# Exact fixed path accounting (each slash-separated directory is an original):
# source6 + support1 + three callers1 each + cert/key2 each =14 held FDs.
# Only source's common four-directory prefix is borrowed by journal witnesses.
# Normal: final directory6 + family parent5 =>25 held. Response-loss: intent7,
# run7, final directory6, parent5 =>39. Revocation: discovery6 + intent7 + final6
# + parent5 =>38. The unchanged cap64 also covers stdio3 (control is stdin),
# listener/accepted/unexpected <=3 and <=4 transient import/cert/scandir FDs:
# conservative peaks35/49/48. Connections close before accepting the next one;
# SSL MemoryBIO/select create no descriptors. No cap increase or dropped check.
INPUT_FD_PEAKS = dict(zip(CASES, (25, 39, 38)))


def selected(case):
    require(case in CASES, "release-case")
    if case == "release-pre-go-revocation":
        return "candidate", "android", "main", "Mobile internal candidate"
    return "production-submit", "ios", "production", "Mobile production submission"


def workflow(case):
    stage, _, _, name = selected(case)
    return {"id": 33, "path": ".github/workflows/mobile-" + stage + ".yml", "name": name, "state": "active"}


def require(value: bool, code: str) -> None:
    if not value:
        raise ValueError(code)


def identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


class Input:
    """Retained read-only witness, borrowing only the first source's directories.

    The source anchor stays strongly held until reverse-acquisition cleanup has
    checked/closed all borrowers. A borrower owns only its newly opened suffix;
    no source leaf, journal leaf, duplicate FD or reopened path is substituted.
    """

    def __init__(self, path: Path, maximum: int, *, owner: int, mode: int,
                 private_parent: bool = False, directory: bool = False, anchor: Input | None = None):
        self.slots = []
        self.before = []
        self.anchor = anchor
        self.borrowed = 0
        self.parts = path.parts
        self.raw = b""
        self.closed = False
        self.directory = directory
        self.roster = None
        require(path.is_absolute() and path == Path(*self.parts)
                and 2 <= len(self.parts) <= 16 and ".." not in self.parts, "input-path")
        try:
            if anchor is not None:
                require(not anchor.closed and anchor.anchor is None and anchor.borrowed == 0
                        and not anchor.directory and anchor.parts[-1] == "github_release_peer.py", "input-anchor")
                anchor.check()
                common = 0
                # Never borrow either input's leaf, even if it is a directory.
                for left, right in zip(self.parts[:-1], anchor.parts[:-1]):
                    if left != right:
                        break
                    common += 1
                require(common > 0, "input-anchor")
                # Set custody before allocating lists: a failed allocation must
                # not accidentally make any borrowed original ours to close.
                self.borrowed = common
                self.slots = anchor.slots[:common]
                self.before = anchor.before[:common]
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            for index, part in enumerate(self.parts):
                is_directory = index < len(self.parts) - 1 or directory
                if index < self.borrowed:
                    fd = self.slots[index]
                else:
                    fd = os.open(part, flags | (os.O_DIRECTORY if is_directory else 0),
                                 dir_fd=self.slots[-1] if self.slots else None)
                    try:
                        self.slots.append(fd)
                    except BaseException:
                        os.close(fd)
                        raise
                st = os.fstat(fd)
                if is_directory:
                    require(stat.S_ISDIR(st.st_mode) and st.st_uid in ((0, owner) if private_parent else (0,))
                            and st.st_mode & 0o7022 == 0, "input-parent")
                    require(st.st_gid == (0 if st.st_uid == 0 else os.getegid()), "input-parent")
                    if private_parent and index == len(self.parts) - 2:
                        require(st.st_uid == owner and stat.S_IMODE(st.st_mode) == 0o700, "journal-parent")
                    if index == len(self.parts) - 1:
                        require(directory and private_parent and st.st_uid == owner
                                and stat.S_IMODE(st.st_mode) == mode == 0o700, "journal-parent")
                else:
                    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == owner
                            and stat.S_IMODE(st.st_mode) == mode and 0 < st.st_size <= maximum, "input")
                    require(st.st_gid == (0 if owner == 0 else os.getegid()), "input")
                if index >= self.borrowed:
                    self.before.append(st)
            if directory:
                self.roster = journal_names(self.slots[-1])
                require(len(self.roster) <= maximum, "journal-roster")
                self.check()
                return
            raw = bytearray()
            size = self.before[-1].st_size
            while len(raw) <= size:
                block = os.read(self.slots[-1], min(16384, size + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            require(len(raw) == size, "input-length")
            self.raw = bytes(raw)
            self.check()
        except BaseException:
            self.close()
            raise

    def check_anchor(self) -> None:
        if self.anchor is None:
            require(self.borrowed == 0, "input-anchor")
            return
        anchor = self.anchor
        require(not anchor.closed and anchor.anchor is None and anchor.borrowed == 0 and not anchor.directory
                and 0 < self.borrowed < min(len(self.parts), len(anchor.parts))
                and self.parts[:self.borrowed] == anchor.parts[:self.borrowed]
                and self.slots[:self.borrowed] == anchor.slots[:self.borrowed]
                and len(self.before) >= self.borrowed
                and tuple(map(identity, self.before[:self.borrowed])) == tuple(map(identity, anchor.before[:self.borrowed])),
                "input-anchor")
        anchor.check()

    def check(self) -> None:
        require(not self.closed and len(self.slots) == len(self.parts)
                and len(self.before) == len(self.parts), "input-custody")
        self.check_anchor()
        for index, (fd, before) in enumerate(zip(self.slots, self.before)):
            named = os.stat(self.parts[index], dir_fd=self.slots[index - 1] if index else None,
                            follow_symlinks=False)
            held = os.fstat(fd)
            # A journal parent legitimately gains the run leaf later. Its
            # name/identity/mode/ownership cannot change; directory timestamps
            # are not a promise that no product journal write occurred.
            key = identity if index == len(self.parts) - 1 else lambda st: identity(st)[:5]
            require(key(held) == key(before) == key(named), "input-post")
        if self.directory:
            require(self.roster == journal_names(self.slots[-1]), "journal-roster")
        else:
            require(os.pread(self.slots[-1], self.before[-1].st_size + 1, 0) == self.raw, "input-content-post")
            named = os.stat(self.parts[-1], dir_fd=self.slots[-2], follow_symlinks=False)
            require(identity(os.fstat(self.slots[-1])) == identity(named) == identity(self.before[-1]), "input-post")
        self.check_anchor()

    def close(self) -> None:
        if self.closed:
            return
        failed = False
        try:
            self.check_anchor()
        except BaseException:
            failed = True
        while len(self.slots) > self.borrowed:
            fd = self.slots.pop()  # Each original close is attempted once only.
            try:
                os.close(fd)
            except BaseException:
                failed = True
        self.slots.clear()  # Borrowed prefix references are not close authority.
        self.closed = True
        require(not failed, "input-close")


def acquire(inputs: list, path: Path, maximum: int, expected: str) -> bytes:
    original = Input(path, maximum, owner=0, mode=0o444, anchor=inputs[0] if inputs else None)
    try:
        inputs.append(original)
    except BaseException:
        original.close()
        raise
    require(hashlib.sha256(original.raw).hexdigest() == expected, "input-hash")
    return original.raw


def admit(case: str, inputs: list):
    keys = {"LANG", "LC_ALL", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "MRK_DESKTOP_HOSTED_CHECKS",
            "MRK_TLS_ORIGINAL_UID", "MRK_TLS_ORIGINAL_GID", "MRK_TLS_NETNS", "MRK_TLS_MNTNS",
            "MRK_TLS_USERNS", "MRK_TLS_PIDNS", "MRK_TLS_PARENT_USERNS", "MRK_TLS_PARENT_PIDNS",
            "MRK_TLS_PARENT_NETNS", "MRK_TLS_PARENT_MNTNS", "MRK_TLS_PEER_OWNER_TAG",
            "MRK_RELEASE_PEER_SHA256"}
    uname = os.uname()
    require(uname.sysname == "Linux" and uname.machine == "x86_64"
            and uname.release == "6.17.0-1022-azure" and sys.executable == PYTHON, "platform")
    require(set(os.environ) == keys and sys.platform == "linux" and sys.flags.isolated == 1
            and sys.flags.no_site == 1 and sys.dont_write_bytecode and sys.flags.optimize == 0
            and os.environ["MRK_DESKTOP_HOSTED_CHECKS"] == MODE
            and os.environ["GITHUB_ACTIONS"] == "true" and os.environ["RUNNER_ENVIRONMENT"] == "github-hosted"
            and os.environ["LANG"] == os.environ["LC_ALL"] == "C" and case in CASES, "admission")
    ids = tuple(os.environ[key] for key in ("MRK_TLS_ORIGINAL_UID", "MRK_TLS_ORIGINAL_GID"))
    require(all(re.fullmatch(r"[1-9][0-9]{0,9}", value) is not None for value in ids), "identity")
    uid, gid = map(int, ids)
    require(0 < uid < 2**32 - 1 and 0 < gid < 2**32 - 1 and os.getresuid() == (uid,) * 3
            and os.getresgid() == (gid,) * 3 and os.getgroups() == [], "identity")
    for kind, key in (("net", "NETNS"), ("mnt", "MNTNS"), ("user", "USERNS"), ("pid", "PIDNS")):
        expected = os.environ["MRK_TLS_" + key]
        require(re.fullmatch(kind + r":\[[1-9][0-9]{0,19}\]", expected) is not None
                and expected == os.environ["MRK_TLS_PARENT_" + key]
                and os.readlink("/proc/self/ns/" + kind) == expected, "namespace")
    source = Path(__file__)
    require(source.is_absolute() and source.name == "github_release_peer.py"
            and source.parent.name == "github-peer" and source.parent.parent.parent == Path("/var/lib"), "path")
    require(re.fullmatch(r"[0-9a-f]{64}", os.environ["MRK_RELEASE_PEER_SHA256"]) is not None
            and re.fullmatch(r"[0-9a-f]{16}", os.environ["MRK_TLS_PEER_OWNER_TAG"]) is not None, "source")
    acquire(inputs, source, 65536, os.environ["MRK_RELEASE_PEER_SHA256"])
    with open("/proc/self/status", "rb") as file:
        status = file.read(16385)
    require(len(status) <= 16384, "identity")
    fields = dict(line.split(b":", 1) for line in status.splitlines() if b":" in line)
    require(fields.get(b"NoNewPrivs", b"").strip() == b"1", "identity")
    for key in (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"):
        require(fields.get(key, b"").strip() == b"0000000000000000", "identity")
    for key, limit in ((resource.RLIMIT_AS, 256 * 1024 * 1024), (resource.RLIMIT_NOFILE, 64),
                       (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 0)):
        _, hard = resource.getrlimit(key)
        require(hard == resource.RLIM_INFINITY or hard >= limit, "limits")
        resource.setrlimit(key, (limit, limit))
    # Execute only the exact protected, already-reviewed support bytes. The old
    # GET parser/admission/main are not called or broadened by the action fixture.
    support = source.with_name("github_tls_peer.py")
    raw = acquire(inputs, support, 65536, SUPPORT_SHA)
    module = types.ModuleType("_mrk_original_tls_peer_support")
    module.__file__ = str(support)
    exec(compile(raw, str(support), "exec"), module.__dict__)
    callers = {}
    for stage, (size, digest) in CALLERS.items():
        raw = acquire(inputs, source.with_name("mobile-" + stage + ".yml"), 16384, digest)
        require(len(raw) == size, "caller-size")
        callers[stage] = raw
    return module, source, callers, uid


def body(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def wire_request(connection, method: str, path: str, version: str, record: dict) -> bytes:
    raw = bytearray()
    header = None
    length = 0
    while header is None or len(raw) < len(header) + length:
        connection.flush()
        require(len(raw) < 8192, "request-limit")
        try:
            part = connection.tls.read(min(4096, 8192 - len(raw)))
        except ssl.SSLWantReadError:
            connection.receive()
            continue
        except ssl.SSLWantWriteError:
            connection.flush()
            continue
        require(bool(part), "request-incomplete")
        raw.extend(part)
        if header is None and b"\r\n\r\n" in raw:
            end = raw.index(b"\r\n\r\n") + 4
            header = bytes(raw[:end])
            expected = (method + " " + path + " HTTP/1.1\r\n").encode() + b"\r\n".join((
                b"Host: api.github.com", b"User-Agent: MobileReleaseKit-Desktop/0.3.0",
                b"Accept: application/vnd.github+json", b"X-GitHub-Api-Version: " + version.encode(),
                b"Accept-Encoding: identity", b"Connection: close", b"Authorization: Bearer INERT_NOT_A_CREDENTIAL"))
            if method == "POST":
                match = re.fullmatch(re.escape(expected) + rb"\r\nContent-Type: application/json\r\nContent-Length: ([1-9][0-9]{0,3})\r\n\r\n", header)
                require(match is not None, "request-header")
                length = int(match[1])
                require(length <= 2048, "request-limit")
            else:
                require(method == "GET" and header == expected + b"\r\n\r\n", "request-header")
    require(header is not None and len(raw) == len(header) + length, "request-surplus")
    record["requests"] += 1
    record["decryptedBytes"] += len(raw)
    return bytes(raw[len(header):])


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def dispatch_marker(raw: bytes) -> str:
    value = json.loads(raw)
    require(type(value) is dict and set(value) == {"ref", "return_run_details", "inputs"}
            and value["ref"] == "production" and value["return_run_details"] is True, "dispatch")
    inputs = value["inputs"]
    require(type(inputs) is dict and set(inputs) == {"platform", "confirmation", "recovery_run_id", "recovery_confirmation",
        "desktop_request", "desktop_source_sha", "desktop_expected_ref", "candidate_run_id", "external_run_id"}
        and inputs["platform"] == "ios" and inputs["confirmation"] == "production-submit:ios:1.2.3:42"
        and inputs["recovery_run_id"] == inputs["recovery_confirmation"] == "" and inputs["candidate_run_id"] == "101"
        and inputs["external_run_id"] == "102" and inputs["desktop_source_sha"] == SOURCE
        and inputs["desktop_expected_ref"] == "refs/heads/production"
        and type(inputs["desktop_request"]) is str and re.fullmatch(r"[0-9a-f]{32}", inputs["desktop_request"]) is not None
        and canonical(value) == raw, "dispatch")
    return inputs["desktop_request"]


def journal_root(source: Path, case: str) -> Path:
    require(case in CASES, "journal-case")
    return source.parent.parent / ("gui-github-" + case) / "home/.local/share/mobile-release-kit/github-release"


def journal_names(fd: int) -> list[str]:
    # Bounded read on the retained original directory, not an ambient path scan.
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            require(len(names) < 2, "journal-roster")
            names.append(entry.name)
    return sorted(names)


def revoked_intent(source: Path, case: str, uid: int, inputs: list) -> tuple[str, tuple]:
    require(case == "release-pre-go-revocation", "journal-case")
    original = Input(journal_root(source, case), 1, owner=uid, mode=0o700,
                     private_parent=True, directory=True, anchor=inputs[0])
    try:
        inputs.append(original)
    except BaseException:
        original.close()
        raise
    require(original.roster is not None and len(original.roster) == 1, "journal-roster")
    match = re.fullmatch(r"([0-9a-f]{32})\.intent\.json", original.roster[0])
    require(match is not None, "journal-roster")
    marker = match[1]
    return marker, journal_intent(source, case, marker, uid, inputs)


def journal_intent(source: Path, case: str, marker: str, uid: int, inputs: list) -> tuple[Input, int, str]:
    # Actual product create-only/fsynced intent, witnessed before losing the
    # sole POST response. This read grants neither durability nor final GO.
    root = journal_root(source, case)
    original = Input(root / (marker + ".intent.json"), 8192, owner=uid, mode=0o400, private_parent=True, anchor=inputs[0])
    try:
        inputs.append(original)
    except BaseException:
        original.close()
        raise
    raw = original.raw
    original.check()
    value = json.loads(raw)
    require(type(value) is dict and set(value) == {"schemaVersion", "protocol", "prepared"}
            and raw == canonical(value) + b"\n" and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["protocol"] == "mrk-github-release/1", "journal")
    prepared = value["prepared"]
    require(type(prepared) is dict and set(prepared) == {"target", "sourceSha", "sourceTree", "workflowId", "workflowPath",
        "callerSha256", "observedAt", "expectedRef", "displayTitle", "configSha256", "versionSource", "versionSha256",
        "currentVersion", "destination", "checklist", "environment", "confirmation", "originalAssurance"}, "journal")
    target = prepared["target"]
    stage, platform, branch, _ = selected(case)
    promotion = stage == "production-submit"
    selection = {"stage": stage, "candidateRunId": "101" if promotion else None,
        "externalRunId": "102" if promotion else None, "recoveryRunId": None,
        "originalSourceSha": ORIGINAL if promotion else None, "originalVersion": {"name": "1.2.3", "build": 42} if promotion else None}
    require(type(target) is dict and set(target) == {"projectBinding", "repository", "accountId", "repositoryId",
        "branch", "toolingRepository", "toolingSha", "platform", "marker", "selection"}
        and type(target["projectBinding"]) is str and re.fullmatch(r"[0-9a-f]{64}", target["projectBinding"]) is not None
        and target["toolingRepository"] == "Apdelrahman1911/mobile-release-kit"
        and target["repository"] == "owner/app" and target["accountId"] == "11" and target["repositoryId"] == "22"
        and target["branch"] == branch and target["platform"] == platform and target["selection"] == selection
        and target["marker"] == marker and target["toolingSha"] == TOOLING
        and prepared["sourceSha"] == SOURCE and prepared["sourceTree"] == TREE and prepared["workflowId"] == "33"
        and prepared["workflowPath"] == workflow(case)["path"] and prepared["callerSha256"] == CALLERS[stage][1]
        and prepared["configSha256"] == hashlib.sha256(CONFIG).hexdigest()
        and prepared["versionSource"] == "release/version.properties" and prepared["versionSha256"] == hashlib.sha256(VERSION).hexdigest()
        and prepared["currentVersion"] == {"name": "2.0.0", "build": 99}
        and prepared["expectedRef"] == "refs/heads/" + branch and prepared["displayTitle"] == "MRK Desktop " + stage + " [" + marker + "]"
        and prepared["confirmation"] == ("production-submit:ios:1.2.3:42" if promotion else "candidate:android:2.0.0:99")
        and prepared["environment"] == ("mobile-production" if promotion else "mobile-candidate")
        and prepared["originalAssurance"] == "declared-original-references-not-authenticated-release-evidence"
        and prepared["destination"] == {"applicationId": "org.fixture.app",
            "destination": "App Review; manual release" if promotion else "internal",
            "assurance": "current-dispatch-config-not-authenticated-original-destination"}, "journal")
    return original, len(raw), hashlib.sha256(raw).hexdigest()


def journal_run(source: Path, case: str, marker: str, uid: int, intent: tuple[Input, int, str], inputs: list) -> dict:
    # Check the SAME original intent and every held named ancestor from POST.
    # A byte-identical replacement is not the original immutable journal.
    intent[0].check()
    path = journal_root(source, case) / (marker + ".run.json")
    original = Input(path, 512, owner=uid, mode=0o400, private_parent=True, anchor=inputs[0])
    try:
        inputs.append(original)
    except BaseException:
        original.close()
        raise
    raw = original.raw
    expected = {"schemaVersion": 1, "intentSha256": intent[2], "runId": "9001", "attempt": 1}
    require(raw == json.dumps(expected, sort_keys=True, separators=(",", ":")).encode() + b"\n", "journal-run")
    original.check()
    intent[0].check()
    return {"marker": marker, "intentBytes": intent[1], "intentSha256": intent[2],
            "runBytes": len(raw), "runSha256": hashlib.sha256(raw).hexdigest(), "runId": "9001", "attempt": 1}


def run_value(marker: str) -> dict:
    current = workflow("release-response-loss")
    return {"id": 9001, "run_attempt": 1, "workflow_id": 33, "path": current["path"], "name": current["name"],
            "repository": REPOSITORY, "head_repository": REPOSITORY, "actor": ACCOUNT, "triggering_actor": ACCOUNT,
            "head_sha": SOURCE, "head_branch": "production", "event": "workflow_dispatch",
            "display_title": "MRK Desktop production-submit [" + marker + "]", "status": "completed", "conclusion": "success",
            "html_url": "https://github.com/owner/app/actions/runs/9001"}


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest()


def contents(path, raw):
    return {"type": "file", "path": path, "encoding": "base64", "size": len(raw),
            "content": base64.b64encode(raw).decode(), "sha": blob(raw)}


def source_tree(files):
    parents = set()
    for path in files:
        parts = path.split("/")
        parents.update("/".join(parts[:n]) for n in range(1, len(parts)))
    rows = [{"path": path, "mode": "040000", "type": "tree", "sha": "0" * 40,
             "url": "https://api.github.com/repos/owner/app/git/trees/" + "0" * 40} for path in sorted(parents)]
    rows += [{"path": path, "mode": "100644", "type": "blob", "sha": blob(raw), "size": len(raw),
              "url": "https://api.github.com/repos/owner/app/git/blobs/" + blob(raw)} for path, raw in files.items()]
    return {"sha": TREE, "url": "https://api.github.com/repos/owner/app/git/trees/" + TREE, "truncated": False, "tree": rows}


def schedule(case: str, callers: dict) -> tuple[tuple[str, str, str, object], ...]:
    require(case in CASES, "schedule")
    read = (("GET", "/user", "2022-11-28", ACCOUNT), ("GET", "/repos/owner/app", "2022-11-28", REPOSITORY),
            ("GET", "/repos/owner/app/actions/workflows?per_page=100&page=1", "2022-11-28", {"total_count": 0, "workflows": []}),
            ("GET", "/repos/owner/app", "2022-11-28", REPOSITORY))
    if case == "release-normal-pending":
        return read  # R receives no HTTP response because its genuine Pending makes no transport.
    stage, _, branch, _ = selected(case)
    current = workflow(case)
    files = {current["path"]: callers[stage], "release/mobile-release.json": CONFIG, "release/version.properties": VERSION}
    branch_value = {"name": branch, "commit": {"sha": SOURCE, "commit": {"tree": {
        "sha": TREE, "url": "https://api.github.com/repos/owner/app/git/trees/" + TREE}}}}
    core = (("GET", "/user", "2026-03-10", ACCOUNT), ("GET", "/repos/owner/app", "2026-03-10", REPOSITORY),
            ("GET", "/repos/owner/app/branches/" + branch, "2026-03-10", branch_value),
            ("GET", "/repos/owner/app/actions/workflows/mobile-" + stage + ".yml", "2026-03-10", current))
    prepare = (*core,
        ("GET", "/repos/owner/app/contents/" + current["path"] + "?ref=" + SOURCE, "2026-03-10", contents(current["path"], files[current["path"]])),
        ("GET", "/repos/owner/app/contents/release/mobile-release.json?ref=" + SOURCE, "2026-03-10", contents("release/mobile-release.json", CONFIG)),
        ("GET", "/repos/owner/app/git/trees/" + TREE + "?recursive=1", "2026-03-10", source_tree(files)),
        ("GET", "/repos/owner/app/contents/release/version.properties?ref=" + SOURCE, "2026-03-10", contents("release/version.properties", VERSION)),
        core[2], ("GET", "/repos/owner/app", "2026-03-10", REPOSITORY))
    dispatch = (*core, ("POST", "/repos/owner/app/actions/workflows/33/dispatches", "2026-03-10", "dispatch"))
    observe = (*core[:2],
        ("GET", "/repos/owner/app/actions/workflows/33/runs?event=workflow_dispatch&branch=production&head_sha=" + SOURCE + "&per_page=100&page=1", "2026-03-10", "runs"),
        ("GET", "/repos/owner/app/actions/runs/9001/attempts/1", "2026-03-10", "attempt"),
        ("GET", "/repos/owner/app/actions/runs/9001/attempts/1/jobs?per_page=100&page=1", "2026-03-10", "jobs"),
        ("GET", "/repos/owner/app", "2026-03-10", REPOSITORY))
    require(len(prepare) == 10 and len(dispatch) == 5 and len(observe) == 6, "schedule")
    return (*read, *prepare) if case == "release-pre-go-revocation" else (*read, *prepare, *dispatch, *observe)


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in CASES:
        return 71
    case = sys.argv[1]
    module = None
    listener = unregistered = None
    original_control = None
    connections = []
    unexpected = [None, None]
    completion = {"bytes": 0, "eof": False, "closed": False, "primaryEmpty": False,
                  "primaryUnexpected": 0, "primaryClosed": False, "redirect": None}
    record = {"schemaVersion": 1, "scope": SCOPE, "case": case, "state": "finished", "status": "failed",
              "requests": 0, "posts": 0, "decryptedBytes": 0, "intentBeforeResponse": False,
              "allSocketsClosed": False, "inputsCheckedClosed": False, "code": "admission", "completion": completion,
              "journal": None, "otherJournalAbsent": False}
    inputs = []
    close_failed = False
    inputs_checked = True
    unregistered_closed = False
    journal_post = None
    try:
        module, source, callers, uid = admit(case, inputs)
        original_control = 0
        st = os.fstat(original_control)
        require(stat.S_ISFIFO(st.st_mode) and st.st_uid == uid, "control")
        os.set_blocking(original_control, False)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.keylog_filename = None
        context.set_alpn_protocols(["http/1.1"])
        fixtures = source.with_name("github_tls")
        cert, key = fixtures / "api-valid.pem", fixtures / "server-key.pem"
        acquire(inputs, cert, 16384, "33f6acd10b8d466078525b80464a1c5938266b1084ea5aabf43b348bd7dca6f2")
        acquire(inputs, key, 16384, "33332bb26fd6e394d067f7e2df563d496f934e0a098de1e3039169fb8d4ee109")
        context.load_cert_chain(str(cert), str(key))
        for original in inputs:
            original.check()
        context.set_servername_callback(lambda _socket, name, _ctx: None if name == "api.github.com" else ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.settimeout(module.remaining())
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 18443))
        listener.listen(1)
        binding = {"schemaVersion": 1, "scope": SCOPE, "case": case, "ownerTag": os.environ["MRK_TLS_PEER_OWNER_TAG"],
                   "manifestSha256": N if case == "release-normal-pending" else MANIFEST, "peerSha256": os.environ["MRK_RELEASE_PEER_SHA256"],
                   "toolingSha": TOOLING, "callerSha256": {stage: pin[1] for stage, pin in CALLERS.items()}, "primaryPort": 18443}
        record.update(binding)
        module.emit({**binding, "state": "ready"})
        record["code"] = "request"
        marker = None
        intent = None
        for method, path, version, response in schedule(case, callers):
            listener.settimeout(module.remaining())
            unregistered, address = listener.accept()
            require(address[0] == "127.0.0.1" and 0 < address[1] < 65536, "peer")
            connection = module.Connection(unregistered)
            connections.append(connection)
            unregistered = None
            connection.attach(context)
            connection.handshake()
            raw = wire_request(connection, method, path, version, record)
            if method == "POST":
                require(case == "release-response-loss" and marker is None and record["posts"] == 0, "post-retry")
                marker = dispatch_marker(raw)
                record["posts"] += 1
                intent = journal_intent(source, case, marker, uid, inputs)
                record["intentBeforeResponse"] = True
                connection.close()  # Actual complete POST; no response and never a resend grant.
                continue
            elif response in ("runs", "attempt", "jobs"):
                require(marker is not None, "correlation")
                if response == "runs":
                    response = {"total_count": 1, "workflow_runs": [run_value(marker)]}
                elif response == "attempt":
                    response = run_value(marker)
                else:
                    response = {"total_count": 2, "jobs": [{"id": 9101 + index, "run_id": 9001, "run_attempt": 1,
                        "head_sha": SOURCE, "name": name, "status": "completed", "conclusion": "success"}
                        for index, name in enumerate(("production-submit / validate-platform", "production-submit / ios"))]}
            encoded = body(response)
            reply = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + str(len(encoded)).encode() + b"\r\n\r\n" + encoded
            connection.respond(reply, True)
            connection.close()
        require(record["posts"] == (1 if case == "release-response-loss" else 0)
                and record["requests"] == REQUESTS[case], "schedule")
        record["code"] = "completion"
        module.complete_listener_observation(listener, None, original_control, unexpected, completion)
        if case == "release-normal-pending":
            require(marker is None and intent is None, "journal")
            record["journal"] = dict.fromkeys(("marker", "intentBytes", "intentSha256", "runBytes", "runSha256", "runId", "attempt"))
            expected_names = []
        elif case == "release-pre-go-revocation":
            require(marker is None and intent is None, "journal")
            marker, intent = revoked_intent(source, case, uid, inputs)
            record["journal"] = {"marker": marker, "intentBytes": intent[1], "intentSha256": intent[2],
                                 "runBytes": None, "runSha256": None, "runId": None, "attempt": None}
            expected_names = [marker + ".intent.json"]
        else:
            require(marker is not None and intent is not None, "journal")
            record["journal"] = journal_run(source, case, marker, uid, intent, inputs)
            expected_names = [marker + ".intent.json", marker + ".run.json"]
        # Only the original product creates the R directory and entries. Hold
        # final journal and its shared MRK parent; absence of G is observed,
        # not inferred from request counts or a synthetic receipt.
        directory = Input(journal_root(source, case), 2, owner=uid, mode=0o700, private_parent=True, directory=True, anchor=inputs[0])
        try:
            inputs.append(directory)
        except BaseException:
            directory.close()
            raise
        require(directory.roster == expected_names, "journal-roster")
        family_parent = Input(journal_root(source, case).parent, 1, owner=uid, mode=0o700, private_parent=True, directory=True, anchor=inputs[0])
        try:
            inputs.append(family_parent)
        except BaseException:
            family_parent.close()
            raise
        require(family_parent.roster == ["github-release"], "other-journal")
        record["otherJournalAbsent"] = True
        journal_post = (directory.slots[-1], identity(os.fstat(directory.slots[-1])), expected_names)
        record["journal"]["leafCount"] = len(expected_names)
        if intent is not None:
            intent[0].check()
        record["status"] = "passed"
        record["code"] = None
    except BaseException:
        record["status"] = "failed"
    finally:
        for connection in reversed(connections):
            try:
                connection.close()
            except BaseException:
                close_failed = True
        if unregistered is not None:
            try:
                unregistered.close()
                unregistered_closed = True
            except BaseException:
                close_failed = True
        unexpected_closed = [False, False]
        for index, original in enumerate(unexpected):
            if original is not None:
                try:
                    original.close()
                    unexpected_closed[index] = True
                except BaseException:
                    close_failed = True
        if listener is not None:
            try:
                listener.close()
                completion["primaryClosed"] = True
            except BaseException:
                close_failed = True
        if original_control is not None:
            try:
                os.close(original_control)
                completion["closed"] = True
            except OSError:
                close_failed = True
        if journal_post is not None:
            try:
                fd, before, names = journal_post
                require(identity(os.fstat(fd)) == before and journal_names(fd) == names, "journal-final-roster")
            except BaseException:
                inputs_checked = False
        for original in reversed(inputs):
            try:
                original.check()
            except BaseException:
                inputs_checked = False
            try:
                original.close()
            except BaseException:
                close_failed = True
        record["inputsCheckedClosed"] = inputs_checked and len(inputs) == (9 if case == "release-normal-pending" else 11) and all(item.closed for item in inputs) and not close_failed
        record["allSocketsClosed"] = (not close_failed and completion["primaryClosed"] and all(c.closed for c in connections)
            and (unregistered is None or unregistered_closed)
            and all(original is None or closed for original, closed in zip(unexpected, unexpected_closed)))
        if not record["allSocketsClosed"] or not record["inputsCheckedClosed"] or not completion["closed"]:
            record["status"], record["code"] = "failed", "cleanup"
        if module is not None:
            try:
                module.emit(record)
            except BaseException:
                return 74
    return 0 if record["status"] == "passed" else 71


if __name__ == "__main__":
    raise SystemExit(main())
