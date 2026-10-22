"""Two fixed nonshipping installed-mrk recipes. Import performs no IO.

The existing Fixtures owns every file and the existing run_owned owns every
process. Phase files contain comparison DATA, never a grant or an IPC endpoint.
Only the actual Desktop APIs can authorize the selected original operation.
"""
from pathlib import Path
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
import math
import os
import re
import stat
import subprocess
import threading
import time

SCOPE = "installed-cli-local-check"
CASES = (SCOPE,)
APPLICATION = "dev.mobile-release-kit.desktop"
CLI = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/MacOS/mrk"
PHASES = ("cli-native.jsonl", "cli-driver.jsonl")
PHASE_LIMIT, OUTPUT_LIMIT, FD_LIMIT = 4096, 128 * 1024, 16
SUCCESS_SECONDS, APP_SECONDS, CLEANUP_SECONDS, JOIN_MARGIN = 120, 135, 3, 1
NATIVE_PHASES = ("allowed", "terminal", "revoked", "reallowed")
DRIVER_PHASES = ("submitted", "checked", "denied", "done")
LIMITATIONS = ["saved-inputs-not-atomic", "project-code-effects-possible", "not-network-isolated",
              "core-builds-disabled", "artifact-validation-not-requested",
              "toolkit-signing-credentials-store-not-requested", "release-readiness-not-assessed"]

# Exactly one additional recipe, loaded from the same first-party directory.
# It contains no process/thread/native/cleanup owner.
_backup_spec = spec_from_file_location("mrk_upload_backup_cli_recipe", Path(__file__).with_name("macos_upload_key_cli_observation.py"))
if _backup_spec is None or _backup_spec.loader is None:
    raise RuntimeError("backup-cli-recipe-unavailable")
BACKUP = module_from_spec(_backup_spec)
_backup_spec.loader.exec_module(BACKUP)
del _backup_spec


def selected(cases):
    return cases in (CASES, BACKUP.CASES)


def _scope(f):
    need(selected(f.cases), "cli-fixed-case")
    return f.cases[0]


def _policy(case):
    if case == SCOPE:
        return (7, 4, SUCCESS_SECONDS, APP_SECONDS)
    if case == BACKUP.SCOPE:
        return (BACKUP.CALLS, BACKUP.ROWS, BACKUP.SUCCESS_SECONDS, BACKUP.APP_SECONDS)
    raise ValueError("cli-fixed-case")



def need(ok, reason):
    if not ok:
        raise ValueError(reason)  # Fixed reasons only, never subprocess output.


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _decode(raw, limit=OUTPUT_LIMIT):
    need(type(raw) is bytes and 0 < len(raw) <= limit, "cli-json-bound")
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "cli-json-duplicate")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("cli-json-invalid") from None
    need(type(value) is dict, "cli-json-object")
    return value


def _keys(v, *keys):
    return type(v) is dict and set(v) == set(keys)


def _id(v):
    return type(v) is str and re.fullmatch(r"[0-9a-f]{32}", v) is not None and v != "0" * 32


def _integer(v):
    return type(v) is int and 0 < v < 2 ** 63


def _config(v):
    return (_keys(v, "bytes", "sha256") and _integer(v["bytes"]) and v["bytes"] <= 524288
            and type(v["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", v["sha256"]) is not None)


def _sig(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def fixture_path(binding, *, case=SCOPE):
    binding.checked()
    _policy(case)
    return Path("/private/tmp") / f"mrk-macos-aqua-{binding.source}-{binding.run}-{binding.attempt}-{case}"


def short_home(binding, native_home, *, case=SCOPE):
    binding.checked()
    _policy(case)
    home = Path(native_home)
    need(home.is_absolute() and home != Path("/") and len(home.parts) <= 6
         and str(home) == str(home.absolute()), "cli-native-home")
    tag = _hash(f"{binding.source}/{binding.run}/{binding.attempt}/{case}".encode("ascii"))[:12]
    home = home / (".c-" + tag)
    need(len(os.fsencode(home / "Library/Application Support" / APPLICATION / "service-v1/s")) < 104,
         "cli-socket-path-bound")
    return home


class PhaseFile:
    """A borrowed Fixtures FD; one append-only writer and no destructor/close."""
    def __init__(self, parent, name, fd, uid, writable, *, case=SCOPE):
        self.case, self.limit = case, _policy(case)[1]
        self.parent, self.name, self.fd, self.uid, self.writable = parent, name, fd, uid, writable
        self.original = _sig(os.fstat(fd))
        self.prefix, self.rows = b"", []
        self.current()
        need(self.original[6] == 0, "cli-phase-not-empty")

    def current(self):
        before = _sig(os.fstat(self.fd))
        named = _sig(os.stat(self.name, dir_fd=self.parent, follow_symlinks=False))
        # A concurrent original append can change length/times between these
        # samples. Identity/policy must still match; read() separately requires
        # one stable full before/after stamp before interpreting any bytes.
        need(before[:6] == named[:6] and 0 <= named[6] <= PHASE_LIMIT
             and before[:6] == self.original[:6] and before[2] == stat.S_IFREG | 0o600
             and before[3] == self.uid and before[5] == 1 and 0 <= before[6] <= PHASE_LIMIT,
             "cli-phase-original")
        return before

    def read(self):
        before = self.current()
        raw = os.pread(self.fd, PHASE_LIMIT + 1, 0)
        # Writer append may race; no adoption until one complete stable sample.
        after = self.current()
        if before != after:
            return None
        need(len(raw) == before[6] and raw.startswith(self.prefix), "cli-phase-rewritten")
        complete = raw.rsplit(b"\n", 1)[0] + b"\n" if b"\n" in raw else b""
        lines = complete.splitlines()
        need(len(lines) <= self.limit and (self.case == SCOPE or all(len(line) <= 512 for line in lines)), "cli-phase-count")
        rows = [_decode(line, PHASE_LIMIT) for line in lines]
        need(rows[:len(self.rows)] == self.rows, "cli-phase-changed")
        self.prefix, self.rows = complete, rows
        return rows

    def append(self, value):
        need(self.writable and len(self.rows) < self.limit, "cli-phase-write-role")
        self.read()
        before = self.current()
        need(before[6] == len(self.prefix), "cli-phase-partial-write")
        raw = _json(value) + b"\n"
        need((self.case == SCOPE or len(raw) - 1 <= 512) and len(self.prefix) + len(raw) <= PHASE_LIMIT, "cli-phase-write-bound")
        offset = 0
        while offset < len(raw):
            n = os.pwrite(self.fd, raw[offset:], len(self.prefix) + offset)
            need(type(n) is int and 0 < n <= len(raw) - offset, "cli-phase-write")
            offset += n
        os.fsync(self.fd)
        expected = self.prefix + raw
        need(os.pread(self.fd, PHASE_LIMIT + 1, 0) == expected, "cli-phase-write-post")
        self.prefix, self.rows = expected, self.rows + [value]
        need(self.current()[6] == len(expected), "cli-phase-write-length")


class Calls:
    """One closed recipe's numbered admissions, NOT a process executor.

    Main and its one retained thread share only this short lock. No lock spans
    run_owned/join; closing admission never forgets an already claimed original.
    """
    def __init__(self, clock=time.monotonic, *, case=SCOPE):
        self.count, self.rows, success, app = _policy(case)
        self.case, self.app_seconds = case, app
        self.clock, self.lock, self.stop = clock, threading.Lock(), threading.Event()
        start = clock()
        self.success_end, self.hard_end = start + success, start + app + CLEANUP_SECONDS
        self.next, self.inflight, self.closed, self.failed = 0, None, False, False
        self.results, self.returned = [], False

    def claim(self, number):
        with self.lock:
            now = self.clock()
            timeout = math.floor(min(30, self.success_end - now,
                                     self.hard_end - now - CLEANUP_SECONDS - JOIN_MARGIN))
            need(not self.closed and not self.failed and self.inflight is None
                 and number == self.next and number < self.count and timeout >= 1, "cli-call-admission")
            self.inflight = number  # Linearizes against main's close, before launch.
            return timeout

    def returned_call(self, number, result):
        with self.lock:
            need(self.inflight == number and len(self.results) == number, "cli-call-return-order")
            self.results.append(result)
            self.inflight = None
            self.next += 1

    def close(self, *, failed=False):
        with self.lock:
            self.closed = True
            self.failed |= failed
            self.stop.set()

    def check(self):
        with self.lock:
            need(not self.closed and not self.failed and self.clock() < self.success_end, "cli-phase-deadline")

    def wait(self):
        self.check()
        self.stop.wait(0.025)


def _response(result, argv, kind):
    need(type(result) is subprocess.CompletedProcess and result.args == argv
         and type(result.returncode) is int and (result.returncode == 0 or kind == "upload-key-request" and result.returncode == 5)
         and type(result.stdout) is bytes and type(result.stderr) is bytes
         and len(result.stdout) + len(result.stderr) <= OUTPUT_LIMIT, "cli-original-result")
    v = _decode(result.stdout)
    need(_keys(v, "version", "requestId", "serviceInstance", "clientId", "sessionId", "response")
         and type(v["version"]) is int and v["version"] == 1
         and all(_id(v[k]) for k in ("requestId", "serviceInstance", "clientId", "sessionId"))
         and _keys(v["response"], "kind", "value") and v["response"]["kind"] == kind, "cli-response-shape")
    return v["serviceInstance"], v["response"]["value"]


def _origin(v):
    return _keys(v, "serviceInstance", "projectId", "requestId") and all(_id(x) for x in v.values())


def _report(v, config):
    need(_keys(v, "schemaVersion", "scope", "usedConfig", "findings", "summary", "limitations")
         and type(v["schemaVersion"]) is int and v["schemaVersion"] == 1
         and v["scope"] == "saved-local-android-project-checks"
         and v["usedConfig"] == config and v["limitations"] == LIMITATIONS
         and type(v["findings"]) is list and len(v["findings"]) <= 128, "cli-report-shape")
    rows = v["findings"]
    need(all(type(r) is dict and r.get("ordinal") == i and r.get("projectCheckIndex") is None
             and r.get("check") != "configured-project-check" and r.get("message") == r.get("check")
             for i, r in enumerate(rows)), "cli-report-project-checks")
    need(all(any(r.get("check") == check and r.get("status") == status for r in rows)
             for check, status in (("android-gradle-wrapper", "MISSING"), ("version-source", "PASS"),
                                   ("workspace-private-output", "PASS"))), "cli-report-findings")
    # Native additionally uses the existing typed Report::valid. Comparison of
    # this whole canonical value binds every summary/enum field, not just rows.
    return _hash(_json(v))


def _settled(v, origin, revision, config, terminal):
    need(_keys(v, "origin", "expectedObservationRevision", "requestState", "operation", "historyAvailable", "doNotReplay")
         and v["origin"] == origin and v["expectedObservationRevision"] == revision
         and v["requestState"] == "original-available" and v["doNotReplay"] is True
         and type(v["historyAvailable"]) is bool, "cli-status-origin")
    op = v["operation"]
    need(_keys(op, "operationId", "ownerGeneration", "statusRevision", "state", "settlement", "outcome", "reason", "result")
         and op["operationId"] == terminal["operationId"] and op["ownerGeneration"] == terminal["ownerGeneration"]
         and _integer(op["statusRevision"]) and op["state"] == "succeeded" and op["settlement"] == "settled"
         and op["outcome"] == "complete" and op["reason"] == "none", "cli-status-not-complete")
    need(_report(op["result"], config) == terminal["reportSha256"], "cli-status-report-changed")


def _phase(channel, calls, name, index):
    while True:
        calls.check()  # A ready DATA row cannot reopen a stopped admission.
        rows = channel.read()
        if rows is not None:
            need(len(rows) <= index + 1 and all(r.get("phase") == NATIVE_PHASES[i] for i, r in enumerate(rows)),
                 "cli-native-phase-order")
            if len(rows) == index + 1:
                need(rows[index].get("phase") == name, "cli-native-phase-name")
                return rows[index]
        calls.wait()


def _call(c, run_owned, env, state, calls, number, args, kind, *, receipt=False):
    c.current_cli()
    argv = [CLI, *args, "--json"]
    timeout = calls.claim(number)
    result = run_owned(argv, environ=env, cwd=state, timeout=timeout, capture=True,
                       text=False, output_limit=OUTPUT_LIMIT, cancellation=None)
    # Only the original normal return is retained. Exception leaves the
    # claim in flight; no later call or fixture close can replace it.
    need(type(result) is subprocess.CompletedProcess and type(result.args) is list and result.args == argv
         and type(result.returncode) is int and type(result.stdout) is bytes and type(result.stderr) is bytes
         and len(result.stdout) + len(result.stderr) <= OUTPUT_LIMIT, "cli-call-original")
    calls.returned_call(number, result)
    calls.check()  # The preclaimed original may return, but cannot advance after STOP.
    c.current_cli()
    if kind is None:
        # The ordinary CLI writes its one JSON result, including a
        # pre-admission denial, to stdout. Public prose is bounded DATA;
        # only the closed error code/shape and exit status identify denial.
        need(result.returncode == 4 and result.stderr == b"", "cli-revoke-not-denied")
        error = _decode(result.stdout)
        need(_keys(error, "version", "ok", "error", "message")
             and type(error["version"]) is int and error["version"] == 1
             and error["ok"] is False and error["error"] == "access_denied"
             and type(error["message"]) is str
             and 0 < len(error["message"].encode("utf-8")) <= 1024, "cli-revoke-not-denied")
        return None
    instance, value = _response(result, argv, kind)
    need(receipt or result.stderr == b"", "cli-unexpected-stderr")
    return instance, value


def _journey(f, run_owned, env, state, calls):
    """Exactly one submit; every other command is a fresh real read/late STOP."""
    c = f.cli
    def call(number, args, kind, *, receipt=False):
        return _call(c, run_owned, env, state, calls, number, args, kind, receipt=receipt)
    allowed = _phase(c.native, calls, "allowed", 0)
    need(_keys(allowed, "phase", "projectId", "revision", "config") and _id(allowed["projectId"])
         and _integer(allowed["revision"]) and _config(allowed["config"]), "cli-native-allow-data")
    project, revision, config = allowed["projectId"], allowed["revision"], allowed["config"]
    instance, observed = call(0, ["observe", project], "observation")
    need(observed.get("projectId") == project and observed.get("registeredInCurrentHost") is True
         and type(observed.get("observation")) is dict, "cli-observation")
    saved = observed["observation"]
    need(saved.get("revision") == revision and saved.get("stale") is False
         and saved.get("configuration") == {"state": "format-valid", **config}
         and saved.get("discoveryPartial") is False, "cli-saved-observation")
    same, submitted = call(1, ["local-check", project, str(revision)], "local-check", receipt=True)
    origin = submitted.get("origin")
    need(same == instance and _origin(origin) and origin["serviceInstance"] == instance and origin["projectId"] == project
         and submitted.get("expectedObservationRevision") == revision and submitted.get("doNotReplay") is True
         and submitted.get("requestState") in ("queued", "admitting", "original-available"), "cli-submit-unadmitted")
    receipt = (f"Inspect without replay: mrk local-check-status {project} {instance} {origin['requestId']} --json\n"
               f"Request STOP: mrk local-check-cancel {project} {instance} {origin['requestId']} --json\n").encode("ascii")
    need(calls.results[1].stderr == receipt, "cli-original-receipt")
    c.driver.append({"phase": "submitted", "origin": origin, "revision": revision})
    terminal = _phase(c.native, calls, "terminal", 1)
    need(_keys(terminal, "phase", "operationId", "ownerGeneration", "reportSha256")
         and _id(terminal["operationId"]) and _id(terminal["ownerGeneration"])
         and terminal["operationId"] != terminal["ownerGeneration"]
         and type(terminal["reportSha256"]) is str
         and re.fullmatch(r"[0-9a-f]{64}", terminal["reportSha256"]) is not None, "cli-native-terminal-data")
    query = [project, instance, origin["requestId"]]
    for number, verb in ((2, "local-check-status"), (3, "local-check-cancel")):
        same, status = call(number, [verb, *query], "local-check")
        need(same == instance, "cli-instance-changed")
        _settled(status, origin, revision, config, terminal)
    c.driver.append({"phase": "checked", "origin": origin, "reportSha256": terminal["reportSha256"]})
    need(_phase(c.native, calls, "revoked", 2) == {"phase": "revoked"}, "cli-revoke-data")
    call(4, ["observe", project], None)
    c.driver.append({"phase": "denied"})
    need(_phase(c.native, calls, "reallowed", 3) == {"phase": "reallowed"}, "cli-reallow-data")
    same, status = call(5, ["local-check-status", *query], "local-check")
    need(same == instance, "cli-reconnect-instance")
    _settled(status, origin, revision, config, terminal)
    same, catalogue = call(6, ["requests", project], "requests")
    need(same == instance and type(catalogue.get("schemaVersion")) is int and catalogue["schemaVersion"] == 2
         and catalogue.get("scope") == "current-host-retained-requests"
         and catalogue.get("sampling") == "per-request-not-atomic" and catalogue.get("doNotReplay") is True
         and catalogue.get("serviceInstance") == instance and catalogue.get("projectId") == project
         and catalogue.get("additionalRequests") == [] and type(catalogue.get("requests")) is list
         and len(catalogue["requests"]) == 1, "cli-request-catalogue")
    row = catalogue["requests"][0]
    need(row.get("requestId") == origin["requestId"] and row.get("expectedObservationRevision") == revision
         and row.get("progress") == {"family": "local-check", "requestState": "original-available"}
         and type(row.get("operation")) is dict, "cli-request-origin")
    op = row["operation"]
    need(op.get("operationId") == terminal["operationId"] and op.get("ownerGeneration") == terminal["ownerGeneration"]
         and op.get("state") == "succeeded" and op.get("settlement") == "settled", "cli-request-operation")
    c.driver.append({"phase": "done", "origin": origin, "reportSha256": terminal["reportSha256"]})
    calls.returned = True


def invoke(f, run_owned, argv, env, state):
    need(selected(f.cases) and f.inflight and not f.last_returned and f.cli is not None
         and f.cli.calls is None and argv[1:] == [_scope(f)], "cli-invocation-order")
    c = f.cli
    calls = c.calls = Calls(case=_scope(f))
    environment = dict(env, HOME=str(c.home))
    # One retained non-daemon thread, before the sole start. No thread may use
    # the main DefaultCancellation or own a native application invocation.
    def worker():
        try:
            if calls.case == SCOPE:
                _journey(f, run_owned, environment, state, calls)
            else:
                BACKUP.journey(c, calls, lambda number, args, kind, **kw:
                    _call(c, run_owned, environment, state, calls, number, args, kind, **kw))
        except BaseException:
            calls.close(failed=True)  # Fixed failure only, no secret exception retention.
    c.thread = threading.Thread(target=worker, name="mrk-installed-cli-fixture", daemon=False)
    started = False
    try:
        c.thread.start()
        started = True
        result = run_owned(argv, environ=environment, cwd=state, timeout=calls.app_seconds,
                           capture=True, text=False, output_limit=2 * 1024 * 1024)
    except BaseException:
        calls.close(failed=True)
        raise
    finally:
        calls.close()
        # One join, under the fixed original endpoint. No new cleanup timer,
        # detach, kill, cross-thread signal or retry if it cannot be established.
        if started:
            c.thread.join(max(0.0, calls.hard_end - calls.clock()))
            c.joined = not c.thread.is_alive() and calls.clock() < calls.hard_end
        if not started or not c.joined or calls.inflight is not None:
            calls.failed = True
        # Existing run_cases alone clears Fixtures.inflight after THIS returns.
    need(c.joined and not calls.failed and calls.returned and calls.next == calls.count
         and calls.inflight is None and len(calls.results) == calls.count, "cli-thread-originals-not-returned")
    c.current_cli()
    return result


class Fixture:
    def __init__(self, f):
        self.f, self.extra, self.parents, self.cli_row = f, [], [], None
        self.home = None
        self.native = self.driver = self.calls = self.thread = None
        self.joined = False

    def retain(self, fd):
        self.f.fds.add(fd)  # Retain BEFORE validating a possibly bad returned FD.
        self.extra.append(fd)
        need(len(self.extra) <= FD_LIMIT and not os.get_inheritable(fd), "cli-fixture-fd-bound")
        return fd

    def directory(self, parent, name, *, owner, mode=None, create=False):
        fd = self.retain(self.f._mkdir(parent, name) if create else self.f._open(name, parent, directory=True))
        before = _sig(os.fstat(fd))
        need(before == _sig(os.stat(name, dir_fd=parent, follow_symlinks=False))
             and stat.S_ISDIR(before[2]) and before[3] == owner and before[2] & 0o7022 == 0
             and (mode is None or stat.S_IMODE(before[2]) == mode), "cli-original-directory")
        self.parents.append((parent, name, fd, before[:5]))
        return fd

    def current(self):
        for parent, name, fd, stamp in self.parents:
            held = _sig(os.fstat(fd))
            need(held == _sig(os.stat(name, dir_fd=parent, follow_symlinks=False))
                 and held[:5] == stamp, "cli-fixture-parent-changed")

    def current_cli(self):
        self.current()
        need(self.cli_row is not None, "cli-runtime-unadmitted")
        parent, name, fd, before, expected = self.cli_row
        # Reuse ALL current installation/M/source originals, not just mrk path.
        for p, n, h, original in self.f.recovery_runtime_originals:
            need(_sig(os.fstat(h)) == original
                 and _sig(os.stat(n, dir_fd=p, follow_symlinks=False)) == original, "cli-runtime-original-changed")
        self.f._normal_runtime_post()
        need(_sig(os.fstat(fd)) == before and _sig(os.stat(name, dir_fd=parent, follow_symlinks=False)) == before,
             "cli-executable-original-changed")
        sha, offset = hashlib.sha256(), 0
        while offset < before[6]:
            block = os.pread(fd, min(65536, before[6] - offset), offset)
            need(bool(block), "cli-executable-read")
            sha.update(block)
            offset += len(block)
        need(sha.hexdigest() == expected and _sig(os.fstat(fd)) == before
             and _sig(os.stat(name, dir_fd=parent, follow_symlinks=False)) == before, "cli-executable-post")


def prepare(f):
    import pwd
    need(selected(f.cases) and not f.inflight and f.cli is None, "cli-fixture-order")
    c = f.cli = Fixture(f)
    account = pwd.getpwuid(f.uid)
    need(f.uid > 0 and account.pw_uid == f.uid, "cli-fixture-native-user")
    c.home = short_home(f.binding, account.pw_dir, case=_scope(f))
    parent = c.directory(None, "/", owner=0)
    path = Path("/")
    for part in Path(account.pw_dir).parts[1:]:
        path /= part
        owner = f.uid if path == Path(account.pw_dir) else 0
        parent = c.directory(parent, part, owner=owner)
    parent = c.directory(parent, c.home.name, owner=f.uid, mode=0o700, create=True)
    for name in ("Library", "Application Support", APPLICATION):
        parent = c.directory(parent, name, owner=f.uid, mode=0o700, create=True)
    f._roster(parent, (), "cli-application-not-absent")
    for index, name in enumerate(PHASES):
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = c.retain(os.open(name, flags, 0o600, dir_fd=f.states[_scope(f)]))
        phase = PhaseFile(f.states[_scope(f)], name, fd, f.uid, index == 1, case=_scope(f))
        if index == 0:
            c.native = phase
        else:
            c.driver = phase
    c.current()


def admit_installed(f, stager, parents, inventory):
    need(selected(f.cases) and not f.inflight and f.cli is not None and f.cli.cli_row is None, "cli-runtime-order")
    c = f.cli
    need(str(stager.INSTALL_ROOT / stager.APP_NAME / stager.INSTALLED_CLI) == CLI
         and stager.INSTALLED_CLI == "Contents/MacOS/mrk", "cli-runtime-fixed-role")
    parent = parents[str(stager.INSTALL_ROOT)]
    for name in (stager.APP_NAME, "Contents", "MacOS"):
        parent = c.directory(parent, name, owner=0, mode=0o555)
        stager.no_xattrs(parent)
    row = inventory.get("app/" + stager.INSTALLED_CLI)
    need(_keys(row, "path", "size", "sha256", "executable") and row["path"] == "app/" + stager.INSTALLED_CLI
         and type(row["size"]) is int and 32 <= row["size"] <= stager.INSTALLED_CLI_BYTES
         and row["executable"] is True, "cli-inventory-role")
    before, hashed, _ = f._recovery_read(parent, "mrk", 0, stager.INSTALLED_CLI_BYTES, 0o555, retain=True)
    fd = c.retain(f.recovery_runtime_originals[-1][2])
    need(before[6] == row["size"] and hashed == row["sha256"], "cli-inventory-mismatch")
    f.normal_runtime_policy[fd] = stat.S_IFREG | 0o555
    c.cli_row = (parent, "mrk", fd, before, hashed)
    c.current_cli()


def before_call(f):
    need(selected(f.cases) and f.cli is not None and f.cli.calls is None, "cli-case-reused")
    f.cli.current_cli()
    need(f.cli.native.read() == [] and f.cli.driver.read() == [], "cli-phase-not-fresh")


def report(v, require=need):
    require(_keys(v, "schemaVersion", "scope", "origin", "operationId", "ownerGeneration", "reportSha256",
                  "consumedPermission", "sameOriginalAfterLateStop", "readRevoked", "readReallowedOnly",
                  "driverSequenceCompared", "phaseOriginalsClosed", "hostWorkersJoined", "hostOriginalsClosed",
                  "projectFilesUnchanged", "liveInterruptionTested", "applicationRestartTested")
            and type(v["schemaVersion"]) is int and v["schemaVersion"] == 1 and v["scope"] == SCOPE and _origin(v["origin"])
            and _id(v["operationId"]) and _id(v["ownerGeneration"]) and v["operationId"] != v["ownerGeneration"]
            and type(v["reportSha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", v["reportSha256"]) is not None
            and type(v["hostWorkersJoined"]) is int and v["hostWorkersJoined"] == 8
            and all(v[k] is True for k in ("consumedPermission", "sameOriginalAfterLateStop", "readRevoked",
                "readReallowedOnly", "driverSequenceCompared", "phaseOriginalsClosed", "hostOriginalsClosed", "projectFilesUnchanged"))
            and v["liveInterruptionTested"] is False and v["applicationRestartTested"] is False, "cli-native-report")
    return v


def readback(f, v):
    if _scope(f) == BACKUP.SCOPE:
        return BACKUP.readback(f, v)
    report(v)
    c = f.cli
    need(not f.inflight and f.last_returned and c is not None and c.joined and c.calls.returned
         and not c.calls.failed and c.calls.next == 7 and c.calls.inflight is None, "cli-readback-originals")
    c.current_cli()
    native, driver = c.native.read(), c.driver.read()
    need(native is not None and driver is not None and len(native) == len(driver) == 4
         and driver[-1]["origin"] == v["origin"] and driver[-1]["reportSha256"] == v["reportSha256"]
         and native[1]["operationId"] == v["operationId"] and native[1]["ownerGeneration"] == v["ownerGeneration"],
         "cli-readback-comparison")
    return {"cliProcessesReturned": 7, "ipcWorkersActuallyJoined": 8, "submissions": 1,
            "sameRequestReconnected": True, "originalThreadJoined": True,
            "lateStopOnly": True, "privateEndpointCopied": False}
