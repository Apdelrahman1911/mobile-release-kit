"""Two fixed additional ToolSetup observations, not an acquisition engine.

Only the existing Fixtures/Calls retain files, processes and their returns.
Imports are passive; public report comparisons cannot mint native authority.
"""
import os
import re
import stat

SCOPE = "tool-public-acquisition"  # Internal selector; compiled scope stays tool-setup.
COLD = "tool-acquisition-cold-warm"
CANCEL = "tool-acquisition-cancel-in-transfer"
CASES = (CANCEL, COLD)
CANCEL_CASES = (CANCEL,)
CALLS, ROWS = 7, 3
SUCCESS_SECONDS, APP_SECONDS = 2400, 2415
NATIVE_PHASES = ("allowed", "active", "terminal")
DRIVER_PHASES = ("submitted", "checked")
ARCHIVE = "sdk-build-tools.archive"
ARCHIVE_BYTES = 76857898
MIN_CUT = 65536
POLL_LIMIT, POLL_SECONDS, POLL_INTERVAL = 6000, 120, 0.02
COLD_WARM_BYTES = 2012046476
COPY_BYTES = 102589879
RESERVE, METADATA = 2 << 30, 64 << 20
PARTS = ["jdk", "sdk-platform", "sdk-build-tools", "gradle"]
SAMPLE_BOOLS = ("firstFailure", "sameActive", "accepted", "terminal", "current", "allJoined",
                "sourceInspected", "sourceClosed", "cacheClosed", "runtimeClosed", "cacheAttempted",
                "caArmed", "transferAttempted", "childAttempted", "childWaited", "ioJoined",
                "completeSdkLocation", "reuseSelected")


def need(ok, why):
    if not ok:
        raise ValueError(why)


def keys(value, *names):
    return type(value) is dict and set(value) == set(names)


def identifier(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value) is not None and value != "0" * 32


def origin(value):
    return keys(value, "projectId", "serviceInstance", "requestId") and all(identifier(v) for v in value.values())


def receipt(query):
    need(origin(query), "tool-cli-receipt-origin")
    p, s, r = (query[k] for k in ("projectId", "serviceInstance", "requestId"))
    return (f"Request {r}\nCheck: mrk tool-setup-status {p} {s} {r} --json\n"
            f"Stop: mrk tool-setup-cancel {p} {s} {r} --json\n").encode("ascii")


def partial(stamp, uid, gid):
    return (type(stamp) in (tuple, list) and len(stamp) == 7
            and all(type(n) is int and 0 <= n < 2 ** 64 for n in stamp)
            and stamp[2] == stat.S_IFREG | 0o600 and stamp[3:6] == type(stamp)((uid, gid, 1))
            and MIN_CUT <= stamp[6] < ARCHIVE_BYTES)


def same_partial(cut, after):
    return (type(cut) is list and type(after) is list and len(cut) == len(after) == 7
            and partial(cut, cut[3], cut[4]) and partial(after, cut[3], cut[4])
            and cut[:6] == after[:6] and cut[6] <= after[6] < ARCHIVE_BYTES)


def cancelled_sample(value, require):
    flags = ("firstFailure", "sameActive", "accepted", "terminal", "allJoined", "sourceInspected", "sourceClosed",
             "cacheClosed", "runtimeClosed", "cacheAttempted", "caArmed", "transferAttempted", "childAttempted",
             "childWaited", "ioJoined")
    require(keys(value, "action", "outcome", "reason", "sourceFailure", *SAMPLE_BOOLS)
            and all(type(value[k]) is bool for k in SAMPLE_BOOLS) and all(value[k] is True for k in flags)
            and value.get("action") == "acquire" and value.get("outcome") == "cancelled"
            and value.get("reason") == "cancelled" and value.get("sourceFailure") is None
            and value.get("completeSdkLocation") is False and value.get("reuseSelected") is False,
            "tool-live-stop-originals")


def report(value, case, require, sample):
    require(case in CASES and keys(value, "mechanism", "execution", "testResult", "finding", "initial", "cold",
        "warmInitial", "warm", "coldOperation", "warmOperation", "initialSdkSelected", "selectedSources", "sourceReviewed", "cli",
        "normalQuitOriginal", "normalAcquisitionEnabled", "protectedCopyRegistered", "selectedCatalogVerified",
        "allOriginalsSettled", "projectSentinelPreserved", "productionQualified"), "tool-public-report")
    require(value["mechanism"] == "same-original-public-tool-acquisition-v1"
            and all(value[k] is False for k in ("normalAcquisitionEnabled", "protectedCopyRegistered",
                                               "selectedCatalogVerified", "productionQualified"))
            and value["allOriginalsSettled"] is True and value["projectSentinelPreserved"] is True,
            "tool-public-scope")
    require(type(value["selectedSources"]) is list and len(value["selectedSources"]) == 3
            and all(type(v) is bool for v in value["selectedSources"])
            and type(value["normalQuitOriginal"]) is int and type(value["sourceReviewed"]) is bool
            and type(value["initialSdkSelected"]) is bool,
            "tool-public-source-shape")
    if value["execution"] == "not-executed-prerequisite":
        require(case == COLD and value["testResult"] == "not-executed"
                and value["finding"] in ("service-or-catalogue", "cold-sources-not-absent")
                and value["selectedSources"] == [False] * 3
                and value["normalQuitOriginal"] == (3 if value["initialSdkSelected"] else 2)
                and not value["sourceReviewed"]
                and all(value[k] is None for k in ("cold", "warmInitial", "warm", "coldOperation", "warmOperation", "cli")),
                "tool-public-unexecuted")
        require((value["finding"] == "cold-sources-not-absent") == (value["initial"] is not None),
                "tool-public-prerequisite-source")
        if value["initial"] is not None:
            require(value["initialSdkSelected"], "tool-public-inspection-needs-original-sdk-pick")
            sample(value["initial"], "initial", require)
        return value
    require(value["execution"] == "executed" and value["finding"] == "none"
            and value["normalQuitOriginal"] == (6 if case == COLD else 5)
            and value["initialSdkSelected"] == (case == COLD) and value["selectedSources"] == [True] * 3,
            "tool-public-executed")
    sample(value["initial"], "initial", require)
    if case == COLD:
        require(value["testResult"] == "cold-warm-source-inspected" and value["sourceReviewed"]
                and value["cli"] is None and identifier(value["coldOperation"])
                and identifier(value["warmOperation"]) and value["coldOperation"] != value["warmOperation"],
                "tool-public-cold-result")
        sample(value["cold"], "acquire", require)
        sample(value["warmInitial"], "initial", require)
        sample(value["warm"], "acquire", require)
    else:
        require(value["testResult"] == "cancelled-in-transfer" and not value["sourceReviewed"]
                and all(value[k] is None for k in ("warmInitial", "warm", "coldOperation", "warmOperation")),
                "tool-public-cancel-result")
        cancelled_sample(value["cold"], require)
        cli_report(value["cli"], require)
    return value


def cli_report(value, require=need):
    require(keys(value, "origin", "operationId", "ownerGeneration", "cut", "after", "consumedPermission",
                 "duplicateRefused", "nativeCallerHistoryReturned", "phaseOriginalsClosed", "hostWorkersJoined")
            and origin(value["origin"]) and identifier(value["operationId"]) and identifier(value["ownerGeneration"])
            and value["operationId"] != value["ownerGeneration"] and same_partial(value["cut"], value["after"])
            and all(value[k] is True for k in ("consumedPermission", "duplicateRefused", "nativeCallerHistoryReturned",
                                               "phaseOriginalsClosed"))
            and type(value["hostWorkersJoined"]) is int and value["hostWorkersJoined"] == CALLS,
            "tool-cli-original-report")
    return value


def space_before(fixtures, case):
    need(case in CASES and not fixtures.inflight, "tool-public-space-order")
    available = os.fstatvfs(fixtures.parent)
    remaining = COLD_WARM_BYTES if case == COLD else COPY_BYTES + ARCHIVE_BYTES
    need(available.f_bavail * available.f_frsize >= remaining + METADATA + RESERVE,
         "tool-public-disk-prerequisite")


class TransferCut:
    """Only borrowed existing Fixtures descriptors; never reads archive bytes."""
    def __init__(self, fixture, operation):
        need(identifier(operation) and fixture.application_fd is not None, "tool-cut-original")
        self.fixture, self.operation = fixture, operation
        self.parent, self.depth, self.cut = fixture.application_fd, 0, None
        self.archives = None  # Borrowed from the same three retained directories.
        self.names = ("tool-cache-v1", "archives", "tool-" + operation)

    def sample(self):
        c = self.fixture
        c.current()
        while self.depth < len(self.names):
            name = self.names[self.depth]
            try:
                os.stat(name, dir_fd=self.parent, follow_symlinks=False)
            except FileNotFoundError:
                return None
            self.parent = c.directory(self.parent, name, owner=c.f.uid, mode=0o700)
            self.depth += 1
            if self.depth == 2:
                self.archives = self.parent
        try:
            s = os.stat(ARCHIVE, dir_fd=self.parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
        row = [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size]
        need(row[2] == stat.S_IFREG | 0o600 and row[3:6] == [c.f.uid, c.f.gid, 1]
             and row[6] < ARCHIVE_BYTES, "tool-cut-file-shape")
        if row[6] < MIN_CUT:
            return None
        need(partial(row, c.f.uid, c.f.gid), "tool-cut-partial")
        if self.cut is not None:
            need(same_partial(self.cut, row), "tool-cut-substitution-or-truncation")
        return row

    def capture(self, calls):
        need(self.cut is None, "tool-cut-reused")
        # Conservative original case-start+1200 bound is never later than the
        # actual native Acquire work end, which starts after the initial Inspect.
        end = min(calls.success_end, calls.success_end - SUCCESS_SECONDS + 1200,
                  calls.clock() + POLL_SECONDS)
        for _ in range(POLL_LIMIT):
            calls.check()
            need(calls.clock() < end, "tool-cut-not-observed")
            row = self.sample()
            if row is not None:
                self.cut = row
                return row
            calls.stop.wait(POLL_INTERVAL)  # Existing Calls stop, no new timer/owner.
        raise ValueError("tool-cut-not-observed")

    def returned(self):
        need(self.cut is not None, "tool-cut-not-captured")
        after = self.sample()
        need(after is not None and same_partial(self.cut, after), "tool-cut-returned-full-or-foreign")
        # Copied platform sources are allowed; no second transfer or success
        # result may have appeared in this genuinely cancelled original job.
        self.fixture.f._roster(self.archives, ("tool-" + self.operation,), "tool-cut-only-original-job")
        self.fixture.f._roster(self.parent, ("origin.json", "sources", ARCHIVE), "tool-cut-job-roster")
        return after


def cold_readback(fixtures, application, value):
    """Bounded post-return rosters only, never a producer/cache authority."""
    need(not fixtures.inflight and fixtures.last_returned and value["execution"] == "executed"
         and identifier(value["coldOperation"]) and identifier(value["warmOperation"])
         and value["coldOperation"] != value["warmOperation"], "tool-cold-readback-order")
    with fixtures._temporary(fixtures._open("tool-cache-v1", application, directory=True)) as cache:
        fixtures._named(application, "tool-cache-v1", cache, 0o700)
        fixtures._roster(cache, (".lease", "archives", "origins"), "tool-cold-cache-roster")
        with fixtures._temporary(fixtures._open("archives", cache, directory=True)) as archives:
            fixtures._named(cache, "archives", archives, 0o700)
            jobs = ("tool-" + value["coldOperation"], "tool-" + value["warmOperation"])
            fixtures._roster(archives, jobs, "tool-cold-two-original-jobs")
            for index, name in enumerate(jobs):
                with fixtures._temporary(fixtures._open(name, archives, directory=True)) as job:
                    fixtures._named(archives, name, job, 0o700)
                    files = ("origin.json", "result.json", "sources")
                    if index == 0:
                        files += tuple(part + ".archive" for part in PARTS)
                    fixtures._roster(job, files, "tool-cold-producer-or-warm-roster")
                    fixtures._named(archives, name, job, 0o700)
            fixtures._named(cache, "archives", archives, 0o700)
        fixtures._named(application, "tool-cache-v1", cache, 0o700)


def phase(channel, calls, name, index):
    while True:
        calls.check()
        rows = channel.read()
        if rows is not None:
            need(len(rows) <= index + 1 and all(r.get("phase") == NATIVE_PHASES[i] for i, r in enumerate(rows)),
                 "tool-cli-native-phase-order")
            if len(rows) == index + 1:
                need(rows[index].get("phase") == name, "tool-cli-native-phase")
                return rows[index]
        calls.wait()


def _status(value, original, grant, review, *, operation=None, terminal=False):
    need(keys(value, "origin", "grantId", "reviewId", "revision", "review", "state", "settlement", "reason", "operation", "outcome", "result")
         and value["origin"] == original and value["grantId"] == grant and value["reviewId"] == review
         and type(value["revision"]) is int and 0 < value["revision"] < 2 ** 32 - 1
         and type(value["review"]) is dict and value["review"].get("kind") == "acquire-reviewed-missing"
         and value["review"].get("platform") == "android"
         and value["review"].get("acquisition", {}).get("missing") == ["android-build-tools"], "tool-cli-status-origin")
    if operation is not None:
        need(value["operation"] == operation, "tool-cli-native-identity-changed")
    if terminal:
        need(value["state"] == "cancelled" and value["settlement"] == "settled" and value["outcome"] == "cancelled"
             and value["reason"] == "user-cancelled" and value["result"] is None, "tool-cli-cancel-not-retired")
    else:
        need(value["state"] in ("queued", "starting", "running", "stopping", "finishing", "cancelled")
             and value["state"] != "unknown", "tool-cli-original-unavailable")


def journey(c, calls, call):
    allowed = phase(c.native, calls, "allowed", 0)
    need(keys(allowed, "phase", "projectId", "serviceInstance", "grantId", "reviewId")
         and all(identifier(allowed[k]) for k in ("projectId", "serviceInstance", "grantId", "reviewId")), "tool-cli-allow")
    project, instance, grant, review = (allowed[k] for k in ("projectId", "serviceInstance", "grantId", "reviewId"))
    seen, observed = call(0, ["observe", project], "observation")
    need(seen == instance and observed.get("projectId") == project and observed.get("registeredInCurrentHost") is True,
         "tool-cli-observe")
    args = ["tool-setup-submit", project, instance, grant, review, "--reviewed"]
    seen, submitted = call(1, args, "tool-setup-request", receipt=True)
    query = submitted.get("origin")
    need(seen == instance and origin(query) and query["projectId"] == project and query["serviceInstance"] == instance,
         "tool-cli-submit")
    _status(submitted, query, grant, review)
    need(calls.results[1].stderr == receipt(query), "tool-cli-original-receipt")
    c.driver.append({"phase": "submitted", "origin": query})
    active = phase(c.native, calls, "active", 1)
    need(keys(active, "phase", "origin", "operationId", "ownerGeneration") and active["origin"] == query
         and identifier(active["operationId"]) and identifier(active["ownerGeneration"]), "tool-cli-active")
    # Exact original pending-row Busy on this consumed grant, not a generic
    # nonzero exit or a successful new operation. Native checks its unchanged
    # first Entry again before emitting terminal.
    rejected = call(2, args, "tool-concurrent-refusal")
    need(origin(rejected) and rejected["projectId"] == project and rejected["serviceInstance"] == instance
         and rejected["requestId"] != query["requestId"], "tool-cli-concurrent-origin")
    cut = c.transfer_cut = TransferCut(c, active["operationId"])
    before = cut.capture(calls)
    seen, stopped = call(3, ["tool-setup-cancel", project, instance, query["requestId"]], "tool-setup-request")
    need(seen == instance, "tool-cli-cancel-instance")
    operation = {"operationId": active["operationId"], "ownerGeneration": active["ownerGeneration"], "registrationGeneration": None}
    _status(stopped, query, grant, review, operation=operation)
    terminal = phase(c.native, calls, "terminal", 2)
    need(terminal == {**active, "phase": "terminal"}, "tool-cli-terminal-origin")
    for number in (4, 5):
        seen, value = call(number, ["tool-setup-status", project, instance, query["requestId"]], "tool-setup-request")
        need(seen == instance, "tool-cli-status-instance")
        _status(value, query, grant, review, operation=operation, terminal=True)
    seen, catalogue = call(6, ["requests", project], "requests")
    need(seen == instance and type(catalogue.get("schemaVersion")) is int and catalogue["schemaVersion"] == 2
         and catalogue.get("scope") == "current-host-retained-requests"
         and catalogue.get("sampling") == "per-request-not-atomic" and catalogue.get("doNotReplay") is True
         and catalogue.get("projectId") == project and catalogue.get("serviceInstance") == instance
         and catalogue.get("requests") == []
         and catalogue.get("additionalRequests") == [{"family": "tool-setup", "requestId": query["requestId"]}],
         "tool-cli-catalogue")
    after = cut.returned()
    c.driver.append({"phase": "checked", "origin": query, "cut": before, "after": after})
    calls.returned = True


def cli_readback(fixtures, value):
    cli_report(value)
    c = fixtures.cli
    need(not fixtures.inflight and fixtures.last_returned and c is not None and c.joined
         and c.calls.returned and not c.calls.failed and c.calls.next == CALLS and c.calls.inflight is None,
         "tool-cli-returned-originals")
    c.current_cli()
    native, driver = c.native.read(), c.driver.read()
    need(type(native) is list and type(driver) is list and len(native) == 3 and len(driver) == 2
         and driver[-1] == {"phase": "checked", "origin": value["origin"], "cut": value["cut"], "after": value["after"]}
         and native[-1] == {"phase": "terminal", "origin": value["origin"], "operationId": value["operationId"],
                            "ownerGeneration": value["ownerGeneration"]}
         and c.transfer_cut is not None and c.transfer_cut.returned() == value["after"], "tool-cli-readback")
    return {"cliProcessesReturned": CALLS, "ipcWorkersActuallyJoined": CALLS,
            "submissionAttempts": 2, "admittedOriginals": 1,
            "duplicateGrantRefused": True, "originalThreadJoined": True, "liveInterruptionTested": True,
            "privateEndpointCopied": False}
