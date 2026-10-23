"""One closed fixture preparation, using the existing extraction/command owners.

Import is passive. Only the current installed-observer job's fixed parent/child
entries call run(). No supplier tool, sdkmanager, key generator, registration,
licence writer, arbitrary URL, or recursive cleanup is added.
"""
from pathlib import Path
import hashlib
import os
import pwd
import re
import ssl
import stat
import sys
import urllib.request

SCOPE = "tool-setup"
CASES = ("tool-setup-cancel-transfer", "tool-setup-source-drift", "tool-setup-missing-sdk")
ROLES = ("jdk", "sdk-platform", "gradle")
FILES = (11938, 11162, 11162)
BYTES = (578785018, 102589879, 102589879)
ARCHIVE_BYTES = 388193648
TARGET = "aarch64-apple-darwin"
_CONTEXT = None
_ATTEMPT = None  # Retain the sole original attempt, including failed/unknown IO.


def source_root(source, run, attempt, home, need):
    """Fixed comparison DATA; the entry supplies actual native pwd, never HOME."""
    need(type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source)
         and source != "0" * 40 and all(type(v) is str and re.fullmatch(r"[1-9][0-9]{0,19}", v)
                                       for v in (run, attempt)), "tool-input-tuple")
    need(type(home) is str and Path(home).is_absolute() and str(Path(home)) == home
         and home != "/" and len(Path(home).parts) <= 17
         and all(p not in (".", "..") and len(os.fsencode(p)) <= 255 for p in Path(home).parts[1:]),
         "tool-input-native-home")
    result = Path(home) / "Library/Application Support" / f"mrk-macos-tool-inputs-{source}-{run}-{attempt}"
    need(len(os.fsencode(result)) <= 4096 and len(result.parts) <= 22, "tool-input-source-path")
    return result


def context(a):
    global _CONTEXT
    a.need(_CONTEXT is None and a.RUN_SCOPE == a.TOOL_SCOPE
           and os.environ.get("MRK_MACOS_NATIVE_SCOPE") == SCOPE
           and os.environ.get("MRK_MACOS_TARGET") == TARGET
           and Path(a.__file__).absolute() == a.SOURCE / "desktop/tools/macos_android_dependency_preparation.py"
           and Path(__file__).absolute() == a.SOURCE / "desktop/tools/macos_tool_setup_inputs.py"
           and sys.version_info[:3] == (3, 14, 7), "tool-input-fixed-entry")
    driver = a.load("_mrk_tool_input_current_driver", "desktop/tools/macos_identity_current_runtime.py")
    if os.environ.get("MRK_CANDIDATE_MODE") == "install-retained-observer":
        a.need(a.SOURCE == a.UI_CONSUMER_SOURCE, "tool-input-retained-helper")
        uid, gid, username, _host = driver._native_user(os.environ, retained=True)
        # Current helper/run authority stays current; only the validated
        # original product tuple selects the compiled observer's fixture path.
        source, run, attempt, work = driver.retained_fixture_context(os.environ, TARGET, uid, gid)
    else:
        source, run, attempt, work = driver.current_context(os.environ, TARGET)
        uid, gid, username, _host = driver._native_user(os.environ)
    account = pwd.getpwuid(uid)
    a.need(account.pw_uid == uid and account.pw_gid == gid and username == account.pw_name
           and os.environ.get("MRK_ANDROID_PREPARATION_WORK") == str(work), "tool-input-native-account")
    root = source_root(source, run, attempt, account.pw_dir, a.need)
    _CONTEXT = (source, run, attempt, work, root, uid, gid)
    return work, TARGET


def expected_cases(a, catalogue):
    """Exact supported source subsets, not a complete/registered SDK claim."""
    a.need(type(catalogue) is dict, "tool-input-catalogue")
    platform = {p: v for p, v in catalogue.items() if v[0] != "metadata"
                and (p in ("sdk", "sdk/platforms", "sdk/platforms/android-35")
                     or p.startswith("sdk/platforms/android-35/"))}
    a.need(platform and all(v[0] in ("directory", "file") for v in platform.values()), "tool-input-platform-only")
    first = {p: v for p, v in catalogue.items() if p == "jdk" or p.startswith("jdk/")
             or p == "gradle" or p.startswith("gradle/")}
    first.update(platform)
    values = (first, dict(platform), dict(platform))
    a.need(tuple(sum(v[0] == "file" for v in value.values()) for value in values) == FILES
           and tuple(sum(v[2] for v in value.values()) for value in values) == BYTES
           and all(len(value) <= a.ENTRIES for value in values), "tool-input-exact-subsets")
    return values


def parent_read_reserve(a):
    # Two complete parent POST allowances plus both catalogue reads, all three
    # rosters/EOFs and bounded private output. Same8GiB aggregate, not three new
    # whole-preparation quotas. Unknown reads are never refunded.
    return 2 * (a.TOOL_BYTES + 3 * (a.FILES + 2 * ((4 << 20) + 1))) + 2 * (a.UI_CATALOGUE_PIN[0] + 1) + (8 << 20)


class _Reads:
    def __init__(self, a, clock):
        self.a, self.clock, self.reads, self.writes = a, clock, 0, 0
        self.maximum = a.READ_BYTES - parent_read_reserve(a)
        a.need(self.maximum > 0, "tool-input-whole-read-reservation")

    def read(self, amount):
        self.clock.check()
        self.a.need(type(amount) is int and 0 <= amount <= self.a.CHUNK
                    and self.reads + amount <= self.maximum, "tool-input-whole-read-bound")
        self.reads += amount

    def file(self, amount):
        self.clock.check()
        self.a.need(type(amount) is int and 0 <= amount <= 512 << 20
                    and self.writes + amount <= self.a.TOOL_BYTES, "tool-input-whole-write-bound")
        self.writes += amount  # Before opening/writing; unknown effects keep debit.


def _case_type(a):
    class Inputs(a.UiAcquisition):
        def __init__(self, work, source, expected, index, shared):
            self.source, self.shared = source, shared
            a.Acquisition.__init__(self, work, clock=shared.clock)
            self.archives = [r for r in a.ARCHIVES if r["role"] in (ROLES if index == 0 else ("sdk-platform",))]
            self.expected = expected

        @property
        def tools_root(self):
            return self.source["path"]

        def point(self):
            self.clock.check()
            a.recheck_chain(self.source["fds"], self.source["originals"])

        def charge_read(self, amount):
            self.shared.read(amount)
            super().charge_read(amount)

        def begin(self, row):
            self.shared.file(row[3])
            super().begin(row)

        def replay_platform(self, original):
            # A NEW original open of the same verified public archive. Not a
            # revived FD/lease or receipt-based shortcut, and never another GET.
            role = next(r for r in self.archives if r["role"] == "sdk-platform")
            path, before = original
            held = a.chain(path.parent, retained=True)
            fd = None
            primary = None
            try:
                self.role = role
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=held[0][-1])
                self.archive_fd, self.archive_before, self.archive_path = fd, a.nine(os.fstat(fd)), path
                a.need(self.archive_before == before and before[3:7] == (os.getuid(), os.getgid(), 1, role["bytes"])
                       and stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) == 0o600, "tool-input-replay-original")
                sha = hashlib.sha256()
                for offset in range(0, role["bytes"], a.CHUNK):
                    amount = min(a.CHUNK, role["bytes"] - offset)
                    raw = self.read_at(offset, amount)
                    a.need(len(raw) == amount, "tool-input-replay-short")
                    sha.update(raw)
                a.need(not self.read_at(role["bytes"], 1) and sha.hexdigest() == role["sha256"], "tool-input-replay-digest")
                self.verify_binding()
                capture = a.C.compile_archive(self, a.C.Pin(role["role"], role["bytes"], role["sha256"]), observer=self)
                capture.consume_rows(self.terminal_row)
                self.verify_binding()
                a.recheck_chain(*held)
            except BaseException as error:
                primary = error
                raise
            finally:
                failure = None
                if self.active is not None:
                    active, self.active = self.active, None
                    try:
                        a.close_chain(*active[1], file_fd=active[0])
                    except BaseException as error:
                        failure = error
                self.archive_fd = None
                try:
                    a.close_chain(*held, file_fd=fd)
                except BaseException as error:
                    if failure is None:
                        failure = error
                if primary is None and failure is not None:
                    raise failure
    return Inputs


def _remember(a, path):
    original = a.admit_work(path)
    _ATTEMPT["roots"].append(original)
    return original


def _new(a, parent, name, clock):
    # All callers below supply this closed leaf roster; never mkdirall or adopt.
    a.need(name in (*CASES, "tool-setup-inputs", "archives", "tmp") or name == _CONTEXT[4].name,
           "tool-input-directory-role")
    clock.check()
    a.recheck_chain(parent["fds"], parent["originals"])
    os.mkdir(name, 0o700, dir_fd=parent["fds"][-1])
    child = _remember(a, parent["path"] / name)
    a.need(a.nine(os.fstat(child["fds"][-1]))[:5] == a.nine(os.stat(name, dir_fd=parent["fds"][-1], follow_symlinks=False))[:5],
           "tool-input-new-child-binding")
    os.fsync(child["fds"][-1])
    os.fsync(parent["fds"][-1])
    a.recheck_chain(parent["fds"], parent["originals"])
    clock.check()
    return child


def _facts(a, original):
    a.recheck_chain(original["fds"], original["originals"])
    return list(a.nine(os.fstat(original["fds"][-1]))[:5])


def _binding(a, root, sources, stage, stages):
    source, run, attempt, _, _, _, _ = _CONTEXT
    return {"schemaVersion": 1, "scope": "tool-input-originals-v1", "sourceCommit": source,
        "runId": run, "runAttempt": attempt, "target": TARGET,
        "root": _facts(a, root), "stage": _facts(a, stage),
        "cases": {case: {"source": _facts(a, sources[i]), "stage": _facts(a, stages[i])} for i, case in enumerate(CASES)}}


def _close(a, first):
    if _ATTEMPT["inflight"]:
        return first  # Same unreturned command retains all exact originals.
    for original in reversed(_ATTEMPT["roots"]):
        try:
            a.close_chain(original["fds"], original["originals"])
        except BaseException as error:
            if first is None:
                first = error
    return first


def _child(a, work, private, clock):
    a.need(os.environ.get("MRK_ANDROID_ACQUISITION_CHILD") == "1", "tool-input-child-role")
    root = _remember(a, _CONTEXT[4])
    stage = _remember(a, work / "tool-setup-inputs")
    sources = [_remember(a, root["path"] / case) for case in CASES]
    stages = [_remember(a, stage["path"] / case) for case in CASES]
    raw, _ = a.read(stage["path"] / "tool-setup-origin.json", 16384, clock=clock)
    a.need(a.N.document(raw) == _binding(a, root, sources, stage, stages), "tool-input-original-parent-binding")
    # An existing/partial fixture cannot become a new attempt or resume grant.
    for source in sources:
        a.need(os.listdir(source["fds"][-1]) == [], "tool-input-source-already-populated")
    shared = _Reads(a, clock)
    for offset in range(0, a.UI_CATALOGUE_PIN[0], a.CHUNK):
        shared.read(min(a.CHUNK, a.UI_CATALOGUE_PIN[0] - offset))
    shared.read(1)
    expected = expected_cases(a, a.ui_source_roster(clock, target=TARGET))
    for offset in range(0, 1 << 20, a.CHUNK):
        shared.read(a.CHUNK)
    shared.read(1)
    ca, identity = a.read(Path("/private/etc/ssl/cert.pem"), 1 << 20, clock=clock)
    a.need(identity[3] == 0, "root-owned-stock-ca")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.minimum_version, tls.verify_mode, tls.check_hostname = ssl.TLSVersion.TLSv1_2, ssl.CERT_REQUIRED, True
    tls.load_verify_locations(cadata=ca.decode("ascii"))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), a.P.NoRedirect(), urllib.request.HTTPSHandler(context=tls))
    Inputs = _case_type(a)
    platform = None
    results = []
    for index, case in enumerate(CASES):
        original = Inputs(stages[index]["path"], sources[index], expected[index], index, shared)
        _ATTEMPT["extractions"].append(original)  # BEFORE its first effect.
        if index == 0:
            for archive in original.archives:
                original.capture(archive, opener)
                if archive["role"] == "sdk-platform":
                    platform = (original.archive_path, original.archive_before)
        else:
            a.need(platform is not None, "tool-input-platform-original-missing")
            original.replay_platform(platform)
        roster = original.seal()
        a.need(original.active is None and original.archive_fd is None and original.files == FILES[index]
               and original.writes == BYTES[index], "tool-input-extraction-incomplete")
        results.append({"case": case, "toolRosterSha256": roster, "toolBytes": original.writes,
            "files": original.files, "entries": original.entries, "directories": len(original.directories)})
    a.need(sum(r["toolBytes"] for r in results) == sum(BYTES)
           and sum(x.downloads for x in _ATTEMPT["extractions"]) == ARCHIVE_BYTES, "tool-input-missing-only-totals")
    a.need(a.N.document(raw) == _binding(a, root, sources, stage, stages), "tool-input-originals-post")
    value = {"schemaVersion": 1, "scope": "three-platform-fixtures-not-installed-v1", "sourceCommit": _CONTEXT[0],
        "runId": _CONTEXT[1], "runAttempt": _CONTEXT[2], "target": TARGET, "archiveRoles": list(ROLES),
        "archiveBytes": ARCHIVE_BYTES, "toolBytes": shared.writes, "readBytes": shared.reads,
        "cases": results, "sdkMetadata": False, "licencesWritten": False, "nativeExecuted": False,
        "protectedRegistration": False, "stockCaSha256": a.digest(ca), "phaseClock": clock.before_publication()}
    a.publish_preparation(stage["path"], "tool-setup-inputs.json", a.encoded(value), clock=clock)
    a.recheck_chain(private["fds"], private["originals"])


def _parent(a, work, private, clock):
    root_path = _CONTEXT[4]
    held = a.chain(root_path.parent, retained=True)
    support = {"path": root_path.parent, "fds": held[0], "originals": held[1]}
    _ATTEMPT["roots"].append(support)
    for fd in (support["fds"][-1], private["fds"][-1]):
        available = os.fstatvfs(fd)
        a.need(available.f_bavail * available.f_frsize >= 8 << 30, "eight-gib-free-prerequisite")
    root = _new(a, support, root_path.name, clock)
    sources = [_new(a, root, case, clock) for case in CASES]
    stage = _new(a, private, "tool-setup-inputs", clock)
    stages = [_new(a, stage, case, clock) for case in CASES]
    temporary = _new(a, stage, "tmp", clock)
    for original in stages:
        _new(a, original, "archives", clock)
    before = _binding(a, root, sources, stage, stages)
    a.publish_preparation(stage["path"], "tool-setup-origin.json", a.encoded(before), clock=clock)
    environment = a.clean_environment(temporary["path"])
    for key in ("GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_SHA", "GITHUB_WORKFLOW_SHA",
                "GITHUB_WORKFLOW_REF", "GITHUB_WORKSPACE", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_ENVIRONMENT",
                "RUNNER_OS", "RUNNER_ARCH", "MRK_EXPECTED_SHA", "MRK_MACOS_INSTALL_SOURCE_COMMIT", "MRK_MACOS_STORE_RUNTIME",
                "MRK_MACOS_NATIVE_SCOPE", "MRK_MACOS_PACKAGE_ROLE", "MRK_MACOS_WORK", "MRK_MACOS_TARGET", "MRK_ANDROID_PREPARATION_WORK",
                "MRK_MACOS_RUNNER", "MRK_MACOS_MACHINE", "MRK_MACOS_HOSTED_JOB"):
        environment[key] = os.environ[key]
    retained = os.environ.get("MRK_CANDIDATE_MODE") == "install-retained-observer"
    if retained:
        for key in ("MRK_CANDIDATE_MODE", "MRK_CANDIDATE_SOURCE"):
            environment[key] = os.environ[key]
    environment["MRK_ANDROID_ACQUISITION_CHILD"] = "1"
    cwd = a.UI_CONSUMER_SOURCE.parent if retained else a.SOURCE
    phase = a.N.NormalPhase(a.N.load_normal_owner(a.SOURCE), environment, cwd, clock)
    _ATTEMPT["phase"] = phase
    # Reuse the existing original caller and fixed source PRE/POST commands.
    _ATTEMPT["inflight"] = True
    a.source_original(phase, "pre")
    _ATTEMPT["inflight"] = False
    _ATTEMPT["inflight"] = True
    result = phase.call("android-tool-setup-three-source-fixtures", [sys.executable, "-I", "-S", "-B",
        str(a.SOURCE / "desktop/tools/macos_android_dependency_preparation.py"), a.TOOL_COMMANDS[1]], a.ACQUISITION_SECONDS, 16384)
    _ATTEMPT["inflight"] = False
    a.need(result.returncode == 0, "tool-input-original-child-return")
    a.need(_binding(a, root, sources, stage, stages) == before, "tool-input-parent-post")
    raw, _ = a.read(stage["path"] / "tool-setup-inputs.json", 16384, clock=clock)
    value = a.N.document(raw)
    expected = expected_cases(a, a.ui_source_roster(clock, target=TARGET))
    _receipt(a, value)
    a.need(value["readBytes"] + parent_read_reserve(a) <= a.READ_BYTES, "tool-input-parent-read-reservation")
    for index, case in enumerate(CASES):
        row = value["cases"][index]
        observed = a._ui_tool_post(stages[index]["path"], clock, expected[index], sources[index]["path"])
        a.need(observed == (row["toolRosterSha256"], BYTES[index], FILES[index], row["directories"]), "tool-input-live-source-post")
    _ATTEMPT["inflight"] = True
    a.source_original(phase, "post")
    _ATTEMPT["inflight"] = False
    a.need(_binding(a, root, sources, stage, stages) == before, "tool-input-final-parent-post")
    a.publish_preparation(stage["path"], "tool-setup-commands.json", a.encoded(phase.records), clock=clock)


def _receipt(a, value):
    a.need(type(value) is dict and set(value) == {"schemaVersion", "scope", "sourceCommit", "runId", "runAttempt", "target",
        "archiveRoles", "archiveBytes", "toolBytes", "readBytes", "cases", "sdkMetadata", "licencesWritten", "nativeExecuted",
        "protectedRegistration", "stockCaSha256", "phaseClock"}, "tool-input-receipt-fields")
    a.need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
           and value["scope"] == "three-platform-fixtures-not-installed-v1" and value["sourceCommit"] == _CONTEXT[0]
           and value["runId"] == _CONTEXT[1] and value["runAttempt"] == _CONTEXT[2] and value["target"] == TARGET
           and value["archiveRoles"] == list(ROLES) and value["archiveBytes"] == ARCHIVE_BYTES
           and value["toolBytes"] == sum(BYTES) and type(value["readBytes"]) is int and 0 < value["readBytes"] <= a.READ_BYTES
           and all(value[k] is False for k in ("sdkMetadata", "licencesWritten", "nativeExecuted", "protectedRegistration"))
           and type(value["stockCaSha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["stockCaSha256"]), "tool-input-receipt-binding")
    a.need(type(value["cases"]) is list and len(value["cases"]) == 3, "tool-input-receipt-cases")
    for index, row in enumerate(value["cases"]):
        a.need(type(row) is dict and set(row) == {"case", "toolRosterSha256", "toolBytes", "files", "entries", "directories"}
               and row["case"] == CASES[index] and row["toolBytes"] == BYTES[index] and row["files"] == FILES[index]
               and type(row["toolRosterSha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["toolRosterSha256"])
               and all(type(row[k]) is int and 0 < row[k] <= a.ENTRIES for k in ("entries", "directories")), "tool-input-receipt-case")
    a.clock_record(value["phaseClock"], 810)


def run(a, work, private, *, child):
    global _ATTEMPT
    a.need(type(child) is bool and _CONTEXT is not None and _ATTEMPT is None
           and private is not None and private["path"] == work == _CONTEXT[3], "tool-input-one-original-attempt")
    clock = a.N.PhaseClock(810 if child else a.PHASE_SECONDS)
    _ATTEMPT = {"roots": [], "extractions": [], "phase": None, "inflight": False, "first": None}
    error = None
    try:
        (_child if child else _parent)(a, work, private, clock)
    except BaseException as first:
        error = first
    error = _close(a, error)
    _ATTEMPT["first"] = error
    if error is not None:
        raise error
    clock.check()
    return clock  # Existing main closes its original work before finish().
