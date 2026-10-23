"""Two closed Git recipes on the existing Fixtures/Calls/installed-mrk owners.

No process is created here except through the supplied original run_owned. No
account, remote, alternate transport, permission, or native receipt is made.
"""
from contextlib import ExitStack
from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import zlib

_spec = spec_from_file_location("mrk_git_cli_fixture_io", Path(__file__).with_name("macos_git_upstream_qualification.py"))
if _spec is None or _spec.loader is None:
    raise RuntimeError("git-cli-fixture-io-unavailable")
upstream = module_from_spec(_spec)
_spec.loader.exec_module(upstream)
del _spec
shared = upstream.shared
INDEX, BRANCH = "git-index-cli", "git-branch-cli"
CASES = (INDEX, BRANCH)
SCOPES = ("git-index-cli-native", "git-branch-cli-native")
SUCCESS_SECONDS, APP_SECONDS, TOTAL_SECONDS = 120, 135, 600
UNTRACKED = upstream.UNTRACKED
BRANCH_REF = "refs/heads/observer-local"
BLOB = hashlib.sha1(b"blob " + str(len(UNTRACKED)).encode("ascii") + b"\0" + UNTRACKED).hexdigest()
_need, _sig = shared._need, shared._sig


def selected(cases):
    return cases in ((INDEX,), (BRANCH,))


def policy(case):
    _need(case in CASES, "git-cli-fixed-case")
    return (8, 5, SUCCESS_SECONDS, APP_SECONDS) if case == INDEX else (5, 3, SUCCESS_SECONDS, APP_SECONDS)


def scope(case):
    policy(case)
    return SCOPES[CASES.index(case)]


def phases(case):
    policy(case)
    return (("allowed", "prepared", "terminal", "revoked", "reallowed"),
            ("submitted", "started", "checked", "denied", "done")) if case == INDEX else (
            ("allowed", "prepared", "terminal"), ("submitted", "started", "done"))


def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(v):
    return hashlib.sha256(canonical(v)).hexdigest()


def keys(v, *names):
    return type(v) is dict and set(v) == set(names)


def ident(v):
    return type(v) is str and re.fullmatch("[0-9a-f]{32}", v) is not None and v != "0" * 32


def native_id(v):
    return type(v) is str and re.fullmatch("[A-Za-z0-9_-]{1,96}", v) is not None


def hashed(v):
    return type(v) is str and re.fullmatch("[0-9a-f]{64}", v) is not None


def origin(v):
    return keys(v, "projectId", "serviceInstance", "requestId") and all(ident(x) for x in v.values())


def _phase(c, calls, number):
    names, _ = phases(calls.case)
    while True:
        calls.check()
        rows = c.native.read()
        if rows is not None:
            _need(len(rows) <= number + 1 and all(v.get("phase") == names[i] for i, v in enumerate(rows)), "git-cli-phase-order")
            if len(rows) == number + 1:
                return rows[-1]
        calls.wait()


def selection(v, case, allowed):
    if case == INDEX:
        _need(keys(v, "summary", "paths") and v["paths"] == ["untracked.txt"], "git-cli-index-selection")
        s = v["summary"]
        _need(keys(s, "action", "repositoryRevision", "pathCount", "selectionSha256")
              and s["action"] == "stage" and s["repositoryRevision"] == allowed["repositoryRevision"]
              and type(s["pathCount"]) is int and s["pathCount"] == 1
              and s["selectionSha256"] == allowed["selectionSha256"], "git-cli-index-selection")
        return s
    _need(keys(v, "action", "selectionSha256") and v["selectionSha256"] == allowed["selectionSha256"]
          and v["action"] == {"kind": "branch-create", "expectedRevision": allowed["repositoryRevision"],
              "expectedReferenceRevision": allowed["referenceRevision"], "name": "observer-local"}, "git-cli-branch-selection")
    return v


def status(v, expected_origin, grant, selected_summary, prepared=None, terminal=None):
    _need(keys(v, "origin", "grantId", "selection", "revision", "state", "prepareOperationId", "applyOperationId",
               "review", "outcome", "settlement", "reason", "historyAvailable", "doNotReplay")
          and v["origin"] == expected_origin and v["grantId"] == grant and v["selection"] == selected_summary
          and type(v["revision"]) is int and 0 < v["revision"] < 2 ** 32
          and v["doNotReplay"] is True, "git-cli-status-origin")
    if prepared is not None:
        _need(v["prepareOperationId"] == prepared["prepareOperationId"], "git-cli-original-prepare")
    if terminal is not None:
        _need(v["state"] == "finished" and v["settlement"] == "settled" and v["outcome"] == "succeeded"
              and v["reason"] is None and v["review"] is None and v["historyAvailable"] is True
              and v["applyOperationId"] == terminal["applyOperationId"] and digest(v) == terminal["statusSha256"],
              "git-cli-original-not-finished")
    elif prepared is not None:
        _need(v["state"] == "prepared" and v["settlement"] == "pending" and v["outcome"] is None
              and v["reason"] is None and v["applyOperationId"] is None and v["historyAvailable"] is True
              and type(v["review"]) is dict and v["review"].get("reviewId") == prepared["reviewId"]
              and v["review"].get("reviewDigest") == prepared["reviewDigest"] and digest(v) == prepared["statusSha256"],
              "git-cli-original-not-prepared")
    else:
        _need(v["state"] in ("queued", "preparing", "prepared") and v["reason"] is None, "git-cli-prepare-refused")
    return v


def journey(c, calls, call):
    case = calls.case
    prefix = "git-index" if case == INDEX else "git-repository"
    allowed = _phase(c, calls, 0)
    _need(keys(allowed, "phase", "projectId", "grantId", "repositoryRevision", "referenceRevision", "selectionSha256")
          and ident(allowed["projectId"]) and ident(allowed["grantId"])
          and all(hashed(allowed[k]) for k in ("repositoryRevision", "referenceRevision", "selectionSha256")), "git-cli-allowed")
    project, grant = allowed["projectId"], allowed["grantId"]
    instance, view = call(0, [prefix + "-scope", project], prefix + "-scope")
    _need(keys(view, "serviceInstance", "projectId", "access") and ident(instance)
          and view["serviceInstance"] == instance and view["projectId"] == project, "git-cli-scope")
    a = view["access"]
    _need(keys(a, "enabled", "remainingMs", "consumed", "projectId", "grantId", "selection")
          and a["enabled"] is True and a["consumed"] is False and a["projectId"] == project and a["grantId"] == grant
          and type(a["remainingMs"]) is int and 0 < a["remainingMs"] <= 900000, "git-cli-grant")
    chosen = selection(a["selection"], case, allowed)
    same, submitted = call(1, [prefix + "-prepare", project, instance, grant], prefix + "-request")
    o = submitted.get("origin")
    _need(same == instance and origin(o) and o["projectId"] == project and o["serviceInstance"] == instance, "git-cli-submit-origin")
    status(submitted, o, grant, chosen)
    c.driver.append({"phase": "submitted", "origin": o})
    prepared = _phase(c, calls, 1)
    _need(keys(prepared, "phase", "prepareOperationId", "reviewId", "reviewDigest", "statusSha256")
          and native_id(prepared["prepareOperationId"]) and native_id(prepared["reviewId"])
          and hashed(prepared["reviewDigest"]) and hashed(prepared["statusSha256"]), "git-cli-native-prepared")
    query = [project, instance, o["requestId"]]
    same, v = call(2, [prefix + "-status", *query], prefix + "-request")
    _need(same == instance, "git-cli-instance")
    status(v, o, grant, chosen, prepared)
    same, started = call(3, [prefix + "-start", *query, prepared["prepareOperationId"], prepared["reviewId"]], prefix + "-request")
    _need(same == instance and started.get("origin") == o and started.get("prepareOperationId") == prepared["prepareOperationId"]
          and started.get("grantId") == grant and started.get("selection") == chosen and started.get("doNotReplay") is True
          and started.get("state") in ("start-queued", "applying", "finished"), "git-cli-start-original")
    c.driver.append({"phase": "started", "origin": o, "prepareOperationId": prepared["prepareOperationId"], "reviewId": prepared["reviewId"]})
    terminal = _phase(c, calls, 2)
    _need(keys(terminal, "phase", "applyOperationId", "statusSha256") and native_id(terminal["applyOperationId"])
          and hashed(terminal["statusSha256"]), "git-cli-native-terminal")
    same, v = call(4, [prefix + "-status", *query], prefix + "-request")
    _need(same == instance, "git-cli-instance")
    status(v, o, grant, chosen, prepared, terminal)
    if case == INDEX:
        same, v = call(5, [prefix + "-cancel", *query], prefix + "-request")
        _need(same == instance, "git-cli-instance")
        status(v, o, grant, chosen, prepared, terminal)
        c.driver.append({"phase": "checked", "origin": o, "statusSha256": terminal["statusSha256"]})
        _need(_phase(c, calls, 3) == {"phase": "revoked"}, "git-cli-revoked")
        call(6, [prefix + "-scope", project], None)
        c.driver.append({"phase": "denied"})
        _need(_phase(c, calls, 4) == {"phase": "reallowed"}, "git-cli-reallowed")
        same, v = call(7, [prefix + "-status", *query], prefix + "-request")
        _need(same == instance, "git-cli-instance")
        status(v, o, grant, chosen, prepared, terminal)
    c.driver.append({"phase": "done", "origin": o, "statusSha256": terminal["statusSha256"]})
    calls.returned = True


def fixture_data(config, version, keep, ignore, source):
    return upstream.fixture_data(config, version, keep, ignore, source)


def fixture_path(binding, home, case):
    return shared._support(binding, home) / f"mrk-macos-aqua-{binding.source}-{binding.run}-{binding.attempt}-{scope(case)}"


def prepare_namespace(f):
    import pwd
    _need(selected(f.cases) and f.path is None and f.git_cli is None and not f.inflight, "git-cli-namespace-order")
    u = pwd.getpwuid(f.uid)
    _need(f.uid > 0 and (u.pw_uid, u.pw_gid) == (f.uid, f.gid), "git-cli-native-user")
    f.git_cli = {"parents": [], "toolParents": [], "tool": None, "end": time.monotonic() + TOTAL_SECONDS,
                 "caseEnd": None, "calls": 0, "before": None, "entered": False, "completed": False}
    f.path = fixture_path(f.binding, u.pw_dir, f.cases[0])
    f.parent = shared._ancestors(f, f.path.parent, f.git_cli["parents"])
    namespace_current(f)


def namespace_current(f):
    _need(selected(f.cases) and f.git_cli is not None and f.git_cli["parents"]
          and f.parent == f.git_cli["parents"][-1][2], "git-cli-parent-original")
    shared._parents_current(f, f.git_cli["parents"])


def tool_current(f):
    g = f.git_cli
    _need(g is not None and g["tool"] is not None, "git-cli-clt-not-held")
    shared._parents_current(f, g["toolParents"])
    parent, fd, before, hashed_tool = g["tool"]
    _need(fd in f.fds and _sig(os.fstat(fd)) == before, "git-cli-clt-original")
    actual = shared._read(f, parent, "git", shared.TOOL_LIMIT, root_owned=True)
    _need(actual[:2] == (before, hashed_tool) and _sig(os.fstat(fd)) == before, "git-cli-clt-changed")


def _tool(f):
    g = f.git_cli
    _need(g["tool"] is None, "git-cli-clt-repeat")
    parent = shared._ancestors(f, Path(shared.GIT).parent, g["toolParents"])
    _need(all(row[3][3] == 0 for row in g["toolParents"]), "git-cli-clt-parent-owner")
    fd = f._open("git", parent)
    before = _sig(os.fstat(fd))
    _need(before[3] == 0 and stat.S_ISREG(before[2]) and before[5] == 1 and before[2] & 0o7022 == 0
          and before[2] & 0o111 and 0 < before[6] <= shared.TOOL_LIMIT, "git-cli-clt-shape")
    actual = shared._read(f, parent, "git", shared.TOOL_LIMIT, root_owned=True)
    _need(actual[0] == before == _sig(os.fstat(fd)), "git-cli-clt-original")
    g["tool"] = (parent, fd, before, actual[1])


def remaining(f, case):
    _need(f.cases == (case,) and selected(f.cases) and f.git_cli is not None
          and type(f.git_cli["caseEnd"]) is float and not f.close_errors, "git-cli-original-clock")
    left = min(f.git_cli["caseEnd"], f.git_cli["end"]) - time.monotonic()
    _need(left >= 1, "git-cli-fixture-deadline")
    return math.floor(left)


def _call(f, run_owned, env, args):
    g, case = f.git_cli, f.cases[0]
    _need(not f.inflight and g["calls"] < 16, "git-cli-setup-call-order")
    timeout = min(5, remaining(f, case))
    tool_current(f)
    argv = [shared.GIT, "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args]
    g["calls"] += 1
    f.case, f.stage, f.inflight, f.last_returned = case, "git-cli-local-setup", True, False
    v = run_owned(argv, environ=env, cwd=f.path / case, timeout=timeout, capture=True, text=False, output_limit=4096)
    _need(type(v) is subprocess.CompletedProcess and type(v.args) is list and v.args == argv and type(v.returncode) is int
          and type(v.stdout) is bytes and type(v.stderr) is bytes and len(v.stdout) + len(v.stderr) <= 4096, "git-cli-setup-original")
    f.inflight, f.last_returned = False, True
    tool_current(f); remaining(f, case)
    _need(v.returncode == 0, "git-cli-setup-failed")
    return v.stdout


def git_tree(f, git):
    # Full fixed tree, every loose object/parent original, <=128 entries/512KiB.
    rows, total = {}, 0
    fixed = {".": {"HEAD", "config", "index", "COMMIT_EDITMSG", "objects", "refs", "logs", "description", "branches"},
             "refs": {"heads", "tags"}, "refs/heads": {"main", "observer-local"}, "refs/tags": set(),
             "logs": {"HEAD", "refs"}, "logs/refs": {"heads"}, "logs/refs/heads": {"main", "observer-local"},
             "objects/info": set(), "objects/pack": set(), "branches": set()}
    def visit(fd, path):
        nonlocal total
        before = _sig(os.fstat(fd))
        _need(before[2] == stat.S_IFDIR | 0o700 and before[3:5] == (f.uid, f.gid), "git-cli-directory")
        names = shared._names(f, fd, 64)
        if path == "objects":
            _need(all(n in ("info", "pack") or re.fullmatch("[0-9a-f]{2}", n) for n in names), "git-cli-object-roster")
        elif re.fullmatch("objects/[0-9a-f]{2}", path):
            _need(all(re.fullmatch("[0-9a-f]{38}", n) for n in names), "git-cli-object-roster")
        else:
            _need(path in fixed and set(names) <= fixed[path], "git-cli-tree-roster")
        _need(len(rows) < 128, "git-cli-tree-count")
        rows[path] = ("directory", before, names)
        for name in names:
            p = name if path == "." else path + "/" + name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                with f._temporary(f._open(name, fd, directory=True)) as child:
                    f._named(fd, name, child, 0o700); visit(child, p); f._named(fd, name, child, 0o700)
            else:
                _need(len(rows) < 128, "git-cli-tree-count")
                shape, hashed_file, body = shared._read(f, fd, name)
                total += shape[6]
                _need(total <= 512 * 1024, "git-cli-tree-bytes")
                # Only the fixed small config/new ref/log need content. Loose
                # blobs are independently bound by exact expected encoded hash.
                rows[p] = ("file", shape, hashed_file, body if p in ("config", BRANCH_REF, "logs/" + BRANCH_REF, "objects/" + BLOB[:2] + "/" + BLOB[2:]) else None)
        _need(_sig(os.fstat(fd)) == before, "git-cli-tree-read-race")
    visit(git, ".")
    _need({"HEAD", "config", "index", "refs/heads/main", "logs/HEAD", "logs/refs/heads/main",
           "objects/info", "objects/pack"} <= rows.keys(), "git-cli-tree-incomplete")
    return rows


def capture(f):
    project = f.projects[f.cases[0]]
    files = {p: shared._at(f, project, p)[:2] for p in shared.FILES}
    dirs = {}
    for p, names in ((".", (".git", ".gitignore", "app", "keep.txt", "release", "untracked.txt", "version.properties")),
                     ("app", ("build.gradle.kts",)), ("release", ("mobile-release.json",))):
        with ExitStack() as opened:
            fd = project if p == "." else opened.enter_context(f._temporary(f._open(p, project, directory=True)))
            before = _sig(os.fstat(fd))
            _need(shared._names(f, fd, 16) == names and _sig(os.fstat(fd)) == before, "git-cli-project-roster")
            dirs[p] = before
    with f._temporary(f._open(".git", project, directory=True)) as git:
        f._named(project, ".git", git, 0o700)
        tree = git_tree(f, git)
        f._named(project, ".git", git, 0o700)
    return {"files": files, "directories": dirs, "git": tree}


def compare(before, after, case, head):
    policy(case)
    _need(before["files"] == after["files"] and before["directories"] == after["directories"], "git-cli-project-changed")
    old, new = before["git"], after["git"]
    upstream.fixture_config(old["config"][3])
    branch_paths = {BRANCH_REF, "logs/" + BRANCH_REF}
    object_parent, blob = "objects/" + BLOB[:2], "objects/" + BLOB[:2] + "/" + BLOB[2:]
    _need(not branch_paths & old.keys() and blob not in old, "git-cli-original-absence")
    additions = branch_paths if case == BRANCH else ({blob} | ({object_parent} - old.keys()))
    _need(new.keys() == old.keys() | additions, "git-cli-exact-added-roster")
    for path, row in old.items():
        current = new[path]
        if case == INDEX and path == "index":
            _need(row[0] == current[0] == "file" and row[1][0] == current[1][0] and row[1][1] != current[1][1]
                  and row[1][2:6] == current[1][2:6] and row[2] != current[2], "git-cli-index-successor")
        elif path in ((".", "objects", object_parent) if case == INDEX else (".", "refs/heads", "logs/refs/heads")):
            # Both existing transactions create/remove their original config
            # and HEAD/index locks in .git. Only this same parent's metadata
            # may change; its exact final roster/identity must still match.
            expected = tuple(sorted((*row[2], *[p.rsplit("/", 1)[-1] for p in additions if p.rsplit("/", 1)[0] == path])))
            _need(row[0] == current[0] == "directory" and row[1][:5] == current[1][:5] and current[2] == expected,
                  "git-cli-parent-successor")
        else:
            _need(row == current, "git-cli-unrelated-original-changed")
    for path in additions:
        row = new[path]
        _need(row[1][0] == old["."][1][0] and row[1][3:5] == old["."][1][3:5], "git-cli-created-identity")
        if path == object_parent:
            _need(row[0] == "directory" and row[1][2] == stat.S_IFDIR | 0o700 and row[2] == (BLOB[2:],), "git-cli-created-parent")
        else:
            _need(row[0] == "file" and row[1][5] == 1, "git-cli-created-file")
    if case == INDEX:
        packed = new[blob][3]
        _need(type(packed) is bytes and len(packed) <= 65536, "git-cli-blob-bound")
        decoder = zlib.decompressobj()
        wanted = b"blob " + str(len(UNTRACKED)).encode("ascii") + b"\0" + UNTRACKED
        try:
            raw = decoder.decompress(packed, len(wanted) + 1)
        except zlib.error:
            raise ValueError("git-cli-blob-content") from None
        _need(raw == wanted and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
              "git-cli-blob-content")
    if case == BRANCH:
        _need(new[BRANCH_REF][3] == (head + "\n").encode("ascii"), "git-cli-created-ref")
        pattern = ("0" * 40 + " " + head + r" MRK Upstream Fixture <upstream-fixture@example\.invalid> [0-9]{1,12} [+-][0-9]{4}\tMRK: create reviewed branch\n").encode("ascii")
        _need(re.fullmatch(pattern, new["logs/" + BRANCH_REF][3]) is not None, "git-cli-created-reflog")
    return True


def before_invocation(f, case, run_owned, username):
    _need(f.cases == (case,) and selected(f.cases) and f.git_cli is not None and f.git_cli["caseEnd"] is None
          and not f.inflight and not f.close_errors, "git-cli-single-attempt")
    f._namespace()
    now = time.monotonic()
    _need(now < f.git_cli["end"], "git-cli-suite-clock")
    f.git_cli["caseEnd"] = min(now + SUCCESS_SECONDS, f.git_cli["end"])
    _tool(f)
    _need(f.originals[case] == f._capture(case, False), "git-cli-initial-project-changed")
    with f._temporary(f._open("tmp", f.states[case], directory=True)) as tmp:
        with f._temporary(f._mkdir(tmp, "empty-template")) as template:
            template_path = f.path / "state" / case / "tmp/empty-template"
            env = shared._environment(f, case, username, template_path)
            env.update(GIT_AUTHOR_NAME="MRK Upstream Fixture", GIT_COMMITTER_NAME="MRK Upstream Fixture",
                       GIT_AUTHOR_EMAIL="upstream-fixture@example.invalid", GIT_COMMITTER_EMAIL="upstream-fixture@example.invalid")
            with f._temporary(f._mkdir(f.projects[case], ".git")) as git:
                f._write(git, "config", upstream.CONFIG)
                version = _call(f, run_owned, env, ["--version", "--build-options"])
                _need(0 < len(version) <= 1024 and version.startswith(b"git version ")
                      and all(c in (9, 10, 13) or 32 <= c < 127 for c in version), "git-cli-build-metadata")
                _call(f, run_owned, env, ["init", "--quiet", "--initial-branch=main", "--object-format=sha1", "--template=" + str(template_path)])
                _call(f, run_owned, env, ["add", "--", *shared.FILES[:-1]])
                _call(f, run_owned, env, ["commit", "--quiet", "--no-gpg-sign", "-m", "MRK public local Git CLI fixture"])
                f.git_cli.update(head=shared._oid(_call(f, run_owned, env, ["rev-parse", "--verify", "HEAD"])), version=version.decode("ascii"))
            f._retire_git_template(case, tmp, template)
        f._roster(tmp, (), "git-cli-setup-tmp-not-empty")
    f.git_cli["before"] = capture(f)
    upstream.fixture_config(f.git_cli["before"]["git"]["config"][3])
    remaining(f, case)


def before_call(f, case):
    _need(f.cases == (case,) and f.git_cli["before"] is not None and not f.git_cli["entered"]
          and not f.inflight and f.last_returned, "git-cli-before-app")
    tool_current(f)
    _need(capture(f) == f.git_cli["before"], "git-cli-before-app-changed")
    remaining(f, case)
    f.git_cli["entered"] = True


def report(v, case, need=_need):
    count, rows, _, _ = policy(case)
    need(keys(v, "mechanism", "case", "origin", "prepareOperationId", "applyOperationId", "reviewId", "statusSha256",
              "readOriginalsJoined", "prepareOriginalsJoined", "applyOriginalsJoined", "hostWorkersJoined", "normalQuitOriginal",
              "allOriginalsSettled", "phaseOriginalsClosed", "projectDeltaCompared", "emptyRevokeRefused", "lateStopOnly",
              "readReallowedOnly", "networkRequested", "bootstrapOverride", "productionQualified")
         and v["mechanism"] == "same-original-local-git-cli-v1" and v["case"] == case and origin(v["origin"])
         and all(native_id(v[k]) for k in ("prepareOperationId", "applyOperationId", "reviewId")) and hashed(v["statusSha256"]), "git-cli-report")
    for k, expected in (("readOriginalsJoined", 2), ("prepareOriginalsJoined", 1), ("applyOriginalsJoined", 1),
                        ("hostWorkersJoined", count), ("normalQuitOriginal", 2)):
        need(type(v[k]) is int and v[k] == expected, "git-cli-original-count")
    for k in ("allOriginalsSettled", "phaseOriginalsClosed", "projectDeltaCompared"):
        need(v[k] is True, "git-cli-not-settled")
    for k in ("emptyRevokeRefused", "lateStopOnly", "readReallowedOnly"):
        need(v[k] is (case == INDEX), "git-cli-case-meaning")
    for k in ("networkRequested", "bootstrapOverride", "productionQualified"):
        need(v[k] is False, "git-cli-no-qualification")
    return v


def readback(f, v):
    case = f.cases[0]
    report(v, case)
    g, c = f.git_cli, f.cli
    count, rows, _, _ = policy(case)
    _need(g["entered"] and not g["completed"] and not f.inflight and f.last_returned and not f.close_errors
          and c.joined and c.calls.returned and not c.calls.failed and c.calls.next == count
          and c.calls.inflight is None and len(c.calls.results) == count, "git-cli-readback-originals")
    f._namespace(); tool_current(f); c.current_cli()
    native, driver = c.native.read(), c.driver.read()
    np, dp = phases(case)
    _need(native is not None and driver is not None and len(native) == len(driver) == rows
          and [r.get("phase") for r in native] == list(np) and [r.get("phase") for r in driver] == list(dp)
          and driver[-1] == {"phase": "done", "origin": v["origin"], "statusSha256": v["statusSha256"]}
          and native[1]["prepareOperationId"] == v["prepareOperationId"] and native[1]["reviewId"] == v["reviewId"]
          and native[2]["applyOperationId"] == v["applyOperationId"] and native[2]["statusSha256"] == v["statusSha256"], "git-cli-readback-phases")
    compare(g["before"], capture(f), case, g["head"])
    remaining(f, case)
    g["completed"] = True
    return {"mechanism": "same-fixtures-local-git-cli-readback-v1", "cliProcessesReturned": count,
            "ipcWorkersActuallyJoined": count, "preparations": 1, "starts": 1, "originalThreadJoined": True,
            "sameRequestReconnected": True, "lateStopOnly": case == INDEX, "privateEndpointCopied": False,
            "exactGitDeltaCompared": True, "worktreePreserved": True, "networkRequested": False,
            "cltBuildMetadata": g["version"], "toolSha256": g["tool"][3], "localSetupCalls": g["calls"], "nativeAuthority": False}
