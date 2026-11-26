"""One local SetUpstream case on the existing installed Fixtures/run_owned.

Only fixed public fixture setup/readback lives here. There is no remote command,
credential, runtime override, new invocation owner, or manufactured native ACK.
"""
from contextlib import ExitStack
from importlib.util import module_from_spec, spec_from_file_location
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time

_spec = spec_from_file_location("mrk_upstream_shared_fixture_io", Path(__file__).with_name("macos_git_push_qualification.py"))
if _spec is None or _spec.loader is None:
    raise RuntimeError("upstream-fixture-io-unavailable")
shared = module_from_spec(_spec)
_spec.loader.exec_module(shared)
del _spec

SCOPE = "git-upstream-native"
CASE = "git-upstream-local"
CASES = (CASE,)
TIMEOUT, TOTAL_TIMEOUT, CALL_TIMEOUT, CALLS = 120, 600, 5, 160
GIT = shared.GIT
REPOSITORY = "mrk-upstream-fixture/local"
FILES = shared.FILES
UNTRACKED = b"MRK public untracked Upstream fixture: never staged or sent.\n"
CONFIG = (b"[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false\nlogallrefupdates = true\n"
          b"[user]\nname = MRK Upstream Fixture\nemail = upstream-fixture@example.invalid\n")
APPENDED = (b'[remote "origin"]\n\turl = https://github.com/mrk-upstream-fixture/local.git\n'
            b'\tfetch = +refs/heads/*:refs/remotes/origin/*\n'
            b'[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n')
CREATED = ("refs/remotes", "logs/refs/remotes", "refs/remotes/origin", "logs/refs/remotes/origin")
_need, _sig = shared._need, shared._sig


def fixture_data(config, version, keep, ignore, source):
    files, dirs = shared.fixture_data(config, version, keep, ignore, source)
    files["untracked.txt"] = UNTRACKED
    return files, dirs


def fixture_path(binding, home):
    return shared._support(binding, home) / f"mrk-macos-aqua-{binding.source}-{binding.run}-{binding.attempt}-{SCOPE}"


def application_path(binding, home):
    return shared._support(binding, home) / f"mrk-macos-aqua-upstream-{binding.source}-{binding.run}-{binding.attempt}" / CASE / shared.APPLICATION


def prepare_namespace(f):
    import pwd
    _need(f.cases == CASES and f.path is None and not f.upstream_ancestors and not f.inflight
          and f.upstream_end is None, "upstream-namespace-order")
    f.upstream_end = time.monotonic() + TOTAL_TIMEOUT
    u = pwd.getpwuid(f.uid)
    _need(f.uid > 0 and (u.pw_uid, u.pw_gid) == (f.uid, f.gid), "upstream-native-user")
    f.path = fixture_path(f.binding, u.pw_dir)
    f.parent = shared._ancestors(f, f.path.parent, f.upstream_ancestors)
    f.upstream_path = application_path(f.binding, u.pw_dir)
    namespace_current(f)


def namespace_current(f):
    _need(f.cases == CASES and f.path is not None and f.upstream_ancestors
          and f.parent == f.upstream_ancestors[-1][2], "upstream-parent-original")
    shared._parents_current(f, f.upstream_ancestors)


def prepare_parents(f):
    _need(f.cases == CASES and not f.inflight and f.upstream_namespace is None, "upstream-app-parent-order")
    namespace_current(f)
    f.upstream_namespace = f._mkdir(f.parent, f.upstream_path.parents[1].name)
    f.upstream_parent = f._mkdir(f.upstream_namespace, CASE)
    parents_current(f)


def parents_current(f):
    namespace_current(f)
    _need(f.upstream_namespace is not None and f.upstream_parent is not None, "upstream-app-parent-custody")
    f._named(f.parent, f.upstream_path.parents[1].name, f.upstream_namespace, 0o700)
    f._roster(f.upstream_namespace, CASES, "upstream-app-namespace")
    f._named(f.upstream_namespace, CASE, f.upstream_parent, 0o700)
    if not f.upstream_entered:
        f._roster(f.upstream_parent, (), "upstream-unentered-app-parent")
    else:
        f._roster(f.upstream_parent, (shared.APPLICATION,), "upstream-returned-app-parent")


def tool_current(f):
    _need(f.upstream_tool is not None, "upstream-clt-not-held")
    shared._parents_current(f, f.upstream_tool_parents)
    parent, fd, before, hashed = f.upstream_tool
    _need(fd in f.fds and _sig(os.fstat(fd)) == before, "upstream-clt-original")
    actual = shared._read(f, parent, "git", shared.TOOL_LIMIT, root_owned=True)
    _need(actual[:2] == (before, hashed) and _sig(os.fstat(fd)) == before, "upstream-clt-changed")


def _tool(f):
    _need(f.upstream_tool is None, "upstream-clt-repeat")
    parent = shared._ancestors(f, Path(GIT).parent, f.upstream_tool_parents)
    _need(all(row[3][3] == 0 for row in f.upstream_tool_parents), "upstream-clt-parent-owner")
    fd = f._open("git", parent)
    before = _sig(os.fstat(fd))
    _need(before[3] == 0 and stat.S_ISREG(before[2]) and before[5] == 1 and before[2] & 0o7022 == 0
          and before[2] & 0o111 and 0 < before[6] <= shared.TOOL_LIMIT, "upstream-clt-shape")
    actual = shared._read(f, parent, "git", shared.TOOL_LIMIT, root_owned=True)
    _need(actual[0] == before == _sig(os.fstat(fd)), "upstream-clt-original")
    f.upstream_tool = (parent, fd, before, actual[1])


def remaining(f, case):
    _need(case == CASE and f.upstream_case is not None and not f.close_errors, "upstream-original-clock")
    left = min(f.upstream_case["end"], f.upstream_end) - time.monotonic()
    _need(left >= 1, "upstream-fixture-deadline")
    return math.floor(left)


def _call(f, run_owned, environ, args, *, limit=4096):
    row = f.upstream_case
    _need(row is not None and not f.inflight and row["calls"] < CALLS, "upstream-setup-call-order")
    timeout = min(CALL_TIMEOUT, remaining(f, CASE))
    tool_current(f)
    argv = [GIT, "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args]
    row["calls"] += 1
    f.case, f.stage, f.inflight, f.last_returned = CASE, "upstream-local-setup", True, False
    result = run_owned(argv, environ=environ, cwd=f.path / CASE, timeout=timeout,
                       capture=True, text=False, output_limit=limit)
    _need(type(result) is subprocess.CompletedProcess and type(result.args) is list and result.args == argv
          and type(result.returncode) is int and type(result.stdout) is bytes and type(result.stderr) is bytes
          and len(result.stdout) + len(result.stderr) <= limit, "upstream-setup-owner-return")
    f.inflight, f.last_returned = False, True
    tool_current(f)
    remaining(f, CASE)
    _need(result.returncode == 0, "upstream-setup-command-failed")
    return result.stdout


def _git_tree(f, git):
    """Complete small fixture tree, with every original file/parent compared."""
    rows, total = {}, 0
    fixed = {".": {"HEAD", "config", "index", "COMMIT_EDITMSG", "objects", "refs", "logs", "description", "branches"},
             "refs": {"heads", "tags", "remotes"}, "refs/heads": {"main"}, "refs/tags": set(),
             "logs": {"HEAD", "refs"}, "logs/refs": {"heads", "remotes"}, "logs/refs/heads": {"main"},
             "objects/info": set(), "objects/pack": set(), "branches": set(),
             "refs/remotes": {"origin"}, "logs/refs/remotes": {"origin"},
             "refs/remotes/origin": set(), "logs/refs/remotes/origin": set()}

    def visit(fd, path):
        nonlocal total
        before = _sig(os.fstat(fd))
        _need(before[2] == stat.S_IFDIR | 0o700 and before[3:5] == (f.uid, f.gid), "upstream-git-directory")
        names = shared._names(f, fd, 64)
        if path == "objects":
            _need(all(n in ("info", "pack") or re.fullmatch("[0-9a-f]{2}", n) for n in names), "upstream-object-roster")
        elif re.fullmatch(r"objects/[0-9a-f]{2}", path):
            _need(all(re.fullmatch("[0-9a-f]{38}", n) for n in names), "upstream-object-roster")
        else:
            _need(path in fixed and set(names) <= fixed[path], "upstream-git-roster")
        _need(len(rows) < 128, "upstream-fixture-entry-bound")
        rows[path] = ("directory", before, names)
        for name in names:
            relative = name if path == "." else path + "/" + name
            observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(observed.st_mode):
                with f._temporary(f._open(name, fd, directory=True)) as child:
                    f._named(fd, name, child, 0o700)
                    visit(child, relative)
                    f._named(fd, name, child, 0o700)
            else:
                _need(len(rows) < 128, "upstream-fixture-entry-bound")
                shape, hashed, body = shared._read(f, fd, name)
                total += shape[6]
                _need(total <= 512 * 1024, "upstream-fixture-byte-bound")
                rows[relative] = ("file", shape, hashed, body if relative == "config" else None)
        _need(_sig(os.fstat(fd)) == before, "upstream-fixture-read-race")
    visit(git, ".")
    required = {".", "HEAD", "config", "index", "refs", "refs/heads", "refs/heads/main", "refs/tags",
                "logs", "logs/HEAD", "logs/refs", "logs/refs/heads", "logs/refs/heads/main", "objects", "objects/info", "objects/pack"}
    _need(required <= rows.keys(), "upstream-fixture-incomplete")
    return rows


def _capture(f):
    project = f.projects[CASE]
    files = {p: shared._at(f, project, p)[:2] for p in FILES}
    dirs = {}
    for p, names in ((".", (".git", ".gitignore", "app", "keep.txt", "release", "untracked.txt", "version.properties")),
                     ("app", ("build.gradle.kts",)), ("release", ("mobile-release.json",))):
        with ExitStack() as opened:
            fd = project if p == "." else opened.enter_context(f._temporary(f._open(p, project, directory=True)))
            before = _sig(os.fstat(fd))
            _need(shared._names(f, fd, 16) == names and _sig(os.fstat(fd)) == before, "upstream-project-roster")
            dirs[p] = before
    with f._temporary(f._open(".git", project, directory=True)) as git:
        f._named(project, ".git", git, 0o700)
        tree = _git_tree(f, git)
        f._named(project, ".git", git, 0o700)
    return {"files": files, "directories": dirs, "git": tree}


def fixture_config(raw):
    """Closed setup-only contents; preserve Git's actual bytes, never rewrite.

    init can change whitespace and add its macOS filesystem probes. These are
    comparison DATA, not a relaxation of the ordinary Git source/config policy.
    """
    _need(type(raw) is bytes and 0 < len(raw) <= 4096 and raw.endswith(b"\n")
          and all(c in (9, 10) or 32 <= c < 127 for c in raw), "upstream-fixture-config")
    expected = {("core", "repositoryformatversion"): "0", ("core", "filemode"): "true",
                ("core", "bare"): "false", ("core", "logallrefupdates"): "true",
                ("user", "name"): "MRK Upstream Fixture",
                ("user", "email"): "upstream-fixture@example.invalid"}
    optional = {("core", "ignorecase"), ("core", "precomposeunicode")}
    section, sections, seen = None, set(), set()
    for line in raw.decode("ascii").splitlines():
        if line in ("[core]", "[user]"):
            section = line[1:-1]
            _need(section not in sections, "upstream-fixture-config")
            sections.add(section)
            continue
        _need(section is not None and "=" in line, "upstream-fixture-config")
        name, value = (s.strip(" \t") for s in line.split("=", 1))
        key = section, name
        _need(key not in seen and (value == expected[key] if key in expected
              else key in optional and value in ("true", "false")), "upstream-fixture-config")
        seen.add(key)
    _need(sections == {"core", "user"} and expected.keys() <= seen, "upstream-fixture-config")
    return raw


def compare(before, after):
    _need(before["files"] == after["files"] and before["directories"] == after["directories"], "upstream-project-changed")
    old, new = before["git"], after["git"]
    _need(not set(CREATED) & old.keys() and new.keys() == old.keys() | set(CREATED), "upstream-created-roster")
    original = fixture_config(old["config"][3])
    _need(new["config"][3] == original + APPENDED, "upstream-config-content")
    a, b = old["config"][1], new["config"][1]
    _need(a[0] == b[0] and a[1] != b[1] and a[2:6] == b[2:6] and b[5] == 1, "upstream-config-successor")
    for path, original in old.items():
        current = new[path]
        if path == "config":
            continue
        if path in (".", "refs", "logs/refs"):
            expected = tuple(sorted((*original[2], "remotes"))) if path != "." else original[2]
            _need(original[0] == current[0] == "directory" and original[1][:5] == current[1][:5]
                  and current[2] == expected, "upstream-parent-successor")
        else:
            _need(current == original, "upstream-unrelated-original-changed")
    for path in CREATED:
        kind, identity, names = new[path]
        expected = () if path.endswith("/origin") else ("origin",)
        _need(kind == "directory" and identity[2] == stat.S_IFDIR | 0o700 and identity[0] == a[0]
              and identity[3:5] == a[3:5] and names == expected, "upstream-created-directory")
    return True


def before_invocation(f, case, run_owned, username):
    _need(f.cases == CASES and case == CASE and f.upstream_case is None and not f.inflight
          and not f.close_errors, "upstream-fixture-single-attempt")
    f._namespace(); parents_current(f)
    now = time.monotonic()
    _need(type(f.upstream_end) is float and now < f.upstream_end, "upstream-suite-clock")
    f.upstream_case = {"end": min(now + TIMEOUT, f.upstream_end), "calls": 0, "before": None}
    _tool(f)
    _need(f.originals[case] == f._capture(case, False), "upstream-initial-project-changed")
    with f._temporary(f._open("tmp", f.states[case], directory=True)) as tmp:
        with f._temporary(f._mkdir(tmp, "empty-template")) as template:
            template_path = f.path / "state" / case / "tmp/empty-template"
            env = shared._environment(f, case, username, template_path)
            env.update(GIT_AUTHOR_NAME="MRK Upstream Fixture", GIT_COMMITTER_NAME="MRK Upstream Fixture",
                       GIT_AUTHOR_EMAIL="upstream-fixture@example.invalid", GIT_COMMITTER_EMAIL="upstream-fixture@example.invalid")
            with f._temporary(f._mkdir(f.projects[case], ".git")) as git:
                f._write(git, "config", CONFIG)
                version = _call(f, run_owned, env, ["--version", "--build-options"])
                _need(0 < len(version) <= 1024 and version.startswith(b"git version ")
                      and all(c in (9, 10, 13) or 32 <= c < 127 for c in version), "upstream-clt-build-metadata")
                _call(f, run_owned, env, ["init", "--quiet", "--initial-branch=main", "--object-format=sha1", "--template=" + str(template_path)])
                _call(f, run_owned, env, ["add", "--", *FILES[:-1]])
                _call(f, run_owned, env, ["commit", "--quiet", "--no-gpg-sign", "-m", "MRK public Upstream base"])
                base = shared._oid(_call(f, run_owned, env, ["rev-parse", "--verify", "HEAD"]))
                _call(f, run_owned, env, ["commit", "--quiet", "--no-gpg-sign", "--allow-empty", "-m", "MRK public Upstream target"])
                target = shared._oid(_call(f, run_owned, env, ["rev-parse", "--verify", "HEAD"]))
                _need(base != target, "upstream-distinct-target")
                f.upstream_case.update(target=target, version=version.decode("ascii"))
            f._retire_git_template(case, tmp, template)
        f._roster(tmp, (), "upstream-setup-tmp-not-empty")
    f.upstream_case["before"] = _capture(f)
    fixture_config(f.upstream_case["before"]["git"]["config"][3])
    _need(not set(CREATED) & f.upstream_case["before"]["git"].keys(), "upstream-tracking-not-absent")
    remaining(f, case)


def before_call(f, case):
    _need(case == CASE and f.upstream_case is not None and f.upstream_case["before"] is not None
          and not f.upstream_entered and not f.inflight and f.last_returned and not f.close_errors, "upstream-before-app")
    parents_current(f); tool_current(f)
    _need(_capture(f) == f.upstream_case["before"], "upstream-before-app-changed")
    remaining(f, case)
    f.upstream_entered = True


def report(value, case, need):
    fields = {"mechanism", "case", "readOriginalsJoined", "prepareOriginalsJoined", "applyOriginalJoined",
              "unchangedReviewClosed", "normalQuitOriginal", "allOriginalsSettled", "configOnly",
              "newParentDirectories", "trackingAbsent", "worktreePreserved", "networkRequested", "bootstrapOverride", "productionQualified"}
    need(type(value) is dict and value.keys() == fields and case == CASE and value["case"] == case
         and value["mechanism"] == "same-original-git-upstream-v1", "upstream-observer-report")
    for key in ("applyOriginalJoined", "unchangedReviewClosed", "allOriginalsSettled", "configOnly", "trackingAbsent", "worktreePreserved"):
        need(value[key] is True, "upstream-original-not-settled")
    for key in ("networkRequested", "bootstrapOverride", "productionQualified"):
        need(value[key] is False, "upstream-local-scope")
    for key, expected in (("readOriginalsJoined", 2), ("prepareOriginalsJoined", 2), ("normalQuitOriginal", 2), ("newParentDirectories", 4)):
        need(type(value[key]) is int and value[key] == expected, "upstream-original-count")
    return value


def readback(f, case, value, need):
    report(value, case, need)
    need(case == CASE and f.upstream_entered and not f.upstream_completed and not f.inflight
         and f.last_returned and not f.close_errors, "upstream-readback-before-return")
    f._namespace(); parents_current(f); tool_current(f)
    compare(f.upstream_case["before"], _capture(f))
    remaining(f, case)
    f.upstream_completed = True
    return {"mechanism": "same-fixtures-git-upstream-readback-v1", "originalIdentitiesMatched": True,
            "configOnly": True, "trackingAbsent": True, "untrackedPreserved": True,
            "toolSha256": f.upstream_tool[3], "cltBuildMetadata": f.upstream_case["version"],
            "localSetupCalls": f.upstream_case["calls"], "networkRequested": False, "nativeAuthority": False}
