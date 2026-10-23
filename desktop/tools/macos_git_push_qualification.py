"""Three fixed Push observations on the EXISTING installed observer/Fixtures.

This module supplies only nonsecret fixture bytes, finite setup and independent
readback. It never launches on import, creates an invocation owner, supplies a
native receipt, admits a credential, or makes a network request. Every Git/app
call below is the original run_owned supplied by macos_aqua_qualification.
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

_create_spec = spec_from_file_location("mrk_macos_git_push_create_qualification", Path(__file__).with_name("macos_git_push_create_qualification.py"))
if _create_spec is None or _create_spec.loader is None:
    raise RuntimeError("push-create-observation-module-unavailable")
CREATE = module_from_spec(_create_spec)
_create_spec.loader.exec_module(CREATE)
del _create_spec

SCOPE = "git-push-native"
CASES = ("git-push-pack", "git-push-stale", "git-push-held-refusal")
ALL_CASES = CASES + CREATE.CASES
SCOPES = (SCOPE, CREATE.SCOPE)

def case_family(cases):
    _need(type(cases) is tuple and cases in (CASES, CREATE.CASES), "push-fixed-case-family")
    return cases


BOOTSTRAPS = ("github_push_connection_observation_bootstrap.py", "git_push_observation_bootstrap.py")
GIT = "/Library/Developer/CommandLineTools/usr/bin/git"
ACCOUNT = "mrk-push-fixture"
APPLICATION = "dev.mobile-release-kit.desktop"
DATA = "mrk-push-observation.json"
TIMEOUT, TOTAL_TIMEOUT, CALL_TIMEOUT, CALLS = 120, 600, 5, 160
DATA_LIMIT, FILE_LIMIT, TOOL_LIMIT = 4096, 64 * 1024, 128 * 1024 * 1024
ZERO = "0" * 40
UNTRACKED = b"MRK public untracked Push fixture: never staged or sent.\n"
FILES = ("app/build.gradle.kts", "release/mobile-release.json", "version.properties", "keep.txt", ".gitignore", "untracked.txt")
ORIGINALS = ("HEAD", "config", "index", "refs/heads/main", "logs/HEAD", "logs/refs/heads/main",
             "refs/remotes/origin/main", "logs/refs/remotes/origin/main", DATA)


def _need(condition, reason):
    if not condition:
        raise ValueError(reason)  # Fixed reason only; never Git output/config.


def _hash(body):
    return hashlib.sha256(body).hexdigest()


def _sig(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def fixture_data(config, version, keep, ignore, source):
    return ({FILES[0]: source, FILES[1]: config, FILES[2]: version, FILES[3]: keep, FILES[4]: ignore, FILES[5]: UNTRACKED},
            {".": (0o700, (".gitignore", "app", "keep.txt", "release", "untracked.txt", "version.properties")),
             "app": (0o700, ("build.gradle.kts",)), "release": (0o700, ("mobile-release.json",))})


def _support(binding, home):
    binding.checked()
    p = Path(home)
    _need(type(home) is str and p.is_absolute() and str(p) == home and p != Path("/")
          and len(p.parts) <= 17 and len(os.fsencode(p)) <= 4096
          and all(s not in (".", "..") and len(os.fsencode(s)) <= 255 for s in p.parts[1:]),
          "push-native-home")
    return p / "Library/Application Support"


def application_path(binding, home, case):
    _need(type(case) is str and case in ALL_CASES, "push-fixture-case")
    tag = "push-create" if case in CREATE.CASES else "push"
    return _support(binding, home) / f"mrk-macos-aqua-{tag}-{binding.source}-{binding.run}-{binding.attempt}" / case / APPLICATION


def fixture_path(binding, home, *, cases=CASES):
    scope = CREATE.SCOPE if case_family(cases) == CREATE.CASES else SCOPE
    return _support(binding, home) / f"mrk-macos-aqua-{binding.source}-{binding.run}-{binding.attempt}-{scope}"


def _ancestors(f, path, roster):
    """Only existing protected parents, in the original Fixtures FD book."""
    current, parent = f._open("/", directory=True), None
    for name in ("/", *path.parts[1:]):
        if name != "/":
            parent, current = current, f._open(name, current, directory=True)
        before = _sig(os.fstat(current))
        _need(before == _sig(os.stat(name, dir_fd=parent, follow_symlinks=False))
              and stat.S_ISDIR(before[2]) and before[2] & 0o7022 == 0 and before[3] in (0, f.uid),
              "push-protected-ancestor")
        roster.append((parent, name, current, before[:5]))
    return current


def _parents_current(f, roster):
    _need(roster, "push-parent-custody")
    for parent, name, fd, old in roster:
        _need(fd in f.fds and (parent is None or parent in f.fds)
              and _sig(os.fstat(fd))[:5] == old == _sig(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5],
              "push-parent-changed")


def prepare_namespace(f):
    import pwd
    _need(f.cases == case_family(f.cases) and f.path is None and not f.push_ancestors and not f.inflight, "push-namespace-order")
    _need(f.push_end is None, "push-original-suite-clock")
    f.push_end = time.monotonic() + TOTAL_TIMEOUT
    u = pwd.getpwuid(f.uid)
    _need(f.uid > 0 and (u.pw_uid, u.pw_gid) == (f.uid, f.gid), "push-native-user")
    f.path = fixture_path(f.binding, u.pw_dir, cases=f.cases)
    f.parent = _ancestors(f, f.path.parent, f.push_ancestors)
    f.push_paths = {c: application_path(f.binding, u.pw_dir, c) for c in f.cases}
    namespace_current(f)


def namespace_current(f):
    _need(f.cases == case_family(f.cases) and f.path is not None and f.parent == f.push_ancestors[-1][2], "push-parent-original")
    _parents_current(f, f.push_ancestors)


def prepare_parents(f):
    _need(f.cases == case_family(f.cases) and not f.inflight and f.push_namespace is None, "push-app-parent-order")
    namespace_current(f)
    # The admitted application-data parent shares the same native home/support
    # ancestors; no ancestor repair or alternate /tmp/keyring/Host route.
    name = f.push_paths[f.cases[0]].parents[1].name
    f.push_namespace = f._mkdir(f.parent, name)
    for case in f.cases:
        f.push_parents[case] = f._mkdir(f.push_namespace, case)
        f._roster(f.push_parents[case], (), "push-app-parent-occupied")
    # Only the existing native Host may create its application-data leaf.
    parents_current(f)


def parents_current(f):
    namespace_current(f)
    _need(f.push_namespace is not None and set(f.push_parents) == set(f.cases), "push-app-parent-custody")
    f._named(f.parent, f.push_paths[f.cases[0]].parents[1].name, f.push_namespace, 0o700)
    f._roster(f.push_namespace, f.cases, "push-app-namespace")
    for case in f.cases:
        f._named(f.push_namespace, case, f.push_parents[case], 0o700)
        if case not in f.push_entered:
            f._roster(f.push_parents[case], (), "push-unentered-app-parent")


def _read(f, parent, name, maximum=FILE_LIMIT, *, root_owned=False):
    _need(0 < maximum <= TOOL_LIMIT, "push-file-bound")
    with f._temporary(f._open(name, parent)) as fd:
        before = _sig(os.fstat(fd))
        _need(before == _sig(os.stat(name, dir_fd=parent, follow_symlinks=False))
              and stat.S_ISREG(before[2]) and before[5] == 1 and before[6] <= maximum
              and before[2] & 0o7022 == 0 and before[3] == (0 if root_owned else f.uid), "push-file-original")
        h, chunks, count = hashlib.sha256(), [], 0
        while count < before[6]:
            block = os.read(fd, min(65536, before[6] - count))
            _need(block, "push-file-short")
            h.update(block); count += len(block)
            if maximum <= FILE_LIMIT:
                chunks.append(block)
        _need(os.read(fd, 1) == b"" and _sig(os.fstat(fd)) == before
              == _sig(os.stat(name, dir_fd=parent, follow_symlinks=False)), "push-file-post")
        return before, h.hexdigest(), b"".join(chunks)


def _at(f, root, relative, maximum=FILE_LIMIT):
    parts = relative.split("/")
    _need(parts and all(p and p not in (".", "..") for p in parts), "push-fixed-relative")
    with ExitStack() as held:
        parent = root
        for p in parts[:-1]:
            parent = held.enter_context(f._temporary(f._open(p, parent, directory=True)))
            s = _sig(os.fstat(parent))
            _need(stat.S_ISDIR(s[2]) and s[3:5] == (f.uid, f.gid) and s[2] & 0o7022 == 0, "push-fixed-parent")
        return _read(f, parent, parts[-1], maximum)


def _names(f, fd, maximum):
    """One finite scan on a fresh original description, not shared cursor dup."""
    before = _sig(os.fstat(fd))
    with f._temporary(f._open(".", fd, directory=True)) as reader:
        _need(_sig(os.fstat(reader)) == before, "push-roster-original")
        iterator, names, error = os.scandir(reader), [], None
        try:
            for item in iterator:
                _need(len(names) < maximum and type(item.name) is str and item.name not in (".", ".."), "push-roster-bound")
                names.append(item.name)
            _need(len(set(names)) == len(names) and _sig(os.fstat(reader)) == before == _sig(os.fstat(fd)), "push-roster-changed")
            return tuple(sorted(names))
        except BaseException as caught:
            error = caught
            raise
        finally:
            try:
                iterator.close()
            except BaseException as caught:
                f.close_errors += 1
                if f.first_close_error is None:
                    f.first_close_error = caught
                if error is None:
                    raise


def _objects(f, git):
    """Bounded original loose-object comparison. Extra output never becomes owned."""
    files, dirs, total = {}, {}, 0
    with f._temporary(f._open("objects", git, directory=True)) as objects:
        for name in _names(f, objects, 64):
            _need(name in ("info", "pack") or re.fullmatch("[0-9a-f]{2}", name), "push-setup-object-directory")
            with f._temporary(f._open(name, objects, directory=True)) as fanout:
                dirs[name] = _sig(os.fstat(fanout))[:5]
                _need(dirs[name][2] == stat.S_IFDIR | 0o700 and dirs[name][3:5] == (f.uid, f.gid), "push-setup-object-owner")
                for leaf in _names(f, fanout, 64):
                    _need(name not in ("info", "pack") and re.fullmatch("[0-9a-f]{38}", leaf)
                          and len(files) < 64, "push-setup-object-name")
                    row = _read(f, fanout, leaf)
                    total += row[0][6]
                    _need(total <= 512 * 1024, "push-setup-object-bytes")
                    files[name + "/" + leaf] = row[:2]
    return files, dirs


def _tool(f):
    if f.push_tool is None:
        roster = []
        parent = _ancestors(f, Path(GIT).parent, roster)
        _need(all(row[3][3] == 0 for row in roster), "push-clt-root-owned-ancestors")
        f.push_tool_parents = roster
        # Keep this exact original through all three cases/installed readbacks.
        fd = f._open("git", parent)
        before = _sig(os.fstat(fd))
        _need(before[3] == 0 and stat.S_ISREG(before[2]) and before[5] == 1
              and before[2] & 0o7022 == 0 and before[2] & 0o111 and 0 < before[6] <= TOOL_LIMIT,
              "push-clt-protected-file")
        observed = _read(f, parent, "git", TOOL_LIMIT, root_owned=True)
        _need(before == observed[0] == _sig(os.fstat(fd)), "push-clt-original")
        f.push_tool = (parent, fd, before, observed[1])
    tool_current(f)


def tool_current(f):
    _parents_current(f, f.push_tool_parents)
    parent, fd, before, digest = f.push_tool
    _need(fd in f.fds and _sig(os.fstat(fd)) == before
          == _sig(os.stat("git", dir_fd=parent, follow_symlinks=False)), "push-clt-changed")
    current = _read(f, parent, "git", TOOL_LIMIT, root_owned=True)
    _need(current[:2] == (before, digest), "push-clt-bytes-changed")


def _environment(f, case, username, template):
    state = f.path / "state" / case
    _need(type(username) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", username), "push-native-user")
    return {"HOME": str(state / "home"), "XDG_CONFIG_HOME": str(state / "home"),
            "TMPDIR": str(state / "tmp") + "/", "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
            "USER": username, "LOGNAME": username, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_ATTR_NOSYSTEM": "1", "GIT_TEMPLATE_DIR": str(template),
            "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "none", "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_AUTHOR_NAME": "MRK Push Fixture", "GIT_COMMITTER_NAME": "MRK Push Fixture",
            "GIT_AUTHOR_EMAIL": "push-fixture@example.invalid", "GIT_COMMITTER_EMAIL": "push-fixture@example.invalid",
            "GIT_AUTHOR_DATE": "1700000000 +0000", "GIT_COMMITTER_DATE": "1700000000 +0000"}


def remaining(f, case):
    row = f.push_cases[case]
    left = min(row["end"], f.push_end) - time.monotonic()
    _need(left >= 1 and not f.close_errors, "push-fixture-deadline")
    return math.floor(left)  # Never round up, reset, or extend any original.


def _call(f, case, run_owned, environ, args, *, limit=4096):
    row = f.push_cases[case]
    _need(not f.inflight and row["calls"] < CALLS and type(args) is list and all(type(a) is str for a in args), "push-setup-call-order")
    timeout = min(CALL_TIMEOUT, remaining(f, case))
    tool_current(f)
    argv = [GIT, "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args]
    row["calls"] += 1
    f.case, f.stage, f.inflight, f.last_returned = case, "push-local-setup", True, False
    result = run_owned(argv, environ=environ, cwd=f.path / case, timeout=timeout,
                       capture=True, text=False, output_limit=limit)
    _need(type(result) is subprocess.CompletedProcess and type(result.args) is list and result.args == argv
          and type(result.returncode) is int and type(result.stdout) is bytes and type(result.stderr) is bytes
          and len(result.stdout) + len(result.stderr) <= limit, "push-setup-owner-return")
    f.inflight, f.last_returned = False, True
    tool_current(f)
    remaining(f, case)
    _need(result.returncode == 0, "push-setup-command-failed")
    return result.stdout


def _oid(body):
    _need(type(body) is bytes and re.fullmatch(b"[0-9a-f]{40}\n", body) and body != (ZERO + "\n").encode(), "push-setup-oid")
    return body[:-1].decode("ascii")


def _transcript(case, base, target, other):
    _need(case in ALL_CASES and len({base, target, other}) == 3
          and all(type(v) is str and re.fullmatch("[0-9a-f]{40}", v) and v != ZERO for v in (base, target, other)),
          "push-distinct-original-commits")
    raw = json.dumps({"schemaVersion": 1, "case": case, "base": base, "target": target,
                      "other": other}, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    _need(len(raw) <= DATA_LIMIT, "push-data-bound")
    return raw


def _capture(f, case):
    root, rows = f.projects[case], {}
    with f._temporary(f._open(".git", root, directory=True)) as git:
        for name in CREATE.ORIGINALS if case in CREATE.CASES else ORIGINALS:
            rows[".git/" + name] = _at(f, git, name)[:2]
        rows["objects"] = _objects(f, git)
        if case in CREATE.CASES:
            rows["absent-tracking"] = CREATE.absence(f, git, _sig, _names, _need)
    for name in FILES:
        rows[name] = _at(f, root, name)[:2]
    rows["root"] = _sig(os.fstat(root))[:6]
    return rows


def _configuration(case):
    if case in CREATE.CASES:
        return CREATE.configuration(case, _need)
    _need(type(case) is str and case in ALL_CASES, "push-fixture-case")
    return ("[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false\nlogallrefupdates = true\n"
            "[user]\nname = MRK Push Fixture\nemail = push-fixture@example.invalid\n"
            f'[remote "origin"]\nurl = https://github.com/{ACCOUNT}/{case}.git\nfetch = +refs/heads/*:refs/remotes/origin/*\n'
            '[branch "main"]\nremote = origin\nmerge = refs/heads/main\n').encode("ascii")


def before_invocation(f, case, run_owned, username):
    """Fixed local setup ONLY; no stock Git remote/auth/server command."""
    _need(f.cases == case_family(f.cases) and case in f.cases and case not in f.push_cases
          and not f.inflight and not f.close_errors, "push-fixture-single-attempt")
    f._namespace(); parents_current(f)
    now = time.monotonic()
    _need(type(f.push_end) is float and now < f.push_end, "push-original-suite-clock")
    f.push_cases[case] = {"end": min(now + TIMEOUT, f.push_end), "calls": 0, "before": None, "base": None, "target": None, "other": None}
    _tool(f)
    # Exact initial public files/dirs, captured by existing Fixtures before .git.
    _need(f.originals[case] == f._capture(case, False), "push-initial-project-changed")
    with f._temporary(f._open("tmp", f.states[case], directory=True)) as tmp:
        with f._temporary(f._mkdir(tmp, "empty-template")) as template:
            env = _environment(f, case, username, f.path / "state" / case / "tmp/empty-template")
            with f._temporary(f._mkdir(f.projects[case], ".git")) as git:
                # Fresh synthetic config only. No original supplied config is
                # overwritten, inferred, migrated, or used for a credential.
                config = _configuration(case)
                f._write(git, "config", config)
                version = _call(f, case, run_owned, env, ["--version", "--build-options"])
                _need(0 < len(version) <= 1024 and version.startswith(b"git version ")
                      and all(c in (9, 10, 13) or 32 <= c < 127 for c in version), "push-clt-build-metadata")
                _call(f, case, run_owned, env, ["init", "--quiet", "--initial-branch=main", "--object-format=sha1", "--template=" + str(f.path / "state" / case / "tmp/empty-template")])
                _call(f, case, run_owned, env, ["add", "--", *FILES[:-1]])
                _call(f, case, run_owned, env, ["commit", "--quiet", "--no-gpg-sign", "-m", "MRK public Push base"])
                base = _oid(_call(f, case, run_owned, env, ["rev-parse", "--verify", "HEAD"]))
                _call(f, case, run_owned, env, ["commit", "--quiet", "--no-gpg-sign", "--allow-empty", "-m", "MRK public Push target"])
                target = _oid(_call(f, case, run_owned, env, ["rev-parse", "--verify", "HEAD"]))
                _need(base != target, "push-distinct-target")
                # A second real commit with the same base/tree is only the
                # stale advertised OLD in B. It never moves any local reference.
                other = _oid(_call(f, case, run_owned, env,
                    ["commit-tree", "HEAD^{tree}", "-p", base, "-m", "MRK public distinct Push peer"]))
                data = _transcript(case, base, target, other)
                if case not in CREATE.CASES:
                    _call(f, case, run_owned, env, ["update-ref", "--no-deref", "refs/remotes/origin/main", base, ZERO])
                # HEAD stays at the one outgoing target. No reset, checkout,
                # fetch, remote process, object removal or separate pack spool.
                f._write(git, DATA, data)
                f.push_cases[case].update(base=base, target=target, other=other, version=version.decode("ascii"))
            f._roster(template, (), "push-template-used")
            held = _sig(os.fstat(template))
            _need(held[:5] == _sig(os.stat("empty-template", dir_fd=tmp, follow_symlinks=False))[:5], "push-template-original")
            os.rmdir("empty-template", dir_fd=tmp)
            os.fsync(tmp)
            _need(os.fstat(template).st_nlink == 0, "push-template-unlink")
        f._roster(tmp, (), "push-setup-tmp-not-empty")
    f.push_cases[case]["before"] = _capture(f, case)
    remaining(f, case)


def before_call(f, case):
    _need(case in f.push_cases and f.push_cases[case]["before"] is not None and case not in f.push_entered
          and not f.inflight and f.last_returned and not f.close_errors, "push-before-app")
    parents_current(f); tool_current(f)
    _need(_capture(f, case) == f.push_cases[case]["before"], "push-before-app-originals")
    remaining(f, case)
    f.push_entered.add(case)  # A lost app return cannot restart this case.


def report(value, case, need):
    if case in CREATE.CASES:
        return CREATE.report(value, case, need)
    fields = {"mechanism", "case", "syntheticProviderBytes", "connectionOriginalJoined", "readOriginalJoined",
              "prepareOriginalJoined", "applyOriginalJoined", "connectionRetired", "remoteReturned",
              "helperRefusedBeforeAllCopyEof", "producerPendingBeforeStop", "sameTicketStop", "toolSha256",
              "normalQuitOriginal", "allOriginalsSettled", "worktreePreserved", "shippingNominationEnabled",
              "tlsQualified", "liveAccountQualified", "productionQualified"}
    need(type(value) is dict and value.keys() == fields and type(case) is str and case in ALL_CASES
         and value["case"] == case and value["mechanism"] == "same-original-git-push-v1", "push-observer-report")
    for key in ("syntheticProviderBytes", "connectionOriginalJoined", "readOriginalJoined", "prepareOriginalJoined",
                "applyOriginalJoined", "connectionRetired", "allOriginalsSettled", "worktreePreserved"):
        need(value[key] is True, "push-originals-not-settled")
    for key in ("shippingNominationEnabled", "tlsQualified", "liveAccountQualified", "productionQualified"):
        need(value[key] is False, "push-nonshipping-scope")
    need(value["remoteReturned"] is (case == CASES[0])
         and type(value["normalQuitOriginal"]) is int and value["normalQuitOriginal"] == 2
         and type(value["toolSha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["toolSha256"]), "push-original-report-fields")
    for key in ("helperRefusedBeforeAllCopyEof", "producerPendingBeforeStop", "sameTicketStop"):
        need(value[key] is (case == CASES[2]), "push-helper-stop-window")
    return value  # Actual DATA only, no filled-in missing facts.


def readback(f, case, value, need):
    report(value, case, need)
    need(case in f.push_entered and case not in f.push_completed and not f.inflight
         and f.last_returned and not f.close_errors, "push-readback-before-original-return")
    f._namespace(); parents_current(f); tool_current(f)
    row = f.push_cases[case]
    current, before = _capture(f, case), row["before"]
    need(value["toolSha256"] == f.push_tool[3], "push-native-clt-correspondence")
    # No local publication belongs to Push, including when its synthetic
    # peer accepted the body. Tracking refs/logs remain the last fetched DATA.
    need(current == before, "push-original-readback-changed")
    remaining(f, case)
    f.push_completed.add(case)
    return {"mechanism": "same-fixtures-git-push-readback-v1", "originalIdentitiesMatched": True,
            "headIndexWorktreeUnchanged": True, "remoteReturned": case in (CASES[0], CREATE.CASES[0]), "toolSha256": f.push_tool[3],
            "cltBuildMetadata": row["version"], "localTrackingUnchanged": True, **({"upstreamAbsent": True, "localTrackingAbsent": True} if case in CREATE.CASES else {}), "untrackedPreserved": True, "localSetupCalls": row["calls"],
            "syntheticProviderBytes": True, "shippingNominationEnabled": False, "nativeAuthority": False}
