"""Four fixed Fetch observations on the EXISTING installed observer/Fixtures.

This module supplies only nonsecret fixture bytes, finite setup and independent
readback. It never launches on import, creates an invocation owner, supplies a
native receipt, admits a credential, or makes a network request. Every Git/app
call below is the original run_owned supplied by macos_aqua_qualification.
"""
from contextlib import ExitStack
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time

SCOPE = "git-fetch-native"
CASES = ("git-fetch-pack", "git-fetch-corrupt", "git-fetch-limit", "git-fetch-held-helper")
BOOTSTRAPS = ("github_fetch_connection_observation_bootstrap.py", "git_fetch_observation_bootstrap.py")
GIT = "/Library/Developer/CommandLineTools/usr/bin/git"
ACCOUNT = "mrk-fetch-fixture"
APPLICATION = "dev.mobile-release-kit.desktop"
DATA = "mrk-fetch-observation.json"
TIMEOUT, TOTAL_TIMEOUT, CALL_TIMEOUT, CALLS = 120, 600, 5, 160
PACK_LIMIT, FILE_LIMIT, TOOL_LIMIT = 40 * 1024, 64 * 1024, 128 * 1024 * 1024
ZERO = "0" * 40
FILES = ("app/build.gradle.kts", "release/mobile-release.json", "version.properties", "keep.txt", ".gitignore")
ORIGINALS = ("HEAD", "config", "index", "refs/heads/main", "logs/HEAD", "logs/refs/heads/main", DATA)


def _need(condition, reason):
    if not condition:
        raise ValueError(reason)  # Fixed reason only; never Git output/config.


def _hash(body):
    return hashlib.sha256(body).hexdigest()


def _sig(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def fixture_data(config, version, keep, ignore, source):
    return ({FILES[0]: source, FILES[1]: config, FILES[2]: version, FILES[3]: keep, FILES[4]: ignore},
            {".": (0o700, (".gitignore", "app", "keep.txt", "release", "version.properties")),
             "app": (0o700, ("build.gradle.kts",)), "release": (0o700, ("mobile-release.json",))})


def _support(binding, home):
    binding.checked()
    p = Path(home)
    _need(type(home) is str and p.is_absolute() and str(p) == home and p != Path("/")
          and len(p.parts) <= 17 and len(os.fsencode(p)) <= 4096
          and all(s not in (".", "..") and len(os.fsencode(s)) <= 255 for s in p.parts[1:]),
          "fetch-native-home")
    return p / "Library/Application Support"


def application_path(binding, home, case):
    _need(type(case) is str and case in CASES, "fetch-fixture-case")
    return _support(binding, home) / f"mrk-macos-aqua-fetch-{binding.source}-{binding.run}-{binding.attempt}" / case / APPLICATION


def fixture_path(binding, home):
    return _support(binding, home) / f"mrk-macos-aqua-{binding.source}-{binding.run}-{binding.attempt}-{SCOPE}"


def _ancestors(f, path, roster):
    """Only existing protected parents, in the original Fixtures FD book."""
    current, parent = f._open("/", directory=True), None
    for name in ("/", *path.parts[1:]):
        if name != "/":
            parent, current = current, f._open(name, current, directory=True)
        before = _sig(os.fstat(current))
        _need(before == _sig(os.stat(name, dir_fd=parent, follow_symlinks=False))
              and stat.S_ISDIR(before[2]) and before[2] & 0o7022 == 0 and before[3] in (0, f.uid),
              "fetch-protected-ancestor")
        roster.append((parent, name, current, before[:5]))
    return current


def _parents_current(f, roster):
    _need(roster, "fetch-parent-custody")
    for parent, name, fd, old in roster:
        _need(fd in f.fds and (parent is None or parent in f.fds)
              and _sig(os.fstat(fd))[:5] == old == _sig(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5],
              "fetch-parent-changed")


def prepare_namespace(f):
    import pwd
    _need(f.cases == CASES and f.path is None and not f.fetch_ancestors and not f.inflight, "fetch-namespace-order")
    _need(f.fetch_end is None, "fetch-original-suite-clock")
    f.fetch_end = time.monotonic() + TOTAL_TIMEOUT
    u = pwd.getpwuid(f.uid)
    _need(f.uid > 0 and (u.pw_uid, u.pw_gid) == (f.uid, f.gid), "fetch-native-user")
    f.path = fixture_path(f.binding, u.pw_dir)
    f.parent = _ancestors(f, f.path.parent, f.fetch_ancestors)
    f.fetch_paths = {c: application_path(f.binding, u.pw_dir, c) for c in CASES}
    namespace_current(f)


def namespace_current(f):
    _need(f.cases == CASES and f.path is not None and f.parent == f.fetch_ancestors[-1][2], "fetch-parent-original")
    _parents_current(f, f.fetch_ancestors)


def prepare_parents(f):
    _need(f.cases == CASES and not f.inflight and f.fetch_namespace is None, "fetch-app-parent-order")
    namespace_current(f)
    # The admitted application-data parent shares the same native home/support
    # ancestors; no ancestor repair or alternate /tmp/keyring/Host route.
    name = f.fetch_paths[CASES[0]].parents[1].name
    f.fetch_namespace = f._mkdir(f.parent, name)
    for case in CASES:
        f.fetch_parents[case] = f._mkdir(f.fetch_namespace, case)
        f._roster(f.fetch_parents[case], (), "fetch-app-parent-occupied")
    # Only the existing native Host may create its application-data leaf.
    parents_current(f)


def parents_current(f):
    namespace_current(f)
    _need(f.fetch_namespace is not None and set(f.fetch_parents) == set(CASES), "fetch-app-parent-custody")
    f._named(f.parent, f.fetch_paths[CASES[0]].parents[1].name, f.fetch_namespace, 0o700)
    f._roster(f.fetch_namespace, CASES, "fetch-app-namespace")
    for case in CASES:
        f._named(f.fetch_namespace, case, f.fetch_parents[case], 0o700)
        if case not in f.fetch_entered:
            f._roster(f.fetch_parents[case], (), "fetch-unentered-app-parent")


def _read(f, parent, name, maximum=FILE_LIMIT, *, root_owned=False):
    _need(0 < maximum <= TOOL_LIMIT, "fetch-file-bound")
    with f._temporary(f._open(name, parent)) as fd:
        before = _sig(os.fstat(fd))
        _need(before == _sig(os.stat(name, dir_fd=parent, follow_symlinks=False))
              and stat.S_ISREG(before[2]) and before[5] == 1 and before[6] <= maximum
              and before[2] & 0o7022 == 0 and before[3] == (0 if root_owned else f.uid), "fetch-file-original")
        h, chunks, count = hashlib.sha256(), [], 0
        while count < before[6]:
            block = os.read(fd, min(65536, before[6] - count))
            _need(block, "fetch-file-short")
            h.update(block); count += len(block)
            if maximum <= FILE_LIMIT:
                chunks.append(block)
        _need(os.read(fd, 1) == b"" and _sig(os.fstat(fd)) == before
              == _sig(os.stat(name, dir_fd=parent, follow_symlinks=False)), "fetch-file-post")
        return before, h.hexdigest(), b"".join(chunks)


def _at(f, root, relative, maximum=FILE_LIMIT):
    parts = relative.split("/")
    _need(parts and all(p and p not in (".", "..") for p in parts), "fetch-fixed-relative")
    with ExitStack() as held:
        parent = root
        for p in parts[:-1]:
            parent = held.enter_context(f._temporary(f._open(p, parent, directory=True)))
            s = _sig(os.fstat(parent))
            _need(stat.S_ISDIR(s[2]) and s[3:5] == (f.uid, f.gid) and s[2] & 0o7022 == 0, "fetch-fixed-parent")
        return _read(f, parent, parts[-1], maximum)


def _names(f, fd, maximum):
    """One finite scan on a fresh original description, not shared cursor dup."""
    before = _sig(os.fstat(fd))
    with f._temporary(f._open(".", fd, directory=True)) as reader:
        _need(_sig(os.fstat(reader)) == before, "fetch-roster-original")
        iterator, names, error = os.scandir(reader), [], None
        try:
            for item in iterator:
                _need(len(names) < maximum and type(item.name) is str and item.name not in (".", ".."), "fetch-roster-bound")
                names.append(item.name)
            _need(len(set(names)) == len(names) and _sig(os.fstat(reader)) == before == _sig(os.fstat(fd)), "fetch-roster-changed")
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
    """Tiny setup-only inventory; NEVER enumerates/adopts remote operation output."""
    files, dirs, total = {}, {}, 0
    with f._temporary(f._open("objects", git, directory=True)) as objects:
        for name in _names(f, objects, 64):
            _need(name in ("info", "pack") or re.fullmatch("[0-9a-f]{2}", name), "fetch-setup-object-directory")
            with f._temporary(f._open(name, objects, directory=True)) as fanout:
                dirs[name] = _sig(os.fstat(fanout))[:5]
                _need(dirs[name][2] == stat.S_IFDIR | 0o700 and dirs[name][3:5] == (f.uid, f.gid), "fetch-setup-object-owner")
                for leaf in _names(f, fanout, 64):
                    _need(name not in ("info", "pack") and re.fullmatch("[0-9a-f]{38}", leaf)
                          and len(files) < 64, "fetch-setup-object-name")
                    row = _read(f, fanout, leaf)
                    total += row[0][6]
                    _need(total <= 512 * 1024, "fetch-setup-object-bytes")
                    files[name + "/" + leaf] = row[:2]
    return files, dirs


def _tool(f):
    if f.fetch_tool is None:
        roster = []
        parent = _ancestors(f, Path(GIT).parent, roster)
        _need(all(row[3][3] == 0 for row in roster), "fetch-clt-root-owned-ancestors")
        f.fetch_tool_parents = roster
        # Keep this exact original through all four cases/installed readbacks.
        fd = f._open("git", parent)
        before = _sig(os.fstat(fd))
        _need(before[3] == 0 and stat.S_ISREG(before[2]) and before[5] == 1
              and before[2] & 0o7022 == 0 and before[2] & 0o111 and 0 < before[6] <= TOOL_LIMIT,
              "fetch-clt-protected-file")
        observed = _read(f, parent, "git", TOOL_LIMIT, root_owned=True)
        _need(before == observed[0] == _sig(os.fstat(fd)), "fetch-clt-original")
        f.fetch_tool = (parent, fd, before, observed[1])
    tool_current(f)


def tool_current(f):
    _parents_current(f, f.fetch_tool_parents)
    parent, fd, before, digest = f.fetch_tool
    _need(fd in f.fds and _sig(os.fstat(fd)) == before
          == _sig(os.stat("git", dir_fd=parent, follow_symlinks=False)), "fetch-clt-changed")
    current = _read(f, parent, "git", TOOL_LIMIT, root_owned=True)
    _need(current[:2] == (before, digest), "fetch-clt-bytes-changed")


def _environment(f, case, username, template):
    state = f.path / "state" / case
    _need(type(username) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", username), "fetch-native-user")
    return {"HOME": str(state / "home"), "XDG_CONFIG_HOME": str(state / "home"),
            "TMPDIR": str(state / "tmp") + "/", "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
            "USER": username, "LOGNAME": username, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_ATTR_NOSYSTEM": "1", "GIT_TEMPLATE_DIR": str(template),
            "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "none", "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_AUTHOR_NAME": "MRK Fetch Fixture", "GIT_COMMITTER_NAME": "MRK Fetch Fixture",
            "GIT_AUTHOR_EMAIL": "fetch-fixture@example.invalid", "GIT_COMMITTER_EMAIL": "fetch-fixture@example.invalid",
            "GIT_AUTHOR_DATE": "1700000000 +0000", "GIT_COMMITTER_DATE": "1700000000 +0000"}


def remaining(f, case):
    row = f.fetch_cases[case]
    left = min(row["end"], f.fetch_end) - time.monotonic()
    _need(left >= 1 and not f.close_errors, "fetch-fixture-deadline")
    return math.floor(left)  # Never round up, reset, or extend any original.


def _call(f, case, run_owned, environ, args, *, limit=4096):
    row = f.fetch_cases[case]
    _need(not f.inflight and row["calls"] < CALLS and type(args) is list and all(type(a) is str for a in args), "fetch-setup-call-order")
    timeout = min(CALL_TIMEOUT, remaining(f, case))
    tool_current(f)
    argv = [GIT, "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args]
    row["calls"] += 1
    f.case, f.stage, f.inflight, f.last_returned = case, "fetch-local-setup", True, False
    result = run_owned(argv, environ=environ, cwd=f.path / case, timeout=timeout,
                       capture=True, text=False, output_limit=limit)
    _need(type(result) is subprocess.CompletedProcess and type(result.args) is list and result.args == argv
          and type(result.returncode) is int and type(result.stdout) is bytes and type(result.stderr) is bytes
          and len(result.stdout) + len(result.stderr) <= limit, "fetch-setup-owner-return")
    f.inflight, f.last_returned = False, True
    tool_current(f)
    remaining(f, case)
    _need(result.returncode == 0, "fetch-setup-command-failed")
    return result.stdout


def _oid(body):
    _need(type(body) is bytes and re.fullmatch(b"[0-9a-f]{40}\n", body) and body != (ZERO + "\n").encode(), "fetch-setup-oid")
    return body[:-1].decode("ascii")


def _transcript(case, base, target, pack):
    _need(type(case) is str and case in CASES and type(base) is str and type(target) is str
          and base != target and base != ZERO and target != ZERO and re.fullmatch("[0-9a-f]{40}", base)
          and re.fullmatch("[0-9a-f]{40}", target) and type(pack) is bytes and 32 <= len(pack) <= PACK_LIMIT
          and pack[:8] == b"PACK\x00\x00\x00\x02" and 1 <= int.from_bytes(pack[8:12], "big") <= 24
          and hashlib.sha1(pack[:-20], usedforsecurity=False).digest() == pack[-20:], "fetch-real-pack-data")
    return json.dumps({"schemaVersion": 1, "case": case, "base": base, "target": target,
                       "pack": base64.b64encode(pack).decode("ascii")}, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def _remove_target(f, git, before, after, target):
    name = target[:2] + "/" + target[2:]
    _need(set(after[0]) == set(before[0]) | {name} and name not in before[0]
          and all(after[0][n] == row for n, row in before[0].items())
          and set(after[1]) == set(before[1]) | {target[:2]}
          and all(after[1][n] == row for n, row in before[1].items()), "fetch-target-only-setup-object")
    with f._temporary(f._open("objects", git, directory=True)) as objects:
        with f._temporary(f._open(target[:2], objects, directory=True)) as fanout:
            with f._temporary(f._open(target[2:], fanout)) as fd:
                old = after[0][name]
                _need(_sig(os.fstat(fd)) == old[0] and _read(f, fanout, target[2:])[:2] == old, "fetch-target-original")
                os.unlink(target[2:], dir_fd=fanout)  # Sole exact created object, never broad cleanup.
                os.fsync(fanout)
                now = _sig(os.fstat(fd))
                _need(now[:5] == old[0][:5] and now[5] == 0 and now[6:8] == old[0][6:8], "fetch-target-unlink-post")
                try:
                    os.stat(target[2:], dir_fd=fanout, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError("fetch-target-unlink-absent")
        # An empty, ordinary fanout may remain; it is part of the PRE-app
        # captured original inventory. No reconstruction/cleanup authorization.
    final = _objects(f, git)
    _need(final[0] == before[0] and final[1] == after[1], "fetch-target-removal-readback")


def _capture(f, case):
    root, rows = f.projects[case], {}
    with f._temporary(f._open(".git", root, directory=True)) as git:
        for name in ORIGINALS:
            rows[".git/" + name] = _at(f, git, name)[:2]
        rows["tracking"] = _at(f, git, "refs/remotes/origin/main")[:2]
        rows["trackingLog"] = _at(f, git, "logs/refs/remotes/origin/main")[:2]
        rows["trackingBody"] = _at(f, git, "refs/remotes/origin/main")[2]
        rows["trackingLogBody"] = _at(f, git, "logs/refs/remotes/origin/main")[2]
        with f._temporary(f._open("objects", git, directory=True)) as objects:
            with f._temporary(f._open("pack", objects, directory=True)) as pack:
                rows["packParent"] = _sig(os.fstat(pack))[:5]
                rows["packs"] = {n: _read(f, pack, n) for n in _names(f, pack, 3)}
    for name in FILES:
        rows[name] = _at(f, root, name)[:2]
    rows["root"] = _sig(os.fstat(root))[:6]
    return rows


def before_invocation(f, case, run_owned, username):
    """Fixed local setup ONLY; no stock Git remote/auth/server command."""
    _need(f.cases == CASES and case in CASES and case not in f.fetch_cases
          and not f.inflight and not f.close_errors, "fetch-fixture-single-attempt")
    f._namespace(); parents_current(f)
    now = time.monotonic()
    _need(type(f.fetch_end) is float and now < f.fetch_end, "fetch-original-suite-clock")
    f.fetch_cases[case] = {"end": min(now + TIMEOUT, f.fetch_end), "calls": 0, "before": None, "pack": None, "base": None, "target": None}
    _tool(f)
    # Exact initial public files/dirs, captured by existing Fixtures before .git.
    _need(f.originals[case] == f._capture(case, False), "fetch-initial-project-changed")
    with f._temporary(f._open("tmp", f.states[case], directory=True)) as tmp:
        with f._temporary(f._mkdir(tmp, "empty-template")) as template:
            env = _environment(f, case, username, f.path / "state" / case / "tmp/empty-template")
            with f._temporary(f._mkdir(f.projects[case], ".git")) as git:
                # Fresh synthetic config only. No original supplied config is
                # overwritten, inferred, migrated, or used for a credential.
                config = ("[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false\nlogallrefupdates = true\n"
                          "[user]\nname = MRK Fetch Fixture\nemail = fetch-fixture@example.invalid\n"
                          f'[remote "origin"]\nurl = https://github.com/{ACCOUNT}/{case}.git\nfetch = +refs/heads/*:refs/remotes/origin/*\n'
                          '[branch "main"]\nremote = origin\nmerge = refs/heads/main\n').encode("ascii")
                f._write(git, "config", config)
                version = _call(f, case, run_owned, env, ["--version", "--build-options"])
                _need(0 < len(version) <= 1024 and version.startswith(b"git version ")
                      and all(c in (9, 10, 13) or 32 <= c < 127 for c in version), "fetch-clt-build-metadata")
                _call(f, case, run_owned, env, ["init", "--quiet", "--initial-branch=main", "--object-format=sha1", "--template=" + str(f.path / "state" / case / "tmp/empty-template")])
                _call(f, case, run_owned, env, ["add", "--", *FILES])
                _call(f, case, run_owned, env, ["commit", "--quiet", "--no-gpg-sign", "-m", "MRK public Fetch base"])
                base = _oid(_call(f, case, run_owned, env, ["rev-parse", "--verify", "HEAD"]))
                before = _objects(f, git)
                _call(f, case, run_owned, env, ["commit", "--quiet", "--no-gpg-sign", "--allow-empty", "-m", "MRK public Fetch target"])
                target = _oid(_call(f, case, run_owned, env, ["rev-parse", "--verify", "HEAD"]))
                _need(base != target, "fetch-distinct-target")
                pack = _call(f, case, run_owned, env, ["pack-objects", "--stdout", "--all", "--no-reuse-delta", "--no-reuse-object"], limit=FILE_LIMIT)
                data = _transcript(case, base, target, pack)
                _call(f, case, run_owned, env, ["update-ref", "--no-deref", "refs/heads/main", base, target])
                _call(f, case, run_owned, env, ["update-ref", "--no-deref", "refs/remotes/origin/main", base, ZERO])
                _remove_target(f, git, before, _objects(f, git), target)
                f._write(git, DATA, data)
                f.fetch_cases[case].update(pack=pack, base=base, target=target, version=version.decode("ascii"))
            f._roster(template, (), "fetch-template-used")
            held = _sig(os.fstat(template))
            _need(held[:5] == _sig(os.stat("empty-template", dir_fd=tmp, follow_symlinks=False))[:5], "fetch-template-original")
            os.rmdir("empty-template", dir_fd=tmp)
            os.fsync(tmp)
            _need(os.fstat(template).st_nlink == 0, "fetch-template-unlink")
        f._roster(tmp, (), "fetch-setup-tmp-not-empty")
    f.fetch_cases[case]["before"] = _capture(f, case)
    _need(f.fetch_cases[case]["before"]["packs"] == {}, "fetch-original-pack-not-empty")
    remaining(f, case)


def before_call(f, case):
    _need(case in f.fetch_cases and f.fetch_cases[case]["before"] is not None and case not in f.fetch_entered
          and not f.inflight and f.last_returned and not f.close_errors, "fetch-before-app")
    parents_current(f); tool_current(f)
    _need(_capture(f, case) == f.fetch_cases[case]["before"], "fetch-before-app-originals")
    remaining(f, case)
    f.fetch_entered.add(case)  # A lost app return cannot restart this case.


def report(value, case, need):
    fields = {"mechanism", "case", "syntheticProviderBytes", "connectionOriginalJoined", "readOriginalJoined",
              "prepareOriginalJoined", "applyOriginalJoined", "connectionRetired", "publication",
              "helperReturnedBeforeAllCopyEof", "producerPendingBeforeStop", "sameTicketStop", "toolSha256",
              "normalQuitOriginal", "allOriginalsSettled", "worktreePreserved", "shippingNominationEnabled",
              "tlsQualified", "liveAccountQualified", "productionQualified"}
    need(type(value) is dict and value.keys() == fields and type(case) is str and case in CASES
         and value["case"] == case and value["mechanism"] == "same-original-git-fetch-v1", "fetch-observer-report")
    for key in ("syntheticProviderBytes", "connectionOriginalJoined", "readOriginalJoined", "prepareOriginalJoined",
                "applyOriginalJoined", "connectionRetired", "allOriginalsSettled", "worktreePreserved"):
        need(value[key] is True, "fetch-originals-not-settled")
    for key in ("shippingNominationEnabled", "tlsQualified", "liveAccountQualified", "productionQualified"):
        need(value[key] is False, "fetch-nonshipping-scope")
    need(value["publication"] is (case == CASES[0])
         and type(value["normalQuitOriginal"]) is int and value["normalQuitOriginal"] == 2
         and type(value["toolSha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["toolSha256"]), "fetch-original-report-fields")
    for key in ("helperReturnedBeforeAllCopyEof", "producerPendingBeforeStop", "sameTicketStop"):
        need(value[key] is (case == CASES[3]), "fetch-helper-stop-window")
    return value  # Actual DATA only, no filled-in missing facts.


def readback(f, case, value, need):
    report(value, case, need)
    need(case in f.fetch_entered and case not in f.fetch_completed and not f.inflight
         and f.last_returned and not f.close_errors, "fetch-readback-before-original-return")
    f._namespace(); parents_current(f); tool_current(f)
    row = f.fetch_cases[case]
    current, before = _capture(f, case), row["before"]
    need(value["toolSha256"] == f.fetch_tool[3], "fetch-native-clt-correspondence")
    for key in (*FILES, *(".git/" + p for p in ORIGINALS), "root", "packParent"):
        need(current[key] == before[key], "fetch-original-readback-changed")
    if case == CASES[0]:
        pack_id = row["pack"][-20:].hex()
        p, i = "pack-" + pack_id + ".pack", "pack-" + pack_id + ".idx"
        need(set(current["packs"]) == {p, i} and current["packs"][p][2] == row["pack"]
             and all(r[0][5] == 1 for r in current["packs"].values())
             and current["trackingBody"] == (row["target"] + "\n").encode("ascii")
             and current["tracking"] != before["tracking"], "fetch-positive-pack-cas-readback")
        log, prefix = current["trackingLogBody"], before["trackingLogBody"]
        suffix = log[len(prefix):]
        need(log.startswith(prefix) and suffix.count(b"\n") == 1 and suffix.startswith((row["base"] + " " + row["target"] + " ").encode("ascii")),
             "fetch-stock-ref-log-readback")
    else:
        need(not current["packs"] and all(current[k] == before[k] for k in ("tracking", "trackingBody", "trackingLog", "trackingLogBody")),
             "fetch-refused-no-original-publication")
    remaining(f, case)
    f.fetch_completed.add(case)
    return {"mechanism": "same-fixtures-git-fetch-readback-v1", "originalIdentitiesMatched": True,
            "headIndexWorktreeUnchanged": True, "publication": case == CASES[0], "toolSha256": f.fetch_tool[3],
            "cltBuildMetadata": row["version"], "realPackBytes": len(row["pack"]), "localSetupCalls": row["calls"],
            "syntheticProviderBytes": True, "shippingNominationEnabled": False, "nativeAuthority": False}
