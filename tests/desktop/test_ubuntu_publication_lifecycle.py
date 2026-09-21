"""Inert lifecycle policy tests; never start a service, child or package tool."""
from copy import deepcopy
import ast
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "publication_lifecycle_data", SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py")
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)

NEEDRESTART_CONFIG_DATA = (
    b"# needrestart - Restart daemons after library updates.\n#\n"
    b"# Scan for (successfully) installed packages,\n"
    b"# triggers needrestart in apt's Dpkg::Post-Invoke\n# hook.\n\n"
    b"status-logger=(test -x /usr/lib/needrestart/dpkg-status && /usr/lib/needrestart/dpkg-status || cat > /dev/null)\n"
)


def needrestart_stat(mode, *, ino=10, uid=0, nlink=1, rdev=0, size=0):
    return SimpleNamespace(st_dev=1, st_ino=ino, st_mode=mode, st_uid=uid, st_gid=0,
                           st_nlink=nlink, st_rdev=rdev, st_size=size, st_mtime_ns=0, st_ctime_ns=0)


def needrestart_data(*names, present=True, stamp=0):
    return {"runIdentity": [1, 1, stat.S_IFDIR | 0o755, 0, 0],
            "directory": [1, 2, stat.S_IFDIR | 0o755, 0, 0, 2, 4096, stamp, stamp] if present else None,
            "markers": {name: {"path": "/run/needrestart/" + name, "size": 0, "sha256": hashlib.sha256(b"").hexdigest(),
                              "identity": [1, 3 + (name == "errored"), stat.S_IFREG | 0o644, 0, 0, 1, 0, stamp, stamp]}
                        for name in names}}


def diagnostic_data():
    rows = {"dl_dst_lib": '"lib/x86_64-linux-gnu"', "dso.ld": '"ld-linux-x86-64.so.2"', "dso.libc": '"libc.so.6"',
            "path.rtld": '"/lib64/ld-linux-x86-64.so.2"', "version.version": '"2.39"',
            "dl_hwcaps_subdirs": '"x86-64-v4:x86-64-v3:x86-64-v2"', "dl_hwcaps_subdirs_active": "0x7"}
    rows.update({"path.system_dirs[0x" + format(index, "x") + "]": '"' + path + '/"' for index, path in enumerate(L.DEFAULT_LIBRARY_DIRS)})
    return "".join(key + "=" + value + "\n" for key, value in rows.items()).encode("ascii")


def map_data():
    roles = {"python", "libssl.so.3", "libcrypto.so.3", "ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6"}
    return {role: {"paths": ["/inert/" + role], "deviceMajor": 8, "deviceMinor": 2, "inode": index + 1} for index, role in enumerate(sorted(roles))}


def native_capture(case, expected=None):
    prefix = "test " + L.INSTALLED_TESTS[case] + " ... "
    count = {"positive": 2, "shutdown": 1, "overlap": 2}.get(case, 0)
    if case == "emfile":
        return ("running 1 test\n" + prefix + "\n" + L.EMFILE_MARKER + "\n").encode("ascii")
    summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.01s\n"
    if not count:
        return ("running 1 test\n" + prefix + "ok\n" + summary).encode("ascii")
    rows = [{"role": role, "path": row["paths"][0], **{key: row[key] for key in ("deviceMajor", "deviceMinor", "inode")}} for role, row in sorted(expected.items())]
    marker = L.CHILD_MARKER.encode("ascii") + L.canonical(rows)
    return ("running 1 test\n" + prefix + "\n").encode("ascii") + marker * count + ("ok\n" + summary).encode("ascii")


def installed_handoff(case="positive"):
    pin = {"size": 12, "sha256": "c" * 64}
    candidate = {"path": "/task/admitted-candidate/candidate", **pin}
    return {"sourceSha": "a" * 40, "runId": "10", "attempt": "2", "deadline": 1300.0, "runnerUid": 1001, "runnerGid": 1001,
            "source": "/source", "taskRoot": "/task", "library": {"path": "/task/admitted-u/libtest", **pin},
            "packages": {label: {"path": "/task/admitted-u/" + label + ".deb", **pin, "manifestSha256": row[0], "version": row[1]} for label, row in L.VERSIONS.items()},
            "compilerRecords": {"sourceSha": "b" * 40},
            "installed": {"case": case, "candidate": candidate, "candidateRosterSha256": "d" * 64,
                "candidateProducerAttempt": "1", "candidateArtifactId": "17", "loaderPolicy": {},
                "acceptedU": {"sourceSha": "b" * 40, "runId": "5", "attempt": "1", "artifactId": "11"},
                "candidateCompiler": {"sourceSha": "a" * 40, "runId": "10", "attempt": "1", "features": [],
                    "manifestSha256": L.M, "protocolSha256": L.Q, "exportedArtifacts": {"candidate": candidate}}}}


def inert_stat(ino, mode, *, size=0, uid=0, gid=0, stamp=0):
    return SimpleNamespace(st_dev=1, st_ino=ino, st_mode=mode, st_uid=uid, st_gid=gid,
                           st_nlink=2 if stat.S_ISDIR(mode) else 1, st_size=size, st_mtime_ns=stamp, st_ctime_ns=stamp)


def shell_loader_data():
    """Inert closed-observation DATA, not native execution or host receipts."""
    value = installed_handoff()
    value.pop("installed")
    libraries, bindings = {}, {}
    names = sorted({"libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2", *L.PRIVATE_SONAMES, "libpxbackend-1.0.so"})
    for index, name in enumerate(names):
        path = "/usr/lib/x86_64-linux-gnu/" + ("libproxy/" if name == "libpxbackend-1.0.so" else "") + name
        row = {"path": path, "selectedPath": path, "size": 4, "sha256": "a" * 64,
               "identity": [os.makedev(8, 2), index + 1, stat.S_IFREG | 0o644, 1, 4, 0, 0]}
        libraries[name] = {"file": row}
        bindings[path] = row
    tiers = {directory + "/glibc-hwcaps/" + tier: False for directory in L.DEFAULT_LIBRARY_DIRS for tier in L.HWCAPS}
    for path in tiers:
        bindings[path] = {"absent": True}
    globals_ = sorted(name for name in names if name != "libpxbackend-1.0.so")
    for name in globals_:
        for directory in L.DEFAULT_LIBRARY_DIRS:
            path = directory + "/" + name
            bindings[path] = ({**libraries[name]["file"], "selectedPath": path}
                              if directory in L.DEFAULT_LIBRARY_DIRS[:2] else {"absent": True})
    alias = "/lib64/ld-linux-x86-64.so.2"
    bindings[alias] = {**libraries["ld-linux-x86-64.so.2"]["file"], "selectedPath": alias}
    module_root = "/usr/lib/x86_64-linux-gnu/gio/modules"
    bindings[module_root] = {"directory": [1, 2, stat.S_IFDIR | 0o755, 0, 0]}
    roots = {module_root: {"binding": bindings[module_root], "children": ["giomodule.cache", "libinert.so"]}}
    search = [{"requester": "/usr/lib/x86_64-linux-gnu/libproxy.so.1", "runpath": "/usr/lib/x86_64-linux-gnu/libproxy",
               "name": name, "path": "/usr/lib/x86_64-linux-gnu/libproxy/" + name, "selected": name == "libpxbackend-1.0.so"}
              for name in ("libc.so.6", "libpxbackend-1.0.so")]
    bindings[search[0]["path"]] = {"absent": True}
    summary = {"suppliers": {"sha256": "b" * 64}, "caches": {"sha256": "c" * 64},
               "moduleSelections": {}, "eglLibraries": {}}
    files, records = {}, []
    for index in range(len(L.SHELL_DATA_ROOTS)):
        leaf, raw = "shell-root-data-" + str(index) + ".json", L.canonical({"inert": index})
        files[leaf] = raw
        records.append({"path": leaf, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    graph = {"moduleRoots": {module_root: {"present": True, "modules": ["libinert.so"]}},
             "modules": {module_root + "/libinert.so": {}}, "privateSearch": search, "runtime": {}}
    policy = {"osNames": names, "libraries": libraries, "packages": {"libc6": {"binaryPackage": "libc6:amd64", "version": "2.39-0ubuntu8.8"}},
              "moduleRoots": roots, "runtimeData": {**summary, "records": [
                  {**row, "path": "shell-consumer-data-" + str(index) + ".json"} for index, row in enumerate(records)]}, "graph": graph}
    value["shell"] = {"loaderPolicy": policy}
    entry = {"scope": {}, "namespaces": {}, "bindings": deepcopy(bindings), "diagnostics": L.loader_diagnostics(diagnostic_data()),
             "cacheRows": [], "entryObjects": names, "globalObjects": globals_, "hwcapsTiers": tiers,
             "moduleRoots": roots, "privateSearch": search, "runtimeData": {**summary, "records": records},
             "runtimeDataRechecked": False, "payloadAdmitted": False, "externalPrerequisites": "inert DATA fixture"}
    final = deepcopy(entry)
    final.update(runtimeDataRechecked=True, payloadAdmitted=True)
    expected = {}
    for index, role in enumerate(sorted({"python", "ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6", *L.PRIVATE_SONAMES})):
        if role == "python" or role in L.PRIVATE_SONAMES:
            relative = "python/bin/python3" if role == "python" else "python/lib/" + role
            path = str(L.PREFIX / L.M / relative)
            row = {"path": path, "size": 5, "sha256": "d" * 64,
                   "identity": [os.makedev(8, 2), 20 + index, stat.S_IFREG | 0o444, 1, 5, 0, 0]}
            final["bindings"][path] = row
            graph["runtime"][relative] = {"file": row}
            paths = [path]
        else:
            row = libraries[role]["file"]
            paths = sorted([directory + "/" + role for directory in L.DEFAULT_LIBRARY_DIRS[:2]]
                           + (["/lib64/" + role] if role == "ld-linux-x86-64.so.2" else []))
        expected[role] = {"paths": paths, "deviceMajor": 8, "deviceMinor": 2, "inode": row["identity"][1]}
    files.update({"loader-entry.json": L.canonical(entry), "loader-final.json": L.canonical(final),
        "loader-diagnostics.stdout": diagnostic_data(), "loader-diagnostics.stderr": b"", "loader-cache.stderr": b"",
        "loader-cache.stdout": b"1 libs found in cache `/etc/ld.so.cache'\n\tlibunrelated.so (libc6,x86-64) => /usr/lib/libunrelated.so\n",
        "loader-runtime.json": L.canonical({"expectedMaps": expected, "manifestSha256": L.M, "protocolSha256": L.Q,
            "privateObjects": sorted(L.PRIVATE_SONAMES), "shadowedCacheRows": [],
            "shadowedDefaultNames": [directory + "/" + tier + name for directory in L.DEFAULT_LIBRARY_DIRS
                for tier in ("", *("glibc-hwcaps/" + tier + "/" for tier in L.HWCAPS)) for name in sorted(L.PRIVATE_SONAMES)]})})
    return value, files, expected


class LifecycleData(unittest.TestCase):
    def test_shell_closed_loader_reconciles_interval_search_data_and_actual_aliases(self):
        value, files, expected = shell_loader_data()
        self.assertEqual(L.shell_closed_loader(value, files), expected)
        for case in ("late-data", "changed-binding", "missing-hwcaps", "private-shadow", "wrong-map", "wrong-private-bytes", "changed-data", "changed-consumer"):
            current = deepcopy(value)
            changed = dict(files)
            entry, final = (L.decode(changed["loader-" + phase + ".json"]) for phase in ("entry", "final"))
            runtime = L.decode(changed["loader-runtime.json"])
            if case == "late-data":
                final["runtimeDataRechecked"] = False
            elif case == "changed-binding":
                final["bindings"]["/lib/libc.so.6"] = {"absent": False}
            elif case == "missing-hwcaps":
                for proof in (entry, final):
                    proof["bindings"].pop("/lib/glibc-hwcaps/x86-64-v2")
            elif case == "private-shadow":
                for proof in (entry, final):
                    proof["bindings"]["/usr/lib/x86_64-linux-gnu/libproxy/libc.so.6"] = {"absent": False}
            elif case == "wrong-map":
                runtime["expectedMaps"]["libssl.so.3"]["inode"] += 1
            elif case == "wrong-private-bytes":
                final["bindings"][str(L.PREFIX / L.M / "python/lib/libssl.so.3")]["sha256"] = "e" * 64
            elif case == "changed-consumer":
                current["shell"]["loaderPolicy"]["runtimeData"]["records"][0]["sha256"] = "f" * 64
            else:
                changed["shell-root-data-0.json"] = b"not the original complete DATA\n"
            changed.update({"loader-entry.json": L.canonical(entry), "loader-final.json": L.canonical(final),
                            "loader-runtime.json": L.canonical(runtime)})
            with self.subTest(case=case), self.assertRaises((ValueError, KeyError)):
                L.shell_closed_loader(current, changed)

    def test_shell_cache_is_graph_bound_and_does_not_widen_the_headless_profile(self):
        # A protected global selector through an alternatives subdirectory
        # must still have every eligible cache/default candidate checked.
        providers = {"libinert.so": {"file": {"selectedPath": "/usr/lib/x86_64-linux-gnu/libinert.so",
                     "path": "/usr/lib/x86_64-linux-gnu/inert/libinert.so"}},
                     "libpxbackend-1.0.so": {"file": {"selectedPath": "/usr/lib/x86_64-linux-gnu/libproxy/libpxbackend-1.0.so"}}}
        self.assertEqual(L.shell_global_names(providers), ["libinert.so"])
        with self.assertRaises(ValueError):
            L.shell_global_names({"libinert.so": {"file": {"selectedPath": "/unselected/libinert.so"}}})
        raw = b"1 libs found in cache `/etc/ld.so.cache'\n\tlibgtk-3.so.0 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libgtk-3.so.0\n"
        self.assertFalse(L.loader_cache(raw, "2.39-0ubuntu8.8")[0]["eligibleX86_64"])
        rows = L.loader_cache(raw, "2.39-0ubuntu8.8", shell_names=["libgtk-3.so.0"])
        self.assertTrue(rows[0]["eligibleX86_64"])
        tiers = {directory + "/glibc-hwcaps/" + tier: False for directory in L.DEFAULT_LIBRARY_DIRS for tier in L.HWCAPS}
        self.assertEqual(len(L.shell_loader_candidates(["libgtk-3.so.0"], rows, tiers)), 4)
        tiers["/lib/glibc-hwcaps/x86-64-v2"] = True
        self.assertIn(("libgtk-3.so.0", "/lib/glibc-hwcaps/x86-64-v2/libgtk-3.so.0"),
                      L.shell_loader_candidates(["libgtk-3.so.0"], rows, tiers))
        with self.assertRaises(ValueError):
            L.loader_candidates(["libgtk-3.so.0"], rows)
        with self.assertRaises(ValueError):
            L.shell_loader_candidates(["libgtk-3.so.0"], rows, {})

    def test_shell_observation_requires_real_bootstrap_and_explicit_pure_contract_completion(self):
        expected = map_data()
        bootstrap = b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n"
        contracts = b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n"
        maps = [{"role": role, "path": row["paths"][0], **{key: row[key] for key in ("deviceMajor", "deviceMinor", "inode")}}
                for role, row in sorted(expected.items())]
        captures = {"normal": (bootstrap, b""), "positive": positive_capture(),
                    "quit-outstanding": (contracts + L.CHILD_MARKER.encode() + L.canonical(maps)
                        + b"MRK_INSTALLED_SHELL_OBSERVATION=quit-outstanding-verified\n", b"")}
        for case, (stdout, stderr) in captures.items():
            with self.subTest(case=case):
                self.assertEqual(L.shell_result(stdout, stderr, case, 0, expected)["case"], case)
                if case != "positive":
                    self.assertEqual(L.shell_result(stderr, stdout, case, 0, expected)["case"], case)
                for changed in ((b"", b""), (stdout + contracts, stderr),
                                (stdout.replace(b"=available", b"=unavailable"), stderr.replace(b"=available", b"=unavailable")),
                                (stdout.replace(contracts, b""), stderr), (stdout.replace(b'"inode":1', b'"inode":999'), stderr)):
                    if changed != (stdout, stderr):
                        with self.assertRaises(ValueError):
                            L.shell_result(*changed, case, 0, expected)
                with self.assertRaises(ValueError):
                    L.shell_result(stdout, stderr, case, True, expected)

    def test_normal_controller_joins_the_original_even_when_start_or_input_fails(self):
        value, expected = installed_handoff(), map_data()
        value.pop("installed")
        value["shell"] = {}
        for case in ("complete", "start-return-error", "input-error", "unjoined"):
            events, originals, retained, now, focused = [], [], {}, [100.0], [31]
            class Original:
                def __init__(self, **options):
                    originals.append(self)
                    self.joined = False
                    holder, argv, _, _ = options["args"]
                    holder.update(guardState="RESTORED", errors=[], result=subprocess.CompletedProcess(argv, 0,
                        b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n", b""))
                def start(self):
                    events.append("start")
                    if case == "start-return-error":
                        raise RuntimeError("inert start-return loss")
                def join(self, timeout):
                    events.append("join")
                    self.joined = case != "unjoined"
                def is_alive(self):
                    return not self.joined
            def clock():
                now[0] += 0.05
                return now[0]
            def owned(argv, **options):
                args = argv[argv.index("/usr/bin/xdotool") + 1:]
                events.append(args[0])
                if case == "input-error":
                    raise RuntimeError("inert controller failure")
                output = b""
                if args[0] == "search":
                    output = b"32\n" if args[-1].startswith("^Quit") else b"31\n"
                elif args[0] == "getwindowpid":
                    output = b"123\n"
                elif args[0] == "windowfocus":
                    focused[0] = int(args[-1])
                elif args[0] == "getwindowfocus":
                    output = str(focused[0]).encode() + b"\n"
                return subprocess.CompletedProcess(argv, 0, output, b"")
            with self.subTest(case=case), patch.multiple(L, _ROOT=L.root_path(value), _END=value["deadline"],
                    _FAILED=False, _COMMANDS=[], _OWNER=SimpleNamespace(run_owned=owned)), \
                 patch.object(L.threading, "Thread", Original), patch.object(L.time, "monotonic", side_effect=clock), \
                 patch.object(L.time, "sleep"), patch.object(L, "_shell_window_pid"), \
                 patch.object(L, "_retain", side_effect=lambda name, raw: retained.update({name: raw})):
                if case == "complete":
                    result = L._shell_normal(value, L.shell_environment(value, "normal"), expected)
                    self.assertTrue(result["bootstrapReturned"])
                    control = L.decode(retained["shell-normal-control.json"])
                    self.assertEqual([row["argv"][-1] for row in control["commands"] if row["phase"] == "key"], ["ctrl+q", "alt+o"])
                    self.assertFalse(L._FAILED)
                else:
                    with self.assertRaises((ValueError, RuntimeError)):
                        L._shell_normal(value, L.shell_environment(value, "normal"), expected)
                    self.assertTrue(L._FAILED)
                self.assertEqual(len(originals), 1)
                self.assertEqual(events.count("join"), 1)

    def test_version_store_prefixes_bind_exact_application_children(self):
        app = Path("/var/lib/mobile-release-kit")
        self.assertEqual(L.PREFIX, app / "versions" / L.TARGET)
        children = {app: {"versions"}, app / "versions": {L.TARGET}, L.PREFIX: {L.M}}
        nodes = {path: needrestart_stat(stat.S_IFDIR | 0o755, ino=index + 1)
                 for index, path in enumerate(children)}
        with patch.object(L, "directory") as checked, patch.object(L, "_xattrs") as attrs, \
                patch.object(L.Path, "lstat", lambda path: nodes[path]), \
                patch.object(L.Path, "iterdir", lambda path: iter(path / name for name in children[path])):
            actual = L._prefixes(("P0",))
            self.assertEqual(actual, {str(path): list(L.identity(nodes[path])) for path in children})
            self.assertEqual(checked.call_args_list, [unittest.mock.call(path, protected=True) for path in children])
            self.assertEqual(attrs.call_args_list, [unittest.mock.call(path, True) for path in children])
            children[L.PREFIX].add("unexpected")
            with self.assertRaises(L.Refused):
                L._prefixes(("P0",))

    def test_directory_refusal_reports_the_same_inspected_ancestor_without_weakening_policy(self):
        path = Path("/inert/\u00e9\nleaf")
        ancestors = [path, *path.parents]
        for protected, selected, mode, uid, gid, reason in (
            (True, path, stat.S_IFDIR | 0o755, 0, 0, None),
            (False, path, stat.S_IFDIR | 0o777, 1001, 1002, None),
            (True, path, stat.S_IFDIR | 0o1700, 0, 0, None),
            (False, path, stat.S_IFREG | 0o644, 0, 0, "Nonordinary lifecycle ancestor"),
            (False, path, stat.S_IFLNK | 0o777, 0, 0, "Nonordinary lifecycle ancestor"),
            (True, path, stat.S_IFDIR | 0o755, 1001, 0, "Unprotected lifecycle ancestor"),
            (True, path, stat.S_IFDIR | 0o755, 0, 1002, "Unprotected lifecycle ancestor"),
            (True, path, stat.S_IFDIR | 0o757, 0, 0, "Unprotected lifecycle ancestor"),
            (True, path.parent, stat.S_IFDIR | 0o775, 0, 0, "Unprotected lifecycle ancestor"),
        ):
            inspected = []
            def lstat(parent):
                inspected.append(parent)
                return SimpleNamespace(st_mode=mode if parent == selected else stat.S_IFDIR | 0o755,
                                       st_uid=uid if parent == selected else 0, st_gid=gid if parent == selected else 0)
            with self.subTest(protected=protected, path=selected, mode=mode, uid=uid, gid=gid), \
                 patch.object(Path, "lstat", autospec=True, side_effect=lstat), \
                 patch.object(Path, "stat", side_effect=AssertionError("Unexpected link-following probe")):
                if reason is None:
                    L.directory(path, protected=protected)
                else:
                    with self.assertRaises(L.Refused) as refused:
                        L.directory(path, protected=protected)
                    self.assertEqual(str(refused.exception), reason + " path=" + ascii(str(selected))
                                     + " mode=" + oct(mode) + " uid=" + str(uid) + " gid=" + str(gid))
                    self.assertTrue(all(32 <= ord(character) < 127 for character in str(refused.exception)))
                self.assertEqual(inspected, ancestors if reason is None else ancestors[:ancestors.index(selected) + 1])
        with patch.object(Path, "lstat", side_effect=AssertionError("Relative path was inspected")), \
             self.assertRaisesRegex(L.Refused, "Absolute directory required"):
            L.directory(Path("relative"))

    def test_dpkg_policy_uses_dynamic_default_or_explicit_empty_ordinary_home(self):
        links = {Path("/bin"): "usr/bin", Path("/sbin"): "usr/sbin", Path("/usr/bin/sh"): "dash"}
        config = b"log /var/log/dpkg.log\n"
        fragments, environment, expected = Path("/etc/dpkg/dpkg.cfg.d"), dict(os.environ), None
        for case in ("default-first", "default-later", "explicit", "default-nonempty", "explicit-nonempty", "default-link", "explicit-link"):
            root = None if case.startswith("explicit") else Path("/inert/later" if case == "default-later" else "/inert/original")
            home = Path("/runner/work/home") if root is None else root / "private/home"
            binding = None if root is None else {"path": str(root / "private/dpkg.log"), "identity": [1, 2, stat.S_IFREG | 0o600, 0, 0, 1]}
            home_reads = []
            def lstat(path):
                self.assertFalse(path.is_relative_to("/var/log"), "Ambient dpkg log ancestry was inspected")
                info = needrestart_stat(stat.S_IFLNK | 0o777 if path in links else stat.S_IFDIR | 0o755, nlink=1 if path in links else 2)
                if path != Path("/") and path in (home, *home.parents):
                    info.st_uid = info.st_gid = 1001
                if case.endswith("link") and path == home.parent:
                    info.st_mode = stat.S_IFLNK | 0o777
                return info
            def entries(path):
                if path == fragments:
                    return iter(())
                self.assertEqual(path, home)
                home_reads.append(path)
                return iter([home / "occupied"] if case.endswith("nonempty") else [])
            def record(path, limit=L.FILE_LIMIT):
                raw = config if path == Path("/etc/dpkg/dpkg.cfg") else b""
                return {"path": str(path), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                        "identity": list(L.identity(needrestart_stat(stat.S_IFREG | 0o755, size=len(raw))))}
            with self.subTest(case=case), patch.object(L, "_ROOT", root), \
                 patch.object(L, "protected_record", side_effect=record), patch.object(L, "read", return_value=config), \
                 patch.object(L, "private_dpkg_log", return_value=binding) as private_log, \
                 patch.object(L, "needrestart_inputs", return_value={}), patch.object(L.os, "readlink", side_effect=links.__getitem__), \
                 patch.object(Path, "lstat", autospec=True, side_effect=lstat), patch.object(Path, "stat", autospec=True, side_effect=lstat), \
                 patch.object(Path, "iterdir", autospec=True, side_effect=entries), patch.object(L, "directory", wraps=L.directory) as directories:
                options = {"home": home} if root is None else {}
                if case.endswith(("nonempty", "link")):
                    with self.assertRaisesRegex(L.Refused, "Nonordinary lifecycle ancestor" if case.endswith("link") else "Dpkg HOME is no longer empty"):
                        L.dpkg_policy(**options)
                else:
                    observed = L.dpkg_policy(**options)
                    self.assertEqual("logBinding" in observed, root is not None)
                    self.assertEqual(observed.pop("logBinding", None), binding)
                    if expected is None:
                        expected = observed
                    self.assertEqual(observed, expected)
                directories.assert_any_call(home)
                if root is None:
                    private_log.assert_not_called()
                else:
                    private_log.assert_called_once_with()
                self.assertEqual(home_reads, [] if case.endswith("link") else [home])
                self.assertEqual(L._ROOT, root)
                self.assertTrue(dict(os.environ) == environment, "Policy mutated the process environment")

    def test_needrestart_config_requires_the_exact_path_and_complete_bytes(self):
        path = Path("/etc/dpkg/dpkg.cfg.d/needrestart")
        self.assertEqual((len(NEEDRESTART_CONFIG_DATA), hashlib.sha256(NEEDRESTART_CONFIG_DATA).hexdigest()), L.NEEDRESTART_CONFIG_PIN)
        self.assertEqual(L.dpkg_config_options(path, NEEDRESTART_CONFIG_DATA), [L.NEEDRESTART_OPTION])
        for changed_path, raw in ((path, NEEDRESTART_CONFIG_DATA + b"\n"), (path, NEEDRESTART_CONFIG_DATA.replace(b"# hook.", b"# other")),
                                  (path, b"no-debsig\n"), (Path("/etc/dpkg/dpkg.cfg"), NEEDRESTART_CONFIG_DATA),
                                  (Path("/etc/dpkg/dpkg.cfg.d/relocated"), NEEDRESTART_CONFIG_DATA)):
            with self.subTest(path=changed_path, raw=raw), self.assertRaises(ValueError):
                L.dpkg_config_options(changed_path, raw)
        with self.assertRaises(ValueError):
            L.config_options(NEEDRESTART_CONFIG_DATA)
        self.assertEqual(L.dpkg_config_options(Path("/etc/dpkg/dpkg.cfg"), b"no-debsig\n"), ["no-debsig"])

    def test_needrestart_logger_search_and_fallback_require_protected_exact_inputs(self):
        self.assertTrue({"/usr/bin/" + name for name in ("cat", "mkdir", "touch")} <= set(L.TOOLS))
        for case in ("ok", "script-sha", "script-size", "script-mode", "shadow-cat", "shadow-mkdir", "shadow-touch",
                     "null-type", "null-device", "null-links", "null-owner", "null-mode"):
            script = {"path": str(L.NEEDRESTART_SCRIPT), "size": 1045, "sha256": L.NEEDRESTART_SCRIPT_PIN[1],
                      "identity": list(L.identity(needrestart_stat(stat.S_IFREG | 0o755, size=1045)))}
            null = needrestart_stat(stat.S_IFCHR | 0o666, ino=5, rdev=os.makedev(1, 3))
            if case == "script-sha": script["sha256"] = "0" * 64
            if case == "script-size": script["size"] += 1
            if case == "script-mode": script["identity"][2] = stat.S_IFREG | 0o644
            if case == "null-type": null.st_mode = stat.S_IFREG | 0o666
            if case == "null-device": null.st_rdev = os.makedev(1, 5)
            if case == "null-links": null.st_nlink = 2
            if case == "null-owner": null.st_uid = 1001
            if case == "null-mode": null.st_mode = stat.S_IFCHR | 0o600
            def lstat(path):
                if path.parent == Path("/usr/sbin"):
                    if case == "shadow-" + path.name:
                        return needrestart_stat(stat.S_IFLNK | 0o777)
                    raise FileNotFoundError()
                if path == Path("/dev/null"): return null
                return needrestart_stat(stat.S_IFDIR | 0o755, ino=2 if path == Path("/dev") else 1, nlink=2)
            with self.subTest(case=case), patch.object(L, "protected_record", return_value=script), \
                 patch.object(L, "directory") as directory, patch.object(L, "_xattrs"), patch.object(Path, "lstat", autospec=True, side_effect=lstat):
                if case == "ok":
                    result = L.needrestart_inputs()
                    self.assertEqual(result["absentEarlierSearch"], ["/usr/sbin/" + name for name in ("cat", "mkdir", "touch")])
                    self.assertEqual(result["nullDevice"]["device"], [1, 3])
                    directory.assert_any_call(Path("/dev"), protected=True)
                else:
                    with self.assertRaises(ValueError): L.needrestart_inputs()

    def test_needrestart_markers_preserve_originals_and_only_allow_known_empty_creation(self):
        absent, initial = needrestart_data(present=False), needrestart_data("unpacked")
        L.needrestart_transition(absent, absent)  # No claim that the logger creates anything.
        L.needrestart_transition(absent, needrestart_data())
        L.needrestart_transition(absent, initial)
        L.needrestart_transition(initial, needrestart_data("unpacked", "errored", stamp=2))
        L.needrestart_transition(initial, needrestart_data("unpacked", stamp=3))
        changes = (
            lambda row: row["markers"]["unpacked"]["identity"].__setitem__(1, 99),
            lambda row: row["markers"]["unpacked"]["identity"].__setitem__(2, stat.S_IFLNK | 0o777),
            lambda row: row["markers"]["unpacked"]["identity"].__setitem__(3, 1001),
            lambda row: row["markers"]["unpacked"]["identity"].__setitem__(5, 2),
            lambda row: row["markers"]["unpacked"].__setitem__("size", 1),
            lambda row: row["markers"]["unpacked"].__setitem__("sha256", "0" * 64),
            lambda row: row["markers"].pop("unpacked"),
            lambda row: row["markers"].__setitem__("extra", deepcopy(row["markers"]["unpacked"])),
            lambda row: row["directory"].__setitem__(1, 99),
            lambda row: row["directory"].__setitem__(2, stat.S_IFLNK | 0o777),
            lambda row: row["directory"].__setitem__(6, 8192),
            lambda row: row["runIdentity"].__setitem__(1, 99),
        )
        for change in changes:
            after = deepcopy(initial); change(after)
            with self.assertRaises(ValueError): L.needrestart_transition(initial, after)
        alias = needrestart_data("unpacked", "errored")
        alias["markers"]["errored"]["identity"][:2] = alias["markers"]["unpacked"]["identity"][:2]
        with self.assertRaises(ValueError): L.needrestart_transition(absent, alias)
        for part in ("directory", "marker"):
            after = needrestart_data("unpacked")
            (after["directory"] if part == "directory" else after["markers"]["unpacked"]["identity"])[2] &= ~0o044
            with self.assertRaises(ValueError): L.needrestart_transition(absent, after)
        for extra in (False, True):
            names = ["unpacked"] + (["unlisted"] if extra else [])
            with patch.object(L, "directory"), patch.object(L, "_xattrs"), \
                 patch.object(Path, "lstat", return_value=needrestart_stat(stat.S_IFDIR | 0o755, ino=2, nlink=2, size=4096)), \
                 patch.object(L.os, "scandir") as scan, patch.object(L, "protected_record", return_value=initial["markers"]["unpacked"]):
                scan.return_value.__enter__.return_value = iter(SimpleNamespace(name=name) for name in names)
                if extra:
                    with self.assertRaises(ValueError): L.needrestart_state()
                else:
                    self.assertEqual(L.needrestart_state()["markers"], initial["markers"])

    def test_private_dpkg_log_requires_fresh_protected_bounded_original(self):
        root = Path("/inert")
        log = root / "private/dpkg.log"
        original = needrestart_stat(stat.S_IFREG | 0o600)
        binding = {"path": str(log), "identity": list(L.identity(original)[:6])}
        for case in ("empty", "append", "missing", "symlink", "mode", "uid", "gid", "links", "oversize", "xattr", "drift", "parent"):
            item, reads = deepcopy(original), []
            if case == "append": item.st_size, item.st_mtime_ns, item.st_ctime_ns = L.LIMIT, 1, 2
            if case == "symlink": item.st_mode = stat.S_IFLNK | 0o600
            if case == "mode": item.st_mode = stat.S_IFREG | 0o640
            if case == "uid": item.st_uid = 1001
            if case == "gid": item.st_gid = 1001
            if case == "links": item.st_nlink = 2
            if case == "oversize": item.st_size = L.LIMIT + 1
            def lstat(path):
                if path == log:
                    reads.append(path)
                    if case == "missing": raise FileNotFoundError()
                    result = deepcopy(item)
                    if case == "drift" and len(reads) == 2: result.st_ino += 1
                    return result
                mode = 0o770 if case == "parent" and path == log.parent else 0o700
                return needrestart_stat(stat.S_IFDIR | mode, nlink=2)
            with self.subTest(case=case), patch.object(L, "_ROOT", root), \
                 patch.object(Path, "lstat", autospec=True, side_effect=lstat), \
                 patch.object(L, "_xattrs", side_effect=L.Refused("Inert log ACL") if case == "xattr" else None), \
                 patch.object(L, "directory", wraps=L.directory) as directory:
                if case in {"empty", "append"}:
                    self.assertEqual(L.private_dpkg_log(), binding)
                else:
                    with self.assertRaises((L.Refused, FileNotFoundError)):
                        L.private_dpkg_log()
                directory.assert_called_once_with(log.parent, protected=True)
        # Reuse the unchanged exclusive DATA writer; an occupied name stops
        # root entry before policy admission, with the original error intact.
        for occupied in (False, True):
            events = []
            stopped = FileExistsError("Inert occupied log") if occupied else RuntimeError("Stop after initial policy")
            def write(path, raw, mode):
                self.assertEqual((path, raw, mode), (log, b"", 0o600))
                context.assert_called_once_with(copying=True)
                events.append("write")
                if occupied: raise stopped
            def policy():
                events.append("policy")
                raise stopped
            with patch.multiple(L, _ROOT=root, _D=SimpleNamespace(write=write)), patch.object(L, "_root_ids"), \
                 patch.object(L, "_context", return_value=({}, "a" * 64)) as context, patch.object(L, "_namespaces"), \
                 patch.object(L, "dpkg_policy", side_effect=policy), patch.object(L, "command", side_effect=AssertionError("Package launch")):
                with self.assertRaises(type(stopped)) as refused:
                    L.unit_start()
                self.assertIs(refused.exception, stopped)
                self.assertEqual(events, ["write"] if occupied else ["write", "policy"])

    def test_package_observation_uses_original_return_and_latches_every_failure(self):
        root = Path("/inert")
        binding = {"path": str(root / "private/dpkg.log"), "identity": [1, 2, stat.S_IFREG | 0o600, 0, 0, 1]}
        policy = {"logBinding": binding}
        before, after = needrestart_data(present=False), needrestart_data("unpacked")
        for case in ("complete", "collision", "endpoint", "caller-log", "policy", "before", "command", "log-failure", "log-change",
                     "after", "changed", "late", "endpoint-late"):
            phase = "duplicate" if case == "collision" else "upgrade-configure" if case.startswith("endpoint") else "unpack"
            codes = (1,) if case == "collision" else (0,)
            argv = ["/usr/bin/dpkg", "--debug=2", "--no-triggers", L.PACKAGE_ACTIONS[phase],
                    L.PACKAGE if phase == "upgrade-configure" else "/inert/P0.deb"]
            owned = argv[:4] + ["--log=" + str(root / "private/dpkg.log"), argv[4]]
            if case == "caller-log": argv.insert(4, "--log=/foreign")
            caller = list(argv)
            endpoint = 150 if case.startswith("endpoint") else None
            completed = subprocess.CompletedProcess(owned, codes[0], b"", b"")
            owner_error = RuntimeError("inert original owner failure")
            reads, events = [], []
            def snapshot():
                events.append("snapshot")
                reads.append(None)
                if case == "before" or case == "after" and len(reads) == 2:
                    raise ValueError("inert marker refusal")
                result = deepcopy(before if len(reads) == 1 else after)
                if case == "changed" and len(reads) == 2: result["markers"]["unpacked"]["size"] = 1
                return result
            def read_log():
                events.append("log")
                self.assertTrue(L._FAILED, "Post-log observation did not retain the failed latch")
                if case == "log-failure": raise ValueError("inert log refusal")
                result = deepcopy(binding)
                if case == "log-change": result["identity"][1] += 1
                return result
            def command(label, actual, **options):
                events.append("command")
                if case == "command": raise owner_error
                self.assertEqual((actual, options["maximum"], options["env"]["PATH"], options["codes"]), (owned, 240, L.DPKG_PATH, codes))
                if endpoint is None: self.assertNotIn("endpoint", options)
                else: self.assertEqual(options["endpoint"], endpoint)
                L._COMMANDS.append({"phase": label, "argv": actual, "exitCode": completed.returncode})
                return completed
            with self.subTest(case=case), patch.multiple(L, _ROOT=root, _END=200, _FAILED=False, _COMMANDS=[], _PHASE="inert"), \
                 patch.object(L, "dpkg_policy", return_value={"changed": 1} if case == "policy" else policy), \
                 patch.object(L, "private_dpkg_log", side_effect=read_log), \
                 patch.object(L, "needrestart_state", side_effect=snapshot), patch.object(L, "command", side_effect=command), \
                 patch.object(L.time, "monotonic", return_value=201 if case == "late" else 151 if case == "endpoint-late" else 100):
                if case in {"complete", "collision", "endpoint"}:
                    self.assertIs(L.package_command(phase, argv, policy=policy, codes=codes, endpoint=endpoint), completed)
                    self.assertFalse(L._FAILED)
                    self.assertEqual(events, ["snapshot", "command", "log", "snapshot"])
                    self.assertIs(L._COMMANDS[0]["needrestartMarkers"]["loggerCompletionClaimed"], False)
                    with patch.object(L, "_ROOT", None), patch.object(L, "private_dpkg_log", side_effect=AssertionError("Collector probed private log")):
                        L.verify_package_observations(L._COMMANDS, root)
                        with self.assertRaises(ValueError): L.verify_package_observations(L._COMMANDS, Path("/different-original-root"))
                        for changed in ("missing-observation", "missing-log", "foreign-log", "wrong-order", "duplicate-log"):
                            rows = deepcopy(L._COMMANDS)
                            if changed == "missing-observation": rows[0].pop("needrestartMarkers")
                            if changed == "missing-log": rows[0]["argv"].pop(4)
                            if changed == "foreign-log": rows[0]["argv"][4] = "--log=/foreign"
                            if changed == "wrong-order": rows[0]["argv"][4:6] = reversed(rows[0]["argv"][4:6])
                            if changed == "duplicate-log": rows[0]["argv"].insert(4, owned[4])
                            with self.assertRaises(ValueError): L.verify_package_observations(rows, root)
                else:
                    with self.assertRaises((ValueError, RuntimeError)) as refused:
                        L.package_command(phase, argv, policy=policy, codes=codes, endpoint=endpoint)
                    if case == "command": self.assertIs(refused.exception, owner_error)
                    self.assertTrue(L._FAILED)
                    settled = list(events)
                    with self.assertRaises(ValueError): L.package_command(phase, argv, policy=policy, codes=codes, endpoint=endpoint)
                    self.assertEqual(events, settled)
                self.assertEqual(argv, caller)
                if case in {"caller-log", "policy", "before"}: self.assertNotIn("command", events)
                if case in {"caller-log", "policy", "before", "command"}: self.assertNotIn("log", events)
                if case == "command": self.assertEqual(len(reads), 1)

    def test_all_package_mutations_share_the_observed_command_wrapper(self):
        tree = ast.parse((SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_text())
        functions = {node.name: node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        def calls(name, target):
            return [node for node in ast.walk(functions[name]) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == target]
        self.assertEqual(len(calls("mutate", "package_command")), 1)
        self.assertFalse(calls("mutate", "command"))
        self.assertEqual(len(calls("package_command", "command")), 1)
        expected = {"unpack", "configure", "upgrade", "duplicate", "remove", "purge"}
        if "_installed_overlap" in functions:
            expected.add("upgrade-unpack")
            self.assertEqual(len(calls("_installed_overlap", "package_command")), 1)
            self.assertFalse(calls("_installed_overlap", "command"))
        self.assertEqual({node.args[0].value for node in calls("unit_start", "mutate")}, expected)
        self.assertEqual(len(calls("verify_service_result", "verify_package_observations")), 1)
        self.assertEqual(len(calls("_finish_body" if "_finish_body" in functions else "unit_start", "verify_package_observations")), 1)

    def test_loader_diagnostics_cache_and_every_soname_search_are_finite(self):
        raw = diagnostic_data()
        self.assertEqual(L.loader_diagnostics(raw)["activeMask"], 7)
        self.assertEqual(L.loader_diagnostics(raw.replace(b"active=0x7", b"active=0x0"))["checkedTiers"], list(L.HWCAPS))
        for changed in (raw + b'dso.libc="libc.so.6"\n', raw.replace(b'"2.39"', b'"2.40"'),
                        raw.replace(b"active=0x7", b"active=0x8"), raw.replace(b'"/usr/lib/"', b'"/tmp/"'), raw + b"unknown text\n"):
            with self.subTest(data=changed), self.assertRaises(ValueError):
                L.loader_diagnostics(changed)
        names = sorted(L.OS_SONAMES | L.PRIVATE_SONAMES)
        cache = (str(len(names)) + " libs found in cache `/etc/ld.so.cache'\n" +
                 "".join("\t" + name + " (libc6,x86-64) => /chosen/" + name + "\n" for name in names)).encode("ascii")
        rows = L.loader_cache(cache, "2.39-0ubuntu8.8")
        choices = L.loader_candidates(names, rows)
        for name in names:
            self.assertIn((name, "/chosen/" + name), choices)
            for directory in L.DEFAULT_LIBRARY_DIRS:
                self.assertIn((name, directory + "/" + name), choices)
                for tier in L.HWCAPS:
                    self.assertIn((name, directory + "/glibc-hwcaps/" + tier + "/" + name), choices)
        for changed in (cache.replace(b"11 libs", b"0 libs"), cache.replace(b"libc6,x86-64", b"libc6,unknown", 1),
                        cache.replace(b"/chosen/", b"/chosen/../", 1), cache + b"unexpected footer\n"):
            with self.assertRaises(ValueError):
                L.loader_cache(changed, "2.39-0ubuntu8.8")
        admitted = {"path": "/canonical/libc.so.6", "identity": [1, 2, 0o100644, 1, 3, 4, 5], "size": 3, "sha256": "a" * 64}
        L.loader_selected(admitted, admitted)
        L.loader_selected({"absent": True}, admitted)
        for key, value in (("path", "/other/libc.so.6"), ("identity", [1, 99, 0o100644, 1, 3, 4, 5]), ("sha256", "b" * 64)):
            with self.assertRaises(ValueError):
                L.loader_selected({**admitted, key: value}, admitted)

    def test_initial_root_mount_and_nested_loader_mounts_are_not_guessed(self):
        raw = "29 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n30 29 0:22 / /proc rw,nosuid,nodev,noexec - proc proc rw\n"
        device = os.makedev(8, 2)
        scope = L.mount_scope(raw, raw, device)
        L._mount_path(scope, Path("/usr/lib/x86_64-linux-gnu/libc.so.6"))
        with self.assertRaises(ValueError):
            L._mount_path(scope, Path("/proc/anything"))
        for changed in (raw.replace(" - ext4 ", " - overlay "), raw + raw.splitlines()[0] + "\n",
                        raw.replace("8:2", "8:3"), raw.replace("/ / rw", r"/ \057 rw"), raw.replace("shared:1", "idmapped:1")):
            with self.subTest(mounts=changed), self.assertRaises(ValueError):
                L.mount_scope(changed, changed, device)
        with self.assertRaises(ValueError):
            L.mount_scope(raw, raw + "different", device)

    def test_root_loader_binding_checks_original_alias_acl_and_mount_ancestry(self):
        library = Path("/usr/lib/libc.so.6")
        nodes = {Path("/"): inert_stat(1, stat.S_IFDIR | 0o755), Path("/usr"): inert_stat(2, stat.S_IFDIR | 0o755),
                 Path("/usr/lib"): inert_stat(3, stat.S_IFDIR | 0o755), Path("/lib"): inert_stat(4, stat.S_IFLNK | 0o777),
                 library: inert_stat(5, stat.S_IFREG | 0o644, size=4)}
        scope = {"root": {"device": 1}, "mountpoints": ["/"]}
        with patch.object(Path, "lstat", lambda path: nodes[path]), patch.object(Path, "resolve", return_value=library), \
             patch.object(L.os, "readlink", return_value="usr/lib"), patch.object(L, "record", return_value={"path": str(library), "size": 4, "sha256": "a" * 64}), \
             patch.object(L.os, "getxattr", side_effect=OSError(errno.ENODATA, "inert absent attribute")):
            row = L._loader_binding(Path("/lib/libc.so.6"), scope)
            self.assertEqual(row["path"], str(library))
            self.assertEqual(row["links"][0][0], "/lib")
            for changed in (inert_stat(2, stat.S_IFDIR | 0o777), inert_stat(2, stat.S_IFDIR | 0o755, uid=1001)):
                with patch.dict(nodes, {Path("/usr"): changed}), self.assertRaises(ValueError):
                    L._loader_binding(Path("/lib/libc.so.6"), scope)
            with patch.object(L.os, "getxattr", return_value=b"inert unexpected ACL"), self.assertRaises(ValueError):
                L._loader_binding(Path("/lib/libc.so.6"), scope)
            with self.assertRaises(ValueError):
                L._loader_binding(Path("/lib/libc.so.6"), {**scope, "mountpoints": ["/", "/usr"]})

    def test_exact_installed_captures_bind_original_maps_and_exit79_is_not_a_pass(self):
        expected = map_data()
        for case in L.INSTALLED_TESTS:
            raw = native_capture(case, expected)
            observed = L.installed_result(raw, b"", case, 79 if case == "emfile" else 0, expected)
            self.assertEqual(observed["libtestPassed"], case != "emfile")
            self.assertEqual(len(observed["maps"]), {"positive": 2, "shutdown": 1, "overlap": 2}.get(case, 0))
            for changed in (raw + b"extra\n", raw.replace(b"running 1 test", b"running 0 tests"),
                            raw.replace(b" ... \n", b" ... ", 1) if case in {"positive", "shutdown", "overlap", "emfile"} else raw.replace(b" ... ok", b" ... ignored")):
                with self.subTest(case=case), self.assertRaises(ValueError):
                    L.installed_result(changed, b"", case, 79 if case == "emfile" else 0, expected)
        emfile = L.installed_result(native_capture("emfile"), b"", "emfile", 79, None)
        self.assertFalse(emfile["nativeCleanupProven"])
        self.assertTrue(emfile["originalCarrierComplete"])
        for code in (0, True, -79):
            with self.assertRaises(ValueError):
                L.installed_result(native_capture("emfile"), b"", "emfile", code, None)
        raw = native_capture("overlap", expected)
        for changed in (raw.replace(b'"inode":1', b'"inode":99', 1), raw.replace(b'"deviceMajor":8', b'"deviceMajor":true', 1),
                        raw.replace(b'/inert/libc.so.6', b'/inert/libc.so.6 (deleted)', 1)):
            with self.assertRaises(ValueError):
                L.installed_result(changed, b"", "overlap", 0, expected)

    def test_installed_handoff_and_fixed_profiles_preserve_u_and_producer_identity(self):
        value = installed_handoff()
        def admitted(data):
            raw = L.canonical(data)
            with patch.object(L, "read", return_value=raw):
                return L.handoff(Path("/inert-handoff"), hashlib.sha256(raw).hexdigest())
        self.assertEqual(admitted(value)["installed"]["candidateProducerAttempt"], "1")
        changes = (lambda data: data["installed"].update(candidateProducerAttempt="3"),
                   lambda data: data["installed"].update(candidateArtifactId="0"),
                   lambda data: data["installed"]["candidateCompiler"].update(attempt="2"),
                   lambda data: data["installed"]["candidateCompiler"].update(features=["ubuntu-runtime-publisher"]),
                   lambda data: data["compilerRecords"].update(sourceSha=data["sourceSha"]),
                   lambda data: data["installed"]["candidate"].update(path=data["library"]["path"]))
        for index, change in enumerate(changes):
            data = deepcopy(value)
            change(data)
            with self.subTest(change=index), self.assertRaises(ValueError):
                admitted(data)
        self.assertEqual(L.root_phases({}), L.ROOT_PHASES)
        positive = L.root_phases(value)
        self.assertLess(positive.index("upgrade-unpack"), positive.index("upgrade-configure"))
        self.assertLess(positive.index("upgrade-configure"), positive.index("installed-overlap"))
        self.assertNotIn("upgrade", positive)
        for case in ("positive", "refuse-writable", "refuse-pth"):
            data = installed_handoff(case)
            phases = L.root_phases(data)
            self.assertEqual(len(phases), len(set(phases)))
            self.assertLessEqual(len(L.public_files(data)), 128)
            self.assertIn("native-root", phases)
            self.assertIn("native-user", phases)
            if case != "positive":
                self.assertNotIn("configure", phases)
                self.assertNotIn("installed-positive", phases)
                self.assertNotIn("loader-runtime.json", L.public_files(data))
                self.assertEqual(set(L.lifecycle_states(data)), {"initial", "unpacked", "refusal"})
                self.assertEqual(L.result_state(data), "installed-passive-refusal-observed")

    def test_shorter_command_cap_and_old_child_deadline_never_renew(self):
        argv = ["/inert-never-executed"]
        result = subprocess.CompletedProcess(argv, 0, b"", b"")
        owner = Mock(return_value=result)
        with patch.multiple(L, _END=120, _FAILED=False, _COMMANDS=[], _OWNER=SimpleNamespace(run_owned=owner)), \
             patch.object(L, "_root_ids"), patch.object(L, "_retain"), patch.object(L.time, "monotonic", side_effect=[100.0, 102.0]):
            L.command("upgrade-configure", argv, maximum=240, endpoint=109.5, env={})
            self.assertEqual(owner.call_args.kwargs["timeout"], 9)
            self.assertEqual(L._COMMANDS[0]["originalEndpoint"], 109.5)
            self.assertEqual(L._COMMANDS[0]["startMonotonic"], 100.0)
        with patch.multiple(L, _END=120, _FAILED=False, _COMMANDS=[], _OWNER=SimpleNamespace(run_owned=owner)), \
             patch.object(L, "_root_ids"), patch.object(L, "_retain"), patch.object(L.time, "monotonic", side_effect=[100.0, 110.0]):
            with self.assertRaises(ValueError):
                L.command("upgrade-configure", argv, endpoint=109.5, env={})
            self.assertTrue(L._FAILED)
        self.assertLessEqual(L.overlap_endpoint(b"109500000000\n", 100.0, 120.0), 109.5)
        self.assertEqual(L.overlap_endpoint(b"999000000000\n", 100.0, 120.0), 110.0)
        self.assertEqual(L.overlap_endpoint(b"999000000000\n", 100.0, 108.0), 108.0)
        for raw in (b"0\n", b"010\n", b"999\nextra", b"-10\n", b"18446744073709551616\n"):
            with self.assertRaises(ValueError):
                L.overlap_endpoint(raw, 100.0, 120.0)

    def test_ready_scheduling_write_may_change_times_but_never_original_inode_or_close(self):
        before = inert_stat(55, stat.S_IFREG | 0o620, gid=1001)
        after = inert_stat(55, stat.S_IFREG | 0o620, gid=1001, size=13, stamp=1)
        controls = {"readyIdentity": list(L.identity(before)[:6])}
        for case in ("written", "inode-changed", "read-error", "oversized"):
            changed = after if case != "inode-changed" else inert_stat(56, stat.S_IFREG | 0o620, gid=1001, size=13)
            if case == "oversized":
                changed = inert_stat(55, stat.S_IFREG | 0o620, gid=1001, size=33)
            with self.subTest(case=case), patch.object(L, "_ROOT", Path("/inert-root")), \
                 patch.object(Path, "lstat", return_value=before), patch.object(L.os, "open", return_value=51), \
                 patch.object(L.os, "fstat", side_effect=[before, changed]), patch.object(L.os, "close") as close, \
                 patch.object(L.os, "read", side_effect=OSError("inert read failure") if case == "read-error" else None, return_value=b"109500000000\n"):
                if case == "written":
                    self.assertEqual(L._overlap_ready_bytes(controls), b"109500000000\n")
                else:
                    with self.assertRaises((ValueError, OSError)):
                        L._overlap_ready_bytes(controls)
                close.assert_called_once_with(51)

    def test_original_overlap_worker_restores_its_same_guard_on_every_return(self):
        for case in ("complete", "owner-error", "install-error", "restore-error"):
            calls, holder = [], {}
            class Guard:
                handler_state = "RESTORED"
                def install(self):
                    calls.append("install")
                    if case == "install-error":
                        raise RuntimeError("inert install loss")
                def activate(self):
                    calls.append("activate")
                def restore(self):
                    calls.append("restore")
                    if case == "restore-error":
                        raise RuntimeError("inert restoration loss")
                def check(self):
                    calls.append("check")
            guard, argv = Guard(), ["/inert-overlap"]
            result = subprocess.CompletedProcess(argv, 0, b"inert", b"")
            def owned(*args, **kwargs):
                calls.append("owned")
                self.assertIs(kwargs["cancellation"], guard)
                if case == "owner-error":
                    raise RuntimeError("inert original owner failure")
                return result
            owner = SimpleNamespace(DefaultCancellation=Mock(return_value=guard), ProcessCleanupError=RuntimeError, run_owned=owned)
            with self.subTest(case=case), patch.object(L, "_OWNER", owner), patch.object(L, "command") as command, patch.object(L, "_retain") as retain:
                L._overlap_worker(holder, argv, {}, 30)
                self.assertEqual(calls[-2:], ["restore", "check"])
                self.assertEqual(len(holder["errors"]), 0 if case == "complete" else 1)
                if case in {"complete", "restore-error"}:
                    self.assertIs(holder["result"], result)
                command.assert_not_called()
                retain.assert_not_called()

    def test_overlap_always_joins_original_before_serializing_and_never_releases_after_failure(self):
        expected, value = map_data(), installed_handoff()
        for case in ("complete", "start-error", "ready-error", "configure-error", "release-error", "worker-error", "join-error", "unjoined", "bad-result"):
            events, originals = [], []
            class Original:
                def __init__(self, **kwargs):
                    originals.append(self)
                    self.joined = False
                    holder, argv, _, _ = kwargs["args"]
                    holder.update(guardState="RESTORED", errors=[RuntimeError("inert worker failure")] if case == "worker-error" else [],
                                  result=None if case == "bad-result" else subprocess.CompletedProcess(argv, 0, native_capture("overlap", expected), b""))
                    self.holder = holder
                    self.assert_daemon = kwargs["daemon"]
                def start(self):
                    events.append("start")
                    if case == "start-error":
                        raise RuntimeError("inert start return loss")
                def join(self, timeout):
                    events.append("join")
                    if case in {"start-error", "join-error"}:
                        raise RuntimeError("inert join failure")
                    self.joined = case != "unjoined"
                def is_alive(self):
                    return not self.joined
            def ready(*args):
                events.append("ready")
                if case == "ready-error":
                    raise RuntimeError("inert ready refusal")
                return 109.5
            def configure(label, argv, **kwargs):
                events.append("configure")
                self.assertEqual((label, argv), ("upgrade-configure",
                    ["/usr/bin/dpkg", "--debug=2", "--no-triggers", "--configure", L.PACKAGE]))
                self.assertEqual(kwargs["policy"], {})
                self.assertEqual(kwargs["endpoint"], 109.5)
                if case == "configure-error":
                    raise RuntimeError("inert configure failure")
                return subprocess.CompletedProcess(argv, 0, L.PUBLISHED, b"")
            def release(*args):
                events.append("release")
                if case == "release-error":
                    raise RuntimeError("inert release failure")
            def retain(name, raw):
                events.append("retain-" + name)
            with self.subTest(case=case), patch.multiple(L, _ROOT=Path("/inert-root"), _END=1000.0, _FAILED=False, _COMMANDS=[]), \
                 patch.object(L.time, "monotonic", return_value=100.0), patch.object(L, "dpkg_policy", return_value={}), \
                 patch.object(L, "_installed_loader_check"), patch.object(L, "_overlap_controls", return_value={"readyIdentity": [1, 2, 3, 0, 1001, 1]}), \
                 patch.object(L.threading, "Thread", Original), patch.object(L, "_overlap_ready", side_effect=ready), \
                 patch.object(L, "package_command", side_effect=configure), patch.object(L, "script_trace", return_value=[]), \
                 patch.object(L, "_overlap_release", side_effect=release), patch.object(L, "_retain", side_effect=retain):
                if case == "complete":
                    observed, _ = L._installed_overlap(value, {}, {}, expected)
                    self.assertTrue(observed["libtestPassed"])
                    self.assertFalse(L._FAILED)
                else:
                    with self.assertRaises((ValueError, RuntimeError)):
                        L._installed_overlap(value, {}, {}, expected)
                    self.assertTrue(L._FAILED)
                self.assertEqual(len(originals), 1)
                self.assertFalse(originals[0].assert_daemon)
                self.assertEqual(events.count("start"), 1)
                self.assertEqual(events.count("join"), 1)
                self.assertTrue(all(events.index("join") < index for index, event in enumerate(events) if event.startswith("retain-")))
                if case in {"start-error", "ready-error", "configure-error"}:
                    self.assertNotIn("release", events)

    def test_failed_original_client_forbids_any_root_result_read(self):
        for code in (1, True, None):
            client = subprocess.CompletedProcess(["/inert-client"], code, b"", b"")
            with self.subTest(code=code), patch.object(L, "handoff") as handoff, patch.object(L, "read") as read, \
                 patch.object(L, "directory") as directory, self.assertRaises(ValueError):
                L.verify_service_result(Path("/inert"), "a" * 64, "b" * 64, client, Path("/inert-public"))
            handoff.assert_not_called()
            read.assert_not_called()
            directory.assert_not_called()

    def test_service_lifetime_reserves_cleanup_without_renewing_work(self):
        first = L.service_properties(1300, now=100)
        later = L.service_properties(1300, now=200)
        self.assertEqual(first["RuntimeMaxSec"], "1160s")
        self.assertEqual(later["RuntimeMaxSec"], "1060s")
        self.assertEqual(L.service_properties(141, now=100)["RuntimeMaxSec"], "1s")
        for deadline in (99, 100, 140, 140.99, 1301, float("inf"), float("nan"), True):
            with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                L.service_properties(deadline, now=100)
        # A package must be observed in the real installed namespace, not in a
        # private filesystem view that could make a false positive look safe.
        self.assertTrue({"PrivateMounts", "PrivateTmp", "PrivateUsers", "PrivateNetwork",
                         "ProtectControlGroups"}.isdisjoint(first))
        self.assertEqual(first["KillMode"], "control-group")
        self.assertEqual(first["ExitType"], "cgroup")
        self.assertEqual(first["Restart"], "no")

    def test_namespace_keys_survive_reopen_but_original_checks_stay_exact(self):
        expected = {"user": [7, 0xeffffffd], "pid": [7, 0xeffffffc], "mnt": [7, 45]}
        for case in ("root", "reopened", "device", "inode", "drift", "owner", "type", "close"):
            roles = [(0xeffffffd, 0x10000000), (0xeffffffc, 0x20000000), (46 if case == "inode" else 45, 0x00020000)]
            if case == "root": roles.append(roles[-1])
            rows, calls = {}, {}
            for fd, (inode, _) in enumerate(roles, 10):
                item = needrestart_stat(stat.S_IFREG | 0o444, ino=inode, uid=1 if case == "owner" else 0)
                item.st_dev = 8 if case == "device" else 7
                item.st_mtime_ns = item.st_ctime_ns = 10 if case == "root" else 20
                rows[fd], calls[fd] = item, 0
            def fstat(fd):
                calls[fd] += 1
                item = SimpleNamespace(**vars(rows[fd]))
                if case == "drift" and calls[fd] > 1: item.st_ctime_ns += 1
                return item
            def close(fd):
                if case == "close" and fd == 12: raise OSError("original close refused")
            with self.subTest(case=case), patch.object(L.os, "open", side_effect=range(10, 10 + len(roles))) as opened, \
                    patch.object(L.os, "fstat", side_effect=fstat), patch.object(L.os, "close", side_effect=close) as closed, \
                    patch.object(L.fcntl, "ioctl", side_effect=lambda fd, _: roles[fd - 10][1] ^ (1 if case == "type" else 0)), \
                    patch.object(L, "_kernel", return_value="0 0 4294967295\n"):
                if case in {"drift", "owner", "type", "close"}:
                    with self.assertRaises(ValueError): L._namespaces(case == "root")
                else:
                    actual = L._namespaces(case == "root")
                    self.assertEqual(actual, L.decode(L.canonical(actual)))
                    if case in {"root", "reopened"}: self.assertEqual(actual, expected)
                    else: self.assertNotEqual(actual, expected)
                self.assertEqual([call.args[0] for call in closed.call_args_list],
                                 list(reversed(range(10, 10 + opened.call_count))))

    def test_observer_namespace_and_deadline_gates_precede_tree_observation(self):
        namespaces = {"user": [7, 0xeffffffd], "pid": [7, 0xeffffffc], "mnt": [7, 45]}
        start = {"unit": {"Id": "mrk-ubuntu-native-10-1.service"}, "runnerUid": 1001, "runnerGid": 1001,
                 "namespaces": namespaces, "deadline": 120}
        status = {"Uid": "1001 1001 1001 1001", "Gid": "1001 1001 1001 1001", "NoNewPrivs": "1",
                  **{name: "0" for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}}
        for case in ("admitted", "changed", "expired"):
            actual = {**namespaces, "mnt": [7, 46]} if case == "changed" else namespaces
            boundary = RuntimeError("inert first absence observation")
            with self.subTest(case=case), patch.object(L, "__file__", "/var/lib/mrk-ubuntu-native-10-1/entry.py"), \
                    patch.object(L, "directory"), patch.object(L, "read", return_value=L.canonical(start)), \
                    patch.object(L, "_modules"), patch.object(L, "_status", return_value=status), \
                    patch.object(L.os, "getresuid", return_value=(1001,) * 3), \
                    patch.object(L.os, "getresgid", return_value=(1001,) * 3), patch.object(L.os, "getgroups", return_value=[]), \
                    patch.object(L, "_namespaces", return_value=actual) as observed, \
                    patch.object(L.time, "monotonic", return_value=121 if case == "expired" else 100) as clock, \
                    patch.object(L, "_absent", side_effect=boundary) as absent, patch.object(L, "_tree") as tree:
                if case == "admitted":
                    with self.assertRaises(RuntimeError) as stopped: L.observe("unpacked")
                    self.assertIs(stopped.exception, boundary)
                    absent.assert_called_once_with(L.PREFIX / (".publish-" + L.M))
                else:
                    message = "Observer namespace identity differs" if case == "changed" else "Observer original endpoint expired"
                    with self.assertRaisesRegex(ValueError, message): L.observe("unpacked")
                    absent.assert_not_called()
                observed.assert_called_once_with(False)
                self.assertEqual(clock.call_count, 0 if case == "changed" else 1)
                tree.assert_not_called()

    def test_native_failure_diagnostic_uses_only_original_bounded_capture(self):
        argv = ["/inert-native-fixture-never-executed"]
        raw = b'\0\x1b\xff"' + b"a" * 1500
        prefix = "Fixture command failure DATA: "
        for case in ("root-failed", "user-failed", "observer-failed", "late", "success", "other-command",
                     "unlisted-observer", "owner-error", "malformed", "sink-error"):
            label = {"user-failed": "native-user", "observer-failed": "observe-unpacked",
                     "other-command": "unpack", "unlisted-observer": "observe-unknown"}.get(case, "native-root")
            result = subprocess.CompletedProcess(argv, 0 if case in {"late", "success"} else 7, raw, raw[::-1])
            if case == "malformed": result.stdout = "not an admitted byte capture"
            owner_error, sink_error = RuntimeError("original owner refused"), OSError("diagnostic writer refused")
            owner = Mock(return_value=result, side_effect=owner_error if case == "owner-error" else None)
            emitted = []
            def write(text):
                self.assertTrue(L._FAILED, "Diagnostic emission cleared the failure latch")
                emitted.append(text)
                if case == "sink-error": raise sink_error
                return len(text)
            with self.subTest(case=case), patch.multiple(L, _END=120, _FAILED=False, _COMMANDS=[],
                    _OWNER=SimpleNamespace(run_owned=owner)), patch.object(L, "_root_ids"), \
                    patch.object(L, "_retain") as retain, patch.object(L.sys, "stderr", SimpleNamespace(write=write)), \
                    patch.object(L.time, "monotonic", side_effect=[100, 121 if case == "late" else 100]) as clock:
                if case == "success":
                    self.assertIs(L.command(label, argv, env={}), result)
                    self.assertFalse(L._FAILED)
                else:
                    with self.assertRaises((ValueError, RuntimeError, OSError)) as refused:
                        L.command(label, argv, env={})
                    if case == "owner-error": self.assertIs(refused.exception, owner_error)
                    if case == "sink-error": self.assertIs(refused.exception, sink_error)
                    self.assertTrue(L._FAILED)
                    observed = list(emitted)
                    with self.assertRaises(ValueError): L.command("must-not-launch", argv, env={})
                    self.assertEqual(emitted, observed)
                owner.assert_called_once()
                self.assertEqual(clock.call_count, 2 if case in {"late", "success"} else 1)
                self.assertEqual(retain.call_count, 0 if case in {"owner-error", "malformed"} else 2)
                if case in {"root-failed", "user-failed", "observer-failed", "late", "sink-error"}:
                    self.assertEqual(len(emitted), 1)
                    text = emitted[0]
                    self.assertTrue(text.startswith(prefix) and text.endswith("\n"))
                    self.assertTrue(all(32 <= ord(char) < 127 for char in text[:-1]))
                    self.assertLess(len(text), 14 * 1024)
                    self.assertEqual(L.decode(text[len(prefix):].encode("ascii")), {
                        "phase": label, "exitCode": result.returncode, "timeoutSeconds": 20,
                        "stdoutBytes": len(raw), "stderrBytes": len(raw),
                        "stdoutPrefix": raw[:1024].decode("utf-8", errors="backslashreplace"),
                        "stderrPrefix": raw[::-1][:1024].decode("utf-8", errors="backslashreplace")})
                else:
                    self.assertEqual(emitted, [])

    def test_mocked_owner_failure_or_late_return_cannot_launch_again(self):
        argv = ["/inert-command-never-executed"]
        for case in ("nonzero", "owner-error", "late", "boolean-exit"):
            result = subprocess.CompletedProcess(argv, 7 if case == "nonzero" else True if case == "boolean-exit" else 0,
                                                 b"synthetic output", b"")
            owner = Mock(return_value=result, side_effect=RuntimeError("synthetic owner loss") if case == "owner-error" else None)
            clock = [100, 121] if case == "late" else [100, 100]
            with self.subTest(case=case), patch.multiple(L, _END=120, _FAILED=False, _COMMANDS=[],
                                                        _OWNER=SimpleNamespace(run_owned=owner)), \
                    patch.object(L, "_root_ids"), patch.object(L, "_retain"), \
                    patch.object(L.time, "monotonic", side_effect=clock):
                with self.assertRaises((ValueError, RuntimeError)):
                    L.command("inert", argv, env={})
                self.assertTrue(L._FAILED)
                with self.assertRaises(ValueError):
                    L.command("must-not-launch", argv, env={})
                self.assertEqual(owner.call_count, 1)

    def test_dpkg_configuration_allows_only_the_reviewed_non_hook_options(self):
        self.assertEqual(L.DPKG_PATH, "/usr/sbin:/usr/bin:/sbin:/bin")
        self.assertEqual(L.config_options(b"# ordinary config\n\nno-debsig\nlog /var/log/dpkg.log\n"),
                         ["no-debsig", "log /var/log/dpkg.log"])
        for raw in (b"pre-invoke=/inert\n", b"post-invoke=/inert\n", b"path-exclude=/usr/share/*\n",
                    b"force-unsafe-io\n", b"force-bad-path\n", b"root=/elsewhere\n",
                    b"admindir=/elsewhere\n", b"log /tmp/foreign\n", b"include /other/config\n", b"no-debsig\0"):
            with self.subTest(config=raw), self.assertRaises(ValueError):
                L.config_options(raw)

    def test_missing_or_other_errors_are_not_write_denial_evidence(self):
        for code in (errno.EACCES, errno.EPERM):
            self.assertEqual(L.denied(OSError(code, "inert error DATA")), code)
        for code in (errno.ENOENT, errno.ENOTDIR, errno.EROFS, errno.EBUSY, errno.EINTR):
            with self.subTest(errno=code), self.assertRaises(ValueError):
                L.denied(OSError(code, "inert error DATA"))
        with self.assertRaises(ValueError):
            L.denied(RuntimeError("not a permission result"))

    def test_invalid_copy_pin_or_source_alias_refuses_before_output(self):
        with tempfile.TemporaryDirectory(prefix="mrk-lifecycle-copy-data-") as name:
            root = Path(name)
            source, target = root / "source-data", root / "not-created"
            source.write_bytes(b"inert source DATA")
            row = {"path": str(source), "size": source.stat().st_size, "sha256": "0" * 64}
            with self.assertRaises(ValueError):
                L.copy_pinned(source, target, row)
            self.assertFalse(target.exists())
            row["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            os.link(source, root / "source-alias")
            with self.assertRaises(ValueError):
                L.copy_pinned(source, target, row)
            self.assertFalse(target.exists())

    def test_finality_requires_original_matching_success_without_resource_denial(self):
        # Synthetic observation DATA only: this proves the decision gate, not
        # actual systemd completion or an operating-system fault injection.
        start = {
            "sourceSha": "a" * 40,
            "entrySha256": "b" * 64,
            "handoffSha256": "c" * 64,
            "invocationId": "d" * 32,
            "deadline": 1300.0,
            "namespaces": {"mnt": "mnt:[1]", "user": "user:[2]"},
            "unit": {
                "Id": "mrk-ubuntu-native-10-1.service",
                "InvocationID": "d" * 32,
                "Result": "success",
                "ControlGroup": "/system.slice/mrk-ubuntu-native-10-1.service",
            },
            "effective": {"KillMode": "control-group", "ExitType": "cgroup"},
            "events": {
                "memory.events": {"max": 0, "oom": 0, "oom_kill": 0},
                "pids.events": {"max": 0},
            },
        }
        stop = {**deepcopy(start), "completion": {
            "SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0",
        }}
        L.verify_finality(start, stop, 0)
        for code in (True, False, 1, -1, None):
            with self.subTest(client=code), self.assertRaises(ValueError):
                L.verify_finality(start, stop, code)
        for key, changed in (
            ("sourceSha", "f" * 40), ("entrySha256", "f" * 64),
            ("handoffSha256", "f" * 64), ("invocationId", "f" * 32),
            ("deadline", 1301.0), ("deadline", 1300),
            ("namespaces", {}), ("unit", {}), ("effective", {}),
            ("completion", {"SERVICE_RESULT": "timeout", "EXIT_CODE": "killed", "EXIT_STATUS": "TERM"}),
        ):
            altered = {**deepcopy(stop), key: changed}
            with self.subTest(field=key, value=changed), self.assertRaises(ValueError):
                L.verify_finality(start, altered, 0)
        for side in ("start", "stop"):
            for counter, key in (("memory.events", "oom_kill"), ("memory.events", "max"), ("pids.events", "max")):
                first, last = deepcopy(start), deepcopy(stop)
                (first if side == "start" else last)["events"][counter][key] = 1
                with self.subTest(side=side, counter=counter, key=key), self.assertRaises(ValueError):
                    L.verify_finality(first, last, 0)


def project_draft_receipt():
    """Expected typed schema DATA, not a native observation or original owner."""
    return {
        "schemaVersion": 1, "fixture": "android-static-v1", "projectGateContract": True,
        "methods": "eight-passive", "mutationActions": False,
        "cancel": {"operation": 1, "widget": "cancel", "guiSettled": True, "originalsSettled": True, "registered": False},
        "select": {"operation": 2, "widget": "select", "filenameRead": True, "guiSettled": True, "originalsSettled": True, "registered": True},
        "snapshot": {"config": "missing", "androidHint": True, "sourceFiles": 1},
        "suggestion": {"coreProvenance": True, "explicitAdoption": True},
        "field": {"path": "version.source", "catalogHelp": True, "explicitUnset": True},
        "validation": {"valid": False, "issue": "config.invalid"},
        "review": {"kind": "redacted", "required": True, "present": False},
        "draft": {"unsaved": True, "saveAvailable": False},
        "guidance": {
            "draftFormatValid": True, "draftUnchanged": True,
            "requirements": {"requestMatched": True, "resultMatched": True, "domMatched": True,
                             "context": "android/build", "roles": 3, "presence": "unknown", "version": "unknown",
                             "inspection": "not-run", "nativeInspection": "unavailable", "dependencies": "unknown"},
            "github": {"requestMatched": True, "resultMatched": True, "domMatched": True, "explicitInputs": True,
                       "browserEdit": "insertText", "comparison": "not-supplied", "snapshotProvided": False,
                       "workflowCount": 4, "workflowContentMatched": True, "resourceMatched": True,
                       "tooling": "format-only", "githubContacted": False, "repositoryObserved": False,
                       "toolingRefResolved": False, "templateCompatibility": "unknown", "applyAvailable": False},
            "assuranceActions": False, "releaseReadiness": "unknown",
        },
        "quit": {"operation": 3, "originalsSettled": True, "relayJoined": True, "exit": True},
    }


def positive_capture(receipt=None):
    return (b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n"
            + L.SHELL_PROJECT_MARKER + L.canonical(project_draft_receipt() if receipt is None else receipt)
            + b"MRK_INSTALLED_SHELL_OBSERVATION=positive-verified\n",
            b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n")


def project_fixture_data(value):
    source = (b'plugins { id("com.android.application") }\n'
              b'android { defaultConfig { applicationId = "org.example.mrk.observed" } }\n')
    return {"schemaVersion": 1, "fixture": "android-static-v1", "root": str(L.root_path(value) / "positive-project"),
            "entries": [
                {"path": ".", "kind": "directory", "identity": [1, 100, stat.S_IFDIR | 0o555, 0, 0, 3, 4096, 11, 11], "children": ["app"]},
                {"path": "app", "kind": "directory", "identity": [1, 101, stat.S_IFDIR | 0o555, 0, 0, 2, 4096, 11, 11], "children": ["build.gradle.kts"]},
                {"path": "app/build.gradle.kts", "kind": "file", "identity": [1, 102, stat.S_IFREG | 0o444, 0, 0, 1, len(source), 11, 11],
                 "size": len(source), "sha256": hashlib.sha256(source).hexdigest()},
            ], "absent": [".gitignore", "release/mobile-release.json"]}


def closed_shell_data():
    value, expected = installed_handoff(), map_data()
    value.pop("installed")
    value["shell"] = {"rosterSha256": "a" * 64, "producerAttempt": "1", "artifactId": "7",
                      "acceptedU": {"sourceSha": "b" * 40, "runId": "8", "attempt": "1", "artifactId": "9"}}
    maps = [{"role": role, "path": row["paths"][0], **{key: row[key] for key in ("deviceMajor", "deviceMinor", "inode")}}
            for role, row in sorted(expected.items())]
    captures = {"normal": (b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n", b""),
                "positive": positive_capture(),
                "quit-outstanding": (b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n"
                    + L.CHILD_MARKER.encode() + L.canonical(maps) + b"MRK_INSTALLED_SHELL_OBSERVATION=quit-outstanding-verified\n", b"")}
    cases, files, commands = {}, {}, []
    for case, (stdout, stderr) in captures.items():
        cases[case] = L.shell_result(stdout, stderr, case, 0, expected)
        files["shell-" + case + ".stdout"], files["shell-" + case + ".stderr"] = stdout, stderr
        commands.append({"phase": "shell-" + case, "argv": L.shell_argv(value, case), "exitCode": 0})
    files["shell-cases.json"] = L.canonical(cases)
    fixture = L.canonical(project_fixture_data(value))
    files["shell-positive-project-before.json"] = files["shell-positive-project-after.json"] = fixture
    keys = [{"phase": "key", "exitCode": 0, "stdout": "", "stderr": "",
             "argv": L._drop(value, ["/usr/bin/xdotool", "key", "--clearmodifiers", key])} for key in ("ctrl+q", "alt+o")]
    files["shell-normal-control.json"] = L.canonical({"joined": True, "inputs": 2, "workerGuardState": "RESTORED",
        "workerErrorCount": 0, "errorType": None, "originalDeadline": value["deadline"], "commands": [*keys, *({"phase": "DATA"} for _ in range(9))]})
    files["observe-p0.stdout"] = L.canonical({"published": {"P0": {"DATA": True}}})
    files["published-before-upgrade.txt"] = L.canonical({"P0": {"DATA": True}})
    outcome = {"shellRosterSha256": value["shell"]["rosterSha256"], "shellProducerAttempt": "1", "shellArtifactId": "7",
               "acceptedU": value["shell"]["acceptedU"], "consumerAttempt": value["attempt"],
               "packageLifecycleQualified": False, "shellPackageBuilt": False, "commands": commands}
    return value, outcome, files, expected


class ProjectDraftLifecycleContracts(unittest.TestCase):
    def test_shell_fixture_roster_fits_the_unchanged_root_evidence_cap(self):
        value, _, _, _ = closed_shell_data()
        roster = L.public_files(value)
        self.assertEqual({name for name in roster if name.startswith("shell-positive-project-")},
                         {"shell-positive-project-before.json", "shell-positive-project-after.json"})
        self.assertEqual(len(roster), 74)
        self.assertLessEqual(len(roster), 128)
        for case in ("positive", "refuse-writable", "refuse-pth"):
            self.assertFalse(any(name.startswith("shell-positive-project-") for name in L.public_files(installed_handoff(case))))

    def test_positive_typed_schema_rejects_each_missing_or_changed_leaf(self):
        expected = project_draft_receipt()
        raw = L.canonical(expected)
        self.assertLessEqual(len(raw), 2048)
        self.assertEqual(L.shell_project_receipt(raw), expected)
        value, outcome, files, mappings = closed_shell_data()

        def leaves(value, prefix=()):
            for key, child in value.items():
                if type(child) is dict:
                    yield from leaves(child, (*prefix, key))
                else:
                    yield (*prefix, key), child

        for path, original in leaves(expected):
            for mode in ("missing", "changed", "wrong-type"):
                changed = deepcopy(expected)
                parent = changed
                for key in path[:-1]:
                    parent = parent[key]
                if mode == "missing":
                    del parent[path[-1]]
                elif mode == "wrong-type":
                    parent[path[-1]] = int(original) if type(original) is bool else True if type(original) is int else None
                else:
                    parent[path[-1]] = not original if type(original) is bool else original + 1 if type(original) is int else original + "-other"
                with self.subTest(path=path, mode=mode):
                    with self.assertRaises(ValueError):
                        L.shell_project_receipt(L.canonical(changed))
                    with self.assertRaises(ValueError):
                        L.shell_result(*positive_capture(changed), "positive", 0, mappings)
                    # A genuine capture cannot authenticate a changed closed
                    # copy, including Python-equal boolean/integer leaves.
                    altered = deepcopy(files)
                    cases = L.decode(altered["shell-cases.json"])
                    cases["positive"]["projectDraft"] = changed
                    altered["shell-cases.json"] = L.canonical(cases)
                    with patch.object(L, "shell_closed_loader", return_value=mappings), self.assertRaises(ValueError):
                        L.shell_closed_result(value, outcome, altered)
        legacy = deepcopy(expected)
        legacy.pop("guidance")
        legacy["methods"] = "six-passive"
        for changed in (b"", b"{}", L.canonical(legacy), L.canonical({**expected, "methods": "six-passive"}),
                        L.canonical({key: child for key, child in expected.items() if key != "guidance"}),
                        L.canonical({**expected, "guidance": {}}), L.canonical({**expected, "guidance": []}),
                        L.canonical({**expected, "guidance": {**expected["guidance"], "untrustedSuccess": True}}),
                        raw.replace(b'"valid":false', b'"valid":false,"valid":false'),
                        raw.replace(b'"guidance":{', b'"guidance":{},"guidance":{'),
                        L.canonical({**expected, "message": "ConfigurationError text is not a receipt field"}), raw + b" " * 2048):
            with self.subTest(raw=changed), self.assertRaises(ValueError):
                L.shell_project_receipt(changed)

    def test_positive_completion_is_last_on_original_stdout_not_inferred_from_zero(self):
        stdout, stderr = positive_capture()
        parsed = L.shell_result(stdout, stderr, "positive", 0, map_data())
        self.assertEqual(parsed["projectDraft"], project_draft_receipt())
        lines = stdout.splitlines(keepends=True)
        for out, err in ((stdout, b""), (b"", stderr), (stderr, stdout), (stdout + lines[-1], stderr),
                         (b"".join([lines[-1], *lines[:-1]]), stderr), (b"".join([lines[1], lines[0], lines[2]]), stderr),
                         (b"".join([lines[0], lines[2], lines[1]]), stderr), (stdout + lines[1], stderr),
                         (lines[0] + lines[1] + lines[1] + lines[-1], stderr),
                         (lines[0] + lines[-1], stderr), (lines[0] + lines[-1], stderr + lines[1]),
                         (stdout, stderr + lines[1]), (stdout, stderr + stderr),
                         (stdout, stderr.replace(b"=available", b"=unavailable"))):
            with self.subTest(stdout=out, stderr=err), self.assertRaises(ValueError):
                L.shell_result(out, err, "positive", 0, map_data())
        for code in (True, False, 1, -1, None):
            with self.subTest(code=code), self.assertRaises(ValueError):
                L.shell_result(stdout, stderr, "positive", code, map_data())
        for case in ("normal", "quit-outstanding"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                L.shell_result(stdout, stderr, case, 0, map_data())

    def test_fixture_inventory_is_exact_immutable_inert_and_has_no_config_or_ignore(self):
        value = installed_handoff()
        original = project_fixture_data(value)
        raw = L.canonical(original)
        result = L.shell_project_fixture(value, raw, raw)
        self.assertEqual(result, {"fixture": "android-static-v1", "unchanged": True, "configAbsent": True, "gitignoreAbsent": True,
            "entryCount": 3, "sourceBytes": original["entries"][2]["size"], "inventoryBytes": len(raw), "inventorySha256": hashlib.sha256(raw).hexdigest()})
        mutations = (
            lambda v: v.update(schemaVersion=True), lambda v: v.update(root="/other/project"),
            lambda v: v.update(absent=[".gitignore"]), lambda v: v["entries"].append(deepcopy(v["entries"][2])),
            lambda v: v["entries"][0].update(children=["app", "release"]),
            lambda v: v["entries"][0].update(children=[".github", "app"]),
            lambda v: v["entries"][1].update(children=["build.gradle.kts", ".gitignore"]),
            lambda v: v["entries"][2].update(path="app/../build.gradle.kts"),
            lambda v: v["entries"][2].update(sha256="0" * 64), lambda v: v["entries"][2].update(size=True),
            lambda v: v["entries"][2]["identity"].__setitem__(2, stat.S_IFLNK | 0o444),
            lambda v: v["entries"][2]["identity"].__setitem__(2, stat.S_IFREG | 0o555),
            lambda v: v["entries"][2]["identity"].__setitem__(2, stat.S_IFREG | 0o666),
            lambda v: v["entries"][2]["identity"].__setitem__(3, 1000),
            lambda v: v["entries"][2]["identity"].__setitem__(5, 2),
            lambda v: v["entries"][2]["identity"].__setitem__(1, True),
        )
        for mutate in mutations:
            changed = deepcopy(original); mutate(changed); encoded = L.canonical(changed)
            with self.subTest(mutate=mutate):
                with self.assertRaises(ValueError):
                    L.shell_project_fixture(value, raw, encoded)
                with self.assertRaises(ValueError):
                    L.shell_project_fixture(value, encoded, encoded)
        changed = deepcopy(original); changed["entries"][2]["identity"][8] += 1
        with self.assertRaises(ValueError):
            L.shell_project_fixture(value, raw, L.canonical(changed))
        for encoded in (b"{}", b"[]", json.dumps(original, indent=2).encode(), raw + b" " * 8192):
            with self.assertRaises(ValueError):
                L.shell_project_fixture(value, encoded, encoded)

    def test_prepare_creates_only_one_positive_fixture_without_running_anything(self):
        value = installed_handoff(); root = L.root_path(value)
        for case in L.SHELL_CASES:
            writer = Mock()
            with self.subTest(case=case), patch.object(L, "_ROOT", root), patch.object(L, "_D", SimpleNamespace(write=writer)), \
                 patch.object(Path, "mkdir") as mkdir, patch.object(L.os, "chown"), patch.object(L.os, "chmod") as chmod, \
                 patch.object(L, "_absent"), patch.object(L, "_retain") as retain, \
                 patch.object(L, "_shell_project_inventory", return_value=project_fixture_data(value)) as inventory:
                L._shell_prepare(value, case)
                fixture_writes = [call for call in writer.call_args_list if call.args[0] == root / "positive-project/app/build.gradle.kts"]
                self.assertEqual(len(fixture_writes), int(case == "positive"))
                self.assertEqual(mkdir.call_count, 10 if case == "positive" else 8)
                if case == "positive":
                    self.assertEqual(fixture_writes[0].args[1:], (L.SHELL_PROJECT_SOURCE, 0o444))
                    self.assertEqual([call.args for call in chmod.call_args_list], [(root / "positive-project/app", 0o555), (root / "positive-project", 0o555)])
                    inventory.assert_called_once_with(value)
                    retain.assert_called_once_with("shell-positive-project-before.json", L.canonical(project_fixture_data(value)))
                else:
                    inventory.assert_not_called(); retain.assert_not_called(); chmod.assert_not_called()

    def test_closed_case_requires_native_receipt_and_same_before_after_originals(self):
        value, outcome, files, expected = closed_shell_data()
        with patch.object(L, "shell_closed_loader", return_value=expected):
            result = L.shell_closed_result(value, outcome, files)
        self.assertEqual(result["projectDraft"]["native"], project_draft_receipt())
        self.assertTrue(result["projectDraft"]["fixture"]["unchanged"])
        self.assertEqual(result["cases"]["normal"]["domAndGtkObserved"], False)
        self.assertEqual(len(result["cases"]["quit-outstanding"]["maps"]), 1)
        for change in ("missing-before", "missing-after", "different-after", "coerced-case", "missing-receipt", "wrong-argv"):
            changed, current = deepcopy(files), deepcopy(outcome)
            if change.startswith("missing-") and change != "missing-receipt":
                changed.pop("shell-positive-project-" + change.removeprefix("missing-") + ".json")
            elif change == "different-after":
                altered = L.decode(changed["shell-positive-project-after.json"]); altered["entries"][0]["identity"][1] += 1
                changed["shell-positive-project-after.json"] = L.canonical(altered)
            elif change == "coerced-case":
                altered = L.decode(changed["shell-cases.json"]); altered["positive"]["projectDraft"]["select"]["originalsSettled"] = 1
                changed["shell-cases.json"] = L.canonical(altered)
            elif change == "missing-receipt":
                changed["shell-positive.stdout"] = b"MRK_INSTALLED_SHELL_OBSERVATION=positive-verified\n"
            else:
                current["commands"][1]["argv"][-1] = "quit-outstanding"
            with self.subTest(change=change), patch.object(L, "shell_closed_loader", return_value=expected), self.assertRaises((ValueError, KeyError)):
                L.shell_closed_result(value, current, changed)


if __name__ == "__main__":
    unittest.main()
