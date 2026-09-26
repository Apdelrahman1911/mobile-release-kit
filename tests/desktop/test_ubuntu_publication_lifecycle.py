"""Inert lifecycle policy tests; never start a service, child or package tool."""
from copy import deepcopy
from itertools import permutations
import ast
import errno
import hashlib
import importlib.util
import io
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


def resource_observation(phase="main-failure-before-join", *, unavailable=False):
    return {"scope": "original-service-resource-observation-only", "phase": phase,
            "bindingMatched": not unavailable, "pidsMax": None if unavailable else 64,
            "pidsCurrent": None if unavailable else 62, "pidsEventsMax": None if unavailable else 1,
            "memoryEvents": None if unavailable else {"max": 0, "oom": 0, "oom_kill": 0},
            "unavailable": ["binding"] if unavailable else []}


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


def shell_loader_data(*, compact=True):
    """Inert closed-observation DATA, not native execution or host receipts."""
    value = installed_handoff()
    value.pop("installed")
    libraries, bindings, os_files = {}, {}, {}

    def file(path, inode, mode=0o644):
        return {"path": path, "selectedPath": path, "size": 4, "sha256": "a" * 64, "links": [], "ancestry": {},
                "identity": [os.makedev(8, 2), inode, stat.S_IFREG | mode, 1, 4, 0, 0]}

    def executable(row, *, script=False):
        portable = {key: row[key] for key in ("path", "selectedPath", "size", "sha256")}
        return {"file": {**portable, "mode": stat.S_IMODE(row["identity"][2]), "identity": list(row["identity"])},
                "package": "libc6", **({"interpreter": "/bin/sh"} if script else {"elf": {"needed": []}})}

    def compiled(rows):
        return {name: {**deepcopy(row), "file": {key: part for key, part in row["file"].items() if key != "identity"}}
                for name, row in rows.items()}

    names = sorted({"libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2", *L.PRIVATE_SONAMES, "libpxbackend-1.0.so"})
    for index, name in enumerate(names):
        path = "/usr/lib/x86_64-linux-gnu/" + ("libproxy/" if name == "libpxbackend-1.0.so" else "") + name
        row = file(path, index + 1)
        libraries[name] = executable(row)
        bindings[path] = os_files[path] = row
    tiers = {directory + "/glibc-hwcaps/" + tier: False for directory in L.DEFAULT_LIBRARY_DIRS for tier in L.HWCAPS}
    for path in tiers:
        bindings[path] = {"absent": True}
    globals_ = sorted(name for name in names if name != "libpxbackend-1.0.so")
    for name in globals_:
        for directory in L.DEFAULT_LIBRARY_DIRS:
            path = directory + "/" + name
            bindings[path] = ({**os_files[libraries[name]["file"]["selectedPath"]], "selectedPath": path}
                              if directory in L.DEFAULT_LIBRARY_DIRS[:2] else {"absent": True})
    alias = "/lib64/ld-linux-x86-64.so.2"
    bindings[alias] = os_files[alias] = {**os_files[libraries["ld-linux-x86-64.so.2"]["file"]["selectedPath"]], "selectedPath": alias}
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
    programs, modules, scripts = {}, {}, {}
    for index, (path, rows, script) in enumerate((("/usr/bin/inert-tool", programs, False),
            (module_root + "/libinert.so", modules, False), ("/usr/bin/inert-wrapper", scripts, True))):
        row = file(path, 40 + index, 0o755)
        os_files[path] = bindings[path] = row
        rows[path] = executable(row, script=script)
    packages = {"libc6": {"binaryPackage": "libc6:amd64", "version": "2.39-0ubuntu8.8"}}
    graph = {"manifestSha256": L.M, "protocolSha256": L.Q, "outputs": {"normal": {}, "observer": {}},
             "moduleRoots": {module_root: {"present": True, "modules": ["libinert.so"]}},
             "sharedObjects": compiled(libraries), "programs": compiled(programs), "scripts": compiled(scripts),
             "modules": compiled(modules), "osPackages": deepcopy(packages),
             "osFiles": {path: {**{key: row[key] for key in ("path", "selectedPath", "size", "sha256")},
                                "mode": stat.S_IMODE(row["identity"][2])} for path, row in os_files.items()},
             "privateSearch": search, "runtime": {},
             "runtimeObjects": sorted(L.PRIVATE_SONAMES | {"libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2"})}
    policy = {"osNames": names, "libraries": libraries, "programs": programs, "modules": modules, "scripts": scripts,
              "packages": packages, "osFiles": os_files, "loader": os_files[alias],
              "ldconfig": file("/usr/sbin/ldconfig.real", 50, 0o755), "cache": file("/etc/ld.so.cache", 51),
              "moduleRoots": roots, "runtimeData": {**summary, "records": [
                  {**row, "path": "shell-consumer-data-" + str(index) + ".json"} for index, row in enumerate(records)]},
              "graph": graph, "externalPrerequisites": "inert DATA fixture"}
    value["shell"] = {"loaderPolicy": policy, "binaries": {"normal": {}, "observer": {}}}
    value["compilerRecords"]["nativeInputs"] = {"outputs": {"libtest": {"objects": names}}, "sharedObjects": compiled(libraries)}
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
            graph["runtime"][relative] = {"file": row, "elf": {
                "soname": None if role == "python" else role, "runpath": "$ORIGIN/../lib" if role == "python" else "$ORIGIN"}}
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
    raw = L.canonical(graph)
    value["shell"]["compiler"] = {"nativeRecord": {"path": "shell-native.json", "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}}
    if compact:
        value["shell"]["loaderPolicy"] = L.compact_shell_loader_policy(policy, value["shell"]["compiler"])
    return value, files, expected


class GuardedXattrDiagnostics(unittest.TestCase):
    """Mock the sole xattr observation; diagnostics may not inspect another path."""

    def test_guarded_roster_keeps_enodata_only_absence_and_stops_at_presence(self):
        access = "system.posix_acl_access"
        for directory, other in ((True, "system.posix_acl_default"), (False, "security.capability")):
            path = Path("/usr/share/fonts" if directory else "/usr/share/fonts/inert.ttf")
            with self.subTest(directory=directory), \
                 patch.object(L.os, "getxattr", side_effect=OSError(errno.ENODATA, "mock absent")) as query:
                self.assertIsNone(L._xattrs(path, directory))
                self.assertEqual([call.args for call in query.call_args_list], [(path, access), (path, other)])
                self.assertTrue(all(call.kwargs == {"follow_symlinks": False} for call in query.call_args_list))
            for forbidden in (access, other):
                for value in (b"", b"never-export-this-attribute-value"):
                    def observed(_path, name, *, follow_symlinks):
                        self.assertIs(follow_symlinks, False)
                        if name == forbidden:
                            return value
                        raise OSError(errno.ENODATA, "mock absent")

                    with self.subTest(directory=directory, attribute=forbidden, empty=not value), \
                         patch.object(L.os, "getxattr", side_effect=observed) as query, self.assertRaises(L.Refused) as refused:
                        L._xattrs(path, directory)
                    message = str(refused.exception)
                    self.assertIn("attribute=" + forbidden + " result=present errno=none", message)
                    self.assertEqual([call.args[1] for call in query.call_args_list],
                                     [access] if forbidden == access else [access, other])
                    self.assertNotIn("never-export-this", message)

    def test_unknown_xattr_errno_is_a_typed_refusal_not_absence(self):
        for number in (errno.EACCES, errno.EPERM, errno.EOPNOTSUPP, errno.ENOSYS, errno.EBADF,
                       errno.ENOENT, errno.EIO, None, -1, 4096):
            with self.subTest(errno=number), \
                 patch.object(L.os, "getxattr", side_effect=OSError(number, "private-error-marker")) as query, \
                 self.assertRaises(L.Refused) as refused:
                L._xattrs(Path("/usr/share/fonts"), True)
            message = str(refused.exception)
            expected = str(number) if type(number) is int and 0 <= number <= 4095 else "unknown"
            self.assertIn("attribute=system.posix_acl_access result=errno errno=" + expected, message)
            self.assertEqual(query.call_count, 1)
            self.assertNotIn("private-error-marker", message)
            self.assertLessEqual(len(message.encode("ascii")), 512)

    def test_xattr_diagnostic_bounds_and_redacts_without_new_filesystem_observations(self):
        cases = (("/usr/share/fonts/inert.ttf", False, False), ("/usr/share/" + "a" * 300, False, True),
                 ("/home/private-path-marker/key", True, False), ("/usr/sharex/private-path-marker", True, False),
                 ("/opt/private-path-marker", True, False),
                 (str(L.PREFIX) + "/manifest.json", False, False),
                 (str(L.PREFIX.parent) + "/other-target/private-path-marker", True, False),
                 ("/usr/share/fonts/../private-path-marker", True, False),
                 ("/usr/share/fonts/private-path-marker\nforged", True, False))
        for path, redacted, truncated in cases:
            with self.subTest(path=path), \
                 patch.object(L.os, "getxattr", return_value=b"private-value-marker\nforged") as query, \
                 patch.object(L.os, "open", side_effect=AssertionError("diagnostic reopened a file")), \
                 patch.object(L.os, "listxattr", side_effect=AssertionError("diagnostic enumerated attributes")), \
                 patch.object(Path, "lstat", side_effect=AssertionError("diagnostic restatted a file")), \
                 patch.object(Path, "resolve", side_effect=AssertionError("diagnostic resolved a new path")), \
                 self.assertRaises(L.Refused) as refused:
                L._xattrs(path, False)
            message = str(refused.exception)
            self.assertIn("path=" + ("<redacted>" if redacted else path[:256]) + " pathTruncated=" + str(truncated).lower(), message)
            self.assertIn(" kind=non-directory attribute=system.posix_acl_access result=present errno=none", message)
            self.assertNotIn("private-path-marker", message)
            self.assertNotIn("private-value-marker", message)
            self.assertNotIn("\n", message)
            self.assertLessEqual(len(message.encode("ascii")), 512)
            self.assertEqual(query.call_count, 1)


class LifecycleData(unittest.TestCase):
    def test_compact_shell_policy_is_exact_lossless_and_independent_of_wire_inputs(self):
        value, _, _ = shell_loader_data(compact=False)
        full, compiler = value["shell"]["loaderPolicy"], value["shell"]["compiler"]
        original = L.canonical(value)
        compact = L.compact_shell_loader_policy(full, compiler)
        self.assertEqual(set(compact), {"schemaVersion", "graph", "osFiles", "moduleRoots", "runtimeData", "loader",
                                        "ldconfig", "cache", "osNames", "externalPrerequisites"})
        self.assertEqual(compact["schemaVersion"], 1)
        self.assertEqual(L.canonical(value), original)
        graph = L.canonical(compact["graph"])
        self.assertEqual(compiler["nativeRecord"], {"path": "shell-native.json", "size": len(graph), "sha256": hashlib.sha256(graph).hexdigest()})
        wire = L.canonical(compact)
        first = L.expand_shell_loader_policy(compact, compiler)
        second = L.expand_shell_loader_policy(compact, compiler)
        self.assertEqual(L.canonical(first), L.canonical(full))
        first["graph"]["osPackages"]["libc6"]["version"] = "changed view only"
        first["packages"]["libc6"]["version"] = "changed reconstructed copy"
        first["libraries"]["libc.so.6"]["file"]["identity"][1] += 1
        first["osFiles"]["/lib64/ld-linux-x86-64.so.2"]["identity"][1] += 1
        first["moduleRoots"][next(iter(first["moduleRoots"]))]["children"].clear()
        first["runtimeData"]["records"][0]["sha256"] = "f" * 64
        self.assertEqual(L.canonical(compact), wire)
        self.assertEqual(L.canonical(second), L.canonical(full))
        compact["cache"]["identity"][1] += 1
        self.assertEqual(L.canonical(value), original)  # The producer's compact copy is independent too.

    def test_compact_shell_policy_refuses_each_omitted_mismatch_and_legacy_or_malformed_wire(self):
        value, _, _ = shell_loader_data(compact=False)
        full, compiler = value["shell"]["loaderPolicy"], value["shell"]["compiler"]
        compact = L.compact_shell_loader_policy(full, compiler)
        for kind in ("libraries", "programs", "modules", "scripts", "packages"):
            changed = deepcopy(full)
            row = next(iter(changed[kind].values()))
            if kind == "packages":
                row["version"] = "different"
            else:
                row["file"]["size"] = float(row["file"]["size"])  # Python == alone would miss this.
            with self.subTest(omitted=kind), self.assertRaisesRegex(ValueError, "reconstruction differs"):
                L.compact_shell_loader_policy(changed, compiler)
        malformed = [None, {}, deepcopy(full)]
        malformed += [{**compact, "schemaVersion": version} for version in (True, 0, 2, "1", None)]
        malformed += [{key: row for key, row in compact.items() if key != missing} for missing in compact]
        malformed += [{**compact, key: {}} for key in (*L.SHELL_LOADER_OMITTED, "extra")]
        for index, current in enumerate(malformed):
            with self.subTest(shape=index), self.assertRaises(ValueError):
                L.expand_shell_loader_policy(current, compiler)
        for key, changed in (("size", True), ("size", compiler["nativeRecord"]["size"] + 1), ("sha256", "f" * 64)):
            bad = deepcopy(compiler); bad["nativeRecord"][key] = changed
            with self.subTest(binding=key, value=changed), self.assertRaises(ValueError):
                L.expand_shell_loader_policy(compact, bad)
        for change in ("graph", "current-bytes", "current-identity", "generic-identity", "current-roster"):
            bad = deepcopy(compact)
            if change == "graph":
                bad["graph"]["extra"] = "not the original compiler graph"
            elif change == "current-bytes":
                bad["osFiles"]["/lib64/ld-linux-x86-64.so.2"]["sha256"] = "f" * 64
            elif change == "current-identity":
                bad["osFiles"]["/lib64/ld-linux-x86-64.so.2"]["identity"].pop()
            elif change == "generic-identity":
                bad["osFiles"]["/lib64/ld-linux-x86-64.so.2"]["identity"][3:3] = [0, 0]
            else:
                bad["osFiles"].pop("/lib64/ld-linux-x86-64.so.2")
            with self.subTest(change=change), self.assertRaises(ValueError):
                L.expand_shell_loader_policy(bad, compiler)

    def test_compact_shell_consumers_keep_original_inputs_and_do_not_change_installed_policy(self):
        value, files, expected = shell_loader_data()
        original = L.canonical(value)
        with patch.object(L, "_mount_scope", side_effect=RuntimeError("inert stop before native binding")), \
             patch.object(L, "command") as command, self.assertRaisesRegex(RuntimeError, "inert stop"):
            L._shell_loader_start(value, {})
        command.assert_not_called()
        self.assertEqual(L.canonical(value), original)
        entry = L.decode(files["loader-entry.json"])
        final = L.decode(files["loader-final.json"])
        published = {path: deepcopy(row["file"]) for path, row in value["shell"]["loaderPolicy"]["graph"]["runtime"].items()}
        for profile in ("shell", "installed"):
            current = deepcopy(value)
            if profile == "installed":
                shell = current.pop("shell")
                current["installed"] = {"case": "positive", "loaderPolicy": L.expand_shell_loader_policy(shell["loaderPolicy"], shell["compiler"])}
            before = L.canonical(current)
            with self.subTest(profile=profile), patch.object(L, "_tree", return_value=published), \
                 patch.object(L, "_loader_binding", side_effect=lambda path, *a, **kw: deepcopy(final["bindings"].get(str(path), {"absent": True}))), \
                 patch.object(L, "_installed_loader_check"), patch.object(L, "_retain"), \
                 patch.object(L, "expand_shell_loader_policy", wraps=L.expand_shell_loader_policy) as expand:
                self.assertEqual(L._installed_payload(current, deepcopy(entry), published), expected)
                self.assertEqual(expand.call_count, int(profile == "shell"))
            self.assertEqual(L.canonical(current), before)

    def test_shell_closed_loader_reconciles_interval_search_data_and_actual_aliases(self):
        value, files, expected = shell_loader_data()
        original = L.canonical(value)
        self.assertEqual(L.shell_closed_loader(value, files), expected)
        self.assertEqual(L.canonical(value), original)
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

        stdout, stderr = settled_failure_capture()
        labels = L.SHELL_SETTLED_FAILURE_LABELS
        observed = L.shell_result(stdout, stderr, "settled-failure", 1, expected, failure_labels=labels)
        self.assertEqual(observed, {"case": "settled-failure", "exitCode": 1, "bootstrapReturned": True,
            "domAndGtkObserved": True, "maps": [], "qualified": False, "expectedFailureObserved": True,
            "failureHandoff": "original-quit-relay-loop-returned"})
        for code in (0, True, 2, -1):
            with self.subTest(code=code), self.assertRaises(ValueError):
                L.shell_result(stdout, stderr, "settled-failure", code, expected, failure_labels=labels)
        for wrong in (None, b"", labels[:-1], labels.replace(b"=dom", b"=tick"),
                      labels.replace(b"=SettledFailure", b"=ReadCancelled")):
            with self.subTest(labels=wrong), self.assertRaises(ValueError):
                L.shell_result(stdout, stderr, "settled-failure", 1, expected, failure_labels=wrong)
        for wrong_case in ("normal", "positive", "offline-negative"):
            with self.subTest(case=wrong_case), self.assertRaises(ValueError):
                L.shell_result(stdout, stderr, wrong_case, 1, expected, failure_labels=labels)
        for marker in (b"MRK_INSTALLED_SHELL_FAILURE_HANDOFF=original-quit-relay-loop-returned\n",
                       b"MRK_INSTALLED_SHELL_OBSERVATION=failed\n"):
            variants = ((stdout.replace(marker, b""), stderr), (stdout + marker, stderr),
                        (stdout.replace(marker, b"prefixed " + marker), stderr),
                        (stdout.replace(marker, marker.replace(b"\n", b"\r\n")), stderr),
                        (stdout.replace(marker, b"") + marker[:-1], stderr),
                        (stdout.replace(marker, b""), marker))
            for changed in variants:
                with self.subTest(marker=marker, changed=changed), self.assertRaises(ValueError):
                    L.shell_result(*changed, "settled-failure", 1, expected, failure_labels=labels)
        for changed in ((stdout.replace(b"=available", b"=unavailable"), stderr),
                        (stdout.replace(b"=advanced", b"=pending"), stderr),
                        (stdout + b"MRK_INSTALLED_SHELL_OBSERVATION=settled-failure-verified\n", stderr),
                        (stdout + contracts, stderr), (stdout, b"MRK_EXTRA=contradiction\n"),
                        (stdout + b"MRK_EXTRA=truncated", stderr)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                L.shell_result(*changed, "settled-failure", 1, expected, failure_labels=labels)
        with self.assertRaises(ValueError):
            L.shell_result(*positive_capture(), "positive", 0, expected, failure_labels=labels)

    def test_normal_controller_joins_the_original_even_when_start_or_input_fails(self):
        value, expected = installed_handoff(), map_data()
        value.pop("installed")
        value["shell"] = {}
        class ProcessError(RuntimeError):
            def __init__(self, message, *, cleanup_complete=True):
                super().__init__(message)
                self.dispatched, self.contained, self.cleanup_complete = True, True, cleanup_complete
        owner_failures = {"second-search-timeout", "pid-query-timeout", "finish-clock-error"}
        invalid_results = {"malformed-result", "malformed-object"}
        original_failures = owner_failures | invalid_results | {"controller-policy-error"}
        no_log_cases = {"unjoined", "worker-error", "guard-unknown", "missing-result", *original_failures}
        for case in ("complete", "start-return-error", "input-error", "unjoined", "early-return",
                     "controller-deadline", "command-bound", "final-result-failure", "diagnostic-write-error",
                     "log-error", "input-and-log-error", "worker-error", "guard-unknown", "missing-result",
                     "second-search-timeout", "pid-query-timeout", "malformed-result", "malformed-object",
                     "finish-clock-error", "controller-policy-error"):
            events, originals, retained, now, focused = [], [], {}, [100.0], [31]
            clock_calls, searches, fail_clock = [0], [0], [False]
            primary = (ProcessError("owned command exceeded its original deadline") if case in owner_failures else
                       RuntimeError("inert controller failure; context must not be exported"))
            worker_error = ProcessError("owned command protocol or original ownership is incomplete", cleanup_complete=False)
            class Original:
                def __init__(self, **options):
                    originals.append(self)
                    self.joined, self.options = False, options
                    holder, argv, _, seconds = options["args"]
                    holder.update(guardState="RESTORED", errors=[], result=subprocess.CompletedProcess(argv, 0,
                        b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n", b""))
                    if case in ("early-return", "final-result-failure"):
                        holder["result"] = subprocess.CompletedProcess(argv, 127, b"", b"synthetic native startup refusal\n")
                    if case == "worker-error":
                        holder["errors"] = [primary]
                    if case == "guard-unknown":
                        holder["guardState"] = "UNKNOWN"
                    if case == "missing-result":
                        holder.pop("result")
                    if case in original_failures:
                        holder.pop("result")
                        holder.update(errors=[worker_error], shellDiagnostic={"errorOrigins": ["owner"],
                            "ownerCall": {"timeoutSeconds": seconds, "ownerReturned": False,
                                          "startMonotonic": 100.0, "endMonotonic": 160.0}})
                def start(self):
                    events.append("start")
                    if case == "start-return-error":
                        raise RuntimeError("inert start-return loss")
                def join(self, timeout):
                    events.append("join")
                    self.joined = case != "unjoined"
                def is_alive(self):
                    return not self.joined and case != "early-return"
            def clock():
                clock_calls[0] += 1
                if fail_clock[0]:
                    fail_clock[0] = False
                    raise OSError("inert diagnostic finish clock unavailable")
                now[0] += 46.0 if case == "controller-deadline" and clock_calls[0] == 2 else 0.001
                return now[0]
            def sleep(seconds):
                now[0] += seconds
            def owned(argv, **options):
                args = argv[argv.index("/usr/bin/xdotool") + 1:]
                events.append(args[0])
                if case in ("input-error", "diagnostic-write-error", "input-and-log-error"):
                    raise primary
                if case in invalid_results:
                    return object() if case == "malformed-object" else subprocess.CompletedProcess(argv, True, b"", b"")
                if case == "controller-policy-error":
                    return subprocess.CompletedProcess(argv, 2, b"", b"synthetic query refusal\n")
                if ((case in ("second-search-timeout", "finish-clock-error") and searches[0] == 1)
                        or (case == "pid-query-timeout" and args[0] == "getwindowpid")):
                    now[0] += options["timeout"] + 0.25  # Enclosing owner includes its cleanup, not target runtime.
                    fail_clock[0] = case == "finish-clock-error"
                    raise primary
                output = b""
                if args[0] == "search":
                    searches[0] += 1
                    if case in ("second-search-timeout", "finish-clock-error"):
                        return subprocess.CompletedProcess(argv, 1, b"", b"synthetic display not ready\n")
                    if case == "command-bound" and (searches[0] < 50 or args[-1].startswith("^Quit")):
                        return subprocess.CompletedProcess(argv, 1, b"", b"")
                    output = b"32\n" if args[-1].startswith("^Quit") else b"31\n"
                elif args[0] == "getwindowpid":
                    output = b"123\n"
                elif args[0] == "windowfocus":
                    focused[0] = int(args[-1])
                elif args[0] == "getwindowfocus":
                    output = str(focused[0]).encode() + b"\n"
                return subprocess.CompletedProcess(argv, 0, output, b"")
            def log_capture(*args):
                self.assertTrue(originals[0].joined)
                self.assertEqual(args[:3], (value, "normal", "original-log-binding"))
                events.append("log-capture")
                if case in ("log-error", "input-and-log-error"):
                    raise OSError("inert log retention failure")
                return b"inert original display diagnostic\n"
            def resources(observed_value, phase):
                self.assertEqual(observed_value, value)
                self.assertTrue(L._FAILED)
                self.assertEqual(phase, "failure-after-join-attempt" if "join" in events else "main-failure-before-join")
                events.append("resources")
                if case == "input-and-log-error":
                    raise OSError("private resource diagnostic error must not replace the original")
                return resource_observation(phase, unavailable=case == "input-error")
            with self.subTest(case=case), patch.multiple(L, _ROOT=L.root_path(value), _END=value["deadline"],
                    _FAILED=False, _COMMANDS=[], _OWNER=SimpleNamespace(run_owned=owned, ProcessError=ProcessError)), \
                 patch.object(L.threading, "Thread", Original), patch.object(L.time, "monotonic", side_effect=clock), \
                 patch.object(L.time, "sleep", side_effect=sleep), patch.object(L, "_shell_window_pid"), \
                 patch.object(L, "_shell_log_capture", side_effect=log_capture) as log, \
                 patch.object(L, "_shell_resource_diagnostic", side_effect=resources) as resource_read, \
                 patch.object(L, "_retain", side_effect=lambda name, raw: retained.update({name: raw})), \
                 patch.object(L.sys, "stderr", new_callable=io.StringIO) as diagnostic:
                if case == "diagnostic-write-error":
                    diagnostic.write = Mock(side_effect=OSError("synthetic diagnostic output failure"))
                if case == "complete":
                    result = L._shell_normal(value, L.shell_environment(value, "normal"), expected, "original-log-binding")
                    self.assertTrue(result["bootstrapReturned"])
                    control = L.decode(retained["shell-normal-control.json"])
                    self.assertEqual([row["argv"][-1] for row in control["commands"] if row["phase"] == "key"], ["ctrl+q", "alt+o"])
                    self.assertFalse(L._FAILED)
                    self.assertEqual(diagnostic.getvalue(), "")
                else:
                    with self.assertRaises((ValueError, RuntimeError, OSError)) as raised:
                        L._shell_normal(value, L.shell_environment(value, "normal"), expected, "original-log-binding")
                    self.assertTrue(L._FAILED)
                    if case == "diagnostic-write-error":
                        self.assertIs(raised.exception, primary)
                        self.assertEqual(diagnostic.write.call_count, 1)
                    else:
                        lines = diagnostic.getvalue().splitlines()
                        self.assertEqual(len(lines), 1)
                        self.assertTrue(lines[0].startswith("MRK_INSTALLED_SHELL_FAILURE="))
                        observed = json.loads(lines[0].split("=", 1)[1])
                        self.assertFalse(observed["qualified"])
                        self.assertFalse(observed["cleanupEstablished"])
                        if case == "input-and-log-error":
                            self.assertIsNone(observed["resources"])
                        else:
                            self.assertEqual(observed["resources"], resource_observation(
                                resource_read.call_args.args[1], unavailable=case == "input-error"))
                        if case == "early-return":
                            self.assertEqual(observed["stage"], "initial-window")
                            self.assertEqual(observed["capture"]["exitCode"], 127)
                            self.assertEqual(observed["errors"][0]["message"], "Normal original returned before controller command")
                        elif case == "controller-deadline":
                            self.assertEqual(observed["errors"][0]["message"], "Normal window controller endpoint expired")
                            self.assertIsNone(observed["controller"]["lastAttempt"]["ownerCall"])
                            self.assertEqual(observed["controller"]["lastAttempt"]["phase"], "admission")
                        elif case == "command-bound":
                            self.assertEqual(observed["controllerCommands"], 96)
                            self.assertEqual(observed["errors"][0]["message"], "Normal window controller command bound exhausted")
                            self.assertEqual(observed["controller"]["lastAttempt"]["ordinal"], 97)
                        elif case == "final-result-failure":
                            self.assertEqual(observed["stage"], "final-verification")
                            self.assertEqual(observed["capture"]["exitCode"], 127)
                        elif case == "unjoined":
                            self.assertIsNone(observed["capture"])
                            self.assertIsNone(observed["workerGuardState"])
                        elif case in ("input-error", "input-and-log-error", "worker-error"):
                            self.assertIs(raised.exception, primary)
                            self.assertNotIn("context must not be exported", lines[0])
                        elif case in original_failures:
                            self.assertIsNone(observed["capture"])
                            self.assertTrue(observed["joined"])
                            self.assertEqual(observed["workerGuardState"], "RESTORED")
                            self.assertFalse(observed["workerCall"]["ownerReturned"])
                            self.assertEqual(observed["workerCall"]["ownerElapsedSeconds"], 60.0)
                            self.assertEqual(observed["errors"][-1]["origin"], "worker-owner")
                            self.assertFalse(observed["errors"][-1]["originalProcessFacts"]["cleanup_complete"])
                            controller = observed["controller"]
                            attempt, completed = controller["lastAttempt"], controller["lastCompleted"]
                            self.assertEqual(controller["controllerEndpoint"], controller["normalStartMonotonic"] + 45)
                            self.assertEqual(controller["serviceEndpoint"], value["deadline"])
                            self.assertEqual(controller["carrierTimeoutSeconds"], 60)
                            self.assertGreaterEqual(controller["failureMonotonic"], attempt["ownerCall"]["startMonotonic"])
                            self.assertEqual(attempt["stage"], "initial-window")
                            self.assertEqual(attempt["validOriginalResult"], case == "controller-policy-error")
                            self.assertEqual(attempt["ownerCall"]["timeoutSeconds"], 5)
                            if case in owner_failures:
                                self.assertIs(raised.exception, primary)
                                self.assertEqual(observed["controllerCommands"], 1)
                                self.assertEqual(observed["errors"][0]["message"], "owned command exceeded its original deadline")
                                self.assertEqual(observed["errors"][0]["origin"], "main")
                                self.assertTrue(observed["errors"][0]["originalProcessFacts"]["cleanup_complete"])
                                self.assertEqual(attempt["label"], "window-pid" if case == "pid-query-timeout" else "search")
                                self.assertEqual((attempt["ordinal"], completed["ordinal"]), (2, 1))
                                self.assertEqual(attempt["phase"], "owner-call")
                                self.assertFalse(attempt["ownerCall"]["ownerReturned"])
                                if case == "finish-clock-error":
                                    self.assertIsNone(attempt["ownerCall"]["endMonotonic"])
                                    self.assertIsNone(attempt["ownerCall"]["ownerElapsedSeconds"])
                                else:
                                    self.assertGreater(attempt["ownerCall"]["ownerElapsedSeconds"], 5.25)
                                self.assertEqual((completed["label"], completed["stage"]), ("search", "initial-window"))
                                self.assertTrue(completed["ownerCall"]["ownerReturned"])
                                self.assertGreater(completed["ownerCall"]["ownerElapsedSeconds"], 0)
                                self.assertEqual(completed["capture"]["exitCode"], int(case != "pid-query-timeout"))
                                stdout = b"31\n" if case == "pid-query-timeout" else b""
                                stderr = b"" if case == "pid-query-timeout" else b"synthetic display not ready\n"
                                for name, raw in (("stdout", stdout), ("stderr", stderr)):
                                    self.assertEqual(completed["capture"][name]["sha256"], hashlib.sha256(raw).hexdigest())
                                    self.assertEqual(completed["capture"][name]["size"], len(raw))
                                    self.assertEqual(completed["capture"][name]["head"], raw.decode())
                            elif case == "controller-policy-error":
                                self.assertEqual(observed["controllerCommands"], 1)
                                self.assertEqual(attempt["phase"], "policy")
                                self.assertEqual((attempt["ordinal"], completed["ordinal"]), (1, 1))
                                self.assertTrue(attempt["ownerCall"]["ownerReturned"])
                                self.assertEqual(completed["capture"]["exitCode"], 2)
                            else:
                                self.assertEqual(observed["controllerCommands"], 0)
                                self.assertIsNone(completed)
                                self.assertEqual(attempt["ordinal"], 1)
                                self.assertEqual(attempt["phase"], "result-validation")
                                self.assertTrue(attempt["ownerCall"]["ownerReturned"])
                        if case not in no_log_cases | {"log-error", "input-and-log-error"}:
                            self.assertEqual(observed["capture"]["display"]["head"], "inert original display diagnostic\n")
                self.assertEqual(len(originals), 1)
                self.assertEqual(originals[0].options["kwargs"], {"shell_diagnostic": True})
                self.assertEqual(events.count("join"), 1)
                self.assertEqual(log.call_count, int(case not in no_log_cases))
                self.assertEqual(resource_read.call_count, int(case != "complete"))
                if case != "complete":
                    later = case in {"unjoined", "final-result-failure", "log-error", "worker-error", "guard-unknown", "missing-result"}
                    self.assertEqual(events.index("resources") > events.index("join"), later)

    def test_normal_failure_diagnostic_is_bounded_joined_only_and_non_authoritative(self):
        argv = ["/inert/original"]
        original = subprocess.CompletedProcess(argv, 127, b"\x1b" * 1000, b"\x00" * 8192)
        holder = {"result": original, "guardState": "RESTORED", "errors": []}
        error = RuntimeError("private argv and environment must not be exported")
        display = b"\x00" * 8192
        options = dict(joined=True, stage="initial-window", inputs=0, commands=[], error=error,
                       display_log=display, resources=resource_observation())
        def observe(value=holder, **changes):
            with patch.object(L.sys, "stderr", new_callable=io.StringIO) as stream:
                L._shell_normal_failure(value, argv, **dict(options, **changes))
            raw = stream.getvalue().encode("ascii")
            self.assertLessEqual(len(raw), 32768)
            self.assertEqual(raw.count(b"\n"), 1)
            self.assertTrue(raw.startswith(b"MRK_INSTALLED_SHELL_FAILURE="))
            self.assertNotIn(b"private argv", raw)
            self.assertNotIn(b"/inert/original", raw)
            self.assertNotIn(b"\x00", raw)
            self.assertNotIn(b"\x1b", raw)
            return json.loads(raw.split(b"=", 1)[1])
        observed = observe()
        self.assertFalse(observed["qualified"])
        self.assertFalse(observed["cleanupEstablished"])
        # Keep the complete short merged normal output instead of losing its
        # middle. The shared observer/controller snippet limits do not change.
        short = b"inert normal provider diagnostic " + b"x" * 777
        completed = subprocess.CompletedProcess(argv, 0, short, b"")
        normal = observe(dict(holder, result=completed), display_log=b"")["capture"]["stdout"]
        self.assertEqual(normal["head"] + normal["tail"], short.decode("ascii"))
        self.assertFalse(normal["truncated"])
        long = subprocess.CompletedProcess(argv, 0, b"h" * 1024 + b"omitted" * 1024 + b"t" * 2048, b"")
        for flags, sizes in (({}, (256, 256)), ({"normal": True}, (1024, 2048))):
            row = L._shell_capture_summary(long, argv, **flags)["stdout"]
            self.assertEqual((len(row["head"]), len(row["tail"])), sizes)
            self.assertTrue(row["truncated"])
        control = L._shell_capture_summary(completed, argv, controller=True, normal=True)["stdout"]
        self.assertEqual((len(control["head"]), len(control["tail"])), (128, 128))
        self.assertEqual(set(observed["bootstrap"]), {"stdout", "stderr"})
        for row in observed["bootstrap"].values():
            self.assertTrue(all(count == 0 for count in row["markers"].values()))
            self.assertTrue(all(count == 0 for count in row["stages"].values()))
            self.assertEqual((row["unexpectedMrk"], row["unexpectedBootstrap"]), (0, 0))
        # A finite original failure in an omitted middle is counted from the
        # SAME validated capture, not recovered by opening another log.
        failed_capability = b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-query-wait-query_timeout\n"
        failed_cause = b"MRKDBG_DESKTOP_BOOTSTRAP=capabilities-cause-inspection-namespace\n"
        middle = subprocess.CompletedProcess(argv, 0, b"h" * 1024 + b"\n" + failed_capability + failed_cause + b"t" * 2048, b"")
        counted_middle = observe(dict(holder, result=middle), display_log=b"")
        self.assertEqual(counted_middle["bootstrap"]["stdout"]["stages"]["capabilities-query-wait-query_timeout"], 1)
        self.assertEqual(counted_middle["bootstrap"]["stdout"]["stages"]["capabilities-cause-inspection-namespace"], 1)
        summary = counted_middle["capture"]["stdout"]
        self.assertTrue(summary["truncated"])
        self.assertNotIn("capabilities-query-wait-query_timeout", summary["head"] + summary["tail"])
        self.assertNotIn("capabilities-cause-inspection-namespace", summary["head"] + summary["tail"])
        self.assertEqual(observed["resources"], resource_observation())
        self.assertLess(len(L.canonical(observed["resources"])), 1024)
        unavailable = observe(resources=resource_observation(unavailable=True))
        self.assertEqual(unavailable["resources"], resource_observation(unavailable=True))
        self.assertFalse(unavailable["qualified"])
        self.assertFalse(unavailable["cleanupEstablished"])
        for name in ("stdout", "stderr", "display"):
            raw = display if name == "display" else getattr(original, name)
            row = observed["capture"][name]
            self.assertEqual(row["size"], len(raw))
            self.assertEqual(row["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertTrue(row["truncated"])
        query = subprocess.CompletedProcess(["/inert/controller"], 1, b"\x1b" * 512, b"\x00" * 3584)
        call = {"timeoutSeconds": 5, "ownerReturned": True, "startMonotonic": 100.0, "endMonotonic": 101.0}
        controller = {"normalStartMonotonic": 100.0, "controllerEndpoint": 145.0, "serviceEndpoint": 1300.0,
                      "carrierTimeoutSeconds": 60, "failureMonotonic": 107.0,
                      "lastAttempt": {"label": "search", "ordinal": 2, "stage": "initial-window", "phase": "owner-call",
                                      "validOriginalResult": False, "ownerCall": {**call, "ownerReturned": False}},
                      "lastCompleted": {"label": "search", "ordinal": 1, "stage": "initial-window",
                                        "argv": query.args, "result": query, "ownerCall": call}}
        observed = observe(controller=controller)
        self.assertEqual(observed["resources"], resource_observation())
        self.assertIsNotNone(observed["bootstrap"])
        # The complete escaped payload forces the existing fallback. Both old
        # and new snippets are stripped, while their sizes/hashes survive.
        for capture in (observed["capture"], observed["controller"]["lastCompleted"]["capture"]):
            for row in capture.values():
                if type(row) is dict:
                    self.assertNotIn("head", row)
                    self.assertNotIn("tail", row)
                    self.assertTrue(row["truncated"])
        for name in ("stdout", "stderr"):
            self.assertEqual(observed["controller"]["lastCompleted"]["capture"][name]["sha256"],
                             hashlib.sha256(getattr(query, name)).hexdigest())
        # Expanded cause counts survive the SAME <=32768-byte fallback;
        # neither another capture nor a larger report limit is permitted.
        tagged = subprocess.CompletedProcess(argv, 127, original.stdout + b"\n" + failed_cause,
                                             original.stderr + b"\n" + failed_cause)
        trimmed = observe(dict(holder, result=tagged), controller=controller)
        for name in ("stdout", "stderr"):
            self.assertEqual(trimmed["bootstrap"][name]["stages"]["capabilities-cause-inspection-namespace"], 1)
            self.assertNotIn("head", trimmed["capture"][name])
            self.assertNotIn("tail", trimmed["capture"][name])
            self.assertEqual(trimmed["capture"][name]["sha256"], hashlib.sha256(getattr(tagged, name)).hexdigest())
        self.assertFalse(trimmed["qualified"])
        self.assertFalse(trimmed["cleanupEstablished"])
        # A returned object is not a valid capture, and mistyped scalar facts
        # must not be presented as known observations.
        altered = deepcopy(controller)
        altered["lastAttempt"].update(ordinal=True, validOriginalResult=1)
        altered["lastAttempt"]["ownerCall"].update(timeoutSeconds=True, ownerReturned=1, endMonotonic=float("nan"))
        altered["lastCompleted"]["result"] = subprocess.CompletedProcess(query.args, 1, b"", b"x" * 4097)
        observed = observe(controller=altered)
        self.assertIsNone(observed["controller"]["lastCompleted"]["capture"])
        attempted = observed["controller"]["lastAttempt"]
        self.assertIsNone(attempted["ordinal"])
        self.assertIsNone(attempted["validOriginalResult"])
        for key in ("timeoutSeconds", "ownerReturned", "endMonotonic", "ownerElapsedSeconds"):
            self.assertIsNone(attempted["ownerCall"][key])
        reversed_call = {**call, "endMonotonic": 99.0}
        observed = observe(dict(holder, shellDiagnostic={"ownerCall": reversed_call, "errorOrigins": []}))
        self.assertIsNone(observed["workerCall"]["ownerElapsedSeconds"])
        class Unjoined:
            def get(self, *args):
                raise AssertionError("unjoined holder must never be read")
        unjoined = observe(Unjoined(), joined=False, controller=controller)
        self.assertIsNone(unjoined["capture"])
        self.assertIsNone(unjoined["bootstrap"])
        self.assertIsNone(unjoined["workerCall"])
        self.assertIsNotNone(unjoined["controller"]["lastCompleted"]["capture"])
        self.assertEqual(unjoined["resources"], resource_observation())
        for result in (subprocess.CompletedProcess(["/inert/different"], 127, b"", b""),
                       subprocess.CompletedProcess(argv, True, b"", b""),
                       subprocess.CompletedProcess(argv, 127, "not bytes", b""),
                       subprocess.CompletedProcess(argv, 127, b"", b"x" * (L.LIMIT + 1)), {}):
            with self.subTest(result_type=type(result).__name__):
                with patch.object(L, "_shell_normal_markers") as counter:
                    invalid = observe(dict(holder, result=result))
                    self.assertIsNone(invalid["capture"])
                    self.assertIsNone(invalid["bootstrap"])
                    counter.assert_not_called()
        with patch.object(L, "_shell_normal_markers", side_effect=ValueError("synthetic classifier failure")):
            failed_count = observe()
            self.assertIsNone(failed_count["bootstrap"])
            self.assertIsNotNone(failed_count["capture"])
            self.assertEqual(failed_count["errors"], [{"type": "RuntimeError", "origin": "main", "originalProcessFacts": None}])
        # Unknown exception formatting is never invoked; diagnostic encoder or
        # output failure must return without replacing the caller's failure.
        class BadFormat(Exception):
            def __str__(self):
                raise AssertionError("exception formatting is forbidden")
        self.assertEqual(observe(error=BadFormat())["errors"],
                         [{"type": "BadFormat", "origin": "main", "originalProcessFacts": None}])
        class ProcessError(RuntimeError):
            def __init__(self, message):
                super().__init__(message)
                self.__dict__.update(dispatched=True, contained=False, cleanup_complete=False)
        class ProcessCleanupError(ProcessError):
            pass
        class ProcessOutcomeUnknown(ProcessError):
            pass
        class Unknown(ProcessError):
            @property
            def dispatched(self):
                raise AssertionError("unknown process properties must not be read")
            @property
            def args(self):
                raise AssertionError("unknown exception args property must not be read")
            def __str__(self):
                raise AssertionError("unknown process formatting must not be used")
        owner = SimpleNamespace(ProcessError=ProcessError, ProcessCleanupError=ProcessCleanupError,
                                ProcessOutcomeUnknown=ProcessOutcomeUnknown)
        with patch.object(L, "_OWNER", owner):
            for error_type in (ProcessError, ProcessCleanupError, ProcessOutcomeUnknown, Unknown):
                typed = error_type("owned command exceeded its original deadline")
                row = observe(error=typed)["errors"][0]
                self.assertEqual(row["message"], "owned command exceeded its original deadline")
                self.assertEqual(row["originalProcessFacts"], None if error_type is Unknown else
                                 {"dispatched": True, "contained": False, "cleanup_complete": False})
            typed = ProcessError("not a public message")
            typed.__dict__.update(dispatched=1, contained=None, cleanup_complete="true")
            self.assertEqual(observe(error=typed)["errors"][0]["originalProcessFacts"],
                             {"dispatched": None, "contained": None, "cleanup_complete": None})
            worker = dict(holder, errors=[ProcessCleanupError("not a public message")],
                          shellDiagnostic={"ownerCall": call, "errorOrigins": ["guard-restore"]})
            rows = observe(worker, error=typed, error_origin="main", join_error=BadFormat(), capture_error=BadFormat())["errors"]
            self.assertEqual([row["origin"] for row in rows], ["main", "join", "capture", "worker-guard-restore"])
            self.assertFalse(rows[-1]["originalProcessFacts"]["cleanup_complete"])
        with patch.object(L, "canonical", side_effect=OSError("synthetic encoder failure")), \
             patch.object(L.sys, "stderr", new_callable=io.StringIO) as stream:
            L._shell_normal_failure(holder, argv, **options)
            self.assertEqual(stream.getvalue(), "")
        with patch.object(L.sys, "stderr", SimpleNamespace(write=Mock(side_effect=OSError("synthetic write failure")))) as stream:
            L._shell_normal_failure(holder, argv, **options)
            self.assertEqual(stream.write.call_count, 1)

    def test_normal_marker_diagnostic_counts_only_complete_original_records(self):
        markers = (b"MRK_DESKTOP_CAPABILITIES=available\n", b"MRK_DESKTOP_CAPABILITIES=unavailable\n",
                   b"MRK_DESKTOP_CATALOGUE=returned\n", b"MRK_DESKTOP_CATALOGUE=refused\n")
        stages = ("setup-enter", "page-start-trusted", "page-start-untrusted", "page-finish-trusted",
                  "page-finish-untrusted", "hook-installed", "app-info-enter", "catalog-enter", "content-terminated",
                  "content-reason-crashed", "content-reason-exceeded-memory-limit",
                  "content-reason-terminated-by-api", "content-reason-unknown")
        capability_codes = ("runtime_unavailable", "cleanup_unknown", "invalid_request", "shutting_down", "busy", "unavailable",
                            "offline_preflight_busy", "android_build_busy", "environment_diagnostics_busy", "query_timeout",
                            "protocol_error", "engine_failed", "io_error", "output_limit", "other")
        capability_stages = tuple("capabilities-" + origin + "-" + code
                                  for origin in ("admission", "query-wait") for code in capability_codes)
        native_failures = (
            'unsupported-platform',
            'missing-compile-anchor',
            'stopped',
            'deadline',
            'native-unavailable',
            'native-denied',
            'namespace',
            'mount',
            'ownership',
            'extended-attributes',
            'identity-changed',
            'manifest',
            'inventory',
            'bounds',
            'already-used',
            'interrupted',
            'close-uncertain',
            'ledger-invariant',
            'transfer-unavailable',
            'destination-occupied',
        )
        local_causes = (
            'selection-profile-closed',
            'selection-compile-binding',
            'selection-method-outside-profile',
            'inspection-unavailable',
            'acquisition-entry-not-released',
            'acquisition-custody-missing',
            'acquisition-lock',
            'final-claim-owner-gate',
            'returned-spawn-process-fd-limit',
            'returned-spawn-system-fd-limit',
            'returned-spawn-memory',
            'returned-spawn-resource-unavailable',
            'returned-spawn-permission-denied',
            'returned-spawn-not-found',
            'returned-spawn-exec-format',
            'returned-spawn-other',
            'engine-response',
            'unavailable',
        )
        cause_stages = tuple("capabilities-cause-" + origin + "-" + reason
                             for origin in ("inspection", "capability", "preparation", "final-claim") for reason in native_failures)
        cause_stages += tuple("capabilities-cause-" + label for label in local_causes)
        self.assertEqual(len(cause_stages), 98)
        self.assertEqual(len(set(cause_stages)), 98)
        stages += capability_stages + cause_stages
        prefix = b"MRKDBG_DESKTOP_BOOTSTRAP="
        stdout = (b"ordinary wrapper text\n" + b"".join(markers) + markers[0]
                  + b"".join(prefix + stage.encode("ascii") + b"\n" for stage in stages)
                  + b"MRK_DESKTOP_CAPABILITIES=available extra\nMRK_DESKTOP_CAPABILITIES=available\r\n"
                  + b"MRK_UNKNOWN=private-value\n" + prefix + b"unknown-private\n"
                  + prefix + b"hook-installed extra\n" + prefix + b"catalog-enter\r\n"
                  + b"noise prefix " + markers[0] + prefix + b"setup-enter")
        stderr = markers[1] + prefix + b"catalog-enter\n" + markers[0].rstrip(b"\n")
        counted = L._shell_normal_markers(stdout, stderr)
        self.assertEqual(counted["stdout"], {
            "markers": {"capabilitiesAvailable": 2, "capabilitiesUnavailable": 1, "catalogueReturned": 1, "catalogueRefused": 1},
            "unexpectedMrk": 3, "stages": dict.fromkeys(stages, 1), "unexpectedBootstrap": 4})
        self.assertEqual(counted["stderr"], {
            "markers": {"capabilitiesAvailable": 0, "capabilitiesUnavailable": 1, "catalogueReturned": 0, "catalogueRefused": 0},
            "unexpectedMrk": 1, "stages": {stage: int(stage == "catalog-enter") for stage in stages}, "unexpectedBootstrap": 0})
        self.assertNotIn(b"private", L.canonical(counted))
        for reason in ("content-reason-crashed", "content-reason-exceeded-memory-limit",
                       "content-reason-terminated-by-api", "content-reason-unknown", *capability_stages, *cause_stages):
            line = prefix + reason.encode("ascii")
            for malformed in (line, line + b"\r\n", line + b" extra\n"):
                row = L._shell_normal_markers(malformed, b"")["stdout"]
                self.assertEqual(row["stages"][reason], 0)
                self.assertEqual(row["unexpectedBootstrap"], 1)
        for line in (prefix + b"capabilities-admission-PRIVATE_CODE\n",
                     prefix + b"capabilities-PRIVATE_ORIGIN-query_timeout\n",
                     prefix + b"capabilities-query-wait-protocol_error\x1b[31mPRIVATE\n",
                     prefix + b"capabilities-cause-inspection-PRIVATE_REASON\n",
                     prefix + b"capabilities-cause-PRIVATE_ORIGIN-namespace\n",
                     prefix + b"capabilities-cause-returned-spawn-13\n",
                     prefix + b"capabilities-cause-engine-response\x1b[31mPRIVATE\n"):
            row = L._shell_normal_markers(line, b"")["stdout"]
            self.assertTrue(all(row["stages"][stage] == 0 for stage in capability_stages + cause_stages))
            self.assertEqual(row["unexpectedBootstrap"], 1)
            self.assertNotIn(b"PRIVATE", L.canonical(row))
        duplicate = prefix + b"capabilities-admission-busy\n"
        row = L._shell_normal_markers(duplicate * 2, b"")["stdout"]
        self.assertEqual(row["stages"]["capabilities-admission-busy"], 2)
        self.assertEqual(row["unexpectedBootstrap"], 0)
        cause = prefix + b"capabilities-cause-inspection-namespace\n"
        row = L._shell_normal_markers(cause * 2, b"")["stdout"]
        self.assertEqual(row["stages"]["capabilities-cause-inspection-namespace"], 2)
        self.assertEqual(row["unexpectedBootstrap"], 0)
        # Counts are diagnostic-only; neither all causes nor a stage can
        # manufacture normal capabilities/catalogue or observer success.
        for raw in (prefix + b"setup-enter\n", b"".join(prefix + stage.encode("ascii") + b"\n" for stage in cause_stages)):
            with self.assertRaises(ValueError):
                L.shell_result(raw, b"", "normal", 0, map_data())


    def test_normal_resource_diagnostic_is_original_bounded_and_failure_only(self):
        value = installed_handoff()
        root = L.root_path(value)
        group = "/system.slice/" + root.name + ".service"
        self_path, membership = "/proc/self/cgroup", "0::" + group + "\n"
        files = {"pids.max": "64\n", "pids.current": "62\n", "pids.events": "max 1\nfuture_counter 7\n",
                 "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n"}
        leaves = [(str(Path("/sys/fs/cgroup" + group) / name), 1024) for name in files]
        expected_calls = [(self_path, 512), *leaves, (self_path, 512)]
        class Unprintable(OSError):
            def __str__(self):
                raise AssertionError("private kernel failure formatting is forbidden")
        def observe(changes=None, *, bindings=None, original=value, selected_root=root):
            calls, self_reads = [], [0]
            content = {**files, **(changes or {})}
            def kernel(path, limit):
                calls.append((str(path), limit))
                if str(path) == self_path:
                    index = self_reads[0]
                    self_reads[0] += 1
                    raw = bindings[index] if bindings is not None else membership
                else:
                    raw = content[Path(path).name]
                if isinstance(raw, BaseException):
                    raise raw
                return raw
            with patch.object(L, "_ROOT", selected_root), patch.object(L, "_kernel", side_effect=kernel), \
                 patch.object(L, "command", side_effect=AssertionError("no diagnostic process")) as command, \
                 patch.object(L.threading, "Thread", side_effect=AssertionError("no diagnostic thread")) as thread:
                result = L._shell_resource_diagnostic(original, "main-failure-before-join")
                command.assert_not_called()
                thread.assert_not_called()
            self.assertIsNotNone(result)
            self.assertLess(len(L.canonical(result)), 1024)
            self.assertNotIn("future_counter", L.canonical(result).decode())
            return result, calls
        observed, calls = observe()
        self.assertEqual(observed, resource_observation())
        self.assertEqual(calls, expected_calls)
        unlimited, _ = observe({"pids.max": "max\n"})
        self.assertEqual(unlimited["pidsMax"], "max")  # Observation of drift, never policy acceptance.
        upper, _ = observe({"pids.current": str((1 << 64) - 1) + "\n"})
        self.assertEqual(upper["pidsCurrent"], (1 << 64) - 1)
        for options, expected in (
                ({"original": {**value, "runId": "../other"}}, []),
                ({"original": {**value, "attempt": True}}, []),
                ({"selected_root": Path("/other")}, []),
                ({"bindings": ["0::/system.slice/other.service\n"]}, [(self_path, 512)]),
                ({"bindings": [Unprintable("private input")]}, [(self_path, 512)]),
                ({"bindings": [membership, "0::/system.slice/other.service\n"]}, expected_calls),
                ({"bindings": [membership, Unprintable("private input")]}, expected_calls)):
            with self.subTest(binding=options):
                result, calls = observe(**options)
                self.assertEqual(result, resource_observation(unavailable=True))
                self.assertEqual(calls, expected)
        failures = (
            ("pids.max", "pidsMax", "64"), ("pids.current", "pidsCurrent", "-1\n"),
            ("pids.current", "pidsCurrent", "\u0661\n"),
            ("pids.current", "pidsCurrent", str(1 << 64) + "\n"),
            ("pids.current", "pidsCurrent", b"62\n"),
            ("pids.events", "pidsEventsMax", "max 1\nmax 2\n"),
            ("pids.events", "pidsEventsMax", "max 1\n" + "x" * 1024),
            ("pids.events", "pidsEventsMax", "max 1\n" + "".join("a" * count + " 0\n" for count in range(1, 33))),
            ("pids.events", "pidsEventsMax", "max " + str(1 << 64) + "\n"),
            ("memory.events", "memoryEvents", "max 0\noom 0\n"),
            ("memory.events", "memoryEvents", "max 0\noom 0\noom_kill 0\nprivate/path 0\n"),
            ("memory.events", "memoryEvents", Unprintable("private input")),
        )
        for leaf, field, raw in failures:
            with self.subTest(leaf=leaf, input_type=type(raw).__name__):
                result, calls = observe({leaf: raw})
                expected = resource_observation()
                expected[field], expected["unavailable"] = None, [leaf]
                self.assertEqual(result, expected)
                self.assertEqual(calls, expected_calls)
        malformed = (
            {"scope": "private input"}, {"phase": "private input"}, {"bindingMatched": 1},
            {"pidsCurrent": True}, {"pidsEventsMax": 1 << 64}, {"pidsMax": "64"},
            {"memoryEvents": {"max": 0, "oom": 0, "oom_kill": 0, "private": 0}},
            {"unavailable": ["pids.current"]}, {"unavailable": ["binding", "binding"]},
            {"unavailable": ["private input"]}, {"private": "x" * 1024},
        )
        for changed in malformed:
            with self.subTest(fields=list(changed)):
                self.assertIsNone(L._shell_resource_summary({**resource_observation(), **changed}))

    def test_shell_display_route_precreates_one_protected_log_and_never_widens_file_limits(self):
        value = installed_handoff(); value.pop("installed"); value["shell"] = {}
        root = L.root_path(value)
        node = needrestart_stat(stat.S_IFREG | 0o620)
        node.st_gid = value["runnerGid"]
        source = ast.parse((SOURCE / "desktop/tools/ci_ubuntu_publication.py").read_text())
        roster = next(item.value for item in source.body if isinstance(item, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "SHELL_PROGRAMS" for target in item.targets))
        self.assertEqual(sum(isinstance(item, ast.Constant) and item.value == "/usr/bin/prlimit" for item in roster.elts), 1)
        self.assertEqual((L.LIMIT, L.TOTAL_LIMIT, L.SHELL_WORK_FILE_LIMIT), (2 << 20, 32 << 20, 64 << 20))
        for case in L.SHELL_CASES:
            argv = L.shell_argv(value, case)
            at = argv.index("/usr/bin/prlimit")
            self.assertEqual(argv[at:at + 4], ["/usr/bin/prlimit", "--fsize=67108864:67108864", "--", "/usr/bin/dbus-run-session"])
            self.assertIn("--error-file=" + str(root / ("shell-" + case + "-xvfb.log")), argv)
            self.assertNotIn("--error-file=/dev/stderr", argv)
            self.assertEqual(argv[:at], L._drop(value, []))
        ceiling = L.SHELL_WORK_FILE_LIMIT
        for bounds in ((-1, -1), (ceiling, ceiling), (ceiling * 2, ceiling * 3),
                       (ceiling - 1, -1), (-1, ceiling - 1), (L.LIMIT, L.LIMIT), (True, -1), (-2, -1), (-1,)):
            accepted = len(bounds) == 2 and all(type(number) is int and (number == -1 or number >= ceiling) for number in bounds)
            with self.subTest(bounds=bounds), patch.object(L, "_ROOT", root), patch.object(L, "directory"), \
                 patch.object(L.resource, "getrlimit", return_value=bounds) as limits, \
                 patch.object(L.resource, "setrlimit") as change_limits, \
                 patch.object(L.os, "open", return_value=41) as opening, \
                 patch.object(L.os, "fchown") as owner, patch.object(L.os, "fchmod") as mode, \
                 patch.object(L.os, "fsync"), patch.object(L.os, "fstat", return_value=node), \
                 patch.object(L.os, "close") as closing, patch.object(Path, "lstat", return_value=node), patch.object(L, "_xattrs"):
                if accepted:
                    self.assertEqual(L._shell_log_prepare(value, "normal"), L.identity(node)[:6])
                    opening.assert_called_once_with(root / "shell-normal-xvfb.log",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                    owner.assert_called_once_with(41, 0, value["runnerGid"])
                    mode.assert_called_once_with(41, 0o620)
                    closing.assert_called_once_with(41)
                else:
                    with self.assertRaises(ValueError): L._shell_log_prepare(value, "normal")
                    opening.assert_not_called(); closing.assert_not_called()
                limits.assert_called_once_with(L.resource.RLIMIT_FSIZE)
                change_limits.assert_not_called()
        # An exclusive-creation conflict never authorizes reopening or repair.
        with patch.object(L, "_ROOT", root), patch.object(L, "directory"), \
             patch.object(L.resource, "getrlimit", return_value=(-1, -1)), \
             patch.object(L.os, "open", side_effect=FileExistsError("inert conflict")) as opening, \
             patch.object(L.os, "close") as closing, patch.object(L.os, "unlink") as removing:
            with self.assertRaises(FileExistsError): L._shell_log_prepare(value, "normal")
            self.assertEqual(opening.call_count, 1); closing.assert_not_called(); removing.assert_not_called()

    def test_shell_capacity_adds_fixed_private_logs_and_label_leaves_without_changing_other_profiles(self):
        value = installed_handoff()
        value["compilerRecords"]["capacity"] = {"runtimeBytes": 1024,
            "installedBytes": {key: 2048 for key in L.VERSIONS},
            "installedEntries": {key: 16 for key in L.VERSIONS}}
        for profile in ("root", "installed", "shell"):
            candidate = deepcopy(value)
            if profile != "installed":
                candidate.pop("installed")
            if profile == "shell":
                candidate["shell"] = {"binaries": {"normal": {"size": 31}, "observer": {"size": 37}}}
            baseline = (sum(row["size"] for row in candidate["packages"].values()) + candidate["library"]["size"]
                        + (12 if profile == "installed" else 68 if profile == "shell" else 0)
                        + 2 * 1024 + 1 + 2 * 2048 + (32 << 20) + (1 << 20))
            # Twenty logs plus nineteen failure leaves retain the64MiB
            # ceiling. Version adds six fixture and twelve GUI environment
            # nodes beyond the existing nineteen cases.
            # Only the shell roster cap is165;
            # the other profiles and32MiB aggregate evidence cap stay fixed.
            session_bytes = sum(len(data) for case in L.SHELL_SESSION_CASES
                for _, mode, _, data in L._shell_session_roster(value, case) if not stat.S_ISDIR(mode))
            tools_bytes = sum(len(data) for case in L.SHELL_TOOLS_OFFLINE_CASES
                for _, mode, _, data in L._shell_tools_offline_roster(value, case, True) if stat.S_ISREG(mode))
            version_bytes = len(L.SHELL_PROJECT_CONFIG) + len(L.SHELL_PROJECT_IGNORE) + len(b"keep unrelated version fixture data\n") + 34
            required = baseline + ((2496 << 20) + 7235 + session_bytes + tools_bytes + 1186 + 11 + version_bytes + 411 if profile == "shell" else 0)
            inodes = 2 * 16 + 2 * 8192 + (165 + 430 if profile == "shell" else 128)
            for available in (required - 1, required):
                with self.subTest(profile=profile, available=available), \
                     patch.object(Path, "stat", return_value=SimpleNamespace(st_dev=1)), \
                     patch.object(L.os, "statvfs", return_value=SimpleNamespace(
                         f_bavail=available, f_frsize=1, f_favail=inodes)):
                    if available < required:
                        with self.assertRaisesRegex(ValueError, "Insufficient original host capacity"):
                            L._capacity(candidate)
                    else:
                        self.assertIsNone(L._capacity(candidate))
            with patch.object(Path, "stat", return_value=SimpleNamespace(st_dev=1)), \
                 patch.object(L.os, "statvfs", return_value=SimpleNamespace(f_bavail=required, f_frsize=1, f_favail=inodes - 1)):
                with self.assertRaisesRegex(ValueError, "Insufficient original host capacity"):
                    L._capacity(candidate)

    def test_shell_display_capture_requires_bound_original_and_complete_combined_bytes(self):
        value = installed_handoff(); value.pop("installed"); value["shell"] = {}
        root = L.root_path(value)
        node = needrestart_stat(stat.S_IFREG | 0o620, size=6); node.st_gid = value["runnerGid"]
        initial = L.identity(node)[:6]
        argv = L.shell_argv(value, "positive")
        for case in ("complete", "nonzero", "wrong-result", "wrong-mode", "wrong-inode", "wrong-owner", "wrong-group",
                     "hardlink", "changed-after", "combined-bound", "oversized-log", "read-error", "retain-error"):
            before, after = deepcopy(node), deepcopy(node)
            raw = b"inert\n"
            result = subprocess.CompletedProcess(argv, 2 if case == "nonzero" else 0, b"a", b"b")
            if case == "wrong-result": result.args = ["/different/original"]
            changes = {"wrong-mode": ("st_mode", stat.S_IFLNK | 0o777), "wrong-inode": ("st_ino", 99),
                       "wrong-owner": ("st_uid", 99), "wrong-group": ("st_gid", 99), "hardlink": ("st_nlink", 2)}
            if case in changes: setattr(before, *changes[case])
            if case == "changed-after": after.st_mtime_ns += 1
            if case == "combined-bound": raw = b"x" * (L.LIMIT - 1)
            if case == "oversized-log": raw = b"x" * (L.LIMIT + 1)
            with self.subTest(case=case), patch.object(L, "_ROOT", root), patch.object(L, "directory"), \
                 patch.object(Path, "lstat", side_effect=[before, after]), patch.object(L, "_xattrs"), \
                 patch.object(L, "read", return_value=raw) as reading, patch.object(L, "_retain") as retain:
                if case == "read-error": reading.side_effect = OSError("inert read/close refusal")
                if case == "retain-error": retain.side_effect = OSError("inert retention failure")
                if case in ("complete", "nonzero"):
                    self.assertEqual(L._shell_log_capture(value, "positive", initial, result), raw)
                    reading.assert_called_once_with(root / "shell-positive-xvfb.log", L.LIMIT)
                    retain.assert_called_once_with("shell-positive-xvfb.stderr", raw)
                else:
                    with self.assertRaises((ValueError, OSError)): L._shell_log_capture(value, "positive", initial, result)
                    if case in changes or case == "wrong-result": reading.assert_not_called()
                    if case != "retain-error": retain.assert_not_called()

    def test_shell_command_log_finality_and_primary_failure_are_preserved(self):
        value = installed_handoff(); value.pop("installed"); value["shell"] = {}
        argv = L.shell_argv(value, "positive")
        frame = (b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionReview\n"
                 b"MRK_INSTALLED_SHELL_FAILURE_PHASE=settlement\n"
                 b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n"
                 b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v6;index=6;eval=13;"
                 b"reject=reply-assessment-unavailable;wait=native-reply-pending;"
                 b"o=supervisor-disabled;d=none;a=bound;q=cleanup.none.pp;w=none-recorded;"
                 b"ao=bridge;ac=runtime-unavailable;ax=prepare;af=missing-compile-anchor;u=native-observe;g=na\n")
        parsed = L._shell_label_pair(frame)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["session"]["firstOrigin"]["unknownBoundary"], "native-observe")
        self.assertIsNone(parsed["session"]["gtkCallbacks"])
        original_finish, original_capture = L._shell_call_finished, L._command_capture
        nonzero = {"nonzero", "nonzero-log-error", "diagnostic-error", "missing-label", "malformed-label", "label-read-error",
                   "clock-error", "finish-dispatch-error", "reporter-dispatch-error", "format-error", "nonzero-close-error", "nonzero-log-close-error"}
        log_failure = {"log-error", "nonzero-log-error", "nonzero-log-close-error"}
        for case in ("complete", "owner-error", "bad-result", "nonzero", "log-error", "nonzero-log-error", "diagnostic-error", "wrong-route",
                     "late-return", "post-log-expiry", "missing-label", "malformed-label", "label-read-error", "clock-error",
                     "finish-dispatch-error", "reporter-dispatch-error", "format-error", "nonzero-close-error", "nonzero-log-close-error"):
            primary, events, clock, calls = OSError("inert original log failure"), [], [100.0], {}
            result = subprocess.CompletedProcess(argv, 2 if case in nonzero else 0, b"", b"")
            if case == "bad-result": result.args = ["/other/original"]
            def run(*args, **options):
                events.append("owner")
                if case == "owner-error": raise primary
                if case == "late-return": clock[0] = 1000.0
                events.append("owner-return")
                return result
            def diagnostic_time():
                if "record" in calls:
                    self.assertIs(calls["record"]["ownerReturned"], case != "owner-error")
                    events.append("finish-clock")
                    if case == "clock-error": raise OSError("inert finish clock failure")
                return clock[0]
            def finish(record, returned):
                events.append("finish")
                calls["record"] = record
                if case == "finish-dispatch-error": raise OSError("inert finish dispatch failure")
                original_finish(record, returned)
            def capture_result(*args):
                self.assertEqual(events[:3], ["owner", "owner-return", "finish"])
                events.append("capture")
                return original_capture(*args)
            def capture_log(*args):
                self.assertEqual(events[-3:], ["capture", "stdout", "stderr"])
                events.append("log")
                if case in log_failure: raise primary
                if case == "post-log-expiry": clock[0] = 1000.0
                return b"inert display output\n"
            def read_labels(original):
                self.assertEqual(original, (41, "original-label-binding"))
                self.assertEqual(events[-1], "log")
                events.append("labels")
                if case == "label-read-error": raise InterruptedError("inert original sidecar read failure")
                return None if case == "missing-label" else L._shell_label_pair(frame[:-1]) if case == "malformed-label" else parsed
            def close(original):
                self.assertEqual(original, 41)
                events.append("close")
                if case in ("nonzero-close-error", "nonzero-log-close-error"): raise OSError("inert original close failure")
            with self.subTest(case=case), patch.multiple(L, _ROOT=L.root_path(value), _END=1000.0, _FAILED=False,
                    _PHASE="inert", _COMMANDS=[], _OWNER=SimpleNamespace(run_owned=run)), patch.object(L, "_root_ids"), \
                 patch.object(L.time, "monotonic", side_effect=lambda: clock[0]), \
                 patch.object(L, "_shell_diagnostic_time", side_effect=diagnostic_time), \
                 patch.object(L, "_shell_call_finished", side_effect=finish) as finishing, \
                 patch.object(L, "_command_capture", side_effect=capture_result), \
                 patch.object(L, "_retain", side_effect=lambda name, raw: events.append(name.rsplit(".", 1)[1])), \
                 patch.object(L, "_shell_log_capture", side_effect=capture_log) as log, \
                 patch.object(L, "_shell_labels_prepare", return_value=(41, "original-label-binding")) as labels, \
                 patch.object(L, "_shell_labels_read", side_effect=read_labels) as label_read, \
                 patch.object(L, "_shell_command_failure", wraps=L._shell_command_failure) as reporting, \
                 patch.object(L, "canonical", wraps=L.canonical) as formatting, \
                 patch.object(L.os, "close", side_effect=close) as closing, \
                 patch.object(L.sys, "stderr", new_callable=io.StringIO) as stream:
                if case == "diagnostic-error": stream.write = Mock(side_effect=OSError("inert diagnostic error"))
                if case == "reporter-dispatch-error": reporting.side_effect = OSError("inert reporter dispatch failure")
                if case == "format-error": formatting.side_effect = OSError("inert diagnostic format failure")
                arguments = dict(maximum=60, shell_log=(value, "normal" if case == "wrong-route" else "positive", "original-log-binding"))
                if case == "complete":
                    self.assertIs(L.command("shell-positive", argv, **arguments), result)
                    self.assertFalse(L._FAILED)
                else:
                    with self.assertRaises((ValueError, OSError)) as raised: L.command("shell-positive", argv, **arguments)
                    if case in ("owner-error", "log-error"): self.assertIs(raised.exception, primary)
                    if case in nonzero or case == "late-return":
                        self.assertEqual(str(raised.exception), "Original root command failed or completed late")
                        self.assertIs(raised.exception.__cause__, primary if case in log_failure else None)
                    if case == "post-log-expiry": self.assertEqual(str(raised.exception), "Original shell log captured after endpoint")
                    if case != "wrong-route": self.assertTrue(L._FAILED)
                reports = case in nonzero or case in ("log-error", "late-return")
                reads = reports and case != "reporter-dispatch-error"
                self.assertEqual(log.call_count, int(case not in ("owner-error", "bad-result", "wrong-route")))
                self.assertEqual(labels.call_count, int(case != "wrong-route"))
                self.assertEqual(finishing.call_count, int(case != "wrong-route"))
                if case != "wrong-route": self.assertIs(finishing.call_args.args[1], case != "owner-error")
                self.assertEqual(reporting.call_count, int(reports))
                if reports:
                    self.assertIs(reporting.call_args.args[1], result)
                    self.assertEqual(reporting.call_args.args[5], (41, "original-label-binding"))
                    self.assertIs(reporting.call_args.args[6], calls["record"])
                self.assertEqual(label_read.call_count, int(reads))
                self.assertEqual(closing.call_args_list, [] if case == "wrong-route" else [unittest.mock.call(41)])
                expected = [] if case == "wrong-route" else ["owner"] + ([] if case == "owner-error" else ["owner-return"]) + ["finish"]
                if case not in ("wrong-route", "finish-dispatch-error"): expected.append("finish-clock")
                if case not in ("wrong-route", "owner-error"):
                    expected.append("capture")
                    if case != "bad-result": expected += ["stdout", "stderr", "log"]
                if reads: expected.append("labels")
                if case != "wrong-route": expected.append("close")
                self.assertEqual(events, expected)
                if reports and case not in ("diagnostic-error", "reporter-dispatch-error", "format-error"):
                    raw = stream.getvalue().encode("ascii")
                    self.assertLessEqual(len(raw), 32768)
                    diagnostic = json.loads(raw.split(b"=", 1)[1])
                    self.assertEqual(diagnostic["capture"]["exitCode"], result.returncode)
                    if case not in log_failure: self.assertEqual(diagnostic["capture"]["display"]["head"], "inert display output\n")
                    self.assertEqual(diagnostic["logErrorType"], "OSError" if case in log_failure else None)
                    missing = case in ("missing-label", "malformed-label", "label-read-error")
                    self.assertEqual(diagnostic["labels"], None if missing else parsed)
                    self.assertEqual(diagnostic["labelsReason"], "unavailable" if missing else None)
                    self.assertIs(diagnostic["ownerCall"]["ownerReturned"], case != "finish-dispatch-error")
                    if case in ("clock-error", "finish-dispatch-error"): self.assertIsNone(diagnostic["ownerCall"]["endMonotonic"])
                    self.assertFalse(diagnostic["qualified"]); self.assertFalse(diagnostic["cleanupEstablished"])

        # The one expected-negative route uses these same command/FD owners.
        # All capture, file, clock and owner operations below are inert doubles.
        argv = L.shell_argv(value, "settled-failure")
        original_classifier = L._shell_settled_failure_result
        route_errors = {"wrong-route", "missing-route", "exit-override"}
        for case in ("complete", "owner-error", "owner-interrupt", "bad-result", "wrong-route", "missing-route", "exit-override",
                     "zero", "other-code", "capture-error", "log-error", "label-read-error", "label-grammar-error",
                     "marker-error", "retention-error", "label-read-interrupt", "retention-interrupt", "close-error", "log-close-error", "expiry-before-label",
                     "expiry-before-close", "expiry-after-close", "clock-after-close"):
            events, now, retained = [], [100.0], {}
            primary = KeyboardInterrupt("inert original interruption") if case.endswith("-interrupt") else OSError("inert original failure")
            close_error = OSError("inert checked-close failure")
            stdout, stderr = settled_failure_capture()
            if case == "marker-error": stdout += b"MRK_INSTALLED_SHELL_OBSERVATION=settled-failure-verified\n"
            result = subprocess.CompletedProcess(argv, 0 if case == "zero" else 2 if case == "other-code" else 1, stdout, stderr)
            if case == "bad-result": result.args = ["/other/original"]
            def run(*args, **options):
                events.append("owner")
                self.assertTrue(L._FAILED)
                if case in ("owner-error", "owner-interrupt"): raise primary
                return result
            def clock():
                if events and events[-1] == "close":
                    events.append("post-close-clock")
                    if case == "clock-after-close": raise primary
                return now[0]
            def capture(*args):
                events.append("capture")
                return original_capture(*args)
            def retain(name, raw):
                self.assertTrue(L._FAILED)
                events.append("label-export" if name.endswith(".labels") else name.rsplit(".", 1)[1])
                if case == "capture-error" or case in ("retention-error", "retention-interrupt") and name.endswith(".labels"): raise primary
                retained[name] = raw
                if case == "expiry-before-close" and name.endswith(".labels"): now[0] = 200.0
            def log(*args):
                self.assertEqual(events[-3:], ["capture", "stdout", "stderr"])
                events.append("log")
                if case in ("log-error", "log-close-error"): raise primary
                if case == "expiry-before-label": now[0] = 200.0
                return b"inert display output\n"
            def labels(original, *, with_raw=False):
                self.assertEqual(original, (41, "original-label-binding"))
                events.append("labels")
                if case in ("label-read-error", "label-read-interrupt"): raise primary
                raw = L.SHELL_SETTLED_FAILURE_LABELS
                if case == "label-grammar-error": raw = raw[:-1]
                parsed = L._shell_label_pair(raw)
                return (raw, parsed) if with_raw else parsed
            def classify(*args):
                self.assertEqual(events[-1], "labels")
                events.append("classify")
                return original_classifier(*args)
            def close(fd):
                self.assertEqual(fd, 41)
                self.assertTrue(L._FAILED)
                events.append("close")
                if case in ("close-error", "log-close-error"): raise close_error
                if case == "expiry-after-close": now[0] = 200.0
            with self.subTest(negative=case), patch.multiple(L, _ROOT=L.root_path(value), _END=200.0, _FAILED=False,
                    _PHASE="inert", _COMMANDS=[], _OWNER=SimpleNamespace(run_owned=run)), \
                 patch.object(L, "_root_ids"), patch.object(L.time, "monotonic", side_effect=clock), \
                 patch.object(L, "_command_capture", side_effect=capture), patch.object(L, "_retain", side_effect=retain), \
                 patch.object(L, "_shell_log_capture", side_effect=log) as capturing_log, \
                 patch.object(L, "_shell_labels_prepare", return_value=(41, "original-label-binding")) as prepare, \
                 patch.object(L, "_shell_labels_read", side_effect=labels) as reading, \
                 patch.object(L, "_shell_settled_failure_result", side_effect=classify) as classifier, \
                 patch.object(L, "_shell_command_failure", wraps=L._shell_command_failure) as reporting, \
                 patch.object(L, "_shell_owner_failure") as owner_diagnostic, \
                 patch.object(L.os, "close", side_effect=close) as closing, \
                 patch.object(L.sys, "stderr", new_callable=io.StringIO) as stream:
                options = dict(maximum=60, env={}, shell_log=(value,
                    "positive" if case == "wrong-route" else "settled-failure", "original-log-binding"))
                if case == "missing-route": options.pop("shell_log")
                if case == "exit-override": options["codes"] = (1,)
                if case == "complete":
                    self.assertIs(L.command("shell-settled-failure", argv, **options), result)
                    self.assertFalse(L._FAILED)
                    self.assertEqual(events, ["owner", "capture", "stdout", "stderr", "log", "labels", "classify",
                                              "label-export", "close", "post-close-clock"])
                    self.assertEqual(retained["shell-settled-failure-failure.labels"], L.SHELL_SETTLED_FAILURE_LABELS)
                    reporting.assert_not_called()
                else:
                    with self.assertRaises((ValueError, OSError, KeyboardInterrupt)) as raised:
                        L.command("shell-settled-failure", argv, **options)
                    self.assertIs(L._FAILED, case not in route_errors)
                    if case in ("owner-error", "owner-interrupt"): self.assertIs(raised.exception, primary)
                    elif case not in route_errors | {"bad-result"}:
                        self.assertEqual(str(raised.exception), "Original root command failed or completed late")
                    if case in ("capture-error", "log-error", "log-close-error", "label-read-error", "retention-error", "clock-after-close",
                                "label-read-interrupt", "retention-interrupt"):
                        self.assertIs(raised.exception.__cause__, primary)
                    if case == "close-error": self.assertIs(raised.exception.__cause__, close_error)
                self.assertEqual(closing.call_args_list, [] if case in route_errors else [unittest.mock.call(41)])
                self.assertEqual(prepare.call_count, int(case not in route_errors))
                self.assertEqual(owner_diagnostic.call_count, int(case in ("owner-error", "owner-interrupt")))
                self.assertEqual(capturing_log.call_count, int(case not in route_errors | {"owner-error", "owner-interrupt", "bad-result", "capture-error"}))
                self.assertLessEqual(reading.call_count, 1)  # Even failed reads/classification/export never cause a retry.
                attempted = case not in route_errors | {"owner-error", "owner-interrupt", "bad-result", "capture-error", "zero", "other-code",
                                                       "log-error", "log-close-error", "expiry-before-label"}
                if attempted: reading.assert_called_once_with((41, "original-label-binding"), with_raw=True)
                self.assertEqual(classifier.call_count, int(attempted and case not in ("label-read-error", "label-read-interrupt")))
                if L._COMMANDS:
                    self.assertEqual(L._COMMANDS[-1]["phase"], "shell-settled-failure")
                    self.assertEqual(L._COMMANDS[-1]["exitCode"], result.returncode)
                if reporting.called:
                    diagnostic = json.loads(stream.getvalue().split("=", 1)[1])
                    self.assertFalse(diagnostic["qualified"]); self.assertFalse(diagnostic["cleanupEstablished"])

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
        for diagnostic in (False, True):
            for case in ("complete", "owner-error", "install-error", "activate-error", "restore-error",
                         "check-error", "state-error", "finish-clock-error"):
                calls, holder = [], {}
                primary = RuntimeError("inert original worker failure")
                class Guard:
                    @property
                    def handler_state(self):
                        if case == "state-error":
                            raise primary
                        return "RESTORED"
                    def install(self):
                        calls.append("install")
                        if case == "install-error":
                            raise primary
                    def activate(self):
                        calls.append("activate")
                        if case == "activate-error":
                            raise primary
                    def restore(self):
                        calls.append("restore")
                        if case == "restore-error":
                            raise primary
                    def check(self):
                        calls.append("check")
                        if case == "check-error":
                            raise primary
                guard, argv = Guard(), ["/inert-overlap"]
                result = subprocess.CompletedProcess(argv, 0, b"inert", b"")
                def owned(*args, **kwargs):
                    calls.append("owned")
                    self.assertIs(kwargs["cancellation"], guard)
                    self.assertEqual(kwargs["timeout"], 60)
                    if case in {"owner-error", "finish-clock-error"}:
                        raise primary
                    return result
                owner = SimpleNamespace(DefaultCancellation=Mock(return_value=guard), ProcessCleanupError=RuntimeError, run_owned=owned)
                clock_values = [100.0, OSError("inert finish clock loss") if case == "finish-clock-error" else 102.5]
                with self.subTest(case=case, diagnostic=diagnostic), patch.object(L, "_OWNER", owner), \
                     patch.object(L, "command") as command, patch.object(L, "_retain") as retain, \
                     patch.object(L.time, "monotonic", side_effect=clock_values) as clock:
                    if diagnostic:
                        L._overlap_worker(holder, argv, {}, 60, shell_diagnostic=True)
                    else:
                        L._overlap_worker(holder, argv, {}, 60)
                    self.assertEqual(calls[-2:], ["restore", "check"])
                    self.assertEqual(holder["errors"], [] if case == "complete" else [primary])
                    returned = case in {"complete", "restore-error", "check-error", "state-error"}
                    if returned:
                        self.assertIs(holder["result"], result)
                    else:
                        self.assertNotIn("result", holder)
                    if diagnostic:
                        observation = holder["shellDiagnostic"]
                        origins = {"install-error": "guard-install", "activate-error": "guard-activate", "owner-error": "owner",
                                   "finish-clock-error": "owner", "restore-error": "guard-restore", "check-error": "guard-check",
                                   "state-error": "guard-state"}
                        self.assertEqual(observation["errorOrigins"], [] if case == "complete" else [origins[case]])
                        if case in {"install-error", "activate-error"}:
                            self.assertIsNone(observation["ownerCall"])
                            clock.assert_not_called()
                        else:
                            call = L._shell_call_summary(observation["ownerCall"])
                            self.assertEqual(clock.call_count, 2)
                            self.assertEqual(call["ownerReturned"], returned)
                            self.assertEqual(call["timeoutSeconds"], 60)
                            self.assertEqual(call["ownerElapsedSeconds"], None if case == "finish-clock-error" else 2.5)
                    else:
                        self.assertNotIn("shellDiagnostic", holder)
                        clock.assert_not_called()
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

    def test_shell_task_budget_is_role_bound_and_checked_end_to_end(self):
        defaults = deepcopy(L.PROPERTIES)
        self.assertEqual(defaults["TasksMax"], "64")
        handoff_path, handoff_sha, entry_sha = Path("/inert/handoff.json"), "a" * 64, "b" * 64
        for profile in ("ordinary", "installed", "shell"):
            value = installed_handoff()
            if profile != "installed":
                value.pop("installed")
            if profile == "shell":
                value["shell"] = {}  # Shape was admitted by the doubled handoff boundary.
            tasks = "256" if profile == "shell" else "64"
            unit = L.root_path(value).name + ".service"
            group = "/system.slice/" + unit
            environment = {"MRK_UBUNTU_LIFECYCLE_BOOTSTRAP": L.BOOTSTRAP,
                           "MRK_LIFECYCLE_RUNTIME_SECONDS": "1160", "INVOCATION_ID": "d" * 32}
            with self.subTest(profile=profile), patch.object(L, "handoff", return_value=value), \
                    patch.object(L, "record", return_value={"sha256": entry_sha}), \
                    patch.object(L.os, "getresuid", return_value=(1001,) * 3), \
                    patch.object(L.os, "getresgid", return_value=(1001,) * 3), \
                    patch.dict(L.os.environ, environment, clear=True), \
                    patch.object(L.time, "monotonic", return_value=100.0):
                argv = L.service_argv(handoff_path, handoff_sha, entry_sha)
                properties = dict(arg.removeprefix("--property=").split("=", 1)
                                  for arg in argv if arg.startswith("--property="))
                self.assertEqual(properties["TasksMax"], tasks)
                self.assertEqual({key: properties[key] for key in defaults if key != "TasksMax"},
                                 {key: item for key, item in defaults.items() if key != "TasksMax"})
                self.assertEqual(properties["RuntimeMaxSec"], "1160s")

                # The collector must authenticate this original profile's argv
                # before any public-root observation. The sentinel is not a
                # successful lifecycle result and no service is started here.
                for wrong in (None, "64" if tasks == "256" else "256", "max", "257"):
                    args = [arg if wrong is None or not arg.startswith("--property=TasksMax=")
                            else "--property=TasksMax=" + wrong for arg in argv]
                    client = subprocess.CompletedProcess(args, 0, b"", b"")
                    boundary = RuntimeError("inert first public-root observation")
                    with self.subTest(client_tasks=wrong), patch.object(L, "directory", side_effect=boundary) as directory, \
                            patch.object(L, "read") as read:
                        if wrong is None:
                            with self.assertRaises(RuntimeError) as stopped:
                                L.verify_service_result(handoff_path, handoff_sha, entry_sha, client, Path("/inert/public"))
                            self.assertIs(stopped.exception, boundary)
                            directory.assert_called_once_with(L.root_path(value) / "public", protected=True)
                        else:
                            with self.assertRaisesRegex(ValueError, "Original service client argv differs"):
                                L.verify_service_result(handoff_path, handoff_sha, entry_sha, client, Path("/inert/public"))
                            directory.assert_not_called()
                        read.assert_not_called()

                observed = {key: defaults[key] for key in L.SHOW if key in defaults}
                observed.update(Id=unit, Type="exec", InvocationID="d" * 32, ControlGroup=group, Result="success",
                                MemoryMax=str(6 << 30), TasksMax=tasks, RuntimeMaxUSec="1160s",
                                RuntimeRandomizedExtraUSec="0", TimeoutStartUSec="10s", TimeoutStopUSec="10s",
                                **{key: "no" for key in ("PrivateMounts", "PrivateTmp", "PrivateUsers",
                                                        "PrivateNetwork", "ProtectControlGroups")})
                kernel = {"/proc/self/cgroup": "0::" + group + "\n",
                          **{str(Path("/sys/fs/cgroup" + group) / key): item for key, item in {
                              "cgroup.type": "domain\n", "memory.max": str(6 << 30) + "\n",
                              "memory.swap.max": "0\n", "memory.oom.group": "1\n", "pids.max": tasks + "\n",
                              "cpu.max": "200000 100000\n", "memory.events": "max 0\noom 0\noom_kill 0\n",
                              "pids.events": "max 0\n"}.items()}}
                for phase in ("start", "stop"):
                    for fault in (None, "systemd-limit", "kernel-limit", "both-limits", "unlimited", "task-denial", "memory-denial"):
                        props, counters = dict(observed), dict(kernel)
                        other = "64" if tasks == "256" else "256"
                        if fault in {"systemd-limit", "both-limits", "unlimited"}:
                            props["TasksMax"] = "infinity" if fault == "unlimited" else other
                        if fault in {"kernel-limit", "both-limits", "unlimited"}:
                            counters["/sys/fs/cgroup" + group + "/pids.max"] = ("max" if fault == "unlimited" else other) + "\n"
                        if fault in {"task-denial", "memory-denial"}:
                            key = "pids.events" if fault == "task-denial" else "memory.events"
                            path = "/sys/fs/cgroup" + group + "/" + key
                            counters[path] = counters[path].replace("max 0", "max 1")
                        stdout = "".join(key + "=" + props[key] + "\n" for key in L.SHOW).encode("ascii")
                        result = subprocess.CompletedProcess(["/inert-show"], 0, stdout, b"")
                        with self.subTest(phase=phase, fault=fault), patch.object(L, "command", return_value=result) as command, \
                                patch.object(L, "_kernel", side_effect=lambda path: counters[str(path)]):
                            if fault is None:
                                actual = L._domain(value, phase)
                                self.assertEqual(actual["unit"]["TasksMax"], tasks)
                                self.assertEqual(actual["effective"]["pids.max"], tasks)
                            else:
                                with self.assertRaisesRegex(ValueError, "Effective aggregate limits differ|Original aggregate resource denial"):
                                    L._domain(value, phase)
                            command.assert_called_once_with(phase + "-unit-show",
                                ["/usr/bin/systemctl", "show", "--no-pager", "--property=" + ",".join(L.SHOW), unit], maximum=3)
        self.assertEqual(L.PROPERTIES, defaults)

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


class GitHubPeerNamespaceWitnessContracts(unittest.TestCase):
    @staticmethod
    def observations():
        start = {
            "sourceSha": "a" * 40, "entrySha256": "b" * 64, "handoffSha256": "c" * 64,
            "invocationId": "d" * 32, "deadline": 1300.0,
            "namespaces": {"user": [4, 11], "pid": [4, 12], "mnt": [4, 13]},
            "githubPeerNamespaces": {"user": [4, 11], "pid": [4, 12], "mnt": [4, 13], "net": [4, 14]},
            "unit": {"Id": "mrk-ubuntu-native-10-2.service", "InvocationID": "d" * 32,
                     "Result": "success", "ControlGroup": "/system.slice/mrk-ubuntu-native-10-2.service"},
            "effective": {"KillMode": "control-group", "ExitType": "cgroup"},
            "events": {"memory.events": {"max": 0, "oom": 0, "oom_kill": 0}, "pids.events": {"max": 0}},
        }
        stop = {**deepcopy(start), "completion": {
            "SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}}
        return start, stop

    def test_route_requires_both_witnesses_and_preserves_ordinary_finality(self):
        start, stop = self.observations()
        L.verify_finality(start, stop, 0, github=True)
        for remove_start, remove_stop in ((True, False), (False, True), (True, True)):
            first, last = deepcopy(start), deepcopy(stop)
            if remove_start:
                first.pop("githubPeerNamespaces")
            if remove_stop:
                last.pop("githubPeerNamespaces")
            with self.subTest(remove_start=remove_start, remove_stop=remove_stop), self.assertRaises(ValueError):
                L.verify_finality(first, last, 0, github=True)
        for first, last in ((start, stop), ({k: v for k, v in start.items() if k != "githubPeerNamespaces"}, stop)):
            with self.assertRaises(ValueError):
                L.verify_finality(first, last, 0)
        start.pop("githubPeerNamespaces")
        stop.pop("githubPeerNamespaces")
        L.verify_finality(start, stop, 0)
        for invalid_context in (None, 0, 1, "true"):
            with self.assertRaises(ValueError):
                L.verify_finality(start, stop, 0, github=invalid_context)

    def test_witness_rejects_malformed_pairs_roles_and_changed_stop_domain(self):
        start, stop = self.observations()
        self.assertEqual(L._github_peer_namespace_witness(start), start["githubPeerNamespaces"])
        for field in ("namespaces", "githubPeerNamespaces"):
            for malformed in ([0, 11], [4, 0], [True, 11], [4, 11.0], [4, -1], [4, 2**64],
                              [4], [4, 11, 12], (4, 11), ["4", 11], None):
                invalid = deepcopy(start)
                invalid[field]["user"] = malformed
                with self.subTest(field=field, pair=malformed), self.assertRaises(ValueError):
                    L._github_peer_namespace_witness(invalid)
            missing = deepcopy(start)
            missing[field].pop("user")
            with self.assertRaises(ValueError):
                L._github_peer_namespace_witness(missing)
            extra = deepcopy(start)
            extra[field]["extra"] = [4, 15]
            with self.assertRaises(ValueError):
                L._github_peer_namespace_witness(extra)
        changed = deepcopy(stop)
        changed["githubPeerNamespaces"]["net"] = [4, 15]
        with self.assertRaises(ValueError):
            L.verify_finality(start, changed, 0, github=True)
        changed = deepcopy(start)
        changed["namespaces"]["mnt"] = [4, 15]
        with self.assertRaises(ValueError):
            L._github_peer_namespace_witness(changed)

    def test_real_producers_and_finality_callers_keep_the_explicit_route(self):
        source = (SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_text()
        for producer, following in (("unit_start", "_no_denials"), ("unit_stop", "installed_closed_result")):
            body = source.split("def " + producer + "(", 1)[1].split("def " + following + "(", 1)[0]
            self.assertIn('if shell_github(value):', body)
            self.assertIn('["githubPeerNamespaces"] = _github_boundary_namespaces()', body)
            self.assertIn('_github_peer_namespace_witness(', body)
        self.assertIn('verify_finality(start, stop, 0, github=shell_github(value))', source)
        self.assertIn('verify_finality(start, stop, client_result.returncode, github=shell_github(value))', source)


def project_draft_receipt():
    """Expected typed schema DATA, not a native observation or original owner."""
    return {
        "schemaVersion": 3, "fixture": "android-saved-readonly-v1", "projectGateContract": True,
        "methods": "thirteen-passive", "passiveActions": False,
        "cancel": {"operation": 1, "widget": "cancel", "guiSettled": True, "originalsSettled": True, "registered": False},
        "select": {"operation": 2, "widget": "select", "filenameRead": True, "guiSettled": True, "originalsSettled": True, "registered": True},
        "snapshot": {"initial": "missing", "androidHint": True, "sourceFiles": 2},
        "suggestion": {"coreProvenance": True, "explicitAdoption": True},
        "save": {"capability": True, "requests": {"open": 2, "prepare": 2, "apply": 1, "close": 0},
                 "bindingsMatched": True, "draftRevisions": [1, 1], "baselineGenerations": [1, 2],
                 "reviewMatched": True, "confirmation": {"opened": 2, "keepReviewing": True, "applyBeforeAck": 0, "acknowledged": True},
                 "outcome": ["committed", "clean", "settled", "none"], "nativeFinality": "settled",
                 "savedVisible": True, "baselineAdvanced": True, "createReleaseDirectory": True},
        "readback": {"fresh": True, "domMatched": True, "draftMatched": True, "size": 684,
                     "sha256": "0c47aaffe3971b122f21ebddf8070ab29014c4b7c79a56e23335ed110f1e6acc"},
        "noop": {"reviewMatched": True, "apply": 0, "quitOutstanding": True,
                 "outcome": ["not_started", "not_created", "settled", "cancelled"], "nativeReason": "shutdown"},
        "originals": {"sessions": 2, "writerFrames": [3, 2], "stdoutFrames": [3, 3],
                      "startupJoined": 2, "childWaited": 2, "ioSettled": 2, "ownersJoined": 2,
                      "runtimeLedgerSettled": 2, "runtimeSettlementJoined": 2},
        "quit": {"operation": 7, "originalsSettled": True, "relayJoined": True, "exit": True},
        "guidance": {
            "draftUnchanged": True,
            "requirements": {"requestResultDomMatched": True, "context": "android/build", "roles": 3},
            "github": {"requestResultDomMatched": True, "explicitInputs": True, "browserEdit": "insertText",
                       "workflowCount": 4},
            "assuranceActions": False, "releaseReadiness": "unknown",
        },
        "savedReads": {
            "version": {"requestResultDomMatched": True, "pairMatched": True, "name": "1.2.3", "build": 7},
            "metadata": {"observeRequestResultDomMatched": True, "absent": 3, "validateRequestResultDomMatched": True,
                         "browserEdit": "insertText", "draftRetained": True},
            "scope": "single-request-non-atomic",
        },
    }


CANDIDATE_FIXTURE_PINS = (
    ("candidate-manifest.json", "candidate-valid.json", 3907, "285685846ac73e215aacc77436884e42f3e973a105dc5e40f1add0a020f2e06d"),
    ("candidate-receipt.json", "receipt-candidate-valid.json", 3363, "375d5b895b62b62842338acff9c8ed9cfafe9a618eb51439d9ebc042d401e183"),
    ("operation/candidate-operation-intent.json", "intent-candidate-valid.json", 4096, "e56ad77ee3cb4b1d3e12d1a6f5be8f7d0e90497934d1ebbd5bd9312b53362e42"),
)


def lifecycle_documents_receipt():
    """Independent expected DATA; source-only tests are not an installed witness."""
    return {
        "schemaVersion": 1, "fixture": "android-candidate-documents-v1",
        "gate": "installed-project-profile+lifecycle-passive", "privacy": "independent-predicate+gtk-readback",
        "requests": {"choose": 3, "observe": 1, "cancel": 1},
        "cancel": {"operation": 3, "stage": "candidate", "gtkSettled": True, "nativeFinal": True, "probeUnstarted": True},
        "select": {"operation": 4, "stage": "candidate", "gtkSettled": True, "filenameMatched": True,
                   "nativeFinal": True, "selectionMatched": True},
        "observe": {"operation": 5, "method": "release.evidence.observe", "stage": "candidate", "bindingMatched": True,
                    "requestResultDomMatched": True, "nativeFinal": True},
        "shared": {"current": ["Artifacts", "Releases", "Recovery"], "stale": ["Releases", "Artifacts", "Recovery"],
                   "sameObservation": True, "noExtraObservation": True, "recoveryCurrent": False},
        "stageChange": {"requested": "external-testing", "retained": "candidate", "inspectDisabled": True, "currentBeforeChoice": True},
        "opposite": {"boundary": "native-owner-endpoints", "checks": 1, "status": "busy", "cancel": "stale-selection",
                     "sameOriginal": True, "noStop": True},
        "stop": {"operation": 6, "stage": "external-testing", "rendererRequest": True, "createdBeforeStop": True,
                 "deleteEvent": True, "gtkCancel": False, "gtkSettled": True, "nativeFinal": True, "probeUnstarted": True, "noResult": True},
        "preserved": {"sourceProject": True, "registry": True, "credentialStateEmpty": True, "savedReads": True, "wholeDraft": True},
        "scope": {"documents": 3, "formatsDigestsBindingsMatched": True, "artifactPayloadsObserved": False,
                  "sourceCompared": False, "signingVerified": False, "workflowAuthenticated": False,
                  "storeObserved": False, "releaseReady": False, "recoveryAuthority": False},
        "quit": {"operation": 7, "gtkSettled": True, "coordinatorJoined": True, "relayJoined": True, "exit": True},
    }


def legacy_candidate_documents_receipt():
    """Independent compact expected DATA; no paths, IDs or release authority."""
    return {
        "schemaVersion": 1, "fixture": "android-candidate-documents-v1",
        "gate": "installed-project-profile+candidate-passive", "privacy": "independent-predicate+gtk-readback",
        "cancel": {"operation": 3, "requestMatched": True, "gtkSettled": True, "tokenJoined": True,
                   "probeUnstarted": True, "coordinatorJoined": True, "noRegistration": True},
        "select": {"operation": 4, "requestMatched": True, "gtkSettled": True, "filenameMatched": True,
                   "tokenJoined": True, "probeJoined": True, "coordinatorJoined": True, "selectionMatched": True},
        "observe": {"operation": 5, "requests": 1, "requestResultDomMatched": True, "bindingMatched": True,
                    "coordinatorJoined": True, "supervisorIdle": True, "knownIdle": True},
        "preserved": {"sourceProject": True, "registry": True, "credentialStateEmpty": True, "savedReads": True, "wholeDraft": True},
        "scope": {"documents": 3, "formatsDigestsBindingsMatched": True, "artifactPayloadsObserved": False,
                  "sourceCompared": False, "signingVerified": False, "storeObserved": False, "releaseReady": False, "recoveryAuthority": False},
        "quit": {"operation": 6, "gtkSettled": True, "coordinatorJoined": True, "relayJoined": True, "exit": True},
    }


def positive_capture(receipt=None, lifecycle=None):
    return (b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n"
            + b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n"
            + L.SHELL_PROJECT_MARKER + L.canonical(project_draft_receipt() if receipt is None else receipt)
            + L.SHELL_LIFECYCLE_MARKER + L.canonical(lifecycle_documents_receipt() if lifecycle is None else lifecycle)
            + b"MRK_INSTALLED_SHELL_OBSERVATION=positive-verified\n", b"")


def fixture_namespace_data(value):
    suffix = value["runId"] + "-" + value["attempt"]
    return {"root": "/var/lib/mrk-ubuntu-shell-fixtures-" + suffix,
            "identity": [1, 5, stat.S_IFDIR | 0o755, 0, 0, 21, 4096, 11, 11],
            "children": ["candidate-evidence", "metadata-project", "offline-cancel", "offline-drift", "offline-negative",
                         "offline-pass", "offline-settlement", "path-outside", "path-project", "positive-project",
                         "session-deadline", "session-inputs", "session-loss", "session-refusals", "tools-cancel",
                         "tools-observed", "tools-settlement", "version-project", "workflow-project"],
            "control": {"path": "/var/lib/mrk-ubuntu-native-" + suffix, "identity": [1, 4, stat.S_IFDIR | 0o711, 0, 0]},
            "ancestors": [{"path": path, "identity": [1, i + 1, stat.S_IFDIR | 0o755, 0, 0]}
                          for i, path in enumerate(("/", "/var", "/var/lib"))]}


def session_fixture_data(value, case, *, changed=False):
    """In-memory fixture correspondence only; no native inputs are created."""
    namespace = fixture_namespace_data(value)
    roster = L._shell_session_roster(value, case, changed)
    original_names = [name for name, _, _, _ in L._shell_session_roster(value, case)]
    offset = 600 + 100 * L.SHELL_SESSION_CASES.index(case)
    rows = []
    for name, mode, owners, expected in roster:
        original_name = "sources/changed-next.jks" if changed and name == "sources/changed.jks" else name
        stamp = 22 if changed and name in ("sources", "sources/changed.jks") else 11
        kind = "directory" if stat.S_ISDIR(mode) else "symlink" if stat.S_ISLNK(mode) else "file"
        original = [1, offset + original_names.index(original_name), mode, *owners,
                    2 if kind == "directory" else 1, 4096 if kind == "directory" else len(expected),
                    22 if changed and name == "sources" else 11, stamp]
        row = {"path": name, "kind": kind, "identity": original}
        row.update({"children": expected} if kind == "directory" else {"target": expected} if kind == "symlink"
                   else {"size": len(expected), "sha256": hashlib.sha256(expected).hexdigest()})
        rows.append(row)
    return {"schemaVersion": 1, "fixture": "four-kind-session-v1", "case": case,
            "root": namespace["root"] + "/" + case, "changed": changed, "entries": rows,
            "absent": L._shell_session_absent(case, changed), "namespace": namespace}


def project_fixture_data(value, *, saved=False):
    source = (b'plugins { id("com.android.application") }\n'
              b'android { defaultConfig { applicationId = "org.example.mrk.observed" } }\n')
    version = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
    uid, gid = value["runnerUid"], value["runnerGid"]
    stamp = 22 if saved else 11
    rows = [{"path": ".", "kind": "directory", "identity": [1, 100, stat.S_IFDIR | 0o700, uid, gid, 4 if saved else 3, 4096, stamp, stamp],
             "children": [".gitignore", "app", "release", "version.properties"] if saved else ["app", "version.properties"]},
            {"path": "app", "kind": "directory", "identity": [1, 101, stat.S_IFDIR | 0o555, 0, 0, 2, 4096, 11, 11], "children": ["build.gradle.kts"]}]
    if saved:
        rows.append({"path": "release", "kind": "directory", "identity": [1, 103, stat.S_IFDIR | 0o755, uid, gid, 2, 4096, stamp, stamp],
                     "children": ["mobile-release.json"]})
    rows.extend(({"path": "app/build.gradle.kts", "kind": "file", "identity": [1, 102, stat.S_IFREG | 0o444, 0, 0, 1, len(source), 11, 11],
             "size": len(source), "sha256": hashlib.sha256(source).hexdigest()},
            {"path": "version.properties", "kind": "file", "identity": [1, 104, stat.S_IFREG | 0o600, uid, gid, 1, len(version), 11, 11],
             "size": len(version), "sha256": hashlib.sha256(version).hexdigest()}))
    if saved:
        for index, (relative, data) in enumerate((("release/mobile-release.json", L.SHELL_PROJECT_CONFIG), (".gitignore", L.SHELL_PROJECT_IGNORE))):
            rows.append({"path": relative, "kind": "file", "identity": [1, 105 + index, stat.S_IFREG | 0o600, uid, gid, 1, len(data), 22, 22],
                         "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    namespace = fixture_namespace_data(value)
    return {"schemaVersion": 3, "fixture": "android-saved-readonly-v1", "root": namespace["root"] + "/positive-project",
            "saved": saved, "entries": rows, "namespace": namespace,
            "absent": ["release/store"] if saved else [".gitignore", "release"]}


def candidate_fixture_data(value):
    uid, gid = value["runnerUid"], value["runnerGid"]
    rows = [{"path": ".", "kind": "directory", "identity": [1, 200, stat.S_IFDIR | 0o700, uid, gid, 3, 4096, 11, 11],
             "children": ["candidate-manifest.json", "candidate-receipt.json", "operation"]},
            {"path": "operation", "kind": "directory", "identity": [1, 201, stat.S_IFDIR | 0o700, uid, gid, 2, 4096, 11, 11],
             "children": ["candidate-operation-intent.json"]}]
    for index, (relative, _, size, digest) in enumerate(CANDIDATE_FIXTURE_PINS):
        rows.append({"path": relative, "kind": "file", "identity": [1, 202 + index, stat.S_IFREG | 0o600, uid, gid, 1, size, 11, 11],
                     "size": size, "sha256": digest})
    namespace = fixture_namespace_data(value)
    return {"schemaVersion": 2, "fixture": "android-candidate-documents-v1", "root": namespace["root"] + "/candidate-evidence",
            "entries": rows, "namespace": namespace,
            "absent": ["reader-1.2.3-42.aab", "store-metadata-1.2.3-42.zip", "validation-report-1.2.3-42.json"]}


def project_path_receipt():
    # Independent fixed protocol DATA from the accepted native plan.
    return json.loads('{"assetAuthorityCreated":false,"cancel":[{"field":"version.source","operation":3},{"field":"metadata.root","operation":7}],"draft":{"baselineUnchanged":true,"positivePatchMatched":true,"previews":3,"refusalsUnchanged":true,"xcodePairRetained":true},"fixture":"project-paths-v1","fixtureMutations":{"actorReturned":4,"newWorker":false},"gate":"installed-project-profile","originals":{"childNew":2,"childReturned":9,"coordinatorReturned":11,"failedJoins":0,"filenameReads":9,"guiSettled":11,"sourceClosed":8,"sourceUnstarted":3},"projectOriginalsSettled":true,"quit":{"exit":true,"operation":14,"originalsSettled":true,"relayJoined":true},"refused":[{"case":"outside","code":"project_path_unsafe","operation":9},{"case":"post-selection-symlink","code":"project_path_unsafe","operation":10},{"case":"post-selection-directory-for-file","code":"project_path_unsafe","operation":11},{"case":"post-selection-file-for-directory","code":"project_path_unsafe","operation":12},{"case":"changed-root-mode","code":"project_path_changed","operation":13}],"registryUnchanged":true,"requestResultDomMatched":11,"saveRequests":0,"schemaVersion":1,"scope":"point-in-time-path-metadata-only","select":[{"field":"version.source","operation":4,"relativePath":"inputs/VERSION"},{"field":"ios.project","operation":5,"relativePath":"ios/Example.xcodeproj"},{"field":"ios.workspace","operation":6,"relativePath":"ios/Example.xcworkspace"},{"field":"metadata.root","operation":8,"relativePath":"metadata"}]}')



def path_capture(receipt=None):
    return (b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n"
            + b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n"
            + b"MRK_INSTALLED_SHELL_PROJECT_PATHS=" + L.canonical(project_path_receipt() if receipt is None else receipt)
            + b"MRK_INSTALLED_SHELL_OBSERVATION=project-paths-verified\n", b"")


PATH_FIXTURE_NODES = (
    ("path-project", True), ("path-project/inputs", True), ("path-project/inputs/VERSION", False),
    ("path-project/inputs/link-input", False), ("path-project/inputs/kind-input", False), ("path-project/inputs/kind-directory", True),
    ("path-project/ios", True), ("path-project/ios/Example.xcodeproj", True), ("path-project/ios/Example.xcworkspace", True),
    ("path-project/ios/Kind.xcodeproj", True), ("path-project/ios/Kind.file", False), ("path-project/metadata", True),
    ("path-outside", True), ("path-outside/VERSION", False),
)


def path_fixture_data(value, *, changed=False):
    moves = {3: "path-project/inputs/link-original", 4: "path-project/inputs/kind-original", 5: "path-project/inputs/kind-input",
             9: "path-project/ios/Kind.original", 10: "path-project/ios/Kind.xcodeproj"}
    names = [(moves.get(i, name) if changed else name, kind) for i, (name, kind) in enumerate(PATH_FIXTURE_NODES)]
    all_names = [name for name, _ in names] + (["path-project/inputs/link-input"] if changed else [])
    rows = []
    for index, (name, directory) in enumerate(names):
        children = sorted(Path(child).name for child in all_names if str(Path(child).parent) == name)
        nlink = 2 + sum(is_directory and str(Path(child).parent) == name for child, is_directory in names) if directory else 1
        mode = stat.S_IFDIR | (0o500 if changed and index == 0 else 0o700) if directory else stat.S_IFREG | 0o600
        modified = changed and index in (1, 6)
        identity = [1, 300 + index, mode, value["runnerUid"], value["runnerGid"], nlink, 4096 if directory else 26,
                    22 if modified else 11, 22 if changed and (index in (0, 1, 6) or index in moves) else 11]
        row = {"path": name, "kind": "directory" if directory else "file", "identity": identity}
        row.update({"children": children} if directory else {"size": 26, "sha256": "b6443459323e40905f046fab46eb17047c7720b9dcd1931d5f6eac0ccd27785f"})
        rows.append(row)
    if changed:
        rows.append({"path": "path-project/inputs/link-input", "kind": "symlink",
                     "identity": [1, 314, stat.S_IFLNK | 0o777, value["runnerUid"], value["runnerGid"], 1, 13, 22, 22], "target": "link-original"})
    absent = ["path-project/.gitignore", "path-project/release", "path-project/.mobile-release",
              "path-project/.mobile-release-init-prepare", "path-project/.mobile-release-init", "path-project/.mobile-release-init-cleanup",
              "path-project/.mobile-release-metadata-text-prepare", "path-project/.mobile-release-metadata-text", "path-project/.mobile-release-metadata-text-cleanup",
            "path-project/.mobile-release-version-prepare", "path-project/.mobile-release-version", "path-project/.mobile-release-version-cleanup"]
    absent += ["path-project/inputs/kind-directory", "path-project/ios/Kind.file"] if changed else [
        "path-project/inputs/link-original", "path-project/inputs/kind-original", "path-project/ios/Kind.original"]
    namespace = fixture_namespace_data(value)
    return {"schemaVersion": 2, "fixture": "project-paths-v1", "root": namespace["root"], "changed": changed,
            "entries": rows, "absent": absent, "namespace": namespace}


def workflow_capture():
    return (b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n"
            + b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n"
            + L.SHELL_WORKFLOW_MARKER + L.canonical(L.SHELL_WORKFLOW_RECEIPT)
            + b"MRK_INSTALLED_SHELL_OBSERVATION=workflow-apply-verified\n", b"")


def session_capture(case, receipt=None, *, expected=None, maps=None):
    observed = deepcopy(L.SHELL_SESSION_RECEIPTS[case]) if receipt is None else receipt
    expected = map_data() if expected is None else expected
    rows = [{"role": role, "path": row["paths"][0], **{key: row[key] for key in ("deviceMajor", "deviceMinor", "inode")}}
            for role, row in sorted(expected.items())]
    maps = [rows] * L.SHELL_SESSION_RECEIPTS[case]["behavior"]["assessments"] if maps is None else maps
    return (b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n"
            b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n"
            + b"".join(L.CHILD_MARKER.encode("ascii") + L.canonical(rows) for rows in maps)
            + L.SHELL_SESSION_MARKER + L.canonical(observed)
            + b"MRK_INSTALLED_SHELL_OBSERVATION=" + case.encode("ascii") + b"-verified\n", b"")


def workflow_fixture_data(value, *, installed=False):
    """Finite synthetic before/after DATA; no fixture construction or renderer."""
    owner = (value["runnerUid"], value["runnerGid"])
    callers = (".github/workflows/mobile-preflight.yml", ".github/workflows/mobile-candidate.yml",
               ".github/workflows/mobile-external-testing.yml", ".github/workflows/mobile-production-submit.yml")
    selected = callers if installed else callers[:1]
    directories = ((".", 0o700, owner, 4, [".github", ".gitignore", "app", "version.properties"]),
                   ("app", 0o555, (0, 0), 2, ["build.gradle.kts"]),
                   (".github", 0o700, owner, 3, ["workflows"]),
                   (".github/workflows", 0o700, owner, 2, sorted([Path(name).name for name in selected] + ["unrelated.yml"])))
    rows = []
    for index, (name, mode, owners, links, children) in enumerate(directories):
        stamp = 22 if installed and name in (".", ".github/workflows") else 11
        rows.append({"path": name, "kind": "directory", "children": children,
                     "identity": [1, 400 + index, stat.S_IFDIR | mode, *owners, links, 4096, stamp, stamp]})
    files = [("app/build.gradle.kts", L.SHELL_PROJECT_SOURCE, 0o444, (0, 0)),
             ("version.properties", L.SHELL_PROJECT_VERSION, 0o600, owner),
             (".gitignore", L.SHELL_WORKFLOW_IGNORE, 0o640, owner),
             (".github/workflows/unrelated.yml", L.SHELL_WORKFLOW_SIBLING, 0o600, owner),
             *((name, L.SHELL_WORKFLOW_CALLERS[name], 0o640 if index == 0 else 0o600, owner)
               for index, name in enumerate(selected))]
    for index, (name, raw, mode, owners) in enumerate(files):
        stamp = 22 if index >= 5 else 11
        rows.append({"path": name, "kind": "file", "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                     "identity": [1, 404 + index, stat.S_IFREG | mode, *owners, 1, len(raw), stamp, stamp]})
    absent = ["release", ".mobile-release", ".mobile-release-init-prepare", ".mobile-release-init", ".mobile-release-init-cleanup",
              ".mobile-release-metadata-text-prepare", ".mobile-release-metadata-text", ".mobile-release-metadata-text-cleanup",
            ".mobile-release-version-prepare", ".mobile-release-version", ".mobile-release-version-cleanup"]
    namespace = fixture_namespace_data(value)
    return {"schemaVersion": 1, "fixture": "android-workflow-apply-v1", "root": namespace["root"] + "/workflow-project",
            "installed": installed, "entries": rows, "absent": absent + ([] if installed else list(callers[1:])), "namespace": namespace}


def metadata_receipt_data():
    """Independent fixed expected DATA, not native finality or Save authority."""
    return {
        "schemaVersion": 1, "fixture": "android-metadata-save-v1", "gate": "installed-metadata-profile",
        "project": {"cancelSettled": True, "registered": True, "snapshot": True},
        "requests": {"observe": 2, "validate": 1, "open": 2, "prepare": 2, "apply": 1, "close": 1,
                     "configuration": [0, 0, 0, 0], "workflow": [0, 0, 0, 0]},
        "draft": {"revision": 2, "baselineGeneration": 0, "wholeMatched": True,
                  "retainedAfterClose": True, "browserEdit": "insertText"},
        "reviews": {"fullText": 2, "actions": [1, 1, 1], "distinctOriginals": True, "configBlocked": 2},
        "confirmation": {"opened": 1, "initiallyDisabled": True, "checkboxOnlyDisabled": True,
                         "typedSave": True, "acknowledged": True},
        "outcomes": [["not_started", "not_created", "settled", "cancelled"], ["committed", "clean", "settled", "none"]],
        "nativeReasons": ["discarded", "none"],
        "originals": {"sessions": 2, "writerFrames": [2, 3], "stdoutFrames": [3, 3],
                      "startupJoined": 2, "childWaited": 2, "ioSettled": 2, "ownersJoined": 2,
                      "runtimeLedgerSettled": 2, "runtimeSettlementJoined": 2},
        "readback": {"planMatched": True, "savedBaseline": True, "originalObservation": True},
        "quit": {"operation": 3, "gtkSettled": True, "originalsSettled": True, "relayJoined": True, "exit": True},
    }


def metadata_capture(receipt=None):
    return (b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n"
            + b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n"
            + b"MRK_INSTALLED_SHELL_METADATA_SAVE=" + L.canonical(metadata_receipt_data() if receipt is None else receipt)
            + b"MRK_INSTALLED_SHELL_OBSERVATION=metadata-save-verified\n", b"")


def metadata_fixture_data(value, *, saved=False):
    """Finite synthetic originals and one replacement/create; never a writer."""
    owner = (value["runnerUid"], value["runnerGid"])
    locale = "release/store/android/en-US"
    names = ["keep.txt", "short_description.txt", "title.txt"]
    directories = ((".", 0o700, owner, 4, [".gitignore", "app", "release", "version.properties"]),
                   ("app", 0o555, (0, 0), 2, ["build.gradle.kts"]),
                   ("release", 0o700, owner, 3, ["mobile-release.json", "store"]),
                   ("release/store", 0o700, owner, 3, ["android"]),
                   ("release/store/android", 0o700, owner, 3, ["en-US"]),
                   (locale, 0o700, owner, 2, ["full_description.txt", *names] if saved else names))
    rows = []
    for index, (name, mode, owners, links, children) in enumerate(directories):
        stamp = 22 if saved and name in (".", locale) else 11
        rows.append({"path": name, "kind": "directory", "children": children,
                     "identity": [1, 500 + index, stat.S_IFDIR | mode, *owners, links, 4096, stamp, stamp]})
    files = [("app/build.gradle.kts", L.SHELL_PROJECT_SOURCE, 0o444, (0, 0)),
             ("version.properties", L.SHELL_PROJECT_VERSION, 0o600, owner),
             (".gitignore", L.SHELL_PROJECT_IGNORE, 0o600, owner),
             ("release/mobile-release.json", L.SHELL_PROJECT_CONFIG, 0o600, owner),
             (locale + "/title.txt", b"Public title", 0o600, owner),
             (locale + "/short_description.txt", b"Public summary" if saved else b"Old summary", 0o600, owner),
             (locale + "/keep.txt", b"untouched\n", 0o600, owner)]
    if saved:
        files.append((locale + "/full_description.txt", b"Public description", 0o600, owner))
    for index, (name, raw, mode, owners) in enumerate(files):
        replaced = saved and name == locale + "/short_description.txt"
        stamp = 22 if replaced or index == 7 else 11
        rows.append({"path": name, "kind": "file", "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                     "identity": [1, 514 if replaced else 506 + index, stat.S_IFREG | mode, *owners, 1, len(raw), stamp, stamp]})
    absent = [".mobile-release", ".mobile-release-init-prepare", ".mobile-release-init", ".mobile-release-init-cleanup",
              ".mobile-release-metadata-text-prepare", ".mobile-release-metadata-text", ".mobile-release-metadata-text-cleanup",
            ".mobile-release-version-prepare", ".mobile-release-version", ".mobile-release-version-cleanup"]
    namespace = fixture_namespace_data(value)
    return {"schemaVersion": 1, "fixture": "android-metadata-save-v1", "root": namespace["root"] + "/metadata-project",
            "saved": saved, "entries": rows, "absent": absent + ([] if saved else [locale + "/full_description.txt"]), "namespace": namespace}


def version_receipt_data():
    """Independent expected DATA only, never proof of native execution."""
    return {'confirmation': {'acknowledged': 3,
                      'checkboxOnlyDisabled': 3,
                      'initiallyDisabled': 3,
                      'opened': 3,
                      'typedSave': 3},
     'domain': 'release_version',
     'draft': {'bindings': [[2, 0], [4, 1], [4, 2]], 'browserEdit': 'insertText', 'wholeMatched': True},
     'filesystem': {'afterModes': [384, 384, 384],
                    'parents': 2,
                    'preserveFull9': True,
                    'preservedFiles': 3,
                    'replaceIdentityChanged': True},
     'fixture': 'release-version-save-v1',
     'gate': 'installed-version-profile',
     'lateSettled': [False, False, False],
     'nativeFinality': ['settled', 'settled', 'settled'],
     'nativeReasons': ['none', 'none', 'none'],
     'originals': {'childWaited': 3,
                   'ioSettled': 3,
                   'ownersJoined': 3,
                   'runtimeLedgerSettled': 3,
                   'runtimeSettlementJoined': 3,
                   'sessions': 3,
                   'startupJoined': 3,
                   'stdoutFrames': [3, 3, 3],
                   'writerFrames': [3, 3, 3]},
     'outcomes': [['committed', 'clean', 'settled', 'none'],
                  ['committed', 'clean', 'settled', 'none'],
                  ['unchanged', 'not_created', 'settled', 'none']],
     'project': {'cancelSettled': True, 'registered': True, 'snapshot': True},
     'quit': {'exit': True, 'gtkSettled': True, 'operation': 3, 'originalsSettled': True, 'relayJoined': True},
     'readback': {'originalObservations': 3,
                  'planMatched': 3,
                  'savedBaseline': 3,
                  'values': [['1.2.3', 7], ['2.3.4', 8], ['2.3.4', 8]]},
     'requests': {'apply': 3,
                  'close': 0,
                  'configuration': [0, 0, 0, 0],
                  'metadata': [0, 0, 0, 0],
                  'observe': 3,
                  'open': 3,
                  'prepare': 3,
                  'workflow': [0, 0, 0, 0]},
     'reviews': {'actions': ['create', 'replace', 'preserve'],
                 'configBlocked': 3,
                 'distinctOriginals': True,
                 'distinctPlans': True,
                 'fullText': 3},
     'schemaVersion': 1}


def version_capture(receipt=None):
    return (b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n"
            + b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n"
            + b"MRK_INSTALLED_SHELL_VERSION_SAVE=" + L.canonical(version_receipt_data() if receipt is None else receipt)
            + b"MRK_INSTALLED_SHELL_OBSERVATION=version-save-verified\n", b"")


def version_fixture_data(value, *, saved=False):
    """Finite DATA with an absent source followed by the final replacement."""
    owner = (value["runnerUid"], value["runnerGid"])
    rows = []
    for index, (name, links, children) in enumerate((
        (".", 3, [".gitignore", "release", "unrelated.txt", "version.properties"] if saved
         else [".gitignore", "release", "unrelated.txt"]),
        ("release", 2, ["mobile-release.json"]),
    )):
        stamp = 22 if saved and name == "." else 11
        rows.append({"path": name, "kind": "directory", "children": children,
                     "identity": [1, 600 + index, stat.S_IFDIR | 0o700, *owner, links, 4096, stamp, stamp]})
    files = [(".gitignore", L.SHELL_PROJECT_IGNORE), ("release/mobile-release.json", L.SHELL_PROJECT_CONFIG),
             ("unrelated.txt", b"keep unrelated version fixture data\n")]
    if saved:
        files.append(("version.properties", b"VERSION_NAME=2.3.4\nBUILD_NUMBER=8\n"))
    for index, (name, raw) in enumerate(files):
        stamp = 22 if name == "version.properties" else 11
        rows.append({"path": name, "kind": "file", "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                     "identity": [1, 602 + index, stat.S_IFREG | 0o600, *owner, 1, len(raw), stamp, stamp]})
    absent = [".mobile-release", ".mobile-release-init-prepare", ".mobile-release-init", ".mobile-release-init-cleanup",
              ".mobile-release-metadata-text-prepare", ".mobile-release-metadata-text", ".mobile-release-metadata-text-cleanup",
              ".mobile-release-version-prepare", ".mobile-release-version", ".mobile-release-version-cleanup"]
    namespace = fixture_namespace_data(value)
    return {"schemaVersion": 1, "fixture": "release-version-save-v1", "root": namespace["root"] + "/version-project",
            "saved": saved, "entries": rows, "absent": absent + ([] if saved else ["version.properties"]), "namespace": namespace}


def tools_offline_receipt(case):
    """Fictional closed protocol DATA; no host executable or owner is invoked."""
    offline, cancel = case.startswith("offline-"), case in ("tools-cancel", "offline-cancel")
    context = {"projectId": "inert_project", "draftRevision": 1, "baselineGeneration": 0,
               "platform": "android", "operation": "offline-preflight" if offline else "build"}
    if offline:
        config = L.SHELL_TOOLS_OFFLINE_CONFIGS[case]
        context["savedConfig"] = {"bytes": len(config), "sha256": hashlib.sha256(config).hexdigest()}
    original = {key: True for key in ("inspectionJoined", "acquisitionJoined", "attempted", "childWaitedSuccess", "stdinClosed",
        "stdoutEofClosed", "stderrEofClosed", "ioJoined", "coreLifetimeSettled", "runtimeLedgerSettled", "runtimeSettlementJoined",
        "driverJoined", "managerJoined", "observerJoined", "watchdogJoined", "retiredBeforeCutoff")}
    original.update(domain="offline" if offline else "tools", id="a" * 32, generation="b" * 32,
                    noChild=False, activeRetained=False, resourceUnknown=False)
    if case == "tools-cancel":
        original.update({key: False for key in ("acquisitionJoined", "attempted", "childWaitedSuccess", "stdinClosed", "stdoutEofClosed",
                                               "stderrEofClosed", "coreLifetimeSettled")})
        original["noChild"] = True
    outcome, reason = (("cancelled", "cancelled") if cancel else ("refused", "saved-config-changed") if case == "offline-drift"
                       else ("complete", "none"))
    terminal = {"ownerGeneration": "b" * 32, "context": context, "phase": "terminal" if offline else "settled",
                "outcome": outcome, "reason": reason, "result": None}
    terminal.update({"operationId": "a" * 32, "intentUsable": False} if offline else {"runId": "a" * 32, "finality": "settled"})
    if outcome == "complete" and not offline:
        checks = [{"id": role, "state": "completed", "reason": "observed", "version": "2.43.0" if role == "git" else "17.0.16",
            "build": None, "returnCode": 0, "baseline": {"kind": "no-local-policy" if role == "git" else "workflow-reference",
                "version": None if role == "git" else "21", "build": None}, "assessment": "no-local-policy", "help": "Fixed core explanation"}
            for role in ("git", "java", "javac")]
        terminal["result"] = {"schemaVersion": 1, "policyVersion": "environment-diagnostics-v1", "context": deepcopy(context),
            "hostPlatform": "linux", "outcome": "complete", "checks": checks, "commandsAttempted": 3,
            "lifetime": {"complete": True, "fatal": False, "contained": True, "commandDispatched": True, "commands": 3,
                "inputClosed": True, "handlersRestored": True, "toolDescriptorsClosed": True, "stopObserved": "none"},
            "assurance": {"basis": "local-tool-observation", "toolsAttempted": True, "projectCodeExecuted": False, "projectFilesRead": False,
                "repositoryObserved": False, "sdkInspected": False, "credentialsRead": False, "storeContacted": False,
                "dependencyCompleteness": "unknown", "releaseReadiness": "unknown", "toolCacheEffects": "possible"}}
    elif outcome == "complete":
        negative = case == "offline-negative"
        counts = {status: 0 for status in ("PASS", "FAIL", "MISSING", "BLOCKED", "INVALID", "SKIP", "MANUAL", "CONFIGURED", "NOT_APPLICABLE")}
        counts.update(PASS=1 if negative else 2, FAIL=1 if negative else 0)
        terminal["result"] = {"schemaVersion": 1, "scope": "saved-offline-android-no-core-build", "usedConfig": deepcopy(context["savedConfig"]),
            "findings": [{"ordinal": 0, "check": "version-source", "status": "PASS", "message": "version-source", "projectCheckIndex": None},
                         {"ordinal": 1, "check": "configured-project-check", "status": "FAIL" if negative else "PASS",
                          "message": "configured-project-check", "projectCheckIndex": 0}],
            "summary": {"total": 2, "shown": 2, "omitted": 0, "counts": counts},
            "limitations": ["saved-inputs-not-atomic", "project-code-effects-possible", "not-network-isolated", "core-builds-disabled",
                "artifact-validation-not-requested", "toolkit-signing-credentials-store-not-requested", "release-readiness-not-assessed"]}
    boundary = "inspection" if case == "tools-cancel" else "settlement" if case in ("tools-settlement", "offline-settlement") else "none"
    trace = "pass\n" if case in ("offline-pass", "offline-settlement") else "exit-7\n" if case == "offline-negative" else "active\n" if case == "offline-cancel" else ""
    return {"schema": "installed-tools-offline-v1", "case": case, "qualificationOnly": True, "builder": "normal", "projectPicker": True,
        "savedObservation": True, "requests": {"toolsStart": 0 if offline else 1, "toolsCancel": 1 if case == "tools-cancel" else 0,
            "offlinePrepare": 1 if offline else 0, "offlineStart": 1 if offline else 0, "offlineCancel": 1 if case == "offline-cancel" else 0},
        "initial": {"toolsAvailable": True, "offlineAvailable": True}, "ui": {"start": True, "consent": offline, "terminal": True, "cancel": cancel},
        "reciprocalBusy": case in ("tools-settlement", "offline-cancel", "offline-settlement"),
        "hold": {"boundary": boundary, "entered": boundary != "none", "released": boundary != "none"},
        "original": original, "terminal": terminal, "fixture": {"scriptTrace": trace, "laterTrace": "", "savedConfigChanged": case == "offline-drift"}}


def tools_offline_fixture_data(value, case, *, after=False):
    namespace = fixture_namespace_data(value)
    roster = L._shell_tools_offline_roster(value, case, after)
    offset = 1000 + 100 * L.SHELL_TOOLS_OFFLINE_CASES.index(case)
    rows = []
    for index, (name, mode, owners, expected) in enumerate(roster):
        directory = stat.S_ISDIR(mode)
        changed = after and (name == "project/release/mobile-release.json" and case == "offline-drift"
                             or name == "project/script.trace" and bool(L.SHELL_TOOLS_OFFLINE_TRACES[case]))
        size = 4096 if directory else len(expected)
        links = 2 + sum(stat.S_ISDIR(m) and n != "." and str(Path(n).parent) == name for n, m, _, _ in roster) if directory else 1
        row = {"path": name, "kind": "directory" if directory else "file",
               "identity": [1, offset + index, mode, *owners, links, size, 22 if changed else 11, 22 if changed else 11]}
        row.update({"children": expected} if directory else {"size": size, "sha256": hashlib.sha256(expected).hexdigest()})
        rows.append(row)
    return {"schemaVersion": 1, "fixture": "installed-tools-offline-fixture-v1", "case": case, "root": namespace["root"] + "/" + case,
            "changed": after and case.startswith("offline-"), "entries": rows, "absent": list(L.SHELL_TOOLS_OFFLINE_ABSENT), "namespace": namespace}


def tools_offline_capture(case, receipt=None):
    return (b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n"
            + b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n"
            + b"MRK_INSTALLED_SHELL_TOOLS_OFFLINE=" + L.canonical(tools_offline_receipt(case) if receipt is None else receipt)
            + b"MRK_INSTALLED_SHELL_OBSERVATION=" + case.encode("ascii") + b"-verified\n", b"")


def settled_failure_capture():
    # Fixed synthetic parser DATA; never native execution/finality evidence.
    return (b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n"
            + b"MRK_INSTALLED_SHELL_FAILURE_STEP=SettledFailure\n"
            + b"MRK_INSTALLED_SHELL_FAILURE_PHASE=dom\n"
            + b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n"
            + b"MRK_INSTALLED_SHELL_FAILURE_HANDOFF=original-quit-relay-loop-returned\n"
            + b"MRK_INSTALLED_SHELL_OBSERVATION=failed\n", b"")


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
                    + L.CHILD_MARKER.encode() + L.canonical(maps) + b"MRK_INSTALLED_SHELL_OBSERVATION=quit-outstanding-verified\n", b""),
                "project-paths": path_capture(), "workflow-apply": workflow_capture(),
                **{case: session_capture(case, expected=expected) for case in L.SHELL_SESSION_CASES}, "metadata-save": metadata_capture(),
                **{case: tools_offline_capture(case) for case in L.SHELL_TOOLS_OFFLINE_CASES},
                "settled-failure": settled_failure_capture(), "version-save": version_capture()}
    cases, files, commands = {}, {}, []
    for case, (stdout, stderr) in captures.items():
        code = 1 if case == "settled-failure" else 0
        cases[case] = L.shell_result(stdout, stderr, case, code, expected,
                                    failure_labels=L.SHELL_SETTLED_FAILURE_LABELS if case == "settled-failure" else None)
        files["shell-" + case + ".stdout"], files["shell-" + case + ".stderr"] = stdout, stderr
        files["shell-" + case + "-xvfb.stderr"] = b"inert original display output\n"
        commands.append({"phase": "shell-" + case, "argv": L.shell_argv(value, case), "exitCode": code})
    files["shell-settled-failure-failure.labels"] = L.SHELL_SETTLED_FAILURE_LABELS
    files["shell-cases.json"] = L.canonical(cases)
    files["shell-positive-project-before.json"] = L.canonical(project_fixture_data(value))
    files["shell-positive-project-after.json"] = L.canonical(project_fixture_data(value, saved=True))
    for phase in ("before", "after"):
        files["shell-positive-candidate-" + phase + ".json"] = L.canonical(candidate_fixture_data(value))
        files["shell-project-paths-" + phase + ".json"] = L.canonical(path_fixture_data(value, changed=phase == "after"))
        files["shell-workflow-apply-" + phase + ".json"] = L.canonical(workflow_fixture_data(value, installed=phase == "after"))
        for case in L.SHELL_SESSION_CASES:
            files["shell-" + case + "-" + phase + ".json"] = L.canonical(
                session_fixture_data(value, case, changed=phase == "after" and case == "session-refusals"))
        files["shell-metadata-save-" + phase + ".json"] = L.canonical(metadata_fixture_data(value, saved=phase == "after"))
        files["shell-version-save-" + phase + ".json"] = L.canonical(version_fixture_data(value, saved=phase == "after"))
        for case in L.SHELL_TOOLS_OFFLINE_CASES:
            files["shell-" + case + "-" + phase + ".json"] = L.canonical(tools_offline_fixture_data(value, case, after=phase == "after"))
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


class ShellFixtureNamespaceContracts(unittest.TestCase):
    def test_readable_ancestry_preserves_control_private_and_only_stable_identity(self):
        value = installed_handoff(); value.pop("installed"); value["shell"] = {}
        namespace = fixture_namespace_data(value); root = L.root_path(value)
        expected = {key: namespace[key] for key in ("control", "ancestors")}
        for fault in (None, "unreadable", "writable", "control-mode", "private-mode", "owner", "device", "alias", "symlink", "drift", "acl"):
            nodes = {Path(row["path"]): inert_stat(row["identity"][1], row["identity"][2])
                     for row in [namespace["control"], *namespace["ancestors"]]}
            nodes[root / "private"] = inert_stat(6, stat.S_IFDIR | 0o700)
            if fault == "unreadable": nodes[Path("/var/lib")].st_mode = stat.S_IFDIR | 0o711
            if fault == "writable": nodes[Path("/var")].st_mode = stat.S_IFDIR | 0o777
            if fault == "control-mode": nodes[root].st_mode = stat.S_IFDIR | 0o755
            if fault == "private-mode": nodes[root / "private"].st_mode = stat.S_IFDIR | 0o711
            if fault == "owner": nodes[Path("/var/lib")].st_uid = value["runnerUid"]
            if fault == "device": nodes[root].st_dev = 2
            if fault == "alias": nodes[root].st_ino = 3
            if fault == "symlink": nodes[Path("/var")].st_mode = stat.S_IFLNK | 0o755
            observed = []
            def metadata(path):
                observed.append(path); node = deepcopy(nodes[path])
                # Legitimate sibling/control activity is not stable authority.
                node.st_nlink += len(observed); node.st_size += len(observed)
                node.st_mtime_ns += len(observed); node.st_ctime_ns += len(observed)
                if fault == "drift" and path == root and observed.count(root) == 2: node.st_ino += 100
                return node
            with self.subTest(fault=fault), patch.object(L, "_ROOT", root), patch.object(Path, "lstat", metadata), \
                 patch.object(L, "_xattrs", side_effect=L.Refused("inert ACL") if fault == "acl" else None) as attrs, \
                 patch.object(L.os, "scandir", side_effect=AssertionError("No private/fixture scan")):
                if fault is None:
                    self.assertEqual(L._shell_fixture_ancestry(value), expected)
                    self.assertEqual([call.args for call in attrs.call_args_list],
                                     [(path, True) for path in (Path("/"), Path("/var"), Path("/var/lib"), root, root / "private")])
                else:
                    with self.assertRaises(ValueError): L._shell_fixture_ancestry(value)

    def test_constructor_exact_fixed_bytes_then_original_publication_or_refusal(self):
        value = installed_handoff(); value.pop("installed"); value["shell"] = {}
        namespace = fixture_namespace_data(value); root = Path(namespace["root"])
        ancestry = {key: namespace[key] for key in ("control", "ancestors")}
        for fault in (None, "occupied", "mode", "owner", "device", "alias", "acl", "leaf-acl", "metadata-acl", "metadata-leaf-acl", "version-acl", "version-leaf-acl",
                      "write", "unknown-child", "identity", "ancestry", "published-identity"):
            node = inert_stat(5, stat.S_IFDIR | 0o700, size=4096, stamp=11)
            if fault == "mode": node.st_mode = stat.S_IFDIR | 0o755
            if fault == "owner": node.st_uid = value["runnerUid"]
            if fault == "device": node.st_dev = 2
            if fault == "alias": node.st_ino = 4
            created = []
            def mkdir(path, *, mode):
                self.assertEqual(mode, 0o700)
                if fault == "occupied" and path == root: raise FileExistsError("inert occupied sibling")
                created.append(path)
                if path.parent == root: node.st_nlink += 1
            def metadata(path):
                self.assertEqual(path, root)
                current = deepcopy(node)
                if fault == "identity" and len(created) > 1: current.st_ino += 100
                if fault == "published-identity" and stat.S_IMODE(node.st_mode) == 0o755: current.st_ino += 100
                return current
            def chmod(path, mode):
                self.assertIn((path, mode), ((root / "positive-project/app", 0o555),
                    (root / "workflow-project/.github/workflows", 0o700), (root / "workflow-project/.github", 0o700),
                    (root / "workflow-project/app", 0o555), (root / "workflow-project", 0o700),
                    (root / "metadata-project/release/store/android/en-US", 0o700), (root / "metadata-project/release/store/android", 0o700),
                    (root / "metadata-project/release/store", 0o700), (root / "metadata-project/release", 0o700),
                    (root / "metadata-project/app", 0o555), (root / "metadata-project", 0o700),
                    (root / "version-project/release", 0o700), (root / "version-project", 0o700), (root, 0o755)))
                if path == root: node.st_mode = stat.S_IFDIR | mode
            def attrs(path, directory):
                if (fault == "acl" and path == root or fault == "leaf-acl" and path == root / "path-outside/VERSION"
                        or fault == "metadata-acl" and path == root / "metadata-project/release/store/android/en-US"
                        or fault == "metadata-leaf-acl" and path == root / "metadata-project/release/store/android/en-US/short_description.txt"
                        or fault == "version-acl" and path == root / "version-project/release"
                        or fault == "version-leaf-acl" and path == root / "version-project/unrelated.txt"):
                    raise L.Refused("inert ACL")
            def scan(path):
                self.assertEqual(path, root)
                names = [p.name for p in created if p.parent == root]
                if fault == "unknown-child": names.insert(0, "unexpected")
                context = Mock(); context.__enter__ = Mock(return_value=iter(SimpleNamespace(name=n) for n in names))
                context.__exit__ = Mock(return_value=False); return context
            def ancestors(_):
                current = deepcopy(ancestry)
                if fault == "ancestry" and len(created) > 1: current["control"]["identity"][1] += 100
                return current
            writer = Mock(side_effect=OSError("inert write failure") if fault == "write" else None)
            with self.subTest(fault=fault), patch.object(L, "_ROOT", L.root_path(value)), \
                 patch.object(L, "_shell_fixture_ancestry", side_effect=ancestors), \
                 patch.object(Path, "mkdir", autospec=True, side_effect=mkdir) as making, \
                 patch.object(Path, "lstat", autospec=True, side_effect=metadata) as reading, \
                 patch.object(L, "_D", SimpleNamespace(write=writer)), patch.object(L.os, "chown") as ownership, \
                 patch.object(L.os, "chmod", side_effect=chmod) as modes, patch.object(L, "_xattrs", side_effect=attrs), \
                 patch.object(L.os, "scandir", side_effect=scan) as scans, patch.object(L.os, "symlink") as links:
                if fault is None:
                    binding = L._shell_fixtures_prepare(value)
                    self.assertIs(type(binding), bytes); self.assertEqual(L.decode(binding), namespace)
                    self.assertEqual(created, [root, root / "positive-project", root / "positive-project/app",
                        root / "candidate-evidence", root / "candidate-evidence/operation",
                        *(root / name for name, directory in PATH_FIXTURE_NODES if directory),
                        root / "workflow-project", root / "workflow-project/app", root / "workflow-project/.github",
                        root / "workflow-project/.github/workflows", root / "metadata-project", root / "metadata-project/app",
                        root / "metadata-project/release", root / "metadata-project/release/store",
                        root / "metadata-project/release/store/android", root / "metadata-project/release/store/android/en-US",
                        root / "version-project", root / "version-project/release",
                        *(root / case / name for case in L.SHELL_SESSION_CASES for name in (".", "project", "project/release", "sources")),
                        *(root / case / name for case in L.SHELL_TOOLS_OFFLINE_CASES
                          for name, mode, _, _ in L._shell_tools_offline_roster(value, case) if stat.S_ISDIR(mode))])
                    self.assertEqual([call.args for call in writer.call_args_list], [
                        (root / "positive-project/app/build.gradle.kts", L.SHELL_PROJECT_SOURCE, 0o444),
                        (root / "positive-project/version.properties", L.SHELL_PROJECT_VERSION, 0o600),
                        *((root / "candidate-evidence" / name, raw, 0o600) for name, raw in L.SHELL_CANDIDATE_DOCUMENTS.items()),
                        *((root / name, b"inert path-picker fixture\n", 0o600) for name, directory in PATH_FIXTURE_NODES if not directory),
                        (root / "workflow-project/app/build.gradle.kts", L.SHELL_PROJECT_SOURCE, 0o444),
                        (root / "workflow-project/version.properties", L.SHELL_PROJECT_VERSION, 0o600),
                        (root / "workflow-project/.gitignore", L.SHELL_WORKFLOW_IGNORE, 0o640),
                        (root / "workflow-project/.github/workflows/unrelated.yml", L.SHELL_WORKFLOW_SIBLING, 0o600),
                        (root / "workflow-project/.github/workflows/mobile-preflight.yml", L.SHELL_WORKFLOW_CALLERS[".github/workflows/mobile-preflight.yml"], 0o640),
                        (root / "metadata-project/app/build.gradle.kts", L.SHELL_PROJECT_SOURCE, 0o444),
                        (root / "metadata-project/version.properties", L.SHELL_PROJECT_VERSION, 0o600),
                        (root / "metadata-project/.gitignore", L.SHELL_PROJECT_IGNORE, 0o600),
                        (root / "metadata-project/release/mobile-release.json", L.SHELL_PROJECT_CONFIG, 0o600),
                        (root / "metadata-project/release/store/android/en-US/title.txt", b"Public title", 0o600),
                        (root / "metadata-project/release/store/android/en-US/short_description.txt", b"Old summary", 0o600),
                        (root / "metadata-project/release/store/android/en-US/keep.txt", b"untouched\n", 0o600),
                        (root / "version-project/.gitignore", L.SHELL_PROJECT_IGNORE, 0o600),
                        (root / "version-project/release/mobile-release.json", L.SHELL_PROJECT_CONFIG, 0o600),
                        (root / "version-project/unrelated.txt", b"keep unrelated version fixture data\n", 0o600),
                        *((root / case / name, data, stat.S_IMODE(mode)) for case in L.SHELL_SESSION_CASES
                          for name, mode, _, data in L._shell_session_roster(value, case) if stat.S_ISREG(mode)),
                        *((root / case / name, data, 0o600) for case in L.SHELL_TOOLS_OFFLINE_CASES
                          for name, mode, _, data in L._shell_tools_offline_roster(value, case) if stat.S_ISREG(mode))])
                    self.assertEqual([call.args for call in ownership.call_args_list], [
                        (path, value["runnerUid"], value["runnerGid"]) for path in
                        (root / "positive-project/version.properties", root / "positive-project",
                         *(root / "candidate-evidence" / name for name in L.SHELL_CANDIDATE_DOCUMENTS),
                         root / "candidate-evidence/operation", root / "candidate-evidence", *(root / name for name, _ in PATH_FIXTURE_NODES))] + [
                        (root / "workflow-project/app/build.gradle.kts", 0, 0),
                        *((root / "workflow-project" / name, value["runnerUid"], value["runnerGid"]) for name in
                          ("version.properties", ".gitignore", ".github/workflows/unrelated.yml", ".github/workflows/mobile-preflight.yml",
                           ".github/workflows", ".github")),
                        (root / "workflow-project/app", 0, 0), (root / "workflow-project", value["runnerUid"], value["runnerGid"]),
                        (root / "metadata-project/app/build.gradle.kts", 0, 0),
                        *((root / "metadata-project" / name, value["runnerUid"], value["runnerGid"]) for name in
                          ("version.properties", ".gitignore", "release/mobile-release.json", "release/store/android/en-US/title.txt",
                           "release/store/android/en-US/short_description.txt", "release/store/android/en-US/keep.txt",
                           "release/store/android/en-US", "release/store/android", "release/store", "release")),
                        (root / "metadata-project/app", 0, 0), (root / "metadata-project", value["runnerUid"], value["runnerGid"]),
                        *((root / "version-project" / name, value["runnerUid"], value["runnerGid"]) for name in
                          (".gitignore", "release/mobile-release.json", "unrelated.txt", "release", ".")),
                        *((root / case / name, *owners) for case in L.SHELL_SESSION_CASES
                          for name, _, owners, _ in L._shell_session_roster(value, case)),
                        *((root / case / name, *owners) for case in L.SHELL_TOOLS_OFFLINE_CASES
                          for name, _, owners, _ in L._shell_tools_offline_roster(value, case))])
                    links.assert_called_once_with("input.jks", root / "session-refusals/sources/link.jks")
                    self.assertTrue(all(call.kwargs == {"follow_symlinks": False} for call in ownership.call_args_list[-210:]))
                    self.assertEqual([call.args for call in modes.call_args_list], [(root / "positive-project/app", 0o555),
                        (root / "workflow-project/.github/workflows", 0o700), (root / "workflow-project/.github", 0o700),
                        (root / "workflow-project/app", 0o555), (root / "workflow-project", 0o700),
                        (root / "metadata-project/release/store/android/en-US", 0o700), (root / "metadata-project/release/store/android", 0o700),
                        (root / "metadata-project/release/store", 0o700), (root / "metadata-project/release", 0o700),
                        (root / "metadata-project/app", 0o555), (root / "metadata-project", 0o700),
                        (root / "version-project/release", 0o700), (root / "version-project", 0o700), (root, 0o755)])
                else:
                    with self.assertRaises((ValueError, OSError)): L._shell_fixtures_prepare(value)
                    publications = [call.args for call in modes.call_args_list if call.args[0] == root]
                    self.assertEqual(publications, [(root, 0o755)] if fault == "published-identity" else [])
                    if fault == "occupied":
                        making.assert_called_once_with(root, mode=0o700)
                        reading.assert_not_called(); scans.assert_not_called(); ownership.assert_not_called(); writer.assert_not_called()

    def test_original_namespace_drift_and_unexpected_names_refuse_without_descendant_reads(self):
        value = installed_handoff(); namespace = fixture_namespace_data(value); root = Path(namespace["root"])
        binding = L.canonical(namespace); ancestry = {key: namespace[key] for key in ("control", "ancestors")}
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        for fault in (None, *range(9), "unknown-child", "after-scan", "ancestry"):
            values = list(namespace["identity"])
            if type(fault) is int: values[fault] += 1
            node = SimpleNamespace(**dict(zip(fields, values))); scans_seen = []
            def metadata(path):
                self.assertEqual(path, root)
                current = deepcopy(node)
                if fault == "after-scan" and scans_seen: current.st_ctime_ns += 1
                return current
            def scan(path):
                self.assertEqual(path, root); scans_seen.append(path)
                names = ["unrelated"] if fault == "unknown-child" else namespace["children"]
                context = Mock(); context.__enter__ = Mock(return_value=iter(SimpleNamespace(name=n) for n in names))
                context.__exit__ = Mock(return_value=False); return context
            current_ancestry = deepcopy(ancestry)
            if fault == "ancestry": current_ancestry["control"]["identity"][1] += 1
            with self.subTest(fault=fault), patch.object(L, "_shell_fixture_ancestry", return_value=current_ancestry), \
                 patch.object(Path, "lstat", metadata), patch.object(L, "_xattrs"), patch.object(L.os, "scandir", side_effect=scan), \
                 patch.object(L, "record", side_effect=AssertionError("Namespace check cannot read a fixture leaf")):
                if fault is None: self.assertEqual(L._shell_namespace_check(value, binding), namespace)
                else:
                    with self.assertRaises(ValueError): L._shell_namespace_check(value, binding)
                if type(fault) is int or fault == "ancestry": self.assertEqual(scans_seen, [])
        with patch.object(L, "_shell_fixture_ancestry", side_effect=AssertionError("Malformed DATA cannot authorize filesystem observation")):
            for raw in (bytearray(binding), binding.decode(), binding + b" ", b"{}", b"x" * 2049):
                with self.subTest(kind=type(raw)), self.assertRaises(ValueError): L._shell_namespace_check(value, raw)

    def test_closed_namespaces_reject_old_shapes_wrong_authority_and_cross_family_mismatch(self):
        value, outcome, files, expected = closed_shell_data(); original = fixture_namespace_data(value)
        self.assertEqual(L._shell_namespace_data(value, original), original)
        for mutate in (lambda d: d.pop("control"), lambda d: d.update(root=str(L.root_path(value))),
                       lambda d: d.update(children=d["children"][:-1]), lambda d: d["identity"].__setitem__(2, stat.S_IFDIR | 0o711),
                       lambda d: d["identity"].__setitem__(0, 2), lambda d: d["identity"].__setitem__(1, 4),
                       lambda d: d["identity"].__setitem__(3, 1001), lambda d: d["identity"].__setitem__(5, True),
                       lambda d: d["identity"].__setitem__(8, -1), lambda d: d["identity"].append(0),
                       lambda d: d["control"].update(path="/other"), lambda d: d["control"]["identity"].append(0),
                       lambda d: d["control"]["identity"].__setitem__(2, stat.S_IFDIR | 0o755),
                       lambda d: d["ancestors"][0].update(path="/var"),
                       lambda d: d["ancestors"][1]["identity"].__setitem__(2, stat.S_IFDIR | 0o711)):
            altered = deepcopy(original); mutate(altered)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): L._shell_namespace_data(value, altered)
        families = ((L.shell_project_fixture, "shell-positive-project"), (L.shell_candidate_fixture, "shell-positive-candidate"),
                    (L.shell_paths_fixture, "shell-project-paths"), (L.shell_workflow_fixture, "shell-workflow-apply"),
                    (L.shell_metadata_fixture, "shell-metadata-save"), (L.shell_version_fixture, "shell-version-save"),
                    *((lambda value, before, after, case=case: L.shell_session_fixture(value, case, before, after),
                       "shell-" + case) for case in L.SHELL_SESSION_CASES),
                    *((lambda value, before, after, case=case: L.shell_tools_offline_fixture(value, case, before, after),
                       "shell-" + case) for case in L.SHELL_TOOLS_OFFLINE_CASES))
        for validate, prefix in families:
            for change in ("missing", "old-schema", "old-root", "binding-drift"):
                before, after = (L.decode(files[prefix + "-" + phase + ".json"]) for phase in ("before", "after"))
                if change == "missing": after.pop("namespace")
                elif change == "old-schema": after["schemaVersion"] -= 1
                elif change == "old-root": after["root"] = after["root"].replace("mrk-ubuntu-shell-fixtures-", "mrk-ubuntu-native-")
                else: after["namespace"]["identity"][1] = 50
                with self.subTest(family=prefix, change=change), self.assertRaises(ValueError):
                    validate(value, L.canonical(before), L.canonical(after))
        for validate, prefix in families[1:]:
            altered = dict(files)
            for phase in ("before", "after"):
                name = prefix + "-" + phase + ".json"; document = L.decode(altered[name])
                document["namespace"]["identity"][1] = 50; altered[name] = L.canonical(document)
            validate(value, altered[prefix + "-before.json"], altered[prefix + "-after.json"])
            with self.subTest(family=prefix), patch.object(L, "shell_closed_loader", return_value=expected), \
                 patch.object(L, "_shell_namespace_check", side_effect=AssertionError("Closed DATA is not live authority")), \
                 self.assertRaisesRegex(ValueError, "different original namespaces"):
                L.shell_closed_result(value, outcome, altered)

    def test_twenty_digit_roots_keep_existing_inventory_byte_caps(self):
        value = installed_handoff(); value.update(runId="9" * 20, attempt="9" * 20)
        namespace = fixture_namespace_data(value)
        self.assertEqual(str(L.shell_fixture_root(value)), namespace["root"])
        self.assertLess(len(L.canonical(namespace)), 2048)
        for document in (project_fixture_data(value), project_fixture_data(value, saved=True), candidate_fixture_data(value),
                         path_fixture_data(value), path_fixture_data(value, changed=True),
                         workflow_fixture_data(value), workflow_fixture_data(value, installed=True),
                         metadata_fixture_data(value), metadata_fixture_data(value, saved=True),
                         version_fixture_data(value), version_fixture_data(value, saved=True)):
            self.assertLessEqual(len(L.canonical(document)), 8192)
        for case in L.SHELL_TOOLS_OFFLINE_CASES:
            for after in (False, True):
                self.assertLessEqual(len(L.canonical(tools_offline_fixture_data(value, case, after=after))), 16 << 10)
        for field in ("runId", "attempt"):
            for bad in ("", "0", "01", "1-2", "9" * 21, 10, True):
                altered = dict(value); altered[field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(ValueError): L.shell_fixture_root(altered)

    def test_source_has_one_constructor_after_admission_and_postchecks_after_success(self):
        tree = ast.parse((SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_text())
        unit = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "unit_start")
        branch = next(n for n in unit.body if isinstance(n, ast.If) and ast.unparse(n.test) == "'shell' in value")
        loop = next(n for n in branch.body if isinstance(n, ast.For))
        self.assertEqual(ast.unparse(loop.iter), "shell_cases(value)")
        self.assertEqual(ast.unparse(branch.body[1]), "expected = _installed_payload(value, loader, original)")
        self.assertEqual(ast.unparse(branch.body[2]),
                         "github_expected = _shell_github_materials_prepare(value, loader, original, expected) if shell_github(value) else None")
        self.assertEqual(ast.unparse(branch.body[3]), "namespace = _shell_fixtures_prepare(value)")
        self.assertIsInstance(branch.body[4], ast.If)
        self.assertEqual(ast.unparse(branch.body[4].test), "shell_github(value)")
        self.assertIs(branch.body[5], loop)
        self.assertEqual(ast.unparse(branch.body[6]), "_shell_fixtures_final(value, namespace)")
        self.assertEqual(L.SHELL_CASES[9], "metadata-save")
        self.assertEqual(L.SHELL_CASES[-3:], ("offline-settlement", "settled-failure", "version-save"))
        self.assertEqual(ast.unparse(loop.body[0]), "environment, log_binding = _shell_prepare(value, case, namespace)")
        self.assertIsInstance(loop.body[1], ast.If)
        self.assertEqual(ast.unparse(loop.body[1].body[0]), "cases[case] = _shell_normal(value, environment, expected, log_binding)")
        self.assertEqual(ast.unparse(loop.body[-1]), "_shell_namespace_check(value, namespace)")
        self.assertFalse(any(isinstance(n, ast.Try) for n in ast.walk(branch)))
        calls = [n.func.id for n in ast.walk(unit) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
        self.assertEqual(calls.count("_shell_fixtures_prepare"), 1)
        prepare = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_shell_prepare")
        self.assertEqual(ast.unparse(prepare.body[0]), "_shell_namespace_check(value, namespace)")


class ProjectDraftLifecycleContracts(unittest.TestCase):
    def test_fixed_saved_bytes_are_derived_from_actual_pure_core_and_wire_order(self):
        # Import the actual in-memory functions only when this focused DATA
        # check is explicitly run. No lease, filesystem fixture, bootstrap or
        # native transaction is constructed. Production lifecycle imports none.
        from mobile_release.api._preview import suggest_config
        from mobile_release.api._release_version import _source_path
        from mobile_release.config_payloads import prepare_edit_ignore, serialize_config_data
        from mobile_release.discovery import parse_project_sources
        discovered = parse_project_sources({"app/build.gradle.kts": L.SHELL_PROJECT_SOURCE.decode("ascii"),
                                            "version.properties": L.SHELL_PROJECT_VERSION.decode("ascii")}, ("app",))
        hints = {"platforms": ["android"], "androidApplicationId": discovered["android"]["applicationId"],
                 **{key: discovered[key] for key in ("versionSource", "versionNameKey", "versionBuildKey")}}
        self.assertEqual(hints, {"platforms": ["android"], "androidApplicationId": "org.example.mrk.observed",
                                "versionSource": "version.properties", "versionNameKey": "VERSION_NAME", "versionBuildKey": "BUILD_NUMBER"})
        self.assertTrue(_source_path(hints["versionSource"]))  # Named-reader admission is pure; no file opens.
        proposed = suggest_config(hints)
        self.assertTrue(proposed["validation"]["valid"])
        provenance = {row["path"]: row["source"] for row in proposed["provenance"]}
        hinted = ("android.enabled", "android.applicationId", "version.source", "version.nameKey", "version.buildKey")
        self.assertEqual({path: provenance[path] for path in hinted}, dict.fromkeys(hinted, "hint"))
        self.assertEqual(L.SHELL_PROJECT_VERSION, b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n")
        self.assertEqual(len(L.SHELL_PROJECT_VERSION), 34)
        self.assertEqual(hashlib.sha256(L.SHELL_PROJECT_VERSION).hexdigest(), "a811da0677c243236101fb4aa93319d28b731f963f8a295c1028b8aee136386b")
        # serde_json::Value uses its default sorted-key Map; the fixed native
        # Prepare serializes that genuine renderer draft to the Python adapter.
        wire_draft = json.loads(json.dumps(proposed["draft"], sort_keys=True))
        self.assertEqual(serialize_config_data(wire_draft), L.SHELL_PROJECT_CONFIG)
        self.assertEqual(len(L.SHELL_PROJECT_CONFIG), L.SHELL_PROJECT_RECEIPT["readback"]["size"])
        self.assertEqual(hashlib.sha256(L.SHELL_PROJECT_CONFIG).hexdigest(), L.SHELL_PROJECT_RECEIPT["readback"]["sha256"])
        ignored, additions = prepare_edit_ignore(b"")
        self.assertEqual(ignored, L.SHELL_PROJECT_IGNORE)
        self.assertEqual(len(additions), 10)
        self.assertEqual(prepare_edit_ignore(ignored), (ignored, ()))

    def test_shell_fixture_roster_fits_shell_only_cap_without_changing_aggregate_or_other_profiles(self):
        value, _, _, _ = closed_shell_data()
        # The namespace exists before every old session/Tools/Offline original,
        # so its shared Rust roster and both finite link bounds must agree.
        native = (SOURCE / "desktop/src-tauri/src/installed_shell_observation.rs").read_text()
        tools_native = (SOURCE / "desktop/src-tauri/src/installed_tools_observation.rs").read_text()
        marker = "const SESSION_FIXTURE_NAMESPACE: [&str; "
        self.assertEqual(native.count(marker), 1)
        declared, entries = native.split(marker, 1)[1].split("] = [", 1)
        names = tuple(json.loads("[" + entries.split("];", 1)[0].strip().removesuffix(",") + "]"))
        self.assertEqual((int(declared), len(names), len(set(names))), (19, 19, 19))
        self.assertEqual(names, L.SHELL_FIXTURE_CHILDREN)
        namespace = fixture_namespace_data(value)
        self.assertEqual(namespace["children"], list(names))
        self.assertEqual(namespace["identity"][5], len(names) + 2)
        session_capture = native.split("impl SessionFixture {", 1)[1].split("    fn namespace_unchanged", 1)[0]
        self.assertEqual(session_capture.count("id[5] > (SESSION_FIXTURE_NAMESPACE.len() as u64 + 2)"), 1)
        self.assertEqual(tools_native.count("id[5] > (super::SESSION_FIXTURE_NAMESPACE.len() as u64 + 2)"), 1)
        self.assertNotIn("id[5] > 20", session_capture)
        self.assertNotIn("id[5] > 20", tools_native)
        self.assertEqual(L.SHELL_CASES, ("normal", "positive", "quit-outstanding", "project-paths", "workflow-apply",
                                       "session-inputs", "session-refusals", "session-loss", "session-deadline", "metadata-save",
                                       "tools-observed", "tools-cancel", "tools-settlement", "offline-pass", "offline-negative",
                                       "offline-drift", "offline-cancel", "offline-settlement", "settled-failure", "version-save"))
        roster = L.public_files(value)
        self.assertEqual({name for name in roster if name.startswith("shell-positive-project-")},
                         {"shell-positive-project-before.json", "shell-positive-project-after.json"})
        self.assertEqual({name for name in roster if name.endswith("-xvfb.stderr")},
                         {"shell-" + case + "-xvfb.stderr" for case in L.SHELL_CASES})
        self.assertEqual({name for name in roster if name.startswith("shell-positive-candidate-")},
                         {"shell-positive-candidate-before.json", "shell-positive-candidate-after.json"})
        self.assertEqual({name for name in roster if name.startswith("shell-workflow-apply-") and name.endswith(".json")},
                         {"shell-workflow-apply-before.json", "shell-workflow-apply-after.json"})
        self.assertEqual({name for name in roster if name.startswith("shell-metadata-save-") and name.endswith(".json")},
                         {"shell-metadata-save-before.json", "shell-metadata-save-after.json"})
        self.assertEqual({name for name in roster if name.startswith("shell-session-") and name.endswith(".json")},
                         {"shell-" + case + "-" + phase + ".json" for case in L.SHELL_SESSION_CASES for phase in ("before", "after")})
        self.assertEqual({name for name in roster if name.startswith(("shell-tools-", "shell-offline-")) and name.endswith(".json")},
                         {"shell-" + case + "-" + phase + ".json" for case in L.SHELL_TOOLS_OFFLINE_CASES for phase in ("before", "after")})
        self.assertEqual({name for name in roster if name.startswith("shell-settled-failure")},
                         {"shell-settled-failure.stdout", "shell-settled-failure.stderr",
                          "shell-settled-failure-xvfb.stderr", "shell-settled-failure-failure.labels"})
        self.assertEqual({name for name in roster if name.endswith("failure.labels")},
                         {"shell-settled-failure-failure.labels"})
        self.assertEqual({name for name in roster if name.startswith("shell-version-save")},
                         {"shell-version-save.stdout", "shell-version-save.stderr", "shell-version-save-xvfb.stderr",
                          "shell-version-save-before.json", "shell-version-save-after.json"})
        self.assertEqual(len(roster), 163)
        self.assertEqual(len(roster) + 2, 165)
        self.assertEqual(len(L.root_phases(value)), 34)
        self.assertEqual(L.SHELL_PUBLIC_FILE_LIMIT, 165)
        self.assertEqual(L.TOTAL_LIMIT, 32 << 20)
        self.assertLessEqual(len(roster), L.SHELL_PUBLIC_FILE_LIMIT)
        for case in ("positive", "refuse-writable", "refuse-pth"):
            self.assertFalse(any(name.startswith("shell-positive-project-") for name in L.public_files(installed_handoff(case))))
            self.assertFalse(any(name.startswith("shell-positive-candidate-") for name in L.public_files(installed_handoff(case))))
            self.assertFalse(any(name.startswith("shell-workflow-apply-") for name in L.public_files(installed_handoff(case))))
            self.assertFalse(any(name.startswith("shell-metadata-save-") for name in L.public_files(installed_handoff(case))))
            self.assertFalse(any(name.startswith("shell-version-save-") for name in L.public_files(installed_handoff(case))))
            self.assertFalse(any(name.startswith(("shell-tools-", "shell-offline-")) for name in L.public_files(installed_handoff(case))))
            self.assertLessEqual(len(L.public_files(installed_handoff(case))), 128)

    def test_positive_typed_schema_rejects_each_missing_or_changed_leaf(self):
        expected = project_draft_receipt()
        raw = L.canonical(expected)
        self.assertEqual(len(raw), 2043)  # The one receipt includes its trailing newline.
        self.assertEqual(hashlib.sha256(raw).hexdigest(), "bb1e915f24abab3a6ba30e188af070abf7ad99bc735733f3fb28d045d6773b53")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertLessEqual(len(raw), 2048)
        self.assertEqual(L.shell_project_receipt(raw), expected)
        value, outcome, files, mappings = closed_shell_data()

        def leaves(value, prefix=()):
            for key, child in (value.items() if type(value) is dict else enumerate(value)):
                if type(child) in (dict, list):
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
        prior_u = deepcopy(expected)
        prior_u["methods"] = "twelve-passive"
        prior_u["quit"]["operation"] = 6
        prior_u["save"]["createReleaseDirectory"] = False
        prior_u["readback"].update(size=692, sha256="4b3a5aaa718b018101ee0fcd0e612285be8a1b93cab20c5ff15e8d441069b917")
        self.assertEqual(hashlib.sha256(L.canonical(prior_u)).hexdigest(), "40389f4ea473b4324690bf44bbc98fb8cc8106e829364fe07d1a3a2b8b9340ad")
        legacy = deepcopy(prior_u)
        legacy.pop("save")
        legacy.update(schemaVersion=1, fixture="android-static-v1", guidance={"draftUnchanged": True})
        legacy_v2 = deepcopy(prior_u)
        legacy_v2.update(schemaVersion=2, fixture="android-config-save-v1", methods="eight-passive")
        legacy_v2["snapshot"]["sourceFiles"] = 1
        legacy_v2["save"].pop("createReleaseDirectory")
        legacy_v2.pop("savedReads")
        legacy_v2["guidance"]["requirements"].update(presence="unknown", version="unknown", inspection="not-run",
                                                    nativeInspection="unavailable", dependencies="unknown")
        legacy_v2["guidance"]["github"].update(comparison="not-supplied", tooling="format-only", githubContacted=False,
                                              repositoryObserved=False, toolingRefResolved=False, templateCompatibility="unknown", applyAvailable=False)
        self.assertEqual(len(L.canonical(legacy_v2)), 2029)
        legacy_r = {**prior_u, "methods": "eleven-passive", "quit": {**prior_u["quit"], "operation": 3}}
        self.assertEqual(hashlib.sha256(L.canonical(legacy_r)).hexdigest(), "aae33b86cb288492032b903bc845929b08e904173264762971e65b3903f05af8")
        save_only = {key: child for key, child in expected.items() if key not in {"guidance", "savedReads"}}
        guidance_only = {key: child for key, child in expected.items() if key not in {"save", "readback", "noop", "originals", "savedReads"}}
        saved_reads_only = {key: child for key, child in expected.items() if key not in {"save", "readback", "noop", "originals", "guidance"}}
        for changed in (b"", b"{}", L.canonical(prior_u), L.canonical(legacy), L.canonical(legacy_v2), L.canonical(legacy_r), L.canonical({**expected, "methods": "six-passive"}),
                        L.canonical(save_only), L.canonical(guidance_only), L.canonical(saved_reads_only),
                        L.canonical({key: child for key, child in expected.items() if key != "save"}),
                        L.canonical({**expected, "save": {}}), L.canonical({**expected, "save": []}),
                        L.canonical({**expected, "save": {**expected["save"], "untrustedSuccess": True}}),
                        L.canonical({**expected, "guidance": {"draftUnchanged": True}}),
                        L.canonical({**expected, "guidance": {}}), L.canonical({**expected, "guidance": []}),
                        L.canonical({**expected, "guidance": {**expected["guidance"], "github": None}}),
                        L.canonical({key: child for key, child in expected.items() if key != "savedReads"}),
                        L.canonical({**expected, "savedReads": {}}), L.canonical({**expected, "savedReads": []}),
                        L.canonical({**expected, "savedReads": {"version": expected["savedReads"]["version"]}}),
                        L.canonical({**expected, "savedReads": {**expected["savedReads"], "metadata": None}}),
                        raw.replace(b'"fresh":true', b'"fresh":true,"fresh":true'),
                        raw.replace(b'"save":{', b'"save":{},"save":{'),
                        raw.replace(b'"guidance":{', b'"guidance":{},"guidance":{'),
                        raw.replace(b'"savedReads":{', b'"savedReads":{},"savedReads":{'),
                        L.canonical({**expected, "message": "ConfigurationError text is not a receipt field"}), raw + b" " * 2048):
            with self.subTest(raw=changed), self.assertRaises(ValueError):
                L.shell_project_receipt(changed)

    def test_positive_completion_is_last_on_original_stdout_not_inferred_from_zero(self):
        stdout, stderr = positive_capture()
        parsed = L.shell_result(stdout, stderr, "positive", 0, map_data())
        self.assertEqual(parsed["projectDraft"], project_draft_receipt())
        self.assertEqual(parsed["lifecycleDocuments"], lifecycle_documents_receipt())
        lines = stdout.splitlines(keepends=True)
        noise = b"ordinary wrapper text\nMRKDBG_DESKTOP_BOOTSTRAP=setup-enter\n"
        self.assertEqual(L.shell_result(noise + noise.join(lines), noise, "positive", 0, map_data()), parsed)
        changes = [(b"", b""), (b"", stdout), (b"".join(lines[2:]), b"".join(lines[:2])),
                   (stdout + b"MRK_UNEXPECTED=1\n", b""), (stdout, lines[0]),
                   (stdout.replace(b"=available", b"=unavailable"), b""),
                   (stdout.rstrip(b"\n"), b""), (stdout.replace(b"\n", b"\r\n"), b"")]
        for index, line in enumerate(lines):
            changes.extend(((b"".join(lines[:index] + lines[index + 1:]), b""), (stdout + line, b""),
                            (b"".join(lines[:index] + lines[index + 1:]), line)))
            if index + 1 < len(lines):
                changed = list(lines)
                changed[index], changed[index + 1] = changed[index + 1], changed[index]
                changes.append((b"".join(changed), b""))
        for out, err in changes:
            with self.subTest(stdout=out, stderr=err), self.assertRaises(ValueError):
                L.shell_result(out, err, "positive", 0, map_data())
        for code in (True, False, 1, -1, None):
            with self.subTest(code=code), self.assertRaises(ValueError):
                L.shell_result(stdout, stderr, "positive", code, map_data())
        for case in ("normal", "quit-outstanding"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                L.shell_result(stdout, stderr, case, 0, map_data())

    def test_fixture_inventory_allows_only_exact_saved_outputs_and_preserves_original_hints(self):
        value = installed_handoff()
        original = project_fixture_data(value)
        saved = project_fixture_data(value, saved=True)
        raw, after_raw = L.canonical(original), L.canonical(saved)
        result = L.shell_project_fixture(value, raw, after_raw)
        self.assertTrue(all(result[key] for key in ("rootRetained", "hintUnchanged", "savedOutputsMatched", "noUnexpectedEntries", "noPendingState")))
        self.assertEqual(result["fixture"], "android-saved-readonly-v1")
        self.assertEqual((len(original["entries"]), len(saved["entries"]), result["entryCount"]), (4, 7, 7))
        self.assertEqual(original["absent"], [".gitignore", "release"])
        self.assertEqual(result["sourceBytes"], original["entries"][2]["size"] + original["entries"][3]["size"])
        self.assertEqual(result["sourceBytes"], 149)
        self.assertEqual(result["releaseMode"], 0o755)
        for phase, encoded in (("before", raw), ("after", after_raw)):
            self.assertEqual(result[phase], {"size": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()})
        for key, expected in (("config", L.SHELL_PROJECT_CONFIG), ("gitignore", L.SHELL_PROJECT_IGNORE)):
            self.assertEqual(result[key], {"size": len(expected), "sha256": hashlib.sha256(expected).hexdigest(), "mode": 0o600})
        mutations = (
            lambda v: v.update(schemaVersion=True), lambda v: v.update(root="/other/project"),
            lambda v: v.update(fixture="android-config-save-v1"),
            lambda v: v.update(saved=1), lambda v: v.update(absent=[".gitignore"]),
            lambda v: v.update(absent=[]),
            lambda v: v["entries"].append(deepcopy(v["entries"][-1])),
            lambda v: v["entries"][0].update(children=[".gitignore", ".mobile-release-init", "app", "release"]),
            lambda v: v["entries"][0].update(children=[".github", ".gitignore", "app", "release"]),
            lambda v: v["entries"][1].update(children=["build.gradle.kts", ".gitignore"]),
            lambda v: v["entries"][2].update(children=["mobile-release.json", "unexpected"]),
            lambda v: v["entries"][2].update(children=["mobile-release.json", "store", "version.properties"]),
            lambda v: v["entries"][3].update(path="app/../build.gradle.kts"),
            lambda v: v["entries"][3].update(sha256="0" * 64), lambda v: v["entries"][3].update(size=True),
            lambda v: v["entries"][3]["identity"].__setitem__(2, stat.S_IFLNK | 0o444),
            lambda v: v["entries"][3]["identity"].__setitem__(2, stat.S_IFREG | 0o555),
            lambda v: v["entries"][3]["identity"].__setitem__(2, stat.S_IFREG | 0o666),
            lambda v: v["entries"][3]["identity"].__setitem__(3, 1000),
            lambda v: v["entries"][3]["identity"].__setitem__(5, 2),
            lambda v: v["entries"][3]["identity"].__setitem__(1, True),
            lambda v: v["entries"][3]["identity"].__setitem__(8, 99),
            lambda v: v["entries"][0]["identity"].__setitem__(1, 999),
            lambda v: v["entries"][1]["identity"].__setitem__(1, 999),
            lambda v: v["entries"][2]["identity"].__setitem__(1, v["entries"][0]["identity"][1]),
            lambda v: v["entries"][2]["identity"].__setitem__(2, stat.S_IFDIR | 0o700),
            lambda v: v["entries"][2]["identity"].__setitem__(3, 0),
            lambda v: v["entries"][4]["identity"].__setitem__(1, 999),
            lambda v: v["entries"][4]["identity"].__setitem__(2, stat.S_IFREG | 0o644),
            lambda v: v["entries"][4]["identity"].__setitem__(3, 0),
            lambda v: v["entries"][4]["identity"].__setitem__(5, 2),
            lambda v: v["entries"][4]["identity"].__setitem__(8, 99),
            lambda v: v["entries"][4].update(sha256="f" * 64),
            lambda v: v["entries"][4].update(size=True),
            lambda v: v["entries"][5]["identity"].__setitem__(2, stat.S_IFREG | 0o644),
            lambda v: v["entries"][5]["identity"].__setitem__(3, 0),
            lambda v: v["entries"][5].update(sha256="f" * 64),
            lambda v: v["entries"][6].update(sha256="f" * 64),
            lambda v: v["entries"][6]["identity"].__setitem__(0, 2),
            lambda v: v["entries"][6]["identity"].__setitem__(1, v["entries"][5]["identity"][1]),
        )
        for mutate in mutations:
            changed = deepcopy(saved); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                L.shell_project_fixture(value, raw, L.canonical(changed))
        # release is newly created, not a retained before-inode. Its precise
        # inode may vary, but it must be unique and meet the saved policy.
        fresh_release = deepcopy(saved); fresh_release["entries"][2]["identity"][1] = 999
        self.assertEqual(L.shell_project_fixture(value, raw, L.canonical(fresh_release))["releaseMode"], 0o755)
        for mutate in (lambda v: v["entries"].pop(),
                       lambda v: v["entries"][0].update(children=["app", "release", "version.properties"]),
                       lambda v: v["entries"].insert(2, deepcopy(saved["entries"][2])),
                       lambda v: v["entries"][3].update(sha256="f" * 64),
                       lambda v: v.update(absent=[".gitignore", "release/mobile-release.json"])):
            changed = deepcopy(original); mutate(changed)
            with self.subTest(initial=mutate), self.assertRaises(ValueError):
                L.shell_project_fixture(value, L.canonical(changed), after_raw)
        for before, after in ((raw, raw), (after_raw, after_raw), (after_raw, raw),
                              (b"{}", after_raw), (raw, b"[]"), (json.dumps(original, indent=2).encode(), after_raw),
                              (raw, after_raw + b" " * 8192)):
            with self.subTest(before=before, after=after), self.assertRaises(ValueError):
                L.shell_project_fixture(value, before, after)

    def test_actual_inventory_observes_only_fixed_nodes_and_refuses_changed_or_pending_data(self):
        value = installed_handoff(); root = L.root_path(value); namespace = fixture_namespace_data(value)
        binding = L.canonical(namespace); project = Path(namespace["root"]) / "positive-project"
        for saved in (False, True):
            fixture = project_fixture_data(value, saved=saved)
            by_path = {project if row["path"] == "." else project / row["path"]: row for row in fixture["entries"]}
            def file_stat(path):
                value = by_path[path]["identity"]
                return SimpleNamespace(**dict(zip(("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"), value)))
            def scan(path):
                context = Mock()
                context.__enter__ = Mock(return_value=iter(SimpleNamespace(name=name) for name in by_path[path]["children"]))
                context.__exit__ = Mock(return_value=False)
                return context
            def read_data(path, limit):
                row = by_path[path]
                return {"path": str(path), "size": row["size"], "sha256": row["sha256"]}
            with self.subTest(saved=saved), patch.object(L, "_ROOT", root), patch.object(L, "directory"), \
                 patch.object(L, "_shell_namespace_check", return_value=namespace) as namespace_check, \
                 patch.object(Path, "lstat", file_stat), patch.object(L.os, "scandir", side_effect=scan), \
                 patch.object(L, "record", side_effect=read_data) as reads, patch.object(L, "_absent") as absent:
                self.assertEqual(L._shell_project_inventory(value, binding, saved=saved), fixture)
                self.assertEqual([call.args for call in namespace_check.call_args_list], [(value, binding)] * 2)
                self.assertEqual([call.args for call in reads.call_args_list],
                                 [(project / row["path"], row["size"]) for row in fixture["entries"] if row["kind"] == "file"])
                self.assertEqual(reads.call_count, 4 if saved else 2)
                self.assertEqual([call.args[0] for call in absent.call_args_list], [project / relative for relative in fixture["absent"]])
                for parent, extra in ((project, ".mobile-release-init"), (project / ("release" if saved else "app"), "store")):
                    reads.reset_mock()
                    by_path[parent]["children"].append(extra)
                    with self.assertRaises(ValueError):
                        L._shell_project_inventory(value, binding, saved=saved)
                    reads.assert_not_called()  # Never inspect an unadmitted journal/metadata subtree.
                    by_path[parent]["children"].pop()

    def test_prepare_keeps_per_case_before_captures_without_recreating_fixtures(self):
        value = installed_handoff(); root = L.root_path(value); namespace = fixture_namespace_data(value)
        binding = L.canonical(namespace)
        for case in L.SHELL_CASES:
            writer = Mock()
            with self.subTest(case=case), patch.object(L, "_ROOT", root), patch.object(L, "_D", SimpleNamespace(write=writer)), \
                 patch.object(Path, "mkdir", autospec=True) as mkdir, patch.object(L.os, "chown") as chown, patch.object(L.os, "chmod") as chmod, \
                 patch.object(L, "_shell_namespace_check", return_value=namespace) as namespace_check, \
                 patch.object(L, "_shell_fixtures_prepare") as prepare, \
                 patch.object(L, "_shell_log_prepare", return_value="original-log-binding") as log, \
                 patch.object(L, "_absent"), patch.object(L, "_retain") as retain, \
                 patch.object(L, "_shell_project_inventory", return_value=project_fixture_data(value)) as inventory, \
                 patch.object(L, "_shell_candidate_inventory", return_value=candidate_fixture_data(value)) as candidate_inventory, \
                 patch.object(L, "_shell_paths_inventory", return_value=path_fixture_data(value)) as path_inventory, \
                  patch.object(L, "_shell_workflow_inventory", return_value=workflow_fixture_data(value)) as workflow_inventory, \
                  patch.object(L, "_shell_metadata_inventory", return_value=metadata_fixture_data(value)) as metadata_inventory, \
                  patch.object(L, "_shell_version_inventory", return_value=version_fixture_data(value)) as version_inventory, \
                  patch.object(L, "_shell_session_inventory", return_value={"inert": "session-fixture"}) as session_inventory, \
                  patch.object(L, "_shell_tools_offline_inventory", return_value={"inert": "tools-offline-fixture"}) as tools_inventory:
                self.assertEqual(L._shell_prepare(value, case, binding), (L.shell_environment(value, case), "original-log-binding"))
                namespace_check.assert_called_once_with(value, binding)
                prepare.assert_not_called(); chmod.assert_not_called()
                log.assert_called_once_with(value, case)
                self.assertEqual(mkdir.call_count, 8)
                self.assertEqual(chown.call_count, 9)
                self.assertEqual(writer.call_count, 2)
                self.assertTrue(all(root in call.args[0].parents for call in
                                    [*mkdir.call_args_list, *chown.call_args_list, *writer.call_args_list]))
                if case == "positive":
                    inventory.assert_called_once_with(value, binding)
                    candidate_inventory.assert_called_once_with(value, binding)
                    path_inventory.assert_not_called(); workflow_inventory.assert_not_called()
                    metadata_inventory.assert_not_called()
                    self.assertEqual([call.args for call in retain.call_args_list], [
                        ("shell-positive-project-before.json", L.canonical(project_fixture_data(value))),
                        ("shell-positive-candidate-before.json", L.canonical(candidate_fixture_data(value)))])
                elif case == "project-paths":
                    inventory.assert_not_called(); candidate_inventory.assert_not_called()
                    path_inventory.assert_called_once_with(value, binding)
                    workflow_inventory.assert_not_called(); metadata_inventory.assert_not_called()
                    retain.assert_called_once_with("shell-project-paths-before.json", L.canonical(path_fixture_data(value)))
                elif case == "workflow-apply":
                    inventory.assert_not_called(); candidate_inventory.assert_not_called(); path_inventory.assert_not_called()
                    workflow_inventory.assert_called_once_with(value, binding)
                    metadata_inventory.assert_not_called()
                    retain.assert_called_once_with("shell-workflow-apply-before.json", L.canonical(workflow_fixture_data(value)))
                elif case == "metadata-save":
                    inventory.assert_not_called(); candidate_inventory.assert_not_called(); path_inventory.assert_not_called()
                    workflow_inventory.assert_not_called()
                    metadata_inventory.assert_called_once_with(value, binding)
                    retain.assert_called_once_with("shell-metadata-save-before.json", L.canonical(metadata_fixture_data(value)))
                elif case == "version-save":
                    inventory.assert_not_called(); candidate_inventory.assert_not_called(); path_inventory.assert_not_called()
                    workflow_inventory.assert_not_called()
                    version_inventory.assert_called_once_with(value, binding)
                    retain.assert_called_once_with("shell-version-save-before.json", L.canonical(version_fixture_data(value)))
                elif case in L.SHELL_SESSION_CASES:
                    inventory.assert_not_called(); candidate_inventory.assert_not_called(); path_inventory.assert_not_called()
                    workflow_inventory.assert_not_called()
                    session_inventory.assert_called_once_with(value, binding, case)
                    retain.assert_called_once_with("shell-" + case + "-before.json", L.canonical({"inert": "session-fixture"}))
                elif case in L.SHELL_TOOLS_OFFLINE_CASES:
                    inventory.assert_not_called(); candidate_inventory.assert_not_called(); path_inventory.assert_not_called()
                    workflow_inventory.assert_not_called()
                    tools_inventory.assert_called_once_with(value, binding, case)
                    retain.assert_called_once_with("shell-" + case + "-before.json", L.canonical({"inert": "tools-offline-fixture"}))
                else:
                    inventory.assert_not_called(); candidate_inventory.assert_not_called(); path_inventory.assert_not_called()
                    workflow_inventory.assert_not_called(); retain.assert_not_called(); chmod.assert_not_called()
                if case not in L.SHELL_SESSION_CASES:
                    session_inventory.assert_not_called()
                if case != "metadata-save":
                    metadata_inventory.assert_not_called()
                if case != "version-save":
                    version_inventory.assert_not_called()
                if case not in L.SHELL_TOOLS_OFFLINE_CASES:
                    tools_inventory.assert_not_called()
        with patch.object(L, "_shell_namespace_check", side_effect=L.Refused("original namespace changed")), \
             patch.object(L, "_shell_log_prepare") as logs, patch.object(Path, "mkdir") as mkdir:
            with self.assertRaises(ValueError): L._shell_prepare(value, "normal", binding)
            logs.assert_not_called(); mkdir.assert_not_called()

    def test_closed_case_requires_native_receipt_and_same_before_after_originals(self):
        value, outcome, files, expected = closed_shell_data()
        with patch.object(L, "shell_closed_loader", return_value=expected):
            result = L.shell_closed_result(value, outcome, files)
        self.assertEqual(result["projectDraft"]["native"], project_draft_receipt())
        self.assertTrue(result["projectDraft"]["fixture"]["savedOutputsMatched"])
        self.assertNotEqual(result["projectDraft"]["fixture"]["before"], result["projectDraft"]["fixture"]["after"])
        self.assertEqual(result["cases"]["normal"]["domAndGtkObserved"], False)
        self.assertEqual(len(result["cases"]["quit-outstanding"]["maps"]), 1)
        self.assertEqual(result["settledFailure"], result["cases"]["settled-failure"])
        self.assertEqual(result["settledFailure"]["exitCode"], 1)
        self.assertIs(result["settledFailure"]["qualified"], False)
        self.assertIs(result["settledFailure"]["expectedFailureObserved"], True)
        for change in ("missing-before", "missing-after", "different-after", "coerced-case", "missing-receipt",
                       "case-save-only", "stdout-save-only", "case-guidance-only", "stdout-guidance-only",
                       "case-saved-reads-only", "stdout-saved-reads-only", "case-no-saved-reads", "stdout-no-saved-reads", "wrong-argv",
                       "no-display-log", "display-type", "combined-output"):
            changed, current = deepcopy(files), deepcopy(outcome)
            if change == "no-display-log":
                changed.pop("shell-positive-xvfb.stderr")
            elif change == "display-type":
                changed["shell-positive-xvfb.stderr"] = "not original bytes"
            elif change == "combined-output":
                changed["shell-positive-xvfb.stderr"] = b"x" * L.LIMIT
            elif change.startswith("missing-") and change != "missing-receipt":
                changed.pop("shell-positive-project-" + change.removeprefix("missing-") + ".json")
            elif change == "different-after":
                altered = L.decode(changed["shell-positive-project-after.json"]); altered["entries"][0]["identity"][1] += 1
                changed["shell-positive-project-after.json"] = L.canonical(altered)
            elif change == "coerced-case":
                altered = L.decode(changed["shell-cases.json"]); altered["positive"]["projectDraft"]["select"]["originalsSettled"] = 1
                changed["shell-cases.json"] = L.canonical(altered)
            elif change == "missing-receipt":
                changed["shell-positive.stdout"] = b"MRK_INSTALLED_SHELL_OBSERVATION=positive-verified\n"
            elif change.startswith(("case-", "stdout-")):
                omitted = {"save-only": {"guidance", "savedReads"},
                           "guidance-only": {"save", "readback", "noop", "originals", "savedReads"},
                           "saved-reads-only": {"save", "readback", "noop", "originals", "guidance"},
                           "no-saved-reads": {"savedReads"}}[change.split("-", 1)[1]]
                partial = {key: child for key, child in project_draft_receipt().items() if key not in omitted}
                if change.startswith("case-"):
                    altered = L.decode(changed["shell-cases.json"]); altered["positive"]["projectDraft"] = partial
                    changed["shell-cases.json"] = L.canonical(altered)
                else:
                    changed["shell-positive.stdout"] = positive_capture(partial)[0]
            else:
                current["commands"][1]["argv"][-1] = "quit-outstanding"
            with self.subTest(change=change), patch.object(L, "shell_closed_loader", return_value=expected), self.assertRaises((ValueError, KeyError)):
                L.shell_closed_result(value, current, changed)

        for change in ("missing-label", "truncated-label", "wrong-label", "missing-handoff", "duplicate-handoff", "verified",
                       "zero-exit", "bool-exit", "other-exit", "wrong-argv", "missing-case", "case-qualified", "case-exit", "case-coerced"):
            changed, current = deepcopy(files), deepcopy(outcome)
            name = "shell-settled-failure"
            if change == "missing-label": changed.pop(name + "-failure.labels")
            elif change == "truncated-label": changed[name + "-failure.labels"] = L.SHELL_SETTLED_FAILURE_LABELS[:-1]
            elif change == "wrong-label": changed[name + "-failure.labels"] = L.SHELL_SETTLED_FAILURE_LABELS.replace(b"=dom", b"=tick")
            elif change in ("missing-handoff", "duplicate-handoff"):
                handoff = b"MRK_INSTALLED_SHELL_FAILURE_HANDOFF=original-quit-relay-loop-returned\n"
                changed[name + ".stdout"] = changed[name + ".stdout"].replace(handoff, b"" if change == "missing-handoff" else handoff * 2)
            elif change == "verified": changed[name + ".stdout"] += b"MRK_INSTALLED_SHELL_OBSERVATION=settled-failure-verified\n"
            elif change in ("zero-exit", "bool-exit", "other-exit", "wrong-argv"):
                command = next(row for row in current["commands"] if row["phase"] == name)
                if change == "wrong-argv": command["argv"][-1] = "positive"
                else: command["exitCode"] = {"zero-exit": 0, "bool-exit": True, "other-exit": 2}[change]
            else:
                cases = L.decode(changed["shell-cases.json"])
                if change == "missing-case": cases.pop("settled-failure")
                elif change == "case-qualified": cases["settled-failure"]["qualified"] = True
                elif change == "case-exit": cases["settled-failure"]["exitCode"] = 0
                else: cases["settled-failure"]["expectedFailureObserved"] = 1
                changed["shell-cases.json"] = L.canonical(cases)
            with self.subTest(negative=change), patch.object(L, "shell_closed_loader", return_value=expected), \
                 self.assertRaises((ValueError, KeyError)):
                L.shell_closed_result(value, current, changed)

    def test_metadata_receipt_requires_each_typed_original_finality_and_readback_leaf(self):
        expected = metadata_receipt_data(); raw = L.canonical(expected)
        self.assertLessEqual(len(raw), 2048)
        self.assertEqual(L.shell_metadata_receipt(raw), expected)
        value, outcome, files, mappings = closed_shell_data()

        def leaves(value, prefix=()):
            for key, child in (value.items() if type(value) is dict else enumerate(value)):
                if type(child) in (dict, list):
                    yield from leaves(child, (*prefix, key))
                else:
                    yield (*prefix, key), child

        for path, original in leaves(expected):
            for mode in ("missing", "changed", "wrong-type"):
                changed = deepcopy(expected); parent = changed
                for key in path[:-1]:
                    parent = parent[key]
                if mode == "missing":
                    del parent[path[-1]]
                elif mode == "wrong-type":
                    parent[path[-1]] = int(original) if type(original) is bool else float(original) if type(original) is int else None
                else:
                    parent[path[-1]] = not original if type(original) is bool else original + 1 if type(original) is int else original + "-other"
                with self.subTest(path=path, mode=mode):
                    with self.assertRaises(ValueError):
                        L.shell_metadata_receipt(L.canonical(changed))
                    with self.assertRaises(ValueError):
                        L.shell_result(*metadata_capture(changed), "metadata-save", 0, mappings)
                    altered = dict(files); cases = L.decode(altered["shell-cases.json"])
                    cases["metadata-save"]["metadataSave"] = changed
                    altered["shell-cases.json"] = L.canonical(cases)
                    with patch.object(L, "shell_closed_loader", return_value=mappings), self.assertRaises(ValueError):
                        L.shell_closed_result(value, outcome, altered)
        for changed in (b"", b"{}", b"[]", b"null", raw + b" " * 2048,
                        raw.replace(b'"apply":1', b'"apply":1,"apply":1'),
                        raw.replace(b'"originals":{', b'"originals":{},"originals":{'),
                        L.canonical(project_draft_receipt()), L.canonical(L.SHELL_WORKFLOW_RECEIPT),
                        L.canonical({**expected, "message": "not a finality fact"}),
                        *(L.canonical({key: child for key, child in expected.items() if key != omitted})
                          for omitted in ("requests", "draft", "reviews", "confirmation", "outcomes", "nativeReasons", "originals", "readback", "quit"))):
            with self.subTest(raw=changed), self.assertRaises(ValueError):
                L.shell_metadata_receipt(changed)

    def test_metadata_requires_original_stdout_order_complete_receipt_and_zero_exit(self):
        stdout, stderr = metadata_capture(); expected = map_data()
        parsed = L.shell_result(stdout, stderr, "metadata-save", 0, expected)
        self.assertEqual(parsed["metadataSave"], metadata_receipt_data())
        lines = stdout.splitlines(keepends=True)
        self.assertEqual(len(lines), 5)
        noise = b"ordinary wrapper text\nMRKDBG_DESKTOP_BOOTSTRAP=setup-enter\n"
        self.assertEqual(L.shell_result(noise + noise.join(lines), noise, "metadata-save", 0, expected), parsed)
        for order in permutations(range(5)):
            if order != (0, 1, 2, 3, 4):
                with self.subTest(order=order), self.assertRaises(ValueError):
                    L.shell_result(b"".join(lines[index] for index in order), stderr, "metadata-save", 0, expected)
        changes = [(b"", b""), (b"", stdout), (stdout.rstrip(b"\n"), b""), (stdout.replace(b"\n", b"\r\n"), b""),
                   (stdout.replace(b"=available", b"=unavailable"), b""), (stdout + b"MRK_UNEXPECTED=1\n", b""),
                   (stdout + L.SHELL_WORKFLOW_MARKER + L.canonical(L.SHELL_WORKFLOW_RECEIPT), b"")]
        for index, line in enumerate(lines):
            changes.extend(((b"".join(lines[:index] + lines[index + 1:]), b""), (stdout + line, b""),
                            (b"".join(lines[:index] + lines[index + 1:]), line), (stdout, line)))
        # JSON and its original LF must fit the same unchanged receipt bound.
        body = lines[3][len(L.SHELL_METADATA_MARKER):-1]
        changes.append((b"".join(lines[:3]) + L.SHELL_METADATA_MARKER + body + b" " * (2048 - len(body)) + b"\n" + lines[4], b""))
        for out, err in changes:
            with self.subTest(stdout=out, stderr=err), self.assertRaises(ValueError):
                L.shell_result(out, err, "metadata-save", 0, expected)
        for code in (True, False, 1, -1, None):
            with self.subTest(code=code), self.assertRaises(ValueError):
                L.shell_result(stdout, stderr, "metadata-save", code, expected)
        for case in L.SHELL_CASES:
            if case != "metadata-save":
                with self.subTest(case=case), self.assertRaises(ValueError):
                    L.shell_result(stdout, stderr, case, 0, expected)

    def test_metadata_fixture_preserves_originals_and_requires_one_new_and_one_replaced_inode(self):
        value = installed_handoff(); before = metadata_fixture_data(value); after = metadata_fixture_data(value, saved=True)
        raw, final = L.canonical(before), L.canonical(after)
        locale = "release/store/android/en-US"
        short, full = (locale + "/" + name + "_description.txt" for name in ("short", "full"))
        first, last = ({row["path"]: row for row in document["entries"]} for document in (before, after))
        with patch.object(Path, "lstat", side_effect=AssertionError("Closed metadata DATA cannot inspect a live tree")), \
             patch.object(L, "record", side_effect=AssertionError("Closed metadata DATA cannot reopen text")):
            result = L.shell_metadata_fixture(value, raw, final)
        self.assertEqual(result, {
            "fixture": "android-metadata-save-v1", "rootRetained": True, "preservedOriginals": True,
            "createdCount": 1, "replacedCount": 1, "beforeCount": 13, "afterCount": 14,
            "configurationUnchanged": True, "noUnexpectedEntries": True, "noPendingState": True,
            "files": [{"path": locale + "/" + name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mode": 0o600}
                      for name, data in (("title.txt", b"Public title"), ("short_description.txt", b"Public summary"),
                                         ("keep.txt", b"untouched\n"), ("full_description.txt", b"Public description"))],
            "before": {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
            "after": {"size": len(final), "sha256": hashlib.sha256(final).hexdigest()}})
        self.assertEqual((len(first), len(last), set(last) - set(first)), (13, 14, {full}))
        self.assertEqual((sum(row["size"] for row in first.values() if row["kind"] == "file"),
                          sum(row["size"] for row in last.values() if row["kind"] == "file"), first[short]["size"]), (1165, 1186, 11))
        self.assertEqual(first[short]["sha256"], hashlib.sha256(b"Old summary").hexdigest())
        self.assertEqual(before["absent"], [*after["absent"], full])
        for name, original in first.items():
            if name == short:
                continue
            if name not in (".", locale):
                self.assertEqual(original, last[name])
            # Only staging-root and locale timestamps/size may move. The
            # title, sentinel, hint, version, config and ignore stay identical.
            for field in range(6 if name in (".", locale) else 9):
                changed = deepcopy(after)
                next(row for row in changed["entries"] if row["path"] == name)["identity"][field] += 1
                with self.subTest(preserved=name, identity=field), self.assertRaises(ValueError):
                    L.shell_metadata_fixture(value, raw, L.canonical(changed))
        for name in (short, full):
            for original in first.values():
                changed = deepcopy(after)
                next(row for row in changed["entries"] if row["path"] == name)["identity"][1] = original["identity"][1]
                with self.subTest(new=name, reused=original["path"]), self.assertRaises(ValueError):
                    L.shell_metadata_fixture(value, raw, L.canonical(changed))
        changed = deepcopy(after)
        next(row for row in changed["entries"] if row["path"] == full)["identity"][1] = last[short]["identity"][1]
        with self.assertRaises(ValueError): L.shell_metadata_fixture(value, raw, L.canonical(changed))
        fresh = deepcopy(after)
        for index, name in enumerate((short, full)):
            next(row for row in fresh["entries"] if row["path"] == name)["identity"][1] = 900 + index
        self.assertTrue(L.shell_metadata_fixture(value, raw, L.canonical(fresh))["preservedOriginals"])
        mutations = (
            lambda d: d.update(schemaVersion=True), lambda d: d.update(fixture="android-workflow-apply-v1"),
            lambda d: d.update(root=d["root"].replace("metadata-project", "positive-project")),
            lambda d: d.update(saved=int(d["saved"])), lambda d: d.update(absent=[]),
            lambda d: d["entries"].pop(), lambda d: d["entries"].append(deepcopy(d["entries"][-1])),
            lambda d: d["entries"].reverse(), lambda d: d["entries"][0]["children"].append(".mobile-release-metadata-text"),
            lambda d: d["entries"][5]["children"].append("private"),
            lambda d: d["entries"][6].update(path="app/../build.gradle.kts"),
            lambda d: d["entries"][-1].update(sha256="f" * 64), lambda d: d["entries"][-1].update(size=True),
            lambda d: d["entries"][-1].update(extra=True), lambda d: d["entries"][-1]["identity"].__setitem__(1, True),
            lambda d: d["entries"][-1]["identity"].__setitem__(2, stat.S_IFLNK | 0o600),
            lambda d: d["entries"][-1]["identity"].__setitem__(2, stat.S_IFREG | 0o644),
            lambda d: d["entries"][-1]["identity"].__setitem__(3, 0),
            lambda d: d["entries"][-1]["identity"].__setitem__(5, 2),
            lambda d: d["entries"][-1]["identity"].__setitem__(0, 2),
            lambda d: d["entries"][-1]["identity"].__setitem__(1, d["namespace"]["identity"][1]),
        )
        for phase, document in (("before", before), ("after", after)):
            for mutate in mutations:
                changed = deepcopy(document); mutate(changed)
                with self.subTest(phase=phase, mutate=mutate), self.assertRaises(ValueError):
                    L.shell_metadata_fixture(value, L.canonical(changed) if phase == "before" else raw,
                                              L.canonical(changed) if phase == "after" else final)
            for index, row in enumerate(document["entries"]):
                if row["kind"] == "file":
                    for field, bad in (("sha256", "f" * 64), ("size", float(row["size"]))):
                        changed = deepcopy(document); changed["entries"][index][field] = bad
                        with self.subTest(phase=phase, text=row["path"], field=field), self.assertRaises(ValueError):
                            L.shell_metadata_fixture(value, L.canonical(changed) if phase == "before" else raw,
                                                      L.canonical(changed) if phase == "after" else final)
        for first_raw, last_raw in ((raw, raw), (final, final), (final, raw), (b"{}", final), (raw, b"[]"),
                                   (json.dumps(before, indent=2).encode(), final), (raw, final + b" " * 8192),
                                   (raw, final.replace(b'"saved":true', b'"saved":true,"saved":true'))):
            with self.subTest(before=first_raw, after=last_raw), self.assertRaises(ValueError):
                L.shell_metadata_fixture(value, first_raw, last_raw)

    def test_metadata_inventory_reads_only_fixed_public_files_and_refuses_drift_or_residue(self):
        value = installed_handoff(); namespace = fixture_namespace_data(value); binding = L.canonical(namespace)
        project = Path(namespace["root"]) / "metadata-project"
        for saved in (False, True):
            for fault in (None, "pending", "locale-child", "mode", "owner", "bytes", "file-drift", "parent-drift", "residue", "namespace-drift"):
                fixture = metadata_fixture_data(value, saved=saved)
                by_path = {project if row["path"] == "." else project / row["path"]: row for row in fixture["entries"]}
                if fault == "pending": by_path[project]["children"].append(".mobile-release-metadata-text")
                if fault == "locale-child": by_path[project / "release/store/android/en-US"]["children"].append("private")
                source = by_path[project / "app/build.gradle.kts"]
                if fault == "mode": source["identity"][2] = stat.S_IFLNK | 0o444
                if fault == "owner": source["identity"][3] = value["runnerUid"]
                reads_seen = []
                def file_stat(path):
                    values = list(by_path[path]["identity"])
                    if (fault == "file-drift" and path in reads_seen
                            or fault == "parent-drift" and path == project and reads_seen):
                        values[8] += 1
                    return SimpleNamespace(**dict(zip(("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"), values)))
                def scan(path):
                    context = Mock()
                    context.__enter__ = Mock(return_value=iter(SimpleNamespace(name=name) for name in by_path[path]["children"]))
                    context.__exit__ = Mock(return_value=False)
                    return context
                def read_data(path, limit):
                    row = by_path[path]; self.assertEqual(limit, row["size"]); reads_seen.append(path)
                    return {"path": str(path), "size": row["size"], "sha256": "f" * 64 if fault == "bytes" else row["sha256"]}
                with self.subTest(saved=saved, fault=fault), patch.object(L, "_ROOT", L.root_path(value)), patch.object(L, "directory"), \
                     patch.object(L, "_shell_namespace_check", side_effect=[namespace, L.Refused("changed namespace")]
                                  if fault == "namespace-drift" else None, return_value=namespace) as namespace_check, \
                     patch.object(Path, "lstat", file_stat), patch.object(L.os, "scandir", side_effect=scan) as scans, \
                     patch.object(L, "record", side_effect=read_data) as reads, \
                     patch.object(L, "_absent", side_effect=L.Refused("pending state") if fault == "residue" else None) as absent:
                    if fault is None:
                        self.assertEqual(L._shell_metadata_inventory(value, binding, saved=saved), fixture)
                        self.assertEqual([call.args for call in namespace_check.call_args_list], [(value, binding)] * 2)
                        self.assertEqual([call.args for call in reads.call_args_list],
                                         [(project / row["path"], row["size"]) for row in fixture["entries"] if row["kind"] == "file"])
                        self.assertEqual(reads.call_count, 8 if saved else 7)
                        self.assertEqual([call.args[0] for call in absent.call_args_list], [project / name for name in fixture["absent"]])
                    else:
                        with self.assertRaises(ValueError): L._shell_metadata_inventory(value, binding, saved=saved)
                        if fault in ("pending", "locale-child", "mode", "owner"): reads.assert_not_called()
                    self.assertTrue(all(by_path[call.args[0]]["kind"] == "directory" for call in scans.call_args_list))
                    self.assertTrue(all(by_path[call.args[0]]["kind"] == "file" for call in reads.call_args_list))
        with patch.object(L, "_ROOT", L.root_path(value)), \
             patch.object(L, "_shell_namespace_check", side_effect=AssertionError("Untyped phase cannot authorize observation")):
            for saved in (0, 1, None, "true"):
                with self.subTest(saved=saved), self.assertRaises(ValueError):
                    L._shell_metadata_inventory(value, binding, saved=saved)

    def test_closed_metadata_requires_native_receipt_original_exports_and_successful_command(self):
        value, outcome, files, expected = closed_shell_data()
        with patch.object(L, "shell_closed_loader", return_value=expected):
            result = L.shell_closed_result(value, outcome, files)
        self.assertEqual(result["metadataSave"]["native"], metadata_receipt_data())
        fixture = result["metadataSave"]["fixture"]
        self.assertEqual((fixture["createdCount"], fixture["replacedCount"]), (1, 1))
        self.assertTrue(fixture["preservedOriginals"] and fixture["configurationUnchanged"] and fixture["noPendingState"])
        self.assertNotEqual(fixture["before"], fixture["after"])
        for change in ("missing-before", "missing-after", "missing-display", "display-type", "missing-metadata-case", "partial-closed",
                       "foreign-closed", "session-closed", "extra-case", "missing-session-case", "mixed-session-case",
                       "partial-native", "foreign-native", "session-native", "unchanged-after", "journal", "short-in-place",
                       "missing-command", "wrong-exit", "wrong-argv"):
            altered, current = dict(files), deepcopy(outcome)
            if change in ("missing-before", "missing-after"):
                altered.pop("shell-metadata-save-" + change.removeprefix("missing-") + ".json")
            elif change == "missing-display":
                altered.pop("shell-metadata-save-xvfb.stderr")
            elif change == "display-type":
                altered["shell-metadata-save-xvfb.stderr"] = "not captured bytes"
            elif change in ("missing-metadata-case", "partial-closed", "foreign-closed", "session-closed",
                             "extra-case", "missing-session-case", "mixed-session-case"):
                cases = L.decode(altered["shell-cases.json"])
                if change == "missing-metadata-case": cases.pop("metadata-save")
                elif change == "partial-closed": cases["metadata-save"]["metadataSave"].pop("readback")
                elif change == "session-closed": cases["metadata-save"]["metadataSave"] = L.SHELL_SESSION_RECEIPTS["session-inputs"]
                elif change == "extra-case": cases["unexpected"] = deepcopy(cases["normal"])
                elif change == "missing-session-case": cases.pop("session-inputs")
                elif change == "mixed-session-case": cases["session-inputs"]["metadataSave"] = L.SHELL_METADATA_RECEIPT
                else: cases["metadata-save"]["metadataSave"] = L.SHELL_WORKFLOW_RECEIPT
                altered["shell-cases.json"] = L.canonical(cases)
            elif change == "partial-native":
                receipt = metadata_receipt_data(); receipt.pop("originals")
                altered["shell-metadata-save.stdout"] = metadata_capture(receipt)[0]
            elif change == "foreign-native":
                altered["shell-metadata-save.stdout"] = workflow_capture()[0]
            elif change == "session-native":
                altered["shell-metadata-save.stdout"] = session_capture("session-inputs")[0]
            elif change == "unchanged-after":
                altered["shell-metadata-save-after.json"] = altered["shell-metadata-save-before.json"]
            elif change in ("journal", "short-in-place"):
                document = L.decode(altered["shell-metadata-save-after.json"])
                if change == "journal": document["entries"][0]["children"].append(".mobile-release-metadata-text")
                else:
                    name = "release/store/android/en-US/short_description.txt"
                    original = L.decode(altered["shell-metadata-save-before.json"])
                    next(row for row in document["entries"] if row["path"] == name)["identity"][1] = next(
                        row for row in original["entries"] if row["path"] == name)["identity"][1]
                altered["shell-metadata-save-after.json"] = L.canonical(document)
            elif change == "missing-command":
                current["commands"] = [row for row in current["commands"] if row["phase"] != "shell-metadata-save"]
            else:
                command = next(row for row in current["commands"] if row["phase"] == "shell-metadata-save")
                if change == "wrong-exit": command["exitCode"] = 1
                else: command["argv"][-1] = "workflow-apply"
            with self.subTest(change=change), patch.object(L, "shell_closed_loader", return_value=expected), \
                 patch.object(L, "_shell_metadata_inventory", side_effect=AssertionError("No failed-work metadata rescan")), \
                 patch.object(L, "_shell_namespace_check", side_effect=AssertionError("Closed DATA is not live authority")), \
                 self.assertRaises((ValueError, KeyError)):
                L.shell_closed_result(value, current, altered)

    def test_metadata_postexit_inventory_and_other_original_rechecks_follow_the_success_gate(self):
        tree = ast.parse((SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_text())
        unit = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "unit_start")
        loop = next(node for node in ast.walk(unit) if isinstance(node, ast.For)
                    and isinstance(node.iter, ast.Name) and node.iter.id == "SHELL_CASES")
        branch = loop.body[1]
        self.assertIsInstance(branch, ast.If)
        self.assertEqual(ast.unparse(branch.orelse[0]),
                         "result = command('shell-' + case, shell_argv(value, case), maximum=60, env=environment, shell_log=(value, case, log_binding))")
        self.assertEqual(ast.unparse(branch.orelse[1]),
                         "failure_labels = read(_ROOT / 'public/shell-settled-failure-failure.labels', SHELL_FAILURE_LABEL_LIMIT) if case == 'settled-failure' else None")
        self.assertEqual(ast.unparse(branch.orelse[2]),
                         "cases[case] = shell_result(result.stdout, result.stderr, case, result.returncode, expected, failure_labels=failure_labels)")
        metadata = next(node for node in branch.orelse[3:] if isinstance(node, ast.If) and ast.unparse(node.test) == "case == 'metadata-save'")
        self.assertEqual(len(metadata.body), 3)
        self.assertEqual([ast.unparse(node) for node in metadata.body[:3]], [
            "metadata_after = canonical(_shell_metadata_inventory(value, namespace, saved=True))",
            "_retain('shell-metadata-save-after.json', metadata_after)",
            "shell_metadata_fixture(value, read(_ROOT / 'public/shell-metadata-save-before.json', 8192), metadata_after)"])
        final = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_shell_fixtures_final")
        self.assertEqual(len(final.body), 4)  # Docstring, common comparisons, session loop and Tools/Offline loop.
        recheck = final.body[1].value
        self.assertEqual(ast.unparse(recheck.func), "need")
        self.assertEqual([ast.unparse(node) for node in recheck.args[0].values], [
            "canonical(_shell_project_inventory(value, namespace, saved=True)) == read(_ROOT / 'public/shell-positive-project-after.json', 8192)",
            "canonical(_shell_candidate_inventory(value, namespace)) == read(_ROOT / 'public/shell-positive-candidate-after.json', 8192)",
            "canonical(_shell_paths_inventory(value, namespace, changed=True)) == read(_ROOT / 'public/shell-project-paths-after.json', 8192)",
            "canonical(_shell_workflow_inventory(value, namespace, installed=True)) == read(_ROOT / 'public/shell-workflow-apply-after.json', 8192)",
            "canonical(_shell_metadata_inventory(value, namespace, saved=True)) == read(_ROOT / 'public/shell-metadata-save-after.json', 8192)",
            "canonical(_shell_version_inventory(value, namespace, saved=True)) == read(_ROOT / 'public/shell-version-save-after.json', 8192)"])
        session_loop = final.body[2]
        self.assertEqual(ast.unparse(session_loop.iter), "SHELL_SESSION_CASES")
        self.assertEqual(ast.unparse(session_loop.body[0].value.args[0]),
            "canonical(_shell_session_inventory(value, namespace, case, changed=case == 'session-refusals')) == read(_ROOT / 'public' / ('shell-' + case + '-after.json'), SHELL_SESSION_INVENTORY_LIMIT)")
        tools_loop = final.body[3]
        self.assertEqual(ast.unparse(tools_loop.iter), "SHELL_TOOLS_OFFLINE_CASES")
        self.assertEqual(ast.unparse(tools_loop.body[0].value.args[0]),
            "canonical(_shell_tools_offline_inventory(value, namespace, case, after=True)) == read(_ROOT / 'public' / ('shell-' + case + '-after.json'), SHELL_TOOLS_OFFLINE_INVENTORY_LIMIT)")
        shell = next(node for node in unit.body if isinstance(node, ast.If) and ast.unparse(node.test) == "'shell' in value")
        self.assertIs(shell.body[3], loop)
        self.assertEqual(ast.unparse(shell.body[4]), "_shell_fixtures_final(value, namespace)")
        self.assertFalse(any(isinstance(node, (ast.Try, ast.While)) for node in ast.walk(final)))
        calls = [node for node in ast.walk(unit) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == "_shell_metadata_inventory"]
        self.assertEqual(len(calls), 1)
        self.assertTrue(metadata.body[0].lineno <= calls[0].lineno <= metadata.body[0].end_lineno)
        version = next(node for node in branch.orelse[3:] if isinstance(node, ast.If) and ast.unparse(node.test) == "case == 'version-save'")
        self.assertEqual([ast.unparse(node) for node in version.body], [
            "version_after = canonical(_shell_version_inventory(value, namespace, saved=True))",
            "_retain('shell-version-save-after.json', version_after)",
            "shell_version_fixture(value, read(_ROOT / 'public/shell-version-save-before.json', 8192), version_after)"])
        version_calls = [node for node in ast.walk(unit) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                         and node.func.id == "_shell_version_inventory"]
        self.assertEqual(len(version_calls), 1)
        self.assertTrue(version.body[0].lineno <= version_calls[0].lineno <= version.body[0].end_lineno)
        self.assertFalse(any(isinstance(node, ast.Try) for node in ast.walk(loop)))



class VersionSaveLifecycleContracts(unittest.TestCase):
    def test_version_receipt_requires_three_original_sessions_and_typed_finality(self):
        expected = version_receipt_data(); raw = L.canonical(expected)
        compact = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertEqual((len(compact), len(raw)), (1431, 1432))
        self.assertEqual(raw, compact + b"\n")
        self.assertLessEqual(len(raw), 2048)
        self.assertEqual(L.shell_version_receipt(raw), expected)
        self.assertEqual(expected["reviews"]["actions"], ["create", "replace", "preserve"])
        self.assertEqual(expected["readback"]["values"], [["1.2.3", 7], ["2.3.4", 8], ["2.3.4", 8]])
        self.assertEqual(expected["draft"]["bindings"], [[2, 0], [4, 1], [4, 2]])
        # Different booleans/integers, wrong domains and apparent success before
        # any original writer/child/owner/ledger/relay retirement all fail closed.
        changes = (
            (("schemaVersion",), True), (("domain",), "metadata"), (("gate",), "installed-metadata-profile"),
            (("requests", "apply"), 2), (("requests", "workflow", 0), 1),
            (("draft", "bindings", 2, 1), 1), (("reviews", "distinctOriginals"), 1),
            (("confirmation", "checkboxOnlyDisabled"), True), (("confirmation", "acknowledged"), 2),
            (("originals", "writerFrames", 2), 2), (("originals", "stdoutFrames", 1), 2),
            (("originals", "startupJoined"), 2), (("originals", "childWaited"), 2),
            (("originals", "ioSettled"), 2), (("originals", "ownersJoined"), 2),
            (("originals", "runtimeLedgerSettled"), 2), (("originals", "runtimeSettlementJoined"), 2),
            (("nativeFinality", 2), "retained"), (("nativeReasons", 0), "unknown"), (("lateSettled", 0), True),
            (("outcomes", 2, 0), "committed"), (("filesystem", "preserveFull9"), False),
            (("filesystem", "replaceIdentityChanged"), False), (("readback", "savedBaseline"), 2),
            (("quit", "relayJoined"), False), (("quit", "originalsSettled"), False),
        )
        for path, bad in changes:
            changed = deepcopy(expected); parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = bad
            with self.subTest(path=path), self.assertRaises(ValueError):
                L.shell_version_receipt(L.canonical(changed))
        for key in expected:
            changed = deepcopy(expected); changed.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                L.shell_version_receipt(L.canonical(changed))
        for malformed in (b"", b"{}", b"[]", raw + b" ", raw.replace(b'"apply":3', b'"apply":3,"apply":3'),
                          json.dumps(expected, indent=2).encode(), raw + b" " * 2048,
                          L.canonical(metadata_receipt_data()), L.canonical({**expected, "qualified": True})):
            with self.subTest(raw=malformed), self.assertRaises(ValueError):
                L.shell_version_receipt(malformed)
        labels = [b"MRK_INSTALLED_SHELL_FAILURE_STEP=" + step.encode() + b"\n" for step in (
            "VersionOpen", "VersionReadOpen", "VersionName", "VersionBuild", "VersionReadInputs",
            "VersionReview", "VersionReadReview", "VersionConfirm", "VersionReadConfirmation", "VersionCheck",
            "VersionReadChecked", "VersionType", "VersionReadTyped", "VersionApply", "VersionReadSaved",
            "VersionReadback", "VersionReadReadback")]
        self.assertEqual([label for label in L.SHELL_FAILURE_STEPS if b"=Version" in label], labels)
        self.assertEqual(L.SHELL_FAILURE_LABEL_LIMIT, 512)

    def test_version_original_stdout_framing_rejects_missing_foreign_or_premature_success(self):
        stdout, stderr = version_capture(); lines = stdout.splitlines(keepends=True)
        result = L.shell_result(stdout, stderr, "version-save", 0, {})
        self.assertEqual(result["versionSave"], version_receipt_data())
        self.assertEqual(len(lines), 5)
        invalid = [(b"", b""), (stdout, lines[3]), (b"", stdout),
                   (stdout.rstrip(b"\n"), b""), (stdout.replace(b"\n", b"\r\n"), b""),
                   (b"".join(lines[:3] + [lines[4], lines[3]]), b""),
                   (metadata_capture()[0], b""), (stdout + b"MRK_UNEXPECTED=1\n", b"")]
        for index, line in enumerate(lines):
            invalid.extend(((b"".join(lines[:index] + lines[index + 1:]), b""), (stdout + line, b"")))
        for out, err in invalid:
            with self.subTest(stdout=out, stderr=err), self.assertRaises(ValueError):
                L.shell_result(out, err, "version-save", 0, {})
        for code in (1, -1, True, False, None):
            with self.subTest(code=code), self.assertRaises(ValueError):
                L.shell_result(stdout, stderr, "version-save", code, {})
        for case in ("normal", "positive", "metadata-save", "settled-failure"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                L.shell_result(stdout, stderr, case, 0, {})

    def test_version_fixture_preserves_every_original_and_one_distinct_final_source(self):
        value = installed_handoff(); before = version_fixture_data(value); after = version_fixture_data(value, saved=True)
        raw, final = L.canonical(before), L.canonical(after)
        with patch.object(Path, "lstat", side_effect=AssertionError("Closed DATA cannot inspect a live fixture")), \
             patch.object(L, "record", side_effect=AssertionError("Closed DATA cannot reopen originals")):
            result = L.shell_version_fixture(value, raw, final)
        self.assertEqual(result, {
            "fixture": "release-version-save-v1", "rootRetained": True, "preservedOriginals": True,
            "createdFileCount": 1, "beforeCount": 5, "afterCount": 6,
            "configurationUnchanged": True, "ignoreUnchanged": True, "sentinelUnchanged": True,
            "noUnexpectedEntries": True, "noPendingState": True,
            "version": {"path": "version.properties", "size": 34,
                        "sha256": hashlib.sha256(b"VERSION_NAME=2.3.4\nBUILD_NUMBER=8\n").hexdigest(), "mode": 0o600},
            "before": {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
            "after": {"size": len(final), "sha256": hashlib.sha256(final).hexdigest()}})
        self.assertEqual(before["absent"], [*after["absent"], "version.properties"])
        self.assertEqual((len(L._shell_version_roster(value, False)), len(L._shell_version_roster(value, True))), (5, 6))
        for index, original in enumerate(before["entries"]):
            for field in range(6 if original["path"] == "." else 9):
                changed = deepcopy(after); changed["entries"][index]["identity"][field] += 1
                with self.subTest(preserved=original["path"], field=field), self.assertRaises(ValueError):
                    L.shell_version_fixture(value, raw, L.canonical(changed))
            changed = deepcopy(after); changed["entries"][-1]["identity"][1] = original["identity"][1]
            with self.subTest(alias=original["path"]), self.assertRaises(ValueError):
                L.shell_version_fixture(value, raw, L.canonical(changed))
        mutations = (
            lambda d: d.update(schemaVersion=True), lambda d: d.update(saved=int(d["saved"])),
            lambda d: d.update(root=d["root"].replace("version-project", "metadata-project")),
            lambda d: d.update(absent=[]), lambda d: d["entries"].pop(),
            lambda d: d["entries"].reverse(), lambda d: d["entries"].append(deepcopy(d["entries"][-1])),
            lambda d: d["entries"][0]["children"].append(".mobile-release-version"),
            lambda d: d["entries"][1]["children"].append("unexpected"),
            lambda d: d["entries"][-1].update(sha256="0" * 64), lambda d: d["entries"][-1].update(size=True),
            lambda d: d["entries"][-1]["identity"].__setitem__(2, stat.S_IFLNK | 0o600),
            lambda d: d["entries"][-1]["identity"].__setitem__(2, stat.S_IFREG | 0o644),
            lambda d: d["entries"][-1]["identity"].__setitem__(3, 0),
            lambda d: d["entries"][-1]["identity"].__setitem__(5, 2),
            lambda d: d["entries"][-1]["identity"].__setitem__(0, 2),
            lambda d: d["entries"][-1]["identity"].__setitem__(1, d["namespace"]["identity"][1]),
        )
        for saved, document in ((False, before), (True, after)):
            for mutate in mutations:
                changed = deepcopy(document); mutate(changed)
                with self.subTest(saved=saved, mutate=mutate), self.assertRaises(ValueError):
                    L.shell_version_fixture(value, raw if saved else L.canonical(changed), L.canonical(changed) if saved else final)
        for first, last in ((raw, raw), (final, raw), (final, final), (b"{}", final),
                            (json.dumps(before, indent=2).encode(), final), (raw, final + b" "),
                            (raw, final.replace(b'"saved":true', b'"saved":true,"saved":true'))):
            with self.subTest(first=first, last=last), self.assertRaises(ValueError):
                L.shell_version_fixture(value, first, last)

    def test_version_inventory_uses_only_fixed_files_and_rejects_namespace_or_original_drift(self):
        value = installed_handoff(); namespace = fixture_namespace_data(value); binding = L.canonical(namespace)
        project = Path(namespace["root"]) / "version-project"
        for saved in (False, True):
            for fault in (None, "pending", "release-child", "file-mode", "bytes", "parent-drift", "namespace-drift", "residue"):
                fixture = version_fixture_data(value, saved=saved)
                by_path = {project if row["path"] == "." else project / row["path"]: row for row in fixture["entries"]}
                if fault == "pending": by_path[project]["children"].append(".mobile-release-version")
                if fault == "release-child": by_path[project / "release"]["children"].append("unexpected")
                if fault == "file-mode": by_path[project / "unrelated.txt"]["identity"][2] = stat.S_IFLNK | 0o600
                counts = {}
                def metadata(path):
                    row = by_path[path]; n = list(row["identity"]); counts[path] = counts.get(path, 0) + 1
                    if fault == "parent-drift" and path == project and counts[path] > 1: n[8] += 1
                    return SimpleNamespace(**dict(zip(("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                                                       "st_size", "st_mtime_ns", "st_ctime_ns"), n)))
                class Entries:
                    def __init__(self, path): self.children = by_path[path]["children"]
                    def __enter__(self): return iter(SimpleNamespace(name=name) for name in self.children)
                    def __exit__(self, *_): return False
                def record(path, limit):
                    row = by_path[path]; self.assertEqual(limit, row["size"])
                    return {"path": str(path), "size": row["size"], "sha256": "0" * 64 if fault == "bytes" else row["sha256"]}
                with self.subTest(saved=saved, fault=fault), patch.object(L, "_ROOT", L.root_path(value)), patch.object(L, "directory"), \
                     patch.object(Path, "lstat", metadata), patch.object(L.os, "scandir", side_effect=Entries), \
                     patch.object(L, "_shell_namespace_check", side_effect=[namespace, L.Refused("namespace drift")] if fault == "namespace-drift"
                                  else None, return_value=namespace) as namespaces, \
                     patch.object(L, "record", side_effect=record) as reads, \
                     patch.object(L, "_absent", side_effect=L.Refused("residue") if fault == "residue" else None) as absent:
                    if fault is None:
                        self.assertEqual(L._shell_version_inventory(value, binding, saved=saved), fixture)
                        self.assertEqual([call.args for call in namespaces.call_args_list], [(value, binding)] * 2)
                        self.assertEqual([call.args for call in reads.call_args_list],
                            [(project / row["path"], row["size"]) for row in fixture["entries"] if row["kind"] == "file"])
                        self.assertEqual([call.args[0] for call in absent.call_args_list], [project / name for name in fixture["absent"]])
                    else:
                        with self.assertRaises(ValueError): L._shell_version_inventory(value, binding, saved=saved)
                        if fault in ("pending", "release-child", "parent-drift"): reads.assert_not_called()
        with patch.object(L, "_ROOT", L.root_path(value)), \
             patch.object(L, "_shell_namespace_check", side_effect=AssertionError("Invalid phase must not inspect originals")):
            for saved in (0, 1, None, "true"):
                with self.subTest(saved=saved), self.assertRaises(ValueError):
                    L._shell_version_inventory(value, binding, saved=saved)

    def test_closed_version_requires_original_capture_fixture_and_successful_command(self):
        value, outcome, files, expected = closed_shell_data()
        with patch.object(L, "shell_closed_loader", return_value=expected):
            result = L.shell_closed_result(value, outcome, files)
        self.assertEqual(result["versionSave"]["native"], version_receipt_data())
        self.assertEqual(result["versionSave"]["fixture"]["afterCount"], 6)
        for change in ("before", "after", "display", "case", "receipt", "capture", "command", "exit", "argv", "unchanged", "journal"):
            altered, current = dict(files), deepcopy(outcome)
            if change in ("before", "after"):
                altered.pop("shell-version-save-" + change + ".json")
            elif change == "display":
                altered.pop("shell-version-save-xvfb.stderr")
            elif change in ("case", "receipt"):
                cases = L.decode(altered["shell-cases.json"])
                if change == "case": cases.pop("version-save")
                else: cases["version-save"]["versionSave"] = metadata_receipt_data()
                altered["shell-cases.json"] = L.canonical(cases)
            elif change == "capture":
                altered["shell-version-save.stdout"] = metadata_capture()[0]
            elif change == "command":
                current["commands"] = [row for row in current["commands"] if row["phase"] != "shell-version-save"]
            elif change in ("exit", "argv"):
                command = next(row for row in current["commands"] if row["phase"] == "shell-version-save")
                if change == "exit": command["exitCode"] = 1
                else: command["argv"][-1] = "metadata-save"
            elif change == "unchanged":
                altered["shell-version-save-after.json"] = altered["shell-version-save-before.json"]
            else:
                document = L.decode(altered["shell-version-save-after.json"])
                document["entries"][0]["children"].append(".mobile-release-version")
                altered["shell-version-save-after.json"] = L.canonical(document)
            with self.subTest(change=change), patch.object(L, "shell_closed_loader", return_value=expected), \
                 patch.object(L, "_shell_version_inventory", side_effect=AssertionError("No failed-work rescan")), \
                 self.assertRaises((ValueError, KeyError)):
                L.shell_closed_result(value, current, altered)


class CandidateDocumentsLifecycleContracts(unittest.TestCase):
    def test_fixed_literal_bytes_produce_the_existing_android_documents_only_dto(self):
        # Only an explicitly run DATA check imports the actual pure validators.
        # The production lifecycle never imports them or constructs a sealer.
        from mobile_release import provenance
        from mobile_release.api import _candidate_evidence as evidence
        tree = ast.parse((SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_text())
        literal = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "SHELL_CANDIDATE_DOCUMENTS" for target in node.targets))
        self.assertIsInstance(literal, ast.Dict)
        self.assertTrue(all(isinstance(node, ast.Constant) and type(node.value) is bytes for node in literal.values))
        self.assertEqual(list(L.SHELL_CANDIDATE_DOCUMENTS), [row[0] for row in CANDIDATE_FIXTURE_PINS])
        for relative, source, size, digest in CANDIDATE_FIXTURE_PINS:
            raw = L.SHELL_CANDIDATE_DOCUMENTS[relative]
            self.assertEqual(raw, (SOURCE / "tests/fixtures" / source).read_bytes())
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (size, digest))
        expected_raw = (SOURCE / "desktop/tests/fixtures/candidate-evidence.json").read_bytes()
        self.assertEqual((len(expected_raw), hashlib.sha256(expected_raw).hexdigest()),
                         (6652, "a5689c1d0067cff8a2315f65fb8dc4d828ee041aab7f11d3c5eebf5ce0ec5923"))
        expected = json.loads(expected_raw)["androidConsistent"]
        inventory = SimpleNamespace(counts={"sourceBytes": 0}, tick=lambda: True)
        def read_document(relative, *, limit):
            raw = L.SHELL_CANDIDATE_DOCUMENTS[relative]
            self.assertLessEqual(len(raw), limit)
            inventory.counts["sourceBytes"] += len(raw)
            return raw.decode("utf-8")
        reader = SimpleNamespace(read=Mock(side_effect=read_document))
        with patch.object(os, "open", side_effect=AssertionError("No fixture or artifact open")), \
             patch.object(Path, "open", side_effect=AssertionError("No document-directed read")), \
             patch.object(provenance, "sha256_file", side_effect=AssertionError("No artifact payload hashing")), \
             patch.object(provenance, "seal", side_effect=AssertionError("No evidence generation")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("No execution")):
            actual = evidence._read_outcome(reader, inventory)
        self.assertEqual(actual, expected)
        self.assertEqual([call.args[0] for call in reader.read.call_args_list], list(L.SHELL_CANDIDATE_DOCUMENTS))
        self.assertEqual(inventory.counts["sourceBytes"], 11366)
        manifest = json.loads(L.SHELL_CANDIDATE_DOCUMENTS["candidate-manifest.json"])
        self.assertEqual(tuple(row["fileName"] for row in manifest["artifacts"]), L.SHELL_CANDIDATE_ARTIFACT_TARGETS)
        self.assertTrue(actual["assurance"]["documentsOnly"])
        for key in ("artifactBytesVerified", "workflowAuthenticated", "storeStateObserved", "comparedWithSourceProject", "releaseReady", "recoveryAuthorized"):
            self.assertIs(actual["assurance"][key], False)
        self.assertNotEqual(actual["summary"]["documentPayloadSha256"]["manifest"], CANDIDATE_FIXTURE_PINS[0][3])

    def test_unchanged_candidate_bytes_produce_the_new_lifecycle_candidate_projection(self):
        from mobile_release import provenance
        from mobile_release.api import _lifecycle_evidence as evidence
        expected = json.loads((SOURCE / "desktop/tests/fixtures/lifecycle-evidence.json").read_bytes())["androidCandidate"]
        inventory = SimpleNamespace(counts={"sourceBytes": 0}, tick=lambda: True)
        def read_document(relative, *, limit):
            raw = L.SHELL_CANDIDATE_DOCUMENTS[relative]
            self.assertLessEqual(len(raw), limit)
            inventory.counts["sourceBytes"] += len(raw)
            return raw.decode("utf-8")
        reader = SimpleNamespace(read=Mock(side_effect=read_document))
        with patch.object(os, "open", side_effect=AssertionError("No fixture or artifact open")), \
             patch.object(Path, "open", side_effect=AssertionError("No document-directed read")), \
             patch.object(provenance, "sha256_file", side_effect=AssertionError("No payload hashing")), \
             patch.object(provenance, "seal", side_effect=AssertionError("No evidence generation")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("No execution")):
            actual = evidence._read_outcome("candidate", reader, inventory)
        self.assertEqual(actual, expected)
        self.assertEqual([call.args[0] for call in reader.read.call_args_list],
                         [row["path"] for row in expected["documents"]])
        self.assertEqual(inventory.counts["sourceBytes"], 11366)
        self.assertEqual(actual["stage"], "candidate")
        self.assertEqual([row["stage"] for row in actual["history"]], ["candidate"])
        self.assertEqual(actual["guidance"]["code"], "candidate-only")
        self.assertIs(actual["assurance"]["documentsOnly"], True)
        for key in ("artifactBytesVerified", "workflowAuthenticated", "storeStateObserved", "comparedWithSourceProject", "releaseReady", "recoveryAuthorized"):
            self.assertIs(actual["assurance"][key], False)

    def test_legacy_candidate_marker_body_or_combined_key_cannot_be_relabelled_as_lifecycle_proof(self):
        legacy = legacy_candidate_documents_receipt()
        marker = b"MRK_INSTALLED_SHELL_CANDIDATE_DOCUMENTS="
        with self.assertRaises(ValueError):
            L.shell_lifecycle_receipt(L.canonical(legacy))
        stdout, stderr = positive_capture()
        for changed in (stdout.replace(L.SHELL_LIFECYCLE_MARKER, marker),
                        positive_capture(lifecycle=legacy)[0],
                        positive_capture(lifecycle=legacy)[0].replace(L.SHELL_LIFECYCLE_MARKER, marker),
                        stdout + marker + L.canonical(legacy)):
            with self.subTest(stdout=changed), self.assertRaises(ValueError):
                L.shell_result(changed, stderr, "positive", 0, map_data())
        value, outcome, files, mappings = closed_shell_data()
        for body in (legacy, lifecycle_documents_receipt()):
            changed = dict(files)
            cases = L.decode(changed["shell-cases.json"])
            cases["positive"].pop("lifecycleDocuments")
            cases["positive"]["candidateDocuments"] = body
            changed["shell-cases.json"] = L.canonical(cases)
            with self.subTest(body=body), patch.object(L, "shell_closed_loader", return_value=mappings), self.assertRaises(ValueError):
                L.shell_closed_result(value, outcome, changed)

    def test_candidate_receipt_rejects_each_missing_changed_or_wrongly_typed_leaf(self):
        expected = lifecycle_documents_receipt()
        raw = L.canonical(expected)
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()),
                         (1690, "7d7bef285e1d9aace0e4a5b6811c063ea6e2c2ef058b31bffc4b1cb37c16cb53"))
        self.assertLessEqual(len(raw), 2048)
        self.assertEqual(L.shell_lifecycle_receipt(raw), expected)
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
                    parent[path[-1]] = not original if type(original) is bool else original + 1 if type(original) is int else original[::-1] if type(original) is list else original + "-other"
                with self.subTest(path=path, mode=mode):
                    with self.assertRaises(ValueError):
                        L.shell_lifecycle_receipt(L.canonical(changed))
                    with self.assertRaises(ValueError):
                        L.shell_result(*positive_capture(lifecycle=changed), "positive", 0, mappings)
                    altered = dict(files)
                    cases = L.decode(altered["shell-cases.json"])
                    cases["positive"]["lifecycleDocuments"] = changed
                    altered["shell-cases.json"] = L.canonical(cases)
                    with patch.object(L, "shell_closed_loader", return_value=mappings), self.assertRaises(ValueError):
                        L.shell_closed_result(value, outcome, altered)
        for changed in (b"", b"{}", b"[]", b"null", raw + b" " * 2048,
                        raw.replace(b'"scope":{', b'"scope":{},"scope":{'),
                        raw.replace(b'"exit":true', b'"exit":true,"exit":true'),
                        L.canonical({**expected, "selectionId": "untrusted"}),
                        L.canonical({**expected, "scope": {**expected["scope"], "workflowAuthenticated": True}}),
                        *(L.canonical({key: child for key, child in expected.items() if key != omitted})
                          for omitted in ("cancel", "select", "observe", "preserved", "scope", "quit"))):
            with self.subTest(raw=changed), self.assertRaises(ValueError):
                L.shell_lifecycle_receipt(changed)

    def test_both_independent_receipts_must_precede_completion_in_exact_stdout_order(self):
        stdout, stderr = positive_capture()
        lines = stdout.splitlines(keepends=True)
        self.assertEqual(len(lines), 6)
        # Permute the independent contract/receipt/completion suffix; the
        # positive transport test covers both bootstrap records and all cuts.
        for order in permutations(range(2, 6)):
            if order == (2, 3, 4, 5):
                continue
            with self.subTest(order=order), self.assertRaises(ValueError):
                L.shell_result(b"".join(lines[:2] + [lines[index] for index in order]), stderr, "positive", 0, map_data())
        for index in range(6):
            for changed in (b"".join(lines[:index] + lines[index + 1:]), b"".join(lines[:index] + [lines[index]] + lines[index:])):
                with self.subTest(index=index, stdout=changed), self.assertRaises(ValueError):
                    L.shell_result(changed, stderr, "positive", 0, map_data())
        for index in (3, 4):
            with self.subTest(stderr=index), self.assertRaises(ValueError):
                L.shell_result(b"".join(lines[:index] + lines[index + 1:]), stderr + lines[index], "positive", 0, map_data())
            # Exactly 2048 bytes of JSON without LF must fail once the
            # independent line terminator is counted, not share another cap.
            marker = L.SHELL_PROJECT_MARKER if index == 3 else L.SHELL_LIFECYCLE_MARKER
            raw = lines[index][len(marker):-1]
            inflated = list(lines)
            inflated[index] = marker + raw + b" " * (2048 - len(raw)) + b"\n"
            with self.subTest(oversize=index), self.assertRaises(ValueError):
                L.shell_result(b"".join(inflated), stderr, "positive", 0, map_data())
        value, _, files, mappings = closed_shell_data()
        for case in ("normal", "quit-outstanding"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                L.shell_result(files["shell-" + case + ".stdout"] + lines[4], files["shell-" + case + ".stderr"], case, 0, mappings)

    def test_candidate_inventory_requires_exact_five_unchanged_nodes_and_absent_artifacts(self):
        value = installed_handoff()
        fixture = candidate_fixture_data(value)
        raw = L.canonical(fixture)
        with patch.object(Path, "lstat", side_effect=AssertionError("Closed DATA cannot inspect possible-live work")):
            result = L.shell_candidate_fixture(value, raw, raw)
        self.assertEqual(result, {"fixture": "android-candidate-documents-v1", "rootRetained": True, "documentsUnchanged": True,
            "noUnexpectedEntries": True, "artifactTargetsAbsent": True, "entryCount": 5, "documentBytes": 11366,
            "directoryMode": 0o700, "fileMode": 0o600,
            "documents": [{"path": name, "size": size, "sha256": digest} for name, _, size, digest in CANDIDATE_FIXTURE_PINS],
            "before": {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
            "after": {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}})
        for index, row in enumerate(fixture["entries"]):
            for field in range(9):
                changed = deepcopy(fixture)
                changed["entries"][index]["identity"][field] += 1
                for before, after in ((raw, L.canonical(changed)), (L.canonical(changed), raw)):
                    with self.subTest(node=index, identity=field), self.assertRaises(ValueError):
                        L.shell_candidate_fixture(value, before, after)
        mutations = (
            lambda v: v.update(schemaVersion=True), lambda v: v.update(fixture="android-saved-readonly-v1"),
            lambda v: v.update(root=str(L.root_path(value) / "positive-project")), lambda v: v.update(saved=True),
            lambda v: v.update(absent=[]), lambda v: v["absent"].append("unbound"),
            lambda v: v["entries"].pop(), lambda v: v["entries"].append(deepcopy(v["entries"][-1])),
            lambda v: v["entries"].reverse(), lambda v: v["entries"][0]["children"].append("reader-1.2.3-42.aab"),
            lambda v: v["entries"][1]["children"].append("credentials"),
            lambda v: v["entries"][2].update(path="../candidate-manifest.json"),
            lambda v: v["entries"][2].update(kind="directory"), lambda v: v["entries"][2].update(size=True),
            lambda v: v["entries"][2].update(sha256="0" * 64), lambda v: v["entries"][2].update(extra=True),
            lambda v: v["entries"][2]["identity"].__setitem__(1, True),
            lambda v: v["entries"][2]["identity"].__setitem__(2, stat.S_IFLNK | 0o600),
            lambda v: v["entries"][2]["identity"].__setitem__(3, 0),
            lambda v: v["entries"][2]["identity"].__setitem__(4, 0),
            lambda v: v["entries"][2]["identity"].__setitem__(5, 2),
            lambda v: v["entries"][3]["identity"].__setitem__(0, 2),
            lambda v: v["entries"][3]["identity"].__setitem__(1, v["entries"][2]["identity"][1]),
        )
        for mutate in mutations:
            changed = deepcopy(fixture); mutate(changed)
            # Two mutually agreeing but invalid inventories still cannot pass.
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                L.shell_candidate_fixture(value, L.canonical(changed), L.canonical(changed))
        for malformed in (b"{}", b"[]", raw + b" " * 8192, json.dumps(fixture, indent=2).encode(),
                          raw.replace(b'"entries":[', b'"entries":[],"entries":[')):
            with self.subTest(raw=malformed), self.assertRaises(ValueError):
                L.shell_candidate_fixture(value, malformed, raw)

    def test_actual_candidate_inventory_never_reads_artifacts_or_unexpected_subtrees(self):
        value = installed_handoff(); root = L.root_path(value); namespace = fixture_namespace_data(value)
        binding = L.canonical(namespace); evidence = Path(namespace["root"]) / "candidate-evidence"
        for case in ("complete", "artifact", "private-subtree", "mode", "owner", "links", "special", "bytes", "alias", "device", "drift"):
            fixture = candidate_fixture_data(value)
            by_path = {evidence if row["path"] == "." else evidence / row["path"]: row for row in fixture["entries"]}
            if case == "artifact": by_path[evidence]["children"].append("reader-1.2.3-42.aab")
            if case == "private-subtree": by_path[evidence / "operation"]["children"].append("credentials")
            first, second = (by_path[evidence / name] for name in ("candidate-manifest.json", "candidate-receipt.json"))
            if case == "mode": first["identity"][2] = stat.S_IFREG | 0o644
            if case == "owner": first["identity"][3] = 0
            if case == "links": first["identity"][5] = 2
            if case == "special": first["identity"][2] = stat.S_IFLNK | 0o600
            if case == "bytes": first["sha256"] = "f" * 64
            if case == "alias": second["identity"][1] = first["identity"][1]
            if case == "device": second["identity"][0] = 2
            def file_stat(path):
                values = by_path[path]["identity"]
                return SimpleNamespace(**dict(zip(("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"), values)))
            def scan(path):
                context = Mock()
                context.__enter__ = Mock(return_value=iter(SimpleNamespace(name=name) for name in by_path[path]["children"]))
                context.__exit__ = Mock(return_value=False)
                return context
            def read_data(path, limit):
                row = by_path[path]
                self.assertEqual(limit, row["size"])
                if case == "drift" and path.name == "candidate-receipt.json":
                    first["identity"][8] += 1
                return {"path": str(path), "size": row["size"], "sha256": row["sha256"]}
            with self.subTest(case=case), patch.object(L, "_ROOT", root), patch.object(L, "directory"), \
                 patch.object(L, "_shell_namespace_check", return_value=namespace) as namespace_check, \
                 patch.object(Path, "lstat", file_stat), patch.object(L.os, "scandir", side_effect=scan) as scans, \
                 patch.object(L, "record", side_effect=read_data) as reads, patch.object(L, "_absent") as absent:
                if case == "complete":
                    self.assertEqual(L._shell_candidate_inventory(value, binding), fixture)
                    self.assertEqual([call.args for call in namespace_check.call_args_list], [(value, binding)] * 2)
                    self.assertEqual([call.args for call in reads.call_args_list], [(evidence / name, size) for name, _, size, _ in CANDIDATE_FIXTURE_PINS])
                    self.assertEqual([call.args[0] for call in absent.call_args_list], [evidence / relative for relative in fixture["absent"]])
                else:
                    with self.assertRaises(ValueError):
                        L._shell_candidate_inventory(value, binding)
                    if case in {"artifact", "private-subtree", "mode", "owner", "links", "special"}:
                        reads.assert_not_called()
                self.assertTrue(all(call.args[0] in {evidence, evidence / "operation"} for call in scans.call_args_list))
                self.assertTrue(all(call.args[0] in {evidence / name for name in L.SHELL_CANDIDATE_DOCUMENTS} for call in reads.call_args_list))

    def test_closed_candidate_requires_both_receipts_and_separate_original_exports(self):
        value, outcome, files, mappings = closed_shell_data()
        with patch.object(L, "shell_closed_loader", return_value=mappings):
            result = L.shell_closed_result(value, outcome, files)
        self.assertEqual(result["lifecycleDocuments"]["native"], lifecycle_documents_receipt())
        self.assertEqual(result["lifecycleDocuments"]["fixture"]["before"], result["lifecycleDocuments"]["fixture"]["after"])
        self.assertEqual(result["projectDraft"]["native"], project_draft_receipt())
        for change in ("missing-before", "missing-after", "changed-after", "case-partial", "case-missing", "stdout-partial", "stdout-missing", "wrong-exit"):
            changed, current = dict(files), deepcopy(outcome)
            if change.startswith("missing-"):
                changed.pop("shell-positive-candidate-" + change.removeprefix("missing-") + ".json")
            elif change == "changed-after":
                fixture = L.decode(changed["shell-positive-candidate-after.json"])
                fixture["entries"][0]["identity"][1] += 1
                changed["shell-positive-candidate-after.json"] = L.canonical(fixture)
            elif change.startswith("case-"):
                cases = L.decode(changed["shell-cases.json"])
                if change == "case-missing": cases["positive"].pop("lifecycleDocuments")
                else: cases["positive"]["lifecycleDocuments"].pop("observe")
                changed["shell-cases.json"] = L.canonical(cases)
            elif change == "stdout-partial":
                partial = lifecycle_documents_receipt(); partial.pop("quit")
                changed["shell-positive.stdout"] = positive_capture(lifecycle=partial)[0]
            elif change == "stdout-missing":
                changed["shell-positive.stdout"] = b"".join(line for line in changed["shell-positive.stdout"].splitlines(keepends=True)
                                                          if not line.startswith(L.SHELL_LIFECYCLE_MARKER))
            else:
                current["commands"][1]["exitCode"] = 1
            with self.subTest(change=change), patch.object(L, "shell_closed_loader", return_value=mappings), \
                 patch.object(L, "_shell_candidate_inventory", side_effect=AssertionError("No failed-work rescan")), self.assertRaises((ValueError, KeyError)):
                L.shell_closed_result(value, current, changed)
        tree = ast.parse((SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_text())
        body = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "unit_start")
        calls = [(node.func.id, node.lineno) for node in ast.walk(body) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        gated = [line for name, line in calls if name == "shell_result"]
        inventories = sorted(line for name, line in calls if name == "_shell_candidate_inventory")
        self.assertEqual((len(gated), len(inventories)), (1, 2))
        self.assertLess(gated[0], inventories[0])
        loop = next(node for node in ast.walk(body) if isinstance(node, ast.For)
                    and ast.unparse(node.iter) == "shell_cases(value)")
        original_case = next(node for node in loop.body if isinstance(node, ast.Try))
        branch = next(node for node in original_case.body if isinstance(node, ast.If)
                      and ast.unparse(node.test) == "case == 'normal'")
        gate = next(index for index, node in enumerate(branch.orelse) if isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "shell_result")
        positive = next(node for node in branch.orelse[gate + 1:] if isinstance(node, ast.If)
                        and ast.unparse(node.test) == "case == 'positive'")
        # The original post-exit capture remains a direct positive-branch
        # assignment inside the original case's try/finally. Later rechecks
        # reuse this fixture only after their completed case gates.
        self.assertTrue(any(isinstance(node, ast.Assign) and node.lineno <= inventories[0] <= node.end_lineno for node in positive.body))
        names = ["_shell_project_inventory", "_shell_candidate_inventory", "_shell_paths_inventory"]
        for index, (case, expected_calls) in enumerate((("workflow-apply", names),), 1):
            later = next(node for node in branch.orelse[gate + 1:]
                         if isinstance(node, ast.If) and ast.unparse(node.test) == "case == '" + case + "'")
            rechecks = [node for node in later.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                        and isinstance(node.value.func, ast.Name) and node.value.func.id == "need"]
            self.assertEqual(len(rechecks), 1)
            self.assertLess(gated[0], inventories[index])
            self.assertTrue(rechecks[0].lineno <= inventories[index] <= rechecks[0].end_lineno)
            self.assertEqual([node.func.id for node in ast.walk(rechecks[0]) if isinstance(node, ast.Call)
                              and isinstance(node.func, ast.Name) and node.func.id in {*names, "_shell_workflow_inventory"}],
                             expected_calls)



class ProjectPathLifecycleContracts(unittest.TestCase):
    def test_receipt_exact_size_every_leaf_and_closed_original_correspondence(self):
        receipt = project_path_receipt(); raw = L.canonical(receipt)
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (1482, "b3784f485377a9e7b249d5dcac1eae98ae4825dd1e9bf1fbce4b0f2e82698633"))
        self.assertEqual(L.shell_path_receipt(raw), receipt)
        value, outcome, files, expected = closed_shell_data()
        with patch.object(L, "shell_closed_loader", return_value=expected):
            result = L.shell_closed_result(value, outcome, files)
        self.assertEqual(result["projectPaths"]["native"], receipt)
        self.assertEqual(result["projectPaths"]["fixture"]["rootModes"], [0o700, 0o500])
        stdout, stderr = path_capture()
        lines = stdout.splitlines(keepends=True)
        self.assertEqual(len(lines), 5)
        noise = b"ordinary wrapper text\nMRKDBG_DESKTOP_BOOTSTRAP=hook-installed\n"
        self.assertEqual(L.shell_result(noise + noise.join(lines), noise, "project-paths", 0, expected), result["cases"]["project-paths"])
        changes = [(b"".join(lines[2:]), b"".join(lines[:2])), (stdout.rstrip(b"\n"), stderr),
                   (stdout + b"MRK_UNKNOWN=1\n", stderr), (stdout.replace(b"=available", b"=unavailable"), stderr)]
        for index, line in enumerate(lines):
            changes.extend(((b"".join(lines[:index] + lines[index + 1:]), stderr), (stdout + line, stderr),
                            (b"".join(lines[:index] + lines[index + 1:]), line)))
            if index + 1 < len(lines):
                changed = list(lines); changed[index], changed[index + 1] = changed[index + 1], changed[index]
                changes.append((b"".join(changed), stderr))
        for out, err in changes:
            with self.subTest(stdout=out, stderr=err), self.assertRaises(ValueError):
                L.shell_result(out, err, "project-paths", 0, expected)
        def leaves(value, prefix=()):
            if type(value) is dict:
                for key, child in value.items():
                    yield from leaves(child, (*prefix, key))
            elif type(value) is list:
                for key, child in enumerate(value):
                    yield from leaves(child, (*prefix, key))
            else:
                yield prefix, value
        for path, old in leaves(receipt):
            for mode in ("missing", "changed", "wrong-type"):
                changed = deepcopy(receipt); parent = changed
                for key in path[:-1]:
                    parent = parent[key]
                if mode == "missing":
                    del parent[path[-1]]
                else:
                    parent[path[-1]] = (int(old) if type(old) is bool else True if type(old) is int else None) if mode == "wrong-type" else (
                        not old if type(old) is bool else old + 1 if type(old) is int else old + "-other")
                with self.subTest(path=path, mode=mode), self.assertRaises(ValueError):
                    L.shell_path_receipt(L.canonical(changed))
        for raw in (b"{}", L.canonical(receipt) + b" ", json.dumps(receipt, indent=2).encode(),
                    L.canonical(receipt).replace(b'"exit":true', b'"exit":true,"exit":true'),
                    L.canonical({**receipt, "select": list(reversed(receipt["select"]))}),
                    L.canonical({**receipt, "scope": "release-ready"}), b" " * 2049):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                L.shell_path_receipt(raw)
        for change in ("missing-case", "case-type", "stdout", "stderr-only", "reorder", "line-endings", "exit", "display", "combined-cap", "before", "after"):
            current = deepcopy(outcome); altered = dict(files)
            if change in ("missing-case", "case-type"):
                cases = L.decode(altered["shell-cases.json"])
                if change == "missing-case":
                    cases.pop("project-paths")
                else:
                    cases["project-paths"]["projectPaths"]["originals"]["childNew"] = True
                altered["shell-cases.json"] = L.canonical(cases)
            elif change in ("before", "after"):
                altered.pop("shell-project-paths-" + change + ".json")
            elif change == "stdout":
                altered["shell-project-paths.stdout"] = b"MRK_INSTALLED_SHELL_OBSERVATION=project-paths-verified\n"
            elif change == "stderr-only":
                altered["shell-project-paths.stderr"] += altered["shell-project-paths.stdout"]
                altered["shell-project-paths.stdout"] = b""
            elif change == "reorder":
                altered["shell-project-paths.stdout"] = b"".join(reversed(altered["shell-project-paths.stdout"].splitlines(keepends=True)))
            elif change == "line-endings":
                altered["shell-project-paths.stdout"] = altered["shell-project-paths.stdout"].replace(b"\n", b"\r\n")
            elif change == "exit":
                next(row for row in current["commands"] if row["phase"] == "shell-project-paths")["exitCode"] = 1
            elif change == "display":
                altered.pop("shell-project-paths-xvfb.stderr")
            else:
                altered["shell-project-paths-xvfb.stderr"] = b"x" * L.LIMIT
            with self.subTest(change=change), patch.object(L, "shell_closed_loader", return_value=expected), \
                 patch.object(L, "_shell_paths_inventory", side_effect=AssertionError("No live/failed original rescan")), self.assertRaises((ValueError, KeyError)):
                L.shell_closed_result(value, current, altered)

    def test_exact_fixture_transitions_reject_aliases_kind_content_or_identity_drift(self):
        value, _, _, _ = closed_shell_data()
        before = path_fixture_data(value); after = path_fixture_data(value, changed=True)
        result = L.shell_paths_fixture(value, L.canonical(before), L.canonical(after))
        self.assertEqual((result["beforeCount"], result["afterCount"], result["fileCount"], result["fileBytes"]), (14, 15, 5, 130))
        self.assertNotEqual(result["before"]["sha256"], result["after"]["sha256"])
        mutations = (
            lambda d: d.update(changed=False), lambda d: d.update(schemaVersion=True), lambda d: d.update(root="/other"),
            lambda d: d["entries"].pop(), lambda d: d["entries"].reverse(), lambda d: d["absent"].pop(),
            lambda d: d["entries"][0]["identity"].__setitem__(2, stat.S_IFDIR | 0o700),
            lambda d: d["entries"][0]["identity"].__setitem__(1, 999), lambda d: d["entries"][0]["identity"].__setitem__(7, 22),
            lambda d: d["entries"][1]["children"].append("extra"), lambda d: d["entries"][1]["identity"].__setitem__(3, 0),
            lambda d: d["entries"][3]["identity"].__setitem__(1, 999), lambda d: d["entries"][3]["identity"].__setitem__(5, 2),
            lambda d: d["entries"][5].update(kind="file"), lambda d: d["entries"][9].update(path="path-project/ios/Kind.xcodeproj"),
            lambda d: d["entries"][10]["identity"].__setitem__(1, d["entries"][2]["identity"][1]),
            lambda d: d["entries"][11]["identity"].__setitem__(8, 22), lambda d: d["entries"][13].update(size=True),
            lambda d: d["entries"][13].update(sha256="0" * 64), lambda d: d["entries"][14].update(target="../VERSION"),
            lambda d: d["entries"][14]["identity"].__setitem__(0, 2), lambda d: d["entries"][14]["identity"].__setitem__(1, 300),
        )
        for mutate in mutations:
            changed = deepcopy(after); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                L.shell_paths_fixture(value, L.canonical(before), L.canonical(changed))
        for left, right in ((after, before), (before, before), (after, after)):
            with self.assertRaises(ValueError):
                L.shell_paths_fixture(value, L.canonical(left), L.canonical(right))

    def test_inventory_admits_all_parents_before_only_fixed_inert_reads_and_no_link_follow(self):
        value, _, _, _ = closed_shell_data(); namespace = fixture_namespace_data(value)
        root = Path(namespace["root"]); binding = L.canonical(namespace)
        for changed in (False, True):
            expected = path_fixture_data(value, changed=changed)
            by_path = {root / row["path"]: row for row in expected["entries"]}
            def metadata(path):
                row = by_path[path]; n = row["identity"]
                return SimpleNamespace(**dict(zip(("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"), n)))
            class Entries:
                def __init__(self, path): self.children = by_path[path]["children"]
                def __enter__(self): return iter(SimpleNamespace(name=name) for name in self.children)
                def __exit__(self, *_): return False
            def read_file(path, limit):
                self.assertEqual(limit, 26); row = by_path[path]; self.assertEqual(row["kind"], "file")
                return {"path": str(path), "size": row["size"], "sha256": row["sha256"]}
            with patch.object(L, "_ROOT", L.root_path(value)), patch.object(L, "_absent"), \
                 patch.object(L, "_shell_namespace_check", return_value=namespace) as namespace_check, \
                 patch.object(Path, "lstat", metadata), patch.object(L.os, "scandir", side_effect=Entries), \
                 patch.object(L.os, "readlink", return_value="link-original") as link, patch.object(L, "record", side_effect=read_file) as reads:
                self.assertEqual(L._shell_paths_inventory(value, binding, changed=changed), expected)
                self.assertEqual([call.args for call in namespace_check.call_args_list], [(value, binding)] * 2)
                self.assertEqual(reads.call_count, 5)
                self.assertEqual(link.call_count, int(changed))
                reads.reset_mock(); by_path[root / "path-project"]["children"].append("unexpected")
                with self.assertRaises(ValueError):
                    L._shell_paths_inventory(value, binding, changed=changed)
                reads.assert_not_called()

    def test_after_inventory_is_only_after_success_in_the_existing_original_case_branch(self):
        tree = ast.parse((SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_text())
        body = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "unit_start")
        loop = next(n for n in ast.walk(body) if isinstance(n, ast.For) and isinstance(n.iter, ast.Name) and n.iter.id == "SHELL_CASES")
        branch = next(n for n in loop.body if isinstance(n, ast.If))
        gate = next(i for i,n in enumerate(branch.orelse) if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
                    and isinstance(n.value.func, ast.Name) and n.value.func.id == "shell_result")
        path_branch = next(n for n in branch.orelse[gate+1:] if isinstance(n, ast.If) and ast.unparse(n.test) == "case == 'project-paths'")
        calls = [n for n in ast.walk(path_branch) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_shell_paths_inventory"]
        self.assertEqual(len(calls), 1)
        self.assertEqual([(arg.arg, ast.literal_eval(arg.value)) for arg in calls[0].keywords], [("changed", True)])
        workflow_branch = next(n for n in branch.orelse[gate+1:] if isinstance(n, ast.If) and ast.unparse(n.test) == "case == 'workflow-apply'")
        workflow_calls = [n for n in ast.walk(workflow_branch) if isinstance(n, ast.Call)
                          and isinstance(n.func, ast.Name) and n.func.id == "_shell_workflow_inventory"]
        self.assertEqual(len(workflow_calls), 1)
        self.assertEqual([(arg.arg, ast.literal_eval(arg.value)) for arg in workflow_calls[0].keywords], [("installed", True)])
        metadata_branch = next(n for n in branch.orelse[gate+1:] if isinstance(n, ast.If) and ast.unparse(n.test) == "case == 'metadata-save'")
        metadata_calls = [n for n in ast.walk(metadata_branch) if isinstance(n, ast.Call)
                          and isinstance(n.func, ast.Name) and n.func.id == "_shell_metadata_inventory"]
        self.assertEqual(len(metadata_calls), 1)
        self.assertEqual([(arg.arg, ast.literal_eval(arg.value)) for arg in metadata_calls[0].keywords], [("saved", True)])
        self.assertEqual(L.SHELL_CASES, ("normal", "positive", "quit-outstanding", "project-paths", "workflow-apply",
                                       "session-inputs", "session-refusals", "session-loss", "session-deadline", "metadata-save",
                                       "tools-observed", "tools-cancel", "tools-settlement", "offline-pass", "offline-negative",
                                       "offline-drift", "offline-cancel", "offline-settlement", "settled-failure", "version-save"))



class ToolsOfflineLifecycleContracts(unittest.TestCase):
    def test_fixed_synthetic_roster_configs_and_existing_project_script_are_pinned(self):
        # Shape/correspondence DATA only. Actual core configuration validation
        # belongs to the separately admitted native Offline cases, not this test.
        rust = (SOURCE / "desktop/src-tauri/src/offline_preflight_owner_tests.rs").read_text()
        script = rust.split('const SCRIPT: &str = r#"', 1)[1].split('"#;', 1)[0].encode("ascii")
        self.assertEqual(script, L.SHELL_TOOLS_OFFLINE_SCRIPT)
        self.assertEqual((len(script), hashlib.sha256(script).hexdigest()),
                         (829, "4ff4b3b59ea27f0761881c9ab56d9478c0ce1e6f74554105917d8fcd8ea0d9e1"))
        pins = {"pass": (1045, "5e9bbc6ceb2d3a08ac8a78a393138ea74aa996954d744ac9f2fbdc28db6ef84d"),
                "nonzero": (1174, "4081ee76f52e0c4f50c788a53856bd80c69b2462e2d5349318b32a4603737419"),
                "active": (1173, "e59ce7cab9b7959e217bde3054bf87ac1576f1bd1a5fe2ef880963356e2509ec")}
        value = installed_handoff()
        for case in L.SHELL_TOOLS_OFFLINE_CASES:
            with self.subTest(case=case):
                roster = L._shell_tools_offline_roster(value, case)
                self.assertEqual(len(roster), 21)
                self.assertEqual(sum(stat.S_ISDIR(mode) for _, mode, _, _ in roster), 9)
                self.assertEqual(sum(stat.S_ISREG(mode) for _, mode, _, _ in roster), 12)
                self.assertTrue(all(owners == (value["runnerUid"], value["runnerGid"]) and stat.S_IMODE(mode) in (0o600, 0o700)
                                    for _, mode, owners, _ in roster))
                files = {name: data for name, mode, _, data in roster if stat.S_ISREG(mode)}
                self.assertEqual(files["project/script.trace"], files["project/later.trace"])
                self.assertEqual(files["project/script.trace"], b"")
                self.assertEqual(files["project/gradlew"], b"#!/bin/sh\nexit 93\n")
                config = files["project/release/mobile-release.json"]
                document = json.loads(config)
                mode = "nonzero" if case == "offline-negative" else "active" if case == "offline-cancel" else "pass"
                self.assertEqual((len(config), hashlib.sha256(config).hexdigest()), pins[mode])
                prefix = ["/usr/bin/python3.12", "-I", "-S", "-B", "check.py"]
                self.assertEqual(document["projectChecks"], {"androidArtifact": [], "iosArtifact": [],
                    "preflight": [prefix + [mode]] + ([prefix + ["later"]] if mode != "pass" else [])})
        self.assertEqual(L.SHELL_TOOLS_OFFLINE_RECEIPT_LIMIT, 64 << 10)
        self.assertEqual(L.SHELL_TOOLS_OFFLINE_INVENTORY_LIMIT, 16 << 10)

    def test_eight_receipts_require_original_transport_and_do_not_invent_child_maps(self):
        for case in L.SHELL_TOOLS_OFFLINE_CASES:
            receipt = tools_offline_receipt(case)
            raw = L.canonical(receipt); self.assertLess(len(raw), 32 << 10)
            self.assertEqual(L.shell_tools_offline_receipt(raw, case), receipt)
            stdout, stderr = tools_offline_capture(case)
            result = L.shell_result(stdout, stderr, case, 0, map_data())
            self.assertEqual(result, {"case": case, "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True,
                                      "maps": [], "toolsOffline": receipt})
            lines = stdout.splitlines(keepends=True)
            for bad_stdout, bad_stderr, code in ((b"".join(lines[:3] + lines[4:]), b"", 0),
                    (b"".join(lines[:3] + [lines[3], lines[3]] + lines[4:]), b"", 0),
                    (b"".join(lines[:2] + [lines[3], lines[2], lines[4]]), b"", 0),
                    (stdout + b"MRK_INSTALLED_NATIVE_CHILD=[]\n", b"", 0), (stdout, b"MRK_PRIVATE=unknown\n", 0),
                    (stdout, stderr, 1), (stdout, stderr, True), (stdout.rstrip(b"\n"), stderr, 0)):
                with self.subTest(case=case, code=code, stdout=bad_stdout[:30]), self.assertRaises(ValueError):
                    L.shell_result(bad_stdout, bad_stderr, case, code, map_data())
            for bad in (raw + b" ", raw.rstrip(b"\n"), raw.replace(b'"case":', b'"case":"duplicate","case":', 1),
                        b"x" * ((64 << 10) + 1), bytearray(raw)):
                with self.subTest(case=case, framing=type(bad)), self.assertRaises(ValueError):
                    L.shell_tools_offline_receipt(bad, case)

    def test_receipts_reject_missing_fields_false_joins_and_forged_route_consent(self):
        for case in L.SHELL_TOOLS_OFFLINE_CASES:
            receipt = tools_offline_receipt(case)
            mutations = [lambda d, key=key: d.pop(key) for key in receipt]
            mutations += [lambda d, key=key: d["original"].__setitem__(key, not d["original"][key])
                          for key, value in receipt["original"].items() if type(value) is bool]
            mutations += [lambda d, key=key: d["requests"].__setitem__(key, bool(d["requests"][key])) for key in receipt["requests"]]
            mutations += [lambda d: d.update(qualificationOnly=False), lambda d: d.update(builder="observer-only"),
                lambda d: d["ui"].update(terminal=False), lambda d: d["ui"].update(consent=not d["ui"]["consent"]),
                lambda d: d["initial"].update(toolsAvailable=False), lambda d: d["initial"].update(offlineAvailable=False),
                lambda d: d["hold"].update(boundary="watchdog"), lambda d: d["hold"].update(released=not d["hold"]["released"]),
                lambda d: d["original"].update(id="c" * 32), lambda d: d["original"].update(generation="c" * 32),
                lambda d: d["terminal"]["context"].update(draftRevision=True), lambda d: d["terminal"]["context"].update(baselineGeneration=2 ** 32 - 1),
                lambda d: d["terminal"]["context"].update(projectId="/private/path"), lambda d: d["fixture"].update(laterTrace="later\n"),
                lambda d: d["fixture"].update(savedConfigChanged=not d["fixture"]["savedConfigChanged"])]
            for mutate in mutations:
                altered = deepcopy(receipt); mutate(altered)
                with self.subTest(case=case, mutate=mutate), self.assertRaises(ValueError):
                    L.shell_tools_offline_receipt(L.canonical(altered), case)

    def test_tools_honest_lookup_refusal_is_not_positive_jdk_or_partial_readiness(self):
        for attempted in (0, 1):
            receipt = tools_offline_receipt("tools-observed")
            core = receipt["terminal"]["result"]
            for row in core["checks"][attempted:]:
                row.update(state="not-run", reason="unsupported-installation", version=None, returnCode=None, assessment="not-assessed")
            outcome = "complete" if attempted else "unavailable"
            receipt["terminal"]["outcome"] = core["outcome"] = outcome
            core["commandsAttempted"] = core["lifetime"]["commands"] = attempted
            core["lifetime"]["commandDispatched"] = core["assurance"]["toolsAttempted"] = bool(attempted)
            self.assertEqual(L.shell_tools_offline_receipt(L.canonical(receipt), "tools-observed"), receipt)
        original = tools_offline_receipt("tools-observed")
        for mutate in (lambda d: d["terminal"].update(finality="pending"), lambda d: d["terminal"].update(outcome="partial"),
                       lambda d: d["terminal"]["result"].update(outcome="failed"),
                       lambda d: d["terminal"]["result"].update(commandsAttempted=True),
                       lambda d: d["terminal"]["result"]["lifetime"].update(complete=False),
                       lambda d: d["terminal"]["result"]["assurance"].update(releaseReadiness="ready"),
                       lambda d: d["terminal"]["result"]["assurance"].update(projectCodeExecuted=True),
                       lambda d: d["terminal"]["result"]["checks"][1].update(assessment="match"),
                       lambda d: d["terminal"]["result"]["checks"][1].update(help="raw\noutput"),
                       lambda d: d["terminal"]["result"]["checks"][1].update(returnCode=True),
                       lambda d: d["terminal"]["result"]["checks"].reverse()):
            altered = deepcopy(original); mutate(altered)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                L.shell_tools_offline_receipt(L.canonical(altered), "tools-observed")

    def test_offline_negative_drift_and_cancel_cannot_be_relabelled_pass_or_no_child(self):
        for case in ("offline-pass", "offline-negative", "offline-drift", "offline-cancel", "offline-settlement"):
            original = tools_offline_receipt(case)
            mutations = [lambda d: d["terminal"].update(intentUsable=True), lambda d: d["original"].update(noChild=True),
                         lambda d: d["terminal"]["context"]["savedConfig"].update(sha256="0" * 64),
                         lambda d: d["terminal"].update(reason="none" if case in ("offline-drift", "offline-cancel") else "cancelled")]
            if original["terminal"]["result"] is not None:
                mutations += [lambda d: d["terminal"]["result"]["summary"].update(total=True),
                    lambda d: d["terminal"]["result"]["findings"][1].update(projectCheckIndex=1),
                    lambda d: d["terminal"]["result"]["findings"][1].update(status="PASS" if case == "offline-negative" else "FAIL"),
                    lambda d: d["terminal"]["result"].update(limitations=[]), lambda d: d["terminal"]["result"].update(scope="release-ready")]
            else:
                mutations += [lambda d: d["terminal"].update(result={}), lambda d: d["terminal"].update(outcome="complete")]
            for mutate in mutations:
                altered = deepcopy(original); mutate(altered)
                with self.subTest(case=case, mutate=mutate), self.assertRaises(ValueError):
                    L.shell_tools_offline_receipt(L.canonical(altered), case)

    def test_fixture_changes_are_exact_in_place_mutations_of_the_same_originals(self):
        value = installed_handoff()
        for case in L.SHELL_TOOLS_OFFLINE_CASES:
            before, after = (tools_offline_fixture_data(value, case, after=phase) for phase in (False, True))
            observed = L.shell_tools_offline_fixture(value, case, L.canonical(before), L.canonical(after))
            self.assertEqual(observed["beforeCount"], observed["afterCount"])
            self.assertEqual(observed["beforeCount"], 21)
            self.assertEqual({key: observed[key] for key in ("scriptTrace", "laterTrace", "savedConfigChanged")},
                             tools_offline_receipt(case)["fixture"])
            for mutate in (lambda d: d["entries"][0]["identity"].__setitem__(1, 9000),
                           lambda d: d["entries"][-1]["identity"].__setitem__(5, 2),
                           lambda d: d["entries"][-1]["identity"].__setitem__(3, 0),
                           lambda d: d["entries"][-1].update(kind="symlink"),
                           lambda d: d["entries"][-1].update(size=True), lambda d: d["entries"][-1].update(sha256="0" * 64),
                           lambda d: d["entries"][1]["children"].append(".mobile-release"),
                           lambda d: d["entries"].append(deepcopy(d["entries"][-1])),
                           lambda d: d["namespace"]["identity"].__setitem__(1, 9999), lambda d: d.update(changed=not d["changed"]),
                           lambda d: d.update(absent=[])):
                altered = deepcopy(after); mutate(altered)
                with self.subTest(case=case, mutate=mutate), self.assertRaises(ValueError):
                    L.shell_tools_offline_fixture(value, case, L.canonical(before), L.canonical(altered))
            for name in observed["mutations"]:
                altered = deepcopy(after)
                row = next(row for row in altered["entries"] if row["path"] == name); row["identity"][1] += 5000
                with self.subTest(case=case, replaced=name), self.assertRaisesRegex(ValueError, "replaced or chmodded"):
                    L.shell_tools_offline_fixture(value, case, L.canonical(before), L.canonical(altered))

    def test_inventory_admits_complete_parent_rosters_before_any_leaf_bytes(self):
        value = installed_handoff(); namespace = fixture_namespace_data(value); binding = L.canonical(namespace)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        for case in L.SHELL_TOOLS_OFFLINE_CASES:
            for after in (False, True):
                document = tools_offline_fixture_data(value, case, after=after); base = Path(document["root"])
                nodes = {base / row["path"]: row for row in document["entries"]}
                def metadata(path): return SimpleNamespace(**dict(zip(fields, nodes[path]["identity"])))
                def scan(path):
                    context = Mock(); context.__enter__ = Mock(return_value=iter(SimpleNamespace(name=n) for n in nodes[path]["children"]))
                    context.__exit__ = Mock(return_value=False); return context
                def record(path, limit):
                    row = nodes[path]; self.assertEqual(limit, row["size"])
                    return {"path": str(path), "size": row["size"], "sha256": row["sha256"]}
                with self.subTest(case=case, after=after), patch.object(L, "_ROOT", L.root_path(value)), \
                     patch.object(L, "_shell_namespace_check", return_value=namespace) as checking, patch.object(L, "directory"), \
                     patch.object(Path, "lstat", metadata), patch.object(L.os, "scandir", side_effect=scan), \
                     patch.object(L, "record", side_effect=record) as reading, patch.object(L, "_xattrs"), patch.object(L, "_absent") as absent, \
                     patch.object(L.os, "readlink", side_effect=AssertionError("No aliases in a Tools/Offline fixture")):
                    self.assertEqual(L._shell_tools_offline_inventory(value, binding, case, after=after), document)
                    self.assertEqual(reading.call_count, 12)
                    self.assertEqual([call.args for call in checking.call_args_list], [(value, binding)] * 2)
                    self.assertEqual([call.args[0] for call in absent.call_args_list], [base / name for name in document["absent"]])
                    reading.reset_mock()
                    nodes[base / "project/release/store/android/en-US/changelogs"]["children"].append("unreviewed")
                    with self.assertRaises(ValueError): L._shell_tools_offline_inventory(value, binding, case, after=after)
                    reading.assert_not_called()

    def test_new_postexit_capture_stays_after_the_existing_success_gate(self):
        tree = ast.parse((SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_text())
        unit = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "unit_start")
        loop = next(node for node in ast.walk(unit) if isinstance(node, ast.For) and ast.unparse(node.iter) == "SHELL_CASES")
        branch = next(node for node in loop.body if isinstance(node, ast.If))
        gate = next(i for i, node in enumerate(branch.orelse) if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name) and node.value.func.id == "shell_result")
        added = next(node for node in branch.orelse[gate + 1:] if isinstance(node, ast.If) and ast.unparse(node.test) == "case in SHELL_TOOLS_OFFLINE_CASES")
        inventories = [node for node in ast.walk(added) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                       and node.func.id == "_shell_tools_offline_inventory"]
        self.assertEqual(len(inventories), 1)
        self.assertEqual([(kw.arg, ast.literal_eval(kw.value)) for kw in inventories[0].keywords], [("after", True)])
        self.assertFalse(any(isinstance(node, (ast.Try, ast.While)) for node in ast.walk(added)))
        self.assertEqual([node.func.id for node in ast.walk(unit) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                          and node.func.id == "_shell_fixtures_prepare"], ["_shell_fixtures_prepare"])

    def test_closed_result_rebinds_every_new_native_receipt_and_inventory(self):
        value, outcome, files, expected = closed_shell_data()
        with patch.object(L, "shell_closed_loader", return_value=expected):
            observed = L.shell_closed_result(value, outcome, files)
            self.assertEqual(set(observed["toolsOffline"]), set(L.SHELL_TOOLS_OFFLINE_CASES))
            for case in L.SHELL_TOOLS_OFFLINE_CASES:
                self.assertEqual(observed["toolsOffline"][case]["native"], tools_offline_receipt(case))
                for fault in ("receipt", "inventory", "command"):
                    altered, result = dict(files), deepcopy(outcome)
                    if fault == "receipt":
                        cases = L.decode(altered["shell-cases.json"]); cases[case]["toolsOffline"]["original"]["driverJoined"] = False
                        altered["shell-cases.json"] = L.canonical(cases)
                    elif fault == "inventory":
                        name = "shell-" + case + "-after.json"; document = L.decode(altered[name])
                        document["entries"][-1]["sha256"] = "0" * 64; altered[name] = L.canonical(document)
                    else:
                        next(row for row in result["commands"] if row["phase"] == "shell-" + case)["exitCode"] = 1
                    with self.subTest(case=case, fault=fault), self.assertRaises(ValueError):
                        L.shell_closed_result(value, result, altered)


class SessionFixtureContracts(unittest.TestCase):
    def test_private_fixture_actual_snapshot_matches_installed_session_contract(self):
        from mobile_release.api._snapshot import project_snapshot

        # Use the actual static reader, not only configuration validation or a
        # fabricated bridge reply. Nothing here starts a tool or reads a secret.
        with tempfile.TemporaryDirectory(prefix="mrk-session-snapshot-") as directory:
            root = Path(directory) / "project"
            root.mkdir(mode=0o700)
            (root / "release").mkdir(mode=0o700)
            files = {
                "release/mobile-release.json": L.SHELL_SESSION_CONFIG,
                "version.properties": L.SHELL_PROJECT_VERSION,
            }
            for name, data in files.items():
                fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)

            def identity(path):
                value = path.lstat()
                return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

            # Reads may update atime, but may not replace even identical input
            # bytes or change the original file/directory identities.
            originals = {path: identity(path) for path in (root, root / "release", *(root / name for name in files))}
            actual = project_snapshot(str(root))
            self.assertEqual({path: identity(path) for path in originals}, originals)
            self.assertEqual(actual["root"], str(root))
            self.assertEqual(actual["observationScope"], "single-request-non-atomic")
            config = actual["config"]
            self.assertEqual(config["path"], "release/mobile-release.json")
            self.assertEqual(config["state"], "format-valid")
            self.assertEqual(config["issues"], [])
            self.assertEqual(config["data"], json.loads(L.SHELL_SESSION_CONFIG))
            self.assertEqual(config["content"], {
                "bytes": 608,
                "sha256": "ce38aeb0676d4221a3054744083162158e5a33afade4e77ca4dcf9e7c96d53c3",
            })
            self.assertEqual(actual["issues"], [])
            self.assertEqual(actual["discovery"]["state"], "unverified")
            self.assertIs(actual["discovery"]["partial"], False)
            self.assertEqual(actual["discovery"]["scan"], {
                "sourceFiles": 2, "sourceBytes": 642, "entries": 3, "excludedEntries": 0,
            })
            self.assertEqual(actual["assurance"]["basis"], "static-text")
            self.assertEqual(actual["assurance"]["releaseReadiness"], "unknown")
            for field in ("projectCodeExecuted", "toolsProbed", "credentialsRead", "gitObserved",
                          "storeContacted", "writesPerformed"):
                self.assertIs(actual["assurance"][field], False)
            for name, data in files.items():
                self.assertEqual((root / name).read_bytes(), data)
                self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o600)

    def test_private_fixture_config_is_valid_shared_policy_without_build_commands(self):
        from mobile_release.config import validate_config_data
        draft = json.loads(L.SHELL_SESSION_CONFIG)
        validate_config_data(draft)
        self.assertEqual(draft["android"], {"applicationId": "org.assessment.fixture", "enabled": True, "identityStatus": "unverified"})
        self.assertEqual(draft["ios"], {"enabled": False})
        self.assertEqual(draft["projectChecks"], {"androidArtifact": [], "iosArtifact": [], "preflight": []})
        self.assertEqual(draft["services"], {"androidFirebase": "required", "iosFirebase": "disabled"})
        self.assertIs(draft["source"]["projectReadTokenRequired"], True)
        self.assertEqual(draft["version"]["source"], "version.properties")

    def test_original_session_receipt_framing_profile_finality_and_redaction_are_closed(self):
        for case in L.SHELL_SESSION_CASES:
            mappings = map_data()
            stdout, stderr = session_capture(case)
            expected = deepcopy(L.SHELL_SESSION_RECEIPTS[case])
            with self.subTest(case=case):
                result = L.shell_result(stdout, stderr, case, 0, mappings)
                self.assertEqual(result["sessionInputs"], expected)
                self.assertEqual(len(result["maps"]), expected["behavior"]["assessments"])
                self.assertTrue(all(len(rows) == 6 for rows in result["maps"]))
                self.assertLessEqual(len(L.canonical(expected)), 4096)
            mutations = [
                lambda doc: doc.update(schemaVersion=True), lambda doc: doc.update(case="positive"),
                lambda doc: doc.update(methods="twelve-passive"), lambda doc: doc.update(profile="development-runtime"),
                lambda doc: doc["project"].update(snapshotMatched=1), lambda doc: doc.pop("behavior"),
                lambda doc: doc.update(privateInput="fictional-private-input-must-not-be-exported"),
                lambda doc: doc["safety"].update(signingVerified=True),
                lambda doc: doc["behavior"].update(assessments=True),
                lambda doc: doc["behavior"].update(assessments=17),
            ]
            for original in ("assetJoined", "sourceClosed", "r1Joined", "guiSettled", "relayJoined", "exit"):
                altered = deepcopy(expected); altered["originals"][original] = False
                with self.subTest(case=case, original=original), self.assertRaises(ValueError):
                    L.shell_session_receipt(L.canonical(altered), case)
            for mutate in mutations:
                altered = deepcopy(expected); mutate(altered)
                with self.subTest(case=case, mutate=mutate), self.assertRaises(ValueError):
                    L.shell_result(*session_capture(case, altered), case, 0, mappings)
            lines = stdout.splitlines(keepends=True)
            for altered in (b"".join(lines[1:]), b"".join(reversed(lines)), stdout + lines[3], stdout.replace(b"\n", b"\r\n"),
                            stdout.replace(case.encode() + b"-verified", b"positive-verified")):
                with self.subTest(case=case, framing=altered[:48]), self.assertRaises(ValueError):
                    L.shell_result(altered, b"", case, 0, mappings)
            with self.assertRaises(ValueError): L.shell_result(stdout, stdout, case, 0, mappings)
            with self.assertRaises(ValueError): L.shell_result(stdout, stderr, case, True, mappings)
            with self.assertRaises(ValueError): L.shell_session_receipt(L.canonical(expected) + b" " * 4096, case)

    def test_each_assessment_requires_its_original_six_loader_bound_roles(self):
        mappings = map_data()
        case = "session-inputs"
        maps = L.shell_result(*session_capture(case), case, 0, mappings)["maps"]
        mutations = (
            lambda rows: rows.clear(), lambda rows: rows.pop(), lambda rows: rows.append(deepcopy(rows[0])),
            lambda rows: rows[0].pop(), lambda rows: rows[0].reverse(),
            lambda rows: rows[0][0].update(role="different"), lambda rows: rows[0][0].update(path="/unadmitted/object"),
            lambda rows: rows[0][0].update(inode=9999), lambda rows: rows[0][0].update(deviceMajor=True),
            lambda rows: rows[0][0].update(extra="not-a-map-field"),
        )
        for mutate in mutations:
            changed = deepcopy(maps); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                L.shell_result(*session_capture(case, maps=changed), case, 0, mappings)
        with self.assertRaises(ValueError):
            L.shell_result(*session_capture(case, maps=[deepcopy(maps[0]) for _ in range(17)]), case, 0, mappings)
        stdout, _ = session_capture(case)
        lines = stdout.splitlines(keepends=True)
        for altered in (b"".join(lines[:3] + lines[4:]), b"".join(lines[:3] + [lines[3].rstrip(b"\n")] + lines[4:]),
                        b"".join(lines[:3] + [lines[3].replace(b"\n", b"\r\n")] + lines[4:])):
            with self.assertRaises(ValueError): L.shell_result(altered, b"", case, 0, mappings)
        with self.assertRaises(ValueError): L.shell_result(stdout, b"", case, 0, {})

    def test_closed_four_case_fixtures_and_only_original_leaf_rename_are_accounted(self):
        value = installed_handoff(); value.update(runId="9" * 20, attempt="9" * 20)
        self.assertEqual(L.SHELL_SESSION_CASES, ("session-inputs", "session-refusals", "session-loss", "session-deadline"))
        self.assertEqual(sum(len(L._shell_session_roster(value, case)) for case in L.SHELL_SESSION_CASES), 42)
        self.assertEqual(L.SHELL_SESSION_JKS, bytes.fromhex("feedfeed0000000200000000"))
        self.assertEqual(L.SHELL_SESSION_REPLACEMENT_JKS, bytes.fromhex("feedfeed0000000100000000"))
        for case in L.SHELL_SESSION_CASES:
            before = L.canonical(session_fixture_data(value, case))
            after = L.canonical(session_fixture_data(value, case, changed=case == "session-refusals"))
            with self.subTest(case=case):
                result = L.shell_session_fixture(value, case, before, after)
                self.assertEqual((result["beforeCount"], result["afterCount"]), (15, 14) if case == "session-refusals" else (9, 9))
                self.assertEqual(result["mutations"], ["changed-leaf-rename"] if case == "session-refusals" else [])
                self.assertTrue(result["projectUnchanged"] and result["sourcesOutsideProject"] and result["originalsAccounted"])
                self.assertEqual(result["before"] == result["after"], case != "session-refusals")
                self.assertLessEqual(max(len(before), len(after)), 8192)
                self.assertLess(len(L.canonical(session_fixture_data(value, case)["namespace"])), 1024)

    def test_refuses_changed_private_originals_aliases_and_unaccounted_replacement(self):
        value = installed_handoff()
        for case in L.SHELL_SESSION_CASES:
            before = session_fixture_data(value, case)
            after = session_fixture_data(value, case, changed=case == "session-refusals")
            mutations = [
                lambda doc: doc.update(case="positive"), lambda doc: doc.update(changed=1),
                lambda doc: doc.update(root=doc["root"] + "/project"), lambda doc: doc.update(schemaVersion=True),
                lambda doc: doc["entries"].pop(), lambda doc: doc["entries"].reverse(),
                lambda doc: doc["namespace"]["identity"].__setitem__(1, 90),
                lambda doc: doc["entries"][0]["children"].append("unrelated"),
                lambda doc: doc["entries"][1]["identity"].__setitem__(2, stat.S_IFDIR | 0o755),
                lambda doc: doc["entries"][1]["identity"].__setitem__(1, doc["entries"][0]["identity"][1]),
                lambda doc: next(row for row in doc["entries"] if row["path"] == "sources/input.jks").update(size=True),
                lambda doc: next(row for row in doc["entries"] if row["path"] == "sources/input.jks")["identity"].__setitem__(2, stat.S_IFREG | 0o644),
                lambda doc: next(row for row in doc["entries"] if row["path"] == "project/release/mobile-release.json").update(sha256="0" * 64),
            ]
            if case == "session-refusals":
                mutations += [
                    lambda doc: doc["absent"].remove("sources/changed-next.jks"),
                    lambda doc: next(row for row in doc["entries"] if row["path"] == "sources/changed.jks")["identity"].__setitem__(1, 999),
                    lambda doc: next(row for row in doc["entries"] if row["path"] == "sources/changed.jks")["identity"].__setitem__(7, 22),
                    lambda doc: next(row for row in doc["entries"] if row["path"] == "sources/link.jks").update(target="../project/overlap.jks"),
                ]
            for mutate in mutations:
                altered = deepcopy(after); mutate(altered)
                with self.subTest(case=case, mutate=mutate), self.assertRaises((ValueError, KeyError)):
                    L.shell_session_fixture(value, case, L.canonical(before), L.canonical(altered))
        # A coherent replacement DATA document is still not the old opened
        # original. Reusing its own before/after inventory cannot hide a rename.
        original = session_fixture_data(value, "session-refusals")
        with self.assertRaises(ValueError):
            L.shell_session_fixture(value, "session-refusals", L.canonical(original), L.canonical(original))

    def test_inventory_admits_all_directory_names_before_source_reads_and_does_not_follow_links(self):
        value = installed_handoff(); case = "session-refusals"
        namespace = fixture_namespace_data(value); binding = L.canonical(namespace)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        for changed in (False, True):
            document = session_fixture_data(value, case, changed=changed)
            base = Path(document["root"])
            nodes = {base if row["path"] == "." else base / row["path"]: row for row in document["entries"]}
            def metadata(path):
                return SimpleNamespace(**dict(zip(fields, nodes[path]["identity"])))
            def scan(path):
                context = Mock()
                context.__enter__ = Mock(return_value=iter(SimpleNamespace(name=name) for name in nodes[path]["children"]))
                context.__exit__ = Mock(return_value=False)
                return context
            def file_record(path, limit):
                row = nodes[path]
                self.assertEqual(row["kind"], "file")
                self.assertEqual(limit, row["size"])
                return {"path": str(path), "size": row["size"], "sha256": row["sha256"]}
            with self.subTest(changed=changed), patch.object(L, "_ROOT", L.root_path(value)), \
                 patch.object(L, "_shell_namespace_check", return_value=namespace), patch.object(L, "directory"), \
                 patch.object(Path, "lstat", metadata), patch.object(L.os, "scandir", side_effect=scan), \
                 patch.object(L, "record", side_effect=file_record) as reading, patch.object(L, "_xattrs"), \
                 patch.object(L.os, "readlink", return_value="input.jks") as linking, patch.object(L, "_absent") as absent:
                self.assertEqual(L._shell_session_inventory(value, binding, case, changed=changed), document)
                self.assertEqual(reading.call_count, 9 if changed else 10)
                linking.assert_called_once_with(base / "sources/link.jks")
                self.assertEqual([call.args[0] for call in absent.call_args_list], [base / name for name in document["absent"]])
                reading.reset_mock(); linking.reset_mock()
                nodes[base / "sources"]["children"].append("unreviewed-output")
                with self.assertRaises(ValueError):
                    L._shell_session_inventory(value, binding, case, changed=changed)
                reading.assert_not_called(); linking.assert_not_called()

    def test_final_metadata_cannot_replace_a_prior_session_inventory_or_its_own_saved_original(self):
        # In-memory failure injection after the final saved-version return. Reuse the
        # actual final comparison, never unit_start, a process or a live tree.
        value, _, files, _ = closed_shell_data()
        namespace = L.canonical(fixture_namespace_data(value))
        sessions = {case: session_fixture_data(value, case, changed=case == "session-refusals") for case in L.SHELL_SESSION_CASES}
        tools = {case: tools_offline_fixture_data(value, case, after=True) for case in L.SHELL_TOOLS_OFFLINE_CASES}
        for changed in (None, *L.SHELL_SESSION_CASES, "metadata-save", "version-save", *L.SHELL_TOOLS_OFFLINE_CASES):
            current = deepcopy(sessions)
            current_tools = deepcopy(tools)
            metadata = metadata_fixture_data(value, saved=True)
            version = version_fixture_data(value, saved=True)
            if changed == "version-save":
                version["entries"][0]["identity"][1] += 1000
            elif changed == "metadata-save":
                metadata["entries"][0]["identity"][1] += 1000
            elif changed in L.SHELL_TOOLS_OFFLINE_CASES:
                current_tools[changed]["entries"][0]["identity"][1] += 1000
            elif changed is not None:
                # Identical fictional bytes can still belong to a different
                # directory original. The already-retained capture must win.
                current[changed]["entries"][0]["identity"][1] += 1000
            def session_inventory(actual_value, actual_namespace, case, *, changed=False):
                self.assertIs(actual_value, value); self.assertEqual(actual_namespace, namespace)
                self.assertEqual(changed, case == "session-refusals")
                return current[case]
            def tools_inventory(actual_value, actual_namespace, case, *, after=False):
                self.assertIs(actual_value, value); self.assertEqual(actual_namespace, namespace)
                self.assertIs(after, True)
                return current_tools[case]
            def retained(path, limit):
                self.assertEqual(path.parent, L.root_path(value) / "public")
                raw = files[path.name]; self.assertLessEqual(len(raw), limit); return raw
            with self.subTest(changed=changed), patch.object(L, "_ROOT", L.root_path(value)), \
                 patch.object(L, "_shell_project_inventory", return_value=project_fixture_data(value, saved=True)), \
                 patch.object(L, "_shell_candidate_inventory", return_value=candidate_fixture_data(value)), \
                 patch.object(L, "_shell_paths_inventory", return_value=path_fixture_data(value, changed=True)), \
                 patch.object(L, "_shell_workflow_inventory", return_value=workflow_fixture_data(value, installed=True)), \
                  patch.object(L, "_shell_metadata_inventory", return_value=metadata), \
                  patch.object(L, "_shell_version_inventory", return_value=version), \
                  patch.object(L, "_shell_session_inventory", side_effect=session_inventory) as checking, \
                  patch.object(L, "_shell_tools_offline_inventory", side_effect=tools_inventory) as checking_tools, \
                 patch.object(L, "read", side_effect=retained), patch.object(L, "_retain") as replacement:
                if changed is None:
                    self.assertIsNone(L._shell_fixtures_final(value, namespace))
                    self.assertEqual([call.args[2] for call in checking.call_args_list], list(L.SHELL_SESSION_CASES))
                    self.assertEqual([call.args[2] for call in checking_tools.call_args_list], list(L.SHELL_TOOLS_OFFLINE_CASES))
                else:
                    reason = ("another original fixture family" if changed in ("metadata-save", "version-save") else
                              "earlier original Tools/Offline fixture" if changed in L.SHELL_TOOLS_OFFLINE_CASES else "earlier original session fixture")
                    with self.assertRaisesRegex(ValueError, reason):
                        L._shell_fixtures_final(value, namespace)
                replacement.assert_not_called()

    def test_session_after_inventory_requires_original_case_gate_without_new_owner_or_deadline(self):
        tree = ast.parse((SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_text())
        unit = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "unit_start")
        loop = next(node for node in ast.walk(unit) if isinstance(node, ast.For)
                    and isinstance(node.iter, ast.Name) and node.iter.id == "SHELL_CASES")
        branch = next(node for node in loop.body if isinstance(node, ast.If))
        gate = next(node for node in branch.orelse if isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "shell_result")
        session = next(node for node in branch.orelse if isinstance(node, ast.If) and ast.unparse(node.test) == "case in SHELL_SESSION_CASES")
        self.assertLess(gate.end_lineno, session.lineno)
        calls = [node for node in ast.walk(session) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        self.assertEqual([node.func.id for node in calls].count("_shell_session_inventory"), 1)
        self.assertEqual([node.func.id for node in calls].count("shell_session_fixture"), 1)
        command = next(node for node in ast.walk(branch) if isinstance(node, ast.Call)
                       and isinstance(node.func, ast.Name) and node.func.id == "command")
        self.assertIn(("maximum", 60), [(arg.arg, ast.literal_eval(arg.value)) for arg in command.keywords if arg.arg == "maximum"])
        self.assertFalse(any(isinstance(node, (ast.Try, ast.While)) for node in ast.walk(session)))



class GitHubEntryFailureLabelContracts(unittest.TestCase):
    def test_guidance_reload_labels_are_closed_and_never_entry_samples(self):
        labels = (b"GitHubGuidanceReady", b"GitHubGuidanceReload")
        expected = [b"MRK_INSTALLED_SHELL_FAILURE_STEP=" + label + b"\n" for label in labels]
        self.assertEqual([line for line in L.SHELL_FAILURE_STEPS if b"=GitHubGuidance" in line], expected)
        for label, first in zip(labels, expected):
            raw = first + b"MRK_INSTALLED_SHELL_FAILURE_PHASE=dom\nMRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n"
            self.assertEqual(L._shell_label_pair(raw), {
                "step": label.decode("ascii"), "boundary": "dom", "bootstrapProgress": "advanced"})
            for invalid in (raw[:-1], raw + b"\n", raw.replace(label, label + b"Extra"),
                            self.frame().replace(b"GitHubEntry", label)):
                self.assertIsNone(L._shell_label_pair(invalid))
        self.assertEqual(L.SHELL_FAILURE_LABEL_LIMIT, 512)

    @staticmethod
    def frame(*, boundary=b"settlement", progress=b"advanced", **changes):
        fields = {
            "o": b"evaluation-budget", "eval": b"128", "ne": b"128", "ns": b"present",
            "cap": b"1", "reason": b"none", "sess": b"0", "de": b"128", "dom": b"wait",
            "sel": b"1", "form": b"1", "submit": b"1", "enabled": b"0", "help": b"na",
            "repo": b"1", "guide": b"1",
        }
        fields.update(changes)
        return (b"MRK_INSTALLED_SHELL_GITHUB_ENTRY_FAILURE=v1;"
                + b";".join(key.encode("ascii") + b"=" + value for key, value in fields.items()) + b"\n"
                + b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubEntry\n"
                + b"MRK_INSTALLED_SHELL_FAILURE_PHASE=" + boundary + b"\n"
                + b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=" + progress + b"\n")

    def test_entry_roundtrip_closed_native_and_same_callback_dom_samples(self):
        parsed = L._shell_label_pair(self.frame())
        self.assertEqual(parsed, {"step": "GitHubEntry", "boundary": "settlement", "bootstrapProgress": "advanced",
            "githubEntry": {"origin": "evaluation-budget", "evaluations": 128,
                "native": {"sampleEvaluations": 128, "status": "present", "capabilityAvailable": True,
                           "capabilityReason": "none", "sessionPresent": False},
                "dom": {"sampleEvaluations": 128, "state": "wait", "pageSelected": True, "formPresent": True,
                        "submitPresent": True, "submitEnabled": False, "helpPresent": None,
                        "repositoryExpected": True, "helpContainerPresent": True}}})
        reasons = (b"none", b"unqualified", b"runtime-unavailable", b"publisher-unconfigured", b"not-connected",
                   b"invalid-input", b"busy", b"unauthorized", b"forbidden", b"not-found-or-inaccessible",
                   b"target-changed", b"rate-limited", b"network-unavailable", b"tls-failed", b"response-invalid",
                   b"response-limit", b"expired", b"stale", b"cancelled", b"cleanup-unknown")
        for reason in reasons:
            native = L._shell_label_pair(self.frame(reason=reason, cap=b"1" if reason == b"none" else b"0"))["githubEntry"]["native"]
            self.assertEqual(native["capabilityReason"], reason.decode("ascii"))
        for presence in (b"absent", b"not-observed"):
            native = L._shell_label_pair(self.frame(ns=presence, ne=b"128" if presence == b"absent" else b"na",
                                                    cap=b"na", reason=b"na", sess=b"na"))["githubEntry"]["native"]
            self.assertEqual(native["status"], presence.decode("ascii"))
            self.assertIsNone(native["capabilityAvailable"])
            self.assertIsNone(native["sessionPresent"])
        # Native and DOM stamps are independent global-counter samples, not a join.
        earlier = L._shell_label_pair(self.frame(ne=b"17", de=b"93"))["githubEntry"]
        self.assertEqual((earlier["native"]["sampleEvaluations"], earlier["dom"]["sampleEvaluations"]), (17, 93))
        unavailable = dict(de=b"na", dom=b"not-observed", sel=b"na", form=b"na", submit=b"na",
                           enabled=b"na", help=b"na", repo=b"na", guide=b"na")
        for origin in (b"callback-shape", b"script-error"):
            data = dict(unavailable, de=b"128", dom=b"error")
            self.assertEqual(L._shell_label_pair(self.frame(o=origin, boundary=b"dom", **data))["githubEntry"]["origin"],
                             origin.decode("ascii"))
        refused = L._shell_label_pair(self.frame(o=b"ready-refused", boundary=b"dom", dom=b"ready",
                                                enabled=b"1", help=b"0", repo=b"0", guide=b"0"))
        self.assertFalse(refused["githubEntry"]["dom"]["repositoryExpected"])
        self.assertFalse(refused["githubEntry"]["dom"]["helpPresent"])
        deadline = L._shell_label_pair(self.frame(o=b"deadline", boundary=b"deadline", eval=b"127", ne=b"127", **unavailable))
        self.assertEqual(deadline["githubEntry"]["evaluations"], 127)
        generic = L._shell_label_pair(self.frame(o=b"not-recorded", eval=b"na", ne=b"na", ns=b"not-observed",
                                                cap=b"na", reason=b"na", sess=b"na", **unavailable))["githubEntry"]
        self.assertIsNone(generic["evaluations"])
        self.assertEqual(generic["native"]["status"], "not-observed")
        self.assertTrue(all(value is None for key, value in generic["dom"].items() if key != "state"))

    def test_entry_rejects_every_prefix_extra_field_and_unbound_shape(self):
        good = self.frame()
        for end in range(len(good)):
            for raw in (good[:end], good[:end] + b"\n"):
                if raw != good:
                    with self.subTest(prefix=end): self.assertIsNone(L._shell_label_pair(raw))
        lines = good.splitlines(keepends=True)
        for raw in (good + b"\n", good + b"x", b"".join(lines[1:]), b"".join(lines[1:] + lines[:1]),
                    good.replace(b"\n", b"\r\n"), good.replace(b"=v1;", b"=v2;"),
                    good.replace(b"GitHubEntry", b"GitHubToken"), good.replace(b"GitHubEntry", b"Bootstrap"),
                    good.replace(b";eval=128", b";eval=128;eval=128"), good.replace(b";repo=1", b""),
                    good.replace(b";guide=1\n", b";guide=1;extra=0\n"), good.replace(b";cap=1", b";cap=true"),
                    good.replace(b";reason=none", b";reason=private-text"), good.decode("ascii")):
            with self.subTest(malformed=repr(raw)[:100]): self.assertIsNone(L._shell_label_pair(raw))
        for key in ("o", "eval", "ne", "ns", "cap", "reason", "sess", "de", "dom", "sel", "form", "submit",
                    "enabled", "help", "repo", "guide"):
            prefix = key.encode("ascii") + b"="
            pieces = lines[0].split(b";")
            raw = b";".join(piece for piece in pieces if not piece.startswith(prefix))
            if not raw.endswith(b"\n"): raw += b"\n"
            self.assertIsNone(L._shell_label_pair(raw + b"".join(lines[1:])))
        for changes in (
            {"eval": b"127"}, {"eval": b"129"}, {"eval": b"na"}, {"eval": b"0128"}, {"eval": b"-1"},
            {"ne": b"129"}, {"ne": b"na"}, {"de": b"0"}, {"de": b"129"}, {"de": b"na"},
            {"ns": b"absent"}, {"cap": b"0"}, {"reason": b"busy"}, {"sess": b"na"},
            {"dom": b"not-observed"}, {"dom": b"error"}, {"dom": b"ready"}, {"sel": b"na"},
            {"form": b"0"}, {"submit": b"0"}, {"enabled": b"na"}, {"enabled": b"1"},
            {"help": b"1"}, {"guide": b"na"}, {"o": b"not-recorded"}, {"o": b"deadline"},
            {"o": b"callback-shape"}, {"repo": b"owner/app"}, {"guide": b"false"},
        ):
            with self.subTest(changes=changes): self.assertIsNone(L._shell_label_pair(self.frame(**changes)))
        for changes in ({"enabled": b"0", "help": b"0"}, {"enabled": b"1", "help": b"1"},
                        {"enabled": b"1", "help": b"0", "de": b"127"}):
            self.assertIsNone(L._shell_label_pair(self.frame(o=b"ready-refused", boundary=b"dom", dom=b"ready", **changes)))

    def test_entry_maximum_legal_frame_fits_original_512_and_legacy_is_unchanged(self):
        doms = (
            dict(de=b"na", dom=b"not-observed", sel=b"na", form=b"na", submit=b"na", enabled=b"na", help=b"na", repo=b"na", guide=b"na"),
            dict(de=b"128", dom=b"error", sel=b"na", form=b"na", submit=b"na", enabled=b"na", help=b"na", repo=b"na", guide=b"na"),
            dict(de=b"128", dom=b"wait", sel=b"0", form=b"0", submit=b"0", enabled=b"na", help=b"na", repo=b"na", guide=b"na"),
            dict(de=b"128", dom=b"ready", sel=b"1", form=b"1", submit=b"1", enabled=b"1", help=b"0", repo=b"na", guide=b"0"),
        )
        natives = (
            dict(ne=b"na", ns=b"not-observed", cap=b"na", reason=b"na", sess=b"na"),
            dict(ne=b"128", ns=b"absent", cap=b"na", reason=b"na", sess=b"na"),
            dict(ne=b"128", ns=b"present", cap=b"0", reason=b"not-found-or-inaccessible", sess=b"0"),
        )
        # Maximal representatives: three-digit counts, longest reason, all
        # legal nullable slots at na; 0 and 1 occupy the same one byte.
        frames = []
        for native in natives:
            for dom in doms:
                for origin, boundary in ((b"evaluation-budget", b"settlement"), (b"deadline", b"deadline"),
                                         (b"callback-shape", b"dom"), (b"script-error", b"dom"), (b"ready-refused", b"dom")):
                    frame = self.frame(o=origin, boundary=boundary, progress=b"app-info-returned-before-hold", **native, **dom)
                    if L._shell_label_pair(frame) is not None: frames.append(frame)
        self.assertEqual(max(map(len, frames)), 380)
        self.assertEqual(L.SHELL_FAILURE_LABEL_LIMIT, 512)
        self.assertLessEqual(max(map(len, frames)), L.SHELL_FAILURE_LABEL_LIMIT)
        longest = max(frames, key=len)
        self.assertIn(b";repo=na;guide=na\n", longest)
        for step in (b"PrepareSave", b"PathSettlement", b"Bootstrap"):
            old = (b"MRK_INSTALLED_SHELL_FAILURE_STEP=" + step + b"\n"
                   b"MRK_INSTALLED_SHELL_FAILURE_PHASE=settlement\nMRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n")
            self.assertEqual(L._shell_label_pair(old), {"step": step.decode("ascii"), "boundary": "settlement", "bootstrapProgress": "advanced"})
        session = (b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionReview\n"
                   b"MRK_INSTALLED_SHELL_FAILURE_PHASE=settlement\nMRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n"
                   b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v1;index=29;evaluations=73;reject=native-readiness-invariant;wait=native-reply-pending\n")
        self.assertNotIn("githubEntry", L._shell_label_pair(session))
        path = (b"MRK_INSTALLED_SHELL_PATH_FAILURE=v1;index=0;reject=gtk-initial-folder\n"
                b"MRK_INSTALLED_SHELL_FAILURE_STEP=PathActivate\nMRK_INSTALLED_SHELL_FAILURE_PHASE=gtk\n"
                b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n")
        self.assertNotIn("githubEntry", L._shell_label_pair(path))
        with patch.object(L, "SHELL_FAILURE_LABEL_LIMIT", len(longest) - 1):
            self.assertIsNone(L._shell_label_pair(longest))


class FailureLabelSinkContracts(unittest.TestCase):
    @staticmethod
    def metadata_open_frame(*, site=b"65535", origin=b"evaluation-budget", evaluations=b"128", index=b"1",
                            sample=b"127", wait=b"heading-not-review", heading=b"protocol-unverified", boundary=b"settlement"):
        return (b"MRK_INSTALLED_SHELL_METADATA_OPEN_FAILURE=v1;site=" + site + b";origin=" + origin
                + b";eval=" + evaluations + b";index=" + index + b";sample=" + sample + b";wait=" + wait + b";heading=" + heading
                + b"\nMRK_INSTALLED_SHELL_FAILURE_STEP=MetadataOpenText\nMRK_INSTALLED_SHELL_FAILURE_PHASE=" + boundary
                + b"\nMRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=app-info-returned-before-hold\n")

    def test_metadata_open_failure_records_first_winner_and_explicit_unavailable_samples(self):
        raw = self.metadata_open_frame()
        self.assertLessEqual(len(raw), 384)
        parsed = L._shell_label_pair(raw)
        self.assertEqual(parsed, {"step": "MetadataOpenText", "boundary": "settlement", "bootstrapProgress": "app-info-returned-before-hold",
                         "metadataOpenFailure": {"sourceLine": 65535, "origin": "evaluation-budget", "evaluations": 128,
                         "reviewIndex": 1, "lastSampleEvaluation": 127, "wait": "heading-not-review", "heading": "protocol-unverified"}})
        for index in (b"0", b"1"):
            for heading in (b"empty", b"protocol-unverified", b"opening", b"preparing", b"other"):
                sample = L._shell_label_pair(self.metadata_open_frame(index=index, sample=b"128", heading=heading))
                self.assertEqual(sample["metadataOpenFailure"]["heading"], heading.decode("ascii"))
                self.assertEqual(sample["metadataOpenFailure"]["lastSampleEvaluation"], 128)
        missing = L._shell_label_pair(self.metadata_open_frame(wait=b"review-missing", heading=b"na"))
        self.assertIsNone(missing["metadataOpenFailure"]["heading"])
        for site in (b"na", b"1"):
            unknown = L._shell_label_pair(self.metadata_open_frame(site=site, origin=b"not-recorded", evaluations=b"na",
                                         sample=b"na", wait=b"na", heading=b"na", boundary=b"dom"))["metadataOpenFailure"]
            self.assertIsNone(unknown["evaluations"])
            self.assertIsNone(unknown["lastSampleEvaluation"])
            self.assertIsNone(unknown["wait"])
            self.assertIsNone(unknown["heading"])
        for evaluations, sample in ((b"0", b"na"), (b"128", b"128")):
            deadline = L._shell_label_pair(self.metadata_open_frame(site=b"na", origin=b"deadline", evaluations=evaluations,
                                          sample=sample, wait=b"na" if sample == b"na" else b"review-missing", heading=b"na", boundary=b"deadline"))
            self.assertIsNone(deadline["metadataOpenFailure"]["sourceLine"])
            self.assertEqual(deadline["metadataOpenFailure"]["evaluations"], int(evaluations))
        legacy = raw.split(b"\n", 1)[1]
        self.assertEqual(L._shell_label_pair(legacy), {key: value for key, value in parsed.items() if key != "metadataOpenFailure"})
        snapshot = (b"MRK_INSTALLED_SHELL_SNAPSHOT_FAILURE=v1;site=1;check=stage;error=none\n"
                    + legacy.replace(b"PHASE=settlement", b"PHASE=result"))
        self.assertEqual(L._shell_label_pair(snapshot)["snapshotFailure"]["check"], "stage")

    def test_metadata_open_failure_rejects_truncation_unknowns_and_contradictory_stamps(self):
        raw = self.metadata_open_frame()
        for end in range(1, len(raw)):
            self.assertIsNone(L._shell_label_pair(raw[:end]))
        mutations = [dict(site=b"0"), dict(site=b"65536"), dict(site=b"01"), dict(site=b"na"), dict(index=b"2"), dict(index=b"01"),
                     dict(evaluations=b"127"), dict(evaluations=b"129"), dict(sample=b"129"), dict(sample=b"0"),
                     dict(wait=b"review-missing"), dict(heading=b"na"), dict(heading=b"private title"), dict(wait=b"other"),
                     dict(sample=b"na"), dict(boundary=b"dom"), dict(origin=b"deadline"), dict(origin=b"not-recorded"),
                     dict(origin=b"deadline", site=b"na", boundary=b"deadline", evaluations=b"126", sample=b"127"),
                     dict(origin=b"not-recorded", evaluations=b"na", sample=b"na", wait=b"na"),
                     dict(origin=b"deadline", site=b"na", boundary=b"deadline", evaluations=b"na")]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertIsNone(L._shell_label_pair(self.metadata_open_frame(**mutation)))
        for bad in (raw + b"\n", raw.replace(b";eval=", b";extra=0;eval="), raw.replace(b";index=1;sample=127", b";sample=127;index=1"),
                    raw.replace(b"MetadataOpenText", b"MetadataReadReview"), raw.replace(b"MetadataOpenText", b"SessionReview"),
                    raw.replace(b"\n", b"\r\n"), raw.split(b"\n", 1)[1] + raw.split(b"\n", 1)[0] + b"\n",
                    raw.decode("ascii"), bytearray(raw)):
            self.assertIsNone(L._shell_label_pair(bad))

    def test_metadata_open_diagnostic_wiring_retains_original_guards_and_first_winner(self):
        source = (SOURCE / "desktop/src-tauri/src/installed_shell_observation.rs").read_text()
        report = source.split("fn report_failure(&self)", 1)[1].split("fn report_failure_handoff", 1)[0]
        self.assertLess(report.index("snapshot_failure_frame("), report.index("metadata_open_failure_frame("))
        self.assertIn("session.is_none() && path.is_none() && evidence.is_none()", report)
        self.assertIn("self.failed.site(), r.metadata.open_failure, r.github_entry)", report)
        self.assertNotIn("r.metadata.open_sample", report)
        self.assertEqual(report.count("rustix::io::write"), 1)
        self.assertLess(report.index("Err(_) => return"), report.index("metadata_open_failure_frame("))
        dom = source.split("fn metadata_dom(&self", 1)[1].split("fn ", 1)[0]
        self.assertIn("MetadataOpenSample::parse(index, r.evaluations, value)", dom)
        self.assertIn("if !self.failed.load(Ordering::SeqCst) { r.metadata.open_sample = Some(sample); }", dom)
        self.assertNotIn("open_failure =", dom)
        tick = source.split("pub(super) fn tick(", 1)[1].split("fn dom(", 1)[0]
        deadline = tick.split("if Instant::now() >= self.end", 1)[1].split("self.failure_tick(app); return;", 1)[0]
        self.assertLess(deadline.index("if latch_failure("), deadline.index("r.metadata.open_failure = metadata_diagnostic"))
        budget = tick.split("if r.evaluations >= 128", 1)[1].split("r.evaluations += 1", 1)[0]
        self.assertLess(budget.index("if self.failed.mark_caller()"), budget.index("r.metadata.open_failure ="))
        self.assertIn("} else { self.fail(); }", budget)
        self.assertIn("Duration::from_secs(45)", source)
        native = tick.split("let native_pending = match r.step", 1)[1].split("Step::Workflow", 1)[0]
        self.assertIn("s.prepare_returned && s.live_review()", native)
        script = source.split("fn metadata_script(", 1)[1].split("fn ", 1)[0]
        open_text = script.split("MetadataStep::OpenText(_) =>", 1)[1].split("MetadataStep::ReadReview(_) =>", 1)[0]
        self.assertIn("reason:'review-missing',heading:'na'", open_text)
        self.assertIn("const p=panel(),heading=text(p.querySelector('.section-heading h2'))", open_text)
        self.assertIn("if (heading!=='Review text changes')", open_text)
        self.assertIn("rows.length!==3 || document.querySelector('dialog')", open_text)
        self.assertIn("if (!row.open) summary.click();", open_text)
        self.assertEqual(open_text.count(".section-heading h2"), 1)
        self.assertIn("if (!e || typeof e.textContent!=='string' || e.textContent.length>4096) throw 0", script)
        self.assertIn("assert_metadata_open_diagnostic_contract();", source.split("pub(crate) fn main()", 1)[1])

    def test_snapshot_first_origin_is_complete_closed_and_preserves_actual_wrong_stage(self):
        def frame(site=b"65535", check=b"root", error=b"none", step=b"ReadSnapshot", boundary=b"result"):
            return (b"MRK_INSTALLED_SHELL_SNAPSHOT_FAILURE=v1;site=" + site + b";check=" + check + b";error=" + error + b"\n"
                    + b"MRK_INSTALLED_SHELL_FAILURE_STEP=" + step + b"\nMRK_INSTALLED_SHELL_FAILURE_PHASE=" + boundary
                    + b"\nMRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n")
        raw = frame()
        self.assertLessEqual(len(raw), L.SHELL_FAILURE_LABEL_LIMIT)
        self.assertEqual(L._shell_label_pair(raw), {"step": "ReadSnapshot", "boundary": "result", "bootstrapProgress": "advanced",
                         "snapshotFailure": {"sourceLine": 65535, "check": "root", "error": "none"}})
        for check in L.SHELL_SNAPSHOT_CHECKS:
            step = b"SessionQuitPreserved" if check == b"stage" else b"ReadSnapshot"
            error = b"query-timeout" if check == b"bridge" else b"none"
            parsed = L._shell_label_pair(frame(check=check, error=error, step=step))
            self.assertEqual(parsed["snapshotFailure"]["check"], check.decode("ascii"))
            self.assertEqual(set(parsed), {"step", "boundary", "bootstrapProgress", "snapshotFailure"})
        for step in (b"SessionQuitPreserved", b"PathActivate", b"Close"):
            # No invented legacy Session/Path record, even for a wrong stage.
            self.assertEqual(L._shell_label_pair(frame(check=b"stage", step=step))["step"], step.decode("ascii"))
            self.assertIsNotNone(L._shell_label_pair(frame(step=step)))
        for error in L.SHELL_EVIDENCE_ERRORS:
            if error != b"none":
                self.assertEqual(L._shell_label_pair(frame(check=b"bridge", error=error))["snapshotFailure"]["error"], error.decode("ascii"))
        for step in (b"Selected", b"ReadSnapshot"):
            for boundary in (b"request", b"result", b"dom"):
                self.assertIsNotNone(L._shell_label_pair(frame(site=b"1", check=b"other-callback", step=step, boundary=boundary)))
        for value in (raw, frame(check=b"stage", step=b"SessionQuitPreserved"), frame(check=b"other-callback", boundary=b"dom")):
            for end in range(len(value)):
                self.assertIsNone(L._shell_label_pair(value[:end]))
                if 0 < end < len(value) - 1 and not value[:end].endswith(b"\n"):
                    self.assertIsNone(L._shell_label_pair(value[:end] + b"\n"))
        for bad in (frame(site=b"0"), frame(site=b"01"), frame(site=b"65536"), frame(site=b"-1"), frame(site=b"unknown"),
                    frame(check=b"unknown"), frame(error=b"private-message"), frame(check=b"bridge"),
                    frame(error=b"other"), frame(boundary=b"dom"), frame(check=b"stage"), frame(step=b"Unknown"),
                    frame(check=b"other-callback", step=b"Close"), frame(check=b"other-callback", error=b"other"),
                    raw.replace(b"v1;", b"v2;"), raw.replace(b";check=root", b";site=12;check=root"),
                    raw + b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v1;index=0\n", raw + raw,
                    raw.replace(b"MRK_INSTALLED_SHELL_FAILURE_STEP=", b"MRK_INSTALLED_SHELL_PATH_FAILURE=v2;index=0\nMRK_INSTALLED_SHELL_FAILURE_STEP=")):
            self.assertIsNone(L._shell_label_pair(bad))
        with patch.object(L, "SHELL_FAILURE_LABEL_LIMIT", len(raw) - 1):
            self.assertIsNone(L._shell_label_pair(raw))
        source = (SOURCE / "desktop/src-tauri/src/installed_shell_observation.rs").read_text()
        tokens = source.split("impl SnapshotCheck {", 1)[1].split("struct SnapshotRejection", 1)[0]
        import re
        self.assertEqual(tuple(re.findall(rb'=> b"([a-z-]+)"', tokens.encode())), L.SHELL_SNAPSHOT_CHECKS)

    def test_evidence_result_prefix_is_closed_complete_and_not_a_native_receipt(self):
        def frame(callback=b"status", check=b"problem", phase=b"refused", problem=b"deadline", error=b"none",
                  step=b"EvidenceObserved", boundary=b"result"):
            return (b"MRK_INSTALLED_SHELL_EVIDENCE_FAILURE=v1;callback=" + callback + b";check=" + check
                    + b";phase=" + phase + b";problem=" + problem + b";error=" + error + b"\n"
                    + b"MRK_INSTALLED_SHELL_FAILURE_STEP=" + step + b"\nMRK_INSTALLED_SHELL_FAILURE_PHASE=" + boundary
                    + b"\nMRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n")
        raw = frame()
        self.assertEqual(L._shell_label_pair(raw), {
            "step": "EvidenceObserved", "boundary": "result", "bootstrapProgress": "advanced",
            "evidence": {"callback": "status", "check": "problem", "phase": "refused", "problem": "deadline", "error": "none"}})
        self.assertLessEqual(len(raw), L.SHELL_FAILURE_LABEL_LIMIT)
        for end in range(len(raw)):
            self.assertIsNone(L._shell_label_pair(raw[:end]), end)
        legacy = raw.split(b"\n", 1)[1]
        self.assertEqual(L._shell_label_pair(legacy), {"step": "EvidenceObserved", "boundary": "result", "bootstrapProgress": "advanced"})
        for check in L.SHELL_EVIDENCE_CHECKS:
            if check == b"bridge":
                value = frame(check=check, phase=b"na", problem=b"na", error=b"other")
            elif check == b"status-pending":
                value = frame(check=check, phase=b"na", problem=b"na")
            else:
                value = frame(callback=b"observe-start", check=check)
            self.assertEqual(L._shell_label_pair(value)["evidence"]["check"], check.decode("ascii"))
        for error in L.SHELL_EVIDENCE_ERRORS[1:]:
            self.assertEqual(L._shell_label_pair(frame(check=b"bridge", phase=b"na", problem=b"na", error=error))["evidence"]["error"], error.decode("ascii"))
        for phase in L.SHELL_EVIDENCE_PHASES[1:]:
            self.assertEqual(L._shell_label_pair(frame(phase=phase))["evidence"]["phase"], phase.decode("ascii"))
        for problem in L.SHELL_EVIDENCE_PROBLEMS[1:]:
            self.assertEqual(L._shell_label_pair(frame(problem=problem))["evidence"]["problem"], problem.decode("ascii"))
        for bad in (
            frame(callback=b"other"), frame(check=b"raw-error"), frame(phase=b"raw-error"), frame(problem=b"raw-error"),
            frame(error=b"raw-error"), frame(check=b"bridge"), frame(check=b"bridge", phase=b"na", problem=b"na"),
            frame(error=b"other"), frame(phase=b"na"), frame(problem=b"na"),
            frame(callback=b"observe-start", step=b"ReadEvidenceObserved"), frame(callback=b"observe-start", check=b"status-pending", phase=b"na", problem=b"na"),
            frame(check=b"observe-pending"), frame(check=b"observe-returned"), frame(check=b"case"),
            frame(step=b"PathActivate"), frame(step=b"SessionReview"), frame(boundary=b"deadline"),
            raw + raw, raw + b"\n", raw.replace(b"v1;", b"v2;"), b"x" * 513,
            b"MRK_INSTALLED_SHELL_PATH_FAILURE=v1;index=0;reject=not-recorded\n" + raw,
            raw + b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v1;index=0;eval=0;reject=not-recorded;wait=not-sampled\n",
        ):
            self.assertIsNone(L._shell_label_pair(bad), bad)

    def test_lifecycle_stop_diagnostic_is_finite_stage_bound_and_never_a_success_receipt(self):
        def frame(step=b"EvidenceStopped", callback=b"cancel-start", check=b"operation-stage", phase=b"stopping", problem=b"cancelled", error=b"none"):
            return (b"MRK_INSTALLED_SHELL_EVIDENCE_FAILURE=v1;callback=" + callback + b";check=" + check
                    + b";phase=" + phase + b";problem=" + problem + b";error=" + error + b"\n"
                    + b"MRK_INSTALLED_SHELL_FAILURE_STEP=" + step + b"\nMRK_INSTALLED_SHELL_FAILURE_PHASE=result\n"
                    + b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n")
        for step in (b"RequestEvidenceStop", b"EvidenceStopped"):
            raw = frame(step)
            parsed = L._shell_label_pair(raw)
            self.assertEqual(parsed["step"], step.decode())
            self.assertEqual(parsed["evidence"], {"callback": "cancel-start", "check": "operation-stage",
                                                "phase": "stopping", "problem": "cancelled", "error": "none"})
            self.assertEqual(set(parsed), {"step", "boundary", "bootstrapProgress", "evidence"})
            self.assertLessEqual(len(raw), L.SHELL_FAILURE_LABEL_LIMIT)
            for end in range(len(raw)):
                self.assertIsNone(L._shell_label_pair(raw[:end]))
            self.assertIsNotNone(L._shell_label_pair(frame(step, check=b"bridge", phase=b"na", problem=b"na", error=b"other")))
            for check in (b"case", b"observe-pending", b"observe-returned", b"status-pending"):
                self.assertIsNone(L._shell_label_pair(frame(step, check=check)))
        for step in (b"InspectEvidence", b"EvidenceObserved", b"ReadEvidenceStale", b"ReadStaleRecovery", b"PathActivate", b"SessionReview", b"Close"):
            self.assertIsNone(L._shell_label_pair(frame(step)))
        for raw in (frame(callback=b"stop"), frame(check=b"actual-stage"), frame(phase=b"external-testing"), frame(error=b"private-message")):
            self.assertIsNone(L._shell_label_pair(raw))

    def test_path_v3_readiness_relations_are_closed_and_keep_original_callback_contract(self):
        def frame(*, step=b"PathActivate", index=b"7", wait=b"selection-different", picker=b"4o"):
            return (b"MRK_INSTALLED_SHELL_PATH_FAILURE=v3;index=" + index
                    + b";reject=not-recorded;start=18000;now=45000;rsv=m;in=m;out=m;cb=returned;wait="
                    + wait + b";h=" + picker + b"\nMRK_INSTALLED_SHELL_FAILURE_STEP=" + step
                    + b"\nMRK_INSTALLED_SHELL_FAILURE_PHASE=deadline\nMRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n")
        good = frame()
        self.assertEqual(L._shell_label_pair(good)["path"]["gtkPicker"],
                         {"mapped": True, "folder": "target-parent", "selected": "other"})
        for end in range(len(good)):
            self.assertIsNone(L._shell_label_pair(good[:end]))
        for state, (mapped, folder) in L.SHELL_SESSION_PICKER_FOLDERS.items():
            for selected in (b"a", b"t", b"p", b"o"):
                wait = b"selection-absent" if selected == b"a" else b"not-sampled" if selected == b"t" else b"selection-different"
                parsed = L._shell_label_pair(frame(wait=wait, picker=state + selected))
                self.assertEqual(parsed["path"]["gtkPicker"],
                                 {"mapped": mapped, "folder": folder, "selected": L.SHELL_SESSION_PICKER_SELECTIONS[selected]})
                set_wait = (b"unmapped" if not mapped else b"target-parent-absent" if folder == "absent"
                            else b"target-parent-different" if folder == "other" else b"not-sampled")
                self.assertIsNotNone(L._shell_label_pair(frame(step=b"PathSet", wait=set_wait, picker=state + selected)))
        for index in (b"1", b"6", b"7", b"8"):
            self.assertIsNotNone(L._shell_label_pair(frame(step=b"PathSet", index=index, wait=b"not-sampled", picker=b"4a")))
        for index in (b"0", b"2", b"3", b"4", b"5", b"9", b"10"):
            self.assertIsNone(L._shell_label_pair(frame(step=b"PathSet", index=index, wait=b"not-sampled", picker=b"4a")))
        for index in (b"0", b"4"):
            self.assertIsNone(L._shell_label_pair(frame(index=index)))
            self.assertIsNotNone(L._shell_label_pair(frame(index=index, wait=b"response-insensitive", picker=b"na")))
        for wait in (b"not-sampled", b"dialog-absent", b"initial-folder-absent"):
            self.assertIsNone(L._shell_label_pair(frame(wait=wait)))
            self.assertIsNotNone(L._shell_label_pair(frame(wait=wait, picker=b"na")))
        bad = [
            frame(wait=b"selection-different", picker=b"na"),
            frame(step=b"PathSet", wait=b"unmapped", picker=b"na"),
            frame(step=b"PathSet", wait=b"target-parent-different", picker=b"4o"),
            frame(step=b"PathSet", wait=b"target-parent-absent", picker=b"0a"),
            frame(step=b"PathSet", wait=b"not-sampled", picker=b"5o"),
            frame(step=b"PathSet", wait=b"unmapped", picker=b"4o"),
            frame(wait=b"unmapped", picker=b"0a"),
            frame(step=b"PathBrowse", wait=b"not-sampled", picker=b"4t"),
            frame(wait=b"response-insensitive", picker=b"na"),
            frame(wait=b"selection-absent", picker=b"4t"),
            frame(wait=b"response-insensitive", picker=b"4o"),
            frame(wait=b"selection-different", picker=b"4a"),
            frame(wait=b"not-sampled", picker=b"4p"),
            frame(wait=b"selection-different", picker=b"4t"),
        ]
        ready = frame(wait=b"not-sampled", picker=b"4t")
        bad += [ready.replace(b"rsv=m;in=m;out=m;cb=returned", callbacks) for callbacks in (
            b"rsv=0;in=0;out=0;cb=idle", b"rsv=1;in=0;out=0;cb=reserved")]
        bad += [good.replace(before, after) for before, after in (
            (b";h=4o", b";h=4o;h=4o"), (b";h=4o", b""), (b"=v3;", b"=v2;"),
            (b"=v3;", b"=v1;"), (b"=v3;", b"=v4;"))]
        for raw in bad:
            self.assertIsNone(L._shell_label_pair(raw))
        for picker in (b"4f", b"0f", b"6t", b"4x", b"n", b"nat", b"/private/path", b"4o;h=4o"):
            self.assertIsNone(L._shell_label_pair(frame(picker=picker)))
        for raw in (good + b"\n", good + good, good.replace(b"\n", b"\r\n"), good.replace(b"now=45000", b"now=1")):
            self.assertIsNone(L._shell_label_pair(raw))
        largest = frame(step=b"PathSet", wait=b"target-parent-different", picker=b"5o").replace(
            b"start=18000;now=45000", b"start=999999;now=999999").replace(b"reject=not-recorded", b"reject=gtk-fixture-transition")
        self.assertIsNotNone(L._shell_label_pair(largest))
        self.assertLessEqual(len(largest), L.SHELL_PATH_FAILURE_V3_FRAME_BOUND)
        with patch.object(L, "SHELL_PATH_FAILURE_V3_FRAME_BOUND", len(good) - 1):
            self.assertIsNone(L._shell_label_pair(good))

    def test_path_v2_timing_callback_wait_preserves_closed_prefix_contract(self):
        good = (b"MRK_INSTALLED_SHELL_PATH_FAILURE=v2;index=8;reject=not-recorded;start=43000;now=45000;"
                b"rsv=m;in=m;out=m;cb=returned;wait=selection-different\n"
                b"MRK_INSTALLED_SHELL_FAILURE_STEP=PathActivate\nMRK_INSTALLED_SHELL_FAILURE_PHASE=deadline\n"
                b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n")
        sample = L._shell_label_pair(good)["path"]
        self.assertEqual(sample, {"recipeIndex": 8, "rejection": "not-recorded", "stepEntryElapsedMs": 43000,
                                 "sampleElapsedMs": 45000, "callbackReservations": "m", "callbackEntries": "m",
                                 "callbackReturns": "m", "callbackPhase": "returned", "lastWait": "selection-different"})
        for end in range(len(good)):
            self.assertIsNone(L._shell_label_pair(good[:end]))
        for before, after in ((b"start=43000;now=45000", b"start=over;now=over"),
                              (b"now=45000", b"now=over"), (b"cb=returned", b"cb=entered"),
                              (b"cb=returned", b"cb=reserved")):
            self.assertIsNotNone(L._shell_label_pair(good.replace(before, after)))
        idle = good.replace(b"rsv=m;in=m;out=m;cb=returned;wait=selection-different", b"rsv=0;in=0;out=0;cb=idle;wait=not-sampled")
        self.assertIsNotNone(L._shell_label_pair(idle))
        reserved = idle.replace(b"rsv=0;in=0;out=0;cb=idle", b"rsv=1;in=0;out=0;cb=reserved")
        self.assertIsNotNone(L._shell_label_pair(reserved))
        self.assertIsNotNone(L._shell_label_pair(reserved.replace(b"in=0;out=0;cb=reserved", b"in=1;out=0;cb=entered")))
        navigation = idle.replace(b"index=8", b"index=none").replace(b"PathActivate", b"PathNavigation").replace(b"cb=idle", b"cb=na")
        self.assertIsNotNone(L._shell_label_pair(navigation))
        bad = [good.replace(before, after) for before, after in (
            (b"start=43000", b"start=45001"), (b"start=43000", b"start=over"),
            (b"now=45000", b"now=1000000"), (b"now=45000", b"now=045000"), (b"now=45000", b"now=-1"),
            (b"rsv=m", b"rsv=1"), (b"in=m", b"in=0"), (b"out=m", b"out=1"),
            (b"cb=returned", b"cb=idle"), (b"cb=returned", b"cb=na"), (b"cb=returned", b"cb=queued"),
            (b"PathActivate", b"PathSet"), (b"wait=selection-different", b"wait=arbitrary"),
            (b";now=", b";start=1;now="), (b"=v2;", b"=v3;"), (b"\n", b"\r\n"))]
        bad += [good + b"x", good + b"\n", idle.replace(b"out=0", b"out=1"),
                reserved.replace(b"rsv=1", b"rsv=m"), navigation.replace(b"cb=na", b"cb=idle")]
        for raw in bad:
            self.assertIsNone(L._shell_label_pair(raw))
        with patch.object(L, "SHELL_PATH_FAILURE_V2_FRAME_BOUND", len(good) - 1):
            self.assertIsNone(L._shell_label_pair(good))

    def test_path_prefix_requires_complete_frame_closed_reason_and_recipe_shape(self):
        def frame(step=b"PathActivate", index=b"0", rejection=b"gtk-initial-folder"):
            return (b"MRK_INSTALLED_SHELL_PATH_FAILURE=v1;index=" + index + b";reject=" + rejection + b"\n"
                    b"MRK_INSTALLED_SHELL_FAILURE_STEP=" + step + b"\nMRK_INSTALLED_SHELL_FAILURE_PHASE=gtk\n"
                    b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n")
        good = frame()
        self.assertEqual(L._shell_label_pair(good), {"step": "PathActivate", "boundary": "gtk", "bootstrapProgress": "advanced",
            "path": {"recipeIndex": 0, "rejection": "gtk-initial-folder"}})
        indexed = (b"PathBrowse", b"PathSet", b"PathActivate", b"PathSettlement", b"PathField")
        unindexed = (b"PathDraft", b"PathPreview", b"PathNavigation")
        for step in indexed:
            for index in range(11):
                self.assertEqual(L._shell_label_pair(frame(step, str(index).encode("ascii")))["path"]["recipeIndex"], index)
            self.assertIsNone(L._shell_label_pair(frame(step, b"none")))
        for step in unindexed:
            self.assertEqual(L._shell_label_pair(frame(step, b"none"))["path"], {"recipeIndex": None, "rejection": "gtk-initial-folder"})
            # Preview round0..2 never masquerades as a recipe identifier.
            for index in (b"0", b"1", b"2"):
                self.assertIsNone(L._shell_label_pair(frame(step, index)))
        for rejection in L.SHELL_PATH_REJECTIONS:
            self.assertEqual(L._shell_label_pair(frame(rejection=rejection))["path"]["rejection"], rejection.decode("ascii"))
        longest = frame(b"PathNavigation", b"none", b"gtk-fixture-transition").replace(
            b"=gtk\n", b"=settlement\n").replace(b"=advanced\n", b"=app-info-returned-before-hold\n")
        self.assertIsNotNone(L._shell_label_pair(longest))
        self.assertLessEqual(len(longest), L.SHELL_PATH_FAILURE_FRAME_BOUND)
        self.assertEqual(L.SHELL_FAILURE_LABEL_LIMIT, 512)
        # Including cuts exactly at line boundaries: the leading version record
        # prevents a short new write from impersonating an old three-line frame.
        for end in range(len(good)):
            with self.subTest(prefix_bytes=end):
                self.assertIsNone(L._shell_label_pair(good[:end]))
        prefix, legacy = good.split(b"\n", 1)
        prefix += b"\n"
        for step in indexed + unindexed:
            old = legacy.replace(b"PathActivate", step)
            self.assertEqual(L._shell_label_pair(old), {"step": step.decode("ascii"), "boundary": "gtk", "bootstrapProgress": "advanced"})
        bad = [good.replace(b"=v1;", b"=v2;"), good.replace(b"=v1;", b"=V1;"),
               frame(index=b"11"), frame(index=b"255"), frame(index=b"00"), frame(index=b"01"),
               frame(index=b"-1"), frame(index=b"+1"), frame(index=b"NONE"), frame(index=b"0 "),
               frame(step=b"SessionActivateFile"), frame(step=b"PrepareSave"), frame(step=b"PathUnknown"),
               frame(rejection=b"gtk-future"), frame(rejection=b"gtk_initial_folder"), frame(rejection=b"GTK-thread"),
               frame(rejection=b"x" * 23), frame(rejection=b"gtk-thread;extra=1"), frame(rejection=b"gtk-thread\n/private/inert"),
               good.replace(b";reject=", b";index=0;reject="), good.replace(b";reject=", b";extra=1;reject="),
               good.replace(b"index=0;reject=gtk-initial-folder", b"reject=gtk-initial-folder;index=0"),
               good.replace(b"\n", b"\r\n"), prefix + legacy + legacy, prefix + prefix + legacy, legacy + prefix,
               good + b"\n", good + b"x" * 512, good.decode("ascii"), bytearray(good),
               prefix + legacy.replace(b"PathActivate", b"SessionReview") +
               b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v1;index=0;evaluations=1;reject=not-recorded;wait=not-sampled\n"]
        for raw in bad:
            with self.subTest(kind=type(raw).__name__, length=len(raw)):
                self.assertIsNone(L._shell_label_pair(raw))

    def test_session_record_requires_exact_index_bounds_categories_and_complete_frame(self):
        header = (b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionReview\n"
                  b"MRK_INSTALLED_SHELL_FAILURE_PHASE=settlement\n"
                  b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n")
        detail = (b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v1;index=63;evaluations=128;"
                  b"reject=evaluation-budget;wait=rendered-display-mismatch\n")
        good = header + detail
        self.assertEqual(L._shell_label_pair(good), {"step": "SessionReview", "boundary": "settlement", "bootstrapProgress": "advanced",
            "session": {"recipeIndex": 63, "evaluations": 128, "rejection": "evaluation-budget", "lastWait": "rendered-display-mismatch"}})
        gtk = (b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionActivateFile\n"
               b"MRK_INSTALLED_SHELL_FAILURE_PHASE=gtk\nMRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n"
               b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v1;index=3;evaluations=16;"
               b"reject=gtk-observer-endpoint;wait=gtk-action-insensitive\n")
        self.assertEqual(L._shell_label_pair(gtk), {"step": "SessionActivateFile", "boundary": "gtk", "bootstrapProgress": "advanced",
            "session": {"recipeIndex": 3, "evaluations": 16, "rejection": "gtk-observer-endpoint", "lastWait": "gtk-action-insensitive"}})
        self.assertEqual(L._shell_label_pair(gtk.replace(b"gtk-action-insensitive", b"gtk-selection-pending"))["session"],
            {"recipeIndex": 3, "evaluations": 16, "rejection": "gtk-observer-endpoint", "lastWait": "gtk-selection-pending"})
        historical = header + (b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v1;index=29;evaluations=73;"
                               b"reject=native-readiness-invariant;wait=native-reply-pending\n")
        self.assertEqual(L._shell_label_pair(historical)["session"], {"recipeIndex": 29, "evaluations": 73,
            "rejection": "native-readiness-invariant", "lastWait": "native-reply-pending"})
        unavailable = [L._shell_label_pair(good.replace(b"evaluation-budget", token))["session"]["rejection"]
                       for token in (b"reply-code-unavailable", b"reply-assessment-unavailable", b"capability-unavailable")]
        self.assertEqual(unavailable, ["reply-code-unavailable", "reply-assessment-unavailable", "capability-unavailable"])
        for rejection in L.SHELL_SESSION_REJECTIONS:
            for wait in L.SHELL_SESSION_WAITS:
                raw = header + b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v1;index=0;evaluations=128;reject=" + rejection + b";wait=" + wait + b"\n"
                value = L._shell_label_pair(raw)
                self.assertEqual(value["session"], {"recipeIndex": 0, "evaluations": 128,
                    "rejection": rejection.decode("ascii"), "lastWait": wait.decode("ascii")})
                self.assertLessEqual(len(raw), 512)
        for number in (b"0", b"9", b"10", b"99", b"100", b"128"):
            raw = good.replace(b"evaluations=128", b"evaluations=" + number).replace(b"evaluation-budget", b"not-recorded")
            self.assertEqual(L._shell_label_pair(raw)["session"]["evaluations"], int(number))
        for name in (b"SessionNavigate", b"SessionReload", b"SessionLoss", b"SessionDeadline", b"SessionQuitPreserved"):
            raw = good.replace(b"SessionReview", name).replace(b"index=63", b"index=none")
            self.assertIsNone(L._shell_label_pair(good.replace(b"SessionReview", name)))
            self.assertIsNone(L._shell_label_pair(raw)["session"]["recipeIndex"])
        for name in (b"SessionQuitCancel", b"SessionFinality"):
            self.assertIsNotNone(L._shell_label_pair(good.replace(b"SessionReview", name)))
            self.assertIsNotNone(L._shell_label_pair(good.replace(b"SessionReview", name).replace(b"index=63", b"index=none")))
        bad = [header, header + detail[:-1], header + detail + detail, detail + header,
            good.replace(b"SessionReview", b"PrepareSave"), good.replace(b"index=63", b"index=none"),
            good.replace(b"index=63", b"index=64"), good.replace(b"index=63", b"index=063"),
            good.replace(b"index=63", b"index=-1"), good.replace(b"evaluations=128", b"evaluations=129"),
            good.replace(b"evaluations=128", b"evaluations=0128"), good.replace(b"evaluations=128", b"evaluations=127"),
            good.replace(b"evaluation-budget", b"not-an-allowed-condition"), good.replace(b"rendered-display-mismatch", b"unknown"),
            good.replace(b"evaluation-budget", b"asset_deadline"), good.replace(b"evaluation-budget", b"reply-future-code"),
            good.replace(b"evaluation-budget", b"x" * 33),
            good.replace(b"evaluation-budget", b"reply-code-unavailable;code=asset_deadline"),
            good.replace(b"evaluation-budget", b"reply-code-unavailable\n/private/inert"),
            good.replace(b"v1;", b"v2;"), good.replace(b";wait=", b";extra=1;wait="),
            good.replace(b";reject=", b";index=63;reject="), good.replace(b"\n", b"\r\n"),
            good + b"/private/inert\n", good + b"x" * 512]
        for raw in bad:
            with self.subTest(raw=raw[:80]): self.assertIsNone(L._shell_label_pair(raw))

        # v1 stays distinguishable as lacking origin metadata. v2 never accepts
        # an omitted field, guessed association or arbitrary original error.
        self.assertNotIn("firstOrigin", L._shell_label_pair(historical)["session"])
        def frame(origin=b"not-recorded", origin_detail=b"none", association=b"unassociated", query=b"na", worker=b"na"):
            return (good[:-1].replace(b"=v1;", b"=v2;") + b";o=" + origin + b";d=" + origin_detail
                    + b";a=" + association + b";q=" + query + b";w=" + worker + b"\n")
        v2 = frame()
        expected = deepcopy(L._shell_label_pair(good))
        expected["session"]["firstOrigin"] = {"origin": "not-recorded", "detail": "none", "association": "unassociated", "query": "na", "worker": "na"}
        self.assertEqual(L._shell_label_pair(v2), expected)
        bound = frame(b"supervisor-disabled", b"none", b"bound", b"unavailable.spawn-other.xf", b"settle-unknown")
        expected["session"]["firstOrigin"] = {"origin": "supervisor-disabled", "detail": "none", "association": "bound",
                                               "query": "unavailable.spawn-other.xf", "worker": "settle-unknown"}
        self.assertEqual(L._shell_label_pair(bound), expected)
        self.assertLessEqual(len(bound), 412)
        self.assertEqual(bound.count(b"\n"), 4)
        self.assertTrue(bound.isascii())
        for origin in L.SHELL_SESSION_ORIGINS:
            origin_detail = b"other" if origin == b"op-cleanup" else b"failed" if origin == b"coord-join" else b"unavailable" if origin == b"staged-refusal" else b"none"
            self.assertEqual(L._shell_label_pair(frame(origin, origin_detail))["session"]["firstOrigin"]["origin"], origin.decode("ascii"))
        for origin, details in ((b"op-cleanup", (b"deadline", b"review-expired", b"context-stale", b"cleanup-unknown", b"user-cancelled", b"shutdown", b"document-lost", b"other")),
                                (b"staged-refusal", (b"new", b"pending", b"returned", b"failed", b"unavailable"))):
            for origin_detail in details:
                self.assertEqual(L._shell_label_pair(frame(origin, origin_detail, b"bound", b"unregistered"))["session"]["firstOrigin"]["detail"], origin_detail.decode("ascii"))
        for error in L.SHELL_SESSION_QUERY_ERRORS:
            value = error + b".none.pr"
            self.assertEqual(L._shell_label_pair(frame(b"registry", b"none", b"bound", value, b"none-recorded"))["session"]["firstOrigin"]["query"], value.decode("ascii"))
        for cause in L.SHELL_SESSION_QUERY_CAUSES:
            value = b"cleanup." + cause + b".cf"
            self.assertEqual(L._shell_label_pair(frame(b"coord-join", b"failed", b"bound", value, b"acquire-f"))["session"]["firstOrigin"]["query"], value.decode("ascii"))
        for join in L.SHELL_SESSION_MANAGEMENT_JOINS:
            value = b"timeout.none." + bytes([join, join])
            self.assertIsNotNone(L._shell_label_pair(frame(b"registry", b"none", b"bound", value, b"unavailable")))
        for worker in L.SHELL_SESSION_WORKERS:
            value = b"unregistered" if worker == b"na" else b"unavailable"
            self.assertEqual(L._shell_label_pair(frame(b"registry", b"none", b"bound", value, worker))["session"]["firstOrigin"]["worker"], worker.decode("ascii"))
        self.assertEqual((len(L.SHELL_SESSION_PUBLIC_MAP_WORKERS), L.SHELL_SESSION_PUBLIC_MAP_WORKERS[0], L.SHELL_SESSION_PUBLIC_MAP_WORKERS[-1]),
                         (648, b"map-x-aa", b"map-x-yx"))
        self.assertEqual(L.SHELL_SESSION_GENERIC_MAP_WORKERS, tuple(b"map-x-" + group + b"-" + tail
                         for group in (b"v", b"l", b"c", b"h", b"m", b"o") for tail in (b"na", b"np", b"da", b"dp")))
        self.assertEqual(len(set(L.SHELL_SESSION_GENERIC_MAP_WORKERS)), 24)
        for worker in (b"maps-check", b"map-p-nl", b"map-p-order", b"map-x-file", b"map-m-owner-cr", b"map-dup-py",
                       b"map-x-hist-py", b"map-x-hist-ss", b"map-x-hist-cr",
                       *L.SHELL_SESSION_GENERIC_MAP_WORKERS, *L.SHELL_SESSION_PUBLIC_MAP_WORKERS):
            raw = frame(b"supervisor-disabled", b"none", b"bound", b"cleanup.none.pp", worker)
            self.assertEqual(L._shell_label_pair(raw)["session"]["firstOrigin"], {
                "origin": "supervisor-disabled", "detail": "none", "association": "bound", "query": "cleanup.none.pp", "worker": worker.decode("ascii")})
            self.assertLessEqual(len(raw), 412)
            self.assertIsNone(L._shell_label_pair(raw.replace(b";a=bound", b";a=unassociated")))
            self.assertIsNone(L._shell_label_pair(raw.replace(b";q=cleanup.none.pp", b";q=unregistered")))
        for stage in L.SHELL_SESSION_WORKER_STAGES:
            self.assertIsNotNone(L._shell_label_pair(frame(b"registry", b"none", b"bound", b"cleanup.none.pp", stage + b"-c")))
        for suffix in L.SHELL_SESSION_WORKER_JOINS:
            self.assertIsNotNone(L._shell_label_pair(frame(b"registry", b"none", b"bound", b"cleanup.none.pp", b"observe-" + bytes([suffix]))))
        bad_v2 = [v2[:-1], v2 + b"\n", v2 + detail, bound.replace(b"=v2;", b"=v1;"), bound.replace(b"=v2;", b"=v3;"),
            bound.replace(b";o=supervisor-disabled", b""), bound.replace(b";d=none", b""), bound.replace(b";a=bound", b""),
            bound.replace(b";q=unavailable.spawn-other.xf", b""), bound.replace(b";w=settle-unknown", b""),
            bound.replace(b";d=none", b";d=none;d=none"), bound.replace(b";a=bound", b";a=bound;a=unassociated"),
            bound.replace(b";o=supervisor-disabled;d=none", b";d=none;o=supervisor-disabled"),
            bound.replace(b";w=settle-unknown", b";w=settle-unknown;extra=1"), bound.replace(b"\n", b"\r\n"),
            bound.replace(b"supervisor-disabled", b"supervisor-future"), bound.replace(b";d=none", b";d=failed"),
            bound.replace(b";a=bound", b";a=unknown"), bound.replace(b";a=bound", b";a=unassociated"),
            frame(b"not-recorded", b"none", b"bound", b"unavailable", b"unavailable"),
            frame(b"op-cleanup", b"none"), frame(b"coord-join", b"none"), frame(b"staged-refusal", b"deadline"),
            frame(b"registry", b"none", b"bound"), frame(b"registry", b"none", b"unassociated", b"unregistered"),
            frame(b"registry", b"none", b"bound", b"unregistered", b"none-recorded"),
            *(frame(b"registry", b"none", b"bound", query, b"unavailable") for query in (
                b"none.spawn-other.pp", b"future.none.pp", b"cleanup.future.pp", b"cleanup.none.p", b"cleanup.none.ppp",
                b"cleanup.none.pz", b"cleanup.none.pr.extra", b"cleanup..pr", b"cleanup_none_pr", b"cleanup.none.PR")),
            *(frame(b"registry", b"none", b"bound", b"cleanup.none.pp", worker) for worker in (
                b"inspect-r", b"inspect-c-extra", b"future-c", b"maps-future", b"settle-unknownx", b"\xff",
                b"map-p-future", b"map-m-time-py", b"map-m-owner-zz", b"map-m-owner-pyx", b"map-x-file\n/private/inert",
                b"map-x-yy", b"map-x-zz", b"map-x-a", b"map-x-aaa", b"map-x-AA", b"map-x-aa ",
                 b"map-x-aa;extra=1", b"map-x-aa/path", b"map-x-aa\n/private/inert",
                 b"map-x-hist-zz", b"map-x-hist-pyx", b"map-x-hist-ss ", b"map-x-hist-cr;extra=1",
                 b"map-x-hist-py\n/private/inert", b"map-x-v-n", b"map-x-v-nax", b"map-x-z-na", b"map-x-l-aa",
                 b"map-x-c-NP", b"map-x-h-na ", b"map-x-m-da;extra=1", b"map-x-o-dp/path", b"map-x-o-na\n/private/inert"))]
        for raw in bad_v2:
            with self.subTest(version="v2", raw=raw[:80]): self.assertIsNone(L._shell_label_pair(raw))

    def test_finite_pair_refuses_partial_reordered_duplicate_or_injected_data(self):
        step = b"MRK_INSTALLED_SHELL_FAILURE_STEP=PrepareSave\n"
        boundary = b"MRK_INSTALLED_SHELL_FAILURE_PHASE=request\n"
        progress = b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n"
        good = step + boundary + progress
        self.assertEqual(L._shell_label_pair(good), {"step": "PrepareSave", "boundary": "request", "bootstrapProgress": "advanced"})
        self.assertEqual(L._shell_label_pair(b"MRK_INSTALLED_SHELL_FAILURE_STEP=PathSettlement\n"
                                           b"MRK_INSTALLED_SHELL_FAILURE_PHASE=settlement\n" + progress),
                         {"step": "PathSettlement", "boundary": "settlement", "bootstrapProgress": "advanced"})
        for line in L.SHELL_BOOTSTRAP_PROGRESS:
            parsed = L._shell_label_pair(step + boundary + line)
            self.assertEqual(parsed["bootstrapProgress"], line.split(b"=", 1)[1][:-1].decode("ascii"))
        for raw in (b"", good[:-1], step, step + boundary, boundary + step + progress, step + step + progress,
                    step + progress + boundary, good + progress, good + boundary,
                    b"prefix" + good, good.replace(b"PrepareSave", b"NotAnAllowedStep"),
                    good.replace(b"request", b"unknown"), good.replace(b"\n", b"\r\n"),
                    good.replace(b"advanced", b"unknown"), good.replace(b"advanced", b"\xff"),
                    good + b"/private/injected\n", good + b"x" * 512, good.decode(), bytearray(good)):
            with self.subTest(kind=type(raw).__name__, length=len(raw)):
                self.assertIsNone(L._shell_label_pair(raw))

    def test_session_v6_selection_and_callback_facts_are_closed_versioned_and_bounded(self):
        def frame(step=b"SessionActivateFile", index=b"3", wait=b"gtk-selection-absent", callbacks=b"mp"):
            return (b"MRK_INSTALLED_SHELL_FAILURE_STEP=" + step + b"\n"
                    b"MRK_INSTALLED_SHELL_FAILURE_PHASE=deadline\n"
                    b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n"
                    b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v6;index=" + index + b";eval=16;"
                    b"reject=not-recorded;wait=" + wait
                    + b";o=not-recorded;d=none;a=unassociated;q=na;w=na;ao=none;ac=na;ax=none;af=na;u=na;g=" + callbacks + b"\n")
        expected_tokens = (b"na", b"0i", b"0p", b"0w", b"1i", b"1p", b"1w", b"mi", b"mp", b"mw")
        self.assertEqual(L.SHELL_SESSION_GTK_CALLBACKS, expected_tokens)
        for returns, label in ((b"0", "none"), (b"1", "one"), (b"m", "multiple")):
            for phase, observed in ((b"i", "idle"), (b"p", "pending"), (b"w", "wait-observed")):
                callbacks = returns + phase
                wait = b"not-sampled" if callbacks in (b"0i", b"0p") else b"gtk-selection-absent"
                value = L._shell_label_pair(frame(wait=wait, callbacks=callbacks))
                self.assertEqual(value["session"]["gtkCallbacks"], {"returns": label, "phase": observed})
                self.assertEqual(value["session"]["evaluations"], 16)  # Remains DOM-only.
                self.assertEqual(value["session"]["lastWait"], wait.decode("ascii"))
        for wait in (b"gtk-selection-absent", b"gtk-selection-different"):
            raw = frame(wait=wait)
            self.assertEqual(L._shell_label_pair(raw)["session"]["lastWait"], wait.decode("ascii"))
            self.assertLessEqual(len(raw), L.SHELL_SESSION_FAILURE_V6_FRAME_BOUND)
            for end in range(len(raw)):
                self.assertIsNone(L._shell_label_pair(raw[:end]))
                if end < len(raw) - 1:
                    self.assertIsNone(L._shell_label_pair(raw[:end] + b"\n"))
            self.assertIsNone(L._shell_label_pair(frame(step=b"SessionSetFile", wait=wait)))
        self.assertIsNotNone(L._shell_label_pair(frame(step=b"SessionSetFile", wait=b"gtk-dialog-absent")))
        self.assertIsNone(L._shell_label_pair(frame(callbacks=b"na")))
        review = frame(step=b"SessionReview", wait=b"native-reply-pending", callbacks=b"na")
        self.assertIsNone(L._shell_label_pair(review)["session"]["gtkCallbacks"])
        self.assertIsNone(L._shell_label_pair(frame(step=b"SessionReview", wait=b"native-reply-pending")))
        raw = frame()
        self.assertEqual(L.SHELL_SESSION_FAILURE_V6_FRAME_BOUND, 509 - 7 + 5)
        self.assertEqual(L.SHELL_FAILURE_LABEL_LIMIT, 512)
        with patch.object(L, "SHELL_SESSION_FAILURE_V6_FRAME_BOUND", len(raw) - 1):
            self.assertIsNone(L._shell_label_pair(raw))
        bad = [frame(index=b"none"), frame(index=b"64"), frame(index=b"03"), frame(wait=b"gtk-selection-pending"),
               frame(callbacks=b"2p"), frame(callbacks=b"mP"), frame(callbacks=b"mm"), frame(callbacks=b"mw0"),
               raw.replace(b";eval=16;", b";evaluations=16;"), raw.replace(b";eval=16;", b";eval=129;"),
               raw.replace(b";eval=16;", b";eval=016;"), raw.replace(b";g=mp", b""),
               raw.replace(b";g=mp", b";g=mp;g=mp"), raw.replace(b";g=mp", b";g=mp;extra=na"),
               raw.replace(b";u=na;g=mp", b";g=mp;u=na"), raw.replace(b";g=mp", b";callbacks=mp"),
               raw.replace(b"\n", b"\r\n"), raw + b"\n", raw + raw, raw + b"x" * 512]
        for version in (b"v1", b"v2", b"v3", b"v4", b"v5", b"v7"):
            bad.append(raw.replace(b"=v6;", b"=" + version + b";"))
        for value in bad:
            self.assertIsNone(L._shell_label_pair(value))
        # Exact v5 still has no gtkCallbacks field; v6-only tokens cannot leak backward.
        historical = review.replace(b"=v6;", b"=v5;").replace(b";eval=", b";evaluations=").replace(b";g=na", b"")
        self.assertNotIn("gtkCallbacks", L._shell_label_pair(historical)["session"])
        for wait in (b"gtk-selection-absent", b"gtk-selection-different"):
            self.assertIsNone(L._shell_label_pair(historical.replace(b"native-reply-pending", wait)))

    def test_session_v7_picker_relations_are_closed_and_do_not_certify_readiness(self):
        def frame(picker=b"4f", step=b"SessionActivateFile", index=b"9",
                  wait=b"gtk-selection-different", callbacks=b"mw"):
            return (b"MRK_INSTALLED_SHELL_FAILURE_STEP=" + step + b"\n"
                    b"MRK_INSTALLED_SHELL_FAILURE_PHASE=deadline\n"
                    b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n"
                    b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v7;index=" + index + b";eval=30;"
                    b"reject=not-recorded;wait=" + wait
                    + b";o=not-recorded;d=none;a=unassociated;q=na;w=na;ao=none;ac=na;ax=none;af=na;u=na;g="
                    + callbacks + b";h=" + picker + b"\n")
        folders = {b"0": (False, "absent"), b"1": (False, "target-parent"), b"2": (False, "other"),
                   b"3": (True, "absent"), b"4": (True, "target-parent"), b"5": (True, "other")}
        selections = {b"a": "absent", b"t": "target", b"p": "target-parent", b"f": "firebase-peer", b"o": "other"}
        self.assertEqual(L.SHELL_SESSION_PICKER_FOLDERS, folders)
        self.assertEqual(L.SHELL_SESSION_PICKER_SELECTIONS, selections)
        tokens = set()
        for folder_token, (mapped, folder) in folders.items():
            for selected_token, selected in selections.items():
                token = folder_token + selected_token
                tokens.add(token)
                allowed = ((b"not-sampled", b"gtk-action-insensitive") if selected == "target"
                           else (b"gtk-selection-absent",) if selected == "absent"
                           else (b"gtk-selection-different",))
                for wait in (b"not-sampled", b"gtk-dialog-absent", b"gtk-selection-absent",
                             b"gtk-selection-different", b"gtk-action-insensitive"):
                    with self.subTest(token=token, wait=wait):
                        value = L._shell_label_pair(frame(picker=token, wait=wait))
                        if wait not in allowed:
                            self.assertIsNone(value)
                        else:
                            self.assertEqual(value["session"]["gtkPicker"],
                                             {"mapped": mapped, "folder": folder, "selected": selected})
                            self.assertEqual(value["session"]["recipeIndex"], 9)
                            self.assertEqual(value["session"]["evaluations"], 30)  # Still DOM evaluations.
                            self.assertEqual(value["session"]["gtkCallbacks"], {"returns": "multiple", "phase": "wait-observed"})
                self.assertIsNone(L._shell_label_pair(frame(picker=token, step=b"SessionSetFile", wait=allowed[0])))
        self.assertEqual(len(tokens), 30)
        self.assertNotIn(b"na", tokens)
        absent = L._shell_label_pair(frame(picker=b"0a", wait=b"gtk-selection-absent"))["session"]["gtkPicker"]
        self.assertEqual(absent, {"mapped": False, "folder": "absent", "selected": "absent"})
        self.assertIsNone(L._shell_label_pair(frame(picker=b"na"))["session"]["gtkPicker"])
        for step, callbacks, wait in ((b"SessionSetFile", b"0p", b"gtk-dialog-absent"),
                                      (b"SessionReview", b"na", b"native-reply-pending")):
            self.assertIsNone(L._shell_label_pair(frame(picker=b"na", step=step, callbacks=callbacks, wait=wait))["session"]["gtkPicker"])
            self.assertIsNone(L._shell_label_pair(frame(step=step, callbacks=callbacks, wait=wait)))
        raw = frame()
        self.assertEqual(raw.count(b"\n"), 4)
        self.assertEqual(L.SHELL_SESSION_FAILURE_V7_FRAME_BOUND, L.SHELL_SESSION_FAILURE_V6_FRAME_BOUND + 5)
        self.assertEqual(L.SHELL_SESSION_FAILURE_V7_FRAME_BOUND, L.SHELL_FAILURE_LABEL_LIMIT)
        self.assertEqual(L.SHELL_FAILURE_LABEL_LIMIT, 512)
        self.assertLessEqual(len(raw), L.SHELL_SESSION_FAILURE_V7_FRAME_BOUND)
        with patch.object(L, "SHELL_SESSION_FAILURE_V7_FRAME_BOUND", len(raw) - 1):
            self.assertIsNone(L._shell_label_pair(raw))
        for end in range(len(raw)):
            self.assertIsNone(L._shell_label_pair(raw[:end]))
            if end < len(raw) - 1:
                self.assertIsNone(L._shell_label_pair(raw[:end] + b"\n"))
        bad = [frame(index=b"none"), frame(index=b"64"), frame(index=b"09"), frame(callbacks=b"na"),
               raw.replace(b";h=4f", b""), raw.replace(b";h=4f", b";h=4f;h=4f"),
               raw.replace(b";g=mw;h=4f", b";h=4f;g=mw"), raw.replace(b";h=4f", b";picker=4f"),
               raw.replace(b";eval=30;", b";evaluations=30;"), raw + b"\n", raw + raw, raw + b"x" * 512,
               raw.replace(b"\n", b"\r\n"), raw.replace(b";h=4f", b";h=4f;path=/private/inert.json")]
        for token in (b"", b"n", b"n0", b"0", b"4", b"6f", b"4x", b"4F", b"44f", b"Na",
                      b"4f/private/inert.json", b"file:///private/inert.json", b"4f\x00", b"4f\n"):
            bad.append(frame(picker=token))
        for version in (b"v1", b"v2", b"v3", b"v4", b"v5", b"v6", b"v8"):
            bad.append(raw.replace(b"=v7;", b"=" + version + b";"))
        for value in bad:
            self.assertIsNone(L._shell_label_pair(value))
        historical = raw.replace(b"=v7;", b"=v6;").replace(b";h=4f", b"")
        self.assertNotIn("gtkPicker", L._shell_label_pair(historical)["session"])
        self.assertEqual(L.SHELL_SESSION_FAILURE_V6_FRAME_BOUND, 507)
        # Exact closed DATA projection, not a load-complete or native-finality receipt.

    def test_preparation_exclusively_binds_original_fd_and_preserves_preparation_failure(self):
        value = installed_handoff(); value.pop("installed"); value["shell"] = {}
        root = L.root_path(value)
        for fault in (None, "occupied", "owner", "acl", "hardlink", "parent"):
            parent = needrestart_stat(stat.S_IFDIR | 0o711)
            leaf = needrestart_stat(stat.S_IFREG | 0o620, ino=42); leaf.st_gid = value["runnerGid"]
            if fault == "hardlink": leaf.st_nlink = 2
            if fault == "parent": parent.st_mode = stat.S_IFDIR | 0o777
            primary = OSError("inert preparation failure; must not be formatted")
            with self.subTest(fault=fault), patch.object(L, "_ROOT", root), patch.object(L, "directory"), \
                 patch.object(L, "_xattrs"), patch.object(Path, "lstat", lambda path: parent if path == root else leaf), \
                 patch.object(L.os, "open", return_value=41) as opening, patch.object(L.os, "fchown") as chown, \
                 patch.object(L.os, "fchmod") as chmod, patch.object(L.os, "fstat", return_value=leaf), \
                 patch.object(L.os, "listxattr", return_value=["system.posix_acl_access"] if fault == "acl" else []), \
                 patch.object(L.os, "close") as closing, patch.object(L.os, "unlink") as unlinking:
                if fault == "occupied": opening.side_effect = primary
                if fault == "owner":
                    chown.side_effect = primary
                    closing.side_effect = OSError("inert ambiguous close")
                if fault is None:
                    self.assertEqual(L._shell_labels_prepare(value, "positive"), (41, L.identity(leaf)[:6]))
                    opening.assert_called_once_with(root / "shell-positive-failure.labels",
                        os.O_RDONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
                    chown.assert_called_once_with(41, 0, value["runnerGid"])
                    chmod.assert_called_once_with(41, 0o620)
                    closing.assert_not_called()  # The command, not preparation, now owns this original.
                else:
                    with self.assertRaises((OSError, ValueError)) as raised:
                        L._shell_labels_prepare(value, "positive")
                    if fault in ("occupied", "owner"): self.assertIs(raised.exception, primary)
                    self.assertEqual(closing.call_count, int(fault not in ("occupied", "parent")))
                    self.assertEqual(opening.call_count, int(fault != "parent"))
                unlinking.assert_not_called()

    def test_original_fd_read_is_single_bounded_and_rejects_binding_or_metadata_loss(self):
        raw = (b"MRK_INSTALLED_SHELL_FAILURE_STEP=Bootstrap\nMRK_INSTALLED_SHELL_FAILURE_PHASE=bootstrap\n"
               b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=not-sampled\n")
        node = needrestart_stat(stat.S_IFREG | 0o620, size=len(raw)); node.st_gid = 1001
        original = (41, L.identity(node)[:6])
        for fault in (None, "inode", "link", "mode", "group", "oversized", "acl", "drift", "partial", "empty", "read-error"):
            before, after = deepcopy(node), deepcopy(node)
            for name, field, value in (("inode", "st_ino", 99), ("link", "st_nlink", 2),
                    ("mode", "st_mode", stat.S_IFIFO | 0o620), ("group", "st_gid", 99),
                    ("oversized", "st_size", 513)):
                if fault == name: setattr(before, field, value)
            if fault == "drift": after.st_ctime_ns += 1
            if fault == "empty": before.st_size = after.st_size = 0
            with self.subTest(fault=fault), patch.object(L.os, "fstat", side_effect=[before, after]), \
                 patch.object(L.os, "listxattr", return_value=["user.inert"] if fault == "acl" else []), \
                 patch.object(L.os, "read", return_value=b"" if fault == "empty" else raw[:-1] if fault == "partial" else raw) as reading, \
                 patch.object(L.os, "open") as opening, patch.object(L, "read") as raw_read, \
                 patch.object(L.os, "lseek") as seeking:
                if fault == "read-error": reading.side_effect = InterruptedError("inert read interruption")
                if fault in (None, "empty"):
                    self.assertEqual(L._shell_labels_read(original), None if fault == "empty" else
                                     {"step": "Bootstrap", "boundary": "bootstrap", "bootstrapProgress": "not-sampled"})
                else:
                    with self.assertRaises((ValueError, OSError)): L._shell_labels_read(original)
                if fault in ("inode", "link", "mode", "group", "oversized", "acl"):
                    reading.assert_not_called()
                else:
                    reading.assert_called_once_with(41, 513)
                opening.assert_not_called(); raw_read.assert_not_called(); seeking.assert_not_called()

        # The classifier gets the same bounded original read, not a second
        # read/reopen for its raw frame after the diagnostic parser consumes it.
        with patch.object(L.os, "fstat", side_effect=[node, node]), patch.object(L.os, "listxattr", return_value=[]), \
             patch.object(L.os, "read", return_value=raw) as reading, patch.object(L.os, "open") as opening, \
             patch.object(L, "read") as raw_read, patch.object(L.os, "lseek") as seeking:
            self.assertEqual(L._shell_labels_read(original, with_raw=True),
                             (raw, {"step": "Bootstrap", "boundary": "bootstrap", "bootstrapProgress": "not-sampled"}))
            reading.assert_called_once_with(41, 513)
            opening.assert_not_called(); raw_read.assert_not_called(); seeking.assert_not_called()

    def test_returned_failure_requires_the_same_typed_bounded_result(self):
        class Subclass(subprocess.CompletedProcess): pass
        value = installed_handoff(); value.pop("installed"); value["shell"] = {}
        argv = L.shell_argv(value, "positive")
        original = (41, "original-label-binding")
        handoff = b"MRK_INSTALLED_SHELL_FAILURE_HANDOFF=original-quit-relay-loop-returned\n"
        failed = b"MRK_INSTALLED_SHELL_OBSERVATION=failed\n"
        payload = handoff + failed
        limit = len(payload) + 32
        good = subprocess.CompletedProcess(argv, 1, payload, b"")
        call = {"timeoutSeconds": 60, "ownerReturned": True, "startMonotonic": 100.0, "endMonotonic": 101.0}
        broken = {"timeoutSeconds": True, "ownerReturned": False, "startMonotonic": float("nan"), "endMonotonic": "101"}
        labels = L._shell_label_pair(b"MRK_INSTALLED_SHELL_FAILURE_STEP=Bootstrap\nMRK_INSTALLED_SHELL_FAILURE_PHASE=bootstrap\n"
                                    b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=not-sampled\n")
        candidates = [("original", good, call, True), ("missing-call", good, None, True), ("broken-call", good, broken, True),
                      ("subclass", Subclass(argv, 1, payload, b""), call, False),
                      ("lookalike", SimpleNamespace(args=argv, returncode=1, stdout=payload, stderr=b""), call, False),
                      ("wrong-argv", subprocess.CompletedProcess(["/other/original"], 1, payload, b""), call, False),
                      ("bool-code", subprocess.CompletedProcess(argv, True, payload, b""), call, False),
                      ("stdout-text", subprocess.CompletedProcess(argv, 1, payload.decode("ascii"), b""), call, False),
                      ("stderr-text", subprocess.CompletedProcess(argv, 1, payload, ""), call, False),
                      ("mutable-stream", subprocess.CompletedProcess(argv, 1, bytearray(payload), b""), call, False),
                      ("combined-bound", subprocess.CompletedProcess(argv, 1, payload, b"x" * 33), call, False)]
        for name, result, observed_call, allowed in candidates:
            with self.subTest(name=name), patch.object(L, "LIMIT", limit), \
                 patch.object(L, "_shell_capture_summary", wraps=L._shell_capture_summary) as capture, \
                 patch.object(L, "_shell_labels_read", return_value=labels) as reading, \
                 patch.object(L, "_shell_call_finished") as finishing, patch.object(L, "_shell_diagnostic_time") as clock, \
                 patch.object(L.os, "open") as opening, patch.object(L.os, "close") as closing, \
                 patch.object(L.os, "lseek") as seeking, patch.object(L, "read") as raw_read, \
                 patch.object(L.sys, "stderr", new_callable=io.StringIO) as stream:
                L._shell_command_failure(argv, result, "positive", None, None, original, observed_call)
                capture.assert_called_once_with(result, argv, None)
                self.assertIs(capture.call_args.args[0], result)
                self.assertEqual(reading.call_args_list, [unittest.mock.call(original)] if allowed else [])
                raw = stream.getvalue().encode("ascii")
                self.assertLessEqual(len(raw), 32768)
                data = json.loads(raw.split(b"=", 1)[1])
                self.assertEqual(data["scope"], "original-shell-command-failure-diagnostic-only")
                self.assertEqual(data["labels"], labels if allowed else None)
                self.assertEqual(data["labelsReason"], None if allowed else "owner-finality-unavailable")
                self.assertEqual(data["capture"] is not None, allowed)
                self.assertEqual(data["failureHandoff"], "original-quit-relay-loop-returned" if allowed else None)
                self.assertFalse(data["qualified"]); self.assertFalse(data["cleanupEstablished"])
                if observed_call is None: self.assertIsNone(data["ownerCall"])
                elif observed_call is broken:
                    self.assertFalse(data["ownerCall"]["ownerReturned"])
                    for key in ("timeoutSeconds", "startMonotonic", "endMonotonic", "ownerElapsedSeconds"):
                        self.assertIsNone(data["ownerCall"][key])
                else: self.assertTrue(data["ownerCall"]["ownerReturned"])
                finishing.assert_not_called(); clock.assert_not_called()
                opening.assert_not_called(); closing.assert_not_called(); seeking.assert_not_called(); raw_read.assert_not_called()

        # Only two complete closed records from the original returned streams
        # can project the witness; display logs and label presence cannot invent it.
        records = [
            ("stderr", 1, b"inert\n", payload, labels, None, True),
            ("split", 1, handoff, failed, labels, None, True),
            ("missing-labels", 1, payload, b"", None, None, False),
            ("label-read-error", 1, payload, b"", labels, None, False),
            ("zero", 0, payload, b"", labels, None, False),
            ("other-code", 2, payload, b"", labels, None, False),
            ("signal", -15, payload, b"", labels, None, False),
            ("log-only", 1, failed, b"", labels, handoff, False),
            ("missing-failed", 1, handoff, b"", labels, None, False),
            ("duplicate-handoff", 1, payload, handoff, labels, None, False),
            ("duplicate-failed", 1, payload, failed, labels, None, False),
            ("unterminated", 1, failed, handoff[:-1], labels, None, False),
            ("crlf", 1, payload.replace(b"\n", b"\r\n"), b"", labels, None, False),
            ("prefixed", 1, b"inert " + payload, b"", labels, None, False),
            ("bare-cr-prefix", 1, b"inert\r" + payload, b"", labels, None, False),
            ("bare-cr-separator", 1, handoff[:-1] + b"\r" + failed, b"", labels, None, False),
            ("prefixed-extra", 1, payload, b"inert\r" + handoff, labels, None, False),
            ("malformed", 1, failed, b"MRK_INSTALLED_SHELL_FAILURE_HANDOFF=other\n", labels, None, False),
            ("partial-extra", 1, payload, b"MRK_INSTALLED_SHELL_FAILURE_HANDOFF", labels, None, False),
            ("conflicting-verdict", 1, payload, b"MRK_INSTALLED_SHELL_OBSERVATION=route-refused\n", labels, None, False),
            ("verified-verdict", 1, payload, b"MRK_INSTALLED_SHELL_OBSERVATION=positive-verified\n", labels, None, False),
            ("verified-contract", 1, payload, b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n", labels, None, False),
        ]
        for name, code, stdout, stderr, first_labels, display, allowed in records:
            result = subprocess.CompletedProcess(argv, code, stdout, stderr)
            with self.subTest(records=name), \
                 patch.object(L, "_shell_capture_summary", wraps=L._shell_capture_summary) as capture, \
                 patch.object(L, "_shell_labels_read", return_value=first_labels) as reading, \
                 patch.object(L, "_shell_call_finished") as finishing, patch.object(L, "_shell_diagnostic_time") as clock, \
                 patch.object(L.os, "open") as opening, patch.object(L.os, "close") as closing, \
                 patch.object(L.os, "lseek") as seeking, patch.object(L, "read") as raw_read, \
                 patch.object(L.sys, "stderr", new_callable=io.StringIO) as stream:
                if name == "label-read-error": reading.side_effect = OSError("inert label read failure")
                L._shell_command_failure(argv, result, "positive", display, None, original, None)
                capture.assert_called_once_with(result, argv, display)
                reading.assert_called_once_with(original)
                raw = stream.getvalue().encode("ascii")
                self.assertLessEqual(len(raw), 32768)
                data = json.loads(raw.split(b"=", 1)[1])
                self.assertEqual(data["failureHandoff"], "original-quit-relay-loop-returned" if allowed else None)
                self.assertEqual(data["labels"], None if name == "label-read-error" else first_labels)
                self.assertFalse(data["qualified"]); self.assertFalse(data["cleanupEstablished"])
                self.assertIsNone(data["ownerCall"])
                finishing.assert_not_called(); clock.assert_not_called()
                opening.assert_not_called(); closing.assert_not_called(); seeking.assert_not_called(); raw_read.assert_not_called()

    def test_owner_exception_requires_exact_stored_true_facts_and_same_original_is_reraised(self):
        class ProcessError(RuntimeError):
            def __init__(self, contained=True, cleanup=True):
                super().__init__("/private/inert-secret must not be exposed")
                self.__dict__.update(dispatched=True, contained=contained, cleanup_complete=cleanup)
            def __str__(self):
                raise AssertionError("error formatting is forbidden")
        class ProcessCleanupError(ProcessError): pass
        class ProcessOutcomeUnknown(ProcessError): pass
        class Unknown(ProcessError):
            @property
            def contained(self): raise AssertionError("subclass properties are not evidence")
        value = installed_handoff(); value.pop("installed"); value["shell"] = {}
        argv = L.shell_argv(value, "positive")
        errors = [ProcessError(), ProcessError(False), ProcessError(True, False), ProcessError(1),
                  ProcessError(True, "true"), ProcessCleanupError(), ProcessOutcomeUnknown(), Unknown(),
                  KeyboardInterrupt(), SystemExit(), OSError("private generic error")]
        missing = ProcessError(); del missing.__dict__["cleanup_complete"]; errors.append(missing)
        for index, primary in enumerate(errors):
            if index:
                primary.__cause__ = ProcessError()  # Cause-chain facts grant no read authority.
            owner = SimpleNamespace(run_owned=Mock(side_effect=primary), ProcessError=ProcessError,
                                    ProcessCleanupError=ProcessCleanupError, ProcessOutcomeUnknown=ProcessOutcomeUnknown)
            with self.subTest(index=index), patch.multiple(L, _ROOT=L.root_path(value), _END=1000.0,
                    _FAILED=False, _COMMANDS=[], _OWNER=owner), patch.object(L, "_root_ids"), \
                 patch.object(L.time, "monotonic", return_value=100.0), \
                 patch.object(L, "_shell_labels_prepare", return_value=(41, "original")), \
                 patch.object(L, "_shell_labels_read", return_value={"step": "PrepareSave", "boundary": "request", "bootstrapProgress": "advanced"}) as reading, \
                 patch.object(L, "_shell_log_capture") as raw_log, patch.object(L, "_command_capture") as capture, \
                 patch.object(L.os, "close") as closing, patch.object(L.sys, "stderr", new_callable=io.StringIO) as stream:
                with self.assertRaises(BaseException) as raised:
                    L.command("shell-positive", argv, maximum=60, shell_log=(value, "positive", "original-log"))
                self.assertIs(raised.exception, primary)
                self.assertTrue(L._FAILED)
                self.assertEqual(reading.call_count, int(index == 0))
                raw_log.assert_not_called(); capture.assert_not_called(); closing.assert_called_once_with(41)
                owner.run_owned.assert_called_once()
                self.assertEqual(owner.run_owned.call_args.kwargs["timeout"], 60)
                text = stream.getvalue()
                self.assertLessEqual(len(text.encode("ascii")), 32768)
                self.assertNotIn("inert-secret", text); self.assertNotIn("private generic", text)
                data = json.loads(text.split("=", 1)[1])
                self.assertEqual((data["case"], data["phase"]), ("positive", "owner-call"))
                self.assertIsNone(data["capture"])
                self.assertFalse(data["qualified"]); self.assertFalse(data["cleanupEstablished"])
                self.assertEqual(data["labelsReason"], None if index == 0 else "owner-finality-unavailable")
                self.assertEqual(data["labels"], {"step": "PrepareSave", "boundary": "request", "bootstrapProgress": "advanced"} if index == 0 else None)
                self.assertFalse(data["ownerCall"]["ownerReturned"])

    def test_bootstrap_catalog_and_first_failure_wiring_match_the_original_observer(self):
        source = (SOURCE / "desktop/src-tauri/src/installed_shell_observation.rs").read_text()
        block = source.split("impl BootstrapProgress {", 1)[1].split("enum OutstandingInfo", 1)[0]
        actual = [ast.literal_eval(line.split("=>", 1)[1].strip().rstrip(","))
                  for line in block.splitlines() if "=> b" in line]
        self.assertEqual(tuple(actual), L.SHELL_BOOTSTRAP_PROGRESS)
        self.assertEqual(len(set(actual)), 8)
        callback = source.split("pub(super) fn app_info(&self", 1)[1].split("pub(super) fn unexpected", 1)[0]
        outstanding = callback.split("let Some(methods)", 1)[0]
        self.assertIn("self.record()", outstanding)
        self.assertNotIn("record_at", outstanding)
        self.assertIn("outstanding_info(r.step", outstanding)
        self.assertIn("result != OutstandingInfo::ShutdownUnavailable", outstanding)
        self.assertIn("latch_failure(&self.failed", outstanding)
        self.assertNotIn("runtime.reason", outstanding)
        self.assertNotIn("r.held", outstanding)
        report = source.split("fn report_failure(&self)", 1)[1].split("pub(super) fn attach", 1)[0]
        self.assertIn("Ok(r) => (r.trace, r.bootstrap, r.session.diagnostic, r.paths.diagnostic, r.evidence_diagnostic,", report)
        self.assertIn("r.snapshot_diagnostic, self.failed.site(), r.metadata.open_failure, r.github_entry)", report)
        self.assertIn("snapshot_failure_frame(trace, progress, site, snapshot)", report)
        self.assertIn("failure_frame(trace, progress, session, path, evidence)", report)
        self.assertEqual(report.count("rustix::io::write"), 1)
        self.assertNotIn("retain_held_app_info", report)
        tick = source.split("pub(super) fn tick(", 1)[1].split("pub(super) fn", 1)[0]
        self.assertEqual(tick.count("retain_held_app_info()"), 1)
        self.assertIn("(*step, Boundary::Deadline), progress", tick)
        self.assertIn("Duration::from_secs(45)", source)
        self.assertIn("assert_failure_pair_contract();", source)
        for contract in ("assert_failure_latch_contract();", "assert_snapshot_rejection_contract();", "assert_snapshot_frame_contract();"):
            self.assertIn(contract, source.split("pub(crate) fn main()", 1)[1])

    def test_path_first_rejection_preserves_borrows_guard_order_and_first_winner(self):
        source = (SOURCE / "desktop/src-tauri/src/installed_shell_observation.rs").read_text()
        shell = (SOURCE / "desktop/src-tauri/src/shell.rs").read_text()
        def body(text, name):
            return text.split("fn " + name + "(", 1)[1].split("\n    }", 1)[0]
        diagnostic = source.split("struct PathDiagnostic", 1)[1].split("#[derive(Clone, Copy)]", 1)[0]
        self.assertIn("{ step: PathStep, rejection: PathRejection, step_entry_ms: u128, sample_ms: u128,", diagnostic)
        self.assertIn("previous.filter(|old| old.step == step)", diagnostic)
        self.assertIn("old.sample_ms = elapsed_ms; return Some(old);", diagnostic)
        self.assertIn("step_entry_ms: elapsed_ms, sample_ms: elapsed_ms", diagnostic)
        for forbidden in ("PathBuf", "String", "filename", "Instant", "snapshot"):
            self.assertNotIn(forbidden, diagnostic)
        cache = body(source, "record_at")
        self.assertIn("self.path_sample(&mut r);", cache)
        self.assertLess(cache.index("if !self.failed.load(Ordering::SeqCst)"), cache.index("self.path_sample("))
        sampler = body(source, "path_sample")
        self.assertLess(sampler.index("if !self.failed.load(Ordering::SeqCst)"), sampler.index("r.paths.diagnostic ="))
        self.assertIn("PathDiagnostic::sample_trace(&mut r.trace,step,self.start.elapsed().as_millis(),previous)", sampler)
        self.assertIn("if matches!(step,Step::Paths(_)) || matches!(trace.0,Step::Paths(_)) || previous.is_some() { trace.0 = step; }", diagnostic)
        self.assertIn("} else { false }", sampler)
        marker = body(source, "path_callback")
        self.assertIn("if self.path_sample(&mut r) {\n            if let Some(diagnostic) = r.paths.diagnostic.as_mut() { diagnostic.mark(callback); }\n        }", marker)
        self.assertIn("self.path_file_wait(wait,SessionPickerReadiness::NotSampled);", body(source, "path_wait"))
        wait = body(source, "path_file_wait")
        self.assertEqual(wait.count("self.record()"), 1)
        self.assertLess(wait.index("self.failed.load"), wait.index("d.file_wait(wait,picker)"))
        self.assertIn("self.path_sample(&mut r)", wait)
        self.assertIn("self.wait = wait; self.gtk_picker = picker; true", diagnostic)
        self.assertIn("if !picker.valid_path(self.step,wait) { return false; }", diagnostic)
        latch = source.split("fn latch_path_diagnostic(", 1)[1].split("const PROJECT_SOURCE", 1)[0]
        self.assertIn("if failed.mark_unknown() { *diagnostic = Some(next); }", latch)
        helper = body(source, "path_fail")
        self.assertIn("PathDiagnostic::sample(r.trace.0,self.start.elapsed().as_millis(),r.paths.diagnostic)", helper)
        self.assertIn("latch_path_diagnostic(&self.failed,&mut r.paths.diagnostic,diagnostic)", helper)
        self.assertNotIn("self.record", helper)
        pure = source.split("fn assert_failure_pair_contract()", 1)[1].split("// Original destruction facts", 1)[0]
        self.assertIn("for order in [[0,1,2],[0,2,1],[1,0,2],[1,2,0],[2,0,1],[2,1,0]]", pure)
        self.assertIn("0 => { failed.mark_unknown(); }", pure)
        self.assertIn("retained == Some(if order[0] == 1 { path_gtk } else { path_plain })", pure)
        self.assertIn("step:PathStep::Activate(4),rejection:PathRejection::GtkReturnState", pure)

        admitting = body(shell, "observed_path_dialog")
        borrowed = admitting.split("let original = DIALOG.with(|book| {", 1)[1].split("        });", 1)[0]
        self.assertIn("map_err(|_| R::GtkDialogBook)", borrowed)
        self.assertIn("Err(R::GtkDialogOriginal)", borrowed)
        self.assertNotIn("q.", borrowed); self.assertNotIn(".facts()", borrowed)
        self.assertLess(admitting.index("        });"), admitting.index("Err(reason) => { q.path_failed(reason); return Err(()); }"))
        guards = ["gtk::is_initialized_main_thread()", "DIALOG.with", "context.upgrade()", "call.upgrade()", "call.owner()",
                  "owner.id != id", "owner.interrupted()", "let original_facts = call.facts()", "if !original_facts",
                  "q.path_dialog(id,index)?", "app.get_webview_window(MAIN_WINDOW)", "dialog.title()", "if initial {", "dialog.current_folder()"]
        self.assertEqual([admitting.index(guard) for guard in guards], sorted(admitting.index(guard) for guard in guards))
        facts = admitting.split("let original_facts =", 1)[1].split("if !original_facts", 1)[0]
        self.assertTrue(facts.rstrip().endswith("f.refusal.is_none());")); self.assertNotIn("q.", facts)
        self.assertEqual(admitting.count("dialog.current_folder()"), 1)
        self.assertIn("let Some(folder) = dialog.current_folder() else { q.path_wait(installed_observation::PathWait::InitialFolderAbsent); return Ok(None); };", admitting)
        self.assertIn("if Some(folder.as_path()) != q.project_path() { q.path_failed(R::GtkInitialFolder); return Err(()); }", admitting)
        selecting = body(shell, "select_observed_path"); activating = body(shell, "activate_observed_path")
        self.assertNotIn("dialog.set_filename(", selecting)
        self.assertEqual(selecting.count("dialog.set_current_folder(path)"), 1)
        self.assertEqual(selecting.count("dialog.set_current_folder(parent)"), 1)
        self.assertEqual(selecting.count("dialog.select_file(&target_file).is_err()"), 1)
        self.assertIn('match dialog.property::<gtk::FileChooserAction>("action")', selecting)
        folder, opened = selecting.split("gtk::FileChooserAction::Open =>", 1)
        self.assertLess(folder.index("q.path_selection(id,index)?"), folder.index("dialog.set_current_folder(path)"))
        navigation, passive = opened.split("let target_file =", 1)
        self.assertIn("if !parent_navigation_reserved {", navigation)
        self.assertLess(navigation.index("q.path_parent_navigation(id,index)?"), navigation.index("dialog.set_current_folder(parent)"))
        self.assertIn("return Ok(false);", navigation)
        self.assertNotIn("set_current_folder", passive)
        guards = ["dialog.is_mapped()", "dialog.current_folder_file()", "dialog.file()", "if !mapped",
                  "if current_folder.is_none() { q.path_file_wait", "if !parent_ready", "q.path_selection(id,index)?", "dialog.select_file(&target_file).is_err()"]
        self.assertEqual([passive.index(guard) for guard in guards], sorted(passive.index(guard) for guard in guards))
        self.assertIn("file.equal(&parent_file)", passive)
        self.assertIn("_ => { q.path_failed(R::GtkDialogProperties); return Err(()); }", selecting)
        self.assertEqual(selecting.count("q.path_failed(R::GtkSelectionSetter)"), 3)
        self.assertLess(activating.index("if !button.is_sensitive() { q.path_file_wait(W::ResponseInsensitive,picker); return Ok(false); }"), activating.index("q.path_activation(id,index)?"))
        self.assertEqual(activating.count("dialog.file()"), 1)
        self.assertIn("q.path_file_wait(W::SelectionAbsent,picker); return Ok(false)", activating)
        self.assertIn("q.path_file_wait(W::SelectionDifferent,picker); return Ok(false)", activating)
        self.assertLess(activating.index("q.path_activation(id,index)?"), activating.index("button.emit_clicked()"))
        self.assertEqual(activating.count("button.emit_clicked()"), 1)
        for forbidden in (".filename(", ".response(", ".begin_response(", "Instant::", "sleep"):
            self.assertNotIn(forbidden, admitting + selecting + activating)
        self.assertNotIn("set_current_folder", admitting + activating)
        self.assertNotIn("set_filename", activating)
        self.assertEqual(shell.count("dialog.filename()"), 1)
        for name in ("path_failed", "path_dialog", "path_parent_navigation", "path_selection", "path_activation", "path_filename", "path_response", "path_gtk_returned"):
            callback = body(source, name)
            self.assertEqual(callback.count("self.record_at(Boundary::Gtk)"), 1)
            self.assertIn("self.path_fail(&mut r,", callback)
            self.assertNotIn("self.path_failed(", callback); self.assertNotIn("self.record()", callback)
        for name, guards in (("path_dialog", ("PATH_CASES.get", "self.failed.load", "Instant::now()", "self.case !=")),
                             ("path_parent_navigation", ("PATH_CASES.get", "self.case !=", "Instant::now()", "self.failed.load", "id !=")),
                             ("path_selection", ("PATH_CASES.get", "self.case !=", "Instant::now()", "self.failed.load", "id !=")),
                             ("path_activation", ("PATH_CASES.get", "self.case !=", "Instant::now()", "self.failed.load", "id !="))):
            callback = body(source, name)
            self.assertEqual([callback.index(guard) for guard in guards], sorted(callback.index(guard) for guard in guards))
            self.assertEqual(callback.count("Instant::now()"), 1)
            self.assertIn("PathRejection::GtkObserverEndpoint", callback)
        for name, reserve in (("path_parent_navigation", "reserve_parent_navigation(case)"), ("path_selection", "reserve_selection(case)")):
            callback = body(source, name)
            guards = ["PATH_CASES.get(index as usize)", "Instant::now() >= self.end", "self.failed.load",
                      "id != u32::from(index)+3", "r.step != Step::Paths(PathStep::Set(index))",
                      "r.pending != Some(Pending::Path(PathStep::Set(index)))", reserve]
            self.assertEqual([callback.index(guard) for guard in guards], sorted(callback.index(guard) for guard in guards))
            self.assertNotIn("self.end =", callback)
            self.assertEqual(callback.count(reserve), 1)
        operation = source.split("impl PathOperation {", 1)[1].split("struct Paths", 1)[0]
        self.assertEqual(operation.count("self.parent_navigation_reserved = true"), 1)
        self.assertIn("!self.requested || !self.picker.created", operation)
        self.assertIn("self.parent_navigation_reserved == case.selects_open()", operation)
        self.assertIn("|| self.picker.selected || self.picker.activated", operation)
        self.assertIn("case.path.is_none()", operation)
        self.assertIn("!self.navigation_matches(case)", operation)
        self.assertIn("!op.picker.selected && !op.parent_navigation_reserved", body(source, "path_dialog"))
        self.assertIn("!op.navigation_matches(case)", body(source, "path_activation"))
        self.assertIn("op.navigation_matches(&PATH_CASES[i]) && op.picker.settled", source)
        self.assertIn("assert_eq!(open,vec![1,6,7,8]);", source)
        filename = body(source, "path_filename")
        guards = ["id.checked_sub", "self.case !=", "self.failed.load", "Instant::now()", "PATH_CASES[index].field != field",
                  "path.is_none()", "path != self.path_target", "!r.paths.operations[index].picker.activated", "fixture.transition(id)"]
        self.assertEqual([filename.index(guard) for guard in guards], sorted(filename.index(guard) for guard in guards))
        self.assertEqual(filename.count("fixture.transition(id)"), 1); self.assertEqual(filename.count("Instant::now()"), 2)
        self.assertNotIn(".filename(", filename)
        self.assertLess(filename.index("PathRejection::GtkFilenameAbsent"), filename.index("PathRejection::GtkFilenameDifferent"))
        self.assertLess(filename.index("PathRejection::GtkFixtureTransition"), filename.rindex("PathRejection::GtkObserverEndpoint"))
        self.assertLess(filename.rindex("PathRejection::GtkObserverEndpoint"), filename.index("picker.filename = true"))
        returned = body(source, "path_gtk_returned")
        self.assertIn("r.pending.take() != Some(Pending::Path(path)) || r.step != Step::Paths(path)", returned)
        self.assertEqual(returned.count(".activation_returned(result)"), 1)
        self.assertNotIn(".responded", returned); self.assertNotIn("self.failed.load", returned)
        self.assertIn("self.path_fail(&mut r,PathRejection::GtkReturnState)", returned)
        self.assertIn("self.path_sample(&mut r);", returned)
        self.assertIn("self.path_sample(&mut r);", body(source, "path_dom"))
        tick = body(source, "tick")
        self.assertIn("if let Some(mut r) = self.record() { self.path_fail(&mut r,PathRejection::GtkDispatch); } else { self.fail(); }", tick)
        dispatch = tick.split("let q = self.clone(); let app = app.clone();\n                // Reservation", 1)[1].split("Step::Cancel |", 1)[0]
        markers = ["self.path_callback(path,PathCallback::Reserved)", "window.run_on_main_thread", "q.path_callback(path,PathCallback::Entered)",
                   "let result =", "q.path_callback(path,PathCallback::Returned)", "q.path_gtk_returned(path,result)"]
        self.assertEqual([dispatch.index(marker) for marker in markers], sorted(dispatch.index(marker) for marker in markers))
        self.assertNotIn("return;", dispatch.split("}).is_err()", 1)[0])
        for name, reason in (("native_destroyed", "GtkDestroyState"), ("native_released", "GtkReleaseState")):
            path_branch = body(source, name).split("if self.case == Case::ProjectPaths", 1)[1].split("if self.case == Case::Positive", 1)[0]
            self.assertIn("self.path_fail(&mut r,PathRejection::" + reason + ")", path_branch)
        # Source contracts and the inert Rust checks are not native receipts.

    def test_session_diagnostics_are_cached_same_step_and_first_failure_only(self):
        source = (SOURCE / "desktop/src-tauri/src/installed_shell_observation.rs").read_text()
        sample = source.split("impl SessionDiagnostic {", 1)[1].split("use SessionAction", 1)[0]
        self.assertIn("old.step == step", sample)
        self.assertIn("SessionWait::NotSampled", sample)
        self.assertIn("SessionGtkCallbacks::initial(step)", sample)
        self.assertIn("|old| old.gtk_callbacks", sample)
        self.assertIn("gtk_picker: previous.filter(|old| old.step == step)", sample)
        self.assertIn(".map_or(SessionPickerReadiness::NotSampled, |old| old.gtk_picker)", sample)
        file_wait = sample.split("fn file_wait(", 1)[1].split("\n    }", 1)[0]
        self.assertLess(file_wait.index("if !picker.valid(self.step,wait) { return false; }"),
                        file_wait.index("self.wait = wait; self.gtk_picker = picker;"))
        self.assertIn("if wait != SessionWait::NotSampled { self.gtk_callbacks.wait_observed(); }", file_wait)
        generic_wait = source.split("fn session_wait(", 1)[1].split("\n    }", 1)[0]
        self.assertIn("diagnostic.wait = wait; diagnostic.gtk_picker = SessionPickerReadiness::NotSampled;", generic_wait)
        self.assertLess(generic_wait.index("if !self.failed.load(Ordering::SeqCst)"), generic_wait.index("diagnostic.gtk_picker ="))
        dispatch = source.split("if matches!(step,SessionStep::SetFile(_) | SessionStep::ActivateFile(_)) {", 1)[1].split("if step==SessionStep::QuitCancel", 1)[0]
        ordered = ("if self.failed.load", "if r.pending.is_some()", "r.pending=Some", "diagnostic.gtk_callbacks.reserved()", "window.run_on_main_thread", "q.session_file_returned(step,result)")
        self.assertEqual([dispatch.index(part) for part in ordered], sorted(dispatch.index(part) for part in ordered))
        wait = source.split("pub(super) fn session_file_wait(", 1)[1].split("pub(super) fn session_file_created(", 1)[0]
        self.assertLess(wait.index("session_file_wait_pending(r.step,r.pending,index,activating)"), wait.index("diagnostic.file_wait(wait,picker)"))
        self.assertLess(wait.index("if !self.failed.load"), wait.index("diagnostic.file_wait(wait,picker)"))
        returned = source.split("fn session_file_returned(", 1)[1].split("pub(super) fn quit_selects_ok(", 1)[0]
        ordered = ("r.pending.take()!=Some(Pending::Dom(Step::Session(step))) || r.step!=Step::Session(step)",
                   "let index=match step", "if !self.failed.load", "diagnostic.gtk_callbacks.returned()", "r.session.files.last_mut()", "match result")
        self.assertEqual([returned.index(part) for part in ordered], sorted(returned.index(part) for part in ordered))
        self.assertNotIn("self.failed.load", returned.split("r.pending.take()", 1)[0])
        self.assertIn("if result!=Ok(false)", returned)  # Missing dialog still returns its original notification.
        self.assertIn("file.picker.activation_returned(result)", returned)
        callbacks = source.split("impl SessionGtkCallbacks {", 1)[1].split("// Map only cached public DATA", 1)[0]
        for forbidden in ("Instant::", "std::thread", "run_on_main_thread", "fs::", "rustix::", "Command::", "fetch_add"):
            self.assertNotIn(forbidden, callbacks)
        cache = source.split("fn record_at(&self", 1)[1].split("fn report_failure(&self)", 1)[0]
        self.assertIn("if !self.failed.load(Ordering::SeqCst)", cache)
        self.assertIn("SessionDiagnostic::sample(r.step,r.evaluations,r.session.diagnostic)", cache)
        latch = source.split("fn latch_session_diagnostic(", 1)[1].split("const PROJECT_SOURCE", 1)[0]
        self.assertIn("if failed.mark_unknown()", latch)
        report = source.split("fn report_failure(&self)", 1)[1].split("pub(super) fn attach", 1)[0]
        self.assertNotIn("installed_session_snapshot", report)
        self.assertNotIn("session_wait", report)
        self.assertNotIn("session_fail", report)
        self.assertNotIn("session_reply_rejection", report)
        self.assertNotIn("session_capability_rejection", report)
        encoder = source.split("fn failure_pair(", 1)[1].split("fn assert_failure_pair_contract", 1)[0]
        self.assertIn("diagnostic.step == step", encoder)
        self.assertIn("diagnostic.evaluations > 128", encoder)
        self.assertIn("index >= 64", encoder)
        self.assertIn("bytes.get_mut(*length..end)?", encoder)
        self.assertNotIn("format!", encoder)
        tick = source.split("fn session_tick(", 1)[1].split("fn session_dom(", 1)[0]
        self.assertIn("if r.evaluations>=128", tick)
        self.assertIn("SessionRejection::EvaluationBudget", tick)
        self.assertIn("Ok(Some(wait))=>{self.session_wait(&mut r,wait);return;}", tick)
        self.assertIn("match self.session_native_ready(&r,action,&snapshot)", tick)
        self.assertIn("Err(refusal)=>{self.session_fail_with_assessment(&mut r,refusal);return;}", tick)
        self.assertIn("r.evaluations+=1", tick)
        # Exact source correspondence preserves priority, not executed Rust/native evidence.
        ready = source.split("fn session_native_ready(", 1)[1].split("fn session_accept_action(", 1)[0]
        self.assertEqual(ready.strip(), '''&self, r: &Record, action: SA, snapshot: &InstalledSessionSnapshot) -> Result<Option<SessionWait>,SessionRefusal> {
        let s = &r.session;
        if snapshot.unknown { return Err(SessionRejection::UnknownNativeSnapshot.into()); }
        if snapshot.lost { return Err(SessionRejection::LostNativeSnapshot.into()); }
        if !snapshot.bound { return Err(SessionRejection::UnboundNativeSnapshot.into()); }
        if snapshot.status["capability"]["available"] != true {
            return Err(session_capability_rejection(snapshot.status["capability"]["reason"].as_str()).into());
        }
        for index in 1..10 {
            let extra_context = action == SA::Open && index == SessionCommand::Context.index();
            let expected = session_action_command(action).is_some_and(|command| command.index() == index) || extra_context;
            let stale = matches!(action,SA::Stale("save")) && index == SessionCommand::Commit.index()
                || matches!(action,SA::Stale("bind")) && index == SessionCommand::Bind.index();
            let delta = s.requests[index].checked_sub(s.base_requests[index]).ok_or(SessionRejection::RequestCounterUnderflow)?;
            if delta > u8::from(expected || stale) { return Err(SessionRejection::RequestCounterSurplus.into()); }
            if expected && delta == 0 { return Ok(Some(SessionWait::RequestNotSeen)); }
            if s.returns[index] < s.requests[index] { return Ok(Some(SessionWait::ReplyPending)); }
            if expected {
                if let Some(refusal) = session_reply_refusal(index, s.requests[index], s.returns[index], s.base_requests[index], &s.replies[index]) { return Err(refusal); }
            }
            if stale && delta != 0 && !matches!(s.replies[index].error.as_deref(),Some("asset_invalid_request"|"assessment_context_stale")) { return Err(SessionRejection::StaleReplyContract.into()); }
        }
        if !snapshot.settled { return Ok(Some(SessionWait::OwnerUnsettled)); }
        let op = &snapshot.status["operation"];
        let stable = match action {
            SA::Prepare(_,"save") | SA::Reassess(..) | SA::Keep | SA::ReviewRemoval(_) => op["phase"] == "preview" && op["settlement"] == "known",
            SA::Prepare(_,"missing" | "mismatch") => op["phase"] == "selected" && op["settlement"] == "known",
            SA::Choose(_,_,None) => op["phase"] == "selected" && op["settlement"] == "known",
            SA::Choose(_,_,Some(_)) | SA::Assign | SA::Remove | SA::CancelOperation | SA::ConfirmDiscard | SA::Platform(_) | SA::Open => op["phase"] == "idle" && op["settlement"] == "known",
            _ => true,
        };
        Ok((!stable).then_some(SessionWait::PhaseNotReady))
    }''')

    def test_session_gtk_first_rejection_waits_and_callbacks_preserve_original_custody(self):
        source = (SOURCE / "desktop/src-tauri/src/installed_shell_observation.rs").read_text()
        shell = (SOURCE / "desktop/src-tauri/src/shell.rs").read_text()
        def body(text, name):
            return text.split("fn " + name + "(", 1)[1].split("\n    }", 1)[0]
        admitting = source.split("fn session_file_wait_pending(", 1)[1].split("\n}", 1)[0]
        self.assertIn("if activating { SessionStep::ActivateFile(index) } else { SessionStep::SetFile(index) }", admitting)
        self.assertIn("actual == expected && pending == Some(Pending::Dom(expected))", admitting)
        waiting = body(source, "session_file_wait")
        self.assertIn("self.record()", waiting); self.assertNotIn("record_at", waiting)
        gate = "if !session_file_wait_pending(r.step,r.pending,index,activating) || self.failed.load(Ordering::SeqCst) { return; }"
        self.assertLess(waiting.index(gate), waiting.index("r.trace=(r.step,Boundary::Gtk)"))
        self.assertLess(waiting.index(gate), waiting.index("diagnostic.file_wait(wait,picker)"))
        helper = body(shell, "observed_session_file")
        borrowed = helper.split("let original = DIALOG.with(|book| {", 1)[1].split("        });", 1)[0]
        self.assertIn("map_err(|_| R::GtkDialogBook)", borrowed)
        self.assertIn("Err(R::GtkDialogOriginal)", borrowed)
        self.assertNotIn("q.", borrowed); self.assertNotIn(".facts()", borrowed)
        self.assertLess(helper.index("        });"), helper.index("Err(reason) => { q.session_file_failed(reason); return Err(()); }"))
        self.assertIn("q.session_file_wait(index, activating, W::GtkDialogAbsent, installed_observation::SessionPickerReadiness::NotSampled); return Ok(None);", helper)
        guards = ["gtk::is_initialized_main_thread()", "DIALOG.with", "context.upgrade()", "call.upgrade()",
                  "call.owner()", "owner.id != id", "owner.interrupted()", "let original_facts = call.facts()",
                  "if !original_facts", "q.session_file_dialog(id, index)?", "app.get_webview_window(MAIN_WINDOW)", "dialog.title()"]
        self.assertEqual([helper.index(guard) for guard in guards], sorted(helper.index(guard) for guard in guards))
        facts = helper.split("let original_facts =", 1)[1].split("if !original_facts", 1)[0]
        self.assertTrue(facts.rstrip().endswith("facts.refusal.is_none());"))
        self.assertNotIn("q.", facts)
        selecting = body(shell, "select_observed_session_file")
        activating = body(shell, "activate_observed_session_file")
        self.assertIn("observed_session_file(app, q, index, false)?", selecting)
        self.assertIn("observed_session_file(app, q, index, true)?", activating)
        self.assertEqual(selecting.count("dialog.set_filename(&path)"), 1)
        self.assertLess(selecting.index("q.session_file_selection(id, index)?"), selecting.index("dialog.set_filename(&path)"))
        self.assertIn("if !dialog.set_filename(&path) { q.session_file_failed(R::GtkSelectionSetter); return Err(()); }", selecting)
        insensitive = "if !button.is_sensitive() { q.session_file_wait(index, true, W::GtkActionInsensitive, picker); return Ok(false); }"
        self.assertLess(activating.index(insensitive), activating.index("q.session_file_activation(id, index)?"))
        self.assertLess(activating.index("q.session_file_activation(id, index)?"), activating.index("button.emit_clicked()"))
        self.assertEqual(activating.count("button.emit_clicked()"), 1)
        self.assertNotIn(".set_filename(", activating)
        self.assertNotIn(".filename(", selecting + activating)
        self.assertNotIn(".response(", selecting + activating); self.assertNotIn(".begin_response(", selecting + activating)
        self.assertEqual(shell.count("dialog.filename()"), 1)
        response = shell.split("entry.response = Some(dialog.connect_response(move |dialog, response| {", 1)[1].split("}));", 1)[0]
        self.assertEqual(response.count("let path = native_path(dialog, &call);"), 1)
        self.assertIn("q.session_file_filename(observed_id,path.as_ref().ok().map(PathBuf::as_path))", response)
        self.assertLess(response.index("let path = native_path(dialog, &call);"), response.index("q.session_file_filename("))
        self.assertLess(response.index("q.session_file_filename("), response.index("call.selected_path(path)"))
        for name in ("session_file_failed", "session_file_dialog", "session_file_selection", "session_file_activation",
                     "session_file_filename", "session_file_response", "session_file_returned", "native_destroyed", "native_released"):
            callback = body(source, name)
            self.assertEqual(callback.count("self.record_at(Boundary::Gtk)"), 1)
            self.assertIn("self.session_fail(&mut r,", callback)
            self.assertNotIn("self.session_file_failed(", callback); self.assertNotIn("self.record()", callback)
        for name in ("session_file_dialog", "session_file_selection", "session_file_activation"):
            callback = body(source, name)
            self.assertLess(callback.index("self.failed.load(Ordering::SeqCst)"), callback.index("Instant::now()>=self.end"))
            self.assertIn("if Instant::now()>=self.end { self.session_fail(&mut r,SessionRejection::GtkObserverEndpoint); return Err(()); }", callback)
        filename = body(source, "session_file_filename")
        reasons = ["GtkFilenameState", "GtkFilenameAbsent", "GtkFilenameDifferent", "file.picker.filename=true"]
        self.assertEqual([filename.index(reason) for reason in reasons], sorted(filename.index(reason) for reason in reasons))
        returned = body(source, "session_file_returned")
        self.assertIn("r.pending.take()!=Some(Pending::Dom(Step::Session(step))) || r.step!=Step::Session(step)", returned)
        self.assertEqual(returned.count(".activation_returned(result)"), 1)
        # First-failure diagnostics freeze, but original return/lifecycle bookkeeping
        # must still run after a failure. Only this exact counter update is guarded.
        diagnostic_only = """        if !self.failed.load(Ordering::SeqCst) {
            if let Some(diagnostic) = r.session.diagnostic.as_mut() { diagnostic.gtk_callbacks.returned(); }
        }
"""
        self.assertEqual(returned.count(diagnostic_only), 1)
        before_diagnostic, lifecycle = returned.split(diagnostic_only)
        self.assertNotIn("self.failed.load", before_diagnostic + lifecycle)
        self.assertLess(before_diagnostic.index("r.pending.take()"), before_diagnostic.index("let index=match step"))
        self.assertEqual(lifecycle, """        let Some(file)=r.session.files.last_mut().filter(|file| file.index==index) else {
            if result!=Ok(false) { self.session_fail(&mut r,SessionRejection::GtkReturnState); } return;
        };
        match result {
            Ok(false) if !file.picker.activated && (step!=SessionStep::SetFile(index) || !file.picker.selected)=>{},
            Ok(true) if step==SessionStep::SetFile(index) && file.picker.selected && !file.picker.activated=>r.step=Step::Session(SessionStep::ActivateFile(index)),
            Ok(true) if step==SessionStep::ActivateFile(index)=>{
                if !file.picker.activation_returned(result) { self.session_fail(&mut r,SessionRejection::GtkReturnState); return; } r.step=Step::Session(SessionStep::Capture(index));
            }, _=>self.session_fail(&mut r,SessionRejection::GtkReturnState),
        }""")
        self.assertNotIn(".responded", returned)
        self.assertLess(returned.index("r.pending.take()"), returned.index(".activation_returned(result)"))
        # Source ordering and parser contracts are not executed GTK/native finality.

    def test_diagnostic_and_close_failures_cannot_replace_an_active_owner_exception(self):
        class ProcessError(RuntimeError):
            def __init__(self):
                super().__init__("inert original")
                self.__dict__.update(dispatched=True, contained=True, cleanup_complete=True)
        value = installed_handoff(); value.pop("installed"); value["shell"] = {}
        argv = L.shell_argv(value, "project-paths")
        for fault in ("read", "clock", "format", "write", "close", "diagnostic-dispatch"):
            primary = ProcessError()
            with self.subTest(fault=fault), patch.multiple(L, _ROOT=L.root_path(value), _END=1000.0, _FAILED=False,
                    _COMMANDS=[], _OWNER=SimpleNamespace(ProcessError=ProcessError, run_owned=Mock(side_effect=primary))), \
                 patch.object(L, "_root_ids"), patch.object(L.time, "monotonic", return_value=100.0), \
                 patch.object(L, "_shell_labels_prepare", return_value=(41, "original")), \
                 patch.object(L, "_shell_labels_read", return_value=None) as reading, \
                 patch.object(L, "_shell_diagnostic_time", return_value=None) as clock, \
                 patch.object(L, "canonical", wraps=L.canonical) as formatting, \
                 patch.object(L, "_shell_owner_failure", wraps=L._shell_owner_failure) as diagnostic, \
                 patch.object(L, "_shell_log_capture") as raw_log, patch.object(L.os, "close") as closing, \
                 patch.object(L.sys, "stderr", new_callable=io.StringIO) as stream:
                failing = {"read": reading, "clock": clock, "format": formatting,
                           "close": closing, "diagnostic-dispatch": diagnostic}
                if fault == "write": stream.write = Mock(side_effect=OSError("inert diagnostic write"))
                else: failing[fault].side_effect = OSError("inert diagnosis failure")
                with self.assertRaises(ProcessError) as raised:
                    L.command("shell-project-paths", argv, maximum=60, shell_log=(value, "project-paths", "log"))
                self.assertIs(raised.exception, primary); self.assertTrue(L._FAILED)
                closing.assert_called_once_with(41); raw_log.assert_not_called()
                self.assertLessEqual(reading.call_count, 1)
                if fault == "read":
                    data = json.loads(stream.getvalue().split("=", 1)[1])
                    self.assertIsNone(data["labels"]); self.assertEqual(data["labelsReason"], "unavailable")

    def test_good_return_closes_once_and_close_loss_refuses_without_altering_capture(self):
        value = installed_handoff(); value.pop("installed"); value["shell"] = {}
        for synthetic, close_error in ((True, False), (True, True), (False, False)):
            argv = L.shell_argv(value, "positive") if synthetic else ["/inert-fixed-command"]
            result = subprocess.CompletedProcess(argv, 0, b"unchanged stdout", b"unchanged stderr")
            with self.subTest(synthetic=synthetic, close_error=close_error), \
                 patch.multiple(L, _ROOT=L.root_path(value), _END=1000.0, _FAILED=False,
                    _COMMANDS=[], _OWNER=SimpleNamespace(run_owned=Mock(return_value=result))), \
                 patch.object(L, "_root_ids"), patch.object(L, "_retain") as retained, \
                 patch.object(L.time, "monotonic", return_value=100.0), \
                 patch.object(L, "_shell_call_finished", wraps=L._shell_call_finished) as finishing, \
                 patch.object(L, "_shell_diagnostic_time", return_value=100.0) as clock, \
                 patch.object(L, "_shell_labels_prepare", return_value=(41, "original")) as preparation, \
                 patch.object(L, "_shell_labels_read") as reading, patch.object(L, "_shell_log_capture", return_value=b""), \
                 patch.object(L.os, "close") as closing, patch.object(L.sys, "stderr", new_callable=io.StringIO) as stream:
                if close_error: closing.side_effect = OSError("inert close loss")
                options = {"shell_log": (value, "positive", "log")} if synthetic else {}
                if close_error:
                    with self.assertRaises(OSError): L.command("shell-positive", argv, maximum=60, **options)
                    self.assertTrue(L._FAILED)
                else:
                    label = "shell-positive" if synthetic else "inert-command"
                    self.assertIs(L.command(label, argv, maximum=60, **options), result)
                    self.assertFalse(L._FAILED)
                self.assertEqual(preparation.call_count, int(synthetic))
                self.assertEqual(finishing.call_count, int(synthetic))
                self.assertEqual(clock.call_count, 2 if synthetic else 0)
                self.assertEqual(closing.call_count, int(synthetic)); reading.assert_not_called()
                self.assertEqual([call.args[1] for call in retained.call_args_list], [b"unchanged stdout", b"unchanged stderr"])
                self.assertEqual(stream.getvalue(), "")



# Deliberately fictional DATA below: no fixture construction, native execution,
# listener, archive import or runtime observation is performed by these tests.
GITHUB_FICTIONAL_CASES = {
    "github-connect-refresh": ("G-connect-refresh", 8, "none"),
    "github-real-ca-refusal": ("T2-root", 1, "tls-failed"),
    "github-wrong-name": ("T2-name", 1, "tls-failed"),
    "github-expired": ("T2-expired", 1, "tls-failed"),
    "github-ragged": ("T3-ragged", 1, "tls-failed"),
    "github-length": ("T3-length", 1, "response-invalid"),
    "github-chunk": ("T3-chunk", 1, "response-invalid"),
    "github-header-limit": ("T6-header", 1, "response-limit"),
    "github-body-limit": ("T6-body", 1, "response-limit"),
    "github-chunk-limit": ("T6-chunk-metadata", 1, "response-limit"),
    "github-unauthorized": ("T6-unauthorized", 1, "unauthorized"),
    "github-rate": ("T6-rate-expiry", 1, "response-invalid"),
    "github-identity": ("T6-target", 4, "target-changed"),
    "github-redirect": ("T6-redirect", 1, "response-invalid"),
    "github-ambient-fixed": ("T4-ambient-fixed", 4, "none"),
    "github-ambient-no-rescue": ("T4-ambient-no-rescue", 1, "tls-failed"),
    "github-handshake-deadline": ("T5-handshake", 1, "query_timeout"),
    "github-header-deadline": ("G-header-withhold", 1, "query_timeout"),
    "github-body-deadline": ("T5-read", 1, "query_timeout"),
    "github-cancel": ("T5-read", 1, "cancelled"),
    "github-quit": ("T5-read", 1, "cancelled"),
    "github-unknown": ("T5-read", 1, "cleanup_unknown"),
}


def github_handoff_data():
    value = installed_handoff()
    installed = value.pop("installed")
    value["shell"] = {"githubReadOnly": L.shell_github_selection(),
                      "rosterSha256": "d" * 64, "producerAttempt": "1", "artifactId": "17",
                      "acceptedU": installed["acceptedU"]}
    return value


def github_map_data():
    """Synthetic distinct private inodes, unchanged synthetic OS map aliases."""
    maps = {}
    roles = ("python", "libssl.so.3", "libcrypto.so.3", "ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6")
    for profile_index, profile in enumerate(("N", "D-R", "D-S")):
        maps[profile] = {}
        for index, name in enumerate(roles):
            private = name in roles[:3]
            relative = "python/bin/python3" if name == "python" else "python/lib/" + name
            paths = [str(L.PREFIX / L.SHELL_GITHUB_PAYLOADS[profile]["manifestSha256"] / relative)] if private else sorted(
                [directory + "/" + name for directory in L.DEFAULT_LIBRARY_DIRS[:2]]
                + (["/lib64/" + name] if name == "ld-linux-x86-64.so.2" else []))
            maps[profile][name] = {"paths": paths, "deviceMajor": 8, "deviceMinor": 2,
                                   "inode": 1000 + 100 * profile_index + index if private else 100 + index}
    return maps


def github_fixture_data(value):
    namespace = fixture_namespace_data(value)
    namespace["children"] = ["github-project"]
    namespace["identity"][5] = 3
    nodes = {}
    for index, (name, mode, owners, body) in enumerate((
        (".", stat.S_IFDIR | 0o700, (1001, 1001), None),
        ("app", stat.S_IFDIR | 0o555, (0, 0), None),
        ("app/build.gradle.kts", stat.S_IFREG | 0o444, (0, 0), L.SHELL_PROJECT_SOURCE),
        ("version.properties", stat.S_IFREG | 0o600, (1001, 1001), L.SHELL_PROJECT_VERSION),
    )):
        nodes[name] = {"identity": [1, 30 + index, mode, *owners,
                                   3 if name == "." else 2 if body is None else 1,
                                   4096 if body is None else len(body), 11, 11]}
        if body is not None:
            nodes[name].update(size=len(body), sha256=hashlib.sha256(body).hexdigest())
    return {"schema": "installed-github-project-v1", "sourceSha": value["sourceSha"],
            "runId": value["runId"], "attempt": value["attempt"],
            "project": str(L.shell_fixture_root(value) / "github-project"), "namespace": namespace, "nodes": nodes}


def github_receipt_data(case, expected=None):
    expected = github_map_data() if expected is None else expected
    script, connections, reason = GITHUB_FICTIONAL_CASES[case]
    role = "D-R" if case in ("github-real-ca-refusal", "github-ambient-no-rescue") else "D-S"
    manifest = L.SHELL_GITHUB_PAYLOADS[role]["manifestSha256"]
    active = case in ("github-cancel", "github-quit", "github-unknown")
    deadline = case in ("github-handshake-deadline", "github-header-deadline", "github-body-deadline")
    ambient = case in ("github-ambient-fixed", "github-ambient-no-rescue")
    refused = case in ("github-real-ca-refusal", "github-wrong-name", "github-expired", "github-ambient-no-rescue")
    handshake = case == "github-handshake-deadline"
    requests = 0 if refused or handshake else connections
    reads = 2 if case == "github-connect-refresh" else 1
    streaming = {
        "github-header-limit": [40630], "github-body-limit": [262215], "github-chunk-limit": [35803],
        "github-unauthorized": [99], "github-rate": [175], "github-identity": [95, 222, 102, 222],
        "github-redirect": [136],
    }
    reply = streaming.get(case, [0 if refused or handshake or case == "github-header-deadline" else 128] * connections)
    notify = connections if case in streaming or case in (
        "github-connect-refresh", "github-length", "github-chunk", "github-ambient-fixed") else 0
    completion = {"bytes": 1, "eof": True, "closed": True, "primaryEmpty": True,
                  "primaryUnexpected": 0, "primaryClosed": True}
    terminal = {"schemaVersion": 1, "scope": "github-installed-tls-peer-v1", "case": script,
        "installedCase": case, "ownerTag": "0123456789abcdef", "manifestSha256": manifest,
        "peerSha256": L.SHELL_GITHUB_PEER_PINS["github_tls_peer.py"][1], "primaryPort": 18443,
        "state": "finished", "status": "passed", "code": None, "connections": connections,
        "handshakes": requests, "requests": requests, "decryptedBytes": requests * 180,
        "authBytes": requests * len(b"Bearer INERT_NOT_A_CREDENTIAL"), "closeNotify": notify,
        "tlsRefused": refused, "wireReadBytes": [512] * connections,
        "wireWriteBytes": [0 if handshake else max(512, count) for count in reply],
        "replyBytes": reply, "allSocketsClosed": True, "completion": completion}
    if active or deadline or ambient:
        terminal.update(sni=connections, phase="handshake" if handshake else "headers" if case == "github-header-deadline"
                        else "read" if active or deadline else "finished", withheldWireBytes=512 if handshake else 0,
                        bodyBytes=7 if case == "github-body-deadline" else 1 if active else 0,
                        incompleteBody=active or case == "github-body-deadline",
                        clientStop="tcp-eof" if active or deadline else None,
                        progressCount=2 if active or deadline else 0, dnsQuestions=0, dnsA=0, dnsAAAA=0, dnsReplies=0)
        completion.update(proxy={"empty": True, "unexpected": 0, "closed": True} if ambient else None,
                          dnsEmpty=None, dnsClosed=None)
    else:
        terminal["replyStops"] = ["none"] * connections
        completion["redirect"] = {"empty": True, "unexpected": 0, "closed": True} if case == "github-redirect" else None
    peer = {key: True for key in ("acquisitionJoined", "spawned", "waited", "exitSuccess", "stdoutJoined", "stderrJoined",
                                  "stdoutEof", "stderrEof", "ready", "settled", "withinEndpoint", "protocolChecked")}
    peer.update({key: False for key in ("stopAttempted", "stdoutOverflow", "stderrOverflow")})
    peer.update(exitCode=0, stdoutBytes=8192, stderrBytes=0, terminal=terminal,
                control={**{key: True for key in ("acquired", "started", "joined", "writeComplete", "shutdownComplete",
                                                  "productSettled", "withinEndpoint", "released")}, "failed": False})
    outcomes = []
    for index in range(0 if active else reads):
        positive = reason == "none"
        outcomes.append({"revision": index + 1, "sessionId": "github-session-1", "projectId": "fictional-project",
            "target": "owner/app", "sessionState": "connected" if positive else "failed",
            "kind": "connect" if index == 0 else "refresh", "phase": "settled",
            "reason": "network-unavailable" if deadline else reason,
            "facts": ["observed" if positive else "unavailable"] * 3, "accountId": "11" if positive else None,
            "repositoryId": "22" if positive else None, "workflowRows": 4 if positive else 0})
    rows = [{"role": name, "path": row["paths"][0],
             **{key: row[key] for key in ("deviceMajor", "deviceMinor", "inode")}}
            for name, row in sorted(expected[role].items())]
    originals = [{"operationId": "github-read-" + str(index + 1), "manifestSha256": manifest,
                  "receiptKind": "native-error" if active or deadline else "typed-outcome", "reason": reason,
                  "terminal": True, "unknownLatched": case == "github-unknown",
                  "firstError": reason if active or deadline else None, "originalObserverJoined": True,
                  "nativeSettled": True, "environmentClear": True, "maps": deepcopy(rows),
                  "cleanupWithinOriginalEndpoint": True, "elapsedMs": 10500 if deadline else 100}
                 for index in range(reads)]
    return {"schemaVersion": 1, "fixture": "github-readonly-installed-v1", "case": case, "sourceCommit": "a" * 40,
            "normalManifestSha256": L.M, "productManifestSha256": manifest, "protocolSha256": L.Q,
            "peerSha256": L.SHELL_GITHUB_PEER_PINS["github_tls_peer.py"][1],
            "project": {"cancelSettled": True, "registered": True, "snapshot": True},
            "nativeSession": {"connect": 1, "refresh": reads - 1,
                "disconnect": 0 if case in ("github-quit", "github-unknown") else 1,
                "retainedStatus": not active, "runningObserved": active, "outcomes": outcomes,
                "cleared": case not in ("github-quit", "github-unknown"),
                "unknownRetained": case == "github-unknown", "tokenFieldCleared": True},
            "originals": originals, "peer": peer,
            "quit": {"originalsFinal": True, "relayJoined": True, "gtkSettled": True, "exit": True},
            "notProven": ["normal-resolver-withholding", "real-stalled-tcp-connect"]}


def github_capture_data(case, receipt):
    return (b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n"
            b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n"
            + b"MRK_INSTALLED_SHELL_GITHUB_READONLY=" + L.canonical(receipt)
            + b"MRK_INSTALLED_SHELL_OBSERVATION=" + case.encode("ascii") + b"-verified\n")


def github_data_set(value, path, replacement):
    for name in path[:-1]:
        value = value[name]
    value[path[-1]] = replacement


def github_closed_observation_data():
    value, maps = github_handoff_data(), github_map_data()
    cases = {case: {"case": case, "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True,
                    "maps": [], "githubReadOnly": github_receipt_data(case, maps)} for case in GITHUB_FICTIONAL_CASES}
    project = github_fixture_data(value)
    def pin(raw):
        return {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    # The CI parser consumes export pins after lifecycle finality, not material
    # bytes. These fictional pins do not claim to pass the lifecycle producer.
    material_pin, fixture_pin = pin(b"fictional material capture\n"), pin(L.canonical(project))
    fixture = {"project": project["project"], "namespace": project["namespace"], "unchanged": True,
               "sourceSha256": hashlib.sha256(L.SHELL_PROJECT_SOURCE).hexdigest(),
               "versionSha256": hashlib.sha256(L.SHELL_PROJECT_VERSION).hexdigest(),
               "releaseConfigCreated": False, "sourceSha": value["sourceSha"],
               "before": fixture_pin, "after": deepcopy(fixture_pin)}
    github = {"selection": L.shell_github_selection(), "expectedMaps": maps,
              "materials": {"before": material_pin, "after": deepcopy(material_pin)}, "fixture": fixture,
              "casesCapture": pin(L.canonical(cases)), "normalDestinationAction": False, "normalTransportPositive": False,
              "remainingCoverage": ["normal-resolver-withholding", "real-stalled-tcp-connect",
                                    "separately-approved-normal-destination-negative"]}
    captures = {"shell-cases.json": github["casesCapture"]}
    for phase in ("before", "after"):
        captures["shell-github-materials-" + phase + ".json"] = material_pin
        captures["shell-github-project-" + phase + ".json"] = fixture_pin
    files = [{"path": "lifecycle-" + name, **captures.get(name, pin(b"fictional export\n"))}
             for name in sorted(L.public_files(value) | {"client.stdout", "client.stderr"})]
    return {"state": "installed-github-readonly-synthetic-observed", "productQualified": False,
            "packageLifecycleQualified": False, "shellPackageBuilt": False, "sourceSha": value["sourceSha"],
            "consumerAttempt": value["attempt"], "unit": L.root_path(value).name + ".service",
            "githubReadOnly": github, "cases": cases, "files": files}


class InstalledGitHubReadOnlyDataContracts(unittest.TestCase):
    """Closed fictional records exercise parsers, not TLS/GTK/process finality."""

    def test_exact_selection_keeps_legacy_twenty_and_normal_action_separate(self):
        value = github_handoff_data()
        self.assertEqual(L.shell_cases(value), tuple(GITHUB_FICTIONAL_CASES))
        self.assertEqual(L.SHELL_GITHUB_CASE_DATA, GITHUB_FICTIONAL_CASES)
        self.assertEqual(len(L.shell_cases(value)), 22)
        self.assertEqual(L.shell_observers(value), L.shell_cases(value))
        self.assertEqual({name for name in L.shell_cases(value) if L.shell_github_role(name) == "D-R"},
                         {"github-real-ca-refusal", "github-ambient-no-rescue"})
        legacy = deepcopy(value); legacy["shell"].pop("githubReadOnly")
        self.assertEqual(L.shell_cases(legacy), L.SHELL_CASES)
        self.assertEqual(len(L.shell_cases(legacy)), 20)
        self.assertEqual(L.shell_public_limit(legacy), 165)
        self.assertEqual(L.shell_fixture_children(value), ("github-project",))
        for case in ("normal", "github-normal-negative", "github-other"):
            with self.subTest(case=case), self.assertRaises(L.Refused):
                L.shell_github_role(case)
        changes = (
            (("normalDestinationAction",), True), (("normalDestinationAction",), 0),
            (("cases",), list(GITHUB_FICTIONAL_CASES) + ["github-normal-negative"]),
            (("payloads", "D-S", "manifestSha256"), L.M),
            (("peerSources", 0, "size"), True), (("profile",), "caller-profile"),
            (("endpoint",), "https://example.invalid"),
        )
        for path, replacement in changes:
            bad = deepcopy(value); github_data_set(bad["shell"]["githubReadOnly"], path, replacement)
            with self.subTest(path=path), self.assertRaises(L.Refused):
                L.shell_cases(bad)
        first = L.shell_github_selection(); first["payloads"]["N"]["manifestSha256"] = "f" * 64
        self.assertEqual(L.shell_github_selection()["payloads"]["N"]["manifestSha256"], L.M)

    def test_public_roster_argv_and_only_two_ambient_decoy_environments(self):
        value = github_handoff_data()
        files = L.public_files(value)
        self.assertEqual(len(files), 135)
        self.assertEqual(L.shell_public_limit(value), 135)
        self.assertEqual(len(files | {"client.stdout", "client.stderr"}), 137)
        self.assertTrue({"shell-github-materials-before.json", "shell-github-materials-after.json",
                         "shell-github-project-before.json", "shell-github-project-after.json",
                         "shell-cases.json"} <= files)
        self.assertNotIn("shell-normal-control.json", files)
        self.assertFalse(any(name.startswith(("shell-positive", "shell-tools", "shell-offline")) for name in files))
        self.assertEqual([phase for phase in L.root_phases(value) if phase.startswith("shell-")],
                         ["shell-" + name for name in GITHUB_FICTIONAL_CASES])
        proxy = {"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"}
        trust = {"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"}
        decoys = proxy | trust | {"SSLKEYLOGFILE"}
        baseline = L.shell_environment(value, "github-connect-refresh")
        self.assertTrue(set(baseline).isdisjoint(decoys | {"GH_TOKEN", "GITHUB_TOKEN", "PYTHONPATH"}))
        for case in GITHUB_FICTIONAL_CASES:
            with self.subTest(case=case):
                environment = L.shell_environment(value, case)
                self.assertEqual(L.shell_argv(value, case)[-2:], [str(L.root_path(value) / "shell-observer"), case])
                ambient = case in ("github-ambient-fixed", "github-ambient-no-rescue")
                self.assertEqual(set(environment), set(baseline) | (decoys if ambient else set()))
                if ambient:
                    self.assertEqual({environment[key] for key in proxy}, {"http://127.0.0.1:18888"})
                    self.assertEqual({environment[key] for key in trust},
                                     {str(L.root_path(value) / "github-peer/github_tls/root-ca.pem")})
                    self.assertEqual(environment["SSLKEYLOGFILE"], str(L.root_path(value) / ("shell-" + case + "-keylog.log")))
        with self.assertRaises(L.Refused):
            L.shell_argv(value, "github-normal-negative")

    def test_fixture_closed_four_node_data_rejects_drift_aliases_and_release_outputs(self):
        value = github_handoff_data()
        data = github_fixture_data(value); raw = L.canonical(data)
        result = L.shell_github_fixture(value, raw, raw)
        self.assertTrue(result["unchanged"]); self.assertFalse(result["releaseConfigCreated"])
        changes = (
            (("sourceSha",), "b" * 40), (("namespace", "children"), ["github-project", "release"]),
            (("nodes", ".", "identity", 3), 0), (("nodes", "app", "identity", 2), stat.S_IFLNK | 0o555),
            (("nodes", "app", "identity", 1), data["namespace"]["identity"][1]),
            (("nodes", "version.properties", "identity", 5), 2),
            (("nodes", "version.properties", "identity", 6), True),
            (("nodes", "version.properties", "size"), True),
            (("nodes", "app/build.gradle.kts", "sha256"), "f" * 64),
            (("nodes", "release-config.json"), {"identity": [1] * 9}),
        )
        for path, replacement in changes:
            bad = deepcopy(data); github_data_set(bad, path, replacement); encoded = L.canonical(bad)
            with self.subTest(path=path), self.assertRaises(L.Refused):
                L.shell_github_fixture(value, encoded, encoded)
        after = deepcopy(data); after["nodes"]["version.properties"]["identity"][8] += 1
        for before_raw, after_raw in ((raw, L.canonical(after)), (raw, raw + b"\n"), (raw.decode(), raw)):
            with self.subTest(after=type(after_raw)), self.assertRaises(L.Refused):
                L.shell_github_fixture(value, before_raw, after_raw)

    def test_three_map_roles_keep_n_d_originals_distinct_and_os_aliases_unchanged(self):
        maps = github_map_data()
        self.assertIs(L.shell_github_maps(maps), maps)
        mutations = (
            (("D-S", "python", "paths"), maps["N"]["python"]["paths"]),
            (("D-S", "python", "inode"), maps["N"]["python"]["inode"]),
            (("D-R", "libssl.so.3", "inode"), True),
            (("D-R", "libc.so.6", "inode"), 999999),
            (("N", "libm.so.6", "paths"), ["/caller/libm.so.6"]),
        )
        for path, replacement in mutations:
            bad = deepcopy(maps); github_data_set(bad, path, replacement)
            with self.subTest(path=path), self.assertRaises(L.Refused):
                L.shell_github_maps(bad)
        bad = deepcopy(maps); bad["normal"] = bad.pop("N")
        with self.assertRaises(L.Refused):
            L.shell_github_maps(bad)

    def test_final_loader_correlates_full9_with_the_original_seven_field_layout(self):
        material, final = {"payloads": {}}, {"bindings": {}, "entryObjects": ["libssl.so.3", "libcrypto.so.3", "libc.so.6"]}
        for index, role in enumerate(("D-R", "D-S")):
            root = L.PREFIX / L.SHELL_GITHUB_PAYLOADS[role]["manifestSha256"]
            tree = {}
            for offset, name in enumerate(("", "python", "python/bin", "python/lib")):
                tree[name] = {"identity": [1, 100 + index * 100 + offset, stat.S_IFDIR | 0o555, 0, 0, 2, 4096, 17, 18]}
            present = ("python/bin/python3", "python/lib/libssl.so.3", "python/lib/libcrypto.so.3")
            absent = ("python/lib/glibc-hwcaps", "python/lib/libc.so.6",
                      *(prefix + name for prefix in ("", "python/", "python/bin/")
                        for name in ("pyvenv.cfg", "python3._pth", "pybuilddir.txt")))
            for offset, name in enumerate(present):
                tree[name] = {"identity": [1, 150 + index * 100 + offset, stat.S_IFREG | 0o444, 0, 0, 1, 16, 17, 18],
                              "size": 16, "sha256": "b" * 64}
            material["payloads"][role] = tree
            for name in (*present, *absent):
                path = str(root / name)
                row = {"path": path, "selectedPath": path, "links": [],
                       "ancestry": {str(root / ("" if str(parent) == "." else parent.as_posix())):
                                    tree["" if str(parent) == "." else parent.as_posix()]["identity"][:5]
                                    for parent in Path(name).parents}}
                if name in present:
                    row.update(identity=[tree[name]["identity"][position] for position in (0, 1, 2, 5, 6, 7, 8)],
                               size=16, sha256="b" * 64)
                else:
                    row.update(absent=True, absentAt=path)
                final["bindings"][path] = row
        self.assertIsNone(L._shell_github_closed_loader(material, final))
        path = str(L.PREFIX / L.SHELL_GITHUB_PAYLOADS["D-S"]["manifestSha256"] / "python/bin/python3")
        for replacement in (material["payloads"]["D-S"]["python/bin/python3"]["identity"],
                            [1, 999, stat.S_IFREG | 0o444, 1, 16, 17, 18]):
            bad = deepcopy(final); bad["bindings"][path]["identity"] = replacement
            with self.subTest(identity=replacement), self.assertRaises(L.Refused):
                L._shell_github_closed_loader(material, bad)
        bad = deepcopy(final); bad["bindings"][path]["links"] = [{"path": path, "target": "/replacement"}]
        with self.assertRaises(L.Refused):
            L._shell_github_closed_loader(material, bad)

    def test_all_twenty_two_fictional_native_receipts_and_marker_records_parse(self):
        maps = github_map_data()
        for case in GITHUB_FICTIONAL_CASES:
            with self.subTest(case=case):
                receipt = github_receipt_data(case, maps)
                self.assertEqual(L.shell_github_receipt(L.canonical(receipt), case, maps), receipt)
                result = L.shell_github_result(github_capture_data(case, receipt), b"", case, 0, maps)
                self.assertEqual(result["githubReadOnly"], receipt)
                self.assertEqual(result["maps"], [])  # D maps stay nested under each original.
                self.assertNotIn("qualified", result)

    def test_native_receipt_rejects_relabelled_maps_errors_ui_and_unjoined_originals(self):
        variants = (
            ("github-connect-refresh", ("schemaVersion",), True),
            ("github-connect-refresh", ("endpoint",), "https://example.invalid"),
            ("github-connect-refresh", ("productManifestSha256",), L.M),
            ("github-connect-refresh", ("protocolSha256",), "f" * 64),
            ("github-connect-refresh", ("peerSha256",), "f" * 64),
            ("github-connect-refresh", ("project", "registered"), False),
            ("github-connect-refresh", ("quit", "relayJoined"), False),
            ("github-connect-refresh", ("originals", 1, "operationId"), "github-read-1"),
            ("github-connect-refresh", ("originals", 0, "operationId"), "github-read-18446744073709551616"),
            ("github-connect-refresh", ("originals", 0, "originalObserverJoined"), False),
            ("github-connect-refresh", ("originals", 0, "nativeSettled"), False),
            ("github-connect-refresh", ("originals", 0, "environmentClear"), False),
            ("github-connect-refresh", ("originals", 0, "firstError"), "cancelled"),
            ("github-connect-refresh", ("originals", 0, "elapsedMs"), True),
            ("github-connect-refresh", ("originals", 0, "maps", 0, "inode"), True),
            ("github-connect-refresh", ("nativeSession", "outcomes", 1, "sessionId"), "github-session-2"),
            ("github-connect-refresh", ("nativeSession", "outcomes", 1, "revision"), 1),
            ("github-identity", ("nativeSession", "outcomes", 0, "facts"), ["observed", "unavailable", "unavailable"]),
            ("github-identity", ("nativeSession", "outcomes", 0, "accountId"), "11"),
            ("github-unknown", ("nativeSession", "unknownRetained"), False),
            ("github-unknown", ("originals", 0, "unknownLatched"), False),
            ("github-unknown", ("originals", 0, "reason"), "none"),
            ("github-cancel", ("originals", 0, "receiptKind"), "typed-outcome"),
            ("github-quit", ("originals", 0, "firstError"), None),
            ("github-body-deadline", ("originals", 0, "cleanupWithinOriginalEndpoint"), False),
        )
        maps = github_map_data()
        for case, path, replacement in variants:
            bad = github_receipt_data(case, maps); github_data_set(bad, path, replacement)
            with self.subTest(case=case, path=path), self.assertRaises(L.Refused):
                L.shell_github_receipt(L.canonical(bad), case, maps)
        receipt = github_receipt_data("github-real-ca-refusal", maps)
        for row in receipt["originals"][0]["maps"]:
            if row["role"] == "python":
                normal = maps["N"]["python"]
                row.update(path=normal["paths"][0], inode=normal["inode"])
        with self.assertRaises(L.Refused):
            L.shell_github_receipt(L.canonical(receipt), "github-real-ca-refusal", maps)

    def test_original_deadline_is_ten_seconds_with_only_its_two_second_cleanup(self):
        maps = github_map_data()
        for case in ("github-handshake-deadline", "github-header-deadline", "github-body-deadline"):
            for elapsed in (10000, 11999, 9999, 12000, True):
                receipt = github_receipt_data(case, maps); receipt["originals"][0]["elapsedMs"] = elapsed
                with self.subTest(case=case, elapsed=elapsed):
                    if type(elapsed) is int and 10000 <= elapsed < 12000:
                        L.shell_github_receipt(L.canonical(receipt), case, maps)
                    else:
                        with self.assertRaises(L.Refused):
                            L.shell_github_receipt(L.canonical(receipt), case, maps)

    def test_peer_requires_original_wait_eofs_control_and_real_case_counters(self):
        variants = (
            ("github-connect-refresh", ("waited",), False),
            ("github-connect-refresh", ("stdoutEof",), False),
            ("github-connect-refresh", ("stderrJoined",), False),
            ("github-connect-refresh", ("withinEndpoint",), False),
            ("github-connect-refresh", ("protocolChecked",), 1),
            ("github-connect-refresh", ("stopAttempted",), True),
            ("github-connect-refresh", ("stdoutBytes",), 8193),
            ("github-connect-refresh", ("stderrBytes",), 1),
            ("github-connect-refresh", ("control", "joined"), False),
            ("github-connect-refresh", ("control", "productSettled"), False),
            ("github-connect-refresh", ("control", "released"), False),
            ("github-connect-refresh", ("control", "failed"), True),
            ("github-connect-refresh", ("terminal", "authBytes"), 8 * 27),
            ("github-connect-refresh", ("terminal", "requests"), True),
            ("github-connect-refresh", ("terminal", "completion", "eof"), False),
            ("github-real-ca-refusal", ("terminal", "authBytes"), 1),
            ("github-redirect", ("terminal", "completion", "redirect", "unexpected"), 1),
            ("github-ambient-fixed", ("terminal", "completion", "proxy", "empty"), False),
            ("github-ambient-no-rescue", ("terminal", "dnsQuestions"), 1),
            ("github-handshake-deadline", ("terminal", "wireWriteBytes"), [1]),
            ("github-header-deadline", ("terminal", "phase"), "header"),
            ("github-body-deadline", ("terminal", "bodyBytes"), 6),
            ("github-cancel", ("terminal", "clientStop"), None),
            ("github-quit", ("terminal", "progressCount"), 1),
        )
        for case, path, replacement in variants:
            peer = github_receipt_data(case)["peer"]; github_data_set(peer, path, replacement)
            with self.subTest(case=case, path=path), self.assertRaises(L.Refused):
                L.shell_github_peer_receipt(peer, case)
        peer = github_receipt_data("github-connect-refresh")["peer"]
        peer["terminal"]["ownerTag"] = "fedcba9876543210"
        self.assertIs(L.shell_github_peer_receipt(peer, "github-connect-refresh"), peer)
        # A different valid correlation tag is not another authority or owner.

    def test_streaming_stop_cannot_claim_a_response_boundary_it_did_not_reach(self):
        for case, minimum in (("github-header-limit", 32768), ("github-chunk-limit", 33143),
                              ("github-unauthorized", 80), ("github-rate", 156), ("github-redirect", 117)):
            peer = github_receipt_data(case)["peer"]
            peer["terminal"].update(replyStops=["reply:broken-pipe"], closeNotify=0,
                                    replyBytes=[minimum], wireWriteBytes=[minimum])
            self.assertIs(L.shell_github_peer_receipt(peer, case), peer)
            peer["terminal"]["replyBytes"][0] -= 1
            with self.subTest(case=case), self.assertRaises(L.Refused):
                L.shell_github_peer_receipt(peer, case)
        peer = github_receipt_data("github-identity")["peer"]
        peer["terminal"]["replyStops"][0] = "notify:broken-pipe"
        with self.assertRaises(L.Refused):
            L.shell_github_peer_receipt(peer, "github-identity")

    def test_stdout_requires_order_one_receipt_no_separate_d_maps_and_integer_exit(self):
        case, maps = "github-connect-refresh", github_map_data()
        raw = github_capture_data(case, github_receipt_data(case, maps))
        lines = raw.splitlines(keepends=True)
        bad_outputs = (b"".join(lines[:3] + lines[4:]), raw + lines[3],
                       b"".join([lines[1], lines[0], *lines[2:]]), raw.rstrip(b"\n"),
                       raw + b"MRK_INSTALLED_NATIVE_CHILD=[]\n")
        for stdout, stderr, code in [(value, b"", 0) for value in bad_outputs] + [
                (raw, b"MRK_INSTALLED_SHELL_OBSERVATION=failed\n", 0), (raw, b"", False), (raw, b"", 1)]:
            with self.subTest(code=code, length=len(stdout)), self.assertRaises(L.Refused):
                L.shell_github_result(stdout, stderr, case, code, maps)
        receipt = github_receipt_data(case, maps)
        for encoded in (L.canonical(receipt) + b"\n", json.dumps(receipt, indent=2).encode(), b"{}"):
            with self.subTest(raw=encoded[:20]), self.assertRaises(L.Refused):
                L.shell_github_receipt(encoded, case, maps)


class InstalledGitHubClosedExportDataContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Import at test execution only; no verifier, command or host observer is called.
        spec = importlib.util.spec_from_file_location(
            "github_closed_export_data", SOURCE / "desktop/tools/ci_ubuntu_publication.py")
        cls.CI = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.CI)

    def test_exact_137_fictional_export_records_bind_case_capture_and_fixture_pins(self):
        observed = github_closed_observation_data()
        self.assertEqual(len(observed["files"]), 137)
        self.assertIs(self.CI.shell_github_observation(observed, L), observed["githubReadOnly"])
        self.assertFalse(observed["productQualified"])
        self.assertFalse(observed["githubReadOnly"]["normalDestinationAction"])
        self.assertFalse(observed["githubReadOnly"]["normalTransportPositive"])

    def test_missing_duplicate_changed_or_qualified_copies_refuse(self):
        variants = (
            (("state",), "qualified"), (("productQualified",), True),
            (("packageLifecycleQualified",), True), (("shellPackageBuilt",), True),
            (("sourceSha",), "b" * 40), (("consumerAttempt",), 2),
            (("unit",), "mrk-ubuntu-native-10-3.service"),
            (("githubReadOnly", "normalDestinationAction"), 0),
            (("githubReadOnly", "normalTransportPositive"), True),
            (("githubReadOnly", "remainingCoverage"), []),
            (("githubReadOnly", "materials", "before", "sha256"), "f" * 64),
            (("githubReadOnly", "fixture", "releaseConfigCreated"), True),
            (("githubReadOnly", "fixture", "sourceSha256"), "f" * 64),
            (("githubReadOnly", "fixture", "project"), "/unbound/github-project"),
            (("githubReadOnly", "casesCapture", "sha256"), "f" * 64),
            (("files", 0, "path"), "lifecycle-unrelated.json"),
            (("files", 0, "size"), True),
            (("cases", "github-normal-negative"), {}),
            (("cases", "github-connect-refresh", "githubReadOnly", "sourceCommit"), "c" * 40),
        )
        for path, replacement in variants:
            observed = github_closed_observation_data(); github_data_set(observed, path, replacement)
            with self.subTest(path=path), self.assertRaises((L.Refused, self.CI.D.Refused)):
                self.CI.shell_github_observation(observed, L)
        for duplicate in (False, True):
            observed = github_closed_observation_data()
            if duplicate:
                observed["files"][-1] = deepcopy(observed["files"][0])
            else:
                observed["files"].pop()
            with self.subTest(duplicate=duplicate), self.assertRaises(self.CI.D.Refused):
                self.CI.shell_github_observation(observed, L)

    def test_canonical_case_copy_must_match_the_original_export_even_if_both_summary_pins_change(self):
        observed = github_closed_observation_data()
        capture = observed["githubReadOnly"]["casesCapture"]
        capture["sha256"] = "f" * 64
        row = next(row for row in observed["files"] if row["path"] == "lifecycle-shell-cases.json")
        row["sha256"] = capture["sha256"]
        with self.assertRaises(self.CI.D.Refused):
            self.CI.shell_github_observation(observed, L)

# Fictional DATA only. None of these helpers starts nft, a socket, a service,
# a product Child, or a compiler; they are not hosted boundary evidence.
GITHUB_BOUNDARY_FICTIONAL_CASES = ("github-dns-deadline", "github-connect-deadline")
GITHUB_BOUNDARY_FICTIONAL_META = {"version": "fictional", "release_name": "fictional", "json_schema_version": 1}


def github_boundary_handoff_data():
    value = github_handoff_data()
    value["shell"]["githubReadOnly"] = L.shell_github_selection("github-readonly-installed-normal-boundaries-v1")
    return value


def github_boundary_receipt_data(case, *, unconnected=False, ipv6=False):
    assert case in GITHUB_BOUNDARY_FICTIONAL_CASES
    maps, value = github_map_data(), github_boundary_handoff_data()
    receipt = github_receipt_data("github-handshake-deadline", maps)
    dns = case == "github-dns-deadline"
    receipt.update(case=case, productManifestSha256=L.M,
                   notProven=["real-stalled-tcp-connect"] if dns else ["normal-resolver-withholding"])
    original = receipt["originals"][0]
    original["manifestSha256"] = L.M
    original["maps"] = [{"role": name, "path": row["paths"][0],
                          **{key: row[key] for key in ("deviceMajor", "deviceMinor", "inode")}}
                         for name, row in sorted(maps["N"].items())]
    source = {"address": "127.0.0.2", "port": 40001, "questionId": 123, "questionType": 1}
    original["boundary"] = {
        "kind": "normal-dns" if dns else "normal-connect", "childPid": 42, "fd": 7,
        "inode": "7001", "uid": value["runnerUid"], "family": "ipv6" if ipv6 else "ipv4",
        "protocol": "udp" if dns else "tcp", "localAddress": source["address"] if dns else "10.0.0.2",
        "localPort": source["port"] if dns else 40002,
        "remoteAddress": ("0.0.0.0" if unconnected else "127.0.0.53") if dns else "140.82.112.3",
        "remotePort": (0 if unconnected else 53) if dns else 443, "state": ("07" if unconnected else "01") if dns else "02",
        "originalFdStable": True, "observedBeforeDeadline": True, "peerSource": deepcopy(source) if dns else None}
    if ipv6:
        original["boundary"].update(localAddress="2606:4700::1111", remoteAddress="2606:50c0:8000::154")
    if dns:
        terminal = receipt["peer"]["terminal"]
        terminal.update(case="G-dns-withhold", installedCase=case, manifestSha256=L.M, primaryPort=18553,
                        connections=0, handshakes=0, requests=0, decryptedBytes=0, authBytes=0, closeNotify=0,
                        tlsRefused=False, wireReadBytes=[], wireWriteBytes=[], replyBytes=[], sni=0, phase="dns",
                        withheldWireBytes=0, bodyBytes=0, incompleteBody=False, clientStop=None,
                        progressCount=2, dnsQuestions=2, dnsA=1, dnsAAAA=1, dnsReplies=0, dnsSource=source)
        terminal["completion"] = {"bytes": 1, "eof": True, "closed": True, "primaryEmpty": None, "primaryUnexpected": 0,
                                  "primaryClosed": None, "proxy": None, "dnsEmpty": True, "dnsClosed": True}
    else:
        receipt.update(peer=None, peerSha256=None)
    return receipt


def github_boundary_objects_data(value, case, *, post=False):
    """Independently specified fictional nft dialect/handles, never live output."""
    dns = case == "github-dns-deadline"
    table = "mrk_gnb_" + value["runId"] + "_" + value["attempt"] + ("_dns" if dns else "_connect")
    unit = "system.slice/mrk-ubuntu-native-" + value["runId"] + "-" + value["attempt"] + ".service"
    def equal(left, right):
        return {"match": {"op": "==", "left": left, "right": right}}
    def payload(protocol, field):
        return {"payload": {"protocol": protocol, "field": field}}
    scope = [equal({"meta": {"key": "skuid"}}, value["runnerUid"]),
             equal({"socket": {"key": "cgroupv2", "level": 2}}, unit)]
    rows = [{"table": {"family": "inet", "name": table}}]
    for name in (("dns_queries", "https_syns") if dns else ("https_syns",)):
        packets = 2 if post and (name == "dns_queries" or not dns) else 0
        rows.append({"counter": {"family": "inet", "table": table, "name": name,
                                  "packets": packets, "bytes": packets * (80 if dns else 60)}})
    rows.append({"chain": {"family": "inet", "table": table, "name": "output", "type": "route",
                           "hook": "output", "prio": -300, "policy": "accept"}})
    if dns:
        rows.append({"rule": {"family": "inet", "table": table, "chain": "output", "expr": deepcopy(scope) + [
            equal({"meta": {"key": "nfproto"}}, "ipv4"), equal(payload("ip", "daddr"), "127.0.0.53"),
            equal(payload("udp", "dport"), 53), {"counter": "dns_queries"},
            {"mangle": {"key": payload("udp", "dport"), "value": 18553}}]}})
    rows.append({"rule": {"family": "inet", "table": table, "chain": "output", "expr": deepcopy(scope) + [
        equal({"meta": {"key": "l4proto"}}, "tcp"), equal(payload("tcp", "dport"), 443),
        equal({"&": [payload("tcp", "flags"), ["fin", "syn", "rst", "ack"]]}, "syn"),
        {"counter": "https_syns"}, {"drop": None}]}})
    for handle, row in enumerate(rows, 1):
        next(iter(row.values()))["handle"] = handle
    return rows


def github_boundary_policy_data_fixture(value, case):
    receipt = github_boundary_receipt_data(case)
    installed = L._github_boundary_policy_objects(value, case, github_boundary_objects_data(value, case))
    post = L._github_boundary_policy_objects(value, case, github_boundary_objects_data(value, case, post=True))
    prefix = "github-boundary-" + ("dns" if case == "github-dns-deadline" else "connect")
    unit = L.root_path(value).name + ".service"
    domain = {"sourceSha": value["sourceSha"], "runId": value["runId"], "attempt": value["attempt"],
              "runnerUid": value["runnerUid"], "invocationId": "1" * 32, "unit": unit,
              "cgroupPath": "/sys/fs/cgroup/system.slice/" + unit,
              "cgroupIdentity": [1, 321, stat.S_IFDIR | 0o755, 0, 0, 2],
              "namespaces": {name: [4, index] for index, name in enumerate(("user", "pid", "net", "mnt"), 1)},
              "bootId": "11111111-2222-3333-4444-555555555555"}
    def protected(suffix, inode):
        return {"path": str(L.root_path(value) / "private" / (prefix + "-" + suffix)), "size": 1, "sha256": "e" * 64,
                "identity": [1, inode, stat.S_IFREG | 0o400, 0, 0, 1, 1, 10, 10]}
    absence = L._shell_github_pin(L.canonical({"nftables": [{"metainfo": GITHUB_BOUNDARY_FICTIONAL_META}]}))
    return {"schema": "installed-github-normal-boundary-policy-v1", "case": case,
            "profile": "github-readonly-installed-normal-boundaries-v1", "sourceSha": value["sourceSha"], "domain": domain,
            "intent": protected("intent.json", 501), "owned": protected("owned.json", 502),
            "installed": installed, "post": post,
            "productCommand": {"phase": "shell-" + case, "argv": L.shell_argv(value, case), "exitCode": 0, "timeoutSeconds": 60},
            "nativeBoundary": deepcopy(receipt["originals"][0]["boundary"]), "state": "removed-and-observed",
            "productOriginalsFinal": True, "noPriorWorkers": True, "absence": absence,
            "policySha256": hashlib.sha256(L.shell_github_boundary_policy(value, case)).hexdigest(),
            "faultHeldThroughOriginalFinality": True, "normalHttpRequests": False}


def github_boundary_closed_observation_data():
    """Fictional CI export shape; DOES NOT pass the root host/admission producer."""
    value, observed = github_boundary_handoff_data(), github_closed_observation_data()
    cases = {case: {"case": case, "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True, "maps": [],
                    "githubReadOnly": github_boundary_receipt_data(case)} for case in GITHUB_BOUNDARY_FICTIONAL_CASES}
    github = observed["githubReadOnly"]
    host = L._shell_github_pin(b"fictional host DATA, not admission\n")
    policies = {}
    captures = {"shell-cases.json": L._shell_github_pin(L.canonical(cases))}
    for case in GITHUB_BOUNDARY_FICTIONAL_CASES:
        proof = github_boundary_policy_data_fixture(value, case)
        pin = L._shell_github_pin(L.canonical(proof))
        policies[case] = {"capture": pin, "evidence": proof}
        prefix = "github-boundary-" + ("dns" if case == "github-dns-deadline" else "connect")
        captures[prefix + "-policy.json"] = pin
        captures[prefix + "-absence.stdout"] = proof["absence"]
    for phase in ("before", "after"):
        captures["shell-github-materials-" + phase + ".json"] = github["materials"][phase]
        captures["shell-github-project-" + phase + ".json"] = github["fixture"][phase]
        captures["github-boundary-host-" + phase + ".json"] = host
    github.update(selection=value["shell"]["githubReadOnly"], casesCapture=captures["shell-cases.json"],
                  normalDestinationAction=True, normalNetworkScope="normal-dns-and-scoped-https-acquisition-syns-only",
                  normalHttpRequests=False,
                  remainingCoverage=["current-twenty-two-synthetic-regressions", "separately-approved-normal-destination-negative"],
                  boundaries={"host": {"before": host, "after": deepcopy(host)}, "policies": policies,
                              "normalResolverWithholdingObserved": True, "realStalledTcpConnectObserved": True,
                              "rootUidAndCgroupScoped": True, "normalHttpRequests": False})
    files = [{"path": "lifecycle-" + name, **captures.get(name, L._shell_github_pin(b"fictional export\n"))}
             for name in sorted(L.public_files(value) | {"client.stdout", "client.stderr"})]
    observed.update(state="installed-github-normal-boundaries-observed", invocationId="1" * 32, cases=cases, files=files)
    return observed


class InstalledGitHubNormalBoundaryDataContracts(unittest.TestCase):
    """Fixed two-case inert DATA contracts, not native or kernel qualification."""

    def test_pair_is_separate_and_never_silently_runs_twenty_two_or_normal_http(self):
        value = github_boundary_handoff_data()
        self.assertEqual(L.shell_cases(value), GITHUB_BOUNDARY_FICTIONAL_CASES)
        self.assertEqual(L.shell_github_selection()["cases"], list(GITHUB_FICTIONAL_CASES))
        self.assertEqual(L.SHELL_GITHUB_CASE_DATA, GITHUB_FICTIONAL_CASES)
        self.assertTrue(value["shell"]["githubReadOnly"]["normalDestinationAction"])
        self.assertFalse(value["shell"]["githubReadOnly"]["normalHttpRequests"])
        for case in GITHUB_BOUNDARY_FICTIONAL_CASES:
            self.assertEqual(L.shell_github_role(case), "N")
            self.assertEqual(L.shell_argv(value, case)[-2:], [str(L.root_path(value) / "shell-observer"), case])
        files = L.public_files(value)
        self.assertLessEqual(len(files), 135)
        self.assertFalse(any(name.startswith("shell-github-connect-refresh") for name in files))
        for case in GITHUB_BOUNDARY_FICTIONAL_CASES:
            prefix = L._github_boundary_prefix(case)
            self.assertIn(prefix + "-policy.json", files)
            self.assertIn(prefix + "-absence.stdout", files)
            phases = L.root_phases(value)
            self.assertLess(phases.index(prefix + "-installed"), phases.index("shell-" + case))
            self.assertLess(phases.index("shell-" + case), phases.index(prefix + "-post"))
            self.assertLess(phases.index(prefix + "-delete"), phases.index(prefix + "-absence"))
        for case in ("github-normal-negative", "github-connect-refresh"):
            bad = deepcopy(value)
            bad["shell"]["githubReadOnly"]["cases"].append(case)
            with self.subTest(case=case), self.assertRaises(L.Refused):
                L.shell_cases(bad)

    def test_real_boundary_shapes_require_n_maps_and_connected_or_unconnected_dns(self):
        maps = github_map_data()
        for case, options in (("github-dns-deadline", {}), ("github-dns-deadline", {"unconnected": True}),
                              ("github-connect-deadline", {}), ("github-connect-deadline", {"ipv6": True})):
            receipt = github_boundary_receipt_data(case, **options)
            with self.subTest(case=case, options=options):
                self.assertEqual(L.shell_github_receipt(L.canonical(receipt), case, maps), receipt)
                result = L.shell_github_result(github_capture_data(case, receipt), b"", case, 0, maps)
                self.assertEqual(result["githubReadOnly"], receipt)
                self.assertEqual(result["maps"], [])
                self.assertEqual(receipt["productManifestSha256"], L.M)
                if case == "github-connect-deadline":
                    self.assertIsNone(receipt["peer"])
                    self.assertIsNone(receipt["peerSha256"])
                bad = deepcopy(receipt)
                bad["originals"][0]["maps"] = github_receipt_data("github-handshake-deadline")["originals"][0]["maps"]
                with self.assertRaises(L.Refused):
                    L.shell_github_receipt(L.canonical(bad), case, maps)

    def test_boundary_refuses_wrong_socket_phase_source_timing_and_normal_http(self):
        changes = [
            ("github-dns-deadline", ("originals", 0, "boundary", key), replacement)
            for key, replacement in (("childPid", 0), ("fd", -1), ("inode", 7001), ("inode", "07001"),
                                     ("inode", "18446744073709551616"), ("uid", True), ("state", "02"),
                                     ("localAddress", "0.0.0.0"), ("localAddress", "not-an-ip"),
                                     ("remotePort", 18553), ("originalFdStable", False), ("observedBeforeDeadline", False))]
        changes += [
            ("github-dns-deadline", ("originals", 0, "boundary", "peerSource", "port"), 40003),
            ("github-dns-deadline", ("peer", "terminal", "dnsSource", "questionId"), 999),
            ("github-dns-deadline", ("peer", "terminal", "dnsQuestions"), 0),
            ("github-dns-deadline", ("peer", "terminal", "dnsReplies"), 1),
            ("github-dns-deadline", ("peer", "terminal", "requests"), 1),
            ("github-dns-deadline", ("peer", "terminal", "authBytes"), 1),
            ("github-dns-deadline", ("peer", "terminal", "completion", "dnsClosed"), False),
            ("github-connect-deadline", ("originals", 0, "boundary", "state"), "01"),
            ("github-connect-deadline", ("originals", 0, "boundary", "remoteAddress"), "127.0.0.1"),
            ("github-connect-deadline", ("originals", 0, "boundary", "remoteAddress"), "10.0.0.1"),
            ("github-connect-deadline", ("originals", 0, "boundary", "remotePort"), 18443),
            ("github-connect-deadline", ("peer",), {}),
            ("github-connect-deadline", ("peerSha256",), L.SHELL_GITHUB_PEER_PINS["github_tls_peer.py"][1]),
        ]
        for case, path, replacement in changes:
            receipt = github_boundary_receipt_data(case)
            github_data_set(receipt, path, replacement)
            with self.subTest(case=case, path=path, replacement=replacement), self.assertRaises(L.Refused):
                L.shell_github_receipt(L.canonical(receipt), case, github_map_data())
        for case in GITHUB_BOUNDARY_FICTIONAL_CASES:
            for elapsed in (9999, 12000, True):
                receipt = github_boundary_receipt_data(case)
                receipt["originals"][0]["elapsedMs"] = elapsed
                with self.subTest(case=case, elapsed=elapsed), self.assertRaises(L.Refused):
                    L.shell_github_receipt(L.canonical(receipt), case, github_map_data())

    def test_no_runtime_host_tuple_self_admission_or_resolver_shortcut(self):
        self.assertIsNone(L.SHELL_GITHUB_BOUNDARY_HOST_PROFILE)
        with self.assertRaisesRegex(L.Refused, "not yet independently SOURCE-admitted"):
            L._github_boundary_host_admit({"runtimeSelfAdmission": True})
        nss, hosts = b"hosts: files dns\n", b"127.0.0.1 localhost\n"
        resolver = b"nameserver 127.0.0.53\noptions timeout:7 attempts:2 ndots:1 edns0 trust-ad\n"
        shape = L._github_boundary_resolver_shape(nss, hosts, resolver)
        self.assertEqual((shape["timeoutSeconds"], shape["attempts"], shape["maximumQuestions"]), (7, 2, 4))
        for changed in ((b"hosts: files resolve dns\n", hosts, resolver),
                        (b"hosts: files [NOTFOUND=return] dns\n", hosts, resolver),
                        (nss, b"127.0.0.1 API.GITHUB.COM.\n", resolver),
                        (nss, hosts, b"nameserver 127.0.0.53\n"),
                        (nss, hosts, resolver + b"nameserver 127.0.0.54\n"),
                        (nss, hosts, resolver + b"options rotate\n"),
                        (nss, hosts, resolver.replace(b"ndots:1", b"ndots:2"))):
            with self.subTest(changed=changed), self.assertRaises(L.Refused):
                L._github_boundary_resolver_shape(*changed)
        body = (SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_text().split(
            "def shell_github_boundary_host_materials():", 1)[1].split("\ndef ", 1)[0]
        for forbidden in (".run_owned(", "command(", "socket.socket(", "getaddrinfo(", ".write(", "Popen("):
            self.assertNotIn(forbidden, body)

    def test_policy_is_atomic_stateless_port_only_and_every_effect_has_uid_and_cgroup(self):
        value = github_boundary_handoff_data()
        for case in GITHUB_BOUNDARY_FICTIONAL_CASES:
            raw = L.shell_github_boundary_policy(value, case)
            lines = raw.decode("ascii").splitlines()
            table = "mrk_gnb_" + value["runId"] + "_" + value["attempt"] + (
                "_dns" if case == "github-dns-deadline" else "_connect")
            self.assertEqual(lines[0], "create table inet " + table)
            self.assertIn("add chain inet " + table + " output { type route hook output priority -300; policy accept; }", lines)
            rules = [line for line in lines if line.startswith("add rule ")]
            self.assertEqual(len(rules), 2 if case == "github-dns-deadline" else 1)
            scope = 'meta skuid ' + str(value["runnerUid"]) + ' socket cgroupv2 level 2 "system.slice/' + L.root_path(value).name + '.service"'
            self.assertTrue(all(scope in rule for rule in rules))
            self.assertTrue(rules[-1].endswith(
                "meta l4proto tcp tcp dport 443 tcp flags & (fin | syn | rst | ack) == syn counter name https_syns drop"))
            if case == "github-dns-deadline":
                self.assertTrue(rules[0].endswith(
                    "meta nfproto ipv4 ip daddr 127.0.0.53 udp dport 53 counter name dns_queries udp dport set 18553"))
            for forbidden in ("redirect", "dnat", "snat", "notrack", "flow", "offload", " mark ", "flush", "type nat", "ip daddr set"):
                self.assertNotIn(forbidden, raw.decode())
        for bad_uid in (0, True, -1):
            bad = deepcopy(value); bad["runnerUid"] = bad_uid
            with self.assertRaises(L.Refused):
                L.shell_github_boundary_policy(bad, "github-dns-deadline")
        with self.assertRaises(L.Refused):
            L.shell_github_boundary_policy(github_handoff_data(), "github-dns-deadline")

    def test_actual_object_parser_rejects_uid_only_wrong_handles_predicates_and_dialect(self):
        value = github_boundary_handoff_data()
        profile = {"materials": {}, "nftMetainfo": GITHUB_BOUNDARY_FICTIONAL_META}
        with patch.object(L, "SHELL_GITHUB_BOUNDARY_HOST_PROFILE", profile):
            for case in GITHUB_BOUNDARY_FICTIONAL_CASES:
                objects = github_boundary_objects_data(value, case)
                raw = L.canonical({"nftables": [{"metainfo": GITHUB_BOUNDARY_FICTIONAL_META}, *objects]})
                observed = L.shell_github_boundary_policy_readback(value, case, raw)
                self.assertEqual(L._github_boundary_policy_evidence(value, case, observed), observed)
                variants = []
                for key in ("uid-only", "wrong-uid", "wrong-cgroup", "wrong-hook", "wrong-handle", "extra", "wrong-effect"):
                    bad = deepcopy(objects)
                    rule = next(row["rule"] for row in bad if "rule" in row)
                    chain = next(row["chain"] for row in bad if "chain" in row)
                    if key == "uid-only": del rule["expr"][1]
                    elif key == "wrong-uid": rule["expr"][0]["match"]["right"] += 1
                    elif key == "wrong-cgroup": rule["expr"][1]["match"]["right"] += ".foreign"
                    elif key == "wrong-hook": chain["hook"] = "input"
                    elif key == "wrong-handle": bad[0]["table"]["handle"] = True
                    elif key == "extra": bad.append(deepcopy(bad[-1]))
                    else: rule["expr"][-1] = {"accept": None}
                    variants.append((key, bad))
                for key, bad in variants:
                    changed = L.canonical({"nftables": [{"metainfo": GITHUB_BOUNDARY_FICTIONAL_META}, *bad]})
                    with self.subTest(case=case, key=key), self.assertRaises(L.Refused):
                        L.shell_github_boundary_policy_readback(value, case, changed)
                bad_meta = {"nftables": [{"metainfo": {**GITHUB_BOUNDARY_FICTIONAL_META, "json_schema_version": 2}}, *objects]}
                with self.assertRaises(L.Refused):
                    L.shell_github_boundary_policy_readback(value, case, L.canonical(bad_meta))

    def test_closed_policy_rejects_matching_but_unscoped_summaries_and_changed_finality(self):
        value = github_boundary_handoff_data()
        for case in GITHUB_BOUNDARY_FICTIONAL_CASES:
            receipt = github_boundary_receipt_data(case)
            proof = github_boundary_policy_data_fixture(value, case)
            self.assertIs(L.shell_github_boundary_policy_data(value, case, proof, receipt), proof)
            for path, replacement in ((("productOriginalsFinal",), False), (("faultHeldThroughOriginalFinality",), False),
                                      (("noPriorWorkers",), False), (("normalHttpRequests",), True),
                                      (("domain", "runnerUid"), value["runnerUid"] + 1),
                                      (("domain", "cgroupIdentity", 3), value["runnerUid"]),
                                      (("domain", "namespaces", "net"), [0, 1]),
                                      (("productCommand", "exitCode"), 1), (("absence", "size"), True)):
                bad = deepcopy(proof); github_data_set(bad, path, replacement)
                with self.subTest(case=case, path=path), self.assertRaises(L.Refused):
                    L.shell_github_boundary_policy_data(value, case, bad, receipt)
            bad = deepcopy(proof)
            for phase in ("installed", "post"):
                rule = next(row["rule"] for row in bad[phase]["immutable"] if "rule" in row)
                del rule["expr"][1]
            with self.assertRaises(L.Refused):
                L.shell_github_boundary_policy_data(value, case, bad, receipt)
            bad = deepcopy(proof)
            if case == "github-dns-deadline":
                bad["post"]["counters"]["https_syns"] = {"packets": 1, "bytes": 60}
            else:
                bad["post"]["counters"]["https_syns"] = {"packets": 0, "bytes": 0}
            with self.assertRaises(L.Refused):
                L.shell_github_boundary_policy_data(value, case, bad, receipt)

    def test_reservations_precede_create_and_uncertain_capture_burns_its_finite_slot(self):
        case = "github-dns-deadline"
        slots = {}
        with patch.multiple(L, _GITHUB_BOUNDARY_SLOTS=slots, _TOTAL=0, _FILES=[], _ROOT=Path("/inert"),
                            _D=SimpleNamespace(write=Mock(side_effect=OSError("uncertain write")))):
            roster = L._github_boundary_reserve(case)
            self.assertTrue(any(name.startswith("stop-") for name in roster))
            self.assertTrue(set(roster) == set(slots))
            with self.assertRaises(L.Refused):
                L._github_boundary_reserve(case)
            name = "github-boundary-dns-create.stdout"
            with self.assertRaises(OSError):
                L._retain(name, b"not a creation authority")
            self.assertTrue(slots[name]["entered"])
            self.assertFalse(slots[name]["retained"])
            self.assertEqual(L._TOTAL, 0)
            with self.assertRaises(L.Refused):
                L._retain(name, b"retry")
            L._D.write.assert_called_once()
        with patch.multiple(L, _GITHUB_BOUNDARY_SLOTS={}, _TOTAL=L.TOTAL_LIMIT, _FILES=[]):
            with self.assertRaises(L.Refused):
                L._github_boundary_reserve(case)

    def test_collision_or_unknown_create_never_obtains_delete_authority(self):
        value, case = github_boundary_handoff_data(), "github-dns-deadline"
        empty = L.canonical({"nftables": [{"metainfo": GITHUB_BOUNDARY_FICTIONAL_META}]})
        for failure in (FileExistsError("collision"), RuntimeError("unknown creation owner")):
            events, state = [], {"domain": {}, "cgroupFd": 123}
            def reserve(*args, **kwargs):
                events.append("reserve"); return {}
            def private(which, suffix, raw):
                events.append(suffix); return {"path": suffix}
            def command(current, action):
                events.append(action)
                if action == "before":
                    return subprocess.CompletedProcess([], 0, empty, b"")
                raise failure
            with patch.multiple(L, _FAILED=False, _GITHUB_BOUNDARY_COMMAND_FINAL=True,
                                SHELL_GITHUB_BOUNDARY_HOST_PROFILE={"materials": {}, "nftMetainfo": GITHUB_BOUNDARY_FICTIONAL_META}), \
                 patch.object(L, "_github_boundary_host_check"), patch.object(L, "_github_boundary_domain", return_value=state), \
                 patch.object(L, "_github_boundary_reserve", side_effect=reserve), \
                 patch.object(L, "_github_boundary_private_write", side_effect=private), \
                 patch.object(L, "_github_boundary_body_command", side_effect=command), \
                 patch.object(L, "_github_boundary_close_after") as close:
                with self.assertRaises(type(failure)):
                    L._github_boundary_prepare(value, case, {"namespaces": {}}, {})
                close.assert_called_once_with(state)
            self.assertLess(events.index("reserve"), events.index("create"))
            self.assertLess(events.index("intent.json"), events.index("create"))
            self.assertNotIn("owned.json", events)
            self.assertNotIn("delete", events)

    def test_stoppost_capture_failure_preserves_first_latch_but_unknown_owner_closes_next_launch(self):
        value, case = github_boundary_handoff_data(), "github-connect-deadline"
        proof = github_boundary_policy_data_fixture(value, case)
        for unknown in (False, True):
            def run(argv, **kwargs):
                if unknown:
                    raise RuntimeError("unknown original wait")
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            owner = SimpleNamespace(run_owned=Mock(side_effect=run))
            state = {"value": value, "case": case, "owned": {"installed": proof["installed"]}, "ownedRecord": {},
                     "owner": owner, "next": "delete"}
            controller = {"owner": owner, "endpoint": 100.0, "launchesClosed": False, "errors": [], "context": None}
            with patch.multiple(L, _OWNER=owner, _END=100.0, _FAILED=True, _PHASE="inert",
                                _GITHUB_BOUNDARY_COMMAND_FINAL=True), \
                 patch.object(L.time, "monotonic", return_value=90.0), patch.object(L, "_environment", return_value={}), \
                 patch.object(L, "_github_boundary_owned_admit"), patch.object(L, "_github_boundary_domain_check"), \
                 patch.object(L, "_command_capture", side_effect=OSError("capture refusal")):
                result = L._github_boundary_dispose_command(controller, state, "delete")
                self.assertTrue(L._FAILED)
                self.assertEqual(L._END, 100.0)
                self.assertEqual(controller["launchesClosed"], unknown)
                self.assertEqual(L._GITHUB_BOUNDARY_COMMAND_FINAL, not unknown)
                self.assertEqual(result is None, unknown)
                self.assertEqual(len(controller["errors"]), 1)
                self.assertTrue(controller["errors"][0]["stage"].endswith("-owner" if unknown else "-capture"))
                kwargs = owner.run_owned.call_args.kwargs
                self.assertIs(kwargs["cleanup"], False)
                self.assertEqual(kwargs["timeout"], 2)
                state["next"] = "absence"
                if unknown:
                    with self.assertRaises(L.Refused):
                        L._github_boundary_dispose_command(controller, state, "absence")
                    owner.run_owned.assert_called_once()
                else:
                    L._github_boundary_dispose_command(controller, state, "absence")
                    self.assertEqual(owner.run_owned.call_count, 2)
                    self.assertEqual(controller["errors"][0]["stage"], "stop-github-boundary-connect-delete-capture")
                    self.assertTrue(L._FAILED)

    def test_stoppost_disposition_is_before_completion_missing_result_and_denial_success_gates(self):
        value = github_boundary_handoff_data()
        for fault in ("completion", "missing-result", "denial"):
            events = []
            def disposition(current):
                events.append("dispose")
                return {}, {"errors": [], "allOwnedPoliciesAbsent": True, "laterLaunchesClosed": False, "cases": {}}
            def record(path, *args):
                events.append(path.name)
                if fault == "missing-result":
                    raise FileNotFoundError("unit-result is missing")
                return {"size": 1, "sha256": "e" * 64}
            def denial(observation):
                events.append("denial"); raise L.Refused("resource denial")
            env = {} if fault == "completion" else {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}
            with patch.multiple(L, _ROOT=Path("/inert"), _END=0.0), patch.object(L.time, "monotonic", return_value=90.0), \
                 patch.object(L, "_root_ids"), patch.object(L, "_context", return_value=(value, "e" * 64)), \
                 patch.object(L, "_github_boundary_stop", side_effect=disposition), patch.dict(L.os.environ, env, clear=True), \
                 patch.object(L, "read", return_value=b"{}\n"), patch.object(L, "record", side_effect=record), \
                 patch.object(L, "_domain_events", side_effect=denial):
                with self.assertRaises((L.Refused, FileNotFoundError)):
                    L.unit_stop()
                self.assertEqual(L._END, 99.0)
            self.assertEqual(events[0], "dispose")
            self.assertEqual("denial" in events, fault == "denial")

    def test_same_cgroup_contains_only_retained_self_no_uid_or_root_worker_exemption(self):
        value = github_boundary_handoff_data()
        domain = github_boundary_policy_data_fixture(value, "github-connect-deadline")["domain"]
        current = needrestart_stat(stat.S_IFDIR | 0o755, ino=321, nlink=2, size=4096)
        owner, me = object(), {"pid": 42, "startTicks": 1}
        state = {"value": value, "domain": domain, "cgroupFd": 123, "owner": owner, "endpoint": 100.0, "self": me}
        for workers in ("42\n", "42\n99\n", "99\n", ""):
            def kernel(path, cap=None):
                path = str(path)
                if path == "/proc/self/cgroup": return "0::/system.slice/" + domain["unit"] + "\n"
                if path.endswith("/boot_id"): return domain["bootId"] + "\n"
                if path.endswith("/cgroup.type"): return "domain\n"
                if path.endswith(("/cgroup.procs", "/cgroup.threads")): return workers
                raise AssertionError("unreviewed mock kernel path")
            with patch.multiple(L, _OWNER=owner, _END=100.0), patch.object(L.time, "monotonic", return_value=90.0), \
                 patch.object(L, "_root_ids"), patch.object(L, "_kernel", side_effect=kernel), \
                 patch.object(L, "_github_boundary_namespaces", return_value=domain["namespaces"]), \
                 patch.object(L, "_github_boundary_self", return_value=me), \
                 patch.dict(L.os.environ, {"INVOCATION_ID": domain["invocationId"]}, clear=True), \
                 patch.object(L.os, "fstat", return_value=current), patch.object(Path, "lstat", return_value=current), \
                 patch.object(L.os, "listdir", return_value=["cgroup.procs", "cgroup.threads"]), \
                 patch.object(L.os, "stat", return_value=needrestart_stat(stat.S_IFREG | 0o644)):
                if workers == "42\n":
                    self.assertIs(L._github_boundary_domain_check(state, no_workers=True), domain)
                else:
                    with self.subTest(workers=workers), self.assertRaises(L.Refused):
                        L._github_boundary_domain_check(state, no_workers=True)

    def test_original_close_error_does_not_replace_body_first_failure(self):
        first = RuntimeError("first body failure")
        with patch.multiple(L, _FAILED=False, _GITHUB_BOUNDARY_BODY_ERRORS=[]), \
             patch.object(L, "_github_boundary_close_domain", side_effect=OSError("cgroup close")):
            try:
                try:
                    raise first
                finally:
                    L._github_boundary_close_after({})
            except RuntimeError as error:
                self.assertIs(error, first)
            self.assertTrue(L._FAILED)
            self.assertEqual(L._GITHUB_BOUNDARY_BODY_ERRORS, [{"stage": "original-cgroup-close", "errorType": "OSError"}])


class InstalledGitHubNormalBoundaryClosedExportDataContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "github_boundary_closed_export_data", SOURCE / "desktop/tools/ci_ubuntu_publication.py")
        cls.CI = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.CI)

    def validate(self, observed):
        value = github_boundary_handoff_data()
        return self.CI.shell_github_observation(observed, L, "github-readonly-installed-normal-boundaries-v1",
                                               runner_uid=value["runnerUid"], runner_gid=value["runnerGid"])

    def test_pair_has_distinct_root_policy_and_export_pins_not_just_native_flags(self):
        observed = github_boundary_closed_observation_data()
        self.assertIs(self.validate(observed), observed["githubReadOnly"])
        self.assertEqual(set(observed["cases"]), set(GITHUB_BOUNDARY_FICTIONAL_CASES))
        self.assertFalse(observed["githubReadOnly"]["normalHttpRequests"])
        self.assertIn("current-twenty-two-synthetic-regressions", observed["githubReadOnly"]["remainingCoverage"])
        with self.assertRaises(self.CI.D.Refused):
            self.CI.shell_github_observation(observed, L)  # Legacy profile never adopts the new pair.
        with self.assertRaises(self.CI.D.Refused):
            self.CI.shell_github_observation(observed, L, "github-readonly-installed-normal-boundaries-v1")

    def test_missing_or_forged_root_policy_uid_invocation_scope_and_capture_refuse(self):
        root = ("githubReadOnly", "boundaries")
        changes = [(("invocationId",), "2" * 32), (("githubReadOnly", "normalDestinationAction"), False),
                   (("githubReadOnly", "normalHttpRequests"), True), (("githubReadOnly", "remainingCoverage"), []),
                   (root + ("rootUidAndCgroupScoped",), False),
                   (root + ("host", "after", "sha256"), "f" * 64),
                   (root + ("policies", "github-connect-deadline", "capture", "sha256"), "f" * 64),
                   (root + ("policies", "github-connect-deadline", "evidence", "domain", "runnerUid"), 555),
                   (root + ("policies", "github-connect-deadline", "evidence", "faultHeldThroughOriginalFinality"), False)]
        for path, replacement in changes:
            observed = github_boundary_closed_observation_data(); github_data_set(observed, path, replacement)
            with self.subTest(path=path), self.assertRaises((L.Refused, self.CI.D.Refused)):
                self.validate(observed)
        observed = github_boundary_closed_observation_data()
        row = observed["githubReadOnly"]["boundaries"]["policies"]["github-dns-deadline"]
        for phase in ("installed", "post"):
            rule = next(item["rule"] for item in row["evidence"][phase]["immutable"] if "rule" in item)
            del rule["expr"][1]
        row["capture"] = L._shell_github_pin(L.canonical(row["evidence"]))
        exported = next(item for item in observed["files"] if item["path"] == "lifecycle-github-boundary-dns-policy.json")
        exported.update(row["capture"])
        with self.assertRaises(L.Refused):
            self.validate(observed)  # Matching altered pins cannot legitimize an unscoped policy.


if __name__ == "__main__":
    unittest.main()
