"""Inert lifecycle policy tests; never start a service, child or package tool."""
from copy import deepcopy
import ast
import errno
import hashlib
import importlib.util
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


class LifecycleData(unittest.TestCase):
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

    def test_native_failure_diagnostic_uses_only_original_bounded_capture(self):
        argv = ["/inert-native-fixture-never-executed"]
        raw = b'\0\x1b\xff"' + b"a" * 1500
        prefix = "Native platform failure DATA: "
        for case in ("root-failed", "user-failed", "late", "success", "other-command", "owner-error", "malformed", "sink-error"):
            label = "native-user" if case == "user-failed" else "unpack" if case == "other-command" else "native-root"
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
                if case in {"root-failed", "user-failed", "late", "sink-error"}:
                    self.assertEqual(len(emitted), 1)
                    text = emitted[0]
                    self.assertTrue(text.startswith(prefix) and text.endswith("\n"))
                    self.assertTrue(all(32 <= ord(char) < 127 for char in text[:-1]))
                    self.assertLess(len(text), 14 * 1024)
                    self.assertEqual(L.decode(text[len(prefix):].encode("ascii")), {
                        "phase": label, "exitCode": result.returncode,
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


if __name__ == "__main__":
    unittest.main()
