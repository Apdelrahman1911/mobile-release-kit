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

    def test_package_observation_uses_original_return_and_latches_every_failure(self):
        before, after = needrestart_data(present=False), needrestart_data("unpacked")
        for case in ("complete", "collision", "endpoint", "policy", "before", "command", "after", "changed", "late", "endpoint-late"):
            phase, codes = ("duplicate", (1,)) if case == "collision" else ("unpack", (0,))
            argv = ["/usr/bin/dpkg", "--debug=2", "--no-triggers", L.PACKAGE_ACTIONS[phase], "/inert/P0.deb"]
            endpoint = 150 if case.startswith("endpoint") else None
            completed = subprocess.CompletedProcess(argv, codes[0], b"", b"")
            reads, events = [], []
            def snapshot():
                events.append("snapshot")
                reads.append(None)
                if case == "before" or case == "after" and len(reads) == 2:
                    raise ValueError("inert marker refusal")
                result = deepcopy(before if len(reads) == 1 else after)
                if case == "changed" and len(reads) == 2: result["markers"]["unpacked"]["size"] = 1
                return result
            def command(label, actual, **options):
                events.append("command")
                if case == "command": raise RuntimeError("inert original owner failure")
                self.assertEqual((actual, options["maximum"], options["env"]["PATH"], options["codes"]), (argv, 240, L.DPKG_PATH, codes))
                if endpoint is None: self.assertNotIn("endpoint", options)
                else: self.assertEqual(options["endpoint"], endpoint)
                L._COMMANDS.append({"phase": label, "argv": actual, "exitCode": completed.returncode})
                return completed
            with self.subTest(case=case), patch.multiple(L, _ROOT=Path("/inert"), _END=200, _FAILED=False, _COMMANDS=[], _PHASE="inert"), \
                 patch.object(L, "dpkg_policy", return_value={"changed": 1} if case == "policy" else {}), \
                 patch.object(L, "needrestart_state", side_effect=snapshot), patch.object(L, "command", side_effect=command), \
                 patch.object(L.time, "monotonic", return_value=201 if case == "late" else 151 if case == "endpoint-late" else 100):
                if case in {"complete", "collision", "endpoint"}:
                    self.assertIs(L.package_command(phase, argv, policy={}, codes=codes, endpoint=endpoint), completed)
                    self.assertFalse(L._FAILED)
                    self.assertEqual(events, ["snapshot", "command", "snapshot"])
                    self.assertIs(L._COMMANDS[0]["needrestartMarkers"]["loggerCompletionClaimed"], False)
                    L.verify_package_observations(L._COMMANDS)
                    missing = deepcopy(L._COMMANDS); missing[0].pop("needrestartMarkers")
                    with self.assertRaises(ValueError): L.verify_package_observations(missing)
                else:
                    with self.assertRaises((ValueError, RuntimeError)):
                        L.package_command(phase, argv, policy={}, codes=codes, endpoint=endpoint)
                    self.assertTrue(L._FAILED)
                if case in {"policy", "before"}: self.assertNotIn("command", events)
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
