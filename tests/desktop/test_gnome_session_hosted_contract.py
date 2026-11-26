"""Focused inert hosted-carrier contracts: no native tools, accounts or network.

Independent SOURCE/COMMAND review precedes execution. No historical native test
suite is imported; the seven Rust cases still require the original hosted run.
"""
from __future__ import annotations

import copy
from contextlib import ExitStack, nullcontext
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("gnome_host_contract", "desktop/tools/gnome_session_native/host-admit.py")
C = load("gnome_carrier_contract", "desktop/tools/gnome_session_hosted.py")
N = load("gnome_owner_contract", "desktop/tools/gnome_session_native/owner.py")


def bus(signature, value):
    return (json.dumps({"type": signature, "data": [value]}) + "\n").encode("ascii")


def environment():
    return {"RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
            "ImageOS": "ubuntu24", "ImageVersion": "20260907.300.1", "GITHUB_REF": C.REF,
            "GITHUB_REPOSITORY": "example/project", "GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40,
            "GITHUB_WORKFLOW_REF": "example/project/" + C.WORKFLOW + "@" + C.REF,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push",
            "MRK_PUSH_EVENT_AFTER": "a" * 40, "MRK_EXPECTED_SHA": ""}


def host_facts():
    return {"shadowCacheHelpers": {"nscd": "/usr/sbin/nscd", "sssCache": "/usr/sbin/sss_cache"},
            "shadowVersion": "1:4.13+dfsg1-4ubuntu3.2",
            "systemdVersion": "255.4-1ubuntu8.17"}


def root_status():
    return b"Name:\tfixture\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\n"


def file_info(*, uid=0, gid=0, mode=stat.S_IFDIR | 0o755):
    return SimpleNamespace(st_dev=7, st_ino=31, st_mode=mode, st_nlink=1, st_uid=uid, st_gid=gid,
                           st_size=4096, st_mtime_ns=10, st_ctime_ns=11)


class HostAdmissionContracts(unittest.TestCase):
    def test_actual_backend_sequence_authenticates_manager_and_latches_original_failures(self):
        expected = [
            ("manager-owner", H.DBUS, "GetNameOwner", ("s", H.MANAGER)),
            ("manager-pid", H.DBUS, "GetConnectionUnixProcessID", ("s", ":1.0")),
            ("manager-uid", H.DBUS, "GetConnectionUnixUser", ("s", ":1.0")),
            ("manager-roster", (H.MANAGER, "/org/freedesktop/systemd1", H.MANAGER + ".Manager"), "GetDynamicUsers", ()),
            ("manager-owner-post", H.DBUS, "GetNameOwner", ("s", H.MANAGER))]
        for failure in (None, "original", "wrong-pid", "wrong-uid", "owner-changed"):
            replies = [bus("s", ":1.0"), bus("u", 2 if failure == "wrong-pid" else 1),
                       bus("u", 1 if failure == "wrong-uid" else 0), bus("a(us)", [[62000, "another-service"]]),
                       bus("s", ":1.1" if failure == "owner-changed" else ":1.0")]
            calls = []
            def original(role, argv, **kwargs):
                calls.append((role, argv, kwargs))
                return SimpleNamespace(returncode=1 if failure == "original" else 0,
                                       stdout=replies[len(calls) - 1], stderr=b"")
            host = H.HostAdmission(original, host_facts())
            executable = {"identity": H.identity(file_info(mode=stat.S_IFREG | 0o755)), "sha256": "e" * 64}
            def kernel(path):
                if path == "/proc/1/status":
                    return root_status()
                self.assertIn(path, ("/proc/1/uid_map", "/proc/1/gid_map"))
                return b"0 0 4294967295\n"
            with self.subTest(failure=failure), patch.object(host, "kernel", side_effect=kernel), \
                 patch.object(host, "read", return_value=executable), \
                 patch.object(H.os, "readlink", return_value="/usr/lib/systemd/systemd"), \
                 patch.object(H.os, "stat", return_value=file_info()):
                if failure is None:
                    value = host.backend("before-owner", 100)
                    self.assertTrue(value["healthyAuthoritativeBackend"])
                    self.assertFalse(value["nssTransportQualified"])
                    self.assertEqual((value["managerPid"], value["managerUid"], value["records"]), (1, 0, 1))
                else:
                    code = ("backend-original-failed" if failure == "original" else
                            "system-manager-owner-changed" if failure == "owner-changed" else "system-manager-peer-identity")
                    with self.assertRaisesRegex(H.Refused, code):
                        host.backend("before-owner", 100)
            count = 1 if failure == "original" else 3 if failure in ("wrong-pid", "wrong-uid") else 5
            self.assertEqual(len(calls), count)
            for (role, argv, kwargs), (suffix, destination, method, arguments) in zip(calls, expected):
                self.assertEqual((role, argv), ("before-owner-" + suffix, list(H.BUS + destination + (method,) + arguments)))
                self.assertEqual(kwargs, {"maximum": 8, "deadline": 100, "output_limit": H.MIB})

    def test_census_reads_nonleader_credentials_and_only_allows_genuine_disappearance(self):
        for case in ("clean", "uid", "gid", "group", "thread-vanished", "thread-live-missing", "unreadable",
                     "process-vanished", "task-live-missing"):
            def listing(path):
                value = str(path)
                if value == "/proc":
                    entries = [SimpleNamespace(name=n, path="/proc/" + n) for n in ("1", "42")]
                elif value == "/proc/1/task":
                    entries = [SimpleNamespace(name="1", path="/proc/1/task/1")]
                else:
                    self.assertEqual(value, "/proc/42/task")
                    if case in ("process-vanished", "task-live-missing"):
                        raise FileNotFoundError
                    entries = [SimpleNamespace(name=n, path="/proc/42/task/" + n) for n in ("42", "43")]
                return nullcontext(iter(entries))
            reads = []
            def kernel(path):
                reads.append(str(path))
                if str(path) != "/proc/42/task/43/status":
                    self.assertIn(str(path), ("/proc/1/status", "/proc/42/status"))
                    return root_status()
                if case in ("thread-vanished", "thread-live-missing"):
                    raise FileNotFoundError
                if case == "unreadable":
                    raise PermissionError
                raw = root_status()
                if case in ("uid", "gid"):
                    key = b"Uid" if case == "uid" else b"Gid"
                    raw = raw.replace(key + b":\t0\t0\t0\t0", key + b":\t0\t0\t61000\t0")
                elif case == "group":
                    raw = raw.replace(b"Groups:\t\n", b"Groups:\t61000\n")
                return raw
            host = H.HostAdmission(Mock(side_effect=AssertionError("No command in census")), host_facts())
            vanished = case in ("thread-vanished", "process-vanished")
            with self.subTest(case=case), patch.object(H.os, "scandir", side_effect=listing), \
                 patch.object(H.time, "monotonic", return_value=1), patch.object(host, "kernel", side_effect=kernel), \
                 patch.object(Path, "exists", return_value=not vanished):
                if case in ("clean", "thread-vanished", "process-vanished"):
                    result = host.census(100)
                    self.assertTrue(result["threadCredentialsIncluded"])
                    self.assertEqual(result["vanished"], int(vanished))
                elif case == "unreadable":
                    with self.assertRaises(PermissionError):
                        host.census(100)
                else:
                    with self.assertRaises(H.Refused):
                        host.census(100)
            if case not in ("process-vanished", "task-live-missing"):
                self.assertIn("/proc/42/task/43/status", reads)
            host.command.assert_not_called()

    def test_occupied_useradd_hooks_refuse_before_either_real_reservation_command(self):
        for hook in ("/etc/shadow-maint/useradd-pre.d", "/etc/shadow-maint/useradd-post.d"):
            original = Mock(side_effect=AssertionError("Account command must not be attempted"))
            host = H.HostAdmission(original, host_facts())
            actual_empty = host.empty_or_absent
            def empty(name):
                return actual_empty(name) if name == hook else {"absent": True}
            with self.subTest(hook=hook), patch.object(host, "root_identity"), patch.object(host, "ancestors"), \
                 patch.object(host, "empty_or_absent", side_effect=empty), \
                 patch.object(host, "read", side_effect=AssertionError("No account read before hook refusal")), \
                 patch.object(H.time, "monotonic", return_value=1), patch.object(Path, "lstat", return_value=file_info()), \
                 patch.object(H.os, "open", return_value=17), patch.object(H.os, "close"), \
                 patch.object(H.os, "listdir", return_value=["unreviewed-hook"]), \
                 patch.object(H.os, "fstat", return_value=file_info()), patch.object(C, "save_host") as saved:
                with self.assertRaisesRegex(H.Refused, "provider-or-hook-directory-occupied"):
                    C.reserve_host(host, 100)
            original.assert_not_called()
            saved.assert_not_called()

    def test_actual_finite_nss_profile_not_files_only_or_foreign_provider(self):
        for group in ("files systemd", "files [SUCCESS=merge] systemd"):
            self.assertEqual(H.parse_nss(("passwd: files systemd\ngroup: " + group + "\n").encode())["passwd"],
                             ["files", "systemd"])
        for raw in (b"passwd: files\ngroup: files\n", b"passwd: files systemd\ngroup: files sss systemd\n",
                    b"passwd: files systemd\npasswd: files systemd\ngroup: files systemd\n"):
            with self.subTest(raw=raw), self.assertRaises(H.Refused):
                H.parse_nss(raw)

    def test_whole_manager_roster_covers_explicit_and_group_reservations(self):
        self.assertEqual(H.parse_dynamic_users(bus("a(us)", [[500, "static-service"], [62000, "dynamic-service"]])), 2)
        for rows in ([[61000, "foreign-group"]], [[500, H.NAME]], [[500, "a"], [500, "a"]],
                     [[True, "boolean-is-not-uid"]], [[-1, "invalid"]]):
            with self.subTest(rows=rows), self.assertRaises(H.Refused):
                H.parse_dynamic_users(bus("a(us)", rows))

    def test_failed_truncated_or_wrong_backend_response_is_not_absence(self):
        for raw in (b"", bus("a(us)", [])[:-1], bus("au", []), b'{"type":"a(us)","data":[[]],"error":true}\n',
                    b'{"type":"a(us)","type":"a(us)","data":[[]]}\n'):
            with self.subTest(raw=raw), self.assertRaises((H.Refused, ValueError)):
                H.parse_dynamic_users(raw)

    def test_subordinate_grants_cannot_lend_identity_or_hide_numeric_grantee(self):
        self.assertEqual(H.parse_subids(b"runner:100000:65536\n"), 1)
        for raw in (b"runner:60999:2\n", b"000061000:100000:1\n", b"mrk-gnome-fixture:100000:1\n",
                    b"runner:4294967294:3\n", b"runner:100000:1\nrunner:100000:1\n", b"runner:100000:0\n"):
            with self.subTest(raw=raw), self.assertRaises(H.Refused):
                H.parse_subids(raw)

    def test_strict_status_width_duplicates_and_bound_preserved(self):
        good = b"Name:\tfixture\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\n"
        self.assertEqual(H.parse_status(good)["Uid"], [0] * 4)
        for raw in (good + b"Uid:\t0\t0\t0\t0\n", good.replace(b"Uid:\t0\t0\t0\t0", b"Uid:\t0\t0\t0"),
                    good.replace(b"Groups:\t", b"Groups:\t1 1"), good + b"x" * 16384, good[:-1]):
            with self.subTest(size=len(raw)), self.assertRaises(H.Refused):
                H.parse_status(raw)

    def test_automatic_uid_and_gid_ranges_cannot_include_the_fixture(self):
        self.assertEqual(H.parse_login_defs(b"UID_MAX 60000\nGID_MAX 60000\n")["SYS_UID_MAX"], 999)
        for raw in (b"UID_MAX 61000\n", b"SYS_GID_MAX 62000\n", b"UID_MIN 70000\n", b"GID_MAX 60000\nGID_MAX 60000\n"):
            with self.subTest(raw=raw), self.assertRaises(H.Refused):
                H.parse_login_defs(raw)

    def test_reservation_is_locked_exact_and_preserves_unrelated_bytes(self):
        original = b"root:x:0:0:root:/root:/bin/bash\n\n"
        task = (H.NAME + ":x:61000:61000:MRK GNOME fixture:/nonexistent:/usr/sbin/nologin\n").encode()
        self.assertIn(H.NAME, H.parse_accounts(original + task, "passwd", True))
        self.assertEqual(H.unrelated_bytes(original + task), original)
        for kind, raw in (("passwd", original + task.replace(b":61000:61000:", b":61001:61000:")),
                          ("shadow", (H.NAME + ":*:21000::::::\n").encode()),
                          ("group", (H.NAME + ":x:61000:runner\n").encode())):
            with self.subTest(kind=kind), self.assertRaises(H.Refused):
                H.parse_accounts(raw, kind, True)

    def test_partial_provisioning_latches_failure_without_retry_adoption_or_deletion(self):
        calls = []
        def original(role, argv, **_):
            calls.append((role, argv))
            return SimpleNamespace(returncode=1 if role == "useradd" else 0, stdout=b"", stderr=b"")
        host = H.HostAdmission(original, {"shadowCacheHelpers": {"nscd": "/usr/sbin/nscd", "sssCache": "/usr/sbin/sss_cache"},
                                         "shadowVersion": "1:4.13+dfsg1-4ubuntu3.2", "systemdVersion": "255.4-1ubuntu8.17"})
        with self.assertRaises(H.Refused):
            host.provision(100)
        self.assertEqual(calls, [("groupadd", list(H.GROUPADD)), ("useradd", list(H.USERADD))])

    def test_all_four_actual_host_boundaries_required_for_final_census(self):
        states = [{"stage": name} for name in H.STAGES]
        self.assertFalse(H.public_projection(states[:-1], account_created=True)["completeHostThreadCensus"])
        self.assertTrue(H.public_projection(states, account_created=True)["hostAccountCreated"])
        with self.assertRaises(H.Refused):
            H.public_projection(states[1:], account_created=True)


class CarrierContracts(unittest.TestCase):
    def setUp(self):
        for name, value in (("_EVIDENCE", {"context": None, "source": None, "hostToolOriginalsSha256": None,
                                        "hostToolSuppliers": None, "acquisition": None, "owner": None,
                                        "reservationSha256": None, "originalWorkflowWait": None,
                                        "bootstrap": None, "hostAuthenticationScope": None, "pythonRuntime": None,
                                        "bwrapSupply": None, "pythonPycache": None}),
                            ("_WAITS", []), ("_PINS", {}), ("_SUPPLIERS", []),
                            ("_OWNER", None), ("_PYCACHE", None), ("_ORIGINALS_SETTLED", True)):
            item = patch.object(C, name, value)
            item.start()
            self.addCleanup(item.stop)

    def test_root_git_allows_only_freshly_authenticated_exact_checkout_with_clean_config(self):
        checkout = {"repository": "example/project", "path": str(C.SOURCE), "uid": 1001}
        original = Mock(return_value=SimpleNamespace(returncode=0, stdout=b"a\n", stderr=b""))
        with patch.object(C, "checkout_admission", return_value=checkout), patch.object(C, "command", original), \
             patch.dict(C.os.environ, {"SUDO_UID": "999", "GIT_CONFIG_COUNT": "1", "GIT_TRACE": "ambient", "GH_DEBUG": "api"}):
            self.assertEqual(C.git_output(["rev-parse", "HEAD"], 100, "source-commit", checkout), b"a\n")
        original.assert_called_once_with("source-commit", ["/usr/bin/git", "--no-replace-objects",
            "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.attributesFile=/dev/null",
            "-c", "safe.directory=" + str(C.SOURCE), "-C", str(C.SOURCE), "rev-parse", "HEAD"],
            maximum=15, deadline=100, output_limit=C.MIB,
            environment={**C.ENV, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                         "GIT_ATTR_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0"})
        original.reset_mock()
        with patch.object(C, "checkout_admission", return_value={**checkout, "uid": 2000}), patch.object(C, "command", original):
            with self.assertRaisesRegex(C.Refused, "original-checkout-admission-changed"):
                C.git_output(["rev-parse", "HEAD"], 100, "source-commit", checkout)
        original.assert_not_called()

    @staticmethod
    def git_config():
        return (b'[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n'
                b'\tlogallrefupdates = true\n[remote "origin"]\n\turl = https://github.com/example/project\n'
                b'\tfetch = +refs/heads/*:refs/remotes/origin/*\n[gc]\n\tauto = 0\n')

    def test_literal_git_config_rejects_unreviewed_extensions_before_any_command(self):
        raw = self.git_config()
        with patch.object(C, "command") as command:
            self.assertIsNone(C.git_configuration(raw, "example/project"))
            for changed in (raw + b'[include]\n path = /outside\n',
                            raw + b'[includeIf "gitdir:*"]\n path = /outside\n',
                            raw + b'[core]\n fsmonitor = /outside\n',
                            raw + b'[remote "origin"]\n promisor = true\n',
                            raw + b'[extensions]\n worktreeConfig = true\n',
                            raw + b'[filter "external"]\n clean = /outside\n',
                            raw + b'[gc]\n auto = 0\n', raw.replace(b'auto = 0', b'auto = 0\\'),
                            raw.replace(b'https://github.com/', b'https://credential@github.com/'),
                            raw.replace(b'filemode = true', b'filemode = false'), raw.replace(b'\n', b'\r\n'), b''):
                with self.subTest(changed=changed), self.assertRaises(C.Refused):
                    C.git_configuration(changed, "example/project")
        command.assert_not_called()

    def test_git_control_bytes_absences_and_parent_aliases_are_bound_without_git(self):
        with tempfile.TemporaryDirectory(prefix="mrk-gnome-git-control-") as temporary:
            root = Path(temporary)
            git = root / ".git"
            for path in (git, git / "info", git / "objects", git / "objects/info"):
                path.mkdir(mode=0o700)
            (git / "config").write_bytes(self.git_config())
            (git / "config").chmod(0o600)
            info = git.lstat()
            owner = (info.st_uid, info.st_gid)
            with patch.object(C, "command") as command:
                before = C.checkout_git_controls(root, owner, "example/project")
                self.assertEqual(before["files"]["info/exclude"], {"absent": True})
                self.assertEqual(C.checkout_git_controls(root, owner, "example/project"), before)
                for name in C.GIT_FORBIDDEN_CONTROLS:
                    occupied = git / name
                    occupied.symlink_to("absent-target")
                    with self.subTest(name=name), self.assertRaisesRegex(C.Refused, "checkout-git-control-occupied"):
                        C.checkout_git_controls(root, owner, "example/project")
                    occupied.unlink()
                (git / "config").rename(git / "saved-config")
                (git / "config").symlink_to("saved-config")
                with self.assertRaisesRegex(C.Refused, "checkout-git-control-file"):
                    C.checkout_git_controls(root, owner, "example/project")
                (git / "config").unlink()
                (git / "config").write_bytes(self.git_config())
                (git / "config").chmod(0o600)
                changed = C.checkout_git_controls(root, owner, "example/project")
                self.assertEqual(before["files"]["config"]["sha256"], changed["files"]["config"]["sha256"])
                self.assertNotEqual(before["files"]["config"]["identity"], changed["files"]["config"]["identity"])
                (git / "info").rename(git / "saved-info")
                (git / "info").symlink_to("saved-info", target_is_directory=True)
                with self.assertRaisesRegex(C.Refused, "checkout-git-control-parent"):
                    C.checkout_git_controls(root, owner, "example/project")
            command.assert_not_called()

    def test_git_controls_are_rechecked_after_original_return_and_in_later_binding(self):
        checkout = {"repository": "example/project", "path": str(C.SOURCE), "gitControls": {"sha256": "a" * 64}}
        changed = {**checkout, "gitControls": {"sha256": "b" * 64}}
        result = SimpleNamespace(returncode=7, stdout=b"original", stderr=b"original error")
        with patch.object(C, "checkout_admission", side_effect=[checkout, changed]), \
             patch.object(C, "command", return_value=result) as original:
            with self.assertRaisesRegex(C.Refused, "original-checkout-admission-changed"):
                C.git_output(["rev-parse", "HEAD"], 100, "source-commit", checkout)
        original.assert_called_once()
        self.assertEqual(result.returncode, 7)
        binding = {"schema": "gnome-session-source-binding-1", "repository": "example/project", "checkoutAdmission": checkout}
        with patch.object(C, "read", return_value=(C.canonical(binding), {"mode": "0o400"})), \
             patch.object(C, "checkout_admission", return_value=changed), patch.object(C, "command") as original:
            with self.assertRaisesRegex(C.Refused, "original-checkout-admission-changed"):
                C.binding_for({})
        original.assert_not_called()

    def test_checkout_admission_rejects_foreign_owner_or_alias_without_git(self):
        root = Path("/home/runner/work/project/project")
        for conflict in (None, "foreign-owner", "git-alias", "output-owner"):
            def info(path):
                owner = 0 if str(path) in ("/", "/home") else 1001
                mode = stat.S_IFDIR | (0o700 if path == C.OUTER else 0o755)
                if path == root / ".git":
                    if conflict == "foreign-owner":
                        owner = 2000
                    if conflict == "git-alias":
                        mode = stat.S_IFLNK | 0o777
                if path == C.OUTER and conflict == "output-owner":
                    owner = 2000
                return file_info(uid=owner, gid=owner, mode=mode)
            with self.subTest(conflict=conflict), patch.object(C, "SOURCE", root), patch.object(Path, "lstat", info), \
                 patch.object(C, "checkout_git_controls", return_value={"inert": True}):
                if conflict is None:
                    self.assertEqual(C.checkout_admission("example/project")["path"], str(root))
                else:
                    with self.assertRaises(C.Refused):
                        C.checkout_admission("example/project")

    def test_registry_remapping_retains_acquisition_identities_and_rejects_same_content_change(self):
        base = str(C.TASK / "temporary/cargo/registry")
        original = {"files": [{"path": base + "/index/config.json", "identity": [7, 31, 0o100600, 1, 0, 0, 4, 10, 11],
                               "bytes": 4, "sha256": "a" * 64, "mode": "0o600"}],
                    "directories": [{"path": base, "identity": [7, 32, 0o40700, 2, 0, 0, 4096, 10, 11],
                                     "entries": ["index"], "mode": "0o700"}],
                    "rootIdentity": [7, 32, 0o40700, 2, 0, 0, 4096, 10, 11], "bytes": 4}
        mapped = C.remap_inputs(original)
        self.assertEqual(mapped["files"][0]["path"], "/registry/index/config.json")
        self.assertEqual(mapped["files"][0]["identity"], original["files"][0]["identity"])
        self.assertEqual(mapped["directories"][0]["identity"], original["directories"][0]["identity"])
        changed = copy.deepcopy(original)
        changed["files"][0]["identity"][-1] += 1  # Same bytes, mode and inode; original ctime changed.
        self.assertEqual(changed["files"][0]["sha256"], original["files"][0]["sha256"])
        with patch.object(C, "read", return_value=(C.canonical(original), {})):
            for stage in ("before-owner", "after-owner", "before-cleanup"):
                with self.subTest(stage=stage), patch.object(C, "bounded_roster", return_value=original):
                    self.assertEqual(C.registry_originals(stage), original)
                with patch.object(C, "bounded_roster", return_value=changed), self.assertRaisesRegex(C.Refused, "private-registry-originals"):
                    C.registry_originals(stage)

    def test_tool_package_versions_are_only_projected_after_original_payload_correspondence(self):
        row = {"path": "/usr/bin/git", "package": "git", "version": "2.43.0-1ubuntu7.3", "bytes": 20,
               "sha256": "a" * 64, "mode": "0o755", "provenance": {"archiveSha256": "b" * 64, "member": "usr/bin/git"}}
        catalogue = {"hostFiles": [row], "hostDirectories": [], "hostAliases": []}
        pin = {"identity": [7, 31, 0o100755, 1, 0, 0, 20, 10, 11],
               **{key: row[key] for key in ("bytes", "sha256", "mode")}}
        with patch.object(C, "read", return_value=(b"inert DATA", pin)), patch.object(C, "command") as command, \
             patch.object(C, "authenticate_absent_host_inputs") as absence, \
             patch.object(C, "python_alias_begin", return_value={"files": {}}) as chains, \
             patch.object(C, "authenticate_python_runtime") as runtime:
            C.authenticate_host(catalogue)
        command.assert_not_called()
        absence.assert_called_once_with(catalogue)
        runtime.assert_called_once_with(catalogue)
        chains.assert_called_once_with(catalogue)
        self.assertIn("not-retroactive", C._EVIDENCE["hostAuthenticationScope"])
        self.assertEqual(C._EVIDENCE["hostToolSuppliers"][0]["packageVersion"], row["version"])
        self.assertEqual(C._EVIDENCE["hostToolSuppliers"][0]["basis"],
                         "authenticated-supplier-payload-correspondence; version-probe-not-run")
        C._EVIDENCE["hostToolSuppliers"] = None
        with patch.object(C, "read", return_value=(b"changed", {**pin, "sha256": "f" * 64})), \
             patch.object(C, "authenticate_absent_host_inputs") as absence, patch.object(C, "authenticate_python_runtime"), \
             patch.object(C, "python_alias_originals", return_value={"files": {}}) as chains:
            with self.assertRaisesRegex(C.Refused, "host-tool-payload-differs"):
                C.authenticate_host(catalogue, after=True)
        absence.assert_called_once_with(catalogue)
        chains.assert_called_once_with()
        self.assertIsNone(C._EVIDENCE["hostToolSuppliers"])

    @staticmethod
    def python_catalogue():
        root = C.PYTHON_STDLIB
        paths = C.PYTHON_REQUIRED_FILES | {root + "/os.py", root + "/__pycache__/os.cpython-312.pyc"}
        return {"hostFiles": [{"path": path} for path in sorted(paths)]
                    + [{"path": path, **pin} for path, pin in C.PYTHON_ALIAS_FILES.items()],
                "hostDirectories": [
                    {"path": root, "entries": ["__pycache__", "config-3.12-x86_64-linux-gnu", "ctypes",
                                               "lib-dynload", "os.py", "sitecustomize.py"]},
                    {"path": root + "/__pycache__", "entries": ["os.cpython-312.pyc"]},
                    {"path": root + "/ctypes", "entries": ["__init__.py"]},
                    {"path": root + "/lib-dynload", "entries": ["_ctypes.cpython-312-x86_64-linux-gnu.so"]},
                    {"path": root + "/config-3.12-x86_64-linux-gnu", "entries": ["libpython3.12.so"]}],
                "hostAliases": [{"path": "/usr/lib/x86_64-linux-gnu/libffi.so.8", "target": "libffi.so.8.1.4"}]
                    + [{"path": path, "target": target} for path, target in C.PYTHON_ALIAS_LINKS.items()]}

    def test_python_catalogue_requires_pyc_search_and_ctypes_ffi_inputs(self):
        value = self.python_catalogue()
        self.assertEqual(C.python_runtime_catalogue(value)["pinnedSourceCacheDataRows"], 1)
        self.assertEqual(len(C.PYTHON_ALIAS_LINKS), 3)
        library = "/usr/lib/x86_64-linux-gnu/libpython3.12.so.1.0"
        mutations = [lambda v: v["hostFiles"].pop(next(i for i, r in enumerate(v["hostFiles"]) if r["path"].endswith(".pyc"))),
                     lambda v: v["hostFiles"].pop(next(i for i, r in enumerate(v["hostFiles"]) if r["path"] == C.PYTHON_FFI)),
                     lambda v: v["hostFiles"].pop(next(i for i, r in enumerate(v["hostFiles"]) if "/_ctypes." in r["path"])),
                     lambda v: v["hostFiles"].append({"path": C.PYTHON_SEARCH[0]}),
                     lambda v: v["hostAliases"][0].update(target="unbound.so"),
                     lambda v: v["hostDirectories"][0]["entries"].append("unbound.py"),
                     lambda v: v["hostDirectories"][1]["entries"].append("unbound.pyc"),
                     lambda v: v["hostAliases"].append({"path": C.PYTHON_STDLIB + "/outside.py", "target": "/unbound"}),
                     lambda v: v["hostAliases"].pop(2),
                     lambda v: v["hostAliases"][2].update(target="libpython3.12.so.1"),
                     lambda v: (v["hostAliases"][2].update(target="extra.so"),
                                v["hostAliases"].append({"path": "/usr/lib/x86_64-linux-gnu/extra.so", "target": "libpython3.12.so.1.0"})),
                     lambda v: v["hostFiles"].pop(next(i for i, r in enumerate(v["hostFiles"]) if r["path"] == library)),
                     lambda v: v["hostAliases"][1].update(target="../../x86_64-linux-gnu/unbound.so"),
                     lambda v: v["hostAliases"][2].update(target="/usr/lib/python3.12/__pycache__/os.cpython-312.pyc"),
                     lambda v: v["hostDirectories"].append({"path": library, "entries": []}),
                     lambda v: v["hostFiles"].append({"path": "/usr/lib/x86_64-linux-gnu/libpython3.12.so.1"}),
                     lambda v: next(r for r in v["hostFiles"] if r["path"] == library).update(sha256="f" * 64)]
        with patch.object(C, "command") as command, patch.object(C, "read") as read:
            for mutate in mutations:
                changed = copy.deepcopy(value)
                mutate(changed)
                with self.subTest(mutation=mutate), self.assertRaises(C.Refused):
                    C.python_runtime_catalogue(changed)
        command.assert_not_called()
        read.assert_not_called()

    def test_actual_python_selection_binds_reexec_search_and_bytecode_read_policy(self):
        selected = SimpleNamespace(executable=C.PYTHON_EXECUTABLE, path=list(C.PYTHON_SEARCH),
            implementation=SimpleNamespace(name="cpython", cache_tag="cpython-312"),
            prefix="/usr", base_prefix="/usr", exec_prefix="/usr", base_exec_prefix="/usr",
            flags=SimpleNamespace(isolated=1, no_site=1, optimize=0), dont_write_bytecode=True,
            pycache_prefix=str(C.PYTHON_PYCACHE))
        value = self.python_catalogue()
        with patch.object(C, "sys", selected), patch.object(Path, "lstat", return_value=file_info()), \
             patch.object(C, "root_absent") as absent, patch.object(C, "command") as command, \
             patch.object(C, "pycache_original", return_value=self.pycache_fixture()) as custody:
            C.authenticate_python_runtime(value)
        custody.assert_called_once_with()
        absent.assert_called_once_with(C.PYTHON_SEARCH[0], "python-zip-search")
        command.assert_not_called()
        self.assertEqual(C._EVIDENCE["pythonRuntime"]["pinnedSourceCacheDataRows"], 1)
        self.assertEqual(C._EVIDENCE["pythonRuntime"]["bytecodePolicy"], "fixed-normal-source-cache-miss; existing-pyc-pinned-data; implicit-writes-disabled")
        self.assertEqual(C._EVIDENCE["pythonRuntime"]["pycachePrefix"], str(C.PYTHON_PYCACHE))
        self.assertEqual(C._EVIDENCE["pythonRuntime"]["normalSourceCacheInputs"], 0)
        self.assertFalse(C._EVIDENCE["pythonRuntime"]["sourcelessOrZipExecutionDisabled"])
        self.assertFalse(C._EVIDENCE["pythonRuntime"]["oldCachesPhysicallyInaccessible"])
        with patch.object(C, "sys", selected), patch.object(C, "command") as command:
            with self.assertRaisesRegex(C.Refused, "pycache-original-custody-required"):
                C.authenticate_python_runtime(value)
        command.assert_not_called()
        for field, changed in (("executable", "/other/python3.12"), ("path", ["/other", *C.PYTHON_SEARCH]),
                               ("base_prefix", "/venv"), ("pycache_prefix", None), ("pycache_prefix", "/unbound"),
                               ("pycache_prefix", str(C.PYTHON_PYCACHE) + "/"), ("dont_write_bytecode", False),
                               ("flags", SimpleNamespace(isolated=1, no_site=0, optimize=0))):
            fake = copy.deepcopy(selected)
            setattr(fake, field, changed)
            with self.subTest(field=field), patch.object(C, "sys", fake), patch.object(C, "root_absent") as absent:
                with self.assertRaisesRegex(C.Refused, "actual-python-runtime-selection"):
                    C.authenticate_python_runtime(value)
            absent.assert_not_called()
        source = (ROOT / "desktop/tools/gnome_session_hosted.py").read_text()
        main = source.split("def main():", 1)[1]
        self.assertLess(main.index("authenticate_host(catalogue)"), main.index("owner_modules(SOURCE, catalogue)"))
        supply = source.split("def supply_bwrap(", 1)[1].split("\ndef bwrap_supply_for(", 1)[0]
        self.assertLess(supply.index("authenticate_bwrap_absent(catalogue)"),
                        supply.index("owner_modules(SOURCE, catalogue)"))
        process = (ROOT / "src/mobile_release/_command_process.py").read_text()
        self.assertIn("executable = os.path.abspath(sys.executable)", process)
        self.assertIn('argv = (executable, "-I", "-S", "-B", *cache_args, "-c", _BOOTSTRAP', process)
        self.assertIn('("-X", "pycache_prefix=/run/mrk-gnome-python-empty-pycache-v1")', process)
        self.check_python_alias_custody()

    def check_python_alias_custody(self):
        # Same actual-selection selector, with a finite inert FD graph. Nothing
        # opens, reads or closes a real host file, and no candidate tool runs.
        payloads = {path: ("inert terminal " + str(i) + "\n").encode()
                    for i, path in enumerate(C.PYTHON_ALIAS_FILES)}
        terminals = {path: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": "0o644"}
                     for path, raw in payloads.items()}
        first_link, first_file = next(iter(C.PYTHON_ALIAS_LINKS)), next(iter(terminals))
        cases = ("good", "parent-owner", "parent-alias", "link-kind", "link-text", "terminal-bytes",
                 "open-replaced", "fstat-and-close", "read-and-close", "parent-replaced", "link-replaced",
                 "terminal-replaced", "link-during-read", "earlier-file-during-read", "sibling-change",
                 "close-failed", "post-bytes-and-close", "originals-unsettled")
        with patch.object(C, "_PYTHON_ALIASES", None), patch.object(C.os, "open") as opened:
            with self.assertRaisesRegex(C.Refused, "python-alias-originals-required"):
                C.python_alias_originals()
            opened.assert_not_called()
        for case in cases:
            paths = [*C.PYTHON_ALIAS_PARENTS, *C.PYTHON_ALIAS_LINKS, *terminals]
            infos = {}
            for i, path in enumerate(paths):
                mode = stat.S_IFDIR | 0o755 if path in C.PYTHON_ALIAS_PARENTS else (
                    stat.S_IFLNK | 0o777 if path in C.PYTHON_ALIAS_LINKS else stat.S_IFREG | 0o644)
                info = file_info(mode=mode)
                info.st_ino = 100 + i
                info.st_size = (len(C.PYTHON_ALIAS_LINKS[path]) if path in C.PYTHON_ALIAS_LINKS else
                                len(payloads[path]) if path in payloads else 4096)
                infos[path] = info
            if case == "parent-owner":
                infos["/etc"].st_uid = 1001
            if case == "parent-alias":
                infos["/usr/lib"].st_mode = stat.S_IFLNK | 0o777
            if case == "link-kind":
                infos[first_link].st_mode = stat.S_IFREG | 0o644
            descriptors, opened, closed = {}, [], []
            state = {"after": False, "drift": None}
            primary = OSError("inert selected-original observation failure")
            close_bad = case in ("fstat-and-close", "read-and-close", "close-failed", "post-bytes-and-close")

            def path_for(name, dir_fd):
                return str(Path(name) if dir_fd is None else Path(descriptors[dir_fd]) / name)

            def opening(name, flags, *, dir_fd=None):
                path = path_for(name, dir_fd)
                self.assertIn(path, paths)
                self.assertTrue(flags & C.os.O_NOFOLLOW and flags & C.os.O_CLOEXEC)
                if path in C.PYTHON_ALIAS_PARENTS:
                    self.assertTrue(flags & C.os.O_DIRECTORY)
                elif path in C.PYTHON_ALIAS_LINKS:
                    self.assertTrue(flags & C.os.O_PATH)
                else:
                    self.assertTrue(flags & C.os.O_NONBLOCK)
                fd = 90 + len(opened)
                descriptors[fd] = path
                opened.append(fd)
                return fd

            def named(name, *, dir_fd=None, follow_symlinks=False):
                self.assertFalse(follow_symlinks)
                path = path_for(name, dir_fd)
                info = copy.copy(infos[path])
                if state["drift"] == path or state["after"] and ((case == "parent-replaced" and path == "/usr/lib") or
                    (case == "link-replaced" and path == first_link) or
                    (case == "terminal-replaced" and path == first_file)):
                    info.st_ino += 1000  # Same body/link spelling is still a different original.
                if state["after"] and case == "sibling-change" and path in C.PYTHON_ALIAS_PARENTS:
                    info.st_nlink += 1
                    info.st_mtime_ns += 100
                    info.st_ctime_ns += 100
                return info

            def fstat(fd):
                self.assertIn(fd, C._PYTHON_ALIASES["fds"])  # Acquired before fallible fstat.
                if case == "fstat-and-close" and len(opened) == 3:
                    raise primary
                info = copy.copy(infos[descriptors[fd]])
                if case == "open-replaced" and descriptors[fd] == first_file:
                    info.st_ino += 1000
                return info

            def readlink(name, *, dir_fd):
                path = path_for(name, dir_fd)
                return "different" if case == "link-text" and path == first_link else C.PYTHON_ALIAS_LINKS[path]

            def pread(fd, count, offset):
                path = descriptors[fd]
                self.assertIn(path, payloads)
                self.assertGreater(count, 0)
                self.assertLessEqual(count, 65536)
                if case == "read-and-close":
                    raise primary
                if case == "link-during-read":
                    state["drift"] = first_link
                elif case == "earlier-file-during-read" and path != first_file:
                    state["drift"] = first_file
                raw = payloads[path]
                if case == "terminal-bytes" or case == "post-bytes-and-close" and state["after"]:
                    raw = raw[::-1]
                return raw[offset:offset + count]

            def close(fd):
                self.assertNotIn(fd, closed)
                self.assertNotIn(fd, C._PYTHON_ALIASES["fds"])
                closed.append(fd)
                if close_bad and fd in opened[:2]:
                    raise OSError("inert consuming-close Unknown")

            early = case in ("parent-owner", "parent-alias", "link-kind", "link-text", "terminal-bytes",
                             "open-replaced", "fstat-and-close", "read-and-close", "link-during-read", "earlier-file-during-read")
            with self.subTest(alias_case=case), patch.object(C, "_PYTHON_ALIASES", None), \
                 patch.object(C, "_ORIGINALS_SETTLED", True), patch.object(C, "PYTHON_ALIAS_FILES", terminals), \
                 patch.dict(C._EVIDENCE, {"pythonAliasCustody": None}), \
                 patch.object(C.os, "open", side_effect=opening), patch.object(C.os, "fstat", side_effect=fstat), \
                 patch.object(C.os, "stat", side_effect=named), patch.object(Path, "lstat", lambda path: named(str(path))), \
                 patch.object(C.os, "readlink", side_effect=readlink), patch.object(C.os, "pread", side_effect=pread), \
                 patch.object(C.os, "close", side_effect=close), patch.object(C, "command") as command, \
                 patch.object(C, "read", side_effect=AssertionError("selected terminals must use held FDs")) as generic_read:
                if early:
                    with self.assertRaises(OSError if case in ("fstat-and-close", "read-and-close") else C.Refused) as failure:
                        C.python_alias_begin(self.python_catalogue())
                    if case in ("fstat-and-close", "read-and-close"):
                        self.assertIs(failure.exception, primary)
                else:
                    original = C.python_alias_begin(self.python_catalogue())
                    self.assertEqual(len(opened), 13)
                    self.assertEqual(closed, [])
                    self.assertEqual(original, C.python_alias_originals())
                    with self.assertRaisesRegex(C.Refused, "python-alias-phase-already-started"):
                        C.python_alias_begin(self.python_catalogue())
                    self.assertEqual(len(opened), 13)
                    state["after"] = True
                    if case == "originals-unsettled":
                        C._ORIGINALS_SETTLED = False
                    if case in ("good", "sibling-change"):
                        self.assertEqual(original, C.python_alias_originals())
                        C.python_alias_finish()
                        self.assertTrue(C._EVIDENCE["pythonAliasCustody"]["phaseCustodyPostchecked"])
                    else:
                        with self.assertRaises(C.Refused) as failure:
                            C.python_alias_finish()
                        if case == "post-bytes-and-close":
                            self.assertEqual(str(failure.exception), "python-alias-terminal-bytes")
                self.assertEqual(closed, list(reversed(opened)))
                self.assertTrue(C._PYTHON_ALIASES["closed"])
                self.assertEqual(C._EVIDENCE["pythonAliasCustody"]["closeErrors"], 2 if close_bad else 0)
                self.assertEqual(C._EVIDENCE["pythonAliasCustody"]["phaseHandlesClosed"], not close_bad)
                self.assertEqual(C._ORIGINALS_SETTLED, not close_bad and case != "originals-unsettled")
                C.python_alias_finish(failed=True)  # Main's refusal path must not retry any close.
                self.assertEqual(closed, list(reversed(opened)))
                command.assert_not_called()
                generic_read.assert_not_called()

    @staticmethod
    def pycache_fixture():
        infos = [file_info(mode=stat.S_IFDIR | mode) for mode in (0o755, 0o755, 0o555)]
        for index, info in enumerate(infos):
            info.st_ino = 100 + index
        return {"path": str(C.PYTHON_PYCACHE), "identity": C.identity(infos[-1]), "entries": [],
                "parents": [{"path": path, "custody": C.directory_custody(info)}
                            for path, info in zip(("/", "/run"), infos)]}

    def test_real_command_spec_keeps_only_the_fixed_cache_policy_on_every_reexec(self):
        # Actual shared callable; only effects/permit construction are inert.
        # Do not alter the test interpreter's own cache selection while importing.
        with patch.object(sys, "path", [str(ROOT / "src"), *sys.path]):
            from mobile_release import _command_process as process
        for parent, child in (("O", "C"), ("C", "A"), ("A", "W")):
            for prefix in (None, str(C.PYTHON_PYCACHE), "/unbound", "", str(C.PYTHON_PYCACHE) + "/",
                           Path(C.PYTHON_PYCACHE), True):
                with self.subTest(parent=parent, child=child, prefix=prefix):
                    context = SimpleNamespace(check=Mock(), role=parent, child_acquisition=object(),
                        pid=17, run=41, hard=51, nonce=b"x" * 16)
                    hold = None if child == "W" else SimpleNamespace(uid=61000, identity=(7, 99))
                    sources = tuple(SimpleNamespace(account_binding=hold if i == 5 else None) for i in range(8))
                    selected = SimpleNamespace(executable=C.PYTHON_EXECUTABLE, pycache_prefix=prefix,
                                               _xoptions={"pycache_prefix": "/ambient", "importtime": True})
                    permit, spec = object(), object()
                    with patch.object(process, "sys", selected), \
                         patch.object(process.os, "getsid", return_value=21), \
                         patch.object(process.os, "getpgrp", return_value=22), \
                         patch.dict(process.os.environ, {"PYTHONPYCACHEPREFIX": "/ambient"}), \
                         patch.object(process.native, "_issue_command_map", return_value=permit) as issue, \
                         patch.object(process.native, "SpawnSpec", return_value=spec) as construct:
                        admitted = prefix is None or type(prefix) is str and prefix == str(C.PYTHON_PYCACHE)
                        if not admitted:
                            with self.assertRaises(process.ProcessError):
                                process._command_spec(context, child, sources)
                            context.check.assert_not_called()
                            issue.assert_not_called()
                            construct.assert_not_called()
                            continue
                        self.assertIs(process._command_spec(context, child, sources), spec)
                    context.check.assert_called_once_with()
                    options = () if prefix is None else ("-X", "pycache_prefix=" + str(C.PYTHON_PYCACHE))
                    root = str(Path(process.__file__).resolve().parent.parent)
                    tail = (process._BOOTSTRAP, root, child, "17", "21", "22", "41", "51",
                            (b"x" * 16).hex(), "-" if child == "W" else "61000,7,99", "1")
                    argv = (C.PYTHON_EXECUTABLE, "-I", "-S", "-B", *options, "-c", *tail)
                    env = (("PATH", process.os.defpath), ("LC_ALL", "C"), ("LANG", "C"))
                    issue.assert_called_once_with(context.child_acquisition, role=child,
                        command_nonce=context.nonce, executable=C.PYTHON_EXECUTABLE, argv=argv,
                        env=env, fd_sources=sources)
                    construct.assert_called_once_with(C.PYTHON_EXECUTABLE, argv, env, sources, command_map=permit)
                    self.assertIs(issue.call_args.kwargs["fd_sources"], sources)
                    self.assertIs(construct.call_args.args[3], sources)
                    if prefix is None:
                        self.assertEqual(argv[:5], (C.PYTHON_EXECUTABLE, "-I", "-S", "-B", "-c"))
        native = (ROOT / "src/mobile_release/_native_process.py").read_text()
        self.assertIn("self._recipe == (spec.executable, spec.argv, spec.env)", native)
        self.assertIn("all(left is right for left, right in zip(self._sources, spec.fd_sources))", native)

    def test_all_gnome_launches_have_the_fixed_prestartup_option_and_no_live_cleanup(self):
        literal = "/run/mrk-gnome-python-empty-pycache-v1"
        shell_python = "/usr/bin/python3.12 -I -S -B -X pycache_prefix=" + literal + " "
        workflow = (ROOT / C.WORKFLOW).read_text()
        launches = [line.strip() for line in workflow.splitlines() if "/usr/bin/python3.12 " in line]
        self.assertEqual(len(launches), 4)  # prepare/acquire share one fixed loop.
        self.assertTrue(all(line.startswith(shell_python) for line in launches))
        self.assertIn("for phase in prepare acquire; do", workflow)
        bootstrap = workflow.split("<<'PYCACHE_BOOTSTRAP'\n", 1)[1].split("\n          PYCACHE_BOOTSTRAP", 1)[0]
        mkdir = "/usr/bin/mkdir -m 0555 -- " + literal
        self.assertEqual(bootstrap.count(mkdir), 1)
        self.assertEqual([line.strip() for line in bootstrap.splitlines() if line.strip().startswith("/usr/bin/mkdir")], [mkdir])
        self.assertNotIn("mkdir -p", bootstrap.split("# Exclusive mkdir", 1)[0])
        self.assertIn('[[ -d "$path" && ! -L "$path" ]] || return 1', bootstrap)
        self.assertIn('(16#$mode & 0022) == 0', bootstrap)
        self.assertIn('&& "$uid" == 0 && "$gid" == 0', bootstrap)
        self.assertIn('[[ "$root_after" == "$root_before" && "$run_after" == "$run_before" ]]', bootstrap)
        self.assertIn('[[ "$leaf" == 555:0:0:directory ]]', bootstrap)
        self.assertLess(workflow.index(mkdir), workflow.index(shell_python))
        argv = C.owner_argv()
        bind = argv.index(literal)
        self.assertEqual(argv[bind - 1:bind + 2], ["--ro-bind", literal, literal])
        self.assertLess(bind, argv.index("--remount-ro"))
        self.assertIn(["--dir", "/run"], [argv[i:i + 2] for i in range(len(argv) - 1)])
        start = argv.index("/usr/bin/python3.12")
        self.assertEqual(argv[start:], ["/usr/bin/python3.12", "-I", "-S", "-B", "-X",
                                       "pycache_prefix=" + literal, "/owner.py"])
        compile_only = (ROOT / "desktop/tools/gnome_session_native/compile-only.sh").read_text()
        self.assertIn(shell_python + "/prepare.py prepare", compile_only)
        self.assertIn(shell_python + '/check-compile.py "$phase"', compile_only)
        owner = (ROOT / "desktop/tools/gnome_session_native/owner.py").read_text()
        self.assertIn('["/usr/bin/python3.12", "-I", "-S", "-B", "-X", "pycache_prefix='
                      + literal + '", "/prepare.py", "post"]', " ".join(owner.split()))
        for name in ("prepare.py", "check-compile.py"):
            script = (ROOT / "desktop/tools/gnome_session_native" / name).read_text()
            self.assertIn("sys.pycache_prefix == '" + literal + "'", script)
            self.assertLess(script.index("sys.pycache_prefix"), script.index("read_bytes()"))
        self.assertNotIn("/usr/bin/python", (ROOT / "desktop/tools/gnome_session_native/native-entry.sh").read_text())
        source = (ROOT / "desktop/tools/gnome_session_hosted.py").read_text()
        for function, destination in (("supply_bwrap", 'write(BWRAP_SUPPLY / "receipt.json"'),
                                      ("prepare", 'write(TASK / "controls/prepared.json"'),
                                      ("acquire", 'write(TASK / "controls/acquired.json"'),
                                      ("run_native", 'write(TASK / "controls/native-result.json"'),
                                      ("settle", 'write(PUBLIC / "result.json"')):
            body = source.split("def " + function + "(", 1)[1].split("\ndef ", 1)[0]
            self.assertLess(body.index("python_alias_finish()"), body.index("pycache_finish()"))
            self.assertLess(body.index("pycache_finish()"), body.index(destination))
        main = source.split("def main():", 1)[1]
        self.assertIn('"python-alias-phase-not-closed"', main)
        self.assertLess(main.index("python_alias_finish(failed=True)"), main.index("pycache_finish(failed=True)"))
        cleanup = source.split("def remove_settled(", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("Path(root).is_relative_to(TASK)", cleanup)
        self.assertNotIn("PYTHON_PYCACHE", cleanup)
        self.assertNotIn("rmdir", source.split("def pycache_empty(", 1)[1].split("\ndef capath_state(", 1)[0])
        self.assertNotIn("unlink", bootstrap)
        self.assertNotIn("rmdir", bootstrap)
        with patch.object(C, "bounded_roster") as roster:
            with self.assertRaisesRegex(C.Refused, "settled-cleanup-correspondence"):
                C.remove_settled(C.PYTHON_PYCACHE, {})
        roster.assert_not_called()

    def test_gnome_entries_refuse_none_and_wrong_prefix_before_any_phase_or_helper(self):
        for prefix in (None, "/unbound", str(C.PYTHON_PYCACHE) + "/", Path(C.PYTHON_PYCACHE)):
            for phase in ("supply-bwrap", "prepare", "acquire", "run", "settle"):
                selected = SimpleNamespace(argv=["inert", phase], flags=SimpleNamespace(isolated=1, no_site=1),
                                           dont_write_bytecode=True, pycache_prefix=prefix)
                with self.subTest(prefix=prefix, phase=phase), patch.object(C, "sys", selected), \
                     patch.object(C, "read") as read, patch.object(C, "pycache_for_phase") as begin, \
                     patch.object(C, "command") as command, patch("builtins.print") as output:
                    self.assertEqual(C.main(), 1)
                output.assert_called_once_with("GNOME_HOSTED_REFUSAL=fixed-isolated-controller-entry", flush=True)
                for blocked in (read, begin, command):
                    blocked.assert_not_called()
            selected.argv = ["inert-owner"]
            with patch.object(N, "sys", selected), patch.multiple(N, report={}, errors=[], native_accepted=False,
                 pycache_fds=[], pycache_state=None), patch.object(N, "owner_identity") as identity, \
                 patch.object(N, "data") as data, patch.object(N, "invoke") as invoke, patch.object(N, "emit"):
                self.assertEqual(N.main(), 1)
                self.assertEqual(N.errors, ["operation:isolated-owner-entry"])
            for blocked in (identity, data, invoke):
                blocked.assert_not_called()

    def test_cache_data_roster_refuses_direct_bytecode_and_pyc_aliases_without_deleting_old_rows(self):
        value = self.python_catalogue()
        for case in ("legacy", "missing-source", "pyc-alias", "source-alias-to-pyc"):
            changed = copy.deepcopy(value)
            root = C.PYTHON_STDLIB
            if case == "legacy":
                changed["hostFiles"].append({"path": root + "/legacy.pyc"})
                changed["hostDirectories"][0]["entries"] = sorted([*changed["hostDirectories"][0]["entries"], "legacy.pyc"])
            elif case == "missing-source":
                changed["hostFiles"] = [row for row in changed["hostFiles"] if row["path"] != root + "/os.py"]
                changed["hostDirectories"][0]["entries"].remove("os.py")
            else:
                name = "alias.pyc" if case == "pyc-alias" else "alias.py"
                changed["hostAliases"].append({"path": root + "/" + name, "target": "__pycache__/os.cpython-312.pyc"})
                changed["hostDirectories"][0]["entries"] = sorted([*changed["hostDirectories"][0]["entries"], name])
            with self.subTest(case=case), patch.object(C, "command") as command, patch.object(C, "read") as read:
                with self.assertRaisesRegex(C.Refused, "python-runtime-(direct-bytecode-route|cache-source|bytecode-alias)"):
                    C.python_runtime_catalogue(changed)
            command.assert_not_called()
            read.assert_not_called()
        source = (ROOT / "desktop/tools/gnome_session_hosted.py").read_text()
        loader = source.split("def host_module(", 1)[1].split("\ndef ", 1)[0]
        self.assertIn('"host-admit.py"', loader)
        self.assertIn("spec_from_file_location", loader)
        imports = source.split("def owner_modules(", 1)[1].split("\ndef ", 1)[0]
        self.assertLess(imports.index('"original-owner-source-differs"'), imports.index("from mobile_release import owned_process"))
        self.assertIn('getattr(module, "__file__", None) in allowed', imports)

    def test_exact_source_run_workflow_and_host_must_agree(self):
        self.assertEqual(C.workflow_context(environment())["sourceSha"], "a" * 40)
        for key, value in (("GITHUB_WORKFLOW_SHA", "b" * 40), ("MRK_PUSH_EVENT_AFTER", "b" * 40),
                           ("GITHUB_REF", "refs/heads/main"), ("RUNNER_ENVIRONMENT", "self-hosted"),
                           ("GITHUB_RUN_ATTEMPT", "0"), ("ImageVersion", "different-image")):
            with self.subTest(key=key), self.assertRaises(C.Refused):
                C.workflow_context({**environment(), key: value})

    def test_unresolved_supplier_catalogue_fails_before_tools_or_accounts(self):
        value = json.loads((ROOT / "desktop/tools/gnome_session_native/runtime-suppliers.json").read_text())
        self.assertEqual(len(value["product"]), 964)
        # A source catalogue is not an execution grant. If suppliers are later
        # closed, this still tests the genuine missing-fact branch directly.
        value["unresolved"] = ["missing-native-package-member"]
        with self.assertRaisesRegex(C.Refused, "supplier-facts-unresolved"):
            C.catalogue_ready(value)

    def test_supplier_population_preserves_native_layout_private_rust_modes_and_host_refusal(self):
        value = json.loads((ROOT / "desktop/tools/gnome_session_native/runtime-suppliers.json").read_text())
        layout = json.loads((ROOT / "desktop/tools/gnome_session_native/runtime-layout.json").read_text())
        self.assertIn("complete-actual-host-outer-tool-and-stdlib-supplier-closure", value["unresolved"])
        self.assertIn("python-two-alias-text-target-and-ancestry-acceptance", value["unresolved"])
        self.assertIn("cargo-resolver-exact-parent-observation-acceptance", value["unresolved"])
        self.assertEqual(value["hostAbsent"], ["/etc/ld.so.preload"])
        self.assertEqual(value["bootstrapTrust"], C.BOOTSTRAP_TRUST)
        self.assertFalse(value["bootstrapTrust"]["retroactiveAuthentication"])
        self.assertTrue(value["bootstrapTrust"]["subsequentExactGuardsRequired"])
        counts = value["consumerClosure"]["counts"]
        self.assertEqual((counts["pythonRegularLeaves"], counts["pythonDirectoryRosters"], counts["pythonPycLeaves"]),
                         (1213, 93, 573))
        for key in ("hostFiles", "hostDirectories", "hostAliases"):
            self.assertEqual(len(value[key]), counts[key])
            self.assertTrue(value[key])
        self.assertFalse(value["consumerClosure"]["runtimeQualified"] or value["consumerClosure"]["gateClearingApproved"])
        self.assertTrue(all(not row["path"].startswith("/usr/share/ca-certificates") for row in value["hostFiles"]))
        # The exact chains now close the structural roster, not runtime gates.
        self.assertEqual(C.python_runtime_catalogue(value), {"stdlibInputs": 1309, "pinnedSourceCacheDataRows": 573})
        self.assertEqual((len(value["hostFiles"]), len(value["hostAliases"])), (1315, 61))
        self.assertEqual({row["path"] for row in value["consumerClosure"]["rows"][0]["parentMetadata"]},
                         set(C.PYTHON_ALIAS_PARENTS))
        self.assertEqual(C.native_layout(value, layout), layout)
        self.assertEqual(len(value["nativePackages"]), 29)
        self.assertEqual(sum(len(row["members"]) for row in value["nativePackages"]), 34)
        self.assertEqual([row["memberLimit"] for row in value["nativePackages"][-3:]], [256, 256, 256])
        self.assertTrue(all(row["provenance"]["gnomeCatalogueSha256"] ==
                            "d301af5d7fb2a0e6a9f3e06253a6d98222195e7fbec93c4321678becf0d3dace"
                            for row in value["nativePackages"][-3:]))
        members = [member for row in value["rust"] for member in row["members"]]
        self.assertEqual(len(members), 74)
        self.assertEqual(len({member["target"] for member in members}), 74)
        self.assertEqual(sum(member["bytes"] for member in members), 571579677)
        self.assertEqual(sum(member["mode"] == "0o500" for member in members), 10)
        self.assertEqual(sum(member["mode"] == "0o400" for member in members), 64)
        self.assertTrue(all(member["archiveMode"] in ("0o644", "0o755") for member in members))
        self.assertTrue(all(row["releaseVersion"] == "1.98.0" for row in value["rust"]))
        self.assertEqual(value["rust"][0]["componentDeclaredVersion"], "0.99.0 (797e8a9bc 2026-08-05)")
        for row in (*value["nativePackages"], *value["rust"]):
            for key in ("bytes", "decodedBytes", "memberLimit", "expandedLimit"):
                self.assertIs(type(row[key]), int)
                self.assertGreater(row[key], 0)
            for key in ("sha256", "decodedSha256"):
                self.assertRegex(row[key], r"^[0-9a-f]{64}$")
            self.assertTrue(row["provenance"])
        # Supplier DATA cannot authorize the still-unobserved hosted boundary.
        with self.assertRaisesRegex(C.Refused, "supplier-facts-unresolved"):
            C.catalogue_ready(value)
        # Inert host scaffolding reaches the remaining pure schema checks;
        # it is never passed to host authentication or an execution phase.
        inert = copy.deepcopy(value)
        inert["unresolved"] = []
        python = self.python_catalogue()
        cargo_paths = set(inert["cargoAcquisition"]["hostLibraries"]) | set(C.CARGO_DNS_TARGETS[:-1])
        inert["hostFiles"] = [{"path": path, "package": "inert", "version": "0",
                                "provenance": {"basis": "synthetic-test-only"}}
                              for path in sorted(C.FIXED_HOST_ROLES | cargo_paths | {row["path"] for row in python["hostFiles"]})]
        inert["hostDirectories"] = python["hostDirectories"]
        inert["hostAliases"] = python["hostAliases"]
        for row in inert["hostFiles"]:
            if row["path"] in C.PYTHON_ALIAS_FILES:
                row.update(C.PYTHON_ALIAS_FILES[row["path"]])
        supplier = inert["bwrapSupplier"]
        member = supplier["members"][0]
        target = next(row for row in inert["hostFiles"] if row["path"] == str(C.BWRAP_TARGET))
        target.update(bytes=member["bytes"], sha256=member["sha256"], mode="0o755",
                      package=supplier["package"], version=supplier["version"], provenance=supplier["provenance"])
        self.assertEqual(C.catalogue_ready(inert), inert)
        changed = copy.deepcopy(inert)
        changed["bootstrapTrust"]["retroactiveAuthentication"] = True
        with self.assertRaisesRegex(C.Refused, "explicit-provider-bootstrap-boundary"):
            C.catalogue_ready(changed)
        inert["hostAbsent"] = []
        with self.assertRaisesRegex(C.Refused, "host-absent-input-contract"):
            C.catalogue_ready(inert)

    @staticmethod
    def bwrap_host_fixture():
        value = json.loads((ROOT / "desktop/tools/gnome_session_native/runtime-suppliers.json").read_text())
        row = value["bwrapSupplier"]
        member = row["members"][0]
        target = {"path": str(C.BWRAP_TARGET), "bytes": member["bytes"], "sha256": member["sha256"],
                  "mode": "0o755", "package": row["package"], "version": row["version"],
                  "provenance": copy.deepcopy(row["provenance"])}
        peer = {"path": "/usr/bin/cat", "bytes": 5, "sha256": "c" * 64, "mode": "0o755",
                "package": "inert", "version": "0", "provenance": {"basis": "inert-test-only"}}
        # Only a pure-function fixture, never a ready execution catalogue.
        return {"bwrapSupplier": row, "hostFiles": [target, peer],
                "hostDirectories": [{"path": "/usr/bin", "entries": ["bwrap", "cat"]}], "hostAliases": []}

    def test_bwrap_contract_is_one_retained_member_and_cannot_close_the_native_gate(self):
        value = json.loads((ROOT / "desktop/tools/gnome_session_native/runtime-suppliers.json").read_text())
        row = C.bwrap_archive(value)
        self.assertEqual((row["package"], row["version"], row["bytes"], row["decodedBytes"]),
                         ("bubblewrap", "0.9.0-1ubuntu0.1", 50178, 133120))
        self.assertEqual((row["memberLimit"], row["expandedLimit"]), (260, 133120))
        self.assertEqual([(m["member"], m["target"], m["mode"], m["bytes"]) for m in row["members"]],
                         [("usr/bin/bwrap", "bwrap", "0o400", 72160)])
        for mutate in (lambda r: r.update(url=r["url"] + "?fallback=1"),
                       lambda r: r.update(sha256="0" * 64), lambda r: r.update(format="tar.xz"),
                       lambda r: r.update(memberLimit=261),
                       lambda r: r["members"][0].update(target="/usr/bin/bwrap"),
                       lambda r: r["members"][0].update(mode="0o755"),
                       lambda r: r["members"].append(copy.deepcopy(r["members"][0])),
                       lambda r: r["provenance"].update(basis="observed-host-repin")):
            changed = copy.deepcopy(value)
            mutate(changed["bwrapSupplier"])
            with self.subTest(mutate=mutate), self.assertRaisesRegex(C.Refused, "fixed-bwrap-supplier-contract"):
                C.bwrap_archive(changed)
        with patch.object(C, "owner_modules") as owner, patch.object(C, "command") as command, \
             patch.object(C, "bwrap_create_leaf") as create:
            with self.assertRaisesRegex(C.Refused, "supplier-facts-unresolved"):
                C.catalogue_ready(value)
        owner.assert_not_called()
        command.assert_not_called()
        create.assert_not_called()
        self.assertIn("complete-actual-host-outer-tool-and-stdlib-supplier-closure", value["unresolved"])

    def test_every_fixed_entry_refuses_unresolved_facts_before_source_owner_or_phase_dispatch(self):
        value = json.loads((ROOT / "desktop/tools/gnome_session_native/runtime-suppliers.json").read_text())
        for phase in ("supply-bwrap", "prepare", "acquire", "run", "settle"):
            entry = SimpleNamespace(argv=["inert-controller", phase],
                                    flags=SimpleNamespace(isolated=1, no_site=1), dont_write_bytecode=True,
                                    pycache_prefix=str(C.PYTHON_PYCACHE))
            with self.subTest(phase=phase), patch.object(C, "sys", entry), \
                 patch.object(C.os, "getresuid", return_value=(0, 0, 0)), \
                 patch.object(C.os, "getresgid", return_value=(0, 0, 0)), \
                 patch.object(C.os, "getgroups", return_value=[]), \
                 patch.object(C.os, "uname", return_value=SimpleNamespace(machine="x86_64")), \
                 patch.object(C.os, "environ", environment()), \
                 patch.object(C, "read", return_value=(C.canonical(value), {})) as read, \
                 patch.object(Path, "is_dir", return_value=False), patch("builtins.print") as output, \
                 patch.object(C, "native_layout") as layout, patch.object(C, "source_product") as source, \
                 patch.object(C, "authenticate_host") as host, patch.object(C, "supply_bwrap") as supply, \
                 patch.object(C, "owner_modules") as owner, patch.object(C, "command") as command:
                self.assertEqual(C.main(), 1)
            read.assert_called_once_with(C.SOURCE / C.CONTROL / "runtime-suppliers.json", 16 * C.MIB, root=False)
            output.assert_called_once_with("GNOME_HOSTED_REFUSAL=supplier-facts-unresolved", flush=True)
            for blocked in (layout, source, host, supply, owner, command):
                blocked.assert_not_called()

    def test_bwrap_prestate_checks_all_peers_and_preserves_the_original_pin_dictionary(self):
        value = self.bwrap_host_fixture()
        peer = value["hostFiles"][1]
        pin = {"identity": [7, 31, stat.S_IFREG | 0o755, 1, 0, 0, 5, 10, 11],
               **{key: peer[key] for key in ("bytes", "sha256", "mode")}}
        pins = C._PINS
        def read_peer(path, *args, **kwargs):
            if str(path) == str(C.BWRAP_TARGET):
                raise FileNotFoundError("inert absent target")
            self.assertEqual(str(path), peer["path"])
            return b"inert", pin
        with patch.object(C, "read", side_effect=read_peer), patch.object(C, "root_absent") as absent, \
             patch.object(C, "authenticate_absent_host_inputs"), patch.object(C, "authenticate_python_runtime"), \
             patch.object(C, "python_alias_begin", return_value={"files": {}}), \
             patch.object(C, "python_alias_originals", return_value={"files": {}}), \
             patch.object(Path, "lstat", return_value=file_info()), patch.object(C.os, "listdir", return_value=["cat"]):
            C.authenticate_bwrap_absent(value)
            C.authenticate_bwrap_absent(value, after=True)
            self.assertIs(C._PINS, pins)
            self.assertEqual(C._PINS, {peer["path"]: pin})
            # The full ordinary gate never accepts that absent-file pre-state.
            with self.assertRaises(FileNotFoundError):
                C.authenticate_host(value, after=True)
        self.assertEqual(absent.call_args.args, (C.BWRAP_TARGET, "bwrap-supplier-target"))
        self.assertEqual(value["hostDirectories"][0]["entries"], ["bwrap", "cat"])
        changed = copy.deepcopy(value)
        changed["hostDirectories"][0]["entries"] = ["cat"]
        with self.assertRaisesRegex(C.Refused, "bwrap-parent-final-roster"):
            C.authenticate_bwrap_absent(changed, after=True)
        for failure in (FileExistsError("occupied"), PermissionError("unknown absence")):
            with self.subTest(failure=type(failure)), patch.object(C, "root_absent", side_effect=failure), \
                 patch.object(C, "authenticate_host") as host:
                with self.assertRaises(type(failure)):
                    C.authenticate_bwrap_absent(value, after=True)
            host.assert_not_called()

    def test_bwrap_parent_delta_cannot_authorize_any_other_name_owner_mode_or_identity_change(self):
        parents = [{"path": path, "identity": C.identity(file_info())} for path in ("/", "/usr", "/usr/bin")]
        before = {"parents": parents, "entries": ["cat"]}
        after = copy.deepcopy(before)
        after["entries"] = ["bwrap", "cat"]
        self.assertIsNone(C.bwrap_parent_transition(before, after))
        for mutate in (lambda v: v["entries"].append("other"), lambda v: v["entries"].remove("cat"),
                       lambda v: v["parents"][2]["identity"].__setitem__(1, 99),
                       lambda v: v["parents"][2]["identity"].__setitem__(2, stat.S_IFDIR | 0o777),
                       lambda v: v["parents"][1]["identity"].__setitem__(3, 99),
                       lambda v: v["parents"][1]["identity"].__setitem__(4, 1000),
                       lambda v: v["parents"][2].update(path="/somewhere-else")):
            changed = copy.deepcopy(after)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaisesRegex(C.Refused, "bwrap-only-declared-parent-transition"):
                C.bwrap_parent_transition(before, changed)

    def test_bwrap_parent_handles_close_each_owned_fd_once_even_if_initial_fstat_or_close_fails(self):
        with patch.object(C.os, "open", side_effect=[31, 32]), \
             patch.object(C.os, "fstat", side_effect=[file_info(), OSError("inert-fstat")]), \
             patch.object(Path, "lstat", return_value=file_info()), patch.object(C.os, "close") as closed:
            with self.assertRaisesRegex(OSError, "inert-fstat"):
                C.bwrap_parent_handles()
        self.assertEqual([entry.args[0] for entry in closed.call_args_list], [32, 31])
        parents = [(Path("/"), 31, None), (Path("/usr"), 32, None)]
        with patch.object(C.os, "close", side_effect=[OSError("inert-close-unknown"), None]) as closed:
            with self.assertRaisesRegex(C.Refused, "bwrap-parent-close-unsettled"):
                C.bwrap_close_parents(parents)
            self.assertEqual(parents, [])
            C.bwrap_close_parents(parents)
        self.assertEqual([entry.args[0] for entry in closed.call_args_list], [32, 31])

    def test_bwrap_owned_fd_read_refuses_wrong_bytes_mode_owner_link_or_path_original(self):
        raw = b"inert"
        member = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        for case in ("good", "bytes", "grown", "executable", "owner", "links", "symlink", "replaced"):
            info = file_info(mode=stat.S_IFREG | (0o755 if case == "executable" else 0o600))
            info.st_size = len(raw)
            if case == "owner":
                info.st_uid = 1000
            if case == "links":
                info.st_nlink = 2
            named = copy.deepcopy(info)
            if case == "symlink":
                named.st_mode = stat.S_IFLNK | 0o777
            if case == "replaced":
                named.st_ino += 1
            body = b"other" if case == "bytes" else raw + b"x" if case == "grown" else raw
            with self.subTest(case=case), patch.object(C.os, "fstat", return_value=info), \
                 patch.object(C.os, "stat", return_value=named) as named_stat, \
                 patch.object(C.os, "lseek"), patch.object(C.os, "read", side_effect=[body, b""]), \
                 patch.object(C.os, "fchmod") as chmod, patch.object(C, "command") as command:
                if case == "good":
                    pin = C.bwrap_file_original(31, 17, member, 0o600)
                    self.assertEqual((pin["bytes"], pin["sha256"], pin["mode"]), (5, member["sha256"], "0o600"))
                    named_stat.assert_called_once_with("bwrap", dir_fd=17, follow_symlinks=False)
                else:
                    with self.assertRaises(C.Refused):
                        C.bwrap_file_original(31, 17, member, 0o600)
            chmod.assert_not_called()
            command.assert_not_called()

    def test_bwrap_exclusive_leaf_verifies_nonexecuting_original_before_one_final_chmod(self):
        raw = b"inert"
        member = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        for case in ("good", "occupied", "short-write", "body-refusal", "peer-refusal",
                     "changed-before-enable", "chmod-unknown", "post-refusal", "close-unknown"):
            events = []
            def observe(fd, parent, expected, mode):
                events.append(("observe", mode))
                self.assertEqual((fd, parent, expected), (31, 17, member))
                if case == "body-refusal" or case == "post-refusal" and mode == 0o755:
                    raise C.Refused("inert-body-refusal")
                inode = 99 if case == "changed-before-enable" and ("guard", None) in events else 31
                return {"identity": [7, inode, stat.S_IFREG | mode, 1, 0, 0, 5, 10, 11 if mode == 0o600 else 12],
                        "bytes": 5, "sha256": member["sha256"], "mode": oct(mode)}
            def guard():
                events.append(("guard", None))
                if case == "peer-refusal":
                    raise C.Refused("inert-peer-refusal")
            def enable(fd, mode):
                events.append(("chmod", mode))
                if case == "chmod-unknown":
                    raise OSError("inert-chmod-unknown")
            with self.subTest(case=case), patch.object(C.os, "open", return_value=31,
                    side_effect=FileExistsError("occupied") if case == "occupied" else None) as opened, \
                 patch.object(C.os, "write", return_value=0 if case == "short-write" else len(raw)), \
                 patch.object(C.os, "fsync"), patch.object(C.os, "close",
                    side_effect=OSError("inert-close-unknown") if case == "close-unknown" else None) as closed, \
                 patch.object(C, "bwrap_file_original", side_effect=observe), \
                 patch.object(C.os, "fchmod", side_effect=enable) as chmod, \
                 patch.object(C.os, "unlink") as unlink, patch.object(C, "command") as command:
                if case == "good":
                    self.assertEqual(C.bwrap_create_leaf(raw, member, 17, guard)["mode"], "0o755")
                    self.assertEqual(events, [("observe", 0o600), ("guard", None), ("observe", 0o600),
                                              ("chmod", 0o755), ("observe", 0o755)])
                    chmod.assert_called_once_with(31, 0o755)
                else:
                    with self.assertRaises((OSError, C.Refused)):
                        C.bwrap_create_leaf(raw, member, 17, guard)
                    if case in ("chmod-unknown", "post-refusal", "close-unknown"):
                        chmod.assert_called_once_with(31, 0o755)
                    else:
                        chmod.assert_not_called()
                args, kwargs = opened.call_args
                self.assertEqual((args[0], args[2], kwargs), ("bwrap", 0o600, {"dir_fd": 17}))
                self.assertEqual(args[1] & (C.os.O_EXCL | C.os.O_NOFOLLOW | C.os.O_CLOEXEC),
                                 C.os.O_EXCL | C.os.O_NOFOLLOW | C.os.O_CLOEXEC)
                if case == "occupied":
                    closed.assert_not_called()
                else:
                    closed.assert_called_once_with(31)
            unlink.assert_not_called()
            command.assert_not_called()

    def test_bwrap_acquisition_uses_unchanged_original_caw_without_a_native_bwrap_launch(self):
        row = self.bwrap_host_fixture()["bwrapSupplier"]
        for case in ("good", "download-nonzero", "unknown", "decode-nonzero", "decode-unknown",
                     "archive-differs", "decoded-differs", "capath-changed"):
            capath = {"path": str(C.BWRAP_SUPPLY / "inputs/download/empty-capath"), "identity": [7, 83]}
            def owned(argv, **kwargs):
                self.assertEqual(kwargs["execution_scope"], None)
                self.assertEqual(kwargs["journal_binding"], None)
                self.assertFalse(kwargs["cleanup"])
                self.assertFalse(kwargs["text"])
                self.assertNotIn(str(C.BWRAP_TARGET), argv)
                decoder = argv[0] == "/usr/bin/bash"
                if case == "unknown" or case == "decode-unknown" and decoder:
                    raise RuntimeError("inert original lifetime unknown")
                nonzero = case == "download-nonzero" or case == "decode-nonzero" and decoder
                return SimpleNamespace(args=argv, returncode=1 if nonzero else 0,
                                       stdout=b"", stderr=b"")
            owner = SimpleNamespace(run_owned=Mock(side_effect=owned))
            def supplied(path, *args, **kwargs):
                archive = str(path).endswith(".archive")
                digest = row["sha256"] if archive else row["decodedSha256"]
                if (archive and case == "archive-differs") or (not archive and case == "decoded-differs"):
                    digest = "0" * 64
                return b"inert", {"bytes": row["bytes"] if archive else row["decodedBytes"],
                                  "sha256": digest, "mode": "0o600", "identity": [7, 31]}
            with self.subTest(case=case), patch.object(C, "_OWNER", owner), patch.object(C, "_WAITS", []), \
                 patch.object(C, "_SUPPLIERS", []), patch.object(C, "_ORIGINALS_SETTLED", True), \
                 patch.object(C, "_CATALOGUE", {"caFile": "/etc/ssl/certs/ca-certificates.crt"}), \
                 patch.object(C.time, "monotonic", return_value=0), patch.object(C, "read", side_effect=supplied), \
                 patch.object(Path, "exists", return_value=False), patch.object(Path, "is_symlink", return_value=False), \
                 patch.object(Path, "is_dir", return_value=False), patch.object(C, "owner_argv") as native, \
                 patch.object(C, "bwrap_create_leaf") as create, \
                 patch.object(C, "acquisition_capath", side_effect=[capath,
                              {**capath, "identity": [7, 84]} if case == "capath-changed" else capath]):
                if case == "good":
                    result = C.acquire_archive(row, "bwrap", 240, download_root=C.BWRAP_SUPPLY / "inputs/download")
                    self.assertEqual(result, C.BWRAP_SUPPLY / "inputs/download/bwrap.tar")
                    self.assertEqual(C._WAITS, C.bwrap_original_waits())
                    self.assertEqual(len(C._SUPPLIERS), 1)
                    first, second = owner.run_owned.call_args_list
                    self.assertEqual(first.args[0][0], "/usr/bin/curl")
                    self.assertEqual(first.args[0][1], "--disable")
                    self.assertEqual(first.args[0][first.args[0].index("--capath") + 1], capath["path"])
                    self.assertEqual(second.args[0][0], "/usr/bin/bash")
                    self.assertIn("/usr/bin/dpkg-deb", second.args[0])
                    self.assertEqual((first.kwargs["timeout"], second.kwargs["timeout"]), (125, 90))
                else:
                    with self.assertRaises((C.Refused, RuntimeError)):
                        C.acquire_archive(row, "bwrap", 240, download_root=C.BWRAP_SUPPLY / "inputs/download")
                    self.assertEqual(C._SUPPLIERS, [])
                    self.assertEqual(owner.run_owned.call_count,
                                     2 if case in ("decode-nonzero", "decode-unknown", "decoded-differs") else 1)
                    self.assertEqual(C._ORIGINALS_SETTLED, case not in ("unknown", "decode-unknown"))
            native.assert_not_called()
            create.assert_not_called()
        with patch.object(C, "command") as command:
            with self.assertRaisesRegex(C.Refused, "fixed-supplier-download-root"):
                C.acquire_archive(row, "bwrap", 240, download_root=Path("/unbound"))
        command.assert_not_called()

    def bwrap_input_fixture(self):
        row = self.bwrap_host_fixture()["bwrapSupplier"]
        member = row["members"][0]
        root = C.BWRAP_SUPPLY / "inputs"
        files = []
        for index, (name, size, digest, mode) in enumerate((
                ("download/bwrap.archive", row["bytes"], row["sha256"], "0o600"),
                ("download/bwrap.tar", row["decodedBytes"], row["decodedSha256"], "0o600"),
                ("staged/bwrap", member["bytes"], member["sha256"], "0o400"))):
            files.append({"path": str(root / name), "bytes": size, "sha256": digest, "mode": mode,
                          "identity": [7, 31 + index, stat.S_IFREG | int(mode, 8), 1, 0, 0, size, 10, 11]})
        roster = {"files": files, "directories": [{"path": str(root / name),
                  "mode": "0o500" if name == "download/empty-capath" else "0o700"}
                  for name in (".", "download", "download/empty-capath", "staged")], "bytes": sum(f["bytes"] for f in files)}
        selected = {"member": member["member"], "target": member["target"],
                    **{key: files[2][key] for key in ("identity", "bytes", "sha256", "mode")}}
        supplier = {"role": "bwrap", "package": row["package"], "component": None,
                    "packageVersion": row["version"], "releaseVersion": None, "componentDeclaredVersion": None,
                    "archive": {key: files[0][key] for key in ("bytes", "sha256")},
                    "decoded": {key: files[1][key] for key in ("bytes", "sha256")},
                    "provenanceSha256": hashlib.sha256(C.canonical(row["provenance"])).hexdigest(),
                    "originalArchiveIdentitySha256": hashlib.sha256(C.canonical(files[0]["identity"])).hexdigest(),
                    "originalDecodedIdentitySha256": hashlib.sha256(C.canonical(files[1]["identity"])).hexdigest(),
                    "selectedMembers": {"count": 1, "bytes": member["bytes"],
                                        "originalsSha256": hashlib.sha256(C.canonical([selected])).hexdigest()}}
        return row, roster, supplier

    def test_bwrap_private_inputs_bind_acquisition_originals_not_just_repeated_hashes(self):
        row, roster, supplier = self.bwrap_input_fixture()
        with patch.object(C, "bounded_roster", return_value=roster):
            self.assertEqual(C.bwrap_input_originals(row, supplier), roster)
        for mutate in (lambda v: v["files"][0]["identity"].__setitem__(1, 999),
                       lambda v: v["files"][1]["identity"].__setitem__(1, 999),
                       lambda v: v["files"][2]["identity"].__setitem__(1, 999),
                       lambda v: v["files"][2].update(mode="0o755"),
                       lambda v: v["directories"][2].update(mode="0o777"),
                       lambda v: v["files"][0].update(sha256="0" * 64),
                       lambda v: v["files"].append({**v["files"][0], "path": str(C.BWRAP_SUPPLY / "inputs/extra")})):
            changed = copy.deepcopy(roster)
            mutate(changed)
            with self.subTest(mutate=mutate), patch.object(C, "bounded_roster", return_value=changed):
                with self.assertRaises(C.Refused):
                    C.bwrap_input_originals(row, supplier)
        with patch.object(C, "bounded_roster", return_value=roster):
            with self.assertRaisesRegex(C.Refused, "bwrap-acquisition-originals-changed"):
                C.bwrap_input_originals(row, {**supplier, "component": "unbound"})

    def test_bwrap_supplier_orchestration_orders_originals_and_refuses_each_failed_boundary(self):
        # Exercise the real orchestrator and its nested before_enable callback.
        # Host/process/filesystem seams are inert; leaf byte/chmod mechanics have
        # their own focused test above. No real descriptor or payload is used.
        catalogue = self.bwrap_host_fixture()
        row, inputs, supplier = self.bwrap_input_fixture()
        context, names = C.workflow_context(environment()), ["inert/source.py"]
        peer = catalogue["hostFiles"][1]
        peer_pin = {"identity": [7, 41, stat.S_IFREG | 0o755, 1, 0, 0, 5, 10, 11],
                    **{key: peer[key] for key in ("bytes", "sha256", "mode")}}
        peers = {peer["path"]: peer_pin}
        sources = {"files": {names[0]: peer_pin}, "directories": []}
        member = row["members"][0]
        installed = {"identity": [7, 99, stat.S_IFREG | 0o755, 1, 0, 0, member["bytes"], 10, 11],
                     "bytes": member["bytes"], "sha256": member["sha256"], "mode": "0o755"}
        parent_before = {"parents": [{"path": path, "identity": C.identity(file_info())}
                                    for path in ("/", "/usr", "/usr/bin")], "entries": ["cat"]}
        parent_after = {**copy.deepcopy(parent_before), "entries": ["bwrap", "cat"]}
        stage_info = file_info(mode=stat.S_IFDIR | 0o700)
        stage_info.st_nlink = 3
        empty_capath = {"path": str(C.BWRAP_SUPPLY / "inputs/download/empty-capath"), "identity": [7, 83], "entries": []}
        project_evidence = C.bwrap_supply_evidence
        cases = (("good", None), ("prehost", "inert-prehost"),
            ("acquisition-failed", "inert-acquisition-failed"), ("acquisition-unknown", "inert-acquisition-unknown"),
            ("wait-failed", "bwrap-originals-not-successful"), ("wait-unknown", "bwrap-originals-not-successful"),
            ("host-changed", "inert-host-changed"), ("source-changed", "bwrap-before-enable-originals-changed"),
            ("input-changed", "bwrap-acquisition-originals-changed"), ("capath-changed", "bwrap-before-enable-originals-changed"),
            ("posthost", "inert-posthost"),
            ("poststate", "bwrap-only-declared-parent-transition"),
            ("parent-close", "bwrap-parent-close-unsettled"), ("prefix-close", "pycache-original-close-unknown"),
            ("alias-close", "python-alias-original-close-unknown"),
            ("receipt-write", "inert-receipt-write"))
        for case, refusal in cases:
            events, mkdirs, masks, closes, writes, retained, pins = [], [], [], [], [], {}, {}
            state = {"stage": False, "created": False, "enabled": False, "mask": 0o022}
            parents = [(Path(item["path"]), 71 + i, item["identity"])
                       for i, item in enumerate(parent_before["parents"])]
            def parent_handles():
                events.append("parents")
                return parents
            def parent_snapshot(handles):
                self.assertIs(handles, parents)
                snapshot = copy.deepcopy(parent_after if state["created"] else parent_before)
                if case == "poststate" and state["enabled"]:
                    snapshot["entries"].append("unexpected")
                return snapshot
            def prehost(value, *, after=False):
                self.assertIs(value, catalogue)
                events.append("prehost-post" if after else "prehost")
                if case == "prehost":
                    raise C.Refused("inert-prehost")
                if not after:
                    pins.update(copy.deepcopy(peers))
                self.assertEqual(pins, peers)
            def source_originals(value):
                self.assertEqual(value, names)
                label = ("source-post" if state["enabled"] else "source-before-enable" if state["created"]
                         else "source-precreate" if "source-initial" in events else "source-initial")
                events.append(label)
                return {"changed": True} if case == "source-changed" and label == "source-before-enable" else copy.deepcopy(sources)
            def owner(root, value):
                events.append("owner-import")
                self.assertEqual((root, value), (C.SOURCE, catalogue))
                self.assertIn("prehost", events)
                self.assertIn("source-initial", events)
                self.assertEqual(pins, peers)
            def acquire(value, role, deadline, *, download_root):
                events.append("acquire")
                self.assertIn("owner-import", events)
                self.assertEqual((value, role, deadline, download_root),
                                 (row, "bwrap", 240, C.BWRAP_SUPPLY / "inputs/download"))
                C._WAITS.extend(C.bwrap_original_waits())
                if case in ("acquisition-unknown", "wait-unknown"):
                    C._ORIGINALS_SETTLED = False
                    C._WAITS[-1].update(returned=False, originalsSettled=False, exitCode=None)
                if case in ("acquisition-failed", "wait-failed"):
                    C._WAITS[-1]["exitCode"] = 1
                if case == "acquisition-failed":
                    raise C.Refused("inert-acquisition-failed")
                if case == "acquisition-unknown":
                    raise RuntimeError("inert-acquisition-unknown")
                # Also test the orchestrator's own wait gate, not just exceptions
                # raised by an acquisition helper that never creates a host leaf.
                C._SUPPLIERS.append({**copy.deepcopy(supplier), "selectedMembers": None})
                return C.BWRAP_SUPPLY / "inputs/download/bwrap.tar"
            def selected(path, value, destination):
                events.append("selected-member")
                self.assertEqual((path, value, destination),
                    (C.BWRAP_SUPPLY / "inputs/download/bwrap.tar", row, C.BWRAP_SUPPLY / "inputs/staged"))
                return copy.deepcopy(supplier["selectedMembers"])
            def input_roster(root, **bounds):
                self.assertEqual((root, bounds), (C.BWRAP_SUPPLY / "inputs", {"files": 8, "total": C.MIB}))
                events.append("inputs-post" if state["enabled"] else "inputs-before-enable" if state["created"] else "inputs-initial")
                roster = copy.deepcopy(inputs)
                if case == "input-changed" and state["created"] and not state["enabled"]:
                    roster["files"][0]["identity"][1] += 1
                return roster
            def host(value, *, after=False):
                self.assertTrue(after)
                full = any(item["path"] == str(C.BWRAP_TARGET) for item in value["hostFiles"])
                events.append("full-posthost" if full else "host-before-enable")
                self.assertTrue(state["created"])
                self.assertEqual(state["enabled"], full)
                self.assertEqual(pins, {**peers, str(C.BWRAP_TARGET): installed} if full else peers)
                if case == ("posthost" if full else "host-changed"):
                    raise C.Refused("inert-posthost" if full else "inert-host-changed")
            def create(raw, value, parent_fd, before_enable):
                events.append("canonical-create")
                self.assertEqual((raw, value, parent_fd), (b"inert-selected-member", member, 73))
                self.assertTrue(C._ORIGINALS_SETTLED)
                self.assertEqual(C._WAITS, C.bwrap_original_waits())
                self.assertIn("prehost-post", events)
                self.assertIn("source-precreate", events)
                state["created"] = True  # Inert nonexecuting-leaf boundary.
                before_enable()  # Actual nested callback, never a canned success.
                for event in ("host-before-enable", "source-before-enable", "inputs-before-enable"):
                    self.assertIn(event, events)
                state["enabled"] = True
                events.append("enable")
                return copy.deepcopy(installed)
            def lstat(path):
                if path in (C.TASK, C.PUBLIC):
                    raise FileNotFoundError("inert absent native root")
                if path == C.BWRAP_SUPPLY:
                    self.assertTrue(state["stage"])
                    return stage_info
                self.assertIn(path, (Path("/var"), Path("/var/tmp")))
                return file_info(mode=stat.S_IFDIR | (0o1777 if path == Path("/var/tmp") else 0o755))
            def mkdir(path, mode=0o777, parents=False, exist_ok=False):
                self.assertEqual((mode, parents, exist_ok), (0o700, False, False))
                self.assertIn(path, [C.BWRAP_SUPPLY / name for name in (".", "inputs", "inputs/download", "inputs/staged")])
                self.assertNotIn(path, mkdirs)
                mkdirs.append(path)
                state["stage"] = True
            def fresh(path):
                self.assertEqual(path, C.BWRAP_SUPPLY)
                return False
            def listdir(path):
                self.assertEqual(path, C.BWRAP_SUPPLY)
                return sorted(["inputs", *(p.name for p in retained)])
            def read(path, limit, **kwargs):
                if path == C.BWRAP_SUPPLY / "inputs/staged/bwrap":
                    self.assertEqual(limit, member["bytes"])
                    return b"inert-selected-member", {key: inputs["files"][2][key] for key in ("identity", "bytes", "sha256", "mode")}
                self.assertEqual((path, limit), (C.BWRAP_SUPPLY / "before.json", 16 * C.MIB))
                return retained[path]
            def write(path, raw, mode=0o400):
                self.assertEqual((path.parent, mode), (C.BWRAP_SUPPLY, 0o400))
                self.assertNotIn(path, retained)
                self.assertIsNone(C._EVIDENCE["bwrapSupply"])
                frame = C.decode(raw)
                writes.append(path.name)
                if path.name == "before.json":
                    events.append("before-write")
                    self.assertEqual(frame["hostOriginals"], peers)
                    self.assertEqual(frame["sourceOriginals"], sources)
                    self.assertEqual(frame["emptyCapath"], empty_capath)
                    self.assertEqual(frame["pythonPycache"], self.pycache_fixture())
                elif path.name == "receipt.json":
                    events.append("receipt-write")
                    self.assertEqual((parents, closes, state["mask"]), ([], [73, 72, 71], 0o022))
                    self.assertIn("full-posthost", events)
                    self.assertIn("inputs-post", events)
                    self.assertTrue(frame["passed"] and frame["originalsSettled"] and frame["parentHandlesClosed"])
                    self.assertTrue(frame["pythonPycacheHandlesClosed"])
                    self.assertEqual(frame["pythonPycache"], self.pycache_fixture())
                    self.assertIn("alias-close", events)
                    self.assertIn("prefix-close", events)
                    self.assertFalse(frame["nativeQualified"])
                    self.assertEqual(frame["installed"], installed)
                    self.assertEqual(frame["waits"], C._WAITS)
                    if case == "receipt-write":
                        raise OSError("inert-receipt-write")
                else:
                    self.assertEqual(path.name, "refusal.json")
                    events.append("refusal-write")
                    self.assertFalse(frame["passed"] or frame["cleanupVerified"])
                pin = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": "0o400", "identity": [7, 100 + len(retained)]}
                retained[path] = (raw, pin)
                if path.name == "receipt.json":
                    events.append("receipt-return")
                return pin
            def close(fd):
                self.assertNotIn(fd, closes)
                self.assertNotIn(fd, [item[1] for item in parents])  # Real helper popped before closing.
                closes.append(fd)
                events.append("close:" + str(fd))
                if case == "parent-close" and fd == 73:
                    raise OSError("inert-close-unknown")
            def umask(value):
                previous, state["mask"] = state["mask"], value
                masks.append(value)
                return previous
            def prefix_finish():
                events.append("prefix-close")
                if case == "prefix-close":
                    C._ORIGINALS_SETTLED = False
                    raise C.Refused("pycache-original-close-unknown")
            def alias_finish():
                events.append("alias-close")
                if case == "alias-close":
                    C._ORIGINALS_SETTLED = False
                    raise C.Refused("python-alias-original-close-unknown")
            def evidence(pin, value):
                self.assertIn("receipt-return", events)
                events.append("success-evidence")
                project_evidence(pin, value)
            with self.subTest(case=case), ExitStack() as stack:
                for name, value in (("_PINS", pins), ("_WAITS", []), ("_SUPPLIERS", []),
                                    ("_ORIGINALS_SETTLED", True), ("_EVIDENCE", {"bwrapSupply": None})):
                    stack.enter_context(patch.object(C, name, value))
                stack.enter_context(patch.object(C, "pycache_original", return_value=self.pycache_fixture()))
                stack.enter_context(patch.object(C, "pycache_finish", side_effect=prefix_finish))
                stack.enter_context(patch.object(C, "python_alias_finish", side_effect=alias_finish))
                stack.enter_context(patch.object(C, "capath_state", return_value=empty_capath))
                stack.enter_context(patch.object(C, "acquisition_capath", side_effect=lambda *_:
                    {**empty_capath, "identity": [7, 84]} if case == "capath-changed" and state["created"] else empty_capath))
                for name, fake in (("bwrap_parent_handles", parent_handles), ("bwrap_parent_snapshot", parent_snapshot),
                    ("authenticate_bwrap_absent", prehost), ("bwrap_sources", source_originals), ("owner_modules", owner),
                    ("acquire_archive", acquire), ("selected_members", selected), ("bounded_roster", input_roster),
                    ("authenticate_host", host), ("bwrap_create_leaf", create), ("read", read), ("write", write),
                    ("bwrap_supply_evidence", evidence)):
                    stack.enter_context(patch.object(C, name, fake))
                for name, fake in (("lstat", lstat), ("mkdir", mkdir), ("exists", fresh), ("is_symlink", fresh)):
                    stack.enter_context(patch.object(Path, name, fake))
                for name, fake in (("listdir", listdir), ("close", close), ("umask", umask)):
                    stack.enter_context(patch.object(C.os, name, fake))
                stack.enter_context(patch.object(C.time, "monotonic", return_value=0))
                prohibited = [stack.enter_context(patch.object(C.os, name, side_effect=AssertionError("non-inert filesystem call")))
                              for name in ("open", "fstat", "read", "write", "fsync", "fchmod", "unlink", "remove", "mkdir")]
                prohibited += [stack.enter_context(patch.object(C, name, side_effect=AssertionError("unowned/native call")))
                               for name in ("command", "owner_argv")]
                if refusal is None:
                    self.assertIsNone(C.supply_bwrap(context, catalogue, names))
                    self.assertEqual(events, ["parents", "prehost", "source-initial", "before-write", "owner-import",
                        "acquire", "selected-member", "inputs-initial", "prehost-post", "source-precreate", "canonical-create",
                        "host-before-enable", "source-before-enable", "inputs-before-enable", "enable", "full-posthost",
                        "source-post", "inputs-post", "close:73", "close:72", "close:71", "alias-close", "prefix-close",
                        "receipt-write", "receipt-return", "success-evidence"])
                    receipt = C.decode(retained[C.BWRAP_SUPPLY / "receipt.json"][0])
                    self.assertTrue(all(receipt[key] == value for key, value in context.items()))
                    self.assertFalse(C._EVIDENCE["bwrapSupply"]["nativeQualified"])
                else:
                    with self.assertRaisesRegex((C.Refused, OSError, RuntimeError), refusal):
                        C.supply_bwrap(context, catalogue, names)
                    self.assertNotIn(C.BWRAP_SUPPLY / "receipt.json", retained)
                    self.assertIsNone(C._EVIDENCE["bwrapSupply"])
                before_create = case in ("prehost", "acquisition-failed", "acquisition-unknown", "wait-failed", "wait-unknown")
                enabled = not before_create and case not in ("host-changed", "source-changed", "input-changed", "capath-changed")
                self.assertEqual(events.count("canonical-create"), int(not before_create))
                self.assertEqual(events.count("enable"), int(enabled))
                self.assertEqual(events.count("acquire"), int(case != "prehost"))
                self.assertEqual(events.count("receipt-write"), int(case in ("good", "receipt-write")))
                self.assertIs(C._PINS, pins)
                self.assertEqual(pins, {} if case == "prehost" else {**peers, **({str(C.BWRAP_TARGET): installed} if enabled else {})})
                self.assertEqual(C._ORIGINALS_SETTLED, case not in ("acquisition-unknown", "wait-unknown", "prefix-close", "alias-close"))
                self.assertEqual((parents, closes, state["mask"]), ([], [73, 72, 71], 0o022))
                self.assertEqual(masks, [] if case == "prehost" else [0o077, 0o022])
                self.assertEqual(mkdirs, [] if case == "prehost" else
                                 [C.BWRAP_SUPPLY / name for name in (".", "inputs", "inputs/download", "inputs/staged")])
                self.assertEqual(writes, [] if case == "prehost" else ["before.json"] +
                                 (["receipt.json"] if case in ("good", "receipt-write") else []) +
                                 ([] if case == "good" else ["refusal.json"]))
                for blocked in prohibited:
                    blocked.assert_not_called()

    def test_bwrap_receipt_cannot_replay_context_or_replace_originals_or_hide_a_failed_stage(self):
        context = C.workflow_context(environment())
        catalogue = self.bwrap_host_fixture()
        row, inputs, supplier = self.bwrap_input_fixture()
        member = row["members"][0]
        installed = {"identity": [7, 99, stat.S_IFREG | 0o755, 1, 0, 0, member["bytes"], 10, 11],
                     "bytes": member["bytes"], "sha256": member["sha256"], "mode": "0o755"}
        parent_before = {"parents": [{"path": path, "identity": C.identity(file_info())}
                                    for path in ("/", "/usr", "/usr/bin")], "entries": ["cat"]}
        parent_after = {**copy.deepcopy(parent_before), "entries": ["bwrap", "cat"]}
        stage, sources, peer = [7, 55, stat.S_IFDIR | 0o700, 3, 0, 0], {"inert": "source originals"}, {"inert": "peer"}
        empty_capath = {"path": str(C.BWRAP_SUPPLY / "inputs/download/empty-capath"), "identity": [7, 83], "entries": []}
        before = {"schema": C.BWRAP_SUPPLY_SCHEMA, **context, "stageIdentity": stage,
                  "hostOriginals": {"/usr/bin/cat": peer}, "sourceOriginals": sources, "parentBefore": parent_before,
                  "emptyCapath": empty_capath, "pythonPycache": self.pycache_fixture()}
        before_raw = C.canonical(before)
        before_pin = {"mode": "0o400", "sha256": hashlib.sha256(before_raw).hexdigest()}
        receipt = {"schema": C.BWRAP_SUPPLY_SCHEMA, **context, "phase": "supply-bwrap", "passed": True,
                   "originalsSettled": True, "parentHandlesClosed": True, "nativeQualified": False,
                   "supplierContractSha256": C.BWRAP_SUPPLIER_SHA256, "beforeSha256": before_pin["sha256"],
                   "installed": installed, "parentAfter": parent_after, "inputOriginals": inputs,
                   "pythonPycache": self.pycache_fixture(), "pythonPycacheHandlesClosed": True,
                   "supplierOriginal": supplier, "waits": C.bwrap_original_waits()}
        for case in ("good", "source", "run", "unsettled", "handles", "wait", "installed", "parent", "failed-stage", "capath", "prefix", "prefix-handles"):
            changed = copy.deepcopy(receipt)
            if case == "source":
                changed["sourceSha"] = "b" * 40
            if case == "run":
                changed["runId"] = "124"
            if case == "unsettled":
                changed["originalsSettled"] = False
            if case == "handles":
                changed["parentHandlesClosed"] = False
            if case == "prefix":
                changed["pythonPycache"]["identity"][1] += 1
            if case == "prefix-handles":
                changed["pythonPycacheHandlesClosed"] = False
            if case == "wait":
                changed["waits"][0]["exitCode"] = 1
            if case == "installed":
                changed["installed"]["identity"][1] += 1
            if case == "parent":
                changed["parentAfter"]["entries"].append("other")
            receipt_raw = C.canonical(changed)
            receipt_pin = {"mode": "0o400", "sha256": hashlib.sha256(receipt_raw).hexdigest()}
            def retained(path, *args, **kwargs):
                if Path(path).name == "before.json":
                    return before_raw, before_pin
                self.assertEqual(Path(path).name, "receipt.json")
                return receipt_raw, receipt_pin
            entries = ["before.json", "inputs", "receipt.json"]
            if case == "failed-stage":
                entries.append("refusal.json")
            with self.subTest(case=case), patch.object(C, "bwrap_stage_identity", return_value=stage), \
                 patch.object(C.os, "listdir", return_value=entries), patch.object(C, "read", side_effect=retained), \
                 patch.object(C, "bwrap_sources", return_value=sources), patch.object(C, "bounded_roster", return_value=inputs), \
                 patch.object(C, "_PINS", {"/usr/bin/cat": peer, str(C.BWRAP_TARGET): installed}), \
                 patch.object(C, "bwrap_parent_handles", return_value=[]), \
                 patch.object(C, "pycache_original", return_value=self.pycache_fixture()), \
                 patch.object(C, "bwrap_parent_snapshot", return_value=parent_after), \
                 patch.object(C, "acquisition_capath", return_value={} if case == "capath" else empty_capath), \
                 patch.object(C, "bwrap_close_parents"), patch.object(C, "owner_modules") as owner, \
                 patch.object(C, "command") as command:
                if case == "good":
                    C.bwrap_supply_for(context, catalogue, [])
                    self.assertFalse(C._EVIDENCE["bwrapSupply"]["nativeQualified"])
                else:
                    with self.assertRaises(C.Refused):
                        C.bwrap_supply_for(context, catalogue, [])
            owner.assert_not_called()
            command.assert_not_called()

    def test_snapshot_url_allowance_is_exact_and_never_a_hostname_or_redirect_fallback(self):
        value = json.loads((ROOT / "desktop/tools/gnome_session_native/runtime-suppliers.json").read_text())
        urls = {row["url"] for row in value["nativePackages"] if row["url"].startswith("https://snapshot.")}
        self.assertEqual(len(urls), 26)
        self.assertEqual(urls, C.SNAPSHOT_NATIVE_URLS)
        for row in (*value["nativePackages"], *value["rust"]):
            self.assertIsNone(C.public_url(row["url"]))
        self.assertEqual(value["bwrapSupplier"]["url"], C.BWRAP_URL)
        self.assertIsNone(C.public_url(C.BWRAP_URL))
        for suffix in ("?fallback=1", "#fragment", "\n"):
            with self.assertRaises(C.Refused):
                C.public_url(C.BWRAP_URL + suffix)
        url = sorted(urls)[0]
        for changed in (url.replace("https:", "http:"), url + "?alternative=1", url + "#fragment",
                        url.replace("https://", "https://user@"), url.replace(".com/", ".com:444/"),
                        url.replace(".com/", ".com:443/"), url.replace("/ubuntu/", "/ubuntu/../ubuntu/", 1),
                        url.replace("/ubuntu/", "/ubuntu/%2e/", 1), url + "\n",
                        "https://snapshot.ubuntu.com/ubuntu/20200101T000000Z/pool/unlisted.deb",
                        "https://snapshot.ubuntu.com.example/ubuntu/unlisted.deb"):
            with self.subTest(changed=changed), self.assertRaises(C.Refused):
                C.public_url(changed)

    def test_preload_absence_is_consumed_before_and_after_and_dangling_or_uncertain_is_occupied(self):
        catalogue = {"hostAbsent": ["/etc/ld.so.preload"], "hostFiles": [], "hostDirectories": [], "hostAliases": []}
        parent = SimpleNamespace(st_dev=7, st_ino=31, st_mode=stat.S_IFDIR | 0o755, st_nlink=2,
                                 st_uid=0, st_gid=0, st_size=4096, st_mtime_ns=10, st_ctime_ns=11)
        for after in (False, True):
            for failure in (None, "regular", "dangling", "denied", "parent-link", "parent-changed"):
                calls = []
                def info(path):
                    calls.append(str(path))
                    if path == Path("/etc"):
                        if failure == "parent-link":
                            return SimpleNamespace(**{**vars(parent), "st_mode": stat.S_IFLNK | 0o777})
                        if failure == "parent-changed" and len(calls) > 1:
                            return SimpleNamespace(**{**vars(parent), "st_ino": 32})
                        return parent
                    self.assertEqual(path, Path("/etc/ld.so.preload"))
                    if failure == "denied":
                        raise PermissionError("inert DATA")
                    if failure in ("regular", "dangling"):
                        return SimpleNamespace(st_mode=(stat.S_IFREG if failure == "regular" else stat.S_IFLNK) | 0o600)
                    raise FileNotFoundError("inert DATA")
                with self.subTest(after=after, failure=failure), patch.object(Path, "lstat", info), \
                     patch.object(C, "read") as read, patch.object(C, "command") as command, \
                     patch.object(C, "python_alias_begin", return_value={"files": {}}), \
                     patch.object(C, "python_alias_originals", return_value={"files": {}}), \
                     patch.object(C, "authenticate_python_runtime"):
                    if failure is None:
                        C.authenticate_host(catalogue, after=after)
                        self.assertEqual(calls, ["/etc", "/etc/ld.so.preload", "/etc"])
                    else:
                        with self.assertRaises(C.Refused):
                            C.authenticate_host(catalogue, after=after)
                    read.assert_not_called()
                    command.assert_not_called()
        for changed in (None, [], ["/other"], ["/etc/ld.so.preload", "/other"]):
            with self.subTest(contract=changed), patch.object(Path, "lstat") as observe:
                with self.assertRaisesRegex(C.Refused, "host-absent-input-contract"):
                    C.authenticate_host({**catalogue, "hostAbsent": changed})
                observe.assert_not_called()

    def test_pycache_host_originals_span_the_consumer_and_all_partial_closes_are_once(self):
        paths = [Path("/"), Path("/run"), C.PYTHON_PYCACHE]
        cases = ("good", "parent-sibling", "unsafe-parent", "wrong-owner", "writable-leaf", "nonempty",
                 "alias", "partial-open", "parent-replaced", "leaf-replaced", "new-empty-replacement",
                 "scan-leaf-drift", "scan-parent-drift", "post-nonempty", "post-leaf-replaced", "post-parent-replaced",
                 "fstat-failed", "close-failed", "fstat-and-close-failed", "nonempty-and-close-failed",
                 "body-and-close-failed", "scan-close-failed")
        unknown = {"close-failed", "fstat-and-close-failed", "nonempty-and-close-failed",
                   "body-and-close-failed", "scan-close-failed"}
        for case in cases:
            infos = {path: file_info(mode=stat.S_IFDIR | (0o555 if path == paths[-1] else 0o755)) for path in paths}
            for i, path in enumerate(paths):
                infos[path].st_ino = 100 + i
            if case == "unsafe-parent":
                infos[paths[1]].st_mode = stat.S_IFDIR | 0o777
            if case == "wrong-owner":
                infos[paths[-1]].st_uid = 1001
            if case == "writable-leaf":
                infos[paths[-1]].st_mode = stat.S_IFDIR | 0o755
            state = {"post": False}
            opened, closed, descriptors, scans = [], [], {}, []
            primary = OSError("inert primary body")
            def opening(name, flags, *, dir_fd=None):
                self.assertEqual(flags, C.os.O_RDONLY | C.os.O_DIRECTORY | C.os.O_NOFOLLOW | C.os.O_CLOEXEC)
                path = Path(name) if dir_fd is None else descriptors[dir_fd] / name
                self.assertIn(path, paths)
                if case in ("alias", "partial-open") and path == paths[-1]:
                    raise OSError("inert nofollow/open refusal")
                fd = 70 + len(opened)
                opened.append(fd)
                descriptors[fd] = path
                return fd
            def fstat(fd):
                self.assertIn(fd, C._PYCACHE["fds"])  # Own before ANY failing fstat.
                if case in ("fstat-failed", "fstat-and-close-failed"):
                    raise primary
                return copy.copy(infos[descriptors[fd]])
            def named(path):
                info = copy.copy(infos[path])
                if (case == "parent-replaced" and path == paths[1]
                        or case == "leaf-replaced" and path == paths[-1]
                        or state["post"] and case == "post-leaf-replaced" and path == paths[-1]
                        or state["post"] and case == "post-parent-replaced" and path == paths[1]):
                    info.st_ino += 500
                return info
            def relative(name, *, dir_fd, follow_symlinks):
                self.assertFalse(follow_symlinks)
                return named(descriptors[dir_fd] / name)
            class Scan:
                def __init__(self):
                    self.reads, self.closed = 0, False
                    scans.append(self)
                def __iter__(self):
                    return self
                def __next__(self):
                    self.reads += 1
                    if self.reads != 1:
                        raise AssertionError("directory scan exceeded one entry")
                    if case in ("nonempty", "nonempty-and-close-failed") or state["post"] and case == "post-nonempty":
                        return object()
                    if case == "scan-leaf-drift":
                        infos[paths[-1]].st_ctime_ns += 1
                    if case == "scan-parent-drift":
                        infos[paths[1]].st_ino += 1
                    raise StopIteration
                def close(self):
                    if self.closed:
                        raise AssertionError("iterator close retried")
                    self.closed = True
                    if case == "scan-close-failed":
                        raise OSError("inert scan close unknown")
            def scan(fd):
                self.assertEqual(descriptors[fd], paths[-1])
                return Scan()
            def close(fd):
                self.assertNotIn(fd, C._PYCACHE["fds"])
                self.assertNotIn(fd, closed)
                closed.append(fd)
                if case in unknown - {"scan-close-failed"} and fd == opened[-1]:
                    raise OSError("inert close unknown")
            with self.subTest(case=case), patch.object(C, "_PYCACHE", None), \
                 patch.object(C, "_ORIGINALS_SETTLED", True), patch.object(C.os, "open", side_effect=opening), \
                 patch.object(C.os, "fstat", side_effect=fstat), patch.object(C.os, "stat", side_effect=relative), \
                 patch.object(Path, "lstat", named), patch.object(C.os, "scandir", side_effect=scan), \
                 patch.object(C.os, "close", side_effect=close), patch.object(C, "command") as command, \
                 patch.object(C.os, "mkdir") as mkdir, patch.object(C.os, "rmdir") as rmdir:
                expected = self.pycache_fixture()
                if case == "new-empty-replacement":
                    expected["identity"][1] += 500
                def consume():
                    original = C.pycache_begin(expected)
                    self.assertEqual(closed, [])
                    self.assertEqual(len(C._PYCACHE["fds"]), 3)
                    self.assertEqual(original, expected)
                    state["post"] = True
                    if case == "parent-sibling":
                        for path in paths[:2]:
                            infos[path].st_nlink += 2
                            infos[path].st_ctime_ns += 2
                    if case == "body-and-close-failed":
                        try:
                            raise primary
                        except BaseException:
                            C.pycache_finish(failed=True)
                            raise
                    C.pycache_finish()
                if case in ("good", "parent-sibling"):
                    consume()
                    self.assertTrue(C._EVIDENCE["pythonPycache"]["phaseCustodyPostchecked"])
                    self.assertTrue(C._EVIDENCE["pythonPycache"]["phaseHandlesClosed"])
                else:
                    with self.assertRaises((C.Refused, OSError)) as failure:
                        consume()
                    if case in ("fstat-failed", "fstat-and-close-failed", "body-and-close-failed"):
                        self.assertIs(failure.exception, primary)
                    if case == "nonempty-and-close-failed":
                        self.assertEqual(str(failure.exception), "pycache-not-empty")
                self.assertEqual(closed, list(reversed(opened)))
                self.assertTrue(all(item.closed and item.reads == 1 for item in scans))
                self.assertEqual(C._ORIGINALS_SETTLED, case not in unknown)
                self.assertTrue(C._PYCACHE["closed"])
                C.pycache_finish(failed=True)  # No descriptor-close retry on the main refusal path.
                self.assertEqual(closed, list(reversed(opened)))
                command.assert_not_called()
                mkdir.assert_not_called()
                rmdir.assert_not_called()

    def test_pycache_later_phases_require_the_first_control_not_new_observation_authority(self):
        context = C.workflow_context(environment())
        original, stage = self.pycache_fixture(), [7, 55, stat.S_IFDIR | 0o700, 3, 0, 0]
        before = {"schema": C.BWRAP_SUPPLY_SCHEMA, **context, "stageIdentity": stage, "pythonPycache": original}
        with patch.object(C, "pycache_begin", return_value=original) as begin, patch.object(C, "read") as read:
            self.assertIs(C.pycache_for_phase(context, "supply-bwrap"), original)
        begin.assert_called_once_with(None)
        read.assert_not_called()
        for phase in ("prepare", "acquire", "run", "settle"):
            for case in ("good", "other-run", "other-stage", "writable-control", "missing-original"):
                changed = copy.deepcopy(before)
                if case == "other-run":
                    changed["runId"] = "124"
                if case == "other-stage":
                    changed["stageIdentity"][1] += 1
                if case == "missing-original":
                    changed["pythonPycache"] = None
                pin = {"mode": "0o600" if case == "writable-control" else "0o400"}
                with self.subTest(phase=phase, case=case), \
                     patch.object(C, "bwrap_stage_identity", return_value=stage), \
                     patch.object(C, "read", return_value=(C.canonical(changed), pin)), \
                     patch.object(C, "pycache_begin", return_value=original) as begin:
                    if case == "good":
                        self.assertIs(C.pycache_for_phase(context, phase), original)
                        begin.assert_called_once_with(original)
                    else:
                        with self.assertRaises(C.Refused):
                            C.pycache_for_phase(context, phase)
                        begin.assert_not_called()

    def test_namespace_pycache_keeps_same_leaf_and_its_own_readonly_parent_originals(self):
        paths = [Path("/"), Path("/run"), C.PYTHON_PYCACHE]
        for case in ("good", "other-leaf", "writable-parent", "writable-parent-mount", "writable-leaf-mount",
                     "alias", "partial-fstat", "post-parent-drift", "post-leaf-drift", "close-unknown"):
            infos = {path: file_info(mode=stat.S_IFDIR | (0o555 if path == paths[-1] else 0o755)) for path in paths}
            infos[paths[0]].st_ino, infos[paths[1]].st_ino, infos[paths[2]].st_ino = 900, 901, 102
            if case == "other-leaf":
                infos[paths[-1]].st_ino += 1
            if case == "writable-parent":
                infos[paths[1]].st_mode = stat.S_IFDIR | 0o777
            opened, closed, descriptors = [], [], {}
            def opening(name, flags, *, dir_fd=None):
                self.assertEqual(flags, N.os.O_RDONLY | N.os.O_DIRECTORY | N.os.O_NOFOLLOW | N.os.O_CLOEXEC)
                path = Path(name) if dir_fd is None else descriptors[dir_fd] / name
                if case == "alias" and path == paths[-1]:
                    raise OSError("inert alias")
                fd = 80 + len(opened)
                opened.append(fd)
                descriptors[fd] = path
                return fd
            def fstat(fd):
                self.assertIn(fd, N.pycache_fds)
                if case == "partial-fstat" and descriptors[fd] == paths[1]:
                    raise OSError("inert partial fstat")
                return copy.copy(infos[descriptors[fd]])
            def readonly(fd):
                writable = (case == "writable-parent-mount" and descriptors[fd] == paths[1]
                            or case == "writable-leaf-mount" and descriptors[fd] == paths[-1])
                return SimpleNamespace(f_flag=0 if writable else N.os.ST_RDONLY)
            def named(path):
                return copy.copy(infos[path])
            def relative(name, *, dir_fd, follow_symlinks):
                self.assertFalse(follow_symlinks)
                return named(descriptors[dir_fd] / name)
            def close(fd):
                self.assertNotIn(fd, N.pycache_fds)
                self.assertNotIn(fd, closed)
                closed.append(fd)
                if case == "close-unknown" and fd == opened[-1]:
                    raise OSError("inert namespace close unknown")
            with self.subTest(case=case), patch.multiple(N, pycache_fds=[], pycache_state=None, report={}, errors=[]), \
                 patch.object(N.os, "open", side_effect=opening), patch.object(N.os, "fstat", side_effect=fstat), \
                 patch.object(N.os, "fstatvfs", side_effect=readonly), patch.object(N.os, "stat", side_effect=relative), \
                 patch.object(Path, "lstat", named), patch.object(N, "pycache_empty") as empty, \
                 patch.object(N.os, "close", side_effect=close), patch.object(N, "invoke") as invoke:
                try:
                    if case in ("good", "post-parent-drift", "post-leaf-drift", "close-unknown"):
                        N.pycache_namespace_begin(self.pycache_fixture())
                        self.assertEqual(closed, [])
                        self.assertTrue(N.report["pythonPycacheSameLeaf"])
                        self.assertEqual(N.pycache_state["parents"][0][1], 900)
                        if case == "post-parent-drift":
                            infos[paths[1]].st_ino += 1
                        if case == "post-leaf-drift":
                            infos[paths[-1]].st_ctime_ns += 1
                    else:
                        with self.assertRaises((N.Refusal, OSError)):
                            N.pycache_namespace_begin(self.pycache_fixture())
                finally:
                    N.pycache_namespace_finish()
                self.assertEqual(closed, list(reversed(opened)))
                invoke.assert_not_called()
                if case == "good":
                    self.assertEqual(N.errors, [])
                    self.assertTrue(N.report["pythonPycachePostchecked"] and N.report["pythonPycacheHandlesClosed"])
                    self.assertEqual(empty.call_count, 2)
                if case in ("post-parent-drift", "post-leaf-drift", "close-unknown"):
                    self.assertTrue(N.errors)
                if case == "close-unknown":
                    self.assertFalse(N.report["pythonPycacheHandlesClosed"])

    def test_empty_capath_owns_every_original_directory_and_closes_each_fd_once(self):
        root = C.TASK / "download"
        target = root / "empty-capath"
        paths = [Path("/")]
        for part in target.parts[1:]:
            paths.append(paths[-1] / part)
        for case in ("create", "existing", "occupied", "unsafe-parent", "wrong-owner", "nonempty",
                     "alias", "parent-replaced", "leaf-replaced", "fstat-failed", "close-failed",
                     "fstat-and-close-failed", "nonempty-and-close-failed"):
            infos = {}
            for i, path in enumerate(paths):
                mode = 0o500 if path == target else 0o1777 if path == Path("/var/tmp") else 0o700 if path.is_relative_to(C.TASK) else 0o755
                infos[path] = file_info(mode=stat.S_IFDIR | mode)
                infos[path].st_ino = 100 + i
            if case == "unsafe-parent":
                infos[root].st_mode = stat.S_IFDIR | 0o777
            if case == "wrong-owner":
                infos[target].st_uid = 1001
            opened, closed, descriptors, created = [], [], {}, []
            primary = OSError("inert initial descriptor failure")
            def opening(name, flags, *, dir_fd=None):
                self.assertEqual(flags, C.os.O_RDONLY | C.os.O_DIRECTORY | C.os.O_NOFOLLOW | C.os.O_CLOEXEC)
                path = Path(name) if dir_fd is None else descriptors[dir_fd] / name
                self.assertIn(path, paths)
                if case == "alias" and path == target:
                    raise OSError("inert nofollow directory refusal")
                fd = 70 + len(opened)
                opened.append(fd)
                descriptors[fd] = path
                return fd
            def creating(name, mode, *, dir_fd):
                self.assertEqual((descriptors[dir_fd] / name, mode), (target, 0o500))
                created.append(target)
                if case == "occupied":
                    raise FileExistsError("existing directory is not adopted")
                # A legitimate new child changes these parent fields. Custody
                # must not compare them, while the empty leaf stays exact.
                infos[root].st_nlink += 1
                infos[root].st_mtime_ns += 1
                infos[root].st_ctime_ns += 1
            def fstat(fd):
                if case in ("fstat-failed", "fstat-and-close-failed"):
                    raise primary
                return copy.copy(infos[descriptors[fd]])
            def lstat(path):
                value = copy.copy(infos[path])
                if (case == "parent-replaced" and path == root and len(opened) == len(paths)
                        or case == "leaf-replaced" and path == target):
                    value.st_ino += 1000
                return value
            def close(fd):
                self.assertNotIn(fd, closed)
                closed.append(fd)
                if case in ("close-failed", "fstat-and-close-failed", "nonempty-and-close-failed") and fd == opened[-1]:
                    raise OSError("inert close status unknown")
            with self.subTest(case=case), patch.object(C, "_ORIGINALS_SETTLED", True), \
                 patch.object(C.os, "open", side_effect=opening), patch.object(C.os, "mkdir", side_effect=creating), \
                 patch.object(C.os, "fstat", side_effect=fstat), patch.object(Path, "lstat", lstat), \
                 patch.object(C.os, "listdir", return_value=["unadmitted.pem"] if case in ("nonempty", "nonempty-and-close-failed") else []), \
                 patch.object(C.os, "close", side_effect=close), patch.object(C, "command") as command:
                if case in ("create", "existing"):
                    result = C.capath_state(root, create=case != "existing")
                    self.assertEqual((result["path"], result["entries"], result["identity"]),
                                     (str(target), [], C.identity(infos[target])))
                    self.assertEqual(created, [target] if case == "create" else [])
                else:
                    with self.assertRaises((C.Refused, OSError)) as failure:
                        C.capath_state(root, create=True)
                    if case == "fstat-and-close-failed":
                        self.assertIs(failure.exception, primary)
                    if case == "nonempty-and-close-failed":
                        self.assertEqual(str(failure.exception), "capath-not-protected-empty")
                self.assertEqual(closed, list(reversed(opened)))
                self.assertEqual(C._ORIGINALS_SETTLED, case not in ("close-failed", "fstat-and-close-failed", "nonempty-and-close-failed"))
                command.assert_not_called()

    def test_capath_control_and_ca_originals_cannot_be_replaced_or_made_writable(self):
        root = C.TASK / "download"
        original = {"path": str(root / "empty-capath"), "identity": [7, 80], "parents": [], "entries": []}
        ca = {"bytes": 10, "sha256": "c" * 64, "mode": "0o644", "identity": [7, 81]}
        for case in ("good", "directory", "control-mode", "ca-bytes", "ca-parent"):
            def read(path, *_args, **_kwargs):
                if Path(path).name == "prepared.json":
                    return C.canonical({"emptyCapath": original}), {"mode": "0o600" if case == "control-mode" else "0o400"}
                self.assertEqual(str(path), C.CA_FILE)
                return b"inert CA", {**ca, "sha256": "d" * 64} if case == "ca-bytes" else ca
            with self.subTest(case=case), patch.object(C, "read", side_effect=read), \
                 patch.object(C, "_CATALOGUE", {"caFile": C.CA_FILE}), patch.object(C, "_PINS", {C.CA_FILE: ca}), \
                 patch.object(C, "capath_state", return_value={} if case == "directory" else original), \
                 patch.object(Path, "lstat", return_value=file_info(mode=stat.S_IFDIR | (0o777 if case == "ca-parent" else 0o755))), \
                 patch.object(C, "command") as command:
                if case == "good":
                    self.assertEqual(C.acquisition_capath(root), original)
                else:
                    with self.assertRaises(C.Refused):
                        C.acquisition_capath(root)
                command.assert_not_called()

    def test_cargo_acquisition_mounts_only_admitted_files_and_retains_tls_verification(self):
        catalogue = json.loads((ROOT / "desktop/tools/gnome_session_native/runtime-suppliers.json").read_text())
        selection = C.cargo_mount_selection(catalogue)
        argv = C.cargo_acquisition_argv(selection)
        readonly = [tuple(argv[i + 1:i + 3]) for i, item in enumerate(argv) if item == "--ro-bind"]
        writable = [tuple(argv[i + 1:i + 3]) for i, item in enumerate(argv) if item == "--bind"]
        env = {argv[i + 1]: argv[i + 2] for i, item in enumerate(argv) if item == "--setenv"}
        expected = [(p, "/trust/ca.pem" if q == C.CA_FILE else q) for p, q in selection["files"]]
        expected += [(str(C.TASK / p), str(C.TASK / p)) for p in ("source", "inputs/rust")]
        expected += [(str(C.TASK / "download/empty-capath"), "/trust/empty"),
                     (str(C.TASK / "temporary/resolv.conf"), "/etc/resolv.conf")]
        self.assertEqual(readonly, expected)
        self.assertEqual(writable, [(str(C.TASK / "temporary" / name), str(C.TASK / "temporary" / name))
                                    for name in ("cargo", "home", "rustup", "tmp")])
        self.assertEqual((env["CARGO_HTTP_SSL_VERIFY"], env["CARGO_HTTP_SSL_CAINFO"], env["SSL_CERT_DIR"]),
                         ("true", "/trust/ca.pem", "/trust/empty"))
        self.assertEqual((env["CARGO_HTTP_PROXY"], env["CARGO_NET_RETRY"], env["HOME"]), ("", "0", str(C.TASK / "temporary/home")))
        self.assertEqual(argv[0], str(C.BWRAP_TARGET))
        self.assertNotIn("--unshare-net", argv)  # Acquisition only; native owner remains offline.
        for option in ("--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--clearenv", "--die-with-parent"):
            self.assertIn(option, argv)
        self.assertTrue(all(p not in ("/usr", "/etc", "/etc/ld.so.cache", "/etc/ssl/openssl.cnf")
                            and "ossl-modules" not in p and "ca-certificates/mozilla" not in p for p, _ in readonly))
        self.assertEqual(argv[-10:], [str(C.TASK / "inputs/rust/bin/cargo"), "metadata", "--locked", "--no-default-features",
                                     "--filter-platform", C.TARGET, "--format-version", "1", "--manifest-path",
                                     str(C.TASK / "source/desktop/src-tauri/Cargo.toml")])
        for mutate in (lambda v: v["cargoAcquisition"]["hostLibraries"].append("/usr"),
                       lambda v: v["cargoAcquisition"]["libraryAliases"][0].update(target="../unadmitted.so"),
                       lambda v: v["cargoAcquisition"]["resolverData"].update(uid=0),
                       lambda v: v["cargoAcquisition"]["resolverData"].update(role="runtime-executable"),
                       lambda v: v["cargoAcquisition"]["resolverData"]["parentRequirements"].reverse(),
                       lambda v: v["cargoAcquisition"]["resolverData"]["parentObservation"].update(resolverBodyObserved=True),
                       lambda v: v["hostFiles"].append({"path": C.CARGO_RESOLVER["path"]}),
                       lambda v: v["hostFiles"].__setitem__(slice(None), [r for r in v["hostFiles"] if r["path"] != C.CA_FILE])):
            changed = copy.deepcopy(catalogue)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(C.Refused):
                C.cargo_mount_selection(changed)
        self.assertTrue(catalogue["unresolved"])
        resolver = catalogue["cargoAcquisition"]["resolverData"]
        self.assertFalse(resolver["provenance"]["parentOriginalsObserved"])
        self.assertTrue(resolver["parentObservation"]["parentOriginalsObserved"])
        self.assertNotEqual(resolver["provenance"]["observationSha256"], resolver["parentObservation"]["observationSha256"])

    def test_cargo_resolver_is_exact_nonexecuting_data_and_never_general_runtime_authority(self):
        payload = b"nameserver 192.0.2.1\n"
        contract = {**C.CARGO_RESOLVER, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        catalogue = {"cargoAcquisition": {"resolverData": {**contract, "role": "cargo-acquisition-resolver-snapshot-only",
                     "parentRequirements": copy.deepcopy(C.CARGO_RESOLVER_PARENTS),
                     "parentObservation": copy.deepcopy(C.CARGO_RESOLVER_PARENT_OBSERVATION)}}}
        for mutate in (lambda row: row.pop("parentRequirements"),
                       lambda row: row["parentRequirements"].reverse(),
                       lambda row: row["parentRequirements"][3].update(uid=0),
                       lambda row: row["parentRequirements"][0].update(uid=False),
                       lambda row: row["parentObservation"].update(observationSha256="f" * 64),
                       lambda row: row["parentObservation"].update(parentOriginalsObserved=1),
                       lambda row: row["parentObservation"].update(freshOriginalCustodyRequired=False),
                       lambda row: row["parentObservation"].update(role="general-runtime-authority")):
            changed = copy.deepcopy(catalogue)
            mutate(changed["cargoAcquisition"]["resolverData"])
            with self.subTest(parent_contract=mutate), patch.object(C, "CARGO_RESOLVER", contract), \
                 patch.object(C.os, "open") as opening:
                with self.assertRaisesRegex(C.Refused, "cargo-resolver-parent-observation-contract"):
                    C.cargo_resolver_data(changed)
                opening.assert_not_called()
        target = Path(contract["path"])
        paths = (Path("/"), Path("/run"), Path("/run/systemd"), target.parent, target)
        for case in ("good", "parent-owner", "parent-writable", "leaf-owner", "leaf-executable", "leaf-alias",
                     "bytes", "replaced", "close-failed", "read-and-close-failed", "bytes-and-close-failed"):
            infos = {}
            for i, path in enumerate(paths):
                uid = 991 if i >= 3 else 0
                mode = stat.S_IFREG | 0o644 if path == target else stat.S_IFDIR | 0o755
                infos[path] = file_info(uid=uid, gid=uid, mode=mode)
                infos[path].st_ino = 100 + i
            infos[target].st_size = len(payload)
            if case == "parent-owner":
                infos[target.parent].st_uid = 1001
            if case == "parent-writable":
                infos[target.parent].st_mode = stat.S_IFDIR | 0o777
            if case == "leaf-owner":
                infos[target].st_uid = 0
            if case == "leaf-executable":
                infos[target].st_mode = stat.S_IFREG | 0o755
            if case == "leaf-alias":
                infos[target].st_mode = stat.S_IFLNK | 0o777
            opened, closed, descriptors = [], [], {}
            primary = OSError("inert resolver read failure")
            def opening(name, flags, *, dir_fd=None):
                path = Path(name) if dir_fd is None else descriptors[dir_fd] / name
                self.assertIn(path, paths)
                self.assertTrue(flags & C.os.O_NOFOLLOW and flags & C.os.O_CLOEXEC)
                self.assertTrue(flags & (C.os.O_NONBLOCK if path == target else C.os.O_DIRECTORY))
                fd = 90 + len(opened)
                opened.append(fd)
                descriptors[fd] = path
                return fd
            def lstat(path):
                value = copy.copy(infos[path])
                if path == target and case == "replaced":
                    value.st_ino += 1
                return value
            def close(fd):
                self.assertNotIn(fd, closed)
                closed.append(fd)
                if case in ("close-failed", "read-and-close-failed", "bytes-and-close-failed") and fd == opened[-1]:
                    raise OSError("inert close unknown")
            with self.subTest(case=case), patch.object(C, "CARGO_RESOLVER", contract), \
                 patch.object(C, "_ORIGINALS_SETTLED", True), patch.object(C.os, "open", side_effect=opening), \
                 patch.object(C.os, "fstat", side_effect=lambda fd: copy.copy(infos[descriptors[fd]])), \
                 patch.object(C.os, "read", side_effect=[primary] if case == "read-and-close-failed" else
                              [payload[::-1] if case in ("bytes", "bytes-and-close-failed") else payload, b""]), \
                 patch.object(Path, "lstat", lstat), patch.object(C.os, "close", side_effect=close), \
                 patch.object(C, "read", side_effect=AssertionError("do not relax the general root-owned reader")) as read:
                if case == "good":
                    raw, original = C.cargo_resolver_data(catalogue)
                    self.assertEqual(raw, payload)
                    self.assertEqual(original["file"]["uid"], 991)
                    self.assertEqual(original["file"]["mode"], "0o644")
                    self.assertEqual(len(original["parents"]), 4)
                else:
                    with self.assertRaises(OSError if case == "read-and-close-failed" else C.Refused) as failure:
                        C.cargo_resolver_data(catalogue)
                    if case == "read-and-close-failed":
                        self.assertIs(failure.exception, primary)
                    if case == "bytes-and-close-failed":
                        self.assertEqual(str(failure.exception), "cargo-resolver-original")
                self.assertEqual(closed, list(reversed(opened)))
                self.assertEqual(C._ORIGINALS_SETTLED, case not in ("close-failed", "read-and-close-failed", "bytes-and-close-failed"))
                self.assertEqual(C._PINS, {})
                read.assert_not_called()

    def test_cargo_metadata_preserves_one_original_wait_bounds_and_failure_latching(self):
        catalogue = json.loads((ROOT / "desktop/tools/gnome_session_native/runtime-suppliers.json").read_text())
        lock = b'[[package]]\nname = "inert"\nversion = "0.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
        original = {"inputs": {"files": []}, "capath": {"identity": [7, 81]}}
        resolver = {"identity": [7, 82]}
        snapshot = {"identity": [7, 83], "mode": "0o400"}
        for case in ("parser-boundary", "config", "foreign-lock", "missing-input", "unknown", "nonzero",
                     "input-changed", "resolver-changed", "snapshot-changed"):
            def read(path, *_args, **_kwargs):
                if Path(path).name == "Cargo.lock":
                    return (lock.replace(b"registry+https://github.com/rust-lang/crates.io-index", b"git+https://example.invalid/unadmitted")
                            if case == "foreign-lock" else lock), {}
                self.assertEqual(Path(path), C.TASK / "temporary/resolv.conf")
                return b"inert resolver", {} if case == "snapshot-changed" else snapshot
            def owned(argv, **kwargs):
                self.assertEqual(kwargs["environ"], C.ENV)
                self.assertEqual((kwargs["timeout"], kwargs["output_limit"], kwargs["cleanup"]), (420, 8 * C.MIB, False))
                self.assertEqual((kwargs["execution_scope"], kwargs["journal_binding"]), (None, None))
                if case == "unknown":
                    raise RuntimeError("inert original lifetime unknown")
                return SimpleNamespace(args=argv, returncode=1 if case == "nonzero" else 0, stdout=b"{}", stderr=b"")
            owner = SimpleNamespace(run_owned=Mock(side_effect=owned))
            before_after = [C.Refused("inert missing input")] if case == "missing-input" else [original,
                            {**original, "changed": True} if case == "input-changed" else original]
            with self.subTest(case=case), patch.object(C, "_OWNER", owner), patch.object(C, "_WAITS", []), \
                 patch.object(C, "_ORIGINALS_SETTLED", True), patch.object(C.time, "monotonic", return_value=0), \
                 patch.object(Path, "mkdir"), patch.object(Path, "lstat", return_value=file_info(mode=stat.S_IFDIR | 0o700)), \
                 patch.object(C.os, "listdir", return_value=[]), patch.object(Path, "exists", return_value=case == "config"), \
                 patch.object(Path, "is_symlink", return_value=False), patch.object(Path, "is_dir", return_value=False), \
                 patch.object(C, "read", side_effect=read), patch.object(C, "write", return_value=snapshot), \
                 patch.object(C, "cargo_resolver_data", side_effect=[(b"inert resolver", resolver),
                              (b"inert resolver", {} if case == "resolver-changed" else resolver)]), \
                 patch.object(C, "cargo_input_originals", side_effect=before_after), \
                 patch.object(C, "decode", side_effect=C.Refused("inert parser boundary")) as parser, \
                 patch.object(C, "owner_argv") as native:
                with self.assertRaises((C.Refused, RuntimeError)):
                    C.cargo_prepare(catalogue, {}, 900)
                prior = case in ("config", "foreign-lock", "missing-input")
                self.assertEqual(owner.run_owned.call_count, 0 if prior else 1)
                self.assertEqual(parser.call_count, int(case == "parser-boundary"))
                self.assertEqual(C._ORIGINALS_SETTLED, case != "unknown")
                if not prior:
                    self.assertEqual(len(C._WAITS), 1)
                    self.assertEqual(C._WAITS[0]["role"], "locked-headless-metadata")
                    self.assertEqual(C._WAITS[0]["originalsSettled"], case != "unknown")
                    self.assertEqual(C._WAITS[0]["exitCode"], None if case == "unknown" else 1 if case == "nonzero" else 0)
                native.assert_not_called()

    def test_cargo_input_mounts_require_the_complete_supplied_roster_and_bound_source(self):
        pin = {"identity": [7, 81], "bytes": 4, "sha256": "a" * 64, "mode": "0o400"}
        catalogue = {"nativePackages": [{"format": "deb", "members": [{"target": "native/09", **pin}]}],
                     "rust": [{"format": "tar.xz", "members": [{"target": "bin/cargo", **pin}]}]}
        roster = {"files": [{"path": str(C.TASK / "inputs" / name), **pin} for name in ("native/09", "rust/bin/cargo")],
                  "directories": [{"path": str(C.TASK / "inputs" / name), "mode": "0o700"}
                                  for name in (".", "native", "rust", "rust/bin")]}
        binding = {"sourceFiles": [{"path": "/source/inert", **pin, "snapshotIdentity": pin["identity"]}], "snapshotDirectories": []}
        for case in ("good", "missing", "extra", "input-mode", "directory", "host-original", "source-original"):
            actual = copy.deepcopy(roster)
            if case == "missing":
                actual["files"].pop()
            if case == "extra":
                actual["files"].append({**pin, "path": str(C.TASK / "inputs/unbound")})
            if case == "input-mode":
                actual["files"][0]["mode"] = "0o755"
            if case == "directory":
                actual["directories"].append({"path": str(C.TASK / "inputs/unbound"), "mode": "0o700"})
            def read(path, *_args, **_kwargs):
                changed = str(path) == C.CA_FILE and case == "host-original" or Path(path).name == "inert" and case == "source-original"
                return b"data", {**pin, "identity": [7, 99]} if changed else pin
            with self.subTest(case=case), patch.object(C, "_PINS", {C.CA_FILE: pin}), patch.object(C, "read", side_effect=read), \
                 patch.object(C, "bounded_roster", return_value=actual), patch.object(C, "source_directories", return_value=[]), \
                 patch.object(C, "acquisition_capath", return_value={"identity": [7, 90]}):
                if case == "good":
                    result = C.cargo_input_originals(catalogue, binding, {"hostFiles": [C.CA_FILE]})
                    self.assertEqual(result["inputs"], roster)
                    self.assertEqual(result["source"]["inert"], pin)
                else:
                    with self.assertRaises(C.Refused):
                        C.cargo_input_originals(catalogue, binding, {"hostFiles": [C.CA_FILE]})

    def test_original_network_deadlines_and_private_mount_scope_are_not_weakened(self):
        argv = C.owner_argv()
        self.assertIn("--unshare-net", argv)
        self.assertIn("690s", argv)
        self.assertIn("67108864", argv)
        self.assertIn("2147483648", argv)
        self.assertNotIn("--unshare-user", argv)
        entry = (ROOT / "desktop/tools/gnome_session_native/native-entry.sh").read_text()
        self.assertIn("expected_uid=61000\nexpected_gid=61000", entry)
        self.assertIn("[[ $interface == lo ]] || refuse network-interface", entry)
        self.assertIn("exec -c /mrk-libtest --ignored --exact --test-threads=1 --color=never --nocapture", entry)
        self.assertIn("fd-inheritance", entry)
        owner = (ROOT / "desktop/tools/gnome_session_native/owner.py").read_text()
        self.assertLess(owner.index('invoke("namespace-probe"'), owner.index('invoke("compile"'))
        self.assertIn('"540s"', owner)
        self.assertIn('"120s"', owner)

    @staticmethod
    def original_report():
        report = {"schema": "gnome-native-original-result-1", "sourceSha": "a" * 40, "sourceTree": "b" * 40,
                  "sourceBindingSha256": "c" * 64, "uid": 61000, "gid": 61000, "errors": [],
                  "completeSourceFiles": 975, "productTree": C.PRODUCT_TREE, "productFiles": 964, "hostArtifactsExported": False,
                  "artifact": {"sameInode": True, "copiedOrExported": False, "sha256": "d" * 64, "bytes": 123456,
                               "before": [7, 31, 0o100755, 1, 0, 0, 123456, 10, 11],
                               "afterModeTransition": [7, 31, 0o100555, 1, 0, 0, 123456, 10, 12]},
                  "stagedInputsPreNativeChecked": 8,
                  "runtimeInputsPrechecked": 42, "runtimeInputsPostchecked": 42, "runtimeInputsExpected": 42,
                  "nativeEvidence": {"cases": ["existing", "missing", "duplicate", "stop-after-secret", "deadline-after-secret", "owner-loss", "fresh-session-absent"],
                                     "actualLibtestPassed": 1, "persistent": False, "installedProvider": False, "gui": False},
                  "waits": [{"role": role, "originalEnvelopeExit": 0, "originalReaderExit": 0,
                             "readerTimedOut": False, "cleanupErrors": [], "logBytes": 20, "logSha256": "e" * 64}
                            for role in ("namespace-probe", "compile", "artifact-elf", "native", "source-post")]}
        for key in ("namespaceProbeAttempted", "namespaceProbePassed", "nativeEnvelopeAttempted", "nativeEntryObserved", "nativeAccepted", "passed",
                    "nestedNamespaceRetired", "completeSourceDependencyPostchecked", "artifactReceiptPostchecked", "artifactPostchecked",
                    "outerPrivateCohortQuiet", "hostReservationChecked", "pythonPycacheSameLeaf",
                    "pythonPycachePostchecked", "pythonPycacheHandlesClosed"):
            report[key] = True
        return report

    @staticmethod
    def original_output(report, *, compiled=True):
        prefix = (b'VAULT_FINALITY_COMPILE_WAITS=libtest:{"originalCargoEnvelopeExit":0,"logReaderExit":0}\n'
                  if compiled else b"")
        return prefix + b"GNOME_NATIVE_RESULT=" + C.canonical(report)

    def test_original_finality_rejects_skipped_smoke_errors_missing_cases_and_unwaited_reader(self):
        binding = {"sourceSha": "a" * 40, "fullTree": "b" * 40, "completeSourceFiles": 975}
        def parse(report):
            return C.parse_owner(self.original_output(report), binding, "c" * 64)
        self.assertTrue(parse(self.original_report())["passed"])
        mutations = [lambda r: r.update(namespaceProbePassed=False), lambda r: r.update(errors=["late-failure"]),
                     lambda r: r["nativeEvidence"]["cases"].pop(), lambda r: r["waits"][0].update(originalReaderExit=None),
                     lambda r: r["waits"][1].update(originalEnvelopeExit=False),
                     lambda r: r["artifact"].update(sha256=None), lambda r: r["waits"][1].pop("logSha256"),
                     lambda r: r.update(sourceBindingSha256="d" * 64), lambda r: r.update(runtimeInputsPostchecked=41),
                     lambda r: r.update(pythonPycacheSameLeaf=False), lambda r: r.pop("pythonPycachePostchecked"),
                     lambda r: r.update(pythonPycacheHandlesClosed=False)]
        for mutate in mutations:
            report = copy.deepcopy(self.original_report())
            mutate(report)
            with self.assertRaises(C.Refused):
                parse(report)
        with self.assertRaisesRegex(C.Refused, "compiler-original-wait-frame"):
            C.parse_owner(self.original_output(self.original_report(), compiled=False), binding, "c" * 64)

    def test_public_owner_keeps_actual_waits_and_hashes_not_private_data_or_fabricated_failure_results(self):
        binding = {"sourceSha": "a" * 40, "fullTree": "b" * 40, "completeSourceFiles": 975}
        report = self.original_report()
        report["waits"][0]["originalEnvelopePid"] = 12345
        report["artifact"]["path"] = "/private/task/libtest"
        value = C.public_owner(self.original_output(report), binding, "c" * 64)
        self.assertEqual(value["artifact"]["sha256"], "d" * 64)
        self.assertEqual(value["compilerWait"], {"originalCargoEnvelopeExit": 0, "logReaderExit": 0})
        self.assertTrue(all(row["originalReaderExit"] == 0 for row in value["waits"]))
        self.assertNotIn("originalEnvelopePid", C.canonical(value).decode())
        self.assertNotIn("/private/", C.canonical(value).decode())
        report.update(namespaceProbePassed=False, nativeEnvelopeAttempted=False, nativeAccepted=False, passed=False,
                      errors=["private diagnostic /private/task/do-not-publish"])
        report.pop("artifact")
        report.pop("nativeEvidence")
        report["waits"] = [report["waits"][0], report["waits"][-1]]
        report["waits"][0]["originalEnvelopeExit"] = 90
        failed = C.public_owner(self.original_output(report, compiled=False), binding, "c" * 64)
        self.assertFalse(failed["finality"]["passed"])
        self.assertEqual(failed["waits"][0]["originalEnvelopeExit"], 90)
        self.assertFalse(failed["waits"][1]["invocationRecorded"])
        self.assertIsNone(failed["waits"][1]["originalEnvelopeExit"])
        self.assertIsNone(failed["compilerWait"])
        self.assertIsNone(failed["artifact"])
        self.assertEqual(failed["errorCount"], 1)
        self.assertNotIn("private diagnostic", C.canonical(failed).decode())
        unknown = C.public_owner(b"incomplete original\n", binding, "c" * 64)
        self.assertFalse(unknown["sourceBoundResultObserved"])
        self.assertTrue(all(row["invocationRecorded"] is None for row in unknown["waits"]))
        self.assertIsNone(unknown["finality"]["passed"])

    def test_failure_projection_is_finite_and_cannot_be_native_evidence(self):
        raw = (b"MRK_GNOME_NATIVE_ENTRY refused=true site=network-interface\n"
               b'GNOME_NATIVE_NETWORK_SNAPSHOT={"outerClass":"non-loopback"}\n'
               b"private host account data must not escape\n")
        self.assertEqual(C.owner_diagnostic(raw), {"entryRefusal": "network-interface", "outerNetworkClass": "non-loopback"})
        self.assertNotIn("passed", C.owner_diagnostic(raw))

    def test_failed_owner_and_failed_host_post_do_not_skip_independent_data_postconditions(self):
        for uncertain_original in (False, True):
            events, writes = [], {}
            binding = {"workflowDeadlineMonotonic": 999999999.0}
            def source(_):
                events.append("source")
                return binding, "c" * 64
            def capture(stage, *_args, **_kwargs):
                events.append(stage)
                if stage == "after-settlement":
                    raise C.Refused("host-post-failed")
                return {"stage": stage}
            def original(*_args, **_kwargs):
                if uncertain_original:
                    C._ORIGINALS_SETTLED = False
                    raise C.Refused("original-unsettled")
                return SimpleNamespace(returncode=1, stdout=b"failed\n", stderr=b"")
            def roster(*_args, **_kwargs):
                events.append("inputs")
                return {}
            def read(path, *_args):
                value = {"networkPreparationComplete": True, "originalsSettled": True} if path.name == "acquired.json" else {}
                return C.canonical(value), {}
            def write(path, raw, *_args):
                writes[path.name] = raw
                return {"sha256": hashlib.sha256(raw).hexdigest()}
            with self.subTest(uncertain_original=uncertain_original), patch.multiple(C,
                _ORIGINALS_SETTLED=True, binding_for=source, read=read, write=write, command=original,
                acquisition_for=lambda *_: {}, registry_originals=lambda stage: events.append("registry-" + stage),
                host_module=lambda _: (SimpleNamespace(public_projection=lambda *_a, **_k: {}), SimpleNamespace(capture=capture)),
                load_host=lambda _: {}, save_host=lambda *_: None, bounded_roster=roster,
                authenticate_host=lambda *_a, **_k: events.append("host-tools")):
                with self.assertRaisesRegex(C.Refused, "native-owner-or-postconditions-failed"):
                    C.run_native({}, {})
            self.assertEqual(events.count("source"), 2)
            self.assertEqual(events.count("inputs"), 2)
            self.assertIn("registry-before-owner", events)
            self.assertIn("registry-after-owner", events)
            self.assertIn("host-tools", events)
            self.assertEqual("after-settlement" in events, not uncertain_original)
            diagnostic = json.loads(writes["owner-diagnostic.json"])
            self.assertFalse(diagnostic["nativeQualified"])
            self.assertFalse(diagnostic["cleanupVerified"])
            self.assertNotIn("native-result.json", writes)

    def test_settlement_deletes_registry_against_acquisition_originals_not_a_fresh_roster(self):
        context = {"sourceSha": "a" * 40}
        binding = {**context, "fullTree": "b" * 40, "completeSourceFiles": 975}
        report = self.original_report()
        value = {"passed": True, "originalsSettled": True, "outerNamespaceRetired": True,
                 "host": {"phases": list(H.STAGES)}, "owner": report, "waits": [], "reservationSha256": "f" * 64}
        registry, inputs = {"bytes": 4, "original": "registry"}, {"bytes": 2, "original": "inputs"}
        events, writes = [], {}
        def read(path, *_args, **_kwargs):
            if path.name == "native-result.json":
                return C.canonical(value), {}
            if path.name == "native-owner.stdout":
                return self.original_output(report), {}
            if path.name == "account-reservation.json":
                return b"inert", {"sha256": "f" * 64, "mode": "0o400"}
            self.assertEqual(path.name, "input-roster.json")
            return C.canonical(inputs), {}
        def original_registry(stage):
            events.append(("registry-check", stage))
            return registry
        def roster(path, **_kwargs):
            self.assertIn(path.name, ("download", "temporary"))
            return {"bytes": 8, "original": path.name}
        def remove(path, original):
            events.append(("remove", str(path), original))
        with patch.dict(C.os.environ, {"MRK_ORIGINAL_OUTCOME": "success"}), patch.multiple(C,
             binding_for=lambda _: (binding, "c" * 64), acquisition_for=lambda *_: {}, read=read,
             original_outer=lambda *_: {"originalWait": True, "exitCode": 0, "outputWritersClosed": True},
             authenticate_host=lambda *_a, **_k: None, acquisition_capath=lambda *_: None, registry_originals=original_registry,
             bounded_roster=roster, remove_settled=remove, pycache_finish=lambda: None, python_alias_finish=lambda: None,
             write=lambda path, raw, *_: writes.update({path.name: raw})):
            C.settle(context, {})
        self.assertEqual(events[0], ("registry-check", "before-cleanup"))
        self.assertEqual(events[1], ("remove", str(C.TASK / "temporary/cargo/registry"), registry))
        self.assertEqual(events[-1], ("remove", str(C.TASK / "inputs"), inputs))
        result = json.loads(writes["result.json"])
        self.assertEqual(result["disposedTaskInputBytes"], 22)
        self.assertEqual(result["evidence"]["owner"]["artifact"]["sha256"], "d" * 64)

    def test_complete_source_directories_refuse_untracked_empty_directory_or_alias(self):
        with tempfile.TemporaryDirectory(prefix="mrk-gnome-contract-") as path:
            root = Path(path)
            (root / "src").mkdir(mode=0o700)
            (root / "src/one.txt").write_bytes(b"source DATA\n")
            before = C.source_directories(root, ["src/one.txt"], original=True)
            self.assertEqual(C.source_directories(root, ["src/one.txt"], original=True), before)
            (root / "extra").mkdir(mode=0o700)
            with self.assertRaises(C.Refused):
                C.source_directories(root, ["src/one.txt"], original=True)
            (root / "extra").rmdir()
            (root / "alias").symlink_to("src", target_is_directory=True)
            with self.assertRaises(C.Refused):
                C.source_directories(root, ["src/one.txt"], original=True)

    def test_native_destinations_are_closed_private_sources_not_ambient_host_files(self):
        layout = json.loads((ROOT / "desktop/tools/gnome_session_native/runtime-layout.json").read_text())
        rows = layout["installedFileMounts"]
        self.assertEqual(len(rows), 31)
        self.assertEqual({row["path"] for row in rows}, {"/inputs/native/" + str(i).zfill(2) for i in range(31)})
        self.assertEqual(len({row["nativeDestination"] for row in rows}), 31)
        self.assertEqual(layout["credentials"]["actualNonzeroUid"], 61000)
        self.assertTrue(layout["credentials"]["hostAccountFilesChanged"])

    def test_native_catalogue_binds_each_body_and_retained_tar_not_only_counts(self):
        layout = json.loads((ROOT / "desktop/tools/gnome_session_native/runtime-layout.json").read_text())
        value = json.loads((ROOT / "desktop/tools/gnome_session_native/runtime-suppliers.json").read_text())
        # Complete only the three already frozen tar facts in this inert input;
        # this is not a catalogue_ready call or supplier admission.
        for row in layout["stagedPackageMembers"]:
            package = next(item for item in value["nativePackages"] if item.get("retainedTar") == Path(row["sourceTar"]).name)
            package.update(decodedBytes=row["tarBytes"], decodedSha256=row["tarSha256"])
        self.assertEqual(C.native_layout(value, layout), layout)
        changed = copy.deepcopy(value)
        changed["nativePackages"][0]["members"][0]["sha256"] = "0" * 64
        with self.assertRaises(C.Refused):
            C.native_layout(changed, layout)
        changed = copy.deepcopy(layout)
        changed["stagedPackageMembers"][0]["sourceTar"] = "/inputs/native-tars/01.tar"
        with self.assertRaises(C.Refused):
            C.native_layout(value, changed)

    def test_workflow_never_uses_raw_historical_path_or_uploads_private_roots(self):
        workflow = (ROOT / C.WORKFLOW).read_text()
        self.assertNotIn("ci_foundation.py", workflow)
        self.assertNotIn("secrets:", workflow)
        self.assertNotIn("setup-python", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("--clear-groups", workflow)
        self.assertIn("steps.native.outcome == 'success'", workflow)
        job_header = workflow.split("  gnome-session-native:\n", 1)[1].split("    steps:\n", 1)[0]
        self.assertNotIn("runner.environment", job_header)
        self.assertEqual(workflow.count("RUNNER_ENVIRONMENT: ${{ runner.environment }}"), 5)
        supply = '"$GITHUB_WORKSPACE/desktop/tools/gnome_session_hosted.py" supply-bwrap </dev/null'
        self.assertEqual(workflow.count(supply), 1)
        self.assertLess(workflow.index(supply), workflow.index("for phase in prepare acquire; do"))
        self.assertIn("        id: bwrap\n        timeout-minutes: 5\n", workflow)
        for installer in ("apt-get", "apt install", "dpkg --install", "dpkg -i"):
            self.assertNotIn(installer, workflow)
        for relative in C.CARRIER_FILES:
            if relative != C.WORKFLOW:
                self.assertIn(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() + "  " + relative, workflow)
        public_paths = workflow.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]
        self.assertTrue(all(line.strip().startswith(str(C.PUBLIC) + "/") for line in public_paths.splitlines() if line.strip()))


if __name__ == "__main__":
    unittest.main()
