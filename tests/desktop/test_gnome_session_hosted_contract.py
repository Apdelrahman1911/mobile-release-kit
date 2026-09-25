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
            "ImageOS": "ubuntu24", "ImageVersion": C.SUPPORTED_IMAGE_VERSION, "GITHUB_REF": C.REF,
            "GITHUB_REPOSITORY": "example/project", "GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40,
            "GITHUB_WORKFLOW_REF": "example/project/" + C.WORKFLOW + "@" + C.REF,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push",
            "MRK_PUSH_EVENT_AFTER": "a" * 40, "MRK_EXPECTED_SHA": ""}



def characterization_environment(*, post=False):
    value = {**C.ENV, **environment(), "GITHUB_REF": C.CONTROLLER_CHARACTERIZATION_REF,
        "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit",
        "GITHUB_WORKFLOW_REF": "Apdelrahman1911/mobile-release-kit/" + C.WORKFLOW + "@" + C.CONTROLLER_CHARACTERIZATION_REF}
    if post:
        value.update(MRK_CONTROLLER_STAGE_OUTCOME="success", MRK_CONTROLLER_CHECK_OUTCOME="success")
    return value


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
                                        "bwrapSupply": None, "pythonPycache": None, "controllerRuntime": None}),
                            ("_WAITS", []), ("_PINS", {}), ("_SUPPLIERS", []),
                            ("_OWNER", None), ("_PYCACHE", None), ("_PYTHON_RUNTIME", None),
                             ("_CONTROLLER_SOURCE", None), ("_CONTROLLER_CHECK_STATE", None), ("_ORIGINALS_SETTLED", True)):
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
             patch.object(C, "authenticate_python_runtime") as runtime:
            C.authenticate_host(catalogue)
        command.assert_not_called()
        absence.assert_called_once_with(catalogue)
        runtime.assert_called_once_with(catalogue)
        self.assertIn("not-retroactive", C._EVIDENCE["hostAuthenticationScope"])
        self.assertEqual(C._EVIDENCE["hostToolSuppliers"][0]["packageVersion"], row["version"])
        self.assertEqual(C._EVIDENCE["hostToolSuppliers"][0]["basis"],
                         "authenticated-supplier-payload-correspondence; version-probe-not-run")
        C._EVIDENCE["hostToolSuppliers"] = None
        with patch.object(C, "read", return_value=(b"changed", {**pin, "sha256": "f" * 64})), \
             patch.object(C, "authenticate_absent_host_inputs") as absence, patch.object(C, "authenticate_python_runtime"):
            with self.assertRaisesRegex(C.Refused, "host-tool-payload-differs"):
                C.authenticate_host(catalogue, after=True)
        absence.assert_called_once_with(catalogue)
        self.assertIsNone(C._EVIDENCE["hostToolSuppliers"])

    @staticmethod
    def python_catalogue():
        # Literal SOURCE DATA, not a newly observed host or an execution grant.
        return json.loads((ROOT / "desktop/tools/gnome_session_native/runtime-suppliers.json").read_text())

    @staticmethod
    def selected_python():
        prefix = str(C.PYTHON_ROOT / "python")
        return SimpleNamespace(executable=C.PYTHON_EXECUTABLE, path=list(C.PYTHON_SEARCH),
            version_info=(3, 14, 7), builtin_module_names=C.PYTHON_BUILTINS,
            implementation=SimpleNamespace(name="cpython", cache_tag="cpython-314"),
            prefix=prefix, base_prefix=prefix, exec_prefix=prefix, base_exec_prefix=prefix,
            flags=SimpleNamespace(isolated=1, no_site=1, optimize=0), dont_write_bytecode=True,
            pycache_prefix=str(C.PYTHON_PYCACHE))

    def test_python_catalogue_requires_complete_private_projection_and_provenance(self):
        value = self.python_catalogue()
        self.assertEqual(C.python_runtime_catalogue(value),
            {"runtimeFiles": 598, "runtimeDirectories": 53, "runtimeBytes": 27303244,
             "normalSourceCacheInputs": 0, "pinnedSourceCacheDataRows": 0})
        runtime = value["controllerRuntime"]
        self.assertEqual(sum(row["bytes"] == 0 for row in runtime["projection"]["files"]), 7)
        self.assertEqual(hashlib.sha256(C.canonical(runtime)).hexdigest(), C.CONTROLLER_RUNTIME_SHA256)
        self.assertEqual(runtime["version"], [3, 14, 7])
        self.assertEqual(len(runtime["builtins"]), 60)
        self.assertIn("_ctypes", runtime["builtins"])
        self.assertEqual(runtime["sharedExtensionModules"], [])
        mutations = (
            ("missing-file", lambda r: r["projection"]["files"].pop()),
            ("extra-file", lambda r: r["projection"]["files"].append(copy.deepcopy(r["projection"]["files"][0]))),
            ("duplicate-file", lambda r: r["projection"]["files"].__setitem__(-1, copy.deepcopy(r["projection"]["files"][0]))),
            ("absolute", lambda r: r["projection"]["files"][0].update(path="/outside")),
            ("parent", lambda r: r["projection"]["files"][0].update(path="python/../outside")),
            ("foreign", lambda r: r["projection"]["files"][0].update(path="core.zip")),
            ("pyc", lambda r: r["projection"]["files"][0].update(path="python/cache.pyc")),
            ("cache", lambda r: r["projection"]["files"][0].update(path="python/__pycache__/cache.py")),
            ("bool-size", lambda r: r["projection"]["files"][0].update(bytes=True)),
            ("size", lambda r: r["projection"]["files"][0].update(bytes=-1)),
            ("hash", lambda r: r["projection"]["files"][0].update(sha256="0" * 64)),
            ("mode", lambda r: r["projection"]["files"][0].update(mode="0o777")),
            ("archive-mode", lambda r: r["projection"]["files"][0].update(archiveMode="0o555")),
            ("origin", lambda r: r["projection"]["files"][0].update(origin="unreviewed-host")),
            ("missing-directory", lambda r: r["projection"]["directories"].pop()),
            ("duplicate-directory", lambda r: r["projection"]["directories"].__setitem__(-1, copy.deepcopy(r["projection"]["directories"][0]))),
            ("directory-mode", lambda r: r["projection"]["directories"][0].update(mode="0o755")),
            ("directory-roster", lambda r: r["projection"]["directories"][0]["entries"].append("extra")),
            ("alias", lambda r: r["projection"]["aliases"].append({"path": "python/alias", "target": "/usr/bin/python3.12"})),
            ("prefix", lambda r: r.update(prefix="/usr")),
            ("search", lambda r: r["searchPath"].append("/usr/lib/python3.12")),
            ("builtin", lambda r: r["builtins"].remove("_ctypes")),
            ("extra-builtin", lambda r: r["builtins"].append("_unbound")),
            ("shared-ctypes", lambda r: r["sharedExtensionModules"].append("_ctypes")),
            ("zip-absent", lambda r: r.update(emptyZip=None)),
            ("zip-hash", lambda r: r["emptyZip"].update(sha256="0" * 64)),
            ("archive", lambda r: r["archive"].update(sha256="0" * 64)),
        )
        with patch.object(C, "command") as command, patch.object(C, "read") as read:
            for name, mutate in mutations:
                changed = copy.deepcopy(value)
                mutate(changed["controllerRuntime"])
                with self.subTest(mutation=name), self.assertRaises(C.Refused):
                    C.python_runtime_catalogue(changed)
        command.assert_not_called()
        read.assert_not_called()

    def test_actual_python_selection_binds_reexec_search_and_bytecode_read_policy(self):
        selected = self.selected_python()
        value, cache = self.python_catalogue(), self.pycache_fixture()
        state = {"receipt": {"pythonPycache": cache}, "receiptPin": {"sha256": "f" * 64}}
        with patch.object(C, "sys", selected), patch.object(C, "_PYTHON_RUNTIME", state), \
             patch.object(C, "root_absent") as absent, patch.object(C, "command") as command, \
             patch.object(C, "pycache_original", return_value=cache) as custody, \
             patch.object(C, "controller_runtime_original") as runtime, \
             patch.object(C.importlib.util, "find_spec", return_value=SimpleNamespace(origin="built-in")) as spec:
            C.authenticate_python_runtime(value)
        custody.assert_called_once_with()
        runtime.assert_called_once_with()
        spec.assert_called_once_with("_ctypes")
        absent.assert_called_once_with("/usr/lib/python312.zip", "old-python-zip")
        command.assert_not_called()
        observed = C._EVIDENCE["pythonRuntime"]
        self.assertEqual(observed["pinnedSourceCacheDataRows"], 0)
        self.assertEqual(observed["bytecodePolicy"], "complete-no-pyc-private-projection; fixed-empty-normal-source-cache; writes-disabled")
        self.assertEqual(observed["pycachePrefix"], str(C.PYTHON_PYCACHE))
        self.assertEqual(observed["normalSourceCacheInputs"], 0)
        self.assertTrue(observed["emptyZipPresentAndPinned"])
        self.assertEqual(observed["ctypes"], "static-builtin")
        self.assertFalse(observed["sourcelessOrZipExecutionDisabled"])
        self.assertFalse(observed["oldCachesPhysicallyInaccessible"])
        with patch.object(C, "sys", selected), patch.object(C, "command") as command:
            with self.assertRaisesRegex(C.Refused, "pycache-original-custody-required"):
                C.authenticate_python_runtime(value)
        command.assert_not_called()
        with patch.object(C, "sys", selected), patch.object(C, "pycache_original", return_value=cache):
            with self.assertRaisesRegex(C.Refused, "controller-runtime-original-required"):
                C.authenticate_python_runtime(value)
        for origin in (None, "/usr/lib/python3.12/lib-dynload/_ctypes.so"):
            with self.subTest(origin=origin), patch.object(C, "sys", selected), patch.object(C, "_PYTHON_RUNTIME", state), \
                 patch.object(C, "pycache_original", return_value=cache), patch.object(C, "controller_runtime_original"), \
                 patch.object(C.importlib.util, "find_spec", return_value=None if origin is None else SimpleNamespace(origin=origin)), \
                 patch.object(C, "root_absent") as absent:
                with self.assertRaisesRegex(C.Refused, "controller-runtime-ctypes-not-builtin"):
                    C.authenticate_python_runtime(value)
            absent.assert_not_called()
        for field, changed in (("executable", "/usr/bin/python3.12"), ("path", ["/other", *C.PYTHON_SEARCH]),
                               ("version_info", (3, 12, 3)), ("builtin_module_names", ("_ctypes",)),
                               ("base_prefix", "/venv"), ("pycache_prefix", None), ("pycache_prefix", "/unbound"),
                               ("pycache_prefix", str(C.PYTHON_PYCACHE) + "/"), ("dont_write_bytecode", False),
                               ("flags", SimpleNamespace(isolated=1, no_site=0, optimize=0)),
                               ("implementation", SimpleNamespace(name="cpython", cache_tag="cpython-312"))):
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

    @staticmethod
    def pycache_fixture():
        infos = [file_info(mode=stat.S_IFDIR | mode) for mode in (0o755, 0o755, 0o555)]
        for index, info in enumerate(infos):
            info.st_ino = 100 + index
        return {"path": str(C.PYTHON_PYCACHE), "identity": C.identity(infos[-1]), "entries": [],
                "parents": [{"path": path, "custody": C.directory_custody(info)}
                            for path, info in zip(("/", "/run"), infos)]}

    def controller_fixture(self):
        catalogue = self.python_catalogue()
        runtime = catalogue["controllerRuntime"]
        projection = {"files": [], "directories": [], "bytes": 27303244}
        infos = {}
        for index, row in enumerate(runtime["projection"]["directories"]):
            path = C.PYTHON_ROOT / row["path"]
            info = file_info(mode=stat.S_IFDIR | 0o555)
            info.st_ino = 1000 + index
            infos[path] = info
            projection["directories"].append({"path": str(path), "mode": row["mode"],
                "entries": list(row["entries"]), "identity": C.identity(info)})
        for index, row in enumerate(runtime["projection"]["files"]):
            path = C.PYTHON_ROOT / row["path"]
            info = file_info(mode=stat.S_IFREG | int(row["mode"], 8))
            info.st_ino, info.st_size = 2000 + index, row["bytes"]
            infos[path] = info
            projection["files"].append({"path": str(path), "identity": C.identity(info),
                **{key: row[key] for key in ("bytes", "sha256", "mode")}})
        projection["rootIdentity"] = C.identity(infos[C.PYTHON_ROOT])
        for path, inode, mode in ((Path("/"), 900, 0o755), (Path("/run"), 901, 0o755), (C.PYTHON_STAGE, 902, 0o700)):
            infos[path] = file_info(mode=stat.S_IFDIR | mode)
            infos[path].st_ino = inode
        source_pin, helper_pin = ({"sha256": c * 64, "mode": "0o600", "identity": [7, n]}
                                  for c, n in (("d", 41), ("e", 42)))
        receipt = {"schema": C.CONTROLLER_ORIGINALS_SCHEMA, **C.workflow_context(environment()),
            "controllerCatalogueSha256": C.CONTROLLER_RUNTIME_SHA256,
            "sourceCatalogue": source_pin, "unpackHelper": helper_pin,
            "projection": projection, "pythonPycache": self.pycache_fixture(),
            "parents": [{"path": str(path), "custody": C.directory_custody(infos[path])}
                        for path in (Path("/"), Path("/run"))],
            "readonlyMountRequiredBeforePrivateStartup": True, "retirement": "disposable-vm-only"}
        raw = C.canonical(receipt)
        info = file_info(mode=stat.S_IFREG | 0o400)
        info.st_ino, info.st_size = 3000, len(raw)
        pin = {"identity": C.identity(info), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": "0o400"}
        return {"catalogue": catalogue, "runtime": runtime, "projection": projection, "infos": infos,
                "receipt": receipt, "pin": pin}

    def test_controller_bootstrap_refuses_occupied_prefix_and_stage_before_helper_import(self):
        value = self.python_catalogue()
        provider = value["controllerRuntime"]["bootstrap"]["python"]
        selected = SimpleNamespace(executable=provider["path"], version_info=(3, 12, 3), prefix="/usr", base_prefix="/usr")
        pin = {"bytes": provider["size"], "sha256": provider["sha256"], "mode": "0o755"}
        for occupied in (C.PYTHON_ROOT, C.PYTHON_STAGE):
            def named(path):
                if path == Path("/run") or path == occupied:
                    return file_info()
                self.assertIn(path, (C.PYTHON_ROOT, C.PYTHON_STAGE))
                raise FileNotFoundError
            with self.subTest(occupied=occupied), patch.object(C, "sys", selected), \
                 patch.object(C, "read", return_value=(b"inert-provider", pin)), patch.object(Path, "lstat", named), \
                 patch.object(Path, "is_symlink", return_value=True), \
                 patch.object(C.os, "readlink", side_effect=lambda p: {"/bin": "usr/bin", "/usr/bin/python3": "python3.12"}[p]), \
                 patch.object(C.importlib.util, "spec_from_file_location") as imported, \
                 patch.object(Path, "mkdir") as mkdir, patch.object(C, "command") as command, \
                 patch.object(C, "owner_modules") as owner:
                with self.assertRaisesRegex(C.Refused, "controller-runtime-exclusive-root-occupied"):
                    C.stage_controller_runtime(C.workflow_context(environment()), value, {})
            for blocked in (imported, mkdir, command, owner):
                blocked.assert_not_called()

    def test_controller_runtime_originals_require_readonly_members_parents_receipt_and_exact_closes(self):
        cases = ("good", "partial-open", "partial-fstat", "unsafe-parent", "stage-owner", "receipt-context",
                 "source-original", "root-replaced", "root-writable", "member-writable", "directory-writable",
                 "missing-member", "extra-member", "member-hash", "parent-roster",
                 "post-parent", "post-root", "post-receipt", "post-member", "close-unknown", "body-and-close")
        for case in cases:
            fixture = self.controller_fixture()
            infos, projection, receipt, pin = (fixture[key] for key in ("infos", "projection", "receipt", "pin"))
            changed_receipt = copy.deepcopy(receipt)
            if case == "receipt-context":
                changed_receipt["sourceSha"] = "b" * 40
            opened, closed, descriptors = [], [], {}
            state = {"post": False, "unknown": False}
            first_file = Path(projection["files"][0]["path"])
            first_directory = C.PYTHON_ROOT / "python"
            primary = OSError("inert runtime fstat")
            def opening(name, flags, *, dir_fd=None):
                path = Path(name) if dir_fd is None else descriptors[dir_fd] / name
                self.assertIn(path, infos)
                self.assertTrue(flags & C.os.O_NOFOLLOW)
                if case == "partial-open" and path == C.PYTHON_ROOT:
                    raise OSError("inert runtime nofollow")
                fd = 70 + len(opened)
                opened.append(fd)
                descriptors[fd] = path
                return fd
            def fstat(fd):
                self.assertIn(fd, opened)
                self.assertNotIn(fd, closed)
                if case == "partial-fstat" and fd == 70:
                    self.assertIn(fd, C._PYTHON_RUNTIME["fds"])
                    raise primary
                if case == "body-and-close" and descriptors[fd] == first_file:
                    raise primary
                info = copy.copy(infos[descriptors[fd]])
                if case == "unsafe-parent" and descriptors[fd] == Path("/run"):
                    info.st_mode = stat.S_IFDIR | 0o777
                return info
            def named(path):
                info = copy.copy(infos[path])
                if (case == "root-replaced" and path == C.PYTHON_ROOT
                        or state["post"] and case == "post-parent" and path == Path("/run")
                        or state["post"] and case == "post-root" and path == C.PYTHON_ROOT):
                    info.st_ino += 1
                if case == "stage-owner" and path == C.PYTHON_STAGE:
                    info.st_uid = 1001
                return info
            def readonly(fd):
                path = descriptors[fd]
                writable = (case == "root-writable" and path == C.PYTHON_ROOT
                            or case == "member-writable" and path == first_file
                            or case == "directory-writable" and path == first_directory)
                return SimpleNamespace(f_flag=0 if writable else C.os.ST_RDONLY)
            def roster(root, **bounds):
                self.assertEqual((root, bounds), (C.PYTHON_ROOT, {"files": 700, "total": 32 * C.MIB}))
                actual = copy.deepcopy(projection)
                if case == "missing-member":
                    actual["files"].pop()
                elif case == "extra-member":
                    actual["files"].append({**actual["files"][0], "path": str(C.PYTHON_ROOT / "extra")})
                elif case == "member-hash" or state["post"] and case == "post-member":
                    actual["files"][0]["sha256"] = "0" * 64
                elif case == "parent-roster":
                    actual["directories"][0]["entries"].append("extra")
                return actual
            def retained(path, *args, **kwargs):
                if path == C.PYTHON_ORIGINALS:
                    selected_pin = copy.deepcopy(pin)
                    if state["post"] and case == "post-receipt":
                        selected_pin["identity"][1] += 1
                    return C.canonical(changed_receipt), selected_pin
                if path == C.SOURCE / C.CONTROL / "runtime-suppliers.json":
                    return b"inert-source", {} if case == "source-original" else receipt["sourceCatalogue"]
                self.assertEqual(path, C.SOURCE / "desktop/tools/conventional_runtime_data.py")
                return b"inert-helper", receipt["unpackHelper"]
            def close(fd):
                self.assertNotIn(fd, closed)
                self.assertNotIn(fd, C._PYTHON_RUNTIME["fds"])
                closed.append(fd)
                if case in ("close-unknown", "body-and-close") and descriptors[fd] == first_file and not state["unknown"]:
                    state["unknown"] = True
                    raise OSError("inert runtime close unknown")
            with self.subTest(case=case), patch.multiple(C, _PYTHON_RUNTIME=None, _PINS={}, _ORIGINALS_SETTLED=True), \
                 patch.object(C.os, "open", side_effect=opening), patch.object(C.os, "fstat", side_effect=fstat), \
                 patch.object(C.os, "fstatvfs", side_effect=readonly), patch.object(C.os, "close", side_effect=close), \
                 patch.object(Path, "lstat", named), patch.object(C, "read", side_effect=retained), \
                 patch.object(C, "bounded_roster", side_effect=roster), patch.object(C, "command") as command:
                try:
                    if case == "good" or case.startswith("post-"):
                        C.controller_runtime_begin(C.workflow_context(environment()), fixture["catalogue"])
                        self.assertEqual(len(C._PYTHON_RUNTIME["fds"]), 3)
                        self.assertEqual(len(C._PINS), 599)
                        self.assertEqual(C._PINS[str(C.PYTHON_ORIGINALS)], pin)
                        state["post"] = True
                        if case == "good":
                            C.controller_runtime_finish()
                            self.assertTrue(C._EVIDENCE["controllerRuntime"]["phaseCustodyPostchecked"])
                        else:
                            with self.assertRaises(C.Refused):
                                C.controller_runtime_finish()
                    else:
                        with self.assertRaises((C.Refused, OSError)) as error:
                            C.controller_runtime_begin(C.workflow_context(environment()), fixture["catalogue"])
                        if case in ("partial-fstat", "body-and-close"):
                            self.assertIs(error.exception, primary)
                finally:
                    C.controller_runtime_finish(failed=True)
                self.assertTrue(C._PYTHON_RUNTIME["closed"])
                self.assertEqual(C._PYTHON_RUNTIME["fds"], [])
                self.assertEqual(sorted(closed), sorted(opened))
                self.assertEqual(len(closed), len(set(closed)))
                self.assertEqual(C._ORIGINALS_SETTLED, case not in ("close-unknown", "body-and-close"))
                self.assertEqual(C._EVIDENCE["controllerRuntime"]["phaseHandlesClosed"],
                                 case not in ("close-unknown", "body-and-close"))
                command.assert_not_called()

    def test_runtime_and_pycache_finalizers_both_run_without_masking_first_failure(self):
        first, second = C.Refused("inert runtime first"), OSError("inert cache close")
        for failed in (False, True):
            events = []
            def runtime(*, failed):
                events.append(("runtime", failed))
                raise first
            def cache(*, failed):
                events.append(("cache", failed))
                raise second
            with self.subTest(failed=failed), patch.object(C, "controller_runtime_finish", side_effect=runtime), \
                 patch.object(C, "pycache_finish", side_effect=cache):
                if failed:
                    C.phase_finish(failed=True)
                else:
                    with self.assertRaises(C.Refused) as error:
                        C.phase_finish()
                    self.assertIs(error.exception, first)
            self.assertEqual(events, [("runtime", failed), ("cache", failed)])

    def test_namespace_runtime_requires_same_readonly_projection_and_actual_old_profile_masks(self):
        cases = ("good", "root-writable", "parent-writable", "member-writable", "directory-replaced",
                 "old-executable-missing", "old-executable-replaced", "old-executable-writable",
                 "old-stdlib-missing", "old-stdlib-replaced", "old-stdlib-writable",
                 "old-alias-text", "old-alias-original", "old-zip-present",
                 "post-root", "post-mask", "post-accounting", "close-unknown")
        for case in cases:
            fixture = self.controller_fixture()
            infos, projection, receipt, pin = (fixture[key] for key in ("infos", "projection", "receipt", "pin"))
            cache_info = file_info(mode=stat.S_IFDIR | 0o555)
            cache_info.st_ino = 102
            zip_row = next(row for row in projection["files"] if row["path"] == C.PYTHON_SEARCH[0])
            zip_info = infos[Path(C.PYTHON_SEARCH[0])]
            aliases = ("/usr/bin/python3", "/bin/python3", "/bin/python3.12")
            infos[Path("/usr/bin/python3.12")] = zip_info
            for name in ("/usr/lib/python3.12", "/lib/python3.12"):
                infos[Path(name)] = cache_info
            expected = {"catalogueSha256": C.CONTROLLER_RUNTIME_SHA256, "originals": pin,
                        "projection": projection, "builtins": list(C.PYTHON_BUILTINS), "searchPath": list(C.PYTHON_SEARCH)}
            directory_rows = {Path(row["path"]): row for row in projection["directories"]}
            first_file = Path(projection["files"][0]["path"])
            opened, closed, descriptors = [], [], {}
            state = {"post": False}
            def opening(name, flags, *, dir_fd=None):
                path = Path(name) if dir_fd is None else descriptors[dir_fd] / name
                self.assertIn(path, infos)
                self.assertTrue(flags & N.os.O_NOFOLLOW)
                self.assertLessEqual(len(opened) - len(closed), 3)
                fd = 80 + len(opened)
                opened.append(fd)
                descriptors[fd] = path
                return fd
            def fstat(fd):
                self.assertNotIn(fd, closed)
                return copy.copy(infos[descriptors[fd]])
            def named(path):
                if path == Path("/usr/lib/python312.zip"):
                    if case != "old-zip-present":
                        raise FileNotFoundError
                    return file_info(mode=stat.S_IFREG | 0o444)
                if path == Path("/usr/lib/python3.12") and case == "old-stdlib-missing":
                    raise FileNotFoundError
                info = copy.copy(infos[path])
                if (case == "directory-replaced" and path == C.PYTHON_ROOT / "python"
                        or case == "old-stdlib-replaced" and path == Path("/usr/lib/python3.12")
                        or state["post"] and case == "post-root" and path == C.PYTHON_ROOT
                        or state["post"] and case == "post-mask" and path == Path("/usr/lib/python3.12")):
                    info.st_ino += 1
                return info
            def named_stat(name, *, dir_fd=None, follow_symlinks=True):
                if dir_fd is not None:
                    self.assertFalse(follow_symlinks)
                    return named(descriptors[dir_fd] / name)
                self.assertIn(name, aliases)
                info = copy.copy(zip_info)
                if case == "old-alias-original" and name == "/usr/bin/python3":
                    info.st_ino += 1
                return info
            def readonly(fd):
                path = descriptors[fd]
                writable = (case == "root-writable" and path == C.PYTHON_ROOT
                            or case == "parent-writable" and path == Path("/run")
                            or case == "member-writable" and path == first_file
                            or case == "old-executable-writable" and path == Path("/usr/bin/python3.12")
                            or case == "old-stdlib-writable" and path == Path("/usr/lib/python3.12"))
                return SimpleNamespace(f_flag=0 if writable else N.os.ST_RDONLY)
            def readlink(name):
                if case == "old-alias-text" and name == "/usr/bin/python3":
                    return "another-python"
                return {"/bin": "usr/bin", "/lib": "usr/lib", "/usr/bin/python3": "python3.12"}[name]
            def mask_data(name, limit):
                self.assertEqual((name, limit), ("/usr/bin/python3.12", 23))
                if case == "old-executable-missing":
                    raise FileNotFoundError
                original = list(zip_row["identity"])
                if case == "old-executable-replaced":
                    original[1] += 1
                return original, zip_row["sha256"], None
            def close(fd):
                self.assertNotIn(fd, closed)
                self.assertNotIn(fd, N.runtime_fds)
                closed.append(fd)
                if case == "close-unknown" and fd == 82:
                    raise OSError("inert namespace runtime close unknown")
            initial = {"controllerRuntimeInputsPrechecked": 598, "controllerRuntimeInputsPostchecked": 598}
            with self.subTest(case=case), patch.multiple(N, runtime_fds=[], runtime_state=None, report=initial, errors=[],
                 binding={"sourceSha": receipt["sourceSha"], "pythonPycache": receipt["pythonPycache"]},
                 pycache_state={"identity": C.identity(cache_info)},
                 control_pins={"/controller-runtime-originals.json": (pin["identity"], pin["sha256"])}), \
                 patch.object(N.os, "open", side_effect=opening), patch.object(N.os, "fstat", side_effect=fstat), \
                 patch.object(N.os, "stat", side_effect=named_stat), patch.object(N.os, "fstatvfs", side_effect=readonly), \
                 patch.object(N.os, "close", side_effect=close), patch.object(N.os, "readlink", side_effect=readlink), \
                 patch.object(N.os, "listdir", side_effect=lambda fd: list(directory_rows[descriptors[fd]]["entries"])), \
                 patch.object(Path, "lstat", named), \
                 patch.object(Path, "is_symlink", lambda path: str(path) in ("/bin", "/lib", "/usr/bin/python3")), \
                 patch.object(N, "data", side_effect=mask_data), patch.object(N, "pycache_empty") as empty, \
                 patch.object(N, "invoke") as invoke:
                try:
                    if case in ("good", "close-unknown") or case.startswith("post-"):
                        N.runtime_namespace_begin(expected, receipt)
                        self.assertEqual(len(N.runtime_fds), 3)
                        self.assertTrue(N.report["controllerRuntimeSameRoot"] and N.report["oldPythonMasksChecked"])
                        state["post"] = True
                        if case == "post-accounting":
                            N.report["controllerRuntimeInputsPostchecked"] = 597
                    else:
                        with self.assertRaises((N.Refusal, OSError)):
                            N.runtime_namespace_begin(expected, receipt)
                finally:
                    N.runtime_namespace_finish()
                self.assertEqual(sorted(closed), sorted(opened))
                self.assertEqual(len(closed), len(set(closed)))
                self.assertEqual(N.runtime_fds, [])
                invoke.assert_not_called()
                if case == "good":
                    self.assertEqual(N.errors, [])
                    self.assertTrue(N.report["controllerRuntimePostchecked"] and N.report["oldPythonMasksPostchecked"])
                    self.assertTrue(N.report["controllerRuntimeHandlesClosed"])
                    self.assertEqual(empty.call_count, 4)
                if case.startswith("post-") or case == "close-unknown":
                    self.assertTrue(N.errors)
                if case == "close-unknown":
                    self.assertFalse(N.report["controllerRuntimeHandlesClosed"])

    def test_controller_bootstrap_copies_only_pinned_python_after_complete_original_postchecks(self):
        for case in ("good", "artifact-post", "prepared-post", "source-post", "provider-post", "helper-post"):
            fixture = self.controller_fixture()
            value, runtime = fixture["catalogue"], fixture["runtime"]
            provider, helper = runtime["bootstrap"]["python"], runtime["bootstrap"]["unpackHelper"]
            selected = SimpleNamespace(executable=provider["path"], version_info=(3, 12, 3), prefix="/usr", base_prefix="/usr")
            provider_pin = {"bytes": provider["size"], "sha256": provider["sha256"], "mode": "0o755"}
            helper_pin = {"bytes": helper["size"], "sha256": helper["sha256"], "mode": "0o600"}
            catalogue_pin = {"sha256": "a" * 64, "mode": "0o600"}
            events, copies, mkdirs, chmods, writes, read_counts = [], [], [], [], [], {}
            helper_path = C.SOURCE / helper["path"]
            source_binding, check_inputs = {"inert": "readonly-bind-originals"}, {"inert": "positive-loader-inputs"}
            def ready(_catalogue):
                events.append("check-ready")
                return check_inputs
            def retained(path, limit, **kwargs):
                path = Path(path)
                read_counts[path] = read_counts.get(path, 0) + 1
                if path == Path(provider["path"]):
                    events.append("provider-read")
                    changed = case == "provider-post" and read_counts[path] == 2
                    return b"inert-provider", {} if changed else provider_pin
                if path == helper_path:
                    events.append("helper-read")
                    changed = case == "helper-post" and read_counts[path] == 3
                    return b"inert-helper", {} if changed else helper_pin
                self.assertEqual(path, C.SOURCE / C.CONTROL / "runtime-suppliers.json")
                events.append("catalogue-post")
                return b"inert-catalogue", {} if case == "source-post" else catalogue_pin
            def imported(_module):
                events.append("helper-import")
                self.assertEqual(read_counts[helper_path], 1)
            def artifact(_data, _runtime):
                count = events.count("artifact")
                events.append("artifact")
                return {"inert": "changed" if case == "artifact-post" and count else "artifact-originals"}
            def prepared(_runtime):
                count = events.count("prepared")
                events.append("prepared")
                return {"inert": "changed" if case == "prepared-post" and count else "prepared-originals"}
            def mkdir(path, mode=0o777, parents=False, exist_ok=False):
                self.assertEqual((mode, parents, exist_ok), (0o700, False, False))
                self.assertNotIn(path, mkdirs)
                mkdirs.append(path)
            def unpack(path, expected, target):
                events.append("unpack")
                self.assertEqual((path, expected, target),
                    (C.PYTHON_SUPPLIER / "prepared-runtime.tar", runtime["archive"], C.PYTHON_STAGE / "prepared"))
            def copy_member(original, target, expected, mode):
                row = runtime["projection"]["files"][len(copies)]
                self.assertEqual((original, target, mode),
                    (C.PYTHON_STAGE / "prepared/runtime" / row["path"], C.PYTHON_ROOT / row["path"], 0o444))
                self.assertEqual(expected, {"path": row["path"], "size": row["bytes"], "sha256": row["sha256"]})
                copies.append(row["path"])
            def chmod(path, mode):
                self.assertEqual(len(copies), 598)
                self.assertIn("catalogue-post", events)
                self.assertEqual(mode, 0o555)
                chmods.append((str(path), mode))
                events.append("enable" if str(path) == C.PYTHON_EXECUTABLE else "directory-mode")
            def write(path, raw):
                self.assertEqual(path, C.PYTHON_ORIGINALS)
                self.assertEqual(len(chmods), 54)
                frame = C.decode(raw)
                self.assertTrue(frame["readonlyMountRequiredBeforePrivateStartup"])
                self.assertEqual(frame["projection"], fixture["projection"])
                self.assertEqual(frame["providerPython"], provider_pin)
                self.assertEqual(frame["sourceBinding"], source_binding)
                self.assertEqual(frame["controllerCheckInputs"], check_inputs)
                writes.append(frame)
            data = SimpleNamespace(unpack=unpack, copy=copy_member)
            spec = SimpleNamespace(loader=SimpleNamespace(exec_module=imported))
            with self.subTest(case=case), ExitStack() as stack:
                stack.enter_context(patch.object(C, "sys", selected))
                stack.enter_context(patch.object(C, "read", side_effect=retained))
                absent = stack.enter_context(patch.object(C, "root_absent"))
                stack.enter_context(patch.object(Path, "mkdir", mkdir))
                stack.enter_context(patch.object(Path, "lstat", lambda path: fixture["infos"][path]))
                stack.enter_context(patch.object(Path, "is_symlink", return_value=True))
                stack.enter_context(patch.object(C.os, "readlink", side_effect=lambda p: {"/bin": "usr/bin", "/usr/bin/python3": "python3.12"}[p]))
                stack.enter_context(patch.object(C.os, "chmod", side_effect=chmod))
                stack.enter_context(patch.object(C, "write", side_effect=write))
                stack.enter_context(patch.object(C.importlib.util, "spec_from_file_location", return_value=spec))
                stack.enter_context(patch.object(C.importlib.util, "module_from_spec", return_value=data))
                source_names = stack.enter_context(patch.object(C, "source_product", return_value=["inert-complete-roster"]))
                source_stage = stack.enter_context(patch.object(C, "controller_stage_source", return_value=source_binding))
                check_ready = stack.enter_context(patch.object(C, "controller_check_ready", side_effect=ready))
                stack.enter_context(patch.object(C, "controller_source_original"))
                source_finish = stack.enter_context(patch.object(C, "controller_source_finish"))
                stack.enter_context(patch.object(C, "controller_artifact_originals", side_effect=artifact))
                stack.enter_context(patch.object(C, "controller_prepared_runtime", side_effect=prepared))
                stack.enter_context(patch.object(C, "controller_runtime_roster", return_value=fixture["projection"]))
                stack.enter_context(patch.object(C, "pycache_original", return_value=self.pycache_fixture()))
                finish = stack.enter_context(patch.object(C, "pycache_finish"))
                command = stack.enter_context(patch.object(C, "command"))
                owner = stack.enter_context(patch.object(C, "owner_modules"))
                output = stack.enter_context(patch("builtins.print"))
                if case == "good":
                    C.stage_controller_runtime(C.workflow_context(environment()), value, catalogue_pin)
                else:
                    with self.assertRaisesRegex(C.Refused, "controller-bootstrap-original-postcheck"):
                        C.stage_controller_runtime(C.workflow_context(environment()), value, catalogue_pin)
            self.assertEqual(len(copies), 598)
            self.assertTrue(all(path.startswith("python/") for path in copies))
            self.assertEqual(len(mkdirs), 54)
            self.assertEqual(events.count("unpack"), 1)
            self.assertLess(events.index("helper-import"), events.index("unpack"))
            self.assertLess(events.index("check-ready"), events.index("helper-import"))
            source_names.assert_called_once_with(value)
            source_stage.assert_called_once_with(["inert-complete-roster"])
            self.assertEqual(check_ready.call_count, 2 if case == "good" else 1)
            self.assertEqual([call.args[0] for call in absent.call_args_list],
                             [C.PYTHON_ROOT, C.PYTHON_STAGE, "/etc/ld.so.preload", "/usr/lib/python312.zip"])
            for blocked in (command, owner):
                blocked.assert_not_called()
            if case == "good":
                self.assertEqual(len(writes), 1)
                self.assertEqual(chmods[0], (C.PYTHON_EXECUTABLE, 0o555))
                source_finish.assert_called_once_with()
                finish.assert_called_once_with()
                output.assert_called_once_with("GNOME_HOSTED_CONTROLLER_RUNTIME_STAGED=598-files;readonly-mount-still-required", flush=True)
            else:
                self.assertEqual(chmods, [])
                self.assertEqual(writes, [])
                source_finish.assert_not_called()
                finish.assert_not_called()
                output.assert_not_called()

    def test_namespace_runtime_binding_rejects_altered_projection_before_open(self):
        mutations = (
            ("missing", lambda e: e["projection"]["files"].pop()),
            ("duplicate", lambda e: e["projection"]["files"].__setitem__(-1, copy.deepcopy(e["projection"]["files"][0]))),
            ("hash", lambda e: e["projection"]["files"][0].update(sha256="0" * 64)),
            ("mode", lambda e: e["projection"]["files"][0].update(mode="0o777")),
            ("path", lambda e: e["projection"]["files"][0].update(path="/foreign/python")),
            ("builtin", lambda e: e["builtins"].pop()),
            ("search", lambda e: e["searchPath"].append("/usr/lib/python3.12")),
            ("receipt-mode", lambda e: e["originals"].update(mode="0o600")),
        )
        for name, mutate in mutations:
            fixture = self.controller_fixture()
            receipt, pin = fixture["receipt"], fixture["pin"]
            expected = {"catalogueSha256": C.CONTROLLER_RUNTIME_SHA256, "originals": pin,
                        "projection": fixture["projection"], "builtins": list(C.PYTHON_BUILTINS), "searchPath": list(C.PYTHON_SEARCH)}
            mutate(expected)
            with self.subTest(name=name), patch.multiple(N, runtime_fds=[], runtime_state=None,
                 binding={"sourceSha": receipt["sourceSha"], "pythonPycache": receipt["pythonPycache"]},
                 control_pins={"/controller-runtime-originals.json": (pin["identity"], pin["sha256"])}), \
                 patch.object(N.os, "open") as opened, patch.object(N, "invoke") as invoke:
                with self.assertRaises((N.Refusal, ValueError)):
                    N.runtime_namespace_begin(expected, receipt)
            opened.assert_not_called()
            invoke.assert_not_called()

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



    def test_characterization_read_close_unknown_is_absorbing_in_provider_stage_and_body(self):
        info = file_info(mode=stat.S_IFREG | 0o444)
        info.st_size = 1
        for stage in (True, False):
            for earlier in (False, True):
                reads = [C.Refused("inert-read-first")] if earlier else [b"x", b""]
                with self.subTest(stage=stage, earlier=earlier), patch.multiple(C,
                    _CONTROLLER_CHARACTERIZATION_ACTIVE=True,
                    _CONTROLLER_CHARACTERIZATION_STAGE={} if stage else None,
                    _CONTROLLER_CHARACTERIZATION_READ_BYTES=None if stage else 0,
                    _ORIGINALS_SETTLED=True), patch.object(C.os, "open", return_value=37), \
                    patch.object(C.os, "fstat", return_value=info), patch.object(Path, "lstat", return_value=info), \
                    patch.object(C.os, "read", side_effect=reads), \
                    patch.object(C.os, "close", side_effect=OSError("inert-close-unknown")) as close:
                    with self.assertRaisesRegex(C.Refused,
                        "inert-read-first" if earlier else "controller-characterization-input-close-unknown"):
                        C.read("/inert-original", 1)
                    self.assertFalse(C._ORIGINALS_SETTLED)
                close.assert_called_once_with(37)

        # Exercise main's initial catalogue read before the stage or cache exists.
        # A phase-owned close Unknown must not replace that read's earlier failure.
        for earlier in (False, True):
            output = []
            reads = [C.Refused("inert-read-first")] if earlier else [b"x", b""]
            fake_sys = SimpleNamespace(argv=["inert-carrier", "stage-controller-characterization"],
                flags=SimpleNamespace(isolated=True, no_site=True), dont_write_bytecode=True,
                pycache_prefix=str(C.PYTHON_PYCACHE))
            with self.subTest(entry=True, earlier=earlier), ExitStack() as stack:
                stack.enter_context(patch.object(C, "sys", fake_sys))
                stack.enter_context(patch.multiple(C, _CONTROLLER_CHARACTERIZATION_ACTIVE=False,
                    _CONTROLLER_CHARACTERIZATION_STAGE=None, _CONTROLLER_CHARACTERIZATION_READ_BYTES=None,
                    _ORIGINALS_SETTLED=True, _CONTROLLER_CHECK_STATE=None, _CONTROLLER_SOURCE=None, _EVIDENCE={}))
                stack.enter_context(patch.object(C.os, "environ", characterization_environment()))
                stack.enter_context(patch.object(C.os, "getresuid", return_value=(0, 0, 0)))
                stack.enter_context(patch.object(C.os, "getresgid", return_value=(0, 0, 0)))
                stack.enter_context(patch.object(C.os, "getgroups", return_value=[]))
                stack.enter_context(patch.object(C.os, "uname", return_value=SimpleNamespace(machine="x86_64")))
                stack.enter_context(patch.object(C.os, "open", return_value=37))
                stack.enter_context(patch.object(C.os, "fstat", return_value=info))
                stack.enter_context(patch.object(Path, "lstat", return_value=info))
                stack.enter_context(patch.object(C.os, "read", side_effect=reads))
                close = stack.enter_context(patch.object(C.os, "close", side_effect=OSError("inert-close-unknown")))
                cache = stack.enter_context(patch.object(C, "pycache_begin"))
                stage = stack.enter_context(patch.object(C, "stage_controller_characterization"))
                finish = stack.enter_context(patch.object(C, "phase_finish"))
                stack.enter_context(patch.object(C, "controller_check_output_root"))
                stack.enter_context(patch.object(C, "public_evidence", return_value={}))
                stack.enter_context(patch.object(C, "write", side_effect=lambda path, raw, mode: output.append(C.decode(raw))))
                stack.enter_context(patch("builtins.print"))
                self.assertEqual(C.main(), 1)
                self.assertTrue(C._CONTROLLER_CHARACTERIZATION_ACTIVE)
                self.assertFalse(C._ORIGINALS_SETTLED)
            close.assert_called_once_with(37)
            cache.assert_not_called()
            stage.assert_not_called()
            finish.assert_called_once_with(failed=True)
            self.assertEqual(len(output), 1)
            self.assertFalse(output[0]["passed"])
            self.assertFalse(output[0]["originalsSettled"])
            self.assertEqual(output[0]["firstFailure"], {"role": "stage-controller-characterization",
                "refusal": "inert-read-first" if earlier else "controller-characterization-input-close-unknown"})


    def test_characterization_authority_is_exact_and_cannot_enter_production(self):
        env = characterization_environment()
        context = C.controller_characterization_context(env)
        self.assertIs(context["measurementOnly"], True)
        with self.assertRaises(C.Refused):
            C.workflow_context(env)
        for key, value in (("GITHUB_REPOSITORY", "example/project"), ("GITHUB_RUN_ATTEMPT", "2"),
                           ("GITHUB_REF", C.REF), ("ImageVersion", "different"), ("GITHUB_WORKFLOW_SHA", "b" * 40),
                           ("LD_LIBRARY_PATH", "/unbound"), ("OPENSSL_CONF", "/unbound")):
            with self.subTest(key=key), self.assertRaises(C.Refused):
                C.controller_characterization_context({**env, key: value})
        with self.assertRaises(C.Refused):
            C.controller_characterization_context(characterization_environment(post=True))
        self.assertEqual(C.controller_characterization_context(characterization_environment(post=True), post=True), context)
        native_context = C.workflow_context(environment())
        for actual_schema, selected_context, call in (
                (C.CONTROLLER_CHARACTERIZATION_ORIGINALS, native_context, C.controller_staging_receipt),
                (C.CONTROLLER_ORIGINALS_SCHEMA, context, C.controller_characterization_staging_receipt)):
            raw = C.canonical({"schema": actual_schema})
            with self.subTest(schema=actual_schema), patch.object(Path, "lstat", return_value=file_info(mode=stat.S_IFDIR | 0o700)), \
                 patch.object(C, "read", return_value=(raw, {"mode": "0o400"})), self.assertRaises(C.Refused):
                call(selected_context)
        waits = {"schema": C.CONTROLLER_CHECK_SCHEMA, "originalWait": True, "exitCode": 0}
        with self.assertRaises(C.Refused):
            C.controller_characterization_original_join(context, "success", {}, waits)
        self.assertIsNone(C.CONTROLLER_CHECK_HOST_SHA256)

    def characterization_mapping_fixture(self):
        hosts = sorted(C.CONTROLLER_CHARACTERIZATION_HOSTS)
        private = [str(C.PYTHON_ROOT / name) for name in
                   ("python/bin/python3", "python/lib/libcrypto.so.3", "python/lib/libssl.so.3")]
        pins = {}
        for index, path in enumerate(hosts + private + list(C.CONTROLLER_CHARACTERIZATION_CONFIG)):
            info = file_info(mode=stat.S_IFREG | 0o555)
            info.st_ino, info.st_size = 100 + index, 64
            pins[path] = {"identity": C.identity(info), "bytes": 64, "sha256": "a" * 64, "mode": "0o555"}
        receipt = {"schema": C.CONTROLLER_CHARACTERIZATION_ORIGINALS,
            "sourceBinding": {"inert": "complete-pinned-source"}, "sourceCatalogue": {"sha256": "b" * 64},
            "controllerCheckInputs": {"mappedHostFiles": hosts, "files": {path: pins[path] for path in
                hosts + list(C.CONTROLLER_CHARACTERIZATION_CONFIG)},
                "directories": [{"path": C.CONTROLLER_CHARACTERIZATION_DIRS[-1], "entries": [], "identity": [1]}]},
            "projection": {"files": [{"path": path, **pins[path]} for path in private]}}
        selected = sorted(set(C.CONTROLLER_CHARACTERIZATION_REQUIRED) | set(private))
        rows = [["1000-2000", "r-xp", "00000000", "00:07", str(pins[path]["identity"][1]), path] for path in selected]
        rows += [["2000-3000", "rw-p", "00000000", "00:00", "0", "[heap]"],
                 ["3000-4000", "r-xp", "00000000", "00:00", "0", "[vdso]"]]
        return receipt, rows, selected

    def test_characterization_maps_require_executable_original_backing_not_the_entire_ceiling(self):
        receipt, rows, selected = self.characterization_mapping_fixture()
        self.assertEqual(C._controller_mapping_rows(receipt, rows, characterization=True), selected)
        with self.assertRaisesRegex(C.Refused, "mapped-provider-closure"):
            C._controller_mapping_rows(receipt, rows, characterization=False)
        for case in ("foreign", "device", "inode", "missing", "no-executable", "anonymous-executable",
                     "heap-executable", "writable-executable", "unknown-anonymous"):
            changed = copy.deepcopy(rows)
            if case == "foreign":
                changed[0][5] = "/usr/lib/unadmitted.so"
            elif case == "device":
                changed[0][3] = "00:08"
            elif case == "inode":
                changed[0][4] = "999"
            elif case == "missing":
                changed.pop(0)
            elif case == "no-executable":
                changed[0][1] = "r--p"
            elif case == "anonymous-executable":
                changed[-1] = changed[-1][:5]
            elif case == "heap-executable":
                changed[-2][1] = "r-xp"
            elif case == "writable-executable":
                changed[0][1] = "rwxp"
            else:
                changed[-1][5] = "[unadmitted]"
            with self.subTest(case=case), self.assertRaises(C.Refused):
                C._controller_mapping_rows(receipt, changed, characterization=True)

    def test_characterization_absence_records_first_edge_not_dangling_or_inaccessible_inputs(self):
        target = "/usr/lib/glibc-hwcaps/x86-64-v3/libc.so.6"
        for case in ("absent", "dangling", "inaccessible", "present-provider"):
            inputs = {"parents": {}, "directories": [], "absent": []}
            def info(path):
                name = str(path)
                if name == "/usr/lib/glibc-hwcaps":
                    if case == "absent":
                        raise FileNotFoundError
                    if case == "inaccessible":
                        raise PermissionError
                    if case == "dangling":
                        return file_info(mode=stat.S_IFLNK | 0o777)
                return file_info()
            with self.subTest(case=case), patch.object(Path, "lstat", info), \
                 patch.object(C, "controller_characterization_retain_directory") as directory:
                if case == "absent":
                    self.assertEqual(C.controller_characterization_absence(target, inputs),
                        {"requested": target, "firstAbsent": "/usr/lib/glibc-hwcaps", "parent": "/usr/lib"})
                    self.assertEqual(inputs["absent"], ["/usr/lib/glibc-hwcaps"])
                    directory.assert_called_once_with(Path("/usr/lib"), inputs)
                else:
                    with self.assertRaises(C.Refused):
                        C.controller_characterization_absence(target, inputs)
                    self.assertEqual(inputs["absent"], [])

    def test_characterization_partial_stage_keeps_first_failure_and_attempts_every_owned_post(self):
        context = C.controller_characterization_context(characterization_environment())
        pin = {"bytes": 1, "sha256": "a" * 64, "mode": "0o444"}
        def partial(*args, **kwargs):
            self.assertTrue(kwargs["characterization"])
            C._CONTROLLER_CHARACTERIZATION_STAGE["copies"].append({
                "path": Path("/inert-copy"), "row": {"bytes": 1, "sha256": "a" * 64}, "original": None})
            C._CONTROLLER_CHARACTERIZATION_INPUTS = {"inert": "partial-host-originals"}
            raise C.Refused("inert-copy-first")
        with patch.multiple(C, _CONTROLLER_CHECK_STATE=None, _CONTROLLER_CHARACTERIZATION_STAGE=None,
                            _CONTROLLER_CHARACTERIZATION_INPUTS=None, _ORIGINALS_SETTLED=True), \
             patch.object(C, "_stage_controller_runtime", side_effect=partial), \
             patch.object(C, "read", return_value=(b"x", pin)) as read, \
             patch.object(C, "controller_characterization_post_inputs", side_effect=C.Refused("inert-host-later")) as host, \
             patch.object(C, "controller_source_finish", side_effect=C.Refused("inert-source-later")) as source, \
             patch.object(C, "pycache_finish") as cache, patch.object(C.os, "chmod") as enable:
            with self.assertRaises(C.Refused):
                C.stage_controller_characterization(context, {"controllerRuntime": {}}, pin)
            state = copy.deepcopy(C._CONTROLLER_CHECK_STATE)
        self.assertEqual(state["firstFailure"], {"role": "stage", "refusal": "inert-copy-first"})
        self.assertEqual([row["role"] for row in state["errors"]], ["stage", "copy", "host", "source"])
        self.assertEqual(read.call_count, 2)
        host.assert_called_once()
        source.assert_called_once_with(failed=True)
        cache.assert_called_once_with(failed=True)
        enable.assert_not_called()

    def test_characterization_return_documents_bind_actual_subset_and_never_export_raw_maps(self):
        context = C.controller_characterization_context(characterization_environment())
        receipt, rows, selected = self.characterization_mapping_fixture()
        mapping = {"rows": rows, "files": selected, "sha256": "c" * 64}
        body, outputs = {"mappingsBefore": mapping, "mappingsAfter": copy.deepcopy(mapping)}, {}
        def write(path, raw, mode):
            self.assertLess(len(raw), C.CONTROLLER_CHECK_LIMIT)
            self.assertEqual(mode, 0o444)
            self.assertNotIn("1000-2000", raw.decode())
            self.assertNotIn('"rows"', raw.decode())
            outputs[path.name] = C.decode(raw)
            return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": "0o444"}
        with patch.object(C.os, "environ", characterization_environment()), patch.object(C, "write", side_effect=write):
            result = C.controller_characterization_documents(context, receipt, body)
        self.assertEqual(set(outputs), {"loader-search.json", "provider-config.json", "actual-mappings.json"})
        self.assertEqual(outputs["actual-mappings.json"]["mappedHostFiles"], sorted(C.CONTROLLER_CHARACTERIZATION_REQUIRED))
        self.assertTrue(all(row["executableCoverageBefore"] and row["executableCoverageAfter"]
                            for row in outputs["actual-mappings.json"]["selected"]))
        self.assertFalse(result["automaticAdoption"])
        self.assertTrue(result["independentReturnOriginalAndJobCompletionRequired"])
        for value in outputs.values():
            self.assertEqual(value["sourceSha"], context["sourceSha"])
            self.assertEqual(value["controllerRuntimeSha256"], C.CONTROLLER_RUNTIME_SHA256)
            self.assertFalse(value["productionQualified"])
        changed = copy.deepcopy(body)
        changed["mappingsAfter"]["rows"][0][4] = "999"
        with patch.object(C, "write") as writer, self.assertRaises(C.Refused):
            C.controller_characterization_documents(context, receipt, changed)
        writer.assert_not_called()

    def test_characterization_provider_post_keeps_timeout_failure_and_never_publishes_candidate_success(self):
        fixture = self.controller_fixture()
        catalogue, runtime = fixture["catalogue"], fixture["runtime"]
        env = characterization_environment(post=True)
        env["MRK_CONTROLLER_CHECK_OUTCOME"] = "failure"
        context, provider = C.controller_characterization_context(env, post=True), runtime["bootstrap"]["python"]
        pin = {"bytes": provider["size"], "sha256": provider["sha256"], "mode": "0o755"}
        receipt = {"sourceBinding": {"inert": "source"}, "pythonPycache": {"inert": "cache"}, "providerPython": pin}
        body = {"schema": C.CONTROLLER_CHARACTERIZATION_SCHEMA, **context, "passed": False,
                "firstFailure": {"role": "body", "refusal": "inert-abi-first"}}
        def read(path, limit, **kwargs):
            if str(path) == provider["path"]:
                return b"inert-provider", pin
            raw = (C.canonical(body) if path.name == "stdout" else b"" if path.name == "stderr"
                   else C.canonical({"schema": C.CONTROLLER_CHARACTERIZATION_SCHEMA, "exitCode": 124}))
            return raw, {"bytes": len(raw), "mode": "0o600"}
        def finish(*, failed):
            self.assertTrue(failed)
            for key in ("controllerRuntime", "pythonPycache"):
                C._EVIDENCE[key] = {"phaseCustodyPostchecked": True, "phaseHandlesClosed": True}
        output = []
        with patch.object(C, "sys", SimpleNamespace(executable=provider["path"], version_info=(3, 12, 3),
                prefix="/usr", base_prefix="/usr")), patch.object(C.os, "environ", env), \
             patch.multiple(C, _CONTROLLER_CHECK_STATE=None, _ORIGINALS_SETTLED=True,
                _CONTROLLER_SOURCE={"closed": True, "postchecked": True, "handlesClosed": True},
                _EVIDENCE=copy.deepcopy(C._EVIDENCE)), \
             patch.object(C, "read", side_effect=read), patch.object(C, "controller_check_output_root"), \
             patch.object(C, "controller_characterization_staging_receipt", return_value=receipt), \
             patch.object(C, "controller_source_begin", side_effect=C.Refused("inert-source-later")) as source, \
             patch.object(C, "controller_characterization_runtime_begin") as runtime_begin, \
             patch.object(C, "pycache_begin") as cache, patch.object(C, "controller_characterization_post_host") as host, \
             patch.object(C, "phase_finish", side_effect=finish), \
             patch.object(C, "controller_characterization_documents") as documents, \
             patch.object(C, "write", side_effect=lambda path, raw, mode: output.append(C.decode(raw))), patch("builtins.print"):
            self.assertEqual(C.post_controller_characterization(context, catalogue), 1)
        for operation in (source, runtime_begin, cache, host):
            operation.assert_called_once()
        documents.assert_not_called()
        self.assertEqual(len(output), 1)
        self.assertEqual(output[0]["schema"], C.CONTROLLER_CHARACTERIZATION_SCHEMA)
        self.assertEqual(output[0]["firstFailure"], {"role": "body", "refusal": "inert-abi-first"})
        self.assertFalse(output[0]["passed"])
        self.assertIsNone(output[0]["candidate"])
        self.assertIsNone(output[0]["originalWaitAndWriters"])

    def test_characterization_job_has_one_fixed_body_and_no_native_follow_on(self):
        workflow = (ROOT / C.WORKFLOW).read_text()
        native, measurement = workflow.split("\n  gnome-controller-characterization:\n", 1)
        self.assertIn("if: github.ref == 'refs/heads/verify/desktop-gnome-session-native'", native)
        self.assertIn("if: github.ref == 'refs/heads/verify/desktop-gnome-controller-characterization'", measurement)
        self.assertIn('[[ "$GITHUB_REPOSITORY" == Apdelrahman1911/mobile-release-kit ]]', measurement)
        self.assertIn('[[ "$GITHUB_RUN_ATTEMPT" == 1 ]]', measurement)
        self.assertEqual(measurement.count(C.PYTHON_EXECUTABLE + " -I -S -B "), 1)
        self.assertEqual(measurement.count("/usr/bin/python3.12 -I -S -B "), 2)
        for phase in C.CONTROLLER_CHARACTERIZATION_PHASES:
            self.assertIn('" ' + phase, measurement)
        self.assertIn('"schema":"gnome-controller-host-characterization-1"', measurement)
        self.assertIn("if: always() && steps.controller-runtime.outcome != 'skipped'", measurement)
        self.assertIn("--signal=TERM --kill-after=2s 30s", measurement)
        self.assertIn("--signal=TERM --kill-after=2s 13s", measurement)
        for forbidden in (" supply-bwrap", "for phase in prepare acquire", "id: native", " settle ",
                          "core.zip", "unmount", "umount", "rm -", "CONTROLLER_CHECK_HOST_SHA256"):
            self.assertNotIn(forbidden, measurement)
        upload = measurement.split("      - name: Retain only closed controller characterization DATA\n", 1)[1]
        for name in ("loader-search.json", "provider-config.json", "actual-mappings.json", "receipt.json", "waits.json"):
            self.assertIn(str(C.CONTROLLER_CHECK_ROOT / name), upload)
        for private in ("/stdout", "/stderr", "/source", "originals.json", "/run/"):
            self.assertNotIn(private, upload)


    def test_controller_check_entries_are_fixed_and_before_only_the_full_native_gate(self):
        value = {"unresolved": ["inert-retained"]}
        for phase, function in (("check-controller-runtime", "check_controller_runtime"),
                                ("post-controller-check", "post_controller_check")):
            selected = self.selected_python()
            selected.argv = ["inert-controller", phase]
            with self.subTest(phase=phase), ExitStack() as stack:
                stack.enter_context(patch.object(C, "sys", selected))
                stack.enter_context(patch.object(C.os, "getresuid", return_value=(0, 0, 0)))
                stack.enter_context(patch.object(C.os, "getresgid", return_value=(0, 0, 0)))
                stack.enter_context(patch.object(C.os, "getgroups", return_value=[]))
                stack.enter_context(patch.object(C.os, "uname", return_value=SimpleNamespace(machine="x86_64")))
                stack.enter_context(patch.object(C.os, "environ", environment()))
                stack.enter_context(patch.object(C, "read", return_value=(C.canonical(value), {})))
                selected_phase = stack.enter_context(patch.object(C, function, return_value=0))
                blocked = [stack.enter_context(patch.object(C, name)) for name in (
                    "catalogue_ready", "native_layout", "source_product", "owner_modules", "command",
                    "pycache_for_phase", "supply_bwrap", "prepare", "acquire", "run_native", "settle")]
                self.assertEqual(C.main(), 0)
                selected_phase.assert_called_once_with(C.workflow_context(environment()), value)
                for operation in blocked:
                    operation.assert_not_called()
        selected.argv = ["inert-controller", "check-controller-runtime", "run"]
        with patch.object(C, "sys", selected), patch.object(C, "read") as read, patch("builtins.print"), \
             patch.object(C, "check_controller_runtime") as check:
            self.assertEqual(C.main(), 1)
        read.assert_not_called()
        check.assert_not_called()

    def test_controller_check_missing_positive_loader_evidence_cannot_clear_any_gate(self):
        value = json.loads((ROOT / C.CONTROL / "runtime-suppliers.json").read_text())
        original = copy.deepcopy(value)
        self.assertEqual(len(value["unresolved"]), 6)
        self.assertIsNone(C.CONTROLLER_CHECK_HOST_SHA256)
        for unresolved, extra in ((value["unresolved"], None), ([], {}),
                                  ([], {"schema": "gnome-controller-check-loader-inputs-1"})):
            changed = copy.deepcopy(value)
            changed["unresolved"] = unresolved
            if extra is not None:
                changed["controllerCheckInputs"] = extra
            with self.subTest(unresolved=unresolved, extra=extra), patch.object(C, "read") as read, \
                 patch.object(C, "command") as command, patch.object(C, "owner_modules") as owner:
                with self.assertRaisesRegex(C.Refused, "controller-check-loader-evidence-unresolved"):
                    C.controller_check_ready(changed)
            for operation in (read, command, owner):
                operation.assert_not_called()
        self.assertEqual(value, original)

    def test_controller_source_bind_keeps_native_originals_instead_of_copy_identities(self):
        source = Path("/inert-original-checkout")
        info = file_info()
        originals = {"files": {"inert.py": {"identity": C.identity(info), "sha256": "a" * 64}},
                     "directories": [{"relative": ".", "identity": C.identity(info)}]}
        binding = {"originalRoot": str(source), "viewRoot": str(C.CONTROLLER_CHECK_SOURCE),
                   "originals": originals, "originalReadonly": False, "mounts": {"inert": "mount-originals"},
                   "outputCustody": {"inert": "output"}, "nativeOuter": ["inert-empty"]}
        for case in ("good", "copy", "writable", "mount-replaced", "source-replaced"):
            view = copy.deepcopy(info)
            if case == "copy":
                view.st_ino += 1
            state = {"binding": binding, "fds": [40, 41], "closed": False}
            changed = copy.deepcopy(originals)
            if case == "source-replaced":
                changed["files"]["inert.py"]["identity"][1] += 1
            def snapshot(root, names, *, readonly):
                self.assertEqual(names, ["inert.py"])
                self.assertEqual(readonly, root == C.CONTROLLER_CHECK_SOURCE)
                return changed if root == C.CONTROLLER_CHECK_SOURCE else originals
            with self.subTest(case=case), patch.object(C, "_CONTROLLER_SOURCE", state), \
                 patch.object(C.os, "fstat", side_effect=lambda fd: info if fd == 40 else view), \
                 patch.object(Path, "lstat", side_effect=lambda: info), \
                 patch.object(C.os, "fstatvfs", side_effect=lambda fd: SimpleNamespace(
                     f_flag=C.os.ST_RDONLY if fd == 41 and case != "writable" else 0)), \
                 patch.object(C, "controller_source_snapshot", side_effect=snapshot) as snapshots, \
                 patch.object(C, "controller_source_mounts", return_value={} if case == "mount-replaced" else binding["mounts"]), \
                 patch.object(C, "controller_check_output_root", return_value=binding["outputCustody"]), \
                 patch.object(C, "controller_native_pristine", return_value=binding["nativeOuter"]):
                if case == "good":
                    self.assertIs(C.controller_source_original(), originals)
                    self.assertEqual(snapshots.call_count, 2)
                else:
                    with self.assertRaises(C.Refused):
                        C.controller_source_original()
            self.assertEqual(binding["originals"]["files"]["inert.py"]["identity"], C.identity(info))

    def test_controller_source_roster_checks_readonly_on_each_file_and_directory_fd(self):
        root, info = Path("/inert-readonly-bind"), file_info()
        leaf = file_info(mode=stat.S_IFREG | 0o600)
        leaf.st_ino += 1
        pin = {"identity": C.identity(leaf), "bytes": 1, "sha256": "a" * 64, "mode": "0o600"}
        directory = {"relative": ".", "identity": C.identity(info), "entries": ["one.py"], "mode": "0o755"}
        for case in ("good", "file-writable", "directory-writable"):
            opened, closed = [], []
            def opening(path, flags):
                opened.append(Path(path))
                return 50 + len(opened)
            def selected(fd):
                return leaf if fd == 51 else info
            def flags(fd):
                return SimpleNamespace(f_flag=0 if (case, fd) in (("file-writable", 51), ("directory-writable", 52))
                                       else C.os.ST_RDONLY)
            with self.subTest(case=case), patch.object(C, "read", return_value=(b"x", pin)), \
                 patch.object(C, "source_directories", return_value=[directory]), \
                 patch.object(C.os, "open", side_effect=opening), patch.object(C.os, "fstat", side_effect=selected), \
                 patch.object(C.os, "fstatvfs", side_effect=flags), patch.object(C.os, "close", side_effect=closed.append), \
                 patch.object(Path, "lstat", lambda path: leaf if path == root / "one.py" else info):
                if case == "good":
                    self.assertEqual(C.controller_source_snapshot(root, ["one.py"], readonly=True),
                                     {"files": {"one.py": pin}, "directories": [directory]})
                else:
                    with self.assertRaisesRegex(C.Refused, "controller-source-member-replaced-or-writable"):
                        C.controller_source_snapshot(root, ["one.py"], readonly=True)
            self.assertEqual(closed, list(range(51, 51 + len(opened))))
            if case == "good":
                self.assertEqual(opened, [root / "one.py", root])

    def test_controller_check_uses_staging_cache_and_preserves_body_failure_across_posts(self):
        import io
        context, cache = C.workflow_context(environment()), {"inert": "retained-cache"}
        receipt = {"pythonPycache": cache, "sourceBinding": {"inert": "source-originals"}}
        for case in ("good", "body-first", "host-post", "finish"):
            output = io.StringIO()
            selected = self.selected_python()
            selected.stdout = output
            source_state = {"closed": True, "postchecked": True, "handlesClosed": True}
            primary = C.Refused("inert-abi-first")
            def finish(*, failed):
                for key in ("controllerRuntime", "pythonPycache"):
                    C._EVIDENCE[key] = {"phaseCustodyPostchecked": True, "phaseHandlesClosed": True}
                if case in ("body-first", "finish"):
                    raise C.Refused("inert-finish-later")
            with self.subTest(case=case), ExitStack() as stack:
                stack.enter_context(patch.object(C, "sys", selected))
                stack.enter_context(patch.object(C, "SOURCE", C.CONTROLLER_CHECK_SOURCE))
                stack.enter_context(patch.object(C, "_CONTROLLER_SOURCE", source_state))
                stack.enter_context(patch.object(C, "controller_check_stdio"))
                stack.enter_context(patch.object(C, "controller_staging_receipt", return_value=receipt))
                stack.enter_context(patch.object(C, "controller_runtime_begin"))
                stack.enter_context(patch.object(C, "controller_source_begin"))
                stack.enter_context(patch.object(C, "authenticate_python_runtime"))
                cache_begin = stack.enter_context(patch.object(C, "pycache_begin"))
                forbidden_cache = stack.enter_context(patch.object(C, "pycache_for_phase"))
                body = stack.enter_context(patch.object(C, "controller_check_body",
                    side_effect=primary if case == "body-first" else None, return_value=True))
                host = stack.enter_context(patch.object(C, "controller_post_host",
                    side_effect=[None, C.Refused("inert-host-later")] if case in ("body-first", "host-post") else None))
                stack.enter_context(patch.object(C, "controller_module_origins", return_value=[]))
                stack.enter_context(patch.object(C, "controller_check_mappings", return_value={"inert": "maps"}))
                stack.enter_context(patch.object(C, "phase_finish", side_effect=finish))
                self.assertEqual(C.check_controller_runtime(context, {}), 0 if case == "good" else 1)
                frame = C.decode(output.getvalue())
                self.assertEqual(frame["passed"], case == "good")
                if case == "body-first":
                    self.assertEqual(frame["firstFailure"], {"role": "body", "refusal": "inert-abi-first"})
                    self.assertEqual([row["role"] for row in frame["errors"]], ["body", "host", "finish"])
                self.assertTrue(frame["post"]["source"] and frame["post"]["runtime"] and frame["post"]["cache"])
                cache_begin.assert_called_once_with(cache)
                forbidden_cache.assert_not_called()
                body.assert_called_once()
                self.assertEqual(host.call_count, 2)

    def test_controller_check_exact_unittest_selector_refuses_counts_skips_and_expected_successes(self):
        module = object()
        for case in ("good", "count", "testsRun", "failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses"):
            result = SimpleNamespace(testsRun=1, failures=[], errors=[], skipped=[], expectedFailures=[],
                                     unexpectedSuccesses=[], wasSuccessful=Mock(return_value=True))
            if case == "testsRun":
                result.testsRun = 0
            elif case not in ("good", "count"):
                setattr(result, case, [("inert", "not-clean")])
            suite = SimpleNamespace(countTestCases=Mock(return_value=2 if case == "count" else 1))
            loader, runner = Mock(), Mock()
            loader.loadTestsFromName.return_value = suite
            runner.run.return_value = result
            with self.subTest(case=case), patch.object(unittest, "TestLoader", return_value=loader), \
                 patch.object(unittest, "TextTestRunner", return_value=runner) as runner_type:
                if case == "good":
                    self.assertEqual(C.controller_run_contract(module)["testsRun"], 1)
                else:
                    with self.assertRaises(C.Refused):
                        C.controller_run_contract(module)
            loader.loadTestsFromName.assert_called_once_with(C.CONTROLLER_CHECK_TEST, module)
            if case == "count":
                runner.run.assert_not_called()
            else:
                runner.run.assert_called_once_with(suite)
                self.assertIs(runner_type.call_args.kwargs["failfast"], True)

    def test_controller_source_finalizer_keeps_first_failure_and_never_retries_unknown_close(self):
        primary = C.Refused("inert-source-first")
        for failed in (False, True):
            state = {"fds": [41, 42], "closed": False, "closeFailed": False,
                     "postchecked": False, "handlesClosed": False}
            closes = []
            def closing(fd):
                closes.append(fd)
                if fd == 42:
                    raise OSError("inert-close-unknown")
            with self.subTest(failed=failed), patch.object(C, "_CONTROLLER_SOURCE", state), \
                 patch.object(C, "_ORIGINALS_SETTLED", True), \
                 patch.object(C, "controller_source_original", side_effect=primary), \
                 patch.object(C.os, "close", side_effect=closing):
                if failed:
                    C.controller_source_finish(failed=True)
                else:
                    with self.assertRaises(C.Refused) as error:
                        C.controller_source_finish()
                    self.assertIs(error.exception, primary)
                C.controller_source_finish(failed=True)
                self.assertEqual(closes, [42, 41])
                self.assertEqual(state["fds"], [])
                self.assertTrue(state["closed"] and state["closeFailed"])
                self.assertFalse(state["postchecked"] or state["handlesClosed"] or C._ORIGINALS_SETTLED)

    def test_controller_check_audit_denial_is_absorbing_without_installing_any_hook(self):
        path = str(C.CONTROLLER_CHECK_SOURCE / "one.py")
        receipt = {"sourceBinding": {"originalRoot": "/inert-source", "viewRoot": str(C.CONTROLLER_CHECK_SOURCE),
            "originals": {"files": {"one.py": {}}, "directories": []}, "nativeOuter": []},
            "projection": {"files": [], "directories": []}, "controllerCheckInputs": {"files": {}, "directories": []},
            "pythonPycache": {"identity": []}}
        with patch.object(C.sys, "addaudithook") as install:
            audit = C.ControllerCheckAudit(receipt)
            for event, args in (("socket.__new__", (None,)), ("subprocess.Popen", (None,)),
                                ("ctypes.dlopen", ("/inert-unbound.so",)), ("os.mkdir", ("/inert-write", 0o700, -1))):
                with self.subTest(event=event), self.assertRaisesRegex(C.Refused, "controller-check-effect-denied"):
                    audit(event, args)
                self.assertEqual(audit.first, "controller-check-effect-denied")
                audit("open", (path, None, C.os.O_RDONLY))
                self.assertEqual(audit.first, "controller-check-effect-denied")
            with self.assertRaises(C.Refused):
                audit("open", (path, None, C.os.O_WRONLY))
        install.assert_not_called()

    def test_controller_host_post_scans_only_retained_host_directory_originals_under_audit(self):
        # Inert positive loader evidence exercises the real gate and POST, not a
        # host admission. Only runtime-catalogue validation and IO are mocked.
        directories = sorted(("/usr/lib", "/usr/lib64", "/usr/lib/x86_64-linux-gnu",
                              "/usr/lib/x86_64-linux-gnu/ossl-modules"))
        aliases = dict(C.CARGO_ROOT_ALIASES)
        selected = {"schema": "gnome-controller-check-loader-inputs-1", "imageVersion": C.SUPPORTED_IMAGE_VERSION,
            "runtimeSha256": C.CONTROLLER_RUNTIME_SHA256,
            "mappedHostFiles": sorted(("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                                       "/usr/lib/x86_64-linux-gnu/libc.so.6")),
            "configurationFiles": ["/etc/ld.so.cache", "/etc/ssl/openssl.cnf"],
            "directories": directories, "aliases": sorted(aliases), "absent": ["/etc/ld.so.preload"],
            "selectionEvidence": {"loaderSearchSha256": "a" * 64, "providerConfigSha256": "b" * 64,
                                  "actualMappingsSha256": "c" * 64}}
        file_pins, raw = {}, b"inert-host-input"
        for index, path in enumerate(sorted(selected["mappedHostFiles"] + selected["configurationFiles"])):
            info = file_info(mode=stat.S_IFREG | 0o644)
            info.st_ino, info.st_size = 100 + index, len(raw)
            file_pins[path] = {"identity": C.identity(info), "bytes": len(raw),
                              "sha256": hashlib.sha256(raw).hexdigest(), "mode": "0o644"}
        entries = {path: ["retained-input"] for path in directories}
        paths = set(file_pins) | set(directories) | set(aliases) | set(selected["absent"])
        infos = {str(parent): file_info() for path in paths for parent in Path(path).parents}
        infos.update({path: file_info() for path in directories})
        infos.update({path: file_info(mode=stat.S_IFLNK | 0o777) for path in aliases})
        for index, path in enumerate(sorted(infos)):
            infos[path].st_ino += index
        catalogue = {"schema": "gnome-session-hosted-suppliers-2", "bootstrapTrust": C.BOOTSTRAP_TRUST,
            "productTree": C.PRODUCT_TREE, "product": [None] * 964, "controllerCheckInputs": selected,
            "hostFiles": [{"path": path, **pin} for path, pin in sorted(file_pins.items())],
            "hostDirectories": [{"path": path, "mode": "0o755", "entries": entries[path][:]}
                                for path in directories],
            "hostAliases": [{"path": path, "target": target} for path, target in sorted(aliases.items())]}
        scans, audit = [], None
        def lstat(path):
            path = str(path)
            if path in selected["absent"]:
                raise FileNotFoundError(path)
            self.assertIn(path, infos)
            return infos[path]
        def read(path, limit):
            self.assertEqual(limit, 16 * C.MIB)
            return raw, file_pins[str(path)]
        def scandir(path):
            path = C.os.fspath(path)
            if audit is not None:
                audit("os.scandir", (path,))
            scans.append(path)
            return nullcontext(iter(SimpleNamespace(name=name) for name in entries[path]))
        with patch.object(C, "CONTROLLER_CHECK_HOST_SHA256", hashlib.sha256(C.canonical(selected)).hexdigest()), \
             patch.object(C, "python_runtime_catalogue"), patch.object(C, "read", side_effect=read), \
             patch.object(C.Path, "lstat", lstat), patch.object(C.os, "readlink", side_effect=aliases.__getitem__), \
             patch.object(C.os, "scandir", side_effect=scandir), patch.object(C.sys, "addaudithook") as install:
            retained = C.controller_check_ready(catalogue)
            receipt = {"sourceBinding": {"originalRoot": "/inert-source", "viewRoot": str(C.CONTROLLER_CHECK_SOURCE),
                "originals": {"files": {}, "directories": []}, "nativeOuter": []},
                "projection": {"files": [], "directories": []}, "controllerCheckInputs": retained,
                "pythonPycache": {"identity": []}}
            audit = C.ControllerCheckAudit(receipt)
            scans.clear()
            self.assertIsNone(C.controller_post_host(catalogue, receipt))
            self.assertEqual(scans, directories)
            self.assertIsNone(audit.first)
            for path in directories:
                audit("open", (path, None, C.os.O_RDONLY))
                with patch.object(C.os, "fstat", return_value=infos[path]):
                    audit("os.scandir", (57,))
            for path in ("/usr", "/usr/lib/unretained", "/usr/lib/x86_64-linux-gnu/unretained"):
                with self.subTest(path=path), self.assertRaisesRegex(C.Refused, "controller-check-effect-denied"):
                    audit("os.scandir", (path,))
            original = infos[directories[0]]
            for attribute in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
                              "st_size", "st_mtime_ns", "st_ctime_ns"):
                substituted = copy.copy(original)
                setattr(substituted, attribute, getattr(substituted, attribute) + 1000)
                with self.subTest(attribute=attribute), patch.object(C.os, "fstat", return_value=substituted), \
                     self.assertRaisesRegex(C.Refused, "controller-check-effect-denied"):
                    audit("os.scandir", (57,))
            # A textual path permit does not replace the original full-identity
            # POST; a current snapshot with a substituted inode still refuses.
            original.st_ino += 1000
            with self.assertRaisesRegex(C.Refused, "controller-check-host-originals-changed"):
                C.controller_post_host(catalogue, receipt)
            original.st_ino -= 1000
            entries[directories[0]].append("substituted-input")
            with self.assertRaisesRegex(C.Refused, "controller-check-host-directory-differs"):
                C.controller_post_host(catalogue, receipt)
            # Even if a fresh table describes the changed roster, the retained
            # PRE remains the authority for the actual POST equality.
            catalogue["hostDirectories"][0]["entries"] = entries[directories[0]][:]
            with self.assertRaisesRegex(C.Refused, "controller-check-host-originals-changed"):
                C.controller_post_host(catalogue, receipt)
            entries[directories[0]].pop()
            catalogue["hostDirectories"][0]["entries"] = entries[directories[0]][:]
            self.assertIsNone(C.controller_post_host(catalogue, receipt))
            self.assertEqual(audit.first, "controller-check-effect-denied")
        install.assert_not_called()

    def test_controller_original_join_needs_clean_body_original_wait_writers_and_step(self):
        context = C.workflow_context(environment())
        body = {"schema": C.CONTROLLER_CHECK_SCHEMA, **context, "phase": "check-controller-runtime",
            "passed": True, "bodyPassed": True, "firstFailure": None, "errors": [], "originalsSettled": True,
            "auditDenied": False, "controllerCatalogueSha256": C.CONTROLLER_RUNTIME_SHA256,
            "post": {"source": True, "runtime": True, "cache": True, "host": True, "moduleOrigins": True, "mappings": True},
            "contract": {"id": C.CONTROLLER_CHECK_TEST, "testsRun": 1, "failures": 0, "errors": 0, "skips": 0,
                         "expectedFailures": 0, "unexpectedSuccesses": 0, "failfast": True},
            "compiledOnly": ["prepare.py", "check-compile.py"], "tarModes": ["r:", "r|"],
            "nativeAdmission": {"onlyLibcCall": "gnu_get_libc_version", "publicSymbols": sorted(C.CONTROLLER_CHECK_SYMBOLS),
                "abi": {"schema": "mrk-native-process-abi-v1", "family": "linux-glibc", "architecture": "x86_64"}},
            "originsBefore": [{"inert": "origin"}], "originsAfter": [{"inert": "origin"}],
            "mappingsBefore": {"sha256": "a" * 64, "rows": [["inert"]], "files": ["/inert-libc"]},
            "mappingsAfter": {"sha256": "b" * 64, "rows": [["inert"]], "files": ["/inert-libc"]}}
        waits = {"schema": C.CONTROLLER_CHECK_SCHEMA, **{key: context[key] for key in ("sourceSha", "runId", "attempt")},
                 "originalWait": True, "exitCode": 0, "outputWritersClosed": True,
                 "statusWriterCloseGate": "original-step-success-required"}
        accepted = C.controller_original_join(context, "success", body, waits)
        self.assertTrue(all(accepted[key] for key in ("originalWait", "stdoutEOF", "stderrEOF", "statusWriterClosed")))
        mutations = (
            ("exit", lambda b, w: w.update(exitCode=124)),
            ("wait", lambda b, w: w.update(originalWait=False)),
            ("writers", lambda b, w: w.update(outputWritersClosed=False)),
            ("status-close", lambda b, w: w.pop("statusWriterCloseGate")),
            ("body", lambda b, w: b.update(bodyPassed=False)),
            ("post", lambda b, w: b["post"].update(cache=False)),
            ("failure", lambda b, w: b.update(firstFailure={"role": "body", "refusal": "first"})),
            ("skip", lambda b, w: b["contract"].update(skips=1)),
            ("wrong-test", lambda b, w: b["contract"].update(id="CarrierContracts.anything_else")),
            ("native-missing", lambda b, w: b.pop("nativeAdmission")),
            ("origins-missing", lambda b, w: b.update(originsAfter=[])),
            ("mappings-changed", lambda b, w: b["mappingsAfter"].update(files=["/inert-other"])),
        )
        for name, mutate in mutations:
            b, w = copy.deepcopy(body), copy.deepcopy(waits)
            mutate(b, w)
            with self.subTest(name=name), self.assertRaises(C.Refused):
                C.controller_original_join(context, "success", b, w)
        for outcome in ("failure", "cancelled", "skipped", None):
            with self.subTest(outcome=outcome), self.assertRaises(C.Refused):
                C.controller_original_join(context, outcome, body, waits)

    def test_controller_provider_post_preserves_abi_first_and_attempts_every_original_after_timeout(self):
        fixture = self.controller_fixture()
        catalogue, runtime = fixture["catalogue"], fixture["runtime"]
        context, provider = C.workflow_context(environment()), runtime["bootstrap"]["python"]
        provider_pin = {"bytes": provider["size"], "sha256": provider["sha256"], "mode": "0o755"}
        receipt = {"sourceBinding": {"inert": "source"}, "pythonPycache": {"inert": "cache"}, "providerPython": provider_pin}
        body = {"schema": C.CONTROLLER_CHECK_SCHEMA, **context, "passed": False,
                "firstFailure": {"role": "body", "refusal": "inert-abi-first"}}
        waits = {"schema": C.CONTROLLER_CHECK_SCHEMA, "exitCode": 124}
        written = []
        def read(path, limit, **kwargs):
            if str(path) == provider["path"]:
                return b"inert-provider", provider_pin
            if path == C.CONTROLLER_CHECK_ROOT / "stdout":
                raw = C.canonical(body)
            elif path == C.CONTROLLER_CHECK_ROOT / "stderr":
                raw = b""
            else:
                self.assertEqual(path, C.CONTROLLER_CHECK_ROOT / "waits.json")
                raw = C.canonical(waits)
            return raw, {"bytes": len(raw), "mode": "0o600"}
        def finish(*, failed):
            self.assertTrue(failed)
            for key in ("controllerRuntime", "pythonPycache"):
                C._EVIDENCE[key] = {"phaseCustodyPostchecked": True, "phaseHandlesClosed": True}
        selected = SimpleNamespace(executable=provider["path"], version_info=(3, 12, 3), prefix="/usr", base_prefix="/usr")
        selected_environment = {**environment(), "MRK_CONTROLLER_STAGE_OUTCOME": "success",
                                "MRK_CONTROLLER_CHECK_OUTCOME": "failure"}
        with patch.object(C, "sys", selected), patch.object(C.os, "environ", selected_environment), \
             patch.object(C, "read", side_effect=read), patch.object(C, "controller_check_output_root"), \
             patch.object(C, "controller_staging_receipt", return_value=receipt), \
             patch.object(C, "controller_source_begin", side_effect=C.Refused("inert-source-later")) as source, \
             patch.object(C, "controller_runtime_begin") as runtime_begin, patch.object(C, "pycache_begin") as cache, \
             patch.object(C, "controller_post_host") as host, patch.object(C, "phase_finish", side_effect=finish), \
             patch.object(C, "write", side_effect=lambda path, raw, mode: written.append((path, C.decode(raw), mode))), \
             patch.object(C, "controller_check_body") as check, patch.object(C, "authenticate_python_runtime") as startup, \
             patch.object(C, "pycache_for_phase") as later_cache, patch("builtins.print"):
            self.assertEqual(C.post_controller_check(context, catalogue), 1)
        source.assert_called_once_with(receipt["sourceBinding"])
        runtime_begin.assert_called_once_with(context, catalogue)
        cache.assert_called_once_with(receipt["pythonPycache"])
        host.assert_called_once_with(catalogue, receipt)
        for operation in (check, startup, later_cache):
            operation.assert_not_called()
        self.assertEqual(len(written), 1)
        self.assertEqual((written[0][0], written[0][2]), (C.CONTROLLER_CHECK_ROOT / "receipt.json", 0o444))
        frame = written[0][1]
        self.assertEqual(frame["firstFailure"], {"role": "body", "refusal": "inert-abi-first"})
        self.assertFalse(frame["passed"])
        self.assertIsNone(frame["originalWaitAndWriters"])
        self.assertFalse(frame["privateSourceAndMappingsUploaded"])
        self.assertTrue(frame["providerDataPost"]["runtime"] and frame["providerDataPost"]["cache"])
        for private in ("mappingsBefore", "mappingsAfter", "sourceBinding", "originsAfter", "nativeAdmission"):
            self.assertNotIn(private, frame)

    def test_controller_check_workflow_orders_readonly_bind_check_post_and_native_gates(self):
        source = (ROOT / "desktop/tools/gnome_session_hosted.py").read_text()
        workflow = (ROOT / C.WORKFLOW).read_text().split("\n  gnome-controller-characterization:\n", 1)[0]
        body = source.split("def controller_check_body(", 1)[1].split("\ndef controller_failure(", 1)[0]
        self.assertEqual(body.count("_native_process._Native()"), 1)
        self.assertIn('compile(raw, str(path), "exec", dont_inherit=True, optimize=0)', body)
        self.assertNotIn("Acquisition(", body)
        self.assertNotIn("find_library(", body)
        self.assertNotIn(".call(", body)
        for label in ('CONTROL + "prepare.py"', 'CONTROL + "check-compile.py"'):
            self.assertIn(label, body)
        stage = source.split("def stage_controller_runtime(", 1)[1].split("\ndef controller_runtime_original(", 1)[0]
        self.assertLess(stage.index("controller_check_ready(catalogue)"), stage.index("spec.loader.exec_module(data)"))
        self.assertLess(stage.index("controller_check_ready(catalogue)"), stage.index("os.chmod(PYTHON_EXECUTABLE"))
        self.assertIn('"sourceBinding": source_binding, "controllerCheckInputs": check_inputs', stage)
        check = source.split("def check_controller_runtime(", 1)[1].split("\ndef controller_original_join(", 1)[0]
        self.assertIn('pycache_begin(receipt["pythonPycache"])', check)
        self.assertNotIn("pycache_for_phase(", check)
        bind = '/usr/bin/mount --bind "$GITHUB_WORKSPACE" /var/tmp/mrk-gnome-controller-check-v1/source'
        remount = "/usr/bin/mount -o remount,bind,ro /var/tmp/mrk-gnome-controller-check-v1/source"
        launch = '"/var/tmp/mrk-gnome-controller-check-v1/source/desktop/tools/gnome_session_hosted.py" check-controller-runtime'
        post = '"$GITHUB_WORKSPACE/desktop/tools/gnome_session_hosted.py" post-controller-check'
        self.assertEqual(workflow.count(launch), 1)
        self.assertLess(workflow.index(bind), workflow.index(remount))
        self.assertLess(workflow.index(remount), workflow.index(" stage-controller-runtime </dev/null"))
        self.assertLess(workflow.index(launch), workflow.index(post))
        self.assertLess(workflow.index(post), workflow.index(" supply-bwrap </dev/null"))
        self.assertIn("if: always() && steps.controller-runtime.outcome != 'skipped'", workflow)
        capsule = workflow.split("        id: controller-check\n", 1)[1].split("      - name:", 1)[0]
        for literal in ("ulimit -v 524288", "ulimit -t 15", "ulimit -n 64", "ulimit -f 128", "ulimit -c 0",
                        "--signal=TERM --kill-after=2s 30s", "mem_available > 6291456", "2147483648 / block_size",
                        "exec 4>&- 5>&-", 'exit "$final_result"'):
            self.assertIn(literal, capsule)
        self.assertNotIn(str(C.OUTER), capsule)
        self.assertIn("--signal=TERM --kill-after=2s 13s", workflow)
        upload = workflow.split("      - name: Retain only explicit redacted verification evidence", 1)[1]
        self.assertIn("if: always()", upload)
        for name in ("receipt.json", "waits.json", "stage-controller-runtime-refusal.json", "post-controller-check-refusal.json"):
            self.assertIn(str(C.CONTROLLER_CHECK_ROOT / name), upload)
        for private in ("/stdout", "/stderr", "/source", "originals.json", "/run/"):
            self.assertNotIn(private, upload)


    def owner_argv_fixture(self):
        info = file_info(mode=stat.S_IFREG | 0o444)
        info.st_size = 22
        runtime = {"files": [{"path": C.PYTHON_SEARCH[0], "identity": C.identity(info)}]}
        with patch.object(C, "controller_runtime_original", return_value=runtime), \
             patch.object(C, "pycache_original", return_value=self.pycache_fixture()):
            return C.owner_argv()

    def test_all_gnome_launches_have_the_fixed_prestartup_option_and_no_live_cleanup(self):
        literal = "/run/mrk-gnome-python-empty-pycache-v1"
        shell_python = C.PYTHON_EXECUTABLE + " -I -S -B -X pycache_prefix=" + literal + " "
        provider_python = "/usr/bin/python3.12 -I -S -B -X pycache_prefix=" + literal + " "
        workflow = (ROOT / C.WORKFLOW).read_text().split("\n  gnome-controller-characterization:\n", 1)[0]
        launches = [line.strip() for line in workflow.splitlines() if C.PYTHON_EXECUTABLE + " -I " in line]
        self.assertEqual(len(launches), 5)  # check plus existing phases; prepare/acquire share one fixed loop.
        self.assertTrue(all(line.startswith(shell_python) for line in launches))
        staging = [line.strip() for line in workflow.splitlines() if "/usr/bin/python3.12 -I " in line]
        self.assertEqual(len(staging), 2)  # DATA stage and all-outcome DATA POST only.
        self.assertTrue(all(line.startswith(provider_python) for line in staging))
        self.assertIn('"$GITHUB_WORKSPACE/desktop/tools/gnome_session_hosted.py" stage-controller-runtime', staging[0])
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
        self.assertLess(workflow.index(mkdir), workflow.index(provider_python))
        bind = "/usr/bin/mount --bind " + str(C.PYTHON_ROOT) + " " + str(C.PYTHON_ROOT)
        remount = "/usr/bin/mount -o remount,bind,ro " + str(C.PYTHON_ROOT)
        self.assertLess(workflow.index(provider_python), workflow.index(bind))
        self.assertLess(workflow.index(bind), workflow.index(remount))
        self.assertLess(workflow.index(remount), workflow.index(shell_python))
        argv = self.owner_argv_fixture()
        triples = [argv[i:i + 3] for i in range(len(argv) - 2)]
        for original, destination in ((literal, literal), (str(C.PYTHON_ROOT), str(C.PYTHON_ROOT)),
                                     (C.PYTHON_SEARCH[0], "/usr/bin/python3.12"),
                                     (literal, "/usr/lib/python3.12"),
                                     (str(C.PYTHON_ORIGINALS), "/controller-runtime-originals.json")):
            self.assertIn(["--ro-bind", original, destination], triples)
            self.assertLess(triples.index(["--ro-bind", original, destination]), argv.index("--remount-ro"))
        self.assertIn(["--dir", "/run"], [argv[i:i + 2] for i in range(len(argv) - 1)])
        start = argv.index(C.PYTHON_EXECUTABLE)
        self.assertEqual(argv[start:], [C.PYTHON_EXECUTABLE, "-I", "-S", "-B", "-X",
                                       "pycache_prefix=" + literal, "/owner.py"])
        guard = argv[argv.index("mrk-private-python-mask-guard") - 1]
        self.assertIn('[[ "$#" -eq 7 && "$1" == ' + C.PYTHON_EXECUTABLE + ' ]]', guard)
        self.assertIn("done </proc/self/mountinfo", guard)
        self.assertIn("(( runtime_ro == 1 && zip_ro == 1 && stdlib_ro == 1 && cache_ro == 1 ))", guard)
        self.assertIn('[[ ",$options," == *,ro,* ]]', guard)
        self.assertIn("--dereference --printf='%d:%i:%f:%h:%u:%g:%s'", guard)
        self.assertIn('exec /usr/bin/env -i PATH=/usr/bin:/bin HOME=/tmp TMPDIR=/tmp LANG=C LC_ALL=C TZ=UTC PWD=/tmp "$@"', guard)
        compile_only = (ROOT / "desktop/tools/gnome_session_native/compile-only.sh").read_text()
        self.assertIn(shell_python + "/prepare.py prepare", compile_only)
        self.assertIn(shell_python + '/check-compile.py "$phase"', compile_only)
        self.assertNotIn("/usr/bin/python3.12", compile_only)
        owner = (ROOT / "desktop/tools/gnome_session_native/owner.py").read_text()
        self.assertIn('[PYTHON_EXECUTABLE, "-I", "-S", "-B", "-X", "pycache_prefix='
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
            self.assertLess(body.index("phase_finish()"), body.index(destination))
        cleanup = source.split("def remove_settled(", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("Path(root).is_relative_to(TASK)", cleanup)
        for preserved in ("PYTHON_PYCACHE", "PYTHON_ROOT", "PYTHON_STAGE"):
            self.assertNotIn(preserved, cleanup)
        self.assertNotIn("rmdir", source.split("def pycache_empty(", 1)[1].split("\ndef capath_state(", 1)[0])
        self.assertNotIn("unlink", bootstrap)
        self.assertNotIn("rmdir", bootstrap)
        with patch.object(C, "bounded_roster") as roster:
            for preserved in (C.PYTHON_PYCACHE, C.PYTHON_ROOT, C.PYTHON_STAGE):
                with self.assertRaisesRegex(C.Refused, "settled-cleanup-correspondence"):
                    C.remove_settled(preserved, {})
        roster.assert_not_called()

    def test_gnome_entries_refuse_none_and_wrong_prefix_before_any_phase_or_helper(self):
        for prefix in (None, "/unbound", str(C.PYTHON_PYCACHE) + "/", Path(C.PYTHON_PYCACHE)):
            for phase in ("supply-bwrap", "prepare", "acquire", "run", "settle"):
                selected = self.selected_python()
                selected.argv, selected.pycache_prefix = ["inert", phase], prefix
                with self.subTest(prefix=prefix, phase=phase), patch.object(C, "sys", selected), \
                     patch.object(C, "read") as read, patch.object(C, "pycache_for_phase") as begin, \
                     patch.object(C, "command") as command, patch("builtins.print") as output:
                    self.assertEqual(C.main(), 1)
                output.assert_called_once_with("GNOME_HOSTED_REFUSAL=fixed-isolated-controller-entry", flush=True)
                for blocked in (read, begin, command):
                    blocked.assert_not_called()
            selected.argv = ["inert-owner"]
            with patch.object(N, "sys", selected), patch.multiple(N, report={}, errors=[], native_accepted=False,
                 pycache_fds=[], pycache_state=None, runtime_fds=[], runtime_state=None), patch.object(N, "owner_identity") as identity, \
                 patch.object(N, "data") as data, patch.object(N, "invoke") as invoke, patch.object(N, "emit"):
                self.assertEqual(N.main(), 1)
                self.assertEqual(N.errors, ["operation:isolated-owner-entry"])
            for blocked in (identity, data, invoke):
                blocked.assert_not_called()

    def test_private_projection_rejects_old_python_and_bytecode_alias_authority(self):
        value = self.python_catalogue()
        for key, path in (("hostFiles", "/usr/bin/python3.12"), ("hostFiles", "/usr/lib/python3.12/os.py"),
                          ("hostDirectories", "/usr/lib/python3.12"), ("hostAliases", "/usr/bin/python3"),
                          ("hostAliases", "/usr/lib/python3.12/alias.pyc")):
            changed = copy.deepcopy(value)
            changed[key].append({"path": path})
            with self.subTest(key=key, path=path), patch.object(C, "command") as command, patch.object(C, "read") as read:
                with self.assertRaisesRegex(C.Refused, "old-python-not-active-authority"):
                    C.python_runtime_catalogue(changed)
            command.assert_not_called()
            read.assert_not_called()
        historical = value["historicalPythonBaseline"]
        self.assertEqual(historical["imageVersion"], "20260907.300.1")
        self.assertEqual(historical["consumerClosure"]["counts"]["pythonPycLeaves"], 573)
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
        self.assertIn("python-two-alias-text-target-and-ancestry-acceptance",
                      value["historicalPythonBaseline"]["unresolvedPreservedAsHistorical"])
        self.assertIn("controller-runtime-actual-GN-import-ABI-and-original-custody-acceptance", value["unresolved"])
        self.assertIn("cargo-resolver-exact-parent-observation-acceptance", value["unresolved"])
        self.assertEqual(value["hostAbsent"], ["/etc/ld.so.preload"])
        self.assertEqual(value["bootstrapTrust"], C.BOOTSTRAP_TRUST)
        self.assertFalse(value["bootstrapTrust"]["retroactiveAuthentication"])
        self.assertTrue(value["bootstrapTrust"]["subsequentExactGuardsRequired"])
        counts = value["consumerClosure"]["counts"]
        self.assertEqual((counts["pythonRegularLeaves"], counts["pythonDirectoryRosters"], counts["pythonPycLeaves"]),
                         (598, 52, 0))
        for key in ("hostFiles", "hostDirectories", "hostAliases"):
            self.assertEqual(len(value[key]), counts[key])
            self.assertTrue(value[key])
        self.assertFalse(value["consumerClosure"]["runtimeQualified"] or value["consumerClosure"]["gateClearingApproved"])
        self.assertTrue(all(not row["path"].startswith("/usr/share/ca-certificates") for row in value["hostFiles"]))
        # Complete private Python SOURCE does not close any actual host/native prerequisite.
        self.assertEqual(C.python_runtime_catalogue(value)["runtimeFiles"], 598)
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
            entry = self.selected_python()
            entry.argv = ["inert-controller", phase]
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
            ("runtime-close", "controller-runtime-close-unknown"),
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
                    self.assertTrue(frame["pythonPycacheHandlesClosed"] and frame["controllerRuntimeHandlesClosed"])
                    self.assertEqual(frame["pythonPycache"], self.pycache_fixture())
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
            def prefix_finish(*, failed=False):
                events.append("prefix-close")
                if case == "prefix-close":
                    C._ORIGINALS_SETTLED = False
                    raise C.Refused("pycache-original-close-unknown")
            def runtime_finish(*, failed=False):
                events.append("runtime-close")
                C._EVIDENCE["controllerRuntime"]["phaseHandlesClosed"] = case != "runtime-close"
                if case == "runtime-close":
                    C._ORIGINALS_SETTLED = False
                    raise C.Refused("controller-runtime-close-unknown")
            def evidence(pin, value):
                self.assertIn("receipt-return", events)
                events.append("success-evidence")
                project_evidence(pin, value)
            with self.subTest(case=case), ExitStack() as stack:
                for name, value in (("_PINS", pins), ("_WAITS", []), ("_SUPPLIERS", []),
                                    ("_ORIGINALS_SETTLED", True), ("_EVIDENCE", {"bwrapSupply": None, "controllerRuntime": {"phaseHandlesClosed": False}})):
                    stack.enter_context(patch.object(C, name, value))
                stack.enter_context(patch.object(C, "pycache_original", return_value=self.pycache_fixture()))
                stack.enter_context(patch.object(C, "pycache_finish", side_effect=prefix_finish))
                stack.enter_context(patch.object(C, "controller_runtime_finish", side_effect=runtime_finish))
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
                        "source-post", "inputs-post", "close:73", "close:72", "close:71", "runtime-close", "prefix-close",
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
                self.assertEqual(C._ORIGINALS_SETTLED, case not in ("acquisition-unknown", "wait-unknown", "prefix-close", "runtime-close"))
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
                   "controllerRuntimeHandlesClosed": True,
                   "supplierOriginal": supplier, "waits": C.bwrap_original_waits()}
        for case in ("good", "source", "run", "unsettled", "handles", "wait", "installed", "parent", "failed-stage", "capath", "prefix", "prefix-handles", "runtime-handles"):
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
            if case == "runtime-handles":
                changed["controllerRuntimeHandlesClosed"] = False
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
        runtime = {"receipt": {"pythonPycache": original}}
        before = {"schema": C.BWRAP_SUPPLY_SCHEMA, **context, "stageIdentity": stage, "pythonPycache": original}
        with patch.object(C, "_PYTHON_RUNTIME", runtime), \
             patch.object(C, "pycache_begin", return_value=original) as begin, patch.object(C, "read") as read:
            self.assertIs(C.pycache_for_phase(context, "supply-bwrap"), original)
        begin.assert_called_once_with(original)
        read.assert_not_called()
        for missing in (None, [], "unbound"):
            with self.subTest(missing=missing), patch.object(C, "_PYTHON_RUNTIME", {"receipt": {"pythonPycache": missing}}), \
                 patch.object(C, "pycache_begin") as begin:
                with self.assertRaisesRegex(C.Refused, "pycache-first-phase-original-required"):
                    C.pycache_for_phase(context, "supply-bwrap")
            begin.assert_not_called()
        for phase in ("prepare", "acquire", "run", "settle"):
            for case in ("good", "other-run", "other-stage", "writable-control", "missing-original", "other-original"):
                changed = copy.deepcopy(before)
                if case == "other-run":
                    changed["runId"] = "124"
                if case == "other-stage":
                    changed["stageIdentity"][1] += 1
                if case == "missing-original":
                    changed["pythonPycache"] = None
                if case == "other-original":
                    changed["pythonPycache"]["identity"][1] += 1
                pin = {"mode": "0o600" if case == "writable-control" else "0o400"}
                with self.subTest(phase=phase, case=case), patch.object(C, "_PYTHON_RUNTIME", runtime), \
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
                       lambda v: v["hostFiles"].append({"path": C.CARGO_RESOLVER["path"]}),
                       lambda v: v["hostFiles"].__setitem__(slice(None), [r for r in v["hostFiles"] if r["path"] != C.CA_FILE])):
            changed = copy.deepcopy(catalogue)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(C.Refused):
                C.cargo_mount_selection(changed)
        self.assertTrue(catalogue["unresolved"])

    def test_cargo_resolver_is_exact_nonexecuting_data_and_never_general_runtime_authority(self):
        payload = b"nameserver 192.0.2.1\n"
        contract = {**C.CARGO_RESOLVER, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        catalogue = {"cargoAcquisition": {"resolverData": {**contract, "role": "cargo-acquisition-resolver-snapshot-only"}}}
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
        argv = self.owner_argv_fixture()
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
                  "controllerRuntimeInputsPrechecked": 598, "controllerRuntimeInputsPostchecked": 598,
                  "controllerRuntimeInputsExpected": 598,
                  "nativeEvidence": {"cases": ["existing", "missing", "duplicate", "stop-after-secret", "deadline-after-secret", "owner-loss", "fresh-session-absent"],
                                     "actualLibtestPassed": 1, "persistent": False, "installedProvider": False, "gui": False},
                  "waits": [{"role": role, "originalEnvelopeExit": 0, "originalReaderExit": 0,
                             "readerTimedOut": False, "cleanupErrors": [], "logBytes": 20, "logSha256": "e" * 64}
                            for role in ("namespace-probe", "compile", "artifact-elf", "native", "source-post")]}
        for key in ("namespaceProbeAttempted", "namespaceProbePassed", "nativeEnvelopeAttempted", "nativeEntryObserved", "nativeAccepted", "passed",
                    "nestedNamespaceRetired", "completeSourceDependencyPostchecked", "artifactReceiptPostchecked", "artifactPostchecked",
                    "outerPrivateCohortQuiet", "hostReservationChecked", "pythonPycacheSameLeaf",
                    "pythonPycachePostchecked", "pythonPycacheHandlesClosed",
                    "controllerRuntimeSameRoot", "controllerRuntimePostchecked", "controllerRuntimeHandlesClosed",
                    "oldPythonMasksChecked", "oldPythonMasksPostchecked"):
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
                     lambda r: r.update(pythonPycacheHandlesClosed=False),
                     lambda r: r.pop("controllerRuntimeSameRoot"), lambda r: r.update(controllerRuntimePostchecked=False),
                     lambda r: r.update(controllerRuntimeHandlesClosed=False), lambda r: r.update(oldPythonMasksChecked=False),
                     lambda r: r.pop("oldPythonMasksPostchecked"), lambda r: r.update(controllerRuntimeInputsPostchecked=597),
                     lambda r: r.update(controllerRuntimeInputsExpected=True)]
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
                owner_argv=lambda: ["inert-owner-argv"],
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
             bounded_roster=roster, remove_settled=remove, phase_finish=lambda: None,
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
        workflow = (ROOT / C.WORKFLOW).read_text().split("\n  gnome-controller-characterization:\n", 1)[0]
        self.assertNotIn("ci_foundation.py", workflow)
        self.assertNotIn("secrets:", workflow)
        self.assertNotIn("setup-python", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("--clear-groups", workflow)
        self.assertIn("steps.native.outcome == 'success'", workflow)
        job_header = workflow.split("  gnome-session-native:\n", 1)[1].split("    steps:\n", 1)[0]
        self.assertNotIn("runner.environment", job_header)
        self.assertEqual(workflow.count("RUNNER_ENVIRONMENT: ${{ runner.environment }}"), 8)
        supply = '"$GITHUB_WORKSPACE/desktop/tools/gnome_session_hosted.py" supply-bwrap </dev/null'
        self.assertEqual(workflow.count(supply), 1)
        self.assertLess(workflow.index(supply), workflow.index("for phase in prepare acquire; do"))
        self.assertIn("        id: bwrap\n        timeout-minutes: 5\n", workflow)
        for installer in ("apt-get", "apt install", "dpkg --install", "dpkg -i"):
            self.assertNotIn(installer, workflow)
        for relative in C.CARRIER_FILES:
            if relative != C.WORKFLOW:
                self.assertIn(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() + "  " + relative, workflow)
        unpack = "desktop/tools/conventional_runtime_data.py"
        self.assertEqual(len(C.CARRIER_FILES), 11)
        self.assertNotIn(unpack, C.CARRIER_FILES)
        self.assertIn(hashlib.sha256((ROOT / unpack).read_bytes()).hexdigest() + "  " + unpack, workflow)
        self.assertIn("actions: read", workflow)
        self.assertIn("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", workflow)
        self.assertIn("run-id: '36074195702'", workflow)
        self.assertIn("artifact-ids: '10839621457'", workflow)
        self.assertIn("digest-mismatch: error", workflow)
        self.assertEqual(workflow.count("github-token: ${{ github.token }}"), 1)
        helper = (ROOT / "desktop/tools/gnome_session_native/check-compile.py").read_text()
        self.assertEqual(helper.count("or binding['productTree'] != '" + C.PRODUCT_TREE + "'"), 1)
        self.assertNotIn("d8686187fd23d74dc5bd179d1b44f63f696d987b", helper)
        self.assertIn("or binding['productFiles'] != 964", helper)
        self.assertIn("binding['sourceIndexSha256'] != hashlib.sha256(index).hexdigest()", helper)
        public_paths = workflow.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]
        early = {str(C.CONTROLLER_CHECK_ROOT / name) for name in (
            "receipt.json", "waits.json", "stage-controller-runtime-refusal.json", "post-controller-check-refusal.json")}
        self.assertTrue(all(line.strip().startswith(str(C.PUBLIC) + "/") or line.strip() in early
                            for line in public_paths.splitlines() if line.strip()))


if __name__ == "__main__":
    unittest.main()
