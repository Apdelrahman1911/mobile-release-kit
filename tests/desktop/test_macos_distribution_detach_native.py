"""Real nonroot macOS lsof smoke; no Installer, signing or app qualification.

Run this file in a fresh interpreter on the selected disposable hosted runner.
Unknown native completion retains the tiny fixture for runner disposal, never
force-detaches, retries an uncertain detach or recursively removes a mount.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
HOSTED_MAC = (sys.platform == "darwin"
              and os.environ.get("GITHUB_ACTIONS") == "true"
              and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted")
BODY = b"Harmless MobileReleaseKit detach diagnostic fixture.\n"


class _FiniteFailure(Exception):
    """Only fixed local labels, never native output or exception messages."""


def _need(condition, label):
    if not condition:
        raise _FiniteFailure(label)


def _load(name):
    spec = importlib.util.spec_from_file_location(
        "_mrk_detach_native_" + name, ROOT / "desktop/tools" / (name + ".py"))
    _need(spec is not None and spec.loader is not None, "source-unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _identity(info):
    # Directory times change during our fixed creation/mount/removal actions.
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _detach_text_hints(stdout, stderr):
    # Bounded original captures; literal text ONLY, not cause/stage/dissenter.
    data = stdout.lower() + b"\n" + stderr.lower()
    return [label for token, label in (
        (b"resource busy", "resource-busy-text"),
        (b"unmount", "unmount-text"),
        (b"eject", "eject-text"),
        (b"dissent", "dissent-text"),
    ) if token in data]


def _lsof_warning_hints(stderr):
    # Full-line source forms from bounded stderr. No interpolated path/device
    # escapes; even only expected warnings cannot exclude silent EPERM skips.
    forms = (
        ("avoided-stat", rb"lsof: avoiding stat\([^\r\n]*\): -b was specified\."),
        ("avoided-readlink", rb"lsof: avoiding readlink\([^\r\n]*\): -b was specified\."),
        ("cannot-stat-filesystem", rb"lsof: WARNING: can't stat\(\) [^\r\n]+ file system [^\r\n]+"),
        ("incomplete-information", rb"      Output information may be incomplete\."),
        ("mount-table-device-fallback", rb'      assuming "dev=[0-9a-fA-F]{1,16}" from mount table'),
        ("no-mount-information", rb"lsof: no mount information"),
    )
    found = set()
    for line in stderr.split(b"\n"):
        if not line:
            continue
        for label, pattern in forms:
            if re.fullmatch(pattern, line):
                found.add(label)
                break
        else:
            found.add("other-warning")
    return [label for label, _ in forms if label in found] + (["other-warning"] if "other-warning" in found else [])


@unittest.skipUnless(HOSTED_MAC, "requires disposable github-hosted macOS")
class DistributionDetachNative(unittest.TestCase):
    def test_original_holder_visible_until_original_fds_close(self):
        deadline = time.monotonic() + 180
        report = {
            "scope": "macos-distribution-detach-native", "busyDetach16": None,
            "mountLocation": "volumes", "imageFormat": "UDZO",
            "mountAbsentBefore": None, "mountAbsentAfter": None,
            "busyStderr": "unavailable", "holderState": "unavailable",
            "busyTextHints": [], "lsofWarningHints": [],
            "ownHolderOnOriginalDevice": False, "lsofWarnings": None,
            "mountedFdsClosed": None, "finalDetach0": None,
            "originalDetached": False, "callersReturned": True,
            "nativeOutcomeKnown": True, "originalChecksFailed": False, "fixtureRetired": False,
        }
        failure = None
        stage = "source-setup"
        host_fds, mounted_fds = [], []
        busy16 = False

        def clock():
            _need(time.monotonic() < deadline, "deadline")

        def host_open(path, flags, *, parent=None, mode=0o600):
            clock()
            fd = os.open(path, flags, mode, dir_fd=parent)
            host_fds.append(fd)
            return fd

        def same_entry(parent, name, fd, expected):
            try:
                clock()
                _need(_identity(os.fstat(fd)) == expected
                      == _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                      "original-entry-changed")
            except BaseException:
                report["originalChecksFailed"] = True
                raise

        def work_original():
            same_entry(None, str(temp_parent), temp_fd, temp_identity)
            same_entry(temp_fd, work.name, work_fd, work_identity)

        def run(role, argv, maximum, limit=65536):
            work_original()
            # run_owned owns an additional three-second cleanup reserve. All
            # five calls consume this ONE deadline; none renews the clock.
            timeout = min(maximum, int(deadline - time.monotonic() - 3))
            _need(timeout >= 1, "deadline")
            report["callersReturned"] = False
            try:
                result = owner.run_owned(argv, environ=environment, cwd=work,
                                         timeout=timeout, capture=True, text=False,
                                         output_limit=limit)
            except BaseException:
                report["nativeOutcomeKnown"] = False
                raise _FiniteFailure(role + "-unknown") from None
            report["callersReturned"] = True
            if type(result.returncode) is not int or result.returncode < 0:
                report["nativeOutcomeKnown"] = False
                raise _FiniteFailure(role + "-unknown")
            return result

        def mount_original():
            try:
                work_original()
                same_entry(None, "/Volumes", volumes_fd, volumes_identity)
                _need(_identity(os.stat(mount_path.name, dir_fd=volumes_fd, follow_symlinks=False))
                      == mounted_identity, "original-mount-changed")
                node = os.stat(device, follow_symlinks=False)
                _need(_identity(node) == device_identity and stat.S_ISBLK(node.st_mode)
                      and node.st_rdev == mounted_identity[0], "original-device-changed")
            except BaseException:
                report["originalChecksFailed"] = True
                raise

        def mount_absent():
            try:
                same_entry(None, "/Volumes", volumes_fd, volumes_identity)
                try:
                    os.stat(mount_path.name, dir_fd=volumes_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return
                raise _FiniteFailure("transport-mount-not-absent")
            except BaseException:
                report["originalChecksFailed"] = True
                raise

        try:
            _need(os.getuid() == os.geteuid() != 0, "nonroot-required")
            qualification = _load("macos_aqua_qualification")
            stager = _load("stage_macos_installed")
            helper = _load("macos_android_helper_package")
            _need(callable(getattr(helper, "distribution_busy_holders", None))
                  and callable(getattr(helper, "distribution_detach_stderr", None)), "classifier-unavailable")
            owner = qualification.load_owner(ROOT)
            clock()
            stage = "host-fixture"
            supplied_temp = os.environ.get("RUNNER_TEMP", "")
            _need(bool(supplied_temp) and os.path.isabs(supplied_temp), "runner-temp-required")
            temp_parent = Path(supplied_temp).resolve(strict=True)
            read_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            directory_flags = read_flags | os.O_DIRECTORY
            temp_fd = host_open(temp_parent, directory_flags)
            temp_identity = _identity(os.fstat(temp_fd))
            # Deliberately NOT TemporaryDirectory: no automatic rmtree on an
            # uncertain original mount, even after a failed attach.
            work = Path(tempfile.mkdtemp(prefix="mrk-detach-smoke-", dir=temp_parent))
            work_fd = host_open(work, directory_flags)
            work_identity = _identity(os.fstat(work_fd))
            work_original()
            environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C",
                           "LC_ALL": "C", "TZ": "UTC", "HOME": str(work), "TMPDIR": str(work)}
            # Match the production transport namespace and image format. Only
            # hdiutil creates/removes this initially absent /Volumes entry.
            mount_path = helper.transport_mount_path_data(
                {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")},
                helper.ARM_TARGET, "package-install")
            volumes_fd = host_open("/Volumes", directory_flags)
            volumes_identity = _identity(os.fstat(volumes_fd))
            _need(volumes_identity[3] == 0, "volumes-parent-owner-required")
            os.mkdir("source", 0o700, dir_fd=work_fd)
            source_fd = host_open("source", directory_flags, parent=work_fd)
            source_identity = _identity(os.fstat(source_fd))
            source_file = host_open("held.txt", os.O_RDWR | os.O_CREAT | os.O_EXCL
                                    | os.O_NOFOLLOW | os.O_CLOEXEC, parent=source_fd)
            _need(os.write(source_file, BODY) == len(BODY), "fixture-write-incomplete")
            source_file_identity = _identity(os.fstat(source_file))

            created = run("create", ["/usr/bin/hdiutil", "create", "-size", "8m", "-fs", "HFS+",
                          "-volname", "MRKDetachSmoke", "-srcfolder", str(work / "source"),
                          "-format", "UDZO", str(work / "image.dmg")], 45)
            _need(created.returncode == 0, "create-nonzero")
            image_fd = host_open("image.dmg", read_flags, parent=work_fd)
            image_info = os.fstat(image_fd)
            _need(stat.S_ISREG(image_info.st_mode) and image_info.st_nlink == 1
                  and image_info.st_uid == os.getuid() and 0 < image_info.st_size <= 16 * 1024 * 1024,
                  "created-image-invalid")
            image_identity = _identity(image_info)
            mount_absent()
            report["mountAbsentBefore"] = True
            attached = run("attach", ["/usr/bin/hdiutil", "attach", str(work / "image.dmg"),
                           "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", str(mount_path),
                           "-plist"], 30)
            _need(attached.returncode == 0, "attach-nonzero")
            try:
                device = stager.distribution_mount_data(
                    attached.stdout, attached.stderr, attached.returncode, mount_path)
            except BaseException:
                raise _FiniteFailure("attach-identity-unknown") from None
            clock()
            stage = "mounted-fixture"
            mounted_fd = os.open(mount_path.name, directory_flags, dir_fd=volumes_fd)
            mounted_fds.append(mounted_fd)
            mounted_identity = _identity(os.fstat(mounted_fd))
            _need(mounted_identity[0] != volumes_identity[0]
                  and os.fstatvfs(mounted_fd).f_flag & os.ST_RDONLY, "readonly-mount-required")
            device_info = os.stat(device, follow_symlinks=False)
            device_identity = _identity(device_info)
            mount_original()
            file_fd = os.open("held.txt", read_flags, dir_fd=mounted_fd)
            mounted_fds.append(file_fd)
            file_info = os.fstat(file_fd)
            _need(stat.S_ISREG(file_info.st_mode) and file_info.st_dev == mounted_identity[0]
                  and file_info.st_size == len(BODY) and os.read(file_fd, len(BODY) + 1) == BODY,
                  "original-mounted-file-required")

            busy = run("busy-detach", ["/usr/bin/hdiutil", "detach", device, "-verbose"], 20)
            busy16 = busy.returncode == 16
            report["busyDetach16"] = busy16
            report["originalDetached"] = busy.returncode == 0
            report["busyStderr"] = helper.distribution_detach_stderr(busy.stderr)
            report["busyTextHints"] = _detach_text_hints(busy.stdout, busy.stderr)
            _need(busy16, "held-detach-not16")
            mount_original()
            observed = run("lsof", ["/usr/sbin/lsof", "-n", "-P", "-b", "-F0pcuftD",
                           "+f", "--", str(mount_path)], 10, 16 * 1024)
            stage = "holder-classifier"
            holders = helper.distribution_busy_holders(
                observed.stdout, observed.stderr, observed.returncode,
                device=mounted_identity[0], own_pid=os.getpid(), own_uid=os.getuid())
            report["holderState"] = holders["state"]
            report["lsofWarnings"] = holders["warnings"]
            report["lsofWarningHints"] = _lsof_warning_hints(observed.stderr)
            # Nonroot warnings/NOFD/exit1 cannot prove absence. This assertion
            # requires a positive OUR descriptor on the original mounted dev.
            report["ownHolderOnOriginalDevice"] = holders["state"] == "visible-holders" and any(
                row["owner"] == "self" and row["reference"] == "descriptor" and row["count"] >= 1
                for row in holders["rows"])
            _need(report["ownHolderOnOriginalDevice"], "own-original-holder-not-visible")
        except _FiniteFailure as error:
            failure = str(error)
        except BaseException:
            failure = stage + "-unknown"
        finally:
            had_mounted_fds = bool(mounted_fds)
            closes_known = True
            while mounted_fds:
                fd = mounted_fds.pop()  # Consume each original once, including a failed close.
                try:
                    os.close(fd)
                except BaseException:
                    closes_known = False
                    failure = failure or "mounted-close-unknown"
            report["mountedFdsClosed"] = closes_known if had_mounted_fds else None
            # The first detach16 was an intentional negative probe. Only known
            # closure of those ORIGINAL holders authorizes this second detach.
            # A failed classifier may still retire known originals; an unknown
            # native outcome may not. No force or speculative detach is present.
            # A failed original check is never refreshed into later authority.
            if (busy16 and closes_known and report["callersReturned"] and report["nativeOutcomeKnown"]
                    and not report["originalChecksFailed"]):
                try:
                    mount_original()
                    final = run("final-detach", ["/usr/bin/hdiutil", "detach", device], 30)
                    report["finalDetach0"] = final.returncode == 0
                    report["originalDetached"] = final.returncode == 0
                    _need(report["finalDetach0"], "final-detach-nonzero")
                except _FiniteFailure as error:
                    failure = failure or str(error)
                except BaseException:
                    failure = failure or "final-detach-local-unknown"
            if (report["originalDetached"] and closes_known and report["callersReturned"]
                    and report["nativeOutcomeKnown"] and not report["originalChecksFailed"]):
                try:
                    work_original()
                    mount_absent()
                    report["mountAbsentAfter"] = True
                    same_entry(work_fd, "source", source_fd, source_identity)
                    same_entry(source_fd, "held.txt", source_file, source_file_identity)
                    same_entry(work_fd, "image.dmg", image_fd, image_identity)
                    # Fixed original inventory only. Unexpected native scratch
                    # entries are retained by rmdir refusal, never discovered
                    # and recursively deleted or adopted into the inventory.
                    clock()
                    os.unlink("held.txt", dir_fd=source_fd)
                    clock()
                    os.unlink("image.dmg", dir_fd=work_fd)
                    clock()
                    os.rmdir("source", dir_fd=work_fd)
                    work_original()
                    os.rmdir(work.name, dir_fd=temp_fd)
                    report["fixtureRetired"] = True
                except _FiniteFailure as error:
                    failure = failure or str(error)
                except BaseException:
                    failure = failure or "fixture-retirement-unknown"
            while host_fds:
                fd = host_fds.pop()
                try:
                    os.close(fd)
                except BaseException:
                    failure = failure or "host-close-unknown"

        if time.monotonic() >= deadline:
            failure = failure or "deadline"
        report["outcome"] = failure or "passed"
        print(json.dumps(report, sort_keys=True, separators=(",", ":")), flush=True)
        if failure:
            self.fail(failure)


if __name__ == "__main__":
    unittest.main()
