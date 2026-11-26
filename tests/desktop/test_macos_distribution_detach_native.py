"""Real macOS detach diagnostics; no signing or app qualification.

Select ONE test method in a fresh interpreter on the disposable hosted runner.
Only the scripts-only case elevates the ordinary Installer for a fixed no-op.
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
POSTINSTALL = b"#!/bin/sh\nexit 0\n"
RECEIPTS = "/private/var/db/receipts"


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


def _noop_package(stager, body, identifier):
    """Audit native pkgbuild output with existing bounded DATA parsers only."""
    _need(0 < len(body) <= 1024 * 1024, "fixture-package-bound")

    def allocation(_label, live, packed, expanded):
        _need(live + packed + expanded <= 4 * 1024 * 1024, "fixture-package-data-bound")

    members = stager.xar_members(body, allocation_budget=allocation)
    _need(len(members["PackageInfo"]) <= 16384 and len(members["Scripts"]) <= 65536,
          "fixture-package-members-bound")
    info = stager.ET.fromstring(members["PackageInfo"])
    _need(info.tag == "pkg-info" and info.get("identifier") == identifier
          and info.get("version") == "1" and info.get("install-location") == "/"
          and info.get("auth") == "root" and info.get("postinstall-action", "none") == "none",
          "fixture-package-identity")
    payload = info.findall("payload")
    _need(len(payload) <= 1 and all(row.get("numberOfFiles") == "0"
          and row.get("installKBytes", "0") == "0" for row in payload), "fixture-package-has-payload")
    hooks = info.findall("scripts")
    _need(len(hooks) == 1 and [row.tag for row in hooks[0]] == ["postinstall"]
          and hooks[0][0].get("file") in ("postinstall", "./postinstall")
          and hooks[0][0].get("timeout") in (None, "600"), "fixture-package-hooks")
    archive = members["Scripts"]
    if archive.startswith(b"\x1f\x8b"):
        archive = stager.inflate(archive, 65536, gzip=True)
    # The existing original-package preparation parser admits the packager's
    # real UID/GID. No archive rewriting, root chown or custom serializer.
    _need(stager._cpio_members(archive, (os.getuid(), os.getgid()), allocation_budget=allocation)
          == {"postinstall": (POSTINSTALL, 0o555)}, "fixture-package-script-bytes")


@unittest.skipUnless(HOSTED_MAC, "requires disposable github-hosted macOS")
class DistributionDetachNative(unittest.TestCase):
    def test_original_holder_visible_until_original_fds_close(self):
        self._exercise(installer_case=False)

    def test_scripts_only_installer_returns_before_original_detach(self):
        self._exercise(installer_case=True)

    def _exercise(self, *, installer_case):
        deadline = time.monotonic() + 180
        report = {
            "scope": "macos-distribution-detach-native", "busyDetach16": None,
            "case": "scripts-only-installer" if installer_case else "held-fd",
            "mountLocation": "volumes", "imageFormat": "UDZO",
            "mountAbsentBefore": None, "mountAbsentAfter": None,
            "busyStderr": "unavailable", "holderState": "unavailable",
            "busyTextHints": [], "lsofWarningHints": [],
            "ownHolderOnOriginalDevice": False, "lsofWarnings": None,
            "mountedFdsClosed": None, "finalDetach0": None,
            "originalDetached": False, "callersReturned": True,
            "nativeOutcomeKnown": True, "originalChecksFailed": False, "fixtureRetired": False,
        }
        if installer_case:
            report.update(noPayloadPackageVerified=False, installerReturnedZero=None,
                          receiptBefore="unobserved", receiptAfter="unobserved",
                          protectedReceiptCleanup=False, systemServiceExitClaimed=False,
                          finalDetach16=None, finalStderr="unavailable", finalTextHints=[])
        failure = None
        stage = "source-setup"
        host_fds, mounted_fds = [], []
        busy16 = False
        installer_ready = False

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
            # selected-case calls consume this ONE deadline; none renews it.
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

        def observe_holders():
            mount_original()
            observed = run("lsof", ["/usr/sbin/lsof", "-n", "-P", "-b", "-F0pcuftD",
                           "+f", "--", str(mount_path)], 10, 16 * 1024)
            holders = helper.distribution_busy_holders(
                observed.stdout, observed.stderr, observed.returncode,
                device=mounted_identity[0], own_pid=os.getpid(), own_uid=os.getuid())
            report["holderState"] = holders["state"]
            report["holderReferences"] = holders["references"]
            report["holderRows"] = holders["rows"]
            report["lsofWarnings"] = holders["warnings"]
            report["lsofWarningHints"] = _lsof_warning_hints(observed.stderr)
            report["ownHolderOnOriginalDevice"] = holders["state"] == "visible-holders" and any(
                row["owner"] == "self" and row["reference"] == "descriptor" and row["count"] >= 1
                for row in holders["rows"])

        def receipt_slots():
            # Read-only observations of two fixed protected names. They are
            # never cleanup targets, including after a known successful case.
            same_entry(None, RECEIPTS, receipts_fd, receipts_identity)
            slots = []
            for suffix, limit in (("plist", 65536), ("bom", 1024 * 1024)):
                try:
                    info = os.stat(identifier + "." + suffix, dir_fd=receipts_fd, follow_symlinks=False)
                except FileNotFoundError:
                    slots.append(None)
                    continue
                _need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                      and info.st_nlink == 1 and 0 < info.st_size <= limit, "receipt-entry-shape")
                slots.append(_identity(info) + (info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
            return tuple(slots)

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
            context = {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
            mount_path = helper.transport_mount_path_data(
                context, helper.ARM_TARGET, "package-install")
            volumes_fd = host_open("/Volumes", directory_flags)
            volumes_identity = _identity(os.fstat(volumes_fd))
            _need(volumes_identity[3] == 0, "volumes-parent-owner-required")
            os.mkdir("source", 0o700, dir_fd=work_fd)
            source_fd = host_open("source", directory_flags, parent=work_fd)
            source_identity = _identity(os.fstat(source_fd))
            source_name = "Install.pkg" if installer_case else "held.txt"
            create_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            if installer_case:
                stage = "receipt-before"
                identifier = ("dev.mobile-release-kit.detach-smoke." + context["GITHUB_RUN_ID"]
                              + "." + context["GITHUB_RUN_ATTEMPT"])
                receipts_fd = host_open(RECEIPTS, directory_flags)
                receipts_identity = _identity(os.fstat(receipts_fd))
                _need(receipts_identity[3] == 0, "receipt-parent-owner-required")
                _need(receipt_slots() == (None, None), "receipt-collision")
                report["receiptBefore"] = "absent"
                stage = "package-fixture"
                os.mkdir("scripts", 0o700, dir_fd=work_fd)
                scripts_fd = host_open("scripts", directory_flags, parent=work_fd)
                os.fchmod(scripts_fd, 0o755)  # This fresh original only; never a shared ancestor.
                scripts_identity = _identity(os.fstat(scripts_fd))
                script_fd = host_open("postinstall", create_flags, parent=scripts_fd)
                _need(os.write(script_fd, POSTINSTALL) == len(POSTINSTALL), "fixture-script-write-incomplete")
                os.fchmod(script_fd, 0o555)
                script_identity = _identity(os.fstat(script_fd))
                built = run("pkgbuild", ["/usr/bin/pkgbuild", "--nopayload", "--scripts", str(work / "scripts"),
                            "--identifier", identifier, "--version", "1", "--install-location", "/",
                            "--ownership", "recommended", "--compression", "legacy",
                            str(work / "source" / source_name)], 15)
                _need(built.returncode == 0, "pkgbuild-nonzero")
                same_entry(work_fd, "scripts", scripts_fd, scripts_identity)
                same_entry(scripts_fd, "postinstall", script_fd, script_identity)
                _need(os.pread(script_fd, len(POSTINSTALL) + 1, 0) == POSTINSTALL, "fixture-script-changed")
                source_file = host_open(source_name, read_flags, parent=source_fd)
            else:
                source_file = host_open(source_name, create_flags, parent=source_fd)
                _need(os.write(source_file, BODY) == len(BODY), "fixture-write-incomplete")
            source_info = os.fstat(source_file)
            source_file_identity = _identity(source_info)
            _need(stat.S_ISREG(source_info.st_mode) and source_info.st_uid == os.getuid()
                  and source_info.st_nlink == 1 and 0 < source_info.st_size <= 1024 * 1024,
                  "fixture-source-file-shape")
            source_body = os.pread(source_file, source_info.st_size + 1, 0)
            _need(len(source_body) == source_info.st_size and (installer_case or source_body == BODY),
                  "fixture-source-file-read")
            if installer_case:
                stage = "package-audit"
                _noop_package(stager, source_body, identifier)
                report["noPayloadPackageVerified"] = True

            stage = "image-fixture"
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
            file_fd = os.open(source_name, read_flags, dir_fd=mounted_fd)
            mounted_fds.append(file_fd)
            file_info = os.fstat(file_fd)
            _need(stat.S_ISREG(file_info.st_mode) and file_info.st_dev == mounted_identity[0]
                  and file_info.st_size == len(source_body) and os.read(file_fd, len(source_body) + 1) == source_body,
                  "original-mounted-file-required")

            if installer_case:
                stage = "installer"
                same_entry(source_fd, source_name, source_file, source_file_identity)
                same_entry(mounted_fd, source_name, file_fd, _identity(file_info))
                _need(os.pread(source_file, len(source_body) + 1, 0) == source_body, "original-package-changed")
                mount_original()
                # The ONLY elevated call. Installer itself runs the audited
                # standard no-op hook; no root Python/driver or other payload.
                installed = run("installer", ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer",
                                "-pkg", str(mount_path / source_name), "-target", "/", "-dumplog", "-verboseR"], 45)
                report["installerReturnedZero"] = installed.returncode == 0
                _need(report["installerReturnedZero"], "installer-nonzero")
                stage = "receipt-after"
                slots = receipt_slots()
                # Slot observations only, not registry or daemon-finality proof.
                # Do not contact PackageKit again before the detach being tested.
                report["receiptAfter"] = ("absent" if slots == (None, None) else
                                          "present" if all(slot is not None for slot in slots) else "partial")
                _need(receipt_slots() == slots, "receipt-slots-changed")
                installer_ready = True  # No artificial busy probe in this case.
            else:
                busy = run("busy-detach", ["/usr/bin/hdiutil", "detach", device, "-verbose"], 20)
                busy16 = busy.returncode == 16
                report["busyDetach16"] = busy16
                report["originalDetached"] = busy.returncode == 0
                report["busyStderr"] = helper.distribution_detach_stderr(busy.stderr)
                report["busyTextHints"] = _detach_text_hints(busy.stdout, busy.stderr)
                _need(busy16, "held-detach-not16")
                stage = "holder-classifier"
                observe_holders()
                # Nonroot warnings/NOFD/exit1 cannot prove absence. This control
                # requires a positive OUR descriptor on the original device.
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
            # The held-FD control has one intentional negative probe. The
            # Installer case has NONE: its one detach follows actual Installer0,
            # known receipt observations and original mounted descriptor closes.
            # A failed control classifier may retire known originals; an unknown
            # native outcome may not. Neither case forces or retries a detach.
            # A failed original check is never refreshed into later authority.
            if ((installer_ready if installer_case else busy16) and closes_known
                    and report["callersReturned"] and report["nativeOutcomeKnown"]
                    and not report["originalChecksFailed"]):
                try:
                    mount_original()
                    final = run("final-detach", ["/usr/bin/hdiutil", "detach", device]
                                + (["-verbose"] if installer_case else []), 30)
                    report["finalDetach0"] = final.returncode == 0
                    report["originalDetached"] = final.returncode == 0
                    if installer_case:
                        report["finalDetach16"] = final.returncode == 16
                        if not report["finalDetach0"]:
                            failure = failure or ("final-detach16" if report["finalDetach16"] else "final-detach-nonzero")
                        report["finalStderr"] = helper.distribution_detach_stderr(final.stderr)
                        report["finalTextHints"] = _detach_text_hints(final.stdout, final.stderr)
                        if report["finalDetach16"]:
                            # Failure-only observation; no absence/cleanup claim
                            # follows even a settled no-visible-match result.
                            observe_holders()
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
                    same_entry(source_fd, source_name, source_file, source_file_identity)
                    same_entry(work_fd, "image.dmg", image_fd, image_identity)
                    if installer_case:
                        _need(receipt_slots() == slots, "receipt-slots-changed")
                        same_entry(work_fd, "scripts", scripts_fd, scripts_identity)
                        same_entry(scripts_fd, "postinstall", script_fd, script_identity)
                    # Fixed original inventory only. Unexpected native scratch
                    # entries are retained by rmdir refusal, never discovered
                    # and recursively deleted or adopted into the inventory.
                    # Protected Installer receipts are NOT part of this scratch.
                    clock()
                    os.unlink(source_name, dir_fd=source_fd)
                    clock()
                    os.unlink("image.dmg", dir_fd=work_fd)
                    clock()
                    os.rmdir("source", dir_fd=work_fd)
                    if installer_case:
                        clock()
                        os.unlink("postinstall", dir_fd=scripts_fd)
                        clock()
                        os.rmdir("scripts", dir_fd=work_fd)
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
