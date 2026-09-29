"""Focused Android qualification functions for the existing private CI owner.

No CLI, process owner, tool discovery, download, account acquisition or profile
enablement lives here. The caller must already have admitted the selected
Android material/OS tuple and the existing Check.private_command execution
route. Pure roster calculations are not native qualification evidence.
"""
from __future__ import annotations

import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import zipfile

from mobile_release import android, android_build_tools as tools


_SCOPE = "android-jdk17-reserved-output-v1"
_OUTPUT_LIMIT = 2 * 1024 * 1024
_STORE_PASSWORD = "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD"
_KEY_PASSWORD = "MOBILE_RELEASE_ANDROID_KEY_PASSWORD"
_ALIAS = "mrk-synthetic-upload"


def _need(value, message):
    if not value:
        raise ValueError(message)


def signed_checkpoint_budget(profile):
    """Use the exact parsed production roster, never MAX_OS_FILES*MAX_DEPTH.

    The existing per-record regression binds199+k/217 charges at29 metadata
    rounds. This conservative bound assumes full requested reads; additional
    positive short reads may still exhaust the unchanged original counter.
    """
    _need(type(profile) is tools._Profile, "Exact parsed Android profile required")
    root = Path(profile.binding.root)
    ancestry = {str(path) for path in (root, *root.parents)}
    directories = {str(root / relative) for relative in profile.directories}
    os_directories = {str(parent) for row in profile.native_files for parent in Path(row.path).parents}
    added_os_directories = os_directories - ancestry - directories
    regular = 1 + len(profile.files) + len(profile.native_files)
    # Include the separately checked root record in addition to its ancestor.
    directory = len(ancestry) + 1 + len(directories) + len(added_os_directories)
    retained = regular + directory
    bound = (199 * regular + 217 * directory + 5 * retained
             + (tools.MAX_TOTAL_BYTES + tools.MAX_MANIFEST_BYTES) // tools.READ_CHUNK
             + regular + 1024)
    descriptor_roster = (len(ancestry) + 1 + len(directories) + len(profile.files)
                         + len(profile.native_files) + len(added_os_directories) + 1)
    _need(tools.MAX_CHECKPOINTS == 4_000_000, "Signed checkpoint cap must not be relaxed")
    return {
        "schema": "android-signed-roster-budget-v1", "metadataRounds": 29,
        "toolFiles": len(profile.files), "toolDirectories": len(directories),
        "osFiles": len(profile.native_files), "uniqueOsDirectories": len(os_directories),
        "additionalOsDirectories": len(added_os_directories),
        "regularRecords": regular, "directoryRecords": directory,
        "descriptorReservation": descriptor_roster,
        "checkpointBound": bound, "checkpointCap": tools.MAX_CHECKPOINTS,
        "fits": bound <= tools.MAX_CHECKPOINTS and descriptor_roster <= tools.MAX_DESCRIPTORS,
        "assumption": "full-requested-reads; actual native operation still required",
        "nativeOperationObserved": False,
    }


def profile_and_budget(manifest, binding, os_contract):
    """Authenticate supplied document correspondence, not the host/OS itself."""
    _need(type(os_contract) is bytes and 0 < len(os_contract) <= 1024 * 1024,
          "Original OS contract byte bound")
    profile = tools._parse_manifest(manifest, tools._binding(binding))
    _need(hashlib.sha256(os_contract).hexdigest() == profile.os_inventory_sha256,
          "Original manifest/OS contract binding differs")
    value = json.loads(os_contract, object_pairs_hook=tools._pairs,
                       parse_constant=lambda _: _need(False, "Nonfinite OS contract"))
    _need(type(value) is dict and value.get("id") == profile.os_identity
          and value.get("files") == [{"path": row.path, "size": row.size,
                                     "sha256": row.sha256, "mode": row.mode}
                                    for row in profile.native_files],
          "Original manifest/OS file roster differs")
    budget = signed_checkpoint_budget(profile)
    _need(budget["fits"], "Signed original roster exceeds its existing bound")
    return profile, budget


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def qualify_reserved_output(check, *, manifest, binding, os_contract):
    """Run fixed synthetic cases through Check.private_command, never raw exec.

    The caller supplies its already admitted immutable publication tuple. The
    returned evidence proves JDK behavior only, NOT a saved-build, cancellation,
    material transport, native OS admission or production profile enablement.
    All fixture files remain under the existing owner's private root; that owner
    performs its normal all-outcome POST and exact task-output cleanup.
    """
    _need(not check.failed and callable(check.private_command), "Original private owner required")
    try:
        return _qualify_reserved_output(check, manifest, binding, os_contract)
    except BaseException:
        check.failed = True
        raise


def _qualify_reserved_output(check, manifest, binding, os_contract):
    profile, budget = profile_and_budget(manifest, binding, os_contract)
    versions = dict(profile.versions)
    version = versions["jdkVersion"]
    _need(sys.platform == "linux" and os.getuid() != 0
          and versions["jdkVendor"] == "Ubuntu-OpenJDK"
          and re.fullmatch(r"17\.[0-9]+\.[0-9]+\+[0-9]+", version) is not None,
          "Selected nonroot Linux JDK17 tuple required")
    selected = {row.path: row for row in profile.files}
    names = {"java": tools.TOOL_ROLES["java"], "keytool": tools.KEYTOOL_PATH,
             "jarsigner": tools.JARSIGNER_PATH}
    _need(all(name in selected and selected[name].size > 0 and selected[name].mode & 0o111
              for name in names.values()), "Same selected JDK signer leaves required")
    root = Path(profile.binding.root)
    work = check.root / "android-jdk17-reserved-output"
    original_end = check.end
    owner = (os.getuid(), os.getgid())
    held = []
    primary = None
    result = None
    close_errors = []

    def point():
        _need(check.end == original_end and type(original_end) in (int, float)
              and math.isfinite(original_end) and time.monotonic() < original_end
              and not check.failed, "Original qualification endpoint/owner changed")

    def hold(path, flags, *, parent=None):
        point()
        number = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=parent)
        held.append(number)
        return number

    point()
    work.mkdir(mode=0o700)  # Exclusive task-owned fixture; never adopt a prior tree.
    try:
        directory = hold(work, os.O_RDONLY | os.O_DIRECTORY)
        directory_identity = _identity(os.fstat(directory))[:5]
        _need(directory_identity[2] == stat.S_IFDIR | 0o700
              and directory_identity[3:5] == owner, "Private fixture directory shape")

        def directory_check():
            point()
            _need(_identity(os.fstat(directory))[:5] == directory_identity
                  == _identity(work.lstat())[:5], "Original fixture directory changed")

        def original(number, name, *, maximum=_OUTPUT_LIMIT):
            directory_check()
            value = os.fstat(number)
            _need(_identity(value) == _identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
                  and stat.S_ISREG(value.st_mode) and stat.S_IMODE(value.st_mode) == 0o600
                  and (value.st_uid, value.st_gid) == owner and value.st_nlink == 1
                  and 0 <= value.st_size <= maximum and not os.get_inheritable(number),
                  "Original synthetic file custody differs")
            return _identity(value)

        def digest(number, name):
            before = original(number, name)
            _need(os.lseek(number, 0, os.SEEK_SET) == 0, "Original fixture rewind")
            remaining, state = before[6], hashlib.sha256()
            while remaining:
                point()
                block = os.read(number, min(65536, remaining))
                _need(0 < len(block) <= remaining, "Original fixture read bound")
                state.update(block)
                remaining -= len(block)
            _need(original(number, name) == before, "Original fixture changed during read")
            return state.hexdigest()

        def absent(name):
            directory_check()
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise ValueError("Synthetic fixture output already exists")

        def environment(*, store=None, key=None):
            value = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
                     "PATH": str(root / "jdk/bin") + ":/usr/bin", "HOME": str(work),
                     "TMPDIR": str(work), "JAVA_HOME": str(root / "jdk")}
            if store is not None:
                value[_STORE_PASSWORD] = store
            if key is not None:
                value[_KEY_PASSWORD] = key
            return value

        calls = []

        def call(label, role, arguments, *, env=None, codes=(0,), seconds=30):
            directory_check()
            jvm = tools._jvm_arguments(work, bundletool=True)
            argv = [str(root / names[role]), *(jvm if role == "java" else ["-J" + arg for arg in jvm]), *arguments]
            value = check.private_command("android-jdk17-" + label, argv,
                environment() if env is None else env, work, timeout=seconds, codes=codes, limit=_OUTPUT_LIMIT)
            directory_check()
            calls.append({"case": label, "tool": role, "exitCode": value.returncode})
            return value

        actual = call("version", "java", ["-version"])
        actual_version = (actual.stdout + actual.stderr).decode("utf-8", "strict")
        _need(re.search(r'^openjdk version "' + re.escape(version.split("+", 1)[0]) + r'"', actual_version)
              and re.search(r"build " + re.escape(version) + r"[-)\s]", actual_version),
              "Actual selected JDK version differs")
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as writer:
            member = zipfile.ZipInfo("content.txt", (2000, 1, 1, 0, 0, 0))
            member.create_system, member.external_attr = 3, (stat.S_IFREG | 0o600) << 16
            writer.writestr(member, b"Non-executable MRK synthetic signing fixture.")
        unsigned = archive.getvalue()
        _need(len(unsigned) < 4096, "Synthetic ZIP extent")
        input_name = "unsigned.jar"
        input_fd = hold(input_name, os.O_RDWR | os.O_CREAT | os.O_EXCL, parent=directory)
        offset = 0
        while offset < len(unsigned):
            point()
            written = os.write(input_fd, unsigned[offset:])
            _need(0 < written <= len(unsigned) - offset, "Synthetic input write")
            offset += written
        os.fsync(input_fd)
        input_identity = original(input_fd, input_name)
        input_hash = digest(input_fd, input_name)
        final_files = [(input_fd, input_name, input_identity, input_hash)]
        cases = []
        for container in ("JKS", "PKCS12"):
            stem = container.lower()
            store_name = stem + ".keystore"
            absent(store_name)
            env = environment(store="mrk-synthetic-store-pass",
                              key="mrk-synthetic-key-pass" if container == "JKS" else "mrk-synthetic-store-pass")
            call(stem + "-generate", "keytool", ["-genkeypair", "-alias", _ALIAS,
                "-keyalg", "RSA", "-keysize", "2048", "-sigalg", "SHA256withRSA",
                "-dname", "CN=MRK Disposable Reserved Output", "-validity", "365",
                "-storetype", container, "-keystore", str(work / store_name),
                "-storepass:env", _STORE_PASSWORD, "-keypass:env", _KEY_PASSWORD, "-noprompt"], env=env)
            store_fd = hold(store_name, os.O_RDONLY, parent=directory)
            store_identity, store_hash = original(store_fd, store_name), digest(store_fd, store_name)
            final_files.append((store_fd, store_name, store_identity, store_hash))
            listed = call(stem + "-list", "keytool", ["-J-Duser.timezone=UTC", "-list", "-v",
                "-keystore", str(work / store_name), "-alias", _ALIAS,
                "-storepass:env", _STORE_PASSWORD, "-keypass:env", _KEY_PASSWORD], env=env)
            _need(b"PrivateKeyEntry" in listed.stdout + listed.stderr, "Synthetic private-key entry not validated")
            certificate = call(stem + "-certificate", "keytool", ["-exportcert", "-alias", _ALIAS,
                "-keystore", str(work / store_name), "-storepass:env", _STORE_PASSWORD],
                env=environment(store=env[_STORE_PASSWORD])).stdout
            _need(0 < len(certificate) <= 64 * 1024 and certificate.startswith(b"\x30"), "Synthetic DER certificate bound")
            fingerprint = hashlib.sha256(certificate).hexdigest()
            wrong_store = dict(env, **{_STORE_PASSWORD: "mrk-definitely-wrong-store"})
            refused = call(stem + "-wrong-store", "keytool", ["-J-Duser.timezone=UTC", "-list", "-v",
                "-keystore", str(work / store_name), "-alias", _ALIAS,
                "-storepass:env", _STORE_PASSWORD, "-keypass:env", _KEY_PASSWORD], env=wrong_store, codes=(1,))
            _need(refused.returncode == 1, "Wrong store password was not rejected")
            for scenario in (("success", "wrong-key") if container == "JKS" else ("success",)):
                output_name = stem + "-" + scenario + ".jar"
                output_fd = hold(output_name, os.O_RDWR | os.O_CREAT | os.O_EXCL, parent=directory)
                before = original(output_fd, output_name)
                _need(before[6] == 0, "Reserved output was not empty")
                command_env = env if scenario == "success" else dict(env, **{_KEY_PASSWORD: "mrk-definitely-wrong-key"})
                if scenario == "wrong-key":
                    key_listing = call(stem + "-wrong-key-list", "keytool", ["-J-Duser.timezone=UTC", "-list", "-v",
                        "-keystore", str(work / store_name), "-alias", _ALIAS,
                        "-storepass:env", _STORE_PASSWORD, "-keypass:env", _KEY_PASSWORD], env=command_env)
                    _need(b"PrivateKeyEntry" in key_listing.stdout + key_listing.stderr,
                          "Independent wrong-key case did not pass store listing")
                signed = call(stem + "-" + scenario + "-sign", "jarsigner", ["-keystore", str(work / store_name),
                    "-storepass:env", _STORE_PASSWORD, "-keypass:env", _KEY_PASSWORD,
                    "-signedjar", str(work / output_name), str(work / input_name), _ALIAS],
                    env=command_env, codes=(0,) if scenario == "success" else (1,), seconds=120)
                after = original(output_fd, output_name)
                _need(after[:6] == before[:6] and original(input_fd, input_name) == input_identity
                      and digest(input_fd, input_name) == input_hash
                      and original(store_fd, store_name) == store_identity and digest(store_fd, store_name) == store_hash,
                      "Signer replaced a reserved output or changed an original input")
                accepted = False
                if scenario == "success":
                    _need(after[6] > 0, "Successful signer left an empty reserved output")
                    output_hash = digest(output_fd, output_name)
                    verification = call(stem + "-verify", "jarsigner", ["-verify", "-strict", str(work / output_name)],
                                        codes=(0, 4), seconds=120)
                    _need(android._jar_signature_policy(verification.returncode,
                        verification.stdout.decode("utf-8", "strict"), verification.stderr.decode("utf-8", "strict")),
                        "Actual signature policy rejected the synthetic output")
                    leaf = call(stem + "-leaf", "keytool", ["-printcert", "-jarfile", str(work / output_name)])
                    _need(android._keytool_fingerprint(leaf.returncode, leaf.stdout.decode("utf-8", "strict")) == fingerprint,
                          "Actual signed output leaf does not match its synthetic saved certificate")
                    _need(original(output_fd, output_name) == after and digest(output_fd, output_name) == output_hash,
                          "Reserved output changed across native inspectors")
                    accepted = True
                final_files.append((output_fd, output_name, after, digest(output_fd, output_name)))
                cases.append({"container": container, "case": scenario, "signerExit": signed.returncode,
                              "reservedInodePreserved": True, "inputUnchanged": True,
                              "signatureAndLeafAccepted": accepted})
        # Later keytool/verification calls cannot invalidate an earlier case.
        # Keep every original FD through this final byte/identity observation.
        for number, name, identity, expected_hash in final_files:
            _need(original(number, name) == identity and digest(number, name) == expected_hash,
                  "Original synthetic file changed before fixture finality")
        directory_check()
        result = {"schema": _SCOPE, "manifestSha256": profile.binding.sha256,
                  "osContractSha256": profile.os_inventory_sha256, "jdkVersion": version,
                  "rosterBudget": budget, "cases": cases, "commands": calls,
                  "selectedTools": {role: {"path": path, "size": selected[path].size,
                                         "sha256": selected[path].sha256, "mode": selected[path].mode}
                                    for role, path in names.items()},
                  "privateFixtureOnly": True, "savedBuildQualified": False,
                  "signingTimeCancellationObserved": False, "qualificationEnabled": False}
    except BaseException as error:
        primary = error
        check.failed = True  # Latch before independent descriptor cleanup.
    finally:
        # Independent one-attempt closes; never retry a consuming close or
        # recursively delete the private fixture after uncertain ownership.
        for number in reversed(held):
            try:
                os.close(number)
            except BaseException as error:
                close_errors.append(type(error).__name__)
    if primary is not None:
        if close_errors:
            raise RuntimeError("JDK fixture failed and descriptor cleanup is incomplete") from primary
        raise primary
    _need(not close_errors and result is not None, "JDK fixture descriptor cleanup incomplete")
    point()
    result["originalFixtureDescriptorsClosed"] = True
    return result


# Saved-signing comparisons have one pure DATA implementation. Native17
# functions and imports above retain their original behavior and source bytes.
from mobile_release._desktop_android_saved_signing_data import SAVED_SIGNING_CASES, validate_saved_signing_case
