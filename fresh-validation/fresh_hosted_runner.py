"""Fixed two-job/seven-Installer adapter. SOURCE PREPARATION; no live entry.

Uses macos_e2_native_fixture.Operation.call/Originals for process and capture
custody, and the existing stager tree/XAR/cpio/readback implementation.
No acquisition, compiler, credentials, app rebuild, cleanup or public release.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import xml.etree.ElementTree as ET

EXECUTION_BINDING = None
TARGET = "aarch64-apple-darwin"
PRODUCT = {'source': 'f778beb993691330c56b59059de5c8d970fbb27d', 'tree': 'bdd9e77af2c626e435e02f9fbebfd229ef6a06a7'}
# This is the frozen ordinary product, independent of runner/transport sources.
CONTROL_TRANSPORT = {'commit': '6cf1d138781e652b26c28051470254c338186982', 'tree': 'ad1eadeb560bd4a24a9b4f9e8e6254686a8c3fdf', 'manifestSha256': 'b7184e4e296b5bef9392ceb08e702c9f5be74d79cc90a0947a26f6f4408eb176', 'remoteAvailable': True}
JOB_STEPS = {
    "write-diagnostic": ("write", "frontier", "diagnostic-recovery", "completed"),
}
CUT_ROLES = {"write": ("first-payload-write", 87), "torn": ("torn-first-payload-frame", 88)}
CONTROL_ROLE = {"write": "write", "torn": "torn", "frontier": "census",
                "frontier-refusal": "census", "completed": "census", "recovery": "recovery"}
CONTROL_IDS = {role: "dev.mobile-release-kit.disposable-fresh." + role
               for role in ("write", "frontier", "completed", "recovery")}
OUTPUT_LIMIT = 256 * 1024
RECORD_LIMIT = 16 * 1024


class Refused(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def hex_value(value, length):
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) and value != "0" * length


def unique_pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def document(body, limit=RECORD_LIMIT):
    need(type(body) is bytes and 0 < len(body) <= limit and body.endswith(b"\n"), "complete-record-bound")
    return json.loads(body.decode("utf-8", "strict"), object_pairs_hook=unique_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(Refused("json-constant")))


def bound_control(value, binding, image_role):
    need(type(value) is dict and type(value.get("schemaVersion")) is int and value.get("schemaVersion") == 1 and value.get("target") == TARGET,
         "control-record-shape")
    expected = {
        "productSource": binding["productSource"],
        "controlSourceSha256": binding["controlSourceSha256"],
        "controlManifestSha256": binding["controlManifestSha256"],
        "controlImageSha256": binding["controls"][image_role]["sha256"],
        "packageSha256": binding["package"]["sha256"],
        "producerDescriptorSha256": binding["producer"]["sha256"],
        "producerSignatureSha256": binding["signature"]["sha256"],
        "transportState": "pending-original-process-exit", "installationQualified": False,
    }
    need(all(value.get(k) == v and type(value.get(k)) is type(v) for k, v in expected.items()),
         "control-original-binding")


def cut_data(body, binding, role, outer_returncode):
    value = document(body)
    bound_control(value, binding, role)
    label, expected_exit = CUT_ROLES[role]
    need(type(outer_returncode) is int and 1 <= outer_returncode <= 255
         and value.get("kind") == "mrk-disposable-fresh-cut-v1" and value.get("role") == label
         and value.get("originalFailure") == "worker-result-incomplete"
         and type(value.get("originalChildExit")) is int and value["originalChildExit"] == expected_exit
         and value.get("terminationAttempted") is False and hex_value(value.get("invocation"), 32)
         and all(value.get(key) is True for key in ("outputEof", "outputClose", "commandClose",
             "parentOriginalsSettled", "nativeSettled", "timely", "sourcePost", "controlledInterruptionWitnessed")),
         "controlled-original-failure-required")
    return value


def frontier_data(body, binding, invocation, outer_returncode):
    value = document(body)
    bound_control(value, binding, "census")
    need(type(outer_returncode) is int and outer_returncode == 0
         and value.get("kind") == "mrk-disposable-fresh-census-v1"
         and value.get("scope") == "fresh-frontier" and value.get("recoveryExecuted") is False,
         "frontier-original-success-required")
    observed = value.get("observation")
    need(type(observed) is dict and observed.get("kind") == "mrk-fresh-frontier-observed-v1"
         and observed.get("invocation") == invocation and observed.get("frontier") == "copying"
         and type(observed.get("payloadBytes")) is int and observed["payloadBytes"] > 0
         and observed.get("oldOriginalReturnReconstructed") is False
         and observed.get("preservationPerformed") is False
         and hex_value(observed.get("requestId"), 32)
         and all(hex_value(observed.get(key), 64) for key in ("intentSha256", "originSha256",
             "enrollmentSha256", "enrollmentHeadSha256", "physicalCommitmentSha256", "selectionSha256")),
         "genuine-copying-frontier")
    return value


def completed_data(body, binding, frontier, installation, outer_returncode):
    value = document(body)
    bound_control(value, binding, "census")
    need(type(outer_returncode) is int and outer_returncode == 0
         and value.get("kind") == "mrk-disposable-fresh-census-v1"
         and value.get("scope") == "completed-conservation" and value.get("recoveryExecuted") is False,
         "completed-collector-original-success-required")
    old, observed = frontier["observation"], value["observation"]
    result = installation.get("originalInstallerResult", {})
    reference = installation.get("freshConservation")
    need(type(reference) is dict and type(reference.get("reference")) is dict
         and observed.get("kind") == "mrk-fresh-conservation-observed-v1"
         and observed.get("selectionSha256") == old["selectionSha256"]
         and observed.get("root") == old["root"]
         and observed.get("reference") == reference["reference"]
         and reference["reference"].get("invocation") == old["invocation"]
         and hex_value(reference["reference"].get("receiptSha256"), 64)
         and observed.get("attempts") == [{k: old[k] for k in ("invocation", "requestId", "intentSha256")}],
         "completed-reference-and-original-attempt")
    need(installation.get("sourceCommit") == binding["productSource"]
         and installation.get("completedPackageSha256") == binding["package"]["sha256"]
         and installation.get("inventorySha256") == binding["inventorySha256"]
         and installation.get("runtimeManifestSha256") == binding["runtimeManifestSha256"]
         and installation.get("originalInstallerReturnedZero") is True
         and installation.get("originalWriterJoined") is True
         and result.get("action") == "fresh-install"
         and hex_value(installation.get("invocation"), 32)
         and installation["invocation"] != old["invocation"], "genuine-new-Fresh-recovery")
    # Native create/read_attempt/retained_enrollment and two reobservations
    # prove retained physical conservation. Do not invent a digest field that
    # completed output does not export or rename this case clean Fresh.
    return {"case": "diagnostic-recovered-Fresh", "diagnosticOnly": True,
            "ordinaryInstallationQualified": False, "freshRecoveryQualified": False, "cleanFreshQualified": False,
            "interruptedInvocation": old["invocation"],
            "recoveryInvocation": installation["invocation"], "reference": observed["reference"],
            "physicalConservationBasis": "native-authenticated-retained-audit-and-owned-sequence",
            "literalCrossOutputPhysicalDigestEqualityClaimed": False}


def torn_shape(value, binding, cut):
    quote = binding["snapshotQuote"]
    need(value.get("root") == "/Library/Application Support/MobileReleaseKit"
         and value.get("binding") == binding["snapshotBinding"]
         and value.get("resourceBounds") == quote["bounds"]
         and value.get("transportState") == "pending-original-process-exit"
         and value.get("installationQualified") is False and value.get("recoveryQualified") is False,
         "torn-snapshot-exact-binding")
    stage = ".install-" + cut["invocation"]
    directories = {"", "versions", stage, *(stage + "/" + p for p in quote["visitedAppDirectories"])}
    files = {"registration-reservation-v1", "maintenance-gate-v1",
        ".maintenance-" + cut["invocation"] + ".intent.json",
        stage + "/fresh-output-origin-v1.json", stage + "/fresh-output-enrollment-v1",
        stage + "/staging-created.json", stage + "/" + quote["firstPayloadPath"]}
    rows = value.get("rows")
    need(type(rows) is dict and set(rows) == directories | files
         and len(directories) == quote["privateDirectories"] and len(files) == quote["privateFiles"],
         "torn-exact-source-derived-roster")
    for path, row in rows.items():
        need(type(row) is dict and type(row.get("identity")) is list and len(row["identity"]) == 10
             and all(type(n) is int for n in row["identity"]), "torn-row-identity")
        identity = row["identity"]
        need(identity[3:5] == [0, 0] and identity[9] == 0
             and not identity[2] & 0o022 and row.get("native", {}).get("aclEmpty") is True
             and row["native"].get("xattrNames") == [] and row["native"].get("flags") == 0,
             "torn-row-native-protection")
        if path in directories:
            expected = sorted(p.rsplit("/", 1)[-1] for p in rows if p and
                (p.rsplit("/", 1)[0] if "/" in p else "") == path)
            need(row.get("kind") == "directory" and stat.S_ISDIR(identity[2])
                 and row.get("names") == expected, "torn-directory-roster")
        else:
            need(row.get("kind") == "file" and stat.S_ISREG(identity[2]) and identity[5] == 1
                 and type(row.get("bytes")) is int and row["bytes"] == identity[6]
                 and 0 <= row["bytes"] <= quote["bounds"]["maxFileBytes"]
                 and hex_value(row.get("sha256"), 64), "torn-file-row")
    payload = rows[stage + "/" + quote["firstPayloadPath"]]
    need(payload["bytes"] == 0 and payload["sha256"] == sha(b""), "torn-first-payload-empty")
    need(rows["versions"]["names"] == []
         and 0 < rows[stage + "/fresh-output-enrollment-v1"]["bytes"]
         <= (quote["directoryCount"] + 1) * 2052 + 1, "torn-journal-source-bound")
    exports = value.get("requestExports")
    need(type(exports) is dict and len(exports) == 1, "torn-one-reserved-export")
    name, export = next(iter(exports.items()))
    correlation = value.get("originIntentCorrelation")
    need(type(correlation) is dict and correlation.get("invocation") == cut["invocation"]
         and hex_value(correlation.get("requestId"), 32)
         and correlation["requestId"] != cut["invocation"]
         and correlation.get("intentSha256") == rows[".maintenance-" + cut["invocation"] + ".intent.json"]["sha256"]
         and correlation.get("originSha256") == rows[stage + "/fresh-output-origin-v1.json"]["sha256"]
         and correlation.get("journalSemanticsAccepted") is False
         and name == "MobileReleaseKit-InstallerResult-v2-" + correlation["requestId"] + ".json",
         "torn-exact-cut-request-export")
    need(re.fullmatch(r"MobileReleaseKit-InstallerResult-v2-[0-9a-f]{32}\.json", name)
         and export.get("kind") == "file" and export.get("bytes") == 0
         and export.get("sha256") == sha(b"") and type(export.get("identity")) is list
         and len(export["identity"]) == 10 and export["identity"][3:5] == [0, 0]
         and stat.S_IMODE(export["identity"][2]) == 0o600,
         "torn-empty-reserved-export")
    return value


def compare_torn(before_body, after_body, binding, cut):
    before, after = document(before_body, OUTPUT_LIMIT), document(after_body, OUTPUT_LIMIT)
    for value in (before, after):
        need(value.get("kind") == "mrk-fixed-torn-physical-snapshot-v1"
             and value.get("originalClosesKnown") is True and value.get("launcherAbsent") is True
             and value.get("semanticJournalAccepted") is False and value.get("mutationPerformed") is False,
             "complete-physical-snapshot-required")
        torn_shape(value, binding, cut)
    need(before["binding"] == after["binding"] and before["resourceBounds"] == after["resourceBounds"]
         and before["originIntentCorrelation"] == after["originIntentCorrelation"]
         and before["rows"] == after["rows"], "torn-root-enrollment-staging-changed")
    # Fixed policy: no exception is currently admitted. A later exact ordinary
    # diagnostic export needs its own reviewed original identity before it can
    # be added; existing root or private-tree changes never get an exception.
    need(before["requestExports"] == after["requestExports"], "unexpected-request-export")
    return {"case": "torn-Fresh-refusal", "rootBytesAndIdentitiesPreserved": True,
            "installationQualified": False, "recoveryQualified": False,
            "beforeSha256": sha(before_body), "afterSha256": sha(after_body)}


def control_script(scripts, role, invocation=None):
    if role == "recovery":
        need(hex_value(invocation, 32), "diagnostic-fixed-request")
        template = scripts["diagnostic-recovery-postinstall"]
        need(template.count(b"@REQUEST@") == 1, "diagnostic-single-request-slot")
        return template.replace(b"@REQUEST@", invocation.encode("ascii"))
    if role in ("write", "torn"):
        need(invocation is None, "cut-script-no-nomination")
        return scripts["cut-postinstall"]
    if role == "completed":
        need(invocation is None, "completed-script-no-nomination")
        return scripts["completed-postinstall"]
    need(role == "frontier" and invocation is None, "frontier-prebuilt-without-nomination")
    return scripts["frontier-postinstall"]


def frontier_name(invocation):
    need(hex_value(invocation, 32), "frontier-filename-nomination")
    return "Fresh-frontier-" + invocation + ".pkg"


def package_info(body, identifier):
    # Same scripts-only PackageInfo restrictions as existing context reader;
    # only the four literal nonshipping identifiers are added here.
    need(identifier in CONTROL_IDS.values() and len(body) <= 65536, "control-package-identifier")
    need(b"<!DOCTYPE" not in body and b"<!ENTITY" not in body, "control-package-xml-declaration")
    info = ET.fromstring(body)
    allowed = {"format-version", "identifier", "version", "install-location", "auth", "generator-version"}
    defaults = {"overwrite-permissions": "true", "relocatable": "false", "postinstall-action": "none"}
    need(set(info.attrib) <= allowed | defaults.keys()
         and all(info.get(key) in (None, value) for key, value in defaults.items()), "control-package-attributes")
    need(info.tag == "pkg-info" and info.get("identifier") == identifier
         and info.get("version") == "1" and info.get("install-location") == "/"
         and info.get("auth") == "root", "control-package-identity")
    empty = {"bundle-version", "upgrade-bundle", "update-bundle", "atomic-update-bundle",
             "strict-identifier", "relocate"}
    tags = [child.tag for child in info]
    need(len(tags) == len(set(tags)) and set(tags) <= empty | {"payload", "scripts"}
         and "scripts" in tags, "control-no-payload")
    for child in info:
        if child.tag in empty:
            need(not child.attrib and not list(child) and not (child.text or "").strip(), "empty-package-action")
        elif child.tag == "payload":
            need(not list(child) and child.get("numberOfFiles") == "0"
                 and child.get("installKBytes", "0") == "0"
                 and set(child.attrib) <= {"numberOfFiles", "installKBytes"}, "control-no-payload")
        else:
            need(not child.attrib and len(child) == 1 and child[0].tag == "postinstall"
                 and child[0].get("file") in ("postinstall", "./postinstall")
                 and child[0].get("timeout") in (None, "600")
                 and set(child[0].attrib) <= {"file", "timeout"} and not list(child[0])
                 and not (child[0].text or "").strip(), "control-one-exec-hook")
    return info


def build_control(op, stager, binding, role, invocation=None):
    """Reuse original DATA stager + pkgbuild/root-cpio/xar sequence, never sudo."""
    need(EXECUTION_BINDING is not None, "source-preparation-only")
    store_runtime = binding["storeRuntime"]
    need(type(store_runtime) is bool, "bound-store-runtime-profile")
    prefix = "input/runtime/store" if store_runtime else None
    label = "frontier" if role == "frontier-refusal" else role
    image_role = CONTROL_ROLE[role]
    scripts = op.work / ("fresh-" + label + "-scripts")
    original = op.work / ("fresh-" + label + "-original.pkg")
    parts = op.work / ("fresh-" + label + "-parts")
    final = op.work / ("Fresh-" + label + ".pkg")
    files = {"postinstall": (control_script(binding["scriptBodies"], label, invocation), 0o555),
             "mrk-macos-install": (binding["controlBodies"][image_role], 0o555),
             **{"input/" + path: item for path, item in binding["inputFiles"].items()}}
    inputs = sum(len(item[0]) for item in files.values())
    need(inputs <= stager.MAX_BYTES, "control-scripts-existing-aggregate-cap")
    prior = sum(binding.get("builtPackageBytes", {}).values())
    fixed = binding.get("sourceBytes", 0) + len(binding["packageBody"]) + sum(map(len, binding["controlBodies"].values())) + prior + 64 * 1024 * 1024
    resource_capacity(op, binding["hostAPI"], binding,
        {"memoryBytes": fixed + 3 * inputs, "diskBytes": 3 * inputs + 32 * 1024 * 1024},
        label="build-" + label + "-stage")
    stager.write_tree(scripts, files, root_mode=0o755, mac_store_prefix=prefix)
    call = lambda name, argv, cwd=op.work: original_call(op, "build-" + label + "-" + name, argv,
        binding["commandEnvironment"], cwd=cwd, timeout=30, limit=OUTPUT_LIMIT, zero=True)
    call("pkgbuild", ["/usr/bin/pkgbuild", "--nopayload", "--scripts", str(scripts),
        "--identifier", CONTROL_IDS[label], "--version", "1", "--install-location", "/",
        "--ownership", "recommended", "--compression", "legacy", str(original)])
    raw = read_control_archive(op, binding, original, fixed, inputs, "build-" + label + "-original")
    members = stager.xar_members(raw)
    need(set(members) == {"PackageInfo", "Scripts"}, "control-original-roster")
    package_info(members["PackageInfo"], CONTROL_IDS[label])
    archive = members["Scripts"]
    if archive.startswith(b"\x1f\x8b"):
        archive = stager.inflate(archive, stager.MAX_BYTES, gzip=True)
    expected = {**files, **{path: (None, 0o555) for path in stager.directories(files, mac_store_prefix=prefix)}}
    need(stager._cpio_members(archive, (os.getuid(), os.getgid()), store_runtime=store_runtime) == expected, "control-original-script-bytes")
    info_body = members["PackageInfo"]
    # Retire first audit vectors before the second complete archive/readback.
    del archive, members, raw
    stager.write_tree(parts, {"PackageInfo": (info_body, 0o444)}, root_mode=0o700)
    call("tar", ["/usr/bin/tar", "-c", "-z", "-f", str(parts / "Scripts"),
        "--format=odc", "--uid=0", "--gid=0", "--no-acls", "--no-xattrs", "--no-fflags",
        "--no-mac-metadata", "."], cwd=scripts)
    call("xar", ["/usr/bin/xar", "-c", "-f", str(final), "--compression=none", "PackageInfo", "Scripts"], cwd=parts)
    raw = read_control_archive(op, binding, final, fixed, inputs, "build-" + label + "-final")
    actual = stager.xar_members(raw)
    need(set(actual) == {"PackageInfo", "Scripts"} and actual["PackageInfo"] == info_body,
         "control-final-roster")
    packed = actual["Scripts"]
    if packed.startswith(b"\x1f\x8b"):
        packed = stager.inflate(packed, stager.MAX_BYTES, gzip=True)
    need(stager.cpio_members(packed, store_runtime=store_runtime) == expected
         and stager.tree(scripts, packager=True, mac_store_prefix=prefix) == files,
         "complete-root-owned-control-script-readback")
    op.source.book.check()
    binding.setdefault("builtPackageBytes", {})[label] = len(raw)
    return final, {"path": str(final), "bytes": len(raw), "sha256": sha(raw)}


def read_control_archive(op, binding, path, fixed, inputs, label):
    """Admit the actual held size before the existing full archive reader."""
    book = op.outputs
    parent = book.directory(path.parent)
    fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent["fd"])
    entry = book.register(fd, path, "file")
    entry["parent"] = parent
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
         and not info.st_mode & 0o022 and 0 < info.st_size <= 512 * 1024 * 1024, "actual-control-archive-size")
    entry["identity"] = binding["e2Module"].signature(info)
    book.check_one(entry)
    # At full parse: retained input + inflated archive + copied CPIO leaves,
    # and both actual compressed package/member vectors. A bounded index/
    # path/CPIO-header allowance is additional to source/receipt reserve.
    quote = {"memoryBytes": fixed + 3 * inputs + 2 * info.st_size + 16 * 1024 * 1024,
             "diskBytes": 2 * info.st_size + 32 * 1024 * 1024}
    resource_capacity(op, binding["hostAPI"], binding, quote, label=label)
    try:
        return book.read(entry)
    finally:
        book.close(entry)
        need(entry["closed"], "control-archive-original-close")


def original_call(op, label, argv, environment, *, cwd, timeout, limit, zero):
    """The existing call owns wait/EOF and closes the actual full capture files."""
    need(EXECUTION_BINDING is not None, "source-preparation-only")
    need(time.monotonic_ns() + (timeout + 3) * 1_000_000_000 < op.fresh_deadline, "fresh-group-deadline")
    need(len(op.calls) < 128 and label not in {row["role"] for row in op.calls}, "fixed-original-never-replayed")
    result = op.call(label, argv, environment, cwd=cwd, timeout=timeout, limit=limit)
    op.publish(label + ".status", (str(result.returncode) + "\n").encode("ascii"))
    need(op.calls[-1]["returned"] is True
         and all(entry["closed"] for entry in op.outputs.entries if entry["kind"] == "output"),
         "original-capture-closes")
    need(time.monotonic_ns() < op.fresh_deadline, "fresh-group-original-close-deadline")
    op.calls[-1]["capturesSettled"] = True
    if zero:
        need(result.returncode == 0, "original-nonzero")
    return result


def installer_original(op, binding, step, package):
    need(step in JOB_STEPS[binding["job"]], "fixed-installer-step")
    # No PackageKit PID discovery/adoption; same existing owner and root transition.
    return original_call(op, "install-" + step,
        ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer", "-dumplog",
         "-pkg", str(package), "-target", "/"], binding["commandEnvironment"],
        cwd=op.work, timeout=123, limit=OUTPUT_LIMIT, zero=False)


def publish_diagnostic_installation_observation(op, stager, binding, args, original):
    need(original.returncode == 0, "diagnostic-Installer-zero-before-readback")
    need(binding["inputPath"] == op.work / "input", "existing-stager-input-parent")
    status = op.work / "installer-output.status"
    op.outputs.publish(status, b"0\n")
    args.installer_status = status
    observed = stager.observation_command(args)
    need(observed.get("originalInstallerReturnedZero") is True
         and observed.get("originalWriterJoined") is True, "ordinary-readback-finality")
    # Explicit new validation evidence, never silently added to old six-member carrier.
    observed.update(diagnosticOnly=True, ordinaryInstallationQualified=False, freshRecoveryQualified=False,
        diagnosticImageSha256=sha(binding["controlBodies"]["recovery"]))
    body = stager.canonical(observed) + b"\n"
    op.outputs.publish(op.work / "diagnostic-installation-observation.json", body)
    return observed



def log_cursor(stager, binding):
    with stager.installer_log_file() as (fd, outer, name, info):
        identity = stager.installer_log_identity(info)
        size = min(info.st_size, stager.LOG_TAIL_BYTES)
        tail = stager.positioned_log_read(fd, info.st_size - size, size)
        need(stager.positioned_log_read(fd, info.st_size - size, size) == tail, "log-anchor-post")
        growth = stager.log_growth(fd, outer, name, identity, info.st_size)
        return stager.make_log_cursor(binding, identity, info.st_size, tail, growth)


def log_capture(stager, cursor, binding, *, refusal=False, evidence_sink=None):
    """Same bounded fixed install.log window, only new exact Fresh records selected."""
    stager.validate_log_cursor(cursor, binding)
    with stager.installer_log_file() as (fd, outer, name, info):
        identity = stager.installer_log_identity(info)
        need(identity == cursor["identity"], "log-original-identity")
        start, end = cursor["offsetBytes"], info.st_size
        need(start <= end <= start + stager.LOG_INTERVAL_BYTES, "log-interval-bound")
        anchor = stager.positioned_log_read(fd, start - cursor["precedingTailBytes"], cursor["precedingTailBytes"])
        body = stager.positioned_log_read(fd, start, end - start)
        stager.validate_log_window(cursor, identity, end, anchor, body)
        need(stager.positioned_log_read(fd, start - len(anchor), len(anchor)) == anchor, "log-anchor-post")
        growth = stager.log_growth(fd, outer, name, identity, end)
    selected, records, refused = [], [], []
    for line in body.splitlines(keepends=True):
        need(line.endswith(b"\n") and len(line) <= stager.LOG_LINE_BYTES, "log-line-bound")
        if b"mrk-disposable-fresh-cut-v1" in line or b"mrk-disposable-fresh-census-v1" in line:
            records.append(line)
            selected.append(line)
        if b"fresh-census-refused:" in line:
            refused.append(line)
            selected.append(line)
    retained = b"".join(selected)
    need(len(retained) <= stager.LOG_SELECTED_BYTES, "fresh-log-selection-bound")
    metadata = {"schemaVersion": 1, "binding": binding,
        "cursorSha256": sha(canonical(cursor)), "intervalBytes": len(body),
        "intervalSha256": sha(body), "selectedBytes": len(retained), "selectedSha256": sha(retained),
        "growthBeyondSnapshotBytes": growth, "authority": stager.LOG_AUTHORITY,
        "originalInstallerRequiredSeparately": True}
    # The source/interval/close checks above establish diagnostic bytes only.
    # Preserve an actual native refusal before record validation can raise;
    # metadata and file existence never qualify an Installer or a census.
    if evidence_sink is not None:
        evidence_sink(retained, metadata)
    parsed = []
    for line in records:
        index = line.find(b"{")
        need(index >= 0, "fresh-log-json-start")
        raw = line[index:]
        value = document(raw)
        need(value.get("kind") in ("mrk-disposable-fresh-cut-v1", "mrk-disposable-fresh-census-v1"),
             "fresh-log-kind")
        parsed.append(raw)
    records = parsed
    for line in refused:
        need(re.search(rb"fresh-census-refused:[a-z0-9-]{1,128}\r?\n$", line), "fresh-refusal-record")
    if refusal:
        need(not records and len(refused) == 1
             and refused[0].rstrip(b"\r\n").endswith(b"fresh-census-refused:fresh-output-torn-header"),
             "one-exact-torn-census-refusal")
        result = None
    else:
        need(len(records) == 1 and not refused, "one-complete-fresh-record")
        result = records[0]
    return result, retained, metadata


class Carrier:
    """One package invocation per read-only carrier; existing Originals custody."""
    def __init__(self, op, stager, host_api, binding, label, packages, request):
        need(label in ("cut", "frontier", "ordinary", "completed") and hex_value(request, 32), "fixed-carrier-role")
        self.op, self.stager, self.api = op, stager, host_api
        op.fresh_carriers.append(self)
        self.label, self.binding, self.request = label, binding, request
        self.book = type(op.protected)()
        self.attached = self.detached = self.known = False
        self.cleanup_grace_entered = False
        self.device = self.root = self.filesystem = None
        ordinary = stager.distribution_request_name(request) if label == "ordinary" else "Install.pkg"
        need(len(packages) == 1, "one-diagnostic-control-per-carrier")
        self.members = {ordinary: binding["packageBody"], "producer.json": binding["producerBody"],
                        "producer.sig": binding["signatureBody"], **packages}
        self.stage = op.work / ("fresh-" + label + "-carrier")
        self.image = op.work / ("fresh-" + label + ".dmg")
        # Ordinary owns the existing package-install mount convention.
        phase = "package-install" if label == "ordinary" else "fresh-" + label
        suffix = sha("\n".join((binding["runId"], binding["runAttempt"], TARGET, phase)).encode())[:32]
        self.mount = Path("/Volumes") / ("MRK-Install-" + suffix)

    def call(self, part, argv, seconds):
        return original_call(self.op, "carrier-" + self.label + "-" + part, argv,
            self.binding["commandEnvironment"], cwd=self.op.work, timeout=seconds,
            limit=OUTPUT_LIMIT, zero=True)

    def enter(self):
        stager = self.stager
        expected_bytes = self.binding["resourceQuote"]["carrierBytes"][self.label]
        need(sum(map(len, self.members.values())) == expected_bytes, "precut-carrier-exact-size")
        # Actual script bytes, package pair and all final readback hashes are already admitted.
        stager.write_tree(self.stage, {name: (body, 0o444) for name, body in self.members.items()})
        self.call("create", ["/usr/bin/hdiutil", "create", "-srcfolder", str(self.stage),
            "-fs", "HFS+", "-format", "UDZO", "-volname", "MRK Fresh Validation", str(self.image)], 180)
        info = self.image.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and 0 < info.st_size <= self.binding["resourceQuote"]["carrierImageLimits"][self.label],
             "precut-carrier-image-reservation")
        self.call("verify", ["/usr/bin/hdiutil", "verify", str(self.image)], 120)
        need(not self.mount.exists() and not self.mount.is_symlink(), "fresh-mount-absent")
        self.attached = True  # Record possible acquisition before dispatch, including unknown return.
        result = self.call("attach", ["/usr/bin/hdiutil", "attach", str(self.image), "-readonly",
            "-nobrowse", "-noautoopen", "-mountpoint", str(self.mount), "-plist"], 60)
        self.device = stager.distribution_mount_data(result.stdout, result.stderr, result.returncode, self.mount)
        self.root = self.book.directory(self.mount)
        self.filesystem = self.api.filesystem(self.root["fd"])
        need(self.filesystem["mountOn"] == str(self.mount) and self.filesystem["mountFrom"] == self.device
             and self.filesystem["typeName"] in ("hfs", "apfs")
             and self.filesystem["flags"] & 1 and self.filesystem["flags"] & 0x1000
             and not self.filesystem["flags"] & (0x20 | 0x400000)
             and os.fstatvfs(self.root["fd"]).f_flag & os.ST_RDONLY,
             "actual-readonly-original-mount")
        need(set(os.listdir(self.root["fd"])) == set(self.members), "fixed-carrier-roster")
        for name, expected in self.members.items():
            row = os.stat(name, dir_fd=self.root["fd"], follow_symlinks=False)
            entry, body = self.book.file(self.mount / name, stager.MAX_BYTES, uid=row.st_uid, modes=(0o444,))
            need(body == expected, "mounted-original-member")
        self.known = True
        self.post()
        return self

    def post(self):
        need(self.known and not self.detached, "mount-custody-known")
        self.book.check()
        need(self.api.filesystem(self.root["fd"]) == self.filesystem
             and set(os.listdir(self.root["fd"])) == set(self.members), "mounted-readonly-post")
        self.op.source.book.check()

    def detach(self):
        # No forced detach, mount adoption, retry or later cleanup after unknown call.
        self.post()
        # Match the ordinary package owner's one bounded PackageKit grace
        # before its first detach. The same group endpoint is never renewed;
        # actual detach0 and mount absence remain required for qualification.
        need(not self.cleanup_grace_entered
             and time.monotonic_ns() + 90 * 1_000_000_000 < self.op.fresh_deadline,
             "installer-cleanup-grace-admission")
        self.cleanup_grace_entered = True
        started = time.monotonic_ns()
        time.sleep(60)
        need(time.monotonic_ns() + 30 * 1_000_000_000 < self.op.fresh_deadline,
             "installer-cleanup-grace-settlement")
        self.post()
        self.op.outputs.publish(self.op.work / ("fresh-" + self.label + "-cleanup-grace.json"), canonical({
            "seconds": 60, "startedMonotonicNs": started, "returnedMonotonicNs": time.monotonic_ns(),
            "sameGroupDeadlineNs": self.op.fresh_deadline, "detachAttempted": False}))
        need(self.book.finish(), "mounted-original-closes")
        self.call("detach", ["/usr/bin/hdiutil", "detach", self.device], 30)
        self.detached = True
        need(not self.mount.exists() and not self.mount.is_symlink(), "original-mount-retired")
        # All mounted originals are closed and the original unforced detach
        # returned0 with absence. Later cleanup never reads these vectors.
        self.members.clear()


def initial_absence(op, binding):
    rows = []
    for parent, leaf in (("/Library/Application Support", "MobileReleaseKit"),
                         ("/Applications", "Mobile Release Kit.app")):
        entry = op.protected.directory(Path(parent))
        try:
            os.stat(leaf, dir_fd=entry["fd"], follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refused("fresh-runner-not-initially-absent")
        op.protected.check_one(entry)
        if parent == "/Library/Application Support":
            with os.scandir(entry["fd"]) as iterator:
                for count, child in enumerate(iterator, 1):
                    need(count <= 4096, "initial-support-roster-bound")
                    need(not child.name.startswith("MobileReleaseKit-InstallerResult-v2-"),
                         "fresh-runner-prior-request-export")
            op.protected.check_one(entry)
        rows.append({"parent": parent, "parentIdentity": list(entry["identity"]), "leafAbsent": leaf})
    op.outputs.publish(op.work / "initial-protected-absence.json", canonical({
        "schemaVersion": 1, "job": binding["job"], "runId": binding["runId"],
        "runAttempt": binding["runAttempt"], "jobId": binding["jobId"], "observations": rows}))


def captured_control(op, stager, binding, carrier, step, filename):
    carrier.post()
    correlation = {"kind": "fresh-disposable-control-window", "job": binding["job"],
        "step": step, "runId": binding["runId"], "runAttempt": binding["runAttempt"],
        "jobId": binding["jobId"], "packagePath": str(carrier.mount / filename),
        "packageSha256": sha(carrier.members[filename]),
        "productSource": binding["productSource"], "controlSourceSha256": binding["controlSourceSha256"]}
    cursor = log_cursor(stager, correlation)
    op.outputs.publish(op.work / (step + "-log-cursor.json"), canonical(cursor))
    original = installer_original(op, binding, step, carrier.mount / filename)
    # Only after actual original return, source POST and full capture closes.
    def preserve(selected, metadata):
        op.outputs.publish(op.work / (step + "-selected-packagekit.log"), selected)
        op.outputs.publish(op.work / (step + "-log-capture.json"), canonical(metadata))
    body, selected, metadata = log_capture(stager, cursor, correlation,
        refusal=step == "frontier-refusal", evidence_sink=preserve)
    carrier.post()
    return original, body


def snapshot_original(op, binding, role):
    need(role in ("before-ordinary-refusal", "after-ordinary-refusal"), "fixed-snapshot-role")
    root_environment = binding["rootSnapshotEnvironment"]
    need(set(root_environment) == {"PATH", "LANG", "LC_ALL", "TZ", "GITHUB_ACTIONS",
         "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "GITHUB_REPOSITORY", "GITHUB_SHA",
         "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB"}, "fixed-root-environment-roster")
    result = original_call(op, "snapshot-" + role,
        ["/usr/bin/sudo", "-n", "--", "/usr/bin/env", "-i",
         *(key + "=" + root_environment[key] for key in sorted(root_environment)),
         binding["dataPython"], "-I", "-S", "-B", str(binding["runnerSource"] / "read_torn_tree.py")],
        binding["commandEnvironment"], cwd=op.work, timeout=123, limit=OUTPUT_LIMIT, zero=True)
    # Reader reports pending until this original wait/EOF/capture-close envelope.
    value = document(result.stdout, OUTPUT_LIMIT)
    need(value.get("originalClosesKnown") is True
         and value.get("transportState") == "pending-original-process-exit", "snapshot-native-original")
    return result.stdout


def prebuilt_control_data(binding, role, fact):
    """A validated package can stay on disk instead of retaining its full vector."""
    labels = {"cut": "write", "frontier": "frontier", "completed": "completed", "recovery": "recovery"}
    need(binding["job"] in JOB_STEPS and role in labels and (role != "completed" or binding["job"] == "write-diagnostic"),
         "fixed-prebuilt-control-role")
    need(type(fact) is dict and set(fact) == {"path", "bytes", "sha256"}
         and type(fact["bytes"]) is int and 0 < fact["bytes"] <= 512 * 1024 * 1024
         and hex_value(fact["sha256"], 64)
         and fact["path"] == str(binding["inputPath"].parent / ("Fresh-" + labels[role] + ".pkg")),
         "fixed-prebuilt-control-fact")
    return fact["bytes"]


def read_prebuilt_control(op, binding, role, fact):
    """Read a new no-follow original and match the complete previously audited bytes."""
    size = prebuilt_control_data(binding, role, fact)
    entry, body = op.outputs.file(Path(fact["path"]), 512 * 1024 * 1024, modes=(0o444, 0o644))
    try:
        need(len(body) == size and sha(body) == fact["sha256"], "prebuilt-control-original-bytes")
        op.outputs.check_one(entry)
        return body
    finally:
        op.outputs.close(entry)
        need(entry["closed"], "prebuilt-control-original-close")


def route_resource_quote(binding, packages):
    """Exact prebuilt lengths; no forecast of post-cut compression is needed."""
    limit, mib = 512 * 1024 * 1024, 1024 * 1024
    required = {"cut", "frontier", "completed", "recovery"}
    need(set(packages) == required, "prebuilt-control-package-roster")
    sizes = {role: prebuilt_control_data(binding, role, fact) for role, fact in packages.items()}
    ordinary, pair = len(binding["packageBody"]), len(binding["producerBody"]) + len(binding["signatureBody"])
    inputs = sum(len(item[0]) for item in binding["inputFiles"].values())
    images = sum(len(body) for body in binding["controlBodies"].values())
    need(0 < ordinary <= limit and 0 < inputs <= limit and 0 < pair <= 65536 + 512,
         "fixed-carrier-input-bounds")
    carriers = {role: ordinary + pair + size for role, size in sizes.items() if role != "recovery"}
    carriers["ordinary"] = ordinary + pair + sizes["recovery"]
    need(all(n <= limit for n in carriers.values()), "precut-carrier-aggregate-capacity")
    # Keep the original conservative envelope, including every prebuilt package
    # size, even though those byte vectors now stay on disk until needed.
    retained = inputs + ordinary + pair + images + sum(sizes.values()) + binding.get("sourceBytes", 0)
    # Existing tree writer/readback and mount readback retain at most three
    # largest complete carrier byte windows, in addition to admitted inputs.
    # Complete original captures/receipt rows reserve64MiB (128x2x256KiB).
    memory = retained + 3 * max(carriers.values()) + 64 * mib
    need(memory <= 3 * 1024 * mib, "precut-existing-3GiB-memory-envelope")
    count = len(JOB_STEPS[binding["job"]])
    # Remaining private stage + conservative image reservation, PackageKit
    # extraction for every fixed call, installed payload, and diagnostics.
    # This is a capacity estimate, never a claim of an OS reservation.
    disk = 3 * sum(carriers.values()) + len(carriers) * 32 * mib + (count + 1) * inputs + 64 * mib
    return {"memoryBytes": memory, "diskBytes": disk, "carrierBytes": carriers,
        "carrierImageLimits": {role: 2 * size + 32 * mib for role, size in carriers.items()},
        "inputBytes": inputs, "retainedByteVectors": retained,
        "outputCaptureBytes": 64 * mib, "maxOriginalCalls": 128,
        "postCutPackageBuilds": 0, "installerCalls": count,
        "capacityIsReservation": False}


class GroupClock:
    def __init__(self, op):
        self.op = op

    def check(self):
        need(time.monotonic_ns() < self.op.fresh_deadline, "fresh-group-deadline")


def resource_capacity(op, host_api, binding, quote, *, label="route"):
    """Same actual host facts/parsers and process owner; no new controller."""
    import resource
    data = binding["resourceModule"]
    clock = GroupClock(op)
    need(type(quote["memoryBytes"]) is int and 0 < quote["memoryBytes"] <= 3 * 1024 * 1024 * 1024,
         "existing-3GiB-memory-envelope")
    result = original_call(op, "precut-resource-memory-" + label, ["/usr/bin/vm_stat"],
        binding["commandEnvironment"], cwd=op.work, timeout=10, limit=65536, zero=True)
    page, physical = data.host_memory_data(host_api, clock)
    memory = data.memory_data(result.stdout, result.stderr, result.returncode,
        page_size=page, physical_bytes=physical)
    work = op.outputs.directory(op.work)
    disk = os.fstatvfs(work["fd"])
    facts = data.resource_admission_data(memory["availableEstimateBytes"], quote["memoryBytes"],
        disk.f_frsize * disk.f_bavail, quote["diskBytes"])
    live = sum(row["fd"] is not None for book in (op.outputs, op.protected, op.source.book)
               for row in book.entries)
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    op.outputs.publish(op.work / ("precut-resource-observation-" + label + ".json"), canonical({
        "quote": quote, "observed": facts, "liveOriginals": live,
        "softFDLimit": soft, "originalReserve": 64, "admitted": False}))
    need((soft == resource.RLIM_INFINITY or live + 64 <= soft)
         and facts["memorySufficient"] and facts["diskSufficient"], "precut-actual-capacity")
    op.outputs.publish(op.work / ("precut-resource-admission-" + label + ".json"), canonical({
        "quote": quote, "observed": facts, "liveOriginals": live, "originalReserve": 64}))
    op.source.book.check()
    return facts


def execute_job(op, stager, host_api, binding):
    """Concrete fixed sequence after the separate final input/host admission."""
    need(EXECUTION_BINDING is not None and binding["job"] in JOB_STEPS, "source-preparation-only")
    need(binding["productSource"] == PRODUCT["source"] and binding["productTree"] == PRODUCT["tree"],
         "exact-final-product")
    need(type(op.fresh_deadline) is int and time.monotonic_ns() < op.fresh_deadline,
         "pre-admitted-group-deadline")
    op.fresh_carriers = []
    need(binding["inputPath"] == op.work / "input", "existing-stager-input-parent")
    initial_absence(op, binding)
    cut_role = "write" if binding["job"] == "write-diagnostic" else "torn"
    _, cut_package = build_control(op, stager, binding, cut_role)
    _, frontier_package = build_control(op, stager, binding, "frontier")
    packages = {"cut": cut_package, "frontier": frontier_package}
    if cut_role == "write":
        _, packages["completed"] = build_control(op, stager, binding, "completed")
        _, packages["recovery"] = build_control(op, stager, binding, "recovery", binding["ordinaryRequestId"])
    quote = route_resource_quote(binding, packages)
    resource_capacity(op, host_api, binding, quote)
    binding["resourceQuote"] = quote
    request = binding["ordinaryRequestId"]
    cut_carrier = Carrier(op, stager, host_api, binding, "cut",
                          {"Fresh-" + cut_role + ".pkg": read_prebuilt_control(op, binding, "cut", cut_package)}, request).enter()
    original, body = captured_control(op, stager, binding, cut_carrier, cut_role, "Fresh-" + cut_role + ".pkg")
    cut = cut_data(body, binding, cut_role, original.returncode)
    op.outputs.publish(op.work / "controlled-original-failure.json", body)
    cut_carrier.detach()
    frontier_role = "frontier" if cut_role == "write" else "frontier-refusal"
    name = frontier_name(cut["invocation"])
    frontier_carrier = Carrier(op, stager, host_api, binding, "frontier",
        {name: read_prebuilt_control(op, binding, "frontier", frontier_package)}, request).enter()
    original, body = captured_control(op, stager, binding, frontier_carrier, frontier_role, name)
    if cut_role == "write":
        frontier = frontier_data(body, binding, cut["invocation"], original.returncode)
        op.outputs.publish(op.work / "interrupted-frontier.json", body)
    else:
        need(type(original.returncode) is int and 1 <= original.returncode <= 255 and body is None,
             "torn-frontier-original-refusal")
    frontier_carrier.detach()
    if cut_role == "torn":
        before = snapshot_original(op, binding, "before-ordinary-refusal")
    ordinary_carrier = Carrier(op, stager, host_api, binding, "ordinary",
        {"Fresh-recovery.pkg": read_prebuilt_control(op, binding, "recovery", packages["recovery"])}, request).enter()
    ordinary_step = "diagnostic-recovery"
    ordinary_path = ordinary_carrier.mount / stager.distribution_request_name(request)
    args = argparse.Namespace(target=TARGET, fixture=False, input=binding["inputPath"],
        expected_source=binding["productSource"], expected_inventory=binding["inventorySha256"],
        expected_manifest=binding["runtimeManifestSha256"], request_id=request,
        expected_package=binding["package"]["sha256"], producer_descriptor=ordinary_carrier.mount / "producer.json",
        producer_signature=ordinary_carrier.mount / "producer.sig", package=ordinary_path,
        run_id=binding["runId"], run_attempt=binding["runAttempt"])
    stager.installer_result_absent_command(args)
    ordinary_carrier.post()
    diagnostic_path = ordinary_carrier.mount / "Fresh-recovery.pkg"
    correlation = diagnostic_recovery_correlation(binding, diagnostic_path, packages["recovery"])
    diagnostic_cursor = log_cursor(stager, correlation)
    op.outputs.publish(op.work / "diagnostic-recovery-log-cursor.json", canonical(diagnostic_cursor))
    original = installer_original(op, binding, ordinary_step, diagnostic_path)
    diagnostic_log_finish(op, stager, diagnostic_cursor, correlation)
    ordinary_carrier.post()
    if cut_role == "write":
        observed = publish_diagnostic_installation_observation(op, stager, binding, args, original)
        ordinary_carrier.detach()
        completed_carrier = Carrier(op, stager, host_api, binding, "completed",
            {"Fresh-completed.pkg": read_prebuilt_control(op, binding, "completed", packages["completed"])}, request).enter()
        completed_original, completed_body = captured_control(op, stager, binding, completed_carrier,
                                                              "completed", "Fresh-completed.pkg")
        outcome = completed_data(completed_body, binding, frontier, observed, completed_original.returncode)
        op.outputs.publish(op.work / "completed-conservation.json", completed_body)
        completed_carrier.detach()
    else:
        need(type(original.returncode) is int and 1 <= original.returncode <= 255, "ordinary-torn-refusal-required")
        after = snapshot_original(op, binding, "after-ordinary-refusal")
        outcome = compare_torn(before, after, binding, cut)
        ordinary_carrier.detach()
    actual = [row["role"].removeprefix("install-") for row in op.calls if row["role"].startswith("install-")]
    need(actual == list(JOB_STEPS[binding["job"]]), "exact-four-diagnostic-Installer-route")
    op.outputs.publish(op.work / "fresh-validation-outcome.json", canonical(outcome))
    return outcome


TORN_REASON_SHA256 = "d485a2bd231b54851f34d5b7c27724736a565a0a742952b688874f672ec82ed7"
TORN_COMPLETED_MARKER = (
    "MRK_MACOS_INSTALL_COMPLETED_REFUSED=reasonSha256=" + TORN_REASON_SHA256
    + ";exit=1;originals=1;native=1;timely=1;unknown=0"
).encode("ascii")


def diagnostic_recovery_correlation(binding, package_path, package):
    need(binding["job"] == "write-diagnostic", "fixed-diagnostic-job")
    return {"kind": "nonshipping-inventory-recovery-window", "packageKind": "ordinary",
        "job": binding["job"], "step": "diagnostic-recovery", "runId": binding["runId"],
        "runAttempt": binding["runAttempt"], "packageIdentifier": CONTROL_IDS["recovery"],
        "packagePath": str(package_path), "diagnosticPackageSha256": package["sha256"],
        "completedPackageSha256": binding["package"]["sha256"]}


def diagnostic_native_lines(stager, body):
    need(type(body) is bytes and len(body) <= stager.LOG_INTERVAL_BYTES
         and (not body or body.endswith(b"\n")), "diagnostic-window-bound")
    selected = []
    for line in body.splitlines(keepends=True):
        need(line.endswith(b"\n") and len(line) <= stager.LOG_LINE_BYTES, "diagnostic-line-bound")
        if b"MRK_RECOVERY_DIAGNOSTIC=" in line or b"MRK_MACOS_INSTALL_COMPLETED_REFUSED=" in line:
            selected.append(line)
    retained = b"".join(selected)
    need(len(selected) <= 4 and len(retained) <= stager.LOG_SELECTED_BYTES, "diagnostic-native-projection-bound")
    return retained


def publish_diagnostic_log(op, stager, body, correlation, cursor, growth):
    # Preserve the bounded native failure bytes and original-window identity
    # before any semantic parser can fail. These bytes carry no success authority.
    native = diagnostic_native_lines(stager, body)
    op.outputs.publish(op.work / "diagnostic-recovery-native-context.log", native)
    facts = {"binding": correlation, "cursorSha256": sha(canonical(cursor)),
        "intervalBytes": len(body), "intervalSha256": sha(body),
        "nativeBytes": len(native), "nativeSha256": sha(native),
        "growthBeyondSnapshotBytes": growth, "authority": stager.LOG_AUTHORITY,
        "diagnosticOnly": True, "originalInstallerRequiredSeparately": True}
    op.outputs.publish(op.work / "diagnostic-recovery-window-facts.json", canonical(facts))
    selected, selection = stager.select_installer_log(body, correlation)
    need(len(selected) <= stager.LOG_SELECTED_BYTES, "diagnostic-log-selection-bound")
    op.outputs.publish(op.work / "diagnostic-recovery-selected-packagekit.log", selected)
    op.outputs.publish(op.work / "diagnostic-recovery-log-capture.json", canonical(dict(facts,
        selectedBytes=len(selected), selectedSha256=sha(selected), selection=selection)))


def diagnostic_log_finish(op, stager, cursor, correlation):
    stager.validate_log_cursor(cursor, correlation)
    with stager.installer_log_file() as (fd, outer, name, info):
        identity = stager.installer_log_identity(info)
        need(identity == cursor["identity"], "log-original-identity")
        start, end = cursor["offsetBytes"], info.st_size
        need(start <= end <= start + stager.LOG_INTERVAL_BYTES, "log-interval-bound")
        anchor = stager.positioned_log_read(fd, start - cursor["precedingTailBytes"], cursor["precedingTailBytes"])
        body = stager.positioned_log_read(fd, start, end - start)
        stager.validate_log_window(cursor, identity, end, anchor, body)
        need(stager.positioned_log_read(fd, start - len(anchor), len(anchor)) == anchor, "log-anchor-post")
        growth = stager.log_growth(fd, outer, name, identity, end)
    publish_diagnostic_log(op, stager, body, correlation, cursor, growth)


def ordinary_log_begin(op, stager, args):
    args.command = "installer-log-cursor"
    args.cursor = None
    args.selected_output = None
    value, code = stager.installer_log_diagnostic(args)
    need(code == 0, "ordinary-fixed-log-cursor")
    path = op.work / "ordinary-log-cursor.json"
    op.outputs.publish(path, stager.canonical(value) + b"\n")
    return path


def torn_parent_refusal_data(body):
    need(type(body) is bytes, "torn-parent-log-bytes")
    # Require a complete LF/CRLF line. A lookahead for newline followed by $
    # incorrectly requires the following log line to be empty or EOF.
    marker = re.compile(rb"(?<![A-Za-z0-9_])" + re.escape(TORN_COMPLETED_MARKER) + rb"(?=\r?\n)", re.M)
    need(len(marker.findall(body)) == 1
         and body.count(b"MRK_MACOS_INSTALL_COMPLETED_REFUSED=") == 1
         and b"MRK_MACOS_INSTALL_RESULT=" not in body, "exact-torn-parent-refusal")
    return True


def ordinary_log_finish(op, stager, args, cursor, *, torn):
    args.command = "installer-log-capture"
    args.cursor = cursor
    args.selected_output = op.work / "ordinary-selected-packagekit.log"
    value, code = stager.installer_log_diagnostic(args)
    op.outputs.publish(op.work / "ordinary-log-capture.json", stager.canonical(value) + b"\n")
    op.outputs.publish(op.work / "ordinary-log-capture.status", (str(code) + "\n").encode())
    need(code == 0, "ordinary-complete-scoped-log-capture")
    body = stager.read(args.selected_output, stager.LOG_SELECTED_BYTES)
    need(value["selectedData"]["bytes"] == len(body) and value["selectedData"]["sha256"] == sha(body),
         "ordinary-selected-log-binding")
    if torn:
        torn_parent_refusal_data(body)
    return value


def settle_job(op, stager, host_api, binding):
    """Close only this operation's originals and known owned mounts; no installed cleanup."""
    outcome, failure = None, None
    try:
        outcome = execute_job(op, stager, host_api, binding)
    except BaseException as error:
        failure = error
    finality = all(row.get("returned") is True and row.get("capturesSettled") is True for row in op.calls)
    cleanup_errors = []
    for carrier in reversed(getattr(op, "fresh_carriers", ())):
        if carrier.detached:
            continue
        if finality and carrier.known:
            try:
                carrier.detach()
            except BaseException:
                cleanup_errors.append("owned-mount-detach-unknown")
                finality = False
        elif carrier.attached:
            cleanup_errors.append("entered-mount-retained-unknown")
        # Even a pure admission failure cannot leave our known descriptors unclosed.
        if not carrier.book.finish():
            cleanup_errors.append("mount-read-original-close-unknown")
    for book in (op.protected, op.outputs, op.source.book):
        if not book.finish():
            cleanup_errors.append("owned-original-close-unknown")
    passed = failure is None and finality and not cleanup_errors
    receipt = {"schemaVersion": 1, "scope": "nonshipping-inventory-recovery-diagnostic-originals",
        "diagnosticOnly": True, "ordinaryInstallationQualified": False, "freshRecoveryQualified": False,
        "passed": passed, "outcome": outcome, "originalClosesKnown": finality and not cleanup_errors,
        "ownedMountsDetached": all(c.detached for c in getattr(op, "fresh_carriers", ())),
        "calls": op.calls, "cleanFreshQualified": False,
        "firstFailureType": None if failure is None else type(failure).__name__,
        "firstFailureReason": str(failure) if isinstance(failure, Refused) else None,
        "cleanupErrors": cleanup_errors,
        "transportState": "pending-original-process-exit",
        "diagnosticInstallationObservationExplicitlyExported": outcome is not None and binding["job"] == "write-diagnostic"}
    # Preserve actual failed originals and cleanup uncertainty, too. The final
    # publisher is separate from already consumed source/mount/capture books;
    # its own close and this driver's actual return remain caller requirements.
    writer = type(op.outputs)()
    try:
        writer.publish(op.work / "fresh-validation-finality.json", canonical(receipt))
    except BaseException as error:
        op.fresh_receipt_attempt = receipt
        if failure is not None:
            raise error from failure
        raise
    finally:
        need(writer.finish(), "final-receipt-original-close-unknown")
    return receipt


def source_plan():
    return {"schemaVersion": 1, "scope": "nonshipping-inventory-recovery-diagnostic-preparation",
        "executionEnabled": False, "jobs": JOB_STEPS, "installerOriginalCount": 4,
        "signedPayload": PRODUCT, "controlImages": ("census", "write", "recovery"),
        "diagnosticOnly": True, "ordinaryInstallationQualified": False, "freshRecoveryQualified": False,
        "packageBuildsAfterFirstCut": 0, "appBuildCount": 0, "producerPairRegenerated": False,
        "tornCaseReplayed": False, "ownerMachineEffects": False,
        "explicitEvidence": "diagnostic-installation-observation.json"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", action="store_true")
    args = parser.parse_args()
    if args.plan:
        print(json.dumps(source_plan(), sort_keys=True))
        return 0
    need(EXECUTION_BINDING is not None, "source-preparation-only")
    raise Refused("final-input-and-entry-adapter-not-yet-bound")


if __name__ == "__main__":
    raise SystemExit(main())

