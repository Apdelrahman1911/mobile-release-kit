"""One disabled hosted correspondence diagnostic using existing Fresh ownership.

The retained source functions are copied from reviewed v8. This module has one
control and one Installer invocation, no ordinary replay, recovery, or cleanup.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import xml.etree.ElementTree as ET

EXECUTION_BINDING = None
TARGET = "aarch64-apple-darwin"
JOB_STEPS = {"correspondence-diagnostic": ("diagnostic",)}
CONTROL_ROLE = {"diagnostic": "diagnostic"}
CONTROL_IDS = {"diagnostic": "dev.mobile-release-kit.disposable-correspondence.diagnostic"}
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
    need(role == "diagnostic" and invocation is None, "one-diagnostic-control")
    label = role
    image_role = CONTROL_ROLE[role]
    scripts = op.work / ("fresh-" + label + "-scripts")
    original = op.work / ("fresh-" + label + "-original.pkg")
    parts = op.work / ("fresh-" + label + "-parts")
    final = op.work / ("Correspondence-" + label + ".pkg")
    files = {"postinstall": (binding["scriptBodies"]["diagnostic-postinstall"], 0o555),
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
    return final, raw


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
    need(step == "diagnostic" and binding["job"] == "correspondence-diagnostic"
         and not getattr(op, "diagnostic_installer_entered", False), "fixed-installer-step")
    op.diagnostic_installer_entered = True
    # No PackageKit PID discovery/adoption; same existing owner and root transition.
    return original_call(op, "install-" + step,
        ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer", "-dumplog",
         "-pkg", str(package), "-target", "/"], binding["commandEnvironment"],
        cwd=op.work, timeout=123, limit=OUTPUT_LIMIT, zero=False)


def log_cursor(stager, binding):
    with stager.installer_log_file() as (fd, outer, name, info):
        identity = stager.installer_log_identity(info)
        size = min(info.st_size, stager.LOG_TAIL_BYTES)
        tail = stager.positioned_log_read(fd, info.st_size - size, size)
        need(stager.positioned_log_read(fd, info.st_size - size, size) == tail, "log-anchor-post")
        growth = stager.log_growth(fd, outer, name, identity, info.st_size)
        return stager.make_log_cursor(binding, identity, info.st_size, tail, growth)


class Carrier:
    """One package invocation per read-only carrier; existing Originals custody."""
    def __init__(self, op, stager, host_api, binding, label, packages, request):
        need(label == "diagnostic" and hex_value(request, 32), "fixed-carrier-role")
        self.op, self.stager, self.api = op, stager, host_api
        op.fresh_carriers.append(self)
        self.label, self.binding, self.request = label, binding, request
        self.book = type(op.protected)()
        self.attached = self.detached = self.known = False
        self.device = self.root = self.filesystem = None
        ordinary = "Install.pkg"
        need(set(packages) == {"Correspondence-diagnostic.pkg"}, "one-control-per-carrier")
        self.members = {ordinary: binding["packageBody"], "producer.json": binding["producerBody"],
                        "producer.sig": binding["signatureBody"], **packages}
        self.stage = op.work / ("fresh-" + label + "-carrier")
        self.image = op.work / ("fresh-" + label + ".dmg")
        # Ordinary owns the existing package-install mount convention.
        phase = "correspondence-diagnostic"
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
            "-fs", "HFS+", "-format", "UDZO", "-volname", "MRK Correspondence Diagnostic", str(self.image)], 180)
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
        need(self.book.finish(), "mounted-original-closes")
        self.call("detach", ["/usr/bin/hdiutil", "detach", self.device], 30)
        self.detached = True
        need(not self.mount.exists() and not self.mount.is_symlink(), "original-mount-retired")


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
    need((soft == resource.RLIM_INFINITY or live + 64 <= soft)
         and facts["memorySufficient"] and facts["diskSufficient"], "precut-actual-capacity")
    op.outputs.publish(op.work / ("precut-resource-admission-" + label + ".json"), canonical({
        "quote": quote, "observed": facts, "liveOriginals": live, "originalReserve": 64}))
    op.source.book.check()
    return facts



# Native owns the closed schema. It must be bound in reviewed SOURCE, never an
# input-selected regular expression, before this route can be enabled.
CONTEXT_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_CORRESPONDENCE_DIAGNOSTIC=origin=(parent|writer-ready-frame|writer-result-frame)"
    rb";basis=first-observed;site=([0-9]{1,6});pass=([12]);role=([0-9]);original=([0-9]{1,6});parent=([0-9]{1,10})"
    rb";category=([0-9]{1,2});exact=([01]);heldNamed=([0-9]{1,4});heldExpected=([0-9]{1,4})(?=\r?\n$)")
UNAVAILABLE_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_CORRESPONDENCE_DIAGNOSTIC_UNAVAILABLE=origin=writer;basis=no-valid-decoded-hint(?=\r?\n$)")
COMPLETED_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_COMPLETED_REFUSED=reasonSha256=([0-9a-f]{64});exit=(1|20)"
    rb";originals=([01]);native=([01]);timely=([01]);unknown=([01])(?=\r?\n$)")
CORRESPONDENCE_REASON = "cc10c846c8aba5450a52fed5eb86f7b09f543e8d8048249b18be7fbdcf6bdc32"


def prefix_resource_quote(binding):
    """Conservative simultaneous DATA allocations, not an observed RSS claim."""
    facts = binding["preparedInputFacts"]
    package = binding["package"]["bytes"]
    original = binding["preparedMembers"]["MobileReleaseKit-original.pkg"]["bytes"]
    sources = sum(pin["bytes"] for group in binding["sourceFiles"].values() for pin in group.values())
    controls = sum(row["bytes"] for row in binding["controls"].values())
    scripts, inventory = facts["expandedScriptsBytes"], facts["inventoryBytes"]
    need(package == 126981541 and original == 126997145
         and scripts == 350208512 and inventory == 1402721
         and facts["inputFileBytes"] == 344923571, "diagnostic-prepared-actual-sizes")
    # Existing full-audit bound, plus two package windows for the retained
    # final body and producer-root readback. prefix_inputs aliases those bodies;
    # a later independent reader may overlap until the old vectors are retired.
    memory = 3 * (package + original) + 4 * scripts + 2 * inventory + 2 * package + sources + controls + 64 * 1024 * 1024
    disk = 2 * (package + original) + scripts + inventory + 2 * package + 4 * 1024 * 1024 * 1024
    need(memory <= 3 * 1024 * 1024 * 1024, "diagnostic-prefix-allocation-envelope")
    return {"memoryBytes": memory, "diskBytes": disk,
        "packageBytes": package, "originalPackageBytes": original,
        "expandedScriptsBytes": scripts, "producerPackageWindows": 2,
        "prefixInputsAliasBodies": True, "compilerDiskReserveBytes": 4 * 1024 * 1024 * 1024,
        "observedRssEnforcement": False}


def diagnostic_resource_quote(binding, control):
    package, pair = len(binding["packageBody"]), len(binding["producerBody"]) + len(binding["signatureBody"])
    inputs = sum(len(value[0]) for value in binding["inputFiles"].values())
    images = sum(map(len, binding["controlBodies"].values()))
    carrier = package + pair + len(control)
    retained = binding["sourceBytes"] + package + pair + inputs + images + len(control)
    memory = retained + 3 * carrier + 64 * 1024 * 1024
    need(package == binding["package"]["bytes"] and inputs == binding["preparedInputFacts"]["inputFileBytes"]
         and carrier <= 512 * 1024 * 1024 and memory <= 3 * 1024 * 1024 * 1024,
         "diagnostic-actual-allocation-envelope")
    return {"memoryBytes": memory, "diskBytes": 3 * carrier + inputs + 64 * 1024 * 1024,
        "carrierBytes": {"diagnostic": carrier},
        "carrierImageLimits": {"diagnostic": 2 * carrier + 32 * 1024 * 1024},
        "installerCalls": 1, "ordinaryInstallerCalls": 0, "applicationBuilds": 0,
        "observedRssEnforcement": False}


def parse_diagnostic_lines(body, *, line_limit, selected_limit, valid_sites):
    selected, contexts, completed, unavailable, origins = [], [], [], [], set()
    for line in body.splitlines(keepends=True):
        need(line.endswith(b"\n") and len(line) <= line_limit, "log-line-bound")
        if b"MRK_MACOS_INSTALL_CORRESPONDENCE_DIAGNOSTIC=" in line:
            match = CONTEXT_PATTERN.search(line)
            need(match is not None and len(contexts) < 2, "bounded-native-context")
            origin, *fields = match.groups()
            site, check_pass, role, original, parent, category, exact, named, expected = map(int, fields)
            family = "parent" if origin == b"parent" else "writer"
            need(family not in origins and not (family == "writer" and unavailable)
                 and site in valid_sites and 0 < site < 600000 and site % 100000 != 0
                 and original < 196608 and (parent < 196608 or parent == 4294967295)
                 and category <= 15 and named <= 4095 and expected <= 4095
                 and (named != 0 or (expected != 0 if exact else expected & 55 != 0)),
                 "native-context-fields")
            origins.add(family)
            contexts.append({"origin": origin.decode("ascii"), "basis": "first-observed",
                "site": site, "pass": check_pass, "role": role, "original": original,
                "parent": parent, "category": category, "exact": exact,
                "heldNamed": named, "heldExpected": expected})
            selected.append(line)
        if b"MRK_MACOS_INSTALL_CORRESPONDENCE_DIAGNOSTIC_UNAVAILABLE=" in line:
            need(UNAVAILABLE_PATTERN.search(line) is not None and not unavailable and "writer" not in origins,
                 "writer-hint-unavailable-once")
            unavailable.append({"origin": "writer", "basis": "no-valid-decoded-hint"})
            selected.append(line)
        if b"MRK_MACOS_INSTALL_COMPLETED_REFUSED=" in line:
            match = COMPLETED_PATTERN.search(line)
            need(match is not None and not completed, "one-completed-parent-original")
            reason, exit_code, originals, native, timely, unknown = match.groups()
            completed.append({"reasonSha256": reason.decode("ascii"), "exit": int(exit_code),
                "originals": originals == b"1", "native": native == b"1",
                "timely": timely == b"1", "unknown": unknown == b"1"})
            selected.append(line)
    retained = b"".join(selected)
    need(len(retained) <= selected_limit, "diagnostic-log-selection-bound")
    need(not contexts and not unavailable or len(completed) == 1, "context-existing-failure-gate")
    need(not any(row["origin"] == "parent" for row in contexts)
         or completed[0]["reasonSha256"] == CORRESPONDENCE_REASON, "parent-primary-correspondence")
    return {"contexts": contexts, "completed": completed, "unavailable": unavailable}, retained


def unqualified_marker_data(body):
    """Preserve bounded marker suffixes before strict decoding can refuse."""
    prefix = b"MRK_MACOS_INSTALL_"
    names = (b"CORRESPONDENCE_DIAGNOSTIC=", b"CORRESPONDENCE_DIAGNOSTIC_UNAVAILABLE=", b"COMPLETED_REFUSED=")
    rows, count, truncated = [], 0, False
    for line in body.splitlines(keepends=True):
        positions = [line.find(prefix + name) for name in names if prefix + name in line]
        if not positions:
            continue
        count += 1
        raw = line[min(positions):]
        if len(rows) < 16:
            rows.append(raw[:512])
        truncated = truncated or len(raw) > 512 or count > 16
    retained = b"".join(rows)
    return retained, {"qualified": False, "markerLinesObserved": count,
        "markerLinesRetained": len(rows), "truncated": truncated,
        "bytes": len(retained), "sha256": sha(retained)}


def diagnostic_log_capture(op, stager, cursor, correlation, valid_sites):
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
    raw, raw_metadata = unqualified_marker_data(body)
    op.outputs.publish(op.work / "diagnostic-unqualified-markers.log", raw)
    op.outputs.publish(op.work / "diagnostic-unqualified-markers.json", canonical(raw_metadata))
    try:
        parsed, retained = parse_diagnostic_lines(body, line_limit=stager.LOG_LINE_BYTES,
            selected_limit=stager.LOG_SELECTED_BYTES, valid_sites=valid_sites)
        validation_error = None
    except Refused as error:
        parsed, retained, validation_error = {"contexts": [], "completed": [], "unavailable": []}, b"", str(error)
    return {**parsed, "validationError": validation_error,
        "log": {"schemaVersion": 1, "binding": correlation,
            "cursorSha256": sha(canonical(cursor)), "intervalBytes": len(body), "intervalSha256": sha(body),
            "selectedBytes": len(retained), "selectedSha256": sha(retained),
            "growthBeyondSnapshotBytes": growth, "authority": stager.LOG_AUTHORITY,
            "originalInstallerRequiredSeparately": True}}, retained


def execute_job(op, stager, host_api, binding):
    need(EXECUTION_BINDING is not None and CONTEXT_PATTERN is not None
         and binding["job"] == "correspondence-diagnostic", "one-reviewed-diagnostic")
    op.fresh_carriers = []
    op.diagnostic_installer_entered = False
    op.diagnostic_native_closure_observed = False
    initial_absence(op, binding)
    _, control = build_control(op, stager, binding, "diagnostic")
    quote = diagnostic_resource_quote(binding, control)
    binding["resourceQuote"] = quote
    resource_capacity(op, host_api, binding, quote)
    carrier = Carrier(op, stager, host_api, binding, "diagnostic",
        {"Correspondence-diagnostic.pkg": control}, binding["ordinaryRequestId"]).enter()
    correlation = {"kind": "correspondence-diagnostic-packagekit-window", "job": binding["job"],
        "runId": binding["runId"], "runAttempt": binding["runAttempt"],
        "packagePath": str(carrier.mount / "Correspondence-diagnostic.pkg"),
        "packageSha256": sha(control), "completedPackageSha256": binding["package"]["sha256"],
        "productSource": binding["productSource"], "controlSourceSha256": binding["controlSourceSha256"]}
    carrier.post()
    cursor = log_cursor(stager, correlation)
    op.outputs.publish(op.work / "diagnostic-log-cursor.json", canonical(cursor))
    original = installer_original(op, binding, "diagnostic", carrier.mount / "Correspondence-diagnostic.pkg")
    captured, selected = diagnostic_log_capture(op, stager, cursor, correlation, binding["diagnosticSites"])
    op.outputs.publish(op.work / "diagnostic-selected-packagekit.log", selected)
    op.outputs.publish(op.work / "diagnostic-log-capture.json", canonical(captured))
    carrier.post()
    completed = captured["completed"]
    op.diagnostic_native_closure_observed = (original.returncode == 0 or len(completed) == 1
        and all(completed[0][key] for key in ("originals", "native", "timely")) and not completed[0]["unknown"])
    same = len(completed) == 1 and completed[0]["reasonSha256"] == CORRESPONDENCE_REASON
    qualified = captured["validationError"] is None and (not same or bool(captured["contexts"]))
    return {"installerReturncode": original.returncode, "sameFailureReproduced": same,
        "contexts": captured["contexts"], "completed": completed, "unavailable": captured["unavailable"],
        "collectionQualified": qualified, "validationError": captured["validationError"],
        "ordinaryInstallerReplayed": False, "applicationRebuilt": False,
        "installationQualified": False, "mutationAbsentClaimed": False,
        "nativeClosureObserved": op.diagnostic_native_closure_observed}


def settle_job(op, stager, host_api, binding):
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
        inner_known = (not getattr(op, "diagnostic_installer_entered", False)
                       or getattr(op, "diagnostic_native_closure_observed", False))
        if finality and carrier.known and inner_known:
            try:
                carrier.detach()
            except BaseException:
                cleanup_errors.append("owned-mount-detach-unknown")
                finality = False
        elif carrier.attached:
            cleanup_errors.append("entered-mount-retained-unknown")
        if not carrier.book.finish():
            cleanup_errors.append("mount-read-original-close-unknown")
    for book in (op.protected, op.outputs, op.source.book):
        if not book.finish():
            cleanup_errors.append("owned-original-close-unknown")
    endpoint_met = time.monotonic_ns() < op.fresh_deadline
    receipt = {"schemaVersion": 1, "scope": "one-correspondence-diagnostic-originals",
        "passed": failure is None and finality and not cleanup_errors and endpoint_met
            and outcome is not None and outcome["collectionQualified"],
        "outcome": outcome, "originalClosesKnown": finality and not cleanup_errors,
        "originalGroupEndpointMet": endpoint_met,
        "ownedMountsDetached": all(c.detached for c in getattr(op, "fresh_carriers", ())),
        "calls": op.calls, "ordinaryInstallationQualified": False, "cleanFreshQualified": False,
        "firstFailureType": None if failure is None else type(failure).__name__,
        "firstFailureReason": str(failure) if isinstance(failure, Refused) else None,
        "cleanupErrors": cleanup_errors, "transportState": "pending-original-process-exit"}
    writer = type(op.outputs)()
    try:
        writer.publish(op.work / "correspondence-diagnostic-finality.json", canonical(receipt))
    finally:
        need(writer.finish(), "final-receipt-original-close-unknown")
    return receipt


PRODUCER_SOURCE_ROOTS = (
    "desktop/src-tauri", "desktop/native", "desktop/catalogues", "desktop/vendor",
    "desktop/macos-installed-inputs", "desktop/packaging", "desktop/rust-toolchain.toml", "templates/workflows",
)


def producer_source_snapshot(op, binding, e2, root, phase):
    """Finite streamed compiler provenance, separate from live interpreter FDs."""
    need(phase in ("before", "after"), "producer-source-fixed-phase")
    original = original_call(op, "producer-source-roster-" + phase,
        ["/usr/bin/git", "--no-optional-locks", "ls-tree", "-r", "-z", "HEAD", "--", *PRODUCER_SOURCE_ROOTS],
        binding["commandEnvironment"], cwd=root, timeout=15, limit=2 * 1024 * 1024, zero=True)
    need(not original.stderr and original.stdout.endswith(b"\0"), "producer-source-git-roster")
    rows = original.stdout.split(b"\0")[:-1]
    need(0 < len(rows) <= 1800, "producer-source-file-count")
    quote = binding["producerSourceQuote"]
    need(sha(original.stdout) == quote["gitRosterSha256"] and len(rows) == quote["trackedFiles"],
         "exact-frozen-producer-source-roster")
    paths = [root / row.split(b"\t", 1)[1].decode("utf-8", "strict") for row in rows]
    parents = {parent for path in paths for parent in path.parents}
    need(len(set(paths)) == len(paths) and len(paths) + len(parents) <= 2048,
         "producer-source-existing-owner-slots")
    need(len(parents) == quote["absoluteParentSlots"]
         and len(paths) + len(parents) == quote["cumulativeRegisteredSlots"], "exact-producer-slot-quote")
    import resource
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    live = sum(row["fd"] is not None for book in (op.outputs, op.protected, op.source.book) for row in book.entries)
    need(soft == resource.RLIM_INFINITY or live + len(parents) + 8 <= soft,
         "producer-source-existing-descriptor-capacity")
    book, observed, total = e2.Originals(), [], 0
    try:
        for raw in rows:
            GroupClock(op).check()
            header, relative = raw.split(b"\t", 1)
            mode, kind, blob = header.split(b" ")
            name = relative.decode("utf-8", "strict")
            need(kind == b"blob" and mode in (b"100644", b"100755")
                 and any(name == start or name.startswith(start + "/") for start in PRODUCER_SOURCE_ROOTS)
                 and all(part not in ("", ".", "..") for part in name.split("/")), "producer-source-fixed-entry")
            entry, body = book.file(root / name, 32 * 1024 * 1024,
                modes=(0o755 if mode == b"100755" else 0o644,))
            total += len(body)
            need(total <= 128 * 1024 * 1024
                 and hashlib.sha1(b"blob " + str(len(body)).encode("ascii") + b"\0" + body).hexdigest().encode("ascii") == blob,
                 "producer-source-original-git-bytes")
            observed.append({"path": name, "gitMode": mode.decode("ascii"), "blob": blob.decode("ascii"),
                "bytes": len(body), "sha256": sha(body), "identity": list(entry["identity"])})
            book.close(entry)
            need(entry["closed"], "producer-source-original-close")
            del body
        book.check()
        need(total == quote["sourceBytes"], "exact-producer-source-bytes")
    finally:
        need(book.finish(), "producer-source-snapshot-closes")
    value = {"schemaVersion": 1, "scope": "frozen-producer-compiler-inputs", "productSource": binding["productSource"],
        "productTree": binding["productTree"], "files": observed, "bytes": total,
        "retainedFileDescriptors": 0, "originalRosterReturncode": original.returncode,
        "applicationBuildClaimed": False}
    op.outputs.publish(op.work / ("producer-source-" + phase + ".json"), canonical(value))
    return value
