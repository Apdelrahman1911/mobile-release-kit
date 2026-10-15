"""SOURCE-nominated two-generation update, using the existing packaging owner.

No command runner, credential owner, arbitrary URL or historical status authority.
The checked-in nomination is deliberately unconfigured. Qualification/enrollment
and actual pair resource/path admission precede activation, not merely hashes.
"""
import argparse
import hashlib
import json
import os
import pwd
from pathlib import Path
import stat

REF = "refs/heads/verify/desktop-macos-positive-update"
PHASE = "update-baseline"
ROLES = ("update-baseline-attach", "update-baseline-installer", "update-baseline-detach")
TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin")
NOMINATION = "desktop/macos-installed-inputs/update-predecessors.json"
REPOSITORY = "Apdelrahman1911/mobile-release-kit"
LIMIT = 512 * 1024 * 1024
RECORD_LIMIT = 16384
SENTINEL = b"MobileReleaseKit public update preservation fixture v1\n"
IDENTIFIER = "dev.mobile-release-kit.desktop"
# Uploading both delivery directories preserves these exact relative paths.
# This is a closed map, never a normalization or arbitrary nested-path grant.
ARTIFACT_PATHS = {
    "preview/MobileReleaseKit.dmg": ("preview", "MobileReleaseKit.dmg"),
    "preview/README.md": ("preview", "README.md"),
    "preview/PREVIEW.json": ("preview", "PREVIEW.json"),
    "remove-preview/MobileReleaseKit-Remove.dmg": ("remove-preview", "MobileReleaseKit-Remove.dmg"),
    "remove-preview/REMOVE.md": ("remove-preview", "REMOVE.md"),
    "remove-preview/REMOVAL.json": ("remove-preview", "REMOVAL.json"),
}


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def hx(value, size):
    return type(value) is str and len(value) == size and all(c in "0123456789abcdef" for c in value) and any(c != "0" for c in value)


def positive(value):
    return type(value) is str and 0 < len(value) <= 20 and value[0] != "0" and value.isascii() and value.isdecimal()


def scalar(value, maximum):
    return type(value) is int and 0 < value <= maximum


def member_data(value):
    need(type(value) is dict and set(value) == {"name", "bytes", "sha256"}, "update-member-fields")
    name = value["name"]
    need(type(name) is str and 0 < len(name) <= 128 and name not in (".", "..")
         and all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for c in name)
         and scalar(value["bytes"], LIMIT) and hx(value["sha256"], 64), "update-member-values")
    return dict(value)


def artifact_member_data(value):
    if type(value) is dict and type(value.get("name")) is str and value["name"] in ARTIFACT_PATHS:
        member_data(dict(value, name=ARTIFACT_PATHS[value["name"]][1]))
        return dict(value)
    return member_data(value)  # Preserve the existing flat contract unchanged.


def artifact_members_data(rows):
    need(type(rows) is list and 1 <= len(rows) <= 8, "update-nomination-roster")
    members = [artifact_member_data(value) for value in rows]
    names = {value["name"] for value in members}
    need(len(names) == len(members) and sum(value["bytes"] for value in members) <= LIMIT,
         "update-nomination-roster")
    nested = bool(names.intersection(ARTIFACT_PATHS))
    need(not nested or names == set(ARTIFACT_PATHS), "update-artifact-nested-roster")
    return members, nested


def nomination_data(document, target, stager):
    need(target in TARGETS and type(document) is dict and type(document.get("schemaVersion")) is int
         and document["schemaVersion"] == 1, "update-nomination-schema")
    if document == {"schemaVersion": 1, "mode": "unconfigured"}:
        raise ValueError("update-qualified-predecessor-unconfigured")
    need(set(document) == {"schemaVersion", "mode", "targets"} and document["mode"] == "configured"
         and type(document["targets"]) is dict and set(document["targets"]) == set(TARGETS), "update-nomination-fields")
    for selected, row in document["targets"].items():
        need(type(row) is dict and set(row) == {"source", "runId", "runAttempt", "jobId", "artifactId", "artifactBytes",
             "artifactSha256", "members", "image", "package", "descriptor", "signature", "inventory", "release",
             "signingPolicy", "qualificationEvidenceSha256", "resources"}, "update-nomination-row")
        need(hx(row["source"], 40) and all(positive(row[k]) for k in ("runId", "runAttempt", "jobId", "artifactId"))
             and scalar(row["artifactBytes"], LIMIT) and hx(row["artifactSha256"], 64)
             and hx(row["qualificationEvidenceSha256"], 64), "update-nomination-identity")
        members, nested = artifact_members_data(row["members"])
        artifact_member_data(row["image"])
        for key in ("package", "descriptor", "signature", "inventory"):
            member_data(row[key])
        need(row["image"] in members and row["image"]["name"].endswith(".dmg")
             and (not nested or row["image"]["name"] == "preview/MobileReleaseKit.dmg")
             and row["package"]["name"] == "Install.pkg" and row["descriptor"]["name"] == "producer.json"
             and row["signature"]["name"] == "producer.sig" and row["inventory"]["name"] == stager.INSTALLATION_INVENTORY_NAME
             and row["descriptor"]["bytes"] <= 16384 and row["signature"]["bytes"] <= 512
             and row["inventory"]["bytes"] <= 1024 * 1024, "update-nomination-fixed-members")
        release = stager.maintenance_release_data(row["release"], selected)
        need(release["sourceCommit"] == row["source"] and release["packageSha256"] == row["package"]["sha256"]
             and release["inventorySha256"] == row["inventory"]["sha256"], "update-nomination-release")
        policy = row["signingPolicy"]
        probe = {"schemaVersion": 2, "kind": "mrk-macos-install-producer-v2", "domain": "MobileReleaseKit-package-producer-v2",
                 "target": selected, "releaseSet": {"schemaVersion": 2, "current": release, "acceptedPredecessors": []},
                 "signingPolicies": [policy]}
        stager.maintenance_producer_data(stager.canonical(probe) + b"\n", target=selected)
        need(type(row["resources"]) is dict and set(row["resources"]) == {"reviewed", "additionalDiskBytes", "rawPayloadBytes", "maximumOriginals"}
             and row["resources"]["reviewed"] is True and scalar(row["resources"]["additionalDiskBytes"], 8 * 1024**3)
             and scalar(row["resources"]["rawPayloadBytes"], 4 * 1024**3)
             and scalar(row["resources"]["maximumOriginals"], 96), "update-reviewed-resource-nomination")
        quote = resource_quote_data(row)
        need(row["resources"]["additionalDiskBytes"] >= quote["additionalDiskBytes"]
             and row["resources"]["rawPayloadBytes"] >= quote["rawPayloadBytes"]
             and row["resources"]["maximumOriginals"] >= quote["maximumOriginals"], "update-resource-nomination-too-small")
    return document["targets"][target]


def resource_quote_data(row):
    # Incremental held artifact+extracted members, mounted decompression not an
    # owned copy, two generations up to the EXISTING shared bound. Sequential
    # XAR/gzip/CPIO audit may simultaneously retain <=6 archive-sized buffers.
    # Raw application payload quote only: not RSS or a kernel-cache reservation.
    artifact = row["artifactBytes"]
    files = sum(v["bytes"] for v in row["members"])
    package = row["package"]["bytes"]
    need(scalar(artifact, LIMIT) and scalar(files, LIMIT) and scalar(package, LIMIT), "update-resource-sizes")
    return {"additionalDiskBytes": artifact + files + LIMIT + 4 * 1024**2,
            "rawPayloadBytes": 6 * LIMIT + 64 * 1024**2 + 16 * 1024**2,
            "maximumOriginals": 96}


def pair_data(stager, predecessor, current_descriptor, old_inventory, new_inventory, *, old_metadata, new_metadata):
    current = stager.maintenance_producer_data(current_descriptor, target=predecessor["release"]["profile"].replace(
        "fixed-macos26-arm64-maintenance-v2", TARGETS[0]).replace("fixed-macos26-x86_64-maintenance-v2", TARGETS[1]))
    target = current["target"]
    old, new = predecessor["release"], current["releaseSet"]["current"]
    need(current["releaseSet"]["acceptedPredecessors"] == [old]
         and predecessor["signingPolicy"] in current["signingPolicies"] and old != new
         and old["sourceCommit"] != new["sourceCommit"] and old["packageVersion"] != new["packageVersion"]
         and old["release"] != new["release"] and old["packageSha256"] != new["packageSha256"], "update-exact-two-release-lineage")
    counts = []
    for release, inventory, metadata in ((old, old_inventory, old_metadata), (new, new_inventory, new_metadata)):
        rows = stager.observation_inventory_bytes(inventory, release["inventorySha256"], release["runtimeManifestSha256"],
             selection=stager.BuildSelection(target, release["packageVersion"], release["release"]))
        need(type(metadata) is int and 0 < metadata <= 2 * 1024**2, "update-generation-metadata-bound")
        counts.append((len(rows), sum(v["size"] for v in rows.values()) + metadata))
    return aggregate_data(counts, stager.MAX_FILES, stager.MAX_BYTES,
                          len(stager.MAINTENANCE_GATE_BYTES) + len(stager.REGISTRATION_GATE_BYTES))


def aggregate_data(counts, maximum_files, maximum_bytes, gate_bytes):
    need(type(counts) is list and len(counts) == 2 and all(type(v) in (tuple, list) and len(v) == 2
         and all(type(n) is int and n >= 0 for n in v) for v in counts)
         and all(type(n) is int and n >= 0 for n in (maximum_files, maximum_bytes, gate_bytes)), "update-aggregate-types")
    files, size = sum(v[0] for v in counts) + 2, sum(v[1] for v in counts) + gate_bytes
    need(files <= maximum_files and size <= maximum_bytes, "update-retained-pair-exceeds-existing-bound")
    return {"declaredFiles": files, "declaredBytes": size}


def census_data(before, after, *, baseline=None):
    need(type(before) is dict and type(after) is dict, "update-census-types")
    if baseline is None:
        need(not before and len(after) == 1, "update-fresh-census")
        request = next(iter(after))
    else:
        need(hx(baseline, 32) and set(before) == {baseline} and len(after) == 2
             and after.get(baseline) == before[baseline], "update-exact-one-new-export")
        request = next(k for k in after if k != baseline)
    need(hx(request, 32), "update-request-id")
    return request


def phase_credit(rows, *, phase):
    roles = ROLES if phase == PHASE else None
    need(roles is not None and type(rows) is list and len(rows) == len(roles), "update-original-roster")
    need(all(type(row) is dict for row in rows) and tuple(row.get("role") for row in rows) == roles and all(
         row.get("entered") is True and row.get("returned") is True and row.get("capturesSettled") is True
         and type(row.get("returncode")) is int and row["returncode"] == 0 for row in rows), "update-original-finality")
    return True


def context(op):
    return {"source": op.image_source, "workflowSource": op.environment["GITHUB_SHA"], "runId": op.environment["GITHUB_RUN_ID"],
            "runAttempt": op.environment["GITHUB_RUN_ATTEMPT"], "target": op.target}


def clock(op, *, work=True):
    row = op.update
    now = op.update_api.time.monotonic_ns()
    end = row["workEnd"] if work else row["hardEnd"]
    need(type(now) is int and row["start"] <= row["observed"] <= now < end, "update-baseline-deadline")
    row["observed"] = now
    return now


def start(op, api):
    need(op.environment.get("GITHUB_REF") == REF and op.phase in (PHASE, "package-install"), "update-fixed-source-route")
    op.update_api = api
    nomination = op.source_original(NOMINATION, "source-update-nomination", RECORD_LIMIT)
    body = op.read(nomination)
    selected = nomination_data(api.tool_json(body), op.target, op.stager)
    op.package_sources.append((nomination, body))
    now = api.time.monotonic_ns()
    op.update = {"nomination": selected, "complete": False, "start": now, "observed": now,
                 "workEnd": now + 420_000_000_000, "hardEnd": now + 480_000_000_000,
                 "sentinelEntries": [], "originals": [], "case": None}
    if op.phase == PHASE:
        op.package_started = op.package_observed = now
        op.package_endpoint = op.update["workEnd"]


def io(op, name, function, *args, **kwargs):
    need(name in ("census", "absence", "baseline-readback", "update-readback", "sentinel", "sentinel-post", "credential-state", "credential-state-post")
         and op.package_settled(), "update-io-originals-unknown")
    op.package_clock()
    op.stager_io_pending = "update-" + name
    try:
        result = function(*args, **kwargs)
    except BaseException:
        op.errors.append({"stage": "update-io", "operation": name, "type": "CompletionUnknown"})
        raise
    op.stager_io_pending = None
    op.package_clock()
    return result


def retain(op, parent, name, limit, modes=(0o444, 0o600, 0o644)):
    entry = op.original(parent, name, "update-" + name, limit, modes)
    body = op.read(entry)
    op.package_outputs.append((entry, sha(body)))
    return entry, body


def reserve(op, size):
    # Same original volume before creating/copying. This is an admission
    # observation, not a claim of an OS disk quota or immunity to other jobs.
    info = os.fstatvfs(op.work_entry["fd"])
    need(type(size) is int and size > 0 and info.f_bavail * info.f_frsize >= size + 64 * 1024**2,
         "update-incremental-disk-unavailable")


def source_expectation(op):
    api, stager = op.update_api, op.stager
    inventory_entry, inventory = retain(op, op.directory(op.work_entry, "input", "update-current-input"),
                                        stager.INSTALLATION_INVENTORY_NAME, 1024 * 1024)
    package_entry, package = retain(op, op.directory(op.work_entry, "package-final", "update-current-final"),
                                    "MobileReleaseKit.pkg", LIMIT)
    op.package_finalization_input(package_entry, package)
    history_entry = op.source_original("desktop/macos-installed-inputs/producer-history.json", "source-update-history", RECORD_LIMIT)
    history = op.read(history_entry)
    op.package_sources.append((history_entry, history))
    selection = stager.source_build_selection(op.target)
    signing = stager.packaging_signing_data(op.producer_profile, op.service_profile)
    expected = stager.packaging_descriptor_data(history, signing, selection, source_commit=op.image_source,
        manifest=op.environment["MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"], inventory=sha(inventory), package=sha(package))
    del package
    return expected, inventory


def product_inventory(op, body, nomination):
    # Existing complete XAR/root0 CPIO parsers only, one archive at a time.
    stager = op.stager
    members = stager.install_product_members(body)
    if stager.INSTALL_COMPONENT in members:
        component = stager.xar_members(members[stager.INSTALL_COMPONENT])
    else:
        component = {name: members[stager.INSTALL_COMPONENT + "/" + name] for name in ("PackageInfo", "Scripts")}
    need(set(component) == {"PackageInfo", "Scripts"}, "update-product-component")
    release = nomination["release"]
    stager.package_info(component["PackageInfo"], selection=stager.BuildSelection(op.target, release["packageVersion"], release["release"]))
    packed = component["Scripts"]
    archive = stager.inflate(packed, LIMIT, gzip=True) if packed[:2] == b"\x1f\x8b" else packed
    rows = stager.cpio_members(archive)
    key = "input/" + stager.INSTALLATION_INVENTORY_NAME
    need(key in rows and rows[key][1] == 0o444 and type(rows[key][0]) is bytes, "update-original-inventory-member")
    inventory = rows[key][0]
    need((len(inventory), sha(inventory)) == (nomination["inventory"]["bytes"], nomination["inventory"]["sha256"]),
         "update-original-inventory-binding")
    # The signed P nomination authenticates the entire package; this is DATA
    # correspondence, not independent signature/notarization qualification.
    return inventory


def root_absent(stager):
    with stager.installer_channel_parent(stager.INSTALL_ROOT) as (fd, name):
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return True
        raise ValueError("update-initial-root-not-absent")


def dispatch(op, role, argv):
    if op.phase != PHASE:
        return
    index = len(op.calls)
    need(index < len(ROLES) and role == ROLES[index] and op.package_settled(), "update-fixed-original-order")
    selected = op.update["nomination"]
    context = {"GITHUB_RUN_ID": op.environment.get("GITHUB_RUN_ID"),
               "GITHUB_RUN_ATTEMPT": op.environment.get("GITHUB_RUN_ATTEMPT")}
    mount_path = op.update_api.transport_mount_path_data(context, op.target, PHASE)
    need(op.transport_mount == mount_path, "update-original-transport-path")
    commands = {
        ROLES[0]: ["/usr/bin/hdiutil", "attach", str(op.work / "update-predecessor" / selected["image"]["name"]),
                   "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", str(mount_path), "-plist"],
        ROLES[1]: ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer", "-pkg", str(mount_path / "Install.pkg"),
                   "-target", "/", "-dumplog", "-verboseR"],
        ROLES[2]: ["/usr/bin/hdiutil", "detach", op.mount_device],
    }
    need(type(argv) is list and argv == commands[role], "update-fixed-original-argv")
    if role == ROLES[0]:
        op.mount_entered = True
    elif role == ROLES[1]:
        need(op.mount_known and not op.mount_detached, "update-installer-mount-unknown")
        op.installer_entered = True
    else:
        need(op.installer_zero and op.installation_readback, "update-detach-before-readback")


def status(op, code):
    need(op.phase == PHASE and type(code) is int and op.update["case"] is not None, "update-private-status")
    op.publish("installer-output.status", (str(code) + "\n").encode("ascii"), parent=op.update["case"])


def artifact_inputs(op, selected):
    members, nested = artifact_members_data(selected["members"])
    need(selected["image"] in members
         and (not nested or selected["image"]["name"] == "preview/MobileReleaseKit.dmg"), "update-image-original")
    download = op.directory(op.work_entry, "update-predecessor", "update-artifact-root")
    names = {"preview", "remove-preview"} if nested else {row["name"] for row in members}
    need(set(os.listdir(download["fd"])) == names, "update-artifact-exact-roster")
    op.package_roots.append((download, names))
    parents = {}
    if nested:
        for name in ("preview", "remove-preview"):
            entry = op.directory(download, name, "update-artifact-" + name)
            leaves = {leaf for group, leaf in ARTIFACT_PATHS.values() if group == name}
            need(set(os.listdir(entry["fd"])) == leaves, "update-artifact-exact-roster")
            op.package_roots.append((entry, leaves))
            parents[name] = entry
    image_entry = None
    for row in members:
        group, leaf = ARTIFACT_PATHS[row["name"]] if nested else (None, row["name"])
        entry, body = retain(op, parents[group] if nested else download, leaf, row["bytes"], (0o644, 0o444))
        need((len(body), sha(body)) == (row["bytes"], row["sha256"]), "update-artifact-member-binding")
        if row == selected["image"]:
            image_entry = entry
        del body
    need(image_entry is not None, "update-image-original")
    return image_entry


def baseline(op):
    api, stager, selected = op.update_api, op.stager, op.update["nomination"]
    op.stage = PHASE
    quote = resource_quote_data(selected)
    reserve(op, selected["resources"]["additionalDiskBytes"])
    artifact_inputs(op, selected)
    expected, current_inventory = source_expectation(op)
    before = io(op, "census", stager.same_package_result_census)
    need(not before and io(op, "absence", root_absent, stager), "update-initial-baseline-occupied")
    op.update["case"] = op.package_directory("update-baseline-case")
    os.mkdir("input", 0o700, dir_fd=op.update["case"]["fd"])
    case_input = op.directory(op.update["case"], "input", "update-case-input")
    op.normal_mount_host()
    mount_path = op.transport_mount_admit()
    op.package_post()  # Same held complete artifact originals immediately before attach.
    attached = op.package_call(ROLES[0], ["/usr/bin/hdiutil", "attach", str(op.work / "update-predecessor" / selected["image"]["name"]),
        "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", str(mount_path), "-plist"], timeout=60)
    op.mount_custody(attached, "update-readonly-mount")
    fd = op.mount_entry["fd"]
    op.package_name = "Install.pkg"
    need(set(os.listdir(fd)) == {"Install.pkg", "producer.json", "producer.sig"}, "update-mounted-roster")
    original = {}
    for key in ("package", "descriptor", "signature"):
        row = selected[key]
        op.removal_reserve()
        entry = op.register(None, "update-mounted-" + key, "mounted-file", fd, row["name"])
        entry["fd"] = item_fd = os.open(row["name"], api.READ_FLAGS, dir_fd=fd)
        info = os.fstat(item_fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o444
             and info.st_uid in (0, os.getuid()) and info.st_size == row["bytes"], "update-mounted-shape")
        entry["identity"] = api.signature(info)
        value = os.pread(item_fd, row["bytes"] + 1, 0)
        need(len(value) == row["bytes"] and sha(value) == row["sha256"]
             and api.signature(os.fstat(item_fd)) == entry["identity"]
             == api.signature(os.stat(row["name"], dir_fd=fd, follow_symlinks=False)), "update-mounted-hash")
        entry["sha256"] = sha(value)
        original[row["name"]] = value
    stager.distribution_layout_data(os.listdir(fd), "Install.pkg", original, {k: (v, 0o444) for k, v in original.items()})
    old_producer = stager.maintenance_producer_data(original["producer.json"], target=op.target)
    need(old_producer["releaseSet"]["current"] == selected["release"]
         and selected["signingPolicy"] in old_producer["signingPolicies"], "update-signed-descriptor-nomination")
    inventory = product_inventory(op, original["Install.pkg"], selected)
    # Conservative bound for each actual inventory+record+descriptor+signature:
    # fixed record max16KiB is charged before the native writer emits it.
    aggregate = pair_data(stager, selected, expected, inventory, current_inventory,
        old_metadata=len(inventory) + 16384 + len(original["producer.json"]) + len(original["producer.sig"]),
        new_metadata=len(current_inventory) + 16384 + len(expected) + stager.PRODUCER_SIGNATURE_BYTES)
    op.package_file(case_input, stager.INSTALLATION_INVENTORY_NAME, inventory)
    op.package_file(op.update["case"], "expected-current-producer.json", expected)
    # Persist exact nominated descriptor/signature as DATA for later current
    # readback; no re-signing or source rewriting of P0.
    for name in ("producer.json", "producer.sig"):
        op.package_file(op.update["case"], name, original[name])
    del original, current_inventory, inventory
    sentinel = io(op, "sentinel", sentinel_open, op, True, None)
    op.mounted_post(); op.package_post()
    result = op.package_call(ROLES[1], ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer", "-pkg", str(mount_path / "Install.pkg"),
                                      "-target", "/", "-dumplog", "-verboseR"], timeout=123, limit=256 * 1024)
    op.installer_zero = type(result.returncode) is int and result.returncode == 0
    after = io(op, "census", stager.same_package_result_census)
    request = census_data(before, after)
    args = baseline_args(op, request)
    facts = {}
    observed = io(op, "baseline-readback", stager.observation_command, args,
                  nominated_update_predecessor=selected, update_facts=facts)
    need(observed["originalInstallerReturnedZero"] is True and observed["originalInstallerResult"]["action"] == "fresh-install",
         "update-baseline-original-outcome")
    sentinel_post(op, sentinel)
    op.installation_readback = True
    op.mounted_post(); op.package_post(); op.detach_package_mount(); op.package_post()
    phase_credit(op.calls, phase=PHASE)
    op.update["complete"] = True
    op.receipt["updateBaseline"] = {"schemaVersion": 1, **context(op), "predecessorSource": selected["source"],
        "nominationSha256": sha(stager.canonical(selected)), "qualificationEvidenceSha256": selected["qualificationEvidenceSha256"],
        "requestId": request, "readback": facts, "census": after, "sentinel": sentinel,
        "expectedCurrentDescriptorSha256": sha(expected), "predecessorPackageSha256": selected["package"]["sha256"],
        "freshCurrentBytesReadback": True, "aggregate": aggregate,
        "originalInstallerReturnedZero": True, "originalMountDetached": True, "productReady": False}
    op.sha256 = selected["package"]["sha256"]


def baseline_args(op, request):
    old = op.update["nomination"]["release"]
    case = op.work / "update-baseline-case"
    return argparse.Namespace(target=op.target, fixture=False, input=case / "input", expected_source=old["sourceCommit"],
        expected_inventory=old["inventorySha256"], expected_manifest=old["runtimeManifestSha256"], expected_package=old["packageSha256"],
        request_id=request, producer_descriptor=case / "producer.json", producer_signature=case / "producer.sig",
        installer_status=case / "installer-output.status", package=op.transport_mount / "Install.pkg",
        run_id=op.environment["GITHUB_RUN_ID"], run_attempt=op.environment["GITHUB_RUN_ATTEMPT"])


def baseline_input(op):
    _, body = retain(op, op.work_entry, "android-helper-update-baseline.json", RECORD_LIMIT, (0o600,))
    row = op.update_api.tool_json(body)
    need(type(row) is dict and row.get("phase") == PHASE and row.get("passed") is True
         and row.get("targetRetired") is True and row.get("originalClosesKnown") is True
         and all(row.get(k) == v for k, v in context(op).items()), "update-baseline-receipt-finality")
    phase_credit(row["originalCalls"], phase=PHASE)
    _, status_body = retain(op, op.work_entry, "update-baseline.status", 16, (0o600,))
    need(status_body == b"0\n", "update-baseline-outer-original")
    op.update["baselineReceiptSha256"] = sha(body)
    result = row["updateBaseline"]
    need(type(result) is dict and all(result.get(k) == v for k, v in context(op).items())
         and result.get("nominationSha256") == sha(op.stager.canonical(op.update["nomination"]))
         and result.get("predecessorSource") == op.update["nomination"]["source"]
         and result.get("productReady") is False and result.get("originalInstallerReturnedZero") is True
         and result.get("originalMountDetached") is True, "update-baseline-context")
    return result



# Closed two-segment credential fixture DATA; no Keychain selection/repair API.
CREDENTIAL_SCOPE = "one-owned-p0-p1-credential-update-ui-v1"
CREDENTIAL_CONTROLS = {"vault-lock": 0, "initialization-reservation": 48, "vault-header": 104}
CREDENTIAL_RECORD = "Synthetic distribution input"


def credential_facts(info):
    return [str(value) for value in (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_flags, info.st_size, info.st_mtime_ns // 1_000_000_000,
        info.st_mtime_ns % 1_000_000_000, info.st_ctime_ns // 1_000_000_000, info.st_ctime_ns % 1_000_000_000)]


def credential_fact_values(value, *, directory):
    need(type(value) is list and len(value) == 12 and all(type(v) is str and v.isascii()
         and v.isdecimal() and str(int(v)) == v and len(v) <= 20 for v in value), "update-credential-facts")
    values = tuple(map(int, value))
    need(values[0] > 0 and values[1] > 0 and values[2] == (stat.S_IFDIR | 0o700 if directory else stat.S_IFREG | 0o600)
         and values[3] == os.getuid() > 0 and values[4] == os.getgid() and values[6] == 0
         and (values[5] >= 1 if directory else values[5] == 1) and 0 <= values[7] <= 65536
         and 0 <= values[9] < 1_000_000_000 and 0 <= values[11] < 1_000_000_000, "update-credential-facts-policy")
    return values


def credential_leaf_data(row):
    need(type(row) is dict and set(row) == {"facts", "bytes", "sha256"}
         and type(row["bytes"]) is int and 0 <= row["bytes"] <= 32768 and hx(row["sha256"], 64),
         "update-credential-leaf")
    facts = credential_fact_values(row["facts"], directory=False)
    need(facts[7] == row["bytes"], "update-credential-leaf-size")
    return facts


def credential_state_data(value, sentinel, *, records):
    need(type(records) is int and records in (0, 1) and type(value) is dict
         and set(value) == {"root", "sentinel", "vault"}, "update-credential-state")
    root = credential_fact_values(value["root"], directory=True)
    leaf = credential_leaf_data(value["sentinel"])
    signature = [leaf[0], leaf[1], leaf[2], leaf[5], leaf[3], leaf[4], leaf[7],
                 leaf[8] * 1_000_000_000 + leaf[9], leaf[10] * 1_000_000_000 + leaf[11]]
    need(type(sentinel) is dict and set(sentinel) == {"identity", "parentIdentity", "sha256", "bytes"}
         and sentinel == {"identity": signature, "parentIdentity": list(root[:5]),
                          "sha256": sha(SENTINEL), "bytes": len(SENTINEL)}
         and value["sentinel"]["sha256"] == sha(SENTINEL) and leaf[7] == len(SENTINEL)
         and leaf[0] == root[0], "update-credential-owned-sentinel")
    vault = value["vault"]
    need(type(vault) is dict and set(vault) == {"directory", "files"} and type(vault["files"]) is dict,
         "update-credential-vault")
    directory = credential_fact_values(vault["directory"], directory=True)
    names = set(vault["files"])
    record_names = names - set(CREDENTIAL_CONTROLS)
    need(directory[0] == root[0] and names.issuperset(CREDENTIAL_CONTROLS)
         and len(record_names) == records and all(type(name) is str and len(name) == 39
              and name.startswith("record-") and hx(name[7:], 32) for name in record_names),
         "update-credential-exact-vault-roster")
    identities = set()
    total = 0
    for name, row in vault["files"].items():
        facts = credential_leaf_data(row)
        need(facts[0] == directory[0] and (facts[0], facts[1]) not in identities
             and (facts[7] == CREDENTIAL_CONTROLS[name] if name in CREDENTIAL_CONTROLS else facts[7] >= 248),
             "update-credential-vault-leaf-policy")
        identities.add((facts[0], facts[1])); total += facts[7]
    need(total <= 65536 and len(encoded_credential(value)) <= 8192, "update-credential-state-bound")
    return value


def encoded_credential(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def credential_bootstrap_data(value, baseline, *, baseline_sha, source, target, run, attempt, selected):
    keys = {"schemaVersion", "scope", "segment", "sourceCommit", "applicationSourceCommit", "target", "runId", "runAttempt",
        "nominationSha256", "baselineReceiptSha256", "helperSha256", "helperBytes", "state", "recordRevision",
        "testAdmissionSha256", "summaryAdmissionSha256", "nativeSummarySha256", "fixtureOriginalClosesCompleted",
        "normalQuitObserved", "gateReleased", "originalCommandsSettled", "productReady"}
    need(type(value) is dict and set(value) == keys and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["scope"] == CREDENTIAL_SCOPE and value["segment"] == "p0-bootstrap"
         and (value["sourceCommit"], value["applicationSourceCommit"], value["target"], value["runId"], value["runAttempt"])
             == (source, selected["source"], target, run, attempt)
         and value["nominationSha256"] == sha(encoded_credential(selected)) == baseline["nominationSha256"]
         and value["baselineReceiptSha256"] == baseline_sha and hx(baseline_sha, 64)
         and all(hx(value[k], 64) for k in ("helperSha256", "testAdmissionSha256", "summaryAdmissionSha256", "nativeSummarySha256"))
         and scalar(value["helperBytes"], 32 * 1024 * 1024) and type(value["recordRevision"]) is int and value["recordRevision"] == 1
         and all(value[k] is True for k in ("fixtureOriginalClosesCompleted", "normalQuitObserved", "gateReleased", "originalCommandsSettled"))
         and value["productReady"] is False, "update-credential-bootstrap-context-and-finality")
    credential_state_data(value["state"], baseline["sentinel"], records=1)
    return value


def credential_state_open(op, expected):
    """Retain only the already owned sentinel root's exact three controls/one record."""
    api = op.update_api
    need(op.update is not None and "credentialEntries" not in op.update, "update-credential-open-once")
    op.update["credentialEntries"] = entries = []  # Pending custody before any open.
    roots = [row for row in op.update["sentinelEntries"] if row[4]["kind"] == "update-user-directory"]
    root_fd = roots[-1][0]
    need(credential_facts(os.fstat(root_fd)) == expected["root"]
         and set(os.listdir(root_fd)) == {"credential-vault-v1", "mrk-update-preservation-" + op.environment["GITHUB_RUN_ID"] + "-" + op.environment["GITHUB_RUN_ATTEMPT"] + ".txt"},
         "update-credential-owned-root-roster")
    name = "credential-vault-v1"
    op.removal_reserve()
    entry = op.register(None, "update-credential-vault", "update-credential-directory", root_fd, name)
    entry["fd"] = fd = os.open(name, api.READ_FLAGS | os.O_DIRECTORY, dir_fd=root_fd)
    facts = credential_facts(os.fstat(fd)); entry["identity"] = api.signature(os.fstat(fd))
    entries.append((fd, root_fd, name, facts, None, entry))
    need(facts == expected["vault"]["directory"] == credential_facts(os.stat(name, dir_fd=root_fd, follow_symlinks=False))
         and set(os.listdir(fd)) == set(expected["vault"]["files"]), "update-credential-vault-original")
    for name, row in sorted(expected["vault"]["files"].items()):
        op.removal_reserve()
        entry = op.register(None, "update-credential-leaf", "update-credential-file", fd, name)
        entry["fd"] = item = os.open(name, api.READ_FLAGS, dir_fd=fd)
        info = os.fstat(item); entry["identity"] = api.signature(info)
        facts = credential_facts(info)
        entries.append((item, fd, name, facts, row["sha256"], entry))
        need(facts == row["facts"] and sha(os.pread(item, row["bytes"] + 1, 0)) == row["sha256"]
             and facts == credential_facts(os.stat(name, dir_fd=fd, follow_symlinks=False)), "update-credential-leaf-original")
    op.update["credentialState"] = expected
    credential_state_post(op)


def credential_state_post(op):
    need(op.update.get("credentialEntries") and op.update.get("credentialState"), "update-credential-unobserved")
    expected = op.update["credentialState"]
    for fd, parent, name, facts, digest, entry in op.update["credentialEntries"]:
        need(entry["fd"] == fd and credential_facts(os.fstat(fd)) == facts
             == credential_facts(os.stat(name, dir_fd=parent, follow_symlinks=False)), "update-credential-held-named-post")
        if digest is not None:
            need(sha(os.pread(fd, int(facts[7]) + 1, 0)) == digest, "update-credential-byte-post")
        else:
            need(set(os.listdir(fd)) == set(expected["vault"]["files"]), "update-credential-roster-post")
    root_fd = op.update["credentialEntries"][0][1]
    need(credential_facts(os.fstat(root_fd)) == expected["root"] and set(os.listdir(root_fd)) ==
         {"credential-vault-v1", "mrk-update-preservation-" + op.environment["GITHUB_RUN_ID"] + "-" + op.environment["GITHUB_RUN_ATTEMPT"] + ".txt"},
         "update-credential-root-post")
    op.package_clock()


def credential_bootstrap_input(op, baseline):
    normal = op.directory(op.work_entry, "normal-ui", "update-credential-normal-ui")
    _, body = retain(op, normal, "update-p0-bootstrap.result.json", RECORD_LIMIT, (0o600,))
    for name in ("update-p0-bootstrap-test.status", "update-p0-bootstrap-summary.status"):
        _, status = retain(op, normal, name, 16, (0o600,))
        need(status == b"0\n", "update-credential-bootstrap-original-status")
    value = credential_bootstrap_data(op.update_api.tool_json(body), baseline,
        baseline_sha=op.update["baselineReceiptSha256"], source=op.image_source, target=op.target,
        run=op.environment["GITHUB_RUN_ID"], attempt=op.environment["GITHUB_RUN_ATTEMPT"], selected=op.update["nomination"])
    op.update["credentialBootstrapSha256"] = sha(body)
    return value

def before_current(op, descriptor):
    row = baseline_input(op)
    case = op.directory(op.work_entry, "update-baseline-case", "update-baseline-retained")
    _, expected = retain(op, case, "expected-current-producer.json", RECORD_LIMIT, (0o444,))
    need(descriptor == expected and sha(descriptor) == row["expectedCurrentDescriptorSha256"], "update-current-descriptor-expectation")
    facts = {}
    # Actual complete P0 current bytes, same original prior Installer status and
    # exact current state are checked again immediately before P1 mutation.
    io(op, "baseline-readback", op.stager.observation_command, baseline_args(op, row["requestId"]),
       nominated_update_predecessor=op.update["nomination"], update_facts=facts)
    need(facts == row["readback"] and io(op, "census", op.stager.same_package_result_census) == row["census"],
         "update-baseline-changed-before-current")
    sentinel = io(op, "sentinel", sentinel_open, op, False, row["sentinel"])
    sentinel_post(op, sentinel)
    bootstrap = credential_bootstrap_input(op, row)
    io(op, "credential-state", credential_state_open, op, bootstrap["state"])
    op.update["baseline"] = row


def current_readback(op, args):
    baseline = op.update["baseline"]
    expected = baseline["readback"]
    facts = {}
    observed = io(op, "update-readback", op.stager.observation_command, args,
                  expected_update_previous=expected, update_facts=facts)
    after = io(op, "census", op.stager.same_package_result_census)
    request = census_data(baseline["census"], after, baseline=baseline["requestId"])
    need(request == args.request_id and observed["originalInstallerResult"]["action"] == "update", "update-current-request")
    sentinel_post(op, baseline["sentinel"])
    io(op, "credential-state-post", credential_state_post, op)
    op.update["facts"] = facts
    op.update["afterCensus"] = after
    return observed  # EXACT existing ordinary observation schema.


def current_complete(op):
    need(op.installer_zero and op.installation_readback and op.mount_detached and op.package_settled(), "update-current-finality")
    baseline, facts = op.update["baseline"], op.update["facts"]
    op.receipt["positiveUpdate"] = {"schemaVersion": 1, **context(op), "predecessorSource": op.update["nomination"]["source"],
        "predecessorPackageSha256": op.update["nomination"]["package"]["sha256"],
        "predecessorQualificationEvidenceSha256": op.update["nomination"]["qualificationEvidenceSha256"],
        "currentDescriptorSha256": baseline["expectedCurrentDescriptorSha256"],
        "credentialBootstrapSha256": op.update["credentialBootstrapSha256"],
        "baselineInvocation": baseline["readback"]["previous"]["invocation"], "currentInvocation": facts["previous"]["invocation"],
        "rootIdentityPreserved": facts["rootIdentity"] == baseline["readback"]["rootIdentity"],
        "generationInstancesDistinct": facts["generation"]["instance"] != baseline["readback"]["generation"]["instance"],
        "previousExportUnchanged": True, "exportCount": 2, "testedAppDataOriginalPreserved": True,
        "originalCurrentInstallerReturnedZero": True, "originalMountDetached": True,
        "currentPayloadReadback": True, "retainedPayloadRehashed": False,
        "downloadedLaunchQualified": False, "allUserDataCompatible": False, "productReady": False}
    op.update["complete"] = True


def finish_ready(op):
    return (op.update is not None and op.update["complete"] and op.package_settled()
            and op.installer_zero and op.installation_readback and op.mount_detached)


def gui_home_data(environment):
    home = environment.get("MRK_MACOS_GUI_HOME")
    account = pwd.getpwuid(os.getuid())
    console = os.stat("/dev/console", follow_symlinks=False)
    need(os.getuid() > 0 and os.getuid() == os.geteuid() == account.pw_uid == console.st_uid
         and os.getgid() == os.getegid() == account.pw_gid and account.pw_name == "runner"
         and type(home) is str and home == account.pw_dir and home.startswith("/"), "update-actual-gui-home")
    return home


def sentinel_open(op, create, expected):
    # Authenticated tauri2.11.5->dirs6->dirs-sys0.5 mapping: actual APP HOME,
    # then Library/Application Support/config.identifier. Not helper HOME.
    api = op.update_api
    home = op.environment.get("MRK_MACOS_GUI_HOME")
    need(type(home) is str and home.startswith("/") and len(home) <= 1024 and all(p not in ("", ".", "..") for p in home[1:].split("/"))
         and gui_home_data(op.environment) == home, "update-actual-gui-home")
    # Same account/console observations as the reviewed normal UI admission;
    # passwd only crosschecks actual inherited GUI HOME, never substitutes it.
    path = Path(home) / "Library/Application Support" / IDENTIFIER
    opened = []
    try:
        for index, part in enumerate(("/", *path.parts[1:])):
            parent = opened[-1][0] if opened else None
            if create and index == len(path.parts) - 1:
                os.mkdir(part, 0o700, dir_fd=parent)
            before = os.stat(part, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode) and before.st_uid in (0, os.getuid())
                 and not before.st_mode & 0o7022 and (index != len(path.parts) - 1 or before.st_uid == os.getuid()
                    and stat.S_IMODE(before.st_mode) == 0o700), "update-app-data-ancestor")
            fd = os.open(part, api.READ_FLAGS | os.O_DIRECTORY, dir_fd=parent)
            entry = op.register(fd, "update-sentinel-directory", "update-user-directory", parent, part)
            identity = (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid)
            need((lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid))(os.fstat(fd)) == identity, "update-app-data-ancestor-changed")
            entry["identity"] = identity
            opened.append((fd, parent, part, identity, entry))
        leaf_name = "mrk-update-preservation-" + op.environment["GITHUB_RUN_ID"] + "-" + op.environment["GITHUB_RUN_ATTEMPT"] + ".txt"
        if create:
            fd = os.open(leaf_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=opened[-1][0])
        else:
            fd = os.open(leaf_name, api.READ_FLAGS, dir_fd=opened[-1][0])
        entry = op.register(fd, "update-sentinel-file", "update-user-file", opened[-1][0], leaf_name)
        if create:
            need(os.write(fd, SENTINEL) == len(SENTINEL), "update-sentinel-short-write")
            os.fsync(fd)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_gid == os.getgid() and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(SENTINEL)
             and os.pread(fd, len(SENTINEL) + 1, 0) == SENTINEL, "update-sentinel-original")
        identity = list(api.signature(info))
        need(create or type(expected) is dict and expected == {"identity": identity, "parentIdentity": list(opened[-1][3]), "sha256": sha(SENTINEL), "bytes": len(SENTINEL)},
             "update-sentinel-original-changed")
        entry["identity"] = tuple(identity)
        op.update["sentinelEntries"].extend(opened)
        op.update["sentinelEntries"].append((fd, opened[-1][0], leaf_name, tuple(identity), entry))
        return {"identity": identity, "parentIdentity": list(opened[-1][3]), "sha256": sha(SENTINEL), "bytes": len(SENTINEL)}
    except BaseException:
        # Registered originals remain with the SAME consuming cleanup owner.
        raise


def sentinel_post(op, expected):
    api = op.update_api
    need(op.update["sentinelEntries"], "update-sentinel-unobserved")
    for fd, parent, name, identity, entry in op.update["sentinelEntries"]:
        held, named = os.fstat(fd), os.stat(name, dir_fd=parent, follow_symlinks=False)
        actual = (lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)) if entry["kind"] == "update-user-directory" else api.signature
        need(actual(held) == actual(named) == identity, "update-sentinel-original-post")
        if entry["kind"] == "update-user-file":
            need(list(identity) == expected["identity"] and os.pread(fd, len(SENTINEL) + 1, 0) == SENTINEL,
                 "update-sentinel-byte-post")
    op.package_clock()


def source_document(checkout):
    path = checkout / NOMINATION
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
             and stat.S_IMODE(before.st_mode) in (0o444, 0o644) and 0 < before.st_size <= RECORD_LIMIT,
             "update-source-file-shape")
        body = os.pread(fd, before.st_size + 1, 0)
        identity = lambda v: (v.st_dev, v.st_ino, v.st_mode, v.st_nlink, v.st_uid, v.st_gid, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
        need(len(body) == before.st_size and os.pread(fd, before.st_size + 1, 0) == body
             and identity(os.fstat(fd)) == identity(path.lstat()) == identity(before), "update-source-file-post")
    finally:
        os.close(fd)
    def pairs(rows):
        result = {}
        for k, v in rows:
            need(k not in result, "update-source-duplicate-key")
            result[k] = v
        return result
    def invalid(_):
        raise ValueError("update-source-json-number")
    return json.loads(body.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)


def main(arguments):
    import importlib.util
    import sys
    try:
        need(len(arguments) == 3 and arguments[:2] == ["select", "--target"] and arguments[2] in TARGETS,
             "update-fixed-data-command")
        checkout = Path(__file__).absolute().parents[2]
        need(checkout == Path.cwd() and os.environ.get("GITHUB_REF") == REF, "update-fixed-data-context")
        document = source_document(checkout)
        # This default refuses before downloading P0, native preparation, user
        # data creation or loading a process owner. No synthetic predecessor.
        need(document != {"schemaVersion": 1, "mode": "unconfigured"}, "update-qualified-predecessor-unconfigured")
        path = checkout / "desktop/tools/stage_macos_installed.py"
        spec = importlib.util.spec_from_file_location("mrk_update_selection_stager", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
            row = nomination_data(document, arguments[2], module)
        finally:
            sys.modules.pop(spec.name, None)
        result = {"artifactId": row["artifactId"], "runId": row["runId"], "artifactBytes": row["artifactBytes"],
                  "additionalDiskBytes": row["resources"]["additionalDiskBytes"]}
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:
        print("Qualified update predecessor selection unavailable; enroll reviewed P0 and a newer P1 first.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
