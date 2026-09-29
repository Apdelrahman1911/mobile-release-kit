"""Explicit retained Android inputs for the existing preparation/publication owner.

This is a local route, not a fallback for a refused hosted preparation.  It uses
the original private material and acquisition receipts; it neither downloads
suppliers nor creates image, installer, consent, or execution receipts.  The
fixed runtime selection remains closed until independently accepted DATA exists.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import math
import os
from pathlib import Path
import re
import stat


SCOPE = "android-local-retained-material-v1"
SDK_CLASSIFICATION = "local-retained-sdk-current-use-v1"
POLICY_SHA256 = "cc9d927684952ede4f763cefaa663b40323ffacf9666d9aa2db0f1ccf5a9dcb9"
POLICY_LIMIT = 4 << 20
SDK_ROOT = "/opt/android-sdk"
SDK_RECEIPT = SDK_ROOT + "/licenses/android-sdk-license"
SDK_PACKAGES = {name: {"metadataPath": SDK_ROOT + "/" + name.replace(";", "/") + "/package.xml",
                       "propertiesPath": SDK_ROOT + "/" + name.replace(";", "/") + "/source.properties"}
                for name in ("platforms;android-35", "build-tools;35.0.0")}
AAPT2_SOURCE = "gradle/aapt2/8.9.2-12782657-linux/aapt2"
AAPT2_DESTINATION = "gradle/native/aapt2/aapt2"
ABI_PATHS = ("sdk/build-tools/35.0.0/lib64/libncurses.so.5",
             "sdk/build-tools/35.0.0/lib64/libtinfo.so.5",
             "sdk/build-tools/35.0.0/lib64/ncurses5-COPYRIGHT.txt")
LOCAL_CONTEXT_FIELDS = {"kind", "sourceCommit", "sourceTree", "taskId", "preparation"}
ORIGINAL_FIELDS = {"schemaVersion", "kind", "sourceCommit", "sourceTree", "taskId", "source", "ownerRoot",
                   "started", "deadline", "finalityDeadline", "workBudgetSeconds", "finalityBudgetSeconds",
                   "readerUid", "readerGid", "consumerUid", "consumerGid", "rootIdentity", "workIdentity"}


def source_policy(A):
    """Authenticate SOURCE only; a null runtime is deliberately not admission."""
    raw = A.D.read(A.DATA / "local-retained.json", POLICY_LIMIT)
    A.D.need(A._sha(raw) == POLICY_SHA256, "Local Android retained policy source differs")
    selected = A.D.decode(raw, POLICY_LIMIT)
    A._keys(selected, {"schemaVersion", "scope", "basePolicySha256", "sdkPins", "stage", "abiBodies",
                       "evidence", "runtime"}, "Local Android retained policy fields differ")
    A.D.need(type(selected["schemaVersion"]) is int and selected["schemaVersion"] == 1 and selected["scope"] == SCOPE
             and selected["basePolicySha256"] == A.POLICY_SHA256,
             "Local Android retained source classification differs")
    expected = {SDK_RECEIPT, *(p for pair in SDK_PACKAGES.values() for p in pair.values())}
    A.D.need(type(selected["sdkPins"]) is dict and set(selected["sdkPins"]) == expected,
             "Local Android SDK original roster differs")
    for path, pin in selected["sdkPins"].items():
        A._keys(pin, {"size", "sha256"}, "Local Android SDK pin fields differ")
        A.D.need(type(pin["size"]) is int and 0 < pin["size"] <= (4096 if path == SDK_RECEIPT else 32 << 10),
                 "Local Android SDK input extent differs")
        A.D.sha(pin["sha256"])
    return selected


def admitted_value(A):
    selected = source_policy(A)
    runtime = selected["runtime"]
    A.D.need(type(runtime) is dict, "Local Android actual runtime closure is not yet admitted")
    A._keys(runtime, {"host", "controls", "fontDirectories", "fontFileBytes", "fontCacheExtraInputs",
                      "consumerScratchBytes", "minimumAvailableRamBytes"},
            "Local Android actual runtime selection differs")
    A._keys(runtime["controls"], {"fonts.json", "providers.json"}, "Local Android runtime control roster differs")
    for name, control in runtime["controls"].items():
        A.D.need(type(control) is dict and 0 < len(A.D.canonical(control)) <= 1 << 20,
                 "Local Android runtime control extent differs")
    A.D.need(type(runtime["consumerScratchBytes"]) is int and 0 < runtime["consumerScratchBytes"] <= 8 << 30
             and type(runtime["minimumAvailableRamBytes"]) is int
             and 1536 << 20 <= runtime["minimumAvailableRamBytes"] <= 8 << 30,
             "Local Android reviewed consumer resource reservation differs")
    # The existing hosted policy remains untouched and closed.  The marker is
    # minted only by this explicit API after the separate SOURCE digest check.
    return {**A.policy(), "_retained": selected}


def local_instance(A, context):
    A._keys(context, LOCAL_CONTEXT_FIELDS, "Local Android context fields differ")
    A.D.need(context["kind"] == SCOPE
             and all(type(context[k]) is str and re.fullmatch(r"[0-9a-f]{40}", context[k])
                     and context[k] != "0" * 40 for k in ("sourceCommit", "sourceTree"))
             and type(context["taskId"]) is str and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,31}", context["taskId"]),
             "Local Android source/task identity differs")
    # No CI run ID or attempt is fabricated from a local task identifier.
    return "local-" + context["taskId"] + "-" + context["sourceTree"][:12]


@contextmanager
def original_bytes(A, pin, deadline, *, owner=(0, 0), limit=8 << 20):
    """Bound a selected original through read, consuming close and named POST.

    This accepts only a literal SOURCE-selected evidence/input path, not an
    ambient search.  Directory custody begins with this read; historical stage
    directory identities are not misrepresented as current writer identities.
    """
    A._keys(pin, {"path", "size", "sha256", "mode"}, "Local Android original pin fields differ")
    path = A._absolute(pin["path"])
    A.D.need(type(limit) is int and 0 < limit <= 32 << 20
             and type(pin["size"]) is int and 0 <= pin["size"] <= limit
             and type(pin["mode"]) is int and pin["mode"] in {0o400, 0o500, 0o600},
             "Local Android original pin extent/mode differs")
    A.D.sha(pin["sha256"])
    parents = {p: A._directory_identity(p) for p in path.parents}
    original = A._private(path, owner, mode=pin["mode"])

    def recheck(endpoint=deadline):
        A._point(endpoint)
        A.D.need(A._private(path, owner, mode=pin["mode"]) == original,
                 "Local Android original leaf changed")
        for parent, identity in parents.items():
            A.D.need(A._directory_identity(parent) == identity and identity[3:] == [0, 0]
                     and not identity[2] & 0o7022 and not os.listxattr(parent, follow_symlinks=False),
                     "Local Android original canonical ancestry changed")

    primary = None
    try:
        with A._stock_original_bytes(path, original, pin["size"], deadline, recheck) as raw:
            A.D.need(len(raw) == pin["size"] and A._sha(raw) == pin["sha256"],
                     "Local Android original bytes differ from SOURCE")
            yield raw, original
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            # Work never receives a renewed deadline.  A failed read/close
            # still gets its bounded named POST in the original finality
            # reserve (context_original binds work3000/finality3010).
            recheck(deadline + 10)
        except BaseException:
            if primary is None:
                raise
            primary.add_note("Local Android original POST also failed; no publication or retry.")
    A._point(deadline)  # The finality reserve can never turn late work into success.


def context_original(A, context, deadline):
    instance = local_instance(A, context)
    pin = A._keys(context["preparation"], {"path", "size", "sha256"}, "Local Android preparation reference differs")
    path = A._absolute(pin["path"])
    A.D.need(path.name == "local-preparation.json" and type(pin["size"]) is int and 0 < pin["size"] <= 16384,
             "Local Android preparation path/extent differs")
    # A root-owned original describes this existing local preparation owner.
    # It is not created here and is never presented as a hosted preparation.
    with original_bytes(A, {**pin, "mode": 0o600}, deadline) as (raw, identity):
        original = A.D.decode(raw, 16384)
        A._keys(original, ORIGINAL_FIELDS, "Local Android owner original fields differ")
        A.D.need(type(original["schemaVersion"]) is int and original["schemaVersion"] == 1 and original["kind"] == SCOPE
                 and all(original[k] == context[k] for k in ("sourceCommit", "sourceTree", "taskId"))
                 and all(type(original[k]) is int for k in ("readerUid", "readerGid"))
                 and (original["readerUid"], original["readerGid"]) == (0, 0)
                 and all(type(original[k]) is int and 0 < original[k] < 1 << 31
                         for k in ("consumerUid", "consumerGid"))
                 and all(type(original[k]) is str and re.fullmatch(r"[0-9]{1,20}\.[0-9]{1,20}", original[k])
                         and math.isfinite(float(original[k])) for k in ("started", "deadline", "finalityDeadline"))
                 and type(original["workBudgetSeconds"]) is int and original["workBudgetSeconds"] == 3000
                 and type(original["finalityBudgetSeconds"]) is int and original["finalityBudgetSeconds"] == 3010
                 and float(original["started"]) > 0
                 and float(original["deadline"]) == float(original["started"]) + 3000
                 and float(original["finalityDeadline"]) == float(original["started"]) + 3010
                 and type(deadline) in (int, float) and math.isfinite(deadline)
                 and deadline == float(original["deadline"]),
                 "Local Android original source/roles/endpoint differ")
        A.D.need(all(type(original[k]) is list and len(original[k]) == 5
                     and all(type(v) is int for v in original[k])
                     and original[k][2:] == [stat.S_IFDIR | 0o700, 0, 0]
                     for k in ("rootIdentity", "workIdentity")),
                 "Local Android owner directory identity shape differs")
        owner_root, source = A._absolute(original["ownerRoot"]), A._absolute(original["source"])
        A.D.need(path.parent == owner_root and A._directory_identity(owner_root) == original["rootIdentity"]
                 and original["rootIdentity"][2:] == [stat.S_IFDIR | 0o700, 0, 0]
                 and not source.is_relative_to(owner_root) and not owner_root.is_relative_to(source),
                 "Local Android owner/source namespace differs")
        work = owner_root / "work"
        if work.exists() or work.is_symlink():
            A.D.need(A._directory_identity(work) == original["workIdentity"], "Local Android original owner work changed")
    return original, {"instance": instance, "preparationIdentity": identity}


def sdk_state(A, value, host, deadline):
    selected = value["_retained"]
    rules = A._runtime_policy(value)
    expected_rule = {"path": SDK_RECEIPT, "classification": SDK_CLASSIFICATION,
        "licenseDefinition": {"id": "android-sdk-license", "normalizedSha1": A.LICENSE_HASH,
                              "normalizedSha256": A.LICENSE_NORMALIZED_SHA256},
        "packages": [{"id": name, **paths} for name, paths in SDK_PACKAGES.items()]}
    A.D.need(A.D.same(rules["generated"]["sdkLicense"], expected_rule)
             and set(selected["sdkPins"]) <= set(A._input_rules(value)["files"]),
             "Local Android SDK current-use rule differs")
    files = host["bindings"]["files"]
    A.D.need(set(selected["sdkPins"]) <= set(files), "Local Android SDK originals are absent")
    proof = {"classification": SDK_CLASSIFICATION, "currentUse": "selected-local-sdk-no-install-v1",
             "producerExecutionProven": False, "newConsent": False, "packages": {}}

    def observe(path, parse):
        pin = selected["sdkPins"][path]
        primary = None
        try:
            with A._stock_host_original(files[path], path, pin["size"], deadline) as (raw, original):
                A.D.need(len(raw) == pin["size"] and A._sha(raw) == pin["sha256"],
                         "Local Android SDK input differs from SOURCE selection")
                result = {**original, "correspondence": parse(raw)}
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                A._point(deadline + 10)
                A._protected_binding(files[path], path)
            except BaseException:
                if primary is None:
                    raise
                primary.add_note("Local Android SDK original POST also failed; no publication or retry.")
        A._point(deadline)
        return result

    proof["receipt"] = observe(SDK_RECEIPT, A._sdk_receipt_ids)
    for name, paths in SDK_PACKAGES.items():
        proof["packages"][name] = {
            "metadata": observe(paths["metadataPath"], lambda raw: A._sdk_local_package(name, raw)),
            "properties": observe(paths["propertiesPath"], lambda raw: A._sdk_source_properties(name, raw))}
    for path in sorted(selected["sdkPins"]):
        A._point(deadline)
        A._protected_binding(files[path], path)
    return proof


def bind_host(A, native, bindings, *, bind_path, deadline):
    """Explicit closed local roster; never reached by hosted failure handling."""
    value = admitted_value(A)
    inputs = A._input_rules(value)
    A.D.need(type(native) is dict and type(bindings) is dict and type(bindings.get("files")) is dict
             and "androidGenerated" not in native
             and not {"androidDirectories", "androidAbsences", "androidLoader"}.intersection(bindings),
             "Local Android original host graph was already extended")
    host = {"graph": deepcopy(native), "bindings": deepcopy(bindings)}
    files = host["bindings"]["files"]
    for name in inputs["files"]:
        A._point(deadline)
        limit = A._host_input_limit(name)
        if name not in files:
            files[name] = bind_path(Path(name), limit=limit)
        A.D.need(type(files[name].get("size")) is int and 0 <= files[name]["size"] <= limit,
                 "Local Android input role extent differs")
        A._protected_binding(files[name], name)
    for key, paths, options in (("androidDirectories", inputs["directories"], {"directory_only": True}),
                                ("androidAbsences", inputs["absences"], {"absent": True})):
        host["bindings"][key] = {}
        for name in paths:
            A._point(deadline)
            row = bind_path(Path(name), **options)
            A._protected_namespace(row, name, children=inputs["directories"][name]
                                   if key == "androidDirectories" else None, deadline=deadline)
            host["bindings"][key][name] = row
    A._provider_host_inputs(value, host, bind_path, deadline)
    host["graph"]["androidGenerated"] = {"sdkLicense": sdk_state(A, value, host, deadline)}
    return host


def material_rows(A, current, previous, *, generated):
    """Pure complete local mapping; only the reviewed aapt2 duplicate is legal."""
    A.D.need(type(current) is list and type(previous) is list and type(generated) is dict
             and set(generated) == set(A.GENERATED), "Local Android fixed layout input shape differs")
    old = {row["path"]: row for row in previous}
    A.D.need(len(old) == len(previous) == 12371 and len(current) == 12371,
             "Local Android retained/base material roster differs")
    files, mappings = [], []
    for source in current:
        row = {key: source[key] for key in ("path", "size", "sha256", "mode")}
        name = A._tool_path(row["path"])
        if name in ABI_PATHS:
            mapping = {"path": name, "root": "derived", "source": name}
        else:
            retained_name = AAPT2_SOURCE if name == AAPT2_DESTINATION else name
            retained = old.get(retained_name)
            A.D.need(retained is not None and all(row[k] == retained[k] for k in ("size", "sha256"))
                     and row["mode"] == retained["finalMode"],
                     "Local Android retained material differs from current source layout")
            mapping = {"path": name, "root": "retained", "source": retained_name}
        files.append(row)
        mappings.append(mapping)
    for name in A.GENERATED:
        retained = old.get(name)
        pin = generated[name]
        A._keys(pin, {"size", "sha256"}, "Local Android generated original pin differs")
        A.D.need(retained is not None and all(retained[k] == pin[k] for k in pin)
                 and retained["finalMode"] == 0o444,
                 "Local Android retained generated material differs from its current original")
        files.append({"path": name, "mode": 0o444, **pin})
        mappings.append({"path": name, "root": "retained", "source": name})
    files.sort(key=lambda r: r["path"])
    mappings.sort(key=lambda r: r["path"])
    A.D.need(len(files) == 12375 and len({r["path"] for r in files}) == len(files)
             and {r["path"] for r in current} - set(old) == {*ABI_PATHS, AAPT2_DESTINATION}
             and set(old) - {r["path"] for r in current} == set(A.GENERATED),
             "Local Android complete material union differs")
    by_source = {}
    for row in mappings:
        by_source.setdefault((row["root"], row["source"]), []).append(row["path"])
    duplicate = {key: paths for key, paths in by_source.items() if len(paths) > 1}
    A.D.need(duplicate == {("retained", AAPT2_SOURCE): [AAPT2_SOURCE, AAPT2_DESTINATION]},
             "Local Android source aliases are outside the one reviewed aapt2 representation")
    return files, mappings


def retained_layout(A, value, deadline):
    stage = value["_retained"]["stage"]
    A._keys(stage, {"root", "map", "receipt"}, "Local Android retained stage selection differs")
    documents, identities = {}, {}
    for kind in ("map", "receipt"):
        with original_bytes(A, stage[kind], deadline) as (raw, identity):
            documents[kind] = A.D.decode(raw, 8 << 20)
            identities[kind] = identity
    layout, receipt = documents["map"], documents["receipt"]
    A.D.need(layout["stageRoot"] == str(A._absolute(stage["root"]).parent)
             and receipt["toolRoot"] == stage["root"] and receipt["schema"] == 1
             and receipt["status"] == "COMPLETE_PRIVATE_MATERIAL_DATA_ONLY"
             and receipt["map"]["sha256"] == stage["map"]["sha256"]
             and len(layout["files"]) == receipt["materialFiles"] == 12371
             and sum(row["size"] for row in layout["files"]) == receipt["materialBytes"] == 987286104
             and receipt["materialIdentityOrder"] == "exact-map.files"
             and len(receipt["materialFullNineIdentities"]) == len(layout["files"]),
             "Local Android retained layout/receipt correspondence differs")
    for original in receipt["originals"]:
        A.D.need(original["originalExit"] == 0 and original["originalJoined"] is True
                 and original["parserCompleted"] is True and original["streamsClosed"] is True
                 and original["stdoutEof"] is True and original["stderrEof"] is True and original["errors"] == [],
                 "Local Android retained decoder original did not settle")
    leaves = {row["path"]: identity for row, identity in zip(layout["files"], receipt["materialFullNineIdentities"])}
    stage_root = A._absolute(stage["root"]).parent
    directory_names = sorted(str(p) for p in (stage_root, stage_root / "home", stage_root / "tmp",
        stage_root / "tools", *(stage_root / "tools" / name for name in layout["directories"])))
    A.D.need(receipt["directoryIdentityOrder"] == "sorted declared absolute output directories"
             and len(directory_names) == len(receipt["directoryFiveIdentities"])
             and len(leaves) == len(layout["files"]), "Local Android retained original roster differs")
    historical = dict(zip(directory_names, receipt["directoryFiveIdentities"]))
    originals = {"files": leaves, "directories": historical}
    return layout, originals, identities


def retained_tree(A, value, layout, originals, deadline, *, expected_directories=None):
    """Full retained roster and original leaves; fresh read custody for parents.

    The source can be on a separate device from the publication target.  Every
    leaf retains its exact historical full-nine binding; directory identities
    are collected once and required unchanged for this consuming interval.
    Neither storage migration nor a historical directory receipt is silently
    interpreted as a writer-identity match.
    """
    root = A._absolute(value["_retained"]["stage"]["root"])
    names = [A._tool_path(row["path"]) for row in layout["files"]]
    directories = A._parents(names)
    A.D.need(sorted(directories) == layout["directories"], "Local Android retained derived directory roster differs")
    by_name, before, seen, pending = {r["path"]: r for r in layout["files"]}, {}, set(), [(root, "")]
    wanted = set(names) | set(directories) | {""}
    pairs = set()
    while pending:
        A._point(deadline)
        path, name = pending.pop()
        A.D.need(name in wanted and name not in seen and len(seen) < 32768,
                 "Local Android retained namespace has extra or repeated entries")
        seen.add(name)
        if name == "" or name in directories:
            identity = A._private(path, (0, 0), directory=True, mode=0o700)[:5]
            old = originals["directories"][str(path)]
            A.D.need(identity[:1] + identity[2:] == old[:1] + old[2:]
                     and (expected_directories is None or expected_directories.get(name) == identity),
                     "Local Android retained original directory changed")
            before[name] = identity
            children = []
            with os.scandir(path) as entries:
                for entry in entries:
                    A._point(deadline)
                    A.D.need(len(children) + len(pending) + len(seen) < len(wanted),
                             "Local Android retained namespace enumeration bound")
                    children.append((path / entry.name, name + "/" + entry.name if name else entry.name))
            pending.extend(children)
        else:
            row = by_name[name]
            mode = 0o500 if row["finalMode"] & 0o111 else 0o400
            identity = A._private(path, (0, 0), mode=mode)
            A.D.need(identity == originals["files"][name] and identity[6] == row["size"],
                     "Local Android retained original leaf changed")
        A.D.need(tuple(identity[:2]) not in pairs, "Local Android retained namespace contains an inode alias")
        pairs.add(tuple(identity[:2]))
    A.D.need(seen == wanted and (expected_directories is None or before == expected_directories),
             "Local Android retained complete namespace differs")
    for name, identity in before.items():
        A.D.need(A._private(root / name, (0, 0), directory=True, mode=0o700)[:5] == identity,
                 "Local Android retained directory changed during complete readback")
    return before


def source_rows(A, value, material_root, mappings):
    """Compact multi-root references; no duplicate gigabyte private tool tree."""
    return {"schemaVersion": 2, "route": SCOPE,
        "roots": {"retained": {"path": value["_retained"]["stage"]["root"], "owner": [0, 0]},
                  "derived": {"path": str(material_root / "tools"), "owner": [0, 0]}},
        "files": mappings}


def generated_pins(A, host, stock):
    proof = host["graph"]["androidGenerated"]["sdkLicense"]
    A.D.need(proof["classification"] == SDK_CLASSIFICATION and proof["producerExecutionProven"] is False
             and proof["newConsent"] is False, "Local Android SDK proof classification changed")
    files = {A.GENERATED[0]: stock["jks"]["file"], A.GENERATED[2]: proof["receipt"]["file"]}
    for name, package in proof["packages"].items():
        files["sdk/" + name.replace(";", "/") + "/package.xml"] = package["metadata"]["file"]
    return {name: {key: row[key] for key in ("size", "sha256")} for name, row in files.items()}


def _read_material(A, roots, mapping, spec, original, directories, deadline):
    root = A._absolute(roots[mapping["root"]]["path"])
    name = A._tool_path(mapping["source"])
    path = root / name
    mode = 0o500 if spec["mode"] & 0o111 else 0o400

    def recheck(endpoint=deadline):
        A._point(endpoint)
        A.D.need(A._private(path, (0, 0), mode=mode) == original,
                 "Local Android consuming material original changed")
        for parent in path.parents:
            if parent.is_relative_to(root):
                relative = str(parent.relative_to(root))
                relative = "" if relative == "." else relative
                A.D.need(A._private(parent, (0, 0), directory=True, mode=0o700)[:5]
                         == directories[mapping["root"]][relative],
                         "Local Android consuming source ancestor changed")

    primary = None
    try:
        with A._stock_original_bytes(path, original, spec["size"], deadline, recheck) as raw:
            A.D.need(len(raw) == spec["size"] and A._sha(raw) == spec["sha256"],
                     "Local Android consuming material bytes differ")
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            recheck(deadline + 10)
        except BaseException:
            if primary is None:
                raise
            primary.add_note("Local Android consuming source POST also failed; no successor.")
    A._point(deadline)
    return raw, original


def material_reader(A, sources, files, retained, derived, directories, deadline):
    mappings = {row["path"]: row for row in sources["files"]}
    specs = {row["path"]: row for row in files}
    identities = {}
    for name, mapping in mappings.items():
        identities[name] = (retained if mapping["root"] == "retained" else derived)[mapping["source"]]

    def read(name, spec):
        # Provider DATA also records archive provenance/sourceMode.  Compare
        # the complete publication projection, not unlike document schemas.
        A.D.need(name in mappings and type(spec) is dict and set(specs[name]) <= set(spec)
                 and A.D.same({key: spec[key] for key in specs[name]}, specs[name]),
                 "Local Android provider requests an unselected source")
        return _read_material(A, sources["roots"], mappings[name], spec, identities[name], directories, deadline)

    return read, {"files": [{"path": name, "identity": identities[name]} for name in sorted(identities)],
                  "directories": []}


def evidence(A, selected, deadline):
    result = {}
    A.D.need(type(selected) is dict and 0 < len(selected) <= 16, "Local Android retained evidence roster differs")
    for name, pin in selected.items():
        A.D.need(type(name) is str and re.fullmatch(r"[a-zA-Z][a-zA-Z0-9]{0,63}", name),
                 "Local Android retained evidence role differs")
        with original_bytes(A, pin, deadline) as (_, identity):
            result[name] = {"pin": pin, "identity": identity}
    return result


def abi_decoder_records(A, root, compiler_root, indexes, deadline, *, expected=None):
    records = {}
    for index in indexes:
        A._point(deadline)
        label = "android-decode-" + index["id"]
        proof = A._font_owner_records(compiler_root, label, (0, 0),
                                     expected=None if expected is None else expected[index["id"]])
        rows = {row["path"]: row for row in proof["files"]}
        captures = compiler_root / "private-material"
        request = A.D.decode(A.D.read(captures / (label + ".request.json"), 64 << 10), 64 << 10)
        result = A.D.decode(A.D.read(captures / (label + ".result.json"), 128 << 10), 128 << 10)
        argv = ["/usr/bin/bash", "--noprofile", "--norc", "-c", A.DECODER_SCRIPT,
            "mrk-fixed-android-decoder", str(math.ceil(index["decodedBytes"] / 1024)),
            str(root / "decoded" / (index["id"] + ".tar")), "/usr/bin/dpkg-deb", "--fsys-tarfile",
            str(root / "bodies" / index["id"])]
        A._keys(request, {"phase", "argv", "timeoutSeconds"}, "Local Android decoder request differs")
        A.D.need(request["phase"] == label and request["argv"] == argv
                 and type(request["timeoutSeconds"]) is int and 1 <= request["timeoutSeconds"] <= 120
                 and all(rows[label + "." + suffix]["size"] == 0 for suffix in ("stdout", "stderr")),
                 "Local Android decoder original command/captures differ")
        wanted = {**request, "exitCode": 0, "ordinaryOwnerReturned": True,
            "captures": {suffix: {key: rows[label + "." + suffix][key] for key in ("size", "sha256")}
                         for suffix in ("stdout", "stderr")}}
        A.D.need(A.D.same(result, wanted), "Local Android decoder original did not settle")
        A._font_owner_records(compiler_root, label, (0, 0), expected=proof)
        records[index["id"]] = proof
    A.D.need(expected is None or records == expected, "Local Android decoder original record roster differs")
    return records


def abi_selection(A, value):
    inputs = value["_retained"]["abiBodies"]
    A._keys(inputs, {"body-146", "body-147"}, "Local Android ABI5 retained body roster differs")
    suppliers = A._control(value, "suppliers.json")["files"]
    archives = A._control(value, "archives.json.gz")["archives"]
    by_id = {row["id"]: row for row in suppliers}
    indexes = [row for row in archives if row["id"] in inputs]
    A.D.need({row["id"] for row in indexes} == set(inputs) and len(indexes) == 2,
             "Local Android fixed ABI5 archive indexes differ")
    for name, pin in inputs.items():
        A.D.need(all(pin[key] == by_id[name][key] for key in ("size", "sha256")) and pin["mode"] == 0o400,
                 "Local Android retained ABI5 body differs from authenticated supplier")
    files = [row for row in A._control(value, "layout.json.gz")["files"] if row["path"] in ABI_PATHS]
    A.D.need(len(files) == 3 and {row["path"] for row in files} == set(ABI_PATHS),
             "Local Android exact ABI5 derived selection differs")
    return inputs, indexes, files, A._archive_routes(files, suppliers, indexes)


def capacity(A, value, parent, files, indexes, deadline):
    A._point(deadline)
    runtime = value["_retained"]["runtime"]
    # One new protected publication, not a second private gigabyte copy.  All
    # decoder bodies, new ABI5 leaves and metadata remain charged concurrently;
    # no credit is taken for their eventual deletion or native cleanup.
    additions = sum(row["size"] for row in files if row["path"] in ABI_PATHS)
    required = (sum(row["size"] for row in files) + additions
                + sum(row["size"] for row in value["_retained"]["abiBodies"].values())
                + max(row["decodedBytes"] for row in indexes)
                + runtime["consumerScratchBytes"] + (64 << 20))
    entries = len(files) + len(A._parents([row["path"] for row in files])) + 128
    charged = 0
    # The existing publisher targets /opt, not the private staging directory.
    # Check both possible filesystems without assuming a tmpfs/work mount has
    # the final target's capacity.  Requiring the conservative simultaneous
    # total on each avoids taking duplicate capacity or deletion credit.
    for selected in (parent, Path("/opt")):
        A._point(deadline)
        space = os.statvfs(selected)
        extent = required + entries * space.f_frsize
        A.D.need(space.f_bavail * space.f_frsize >= extent and space.f_favail >= entries,
                 "Local Android simultaneous publication/consumer capacity is unavailable")
        charged = max(charged, extent)
    import resource  # The explicit preparer is Linux-only; DATA imports remain portable.
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    A.D.need(soft == resource.RLIM_INFINITY or soft >= 65536,
             "Local Android original descriptor admission floor is unavailable")
    memory_path = Path("/proc/meminfo")
    original = A._identity(memory_path.lstat())
    A.D.need(stat.S_ISREG(original[2]) and original[3:5] == [0, 0],
             "Local Android RAM source is not the fixed kernel file")
    descriptor = os.open("/proc/meminfo", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    primary = None
    try:
        A.D.need(A._identity(os.fstat(descriptor)) == original, "Local Android RAM source changed before read")
        raw = os.read(descriptor, (64 << 10) + 1)
        A.D.need(len(raw) <= 64 << 10 and not os.read(descriptor, 1), "Local Android RAM observation bound")
        A.D.need(A._identity(os.fstat(descriptor)) == original, "Local Android RAM source changed during read")
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            os.close(descriptor)
        except BaseException as error:
            if primary is None:
                primary = error
                raise
            primary.add_note("Local Android RAM original close also failed; no retry.")
        finally:
            try:
                A._point(deadline + 10)
                A.D.need(A._identity(memory_path.lstat()) == original,
                         "Local Android RAM source changed after consuming close")
            except BaseException:
                if primary is None:
                    raise
                primary.add_note("Local Android RAM original POST also failed; no publication.")
    available = re.search(rb"^MemAvailable:\s+([0-9]+) kB$", raw, re.M)
    A.D.need(available is not None and int(available[1]) * 1024 >= runtime["minimumAvailableRamBytes"],
             "Local Android reviewed RAM headroom is unavailable")
    A._point(deadline)
    return {"requiredBytes": charged, "requiredInodes": entries,
            "consumerScratchBytes": runtime["consumerScratchBytes"], "deletionCredit": 0,
            "requiredDescriptorFloor": 65536, "observedDescriptorLimit": soft}


LOCAL_PRIVATE = {"context": 64 << 10, "host": 32 << 20, "provenance": 8 << 20}


def namespace(A, root, deadline):
    root_names = {"private", "bodies", "decoded", "home", "tmp", "tools", *(name for name, _ in A.DOCS.values())}
    private = {key + ".json": limit for key, limit in LOCAL_PRIVATE.items()}
    private.update({**A.FONT_OUTPUTS, **A.PROVIDER_OUTPUTS, "prepared.json": 64 << 10})
    expected = {root: root_names, root / "private": set(private)}
    expected.update({root / name: set() for name in ("bodies", "decoded", "home", "tmp")})
    directories = {}
    for path, names in expected.items():
        A._point(deadline)
        identity = A._private(path, (0, 0), directory=True, mode=0o700)[:5]
        with os.scandir(path) as entries:
            observed = set()
            for entry in entries:
                A.D.need(len(observed) < len(names) and entry.name in names and entry.name not in observed,
                         "Local Android preparation has an undeclared output")
                observed.add(entry.name)
        A.D.need(observed == names and A._private(path, (0, 0), directory=True, mode=0o700)[:5] == identity,
                 "Local Android preparation namespace changed")
        directories[str(path.relative_to(root))] = identity
    for name, limit in private.items():
        A.D.need(A._private(root / "private" / name, (0, 0))[6] <= limit,
                 "Local Android retained output bound differs")
    return directories


def prepare(A, check, source, material_root, *, context, host):
    """Use the caller's existing owner/end/latch; no new process owner exists."""
    value = admitted_value(A)  # Missing actual profile refuses before any I/O creation or command.
    original, binding = context_original(A, context, check.end)
    A.D.need(not check.failed and (os.getuid(), os.getgid()) == (0, 0)
             and check.root == A._absolute(original["ownerRoot"])
             and check.end == float(original["deadline"]) and source == A._absolute(original["source"])
             and material_root == check.root / "work/android-retained",
             "Local Android original owner/source/material endpoint differs")
    contract, _ = A._host_state(value, host, check.end)
    stock = A._stock_trust_state(value, host, check.end)
    layout, retained, layout_identities = retained_layout(A, value, check.end)
    retained_directories = retained_tree(A, value, layout, retained, check.end)
    files, mappings = material_rows(A, A._control(value, "layout.json.gz")["files"], layout["files"],
                                    generated=generated_pins(A, host, stock))
    sources = source_rows(A, value, material_root, mappings)
    documents, materials, publication = A._documents(value, context, files, contract,
        instance=binding["instance"], source_rows=sources)
    inputs, indexes, derived_files, routes = abi_selection(A, value)
    retained_evidence = evidence(A, value["_retained"]["evidence"], check.end)
    reservation = capacity(A, value, material_root.parent, files, indexes, check.end)
    material_root.mkdir(mode=0o700)
    directories = {".": A._private(material_root, (0, 0), directory=True, mode=0o700)[:5]}
    for name in ("private", "bodies", "decoded", "home", "tmp", "tools"):
        A._staging_mkdir(material_root, name, directories, (0, 0))
    for name in A._parents([row["path"] for row in derived_files]):
        A._staging_mkdir(material_root, "tools/" + name, directories, (0, 0))
    references = {}
    for key, data in (("context", context), ("host", host)):
        raw = A.D.canonical(data)
        A.D.need(len(raw) <= LOCAL_PRIVATE[key], "Local Android private input document bound")
        references[key] = A.D.write(material_root / "private" / (key + ".json"), raw, 0o400)
    font = A._font_consumers(check, value, host, material_root, (0, 0), directories)
    provider = A._provider_consumers(check, value, host, material_root, (0, 0), directories)
    originals, body_originals = {}, {}
    for index in indexes:
        pin = inputs[index["id"]]
        with original_bytes(A, pin, check.end) as (raw, retained_identity):
            path = material_root / "bodies" / index["id"]
            A.D.write(path, raw, 0o400)
            body_originals[index["id"]] = {"sourceIdentity": retained_identity,
                "copyIdentity": A._private(path, (0, 0)), "pin": pin}
        A._archive(check, material_root, index, routes[index["id"]], (0, 0), directories, originals)
    decoders = abi_decoder_records(A, material_root, check.root, indexes, check.end)
    derived = A._tree(material_root, derived_files, (0, 0), check.end, directories=directories, originals=originals)
    derived_directories = {"" if row["path"] == "." else row["path"]: row["identity"] for row in derived["directories"]}
    reader, inventory = material_reader(A, sources, files, retained["files"], originals,
        {"retained": retained_directories, "derived": derived_directories}, check.end)
    provider["graph"] = A._provider_material_graph(value, material_root, (0, 0), inventory, check.end, source_reader=reader)
    A.D.need(A._host_state(value, host, check.end)[0] == contract
             and A._stock_trust_state(value, host, check.end) == stock,
             "Local Android current-use/runtime inputs changed during preparation")
    retained_tree(A, value, layout, retained, check.end, expected_directories=retained_directories)
    A.D.need(retained_layout(A, value, check.end) == (layout, retained, layout_identities)
             and evidence(A, value["_retained"]["evidence"], check.end) == retained_evidence,
             "Local Android retained source evidence changed")
    A._font_readback(value, host, material_root, (0, 0), directories, check.root, font, check.end)
    A._provider_capture_readback(value, host, material_root, (0, 0), directories, check.root, provider, check.end)
    for key, raw in documents.items():
        A.D.write(material_root / A.DOCS[key][0], raw, 0o400)
    provenance = {"policySha256": POLICY_SHA256, "contextSha256": A._sha(A.D.canonical(context)),
        "hostSha256": A._sha(A.D.canonical(host)), "contextBinding": binding, "directories": directories,
        "retainedDirectories": retained_directories, "retainedEvidence": retained_evidence,
        "layoutIdentities": layout_identities, "derived": derived, "abiBodies": body_originals,
        "abiDecoders": decoders, "stockTrust": stock, "fontConsumers": font, "providerConsumers": provider,
        "capacity": reservation, "producerExecutionProven": False, "newConsent": False, "qualification": False}
    raw = A.D.canonical(provenance)
    A.D.need(len(raw) <= LOCAL_PRIVATE["provenance"], "Local Android retained provenance bound")
    references["provenance"] = A.D.write(material_root / "private/provenance.json", raw, 0o400)
    record = {"schemaVersion": 1, "scope": SCOPE, "materialRoot": str(material_root), "materials": materials,
        "publication": publication, "provenance": {"policySha256": POLICY_SHA256, "documents": references}}
    # Only these successfully consumed, task-owned copies are disposable. The
    # retained originals, old stage, failures and decoder evidence stay intact.
    for name, body in body_originals.items():
        path = material_root / "bodies" / name
        A.D.need(A._private(path, (0, 0)) == body["copyIdentity"], "Local Android consumed ABI5 copy changed")
        path.unlink()
    A.D.need(not check.failed and len(A.D.canonical(record)) <= 64 << 10,
             "Local Android compact preparation is failed or oversized")
    A.D.write(material_root / "private/prepared.json", A.D.canonical(record), 0o400)
    namespace(A, material_root, check.end)
    return validate(A, record, context=context, host=host, deadline=check.end)


def validate(A, record, *, context, host, deadline):
    """Original readback only. No download, decoder, native command or retry."""
    value = admitted_value(A)
    A._keys(record, {"schemaVersion", "scope", "materialRoot", "materials", "publication", "provenance"},
            "Local Android compact preparation fields differ")
    A.D.need(type(record["schemaVersion"]) is int and record["schemaVersion"] == 1 and record["scope"] == SCOPE,
             "Local Android preparation scope differs")
    original, binding = context_original(A, context, deadline)
    root, owner_root = A._absolute(record["materialRoot"]), A._absolute(original["ownerRoot"])
    A.D.need(root == owner_root / "work/android-retained", "Local Android material namespace differs")
    A._keys(record["provenance"], {"policySha256", "documents"}, "Local Android compact provenance differs")
    A.D.need(record["provenance"]["policySha256"] == POLICY_SHA256, "Local Android source policy changed")
    refs = A._keys(record["provenance"]["documents"], LOCAL_PRIVATE, "Local Android private document roster differs")
    private = {}
    for key, pin in refs.items():
        A._keys(pin, {"path", "size", "sha256"}, "Local Android private document reference differs")
        A.D.need(pin["path"] == key + ".json" and type(pin["size"]) is int and 0 < pin["size"] <= LOCAL_PRIVATE[key],
                 "Local Android private original path/extent differs")
        with original_bytes(A, {**pin, "path": str(root / "private" / pin["path"]), "mode": 0o400}, deadline,
                            limit=LOCAL_PRIVATE[key]) as (raw, _):
            private[key] = A.D.decode(raw, LOCAL_PRIVATE[key])
    A.D.need(A.D.same(private["context"], context) and A.D.same(private["host"], host),
             "Local Android original private inputs changed")
    p = private["provenance"]
    A._keys(p, {"policySha256", "contextSha256", "hostSha256", "contextBinding", "directories", "retainedDirectories",
        "retainedEvidence", "layoutIdentities", "derived", "abiBodies", "abiDecoders", "stockTrust", "fontConsumers",
        "providerConsumers", "capacity", "producerExecutionProven", "newConsent", "qualification"},
        "Local Android retained provenance fields differ")
    A.D.need(p["policySha256"] == POLICY_SHA256 and p["contextSha256"] == A._sha(A.D.canonical(context))
             and p["hostSha256"] == A._sha(A.D.canonical(host)) and p["contextBinding"] == binding
             and p["producerExecutionProven"] is False and p["newConsent"] is False and p["qualification"] is False,
             "Local Android source/context/claim binding changed")
    contract, _ = A._host_state(value, host, deadline)
    stock = A._stock_trust_state(value, host, deadline)
    A.D.need(stock == p["stockTrust"], "Local Android trust original changed")
    layout, retained, layout_ids = retained_layout(A, value, deadline)
    A.D.need(layout_ids == p["layoutIdentities"], "Local Android retained evidence originals changed")
    retained_tree(A, value, layout, retained, deadline, expected_directories=p["retainedDirectories"])
    files, mappings = material_rows(A, A._control(value, "layout.json.gz")["files"], layout["files"],
                                    generated=generated_pins(A, host, stock))
    sources = source_rows(A, value, root, mappings)
    raw, materials, publication = A._documents(value, context, files, contract,
        instance=binding["instance"], source_rows=sources)
    A.D.need(A.D.same(record["materials"], materials) and A.D.same(record["publication"], publication),
             "Local Android complete publication projection differs")
    for key, body in raw.items():
        path = root / A.DOCS[key][0]
        with original_bytes(A, {"path": str(path), "size": len(body), "sha256": A._sha(body), "mode": 0o400}, deadline) as (observed, _):
            A.D.need(observed == body, "Local Android original publication document changed")
    inputs, indexes, derived_files, _ = abi_selection(A, value)
    A._keys(p["abiBodies"], inputs, "Local Android ABI5 consuming-original roster differs")
    for name, pin in inputs.items():
        row = p["abiBodies"][name]
        A._keys(row, {"sourceIdentity", "copyIdentity", "pin"}, "Local Android ABI5 source/copy record differs")
        with original_bytes(A, pin, deadline) as (_, identity):
            A.D.need(row["pin"] == pin and row["sourceIdentity"] == identity,
                     "Local Android ABI5 retained source changed")
        A.D.need(type(row["copyIdentity"]) is list and len(row["copyIdentity"]) == 9
                 and row["copyIdentity"][2:7] == [stat.S_IFREG | 0o400, 0, 0, 1, pin["size"]],
                 "Local Android successfully consumed ABI5 copy record differs")
    abi_decoder_records(A, root, owner_root, indexes, deadline, expected=p["abiDecoders"])
    derived_ids = {row["path"]: row["identity"] for row in p["derived"]["files"]}
    derived = A._tree(root, derived_files, (0, 0), deadline, directories=p["directories"], originals=derived_ids)
    A.D.need(derived == p["derived"], "Local Android derived original tree changed")
    dirs = {"retained": p["retainedDirectories"],
            "derived": {"" if row["path"] == "." else row["path"]: row["identity"] for row in derived["directories"]}}
    reader, inventory = material_reader(A, sources, files, retained["files"], derived_ids, dirs, deadline)
    graph = A._provider_material_graph(value, root, (0, 0), inventory, deadline, source_reader=reader)
    A.D.need(graph == p["providerConsumers"]["graph"], "Local Android retained provider/context graph changed")
    A._font_readback(value, host, root, (0, 0), p["directories"], owner_root, p["fontConsumers"], deadline)
    A._provider_capture_readback(value, host, root, (0, 0), p["directories"], owner_root, p["providerConsumers"], deadline)
    A.D.need(evidence(A, value["_retained"]["evidence"], deadline) == p["retainedEvidence"],
             "Local Android retained evidence bytes or identity changed")
    observed_namespace = namespace(A, root, deadline)
    A.D.need(all(p["directories"].get(name) == identity for name, identity in observed_namespace.items()),
             "Local Android original preparation directories changed")
    A._point(deadline)
    return record


def read_record(A, path, expected, *, context, host, deadline):
    A._keys(expected, {"size", "sha256"}, "Local Android record pin differs")
    A.D.need(type(expected["size"]) is int and 0 < expected["size"] <= 64 << 10,
             "Local Android compact record extent differs")
    with original_bytes(A, {"path": str(path), **expected, "mode": 0o400}, deadline) as (raw, _):
        record = A.D.decode(raw, 64 << 10)
        A.D.need(path == A._absolute(record["materialRoot"]) / "private/prepared.json",
                 "Local Android compact record namespace differs")
        result = validate(A, record, context=context, host=host, deadline=deadline)
    return result


def publication_inputs(A, record, *, context, host, deadline):
    """Validated existing-owner adapter, before the ordinary protected copier."""
    validate(A, record, context=context, host=host, deadline=deadline)
    root = A._absolute(record["materialRoot"])
    raw = {key: A.D.read(root / name, limit) for key, (name, limit) in A.DOCS.items()}
    pin = record["provenance"]["documents"]["provenance"]
    with original_bytes(A, {**pin, "path": str(root / "private/provenance.json"), "mode": 0o400}, deadline) as (body, _):
        p = A.D.decode(body, LOCAL_PRIVATE["provenance"])
    _, retained, _ = retained_layout(A, admitted_value(A), deadline)
    originals = {"retained": {**p["retainedDirectories"], **retained["files"]},
        "derived": {**{"" if r["path"] == "." else r["path"]: r["identity"] for r in p["derived"]["directories"]},
                    **{r["path"]: r["identity"] for r in p["derived"]["files"]}}}
    return {"scope": SCOPE, "context": context, "record": record, "raw": raw,
        "sourceOriginals": originals,
        "request": {"sourceRoot": str(root / "tools"), "totals": record["publication"]["totals"],
            "documents": {key: {"path": str(root / A.DOCS[key][0]), **pin}
                          for key, pin in record["publication"]["documents"].items()}}}
