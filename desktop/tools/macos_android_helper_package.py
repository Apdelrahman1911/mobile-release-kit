#!/usr/bin/env python3
"""Fixed engineering Android-helper packaging, never service registration.

Fixed helper prepare/verify and ordinary package-install entries reuse the same
original process owner. Import is DATA-only; the hosted main alone loads that
owner. SOURCE selects the signing identity. The unconfigured helper engineering
path is separate; ordinary V2 distribution requires genuine configured inputs.
"""
from __future__ import annotations

import argparse
import base64
import codecs
import contextlib
import hashlib
import importlib.util
import json
import os
import plistlib
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import time
from types import MappingProxyType

CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
WORK_PARENT = Path("/Users/runner/work/_temp")
HELPER = "mrk-android-register"
ENTRY = "mrk-macos-entry"
DESKTOP_FACADE = "mobile-release-kit-desktop"
RESIDENT_IMAGE = "libmrk_resident_image.dylib"
IMAGE_TARGET = "mrk_resident_image"
PREPARE_ROLES = ("build", "resident-image-sign", "resident-image-verify-signed", "entry-build",
                 "desktop-facade-build", "resident-facade-build", "sign", "verify-signed")
IDENTIFIER = "dev.mobile-release-kit.desktop.android-register"
WORKSPACE = "desktop/helpers/macos-android-register"
PROFILE = "desktop/packaging/macos-android-service-signing.profile"
UNCONFIGURED_PROFILE = (
    b"schema=1\napp-identifier=dev.mobile-release-kit.desktop\n"
    b"helper-identifier=dev.mobile-release-kit.desktop.android-register\n"
    b"team-identifier=unconfigured\ndeveloper-id-certificate-sha1=unconfigured\n"
)
PACKAGE_SCOPES = (
    "project-fields", "ios-current-synthetic", "android-inputs",
    "project-fields-android-inputs", "vault-helper-shipping",
    "installation-inspection", "vault-helper-shipping-installation-inspection",
    "project-recovery-pending", "ios-recovery-pending", "doctor-preflight2", "local-edits3",
)
APP_ABSENCE_REF = "refs/heads/verify/desktop-macos-app-absence-fixture"
RESTORE_CHAIN_REF = "refs/heads/verify/desktop-macos-restore-chain-fixture"
APP_ABSENCE_PHASES = ("prepare-app-absence", "app-absence-restore")
UPDATE_REF = "refs/heads/verify/desktop-macos-positive-update"
UPDATE_PHASE = "update-baseline"
UPDATE_ROLES = ("update-baseline-attach", "update-baseline-installer", "update-baseline-detach")
XCODE_SETUP_VERIFY = "verify-xcode-setup-package"
XCODE_SETUP_VERIFY_ROLES = ("setup-signature-before", "setup-log-cursor", "setup-installer-first", "setup-installer-repeat", "setup-signature-after")
XCODE_SETUP_VERIFY_TIMEOUTS = (30, 30, 3900, 900, 30)
XCODE_SETUP_LOG_CAPTURE = "setup-log-capture"
SAME_PACKAGE_PHASE = "same-package-noop"
SAME_PACKAGE_ROLES = ("distribution-attach", "installer", "distribution-detach")
PHASES = ("prepare", "verify-before", "verify-after", "package-install", "package-remove", SAME_PACKAGE_PHASE, UPDATE_PHASE, XCODE_SETUP_VERIFY) + APP_ABSENCE_PHASES
REMOVE_PHASES = ("finalize-remove-package", "package-remove", "finalize-remove-image")
REMOVE_PACKAGE_ROLES = ("producer-build", "producer-emitter", "distribution-create", "distribution-sign",
                        "distribution-verify-signature", "distribution-verify-image")
PRODUCER_PROFILE = "desktop/packaging/macos-install-producer-signing.profile"
ARM_TARGET = "aarch64-apple-darwin"
INTEL_TARGET = "x86_64-apple-darwin"
MAX_HELPER = 32 * 1024 * 1024
# Only nonshipping producer graphs use this opt0 override.
PRODUCER_CARGO_OVERRIDE = "profile.release.package.mobile-release-kit-desktop.opt-level=0"
# Intel alone uses this fixed shared-package release optimization.
# Runtime dependencies retain release3; generic code instantiated here inherits release1.
RESIDENT_CARGO_OVERRIDE = "profile.release.package.mobile-release-kit-desktop.opt-level=1"
# Bounded SOURCE input, not an exact historical implementation length. Keep
# normal maintenance from invalidating every packaging consumer of this file.
HELPER_SOURCE_BYTES = 1024 * 1024
# Closed first-failed metadata attribution; no dynamic role/path rendering.
FINAL_IMAGE_VERIFY_FIELDS = ("device", "inode", "mode", "links", "uid", "gid", "size", "mtime", "ctime")
FINAL_IMAGE_VERIFY_OBJECTS = ("output", *("input-%02d" % index for index in range(14)))
FINAL_IMAGE_VERIFY_STAGES = frozenset(
    "final-image-verify-%s-%s-%s" % (object_label, boundary, field)
    for object_label in FINAL_IMAGE_VERIFY_OBJECTS for boundary in ("held", "named")
    for field in FINAL_IMAGE_VERIFY_FIELDS)
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


STORE_SIGNING_PHASES = ("sign-store-runtime",)
STORE_SIGNING_REF = "refs/heads/verify/desktop-macos-store-signing"
SUPPORT_PHASES = ("android-support-shipping",)
SUPPORT_REF = "refs/heads/verify/desktop-macos-android-support-signing"
SUPPORT_IDENTIFIERS = tuple("dev.mobile-release-kit.desktop.android-support." + role
                            for role in ("bundletool-aapt2", "bundletool-jna", "agp-aapt2"))
PYTHON_PHASES = ("python-engineering", "python-shipping")
PYTHON_IDENTIFIER = "dev.mobile-release-kit.desktop.python"
PYTHON_ROLES = ("python-sign", "python-verify", "python-modules", "python-loader", "python-tls", "python-cancellation")
PYTHON_SUPPLIERS = {
    ARM_TARGET: {'receiptSha256': '1e7a28664e9234660fe8377a7a7b3bee5438faf09d40224d2db81ba2d9358809', 'tarSha256': '2835fd45d443c429c2a9f12e9cdbcff109f35a15207ca5a086da24c0b6e338a5', 'sourceCommit': '52485f9fd837f0dacb8dc9621e5a1bee30803506', 'runId': '38343324660', 'runAttempt': '1', 'artifactId': '11788410124'},
    INTEL_TARGET: {'receiptSha256': 'afba303207b19692b73fb1288b56afcd73378fc29b0b0ede4ff10eb2e0f949b8', 'tarSha256': 'ff976626b48e95abc414d46ff91f1ebb183416356bb4706b8e673b7c9018ca9c', 'sourceCommit': 'a2f7a10b4c86305f5ee65c6779ceaf6b128cd8fa', 'runId': '38343340695', 'runAttempt': '1', 'artifactId': '11787588635'},
}


SIGNING_PHASES = ("sign-vault-helper", "sign-installed-cli", "sign-desktop-image", "sign-desktop-payload", "sign-root-app", "sign-root-installer", "sign-remover", "sign-applications-launcher", "sign-xcode-setup")
INSTALLED_CLI_IDENTIFIER = "dev.mobile-release-kit.desktop.cli"
XCODE_SETUP_IDENTIFIER = "dev.mobile-release-kit.desktop.xcode-setup"
CREDENTIAL_VARIABLES = ("MRK_MACOS_DEVELOPER_ID_P12_BASE64", "MRK_MACOS_DEVELOPER_ID_P12_PASSWORD")
CREDENTIAL_ROLES = ("search-before", "default-before", "create", "search-created", "settings", "unlock", "import",
                    "partitions", "identity", "certificates", "search-admit", "restrict", "search-restricted",
                    "search-after-callback", "restore", "search-restored", "delete", "default-after", "search-final",
                    "producer-adhoc", "producer-adhoc-verify", "producer-cdhash", "installer-chain")


# Fixed current build/signed capsule nominations. DATA never selects a path,
# keychain, executable identifier, command, credential or signing identity.
TOOL_SIGNING_PHASES = ("sign-history-provider", "sign-github-seal")
TOOL_SELECTION_PHASES = ("select-history-provider-build", "select-github-seal-build", "select-github-tools-signed")
TOOL_PROJECT_PHASES = ("project-history-provider", "project-github-seal")
TOOL_NOMINATION = "desktop/macos-installed-inputs/github-tool-signing.json"
TOOL_REF = "refs/heads/verify/desktop-macos-github-tool-signing"
TOOL_FIXED = {
    "history-provider": ("gh", "dev.mobile-release-kit.desktop.github-history-provider", 64 * 1024 * 1024),
    "github-seal": ("mrk-github-seal", "dev.mobile-release-kit.desktop.github-seal", 16 * 1024 * 1024),
}
TOOL_RECEIPT_LIMIT = 16384


def tool_hex(value, size=64):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % size, value) is not None and value != "0" * size


def tool_id(value):
    return (type(value) is str and re.fullmatch(r"[1-9][0-9]{0,15}", value) is not None
            and int(value) <= 9007199254740991)


def tool_json(body):
    need(type(body) is bytes and 0 < len(body) <= TOOL_RECEIPT_LIMIT, "tool-json-bound")
    def pairs(items):
        need(len(items) <= 64 and len({key for key, _ in items}) == len(items), "tool-json-keys")
        return dict(items)
    def integer(value):
        need(len(value) <= 20, "tool-json-integer")
        return int(value)
    def reject(_value):
        raise Refused("tool-json-number")
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_int=integer,
                           parse_float=reject, parse_constant=reject)
    except (UnicodeError, ValueError, RecursionError):
        raise Refused("tool-json-format") from None
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop(); count += 1
        need(depth <= 16 and count <= 4096, "tool-json-graph")
        if type(item) is dict:
            pending.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            need(len(item) <= 128, "tool-json-list")
            pending.extend((v, depth + 1) for v in item)
    need(type(value) is dict, "tool-json-object")
    return value


def tool_canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def tool_nomination_data(body):
    value = tool_json(body)
    need(set(value) == {"schemaVersion", "tools"} and type(value["schemaVersion"]) is int
         and value["schemaVersion"] == 1 and type(value["tools"]) is dict
         and set(value["tools"]) == set(TOOL_FIXED), "tool-nomination-shape")
    build_fields = {"state", "sourceCommit", "sourceManifestSha256", "binarySha256", "binaryBytes",
                    "buildReceiptSha256", "runId", "runAttempt", "artifactId", "notices"}
    signed_fields = {"state", "buildSha256", "signingSourceCommit", "signedSha256", "signedBytes", "receiptSha256",
                     "runId", "runAttempt", "artifactId", "producerProfileSha256",
                     "serviceProfileSha256", "entitlementsSha256"}
    for purpose, targets in value["tools"].items():
        need(type(targets) is dict and set(targets) == {ARM_TARGET, INTEL_TARGET}, "tool-nomination-targets")
        for row in targets.values():
            need(type(row) is dict and set(row) == {"build", "signed"}, "tool-nomination-row")
            build, signed = row["build"], row["signed"]
            need(type(build) is dict and type(signed) is dict, "tool-nomination-states")
            if build != {"state": "unconfigured"}:
                need(set(build) == build_fields and build["state"] == "configured"
                     and tool_hex(build["sourceCommit"], 40)
                     and all(tool_hex(build[k]) for k in ("sourceManifestSha256", "binarySha256", "buildReceiptSha256"))
                     and all(tool_id(build[k]) for k in ("runId", "runAttempt", "artifactId"))
                     and type(build["binaryBytes"]) is int and 0 < build["binaryBytes"] <= TOOL_FIXED[purpose][2],
                     "tool-build-nomination")
                notices = build["notices"]
                if purpose == "history-provider":
                    need(type(notices) is dict and set(notices) == {"manifestSha256", "contentSha256", "files", "modules"}
                         and tool_hex(notices["manifestSha256"]) and tool_hex(notices["contentSha256"])
                         and type(notices["files"]) is int and notices["files"] == 333
                         and type(notices["modules"]) is int and notices["modules"] == 162, "tool-notices-complete-nomination")
                else:
                    need(notices is None, "tool-seal-no-gh-notices")
            if signed != {"state": "unconfigured"}:
                need(build["state"] == "configured" and set(signed) == signed_fields and signed["state"] == "configured"
                     and signed["buildSha256"] == digest(tool_canonical(build))
                     and tool_hex(signed["signingSourceCommit"], 40)
                     and all(tool_hex(signed[k]) for k in ("signedSha256", "receiptSha256",
                                                          "producerProfileSha256", "serviceProfileSha256", "entitlementsSha256"))
                     and all(tool_id(signed[k]) for k in ("runId", "runAttempt", "artifactId"))
                     and type(signed["signedBytes"]) is int and 0 < signed["signedBytes"] <= TOOL_FIXED[purpose][2],
                     "tool-signed-nomination")
    return value


def tool_build_origin(value):
    """Closed reference to the real local build, not a GitHub compiler run.

    The complete normalized receipt is separately SOURCE-hash nominated after
    the actual result adapter checks the referenced originals. These reference
    fields alone do not authenticate arbitrary reports or grant finality.
    """
    references = {"result": 256 * 1024, "closedSummary": 16384, "crossbuild": 65536,
                  "buildInfo": 65536}
    true_fields = ("allJoinedZeroAndPipesClosed", "sourcePost", "dependencyPost", "toolchainPost", "embeddedNoticesComplete")
    false_fields = ("noticeContentRuntimeExecuted", "nativeExecuted", "developerIdSigned", "notarized")
    need(type(value) is dict and set(value) == set(references) | set(true_fields) | set(false_fields)
         | {"kind", "sourceInventory", "dependencyInventorySha256", "toolchainInventorySha256", "childOriginals", "namespaceOriginals"}
         and value["kind"] == "offline-owned-crossbuild"
         and type(value["childOriginals"]) is int and value["childOriginals"] == 5
         and type(value["namespaceOriginals"]) is int and value["namespaceOriginals"] == 1
         and all(value[k] is True for k in true_fields) and all(value[k] is False for k in false_fields)
         and tool_hex(value["dependencyInventorySha256"]) and tool_hex(value["toolchainInventorySha256"]), "tool-build-origin")
    for name, limit in references.items():
        row = value[name]
        need(type(row) is dict and set(row) == {"bytes", "sha256"}
             and type(row["bytes"]) is int and 0 < row["bytes"] <= limit and tool_hex(row["sha256"]), "tool-build-reference")
    row = value["sourceInventory"]
    need(type(row) is dict and set(row) == {"bytes", "sha256", "fileCount", "fileBytes"}
         and tool_hex(row["sha256"]) and all(type(row[k]) is int for k in ("bytes", "fileCount", "fileBytes"))
         and 0 < row["bytes"] <= 1024 * 1024 and 0 < row["fileCount"] <= 2048
         and 0 < row["fileBytes"] <= 32 * 1024 * 1024, "tool-build-source-reference")


def tool_build_receipt(body, build, purpose, target):
    """Normalized, independently source-nominated FINAL build facts; not a raw probe."""
    need(digest(body) == build["buildReceiptSha256"], "tool-build-receipt-anchor")
    value = tool_json(body)
    need(set(value) == {"schemaVersion", "kind", "purpose", "target", "sourceCommit", "sourceManifestSha256",
                        "binary", "notices", "runId", "runAttempt", "sourcePost", "originalsClosed", "productsFinal"}
         | ({"buildOrigin"} if purpose == "history-provider" else set())
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["kind"] == "current-tool-build-capsule" and value["purpose"] == purpose and value["target"] == target
         and all(value[k] == build[k] for k in ("sourceCommit", "sourceManifestSha256", "notices", "runId", "runAttempt"))
         and type(value["binary"]) is dict and value["binary"] == {"sha256": build["binarySha256"], "bytes": build["binaryBytes"]}
         and type(value["binary"]["bytes"]) is int
         and all(value[k] is True for k in ("sourcePost", "originalsClosed", "productsFinal")), "tool-build-final-facts")
    if purpose == "history-provider":
        tool_build_origin(value["buildOrigin"])
    return value


def tool_quote(purpose):
    need(purpose in TOOL_FIXED, "tool-fixed-purpose")
    limit = TOOL_FIXED[purpose][2]
    owned = 12 * limit + 8 * 1024 * 1024 + 16 * 1024 * 1024 + 4 * 65536 + TOOL_RECEIPT_LIMIT
    scratch = 3 * limit + 16 * 1024 * 1024 + 8 * 1024 * 1024 + 4 * 65536 + TOOL_RECEIPT_LIMIT
    need(owned <= 1024 * 1024 * 1024, "tool-owned-data-quote")
    return owned, scratch  # Conservative application-owned bytes, not RSS.


def tool_sign_arguments(path, entitlements, purpose, identity):
    need(purpose in TOOL_FIXED and isinstance(path, Path) and isinstance(entitlements, Path), "tool-sign-purpose")
    identifier = TOOL_FIXED[purpose][1]
    requirement = "=" + signing_requirement(identity, identifier)
    return (["/usr/bin/codesign", "--force", "--sign", identity[1], "--identifier", identifier,
             "--options", "runtime", "--entitlements", str(entitlements), "--timestamp", str(path)],
            ["/usr/bin/codesign", "--verify", "--strict", "-R", requirement, str(path)])


def tool_loader(body, purpose, target, stager, matcher):
    need(purpose in TOOL_FIXED and type(body) is bytes and 0 < len(body) <= TOOL_FIXED[purpose][2], "tool-image-bound")
    if purpose == "history-provider":
        stager.history_provider_macho(body, target=target)
    else:
        # Existing fixed system-only macOS26 policy, with the canonical helper's
        # explicit dynamic-sodium veto. This does not execute/load the image.
        stager.macho(body, system_only=True, target=target)
        machine = build_profile(target)[0]
        need(not any("sodium" in row.get("text", "").lower() for row in matcher.macho_records(body, machine)),
             "tool-no-dynamic-sodium")


def tool_signed_receipt(body, row, purpose, target, producer, service, entitlements):
    signed, build = row["signed"], row["build"]
    need(signed["state"] == "configured" and digest(body) == signed["receiptSha256"]
         and all(signed[k] == digest(v) for k, v in (("producerProfileSha256", producer), ("serviceProfileSha256", service),
                                                   ("entitlementsSha256", entitlements))), "tool-signed-receipt-anchor")
    value = tool_json(body)
    need(value.get("schemaVersion") == 1 and type(value.get("schemaVersion")) is int
         and value.get("phase") == "sign-" + purpose and value.get("target") == target
         and value.get("source") == value.get("workflowSource") == signed["signingSourceCommit"]
         and value.get("workflow") == "Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-python-runtime-signing.yml@" + TOOL_REF
         and value.get("outerFinalityRequired") is True and value.get("productReady") is False
         and value.get("runId") == signed["runId"]
         and value.get("runAttempt") == signed["runAttempt"]
         and type(value.get("tool")) is dict
         and type(value["tool"].get("rawBytes")) is int and type(value["tool"].get("signedBytes")) is int
         and value.get("tool") == {"purpose": purpose, "buildSha256": digest(tool_canonical(build)),
             "sourceManifestSha256": build["sourceManifestSha256"], "rawSha256": build["binarySha256"],
             "rawBytes": build["binaryBytes"], "signedSha256": signed["signedSha256"], "signedBytes": signed["signedBytes"],
             "notices": build["notices"], "identifier": TOOL_FIXED[purpose][1],
             "producerProfileSha256": digest(producer), "serviceProfileSha256": digest(service),
             "entitlementsSha256": digest(entitlements)}
         and all(value.get(k) is True for k in ("passed", "originalClosesKnown", "targetRetired", "toolFinal"))
         and value.get("cleanupErrors") == [] and value.get("directStagerIOPending") is None
         and "failure" not in value, "tool-signed-final-receipt")
    credentials, contexts = value.get("credentialOriginals"), value.get("credentialContexts")
    need(type(credentials) is list and 0 < len(credentials) <= 64
         and all(type(c) is dict and c.get("returned") is True and c.get("settled") is True
                 and type(c.get("status")) is int and c["status"] == 0 for c in credentials)
         and type(contexts) is list and len(contexts) == 1 and type(contexts[0]) is dict
         and contexts[0].get("purpose") == "sign-" + purpose
         and all(contexts[0].get(k) is True for k in ("retired", "closed", "searchRestored", "defaultUnchanged")),
         "tool-signed-credential-finality")
    calls = value.get("originalCalls")
    need(type(calls) is list and len(calls) == 2 and all(type(c) is dict for c in calls)
         and tuple(c.get("role") for c in calls) == ("sign-" + purpose, "sign-" + purpose + "-verify")
         and all(c.get("entered") is True and c.get("returned") is True and c.get("capturesSettled") is True
                 and type(c.get("returncode")) is int and c["returncode"] == 0 for c in calls), "tool-signed-original-calls")
    return value


NOTARY_PHASES = ("notarize-payload",)
NOTARY_PROFILE = "desktop/packaging/macos-notary-service.json"
NOTARY_KEY_VARIABLE = "MRK_MACOS_NOTARY_API_KEY_BASE64"
NOTARY_XCODE = Path("/Applications/Xcode.app/Contents/Developer")
# Submission-copy basename only; original/installed APP_NAME is unchanged.
NOTARY_APP_NAME = "MobileReleaseKit.app"
NOTARY_ZIP_NAME = "MobileReleaseKit-notary-payload.zip"
NOTARY_ROLES = ("resolve-notarytool", "resolve-stapler", "verify-inner-before", "verify-outer-before",
                "payload-zip", "payload-submit", "payload-log", "staple-inner", "validate-inner",
                "staple-outer", "validate-outer", "verify-inner-after", "verify-outer-after")
NOTARY_TICKETS = ("Contents/CodeResources", "Contents/Helpers/MobileReleaseKitPayload.app/Contents/CodeResources")
LAUNCHER_IDENTIFIER = "dev.mobile-release-kit.desktop.launcher"
LAUNCHER_BUNDLE = "Contents/Helpers/MobileReleaseKitLauncher.app"
LAUNCHER_TICKET = LAUNCHER_BUNDLE + "/Contents/CodeResources"


def notary_roles(launcher=False):
    need(type(launcher) is bool, "notary-launcher-role")
    if not launcher:
        return NOTARY_ROLES
    return (NOTARY_ROLES[:2] + ("verify-launcher-before",) + NOTARY_ROLES[2:7]
            + ("staple-launcher", "validate-launcher") + NOTARY_ROLES[7:11]
            + ("verify-launcher-after",) + NOTARY_ROLES[11:])


def notary_tickets(launcher=False):
    need(type(launcher) is bool, "notary-launcher-role")
    return NOTARY_TICKETS + ((LAUNCHER_TICKET,) if launcher else ())


NOTARY_FREE_FLOOR = 3 * 1024 * 1024 * 1024
NOTARY_STORAGE_RESERVE = 2 * 1024 * 1024 * 1024
NOTARY_ZIP_LIMIT = 576 * 1024 * 1024


NOTARY_SUBMIT_CLASSES = {"http-401": "http-authentication", "http-403": "http-permission",
    "http-429": "http-rate-limit", **{f"http-{code}": "http-service" for code in (500, 502, 503, 504)},
    "url-1001": "network-timeout", "url-1003": "network-dns", "url-1004": "network-connection",
    "url-1005": "network-connection", "url-1006": "network-dns", "url-1009": "network-connection",
    "url-1200": "network-tls", "url-1202": "network-tls"}
NOTARY_SUBMIT_PREFIX = re.compile(rb"(?<![A-Za-z0-9_])(?:(?P<http>HTTP(?:/[0-9.]{1,8})?[ \t]+(?:status(?:[ \t]+code)?|code)[ \t]*(?:[:=][ \t]*)?)|(?P<url>NSURLErrorDomain[ \t]+Code[ \t]*=[ \t]*))")
NOTARY_SUBMIT_NUMERIC = re.compile(rb"-?[0-9]{1,10}(?=$|[ \t\r\n,;.)])")


def notary_submit_diagnostic(body):
    """Finite lexical facts from one failed original; never authentication evidence."""
    need(type(body) is bytes and len(body) <= 65536, "notary-submit-diagnostic-bound")
    form = "empty" if not body else "bounded-utf8"
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    try:
        view = memoryview(body)
        for offset in range(0, len(body), 512):
            decoder.decode(view[offset:offset + 512], final=False)
        decoder.decode(b"", final=True)
    except UnicodeError:
        form = "invalid-utf8"
    matches, truncated = [], False
    if form == "bounded-utf8":
        for match in NOTARY_SUBMIT_PREFIX.finditer(body):
            if len(matches) == 16:
                truncated = True
                break
            kind = "http" if match.lastgroup == "http" else "url"
            numeric = NOTARY_SUBMIT_NUMERIC.match(body, match.end())
            raw = numeric.group().decode("ascii") if numeric is not None else "malformed"
            key = kind + raw if kind == "url" else kind + "-" + raw
            matches.append(key if key in NOTARY_SUBMIT_CLASSES else "unsupported-" + kind)
    state, error = "none", "unclassified"
    if form == "invalid-utf8" or any(key.startswith("unsupported-") for key in matches):
        state = "unrecognized"
    elif truncated or len(matches) > 1:
        state = "multiple-or-conflicting"
    elif matches:
        state, error = "single-known", NOTARY_SUBMIT_CLASSES[matches[0]]
    result = {"schemaVersion": 1, "kind": "failure-only-notary-submit", "diagnosticOnly": True,
        "nativeSuccessInferred": False, "policyUnchanged": True, "stderrBytes": len(body),
        "stderrSha256": digest(body), "formatClass": form, "lexicalState": state,
        "errorClass": error, "matches": matches, "matchesTruncated": truncated}
    need(len(json.dumps(result, separators=(",", ":"))) <= 2048, "notary-submit-diagnostic-bound")
    return result


def notary_json(body, limit):
    need(type(body) is bytes and 0 < len(body) <= limit, "notary-json-bound")
    def pairs(values):
        need(len(values) <= 16 and len({key for key, _ in values}) == len(values), "notary-json-keys")
        return dict(values)
    def constant(_value):
        raise Refused("notary-json-constant")
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError):
        raise Refused("notary-json-format") from None
    need(type(value) is dict, "notary-json-object")
    return value


def notary_uuid(value):
    need(type(value) is str and re.fullmatch(r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}", value)
         and value.replace("-", "") != "0" * 32, "notary-uuid")
    return value.lower()  # UUID value only, never a filename/path normalization.


def notary_service(body, identity):
    value = notary_json(body, 1024)
    need(type(value.get("schemaVersion")) is int and value["schemaVersion"] == 1, "notary-profile-schema")
    if value.get("mode") == "unconfigured":
        need(set(value) == {"schemaVersion", "mode"}, "notary-profile-keys")
        raise Refused("notary-profile-unconfigured")
    need(set(value) == {"schemaVersion", "mode", "teamId", "keyId", "issuerId"}
         and value["mode"] == "app-store-connect-team-key" and type(identity) is tuple and len(identity) == 2
         and value["teamId"] == identity[0] and type(value["teamId"]) is str
         and re.fullmatch(r"[A-Z0-9]{10}", value["teamId"])
         and type(value["keyId"]) is str and re.fullmatch(r"[A-Z0-9]{10}", value["keyId"]), "notary-profile-source")
    need(notary_uuid(value["issuerId"]) == value["issuerId"], "notary-profile-issuer")
    return value


def notary_key_data(environment):
    value = environment.get(NOTARY_KEY_VARIABLE)
    need(type(value) is str and 4 <= len(value) <= 10924 and value.isascii()
         and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value), "notary-key-input")
    try:
        body = base64.b64decode(value, validate=True)
    except ValueError:
        raise Refused("notary-key-base64") from None
    need(0 < len(body) <= 8192 and base64.b64encode(body).decode("ascii") == value
         and body.isascii() and b"\0" not in body, "notary-key-pem-shape")
    # RFC 7468 standard EOLs and optional final EOL, for validation only.
    # The original credential bytes remain unchanged for custody and Apple.
    view = body.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    need(re.fullmatch(rb"-----BEGIN PRIVATE KEY-----\n(?:[A-Za-z0-9+/=]{1,64}\n)+-----END PRIVATE KEY-----\n?", view),
         "notary-key-pem-shape")
    return body  # Bounded PEM shape only. Apple performs actual authentication.


def notary_text(value, bound):
    if type(value) is not str:
        return False
    try:
        return (0 < len(value.encode("utf-8")) <= bound
                and all(ord(char) >= 0x20 and ord(char) != 0x7f for char in value))
    except UnicodeError:
        return False


def notary_submit_data(body, *, archive_name=NOTARY_ZIP_NAME):
    need(archive_name in (NOTARY_ZIP_NAME, "MobileReleaseKit.pkg", "MobileReleaseKit.dmg", "Remove.pkg", "MobileReleaseKit-Remove.dmg", "Prepare Xcode.pkg"), "notary-fixed-archive-name")
    value = notary_json(body, 65536)
    need({"id", "status"} <= set(value) <= {"id", "status", "message", "name", "createdDate"}
         and value["status"] in ("Accepted", "Invalid"), "notary-submit-terminal")
    for name in ("message", "name", "createdDate"):
        if name in value:
            need(notary_text(value[name], 2048), "notary-submit-metadata")
    if "name" in value:
        need(value["name"] == archive_name, "notary-submit-archive")
    return {"id": notary_uuid(value["id"]), "status": value["status"]}


NOTARY_ISSUE_MESSAGES = {
    'The binary is not signed.': 'unsigned-binary',
    'The signature of the binary is invalid.': 'invalid-signature',
    'The signature does not include a secure timestamp.': 'missing-timestamp',
    'The executable does not have the hardened runtime enabled.': 'missing-hardened-runtime',
    'The binary is not signed with a valid Developer ID certificate.': 'invalid-developer-id',
    'The binary uses an SDK older than the 10.9 SDK.': 'old-sdk',
}
NOTARY_ISSUE_COMPONENTS = ("optional-terminal-notifier-cache", "gem-install-cache", "launcher",
                          "store-runtime", "python-runtime", "desktop-payload", "other")


def notary_issue_summary(issues):
    """Finite categories only, never raw paths/messages; not acceptance evidence."""
    need(issues is None or type(issues) is list and len(issues) <= 2048, "notary-issue-diagnostic-bound")
    counts = {}
    for issue in issues or []:
        need(type(issue) is dict and issue.get('severity') in ('warning', 'error'), "notary-issue-diagnostic-shape")
        path, message, number = issue.get('path'), issue.get('message'), issue.get('code')
        need(type(path) is str and len(path) <= 4096 and type(message) is str and len(message) <= 8192, "notary-issue-diagnostic-shape")
        need(number is None or type(number) is int and 0 <= number <= 999999, "notary-issue-diagnostic-code")
        # These literal classes, never path/message text or sanitized suffixes,
        # are sufficient to locate the failing component without publishing logs.
        component = ('optional-terminal-notifier-cache'
                     if 'terminal-notifier-2.0.0.gem' in path.split('/') and '/terminal-notifier.app/' in path else
                     'gem-install-cache' if '/cache/' in path and '.gem/' in path else
                     'launcher' if '/MobileReleaseKitLauncher.app/' in path else
                     'store-runtime' if '/store/' in path else 'python-runtime' if '/python/' in path else
                     'desktop-payload' if '/MobileReleaseKitPayload.app/' in path else 'other')
        key = (issue['severity'], number, NOTARY_ISSUE_MESSAGES.get(message, 'unclassified'), component)
        counts[key] = counts.get(key, 0) + 1
    need(len(counts) <= 64, "notary-issue-diagnostic-bound")
    return [dict(severity=k[0], code=k[1], category=k[2], component=k[3], count=n) for k, n in counts.items()]


def notary_failure_summary_data(value):
    """Revalidate stored diagnostic DATA before exporting any part of it."""
    if type(value) is not dict or set(value) != {"rows", "rowsOmitted"}:
        return None
    rows = value["rows"]
    if type(rows) is not list or len(rows) > 8 or type(value["rowsOmitted"]) is not bool:
        return None
    out = []
    for row in rows:
        if (type(row) is not dict or set(row) != {"severity", "code", "category", "component", "count"}
            or type(row["severity"]) is not str or row["severity"] not in ("warning", "error")
            or not (row["code"] is None or type(row["code"]) is int and 0 <= row["code"] <= 999999)
            or type(row["category"]) is not str or row["category"] not in (*NOTARY_ISSUE_MESSAGES.values(), "unclassified")
            or type(row["component"]) is not str or row["component"] not in NOTARY_ISSUE_COMPONENTS
            or type(row["count"]) is not int or not 1 <= row["count"] <= 2048):
            return None
        out.append(dict(row))
    return {"rows": out, "rowsOmitted": value["rowsOmitted"]}


def notary_log_data(body, submission, archive_sha256, *, archive_name=NOTARY_ZIP_NAME):
    need(archive_name in (NOTARY_ZIP_NAME, "MobileReleaseKit.pkg", "MobileReleaseKit.dmg", "Remove.pkg", "MobileReleaseKit-Remove.dmg", "Prepare Xcode.pkg"), "notary-fixed-archive-name")
    value = notary_json(body, 1024 * 1024)
    required = {"logFormatVersion", "jobId", "status", "archiveFilename", "issues", "ticketContents"}
    need(required <= set(value) <= required | {"statusSummary", "statusCode", "uploadDate", "sha256"}
         and type(value["logFormatVersion"]) is int and value["logFormatVersion"] == 1
         and notary_uuid(value["jobId"]) == submission["id"] and value["status"] == submission["status"]
         and value["archiveFilename"] == archive_name, "notary-log-binding")
    for name in ("statusSummary", "uploadDate"):
        if name in value:
            need(notary_text(value[name], 4096), "notary-log-metadata")
    if "statusCode" in value:
        need(type(value["statusCode"]) is int and 0 <= value["statusCode"] <= 999999
             and (value["statusCode"] == 0) == (submission["status"] == "Accepted"), "notary-log-status-code")
    if "sha256" in value:
        need(value["sha256"] == archive_sha256, "notary-log-upload-sha256")
    issues, tickets = value["issues"], value["ticketContents"]
    need(issues is None or type(issues) is list and len(issues) <= 2048, "notary-log-issues-bound")
    errors = warnings = 0
    for row in issues or ():
        need(type(row) is dict and {"severity", "path", "message"} <= set(row)
             <= {"severity", "path", "message", "code", "docUrl", "architecture"}
             and row["severity"] in ("warning", "error") and notary_text(row["path"], 4096)
             and notary_text(row["message"], 8192), "notary-log-issue-shape")
        for name in ("docUrl", "architecture"):
            if name in row and row[name] is not None:
                need(notary_text(row[name], 4096 if name == "docUrl" else 32), "notary-log-issue-metadata")
        if "code" in row:
            need(row["code"] is None or type(row["code"]) is int and 0 <= row["code"] <= 999999,
                 "notary-log-issue-code")
        errors += row["severity"] == "error"
        warnings += row["severity"] == "warning"
    need(tickets is None or type(tickets) is list and len(tickets) <= 2048, "notary-log-tickets-bound")
    # Finite Apple ticket annotations include nested signed i386 slices;
    # they never grant native execution, target or provenance authority.
    # Apple creates tickets for nested containers as well as executable slices.
    # An absent/null architecture is informational, regardless of container path.
    # No ticket path/architecture grants IO, native eligibility or provenance;
    # the exact original still requires independent signature/staple validation.
    for row in tickets or ():
        need(type(row) is dict and {"path", "digestAlgorithm", "cdhash"} <= set(row)
             <= {"path", "digestAlgorithm", "cdhash", "arch"}, "notary-log-ticket-shape")
        need(notary_text(row["path"], 4096), "notary-log-ticket-path")
        need(row["digestAlgorithm"] in ("SHA-1", "SHA-256"), "notary-log-ticket-digest-algorithm")
        need(type(row["cdhash"]) is str and re.fullmatch(r"[0-9a-fA-F]{40}", row["cdhash"]),
             "notary-log-ticket-digest")
        need(row.get("arch") is None or row.get("arch") in ("arm64", "x86_64", "i386"),
             "notary-log-ticket-architecture")
    need(submission["status"] != "Accepted" or errors == 0, "notary-log-success-with-errors")
    return {"sha256Compared": "sha256" in value, "errorCount": errors, "warningCount": warnings,
            "ticketRowCount": len(tickets or ()), "logSha256": digest(body)}


FINAL_IMAGE_PHASES = ("finalize-image", "finalize-remove-image")
FINAL_IMAGE_ROLES = ("final-image-resolve-notarytool", "final-image-resolve-stapler", "final-image-signature-before",
                     "final-image-submit", "final-image-log", "final-image-staple", "final-image-validate",
                     "final-image-signature-after", "final-image-verify", "final-image-attach", "final-image-detach",
                     "final-image-policy-status", "final-image-policy-assess")

FINAL_PACKAGE_PHASES = ("finalize-package", "finalize-remove-package", "finalize-xcode-setup-package")
XCODE_SETUP_COMPONENT_ROLES = ("final-package-setup-pkgbuild", "final-package-setup-lsbom",
                               "final-package-setup-tar", "final-package-setup-xar")
XCODE_SETUP_MUTATION_ROLES = ("final-package-setup-pkgbuild", "final-package-setup-tar", "final-package-setup-xar")
INSTALLER_PROFILE = "desktop/packaging/macos-installer-signing.json"
INSTALLER_CREDENTIAL_VARIABLES = ("MRK_MACOS_INSTALLER_P12_BASE64", "MRK_MACOS_INSTALLER_P12_PASSWORD")
FINAL_PACKAGE_ROLES = ("final-package-resolve-notarytool", "final-package-resolve-stapler",
                       "final-package-sign", "final-package-signature-before", "final-package-submit",
                       "final-package-log", "final-package-staple", "final-package-validate",
                       "final-package-signature-after")
def final_package_roles(remove, package_role, *, setup=False):
    need(type(remove) is bool and type(setup) is bool and (not setup or not remove and package_role == "ordinary-image")
         and package_role in ("ordinary-image", "installed-shell-observation"),
         "final-package-fixed-purpose")
    return ((XCODE_SETUP_COMPONENT_ROLES if setup else ()) + ("final-package-productbuild",) + FINAL_PACKAGE_ROLES
            if not remove and package_role == "ordinary-image" else FINAL_PACKAGE_ROLES)


IMAGE_CREDENTIAL_ROLES = {
    "distribution-image": ("distribution-sign", "distribution-verify-signature"),
    "observation-image": ("observation-sign", "observation-verify-signature"),
}


def final_package_json(body, maximum, label):
    need(type(body) is bytes and 0 < len(body) <= maximum, label)

    def pairs(values):
        result = {}
        for key, value in values:
            need(key not in result, label)
            result[key] = value
        return result

    def constant(_value):
        raise Refused(label)

    try:
        return json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError):
        raise Refused(label) from None


def installer_profile(body):
    """Public SOURCE selection only, never an available signing identity."""
    value = final_package_json(body, 1024, "installer-profile-json")
    need(type(value) is dict and type(value.get("schemaVersion")) is int
         and value["schemaVersion"] == 1, "installer-profile-schema")
    if value == {"schemaVersion": 1, "mode": "unconfigured"}:
        return None
    fields = {"schemaVersion", "mode", "teamId", "identityCommonName", "leafSha1", "leafSha256",
              "issuerSha256", "rootSha256"}
    need(set(value) == fields and value["mode"] == "developer-id-installer"
         and type(value["teamId"]) is str and re.fullmatch(r"[A-Z0-9]{10}", value["teamId"]) is not None,
         "installer-profile-schema")
    for name, width in (("leafSha1", 40), ("leafSha256", 64), ("issuerSha256", 64), ("rootSha256", 64)):
        need(type(value[name]) is str and re.fullmatch(r"[0-9a-f]{" + str(width) + r"}", value[name]) is not None
             and value[name] != "0" * width, "installer-profile-fingerprint")
    need(len({value[name] for name in ("leafSha256", "issuerSha256", "rootSha256")}) == 3,
         "installer-profile-chain")
    name = value["identityCommonName"]
    prefix, suffix = "Developer ID Installer: ", " (" + value["teamId"] + ")"
    need(type(name) is str and name.isprintable() and name.startswith(prefix) and name.endswith(suffix)
         and len(name) > len(prefix) + len(suffix), "installer-profile-common-name")
    try:
        encoded = name.encode("utf-8")
    except UnicodeError:
        raise Refused("installer-profile-common-name") from None
    need(len(encoded) <= 256, "installer-profile-common-name")
    return dict(value)


def installer_identity(identity_body, certificate_body, selection, certificates):
    """Bind the single private-key identity to public SOURCE, not its name alone."""
    need(type(identity_body) is bytes and type(certificate_body) is bytes
         and len(identity_body) <= 16384 and len(certificate_body) <= 16384
         and type(selection) is dict and type(certificates) is tuple and len(certificates) == 3
         and all(type(value) is bytes and 0 < len(value) <= 16384 for value in certificates),
         "installer-private-identity-bound")
    try:
        text = identity_body.decode("utf-8")
    except UnicodeError:
        raise Refused("installer-private-identity-format") from None
    expected = re.escape(selection["identityCommonName"])
    rows, summaries = [], 0
    for line in text.splitlines():
        match = re.fullmatch(r'[ \t]*1\) ([0-9A-Fa-f]{40}) "' + expected + '"', line)
        if match is not None:
            rows.append(match[1].lower())
        elif re.fullmatch(r"[ \t]*1 valid identities found", line):
            summaries += 1
        else:
            need(not line.strip(), "installer-private-identity-format")
    need(rows == [selection["leafSha1"]] and summaries == 1, "installer-private-source-identity")
    pattern = rb"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n"
    values, end = [], 0
    for match in re.finditer(pattern, certificate_body):
        need(match.start() == end and len(values) < 3, "installer-private-certificate-format")
        encoded = match[1].replace(b"\n", b"")
        try:
            value = base64.b64decode(encoded, validate=True)
        except ValueError:
            raise Refused("installer-private-certificate-format") from None
        need(0 < len(value) <= 16384 and base64.b64encode(value) == encoded,
             "installer-private-certificate-format")
        values.append(value)
        end = match.end()
    need(end == len(certificate_body) and len(values) == 3 and len(set(values)) == 3
         and set(values) == set(certificates), "installer-private-source-certificates")


_SETUP_DIAGNOSTIC_STAGES = frozenset((
    "input", "source", "self", "carrier", "selection", "source-apple", "staged-apple", "final-apple",
    "facts", "census", "copy", "record", "retire-tree", "current", "source-post", "files-settle", "source-settle",
    "loans-settle", "reply", "endpoint-settle", "namespace", "reservation", "child", "publication",
    "namespace-settle", "finality"))
_SETUP_DIAGNOSTIC_REASONS = frozenset(("clock", "access", "bounds", "state", "binding", "present",
    "read", "write", "sync", "close", "child", "unknown"))


def setup_installer_diagnostics_data(value):
    """Revalidate only closed A observations, never a helper-admission claim."""
    if (type(value) is not dict or set(value) != {"available", "observations"}
            or type(value["available"]) is not bool or type(value["observations"]) is not list
            or len(value["observations"]) > 4 or value["available"] != bool(value["observations"])):
        return None
    rows = []
    for row in value["observations"]:
        if (type(row) is not dict or set(row) != {"scope", "stage", "reason"}
                or type(row["scope"]) is not str or row["scope"] not in ("public", "child")
                or type(row["stage"]) is not str or row["stage"] not in _SETUP_DIAGNOSTIC_STAGES
                or type(row["reason"]) is not str or row["reason"] not in _SETUP_DIAGNOSTIC_REASONS
                or row in rows):
            return None
        rows.append(dict(row))
    return {"available": value["available"], "observations": rows}


_SETUP_HOOKS = ("preinstall", "postinstall")
_SETUP_HOOK_STAGES = ("entry", "target-refused", "path-refused", "cwd-refused", "pre-exec")


def setup_hook_diagnostics_data(value):
    if (type(value) is not dict or set(value) != {"available", "observations"}
            or type(value["available"]) is not bool or type(value["observations"]) is not list
            or len(value["observations"]) > 10 or value["available"] != bool(value["observations"])):
        return None
    rows = []
    for row in value["observations"]:
        if (type(row) is not dict or set(row) != {"hook", "stage"}
                or type(row["hook"]) is not str or row["hook"] not in _SETUP_HOOKS
                or type(row["stage"]) is not str or row["stage"] not in _SETUP_HOOK_STAGES
                or row in rows):
            return None
        rows.append(dict(row))
    return {"available": value["available"], "observations": rows}


def setup_hook_diagnostics(stdout, stderr):
    """Hook text only: pre-exec is not evidence that the helper was admitted."""
    if type(stdout) is not bytes or type(stderr) is not bytes or len(stdout) + len(stderr) > 256 * 1024:
        return None
    pattern = re.compile(rb"(?:^|[ \t])MRK_XCODE_HOOK=hook=(preinstall|postinstall);stage="
                         rb"(entry|target-refused|path-refused|cwd-refused|pre-exec)\r?\n$")
    rows = []
    for body in (stdout, stderr):
        for line in body.splitlines(keepends=True):
            if len(line) > 4096:
                continue
            match = pattern.search(line)
            if match is not None:
                row = {"hook": match[1].decode("ascii"), "stage": match[2].decode("ascii")}
                if row not in rows and len(rows) < 10:
                    rows.append(row)
    return setup_hook_diagnostics_data({"available": bool(rows), "observations": rows})


def setup_installer_diagnostics(stdout, stderr):
    """Only A's compiled public tokens; surrounding Installer text is discarded."""
    need(type(stdout) is bytes and type(stderr) is bytes and len(stdout) + len(stderr) <= 256 * 1024,
         "setup-verification-diagnostic-bound")
    found = []
    pattern = rb"(?:^|[ \t])MRK_XCODE_SETUP_REFUSED=scope=([a-z]+);stage=([a-z-]+);reason=([a-z]+)(?=\r?$)"
    for body in (stdout, stderr):
        for line in body.splitlines():
            if len(line) > 4096:
                continue
            match = re.search(pattern, line)
            if match is None:
                continue
            scope, stage, reason = (value.decode("ascii") for value in match.groups())
            if scope in ("public", "child") and stage in _SETUP_DIAGNOSTIC_STAGES and reason in _SETUP_DIAGNOSTIC_REASONS:
                value = {"scope": scope, "stage": stage, "reason": reason}
                if value not in found and len(found) < 4:
                    found.append(value)
    return {"available": bool(found), "observations": found}


def setup_failed_installer_index(calls):
    """Exact original failure cut; a terminal diagnostic never replaces it."""
    if type(calls) is not list:
        return None
    prefix = calls[:-1] if calls and type(calls[-1]) is dict and calls[-1].get("role") == XCODE_SETUP_LOG_CAPTURE else calls
    if len(prefix) not in (3, 4) or not all(type(row) is dict for row in prefix):
        return None
    if (tuple(row.get("role") for row in prefix) != XCODE_SETUP_VERIFY_ROLES[:len(prefix)]
            or not all(row.get("entered") is True and row.get("returned") is True
                       and row.get("capturesSettled") is True for row in prefix)
            or not all(type(row.get("returncode")) is int and row["returncode"] in
                       ((0, 1) if row["role"] == "setup-log-cursor" else (0,)) for row in prefix[:-1])
            or type(prefix[-1].get("returncode")) is not int
            or not -65536 <= prefix[-1]["returncode"] <= 65535 or prefix[-1]["returncode"] == 0):
        return None
    return len(prefix) - 1


def setup_log_projection_data(value):
    if (type(value) is not dict or set(value) != {"state", "reason", "intervalScope", "hooks", "native", "errors", "omitted"}
            or value.get("intervalScope") != "before-first-through-failed-installer"
            or type(value.get("omitted")) is not bool):
        return None
    if value["state"] == "unknown":
        if (type(value["reason"]) is not str or value["reason"] not in _INSTALLER_LOG_REASONS
                or any(value[name] is not None for name in ("hooks", "native", "errors"))):
            return None
        return dict(value)
    if value["state"] != "observed-project-correlated" or value["reason"] is not None:
        return None
    hooks, native, errors = (setup_hook_diagnostics_data(value["hooks"]),
                             setup_installer_diagnostics_data(value["native"]), installer_errors_data(value["errors"]))
    if any(row is None for row in (hooks, native, errors)):
        return None
    return dict(value, hooks=hooks, native=native, errors=errors)


def package_signature_data(body, selection, certificates, path, *, after_staple=False):
    """Closed pkgutil trust/timestamp/complete-chain projection; no raw output."""
    need(type(body) is bytes and 0 < len(body) <= 65536 and body.endswith(b"\n")
         and type(selection) is dict and type(certificates) is tuple and len(certificates) == 3
         and isinstance(path, Path) and path.name in ("MobileReleaseKit.pkg", "Remove.pkg", "Prepare Xcode.pkg")
         and type(after_staple) is bool, "package-signature-bound")
    try:
        text = body.decode("utf-8")
    except UnicodeError:
        raise Refused("package-signature-utf8") from None
    need(all(character in "\n\t" or character.isprintable() for character in text), "package-signature-format")
    raw_lines = [line for line in text.splitlines() if line.strip(" \t")]
    lines = [line.strip(" \t") for line in raw_lines]
    need(0 < len(lines) <= 256 and all(len(line) <= 1024 for line in lines)
         and lines[0] in ('Package "' + path.name + '":', 'Package "' + str(path) + '":'),
         "package-signature-header")
    # Post-staple informational metadata is not signature/notary authority.
    if after_staple and len(lines) > 2 and lines[2].startswith("Notarization: "):
        prefix = "Notarization: "
        need([i for i, line in enumerate(lines) if line.startswith("Notarization:")] == [2]
             and 0 < len(lines[2][len(prefix):]) <= 128
             and all(32 <= ord(character) <= 126 for character in raw_lines[2]),
             "package-signature-notarization-metadata")
        del lines[2]
    trusted = ("Status: signed by a certificate trusted by macOS", "Status: signed by a certificate trusted by Mac OS X",
               "Status: signed by a developer certificate issued by Apple for distribution")
    need(len(lines) > 4 and lines[1] in trusted
         and lines[2].startswith("Signed with a trusted timestamp on: ")
         and 0 < len(lines[2][len("Signed with a trusted timestamp on: "):]) <= 128
         and lines[3] == "Certificate Chain:", "package-signature-trust-timestamp")
    rows, current, fingerprint = [], None, None
    for line in lines[4:]:
        record = re.fullmatch(r"([123])\. (.{1,512})", line)
        if record is not None:
            need(int(record[1]) == len(rows) + 1, "package-signature-chain-order")
            current = {"name": record[2], "sha256": None, "sha1": None, "expires": False}
            rows.append(current)
            fingerprint = None
            continue
        need(current is not None, "package-signature-chain-format")
        label = re.fullmatch(r"(SHA256|SHA1) [Ff]ingerprint:(?: (.*))?", line)
        if label is not None:
            key = "sha256" if label[1] == "SHA256" else "sha1"
            need(current[key] is None, "package-signature-fingerprint-repeated")
            current[key] = ""
            fingerprint = key
            line = label[2] or ""
            if not line:
                continue
        if re.fullmatch(r"[0-9A-Fa-f]{2}(?:[ \t]+[0-9A-Fa-f]{2})*", line):
            need(fingerprint in ("sha256", "sha1"), "package-signature-fingerprint-position")
            current[fingerprint] += "".join(line.split()).lower()
            need(len(current[fingerprint]) <= (64 if fingerprint == "sha256" else 40),
                 "package-signature-fingerprint-bound")
        elif re.fullmatch(r"-{16,128}", line):
            fingerprint = None
        elif line.startswith("Expires: ") and 0 < len(line[9:]) <= 128:
            need(not current["expires"], "package-signature-expiry-repeated")
            current["expires"] = True
            fingerprint = None
        else:
            raise Refused("package-signature-chain-format")
    expected = [selection[key] for key in ("leafSha256", "issuerSha256", "rootSha256")]
    need(len(rows) == 3 and rows[0]["name"] == selection["identityCommonName"]
         and [row["sha256"] for row in rows] == expected, "package-signature-source-chain")
    for row, certificate in zip(rows, certificates):
        need(digest(certificate) == row["sha256"]
             and (row["sha1"] is None or row["sha1"] == hashlib.sha1(certificate).hexdigest()),
             "package-signature-source-fingerprint")
    return {"trusted": True, "timestamp": True, "certificateSha256": expected}


INSTALLER_CREDENTIAL_ROSTER = (
    "search-before", "default-before", "create", "search-created", "settings", "unlock", "import", "partitions",
    "identity", "certificates", "installer-chain", "search-admit", "restrict", "search-restricted",
    "search-after-callback", "restore", "search-restored", "delete", "search-final", "default-after",
)


def package_staple_observation_data(value):
    flags = {"heldPreIdentityMatched", "namedPreIdentityMatched", "fdNameIdentityMatched",
             "fdNameMetadataMatched", "namedShapeExpected"}
    need(type(value) is dict and set(value) == flags | {"heldLinkState", "selectedBranch", "transitionComplete"}
         and all(value[key] is None or type(value[key]) is bool for key in flags)
         and type(value["transitionComplete"]) is bool
         and type(value["heldLinkState"]) is str and value["heldLinkState"] in ("unavailable", "single", "unlinked", "other")
         and type(value["selectedBranch"]) is str and value["selectedBranch"] in ("unavailable", "same-original", "returned-output"),
         "final-package-staple-observation")
    need(not value["transitionComplete"] or all(type(value[key]) is bool for key in flags)
         and value["heldPreIdentityMatched"] and value["namedShapeExpected"]
         and ((value["selectedBranch"], value["heldLinkState"], value["namedPreIdentityMatched"],
               value["fdNameIdentityMatched"], value["fdNameMetadataMatched"])
              in (("same-original", "single", True, True, True),
                  ("returned-output", "unlinked", False, False, False))),
         "final-package-staple-observation")
    return dict(value)


def final_package_receipt(body, environment, target, selection, profile_sha, notary_sha, package_size, package_sha,
                          image_release, release_sha, *, remove=False, runtime_stager=None, setup=False, setup_originals=None, product_source=None):
    """Closed preceding original observation AND the current immutable P.

    This is not a stand-alone cryptographic authority. The fixed workflow also
    requires the actual earlier helper0 and its held status original; this
    consumer repeats the complete Scripts audit before invoking the producer.
    """
    need(type(remove) is bool and type(setup) is bool
         and not (remove and runtime_stager is not None)
         and (not setup and setup_originals is None or setup and not remove and runtime_stager is None
              and environment.get("MRK_MACOS_PACKAGE_ROLE") == "ordinary-image"
              and environment.get("MRK_MACOS_STORE_RUNTIME") is None
              and type(setup_originals) is dict
              and set(setup_originals) == {"helperSha256", "bomSha256", "payloadSha256"}
              and all(tool_hex(v) for v in setup_originals.values())), "final-package-receipt-purpose")
    if product_source is not None:
        need(remove and environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
             and environment.get("GITHUB_WORKFLOW_REF") == "Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-candidate-consume.yml@refs/heads/task/ci-simplification-20261015"
             and tool_hex(product_source, 40), "candidate-removal-receipt-purpose")
    value = final_package_json(body, 16384, "final-package-receipt-json")
    keys = {"schemaVersion", "phase", "target", "source", "packageRole", "workflowSource", "workflow", "runId", "runAttempt",
            "toolchain", "helperIdentifier", "originalCalls", "credentialOriginals", "credentialContexts", "targetRetired",
            "originalClosesKnown", "passed", "outerFinalityRequired", "androidServiceAuthenticated", "androidRegisteredCopyQualified",
            "androidBuildQualified", "developerIdOrNotarizationQualified", "productReady", "notaryAuthentication", "notarySubmission",
            "finalPackage", "directStagerIOPending", "cleanupErrors", "imageSourceCommit", "imageReleaseId", "imageReleaseSourceSha256"}
    if type(value) is dict and "packageStapleObservation" in value:
        package_staple_observation_data(value["packageStapleObservation"])
        keys.add("packageStapleObservation")
    need(type(value) is dict and set(value) == keys and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["phase"] == ("finalize-xcode-setup-package" if setup else "finalize-remove-package" if remove else "finalize-package") and value["target"] == target and target in (ARM_TARGET, INTEL_TARGET)
         and value["source"] == environment["GITHUB_SHA"] == value["workflowSource"]
         and value["workflow"] == environment["GITHUB_WORKFLOW_REF"]
         and value["runId"] == environment["GITHUB_RUN_ID"] and value["runAttempt"] == environment["GITHUB_RUN_ATTEMPT"]
         and value["packageRole"] == environment["MRK_MACOS_PACKAGE_ROLE"]
         and value["imageSourceCommit"] == environment["MRK_MACOS_INSTALL_SOURCE_COMMIT"] == (value["source"] if product_source is None else product_source)
         and value["imageReleaseId"] == image_release and value["imageReleaseSourceSha256"] == release_sha
         and value["toolchain"] is None and value["helperIdentifier"] is None, "final-package-receipt-source")
    need(all(value[name] is True for name in ("targetRetired", "originalClosesKnown", "passed", "outerFinalityRequired"))
         and all(value[name] is False for name in ("androidServiceAuthenticated", "androidRegisteredCopyQualified", "androidBuildQualified",
                                                  "developerIdOrNotarizationQualified", "productReady"))
         and value["directStagerIOPending"] is None and value["cleanupErrors"] == [], "final-package-receipt-finality")
    calls, auxiliary = value["originalCalls"], value["credentialOriginals"]
    roles = final_package_roles(remove, value["packageRole"], setup=setup)
    need(type(calls) is list and len(calls) == len(roles)
         and type(auxiliary) is list and len(auxiliary) == len(INSTALLER_CREDENTIAL_ROSTER), "final-package-receipt-original-count")
    def sha(item):
        return type(item) is str and re.fullmatch(r"[0-9a-f]{64}", item) is not None and item != "0" * 64
    for row, role in zip(calls, roles):
        need(type(row) is dict and set(row) == {"role", "entered", "returned", "capturesSettled", "returncode", "stdoutSha256", "stderrSha256"}
             and row["role"] == role and all(row[key] is True for key in ("entered", "returned", "capturesSettled"))
             and type(row["returncode"]) is int and row["returncode"] == 0
             and sha(row["stdoutSha256"]) and sha(row["stderrSha256"]), "final-package-receipt-original")
    for row, role in zip(auxiliary, INSTALLER_CREDENTIAL_ROSTER):
        need(type(row) is dict and set(row) == {"role", "entered", "returned", "settled", "status"}
             and row["role"] == role and all(row[key] is True for key in ("entered", "returned", "settled"))
             and type(row["status"]) is int and row["status"] == 0, "final-package-receipt-credential-original")
    contexts = value["credentialContexts"]
    need(type(contexts) is list and len(contexts) == 1 and type(contexts[0]) is dict
         and set(contexts[0]) == {"purpose", "searchRestored", "defaultUnchanged", "retired", "closed"}
         and contexts[0]["purpose"] == "installer"
         and all(contexts[0][key] is True for key in ("searchRestored", "defaultUnchanged", "retired", "closed")),
         "final-package-receipt-credential-finality")
    auth = value["notaryAuthentication"]
    need(type(auth) is dict and set(auth) == {"created", "closed", "retired"}
         and all(item is True for item in auth.values()), "final-package-receipt-key-finality")
    final = value["finalPackage"]
    fields = {"schemaVersion", "kind", "unsignedBytes", "unsignedSha256", "signedBytes", "signedSha256", "packageBytes", "packageSha256",
              "packageMode", "originalPackageSha256", "packageInfoSha256", "scriptFileCount", "installerProfileSha256", "notaryProfileSha256",
              "teamId", "certificateSha256", "submissionId", "status", "sha256Compared", "errorCount", "warningCount", "ticketRowCount", "logSha256",
              "trustedSignatureBeforeAndAfter", "trustedTimestampBeforeAndAfter", "actualStaplerValidation", "signedPrefixUnchanged",
              "completeScriptsAudited", "assurance"}
    if setup:
        fields.update(("helperSha256", "bomSha256", "payloadSha256", "finalDestinationPayloadEntries"))
    need(type(final) is dict and set(final) == fields and type(final["schemaVersion"]) is int and final["schemaVersion"] == 1
         and final["kind"] == ("mrk-final-xcode-setup-package" if setup else "mrk-final-remover-package" if remove else "mrk-final-installer-package") and final["teamId"] == selection["teamId"]
         and final["certificateSha256"] == [selection[key] for key in ("leafSha256", "issuerSha256", "rootSha256")]
         and final["installerProfileSha256"] == profile_sha and final["notaryProfileSha256"] == notary_sha,
         "final-package-receipt-signing-source")
    need(all(type(final[key]) is int and 0 < final[key] <= (68 if setup else 512) * 1024 * 1024 for key in ("unsignedBytes", "signedBytes", "packageBytes"))
         and final["signedBytes"] < final["packageBytes"] <= final["signedBytes"] + 1024 * 1024
         and final["packageBytes"] == package_size and final["packageSha256"] == package_sha
         and type(final["packageMode"]) is int and final["packageMode"] == 0o444
         and type(final["scriptFileCount"]) is int
         and (final["scriptFileCount"] == 4 if setup else final["scriptFileCount"] == 2 if remove else 0 < final["scriptFileCount"] <= (runtime_stager.MAX_FILES if runtime_stager is not None else 4096))
         and all(sha(final[key]) for key in ("unsignedSha256", "signedSha256", "packageSha256", "originalPackageSha256",
                                           "packageInfoSha256", "installerProfileSha256", "notaryProfileSha256", "logSha256")),
         "final-package-receipt-byte-correspondence")
    if setup:
        # These hashes come from the independently audited current component,
        # never from this receipt itself or a renderer/ambient nomination.
        need(all(final[key] == expected for key, expected in setup_originals.items())
             and type(final["finalDestinationPayloadEntries"]) is int
             and final["finalDestinationPayloadEntries"] == 4, "setup-receipt-originals")
    need(final["status"] == "Accepted" and notary_uuid(final["submissionId"]) == final["submissionId"]
         and type(final["sha256Compared"]) is bool and type(final["errorCount"]) is int and final["errorCount"] == 0
         and all(type(final[key]) is int and 0 <= final[key] <= 2048 for key in ("warningCount", "ticketRowCount"))
         and value["notarySubmission"] == {"id": final["submissionId"], "status": "Accepted"}
         and all(final[key] is True for key in ("trustedSignatureBeforeAndAfter", "trustedTimestampBeforeAndAfter", "actualStaplerValidation",
                                               "signedPrefixUnchanged", "completeScriptsAudited"))
         and final["assurance"] == ("final-setup-package-observation-not-installed-or-xcode-setup-authority" if setup
                                    else "final-package-observation-not-installed-or-final-carrier-authority"),
         "final-package-receipt-notarization")
    return final


def credential_values(environment):
    """Bounded secrets only; neither inputs nor their hashes are public evidence."""
    encoded, password = (environment.get(key) for key in CREDENTIAL_VARIABLES)
    need(type(encoded) is str and 4 <= len(encoded) <= 43692 and encoded.isascii()
         and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded) is not None
         and type(password) is str and 1 <= len(password) <= 1024
         and all(0x20 <= ord(value) <= 0x7e for value in password), "credential-input-bound")
    try:
        body = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise Refused("credential-base64") from None
    need(0 < len(body) <= 32768 and base64.b64encode(body).decode("ascii") == encoded, "credential-base64")
    return body, password


def credential_paths(body, *, single=False):
    """Decode only security's quoted user-domain path list, without escapes."""
    need(type(body) is bytes and len(body) <= 16384 and (not body or body.endswith(b"\n")), "credential-search-format")
    paths = []
    for line in body.splitlines(keepends=True):
        match = re.fullmatch(rb'[ \t]*"(/[\x20-\x21\x23-\x5b\x5d-\x7e]{1,4094})"\n', line)
        need(match is not None, "credential-search-format")
        path = match[1].decode("ascii")
        need(all(part not in ("", ".", "..") for part in path[1:].split("/")), "credential-search-format")
        paths.append(path)
    need(len(paths) <= 16 and len(paths) == len(set(paths)) and (not single or len(paths) == 1), "credential-search-format")
    return tuple(paths)


def credential_identity(identity_body, certificate_body, identity, certificates):
    """Exact public SOURCE identity and cert bytes; no general PKCS12 parser."""
    signing_requirement(identity, PYTHON_IDENTIFIER)
    need(type(identity_body) is bytes and type(certificate_body) is bytes
         and len(identity_body) <= 16384 and len(certificate_body) <= 16384
         and type(certificates) is tuple and len(certificates) == 3 and all(type(value) is bytes for value in certificates),
         "credential-identity-bound")
    try:
        text = identity_body.decode("utf-8")
    except UnicodeError:
        raise Refused("credential-identity-format") from None
    rows, summaries = [], []
    for line in text.splitlines():
        match = re.fullmatch(r'[ \t]*1\) ([0-9A-Fa-f]{40}) "([^"\x00-\x1f\x7f]{1,512})"', line)
        if match is not None:
            rows.append(match[1].lower())
        elif re.fullmatch(r"[ \t]*1 valid identities found", line):
            summaries.append(True)
        else:
            need(not line.strip(), "credential-identity-format")
    need(rows == [identity[1]] and summaries == [True], "credential-source-identity")
    pattern = rb"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n"
    values, end = [], 0
    for match in re.finditer(pattern, certificate_body):
        need(match.start() == end and len(values) < 3, "credential-certificate-format")
        encoded = match[1].replace(b"\n", b"")
        try:
            value = base64.b64decode(encoded, validate=True)
        except ValueError:
            raise Refused("credential-certificate-format") from None
        need(0 < len(value) <= 16384 and base64.b64encode(value) == encoded, "credential-certificate-format")
        values.append(value); end = match.end()
    need(end == len(certificate_body) and values and len(values) == len(set(values))
         and certificates[0] in values and all(value in certificates for value in values), "credential-source-certificates")


def credential_cdhash(body):
    need(type(body) is bytes and len(body) <= 16384, "producer-cdhash-bound")
    try:
        text = body.decode("utf-8")
    except UnicodeError:
        raise Refused("producer-cdhash-format") from None
    hashes = [line for line in text.splitlines() if line.startswith("CDHash=")]
    signatures = [line for line in text.splitlines() if line.startswith("Signature=")]
    need(len(hashes) == 1 and re.fullmatch(r"CDHash=[0-9a-f]{40}", hashes[0]) is not None
         and signatures == ["Signature=adhoc"], "producer-cdhash-format")
    return hashes[0][7:]


def python_sign_command(path, entitlements, phase, identity):
    need(phase in PYTHON_PHASES and isinstance(path, Path) and isinstance(entitlements, Path), "python-sign-purpose")
    if phase == "python-engineering":
        signer, timestamp = "-", "--timestamp=none"
    else:
        signing_requirement(identity, PYTHON_IDENTIFIER)
        signer, timestamp = identity[1], "--timestamp"
    return ["/usr/bin/codesign", "--force", "--sign", signer, "--identifier", PYTHON_IDENTIFIER,
            "--options", "runtime", "--entitlements", str(entitlements), timestamp, str(path)]


def python_code_flags(body, machine, phase, matcher):
    """Observe bounded signed headers; codesign, not this reader, verifies crypto."""
    need(phase in PYTHON_PHASES and type(body) is bytes and 0 < len(body) <= MAX_HELPER, "python-signed-image-bound")
    records = matcher.macho_records(body, machine)
    commands = [row for row in records if row["command"] == 0x1D]
    need(len(commands) == 1 and commands[0]["size"] == 16, "python-signature-command")
    offset, size = struct.unpack_from("<II", body, commands[0]["offset"] + 8)
    need(offset >= 32 + struct.unpack_from("<I", body, 20)[0] and 12 <= size <= 1024 * 1024
         and offset + size == len(body), "python-signature-range")
    blob = body[offset:]
    magic, length, count = struct.unpack_from(">III", blob)
    need(magic == 0xFADE0CC0 and 1 <= count <= 32 and 12 + count * 8 <= length <= size,
         "python-signature-superblob")
    # LC_CODE_SIGNATURE allocation may exceed the declared SuperBlob. Parse
    # only that extent; preserve the complete signed body for native verification.
    blob = blob[:length]
    intervals, slots, flags = [], set(), {}
    for index in range(count):
        slot, start = struct.unpack_from(">II", blob, 12 + index * 8)
        need(slot not in slots and 12 + count * 8 <= start <= length - 8, "python-signature-index")
        slots.add(slot)
        kind, extent = struct.unpack_from(">II", blob, start)
        end = start + extent
        need(extent >= 8 and end <= length and all(end <= left or start >= right for left, right in intervals),
             "python-signature-components")
        intervals.append((start, end))
        if slot == 0 or 0x1000 <= slot < 0x1005:
            need(kind == 0xFADE0C02 and extent >= 44, "python-code-directory")
            version, value = struct.unpack_from(">II", blob, start + 8)
            need(0x20001 <= version <= 0x2F000 and value & 0x10002 == (0x10002 if phase == "python-engineering" else 0x10000),
                 "python-runtime-signature-flags")
            flags[slot] = value
    need(0 in flags and 1 <= len(flags) <= 6 and len(set(flags.values())) == 1, "python-code-directory-agreement")
    return [flags[key] for key in sorted(flags)]


def python_signature_diagnostic(original, body, machine, matcher):
    """Failure-only original-byte DATA, never signature or native authority."""
    need(type(original) is bytes and type(body) is bytes
         and 0 < len(original) <= MAX_HELPER and 0 < len(body) <= MAX_HELPER
         and type(machine) is str and machine in ("arm64", "x86_64"), "python-signature-diagnostic-bound")
    records = matcher.macho_records(body, machine)
    commands = [row for row in records if row["command"] == 0x1D]
    need(len(commands) == 1 and commands[0]["size"] == 16, "python-signature-diagnostic-command")
    offset, size = struct.unpack_from("<II", body, commands[0]["offset"] + 8)
    need(offset >= 32 + struct.unpack_from("<I", body, 20)[0] and 12 <= size <= 1024 * 1024
         and offset + size == len(body), "python-signature-diagnostic-range")
    magic, length, count = struct.unpack_from(">III", body, offset)
    tail, tail_zero = None, None
    if 12 <= length <= size:
        start, end = offset + length, offset + size
        remaining = body[start:end]
        nonzero, first, last = 0, None, None
        for position, value in enumerate(remaining):
            if value:
                nonzero += 1
                if first is None:
                    first = position
                last = position
        # Positions are relative to this tail, not raw bytes or process paths.
        tail_zero = nonzero == 0
        tail = {"bytes": len(remaining), "nonzeroBytes": nonzero, "firstNonzeroOffset": first,
                "lastNonzeroOffset": last, "sha256": digest(remaining),
                "matchesOriginalInput": original[start:end] == remaining if end <= len(original) else None}
    result = {"schemaVersion": 1, "available": True, "authority": "original-byte-data-only",
        "input": {"bytes": len(original), "sha256": digest(original)},
        "output": {"bytes": len(body), "sha256": digest(body)},
        "signature": {"offset": offset, "allocatedBytes": size, "magic": magic, "declaredBytes": length, "count": count},
        "predicates": {"magicKnown": magic == 0xFADE0CC0, "countAtLeastOne": count >= 1,
            "countAtMost32": count <= 32, "indexFitsDeclared": 12 + count * 8 <= length,
            "declaredFitsAllocation": length <= size, "allocationTailZero": tail_zero},
        "tail": tail}
    # Every value is constructed from exact bytes, uint32 unpacking, len(),
    # comparison booleans, or explicit nulls; no decoded/arbitrary fields.
    need(len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii")) <= 1536,
         "python-signature-diagnostic-output-bound")
    return result


class Refused(ValueError):
    pass


def need(value, label):
    if not value:
        raise Refused(label)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _CreatedDmgXattrs:
    """Fixed Darwin FD APIs for our fresh, unsigned hdiutil output only."""

    def __init__(self):
        need(sys.platform == "darwin", "created-image-native-host")
        import ctypes
        self.ctypes = ctypes
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        self.list = library.flistxattr
        self.list.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        self.list.restype = ctypes.c_ssize_t
        self.get = library.fgetxattr
        self.get.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p,
                            ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
        self.get.restype = ctypes.c_ssize_t
        self.remove = library.fremovexattr
        self.remove.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        self.remove.restype = ctypes.c_int

    def names(self, fd):
        size = self.list(fd, None, 0, 0)
        need(size in (0, len(b"com.apple.FinderInfo\0")), "created-image-attribute-list")
        if size == 0:
            return b""
        buffer = self.ctypes.create_string_buffer(size)
        need(self.list(fd, buffer, size, 0) == size, "created-image-attribute-list-read")
        return buffer.raw

    def finder_info(self, fd):
        # Apple ATTR_CMN_FNDRINFO is exactly FileInfo + ExtendedFileInfo (32B).
        need(self.get(fd, b"com.apple.FinderInfo", None, 0, 0, 0) == 32,
             "created-image-finder-info-size")
        buffer = self.ctypes.create_string_buffer(32)
        need(self.get(fd, b"com.apple.FinderInfo", buffer, 32, 0, 0) == 32,
             "created-image-finder-info-read")
        return buffer.raw

    def remove_finder_info(self, fd):
        need(self.remove(fd, b"com.apple.FinderInfo", 0) == 0,
             "created-image-finder-info-remove")


def _normalize_created_dmg_finder_info(fd, recheck, no_xattrs, *, api=None):
    """Normalize one tool-generated attribute BEFORE signing, never user assets.

    The caller authorizes the fresh original and retains FD/parent custody and
    its existing deadline. Recheck returns the current named/held identity.
    Only the single removal's ctime transition is authorized; strict stager
    policy and complete image bytes are unchanged. An injected API is DATA
    test plumbing, not a production platform fallback.
    """
    need(type(fd) is int and fd >= 0, "created-image-original-fd")
    before = recheck()
    need(type(before) is tuple and len(before) == 9 and before == signature(os.fstat(fd))
         and stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) in (0o600, 0o644, 0o444)
         and before[3] == 1 and before[4] == os.getuid() and before[5] == os.getgid()
         and 0 < before[6] <= 512 * 1024 * 1024, "created-image-original-shape")

    def checked(expected):
        need(recheck() == expected == signature(os.fstat(fd)), "created-image-original-changed")

    def stream(expected):
        sha, offset = hashlib.sha256(), 0
        while offset < expected[6]:
            checked(expected)
            block = os.pread(fd, min(1024 * 1024, expected[6] - offset), offset)
            need(bool(block), "created-image-original-short-read")
            sha.update(block); offset += len(block)
        need(os.pread(fd, 1, offset) == b"", "created-image-original-eof")
        checked(expected)
        return sha.digest()

    api = _CreatedDmgXattrs() if api is None else api
    checked(before)
    names = api.names(fd)
    checked(before)
    need(type(names) is bytes and names in (b"", b"com.apple.FinderInfo\0"),
         "created-image-only-finder-info")
    if not names:
        no_xattrs(fd)
        checked(before)
        return before
    value = api.finder_info(fd)
    checked(before)
    need(type(value) is bytes and len(value) == 32, "created-image-finder-info-value")
    sha = stream(before)
    # Re-admit the exact metadata immediately before the one permitted change.
    need(api.names(fd) == names, "created-image-attribute-list-changed")
    checked(before)
    api.remove_finder_info(fd)
    after = recheck()
    need(type(after) is tuple and len(after) == 9 and after[:8] == before[:8]
         and after == signature(os.fstat(fd)), "created-image-metadata-transition")
    no_xattrs(fd)  # Unchanged strict production policy, not an allowlist.
    checked(after)
    need(stream(after) == sha, "created-image-normalization-bytes")
    checked(after)
    return after


def cleanup_mount_device_data(body, stderr, code, mountpoint):
    """Cleanup nomination only; the unchanged strict parser still gates use."""
    need(type(code) is int and code == 0 and type(body) is bytes and 0 < len(body) <= 65536
         and type(stderr) is bytes and len(stderr) <= 65536 and b"\x00" not in body
         and b"<!ENTITY" not in body.upper(), "package-cleanup-attach-data")
    value = plistlib.loads(body)
    need(type(value) is dict and len(value) <= 12 and all(type(k) is str for k in value)
         and type(value.get("system-entities")) is list and 0 < len(value["system-entities"]) <= 8,
         "package-cleanup-attach-plist")
    rows = value["system-entities"]
    need(all(type(row) is dict and len(row) <= 12 and all(type(k) is str for k in row) for row in rows),
         "package-cleanup-attach-rows")
    mounted = [row for row in rows if "mount-point" in row]
    need(len(mounted) == 1 and type(mounted[0]["mount-point"]) is str
         and mounted[0]["mount-point"] == str(mountpoint), "package-cleanup-attach-mount")
    device = mounted[0].get("dev-entry")
    need(type(device) is str and re.fullmatch(r"/dev/disk[0-9]{1,5}(?:s[0-9]{1,3})?", device) is not None,
         "package-cleanup-attach-device")
    return device


def directory_identity(info):
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
         and info.st_gid == os.getgid() and not info.st_mode & 0o022, "directory-owner-mode")
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def build_profile(target):
    """Declared compile target only; never supplier/service/native qualification."""
    need(type(target) is str and target in (ARM_TARGET, INTEL_TARGET), "closed-build-target")
    if target == ARM_TARGET:
        return "arm64", "ARM64", "desktop/macos-installed-inputs/build-release.json"
    return "x86_64", "X64", "desktop/macos-installed-inputs/build-release-intel.json"


def entrypoint(argv):
    need(type(argv) is list and len(argv) in (2, 4) and all(type(value) is str for value in argv)
         and argv[1] in (APP_SIGNATURE_SUMMARY,) + PHASES + SUPPORT_PHASES + STORE_SIGNING_PHASES + PYTHON_PHASES + SIGNING_PHASES + TOOL_SIGNING_PHASES + TOOL_SELECTION_PHASES + TOOL_PROJECT_PHASES + NOTARY_PHASES + FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES + REMOVAL_OWNER_PHASES and (len(argv) == 2 or argv[2] == "--target"), "closed-entrypoint")
    target = ARM_TARGET if len(argv) == 2 else argv[3]
    build_profile(target)
    return argv[1], target


def artifact(messages, checkout, target, *, package_version, build_target=ARM_TARGET):
    """One real resident cdylib graph; version comes from checked build selection."""
    need(type(package_version) is str and len(package_version) <= 32
         and re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", package_version) is not None,
         "compiler-application-version")
    build_profile(build_target)
    need(type(messages) is bytes and 0 < len(messages) <= 4 * 1024 * 1024
         and messages.endswith(b"\n"), "compiler-bound")
    def pairs(items):
        output = {}
        for key, value in items:
            need(key not in output, "compiler-duplicate-key")
            output[key] = value
        return output
    try:
        rows = [json.loads(line, object_pairs_hook=pairs) for line in messages.splitlines()]
    except (ValueError, TypeError, RecursionError) as error:
        raise Refused("compiler-json") from error
    need(1 < len(rows) <= 8192 and all(type(row) is dict for row in rows), "compiler-rows")
    records, finished = [], False
    for row in rows:
        need(not finished and row.get("reason") in
             ("compiler-artifact", "compiler-message", "build-script-executed", "build-finished"), "compiler-terminal-order")
        if row["reason"] == "build-finished":
            need(set(row) == {"reason", "success"} and row["success"] is True, "compiler-finish")
            finished = True
        elif row["reason"] == "compiler-artifact":
            need(type(row.get("target")) is dict and type(row.get("filenames")) is list
                 and all(type(value) is str for value in row["filenames"]), "compiler-artifact-shape")
            records.append(row)
    need(finished and not any(row["target"].get("kind") in (["bin"], ["test"], ["example"], ["bench"])
                             for row in records), "resident-image-only-graph")
    source = checkout / WORKSPACE
    binary = target / build_target / "release" / RESIDENT_IMAGE
    selected = [row for row in records if row["target"].get("name") == IMAGE_TARGET
                or str(binary) in row["filenames"] or row.get("executable") == str(binary)]
    need(len(selected) == 1, "one-resident-image")
    row = selected[0]
    need(not any(item is not row and item["target"].get("kind") == ["cdylib"] for item in records),
         "resident-image-only-graph")
    need(row.get("package_id") == "path+" + source.as_uri() + "#" + HELPER + "@0.1.0"
         and row.get("manifest_path") == str(source / "Cargo.toml")
         and row.get("features") == [] and "executable" in row and row["executable"] is None
         and row["filenames"] == [str(binary)], "helper-package-artifact")
    target_row = row["target"]
    need(target_row.get("name") == IMAGE_TARGET and target_row.get("kind") == ["cdylib"]
         and target_row.get("crate_types") == ["cdylib"]
         and target_row.get("src_path") == str(source / "src/lib.rs")
         and target_row.get("edition") == "2021", "helper-release-graph")
    selected_rows = [row]
    for directory, package, name, features in (
        ("desktop/src-tauri", "mobile-release-kit-desktop", "mobile_release_desktop",
         ["macos-android-registration-helper", "macos-installed-resident-image"]),
        ("desktop/native/macos-installed-native", "mrk-macos-installed-native", "mrk_macos_installed_native",
         ["android-registration-helper", "default", "resident-image"]),
    ):
        libraries = [item for item in records if item["target"].get("name") == name]
        need(len(libraries) == 1, "helper-one-library")
        library = libraries[0]
        need(library.get("package_id") == "path+" + (checkout / directory).as_uri() + "#" + package + ("@" + package_version if package == "mobile-release-kit-desktop" else "@0.1.0")
             and library.get("manifest_path") == str(checkout / directory / "Cargo.toml")
             and library.get("features") == features
             and library["target"].get("src_path") == str(checkout / directory / "src/lib.rs")
             and library["target"].get("kind") == ["lib"] and library["target"].get("crate_types") == ["lib"]
             and library["target"].get("edition") == "2021"
             and "executable" in library and library["executable"] is None, "helper-separate-library-features")
        selected_rows.append(library)
    for selected in selected_rows:
        expected_opt = "1" if build_target == INTEL_TARGET and selected is selected_rows[1] else "3"
        profile = selected.get("profile")
        need(type(profile) is dict and profile.get("test") is False and profile.get("debug_assertions") is False
             and profile.get("opt_level") == expected_opt and type(selected.get("fresh")) is bool, "helper-release-profile")
    return binary


def direct_rust_tools(target=ARM_TARGET):
    """Closed SOURCE path selection only; actual workflow admission is separate."""
    build_profile(target)
    directory = "/Users/runner/.rustup/toolchains/" + rust_toolchain(target) + "-" + target + "/bin"
    return directory + "/cargo", directory + "/rustc"


def prepare_roles(target):
    build_profile(target)
    return (("resident-fetch",) if target == INTEL_TARGET else ()) + PREPARE_ROLES


def rust_toolchain(target=ARM_TARGET):
    """Pinned compiler release; the original tool query is separate."""
    build_profile(target)
    return "1.98.0" if target == INTEL_TARGET else "1.98.1"


def build_environment(environment, work, release, *, target=ARM_TARGET):
    # release is the SAME owner's parsed, held source build-release projection;
    # direct tools cannot fall back to a rustup shim or inherited selector.
    need(type(release) is str and 0 < len(release) < 64 and release.isascii()
         and re.fullmatch(r"[a-z0-9_.-]*[a-z0-9]", release) is not None, "image-source-release")
    cargo, rustc = direct_rust_tools(target)
    toolchain = rust_toolchain(target)
    need(environment.get("HOME") == "/Users/runner"
         and environment.get("CARGO_HOME", "/Users/runner/.cargo") == "/Users/runner/.cargo"
         and environment.get("RUSTUP_HOME", "/Users/runner/.rustup") == "/Users/runner/.rustup"
         and environment.get("RUSTC", rustc) == rustc
         and environment.get("RUSTUP_TOOLCHAIN", toolchain) == toolchain
         and environment.get("RUSTUP_AUTO_INSTALL", "0") == "0", "direct-rust-source-route")
    selected = {key: environment[key] for key in ("DEVELOPER_DIR", "MACOSX_DEPLOYMENT_TARGET")}
    selected.update(PATH=cargo.rsplit("/", 1)[0] + ":/usr/bin:/bin:/usr/sbin:/sbin", HOME="/Users/runner",
                    CARGO_HOME="/Users/runner/.cargo", RUSTUP_HOME="/Users/runner/.rustup", RUSTC=rustc,
                    LANG="C", LC_ALL="C", TZ="UTC", RUSTUP_TOOLCHAIN=toolchain, RUSTUP_AUTO_INSTALL="0",
                    CARGO_INCREMENTAL="0", CARGO_TARGET_DIR=str(work / "android-helper-target"),
                    TMPDIR=str(work / "android-helper-target/tmp"),
                    MRK_MACOS_INSTALL_SOURCE_COMMIT=environment["GITHUB_SHA"], MRK_IMAGE_RELEASE_ID=release)
    return selected


def original_failure(error, owner, checkout, timeout, limit):
    """Bounded original exception DATA; never output, completion or custody proof."""
    need(type(timeout) is int and 0 < timeout < 2 ** 31
         and type(limit) is int and 0 < limit < 2 ** 31, "diagnostic-request-bound")
    error_type = next((name for name in ("ProcessError", "ProcessCleanupError", "ProcessOutcomeUnknown")
                       if type(error) is getattr(owner, name, None)), "other")
    classification = "unclassified"
    if error_type != "other":
        # Bypass subclass properties; never render an arbitrary exception.
        arguments = BaseException.args.__get__(error)
        if type(arguments) is tuple and len(arguments) == 1 and type(arguments[0]) is str and len(arguments[0]) <= 128:
            classification = {
                "owned command output exceeds its bound": "output-bound",
                "owned command exceeded its original deadline": "deadline",
                "owned command protocol or original ownership is incomplete": "protocol-or-original-ownership",
                "owned command original parent ended": "original-parent-ended",
                "owned command cleanup could not be confirmed": "cleanup-unconfirmed",
                "owned command failed, timed out, or produced incomplete output": "failed-timeout-or-incomplete-output",
                "owned command executable could not be started": "exec-rejected",
                "owned command was stopped before execution": "stopped-before-execution",
                "owned command produced incomplete output": "incomplete-output",
            }.get(arguments[0], "unclassified")
    # load_owner admitted these exact SOURCE files before the original call.
    # No basename/normalization aliases, filesystem reads or frame locals here.
    sources = {str(checkout / "src/mobile_release" / name): "src/mobile_release/" + name
               for name in ("owned_process.py", "_command_process.py", "_native_process.py", "cancellation.py")}
    frames, visited, foreign = [], 0, 0
    trace = BaseException.__traceback__.__get__(error)
    while trace is not None and visited < 32:
        visited += 1
        code = trace.tb_frame.f_code
        filename, function, line = code.co_filename, code.co_name, trace.tb_lineno
        source = sources.get(filename) if type(filename) is str and len(filename) <= 4096 else None
        if source is None:
            foreign += 1
        elif (type(function) is str and len(function) <= 64
              and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*|<(?:module|lambda|listcomp|setcomp|dictcomp|genexpr)>", function)
              and type(line) is int and 0 < line <= 1000000):
            if len(frames) == 8:
                frames.pop(0)
            frames.append({"source": source, "function": function, "line": line})
        trace = trace.tb_next
    result = {"schemaVersion": 1, "available": True, "ownerErrorType": error_type,
              "classification": classification, "timeoutSeconds": timeout,
              "outputLimitBytes": limit, "captureMode": "bytes", "frames": frames,
              "visitedFrames": visited, "omittedFrames": visited - len(frames),
              "foreignFrames": foreign, "tracebackTruncated": trace is not None}
    observed = error.__dict__.get("owner_finality_diagnostic") if error_type != "other" else None
    valid = (type(observed) is tuple and len(observed) == 5
             and all(type(value) is int for value in observed[:4]) and observed[0] == 1
             and observed[1] in (0, 1) and 0 <= observed[2] <= (1023 if observed[1] == 0 else 1048575)
             and 0 <= observed[3] <= 15 and (observed[4] is None or type(observed[4]) is int
             and observed[1] == 1 and (observed[4] in (0, 32) or 48 <= observed[4] <= 63)))
    result["ownerFinality"] = list(observed) if valid else None
    need(len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii")) <= 2048,
         "original-failure-diagnostic-bound")
    return result


# Public failure DATA only. SOURCE-selected labels, never exception text or a
# diagnostic grant of command/cleanup/signature authority. Unknown labels stay
# unclassified; in particular exact Refused class alone is not a sanitizer.
DISTRIBUTION_STAGER_REASONS = frozenset(('distribution-attach-original', 'distribution-attach-plist', 'distribution-attach-entity', 'distribution-attach-mount', 'distribution-attach-single-mount', 'distribution-package-name', 'distribution-three-file-roster', 'distribution-original-byte-mode'))

# Closed passive input guards only; these labels never confer native or finality authority.

# Fixed first-failing post-staple facts only; never native/finality authority.
FINAL_IMAGE_UNLINK_FLAGS = ('retainedPreIdentityExpected', 'retainedPreLinkUnlinked', 'namedExists', 'namedSameDevice', 'namedRegular', 'namedModeExpected', 'namedOwnerExpected', 'namedGroupExpected', 'namedSingleLink', 'namedSizeBounded', 'namedGrowthBounded', 'namedInodeDifferent', 'heldNameIdentityDifferent', 'parentStable', 'censusStable', 'retainedPreBytesUnchanged', 'namedPostStable')
FINAL_IMAGE_STAPLE_STAGES = ('final-image-staple-clock', 'final-image-staple-parent', 'final-image-staple-held-stat', 'final-image-staple-held-device', 'final-image-staple-held-inode', 'final-image-staple-held-mode', 'final-image-staple-held-links', 'final-image-staple-held-links-unlinked', 'final-image-staple-held-links-other', 'final-image-staple-held-uid', 'final-image-staple-held-gid', 'final-image-staple-size', 'final-image-staple-growth', 'final-image-staple-name-stat', 'final-image-staple-binding', 'final-image-staple-xattr-query', 'final-image-staple-xattrs-present', 'final-image-staple-stream', 'final-image-staple-post', 'final-image-staple-returned-input', 'final-image-staple-returned-preimage', 'final-image-staple-returned-name', 'final-image-staple-returned-acquire', 'final-image-staple-returned-stream', 'final-image-staple-returned-commit')
FINAL_IMAGE_STAPLE_REASONS = frozenset(('final-image-stapled-original', 'file-extended-attributes-query', 'file-extended-attributes', 'notary-monotonic-clock', 'directory-original-unavailable', 'directory-parent-changed', 'directory-original-unbound', 'directory-original-changed', 'notary-zip-original', 'notary-zip-short-read', 'notary-zip-post', 'final-image-directory-census', 'final-image-input-changed', 'final-image-output-changed', 'final-image-target-census', 'final-package-preimage-unavailable', 'final-package-preimage-metadata', 'final-package-preimage-short-read', 'final-package-preimage-content', 'final-package-preimage-post'))

FINAL_IMAGE_INPUT_STAGES = (
    'final-image-original-inputs',
    'final-image-package-owner',
    'final-image-original-readback',
    'final-image-package-audit',
    'final-image-producer',
    'final-image-source-profiles',
    'final-image-original-image',
)
FINAL_IMAGE_INPUT_STAGER_REASONS = frozenset((
    'build-release-identity',
    'build-release-shape',
    'build-release-size',
    'build-release-version',
    'build-target',
    'duplicate-json-key',
    'installer-export-byte-bound',
    'json-byte-bound',
    'json-constant',
    'json-shape-bound',
    'maintenance-export-action',
    'maintenance-export-binding',
    'maintenance-export-shape',
    'maintenance-policy-binding',
    'maintenance-policy-digest-or-order',
    'maintenance-policy-membership',
    'maintenance-policy-row',
    'maintenance-policy-shape',
    'maintenance-predecessor-order',
    'maintenance-producer-binding',
    'maintenance-producer-shape',
    'maintenance-record-byte-bound',
    'maintenance-record-encoding-or-shape',
    'maintenance-record-map',
    'maintenance-release-binding',
    'maintenance-release-set-bound',
    'maintenance-release-set-shape',
    'maintenance-release-shape',
    'maintenance-request-id',
    'maintenance-reused-release-identity',
    'maintenance-signing-policies-bound',
    'maintenance-write-accounting',
    'producer-emitter-original',
    'producer-emitter-package-binding',
    'producer-emitter-summary',
    'registration-reservation-creation-incomplete',
    'registration-reservation-not-predecessor-creation',
    'registration-reservation-parent-not-settled',
    'registration-reservation-result',
    'registration-reservation-reuse-not-observed',
    'registration-reservation-unentered',
    'source-producer-correspondence',
    'source-producer-profile',
    'source-producer-unconfigured',
    'source-service-profile',
))

# Existing notary guards only. A zero log command can still carry an Invalid
# submission or fail its strict DATA parser; neither is native success evidence.
_FAILURE_NOTARY_REASONS = (
    "notary-selected-tool-path", "notary-selected-tool-ancestry",
    "notary-selected-tool-original", "notary-selected-tool-changed",
    # Final input staging is after successful Apple checks. Preserve its exact
    # finite refusal instead of misdiagnosing another Apple rejection.
    'applications-launcher-copy-role', 'applications-launcher-input-pair',
    'applications-launcher-roster', 'applications-launcher-file', 'applications-launcher-info',
    'applications-launcher-version', 'applications-launcher-icon', 'applications-launcher-signed-digest',
    'applications-launcher-ticket-digest', 'applications-launcher-installed-correspondence',
    'ticket-launcher-role', 'ticket-input-expectations', 'ticket-input-correspondence',
    'signed-app-roster', 'input-executable-scope', 'installer-inventory-bound', 'installer-complete-byte-bound',
    'notary-submission-invalid', 'notary-fixed-archive-name', 'notary-uuid',
    'notary-json-bound', 'notary-json-keys', 'notary-json-constant', 'notary-json-format', 'notary-json-object',
    'notary-submit-terminal', 'notary-submit-metadata', 'notary-submit-archive',
    'notary-log-binding', 'notary-log-metadata', 'notary-log-status-code', 'notary-log-upload-sha256',
    'notary-log-issues-bound', 'notary-log-issue-shape', 'notary-log-issue-metadata', 'notary-log-issue-code',
    'notary-log-tickets-bound', 'notary-log-ticket-shape', 'notary-log-success-with-errors',
    'notary-log-ticket-path', 'notary-log-ticket-digest-algorithm',
    'notary-log-ticket-digest', 'notary-log-ticket-architecture',
    'notary-monotonic-clock', 'notary-group-deadline', 'notary-io-unknown', 'notary-fixed-role-order',
    'notary-child-timeout', 'notary-child-settlement-reserve', 'notary-key-role',
    'notary-authentication-not-retired', 'notary-final-stdout-short-write',
    *("original-nonzero-" + role for role in notary_roles(True)),
)

# These are observations, not Installer success or package-service finality.
_PACKAGE_DIAGNOSTIC_ROLES = (
    'producer-tests', 'producer-build', 'producer-emitter', 'distribution-create',
    'distribution-sign', 'distribution-verify-signature', 'distribution-verify-image',
    'observation-create', 'observation-sign', 'observation-verify-signature',
    'observation-verify-image', 'distribution-attach', 'installer-log-cursor',
    'installer', 'installer-log-capture', 'distribution-detach',
)
_INSTALLER_PHASES = ('entry', 'target-ok', 'relative-entry', 'absolute-entry', 'cwd-ok', 'pre-exec')
_INSTALLER_REFUSALS = ('target', 'entry', 'cwd')
_INSTALLER_ACL_ROLES = ('input-directory', 'input-inventory', 'system-root', 'system-library',
                        'system-support', 'other-protected-object')
_INSTALLER_ACL_PHASES = ('filesec-allocation', 'fstatx-snapshot', 'snapshot-owner', 'snapshot-group',
    'snapshot-mode', 'acl-presence', 'acl-conversion', 'acl-object', 'acl-validation',
    'acl-first-entry', 'acl-entry-present', 'acl-free', 'ffi-output')
# Interpret only these known static parent reasons. Composite refusals remain
# composite: neither a timer expiration nor a file-count overflow is inferred.
_INSTALLER_PARENT_REASONS = {
    'deadline': 'deadline', 'worker-work-deadline': 'worker-work-deadline',
    'worker-final-deadline': 'worker-final-deadline',
    'deadline-or-unknown': 'deadline-or-ownership-unknown',
    'export-deadline-or-unknown': 'deadline-or-ownership-unknown',
    'directory-bound': 'directory-policy-or-bound',
    'read-bound': 'original-read-bound',
    'acl-refused': 'acl-refusal', 'export-acl-refused': 'acl-refusal',
    'worker-self-image': 'worker-image-refusal',
}
_INSTALLER_LOG_REASONS = frozenset((
    'log-input-binding', 'log-file-policy', 'log-file-identity', 'log-cursor-shape', 'log-cursor-binding',
    'log-cursor-offset', 'log-anchor-rewritten', 'log-truncated', 'log-incomplete-boundary',
    'log-interval-bound', 'log-line-bound', 'log-selected-bound', 'log-metadata-bound',
    'log-no-project-lines', 'log-read-incomplete', 'log-output-readback', 'original-close-unknown',
    'ancestor-close-unknown', 'log-output-unavailable', 'log-input-or-capture-unavailable',
))


def installer_markers_data(value):
    """Revalidate only finite failure diagnostics, never arbitrary marker payloads."""
    if type(value) is not dict or set(value) != {'phases', 'refusals', 'acl', 'parent', 'omitted'}:
        return None
    if type(value['omitted']) is not bool:
        return None
    for key, choices in (('phases', _INSTALLER_PHASES), ('refusals', _INSTALLER_REFUSALS)):
        rows = value[key]
        if (type(rows) is not list or len(rows) > len(choices)
                or any(type(v) is not str or v not in choices for v in rows)
                or rows != [v for v in choices if v in rows]):
            return None
    for key in ('acl', 'parent'):
        rows = value[key]
        if type(rows) is not list or len(rows) > 2:
            return None
        for row in rows:
            if key == 'acl':
                fields = {'role', 'phase', 'result', 'call', 'errno', 'freeCall', 'freeErrno'}
                if (type(row) is not dict or set(row) != fields
                        or type(row['role']) is not str or row['role'] not in _INSTALLER_ACL_ROLES
                        or type(row['phase']) is not str or row['phase'] not in _INSTALLER_ACL_PHASES
                        or any(type(row[k]) is not int or not -9999999999 <= row[k] <= 9999999999
                               for k in fields - {'role', 'phase'})):
                    return None
            elif (type(row) is not dict or set(row) != {'exit', 'originals', 'native', 'timely', 'unknown', 'category', 'reasonSha256'}
                    or type(row['exit']) is not int or row['exit'] not in (1, 20)
                    or type(row['category']) is not str or row['category'] not in (*_INSTALLER_PARENT_REASONS.values(), 'unclassified')
                    or type(row['reasonSha256']) is not str or re.fullmatch(r'[0-9a-f]{64}', row['reasonSha256']) is None
                    or any(type(row[k]) is not bool for k in ('originals', 'native', 'timely', 'unknown'))):
                return None
    return {'phases': list(value['phases']), 'refusals': list(value['refusals']),
            'acl': [dict(v) for v in value['acl']], 'parent': [dict(v) for v in value['parent']],
            'omitted': value['omitted']}


def installer_markers(stdout, stderr):
    """Same-owned nonzero Installer captures only; no file reads or raw text export.

    Uses the existing fixed-consumer marker grammar, with a smaller package-only
    projection. Kept local so bootstrap acquisition need not load another owner.
    """
    try:
        if type(stdout) is not bytes or type(stderr) is not bytes or len(stdout) + len(stderr) > 256 * 1024:
            return None
        value = {'phases': [], 'refusals': [], 'acl': [], 'parent': [], 'omitted': False}
        patterns = (
            ('phases', re.compile(rb'(?<![A-Za-z0-9_])MRK_MACOS_POSTINSTALL_PHASE=(' + b'|'.join(v.encode() for v in _INSTALLER_PHASES) + rb')(?![A-Za-z0-9_-])'), 6),
            ('refusals', re.compile(rb'(?<![A-Za-z0-9_])MRK_MACOS_POSTINSTALL_REFUSED=(' + b'|'.join(v.encode() for v in _INSTALLER_REFUSALS) + rb')(?![A-Za-z0-9_-])'), 3),
            ('acl', re.compile(rb'(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_ACL_DIAGNOSTIC=role=(' + b'|'.join(v.encode() for v in _INSTALLER_ACL_ROLES) + rb');phase=(' + b'|'.join(v.encode() for v in _INSTALLER_ACL_PHASES) + rb');result=(-?[0-9]{1,10});call=(-?[0-9]{1,10});errno=(-?[0-9]{1,10});freeCall=(-?[0-9]{1,10});freeErrno=(-?[0-9]{1,10})(?=\r?\n$)'), 2),
            ('parent', re.compile(rb'(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_COMPLETED_REFUSED=reasonSha256=([0-9a-f]{64});exit=(1|20);originals=([01]);native=([01]);timely=([01]);unknown=([01])(?=\r?\n$)'), 2),
        )
        for body in (stdout, stderr):
            for line in body.splitlines(keepends=True):
                if len(line) > 16384:
                    value['omitted'] = True
                    continue
                for key, pattern, cap in patterns:
                    for match in pattern.finditer(line):
                        parts = match.groups()
                        if key == 'acl':
                            row = dict(zip(('role', 'phase', 'result', 'call', 'errno', 'freeCall', 'freeErrno'),
                                [parts[0].decode('ascii'), parts[1].decode('ascii'), *[int(p) for p in parts[2:]]]))
                        elif key == 'parent':
                            row = dict(zip(('exit', 'originals', 'native', 'timely', 'unknown'),
                                [int(parts[1]), *[p == b'1' for p in parts[2:]]]))
                            # Preserve the original native Parent's static-reason token,
                            # not exception text. Unknown categories must remain diagnosable
                            # against that exact producer source without exposing raw logs.
                            row['reasonSha256'] = parts[0].decode('ascii')
                            row['category'] = next((category for reason, category in _INSTALLER_PARENT_REASONS.items()
                                if digest(reason.encode('ascii')).encode('ascii') == parts[0]), 'unclassified')
                        else:
                            row = parts[0].decode('ascii')
                        if len(value[key]) == cap or row in value[key]:
                            value['omitted'] = True
                        else:
                            value[key].append(row)
        for key, choices in (('phases', _INSTALLER_PHASES), ('refusals', _INSTALLER_REFUSALS)):
            value[key] = [v for v in choices if v in value[key]]
        return installer_markers_data(value)
    except BaseException:
        return None


_INSTALLER_ERROR_DOMAINS = ("PKInstallErrorDomain", "NSCocoaErrorDomain", "NSPOSIXErrorDomain", "NSOSStatusErrorDomain")


def installer_errors_data(value):
    if (type(value) is not dict or set(value) != {"rows", "omitted"} or type(value["omitted"]) is not bool
            or type(value["rows"]) is not list or len(value["rows"]) > 4):
        return None
    rows = []
    for row in value["rows"]:
        if (type(row) is not dict or set(row) != {"domain", "code"}
                or type(row["domain"]) is not str or row["domain"] not in _INSTALLER_ERROR_DOMAINS
                or type(row["code"]) is not int or not -(1 << 31) <= row["code"] < 1 << 31 or row in rows):
            return None
        rows.append(dict(row))
    return {"rows": rows, "omitted": value["omitted"]}


def installer_errors(stdout, stderr):
    """Finite Apple error facts only; never descriptions, paths or attribution."""
    if type(stdout) is not bytes or type(stderr) is not bytes or len(stdout) + len(stderr) > 256 * 1024:
        return None
    pattern = re.compile(rb"(?<![A-Za-z0-9_])Error[ \t]+Domain=(" +
        b"|".join(v.encode("ascii") for v in _INSTALLER_ERROR_DOMAINS) +
        rb")[ \t]+Code=(-?[0-9]{1,10})(?![A-Za-z0-9_+.-])")
    value = {"rows": [], "omitted": False}
    for body in (stdout, stderr):
        for line in body.splitlines(keepends=True):
            if len(line) > 16384:
                value["omitted"] = True
                continue
            for match in pattern.finditer(line):
                code = int(match[2])
                if not -(1 << 31) <= code < 1 << 31:
                    continue
                row = {"domain": match[1].decode("ascii"), "code": code}
                if row not in value["rows"]:
                    if len(value["rows"]) == 4:
                        value["omitted"] = True
                    else:
                        value["rows"].append(row)
    return installer_errors_data(value)


def installer_log_diagnostic_data(value):
    if type(value) is not dict or set(value) != {'state', 'reason', 'selection'}:
        return None
    if (type(value['state']) is not str or value['state'] not in ('observed', 'observed-project-correlated', 'unknown')
            or value['reason'] is not None and (type(value['reason']) is not str or value['reason'] not in _INSTALLER_LOG_REASONS)
            or value['selection'] is not None and (type(value['selection']) is not str or value['selection'] not in
                ('not-created', 'write-or-close-unknown-preserve-original'))):
        return None
    return dict(value)


# Static SOURCE literals only: no prefix rule or private exception rendering.
_FAILURE_SETUP_REASONS = (
    'setup-verification-audit-bytes',
    'setup-verification-cargo',
    'setup-verification-carrier-content',
    'setup-verification-carrier-roster',
    'setup-verification-cleanup',
    'setup-verification-cleanup-deadline',
    'setup-verification-current-file',
    'setup-verification-current-read',
    'setup-verification-current-roster',
    'setup-verification-diagnostic-bound',
    'setup-verification-final-mode',
    'setup-verification-helper-anchor',
    'setup-verification-input',
    'setup-verification-input-changed',
    'setup-verification-native-nonzero',
    'setup-verification-original-quote',
    'setup-verification-original-status',
    'setup-verification-purpose',
    'setup-verification-receipt-bom',
    'setup-verification-returned-changed',
    'setup-verification-returned-close',
    'setup-verification-returned-cut',
    'setup-verification-role-order',
    'setup-verification-source',
    'setup-verification-source-version',
    'setup-verification-system-parent',
    'xcode-setup-receipt-bound',
    'xcode-setup-receipt-decode',
    'xcode-setup-receipt-identity',
    'xcode-setup-receipt-object',
    'xcode-setup-receipt-offset',
    'xcode-setup-receipt-root',
    'xcode-setup-receipt-table',

    'fixed-product-purpose',
    'fixed-setup-target',
    'fixed-xar-package-purpose',
    'setup-bom-stderr',
    'setup-component-originals-required',
    'setup-component-purpose',
    'setup-component-required',
    'setup-final-originals-required',
    'setup-fixed-tree',
    'setup-held-release-selection',
    'setup-held-source-correspondence',
    'setup-source-purpose',
    'setup-original-ledger-bound',
    'setup-package-fixed-purpose',
    'setup-package-no-store-runtime',
    'setup-package-prequote',
    'setup-pkgbuild-output-roster',
    'setup-prefix-mutation-role',
    'setup-prefix-original-adoption',
    'setup-prefix-purpose',
    'setup-receipt-originals',
    'setup-signed-helper-anchor',
    'setup-signed-mode-original',
    'setup-signed-mode-post',
    'setup-snapshot-fixed-root',
    'setup-tar-output-roster',
    'setup-tool-close-unknown',
    'setup-xar-output-roster',
    'xcode-setup-bom-bound',
    'xcode-setup-bom-list-bound',
    'xcode-setup-bom-payload-roster',
    'xcode-setup-bundle',
    'xcode-setup-bundle-policy',
    'xcode-setup-cargo-version',
    'xcode-setup-carrier-source',
    'xcode-setup-component-source',
    'xcode-setup-component-timeout',
    'xcode-setup-control-bound',
    'xcode-setup-exact-source-scripts',
    'xcode-setup-final-root-scripts',
    'xcode-setup-fixed-source-version',
    'xcode-setup-generator-annotation',
    'xcode-setup-hooks',
    'xcode-setup-member-bound',
    'xcode-setup-original-component-bytes',
    'xcode-setup-original-owner',
    'xcode-setup-original-scripts',
    'xcode-setup-package-bound',
    'xcode-setup-package-identity',
    'xcode-setup-package-roster',
    'xcode-setup-package-text',
    'xcode-setup-payload-bound',
    'xcode-setup-payload-count',
    'xcode-setup-payload-source',
    'xcode-setup-preinstall',
    'xcode-setup-program-anchor',
    'xcode-setup-program-mode',
    'xcode-setup-program-required',
    'xcode-setup-readme',
    'xcode-setup-scripts-shape',
    'xcode-setup-source-binding',
    'xcode-setup-source-version',
)
_FAILURE_SETUP_ROLES = XCODE_SETUP_VERIFY_ROLES + (XCODE_SETUP_LOG_CAPTURE,) + XCODE_SETUP_COMPONENT_ROLES + ("final-package-productbuild",) + FINAL_PACKAGE_ROLES

_FIXTURE_COMPILER_ROLES = ("app-absence-build", "app-absence-cut-app-write-build",
                         "app-absence-cut-own-attempt-build", "app-absence-cut-stage-move-build")

# Closed existing fixture commands, not arbitrary role/prefix passthrough.
_FAILURE_FIXTURE_ROLES = (
    "app-absence-build", "app-absence-data-tests", "app-absence-adhoc", "app-absence-verify-code",
    "app-absence-pkgbuild", "app-absence-tar", "app-absence-xar",
    "app-absence-image-create", "app-absence-image-verify", "app-absence-baseline-attach",
    "app-absence-baseline", "app-absence-baseline-detach", "app-absence-restore-attach",
    "app-absence-log-cursor", "app-absence-log-capture",
    "app-absence-withdraw", "app-absence-install", "app-absence-verify", "app-absence-restore-detach",
    "app-absence-recovery-cut-1", "app-absence-recovery-cut-2", "app-absence-recovery-cut-3", "app-absence-recovered",
) + tuple("app-absence-cut-" + cut + suffix
          for cut in ("app-write", "own-attempt", "stage-move")
          for suffix in ("", "-build", "-adhoc", "-verify-code", "-pkgbuild", "-tar", "-xar"))
# Only these existing roles invoke Installer; build/mount/sign roles do not.
_FIXTURE_INSTALLER_ROLES = {
    "candidate-baseline": ("app-absence-baseline",),
    "package-install": ("app-absence-baseline",),
    "app-absence-restore": (
        "app-absence-withdraw", "app-absence-install", "app-absence-verify",
        "app-absence-cut-app-write", "app-absence-cut-own-attempt", "app-absence-cut-stage-move",
        "app-absence-recovery-cut-1", "app-absence-recovery-cut-2", "app-absence-recovery-cut-3",
        "app-absence-recovered",
    ),
}


def fixture_log_projection_data(value):
    if (type(value) is not dict or set(value) not in ({"state", "reason", "markers", "errors", "omitted"},
            {"state", "reason", "markers", "errors", "omitted", "phaseMarkerCount"})
            or type(value["omitted"]) is not bool
            or "phaseMarkerCount" in value and (type(value["phaseMarkerCount"]) is not int
                or not 0 <= value["phaseMarkerCount"] <= 5)):
        return None
    if value["state"] == "unknown" and type(value["reason"]) is str and value["reason"] in _INSTALLER_LOG_REASONS:
        return dict(value) if value["markers"] is value["errors"] is None and "phaseMarkerCount" not in value else None
    if value["state"] != "observed-project-correlated" or value["reason"] is not None:
        return None
    markers, errors = installer_markers_data(value["markers"]), installer_errors_data(value["errors"])
    if markers is None or errors is None:
        return None
    return {**value, "markers": markers, "errors": errors}


def fixture_log_document(document, status):
    if type(document) is not dict or type(status) is not int or status not in (0, 1):
        return None
    if document.get("state") == "unknown" and status == 1:
        return fixture_log_projection_data(dict(state="unknown", reason=document.get("reason"),
            markers=None, errors=None, omitted=False))
    if (status != 0 or set(document) != {"schemaVersion", "kind", "state", "authority",
            "scriptOutputFinality", "intervalScope", "projection"}
            or type(document["schemaVersion"]) is not int or document["schemaVersion"] != 1
            or document["kind"] != "installer-log-capture" or document["state"] != "observed-project-correlated"
            or document["scriptOutputFinality"] != "unestablished"
            or document["intervalScope"] not in ("before-baseline-through-failed-installer",
                "before-baseline-through-observation-refusal")):
        return None
    value = document["projection"]
    fields = {"markerTokens", "errorTokens", "omitted"}
    if document["intervalScope"] == "before-baseline-through-observation-refusal":
        fields.add("phaseMarkerCount")
    if (type(value) is not dict or set(value) != fields or type(value["omitted"]) is not bool
            or "phaseMarkerCount" in fields and (type(value["phaseMarkerCount"]) is not int
                or not 0 <= value["phaseMarkerCount"] <= 5)):
        return None
    bodies = []
    for key in ("markerTokens", "errorTokens"):
        rows = value[key]
        if (type(rows) is not list or len(rows) > 4 or any(type(row) is not str or not row.isascii()
                or not 0 < len(row) <= 1024 or "\n" in row or "\r" in row for row in rows)):
            return None
        for row in rows:
            body = (row + "\n").encode("ascii")
            if key == "markerTokens":
                parsed = installer_markers(body, b"")
                if (parsed is None or not row.startswith(("MRK_MACOS_INSTALL_ACL_DIAGNOSTIC=", "MRK_MACOS_INSTALL_COMPLETED_REFUSED="))
                        or len(parsed["acl"]) + len(parsed["parent"]) != 1
                        or parsed["phases"] or parsed["refusals"] or parsed["omitted"]):
                    return None
            else:
                parsed = installer_errors(body, b"")
                if parsed is None or len(parsed["rows"]) != 1 or parsed["omitted"]:
                    return None
                error = parsed["rows"][0]
                if row != "Error Domain=" + error["domain"] + " Code=" + str(error["code"]):
                    return None
        bodies.append(("\n".join(rows) + "\n").encode("ascii"))
    markers, errors = installer_markers(bodies[0], b""), installer_errors(bodies[1], b"")
    if markers is None or errors is None:
        return None
    markers["omitted"] |= value["omitted"]
    errors["omitted"] |= value["omitted"]
    return fixture_log_projection_data(dict(state=document["state"], reason=None,
        markers=markers, errors=errors, omitted=value["omitted"],
        **({"phaseMarkerCount": value["phaseMarkerCount"]} if "phaseMarkerCount" in value else {})))


def fixture_installer_diagnostic(phase, calls):
    """Last fixture Installer observation, not a terminal-cause/finality claim.

    An injected interruption can intentionally return nonzero. Never resurrect
    that earlier row after a later successful or unsettled Installer call.
    """
    roles = _FIXTURE_INSTALLER_ROLES.get(phase, ()) if type(phase) is str else ()
    if not roles or type(calls) is not list or len(calls) > 4096:
        return None
    selected = next(((i, row) for i, row in reversed(list(enumerate(calls)))
                     if type(row) is dict and row.get("role") in roles), None)
    if selected is None:
        return None
    index, row = selected
    marker_refusal = row.get("phaseMarkerRefusal")
    zero_refusal = (phase == "candidate-baseline" and index == 4
        and tuple(item.get("role") for item in calls[:4] if type(item) is dict) == (
            "app-absence-image-create", "app-absence-image-verify", "app-absence-baseline-attach", "app-absence-log-cursor")
        and all(item.get("entered") is True and item.get("returned") is True
            and item.get("capturesSettled") is True and type(item.get("returncode")) is int
            and item["returncode"] == 0 for item in calls[:4])
        and type(marker_refusal) is str and marker_refusal in
            ("app-absence-phase-marker-missing", "app-absence-phase-marker-duplicate"))
    if (any(row.get(key) is not True for key in ("entered", "returned", "capturesSettled"))
            or type(row.get("returncode")) is not int or not -65536 <= row["returncode"] <= 65535
            or row["returncode"] == 0 and not zero_refusal):
        return None
    log = None
    if (phase == "candidate-baseline" and index == 4 and len(calls) == 6
            and tuple(item.get("role") for item in calls if type(item) is dict) == (
                "app-absence-image-create", "app-absence-image-verify", "app-absence-baseline-attach",
                "app-absence-log-cursor", "app-absence-baseline", "app-absence-log-capture")
            and all(item.get("entered") is True and item.get("returned") is True
                and item.get("capturesSettled") is True and type(item.get("returncode")) is int
                and item["returncode"] == 0 for item in calls[:4])
            and all(calls[-1].get(key) is True for key in ("entered", "returned", "capturesSettled"))
            and type(calls[-1].get("returncode")) is int and calls[-1]["returncode"] in (0, 1)):
        log = fixture_log_projection_data(calls[-1].get("fixtureLog"))
    return {"role": row["role"], "index": index + 1, "returncode": row["returncode"], "log": log,
            **({"phaseMarkerRefusal": marker_refusal} if zero_refusal and row["returncode"] == 0 else {}),
            "markers": installer_markers_data(row.get("installerMarkers")),
            "errors": installer_errors_data(row.get("installerErrors")),
            "systemServiceExitClaimed": False}


_FAILURE_SETUP_STAGES = ("setup-verification-input", "setup-verification-cleanup") + _FAILURE_SETUP_ROLES + tuple(role + "-adoption" for role in XCODE_SETUP_MUTATION_ROLES) + (
    "sign-xcode-setup", "sign-xcode-setup-verify", "setup-carrier", "setup-scripts-original", "setup-scripts-final",
    "setup-input-root", "setup-presentation", "setup-packager-directory", "setup-original-component-audit",
    "setup-original-parts", "setup-component-directory",
    "setup-tool-pkgbuild", "setup-tool-lsbom", "setup-tool-tar", "setup-tool-xar",
    "install-product-original-adoption", "final-package-original-audit",
)

# Existing product parser/adoption failures only; never arbitrary error text.
_FAILURE_PRODUCT_REASONS = (
    'complete-root-owned-scripts-correspondence',
    'fixed-install-product-purpose',
    'install-product-component',
    'install-product-distribution',
    'install-product-readme',
    'install-product-source-bound',
    'install-product-source-version',
    'install-product-xar-bound',
    'install-product-xar-checksum',
    'install-product-xar-count',
    'install-product-xar-data',
    'install-product-xar-directory',
    'install-product-xar-duplicate',
    'install-product-xar-encoding',
    'install-product-xar-file',
    'install-product-xar-header',
    'install-product-xar-id',
    'install-product-xar-member-checksum',
    'install-product-xar-metadata',
    'install-product-xar-metadata-tags',
    'install-product-xar-finder-shape',
    'install-product-xar-finder-time',
    'install-product-xar-finder-nanoseconds',
    'install-product-xar-scalar-shape',
    'install-product-xar-inode-value',
    'install-product-xar-deviceno-value',
    'install-product-xar-name',
    'install-product-xar-range',
    'install-product-xar-roster',
    'install-product-xar-size',
    'install-product-xar-toc',
    'install-product-xml',
    'install-product-adoption-order',
    'install-product-output-roster',
)

# Fixed fixture guard names only, never arbitrary ValueError text. These remain
# diagnostic observations and cannot qualify the original Installer/readback.
_APP_ABSENCE_BASELINE_REASONS = frozenset((
    "app-absence-phase-output-bound", "app-absence-phase-marker-count",
    "app-absence-phase-marker-missing", "app-absence-phase-marker-duplicate",
    "app-absence-phase-marker-shape", "app-absence-phase-canonical-json",
    "app-absence-phase-observation", "app-absence-phase-proof",
    "app-absence-baseline-original", "app-absence-baseline-original-post",
    "app-absence-baseline-binding", "app-absence-baseline-identity",
    "app-absence-baseline-parent-original", "app-absence-baseline-volume",
))

_FAILURE_REASONS = frozenset((*_APP_ABSENCE_BASELINE_REASONS, *_FAILURE_SETUP_REASONS, *_FAILURE_PRODUCT_REASONS, *("original-nonzero-" + role for role in _FAILURE_SETUP_ROLES + _FAILURE_FIXTURE_ROLES),
    "candidate-fixture-terminal", "candidate-fixture-helper-source", "candidate-fixture-build-selection", "candidate-fixture-source-finality",
    *_FAILURE_NOTARY_REASONS, *FINAL_IMAGE_STAPLE_REASONS, *DISTRIBUTION_STAGER_REASONS, *FINAL_IMAGE_INPUT_STAGER_REASONS,
    *( 'original-nonzero-' + role for role in _PACKAGE_DIAGNOSTIC_ROLES),
    'package-group-clock', 'package-io-finality-unknown', 'package-compiled-bindings',
    'package-source-signing-selection', 'package-final-audit-original', 'package-output-readback',
    'installer-original-clock-reserve', 'installer-diagnostic-original-status', 'installer-diagnostic-original-output',
    'installer-diagnostic-source-purpose', 'installer-diagnostic-source-head',
    'prepared-readback-purpose', 'prepared-readback-built-selection', 'prepared-readback-installer-not-zero',
    'prepared-readback-original-bindings', 'prepared-readback-current-selection',
    'installer-diagnostic-selected', 'installer-diagnostic-selected-close',
    'producer-original-clock-reserve', 'producer-exact-descriptor-emission',
    'producer-tests-bound', 'producer-tests-framing', 'producer-tests-roster', 'producer-tests-result',
    'original-nonzero-producer-tests',
    'same-package-baseline-export', 'same-package-case', 'same-package-census', 'same-package-final-carrier', 'same-package-final-carrier-bytes', 'same-package-final-carrier-root', 'same-package-final-carrier-roster', 'same-package-finalizer-original', 'same-package-fixed-purpose', 'same-package-fresh-baseline', 'same-package-immediate-predecessor', 'same-package-input-', 'same-package-inventory', 'same-package-inventory-binding', 'same-package-inventory-input', 'same-package-live-readback', 'same-package-noop', 'same-package-notary-source', 'same-package-original-boundary', 'same-package-original-input', 'same-package-originals-unknown', 'same-package-parent-entry-bound', 'same-package-previous-shape', 'same-package-readback', 'same-package-readonly-mount', 'same-package-result-delta', 'same-package-result-namespace', 'same-package-result-post', 'same-package-source-scope', 'same-package-status-absence', 'same-package-status-post', 'same-package-status-purpose',
    'app-signature-fixed-native-phase', 'app-signature-summary-ref', 'application-no-installer-secret',
    'build-release-identity', 'build-release-shape', 'build-release-size',
    'build-release-version', 'build-target', 'closed-build-target',
    'closed-entrypoint', 'closed-workflow-route', 'compiler-alias-directory-bound',
    'compiler-alias-original', 'compiler-artifact-close-unknown', 'compiler-artifact-shape',
    'compiler-bound', 'compiler-duplicate-key', 'compiler-finish',
    'compiler-json', 'compiler-original-copy-changed', 'compiler-rows',
    'compiler-terminal-order', 'credential-ancestor-mode', 'credential-base64',
    'credential-callback-deadline', 'credential-callback-purpose', 'credential-callback-reserve',
    'credential-callback-roster', 'credential-census-close-unknown', 'credential-certificate-format',
    'credential-child-environment', 'credential-close-unknown', 'credential-code-purpose',
    'credential-created-searchlist', 'credential-directory-original', 'credential-dispatch-reserve',
    'credential-dispatch-unknown', 'credential-finality-incomplete', 'credential-fixed-original',
    'credential-fixed-purpose', 'credential-identity-bound', 'credential-identity-format',
    'credential-input-bound', 'credential-original-clock', 'credential-original-deadline',
    'credential-original-nonzero', 'credential-original-return', 'credential-original-unknown',
    'credential-p12-after-close', 'credential-p12-close-unknown', 'credential-p12-original',
    'credential-p12-readback', 'credential-private-census', 'credential-private-file',
    'credential-private-file-post', 'credential-private-parent', 'credential-private-query-stderr',
    'credential-private-root-not-empty', 'credential-private-root-remains', 'credential-private-storage-reserve',
    'credential-producer-admission', 'credential-producer-callback-post', 'credential-producer-import-post',
    'credential-producer-original', 'credential-profile-identity', 'credential-root-exclusive',
    'credential-root-mode', 'credential-search-format', 'credential-search-stderr',
    'credential-search-value-changed', 'credential-short-write', 'credential-source-certificate',
    'credential-source-certificates', 'credential-source-identity', 'credential-source-leaf',
    'credential-source-post', 'credential-unwind-original-unknown', 'credential-user-domain',
    'descriptor-relative-cleanup-required', 'direct-rust-source-route', 'directory-owner-mode',
    'entry-compiler-original-changed', 'entry-library-command', 'entry-library-offset',
    'entry-library-padding', 'entry-library-termination', 'entry-libsystem-only',
    'entry-loader-command', 'entry-main-command', 'entry-native-initializer',
    'entry-pie-no-executable-stack', 'entry-segment-command', 'entry-segment-sections',
    'entry-source-changed', 'exact-detached-checkout', 'exclusive-output-original',
    'facade-compiler-artifact-close-unknown', 'facade-compiler-original-changed', 'facade-source-changed',
    'file-original-changed', 'file-original-read-changed', 'file-original-shape', 'final-image-configured-purpose',
    'fixed-facade-role', 'fixed-signing-requirement', 'fixed-source-driver',
    'full-package-scope-only', 'helper-absolute-apple-system-dependency', 'helper-dyld-command',
    'helper-dyld-offset', 'helper-dyld-terminated', 'helper-dylib-command',
    'helper-dylib-name-offset', 'helper-dylib-terminated', 'helper-loader-override-refused',
    'helper-one-library', 'helper-package-artifact', 'helper-package-incomplete',
    'helper-release-graph', 'helper-release-profile', 'helper-separate-library-features',
    'helper-system-dyld-only', 'hosted-native-platform', 'hosted-source-bindings',
    'candidate-companion-event-scope',
    'image-absolute-apple-system-dependency', 'image-build-version', 'image-command',
    'image-dylib-target', 'image-fixed-install-name-and-system-closure', 'image-library-command',
    'image-library-offset', 'image-library-padding', 'image-library-termination',
    'image-loader-command', 'image-role-header', 'image-segment-command',
    'image-segment-sections', 'image-source-release', 'macho-build-version',
    'macho-command', 'macho-command-bound', 'macho-header',
    'macho-minimum-macos26', 'macho-target', 'one-compiler-alias',
    'one-resident-image', 'original-nonzero-resident-fetch', 'original-nonzero-build', 'original-nonzero-desktop-facade-build',
    'original-nonzero-entry-build', 'original-nonzero-resident-facade-build', 'original-nonzero-resident-image-sign',
    'original-nonzero-resident-image-verify-signed', 'original-nonzero-sign', 'original-nonzero-verify-signed',
    'original-operation-refused', 'original-return-contract', 'output-close-unknown',
    'output-readback', 'output-short-write', 'owned-work-route',
    'receipt-bound', 'receipt-readback', 'receipt-short-write',
    'receipt-work-changed', 'receipt-work-unavailable', 'resident-image-only-graph',
    'run-identity', 'source-image-binding', 'source-image-release-changed',
    'source-original-changed', 'source-producer-correspondence', 'source-producer-profile',
    'source-producer-unconfigured', 'source-service-profile', 'source-signing-profile-changed',
    'strict-original-verification', 'work-original',
))
_FAILURE_STAGES = (
    *_FAILURE_SETUP_STAGES,
    *FINAL_IMAGE_STAPLE_STAGES, *FINAL_IMAGE_INPUT_STAGES,
    *notary_roles(True), 'notary-preflight-input', 'notary-final-input', 'notary-known-private-retirement',
    "package-producer-tests", "package-final-audit", "package-explicit-producer-compiler",
    "package-producer-emission", "package-readonly-attach", "standard-original-installer",
    "package-nonroot-v2-readback",
    "same-package-noop",
    "owned-directory-admission", "source-image-binding", "resident-dependency-fetch", "separate-resident-image-compiler",
    "compiler-original-copy", "resident-image-source-selected-signing", "resident-image-verify-signed",
    "fixed-installed-entry-compiler", "desktop-facade-compiler", "resident-facade-compiler",
    "helper-source-selected-signing", "verify-signed",
)
_FAILURE_MAIN_STAGES = (
    "entrypoint", "data-phase", "admission", "stager-load", "source-check", "profile-check",
    "owner-load", "operation-create", "operation-execute", "success-output",
)
_FAILURE_TYPES = (
    "helper-refused", "stager-refused", "os-error", "value-error", "type-error", "runtime-error",
    "assertion-error", "memory-error", "recursion-error", "unicode-error", "json-error",
    "keyboard-interrupt", "system-exit", "other",
)
_FAILURE_OWNER_CLASSES = ("ProcessError", "ProcessCleanupError", "ProcessOutcomeUnknown", "other")
_FAILURE_OWNER_REASONS = (
    "output-bound", "deadline", "protocol-or-original-ownership", "original-parent-ended",
    "cleanup-unconfirmed", "failed-timeout-or-incomplete-output", "exec-rejected",
    "stopped-before-execution", "incomplete-output", "unclassified",
)


# Only these SOURCE crate identities can disambiguate relative compiler spans.
_COMPILER_PACKAGES = {
    "mrk-android-register": ("desktop/helpers/macos-android-register", "0.1.0"),
    "mobile-release-kit-desktop": ("desktop/src-tauri", None),
    "mrk-macos-installed-native": ("desktop/native/macos-installed-native", "0.1.0"),
}
_COMPILER_ROOTS = tuple(value[0] for value in _COMPILER_PACKAGES.values()) + ("desktop/native/macos-installed-entry",)
_COMPILER_NATIVE_FILES = (
    "src/native.m", "src/android_registration.m", "src/android_service_management.m",
    "src/wrapping_keychain.m", "src/vault_filesystem.m", "src/vault_helper_control.m",
    "src/wrapping_interaction_policy.h", "src/vault_helper_control.h", "src/vault_helper_auth.m",
)
_COMPILER_CLASSES = (
    "locked-update", "missing-package", "offline", "download-failed", "network-failed",
    "unsupported-rustc", "no-space", "build-script-failed", "linker-failed", "unclassified",
)


def compiler_source(path, checkout, package=None):
    """Lexical SOURCE location only. Never resolve/stat/read a diagnostic path."""
    if type(path) is not str or not 0 < len(path) <= 4096 or re.fullmatch(r"[A-Za-z0-9_./+-]+", path) is None:
        return None
    if path.startswith(checkout + "/"):
        parts = path[len(checkout) + 1:].split("/")
    elif path.startswith("/"):
        return None
    elif path.startswith("desktop/"):
        parts = path.split("/")
    elif package is not None:
        if type(package) is not str or package not in _COMPILER_ROOTS:
            return None
        parts = package.split("/") + path.split("/")
    elif path in _COMPILER_NATIVE_FILES:
        parts = ["desktop", "native", "macos-installed-native"] + path.split("/")
    elif path.startswith(("../../src-tauri/", "../../native/macos-installed-native/")):
        # Explicit helper Cargo cwd, not a guessed base for src/lib.rs/build.rs.
        parts = ["desktop", "helpers", "macos-android-register"] + path.split("/")
    else:
        return None
    normalized = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not normalized:
                return None
            normalized.pop()
        else:
            normalized.append(part)
    result = "/".join(normalized)
    return result if (len(result) <= 160 and result.endswith((".rs", ".m", ".c", ".h"))
                      and any(result.startswith(root + "/") for root in _COMPILER_ROOTS)) else None


def compiler_diagnostic(stdout, stderr, checkout, *, package_version=None):
    """Sanitize SAME failed Cargo captures. Never export messages or commands."""
    packages = {name: pair for name, pair in _COMPILER_PACKAGES.items() if pair[1] is not None}
    if (type(package_version) is str and len(package_version) <= 32
            and re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", package_version) is not None):
        packages["mobile-release-kit-desktop"] = ("desktop/src-tauri", package_version)
    result = {"rows": [], "rowsOmitted": False, "scanComplete": True,
              "rustMessages": 0, "clangErrors": 0, "buildScriptPanics": 0, "classifications": []}
    if (type(stdout) is not bytes or type(stderr) is not bytes or len(stdout) + len(stderr) > 4 * 1024 * 1024
            or type(checkout) is not str or not checkout.startswith("/") or len(checkout) > 4096):
        result.update(scanComplete=False, classifications=["unclassified"])
        return result
    def position(value, maximum):
        return value if type(value) is int and 0 < value <= maximum else None
    def add(kind, code, path, line, column, package):
        row = {"kind": kind, "code": code if type(code) is str and re.fullmatch(r"E[0-9]{4}", code) else None,
               "source": compiler_source(path, checkout, package),
               "line": position(line, 1000000), "column": position(column, 65535)}
        if row not in result["rows"]:
            if len(result["rows"]) < 8:
                result["rows"].append(row)
            else:
                result["rowsOmitted"] = True
    classes, lines_seen = set(), 0
    for body in (stdout, stderr):
        offset, package = 0, None
        while offset < len(body):
            if lines_seen == 65536:
                result["scanComplete"] = False
                break
            lines_seen += 1
            end = body.find(b"\n", offset)
            end = len(body) if end < 0 else end
            start, offset = offset, end + 1
            if end - start > 256 * 1024:
                result["scanComplete"] = False
                continue
            raw = body[start:end]
            # Text searches have a smaller bound than Cargo JSON. The left
            # path boundary below also prevents retries at each path character.
            if not raw.startswith(b"{") and len(raw) > 8192:
                result["scanComplete"] = False
                continue
            try:
                text = raw.decode("utf-8", "strict").rstrip("\r")
            except UnicodeError:
                result["scanComplete"] = False
                continue
            if text.startswith("{"):
                if '"compiler-message"' not in text:
                    continue
                try:
                    message = json.loads(text)
                except (ValueError, RecursionError):
                    result["scanComplete"] = False
                    continue
                if type(message) is not dict or message.get("reason") != "compiler-message":
                    continue
                detail = message.get("message")
                if type(detail) is not dict or detail.get("level") != "error":
                    continue
                result["rustMessages"] += 1
                context = ""  # Unknown/contradictory package is not the helper cwd.
                for name, (root, version) in packages.items():
                    manifest = checkout + "/" + root + "/Cargo.toml"
                    prefix = "path+file://" + checkout + "/" + root + "#"
                    identities = (prefix + name + "@" + version, prefix + version)
                    supplied_manifest, supplied_id = message.get("manifest_path"), message.get("package_id")
                    if ((supplied_manifest == manifest and (supplied_id is None or supplied_id in identities))
                            or supplied_manifest is None and supplied_id in identities):
                        context = root
                        break
                code = detail.get("code")
                code = code.get("code") if type(code) is dict else None
                spans = detail.get("spans")
                primary = False
                if type(spans) is list:
                    if len(spans) > 64:
                        result["scanComplete"] = False
                    for span in spans[:64]:
                        if type(span) is dict and span.get("is_primary") is True:
                            primary = True
                            add("rust", code, span.get("file_name"), span.get("line_start"), span.get("column_start"), context)
                if not primary:
                    add("rust", code, None, None, None, context)
                continue  # Never mine rendered/message JSON text as stderr.
            lower = text.lower()
            if "lock file" in lower and "--locked" in lower and ("update" in lower or "updated" in lower): classes.add("locked-update")
            if "no matching package named" in lower or "no matching version" in lower: classes.add("missing-package")
            if "offline mode" in lower or "--offline" in lower: classes.add("offline")
            if "failed to download" in lower or ("failed to get" in lower and "as a dependency" in lower): classes.add("download-failed")
            if any(token in lower for token in ("could not resolve host", "failed to connect", "network failure", "timed out", "ssl connect error")): classes.add("network-failed")
            if "requires rustc" in lower or "rustc is not supported" in lower or "requires rust version" in lower: classes.add("unsupported-rustc")
            if "no space left on device" in lower: classes.add("no-space")
            if "failed to run custom build command" in lower:
                classes.add("build-script-failed")
                package = ""
                heading = re.match(r"error: failed to run custom build command for `([A-Za-z0-9_-]+) v([0-9.]+)(?: |`)", text)
                if heading:
                    pair = packages.get(heading[1])
                    if pair is not None and heading[2] == pair[1]:
                        package = pair[0]
            if ("linking with" in lower and "failed" in lower) or "linker command failed" in lower: classes.add("linker-failed")
            line_package = package
            warning = re.match(r"warning: ([A-Za-z0-9_-]+)@([0-9.]+):", text)
            if warning:
                pair = packages.get(warning[1])
                line_package = pair[0] if pair is not None and warning[2] == pair[1] else ""
            clang = re.search(r"(?<![A-Za-z0-9_./+:-])([A-Za-z0-9_./+-]{1,4096}):([1-9][0-9]{0,6})(?::([1-9][0-9]{0,4}))?: (?:fatal )?error:", text)
            if clang:
                result["clangErrors"] += 1
                add("clang", None, clang[1], int(clang[2]), int(clang[3]) if clang[3] else None, line_package)
            panic = re.search(r"panicked at ([A-Za-z0-9_./+-]{1,4096}):([1-9][0-9]{0,6}):([1-9][0-9]{0,4}):", text)
            if panic:
                result["buildScriptPanics"] += 1
                add("build-script-panic", None, panic[1], int(panic[2]), int(panic[3]), line_package)
    result["classifications"] = [value for value in _COMPILER_CLASSES if value in classes] or ["unclassified"]
    return result


def compiler_diagnostic_data(value):
    """Only the parser's closed passive fields can enter the public line."""
    if type(value) is not dict:
        return None
    rows, classes = value.get("rows"), value.get("classifications")
    if (type(rows) is not list or len(rows) > 8 or type(classes) is not list or len(classes) > len(_COMPILER_CLASSES)
            or any(type(item) is not str or item not in _COMPILER_CLASSES for item in classes)
            or any(type(value.get(key)) is not bool for key in ("rowsOmitted", "scanComplete"))
            or any(type(value.get(key)) is not int or not 0 <= value[key] <= 65536
                   for key in ("rustMessages", "clangErrors", "buildScriptPanics"))):
        return None
    output = []
    for row in rows:
        if type(row) is not dict or set(row) != {"kind", "code", "source", "line", "column"}:
            return None
        kind, code, source = row["kind"], row["code"], row["source"]
        if (type(kind) is not str or kind not in ("rust", "clang", "build-script-panic")
                or code is not None and (type(code) is not str or re.fullmatch(r"E[0-9]{4}", code) is None)
                or source is not None and (type(source) is not str or compiler_source(source, "/") != source)
                or any(row[key] is not None and (type(row[key]) is not int or not 0 < row[key] <= maximum)
                       for key, maximum in (("line", 1000000), ("column", 65535)))):
            return None
        output.append(dict(row))
    return {"rows": output, "classifications": list(classes),
            **{key: value[key] for key in ("rowsOmitted", "scanComplete", "rustMessages", "clangErrors", "buildScriptPanics")}}


def failure_stager_line(error, stager):
    """Original stager location only; never exception text, locals or paths."""
    if type(stager) is not type(sys) or type(error) is not stager.__dict__.get("Refused"):
        return None
    namespace = stager.__dict__
    filename = namespace.get("__file__")
    # These two generic guards share every caller's location; report the
    # actual schema/readback caller, without exposing exception text or locals.
    guard_codes = (namespace["need"].__code__, namespace["maintenance_map"].__code__)
    current, selected = BaseException.__traceback__.__get__(error), None
    for _ in range(32):
        if current is None:
            return selected
        frame = current.tb_frame
        if (frame.f_globals is namespace and frame.f_code.co_filename == filename
                and frame.f_code not in guard_codes and 0 < current.tb_lineno <= 100000):
            selected = current.tb_lineno
        current = current.tb_next
    return None  # Truncated trace is unavailable, not an invented location.


def failure_exception(error, stager=None):
    """Classify the original object without rendering it or trusting its name."""
    selected = type(error)
    stager_class = stager.__dict__.get("Refused") if type(stager) is type(sys) else None
    kind = ("helper-refused" if selected is Refused else
            "stager-refused" if selected is stager_class else "other")
    reason, number = "unclassified", None
    if kind in ("helper-refused", "stager-refused"):
        values = BaseException.args.__get__(error)
        if (type(values) is tuple and len(values) == 1 and type(values[0]) is str
                and len(values[0]) <= 96 and values[0] in _FAILURE_REASONS):
            reason = values[0]
    else:
        known = ((ValueError, "value-error"), (TypeError, "type-error"), (RuntimeError, "runtime-error"),
                 (AssertionError, "assertion-error"), (MemoryError, "memory-error"),
                 (RecursionError, "recursion-error"), (UnicodeDecodeError, "unicode-error"),
                 (UnicodeEncodeError, "unicode-error"), (json.JSONDecodeError, "json-error"),
                 (KeyboardInterrupt, "keyboard-interrupt"), (SystemExit, "system-exit"))
        kind = next((label for cls, label in known if selected is cls), "other")
        if selected is ValueError:
            values = BaseException.args.__get__(error)
            if (type(values) is tuple and len(values) == 1 and type(values[0]) is str
                    and len(values[0]) <= 96 and values[0] in _APP_ABSENCE_BASELINE_REASONS):
                reason = values[0]
        if any(selected is cls for cls in (OSError, PermissionError, FileNotFoundError, FileExistsError, IsADirectoryError,
                  NotADirectoryError, InterruptedError, BlockingIOError, TimeoutError,
                  ChildProcessError, BrokenPipeError, ConnectionError, ConnectionAbortedError,
                  ConnectionRefusedError, ConnectionResetError, ProcessLookupError)):
            kind = "os-error"
            value = OSError.errno.__get__(error)
            if type(value) is int and 0 < value < 65536:
                number = value
    return {"type": kind, "reason": reason, "errno": number}


# Static nonshipping emitter/common-Book reasons. Never accept an arbitrary
# native error line just because its characters happen to look like a token.
_REMOVE_PRODUCER_REASONS = (
    'arguments', 'clock', 'completed-package-magic', 'created-root-original', 'deadline', 'file-finality',
    'final-input-post', 'final-package-post', 'final-report-bound', 'final-report-deadline', 'final-report-flush',
    'final-report-write', 'fixed-remover-name', 'installed-current-source', 'installed-data',
    'installed-inventory', 'installed-inventory-index', 'installed-remover-binding', 'installed-remover-missing',
    'installed-signature-finality', 'installed-signature-verification', 'observer-input-roster', 'ordinary-user',
    'original-limit', 'original-name', 'original-no-handle', 'original-not-owned', 'original-open',
    'original-pending', 'original-post', 'original-slot', 'original-stat', 'original-type', 'original-unbound',
    'original-unknown', 'parent-protection', 'path-components', 'path-encoding', 'path-shape', 'platform',
    'private-acl', 'private-attributes', 'private-file', 'private-program', 'private-root', 'program-finality',
    'program-purpose', 'read-budget', 'read-extent', 'read-limit', 'read-original', 'read-short', 'read-size',
    'remove-data', 'remove-emission-binding', 'remove-native-allocation-bound', 'remove-signature-not-created',
    'remove-signature-verification', 'remove-signer-finality', 'remove-verification-finality', 'root-roster',
    'root-roster-bound', 'root-roster-close', 'root-roster-eof', 'root-roster-member', 'root-roster-name',
    'root-roster-record', 'roster-original', 'separate-private-roots', 'sidecar-created', 'sidecar-mode',
    'sidecar-persist', 'sidecar-readback', 'sidecar-root-persist', 'sidecar-sealed-original', 'sidecar-shape',
    'sidecar-write', 'sidecar-write-bound', 'sidecar-written-original', 'signed-input-post',
    'signed-package-post', 'source-current-unavailable', 'source-runtime-unavailable', 'source-signer-unavailable'
)


def remove_producer_refusal(stdout, stderr):
    if type(stdout) is not bytes or stdout != b"" or type(stderr) is not bytes or not 0 < len(stderr) <= 128:
        return None
    match = re.fullmatch(rb"MRK_MACOS_REMOVE_PRODUCER_REFUSED=([a-z][a-z-]{0,63})\n", stderr)
    if match is None:
        return None
    reason = match[1].decode("ascii")
    return reason if reason in _REMOVE_PRODUCER_REASONS else None


def remove_producer_refusal_data(phase, record):
    if (phase == "package-remove" and type(record) is dict and record.get("role") == "producer-emitter"
            and record.get("entered") is True and record.get("returned") is True
            and record.get("capturesSettled") is True and type(record.get("returncode")) is int
            and record["returncode"] == 78 and type(record.get("removeProducerReason")) is str
            and record["removeProducerReason"] in _REMOVE_PRODUCER_REASONS):
        return record["removeProducerReason"]
    return None


def failure_diagnostic(error, *, phase=None, target=None, main_stage=None, operation=None, stager=None):
    """Bounded passive DATA; no owner callbacks, file reads, or state changes."""
    def row(value):
        return value if type(value) is dict else {}
    def token(value, allowed):
        return value if type(value) is str and len(value) <= 96 and value in allowed else "unclassified"
    def flag(value):
        return value if type(value) is bool else None
    def integer(value, lower=0, upper=4096):
        return value if type(value) is int and lower <= value <= upper else None
    def count(value, maximum):
        return len(value) if type(value) is list and len(value) <= maximum else None
    def last(value, maximum):
        return row(value[-1]) if type(value) is list and 0 < len(value) <= maximum else {}

    state = object.__getattribute__(operation, "__dict__") if type(operation) is Operation else {}
    receipt = row(state.get("receipt"))
    original = row(receipt.get("failure"))
    captured = row(state.get("diagnostic_failure"))
    native = last(state.get("calls"), 4096)
    owned = row(native.get("originalFailure"))
    credential = last(state.get("credential_calls"), 64)
    context = last(state.get("credential_contexts"), 64)
    purposes = ("python", "resident-image", "helper", "producer", "installer", "observer-program",
                "distribution-image", "observation-image") + SIGNING_PHASES + TOOL_SIGNING_PHASES + STORE_SIGNING_PHASES
    phases = ((APP_SIGNATURE_SUMMARY,) + PHASES + SUPPORT_PHASES + STORE_SIGNING_PHASES + PYTHON_PHASES + SIGNING_PHASES + TOOL_SIGNING_PHASES
              + TOOL_SELECTION_PHASES + TOOL_PROJECT_PHASES + NOTARY_PHASES + FINAL_PACKAGE_PHASES
              + FINAL_IMAGE_PHASES + REMOVAL_OWNER_PHASES + ("candidate-baseline",))
    pending = receipt.get("directStagerIOPending")
    package = None
    if state.get("phase") == "package-install":
        calls = state.get("calls")
        slots = {}
        for role in _PACKAGE_DIAGNOSTIC_ROLES[12:15]:
            matches = ([i for i, r in enumerate(calls) if type(r) is dict and r.get("role") == role]
                       if type(calls) is list and len(calls) <= 4096 else [])
            index = _PACKAGE_DIAGNOSTIC_ROLES.index(role)
            original_row = calls[index] if matches == [index] else None
            slots[role] = None if original_row is None else {
                "index": index + 1,
                **{key: flag(original_row.get(key)) for key in ("entered", "returned", "capturesSettled")},
                "returncode": integer(original_row.get("returncode"), -65536, 65535),
            }
            if original_row is not None:
                if role == "installer":
                    known_failed = (original_row.get("entered") is True and original_row.get("returned") is True
                        and original_row.get("capturesSettled") is True
                        and type(original_row.get("returncode")) is int and original_row["returncode"] != 0)
                    slots[role]["markers"] = installer_markers_data(original_row.get("installerMarkers")) if known_failed else None
                    slots[role]["errors"] = installer_errors_data(original_row.get("installerErrors")) if known_failed else None
                else:
                    slots[role]["log"] = installer_log_diagnostic_data(original_row.get("installerLog")) if (
                        original_row.get("entered") is True and original_row.get("returned") is True
                        and original_row.get("capturesSettled") is True
                        and type(original_row.get("returncode")) is int and original_row["returncode"] in (0, 1)) else None
        capture = slots.get("installer-log-capture")
        installer = slots.get("installer")
        if capture is not None:
            capture["markers"] = (installer_markers_data(calls[14].get("installerLogMarkers"))
                if capture["returned"] is True and capture["capturesSettled"] is True and capture["returncode"] == 0
                and installer is not None and installer["returned"] is True and installer["capturesSettled"] is True
                and type(installer["returncode"]) is int and installer["returncode"] != 0 else None)
            capture["errors"] = (installer_errors_data(calls[14].get("installerLogErrors"))
                if capture["returned"] is True and capture["capturesSettled"] is True and capture["returncode"] == 0
                and installer is not None and installer["returned"] is True and installer["capturesSettled"] is True
                and type(installer["returncode"]) is int and installer["returncode"] != 0 else None)
        package = {"calls": slots,
            "installerEntered": flag(state.get("installer_entered")),
            "installerZeroLatched": flag(state.get("installer_zero")),
            "installationReadback": flag(state.get("installation_readback")),
            "systemServiceExitClaimed": False}
    setup = None
    calls = state.get("calls")
    failed = setup_failed_installer_index(calls) if state.get("phase") == XCODE_SETUP_VERIFY else None
    if failed is not None:
        current = calls[failed]
        log = None
        if len(calls) == failed + 2:
            capture = calls[-1]
            if (calls[1].get("returncode") == 0 and capture.get("entered") is True and capture.get("returned") is True
                    and capture.get("capturesSettled") is True and type(capture.get("returncode")) is int
                    and capture["returncode"] in (0, 1)):
                log = setup_log_projection_data(capture.get("setupLog"))
        setup = {"role": current["role"], "index": failed + 1, "returncode": current["returncode"],
            "hooks": setup_hook_diagnostics_data(current.get("setupHooks")),
            "native": setup_installer_diagnostics_data(current.get("setupDiagnostic")),
            "errors": installer_errors_data(current.get("installerErrors")), "log": log,
            "systemServiceExitClaimed": False}
    return {
        "schemaVersion": 1, "kind": "android-helper-failure", "outcome": "failure",
        "diagnosticOnly": True, "productReady": False,
        "phase": token(phase, phases), "target": token(target, (ARM_TARGET, INTEL_TARGET)),
        "mainStage": token(main_stage, _FAILURE_MAIN_STAGES), "terminal": failure_exception(error, stager),
        "packageInstall": package, "setupInstall": setup,
        "fixtureInstall": fixture_installer_diagnostic(state.get("phase"), state.get("calls")),
        "compiler": compiler_diagnostic_data(state.get("compiler_failure")),
        "notaryIssues": notary_failure_summary_data(state.get("notary_issue_diagnostic")),
        "originalFailure": {
            "recorded": type(receipt.get("failure")) is dict if state else None,
            "stagerLine": integer(state.get("stager_failure_line"), 1, 100000),
            "stage": token(original.get("stage"), _FAILURE_STAGES),
            "type": token(captured.get("type"), _FAILURE_TYPES),
            "reason": token(captured.get("reason", original.get("reason")), _FAILURE_REASONS),
            "errno": integer(captured.get("errno", original.get("errno")), 1, 65535),
        },
        "lastRecordedNative": {
            "removeProducerReason": remove_producer_refusal_data(state.get("phase"), native),
            "role": token(native.get("role"), ("resident-fetch",) + PREPARE_ROLES + notary_roles(True) + _PACKAGE_DIAGNOSTIC_ROLES + _FAILURE_SETUP_ROLES + _FAILURE_FIXTURE_ROLES),
            **{key: flag(native.get(key)) for key in ("entered", "returned", "capturesSettled", "dispatched", "contained", "cleanup_complete")},
            "returncode": integer(native.get("returncode"), -65536, 65535),
            "originalFailure": {"available": flag(owned.get("available")),
                "ownerErrorType": token(owned.get("ownerErrorType"), _FAILURE_OWNER_CLASSES),
                "classification": token(owned.get("classification"), _FAILURE_OWNER_REASONS)},
        },
        "lastRecordedCredential": {
            "role": token(credential.get("role"), CREDENTIAL_ROLES),
            **{key: flag(credential.get(key)) for key in ("entered", "returned", "settled")},
            "status": integer(credential.get("status"), -65536, 65535),
        },
        "lastRecordedContext": {"purpose": token(context.get("purpose"), purposes),
            **{key: flag(context.get(key)) for key in ("closed", "retired", "searchRestored", "defaultUnchanged")}},
        "counts": {"native": count(state.get("calls"), 4096), "credential": count(state.get("credential_calls"), 64),
                   "contexts": count(state.get("credential_contexts"), 64), "cleanupErrors": count(state.get("errors"), 4096)},
        "cleanup": {"targetRetired": flag(receipt.get("targetRetired")),
            "originalClosesKnown": flag(receipt.get("originalClosesKnown")),
            "credentialUnknown": flag(state.get("credential_unknown")),
            "directStagerIOPending": (False if pending is None else True if type(pending) is str else None)
                if "directStagerIOPending" in receipt else None},
    }


def emit_failure_diagnostic(error, **context):
    """Best effort only: diagnostic failure cannot replace the original exit1."""
    try:
        value = failure_diagnostic(error, **context)
        body = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        # Retain the existing primary diagnosis within its unchanged whole-line
        # bound. Only a fresh diagnostic row copy is trimmed, never owner state.
        while len(body) > 4096 and value["compiler"] is not None and value["compiler"]["rows"]:
            value["compiler"]["rows"].pop()
            value["compiler"]["rowsOmitted"] = True
            body = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        while len(body) > 4096 and value["notaryIssues"] is not None and value["notaryIssues"]["rows"]:
            value["notaryIssues"]["rows"].pop()
            value["notaryIssues"]["rowsOmitted"] = True
            body = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        package = value["packageInstall"]
        installer = package["calls"]["installer"] if package is not None else None
        capture = package["calls"]["installer-log-capture"] if package is not None else None
        fixture_log = value["fixtureInstall"].get("log") if value["fixtureInstall"] is not None else None
        for original in (installer, capture, value["fixtureInstall"], fixture_log):
            markers = original.get("markers") if original is not None else None
            if markers is not None:
                for key in ("acl", "parent", "phases", "refusals"):
                    while len(body) > 4096 and markers[key]:
                        markers[key].pop()
                        markers["omitted"] = True
                        body = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        for original in (installer, capture, value["fixtureInstall"], fixture_log):
            errors = original.get("errors") if original is not None else None
            if errors is not None:
                while len(body) > 4096 and errors["rows"]:
                    errors["rows"].pop()
                    errors["omitted"] = True
                    body = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        setup_log = value["setupInstall"].get("log") if value["setupInstall"] is not None else None
        if setup_log is not None:
            for name, key in (("hooks", "observations"), ("errors", "rows"), ("native", "observations")):
                row = setup_log[name]
                while len(body) > 4096 and row is not None and row[key]:
                    row[key].pop(0)
                    setup_log["omitted"] = True
                    if name != "errors": row["available"] = bool(row[key])
                    else: row["omitted"] = True
                    body = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        if body.isascii() and len(body) <= 4096:
            written = sys.stderr.write(body)
            if type(written) is int and written == len(body):
                sys.stderr.flush()
    except BaseException:
        pass


def package_timeout_data(now, endpoint, requested, *, phase=None, role=None):
    """Leave the existing owner's three-second settlement inside this group."""
    need((phase is None and role is None) or (type(phase) is str and type(role) is str),
         "package-group-clock")
    maximum = (3900 if phase == XCODE_SETUP_VERIFY and role == "setup-installer-first" else
               900 if phase == XCODE_SETUP_VERIFY and role == "setup-installer-repeat" else
               1440 if phase == "prepare-app-absence" and role in
               ("app-absence-build", "app-absence-data-tests", "app-absence-cut-app-write-build",
                "app-absence-cut-own-attempt-build", "app-absence-cut-stage-move-build") else 480)
    need(type(now) is int and type(endpoint) is int and 0 <= now < endpoint
         and type(requested) is int and 0 < requested <= maximum, "package-group-clock")
    remaining = (endpoint - now - 3_000_000_000) // 1_000_000_000
    need(remaining >= 1, "package-group-settlement-reserve")
    return min(requested, remaining)


def signing_requirement(identity, identifier):
    # Each Store image has the fixed namespace plus its admitted member-path
    # digest. This is an identifier grammar, not permission to sign other code;
    # the Store owner still checks the complete input roster before key use.
    store_identifier = (type(identifier) is str
        and re.fullmatch(r"dev\.mobile-release-kit\.desktop\.store\.[0-9a-f]{32}", identifier) is not None)
    need(type(identity) is tuple and len(identity) == 2
         and re.fullmatch(r"[A-Z0-9]{10}", identity[0])
         and re.fullmatch(r"[0-9a-f]{40}", identity[1]) and identity[1] != "0" * 40
         and (store_identifier or identifier in (IDENTIFIER, IDENTIFIER + ".image", "dev.mobile-release-kit.desktop.distribution",
                            "dev.mobile-release-kit.desktop.observation", "dev.mobile-release-kit.desktop.remove-distribution", PYTHON_IDENTIFIER,
                             "dev.mobile-release-kit.desktop", "dev.mobile-release-kit.desktop.entry",
                             "dev.mobile-release-kit.desktop.remove", INSTALLED_CLI_IDENTIFIER, LAUNCHER_IDENTIFIER, XCODE_SETUP_IDENTIFIER, *SUPPORT_IDENTIFIERS, *[row[1] for row in TOOL_FIXED.values()])), "fixed-signing-requirement")
    return ('identifier "' + identifier + '" and anchor apple generic'
            ' and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
            ' and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
            ' and certificate leaf[subject.OU] = "' + identity[0] + '"'
            ' and certificate leaf = H"' + identity[1] + '"')


def producer_tests_result(stdout):
    """Complete fixed libtest DATA after the original zero/capture closes."""
    need(type(stdout) is bytes and 0 < len(stdout) <= 65536 and stdout.isascii(), "producer-tests-bound")
    lines = stdout.split(b"\n")
    need(len(lines) == 7 and lines[:2] == [b"", b"running 1 test"]
         and lines[3] == b"" and lines[5:] == [b"", b""], "producer-tests-framing")
    need(re.fullmatch(rb"test emitter::tests::fixed_cli_and_original_state_data_refuse_ambient_or_partial_routes +\.\.\. ok",
                      lines[2]) is not None, "producer-tests-roster")
    finish = re.fullmatch(rb"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; (0|[1-9][0-9]{0,3}) filtered out; "
                          rb"finished in (0|[1-9][0-9]{0,2})\.([0-9]{2})s", lines[4])
    need(finish is not None and int(finish[2]) * 100 + int(finish[3]) <= 48000, "producer-tests-result")


def producer_artifact(messages, checkout, target_root, target, *, package_version, remove=False, observer=False, candidate_removal=False):
    """One explicit nonshipping example graph; no packaged code is rebuilt."""
    need(type(package_version) is str and len(package_version) <= 32
         and re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", package_version) is not None,
         "compiler-application-version")
    need(type(remove) is bool and type(observer) is bool and (not observer or remove), "producer-compiler-purpose")
    need(type(candidate_removal) is bool and (not candidate_removal or remove and not observer
         and checkout.name == ".candidate-consumer-helper"), "producer-compiler-purpose")
    build_profile(target)
    need(type(messages) is bytes and 0 < len(messages) <= 4 * 1024 * 1024
         and messages.endswith(b"\n"), "producer-compiler-bound")
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "producer-compiler-duplicate-key")
            value[key] = item
        return value
    try:
        rows = [json.loads(line, object_pairs_hook=pairs) for line in messages.splitlines()]
    except (ValueError, TypeError, RecursionError) as error:
        raise Refused("producer-compiler-json") from error
    need(1 < len(rows) <= 8192 and all(type(row) is dict for row in rows), "producer-compiler-rows")
    finished, artifacts = False, []
    for row in rows:
        need(not finished and row.get("reason") in ("compiler-artifact", "compiler-message", "build-script-executed", "build-finished"),
             "producer-compiler-terminal-order")
        if row["reason"] == "build-finished":
            need(row == {"reason": "build-finished", "success": True} and row["success"] is True, "producer-compiler-finish")
            finished = True
        elif row["reason"] == "compiler-artifact":
            need(type(row.get("target")) is dict and type(row.get("filenames")) is list
                 and all(type(name) is str for name in row["filenames"]), "producer-compiler-artifact")
            artifacts.append(row)
    example = "macos_remove_producer" if remove else "macos_package_producer"
    feature = "macos-remove-producer" if remove else "macos-package-producer"
    selected_features = ["macos-remove-observer-producer", feature] if observer else [feature]
    binary = target_root / target / "release/examples" / example
    specs = (("desktop/src-tauri", "mobile-release-kit-desktop", example, "examples/" + example + ".rs",
              ["example"], ["bin"], selected_features, str(binary)),
             ("desktop/src-tauri", "mobile-release-kit-desktop", "mobile_release_desktop", "src/lib.rs",
              ["lib"], ["lib"], selected_features, None),
             ("desktop/native/macos-installed-native", "mrk-macos-installed-native", "mrk_macos_installed_native", "src/lib.rs",
              ["lib"], ["lib"], ["default", "package-producer-signing"], None))
    chosen = []
    for directory, package, name, source, kinds, crates, features, executable in specs:
        matches = [row for row in artifacts if row["target"].get("name") == name]
        need(len(matches) == 1, "producer-one-target")
        row, root = matches[0], checkout / directory
        profile = row.get("profile")
        need(row.get("package_id") == "path+" + root.as_uri() + "#" + package + ("@" + package_version if package == "mobile-release-kit-desktop" else "@0.1.0")
             and row.get("manifest_path") == str(root / "Cargo.toml") and row.get("features") == features
             and row["target"].get("src_path") == str(root / source)
             and row["target"].get("kind") == kinds and row["target"].get("crate_types") == crates
             and row["target"].get("edition") == "2021" and "executable" in row and row["executable"] == executable
             and type(row.get("fresh")) is bool and type(profile) is dict and profile.get("test") is False
             and profile.get("debug_assertions") is False
             and profile.get("opt_level") == ("0" if candidate_removal or package == "mobile-release-kit-desktop" else "3"), "producer-exact-feature-graph")
        if executable is not None:
            need(row["filenames"] == [executable], "producer-executable-path")
        chosen.append(row)
    need(finished and all(row in chosen or row["target"].get("kind") not in
         (["bin"], ["test"], ["example"], ["bench"], ["cdylib"]) for row in artifacts), "producer-only-executable")
    return binary



# NONSHIPPING fixed existing-owner extension. Neither role is a normal product
# selector, a root override, or a serialized source/cleanup capability.
REMOVAL_REF = "refs/heads/verify/desktop-macos-removal-lifecycle"
REMOVAL_OWNER_PHASES = ("prepare-removal-observers", "package-removal-fixture")
REMOVAL_CASES = ("ordinary", "abrupt")
REMOVAL_OBSERVER_PROGRAM = "mrk-macos-removal-observer"
REMOVAL_OBSERVER_PRODUCER = "macos-remove-observer-producer"
REMOVAL_INPUT_NAMES = ("Remove.pkg", "remove-producer.json", "remove-producer.sig")
REMOVAL_PHASE_ENDPOINTS = {"attach": 60, "before": 120, "joint": 720, "resume": 843,
                           "terminal": 903, "detach": 933, "settle": 963}


def removal_context_data(environment, target):
    need(target in (ARM_TARGET, INTEL_TARGET) and environment.get("GITHUB_REF") == REMOVAL_REF
         and environment.get("MRK_MACOS_PACKAGE_ROLE") == "ordinary-image"
         and environment.get("MRK_MACOS_REMOVAL_CASE") in REMOVAL_CASES,
         "removal-fixture-fixed-route")
    correlation = environment.get("MRK_MACOS_REMOVAL_CORRELATION")
    need(type(correlation) is str and re.fullmatch(r"[0-9a-f]{32}", correlation)
         and correlation != "0" * 32, "removal-fixture-correlation")
    return environment["MRK_MACOS_REMOVAL_CASE"], correlation


def removal_native_result_data(case, role, status):
    """Fixed expected NONZERO test route only; never changes Install0 policy."""
    need(case in REMOVAL_CASES and type(status) is int, "removal-original-case-status")
    expected = {"ordinary": {"removal-live-cancel": 1, "removal-live-continue": 0},
                "abrupt": {"removal-live-cut": 1, "removal-resume": 0}}[case]
    return role in expected and status == expected[role]


def removal_runtime_roles(case):
    need(case in REMOVAL_CASES, "removal-fixed-runtime-case")
    return (("removal-target-attach", "removal-observers-attach", "removal-observer-before")
        + (("removal-live-cancel", "removal-observer-after-cancel", "removal-live-continue")
           if case == "ordinary" else ("removal-live-cut", "removal-observer-after-cut", "removal-resume"))
        + ("removal-observer-terminal", "removal-observers-detach", "removal-target-detach"))


class _RemovalHostClock:
    """Only an adapter to the SAME containing clock, not another deadline."""
    def __init__(self, operation):
        self.operation = operation

    def check(self):
        self.operation.package_clock()



def removal_preparation_roles(case):
    need(case in REMOVAL_CASES, "observer-fixed-preparation-case")
    middle = "after-cancel" if case == "ordinary" else "after-cut"
    roles = ["observer-program-sign", "observer-program-verify", "observer-producer-build"]
    for phase in ("before", middle, "terminal"):
        roles.extend("observer-" + phase + "-" + role for role in
                     ("pkgbuild", "tar", "xar") + FINAL_PACKAGE_ROLES + ("producer-emitter",))
    roles.extend("observer-" + role for role in REMOVE_PACKAGE_ROLES[2:])
    return tuple(roles)


def removal_credential_roster_data():
    application = CREDENTIAL_ROLES[:17] + ("search-final", "default-after")
    return (application + ("producer-adhoc", "producer-adhoc-verify", "producer-cdhash")
            + (INSTALLER_CREDENTIAL_ROSTER + application) * 3 + application)


def removal_credential_quote_data():
    # This bounds the retained managed rows, not process RSS. A list with twice
    # the fixed158 slots covers simultaneous old/new append storage; every
    # actual container size is checked against this quote while accumulating.
    roster = removal_credential_roster_data()
    need(len(roster) == 158, "observer-credential-fixed-count")
    sample = {"role": max(CREDENTIAL_ROLES, key=len), "entered": True,
              "returned": True, "settled": True, "status": -65536}
    row_bound = sys.getsizeof(sample) + sum(sys.getsizeof(key) + sys.getsizeof(value)
                                           for key, value in sample.items()) + 256
    quote = sys.getsizeof([None] * 316) + 158 * row_bound
    need(type(quote) is int and quote <= 512 * 1024, "observer-credential-record-storage")
    return quote


def removal_original_storage_data(entries, registry, additional):
    """Managed Original metadata only; aliases/native iterator internals are not copied.

    The fixed8MiB work reservation separately covers bounded source/control/
    name-roster/transient native scan buffers. This measures retained Python
    containers/scalars, NOT RSS or hidden allocator/native bookkeeping.
    """
    need(type(entries) is list and type(registry) is dict and type(additional) is int
         and 0 <= additional <= 128 and len(entries) <= 24576
         and len(registry) <= len(entries), "removal-original-storage-input")
    def scalar(value, depth):
        need(depth <= 6, "removal-original-metadata-depth")
        size = sys.getsizeof(value)
        if type(value) in (tuple, list):
            need(len(value) <= 64, "removal-original-metadata-vector")
            size += sum(scalar(item, depth + 1) for item in value)
        elif type(value) is dict:
            need(len(value) <= 64, "removal-original-metadata-map")
            for key, item in value.items():
                need(type(key) is str and len(key) <= 128, "removal-original-metadata-key")
                size += sys.getsizeof(key) + scalar(item, depth + 1)
        else:
            need(value is None or type(value) in (int, bool, str, bytes), "removal-original-metadata-scalar")
            if type(value) in (str, bytes):
                need(len(value) <= 4096, "removal-original-metadata-string")
        return size
    # Both old/new list+registry storage remain charged across an append.
    total = 2 * (sys.getsizeof(entries) + sys.getsizeof(registry))
    for entry in entries:
        need(type(entry) is dict and len(entry) <= 64, "removal-original-metadata-row")
        row = sys.getsizeof(entry)
        for key, value in entry.items():
            need(type(key) is str and len(key) <= 128, "removal-original-field")
            row += sys.getsizeof(key)
            if key == "parent_entry":
                # SAME retained entry, already measured in this table.
                need(value is None or type(value) is dict, "removal-original-parent-alias")
            elif key == "iterator":
                # Native iterator is at most one active original. Its borrowed
                # fixed scan buffer is in the work reservation, not a body copy.
                row += sys.getsizeof(value)
            else:
                row += scalar(value, 0)
        need(row <= 16384, "removal-original-row-storage")
        total += row
    # Sixty-four fixed extra rows cover the existing bounded source/three
    # capture-publication helpers between new-owner boundaries. Each is
    # measured again at the next boundary; they do not gain lifetime/FD credit.
    return total + (additional + 64) * 16384


def removal_prepared_data(value, environment, target, case, correlation):
    """Closed transport after a separately observed original preparation0.

    Still not P/signature/peer authority: the actual mounted originals and
    observer/native admissions independently establish those relationships.
    """
    fields = {"schemaVersion", "phase", "source", "target", "workflowSource", "runId", "runAttempt",
              "case", "correlation", "passed", "targetRetired", "originalClosesKnown", "outerFinalityRequired",
              "nativeCalls", "nativeCallsSha256", "credentialCalls", "credentialCallsSha256", "credentialContexts",
              "targetBinding", "targetFiles", "targetImage", "observerImage", "observers", "observerProgramSha256",
              "controlBytes", "productReady"}
    need(type(value) is dict and set(value) == fields and type(value["schemaVersion"]) is int
         and value["schemaVersion"] == 1 and value["phase"] == "prepare-removal-observers"
         and value["source"] == value["workflowSource"] == environment["GITHUB_SHA"]
         and value["target"] == target and target in (ARM_TARGET, INTEL_TARGET)
         and value["runId"] == environment["GITHUB_RUN_ID"]
         and value["runAttempt"] == environment["GITHUB_RUN_ATTEMPT"] and value["case"] == case
         and value["correlation"] == correlation
         and all(value[key] is True for key in ("passed", "targetRetired", "originalClosesKnown", "outerFinalityRequired"))
         and value["productReady"] is False and type(value["nativeCalls"]) is int and value["nativeCalls"] == 46
         and type(value["credentialCalls"]) is int and value["credentialCalls"] == 158
         and type(value["credentialContexts"]) is int and value["credentialContexts"] == 8
         and type(value["controlBytes"]) is int and 0 < value["controlBytes"] <= 16 * 1024 * 1024
         and all(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}", value[key]) and value[key] != "0" * 64
                 for key in ("nativeCallsSha256", "credentialCallsSha256", "observerProgramSha256")),
         "observer-preparation-original-binding")
    return value


def transport_mount_path_data(environment, target, phase):
    """Fixed namespace only; neither package authority nor collision retry."""
    need(type(environment) is dict and target in (ARM_TARGET, INTEL_TARGET)
         and phase in ("package-install", SAME_PACKAGE_PHASE, UPDATE_PHASE)
         and all(type(environment.get(key)) is str
                 and re.fullmatch(r"[1-9][0-9]{0,19}", environment[key])
                 for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "package-transport-context")
    context = "\n".join((environment["GITHUB_RUN_ID"], environment["GITHUB_RUN_ATTEMPT"], target, phase))
    return Path("/Volumes") / ("MRK-Install-" + digest(context.encode("ascii"))[:32])


class Operation:
    """Custody for this one fixed packaging operation and its finite outputs."""

    def __init__(self, owner, checkout, work, phase, environment, stager, *, target=ARM_TARGET, support_started=None, prepared=None):
        need(phase in ("candidate-baseline",) + PHASES + SUPPORT_PHASES + STORE_SIGNING_PHASES + PYTHON_PHASES + SIGNING_PHASES + TOOL_SIGNING_PHASES + TOOL_SELECTION_PHASES + TOOL_PROJECT_PHASES + NOTARY_PHASES + FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES + REMOVAL_OWNER_PHASES, "closed-phase")
        self.arch, self.runner_arch, self.release_input = build_profile(target)
        self.target = target
        self.owner, self.checkout, self.work = owner, checkout, work
        if prepared is not None:
            from desktop.tools.macos_prepared_package import PreparedBinding
            need(type(prepared) is PreparedBinding and phase in ("package-install", "finalize-image")
                 and prepared.origin["target"] == target
                 and (phase == "package-install" or prepared.same_source), "prepared-fixed-owner-purpose")
            prepared.finalization_environment(environment)  # Exact current caller, no env mutation.
        self.candidate_removal_context = None
        self.candidate_removal_inputs = []
        self.candidate_removal_root = None
        self.prepared_binding = prepared
        self.prepared_staging = False
        self.diagnostic_source_entry = None
        self.diagnostic_program = None
        self.diagnostic_program_entry = None
        self.current_readback_module = None
        self.stager_failure_module = stager
        self.phase, self.environment, self.stager = phase, environment, stager
        # Exhaustive SOURCE-selected purpose. No filenames/roles come from DATA.
        self.removal = phase in REMOVE_PHASES + REMOVAL_OWNER_PHASES
        self.setup_package = phase == "finalize-xcode-setup-package"
        self.setup_verify = phase == XCODE_SETUP_VERIFY
        need(not self.setup_verify or (environment.get("GITHUB_REF") in (CANDIDATE_REF, XCODE_SETUP_REF)
             and xcode_setup_event(environment, phase)
             and environment.get("MRK_MACOS_PACKAGE_ROLE") == "ordinary-image"
             and environment.get("MRK_MACOS_STORE_RUNTIME") is None
             and not any(key in environment for key in CREDENTIAL_VARIABLES + INSTALLER_CREDENTIAL_VARIABLES + (NOTARY_KEY_VARIABLE,))),
             "setup-verification-purpose")
        self.setup_verify_complete = False
        self.setup_log_cursor = False
        self.setup_verify_inputs = []
        self.setup_verify_system = []
        self.setup_verify_returned = []
        self.setup_verify_hard = None
        need(not self.setup_package or environment.get("MRK_MACOS_PACKAGE_ROLE") == "ordinary-image"
             and environment.get("MRK_MACOS_STORE_RUNTIME") is None, "setup-package-fixed-purpose")
        # The existing SOURCE-selected ordinary workflow alone ships this UI.
        # Aqua observation and the separate Remove package keep their flat form.
        self.install_product = not self.removal and environment.get("MRK_MACOS_PACKAGE_ROLE") == "ordinary-image"
        self.package_filename = "Remove.pkg" if self.removal else "MobileReleaseKit.pkg"
        self.scripts_name = "remove-scripts" if self.removal else "scripts"
        self.packager_filename = "Remove-original.pkg" if self.removal else "MobileReleaseKit-original.pkg"
        self.unsigned_package_name = "remove-package-unsigned" if self.removal else "package-unsigned"
        self.final_package_name = "remove-package-final" if self.removal else "package-final"
        self.package_status_name = "remove-package-finalization.status" if self.removal else "package-finalization.status"
        self.package_receipt_name = "android-helper-finalize-remove-package.json" if self.removal else "android-helper-finalize-package.json"
        self.component_filename = self.package_filename
        if self.setup_package or self.setup_verify:
            self.component_filename, self.package_filename = "PrepareXcode.pkg", "Prepare Xcode.pkg"
            self.scripts_name, self.packager_filename = "xcode-setup-inputs/scripts-original", "xcode-setup-inputs/packager/PrepareXcode-original.pkg"
            self.unsigned_package_name, self.final_package_name = "xcode-setup-unsigned", "xcode-setup-final"
            self.package_status_name, self.package_receipt_name = "xcode-setup-finalization.status", "android-helper-finalize-xcode-setup-package.json"
        self.setup_component_inputs = None
        self.setup_bom_verified = False
        self.setup_helper_sha = None
        self.setup_quoted = False
        self.setup_input_root = self.setup_parts_root = self.setup_component_root = self.setup_packager_root = None
        self.setup_root_names, self.setup_component_names, self.setup_packager_names = set(), set(), set()
        self.setup_parts_names = {"Bom", "PackageInfo", "Payload"}
        self.image_filename = "MobileReleaseKit-Remove.dmg" if self.removal else "MobileReleaseKit.dmg"
        self.image_directory = "remove-distribution" if self.removal else "distribution"
        self.final_image_directory = "remove-distribution-final" if self.removal else "distribution-final"
        self.image_identifier = "dev.mobile-release-kit.desktop.remove-distribution" if self.removal else "dev.mobile-release-kit.desktop.distribution"
        self.producer_filename = "macos-remove-producer" if self.removal else "macos-package-producer"
        self.removal_case = self.removal_correlation = None
        self.removal_prep_phase = self.removal_final_context = None
        self.removal_preparation_complete = self.removal_complete = self.removal_unknown = False
        self.removal_credential_reserved = self.removal_control_reserved = 0
        self.removal_host_module = self.removal_api = None
        self.removal_thread = self.removal_threading = self.removal_runner = None
        self.removal_ui_joined = False
        self.removal_ui_entered = self.removal_before_settled = self.removal_abort_known = False
        self.removal_abort_roles = None
        self.removal_channel = self.removal_channel_parent = self.removal_ui_deadline = None
        self.removal_install_root = None
        self.removal_ui_result = self.removal_ui_error = self.removal_ui_facts = None
        self.removal_ui_outcome = {"done": False, "known": False}
        self.removal_scan_state = "closed"
        self.removal_original_reserved = 0
        self.removal_joint_deadline = self.removal_baseline_mount = None
        self.removal_mounts, self.removal_sources, self.removal_system_parents = [], [], []
        self.removal_output_facts, self.removal_markers = {}, {}
        self.removal_pending_outputs = set()
        self.removal_requests = None
        self.entries, self.calls, self.errors = [], [], []
        self.diagnostic_failure = None  # Private finite DATA, never a completion/ownership latch.
        self.compiler_failure = None  # Only a failed, returned, capture-settled build may populate this.
        self.entry_registry = {}  # Same originals, retained even after consumed/unknown closes.
        self.credential_calls, self.credential_contexts = [], []
        self.credential_active = None
        self.credential_unknown = self.credential_failed = self.signing_mutation_pending = False
        self.fixed_sign_complete = False
        self.notary_started = self.notary_observed = None
        self.notary_unknown = self.notary_mutation_pending = self.notary_retiring = self.notary_complete = False
        self.notary_roots, self.notary_ticket_rows, self.notary_tools = [], [], {}
        self.notary_profile = self.notary_copy = self.notary_zip = self.notary_zip_sha = None
        self.notary_key = self.notary_final = self.notary_result = None
        self.installer_selection = self.installer_certificates = self.installer_profile_sha = None
        self.final_package_roots, self.final_package_inputs = [], []
        self.final_package_output_root = self.final_package_output = self.final_package_sha = None
        self.final_package_preimage = None
        self.final_package_complete = False
        self.install_presentation_sources = []
        self.install_product_root = self.install_product_output_root = self.install_product_original = None
        self.install_component_inputs = None
        self.final_image_roots, self.final_image_inputs = [], []
        self.final_image_original = self.final_image_output_root = self.final_image_output = self.final_image_sha = None
        self.final_image_preimage = None  # Held unlinked PRE, separate from name-bound inputs.
        self.final_image_complete = self.final_image_mount_verified = False
        self.directories = {}
        self.work_entry = self.target_entry = None
        self.profile_entry = self.source_entry = None
        self.target_name = "android-helper-target" if phase == "prepare" else "android-helper-" + phase
        self.stage, self.sha256 = "owned-directory-admission", None
        self.tool_purpose = phase[len("sign-"):] if phase in TOOL_SIGNING_PHASES else None
        self.tool_started = self.tool_observed = None
        self.tool_quote_ready = self.tool_complete = False
        self.tool_staged_roles = ()
        self.signing = self.service_profile = self.producer_profile = None
        self.package_started = self.package_observed = self.package_endpoint = None
        self.package_outputs, self.package_sources, self.package_roots = [], [], []
        self.stager_io_pending = None
        self.python_started = self.python_observed = None
        self.python_directories, self.python_files, self.python_input_originals = {}, {}, []
        self.python_mutation_pending = self.python_retiring = False
        self.python_signed = self.python_modules = None
        self.producer_profile_entry = self.distribution_entry = None
        self.mount_entry = self.mount_placeholder = self.mount_device = None
        self.mount_api = self.mount_host_source = None
        self.transport_mount = self.transport_slash = self.transport_volumes = self.transport_roster = None
        self.mount_entered = self.mount_known = self.mount_detached = False
        self.installer_entered = self.installer_zero = self.installation_readback = False
        self.removal_package_complete = False
        self.android_support = self.android_support_module = None
        self.store_signing = self.store_signing_module = None
        self.support_started = support_started
        self.app_absence = self.app_absence_module = self.app_absence_api = None
        self.update = self.update_module = self.update_api = None
        self.same_package_complete = False
        self.same_package_case = None
        self.entry_sha256 = self.desktop_facade_sha256 = self.resident_image_sha256 = None
        self.image_release = self.image_source = self.image_package_version = self.release_entry = None
        self.receipt = {"schemaVersion": 1, "phase": phase, "target": target, "source": environment["GITHUB_SHA"],
                        "packageRole": environment.get("MRK_MACOS_PACKAGE_ROLE"),
                        "workflowSource": environment["GITHUB_WORKFLOW_SHA"],
                        "workflow": environment["GITHUB_WORKFLOW_REF"], "runId": environment["GITHUB_RUN_ID"],
                        "runAttempt": environment["GITHUB_RUN_ATTEMPT"], "toolchain": rust_toolchain(target),
                        "helperIdentifier": IDENTIFIER, "originalCalls": self.calls,
                        "credentialOriginals": self.credential_calls, "credentialContexts": self.credential_contexts,
                        "targetRetired": False, "originalClosesKnown": False, "passed": False,
                        "outerFinalityRequired": True, "androidServiceAuthenticated": False,
                        "androidRegisteredCopyQualified": False, "androidBuildQualified": False,
                        "developerIdOrNotarizationQualified": False, "productReady": False}
        if phase in FINAL_IMAGE_PHASES:
            self.receipt["distributionQualified"] = False
        if phase in NOTARY_PHASES + FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES or phase in ("prepare-removal-observers", SAME_PACKAGE_PHASE):
            self.receipt.update(notaryAuthentication={"created": False, "closed": False, "retired": False},
                                toolchain=None, helperIdentifier=None)

    def store_signing_load(self):
        entry = self.source_original("desktop/tools/macos_store_signing.py", "source-store-signing", 65536)
        body = self.read(entry)
        path = self.checkout / "desktop/tools/macos_store_signing.py"
        spec = importlib.util.spec_from_file_location("mrk_store_signing", path)
        module = importlib.util.module_from_spec(spec)
        exec(compile(body, str(path), "exec"), module.__dict__)
        module.Refused = Refused
        need(self.read(entry) == body, "store-signing-source-post")
        self.package_sources.append((entry, body))
        self.store_signing_module = module
        module.start(self, sys.modules[__name__], self.support_started)

    def android_support_load(self):
        entry = self.source_original("desktop/tools/macos_android_support_signing.py", "source-support-adapter", 65536)
        body = self.read(entry)
        path = self.checkout / "desktop/tools/macos_android_support_signing.py"
        spec = importlib.util.spec_from_file_location("mrk_android_support_adapter", path)
        module = importlib.util.module_from_spec(spec)
        need(spec.name not in sys.modules, "support-adapter-module-collision")
        sys.modules[spec.name] = module
        try:
            exec(compile(body, str(path), "exec"), module.__dict__)
            module.Refused = Refused
            need(self.read(entry) == body, "support-source-changed")
            self.package_sources.append((entry, body))
            self.android_support_module = module
            module.start(self, sys.modules[__name__], self.support_started)
        finally:
            need(sys.modules.get(spec.name) is module, "support-adapter-module-rebound")
            del sys.modules[spec.name]

    def update_load(self):
        entry = self.source_original("desktop/tools/macos_update_verification.py", "source-update-adapter", 65536)
        body = self.read(entry)
        path = self.checkout / "desktop/tools/macos_update_verification.py"
        spec = importlib.util.spec_from_file_location("mrk_update_adapter", path)
        module = importlib.util.module_from_spec(spec)
        exec(compile(body, str(path), "exec"), module.__dict__)
        need(self.read(entry) == body, "update-source-changed")
        self.package_sources.append((entry, body))
        self.update_module = module
        module.start(self, sys.modules[__name__])

    def app_absence_load(self):
        # One fixed current SOURCE leaf, held before loading any definitions.
        # Not a plug-in resolver or a new process owner.
        entry = self.source_original("desktop/tools/macos_app_absence_fixture.py", "source-app-absence-adapter", 112 * 1024)
        body = self.read(entry)
        path = self.checkout / "desktop/tools/macos_app_absence_fixture.py"
        spec = importlib.util.spec_from_file_location("mrk_app_absence_adapter", path)
        module = importlib.util.module_from_spec(spec)
        exec(compile(body, str(path), "exec"), module.__dict__)
        need(self.read(entry) == body, "app-absence-source-changed")
        self.package_sources.append((entry, body))
        self.app_absence_module = module
        module.start(self, sys.modules[__name__])

    def app_absence_live_limit(self):
        # Only the sequential candidate PREPARE owns the bootstrap originals
        # plus paired source/destination DFS walks. Other phases are unchanged.
        if getattr(self, "candidate_restore_context", None) is not None and self.phase == "prepare-app-absence":
            need(getattr(self, "candidate_external_originals", None) is None, "candidate-builder-budget-scope")
            return 160
        return 128 if getattr(self, "candidate_external_originals", None) is not None else 96

    def register(self, fd, role, kind, parent=None, name=None):
        entry = {"fd": fd, "role": role, "kind": kind, "parent": parent, "name": name, "closed": False}
        self.entries.append(entry)  # Before any fallible identity/content observation.
        if self.setup_package or self.setup_verify:
            need(len(self.entries) <= 24576
                 and sum(e["fd"] is not None or not e["closed"] for e in self.entries) + 24 <= 96,
                 "setup-original-ledger-bound")
        if self.prepared_binding is not None or self.prepared_staging or self.candidate_removal_context is not None:
            # One current book plus forty reserved codec/native/capture slots;
            # consumed-unknown rows never get future-close credit.
            need(len(self.entries) <= 24576
                 and sum(e["fd"] is not None or not e["closed"] for e in self.entries) + 40 <= 256,
                 "prepared-original-ledger-bound")
        if self.app_absence is not None or self.update is not None:
            external = getattr(self, "candidate_external_originals", None)
            extra = 0 if external is None else external()
            # The candidate materializer coexists with the acquisition's original
            # owner (up to96) and its bounded DFS writer (up to19). Other owners
            # retain their existing96 limit. Unknown closes never free a slot.
            live_limit = self.app_absence_live_limit()
            need(type(extra) is int and 0 <= extra <= 96 and len(self.entries) + getattr(self, "candidate_bootstrap_originals", 0) + (24 if getattr(self, "candidate_restore_context", None) is not None else 0) <= 24576
                 and extra + sum(e["fd"] is not None or not e["closed"] for e in self.entries) <= live_limit,
                 "app-absence-original-ledger-bound")
        if self.store_signing is not None:
            need(len(self.entries) <= self.store_signing_module.ORIGINAL_LIMIT
                 and sum(e["fd"] is not None for e in self.entries) <= 128,
                 "store-original-ledger-bound")
        self.entry_registry[id(entry)] = entry  # History retains the FD if this insertion raises.
        return entry

    def close(self, entry):
        if entry["fd"] is None:
            return
        fd, entry["fd"] = entry["fd"], None
        try:
            os.close(fd)  # Never retry an uncertain descriptor close.
            entry["closed"] = True
        except BaseException as error:
            self.errors.append({"stage": "close", "role": entry["role"], "type": type(error).__name__})

    def recheck_directory(self, entry):
        need(type(entry) is dict and self.entry_registry.get(id(entry)) is entry
             and entry["kind"] == "directory"
             and type(entry["fd"]) is int and not entry["closed"], "directory-original-unavailable")
        parent = entry.get("parent_entry")
        if parent is not None:
            self.recheck_directory(parent)
            need(entry["parent"] == parent["fd"], "directory-parent-changed")
            named = os.stat(entry["name"], dir_fd=parent["fd"], follow_symlinks=False)
        elif entry is self.work_entry:
            named = self.work.lstat()
        elif entry is self.source_entry:
            named = self.checkout.lstat()
        elif entry is self.diagnostic_source_entry:
            named = CHECKOUT.lstat()
        else:
            raise Refused("directory-original-unbound")
        need(directory_identity(os.fstat(entry["fd"])) == directory_identity(named)
             == entry["identity"], "directory-original-changed")

    def directory(self, parent, name, role):
        need(type(name) is str and name not in ("", ".", "..") and "/" not in name,
             "directory-component")
        self.recheck_directory(parent)
        # entries retains each parent object for this operation's lifetime, so
        # its identity cannot be recycled like a consumed numeric descriptor.
        key = (id(parent), name)
        if key in self.directories:
            entry = self.directories[key]
            self.recheck_directory(entry)
            return entry  # Same original only; never reopen a closed/replaced hit.
        fd = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=parent["fd"])
        entry = self.register(fd, role, "directory", parent["fd"], name)
        entry["parent_entry"] = parent
        entry["identity"] = directory_identity(os.fstat(fd))
        self.recheck_directory(entry)
        self.directories[key] = entry
        return entry

    def descend(self, parent, names):
        for name in names:
            parent = self.directory(parent, name, "directory-" + name)
        return parent

    def original(self, parent, name, role, limit, modes, *, alias=False):
        self.recheck_directory(parent)
        fd = os.open(name, READ_FLAGS, dir_fd=parent["fd"])
        entry = self.register(fd, role, "file", parent["fd"], name)
        entry["parent_entry"] = parent
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_gid == os.getgid()
             and before.st_nlink in ((1, 2) if alias else (1,))
             and stat.S_IMODE(before.st_mode) in modes and 0 < before.st_size <= limit, "file-original-shape")
        entry["identity"] = signature(before)
        return entry

    def source_original(self, relative, role, limit):
        if self.source_entry is None:
            fd = os.open(self.checkout, READ_FLAGS | os.O_DIRECTORY)
            self.source_entry = self.register(fd, "source-root", "directory")
            self.source_entry["identity"] = directory_identity(os.fstat(fd))
            need(directory_identity(self.checkout.lstat()) == self.source_entry["identity"], "source-original-changed")
        parts = Path(relative).parts
        parent = self.descend(self.source_entry, parts[:-1])
        return self.original(parent, parts[-1], role, limit, (0o444, 0o644))

    def read(self, entry):
        self.recheck_directory(entry["parent_entry"])
        need(signature(os.fstat(entry["fd"])) == entry["identity"]
             and signature(os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False)) == entry["identity"], "file-original-changed")
        size = entry["identity"][6]
        value = os.pread(entry["fd"], size + 1, 0)
        need(len(value) == size and signature(os.fstat(entry["fd"])) == entry["identity"]
             and signature(os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False)) == entry["identity"], "file-original-read-changed")
        self.recheck_directory(entry["parent_entry"])
        return value

    def publish(self, name, data, *, mode=0o600, parent=None):
        if parent is not None:
            prepared = (self.prepared_staging and self.phase == "package-install" and parent is self.target_entry
                and 1 <= len(self.calls) <= 16 and self.calls[-1].get("role") == "prepared-resource-memory"
                and self.calls[-1].get("returned") is True and self.calls[-1].get("capturesSettled") is False
                and name in tuple("android-helper-prepared-resource-memory-" + f"{len(self.calls):02d}" + suffix
                                  for suffix in (".stdout", ".stderr", ".status")))
            need(mode == 0o600 and (prepared or (self.phase == SAME_PACKAGE_PHASE and parent is self.same_package_case
                  or self.phase == UPDATE_PHASE and self.update is not None and parent is self.update["case"])
                 and name == "installer-output.status"), "same-package-status-purpose")
            self.recheck_directory(parent)
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     mode, dir_fd=(self.work_entry if parent is None else parent)["fd"])
        entry = self.register(fd, "output-" + name, "file")
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            need(written > 0, "output-short-write")
            offset += written
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
             and info.st_gid == os.getgid(), "exclusive-output-original")
        os.fchmod(fd, mode)
        os.fsync(fd)
        need(os.pread(fd, len(data) + 1, 0) == data, "output-readback")
        if self.android_support is not None:
            self.android_support_module.output_record(self, name, entry)
        if self.store_signing is not None:
            self.store_signing_module.output_record(self, name, entry)
        self.close(entry)
        need(entry["closed"], "output-close-unknown")

    def call(self, role, argv, environment, *, cwd, timeout, limit):
        self.candidate_removal_quote()
        need(self.credential_known() and not self.credential_failed, "credential-dispatch-unknown")
        image_purpose = {"distribution-sign": "distribution-image", "observation-sign": "observation-image"}.get(role)
        if self.phase in ("package-install", "package-remove", "prepare-removal-observers") and image_purpose is not None:
            need(self.credential_active is not None and self.credential_active.get("purpose") == image_purpose
                 and self.credential_active["ready"] and self.credential_active["roles"] == IMAGE_CREDENTIAL_ROLES[image_purpose],
                 "package-image-credential-required")
        if role == "final-package-sign":
            need(self.removal_final_active() and self.credential_active is not None
                 and self.credential_active.get("purpose") == "installer" and self.credential_active["ready"]
                 and self.credential_active["roles"] == (role,), "installer-credential-required")
        if self.credential_active is not None:
            context = self.credential_active
            need(context["ready"] and not context["retiring"] and role in context["roles"], "credential-callback-purpose")
            now = self.credential_clock(context)
            need(now + (timeout + 3) * 1_000_000_000 < context["endpoint"] - 30_000_000_000, "credential-callback-deadline")
            self.credential_census(context)
            environment = dict(environment, HOME="/Users/runner")
        need(not any(name in environment for name in CREDENTIAL_VARIABLES + INSTALLER_CREDENTIAL_VARIABLES
                     + ("MRK_MACOS_NOTARY_API_KEY_BASE64",)), "credential-child-environment")
        if self.phase in NOTARY_PHASES:
            need(NOTARY_KEY_VARIABLE not in environment and self.credential_active is None
                 and not self.notary_retiring and not self.notary_unknown and not self.errors
                 and self.stager_io_pending is None and len(self.calls) < len(notary_roles(getattr(self, "notary_launcher", False)))
                 and role == notary_roles(getattr(self, "notary_launcher", False))[len(self.calls)]
                 and self.notary_mutation_pending == (role in ("staple-inner", "staple-outer", "staple-launcher"))
                 and all(row.get("returned") is True and row.get("capturesSettled") is True for row in self.calls),
                 "notary-original-dispatch-boundary")
            self.notary_clock()
        if self.removal_final_active():
            current = self.removal_final_calls()
            roles = final_package_roles(self.removal, self.environment["MRK_MACOS_PACKAGE_ROLE"], setup=self.setup_package)
            need(not self.notary_retiring and not self.notary_unknown and not self.errors
                 and self.stager_io_pending is None and len(current) < len(roles)
                 and role == roles[len(current)]
                 and self.notary_mutation_pending == (role in (("final-package-productbuild", "final-package-staple") + (XCODE_SETUP_MUTATION_ROLES if self.setup_package else ())))
                 and self.signing_mutation_pending == (role == "final-package-sign")
                 and all(row.get("returned") is True and row.get("capturesSettled") is True for row in self.calls),
                 "final-package-original-dispatch-boundary")
            self.notary_clock()
        if self.phase in FINAL_IMAGE_PHASES:
            need(self.credential_active is None and not self.credential_calls and not self.credential_contexts
                 and not self.notary_retiring and not self.notary_unknown and not self.errors
                 and self.stager_io_pending is None and len(self.calls) < len(FINAL_IMAGE_ROLES)
                 and role == FINAL_IMAGE_ROLES[len(self.calls)]
                 and self.notary_mutation_pending == (role == "final-image-staple")
                 and not self.signing_mutation_pending
                 and all(row.get("returned") is True and row.get("capturesSettled") is True for row in self.calls),
                 "final-image-original-dispatch-boundary")
            self.notary_clock()
        if self.phase in PYTHON_PHASES:
            need(not self.python_retiring and not self.errors and self.stager_io_pending is None
                 and len(self.calls) < len(PYTHON_ROLES) and role == PYTHON_ROLES[len(self.calls)]
                 and self.python_mutation_pending == (role == "python-sign")
                 and all(row.get("returned") is True and row.get("capturesSettled") is True for row in self.calls),
                 "python-original-dispatch-boundary")
            self.python_clock()
        if self.phase in TOOL_SIGNING_PHASES:
            expected = (self.phase, self.phase + "-verify")
            need(self.tool_quote_ready and not self.errors and self.stager_io_pending is None
                 and len(self.calls) < 2 and role == expected[len(self.calls)]
                 and self.signing_mutation_pending == (role == self.phase)
                 and all(c.get("returned") is True and c.get("capturesSettled") is True for c in self.calls),
                 "tool-original-dispatch-boundary")
            self.tool_clock()
        if self.android_support is not None:
            self.android_support_module.dispatch(self, role)
        if self.store_signing is not None:
            self.store_signing_module.dispatch(self, role)
        if self.app_absence is not None:
            self.app_absence_module.dispatch(self, role)
        if self.update is not None:
            self.update_module.dispatch(self, role, argv)
        recorded_role = self.removal_recorded_role(role)
        if self.phase == "prepare-removal-observers":
            roles = removal_preparation_roles(self.removal_case)
            need(len(self.calls) < len(roles) and recorded_role == roles[len(self.calls)]
                 and all(row.get("returned") is True and row.get("capturesSettled") is True for row in self.calls),
                 "observer-preparation-original-order")
            self.notary_clock()
        if self.phase == "package-removal-fixture":
            roles = self.removal_abort_roles or removal_runtime_roles(self.removal_case)
            need(not self.removal_unknown and len(self.calls) < len(roles) and role == roles[len(self.calls)],
                 "removal-runtime-original-order")
            self.package_clock()
        if self.phase == SAME_PACKAGE_PHASE:
            need(not self.errors and self.stager_io_pending is None and self.credential_active is None
                 and not self.credential_calls and not self.credential_contexts and self.notary_key is None
                 and len(self.calls) < len(SAME_PACKAGE_ROLES)
                 and (role == SAME_PACKAGE_ROLES[len(self.calls)] or role == "distribution-detach"
                      and len(self.calls) == 1 and self.calls[0].get("role") == "distribution-attach"
                      and self.calls[0].get("returncode") == 0 and self.mount_known and not self.installer_entered)
                 and all(c.get("returned") is True and c.get("capturesSettled") is True for c in self.calls),
                 "same-package-original-boundary")
            self.notary_clock()
        if self.setup_verify:
            if role == XCODE_SETUP_LOG_CAPTURE:
                need(setup_failed_installer_index(self.calls) == len(self.calls) - 1
                     and self.setup_log_cursor is True and self.calls[1].get("returncode") == 0,
                     "setup-verification-role-order")
                # A failed Installer may leave a legitimate partial namespace.
                # Recheck immutable inputs only, not the success-only final tree.
                self.setup_verification_quote()
                self.package_post()
            else:
                need(len(self.calls) < len(XCODE_SETUP_VERIFY_ROLES)
                     and role == XCODE_SETUP_VERIFY_ROLES[len(self.calls)]
                     and all(row["returned"] and row.get("capturesSettled") is True
                         and type(row.get("returncode")) is int and row["returncode"] in
                         ((0, 1) if row["role"] == "setup-log-cursor" else (0,)) for row in self.calls),
                     "setup-verification-role-order")
                self.setup_verification_post()
                if role == "setup-installer-first":
                    self.setup_verification_absent()
        prepared_capture = self.prepared_staging and role == "prepared-resource-memory"
        if prepared_capture:
            need(self.phase == "package-install" and self.target_entry is not None and len(self.calls) < 16
                 and all(row.get("role") == role and row.get("returned") is True
                         and row.get("capturesSettled") is True and row.get("returncode") == 0 for row in self.calls),
                 "prepared-resource-capture-order")
            self.recheck_directory(self.target_entry)
        record = {"role": recorded_role, "entered": True, "returned": False, "capturesSettled": False}
        self.calls.append(record)
        try:
            # This is the SAME owner invocation, after package clock/reserve
            # admission. An unknown dispatch remains conservatively entered.
            if self.phase in ("package-install", SAME_PACKAGE_PHASE):
                if role == "distribution-attach":
                    self.mount_entered = True
                elif role == "installer":
                    self.installer_entered = True
            if self.phase in FINAL_IMAGE_PHASES and role == "final-image-attach":
                self.mount_entered = True  # This SAME dispatch, after its clock/reserve admission.
            result = self.owner.run_owned(argv, environ=environment, cwd=cwd, timeout=timeout,
                                          capture=True, text=False, output_limit=limit)
        except BaseException as error:
            for field in ("dispatched", "contained", "cleanup_complete"):
                value = getattr(error, field, None)
                record[field] = value if type(value) is bool else None
            try:
                record["originalFailure"] = original_failure(error, self.owner, self.checkout, timeout, limit)
            except BaseException:
                # Diagnostic failure must never replace the original exception.
                try:
                    record["originalFailure"] = {"schemaVersion": 1, "available": False}
                except BaseException:
                    pass
            raise
        need(type(result) is subprocess.CompletedProcess and type(result.returncode) is int
             and type(result.args) in (list, tuple) and tuple(result.args) == tuple(argv)
             and type(result.stdout) is bytes and type(result.stderr) is bytes
             and len(result.stdout) + len(result.stderr) <= limit, "original-return-contract")
        need(self.android_support is None and self.store_signing is None or 0 <= result.returncode <= 255, "support-native-return-unknown")
        if self.phase == "package-install" and role == "installer":
            # Save the actual original status before any diagnostics/readback.
            self.publish("installer-output.status", (str(result.returncode) + "\n").encode("ascii"))
        if self.phase == SAME_PACKAGE_PHASE and role == "installer":
            self.same_package_save_status(result.returncode)
        if self.phase == UPDATE_PHASE and role == UPDATE_ROLES[1]:
            self.update_module.status(self, result.returncode)
        if self.app_absence is not None and role == "app-absence-install":
            self.app_absence_module.save_restore_status(self, result.returncode)
        record.update(returned=True, returncode=result.returncode,
                      stdoutSha256=digest(result.stdout), stderrSha256=digest(result.stderr))
        prefix = "android-helper-" + ((self.phase + "-") if self.removal or self.setup_package or self.phase == SAME_PACKAGE_PHASE else "") + recorded_role
        # Prepared acquisition/hydration share a work root. Each resource
        # sample belongs to this original target, not a reusable work-root name.
        # The calls row was retained before dispatch; failed slots never replay.
        capture_parent = self.target_entry if prepared_capture else None
        if prepared_capture:
            prefix += "-" + f"{len(self.calls):02d}"
        self.publish(prefix + (".jsonl" if role == "build" else ".stdout"), result.stdout, parent=capture_parent)
        self.publish(prefix + ".stderr", result.stderr, parent=capture_parent)
        self.publish(prefix + ".status", (str(result.returncode) + "\n").encode("ascii"), parent=capture_parent)
        if self.phase == "package-install" and role == "installer":
            self.publish("installer-output.txt", result.stdout + result.stderr)
        record["capturesSettled"] = True  # All original output/readback/closes returned.
        if self.phase == "package-remove" and role == "producer-emitter" and result.returncode == 78:
            try:
                record["removeProducerReason"] = remove_producer_refusal(result.stdout, result.stderr)
            except BaseException:
                pass  # Diagnostics never replace the original unsuccessful command.
        if self.setup_verify and role in XCODE_SETUP_VERIFY_ROLES[2:4] and result.returncode != 0:
            # All three consume only this returned original after its captures
            # positively settled. A diagnostic failure cannot replace its exit.
            for key, parser in (("setupDiagnostic", setup_installer_diagnostics),
                                ("setupHooks", setup_hook_diagnostics), ("installerErrors", installer_errors)):
                try:
                    record[key] = parser(result.stdout, result.stderr)
                except BaseException:
                    pass
        if result.returncode != 0 and (self.phase == "package-install" and role == "installer"
                or self.app_absence is not None and role in _FIXTURE_INSTALLER_ROLES.get(self.phase, ())):
            try:
                record["installerMarkers"] = installer_markers(result.stdout, result.stderr)
                record["installerErrors"] = installer_errors(result.stdout, result.stderr)
            except BaseException:
                pass  # Diagnostics cannot change the original result or cleanup.
        if self.phase == "notarize-payload" and role == "payload-submit" and result.returncode != 0:
            try:
                record["notarySubmitDiagnostic"] = notary_submit_diagnostic(result.stderr)
            except BaseException:
                pass  # Never replace the same nonzero original or affect cleanup.
        if (self.phase == "prepare" and role == "build"
                or self.phase == "prepare-app-absence" and role in _FIXTURE_COMPILER_ROLES) and result.returncode != 0:
            try:
                compiler_root = (self.candidate_fixture_checkout
                    if self.phase == "prepare-app-absence" and role == "app-absence-build"
                    and getattr(self, "candidate_restore_context", None) is not None else self.checkout)
                self.compiler_failure = compiler_diagnostic(result.stdout, result.stderr, str(compiler_root),
                    package_version=self.image_package_version)
            except BaseException:
                pass  # No diagnostic failure may replace the SAME nonzero result.
        diagnostic = (self.phase == "package-install" and role in ("installer-log-cursor", "installer-log-capture")
                      or self.setup_verify and role in ("setup-log-cursor", XCODE_SETUP_LOG_CAPTURE)
                      or self.phase == "candidate-baseline" and role in ("app-absence-log-cursor", "app-absence-log-capture"))
        need(result.returncode == 0 and not (self.app_absence is not None and self.app_absence_module.cut_role_data(self, role))
             or diagnostic and result.returncode == 1
             or self.phase == "package-removal-fixture" and removal_native_result_data(self.removal_case, role, result.returncode)
             or self.app_absence is not None and self.app_absence_module.cut_return_data(self, role, result.returncode),
             "original-nonzero-" + role)
        if self.android_support is not None:
            self.android_support_module.returned(self, role)
        if self.app_absence is not None:
            self.app_absence_module.returned(self, role)
        if self.credential_active is not None:
            self.credential_clock(self.credential_active)
            self.credential_census(self.credential_active)
        return result

    def credential_known(self):
        return (not self.credential_unknown and all(row["returned"] and row["settled"] for row in self.credential_calls))

    def credential_clock(self, context, *, cleanup=False):
        now = time.monotonic_ns()
        need(type(now) is int and context["observed"] <= now < context["endpoint"] - (0 if cleanup else 30_000_000_000),
             "credential-original-deadline")
        context["observed"] = now
        if self.store_signing is not None:
            self.store_signing_module.clock(self, work=not cleanup)
        elif self.android_support is not None:
            self.android_support_module.clock(self, work=not cleanup)
        elif self.phase in PYTHON_PHASES:
            self.python_clock(work=not cleanup)
        elif self.phase in TOOL_SIGNING_PHASES:
            self.tool_clock(work=not cleanup)
        elif self.package_endpoint is not None:
            self.package_clock()
        elif self.phase in FINAL_PACKAGE_PHASES or self.phase in ("prepare-removal-observers", SAME_PACKAGE_PHASE):
            self.notary_clock(work=not cleanup)
        return now

    def credential_new_clock(self):
        now = time.monotonic_ns()
        need(type(now) is int, "credential-original-clock")
        endpoint = now + 240_000_000_000
        if self.store_signing is not None:
            endpoint = self.store_signing_module.credential_endpoint(self)
        elif self.android_support is not None:
            _observed, outer = self.android_support_module.clock(self)
            endpoint = min(endpoint, outer)
        elif self.phase in PYTHON_PHASES:
            _observed, outer = self.python_clock()
            endpoint = min(endpoint, outer)
        elif self.phase in TOOL_SIGNING_PHASES:
            _observed, outer = self.tool_clock()
            endpoint = min(endpoint, outer)
        elif self.package_endpoint is not None:
            self.package_clock()
            endpoint = min(endpoint, self.package_endpoint)
        elif self.phase in FINAL_PACKAGE_PHASES or self.phase in ("prepare-removal-observers", SAME_PACKAGE_PHASE):
            _observed, outer = self.notary_clock()
            endpoint = min(endpoint, outer)
        return {"observed": now, "endpoint": endpoint, "ready": False, "retiring": False, "pending": None,
                "directories": [], "root": None, "created": False, "p12": None, "entries": [], "roles": ()}

    def credential_io(self, context, label, function, *args, **kwargs):
        need(self.credential_known() and context["pending"] is None, "credential-original-unknown")
        self.credential_clock(context, cleanup=context["retiring"])
        context["pending"] = label
        try:
            value = function(*args, **kwargs)
            self.credential_clock(context, cleanup=context["retiring"])
        except BaseException:
            self.credential_unknown = True
            raise
        context["pending"] = None
        return value

    def credential_open(self, context, name, flags, mode=0o600, *, parent=None, directory=False):
        entry = self.register(None, "credential-directory" if directory else "credential-file", "credential-original")
        context["entries"].append(entry)  # Before the original acquisition/result assignment.
        entry["name"], entry["parent_entry"] = name, parent
        entry["fd"] = self.credential_io(context, "open", os.open, name, flags, mode,
                                          **({} if parent is None else {"dir_fd": parent["fd"]}))
        return entry

    def credential_directories_post(self, context):
        for entry in context["directories"]:
            parent = entry["parent_entry"]
            named = os.stat(entry["name"], follow_symlinks=False,
                            **({} if parent is None else {"dir_fd": parent["fd"]}))
            held = os.fstat(entry["fd"])
            value = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
            need(stat.S_ISDIR(held.st_mode) and value(held) == value(named) == entry["identity"],
                 "credential-directory-original")

    def credential_census(self, context):
        """Opaque DBs may be0644: held0700 root, not tool-mode guesses, confines them.

        No special/execute/nonowner-write bits or private DB content reads. The
        one decoded credential file retains its separate exact0600 contract.
        """
        if context["root"] is None:
            return
        def inspect():
            self.credential_directories_post(context)
            root = context["root"]
            names = os.listdir(root["fd"])
            need(len(names) <= 8 and len(names) == len(set(names)) and all(type(name) is str
                 and re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", name) and name not in (".", "..") for name in names),
                 "credential-private-census")
            total = 0
            for name in sorted(names):
                entry = self.register(None, "credential-census-file", "credential-original")
                context["entries"].append(entry)
                entry["fd"] = os.open(name, READ_FLAGS, dir_fd=root["fd"])
                try:
                    info = os.fstat(entry["fd"])
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                         and info.st_gid == os.getgid() and not info.st_mode & 0o7133
                         and (name != "identity.p12" or stat.S_IMODE(info.st_mode) == 0o600)
                         and 0 <= info.st_size <= 16 * 1024 * 1024, "credential-private-file")
                    total += info.st_size
                    need(total <= 16 * 1024 * 1024 and signature(os.fstat(entry["fd"])) == signature(info)
                         == signature(os.stat(name, dir_fd=root["fd"], follow_symlinks=False)), "credential-private-file-post")
                finally:
                    self.close(entry)
                need(entry["closed"], "credential-census-close-unknown")
            self.credential_directories_post(context)
        self.credential_io(context, "census", inspect)

    def credential_call(self, context, role, argv, *, timeout=10):
        self.candidate_removal_quote()
        """The SAME process owner, but no public raw argv/captures/exception text."""
        need(context is self.credential_active and role in CREDENTIAL_ROLES
             and self.credential_known() and context["pending"] is None
             and len(self.credential_calls) < (158 if self.phase == "prepare-removal-observers" else 64) and timeout in (10, 30), "credential-fixed-original")
        if self.phase == "prepare-removal-observers":
            self.removal_credential_records_post()
            need(role == removal_credential_roster_data()[len(self.credential_calls)]
                 and self.removal_credential_reserved == removal_credential_quote_data(),
                 "observer-credential-before-append")
        now = self.credential_clock(context, cleanup=context["retiring"])
        endpoint = context["endpoint"] - (0 if context["retiring"] else 30_000_000_000)
        need(now + (timeout + 3) * 1_000_000_000 < endpoint, "credential-dispatch-reserve")
        self.credential_census(context)
        record = {"role": role, "entered": True, "returned": False, "settled": False, "status": None}
        self.credential_calls.append(record)
        self.removal_credential_records_post()
        environment = self.native_environment()
        environment["HOME"] = "/Users/runner"
        try:
            result = self.owner.run_owned(argv, environ=environment, cwd=self.work, timeout=timeout,
                                          capture=True, text=False, output_limit=16384)
            need(type(result) is subprocess.CompletedProcess and type(result.returncode) is int and -65536 <= result.returncode <= 65535
                 and type(result.args) in (tuple, list) and tuple(result.args) == tuple(argv)
                 and type(result.stdout) is bytes and type(result.stderr) is bytes
                 and len(result.stdout) + len(result.stderr) <= 16384, "credential-original-return")
            need(self.android_support is None and self.store_signing is None or 0 <= result.returncode <= 255, "support-credential-return-unknown")
            record.update(returned=True, settled=True, status=result.returncode)
            self.removal_credential_records_post()
            self.credential_clock(context, cleanup=context["retiring"])
            self.credential_census(context)
        except BaseException:
            self.credential_unknown = True
            raise
        if result.returncode != 0:
            # A normally returned mutator may still have partially changed the
            # database/searchlist. Do not guess its state or delete its names.
            if role in ("create", "settings", "unlock", "import", "partitions", "restrict", "restore", "delete", "producer-adhoc"):
                self.credential_unknown = True
            raise Refused("credential-original-nonzero")
        return result

    def credential_search(self, context, role, *, default=False, expected=None):
        result = self.credential_call(context, role, ["/usr/bin/security",
            "default-keychain" if default else "list-keychains", "-d", "user"])
        try:
            need(not result.stderr, "credential-search-stderr")
            observed = credential_paths(result.stdout, single=default)
            need(expected is None or observed == expected, "credential-search-value-changed")
            return observed
        except BaseException:
            self.credential_unknown = True  # Cannot restore/adopt an unknown list.
            raise

    def credential_sources(self):
        source = self.stager.packaging_signing_data(self.producer_profile, self.service_profile)
        need(self.signing == (source.team, source.leaf_sha1), "credential-profile-identity")
        fields = dict(line.split("=", 1) for line in self.producer_profile.decode("ascii").splitlines())
        certificates = []
        for name, field in (("leaf", "leaf-certificate-sha256"), ("issuer", "issuer-certificate-sha256"), ("root", "root-certificate-sha256")):
            entry = self.source_original("desktop/packaging/macos-install-producer-certificates/" + name + ".der",
                                         "credential-source-" + name, 16384)
            body = self.read(entry)
            need(digest(body) == fields[field], "credential-source-certificate")
            certificates.append(body)
            self.package_sources.append((entry, body))
        need(hashlib.sha1(certificates[0]).hexdigest() == self.signing[1], "credential-source-leaf")
        return tuple(certificates)

    def credential_private_root(self, context, body):
        parts = WORK_PARENT.parts
        need(WORK_PARENT.is_absolute() and self.work.parent == WORK_PARENT,
             "credential-private-parent")
        parent = None
        for part in parts:
            entry = self.credential_open(context, part, READ_FLAGS | os.O_DIRECTORY, parent=parent, directory=True)
            info = os.fstat(entry["fd"])
            need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
                 and (not info.st_mode & 0o022 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                 "credential-ancestor-mode")
            entry["identity"] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
            context["directories"].append(entry)
            self.credential_io(context, "ancestor-post", self.credential_directories_post, context)
            parent = entry
        capacity = self.credential_io(context, "capacity", os.fstatvfs, parent["fd"])
        need(capacity.f_frsize > 0 and capacity.f_bavail * capacity.f_frsize >= 16 * 1024 * 1024 + 32768,
             "credential-private-storage-reserve")
        name = "mrk-macos-signing-private." + os.urandom(16).hex()
        context["path"] = WORK_PARENT / name
        context["parent"] = parent
        self.credential_io(context, "private-mkdir", os.mkdir, name, 0o700, dir_fd=parent["fd"])
        context["created"] = True
        root = self.credential_open(context, name, READ_FLAGS | os.O_DIRECTORY, parent=parent, directory=True)
        info = os.fstat(root["fd"])
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
             and info.st_uid == os.getuid() and info.st_gid == os.getgid(), "credential-root-mode")
        root["identity"] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        context["root"] = root
        context["directories"].append(root)
        self.credential_census(context)
        need(not os.listdir(root["fd"]), "credential-root-exclusive")
        entry = self.credential_open(context, "identity.p12", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     parent=root)
        context["p12"] = entry
        context["body"] = body
        def write():
            offset = 0
            while offset < len(body):
                count = os.write(entry["fd"], body[offset:])
                need(type(count) is int and count > 0, "credential-short-write")
                offset += count
            os.fchmod(entry["fd"], 0o600)
            os.fsync(entry["fd"])
            entry["identity"] = signature(os.fstat(entry["fd"]))
            self.credential_p12_post(context)
        self.credential_io(context, "p12-write-readback", write)

    def credential_p12_post(self, context):
        entry, root, body = context["p12"], context["root"], context["body"]
        self.credential_directories_post(context)
        info = os.fstat(entry["fd"])
        need(signature(info) == entry["identity"] == signature(os.stat("identity.p12", dir_fd=root["fd"], follow_symlinks=False))
             and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
             and info.st_uid == os.getuid() and info.st_gid == os.getgid() and info.st_size == len(body), "credential-p12-original")
        need(os.pread(entry["fd"], len(body) + 1, 0) == body and os.pread(entry["fd"], 1, len(body)) == b""
             and signature(os.fstat(entry["fd"])) == entry["identity"], "credential-p12-readback")
        self.credential_directories_post(context)

    def credential_p12_retire(self, context):
        entry = context["p12"]
        if entry is None:
            return
        self.credential_io(context, "p12-post", self.credential_p12_post, context)
        self.close(entry)
        need(entry["closed"] and not self.errors, "credential-p12-close-unknown")
        def remove():
            self.credential_directories_post(context)
            need(signature(os.stat("identity.p12", dir_fd=context["root"]["fd"], follow_symlinks=False)) == entry["identity"],
                 "credential-p12-after-close")
            os.unlink("identity.p12", dir_fd=context["root"]["fd"])
        self.credential_io(context, "p12-remove", remove)
        context["p12"] = None
        context.pop("body", None)

    @contextlib.contextmanager
    def credential_scope(self, purpose, *, producer=None):
        pairs = {"python": PYTHON_ROLES[:2], "resident-image": ("resident-image-sign", "resident-image-verify-signed"),
                 "helper": ("sign", "verify-signed"), "producer": ("producer-emitter",),
                 "installer": ("final-package-sign",), "observer-program": ("program-sign", "program-verify"), **IMAGE_CREDENTIAL_ROLES,
                 **{phase: (phase, phase + "-verify") for phase in SIGNING_PHASES + TOOL_SIGNING_PHASES},
                 **{role: (role + "-sign", role + "-verify") for role in ("bundletool-aapt2", "bundletool-jna", "agp-aapt2")}}
        if self.store_signing is not None:
            pairs["sign-store-runtime"] = self.store_signing_module.ROLES
        need((purpose == "sign-store-runtime" and self.phase in STORE_SIGNING_PHASES and self.store_signing is not None
              or purpose == "python" and self.phase in PYTHON_PHASES or purpose in ("resident-image", "helper") and self.phase == "prepare"
              or purpose in ("producer", "distribution-image", "observation-image") and self.phase == "package-install"
              or purpose in ("producer", "distribution-image") and self.phase == "package-remove"
              or purpose == "installer" and self.phase in FINAL_PACKAGE_PHASES
              or self.phase == "prepare-removal-observers" and purpose in ("observer-program", "installer", "producer", "distribution-image")
              or purpose in SIGNING_PHASES + TOOL_SIGNING_PHASES and self.phase == purpose
              or self.phase in SUPPORT_PHASES and purpose in ("bundletool-aapt2", "bundletool-jna", "agp-aapt2"))
             and self.credential_active is None and not self.credential_failed and self.credential_known(), "credential-fixed-purpose")
        if self.phase == "python-engineering" or self.phase == "prepare" and self.signing is None:
            yield  # No secret read, directory, keychain or auxiliary call.
            return
        need(self.environment.get("HOME") == "/Users/runner", "credential-user-domain")
        certificates = self.installer_certificates if purpose == "installer" else self.credential_sources()
        if purpose == "installer":
            need(self.installer_selection is not None and type(certificates) is tuple and len(certificates) == 3
                 and self.signing is not None and self.installer_selection["teamId"] == self.signing[0]
                 and self.installer_selection["leafSha1"] != self.signing[1], "installer-credential-source-purpose")
        context = self.credential_new_clock()
        context["purpose"] = purpose
        context["roles"] = pairs[purpose]
        fact = {"purpose": purpose, "searchRestored": False, "defaultUnchanged": False, "retired": False, "closed": False}
        primary, original_list, original_default, expected_list = None, None, None, None
        keychain, password, secret = None, None, None
        keychain_created = False
        try:
            self.credential_active = context  # Inside the whole acquisition/use/unwind guard.
            self.credential_contexts.append(fact)
            if purpose == "installer":
                need(self.phase == "prepare-removal-observers" or not any(name in self.environment for name in CREDENTIAL_VARIABLES), "installer-no-application-secret")
                body, secret = credential_values({old: self.environment.get(new)
                    for old, new in zip(CREDENTIAL_VARIABLES, INSTALLER_CREDENTIAL_VARIABLES)})
            else:
                need(self.phase == "prepare-removal-observers" or not any(name in self.environment for name in INSTALLER_CREDENTIAL_VARIABLES), "application-no-installer-secret")
                body, secret = credential_values(self.environment)
            password = os.urandom(32).hex()
            self.credential_private_root(context, body)
            keychain = str(context["path"] / "identity.keychain-db")
            original_list = self.credential_search(context, "search-before")
            original_default = self.credential_search(context, "default-before", default=True)
            expected_list = original_list
            self.credential_call(context, "create", ["/usr/bin/security", "create-keychain", "-p", password, keychain])
            keychain_created = True
            observed = self.credential_search(context, "search-created")
            if not (observed.count(keychain) <= 1 and tuple(value for value in observed if value != keychain) == original_list):
                self.credential_unknown = True
                raise Refused("credential-created-searchlist")
            expected_list = observed
            # security(1): -u locks after the -t interval in seconds. The fixed
            # Store batch alone needs its original aggregate hard interval;
            # existing short scopes retain240s, and sleep-lock stays enabled.
            lock_interval = str(self.store_signing_module.HARD_SECONDS) if self.store_signing is not None else "240"
            self.credential_call(context, "settings", ["/usr/bin/security", "set-keychain-settings", "-l", "-u", "-t", lock_interval, keychain])
            self.credential_call(context, "unlock", ["/usr/bin/security", "unlock-keychain", "-p", password, keychain])
            if purpose == "producer":
                need(type(producer) is tuple and len(producer) == 3 and re.fullmatch(r"[0-9a-f]{40}", producer[2]),
                     "credential-producer-admission")
                copied, copied_body, code_hash = producer
                need(self.read(copied) == copied_body, "credential-producer-original")
                trusted = str(self.work / self.producer_filename)
                partitions = "apple-tool:,cdhash:" + code_hash
            else:
                need(producer is None, "credential-code-purpose")
                trusted = "/usr/bin/productsign" if purpose == "installer" else "/usr/bin/codesign"
                partitions = "apple-tool:,apple:"
            self.credential_io(context, "p12-import-pre", self.credential_p12_post, context)
            self.credential_call(context, "import", ["/usr/bin/security", "import", str(context["path"] / "identity.p12"),
                "-k", keychain, "-f", "pkcs12", "-P", secret, "-T", trusted, "-T", "/usr/bin/security"])
            if purpose == "producer":
                need(self.read(copied) == copied_body, "credential-producer-import-post")
            self.credential_p12_retire(context)  # No encoded key file exists during the callback.
            secret = None
            self.credential_call(context, "partitions", ["/usr/bin/security", "set-key-partition-list", "-S", partitions,
                                                       "-s", "-k", password, keychain])
            policy = "basic" if purpose == "installer" else "codesigning"
            identities = self.credential_call(context, "identity", ["/usr/bin/security", "find-identity", "-v", "-p", policy, keychain])
            certs = self.credential_call(context, "certificates", ["/usr/bin/security", "find-certificate", "-a", "-p", keychain])
            need(not identities.stderr and not certs.stderr, "credential-private-query-stderr")
            if purpose == "installer":
                installer_identity(identities.stdout, certs.stdout, self.installer_selection, certificates)
                # Exact SOURCE-enrolled DER binds the reviewed Installer role;
                # this is not a live semantic EKU parser. pkgSign requires a
                # different CodeSigning EKU, so use basic for the local anchored
                # crypto/time chain. It proves neither system trust nor revocation.
                # Actual productsign, pkgutil trust/timestamp/chain and Accepted
                # remain mandatory after signing the actual package.
                paths = [str(self.checkout / "desktop/packaging/macos-installer-certificates" / (name + ".der"))
                         for name in ("leaf", "issuer", "root")]
                self.credential_call(context, "installer-chain", ["/usr/bin/security", "verify-cert", "-p", "basic", "-N", "-L",
                    "-c", paths[0], "-c", paths[1], "-r", paths[2]], timeout=30)
            else:
                credential_identity(identities.stdout, certs.stdout, self.signing, certificates)
            self.credential_search(context, "search-admit", expected=expected_list)
            self.credential_call(context, "restrict", ["/usr/bin/security", "list-keychains", "-d", "user", "-s", keychain])
            expected_list = (keychain,)
            self.credential_search(context, "search-restricted", expected=expected_list)
            for entry, data in self.package_sources:
                need(self.read(entry) == data, "credential-source-post")
            maximum = 126 if purpose == "producer" else 96 if purpose in IMAGE_CREDENTIAL_ROLES else 66
            need(self.credential_clock(context) + maximum * 1_000_000_000 < context["endpoint"] - 30_000_000_000,
                 "credential-callback-reserve")
            before = len(self.calls)
            context["ready"] = True
            yield
            context["ready"] = False
            need(tuple(row["role"] for row in self.calls[before:]) == tuple(self.removal_recorded_role(role) for role in context["roles"]), "credential-callback-roster")
            if purpose == "producer":
                need(self.read(copied) == copied_body, "credential-producer-callback-post")
            for entry, data in self.package_sources:
                need(self.read(entry) == data, "credential-source-post")
            self.credential_clock(context)
        except BaseException as error:
            primary = error
        finally:
            context["ready"] = False
            context["retiring"] = True
            try:
                need(self.credential_known() and context["pending"] is None and not self.errors
                     and self.stager_io_pending is None and not self.python_mutation_pending
                     and (not self.signing_mutation_pending or self.store_signing is not None
                          and self.store_signing_module.credential_cleanup_ready(self))
                     and all(row["returned"] and row.get("capturesSettled") is True for row in self.calls),
                     "credential-unwind-original-unknown")
                self.credential_clock(context, cleanup=True)
                if keychain_created:
                    self.credential_census(context)
                    self.credential_search(context, "search-after-callback", expected=expected_list)
                    self.credential_call(context, "restore", ["/usr/bin/security", "list-keychains", "-d", "user", "-s", *original_list])
                    self.credential_search(context, "search-restored", expected=original_list)
                    fact["searchRestored"] = True
                    self.credential_p12_retire(context)
                    self.credential_call(context, "delete", ["/usr/bin/security", "delete-keychain", keychain])
                elif original_list is not None:
                    self.credential_search(context, "search-final", expected=original_list)
                    fact["searchRestored"] = True
                    if original_default is not None:
                        self.credential_search(context, "default-after", default=True, expected=original_default)
                        fact["defaultUnchanged"] = True
                if context["root"] is not None:
                    self.credential_p12_retire(context)
                    self.credential_census(context)
                    need(not os.listdir(context["root"]["fd"]), "credential-private-root-not-empty")
                    self.credential_io(context, "private-rmdir", os.rmdir, context["path"].name,
                                       dir_fd=context["parent"]["fd"])
                    context["directories"].remove(context["root"])
                    context["root"] = None
                    self.credential_io(context, "private-parent-post", self.credential_directories_post, context)
                    try:
                        os.stat(context["path"].name, dir_fd=context["parent"]["fd"], follow_symlinks=False)
                    except FileNotFoundError:
                        fact["retired"] = True
                    else:
                        raise Refused("credential-private-root-remains")
            except BaseException as error:
                self.credential_unknown = True
                self.errors.append({"stage": "credential-unwind", "type": type(error).__name__})
                if primary is None:
                    primary = error
            finally:
                secret = password = None
                context.pop("body", None)
                for entry in reversed(context["entries"]):
                    self.close(entry)  # Known held FDs only, even if a process is unknown.
                fact["closed"] = all(entry["closed"] for entry in context["entries"])
                if not fact["closed"] or context["pending"] is not None:
                    self.credential_unknown = True
                    if primary is None:
                        primary = Refused("credential-close-unknown")
                try:
                    if not self.credential_unknown and original_list is not None:
                        self.credential_search(context, "search-final", expected=original_list)
                        if original_default is not None:
                            self.credential_search(context, "default-after", default=True, expected=original_default)
                            fact["defaultUnchanged"] = True
                    self.credential_clock(context, cleanup=True)
                except BaseException as error:
                    self.credential_unknown = True
                    self.errors.append({"stage": "credential-final-post", "type": type(error).__name__})
                    if primary is None:
                        primary = error
                # Every exit, including BaseException/constructor gaps, latches
                # pending/unknown state before any later command/retirement.
                if context["created"] and not fact["retired"]:
                    self.credential_unknown = True
                self.credential_active = None
        if primary is not None:
            self.credential_failed = True
            raise primary
        need(fact["retired"] and fact["closed"] and fact["searchRestored"] and fact["defaultUnchanged"]
             and self.credential_known(), "credential-finality-incomplete")

    def signing_matcher(self):
        entry = self.source_original("desktop/tools/macos_cpython_orchestrator.py", "signing-content-source", 256 * 1024)
        body = self.read(entry)
        # Existing DATA parser, admitted from the exact held SOURCE before/after
        # loading; not a new native process, signing owner or executable input.
        self.stager_io_pending = "signing-content-source-load"
        matcher = load_data(self.checkout, "macos_cpython_orchestrator.py", "_mrk_credential_signing_content")
        need(self.read(entry) == body, "signing-content-source-post")
        self.stager_io_pending = None
        self.package_sources.append((entry, body))
        return matcher

    def tool_clock(self, *, work=True):
        now = time.monotonic_ns()
        need(self.phase in TOOL_SIGNING_PHASES and type(now) is int and self.tool_started is not None
             and self.tool_observed <= now, "tool-original-clock")
        self.tool_observed = now
        endpoint = self.tool_started + (300 if work else 360) * 1_000_000_000
        need(now < endpoint, "tool-original-deadline")
        return now, endpoint

    def tool_sources(self):
        source = self.source_original(TOOL_NOMINATION, "tool-source-nomination", TOOL_RECEIPT_LIMIT)
        body = self.read(source)
        nomination = tool_nomination_data(body)
        self.package_sources.append((source, body))
        return nomination

    def tool_write(self, parent, name, body, mode, limit):
        self.tool_clock()
        need(self.tool_quote_ready and self.phase in TOOL_SIGNING_PHASES and type(body) is bytes
             and 0 < len(body) <= limit and mode in (0o555, 0o755) and name == TOOL_FIXED[self.tool_purpose][0]
             and self.stager_io_pending is None and not self.errors, "tool-exclusive-copy")
        self.recheck_directory(parent)
        self.stager_io_pending = "tool-exclusive-copy"
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent["fd"])
        entry = self.register(fd, "tool-private-copy", "file", parent["fd"], name)
        entry["parent_entry"] = parent
        offset = 0
        while offset < len(body):
            written = os.write(fd, body[offset:])
            need(type(written) is int and written > 0, "tool-copy-short-write")
            offset += written
        os.fchmod(fd, mode); os.fsync(fd)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
             and info.st_gid == os.getgid() and info.st_size == len(body) and stat.S_IMODE(info.st_mode) == mode,
             "tool-copy-created-original")
        entry["identity"] = signature(info)
        need(self.read(entry) == body, "tool-copy-readback")
        self.tool_clock()
        self.stager_io_pending = None
        return entry

    def tool_roster(self, parent, expected):
        self.tool_clock()
        self.recheck_directory(parent)
        need(self.stager_io_pending is None and not self.errors, "tool-roster-state")
        self.stager_io_pending = "tool-roster"
        row = self.register(None, "tool-roster", "iterator")
        iterator = None
        values = []
        try:
            iterator = os.scandir(parent["fd"])
            row["iterator"] = iterator
            for item in iterator:
                self.tool_clock()
                need(len(values) < len(expected) and item.name in expected and item.name not in values,
                     "tool-capsule-roster")
                values.append(item.name)
            need(sorted(values) == sorted(expected), "tool-capsule-roster")
        finally:
            if iterator is not None:
                iterator.close()  # A raised close leaves pending and this row unclosed.
                row["closed"] = True
                row["iterator"] = None
        self.recheck_directory(parent)
        self.tool_clock()
        self.stager_io_pending = None

    def tool_prepare(self):
        purpose = self.tool_purpose
        name, identifier, limit = TOOL_FIXED[purpose]
        nomination = self.tool_sources()
        build = nomination["tools"][purpose][self.target]["build"]
        need(build["state"] == "configured" and self.signing is not None, "tool-build-unconfigured")
        # Closed metadata/receipt first, before binary accumulation or mutation.
        transport = self.directory(self.work_entry, "tool-transport", "tool-transport")
        self.tool_roster(transport, (name, "tool-build-receipt.json"))
        receipt = self.original(transport, "tool-build-receipt.json", "tool-build-receipt", TOOL_RECEIPT_LIMIT, (0o400, 0o600, 0o644))
        receipt_body = self.read(receipt)
        tool_build_receipt(receipt_body, build, purpose, self.target)
        raw = self.original(transport, name, "tool-raw-original", limit, (0o400, 0o555, 0o600, 0o644, 0o755))
        need(raw["identity"][6] == build["binaryBytes"], "tool-raw-size")
        owned, scratch = tool_quote(purpose)
        capacity = os.fstatvfs(self.work_entry["fd"])
        need(capacity.f_frsize > 0 and capacity.f_bavail * capacity.f_frsize >= scratch, "tool-scratch-reserve")
        self.tool_quote_ready = True
        self.receipt["toolOwnedDataReserveBytes"] = owned
        self.receipt["toolScratchReserveBytes"] = scratch
        original = self.read(raw)
        need(digest(original) == build["binarySha256"], "tool-raw-anchor")
        matcher = self.signing_matcher()
        tool_loader(original, purpose, self.target, self.stager, matcher)
        entitlements = self.source_original("desktop/packaging/macos-empty-entitlements.plist", "tool-empty-entitlements", 1024)
        empty = self.read(entitlements)
        need(digest(empty) == self.stager.SIGNED_ENTITLEMENTS_SHA256, "tool-empty-profile")
        self.package_sources.append((entitlements, empty))
        old = self.tool_write(self.target_entry, name, original, 0o755, limit)
        path = self.work / self.target_name / name
        sign, verify = tool_sign_arguments(path, self.checkout / "desktop/packaging/macos-empty-entitlements.plist", purpose, self.signing)
        with self.credential_scope(self.phase):
            self.stage = self.phase
            self.signing_mutation_pending = True
            self.call(self.phase, sign, self.native_environment(), cwd=self.work, timeout=30, limit=65536)
            self.recheck_directory(self.target_entry)
            signed = self.original(self.target_entry, name, "tool-signed-original", limit, (0o755,))
            body = self.read(signed)
            matcher.macho_content_valid(original, body, self.arch, signing=True)
            tool_loader(body, purpose, self.target, self.stager, matcher)
            self.close(old)
            need(old["closed"] and not self.errors, "tool-input-close-unknown")
            self.signing_mutation_pending = False
            result = self.call(self.phase + "-verify", verify, self.native_environment(), cwd=self.work, timeout=30, limit=65536)
            need(not result.stdout and not result.stderr and self.read(signed) == body, "tool-strict-verification-post")
            self.tool_clock()
            self.signing_mutation_pending = True
            os.fchmod(signed["fd"], 0o555)
            signed["identity"] = signature(os.fstat(signed["fd"]))
            need(stat.S_IMODE(signed["identity"][2]) == 0o555 and self.read(signed) == body, "tool-signed-mode-post")
            self.signing_mutation_pending = False
        need(self.read(raw) == original and self.read(receipt) == receipt_body, "tool-original-build-post")
        for entry, data in self.package_sources:
            need(self.read(entry) == data, "tool-source-post")
        self.tool_roster(transport, (name, "tool-build-receipt.json"))
        self.tool_clock()
        self.tool_write(self.work_entry, name, body, 0o555, limit)
        need(self.read(signed) == body and self.read(raw) == original, "tool-published-original-post")
        self.sha256 = digest(body)
        self.receipt["tool"] = {"purpose": purpose, "buildSha256": digest(tool_canonical(build)),
            "sourceManifestSha256": build["sourceManifestSha256"], "rawSha256": build["binarySha256"],
            "rawBytes": len(original), "signedSha256": self.sha256, "signedBytes": len(body), "notices": build["notices"],
            "identifier": identifier, "producerProfileSha256": digest(self.producer_profile),
            "serviceProfileSha256": digest(self.service_profile), "entitlementsSha256": digest(empty)}
        self.tool_complete = True
        self.tool_clock()

    def tool_staged_inputs(self):
        """Additional fixed originals only when SOURCE actually nominates them."""
        need(self.phase in ("verify-before", "verify-after"), "tool-staged-purpose")
        selection, source = tool_selected(self.stager, self.target, checkout=self.checkout)
        # Four copies of each admitted tool plus the existing bounded helper,
        # image/control working set. No runtime/child execution, no RSS claim.
        need(sum(4 * TOOL_FIXED[p][2] for p, row in selection.items() if row is not None)
             + 128 * 1024 * 1024 <= 1024 * 1024 * 1024, "tool-staged-owned-data-quote")
        values = []
        for purpose in TOOL_FIXED:
            row = selection[purpose]
            if row is None:
                continue
            name, identifier, limit = TOOL_FIXED[purpose]
            path = ("runtime/tools/gh" if purpose == "history-provider" else
                    "app/Mobile Release Kit.app/" + self.stager.GITHUB_SEAL)
            parent = self.descend(self.work_entry, tuple(path.split("/")[:-1]))
            original = self.original(parent, name, "tool-staged-" + purpose, limit, (0o555,))
            body = self.read(original)
            need(digest(body) == row["signed"]["signedSha256"] and len(body) == row["signed"]["signedBytes"],
                 "tool-staged-signed-original")
            capsule = self.directory(self.work_entry, purpose + "-capsule", "tool-staged-capsule")
            receipt = self.original(capsule, "tool-signed-receipt.json", "tool-staged-signed-receipt", TOOL_RECEIPT_LIMIT, (0o444,))
            receipt_body = self.read(receipt)
            tool_signed_receipt(receipt_body, row, purpose, self.target, source[1][0], source[2][0], source[3][0])
            tool_loader(body, purpose, self.target, self.stager, self.signing_matcher())
            values.append((purpose, original, body, self.work / path, receipt, receipt_body))
        self.tool_staged_roles = tuple(self.phase + "-" + row[0] for row in values)
        return values, selection, source

    def tool_staged_post(self, captured):
        values, selection, source = captured
        for purpose, original, body, path, receipt, receipt_body in values:
            need(self.signing is not None, "tool-staged-configured-signing")
            result = self.call(self.phase + "-" + purpose, ["/usr/bin/codesign", "--verify", "--strict", "-R",
                "=" + signing_requirement(self.signing, TOOL_FIXED[purpose][1]), str(path)],
                self.native_environment(), cwd=self.work, timeout=30, limit=65536)
            need(not result.stdout and not result.stderr and self.read(original) == body
                 and self.read(receipt) == receipt_body, "tool-staged-native-post")
        need(tool_selected(self.stager, self.target, checkout=self.checkout) == (selection, source), "tool-staged-source-post")

    def fixed_sign(self):
        """Fixed workflow roles, never a user-selected path/argv."""
        need(self.phase in SIGNING_PHASES and self.signing is not None, "fixed-signing-purpose")
        base = "app/Mobile Release Kit.app"
        payload = base + "/Contents/Helpers/MobileReleaseKitPayload.app"
        selected = {
            "sign-vault-helper": "vault-helper-target/" + self.target + "/release/mrk-vault-keychain",
            "sign-installed-cli": "installed-cli-target/" + self.target + "/release/mrk",
            "sign-desktop-image": payload + "/Contents/Frameworks/libmrk_desktop_image.dylib",
            "sign-desktop-payload": payload,
            "sign-root-app": base,
            "sign-root-installer": "cargo-target/" + self.target + "/release/mrk-macos-install",
            "sign-remover": "remover-target/" + self.target + "/release/mrk-macos-remove",
            "sign-applications-launcher": "applications-launcher/MobileReleaseKitLauncher.app",
            "sign-xcode-setup": "xcode-setup-target/" + self.target + "/release/mrk-macos-xcode-setup",
        }[self.phase]
        if self.phase == "sign-desktop-image":
            need(self.environment.get("MRK_MACOS_PACKAGE_ROLE") == "ordinary-image", "fixed-desktop-image-role")
        if self.phase == "sign-root-installer":
            need(self.environment.get("CARGO_TARGET_DIR") == str(self.work / "cargo-target"), "fixed-installer-target")
        if self.phase == "sign-xcode-setup":
            need(self.environment.get("CARGO_TARGET_DIR") == str(self.work / "xcode-setup-target")
                 and self.environment.get("MRK_MACOS_PACKAGE_ROLE") == "ordinary-image", "fixed-setup-target")
        path = self.work / selected
        launcher = self.phase == "sign-applications-launcher"
        if launcher:
            need(self.environment.get("MRK_MACOS_PACKAGE_ROLE") == "ordinary-image", "fixed-launcher-role")
            unsigned = self.stager.tree(path, max_bytes=4 * 1024 * 1024)
            need(set(unsigned) == {"Contents/Info.plist", "Contents/Resources/icon.png", "Contents/MacOS/mrk-macos-launcher"},
                 "fixed-launcher-unsigned-roster")
            for name, source_path, maximum in (
                    ("Contents/Info.plist", "desktop/native/macos-applications-launcher/Info.plist", 16384),
                    ("Contents/Resources/icon.png", "desktop/src-tauri/icons/icon.png", 1024 * 1024)):
                source = self.source_original(source_path, "fixed-launcher-source", maximum)
                source_body = self.read(source)
                need(unsigned[name][0] == source_body, "fixed-launcher-source-correspondence")
                self.package_sources.append((source, source_body))
        bundled = self.phase in ("sign-desktop-payload", "sign-root-app", "sign-applications-launcher")
        root = self.descend(self.work_entry, tuple(selected.split("/"))) if bundled else None
        binary_name = ("mrk-macos-launcher" if launcher else "mobile-release-kit-desktop" if self.phase == "sign-desktop-payload" else ENTRY)
        binary = selected + "/Contents/MacOS/" + binary_name if bundled else selected
        parent = self.descend(self.work_entry, tuple(binary.split("/")[:-1]))
        old = self.original(parent, binary.split("/")[-1], "fixed-sign-input", 64 * 1024 * 1024, (0o555, 0o700, 0o755), alias=not bundled)
        original = self.read(old)
        if self.phase == "sign-desktop-image":
            self.stager.image_macho(original, "desktop", target=self.target)
        else:
            self.stager.macho(original, system_only=True, target=self.target)
        matcher = self.signing_matcher()
        entitlements = self.source_original("desktop/packaging/macos-empty-entitlements.plist", "fixed-sign-empty-entitlements", 1024)
        empty = self.read(entitlements)
        need(digest(empty) == self.stager.SIGNED_ENTITLEMENTS_SHA256, "fixed-sign-empty-profile")
        self.package_sources.append((entitlements, empty))
        arguments = ["--options", "runtime", "--entitlements",
            str(self.checkout / "desktop/packaging/macos-empty-entitlements.plist")]
        identifier = (INSTALLED_CLI_IDENTIFIER if self.phase == "sign-installed-cli" else
                      XCODE_SETUP_IDENTIFIER if self.phase == "sign-xcode-setup" else LAUNCHER_IDENTIFIER if launcher else "dev.mobile-release-kit.desktop.remove"
                      if self.phase == "sign-remover" else None)
        if identifier is not None:
            arguments += ["--identifier", identifier]
        verify_arguments = (["-R", "=" + signing_requirement(self.signing, identifier)] if identifier is not None else [])
        with self.credential_scope(self.phase):
            self.stage = self.phase
            self.signing_mutation_pending = True
            self.call(self.phase, ["/usr/bin/codesign", "--force", "--sign", self.signing[1], *arguments, "--timestamp", str(path)],
                      self.native_environment(), cwd=self.work, timeout=30, limit=65536)
            if root is not None:
                self.recheck_directory(root)
            self.recheck_directory(parent)
            signed = self.original(parent, binary.split("/")[-1], "fixed-sign-output", 64 * 1024 * 1024,
                                   (0o555, 0o700, 0o755), alias=not bundled)
            body = self.read(signed)
            matcher.macho_content_valid(original, body, self.arch, signing=True)
            self.close(old)
            need(old["closed"] and not self.errors, "fixed-sign-input-close-unknown")
            self.signing_mutation_pending = False
            verified = self.call(self.phase + "-verify", ["/usr/bin/codesign", "--verify", "--strict", *verify_arguments, str(path)],
                                 self.native_environment(), cwd=self.work, timeout=30, limit=65536)
            need(not verified.stdout and not verified.stderr and self.read(signed) == body, "fixed-sign-original-verification")
            if root is not None:
                self.recheck_directory(root)
        if self.phase == "sign-xcode-setup":
            before = signed["identity"]
            os.fchmod(signed["fd"], 0o555)
            os.fsync(signed["fd"])
            after = signature(os.fstat(signed["fd"]))
            need(after[:2] == before[:2] and after[2] == stat.S_IFREG | 0o555 and after[3:8] == before[3:8],
                 "setup-signed-mode-original")
            signed["identity"] = after
            need(self.read(signed) == body, "setup-signed-mode-post")
        self.sha256 = digest(body)
        if launcher:
            # The same signed source bundle is copied into the outer app. No
            # extra files, alternate plist/icon or existing ticket are adopted.
            self.stager.applications_launcher_files(argparse.Namespace(target=self.target, package_role="ordinary-image",
                applications_launcher=path, expected_applications_launcher=self.sha256))
        self.fixed_sign_complete = True
        self.receipt.update(fixedSigningRole=self.phase, signedBytesSha256=self.sha256,
                            signingAuthority="unchanged-source-identity-native-verification-still-required")

    def producer_signing_copy(self, executable, executable_body):
        """Give only the final compiler-derived copy an exact ad-hoc CDHash ACL."""
        self.publish(self.producer_filename, executable_body, mode=0o755)
        need(self.read(executable) == executable_body, "producer-compiler-copy-post")
        old = self.original(self.work_entry, self.producer_filename, "producer-unsigned-copy", 64 * 1024 * 1024, (0o755,))
        need(self.read(old) == executable_body, "producer-copy-original")
        matcher = self.signing_matcher()
        context = self.credential_new_clock()
        need(self.credential_active is None and self.credential_known() and not self.credential_failed, "producer-seal-finality")
        primary = None
        try:
            self.credential_active = context
            self.stage = "producer-private-copy-sealing"
            self.signing_mutation_pending = True
            self.credential_call(context, "producer-adhoc", ["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
                                 str(self.work / self.producer_filename)], timeout=30)
            copied = self.original(self.work_entry, self.producer_filename, "producer-sealed-copy", 64 * 1024 * 1024, (0o755,))
            body = self.read(copied)
            matcher.macho_content_valid(executable_body, body, self.arch, signing=True)
            self.close(old)
            need(old["closed"] and not self.errors, "producer-copy-close-unknown")
            self.signing_mutation_pending = False
            verified = self.credential_call(context, "producer-adhoc-verify", ["/usr/bin/codesign", "--verify", "--strict",
                str(self.work / self.producer_filename)], timeout=30)
            need(not verified.stdout and not verified.stderr, "producer-seal-verification")
            display = self.credential_call(context, "producer-cdhash", ["/usr/bin/codesign", "--display", "--verbose=4",
                str(self.work / self.producer_filename)], timeout=30)
            need(not display.stdout and self.read(copied) == body and self.read(executable) == executable_body,
                 "producer-seal-post")
            code_hash = credential_cdhash(display.stderr)
            self.signing_mutation_pending = True
            os.fchmod(copied["fd"], 0o555)
            copied["identity"] = signature(os.fstat(copied["fd"]))
            need(stat.S_IMODE(copied["identity"][2]) == 0o555 and self.read(copied) == body, "producer-final-seal-original")
            self.signing_mutation_pending = False
            self.credential_clock(context)
        except BaseException as error:
            primary = error
            self.credential_failed = True
            if self.signing_mutation_pending or not self.credential_known():
                self.credential_unknown = True
        finally:
            self.credential_active = None
        if primary is not None:
            raise primary
        self.package_outputs.append((copied, digest(body)))
        self.package_post()
        return copied, body, code_hash

    def notary_clock(self, *, work=True):
        now = time.monotonic_ns()
        need(type(now) is int and type(self.notary_started) is int
             and self.notary_started <= self.notary_observed <= now, "notary-monotonic-clock")
        self.notary_observed = now
        endpoint = self.notary_started + (1740 if work else 1800) * 1_000_000_000
        need(now < endpoint, "notary-group-deadline")
        return now, endpoint

    def notary_known(self):
        return (not self.errors and not self.notary_unknown and not self.notary_mutation_pending
                and self.stager_io_pending is None and self.credential_known() and not self.credential_failed
                and self.credential_active is None and not self.signing_mutation_pending
                and all(row.get("returned") is True and row.get("capturesSettled") is True for row in self.calls))

    def notary_space(self, *, reserve=False):
        self.recheck_directory(self.work_entry)
        volume = os.fstatvfs(self.work_entry["fd"])
        need(type(volume.f_frsize) is int and 0 < volume.f_frsize <= 1024 * 1024
             and type(volume.f_bavail) is int and volume.f_bavail >= 0
             and volume.f_bavail * volume.f_frsize >= NOTARY_FREE_FLOOR + (NOTARY_STORAGE_RESERVE if reserve else 0),
             "notary-work-volume-reserve")

    def notary_io(self, label, function, *args, **kwargs):
        self.notary_clock()
        need(self.notary_known() and not self.notary_retiring, "notary-io-unknown")
        self.stage = label
        self.stager_io_pending = label
        result = function(*args, **kwargs)
        self.notary_clock()
        self.stager_io_pending = None  # Only actual normal return proves its internal closes.
        return result

    def notary_snapshot(self, root, path, *, work=True):
        """Identity supplement to the actual stager tree, with bounded live FDs.

        The existing tree supplies file/path/byte policy. This walk binds those
        same bytes to original identities and records even empty directories;
        at most one depth16 chain and one leaf are live, not2048 retained FDs.
        """
        self.notary_clock(work=work)
        self.recheck_directory(root)
        self.stager_io_pending = "notary-stager-tree"
        store_prefix = None
        if getattr(self, "composed_runtime", False):
            if path == self.work / "runtime":
                store_prefix = "store"
            elif path in (self.work / "input", self.work / self.target_name / "payload-input"):
                store_prefix = "runtime/store"
        if (getattr(self, "package_store_runtime", False) and not self.removal
                and path == self.work / "scripts"):
            store_prefix = "input/runtime/store"
        tree_bounds = {}
        if self.setup_package:
            scripts = path in (self.setup_package_paths() / "scripts-original", self.setup_package_paths() / "scripts-final")
            need(scripts or path in (self.setup_package_paths() / "carrier", self.work / self.target_name / "product-input"),
                 "setup-snapshot-fixed-root")
            tree_bounds["max_bytes"] = self.stager.XCODE_SETUP_PROGRAM_LIMIT + 32768 if scripts else 65536
        files = self.stager.tree(path, mac_store_prefix=store_prefix, **tree_bounds)
        self.stager_io_pending = None
        self.notary_clock(work=work)
        result = {"directories": {}, "files": {}}
        observed, nodes = set(), [0]
        def visit(parent, prefix, depth):
            self.notary_clock(work=work)
            need(depth <= 16 + (len(store_prefix.split("/")) if store_prefix else 0), "notary-original-depth")
            self.recheck_directory(parent)
            names = sorted(os.listdir(parent["fd"]))
            nodes[0] += len(names)
            need(nodes[0] <= (self.stager.MAX_ENTRIES if store_prefix else 4096),
                 "notary-original-node-bound")
            result["directories"][prefix] = (parent["identity"], tuple(names))
            for name in names:
                relative = name if not prefix else prefix + "/" + name
                need(self.stager.safe_path(relative, mac_store_prefix=store_prefix), "notary-original-path")
                before = os.stat(name, dir_fd=parent["fd"], follow_symlinks=False)
                entry = None
                try:
                    fd = os.open(name, READ_FLAGS | (os.O_DIRECTORY if stat.S_ISDIR(before.st_mode) else 0), dir_fd=parent["fd"])
                    entry = self.register(fd, "notary-original", "directory" if stat.S_ISDIR(before.st_mode) else "file", parent["fd"], name)
                    entry["parent_entry"] = parent
                    opened = os.fstat(fd)
                    need(signature(opened) == signature(before), "notary-original-open-changed")
                    if stat.S_ISDIR(before.st_mode):
                        entry["identity"] = directory_identity(opened)
                        self.stager.no_xattrs(fd)
                        visit(entry, relative, depth + 1)
                    else:
                        need(relative in files and stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                             and (opened.st_uid, opened.st_gid) == (os.getuid(), os.getgid())
                             and 0 <= opened.st_size <= self.stager.MAX_BYTES, "notary-original-file")
                        entry["identity"] = signature(opened)
                        self.stager.no_xattrs(fd)
                        body = self.read(entry)
                        need(files[relative] == (body, stat.S_IMODE(opened.st_mode)), "notary-stager-original-correspondence")
                        result["files"][relative] = (entry["identity"], digest(body))
                        observed.add(relative)
                finally:
                    if entry is not None:
                        self.close(entry)
                need(not self.errors, "notary-original-close-unknown")
            self.recheck_directory(parent)
            need(sorted(os.listdir(parent["fd"])) == names, "notary-original-directory-post")
        visit(root, "", 0)
        need(observed == set(files), "notary-stager-original-roster")
        self.recheck_directory(root)
        self.notary_clock(work=work)
        return result

    def final_image_verify_identity_stage(self, entry, observed, boundary):
        # Removal has a different fourteen-input schema; only ordinary finalization
        # may use these fixed ordinals. Every check here is diagnostic-only.
        if self.phase != "finalize-image" or self.stage != "final-image-verify":
            return
        if (type(entry) is not dict or self.entry_registry.get(id(entry)) is not entry
                or entry.get("closed") is not False or type(entry.get("fd")) is not int
                or type(boundary) is not str or boundary not in ("held", "named")):
            return
        before = entry.get("identity")
        if (type(before) is not tuple or type(observed) is not tuple
                or len(before) != 9 or len(observed) != 9
                or any(type(value) is not int for value in (*before, *observed))):
            return
        inputs = self.final_image_inputs
        if (type(inputs) is not list or len(inputs) != 14
                or any(type(row) is not tuple or len(row) != 2 or type(row[0]) is not dict
                       or self.entry_registry.get(id(row[0])) is not row[0] for row in inputs)):
            return
        object_label = "output" if entry is self.final_image_output else None
        if object_label is None:
            matches = [index for index, row in enumerate(inputs) if row[0] is entry]
            if len(matches) != 1:
                return
            object_label = FINAL_IMAGE_VERIFY_OBJECTS[matches[0] + 1]
        for index, field in enumerate(FINAL_IMAGE_VERIFY_FIELDS):
            if before[index] != observed[index]:
                self.stage = "final-image-verify-%s-%s-%s" % (object_label, boundary, field)
                return

    def notary_stream(self, entry, *, work=True):
        self.notary_clock(work=work)
        self.recheck_directory(entry["parent_entry"])
        held = signature(os.fstat(entry["fd"]))
        if not held == entry["identity"]:
            try:
                self.final_image_verify_identity_stage(entry, held, "held")
            except BaseException:
                pass  # Attribution never replaces this original identity refusal.
            need(False, "notary-zip-original")
        named = signature(os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False))
        if not entry["identity"] == named:
            try:
                self.final_image_verify_identity_stage(entry, named, "named")
            except BaseException:
                pass  # No raw values and no fallible diagnostic replaces the original.
            need(False, "notary-zip-original")
        self.stager.no_xattrs(entry["fd"])
        digestor, count = hashlib.sha256(), 0
        while count < entry["identity"][6]:
            self.notary_clock(work=work)
            body = os.pread(entry["fd"], min(1024 * 1024, entry["identity"][6] - count), count)
            need(body, "notary-zip-short-read")
            digestor.update(body); count += len(body)
        need(os.pread(entry["fd"], 1, count) == b"" and signature(os.fstat(entry["fd"])) == entry["identity"]
             == signature(os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False)), "notary-zip-post")
        self.recheck_directory(entry["parent_entry"])
        return digestor.hexdigest()

    def notary_tool(self, name):
        prefix_tool = self.setup_package and name in ("pkgbuild", "lsbom", "tar", "xar")
        system_tool = name == "productbuild" or prefix_tool
        need(name in ("notarytool", "stapler", "productbuild") or prefix_tool, "notary-fixed-tool")
        need(name != "productbuild" or self.phase in ("finalize-package", "finalize-xcode-setup-package") and self.install_product,
             "install-product-fixed-tool")
        if prefix_tool:
            self.stage = "setup-tool-" + name
        # Apple's tar entry is a symlink. Keep exact physical-tool admission,
        # selecting only its fixed bsdtar executable for this existing setup role.
        fixed_name = "bsdtar" if prefix_tool and name == "tar" else name
        fixed = Path("/usr/bin") / fixed_name if system_tool else NOTARY_XCODE / "usr/bin" / name
        canonical = fixed.resolve(strict=True)
        applications = NOTARY_XCODE.parents[2]
        need(canonical == fixed if system_tool else
             canonical.is_absolute() and len(canonical.parts) <= 16
             and applications.resolve(strict=True) in canonical.parents, "notary-selected-tool-path")
        # Both the fixed Xcode.app alias and its independently resolved chain
        # are originals. xcrun output cannot choose a different tool or root.
        paths = {fixed, canonical, *fixed.parents, *canonical.parents}
        originals = []
        for path in sorted(paths, key=lambda item: (len(item.parts), str(item))):
            info = path.lstat()
            selected_alias = stat.S_ISLNK(info.st_mode) and path == NOTARY_XCODE.parent.parent
            above_applications = path in applications.parents
            # Existing macOS directory trust, confined to this exact fixed ancestor.
            trusted_applications_group = (path == applications and stat.S_ISDIR(info.st_mode)
                and info.st_uid == 0 and info.st_gid in (0, 80) and not info.st_mode & 0o002)
            need((info.st_uid == 0 and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                  and not info.st_mode & 0o022) if system_tool else
                 info.st_uid in (0, os.getuid())
                 and (selected_alias or (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                      and (above_applications or not info.st_mode & 0o022 or trusted_applications_group)),
                 "notary-selected-tool-ancestry")
            originals.append((path, signature(info), os.readlink(path) if stat.S_ISLNK(info.st_mode) else None))
        fd = os.open(canonical, READ_FLAGS)
        entry = self.register(fd, "notary-system-tool", "notary-system-tool")
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 64 * 1024 * 1024
             and info.st_mode & 0o111 and not info.st_mode & 0o022 and info.st_uid in (0, os.getuid())
             and signature(info) == signature(canonical.lstat()), "notary-selected-tool-original")
        entry["identity"] = signature(info)
        value = {"fixed": fixed, "path": canonical, "entry": entry, "ancestors": originals}
        self.notary_tools[name] = value
        self.notary_tool_post(value)
        return value

    def notary_tool_post(self, tool):
        for path, identity, link in tool["ancestors"]:
            need(signature(path.lstat()) == identity and (link is None or os.readlink(path) == link),
                 "notary-selected-tool-changed")
        need(tool["fixed"].resolve(strict=True) == tool["path"]
             and signature(os.fstat(tool["entry"]["fd"])) == tool["entry"]["identity"]
             == signature(tool["path"].lstat()), "notary-selected-tool-changed")

    def notary_post(self, *, work=True):
        self.notary_clock(work=work)
        need(not self.errors and self.stager_io_pending is None, "notary-post-unknown")
        self.candidate_removal_post()
        for entry, body in self.package_sources:
            need(self.read(entry) == body, "notary-source-post")
        for item in self.notary_roots:
            need(self.notary_snapshot(item["entry"], item["path"], work=work) == item["snapshot"], "notary-payload-post")
        if self.notary_copy is not None:
            item = self.notary_copy
            need(self.notary_snapshot(item["entry"], item["path"], work=work) == item["snapshot"], "notary-copy-post")
        if self.notary_zip is not None:
            need(self.notary_stream(self.notary_zip, work=work) == self.notary_zip_sha, "notary-zip-sha256-changed")
        for tool in self.notary_tools.values():
            self.notary_tool_post(tool)
        if self.notary_key is not None:
            key = self.notary_key
            self.recheck_directory(key["root"])
            need(os.listdir(key["root"]["fd"]) == [key["name"]]
                 and self.read(key["entry"]) == key["body"], "notary-key-original-changed")
        if self.removal_final_active():
            self.final_package_post(work=work)
        if self.phase in FINAL_IMAGE_PHASES:
            self.final_image_post(work=work)
        if work:
            self.notary_space()
        self.notary_clock(work=work)

    def notary_call(self, role, argv, *, maximum=30, limit=65536, developer=False):
        roles = notary_roles(getattr(self, "notary_launcher", False))
        need(self.notary_known() and not self.notary_retiring and len(self.calls) < len(roles)
             and roles[len(self.calls)] == role, "notary-fixed-role-order")
        self.notary_post()
        now, endpoint = self.notary_clock()
        need(type(maximum) is int and 0 < maximum <= 1200, "notary-child-timeout")
        timeout = min(maximum, (endpoint - now - 3_000_000_000) // 1_000_000_000)
        need(timeout >= 1, "notary-child-settlement-reserve")
        need((self.notary_key is not None) == (role in ("payload-submit", "payload-log")), "notary-key-role")
        environment = self.native_environment()
        if developer:
            environment["DEVELOPER_DIR"] = str(NOTARY_XCODE)
        self.stage = role
        changing = role in ("staple-inner", "staple-outer", "staple-launcher")
        self.notary_mutation_pending = changing
        try:
            result = self.call(role, argv, environment, cwd=self.work, timeout=timeout, limit=limit)
        except BaseException:
            if not changing and self.notary_known():
                try:
                    self.notary_post()
                except BaseException as post_error:
                    self.notary_unknown = True
                    self.errors.append({"stage": "notary-failed-original-post", "type": type(post_error).__name__})
            raise
        self.notary_clock()
        if changing:
            app = self.notary_roots[0]
            actual = self.notary_snapshot(app["entry"], app["path"])
            previous = app["snapshot"]
            added = (LAUNCHER_TICKET if role == "staple-launcher" else
                     NOTARY_TICKETS[1] if role == "staple-inner" else NOTARY_TICKETS[0])
            need(set(actual["files"]) == set(previous["files"]) | {added}
                 and added not in previous["files"] and set(actual["directories"]) == set(previous["directories"]),
                 "notary-ticket-only-addition")
            for name, row in previous["files"].items():
                need(actual["files"][name] == row, "notary-existing-file-changed")
            parent, leaf = added.rsplit("/", 1)
            for name, (identity, names) in previous["directories"].items():
                expected_names = tuple(sorted((*names, leaf))) if name == parent else names
                need(actual["directories"][name] == (identity, expected_names), "notary-existing-directory-changed")
            info, sha = actual["files"][added]
            need(0 < info[6] <= 1024 * 1024 and not stat.S_IMODE(info[2]) & 0o7133, "notary-ticket-shape")
            self.notary_ticket_rows.append({"path": added, "bytes": info[6], "sha256": sha})
            app["snapshot"] = actual
            self.notary_mutation_pending = False
        self.notary_post()
        return result

    def notary_rename_copy(self):
        item = self.notary_copy
        root = item["entry"]
        child = self.directory(root, "app", "notary-copy-app")
        root_identity, child_identity = root["identity"], child["identity"]
        need(stat.S_IMODE(root_identity[2]) == stat.S_IMODE(child_identity[2]) == 0o555, "notary-copy-sealed-directories")
        self.notary_mutation_pending = True
        primary = None
        try:
            self.recheck_directory(root); self.recheck_directory(child)
            os.fchmod(root["fd"], 0o755)
            root["identity"] = directory_identity(os.fstat(root["fd"]))
            need(root["identity"] == (*root_identity[:2], stat.S_IFDIR | 0o755, *root_identity[3:]), "notary-copy-parent-mode")
            self.recheck_directory(root)
            os.rename("app", NOTARY_APP_NAME, src_dir_fd=root["fd"], dst_dir_fd=root["fd"])
            need(directory_identity(os.fstat(child["fd"])) == child_identity
                 == directory_identity(os.stat(NOTARY_APP_NAME, dir_fd=root["fd"], follow_symlinks=False)), "notary-copy-rename-original")
            del self.directories[(id(root), "app")]
            child["name"] = NOTARY_APP_NAME
            self.directories[(id(root), NOTARY_APP_NAME)] = child
        except BaseException as error:
            primary = error
        finally:
            try:
                now = os.fstat(root["fd"])
                need((now.st_dev, now.st_ino, now.st_uid, now.st_gid)
                     == (root_identity[0], root_identity[1], root_identity[3], root_identity[4]), "notary-copy-parent-original")
                os.fchmod(root["fd"], 0o555)
                root["identity"] = directory_identity(os.fstat(root["fd"]))
                need(root["identity"] == root_identity, "notary-copy-parent-restore")
                self.recheck_directory(root)
            except BaseException as error:
                self.notary_unknown = True
                self.errors.append({"stage": "notary-copy-parent-restore", "type": type(error).__name__})
                if primary is None:
                    primary = error
        if primary is not None:
            if not self.notary_unknown and not self.errors:
                try:
                    # A synchronous refusal before rename may leave the exact
                    # original copy intact. Only that proven old state permits
                    # known-only cleanup; an unknown/lost return is not success.
                    need(self.notary_snapshot(root, item["path"]) == item["snapshot"], "notary-copy-failed-rename-post")
                    self.recheck_directory(child)
                    self.notary_mutation_pending = False
                except BaseException as error:
                    self.notary_unknown = True
                    self.errors.append({"stage": "notary-copy-failed-rename-post", "type": type(error).__name__})
            raise primary
        def renamed(name):
            return NOTARY_APP_NAME + name[3:] if name == "app" or name.startswith("app/") else name
        expected = {"files": {renamed(name): row for name, row in item["snapshot"]["files"].items()}, "directories": {}}
        for name, (identity, names) in item["snapshot"]["directories"].items():
            expected["directories"][renamed(name)] = (identity, tuple(sorted(NOTARY_APP_NAME if part == "app" else part for part in names)) if name == "" else names)
        need(self.notary_snapshot(root, item["path"]) == expected, "notary-copy-rename-post")
        item["snapshot"] = expected
        self.notary_mutation_pending = False
        self.notary_post()

    @contextlib.contextmanager
    def notary_key_scope(self):
        package_prefix = None
        if self.removal_final_active():
            roles = final_package_roles(self.removal, self.environment["MRK_MACOS_PACKAGE_ROLE"], setup=self.setup_package)
            package_prefix = roles[:roles.index("final-package-submit")]
        payload_roles = notary_roles(getattr(self, "notary_launcher", False))
        payload_prefix = payload_roles[:payload_roles.index("payload-submit")]
        need((self.phase in NOTARY_PHASES
              and tuple(row.get("role") for row in self.calls) == payload_prefix
              or self.removal_final_active() and self.removal_final_calls() == package_prefix
              or self.phase in FINAL_IMAGE_PHASES and len(self.calls) == 3)
             and self.notary_key is None
             and self.notary_known(), "notary-key-purpose")
        body = notary_key_data(self.environment)
        primary = None
        try:
            self.notary_clock()
            self.stager_io_pending = "notary-private-key-create"
            os.mkdir("notary-key", 0o700, dir_fd=self.target_entry["fd"])
            root = self.directory(self.target_entry, "notary-key", "notary-key-directory")
            name = "AuthKey_" + self.notary_profile["keyId"] + ".p8"
            need(not os.listdir(root["fd"]), "notary-key-directory-empty")
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root["fd"])
            entry = self.register(fd, "notary-private-key", "file", root["fd"], name)
            entry["parent_entry"] = root
            self.notary_key = {"root": root, "entry": entry, "name": name, "body": body}
            self.receipt["notaryAuthentication"]["created"] = True
            offset = 0
            while offset < len(body):
                count = os.write(fd, body[offset:])
                need(type(count) is int and count > 0, "notary-key-short-write")
                offset += count
                self.notary_clock()
            os.fsync(fd)
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and (before.st_uid, before.st_gid) == (os.getuid(), os.getgid()) and before.st_size == len(body)
                 and stat.S_IMODE(before.st_mode) == 0o600 and os.pread(fd, len(body) + 1, 0) == body, "notary-key-original")
            self.stager.no_xattrs(fd)
            os.fchmod(fd, 0o400)
            entry["identity"] = signature(os.fstat(fd))
            need(stat.S_IMODE(entry["identity"][2]) == 0o400 and self.read(entry) == body, "notary-key-readback")
            self.stager_io_pending = None
            self.notary_post()
            yield ["--key", str(self.work / self.target_name / "notary-key" / name),
                   "--key-id", self.notary_profile["keyId"], "--issuer", self.notary_profile["issuerId"]]
        except BaseException as error:
            primary = error
        finally:
            if self.notary_key is not None and self.notary_known():
                try:
                    self.notary_post(work=False)
                    key = self.notary_key
                    self.close(key["entry"])
                    need(key["entry"]["closed"], "notary-key-close-unknown")
                    self.receipt["notaryAuthentication"]["closed"] = True
                    self.recheck_directory(key["root"])
                    need(signature(os.stat(key["name"], dir_fd=key["root"]["fd"], follow_symlinks=False)) == key["entry"]["identity"],
                         "notary-key-unlink-original")
                    os.unlink(key["name"], dir_fd=key["root"]["fd"])
                    need(not os.listdir(key["root"]["fd"]), "notary-key-retirement-census")
                    self.recheck_directory(key["root"])
                    self.close(key["root"])
                    need(key["root"]["closed"], "notary-key-directory-close-unknown")
                    self.recheck_directory(self.target_entry)
                    need(directory_identity(os.stat("notary-key", dir_fd=self.target_entry["fd"], follow_symlinks=False)) == key["root"]["identity"],
                         "notary-key-directory-retire-original")
                    os.rmdir("notary-key", dir_fd=self.target_entry["fd"])
                    need("notary-key" not in os.listdir(self.target_entry["fd"]), "notary-key-directory-remains")
                    self.notary_key = None
                    self.receipt["notaryAuthentication"]["retired"] = True
                    self.notary_clock(work=False)
                except BaseException as error:
                    self.notary_unknown = True
                    self.errors.append({"stage": "notary-key-retirement", "type": type(error).__name__})
                    if primary is None:
                        primary = error
        if primary is not None:
            raise primary

    def notarize_payload(self):
        need(self.phase in NOTARY_PHASES and self.signing is not None
             and not any(key in self.environment for key in CREDENTIAL_VARIABLES), "notary-configured-purpose")
        self.notary_space(reserve=True)
        launcher_sha = self.environment.get("MRK_MACOS_APPLICATIONS_LAUNCHER_SHA256")
        self.notary_launcher = launcher_sha is not None
        need(not self.notary_launcher or self.stager.sha(launcher_sha)
             and self.environment.get("MRK_MACOS_PACKAGE_ROLE") == "ordinary-image", "notary-launcher-binding")
        profile = self.source_original(NOTARY_PROFILE, "source-notary-profile", 1024)
        profile_body = self.read(profile)
        self.notary_profile = notary_service(profile_body, self.signing)
        self.package_sources.append((profile, profile_body))
        nomination = self.source_original("desktop/" + self.stager.SIGNED_RUNTIME_BINDING, "source-notary-runtime-nomination", self.stager.SIGNED_RUNTIME_BINDING_LIMIT)
        nomination_body = self.read(nomination)
        selected = self.stager.signed_runtime_binding_data(nomination_body, self.producer_profile, self.service_profile, target=self.target)
        self.package_sources.append((nomination, nomination_body))
        if self.environment.get("MRK_MACOS_STORE_RUNTIME") is not None:
            need(self.environment["MRK_MACOS_STORE_RUNTIME"] == "signed-component", "notary-store-mode")
            store_source = self.source_original("desktop/" + self.stager.SIGNED_STORE_SELECTION,
                "source-notary-store-selection", self.stager.SIGNED_STORE_SELECTION_LIMIT)
            store_source_body = self.read(store_source)
            store = self.stager.signed_store_selection_data(store_source_body, target=self.target)
            binding_entry = self.original(self.work_entry, "runtime-binding.json", "notary-composed-runtime-binding", 16384, (0o444,))
            binding_body = self.read(binding_entry)
            need(digest(binding_body) == self.environment.get("MRK_MACOS_RUNTIME_BINDING_SHA256"), "notary-composed-binding-original")
            selected, composed = self.stager.composed_runtime_binding_data(binding_body, selected, store, target=self.target)
            source_entry = self.original(self.work_entry, "source-binding.json", "notary-composed-source-binding", 65536, (0o444,))
            source_body = self.read(source_entry)
            work_info = os.fstat(self.work_entry["fd"])
            self.stager.composed_source_binding_data(source_body, binding_body, composed, self.environment,
                (work_info.st_dev, work_info.st_ino, work_info.st_uid))
            self.package_sources.extend(((store_source, store_source_body), (binding_entry, binding_body), (source_entry, source_body)))
            self.composed_runtime = True
        for variable, key in (("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256", "runtimeManifestSha256"),
                              ("MRK_BUNDLED_RUNTIME_SOURCE_SHA256", "sourceInputsSha256"),
                              ("MRK_MACOS_SIGNED_PYTHON_SHA256", "signedPythonSha256"),
                              ("MRK_MACOS_SIGNING_RECEIPT_SHA256", "signingReceiptSha256"),
                              ("MRK_MACOS_SIGNING_SOURCE_COMMIT", "signingSourceCommit"),
                              ("MRK_MACOS_SIGNING_RUN_ID", "signingRunId"), ("MRK_MACOS_SIGNING_RUN_ATTEMPT", "signingRunAttempt")):
            need(self.environment.get(variable) == selected[key], "notary-configured-runtime-binding")
        for filename in ("stage_macos_installed.py", "macos_android_helper_package.py"):
            entry = self.source_original("desktop/tools/" + filename, "source-notary-driver",
                HELPER_SOURCE_BYTES if filename == "macos_android_helper_package.py" else 512 * 1024)
            self.package_sources.append((entry, self.read(entry)))
        app_path = self.work / "app" / self.stager.APP_NAME
        for parts, path in ((("app", self.stager.APP_NAME), app_path), (("runtime",), self.work / "runtime")):
            root = self.descend(self.work_entry, parts)
            self.notary_roots.append({"entry": root, "path": path, "snapshot": self.notary_snapshot(root, path)})
        runtime_files = self.notary_roots[1]["snapshot"]["files"]
        need(runtime_files.get("manifest.json", (None, None))[1] == selected["runtimeManifestSha256"]
             and runtime_files.get("python/bin/python3", (None, None))[1] == selected["signedPythonSha256"], "notary-current-runtime-bytes")
        capsule_parent = self.directory(self.work_entry, "signed-python-capsule", "notary-signed-capsule")
        capsule = self.original(capsule_parent, "python-signed-receipt.json", "notary-signed-capsule-receipt", 16384, (0o444, 0o600))
        capsule_body = self.read(capsule)
        need(digest(capsule_body) == selected["signingReceiptSha256"], "notary-current-capsule-bytes")
        self.package_sources.append((capsule, capsule_body))
        arguments = argparse.Namespace(target=self.target, package_role=self.environment["MRK_MACOS_PACKAGE_ROLE"], current_runtime=True,
            expected_entry=self.environment.get("MRK_MACOS_SIGNED_ENTRY_SHA256"), expected_app_binary=self.environment.get("MRK_MACOS_SIGNED_PAYLOAD_SHA256"),
            expected_vault_helper=self.environment.get("MRK_MACOS_VAULT_HELPER_SHA256"),
            expected_installed_cli=self.environment.get("MRK_MACOS_INSTALLED_CLI_SHA256"),
            expected_github_seal=self.environment.get("MRK_MACOS_GITHUB_SEAL_SHA256"),
            expected_github_seal_bytes=(int(self.environment["MRK_MACOS_GITHUB_SEAL_BYTES"])
                if "MRK_MACOS_GITHUB_SEAL_BYTES" in self.environment else None),
            expected_remover=self.environment.get("MRK_MACOS_REMOVER_SHA256"), expected_android_helper=self.environment.get("MRK_MACOS_ANDROID_HELPER_SHA256"),
            expected_resident_image=self.environment.get("MRK_MACOS_RESIDENT_IMAGE_SHA256"),
            expected_desktop_image=self.environment.get("MRK_MACOS_SIGNED_DESKTOP_IMAGE_SHA256") if self.environment["MRK_MACOS_PACKAGE_ROLE"] == "ordinary-image" else None,
            expected_manifest=selected["runtimeManifestSha256"], app=app_path, runtime=self.work / "runtime",
            output=self.work / self.target_name / "payload-input")
        if self.notary_launcher:
            arguments.applications_launcher = app_path / LAUNCHER_BUNDLE
            arguments.expected_applications_launcher = launcher_sha
        self.notary_post()
        self.notary_io("notary-preflight-input", self.stager.input_command, arguments)
        copied = self.directory(self.target_entry, "payload-input", "notary-disposable-payload")
        self.notary_copy = {"entry": copied, "path": arguments.output, "snapshot": self.notary_snapshot(copied, arguments.output)}
        self.notary_post()
        self.notary_rename_copy()
        for name in ("notarytool", "stapler"):
            tool = self.notary_tool(name)
            result = self.notary_call("resolve-" + name, ["/usr/bin/xcrun", "--find", name], limit=4096, developer=True)
            need(result.stdout in ((str(tool["fixed"]) + "\n").encode(), (str(tool["path"]) + "\n").encode())
                 and not result.stderr, "notary-tool-discovery-original")
            self.notary_tool_post(tool)
        inner_path = app_path / self.stager.PAYLOAD_RELATIVE
        inner_requirement = signing_requirement(self.signing, "dev.mobile-release-kit.desktop")
        outer_requirement = signing_requirement(self.signing, "dev.mobile-release-kit.desktop.entry")
        launcher_path = app_path / LAUNCHER_BUNDLE
        launcher_requirement = signing_requirement(self.signing, LAUNCHER_IDENTIFIER)
        before_roles = ((("verify-launcher-before", launcher_path, launcher_requirement),) if self.notary_launcher else ())
        for role, path, requirement in (*before_roles, ("verify-inner-before", inner_path, inner_requirement), ("verify-outer-before", app_path, outer_requirement)):
            verified = self.notary_call(role, ["/usr/bin/codesign", "--verify", "--strict", "-R=" + requirement, str(path)])
            need(not verified.stdout and not verified.stderr, "notary-strict-verification-output")
        archive_path = self.work / self.target_name / NOTARY_ZIP_NAME
        need(NOTARY_ZIP_NAME not in os.listdir(self.target_entry["fd"]), "notary-zip-path-occupied")
        self.notary_call("payload-zip", ["/usr/bin/ditto", "-c", "-k", "--keepParent", str(arguments.output), str(archive_path)], maximum=180)
        self.notary_zip = self.original(self.target_entry, NOTARY_ZIP_NAME, "notary-submission-zip", NOTARY_ZIP_LIMIT, (0o400, 0o600, 0o644))
        need(os.pread(self.notary_zip["fd"], 4, 0) == b"PK\x03\x04", "notary-submission-zip-format")
        self.notary_zip_sha = self.notary_stream(self.notary_zip)
        tool = str(self.notary_tools["notarytool"]["path"])
        submission = log = None
        with self.notary_key_scope() as key_arguments:
            result = self.notary_call("payload-submit", [tool, "submit", str(archive_path), "--wait", "--output-format", "json", *key_arguments],
                                      maximum=1200, developer=True)
            submission = notary_submit_data(result.stdout)
            self.receipt["notarySubmission"] = dict(submission)
            invalid = Refused("notary-submission-invalid") if submission["status"] == "Invalid" else None
            try:
                result = self.notary_call("payload-log", [tool, "log", submission["id"], *key_arguments], limit=1024 * 1024, developer=True)
                log = notary_log_data(result.stdout, submission, self.notary_zip_sha)
                if invalid is not None:
                    self.capture_notary_failure(result.stdout)
            except BaseException as error:
                if invalid is not None:
                    self.receipt["notaryLogFailure"] = {"type": type(error).__name__}
                    raise invalid from None  # Diagnostic failure cannot replace the terminal refusal.
                raise
            if invalid is not None:
                raise invalid
        need(self.notary_key is None and self.receipt["notaryAuthentication"] == {"created": True, "closed": True, "retired": True},
             "notary-authentication-not-retired")
        tool = str(self.notary_tools["stapler"]["path"])
        launcher_staple = ((("staple-launcher", "staple", launcher_path), ("validate-launcher", "validate", launcher_path))
                          if self.notary_launcher else ())
        for role, verb, path in (*launcher_staple, ("staple-inner", "staple", inner_path), ("validate-inner", "validate", inner_path),
                                 ("staple-outer", "staple", app_path), ("validate-outer", "validate", app_path)):
            self.notary_call(role, [tool, verb, str(path)], developer=True)
        after_roles = ((("verify-launcher-after", launcher_path, launcher_requirement),) if self.notary_launcher else ())
        for role, path, requirement in (*after_roles, ("verify-inner-after", inner_path, inner_requirement), ("verify-outer-after", app_path, outer_requirement)):
            verified = self.notary_call(role, ["/usr/bin/codesign", "--verify", "--strict", "-R=" + requirement, str(path)])
            need(not verified.stdout and not verified.stderr, "notary-strict-verification-output")
        expected_tickets = notary_tickets(self.notary_launcher)
        tickets = sorted(self.notary_ticket_rows, key=lambda row: expected_tickets.index(row["path"]))
        need(tuple(row["path"] for row in tickets) == expected_tickets, "notary-ticket-roster")
        if self.notary_launcher:
            arguments.expected_applications_launcher_ticket = next(row["sha256"] for row in tickets if row["path"] == LAUNCHER_TICKET)
        arguments.output = self.work / "input"
        result = self.notary_io("notary-final-input", self.stager.input_command, arguments, ticket_expectations=tickets)
        self.notary_post()
        self.notary_result = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        need(len(self.notary_result) <= 2048 and result.get("qualification") == "fresh-install-input-not-installed"
             and self.stager.sha(result.get("inventorySha256")), "notary-final-input-result")
        final_root = self.directory(self.work_entry, "input", "notary-final-input")
        self.notary_final = {"entry": final_root, "path": arguments.output, "snapshot": self.notary_snapshot(final_root, arguments.output)}
        need(self.notary_final["snapshot"]["files"].get("install-inventory.json", (None, None))[1] == result["inventorySha256"],
             "notary-final-inventory-original")
        self.sha256 = result["inventorySha256"]
        self.resident_image_sha256 = arguments.expected_resident_image
        self.notary_complete = True
        self.receipt["payloadNotarization"] = {"submissionId": submission["id"], "status": submission["status"], **log,
            "archiveBytes": self.notary_zip["identity"][6], "archiveSha256": self.notary_zip_sha,
            "tickets": tickets, "inventorySha256": self.sha256, "runtimeManifestSha256": selected["runtimeManifestSha256"],
            "strictVerificationBeforeAndAfter": True, "actualStaplerValidation": True,
            "assurance": "accepted-payload-and-ticket-observations-not-package-or-installed-authority"}
        self.notary_clock()

    def notary_retirement(self):
        if self.phase not in NOTARY_PHASES + FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES or self.notary_started is None or self.target_entry is None or not self.notary_known():
            return
        self.notary_retiring = True
        try:
            self.stage = "notary-known-private-retirement"
            need(self.notary_key is None, "notary-private-key-retained")
            self.notary_post(work=False)
            if self.notary_final is not None:
                item = self.notary_final
                need(self.notary_snapshot(item["entry"], item["path"], work=False) == item["snapshot"], "notary-final-input-post")
            if self.install_product_root is not None:
                # Only our freshly generated presentation needs deletion
                # permission. Its native input stayed readonly through every
                # returned call and the full snapshot POST immediately above.
                root = self.install_product_root
                items = [item for item in self.notary_roots if item["entry"] is root]
                need(self.install_product and self.phase in ("finalize-package", "finalize-xcode-setup-package")
                     and root.get("parent_entry") is self.target_entry and root["name"] == "product-input"
                     and len(items) == 1 and items[0]["path"] == self.work / self.target_name / "product-input",
                     "install-product-retirement-root")
                expected = items[0]["snapshot"]["directories"]
                need(set(expected) == {"", "resources"}
                     and set(items[0]["snapshot"]["files"]) == ({"Component.plist", "Distribution", "resources/InstallerReadMe.html"}
                         if self.setup_package else {"Distribution", "resources/InstallerReadMe.html"})
                     and expected[""][1] == (("Component.plist", "Distribution", "resources") if self.setup_package else ("Distribution", "resources"))
                     and expected["resources"][1] == ("InstallerReadMe.html",), "install-product-retirement-roster")
                self.recheck_directory(root)
                need(root["identity"] == expected[""][0] and stat.S_IMODE(root["identity"][2]) == 0o700,
                     "install-product-retirement-root-original")
                child = None
                try:
                    self.notary_clock(work=False)
                    fd = os.open("resources", READ_FLAGS | os.O_DIRECTORY, dir_fd=root["fd"])
                    child = self.register(fd, "install-product-retirement-directory", "directory", root["fd"], "resources")
                    child["parent_entry"] = root
                    child["identity"] = directory_identity(os.fstat(fd))
                    self.recheck_directory(child)
                    need(child["identity"] == expected["resources"][0]
                         and stat.S_IMODE(child["identity"][2]) == 0o555
                         and os.listdir(fd) == ["InstallerReadMe.html"], "install-product-retirement-original")
                    self.notary_clock(work=False)
                    os.fchmod(fd, 0o700)
                    child["identity"] = directory_identity(os.fstat(fd))
                    need(child["identity"] == (expected["resources"][0][:2]
                         + (stat.S_IFDIR | 0o700,) + expected["resources"][0][3:]), "install-product-retirement-mode")
                    self.recheck_directory(child)
                    self.notary_clock(work=False)
                finally:
                    if child is not None:
                        self.close(child)  # Same consuming original, never a cached closed FD.
                need(child["closed"] and not self.errors, "install-product-retirement-close-unknown")
            if self.notary_copy is not None:
                root = self.notary_copy["entry"]
                expected = self.notary_copy["snapshot"]["directories"]
                def writable(parent, prefix):
                    self.notary_clock(work=False)
                    self.recheck_directory(parent)
                    need(parent["identity"] == expected[prefix][0], "notary-retirement-directory-original")
                    os.fchmod(parent["fd"], 0o700)
                    parent["identity"] = directory_identity(os.fstat(parent["fd"]))
                    self.recheck_directory(parent)
                    for name in expected[prefix][1]:
                        relative = name if not prefix else prefix + "/" + name
                        if relative not in expected:
                            continue
                        key = (id(parent), name)
                        if key in self.directories:
                            child = self.directories[key]
                            writable(child, relative)
                        else:
                            fd = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=parent["fd"])
                            child = self.register(fd, "notary-retirement-directory", "directory", parent["fd"], name)
                            child["parent_entry"] = parent
                            child["identity"] = directory_identity(os.fstat(fd))
                            try:
                                writable(child, relative)
                            finally:
                                self.close(child)
                            need(child["closed"], "notary-retirement-close-unknown")
                writable(root, "")
            self.notary_clock(work=False)
        except BaseException as error:
            self.notary_unknown = True
            self.errors.append({"stage": "notary-private-state-retained", "type": type(error).__name__})

    def final_image_known(self):
        return (self.notary_known() and not self.credential_failed and self.credential_active is None
                and not self.credential_calls and not self.credential_contexts)

    def final_image_io(self, label, function, *args, **kwargs):
        need(self.phase in FINAL_IMAGE_PHASES and self.final_image_known() and not self.notary_retiring,
             "final-image-io-unknown")
        self.notary_clock()
        self.stage = self.stager_io_pending = label
        value = function(*args, **kwargs)
        self.notary_clock()
        self.stager_io_pending = None  # Only a returned original clears this latch.
        return value

    def final_image_preimage_post(self, *, work=True, record=None):
        if record is None:
            record = self.final_image_preimage
        if record is not None:
            self.stager.package_staple_preimage_post(self, need, work=work, record=record)

    def final_image_post(self, *, work=True):
        self.notary_clock(work=work)
        self.final_image_preimage_post(work=work)
        for root, names in self.final_image_roots:
            self.recheck_directory(root)
            need(set(os.listdir(root["fd"])) == names, "final-image-directory-census")
        for entry, sha in self.final_image_inputs:
            need(self.notary_stream(entry, work=work) == sha, "final-image-input-changed")
        if self.final_image_output is not None:
            need(self.notary_stream(self.final_image_output, work=work) == self.final_image_sha,
                 "final-image-output-changed")
        if self.target_entry is not None:
            self.recheck_directory(self.target_entry)
            names = {"tmp"}
            if self.final_image_output_root is not None:
                names.add("final-image")
            if self.notary_key is not None:
                names.add("notary-key")
            need(set(os.listdir(self.target_entry["fd"])) == names, "final-image-target-census")
            self.directory(self.target_entry, "tmp", "final-image-tmp")
        self.notary_clock(work=work)

    def final_removal_image_input(self):
        """Only Remove inputs; never fabricate the separate Install readback witnesses."""
        selection = self.stager.BuildSelection(self.target,
            self.stager.build_release_data(self.read(self.release_entry), target=self.target)["packageVersion"], self.image_release)
        def retained(parent, name, limit, modes=(0o444, 0o600, 0o644, 0o400)):
            entry = self.original(parent, name, "final-removal-input-" + name, limit, modes)
            body = self.read(entry)
            self.final_image_inputs.append((entry, digest(body)))
            self.notary_clock()
            return entry, body
        need(retained(self.work_entry, "package-remove.status", 4)[1] == b"0\n", "final-removal-original-status")
        root = self.directory(self.work_entry, self.final_package_name, "final-removal-package")
        need(os.listdir(root["fd"]) == [self.package_filename], "final-removal-package-roster")
        self.final_image_roots.append((root, {self.package_filename}))
        entry, package = retained(root, self.package_filename, self.stager.MAX_BYTES, (0o444,))
        self.package_finalization_input(entry, package)
        self.final_image_inputs.extend(self.package_outputs)
        root = self.directory(self.work_entry, "remove-producer-root", "final-removal-producer")
        names = {"Remove.pkg", "remove-producer.json", "remove-producer.sig"}
        need(set(os.listdir(root["fd"])) == names, "final-removal-producer-roster")
        self.final_image_roots.append((root, names))
        need(retained(root, "Remove.pkg", self.stager.MAX_BYTES, (0o444,))[1] == package, "final-removal-package-copy")
        _, descriptor = retained(root, "remove-producer.json", self.stager.REMOVE_DESCRIPTOR_BYTES, (0o444,))
        _, signed = retained(root, "remove-producer.sig", self.stager.PRODUCER_SIGNATURE_BYTES, (0o444,))
        input_root = self.directory(self.work_entry, "remove-emitter-input", "final-removal-emitter-input")
        input_values = {}
        names = {"remove-descriptor-input.json", "producer.json", "producer.sig", "install-inventory.json", self.stager.REMOVER_NAME}
        need(set(os.listdir(input_root["fd"])) == names, "final-removal-input-roster")
        self.final_image_roots.append((input_root, names))
        for name in sorted(names):
            maximum = self.stager.REMOVER_BYTES if name == self.stager.REMOVER_NAME else (self.stager.INVENTORY_BYTES if name == "install-inventory.json" else self.stager.PRODUCER_DESCRIPTOR_BYTES)
            input_values[name] = retained(input_root, name, maximum, (0o555,) if name == self.stager.REMOVER_NAME else (0o444,))[1]
        source = self.stager.packaging_signing_data(self.producer_profile, self.service_profile)
        expected = self.stager.packaging_removal_descriptor_data(input_values["producer.json"], input_values["install-inventory.json"],
            input_values[self.stager.REMOVER_NAME], package, source, selection, source_commit=self.image_source,
            manifest=self.environment.get("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"))
        need(input_values["remove-descriptor-input.json"] == expected == descriptor
             and digest(input_values["install-inventory.json"]) == self.environment.get("MRK_MACOS_INSTALL_INVENTORY_SHA256")
             and digest(input_values[self.stager.REMOVER_NAME]) == self.environment.get("MRK_MACOS_REMOVER_SHA256"), "final-removal-source-originals")
        _, owner_body = retained(self.work_entry, "android-helper-package-remove.json", 16384, (0o600,))
        binding = ({"source": self.image_source, "runId": self.environment["GITHUB_RUN_ID"], "runAttempt": self.environment["GITHUB_RUN_ATTEMPT"]}
                   if self.candidate_removal_context is None else self.candidate_removal_binding())
        distribution = self.stager.removal_package_receipt_data(owner_body, selection=selection, binding=binding,
            package=package, descriptor=descriptor, signed=signed, expected_descriptor=expected,
            final_package_sha=self.receipt["finalPackageReceiptSha256"], release_body=self.read(self.release_entry),
            profiles=(self.producer_profile, self.service_profile),
            expected_workflow=self.environment["GITHUB_WORKFLOW_REF"])
        image_root = self.directory(self.work_entry, self.image_directory, "final-removal-distribution")
        need(os.listdir(image_root["fd"]) == [self.image_filename], "final-removal-image-roster")
        self.final_image_roots.append((image_root, {self.image_filename}))
        original = self.original(image_root, self.image_filename, "final-removal-original", self.stager.MAX_BYTES, (0o444,))
        sha = self.notary_stream(original)
        self.final_image_inputs.append((original, sha))
        need(distribution["userImage"] == {"file": self.image_filename, "bytes": original["identity"][6], "sha256": sha},
             "final-removal-original-image")
        self.final_image_original = original
        binding = {"target": self.target, "release": selection.release, "packageVersion": selection.package_version,
            "packageRemoveReceiptSha256": digest(owner_body), "finalPackageReceiptSha256": self.receipt["finalPackageReceiptSha256"],
            "packageBytes": len(package), "packageSha256": digest(package), "descriptorBytes": len(descriptor), "descriptorSha256": digest(descriptor),
            "signatureBytes": len(signed), "signatureSha256": digest(signed), "producerProfileSha256": source.producer_sha256,
            "serviceProfileSha256": source.service_sha256, "originalImageBytes": original["identity"][6], "originalImageSha256": sha}
        return {"Remove.pkg": package, "remove-producer.json": descriptor, "remove-producer.sig": signed}, binding

    def final_image_input(self):
        """Keep the preceding original statuses, receipts and final P distinct."""
        self.stage = 'final-image-original-inputs'
        selection = self.stager.BuildSelection(self.target,
            self.stager.build_release_data(self.read(self.release_entry), target=self.target)["packageVersion"], self.image_release)
        def retained(parent, name, limit, modes=(0o444, 0o600, 0o644, 0o400)):
            entry = self.original(parent, name, "final-image-input-" + name, limit, modes)
            body = self.read(entry)
            self.final_image_inputs.append((entry, digest(body)))
            self.notary_clock()
            return entry, body
        for name in ("package-install.status", "installer-output.status"):
            need(retained(self.work_entry, name, 4)[1] == b"0\n", "final-image-original-status")
        final_root = self.directory(self.work_entry, "package-final", "final-image-final-package")
        need(os.listdir(final_root["fd"]) == ["MobileReleaseKit.pkg"], "final-image-final-package-roster")
        self.final_image_roots.append((final_root, {"MobileReleaseKit.pkg"}))
        package_entry, package = retained(final_root, "MobileReleaseKit.pkg", self.stager.MAX_BYTES, (0o444,))
        self.package_finalization_input(package_entry, package)
        self.final_image_inputs.extend(self.package_outputs)
        self.stage = 'final-image-package-owner'
        _, owner_body = retained(self.work_entry, "android-helper-package-install.json", 16384, (0o600,))
        owner = self.stager.maintenance_json(owner_body, 16384)
        need(type(owner) is dict and type(owner.get("schemaVersion")) is int and owner["schemaVersion"] == 1
             and owner.get("phase") == "package-install" and owner.get("target") == self.target
             and all(owner.get(key) == self.environment[env] for key, env in
                     (("source", "GITHUB_SHA"), ("workflowSource", "GITHUB_WORKFLOW_SHA"),
                      ("workflow", "GITHUB_WORKFLOW_REF"), ("runId", "GITHUB_RUN_ID"), ("runAttempt", "GITHUB_RUN_ATTEMPT")))
             and owner.get("imageSourceCommit") == self.image_source and owner.get("imageReleaseId") == selection.release
             and owner.get("imageReleaseSourceSha256") == digest(self.read(self.release_entry))
             and owner.get("packageRole") == "ordinary-image" and owner.get("passed") is True
             and owner.get("targetRetired") is True and owner.get("originalClosesKnown") is True
             and owner.get("outerFinalityRequired") is True and owner.get("cleanupErrors") == []
             and owner.get("directStagerIOPending") is None
             and owner.get("finalPackageReceiptSha256") == self.receipt["finalPackageReceiptSha256"],
             "final-image-package-owner")
        calls = owner.get("originalCalls")
        need(type(calls) is list and len(calls) == len(self.stager.PACKAGING_CALL_ROLES)
             and all(type(row) is dict for row in calls)
             and tuple(row.get("role") for row in calls) == self.stager.PACKAGING_CALL_ROLES
             and all(row.get("entered") is True and row.get("returned") is True and row.get("capturesSettled") is True
                     and type(row.get("returncode")) is int
                     and row["returncode"] in ((0, 1) if row["role"] in ("installer-log-cursor", "installer-log-capture") else (0,))
                     for row in calls), "final-image-package-original-calls")
        credentials, contexts = owner.get("credentialOriginals"), owner.get("credentialContexts")
        need(type(credentials) is list and len(credentials) == 60 and all(type(row) is dict for row in credentials)
             and tuple(row.get("role") for row in credentials) == ("producer-adhoc", "producer-adhoc-verify", "producer-cdhash") + (CREDENTIAL_ROLES[:17] + ("search-final", "default-after")) * 3
             and all(type(row.get("status")) is int and row["status"] == 0
                     and all(row.get(k) is True for k in ("entered", "returned", "settled")) for row in credentials)
             and type(contexts) is list and len(contexts) == 3
             and all(type(row) is dict for row in contexts)
             and tuple(row.get("purpose") for row in contexts) == ("producer", "distribution-image", "observation-image")
             and all(type(row) is dict and all(row.get(k) is True for k in ("retired", "closed", "searchRestored", "defaultUnchanged")) for row in contexts),
             "final-image-package-credentials-settled")
        mount = owner.get("packageMount")
        need(type(mount) is dict and mount == {"attachEntered": True, "originalKnown": True, "detached": True,
             "retained": False, "installerEntered": True, "installerOriginalZero": True,
             "sameRequestV2Readback": True, "systemServiceExitClaimed": False}, "final-image-original-mount")
        distribution = owner.get("distribution")
        need(type(distribution) is dict and type(distribution.get("schemaVersion")) is int and distribution["schemaVersion"] == 1
             and distribution.get("kind") == "mrk-ordinary-package-observed-v2"
             and distribution.get("target") == self.target and distribution.get("release") == selection.release
             and distribution.get("packageVersion") == selection.package_version
             and type(distribution.get("packageBytes")) is int and distribution["packageBytes"] == len(package)
             and all(distribution.get(k) is True for k in ("originalInstallerReturnedZero", "sameRequestV2Readback",
                                                          "originalMountDetached", "groupEndpointMet", "originalOuterReturnRequired")),
             "final-image-original-distribution")
        request = distribution.get("requestId")
        need(self.stager.maintenance_hex(request, 32)
             and retained(self.work_entry, "package-request-id.txt", 33)[1] == (request + "\n").encode("ascii"),
             "final-image-original-request")
        self.stage = 'final-image-original-readback'
        _, observed_body = retained(self.work_entry, "installation-observation.json", self.stager.INSTALLER_RESULT_BYTES)
        observed = self.stager.maintenance_json(observed_body, self.stager.INSTALLER_RESULT_BYTES)
        need(type(observed) is dict and type(observed.get("schemaVersion")) is int and observed["schemaVersion"] == 2 and observed.get("requestId") == request
             and observed.get("sourceCommit") == self.image_source and observed.get("release") == selection.release
             and observed.get("completedPackageSha256") == digest(package)
             and observed.get("originalInstallerReturnedZero") is True and observed.get("originalWriterJoined") is True
             and observed.get("historicalOuterExit") == "unverified"
             and observed.get("applicationLaunched") is False and observed.get("guiSaveQualified") is False
             and observed.get("inventorySha256") == self.environment.get("MRK_MACOS_INSTALL_INVENTORY_SHA256")
             and observed.get("runtimeManifestSha256") == self.environment.get("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"),
             "final-image-original-readback")
        nested = self.stager.maintenance_result_data(self.stager.canonical(observed.get("originalInstallerResult")) + b"\n", request)
        need(nested["invocation"] == observed.get("invocation"), "final-image-readback-invocation")
        self.stage = 'final-image-package-audit'
        _, audit_body = retained(self.work_entry, "package-audit.json", 16384)
        audit = self.stager.maintenance_json(audit_body, 16384)
        need(type(audit) is dict and audit.get("packageSha256") == digest(package) and type(audit.get("packageSize")) is int
             and audit["packageSize"] == len(package) and audit.get("packageIdentifier") == "dev.mobile-release-kit.desktop.installed"
             and audit.get("qualification") == self.stager.INSTALL_PRODUCT_QUALIFICATION, "final-image-package-audit")
        self.stage = 'final-image-producer'
        root = self.directory(self.work_entry, "producer-root", "final-image-producer-root")
        names = {"Install.pkg", "producer.json", "producer.sig"}
        need(set(os.listdir(root["fd"])) == names, "final-image-producer-roster")
        self.final_image_roots.append((root, names))
        need(retained(root, "Install.pkg", self.stager.MAX_BYTES, (0o444,))[1] == package, "final-image-producer-package")
        _, descriptor = retained(root, "producer.json", self.stager.PRODUCER_DESCRIPTOR_BYTES, (0o444,))
        _, signed = retained(root, "producer.sig", self.stager.PRODUCER_SIGNATURE_BYTES, (0o444,))
        need(retained(self.work_entry, "producer-descriptor-input.json", self.stager.PRODUCER_DESCRIPTOR_BYTES)[1] == descriptor,
             "final-image-descriptor-input")
        self.stager.emitted_package_data(self.stager.canonical(distribution.get("producerSummary")) + b"\n", b"", 0,
                                        package, descriptor, signed, target=self.target)
        producer = self.stager.maintenance_producer_data(descriptor, target=self.target)
        current = producer["releaseSet"]["current"]
        need(current["sourceCommit"] == self.image_source and current["release"] == selection.release
             and current["packageVersion"] == selection.package_version and current["protocolSha256"] == self.stager.CURRENT_PROTOCOL
             and current["inventorySha256"] == observed["inventorySha256"]
             and current["runtimeManifestSha256"] == observed["runtimeManifestSha256"]
             and (distribution.get("packageSha256"), distribution.get("descriptorSha256"), distribution.get("signatureSha256"))
                 == (digest(package), digest(descriptor), digest(signed)), "final-image-producer-current")
        self.stage = 'final-image-source-profiles'
        source = self.stager.packaging_signing_data(self.producer_profile, self.service_profile)
        need(distribution.get("sourceProducerProfileSha256") == source.producer_sha256
             and distribution.get("sourceServiceProfileSha256") == source.service_sha256, "final-image-package-source-profiles")
        self.stage = 'final-image-original-image'
        image_root = self.directory(self.work_entry, "distribution", "final-image-original-distribution")
        names = {"MobileReleaseKit.dmg", "MobileReleaseKit-Observation.dmg"}
        need(set(os.listdir(image_root["fd"])) == names, "final-image-original-roster")
        self.final_image_roots.append((image_root, names))
        original = self.original(image_root, "MobileReleaseKit.dmg", "final-image-original", self.stager.MAX_BYTES, (0o444,))
        original_sha = self.notary_stream(original)
        self.final_image_inputs.append((original, original_sha))
        need(distribution.get("userImage") == {"file": "MobileReleaseKit.dmg", "bytes": original["identity"][6], "sha256": original_sha},
             "final-image-original-digest")
        self.final_image_original = original
        binding = {"target": self.target, "release": selection.release, "packageVersion": selection.package_version, "requestId": request,
                   "packageInstallReceiptSha256": digest(owner_body), "finalPackageReceiptSha256": self.receipt["finalPackageReceiptSha256"],
                   "packageBytes": len(package), "packageSha256": digest(package),
                   "descriptorBytes": len(descriptor), "descriptorSha256": digest(descriptor),
                   "signatureBytes": len(signed), "signatureSha256": digest(signed),
                   "producerProfileSha256": source.producer_sha256, "serviceProfileSha256": source.service_sha256,
                   "originalImageBytes": original["identity"][6], "originalImageSha256": original_sha}
        return {"Install.pkg": package, "producer.json": descriptor, "producer.sig": signed}, binding

    def final_image_copy(self):
        self.recheck_directory(self.target_entry)
        os.mkdir("final-image", 0o700, dir_fd=self.target_entry["fd"])
        root = self.directory(self.target_entry, "final-image", "final-image-copy-root")
        self.final_image_output_root = root
        need(stat.S_IMODE(root["identity"][2]) == 0o700 and not os.listdir(root["fd"]), "final-image-copy-directory")
        fd = os.open(self.image_filename, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root["fd"])
        entry = self.register(fd, "final-image-copy", "file", root["fd"], self.image_filename)
        entry["parent_entry"] = root
        self.final_image_output = entry
        original = self.final_image_original
        original_sha = self.notary_stream(original)
        offset, copied = 0, hashlib.sha256()
        while offset < original["identity"][6]:
            self.notary_clock()
            block = os.pread(original["fd"], min(1024 * 1024, original["identity"][6] - offset), offset)
            need(block and len(block) <= original["identity"][6] - offset, "final-image-copy-short-input")
            copied.update(block)
            position = 0
            while position < len(block):
                self.notary_clock()
                count = os.write(fd, block[position:])
                need(count > 0, "final-image-copy-short-write")
                position += count
            offset += len(block)
        os.fsync(fd)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
             and info.st_uid == os.getuid() and info.st_gid == os.getgid() and info.st_size == offset
             and copied.hexdigest() == original_sha and self.notary_stream(original) == original_sha,
             "final-image-copy-original")
        entry["identity"] = signature(info)
        self.final_image_sha = self.notary_stream(entry)
        need(self.final_image_sha == original_sha, "final-image-copy-digest")
        self.final_image_roots.append((root, {self.image_filename}))

    def final_image_returned(self, entry, before, after, before_entry, before_sha):
        # SAME settled staple call: preserve the submitted PRE by its FD and
        # register the returned name before any fallible use of its new FD.
        self.stage = "final-image-staple-returned-input"
        need(self.notary_mutation_pending and self.final_image_preimage is None
             and before_entry is entry and entry is self.final_image_output
             and self.entry_registry.get(id(entry)) is entry and entry["kind"] == "file"
             and entry["role"] == "final-image-copy" and type(entry["fd"]) is int and not entry["closed"]
             and entry["identity"] == before and before_sha == self.final_image_sha
             and type(before_sha) is str and re.fullmatch(r"[0-9a-f]{64}", before_sha) is not None,
             "final-image-stapled-original")
        need(after[:3] == before[:3] and after[3] == 0 and after[4:8] == before[4:8],
             "final-image-stapled-original")
        parent = entry["parent_entry"]
        need(parent is self.final_image_output_root and entry["name"] == self.image_filename
             and set(os.listdir(parent["fd"])) == {entry["name"]}, "final-image-directory-census")
        record = (entry, after, before_sha)
        self.stage = "final-image-staple-returned-preimage"
        self.final_image_preimage_post(record=record)
        self.stage = "final-image-staple-returned-name"
        named = signature(os.stat(entry["name"], dir_fd=parent["fd"], follow_symlinks=False))
        need(named[0] == before[0] and named[1] != before[1] and named[2] == before[2]
             and stat.S_ISREG(named[2]) and named[3] == 1 and named[4:6] == before[4:6]
             and 0 < named[6] <= self.stager.MAX_BYTES
             and abs(named[6] - before[6]) <= 1024 * 1024, "final-image-stapled-original")
        self.stage = "final-image-staple-returned-acquire"
        returned = self.original(parent, entry["name"], "final-image-stapled-output",
                                 self.stager.MAX_BYTES, (stat.S_IMODE(before[2]),))
        need(returned["identity"] == named
             == signature(os.stat(entry["name"], dir_fd=parent["fd"], follow_symlinks=False)),
             "final-image-stapled-original")
        self.final_image_preimage_post(record=record)
        self.recheck_directory(parent)
        need(set(os.listdir(parent["fd"])) == {entry["name"]}, "final-image-directory-census")
        self.stage = "final-image-staple-returned-stream"
        sha = self.notary_stream(returned)
        self.final_image_preimage_post(record=record)
        self.recheck_directory(parent)
        need(set(os.listdir(parent["fd"])) == {entry["name"]}, "final-image-directory-census")
        self.stage = "final-image-staple-returned-commit"
        self.final_image_preimage, self.final_image_output, self.final_image_sha = record, returned, sha
        self.final_image_post()  # First committed PRE/output POST while still pending.
        self.notary_mutation_pending = False

    def final_image_mutated(self, before, *, before_entry=None, before_sha=None):
        # Apple rewrites SuperBlob/UDIF, not a PKG prefix. All original guards
        # and short-circuit reads remain; these finite stages only locate refusal.
        entry = self.final_image_output
        self.stage = "final-image-staple-parent"
        self.recheck_directory(entry["parent_entry"])
        self.stage = "final-image-staple-held-stat"
        after = signature(os.fstat(entry["fd"]))
        if after[3] == 0 and before_entry is not None:
            self.final_image_returned(entry, before, after, before_entry, before_sha)
            return
        for index, label in enumerate(("device", "inode", "mode", "links", "uid", "gid")):
            self.stage = "final-image-staple-held-" + label
            if index == 3 and after[index] != before[index]:
                self.stage += "-unlinked" if after[index] == 0 else "-other"
            need(after[index] == before[index], "final-image-stapled-original")
        self.stage = "final-image-staple-size"
        need(0 < after[6] <= self.stager.MAX_BYTES, "final-image-stapled-original")
        self.stage = "final-image-staple-growth"
        need(abs(after[6] - before[6]) <= 1024 * 1024, "final-image-stapled-original")
        self.stage = "final-image-staple-name-stat"
        named = signature(os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False))
        self.stage = "final-image-staple-binding"
        need(after == named, "final-image-stapled-original")
        self.stage = "final-image-staple-xattr-query"
        try:
            self.stager.no_xattrs(entry["fd"])
        except BaseException as error:
            # Only the trusted exact class/one-string literal is diagnostic.
            # Never render error text, consult foreign properties or replace it.
            if type(error) is self.stager.Refused:
                args = BaseException.args.__get__(error)
                if type(args) is tuple and len(args) == 1 and type(args[0]) is str:
                    if args[0] == "file-extended-attributes":
                        self.stage = "final-image-staple-xattrs-present"
            raise
        entry["identity"] = after
        self.stage = "final-image-staple-stream"
        self.final_image_sha = self.notary_stream(entry)
        self.notary_mutation_pending = False  # Same original only; native integrity/mount gates still required.
    def final_image_observe_unlinked(self, primary, role, entry, before, before_sha):
        """Read-only same-call facts; named stats are NOT returned-output custody."""
        if (self.phase != "finalize-image" or role != "final-image-staple"
                or self.stage != "final-image-staple-held-links-unlinked" or type(primary) is not Refused):
            return
        args = BaseException.args.__get__(primary)
        if type(args) is not tuple or len(args) != 1 or type(args[0]) is not str or args[0] != "final-image-stapled-original":
            return
        if (type(entry) is not dict or entry is not self.final_image_output
                or self.entry_registry.get(id(entry)) is not entry or entry.get("kind") != "file"
                or entry.get("role") != "final-image-copy" or entry.get("name") != self.image_filename
                or type(entry.get("fd")) is not int or entry.get("closed") is not False
                or type(before) is not tuple or len(before) != 9 or entry.get("identity") != before
                or type(before_sha) is not str or re.fullmatch(r"[0-9a-f]{64}", before_sha) is None
                or before_sha != self.final_image_sha or not self.notary_mutation_pending
                or len(self.calls) != 6 or type(self.calls[-1]) is not dict
                or self.calls[-1].get("role") != role or self.calls[-1].get("returned") is not True
                or self.calls[-1].get("capturesSettled") is not True
                or type(self.calls[-1].get("returncode")) is not int or self.calls[-1]["returncode"] != 0):
            return
        parent = entry.get("parent_entry")
        if (type(parent) is not dict or parent is not self.final_image_output_root
                or self.entry_registry.get(id(parent)) is not parent or parent.get("kind") != "directory"
                or type(parent.get("fd")) is not int or parent.get("closed") is not False
                or entry.get("parent") != parent["fd"]):
            return
        observation = {name: None for name in FINAL_IMAGE_UNLINK_FLAGS}
        observation.update(state="refused", outputAdopted=False, transitionComplete=False)
        self.receipt["finalImageUnlinkObservation"] = observation
        try:
            self.notary_clock()
            self.recheck_directory(parent)
            after = signature(os.fstat(entry["fd"]))
            observation["retainedPreIdentityExpected"] = after[:3] == before[:3] and after[4:8] == before[4:8]
            observation["retainedPreLinkUnlinked"] = after[3] == 0
            need(observation["retainedPreIdentityExpected"] and observation["retainedPreLinkUnlinked"], "final-image-unlink-observation")
            named = signature(os.stat(entry["name"], dir_fd=parent["fd"], follow_symlinks=False))
            observation.update(namedExists=True, namedSameDevice=named[0] == before[0],
                namedRegular=stat.S_ISREG(named[2]), namedModeExpected=named[2] == before[2],
                namedOwnerExpected=named[4] == before[4], namedGroupExpected=named[5] == before[5],
                namedSingleLink=named[3] == 1, namedSizeBounded=0 < named[6] <= self.stager.MAX_BYTES,
                namedGrowthBounded=abs(named[6] - before[6]) <= 1024 * 1024,
                namedInodeDifferent=named[1] != before[1], heldNameIdentityDifferent=after != named)
            need(set(os.listdir(parent["fd"])) == {entry["name"]}, "final-image-unlink-observation")
            # Explicit record: no package book assignment, output acquisition,
            # prefix assumption, name-bound PRE reopen or mutation completion.
            self.stager.package_staple_preimage_post(self, need, record=(entry, after, before_sha))
            observation["retainedPreBytesUnchanged"] = True
            self.recheck_directory(parent)
            observation["parentStable"] = True
            observation["censusStable"] = set(os.listdir(parent["fd"])) == {entry["name"]}
            observation["namedPostStable"] = signature(os.stat(entry["name"], dir_fd=parent["fd"], follow_symlinks=False)) == named
            need(observation["censusStable"] and observation["namedPostStable"], "final-image-unlink-observation")
            self.notary_clock()
            observation["state"] = "observed"
        except BaseException:
            # Diagnostic failure has no cleanup/acceptance authority. Never
            # replace or render the SAME primary, nor change its first stage.
            return

    def final_image_call(self, role, argv, *, maximum=30, limit=65536, developer=False):
        need(self.phase in FINAL_IMAGE_PHASES and self.final_image_known() and not self.notary_retiring
             and len(self.calls) < len(FINAL_IMAGE_ROLES) and role == FINAL_IMAGE_ROLES[len(self.calls)], "final-image-fixed-role-order")
        need((self.notary_key is not None) == (role in ("final-image-submit", "final-image-log")), "final-image-private-role")
        bounds = {"final-image-resolve-notarytool": (30, 4096), "final-image-resolve-stapler": (30, 4096),
                  "final-image-submit": (1200, 65536), "final-image-log": (30, 1024 * 1024),
                  "final-image-verify": (120, 65536), "final-image-attach": (60, 65536),
                  "final-image-policy-status": (30, 4096)}
        need((maximum, limit) == bounds.get(role, (30, 65536)), "final-image-original-bound")
        self.notary_post()
        now, endpoint = self.notary_clock()
        timeout = min(maximum, (endpoint - now - 3_000_000_000) // 1_000_000_000)
        need(timeout >= 1, "final-image-original-settlement-reserve")
        environment = self.native_environment()
        if developer:
            environment["DEVELOPER_DIR"] = str(NOTARY_XCODE)
        self.stage = role
        changing = role == "final-image-staple"
        before_entry = self.final_image_output if changing else None
        before = before_entry["identity"] if changing else None
        before_sha = self.final_image_sha if changing else None
        self.notary_mutation_pending = changing
        try:
            result = self.call(role, argv, environment, cwd=self.work, timeout=timeout, limit=limit)
            if changing:
                self.stage = "final-image-staple-clock"
            self.notary_clock()
            if changing:
                self.final_image_mutated(before, before_entry=before_entry, before_sha=before_sha)
                self.stage = "final-image-staple-post"
            self.notary_post()
            if changing:
                self.stage = role
            return result
        except BaseException as primary:
            if changing:
                try:
                    self.final_image_observe_unlinked(primary, role, before_entry, before, before_sha)
                except BaseException:
                    pass  # Even diagnostic allocation/output failure preserves the original failure.
            if self.final_image_known():
                try:
                    self.notary_post()
                except BaseException as error:
                    self.notary_unknown = True
                    self.errors.append({"stage": "final-image-failed-original-post", "type": type(error).__name__})
            raise

    def final_image_readonly_seal(self):
        # Same registered copy/returned FD and access flags, before native verify.
        entry, old_parent = self.final_image_output, self.final_image_output_root
        before, sha = entry["identity"], self.final_image_sha
        self.final_image_preimage_post()
        self.recheck_directory(old_parent)
        need(signature(os.fstat(entry["fd"])) == before
             == signature(os.stat(entry["name"], dir_fd=old_parent["fd"], follow_symlinks=False)), "final-image-owned-mode-transition")
        os.fchmod(entry["fd"], 0o444)
        os.fsync(entry["fd"])
        after = signature(os.fstat(entry["fd"]))
        need(after[:2] == before[:2] and after[2] == stat.S_IFREG | 0o444 and after[3:8] == before[3:8]
             and signature(os.stat(entry["name"], dir_fd=old_parent["fd"], follow_symlinks=False)) == after, "final-image-owned-mode-transition")
        entry["identity"] = after
        self.final_image_preimage_post()
        need(self.notary_stream(entry) == sha, "final-image-mode-bytes")
        self.final_image_preimage_post()

    def final_image_publish(self):
        need(self.final_image_known() and self.notary_key is None and self.mount_known and self.mount_detached
             and self.final_image_mount_verified, "final-image-publication-unknown")
        self.notary_post()
        self.stage = self.stager_io_pending = "final-image-owned-publication"
        entry, old_parent = self.final_image_output, self.final_image_output_root
        before, sha = entry["identity"], self.final_image_sha
        self.final_image_preimage_post()
        need(before[2] == stat.S_IFREG | 0o444 and signature(os.fstat(entry["fd"])) == before
             == signature(os.stat(entry["name"], dir_fd=old_parent["fd"], follow_symlinks=False)), "final-image-owned-mode-transition")
        after = before  # Sealed before verify; publication never refreshes later metadata.
        self.final_image_preimage_post()
        need(self.notary_stream(entry) == sha, "final-image-mode-bytes")
        self.final_image_preimage_post()
        self.recheck_directory(self.work_entry)
        os.mkdir(self.final_image_directory, 0o700, dir_fd=self.work_entry["fd"])
        parent = self.directory(self.work_entry, self.final_image_directory, "final-image-publication")
        need(stat.S_IMODE(parent["identity"][2]) == 0o700 and not os.listdir(parent["fd"]), "final-image-exclusive-publication")
        self.recheck_directory(old_parent)
        need(os.listdir(old_parent["fd"]) == [entry["name"]], "final-image-publication-input")
        self.final_image_preimage_post()
        os.rename(entry["name"], entry["name"], src_dir_fd=old_parent["fd"], dst_dir_fd=parent["fd"])
        moved = signature(os.fstat(entry["fd"]))
        need(moved[:8] == after[:8] and not os.listdir(old_parent["fd"])
             and os.listdir(parent["fd"]) == [entry["name"]]
             and signature(os.stat(entry["name"], dir_fd=parent["fd"], follow_symlinks=False)) == moved, "final-image-publication-original")
        entry.update(parent=parent["fd"], parent_entry=parent, identity=moved)
        self.final_image_roots = [(root, set() if root is old_parent else names) for root, names in self.final_image_roots]
        self.final_image_roots.append((parent, {entry["name"]}))
        os.fsync(parent["fd"]); os.fsync(old_parent["fd"]); os.fsync(self.work_entry["fd"])
        self.final_image_preimage_post()
        need(self.notary_stream(entry) == sha, "final-image-published-bytes")
        self.final_image_preimage_post()
        self.recheck_directory(old_parent); self.recheck_directory(parent)
        self.notary_clock()
        self.stager_io_pending = None
        self.notary_post()

    def finalize_image(self):
        need(self.phase in FINAL_IMAGE_PHASES and self.signing is not None
             and (self.environment.get("GITHUB_REF") == "refs/heads/verify/desktop-macos-preview"
                  or (self.phase == "finalize-image"
                      and self.environment.get("GITHUB_REF") in ("refs/heads/verify/desktop-macos-installed", CANDIDATE_REF))
                  or (self.phase == "finalize-remove-image" and self.removal
                      and self.candidate_removal_context is not None and self.candidate_removal_root is not None
                      and self.environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                      and self.environment.get("GITHUB_REF") == "refs/heads/task/ci-simplification-20261015"
                      and self.environment.get("GITHUB_WORKFLOW_REF") == "Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-candidate-consume.yml@refs/heads/task/ci-simplification-20261015"))
             and not any(name in self.environment for name in CREDENTIAL_VARIABLES + INSTALLER_CREDENTIAL_VARIABLES),
             "final-image-configured-purpose")
        self.notary_space(reserve=True)
        profile = self.source_original(NOTARY_PROFILE, "source-final-image-notary-profile", 1024)
        profile_body = self.read(profile)
        self.notary_profile = notary_service(profile_body, self.signing)
        self.package_sources.append((profile, profile_body))
        for filename in ("stage_macos_installed.py", "macos_android_helper_package.py"):
            entry = self.source_original("desktop/tools/" + filename, "source-final-image-driver",
                HELPER_SOURCE_BYTES if filename == "macos_android_helper_package.py" else 512 * 1024)
            self.package_sources.append((entry, self.read(entry)))
        expected, binding = self.final_removal_image_input() if self.removal else self.final_image_input()
        self.final_image_io("final-image-owned-copy", self.final_image_copy)
        self.notary_post()
        for name in ("notarytool", "stapler"):
            tool = self.notary_tool(name)
            result = self.final_image_call("final-image-resolve-" + name, ["/usr/bin/xcrun", "--find", name], limit=4096, developer=True)
            need(result.stdout in ((str(tool["fixed"]) + "\n").encode(), (str(tool["path"]) + "\n").encode())
                 and not result.stderr, "final-image-tool-original")
            self.notary_tool_post(tool)
        path = self.work / self.target_name / "final-image" / self.image_filename
        requirement = "=" + signing_requirement(self.signing, self.image_identifier)
        self.final_image_call("final-image-signature-before", ["/usr/bin/codesign", "--verify", "--strict", "--test-requirement", requirement, str(path)])
        submitted_sha = self.final_image_sha
        tool = str(self.notary_tools["notarytool"]["path"])
        with self.notary_key_scope() as key_arguments:
            result = self.final_image_call("final-image-submit", [tool, "submit", str(path), "--wait", "--output-format", "json", *key_arguments],
                                           maximum=1200, developer=True)
            submission = notary_submit_data(result.stdout, archive_name=self.image_filename)
            self.receipt["notarySubmission"] = dict(submission)
            invalid = Refused("final-image-notary-invalid") if submission["status"] == "Invalid" else None
            try:
                result = self.final_image_call("final-image-log", [tool, "log", submission["id"], *key_arguments], limit=1024 * 1024, developer=True)
                log = notary_log_data(result.stdout, submission, submitted_sha, archive_name=self.image_filename)
                if invalid is not None:
                    self.capture_notary_failure(result.stdout)
            except BaseException as error:
                if invalid is not None:
                    self.receipt["notaryLogFailure"] = {"type": type(error).__name__}
                    raise invalid from None
                raise
            if invalid is not None:
                raise invalid
        need(self.notary_key is None and self.receipt["notaryAuthentication"] == {"created": True, "closed": True, "retired": True},
             "final-image-notary-key-not-retired")
        tool = str(self.notary_tools["stapler"]["path"])
        self.final_image_call("final-image-staple", [tool, "staple", str(path)], developer=True)
        self.final_image_call("final-image-validate", [tool, "validate", str(path)], developer=True)
        self.final_image_call("final-image-signature-after", ["/usr/bin/codesign", "--verify", "--strict", "--test-requirement", requirement, str(path)])
        self.final_image_io("final-image-readonly-seal", self.final_image_readonly_seal)
        self.final_image_call("final-image-verify", ["/usr/bin/hdiutil", "verify", str(path)], maximum=120)
        self.package_name = "Remove.pkg" if self.removal else "Install.pkg"  # Actual mounted_post fixed roster, never the observation request alias.
        self.mount_placeholder = self.final_image_io("final-image-mount-placeholder", self.package_directory, "package-mount")
        self.normal_mount_host()
        attached = self.final_image_call("final-image-attach", ["/usr/bin/hdiutil", "attach", str(path), "-readonly", "-nobrowse",
            "-noautoopen", "-mountpoint", str(self.work / "package-mount"), "-plist"], maximum=60)
        self.mount_custody(attached, "final-image-readonly-mount")
        self.mount_inputs(expected, self.package_name)
        self.mounted_post()
        self.final_image_mount_verified = True
        self.detach_package_mount()
        self.notary_post()
        # Policy observation on this SAME finalized copy, not a quarantined
        # download or first-launch claim. Never change global policy or xattrs.
        result = self.final_image_call("final-image-policy-status", ["/usr/sbin/spctl", "--status"], limit=4096)
        need(result.stdout == b"assessments enabled\n" and not result.stderr, "final-image-policy-status-format")
        self.final_image_call("final-image-policy-assess", ["/usr/sbin/spctl", "--assess", "--type", "open",
            "--context", "context:primary-signature", "--ignore-cache", "--no-cache", str(path)])
        self.final_image_publish()
        self.notary_post()
        self.sha256 = self.final_image_sha
        self.receipt["finalImage"] = {"schemaVersion": 1, "kind": "mrk-final-removal-image" if self.removal else "mrk-final-user-image", **binding,
            "submittedSha256": submitted_sha, "imageBytes": self.final_image_output["identity"][6], "imageSha256": self.sha256,
            "imageMode": 0o444, "notaryProfileSha256": digest(profile_body), "submissionId": submission["id"], "status": submission["status"], **log,
            "strictSignatureBeforeAndAfter": True, "actualStaplerValidation": True, "actualImageVerification": True,
            "finalMountReadOnly": True, "finalMountOriginalsMatch": True, "originalMountDetached": self.mount_detached,
            "assessmentSubsystemEnabledBefore": True, "actualDiskImagePolicyAssessment": True,
            "assurance": "final-carrier-observation-not-downloaded-install-or-gatekeeper-authority"}
        self.final_image_complete = True
        self.notary_clock()

    def setup_package_quote(self):
        # Existing 96-live / 24576-original / 512MiB bounds, not a new budget.
        # Fifty future held entries cover the fixed six SOURCE leaves, helper
        # ancestry, six input roots/files, tool and product/signing inputs.
        # Twenty-four slots remain for tree/read/capture/credential transients.
        need(self.setup_package and not self.calls and self.credential_active is None
             and final_package_roles(False, "ordinary-image", setup=True) == XCODE_SETUP_COMPONENT_ROLES
                 + ("final-package-productbuild",) + FINAL_PACKAGE_ROLES
             and sum(e["fd"] is not None or not e["closed"] for e in self.entries) + 50 + 24 <= 96
             and len(self.entries) + 8192 <= 24576, "setup-package-prequote")
        self.stager._xcode_setup_allocation(4 * 1024 * 1024)(
            "setup-owned-control", 3 * self.stager.XCODE_SETUP_PROGRAM_LIMIT,
            2 * self.stager.XCODE_SETUP_PACKAGE_LIMIT, self.stager.XCODE_SETUP_PACKAGE_LIMIT)
        self.setup_quoted = True

    def setup_package_paths(self):
        return self.work / "xcode-setup-inputs"

    def setup_package_tree(self, name, files, *, root_mode=0o700):
        need(self.setup_package and self.setup_quoted and name in ("carrier", "scripts-original", "scripts-final"),
             "setup-fixed-tree")
        path = self.setup_package_paths() / name
        self.final_package_io("setup-" + name, self.stager.write_tree, path, files, root_mode=root_mode)
        root = self.directory(self.setup_input_root, name, "setup-" + name)
        self.setup_root_names.add(name)
        self.notary_roots.append({"entry": root, "path": path, "snapshot": self.notary_snapshot(root, path)})
        return root

    def setup_source_original(self, name, role):
        """Exact setup SOURCE hooks are executable; ordinary DATA stays unchanged."""
        need((self.setup_package or self.setup_verify) and self.source_entry is not None
             and name in ("CarrierInfo.plist", "Component.plist", "Distribution.xml", "InstallerReadMe.html",
                          "preinstall", "setup/postinstall"), "setup-source-purpose")
        relative = "desktop/macos-xcode-setup-inputs/" + name
        if name not in ("preinstall", "setup/postinstall"):
            return self.source_original(relative, role, 8192)
        parts = Path(relative).parts
        parent = self.descend(self.source_entry, parts[:-1])
        return self.original(parent, parts[-1], role, 8192, (0o555, 0o755))

    def prepare_setup_component(self):
        """Four original native calls, on fresh fixed inputs, before credentials."""
        need(self.setup_package and self.setup_quoted and not self.calls, "setup-component-purpose")
        selected = self.stager.source_build_selection(self.target)
        held_release = self.stager.build_release_data(self.read(self.release_entry), target=self.target)
        need((selected.package_version, selected.release) == (held_release["packageVersion"], held_release["release"]),
             "setup-held-release-selection")
        cargo = self.source_original("desktop/src-tauri/Cargo.toml", "setup-source-cargo-package", 128 * 1024)
        cargo_body = self.read(cargo)
        self.stager.xcode_setup_cargo_version(cargo_body, selected)
        self.package_sources.append((cargo, cargo_body))
        sources = {}
        for name in ("CarrierInfo.plist", "Component.plist", "Distribution.xml", "InstallerReadMe.html", "preinstall", "setup/postinstall"):
            entry = self.setup_source_original(name, "setup-source-" + name)
            body = self.read(entry)
            self.package_sources.append((entry, body))
            sources[name] = body
            if name in ("Distribution.xml", "InstallerReadMe.html"):
                self.install_presentation_sources.append((entry, body))
        validated = self.stager.xcode_setup_sources(selected)
        for name, body in sources.items():
            expected = body.replace(b"__MRK_PACKAGE_VERSION__", selected.package_version.encode("ascii"))
            need(expected == validated[name], "setup-held-source-correspondence")
        parent = self.descend(self.work_entry, ("xcode-setup-target", self.target, "release"))
        helper = self.original(parent, "mrk-macos-xcode-setup", "setup-signed-helper", self.stager.XCODE_SETUP_PROGRAM_LIMIT, (0o555,))
        program = self.read(helper)
        self.setup_helper_sha = self.environment.get("MRK_MACOS_XCODE_SETUP_SHA256")
        need(tool_hex(self.setup_helper_sha) and digest(program) == self.setup_helper_sha, "setup-signed-helper-anchor")
        self.final_package_inputs.append((helper, self.setup_helper_sha))
        scripts = self.stager.xcode_setup_script_files(program, self.setup_helper_sha, selected)
        def root_directory():
            self.recheck_directory(self.work_entry)
            os.mkdir("xcode-setup-inputs", 0o700, dir_fd=self.work_entry["fd"])
            self.setup_input_root = self.directory(self.work_entry, "xcode-setup-inputs", "setup-input-root")
            self.final_package_roots.append((self.setup_input_root, self.setup_root_names))
        self.final_package_io("setup-input-root", root_directory)
        self.setup_package_tree("carrier", {self.stager.XCODE_SETUP_CARRIER + "/Contents/Info.plist": (validated["CarrierInfo.plist"], 0o444)}, root_mode=0o755)
        self.setup_package_tree("scripts-original", scripts, root_mode=0o755)
        self.scripts_name = "xcode-setup-inputs/scripts-original"
        product_path = self.work / self.target_name / "product-input"
        self.final_package_io("setup-presentation", self.stager.prepare_xcode_setup_product_command,
                              argparse.Namespace(target=self.target, output=product_path))
        self.install_product_root = self.directory(self.target_entry, "product-input", "setup-presentation")
        self.notary_roots.append({"entry": self.install_product_root, "path": product_path,
                                  "snapshot": self.notary_snapshot(self.install_product_root, product_path)})
        def packager_directory():
            self.recheck_directory(self.setup_input_root)
            os.mkdir("packager", 0o700, dir_fd=self.setup_input_root["fd"])
            self.setup_packager_root = self.directory(self.setup_input_root, "packager", "setup-packager")
            self.setup_root_names.add("packager")
            self.final_package_roots.append((self.setup_packager_root, self.setup_packager_names))
        self.final_package_io("setup-packager-directory", packager_directory)
        self.notary_tool("pkgbuild")
        self.final_package_call("final-package-setup-pkgbuild", ["/usr/bin/pkgbuild", "--root", str(self.setup_package_paths() / "carrier"),
            "--scripts", str(self.work / self.scripts_name), "--component-plist", str(product_path / "Component.plist"),
            "--identifier", self.stager.XCODE_SETUP_ID, "--version", selected.package_version,
            "--install-location", "/Library", "--ownership", "recommended", "--compression", "legacy",
            "--min-os-version", "26.0", str(self.work / self.packager_filename)], maximum=60)
        self.setup_close_tool("pkgbuild")
        original = self.final_package_io("setup-original-component-audit", self.stager.xcode_setup_original_package,
            self.work / self.scripts_name, self.work / self.packager_filename, self.setup_helper_sha, selection=selected)
        self.setup_component_inputs = original
        def parts():
            path = self.setup_package_paths() / "parts"
            self.stager.write_tree(path, {"PackageInfo": (original["packageInfo"], 0o444), "Payload": (original["payload"], 0o444),
                                         "Bom": (original["bom"], 0o444)}, root_mode=0o700)
            self.setup_parts_root = self.directory(self.setup_input_root, "parts", "setup-parts")
            self.setup_root_names.add("parts")
            self.final_package_roots.append((self.setup_parts_root, self.setup_parts_names))
            for name in sorted(self.setup_parts_names):
                entry = self.original(self.setup_parts_root, name, "setup-original-" + name, 65536, (0o444,))
                self.final_package_inputs.append((entry, digest(self.read(entry))))
        self.final_package_io("setup-original-parts", parts)
        self.notary_tool("lsbom")
        result = self.final_package_call("final-package-setup-lsbom", ["/usr/bin/lsbom", "-p", "fmugs", str(self.setup_package_paths() / "parts/Bom")], maximum=10, limit=8192)
        need(not result.stderr, "setup-bom-stderr")
        self.stager.xcode_setup_bom_data(result.stdout, validated["CarrierInfo.plist"])
        self.setup_bom_verified = True
        self.setup_close_tool("lsbom")
        self.setup_package_tree("scripts-final", self.stager.xcode_setup_scripts_with_bom(scripts, original["bom"], self.setup_helper_sha, selected), root_mode=0o755)
        # Do not carry the signed helper's byte copies across native work.
        del program, scripts
        self.notary_tool("tar")
        self.final_package_call("final-package-setup-tar", ["/usr/bin/bsdtar", "-c", "-z", "-f", str(self.setup_package_paths() / "parts/Scripts"),
            "--format=odc", "--uid=0", "--gid=0", "--no-acls", "--no-xattrs", "--no-fflags", "--no-mac-metadata", "."])
        self.setup_close_tool("tar")
        def component_directory():
            os.mkdir("component", 0o700, dir_fd=self.setup_input_root["fd"])
            self.setup_component_root = self.directory(self.setup_input_root, "component", "setup-component")
            self.setup_root_names.add("component")
            self.final_package_roots.append((self.setup_component_root, self.setup_component_names))
        self.final_package_io("setup-component-directory", component_directory)
        self.notary_tool("xar")
        self.final_package_call("final-package-setup-xar", ["/usr/bin/xar", "-c", "-f", str(self.setup_package_paths() / "component" / self.component_filename),
            "--compression=none", "PackageInfo", "Scripts", "Bom", "Payload"])
        self.setup_close_tool("xar")
        need(self.setup_bom_verified and tuple(row["role"] for row in self.calls) == XCODE_SETUP_COMPONENT_ROLES,
             "setup-component-originals-required")

    def setup_close_tool(self, name):
        self.notary_post()
        value = self.notary_tools[name]
        self.close(value["entry"])
        need(value["entry"]["closed"] and not self.errors, "setup-tool-close-unknown")
        del self.notary_tools[name]

    def setup_adopt_prefix(self, role):
        need(self.setup_package and self.notary_mutation_pending and role in XCODE_SETUP_COMPONENT_ROLES,
             "setup-prefix-original-adoption")
        self.stage = self.stager_io_pending = role + "-adoption"
        if role == "final-package-setup-pkgbuild":
            parent, name, limit = self.setup_packager_root, "PrepareXcode-original.pkg", self.stager.XCODE_SETUP_PACKAGE_LIMIT
            need(os.listdir(parent["fd"]) == [name], "setup-pkgbuild-output-roster")
            self.setup_packager_names.add(name)
        elif role == "final-package-setup-tar":
            parent, name, limit = self.setup_parts_root, "Scripts", self.stager.XCODE_SETUP_PACKAGE_LIMIT
            need(set(os.listdir(parent["fd"])) == self.setup_parts_names | {name}, "setup-tar-output-roster")
            self.setup_parts_names.add(name)
        else:
            need(role == "final-package-setup-xar", "setup-prefix-mutation-role")
            parent, name, limit = self.setup_component_root, self.component_filename, self.stager.XCODE_SETUP_PACKAGE_LIMIT
            need(os.listdir(parent["fd"]) == [name], "setup-xar-output-roster")
            self.setup_component_names.add(name)
        entry = self.original(parent, name, role + "-original", limit, (0o400, 0o444, 0o600, 0o644))
        self.final_package_inputs.append((entry, self.notary_stream(entry)))
        if role == "final-package-setup-xar":
            self.install_component_inputs = (parent, entry)
        self.notary_clock()
        self.stager_io_pending = None
        self.notary_mutation_pending = False

    def installer_sources(self):
        """One SOURCE-selected Installer chain, distinct from Application use."""
        entry = self.source_original(INSTALLER_PROFILE, "source-installer-profile", 1024)
        body = self.read(entry)
        selected = installer_profile(body)
        need(selected is not None and self.signing is not None and selected["teamId"] == self.signing[0]
             and selected["leafSha1"] != self.signing[1], "installer-source-configuration")
        self.package_sources.append((entry, body))
        certificates = []
        for name, field in (("leaf", "leafSha256"), ("issuer", "issuerSha256"), ("root", "rootSha256")):
            certificate = self.source_original("desktop/packaging/macos-installer-certificates/" + name + ".der",
                                               "source-installer-" + name, 16384)
            value = self.read(certificate)
            need(digest(value) == selected[field], "installer-source-certificate")
            self.package_sources.append((certificate, value))
            certificates.append(value)
        need(hashlib.sha1(certificates[0]).hexdigest() == selected["leafSha1"], "installer-source-leaf")
        if self.install_product and not self.setup_package and not self.setup_verify:
            for name in self.stager.INSTALL_PRESENTATION:
                source = self.source_original("desktop/macos-installed-inputs/" + name,
                                              "source-install-presentation-" + name, 8192)
                original = (source, self.read(source))
                self.package_sources.append(original)
                self.install_presentation_sources.append(original)
        self.installer_selection, self.installer_certificates = selected, tuple(certificates)
        self.installer_profile_sha = digest(body)
        return selected

    def final_package_known(self):
        # An Installer callback may hold its own known credential context. All
        # other final-P work (including P8) requires that context to be absent.
        return (not self.errors and not self.notary_unknown and not self.notary_mutation_pending
                and not self.signing_mutation_pending and self.stager_io_pending is None
                and self.credential_known() and not self.credential_failed
                and all(row.get("returned") is True and row.get("capturesSettled") is True for row in self.calls))

    def final_package_io(self, label, function, *args, **kwargs):
        need(self.removal_final_active() and self.final_package_known() and not self.notary_retiring,
             "final-package-io-unknown")
        self.notary_clock()
        self.stage = label
        self.stager_io_pending = label
        result = function(*args, **kwargs)
        self.notary_clock()
        self.stager_io_pending = None  # No thrown parse/close token is transferable completion.
        return result

    def final_package_post(self, *, work=True):
        """The S2 post/clock supplies SOURCE, scripts, selected tools and P8."""
        self.notary_clock(work=work)
        self.stager.package_staple_preimage_post(self, need, work=work)
        for root, names in self.final_package_roots:
            self.recheck_directory(root)
            need(set(os.listdir(root["fd"])) == names, "final-package-directory-census")
        for entry, sha in self.final_package_inputs:
            need(self.notary_stream(entry, work=work) == sha, "final-package-input-changed")
        if self.final_package_output is not None:
            need(self.notary_stream(self.final_package_output, work=work) == self.final_package_sha,
                 "final-package-output-changed")
        if self.target_entry is not None:
            self.recheck_directory(self.target_entry)
            names = {"tmp"}
            if self.final_package_output_root is not None:
                names.add("signed-package")
            if self.install_product_root is not None:
                names.add("product-input")
            if self.notary_key is not None:
                names.add("notary-key")
            need(set(os.listdir(self.target_entry["fd"])) == names, "final-package-target-census")
            # The original tool TMPDIR may contain its own intermediate files;
            # preserve its directory identity rather than adopt a replacement.
            self.directory(self.target_entry, "tmp", "final-package-tmp")
        self.notary_clock(work=work)

    def final_package_audit(self, entry, path):
        self.notary_post()
        size, sha = entry["identity"][6], self.notary_stream(entry)
        audit = (self.stager.audit_xcode_setup_product_command if self.setup_package else
                 self.stager.audit_install_product_command if self.install_product else self.stager.audit_command)
        try:
            result = self.final_package_io("final-package-original-audit", audit,
                argparse.Namespace(target=self.target, fixture=False, store_runtime=self.selected_package_store(), scripts=self.work / self.scripts_name, package=path,
                                   original_package=self.work / self.packager_filename,
                                   **({"expected_helper": self.setup_helper_sha} if self.setup_package else self.removal_package_audit_arguments())))
        except self.stager.Refused as error:
            values = BaseException.args.__get__(error)
            if (self.install_product is True and type(error) is self.stager.Refused
                    and type(values) is tuple and len(values) == 1 and type(values[0]) is str
                    and len(values[0]) <= 96 and values[0] in self.stager.INSTALL_PRODUCT_AUDIT_REASONS):
                raise Refused(values[0]) from error
            raise  # Preserve unknown failures and the pending original-audit latch.
        need(type(result) is dict and result.get("packageSize") == size and type(result["packageSize"]) is int
             and result.get("packageSha256") == sha and self.notary_stream(entry) == sha,
             "final-package-audit-original")
        self.notary_post()
        return result

    def final_package_adopt_signed(self):
        # Only the one expected output of our returned productsign original.
        # This pending span also bars credential cleanup if acquisition fails.
        self.stage = self.stager_io_pending = "final-package-signed-output"
        parent = self.final_package_output_root
        self.recheck_directory(parent)
        need(os.listdir(parent["fd"]) == [self.package_filename], "final-package-signed-roster")
        entry = self.original(parent, self.package_filename, "final-package-signed-original", self.stager.MAX_BYTES,
                              (0o400, 0o444, 0o600, 0o644))
        self.final_package_output = entry
        self.final_package_sha = self.notary_stream(entry)
        self.final_package_roots.append((parent, {self.package_filename}))
        self.notary_clock()
        self.stager_io_pending = None
        self.signing_mutation_pending = False

    def final_package_appended(self, before, before_sha):
        self.stager.package_staple_appended(self, before, before_sha, need)

    def final_package_call(self, role, argv, *, maximum=30, limit=65536, developer=False):
        roles = final_package_roles(self.removal, self.environment["MRK_MACOS_PACKAGE_ROLE"], setup=self.setup_package)
        current = self.removal_final_calls()
        need(self.removal_final_active() and self.final_package_known() and not self.notary_retiring
             and len(current) < len(roles) and role == roles[len(current)],
             "final-package-fixed-role-order")
        need((self.notary_key is not None) == (role in ("final-package-submit", "final-package-log"))
             and (self.credential_active is None or role == "final-package-sign"
                  and self.credential_active.get("purpose") == "installer"), "final-package-private-role")
        bounds = {"final-package-resolve-notarytool": (30, 4096), "final-package-resolve-stapler": (30, 4096),
                  "final-package-sign": (60, 65536), "final-package-submit": (1200, 65536),
                  "final-package-log": (30, 1024 * 1024),
                  "final-package-setup-pkgbuild": (60, 65536), "final-package-setup-lsbom": (10, 8192)}
        need((maximum, limit) == bounds.get(role, (30, 65536)), "final-package-original-bound")
        self.notary_post()
        now, endpoint = self.notary_clock()
        timeout = min(maximum, (endpoint - now - 3_000_000_000) // 1_000_000_000)
        need(timeout >= 1, "final-package-original-settlement-reserve")
        environment = self.native_environment()
        if developer:
            environment["DEVELOPER_DIR"] = str(NOTARY_XCODE)
        self.stage = role
        changing = role == "final-package-staple"
        before = self.final_package_output["identity"] if changing else None
        before_sha = self.final_package_sha if changing else None
        if changing:
            self.receipt["packageStapleObservation"] = self.stager.package_staple_observation()
        prefix_mutation = self.setup_package and role in XCODE_SETUP_MUTATION_ROLES
        self.notary_mutation_pending = changing or role == "final-package-productbuild" or prefix_mutation
        self.signing_mutation_pending = role == "final-package-sign"
        cwd = self.work
        if role in ("final-package-setup-tar", "final-package-setup-xar"):
            need(self.setup_package, "setup-prefix-purpose")
            cwd = self.setup_package_paths() / ("scripts-final" if role.endswith("-tar") else "parts")
            environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC", "COPYFILE_DISABLE": "1"}
        try:
            result = self.call(role, argv, environment, cwd=cwd, timeout=timeout, limit=limit)
            self.notary_clock()
            if prefix_mutation:
                self.setup_adopt_prefix(role)
            elif role == "final-package-productbuild":
                self.final_package_adopt_product()
            elif role == "final-package-sign":
                self.final_package_adopt_signed()
            elif changing:
                self.final_package_appended(before, before_sha)
            self.notary_post()
            return result
        except BaseException:
            if self.final_package_known():
                try:
                    self.notary_post()
                except BaseException as error:
                    self.notary_unknown = True
                    self.errors.append({"stage": "final-package-failed-original-post", "type": type(error).__name__})
            raise

    def final_package_publish(self):
        need(self.final_package_known() and self.credential_active is None and self.notary_key is None,
             "final-package-publication-unknown")
        self.notary_post()
        self.stage = self.stager_io_pending = "final-package-mode-and-publication"
        entry, old_parent = self.final_package_output, self.final_package_output_root
        before, sha = entry["identity"], self.final_package_sha
        os.fchmod(entry["fd"], 0o444)
        os.fsync(entry["fd"])
        after = signature(os.fstat(entry["fd"]))
        need(after[:2] == before[:2] and after[2] == stat.S_IFREG | 0o444 and after[3:8] == before[3:8]
             and signature(os.stat(entry["name"], dir_fd=old_parent["fd"], follow_symlinks=False)) == after,
             "final-package-owned-mode-transition")
        entry["identity"] = after
        need(self.notary_stream(entry) == sha, "final-package-mode-bytes")
        self.recheck_directory(self.work_entry)
        os.mkdir(self.final_package_name, 0o700, dir_fd=self.work_entry["fd"])
        parent = self.directory(self.work_entry, self.final_package_name, "final-package-publication")
        need(stat.S_IMODE(parent["identity"][2]) == 0o700 and not os.listdir(parent["fd"]), "final-package-fresh-publication")
        self.recheck_directory(old_parent)
        need(os.listdir(old_parent["fd"]) == [entry["name"]], "final-package-move-input")
        os.rename(entry["name"], entry["name"], src_dir_fd=old_parent["fd"], dst_dir_fd=parent["fd"])
        moved = signature(os.fstat(entry["fd"]))
        need(moved[:8] == after[:8] and not os.listdir(old_parent["fd"])
             and os.listdir(parent["fd"]) == [entry["name"]]
             and signature(os.stat(entry["name"], dir_fd=parent["fd"], follow_symlinks=False)) == moved,
             "final-package-move-original")
        entry.update(parent=parent["fd"], parent_entry=parent, identity=moved)
        self.final_package_roots = [(root, set() if root is old_parent else names) for root, names in self.final_package_roots]
        self.final_package_roots.append((parent, {entry["name"]}))
        os.fsync(parent["fd"]); os.fsync(old_parent["fd"]); os.fsync(self.work_entry["fd"])
        need(self.notary_stream(entry) == sha, "final-package-published-bytes")
        self.recheck_directory(old_parent); self.recheck_directory(parent)
        self.notary_clock()
        self.stager_io_pending = None
        self.notary_post()

    def build_install_product(self):
        """One productbuild original inside the existing final-package owner.

        The component and UI SOURCE are held inputs, never final P. The new
        outer file is adopted only after that same original returns zero and
        its captures/close receipts are complete. Unknown effects stay pending.
        """
        need(self.install_product and self.phase in ("finalize-package", "finalize-xcode-setup-package")
             and tuple(row["role"] for row in self.calls) == (XCODE_SETUP_COMPONENT_ROLES if self.setup_package else ())
             and len(self.install_presentation_sources) == 2, "fixed-install-product-purpose")
        component_path = self.setup_package_paths() / "component" if self.setup_package else self.work / "package-component"
        if self.setup_package:
            need(self.setup_bom_verified and self.install_component_inputs is not None, "setup-component-required")
            component_parent, component = self.install_component_inputs
        else:
            component_parent = self.directory(self.work_entry, "package-component", "install-product-component-directory")
            need(os.listdir(component_parent["fd"]) == [self.component_filename], "install-product-component-roster")
            self.final_package_roots.append((component_parent, {self.component_filename}))
            component = self.original(component_parent, self.component_filename, "install-product-component", self.stager.MAX_BYTES,
                                      (0o444, 0o600, 0o644))
            self.install_component_inputs = (component_parent, component)
            self.final_package_inputs.append((component, self.notary_stream(component)))
        component_sha = self.notary_stream(component)
        component_audit = self.final_package_io("install-product-component-audit",
            self.stager.audit_xcode_setup_package_command if self.setup_package else self.stager.audit_command,
            argparse.Namespace(target=self.target, fixture=False, store_runtime=self.selected_package_store(), scripts=self.work / self.scripts_name,
                package=component_path / self.component_filename, original_package=self.work / self.packager_filename,
                **({"expected_helper": self.setup_helper_sha} if self.setup_package else {})))
        need(type(component_audit) is dict and component_audit.get("packageSha256") == component_sha
             and component_audit.get("packageSize") == component["identity"][6], "install-product-component-audit")
        product_input = self.work / self.target_name / "product-input"
        prepared = (None if self.setup_package else self.final_package_io("install-product-presentation-prepare",
            self.stager.prepare_install_product_command, argparse.Namespace(target=self.target, output=product_input)))
        root = self.directory(self.target_entry, "product-input", "install-product-presentation-directory")
        self.install_product_root = root
        resources = self.directory(root, "resources", "install-product-resource-directory")
        need(set(os.listdir(root["fd"])) == ({"Distribution", "resources", "Component.plist"} if self.setup_package else {"Distribution", "resources"})
             and os.listdir(resources["fd"]) == ["InstallerReadMe.html"], "install-product-presentation-roster")
        definition = self.original(root, "Distribution", "install-product-distribution", 8192, (0o444,))
        readme = self.original(resources, "InstallerReadMe.html", "install-product-readme", 8192, (0o444,))
        source_definition, source_readme = (self.read(entry) for entry, _body in self.install_presentation_sources)
        selection = self.stager.build_release_data(self.read(self.release_entry), target=self.target)
        need(source_definition.count(b"__MRK_PACKAGE_VERSION__") == 1, "install-product-source-version")
        expected = source_definition.replace(b"__MRK_PACKAGE_VERSION__", selection["packageVersion"].encode("ascii"))
        need(self.read(definition) == expected and self.read(readme) == source_readme
             and (self.setup_package or type(prepared) is dict and prepared.get("distributionSha256") == digest(expected)
                  and prepared.get("readMeSha256") == digest(source_readme)), "install-product-presentation-source")
        if not self.setup_package:
            self.notary_roots.append({"entry": root, "path": product_input,
                                      "snapshot": self.notary_snapshot(root, product_input)})
        # The retained root/snapshot binds these same named originals on every
        # later POST. Consume these initial validation FDs before the native
        # child, rather than growing the existing simultaneous-FD allowance.
        for entry in (readme, definition, resources):
            self.close(entry)
            need(entry["closed"] and not self.errors, "install-product-presentation-close")
        def output_directory():
            self.recheck_directory(self.work_entry)
            os.mkdir(self.unsigned_package_name, 0o700, dir_fd=self.work_entry["fd"])
            parent = self.directory(self.work_entry, self.unsigned_package_name, "install-product-output-directory")
            self.install_product_output_root = parent
            need(stat.S_IMODE(parent["identity"][2]) == 0o700 and not os.listdir(parent["fd"]),
                 "install-product-output-fresh")
            self.final_package_roots.append((parent, set()))
        self.final_package_io("install-product-output-directory", output_directory)
        self.notary_tool("productbuild")
        result = self.final_package_call("final-package-productbuild", ["/usr/bin/productbuild",
            "--distribution", str(product_input / "Distribution"),
            "--package-path", str(component_path),
            "--resources", str(product_input / "resources"),
            str(self.work / self.unsigned_package_name / self.package_filename)])
        need(type(result.returncode) is int and result.returncode == 0 and self.install_product_original is not None,
             "install-product-original-required")
        return self.install_product_original

    def final_package_adopt_product(self):
        # A build start, timeout or nonzero result is not an outer package. This
        # exact named file is observed only after the actual successful original.
        need(self.install_product and self.notary_mutation_pending and self.install_product_original is None,
             "install-product-adoption-order")
        self.stage = self.stager_io_pending = "install-product-original-adoption"
        parent = self.install_product_output_root
        self.recheck_directory(parent)
        need(os.listdir(parent["fd"]) == [self.package_filename], "install-product-output-roster")
        entry = self.original(parent, self.package_filename, "install-product-unsigned-original", self.stager.MAX_BYTES,
                              (0o444, 0o600, 0o644))
        self.install_product_original = entry
        sha = self.notary_stream(entry)
        self.final_package_inputs.append((entry, sha))
        self.final_package_roots = [(root, {self.package_filename} if root is parent else names)
                                    for root, names in self.final_package_roots]
        self.notary_clock()
        self.stager_io_pending = None
        self.notary_mutation_pending = False

    def retire_install_product_inputs(self):
        # Only after the returned productbuild, its full POST and the actual
        # outer audit. These originals have no further native users; the final
        # package remains bound to the original pkgbuild/Scripts/SOURCE inputs.
        need(self.install_product and self.final_package_known() and self.install_component_inputs is not None,
             "install-product-input-retirement")
        self.notary_post()
        parent, component = self.install_component_inputs
        tool = self.notary_tools["productbuild"]
        for entry in (component, parent, tool["entry"]):
            self.close(entry)
            need(entry["closed"] and not self.errors, "install-product-input-close")
        self.final_package_inputs = [(entry, sha) for entry, sha in self.final_package_inputs if entry is not component]
        self.final_package_roots = [(root, names) for root, names in self.final_package_roots if root is not parent]
        del self.notary_tools["productbuild"]
        self.install_component_inputs = None
        self.notary_post()

    def selected_package_store(self):
        """Hold the same fixed SOURCE selector for ordinary package consumers."""
        if self.setup_package:
            need(self.environment.get("MRK_MACOS_STORE_RUNTIME") is None, "setup-package-no-store-runtime")
            return False
        if hasattr(self, "package_store_runtime"):
            return self.package_store_runtime
        mode = self.environment.get("MRK_MACOS_STORE_RUNTIME")
        need(mode in (None, "signed-component"), "package-store-mode")
        enabled = mode is not None and not self.removal
        if enabled:
            entry = self.source_original("desktop/" + self.stager.SIGNED_STORE_SELECTION,
                "source-package-store-selection", self.stager.SIGNED_STORE_SELECTION_LIMIT)
            body = self.read(entry)
            self.stager.signed_store_selection_data(body, target=self.target)
            self.package_sources.append((entry, body))
        self.package_store_runtime = enabled
        return enabled

    def finalize_package(self):
        need(self.removal_final_active() and self.signing is not None
             and (self.phase == "prepare-removal-observers" or not any(name in self.environment for name in CREDENTIAL_VARIABLES)), "final-package-configured-purpose")
        self.notary_space(reserve=True)  # Existing3GiB floor plus2GiB additional reservation.
        if self.setup_package:
            self.setup_package_quote()
        self.installer_sources()
        profile = self.source_original(NOTARY_PROFILE, "source-final-package-notary-profile", 1024)
        profile_body = self.read(profile)
        self.notary_profile = notary_service(profile_body, self.signing)
        self.package_sources.append((profile, profile_body))
        for filename in ("stage_macos_installed.py", "macos_android_helper_package.py"):
            source = self.source_original("desktop/tools/" + filename, "source-final-package-driver",
                HELPER_SOURCE_BYTES if filename == "macos_android_helper_package.py" else 512 * 1024)
            self.package_sources.append((source, self.read(source)))
        self.selected_package_store()
        if self.setup_package:
            self.prepare_setup_component()
        else:
            scripts = self.directory(self.work_entry, self.scripts_name, "final-package-scripts")
            self.notary_roots.append({"entry": scripts, "path": self.work / self.scripts_name,
                                      "snapshot": self.notary_snapshot(scripts, self.work / self.scripts_name)})
            packager = self.original(self.work_entry, self.packager_filename, "final-package-packager-original", self.stager.MAX_BYTES,
                                    (0o444, 0o600, 0o644))
            self.final_package_inputs.append((packager, self.notary_stream(packager)))
        if not self.install_product:
            parent = self.directory(self.work_entry, self.unsigned_package_name, "final-package-unsigned")
            need(os.listdir(parent["fd"]) == [self.package_filename], "final-package-unsigned-roster")
            self.final_package_roots.append((parent, {self.package_filename}))
            unsigned = self.original(parent, self.package_filename, "final-package-unsigned-original", self.stager.MAX_BYTES,
                                     (0o444, 0o600, 0o644))
            self.final_package_inputs.append((unsigned, self.notary_stream(unsigned)))
        else:
            unsigned = self.build_install_product()
        unsigned_audit = self.final_package_audit(unsigned, self.work / self.unsigned_package_name / self.package_filename)
        if self.install_product:
            self.retire_install_product_inputs()
        def output_directory():
            self.recheck_directory(self.target_entry)
            os.mkdir("signed-package", 0o700, dir_fd=self.target_entry["fd"])
            self.final_package_output_root = self.directory(self.target_entry, "signed-package", "final-package-signed-directory")
            need(stat.S_IMODE(self.final_package_output_root["identity"][2]) == 0o700
                 and not os.listdir(self.final_package_output_root["fd"]), "final-package-signed-directory-empty")
        self.final_package_io("final-package-output-directory", output_directory)
        for name in ("notarytool", "stapler"):
            tool = self.notary_tool(name)
            result = self.final_package_call("final-package-resolve-" + name, ["/usr/bin/xcrun", "--find", name], limit=4096, developer=True)
            need(result.stdout in ((str(tool["fixed"]) + "\n").encode(), (str(tool["path"]) + "\n").encode())
                 and not result.stderr, "final-package-tool-discovery-original")
            self.notary_tool_post(tool)
        path = self.work / self.target_name / "signed-package" / self.package_filename
        with self.credential_scope("installer"):
            need(self.final_package_output is None and not os.listdir(self.final_package_output_root["fd"]), "final-package-sign-output-absent")
            self.final_package_call("final-package-sign", ["/usr/bin/productsign", "--sign", self.installer_selection["identityCommonName"],
                "--keychain", str(self.credential_active["path"] / "identity.keychain-db"), "--timestamp",
                str(self.work / self.unsigned_package_name / self.package_filename), str(path)], maximum=60)
        need(self.credential_active is None and self.credential_known() and len(self.credential_calls) == 20 + (self.removal_final_context["credentials"] if self.phase == "prepare-removal-observers" else 0),
             "final-package-installer-context-not-retired")
        signed_audit = self.final_package_audit(self.final_package_output, path)
        need({key: value for key, value in signed_audit.items() if key not in ("packageSha256", "packageSize")}
             == {key: value for key, value in unsigned_audit.items() if key not in ("packageSha256", "packageSize")},
             "final-package-signed-audit-changed")
        checked = self.final_package_call("final-package-signature-before", ["/usr/sbin/pkgutil", "--check-signature", str(path)])
        need(not checked.stderr, "final-package-signature-stderr")
        before_signature = package_signature_data(checked.stdout, self.installer_selection, self.installer_certificates, path)
        signed_size, signed_sha = self.final_package_output["identity"][6], self.final_package_sha
        tool = str(self.notary_tools["notarytool"]["path"])
        with self.notary_key_scope() as key_arguments:
            result = self.final_package_call("final-package-submit", [tool, "submit", str(path), "--wait", "--output-format", "json", *key_arguments],
                                             maximum=1200, developer=True)
            submission = notary_submit_data(result.stdout, archive_name=self.package_filename)
            self.receipt["notarySubmission"] = dict(submission)
            invalid = Refused("final-package-notary-invalid") if submission["status"] == "Invalid" else None
            try:
                result = self.final_package_call("final-package-log", [tool, "log", submission["id"], *key_arguments],
                                                 limit=1024 * 1024, developer=True)
                log = notary_log_data(result.stdout, submission, signed_sha, archive_name=self.package_filename)
                if invalid is not None:
                    self.capture_notary_failure(result.stdout)
            except BaseException as error:
                if invalid is not None:
                    self.receipt["notaryLogFailure"] = {"type": type(error).__name__}
                    raise invalid from None
                raise
            if invalid is not None:
                raise invalid
        need(self.notary_key is None and self.receipt["notaryAuthentication"] == {"created": True, "closed": True, "retired": True},
             "final-package-notary-key-not-retired")
        tool = str(self.notary_tools["stapler"]["path"])
        self.final_package_call("final-package-staple", [tool, "staple", str(path)], developer=True)
        self.final_package_call("final-package-validate", [tool, "validate", str(path)], developer=True)
        checked = self.final_package_call("final-package-signature-after", ["/usr/sbin/pkgutil", "--check-signature", str(path)])
        need(not checked.stderr, "final-package-signature-stderr")
        after_signature = package_signature_data(checked.stdout, self.installer_selection, self.installer_certificates, path, after_staple=True)
        need(after_signature == before_signature, "final-package-signature-changed")
        final_audit = self.final_package_audit(self.final_package_output, path)
        need({key: value for key, value in final_audit.items() if key not in ("packageSha256", "packageSize")}
             == {key: value for key, value in unsigned_audit.items() if key not in ("packageSha256", "packageSize")},
             "final-package-stapled-audit-changed")
        self.final_package_publish()
        self.sha256 = self.final_package_sha
        self.receipt["finalPackage"] = {"schemaVersion": 1, "kind": "mrk-final-xcode-setup-package" if self.setup_package else "mrk-final-remover-package" if self.removal else "mrk-final-installer-package",
            "unsignedBytes": unsigned["identity"][6], "unsignedSha256": unsigned_audit["packageSha256"],
            "signedBytes": signed_size, "signedSha256": signed_sha, "packageBytes": self.final_package_output["identity"][6],
            "packageSha256": self.sha256, "packageMode": 0o444, "originalPackageSha256": unsigned_audit["originalPackageSha256"],
            "packageInfoSha256": final_audit["packageInfoSha256"], "scriptFileCount": final_audit["scriptFileCount"],
            "installerProfileSha256": self.installer_profile_sha, "notaryProfileSha256": digest(profile_body),
            "teamId": self.installer_selection["teamId"], "certificateSha256": before_signature["certificateSha256"],
            "submissionId": submission["id"], "status": submission["status"], **log,
            "trustedSignatureBeforeAndAfter": True, "trustedTimestampBeforeAndAfter": True,
            "actualStaplerValidation": True, "signedPrefixUnchanged": True, "completeScriptsAudited": True,
            "assurance": "final-package-observation-not-installed-or-final-carrier-authority"}
        if self.setup_package:
            need(self.setup_bom_verified and final_audit["helperSha256"] == self.setup_helper_sha,
                 "setup-final-originals-required")
            self.receipt["finalPackage"].update(payloadSha256=final_audit["payloadSha256"], bomSha256=final_audit["bomSha256"],
                helperSha256=self.setup_helper_sha, finalDestinationPayloadEntries=4,
                assurance="final-setup-package-observation-not-installed-or-xcode-setup-authority")
        self.final_package_complete = True
        self.notary_clock()

    def package_finalization_input(self, original, body):
        """Require the actual closed preceding original and exact final P."""
        self.package_clock()
        self.installer_sources()
        profile = self.source_original(NOTARY_PROFILE, "source-package-notary-profile", 1024)
        profile_body = self.read(profile)
        notary_service(profile_body, self.signing)
        self.package_sources.append((profile, profile_body))
        status = self.original(self.work_entry, self.package_status_name, "final-package-status", 8, (0o400, 0o444, 0o600, 0o644))
        status_body = self.read(status)
        need(status_body == b"0\n", "package-finalization-original-status")
        receipt = self.original(self.work_entry, self.package_receipt_name, "final-package-receipt", 16384, (0o600,))
        receipt_body = self.read(receipt)
        value = final_package_receipt(receipt_body,
                                      self.environment if self.prepared_binding is None else self.prepared_binding.finalization_environment(self.environment),
                                      self.target, self.installer_selection,
                                      self.installer_profile_sha, digest(profile_body), len(body), digest(body),
                                      self.image_release, digest(self.read(self.release_entry)), remove=self.removal,
                                      runtime_stager=self.stager if self.selected_package_store() else None,
                                      product_source=None if self.candidate_removal_context is None else self.candidate_removal_context["productSource"])
        need(self.read(original) == body, "package-finalization-package-post")
        self.package_outputs.extend(((status, digest(status_body)), (receipt, digest(receipt_body))))
        self.receipt["finalPackageReceiptSha256"] = digest(receipt_body)
        self.package_clock()
        return value

    def native_environment(self):
        return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(self.work),
                "TMPDIR": str(self.work / self.target_name / "tmp"), "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}

    def open(self):
        fd = os.open(self.work, READ_FLAGS | os.O_DIRECTORY)
        self.work_entry = self.register(fd, "work", "directory")
        self.work_entry["identity"] = directory_identity(os.fstat(fd))
        need(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700
             and directory_identity(self.work.lstat()) == self.work_entry["identity"], "work-original")
        need(shutil.rmtree.avoids_symlink_attacks, "descriptor-relative-cleanup-required")
        os.mkdir(self.target_name, 0o700, dir_fd=fd)  # Exclusive, never an old target.
        self.target_entry = self.directory(self.work_entry, self.target_name, "target")
        os.mkdir("tmp", 0o700, dir_fd=self.target_entry["fd"])

    def python_clock(self, *, work=True):
        now = time.monotonic_ns()
        need(type(now) is int and self.python_started is not None and self.python_observed <= now,
             "python-monotonic-clock")
        self.python_observed = now
        limit = self.python_started + (300 if work else 360) * 1_000_000_000
        need(now < limit, "python-group-deadline")
        return now, limit

    def python_known(self):
        return (not self.errors and self.credential_known()
                and not self.signing_mutation_pending and self.stager_io_pending is None and not self.python_mutation_pending
                and all(row.get("returned") is True and row.get("capturesSettled") is True for row in self.calls))

    def python_io(self, label, function, *args, **kwargs):
        self.python_clock()
        need(self.python_known() and not self.credential_failed and not self.python_retiring, "python-originals-unknown")
        self.stage = label
        self.stager_io_pending = label
        # A raised external DATA operation has no transferable close proof.
        value = function(*args, **kwargs)
        self.python_clock()
        self.stager_io_pending = None
        return value

    def python_call(self, role, argv, *, maximum=30, limit=65536):
        need(self.python_known() and not self.credential_failed and not self.python_retiring, "python-originals-unknown")
        self.python_post()
        now, endpoint = self.python_clock()
        self.stage = role
        result = self.call(role, argv, self.native_environment(), cwd=self.work,
                           timeout=package_timeout_data(now, endpoint, maximum), limit=limit)
        self.python_clock()
        need(self.python_known(), "python-originals-unknown")
        return result

    def python_directory(self, name):
        self.python_clock()
        need(self.python_known() and not self.python_retiring and type(name) is str
             and self.stager.safe_path(name), "python-owned-relative-directory")
        if name in self.python_directories:
            entry = self.python_directories[name]
            self.recheck_directory(entry)
            return entry
        parts = name.split("/")
        parent = self.target_entry if len(parts) == 1 else self.python_directory("/".join(parts[:-1]))
        self.recheck_directory(parent)
        self.stager_io_pending = "python-directory-create"
        os.mkdir(parts[-1], 0o700, dir_fd=parent["fd"])
        entry = self.directory(parent, parts[-1], "python-directory-" + name)
        self.python_directories[name] = entry
        self.python_clock()
        self.stager_io_pending = None
        return entry

    def python_write(self, name, body, mode):
        self.python_clock()
        need(self.python_known() and not self.python_retiring and self.stager.safe_path(name)
             and name not in self.python_files and type(body) is bytes and len(body) <= MAX_HELPER
             and mode in (0o444, 0o555, 0o755), "python-exclusive-output")
        parts = name.split("/")
        parent = self.target_entry if len(parts) == 1 else self.python_directory("/".join(parts[:-1]))
        self.recheck_directory(parent)
        self.stager_io_pending = "python-file-create"
        fd = os.open(parts[-1], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent["fd"])
        entry = self.register(fd, "python-file-" + name, "file", parent["fd"], parts[-1])
        entry["parent_entry"] = parent
        offset = 0
        while offset < len(body):
            written = os.write(fd, body[offset:])
            need(type(written) is int and written > 0, "python-short-write")
            offset += written
        os.fchmod(fd, mode)
        os.fsync(fd)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
             and info.st_gid == os.getgid() and info.st_size == len(body) and stat.S_IMODE(info.st_mode) == mode,
             "python-created-original")
        entry["identity"] = signature(info)
        need(self.read(entry) == body, "python-created-readback")
        self.python_files[name] = (entry, body)
        self.python_clock()
        self.stager_io_pending = None
        return entry

    def python_post(self):
        self.python_clock(work=not self.python_retiring)
        need(self.python_known(), "python-originals-unknown")
        self.recheck_directory(self.target_entry)
        for name, entry in self.python_directories.items():
            self.recheck_directory(entry)
            expected = {path[len(name) + 1:].split("/")[0] for path in (*self.python_directories, *self.python_files)
                        if path.startswith(name + "/")}
            need(set(os.listdir(entry["fd"])) == expected, "python-directory-members-changed")
        need(set(os.listdir(self.target_entry["fd"]))
             == {path.split("/")[0] for path in (*self.python_directories, *self.python_files)},
             "python-target-members-changed")
        for entry, body in self.python_files.values():
            need(self.read(entry) == body, "python-owned-file-post")
        for entry, body in self.python_input_originals:
            need(self.read(entry) == body, "python-input-original-post")
        self.python_clock(work=not self.python_retiring)

    def python_directory_mode(self, entry, mode):
        self.python_clock(work=not self.python_retiring)
        need(self.python_known() and mode in (0o555, 0o700), "python-directory-mode-purpose")
        self.recheck_directory(entry)
        before = entry["identity"]
        self.stager_io_pending = "python-directory-mode"
        os.fchmod(entry["fd"], mode)
        after = directory_identity(os.fstat(entry["fd"]))
        expected = before[:2] + (stat.S_IFDIR | mode,) + before[3:]
        need(after == expected and directory_identity(os.stat(entry["name"], dir_fd=entry["parent"],
             follow_symlinks=False)) == expected, "python-directory-mode-original")
        entry["identity"] = after
        self.recheck_directory(entry)
        self.python_clock(work=not self.python_retiring)
        self.stager_io_pending = None

    def python_seal(self):
        # Seal only our newly created probe tree, never an input/ancestor.
        for name in sorted(self.python_directories, key=lambda value: (-value.count("/"), value)):
            if name == "signed-payload" or name.startswith("signed-payload/"):
                self.python_directory_mode(self.python_directories[name], 0o555)
        self.python_post()

    def python_prepare(self, modules=None):
        self.python_clock()
        self.python_directories["tmp"] = self.directory(self.target_entry, "tmp", "python-tmp")
        self.python_input_originals.extend(((self.profile_entry, self.service_profile),
                                           (self.producer_profile_entry, self.producer_profile)))
        self.python_pins = dict(PYTHON_SUPPLIERS[self.target])
        data = self.directory(self.work_entry, "python-supplier-transport", "python-original-transport")
        need(set(os.listdir(data["fd"])) == {"supplier.tar", "supplier-receipt.json"}, "python-transport-two-originals")
        receipt_entry = self.original(data, "supplier-receipt.json", "python-original-receipt", 1024 * 1024,
                                      (0o400, 0o444, 0o600, 0o644))
        archive_entry = self.original(data, "supplier.tar", "python-original-tar", 64 * 1024 * 1024,
                                      (0o400, 0o444, 0o600, 0o644))
        receipt, archive = self.read(receipt_entry), self.read(archive_entry)
        self.python_input_originals.extend(((receipt_entry, receipt), (archive_entry, archive)))
        need(digest(receipt) == self.python_pins["receiptSha256"] and digest(archive) == self.python_pins["tarSha256"],
             "python-original-six-pins")
        lock = self.source_original(self.stager.source_lock_input(self.target), "python-original-source-lock", 16384)
        lock_body = self.read(lock)
        self.python_input_originals.append((lock, lock_body))
        provenance, rows = self.stager.fresh_supplier_receipt(receipt, self.python_pins["receiptSha256"], lock_body, target=self.target)
        source_names = ("macos_python_supplier_transport.py", "macos_cpython_orchestrator.py", "macos_cpython_source_build.py",
                        "macos_cpython_source_probe.py", "stage_macos_installed.py", "macos_android_helper_package.py")
        for name in source_names:
            entry = self.source_original("desktop/tools/" + name, "python-source-" + name, 1024 * 1024)
            self.python_input_originals.append((entry, self.read(entry)))
        if modules is None:
            def load_modules():
                loaded = tuple(load_data(self.checkout, name, "_mrk_python_signing_" + str(index))
                               for index, name in enumerate(source_names[:4]))
                for entry, body in self.python_input_originals:
                    need(self.read(entry) == body, "python-import-source-post")
                return loaded
            modules = self.python_io("python-source-import", load_modules)
        transport, matcher, builder, probe = modules
        self.python_modules = modules
        original = transport.project_archive(archive, rows, self.stager)
        need(set(original) == set(rows), "python-original-complete-inventory")
        python = original[self.stager.SIGNED_PYTHON_PATH][0]
        need(0 < len(python) <= MAX_HELPER, "python-executable-bound")
        self.python_original = original
        self.python_original_receipt = receipt
        self.python_inventory = provenance["inventorySha256"]
        capacity = os.fstatvfs(self.target_entry["fd"])
        need(capacity.f_frsize > 0 and capacity.f_bavail * capacity.f_frsize
             >= sum(len(body) for body, _mode in original.values()) + 2 * MAX_HELPER,
             "python-copy-storage-reserve")
        def source_snapshot():
            need(builder.DATA.known, "python-source-data-finality")
            result = builder.source_snapshot(self.checkout, self.target)
            need(builder.DATA.known, "python-source-data-finality")
            return result
        self.python_source_snapshot = self.python_io("python-source-snapshot", source_snapshot)
        entitlements = self.source_original("desktop/packaging/macos-empty-entitlements.plist", "python-empty-entitlements", 1024)
        empty = self.read(entitlements)
        self.python_input_originals.append((entitlements, empty))
        need(digest(empty) == self.stager.SIGNED_ENTITLEMENTS_SHA256, "python-empty-entitlement-source")
        self.python_empty = empty
        path = self.work / self.target_name / "signing-slot/python3"
        old = self.python_write("signing-slot/python3", python, 0o755)
        self.python_post()
        with self.credential_scope("python"):
            now, endpoint = self.python_clock()
            self.stage = "python-sign"
            self.python_mutation_pending = True
            self.call("python-sign", python_sign_command(path, self.checkout / "desktop/packaging/macos-empty-entitlements.plist",
                      self.phase, self.signing), self.native_environment(), cwd=self.work,
                      timeout=package_timeout_data(now, endpoint, 30), limit=65536)
            self.python_clock()
            slot = self.python_directories["signing-slot"]
            self.recheck_directory(slot)
            need(set(os.listdir(slot["fd"])) == {"python3"}, "python-sign-slot-members")
            output = self.original(slot, "python3", "python-signed-original", MAX_HELPER, (0o755,))
            signed = self.read(output)
            matcher.macho_content_valid(python, signed, self.arch, signing=True)
            try:
                self.python_flags = python_code_flags(signed, self.arch, self.phase, matcher)
            except Refused as error:
                if type(error) is Refused and error.args == ("python-signature-superblob",):
                    try:
                        self.receipt["pythonSignatureDiagnostic"] = {
                            "schemaVersion": 1, "available": False, "authority": "original-byte-data-only"}
                        self.receipt["pythonSignatureDiagnostic"] = python_signature_diagnostic(python, signed, self.arch, matcher)
                    except BaseException:
                        pass  # Optional observation must not replace the identical primary refusal.
                raise
            self.close(old)
            need(old["closed"] and not self.errors, "python-input-slot-close-unknown")
            self.python_files["signing-slot/python3"] = (output, signed)
            self.python_mutation_pending = False
            requirement = [] if self.phase == "python-engineering" else ["--test-requirement", "=" + signing_requirement(self.signing, PYTHON_IDENTIFIER)]
            verified = self.python_call("python-verify", ["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", *requirement, str(path)])
            need(not verified.stdout and not verified.stderr and self.read(output) == signed, "python-strict-signature-original")
        derived = dict(original)
        derived[self.stager.SIGNED_PYTHON_PATH] = (signed, 0o555)
        for name, (body, mode) in sorted(derived.items()):
            self.python_write("signed-payload/" + name, body, mode)
        self.python_directory("probe-scratch")
        self.python_seal()
        inventory = [{"path": name, "size": len(body), "sha256": digest(body), "mode": mode}
                     for name, (body, mode) in sorted(derived.items())]
        builtins = sorted(set(builder.BOOTSTRAP + builder.INTRINSIC + builder.OPTIONAL))
        need(len(builtins) == 61, "python-exact-builtin-roster")
        context = {"schemaVersion": 1, "target": self.target, "payload": str(self.work / self.target_name / "signed-payload"),
                   "checkout": str(self.checkout), "scratch": str(self.work / self.target_name / "probe-scratch"),
                   "sourceCommit": self.environment["GITHUB_SHA"], "builtins": builtins, "files": inventory,
                   "sourceFiles": {name: row["sha256"] for name, row in self.python_source_snapshot.items()}}
        context_body = self.stager.canonical(context)
        need(len(context_body) <= 512 * 1024, "python-probe-context-bound")
        self.python_write("python-probe-context.json", context_body, 0o444)
        context_path = self.work / self.target_name / "python-probe-context.json"
        executable = self.work / self.target_name / "signed-payload" / self.stager.SIGNED_PYTHON_PATH
        for role in ("modules", "loader", "tls", "cancellation"):
            result = self.python_call("python-" + role, [str(executable), "-I", "-S", "-B",
                str(self.checkout / "desktop/tools/macos_cpython_source_probe.py"), role, self.target, str(context_path)],
                maximum=60, limit=512 * 1024)
            builder.probe_result(result.stdout, role, self.target, probe)
            self.python_post()
        need(self.python_io("python-source-post", source_snapshot)
             == self.python_source_snapshot, "python-source-post-changed")
        self.python_post()
        self.python_signed = signed
        self.sha256 = digest(signed)
        self.receipt.update(pythonOriginalInventorySha256=self.python_inventory, pythonSignedSha256=self.sha256,
                            pythonCodeDirectoryFlags=self.python_flags, pythonPurpose=self.phase,
                            pythonNativeProbesPassed=True, signedRuntimeManifestComputed=False,
                            developerIdOrNotarizationQualified=False, productReady=False)

    def python_retirement(self):
        if (self.phase not in PYTHON_PHASES or self.python_started is None or self.target_entry is None
                or not self.python_known()):
            return
        self.python_retiring = True  # No command can be dispatched after this point.
        try:
            self.stage = "python-known-target-retirement"
            self.python_clock(work=False)
            self.python_post()
            for name in sorted(self.python_directories, key=lambda value: (value.count("/"), value)):
                self.python_directory_mode(self.python_directories[name], 0o700)
        except BaseException as error:
            self.errors.append({"stage": "python-target-retained", "type": type(error).__name__})

    def python_capsule(self):
        need(self.phase == "python-shipping" and self.receipt["passed"] is True
             and self.python_signed is not None and self.signing is not None, "python-shipping-capsule-required")
        def row(body):
            return {"path": self.stager.SIGNED_PYTHON_PATH, "size": len(body), "mode": 0o555, "sha256": digest(body)}
        signer = {"sourceCommit": self.environment["GITHUB_SHA"], "workflow": self.environment["GITHUB_WORKFLOW_REF"],
                  "runId": self.environment["GITHUB_RUN_ID"], "runAttempt": self.environment["GITHUB_RUN_ATTEMPT"],
                  "identifier": PYTHON_IDENTIFIER, "teamIdentifier": self.signing[0], "leafCertificateSha1": self.signing[1],
                  "producerProfileSha256": digest(self.producer_profile), "serviceProfileSha256": digest(self.service_profile),
                  "entitlementsSha256": digest(self.python_empty), "codeDirectoryFlags": self.python_flags, "timestampRequested": True}
        return {"schemaVersion": 1, "kind": self.stager.SIGNED_PYTHON_KIND, "purpose": "configured-shipping",
                "target": self.target, "pythonVersion": "3.14.7", "originalSupplier": self.python_pins,
                "originalInventorySha256": self.python_inventory,
                "originalPython": row(self.python_original[self.stager.SIGNED_PYTHON_PATH][0]), "signedPython": row(self.python_signed),
                "signer": signer, "nativeEvidence": {record["role"]: {key: record[key] for key in ("stdoutSha256", "stderrSha256")}
                                                        for record in self.calls},
                "originalsKnown": True, "sourcePost": True, "supplierPost": True, "nonimagePost": True,
                "targetRetired": True, "closesKnown": True, "outerExitRequired": True,
                "assurance": "pinned-native-signature-and-probes-not-notarization-or-installed-authority"}
    def python_publish_final(self, name, body, mode):
        # No new process owner. Reopen only the previously held work ORIGINAL;
        # capsule files remain inadmissible until all closes and outer exit zero.
        need(self.phase in PYTHON_PHASES and type(body) is bytes and self.work_entry is not None,
             "python-publication-purpose")
        facts_name = "android-helper-" + self.phase + ".json"
        need((name == facts_name and mode == 0o600 and len(body) <= 16384)
             or (self.phase == "python-shipping" and self.receipt["passed"] is True and self.python_known()
                 and self.receipt["targetRetired"] and self.receipt["originalClosesKnown"]
                 and ((name == "python3" and mode == 0o555 and body == self.python_signed)
                      or (name == "python-signed-receipt.json" and mode == 0o444 and len(body) <= 16384))),
             "python-publication-closed-output")
        self.python_clock(work=False)
        original = self.work_entry["identity"]
        directory_entry = file_entry = None
        primary = None
        try:
            directory = os.open(self.work, READ_FLAGS | os.O_DIRECTORY)
            directory_entry = self.register(directory, "python-publication-directory", "publication-directory")
            need(directory_identity(os.fstat(directory)) == directory_identity(self.work.lstat()) == original,
                 "python-publication-work-changed")
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
            file_entry = self.register(fd, "python-publication-" + name, "file")
            offset = 0
            while offset < len(body):
                count = os.write(fd, body[offset:])
                need(type(count) is int and count > 0, "python-publication-short-write")
                offset += count
                self.python_clock(work=False)
            os.fchmod(fd, mode)
            os.fsync(fd)
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                 and info.st_gid == os.getgid() and info.st_size == len(body) and stat.S_IMODE(info.st_mode) == mode,
                 "python-publication-original")
            need(os.pread(fd, len(body) + 1, 0) == body
                 and signature(os.fstat(fd)) == signature(info)
                 == signature(os.stat(name, dir_fd=directory, follow_symlinks=False)), "python-publication-readback")
            os.fsync(directory)
            need(directory_identity(os.fstat(directory)) == directory_identity(self.work.lstat()) == original,
                 "python-publication-work-post")
            self.python_clock(work=False)
        except BaseException as error:
            primary = error
        finally:
            for entry in (file_entry, directory_entry):
                if entry is not None:
                    self.close(entry)
                    if not entry["closed"] and primary is None:
                        primary = Refused("python-publication-close-unknown")
            self.receipt["originalClosesKnown"] = (self.credential_known() and self.credential_active is None and not self.signing_mutation_pending
                                               and self.stager_io_pending is None and not self.python_mutation_pending
                                                   and all(entry["closed"] for entry in self.entries))
            try:
                need(directory_identity(self.work.lstat()) == original, "python-publication-work-after-close")
                self.python_clock(work=False)
            except BaseException as error:
                self.errors.append({"stage": "python-publication-post", "type": type(error).__name__})
                if primary is None:
                    primary = error
        if primary is not None:
            self.receipt["passed"] = False
            self.receipt.setdefault("failure", {"stage": "python-final-publication", "type": type(primary).__name__,
                                               "reason": "original-publication-refused"})
            raise primary

    def image_binding(self):
        self.stage = "source-image-binding"
        self.release_entry = self.source_original(self.release_input, "source-image-release", self.stager.BUILD_RELEASE_LIMIT)
        body = self.read(self.release_entry)
        value = self.stager.build_release_data(body, target=self.target)
        source = (self.candidate_removal_context["productSource"] if self.candidate_removal_context is not None else
                  self.environment["GITHUB_SHA"] if self.prepared_binding is None else self.prepared_binding.source)
        release = value["release"]
        need(re.fullmatch(r"[0-9a-f]{40}", source) is not None and source != "0" * 40
             and source == self.environment["MRK_MACOS_INSTALL_SOURCE_COMMIT"]
             and type(release) is str and 0 < len(release) < 64 and release.isascii(), "source-image-binding")
        self.image_source, self.image_release = source, release
        self.image_package_version = value["packageVersion"]
        self.receipt.update(imageSourceCommit=source, imageReleaseId=release, imageReleaseSourceSha256=digest(body))
        return body

    def prepare(self):
        if self.target == INTEL_TARGET:
            self.stage = "resident-dependency-fetch"
            # Separate acquisition from the unchanged compiler deadline. The
            # same original call must return0 with settled captures first.
            self.call("resident-fetch", [direct_rust_tools(self.target)[0], "fetch", "--manifest-path",
                      str(self.checkout / WORKSPACE / "Cargo.toml"), "--locked", "--target", self.target],
                      build_environment(self.environment, self.work, self.image_release, target=self.target),
                      cwd=self.checkout / WORKSPACE, timeout=120, limit=4 * 1024 * 1024)
        self.stage = "separate-resident-image-compiler"
        result = self.call("build", [direct_rust_tools(self.target)[0], "build", "--manifest-path", str(self.checkout / WORKSPACE / "Cargo.toml"),
                           "--locked", *(("--offline",) if self.target == INTEL_TARGET else ()), "--release", *(("--config", RESIDENT_CARGO_OVERRIDE) if self.target == INTEL_TARGET else ()),
                           "--jobs", "1", "--target", self.target,
                           "--lib", "--message-format=json-render-diagnostics"],
                           build_environment(self.environment, self.work, self.image_release, target=self.target),
                           cwd=self.checkout / WORKSPACE, timeout=720 if self.target == INTEL_TARGET else 480, limit=4 * 1024 * 1024)
        artifact(result.stdout, self.checkout, self.work / self.target_name,
            package_version=self.image_package_version, build_target=self.target)
        self.stage = "compiler-original-copy"
        release = self.descend(self.target_entry, (self.target, "release"))
        original = self.original(release, RESIDENT_IMAGE, "compiler-artifact", MAX_HELPER, (0o700, 0o755), alias=True)
        if original["identity"][3] == 2:
            deps = self.directory(release, "deps", "compiler-deps")
            names = os.listdir(deps["fd"])
            need(len(names) <= 8192, "compiler-alias-directory-bound")
            # Cargo cdylib outputs have the fixed un-hashed name in deps; never
            # accept a guessed executable alias or sign either linked original.
            aliases = [name for name in names if name == RESIDENT_IMAGE]
            need(len(aliases) == 1, "one-compiler-alias")
            alias = self.original(deps, aliases[0], "compiler-alias", MAX_HELPER, (0o700, 0o755), alias=True)
            need(alias["identity"] == original["identity"], "compiler-alias-original")
        body = self.read(original)
        self.stager.image_macho(body, "resident", target=self.target)
        self.receipt["residentImageCargoArtifact"] = {
            "targetKind": "cdylib", "crate": IMAGE_TARGET, "package": HELPER, "target": self.target,
            "entrypoint": "src/lib.rs", "profileTest": False, "features": [],
            "cargoMessagesSha256": digest(result.stdout), "binarySha256BeforeSigning": digest(body),
            "binaryBytesBeforeSigning": len(body), "instrumented": False}
        self.publish(RESIDENT_IMAGE, body, mode=0o755)
        need(self.read(original) == body, "compiler-original-copy-changed")
        for entry in self.entries:
            if entry["role"] in ("compiler-artifact", "compiler-alias"):
                self.close(entry)
                need(entry["closed"], "compiler-artifact-close-unknown")
        with self.credential_scope("resident-image"):
            self.stage = "resident-image-source-selected-signing"
            self.call("resident-image-sign", ["/usr/bin/codesign", "--force", "--sign", "-" if self.signing is None else self.signing[1],
                      "--identifier", IDENTIFIER + ".image", "--options", "runtime",
                      "--entitlements", str(self.checkout / "desktop/packaging/macos-empty-entitlements.plist"),
                      "--timestamp=none" if self.signing is None else "--timestamp", str(self.work / RESIDENT_IMAGE)],
                      self.native_environment(), cwd=self.work, timeout=30, limit=65536)
            signed = self.original(self.work_entry, RESIDENT_IMAGE, "signed-resident-image", MAX_HELPER, (0o755,))
            body = self.read(signed)
            self.stager.image_macho(body, "resident", target=self.target)
            self.strict_verify(signed, body, "resident-image-verify-signed", self.work / RESIDENT_IMAGE)
        self.resident_image_sha256 = digest(body)
        self.receipt.update(residentImageSha256=self.resident_image_sha256, residentImageBytes=len(body),
                            residentImageOriginal=signed["identity"],
                            residentImageSigning=("ad-hoc" if self.signing is None else "source-selected-leaf") + "-fixed-identifier-runtime-empty-entitlements-strictly-verified")
        self.prepare_entry()
        self.prepare_facade("desktop")
        self.prepare_facade("resident")

    def prepare_facade(self, role):
        need(role in ("desktop", "resident"), "fixed-facade-role")
        name = DESKTOP_FACADE if role == "desktop" else HELPER
        self.stage = role + "-facade-compiler"
        paths = ("desktop/native/macos-installed-entry/" + role + "_facade.c",
                 "desktop/native/macos-installed-entry/gate.c", "desktop/native/macos-installed-entry/gate.h",
                 "desktop/native/macos-installed-entry/fixed_paths.h", "desktop/native/macos-installed-entry/image_abi.h",
                 "desktop/native/macos-installed-native/src/native.m", "desktop/src-tauri/src/macos_install_fixed_paths.rs")
        originals = [(path, self.source_original(path, role + "-facade-source-" + Path(path).name,
                     256 * 1024 if path == paths[5] else 128 * 1024)) for path in paths]
        bodies = [self.read(entry) for _path, entry in originals]
        destination = self.work / self.target_name / name
        self.call(role + "-facade-build", ["/usr/bin/xcrun", "--sdk", "macosx", "clang", "-x", "c", "-std=c11",
                  "-Wall", "-Wextra", "-Werror", "-O2", "-arch", self.arch, "-mmacosx-version-min=26.0",
                  "-DMRK_ENTRY_METADATA_ONLY=1", '-DMRK_IMAGE_SOURCE_COMMIT="' + self.image_source + '"',
                  '-DMRK_IMAGE_RELEASE_ID="' + self.image_release + '"',
                  str(self.checkout / paths[0]), str(self.checkout / paths[1]), str(self.checkout / paths[5]),
                  "-o", str(destination)],
                  dict(self.native_environment(), DEVELOPER_DIR=self.environment["DEVELOPER_DIR"]),
                  cwd=self.checkout, timeout=30, limit=65536)
        need(all(self.read(entry) == body for (_path, entry), body in zip(originals, bodies)), "facade-source-changed")
        original = self.original(self.target_entry, name, role + "-facade-compiler-artifact", 1024 * 1024, (0o700, 0o755))
        body = self.read(original)
        self.stager.entry_macho(body, target=self.target)
        self.publish(name, body, mode=0o755)
        need(self.read(original) == body, "facade-compiler-original-changed")
        self.receipt[role + "FacadeSources"] = [
            {"path": path, "bytes": len(source), "sha256": digest(source)}
            for (path, _entry), source in zip(originals, bodies)]
        self.receipt[role + "FacadeSha256BeforeSigning"] = digest(body)
        self.receipt[role + "FacadeBytesBeforeSigning"] = len(body)
        self.receipt[role + "FacadeOriginalBeforeSigning"] = original["identity"]
        self.close(original)
        need(original["closed"], "facade-compiler-artifact-close-unknown")
        if role == "desktop":
            self.desktop_facade_sha256 = digest(body)
            return
        with self.credential_scope("helper"):
            self.stage = "helper-source-selected-signing"
            self.call("sign", ["/usr/bin/codesign", "--force", "--sign", "-" if self.signing is None else self.signing[1], "--identifier", IDENTIFIER,
                               "--options", "runtime", "--entitlements", str(self.checkout / "desktop/packaging/macos-empty-entitlements.plist"),
                               "--timestamp=none" if self.signing is None else "--timestamp", str(self.work / HELPER)],
                      self.native_environment(), cwd=self.work, timeout=30, limit=65536)
            signed = self.original(self.work_entry, HELPER, "signed-helper", MAX_HELPER, (0o755,))
            body = self.read(signed)
            self.stager.entry_macho(body, target=self.target)
            self.strict_verify(signed, body, "verify-signed", self.work / HELPER)
        self.sha256 = digest(body)
        self.receipt.update(helperSha256=self.sha256, helperBytes=len(body), helperOriginal=signed["identity"],
                            signing=("ad-hoc-fixed-identifier-runtime-empty-entitlements-strictly-verified" if self.signing is None else
                                      "source-selected-developer-id-fixed-requirement-runtime-empty-entitlements"))


    def prepare_entry(self):
        """One fixed C/libSystem-only compile through this same original owner."""
        self.stage = "fixed-installed-entry-compiler"
        paths = ("desktop/native/macos-installed-entry/entry.c", "desktop/native/macos-installed-entry/gate.c",
                 "desktop/native/macos-installed-entry/gate.h", "desktop/native/macos-installed-entry/fixed_paths.h",
                 "desktop/native/macos-installed-native/src/native.m", "desktop/src-tauri/src/macos_install_fixed_paths.rs")
        originals = [(name, self.source_original(name, "entry-source-" + Path(name).name,
                     256 * 1024 if name == paths[4] else 128 * 1024)) for name in paths]
        bodies = [self.read(entry) for _name, entry in originals]
        destination = self.work / self.target_name / ENTRY
        self.call("entry-build", ["/usr/bin/xcrun", "--sdk", "macosx", "clang", "-x", "c", "-std=c11",
                  "-Wall", "-Wextra", "-Werror", "-O2", "-arch", self.arch, "-mmacosx-version-min=26.0",
                  "-DMRK_ENTRY_METADATA_ONLY=1", str(self.checkout / paths[0]), str(self.checkout / paths[1]),
                  str(self.checkout / paths[4]), "-o", str(destination)],
                  dict(self.native_environment(), DEVELOPER_DIR=self.environment["DEVELOPER_DIR"]),
                  cwd=self.checkout, timeout=30, limit=65536)
        need(all(self.read(entry) == body for (_name, entry), body in zip(originals, bodies)), "entry-source-changed")
        original = self.original(self.target_entry, ENTRY, "entry-compiler-artifact", 1024 * 1024, (0o700, 0o755))
        body = self.read(original)
        self.stager.entry_macho(body, target=self.target)
        self.publish(ENTRY, body, mode=0o755)
        need(self.read(original) == body, "entry-compiler-original-changed")
        self.entry_sha256 = digest(body)
        self.receipt.update(entryBinarySha256BeforeSigning=self.entry_sha256, entryBytes=len(body),
                            entryOriginal=original["identity"], entryLoaderPolicy="libSystem-only-no-native-initializers",
                            entrySources=[{"path": name, "bytes": len(body), "sha256": digest(body)}
                                          for (name, _entry), body in zip(originals, bodies)],
                            entryExecutionObserved=False, maintenanceQualified=False)

    def strict_verify(self, original, body, role, path):
        self.stage = role
        requirement = [] if self.signing is None else ["--all-architectures", "--test-requirement",
            "=" + signing_requirement(self.signing, IDENTIFIER + ".image" if path.name == RESIDENT_IMAGE else IDENTIFIER)]
        result = self.call(role, ["/usr/bin/codesign", "--verify", "--strict", *requirement, str(path)],
                           self.native_environment(), cwd=self.work, timeout=30, limit=65536)
        need(not result.stdout and not result.stderr and self.read(original) == body, "strict-original-verification")

    def verify_staged(self, expected, expected_image):
        need(type(expected) is str and re.fullmatch(r"[0-9a-f]{64}", expected), "expected-helper-digest")
        need(type(expected_image) is str and re.fullmatch(r"[0-9a-f]{64}", expected_image), "expected-resident-image-digest")
        tool_inputs = self.tool_staged_inputs()
        self.stage = "staged-helper-original"
        contents = self.descend(self.work_entry, ("app", "Mobile Release Kit.app", "Contents", "Helpers", "MobileReleaseKitPayload.app", "Contents"))
        helpers = self.directory(contents, "Helpers", "staged-helpers")
        original = self.original(helpers, HELPER, "staged-helper", MAX_HELPER, (0o555,))
        body = self.read(original)
        need(digest(body) == expected, "staged-helper-signature-bytes-changed")
        self.stager.entry_macho(body, target=self.target)
        frameworks = self.directory(contents, "Frameworks", "staged-frameworks")
        image = self.original(frameworks, RESIDENT_IMAGE, "staged-resident-image", MAX_HELPER, (0o555,))
        image_body = self.read(image)
        need(digest(image_body) == expected_image, "staged-resident-image-signature-bytes-changed")
        self.stager.image_macho(image_body, "resident", target=self.target)
        daemons = self.descend(contents, ("Library", "LaunchDaemons"))
        plist = self.original(daemons, IDENTIFIER + ".plist", "staged-service-plist", 4096, (0o444, 0o644))
        source_plist = self.source_original("desktop/macos-installed-inputs/" + IDENTIFIER + ".plist", "source-service-plist", 4096)
        expected_plist = self.read(source_plist)
        parsed = self.stager.plistlib.loads(expected_plist)
        need(parsed == {"Label": IDENTIFIER, "BundleProgram": "Contents/Helpers/" + HELPER,
                        "MachServices": {IDENTIFIER: True}} and parsed["MachServices"][IDENTIFIER] is True,
             "source-service-plist")
        need(self.read(plist) == expected_plist, "staged-service-plist")
        self.strict_verify(original, body, self.phase, self.work / "app/Mobile Release Kit.app" / self.stager.ANDROID_HELPER)
        self.strict_verify(image, image_body, self.phase + "-resident-image",
                           self.work / "app/Mobile Release Kit.app" / self.stager.RESIDENT_IMAGE)
        need(self.read(original) == body and self.read(image) == image_body
             and self.read(plist) == self.read(source_plist) == expected_plist, "staged-service-group-changed")
        self.tool_staged_post(tool_inputs)
        self.sha256, self.resident_image_sha256 = expected, expected_image
        self.receipt.update(helperSha256=expected, helperBytes=len(body), helperOriginal=original["identity"],
                            residentImageSha256=expected_image, residentImageBytes=len(image_body),
                            residentImageOriginal=image["identity"])

    def removal_package_audit_arguments(self):
        if not self.removal:
            return {}
        expected = self.environment.get("MRK_MACOS_REMOVER_SHA256")
        if self.phase == "prepare-removal-observers":
            need(self.removal_final_active() and self.removal_prep_phase in self.stager.removal_fixture_case_data(self.removal_case),
                 "observer-audit-same-final-context")
            context = self.removal_final_context
            expected = context["program"]
            fixture = {"removal_fixture_role": "observer-" + self.removal_prep_phase,
                       "removal_fixture_correlation": self.removal_correlation,
                       "removal_fixture_binding": self.removal_binding}
            need(context["fixture"] == fixture, "observer-audit-fixed-source-template")
            return {"remove": True, "expected_remover": expected, **fixture}
        fixture = {}
        if self.environment.get("GITHUB_REF") == REMOVAL_REF:
            case, _correlation = removal_context_data(self.environment, self.target)
            if case == "abrupt":
                fixture["removal_fixture_role"] = "abrupt"
        return {"remove": True, "expected_remover": expected, **fixture}

    def removal_input_control(self, name, role, limit=16384):
        original = self.original(self.work_entry, name, role, limit, (0o600,))
        body = self.read(original)
        self.package_outputs.append((original, digest(body)))
        return final_package_json(body, limit, "removal-preparation-control-format")

    def removal_previous_owner(self, phase):
        need(phase in ("package-install", "package-remove"), "removal-previous-fixed-owner")
        status = self.original(self.work_entry, phase + ".status", "removal-previous-owner-status", 8, (0o600,))
        need(self.read(status) == b"0\n", "removal-previous-original-owner-zero")
        self.package_outputs.append((status, digest(b"0\n")))
        value = self.removal_input_control("android-helper-" + phase + ".json", "removal-previous-owner")
        need(type(value) is dict and type(value.get("schemaVersion")) is int and value["schemaVersion"] == 1
             and value.get("phase") == phase and value.get("target") == self.target
             and value.get("source") == value.get("workflowSource") == self.image_source
             and value.get("runId") == self.environment["GITHUB_RUN_ID"]
             and value.get("runAttempt") == self.environment["GITHUB_RUN_ATTEMPT"]
             and value.get("packageRole") == "ordinary-image" and value.get("productReady") is False
             and all(value.get(key) is True for key in ("passed", "originalClosesKnown", "targetRetired", "outerFinalityRequired")),
             "removal-previous-owner-source")
        roles = self.stager.PACKAGING_CALL_ROLES if phase == "package-install" else REMOVE_PACKAGE_ROLES
        calls = value.get("originalCalls")
        need(type(calls) is list and len(calls) == len(roles)
             and all(type(row) is dict and row.get("role") == role and row.get("entered") is True
                 and row.get("returned") is True and row.get("capturesSettled") is True and type(row.get("returncode")) is int
                 and (row["returncode"] == 0 or phase == "package-install" and role in ("installer-log-cursor", "installer-log-capture")
                      and row["returncode"] == 1) for row, role in zip(calls, roles)), "removal-previous-owner-originals")
        if phase == "package-install":
            observed = value.get("distribution")
            need(type(observed) is dict and observed.get("kind") == "mrk-ordinary-package-observed-v2"
                 and observed.get("target") == self.target and observed.get("release") == self.image_release
                 and all(observed.get(key) is True for key in ("originalInstallerReturnedZero", "sameRequestV2Readback",
                                                              "originalMountDetached", "groupEndpointMet")),
                 "removal-baseline-install-readback")
        return value

    def removal_preparation_inputs(self):
        self.removal_selection = self.stager.BuildSelection(self.target,
            self.stager.build_release_data(self.read(self.release_entry), target=self.target)["packageVersion"], self.image_release)
        self.removal_previous_owner("package-install")
        owner = self.removal_previous_owner("package-remove")
        distribution = owner.get("removalDistribution")
        need(type(distribution) is dict and distribution.get("kind") == "mrk-remove-package-emitted-image-v1"
             and distribution.get("target") == self.target and distribution.get("release") == self.image_release
             and distribution.get("groupEndpointMet") is True and distribution.get("installerEntered") is False
             and distribution.get("removalExecuted") is False, "removal-target-package-preparation")
        root = self.directory(self.work_entry, "remove-producer-root", "removal-target-three-originals")
        need(set(self.removal_names(root, 3)) == set(REMOVAL_INPUT_NAMES), "removal-target-preparation-roster")
        self.package_roots.append((root, set(REMOVAL_INPUT_NAMES)))
        files, bodies = {}, {}
        for leaf in REMOVAL_INPUT_NAMES:
            limit = self.stager.MAX_BYTES if leaf == "Remove.pkg" else 16384 if leaf.endswith("json") else 512
            entry = self.original(root, leaf, "removal-target-preparation-input", limit, (0o444,))
            # The package is streamed by the original final-P observer here;
            # only its bounded sidecars are retained as DATA.
            sha = self.notary_stream(entry) if self.phase == "prepare-removal-observers" else self.removal_stream(entry, limit=limit)[0][1]
            files[leaf] = {"bytes": entry["identity"][6], "sha256": sha}
            if leaf != "Remove.pkg":
                bodies[leaf] = self.read(entry)
            self.package_outputs.append((entry, sha))
        need(files["Remove.pkg"] == {"bytes": distribution["packageBytes"], "sha256": distribution["packageSha256"]}
             and files["remove-producer.json"]["sha256"] == distribution["descriptorSha256"]
             and files["remove-producer.sig"]["sha256"] == distribution["signatureSha256"]
             and distribution["inventorySha256"] == self.environment["MRK_MACOS_INSTALL_INVENTORY_SHA256"]
             and distribution["removerExecutableSha256"] == self.environment["MRK_MACOS_REMOVER_SHA256"],
             "removal-target-preparation-source")
        binding = {"sourceCommit": self.image_source, "target": self.target, "release": self.image_release,
                   "inventorySha256": distribution["inventorySha256"], "packageSha256": files["Remove.pkg"]["sha256"],
                   "removeDescriptorSha256": files["remove-producer.json"]["sha256"],
                   "removeSignatureSha256": files["remove-producer.sig"]["sha256"]}
        self.stager.removal_fixture_binding_data(binding, selection=self.removal_selection)
        image = distribution.get("userImage")
        need(type(image) is dict and set(image) == {"file", "sha256", "bytes"}
             and image["file"] == "MobileReleaseKit-Remove.dmg" and self.stager.maintenance_hex(image["sha256"], 64)
             and type(image["bytes"]) is int and 0 < image["bytes"] <= self.stager.MAX_BYTES, "removal-target-image-binding")
        self.removal_binding, self.removal_target_files, self.removal_target_image = binding, files, image
        return binding

    def removal_credential_records_post(self):
        if self.phase != "prepare-removal-observers":
            return
        roster = removal_credential_roster_data()
        need(tuple(row["role"] for row in self.credential_calls) == roster[:len(self.credential_calls)]
             and len(self.credential_calls) <= 158, "observer-credential-cumulative-roster")
        actual = sys.getsizeof(self.credential_calls)
        for row in self.credential_calls:
            need(set(row) == {"role", "entered", "returned", "settled", "status"}
                 and all(type(row[key]) is bool for key in ("entered", "returned", "settled"))
                 and (row["status"] is None or type(row["status"]) is int and -65536 <= row["status"] <= 65535),
                 "observer-credential-record-shape")
            actual += sys.getsizeof(row) + sum(sys.getsizeof(k) + sys.getsizeof(v) for k, v in row.items())
        need(actual <= self.removal_credential_reserved and self.removal_control_reserved <= 16 * 1024 * 1024,
             "observer-credential-actual-storage")

    def removal_recorded_role(self, role):
        if self.phase != "prepare-removal-observers":
            return role
        return "observer-" + ((self.removal_prep_phase + "-") if self.removal_prep_phase else "") + role

    def removal_final_active(self):
        return self.phase in FINAL_PACKAGE_PHASES or (self.phase == "prepare-removal-observers"
            and self.removal_final_context is not None)

    def removal_final_calls(self):
        if self.phase in FINAL_PACKAGE_PHASES:
            return tuple(row["role"] for row in self.calls)
        need(self.removal_final_active(), "observer-final-package-context")
        prefix = "observer-" + self.removal_prep_phase + "-"
        rows = self.calls[self.removal_final_context["calls"]:]
        need(all(row["role"].startswith(prefix) for row in rows), "observer-final-original-role")
        return tuple(row["role"][len(prefix):] for row in rows)

    def removal_prepare_io(self, label, function, *args, **kwargs):
        need(self.phase == "prepare-removal-observers" and self.final_package_known(), "observer-preparation-known")
        self.notary_clock()
        self.stage = self.stager_io_pending = "observer-" + label
        value = function(*args, **kwargs)
        self.notary_clock()
        self.stager_io_pending = None
        return value

    def removal_prepare_call(self, role, argv, *, maximum=30, limit=65536, cwd=None, environment=None):
        need(self.phase == "prepare-removal-observers" and self.final_package_known(), "observer-preparation-call-known")
        now, endpoint = self.notary_clock()
        timeout = min(maximum, (endpoint - now - 3_000_000_000) // 1_000_000_000)
        need(timeout >= 1 and (role != "producer-emitter" or timeout == 123), "observer-preparation-call-budget")
        result = self.call(role, argv, self.native_environment() if environment is None else environment,
            cwd=self.work if cwd is None else cwd, timeout=timeout, limit=limit)
        self.notary_clock()
        return result

    def removal_prepare_program(self):
        """Own O is a signed copy of the exact SOURCE observer graph, not B."""
        messages = self.original(self.work_entry, "removal-observer-build.jsonl", "observer-compiler-record", 4 * 1024 * 1024, (0o600,))
        status = self.original(self.work_entry, "removal-observer-build.status", "observer-compiler-status", 8, (0o600,))
        need(self.read(status) == b"0\n", "observer-original-compiler-status")
        directory = self.descend(self.work_entry, ("removal-observer-target", self.target, "release"))
        original = self.original(directory, self.stager.REMOVER_NAME, "observer-compiler-program", self.stager.REMOVER_BYTES,
                                 (0o700, 0o755), alias=True)
        body = self.read(original)
        self.stager.removal_fixture_cargo_artifact(self.read(messages), self.work / "removal-observer-target" / self.target / "release" / self.stager.REMOVER_NAME,
            self.work / "removal-observer-target", body, role="observer", target=self.target, package_version=self.image_package_version)
        copied_root = self.package_directory("removal-observer-program")
        self.removal_prepare_io("program-copy", self.stager.write_tree,
            self.work / "removal-observer-program" / "signed", {self.stager.REMOVER_NAME: (body, 0o555)},
            root_mode=0o700, current_owned=True)
        signed_root = self.directory(copied_root, "signed", "observer-signed-program-root")
        unsigned = self.original(signed_root, self.stager.REMOVER_NAME, "observer-unsigned-program", self.stager.REMOVER_BYTES, (0o555,))
        need(self.read(unsigned) == self.read(original) == body, "observer-program-copy-original")
        before = unsigned["identity"]
        self.signing_mutation_pending = True
        os.fchmod(unsigned["fd"], 0o755); os.fsync(unsigned["fd"])
        unsigned["identity"] = signature(os.fstat(unsigned["fd"]))
        need(unsigned["identity"][:2] == before[:2] and unsigned["identity"][3:8] == before[3:8]
             and unsigned["identity"][2] == stat.S_IFREG | 0o755 and self.read(unsigned) == body,
             "observer-owned-signing-mode")
        self.signing_mutation_pending = False
        matcher = self.signing_matcher()
        entitlements = self.source_original("desktop/packaging/macos-empty-entitlements.plist", "observer-empty-entitlements", 1024)
        empty = self.read(entitlements)
        need(digest(empty) == self.stager.SIGNED_ENTITLEMENTS_SHA256, "observer-empty-entitlements")
        self.package_sources.append((entitlements, empty))
        path = self.work / "removal-observer-program/signed" / self.stager.REMOVER_NAME
        with self.credential_scope("observer-program"):
            self.signing_mutation_pending = True
            # This is the same genuine Application identity/purpose, not an
            # ad-hoc observer. Only the separate example gets a private CDHash.
            result = self.call("program-sign", ["/usr/bin/codesign", "--force", "--sign", self.signing[1],
                "--options", "runtime", "--entitlements", str(self.checkout / "desktop/packaging/macos-empty-entitlements.plist"),
                "--identifier", "dev.mobile-release-kit.desktop.remove", "--timestamp", str(path)],
                self.native_environment(), cwd=self.work, timeout=30, limit=65536)
            signed = self.original(signed_root, self.stager.REMOVER_NAME, "observer-signed-program", self.stager.REMOVER_BYTES, (0o755,))
            signed_body = self.read(signed)
            matcher.macho_content_valid(body, signed_body, self.arch, signing=True)
            self.close(unsigned)
            need(unsigned["closed"] and not self.errors, "observer-program-prior-close")
            self.signing_mutation_pending = False
            verified = self.removal_prepare_call("program-verify", ["/usr/bin/codesign", "--verify", "--strict", "-R",
                "=" + signing_requirement(self.signing, "dev.mobile-release-kit.desktop.remove"), str(path)])
            need(not verified.stdout and not verified.stderr, "observer-program-purpose-verification")
            before = signed["identity"]
            self.signing_mutation_pending = True
            os.fchmod(signed["fd"], 0o555); os.fsync(signed["fd"])
            signed["identity"] = signature(os.fstat(signed["fd"]))
            need(signed["identity"][:2] == before[:2] and signed["identity"][3:8] == before[3:8]
                 and signed["identity"][2] == stat.S_IFREG | 0o555 and self.read(signed) == signed_body,
                 "observer-program-owned-mode")
            self.signing_mutation_pending = False
        self.package_outputs.extend(((original, digest(body)), (signed, digest(signed_body)),
                                     (messages, digest(self.read(messages))), (status, digest(b"0\n"))))
        return signed, path

    def removal_prepare_emitter(self):
        environment = build_environment(self.environment, self.work, self.image_release, target=self.target)
        environment.update(CARGO_TARGET_DIR=str(self.work / self.target_name), TMPDIR=str(self.work / self.target_name / "tmp"),
                           MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=self.environment["MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"])
        compiled = self.removal_prepare_call("producer-build", [direct_rust_tools(self.target)[0], "build", "--manifest-path",
            str(self.checkout / "desktop/src-tauri/Cargo.toml"), "--locked", "--offline", "--release", "--config", PRODUCER_CARGO_OVERRIDE, "--jobs", "1",
            "--target", self.target, "--no-default-features", "--features", "macos-remove-observer-producer",
            "--example", "macos_remove_producer", "--message-format=json-render-diagnostics"],
            maximum=480, limit=4 * 1024 * 1024, cwd=self.checkout / "desktop/src-tauri", environment=environment)
        binary = producer_artifact(compiled.stdout, self.checkout, self.work / self.target_name, self.target,
            package_version=self.image_package_version, remove=True, observer=True)
        directory = self.descend(self.target_entry, (self.target, "release", "examples"))
        executable = self.original(directory, binary.name, "observer-producer-compiler", 64 * 1024 * 1024, (0o700, 0o755), alias=True)
        body = self.read(executable)
        self.stager.macho(body, system_only=True, target=self.target)
        return self.producer_signing_copy(executable, body)

    def removal_prepare_one(self, phase, target, own_program, own_path, producer):
        self.removal_prep_phase = phase
        before_entries = len(self.entries)
        source_count, output_count, roots_count = len(self.package_sources), len(self.package_outputs), len(self.package_roots)
        parent_target, parent_name = self.target_entry, self.target_name
        label = "removal-observer-" + phase
        self.scripts_name, self.packager_filename = label + "-scripts", label + "-original.pkg"
        self.unsigned_package_name, self.final_package_name = label + "-unsigned", label + "-final"
        scripts = self.work / self.scripts_name
        own_sha = digest(self.read(own_program))
        self.removal_prepare_io("fixed-scripts", self.stager.removal_fixture_scripts_command,
            argparse.Namespace(target=self.target, role="observer-" + phase, correlation=self.removal_correlation,
                target_binding=target, remover=own_path, expected_remover=own_sha, output=scripts))
        self.removal_prepare_call("pkgbuild", ["/usr/bin/pkgbuild", "--nopayload", "--scripts", str(scripts),
            "--identifier", self.stager.REMOVE_PACKAGE_ID, "--version", self.removal_selection.package_version,
            "--install-location", "/", "--ownership", "recommended", str(self.work / self.packager_filename)])
        fixture = dict(removal_fixture_role="observer-" + phase, removal_fixture_correlation=self.removal_correlation,
                       removal_fixture_binding=target)
        self.removal_prepare_io("package-parts", self.stager.prepare_package_command,
            argparse.Namespace(target=self.target, fixture=False, remove=True, expected_remover=own_sha, scripts=scripts,
                package=self.work / self.packager_filename, output=self.work / (label + "-parts"), **fixture))
        self.removal_prepare_call("tar", ["/usr/bin/tar", "-c", "-z", "-f", str(self.work / (label + "-parts/Scripts")),
            "--format=odc", "--uid=0", "--gid=0", "--no-acls", "--no-xattrs", "--no-fflags", "--no-mac-metadata", "."],
            cwd=scripts, environment={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC", "COPYFILE_DISABLE": "1"})
        self.package_directory(self.unsigned_package_name)
        self.removal_prepare_call("xar", ["/usr/bin/xar", "-c", "-f", str(self.work / self.unsigned_package_name / "Remove.pkg"),
            "--compression=none", "PackageInfo", "Scripts"], cwd=self.work / (label + "-parts"),
            environment={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC", "COPYFILE_DISABLE": "1"})
        # One fixed per-carrier workspace, still inside the SAME outer owner.
        os.mkdir("o-" + phase, 0o700, dir_fd=parent_target["fd"])
        self.target_entry = self.directory(parent_target, "o-" + phase, "observer-one-target")
        self.target_name = parent_name + "/o-" + phase
        os.mkdir("tmp", 0o700, dir_fd=self.target_entry["fd"])
        self.directory(self.target_entry, "tmp", "observer-one-tmp")
        self.removal_final_context = {"calls": len(self.calls), "credentials": len(self.credential_calls), "fixture": fixture,
                                      "program": own_sha}
        self.finalize_package()  # unchanged actual sign/notary/staple/audit engine
        finalized = dict(self.receipt["finalPackage"])
        package_entry = self.final_package_output
        self.removal_final_context = None
        # Actual sizes of the SAME retained originals, before allocating either
        # program body/copy. The caller never assigns an expected source by DATA.
        installed_root = self.directory(self.work_entry, "producer-root", "observer-installed-root")
        installed = self.original(installed_root, "producer.json", "observer-installed-producer", 65536, (0o444,))
        signature = self.original(installed_root, "producer.sig", "observer-installed-signature", 512, (0o444,))
        input_root = self.directory(self.work_entry, "input", "observer-installed-input")
        inventory = self.original(input_root, self.stager.INSTALLATION_INVENTORY_NAME, "observer-installed-inventory", self.stager.INVENTORY_BYTES, (0o444,))
        parts = ("app/" + self.stager.REMOVER).split("/")
        installed_program = self.original(self.descend(input_root, tuple(parts[:-1])), parts[-1],
            "observer-genuine-installed-remover", self.stager.REMOVER_BYTES, (0o555,))
        rows = {"package": package_entry, "observer": own_program, "installedProgram": installed_program,
                "inventory": inventory, "installed": installed, "signature": signature}
        sizes = {key: os.fstat(entry["fd"]).st_size for key, entry in rows.items()}
        copy_quote = self.stager.removal_observer_copy_quote_data(sizes)
        need(copy_quote + len(producer[1]) <= self.stager.MAX_BYTES,
             "observer-copy-and-retained-example-overlap")
        values = {key: self.read(entry) for key, entry in rows.items()}
        need(all(len(values[key]) == sizes[key] for key in rows), "observer-copy-actual-sizes")
        source = self.stager.packaging_signing_data(self.producer_profile, self.service_profile)
        descriptor = self.stager.packaging_observer_descriptor_data(values["installed"], values["inventory"],
            values["installedProgram"], values["observer"], values["package"], source, self.removal_selection,
            source_commit=self.image_source, manifest=self.environment["MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"])
        need(digest(values["inventory"]) == target["inventorySha256"]
             and digest(values["installedProgram"]) == self.environment["MRK_MACOS_REMOVER_SHA256"], "observer-target-input-conservation")
        files = {"remove-descriptor-input.json": (descriptor, 0o444), "producer.json": (values["installed"], 0o444),
            "producer.sig": (values["signature"], 0o444), "install-inventory.json": (values["inventory"], 0o444),
            "mrk-macos-remove": (values["observer"], 0o555), "installed-mrk-macos-remove": (values["installedProgram"], 0o555)}
        input_path = self.work / (label + "-input")
        self.removal_prepare_io("six-input-copy", self.stager.write_tree, input_path, files, root_mode=0o700, current_owned=True)
        copy_root = self.directory(self.work_entry, input_path.name, "observer-six-inputs")
        for name, (body, mode) in files.items():
            copied = self.original(copy_root, name, "observer-six-input-original", len(body), (mode,))
            need(self.read(copied) == body, "observer-six-input-copy-post")
            self.package_outputs.append((copied, digest(body)))
        self.package_roots.append((copy_root, set(files)))
        phase_root = self.directory(self.removal_observer_root, phase, "observer-distribution-phase")
        package_copy = self.package_file(phase_root, "Remove.pkg", values["package"])
        package_sha = digest(values["package"])
        del files, body, values
        self.package_post()
        with self.credential_scope("producer", producer=producer):
            emitted = self.removal_prepare_call("producer-emitter", [str(self.work / self.producer_filename),
                "--package-root", str(self.work / "removal-observer-root" / phase), "--observer-input-root", str(input_path)],
                maximum=123, limit=4096)
            desc = self.original(phase_root, "remove-producer.json", "observer-emitted-descriptor", 16384, (0o444,))
            sig = self.original(phase_root, "remove-producer.sig", "observer-emitted-signature", 512, (0o444,))
            desc_body, sig_body = self.read(desc), self.read(sig)
            summary = self.stager.emitted_removal_data(emitted.stdout, emitted.stderr, emitted.returncode,
                self.read(package_copy), desc_body, sig_body, descriptor)
            self.package_outputs.extend(((desc, digest(desc_body)), (sig, digest(sig_body))))
        need(set(self.removal_names(phase_root, 3)) == set(REMOVAL_INPUT_NAMES), "observer-emitted-three-inputs")
        expected = {"Remove.pkg": {"bytes": package_copy["identity"][6], "sha256": package_sha},
            "remove-producer.json": {"bytes": len(desc_body), "sha256": digest(desc_body)},
            "remove-producer.sig": {"bytes": len(sig_body), "sha256": digest(sig_body)}}
        self.package_post()
        self.notary_clock()
        # Only actual known settled phase originals are released. The actual
        # source directories stay cached/live; no closed cache hit is reused.
        need(self.notary_known() and self.credential_active is None and self.notary_key is None, "observer-phase-settled")
        self.removal_prepared[phase] = {"files": expected, "finalPackage": finalized,
            "emission": summary, "copyQuote": copy_quote, "observerProgramSha256": own_sha}
        for entry in self.entries[before_entries:]:
            ancestor = entry
            source_directory = entry["kind"] == "directory"
            while source_directory and ancestor is not None and ancestor is not self.source_entry:
                ancestor = ancestor.get("parent_entry")
            if source_directory and ancestor is self.source_entry:
                continue
            if entry["kind"] == "directory" and entry.get("parent_entry") is self.work_entry and entry.get("name") in ("input", "producer-root"):
                continue
            if entry["kind"] == "directory":
                cursor = entry
                while cursor is not None and cursor.get("parent_entry") is not self.work_entry:
                    cursor = cursor.get("parent_entry")
                if cursor is not None and cursor.get("name") == "input":
                    continue
            # Root phase directory is reused by final image preparation.
            if entry is phase_root:
                continue
            self.close(entry)
            need(entry["closed"], "observer-phase-consuming-close")
        del self.package_sources[source_count:]
        del self.package_outputs[output_count:]
        del self.package_roots[roots_count:]
        self.target_entry, self.target_name = parent_target, parent_name
        self.notary_roots, self.notary_tools, self.final_package_roots, self.final_package_inputs = [], {}, [], []
        self.final_package_output_root = self.final_package_output = self.final_package_sha = None
        self.final_package_preimage = None
        self.final_package_complete = False
        self.removal_prep_phase = None
        return expected

    def prepare_removal_observers(self):
        need(self.phase == "prepare-removal-observers" and self.signing is not None and not self.calls,
             "observer-preparation-fixed-entry")
        self.removal_case, self.removal_correlation = removal_context_data(self.environment, self.target)
        self.removal_credential_reserved = removal_credential_quote_data()
        # Fixed bookkeeping/source-read reserve, separate from the accepted
        # actual INPUT6 body/copy quote. It is not an RSS/allocator guarantee.
        self.removal_control_reserved = self.removal_credential_reserved + 8 * 1024 * 1024
        need(self.removal_control_reserved <= 16 * 1024 * 1024, "observer-control-reserve")
        self.removal_credential_records_post()
        target = self.removal_preparation_inputs()
        own_program, own_path = self.removal_prepare_program()
        producer = self.removal_prepare_emitter()
        phases = self.stager.removal_fixture_case_data(self.removal_case)
        self.removal_observer_root = self.package_directory("removal-observer-root")
        for phase in phases:
            self.package_clock()
            os.mkdir(phase, 0o700, dir_fd=self.removal_observer_root["fd"])
        need(set(self.removal_names(self.removal_observer_root, 3)) == set(phases), "observer-three-phase-roster")
        self.removal_prepared = {}
        for phase in phases:
            need(self.credential_active is None and self.credential_known() and not self.credential_failed
                 and all(row["closed"] and row["retired"] and row["searchRestored"] and row["defaultUnchanged"]
                         for row in self.credential_contexts), "observer-previous-credential-retirement")
            self.removal_prepare_one(phase, target, own_program, own_path, producer)
        # Drop the separately sealed example body before image allocation;
        # its same original/hash stays in the cumulative original ledger.
        del producer
        self.package_roots.append((self.removal_observer_root, set(phases)))
        expected = {phase: self.removal_prepared[phase]["files"] for phase in phases}
        for phase in phases:
            root = self.directory(self.removal_observer_root, phase, "observer-image-phase")
            need(set(self.removal_names(root, 3)) == set(REMOVAL_INPUT_NAMES), "observer-image-phase-roster")
            self.package_roots.append((root, set(REMOVAL_INPUT_NAMES)))
            for leaf in REMOVAL_INPUT_NAMES:
                item = expected[phase][leaf]
                entry = self.original(root, leaf, "observer-image-input", item["bytes"], (0o444,))
                need(entry["identity"][6] == item["bytes"] and self.notary_stream(entry) == item["sha256"],
                     "observer-image-exact-phase-input")
                self.package_outputs.append((entry, item["sha256"]))
        self.image_directory = "removal-observer-distribution"
        self.image_filename = "MobileReleaseKit-Observation.dmg"
        self.image_identifier = "dev.mobile-release-kit.desktop.observation"
        self.distribution_entry = self.package_directory(self.image_directory)
        self.package_post()
        image, _path = self.package_image(self.removal_observer_root, "distribution")
        self.package_post()
        self.removal_credential_records_post()
        need(tuple(row["role"] for row in self.calls) == removal_preparation_roles(self.removal_case)
             and tuple(row["role"] for row in self.credential_calls) == removal_credential_roster_data()
             and tuple(row["purpose"] for row in self.credential_contexts) ==
                 ("observer-program", "installer", "producer", "installer", "producer", "installer", "producer", "distribution-image")
             and self.notary_known() and self.notary_key is None, "observer-preparation-cumulative-finality")
        self.removal_observer_image = image
        self.removal_observer_program_sha = digest(self.read(own_program))
        self.sha256 = image["sha256"]
        self.removal_preparation_complete = True
        self.notary_clock()

    def removal_preparation_receipt(self):
        need(self.removal_preparation_complete and self.receipt["passed"] and self.receipt["targetRetired"]
             and self.receipt["originalClosesKnown"] and self.notary_known()
             and len(self.calls) == 46 and len(self.credential_calls) == 158
             and len(self.credential_contexts) == 8, "observer-preparation-receipt-finality")
        # The private cumulative ledger is never reset. Public count/hash are
        # compact projections of its complete actual originals, not fake rows.
        native = self.stager.canonical(self.calls)
        credential = self.stager.canonical(self.credential_calls)
        need(len(native) <= 32768 and len(credential) <= 32768, "observer-preparation-ledger-bound")
        value = {"schemaVersion": 1, "phase": self.phase, "source": self.image_source, "target": self.target,
            "workflowSource": self.environment["GITHUB_WORKFLOW_SHA"], "runId": self.environment["GITHUB_RUN_ID"],
            "runAttempt": self.environment["GITHUB_RUN_ATTEMPT"], "case": self.removal_case, "correlation": self.removal_correlation,
            "passed": True, "targetRetired": True, "originalClosesKnown": True, "outerFinalityRequired": True,
            "nativeCalls": len(self.calls), "nativeCallsSha256": digest(native), "credentialCalls": len(self.credential_calls),
            "credentialCallsSha256": digest(credential), "credentialContexts": len(self.credential_contexts),
            "targetBinding": self.removal_binding, "targetFiles": self.removal_target_files,
            "targetImage": self.removal_target_image, "observerImage": self.removal_observer_image,
            "observers": {phase: self.removal_prepared[phase]["files"] for phase in self.stager.removal_fixture_case_data(self.removal_case)},
            "observerProgramSha256": self.removal_observer_program_sha, "controlBytes": self.removal_control_reserved + self.removal_original_reserved,
            "productReady": False}
        return removal_prepared_data(value, self.environment, self.target, self.removal_case, self.removal_correlation)

    def removal_clock(self, segment=None):
        now = self.package_clock()
        if segment is not None:
            need(segment in REMOVAL_PHASE_ENDPOINTS, "removal-fixed-segment")
            endpoint = self.package_started + REMOVAL_PHASE_ENDPOINTS[segment] * 1_000_000_000
            if segment == "joint" and self.removal_joint_deadline is not None:
                endpoint = min(endpoint, self.removal_joint_deadline)
            need(now < endpoint, "removal-segment-deadline")
            return now, endpoint
        return now, self.package_endpoint

    def removal_reserve(self, rows=1):
        active_scan = int(self.removal_scan_state in ("acquiring", "owned", "closing", "unknown"))
        need(type(rows) is int and 0 <= rows <= 128 and len(self.entries) + rows <= 24576
             and sum(entry["fd"] is not None for entry in self.entries) + active_scan + rows <= 96,
             "removal-original-headroom")
        if self.removal_control_reserved == 0:
            self.removal_control_reserved = 8 * 1024 * 1024
        quote = removal_original_storage_data(self.entries, self.entry_registry, rows)
        reserved = max(self.removal_original_reserved, quote)
        need(self.removal_control_reserved + reserved <= 16 * 1024 * 1024,
             "removal-original-control-pool")
        self.removal_original_reserved = reserved  # No credit on close/trim.
        self.package_clock()

    def removal_host(self):
        need(self.removal_host_module is not None and self.removal_api is None, "removal-host-source")
        self.removal_api = self.removal_host_module.DarwinAPI(_RemovalHostClock(self), target=self.target)
        self.removal_api.waitable_sigchld()
        # Initialize the stager's fixed libc observer BEFORE the UI thread.
        self.stager.no_xattrs(self.target_entry["fd"])

    def removal_acl(self, entry, info):
        self.package_clock()
        value = self.removal_host_module._acl_snapshot(self.removal_api.library, entry["fd"],
                                                       self.removal_host_module.full9(info))
        need(type(value) is dict and value.get("empty") is True and value.get("phase") == 0
             and value.get("filesecFreeReturned") is True
             and value.get("aclFreeResult") in (None, 0), "removal-original-empty-acl")
        self.package_clock()
        return value["snapshotFlags"]

    def removal_system_ancestor_path(self, entry):
        """Only four standard parents, via their same registered directory chain."""
        need(self.entry_registry.get(id(entry)) is entry and entry["fd"] is not None and not entry["closed"],
             "removal-protected-owner")
        path = entry.get("removal_system_path")
        need(path in ("/", "/Volumes", "/Library", "/Library/Application Support"), "removal-protected-owner")
        parent = entry.get("parent_entry")
        if path == "/":
            need(parent is None and entry["parent"] is None and entry["name"] == "/", "removal-protected-owner")
        else:
            need(type(parent) is dict and entry["parent"] == parent["fd"] and entry["name"] == path.rsplit("/", 1)[1],
                 "removal-protected-owner")
            expected = path.rsplit("/", 1)[0] or "/"
            need(parent.get("removal_system_path") == expected, "removal-protected-owner")
            need(self.removal_system_ancestor_path(parent) == expected, "removal-protected-owner")
        return path

    def removal_directory_facts(self, entry, *, protected=False, readonly=False, private=False):
        # MNT_MULTILABEL is MAC-label support, not MNT_UNION (Apple mount.h).
        self.package_clock()
        need(self.entry_registry.get(id(entry)) is entry and entry["fd"] is not None and not entry["closed"],
             "removal-directory-original")
        need(entry.get("removal_system_path") is None or (protected is True and readonly is False and private is False),
             "removal-protected-owner")
        info = os.fstat(entry["fd"])
        named = os.lstat("/") if entry.get("name") == "/" else os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False)
        need(signature(info) == signature(named) and stat.S_ISDIR(info.st_mode)
             and not info.st_mode & 0o7022, "removal-directory-named-held")
        if protected:
            system = entry.get("removal_system_path") is not None
            if system:
                self.removal_system_ancestor_path(entry)
            # System parents may be root:admin; managed nodes remain root:wheel.
            # All observed group identities are still retained and POST-checked.
            need(info.st_uid == 0 and (system or info.st_gid == 0), "removal-protected-owner")
        elif private:
            need((info.st_uid, info.st_gid) == (os.getuid(), os.getgid())
                 and stat.S_IMODE(info.st_mode) == 0o700, "removal-channel-directory")
        flags = getattr(info, "st_flags", None) if readonly else self.removal_acl(entry, info)
        need(type(flags) is int and 0 <= flags < 1 << 32, "removal-directory-flags")
        fs = self.removal_api.filesystem(entry["fd"])
        need(type(fs["flags"]) is int and fs["flags"] & 0x1000
             and not fs["flags"] & 0x20
             and (readonly or not fs["flags"] & 0x200000), "removal-local-filesystem")
        if readonly:
            need(fs["flags"] & 1 and fs["typeName"] in ("hfs", "apfs"), "removal-readonly-filesystem")
        else:
            need(fs["typeName"] == "apfs", "removal-protected-apfs")
        if private:
            need(flags == 0, "removal-input-flags")
            self.stager.no_xattrs(entry["fd"])
        need(signature(os.fstat(entry["fd"])) == signature(info), "removal-directory-post")
        return signature(info), flags, fs

    def removal_open_directory(self, parent, name, role, *, protected=False, readonly=False, private=False, context=None, system_ancestor=False):
        need(type(system_ancestor) is bool, "removal-protected-owner")
        system_path = None
        if system_ancestor:
            need(protected is True and readonly is False and private is False, "removal-protected-owner")
            base = "" if parent is None else self.removal_system_ancestor_path(parent).rstrip("/")
            system_path = "/" if parent is None and name == "/" else base + "/" + name
            need((parent is not None or name == "/") and system_path in ("/", "/Volumes", "/Library", "/Library/Application Support")
                 and name == ("/" if parent is None else system_path.rsplit("/", 1)[1]), "removal-protected-owner")
        self.removal_reserve()
        # Register acquisition custody BEFORE the syscall; an exception is not
        # an Absent or a known-close receipt.
        entry = self.register(None, role, "removal-directory", None if parent is None else parent["fd"], name)
        entry["parent_entry"] = parent
        if system_ancestor: entry["removal_system_path"] = system_path
        if context is not None:
            entry["removal_acquired"] = False
            context["entries"].append(entry)
        entry["fd"] = os.open("/" if parent is None else name, READ_FLAGS | os.O_DIRECTORY,
                              **({} if parent is None else {"dir_fd": parent["fd"]}))
        entry["removal_policy"] = (protected, readonly, private)
        entry["removal_facts"] = self.removal_directory_facts(entry, protected=protected, readonly=readonly, private=private)
        if context is not None: entry["removal_acquired"] = True
        return entry

    def removal_directory_post(self, entry):
        protected, readonly, private = entry["removal_policy"]
        need(self.removal_directory_facts(entry, protected=protected, readonly=readonly, private=private)
             == entry["removal_facts"], "removal-directory-facts-changed")

    def removal_names(self, entry, maximum=350):
        """Bounded observations through one retained, consuming-close iterator."""
        need(type(maximum) is int and 0 <= maximum <= 350
             and type(entry) is dict and self.entry_registry.get(id(entry)) is entry
             and type(entry["fd"]) is int and entry["fd"] >= 0 and not entry["closed"],
             "removal-roster-original")
        need(not self.removal_unknown and self.removal_scan_state == "closed",
             "removal-roster-previous-unknown")
        self.package_clock()
        self.removal_reserve(1)
        # Same lifetime ledger as every other original. The iterator owns a
        # transient duplicate, not an integer FD we may close or reconstruct.
        original = self.register(None, "removal-roster-reader", "removal-iterator", entry["fd"], None)
        original["iterator"] = None  # Allocate the slot BEFORE acquisition.
        values = []
        self.removal_scan_state = "acquiring"
        try:
            original["iterator"] = os.scandir(entry["fd"])
        except OSError:
            original["closed"] = True  # No iterator was returned.
            self.removal_scan_state = "closed"
            raise
        except BaseException:
            self.removal_scan_state = "unknown"
            self.removal_unknown = True
            raise
        self.removal_scan_state = "owned"
        first_error = None
        try:
            self.package_clock()
            for item in original["iterator"]:
                self.package_clock()
                name = item.name
                need(len(values) < maximum and type(name) is str and 0 < len(name) <= 255
                     and len(name.encode("utf-8", "strict")) <= 255
                     and name not in (".", "..") and "/" not in name and "\0" not in name
                     and name not in values, "removal-bounded-roster")
                values.append(name)
        except BaseException as error:
            first_error = error
        finally:
            # Known iterator cleanup still runs after a validation/clock
            # refusal. An uncertain close is never retried or called absent.
            self.removal_scan_state = "closing"
            try:
                original["iterator"].close()
            except BaseException as error:
                self.removal_scan_state = "unknown"
                self.removal_unknown = True
                if first_error is None:
                    first_error = error
            else:
                original["closed"] = True
                original["iterator"] = None
                self.removal_scan_state = "closed"
            try:
                self.package_clock()
            except BaseException as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error
        return sorted(values)

    def removal_roster(self, entry, maximum=350):
        self.package_clock()
        names = self.removal_names(entry, maximum)
        rows = {}
        for name in names:
            info = os.stat(name, dir_fd=entry["fd"], follow_symlinks=False)
            rows[name] = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
            self.package_clock()
        need(self.removal_names(entry, maximum) == sorted(rows), "removal-roster-post")
        return rows

    def removal_own_parent_post(self, entry, before_roster, name, *, present):
        """Only after an actual returned own create/mount/export/unmount.

        The full namespace must equal exactly that one SOURCE effect. All
        permission/identity-bearing facts remain equal; no global timestamp
        or discovered-name relaxation is provided to callers.
        """
        before, flags, fs = entry["removal_facts"]
        protected, readonly, private = entry["removal_policy"]
        current = self.removal_directory_facts(entry, protected=protected, readonly=readonly, private=private)
        after = self.removal_roster(entry)
        need(current[0][:3] == before[:3] and current[0][4:6] == before[4:6]
             and current[1:] == (flags, fs), "removal-own-parent-original")
        wanted = dict(before_roster)
        if present:
            need(name not in wanted and name in after, "removal-own-parent-new-name")
            wanted[name] = after[name]
        else:
            need(name in wanted and name not in after, "removal-own-parent-absent-name")
            del wanted[name]
        need(after == wanted, "removal-own-parent-exact-effect")
        entry["removal_facts"] = current
        return after

    def removal_absent(self, parent, name):
        self.removal_directory_post(parent)
        try:
            os.stat(name, dir_fd=parent["fd"], follow_symlinks=False)
        except FileNotFoundError:
            self.removal_directory_post(parent)
            return
        raise Refused("removal-fixed-name-collision")

    def removal_stream(self, entry, *, limit, expected=None, keep=False):
        self.package_clock()
        need(self.entry_registry.get(id(entry)) is entry and entry["fd"] is not None
             and not entry["closed"] and type(keep) is bool, "removal-file-original")
        parent, name = entry["parent"], entry["name"]
        before = os.fstat(entry["fd"])
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit
             and signature(before) == signature(os.stat(name, dir_fd=parent, follow_symlinks=False)),
             "removal-file-named-held")
        need(not keep or before.st_size <= 65536, "removal-retained-small-control")
        readonly = entry.get("removal_readonly", False)
        if not readonly:
            self.stager.no_xattrs(entry["fd"])
            need(self.removal_acl(entry, before) == 0, "removal-file-flags")
        flags = getattr(before, "st_flags", None)
        need(type(flags) is int and (entry.get("removal_flags", flags) == flags), "removal-file-flags-changed")
        entry["removal_flags"] = flags
        digestor, position, chunks = hashlib.sha256(), 0, []
        while position < before.st_size:
            self.package_clock()
            block = os.pread(entry["fd"], min(65536, before.st_size - position), position)
            need(block and len(block) <= before.st_size - position, "removal-file-short-read")
            digestor.update(block)
            if keep:
                chunks.append(block)
            position += len(block)
        need(os.pread(entry["fd"], 1, position) == b"" and getattr(os.fstat(entry["fd"]), "st_flags", None) == flags
             and signature(os.fstat(entry["fd"])) == signature(before)
             == signature(os.stat(name, dir_fd=parent, follow_symlinks=False)), "removal-file-post")
        facts = (signature(before), digestor.hexdigest())
        need(expected is None or facts == expected, "removal-file-bytes-changed")
        return facts, b"".join(chunks) if keep else None

    def removal_open_file(self, parent, name, role, limit, *, owned=False, keep=False, readonly=False, context=None):
        self.removal_reserve()
        entry = self.register(None, role, "removal-file", parent["fd"], name)
        entry["parent_entry"] = parent
        if context is not None:
            entry["removal_acquired"] = False
            context["entries"].append(entry)
        entry["fd"] = os.open(name, READ_FLAGS, dir_fd=parent["fd"])
        info = os.fstat(entry["fd"])
        need((readonly or (info.st_uid, info.st_gid) == ((os.getuid(), os.getgid()) if owned else (0, 0)))
             and stat.S_IMODE(info.st_mode) == 0o444, "removal-file-owner-mode")
        entry["removal_readonly"] = readonly
        facts, body = self.removal_stream(entry, limit=limit, keep=keep)
        entry.update(removal_file_facts=facts, removal_limit=limit)
        return entry, body

    def removal_inputs_post(self):
        self.removal_clock()
        for mount in self.removal_mounts:
            if mount.get("known") and not mount["detached"]:
                self.removal_directory_post(mount["entry"])
                for parent, roster in mount["rosters"]:
                    self.removal_directory_post(parent)
                    need(self.removal_roster(parent) == roster, "removal-mounted-roster-changed")
                for entry in mount["files"]:
                    self.removal_stream(entry, limit=entry["removal_limit"], expected=entry["removal_file_facts"])
        for entry in self.removal_sources:
            self.removal_stream(entry, limit=entry["removal_limit"], expected=entry["removal_file_facts"])
        self.removal_directory_post(self.removal_volumes)
        self.removal_directory_post(self.removal_slash)
        self.removal_clock()

    def removal_native_call(self, role, argv, *, segment, maximum, minimum=1, limit=65536):
        need(self.phase == "package-removal-fixture" and self.package_settled() and not self.removal_unknown,
             "removal-dispatch-custody")
        self.removal_reserve(0)
        roster = self.removal_abort_roles or removal_runtime_roles(self.removal_case)
        need(len(self.calls) < len(roster) and role == roster[len(self.calls)], "removal-original-role-order")
        if self.removal_abort_roles is not None:
            context = next((m for m in self.removal_mounts if role == "removal-" + m["role"] + "-detach"), None)
            need(context is not None and context["known"] and context["detachAttempted"]
                 and argv == ["/usr/bin/hdiutil", "detach", context["device"]], "removal-abort-original-device")
        now, endpoint = self.removal_clock(segment)
        timeout = min(maximum, (endpoint - now - 3_000_000_000) // 1_000_000_000)
        need(timeout >= minimum, "removal-original-budget-before-dispatch")
        result = self.call(role, argv, self.native_environment(), cwd=self.work, timeout=timeout, limit=limit)
        self.removal_clock(segment)
        self.removal_reserve(0)
        return result

    def removal_attach(self, role, path, expected, *, phases=()):
        need(role in ("target", "observers") and (role == "observers") == bool(phases), "removal-attach-role")
        name = self.stager.removal_fixture_mount_path(self.removal_correlation, role).name
        mount_path = Path("/Volumes") / name
        self.removal_absent(self.removal_volumes, name)
        before = self.removal_roster(self.removal_volumes)
        context = {"role": role, "name": name, "path": mount_path, "entered": True,
                   "known": False, "policyAccepted": False, "detached": False, "detachAttempted": False,
                   "entry": None, "device": None, "files": [], "rosters": [], "entries": []}
        self.removal_mounts.append(context)  # Custody precedes original attach.
        result = self.removal_native_call("removal-" + role + "-attach", ["/usr/bin/hdiutil", "attach", str(path),
            "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", str(mount_path), "-plist"],
            segment="attach", maximum=30)
        context["device"] = cleanup_mount_device_data(result.stdout, result.stderr, result.returncode, mount_path)
        entry = self.removal_open_directory(self.removal_volumes, name, "removal-mounted-" + role, readonly=True, context=context)
        context["entry"] = entry
        need(entry["removal_facts"][0][0] != self.removal_volumes["removal_facts"][0][0]
             and entry["removal_facts"][2]["mountOn"] == str(mount_path)
             and entry["removal_facts"][2]["mountFrom"] == context["device"], "removal-actual-mount-device")
        self.removal_own_parent_post(self.removal_volumes, before, name, present=True)
        context["known"] = True
        need(self.stager.distribution_mount_data(result.stdout, result.stderr, result.returncode, mount_path)
             == context["device"], "removal-policy-device")
        context["policyAccepted"] = True
        groups = [(None, entry)]
        if role == "observers":
            need(self.removal_names(entry, len(phases)) == sorted(phases), "removal-observer-mount-roster")
            groups = [(phase, self.removal_open_directory(entry, phase, "removal-mounted-observer-phase", readonly=True, context=context))
                      for phase in phases]
            context["rosters"].append((entry, self.removal_roster(entry)))
        bundles = {}
        for phase, parent in groups:
            need(self.removal_names(parent, 3) == sorted(REMOVAL_INPUT_NAMES), "removal-three-input-roster")
            bodies, facts = {}, {}
            for leaf in REMOVAL_INPUT_NAMES:
                limit = self.stager.MAX_BYTES if leaf == "Remove.pkg" else 16384 if leaf.endswith("json") else 512
                original, body = self.removal_open_file(parent, leaf, "removal-mounted-input", limit,
                    keep=leaf != "Remove.pkg", readonly=True, context=context)
                context["files"].append(original)
                row = original["removal_file_facts"]
                selected = expected if phase is None else expected[phase]
                need((row[0][6], row[1]) == (selected[leaf]["bytes"], selected[leaf]["sha256"]),
                     "removal-mounted-source-binding")
                original["removal_acquired"] = True
                facts[leaf], bodies[leaf] = row, body
            context["rosters"].append((parent, self.removal_roster(parent)))
            bundles[phase] = {"path": mount_path if phase is None else mount_path / phase,
                              "facts": facts, "bodies": bodies, "parent": parent}
        self.removal_inputs_post()
        return context, bundles

    def removal_result_parent(self):
        library = self.removal_open_directory(self.removal_slash, "Library", "removal-system-library", protected=True, system_ancestor=True)
        parent = self.removal_open_directory(library, "Application Support", "removal-result-parent", protected=True, system_ancestor=True)
        self.removal_system_parents.extend((library, parent))
        return parent

    def removal_accept_outputs(self, role):
        # Every allowed own effect is fixed by the actual original just joined.
        # No caller-selected path set, output-body assertion or marker grants it.
        need(self.calls and self.calls[-1]["role"] == role and self.calls[-1]["returned"] is True
             and self.calls[-1]["capturesSettled"] is True and not self.removal_pending_outputs,
             "removal-output-original-call")
        record = self.calls[-1]
        allowed = set()
        first_request = role in ("removal-live-cancel", "removal-live-cut")
        if role.startswith("removal-observer-"):
            phase = role[len("removal-observer-"):]
            need(phase in self.removal_observers and record["returncode"] == 0, "removal-output-observer-role")
            own = self.removal_observers[phase]["own"]
            allowed.add(self.stager.removal_fixture_export_name("observer", own["descriptorSha256"])[0].name)
        else:
            need(removal_native_result_data(self.removal_case, role, record["returncode"]), "removal-output-returned-status")
            if self.removal_case == "abrupt":
                purpose = "live" if role == "removal-live-cut" else "resume"
                allowed.add(self.stager.removal_fixture_export_name("supervisor", self.removal_binding["removeDescriptorSha256"], role=purpose)[0].name)
                if purpose == "resume":
                    allowed.add(self.stager.removal_fixture_export_name("effects", self.removal_binding["removeDescriptorSha256"])[0].name)
        parent, before = self.removal_output_parent, self.removal_output_roster
        old, flags, fs = parent["removal_facts"]
        current = self.removal_directory_facts(parent, protected=True)
        after = self.removal_roster(parent)
        need(current[0][:3] == old[:3] and current[0][4:6] == old[4:6] and current[1:] == (flags, fs),
             "removal-returned-support-original")
        requests = "MobileReleaseKit-RemovalRequests"
        additions = allowed | ({requests} if first_request else set())
        need(not additions.intersection(before) and set(after) == set(before) | additions
             and all(after[name] == fact for name, fact in before.items()), "removal-exact-returned-support-roster")
        if first_request or self.removal_requests is not None:
            named = os.stat(requests, dir_fd=parent["fd"], follow_symlinks=False)
            named_flags = getattr(named, "st_flags", None)
            need(named.st_mode == stat.S_IFDIR | 0o755 and named.st_uid == named.st_gid == 0
                 and type(named_flags) is int and named_flags == 0
                 and signature(os.stat(requests, dir_fd=parent["fd"], follow_symlinks=False)) == signature(named),
                 "removal-named-request-directory")
            observed = (named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid, named_flags)
            need((first_request and self.removal_requests is None) or observed == self.removal_requests,
                 "removal-named-request-directory-changed")
            # This is explicitly NAMED metadata only. No contents audit or a
            # held directory FD are NOT claimed; no cleanup/admission authority.
            self.removal_requests = observed
        parent["removal_facts"], self.removal_output_roster = current, after
        self.removal_pending_outputs = allowed

    def removal_output_read(self, kind, binding, *, role=None, own=None, phase=None):
        descriptor = binding["removeDescriptorSha256"] if own is None else own["descriptorSha256"]
        path, limit = self.stager.removal_fixture_export_name(kind, descriptor, role=role)
        parent = self.removal_output_parent
        need(path.parent == self.stager.INSTALL_ROOT.parent and path.name in self.removal_pending_outputs,
             "removal-output-returned-creation")
        self.removal_directory_post(parent)
        entry, body = self.removal_open_file(parent, path.name, "removal-result-original", limit, keep=True)
        if kind == "observer":
            result = self.stager.removal_fixture_observer_data(body, binding, own, phase, selection=self.removal_selection)
        else:
            result = self.stager.removal_fixture_export_data(body, kind, binding, role=role, selection=self.removal_selection)
        self.removal_stream(entry, limit=limit, expected=entry["removal_file_facts"])
        facts = entry["removal_file_facts"]
        self.close(entry)
        need(entry["closed"], "removal-output-close-unknown")
        self.removal_output_facts[path.name] = (limit, facts)
        self.removal_pending_outputs.remove(path.name)
        self.removal_directory_post(parent)
        self.removal_clock()
        return result, facts[1]

    def removal_outputs_post(self):
        need(not self.removal_pending_outputs, "removal-unread-returned-output")
        self.removal_directory_post(self.removal_output_parent)
        need(self.removal_roster(self.removal_output_parent) == self.removal_output_roster,
             "removal-output-complete-roster-post")
        for name, (limit, expected) in self.removal_output_facts.items():
            original, _ = self.removal_open_file(self.removal_output_parent, name, "removal-output-post", limit)
            self.removal_stream(original, limit=limit, expected=expected)
            self.close(original)
            need(original["closed"], "removal-output-post-close")
        self.removal_directory_post(self.removal_output_parent)

    def removal_observe(self, phase, *, segment):
        own = self.removal_observers[phase]
        self.removal_inputs_post()
        result = self.removal_native_call("removal-observer-" + phase,
            ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer", "-pkg", str(own["path"] / "Remove.pkg"),
             "-target", "/", "-dumplog", "-verboseR"], segment=segment, maximum=60, minimum=55, limit=256 * 1024)
        need(result.returncode == 0, "removal-observer-original-zero")
        self.removal_accept_outputs("removal-observer-" + phase)
        facts, _sha = self.removal_output_read("observer", self.removal_binding, own=own["own"], phase=phase)
        actual = signature(os.fstat(self.removal_install_root["fd"]))
        named = signature(os.stat(self.stager.INSTALL_ROOT.name, dir_fd=self.removal_output_parent["fd"], follow_symlinks=False))
        need(tuple(map(int, facts["rootIdentity"])) == actual == named, "removal-observer-same-retained-root")
        # Root may change only through our genuine Installer operations. The
        # independent observer has audited that entire actual current root.
        previous = self.removal_install_root["removal_facts"]
        current = self.removal_directory_facts(self.removal_install_root, protected=True)
        need(current[0][:3] == previous[0][:3] and current[0][4:6] == previous[0][4:6]
             and current[1:] == previous[1:], "removal-root-original-conservation")
        self.removal_install_root["removal_facts"] = current
        self.removal_inputs_post()
        return facts

    def removal_marker(self, name, deadline):
        parent = self.removal_channel
        while True:
            self.removal_clock("joint")
            with self.removal_ui_lock:
                done = self.removal_ui_outcome["done"]
            need(time.monotonic_ns() < deadline and not done, "removal-marker-original-live")
            self.removal_directory_post(self.removal_channel_parent)
            names = self.removal_names(parent, 2 if self.removal_case == "ordinary" else 1)
            allowed = {"launched", "cancel-observed"} if self.removal_case == "ordinary" else {"launched"}
            need(set(names).issubset(allowed) and len(set(names)) == len(names), "removal-channel-closed-roster")
            if name in names:
                self.removal_reserve()
                entry = self.register(None, "removal-marker-" + name, "removal-marker", parent["fd"], name)
                entry["fd"] = os.open(name, READ_FLAGS, dir_fd=parent["fd"])
                info = os.fstat(entry["fd"])
                need(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == (os.getuid(), os.getgid())
                     and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and 0 <= info.st_size <= 128,
                     "removal-marker-original-shape")
                self.stager.no_xattrs(entry["fd"])
                need(self.removal_acl(entry, info) == 0, "removal-marker-flags")
                body = os.pread(entry["fd"], 129, 0)
                need(signature(os.fstat(entry["fd"])) == signature(info)
                     == signature(os.stat(name, dir_fd=parent["fd"], follow_symlinks=False)), "removal-marker-original-post")
                complete = self.stager.removal_fixture_marker_data(body, self.removal_correlation, self.removal_case, name)
                self.close(entry)
                need(entry["closed"], "removal-marker-close-unknown")
                if complete:
                    self.removal_markers[name] = (signature(info), digest(body))
                    return  # Hint only; final original UI result/close/join is still mandatory.
            time.sleep(0.05)

    def removal_ui_start(self, deadline):
        need(self.removal_runner is not None and self.removal_thread is None and self.removal_resource is not None,
             "removal-preloaded-ui-source")
        need(self.removal_resource.getrlimit(self.removal_resource.RLIMIT_FSIZE) == (1073741824, 1073741824),
             "removal-continuous-process-file-limit")
        normal = self.work / "normal-ui"
        channel = self.work / "removal-ui-v1" / ("r-" + self.removal_correlation)
        environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "USER": "runner", "LOGNAME": "runner",
            "TMPDIR": str(normal / "tmp") + "/", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TZ": "UTC",
            "DEVELOPER_DIR": str(NOTARY_XCODE),
            "TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB": "github-hosted-macos26-" + build_profile(self.target)[0],
            "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE": self.image_source,
            "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE": self.image_source,
            "TEST_RUNNER_MRK_NORMAL_UI_REMOVAL_CHANNEL": str(channel)}
        self.removal_ui_deadline = deadline
        need(self.removal_ui_outcome == {"done": False, "known": False}, "removal-ui-original-once")
        def run_ui():
            # This worker alone creates/uses its phase/cancellation owner.
            # No mutable main FD book, module load, environment or cwd update.
            try:
                phase = self.removal_runner.NormalPhase(self.owner, environment, self.checkout,
                    self.removal_runner.RemovalPhaseClock(deadline), retain_nonzero=True)
                original, facts = self.removal_runner.execute_removal_ui_phase(phase,
                    case=self.removal_case, derived=normal / "DerivedData", channel=channel,
                    source=self.image_source, file_limit=(1073741824, 1073741824), target=self.target)
                with self.removal_ui_lock:
                    self.removal_ui_outcome.update(original=original, facts=facts, known=True)
            except BaseException as error:
                with self.removal_ui_lock:
                    self.removal_ui_outcome.update(error=error, known=False)
            finally:
                with self.removal_ui_lock:
                    self.removal_ui_outcome["done"] = True
        self.removal_ui_entered = True
        self.removal_thread = self.removal_threading.Thread(target=run_ui, name="mrk-fixed-removal-ui", daemon=False)
        self.removal_thread.start()  # Entered before dispatch; no discovered thread/PID.

    def removal_ui_join(self):
        thread = self.removal_thread
        if thread is None:
            return
        remaining = (self.removal_ui_deadline - time.monotonic_ns()) / 1_000_000_000
        if remaining > 0:
            thread.join(remaining)
        need(not thread.is_alive(), "removal-original-ui-thread-unjoined")
        self.removal_ui_joined = True
        with self.removal_ui_lock:
            result = dict(self.removal_ui_outcome)
        need(result.get("done") is True and result.get("known") is True, "removal-original-ui-finality-unknown")
        original, facts = result["original"], result["facts"]
        need(type(original) is subprocess.CompletedProcess and original.returncode == 0
             and facts["case"] == self.removal_case and facts["sourceCommit"] == self.image_source
             and facts["sourcePrePostMatched"] is True and facts["originalCommandReturned"] is True
             and facts["workerJoin"] == "pending-caller-original-join"
             and facts["observation"]["originalAppTerminated"] is True
             and facts["observation"]["uiGateClosed"] is True and facts["observation"]["uiChannelClosed"] is True
             and facts["observation"]["normalQuit"] is False and facts["observation"]["gateFree"] == "unqualified", "removal-ui-returned-facts")
        need(self.removal_resource.getrlimit(self.removal_resource.RLIMIT_FSIZE) == (1073741824, 1073741824),
             "removal-process-file-limit-changed")
        self.removal_ui_facts = facts
        self.removal_channel_post()

    def removal_channel_post(self):
        parent = self.removal_channel
        wanted = ("launched", "cancel-observed") if self.removal_case == "ordinary" else ("launched",)
        need(set(self.removal_names(parent, len(wanted))) == set(wanted) and set(self.removal_markers) == set(wanted),
             "removal-ui-final-roster")
        before, flags, fs = parent["removal_facts"]
        after = self.removal_directory_facts(parent, private=True)
        need(after[0][:3] == before[:3] and after[0][4:6] == before[4:6] and after[1:] == (flags, fs),
             "removal-ui-channel-original")
        parent["removal_facts"] = after
        for name in wanted:
            info = os.stat(name, dir_fd=parent["fd"], follow_symlinks=False)
            need(signature(info) == self.removal_markers[name][0], "removal-ui-marker-changed")
        self.removal_directory_post(self.removal_channel_parent)

    def removal_detach_all(self):
        need(self.removal_complete and self.removal_ui_joined and self.package_settled()
             and not self.removal_unknown, "removal-detach-finality")
        self.removal_inputs_post()
        for context in reversed(self.removal_mounts):
            need(context["known"] and not context["detached"], "removal-mount-original")
            context["detachAttempted"] = True
            for entry in reversed(context["entries"]):
                self.close(entry)
                need(entry["closed"], "removal-mounted-original-close")
            before = self.removal_roster(self.removal_volumes)
            result = self.removal_native_call("removal-" + context["role"] + "-detach",
                ["/usr/bin/hdiutil", "detach", context["device"]], segment="detach", maximum=15)
            need(type(result.returncode) is int and result.returncode == 0, "removal-detach-original-status")
            self.removal_own_parent_post(self.removal_volumes, before, context["name"], present=False)
            context["detached"] = True
        self.removal_clock("settle")

    def removal_preload(self):
        need(self.removal_thread is None and self.removal_runner is None, "removal-preload-once")
        # All imports/module publication occur before the single UI worker.
        # This is the existing host's read-only native adapter, not preparation
        # or repair of a hosted machine/root/ACL.
        for filename, label in (("macos_xcode_host_preparation.py", "host"), ("macos_normal_ui_runner.py", "runner")):
            entry = self.source_original("desktop/tools/" + filename, "removal-" + label + "-source", 512 * 1024)
            body = self.read(entry)
            self.package_sources.append((entry, body))
            self.stager_io_pending = "removal-preload-" + label
            module = load_data(self.checkout, filename, "_mrk_removal_" + label)
            need(self.read(entry) == body, "removal-loaded-source-post")
            self.stager_io_pending = None
            if label == "host":
                self.removal_host_module = module
            else:
                self.removal_runner = module
        import threading
        import resource
        self.removal_threading, self.removal_resource = threading, resource
        need(threading.current_thread() is threading.main_thread() and len(threading.enumerate()) == 1
             and resource.getrlimit(resource.RLIMIT_FSIZE) == (1073741824, 1073741824),
             "removal-pre-overlap-process-state")
        self.removal_ui_lock = threading.Lock()
        self.removal_host()

    def removal_runtime_images(self, prepared):
        images = (("remove-distribution", "MobileReleaseKit-Remove.dmg", prepared["targetImage"]),
                  ("removal-observer-distribution", "MobileReleaseKit-Observation.dmg", prepared["observerImage"]))
        paths = []
        for directory, filename, facts in images:
            need(type(facts) is dict and set(facts) == {"file", "sha256", "bytes"} and facts["file"] == filename
                 and type(facts["bytes"]) is int and 0 < facts["bytes"] <= self.stager.MAX_BYTES
                 and self.stager.maintenance_hex(facts["sha256"], 64), "removal-image-preparation-data")
            root = self.directory(self.work_entry, directory, "removal-task-image-directory")
            need(self.removal_names(root, 1) == [filename], "removal-image-original-roster")
            entry, _ = self.removal_open_file(root, filename, "removal-image-original", self.stager.MAX_BYTES, owned=True)
            actual = entry["removal_file_facts"]
            need((actual[0][6], actual[1]) == (facts["bytes"], facts["sha256"]), "removal-image-source-correspondence")
            self.removal_sources.append(entry)
            paths.append(self.work / directory / filename)
        return paths

    def removal_channel_create(self):
        self.removal_reserve(2)
        self.recheck_directory(self.work_entry)
        os.mkdir("removal-ui-v1", 0o700, dir_fd=self.work_entry["fd"])
        # A parent alias from the same actual work FD, never a new path root.
        parent = self.removal_open_directory(self.work_entry, "removal-ui-v1", "removal-channel-parent", private=True)
        self.removal_channel_parent = parent
        name = "r-" + self.removal_correlation
        before = self.removal_roster(parent)
        need(not before, "removal-channel-parent-fresh")
        os.mkdir(name, 0o700, dir_fd=parent["fd"])
        self.removal_channel = self.removal_open_directory(parent, name, "removal-channel", private=True)
        self.removal_own_parent_post(parent, before, name, present=True)
        need(not self.removal_names(self.removal_channel, 0), "removal-channel-fresh")

    def package_removal_fixture(self):
        need(self.phase == "package-removal-fixture" and not self.calls and self.signing is not None,
             "removal-fixed-owner-entry")
        self.removal_case, self.removal_correlation = removal_context_data(self.environment, self.target)
        self.package_started = self.package_observed = time.monotonic_ns()
        self.package_endpoint = self.package_started + 990_000_000_000
        need(self.removal_control_reserved == 0, "removal-runtime-work-once")
        self.removal_control_reserved = 8 * 1024 * 1024
        self.removal_reserve(0)
        self.removal_preload()
        self.removal_preparation_inputs()
        status = self.original(self.work_entry, "removal-observers.status", "removal-observer-preparation-status", 8, (0o600,))
        need(self.read(status) == b"0\n", "removal-observer-preparation-original-zero")
        self.package_outputs.append((status, digest(b"0\n")))
        prepared = removal_prepared_data(self.removal_input_control("android-helper-prepare-removal-observers.json",
            "removal-observer-preparation-receipt"), self.environment, self.target, self.removal_case, self.removal_correlation)
        phases = self.stager.removal_fixture_case_data(self.removal_case)
        need(prepared["targetBinding"] == self.removal_binding and prepared["targetFiles"] == self.removal_target_files
             and prepared["targetImage"] == self.removal_target_image and set(prepared["observers"]) == set(phases),
             "removal-prepared-actual-target")
        target_image, observer_image = self.removal_runtime_images(prepared)
        self.removal_slash = self.removal_open_directory(None, "/", "removal-system-root", protected=True, system_ancestor=True)
        self.removal_volumes = self.removal_open_directory(self.removal_slash, "Volumes", "removal-protected-volumes", protected=True, system_ancestor=True)
        self.removal_output_parent = self.removal_result_parent()
        self.removal_output_roster = self.removal_roster(self.removal_output_parent)
        self.removal_absent(self.removal_output_parent, "MobileReleaseKit-RemovalRequests")
        self.removal_install_root = self.removal_open_directory(self.removal_output_parent, self.stager.INSTALL_ROOT.name,
                                                               "removal-installed-root", protected=True)
        self.removal_channel_create()
        _target_mount, targets = self.removal_attach("target", target_image, prepared["targetFiles"])
        _observer_mount, observers = self.removal_attach("observers", observer_image, prepared["observers"], phases=phases)
        self.removal_target = targets[None]
        self.removal_observers = {}
        names = set()
        for phase in phases:
            bundle = observers[phase]
            facts = bundle["facts"]
            own = {"packageSha256": facts["Remove.pkg"][1], "descriptorSha256": facts["remove-producer.json"][1],
                   "signatureSha256": facts["remove-producer.sig"][1]}
            need(own["descriptorSha256"] != self.removal_binding["removeDescriptorSha256"], "removal-observer-independent-input")
            bundle["own"] = own
            self.removal_observers[phase] = bundle
            names.add(self.stager.removal_fixture_export_name("observer", own["descriptorSha256"])[0].name)
        need(len(names) == 3, "removal-three-distinct-observer-exports")
        if self.removal_case == "abrupt":
            names.update(self.stager.removal_fixture_export_name("supervisor", self.removal_binding["removeDescriptorSha256"], role=role)[0].name
                         for role in ("live", "resume"))
            names.add(self.stager.removal_fixture_export_name("effects", self.removal_binding["removeDescriptorSha256"])[0].name)
        for name in names:
            self.removal_absent(self.removal_output_parent, name)
        before = self.removal_observe("before", segment="before")
        self.removal_before_settled = True
        # Validate the fresh baseline BEFORE launching an app or sending Remove.
        need(not before["archives"] and before["appPresent"] and not before["firstEligibleAbsent"]
             and not before["allPayloadAbsent"]
             and (before["presentFiles"], before["presentDirectories"]) == (before["expectedFiles"], before["expectedDirectories"]),
             "removal-genuine-installed-baseline")
        now, joint = self.removal_clock("joint")
        self.removal_joint_deadline = min(joint, now + 600_000_000_000)
        self.removal_ui_start(self.removal_joint_deadline)
        self.removal_marker("launched", self.removal_joint_deadline)
        live = "removal-live-cancel" if self.removal_case == "ordinary" else "removal-live-cut"
        package = self.removal_target["path"] / "Remove.pkg"
        argv = ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer", "-pkg", str(package), "-target", "/", "-dumplog", "-verboseR"]
        self.removal_inputs_post()
        self.removal_native_call(live, argv, segment="joint", maximum=123, minimum=123, limit=256 * 1024)
        self.removal_accept_outputs(live)
        if self.removal_case == "ordinary":
            self.removal_marker("cancel-observed", self.removal_joint_deadline)
            middle = self.removal_observe("after-cancel", segment="joint")
            self.stager.removal_fixture_observation_pair(before, middle, phase="after-cancel")
            self.removal_inputs_post()
            self.removal_native_call("removal-live-continue", argv, segment="joint", maximum=123, minimum=123, limit=256 * 1024)
            self.removal_accept_outputs("removal-live-continue")
        else:
            # The actual supervisor report86 is required before the separate
            # readonly O. Installer1 alone does NOT prove an abrupt child cut.
            supervisor, _ = self.removal_output_read("supervisor", self.removal_binding, role="live")
            need(supervisor["actualChildReturncode"] == 86 and supervisor["originalChildWaitObserved"] is True,
                 "removal-cut-actual-original-child")
            middle = self.removal_observe("after-cut", segment="joint")
            self.stager.removal_fixture_observation_pair(before, middle, phase="after-cut")
        self.removal_ui_join()
        self.removal_clock("joint")
        supervisor = effects = effects_sha = None
        if self.removal_case == "abrupt":
            self.removal_inputs_post()
            self.removal_outputs_post()
            self.removal_native_call("removal-resume", argv, segment="resume", maximum=123, minimum=123, limit=256 * 1024)
            self.removal_accept_outputs("removal-resume")
            effects, effects_sha = self.removal_output_read("effects", self.removal_binding)
            supervisor, _ = self.removal_output_read("supervisor", self.removal_binding, role="resume")
        terminal = self.removal_observe("terminal", segment="terminal")
        final = self.stager.removal_fixture_terminal_data(self.removal_case, before, middle, terminal,
            supervisor=supervisor, effects=effects, effects_sha=effects_sha)
        self.removal_outputs_post()
        self.removal_inputs_post()
        self.package_post()
        self.removal_complete = True
        self.removal_detach_all()
        self.removal_outputs_post()
        need(len(self.removal_threading.enumerate()) == 1 and self.removal_ui_joined
             and all(mount["detached"] for mount in self.removal_mounts), "removal-original-workers-settled")
        self.sha256 = self.removal_binding["packageSha256"]
        self.receipt["removalFixture"] = dict(final, originalUIJoined=True,
            uiObservation=self.removal_ui_facts["observation"], outputs=len(self.removal_output_facts),
            outputsSha256=digest(self.stager.canonical({name: facts[1][1] for name, facts in self.removal_output_facts.items()})),
            requestsDirectoryNamedOnly=True, mountedInputsDetached=True, sourcePrePostMatched=True,
            firstOriginalErrorPreserved=True, powerLossQualified=False, productReady=False)
        self.removal_clock("settle")

    def removal_abort_post(self):
        self.removal_clock()
        need(self.removal_api is not None and self.removal_slash is not None and self.removal_volumes is not None,
             "removal-abort-host-originals")
        self.recheck_directory(self.work_entry)
        self.recheck_directory(self.target_entry)
        self.package_post()
        self.removal_inputs_post()
        self.removal_outputs_post()
        if self.removal_install_root is not None: self.removal_directory_post(self.removal_install_root)
        if self.removal_channel is not None:
            self.removal_directory_post(self.removal_channel)
            need(not self.removal_names(self.removal_channel, 0), "removal-abort-empty-channel")
            self.removal_directory_post(self.removal_channel_parent)
        for entry in self.entries:
            need(entry["closed"] or type(entry["fd"]) is int, "removal-abort-unbound-original")
            need(entry.get("removal_acquired", True), "removal-abort-partial-acquisition")
        for context in self.removal_mounts:
            need(context["entered"] and context["known"], "removal-abort-unknown-mount")
            if context["detached"]: continue
            for entry in context["entries"]:
                if entry["kind"] == "removal-directory": self.removal_directory_post(entry)
                else: self.removal_stream(entry, limit=entry["removal_limit"], expected=entry["removal_file_facts"])
        self.removal_reserve(0)

    def removal_abort_detach(self):
        need(self.phase == "package-removal-fixture" and "failure" in self.receipt
             and self.removal_abort_roles is None and not self.removal_abort_known
             and not self.removal_ui_entered and self.removal_thread is None and not self.removal_ui_joined
             and self.removal_ui_outcome == {"done": False, "known": False} and not self.removal_ui_facts and self.removal_ui_deadline is None
             and not self.removal_markers and self.removal_requests is None and not self.removal_complete
             and not self.removal_unknown and self.removal_scan_state == "closed" and self.package_settled()
             and self.removal_threading is not None
             and self.removal_threading.current_thread() is self.removal_threading.main_thread()
             and len(self.removal_threading.enumerate()) == 1, "removal-abort-pre-ui-finality")
        prefix = tuple(row["role"] for row in self.calls)
        need(prefix in ((), ("removal-target-attach",), ("removal-target-attach", "removal-observers-attach"),
                        ("removal-target-attach", "removal-observers-attach", "removal-observer-before"))
             and (len(prefix) < 3 or self.removal_before_settled)
             and all(row.get("returned") is True and row.get("capturesSettled") is True
                     and type(row.get("returncode")) is int and row["returncode"] == 0 for row in self.calls)
             and tuple(m["role"] for m in self.removal_mounts) == (("target", "observers")[:min(len(prefix), 2)])
             and all(not m["detached"] and not m["detachAttempted"] for m in self.removal_mounts),
             "removal-abort-original-prefix")
        self.removal_abort_post()
        suffix = tuple("removal-" + m["role"] + "-detach" for m in reversed(self.removal_mounts))
        self.removal_abort_roles = prefix + suffix
        for context in reversed(self.removal_mounts):
            context["detachAttempted"] = True
            for entry in reversed(context["entries"]):
                self.close(entry)
                need(entry["closed"], "removal-abort-mounted-close")
            before = self.removal_roster(self.removal_volumes)
            result = self.removal_native_call("removal-" + context["role"] + "-detach",
                ["/usr/bin/hdiutil", "detach", context["device"]], segment="detach", maximum=15)
            need(type(result.returncode) is int and result.returncode == 0, "removal-detach-original-status")
            self.removal_own_parent_post(self.removal_volumes, before, context["name"], present=False)
            context["detached"] = True
        self.removal_abort_post()
        self.removal_clock("settle")
        self.removal_abort_known = True
        self.receipt["removalAbort"] = {"preUI": True, "workCalls": len(prefix), "detachCalls": len(suffix),
                                       "originalCleanupKnown": True, "passed": False}

    def removal_cleanup_ready(self):
        if self.phase == "package-removal-fixture" and self.removal_abort_known:
            return ("failure" in self.receipt and not self.removal_ui_entered and self.removal_thread is None
                    and not self.removal_unknown and all(m["known"] and m["detached"] for m in self.removal_mounts)
                    and tuple(row["role"] for row in self.calls) == self.removal_abort_roles and self.package_settled())
        return self.removal_finish_ready()

    def removal_finish_ready(self):
        if self.phase == "prepare-removal-observers":
            return (self.removal_preparation_complete and self.removal_final_context is None
                    and self.notary_known() and self.notary_key is None)
        if self.phase == "package-removal-fixture":
            if self.removal_thread is not None and not self.removal_ui_joined:
                try:
                    self.removal_ui_join()
                except BaseException as error:
                    self.removal_unknown = True
                    self.errors.append({"stage": "removal-ui-original-settlement", "type": type(error).__name__})
            return (self.removal_complete and self.removal_ui_joined and not self.removal_unknown
                    and all(mount["known"] and mount["detached"] for mount in self.removal_mounts)
                    and self.package_settled())
        return True

    def removal_baseline_admit(self):
        """The existing Install owner, on the fixed removal test ref only.

        This is still its original990s operation and genuine V2 readback. It
        only places the actual hdiutil mount under protected /Volumes; there
        is no alternate install root, forced cleanup or ancestor-policy fix.
        """
        need(self.phase == "package-install" and self.environment.get("GITHUB_REF") == REMOVAL_REF,
             "removal-baseline-fixed-owner")
        self.removal_case, self.removal_correlation = removal_context_data(self.environment, self.target)
        original = self.source_original("desktop/tools/macos_xcode_host_preparation.py", "removal-baseline-host-source", 512 * 1024)
        body = self.read(original)
        self.package_sources.append((original, body))
        self.removal_host_module = load_data(self.checkout, "macos_xcode_host_preparation.py", "_mrk_removal_baseline_host")
        need(self.read(original) == body, "removal-baseline-host-source-post")
        self.removal_host()
        self.removal_slash = self.removal_open_directory(None, "/", "removal-baseline-system-root", protected=True, system_ancestor=True)
        self.removal_volumes = self.removal_open_directory(self.removal_slash, "Volumes", "removal-baseline-volumes", protected=True, system_ancestor=True)
        parent = self.removal_result_parent()
        # Before the genuine Install original, absence is actual and exact.
        # The hosted-runner label itself is never installation ownership.
        self.removal_absent(parent, self.stager.INSTALL_ROOT.name)
        self.removal_absent(parent, "MobileReleaseKit-RemovalRequests")
        self.removal_baseline_mount = self.stager.removal_fixture_mount_path(self.removal_correlation, "install")
        self.removal_absent(self.removal_volumes, self.removal_baseline_mount.name)
        self.removal_baseline_roster = self.removal_roster(self.removal_volumes)

    def removal_baseline_attach(self, observation_path):
        need(self.removal_baseline_mount is not None and not self.mount_entered,
             "removal-baseline-one-attach")
        path = self.removal_baseline_mount
        self.removal_absent(self.removal_volumes, path.name)
        self.stage = "package-readonly-attach"
        attached = self.package_call("distribution-attach", ["/usr/bin/hdiutil", "attach", str(observation_path),
            "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", str(path), "-plist"], timeout=60)
        self.mount_device = cleanup_mount_device_data(attached.stdout, attached.stderr, attached.returncode, path)
        entry = self.removal_open_directory(self.removal_volumes, path.name, "removal-baseline-original-mount", readonly=True)
        entry["kind"] = "mount"  # Existing consuming-close route, not a second FD.
        info = os.fstat(entry["fd"])
        entry["identity"] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        self.mount_entry = entry
        need(entry["removal_facts"][0][0] != self.removal_volumes["removal_facts"][0][0]
             and entry["removal_facts"][2]["mountOn"] == str(path)
             and entry["removal_facts"][2]["mountFrom"] == self.mount_device, "removal-baseline-original-device")
        self.removal_own_parent_post(self.removal_volumes, self.removal_baseline_roster, path.name, present=True)
        self.package_post()
        self.mount_known = True
        need(self.stager.distribution_mount_data(attached.stdout, attached.stderr, attached.returncode, path)
             == self.mount_device, "package-accepted-mount-device")
        return path

    def removal_baseline_mount_post(self):
        need(self.mount_known and not self.mount_detached and self.mount_entry is not None,
             "removal-baseline-original-mount-unavailable")
        self.removal_directory_post(self.mount_entry)
        self.removal_directory_post(self.removal_volumes)
        self.removal_directory_post(self.removal_slash)
        need(self.removal_roster(self.removal_volumes) == dict(self.removal_baseline_roster,
             **{self.removal_baseline_mount.name: (self.mount_entry["identity"][0], self.mount_entry["identity"][1], stat.S_IFDIR)}),
             "removal-baseline-mounted-namespace")

    def removal_baseline_detached(self):
        # Called only after the existing actual unforced hdiutil original0.
        need(self.calls[-1]["role"] == "distribution-detach" and self.calls[-1]["returned"]
             and self.calls[-1].get("returncode") == 0 and self.calls[-1].get("capturesSettled") is True,
             "removal-baseline-detach-original")
        before = dict(self.removal_baseline_roster)
        before[self.removal_baseline_mount.name] = (self.mount_entry["identity"][0], self.mount_entry["identity"][1], stat.S_IFDIR)
        self.removal_own_parent_post(self.removal_volumes, before, self.removal_baseline_mount.name, present=False)
        self.removal_absent(self.removal_volumes, self.removal_baseline_mount.name)
        self.removal_directory_post(self.removal_slash)

    def package_clock(self):
        if self.app_absence is not None:
            return self.app_absence_module.clock(self)
        if self.phase == UPDATE_PHASE and self.update is not None:
            return self.update_module.clock(self)
        if self.phase in FINAL_IMAGE_PHASES or self.phase in ("prepare-removal-observers", SAME_PACKAGE_PHASE):
            return self.notary_clock()[0]  # Same clock; never the package-install990s endpoint.
        now = time.monotonic_ns()
        need(type(now) is int and type(self.package_endpoint) is int
             and self.package_started <= self.package_observed <= now < self.package_endpoint, "package-group-deadline")
        self.package_observed = now
        return now

    def package_settled(self):
        return (self.stager_io_pending is None and not self.errors and self.credential_known()
                and not self.credential_failed and not self.signing_mutation_pending
                and all(call["returned"] and call.get("capturesSettled") is True for call in self.calls)
                and all(entry["closed"] for entry in self.entries if entry["role"].startswith("output-")))

    def package_stager_io(self, operation, args):
        # Closed direct stager I/O boundaries, including the fixed no-op census. A thrown parse
        # refusal can mask that stager's local finally/close uncertainty; only a
        # normal return proves completion. Never infer it from an error token.
        need(operation in ("final-audit", "result-absence", "v2-readback")
             or operation == "readback-admission" and self.phase == "package-install"
                and self.prepared_binding is not None and not self.prepared_binding.same_source and args is None
             or operation == "setup-final-audit" and self.setup_verify
             or operation == "remove-input" and self.phase == "package-remove"
             or operation in ("same-package-census", "same-package-readback") and self.phase == SAME_PACKAGE_PHASE,
             "closed-stager-io")
        need(self.package_settled(), "package-io-finality-unknown")
        self.package_clock()
        self.stager_io_pending = operation
        self.stager_failure_module = self.stager
        try:
            if operation == "readback-admission":
                result = self.package_readback_module()
            elif operation == "setup-final-audit":
                result = self.stager.audit_xcode_setup_product_command(args)
            elif operation == "final-audit":
                audit = self.stager.audit_install_product_command if self.install_product else self.stager.audit_command
                result = audit(args)
            elif operation == "remove-input":
                result = self.stager.remove_input_command(args)
            elif operation == "result-absence":
                result = self.stager.installer_result_absent_command(args)
            elif operation == "same-package-census":
                result = self.stager.same_package_result_census()
            elif operation == "same-package-readback":
                result = self.stager.observation_command(args, expected_previous=args.expected_previous)
            else:
                observer = self.package_readback_module(args)
                self.stager_failure_module = observer
                result = observer.observation_command(args)
                if observer is not self.stager:
                    # Keep pending until the SAME current-source originals POST.
                    self.package_post()
                self.stager_failure_module = self.stager
        except BaseException:
            self.errors.append({"stage": "package-stager-io", "operation": operation, "type": "CompletionUnknown"})
            raise  # Preserve the identical primary error; the pending latch stays.
        self.stager_io_pending = None
        self.package_clock()
        return result

    def package_call(self, role, argv, *, environment=None, timeout=30, limit=65536, cwd=None):
        if getattr(self, "candidate_restore_context", None) is not None:
            need(sum(e["fd"] is not None or not e["closed"] for e in self.entries) + 8 <= self.app_absence_live_limit(), "candidate-native-original-quote")
        if self.phase == "prepare-removal-observers":
            return self.removal_prepare_call(role, argv, maximum=timeout, limit=limit, cwd=cwd, environment=environment)
        if self.phase in FINAL_IMAGE_PHASES:
            need(role == "distribution-detach" and argv == ["/usr/bin/hdiutil", "detach", self.mount_device]
                 and timeout == 30 and limit == 65536 and environment is None and cwd is None,
                 "final-image-fixed-detach-route")
            return self.final_image_call("final-image-detach", argv)
        need(self.package_settled(), "package-io-finality-unknown")
        endpoint = self.notary_clock()[1] if self.phase == SAME_PACKAGE_PHASE else self.package_endpoint
        timeout = package_timeout_data(self.package_clock(), endpoint, timeout, phase=self.phase, role=role)
        result = self.call(role, argv, self.native_environment() if environment is None else environment,
                           cwd=self.work if cwd is None else cwd, timeout=timeout, limit=limit)
        self.package_clock()  # Original return AND the existing capture/status closes.
        return result

    def package_producer_compile(self, environment):
        # One480s compiler envelope shared by tests and the normal example.
        endpoint = min(self.package_endpoint, self.package_clock() + 480_000_000_000)
        self.stage = "package-producer-tests"
        tested = self.package_call("producer-tests", [direct_rust_tools(self.target)[0], "test", "--manifest-path",
            str(self.checkout / "desktop/src-tauri/Cargo.toml"), "--locked", "--offline", "--release", "--config",
            PRODUCER_CARGO_OVERRIDE, "--jobs", "1", "--target", self.target, "--no-default-features", "--features",
            "macos-package-producer", "--example", "macos_package_producer", "--message-format=short", "--color", "never",
            "--", "--exact", "emitter::tests::fixed_cli_and_original_state_data_refuse_ambient_or_partial_routes",
            "--test-threads=1", "--format", "pretty", "--color", "never"], environment=environment,
            cwd=self.checkout / "desktop/src-tauri", timeout=package_timeout_data(self.package_clock(), endpoint, 480),
            limit=4 * 1024 * 1024)
        producer_tests_result(tested.stdout)
        remaining = package_timeout_data(self.package_clock(), endpoint, 480)
        del tested
        self.stage = "package-explicit-producer-compiler"
        compiled = self.package_call("producer-build", [direct_rust_tools(self.target)[0], "build", "--manifest-path",
            str(self.checkout / "desktop/src-tauri/Cargo.toml"), "--locked", "--offline", "--release", "--config",
            PRODUCER_CARGO_OVERRIDE, "--jobs", "1", "--target", self.target, "--no-default-features", "--features",
            "macos-package-producer", "--example", "macos_package_producer", "--message-format=json-render-diagnostics"],
            environment=environment, cwd=self.checkout / "desktop/src-tauri", timeout=remaining, limit=4 * 1024 * 1024)
        binary = producer_artifact(compiled.stdout, self.checkout, self.work / self.target_name, self.target,
            package_version=self.image_package_version)
        package_timeout_data(self.package_clock(), endpoint, 480)
        return binary

    def package_directory(self, name):
        self.package_clock()
        self.recheck_directory(self.work_entry)
        os.mkdir(name, 0o700, dir_fd=self.work_entry["fd"])
        entry = self.directory(self.work_entry, name, "package-" + name)
        need(not os.listdir(entry["fd"]), "package-exclusive-empty-directory")
        return entry

    def package_file(self, parent, name, body):
        self.package_clock()
        need(type(body) is bytes and 0 < len(body) <= self.stager.MAX_BYTES, "package-output-bound")
        self.recheck_directory(parent)
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent["fd"])
        entry = self.register(fd, "package-output-" + name, "file", parent["fd"], name)
        entry["parent_entry"] = parent
        offset = 0
        while offset < len(body):
            self.package_clock()
            written = os.write(fd, body[offset:offset + 1024 * 1024])
            need(written > 0, "package-output-short-write")
            offset += written
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
             and info.st_gid == os.getgid() and info.st_size == len(body), "package-output-original")
        os.fchmod(fd, 0o444)
        os.fsync(fd)
        entry["identity"] = signature(os.fstat(fd))
        need(self.read(entry) == body, "package-output-readback")
        self.package_outputs.append((entry, digest(body)))
        self.package_clock()
        return entry

    def package_post(self):
        self.package_clock()
        self.candidate_removal_post()
        for root, names in self.package_roots:
            self.recheck_directory(root)
            observed_names = self.removal_names(root, len(names)) if self.phase in REMOVAL_OWNER_PHASES else os.listdir(root["fd"])
            need(set(observed_names) == names, "package-source-layout-roster")
        for entry, expected in self.package_outputs:
            sha = (self.notary_stream(entry) if self.phase == "prepare-removal-observers" else
                   self.removal_stream(entry, limit=self.stager.MAX_BYTES)[0][1] if self.phase == "package-removal-fixture" else
                   digest(self.read(entry)))
            need(sha == expected, "package-original-post")
            self.package_clock()
        for entry, body in self.package_sources:
            need(self.read(entry) == body, "package-source-post")
        self.package_clock()

    def package_normalize_created_image(self, path, label):
        # Reachable only immediately after the fixed create original settled.
        expected = self.work / self.image_directory / (
            self.image_filename if label == "distribution" else "MobileReleaseKit-Observation.dmg")
        need(label in ("distribution", "observation") and (not self.removal or label == "distribution")
             and path == expected and self.package_settled() and self.calls
             and self.calls[-1]["role"] == label + "-create", "created-image-fixed-admission")
        parent = self.distribution_entry
        self.recheck_directory(parent)
        need(parent["parent_entry"] is self.work_entry and parent["name"] == self.image_directory,
             "created-image-fixed-parent")
        self.package_clock()
        entry = self.original(parent, path.name, label + "-created-image", self.stager.MAX_BYTES,
                              (0o600, 0o644, 0o444))
        try:
            def recheck():
                self.package_clock()
                self.recheck_directory(parent)
                need(self.entry_registry.get(id(entry)) is entry and not entry["closed"]
                     and type(entry["fd"]) is int and entry["parent_entry"] is parent
                     and entry["parent"] == parent["fd"], "created-image-original-unavailable")
                held = signature(os.fstat(entry["fd"]))
                need(held == signature(os.stat(path.name, dir_fd=parent["fd"], follow_symlinks=False)),
                     "created-image-named-original-changed")
                self.recheck_directory(parent)
                return held
            need(recheck() == entry["identity"], "created-image-original-admission")
            entry["identity"] = _normalize_created_dmg_finder_info(
                entry["fd"], recheck, self.stager.no_xattrs)
            self.package_clock()
        finally:
            self.close(entry)  # Existing owner consumes once, collects close errors.
        need(entry["closed"] and entry["fd"] is None and self.package_settled(),
             "created-image-close-unknown")  # No signing after uncertain close.

    def package_image(self, root, label):
        need(label in ("distribution", "observation") and (not self.removal or label == "distribution"), "package-image-fixed-label")
        path = self.work / self.image_directory / (self.image_filename if label == "distribution" else "MobileReleaseKit-Observation.dmg")
        identifier = self.image_identifier if label == "distribution" else "dev.mobile-release-kit.desktop.observation"
        self.package_call(label + "-create", ["/usr/bin/hdiutil", "create", "-srcfolder", str(self.work / root["name"]),
            "-fs", "HFS+", "-format", "UDZO", "-volname", "MobileReleaseKit", str(path)], timeout=180)
        self.package_post()
        self.package_normalize_created_image(path, label)
        # Only this fresh task-owned image is signed. SOURCE selects the exact
        # identity; missing credentials never fall back to an ad-hoc identity.
        with self.credential_scope(label + "-image"):
            self.package_call(label + "-sign", ["/usr/bin/codesign", "--sign", self.signing[1], "--timestamp",
                "--identifier", identifier, str(path)], timeout=60)
            image = self.original(self.distribution_entry, path.name, label + "-signed-image", self.stager.MAX_BYTES, (0o600, 0o644, 0o444))
            body = self.read(image)
            before = image["identity"]
            os.fchmod(image["fd"], 0o444)  # Authorized metadata change on our newly-created original only.
            os.fsync(image["fd"])
            after = signature(os.fstat(image["fd"]))
            need(after[:2] == before[:2] and after[3:8] == before[3:8]
                 and after[2] == stat.S_IFREG | 0o444, "package-image-mode-transition")
            image["identity"] = after  # fchmod may legitimately change ctime; bytes/other identity stay exact.
            need(self.read(image) == body, "package-image-mode-bytes")
            self.package_outputs.append((image, digest(body)))
            self.package_call(label + "-verify-signature", ["/usr/bin/codesign", "--verify", "--strict",
                "--test-requirement", "=" + signing_requirement(self.signing, identifier), str(path)])
        self.package_call(label + "-verify-image", ["/usr/bin/hdiutil", "verify", str(path)], timeout=120)
        self.package_post()
        return {"file": path.name, "sha256": digest(body), "bytes": len(body)}, path

    def normal_mount_host(self):
        self.package_clock()
        need(self.phase in ("package-install", SAME_PACKAGE_PHASE, UPDATE_PHASE, XCODE_SETUP_VERIFY) + FINAL_IMAGE_PHASES
             and self.removal_baseline_mount is None and not self.mount_entered
             and self.mount_api is None and self.mount_host_source is None and self.package_settled(),
             "package-mount-host-admission")
        entry = self.source_original("desktop/tools/macos_xcode_host_preparation.py", "source-package-mount-host", 96477)
        body = self.read(entry)
        need(len(body) == 96477 and digest(body) == "d03cfd5c200564efd71050548ebac85b4f9b56fd3619027ec35ce6a1528e5376",
             "package-mount-host-source")
        self.package_sources.append((entry, body))
        self.mount_host_source = (entry, body)
        module = load_data(self.checkout, "macos_xcode_host_preparation.py", "_mrk_package_mount_host")
        need(self.read(entry) == body, "package-mount-host-source-post")
        self.package_clock()
        self.mount_api = module.DarwinAPI(_RemovalHostClock(self), target=self.target)
        if self.phase in ("package-install", SAME_PACKAGE_PHASE, UPDATE_PHASE, XCODE_SETUP_VERIFY):
            need(self.removal_host_module is None and self.removal_api is None, "package-transport-host-original")
            self.removal_host_module, self.removal_api = module, self.mount_api
        self.package_clock()
        need(self.read(entry) == body, "package-mount-host-source-post")

    def transport_source_post(self):
        need(self.mount_host_source is not None and self.mount_api is self.removal_api,
             "package-transport-host-unavailable")
        source, body = self.mount_host_source
        need(self.read(source) == body, "package-mount-host-source-post")
        self.package_clock()

    def transport_mount_admit(self):
        need(self.transport_mount is None and not self.mount_entered and self.package_settled(),
             "package-transport-one-admission")
        context = {"GITHUB_RUN_ID": self.environment.get("GITHUB_RUN_ID"),
                   "GITHUB_RUN_ATTEMPT": self.environment.get("GITHUB_RUN_ATTEMPT")}
        path = transport_mount_path_data(context, self.target, self.phase)
        self.transport_source_post()
        self.transport_slash = self.removal_open_directory(None, "/", "package-transport-system-root", protected=True, system_ancestor=True)
        self.transport_volumes = self.removal_open_directory(self.transport_slash, "Volumes", "package-transport-volumes", protected=True, system_ancestor=True)
        for entry in (self.transport_slash, self.transport_volumes):
            need(not entry["removal_facts"][2]["flags"] & 0x400000, "package-transport-automounted")
        self.removal_absent(self.transport_volumes, path.name)
        self.transport_roster = self.removal_roster(self.transport_volumes)
        self.transport_mount = path
        self.transport_source_post()
        return path

    def transport_mount_facts(self):
        self.transport_source_post()
        context = {"GITHUB_RUN_ID": self.environment.get("GITHUB_RUN_ID"),
                   "GITHUB_RUN_ATTEMPT": self.environment.get("GITHUB_RUN_ATTEMPT")}
        need(self.transport_mount == transport_mount_path_data(context, self.target, self.phase)
             and self.mount_entry is not None, "package-transport-original-mount")
        self.removal_directory_post(self.mount_entry)
        self.removal_directory_post(self.transport_volumes)
        self.removal_directory_post(self.transport_slash)
        for entry in (self.mount_entry, self.transport_volumes, self.transport_slash):
            need(not entry["removal_facts"][2]["flags"] & 0x400000, "package-transport-automounted")
        need(self.mount_entry["removal_facts"][0][0] != self.transport_volumes["removal_facts"][0][0]
             and self.mount_entry["removal_facts"][2]["mountOn"] == str(self.transport_mount)
             and self.mount_entry["removal_facts"][2]["mountFrom"] == self.mount_device,
             "package-transport-original-device")
        wanted = dict(self.transport_roster)
        wanted[self.transport_mount.name] = (self.mount_entry["identity"][0], self.mount_entry["identity"][1], stat.S_IFDIR)
        need(self.removal_roster(self.transport_volumes) == wanted, "package-transport-mounted-namespace")
        self.transport_source_post()

    def transport_mount_detached(self):
        role = UPDATE_ROLES[2] if self.phase == UPDATE_PHASE else "distribution-detach"
        need(self.calls[-1]["role"] == role and self.calls[-1]["returned"]
             and self.calls[-1].get("returncode") == 0 and self.calls[-1].get("capturesSettled") is True,
             "package-transport-detach-original")
        self.transport_source_post()
        before = dict(self.transport_roster)
        before[self.transport_mount.name] = (self.mount_entry["identity"][0], self.mount_entry["identity"][1], stat.S_IFDIR)
        self.removal_own_parent_post(self.transport_volumes, before, self.transport_mount.name, present=False)
        self.removal_absent(self.transport_volumes, self.transport_mount.name)
        self.removal_directory_post(self.transport_slash)
        for entry in (self.transport_slash, self.transport_volumes):
            need(not entry["removal_facts"][2]["flags"] & 0x400000, "package-transport-automounted")
        self.transport_source_post()

    def mount_facts(self, entry):
        # MNT_MULTILABEL is MAC-label support, not MNT_UNION (Apple mount.h).
        """Validate acquisition without publishing cleanup-known prematurely."""
        self.package_clock()
        self.recheck_directory(self.work_entry)
        need(self.entry_registry.get(id(entry)) is entry and type(entry.get("fd")) is int
             and not entry["closed"] and entry["parent"] == self.work_entry["fd"]
             and entry["name"] == "package-mount" and self.mount_api is not None
             and self.mount_host_source is not None, "package-original-mount-unavailable")
        source, body = self.mount_host_source
        need(self.read(source) == body, "package-mount-host-source-post")
        named = os.stat("package-mount", dir_fd=self.work_entry["fd"], follow_symlinks=False)
        held = os.fstat(entry["fd"])
        need(stat.S_ISDIR(held.st_mode) and held.st_uid in (0, os.getuid()) and not held.st_mode & 0o022
             and signature(named) == signature(held)
             and (held.st_dev, held.st_ino, held.st_mode, held.st_uid, held.st_gid) == entry["identity"],
             "package-readonly-mount-shape")
        flags = os.fstatvfs(entry["fd"]).f_flag
        fs = self.mount_api.filesystem(entry["fd"])
        self.package_clock()
        need(type(flags) is int and flags & os.ST_RDONLY and held.st_dev != self.work_entry["identity"][0]
             and type(fs) is dict and type(fs.get("flags")) is int and 0 <= fs["flags"] < 1 << 32
             and fs["flags"] & 1 and fs["flags"] & 0x1000 and not fs["flags"] & 0x20
             and fs.get("typeName") in ("hfs", "apfs")
             and fs.get("mountOn") == str(self.work / "package-mount")
             and fs.get("mountFrom") == self.mount_device, "package-readonly-mount-original")
        need(self.read(source) == body and signature(os.fstat(entry["fd"])) == signature(held)
             and signature(os.stat("package-mount", dir_fd=self.work_entry["fd"], follow_symlinks=False)) == signature(held),
             "package-readonly-mount-post")
        self.recheck_directory(self.work_entry)
        self.package_clock()
        return fs

    def mount_custody(self, attached, role):
        need(self.mount_entered and not self.mount_known and self.mount_entry is None
             and self.package_settled(), "package-mount-custody-admission")
        path = self.transport_mount if self.transport_mount is not None else self.work / "package-mount"
        self.mount_device = cleanup_mount_device_data(attached.stdout, attached.stderr, attached.returncode, path)
        if self.transport_mount is not None:
            self.transport_source_post()
            self.removal_reserve()
            entry = self.register(None, role, "mount", self.transport_volumes["fd"], path.name)
            self.mount_entry = entry  # Acquisition custody BEFORE the syscall, including failure.
            entry["parent_entry"] = self.transport_volumes
            entry["fd"] = os.open(path.name, READ_FLAGS | os.O_DIRECTORY, dir_fd=self.transport_volumes["fd"])
            entry["removal_policy"] = (False, True, False)
            entry["removal_facts"] = self.removal_directory_facts(entry, readonly=True)
            info = os.fstat(entry["fd"])
            entry["identity"] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
            need(not entry["removal_facts"][2]["flags"] & 0x400000
                 and entry["removal_facts"][0][0] != self.transport_volumes["removal_facts"][0][0]
                 and entry["removal_facts"][2]["mountOn"] == str(path)
                 and entry["removal_facts"][2]["mountFrom"] == self.mount_device,
                 "package-transport-original-device")
            self.removal_own_parent_post(self.transport_volumes, self.transport_roster, path.name, present=True)
            self.transport_mount_facts()
            self.package_post()
            self.mount_known = True  # Original cleanup authority, NOT parser acceptance.
            need(self.stager.distribution_mount_data(attached.stdout, attached.stderr, attached.returncode, path)
                 == self.mount_device, "package-accepted-mount-device")
            return
        self.package_clock()
        self.recheck_directory(self.work_entry)
        entry = self.register(None, role, "mount", self.work_entry["fd"], "package-mount")
        self.mount_entry = entry
        entry["fd"] = os.open("package-mount", READ_FLAGS | os.O_DIRECTORY, dir_fd=self.work_entry["fd"])
        info = os.fstat(entry["fd"])
        entry["identity"] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        entry["mount_facts"] = self.mount_facts(entry)
        self.package_post()
        self.mount_known = True  # Original cleanup authority, NOT parser acceptance.
        need(self.stager.distribution_mount_data(attached.stdout, attached.stderr, attached.returncode, path)
             == self.mount_device, "package-accepted-mount-device")

    def recheck_mount(self):
        if self.removal_baseline_mount is not None:
            self.removal_baseline_mount_post()
            return
        need(self.mount_known and not self.mount_detached and self.mount_entry is not None,
             "package-original-mount-unavailable")
        if self.transport_mount is not None:
            self.transport_mount_facts()
            return
        need(self.phase in FINAL_IMAGE_PHASES, "package-transport-mount-required")
        need(self.mount_facts(self.mount_entry) == self.mount_entry["mount_facts"], "package-mount-facts-changed")



    def mount_inputs(self, expected, package_name):
        self.recheck_mount()
        actual = {}
        descriptor_name = "remove-producer.json" if self.removal else "producer.json"
        signature_name = "remove-producer.sig" if self.removal else "producer.sig"
        for name in (package_name, descriptor_name, signature_name):
            limit = self.stager.MAX_BYTES if name == package_name else (
                self.stager.PRODUCER_DESCRIPTOR_BYTES if name == descriptor_name else self.stager.PRODUCER_SIGNATURE_BYTES)
            entry = self.register(None, "mounted-" + name, "mounted-file", self.mount_entry["fd"], name)
            entry["fd"] = fd = os.open(name, READ_FLAGS, dir_fd=self.mount_entry["fd"])
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o444
                 and info.st_nlink == 1 and info.st_uid in (0, os.getuid()) and 0 < info.st_size <= limit,
                 "package-mounted-file-shape")
            entry["identity"] = signature(info)
            body = os.pread(fd, info.st_size + 1, 0)
            need(len(body) == info.st_size and signature(os.fstat(fd)) == entry["identity"]
                 == signature(os.stat(name, dir_fd=self.mount_entry["fd"], follow_symlinks=False)), "package-mounted-file-original")
            entry["sha256"] = digest(body)
            actual[name] = (body, 0o444)
        if self.removal:
            need(package_name == "Remove.pkg", "final-removal-mount-package")
            self.stager.removal_distribution_layout_data(os.listdir(self.mount_entry["fd"]), expected, actual)
        else:
            self.stager.distribution_layout_data(os.listdir(self.mount_entry["fd"]), package_name, expected, actual)
        self.recheck_mount()

    def mounted_post(self):
        self.recheck_mount()
        for entry in self.entries:
            if entry["kind"] == "mounted-file":
                need(entry["fd"] is not None and signature(os.fstat(entry["fd"])) == entry["identity"]
                     == signature(os.stat(entry["name"], dir_fd=self.mount_entry["fd"], follow_symlinks=False)), "package-mounted-post")
                body = os.pread(entry["fd"], entry["identity"][6] + 1, 0)
                need(len(body) == entry["identity"][6] and digest(body) == entry["sha256"]
                     and signature(os.fstat(entry["fd"])) == entry["identity"]
                     == signature(os.stat(entry["name"], dir_fd=self.mount_entry["fd"], follow_symlinks=False)), "package-mounted-post-bytes")
        need(set(os.listdir(self.mount_entry["fd"])) == {self.package_name, "remove-producer.json" if self.removal else "producer.json",
             "remove-producer.sig" if self.removal else "producer.sig"}, "package-mounted-post-roster")
        self.recheck_mount()

    def detach_package_mount(self):
        need(self.mount_known and not self.mount_detached
             and (not self.installer_entered or self.installer_zero and self.installation_readback), "package-mount-retention-required")
        need(self.package_settled(), "package-mount-finality-unknown")
        self.recheck_mount()
        for entry in self.entries:
            if entry["kind"] in ("mounted-file", "mount"):
                self.close(entry)
                need(entry["closed"], "package-mount-close-unknown")
        # The original reported device is used once, without force/fallback or
        # adopting unrelated OS services. Closing our FDs precedes detach.
        self.package_call(UPDATE_ROLES[2] if self.phase == UPDATE_PHASE else "distribution-detach",
                          ["/usr/bin/hdiutil", "detach", self.mount_device], timeout=60 if self.phase == UPDATE_PHASE else 30)
        if self.removal_baseline_mount is not None:
            self.removal_baseline_detached()
        elif self.transport_mount is not None:
            self.transport_mount_detached()
        else:
            self.recheck_directory(self.mount_placeholder)
            need(not os.listdir(self.mount_placeholder["fd"]), "package-detached-mountpoint-not-empty")
            os.rmdir("package-mount", dir_fd=self.work_entry["fd"])
        self.mount_detached = True
        self.package_clock()

    def same_package_save_status(self, code):
        need(self.phase == SAME_PACKAGE_PHASE and type(code) is int and self.same_package_case is not None,
             "same-package-status-purpose")
        self.recheck_directory(self.same_package_case)
        need(set(os.listdir(self.same_package_case["fd"])) == {"input"}, "same-package-status-absence")
        # Fixed owned ancestry; never overwrite/copy the first Installer status.
        self.publish("installer-output.status", (str(code) + "\n").encode("ascii"), parent=self.same_package_case)
        self.recheck_directory(self.same_package_case)
        need(set(os.listdir(self.same_package_case["fd"])) == {"input", "installer-output.status"}, "same-package-status-post")
        self.package_roots = [(root, {"input", "installer-output.status"} if root is self.same_package_case else names)
                              for root, names in self.package_roots]

    def same_package_post(self):
        self.package_post()
        self.final_image_post()
        need(self.notary_known() and not self.credential_calls and not self.credential_contexts
             and self.notary_key is None, "same-package-originals-unknown")
        if self.mount_known and not self.mount_detached:
            self.mounted_post()

    def same_package_noop(self):
        self.stage = SAME_PACKAGE_PHASE
        need(self.phase == SAME_PACKAGE_PHASE and self.signing is not None
             and self.environment.get("MRK_MACOS_SAME_PACKAGE_SCOPE") == SAME_PACKAGE_PHASE
             and self.environment.get("GITHUB_REF") == "refs/heads/verify/desktop-macos-preview"
             and self.environment.get("MRK_MACOS_PACKAGE_ROLE") == "ordinary-image"
             and not any(k in self.environment for k in CREDENTIAL_VARIABLES + INSTALLER_CREDENTIAL_VARIABLES
                         + (NOTARY_KEY_VARIABLE,)), "same-package-fixed-purpose")
        expected, binding = self.final_image_input()
        def retained(parent, name, maximum, modes=(0o600, 0o444)):
            entry = self.original(parent, name, "same-package-input-" + name, maximum, modes)
            body = self.read(entry)
            self.final_image_inputs.append((entry, digest(body)))
            return body
        need(retained(self.work_entry, "image-finalization.status", 4) == b"0\n", "same-package-finalizer-original")
        owner_body = retained(self.work_entry, "android-helper-package-install.json", 16384)
        final_package = retained(self.work_entry, "android-helper-finalize-package.json", 16384)
        final_body = retained(self.work_entry, "android-helper-finalize-image.json", 16384)
        notary_profile = self.source_original(NOTARY_PROFILE, "same-package-notary-source", 1024)
        profile_body = self.read(notary_profile)
        self.package_sources.append((notary_profile, profile_body))
        selection = self.stager.BuildSelection(self.target, binding["packageVersion"], binding["release"])
        final = self.stager.final_image_receipt_data(final_body, selection=selection,
            binding={"source": self.image_source, "runId": self.environment["GITHUB_RUN_ID"],
                     "runAttempt": self.environment["GITHUB_RUN_ATTEMPT"]}, request=binding["requestId"],
            package=expected["Install.pkg"], descriptor=expected["producer.json"], signed=expected["producer.sig"],
            original_image={"file": "MobileReleaseKit.dmg", "bytes": binding["originalImageBytes"],
                            "sha256": binding["originalImageSha256"]},
            package_owner=owner_body, final_package=final_package, release_body=self.read(self.release_entry),
            profiles=(self.producer_profile, self.service_profile, profile_body))
        root = self.directory(self.work_entry, "distribution-final", "same-package-final-carrier-root")
        need(os.listdir(root["fd"]) == ["MobileReleaseKit.dmg"], "same-package-final-carrier-roster")
        self.final_image_roots.append((root, {"MobileReleaseKit.dmg"}))
        image = self.original(root, "MobileReleaseKit.dmg", "same-package-final-carrier", self.stager.MAX_BYTES, (0o444,))
        need(image["identity"][6] == final["imageBytes"] and self.notary_stream(image) == final["imageSha256"],
             "same-package-final-carrier-bytes")
        self.final_image_inputs.append((image, final["imageSha256"]))
        self.package_name = "Install.pkg"
        self.same_package_post()
        self.normal_mount_host()
        mount_path = self.transport_mount_admit()
        mounted = self.package_call("distribution-attach", ["/usr/bin/hdiutil", "attach",
            str(self.work / "distribution-final/MobileReleaseKit.dmg"), "-readonly", "-nobrowse", "-noautoopen",
            "-mountpoint", str(mount_path), "-plist"], timeout=60)
        self.mount_custody(mounted, "same-package-readonly-mount")
        self.mount_inputs(expected, "Install.pkg")
        args = argparse.Namespace(target=self.target, fixture=False, input=self.work / "input",
            expected_source=self.image_source, expected_inventory=self.environment["MRK_MACOS_INSTALL_INVENTORY_SHA256"],
            expected_manifest=self.environment["MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"], request_id=binding["requestId"],
            expected_package=binding["packageSha256"], producer_descriptor=mount_path / "producer.json",
            producer_signature=mount_path / "producer.sig", installer_status=self.work / "installer-output.status",
            package=mount_path / "Install.pkg")
        self.same_package_post()
        baseline = self.package_stager_io("v2-readback", args)
        need(baseline["originalInstallerResult"]["action"] == "fresh-install", "same-package-fresh-baseline")
        before = self.package_stager_io("same-package-census", None)
        baseline_request = binding["requestId"]
        need(set(before) == {baseline_request} and before[baseline_request] == {
            k: baseline["installerResultExport"][k] for k in ("bytes", "sha256", "identity")}, "same-package-baseline-export")
        self.same_package_case = self.package_directory("same-package-case")
        os.mkdir("input", 0o700, dir_fd=self.same_package_case["fd"])
        projected = self.directory(self.same_package_case, "input", "same-package-inventory-input")
        source_input = self.directory(self.work_entry, "input", "same-package-original-input")
        inventory = self.original(source_input, self.stager.INSTALLATION_INVENTORY_NAME, "same-package-inventory", self.stager.INVENTORY_BYTES, (0o444,))
        inventory_body = self.read(inventory)
        need(digest(inventory_body) == args.expected_inventory, "same-package-inventory-binding")
        self.package_sources.append((inventory, inventory_body))
        self.package_file(projected, self.stager.INSTALLATION_INVENTORY_NAME, inventory_body)
        self.package_roots.extend(((self.same_package_case, {"input"}), (projected, {self.stager.INSTALLATION_INVENTORY_NAME})))
        args.input = self.work / "same-package-case/input"
        args.installer_status = self.work / "same-package-case/installer-output.status"
        args.expected_previous = {"invocation": baseline["invocation"], "sha256": baseline["originalInstallerResult"]["stateSha256"]}
        self.same_package_post()
        need(package_timeout_data(self.package_clock(), self.notary_clock()[1], 123) == 123,
             "installer-original-clock-reserve")
        original = self.package_call("installer", ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer", "-pkg", str(args.package),
            "-target", "/", "-dumplog", "-verboseR"], timeout=123, limit=256 * 1024)
        self.installer_zero = original.returncode == 0
        self.same_package_post()
        after = self.package_stager_io("same-package-census", None)
        args.request_id = self.stager.same_package_new_request(before, after, baseline_request)
        observed = self.package_stager_io("same-package-readback", args)
        need(observed["samePackagePredecessorMatched"] is True and observed["invocation"] != baseline["invocation"]
             and observed["installationMetadata"] == baseline["installationMetadata"]
             and observed["nonrootReadbackFileCount"] == baseline["nonrootReadbackFileCount"]
             and after[args.request_id] == {k: observed["installerResultExport"][k] for k in ("bytes", "sha256", "identity")},
             "same-package-live-readback")
        need(self.package_stager_io("same-package-census", None) == after, "same-package-result-post")
        self.publish("same-package-observation.json", self.stager.canonical(observed) + b"\n")
        self.installation_readback = True
        self.same_package_post()
        self.detach_package_mount()
        self.same_package_post()
        self.receipt["samePackageObservation"] = {"schemaVersion": 1, "kind": "final-carrier-same-package-noop",
            "finalImageReceiptSha256": digest(final_body), "imageSha256": final["imageSha256"],
            "packageSha256": binding["packageSha256"], "inventorySha256": args.expected_inventory,
            "runtimeManifestSha256": args.expected_manifest,
            "baselineResultSha256": before[baseline_request]["sha256"], "resultSha256": after[args.request_id]["sha256"],
            "beforeExportCount": 1, "afterExportCount": 2, "newExportCount": 1,
            "payloadWriteCount": 0, "payloadWriteBytes": 0, "verifiedCurrentFiles": observed["nonrootReadbackFileCount"],
            "samePackageNoopObserved": True, "immediatePredecessorMatched": True, "currentObjectsPreserved": True,
            "retainedGenerationsPreserved": True, "currentBytesVerified": True, "baselineExportUnchanged": True,
            "originalInstallerReturnedZero": self.installer_zero, "mountReadOnly": True, "mountOriginalsMatch": True,
            "originalMountDetached": self.mount_detached, "systemServiceExitClaimed": False, "productReady": False}
        self.sha256 = final["imageSha256"]
        self.same_package_complete = True
        self.notary_clock()

    def candidate_baseline(self, acquisition_entry, acquisition_status, producer, nomination, helper_tree):
        # Internal sequential-owner seam only. admit()/CLI do not admit this
        # phase; no native activation without the separate source/host bootstrap.
        need(self.phase == "candidate-baseline" and self.app_absence_module is not None,
             "candidate-baseline-fixed-phase")
        try:
            self.app_absence_module.candidate_baseline(self, acquisition_entry, acquisition_status, producer, nomination, helper_tree)
        finally:
            self.finish()
        return self.app_absence_module.candidate_baseline_result(self, nomination, helper_tree)

    def setup_verification_cleanup_clock(self):
        now = time.monotonic_ns()
        need(type(now) is int and type(self.setup_verify_hard) is int
             and self.package_started <= self.package_observed <= now < self.setup_verify_hard,
             "setup-verification-cleanup-deadline")
        self.package_observed = now

    def setup_verification_quote(self, extra=0):
        need(self.setup_verify and type(extra) is int and 0 <= extra <= 64,
             "setup-verification-purpose")
        # Original records never refunded; closed descriptors alone release live slots.
        need(len(self.entries) + extra + 20 <= 24576
             and sum(not entry["closed"] for entry in self.entries) + extra + 8 <= 96,
             "setup-verification-original-quote")
        self.package_clock()

    def setup_verification_fixed_post(self, entry):
        facts = self.removal_directory_facts(entry, protected=True)
        old = entry["removal_facts"]
        # PackageKit can change containing directory times/size. Never change
        # the original device/inode/kind/mode/owner, flags, ACL or mount facts.
        need(tuple(facts[0][i] for i in (0, 1, 2, 4, 5)) == tuple(old[0][i] for i in (0, 1, 2, 4, 5)) and facts[1:] == old[1:],
             "setup-verification-system-parent")

    def setup_verification_file(self, parent, name, limit, modes):
        self.setup_verification_quote(1)
        self.setup_verification_fixed_post(parent)
        entry = self.register(None, "setup-current-file", "file", parent["fd"], name)
        entry["parent_entry"] = parent
        entry["fd"] = os.open(name, READ_FLAGS, dir_fd=parent["fd"])
        info = os.fstat(entry["fd"])
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
             and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in modes
             and 0 < info.st_size <= limit, "setup-verification-current-file")
        entry["identity"] = signature(info)
        self.removal_acl(entry, info)
        body = os.pread(entry["fd"], info.st_size + 1, 0)
        need(len(body) == info.st_size and signature(os.fstat(entry["fd"])) == entry["identity"]
             == signature(os.stat(name, dir_fd=parent["fd"], follow_symlinks=False)),
             "setup-verification-current-read")
        self.setup_verify_returned.append((entry, digest(body)))
        return body

    def setup_verification_absent(self):
        for parent, name in ((self.setup_library, "MobileReleaseKitDeveloper"), (self.setup_library, self.stager.XCODE_SETUP_CARRIER),
                             (self.setup_receipts, self.stager.XCODE_SETUP_ID+".plist"), (self.setup_receipts, self.stager.XCODE_SETUP_ID+".bom")):
            self.removal_absent(parent, name)

    def setup_verification_current(self, first):
        need(self.setup_verify and not self.setup_verify_returned
             and len(self.calls) == (3 if first else 4)
             and self.calls[-1].get("returncode") == 0
             and self.calls[-1].get("capturesSettled") is True,
             "setup-verification-returned-cut")
        self.setup_verification_quote(10)
        if first:
            self.setup_namespace = self.removal_open_directory(self.setup_library, "MobileReleaseKitDeveloper", "setup-current-namespace", protected=True)
            self.setup_final = self.removal_open_directory(self.setup_namespace, "Xcode.app", "setup-current-final", protected=True)
            need(stat.S_IMODE(self.setup_final["removal_facts"][0][2]) == 0o555, "setup-verification-final-mode")
        self.setup_verification_fixed_post(self.setup_namespace)
        self.removal_directory_post(self.setup_final)
        need(self.removal_names(self.setup_namespace, maximum=3) == ["Xcode.app", "setup.lock"],
             "setup-verification-current-roster")
        carrier = self.removal_open_directory(self.setup_library, self.stager.XCODE_SETUP_CARRIER, "setup-returned-carrier", protected=True)
        contents = self.removal_open_directory(carrier, "Contents", "setup-returned-contents", protected=True)
        self.setup_verify_returned_dirs = [carrier, contents]
        need(all(stat.S_IMODE(e["removal_facts"][0][2]) == 0o555 for e in (carrier, contents))
             and self.removal_names(carrier, maximum=2) == ["Contents"]
             and self.removal_names(contents, maximum=2) == ["Info.plist"], "setup-verification-carrier-roster")
        info = self.setup_verification_file(contents, "Info.plist", 8192, (0o444,))
        need(info == self.setup_verify_carrier_info, "setup-verification-carrier-content")
        receipt = self.setup_verification_file(self.setup_receipts, self.stager.XCODE_SETUP_ID + ".plist", 16384, (0o644,))
        self.stager.xcode_setup_installed_receipt_data(receipt, self.setup_verify_selection)
        bom = self.setup_verification_file(self.setup_receipts, self.stager.XCODE_SETUP_ID + ".bom", self.stager.XCODE_SETUP_BOM_LIMIT, (0o644,))
        need(digest(bom) == self.setup_verify_bom, "setup-verification-receipt-bom")
        self.setup_verification_post()

    def setup_verification_consume_returned(self):
        # These are originals of FIRST returned carrier/receipt, not immutable
        # inputs for the next PackageKit upgrade. Do not POST stale names later.
        self.setup_verification_post()
        entries = [e for e, _ in self.setup_verify_returned] + list(reversed(self.setup_verify_returned_dirs))
        for entry in entries:
            self.package_clock()
            self.close(entry)
        need(all(e["closed"] for e in entries), "setup-verification-returned-close")
        self.setup_verify_returned.clear()
        self.setup_verify_returned_dirs.clear()

    def setup_verification_post(self):
        self.setup_verification_quote()
        for entry, expected in self.setup_verify_inputs:
            need(digest(self.read(entry)) == expected, "setup-verification-input-changed")
        self.package_post()
        for entry in self.setup_verify_system:
            self.setup_verification_fixed_post(entry)
        if getattr(self, "setup_namespace", None) is not None:
            self.setup_verification_fixed_post(self.setup_namespace)
            self.removal_directory_post(self.setup_final)
            need(self.removal_names(self.setup_namespace, maximum=3) == ["Xcode.app", "setup.lock"],
                 "setup-verification-current-roster")
        for entry in getattr(self, "setup_verify_returned_dirs", ()):
            self.removal_directory_post(entry)
        for entry, expected in self.setup_verify_returned:
            self.setup_verification_fixed_post(entry["parent_entry"])
            need(signature(os.fstat(entry["fd"])) == entry["identity"]
                 == signature(os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False))
                 and digest(os.pread(entry["fd"], entry["identity"][6] + 1, 0)) == expected,
                 "setup-verification-returned-changed")
        self.package_clock()

    def setup_log_diagnostic(self, *, capture):
        need(self.setup_verify and self.package_settled(), "package-io-finality-unknown")
        role = XCODE_SETUP_LOG_CAPTURE if capture else "setup-log-cursor"
        # No new clock. Optional failed-call diagnostics may use only a complete
        # 30-second reservation within the original work endpoint.
        need(package_timeout_data(self.package_clock(), self.package_endpoint, 30) == 30,
             "package-group-settlement-reserve")
        command = "installer-log-capture" if capture else "installer-log-cursor"
        argv = [sys.executable, "-I", "-S", "-B", str(self.checkout / "desktop/tools/stage_macos_installed.py"),
            command, "--xcode-setup", "--target", self.target,
            "--package", str(self.work / "xcode-setup-final/Prepare Xcode.pkg"),
            "--expected-source", self.image_source, "--run-id", self.environment["GITHUB_RUN_ID"],
            "--run-attempt", self.environment["GITHUB_RUN_ATTEMPT"]]
        if capture:
            argv.extend(("--cursor", str(self.work / "xcode-setup-log-cursor.json")))
        result = self.package_call(role, argv, timeout=30, limit=self.stager.LOG_METADATA_BYTES,
            environment={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin", "LANG":"C", "LC_ALL":"C", "TZ":"UTC"})
        # DATA parsing is optional; the original child/capture ledger above is not.
        try:
            document = self.stager.decode(result.stdout)
            need(type(document) is dict and document.get("authority") == self.stager.LOG_AUTHORITY,
                 "installer-diagnostic-original-output")
            if not capture:
                args = argparse.Namespace(xcode_setup=True, fixture=False, target=self.target,
                    package=self.work / "xcode-setup-final/Prepare Xcode.pkg", expected_source=self.image_source,
                    run_id=self.environment["GITHUB_RUN_ID"], run_attempt=self.environment["GITHUB_RUN_ATTEMPT"])
                self.stager.validate_log_cursor(document, self.stager.installer_log_binding(args))
                need(result.returncode == 0, "installer-diagnostic-original-status")
                self.publish("xcode-setup-log-cursor.json", result.stdout)
                self.setup_log_cursor = True
            else:
                observed = document.get("state") == "observed-project-correlated"
                if observed:
                    need(result.returncode == 0 and set(document) == {"schemaVersion", "kind", "state", "authority",
                         "scriptOutputFinality", "intervalScope", "projection"}
                         and type(document["schemaVersion"]) is int and document["schemaVersion"] == 1
                         and document["kind"] == "installer-log-capture" and document["scriptOutputFinality"] == "unestablished"
                         and type(document["projection"]) is dict and set(document["projection"]) == {"hooks", "native", "errors"},
                         "installer-diagnostic-original-output")
                value = {"state": document.get("state"), "reason": None if observed else document.get("reason"),
                    "intervalScope": document.get("intervalScope", "before-first-through-failed-installer"),
                    **(document["projection"] if observed else {"hooks":None, "native":None, "errors":None}), "omitted":False}
                if observed:
                    value["omitted"] = document["projection"]["errors"]["omitted"]
                parsed = setup_log_projection_data(value)
                need(parsed is not None, "installer-diagnostic-original-output")
                self.calls[-1]["setupLog"] = parsed
        except BaseException:
            pass

    def verify_xcode_setup_package(self):
        self.stage = "setup-verification-input"
        self.setup_verification_quote(40)
        # Same finite decoding profile as C2; no Xcode tree loaded into Python.
        self.stager._xcode_setup_allocation(4 * 1024 * 1024)("setup-verification-input",
            3 * self.stager.XCODE_SETUP_PROGRAM_LIMIT, 2 * self.stager.XCODE_SETUP_PACKAGE_LIMIT,
            self.stager.XCODE_SETUP_PACKAGE_LIMIT)
        selected = self.stager.source_build_selection(self.target)
        held = self.stager.build_release_data(self.read(self.release_entry), target=self.target)
        need((selected.package_version, selected.release) == (held["packageVersion"], held["release"]),
             "setup-verification-source-version")
        self.setup_verify_selection = selected
        for name in ("preinstall", "setup/postinstall", "Distribution.xml", "InstallerReadMe.html",
                     "Component.plist", "CarrierInfo.plist"):
            entry = self.setup_source_original(name, "setup-verification-source")
            self.package_sources.append((entry, self.read(entry)))
        entry = self.source_original("desktop/src-tauri/Cargo.toml", "setup-verification-cargo", 128 * 1024)
        self.package_sources.append((entry, self.read(entry)))
        entry = self.source_original("desktop/tools/stage_macos_installed.py", "setup-log-reader-source", 1024 * 1024)
        self.package_sources.append((entry, self.read(entry)))
        def keep(path, maximum, modes=(0o444, 0o600)):
            parent = self.descend(self.work_entry, path.split("/")[:-1])
            item = self.original(parent, path.split("/")[-1], "setup-immutable-input", maximum, modes)
            body = self.read(item)
            self.setup_verify_inputs.append((item, digest(body)))
            return body
        need(keep("xcode-setup-build.status", 4) == b"0\n"
             and keep("xcode-setup-sign.status", 4) == b"0\n"
             and keep("xcode-setup-finalization.status", 4) == b"0\n", "setup-verification-original-status")
        helper_sha = self.environment.get("MRK_MACOS_XCODE_SETUP_SHA256")
        need(tool_hex(helper_sha), "setup-verification-helper-anchor")
        base = "xcode-setup-inputs/"
        for name in ("preinstall", "setup/postinstall", "setup/mrk-macos-xcode-setup"):
            body = keep(base + "scripts-original/" + name, self.stager.XCODE_SETUP_PROGRAM_LIMIT, (0o555,))
            if name.endswith("mrk-macos-xcode-setup"):
                need(digest(body) == helper_sha, "setup-verification-helper-anchor")
            del body
        original_body = keep(base + "packager/PrepareXcode-original.pkg", self.stager.XCODE_SETUP_PACKAGE_LIMIT)
        del original_body
        package = keep("xcode-setup-final/Prepare Xcode.pkg", self.stager.XCODE_SETUP_PACKAGE_LIMIT, (0o444,))
        package_size, package_sha = len(package), digest(package)
        del package
        self.setup_verify_carrier_info = self.stager.xcode_setup_sources(selected)["CarrierInfo.plist"]
        audit_args = argparse.Namespace(target=self.target,
            scripts=self.work / (base + "scripts-original"), original_package=self.work / (base + "packager/PrepareXcode-original.pkg"),
            package=self.work / "xcode-setup-final/Prepare Xcode.pkg", expected_helper=helper_sha)
        audit = self.package_stager_io("setup-final-audit", audit_args)
        need((audit["packageSize"], audit["packageSha256"]) == (package_size, package_sha), "setup-verification-audit-bytes")
        self.setup_verify_bom = audit["bomSha256"]
        self.installer_sources()  # Public SOURCE chain only; no private context.
        profiles = []
        for name in (INSTALLER_PROFILE, NOTARY_PROFILE):
            entry = self.source_original(name, "setup-source-profile", 1024)
            body = self.read(entry)
            self.package_sources.append((entry, body)); profiles.append(body)
        final_body = keep("android-helper-finalize-xcode-setup-package.json", 16384)
        final_package_receipt(final_body, self.environment, self.target, installer_profile(profiles[0]),
            digest(profiles[0]), digest(profiles[1]), package_size, package_sha, self.image_release,
            digest(self.read(self.release_entry)), setup=True,
            setup_originals={key:audit[key] for key in ("helperSha256", "bomSha256", "payloadSha256")})
        del final_body
        self.normal_mount_host()  # Read-only DarwinAPI/ACL source, no host preparation.
        slash = self.removal_open_directory(None, "/", "setup-system-root", protected=True, system_ancestor=True)
        self.setup_library = self.removal_open_directory(slash, "Library", "setup-system-library", protected=True, system_ancestor=True)
        private = self.removal_open_directory(slash, "private", "setup-system-private", protected=True)
        var = self.removal_open_directory(private, "var", "setup-system-var", protected=True)
        db = self.removal_open_directory(var, "db", "setup-system-db", protected=True)
        self.setup_receipts = self.removal_open_directory(db, "receipts", "setup-system-receipts", protected=True)
        self.setup_verify_system = [slash, self.setup_library, private, var, db, self.setup_receipts]
        self.setup_verify_returned_dirs = []
        self.setup_verification_absent()
        path = str(self.work / "xcode-setup-final/Prepare Xcode.pkg")
        for index, (role, maximum) in enumerate(zip(XCODE_SETUP_VERIFY_ROLES, XCODE_SETUP_VERIFY_TIMEOUTS)):
            self.stage = role
            if role == "setup-log-cursor":
                self.setup_log_diagnostic(capture=False)
                continue
            if role == "setup-installer-repeat":
                self.setup_verification_consume_returned()
            signing = role in ("setup-signature-before", "setup-signature-after")
            argv = (["/usr/sbin/pkgutil", "--check-signature", path] if signing else
                    ["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-pkg", path, "-target", "/", "-dumplog", "-verboseR"])
            try:
                result = self.package_call(role, argv, timeout=maximum, limit=256*1024,
                    environment={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin", "LANG":"C", "LC_ALL":"C", "TZ":"UTC"})
            except BaseException:
                if setup_failed_installer_index(self.calls) == len(self.calls) - 1 and self.setup_log_cursor:
                    try:
                        self.setup_log_diagnostic(capture=True)
                    except BaseException:
                        pass  # Preserve the identical original Installer exception.
                raise
            need(result.returncode == 0, "setup-verification-native-nonzero")
            if signing:
                package_signature_data(result.stdout, self.installer_selection, self.installer_certificates,
                                       Path(path), after_staple=True)
            else:
                self.setup_verification_current(role == "setup-installer-first")
            self.setup_verification_post()
        self.receipt["xcodeSetupVerification"] = {"packageSha256": package_sha, "firstInstallerZero":True,
            "samePackageRepeatZero":True, "sameManagedFinalNode":True, "currentCarrierObserved":True,
            "desktopBookQualified":False, "currentToolExecutionQualified":False,
            "oldNativeFinalityRepaired":False, "systemServiceExitClaimed":False}
        self.sha256 = package_sha
        self.setup_verify_complete = True

    def package_install(self):
        self.stage = "package-final-audit"
        if self.app_absence is None:
            self.package_started = self.package_observed = time.monotonic_ns()
            self.package_endpoint = self.package_started + 990_000_000_000
        self.package_clock()
        if self.environment.get("GITHUB_REF") == REMOVAL_REF:
            self.removal_baseline_admit()
        inventory_hash, manifest_hash = (self.environment.get(name) for name in
            ("MRK_MACOS_INSTALL_INVENTORY_SHA256", "MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"))
        need(self.stager.maintenance_hex(inventory_hash, 64) and self.stager.maintenance_hex(manifest_hash, 64), "package-compiled-bindings")
        selection = self.stager.BuildSelection(self.target, self.stager.build_release_data(self.read(self.release_entry), target=self.target)["packageVersion"], self.image_release)
        if self.prepared_binding is not None and not self.prepared_binding.same_source:
            # Same pending/clock boundary also owns import and selection I/O.
            self.package_stager_io("readback-admission", None)
        source = self.stager.packaging_signing_data(self.producer_profile, self.service_profile)
        need(self.signing == (source.team, source.leaf_sha1), "package-source-signing-selection")
        original = self.original(self.directory(self.work_entry, "package-final", "package-final"), "MobileReleaseKit.pkg",
                                 "final-package-original", self.stager.MAX_BYTES, (0o444,))
        body = self.read(original)
        finalization = self.package_finalization_input(original, body)
        audit = self.package_stager_io("final-audit", argparse.Namespace(target=self.target, fixture=False,
            store_runtime=self.selected_package_store(),
            scripts=self.work / "scripts", package=self.work / "package-final/MobileReleaseKit.pkg",
            original_package=self.work / "MobileReleaseKit-original.pkg"))
        need(audit["packageSha256"] == digest(body) and audit["packageSize"] == len(body)
             and self.read(original) == body
             and all(audit[key] == finalization[key] for key in ("originalPackageSha256", "packageInfoSha256", "scriptFileCount")),
             "package-final-audit-original")
        self.package_outputs.append((original, digest(body)))
        self.publish("package-audit.json", self.stager.canonical(audit) + b"\n")
        self.package_clock()
        history_entry = self.source_original("desktop/macos-installed-inputs/producer-history.json", "source-producer-history", self.stager.PRODUCER_DESCRIPTOR_BYTES)
        history = self.read(history_entry)
        self.package_sources.append((history_entry, history))
        for name in ("leaf.der", "issuer.der", "root.der"):
            entry = self.source_original("desktop/packaging/macos-install-producer-certificates/" + name, "source-producer-" + name, 16384)
            self.package_sources.append((entry, self.read(entry)))
        source_inventory = self.original(self.directory(self.work_entry, "input", "package-input"), self.stager.INSTALLATION_INVENTORY_NAME,
            "package-source-inventory", self.stager.INVENTORY_BYTES, (0o444,))
        inventory = self.read(source_inventory)
        self.stager.observation_inventory_bytes(inventory, inventory_hash, manifest_hash, selection=selection)
        self.package_outputs.append((source_inventory, digest(inventory)))
        descriptor = self.stager.packaging_descriptor_data(history, source, selection, source_commit=self.image_source,
            manifest=manifest_hash, inventory=inventory_hash, package=digest(body))
        root = self.package_directory("producer-root")
        self.package_file(root, "Install.pkg", body)
        self.package_file(self.work_entry, "producer-descriptor-input.json", descriptor)
        self.package_post()
        self.stage = "package-explicit-producer-compiler"
        environment = build_environment(self.environment, self.work, self.image_release, target=self.target)
        environment.update(CARGO_TARGET_DIR=str(self.work / self.target_name), TMPDIR=str(self.work / self.target_name / "tmp"),
            MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=manifest_hash, MRK_MACOS_INSTALL_INVENTORY_SHA256=inventory_hash)
        if self.prepared_binding is not None:
            # Compile only the existing producer from its actual built SOURCE;
            # the real consumer GITHUB_* identity is never relabeled.
            environment["MRK_MACOS_INSTALL_SOURCE_COMMIT"] = self.prepared_binding.source
        binary = self.package_producer_compile(environment)
        binary_dir = self.descend(self.target_entry, (self.target, "release", "examples"))
        executable = self.original(binary_dir, binary.name, "producer-compiled-example", 64 * 1024 * 1024, (0o700, 0o755), alias=True)
        executable_body = self.read(executable)
        self.stager.macho(executable_body, system_only=True, target=self.target)
        # Cargo may retain an alias. Execute only a fresh single-link copy, not
        # either compiler-owned name; keep the original through copy POST.
        producer = self.producer_signing_copy(executable, executable_body)
        with self.credential_scope("producer", producer=producer):
            self.stage = "package-producer-emission"
            need(package_timeout_data(self.package_clock(), self.package_endpoint, 123) == 123, "producer-original-clock-reserve")
            emitted = self.package_call("producer-emitter", [str(self.work / "macos-package-producer"), "--package-root", str(self.work / "producer-root"),
                "--descriptor-input", str(self.work / "producer-descriptor-input.json")], timeout=123, limit=4096)
            signed_entry = self.original(root, "producer.sig", "producer-original-signature", self.stager.PRODUCER_SIGNATURE_BYTES, (0o444,))
            descriptor_entry = self.original(root, "producer.json", "producer-original-descriptor", self.stager.PRODUCER_DESCRIPTOR_BYTES, (0o444,))
            signed, actual_descriptor = self.read(signed_entry), self.read(descriptor_entry)
            need(actual_descriptor == descriptor, "producer-exact-descriptor-emission")
            summary = self.stager.emitted_package_data(emitted.stdout, emitted.stderr, emitted.returncode, body, actual_descriptor, signed, target=self.target)
            self.package_outputs.extend(((signed_entry, digest(signed)), (descriptor_entry, digest(descriptor))))
        if self.app_absence is not None:
            self.app_absence_module.image_prepare(self, root)
        expected = {"Install.pkg": body, "producer.json": descriptor, "producer.sig": signed}
        self.stager.distribution_layout_data(os.listdir(root["fd"]), "Install.pkg", expected,
            {name: (value, 0o444) for name, value in expected.items()})
        self.package_roots.append((root, set(expected)))
        request_id = os.urandom(16).hex()  # One new independent correlation ID, no fallback/retry.
        self.package_name = self.stager.distribution_request_name(request_id)
        self.publish("package-request-id.txt", (request_id + "\n").encode("ascii"))
        observed_root = self.package_directory("producer-observation-root")
        for name, value in expected.items():
            self.package_file(observed_root, self.package_name if name == "Install.pkg" else name, value)
        self.package_roots.append((observed_root, {self.package_name, "producer.json", "producer.sig"}))
        self.distribution_entry = self.package_directory("distribution")
        self.package_post()
        user_image, _user_path = self.package_image(root, "distribution")
        observation_image, observation_path = self.package_image(observed_root, "observation")
        if self.removal_baseline_mount is not None:
            mount_path = self.removal_baseline_attach(observation_path)
        else:
            self.stage = "package-readonly-attach"
            self.normal_mount_host()
            mount_path = self.transport_mount_admit()
            attached = self.package_call("distribution-attach", ["/usr/bin/hdiutil", "attach", str(observation_path), "-readonly", "-nobrowse",
                "-noautoopen", "-mountpoint", str(mount_path), "-plist"], timeout=60)
            self.mount_custody(attached, "package-readonly-mount")
        self.mount_inputs(expected, self.package_name)
        args = argparse.Namespace(target=self.target, fixture=False, input=self.work / "input", expected_source=self.image_source,
            expected_inventory=inventory_hash, expected_manifest=manifest_hash, request_id=request_id, expected_package=digest(body),
            producer_descriptor=mount_path / "producer.json", producer_signature=mount_path / "producer.sig",
            installer_status=self.work / "installer-output.status", package=mount_path / self.package_name,
            run_id=self.environment["GITHUB_RUN_ID"], run_attempt=self.environment["GITHUB_RUN_ATTEMPT"])
        self.package_stager_io("result-absence", args)
        if self.update is not None:
            self.update_module.before_current(self, actual_descriptor)
        self.package_diagnostic(args, capture=False)
        self.package_post()
        self.mounted_post()
        if self.app_absence is not None:
            self.app_absence_module.baseline(self)
        self.stage = "standard-original-installer"
        # Require the unchanged inner120s plus this owner's existing3s reserve;
        # neither starts a renewed package-group deadline.
        need(package_timeout_data(self.package_clock(), self.package_endpoint, 123) == 123, "installer-original-clock-reserve")
        try:
            result = self.package_call("installer", ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer", "-pkg", str(args.package),
                "-target", "/", "-dumplog", "-verboseR"], timeout=123, limit=256 * 1024)
            self.installer_zero = result.returncode == 0
        except BaseException:
            # Diagnostics never replace original status or a failing call, and
            # cannot run across an unknown original process boundary.
            if self.calls and self.calls[-1]["role"] == "installer" and self.package_settled():
                try:
                    self.package_diagnostic(args, capture=True)
                except BaseException as diagnostic:
                    self.errors.append({"stage": "installer-diagnostic", "type": type(diagnostic).__name__})
            raise
        self.package_diagnostic(args, capture=True)
        self.package_post()
        self.mounted_post()
        self.stage = "package-nonroot-v2-readback"
        observed = (self.update_module.current_readback(self, args) if self.update is not None
                    else self.package_stager_io("v2-readback", args))
        if self.app_absence is not None:
            self.app_absence_module.initial_readback(self, observed)
        self.package_clock()
        self.publish("installation-observation.json", self.stager.canonical(observed) + b"\n")
        self.installation_readback = True
        self.package_clock()
        self.package_post()
        self.mounted_post()
        self.detach_package_mount()
        self.package_post()
        if self.app_absence is not None:
            self.app_absence_module.package_complete(self)
        if self.update is not None:
            self.update_module.current_complete(self)
        self.receipt["distribution"] = {"schemaVersion": 1, "kind": "mrk-ordinary-package-observed-v2", "target": self.target,
            "packageVersion": selection.package_version, "release": selection.release, "requestId": request_id,
            "packageSha256": digest(body), "packageBytes": len(body), "descriptorSha256": digest(descriptor), "signatureSha256": digest(signed),
            "producerSummary": summary, "userImage": user_image, "observationImage": observation_image,
            "sourceProducerProfileSha256": source.producer_sha256, "sourceServiceProfileSha256": source.service_sha256,
            "originalInstallerReturnedZero": self.installer_zero, "sameRequestV2Readback": self.installation_readback,
            "originalMountDetached": self.mount_detached, "mountIdentity": list(self.mount_entry["identity"]),
            "groupEndpointMet": True, "originalOuterReturnRequired": True,
            "developerIdPurposeAuthority": "native-parent-and-application-checks-separate",
            "notarizationQualified": False, "gatekeeperQualified": False, "systemServiceExitClaimed": False, "productReady": False}
        self.sha256 = user_image["sha256"]
        self.package_clock()

    def candidate_removal_quote(self):
        if self.candidate_removal_context is not None:
            need(len(self.entries) <= 24576 and sum(e["fd"] is not None or not e["closed"] for e in self.entries) + 40 <= 256,
                 "candidate-removal-original-quote")

    def candidate_removal_binding(self):
        value = self.candidate_removal_context
        need(type(value) is dict and self.removal, "candidate-removal-binding")
        return dict(source=value["helperSource"], productSource=value["productSource"], tree=value["tree"],
            runId=value["runId"], runAttempt=value["runAttempt"], runtimeManifestSha256=value["runtimeManifestSha256"],
            artifactId=value["artifactId"], artifactSha256=value["artifactSha256"])

    def candidate_removal_post(self):
        if getattr(self, "candidate_removal_root", None) is None:
            return
        self.recheck_directory(self.candidate_removal_root)
        need(set(os.listdir(self.candidate_removal_root["fd"])) == {
            "Install.pkg", "producer.json", "producer.sig", "install-inventory.json", "mrk-macos-remove"}, "candidate-removal-donor-roster")
        for entry, sha in self.candidate_removal_inputs:
            need(digest(self.read(entry)) == sha, "candidate-removal-donor-post")

    def package_remove(self):
        need(self.phase == "package-remove" and self.removal and self.signing is not None,
             "remove-package-configured-purpose")
        self.stage = "remove-package-final-inputs"
        if self.candidate_removal_context is None:
            self.package_started = self.package_observed = time.monotonic_ns()
            self.package_endpoint = self.package_started + 990_000_000_000
        self.package_clock()
        manifest_hash = self.environment.get("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256")
        inventory_hash = self.environment.get("MRK_MACOS_INSTALL_INVENTORY_SHA256")
        expected_remover = self.environment.get("MRK_MACOS_REMOVER_SHA256")
        need(all(self.stager.maintenance_hex(value, 64) for value in (manifest_hash, inventory_hash, expected_remover)),
             "remove-package-source-bindings")
        selection = self.stager.BuildSelection(self.target,
            self.stager.build_release_data(self.read(self.release_entry), target=self.target)["packageVersion"], self.image_release)
        source = self.stager.packaging_signing_data(self.producer_profile, self.service_profile)
        need(self.signing == (source.team, source.leaf_sha1), "remove-package-source-signing")
        final_root = self.directory(self.work_entry, self.final_package_name, "remove-final-package")
        need(os.listdir(final_root["fd"]) == [self.package_filename], "remove-final-package-roster")
        self.package_roots.append((final_root, {self.package_filename}))
        original = self.original(final_root, self.package_filename, "remove-final-package-original", self.stager.MAX_BYTES, (0o444,))
        package = self.read(original)
        self.package_finalization_input(original, package)
        package_hash, package_bytes = digest(package), len(package)
        self.package_outputs.append((original, package_hash))
        candidate = self.candidate_removal_context is not None
        installed_name = "resume-carrier" if candidate else "producer-root"
        installed_root = self.directory(self.work_entry, installed_name, "remove-installed-producer")
        donor_names = ({"Install.pkg", "producer.json", "producer.sig", "install-inventory.json", "mrk-macos-remove"} if candidate else {"Install.pkg", "producer.json", "producer.sig"})
        need(set(os.listdir(installed_root["fd"])) == donor_names,
             "remove-installed-producer-roster")
        self.package_roots.append((installed_root, donor_names))
        installed_entry = self.original(installed_root, "producer.json", "remove-installed-descriptor", self.stager.PRODUCER_DESCRIPTOR_BYTES, (0o444,))
        signature_entry = self.original(installed_root, "producer.sig", "remove-installed-signature", self.stager.PRODUCER_SIGNATURE_BYTES, (0o444,))
        installed, signature = self.read(installed_entry), self.read(signature_entry)
        self.package_outputs.extend(((installed_entry, digest(installed)), (signature_entry, digest(signature))))
        input_root = installed_root if candidate else self.directory(self.work_entry, "input", "remove-installed-input")
        inventory_entry = self.original(input_root, self.stager.INSTALLATION_INVENTORY_NAME, "remove-installed-inventory", self.stager.INVENTORY_BYTES, (0o444,))
        inventory = self.read(inventory_entry)
        remover_path = self.work / "resume-carrier" / self.stager.REMOVER_NAME if candidate else self.work / "input/app" / self.stager.REMOVER
        parts = [self.stager.REMOVER_NAME] if candidate else ("app/" + self.stager.REMOVER).split("/")
        remover_root = self.descend(input_root, tuple(parts[:-1]))
        remover_entry = self.original(remover_root, parts[-1], "remove-signed-installed-program", self.stager.REMOVER_BYTES, (0o555,))
        program = self.read(remover_entry)
        need(digest(program) == expected_remover and digest(inventory) == inventory_hash, "remove-original-source-digests")
        self.package_outputs.extend(((inventory_entry, digest(inventory)), (remover_entry, digest(program))))
        descriptor = self.stager.packaging_removal_descriptor_data(installed, inventory, program, package, source, selection,
            source_commit=self.image_source, manifest=manifest_hash)
        self.package_post()
        self.stage = "remove-package-five-input-preparation"
        prepared = self.package_stager_io("remove-input", argparse.Namespace(target=self.target,
            installed_producer=self.work / installed_name / "producer.json", installed_signature=self.work / installed_name / "producer.sig",
            inventory=self.work / ("resume-carrier" if candidate else "input") / self.stager.INSTALLATION_INVENTORY_NAME, remover=remover_path,
            package=self.work / self.final_package_name / self.package_filename, output=self.work / "remove-emitter-input",
            expected_source=self.image_source, expected_manifest=manifest_hash))
        need(type(prepared) is dict and prepared == {"schemaVersion": 1, "kind": "remove-emitter-input-data", "target": self.target,
             "descriptorSha256": digest(descriptor), "installedProducerSha256": digest(installed), "inventorySha256": digest(inventory),
             "removerSha256": digest(program), "packageSha256": digest(package), "inputFiles": 5,
             "qualification": "remove-input-data-not-signature-or-removal-authority"}, "remove-input-original-result")
        input_copy = self.directory(self.work_entry, "remove-emitter-input", "remove-emitter-input")
        input_values = {"remove-descriptor-input.json": descriptor, "producer.json": installed, "producer.sig": signature,
                        "install-inventory.json": inventory, self.stager.REMOVER_NAME: program}
        need(set(os.listdir(input_copy["fd"])) == set(input_values), "remove-emitter-five-inputs")
        self.package_roots.append((input_copy, set(input_values)))
        for name, value in input_values.items():
            limit = self.stager.REMOVER_BYTES if name == self.stager.REMOVER_NAME else (self.stager.INVENTORY_BYTES if name == "install-inventory.json" else self.stager.PRODUCER_DESCRIPTOR_BYTES)
            entry = self.original(input_copy, name, "remove-emitter-input-" + name, limit,
                                  (0o555,) if name == self.stager.REMOVER_NAME else (0o444,))
            need(self.read(entry) == value, "remove-input-exact-original-copy")
            self.package_outputs.append((entry, digest(value)))
        # Original FDs/digests stay in package_outputs; every package_post still
        # rehashes them. The copied input bodies are no longer needed here.
        del input_values, value, program, inventory
        root = self.package_directory("remove-producer-root")
        self.package_file(root, "Remove.pkg", package)
        self.package_post()
        self.stage = "remove-explicit-producer-compiler"
        environment = build_environment(self.environment, self.work, self.image_release, target=self.target)
        environment.update(CARGO_TARGET_DIR=str(self.work / self.target_name), TMPDIR=str(self.work / self.target_name / "tmp"),
                           MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=manifest_hash)
        if candidate:
            # H's nonshipping emitter still authenticates the unchanged P product.
            environment["MRK_MACOS_INSTALL_SOURCE_COMMIT"] = self.image_source
        compiler_root = self.checkout / ".candidate-consumer-helper" if candidate else self.checkout
        compiled = self.package_call("producer-build", [direct_rust_tools(self.target)[0], "build", "--manifest-path", str(compiler_root / "desktop/src-tauri/Cargo.toml"),
            "--locked", "--offline", "--release", "--config", PRODUCER_CARGO_OVERRIDE,
            *(["--config", "profile.release.opt-level=0"] if candidate else []), "--jobs", "1", "--target", self.target, "--no-default-features",
            "--features", "macos-remove-producer", "--example", "macos_remove_producer", "--message-format=json-render-diagnostics"],
            environment=environment, cwd=compiler_root / "desktop/src-tauri", timeout=480, limit=4 * 1024 * 1024)
        binary = producer_artifact(compiled.stdout, compiler_root, self.work / self.target_name, self.target,
            package_version=self.image_package_version, remove=True, candidate_removal=candidate)
        binary_dir = self.descend(self.target_entry, (self.target, "release", "examples"))
        executable = self.original(binary_dir, binary.name, "remove-producer-compiled-example", 64 * 1024 * 1024, (0o700, 0o755), alias=True)
        executable_body = self.read(executable)
        self.stager.macho(executable_body, system_only=True, target=self.target)
        producer = self.producer_signing_copy(executable, executable_body)
        del executable_body, compiled
        with self.credential_scope("producer", producer=producer):
            self.stage = "remove-producer-emission"
            need(package_timeout_data(self.package_clock(), self.package_endpoint, 123) == 123, "remove-producer-original-clock-reserve")
            emitted = self.package_call("producer-emitter", [str(self.work / self.producer_filename), "--package-root", str(self.work / "remove-producer-root"),
                "--input-root", str(self.work / "remove-emitter-input")], timeout=123, limit=4096)
            descriptor_entry = self.original(root, "remove-producer.json", "remove-original-descriptor", self.stager.REMOVE_DESCRIPTOR_BYTES, (0o444,))
            signed_entry = self.original(root, "remove-producer.sig", "remove-original-signature", self.stager.PRODUCER_SIGNATURE_BYTES, (0o444,))
            actual_descriptor, signed = self.read(descriptor_entry), self.read(signed_entry)
            summary = self.stager.emitted_removal_data(emitted.stdout, emitted.stderr, emitted.returncode,
                package, actual_descriptor, signed, descriptor)
            self.package_outputs.extend(((descriptor_entry, digest(actual_descriptor)), (signed_entry, digest(signed))))
        expected = {"Remove.pkg": package, "remove-producer.json": descriptor, "remove-producer.sig": signed}
        self.stager.removal_distribution_layout_data(os.listdir(root["fd"]), expected,
            {name: (value, 0o444) for name, value in expected.items()})
        self.package_roots.append((root, set(expected)))
        # Credential checks have consumed the signed producer body. Keep only
        # scalar receipt facts before reading/signing the distribution image.
        del producer, expected, package
        self.distribution_entry = self.package_directory(self.image_directory)
        self.package_post()
        image, _path = self.package_image(root, "distribution")
        self.package_post()
        need(not self.installer_entered and not self.mount_entered, "remove-no-installed-operation")
        self.receipt["removalDistribution"] = {"schemaVersion": 1, "kind": "mrk-remove-package-emitted-image-v1", "target": self.target,
            "packageVersion": selection.package_version, "release": selection.release, "packageSha256": package_hash, "packageBytes": package_bytes,
            "descriptorSha256": digest(descriptor), "signatureSha256": digest(signed), "producerSummary": summary, "userImage": image,
            "installedProducerSha256": digest(installed), "inventorySha256": inventory_hash, "removerExecutableSha256": expected_remover,
            "sourceProducerProfileSha256": source.producer_sha256, "sourceServiceProfileSha256": source.service_sha256,
            "finalPackageReceiptSha256": self.receipt["finalPackageReceiptSha256"], "groupEndpointMet": True, "originalOuterReturnRequired": True,
            "installerEntered": False, "applicationLaunched": False, "removalExecuted": False, "productReady": False}
        self.sha256 = image["sha256"]
        self.removal_package_complete = True
        self.package_clock()

    def capture_notary_failure(self, body):
        # Called only after the existing log binding/acceptance parser returned
        # for an Invalid submission. Never replace the original refusal.
        try:
            rows = notary_issue_summary(notary_json(body, 1024 * 1024).get("issues"))
            self.notary_issue_diagnostic = {"rows": rows[:8], "rowsOmitted": len(rows) > 8}
        except BaseException:
            pass

    def package_diagnostic_program(self):
        # Product readers/compiler remain rooted in the built source. Only the
        # nonroot diagnostics and explicit cross-source readback use the current harness.
        if self.prepared_binding is None:
            return self.checkout / "desktop/tools/stage_macos_installed.py"
        need(self.phase == "package-install", "installer-diagnostic-source-purpose")
        self.prepared_binding.finalization_environment(self.environment)
        if self.diagnostic_program is None:
            fd = os.open(CHECKOUT, READ_FLAGS | os.O_DIRECTORY)
            root = self.diagnostic_source_entry = self.register(fd, "diagnostic-source-root", "directory")
            root["identity"] = directory_identity(os.fstat(fd))
            self.recheck_directory(root)
            head = self.original(self.descend(root, (".git",)), "HEAD", "diagnostic-source-head", 64, (0o444, 0o644))
            body = self.read(head)
            need(body == (self.environment["GITHUB_SHA"] + "\n").encode("ascii"), "installer-diagnostic-source-head")
            self.package_sources.append((head, body))
            entry = self.original(self.descend(root, ("desktop", "tools")), "stage_macos_installed.py",
                "diagnostic-source-program", 1024 * 1024, (0o444, 0o644))
            self.package_sources.append((entry, self.read(entry)))
            self.diagnostic_program_entry = entry
            self.diagnostic_program = CHECKOUT / "desktop/tools/stage_macos_installed.py"
        self.package_post()  # Same retained originals, including on the second call.
        return self.diagnostic_program

    def package_readback_module(self, args=None):
        # Only a genuine manual retry may use newer observer code. Every build,
        # package audit, producer/signature input and absence check remains built-source.
        binding = self.prepared_binding
        if binding is None or binding.same_source:
            return self.stager
        need(self.phase == "package-install" and self.environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
             and self.environment.get("GITHUB_REF") == CANDIDATE_REF
             and self.app_absence is None and self.update is None, "prepared-readback-purpose")
        binding.finalization_environment(self.environment)
        manifest = binding.manifest
        expected = (self.target, manifest["packageVersion"], manifest["release"])
        built = self.stager.source_build_selection(self.target)
        need((built.target, built.package_version, built.release) == expected
             and binding.origin["target"] == self.target and self.image_source == binding.source
             and self.image_release == manifest["release"], "prepared-readback-built-selection")
        if args is not None:
            need(self.installer_zero is True, "prepared-readback-installer-not-zero")
            package = next(row for row in manifest["members"] if row["name"] == "MobileReleaseKit.pkg")
            need((args.target, args.expected_source, args.expected_inventory, args.expected_manifest, args.expected_package)
                 == (self.target, binding.source, manifest["inventorySha256"], manifest["runtimeManifestSha256"], package["sha256"]),
                 "prepared-readback-original-bindings")
        if self.current_readback_module is None:
            path = self.package_diagnostic_program()
            parent = self.descend(self.diagnostic_source_entry, ("desktop", "macos-installed-inputs"))
            # Module import always reads ARM; an Intel observation also reads its
            # fixed Intel selection. Retain BOTH where needed, not only the target.
            names = ("build-release.json",) + (("build-release-intel.json",) if self.target == INTEL_TARGET else ())
            for name in names:
                entry = self.original(parent, name, "readback-source-" + name, self.stager.BUILD_RELEASE_LIMIT, (0o444, 0o644))
                self.package_sources.append((entry, self.read(entry)))
            body = self.read(self.diagnostic_program_entry)
            spec = importlib.util.spec_from_file_location("mrk_prepared_current_readback", path)
            module = importlib.util.module_from_spec(spec)
            self.stager_failure_module = module
            exec(compile(body, str(path), "exec"), module.__dict__)
            self.package_post()
            self.current_readback_module = module
        module = self.current_readback_module
        self.stager_failure_module = module
        current = module.source_build_selection(self.target)
        # Different modules have different namedtuple classes: compare exact fields.
        need((current.target, current.package_version, current.release) == expected
             and module.CURRENT_PROTOCOL == self.stager.CURRENT_PROTOCOL, "prepared-readback-current-selection")
        self.package_post()
        self.stager_failure_module = self.stager
        return module

    def package_log_markers(self, document):
        # The current log reader's selected snapshot is diagnostic DATA only.
        # Never read an arbitrary document path or replace Installer's own slot.
        need(type(document) is dict and document.get("state") == "observed-project-correlated"
             and document.get("authority") == self.stager.LOG_AUTHORITY, "installer-diagnostic-selected")
        row = document.get("selectedData")
        need(type(row) is dict and set(row) == {"file", "bytes", "sha256"}
             and row["file"] == "installer-log-selected.txt" and type(row["bytes"]) is int
             and 0 < row["bytes"] <= self.stager.LOG_SELECTED_BYTES
             and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]),
             "installer-diagnostic-selected")
        entry = self.original(self.work_entry, "installer-log-selected.txt", "diagnostic-selected-log",
            self.stager.LOG_SELECTED_BYTES, (0o600,))
        try:
            body = self.read(entry)
            need((len(body), digest(body)) == (row["bytes"], row["sha256"])
                 and self.read(entry) == body, "installer-diagnostic-selected")
            result = {"markers": installer_markers(body, b""), "errors": installer_errors(body, b"")}
        finally:
            self.close(entry)
        need(entry["closed"] and entry["fd"] is None, "installer-diagnostic-selected-close")
        return result

    def package_diagnostic(self, args, *, capture):
        need(self.package_settled(), "package-io-finality-unknown")
        self.package_clock()
        command = "installer-log-capture" if capture else "installer-log-cursor"
        program = self.package_diagnostic_program()
        argv = [sys.executable, "-I", "-S", "-B", str(program), command,
            "--target", self.target, "--package", str(args.package), "--request-id", args.request_id,
            "--expected-source", args.expected_source, "--expected-inventory", args.expected_inventory,
            "--expected-manifest", args.expected_manifest, "--run-id", args.run_id, "--run-attempt", args.run_attempt]
        if capture:
            argv.extend(("--cursor", str(self.work / "installer-log-cursor.json"), "--selected-output", str(self.work / "installer-log-selected.txt")))
        # This is the existing nonroot log action, run by the SAME original
        # process owner. Its joined0/1 result cannot substitute for Installer0;
        # a child's uncertain file close cannot be disguised as our own close.
        result = self.package_call(command, argv, timeout=30, limit=self.stager.LOG_METADATA_BYTES)
        if self.prepared_binding is not None:
            self.package_post()
        need(result.returncode in (0, 1), "installer-diagnostic-original-status")
        document = self.stager.decode(result.stdout)
        need(type(document) is dict and document.get("authority") == self.stager.LOG_AUTHORITY,
             "installer-diagnostic-original-output")
        self.publish(command + ".json", result.stdout)
        self.publish(command + ".status", (str(result.returncode) + "\n").encode("ascii"))
        try:
            # These already-owned captures passed the authority check above.
            # Retain no log paths, requests, selected bytes, offsets or hashes.
            observed = installer_log_diagnostic_data({"state": document.get("state"),
                "reason": document.get("reason"), "selection": document.get("selectedOutputState")})
            if self.calls and self.calls[-1].get("role") == command:
                self.calls[-1]["installerLog"] = observed
            if (capture and result.returncode == 0 and len(self.calls) == 15
                    and self.calls[-1]["role"] == "installer-log-capture"
                    and self.calls[13].get("role") == "installer"
                    and self.calls[13].get("returned") is True and self.calls[13].get("capturesSettled") is True
                    and type(self.calls[13].get("returncode")) is int and self.calls[13]["returncode"] != 0):
                selected = self.package_log_markers(document)
                self.calls[-1]["installerLogMarkers"] = selected["markers"]
                self.calls[-1]["installerLogErrors"] = selected["errors"]
        except BaseException:
            pass
        self.package_clock()

    def finish(self):
        if self.setup_verify:
            try:
                self.setup_verification_cleanup_clock()
            except BaseException as error:
                self.errors.append({"stage": "setup-verification-cleanup", "type": type(error).__name__})
        if self.store_signing is not None:
            try:
                self.store_signing_module.retire(self)
            except BaseException as error:
                self.errors.append({"stage": "store-retirement", "type": type(error).__name__})
        if self.android_support is not None:
            try:
                self.android_support_module.retire(self)
            except BaseException as error:
                self.errors.append({"stage": "support-retirement", "type": type(error).__name__})
        if self.phase in TOOL_SIGNING_PHASES and self.tool_started is not None:
            try:
                self.tool_clock(work=False)
            except BaseException as error:
                self.errors.append({"stage": "tool-retirement-clock", "type": type(error).__name__})
        if (not self.removal_cleanup_ready()
                or self.store_signing is not None and not self.store_signing_module.finish_ready(self)
                or self.android_support is not None and not self.android_support_module.finish_ready(self)
                or self.app_absence is not None and not self.app_absence_module.finish_ready(self)
                or self.update is not None and not self.update_module.finish_ready(self)):
            # SAME unresolved originals/mounts/thread remain retained. A
            # generic finally/known output close cannot grant fixture custody.
            self.receipt.update(originalClosesKnown=False, targetRetired=False,
                                directStagerIOPending=self.stager_io_pending, cleanupErrors=self.errors)
            return
        if self.phase in PYTHON_PHASES:
            self.python_retirement()
        if self.phase in NOTARY_PHASES + FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES:
            self.notary_retirement()
        # Close every artifact/output/descendant first. Raised or malformed
        # original calls and any unknown close prevent target deletion.
        for entry in self.entries:
            if entry is not self.work_entry and entry is not self.target_entry:
                self.close(entry)
        ordinary_closes = all(entry["closed"] for entry in self.entries
                              if entry is not self.work_entry and entry is not self.target_entry)
        mount_safe = not self.mount_entered or self.mount_detached
        if (self.target_entry and mount_safe and self.credential_known() and self.credential_active is None
                and not self.signing_mutation_pending and self.stager_io_pending is None and not self.python_mutation_pending
                and ordinary_closes and not self.errors
                and (self.phase not in NOTARY_PHASES + FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES or self.notary_retiring and self.notary_known() and self.notary_key is None)
                and all(call["returned"] and call.get("capturesSettled") is True for call in self.calls)):
            try:
                work_fd, target_fd = self.work_entry["fd"], self.target_entry["fd"]
                need(directory_identity(os.fstat(work_fd)) == directory_identity(self.work.lstat()) == self.work_entry["identity"]
                     and directory_identity(os.fstat(target_fd)) == self.target_entry["identity"]
                     and directory_identity(os.stat(self.target_name, dir_fd=work_fd, follow_symlinks=False)) == self.target_entry["identity"],
                     "cleanup-original-directory-changed")
                if self.phase in ("package-install", "package-remove", "package-removal-fixture") and self.package_endpoint is not None:
                    self.package_clock()
                if self.phase in PYTHON_PHASES:
                    need(self.python_retiring, "python-retirement-not-admitted")
                    self.python_clock(work=False)
                if self.phase in NOTARY_PHASES + FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES or self.phase in ("prepare-removal-observers", SAME_PACKAGE_PHASE):
                    self.notary_clock(work=False)
                if self.phase in TOOL_SIGNING_PHASES:
                    self.tool_clock(work=False)
                if self.setup_verify:
                    self.setup_verification_cleanup_clock()
                shutil.rmtree(self.target_name, dir_fd=work_fd)
                if self.setup_verify:
                    self.setup_verification_cleanup_clock()
                if self.phase in TOOL_SIGNING_PHASES:
                    self.tool_clock(work=False)
                if self.phase in NOTARY_PHASES + FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES or self.phase in ("prepare-removal-observers", SAME_PACKAGE_PHASE):
                    self.notary_clock(work=False)
                if self.phase in PYTHON_PHASES:
                    self.python_clock(work=False)
                if self.phase in ("package-install", "package-remove", "package-removal-fixture") and self.package_endpoint is not None:
                    self.package_clock()
                try:
                    os.stat(self.target_name, dir_fd=work_fd, follow_symlinks=False)
                except FileNotFoundError:
                    self.receipt["targetRetired"] = True
                else:
                    raise Refused("cleanup-target-remains")
            except BaseException as error:
                self.errors.append({"stage": "target-retirement", "type": type(error).__name__})
        for entry in (self.target_entry, self.work_entry):
            if entry:
                self.close(entry)
        if self.phase in ("package-install", SAME_PACKAGE_PHASE):
            self.receipt["packageMount"] = {"attachEntered": self.mount_entered, "originalKnown": self.mount_known,
                "detached": self.mount_detached, "retained": self.mount_entered and not self.mount_detached,
                "installerEntered": self.installer_entered, "installerOriginalZero": self.installer_zero,
                "sameRequestV2Readback": self.installation_readback, "systemServiceExitClaimed": False}
        if self.phase in FINAL_IMAGE_PHASES:
            self.receipt["finalImageMount"] = {"attachEntered": self.mount_entered, "originalKnown": self.mount_known,
                "detached": self.mount_detached, "retained": self.mount_entered and not self.mount_detached,
                "installerEntered": self.installer_entered, "systemServiceExitClaimed": False}
        if self.phase in TOOL_SIGNING_PHASES and self.tool_started is not None:
            try:
                self.tool_clock(work=False)
            except BaseException as error:
                self.errors.append({"stage": "tool-post-close-clock", "type": type(error).__name__})
        self.receipt["directStagerIOPending"] = self.stager_io_pending
        if self.phase in PYTHON_PHASES and self.python_started is not None:
            try:
                self.python_clock(work=False)
            except BaseException as error:
                self.errors.append({"stage": "python-post-close-deadline", "type": type(error).__name__})
        self.receipt["originalClosesKnown"] = (self.credential_known() and self.credential_active is None and not self.signing_mutation_pending
                                               and self.stager_io_pending is None and not self.python_mutation_pending
                                               and (self.phase not in NOTARY_PHASES + FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES or not self.notary_unknown
                                                    and not self.notary_mutation_pending and self.notary_key is None)
                                               and all(entry["closed"] for entry in self.entries))
        if self.app_absence is not None:
            try:
                self.app_absence_module.clock(self, work=False)
            except BaseException as error:
                self.errors.append({"stage": "app-absence-post-close-clock", "type": type(error).__name__})
        if self.setup_verify:
            try:
                self.setup_verification_cleanup_clock()
            except BaseException as error:
                self.errors.append({"stage": "setup-verification-cleanup", "type": type(error).__name__})
        self.receipt["cleanupErrors"] = self.errors

    def execute(self, expected=None):
        try:
            if self.setup_verify:
                self.package_started = self.package_observed = time.monotonic_ns()
                self.package_endpoint = self.package_started + 4920_000_000_000
                self.setup_verify_hard = self.package_started + 4980_000_000_000
                self.receipt.update(toolchain=None, helperIdentifier=None)
            if self.phase in TOOL_SIGNING_PHASES:
                self.tool_started = self.tool_observed = time.monotonic_ns()
                self.tool_clock()
                self.receipt.update(toolchain=None, helperIdentifier=None)
            if self.phase in NOTARY_PHASES + FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES or self.phase in ("prepare-removal-observers", SAME_PACKAGE_PHASE):
                self.notary_started = self.notary_observed = time.monotonic_ns()
                self.notary_clock()
            if self.phase in PYTHON_PHASES:
                self.python_started = self.python_observed = time.monotonic_ns()
                self.python_clock()
                self.receipt.update(toolchain=None, helperIdentifier=None, pythonIdentifier=PYTHON_IDENTIFIER)
            self.open()
            if self.candidate_removal_context is not None:
                self.candidate_removal_load()
            if self.prepared_binding is not None:
                # Acquired INSIDE this execute try/finally, including malformed
                # or changed HEAD. Main never leaves a preexecute original open.
                head = self.source_original(".git/HEAD", "prepared-built-source-head", 64)
                body = self.read(head)
                need(body == (self.prepared_binding.source + "\n").encode("ascii"), "prepared-built-source-head")
                self.package_sources.append((head, body))
            if self.phase in STORE_SIGNING_PHASES:
                self.store_signing_load()
            if self.phase in SUPPORT_PHASES:
                self.android_support_load()
            if self.environment.get("GITHUB_REF") == UPDATE_REF and self.phase in (UPDATE_PHASE, "package-install"):
                self.update_load()
            if self.phase in APP_ABSENCE_PHASES or self.phase == "package-install" and self.environment.get("GITHUB_REF") in (APP_ABSENCE_REF, RESTORE_CHAIN_REF):
                self.app_absence_load()
            self.profile_entry = self.source_original(PROFILE, "source-signing-profile", 1024)
            self.service_profile = self.read(self.profile_entry)
            self.signing = self.stager.service_signing_data(self.service_profile)
            self.producer_profile_entry = self.source_original(PRODUCER_PROFILE, "source-producer-profile", 1024)
            self.producer_profile = self.read(self.producer_profile_entry)
            selection = self.stager.packaging_signing_data(self.producer_profile, self.service_profile,
                allow_unconfigured=self.phase not in ("package-install", "package-remove", "python-shipping", SAME_PACKAGE_PHASE) + SUPPORT_PHASES + STORE_SIGNING_PHASES + SIGNING_PHASES + TOOL_SIGNING_PHASES + NOTARY_PHASES + FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES + REMOVAL_OWNER_PHASES
                and self.environment.get("GITHUB_REF") not in (APP_SIGNATURE_REF, APP_ABSENCE_REF, RESTORE_CHAIN_REF, UPDATE_REF, CANDIDATE_REF, XCODE_SETUP_REF))
            need((selection is None) == (self.signing is None), "source-signing-profile-pair")
            self.package_sources.extend(((self.profile_entry, self.service_profile), (self.producer_profile_entry, self.producer_profile)))
            if self.phase in STORE_SIGNING_PHASES:
                self.store_signing_module.prepare(self)
            elif self.phase in SUPPORT_PHASES:
                self.android_support_module.prepare(self)
            elif self.phase in PYTHON_PHASES:
                self.python_prepare()
            elif self.phase in TOOL_SIGNING_PHASES:
                self.tool_prepare()
            else:
                need(self.environment.get("MRK_MACOS_PACKAGE_ROLE") in self.stager.PACKAGE_ROLES, "source-package-role")
                release_body = self.image_binding()
                self.package_sources.append((self.release_entry, release_body))
                if self.phase in APP_ABSENCE_PHASES:
                    (self.app_absence_module.prepare if self.phase == APP_ABSENCE_PHASES[0]
                     else self.app_absence_module.restore)(self)
                elif self.phase == UPDATE_PHASE:
                    self.update_module.baseline(self)
                elif self.phase == "prepare":
                    self.prepare()
                elif self.phase == "package-install":
                    self.package_install()
                elif self.phase == SAME_PACKAGE_PHASE:
                    self.same_package_noop()
                elif self.setup_verify:
                    self.verify_xcode_setup_package()
                elif self.phase == "package-remove":
                    self.package_remove()
                elif self.phase == "prepare-removal-observers":
                    self.prepare_removal_observers()
                elif self.phase == "package-removal-fixture":
                    self.package_removal_fixture()
                elif self.phase in SIGNING_PHASES:
                    self.fixed_sign()
                elif self.phase in NOTARY_PHASES:
                    self.notarize_payload()
                elif self.phase in FINAL_PACKAGE_PHASES:
                    self.finalize_package()
                elif self.phase in FINAL_IMAGE_PHASES:
                    self.finalize_image()
                else:
                    self.verify_staged(expected, self.environment.get("MRK_MACOS_RESIDENT_IMAGE_SHA256"))
            if self.candidate_removal_context is not None:
                self.candidate_removal_post(); self.candidate_removal_sources()
            need(self.read(self.profile_entry) == self.service_profile
                 and self.read(self.producer_profile_entry) == self.producer_profile, "source-signing-profile-changed")
            if self.phase not in SUPPORT_PHASES + STORE_SIGNING_PHASES + PYTHON_PHASES + TOOL_SIGNING_PHASES:
                need(self.read(self.release_entry) == release_body, "source-image-release-changed")
        except BaseException as error:
            try:
                self.diagnostic_failure = failure_exception(error, self.stager_failure_module)
            except BaseException:
                pass  # Do not replace the same original failure or its cleanup.
            try:
                self.stager_failure_line = failure_stager_line(error, self.stager_failure_module)
            except BaseException:
                pass  # Location is optional and never changes original finality.
            self.receipt["failure"] = {"stage": self.stage, "type": type(error).__name__,
                                       "reason": str(error) if type(error) is Refused else "original-operation-refused"}
            captured = self.diagnostic_failure
            if (type(self.stager_failure_module) is type(sys) and type(error) is self.stager_failure_module.__dict__.get("Refused")
                    and type(captured) is dict and all(type(key) is str for key in captured)
                    and tuple(captured) == ("type", "reason", "errno")
                    and type(captured["type"]) is str and captured["type"] == "stager-refused"
                    and type(captured["reason"]) is str
                    and (captured["reason"] in DISTRIBUTION_STAGER_REASONS
                         or self.phase in FINAL_IMAGE_PHASES and self.stage in FINAL_IMAGE_INPUT_STAGES
                         and captured["reason"] in FINAL_IMAGE_INPUT_STAGER_REASONS)
                    and captured["errno"] is None):
                self.receipt["failure"]["reason"] = captured["reason"]
            if isinstance(error, OSError):
                number = OSError.errno.__get__(error)
                if type(number) is int and 0 < number < 65536:
                    self.receipt["failure"]["errno"] = number
        finally:
            if (self.phase in ("package-install", SAME_PACKAGE_PHASE) + FINAL_IMAGE_PHASES and self.mount_known and not self.mount_detached
                    and not self.installer_entered and self.package_settled()
                    and (self.phase not in FINAL_IMAGE_PHASES or self.final_image_known())):
                try:
                    self.detach_package_mount()  # Pure pre-Installer refusal only, original attach/close/clock known.
                except BaseException as error:
                    self.errors.append({"stage": "package-mount-retained", "type": type(error).__name__})
            if self.phase == "package-removal-fixture" and "failure" in self.receipt and not self.removal_ui_entered:
                try:
                    self.removal_abort_detach()
                except BaseException as error:
                    self.errors.append({"stage": "removal-pre-ui-retained", "type": type(error).__name__})
            self.finish()
        roles = (self.store_signing_module.ROLES if self.store_signing is not None else
                 self.android_support_module.ROLES if self.android_support is not None else
                 UPDATE_ROLES if self.phase == UPDATE_PHASE else
                 self.app_absence_module.roles(self) if self.app_absence is not None else
                 SAME_PACKAGE_ROLES if self.phase == SAME_PACKAGE_PHASE else
                 XCODE_SETUP_VERIFY_ROLES if self.setup_verify else
                 (removal_preparation_roles(self.removal_case) if self.removal_case in REMOVAL_CASES else ()) if self.phase == "prepare-removal-observers" else
                 (removal_runtime_roles(self.removal_case) if self.removal_case in REMOVAL_CASES else ()) if self.phase == "package-removal-fixture" else
                 FINAL_IMAGE_ROLES if self.phase in FINAL_IMAGE_PHASES else
                 final_package_roles(self.removal, self.environment["MRK_MACOS_PACKAGE_ROLE"], setup=self.setup_package) if self.phase in FINAL_PACKAGE_PHASES else
                 notary_roles(getattr(self, "notary_launcher", False)) if self.phase in NOTARY_PHASES else
                 PYTHON_ROLES if self.phase in PYTHON_PHASES else
                 self.stager.PACKAGING_CALL_ROLES if self.phase == "package-install" else
                 REMOVE_PACKAGE_ROLES if self.phase == "package-remove" else
                 prepare_roles(self.target) if self.phase == "prepare" else
                 (self.phase, self.phase + "-verify") if self.phase in SIGNING_PHASES + TOOL_SIGNING_PHASES else (self.phase, self.phase + "-resident-image") + self.tool_staged_roles)
        self.receipt["passed"] = ("failure" not in self.receipt and not self.errors and self.credential_known()
                                  and not self.credential_failed and self.credential_active is None
                                  and all(row["status"] == 0 for row in self.credential_calls)
                                  and all(all(row[key] is True for key in ("retired", "closed", "searchRestored", "defaultUnchanged"))
                                          for row in self.credential_contexts)
                                  and self.receipt["targetRetired"] and self.receipt["originalClosesKnown"]
                                  and tuple(call["role"] for call in self.calls) == roles
                                  and all(call["returned"] and call.get("capturesSettled") is True
                                       and (call["returncode"] == 0 and not (self.app_absence is not None and self.app_absence_module.cut_role_data(self, call["role"]))
                                       or self.phase == "package-install"
                                       and call["role"] in ("installer-log-cursor", "installer-log-capture") and call["returncode"] == 1
                                       or self.setup_verify and call["role"] == "setup-log-cursor" and call["returncode"] == 1
                                       or self.phase == "candidate-baseline" and call["role"] == "app-absence-log-cursor" and call["returncode"] == 1
                                       or self.phase == "package-removal-fixture" and removal_native_result_data(self.removal_case, call["role"], call["returncode"])
                                       or self.app_absence is not None and self.app_absence_module.cut_return_data(self, call["role"], call["returncode"])) for call in self.calls)
                                  and self.sha256 is not None
                                  and (self.phase not in FINAL_PACKAGE_PHASES or self.final_package_complete and self.notary_known()
                                       and self.notary_key is None and tuple(row["role"] for row in self.credential_calls) == INSTALLER_CREDENTIAL_ROSTER
                                       and len(self.credential_contexts) == 1 and self.credential_contexts[0]["purpose"] == "installer"
                                       and self.receipt["notaryAuthentication"] == {"created": True, "closed": True, "retired": True})
                                   and (self.phase not in FINAL_IMAGE_PHASES or self.final_image_complete and self.final_image_known()
                                        and self.final_image_mount_verified and self.mount_detached and not self.installer_entered
                                        and self.notary_key is None
                                        and self.receipt["notaryAuthentication"] == {"created": True, "closed": True, "retired": True})
                                    and (self.phase not in NOTARY_PHASES or self.notary_complete and self.notary_known()
                                        and self.notary_result is not None and self.notary_key is None
                                        and not self.credential_calls and not self.credential_contexts
                                        and self.receipt["notaryAuthentication"] == {"created": True, "closed": True, "retired": True})
                                  and ((self.phase in STORE_SIGNING_PHASES and self.store_signing is not None
                                        and self.store_signing_module.success(self))
                                       or (self.phase in SUPPORT_PHASES and self.android_support is not None
                                        and self.android_support_module.success(self))
                                       or (self.phase in PYTHON_PHASES and self.python_signed is not None and self.python_known())
                                       or (self.phase in TOOL_SIGNING_PHASES and self.tool_complete and self.tool_quote_ready)
                                       or (self.phase not in SUPPORT_PHASES + STORE_SIGNING_PHASES + PYTHON_PHASES + TOOL_SIGNING_PHASES
                                            and (self.phase in ("package-install", "package-remove", SAME_PACKAGE_PHASE, UPDATE_PHASE, XCODE_SETUP_VERIFY) + REMOVAL_OWNER_PHASES + APP_ABSENCE_PHASES or self.phase in FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES or self.resident_image_sha256 is not None
                                                 or self.phase in SIGNING_PHASES and self.fixed_sign_complete)
                                           and self.image_source is not None and self.image_release is not None
                                           and (self.phase != "prepare" or self.entry_sha256 is not None
                                                and self.desktop_facade_sha256 is not None))))
        if self.app_absence is not None:
            self.receipt["passed"] = (self.receipt["passed"] and self.app_absence["complete"]
                and self.app_absence_module.finish_ready(self)
                and (self.phase == "package-install" or not self.credential_calls and not self.credential_contexts))
        if self.update is not None:
            self.receipt["passed"] = self.receipt["passed"] and self.update_module.finish_ready(self)
            if self.phase == UPDATE_PHASE:
                self.update_module.clock(self, work=False)
        if self.phase in TOOL_SIGNING_PHASES:
            self.receipt["toolFinal"] = self.receipt["passed"] and self.tool_complete
            self.tool_clock(work=False)
        if self.setup_verify:
            self.receipt["passed"] = (self.receipt["passed"] and self.setup_verify_complete
                and not self.credential_calls and not self.credential_contexts)
        if self.phase == SAME_PACKAGE_PHASE:
            self.receipt["passed"] = (self.receipt["passed"] and self.same_package_complete and self.notary_known()
                and self.installer_zero and self.installation_readback and self.mount_detached
                and not self.credential_calls and not self.credential_contexts and self.notary_key is None)
        if self.phase in REMOVAL_OWNER_PHASES:
            self.receipt["passed"] = self.receipt["passed"] and self.removal_finish_ready()
        if self.phase == "package-remove":
            self.receipt["passed"] = (self.receipt["passed"] and self.removal_package_complete
                and not self.installer_entered and not self.mount_entered and not self.installation_readback
                and tuple(row["role"] for row in self.credential_calls) == ("producer-adhoc", "producer-adhoc-verify", "producer-cdhash")
                    + (CREDENTIAL_ROLES[:17] + ("search-final", "default-after")) * 2
                and tuple(row["purpose"] for row in self.credential_contexts) == ("producer", "distribution-image"))
            if self.receipt["passed"]:
                self.package_clock()
        # This receipt remains provisional until its own write/readback/close
        # and the original Python caller's zero exit. No output digest on error.
        if self.phase == "package-install" and self.receipt["passed"]:
            self.package_clock()
            need(self.installer_zero and self.installation_readback and self.mount_detached, "package-finality-incomplete")
        if self.phase in PYTHON_PHASES and self.receipt["passed"]:
            self.python_clock(work=False)
            if self.phase == "python-shipping":
                self.python_publish_final("python3", self.python_signed, 0o555)
                capsule = (json.dumps(self.python_capsule(), sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
                self.python_publish_final("python-signed-receipt.json", capsule, 0o444)
        if self.phase in NOTARY_PHASES + FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES or self.phase in ("prepare-removal-observers", SAME_PACKAGE_PHASE):
            self.notary_clock(work=False)
        if self.setup_verify:
            self.setup_verification_cleanup_clock()
        self.publish_receipt()
        if self.setup_verify:
            self.setup_verification_cleanup_clock()
        if self.phase in NOTARY_PHASES + FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES or self.phase in ("prepare-removal-observers", SAME_PACKAGE_PHASE):
            self.notary_clock(work=False)
        if self.phase in PYTHON_PHASES and self.receipt["passed"]:
            self.python_clock(work=False)
        if self.phase in ("package-install", "package-remove", "package-removal-fixture") and self.receipt["passed"]:
            self.package_clock()  # Receipt write/readback/closes are inside the SAME original group.
        if self.phase in TOOL_SIGNING_PHASES:
            self.tool_clock(work=False)
        if self.app_absence is not None:
            self.app_absence_module.clock(self, work=False)
        if self.phase in SUPPORT_PHASES and self.receipt["passed"]:
            self.android_support_module.publish_final(self)
        if self.phase in STORE_SIGNING_PHASES and self.receipt["passed"]:
            self.store_signing_module.publish_final(self)
        if self.phase == UPDATE_PHASE and self.update is not None:
            self.update_module.clock(self, work=False)
        need(self.receipt["passed"], "helper-package-incomplete")
        return self.sha256

    def publish_receipt(self):
        need(self.work_entry is not None and self.work_entry.get("identity") is not None, "receipt-work-unavailable")
        receipt = self.removal_preparation_receipt() if self.phase == "prepare-removal-observers" and self.receipt["passed"] else self.receipt
        if self.phase == "prepare-removal-observers" and not self.receipt["passed"]:
            # Keep the failed original ledger private; a finite projection may
            # describe incompletion but never prints secrets or a success hash.
            receipt = {key: self.receipt[key] for key in ("schemaVersion", "phase", "source", "target", "passed",
                       "targetRetired", "originalClosesKnown", "outerFinalityRequired")}
            receipt.update(nativeCalls=len(self.calls), credentialCalls=len(self.credential_calls),
                           credentialContexts=len(self.credential_contexts), productReady=False,
                           failure=self.receipt.get("failure", {"stage": self.stage, "type": "Incomplete"}))
        if self.store_signing is not None:
            receipt = self.store_signing_module.summary(self)
        body = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        need(len(body) <= 16384, "receipt-bound")
        if self.phase in PYTHON_PHASES:
            self.python_publish_final("android-helper-" + self.phase + ".json", body, 0o600)
            return
        directory = os.open(self.work, READ_FLAGS | os.O_DIRECTORY)
        try:
            need(directory_identity(os.fstat(directory)) == directory_identity(self.work.lstat()) == self.work_entry["identity"], "receipt-work-changed")
            fd = os.open(("tool-signed-receipt.json" if self.phase in TOOL_SIGNING_PHASES and self.receipt["passed"] else "android-helper-" + self.phase + ".json"), os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
            try:
                need(os.write(fd, body) == len(body), "receipt-short-write")
                os.fsync(fd)
                need(os.pread(fd, len(body) + 1, 0) == body, "receipt-readback")
            finally:
                os.close(fd)
        finally:
            os.close(directory)


def load_data(checkout, filename, name):
    spec = importlib.util.spec_from_file_location(name, checkout / "desktop/tools" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def xcode_setup_event(environment, phase):
    """Closed event choice only; all ordinary host/source admission still applies."""
    scope = environment.get("MRK_MACOS_XCODE_SETUP_SCOPE", "disabled")
    if environment.get("GITHUB_REF") == XCODE_SETUP_REF:
        return (scope == "companion-only"
                and environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                and phase in ("sign-xcode-setup", "finalize-xcode-setup-package", XCODE_SETUP_VERIFY))
    return scope == "disabled" and environment.get("GITHUB_EVENT_NAME") == "push"


def admit(environment, *, target=ARM_TARGET, phase=None):
    machine, runner_arch, _release_input = build_profile(target)
    need(sys.platform == "darwin" and sys.maxsize == 2 ** 63 - 1, "hosted-native-platform")
    host = os.uname()  # One original observation; an artifact cannot select a host.
    need(host.machine == machine and os.getuid() != 0
         and os.getuid() == os.geteuid() and os.getgid() == os.getegid(), "hosted-native-platform")
    need(Path(__file__).absolute() == CHECKOUT / "desktop/tools/macos_android_helper_package.py", "fixed-source-driver")
    ref = environment.get("GITHUB_REF")
    native_role = None
    if environment.get("MRK_MACOS_NATIVE_SCOPE", "disabled") != "disabled":
        native_role = load_data(CHECKOUT, "macos_identity_current_runtime.py",
            "_mrk_identity_current_package_scope").package_role(environment, phase, target)
    need(xcode_setup_event(environment, phase), "candidate-companion-event-scope")
    scope = environment.get("MRK_MACOS_SAME_PACKAGE_SCOPE", "disabled")
    need(scope in ("disabled", SAME_PACKAGE_PHASE)
         and (scope == "disabled" or ref == "refs/heads/verify/desktop-macos-preview"), "same-package-source-scope")
    if phase == SAME_PACKAGE_PHASE:
        need(scope == SAME_PACKAGE_PHASE and ref == "refs/heads/verify/desktop-macos-preview"
             and not any(k in environment for k in CREDENTIAL_VARIABLES + INSTALLER_CREDENTIAL_VARIABLES
                         + (NOTARY_KEY_VARIABLE,)), "same-package-fixed-purpose")
    if ref == UPDATE_REF:
        need(scope == "disabled" and phase in APP_SIGNATURE_PHASES + ("notarize-payload", "sign-root-installer",
             "finalize-package", "package-install", UPDATE_PHASE, "finalize-image") + REMOVE_PHASES, "update-fixed-native-route")
        need(environment.get("MRK_MACOS_REMOVAL_CASE", "disabled") == "disabled"
             and environment.get("MRK_MACOS_PACKAGE_ROLE") == "ordinary-image", "update-ordinary-package-only")
    if phase == UPDATE_PHASE:
        need(ref == UPDATE_REF and not any(k in environment for k in CREDENTIAL_VARIABLES + INSTALLER_CREDENTIAL_VARIABLES
             + (NOTARY_KEY_VARIABLE,)), "update-fixed-credential-free-baseline")
    if phase in APP_ABSENCE_PHASES:
        need(ref in (APP_ABSENCE_REF, RESTORE_CHAIN_REF) and not any(k in environment for k in CREDENTIAL_VARIABLES + INSTALLER_CREDENTIAL_VARIABLES
             + (NOTARY_KEY_VARIABLE,)), "app-absence-fixed-native-phase")
    if ref in (APP_ABSENCE_REF, RESTORE_CHAIN_REF):
        need(scope == "disabled" and phase in APP_SIGNATURE_PHASES + ("notarize-payload", "sign-root-installer", "finalize-package", "package-install")
             + APP_ABSENCE_PHASES, "app-absence-fixed-native-route")
    if ref == APP_SIGNATURE_REF:
        need(phase in APP_SIGNATURE_PHASES, "app-signature-fixed-native-phase")
    if ref == CANDIDATE_REF:
        need(scope == "disabled" and phase in CANDIDATE_PHASES, "candidate-fixed-native-phase")
    if ref == REMOVAL_REF:
        removal_context_data(environment, target)
        need(phase not in PYTHON_PHASES and phase not in FINAL_IMAGE_PHASES, "removal-only-existing-purpose-route")
    elif phase in REMOVAL_OWNER_PHASES:
        raise Refused("removal-fixture-fixed-ref-only")
    if phase == "finalize-image":
        need(ref in ("refs/heads/verify/desktop-macos-preview", "refs/heads/verify/desktop-macos-installed", CANDIDATE_REF, UPDATE_REF),
             "final-image-preview-ref-only")
    elif (phase in FINAL_IMAGE_PHASES or phase in REMOVE_PHASES) and ref != REMOVAL_REF:
        need(ref in ("refs/heads/verify/desktop-macos-preview", UPDATE_REF), "final-image-preview-ref-only")
    support_phase = phase in SUPPORT_PHASES
    if support_phase or ref == SUPPORT_REF:
        need(support_phase and ref == SUPPORT_REF and target == ARM_TARGET
             and not any(k in environment for k in INSTALLER_CREDENTIAL_VARIABLES + (NOTARY_KEY_VARIABLE,)),
             "support-fixed-purpose-ref")
    store_phase = phase in STORE_SIGNING_PHASES
    if store_phase or ref == STORE_SIGNING_REF:
        need(store_phase and ref == STORE_SIGNING_REF
             and not any(k in environment for k in INSTALLER_CREDENTIAL_VARIABLES + (NOTARY_KEY_VARIABLE,)),
             "store-fixed-purpose-ref")
    tool_phase = phase in TOOL_SIGNING_PHASES
    if tool_phase:
        need(ref == TOOL_REF, "closed-tool-purpose-ref")
    python_phase = phase in PYTHON_PHASES
    if python_phase:
        need(ref == "refs/heads/verify/desktop-macos-python-runtime-signing-" + phase[len("python-"):],
             "closed-python-purpose-ref")
    workflow = ("desktop-macos-android-support-signing.yml" if support_phase else
                "desktop-macos-python-runtime-signing.yml" if python_phase or tool_phase or store_phase else
                "desktop-macos-aqua.yml" if ref == "refs/heads/verify/desktop-macos-aqua" else
                "desktop-macos-installed.yml" if ref in ("refs/heads/verify/desktop-macos-installed", "refs/heads/verify/desktop-macos-preview", REMOVAL_REF, APP_SIGNATURE_REF, APP_ABSENCE_REF, RESTORE_CHAIN_REF, UPDATE_REF, CANDIDATE_REF, XCODE_SETUP_REF) else None)
    need(workflow is not None, "closed-workflow-route")
    sha = environment.get("GITHUB_SHA", "")
    required = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": runner_arch,
                "GITHUB_EVENT_NAME": environment["GITHUB_EVENT_NAME"], "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit",
                "GITHUB_WORKSPACE": str(CHECKOUT), "GITHUB_WORKFLOW_SHA": sha,
                "GITHUB_WORKFLOW_REF": "Apdelrahman1911/mobile-release-kit/.github/workflows/" + workflow + "@" + ref,
                "MRK_EXPECTED_SHA": sha, "MRK_MACOS_INSTALL_SOURCE_COMMIT": sha,
                "MRK_MACOS_PACKAGE_ROLE": native_role or ("installed-shell-observation" if workflow == "desktop-macos-aqua.yml" else "ordinary-image"),
                "RUSTUP_TOOLCHAIN": rust_toolchain(target), "DEVELOPER_DIR": "/Library/Developer/CommandLineTools", "MACOSX_DEPLOYMENT_TARGET": "26.0"}
    if python_phase or tool_phase or support_phase or store_phase:
        del required["MRK_MACOS_PACKAGE_ROLE"]
        del required["RUSTUP_TOOLCHAIN"]
        need(environment.get("MRK_MACOS_PACKAGE_ROLE") is None, "python-no-install-package-role")
    need(re.fullmatch(r"[0-9a-f]{40}", sha) and sha != "0" * 40
         and all(environment.get(k) == v for k, v in required.items()), "hosted-source-bindings")
    need(all(re.fullmatch(r"[1-9][0-9]{0,19}", environment.get(key, "")) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "run-identity")
    if workflow == "desktop-macos-aqua.yml":
        need(environment.get("MRK_MACOS_AQUA_SCOPE") in PACKAGE_SCOPES, "full-package-scope-only")
    work = Path(environment.get("MRK_MACOS_WORK", ""))
    prefix = "mrk-macos-store-signing" if store_phase else "mrk-macos-android-support-signing" if support_phase else "mrk-macos-tool-signing" if tool_phase else "mrk-macos-python-signing" if python_phase else "mrk-macos-aqua" if workflow == "desktop-macos-aqua.yml" else "mrk-macos-installed"
    need(work.parent == WORK_PARENT and re.fullmatch(re.escape(prefix) + r"\.[A-Za-z0-9]{8}", work.name), "owned-work-route")
    return work


# Fixed DATA checkpoint after the existing native phase owners. This is
# not a native operation or a certificate/notary/Installer policy override.
APP_SIGNATURE_REF = "refs/heads/verify/desktop-macos-app-signature"
APP_SIGNATURE_PHASES = ("prepare", "sign-vault-helper", "sign-installed-cli", "sign-remover", "sign-applications-launcher", "verify-before",
                        "sign-desktop-image", "sign-desktop-payload", "sign-root-app", "verify-after")
APP_SIGNATURE_DATA = ("select-github-tools-signed", "project-history-provider", "project-github-seal")
# Only produce one current carrier; no fixture, runtime re-signing or UI claim.
CANDIDATE_REF = "refs/heads/verify/desktop-macos-candidate"
XCODE_SETUP_REF = "refs/heads/verify/desktop-macos-xcode-setup"
CANDIDATE_PHASES = APP_SIGNATURE_PHASES + ("notarize-payload", "sign-root-installer",
    "finalize-package", "package-install", "finalize-image", "sign-xcode-setup",
    "finalize-xcode-setup-package", XCODE_SETUP_VERIFY)
APP_SIGNATURE_SUMMARY = "summarize-app-signature"
APP_SIGNATURE_STEPS = ("work", "source", "app_runtime", "github_tools", "app_tools", "app_selection",
                       "android_helper", "app_vault", "app_build", "app_compiler", "app_assemble")


def app_signature_receipt(value, phase, target, environment, selected):
    """Same-run closed receipt DATA; the original caller exit is checked separately."""
    need(type(value) is dict and phase in APP_SIGNATURE_PHASES
         and type(value.get("schemaVersion")) is int and value["schemaVersion"] == 1
         and value.get("phase") == phase and value.get("target") == target
         and value.get("source") == value.get("workflowSource") == environment["GITHUB_SHA"]
         and value.get("workflow") == environment["GITHUB_WORKFLOW_REF"]
         and value.get("runId") == environment["GITHUB_RUN_ID"]
         and value.get("runAttempt") == environment["GITHUB_RUN_ATTEMPT"]
         and value.get("packageRole") == "ordinary-image"
         and value.get("toolchain") == rust_toolchain(target)
         and all(value.get(key) is True for key in ("passed", "targetRetired", "originalClosesKnown", "outerFinalityRequired"))
         and "failure" not in value and value.get("cleanupErrors") == []
         and value.get("directStagerIOPending", False) is None,
         "app-signature-phase-finality")
    roles = (prepare_roles(target) if phase == "prepare" else
             (phase, phase + "-verify") if phase in SIGNING_PHASES else
             (phase, phase + "-resident-image") + tuple(phase + "-" + p for p in TOOL_FIXED if selected[p] is not None))
    calls = value.get("originalCalls")
    need(type(calls) is list and len(calls) == len(roles)
         and all(type(row) is dict and row.get("role") == role and row.get("returned") is True
                 and row.get("capturesSettled") is True and type(row.get("returncode")) is int
                 and row["returncode"] == 0 for row, role in zip(calls, roles)), "app-signature-original-roster")
    purposes = (("resident-image", "helper") if phase == "prepare" else
                (phase,) if phase in SIGNING_PHASES else ())
    contexts, auxiliary = value.get("credentialContexts"), value.get("credentialOriginals")
    credential_roles = (CREDENTIAL_ROLES[:17] + ("search-final", "default-after")) * len(purposes)
    need(type(contexts) is list and len(contexts) == len(purposes)
         and all(type(row) is dict and row.get("purpose") == purpose
                 and all(row.get(key) is True for key in ("closed", "retired", "searchRestored", "defaultUnchanged"))
                 for row, purpose in zip(contexts, purposes))
         and type(auxiliary) is list and len(auxiliary) == len(credential_roles)
         and all(type(row) is dict and row.get("role") == role
                 and all(row.get(key) is True for key in ("entered", "returned", "settled"))
                 and type(row.get("status")) is int and row["status"] == 0
                 for row, role in zip(auxiliary, credential_roles)), "app-signature-credential-finality")
    need(value.get("imageSourceCommit") == environment["GITHUB_SHA"]
         and tool_hex(value.get("imageReleaseSourceSha256")), "app-signature-release-source")
    if phase in SIGNING_PHASES:
        need(value.get("fixedSigningRole") == phase and tool_hex(value.get("signedBytesSha256")),
             "app-signature-signed-bytes")
    return {"phase": phase, "nativeCalls": len(calls), "credentialCalls": len(auxiliary),
            "credentialContexts": len(contexts), "originalsClosed": True}


def app_signature_outcomes(value):
    need(type(value) is dict and set(value) == set(APP_SIGNATURE_STEPS)
         and all(type(item) is str and item == "success" for item in value.values()),
         "app-signature-original-step-outcomes")
    return value


def app_signature_inventory(files, *, runtime_stager=None):
    # tree() really retains <=512MiB of file bodies. No streaming/RSS claim.
    # This projection contains no second copy of those bodies.
    # Only the authenticated current-runtime caller supplies the SOURCE stager;
    # app observations keep their original count and byte ceilings.
    file_limit = 2048 if runtime_stager is None else runtime_stager.MAX_FILES
    byte_limit = 1024 * 1024 if runtime_stager is None else runtime_stager.INVENTORY_BYTES
    need(type(files) is dict and 0 < len(files) <= file_limit, "app-signature-inventory-count")
    rows = []
    for name, (body, mode) in sorted(files.items()):
        need(type(name) is str and len(name.encode("utf-8")) <= 4096 and type(body) is bytes
             and type(mode) is int, "app-signature-inventory-row")
        rows.append({"path": name, "mode": mode, "bytes": len(body), "sha256": digest(body)})
    result = tool_canonical({"schemaVersion": 1, "files": rows}) + b"\n"
    need(len(result) <= byte_limit, "app-signature-inventory-bytes")
    return rows, result


def app_signature_summary(target, environment, stager, work):
    """Readonly post-sign observations, not custody spanning independent codesign calls."""
    need(environment.get("GITHUB_REF") == APP_SIGNATURE_REF, "app-signature-summary-ref")
    outcomes = app_signature_outcomes(tool_json(environment.get("MRK_APP_SIGNATURE_STEP_OUTCOMES", "").encode("ascii")))
    source_inputs = {}
    def read_source(name, maximum):
        body = stager.read(CHECKOUT / name, maximum)
        source_inputs[name] = (body, maximum)
        return body
    producer = read_source(PRODUCER_PROFILE, 1024)
    service = read_source(PROFILE, 1024)
    identity = stager.packaging_signing_data(producer, service)
    binding = stager.maintenance_json(stager.read(work / "source-binding.json", 65536), 65536)
    work_info = work.lstat()
    need(stat.S_ISDIR(work_info.st_mode) and stat.S_IMODE(work_info.st_mode) == 0o700
         and work_info.st_uid == os.getuid() and os.getuid() != 0
         and binding.get("workDirectory") == [work_info.st_dev, work_info.st_ino, work_info.st_uid]
         and binding.get("scope") == "whole-app-signature-only"
         and binding.get("frontendAbsentAtAdmission") is True
         and binding.get("source") == binding.get("workflowSource") == environment["GITHUB_SHA"]
         and binding.get("runId") == environment["GITHUB_RUN_ID"]
         and binding.get("runAttempt") == environment["GITHUB_RUN_ATTEMPT"]
         and binding.get("target") == target and tool_hex(binding.get("tree"), 40), "app-signature-work-binding")
    selected, selected_source = tool_selected(stager, target)
    receipt_bytes, receipts, phases = {}, {}, []
    for phase in APP_SIGNATURE_PHASES:
        body = stager.read(work / ("android-helper-" + phase + ".json"), 16384)
        value = tool_json(body)
        fact = app_signature_receipt(value, phase, target, environment, selected)
        fact["receiptSha256"] = digest(body)
        receipt_bytes[phase], receipts[phase] = body, value
        phases.append(fact)
    _, _, release_path = build_profile(target)
    release = read_source(release_path, 4096)
    need(all(row["imageReleaseSourceSha256"] == digest(release)
             and row["imageReleaseId"] == receipts["prepare"]["imageReleaseId"] for row in receipts.values()),
         "app-signature-same-release")
    for name in ("normal-build.status", "remover-build.status", "installed-cli-build.status"):
        need(stager.read(work / name, 16) == b"0\n", "app-signature-original-compiler-status")
    app = stager.tree(work / "app/Mobile Release Kit.app")
    prefix = "Contents/Helpers/MobileReleaseKitPayload.app/Contents/"
    anchors = {
        "Contents/MacOS/mrk-macos-entry": ("sign-root-app", "MRK_MACOS_SIGNED_ENTRY_SHA256"),
        stager.INSTALLED_CLI: ("sign-installed-cli", "MRK_MACOS_INSTALLED_CLI_SHA256"),
        prefix + "MacOS/mobile-release-kit-desktop": ("sign-desktop-payload", "MRK_MACOS_SIGNED_PAYLOAD_SHA256"),
        prefix + "Frameworks/libmrk_desktop_image.dylib": ("sign-desktop-image", "MRK_MACOS_SIGNED_DESKTOP_IMAGE_SHA256"),
        prefix + "Helpers/mrk-vault-keychain": ("sign-vault-helper", "MRK_MACOS_VAULT_HELPER_SHA256"),
        prefix + "Helpers/mrk-macos-remove": ("sign-remover", "MRK_MACOS_REMOVER_SHA256"),
        stager.LAUNCHER_EXECUTABLE: ("sign-applications-launcher", "MRK_MACOS_APPLICATIONS_LAUNCHER_SHA256"),
    }
    for path, (phase, variable) in anchors.items():
        need(path in app and tool_hex(environment.get(variable))
             and digest(app[path][0]) == environment[variable] == receipts[phase]["signedBytesSha256"],
             "app-signature-observed-signed-executable")
    for path, key in ((stager.ANDROID_HELPER, "helperSha256"), (stager.RESIDENT_IMAGE, "residentImageSha256")):
        need(path in app and all(receipts[phase][key] == digest(app[path][0])
             for phase in ("prepare", "verify-before", "verify-after")), "app-signature-prepared-original")
    if selected["github-seal"] is not None:
        need(stager.GITHUB_SEAL in app and digest(app[stager.GITHUB_SEAL][0]) == selected["github-seal"]["signed"]["signedSha256"],
             "app-signature-selected-seal")
    app_rows, app_inventory = app_signature_inventory(app)
    del app  # Release this full body map BEFORE the separate runtime tree.
    manifest = environment.get("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256")
    need(tool_hex(manifest) and binding.get("runtimeManifestSha256") == manifest
         and binding.get("runtimeSourceInputsSha256") == environment.get("MRK_BUNDLED_RUNTIME_SOURCE_SHA256"),
         "app-signature-runtime-binding")
    runtime = stager.runtime_tree(work / "runtime", manifest, current=True, target=target)
    runtime_rows, runtime_inventory = app_signature_inventory(runtime, runtime_stager=stager)
    del runtime
    need(tool_selected(stager, target) == (selected, selected_source), "app-signature-tool-source-post")
    # Recheck every actual tracked source leaf against the pre-compilation inventory;
    # generated node_modules/dist are deliberately not treated as source leaves.
    inventory_body = stager.read(work / "source-inventory.json", 2 * 1024 * 1024)
    need(tool_hex(environment.get("MRK_APP_SIGNATURE_SOURCE_INVENTORY_SHA256"))
         and digest(inventory_body) == environment["MRK_APP_SIGNATURE_SOURCE_INVENTORY_SHA256"],
         "app-signature-source-inventory-original")
    inventory = stager.maintenance_json(inventory_body, 2 * 1024 * 1024)
    need(set(inventory) == {"source", "tree", "files"} and inventory["source"] == environment["GITHUB_SHA"]
         and inventory["tree"] == binding["tree"] and type(inventory["files"]) is list
         and 0 < len(inventory["files"]) < 4096, "app-signature-source-inventory")
    names = set()
    for row in inventory["files"]:
        need(type(row) is dict and set(row) == {"path", "gitMode", "blob", "size", "sha256"}
             and type(row["path"]) is str and stager.safe_path(row["path"]) and row["path"] not in names
             and row["gitMode"] in ("100644", "100755") and tool_hex(row["blob"], 40)
             and tool_hex(row["sha256"]) and type(row["size"]) is int and 0 <= row["size"] <= 32 * 1024 * 1024,
             "app-signature-source-row")
        names.add(row["path"])
        with stager.parent(CHECKOUT / row["path"]) as (parent, leaf):
            body, info = stager.read_at(parent, leaf, 32 * 1024 * 1024)
        need(len(body) == row["size"] and digest(body) == row["sha256"]
             and hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest() == row["blob"]
             and bool(info.st_mode & 0o111) == (row["gitMode"] == "100755"), "app-signature-source-post")
    for name, (body, maximum) in source_inputs.items():
        need(stager.read(CHECKOUT / name, maximum) == body, "app-signature-profile-release-post")
    for phase, body in receipt_bytes.items():
        need(stager.read(work / ("android-helper-" + phase + ".json"), 16384) == body, "app-signature-receipt-post")
    need(stager.read(work / "source-inventory.json", 2 * 1024 * 1024) == inventory_body
         and [work.lstat().st_dev, work.lstat().st_ino, work.lstat().st_uid] == binding["workDirectory"],
         "app-signature-input-post")
    value = {"schemaVersion": 1, "scope": "whole-app-signature-only", "source": environment["GITHUB_SHA"],
        "workflow": environment["GITHUB_WORKFLOW_REF"], "workflowSource": environment["GITHUB_WORKFLOW_SHA"],
        "tree": binding["tree"], "target": target, "runId": environment["GITHUB_RUN_ID"], "runAttempt": environment["GITHUB_RUN_ATTEMPT"],
        "teamIdentifier": identity.team, "leafCertificateSha1": identity.leaf_sha1,
        "producerProfileSha256": digest(producer), "serviceProfileSha256": digest(service),
        "runtimeManifestSha256": manifest, "runtimeSourceInputsSha256": binding["runtimeSourceInputsSha256"],
        "sourceInventorySha256": digest(inventory_body), "sourceFilesPostChecked": len(names),
        "appInventorySha256": digest(app_inventory), "appFiles": len(app_rows),
        "runtimeInventorySha256": digest(runtime_inventory), "runtimeFiles": len(runtime_rows),
        "phaseOriginals": phases, "originalStepOutcomes": outcomes,
        "appCodeSignVerified": True, "observation": "post-sign-bytes-and-completed-strict-verification-not-atomic-custody",
        "notarized": False, "packageCreated": False, "installed": False, "appLaunched": False,
        "distributionReady": False, "cleanupStillRequired": True}
    summary = tool_canonical(value) + b"\n"
    need(len(summary) <= 65536, "app-signature-summary-bound")
    stager.write_tree(work / "app-signature-evidence", {"summary.json": (summary, 0o444),
        "app-inventory.json": (app_inventory, 0o444), "runtime-inventory.json": (runtime_inventory, 0o444)},
        current_owned=True, root_mode=0o700)
    return 0


def tool_source_snapshot(stager, checkout=CHECKOUT):
    rows = []
    for path, limit in ((TOOL_NOMINATION, TOOL_RECEIPT_LIMIT), (PRODUCER_PROFILE, 1024), (PROFILE, 1024),
                        ("desktop/packaging/macos-empty-entitlements.plist", 1024)):
        with stager.parent(checkout / path) as (parent, leaf):
            before = stager.current_directory_identity(os.fstat(parent))
            body, info = stager.read_at(parent, leaf, limit)
            need(stager.current_directory_identity(os.fstat(parent)) == before, "tool-selection-source-parent")
            rows.append((body, signature(info), before))
    return tuple(rows)


def tool_selected(stager, target, *, signing_purpose=None, checkout=CHECKOUT):
    before = tool_source_snapshot(stager, checkout)
    nomination = tool_nomination_data(before[0][0])
    selected = {}
    for purpose in TOOL_FIXED:
        row = nomination["tools"][purpose][target]
        if signing_purpose is not None:
            if purpose != signing_purpose:
                continue
            need(row["build"]["state"] == "configured", "tool-build-unconfigured")
            stager.packaging_signing_data(before[1][0], before[2][0])
            selected[purpose] = row["build"]
        elif row["signed"]["state"] == "configured":
            stager.packaging_signing_data(before[1][0], before[2][0])
            need(all(row["signed"][key] == digest(body) for key, body in
                     (("producerProfileSha256", before[1][0]), ("serviceProfileSha256", before[2][0]),
                      ("entitlementsSha256", before[3][0]))), "tool-source-profile-anchor")
            selected[purpose] = row
        else:
            selected[purpose] = None
    if signing_purpose is None:
        gh, provider_source = stager.history_provider_source(target=target)
        need((gh is None) == (selected["history-provider"] is None), "tool-history-profile-presence")
        if gh is not None:
            for selected_target in (ARM_TARGET, INTEL_TARGET):
                profile, _ = stager.history_provider_source(target=selected_target)
                row = nomination["tools"]["history-provider"][selected_target]
                need(row["signed"]["state"] == "configured" and profile is not None
                     and profile["sha256"] == row["signed"]["signedSha256"]
                     and profile["sourceManifestSha256"] == row["build"]["sourceManifestSha256"],
                     "tool-history-profile-agreement")
            need(stager.history_provider_source(target=target) == (gh, provider_source), "tool-history-source-post")
    need(tool_source_snapshot(stager, checkout) == before, "tool-selection-source-post")
    return selected, before


def tool_data_context(environment, phase, target):
    if environment.get("MRK_MACOS_NATIVE_SCOPE", "disabled") != "disabled":
        load_data(CHECKOUT, "macos_identity_current_runtime.py",
            "_mrk_identity_current_package_scope").package_role(environment, phase, target)
    machine, architecture, _ = build_profile(target)
    need(sys.platform == "darwin" and os.uname().machine == machine and os.getuid() != 0
         and os.getuid() == os.geteuid() and os.getgid() == os.getegid(), "tool-data-platform")
    ref = environment.get("GITHUB_REF")
    build_selection = phase in TOOL_SELECTION_PHASES[:2]
    if ref in (APP_SIGNATURE_REF, APP_ABSENCE_REF, RESTORE_CHAIN_REF, UPDATE_REF, CANDIDATE_REF):
        need(phase in APP_SIGNATURE_DATA, "app-signature-fixed-data-phase")
    workflow = "desktop-macos-python-runtime-signing.yml" if build_selection else "desktop-macos-installed.yml"
    need(ref == TOOL_REF if build_selection else ref in
         ("refs/heads/verify/desktop-macos-installed", "refs/heads/verify/desktop-macos-preview", REMOVAL_REF, APP_SIGNATURE_REF, APP_ABSENCE_REF, RESTORE_CHAIN_REF, UPDATE_REF, CANDIDATE_REF), "tool-data-ref")
    sha = environment.get("GITHUB_SHA")
    need(tool_hex(sha, 40) and Path(__file__).absolute() == CHECKOUT / "desktop/tools/macos_android_helper_package.py"
         and all(environment.get(k) == v for k, v in {
             "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": architecture,
             "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit",
             "GITHUB_WORKSPACE": str(CHECKOUT), "GITHUB_WORKFLOW_SHA": sha, "MRK_EXPECTED_SHA": sha,
             "MRK_MACOS_INSTALL_SOURCE_COMMIT": sha,
             "GITHUB_WORKFLOW_REF": "Apdelrahman1911/mobile-release-kit/.github/workflows/" + workflow + "@" + ref}.items()),
         "tool-data-source-context")
    need(all(tool_id(environment.get(k)) for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "tool-data-run-context")


def tool_transport_roster(fd, expected):
    # This same iterator is consumed/closed once. No full listdir allocation.
    values = []
    with os.scandir(fd) as iterator:
        for entry in iterator:
            need(len(values) < len(expected) and entry.name in expected and entry.name not in values, "tool-transport-roster")
            values.append(entry.name)
    need(sorted(values) == sorted(expected), "tool-transport-roster")


def tool_project_signed(stager, purpose, target, environment):
    selected, source = tool_selected(stager, target)
    row = selected[purpose]
    need(row is not None, "tool-signed-unconfigured")
    work = Path(environment.get("MRK_MACOS_WORK", ""))
    need(work.parent == WORK_PARENT and re.fullmatch(r"mrk-macos-installed\.[A-Za-z0-9]{8}", work.name), "tool-project-work")
    name, _identifier, limit = TOOL_FIXED[purpose]
    transport, output = work / (purpose + "-transport"), work / (purpose + "-capsule")
    output_parent = stager.current_output_absent(output)
    owned, scratch = tool_quote(purpose)
    with stager._parent_originals(transport) as (parents, parts):
        outer, leaf = parents[-1], parts[-1]
        parent_identities = tuple(stager.current_directory_identity(os.fstat(fd)) for fd in parents)
        def parents_post():
            for index, held in enumerate(parents):
                named = (os.stat("/", follow_symlinks=False) if index == 0 else
                         os.stat(parts[index - 1], dir_fd=parents[index - 1], follow_symlinks=False))
                need(stager.current_directory_identity(os.fstat(held)) == stager.current_directory_identity(named)
                     == parent_identities[index], "tool-transport-parent-post")
        parents_post()
        original_parent = stager.current_directory_identity(os.fstat(outer))
        before = os.stat(leaf, dir_fd=outer, follow_symlinks=False)
        need(stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid() and before.st_gid == os.getgid()
             and stat.S_IMODE(before.st_mode) in (0o700, 0o755), "tool-transport-directory")
        fd = os.open(leaf, READ_FLAGS | os.O_DIRECTORY, dir_fd=outer)
        try:
            capacity = os.fstatvfs(outer)
            need(capacity.f_frsize > 0 and capacity.f_bavail * capacity.f_frsize >= scratch, "tool-project-reserve")
            def snapshot():
                parents_post()
                need(signature(os.fstat(fd)) == signature(before)
                     == signature(os.stat(leaf, dir_fd=outer, follow_symlinks=False))
                     and stager.current_directory_identity(os.fstat(outer)) == original_parent, "tool-transport-directory-post")
                stager.no_xattrs(fd)
                tool_transport_roster(fd, (name, "tool-signed-receipt.json"))
                files, originals = {}, {}
                for member, maximum in ((name, limit), ("tool-signed-receipt.json", TOOL_RECEIPT_LIMIT)):
                    body, info = stager.read_at(fd, member, maximum)
                    need(info.st_uid == os.getuid() and info.st_gid == os.getgid() and info.st_nlink == 1
                         and stat.S_IMODE(info.st_mode) in (0o400, 0o555, 0o600, 0o644), "tool-transport-file")
                    files[member] = (body, 0o555 if member == name else 0o444)
                    originals[member] = signature(info)
                need(len(files[name][0]) == row["signed"]["signedBytes"]
                     and digest(files[name][0]) == row["signed"]["signedSha256"], "tool-transport-signed-anchor")
                tool_signed_receipt(files["tool-signed-receipt.json"][0], row, purpose, target,
                                    source[1][0], source[2][0], source[3][0])
                tool_transport_roster(fd, (name, "tool-signed-receipt.json"))
                need(signature(os.fstat(fd)) == signature(before), "tool-transport-read-post")
                parents_post()
                return files, originals
            captured = snapshot()
            stager.current_output_absent(output, output_parent)
            stager.write_tree(output, captured[0], current_owned=True)
            need(snapshot() == captured and tool_selected(stager, target) == (selected, source), "tool-project-source-post")
        finally:
            os.close(fd)
    return {"schemaVersion": 1, "purpose": purpose, "target": target,
            "sha256": row["signed"]["signedSha256"], "bytes": row["signed"]["signedBytes"],
            "ownedDataReserveBytes": owned, "nativeAuthority": False}


def tool_data_main(phase, target):
    tool_data_context(os.environ, phase, target)
    stager = load_data(CHECKOUT, "stage_macos_installed.py", "_mrk_tool_stager")
    need(stager.read(CHECKOUT / ".git/HEAD", 64) == (os.environ["GITHUB_SHA"] + "\n").encode("ascii"), "tool-detached-source")
    if phase in TOOL_PROJECT_PHASES:
        result = tool_project_signed(stager, phase[len("project-"):], target, os.environ)
    else:
        purpose = phase[len("select-"):-len("-build")] if phase in TOOL_SELECTION_PHASES[:2] else None
        selected, _ = tool_selected(stager, target, signing_purpose=purpose)
        result = {"schemaVersion": 1, "target": target, "tools": selected, "nativeAuthority": False}
    body = tool_canonical(result) + b"\n"
    need(len(body) <= TOOL_RECEIPT_LIMIT, "tool-selection-output-bound")
    need(sys.stdout.write(body.decode("ascii")) == len(body), "tool-selection-short-output")
    sys.stdout.flush()
    return 0


def candidate_builder_retire(op, cut):
    """Close this completed builder, never credit its disk bytes as removed.

    Later baseline is a separate original owner and re-admits the exact completed
    packages. Shared source/input/compiler ancestors remain held here. This
    scoped candidate path never reopens its consumed builder directories.
    """
    f = op.app_absence_module
    need(getattr(op, "candidate_restore_context", None) is not None and op.phase == f.PREPARE
         and cut in (None, *f.CUTS) and not op.errors, "candidate-builder-retirement-purpose")
    prefix = "app-absence" if cut is None else "app-absence-cut-" + cut
    names = {prefix + "-prepared", prefix + "-scripts", prefix + "-original.pkg"}
    f.input_post(op); f.post(op); op.package_post()
    def belongs(entry):
        while entry.get("parent_entry") is not None and entry["parent_entry"] is not op.work_entry:
            entry = entry["parent_entry"]
        return entry.get("parent_entry") is op.work_entry and entry.get("name") in names
    retiring = [entry for entry in op.entries if belongs(entry)]
    need(retiring and all(any(entry.get("parent_entry") is op.work_entry and entry.get("name") == name
                             for entry in retiring) for name in names), "candidate-builder-original-roots")
    for entry in reversed(retiring):
        if entry["fd"] is not None:
            op.close(entry)
        need(entry["closed"] and entry["fd"] is None and not op.errors, "candidate-builder-close-unknown")
    # Never erase an unresolved original from the operation's lifetime ledger.
    # Only remove settled entries from future live POST lists after all closes.
    ids = {id(entry) for entry in retiring}
    op.app_absence["outputs"] = [row for row in op.app_absence["outputs"] if id(row[0]) not in ids]
    op.app_absence["roots"] = [row for row in op.app_absence["roots"] if id(row[0]) not in ids]
    del op.app_absence["inputCopies"]
    f.clock(op)


def candidate_carrier_retire(op):
    """Last copied-source use before independently admitted read-only mount.

    Never delete disk bytes, retire product/bootstrap controls, or retry closes.
    The next fixed attach must verify every mounted leaf against the complete
    layout before any root observer/Installer effect.
    """
    f = op.app_absence_module
    need(getattr(op, "candidate_restore_context", None) is not None
         and op.phase in ("candidate-baseline", f.RESTORE) and not op.errors
         and op.package_settled() and op.app_absence["mount"] is None
         and not op.app_absence.get("candidateCopiedOriginalsRetired")
         and len(op.calls) == (2 if op.phase == "candidate-baseline" else 0), "candidate-carrier-last-use")
    f.post(op); op.package_post()
    names = {"app-absence-prepared", *("app-absence-cut-" + cut + "-prepared" for cut in f.CUTS)}
    def belongs(entry):
        if entry.get("parent_entry") is not None and entry["parent_entry"].get("parent_entry") is op.work_entry \
                and entry["parent_entry"].get("name") == "app-absence-carrier":
            return entry.get("kind") == "file" and entry.get("name") in f.carrier_names(op)
        while entry.get("parent_entry") is not None and entry["parent_entry"] is not op.work_entry:
            entry = entry["parent_entry"]
        return entry.get("parent_entry") is op.work_entry and entry.get("name") in names
    selected = [entry for entry in op.entries if belongs(entry)]
    need(len(selected) == 12 + len(f.carrier_names(op)) and all(any(entry.get("parent_entry") is op.work_entry
         and entry.get("name") == name for entry in selected) for name in names), "candidate-carrier-original-roster")
    for entry in reversed(selected):
        op.close(entry)
        need(entry["closed"] and entry["fd"] is None and not op.errors, "candidate-carrier-close-unknown")
    retired = {id(entry) for entry in selected}
    op.app_absence["outputs"] = [row for row in op.app_absence["outputs"] if id(row[0]) not in retired]
    op.app_absence["roots"] = [row for row in op.app_absence["roots"] if id(row[0]) not in retired]
    op.app_absence["candidateCopiedOriginalsRetired"] = True
    f.clock(op)


def candidate_materialize(session, originals, inventory, app_scripts):
    """Thin fixture inputs under the SAME verified acquisition, no native call.

    Full P remains byte-identical. Runtime bytes remain in P and its signed
    inventory; only this nonshipping source tree has an empty runtime folder.
    The caller still owns mount/source/finality and cannot return before our
    original copies/readback/closes. No ordinary acquire/install calls here.
    """
    f = session.fixture_api
    need(session.purpose == "acquire-restore" and session.package_api is sys.modules[__name__]
         and session.acquisition_result is not None and not session.installer_entered
         and all(row["returned"] and row["capturesSettled"] for row in session.calls),
         "candidate-materialize-admission")
    session.point()
    selected = session.origin
    for key in ("package", "descriptor", "signature"):
        row = selected[key]; body, mode = originals[row["name"]]
        need(mode == 0o444 and (len(body), digest(body)) == (row["bytes"], row["sha256"]),
             "candidate-materialize-full-product")
    stager = session.stager
    rows = stager.observation_inventory_bytes(inventory, selected["inventorySha256"],
        selected["runtimeManifestSha256"], selection=session.selection)
    apps = f.app_rows(rows)
    # These references came from the acquisition's one validated CPIO parse.
    # Recheck the complete app projection without decoding the full product again.
    need(type(app_scripts) is MappingProxyType and set(app_scripts) == {"input/" + name for name in apps},
         "candidate-materialize-app-roster")
    expected = {}
    for name, row in apps.items():
        value = app_scripts["input/" + name]
        need(type(value) is tuple and len(value) == 2, "candidate-materialize-app-shape")
        body, mode = value
        need(type(body) is bytes and (len(body), digest(body), mode) ==
             (row["size"], row["sha256"], 0o555 if row["executable"] else 0o444),
             "candidate-materialize-app")
        expected[name] = (body, mode)
    expected[stager.INSTALLATION_INVENTORY_NAME] = (inventory, 0o444)
    dirs = {"", "runtime"}
    for name in expected:
        parts = name.split("/")
        need(len(parts) <= 16, "candidate-materialize-depth")
        dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
    def external():
        count = 0
        for book in session.quota.books:
            need(not book.errors, "candidate-materialize-originals-known")
            for entry in book.entries:
                fd = entry["fd"]
                if type(entry) is dict:
                    need((fd is not None and entry["closed"] is False)
                         or (fd is None and entry["closed"] is True),
                         "candidate-materialize-originals-known")
                else:
                    # FixedSudoEntry is a live view of its donor's original node,
                    # not a dictionary and not a second descriptor owner.
                    need(book.ready and not book.failed and not book.finished
                         and not book.close_uncertain and fd is not None
                         and entry.node.close_state == "owned",
                         "candidate-materialize-originals-known")
                count += fd is not None
        need(count <= 96, "candidate-materialize-originals-bound")
        return count
    depth = max((name.count("/") for name in expected), default=0)
    # Work+target+input consume3, a deepest DFS leaf consumes depth+1;
    # the later retained producer directory/files peak at7. Acquisition's
    # lifetime96 budget is unchanged; these are two simultaneous owners.
    import resource
    soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    quote = dict(acquisitionReserved=session.quota.reserved, acquisitionLive=external(),
                 files=len(expected), directories=len(dirs), depth=depth,
                 materializerLive=max(depth + 4, 7), liveLimit=128, lifetimeLimit=24576,
                 osLimit=-1 if soft_limit == resource.RLIM_INFINITY else min(soft_limit, 1000000),
                 osRequired=160)
    for valid, reason in (
            (quote["acquisitionReserved"] + 3 * (len(expected) + len(dirs)) + 16 <= 24576,
             "candidate-materialize-lifetime-quote"),
            (quote["acquisitionLive"] + quote["materializerLive"] <= 128,
             "candidate-materialize-live-quote"),
            (soft_limit == resource.RLIM_INFINITY or soft_limit >= 160,
             "candidate-materialize-os-fd-limit")):
        if not valid:
            # Fixed numerical resource facts only. Never inventory names/bytes,
            # private paths, exception text or a new acceptance receipt.
            try:
                sys.stderr.write("MRK_CANDIDATE_MATERIALIZE_ADMISSION=" + json.dumps(quote, sort_keys=True) + "\n")
            except BaseException:
                pass  # A diagnostic write cannot replace the original refusal.
            need(False, reason)
    environment = dict(GITHUB_SHA=session.helper_source, GITHUB_WORKFLOW_SHA=session.helper_source,
        GITHUB_RUN_ID=session.run_id, GITHUB_RUN_ATTEMPT=session.run_attempt,
        GITHUB_WORKFLOW_REF="Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-candidate-consume.yml@refs/heads/verify/desktop-macos-candidate-consume")
    op = Operation(None, session.candidate_root, session.work.parent, f.PREPARE, environment, stager, target=session.target)
    op.app_absence_module, op.app_absence_api = f, sys.modules[__name__]
    op.candidate_external_originals = external
    op.candidate_bootstrap_originals = session.quota.reserved
    op.app_absence = dict(started=session.clock.started, observed=session.clock.check(), workSeconds=540, hardSeconds=600,
        pendingRoot=None, pendingCut=None, mount=None, roots=[], outputs=[], complete=False)
    original_ids = {}
    try:
        op.open()
        destination = op.package_directory("input")
        def write(parent, prefix):
            names = {name[len(prefix):].split("/")[0] for name in (*expected, *dirs) if name.startswith(prefix) and name != prefix.rstrip("/")}
            for name in sorted(names):
                path = prefix + name
                if path in expected:
                    body, mode = expected[path]
                    entry = op.package_file(parent, name, body)
                    if mode != 0o444:
                        os.fchmod(entry["fd"], mode); os.fsync(entry["fd"])
                        entry["identity"] = signature(os.fstat(entry["fd"]))
                    original_ids[path] = entry["identity"]
                    op.package_outputs.remove(next(row for row in op.package_outputs if row[0] is entry))
                    op.close(entry); need(entry["closed"], "candidate-materialize-close")
                else:
                    child = f.tree_directory(op, parent, name, create=True)
                    write(child, path + "/")
                    original_ids[path] = child["identity"]
                    op.close(child); need(child["closed"], "candidate-materialize-close")
            need(set(os.listdir(parent["fd"])) == names, "candidate-materialize-roster")
            os.fchmod(parent["fd"], 0o555); os.fsync(parent["fd"])
            parent["identity"] = directory_identity(os.fstat(parent["fd"]))
        write(destination, "")
        def post(parent, prefix):
            names = {name[len(prefix):].split("/")[0] for name in (*expected, *dirs) if name.startswith(prefix) and name != prefix.rstrip("/")}
            need(set(os.listdir(parent["fd"])) == names, "candidate-materialize-post-roster")
            for name in sorted(names):
                path = prefix + name
                if path in expected:
                    body, mode = expected[path]
                    entry = f.tree_leaf(op, parent, name, (len(body), digest(body), mode))
                else:
                    entry = f.tree_directory(op, parent, name); post(entry, path + "/")
                need(entry["identity"] == original_ids[path], "candidate-materialize-original-post")
                op.close(entry); need(entry["closed"], "candidate-materialize-close")
            op.recheck_directory(parent)
        post(destination, "")
        producer = op.package_directory("candidate-producer")
        for name in ("Install.pkg", "producer.json", "producer.sig"):
            op.package_file(producer, name, originals[name][0])
        op.package_roots.append((producer, set(originals)))
        op.package_post(); session.point()
        op.app_absence["complete"] = True
    finally:
        op.finish()
    need(op.app_absence["complete"] and op.receipt["originalClosesKnown"] is True
         and op.receipt["targetRetired"] is True and not op.errors
         and all(entry["closed"] for entry in op.entries), "candidate-materialize-finality")
    session.point()


def candidate_removal_phase(consumer, context, phase, bootstrap):
    """Current workflow H packages the authenticated P remover, never an app build.

    Source queries use the same native owner. Their records are separate from
    the unchanged signing/notary rosters. No old producer receipt is rewritten.
    """
    r = consumer.resume
    need(phase in consumer.REMOVAL_PHASES
         and context == consumer.context_data(os.environ, consumer.ROOT, consumer.platform.machine())
         and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
         and os.environ.get("MRK_CANDIDATE_MODE") == "remove-delivery"
         and bootstrap[1] == consumer.HELPER_ROOT / "desktop/tools/macos_android_helper_package.py",
         "candidate-removal-entry")
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    need((soft == resource.RLIM_INFINITY or soft >= 256) and (hard == resource.RLIM_INFINITY or hard >= 256),
         "candidate-removal-os-fd-limit")
    allowed = (INSTALLER_CREDENTIAL_VARIABLES + (NOTARY_KEY_VARIABLE,) if phase == "finalize-remove-package" else
               CREDENTIAL_VARIABLES if phase == "package-remove" else
               (NOTARY_KEY_VARIABLE,) if phase == "finalize-remove-image" else ())
    all_credentials = CREDENTIAL_VARIABLES + INSTALLER_CREDENTIAL_VARIABLES + (NOTARY_KEY_VARIABLE,)
    need(all(key not in os.environ for key in all_credentials if key not in allowed), "candidate-removal-credentials")
    env = {key:os.environ[key] for key in ("GITHUB_SHA", "GITHUB_WORKFLOW_SHA", "GITHUB_WORKFLOW_REF",
        "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", *allowed)}
    env.update(HOME="/Users/runner", DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer",
        MACOSX_DEPLOYMENT_TARGET="26.0", MRK_MACOS_PACKAGE_ROLE="ordinary-image", MRK_MACOS_SAME_PACKAGE_SCOPE="disabled")
    # Export is passive stager I/O, not an additional signing phase/receipt.
    op = Operation(None, consumer.CANDIDATE_ROOT, context["work"].parent,
                   "package-remove" if phase == "remove-preview" else phase, env, None, target=context["target"])
    op.candidate_removal_context = dict(context)
    started = time.monotonic_ns()
    seconds = 180 if phase == "remove-preview" else 990 if phase == "package-remove" else 1740
    op.package_started = op.package_observed = started
    op.package_endpoint = started + seconds * 1_000_000_000
    files, originals = {}, {}
    source_phase = None
    helper_files = tuple(dict.fromkeys((*consumer.HELPER_SOURCE_INPUTS, consumer.CONSUMER_PATH,
        consumer.LEGACY_PATH, consumer.PARSER_PATH, consumer.SELECTION_PATH, consumer.STAGER_PATH,
        "desktop/tools/macos_android_helper_package.py", "desktop/tools/macos_normal_ui_runner.py")))
    shared = ("desktop/macos-installed-inputs/build-release.json", op.release_input, PROFILE, PRODUCER_PROFILE, INSTALLER_PROFILE, NOTARY_PROFILE,
              "desktop/macos-installed-inputs/remove-postinstall", "desktop/packaging/macos-removal.md")
    helper_files = tuple(dict.fromkeys((*helper_files, *shared)))
    if phase == "package-remove":
        helper_files += ("desktop/src-tauri/examples/macos_remove_producer.rs",
                         "desktop/src-tauri/examples/macos_producer_common/mod.rs")
    product_files = tuple(dict.fromkeys((consumer.STAGER_PATH, *shared)))
    nomination = None

    def load():
        nonlocal source_phase, nomination
        for helper, paths in ((True, helper_files), (False, product_files)):
            for relative in paths:
                entry = op.source_original((".candidate-consumer-helper/" if helper else "") + relative,
                                           "candidate-removal-source", r.SOURCE_MODULE_LIMIT)
                body = op.read(entry)
                op.package_sources.append((entry, body))
                files[(helper, relative)], originals[(helper, relative)] = body, entry
        need(consumer.resume_identity(originals[(True, "desktop/tools/macos_android_helper_package.py")]) == bootstrap[0]
             and files[(True, "desktop/tools/macos_android_helper_package.py")] == bootstrap[2], "candidate-bootstrap-original-post")
        nomination = consumer.selection_data(files[(True, consumer.SELECTION_PATH)], op.target)
        def module(leaf, name, helper=True):
            relative = "desktop/tools/" + leaf
            return r.load_module(name, (consumer.HELPER_ROOT if helper else consumer.CANDIDATE_ROOT) / relative, files[(helper,relative)])
        normal = module("macos_normal_ui_runner.py", "_mrk_remove_phase_clock")
        clock = normal.PhaseClock(seconds, started=started)
        qualification = module("macos_aqua_qualification.py", "_mrk_remove_phase_owner")
        op.owner = qualification.load_owner(consumer.HELPER_ROOT)
        clean = dict(PATH="/usr/bin:/bin:/usr/sbin:/sbin", HOME="/Users/runner", LANG="C", LC_ALL="C", TZ="UTC",
            TMPDIR=str(op.work/op.target_name/"tmp")+"/", DEVELOPER_DIR=env["DEVELOPER_DIR"],
            GIT_CONFIG_NOSYSTEM="1",GIT_CONFIG_GLOBAL="/dev/null",GIT_NO_REPLACE_OBJECTS="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0")
        source_phase = normal.NormalPhase(op.owner, clean, op.checkout, clock)
        sources()
        op.stager = module("stage_macos_installed.py", "_mrk_candidate_remove_stager")
        op.stager_failure_module = op.stager
        product = module("stage_macos_installed.py", "_mrk_candidate_remove_product", False)
        selection = product.source_build_selection(op.target)
        current = op.stager.source_build_selection(op.target)
        need((selection.target,selection.package_version,selection.release) == (current.target,current.package_version,current.release)
             and product.CURRENT_PROTOCOL == op.stager.CURRENT_PROTOCOL
             and all(files[(True,path)] == files[(False,path)] for path in shared), "candidate-removal-compatible-source")
        # Same copied-host admission as the existing candidate adapter.
        host_root = op.work / "host-python"
        def directory(path):
            entry = op.descend(op.work_entry, Path(path).relative_to(op.work).parts)
            return entry["identity"], os.listdir(entry["fd"])
        def read_file(path, limit):
            path = Path(path); parent = op.descend(op.work_entry, path.parent.relative_to(op.work).parts)
            entry = op.original(parent, path.name, "candidate-host", limit, (0o600,0o644,0o755))
            body = op.read(entry); op.package_sources.append((entry, body))
            return consumer.resume_identity(entry), body
        _, host_body = read_file(host_root/"host-binding.json",32768)
        snapshot,cfg = r.host_snapshot(host_root,directory,read_file,sidecar=True)
        r.host_selection_data(r.decode(host_body),snapshot,cfg,host_root,
            dict(executable=str(Path(sys.executable).resolve()),prefix=sys.prefix,basePrefix=sys.base_prefix,
                 baseExecutable=str(Path(sys._base_executable).resolve())),context["helperSource"],context["runId"],context["runAttempt"])
        acquired = op.original(op.work_entry,"candidate-acquisition.json","candidate-handoff",65536,(0o600,))
        status = op.original(op.work_entry,"candidate-acquisition.status","candidate-handoff",4,(0o600,))
        body = op.read(acquired)
        need(op.read(status) == b"0\n", "candidate-acquisition-caller-zero")
        value = consumer.removal_acquisition_data(tool_json(body),nomination,context["helperSource"],
            op.candidate_removal_context["helperTree"],context["runId"],context["runAttempt"],selection)
        op.package_sources.extend(((acquired,body),(status,b"0\n")))
        root = op.directory(op.work_entry,"resume-carrier","candidate-removal-donors")
        need(set(os.listdir(root["fd"])) == set(consumer.REMOVAL_DONORS), "candidate-removal-donor-roster")
        op.candidate_removal_root = root
        op.candidate_removal_inputs = []
        for key in ("package","descriptor","signature","inventory","remover"):
            row = value[key]
            entry = op.original(root,row["name"],"candidate-removal-donor",row["bytes"],(0o555,) if key=="remover" else (0o444,))
            need(entry["identity"][6] == row["bytes"] and digest(op.read(entry)) == row["sha256"], "candidate-removal-donor-post")
            op.candidate_removal_inputs.append((entry,row["sha256"]))
        env.update(MRK_MACOS_INSTALL_SOURCE_COMMIT=nomination["source"],
            MRK_MACOS_INSTALL_INVENTORY_SHA256=value["inventory"]["sha256"],
            MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=value["runtimeManifestSha256"],
            MRK_MACOS_REMOVER_SHA256=value["remover"]["sha256"])
        op.candidate_removal_context.update(productSource=nomination["source"], tree=nomination["tree"],
            artifactId=nomination["artifactId"], artifactSha256=nomination["artifactSha256"], runtimeManifestSha256=value["runtimeManifestSha256"])
        op.candidate_removal_post()

    def sources():
        for entry, body in op.package_sources:
            need(op.read(entry) == body, "candidate-removal-source-post")
        for helper, root, sha, paths in ((True,consumer.HELPER_ROOT,context["helperSource"],helper_files),
                                        (False,consumer.CANDIDATE_ROOT,nomination["source"],product_files)):
            prefix=["/usr/bin/git","-C",str(root),"-c","core.fsmonitor=false","-c","core.hooksPath=/dev/null","--no-optional-locks","--literal-pathspecs"]
            op.candidate_removal_quote()
            op.stager_io_pending = "candidate-source-query"
            result=source_phase.call("helper-source" if helper else "candidate-source",prefix+["rev-parse","HEAD","HEAD^{tree}"],15,8192)
            need(result.returncode==0 and result.stderr==b"", "candidate-source-query")
            values=result.stdout.splitlines()
            need(len(values)==2 and values[0]==sha.encode("ascii") and re.fullmatch(rb"[0-9a-f]{40}",values[1]), "candidate-source-identity")
            tree=values[1].decode("ascii")
            if helper:
                need(op.candidate_removal_context.get("helperTree",tree)==tree,"candidate-helper-tree-post")
                op.candidate_removal_context["helperTree"]=tree
            else: need(tree==nomination["tree"],"candidate-source-tree")
            result=source_phase.call("helper-source" if helper else "candidate-source",prefix+["ls-tree","-z","--full-tree",sha,"--",*sorted(paths)],15,8192)
            need(result.returncode==0 and result.stderr==b"", "candidate-source-query")
            consumer.source_rows_data(result.stdout,{path:files[(helper,path)] for path in paths})
            op.stager_io_pending = None
        for entry, body in op.package_sources:
            need(op.read(entry) == body, "candidate-removal-source-post")

    op.candidate_removal_load = load
    op.candidate_removal_sources = sources
    try:
        if phase != "remove-preview":
            op.execute()
            return {"schemaVersion":1,"phase":phase,"source":context["helperSource"],
                    "productSource":nomination["source"],"passed":True,"removalExecuted":False}
        try:
            op.open(); load()
            args = argparse.Namespace(target=op.target, work=op.work, expected_source=nomination["source"],
                output=op.work/"remove-preview")
            result = op.stager.remove_preview_command(args, candidate_binding=op.candidate_removal_binding())
            op.candidate_removal_post(); sources()
        finally:
            op.finish()
        need(op.receipt["originalClosesKnown"] and op.receipt["targetRetired"] and not op.errors
             and not op.calls and not op.credential_calls and len(source_phase.records)==8,
             "candidate-removal-export-finality")
        source_phase.clock.check()
        return result
    except BaseException as error:
        try:
            emit_failure_diagnostic(error,phase=phase,target=op.target,main_stage="operation-execute",operation=op,stager=op.stager)
        except BaseException:
            pass
        raise


def candidate_fixture_phase(consumer, context, purpose, started, bootstrap):
    """Fixed dual-source bootstrap for the three existing nonshipping owners.

    No native qualification or nominal legacy receipt is manufactured here.
    All retained source, host, handoff and phase originals share Operation's
    ledger. The existing bounded native owner is unchanged.
    """
    r = consumer.resume
    phase = {"prepare-restore":"prepare-app-absence", "restore-baseline":"candidate-baseline",
             "restore-chain":"app-absence-restore"}.get(purpose)
    need(phase is not None and {k:v for k,v in context.items() if k != "started"} == consumer.context_data(os.environ, consumer.ROOT, consumer.platform.machine())
         and bootstrap[1] == (consumer.HELPER_ROOT / "desktop/tools/macos_android_helper_package.py"),
         "candidate-fixture-entry")
    work = context["work"].parent
    # These two tiny SOURCE bootstrap reads have already consumed their only
    # originals before creating Operation. Each is retained and compared below.
    fixture_path = consumer.HELPER_ROOT / consumer.FIXTURE_PATH
    fixture_id, fixture_body = r.host_read(fixture_path, 112 << 10)
    f = r.load_module("_mrk_candidate_phase_fixture", fixture_path, fixture_body)
    need(phase in (f.PREPARE, "candidate-baseline", f.RESTORE), "candidate-fixture-phase")
    hard = 3240 if phase == f.PREPARE else 720
    work_seconds = hard - 60
    env = {key:os.environ[key] for key in ("GITHUB_SHA", "GITHUB_WORKFLOW_SHA", "GITHUB_WORKFLOW_REF",
        "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
    env.update(HOME="/Users/runner", DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer",
        MACOSX_DEPLOYMENT_TARGET="26.0", MRK_MACOS_PACKAGE_ROLE="ordinary-image", MRK_MACOS_SAME_PACKAGE_SCOPE="disabled")
    op = Operation(None, consumer.CANDIDATE_ROOT, work, phase, env, None, target=context["target"])
    op.app_absence_module, op.app_absence_api = f, sys.modules[__name__]
    op.app_absence = dict(started=started, observed=time.monotonic_ns(), workSeconds=work_seconds, hardSeconds=hard,
        pendingRoot=None, pendingCut=None, mount=None, roots=[], outputs=[], complete=False,
        future=dict(f.OUTPUTS) if phase == f.PREPARE else {"withdrawn":f.OUTPUTS["withdrawn"]} if phase == f.RESTORE else {})
    op.package_started = op.package_observed = started
    op.package_endpoint = started + work_seconds * 1_000_000_000
    op.candidate_restore_context = dict(context)
    files, originals, source_phase = {}, {}, None
    op.candidate_bootstrap_originals = 6  # Two closed bootstrap reads + four sequential existing owner-loader reads.
    failure = None
    def diagnose(error, *, capture=False):
        # Passive only. Preserve the primary before the unchanged finalizer,
        # and emit its existing bounded projection only after finalization.
        try:
            if capture:
                op.diagnostic_failure = failure_exception(error, op.stager)
                op.receipt["failure"] = {"stage": op.stage, **op.diagnostic_failure}
                op.stager_failure_line = failure_stager_line(error, op.stager)
            else:
                emit_failure_diagnostic(error, phase=phase, target=op.target,
                    main_stage="operation-execute", operation=op, stager=op.stager)
        except BaseException:
            pass  # Never replace the original exception, including cleanup.
    try:
        f.clock(op)
        op.open()
        helper_files = tuple(dict.fromkeys((*consumer.HELPER_SOURCE_INPUTS, consumer.CONSUMER_PATH,
            consumer.LEGACY_PATH, consumer.PARSER_PATH, consumer.FIXTURE_PATH, consumer.SELECTION_PATH,
            "desktop/tools/macos_android_helper_package.py", "desktop/tools/macos_normal_ui_runner.py", consumer.STAGER_PATH,
            "desktop/macos-installed-inputs/build-release.json", "desktop/macos-installed-inputs/build-release-intel.json",
            *(("desktop/src-tauri/src/macos_app_absence_fixture.rs", "desktop/src-tauri/build.rs",
               "desktop/src-tauri/Cargo.toml") if phase == f.PREPARE else ()))))
        candidate_files = (consumer.STAGER_PATH, *(path for path,cap in consumer.CANDIDATE_SOURCE_INPUTS))
        for helper, paths in ((True,helper_files),(False,candidate_files)):
            for relative in paths:
                full = (".candidate-consumer-helper/" if helper else "") + relative
                entry = op.source_original(full, "candidate-source", r.SOURCE_MODULE_LIMIT)
                body = op.read(entry); op.package_sources.append((entry,body))
                files[(helper,relative)], originals[(helper,relative)] = body, entry
        need(consumer.resume_identity(originals[(True,consumer.FIXTURE_PATH)]) == fixture_id
             and files[(True,consumer.FIXTURE_PATH)] == fixture_body
             and consumer.resume_identity(originals[(True,"desktop/tools/macos_android_helper_package.py")]) == bootstrap[0]
             and files[(True,"desktop/tools/macos_android_helper_package.py")] == bootstrap[2],
             "candidate-bootstrap-original-post")
        nomination = consumer.selection_data(files[(True,consumer.SELECTION_PATH)], op.target)
        op.candidate_restore_context["nomination"] = nomination
        def module(leaf, name, helper=True):
            path = "desktop/tools/" + leaf
            return r.load_module(name, (consumer.HELPER_ROOT if helper else consumer.CANDIDATE_ROOT)/path, files[(helper,path)])
        normal = module("macos_normal_ui_runner.py", "_mrk_candidate_phase_clock")
        phase_clock = normal.PhaseClock(work_seconds, started=started)
        qualification = module("macos_aqua_qualification.py", "_mrk_candidate_phase_owner")
        need(sum(e["fd"] is not None for e in op.entries) + 1 <= 96, "candidate-owner-load-quote")
        op.owner = qualification.load_owner(consumer.HELPER_ROOT)
        clean = dict(PATH="/usr/bin:/bin:/usr/sbin:/sbin", HOME="/Users/runner", LANG="C", LC_ALL="C", TZ="UTC",
            TMPDIR=str(work/op.target_name/"tmp")+"/", DEVELOPER_DIR=env["DEVELOPER_DIR"],
            GIT_CONFIG_NOSYSTEM="1",GIT_CONFIG_GLOBAL="/dev/null",GIT_NO_REPLACE_OBJECTS="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0")
        source_phase = normal.NormalPhase(op.owner,clean,op.checkout,phase_clock)
        def sources():
            op.package_post()
            for helper, root, sha, paths in ((True,consumer.HELPER_ROOT,context["helperSource"],helper_files),
                                            (False,consumer.CANDIDATE_ROOT,nomination["source"],candidate_files)):
                prefix=["/usr/bin/git","-C",str(root),"-c","core.fsmonitor=false","-c","core.hooksPath=/dev/null","--no-optional-locks","--literal-pathspecs"]
                need(sum(e["fd"] is not None or not e["closed"] for e in op.entries) + 8 <= op.app_absence_live_limit(), "candidate-source-query-quote")
                op.stager_io_pending = "candidate-source-query"
                result=source_phase.call("helper-source" if helper else "candidate-source",prefix+["rev-parse","HEAD","HEAD^{tree}"],15,8192)
                need(result.returncode == 0 and result.stderr == b"", "candidate-source-query")
                values=result.stdout.splitlines()
                need(len(values)==2 and values[0]==sha.encode("ascii") and re.fullmatch(rb"[0-9a-f]{40}",values[1]), "candidate-source-identity")
                tree=values[1].decode("ascii")
                if helper:
                    need(op.candidate_restore_context.get("helperTree",tree)==tree,"candidate-helper-tree-post")
                    op.candidate_restore_context["helperTree"]=tree
                else: need(tree==nomination["tree"],"candidate-source-tree")
                result=source_phase.call("helper-source" if helper else "candidate-source",prefix+["ls-tree","-z","--full-tree",sha,"--",*sorted(paths)],15,8192)
                need(result.returncode == 0 and result.stderr == b"", "candidate-source-query")
                consumer.source_rows_data(result.stdout,{path:files[(helper,path)] for path in paths})
                op.stager_io_pending = None
            op.package_post()
        sources()
        def fixture_sources():
            op.stager = module("stage_macos_installed.py", "_mrk_candidate_fixture_stager",False)
            op.candidate_fixture_stager = module("stage_macos_installed.py", "_mrk_candidate_fixture_auditor")
            need(op.stager.DESKTOP == op.checkout/"desktop", "candidate-fixture-product-source")
            need(op.candidate_fixture_stager.DESKTOP == consumer.HELPER_ROOT/"desktop",
                 "candidate-fixture-helper-source")
            product = op.stager.source_build_selection(op.target)
            helper = op.candidate_fixture_stager.source_build_selection(op.target)
            held = op.candidate_fixture_stager.build_release_data(files[(True,op.release_input)], target=op.target)
            need((helper.target, helper.package_version, helper.release) ==
                 (product.target, product.package_version, product.release) ==
                 (op.target, held["packageVersion"], held["release"])
                 and op.candidate_fixture_stager.CURRENT_PROTOCOL == op.stager.CURRENT_PROTOCOL,
                 "candidate-fixture-build-selection")
            return product
        selection = f.io(op, "source-selection", fixture_sources)
        op.candidate_fixture_checkout = consumer.HELPER_ROOT
        op.image_source,op.image_release = nomination["source"],selection.release
        op.image_package_version = selection.package_version
        op.release_entry = originals[(False,op.release_input)]
        if phase == f.PREPARE:
            op.candidate_fixture_source_original = originals[(True,"desktop/src-tauri/src/macos_app_absence_fixture.rs")]
        host = module("macos_xcode_host_preparation.py", "_mrk_candidate_fixture_host")
        host_api = host.DarwinAPI(phase_clock,target=op.target)
        host_api.waitable_sigchld()
        # The fixture mount uses the SAME already SOURCE-bound observer and
        # original phase clock. Its mount authority never aliases normal Install.
        if phase != f.PREPARE:
            need(op.removal_host_module is None and op.removal_api is None,
                 "candidate-fixture-mount-host-once")
            op.removal_host_module, op.removal_api = host, host_api
        host_root=work/"host-python"
        def directory(path):
            entry=op.descend(op.work_entry,Path(path).relative_to(work).parts)
            return entry["identity"],os.listdir(entry["fd"])
        def read_file(path,limit):
            path=Path(path); parent=op.descend(op.work_entry,path.parent.relative_to(work).parts)
            entry=op.original(parent,path.name,"candidate-host",limit,(0o600,0o644,0o755))
            body=op.read(entry);op.package_outputs.append((entry,digest(body)))
            return consumer.resume_identity(entry),body
        _,host_body=read_file(host_root/"host-binding.json",32768)
        snapshot,cfg=r.host_snapshot(host_root,directory,read_file,sidecar=True)
        r.host_selection_data(r.decode(host_body),snapshot,cfg,host_root,
            dict(executable=str(Path(sys.executable).resolve()),prefix=sys.prefix,basePrefix=sys.base_prefix,
                 baseExecutable=str(Path(sys._base_executable).resolve())),context["helperSource"],context["runId"],context["runAttempt"])
        def handoff(parent,name,cap=65536):
            return op.original(parent,name,"candidate-handoff",cap,(0o600,))
        acquired=handoff(op.work_entry,"candidate-acquisition.json")
        acquired_status=handoff(op.work_entry,"candidate-acquisition.status",4)
        need(op.read(acquired_status)==b"0\n","candidate-acquisition-caller-zero")
        acquired_body=op.read(acquired)
        value=f.candidate_acquisition_data(tool_json(acquired_body),nomination,context["helperSource"],op.candidate_restore_context["helperTree"],context["runId"],context["runAttempt"])
        op.package_sources.extend(((acquired,acquired_body),(acquired_status,b"0\n")))
        env.update(MRK_MACOS_INSTALL_SOURCE_COMMIT=nomination["source"],MRK_MACOS_INSTALL_INVENTORY_SHA256=value["inventory"]["sha256"],
                   MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=value["runtimeManifestSha256"])
        producer = None
        if phase != f.RESTORE:
            producer=op.directory(op.work_entry,"candidate-producer","candidate-producer")
            need(set(os.listdir(producer["fd"]))=={"Install.pkg","producer.json","producer.sig"},"candidate-producer-roster")
            for key in ("package","descriptor","signature"):
                row=value[key];entry=op.original(producer,row["name"],"candidate-original-product",row["bytes"],(0o444,))
                need(entry["identity"][6]==row["bytes"] and f.original_hash(op,entry)==row["sha256"],"candidate-product-post")
                op.package_outputs.append((entry,row["sha256"]))
            op.package_roots.append((producer,{"Install.pkg","producer.json","producer.sig"}))
            op.candidate_producer_originals = {entry["name"]:entry for entry,sha in op.package_outputs if entry.get("parent_entry") is producer}
        binding=f.binding_data(dict(fixtureSource=context["helperSource"],productSource=nomination["source"],runId=context["runId"],runAttempt=context["runAttempt"],target=op.target))
        op.app_absence["binding"]=binding
        if phase == f.PREPARE:
            f.reserve(op);f.prepare(op)
        elif phase == "candidate-baseline":
            op.app_absence=None
            f.candidate_baseline(op,acquired,acquired_status,producer,nomination,op.candidate_restore_context["helperTree"])
        else:
            retained=op.directory(op.work_entry,"resume-carrier","candidate-transport")
            consumer.candidate_restore(op,handoff(retained,consumer.BASELINE_RECEIPT),handoff(retained,consumer.BASELINE_STATUS,4),
                handoff(op.work_entry,"candidate-install.json"),handoff(op.work_entry,"candidate-install.status",4),
                op.original(retained,"installer-output.status","candidate-native-installer-status",4,(0o600,)))
        sources()
        need(len(source_phase.records)==8 and op.app_absence["complete"],"candidate-fixture-source-finality")
        op.receipt["candidateSource"]={key:op.candidate_restore_context[key] for key in ("helperSource","helperTree","runId","runAttempt")}
        op.receipt["candidateSource"].update(productSource=nomination["source"],productTree=nomination["tree"],originalQueryCount=8,originalQueriesReturned=True)
    except BaseException as error:
        failure = error
        diagnose(error, capture=True)
        raise
    finally:
        try:
            if op.app_absence is not None:
                try: f.clock(op, work=False)
                except BaseException: op.errors.append({"stage":"candidate-retirement-clock","type":"deadline"})
            op.finish()
        except BaseException as error:
            if failure is None:
                diagnose(error, capture=True)
            diagnose(error)
            raise  # Preserve existing cleanup-exception precedence.
        if failure is not None:
            diagnose(failure)
    try:
        need(op.receipt["originalClosesKnown"] is True and op.receipt["targetRetired"] is True and not op.errors
             and op.app_absence["complete"] and len(op.calls)==len(f.roles(op))
             and all(row["returned"] and row["capturesSettled"] for row in op.calls),"candidate-fixture-terminal")
        f.clock(op, work=False)
        if phase == "candidate-baseline":
            return f.candidate_baseline_result(op,nomination,op.candidate_restore_context["helperTree"])
        op.receipt["passed"]=True
        return op.receipt
    except BaseException as error:
        diagnose(error, capture=True)
        diagnose(error)
        raise


def main():
    phase = target = stager = operation = None
    main_stage = "entrypoint"
    try:
        phase, target = entrypoint(sys.argv)
        support_started = time.monotonic_ns() if phase in SUPPORT_PHASES + STORE_SIGNING_PHASES else None
        if phase in TOOL_SELECTION_PHASES + TOOL_PROJECT_PHASES:
            main_stage = "data-phase"
            return tool_data_main(phase, target)
        if phase == APP_SIGNATURE_SUMMARY:
            need(os.environ.get("GITHUB_REF") == APP_SIGNATURE_REF, "app-signature-summary-ref")
            main_stage = "admission"
            work = admit(os.environ, target=target, phase="verify-after")
            main_stage = "stager-load"
            stager = load_data(CHECKOUT, "stage_macos_installed.py", "_mrk_app_signature_stager")
            main_stage = "source-check"
            need(stager.read(CHECKOUT / ".git/HEAD", 64) == (os.environ["GITHUB_SHA"] + "\n").encode("ascii"), "exact-detached-checkout")
            main_stage = "data-phase"
            return app_signature_summary(target, os.environ, stager, work)
        main_stage = "admission"
        work = admit(os.environ, target=target, phase=phase)
        main_stage = "stager-load"
        stager = load_data(CHECKOUT, "stage_macos_installed.py", "_mrk_android_helper_stager")
        main_stage = "source-check"
        need(stager.read(CHECKOUT / ".git/HEAD", 64) == (os.environ["GITHUB_SHA"] + "\n").encode("ascii"), "exact-detached-checkout")
        if os.environ.get("GITHUB_REF") == UPDATE_REF:
            nomination = tool_json(stager.read(CHECKOUT / "desktop/macos-installed-inputs/update-predecessors.json", 16384))
            need(type(nomination) is dict and nomination.get("mode") == "configured",
                 "update-qualified-predecessor-unconfigured")
        main_stage = "profile-check"
        stager.packaging_signing_data(stager.read(CHECKOUT / PRODUCER_PROFILE, 1024), stager.read(CHECKOUT / PROFILE, 1024),
                                     allow_unconfigured=phase not in ("package-install", "package-remove", "python-shipping", SAME_PACKAGE_PHASE) + SUPPORT_PHASES + STORE_SIGNING_PHASES + SIGNING_PHASES + TOOL_SIGNING_PHASES + NOTARY_PHASES + FINAL_PACKAGE_PHASES + FINAL_IMAGE_PHASES + REMOVAL_OWNER_PHASES
                                     and os.environ.get("GITHUB_REF") not in (APP_SIGNATURE_REF, CANDIDATE_REF, XCODE_SETUP_REF))
        if phase in FINAL_PACKAGE_PHASES or phase in ("prepare-removal-observers", SAME_PACKAGE_PHASE):
            need(installer_profile(stager.read(CHECKOUT / INSTALLER_PROFILE, 1024)) is not None, "installer-source-unconfigured")
        main_stage = "owner-load"
        qualification = load_data(CHECKOUT, "macos_aqua_qualification.py", "_mrk_android_helper_owner_loader")
        owner = qualification.load_owner(CHECKOUT)
        main_stage = "operation-create"
        if support_started is not None:
            need(type(support_started) is int and support_started <= time.monotonic_ns() < support_started + (1620 if phase in STORE_SIGNING_PHASES else 960) * 1_000_000_000,
                 "support-admission-deadline")
        operation = Operation(owner, CHECKOUT, work, phase, os.environ, stager, target=target, support_started=support_started)
        main_stage = "operation-execute"
        result = operation.execute(os.environ.get("MRK_MACOS_ANDROID_HELPER_SHA256"))
        main_stage = "success-output"
        if phase == "prepare":
            print("sha256=" + result, flush=True)
            print("entry-sha256=" + operation.entry_sha256, flush=True)
            print("resident-image-sha256=" + operation.resident_image_sha256, flush=True)
            print("desktop-facade-sha256=" + operation.desktop_facade_sha256, flush=True)
            print("image-release-id=" + operation.image_release, flush=True)
        if phase in ("sign-installed-cli", "sign-remover", "sign-applications-launcher", "sign-xcode-setup"):
            # Only the same completed fixed-sign owner may publish this digest;
            # no caller reopens/rehashes a replacement to infer success.
            need(type(result) is str and re.fullmatch(r"[0-9a-f]{64}", result), "fixed-remover-result")
            body = "sha256=" + result + "\n"
            need(sys.stdout.write(body) == len(body), "fixed-remover-result-short-write")
            sys.stdout.flush()
        if phase in NOTARY_PHASES:
            operation.notary_clock(work=False)
            body = operation.notary_result.decode("ascii")
            need(sys.stdout.write(body) == len(body), "notary-final-stdout-short-write")
            sys.stdout.flush()
            operation.notary_clock(work=False)
        return 0
    except BaseException as error:
        # Raw originals/credentials remain private. Even stderr failure must
        # preserve exit1; the finite second line is never success evidence.
        try:
            print("Fixed Android helper packaging refused; see its bounded work receipt.", file=sys.stderr)
        except BaseException:
            pass
        emit_failure_diagnostic(error, phase=phase, target=target, main_stage=main_stage,
                                operation=operation, stager=stager)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
