"""Closed DATA/fixture extension for macos_aqua_qualification, NOT a runner.

No commands, private contents, provider access or report-derived paths. A STOP
diagnostic never supplies invocation finality or permission to close/retry.
"""
from contextlib import ExitStack
from pathlib import Path
import re
import stat

CASES = ("upload-key-roundtrip", "upload-key-stop-before-go", "upload-key-stop-after-new")
TIMEOUT = 495
OBSERVER_SECONDS = 480
PRODUCER_FLAGS = frozenset(("ready", "goClaimed", "goSent", "readerJoined", "resultComplete", "candidate",
                           "inspectorStarted", "inspectorJoined", "acquisitionStarted", "acquisitionJoined",
                           "driverJoined", "managerJoined", "watchdogJoined",
                           "tailClosed", "originalFinal", "cleanupUnknown", "privateDisposed"))
SAMPLE_FLAGS = frozenset(("reserved", "authenticatedNew", "recorded", "published", "privateDisposed", "nativeUseRetired",
                        "nativeUseRetained", "privateRetained", "stopped", "clockFailed", "clockRetired", "coordinatorJoined",
                        "childJoined", "sourcesClosed", "parentEnded", "documentUnknown", "unassigned", "cancelledDisposal"))
REPORT_FIELDS = frozenset(("mechanism", "normalGenerationEnabled", "execution", "testResult", "initializeHelper", "storage",
                         "generated", "repeatedCreateRefused", "authenticatedReopenReadback", "stoppedIntentAcknowledged", "originalCount",
                         "allOriginalsSettled", "finalDocumentEmpty", "automaticallyAssigned", "backupCreated",
                         "releaseSigningQualified", "physicalMacEvidence", "privateContentsExported", "rowRetirement"))
AFTER_NEW_FIELDS = frozenset(("explicitlyBoundSavedKey", "rememberedBoundSavedKey"))


def need(test, label="upload-key-observation"):
    if not test:
        raise ValueError(label)


def _flags(value, names):
    need(type(value) is dict and all(type(value.get(name)) is bool for name in names))


def producer(value):
    need(type(value) is dict and value.keys() == PRODUCER_FLAGS)
    _flags(value, PRODUCER_FLAGS)
    return value


def sample(value):
    need(type(value) is dict and value.keys() == SAMPLE_FLAGS | {"operationId", "checkpoint", "producer", "retainedProducer", "stoppedPreferenceRevision"})
    _flags(value, SAMPLE_FLAGS)
    need(type(value["operationId"]) is int and value["operationId"] == 5)
    need(value["checkpoint"] in ("none", "before-go", "after-new-before-journal"))
    need(value["stoppedPreferenceRevision"] is None or (type(value["stoppedPreferenceRevision"]) is int
         and 0 < value["stoppedPreferenceRevision"] <= 2**64 - 1))
    if value["producer"] is not None:
        producer(value["producer"])
    if value["retainedProducer"] is not None:
        producer(value["retainedProducer"])
    return value


def _generated(value):
    value = producer(value)
    return all(value[key] for key in PRODUCER_FLAGS - {"cleanupUnknown", "privateDisposed"}) \
        and not value["cleanupUnknown"] and not value["privateDisposed"]


def positive(value):
    value = sample(value)
    false = {"nativeUseRetained", "privateRetained", "stopped", "clockFailed", "documentUnknown", "cancelledDisposal"}
    need(all(value[key] is (key not in false) for key in SAMPLE_FLAGS))
    need(value["stoppedPreferenceRevision"] is None)
    need(value["checkpoint"] == "none" and value["producer"] is not None and _generated(value["producer"])
         and value["retainedProducer"] is None)
    return value


def cancelled(value, case):
    """Completed test observation, not generation success or disposal authority."""
    need(case in CASES[1:])
    value = sample(value)
    false = {"recorded", "published", "nativeUseRetained", "privateRetained", "documentUnknown"}
    if case == CASES[1]:
        false.add("authenticatedNew")
    need(all(value[key] is (key not in false) for key in SAMPLE_FLAGS))
    need(value["retainedProducer"] is None)
    if case == CASES[1]:
        need(value["checkpoint"] == "before-go" and value["producer"] is None
             and value["stoppedPreferenceRevision"] is not None)
    else:
        need(value["checkpoint"] == "after-new-before-journal"
             and value["stoppedPreferenceRevision"] is None
             and value["producer"] is not None and _generated(value["producer"]))
    return value


def retained_stop(value, case):
    """Validate diagnostic shape, never return a successful native-run receipt."""
    need(case in CASES[1:])
    need(type(value) is dict and value.keys() == {"source", "observationOnly", "exitOrDisposalPermission", "repeatedCreateRefused", "sample"})
    need(value["source"] == "original-upload-key-sample" and value["observationOnly"] is True
         and value["exitOrDisposalPermission"] is False and value["repeatedCreateRefused"] is True)
    data = sample(value["sample"])
    need(not data["cancelledDisposal"] and data["stoppedPreferenceRevision"] is None)
    for key in ("reserved", "nativeUseRetained", "privateRetained", "stopped", "clockFailed", "unassigned"):
        need(data[key] is True)
    for key in ("recorded", "published", "privateDisposed", "nativeUseRetired", "clockRetired"):
        need(data[key] is False)
    need(data["producer"] is not None)
    if case == CASES[1]:
        need(data["checkpoint"] == "before-go" and data["authenticatedNew"] is False)
        need(data["producer"]["ready"] is True and all(data["producer"][name] is False for name in ("goClaimed", "goSent", "candidate")))
    else:
        need(data["checkpoint"] == "after-new-before-journal" and data["authenticatedNew"] is True and _generated(data["producer"]))
    # `producer` after NEW is the actual previously captured joined receipt;
    # retainedProducer independently preserves the current native axes (or an
    # unavailable sample), never a fallback to that historical receipt.
    # Coordinator, child, source and native axes keep their ORIGINAL booleans.
    return value


def report(value, case):
    need(case in CASES and type(value) is dict)
    after_new = case == CASES[2] and value.get("execution") == "executed"
    need(value.keys() == REPORT_FIELDS | (AFTER_NEW_FIELDS if after_new else frozenset()))
    if after_new:
        need(all(value[key] is True for key in AFTER_NEW_FIELDS))
    need(value["mechanism"] == "same-original-upload-key-v1" and value["normalGenerationEnabled"] is False)
    need(value["allOriginalsSettled"] is True and value["finalDocumentEmpty"] is True)
    for key in ("automaticallyAssigned", "backupCreated", "releaseSigningQualified", "physicalMacEvidence", "privateContentsExported"):
        need(value[key] is False)
    need(value["rowRetirement"] == "disposable-hosted-account-only")
    need(type(value["originalCount"]) is int)
    _flags(value, ("repeatedCreateRefused", "authenticatedReopenReadback", "stoppedIntentAcknowledged"))
    if value["testResult"] == "not-executed":
        need(value["execution"] == "not-executed-prerequisite" and value["generated"] is None
             and not value["repeatedCreateRefused"] and not value["authenticatedReopenReadback"]
             and not value["stoppedIntentAcknowledged"] and value["originalCount"] == 5)
    else:
        need(value["execution"] == "executed" and value["repeatedCreateRefused"]
             and value["originalCount"] == (11 if after_new else 9))
        if case == CASES[0]:
            need(value["testResult"] == "positive" and value["authenticatedReopenReadback"]
                 and not value["stoppedIntentAcknowledged"])
            positive(value["generated"])
        else:
            need(value["testResult"] == "cancelled-cleanup"
                 and value["authenticatedReopenReadback"] is (case == CASES[2])
                 and value["stoppedIntentAcknowledged"] is (case == CASES[1]))
            cancelled(value["generated"], case)
    # The existing runner separately validates original helper/storage syntax.
    # No fixture fills these fields from an expected report or report filename.
    need(type(value["initializeHelper"]) is dict and type(value["storage"]) is dict)
    return value


def fixture_path(binding, native_home, case):
    need(case in CASES and type(native_home) is str and native_home.startswith("/") and native_home != "/"
         and len(native_home.encode("utf-8")) <= 4096 and "\x00" not in native_home
         and all(part not in ("", ".", "..") for part in native_home.split("/")[1:]))
    need(type(binding.source) is str and re.fullmatch(r"[0-9a-f]{40}", binding.source) is not None)
    need(all(type(v) is str and re.fullmatch(r"[1-9][0-9]{0,19}", v) is not None for v in (binding.run, binding.attempt)))
    return Path(native_home) / "Library/Application Support" / (
        f"mrk-macos-aqua-upload-key-{binding.source}-{binding.run}-{binding.attempt}-{case}") / case / "dev.mobile-release-kit.desktop"


def private_roster(names, *, initialized, generated, host_started):
    """Compare names from the held vault FD; never return a report pathname."""
    need(all(type(flag) is bool for flag in (initialized, generated, host_started)))
    need(type(names) is tuple and len(names) <= 4 and all(type(name) is str for name in names)
         and len(set(names)) == len(names))
    controls = {"vault-lock": (0, 0), "initialization-reservation": (48, 48)}
    if initialized:
        controls["vault-header"] = (104, 104)
    record_names = [n for n in names if type(n) is str and re.fullmatch(r"record-[0-9a-f]{32}", n)]
    need(len(record_names) == int(generated))
    if generated:
        need(initialized and host_started and record_names[0] != "record-" + "0" * 32)
        # Fixed generated JKS <=64KiB + bounded original scalars/descriptor and
        # maintained vault AEAD framing. No ciphertext content read here.
        controls[record_names[0]] = (257, 248 + 4096 + 8 + 128 * 1024 + 64 * 1024)
    need(set(names) == set(controls), "upload-key-vault-roster")
    return controls


def _files(fixtures, directory, expected):
    """Pin/recheck already-owned finite file roster, metadata only."""
    before = fixtures._upload_signature(directory)
    fixtures._roster(directory, expected, "upload-key-private-roster")
    total = 0
    with ExitStack() as stack:
        originals = []
        for name, (low, high) in sorted(expected.items()):
            fd = stack.enter_context(fixtures._temporary(fixtures._open(name, directory)))
            held = fixtures._upload_signature(fd)
            need(held[0] == before[0] and held[2] == stat.S_IFREG | 0o600
                 and held[3:6] == (fixtures.uid, fixtures.gid, 1) and low <= held[6] <= high
                 and held == fixtures._upload_named_signature(directory, name), "upload-key-private-custody")
            need(all(held[:2] != prior[:2] for _, _, prior in originals), "upload-key-private-alias")
            originals.append((name, fd, held)); total += held[6]
        for name, fd, held in originals:
            need(fixtures._upload_signature(fd) == held and fixtures._upload_named_signature(directory, name) == held,
                 "upload-key-private-changed")
        need(fixtures._upload_signature(directory) == before, "upload-key-private-directory-changed")
        fixtures._roster(directory, expected, "upload-key-private-roster")
    return total


def readback(fixtures, case, value):
    """Only called by the old invocation owner's genuine CompletedProcess path.

    Private output stays in the disposable hosted account. Exceptions/STOP do
    NOT reach this readback; they retain the existing inflight/unknown boundary.
    """
    report(value, case)
    need(fixtures.cases == (case,) and case not in fixtures.vault_completed
         and not fixtures.inflight and fixtures.last_returned, "upload-key-readback-order")
    host_started = value["execution"] == "executed"
    generated = host_started and case != CASES[1]
    initialized = value["storage"]["header"] == [True, True]
    # Both known cancellations really reserved shared state. Before-GO has
    # NO key; after-NEW preserves its one authenticated key despite cancellation.
    # Only the explicit missing-tools path has never started the Host.
    app_names = ("credential-vault-v1", "service-v1", "service-v1.reservation") if host_started else ("credential-vault-v1",)
    source = fixtures.readback(case)
    parent = fixtures.vault_parents[case]
    fixtures._named(fixtures.vault_namespace, case, parent, 0o700)
    fixtures._roster(parent, ("dev.mobile-release-kit.desktop",), "upload-key-application-roster")
    total = 0
    with fixtures._temporary(fixtures._open("dev.mobile-release-kit.desktop", parent, directory=True)) as app:
        fixtures._named(parent, "dev.mobile-release-kit.desktop", app, 0o700)
        fixtures._roster(app, app_names, "upload-key-application-roster")
        with fixtures._temporary(fixtures._open("credential-vault-v1", app, directory=True)) as vault:
            fixtures._named(app, "credential-vault-v1", vault, 0o700)
            names = fixtures._upload_names(vault)
            total += _files(fixtures, vault, private_roster(names, initialized=initialized, generated=generated, host_started=host_started))
            fixtures._named(app, "credential-vault-v1", vault, 0o700)
        if host_started:
            reservation = len(b"MRK application references v1\nprojects\ncredential-references\nversion-allocations\n")
            root_reservation = len(b"MRK service root v1\n") + 16
            # _files checks complete directory rosters; parent reservation has
            # its own bounded check below because this directory also has dirs.
            with ExitStack() as stack:
                fence = stack.enter_context(fixtures._temporary(fixtures._open("service-v1.reservation", app)))
                held = fixtures._upload_signature(fence)
                need(held[0] == fixtures._upload_signature(app)[0]
                     and held[2] == stat.S_IFREG | 0o600 and held[3:6] == (fixtures.uid, fixtures.gid, 1)
                     and held[6] == root_reservation and held == fixtures._upload_named_signature(app, "service-v1.reservation"))
                total += held[6]
                service = stack.enter_context(fixtures._temporary(fixtures._open("service-v1", app, directory=True)))
                fixtures._named(app, "service-v1", service, 0o700)
                total += _files(fixtures, service, {"owner.lock": (0, 0), "reservation": (reservation, reservation),
                    "projects.state": (53, 1024 * 1024 + 52), "credential-references.state": (53, 1024 * 1024 + 52),
                    "version-allocations.state": (52, 52)})
                fixtures._named(app, "service-v1", service, 0o700)
                need(fixtures._upload_signature(fence) == held
                     and fixtures._upload_named_signature(app, "service-v1.reservation") == held,
                     "upload-key-state-reservation-changed")
        fixtures._roster(app, app_names, "upload-key-application-roster")
        fixtures._named(parent, "dev.mobile-release-kit.desktop", app, 0o700)
    fixtures.vault_completed.add(case)
    fixtures._vault_namespace_current()
    return {**source, "uploadKeyOutput": {"nativeFixtureRootObserved": True, "newEncryptedRecordPresent": generated,
        "referenceNamespacePresent": host_started, "privateContentsExported": False, "keychainInspectedByOwner": False,
        "retainedPrivateFileBytes": total, "retainedForDisposableAccountRetirement": True}}
