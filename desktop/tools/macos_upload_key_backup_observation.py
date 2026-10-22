"""Fixed generated-key backup comparison in the EXISTING installed fixture.

No commands, providers, credential bytes, report paths, or completion authority.
The native child performs the real backup/NEW/authentication/Bind; this leaf
checks only its returned DATA and a finite original private-file roster. All
FDs/close failures belong to the same Fixtures, not a second lifetime owner.
"""
from contextlib import ExitStack
import os
from pathlib import Path
import re
import stat


SCOPE = "upload-key-backup-roundtrip"
CASES = (SCOPE,)
CLI_SCOPE = "upload-key-backup-cli"
CLI_CASES = (CLI_SCOPE,)
APP = "dev.mobile-release-kit.desktop"
PARENTS = ("backup", "recovery", "restored")
RECORD_LIMIT = 248 + 4096 + 8 + 128 * 1024 + 64 * 1024
# This fixture exports one fixed generated JKS, not an arbitrary large asset.
BACKUP_LIMIT = 48 + 4 + 4096 + 8 + 128 * 1024 + 64 * 1024 + 16
CODE_BYTES = len(b"mrk-recovery-v1-") + 64
STATE_LIMIT = 1024 * 1024 + 52
TRUE_FIELDS = frozenset((
    "backendWithoutPickers repeatedCreateRefused backupCreated backupOriginalsPublishedJoined "
    "sourceVaultLocked restoredVaultOpenedEmpty restoredNewAuthenticated freshVaultAndRecord "
    "authenticatedStoredRead explicitlyBoundRestoredKey allOriginalsSettled finalDocumentEmpty"
).split())
FALSE_FIELDS = frozenset((
    "normalGenerationEnabled normalBackupEnabled automaticallyAssigned releaseSigningQualified "
    "physicalMacEvidence pickerUxVerified coldRestartVerified privateContentsExported"
).split())
REPORT_FIELDS = TRUE_FIELDS | FALSE_FIELDS | frozenset((
    "mechanism execution testResult initializeHelper storage generated restoredInitializeHelper "
    "restoredStorage originalCount rowRetirement"
).split())


def need(condition, label="upload-key-backup"):
    if not condition:
        raise ValueError(label)


def report(value, upload):
    """Comparison only: real helper/source/outer finality is checked separately."""
    need(type(value) is dict)
    if value.get("testResult") == "not-executed":
        # This is the unchanged before-generation missing-prerequisite path.
        # It never implies that any backup or restored vault exists.
        return upload.report(value, upload.CASES[0])
    need(value.keys() == REPORT_FIELDS
         and value["mechanism"] == "generated-upload-key-backup-v1"
         and value["execution"] == "executed" and value["testResult"] == "positive"
         and type(value["originalCount"]) is int and value["originalCount"] == 13
         and value["rowRetirement"] == "disposable-hosted-account-only")
    need(all(value[key] is True for key in TRUE_FIELDS)
         and all(value[key] is False for key in FALSE_FIELDS))
    need(all(type(value[key]) is dict for key in (
        "initializeHelper", "storage", "restoredInitializeHelper", "restoredStorage")))
    upload.positive(value["generated"])
    return value


def fixture_path(binding, native_home, *, case=SCOPE):
    """Compiled fixed Control ABI, not a path accepted from an output report."""
    need(case in (SCOPE, CLI_SCOPE))
    need(type(native_home) is str and native_home.startswith("/") and native_home != "/"
         and len(native_home.encode("utf-8")) <= 4096 and "\x00" not in native_home
         and all(part not in ("", ".", "..") for part in native_home.split("/")[1:]))
    need(type(binding.source) is str and re.fullmatch(r"[0-9a-f]{40}", binding.source)
         and all(type(v) is str and re.fullmatch(r"[1-9][0-9]{0,19}", v)
                 for v in (binding.run, binding.attempt)))
    return Path(native_home) / "Library/Application Support" / (
        f"mrk-macos-aqua-upload-key-{binding.source}-{binding.run}-{binding.attempt}-{case}") / case / APP


def _case(fixtures):
    need(fixtures.cases in (CASES, CLI_CASES), "upload-key-backup-case")
    return fixtures.cases[0]


def _original(fixtures):
    need(fixtures.cases in (CASES, CLI_CASES) and set(fixtures.upload_backup_parents) == set(PARENTS)
         and not fixtures.inflight and fixtures.close_errors == 0
         and fixtures.first_close_error is None, "upload-key-backup-original")


def prepare(fixtures):
    need(fixtures.cases in (CASES, CLI_CASES) and not fixtures.upload_backup_parents
         and not fixtures.upload_backup_entered and not fixtures.vault_completed
         and not fixtures.inflight, "upload-key-backup-prepare")
    parent = fixtures.vault_parents[_case(fixtures)]
    fixtures._roster(parent, (), "upload-key-backup-collision")
    for name in PARENTS:
        # The existing owner creates/retains these exact empty parents ONCE.
        # Native owners alone create both app/vaults and the two private files.
        fixtures.upload_backup_parents[name] = fixtures._mkdir(parent, name)


def namespace_current(fixtures):
    _original(fixtures)
    parent = fixtures.vault_parents[_case(fixtures)]
    fixtures._named(fixtures.vault_namespace, _case(fixtures), parent, 0o700)
    fixtures._roster(parent, (*PARENTS, APP) if _case(fixtures) in fixtures.vault_completed else PARENTS,
                     "upload-key-backup-case-roster")
    for name in PARENTS:
        fd = fixtures.upload_backup_parents[name]
        need(fd in fixtures.fds, "upload-key-backup-original-parent")
        fixtures._named(parent, name, fd, 0o700)


def before_call(fixtures):
    _original(fixtures)
    need(not fixtures.upload_backup_entered and not fixtures.vault_completed
         and not fixtures.last_returned, "upload-key-backup-reused")
    fixtures.upload_backup_entered = True  # Never rearm after any refusal.
    fixtures._vault_namespace_current()
    for fd in fixtures.upload_backup_parents.values():
        fixtures._roster(fd, (), "upload-key-backup-existing-output")


def _names(fixtures, directory):
    """Bounded four-name scan. No unbounded list or recursive adoption."""
    before = fixtures._upload_signature(directory)
    with fixtures._temporary(fixtures._open(".", directory, directory=True)) as reader:
        need(fixtures._upload_signature(reader) == before, "upload-key-backup-reader")
        iterator, primary = os.scandir(reader), None
        try:
            names = []
            for entry in iterator:
                need(len(names) < 4 and type(entry.name) is str and len(entry.name) <= 64
                     and entry.name not in names, "upload-key-backup-roster")
                names.append(entry.name)
            need(fixtures._upload_signature(directory) == before
                 and fixtures._upload_signature(reader) == before, "upload-key-backup-roster-changed")
            return tuple(sorted(names))
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                iterator.close()
            except BaseException as error:
                fixtures.close_errors += 1
                if fixtures.first_close_error is None:
                    fixtures.first_close_error = error
                if primary is None:
                    raise


def pair_names(backup, code):
    """Finite metadata roster, NOT backup authentication or pair custody."""
    need(type(backup) is tuple and type(code) is tuple and len(backup) == len(code) == 1)
    need(type(backup[0]) is str and type(code[0]) is str)
    left = re.fullmatch(r"mrk-backup-([0-9a-f]{32})\.mrkbackup", backup[0])
    right = re.fullmatch(r"mrk-recovery-([0-9a-f]{32})\.mrkcode", code[0])
    need(left is not None and right is not None and left[1] == right[1]
         and left[1] != "0" * 32, "upload-key-backup-pair-roster")
    return backup[0], code[0]


def _vault(fixtures, app, *, initialized, record, upload):
    with fixtures._temporary(fixtures._open("credential-vault-v1", app, directory=True)) as vault:
        fixtures._named(app, "credential-vault-v1", vault, 0o700)
        names = _names(fixtures, vault)
        records = [name for name in names if re.fullmatch(r"record-[0-9a-f]{32}", name)]
        need(len(records) == int(record)
             and (not record or initialized and records[0] != "record-" + "0" * 32),
             "upload-key-backup-singleton")
        expected = {"vault-lock": (0, 0), "initialization-reservation": (48, 48)}
        if initialized:
            expected["vault-header"] = (104, 104)
        if record:
            expected[records[0]] = (257, RECORD_LIMIT)
        total = upload._files(fixtures, vault, expected)
        key = fixtures._upload_named_signature(vault, records[0]) if record else None
        fixtures._named(app, "credential-vault-v1", vault, 0o700)
        return total, (records[0], key) if record else None


def _source(fixtures, initialized, generated, upload):
    parent = fixtures.vault_parents[_case(fixtures)]
    app_names = ("credential-vault-v1", "service-v1", "service-v1.reservation") if generated and _case(fixtures) == SCOPE else ("credential-vault-v1",)
    with fixtures._temporary(fixtures._open(APP, parent, directory=True)) as app:
        fixtures._named(parent, APP, app, 0o700)
        fixtures._roster(app, app_names, "upload-key-backup-source-roster")
        total, record = _vault(fixtures, app, initialized=initialized, record=generated, upload=upload)
        if generated and _case(fixtures) == SCOPE:
            # Same closed ordinary Host reference namespace as the producer;
            # no additional service is initialized in the restored vault.
            with ExitStack() as stack:
                fence = stack.enter_context(fixtures._temporary(fixtures._open("service-v1.reservation", app)))
                held = fixtures._upload_signature(fence)
                need(held[0] == fixtures._upload_signature(app)[0]
                     and held[2] == stat.S_IFREG | 0o600 and held[3:6] == (fixtures.uid, fixtures.gid, 1)
                     and held[6] == len(b"MRK service root v1\n") + 16
                     and held == fixtures._upload_named_signature(app, "service-v1.reservation"))
                total += held[6]
                service = stack.enter_context(fixtures._temporary(fixtures._open("service-v1", app, directory=True)))
                fixtures._named(app, "service-v1", service, 0o700)
                size = len(b"MRK application references v1\nprojects\ncredential-references\nversion-allocations\n")
                total += upload._files(fixtures, service, {"owner.lock": (0, 0), "reservation": (size, size),
                    "projects.state": (53, STATE_LIMIT), "credential-references.state": (53, STATE_LIMIT),
                    "version-allocations.state": (52, 52)})
                fixtures._named(app, "service-v1", service, 0o700)
                need(fixtures._upload_signature(fence) == held
                     and fixtures._upload_named_signature(app, "service-v1.reservation") == held)
        fixtures._roster(app, app_names, "upload-key-backup-source-roster")
        fixtures._named(parent, APP, app, 0o700)
        return total, record


def readback(fixtures, value, upload):
    report(value, upload)
    need(fixtures.cases == CASES)
    return _readback_records(fixtures, upload, executed=value["execution"] == "executed",
                             initialized=value["storage"]["header"] == [True, True])


def readback_cli(fixtures, value, upload, cli):
    cli.report(value)
    need(fixtures.cases == CLI_CASES)
    return _readback_records(fixtures, upload, executed=True, initialized=True)


def _readback_records(fixtures, upload, *, executed, initialized):
    _original(fixtures)
    need(fixtures.upload_backup_entered and fixtures.last_returned and not fixtures.vault_completed,
         "upload-key-backup-readback-order")
    source = fixtures.readback(_case(fixtures))  # Existing source-reader originals.
    total, original = _source(fixtures, initialized, executed, upload)
    for name in PARENTS:
        fixtures._named(fixtures.vault_parents[_case(fixtures)], name, fixtures.upload_backup_parents[name], 0o700)
    if executed:
        left, right = (fixtures.upload_backup_parents[name] for name in PARENTS[:2])
        backup_name, code_name = pair_names(_names(fixtures, left), _names(fixtures, right))
        total += upload._files(fixtures, left, {backup_name: (76, BACKUP_LIMIT)})
        total += upload._files(fixtures, right, {code_name: (CODE_BYTES, CODE_BYTES)})
        restored = fixtures.upload_backup_parents["restored"]
        fixtures._roster(restored, (APP,), "upload-key-backup-restored-parent")
        with fixtures._temporary(fixtures._open(APP, restored, directory=True)) as app:
            fixtures._named(restored, APP, app, 0o700)
            fixtures._roster(app, ("credential-vault-v1",), "upload-key-backup-restored-app")
            size, new = _vault(fixtures, app, initialized=True, record=True, upload=upload)
            need(original is not None and new is not None and new[0] != original[0]
                 and new[1][:2] != original[1][:2], "upload-key-backup-fresh-record")
            total += size
            fixtures._roster(app, ("credential-vault-v1",), "upload-key-backup-restored-app")
            fixtures._named(restored, APP, app, 0o700)
    else:
        for fd in fixtures.upload_backup_parents.values():
            fixtures._roster(fd, (), "upload-key-backup-unexecuted-output")
    need(fixtures.close_errors == 0 and fixtures.first_close_error is None,
         "upload-key-backup-close-unknown")
    fixtures.vault_completed.add(_case(fixtures))
    fixtures._vault_namespace_current()
    return {**source, "uploadKeyGeneratedBackup": {
        "nativeFixtureRootObserved": True, "privatePairMetadataObserved": executed,
        "freshEncryptedRecordPresent": executed, "retainedPrivateFileBytes": total,
        "privateContentsExported": False, "keychainInspectedByOwner": False,
        "pickerUxVerified": False, "coldRestartVerified": False,
        "retainedForDisposableAccountRetirement": True}}
