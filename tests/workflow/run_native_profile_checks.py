"""Fixed native/isolated gates. Missing required tooling/skipped tests are FAIL."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import subprocess
import sys
import unittest
import zipimport
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
PATTERNS = ("test_ios_profile_authority.py", "test_ios_profile_trust.py", "test_ios_profile_installation.py",
            "test_default_cancellation.py", "test_profile_processes.py", "test_macho_native.py",
            "test_native_process.py", "test_profile_process_owner.py", "test_inspection_budget.py")
PREREQUISITES = (
    ("openssl-version", ("/usr/bin/openssl", "version")),
    ("clang-discovery", ("/usr/bin/xcrun", "--find", "clang")),
    ("dsymutil-discovery", ("/usr/bin/xcrun", "--find", "dsymutil")),
    ("system-code", ("/usr/bin/codesign", "--verify", "--strict", "/usr/bin/true")),
)
DIAGNOSTIC_PREFIX = "MRK_NATIVE_DIAGNOSTIC="
MAX_DIAGNOSTIC_RECORDS = 16
MAX_DIAGNOSTIC_BYTES = 16 * 1024
RUNTIME_PREFIX = "MRK_NATIVE_PYTHON_RUNTIME="
POISON_PARTITIONS = (
    ("poison-wait-loss", "unit.test_native_process.NativeProcessLifecycleTests.test_native_consumed_wait_result_loss_never_retries_numeric_custody"),
    ("poison-startup-error", "unit.test_native_process.NativeProcessLifecycleTests.test_native_error_startup_is_unknown_not_a_wait_receipt"),
    ("poison-full-zero", "workflow.test_profile_processes.ProfileProcessTests.test_unknown_malformed_c_full_zero_retains_scratch"),
    ("poison-full-failure", "workflow.test_profile_processes.ProfileProcessTests.test_unknown_malformed_c_full_failure_retains_scratch"),
    ("poison-marker-parent-death", "workflow.test_profile_processes.ProfileProcessTests.test_unknown_marker_parent_death_requires_domain_disposal"),
    ("poison-committed-parent-death", "workflow.test_profile_processes.ProfileProcessTests.test_unknown_committed_parent_death_requires_domain_disposal"),
    ("poison-orphan", "workflow.test_profile_processes.ProfileProcessTests.test_killed_ancestor_cannot_strand_independent_native_worker_group"),
    ("poison-payload-writer-close-failure", "workflow.test_profile_processes.ProfileGroupCleanupTests.test_unknown_payload_writer_close_failure_retains_scratch"),
    ("poison-payload-reader-close-failure", "workflow.test_profile_processes.ProfileGroupCleanupTests.test_unknown_payload_reader_close_failure_retains_scratch"),
    ("poison-payload-reader-close-unresolved", "workflow.test_profile_processes.ProfileGroupCleanupTests.test_unknown_payload_reader_close_unresolved_retains_scratch"),
    ("poison-read-restored-int", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_read_restored_int"),
    ("poison-source-restored-int", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_restored_int"),
    ("poison-capture-restored-int", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_capture_restored_int"),
    ("poison-read-restored-term-fatal", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_read_restored_term_fatal"),
    ("poison-source-restored-term-fatal", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_restored_term_fatal"),
    ("poison-capture-restored-term-fatal", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_capture_restored_term_fatal"),
    ("poison-capture-control-close-failure", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_capture_control_close_failure"),
    ("poison-capture-status-close-failure", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_capture_status_close_failure"),
    ("poison-capture-payload-close-failure", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_capture_payload_close_failure"),
    ("poison-capture-payload-close-unresolved", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_capture_payload_close_unresolved"),
    ("poison-source-control-close-failure", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_control_close_failure"),
    ("poison-source-status-close-failure", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_status_close_failure"),
    ("poison-source-payload-close-failure", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_payload_close_failure"),
    ("poison-source-payload-close-unresolved", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_payload_close_unresolved"),
    ("poison-source-scratch-cleanup-failure", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_scratch_cleanup_failure"),
    ("poison-source-scratch-cleanup-unresolved", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_scratch_cleanup_unresolved"),
    ("poison-read-raw-close-before-completion", "unit.test_default_cancellation.ProfileResourceIOTests.test_unknown_read_raw_close_before_completion"),
    ("poison-read-raw-close-after-completion", "unit.test_default_cancellation.ProfileResourceIOTests.test_unknown_read_raw_close_after_completion"),
    ("poison-source-raw-close-before-completion", "unit.test_default_cancellation.ProfileResourceIOTests.test_unknown_source_raw_close_before_completion"),
    ("poison-source-raw-close-after-completion", "unit.test_default_cancellation.ProfileResourceIOTests.test_unknown_source_raw_close_after_completion"),
    ("poison-unpublished-scratch", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_attempted_unpublished_scratch_acquisition_retains_unknown_across_unwind_and_gc"),
    ("poison-directory-replacement", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_directory_replacement"),
    ("poison-symlink-replacement", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_symlink_replacement"),
    ("poison-unexpected-child", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_unexpected_child"),
    ("poison-keyboard-interrupt-cleanup-failure", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_keyboard_interrupt_cleanup_failure"),
    ("poison-keyboard-interrupt-restore-failure", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_keyboard_interrupt_restore_failure"),
    ("poison-keyboard-interrupt-cleanup-and-restore-failure", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_keyboard_interrupt_cleanup_and_restore_failure"),
    ("poison-system-exit-cleanup-failure", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_system_exit_cleanup_failure"),
    ("poison-system-exit-restore-failure", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_system_exit_restore_failure"),
    ("poison-system-exit-cleanup-and-restore-failure", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_system_exit_cleanup_and_restore_failure"),
)
ISOLATED_PROFILE_PRODUCTS = frozenset({
    "mobile_release", "mobile_release._native_process", "mobile_release._profile_process",
    "mobile_release.ios_profiles", "mobile_release.cancellation", "mobile_release.errors", "mobile_release.inspection",
})
ISOLATED_NEGATIVE_IMPORTS = (
    ("unit.test_native_process", ("unit",),
     frozenset({"unit", "unit.test_native_process"}),
     frozenset({"mobile_release", "mobile_release._native_process"})),
    ("workflow.test_profile_processes", ("workflow",),
     frozenset({"workflow", "workflow.test_profile_processes", "workflow.profile_process_fixture", "workflow.process_fixture"}),
     ISOLATED_PROFILE_PRODUCTS),
    ("unit.test_default_cancellation", ("workflow", "unit"),
     frozenset({"unit", "unit.test_default_cancellation", "workflow", "workflow.profile_resource_fixture",
                "workflow.profile_process_fixture", "workflow.process_fixture"}),
     ISOLATED_PROFILE_PRODUCTS),
)
AUTHORITY_UNIT_MODULES = frozenset({
    "unit", "unit.test_ios_profile_authority", "unit.ios_profile_helpers", "unit.ios_entitlement_helpers",
})
AUTHORITY_PRODUCT_MODULES = frozenset({
    "mobile_release", "mobile_release.cancellation", "mobile_release.ios_profiles",
    "mobile_release.ios_profile_auth", "mobile_release.ios_profile_trust",
    "mobile_release._native_process", "mobile_release._profile_process",
})


def _expected_native_ids(partition="all") -> tuple[str, ...]:
    """Reuse the fixed immutable source inventory, never import test modules.

    This gate already runs under the original outer command/aggregate deadline.
    Do not create another time budget just to collect optional failure metadata.
    """
    spec = importlib.util.spec_from_file_location(
        "_mrk_native_inventory", ROOT / ".github/scripts/ci_checks.py",
    )
    if spec is None or spec.loader is None:
        raise AssertionError("required fixed native inventory helper is missing")
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)  # Reviewed inert definitions, not a CLI entry point.
    if checks.NATIVE_PATTERNS != PATTERNS:
        raise AssertionError("required native patterns differ from their source authority")
    return checks.native_partition_ids(ROOT, partition)


def _authority_runtime() -> None:
    """Bind the selected CPython's stock isolated import environment.

    The owner already verified immutable provider/package bytes and ordinary
    modes. This child checks its actual runtime and origins, not a receipt from
    an earlier producer. In particular Python 3.11 -S does not initialize the
    venv's site machinery, so sys.prefix is not the selected package location.
    """
    flags = ("isolated", "ignore_environment", "no_user_site", "no_site", "safe_path", "dont_write_bytecode")
    if (sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 11)
            or any(getattr(sys.flags, flag, None) != 1 for flag in flags)
            or sys.dont_write_bytecode is not True):
        raise AssertionError("native authority requires the selected isolated Python 3.11 runtime")
    machinery = importlib.machinery
    if tuple(sys.meta_path) != (machinery.BuiltinImporter, machinery.FrozenImporter, machinery.PathFinder):
        raise AssertionError("native authority must not use custom meta import hooks")
    stock_hook = machinery.FileFinder.path_hook(
        (machinery.ExtensionFileLoader, machinery.EXTENSION_SUFFIXES),
        (machinery.SourceFileLoader, machinery.SOURCE_SUFFIXES),
        (machinery.SourcelessFileLoader, machinery.BYTECODE_SUFFIXES),
    )
    hooks = tuple(sys.path_hooks)
    if (len(hooks) != 2 or hooks[0] is not zipimport.zipimporter or type(hooks[1]) is not type(stock_hook)
            or hooks[1].__code__ is not stock_hook.__code__
            or tuple(cell.cell_contents for cell in hooks[1].__closure__ or ())
            != tuple(cell.cell_contents for cell in stock_hook.__closure__ or ())):
        raise AssertionError("native authority must not use custom path import hooks")
    base, executable_base = Path(sys.base_prefix), Path(sys.base_exec_prefix)
    standard_paths = (str(base / "lib/python311.zip"), str(base / "lib/python3.11"),
                      str(executable_base / "lib/python3.11/lib-dynload"))
    if not base.is_absolute() or not executable_base.is_absolute() or tuple(sys.path) != standard_paths:
        raise AssertionError("native authority module search must contain only the fixed standard library")
    if any(name in sys.modules for name in ("site", "sitecustomize", "usercustomize")):
        raise AssertionError("native authority must not initialize site or user hooks")
    for finder in sys.path_importer_cache.values():
        if finder is not None and type(finder) not in {machinery.FileFinder, zipimport.zipimporter}:
            raise AssertionError("native authority must not use cached custom import finders")


def _authority_package_root(installed_wheel) -> Path:
    _authority_runtime()
    work = ROOT.parent / "work"
    phase = "wheel" if installed_wheel else "source"
    if sys.executable != str(work / f"{phase}-venv/bin/python"):
        raise AssertionError("native authority interpreter differs from its selected phase")
    package = (work / "wheel-venv/lib/python3.11/site-packages/mobile_release" if installed_wheel
               else work / "source-build/src/mobile_release")
    for name in sys.modules:
        if name in {"mobile_release", "unit", "workflow"} or name.startswith(("mobile_release.", "unit.", "workflow.")):
            raise AssertionError("native authority package imports must have a fresh fixed owner")
    for directory in (package, ROOT / "tests/unit"):
        if str(directory) in sys.path_importer_cache:
            raise AssertionError("native authority package finder must not precede its fixed bootstrap")
    return package


def _check_module_origin(name, module, directory, *, package=False) -> None:
    suffix = name.split(".")[1:]
    expected = directory.joinpath(*suffix, "__init__.py") if package else directory.joinpath(*suffix).with_suffix(".py")
    spec = getattr(module, "__spec__", None)
    loader = getattr(spec, "loader", None)
    if (type(module) is not ModuleType or getattr(module, "__name__", None) != name
            or getattr(module, "__file__", None) != str(expected)
            or getattr(module, "__package__", None) != (name if package else name.rpartition(".")[0])
            or getattr(spec, "name", None) != name or getattr(spec, "origin", None) != str(expected)
            or type(loader) is not importlib.machinery.SourceFileLoader
            or getattr(module, "__loader__", None) is not loader
            or loader.name != name or loader.path != str(expected)):
        raise AssertionError("native authority imported a module outside its exact selected origin")
    if package:
        if (tuple(getattr(module, "__path__", ())) != (str(directory),)
                or tuple(spec.submodule_search_locations or ()) != (str(directory),)):
            raise AssertionError("native authority package search differs from its fixed root")
    elif hasattr(module, "__path__") or spec.submodule_search_locations is not None:
        raise AssertionError("native authority imported an unexpected nested package")


def _fixed_package(name, directory) -> None:
    # Never add a whole installed site-packages directory to sys.path. Loading
    # only this package also preserves ios_profiles.__file__, which the real
    # unchanged -I -S -B worker uses to select the same source/wheel package.
    if (name not in {"mobile_release", "unit", "workflow"}
            or any(key == name or key.startswith(name + ".") for key in sys.modules)):
        raise AssertionError("native fixed package already has an import owner")
    spec = importlib.util.spec_from_file_location(
        name, directory / "__init__.py", submodule_search_locations=[str(directory)],
    )
    if spec is None or type(spec.loader) is not importlib.machinery.SourceFileLoader:
        raise AssertionError("native fixed package loader is unavailable")
    module = importlib.util.module_from_spec(spec)
    _check_module_origin(name, module, directory, package=True)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        if sys.modules.get(name) is not module:
            raise AssertionError("native fixed package lost its import owner")
        _check_module_origin(name, module, directory, package=True)
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise


def _authority_origins(package, *, tests_loaded=False) -> None:
    _authority_runtime()
    required = AUTHORITY_PRODUCT_MODULES | (AUTHORITY_UNIT_MODULES if tests_loaded else {"unit"})
    if not required <= sys.modules.keys():
        raise AssertionError("native authority lost its fixed package imports")
    for name, module in tuple(sys.modules.items()):
        if name == "mobile_release" or name.startswith("mobile_release."):
            _check_module_origin(name, module, package, package=name == "mobile_release")
        elif name == "unit" or name.startswith("unit."):
            if name not in AUTHORITY_UNIT_MODULES:
                raise AssertionError("native authority imported an unrelated test module")
            _check_module_origin(name, module, ROOT / "tests/unit", package=name == "unit")
        elif name == "workflow" or name.startswith("workflow."):
            raise AssertionError("native authority imported an ordinary workflow test module")


def _selected_suite(expected):
    # The pure source authority supplies complete method IDs, not a load_tests
    # hook, wildcard, mutable caller selection or a class-wide permission.
    if (type(expected) is not tuple or not expected or any(type(item) is not str for item in expected)
            or tuple(sorted(set(expected))) != expected):
        raise AssertionError("native partition inventory is empty, duplicated or noncanonical")
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(expected)
    if loader.errors:
        raise AssertionError("required native partition could not load its exact methods")
    identifiers = []

    def inspect(tests):
        for test in tests:
            if isinstance(test, unittest.TestSuite):
                inspect(test)
            else:
                identifiers.append(test.id())

    inspect(suite)
    if tuple(sorted(identifiers)) != expected or suite.countTestCases() != len(expected):
        raise AssertionError("loaded native partition differs from its exact method inventory")
    return suite


def _product_modules():
    from mobile_release import _native_process, _profile_process, cancellation, ios_profile_auth, ios_profile_trust, ios_profiles
    return _native_process, _profile_process, cancellation, ios_profiles, ios_profile_auth, ios_profile_trust


def _ordinary_product_origins(installed_wheel: bool) -> None:
    """Bind both new owners and every loaded product module to this phase.

    This is not the native-authority runtime or an extra permission profile.
    The ordinary source/wheel capture retains its existing process boundary.
    """
    package = (ROOT.parent / "work/wheel-venv/lib/python3.11/site-packages/mobile_release" if installed_wheel
               else ROOT.parent / "work/source-build/src/mobile_release")
    if not AUTHORITY_PRODUCT_MODULES <= sys.modules.keys():
        raise AssertionError("ordinary native partition lost its required product closure")
    for name, module in tuple(sys.modules.items()):
        if name == "mobile_release" or name.startswith("mobile_release."):
            _check_module_origin(name, module, package, package=name == "mobile_release")


def _isolated_compatibility_runtime(minor: int) -> None:
    """Finite ordinary CPython lines; never broadens the 3.11 authority role."""
    if type(minor) is not int or minor not in {11, 12, 13, 14}:
        raise AssertionError("unsupported fixed compatibility runtime")
    flags = ("isolated", "ignore_environment", "no_user_site", "no_site", "safe_path", "dont_write_bytecode")
    if (sys.implementation.name != "cpython" or sys.version_info[:2] != (3, minor)
            or any(getattr(sys.flags, flag, None) != 1 for flag in flags)
            or sys.dont_write_bytecode is not True
            or sys.implementation.cache_tag != f"cpython-3{minor}"):
        raise AssertionError("compatibility requires its selected stock isolated CPython")
    machinery = importlib.machinery
    if tuple(sys.meta_path) != (machinery.BuiltinImporter, machinery.FrozenImporter, machinery.PathFinder):
        raise AssertionError("compatibility must not use custom meta import hooks")
    stock_hook = machinery.FileFinder.path_hook(
        (machinery.ExtensionFileLoader, machinery.EXTENSION_SUFFIXES),
        (machinery.SourceFileLoader, machinery.SOURCE_SUFFIXES),
        (machinery.SourcelessFileLoader, machinery.BYTECODE_SUFFIXES),
    )
    hooks = tuple(sys.path_hooks)
    if (len(hooks) != 2 or hooks[0] is not zipimport.zipimporter or type(hooks[1]) is not type(stock_hook)
            or hooks[1].__code__ is not stock_hook.__code__
            or tuple(cell.cell_contents for cell in hooks[1].__closure__ or ())
            != tuple(cell.cell_contents for cell in stock_hook.__closure__ or ())):
        raise AssertionError("compatibility must not use custom path import hooks")
    base, executable_base = Path(sys.base_prefix), Path(sys.base_exec_prefix)
    expected = (str(base / f"lib/python3{minor}.zip"), str(base / f"lib/python3.{minor}"),
                str(executable_base / f"lib/python3.{minor}/lib-dynload"))
    if (not base.is_absolute() or not executable_base.is_absolute() or tuple(sys.path) != expected
            or not Path(sys.executable).is_absolute() or Path(sys.executable).parent.name != "bin"
            or any(name in sys.modules for name in ("site", "sitecustomize", "usercustomize"))):
        raise AssertionError("compatibility runtime search/origin differs from its provider")
    if any(finder is not None and type(finder) not in {machinery.FileFinder, zipimport.zipimporter}
           for finder in sys.path_importer_cache.values()):
        raise AssertionError("compatibility must not use cached custom import finders")


def _compatibility_origins(minor: int, phase: str, package: Path) -> dict:
    _isolated_compatibility_runtime(minor)
    if not {"mobile_release", "mobile_release._native_process"} <= sys.modules.keys():
        raise AssertionError("compatibility lost its actual native primitive")
    origins = {}
    for name, module in tuple(sys.modules.items()):
        if name == "mobile_release" or name.startswith("mobile_release."):
            _check_module_origin(name, module, package, package=name == "mobile_release")
            origins[name] = module.__file__
        elif name == "unit" or name.startswith("unit."):
            _check_module_origin(name, module, ROOT / "tests/unit", package=name == "unit")
        elif name == "workflow" or name.startswith("workflow."):
            raise AssertionError("focused compatibility imported an unrelated workflow suite")
    return {
        "schema": "mrk-native-python-runtime-v1", "phase": phase,
        "implementation": sys.implementation.name, "version": list(sys.version_info[:3]),
        "executable": sys.executable, "base_prefix": sys.base_prefix,
        "base_exec_prefix": sys.base_exec_prefix, "prefix": sys.prefix, "exec_prefix": sys.exec_prefix,
        "isolated": True, "package_root": str(package), "origins": dict(sorted(origins.items())),
    }


def _emit_runtime(value, stream) -> None:
    line = RUNTIME_PREFIX + json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                                       allow_nan=False) + "\n"
    if len(line) > 64 * 1024 or stream.write(line) != len(line):
        raise AssertionError("native runtime observation could not be published")
    stream.flush()


def run_compatibility(*, minor: int, phase: str, operation: str) -> int:
    """Owner-fixed ordinary declaration/public-only/three-control entrypoints.

    These modes do not compile, install, alter sys.prefix, add site-packages or
    select a native trust role. The outside owner compares each declaration
    with its original frozen C capture BEFORE starting a control invocation.
    """
    if (type(phase) is not str or phase not in {"source", "wheel"}
            or type(operation) is not str or operation not in {"declaration", "public", "controls"}
            or operation == "public" and minor != 11 or operation == "controls" and minor == 11):
        raise AssertionError("compatibility arguments differ from fixed entrypoints")
    _isolated_compatibility_runtime(minor)
    if any(name in {"mobile_release", "unit", "workflow"}
           or name.startswith(("mobile_release.", "unit.", "workflow.")) for name in sys.modules):
        raise AssertionError("compatibility package imports require a fresh owner")
    package = (ROOT.parent / "work/source-build/src/mobile_release" if phase == "source"
               else ROOT.parent / "work/wheel-venv/lib/python3.11/site-packages/mobile_release")
    if minor == 11 and sys.executable != str(ROOT.parent / f"work/{phase}-venv/bin/python"):
        raise AssertionError("public ABI control interpreter differs from its selected phase")
    _fixed_package("mobile_release", package)
    native = importlib.import_module("mobile_release._native_process")
    before = _compatibility_origins(minor, phase, package)
    if operation == "declaration":
        # No acquisition-specific C bindings or POSIX controls: ctypes may
        # initialize its default Python-API handle. This declaration belongs
        # only to the controller's original ordinary admitted capture.
        record = json.dumps(native.declared_abi(), sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True, allow_nan=False) + "\n"
        if not 0 < len(record) <= 8192 or sys.stdout.write(record) != len(record):
            raise AssertionError("native ABI declaration could not be published")
        sys.stdout.flush()
        after = _compatibility_origins(minor, phase, package)
        if after != before:
            raise AssertionError("native declaration changed runtime/module ownership")
        _emit_runtime(after, sys.stderr)
        return 0
    spec = importlib.util.spec_from_file_location("_mrk_compatibility_inventory", ROOT / ".github/scripts/ci_checks.py")
    if spec is None or spec.loader is None:
        raise AssertionError("fixed compatibility inventory is unavailable")
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)  # Reviewed inert source inventory, no CLI/native acquisition.
    expected = checks.native_compatibility_ids(ROOT, public_only=operation == "public")
    _fixed_package("unit", ROOT / "tests/unit")
    suite = _selected_suite(expected)
    _compatibility_origins(minor, phase, package)
    state = {"failed": False, "records": []}
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, failfast=True, descriptions=False,
                                    resultclass=_result_class(expected, state)).run(suite)
    after = _compatibility_origins(minor, phase, package)
    _emit_runtime(after, sys.stdout)
    if not result.wasSuccessful() or result.skipped or state["failed"] or result.testsRun != len(expected):
        if state["records"]:
            _publish_failure("tests", state["records"])
        return 1
    return 0


def _isolated_negative_contract(partition: str) -> tuple:
    """Only the literal singleton's fixed module family can own its bootstrap."""
    if type(partition) is not str or partition not in dict(POISON_PARTITIONS):
        raise AssertionError("isolated negative differs from its fixed entrypoint")
    identifier = dict(POISON_PARTITIONS)[partition]
    matches = [row for row in ISOLATED_NEGATIVE_IMPORTS if row[0] == identifier.rsplit(".", 2)[0]]
    if len(matches) != 1:
        raise AssertionError("isolated negative lacks its fixed module family")
    _module, packages, test_modules, product_modules = matches[0]
    return identifier, packages, test_modules, product_modules


def _isolated_negative_origins(partition: str, phase: str, package: Path) -> dict:
    """Measure only this literal family's origins, before its single proof.

    This is separate from compatibility/authority loaders: admitting the two
    profile fixture families never admits workflow imports to primitive2.
    """
    _isolated_compatibility_runtime(11)
    _identifier, _packages, test_modules, product_modules = _isolated_negative_contract(partition)
    if (type(phase) is not str or phase not in {"source", "wheel"}
            or sys.executable != str(ROOT.parent / f"work/{phase}-venv/bin/python")
            or package != (ROOT.parent / "work/source-build/src/mobile_release" if phase == "source"
                           else ROOT.parent / "work/wheel-venv/lib/python3.11/site-packages/mobile_release")):
        raise AssertionError("isolated negative origin phase differs from its fixed root")
    required = test_modules | product_modules
    loaded = {name for name in sys.modules if name in {"mobile_release", "unit", "workflow"}
              or name.startswith(("mobile_release.", "unit.", "workflow."))}
    if loaded != required:
        raise AssertionError("isolated negative imports differ from its fixed family")
    origins = {}
    for name in sorted(required):
        product = name in product_modules
        directory = package if product else ROOT / "tests" / name.partition(".")[0]
        module = sys.modules[name]
        _check_module_origin(name, module, directory, package="." not in name)
        if product:
            origins[name] = module.__file__
    return {
        "schema": "mrk-native-python-runtime-v1", "phase": phase,
        "implementation": sys.implementation.name, "version": list(sys.version_info[:3]),
        "executable": sys.executable, "base_prefix": sys.base_prefix,
        "base_exec_prefix": sys.base_exec_prefix, "prefix": sys.prefix, "exec_prefix": sys.exec_prefix,
        "isolated": True, "package_root": str(package), "origins": origins,
    }


def _isolated_reporting_bindings(partition: str) -> tuple:
    """In-memory ownership only: no import, path resolution or new native owner.

    A poison proof may leave uncertain resources rooted. After it returns, the
    runner only compares these pre-owned bindings and reports through its
    inherited streams; it must not acquire a replacement fixture or file owner.
    """
    _identifier, _packages, test_modules, product_modules = _isolated_negative_contract(partition)
    required = test_modules | product_modules
    loaded = {name for name in sys.modules if name in {"mobile_release", "unit", "workflow"}
              or name.startswith(("mobile_release.", "unit.", "workflow."))}
    if loaded != required:
        raise AssertionError("isolated negative module bindings differ from its fixed family")
    bindings = []
    for name, module in tuple(sys.modules.items()):
        if name in required:
            if type(module) is not ModuleType:
                raise AssertionError("isolated negative lost an original module binding")
            values = module.__dict__
            spec = values.get("__spec__")
            if type(spec) is not importlib.machinery.ModuleSpec or type(spec.loader) is not importlib.machinery.SourceFileLoader:
                raise AssertionError("isolated negative lost its original source loader")
            bindings.append((name, module, spec, spec.loader, id(module), id(spec), id(spec.loader),
                             values.get("__name__"), values.get("__package__"), values.get("__file__"),
                             id(values.get("__loader__")), spec.name, spec.origin, spec.loader.name, spec.loader.path,
                             tuple(values.get("__path__", ())),
                             None if spec.submodule_search_locations is None else tuple(spec.submodule_search_locations)))
    if {row[0] for row in bindings} != required:
        raise AssertionError("isolated negative module binding count differs")
    return (tuple(sorted(bindings)), tuple(sys.path), tuple(sys.meta_path), tuple(sys.path_hooks),
            sys.executable, sys.base_prefix, sys.base_exec_prefix, sys.prefix, sys.exec_prefix,
            sys.stdout, id(sys.stdout), sys.stderr, id(sys.stderr))


def run_isolated_negative(*, partition: str, phase: str) -> int:
    """One fixed intentional-UNKNOWN method; fresh ordinary Session owns disposal."""
    if (type(partition) is not str or partition not in dict(POISON_PARTITIONS)
            or type(phase) is not str or phase not in {"source", "wheel"}):
        raise AssertionError("isolated negative differs from its fixed entrypoint")
    _isolated_compatibility_runtime(11)
    if (sys.platform not in {"linux", "darwin"}
            or sys.executable != str(ROOT.parent / f"work/{phase}-venv/bin/python")
            or any(name in {"mobile_release", "unit", "workflow"}
                   or name.startswith(("mobile_release.", "unit.", "workflow.")) for name in sys.modules)):
        raise AssertionError("isolated negative requires its original fresh phase interpreter")
    package = (ROOT.parent / "work/source-build/src/mobile_release" if phase == "source"
               else ROOT.parent / "work/wheel-venv/lib/python3.11/site-packages/mobile_release")
    identifier, packages, _test_modules, _products = _isolated_negative_contract(partition)
    expected = _expected_native_ids(partition)
    if expected != (identifier,):
        raise AssertionError("isolated negative source inventory is not its literal singleton")
    _fixed_package("mobile_release", package)
    importlib.import_module("mobile_release._native_process")
    for name in packages:
        _fixed_package(name, ROOT / "tests" / name)
    suite = _selected_suite(expected)
    metadata = _isolated_negative_origins(partition, phase, package)
    bindings = _isolated_reporting_bindings(partition)
    state = {"failed": False, "records": []}
    try:
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, failfast=True, descriptions=False,
                                        resultclass=_result_class(expected, state)).run(suite)
        # Only pre-owned, in-memory reporting follows the proof. In particular
        # do not call an origin checker that resolves paths or import new code.
        if _isolated_reporting_bindings(partition) != bindings:
            raise AssertionError("isolated negative changed its pre-owned reporting bindings")
        success = result.wasSuccessful() and not result.skipped and not state["failed"] and result.testsRun == 1
        _emit_runtime(metadata, sys.stdout)
    except BaseException as error:
        if state["failed"]:
            _publish_failure("tests", state["records"], error)
        raise
    if not success:
        _publish_failure("tests", state["records"])
    return 0 if success else 1


def _diagnostic_ids(expected) -> frozenset[str]:
    classes = {identifier.rsplit(".", 1)[0] for identifier in expected}
    modules = {identifier.rsplit(".", 2)[0] for identifier in expected}
    return frozenset(expected) | frozenset(
        f"{operation} ({name})" for operations, names in (
            (("setUpClass", "tearDownClass"), classes), (("setUpModule", "tearDownModule"), modules),
        ) for operation in operations for name in names
    )


def _failure_record(identifier: str, outcome: str, error: BaseException | None) -> dict:
    """Finite observations from the actual exception, never args or display text."""
    category, number, returncode = "none", None, None
    if error is not None:
        if isinstance(error, subprocess.CalledProcessError):
            category = "nonzero-exit"
            observed = error.returncode
            if type(observed) is int and -255 <= observed <= 255 and observed != 0:
                returncode = observed
        elif isinstance(error, subprocess.TimeoutExpired):
            category = "timeout"
        elif isinstance(error, OSError):
            category = "os-error"
            observed = error.errno
            if type(observed) is int and 0 < observed < 4096:
                number = observed
        else:
            for kind, label in ((AssertionError, "assertion-error"), (ValueError, "value-error"),
                                (TypeError, "type-error"), (MemoryError, "memory-error"),
                                (Exception, "exception"), (BaseException, "base-exception")):
                if isinstance(error, kind):
                    category = label
                    break
    return {"id": identifier, "outcome": outcome, "category": category, "errno": number, "returncode": returncode}


def _emit_diagnostic(phase: str, records: list[dict]) -> None:
    if phase not in {"prerequisite", "tests"} or not 1 <= len(records) <= MAX_DIAGNOSTIC_RECORDS:
        raise AssertionError("native diagnostic contract differs")
    envelope = {"schema": 1, "phase": phase, "records": records}
    # A prerequisite's inherited stderr may end in a partial line. Keep the
    # one diagnostic envelope framed without capturing or replaying that text.
    line = "\n" + DIAGNOSTIC_PREFIX + json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                                               ensure_ascii=True, allow_nan=False) + "\n"
    if len(line.encode("ascii")) > MAX_DIAGNOSTIC_BYTES:
        raise AssertionError("native diagnostic exceeds its fixed bound")
    written = sys.stderr.write(line)
    if type(written) is not int or written != len(line):
        raise OSError("native diagnostic write was incomplete")
    sys.stderr.flush()


def _publish_failure(phase: str, records: list[dict], original: BaseException | None = None) -> None:
    # Only call after failure is established. There is one attempt, no fallback
    # stream/retry, and a broken diagnostic can never turn this into success.
    if not records:
        return  # Unknown/unavailable attribution is not a fabricated record.
    try:
        _emit_diagnostic(phase, records)
    except BaseException as publication:
        if original is None and not isinstance(publication, Exception):
            raise  # Preserve an interruption when no earlier raised error owns it.
        if original is not None:
            try:
                original.add_note("Native failure diagnostic publication failed")
            except BaseException:
                pass  # Never replace the original prerequisite/interruption.


def _result_class(expected, state):
    allowed = _diagnostic_ids(expected)

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            if state["failed"]:
                self.stop()
                raise AssertionError("a native adverse callback prohibits a later test")
            super().startTest(test)

        def record_native(self, test, outcome, error=None):
            state["failed"] = True
            self.stop()
            if len(state["records"]) >= MAX_DIAGNOSTIC_RECORDS:
                return
            try:
                identifier = getattr(test, "test_case", test).id()
                if type(identifier) is not str or identifier not in allowed or len(identifier) > 512:
                    return
                exception = error[1] if error is not None else None
                state["records"].append(_failure_record(identifier, outcome, exception))
            except Exception:
                # The actual adverse callback already latches failure. A
                # superclass reporting error can precede its base storage
                # (addSubTest), so attribution never assumes that append.
                # Optional attribution failure must not retry the callback.
                # BaseException interruptions still propagate to run().
                return

        def super_then_record(self, method, arguments, test, outcome, error=None):
            # Latch before the superclass can fail while reporting or omit its
            # own storage. Skip/expected-failure callbacks must also stop reuse.
            state["failed"] = True
            self.stop()
            try:
                method(*arguments)
            except BaseException:
                # TextTestResult can fail while reporting before or after base
                # storage. Attribute the actual callback either way, but
                # re-raise the very same reporting failure.
                try:
                    self.record_native(test, outcome, error)
                except BaseException:
                    pass
                raise
            self.record_native(test, outcome, error)

        def addError(self, test, error):
            self.super_then_record(super().addError, (test, error), test, "error", error)

        def addFailure(self, test, error):
            self.super_then_record(super().addFailure, (test, error), test, "failure", error)

        def addSkip(self, test, reason):
            self.super_then_record(super().addSkip, (test, reason), test, "skip")

        def addExpectedFailure(self, test, error):
            self.super_then_record(super().addExpectedFailure, (test, error), test, "expected-failure", error)

        def addUnexpectedSuccess(self, test):
            self.super_then_record(super().addUnexpectedSuccess, (test,), test, "unexpected-success")

        def addSubTest(self, test, subtest, error):
            if error is None:
                super().addSubTest(test, subtest, error)
            else:
                outcome = "failure" if issubclass(error[0], test.failureException) else "error"
                self.super_then_record(super().addSubTest, (test, subtest, error), test, outcome, error)

    return Result


def run(*, installed_wheel=False, partition="all") -> int:
    if type(installed_wheel) is not bool or type(partition) is not str or partition not in {"all", "authority", "ordinary"}:
        raise AssertionError("native partition arguments differ from the fixed entrypoints")
    if sys.platform != "darwin":
        print("FAIL: required native Apple profile verification needs macOS", file=sys.stderr)
        return 1
    package = _authority_package_root(installed_wheel) if partition == "authority" else None
    # Check each tool before its consumers in the fixed partition, not as a
    # fallback after failure. Standalone all retains the original command order.
    prerequisites = {
        "all": PREREQUISITES,
        "authority": (PREREQUISITES[0], PREREQUISITES[3]),
        "ordinary": PREREQUISITES[1:3],
    }[partition]
    for role, command in prerequisites:
        try:
            subprocess.run(command, stdin=subprocess.DEVNULL, check=True, timeout=30)
        except BaseException as error:
            try:
                records = [_failure_record(role, "error", error)]
            except BaseException:
                records = []
            _publish_failure("prerequisite", records, error)
            raise
    expected = _expected_native_ids(partition)
    if partition == "all" and any(identifier in expected for _name, identifier in POISON_PARTITIONS):
        raise AssertionError("mixed native discovery requires the original healthy and singleton Session captures")
    if package is not None:
        _fixed_package("mobile_release", package)
    if partition != "all":
        _fixed_package("unit", ROOT / "tests/unit")
    if partition == "ordinary":
        # The native inventory also contains workflow.test_profile_processes;
        # default-cancellation imports its real workflow resource fixtures.
        # Neither package is added to the authority role's import closure.
        _fixed_package("workflow", ROOT / "tests/workflow")
    modules = _product_modules()
    if package is not None:
        _authority_origins(package)
    elif partition == "ordinary":
        _ordinary_product_origins(installed_wheel)
    if installed_wheel:
        for module in modules:
            if Path(module.__file__).resolve().is_relative_to(ROOT):
                raise AssertionError("wheel test imported the repository instead of the installed package")
    if installed_wheel or package is not None:
        modules[-1].apple_roots()  # Actual independent resource pins; no native trust seam.
    if partition == "all":
        suite = unittest.TestSuite()
        for pattern in PATTERNS:
            tests = unittest.TestLoader().discover(str(ROOT / "tests"), pattern=pattern)
            if tests.countTestCases() == 0:
                raise AssertionError(f"required native test group is empty: {pattern}")
            suite.addTests(tests)
    else:
        suite = _selected_suite(expected)
    if package is not None:
        _authority_origins(package, tests_loaded=True)
    elif partition == "ordinary":
        _ordinary_product_origins(installed_wheel)
    state = {"failed": False, "records": []}
    try:
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, failfast=True, descriptions=False,
                                         resultclass=_result_class(expected, state)).run(suite)
        if result.skipped:
            print("FAIL: required native verification must not contain skipped tests", file=sys.stderr)
        success = result.wasSuccessful() and not result.skipped and not state["failed"] and result.testsRun == len(expected)
        if success and package is not None:
            _authority_origins(package, tests_loaded=True)
        elif success and partition == "ordinary":
            _ordinary_product_origins(installed_wheel)
    except BaseException as error:
        if state["failed"]:
            _publish_failure("tests", state["records"], error)
        raise
    if not success:
        _publish_failure("tests", state["records"])
    return 0 if success else 1


def main(arguments) -> int:
    # Owner-fixed phase forms only; no caller-provided IDs, paths or role flags.
    forms = {
        (): ("all", False), ("--installed-wheel",): ("all", True),
        ("--authority",): ("authority", False), ("--authority", "--installed-wheel"): ("authority", True),
        ("--ordinary",): ("ordinary", False), ("--ordinary", "--installed-wheel"): ("ordinary", True),
    }
    if type(arguments) not in {list, tuple} or any(type(argument) is not str for argument in arguments):
        raise SystemExit("usage: run_native_profile_checks.py [--authority|--ordinary] [--installed-wheel]")
    isolated = {(f"--{partition}-{phase}",): (partition, phase)
                for partition, _identifier in POISON_PARTITIONS for phase in ("source", "wheel")}
    poison = isolated.get(tuple(arguments))
    if poison is not None:
        partition, phase = poison
        return run_isolated_negative(partition=partition, phase=phase)
    compatibility = {
        (f"--abi-3{minor}-{phase}",): (minor, phase, "declaration")
        for minor in (11, 12, 13, 14) for phase in ("source", "wheel")
    }
    compatibility.update({(f"--public-311-{phase}",): (11, phase, "public") for phase in ("source", "wheel")})
    compatibility.update({
        (f"--compat-3{minor}-{phase}",): (minor, phase, "controls")
        for minor in (12, 13, 14) for phase in ("source", "wheel")
    })
    ordinary = compatibility.get(tuple(arguments))
    if ordinary is not None:
        minor, phase, operation = ordinary
        return run_compatibility(minor=minor, phase=phase, operation=operation)
    selected = forms.get(tuple(arguments))
    if selected is None:
        raise SystemExit("usage: run_native_profile_checks.py [--authority|--ordinary] [--installed-wheel]")
    partition, installed_wheel = selected
    return run(partition=partition, installed_wheel=installed_wheel)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
