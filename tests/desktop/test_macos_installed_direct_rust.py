"""Bounded Bash/stub controls only; no Rust, network or Mac admission runs."""
from pathlib import Path
import ast
import re
import shlex
import stat
import subprocess
import tempfile
import unittest
from types import SimpleNamespace


SOURCE = Path(__file__).absolute().parents[2] / "desktop/tools/macos_installed_direct_rust.sh"
TARGETS = (("aarch64-apple-darwin", "1.98.1", "/opt/homebrew"),
           ("x86_64-apple-darwin", "1.98.0", "/usr/local"))
MARKER = '"$MRK_PYTHON" -I -S -B - <<\'PY_DIRECT_RUST\'\n'


class InstalledRustBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="mrk-rustup-shell-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.home = self.root / "Users/runner"
        self.home.mkdir(parents=True)
        self.cargo = self.home / ".cargo"
        self.legacy = self.cargo / "bin/rustup"
        self.source = SOURCE.read_text(encoding="utf-8")
        self.assertEqual(self.source.count(MARKER), 1)
        self.prefix = self.source.split(MARKER, 1)[0]
        # Map only fixed filesystem roots into our disposable regular fixtures.
        # Never execute the Python/native admission or a real rustup binary.
        for fixed in ("/Users/runner", "/opt/homebrew", "/usr/local"):
            self.prefix = self.prefix.replace(fixed, str(self.root) + fixed)

    def packaged(self, prefix):
        return self.root / prefix.lstrip("/") / "opt/rustup/bin/rustup"

    def stub(self, path, label, status=0):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "#!/bin/bash\nset -euo pipefail\n"
            + "printf '%s\\n' " + shlex.quote("CALL:" + label) + " \"$@\"\n"
            + "printf '%s\\n' \"PATH=$PATH\" \"HOME=$HOME\" \"CARGO_HOME=$CARGO_HOME\" \"RUSTUP_HOME=$RUSTUP_HOME\"\n"
            + "printf '%s\\n' \"POISON=${MRK_TEST_POISON-unset}\" \"TOOLCHAIN=${RUSTUP_TOOLCHAIN-unset}\"\n"
            + "if [[ -e \"$CARGO_HOME\" || -L \"$CARGO_HOME\" ]]; then echo cargo-present; else echo cargo-absent; fi\n"
            + "exit " + str(status) + "\n", encoding="utf-8")
        path.chmod(0o700)

    def run_prefix(self, target, release, *, mkdir_failure=False):
        prefix = self.prefix
        if mkdir_failure:
            stub = self.root / "mkdir-stub"
            stub.write_text("#!/bin/bash\nprintf '%s\\n' MKDIR \"$@\"\nexit 43\n", encoding="utf-8")
            stub.chmod(0o700)
            self.assertEqual(prefix.count("/bin/mkdir"), 1)
            prefix = prefix.replace("/bin/mkdir", shlex.quote(str(stub)))
        result = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-c", prefix + "\nprintf 'NEXT\\n'\n"],
            env={"PATH": str(self.root / "ambient"), "HOME": "/ambient-home",
                 "CARGO_HOME": "/ambient-cargo", "RUSTUP_HOME": "/ambient-rustup",
                 "MRK_TEST_POISON": "must-not-reach-rustup",
                 "MRK_MACOS_TARGET": target, "RUSTUP_TOOLCHAIN": release},
            cwd=self.root, capture_output=True, text=True, timeout=5, check=False)
        self.assertLess(len(result.stdout) + len(result.stderr), 4096)
        return result

    def expected_call(self, label, release, cargo_state):
        return ["CALL:" + label, "toolchain", "install", release,
                "--profile", "minimal", "--no-self-update",
                "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + str(self.home),
                "CARGO_HOME=" + str(self.cargo), "RUSTUP_HOME=" + str(self.home / ".rustup"),
                "POISON=unset", "TOOLCHAIN=unset", cargo_state]

    def identity(self, path):
        info = path.lstat()
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def test_legacy_launcher_has_priority_for_both_targets(self):
        self.stub(self.legacy, "legacy")
        for target, release, prefix in TARGETS:
            with self.subTest(target=target):
                self.stub(self.packaged(prefix), "unused-packaged")
                before = self.identity(self.cargo)
                result = self.run_prefix(target, release)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), self.expected_call("legacy", release, "cargo-present") + ["NEXT"])
                self.assertEqual(self.identity(self.cargo), before)

    def test_packaged_launchers_create_only_missing_cargo_home_after_return(self):
        for target, release, prefix in TARGETS:
            with self.subTest(target=target):
                self.stub(self.packaged(prefix), target)
                self.assertFalse(self.cargo.exists())
                result = self.run_prefix(target, release)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), self.expected_call(target, release, "cargo-absent") + ["NEXT"])
                self.assertEqual(stat.S_IMODE(self.cargo.stat().st_mode), 0o700)
                self.assertEqual(list(self.cargo.iterdir()), [])
                self.cargo.rmdir()

    def test_missing_or_other_architecture_and_ambient_launchers_refuse(self):
        for target, release, prefix in TARGETS:
            with self.subTest(target=target):
                other = "/usr/local" if prefix == "/opt/homebrew" else "/opt/homebrew"
                unused = self.packaged(other)
                self.stub(unused, "wrong-architecture")
                self.stub(self.root / "ambient/rustup", "ambient")
                result = self.run_prefix(target, release)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "Pinned Mac Rust bootstrap unavailable\n")
                self.assertFalse(self.cargo.exists())
                unused.unlink()

    def test_present_unusable_legacy_is_not_fallback_authority(self):
        self.legacy.parent.mkdir(parents=True)
        self.stub(self.packaged("/opt/homebrew"), "unused-packaged")
        for shape in ("file", "directory", "broken-link"):
            with self.subTest(shape=shape):
                if shape == "file":
                    self.legacy.write_text("inert nonexecutable", encoding="utf-8")
                    self.legacy.chmod(0o600)
                elif shape == "directory":
                    self.legacy.mkdir()
                else:
                    self.legacy.symlink_to(self.root / "missing")
                before = self.identity(self.legacy)
                result = self.run_prefix("aarch64-apple-darwin", "1.98.1")
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "Pinned Mac Rust bootstrap unavailable\n")
                self.assertEqual(self.identity(self.legacy), before)
                self.legacy.rmdir() if shape == "directory" else self.legacy.unlink()

    def test_unsupported_target_or_pin_stops_before_bootstrap(self):
        self.stub(self.legacy, "must-not-run")
        for target, release in (("arm64", "1.98.1"), ("", "1.98.1"),
                                ("aarch64-apple-darwin", "1.98.0"),
                                ("x86_64-apple-darwin", "1.98.1"),
                                ("aarch64-apple-darwin", "stable"),
                                ("aarch64-apple-darwin\n", "1.98.1")):
            with self.subTest(target=target, release=release):
                result = self.run_prefix(target, release)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "Unsupported pinned Mac compiler selection\n")

    def test_original_bootstrap_failure_stops_without_retry_or_mkdir(self):
        for target, release, prefix in TARGETS:
            with self.subTest(target=target):
                self.stub(self.packaged(prefix), target, status=42)
                result = self.run_prefix(target, release)
                self.assertEqual(result.returncode, 42)
                self.assertEqual(result.stdout.splitlines(), self.expected_call(target, release, "cargo-absent"))
                self.assertFalse(self.cargo.exists())
        self.stub(self.legacy, "legacy", status=42)
        self.stub(self.packaged("/opt/homebrew"), "must-not-retry")
        result = self.run_prefix("aarch64-apple-darwin", "1.98.1")
        self.assertEqual(result.returncode, 42)
        self.assertEqual(result.stdout.splitlines(), self.expected_call("legacy", "1.98.1", "cargo-present"))

    def test_existing_cargo_entries_are_untouched_before_python_admission(self):
        # Malformed entries remain for the unchanged Python no-follow refusal;
        # reaching NEXT in this shell-only seam is not compiler admission.
        self.stub(self.packaged("/opt/homebrew"), "packaged")
        for shape in ("directory", "file", "broken-link"):
            with self.subTest(shape=shape):
                if shape == "directory":
                    self.cargo.mkdir(mode=0o750)
                elif shape == "file":
                    self.cargo.write_bytes(b"unchanged inert cargo entry")
                else:
                    self.cargo.symlink_to(self.root / "missing")
                before = self.identity(self.cargo)
                result = self.run_prefix("aarch64-apple-darwin", "1.98.1")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), self.expected_call("packaged", "1.98.1", "cargo-present") + ["NEXT"])
                self.assertEqual(self.identity(self.cargo), before)
                self.cargo.rmdir() if shape == "directory" else self.cargo.unlink()

    def test_mkdir_failure_stops_before_python_admission(self):
        self.stub(self.packaged("/opt/homebrew"), "packaged")
        result = self.run_prefix("aarch64-apple-darwin", "1.98.1", mkdir_failure=True)
        self.assertEqual(result.returncode, 43)
        self.assertEqual(result.stdout.splitlines(), self.expected_call("packaged", "1.98.1", "cargo-absent")
                         + ["MKDIR", "-m", "700", str(self.cargo)])
        self.assertFalse(self.cargo.exists())


class InstalledRustToolHealthTests(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE.read_text(encoding="utf-8")
        body = self.source.split(MARKER, 1)[1].split("\nPY_DIRECT_RUST", 1)[0]
        self.parsed = ast.parse(body)
        functions = [node for node in self.parsed.body if isinstance(node, ast.FunctionDef)
                     and node.name in ("need", "objcopy_version")]
        self.assertEqual([node.name for node in functions], ["need", "objcopy_version"])
        self.namespace = {"re": re, "subprocess": subprocess}
        exec(compile(ast.Module(body=functions, type_ignores=[]), "<fixed-tool-health-functions>", "exec"), self.namespace)
        original = next(node for node in self.parsed.body if isinstance(node, ast.Try))
        start = next(index for index, node in enumerate(original.body) if isinstance(node, ast.Assign)
                     and isinstance(node.value, ast.Constant) and node.value.value == "objcopy-version")
        # Only the actual health-query statements and inert owner doubles run.
        self.health = compile(ast.Module(body=original.body[start:], type_ignores=[]), "<fixed-tool-health-query>", "exec")

    def version(self, release="1.98.1"):
        return ("llvm-objcopy, compatible with GNU objcopy\nLLVM (http://llvm.org/):\n"
                "  LLVM version 22.1.8-rust-" + release + "-stable\n  Optimized build.\n").encode()

    def test_objcopy_version_refuses_wrong_tool_release_or_unbounded_output(self):
        check = self.namespace["objcopy_version"]
        for _, release, _ in TARGETS:
            self.assertTrue(check(self.version(release), release))
            for body in (b"", self.version("9.9.9"), self.version(release).replace(b"llvm-objcopy", b"llvm-strip"),
                         self.version(release) + b"unexpected\n", self.version(release).replace(b"stable", b"nightly"),
                         b"x" * 4097, b"\xff", self.version(release).decode(), None):
                with self.subTest(release=release, bodyType=type(body)):
                    self.assertFalse(check(body, release))

    def test_original_health_return_and_custody_failures_never_retry(self):
        path = Path("/fixed/1.98.1-aarch64-apple-darwin/lib/rustlib/aarch64-apple-darwin/bin/rust-objcopy")
        for case in ("ok", "abort", "stderr", "wrong-version", "wrong-argv", "bool-status", "oversized", "unknown", "changed"):
            with self.subTest(case=case):
                calls, checks = [], []
                environment = {"DYLD_FALLBACK_LIBRARY_PATH": "/fixed/1.98.1-aarch64-apple-darwin/lib"}
                def current():
                    checks.append(True)
                    if case == "changed" and len(checks) == 2:
                        raise ValueError("direct-rust-original-changed")
                def owned(argv, **options):
                    calls.append((argv, options))
                    self.assertEqual(argv, [str(path), "--version"])
                    self.assertIs(options["environ"], environment)
                    self.assertEqual({key: options[key] for key in ("timeout", "capture", "text", "output_limit")},
                                     {"timeout": 15, "capture": True, "text": False, "output_limit": 4096})
                    if case == "unknown":
                        raise RuntimeError("inert original unreturned")
                    return subprocess.CompletedProcess(["wrong"] if case == "wrong-argv" else argv,
                        -6 if case == "abort" else False if case == "bool-status" else 0,
                        b"x" * 4097 if case == "oversized" else self.version("9.9.9") if case == "wrong-version" else self.version(),
                        b"inert dyld failure" if case == "stderr" else b"")
                scope = dict(self.namespace, owner=SimpleNamespace(run_owned=owned), objcopy_path=path,
                             environment=environment, checkout=Path("/fixed/checkout"), rust_release="1.98.1",
                             pending_call=False, no_configuration=lambda: None, check_originals=current)
                if case == "ok":
                    exec(self.health, scope)
                else:
                    with self.assertRaises((ValueError, RuntimeError)):
                        exec(self.health, scope)
                self.assertEqual(len(calls), 1)
                self.assertEqual(scope["pending_call"], case in ("wrong-argv", "bool-status", "oversized", "unknown"))
                self.assertEqual(len(checks), 2 if case in ("ok", "changed") else 1)

    def test_exact_tool_library_is_admitted_before_the_original_queries(self):
        self.assertIn("library_directory = bin_directory.parent / 'lib'", self.source)
        self.assertIn("objcopy_path = library_directory / 'rustlib' / build_target / 'bin/rust-objcopy'", self.source)
        self.assertIn("DYLD_FALLBACK_LIBRARY_PATH=str(library_directory)", self.source)
        for call in ("original_file(library_directory / 'libLLVM.dylib')", "original_file(objcopy_path, executable=True)"):
            self.assertLess(self.source.index(call), self.source.index("result = owner.run_owned("))
        for constraint in ("os.O_NOFOLLOW", "stat.S_ISREG(info.st_mode)", "not info.st_mode & 0o022", "current(row)"):
            self.assertIn(constraint, self.source)
        self.assertNotIn("llvm-tools", self.source)

    def test_selected_shell_compilers_set_only_exact_library_after_system_env(self):
        root = SOURCE.parents[2]
        expected = 'DYLD_FALLBACK_LIBRARY_PATH="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/lib" '
        selected = {"desktop/tools/macos_installed_app_build.sh": 5}
        for recipe in ("app_vault", "compile-the-fixed-ordinary-root-installer-before-cre",
                       "check-actual-git-and-library-flags-before-the-expens", "check-the-corrected-macos-minimum-and-actual-native-"):
            selected[".github/actions/macos-candidate-recipes/" + recipe + "/action.yml"] = 1
        for path, count in selected.items():
            source = (root / path).read_text(encoding="utf-8")
            lines = [line for line in source.splitlines() if expected in line]
            self.assertEqual(len(lines), count, path)
            self.assertEqual(source.count("DYLD_"), count, path)
            for line in lines:
                self.assertRegex(line.split(expected, 1)[1], r'^"/Users/runner/\.rustup/toolchains/.*?/bin/(cargo|rustc)"(?: |$)')
                if "/usr/bin/env -u" in line:
                    self.assertLess(line.index("/usr/bin/env -u"), line.index(expected))


if __name__ == "__main__":
    unittest.main()
