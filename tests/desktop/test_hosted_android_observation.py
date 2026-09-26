"""Inert public-DATA contracts; never observe this machine or invoke a tool."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, SOURCE / "desktop/tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


S = load("observe_hosted_android")
PYTHON = load("observe_hosted_python")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def row(path):
    return {"status": "observed", "file": {"path": path, "selectedPath": path,
            "size": 1, "sha256": "a" * 64}}


class HostedAndroidDataContracts(unittest.TestCase):
    def test_only_original_metadata_source_and_attempt_reach_the_context(self):
        repository = "Apdelrahman1911/mobile-release-kit"
        env = {"GITHUB_REF": S.METADATA_REF, "MRK_INSTALLED_SHELL_CASE": "host-metadata-only",
               "GITHUB_JOB": "compile", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTIONS": "true",
               "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
               "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": repository, "GITHUB_SHA": "a" * 40,
               "GITHUB_WORKFLOW_SHA": "a" * 40, "MRK_PUSH_EVENT_AFTER": "a" * 40, "GITHUB_RUN_ID": "123",
               "GITHUB_WORKFLOW_REF": repository + "/.github/workflows/desktop-ubuntu-publication.yml@" + S.METADATA_REF,
               "ImageOS": "ubuntu24", "ImageVersion": "20260920.314.1"}
        self.assertEqual(S.context(env, PYTHON.context)["GITHUB_SHA"], "a" * 40)
        for change in ({"GITHUB_REF": "refs/heads/main"}, {"GITHUB_RUN_ATTEMPT": "2"},
                       {"GITHUB_JOB": "observe"}, {"MRK_INSTALLED_SHELL_CASE": "compile"},
                       {"GITHUB_EVENT_NAME": "pull_request"}, {"GITHUB_WORKFLOW_SHA": "b" * 40},
                       {"RUNNER_ENVIRONMENT": "self-hosted"}, {"GITHUB_REPOSITORY": "different/repo"}):
            with self.subTest(change=change), self.assertRaises((S.Refused, PYTHON.Refused)):
                S.context({**env, **change}, PYTHON.context)

    def test_failed_reads_keep_their_reservation_and_an_expired_budget_stops(self):
        reader = S.Reader(None, 10)
        with patch.object(S.time, "monotonic", return_value=0):
            before = reader.remaining
            self.assertEqual(reader.charged(8, lambda _: (b"abc", 3)), b"abc")
            self.assertEqual(reader.remaining, before - 3)
            with self.assertRaises(OSError):
                reader.charged(8, Mock(side_effect=OSError("private path must not be emitted")))
            self.assertEqual(reader.remaining, before - 3 - 8 - (64 << 10))
            reader.remaining = 64 << 10
            action = Mock()
            with self.assertRaisesRegex(S.Stopped, "read-budget"):
                reader.charged(8, action)
            action.assert_not_called()
        with patch.object(S.time, "monotonic", return_value=11):
            with self.assertRaisesRegex(S.Stopped, "deadline"):
                reader.point()

    def test_selected_parsers_do_not_reflect_arbitrary_private_fields(self):
        receipt = S.license_ids(b"\n" + b"a" * 40 + b"\n")
        self.assertEqual(receipt, {"existingIds": ["a" * 40], "originProven": False, "newConsent": False})
        for raw in (b"credentials=private", b"a" * 40 + b"\n" + b"a" * 40, b"\r\n" + b"a" * 40):
            with self.assertRaises(S.Refused):
                S.license_ids(raw)
        public = S.image_identity(b'{"image_version":"20260920.314.1","unknown_private":"do-not-export"}')
        self.assertNotIn("do-not-export", json.dumps(public))
        with self.assertRaises(S.Refused):
            S.image_identity(b'{"image_url":"https://unreviewed.invalid/private"}')
        raw = b"Package: coreutils\nStatus: install ok installed\nVersion: 9.4\nArchitecture: amd64\nPrivate: do-not-export\n\nPackage: unrelated\nVersion: do-not-export\n"
        packages = S.package_status(raw)
        self.assertNotIn("do-not-export", json.dumps(packages))
        self.assertEqual(packages["sed"], {"status": "absent"})
        paths = S.selected_input_paths({"fixed": row("/usr/bin/echo"),
            "failed": {"status": "unavailable", "file": {"path": "do-not-export"}},
            "supplierCaInputs": {"status": "observed", "files": [row(S.CA_ROOT + "/mozilla/public.crt")]}})
        members = S.package_members(("/usr/bin/echo\n/unrelated/private\n" + S.CA_ROOT + "/mozilla/public.crt\n").encode(), paths, digests=False)
        self.assertEqual(set(members["selectedMembers"]), paths)
        self.assertNotIn("private", json.dumps(members))
        sums = S.package_members(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  usr/bin/echo\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  unrelated/private\n", paths, digests=True)
        self.assertEqual(sums["selectedMembers"], {"/usr/bin/echo": "a" * 32})

    def test_body_change_and_final_original_change_refuse_the_entire_file_row(self):
        raw = b"public"
        original = {"path": "/fixed", "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        reader = S.Reader(SimpleNamespace(D=SimpleNamespace(same=lambda a, b: a == b)), 10)
        for changed_body, changed_final in ((True, False), (False, True)):
            final = {**original, "sha256": "b" * 64} if changed_final else original
            with self.subTest(body=changed_body), patch.object(S.time, "monotonic", return_value=0), \
                 patch.object(reader, "_record", side_effect=[(original, len(raw)), (final, len(raw))]), \
                 patch.object(reader, "_body", return_value=(b"secret" if changed_body else raw, len(raw))):
                with self.assertRaises(S.Refused):
                    reader.file("/fixed", 100, lambda value: value.decode())

    def test_custom_directory_never_exports_a_name_and_close_failure_refuses(self):
        info = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0,
                               st_nlink=2, st_size=4096, st_mtime_ns=1, st_ctime_ns=1)
        state = lambda value: tuple(vars(value).values())
        binding = {"path": S.CUSTOM_CA_ROOT, "directory": [1, 2, info.st_mode, 0, 0]}
        pub = SimpleNamespace(shell_host_binding=Mock(return_value=binding),
                              D=SimpleNamespace(state=state, same=lambda a, b: a == b))
        class Entry:
            @property
            def name(self):
                raise AssertionError("custom entry name must not be accessed")
        for close_failure in (False, True):
            scanner = Mock()
            scanner.__enter__ = Mock(return_value=iter([Entry()]))
            scanner.__exit__ = Mock(return_value=False)
            with self.subTest(close_failure=close_failure), patch.object(S.time, "monotonic", return_value=0), \
                 patch.object(S.os, "open", return_value=9), patch.object(S.os, "fstat", return_value=info), \
                 patch.object(S.os, "scandir", return_value=scanner), patch.object(Path, "lstat", return_value=info), \
                 patch.object(S.os, "close", side_effect=OSError("private") if close_failure else None) as close:
                reader = S.Reader(pub, 10)
                if close_failure:
                    with self.assertRaises(OSError):
                        reader.directory(S.CUSTOM_CA_ROOT, custom=True)
                else:
                    self.assertEqual(reader.directory(S.CUSTOM_CA_ROOT, custom=True),
                                     {"status": "nonempty", "customBodiesRead": False, "customNamesExported": False})
                close.assert_called_once_with(9)

    def test_supplier_aliases_refuse_before_reading_any_certificate_body(self):
        directory = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0,
                                    st_nlink=2, st_size=4096, st_mtime_ns=1, st_ctime_ns=1)
        alias = SimpleNamespace(**{**vars(directory), "st_mode": stat.S_IFLNK | 0o777})
        state = lambda value: tuple(vars(value).values())
        pub = SimpleNamespace(D=SimpleNamespace(state=state))
        for component in ("ca-certificates", "mozilla", "public.crt"):
            def before(name, **kwargs):
                self.assertIs(kwargs["follow_symlinks"], False)
                return alias if name == component else directory
            with self.subTest(component=component), patch.object(S.time, "monotonic", return_value=0), \
                 patch.object(S.os, "stat", side_effect=before), patch.object(S.os, "fstat", return_value=directory), \
                 patch.object(S.os, "open", side_effect=range(10, 20)) as opened, patch.object(S.os, "close") as closed, \
                 patch.object(S.os, "read", side_effect=AssertionError("must not read alias body")) as read:
                with self.assertRaises(S.Refused):
                    S.Reader(pub, 10).ca_file(S.CA_ROOT + "/mozilla/public.crt")
                read.assert_not_called()
                self.assertEqual(closed.call_count, opened.call_count)
                self.assertEqual(len({call.args[0] for call in closed.call_args_list}), closed.call_count)
                for call in opened.call_args_list:
                    self.assertTrue(call.args[1] & S.os.O_NOFOLLOW)

    def test_supplier_body_is_hashed_on_original_fd_and_all_closes_are_required(self):
        body = b"public CA data"
        directory = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0,
                                    st_nlink=2, st_size=4096, st_mtime_ns=1, st_ctime_ns=1)
        file = SimpleNamespace(**{**vars(directory), "st_ino": 3, "st_mode": stat.S_IFREG | 0o644,
                                 "st_nlink": 1, "st_size": len(body)})
        state = lambda value: tuple(vars(value).values())
        pub = SimpleNamespace(D=SimpleNamespace(state=state))
        for fault in (None, "changed", "close"):
            calls = []
            def fstat(fd):
                if fd != 15:
                    return directory
                calls.append(fd)
                return SimpleNamespace(**{**vars(file), "st_ino": 4}) if fault == "changed" and len(calls) > 1 else file
            def close(fd):
                if fault == "close" and fd == 15:
                    raise OSError("unknown close return, no retry")
            with self.subTest(fault=fault), patch.object(S.time, "monotonic", return_value=0), \
                 patch.object(S.os, "stat", side_effect=lambda name, **_: file if name == "public.crt" else directory), \
                 patch.object(S.os, "fstat", side_effect=fstat), patch.object(S.os, "open", side_effect=range(10, 16)), \
                 patch.object(S.os, "close", side_effect=close) as closed, patch.object(S.os, "read", side_effect=[body, b""]):
                reader = S.Reader(pub, 10)
                if fault:
                    with self.assertRaises((S.Refused, OSError)):
                        reader.ca_file(S.CA_ROOT + "/mozilla/public.crt")
                else:
                    value = reader.ca_file(S.CA_ROOT + "/mozilla/public.crt")
                    self.assertEqual(value["file"]["sha256"], hashlib.sha256(body).hexdigest())
                    self.assertNotIn(body.decode(), json.dumps(value))
                    self.assertEqual(reader.remaining, S.READ_LIMIT - len(body))
                self.assertEqual([call.args[0] for call in closed.call_args_list], list(range(15, 9, -1)))

    def test_partial_observations_preserve_independent_facts_but_global_stop_halts(self):
        pub = SimpleNamespace(D=SimpleNamespace(canonical=canonical))
        for stop in (None, "deadline", "output-budget", "malformed-image"):
            fake = SimpleNamespace(remaining=S.READ_LIMIT, point=Mock())
            def file(name, limit, parse=None):
                if name == S.PROGRAMS[0]:
                    raise PermissionError("private value must not be exported")
                if name == S.PROGRAMS[2] and stop == "deadline":
                    raise S.Stopped("deadline")
                if name == S.IMAGE_DATA and stop == "malformed-image":
                    # Actually exercise the independent deeply nested parser failure.
                    return S.image_identity(b'{"ignored":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}')
                value = row(name)
                if name == S.PROGRAMS[2] and stop == "output-budget":
                    value["data"] = "x" * S.OUTPUT_LIMIT
                return value
            fake.file = Mock(side_effect=file)
            fake.directory = Mock(return_value={"status": "empty", "customBodiesRead": False, "customNamesExported": False})
            github = {"qualified": False, "runtimeSelfAdmission": False, "nftExecuted": False,
                      "dnsQueryIssued": False, "failures": [{"material": "fixed", "errorType": "Refused"}]}
            with self.subTest(stop=stop), patch.object(S, "Reader", return_value=fake), \
                 patch.object(S, "supplier_cas", return_value={"status": "unavailable"}), \
                 patch.object(S, "github_materials", return_value=github) as shared:
                value = S.collect(pub, {"source": "a" * 40}, 10)
                self.assertEqual(value["stopped"], None if stop == "malformed-image" else stop)
                self.assertEqual(value["observations"][S.PROGRAMS[0]], {"status": "unavailable", "reason": "permission-denied"})
                self.assertEqual(value["observations"][S.PROGRAMS[1]]["status"], "observed")
                for flag in ("runtimeAdmission", "nativeQualification", "newConsent", "collectionComplete", "producerOriginProven"):
                    self.assertIs(value[flag], False)
                encoded = canonical(value)
                self.assertLessEqual(len(encoded), S.OUTPUT_LIMIT)
                self.assertNotIn(b"private", encoded)
                if stop in ("deadline", "output-budget"):
                    self.assertEqual(fake.file.call_count, 3)
                    self.assertEqual(value["observations"][S.PROGRAMS[3]]["status"], "not-observed")
                    shared.assert_not_called()
                else:
                    shared.assert_called_once()
                    self.assertEqual(value["observations"]["githubNormalBoundary"]["data"], github)
                    if stop == "malformed-image":
                        self.assertEqual(value["observations"]["imageGeneration"],
                                         {"status": "unavailable", "reason": "invalid-or-changed"})

    def test_workflow_metadata_route_cannot_compile_or_invoke_native_observation(self):
        workflow = (SOURCE / ".github/workflows/desktop-ubuntu-publication.yml").read_text()
        steps = workflow.split("      - name: ")[1:]
        observer = next(s for s in steps if s.startswith("Observe only the missing public Android and GitHub host DATA\n"))
        for item in ("if: github.ref == '" + S.METADATA_REF + "'", "timeout-minutes: 2", "/usr/bin/env -i",
                     "--signal=TERM --kill-after=2s 60s", "python3.12 -I -S -B desktop/tools/observe_hosted_android.py </dev/null",
                     'GITHUB_WORKSPACE="$GITHUB_WORKSPACE" RUNNER_TEMP="$RUNNER_TEMP"'):
            self.assertIn(item, observer)
        output = next(s for s in steps if s.startswith("Retain only the bounded public host delta"))
        self.assertIn("path: ${{ steps.tools_inputs.outputs.root }}/" + S.OUTPUT_NAME, output)
        self.assertNotIn("**", output)
        for label in ("Select the fixed frontend compiler", "Prepare a fresh bounded compiler owner",
                      "Compile the normal shell", "Observe only the fixed installed shell route"):
            step = next(s for s in steps if s.startswith(label))
            condition = next(line for line in step.splitlines() if line.strip().startswith("if:"))
            self.assertNotIn(S.METADATA_REF, condition)
        # The observer's only dynamic modules are the two closed DATA helpers;
        # inspect source without executing either its main or any provider.
        module = ast.parse((SOURCE / "desktop/tools/observe_hosted_android.py").read_bytes())
        calls = {ast.unparse(n.func) for n in ast.walk(module) if isinstance(n, ast.Call)}
        for forbidden in ("subprocess.run", "subprocess.Popen", "os.system", "os.execve", "socket.socket",
                          "lifecycle._github_boundary_host_projection", "lifecycle._github_boundary_host_admission"):
            self.assertNotIn(forbidden, calls)


if __name__ == "__main__":
    unittest.main()
